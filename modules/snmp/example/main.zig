// SPDX-License-Identifier: MIT

//! What an SNMP polling consumer does with `snmp`: point a manager at a
//! `Transport`, read the two scalars every inventory starts with
//! (sysDescr.0 / sysUpTime.0), then walk the ifDescr column of ifTable.
//!
//! The transport here is an in-process agent simulator, which is the shape a
//! downstream test harness wants: no socket, no UDP, deterministic bytes. It
//! is also the honest way to exercise the seam — `UdpTransport` exists for the
//! real path, but a consumer's CI never opens port 161.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`deps` only, no `test_deps`, no access to anything the module does
//! not export). If a type needed to call the API is not public, or an error
//! cannot be named from outside, this file stops compiling. The module's own
//! tests cannot notice either, because they live inside it.

const std = @import("std");
const snmp = @import("snmp");

/// The simulated agent's MIB, in lexicographic OID order — the order a real
/// agent must answer GetNext in, and the order the walker's loop guard
/// checks.
const MibEntry = struct { oid: []const u8, value: snmp.Value };

const mib = [_]MibEntry{
    .{ .oid = "1.3.6.1.2.1.1.1.0", .value = .{ .octet_string = "switch, 24 port, firmware 3.1" } },
    .{ .oid = "1.3.6.1.2.1.1.3.0", .value = .{ .time_ticks = 1_209_600 } }, // 3h 21m
    .{ .oid = "1.3.6.1.2.1.2.2.1.2.1", .value = .{ .octet_string = "lo" } },
    .{ .oid = "1.3.6.1.2.1.2.2.1.2.2", .value = .{ .octet_string = "eth0" } },
    // First OID past the ifDescr column: the walker must stop before this.
    .{ .oid = "1.3.6.1.2.1.2.2.1.3.1", .value = .{ .integer = 6 } },
};

/// A `Transport` implementation living entirely in memory. Everything a
/// consumer needs to write one is public: the error set it may report, the
/// vtable shape, and the message codec used to answer.
const Agent = struct {
    /// The codec writes backwards, so it needs a buffer of its own; the
    /// finished message then has to be copied to the FRONT of `reply_buf`,
    /// because `exchangeFn` reports a length, not a slice.
    scratch: [2048]u8 = undefined,

    fn transport(a: *Agent) snmp.Transport {
        return .{ .ctx = a, .exchangeFn = exchange };
    }

    fn exchange(
        ctx: *anyopaque,
        request: []const u8,
        reply_buf: []u8,
    ) snmp.TransportError!usize {
        const a: *Agent = @ptrCast(@alignCast(ctx));

        // A real agent parses what the manager sent; so does this one, so the
        // response echoes the request-id the client is matching on.
        const msg = snmp.message.decode(request) catch return error.TransportFailed;
        const pdu = switch (msg.pdu) {
            .get_request, .get_next_request => |p| p,
            else => return error.TransportFailed,
        };

        var out: [4]snmp.VarBind = undefined;
        var n: usize = 0;
        var it = pdu.varbinds.iterator();
        while (it.next() catch return error.TransportFailed) |vb| {
            if (n == out.len) return error.TransportFailed;
            out[n] = switch (msg.pdu) {
                .get_request => lookup(vb.name),
                else => successor(vb.name),
            };
            n += 1;
        }

        const wire = snmp.message.encode(&a.scratch, msg.version, msg.community, .{
            .type = .response,
            .request_id = pdu.request_id,
            .varbinds = out[0..n],
        }) catch return error.TransportFailed;

        if (wire.len > reply_buf.len) return error.TransportFailed;
        @memcpy(reply_buf[0..wire.len], wire);
        return wire.len;
    }

    /// Exact-instance read: an absent instance is `noSuchInstance`, not an
    /// error — that distinction is why `Value` has the v2c exception tags.
    fn lookup(name: snmp.Oid) snmp.VarBind {
        for (mib) |e| {
            const o = snmp.Oid.parse(e.oid) catch continue;
            if (name.eql(&o)) return .{ .name = name, .value = e.value };
        }
        return .{ .name = name, .value = .no_such_instance };
    }

    /// GetNext: the lexicographic successor, or `endOfMibView` past the end.
    fn successor(name: snmp.Oid) snmp.VarBind {
        for (mib) |e| {
            const o = snmp.Oid.parse(e.oid) catch continue;
            if (o.order(&name) == .gt) return .{ .name = o, .value = e.value };
        }
        return .{ .name = name, .value = .end_of_mib_view };
    }
};

pub fn main() !void {
    var agent: Agent = .{};
    var client = snmp.Client.init(agent.transport(), .{ .version = .v2c });

    const sys_descr = try snmp.Oid.parse("1.3.6.1.2.1.1.1.0");
    const sys_uptime = try snmp.Oid.parse("1.3.6.1.2.1.1.3.0");

    const resp = try client.get("public", &.{ sys_descr, sys_uptime });

    // A reachable agent that refuses the request is not a transport failure:
    // it answers with a Response PDU carrying an error-status, and the
    // one-based error-index says which varbind was at fault.
    if (resp.error_status != .no_error) {
        std.debug.print(
            "agent refused: {s} at varbind {d}\n",
            .{ @tagName(resp.error_status), resp.error_index },
        );
        return;
    }

    var it = resp.varbinds.iterator();
    while (try it.next()) |vb| {
        std.debug.print("{f} = ", .{vb.name});
        switch (vb.value) {
            .octet_string => |s| std.debug.print("\"{s}\"\n", .{s}),
            .time_ticks => |t| std.debug.print("{d}.{d:0>2}s uptime\n", .{ t / 100, t % 100 }),
            // The three v2c exceptions are values, not errors — a poller that
            // treats them as errors drops the rest of a perfectly good reply.
            .no_such_object, .no_such_instance => std.debug.print("(not implemented)\n", .{}),
            else => std.debug.print("{s}\n", .{@tagName(vb.value)}),
        }
    }

    // Walk the ifDescr column. The walker stops on its own at the subtree
    // edge; the interesting case is the one it cannot recover from.
    const if_descr = try snmp.Oid.parse("1.3.6.1.2.1.2.2.1.2");
    var walk = client.walker("public", if_descr);
    while (walk.next() catch |err| switch (err) {
        // An agent that answers GetNext with an OID that did not advance
        // would spin the walk forever; the module makes that a named error
        // instead, and a poller wants to log the device and move on.
        error.OidNotIncreasing => {
            std.debug.print("agent violates GetNext ordering, abandoning walk\n", .{});
            return;
        },
        error.RequestFailed => {
            std.debug.print("walk rejected mid-subtree\n", .{});
            return;
        },
        else => return err,
    }) |vb| {
        std.debug.print("interface {f} = \"{s}\"\n", .{ vb.name, vb.value.octet_string });
    }
}
