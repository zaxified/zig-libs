// SPDX-License-Identifier: MIT

//! `snmp-demo` — one binary, two modes (`agent` and `manager`) that talk to
//! each other over a **real UDP socket**. Run the agent in one terminal, the
//! manager in another, and watch an inventory poller drive a network device.
//! Either half can be pointed at a foreign implementation: the manager at any
//! v1/v2c agent (`snmpd`), the agent at any manager (`snmpget`, `snmpwalk`).
//!
//! **What a polling consumer does with `snmp`**, which is what `manager` mode
//! is: read the two scalars every inventory starts with (sysDescr.0 /
//! sysUpTime.0), walk the ifDescr column of ifTable, then ask the device to
//! emit a test notification and receive it.
//!
//! **Both halves come out of this module.** `Client` + `UdpTransport` are the
//! manager; `message.decode` / `message.encode` are what the agent answers
//! with; and the notification leg is `receiver.parseTrap` + `receiver.ackInform`,
//! which is the module's own manager-side ingest for traps and informs. The
//! only thing the module does not ship is the socket loop — that is the
//! twenty lines below, and a reader who needs a different concurrency model
//! writes their own twenty.
//!
//! **Four PDU types cross the wire here and they are not interchangeable.**
//! GetRequest reads an exact instance and an absent one is the *value*
//! `noSuchInstance`, not an error. GetNextRequest returns the lexicographic
//! successor, which is what makes a walk possible and what makes a
//! non-advancing agent an infinite loop. SetRequest writes. InformRequest is
//! the one notification shape that is acknowledged — the receiver must echo a
//! Response, and `ackInform` builds it.
//!
//! **Not port 161/162.** Both are privileged, and a demo that needs root to
//! bind teaches the wrong first lesson. 1161/1162 are the conventional
//! unprivileged stand-ins.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`deps` only, no `test_deps`, no access to anything the module does
//! not export). If a type needed to call the API is not public, or an error
//! cannot be named from outside, this file stops compiling. The module's own
//! tests cannot notice either, because they live inside it.

const std = @import("std");
const snmp = @import("snmp");

/// Anything that is this demo's own failure rather than the protocol saying
/// no. An agent that refuses a request is a successful conversation with an
/// unwelcome answer, and exits 0.
const local_failure_exit: u8 = 1;

/// Generous for SNMP over UDP: RFC 3416 only requires 484-byte messages to
/// work, and `Client` sizes its own buffers at 2048.
const max_datagram = 2048;

const default_agent_port: u16 = 1161;
const default_trap_port: u16 = 1162;

/// The enterprise OID this demo's device uses for "emit a test notification".
/// Under the private-enterprise arc, so it cannot collide with a standard MIB.
/// Writing any INTEGER here makes the agent send one InformRequest.
const test_notify_oid = "1.3.6.1.4.1.99999.1.1.0";

/// `snmpTrapOID.0`'s value in the notification the agent sends: linkUp
/// (RFC 3418). A real device would pick the OID of whatever just happened.
const link_up_oid = "1.3.6.1.6.3.1.1.5.4";

const sys_descr_oid = "1.3.6.1.2.1.1.1.0";
const sys_uptime_oid = "1.3.6.1.2.1.1.3.0";
const if_descr_oid = "1.3.6.1.2.1.2.2.1.2";
const snmp_trap_oid = "1.3.6.1.6.3.1.1.4.1.0";

const usage_text =
    \\snmp-demo — an SNMP v2c manager/agent demo for the `snmp` module.
    \\
    \\usage:
    \\  snmp-demo agent   [options]
    \\  snmp-demo manager [options]
    \\
    \\agent options:
    \\  --listen <addr>     address to bind             (default 127.0.0.1)
    \\  --port <port>       UDP port                    (default 1161)
    \\  --community <s>     community it answers for    (default public)
    \\  --trap-port <port>  where to send the notification, on the polling
    \\                      manager's own address       (default 1162)
    \\  --once              serve until it has sent one notification, then exit
    \\  -h, --help          this text
    \\
    \\manager options:
    \\  --host <host>       agent to poll               (default 127.0.0.1)
    \\  --port <port>       UDP port                    (default 1161)
    \\  --community <s>     community to send           (default public)
    \\  --trap-port <port>  port to receive the notification on (default 1162)
    \\  --no-notify         stop after the walk; do not ask for a notification
    \\  -h, --help          this text
    \\
    \\Two terminals:
    \\  snmp-demo agent --once
    \\  snmp-demo manager
    \\
    \\A wrong community is not an error on the wire — an agent drops the
    \\datagram and says nothing, and the manager sits in its response timeout:
    \\  snmp-demo manager --community wrong
    \\
    \\Against a foreign implementation:
    \\  snmpwalk -v2c -c public 127.0.0.1:1161 1.3.6.1.2.1
    \\  snmp-demo manager --host <a real agent> --port 161
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes the example a leak detector
    // for the module's ownership contract. `snmp` itself is allocation-free
    // end to end — there is no allocator anywhere in its API — so what this
    // actually guards is the demo's own I/O plumbing.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.skip(); // argv[0]

    const mode = args.next() orelse {
        std.debug.print("{s}", .{usage_text});
        return local_failure_exit;
    };

    if (std.mem.eql(u8, mode, "agent")) return runAgent(io, &args);
    if (std.mem.eql(u8, mode, "manager")) return runManager(io, &args);
    if (std.mem.eql(u8, mode, "-h") or std.mem.eql(u8, mode, "--help")) {
        std.debug.print("{s}", .{usage_text});
        return 0;
    }

    std.debug.print("snmp-demo: unknown mode '{s}' (expected `agent` or `manager`)\n\n{s}", .{ mode, usage_text });
    return local_failure_exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// the simulated device's MIB
// ─────────────────────────────────────────────────────────────────────────────
//
// In lexicographic OID order — the order a real agent must answer GetNext in,
// and the order the walker's loop guard checks. sysUpTime.0 is the exception:
// it is the process's own elapsed time, filled in per request, because an
// agent whose uptime never moves is the one thing about this MIB a reader
// could not tell from a fixture.

const MibEntry = struct { oid: []const u8, value: snmp.Value };

const mib = [_]MibEntry{
    .{ .oid = sys_descr_oid, .value = .{ .octet_string = "zig-libs snmp-demo, 24 port, firmware 3.1" } },
    .{ .oid = sys_uptime_oid, .value = .{ .time_ticks = 0 } }, // replaced per request
    .{ .oid = "1.3.6.1.2.1.2.2.1.2.1", .value = .{ .octet_string = "lo" } },
    .{ .oid = "1.3.6.1.2.1.2.2.1.2.2", .value = .{ .octet_string = "eth0" } },
    // First OID past the ifDescr column: the walker must stop before this.
    .{ .oid = "1.3.6.1.2.1.2.2.1.3.1", .value = .{ .integer = 6 } },
    // The write-only trigger. Reading it is legal and answers `noSuchInstance`
    // the way a write-only object does; writing it emits the notification.
    .{ .oid = test_notify_oid, .value = .no_such_instance },
};

// ─────────────────────────────────────────────────────────────────────────────
// agent mode
// ─────────────────────────────────────────────────────────────────────────────

const AgentOptions = struct {
    listen: []const u8 = "127.0.0.1",
    port: u16 = default_agent_port,
    community: []const u8 = "public",
    trap_port: u16 = default_trap_port,
    once: bool = false,
};

fn runAgent(io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var opts: AgentOptions = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return 0;
        } else if (std.mem.eql(u8, arg, "--once")) {
            opts.once = true;
        } else if (std.mem.eql(u8, arg, "--listen")) {
            opts.listen = (try nextValue(args, "--listen")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--community")) {
            opts.community = (try nextValue(args, "--community")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = (try parseIntArg(u16, args, "--port")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--trap-port")) {
            opts.trap_port = (try parseIntArg(u16, args, "--trap-port")) orelse return local_failure_exit;
        } else {
            std.debug.print("snmp-demo: unknown agent option '{s}' (try --help)\n", .{arg});
            return local_failure_exit;
        }
    }

    const addr = std.Io.net.IpAddress.parse(opts.listen, opts.port) catch |err| {
        std.debug.print("snmp-demo: cannot parse listen address {s}:{d}: {t}\n", .{ opts.listen, opts.port, err });
        return local_failure_exit;
    };
    var sock = addr.bind(io, .{ .mode = .dgram }) catch |err| {
        std.debug.print("snmp-demo: cannot bind {s}:{d}: {t}\n", .{ opts.listen, opts.port, err });
        if (err == error.AddressInUse) std.debug.print(
            "  Another snmp-demo agent (or a real snmpd) already holds that port; pass --port.\n",
            .{},
        );
        return local_failure_exit;
    };
    defer sock.close(io);

    std.debug.print(
        "snmp-demo: agent listening on {s}:{d} UDP, community \"{s}\"\n",
        .{ opts.listen, opts.port, opts.community },
    );
    printMib();

    const started = std.Io.Clock.Timestamp.now(io, .awake);

    // SNMP is one datagram in, one datagram out — no framing, no connection
    // and no stream to resynchronise. That is why the whole agent is this
    // loop and a pure function, and why `Transport` is one `exchange` call.
    var rx: [max_datagram]u8 = undefined;
    var tx: [max_datagram]u8 = undefined;
    var notified = false;
    while (true) {
        const incoming = sock.receive(io, &rx) catch |err| {
            std.debug.print("snmp-demo: receive failed: {t}\n", .{err});
            return local_failure_exit;
        };
        var peer_buf: [48]u8 = undefined;
        const peer = describeAddr(incoming.from, &peer_buf);

        const outcome = answer(io, started, opts.community, incoming.data, &tx, peer);
        const reply = switch (outcome) {
            // A real agent answers a datagram it does not like with SILENCE.
            // There is no "wrong community" reply in v1/v2c — the manager just
            // sits in its response timeout, which is why every manager needs
            // one. Answering would also make this an amplification reflector.
            .silent => continue,
            .reply => |r| r,
        };
        sock.send(io, &incoming.from, reply) catch |err| {
            std.debug.print("   -> send to {s} failed: {t}\n", .{ peer, err });
            continue;
        };

        if (reply.len != 0 and notifyRequested(incoming.data)) {
            sendInform(io, opts, incoming.from, started) catch |err| {
                std.debug.print("   ~> notification failed: {t}\n", .{err});
            };
            notified = true;
        }
        if (opts.once and notified) break;
    }
    std.debug.print("snmp-demo: agent done\n", .{});
    return 0;
}

const Outcome = union(enum) {
    silent,
    reply: []const u8,
};

/// One request datagram in, one response datagram out — or silence. Pure
/// apart from the clock read for sysUpTime and the logging: everything about
/// SNMP that is worth getting right lives here rather than in the socket loop.
fn answer(
    io: std.Io,
    started: std.Io.Clock.Timestamp,
    community: []const u8,
    datagram: []const u8,
    out: []u8,
    peer: []const u8,
) Outcome {
    const msg = snmp.message.decode(datagram) catch |err| {
        std.debug.print("   <- {d} bytes from {s} that are not an SNMP message ({t}); silent\n", .{ datagram.len, peer, err });
        return .silent;
    };
    const pdu = switch (msg.pdu) {
        .get_request, .get_next_request, .set_request => |p| p,
        // A manager does not send us responses or notifications. Nothing to
        // say back.
        else => {
            std.debug.print("   <- {s} sent a {s}; silent\n", .{ peer, @tagName(msg.pdu) });
            return .silent;
        },
    };
    std.debug.print("   <- {s}  {s} rid {d}  community \"{s}\"\n", .{
        peer, @tagName(msg.pdu), pdu.request_id, msg.community,
    });

    if (!std.mem.eql(u8, msg.community, community)) {
        std.debug.print("   -> wrong community; silent (the manager will sit in its timeout)\n", .{});
        return .silent;
    }

    var vbs: [8]snmp.VarBind = undefined;
    var n: usize = 0;
    var error_status: i32 = 0;
    var error_index: i32 = 0;

    var it = pdu.varbinds.iterator();
    while (it.next() catch {
        std.debug.print("   -> malformed varbind list; silent\n", .{});
        return .silent;
    }) |vb| {
        if (n == vbs.len) {
            // tooBig(1): the honest answer when the request outgrows what this
            // device can assemble. RFC 3416 §4.2.1.
            error_status = 1;
            error_index = 0;
            n = 0;
            break;
        }
        vbs[n] = switch (msg.pdu) {
            .get_request => lookup(io, started, vb.name),
            .get_next_request => successor(io, started, vb.name),
            else => write(vb, &error_status, &error_index, @intCast(n + 1)),
        };
        n += 1;
    }

    const wire = snmp.message.encode(out, msg.version, msg.community, .{
        .type = .response,
        .request_id = pdu.request_id,
        .error_status = error_status,
        .error_index = error_index,
        .varbinds = vbs[0..n],
    }) catch |err| {
        std.debug.print("   -> cannot encode a response ({t}); silent\n", .{err});
        return .silent;
    };
    if (error_status != 0) {
        std.debug.print("   -> Response error-status {d} at varbind {d}\n", .{ error_status, error_index });
    } else {
        std.debug.print("   -> Response, {d} varbind(s), {d} bytes\n", .{ n, wire.len });
    }
    return .{ .reply = wire };
}

/// The MIB with the live value substituted in. Everything else is a constant.
fn valueOf(io: std.Io, started: std.Io.Clock.Timestamp, e: MibEntry) snmp.Value {
    if (!std.mem.eql(u8, e.oid, sys_uptime_oid)) return e.value;
    // TimeTicks is hundredths of a second since the entity was initialised.
    const ns = started.untilNow(io).raw.nanoseconds;
    const hundredths = @divTrunc(ns, 10_000_000);
    return .{ .time_ticks = @intCast(@mod(hundredths, std.math.maxInt(u32))) };
}

/// Exact-instance read: an absent instance is `noSuchInstance`, not an error —
/// that distinction is why `Value` has the v2c exception tags.
fn lookup(io: std.Io, started: std.Io.Clock.Timestamp, name: snmp.Oid) snmp.VarBind {
    for (mib) |e| {
        const o = snmp.Oid.parse(e.oid) catch continue;
        if (name.eql(&o)) return .{ .name = name, .value = valueOf(io, started, e) };
    }
    return .{ .name = name, .value = .no_such_instance };
}

/// GetNext: the lexicographic successor, or `endOfMibView` past the end.
fn successor(io: std.Io, started: std.Io.Clock.Timestamp, name: snmp.Oid) snmp.VarBind {
    for (mib) |e| {
        const o = snmp.Oid.parse(e.oid) catch continue;
        if (o.order(&name) == .gt) return .{ .name = o, .value = valueOf(io, started, e) };
    }
    return .{ .name = name, .value = .end_of_mib_view };
}

/// SetRequest. Everything in this MIB is read-only except the notification
/// trigger, and `readOnly(4)` with a one-based error-index is how an agent
/// says which varbind it refused — not a transport failure, and not silence.
fn write(vb: snmp.VarBind, error_status: *i32, error_index: *i32, index: i32) snmp.VarBind {
    const trigger = snmp.Oid.parse(test_notify_oid) catch unreachable;
    if (vb.name.eql(&trigger) and vb.value == .integer) return vb;
    if (error_status.* == 0) {
        error_status.* = 4; // readOnly
        error_index.* = index;
    }
    return vb;
}

/// True when this datagram is the SetRequest that asks for a notification.
/// Re-decoded rather than threaded out of `answer`, so the reply path stays
/// one value.
fn notifyRequested(datagram: []const u8) bool {
    const msg = snmp.message.decode(datagram) catch return false;
    const pdu = switch (msg.pdu) {
        .set_request => |p| p,
        else => return false,
    };
    const trigger = snmp.Oid.parse(test_notify_oid) catch return false;
    var it = pdu.varbinds.iterator();
    while (it.next() catch return false) |vb| {
        if (vb.name.eql(&trigger) and vb.value == .integer) return true;
    }
    return false;
}

/// Emit one **InformRequest** to the manager that just polled us, and wait for
/// its acknowledgement.
///
/// An Inform is the acknowledged notification: unlike an SNMPv2-Trap, the
/// receiver must echo a Response with the same request-id, and a notifier that
/// does not get one is supposed to retransmit. That is the whole reason to
/// choose it over a Trap for anything that matters — and it is why this demo
/// sends one: the ack is the half `receiver.ackInform` builds on the manager
/// side, so both directions of the notification path are ours.
///
/// It goes out on a socket of its own, to the POLLER's address at the
/// configured notification port. A real device would have that address from
/// its configuration; taking it from the poll is what makes a two-terminal
/// demo work with no configuration at all.
fn sendInform(
    io: std.Io,
    opts: AgentOptions,
    poller: std.Io.net.IpAddress,
    started: std.Io.Clock.Timestamp,
) !void {
    const dest: std.Io.net.IpAddress = switch (poller) {
        .ip4 => |a| .{ .ip4 = .{ .bytes = a.bytes, .port = opts.trap_port } },
        .ip6 => |a| .{ .ip6 = .{ .bytes = a.bytes, .port = opts.trap_port, .flow = a.flow, .interface = a.interface } },
    };
    const local: std.Io.net.IpAddress = switch (dest) {
        .ip4 => .{ .ip4 = .unspecified(0) },
        .ip6 => .{ .ip6 = .unspecified(0) },
    };
    var sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);

    // RFC 3416 §4.2.6: varbind[0] is sysUpTime.0 and varbind[1] is
    // snmpTrapOID.0, in that order. A receiver that reads them positionally —
    // which `TrapEvent.sysUpTime` / `snmpTrapOid` do — gets nothing useful
    // from a notifier that omits them.
    const uptime = valueOf(io, started, mib[1]);
    const request_id: i32 = 0x51D2;
    const vbs = [_]snmp.VarBind{
        .{ .name = try snmp.Oid.parse(sys_uptime_oid), .value = uptime },
        .{ .name = try snmp.Oid.parse(snmp_trap_oid), .value = .{ .oid = try snmp.Oid.parse(link_up_oid) } },
        .{ .name = try snmp.Oid.parse("1.3.6.1.2.1.2.2.1.2.2"), .value = .{ .octet_string = "eth0" } },
    };
    var buf: [max_datagram]u8 = undefined;
    const wire = try snmp.message.encode(&buf, .v2c, opts.community, .{
        .type = .inform_request,
        .request_id = request_id,
        .varbinds = &vbs,
    });

    var dest_buf: [48]u8 = undefined;
    std.debug.print("   ~> InformRequest linkUp(eth0) rid {d} to {s}\n", .{
        request_id, describeAddr(dest, &dest_buf),
    });
    try sock.send(io, &dest, wire);

    var ack_buf: [max_datagram]u8 = undefined;
    const ack = sock.receiveTimeout(io, &ack_buf, .{
        .duration = .{ .raw = .fromMilliseconds(3000), .clock = .awake },
    }) catch |err| switch (err) {
        // The point of an Inform: unacknowledged is a KNOWN outcome, and a
        // real notifier retransmits here rather than assuming delivery.
        error.Timeout => {
            std.debug.print("   ~> no acknowledgement in 3s — a real notifier would retransmit\n", .{});
            return;
        },
        else => return err,
    };
    const msg = snmp.message.decode(ack.data) catch |err| {
        std.debug.print("   ~> acknowledgement is not decodable ({t})\n", .{err});
        return;
    };
    switch (msg.pdu) {
        .response => |p| if (p.request_id == request_id) {
            std.debug.print("   ~> acknowledged, rid {d} echoed\n", .{p.request_id});
        } else {
            std.debug.print("   ~> acknowledgement carries rid {d}, expected {d}\n", .{ p.request_id, request_id });
        },
        else => std.debug.print("   ~> expected a Response, got a {s}\n", .{@tagName(msg.pdu)}),
    }
}

fn printMib() void {
    std.debug.print("  the device's MIB, in the lexicographic order GetNext must follow:\n", .{});
    for (mib) |e| {
        std.debug.print("    {s: <24}", .{e.oid});
        switch (e.value) {
            .octet_string => |s| std.debug.print("\"{s}\"\n", .{s}),
            .integer => |v| std.debug.print("{d}\n", .{v}),
            .time_ticks => std.debug.print("(this process's uptime, filled in per request)\n", .{}),
            .no_such_instance => std.debug.print("(write-only: an INTEGER here emits a notification)\n", .{}),
            else => std.debug.print("{s}\n", .{@tagName(e.value)}),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// manager mode — what a polling consumer does with `snmp`
// ─────────────────────────────────────────────────────────────────────────────

const ManagerOptions = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = default_agent_port,
    community: []const u8 = "public",
    trap_port: u16 = default_trap_port,
    notify: bool = true,
};

fn runManager(io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var opts: ManagerOptions = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return 0;
        } else if (std.mem.eql(u8, arg, "--no-notify")) {
            opts.notify = false;
        } else if (std.mem.eql(u8, arg, "--host")) {
            opts.host = (try nextValue(args, "--host")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--community")) {
            opts.community = (try nextValue(args, "--community")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = (try parseIntArg(u16, args, "--port")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--trap-port")) {
            opts.trap_port = (try parseIntArg(u16, args, "--trap-port")) orelse return local_failure_exit;
        } else {
            std.debug.print("snmp-demo: unknown manager option '{s}' (try --help)\n", .{arg});
            return local_failure_exit;
        }
    }

    // The notification listener is bound FIRST and stays bound for the whole
    // run. An NMS is a server as much as a client — the device decides when to
    // talk — and binding it after the poll would be a race against the
    // notification the poll asks for.
    var notify_sock: ?std.Io.net.Socket = null;
    defer if (notify_sock) |*s| s.close(io);
    if (opts.notify) {
        const bind_addr = std.Io.net.IpAddress.parse("127.0.0.1", opts.trap_port) catch unreachable;
        notify_sock = bind_addr.bind(io, .{ .mode = .dgram }) catch |err| {
            std.debug.print("snmp-demo: cannot bind the notification port 127.0.0.1:{d}: {t}\n", .{ opts.trap_port, err });
            return local_failure_exit;
        };
        std.debug.print("snmp-demo: listening for notifications on 127.0.0.1:{d} UDP\n", .{opts.trap_port});
    }

    const addr = std.Io.net.IpAddress.parse(opts.host, opts.port) catch |err| {
        std.debug.print("snmp-demo: cannot parse {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return local_failure_exit;
    };

    // `UdpTransport` is the module's own adapter over `std.Io.net`; the seam
    // it implements, `Transport`, is what makes `Client` offline-testable.
    // Anything with a "send one request datagram, receive one reply datagram"
    // shape fits — including the in-memory fake a consumer's CI wants, which
    // never opens a socket.
    //
    // The timeout is not decoration. SNMP is UDP: a lost datagram, a wrong
    // community and a device that is simply off all look identical from here,
    // and a manager with no deadline hangs on every one of them.
    var udp = snmp.UdpTransport.open(io, addr, .{
        .timeout = .{ .duration = .{ .raw = .fromMilliseconds(2000), .clock = .awake } },
    }) catch |err| {
        std.debug.print("snmp-demo: cannot open a UDP socket to {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return local_failure_exit;
    };
    defer udp.close();

    var client = snmp.Client.init(udp.transport(), .{ .version = .v2c });
    std.debug.print("snmp-demo: polling {s}:{d} as v2c, community \"{s}\"\n\n", .{ opts.host, opts.port, opts.community });

    var failures: usize = 0;
    failures += @intFromBool(!readScalars(&client, opts.community));
    failures += @intFromBool(!walkIfDescr(&client, opts.community));
    if (opts.notify) {
        if (!askForNotification(&client, opts.community)) {
            failures += 1;
        } else if (!receiveNotification(io, &notify_sock.?)) {
            failures += 1;
        }
    }

    std.debug.print("\nsnmp-demo: done, {d} step(s) failed\n", .{failures});
    return if (failures == 0) 0 else local_failure_exit;
}

/// Step 1 — the two scalars every inventory starts with.
fn readScalars(client: *snmp.Client, community: []const u8) bool {
    std.debug.print("[1] GetRequest sysDescr.0 + sysUpTime.0, and one instance that is not there\n", .{});
    const sys_descr = snmp.Oid.parse(sys_descr_oid) catch unreachable;
    const sys_uptime = snmp.Oid.parse(sys_uptime_oid) catch unreachable;
    // A third OID no agent implements, in the same request: the interesting
    // case, because it must NOT spoil the other two.
    const absent = snmp.Oid.parse("1.3.6.1.2.1.1.9.9.9") catch unreachable;

    const resp = client.get(community, &.{ sys_descr, sys_uptime, absent }) catch |err|
        return pollFailed("GetRequest", err);

    // A reachable agent that refuses the request is not a transport failure:
    // it answers with a Response PDU carrying an error-status, and the
    // one-based error-index says which varbind was at fault.
    if (resp.error_status != .no_error) {
        std.debug.print("    agent refused: {s} at varbind {d}\n", .{ @tagName(resp.error_status), resp.error_index });
        return false;
    }

    var it = resp.varbinds.iterator();
    while (it.next() catch |err| return pollFailed("varbind decode", err)) |vb| {
        std.debug.print("    {f} = ", .{vb.name});
        switch (vb.value) {
            .octet_string => |s| std.debug.print("\"{s}\"\n", .{s}),
            .time_ticks => |t| std.debug.print("{d}.{d:0>2}s uptime\n", .{ t / 100, t % 100 }),
            // The three v2c exceptions are values, not errors — a poller that
            // treats them as errors drops the rest of a perfectly good reply.
            .no_such_object, .no_such_instance => std.debug.print("(not implemented — a VALUE, not an error)\n", .{}),
            else => std.debug.print("{s}\n", .{@tagName(vb.value)}),
        }
    }
    return true;
}

/// Step 2 — walk the ifDescr column. The walker stops on its own at the
/// subtree edge; the interesting case is the one it cannot recover from.
fn walkIfDescr(client: *snmp.Client, community: []const u8) bool {
    std.debug.print("\n[2] GetNext walk of the ifDescr column {s}\n", .{if_descr_oid});
    const if_descr = snmp.Oid.parse(if_descr_oid) catch unreachable;
    var walk = client.walker(community, if_descr);
    var seen: usize = 0;
    while (walk.next() catch |err| switch (err) {
        // An agent that answers GetNext with an OID that did not advance
        // would spin the walk forever; the module makes that a named error
        // instead, and a poller wants to log the device and move on.
        error.OidNotIncreasing => {
            std.debug.print("    agent violates GetNext ordering, abandoning walk\n", .{});
            return false;
        },
        error.RequestFailed => {
            std.debug.print("    walk rejected mid-subtree\n", .{});
            return false;
        },
        else => return pollFailed("walk", err),
    }) |vb| {
        seen += 1;
        std.debug.print("    interface {f} = \"{s}\"\n", .{ vb.name, vb.value.octet_string });
    }
    std.debug.print("    stopped at the subtree edge after {d} row(s) — the walker knows where\n" ++
        "    ifDescr ends because it compares the returned OID's prefix, not a count\n", .{seen});
    return seen != 0;
}

/// Step 3 — SetRequest. Also the demo's way of asking the device to notify us.
fn askForNotification(client: *snmp.Client, community: []const u8) bool {
    std.debug.print("\n[3] SetRequest {s} = 1 (\"emit a test notification\")\n", .{test_notify_oid});
    const trigger = snmp.Oid.parse(test_notify_oid) catch unreachable;
    const resp = client.set(community, &.{
        .{ .name = trigger, .value = .{ .integer = 1 } },
    }) catch |err| return pollFailed("SetRequest", err);

    if (resp.error_status != .no_error) {
        std.debug.print("    refused: {s} at varbind {d}\n", .{ @tagName(resp.error_status), resp.error_index });
        return false;
    }
    std.debug.print("    accepted\n", .{});
    return true;
}

/// Step 4 — the notification, received and acknowledged.
///
/// This is `receiver`, the module's manager-side ingest: `parseTrap`
/// normalizes a v1 Trap, an SNMPv2-Trap and an InformRequest into one
/// `TrapEvent`, and `ackInform` builds the Response that an Inform — and only
/// an Inform — has to be answered with.
fn receiveNotification(io: std.Io, sock: *std.Io.net.Socket) bool {
    std.debug.print("\n[4] waiting for the notification\n", .{});
    var buf: [max_datagram]u8 = undefined;
    const incoming = sock.receiveTimeout(io, &buf, .{
        .duration = .{ .raw = .fromMilliseconds(5000), .clock = .awake },
    }) catch |err| switch (err) {
        error.Timeout => {
            std.debug.print("    nothing arrived in 5s\n", .{});
            return false;
        },
        else => {
            std.debug.print("    receive failed: {t}\n", .{err});
            return false;
        },
    };
    var peer_buf: [48]u8 = undefined;
    const peer = describeAddr(incoming.from, &peer_buf);

    const event = snmp.parseTrap(incoming.data) catch |err| switch (err) {
        // A well-formed SNMP message that is not a notification. An NMS port
        // gets those — scanners, and managers that misconfigured a target —
        // and dropping them by name beats guessing.
        error.NotATrap => {
            std.debug.print("    {s} sent a well-formed message that is not a notification\n", .{peer});
            return false;
        },
        else => {
            std.debug.print("    {s} sent {d} bytes that do not decode ({t})\n", .{ peer, incoming.data.len, err });
            return false;
        },
    };

    std.debug.print("    {s} kind={s} community=\"{s}\"", .{ peer, @tagName(event.kind), event.community });
    if (event.sysUpTime()) |t| std.debug.print(" sysUpTime={d}.{d:0>2}s", .{ t / 100, t % 100 });
    if (event.snmpTrapOid()) |o| std.debug.print(" snmpTrapOID={f}", .{o});
    std.debug.print("\n", .{});

    // Everything after the two conventional varbinds is the payload: what the
    // device is actually telling us.
    var it = event.varbinds.iterator();
    var index: usize = 0;
    while (it.next() catch null) |vb| : (index += 1) {
        if (index < 2) continue;
        std.debug.print("    payload {f} = {s}\n", .{ vb.name, switch (vb.value) {
            .octet_string => |s| s,
            else => @tagName(vb.value),
        } });
    }

    // A Trap is fire-and-forget; an Inform is not, and answering the wrong one
    // is why `ackInform` refuses anything that is not an Inform rather than
    // encoding a Response nobody asked for.
    if (!event.needsAck()) {
        std.debug.print("    unacknowledged notification — nothing to send back\n", .{});
        return true;
    }
    var ack_buf: [max_datagram]u8 = undefined;
    const ack = snmp.ackInform(event, &ack_buf) catch |err| {
        std.debug.print("    cannot build the acknowledgement: {t}\n", .{err});
        return false;
    };
    sock.send(io, &incoming.from, ack) catch |err| {
        std.debug.print("    cannot send the acknowledgement: {t}\n", .{err});
        return false;
    };
    std.debug.print("    acknowledged: Response rid {?d}, varbinds echoed byte for byte\n", .{event.request_id});
    return true;
}

fn pollFailed(what: []const u8, err: anyerror) bool {
    std.debug.print("    {s} failed: {s}\n", .{
        what,
        switch (err) {
            // The one every SNMP newcomer meets: UDP, so an unreachable agent, a
            // dropped datagram and a refused community are indistinguishable.
            error.Timeout => "Timeout — no answer within the deadline. On UDP that is " ++
                "an agent that is down, a datagram that was lost, or a community it did not accept.",
            error.TransportFailed => "TransportFailed — the socket itself refused the round-trip.",
            // Distinct from TransportFailed on purpose: the request was
            // abandoned by whoever asked for it, so retrying it -- what a
            // poller normally does on the next tick -- is work nobody is
            // waiting for any more. This demo has no retry loop, so the only
            // difference visible here is the message; a real poller must
            // stop instead of scheduling the next attempt.
            error.Canceled => "Canceled — the request was abandoned by its own caller, not by the agent.",
            error.RequestIdMismatch => "RequestIdMismatch — the answer belongs to a different request.",
            error.UnexpectedPduType => "UnexpectedPduType — the peer answered with something that is not a Response.",
            else => @errorName(err),
        },
    });
    return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// plumbing
// ─────────────────────────────────────────────────────────────────────────────

fn describeAddr(addr: std.Io.net.IpAddress, buf: []u8) []const u8 {
    return switch (addr) {
        .ip4 => |a| std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{
            a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3], a.port,
        }) catch "an unprintable address",
        .ip6 => |a| std.fmt.bufPrint(buf, "[ipv6]:{d}", .{a.port}) catch "an unprintable address",
    };
}

fn nextValue(args: *std.process.Args.Iterator, flag: []const u8) !?[]const u8 {
    return args.next() orelse {
        std.debug.print("snmp-demo: {s} needs a value\n", .{flag});
        return null;
    };
}

fn parseIntArg(comptime T: type, args: *std.process.Args.Iterator, flag: []const u8) !?T {
    const text = (try nextValue(args, flag)) orelse return null;
    return std.fmt.parseInt(T, text, 10) catch {
        std.debug.print("snmp-demo: {s} wants a number, got '{s}'\n", .{ flag, text });
        return null;
    };
}
