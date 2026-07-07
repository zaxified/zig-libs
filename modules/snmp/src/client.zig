// SPDX-License-Identifier: MIT

//! Manager-side SNMP client (v1 + v2c) behind a caller-provided `Transport`
//! seam — "send these request bytes, give me the reply bytes" — so every
//! test runs offline from in-memory buffers. `UdpTransport` is an optional
//! real adapter over `std.Io.net` (SNMP is UDP/161); tests never send.

const std = @import("std");
const ber = @import("ber.zig");
const oid_mod = @import("oid.zig");
const message = @import("message.zig");

const Oid = oid_mod.Oid;
const VarBind = message.VarBind;

/// Failures a `Transport` implementation may report.
pub const TransportError = error{ TransportFailed, Timeout };

/// One blocking request/reply round-trip. `exchangeFn` sends `request` and
/// writes the reply datagram into `reply_buf`, returning its length.
pub const Transport = struct {
    ctx: *anyopaque,
    exchangeFn: *const fn (ctx: *anyopaque, request: []const u8, reply_buf: []u8) TransportError!usize,

    pub fn exchange(t: Transport, request: []const u8, reply_buf: []u8) TransportError![]const u8 {
        const n = try t.exchangeFn(t.ctx, request, reply_buf);
        if (n > reply_buf.len) return error.TransportFailed;
        return reply_buf[0..n];
    }
};

/// Size of the client's internal request + reply buffers. Generous for
/// SNMP over UDP (RFC 3416 only requires 484-byte messages to work).
pub const max_message_len = 2048;

/// Upper bound on OIDs per get/getNext/getBulk call.
pub const max_request_oids = 32;

/// Allocation-free SNMP manager. Single-owner: it holds the request-id
/// counter and the message buffers, so one thread/loop drives it. Decoded
/// response varbinds borrow the internal reply buffer and stay valid until
/// the next request.
pub const Client = struct {
    transport: Transport,
    version: message.Version,
    next_request_id: i32,
    request_buf: [max_message_len]u8 = undefined,
    reply_buf: [max_message_len]u8 = undefined,

    pub const Options = struct {
        version: message.Version = .v2c,
        initial_request_id: i32 = 1,
    };

    pub const Error = TransportError || message.DecodeError || message.EncodeError ||
        error{ RequestIdMismatch, UnexpectedPduType, TooManyOids };

    pub const Response = struct {
        error_status: message.ErrorStatus,
        error_index: u32,
        varbinds: message.VarBindList,
    };

    pub fn init(transport: Transport, options: Options) Client {
        return .{
            .transport = transport,
            .version = options.version,
            .next_request_id = options.initial_request_id,
        };
    }

    /// GetRequest for up to `max_request_oids` object instances.
    pub fn get(c: *Client, community: []const u8, oids: []const Oid) Error!Response {
        return c.nullVarBindRequest(.get_request, community, oids, 0, 0);
    }

    /// GetNextRequest — the lexicographic successors of `oids`.
    pub fn getNext(c: *Client, community: []const u8, oids: []const Oid) Error!Response {
        return c.nullVarBindRequest(.get_next_request, community, oids, 0, 0);
    }

    /// GetBulkRequest (v2c only — `error.UnsupportedPdu` on a v1 client).
    pub fn getBulk(
        c: *Client,
        community: []const u8,
        non_repeaters: i32,
        max_repetitions: i32,
        oids: []const Oid,
    ) Error!Response {
        if (c.version != .v2c) return error.UnsupportedPdu;
        return c.nullVarBindRequest(.get_bulk_request, community, oids, non_repeaters, max_repetitions);
    }

    /// SetRequest with fully typed varbinds.
    pub fn set(c: *Client, community: []const u8, varbinds: []const VarBind) Error!Response {
        return c.request(.set_request, community, varbinds, 0, 0);
    }

    /// GetNext-based subtree walk. The yielded varbind (and any slice value
    /// in it) is valid until the walker's next step.
    pub fn walker(c: *Client, community: []const u8, root: Oid) Walker {
        return .{ .client = c, .community = community, .root = root, .current = root };
    }

    fn nullVarBindRequest(
        c: *Client,
        pdu_type: message.PduType,
        community: []const u8,
        oids: []const Oid,
        f1: i32,
        f2: i32,
    ) Error!Response {
        if (oids.len > max_request_oids) return error.TooManyOids;
        var vbs: [max_request_oids]VarBind = undefined;
        for (oids, 0..) |o, i| vbs[i] = .{ .name = o, .value = .null };
        return c.request(pdu_type, community, vbs[0..oids.len], f1, f2);
    }

    fn request(
        c: *Client,
        pdu_type: message.PduType,
        community: []const u8,
        varbinds: []const VarBind,
        f1: i32,
        f2: i32,
    ) Error!Response {
        const rid = c.allocRequestId();
        const wire = try message.encode(&c.request_buf, c.version, community, .{
            .type = pdu_type,
            .request_id = rid,
            .error_status = f1,
            .error_index = f2,
            .varbinds = varbinds,
        });
        const reply = try c.transport.exchange(wire, &c.reply_buf);
        const msg = try message.decode(reply);
        const pdu = switch (msg.pdu) {
            .response => |p| p,
            else => return error.UnexpectedPduType,
        };
        if (pdu.request_id != rid) return error.RequestIdMismatch;
        return .{
            .error_status = pdu.error_status,
            .error_index = pdu.error_index,
            .varbinds = pdu.varbinds,
        };
    }

    fn allocRequestId(c: *Client) i32 {
        const rid = c.next_request_id;
        c.next_request_id = if (rid == std.math.maxInt(i32)) 1 else rid + 1;
        return rid;
    }
};

/// Repeated-GetNext subtree iterator. Ends cleanly on endOfMibView (v2c),
/// noSuchName (v1), or the first name outside the root subtree; an agent
/// that fails to advance the OID is a typed error (loop guard).
pub const Walker = struct {
    client: *Client,
    community: []const u8,
    root: Oid,
    current: Oid,
    finished: bool = false,

    pub const Error = Client.Error || error{ OidNotIncreasing, RequestFailed };

    pub fn next(w: *Walker) Error!?VarBind {
        if (w.finished) return null;
        const resp = try w.client.getNext(w.community, &.{w.current});
        if (resp.error_status == .no_such_name) {
            // v1 agents signal "walked off the end of the MIB" this way.
            w.finished = true;
            return null;
        }
        if (resp.error_status != .no_error) {
            w.finished = true;
            return error.RequestFailed;
        }
        var it = resp.varbinds.iterator();
        const vb = (try it.next()) orelse {
            w.finished = true;
            return null;
        };
        switch (vb.value) {
            .end_of_mib_view => {
                w.finished = true;
                return null;
            },
            else => {},
        }
        if (!vb.name.startsWith(&w.root)) {
            w.finished = true;
            return null;
        }
        if (vb.name.order(&w.current) != .gt) {
            w.finished = true;
            return error.OidNotIncreasing;
        }
        w.current = vb.name;
        return vb;
    }
};

// ── optional real transport: SNMP over UDP via std.Io.net ───────────────────

/// Blocking UDP transport (default agent port 161). Gated behind explicit
/// `open` with a runtime `std.Io` — nothing in the test suite constructs
/// one, so tests never touch the network.
pub const UdpTransport = struct {
    io: std.Io,
    socket: std.Io.net.Socket,
    peer: std.Io.net.IpAddress,
    timeout: std.Io.Timeout,

    pub const Options = struct {
        /// Reply deadline; `.none` blocks indefinitely.
        timeout: std.Io.Timeout = .none,
    };

    pub fn open(io: std.Io, peer: std.Io.net.IpAddress, options: Options) !UdpTransport {
        const local: std.Io.net.IpAddress = switch (peer) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        const socket = try local.bind(io, .{ .mode = .dgram });
        return .{ .io = io, .socket = socket, .peer = peer, .timeout = options.timeout };
    }

    pub fn close(t: *UdpTransport) void {
        t.socket.close(t.io);
    }

    pub fn transport(t: *UdpTransport) Transport {
        return .{ .ctx = t, .exchangeFn = exchangeFn };
    }

    fn exchangeFn(ctx: *anyopaque, request: []const u8, reply_buf: []u8) TransportError!usize {
        const t: *UdpTransport = @ptrCast(@alignCast(ctx));
        t.socket.send(t.io, &t.peer, request) catch return error.TransportFailed;
        const incoming = t.socket.receiveTimeout(t.io, reply_buf, t.timeout) catch |err| switch (err) {
            error.Timeout => return error.Timeout,
            else => return error.TransportFailed,
        };
        if (incoming.flags.trunc) return error.TransportFailed;
        return incoming.data.len;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Scripted in-memory agent: decodes the request, echoes its request-id
/// (plus an optional offset) and replies with configured varbinds/status.
const FakeAgent = struct {
    values: []const VarBind = &.{},
    error_status: i32 = 0,
    error_index: i32 = 0,
    rid_offset: i32 = 0,
    reply_pdu_type: message.PduType = .response,
    reply_garbage: bool = false,
    requests_seen: usize = 0,
    last_request_varbinds: usize = 0,

    fn transport(a: *FakeAgent) Transport {
        return .{ .ctx = a, .exchangeFn = exchangeFn };
    }

    fn exchangeFn(ctx: *anyopaque, request: []const u8, reply_buf: []u8) TransportError!usize {
        const a: *FakeAgent = @ptrCast(@alignCast(ctx));
        a.requests_seen += 1;
        if (a.reply_garbage) {
            const junk = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
            @memcpy(reply_buf[0..junk.len], &junk);
            return junk.len;
        }
        const msg = message.decode(request) catch return error.TransportFailed;
        const rid = switch (msg.pdu) {
            .get_request, .get_next_request, .response, .set_request, .inform_request, .trap_v2 => |p| blk: {
                a.last_request_varbinds = p.varbinds.count() catch return error.TransportFailed;
                break :blk p.request_id;
            },
            .get_bulk_request => |p| blk: {
                a.last_request_varbinds = p.varbinds.count() catch return error.TransportFailed;
                break :blk p.request_id;
            },
            .trap_v1 => return error.TransportFailed,
        };
        const out = message.encode(reply_buf, msg.version, msg.community, .{
            .type = a.reply_pdu_type,
            .request_id = rid +% a.rid_offset,
            .error_status = a.error_status,
            .error_index = a.error_index,
            .varbinds = a.values,
        }) catch return error.TransportFailed;
        // The encoder writes to the end of the buffer; the seam contract is
        // "reply occupies reply_buf[0..n]".
        std.mem.copyForwards(u8, reply_buf[0..out.len], out);
        return out.len;
    }
};

test "get round-trip: request-id matched, varbinds parsed" {
    var agent: FakeAgent = .{
        .values = &.{
            .{ .name = try Oid.parse("1.3.6.1.2.1.1.1.0"), .value = .{ .octet_string = "zig agent" } },
        },
    };
    var client = Client.init(agent.transport(), .{});
    const resp = try client.get("public", &.{try Oid.parse("1.3.6.1.2.1.1.1.0")});
    try testing.expectEqual(message.ErrorStatus.no_error, resp.error_status);
    var it = resp.varbinds.iterator();
    const vb = (try it.next()).?;
    try testing.expectEqualStrings("zig agent", vb.value.octet_string);
    try testing.expectEqual(@as(?VarBind, null), try it.next());
    try testing.expectEqual(@as(usize, 1), agent.last_request_varbinds);

    // Request ids advance per request.
    _ = try client.get("public", &.{try Oid.parse("1.3.6.1.2.1.1.1.0")});
    try testing.expectEqual(@as(i32, 3), client.next_request_id);
}

test "mismatched request-id -> RequestIdMismatch" {
    var agent: FakeAgent = .{ .rid_offset = 1 };
    var client = Client.init(agent.transport(), .{});
    try testing.expectError(
        error.RequestIdMismatch,
        client.get("public", &.{try Oid.parse("1.3.6.1.2.1.1.1.0")}),
    );
}

test "reply with a non-Response PDU -> UnexpectedPduType" {
    var agent: FakeAgent = .{ .reply_pdu_type = .get_request };
    var client = Client.init(agent.transport(), .{});
    try testing.expectError(
        error.UnexpectedPduType,
        client.get("public", &.{try Oid.parse("1.3.6.1.2.1.1.1.0")}),
    );
}

test "garbage reply bytes -> typed decode error, no panic" {
    var agent: FakeAgent = .{ .reply_garbage = true };
    var client = Client.init(agent.transport(), .{});
    try testing.expectError(
        error.LengthOverflow,
        client.get("public", &.{try Oid.parse("1.3.6.1.2.1.1.1.0")}),
    );
}

test "getBulk returns multiple varbinds; rejected on a v1 client" {
    var agent: FakeAgent = .{
        .values = &.{
            .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.1"), .value = .{ .octet_string = "eth0" } },
            .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.2"), .value = .{ .octet_string = "eth1" } },
            .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.10.1"), .value = .{ .counter32 = 1234 } },
        },
    };
    var client = Client.init(agent.transport(), .{});
    const resp = try client.getBulk("public", 0, 10, &.{try Oid.parse("1.3.6.1.2.1.2.2")});
    try testing.expectEqual(@as(usize, 3), try resp.varbinds.count());
    var vbs: [4]VarBind = undefined;
    const got = try resp.varbinds.collect(&vbs);
    try testing.expectEqualStrings("eth1", got[1].value.octet_string);
    try testing.expectEqual(@as(u32, 1234), got[2].value.counter32);

    var v1_client = Client.init(agent.transport(), .{ .version = .v1 });
    try testing.expectError(
        error.UnsupportedPdu,
        v1_client.getBulk("public", 0, 10, &.{try Oid.parse("1.3.6.1.2.1.2.2")}),
    );
}

test "set round-trip and error-status surfacing" {
    var agent: FakeAgent = .{ .error_status = 4, .error_index = 1 }; // readOnly(4)
    var client = Client.init(agent.transport(), .{});
    const resp = try client.set("private", &.{
        .{ .name = try Oid.parse("1.3.6.1.2.1.1.6.0"), .value = .{ .octet_string = "dc1" } },
    });
    try testing.expectEqual(message.ErrorStatus.read_only, resp.error_status);
    try testing.expectEqual(@as(u32, 1), resp.error_index);
    try testing.expectEqual(@as(usize, 1), agent.last_request_varbinds);
}

test "too many oids -> TooManyOids without touching the transport" {
    var agent: FakeAgent = .{};
    var client = Client.init(agent.transport(), .{});
    var oids: [max_request_oids + 1]Oid = @splat(try Oid.parse("1.3.6.1"));
    try testing.expectError(error.TooManyOids, client.get("public", &oids));
    try testing.expectEqual(@as(usize, 0), agent.requests_seen);
}

/// GetNext semantics over a sorted table, for walk tests.
const WalkAgent = struct {
    table: []const VarBind,
    v1_style_end: bool = false,

    fn transport(a: *WalkAgent) Transport {
        return .{ .ctx = a, .exchangeFn = exchangeFn };
    }

    fn exchangeFn(ctx: *anyopaque, request: []const u8, reply_buf: []u8) TransportError!usize {
        const a: *WalkAgent = @ptrCast(@alignCast(ctx));
        const msg = message.decode(request) catch return error.TransportFailed;
        const pdu = switch (msg.pdu) {
            .get_next_request => |p| p,
            else => return error.TransportFailed,
        };
        var it = pdu.varbinds.iterator();
        const asked = (it.next() catch return error.TransportFailed) orelse
            return error.TransportFailed;

        var reply: message.EncodePdu = .{
            .type = .response,
            .request_id = pdu.request_id,
        };
        var successor: ?*const VarBind = null;
        for (a.table) |*entry| {
            if (entry.name.order(&asked.name) == .gt) {
                successor = entry;
                break;
            }
        }
        var end_vb: [1]VarBind = undefined;
        if (successor) |vb| {
            reply.varbinds = vb[0..1];
        } else if (a.v1_style_end) {
            reply.error_status = 2; // noSuchName
            reply.error_index = 1;
        } else {
            end_vb[0] = .{ .name = asked.name, .value = .end_of_mib_view };
            reply.varbinds = &end_vb;
        }
        const out = message.encode(reply_buf, msg.version, msg.community, reply) catch
            return error.TransportFailed;
        std.mem.copyForwards(u8, reply_buf[0..out.len], out);
        return out.len;
    }
};

fn ifDescrTable() ![3]VarBind {
    return .{
        .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.1"), .value = .{ .octet_string = "lo" } },
        .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.2"), .value = .{ .octet_string = "eth0" } },
        .{ .name = try Oid.parse("1.3.6.1.2.1.31.1.1.1.1.1"), .value = .{ .octet_string = "lo" } },
    };
}

test "walk stays inside the subtree and stops at the boundary" {
    const table = try ifDescrTable();
    var agent: WalkAgent = .{ .table = &table };
    var client = Client.init(agent.transport(), .{});

    var w = client.walker("public", try Oid.parse("1.3.6.1.2.1.2.2.1.2"));
    var seen: usize = 0;
    while (try w.next()) |vb| {
        seen += 1;
        try testing.expect(vb.value == .octet_string);
    }
    try testing.expectEqual(@as(usize, 2), seen); // stops before ...31.1.1.1.1.1
    try testing.expectEqual(@as(?VarBind, null), try w.next()); // stays finished
}

test "walk ends on endOfMibView and on v1 noSuchName" {
    const table = try ifDescrTable();

    var agent: WalkAgent = .{ .table = table[2..] };
    var client = Client.init(agent.transport(), .{});
    var w = client.walker("public", try Oid.parse("1.3.6.1.2.1.31"));
    try testing.expect((try w.next()) != null);
    try testing.expectEqual(@as(?VarBind, null), try w.next()); // endOfMibView

    var v1_agent: WalkAgent = .{ .table = table[2..], .v1_style_end = true };
    var v1_client = Client.init(v1_agent.transport(), .{ .version = .v1 });
    var w1 = v1_client.walker("public", try Oid.parse("1.3.6.1.2.1.31"));
    try testing.expect((try w1.next()) != null);
    try testing.expectEqual(@as(?VarBind, null), try w1.next()); // noSuchName
}

test "walk detects a non-advancing agent -> OidNotIncreasing" {
    const stuck = [_]VarBind{
        .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.1"), .value = .{ .integer = 1 } },
    };
    // Agent always returns the same varbind, whatever is asked.
    const StuckAgent = struct {
        fn exchangeFn(ctx: *anyopaque, request: []const u8, reply_buf: []u8) TransportError!usize {
            const entry: *const VarBind = @ptrCast(@alignCast(ctx));
            const msg = message.decode(request) catch return error.TransportFailed;
            const pdu = switch (msg.pdu) {
                .get_next_request => |p| p,
                else => return error.TransportFailed,
            };
            const out = message.encode(reply_buf, msg.version, msg.community, .{
                .type = .response,
                .request_id = pdu.request_id,
                .varbinds = entry[0..1],
            }) catch return error.TransportFailed;
            std.mem.copyForwards(u8, reply_buf[0..out.len], out);
            return out.len;
        }
    };
    var client = Client.init(
        .{ .ctx = @ptrCast(@constCast(&stuck[0])), .exchangeFn = StuckAgent.exchangeFn },
        .{},
    );
    var w = client.walker("public", try Oid.parse("1.3.6.1.2.1.2.2.1.2"));
    _ = try w.next(); // first result (root -> .1) is fine
    try testing.expectError(error.OidNotIncreasing, w.next());
}

test "UdpTransport compiles (never sends in tests)" {
    testing.refAllDecls(UdpTransport);
}
