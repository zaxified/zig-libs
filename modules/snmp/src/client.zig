// SPDX-License-Identifier: MIT

//! Manager-side SNMP client (v1 + v2c) behind a caller-provided `Transport`
//! seam — "send these request bytes, give me the reply bytes" — so every
//! test runs offline from in-memory buffers. `UdpTransport` is an optional
//! real adapter over `std.Io.net` (SNMP is UDP/161); tests never send.

const std = @import("std");
const testkit = @import("testkit");
const ber = @import("ber.zig");
const oid_mod = @import("oid.zig");
const message = @import("message.zig");

const Oid = oid_mod.Oid;
const VarBind = message.VarBind;

/// Failures a `Transport` implementation may report.
pub const TransportError = error{
    TransportFailed,
    Timeout,
    /// The caller canceled the request while it was waiting on the socket.
    /// Distinct from `TransportFailed` on purpose: a consumer that folds the
    /// two together retries a request its own caller already abandoned, and
    /// reports a healthy agent as a dead one. Unlike a buffered
    /// `Io.Reader`/`Io.Writer` (whose error sets cannot carry this),
    /// `std.Io.net.Socket.send`/`.receiveTimeout` report it directly — see
    /// `UdpTransport.exchangeFn`.
    Canceled,
};

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
    /// Re-sends of one request after a per-try `error.Timeout` (or after a
    /// reply carrying another request id). See `Options.retries`.
    retries: u8,
    request_buf: [max_message_len]u8 = undefined,
    reply_buf: [max_message_len]u8 = undefined,

    pub const Options = struct {
        version: message.Version = .v2c,
        initial_request_id: i32 = 1,
        /// How many times a request is re-sent (same request id) after the
        /// transport reports `error.Timeout`, or after a reply with another
        /// request id arrives; total tries = `retries + 1`. The per-try
        /// timeout is the transport's own (`UdpTransport.Options.timeout`).
        /// Default 5, net-snmp's default (`-r 5`; its default timeout is
        /// 1 s, which the caller sets on the transport: `UdpTransport`
        /// itself defaults to `.none`, i.e. it blocks, so no retry ever
        /// happens until a timeout is set). Because the id is reused, a late
        /// reply to an earlier try is accepted by a later try. Set 0 for the
        /// old single-shot behaviour.
        retries: u8 = 5,
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
            .retries = options.retries,
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

    /// GetBulk-driven subtree walk (v2c only; on a v1 client `next` returns
    /// `error.UnsupportedPdu`). Uses `default_max_repetitions`.
    pub fn bulkWalker(c: *Client, community: []const u8, root: Oid) BulkWalker {
        return c.bulkWalkerWith(community, root, default_max_repetitions);
    }

    /// As `bulkWalker` with an explicit max-repetitions (>= 1; 0 makes `next`
    /// return `error.InvalidMaxRepetitions`).
    pub fn bulkWalkerWith(c: *Client, community: []const u8, root: Oid, max_repetitions: u16) BulkWalker {
        return .{
            .client = c,
            .community = community,
            .root = root,
            .current = root,
            .max_repetitions = max_repetitions,
        };
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
        // Retry loop: only a Timeout or a stale-id reply is retried; every
        // other failure (transport error, cancel, undecodable bytes, wrong
        // PDU type) is returned at once. After the last try the error of
        // that try is returned.
        var last: Error = error.Timeout;
        var attempt: u32 = 0;
        while (attempt <= c.retries) : (attempt += 1) {
            const reply = c.transport.exchange(wire, &c.reply_buf) catch |err| switch (err) {
                error.Timeout => {
                    last = error.Timeout;
                    continue;
                },
                else => return err,
            };
            const msg = try message.decode(reply);
            const pdu = switch (msg.pdu) {
                .response => |p| p,
                else => return error.UnexpectedPduType,
            };
            if (pdu.request_id != rid) {
                last = error.RequestIdMismatch;
                continue;
            }
            return .{
                .error_status = pdu.error_status,
                .error_index = pdu.error_index,
                .varbinds = pdu.varbinds,
            };
        }
        return last;
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

    // secret-api-ok: iterator over `Client.getNext`; a v1/v2c community string travels in clear by design (no key derivation or cipher here).
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

/// Default GETBULK max-repetitions for `bulkWalker`; net-snmp's
/// `snmpbulkwalk -Cr` default.
pub const default_max_repetitions: u16 = 10;

/// GetBulk-driven subtree iterator: one round trip yields up to
/// `max_repetitions` rows. Same stop rules as `Walker` (end of the subtree,
/// endOfMibView, noSuchName, an empty reply) plus the loop guard: a name that
/// is not strictly greater than the previous one is `error.OidNotIncreasing`.
/// A yielded varbind is valid until the walker's next step that fetches.
pub const BulkWalker = struct {
    client: *Client,
    community: []const u8,
    root: Oid,
    current: Oid,
    max_repetitions: u16,
    batch: ?message.VarBindList.Iterator = null,
    batch_yielded: bool = false,
    finished: bool = false,

    pub const Error = Client.Error || error{ OidNotIncreasing, RequestFailed, InvalidMaxRepetitions };

    // secret-api-ok: iterator over `Client.getBulk`; a v1/v2c community string travels in clear by design (no key derivation or cipher here).
    pub fn next(w: *BulkWalker) BulkWalker.Error!?VarBind {
        return w.step() catch |err| {
            w.finished = true; // never loop on a failing agent
            return err;
        };
    }

    fn step(w: *BulkWalker) BulkWalker.Error!?VarBind {
        while (true) {
            if (w.finished) return null;
            if (w.batch == null) {
                if (w.max_repetitions == 0) return error.InvalidMaxRepetitions;
                const resp = try w.client.getBulk(w.community, 0, w.max_repetitions, &.{w.current});
                if (resp.error_status == .no_such_name) {
                    w.finished = true;
                    return null;
                }
                if (resp.error_status != .no_error) return error.RequestFailed;
                w.batch = resp.varbinds.iterator();
                w.batch_yielded = false;
            }
            const vb = (try w.batch.?.next()) orelse {
                // Batch used up. An empty batch means nothing follows.
                if (!w.batch_yielded) w.finished = true;
                w.batch = null;
                continue;
            };
            if (vb.value == .end_of_mib_view or !vb.name.startsWith(&w.root)) {
                w.finished = true;
                return null;
            }
            if (vb.name.order(&w.current) != .gt) return error.OidNotIncreasing;
            w.current = vb.name;
            w.batch_yielded = true;
            return vb;
        }
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
        t.socket.send(t.io, &t.peer, request) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            else => error.TransportFailed,
        };
        const incoming = t.socket.receiveTimeout(t.io, reply_buf, t.timeout) catch |err| switch (err) {
            error.Timeout => return error.Timeout,
            error.Canceled => return error.Canceled,
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
            .get_request,
            .get_next_request,
            .response,
            .set_request,
            .inform_request,
            .trap_v2,
            .report,
            => |p| blk: {
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

/// Scripted transport for retry tests: per call, either time out, answer
/// with a wrong id, or answer properly (echoing the request's id).
const RetryAgent = struct {
    const Act = enum { timeout, wrong_id, ok, canceled };
    script: []const Act,
    calls: usize = 0,
    ids: [16]i32 = undefined,
    wires_equal: bool = true,
    first_wire: [256]u8 = undefined,
    first_len: usize = 0,

    fn exchangeFn(ctx: *anyopaque, request: []const u8, reply_buf: []u8) TransportError!usize {
        const a: *RetryAgent = @ptrCast(@alignCast(ctx));
        const act = a.script[@min(a.calls, a.script.len - 1)];
        const msg = message.decode(request) catch return error.TransportFailed;
        const rid = msg.pdu.get_request.request_id;
        a.ids[a.calls] = rid;
        if (a.calls == 0) {
            @memcpy(a.first_wire[0..request.len], request);
            a.first_len = request.len;
        } else if (!std.mem.eql(u8, a.first_wire[0..a.first_len], request)) a.wires_equal = false;
        a.calls += 1;
        switch (act) {
            .timeout => return error.Timeout,
            .canceled => return error.Canceled,
            .wrong_id, .ok => {},
        }
        var it = msg.pdu.get_request.varbinds.iterator();
        const asked = (it.next() catch return error.TransportFailed) orelse return error.TransportFailed;
        const vbs = [_]VarBind{.{ .name = asked.name, .value = .{ .integer = 7 } }};
        const out = message.encode(reply_buf, msg.version, msg.community, .{
            .type = .response,
            .request_id = if (act == .wrong_id) rid +% 1 else rid,
            .varbinds = &vbs,
        }) catch return error.TransportFailed;
        std.mem.copyForwards(u8, reply_buf[0..out.len], out);
        return out.len;
    }
};

fn retryClient(a: *RetryAgent, retries: u8) Client {
    return Client.init(.{ .ctx = a, .exchangeFn = RetryAgent.exchangeFn }, .{ .retries = retries });
}

test "retry: default is net-snmp's 5 retries" {
    var a: RetryAgent = .{ .script = &.{.ok} };
    try testing.expectEqual(@as(u8, 5), retryClient(&a, 5).retries);
    try testing.expectEqual(@as(u8, 5), Client.init(.{ .ctx = &a, .exchangeFn = RetryAgent.exchangeFn }, .{}).retries);
}

test "retry: timeouts re-send the identical request (same id) until a reply arrives" {
    var a: RetryAgent = .{ .script = &.{ .timeout, .timeout, .ok } };
    var c = retryClient(&a, 5);
    const resp = try c.get("public", &.{try Oid.parse("1.3.6.1.2.1.1.1.0")});
    try testing.expectEqual(@as(usize, 3), a.calls);
    try testing.expectEqual(a.ids[0], a.ids[1]);
    try testing.expectEqual(a.ids[0], a.ids[2]);
    try testing.expect(a.wires_equal);
    var it = resp.varbinds.iterator();
    try testing.expectEqual(@as(i32, 7), (try it.next()).?.value.integer);
    // The next request gets a fresh id.
    try testing.expectEqual(a.ids[0] + 1, c.next_request_id);
}

test "retry: exhausted retries -> Timeout after retries + 1 tries" {
    var a: RetryAgent = .{ .script = &.{.timeout} };
    var c = retryClient(&a, 3);
    try testing.expectError(error.Timeout, c.get("public", &.{try Oid.parse("1.3.6.1.2.1.1.1.0")}));
    try testing.expectEqual(@as(usize, 4), a.calls);

    var a0: RetryAgent = .{ .script = &.{.timeout} };
    var c0 = retryClient(&a0, 0);
    try testing.expectError(error.Timeout, c0.get("public", &.{try Oid.parse("1.3.6.1.2.1.1.1.0")}));
    try testing.expectEqual(@as(usize, 1), a0.calls);
}

test "retry: a reply with another id is ignored, the next try can succeed" {
    var a: RetryAgent = .{ .script = &.{ .wrong_id, .ok } };
    var c = retryClient(&a, 5);
    _ = try c.get("public", &.{try Oid.parse("1.3.6.1.2.1.1.1.0")});
    try testing.expectEqual(@as(usize, 2), a.calls);

    // Only wrong ids until the budget ends: the mismatch is reported.
    var b: RetryAgent = .{ .script = &.{.wrong_id} };
    var cb = retryClient(&b, 2);
    try testing.expectError(error.RequestIdMismatch, cb.get("public", &.{try Oid.parse("1.3.6.1.2.1.1.1.0")}));
    try testing.expectEqual(@as(usize, 3), b.calls);
}

test "retry: Canceled and transport failures are never retried" {
    var a: RetryAgent = .{ .script = &.{.canceled} };
    var c = retryClient(&a, 5);
    try testing.expectError(error.Canceled, c.get("public", &.{try Oid.parse("1.3.6.1.2.1.1.1.0")}));
    try testing.expectEqual(@as(usize, 1), a.calls);
}

/// GETBULK semantics over a sorted table: up to max_repetitions successors
/// of the single asked OID; an exhausted table ends with endOfMibView.
const BulkAgent = struct {
    table: []const VarBind,
    calls: usize = 0,
    last_max_rep: u32 = 0,
    /// Debug knob: ignore the asked OID and always start at table[0].
    stuck: bool = false,

    fn transport(a: *BulkAgent) Transport {
        return .{ .ctx = a, .exchangeFn = exchangeFn };
    }

    fn exchangeFn(ctx: *anyopaque, request: []const u8, reply_buf: []u8) TransportError!usize {
        const a: *BulkAgent = @ptrCast(@alignCast(ctx));
        const msg = message.decode(request) catch return error.TransportFailed;
        const pdu = switch (msg.pdu) {
            .get_bulk_request => |p| p,
            else => return error.TransportFailed,
        };
        a.calls += 1;
        a.last_max_rep = pdu.max_repetitions;
        var it = pdu.varbinds.iterator();
        const asked = (it.next() catch return error.TransportFailed) orelse return error.TransportFailed;
        var out_vbs: [64]VarBind = undefined;
        var n: usize = 0;
        for (a.table) |*entry| {
            if (n >= pdu.max_repetitions) break;
            if (a.stuck or entry.name.order(&asked.name) == .gt) {
                out_vbs[n] = entry.*;
                n += 1;
            }
        }
        if (n == 0) {
            out_vbs[0] = .{ .name = asked.name, .value = .end_of_mib_view };
            n = 1;
        }
        const out = message.encode(reply_buf, msg.version, msg.community, .{
            .type = .response,
            .request_id = pdu.request_id,
            .varbinds = out_vbs[0..n],
        }) catch return error.TransportFailed;
        std.mem.copyForwards(u8, reply_buf[0..out.len], out);
        return out.len;
    }
};

fn bigTable() ![6]VarBind {
    return .{
        .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.1"), .value = .{ .octet_string = "a" } },
        .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.2"), .value = .{ .octet_string = "b" } },
        .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.3"), .value = .{ .octet_string = "c" } },
        .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.4"), .value = .{ .octet_string = "d" } },
        .{ .name = try Oid.parse("1.3.6.1.2.1.2.2.1.2.5"), .value = .{ .octet_string = "e" } },
        .{ .name = try Oid.parse("1.3.6.1.2.1.31.1.1.1.1.1"), .value = .{ .octet_string = "x" } },
    };
}

test "bulkWalker: batches rows, stops at the subtree end with fewer round trips" {
    const table = try bigTable();
    var agent: BulkAgent = .{ .table = &table };
    var client = Client.init(agent.transport(), .{});
    var w = client.bulkWalkerWith("public", try Oid.parse("1.3.6.1.2.1.2.2.1.2"), 3);
    var seen: usize = 0;
    while (try w.next()) |vb| {
        seen += 1;
        try testing.expect(vb.value == .octet_string);
    }
    try testing.expectEqual(@as(usize, 5), seen);
    try testing.expectEqual(@as(u32, 3), agent.last_max_rep);
    // 5 rows in the subtree: batch of 3, batch (2 + one foreign row ends it).
    try testing.expectEqual(@as(usize, 2), agent.calls);
    try testing.expectEqual(@as(?VarBind, null), try w.next()); // stays finished
}

test "bulkWalker: default max-repetitions; ends on endOfMibView and empty subtree" {
    const table = try bigTable();
    var agent: BulkAgent = .{ .table = table[5..] };
    var client = Client.init(agent.transport(), .{});
    var w = client.bulkWalker("public", try Oid.parse("1.3.6.1.2.1.31"));
    try testing.expect((try w.next()) != null);
    try testing.expectEqual(@as(?VarBind, null), try w.next()); // endOfMibView
    try testing.expectEqual(@as(u32, default_max_repetitions), agent.last_max_rep);

    // Nothing under the root at all: first batch's endOfMibView ends it.
    var w2 = client.bulkWalker("public", try Oid.parse("1.3.6.1.4.1"));
    try testing.expectEqual(@as(?VarBind, null), try w2.next());
}

test "bulkWalker: non-increasing agent -> OidNotIncreasing; v1 and zero repetitions rejected" {
    const table = try bigTable();
    var agent: BulkAgent = .{ .table = &table, .stuck = true };
    var client = Client.init(agent.transport(), .{});
    var w = client.bulkWalkerWith("public", try Oid.parse("1.3.6.1.2.1.2.2.1.2"), 2);
    // First batch (a, b) is fine; the second restarts at a -> not increasing.
    try testing.expect((try w.next()) != null);
    try testing.expect((try w.next()) != null);
    try testing.expectError(error.OidNotIncreasing, w.next());
    try testing.expectEqual(@as(?VarBind, null), try w.next()); // no further loop

    var v1 = Client.init(agent.transport(), .{ .version = .v1 });
    var w1 = v1.bulkWalker("public", try Oid.parse("1.3.6.1.2.1.2.2.1.2"));
    try testing.expectError(error.UnsupportedPdu, w1.next());

    var w0 = client.bulkWalkerWith("public", try Oid.parse("1.3.6.1.2.1.2.2.1.2"), 0);
    const calls_before = agent.calls;
    try testing.expectError(error.InvalidMaxRepetitions, w0.next());
    try testing.expectEqual(calls_before, agent.calls);
}

test "UdpTransport compiles (never sends in tests)" {
    testing.refAllDecls(UdpTransport);
}

// -- test (cancellation, loopback) -----------------------------------------
//
// Mirrors the sibling `whois` module's loopback cancelation test. The peer
// socket below is bound and reachable (so the request is not bounced by an
// ICMP port-unreachable) but never sends a reply, so the read under test is
// genuinely parked in the kernel -- the shape that used to come back as
// `TransportFailed` and make a consumer retry a request its own caller had
// already abandoned.

fn exchangeOnce(t: Transport, request: []const u8, reply_buf: []u8) TransportError![]const u8 {
    return t.exchange(request, reply_buf);
}

test "UdpTransport: a canceled receive surfaces error.Canceled, not error.TransportFailed" {
    var threaded: std.Io.Threaded = .init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const peer_addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var peer_socket = peer_addr.bind(io, .{ .mode = .dgram }) catch |err| {
        return testkit.loopbackSkip("snmp cancel test bind failed ({t})", .{err});
    };
    defer peer_socket.close(io);
    const peer_port = peer_socket.address.getPort();

    var udp = try UdpTransport.open(io, try std.Io.net.IpAddress.parse("127.0.0.1", peer_port), .{});
    defer udp.close();

    var reply_buf: [max_message_len]u8 = undefined;
    var fut = try io.concurrent(exchangeOnce, .{ udp.transport(), "probe", &reply_buf });
    // Cancel once the request has ARRIVED at the peer: the send is done, so
    // the only cancelation point left is the reply receive. After a fixed
    // sleep, a loaded machine could cancel the send instead, and the test
    // passed by the send's `Canceled` arm. The 60 s is a watchdog only.
    var probe_buf: [64]u8 = undefined;
    const arrived = if (peer_socket.receiveTimeout(io, &probe_buf, .{ .duration = .{
        .raw = .fromMilliseconds(60_000),
        .clock = .awake,
    } })) |_| true else |_| false;
    const result = fut.cancel(io);
    try testing.expect(arrived);
    try testing.expectError(error.Canceled, result);
}
