// SPDX-License-Identifier: MIT

//! s7comm — pure-Zig **Siemens S7 communication over ISO-on-TCP**: the
//! protocol STEP 7, WinCC and every third-party S7 driver speak to S7-300,
//! S7-400, S7-1200 and S7-1500 CPUs on TCP port 102.
//!
//! Six layers, each usable on its own:
//!
//! * **`tpkt`** (RFC 1006 §6) — the four-octet shim that carries an ISO
//!   transport service over TCP, plus a stream `Framer`, because TCP delivers
//!   no message boundaries. Its length field counts **itself**.
//! * **`cotp`** (ISO 8073 class 0) — `CR`/`CC` connection setup, `DT` data
//!   with its TPDU number and EOT bit, `DR`/`ER`. **Rack and slot are not
//!   protocol fields**: they live inside the destination TSAP as
//!   `{connection type, rack * 0x20 + slot}`, which is what `cotp.Tsap`
//!   models explicitly.
//! * **`s7`** — the S7comm header (protocol id `0x32`, ROSCTR, redundancy id,
//!   PDU reference, parameter and data lengths, and for an Ack/Ack-Data the
//!   two extra error octets, which is why the header is 10 octets for a
//!   request and 12 for a reply), plus `Setup communication` and the
//!   negotiated PDU length that bounds everything after it.
//! * **`items` / `vars`** — Read Var and Write Var: the `S7ANY` item
//!   specification (area, DB number, transport size, count and the **three
//!   address octets that are a bit address**, `byte * 8 + bit`), multi-item
//!   requests, per-item return codes, and the data block whose length field is
//!   counted in **bits or octets depending on the transport size**, with an
//!   arbitrary pad octet between items.
//! * **`userdata`** — the second request shape: the Userdata sub-header and
//!   `Read SZL` (system status list) for CPU and module identification.
//! * **`address`** — the STEP 7 notation every S7 tool takes: `DB1.DBW20`,
//!   `M10.2`, `I0.0`, `QB4`, `T5`, `C3`, `PIW256`.
//!
//! On top of those, a `client` (connect, typed reads and writes, SZL, PLC
//! control) and a `server` responder that doubles as a fleet-simulation
//! target.
//!
//! Verified against **real traffic between two independent third-party
//! implementations** and by **live round trips in both directions**; see
//! `goldens.zig` and SPEC.md for exactly which frames came from where.
//!
//! Provenance: clean-room from the published ISO 8073 / RFC 1006 / S7comm
//! frame layouts. No third-party source was consulted as a design reference; a
//! third-party stack was used as a black box — to generate wire traffic and to
//! act as a live peer — which is a test oracle, not a design reference. See
//! SPEC.md.

const std = @import("std");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

pub const meta = .{
    // The codecs, the client's PDU logic and the responder are pure
    // computation; only the optional TcpTransport touches std.Io.net.
    .platform = .any,
    .role = .both, // client + responder
    // One Client/Responder owns one connection's buffers and PDU reference;
    // nothing shared or global. Concurrency belongs to the caller.
    .concurrency = .single_owner,
    .model_after = "ISO 8073 class 0 / RFC 1006 + the S7comm frame layouts; wire behaviour cross-checked against captured traffic between two independent third-party stacks (see SPEC.md)",
    .deps = .{},
};

// ── layers ──────────────────────────────────────────────────────────────────

/// TPKT (RFC 1006 §6): the four-octet shim and a stream framer.
pub const tpkt = @import("tpkt.zig");
/// COTP (ISO 8073 class 0): CR/CC/DT/DR/ER and the rack/slot TSAP.
pub const cotp = @import("cotp.zig");
/// The S7comm header and `Setup communication`.
pub const s7 = @import("s7.zig");
/// Read/Write Var item specifications and data blocks.
pub const items = @import("items.zig");
/// The Read/Write Var parameter block and the PDU budgets.
pub const vars = @import("vars.zig");
/// Userdata (ROSCTR 7): the sub-header and `Read SZL`.
pub const userdata = @import("userdata.zig");
/// The STEP 7 address notation parser.
pub const address = @import("address.zig");
/// The byte-stream seam and its adapters.
pub const transport = @import("transport.zig");
/// An S7 client.
pub const client = @import("client.zig");
/// An S7 responder (PLC side / fleet-simulation target).
pub const server = @import("server.zig");
/// Byte-exact frames captured from third-party traffic.
pub const goldens = @import("goldens.zig");

/// **S7CommPlus** (protocol id 0x72): the S7-1200 / S7-1500 dialect. A separate
/// namespace over the *same* TPKT/COTP transport — the typed-value TLV codec,
/// the object/session/integrity model, a symbolic path parser, and a
/// codec-driven client + responder. See `s7plus.zig` and SPEC.md for what is
/// third-party-anchored versus self-derived, and what is codec-only versus
/// driven. Classic S7comm above is unaffected.
pub const s7plus = @import("s7plus.zig");

// ── top-level names (the ones a consumer actually types) ────────────────────

/// An S7 client over any byte stream.
pub const Client = client.Client;
pub const Config = client.Config;
pub const ItemResult = client.ItemResult;

/// The PLC side: answers reads, writes and SZL out of caller-owned areas.
pub const Responder = server.Responder;
pub const AreaBinding = server.AreaBinding;
pub const ResponderConfig = server.Config;

/// The byte-stream seam: one `read`, one `write`.
pub const Transport = transport.Transport;
pub const TransportError = transport.TransportError;
/// Optional adapter onto a real socket.
pub const TcpTransport = transport.TcpTransport;
/// In-memory pipe, for offline round trips.
pub const LoopTransport = transport.LoopTransport;
/// The registered ISO-on-TCP port (102).
pub const default_port = transport.default_port;

/// A two-octet TSAP — where rack and slot live.
pub const Tsap = cotp.Tsap;
pub const ConnectionType = cotp.ConnectionType;
pub const TpduSize = cotp.TpduSize;

pub const Area = items.Area;
pub const TransportSize = items.TransportSize;
pub const DataTransportSize = items.DataTransportSize;
pub const ReturnCode = items.ReturnCode;
pub const Item = items.Item;
pub const Address = address.Address;
pub const parseAddress = address.parse;

pub const Rosctr = s7.Rosctr;
pub const Function = s7.Function;
pub const ErrorClass = s7.ErrorClass;
pub const Setup = s7.Setup;

pub const SzlId = userdata.SzlId;
pub const SzlResponse = userdata.SzlResponse;
pub const CpuStatus = userdata.CpuStatus;

// ── S7CommPlus top-level names (the 0x72 / S7-1200/1500 world) ──────────────
pub const S7PlusClient = s7plus.client.Client;
pub const S7PlusResponder = s7plus.client.Responder;
pub const S7PlusFrame = s7plus.Frame;
pub const S7PlusPduType = s7plus.PduType;
pub const S7PlusDatatype = s7plus.value.Datatype;
pub const S7PlusSession = s7plus.object.Session;
pub const S7PlusFunction = s7plus.object.Function;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ───────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s tests
// into the test binary on its own — every submodule must be named here too.
test {
    _ = tpkt;
    _ = cotp;
    _ = s7;
    _ = items;
    _ = vars;
    _ = userdata;
    _ = address;
    _ = transport;
    _ = client;
    _ = server;
    _ = goldens;
    _ = s7plus;
}

// ── tests: the whole stack, client against responder ───────────────────────

const testing = std.testing;

test "meta names no sibling dependencies" {
    try testing.expectEqual(@as(usize, 0), meta.deps.len);
}

/// A transport that hands every packet the client writes straight to a
/// `Responder` and queues its reply. That turns a full round trip into
/// ordinary synchronous code — no thread, no socket, no clock.
const PairedTransport = struct {
    responder: *Responder,
    out: [4096]u8 = undefined,
    queue: [8192]u8 = undefined,
    queue_len: usize = 0,
    queue_pos: usize = 0,
    /// Requests the responder refused, so a test can assert on them.
    failures: usize = 0,

    fn seam(self: *PairedTransport) Transport {
        return .{ .ctx = self, .vtable = &.{ .read = readFn, .write = writeFn } };
    }

    fn readFn(ctx: *anyopaque, buf: []u8) TransportError!usize {
        const self: *PairedTransport = @ptrCast(@alignCast(ctx));
        const avail = self.queue_len - self.queue_pos;
        if (avail == 0) return 0;
        const n = @min(avail, buf.len);
        @memcpy(buf[0..n], self.queue[self.queue_pos..][0..n]);
        self.queue_pos += n;
        return n;
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
        const self: *PairedTransport = @ptrCast(@alignCast(ctx));
        const reply = self.responder.handle(bytes, &self.out) catch {
            self.failures += 1;
            return;
        };
        const r = reply orelse return;
        if (self.queue_len + r.len > self.queue.len) return error.WriteFailed;
        @memcpy(self.queue[self.queue_len..][0..r.len], r);
        self.queue_len += r.len;
    }
};

test "round trip: client against responder over an in-memory wire" {
    var db1: [256]u8 = @splat(0);
    var flags: [32]u8 = @splat(0);
    var inputs: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{
        .{ .area = .db, .db_number = 1, .bytes = &db1 },
        .{ .area = .flags, .bytes = &flags },
        .{ .area = .inputs, .bytes = &inputs },
    };
    var r = Responder.init(.{}, &areas);
    var paired = PairedTransport{ .responder = &r };
    var buf: [1024]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{
        .remote_tsap = Tsap.rackSlot(.pg, 0, 2),
    });

    try c.connect();
    try testing.expectEqual(@as(u16, 480), c.pduLength());
    try testing.expectEqual(@as(u16, 480), r.pdu_length);

    // Write a word, read it back through the address parser.
    try c.writeAddress("DB1.DBW20", 2, &[_]u8{ 0x12, 0x34, 0x56, 0x78 });
    try testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0x56, 0x78 }, db1[20..24]);
    var out: [4]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{ 0x12, 0x34, 0x56, 0x78 }, try c.readAddress("DB1.DBW20", 2, &out));

    // A bit, which is the case with its own length semantics.
    try c.writeBit(.flags, 0, 10, 2, true);
    try testing.expectEqual(@as(u8, 0x04), flags[10]);
    var bit: [1]u8 = undefined;
    try testing.expectEqualSlices(u8, &[_]u8{1}, try c.readAddress("M10.2", 1, &bit));
    try c.writeBit(.flags, 0, 10, 2, false);
    try testing.expectEqual(@as(u8, 0x00), flags[10]);
    try testing.expectEqualSlices(u8, &[_]u8{0}, try c.readAddress("M10.2", 1, &bit));

    // A transfer larger than one item's worth, so the split path runs.
    var big: [600]u8 = undefined;
    for (&big, 0..) |*b, i| b.* = @intCast(i % 251);
    try c.writeBytes(.db, 1, 0, big[0..200]);
    try testing.expectEqualSlices(u8, big[0..200], db1[0..200]);

    // Multi-item read, including one item that must fail.
    const list = [_]Item{
        try Item.at(.db, 1, 0, 0, .byte, 4),
        try Item.at(.db, 99, 0, 0, .byte, 4), // not registered
        try Item.at(.flags, 0, 0, 0, .byte, 2),
    };
    var mout: [64]u8 = undefined;
    var results: [3]ItemResult = undefined;
    const got = try c.readMulti(&list, &mout, &results);
    try testing.expectEqualSlices(u8, db1[0..4], got[0].payload);
    try testing.expectEqual(ReturnCode.object_does_not_exist, got[1].return_code);
    try testing.expectEqual(@as(usize, 0), got[1].payload.len);
    try testing.expectEqual(@as(usize, 2), got[2].payload.len);

    // SZL: the responder synthesises 0x0424.
    try testing.expectEqual(CpuStatus.run, try c.cpuStatus());

    // PLC control is refused by default, and the CPU stays running.
    try testing.expectError(error.PlcError, c.plcStop());
    try testing.expectEqual(CpuStatus.run, try c.cpuStatus());

    c.disconnect();
    try testing.expect(!r.connected);
    try testing.expectEqual(@as(usize, 0), paired.failures);
}

test "round trip: an odd-length multi-item write pads the way the wire needs" {
    var db1: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db1 }};
    var r = Responder.init(.{}, &areas);
    var paired = PairedTransport{ .responder = &r };
    var buf: [1024]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{});
    try c.connect();

    const list = [_]Item{
        try Item.at(.db, 1, 32, 0, .byte, 1),
        try Item.at(.db, 1, 40, 0, .byte, 3),
    };
    const payloads = [_][]const u8{ &[_]u8{0xAA}, &[_]u8{ 0xB1, 0xB2, 0xB3 } };
    var scratch: [64]u8 = undefined;
    try c.writeMulti(&list, &payloads, &scratch);
    try testing.expectEqual(@as(u8, 0xAA), db1[32]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xB1, 0xB2, 0xB3 }, db1[40..43]);
}

test "round trip: a responder with PLC control enabled stops and restarts" {
    var db1: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db1 }};
    var r = Responder.init(.{ .allow_plc_control = true }, &areas);
    var paired = PairedTransport{ .responder = &r };
    var buf: [1024]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{});
    try c.connect();

    try testing.expectEqual(CpuStatus.run, try c.cpuStatus());
    try c.plcStop();
    try testing.expect(r.stopped);
    try testing.expectEqual(CpuStatus.stop, try c.cpuStatus());
    try c.plcHotStart();
    try testing.expect(!r.stopped);
    try testing.expectEqual(CpuStatus.run, try c.cpuStatus());
}

test "round trip: rack and slot survive the handshake" {
    var db1: [16]u8 = @splat(0);
    var areas = [_]AreaBinding{.{ .area = .db, .db_number = 1, .bytes = &db1 }};
    for ([_]struct { rack: u3, slot: u5 }{
        .{ .rack = 0, .slot = 0 },
        .{ .rack = 0, .slot = 1 },
        .{ .rack = 0, .slot = 2 },
        .{ .rack = 1, .slot = 2 },
        .{ .rack = 7, .slot = 31 },
    }) |rs| {
        var r = Responder.init(.{}, &areas);
        var paired = PairedTransport{ .responder = &r };
        var buf: [1024]u8 = undefined;
        var c = try Client.init(paired.seam(), &buf, .{
            .remote_tsap = Tsap.rackSlot(.pg, rs.rack, rs.slot),
        });
        try c.connect();
        // The CC echoes the destination TSAP, so what the client sent is what
        // the responder saw.
        const cc = (try cotp.decode((try tpkt.decode(&paired.queue)).payload)).cc;
        try testing.expectEqual(rs.rack, cc.dst_tsap.?.rack());
        try testing.expectEqual(rs.slot, cc.dst_tsap.?.slot());
    }
}

// ── live interop ────────────────────────────────────────────────────────────
//
// Both tests print `SKIPPED: …` and pass when no peer is present, exactly like
// the live tests in `iec104` and `netconf`.

fn envVar(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(std.testing.environ, name);
}

const Endpoint = struct { host: []const u8, port: u16 };

fn splitEndpoint(endpoint: []const u8) ?Endpoint {
    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return null;
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return null;
    return .{ .host = endpoint[0..colon], .port = port };
}

// Set S7COMM_TEST_SERVER=host:port to run a real round trip against a live S7
// peer (a `snap7` server on :102, or on an unprivileged port). Rack and slot
// come from S7COMM_TEST_RACK / S7COMM_TEST_SLOT and default to 0 / 1, which is
// what a snap7 server expects.
test "live: our client against a real S7 server" {
    const endpoint = envVar("S7COMM_TEST_SERVER") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live S7 interop (set S7COMM_TEST_SERVER=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;
    const rack = std.fmt.parseInt(u3, envVar("S7COMM_TEST_RACK") orelse "0", 10) catch 0;
    const slot = std.fmt.parseInt(u5, envVar("S7COMM_TEST_SLOT") orelse "1", 10) catch 1;
    const db_number = std.fmt.parseInt(u16, envVar("S7COMM_TEST_DB") orelse "1", 10) catch 1;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var tt = TcpTransport.connect(io, addr) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live S7 interop (cannot connect to {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer tt.close();
    tt.setReadTimeout(2000);

    var buf: [2048]u8 = undefined;
    var c = try Client.init(tt.transport(), &buf, .{
        .remote_tsap = Tsap.rackSlot(.pg, rack, slot),
    });
    try c.connect();
    defer c.disconnect();
    try testing.expect(c.pduLength() >= 240);

    // Write a pattern into the DB and read it back.
    const pattern = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
    try c.writeBytes(.db, db_number, 16, &pattern);
    var back: [8]u8 = undefined;
    _ = try c.readBytes(.db, db_number, 16, &back);
    try testing.expectEqualSlices(u8, &pattern, &back);

    // A single bit, which exercises the bit-counted length in both directions.
    try c.writeBit(.db, db_number, 8, 3, true);
    var bit: [1]u8 = undefined;
    _ = try c.readItem(try Item.at(.db, db_number, 8, 3, .bit, 1), &bit);
    try testing.expectEqual(@as(u8, 1), bit[0] & 1);
    try c.writeBit(.db, db_number, 8, 3, false);
    _ = try c.readItem(try Item.at(.db, db_number, 8, 3, .bit, 1), &bit);
    try testing.expectEqual(@as(u8, 0), bit[0] & 1);

    // A transfer past the negotiated PDU, so the split path runs live.
    const big_db = std.fmt.parseInt(u16, envVar("S7COMM_TEST_BIG_DB") orelse "0", 10) catch 0;
    var split_ok = false;
    if (big_db != 0) {
        var big: [600]u8 = undefined;
        for (&big, 0..) |*b, i| b.* = @intCast((i * 7) % 251);
        var big_back: [600]u8 = undefined;
        try c.writeBytes(.db, big_db, 0, &big);
        _ = try c.readBytes(.db, big_db, 0, &big_back);
        try testing.expectEqualSlices(u8, &big, &big_back);
        split_ok = true;
    }

    // Multi-item read in one PDU, with a deliberately missing DB alongside a
    // real one, so the per-item return codes come from a real peer.
    const list = [_]Item{
        try Item.at(.db, db_number, 16, 0, .byte, 4),
        try Item.at(.db, 60000, 0, 0, .byte, 2),
    };
    var mout: [32]u8 = undefined;
    var results: [2]ItemResult = undefined;
    const multi = try c.readMulti(&list, &mout, &results);
    try testing.expectEqualSlices(u8, pattern[0..4], multi[0].payload);
    try testing.expect(!multi[1].return_code.isSuccess());

    // Read SZL and the CPU status.
    const szl = try c.readSzl(SzlId.module_identification, 0);
    const records = szl.response.header.record_count;
    const status = try c.cpuStatus();
    std.debug.print(
        "live S7: pdu={d} rack={d} slot={d} db_rw=ok bit_rw=ok multi_item_err={t} split={} szl0011_records={d} cpu={t}\n",
        .{ c.pduLength(), rack, slot, multi[1].return_code, split_ok, records, status },
    );
    try testing.expect(records > 0);
}

// Set S7COMM_TEST_LISTEN=host:port and point a real S7 client at it (a `snap7`
// client, for instance). Without the variable the test prints SKIPPED.
test "live: a real S7 client against our responder" {
    const endpoint = envVar("S7COMM_TEST_LISTEN") orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live S7 responder (set S7COMM_TEST_LISTEN=host:port)\n", .{});
        return error.SkipZigTest;
    };
    const ep = splitEndpoint(endpoint) orelse return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(ep.host, ep.port) catch return error.SkipZigTest;
    var listener = addr.listen(io, .{ .reuse_address = true }) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live S7 responder (cannot bind {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer listener.socket.close(io);
    std.debug.print("live S7 responder listening on {s}\n", .{endpoint});

    const stream = listener.accept(io) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live S7 responder (no peer connected)\n", .{});
        return error.SkipZigTest;
    };
    var tt = TcpTransport.fromStream(io, stream);
    defer tt.close();
    tt.setReadTimeout(5000);

    var db1: [256]u8 = @splat(0);
    var flags: [128]u8 = @splat(0);
    db1[0] = 0xA5;
    var areas = [_]AreaBinding{
        .{ .area = .db, .db_number = 1, .bytes = &db1 },
        .{ .area = .flags, .bytes = &flags },
    };
    var r = Responder.init(.{}, &areas);

    var in: [2048]u8 = undefined;
    var out: [2048]u8 = undefined;
    var reads: usize = 0;
    var writes: usize = 0;
    var userdata_requests: usize = 0;
    var rounds: usize = 0;
    const t = tt.transport();
    while (rounds < 500) : (rounds += 1) {
        const n = t.read(&in) catch break;
        if (n == 0) continue;
        // Classify before answering, so the counters describe real requests.
        classify(in[0..n], &reads, &writes, &userdata_requests);
        const reply = r.handle(in[0..n], &out) catch continue;
        const rep = reply orelse break;
        t.write(rep) catch break;
    }
    std.debug.print(
        "live S7 responder: reads={d} writes={d} userdata={d} db1[0]=0x{X:0>2}\n",
        .{ reads, writes, userdata_requests, db1[0] },
    );
    try testing.expect(reads > 0);
    try testing.expect(writes > 0);
}

fn classify(frame: []const u8, reads: *usize, writes: *usize, userdata_requests: *usize) void {
    const pkt = tpkt.decode(frame) catch return;
    const tp = cotp.decode(pkt.payload) catch return;
    const dt = switch (tp) {
        .dt => |d| d,
        else => return,
    };
    const pdu = s7.decode(dt.payload) catch return;
    if (pdu.header.rosctr == .userdata) userdata_requests.* += 1;
    if (pdu.header.rosctr != .job or pdu.parameters.len == 0) return;
    switch (@as(Function, @enumFromInt(pdu.parameters[0]))) {
        .read_var => reads.* += 1,
        .write_var => writes.* += 1,
        else => {},
    }
}
