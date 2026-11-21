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
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Siemens S7 communication — ISO-on-TCP (RFC 1006) plus S7 protocol: connection setup, area read/write (DB/M/I/Q/T/C), PLC info; block and cyclic services are not implemented",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    // The codecs, the client's PDU logic and the responder are pure
    // computation; only the optional TcpTransport touches std.Io.net.
    .targets = .{.linux64},
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
/// Block upload and download (function codes 0x1A-0x1F) and `_INSE`.
pub const blocktransfer = @import("blocktransfer.zig");
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
pub const DateTime = userdata.DateTime;
pub const Clock = server.Clock;
pub const Protection = userdata.Protection;

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
    _ = blocktransfer;
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
    /// Test hooks: copy of the last request, and one reply octet overwritten
    /// after the responder produced it (offset into the reply TPKT).
    last_req: [64]u8 = undefined,
    last_req_len: usize = 0,
    tamper_at: usize = 0,
    tamper_val: ?u8 = null,
    /// Test hook: rewrites the whole reply (into the given buffer) before it
    /// is queued.
    rewrite: ?*const fn (reply: []const u8, buf: []u8) []const u8 = null,
    rewrite_buf: [256]u8 = undefined,

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
        self.last_req_len = @min(bytes.len, self.last_req.len);
        @memcpy(self.last_req[0..self.last_req_len], bytes[0..self.last_req_len]);
        const reply = self.responder.handle(bytes, &self.out) catch {
            self.failures += 1;
            return;
        };
        const r0 = reply orelse return;
        const r = if (self.rewrite) |f| f(r0, &self.rewrite_buf) else r0;
        if (self.queue_len + r.len > self.queue.len) return error.WriteFailed;
        @memcpy(self.queue[self.queue_len..][0..r.len], r);
        if (self.tamper_val) |v| self.queue[self.queue_len + self.tamper_at] = v;
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

test "round trip: read and set the CPU clock through the injected clock" {
    const Ck = struct {
        var value: DateTime = .{ .year = 2031, .month = 2, .day = 28, .hour = 23, .minute = 59, .second = 58, .millisecond = 5, .weekday = 2 };
        fn now(_: ?*anyopaque) DateTime {
            return value;
        }
        fn set(_: ?*anyopaque, v: DateTime) void {
            value = v;
        }
    };
    var r = Responder.init(.{ .clock = .{ .now = Ck.now, .set = Ck.set } }, &.{});
    var paired = PairedTransport{ .responder = &r };
    var buf: [1024]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{});
    try c.connect();
    try testing.expectEqual(Ck.value, try c.readClock());
    const t: DateTime = .{ .year = 1995, .month = 7, .day = 4, .hour = 1, .minute = 2, .second = 3, .millisecond = 456, .weekday = 3 };
    try c.setClock(t);
    try testing.expectEqual(t, Ck.value);
    try testing.expectEqual(t, try c.readClock());
    // An invalid value is refused before it is sent.
    try testing.expectError(error.BadDateTime, c.setClock(.{ .year = 2026, .month = 2, .day = 30 }));
    try testing.expectEqual(t, Ck.value);
    // A responder without a clock answers; the client reports it as a PLC error.
    var r2 = Responder.init(.{}, &.{});
    var paired2 = PairedTransport{ .responder = &r2 };
    var buf2: [1024]u8 = undefined;
    var c2 = try Client.init(paired2.seam(), &buf2, .{});
    try c2.connect();
    try testing.expectError(error.PlcError, c2.readClock());
    try testing.expectError(error.PlcError, c2.setClock(t));
}

test "clock client: not connected, request bytes, and every reply-shape check" {
    const Ck = struct {
        fn now(_: ?*anyopaque) DateTime {
            return .{ .year = 2026, .month = 11, .day = 19, .hour = 13, .minute = 45, .second = 59, .millisecond = 987, .weekday = 5 };
        }
        fn set(_: ?*anyopaque, _: DateTime) void {}
    };
    var r = Responder.init(.{ .clock = .{ .now = Ck.now, .set = Ck.set } }, &.{});
    var paired = PairedTransport{ .responder = &r };
    var buf: [1024]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{});
    const t = Ck.now(null);
    try testing.expectError(error.NotConnected, c.readClock());
    try testing.expectError(error.NotConnected, c.setClock(t));
    try c.connect();

    // The requests, byte for byte (userdata group 7, subfunction 1 and 2).
    _ = try c.readClock();
    try testing.expectEqualSlices(u8, &[_]u8{
        0x00, 0x01, 0x12, 0x04, 0x11, 0x47, 0x01, 0x00, // parameters
        0x0A, 0x00, 0x00, 0x00, // data: object does not exist, no payload
    }, paired.last_req[17..29]);
    try c.setClock(t);
    try testing.expectEqualSlices(u8, &[_]u8{
        0x00, 0x01, 0x12, 0x04, 0x11, 0x47, 0x02, 0x00,
        0xFF, 0x09, 0x00, 0x0A, 0x00, 0x20, 0x26, 0x11,
        0x19, 0x13, 0x45, 0x59, 0x98, 0x75,
    }, paired.last_req[17..39]);

    // One reply octet damaged at a time (offsets into the reply TPKT: 8 = ROSCTR,
    // 22 = type|group, 23 = subfunction, 29 = data return code).
    const Case = struct { at: usize, val: u8 };
    const bad = [_]Case{
        .{ .at = 8, .val = 0x01 },
        .{ .at = 22, .val = 0x47 }, // request, not response
        .{ .at = 22, .val = 0x84 }, // another function group
        .{ .at = 23, .val = 0x02 }, // another subfunction
    };
    for (bad) |cs| {
        paired.tamper_at = cs.at;
        paired.tamper_val = cs.val;
        try testing.expectError(error.UnexpectedReply, c.readClock());
    }
    paired.tamper_at = 29;
    paired.tamper_val = 0x0A;
    try testing.expectError(error.ItemError, c.readClock());
    try testing.expectError(error.ItemError, c.setClock(t));
    paired.tamper_at = 22;
    paired.tamper_val = 0x47;
    try testing.expectError(error.UnexpectedReply, c.setClock(t));
    paired.tamper_val = null;
    // The error code of the parameters (octets 27, 28).
    paired.tamper_at = 28;
    paired.tamper_val = 0x01;
    try testing.expectError(error.PlcError, c.readClock());
    paired.tamper_val = null;
    _ = try c.readClock();
}

test "session password and protection: request bytes are gos7's, and the responder answers them" {
    const prot: Protection = .{ .sch_schal = 2, .sch_par = 3, .sch_rel = 1, .bart_sch = 3, .anl_sch = 2 };
    var r = Responder.init(.{ .password = "s7live", .protection = prot }, &.{});
    var paired = PairedTransport{ .responder = &r };
    var buf: [1024]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{});
    try testing.expectError(error.NotConnected, c.setSessionPassword("s7live"));
    try testing.expectError(error.NotConnected, c.clearSessionPassword());
    try testing.expectError(error.NotConnected, c.readProtection());
    try c.connect();

    // gos7 (BSD-3, commit 153d631d8881) sent these against the live responder
    // (tools/gos7_client_drive); octets 11-12 are its PDU reference.
    const gos7_wrong = "0300002502f0803207000027000008000c0001120411450100ff0900083b3a1e0a6b7f1e0a";
    const gos7_right = "0300002502f0803207000027000008000c0001120411450100ff09000826621f5e3c6e491b";
    const gos7_clear = "0300001d02f0803207000029000008000400011204114502000a000000";
    var g: [64]u8 = undefined;

    try testing.expectError(error.PasswordRejected, c.setSessionPassword("nope"));
    try testing.expect(!r.legitimated);
    var want = try std.fmt.hexToBytes(&g, gos7_wrong);
    try testing.expectEqual(want.len, paired.last_req_len);
    try testing.expectEqualSlices(u8, want[0..11], paired.last_req[0..11]);
    try testing.expectEqualSlices(u8, want[13..], paired.last_req[13..want.len]);

    try c.setSessionPassword("s7live");
    try testing.expect(r.legitimated);
    want = try std.fmt.hexToBytes(&g, gos7_right);
    try testing.expectEqualSlices(u8, want[13..], paired.last_req[13..want.len]);
    // Past the eighth character nothing counts: "s7live  " + anything.
    try c.setSessionPassword("s7live  ignored");
    try testing.expectEqualSlices(u8, want[13..], paired.last_req[13..want.len]);

    try c.clearSessionPassword();
    try testing.expect(!r.legitimated);
    want = try std.fmt.hexToBytes(&g, gos7_clear);
    try testing.expectEqual(want.len, paired.last_req_len);
    try testing.expectEqualSlices(u8, want[0..11], paired.last_req[0..11]);
    try testing.expectEqualSlices(u8, want[13..], paired.last_req[13..want.len]);

    // The protection record, read from SZL 0x0232 index 4 (gos7 reads the same).
    try testing.expectEqual(prot, try c.readProtection());
    try testing.expectEqualSlices(u8, &[_]u8{ 0xFF, 0x09, 0x00, 0x04, 0x02, 0x32, 0x00, 0x04 }, paired.last_req[25..33]);

    // A responder without a password accepts any; without a protection
    // record the SZL is "not available", which the client reports.
    var r2 = Responder.init(.{}, &.{});
    var paired2 = PairedTransport{ .responder = &r2 };
    var buf2: [1024]u8 = undefined;
    var c2 = try Client.init(paired2.seam(), &buf2, .{});
    try c2.connect();
    try c2.setSessionPassword("anything");
    try testing.expect(r2.legitimated);
    try c2.clearSessionPassword();
    try testing.expect(!r2.legitimated);
    try testing.expectError(error.PlcError, c2.readProtection());
}

test "session password client: every reply-shape check" {
    var r = Responder.init(.{ .password = "pw" }, &.{});
    var paired = PairedTransport{ .responder = &r };
    var buf: [1024]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{});
    try c.connect();
    // Offsets into the reply TPKT: 8 = ROSCTR, 22 = type|group, 23 = subfunction,
    // 27/28 = the parameters' error code.
    const Case = struct { at: usize, val: u8, want: anyerror };
    const bad = [_]Case{
        .{ .at = 8, .val = 0x01, .want = error.UnexpectedReply },
        .{ .at = 22, .val = 0x45, .want = error.UnexpectedReply }, // request, not response
        .{ .at = 22, .val = 0x87, .want = error.UnexpectedReply }, // another function group
        .{ .at = 23, .val = 0x02, .want = error.UnexpectedReply }, // another subfunction
        .{ .at = 28, .val = 0x05, .want = error.PlcError }, // 0x0005: not the password code
    };
    for (bad) |cs| {
        paired.tamper_at = cs.at;
        paired.tamper_val = cs.val;
        try testing.expectError(cs.want, c.setSessionPassword("pw"));
    }
    // 0xD600: a 0xD6xx code other than 0xD602 is a PLC error, not a rejection.
    paired.tamper_at = 27;
    paired.tamper_val = 0xD6;
    try testing.expectError(error.PlcError, c.clearSessionPassword());
    paired.tamper_val = null;
    try c.setSessionPassword("pw");
    try c.clearSessionPassword();

    // A reply with the short (request-shaped, 8-octet) sub-header carries no
    // error word; it must not read as an accepted password.
    const Short = struct {
        fn f(reply: []const u8, b: []u8) []const u8 {
            @memcpy(b[0..17], reply[0..17]); // TPKT, COTP, S7 header (PDU reference kept)
            @memcpy(b[17..25], reply[17..25]);
            b[20] = 0x04; // "length of what follows": the request form
            @memcpy(b[25..29], &[_]u8{ 0xFF, 0x09, 0x00, 0x00 });
            b[3] = 29; // TPKT length
            b[13] = 0;
            b[14] = 8; // parameter length
            b[15] = 0;
            b[16] = 4; // data length
            return b[0..29];
        }
    };
    paired.rewrite = Short.f;
    try testing.expectError(error.UnexpectedReply, c.setSessionPassword("wrong"));
    paired.rewrite = null;
    try c.setSessionPassword("pw");
}

// ── fuzz: the client parsing a damaged clock reply ──────────────────────────

const fz = @import("fuzz_test.zig");
const fuzzClockMark = fz.Marker(enum { ran, read_ok, read_err, set_ok, set_err });

/// A wire whose replies are the responder's, damaged after the handshake:
/// 0-3 octets anywhere, and in half the cases one more
/// octet inside the parameters or the date-time, where the checks are.
fn FuzzReplyWire(comptime S: type) type {
    return struct {
        const Self = @This();
        responder: *Responder,
        src: *S,
        out: [4096]u8 = undefined,
        queue: [4096]u8 = undefined,
        queue_len: usize = 0,
        queue_pos: usize = 0,
        armed: bool = false,

        fn seam(self: *Self) Transport {
            return .{ .ctx = self, .vtable = &.{ .read = readFn, .write = writeFn } };
        }

        fn readFn(ctx: *anyopaque, buf: []u8) TransportError!usize {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const avail = self.queue_len - self.queue_pos;
            if (avail == 0) return 0;
            const n = @min(avail, buf.len);
            @memcpy(buf[0..n], self.queue[self.queue_pos..][0..n]);
            self.queue_pos += n;
            return n;
        }

        fn writeFn(ctx: *anyopaque, bytes: []const u8) TransportError!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            const reply = (self.responder.handle(bytes, &self.out) catch return) orelse return;
            self.queue_pos = 0;
            if (!self.armed) {
                @memcpy(self.queue[0..reply.len], reply);
                self.queue_len = reply.len;
                return;
            }
            // Every draw is a full-width `value(u64)` reduced here: a ranged or
            // narrow draw collapses to its minimum under `Smith`.
            var n = @min(reply.len, self.queue.len);
            @memcpy(self.queue[0..n], reply[0..n]);
            const hits = self.src.value(u64) % 4;
            for (0..hits) |_| {
                self.queue[self.src.value(u64) % n] = @truncate(self.src.value(u64));
            }
            // And one octet inside the parameters or the date-time, where the checks are.
            if (self.src.value(u64) % 2 == 0 and n > 17) {
                self.queue[17 + self.src.value(u64) % (n - 17)] = @truncate(self.src.value(u64));
            }
            // A truncated frame: the client must see a closed stream, not hang.
            if (self.src.value(u64) % 6 == 0) n = @intCast(self.src.value(u64) % (n + 1));
            self.queue_len = n;
        }
    };
}

fn fuzzClockClient(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    fuzzClockMark.mark(.ran);
    const Ck = struct {
        fn now(_: ?*anyopaque) DateTime {
            return .{ .year = 2026, .month = 11, .day = 19, .hour = 13, .minute = 45, .second = 59, .millisecond = 987, .weekday = 5 };
        }
        fn set(_: ?*anyopaque, _: DateTime) void {}
    };
    var r = Responder.init(.{ .clock = .{ .now = Ck.now, .set = Ck.set } }, &.{});
    var wire = FuzzReplyWire(S){ .responder = &r, .src = src };
    var buf: [1024]u8 = undefined;
    var c = try Client.init(wire.seam(), &buf, .{});
    try c.connect();
    wire.armed = true;
    if (src.value(u64) % 2 == 0) {
        if (c.readClock()) |dt| {
            // Whatever the client returns is a valid date-time.
            try dt.validate();
            fuzzClockMark.mark(.read_ok);
        } else |_| fuzzClockMark.mark(.read_err);
    } else {
        if (c.setClock(Ck.now(null))) |_| fuzzClockMark.mark(.set_ok) else |_| fuzzClockMark.mark(.set_err);
    }
}

fn fuzzClockClientSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzClockClient(std.testing.Smith, smith, std.testing.allocator);
}

test "fuzz: the clock client survives damaged replies" {
    try std.testing.fuzz({}, fuzzClockClientSmith, .{});
}

test "fuzz driver: S7COMM_FUZZ (fuzzClockClient)" {
    try fz.fuzz_driver.run(fuzzClockClient, .{ .prefix = "S7COMM_FUZZ", .name = "s7comm-root-fuzzClockClient" });
}

test "fuzz harness: fuzzClockClient, 400 seeds, reaches every outcome" {
    try fuzzClockMark.reach(fuzzClockClient, "s7comm-root-fuzzClockClient", 400);
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
    const colon = std.mem.findScalarLast(u8, endpoint, ':') orelse return null;
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

    // Block services (group 3): the registered DBs must be listed, and the
    // list of DBs must agree with the count.
    const counts = try c.listBlocks();
    var entries: [32]userdata.BlockEntry = undefined;
    const dbs = try c.listBlocksOfType(.db, &entries);
    std.debug.print("live S7: blocks db={d} listed={d}\n", .{ counts.db, dbs.len });
    try testing.expect(counts.db >= 1);
    try testing.expectEqual(@as(usize, counts.db), dbs.len);
    const info = try c.getBlockInfo(.db, dbs[0].number);
    try testing.expectEqual(dbs[0].number, info.number);
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
    // Group 5 and SZL 0x0232 for tools/gos7_client_drive (password "s7live").
    const blocks = [_]userdata.BlockInfo{
        .{ .block_type = .ob, .number = 1, .language = 3, .load_size = 300, .mc7_size = 180, .author = "DRIVE   ".*, .version = 17 },
        .{ .block_type = .fc, .number = 5 },
    };
    var r = Responder.init(.{
        .blocks = &blocks,
        .password = "s7live",
        .protection = .{ .sch_schal = 2, .sch_par = 3, .sch_rel = 1, .bart_sch = 3, .anl_sch = 2 },
    }, &areas);

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
        const is_userdata = classify(in[0..n], &reads, &writes, &userdata_requests);
        const reply = r.handle(in[0..n], &out) catch continue;
        const rep = reply orelse break;
        // The peer's userdata frames and our answers, for goldens.
        if (is_userdata) std.debug.print("live S7 userdata: req {x} rep {x} legitimated={}\n", .{ in[0..n], rep, r.legitimated });
        t.write(rep) catch break;
    }
    std.debug.print(
        "live S7 responder: reads={d} writes={d} userdata={d} db1[0]=0x{X:0>2}\n",
        .{ reads, writes, userdata_requests, db1[0] },
    );
    try testing.expect(reads > 0);
    try testing.expect(writes > 0);
}

/// Counts the request kinds; true for a userdata request.
fn classify(frame: []const u8, reads: *usize, writes: *usize, userdata_requests: *usize) bool {
    const pkt = tpkt.decode(frame) catch return false;
    const tp = cotp.decode(pkt.payload) catch return false;
    const dt = switch (tp) {
        .dt => |d| d,
        else => return false,
    };
    const pdu = s7.decode(dt.payload) catch return false;
    if (pdu.header.rosctr == .userdata) {
        userdata_requests.* += 1;
        return true;
    }
    if (pdu.header.rosctr != .job or pdu.parameters.len == 0) return false;
    switch (@as(Function, @fromBackingInt(@intCast(pdu.parameters[0])))) {
        .read_var => reads.* += 1,
        .write_var => writes.* += 1,
        else => {},
    }
    return false;
}

test "round trip: block list, list of type and block info" {
    var db1: [16]u8 = @splat(0);
    var db7: [64]u8 = @splat(0);
    var areas = [_]AreaBinding{
        .{ .area = .db, .db_number = 1, .bytes = &db1 },
        .{ .area = .db, .db_number = 7, .bytes = &db7 },
    };
    const blocks = [_]userdata.BlockInfo{
        .{ .block_type = .ob, .number = 1, .language = 3, .load_size = 200, .mc7_size = 120, .author = "OPERATOR".*, .version = 17, .checksum = 0xBEEF },
        .{ .block_type = .fc, .number = 3, .language = 2 },
        .{ .block_type = .fc, .number = 12 },
        // Names DB 7, which is also bound: the configured entry wins.
        .{ .block_type = .db, .number = 7, .load_size = 999, .mc7_size = 64 },
        .{ .block_type = .db, .number = 100 },
    };
    var r = Responder.init(.{ .blocks = &blocks }, &areas);
    var paired = PairedTransport{ .responder = &r };
    var buf: [1024]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{});
    try c.connect();

    const counts = try c.listBlocks();
    try testing.expectEqual(userdata.BlockCounts{ .ob = 1, .fc = 2, .db = 3 }, counts);

    var entries: [8]userdata.BlockEntry = undefined;
    const fcs = try c.listBlocksOfType(.fc, &entries);
    try testing.expectEqual(@as(usize, 2), fcs.len);
    try testing.expectEqual(@as(u16, 3), fcs[0].number);
    try testing.expectEqual(@as(u8, 2), fcs[0].language);
    try testing.expectEqual(@as(u16, 12), fcs[1].number);
    // Configured DBs first, then the bound DB nobody configured.
    const dbs = try c.listBlocksOfType(.db, &entries);
    try testing.expectEqual(@as(usize, 3), dbs.len);
    try testing.expectEqual(@as(u16, 7), dbs[0].number);
    try testing.expectEqual(@as(u16, 100), dbs[1].number);
    try testing.expectEqual(@as(u16, 1), dbs[2].number);
    try testing.expectEqual(@as(usize, 0), (try c.listBlocksOfType(.sdb, &entries)).len);
    try testing.expectError(error.BufferTooSmall, c.listBlocksOfType(.db, entries[0..2]));

    const ob1 = try c.getBlockInfo(.ob, 1);
    try testing.expectEqual(blocks[0], ob1);
    const db1_info = try c.getBlockInfo(.db, 1);
    try testing.expectEqual(@as(u32, 16), db1_info.load_size);
    try testing.expectEqual(@as(u16, 16), db1_info.mc7_size);
    try testing.expectEqual(@as(u32, 999), (try c.getBlockInfo(.db, 7)).load_size);
    try testing.expectError(error.PlcError, c.getBlockInfo(.db, 2));
    try testing.expectError(error.PlcError, c.getBlockInfo(.sfb, 1));
    try testing.expectEqual(@as(usize, 0), paired.failures);
}

test "round trip: block list of type spans several PDUs" {
    var store: [8]u8 = @splat(0);
    var areas: [5]AreaBinding = undefined;
    for (&areas, 0..) |*a, i| a.* = .{ .area = .db, .db_number = @intCast(10 + i), .bytes = &store };
    // Two entries per PDU.
    var r = Responder.init(.{ .max_userdata_payload = 8 }, &areas);
    var paired = PairedTransport{ .responder = &r };
    var buf: [1024]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{});
    try c.connect();
    var entries: [8]userdata.BlockEntry = undefined;
    const got = try c.listBlocksOfType(.db, &entries);
    try testing.expectEqual(@as(usize, 5), got.len);
    for (got, 0..) |e, i| try testing.expectEqual(@as(u16, @intCast(10 + i)), e.number);
    // The continuation is gone after the last PDU.
    try testing.expect(r.cont == null);
    // A list that ends on a PDU boundary has no empty tail PDU.
    var r2 = Responder.init(.{ .max_userdata_payload = 20 }, &areas);
    var p2 = PairedTransport{ .responder = &r2 };
    var c2 = try Client.init(p2.seam(), &buf, .{});
    try c2.connect();
    try testing.expectEqual(@as(usize, 5), (try c2.listBlocksOfType(.db, &entries)).len);
    try testing.expectEqual(@as(usize, 0), p2.failures);
    try testing.expectEqual(@as(usize, 0), paired.failures);
}

test "round trip: a fragmented SZL list is assembled by readSzlAll" {
    // Three 28-octet records of SZL 0x0011.
    var recs: [84]u8 = undefined;
    for (&recs, 0..) |*b, i| b.* = @intCast(i);
    var r = Responder.init(.{ .szl_0011 = &recs, .max_userdata_payload = 30 }, &.{});
    var paired = PairedTransport{ .responder = &r };
    var buf: [1024]u8 = undefined;
    var c = try Client.init(paired.seam(), &buf, .{});
    try c.connect();

    // The ordinary call returns the first PDU and says so.
    const first = try c.readSzl(0x0011, 0);
    try testing.expect(first.partial);

    var out: [128]u8 = undefined;
    const szl = try c.readSzlAll(0x0011, 0, &out);
    try testing.expectEqual(@as(u16, 3), szl.header.record_count);
    try testing.expectEqual(@as(u16, 28), szl.header.record_length);
    try testing.expectEqualSlices(u8, &recs, szl.records);
    try testing.expectEqual(@as(u8, 56), szl.record(2).?[0]);

    // Too small a buffer is refused, not truncated.
    try testing.expectError(error.BufferTooSmall, c.readSzlAll(0x0011, 0, out[0..60]));
    // A list that fits one PDU is the same call.
    var r2 = Responder.init(.{}, &.{});
    var p2 = PairedTransport{ .responder = &r2 };
    var c2 = try Client.init(p2.seam(), &buf, .{});
    try c2.connect();
    const one = try c2.readSzlAll(userdata.SzlId.cpu_status, 0, &out);
    try testing.expectEqual(CpuStatus.run, userdata.cpuStatusFrom(one).?);
    try testing.expectEqual(@as(usize, 0), paired.failures);
}

// ── block upload and download ───────────────────────────────────────────────

fn patternImage(buf: []u8) []u8 {
    for (buf, 0..) |*b, i| b.* = @truncate(i *% 7 +% 3);
    return buf;
}

test "block upload: the image arrives whole over several PDUs, at two PDU sizes" {
    var img_buf: [1000]u8 = undefined;
    const image = patternImage(&img_buf);
    const images = [_]server.BlockImage{
        .{ .block_type = .fc, .number = 5, .image = image },
        .{ .block_type = .db, .number = 9, .image = &.{} },
    };
    for ([_]u16{ 480, 240 }) |max_pdu| {
        var r = Responder.init(.{ .block_images = &images, .max_pdu_length = max_pdu }, &.{});
        var paired = PairedTransport{ .responder = &r };
        var buf: [1024]u8 = undefined;
        var c = try Client.init(paired.seam(), &buf, .{});
        try c.connect();
        var out: [1000]u8 = undefined;
        const got = try c.uploadBlock(.fc, 5, &out);
        try testing.expectEqualSlices(u8, image, got);
        try testing.expect(r.up == null); // end upload was sent
        // A zero-length image is one empty chunk.
        try testing.expectEqual(@as(usize, 0), (try c.uploadBlock(.db, 9, &out)).len);
        // The caller's buffer too small: refused before any chunk is pulled.
        try testing.expectError(error.BufferTooSmall, c.uploadBlock(.fc, 5, out[0..999]));
        // An unknown block is the CPU's error.
        try testing.expectError(error.PlcError, c.uploadBlock(.fc, 6, &out));
    }
}

test "block download: refused unless confirmed on both sides, then pulled, ended and inserted" {
    var img_buf: [700]u8 = undefined;
    const image = patternImage(&img_buf);
    var store: [1024]u8 = undefined;

    // The client refuses without the explicit option: nothing is sent.
    {
        var r = Responder.init(.{ .allow_block_download = true, .download_buffer = &store }, &.{});
        var paired = PairedTransport{ .responder = &r };
        var buf: [1024]u8 = undefined;
        var c = try Client.init(paired.seam(), &buf, .{});
        try c.connect();
        const before = paired.last_req_len;
        try testing.expectError(error.DownloadNotConfirmed, c.downloadBlock(.fb, 3, image, .{ .mc7_length = 600 }));
        try testing.expectEqual(before, paired.last_req_len);
        try testing.expect(r.dl == null);
    }
    // The responder refuses by default, and a block that does not fit its buffer.
    {
        var r = Responder.init(.{ .download_buffer = &store }, &.{});
        var paired = PairedTransport{ .responder = &r };
        var buf: [1024]u8 = undefined;
        var c = try Client.init(paired.seam(), &buf, .{});
        try c.connect();
        const opts: Client.DownloadOptions = .{ .allow_program_replacement = true, .mc7_length = 600 };
        try testing.expectError(error.PlcError, c.downloadBlock(.fb, 3, image, opts));
        try testing.expect(r.insertedImage() == null);
    }
    for ([_]u16{ 480, 240 }) |max_pdu| {
        var r = Responder.init(.{ .allow_block_download = true, .download_buffer = &store, .max_pdu_length = max_pdu }, &.{});
        var paired = PairedTransport{ .responder = &r };
        var buf: [1024]u8 = undefined;
        var c = try Client.init(paired.seam(), &buf, .{});
        try c.connect();
        const opts: Client.DownloadOptions = .{ .allow_program_replacement = true, .mc7_length = 600 };
        try c.downloadBlock(.fb, 3, image, opts);
        try testing.expectEqual(@as(usize, 0), paired.failures);
        try testing.expectEqualSlices(u8, image, r.insertedImage().?);
        try testing.expectEqual(userdata.BlockType.fb, r.inserted.?.block_type);
        try testing.expectEqual(@as(u16, 3), r.inserted.?.number);
        // Transferred but not activated.
        try c.downloadBlock(.fc, 4, image[0..10], .{ .allow_program_replacement = true, .mc7_length = 1, .insert = false });
        try testing.expect(r.insertedImage() == null);
        try testing.expect(r.dl != null and r.dl.?.stage == .ended);
        // Too big for the responder's buffer.
        var big: [1100]u8 = @splat(1);
        try testing.expectError(error.PlcError, c.downloadBlock(.fc, 4, &big, opts));
    }
}

test "block transfer on the responder: out-of-sequence and damaged requests are refused, not trusted" {
    var store: [64]u8 = undefined;
    const images = [_]server.BlockImage{.{ .block_type = .db, .number = 1, .image = "abcd" }};
    var r = Responder.init(.{ .allow_block_download = true, .download_buffer = &store, .block_images = &images }, &.{});
    var out: [600]u8 = undefined;
    var pb: [64]u8 = undefined;
    const jobs = [_][]const u8{
        // upload and end-upload with no start-upload
        try blocktransfer.encodeIdJob(blocktransfer.fn_upload, 1, &pb),
    };
    for (jobs) |p| {
        var pdu_buf: [128]u8 = undefined;
        const pdu = try s7.encode(.{ .rosctr = .job, .pdu_reference = 1 }, p, &.{}, &pdu_buf);
        var frame: [160]u8 = undefined;
        const reply = (try r.handle(try wrapForTest(pdu, &frame), &out)).?;
        try testing.expect((try s7.decode(reply[7..])).header.isError());
    }
    // A download-ended / insert without a running download.
    var nb: [32]u8 = undefined;
    const name = blocktransfer.FileName{ .block_type = .db, .number = 1 };
    const stray = [_][]const u8{
        try blocktransfer.encodeBlockJob(blocktransfer.fn_download_ended, 1, name, &nb),
    };
    for (stray) |p| {
        var pdu_buf: [128]u8 = undefined;
        const pdu = try s7.encode(.{ .rosctr = .job, .pdu_reference = 2 }, p, &.{}, &pdu_buf);
        var frame: [160]u8 = undefined;
        const reply = (try r.handle(try wrapForTest(pdu, &frame), &out)).?;
        try testing.expect((try s7.decode(reply[7..])).header.isError());
    }
    var ib: [32]u8 = undefined;
    {
        var pdu_buf: [128]u8 = undefined;
        const pdu = try s7.encode(.{ .rosctr = .job, .pdu_reference = 3 }, try blocktransfer.encodeInsert(name, &ib), &.{}, &pdu_buf);
        var frame: [160]u8 = undefined;
        const reply = (try r.handle(try wrapForTest(pdu, &frame), &out)).?;
        try testing.expect((try s7.decode(reply[7..])).header.isError());
        try testing.expect(r.inserted == null);
    }
    // A stray Ack-Data with no download running gets no answer.
    {
        var pdu_buf: [128]u8 = undefined;
        const pdu = try s7.encode(.{ .rosctr = .ack_data, .pdu_reference = 4 }, &[_]u8{ 0x1B, 0x00 }, &blocktransfer.chunkHeader(0), &pdu_buf);
        var frame: [160]u8 = undefined;
        try testing.expect((try r.handle(try wrapForTest(pdu, &frame), &out)) == null);
    }
    // A chunk longer than the announced length aborts the download.
    {
        var rb: [bt_len]u8 = undefined;
        const req = try blocktransfer.encodeRequestDownload(name, 2, 2, &rb);
        var pdu_buf: [128]u8 = undefined;
        const pdu = try s7.encode(.{ .rosctr = .job, .pdu_reference = 5 }, req, &.{}, &pdu_buf);
        var frame: [160]u8 = undefined;
        const two = (try r.handle(try wrapForTest(pdu, &frame), &out)).?;
        try testing.expect(two.len > 7 + 12); // the ack and the first pull
        try testing.expect(r.dl != null);
        var chunk: [8]u8 = undefined;
        const data = try blocktransfer.encodeChunk("xyz", &chunk);
        var pdu2: [128]u8 = undefined;
        const ack = try s7.encode(.{ .rosctr = .ack_data, .pdu_reference = 6 }, &[_]u8{ 0x1B, 0x00 }, data, &pdu2);
        var frame2: [160]u8 = undefined;
        try testing.expect((try r.handle(try wrapForTest(ack, &frame2), &out)) == null);
        try testing.expect(r.dl == null);
    }
}

const bt_len = blocktransfer.request_download_len;

fn wrapForTest(pdu: []const u8, out: []u8) ![]const u8 {
    var tp: [4]u8 = undefined;
    tp = try tpkt.header(3 + pdu.len);
    @memcpy(out[0..4], &tp);
    @memcpy(out[4..7], &cotp.dataHeader(0, true));
    @memcpy(out[7..][0..pdu.len], pdu);
    return out[0 .. 7 + pdu.len];
}
