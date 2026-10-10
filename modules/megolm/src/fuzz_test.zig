// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for megolm (added 2026-10-10): `MEGOLM_FUZZ=<runs>[,<first seed>]`
//! (testkit's driver; `_ONLY` selects a harness by name). Harness names:
//! `megolm-message`, `megolm-session-key`, `megolm-pickle`.
//!
//! The harnesses build a genuine session from knob octets (ratchet, signing
//! key), then drive the PUBLIC API with the genuine artifact (accepted) and a
//! damaged copy (one flipped bit: refused; 0-3 random octets damaged and
//! maybe truncated: never a panic, and never accepted unless byte-identical).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
pub const Cursor = testkit.fuzz.Cursor;

/// Reach counters for one harness's labels. `mark` also feeds the driver's
/// `REACH` report; `reach` runs `seeds` seeds in the ordinary test binary and
/// fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Deterministic bytes from a knob cursor (its first octets seed a PRNG).
pub fn expand(knobs: *Cursor, out: []u8) void {
    var s: u64 = 0;
    for (0..8) |_| s = (s << 8) | knobs.byte();
    var prng = std.Random.DefaultPrng.init(s);
    prng.random().bytes(out);
}

/// Smith-side wrapper so `--fuzz` keeps working: the harness bodies are
/// generic over `S`; `testing.fuzz` hands them a `std.testing.Smith`.
pub fn smithWrap(comptime harness: anytype) fn (void, *std.testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *std.testing.Smith) anyerror!void {
            try harness(std.testing.Smith, smith, testing.allocator);
        }
    }.f;
}

const message = @import("message.zig");
const session = @import("session.zig");
const session_key = @import("session_key.zig");
const pickle = @import("pickle.zig");
const Ratchet = @import("ratchet.zig").Ratchet;
const Message = message.Message;
const Ed25519 = std.crypto.sign.Ed25519;

/// A session built deterministically from the knob cursor.
fn makeOutbound(knobs: *Cursor) !session.OutboundSession {
    var data: [128]u8 = undefined;
    expand(knobs, &data);
    var seed: [32]u8 = undefined;
    expand(knobs, &seed);
    var s: session.OutboundSession = undefined;
    // Mostly small indices; sometimes a large one (index arithmetic).
    const counter: u32 = switch (knobs.ranged(0, 3)) {
        0 => 0,
        1 => knobs.ranged(0, 200),
        2 => std.math.maxInt(u32) - 8 - knobs.ranged(0, 100),
        else => std.mem.readInt(u32, &.{ knobs.byte(), knobs.byte(), knobs.byte(), knobs.byte() & 0x7f }, .little),
    };
    Ratchet.init(&data, counter, &s.ratchet);
    s.signing_key = try Ed25519.KeyPair.generateDeterministic(seed);
    return s;
}

fn flipBit(knobs: *Cursor, bytes: []u8) void {
    const at = (@as(usize, knobs.byte()) << 8 | knobs.byte()) % bytes.len;
    bytes[at] ^= @as(u8, 1) << @intCast(knobs.ranged(0, 7));
}

const MessageMark = Marker(enum { genuine_accepted, flipped_decode_refused, flipped_decrypt_refused, damaged_decode_refused, damaged_decode_ok, damaged_decrypt_refused, b64_refused, b64_ok });

fn fuzzMessage(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [48]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    var out = try makeOutbound(&knobs);
    defer out.deinit();
    var sk: session_key.SessionKey = undefined;
    try out.sessionKey(&sk);
    var in: session.InboundGroupSession = undefined;
    try session.InboundGroupSession.fromSessionKey(&sk, &in);
    defer in.deinit();

    var pt: [40]u8 = undefined;
    expand(&knobs, &pt);
    const pt_len = knobs.ranged(0, 40);
    // Skip ahead so the message is not always the first.
    for (0..knobs.ranged(0, 2)) |_| {
        var skipped = try out.encrypt(gpa, "skip");
        skipped.deinit(gpa);
    }
    var genuine = try out.encrypt(gpa, pt[0..pt_len]);
    defer genuine.deinit(gpa);
    const encoded = try genuine.encode(gpa);
    defer gpa.free(encoded);

    {
        var m = Message.decode(gpa, encoded) catch return error.GenuineMessageRefused;
        defer m.deinit(gpa);
        var d = in.decrypt(gpa, &m) catch return error.GenuineMessageRefused;
        defer d.deinit(gpa);
        if (!std.mem.eql(u8, d.plaintext, pt[0..pt_len])) return error.GenuinePlaintextDiffers;
        MessageMark.mark(.genuine_accepted);
    }

    // One flipped bit anywhere: the signature covers every octet before it,
    // the signature itself is verified strictly.
    {
        const copy = try gpa.dupe(u8, encoded);
        defer gpa.free(copy);
        flipBit(&knobs, copy);
        if (Message.decode(gpa, copy)) |dm| {
            var m = dm;
            defer m.deinit(gpa);
            if (in.decrypt(gpa, &m)) |dd| {
                var d = dd;
                d.deinit(gpa);
                return error.FlippedMessageAccepted;
            } else |_| MessageMark.mark(.flipped_decrypt_refused);
        } else |_| MessageMark.mark(.flipped_decode_refused);
    }

    // Damaged, maybe truncated: never a panic; accepted only if identical.
    {
        var buf: [1024]u8 = undefined;
        const n = damage(src, &buf, encoded);
        const dmg = buf[0..n];
        if (Message.decode(gpa, dmg)) |dm| {
            var m = dm;
            defer m.deinit(gpa);
            MessageMark.mark(.damaged_decode_ok);
            if (in.decrypt(gpa, &m)) |dd| {
                var d = dd;
                d.deinit(gpa);
                if (!std.mem.eql(u8, dmg, encoded)) return error.DamagedMessageAccepted;
            } else |_| MessageMark.mark(.damaged_decrypt_refused);
        } else |_| MessageMark.mark(.damaged_decode_refused);
    }

    // Base64 text, damaged.
    {
        const b64 = try genuine.toBase64(gpa);
        defer gpa.free(b64);
        var buf: [1400]u8 = undefined;
        const n = damage(src, &buf, b64);
        if (Message.fromBase64(gpa, buf[0..n])) |dm| {
            var m = dm;
            defer m.deinit(gpa);
            MessageMark.mark(.b64_ok);
            if (in.decrypt(gpa, &m)) |dd| {
                var d = dd;
                defer d.deinit(gpa);
                // Base64 has non-canonical spellings of the same bytes; the
                // plaintext must then be the genuine one.
                if (!std.mem.eql(u8, d.plaintext, pt[0..pt_len])) return error.DamagedBase64Accepted;
            } else |_| {}
        } else |_| MessageMark.mark(.b64_refused);
    }
}

test "fuzz: megolm message, genuine accepted / damaged refused" {
    try testing.fuzz({}, smithWrap(fuzzMessage), .{});
}
test "fuzz driver: MEGOLM_FUZZ (message)" {
    try fuzz_driver.run(fuzzMessage, .{ .prefix = "MEGOLM_FUZZ", .name = "megolm-message" });
}
test "fuzz harness: message, 300 seeds, reaches every outcome" {
    try MessageMark.reach(fuzzMessage, "megolm-message", 300);
}

const KeyMark = Marker(enum { genuine_accepted, export_roundtrip, flipped_refused, damaged_refused, damaged_export_ok, damaged_export_session, b64_refused, b64_ok });

fn fuzzSessionKey(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [48]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    var out = try makeOutbound(&knobs);
    defer out.deinit();
    var sk: session_key.SessionKey = undefined;
    try out.sessionKey(&sk);
    var wire: [session_key.share_len]u8 = undefined;
    sk.encode(&wire);

    {
        var back: session_key.SessionKey = undefined;
        session_key.SessionKey.decode(&wire, &back) catch return error.GenuineKeyRefused;
        var in: session.InboundGroupSession = undefined;
        session.InboundGroupSession.fromSessionKey(&back, &in) catch return error.GenuineKeyRefused;
        defer in.deinit();
        KeyMark.mark(.genuine_accepted);
        var ex: session_key.ExportedSessionKey = undefined;
        if (!in.exportAt(out.ratchet.counter, &ex)) return error.ExportUnreachable;
        var ew: [session_key.export_len]u8 = undefined;
        ex.encode(&ew);
        var ex2: session_key.ExportedSessionKey = undefined;
        session_key.ExportedSessionKey.decode(&ew, &ex2) catch return error.GenuineExportRefused;
        var in2: session.InboundGroupSession = undefined;
        try session.InboundGroupSession.fromExportedKey(&ex2, &in2);
        in2.deinit();
        KeyMark.mark(.export_roundtrip);
        // Damaged export: no integrity by design (unsigned), never a panic.
        var buf: [session_key.export_len + 8]u8 = undefined;
        const n = damage(src, &buf, &ew);
        var dx: session_key.ExportedSessionKey = undefined;
        if (session_key.ExportedSessionKey.decode(buf[0..n], &dx)) {
            KeyMark.mark(.damaged_export_ok);
            var in3: session.InboundGroupSession = undefined;
            if (session.InboundGroupSession.fromExportedKey(&dx, &in3)) {
                in3.deinit();
                KeyMark.mark(.damaged_export_session);
            } else |_| {}
        } else |_| {}
    }

    // One flipped bit: the share is signed end to end.
    {
        var copy = wire;
        flipBit(&knobs, &copy);
        var k: session_key.SessionKey = undefined;
        if (session_key.SessionKey.decode(&copy, &k)) {
            // decode only checks the signature; a wrong embedded key cannot verify.
            return error.FlippedSessionKeyAccepted;
        } else |_| KeyMark.mark(.flipped_refused);
    }
    {
        var buf: [session_key.share_len + 8]u8 = undefined;
        const n = damage(src, &buf, &wire);
        var k: session_key.SessionKey = undefined;
        if (session_key.SessionKey.decode(buf[0..n], &k)) {
            if (!std.mem.eql(u8, buf[0..n], &wire)) return error.DamagedSessionKeyAccepted;
        } else |_| KeyMark.mark(.damaged_refused);
    }
    {
        const b64 = try sk.toBase64(gpa);
        defer gpa.free(b64);
        var buf: [400]u8 = undefined;
        const n = damage(src, &buf, b64);
        var k: session_key.SessionKey = undefined;
        if (session_key.SessionKey.fromBase64(gpa, buf[0..n], &k)) {
            KeyMark.mark(.b64_ok);
            var back: [session_key.share_len]u8 = undefined;
            k.encode(&back);
            if (!std.mem.eql(u8, &back, &wire)) return error.DamagedBase64Accepted;
        } else |_| KeyMark.mark(.b64_refused);
    }
}

test "fuzz: megolm session key, genuine accepted / damaged refused" {
    try testing.fuzz({}, smithWrap(fuzzSessionKey), .{});
}
test "fuzz driver: MEGOLM_FUZZ (session key)" {
    try fuzz_driver.run(fuzzSessionKey, .{ .prefix = "MEGOLM_FUZZ", .name = "megolm-session-key" });
}
test "fuzz harness: session key, 300 seeds, reaches every outcome" {
    try KeyMark.reach(fuzzSessionKey, "megolm-session-key", 300);
}

const PickleMark = Marker(enum { plain_roundtrip, plain_damaged_ok, plain_damaged_refused, sealed_roundtrip, sealed_flipped_refused, sealed_truncated_refused, sealed_wrong_key_refused, sealed_damaged_refused });

fn fuzzPickle(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [48]u8 = undefined;
    const raw_len: usize = src.slice(&raw);
    var knobs: Cursor = .{ .bytes = raw[0..raw_len] };
    var out = try makeOutbound(&knobs);
    defer out.deinit();
    var sk: session_key.SessionKey = undefined;
    try out.sessionKey(&sk);
    var in: session.InboundGroupSession = undefined;
    try session.InboundGroupSession.fromSessionKey(&sk, &in);
    defer in.deinit();
    var key: pickle.PickleKey = undefined;
    expand(&knobs, &key);
    var other = key;
    flipBit(&knobs, &other);

    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var po: [pickle.outbound_len]u8 = undefined;
    out.pickle(&po);
    var pi: [pickle.inbound_len]u8 = undefined;
    in.pickle(&pi);
    var so: [pickle.sealed_outbound_len]u8 = undefined;
    out.pickleSealed(io, &key, &so);
    var si: [pickle.sealed_inbound_len]u8 = undefined;
    in.pickleSealed(io, &key, &si);
    defer std.crypto.secureZero(u8, &po);
    defer std.crypto.secureZero(u8, &pi);

    {
        var o2: session.OutboundSession = undefined;
        session.OutboundSession.fromPickle(&po, &o2) catch return error.GenuinePickleRefused;
        defer o2.deinit();
        var inb2: session.InboundGroupSession = undefined;
        session.InboundGroupSession.fromPickle(&pi, &inb2) catch return error.GenuinePickleRefused;
        inb2.deinit();
        PickleMark.mark(.plain_roundtrip);
        var o3: session.OutboundSession = undefined;
        session.OutboundSession.fromSealedPickle(&so, &key, &o3) catch return error.GenuineSealedRefused;
        o3.deinit();
        var inb3: session.InboundGroupSession = undefined;
        session.InboundGroupSession.fromSealedPickle(&si, &key, &inb3) catch return error.GenuineSealedRefused;
        inb3.deinit();
        PickleMark.mark(.sealed_roundtrip);
    }
    // Plain pickles carry no integrity: damaged ones may be accepted, never panic.
    {
        var buf: [pickle.inbound_len + 8]u8 = undefined;
        const n = damage(src, &buf, if (knobs.byte() & 1 == 0) &po else &pi);
        var o2: session.OutboundSession = undefined;
        if (session.OutboundSession.fromPickle(buf[0..n], &o2)) {
            o2.deinit();
            PickleMark.mark(.plain_damaged_ok);
        } else |_| PickleMark.mark(.plain_damaged_refused);
        var inb2: session.InboundGroupSession = undefined;
        if (session.InboundGroupSession.fromPickle(buf[0..n], &inb2)) inb2.deinit() else |_| {}
    }
    // Sealed: any single flipped bit, any truncation, any other key refused.
    {
        var c1 = so;
        flipBit(&knobs, &c1);
        var o2: session.OutboundSession = undefined;
        if (session.OutboundSession.fromSealedPickle(&c1, &key, &o2)) |_| return error.FlippedSealedAccepted else |_| {}
        var c2 = si;
        flipBit(&knobs, &c2);
        var inb2: session.InboundGroupSession = undefined;
        if (session.InboundGroupSession.fromSealedPickle(&c2, &key, &inb2)) |_| return error.FlippedSealedAccepted else |_| {}
        PickleMark.mark(.sealed_flipped_refused);
        const cut = knobs.ranged(0, @intCast(si.len - 1));
        if (session.InboundGroupSession.fromSealedPickle(si[0..cut], &key, &inb2)) |_| return error.TruncatedSealedAccepted else |_| {}
        PickleMark.mark(.sealed_truncated_refused);
        if (session.InboundGroupSession.fromSealedPickle(&si, &other, &inb2)) |_| return error.WrongKeySealedAccepted else |_| {}
        if (session.OutboundSession.fromSealedPickle(&so, &other, &o2)) |_| return error.WrongKeySealedAccepted else |_| {}
        PickleMark.mark(.sealed_wrong_key_refused);
        var buf: [pickle.sealed_inbound_len + 8]u8 = undefined;
        const n = damage(src, &buf, &si);
        if (session.InboundGroupSession.fromSealedPickle(buf[0..n], &key, &inb2)) |_| {
            if (!std.mem.eql(u8, buf[0..n], &si)) return error.DamagedSealedAccepted;
            inb2.deinit();
        } else |_| PickleMark.mark(.sealed_damaged_refused);
    }
}

test "fuzz: megolm pickles, genuine accepted / damaged sealed refused" {
    try testing.fuzz({}, smithWrap(fuzzPickle), .{});
}
test "fuzz driver: MEGOLM_FUZZ (pickle)" {
    try fuzz_driver.run(fuzzPickle, .{ .prefix = "MEGOLM_FUZZ", .name = "megolm-pickle" });
}
test "fuzz harness: pickle, 300 seeds, reaches every outcome" {
    try PickleMark.reach(fuzzPickle, "megolm-pickle", 300);
}
