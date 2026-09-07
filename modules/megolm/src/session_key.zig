// SPDX-License-Identifier: MIT

//! session_key.zig — the two "Data exchange formats" megolm.md defines for
//! sharing ratchet state out of band: the **session-sharing format**
//! (signed, sent by the session owner when a session is first shared) and
//! the **session-export format** (unsigned, used when re-sharing a
//! ratcheted-forward copy would otherwise invalidate the original
//! signature — see megolm.md "Session export format").
//!
//! ```
//! session-sharing (SessionKey), version 0x02:
//! +---+----+--------+--------+--------+--------+------+-----------+
//! | V | i  | R(i,0) | R(i,1) | R(i,2) | R(i,3) | Kpub | Signature |
//! +---+----+--------+--------+--------+--------+------+-----------+
//! 0   1    5        37       69      101      133    165         229   bytes
//!
//! session-export (ExportedSessionKey), version 0x01: identical, minus
//! Signature (bytes 0..165 only).
//! ```
//!
//! `i` is big-endian u32. Both wrap the SAME 165-byte "signed part"
//! (version || i || ratchet || Kpub); the session-sharing format appends a
//! 64-byte Ed25519 signature OVER those 165 bytes (verified against the
//! `Kpub` embedded in them — self-certifying, like a self-signed cert) and
//! self-verifies on decode; the export format has nothing to verify against
//! (there is no separate authority key) and an importer's caller is
//! responsible for authenticating the out-of-band channel it arrived over
//! (mirrors vodozemac's `InboundGroupSession::import` doc comment).

const std = @import("std");
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const testkit = @import("testkit");
const ratchet_mod = @import("ratchet.zig");

const Ed25519 = std.crypto.sign.Ed25519;

pub const share_version: u8 = 0x02;
pub const export_version: u8 = 0x01;

const index_len = 4;
const pubkey_len = Ed25519.PublicKey.encoded_length; // 32
const signature_len = Ed25519.Signature.encoded_length; // 64

/// Length of the "signed part" shared by both formats: version(1) +
/// index(4) + ratchet(128) + Kpub(32).
pub const signed_part_len = 1 + index_len + ratchet_mod.ratchet_len + pubkey_len; // 165
pub const export_len = signed_part_len; // 165 -- export format IS the signed part, unsigned
pub const share_len = signed_part_len + signature_len; // 229

pub const DecodeError = error{
    WrongLength,
    UnsupportedVersion,
    InvalidPublicKey,
    InvalidSignature,
};

/// The unsigned session-export format.
pub const ExportedSessionKey = struct {
    ratchet_index: u32,
    ratchet: [ratchet_mod.ratchet_len]u8,
    signing_key: [pubkey_len]u8,

    pub fn encodeSignedPart(self: *const ExportedSessionKey, version: u8, out: *[signed_part_len]u8) void {
        out[0] = version;
        std.mem.writeInt(u32, out[1..][0..index_len], self.ratchet_index, .big);
        @memcpy(out[1 + index_len ..][0..ratchet_mod.ratchet_len], &self.ratchet);
        @memcpy(out[1 + index_len + ratchet_mod.ratchet_len ..][0..pubkey_len], &self.signing_key);
    }

    pub fn encode(self: *const ExportedSessionKey) [export_len]u8 {
        var out: [export_len]u8 = undefined;
        self.encodeSignedPart(export_version, &out);
        return out;
    }

    pub fn decode(bytes: []const u8) DecodeError!ExportedSessionKey {
        if (bytes.len != export_len) return error.WrongLength;
        if (bytes[0] != export_version) return error.UnsupportedVersion;
        return decodeSignedPartUnchecked(bytes[0..signed_part_len]);
    }

    pub fn toBase64(self: *const ExportedSessionKey, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const raw = self.encode();
        return base64Encode(allocator, &raw);
    }

    pub fn fromBase64(allocator: std.mem.Allocator, s: []const u8) (DecodeError || std.mem.Allocator.Error || std.base64.Error)!ExportedSessionKey {
        const raw = try base64Decode(allocator, s);
        defer allocator.free(raw);
        return decode(raw);
    }

    pub fn secureZero(self: *ExportedSessionKey) void {
        std.crypto.secureZero(u8, &self.ratchet);
    }
};

/// The signed session-sharing format.
pub const SessionKey = struct {
    inner: ExportedSessionKey,
    signature: [signature_len]u8,

    pub fn encode(self: *const SessionKey) [share_len]u8 {
        var out: [share_len]u8 = undefined;
        self.inner.encodeSignedPart(share_version, out[0..signed_part_len]);
        @memcpy(out[signed_part_len..], &self.signature);
        return out;
    }

    /// Decode AND verify: the embedded `Kpub` must validate the trailing
    /// signature over the leading 165 bytes (self-certifying — this is
    /// what makes `SessionKey`, unlike `ExportedSessionKey`, safe to trust
    /// without a separate out-of-band authentication step, PROVIDED the
    /// channel it arrived over authenticates the sender at all — see the
    /// module doc comment and SPEC.md's threat model).
    pub fn decode(bytes: []const u8) DecodeError!SessionKey {
        if (bytes.len != share_len) return error.WrongLength;
        if (bytes[0] != share_version) return error.UnsupportedVersion;

        const signed_part = bytes[0..signed_part_len];
        const sig_bytes = bytes[signed_part_len..][0..signature_len].*;
        const inner = try decodeSignedPartUnchecked(signed_part);

        const pk = Ed25519.PublicKey.fromBytes(inner.signing_key) catch return error.InvalidPublicKey;
        const sig = Ed25519.Signature.fromBytes(sig_bytes);
        sig.verify(signed_part, pk) catch return error.InvalidSignature;

        return .{ .inner = inner, .signature = sig_bytes };
    }

    pub fn toBase64(self: *const SessionKey, allocator: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const raw = self.encode();
        return base64Encode(allocator, &raw);
    }

    pub fn fromBase64(allocator: std.mem.Allocator, s: []const u8) (DecodeError || std.mem.Allocator.Error || std.base64.Error)!SessionKey {
        const raw = try base64Decode(allocator, s);
        defer allocator.free(raw);
        return decode(raw);
    }

    pub fn secureZero(self: *SessionKey) void {
        self.inner.secureZero();
    }
};

fn decodeSignedPartUnchecked(bytes: *const [signed_part_len]u8) DecodeError!ExportedSessionKey {
    const index = std.mem.readInt(u32, bytes[1..][0..index_len], .big);
    const ratchet: [ratchet_mod.ratchet_len]u8 = bytes[1 + index_len ..][0..ratchet_mod.ratchet_len].*;
    const signing_key: [pubkey_len]u8 = bytes[1 + index_len + ratchet_mod.ratchet_len ..][0..pubkey_len].*;
    return .{ .ratchet_index = index, .ratchet = ratchet, .signing_key = signing_key };
}

fn base64Encode(allocator: std.mem.Allocator, bytes: []const u8) std.mem.Allocator.Error![]u8 {
    const codec = std.base64.standard_no_pad;
    const out = try allocator.alloc(u8, codec.Encoder.calcSize(bytes.len));
    _ = codec.Encoder.encode(out, bytes);
    return out;
}

fn base64Decode(allocator: std.mem.Allocator, s: []const u8) (std.mem.Allocator.Error || std.base64.Error)![]u8 {
    const codec = std.base64.standard_no_pad;
    const size = try codec.Decoder.calcSizeForSlice(s);
    const out = try allocator.alloc(u8, size);
    errdefer allocator.free(out);
    try codec.Decoder.decode(out, s);
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "ExportedSessionKey encode/decode round-trip" {
    var key = ExportedSessionKey{
        .ratchet_index = 0x01020304,
        .ratchet = [_]u8{0x77} ** ratchet_mod.ratchet_len,
        .signing_key = [_]u8{0x33} ** pubkey_len,
    };
    const raw = key.encode();
    try testing.expectEqual(@as(usize, export_len), raw.len);
    try testing.expectEqual(export_version, raw[0]);

    const decoded = try ExportedSessionKey.decode(&raw);
    try testing.expectEqual(key.ratchet_index, decoded.ratchet_index);
    try testing.expectEqualSlices(u8, &key.ratchet, &decoded.ratchet);
    try testing.expectEqualSlices(u8, &key.signing_key, &decoded.signing_key);
}

test "ExportedSessionKey rejects wrong length and wrong version" {
    try testing.expectError(error.WrongLength, ExportedSessionKey.decode(&[_]u8{0} ** (export_len - 1)));
    var bad_version = [_]u8{0} ** export_len;
    bad_version[0] = share_version; // 0x02 instead of 0x01
    try testing.expectError(error.UnsupportedVersion, ExportedSessionKey.decode(&bad_version));
}

test "SessionKey signs itself and self-verifies on decode" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const kp = Ed25519.KeyPair.generate(io);

    var inner = ExportedSessionKey{
        .ratchet_index = 0,
        .ratchet = [_]u8{0x11} ** ratchet_mod.ratchet_len,
        .signing_key = kp.public_key.toBytes(),
    };
    var signed_part: [signed_part_len]u8 = undefined;
    inner.encodeSignedPart(share_version, &signed_part);
    const sig = try kp.sign(&signed_part, null);

    const key = SessionKey{ .inner = inner, .signature = sig.toBytes() };
    const raw = key.encode();

    const decoded = try SessionKey.decode(&raw);
    try testing.expectEqual(inner.ratchet_index, decoded.inner.ratchet_index);
    try testing.expectEqualSlices(u8, &inner.ratchet, &decoded.inner.ratchet);
}

test "SessionKey rejects a tampered signature" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const kp = Ed25519.KeyPair.generate(io);

    var inner = ExportedSessionKey{
        .ratchet_index = 0,
        .ratchet = [_]u8{0x22} ** ratchet_mod.ratchet_len,
        .signing_key = kp.public_key.toBytes(),
    };
    var signed_part: [signed_part_len]u8 = undefined;
    inner.encodeSignedPart(share_version, &signed_part);
    const sig = try kp.sign(&signed_part, null);

    const key = SessionKey{ .inner = inner, .signature = sig.toBytes() };
    var raw = key.encode();
    raw[raw.len - 1] ^= 0xFF; // tamper one byte of the trailing signature

    try testing.expectError(error.InvalidSignature, SessionKey.decode(&raw));
}

test "SessionKey rejects a signature that doesn't match the embedded ratchet (tampered payload)" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    const kp = Ed25519.KeyPair.generate(io);

    var inner = ExportedSessionKey{
        .ratchet_index = 0,
        .ratchet = [_]u8{0x22} ** ratchet_mod.ratchet_len,
        .signing_key = kp.public_key.toBytes(),
    };
    var signed_part: [signed_part_len]u8 = undefined;
    inner.encodeSignedPart(share_version, &signed_part);
    const sig = try kp.sign(&signed_part, null);

    const key = SessionKey{ .inner = inner, .signature = sig.toBytes() };
    var raw = key.encode();
    raw[10] ^= 0xFF; // tamper a ratchet byte -- signature no longer matches

    try testing.expectError(error.InvalidSignature, SessionKey.decode(&raw));
}

fn testIo() std.Io.Threaded {
    return std.Io.Threaded.init(testing.allocator, .{});
}

// ── fuzz: the session-key decoders ───────────────────────────────────────
//
// `SessionKey.decode`/`fromBase64` and `ExportedSessionKey.decode`/
// `fromBase64` are the other half of `megolm`'s attacker-facing surface
// (the first half is `message.zig`): a session key arrives from whoever
// claims to be sharing the session, and an *exported* one arrives from a
// key backup, i.e. from storage this module does not control. Both were
// unfuzzed — the module had no `testing.fuzz(` call at all, so the
// module-granularity `grep` in `scripts/fuzz-sweep.sh` never listed it.
//
// These decoders are fixed-width, so unlike `message.zig` the shape that
// matters is the LENGTH GATE and what happens just past it: this harness
// biases lengths hard toward `export_len` (165) and `share_len` (229) and
// their off-by-ones, so the `bytes.len != …` check, the version byte, the
// big-endian index read, the Ed25519 `PublicKey.fromBytes` rejection of a
// non-canonical point and the signature verify all get real budget rather
// than being sheltered behind a length that never matches.
//
// Reachability: with a temporary `@panic` where `SessionKey.decode`
// rejects a bad Ed25519 signature — i.e. past the length gate, the
// version byte, the big-endian index read and the public-key parse — a
// 60 s `scripts/fuzz-sweep.sh` run found it. Probe then removed.
/// ⛔ The reachability note above was measured under `--fuzz`. The ORDINARY
/// lane replays `options.corpus` plus one empty input, and this target had no
/// corpus — so the very first draw, `smith.value(enum { … })`, returned the
/// first variant on every round, `len` was always `export_len`, and the
/// `smith.slice` after it read a zero-length input and zero-filled 165 octets.
/// The whole length sweep the comment above is about — `share_len`, the
/// off-by-ones, the arbitrary lengths — had never happened, and the bytes
/// handed to both decoders were the same all-zero buffer every time.
///
/// The byte draw now comes FIRST, into the full buffer, and `len` selects how
/// much of it is used afterwards. The seed's own octets therefore survive
/// whichever length branch is taken. A seed is the key material as a
/// `testkit.fuzz` slice seed, then the `u64` words the knobs read:
/// `[length_mode, (near: base_is_export, delta, plus) | (any: len),
/// version_mode, (any: version), b64_corrupt, (corrupt: position, value)]`.
const SessionKeyCorpus = struct {
    store: [10 * (4 + 320 + 8 * 8)]u8 = undefined,
    used: usize = 0,
    entries: [10][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *SessionKeyCorpus, frame: []const u8, words: []const u64) void {
        const start = self.used;
        var at = start + testkit.fuzz.seedInto(self.store[start..], frame).len;
        for (words) |w| {
            std.mem.writeInt(u64, self.store[at..][0..8], w, .little);
            at += 8;
        }
        self.entries[self.n] = self.store[start..at];
        self.used = at;
        self.n += 1;
    }

    fn build(self: *SessionKeyCorpus, io: std.Io) []const []const u8 {
        const kp = Ed25519.KeyPair.generate(io);
        var inner = ExportedSessionKey{
            .ratchet_index = 0x01020304,
            .ratchet = [_]u8{0x77} ** ratchet_mod.ratchet_len,
            .signing_key = kp.public_key.toBytes(),
        };
        const exported = inner.encode();
        var signed_part: [signed_part_len]u8 = undefined;
        inner.encodeSignedPart(share_version, &signed_part);
        const sig = kp.sign(&signed_part, null) catch unreachable;
        const shared = (SessionKey{ .inner = inner, .signature = sig.toBytes() }).encode();

        // ⛔ `.exact_export`/`.exact_share` are word 0 and 1; the version knob
        // `1` is `.exp` and `0` is `.share`. Both are picked to MATCH the
        // frame, so the seeds actually decode rather than being rewritten at
        // offset 0 into something the version gate refuses.
        self.push(&exported, &.{ 0, 1, 0 }); // a real 165-octet export
        self.push(&shared, &.{ 1, 0, 0 }); // a real 229-octet share, self-verifying
        var tampered = shared;
        tampered[share_len - 1] ^= 0x01; // one octet in the Ed25519 signature
        self.push(&tampered, &.{ 1, 0, 0 });
        var bad_ratchet = shared;
        bad_ratchet[10] ^= 0x01; // one octet in the ratchet: signature no longer covers it
        self.push(&bad_ratchet, &.{ 1, 0, 0 });
        self.push(&exported, &.{ 1, 0, 0 }); // 165 octets read as a 229-octet share
        // `.near`: `export_len` +/- a delta, the off-by-ones around the gate.
        self.push(&exported, &.{ 2, 1, 1, 1, 1, 0 }); // 166
        self.push(&exported, &.{ 2, 1, 1, 0, 1, 0 }); // 164
        // `.any`: an arbitrary length, and the version byte drawn arbitrarily.
        self.push(&shared, &.{ 3, 300, 2, 0xff, 0 });
        // A real export with its base64 wrapper corrupted at offset 0.
        self.push(&exported, &.{ 0, 1, 1, 0, 0xff });
        self.push("", &.{}); // and the input this target used to run for ever
        return self.entries[0..self.n];
    }
};

test "fuzz: session-key decoders never panic on arbitrary bytes" {
    var threaded = testIo();
    defer threaded.deinit();
    var corpus: SessionKeyCorpus = .{};
    try testing.fuzz({}, fuzzSessionKeyDecode, .{ .corpus = corpus.build(threaded.io()) });
}

test "corpus: the session-key seeds drive the length sweep, and the counts are pinned" {
    var threaded = testIo();
    defer threaded.deinit();
    var corpus: SessionKeyCorpus = .{};
    var lengths = [_]usize{0} ** 4;
    var versions = [_]usize{0} ** 3;
    var b64_corrupted: usize = 0;
    var exports: usize = 0;
    var shares: usize = 0;
    var len_total: usize = 0;
    for (corpus.build(threaded.io())) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [320]u8 = undefined;
        _ = smith.slice(&buf);
        const mode = smith.value(u64) % 4;
        lengths[@intCast(mode)] += 1;
        const len: usize = switch (mode) {
            0 => export_len,
            1 => share_len,
            2 => blk: {
                const base: usize = if (smith.value(u64) % 2 == 1) export_len else share_len;
                const delta: usize = @intCast(smith.value(u64) % 5);
                break :blk if (smith.value(u64) % 2 == 1) base + delta else base -| delta;
            },
            else => @intCast(smith.value(u64) % (buf.len + 1)),
        };
        len_total += len;
        if (len > 0) {
            const which = smith.value(enum { share, exp, any });
            versions[@intFromEnum(which)] += 1;
            buf[0] = switch (which) {
                .share => share_version,
                .exp => export_version,
                .any => smith.value(u8),
            };
        }
        if (ExportedSessionKey.decode(buf[0..len])) |_| exports += 1 else |_| {}
        if (SessionKey.decode(buf[0..len])) |_| shares += 1 else |_| {}
        // ⚠ The last three knobs, drawn after everything above. Mirrored here
        // rather than left unmeasured: `boolWeighted(3, 1)` is the one that
        // decides whether `base64Decode`'s own reject path is ever entered.
        const b64 = try base64Encode(testing.allocator, buf[0..len]);
        defer testing.allocator.free(b64);
        if (b64.len > 0 and smith.boolWeighted(3, 1)) {
            b64[smith.index(b64.len)] = smith.value(u8);
            b64_corrupted += 1;
        }
        _ = ExportedSessionKey.fromBase64(testing.allocator, b64) catch {};
        _ = SessionKey.fromBase64(testing.allocator, b64) catch {};
    }
    // ⛔ Before this, `mode` was always `.exact_export` and `len` always 165 —
    // `len_total` would have been 10 * 165 = 1650 with all-zero content, and
    // neither decoder would ever have accepted anything (the all-zero
    // `signing_key` is not a canonical Ed25519 point).
    // ⛔ Pinned as histograms, not `expect(seen)`. A boolean cannot tell an
    // arm that ran once from one that ran nine times, and it cannot notice a
    // seed moving from one arm to another — which is exactly the failure a
    // corpus guard is here to catch. Measured 2026-09-08.
    try testing.expectEqualSlices(usize, &[_]usize{ 3, 4, 2, 1 }, &lengths);
    try testing.expectEqualSlices(usize, &[_]usize{ 5, 4, 1 }, &versions);
    try testing.expectEqual(@as(usize, 1), b64_corrupted);
    try testing.expectEqual(@as(usize, 2), exports);
    try testing.expectEqual(@as(usize, 1), shares);
    try testing.expectEqual(@as(usize, 2041), len_total);
}

fn fuzzSessionKeyDecode(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;

    // ⚠ The byte draw comes FIRST, into the WHOLE buffer, and the length is
    // chosen after it. It used to sit behind the length switch, which meant
    // that outside `--fuzz` the switch collapsed to its first variant and the
    // slice read an already-exhausted input.
    var buf: [320]u8 = undefined;
    _ = smith.slice(&buf);
    // The length knobs are `value(u64)` reduced here, never bounded draws: a
    // bounded draw returns its range minimum unless a whole eight-octet word
    // lands inside the range, which is how this switch used to collapse onto
    // `.exact_export` on every input (`check-fuzz-reach`'s own option 2).
    const len: usize = switch (smith.value(u64) % 4) {
        0 => export_len,
        1 => share_len,
        2 => blk: {
            const base: usize = if (smith.value(u64) % 2 == 1) export_len else share_len;
            const delta: usize = @intCast(smith.value(u64) % 5);
            break :blk if (smith.value(u64) % 2 == 1) base + delta else base -| delta;
        },
        else => @intCast(smith.value(u64) % (buf.len + 1)),
    };
    // The version byte gates everything after the length check, so make it
    // the right one most of the time.
    if (len > 0) {
        buf[0] = switch (smith.value(enum { share, exp, any })) {
            .share => share_version,
            .exp => export_version,
            .any => smith.value(u8),
        };
    }
    const bytes = buf[0..len];

    _ = ExportedSessionKey.decode(bytes) catch {};
    _ = SessionKey.decode(bytes) catch {};

    const b64 = try base64Encode(allocator, bytes);
    defer allocator.free(b64);
    if (b64.len > 0 and smith.boolWeighted(3, 1)) b64[smith.index(b64.len)] = smith.value(u8);
    _ = ExportedSessionKey.fromBase64(allocator, b64) catch {};
    _ = SessionKey.fromBase64(allocator, b64) catch {};
}
