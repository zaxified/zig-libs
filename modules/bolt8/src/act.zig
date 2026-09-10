// SPDX-License-Identifier: MIT

//! BOLT#8 handshake message framing — Act One/Two/Three's fixed byte
//! shapes ("Authenticated Key Exchange Handshake Specification", "Handshake
//! Exchange"). REAL, not a Fable stub: parsing/serializing these fixed
//! layouts is pure wire-shape logic with no cryptographic decision in it
//! (the crypto — what the ciphertext fields actually CONTAIN — lives in
//! `handshake.zig`, mirroring how `sphinx.packet` (framing) is split from
//! `sphinx.core` (crypto) in this repo's sibling Lightning module).
//!
//! Every message starts with a single version byte (`0` = this spec;
//! anything else MUST be rejected before any further parsing — "Handshake
//! Versioning"):
//!
//!   Act One   (50 bytes): version(1) ‖ e.pub(33, compressed, cleartext) ‖ c(16, AEAD tag only — zero-length ciphertext)
//!   Act Two   (50 bytes): version(1) ‖ e.pub(33, compressed, cleartext) ‖ c(16, AEAD tag only)
//!   Act Three (66 bytes): version(1) ‖ c(49 = enc-static-key(33)+tag(16)) ‖ t(16, AEAD tag only)

const std = @import("std");

/// The one handshake version this module speaks ("Handshake Versioning":
/// "A version of 0 indicates that no change is necessary").
pub const version: u8 = 0;

pub const act1_len = 50;
pub const act2_len = 50;
pub const act3_len = 66;

pub const ParseError = error{
    /// The buffer was not exactly the fixed act length — too short OR too
    /// long ("Read _exactly_ N bytes from the network buffer" — a short
    /// read is a hard failure, not a partial-parse; BOLT#8's own
    /// `*_READ_FAILED` test vectors). Audit finding F9 (2026-09-05):
    /// `fromBytes` used to accept `bytes.len > act_len` and silently
    /// discard the tail rather than reject it, and return no count of
    /// bytes consumed — so a caller could never tell where the next
    /// message started. Zero in-repo consumers (`DECISIONS.md` P1):
    /// tightened to the spec's "exactly" without asking.
    ShortRead,
    /// The leading version byte was not `0` ("Clients MUST reject
    /// handshake attempts initiated with an unknown version" —
    /// `*_BAD_VERSION` test vectors).
    BadVersion,
};

/// Act One: `-> e, es`. Sent initiator -> responder. `e_pub` travels in
/// the clear (Noise's `e` token is never itself encrypted — only the
/// following zero-length AEAD payload's TAG is transmitted, since the
/// plaintext has no length to hide); `tag` is that payload's 16-byte
/// Poly1305 tag with no ciphertext bytes attached.
pub const Act1 = struct {
    e_pub: [33]u8,
    tag: [16]u8,

    pub fn toBytes(self: Act1) [act1_len]u8 {
        var out: [act1_len]u8 = undefined;
        out[0] = version;
        out[1..34].* = self.e_pub;
        out[34..50].* = self.tag;
        return out;
    }

    pub fn fromBytes(bytes: []const u8) ParseError!Act1 {
        if (bytes.len != act1_len) return error.ShortRead;
        if (bytes[0] != version) return error.BadVersion;
        return .{ .e_pub = bytes[1..34].*, .tag = bytes[34..50].* };
    }
};

/// Act Two: `<- e, ee`. Sent responder -> initiator. Byte-identical shape
/// to `Act1` (kept as its own type — not a type alias — so call sites read
/// as which act they are handling, matching the spec's own act-numbered
/// prose).
pub const Act2 = struct {
    e_pub: [33]u8,
    tag: [16]u8,

    pub fn toBytes(self: Act2) [act2_len]u8 {
        var out: [act2_len]u8 = undefined;
        out[0] = version;
        out[1..34].* = self.e_pub;
        out[34..50].* = self.tag;
        return out;
    }

    pub fn fromBytes(bytes: []const u8) ParseError!Act2 {
        if (bytes.len != act2_len) return error.ShortRead;
        if (bytes[0] != version) return error.BadVersion;
        return .{ .e_pub = bytes[1..34].*, .tag = bytes[34..50].* };
    }
};

/// Act Three: `-> s, se`. Sent initiator -> responder. `c` is the
/// initiator's static public key ENCRYPTED with the running key (33-byte
/// plaintext + 16-byte tag = 49 bytes); `t` is a second, separate
/// zero-length AEAD payload's tag (the act's own final authenticating
/// step, distinct AEAD invocation from the one that produced `c`).
pub const Act3 = struct {
    c: [49]u8,
    t: [16]u8,

    pub fn toBytes(self: Act3) [act3_len]u8 {
        var out: [act3_len]u8 = undefined;
        out[0] = version;
        out[1..50].* = self.c;
        out[50..66].* = self.t;
        return out;
    }

    pub fn fromBytes(bytes: []const u8) ParseError!Act3 {
        if (bytes.len != act3_len) return error.ShortRead;
        if (bytes[0] != version) return error.BadVersion;
        return .{ .c = bytes[1..50].*, .t = bytes[50..66].* };
    }
};

// ── tests: real KATs (BOLT#8 Appendix A) — pure framing, no crypto ──────
//
// Hex constants live in `kat_vectors.zig` (single source of truth).

const testing = std.testing;
const kv = @import("kat_vectors.zig");
const act1_bytes = kv.act1_bytes;
const act2_bytes = kv.act2_bytes;
const act3_bytes = kv.act3_bytes;

test "Act1: round-trips the published act1 bytes byte-exact" {
    const a = try Act1.fromBytes(act1_bytes);
    try testing.expectEqualSlices(u8, act1_bytes[1..34], &a.e_pub);
    try testing.expectEqualSlices(u8, act1_bytes[34..50], &a.tag);
    try testing.expectEqualSlices(u8, act1_bytes, &a.toBytes());
}

test "Act2: round-trips the published act2 bytes byte-exact" {
    const a = try Act2.fromBytes(act2_bytes);
    try testing.expectEqualSlices(u8, act2_bytes[1..34], &a.e_pub);
    try testing.expectEqualSlices(u8, act2_bytes[34..50], &a.tag);
    try testing.expectEqualSlices(u8, act2_bytes, &a.toBytes());
}

test "Act3: round-trips the published act3 bytes byte-exact" {
    const a = try Act3.fromBytes(act3_bytes);
    try testing.expectEqualSlices(u8, act3_bytes[1..50], &a.c);
    try testing.expectEqualSlices(u8, act3_bytes[50..66], &a.t);
    try testing.expectEqualSlices(u8, act3_bytes, &a.toBytes());
}

test "Act2: 'transport-initiator act2 short read test' — 49 bytes fails ShortRead" {
    try testing.expectError(error.ShortRead, Act2.fromBytes(act2_bytes[0 .. act2_len - 1]));
}

test "Act2: 'transport-initiator act2 bad version test' — leading 0x01 fails BadVersion" {
    var bad = act2_bytes.*;
    bad[0] = 0x01;
    try testing.expectError(error.BadVersion, Act2.fromBytes(&bad));
}

test "Act1: 'transport-responder act1 short read test' — 49 bytes fails ShortRead" {
    try testing.expectError(error.ShortRead, Act1.fromBytes(act1_bytes[0 .. act1_len - 1]));
}

test "Act1: 'transport-responder act1 bad version test' — leading 0x01 fails BadVersion" {
    var bad = act1_bytes.*;
    bad[0] = 0x01;
    try testing.expectError(error.BadVersion, Act1.fromBytes(&bad));
}

test "Act3: 'transport-responder act3 bad version test' — leading 0x01 fails BadVersion" {
    var bad = act3_bytes.*;
    bad[0] = 0x01;
    try testing.expectError(error.BadVersion, Act3.fromBytes(&bad));
}

test "Act3: 'transport-responder act3 short read test' — 65 bytes fails ShortRead" {
    try testing.expectError(error.ShortRead, Act3.fromBytes(act3_bytes[0 .. act3_len - 1]));
}

test "fromBytes rejects a buffer LONGER than the act, not just a shorter one (F9)" {
    // Audit finding F9 (2026-09-05): BOLT#8 says "Read _exactly_ N bytes
    // from the network buffer", but `fromBytes` used to accept
    // `bytes.len > act_len` and silently discard the tail. Mutation A2 (the
    // audit's own `!=` in place of `<`) left the OLD suite and a live
    // `brontide` interop both green either way -- nothing tested which
    // direction of length mismatch mattered. These three pin it directly.
    var over1: [act1_len + 1]u8 = undefined;
    over1[0..act1_len].* = act1_bytes.*;
    over1[act1_len] = 0xAB;
    try testing.expectError(error.ShortRead, Act1.fromBytes(&over1));

    var over2: [act2_len + 1]u8 = undefined;
    over2[0..act2_len].* = act2_bytes.*;
    over2[act2_len] = 0xAB;
    try testing.expectError(error.ShortRead, Act2.fromBytes(&over2));

    var over3: [act3_len + 1]u8 = undefined;
    over3[0..act3_len].* = act3_bytes.*;
    over3[act3_len] = 0xAB;
    try testing.expectError(error.ShortRead, Act3.fromBytes(&over3));
}

// ── fuzz: the untrusted-wire handshake framing never panics/OOB ────────────
//
// ⚠ All three harnesses below used to open with
//
//     smith.bytes(&buf);
//     const len: usize = smith.valueRangeAtMost(u16, 0, buf.len);
//
// which reads the input and then throws it away: `bytes` consumes
// `@min(buf.len, in.len)` octets and the ranged draw then finds fewer than the
// eight it reads as a little-endian u64, so `len` is the range MINIMUM — zero.
// With no corpus either, each target ran exactly one input for ever:
// `fromBytes("")`, which is `error.ShortRead` before a single field is
// touched. Not one octet of a BOLT#8 act had ever gone through these parsers
// under fuzz, and the Appendix A vectors sitting in `kat_vectors.zig` were
// unreachable from them.

/// `frame` with one octet XORed. A published act with a single byte changed is
/// still a well-shaped act, so it reaches the fields; arbitrary bytes almost
/// always die on the version octet instead.
fn perturbed(comptime frame: []const u8, comptime at: usize, comptime mask: u8) []const u8 {
    return &struct {
        const bytes = blk: {
            var out = frame[0..frame.len].*;
            out[at] ^= mask;
            break :blk out;
        };
    }.bytes;
}

/// Distinct `n`-octet field values a corpus actually produced.
///
/// ⛔ Why the guards pin this and not only an accepted count: `accepted` says a
/// frame was well-shaped, not that the SEED decided its content. Ten seeds
/// carrying one act score the same as one, and a seed grown past the harness's
/// buffer reads back EMPTY without a word. This number only moves when a
/// seed's own octets reach the decoded field.
fn Distinct(comptime n: usize) type {
    return struct {
        seen: [8][n]u8 = undefined,
        count: usize = 0,

        const Self = @This();

        fn add(self: *Self, v: [n]u8) !void {
            for (self.seen[0..self.count]) |prev| {
                if (std.mem.eql(u8, &prev, &v)) return;
            }
            if (self.count == self.seen.len) return error.TooManyDistinct;
            self.seen[self.count] = v;
            self.count += 1;
        }
    };
}

// ── Act One ──────────────────────────────────────────────────────────────────

const act1_seeds = [_][]const u8{
    // "transport-responder successful handshake" act1, verbatim.
    fuzzSeedLocal(kv.act1_bytes),
    // One octet inside `e.pub`: a DIFFERENT ephemeral key that still parses,
    // which is what the distinct-key count below is counting.
    fuzzSeedLocal(perturbed(kv.act1_bytes, 5, 0x01)),
    // "transport-responder act1 bad MAC test". The framing must still accept
    // it — the tag is not this file's business (the crypto is handshake.zig).
    fuzzSeedLocal(kv.act1_bad_mac),
    // "transport-responder act1 bad version test": leading 0x01 -> BadVersion.
    fuzzSeedLocal(perturbed(kv.act1_bytes, 0, 0x01)),
    // "transport-responder act1 short read test": 49 octets -> ShortRead.
    fuzzSeedLocal(kv.act1_bytes[0 .. act1_len - 1]),
    // A full act with 32 octets of trailing garbage, filling the buffer.
    // Audit finding F9 (2026-09-05): `fromBytes` used to silently ignore
    // this tail instead of rejecting it (BOLT#8: "Read _exactly_ N bytes");
    // now this seed is REJECTED (ShortRead), which is what the "accepted"
    // count below counts.
    fuzzSeedLocal(&(kv.act1_bytes.* ++ [_]u8{0xAB} ** 32)),
    // Version 0 with every field zero — a third distinct ephemeral key, and
    // the shape the all-zero fuzz round would have produced had the length
    // draw not collapsed to 0 before it.
    fuzzSeedLocal(&[_]u8{0x00} ** act1_len),
    // The one input this target actually ran, for ever, before the corpus.
    fuzzSeedLocal(""),
};

fn fuzzAct1Decode(_: void, smith: *std.testing.Smith) !void {
    // act1_len + 32 also sizes the longest seed above (a full act plus
    // trailing octets); a seed longer than the buffer reads back EMPTY.
    var buf: [act1_len + 32]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const a = Act1.fromBytes(buf[0..len]) catch return;
    // Fixed layout, so decode-then-encode must reproduce the first `act1_len`
    // octets exactly. Before the draw was fixed this had never run on
    // anything but a rejected empty slice.
    try testing.expectEqualSlices(u8, buf[0..act1_len], &a.toBytes());
}
test "fuzz Act1.fromBytes never panics" {
    try testing.fuzz({}, fuzzAct1Decode, .{ .corpus = &act1_seeds });
}

test "corpus: Act1 seeds reach the parser, counts pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var keys: Distinct(33) = .{};
    for (act1_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [act1_len + 32]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const a = Act1.fromBytes(buf[0..len]) catch continue;
        accepted += 1;
        try keys.add(a.e_pub);
    }
    try testing.expectEqual(act1_seeds.len - 1, nonempty); // all but seed("")
    try testing.expectEqual(@as(usize, 4), accepted); // F9: trailing-garbage seed now rejected (was 5)
    try testing.expectEqual(@as(usize, 3), keys.count);
}

// ── Act Two ──────────────────────────────────────────────────────────────────

const act2_seeds = [_][]const u8{
    // "transport-initiator successful handshake" act2, verbatim.
    fuzzSeedLocal(kv.act2_bytes),
    // One octet inside `e.pub`: a different ephemeral key that still parses.
    fuzzSeedLocal(perturbed(kv.act2_bytes, 5, 0x01)),
    // "transport-initiator act2 bad MAC test" — accepted by the framing.
    fuzzSeedLocal(kv.act2_bad_mac),
    // "transport-initiator act2 bad version test": 0x01 -> BadVersion.
    fuzzSeedLocal(perturbed(kv.act2_bytes, 0, 0x01)),
    // "transport-initiator act2 short read test": 49 octets -> ShortRead.
    fuzzSeedLocal(kv.act2_bytes[0 .. act2_len - 1]),
    // Trailing octets past the act, filling the buffer — F9: now rejected.
    fuzzSeedLocal(&(kv.act2_bytes.* ++ [_]u8{0xAB} ** 32)),
    // All-zero act: version 0, a third distinct key.
    fuzzSeedLocal(&[_]u8{0x00} ** act2_len),
    fuzzSeedLocal(""),
};

fn fuzzAct2Decode(_: void, smith: *std.testing.Smith) !void {
    var buf: [act2_len + 32]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const a = Act2.fromBytes(buf[0..len]) catch return;
    try testing.expectEqualSlices(u8, buf[0..act2_len], &a.toBytes());
}
test "fuzz Act2.fromBytes never panics" {
    try testing.fuzz({}, fuzzAct2Decode, .{ .corpus = &act2_seeds });
}

test "corpus: Act2 seeds reach the parser, counts pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var keys: Distinct(33) = .{};
    for (act2_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [act2_len + 32]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const a = Act2.fromBytes(buf[0..len]) catch continue;
        accepted += 1;
        try keys.add(a.e_pub);
    }
    try testing.expectEqual(act2_seeds.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 4), accepted); // F9: trailing-garbage seed now rejected (was 5)
    try testing.expectEqual(@as(usize, 3), keys.count);
}

// ── Act Three ────────────────────────────────────────────────────────────────

const act3_seeds = [_][]const u8{
    // "transport-responder successful handshake" act3, verbatim.
    fuzzSeedLocal(kv.act3_bytes),
    // "transport-responder act3 bad ciphertext test": an octet of `c` changed
    // — a different encrypted static key, still a well-shaped act.
    fuzzSeedLocal(kv.act3_bad_ciphertext),
    // "transport-responder act3 bad MAC test": the last octet of `t` changed,
    // so `c` is unchanged — accepted, and it adds NO distinct `c`.
    fuzzSeedLocal(kv.act3_bad_tag),
    // "transport-responder act3 bad rs test": a third distinct `c`.
    fuzzSeedLocal(kv.act3_bad_rs_message),
    // "transport-responder act3 bad version test": 0x01 -> BadVersion.
    fuzzSeedLocal(perturbed(kv.act3_bytes, 0, 0x01)),
    // "transport-responder act3 short read test": 65 octets -> ShortRead.
    fuzzSeedLocal(kv.act3_bytes[0 .. act3_len - 1]),
    // Trailing octets past the act, filling the buffer — F9: now rejected.
    fuzzSeedLocal(&(kv.act3_bytes.* ++ [_]u8{0xAB} ** 32)),
    // All-zero act: version 0, a fourth distinct `c`.
    fuzzSeedLocal(&[_]u8{0x00} ** act3_len),
    fuzzSeedLocal(""),
};

fn fuzzAct3Decode(_: void, smith: *std.testing.Smith) !void {
    var buf: [act3_len + 32]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const a = Act3.fromBytes(buf[0..len]) catch return;
    try testing.expectEqualSlices(u8, buf[0..act3_len], &a.toBytes());
}
test "fuzz Act3.fromBytes never panics" {
    try testing.fuzz({}, fuzzAct3Decode, .{ .corpus = &act3_seeds });
}

test "corpus: Act3 seeds reach the parser, counts pinned" {
    var nonempty: usize = 0;
    var accepted: usize = 0;
    var ciphertexts: Distinct(49) = .{};
    for (act3_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [act3_len + 32]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const a = Act3.fromBytes(buf[0..len]) catch continue;
        accepted += 1;
        try ciphertexts.add(a.c);
    }
    try testing.expectEqual(act3_seeds.len - 1, nonempty);
    try testing.expectEqual(@as(usize, 5), accepted); // F9: trailing-garbage seed now rejected (was 6)
    try testing.expectEqual(@as(usize, 4), ciphertexts.count);
}

/// ⛔ A LOCAL COPY of `testkit.fuzz.seed`, and it has to be one. Enrolling this
/// module in `test_deps` puts it into `zig build check-testonly`, whose probe
/// imports the PUBLISHED module and references every declaration three levels
/// deep — and this module deliberately guards a test-only function with a
/// `@compileError` that fires outside a test build. The two gates contradict
/// each other: `check-testonly` proves the test dep is not needed by the
/// published module by touching decls that refuse to be touched.
///
/// So the nine lines below stay here rather than the module joining `test_deps`.
/// The anchor test underneath is what stops this copy drifting from
/// `modules/testkit/src/fuzz.zig`: it drives the real `std.testing.Smith` over
/// what this produces, exactly as testkit's own tests do.
fn fuzzSeedLocal(comptime frame: []const u8) []const u8 {
    return &struct {
        const bytes = std.mem.toBytes(@as(u32, @intCast(frame.len))) ++ frame[0..frame.len].*;
    }.bytes;
}

test "the local seed helper produces what Smith.slice reads back" {
    const s = fuzzSeedLocal("abcdef");
    var smith: std.testing.Smith = .{ .in = s };
    var buf: [32]u8 = undefined;
    const n = smith.slice(&buf);
    try std.testing.expectEqualStrings("abcdef", buf[0..n]);
}
