// SPDX-License-Identifier: MIT
//! lms — LMS and HSS (RFC 8554, Leighton-Micali hash-based signatures):
//! **stateful** post-quantum signatures over SHA-256, pure Zig over
//! `std.crypto`. LMS is the tree scheme, HSS the hierarchy of up to eight
//! LMS trees; both are the NIST SP 800-208 firmware-signing scheme (and, in
//! its SHA-256/256 form with L = 1, CNSA 2.0's).
//!
//! Parameter sets: the RFC's SHA-256, n = m = 32 sets — LMS H5 / H10 / H15 /
//! H20 / H25 (typecodes 5..9) and LM-OTS W1 / W2 / W4 / W8 (1..4). Any mix is
//! accepted per HSS level.
//!
//! What is here: RFC 8554 Algorithm 1–4b (LM-OTS), 5/6/6a (LMS), 7/8/§6.3
//! (HSS), Appendix A pseudorandom key generation from a `(SEED, I)` pair,
//! and the wire formats of §3.3. `verify` allocates nothing and returns
//! `false` for every malformed input; keygen and sign take an allocator (the
//! public node cache; see `sign.zig` for sizes and costs).
//!
//! ** STATEFUL-SIGNATURE HAZARD ** — every leaf signs at most one message.
//! Signing two messages with one leaf lets an attacker forge. `sign`
//! advances the position before it produces a signature and reports
//! `error.KeyExhausted` at the end, but making the new position durable
//! before the signature is released, never signing from a restored backup, and
//! never sharing one key between processes without partitioning is the
//! caller's job (RFC 8554 §5.4.1, §9.2). `SigningKey` adds the hook that makes
//! the first of those hard to forget. If that cannot be guaranteed, use the
//! stateless sibling `slhdsa`. See SPEC.md.
//!
//! No RNG: the caller supplies the 32-byte SEED and the 16-byte `I` of the
//! top tree (both from a CSPRNG, SEED secret and never reused for anything
//! else, RFC 8554 §5.2), so key generation is deterministic and testable.
//! The LM-OTS randomizer `C` and the lower HSS trees are derived from SEED
//! (see `core.deriveRandomizer`, `sign.zig`).
//!
//! Validated against RFC 8554 Appendix F Test Cases 1 and 2 (verification of
//! both HSS signatures; for Test Case 2 also regeneration of both public
//! keys from the RFC's SEED and `I`, and byte-exact reproduction of both LMS
//! signatures given the RFC's randomizer `C`). LM-OTS W1 and W2 have no RFC
//! vector and are covered by round trips only.
//!
//! Zig std GAP: yes — std.crypto has no stateful hash-based signature (LMS
//! or XMSS). Recon: `std.crypto.hash.sha2.Sha256` for H, `std.mem`
//! big-endian helpers for `u32str`/`u16str`.

const std = @import("std");
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const testkit = @import("testkit");

pub const params = @import("params.zig");
pub const core = @import("core.zig");
pub const sign = @import("sign.zig");

pub const meta = .{
    // The module catalog's one-line entry; README.md's table is rendered from
    // it by `zig build gen-catalog`.
    .doc = "LMS / HSS (RFC 8554), SHA-256 — **stateful** hash-based signatures (SP 800-208, CNSA 2.0). A leaf signs once; `sign` advances the position first.",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // computation only — no I/O
    // No globals. A bare `SecretKey`/`LmsSecretKey` is caller-synchronised (two
    // racing `sign` calls could reuse a position); `SigningKey` locks.
    .concurrency = .reentrant,
    .model_after = "RFC 8554 (LMS/HSS); RFC 8554 Appendix F as KAT source",
    .deps = .{}, // std only (SHA-256)
};

pub const n = params.n;
pub const id_len = params.id_len;
pub const max_levels = params.max_levels;

pub const OtsParamSet = params.OtsParamSet;
pub const ParamSet = params.ParamSet;
pub const Level = params.Level;

pub const LmsPublicKey = core.LmsPublicKey;
pub const HssPublicKey = core.HssPublicKey;
pub const ParseError = core.ParseError;
pub const lmsVerify = core.lmsVerify;
pub const hssVerify = core.hssVerify;
pub const lmsSignatureLength = core.lmsSignatureLength;
pub const max_lms_signature_length = core.max_lms_signature_length;

pub const Tree = sign.Tree;
pub const LmsSecretKey = sign.LmsSecretKey;
pub const SecretKey = sign.SecretKey;
pub const SigningKey = sign.SigningKey;
pub const Position = sign.Position;
pub const Persist = sign.Persist;
pub const SignError = sign.SignError;
pub const HssError = sign.HssError;
pub const InitError = sign.InitError;

/// Length of an HSS signature for the given level list (§6.2): `4 + sum
/// lmsSignatureLength + 56 * (L - 1)`. Zero when the list has no valid length.
pub fn hssSignatureLength(levels: []const Level) usize {
    if (levels.len < 1 or levels.len > max_levels) return 0;
    var len: usize = 4;
    for (levels, 0..) |lv, i| {
        len += lmsSignatureLength(lv.lms, lv.ots);
        if (i + 1 < levels.len) len += LmsPublicKey.encoded_len;
    }
    return len;
}

// ─── fuzzing ─────────────────────────────────────────────────────────────────

/// Draw order (every draw is a faithful one, no ranged value): public key,
/// message, signature, each as a `smith.slice`.
fn fuzzVerify(_: void, smith: *std.testing.Smith) !void {
    var pk: [96]u8 = undefined;
    var msg: [256]u8 = undefined;
    var sig: [4096]u8 = undefined;
    const pl = smith.slice(&pk);
    const ml = smith.slice(&msg);
    const sl = smith.slice(&sig);
    _ = hssVerify(pk[0..pl], msg[0..ml], sig[0..sl]);
    _ = lmsVerify(pk[0..pl], msg[0..ml], sig[0..sl]);
    // The same bytes as an LMS key behind a fixed prefix, so a mutated
    // signature also reaches the tree walk, not just the typecode guards.
    if (pl >= 8) {
        var t: [96]u8 = pk;
        std.mem.writeInt(u32, t[0..4], ParamSet.sha256_m32_h5.typecode(), .big);
        std.mem.writeInt(u32, t[4..8], OtsParamSet.sha256_n32_w8.typecode(), .big);
        _ = lmsVerify(t[0..pl], msg[0..ml], sig[0..sl]);
    }
}

fn fuzzParse(_: void, smith: *std.testing.Smith) !void {
    var buf: [96]u8 = undefined;
    const len = smith.slice(&buf);
    if (HssPublicKey.parse(buf[0..len])) |pk| {
        _ = pk.toBytes();
    } else |_| {}
    if (LmsPublicKey.parse(buf[0..len])) |pk| {
        _ = pk.toBytes();
    } else |_| {}
}

const kat = @import("kat_vectors.zig");

/// Seeds: the RFC's Test Case 1 HSS triple; the same with one flipped bit in
/// the signature's first `y`, in the message, in the public key; the LMS-only
/// form (final LMS signature of Test Case 1 under the level-1 key).
const Corpus = struct {
    const pk = kat.bytes(kat.tc1_pub);
    const msg = kat.bytes(kat.tc1_msg);
    const sig = kat.bytes(kat.tc1_sig);
    const cap = 6;
    store: [cap * (3 * 4 + pk.len + msg.len + sig.len)]u8 = undefined,
    used: usize = 0,
    entries: [cap][]const u8 = undefined,
    count: usize = 0,

    fn push(self: *Corpus, p: []const u8, m: []const u8, s: []const u8) void {
        const start = self.used;
        var at = start;
        inline for (.{ p, m, s }) |part| at += testkit.fuzz.seedInto(self.store[at..], part).len;
        self.entries[self.count] = self.store[start..at];
        self.used = at;
        self.count += 1;
    }

    fn build(self: *Corpus) []const []const u8 {
        self.push(&pk, &msg, &sig); // verifies
        var t = sig;
        t[60] ^= 1;
        self.push(&pk, &msg, &t);
        var m2 = msg;
        m2[0] ^= 1;
        self.push(&pk, &m2, &sig);
        var p2 = pk;
        p2[40] ^= 1;
        self.push(&p2, &msg, &sig);
        self.push(&pk, &msg, sig[0 .. sig.len - 1]);
        // LMS only: level-1 key = bytes 4+1292 .. of the signature.
        const l1 = sig[4 + 1292 ..][0..LmsPublicKey.encoded_len];
        self.push(l1, &msg, sig[4 + 1292 + LmsPublicKey.encoded_len ..]);
        return self.entries[0..self.count];
    }
};

test "fuzz: verify never panics on arbitrary pk/msg/sig bytes" {
    var corpus: Corpus = .{};
    try std.testing.fuzz({}, fuzzVerify, .{ .corpus = corpus.build() });
}

test "fuzz: public-key parsers never panic on arbitrary bytes" {
    try std.testing.fuzz({}, fuzzParse, .{});
}

test "corpus: the seeds reach the signature walk, and the counts are pinned" {
    var corpus: Corpus = .{};
    var hss_ok: usize = 0;
    var lms_ok: usize = 0;
    for (corpus.build()) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var pk: [96]u8 = undefined;
        var msg: [256]u8 = undefined;
        var sig: [4096]u8 = undefined;
        const pl = smith.slice(&pk);
        const ml = smith.slice(&msg);
        const sl = smith.slice(&sig);
        if (hssVerify(pk[0..pl], msg[0..ml], sig[0..sl])) hss_ok += 1;
        if (lmsVerify(pk[0..pl], msg[0..ml], sig[0..sl])) lms_ok += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), hss_ok);
    try std.testing.expectEqual(@as(usize, 1), lms_ok);
}

test {
    _ = params;
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
    _ = @import("unit_test.zig");
    _ = @import("stackprobe_test.zig");
    _ = @import("stackprobe2_test.zig");
}
