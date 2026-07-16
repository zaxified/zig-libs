// SPDX-License-Identifier: MIT

//! transcript — a self-contained SHA-512-based Fiat-Shamir transcript for
//! Bulletproofs.
//!
//! **REAL — not a Fable stub.**
//!
//! dalek's `bulletproofs` crate uses Merlin (a STROBE-based transcript
//! protocol — itself a separate cryptographic primitive/spec, not merely a
//! hash) to bind a protocol's public values and prover messages into each
//! challenge. Depending on Merlin here would pull a second, unrelated
//! primitive (STROBE's duplex construction) into this repo purely to
//! reproduce ONE module's proof format, and this repo has no existing
//! STROBE/Merlin implementation to build on — CONVENTIONS.md's "prefer
//! std; build a dep only where std has a real gap" directive, plus the
//! zero-dep rule, both point away from that. Instead: a self-contained,
//! domain-separated, incremental-hash transcript with SHA-512 as its only
//! primitive (already used throughout this module for `generators.zig`'s
//! `hashToPoint`).
//!
//! **Consequence — read before assuming byte-compatibility with dalek or
//! any other Bulletproofs implementation.** Every implementation's
//! Fiat-Shamir transcript is DIFFERENT unless a spec pins one down, and
//! the Bulletproofs paper does not (Fiat-Shamir instantiation is always
//! implementation-defined — the same posture this repo's `threshold_ecdsa`
//! module documents for its own Πprm/Πmod transcripts; see
//! `aux_proofs.zig`'s header comment). A proof produced by THIS module's
//! `rangeproof.prove`/`ipa.proveIpa` only verifies against THIS module's
//! `rangeproof.verify`/`ipa.verifyIpa` — internally self-consistent
//! (soundness holds end-to-end) but NOT a wire-compatible Bulletproofs
//! proof against dalek, libsecp256k1-zkp, or any other implementation.
//! The KAT harness (`kat_test.zig`) is therefore PROPERTY-and-SOUNDNESS
//! based (completeness + tamper-rejection + cross-commitment-rejection),
//! never byte-exact against a published third-party vector — see
//! `SPEC.md`.
//!
//! ## Construction
//!
//! A hash CHAIN, not a sponge/duplex: `state` is a running 64-byte SHA-512
//! digest. Each `append*` call re-hashes `state || tag || len(label) ||
//! label || len(data) || data` into a fresh `state`, so every subsequent
//! challenge depends on everything appended so far, in order (the
//! Fiat-Shamir binding property). `challengeScalar` derives a challenge
//! from `state || "challenge" || len(label) || label` and then RATCHETS
//! `state` forward by absorbing the produced challenge bytes back in, so
//! requesting a second challenge under the same label — or replaying part
//! of a transcript — can never reproduce an earlier challenge (the same
//! non-replayability property a STROBE-based transcript's own
//! state-advance step provides, achieved here by an explicit extra absorb
//! instead of a duplex permutation).
//!
//! Length-prefixing every appended field closes the classic
//! transcript-binding gap where `H(a || b)` collides with `H(a' || b')`
//! whenever `a||b == a'||b'` but `a != a'` — the same discipline
//! `zkproofs.zig`/`aux_proofs.zig`'s `appendLenPrefixed` already applies
//! elsewhere in this repo.

const std = @import("std");
const Sha512 = std.crypto.hash.sha2.Sha512;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = Ristretto255.scalar;

pub const Transcript = struct {
    state: [64]u8,

    /// Starts a fresh transcript, domain-separated by `label` (e.g.
    /// `"bulletproofs/range-proof/v1"`, `"bulletproofs/ipa/v1"` — see
    /// `rangeproof.zig`/`ipa.zig`'s domain constants). Two transcripts
    /// started with DIFFERENT labels never produce the same challenge for
    /// identical subsequent appends (the label is absorbed before
    /// anything else).
    pub fn init(label: []const u8) Transcript {
        var h = Sha512.init(.{});
        h.update("zig-libs/bulletproofs/transcript/v1");
        h.update(label);
        var state: [64]u8 = undefined;
        h.final(&state);
        return .{ .state = state };
    }

    fn absorb(self: *Transcript, tag: u8, label: []const u8, data: []const u8) void {
        var h = Sha512.init(.{});
        h.update(&self.state);
        h.update(&[_]u8{tag});
        var label_len: [8]u8 = undefined;
        std.mem.writeInt(u64, &label_len, label.len, .little);
        h.update(&label_len);
        h.update(label);
        var data_len: [8]u8 = undefined;
        std.mem.writeInt(u64, &data_len, data.len, .little);
        h.update(&data_len);
        h.update(data);
        h.final(&self.state);
    }

    /// Binds a public Ristretto255 point (32-byte canonical encoding) —
    /// e.g. range-proof commitments `V`/`A`/`S`/`T1`/`T2`, or an IPA
    /// round's `L`/`R`.
    pub fn appendPoint(self: *Transcript, label: []const u8, p: Ristretto255) void {
        const bytes = p.toBytes();
        self.absorb('P', label, &bytes);
    }

    /// Binds a public scalar (32-byte little-endian canonical encoding).
    /// NEVER call this on a SECRET scalar — the transcript is computed
    /// identically by prover and verifier, so anything absorbed into it
    /// must already be something the verifier independently has (a
    /// published proof field or public input), never the witness.
    pub fn appendScalar(self: *Transcript, label: []const u8, s: [32]u8) void {
        self.absorb('S', label, &s);
    }

    /// Binds a public `u64` (e.g. the bit-width `n`), little-endian.
    pub fn appendU64(self: *Transcript, label: []const u8, v: u64) void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, v, .little);
        self.absorb('U', label, &buf);
    }

    /// Squeezes a Fiat-Shamir challenge scalar, then ratchets `state`
    /// forward (see the module doc comment). Reducing the 64-byte digest
    /// via `scalar.reduce64` is the same wide reduction `voprf`'s
    /// `HashToScalar` and Ed25519's own `Scalar.fromBytes64` use — a
    /// uniform-over-`[0, L)` reduction of a uniformly random 64-byte
    /// input (RFC 9380 Appendix B / RFC 8032's scalar-reduction
    /// convention).
    pub fn challengeScalar(self: *Transcript, label: []const u8) [32]u8 {
        var h = Sha512.init(.{});
        h.update(&self.state);
        h.update("challenge");
        var label_len: [8]u8 = undefined;
        std.mem.writeInt(u64, &label_len, label.len, .little);
        h.update(&label_len);
        h.update(label);
        var wide: [64]u8 = undefined;
        h.final(&wide);
        // Ratchet: fold the produced challenge back into state so a
        // second challengeScalar call (same or different label) can
        // never reproduce this value.
        self.absorb('C', label, &wide);
        return scalar.reduce64(wide);
    }
};

// ── tests ─────────────────────────────────────────────────────────────────

test "init is deterministic and label-separated" {
    const t1 = Transcript.init("a");
    const t2 = Transcript.init("a");
    try std.testing.expectEqualSlices(u8, &t1.state, &t2.state);

    const t3 = Transcript.init("b");
    try std.testing.expect(!std.mem.eql(u8, &t1.state, &t3.state));
}

test "appendPoint changes state and is order-sensitive" {
    var t1 = Transcript.init("x");
    var t2 = Transcript.init("x");
    const g = Ristretto255.basePoint;
    const h = g.dbl();

    const before = t1.state;
    t1.appendPoint("p", g);
    try std.testing.expect(!std.mem.eql(u8, &before, &t1.state));

    t2.appendPoint("p", g);
    try std.testing.expectEqualSlices(u8, &t1.state, &t2.state);

    var t3 = Transcript.init("x");
    t3.appendPoint("p", h);
    try std.testing.expect(!std.mem.eql(u8, &t1.state, &t3.state));

    // Order matters: appending g then h differs from h then g.
    var t4 = Transcript.init("x");
    t4.appendPoint("p", g);
    t4.appendPoint("q", h);
    var t5 = Transcript.init("x");
    t5.appendPoint("q", h);
    t5.appendPoint("p", g);
    try std.testing.expect(!std.mem.eql(u8, &t4.state, &t5.state));
}

test "appendScalar/appendU64 are label- and value-sensitive" {
    var t1 = Transcript.init("x");
    var t2 = Transcript.init("x");
    t1.appendScalar("s", [_]u8{1} ++ [_]u8{0} ** 31);
    t2.appendScalar("s", [_]u8{2} ++ [_]u8{0} ** 31);
    try std.testing.expect(!std.mem.eql(u8, &t1.state, &t2.state));

    var t3 = Transcript.init("x");
    var t4 = Transcript.init("x");
    t3.appendU64("n", 64);
    t4.appendU64("n", 32);
    try std.testing.expect(!std.mem.eql(u8, &t3.state, &t4.state));

    // Length-prefixing prevents a "label||data" concatenation collision:
    // appendScalar("ab", zero) must differ from appendScalar("a", <the
    // byte 'b' followed by 31 zero bytes>) even though the naive
    // concatenations would otherwise coincide.
    var t5 = Transcript.init("x");
    var t6 = Transcript.init("x");
    t5.appendScalar("ab", [_]u8{0} ** 32);
    t6.appendScalar("a", [_]u8{'b'} ++ [_]u8{0} ** 31);
    try std.testing.expect(!std.mem.eql(u8, &t5.state, &t6.state));
}

test "challengeScalar is deterministic given identical prior transcript, and canonical" {
    var t1 = Transcript.init("chal");
    var t2 = Transcript.init("chal");
    t1.appendU64("n", 8);
    t2.appendU64("n", 8);

    const c1 = t1.challengeScalar("y");
    const c2 = t2.challengeScalar("y");
    try std.testing.expectEqualSlices(u8, &c1, &c2);
    try scalar.rejectNonCanonical(c1);
}

test "challengeScalar ratchets state: repeated calls under the same label differ" {
    var t = Transcript.init("ratchet");
    const c1 = t.challengeScalar("y");
    const c2 = t.challengeScalar("y");
    try std.testing.expect(!std.mem.eql(u8, &c1, &c2));
}

test "challengeScalar is label-sensitive" {
    var t1 = Transcript.init("z");
    var t2 = Transcript.init("z");
    const y = t1.challengeScalar("y");
    const z = t2.challengeScalar("z");
    try std.testing.expect(!std.mem.eql(u8, &y, &z));
}
