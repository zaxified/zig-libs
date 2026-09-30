// SPDX-License-Identifier: MIT

//! transcript — Merlin v1.0 Fiat-Shamir transcripts (STROBE-128 over
//! Keccak-f[1600]), byte-compatible with the `merlin` crate that dalek's
//! `bulletproofs` binds every range proof to.
//!
//! Until 2026-09-30 this file was a module-defined SHA-512 hash chain, so a
//! proof made here verified only here. Anchoring the module against dalek
//! (task A1 of the maturity survey) needs the same challenge derivation on
//! both sides, and Merlin is that derivation: nothing else stood between the
//! two implementations (the protocol algebra already matched, see
//! `rangeproof.zig`). Merlin is small — the STROBE subset below is the whole
//! of it — and `std` ships the permutation, so the zero-dependency rule
//! holds.
//!
//! ## Construction (Merlin 1.0, `merlin` crate `src/strobe.rs` and
//! `src/transcript.rs`)
//!
//! A STROBE-128 duplex (rate 166 bytes of the 200-byte Keccak-f[1600]
//! state) initialised with the protocol label `"Merlin v1.0"`, then:
//!
//! - `init(label)`: `appendMessage("dom-sep", label)`.
//! - `appendMessage(label, msg)`: `meta-AD(label)`, `meta-AD(LE32(len))`
//!   (continued), `AD(msg)`.
//! - `challengeBytes(label, dest)`: `meta-AD(label)`,
//!   `meta-AD(LE32(dest.len))` (continued), `PRF(dest)`.
//!
//! Only the operations Merlin uses are implemented (meta-AD, AD, PRF); STROBE
//! `KEY`, the transport flag and the transcript RNG are not, because the
//! prover here draws its blinding from the OS (see `rangeproof.zig`'s
//! `randomScalar`), not from `build_rng()`. Blinding randomness is not bound
//! by any challenge, so that choice does not affect compatibility.
//!
//! The dalek-level helpers (`appendPoint`, `appendScalar`, `appendU64`,
//! `validateAndAppendPoint`, `challengeScalar`) are dalek's
//! `TranscriptProtocol` trait (`bulletproofs` 4.0 `src/transcript.rs`):
//! points and scalars go in as their 32-byte canonical encodings, a `u64` as
//! 8 little-endian bytes, and a challenge scalar is 64 PRF bytes reduced
//! mod `L`.
//!
//! Anchored by `interop_test.zig`: Merlin challenges and dalek range proofs
//! produced by the Rust crates (`tools/dalek/`).

const std = @import("std");
const Ristretto255 = std.crypto.ecc.Ristretto255;
const scalar = Ristretto255.scalar;
const KeccakF1600 = std.crypto.core.keccak.KeccakF(1600);

/// STROBE-128 rate in bytes: 200 - 2*16 (security) - 2 (padding).
const strobe_r: u8 = 166;

const flag_i: u8 = 1;
const flag_a: u8 = 1 << 1;
const flag_c: u8 = 1 << 2;
const flag_m: u8 = 1 << 4;
const flag_k: u8 = 1 << 5;

/// The subset of STROBE v1.0.2 (security level 128) Merlin runs on.
const Strobe128 = struct {
    state: [200]u8,
    pos: u8,
    pos_begin: u8,
    cur_flags: u8,

    fn init(protocol_label: []const u8) Strobe128 {
        var st = [_]u8{0} ** 200;
        st[0..6].* = .{ 1, strobe_r + 2, 1, 0, 1, 96 };
        st[6..18].* = "STROBEv1.0.2".*;
        permute(&st);
        var s: Strobe128 = .{ .state = st, .pos = 0, .pos_begin = 0, .cur_flags = 0 };
        s.metaAd(protocol_label, false);
        return s;
    }

    /// Keccak-f[1600] over the state read as 25 little-endian lanes (the
    /// byte order STROBE and the `keccak` crate use), independent of the
    /// host's endianness.
    fn permute(st: *[200]u8) void {
        var k = KeccakF1600.init(st.*);
        k.permute();
        for (k.st, 0..) |lane, i| std.mem.writeInt(u64, st[i * 8 ..][0..8], lane, .little);
    }

    fn runF(self: *Strobe128) void {
        self.state[self.pos] ^= self.pos_begin;
        self.state[self.pos + 1] ^= 0x04;
        self.state[strobe_r + 1] ^= 0x80;
        permute(&self.state);
        self.pos = 0;
        self.pos_begin = 0;
    }

    fn absorb(self: *Strobe128, data: []const u8) void {
        for (data) |byte| {
            self.state[self.pos] ^= byte;
            self.pos += 1;
            if (self.pos == strobe_r) self.runF();
        }
    }

    fn squeeze(self: *Strobe128, out: []u8) void {
        for (out) |*byte| {
            byte.* = self.state[self.pos];
            self.state[self.pos] = 0;
            self.pos += 1;
            if (self.pos == strobe_r) self.runF();
        }
    }

    fn beginOp(self: *Strobe128, flags: u8, more: bool) void {
        if (more) {
            // Merlin only ever continues the op it just began.
            std.debug.assert(self.cur_flags == flags);
            return;
        }
        const old_begin = self.pos_begin;
        self.pos_begin = self.pos + 1;
        self.cur_flags = flags;
        self.absorb(&.{ old_begin, flags });
        const force_f = (flags & (flag_c | flag_k)) != 0;
        if (force_f and self.pos != 0) self.runF();
    }

    fn metaAd(self: *Strobe128, data: []const u8, more: bool) void {
        self.beginOp(flag_m | flag_a, more);
        self.absorb(data);
    }

    fn ad(self: *Strobe128, data: []const u8, more: bool) void {
        self.beginOp(flag_a, more);
        self.absorb(data);
    }

    fn prf(self: *Strobe128, out: []u8, more: bool) void {
        self.beginOp(flag_i | flag_a | flag_c, more);
        self.squeeze(out);
    }
};

pub const Transcript = struct {
    strobe: Strobe128,

    /// Merlin's `Transcript::new(label)`. dalek leaves the label to the
    /// application (its doctests use `b"doctest example"`); prover and
    /// verifier must agree on it. `rangeproof.transcript_domain` is this
    /// module's default.
    pub fn init(label: []const u8) Transcript {
        var t: Transcript = .{ .strobe = Strobe128.init("Merlin v1.0") };
        t.appendMessage("dom-sep", label);
        return t;
    }

    /// Merlin's `append_message`. `msg.len` must fit in a `u32` (Merlin
    /// asserts the same); every caller here appends at most 32 bytes.
    pub fn appendMessage(self: *Transcript, label: []const u8, msg: []const u8) void {
        var len: [4]u8 = undefined;
        std.mem.writeInt(u32, &len, @intCast(msg.len), .little);
        self.strobe.metaAd(label, false);
        self.strobe.metaAd(&len, true);
        self.strobe.ad(msg, false);
    }

    /// Merlin's `append_u64`: 8 little-endian bytes.
    pub fn appendU64(self: *Transcript, label: []const u8, v: u64) void {
        var buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &buf, v, .little);
        self.appendMessage(label, &buf);
    }

    /// Binds a public Ristretto255 point by its canonical encoding.
    pub fn appendPoint(self: *Transcript, label: []const u8, p: Ristretto255) void {
        const bytes = p.toBytes();
        self.appendMessage(label, &bytes);
    }

    /// dalek's `validate_and_append_point`: the verifier's form for every
    /// prover-chosen point. The identity is refused before anything is
    /// absorbed (dalek returns `VerificationError` there, so the transcript
    /// state after a refusal does not matter).
    pub fn validateAndAppendPoint(self: *Transcript, label: []const u8, p: Ristretto255) error{IdentityElement}!void {
        const bytes = p.toBytes();
        if (std.mem.allEqual(u8, &bytes, 0)) return error.IdentityElement;
        self.appendMessage(label, &bytes);
    }

    /// Binds a public scalar (32-byte little-endian canonical encoding).
    /// NEVER call this on a SECRET scalar — prover and verifier compute the
    /// transcript identically, so everything absorbed is public.
    pub fn appendScalar(self: *Transcript, label: []const u8, s: [32]u8) void {
        self.appendMessage(label, &s);
    }

    /// Merlin's `challenge_bytes`.
    pub fn challengeBytes(self: *Transcript, label: []const u8, out: []u8) void {
        var len: [4]u8 = undefined;
        std.mem.writeInt(u32, &len, @intCast(out.len), .little);
        self.strobe.metaAd(label, false);
        self.strobe.metaAd(&len, true);
        self.strobe.prf(out, false);
    }

    /// dalek's `challenge_scalar`: 64 challenge bytes, wide-reduced mod `L`
    /// (`Scalar::from_bytes_mod_order_wide`).
    pub fn challengeScalar(self: *Transcript, label: []const u8) [32]u8 {
        var wide: [64]u8 = undefined;
        self.challengeBytes(label, &wide);
        return scalar.reduce64(wide);
    }
};

// ── tests ─────────────────────────────────────────────────────────────────
// Byte-exact agreement with the `merlin` crate is asserted in
// `interop_test.zig`; these are the local properties.

test "init is deterministic and label-separated" {
    var t1 = Transcript.init("a");
    var t2 = Transcript.init("a");
    var t3 = Transcript.init("b");
    const c1 = t1.challengeScalar("c");
    const c2 = t2.challengeScalar("c");
    const c3 = t3.challengeScalar("c");
    try std.testing.expectEqualSlices(u8, &c1, &c2);
    try std.testing.expect(!std.mem.eql(u8, &c1, &c3));
}

test "appendPoint is value- and order-sensitive" {
    const g = Ristretto255.basePoint;
    const h = g.dbl();

    var t1 = Transcript.init("x");
    t1.appendPoint("p", g);
    var t2 = Transcript.init("x");
    t2.appendPoint("p", h);
    try std.testing.expect(!std.mem.eql(u8, &t1.strobe.state, &t2.strobe.state));

    var t4 = Transcript.init("x");
    t4.appendPoint("p", g);
    t4.appendPoint("q", h);
    var t5 = Transcript.init("x");
    t5.appendPoint("q", h);
    t5.appendPoint("p", g);
    try std.testing.expect(!std.mem.eql(u8, &t4.strobe.state, &t5.strobe.state));
}

test "the label/message boundary is framed: moving a byte across it changes the challenge" {
    // Merlin frames each message by a separate meta-AD op for the label and
    // a LE32 length; "ab"+"" and "a"+"b" absorb the same bytes in sequence
    // and differ only in that framing.
    var t1 = Transcript.init("x");
    var t2 = Transcript.init("x");
    t1.appendMessage("ab", "");
    t2.appendMessage("a", "b");
    const c1 = t1.challengeScalar("c");
    const c2 = t2.challengeScalar("c");
    try std.testing.expect(!std.mem.eql(u8, &c1, &c2));
}

test "validateAndAppendPoint refuses the identity and absorbs nothing" {
    var t = Transcript.init("x");
    const before = t.strobe;
    const identity: Ristretto255 = .{ .p = std.crypto.ecc.Edwards25519.identityElement };
    try std.testing.expectError(error.IdentityElement, t.validateAndAppendPoint("A", identity));
    try std.testing.expectEqualDeep(before, t.strobe);

    var t1 = Transcript.init("x");
    var t2 = Transcript.init("x");
    try t1.validateAndAppendPoint("A", Ristretto255.basePoint);
    t2.appendPoint("A", Ristretto255.basePoint);
    try std.testing.expectEqualDeep(t1.strobe, t2.strobe);
}

test "challengeScalar is canonical and a second draw under the same label differs" {
    var t = Transcript.init("ratchet");
    const c1 = t.challengeScalar("y");
    const c2 = t.challengeScalar("y");
    try scalar.rejectNonCanonical(c1);
    try std.testing.expect(!std.mem.eql(u8, &c1, &c2));
}

test "a long message crosses the 166-byte rate boundary deterministically" {
    const msg = [_]u8{99} ** 1024;
    var t1 = Transcript.init("x");
    var t2 = Transcript.init("x");
    t1.appendMessage("m", &msg);
    t2.appendMessage("m", &msg);
    var o1: [300]u8 = undefined;
    var o2: [300]u8 = undefined;
    t1.challengeBytes("c", &o1);
    t2.challengeBytes("c", &o2);
    try std.testing.expectEqualSlices(u8, &o1, &o2);
}

test "challengeScalar: 300 draws carry real entropy (audit B3: Fiat-Shamir truncation is unguarded)" {
    // Audit finding B3: determinism, ratcheting and label separation all
    // survive a challenge truncated to a handful of values; these two checks
    // do not.
    var t = Transcript.init("entropy-probe");
    var challenges: [300][32]u8 = undefined;
    for (&challenges, 0..) |*c, i| {
        var label_buf: [8]u8 = undefined;
        const label = std.fmt.bufPrint(&label_buf, "c{d}", .{i}) catch unreachable;
        c.* = t.challengeScalar(label);
    }

    // (1) No two of the 300 draws collide.
    for (challenges[0 .. challenges.len - 1], 0..) |ci, i| {
        for (challenges[i + 1 ..]) |cj| {
            try std.testing.expect(!std.mem.eql(u8, &ci, &cj));
        }
    }

    // (2) The most significant byte takes more than a handful of values.
    var seen = std.AutoHashMap(u8, void).init(std.testing.allocator);
    defer seen.deinit();
    for (challenges) |c| try seen.put(c[31], {});
    try std.testing.expect(seen.count() > 10);
}
