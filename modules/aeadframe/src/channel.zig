// SPDX-License-Identifier: MIT

//! The `Channel(Aead)` seal/open engine for `aeadframe`.
//!
//! `Channel` is comptime-parameterised over any AEAD that presents the
//! std/`chachapoly` shape — 32-byte key, 12-byte nonce, 16-byte tag, and the
//! `encrypt(c, tag, m, ad, npub, k)` / `decrypt(m, c, tag, ad, npub, k)`
//! signature. Ready instantiations `ChaChaChannel` (ChaCha20-Poly1305 via the
//! `chachapoly` sibling) and `AesGcmChannel` (AES-256-GCM via std) are exposed
//! at the bottom.
//!
//! A `Sealer` owns a key + epoch + monotonic sequence counter and turns a
//! plaintext into a self-describing record; an `Opener` owns a key + epoch + a
//! sliding-window replay filter and turns a record back into plaintext,
//! rejecting replays, wrong epochs, tampering, and truncation.

const std = @import("std");
const chachapoly = @import("chachapoly");
const record = @import("record.zig");
const replay = @import("replay.zig");

pub const key_length = 32;

/// Upper bound on the caller-supplied `aad` accepted by `seal`/`open`. Both
/// sides bind the wire header (which carries `version`) into the AAD by
/// prepending it ahead of the caller's own `aad` in a fixed-size stack
/// scratch buffer — see `effectiveAad` below — so the total must stay
/// bounded to keep both functions allocation-free. Generous for the
/// tenant/I-SID context strings this module's callers actually pass.
pub const max_caller_aad = 1024;

/// Errors from `Sealer.seal`.
pub const SealError = error{
    /// The per-epoch sequence space is exhausted. Refused rather than wrapping
    /// (a wrapped `seq` would reuse a nonce — catastrophic). Bump the epoch or
    /// rekey to get a fresh sequence space.
    SequenceExhausted,
    /// The output buffer is smaller than `sealedLen(plaintext.len)`.
    BufferTooSmall,
    /// `aad.len > max_caller_aad`.
    AadTooLarge,
};

/// Concatenate `header_bytes` (the 13-byte wire header, which carries
/// `version`) ahead of the caller's `aad` into `scratch`, and return the
/// combined slice to feed the AEAD as its authenticated data.
///
/// Binding the header this way means a tampered `version` byte breaks AEAD
/// authentication, not merely the `parse`-time equality check — today the
/// only valid version is 1 and `parse` already refuses anything else, so
/// this closes the gap a *future* multi-version wire would otherwise reopen
/// (wave-2 audit finding `aeadframe` F4): without this binding, the version
/// byte would sit outside both the nonce and the AAD, so a downgrade/
/// confusion edit to it would go unauthenticated the moment a second
/// version exists.
fn effectiveAad(scratch: *[record.header_len + max_caller_aad]u8, header_bytes: *const [record.header_len]u8, aad: []const u8) error{AadTooLarge}![]const u8 {
    if (aad.len > max_caller_aad) return error.AadTooLarge;
    @memcpy(scratch[0..record.header_len], header_bytes);
    @memcpy(scratch[record.header_len..][0..aad.len], aad);
    return scratch[0 .. record.header_len + aad.len];
}

/// Error from `Sealer.bumpEpoch` (same-key epoch bump).
pub const EpochError = error{
    /// The 32-bit epoch space is exhausted; only a genuinely new key can
    /// continue safely.
    EpochExhausted,
};

/// Error from `Sealer.rekey`.
pub const RekeyError = error{
    /// The requested `(key, epoch)` pair is one this sealer is already using:
    /// `new_key` equals the current key and `new_epoch` does not advance past
    /// the current epoch. Accepting it would restart `seq` at 0 inside a nonce
    /// subspace that is already spent — keystream reuse (plaintext recovery by
    /// XOR of two records) plus a repeated Poly1305/GHASH one-time key, which
    /// also costs authentication. Supply a genuinely fresh key, or an epoch
    /// strictly greater than the current one.
    NonceSpaceReuse,
};

/// Errors from `Opener.open`.
pub const OpenError = error{
    /// The record is shorter than the minimum (`record.overhead`).
    Truncated,
    /// The record's version byte is not the supported version.
    UnsupportedVersion,
    /// The record's epoch differs from the one this opener expects. Advance
    /// the opener with `rekey`/`bumpEpoch` on a deliberate epoch transition.
    EpochMismatch,
    /// The record's sequence number is a replay (duplicate or too old).
    Replayed,
    /// The output buffer is smaller than the record's plaintext.
    BufferTooSmall,
    /// `aad.len > max_caller_aad`.
    AadTooLarge,
} || std.crypto.errors.AuthenticationError;

/// Build a record/frame channel over a concrete AEAD.
pub fn Channel(comptime Aead: type) type {
    comptime {
        std.debug.assert(Aead.key_length == 32);
        std.debug.assert(Aead.nonce_length == 12);
        std.debug.assert(Aead.tag_length == 16);
    }
    return struct {
        /// Sender half: seals plaintext into records under a fixed key, with a
        /// monotonic 64-bit sequence counter that guarantees nonce uniqueness.
        ///
        /// `single_owner`: one loop/thread owns a `Sealer`; it holds no lock.
        pub const Sealer = struct {
            key: [32]u8,
            epoch: u32,
            /// Next sequence number to use. Public for inspection/tests; the
            /// safe way to move it is `seal` (advance), `bumpEpoch`, or `rekey`.
            seq: u64 = 0,

            pub fn init(key: [32]u8, epoch: u32) Sealer {
                return .{ .key = key, .epoch = epoch };
            }

            /// Exact record size for a plaintext of `pt_len` bytes.
            pub fn sealedLen(pt_len: usize) usize {
                return record.overhead + pt_len;
            }

            /// Seal `plaintext` (bound to `aad`) into `out`, returning the
            /// record length written (`sealedLen(plaintext.len)`). `aad` is the
            /// caller's context binding (tenant / I-SID / channel id): a record
            /// opens only against the identical `aad`. Zero allocation.
            pub fn seal(self: *Sealer, out: []u8, plaintext: []const u8, aad: []const u8) SealError!usize {
                const need = record.overhead + plaintext.len;
                if (out.len < need) return error.BufferTooSmall;
                if (aad.len > max_caller_aad) return error.AadTooLarge;
                // Refuse rather than wrap: a wrapped seq reuses a nonce.
                if (self.seq == std.math.maxInt(u64)) return error.SequenceExhausted;

                const seq = self.seq;
                (record.Header{ .epoch = self.epoch, .seq = seq }).encode(out[0..record.header_len]);
                const nonce = record.deriveNonce(self.epoch, seq);
                var aad_scratch: [record.header_len + max_caller_aad]u8 = undefined;
                const eff_aad = try effectiveAad(&aad_scratch, out[0..record.header_len], aad);
                const ct = out[record.header_len..][0..plaintext.len];
                var tag: [record.tag_len]u8 = undefined;
                Aead.encrypt(ct, &tag, plaintext, eff_aad, nonce, self.key);
                @memcpy(out[record.header_len + plaintext.len ..][0..record.tag_len], &tag);

                self.seq += 1;
                return need;
            }

            /// Same-key rekey: advance to the next epoch and reset the sequence
            /// counter. Nonce-safe because the epoch is embedded in the nonce
            /// and strictly increases, so `(epoch, seq)` never repeats under
            /// this key (SPEC.md). Provides NO forward secrecy — for that, use
            /// `rekey` with a fresh key.
            pub fn bumpEpoch(self: *Sealer) EpochError!void {
                if (self.epoch == std.math.maxInt(u32)) return error.EpochExhausted;
                self.epoch += 1;
                self.seq = 0;
            }

            /// Rekey with a caller-supplied fresh key and epoch, resetting the
            /// sequence counter. The fresh key gives an independent keystream
            /// (and forward secrecy if the old key is destroyed).
            ///
            /// Refuses (`error.NonceSpaceReuse`, state unchanged) the one case
            /// it can detect locally: `new_key` equal to the current key with
            /// an epoch that does not strictly advance. That combination would
            /// restart `seq` at 0 in a spent nonce subspace — the same hazard
            /// `bumpEpoch`'s monotonicity rules out. A *different* key needs no
            /// epoch ordering: an independent keystream cannot collide with the
            /// old one whatever the epoch.
            ///
            /// The residual obligation the sealer cannot discharge is stated in
            /// SPEC.md §8: it remembers only its current key, so re-installing a
            /// key it used *earlier* (A → B → A) at a non-advancing epoch is
            /// undetectable here, exactly as reconstructing a `Sealer` on a spent
            /// `(key, epoch)` is.
            pub fn rekey(self: *Sealer, new_key: [32]u8, new_epoch: u32) RekeyError!void {
                // Constant-time in the key bytes: both operands are the caller's
                // own secrets, and the branch outcome (not the content) is what
                // the caller is told.
                const same_key = std.crypto.timing_safe.eql([32]u8, new_key, self.key);
                if (same_key and new_epoch <= self.epoch) return error.NonceSpaceReuse;
                self.key = new_key;
                self.epoch = new_epoch;
                self.seq = 0;
            }

            /// Destroy the AEAD key held by this sealer (CONVENTIONS §2.1 Z1 —
            /// the key is a secret in storage this struct owns). Call it once
            /// the channel is finished; the sealer is unusable afterwards, since
            /// an all-zero key is not a key. `epoch`/`seq` are left alone: they
            /// are not secret, and leaving them lets a caller log how much of
            /// the nonce space was spent.
            pub fn wipe(self: *Sealer) void {
                std.crypto.secureZero(u8, &self.key);
            }
        };

        /// Receiver half: opens records under a fixed key + epoch, enforcing an
        /// anti-replay window. `single_owner`, lock-free.
        pub const Opener = struct {
            key: [32]u8,
            epoch: u32,
            window: replay.ReplayWindow = .{},

            pub fn init(key: [32]u8, epoch: u32) Opener {
                return .{ .key = key, .epoch = epoch };
            }

            /// As `init`, with an explicit replay-window width (1..64).
            pub fn initWindow(key: [32]u8, epoch: u32, window_size: u7) Opener {
                return .{ .key = key, .epoch = epoch, .window = .{ .size = window_size } };
            }

            /// Open `rec` (bound to `aad`) into `out`, returning the plaintext
            /// length. Order: parse+bounds-check → epoch check → replay
            /// pre-check → AEAD verify+decrypt → commit the sequence number.
            /// The window is committed ONLY after authentication, so a forged
            /// record can never burn a legitimate replay slot. On any failure
            /// `out[0..ct_len]` is zeroed — never garbage plaintext.
            pub fn open(self: *Opener, out: []u8, rec: []const u8, aad: []const u8) OpenError!usize {
                const p = try record.parse(rec);
                if (p.header.epoch != self.epoch) return error.EpochMismatch;
                if (out.len < p.ct_len) return error.BufferTooSmall;
                if (aad.len > max_caller_aad) return error.AadTooLarge;
                if (!self.window.accepts(p.header.seq)) return error.Replayed;

                const nonce = record.deriveNonce(p.header.epoch, p.header.seq);
                const ct = rec[p.ct_off..][0..p.ct_len];
                var tag: [record.tag_len]u8 = undefined;
                @memcpy(&tag, rec[p.tag_off..][0..record.tag_len]);
                var aad_scratch: [record.header_len + max_caller_aad]u8 = undefined;
                const eff_aad = try effectiveAad(&aad_scratch, rec[0..record.header_len], aad);
                const pt = out[0..p.ct_len];
                Aead.decrypt(pt, ct, tag, eff_aad, nonce, self.key) catch |e| {
                    // Uniform across AEADs: std's AES-GCM leaves `m` undefined
                    // on failure, chachapoly zeroes it. Make the "no garbage
                    // plaintext" contract hold for both.
                    std.crypto.secureZero(u8, pt);
                    return e;
                };
                self.window.commit(p.header.seq);
                return p.ct_len;
            }

            /// Same-key epoch advance: expect the next epoch and reset the
            /// replay window (fresh nonce space ⇒ old sequence numbers void).
            pub fn bumpEpoch(self: *Opener) EpochError!void {
                if (self.epoch == std.math.maxInt(u32)) return error.EpochExhausted;
                self.epoch += 1;
                self.window.reset();
            }

            /// Rekey to a caller-supplied fresh key + epoch and reset the
            /// replay window. Infallible, unlike `Sealer.rekey`: the receiver
            /// emits no nonce, so there is no nonce space to spend. It only
            /// changes which records it will accept.
            pub fn rekey(self: *Opener, new_key: [32]u8, new_epoch: u32) void {
                self.key = new_key;
                self.epoch = new_epoch;
                self.window.reset();
            }

            /// Destroy the AEAD key held by this opener — see `Sealer.wipe`.
            /// The replay window is left intact: it is not secret, and it is the
            /// record of what this peer already accepted.
            pub fn wipe(self: *Opener) void {
                std.crypto.secureZero(u8, &self.key);
            }
        };
    };
}

// ── ready instantiations ──────────────────────────────────────────────────────

/// ChaCha20-Poly1305 record channel (via the `chachapoly` sibling).
pub const ChaChaChannel = Channel(chachapoly.ChaCha20Poly1305);
/// AES-256-GCM record channel (via std) — the FIPS/compliance instantiation.
pub const AesGcmChannel = Channel(std.crypto.aead.aes_gcm.Aes256Gcm);

pub const ChaChaSealer = ChaChaChannel.Sealer;
pub const ChaChaOpener = ChaChaChannel.Opener;
pub const AesGcmSealer = AesGcmChannel.Sealer;
pub const AesGcmOpener = AesGcmChannel.Opener;

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

// Run the whole behavioural suite against BOTH instantiations.
const channels = .{ ChaChaChannel, AesGcmChannel };

fn testKey(seed: u8) [32]u8 {
    var k: [32]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = seed +% @as(u8, @intCast(i));
    return k;
}

test "round-trip recovers plaintext (both AEADs)" {
    inline for (channels) |Ch| {
        var s = Ch.Sealer.init(testKey(1), 0);
        var o = Ch.Opener.init(testKey(1), 0);
        const msg = "the quick brown fox";
        var rec: [Ch.Sealer.sealedLen(msg.len)]u8 = undefined;
        const n = try s.seal(&rec, msg, "tenant-A");
        var pt: [msg.len]u8 = undefined;
        const m = try o.open(&pt, rec[0..n], "tenant-A");
        try testing.expectEqualSlices(u8, msg, pt[0..m]);
    }
}

test "empty plaintext round-trips (both AEADs)" {
    inline for (channels) |Ch| {
        var s = Ch.Sealer.init(testKey(9), 3);
        var o = Ch.Opener.init(testKey(9), 3);
        var rec: [record.overhead]u8 = undefined;
        const n = try s.seal(&rec, "", "ctx");
        var pt: [0]u8 = undefined;
        const m = try o.open(&pt, rec[0..n], "ctx");
        try testing.expectEqual(@as(usize, 0), m);
    }
}

test "AAD mismatch (cross-tenant) fails to open (both AEADs)" {
    inline for (channels) |Ch| {
        var s = Ch.Sealer.init(testKey(2), 0);
        var o = Ch.Opener.init(testKey(2), 0);
        const msg = "secret";
        var rec: [Ch.Sealer.sealedLen(msg.len)]u8 = undefined;
        const n = try s.seal(&rec, msg, "tenant-A");
        var pt: [msg.len]u8 = undefined;
        try testing.expectError(error.AuthenticationFailed, o.open(&pt, rec[0..n], "tenant-B"));
        // and the plaintext buffer was zeroed, not left as garbage
        for (pt) |b| try testing.expectEqual(@as(u8, 0), b);
    }
}

test "tampering ciphertext / tag / header is rejected, buffer zeroed (both AEADs)" {
    inline for (channels) |Ch| {
        const msg = "authenticate me";
        var rec: [Ch.Sealer.sealedLen(msg.len)]u8 = undefined;
        var s = Ch.Sealer.init(testKey(3), 0);
        const n = try s.seal(&rec, msg, "ad");

        // Flip a ciphertext byte.
        {
            var bad = rec;
            bad[record.header_len] +%= 1;
            var o = Ch.Opener.init(testKey(3), 0);
            var pt: [msg.len]u8 = undefined;
            try testing.expectError(error.AuthenticationFailed, o.open(&pt, bad[0..n], "ad"));
            for (pt) |b| try testing.expectEqual(@as(u8, 0), b);
        }
        // Flip a tag byte.
        {
            var bad = rec;
            bad[n - 1] +%= 1;
            var o = Ch.Opener.init(testKey(3), 0);
            var pt: [msg.len]u8 = undefined;
            try testing.expectError(error.AuthenticationFailed, o.open(&pt, bad[0..n], "ad"));
        }
        // Flip a seq byte in the header: changes the derived nonce -> auth fail.
        {
            var bad = rec;
            bad[record.header_len - 1] +%= 1; // last seq byte
            var o = Ch.Opener.init(testKey(3), 0);
            var pt: [msg.len]u8 = undefined;
            try testing.expectError(error.AuthenticationFailed, o.open(&pt, bad[0..n], "ad"));
        }
        // Flip the version byte: rejected before any crypto.
        {
            var bad = rec;
            bad[0] +%= 1;
            var o = Ch.Opener.init(testKey(3), 0);
            var pt: [msg.len]u8 = undefined;
            try testing.expectError(error.UnsupportedVersion, o.open(&pt, bad[0..n], "ad"));
        }
    }
}

test "seq is strictly monotonic and distinct nonces per sealer" {
    inline for (channels) |Ch| {
        var s = Ch.Sealer.init(testKey(4), 7);
        var seen = std.AutoHashMap([12]u8, void).init(testing.allocator);
        defer seen.deinit();
        var buf: [record.overhead + 4]u8 = undefined;
        for (0..256) |i| {
            const before = s.seq;
            try testing.expectEqual(@as(u64, i), before); // strictly monotonic from 0
            _ = try s.seal(&buf, "abcd", "x");
            try testing.expectEqual(before + 1, s.seq); // advanced by exactly 1
            const n = record.deriveNonce(7, before);
            try testing.expect(seen.get(n) == null); // never a repeated nonce
            try seen.put(n, {});
        }
    }
}

test "seal refuses at the sequence ceiling instead of wrapping" {
    inline for (channels) |Ch| {
        var s = Ch.Sealer.init(testKey(5), 0);
        s.seq = std.math.maxInt(u64);
        var buf: [record.overhead + 3]u8 = undefined;
        try testing.expectError(error.SequenceExhausted, s.seal(&buf, "abc", ""));
        try testing.expectEqual(@as(u64, std.math.maxInt(u64)), s.seq); // unchanged
    }
}

test "seal rejects an undersized output buffer" {
    var s = ChaChaChannel.Sealer.init(testKey(6), 0);
    var small: [record.overhead + 2]u8 = undefined; // room for 2 pt bytes
    try testing.expectError(error.BufferTooSmall, s.seal(&small, "three", ""));
}

test "open rejects an undersized output buffer (mirrors seal's check)" {
    inline for (channels) |Ch| {
        var s = Ch.Sealer.init(testKey(11), 0);
        const msg = "twelve-bytes"; // 12 bytes of plaintext
        var rec: [Ch.Sealer.sealedLen(msg.len)]u8 = undefined;
        const n = try s.seal(&rec, msg, "ad");

        var o = Ch.Opener.init(testKey(11), 0);
        var too_small: [msg.len - 1]u8 = undefined;
        try testing.expectError(error.BufferTooSmall, o.open(&too_small, rec[0..n], "ad"));

        // And the exact-size buffer (the boundary) still works.
        var out: [msg.len]u8 = undefined;
        const m = try o.open(&out, rec[0..n], "ad");
        try testing.expectEqualSlices(u8, msg, out[0..m]);
    }
}

test "bumpEpoch refuses to wrap at the u32 ceiling (both Sealer and Opener)" {
    inline for (channels) |Ch| {
        var s = Ch.Sealer.init(testKey(12), std.math.maxInt(u32));
        try testing.expectError(error.EpochExhausted, s.bumpEpoch());
        try testing.expectEqual(std.math.maxInt(u32), s.epoch); // unchanged

        var o = Ch.Opener.init(testKey(12), std.math.maxInt(u32));
        try testing.expectError(error.EpochExhausted, o.bumpEpoch());
        try testing.expectEqual(std.math.maxInt(u32), o.epoch); // unchanged
    }
}

test "initWindow honors a narrower window than the 64-byte default" {
    // Zero call sites for initWindow anywhere else in this suite: without
    // this test a regression that ignored `window_size` (defaulting to 64
    // regardless) would go unnoticed.
    var s = ChaChaChannel.Sealer.init(testKey(13), 0);
    var o = ChaChaChannel.Opener.initWindow(testKey(13), 0, 4);
    try testing.expectEqual(@as(u7, 4), o.window.size);

    var recs: [6][record.overhead + 1]u8 = undefined;
    for (0..6) |i| _ = try s.seal(&recs[i], "x", "c");
    var pt: [1]u8 = undefined;

    // Advance the high-water mark to seq 5 first...
    _ = try o.open(&pt, &recs[5], "c");
    // ...then seq 0 (diff 5) is now outside the narrow 4-wide window, even
    // though it would still be inside the library's 64-byte default.
    try testing.expectError(error.Replayed, o.open(&pt, &recs[0], "c"));
    // ...while seq 1 (diff 4, exactly at the edge) is still in-window.
    _ = try o.open(&pt, &recs[1], "c");
}

test "anti-replay: duplicate and reordered-fresh across the channel (both AEADs)" {
    inline for (channels) |Ch| {
        var s = Ch.Sealer.init(testKey(7), 0);
        var o = Ch.Opener.init(testKey(7), 0);
        var recs: [5][record.overhead + 2]u8 = undefined;
        for (0..5) |i| _ = try s.seal(&recs[i], "hi", "c");

        var pt: [2]u8 = undefined;
        // Deliver 0, 2 (reordered-fresh), then replay 0, then 1 (fresh, in-window).
        _ = try o.open(&pt, &recs[0], "c");
        _ = try o.open(&pt, &recs[2], "c");
        try testing.expectError(error.Replayed, o.open(&pt, &recs[0], "c"));
        try testing.expectError(error.Replayed, o.open(&pt, &recs[2], "c"));
        _ = try o.open(&pt, &recs[1], "c"); // reordered but fresh, within window
        try testing.expectError(error.Replayed, o.open(&pt, &recs[1], "c"));
    }
}

test "epoch/rekey: old-epoch record rejected; reused seq in new epoch accepted" {
    inline for (channels) |Ch| {
        const key = testKey(8);
        var s = Ch.Sealer.init(key, 0);
        var o = Ch.Opener.init(key, 0);
        var rec0: [record.overhead + 3]u8 = undefined;
        _ = try s.seal(&rec0, "aaa", "c"); // epoch 0, seq 0

        var pt: [3]u8 = undefined;
        _ = try o.open(&pt, &rec0, "c"); // ok

        // Same-key epoch bump on both ends: seq resets to 0, window fresh.
        try s.bumpEpoch();
        try o.bumpEpoch();

        // The old epoch-0 record is now rejected (opener expects epoch 1).
        try testing.expectError(error.EpochMismatch, o.open(&pt, &rec0, "c"));

        // A new epoch-1 record reuses seq 0 -> a DIFFERENT nonce (epoch in
        // nonce) -> accepted, and the replay window is fresh.
        var rec1: [record.overhead + 3]u8 = undefined;
        _ = try s.seal(&rec1, "bbb", "c");
        try testing.expect(!std.mem.eql(u8, rec0[0..record.header_len], rec1[0..record.header_len]));
        const m = try o.open(&pt, &rec1, "c");
        try testing.expectEqualSlices(u8, "bbb", pt[0..m]);
    }
}

test "rekey with a fresh key: old key's record no longer opens" {
    var s = ChaChaChannel.Sealer.init(testKey(10), 0);
    var o = ChaChaChannel.Opener.init(testKey(10), 0);
    var rec_old: [record.overhead + 2]u8 = undefined;
    _ = try s.seal(&rec_old, "hi", "c");

    try s.rekey(testKey(20), 0); // fresh key: legal at any epoch, incl. the same one
    o.rekey(testKey(20), 0);
    var pt: [2]u8 = undefined;
    // Old record (old key, epoch 0) presented to the rekeyed opener (new key,
    // epoch 0): epoch matches but the key differs -> auth failure.
    try testing.expectError(error.AuthenticationFailed, o.open(&pt, &rec_old, "c"));
    // A fresh record under the new key opens.
    var rec_new: [record.overhead + 2]u8 = undefined;
    _ = try s.seal(&rec_new, "yo", "c");
    const m = try o.open(&pt, &rec_new, "c");
    try testing.expectEqualSlices(u8, "yo", pt[0..m]);
}

test "rekey to the SAME (key, epoch) is refused: no keystream reuse" {
    // Regression for the wave-2 audit's F1 probe. Before the fix, `rekey` reset
    // `seq` to 0 unconditionally, so rekey(current_key, current_epoch) re-emitted
    // nonce (epoch 0, seq 0) and the two ciphertexts XORed to the two plaintexts
    // XORed: full plaintext recovery from ciphertext alone, plus a repeated
    // one-time authentication key.
    inline for (channels) |Ch| {
        const key = testKey(21);
        var s = Ch.Sealer.init(key, 0);
        const a = "AAAAAAAA";
        const b = "BBBBBBBB";
        var rec_a: [record.overhead + a.len]u8 = undefined;
        _ = try s.seal(&rec_a, a, "c"); // epoch 0, seq 0

        // The unsafe operation must be refused, with the sealer untouched.
        const before_epoch = s.epoch;
        const before_seq = s.seq;
        if (s.rekey(key, 0)) |_| {
            // Only reachable if the guard is gone. Then the oracle below is the
            // real one: seal again and show the keystream repeated.
            var rec_b: [record.overhead + b.len]u8 = undefined;
            _ = try s.seal(&rec_b, b, "c");
            const ct_a = rec_a[record.header_len..][0..a.len];
            const ct_b = rec_b[record.header_len..][0..b.len];
            var reused = true;
            for (ct_a, ct_b) |x, y| {
                if (x ^ y != 'A' ^ 'B') reused = false;
            }
            try testing.expect(!reused); // keystream reuse — must never happen
            return error.RekeyAcceptedASpentNonceSpace;
        } else |e| {
            try testing.expectEqual(RekeyError.NonceSpaceReuse, e);
        }
        try testing.expectEqual(before_epoch, s.epoch); // state unchanged
        try testing.expectEqual(before_seq, s.seq);

        // A lower epoch under the same key is the same hazard.
        var s2 = Ch.Sealer.init(key, 7);
        try testing.expectError(error.NonceSpaceReuse, s2.rekey(key, 6));
        try testing.expectError(error.NonceSpaceReuse, s2.rekey(key, 7));
        try testing.expectEqual(@as(u32, 7), s2.epoch);

        // The two safe shapes still work: same key with a strictly greater
        // epoch (bumpEpoch's rule), and a different key at any epoch.
        try s2.rekey(key, 8);
        try testing.expectEqual(@as(u32, 8), s2.epoch);
        try testing.expectEqual(@as(u64, 0), s2.seq);
        try s2.rekey(testKey(22), 0);
        try testing.expectEqual(@as(u32, 0), s2.epoch);
    }
}

// ── KAT: the framing is byte-anchored, not merely self-consistent ─────────────

test "ChaCha record KAT: exact ct+tag for fixed key/epoch/seq/aad/pt" {
    // Anchors header layout + nonce derivation + record framing. The
    // ciphertext were produced independently by std.crypto.aead.chacha_poly
    // (byte-exact to the chachapoly sibling) over nonce =
    // deriveNonce(0x11223344, 42); the tag over the *effective* AAD this
    // module now authenticates — the 13-byte wire header (which carries
    // `version`) followed by the caller's own `aad` (see `effectiveAad`,
    // wave-2 audit finding `aeadframe` F4). ChaCha20-Poly1305's ciphertext
    // does not depend on AAD at all (RFC 8439: keystream XOR is a function
    // of key/nonce/plaintext only), so binding the header changes only the
    // tag, not `expect_ct`.
    const key = blk: {
        var k: [32]u8 = undefined;
        for (&k, 0..) |*b, i| b.* = @intCast(i);
        break :blk k;
    };
    const pt = "aeadframe record layer KAT";
    const aad = "tenant:0xABCD";
    const expect_ct = [_]u8{
        0x9a, 0x51, 0x50, 0xf0, 0xca, 0xe9, 0xaf, 0x6f, 0xfa, 0xab, 0xeb, 0x3f, 0x46,
        0x48, 0x5a, 0xad, 0xfb, 0x97, 0x7c, 0xaa, 0xed, 0xa7, 0xd7, 0x89, 0x33, 0x35,
    };
    const expect_tag = [_]u8{
        0x63, 0x05, 0x2e, 0x8f, 0x26, 0xed, 0x72, 0x30, 0x62, 0xd1, 0xce, 0x83, 0x4e, 0x1f, 0x0f, 0x7f,
    };

    var s = ChaChaChannel.Sealer.init(key, 0x11223344);
    s.seq = 42;
    var rec: [ChaChaChannel.Sealer.sealedLen(pt.len)]u8 = undefined;
    const n = try s.seal(&rec, pt, aad);

    // header: version || epoch(BE) || seq(BE)
    try testing.expectEqual(@as(u8, 1), rec[0]);
    const expect_hdr = [_]u8{ 0x01, 0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 0, 42 };
    try testing.expectEqualSlices(u8, &expect_hdr, rec[0..record.header_len]);
    try testing.expectEqualSlices(u8, &expect_ct, rec[record.header_len..][0..pt.len]);
    try testing.expectEqualSlices(u8, &expect_tag, rec[record.header_len + pt.len .. n]);

    // and it opens
    var out: [pt.len]u8 = undefined;
    var o = ChaChaChannel.Opener.init(key, 0x11223344);
    // move the opener's expected epoch is already set; window fresh accepts seq 42
    const m = try o.open(&out, rec[0..n], aad);
    try testing.expectEqualSlices(u8, pt, out[0..m]);
}

test "F4 regression: version byte is bound into the AEAD tag, not just parse's equality check" {
    // Before the fix, `version` sat outside both the nonce and the AAD:
    // `record.parse`'s raw `record[0] != version` check was the ONLY thing
    // standing between a tampered version byte and a successful decrypt.
    // That is fine while exactly one version is valid (parse's equality
    // check already refuses anything else), but it means a future opener
    // that accepts more than one version would get no AEAD-level protection
    // against a version-downgrade edit — the byte would just be unauthenticated
    // header data. This test exercises the binding at the level beneath
    // `record.parse`, the way a future multi-version opener would need it to
    // hold, by feeding the AEAD `effectiveAad` computed for two different
    // header bytes directly and checking the tags disagree + cross-checking
    // fails to authenticate.
    const key = testKey(99);
    var s = ChaChaChannel.Sealer.init(key, 3);
    var rec: [ChaChaChannel.Sealer.sealedLen(5)]u8 = undefined;
    const n = try s.seal(&rec, "hello", "ctx");
    try testing.expectEqual(rec.len, n);

    const ct = rec[record.header_len..][0..5];
    var real_tag: [record.tag_len]u8 = undefined;
    @memcpy(&real_tag, rec[record.header_len + 5 ..][0..record.tag_len]);
    const nonce = record.deriveNonce(3, 0);

    // The header actually used to seal (version = 1).
    const header_v1 = rec[0..record.header_len].*;
    // A hypothetical future record claiming version 2, everything else equal.
    var header_v2 = header_v1;
    header_v2[0] = 2;
    try testing.expect(!std.mem.eql(u8, &header_v1, &header_v2));

    var scratch1: [record.header_len + 3]u8 = undefined;
    @memcpy(scratch1[0..record.header_len], &header_v1);
    @memcpy(scratch1[record.header_len..], "ctx");
    var scratch2: [record.header_len + 3]u8 = undefined;
    @memcpy(scratch2[0..record.header_len], &header_v2);
    @memcpy(scratch2[record.header_len..], "ctx");

    // effectiveAad disagrees for the two headers (the binding exists)...
    try testing.expect(!std.mem.eql(u8, &scratch1, &scratch2));

    // ...and decrypting the real ciphertext+tag against the version-2 AAD
    // (as a future multi-version opener would compute it for a tampered
    // record) must fail authentication, not silently succeed.
    var pt_out: [5]u8 = undefined;
    try testing.expectError(
        error.AuthenticationFailed,
        chachapoly.ChaCha20Poly1305.decrypt(&pt_out, ct, real_tag, &scratch2, nonce, key),
    );
    // Sanity: the correct (version-1) AAD does authenticate.
    try chachapoly.ChaCha20Poly1305.decrypt(&pt_out, ct, real_tag, &scratch1, nonce, key);
    try testing.expectEqualSlices(u8, "hello", &pt_out);
}

// ── positive controls: permanent sentinels proving the safety tests have teeth ─

test "positive control: dropping epoch from the nonce WOULD collide across epochs" {
    // The real derivation keeps (epoch=0,seq=5) and (epoch=1,seq=5) distinct.
    try testing.expect(!std.mem.eql(u8, &record.deriveNonce(0, 5), &record.deriveNonce(1, 5)));
    // A broken derivation that ignores the epoch collides — demonstrating the
    // uniqueness test above would go RED if the real code regressed to this.
    const broken = struct {
        fn f(_: u32, seq: u64) [12]u8 {
            var n = [_]u8{0} ** 12;
            std.mem.writeInt(u64, n[4..12], seq, .big);
            return n;
        }
    }.f;
    try testing.expect(std.mem.eql(u8, &broken(0, 5), &broken(1, 5)));
}

test "positive control: an always-accept replay filter WOULD admit a replay" {
    // The real window rejects a duplicate.
    var w = replay.ReplayWindow{};
    w.commit(5);
    try testing.expect(!w.accepts(5));
    // A stub that always accepts would admit it — the replay tests would go RED
    // against such a regression.
    const AlwaysAccept = struct {
        fn accepts(_: u64) bool {
            return true;
        }
    };
    try testing.expect(AlwaysAccept.accepts(5));
}

// ── untrusted-decode fuzz: open() over arbitrary bytes never panics ───────────

fn fuzzOpen(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
    var out: [128]u8 = undefined;
    var o = ChaChaChannel.Opener.init([_]u8{0x5A} ** 32, 0);
    // Arbitrary bytes must only ever yield a typed error or a plaintext length
    // <= input — never a panic, OOB, or hang. Bounded allocation (none).
    const m = o.open(&out, buf[0..len], "aad") catch return;
    try testing.expect(m + record.overhead <= len);
}

test "fuzz: Opener.open never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzOpen, .{});
}

// ── key destruction (CONVENTIONS §2.1 Z1) ─────────────────────────────────────

test "wipe destroys the key in both halves and leaves the non-secret state alone" {
    const key = testKey(7);
    var s = ChaChaChannel.Sealer.init(key, 3);
    var o = ChaChaChannel.Opener.init(key, 3);

    var rec: [record.overhead + 5]u8 = undefined;
    _ = try s.seal(&rec, "hello", "aad");
    var pt: [5]u8 = undefined;
    _ = try o.open(&pt, &rec, "aad");

    // Preconditions: the key really is in the structs, and the non-secret
    // bookkeeping really is non-zero, so neither assertion below is vacuous.
    try testing.expectEqualSlices(u8, &key, &s.key);
    try testing.expectEqualSlices(u8, &key, &o.key);
    try testing.expectEqual(@as(u64, 1), s.seq);
    try testing.expectEqual(@as(u32, 3), o.epoch);

    s.wipe();
    o.wipe();

    const zero = [_]u8{0} ** 32;
    try testing.expectEqualSlices(u8, &zero, &s.key);
    try testing.expectEqualSlices(u8, &zero, &o.key);
    // Not secret — wipe must not touch these.
    try testing.expectEqual(@as(u64, 1), s.seq);
    try testing.expectEqual(@as(u32, 3), s.epoch);
    try testing.expectEqual(@as(u32, 3), o.epoch);
}
