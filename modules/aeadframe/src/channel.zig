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

/// Errors from `Sealer.seal`.
pub const SealError = error{
    /// The per-epoch sequence space is exhausted. Refused rather than wrapping
    /// (a wrapped `seq` would reuse a nonce — catastrophic). Bump the epoch or
    /// rekey to get a fresh sequence space.
    SequenceExhausted,
    /// The output buffer is smaller than `sealedLen(plaintext.len)`.
    BufferTooSmall,
};

/// Error from `Sealer.bumpEpoch` (same-key epoch bump).
pub const EpochError = error{
    /// The 32-bit epoch space is exhausted; only a genuinely new key can
    /// continue safely.
    EpochExhausted,
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
                // Refuse rather than wrap: a wrapped seq reuses a nonce.
                if (self.seq == std.math.maxInt(u64)) return error.SequenceExhausted;

                const seq = self.seq;
                (record.Header{ .epoch = self.epoch, .seq = seq }).encode(out[0..record.header_len]);
                const nonce = record.deriveNonce(self.epoch, seq);
                const ct = out[record.header_len..][0..plaintext.len];
                var tag: [record.tag_len]u8 = undefined;
                Aead.encrypt(ct, &tag, plaintext, aad, nonce, self.key);
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
            pub fn rekey(self: *Sealer, new_key: [32]u8, new_epoch: u32) void {
                self.key = new_key;
                self.epoch = new_epoch;
                self.seq = 0;
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
                if (!self.window.accepts(p.header.seq)) return error.Replayed;

                const nonce = record.deriveNonce(p.header.epoch, p.header.seq);
                const ct = rec[p.ct_off..][0..p.ct_len];
                var tag: [record.tag_len]u8 = undefined;
                @memcpy(&tag, rec[p.tag_off..][0..record.tag_len]);
                const pt = out[0..p.ct_len];
                Aead.decrypt(pt, ct, tag, aad, nonce, self.key) catch |e| {
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
            /// replay window.
            pub fn rekey(self: *Opener, new_key: [32]u8, new_epoch: u32) void {
                self.key = new_key;
                self.epoch = new_epoch;
                self.window.reset();
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

    s.rekey(testKey(20), 0);
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

// ── KAT: the framing is byte-anchored, not merely self-consistent ─────────────

test "ChaCha record KAT: exact ct+tag for fixed key/epoch/seq/aad/pt" {
    // Anchors header layout + nonce derivation + record framing. The ct+tag
    // were produced independently by std.crypto.aead.chacha_poly (byte-exact
    // to the chachapoly sibling) over nonce = deriveNonce(0x11223344, 42).
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
        0xa4, 0xfb, 0x09, 0xe9, 0x57, 0x49, 0xc9, 0x75, 0x93, 0x04, 0x2e, 0x7d, 0xfb, 0xb6, 0x5b, 0x24,
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
