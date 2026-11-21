// SPDX-License-Identifier: MIT

//! multi — the version-3 envelope: one time lock, several recipients.
//!
//! age's core feature (one file, many recipients) over this module's AND of
//! locks. A random 32-byte file key `F` encrypts the content; each recipient
//! gets a slot holding `F`, sealed under a key derived from the shared time
//! secret AND that recipient's own HQC shared secret:
//!
//! ```text
//! s_time  -> tlock to round R (one time lock, shared by every slot)
//! slot_i  =  HQC.encaps(ek_i) -> (ct_i, ss_i)
//!            (k_i, n_i) = HKDF-SHA256(salt, s_time || ss_i,
//!                                     "TLE1-slot-key" || 3 || suite || round_be || i_be16)
//!            wrapped_i  = ChaCha20-Poly1305(k_i, n_i, F, aad = prefix || ct_i)
//! content:   (K, N) = HKDF-SHA256(salt, F, "TLE1-file-key" || 3 || suite || round_be)
//!            ChaCha20-Poly1305(K, N, plaintext, aad = everything before the tag)
//! ```
//!
//! So the file opens for ANY ONE recipient's HQC secret key AND the round's
//! beacon signature: `s_time` alone opens no slot (each slot key also needs
//! `ss_i`), a recipient's key alone opens no slot before round `R` (`tlock`'s
//! FO check refuses the signature). The content AEAD authenticates every slot,
//! so slots cannot be added, dropped or swapped without `AuthFailed`.
//!
//! Wire (all integers little-endian like versions 1 and 2):
//! `magic(4) ‖ version = 3 ‖ suite ‖ flags ‖ round(8) ‖ pt_len(4) ‖ count(2) ‖
//! time_lock(128) ‖ count × (hqc_ct ‖ wrapped_F(32) ‖ slot_tag(16)) ‖ tag(16) ‖
//! ciphertext`. `count` is 1..`max_recipients`; age sets no bound, this module
//! bounds it (`Limits.max_recipients`, default 64) on both ends, since opening
//! costs one HQC decapsulation per slot.
//!
//! Opening tries the slots in order and stops at the first that opens, so the
//! time `openMulti` takes says which slot was the reader's (age behaves the
//! same way); recipients are not anonymous from each other either, as every
//! slot sits in the clear next to the others.

const std = @import("std");
const tlock = @import("tlock");
const hqc = @import("hqc");
const chachapoly = @import("chachapoly");
const entropy = @import("entropy");
const envelope = @import("envelope.zig");
const burn = @import("burn.zig");

const g1 = tlock.bls12_381.g1;
const g2 = tlock.bls12_381.g2;
const Aead = chachapoly.ChaCha20Poly1305;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

/// Wire version of the multi-recipient envelope.
pub const multi_version: u8 = 3;
/// Width of the file key `F`.
pub const file_key_bytes = 32;

const slot_label = "TLE1-slot-key";
const file_label = "TLE1-file-key";

/// Bounds on a multi-recipient envelope.
pub const Limits = struct {
    /// Most slots `sealMulti` writes and `openMulti` accepts (each slot costs
    /// the reader one HQC decapsulation). Default 64.
    max_recipients: u16 = 64,
};

/// `envelope.SealError` plus the recipient-count refusals.
pub const MultiSealError = envelope.SealError || error{
    /// No recipient.
    NoRecipients,
    /// More recipients than `Limits.max_recipients`.
    TooManyRecipients,
};

/// `envelope.OpenError` plus a count above the reader's limit.
pub const MultiOpenError = envelope.OpenError || error{
    /// The envelope declares more slots than `Limits.max_recipients`.
    TooManyRecipients,
};

pub fn Multi(comptime Kem: type) type {
    const E = envelope.Envelope(Kem);
    return struct {
        pub const time_lock_bytes = E.time_lock_bytes;
        pub const slot_bytes = Kem.ct_bytes + file_key_bytes + envelope.tag_bytes;
        /// Fixed prefix: the 19-byte header plus the slot count.
        pub const prefix_bytes = envelope.header_bytes + 2;

        /// Total wire size for `count` recipients and a `len`-byte plaintext.
        pub fn sealedLen(count: usize, len: usize) usize {
            return prefix_bytes + time_lock_bytes + count * slot_bytes + envelope.tag_bytes + len;
        }

        /// The randomness one `sealMulti` consumes; every field is secret.
        /// `kem_coins` holds one entry per recipient, in recipient order.
        pub const Randomness = struct {
            s_time: [envelope.time_secret_bytes]u8,
            tlock_sigma: [envelope.time_secret_bytes]u8,
            file_key: [file_key_bytes]u8,
            kem_coins: [][Kem.coins_bytes]u8,
        };

        /// Seal `plaintext` to every key in `recipients` under one time lock
        /// to `round`, drawing the randomness from `io` (fail-closed
        /// `entropy.fill`). Returns the wire buffer (caller frees).
        pub fn seal(
            allocator: std.mem.Allocator,
            io: std.Io,
            plaintext: []const u8,
            recipients: []const *const Kem.EncapsKey,
            p_pub: g2.Affine,
            round: u64,
            limits: Limits,
        ) MultiSealError![]u8 {
            if (recipients.len == 0) return error.NoRecipients;
            if (recipients.len > limits.max_recipients) return error.TooManyRecipients;
            const coins = try allocator.alloc([Kem.coins_bytes]u8, recipients.len);
            defer {
                std.crypto.secureZero(u8, std.mem.sliceAsBytes(coins));
                allocator.free(coins);
            }
            var rnd: Randomness = .{ .s_time = undefined, .tlock_sigma = undefined, .file_key = undefined, .kem_coins = coins };
            entropy.fill(io, &rnd.s_time);
            entropy.fill(io, &rnd.tlock_sigma);
            entropy.fill(io, &rnd.file_key);
            for (coins) |*c| entropy.fill(io, c);
            defer {
                std.crypto.secureZero(u8, &rnd.s_time);
                std.crypto.secureZero(u8, &rnd.tlock_sigma);
                std.crypto.secureZero(u8, &rnd.file_key);
            }
            return sealWithRandomness(allocator, plaintext, recipients, p_pub, round, &rnd, limits);
        }

        /// `seal` over caller-supplied randomness (tests, KATs);
        /// `rnd.kem_coins.len` must equal `recipients.len`. Reusing a
        /// `Randomness` reuses the file key and every slot key: draw a new
        /// one per call.
        pub fn sealWithRandomness(
            allocator: std.mem.Allocator,
            plaintext: []const u8,
            recipients: []const *const Kem.EncapsKey,
            p_pub: g2.Affine,
            round: u64,
            rnd: *const Randomness,
            limits: Limits,
        ) MultiSealError![]u8 {
            if (recipients.len == 0) return error.NoRecipients;
            if (recipients.len > limits.max_recipients) return error.TooManyRecipients;
            std.debug.assert(rnd.kem_coins.len == recipients.len); // one coin set per recipient
            if (plaintext.len > std.math.maxInt(u32)) return error.PlaintextTooLarge;
            return burn.run(burn.envelope_burn, MultiSealError![]u8, sealBody, .{ allocator, plaintext, recipients, p_pub, round, rnd });
        }

        fn sealBody(
            allocator: std.mem.Allocator,
            plaintext: []const u8,
            recipients: []const *const Kem.EncapsKey,
            p_pub: g2.Affine,
            round: u64,
            rnd: *const Randomness,
        ) MultiSealError![]u8 {
            const n = recipients.len;
            const out = try allocator.alloc(u8, sealedLen(n, plaintext.len));
            errdefer allocator.free(out);

            @memcpy(out[0..4], &envelope.magic);
            out[4] = multi_version;
            out[5] = E.suite_id;
            out[6] = 0;
            std.mem.writeInt(u64, out[7..15], round, .little);
            std.mem.writeInt(u32, out[15..19], @intCast(plaintext.len), .little);
            std.mem.writeInt(u16, out[19..21], @intCast(n), .little);

            const tl = tlock.encrypt(p_pub, round, &rnd.s_time, &rnd.tlock_sigma);
            out[prefix_bytes..][0..time_lock_bytes].* = tl.toBytes();

            var off: usize = prefix_bytes + time_lock_bytes;
            for (recipients, rnd.kem_coins, 0..) |ek, *coins, i| {
                const slot = out[off..][0..slot_bytes];
                var ss: Kem.SharedSecret = undefined;
                defer std.crypto.secureZero(u8, &ss);
                Kem.encaps(slot[0..Kem.ct_bytes], &ss, ek, coins);
                var k: envelope.DerivedKeys = undefined;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
                slotKeys(&k, &rnd.s_time, &ss, round, @intCast(i));
                const aad = slotAad(out[0 .. prefix_bytes + time_lock_bytes], slot[0..Kem.ct_bytes]);
                Aead.encrypt(slot[Kem.ct_bytes..][0..file_key_bytes], slot[Kem.ct_bytes + file_key_bytes ..][0..envelope.tag_bytes], &rnd.file_key, &aad.buf, k.nonce, k.key);
                off += slot_bytes;
            }

            var ck: envelope.DerivedKeys = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&ck));
            fileKeys(&ck, &rnd.file_key, round);
            Aead.encrypt(out[off + envelope.tag_bytes ..][0..plaintext.len], out[off..][0..envelope.tag_bytes], plaintext, out[0..off], ck.nonce, ck.key);
            return out;
        }

        /// Slot AAD: SHA-256 of the prefix and time lock, then the slot's
        /// HQC ciphertext, so the slot is bound to its envelope without
        /// copying the multi-KiB ciphertext.
        const SlotAad = struct { buf: [32]u8 };
        fn slotAad(prefix_and_lock: []const u8, ct: []const u8) SlotAad {
            var h = std.crypto.hash.sha2.Sha256.init(.{});
            h.update(prefix_and_lock);
            h.update(ct);
            var a: SlotAad = undefined;
            h.final(&a.buf);
            return a;
        }

        fn slotKeys(out: *envelope.DerivedKeys, s_time: *const [envelope.time_secret_bytes]u8, ss: *const Kem.SharedSecret, round: u64, index: u16) void {
            var ikm: [envelope.time_secret_bytes + @sizeOf(Kem.SharedSecret)]u8 = undefined;
            defer std.crypto.secureZero(u8, &ikm);
            @memcpy(ikm[0..envelope.time_secret_bytes], s_time);
            @memcpy(ikm[envelope.time_secret_bytes..], std.mem.asBytes(ss));
            var info: [slot_label.len + 1 + 1 + 8 + 2]u8 = undefined;
            @memcpy(info[0..slot_label.len], slot_label);
            info[slot_label.len] = multi_version;
            info[slot_label.len + 1] = E.suite_id;
            std.mem.writeInt(u64, info[slot_label.len + 2 ..][0..8], round, .big);
            std.mem.writeInt(u16, info[slot_label.len + 10 ..][0..2], index, .big);
            expand(out, &ikm, &info);
        }

        fn fileKeys(out: *envelope.DerivedKeys, file_key: *const [file_key_bytes]u8, round: u64) void {
            var info: [file_label.len + 1 + 1 + 8]u8 = undefined;
            @memcpy(info[0..file_label.len], file_label);
            info[file_label.len] = multi_version;
            info[file_label.len + 1] = E.suite_id;
            std.mem.writeInt(u64, info[file_label.len + 2 ..][0..8], round, .big);
            expand(out, file_key, &info);
        }

        fn expand(out: *envelope.DerivedKeys, ikm: []const u8, info: []const u8) void {
            var prk = Hkdf.extract(envelope.kdf_salt, ikm);
            defer std.crypto.secureZero(u8, &prk);
            var okm: [32 + envelope.nonce_bytes]u8 = undefined;
            defer std.crypto.secureZero(u8, &okm);
            Hkdf.expand(&okm, info, prk);
            out.key = okm[0..32].*;
            out.nonce = okm[32..][0..envelope.nonce_bytes].*;
        }

        /// The fixed fields of a version-3 buffer, bounds-checked.
        pub const Parsed = struct {
            round: u64,
            pt_len: usize,
            count: usize,
        };

        /// Framing only (no crypto): magic, version 3, suite, the slot
        /// count against `limits`, and the exact total length.
        pub fn parse(buf: []const u8, limits: Limits) MultiOpenError!Parsed {
            if (buf.len < prefix_bytes) return error.Truncated;
            if (!std.mem.eql(u8, buf[0..4], &envelope.magic)) return error.BadMagic;
            if (buf[4] != multi_version) return error.UnsupportedVersion;
            if (buf[5] != E.suite_id) return error.SuiteMismatch;
            const round = std.mem.readInt(u64, buf[7..15], .little);
            const pt_len = std.mem.readInt(u32, buf[15..19], .little);
            const count = std.mem.readInt(u16, buf[19..21], .little);
            if (count == 0) return error.LengthMismatch;
            if (count > limits.max_recipients) return error.TooManyRecipients;
            if (buf.len != sealedLen(count, pt_len)) return error.LengthMismatch;
            return .{ .round = round, .pt_len = pt_len, .count = count };
        }

        /// Open a version-3 envelope with one recipient's HQC secret key and
        /// the round's beacon signature. `TimeGateClosed` before the round;
        /// `AuthFailed` when no slot opens for `recipient_dk` or anything was
        /// tampered with. Returns the plaintext (caller frees).
        pub fn open(
            allocator: std.mem.Allocator,
            buf: []const u8,
            recipient_dk: *const Kem.DecapsKey,
            round_signature: g1.Affine,
            limits: Limits,
        ) MultiOpenError![]u8 {
            return burn.run(burn.envelope_burn, MultiOpenError![]u8, openBody, .{ allocator, buf, recipient_dk, round_signature, limits });
        }

        fn openBody(
            allocator: std.mem.Allocator,
            buf: []const u8,
            recipient_dk: *const Kem.DecapsKey,
            round_signature: g1.Affine,
            limits: Limits,
        ) MultiOpenError![]u8 {
            const p = try parse(buf, limits);
            const tl = tlock.Ciphertext.fromBytes(buf[prefix_bytes..][0..time_lock_bytes].*) catch
                return error.MalformedTimeLock;
            var s_time: [tlock.block_bytes]u8 = undefined;
            tlock.decrypt(&s_time, round_signature, tl) catch return error.TimeGateClosed;
            defer std.crypto.secureZero(u8, &s_time);

            var file_key: [file_key_bytes]u8 = undefined;
            defer std.crypto.secureZero(u8, &file_key);
            var opened = false;
            var off: usize = prefix_bytes + time_lock_bytes;
            for (0..p.count) |i| {
                const slot = buf[off..][0..slot_bytes];
                off += slot_bytes;
                if (opened) continue;
                var ss: Kem.SharedSecret = undefined;
                defer std.crypto.secureZero(u8, &ss);
                Kem.decaps(&ss, recipient_dk, slot[0..Kem.ct_bytes]);
                var k: envelope.DerivedKeys = undefined;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
                slotKeys(&k, &s_time, &ss, p.round, @intCast(i));
                const aad = slotAad(buf[0 .. prefix_bytes + time_lock_bytes], slot[0..Kem.ct_bytes]);
                Aead.decrypt(&file_key, slot[Kem.ct_bytes..][0..file_key_bytes], slot[Kem.ct_bytes + file_key_bytes ..][0..envelope.tag_bytes].*, &aad.buf, k.nonce, k.key) catch continue;
                opened = true;
            }
            if (!opened) return error.AuthFailed;

            var ck: envelope.DerivedKeys = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&ck));
            fileKeys(&ck, &file_key, p.round);
            const pt = try allocator.alloc(u8, p.pt_len);
            errdefer allocator.free(pt);
            Aead.decrypt(pt, buf[off + envelope.tag_bytes ..][0..p.pt_len], buf[off..][0..envelope.tag_bytes].*, buf[0..off], ck.nonce, ck.key) catch
                return error.AuthFailed;
            return pt;
        }
    };
}
