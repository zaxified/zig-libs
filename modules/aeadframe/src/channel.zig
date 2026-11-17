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
const burn = @import("burn.zig");
const record = @import("record.zig");
const replay = @import("replay.zig");

/// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
/// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

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
    /// A padded record (see `Opener.allow_padding`) authenticated, but its
    /// pad-length trailer is longer than the body or its padding bytes are not
    /// all zero. The record is consumed (its sequence number is committed);
    /// nothing is returned.
    InvalidPadding,
} || std.crypto.errors.AuthenticationError;

/// Error from the overlap rekeys of `Opener`.
pub const OverlapError = error{
    /// The new epoch equals the current one, so a record could not be told to
    /// belong to the old key or the new one. Use a distinct epoch.
    EpochNotDistinct,
};

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

            /// `init` with the key by pointer and the sealer built in place
            /// (dead-stack-clean: no key copy in the caller's frame, no
            /// `Sealer` in its result slot).
            pub fn initInto(out: *Sealer, key: *const [32]u8, epoch: u32) void {
                out.* = .{ .key = key.*, .epoch = epoch };
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
                return burn.run(burn.frame_burn, SealError!usize, sealBody, .{ self, out, plaintext, aad });
            }

            /// Exact record size of a padded record: `sealedLen` plus the
            /// padding and the two-byte pad-length trailer.
            pub fn sealedLenPadded(pt_len: usize, pad: u16) usize {
                return record.overhead + pt_len + pad + record.pad_trailer_len;
            }

            /// `seal` with length padding: the record is a version-2 record whose
            /// encrypted body is `plaintext ‖ 0x00 × pad ‖ pad (u16 BE)`, so the
            /// record length hides the plaintext length down to the padding
            /// granularity (TLS 1.3 / DTLS 1.3 record padding; see
            /// `record.padForBlock` for rounding to a block). Returns
            /// `sealedLenPadded(plaintext.len, pad)`. Same nonce, AAD binding and
            /// sequence rules as `seal`. A peer opens it only with
            /// `Opener.allow_padding = true`; `seal` itself is unchanged and still
            /// emits version 1 with no trailer.
            pub fn sealPadded(self: *Sealer, out: []u8, plaintext: []const u8, aad: []const u8, pad: u16) SealError!usize {
                return burn.run(burn.frame_burn, SealError!usize, sealPaddedBody, .{ self, out, plaintext, aad, pad });
            }

            fn sealBody(self: *Sealer, out: []u8, plaintext: []const u8, aad: []const u8) SealError!usize {
                return self.sealCore(out, plaintext, aad, null);
            }

            fn sealPaddedBody(self: *Sealer, out: []u8, plaintext: []const u8, aad: []const u8, pad: u16) SealError!usize {
                return self.sealCore(out, plaintext, aad, pad);
            }

            fn sealCore(self: *Sealer, out: []u8, plaintext: []const u8, aad: []const u8, pad: ?u16) SealError!usize {
                const body_len = if (pad) |p| plaintext.len + p + record.pad_trailer_len else plaintext.len;
                const need = record.overhead + body_len;
                if (out.len < need) return error.BufferTooSmall;
                if (aad.len > max_caller_aad) return error.AadTooLarge;
                // Refuse rather than wrap: a wrapped seq reuses a nonce.
                if (self.seq == std.math.maxInt(u64)) return error.SequenceExhausted;

                const seq = self.seq;
                const h = record.Header{ .epoch = self.epoch, .seq = seq };
                if (pad != null) h.encodePadded(out[0..record.header_len]) else h.encode(out[0..record.header_len]);
                const nonce = record.deriveNonce(self.epoch, seq);
                var aad_scratch: [record.header_len + max_caller_aad]u8 = undefined;
                const eff_aad = try effectiveAad(&aad_scratch, out[0..record.header_len], aad);
                const ct = out[record.header_len..][0..body_len];
                var tag: [record.tag_len]u8 = undefined;
                if (pad) |p| {
                    // Assemble `plaintext ‖ zeros ‖ pad` in the output region and
                    // encrypt it in place (std and `chachapoly` both allow `c`
                    // and `m` to be the same slice).
                    @memcpy(ct[0..plaintext.len], plaintext);
                    @memset(ct[plaintext.len..][0..p], 0);
                    std.mem.writeInt(u16, ct[plaintext.len + p ..][0..record.pad_trailer_len], p, .big);
                    Aead.encrypt(ct, &tag, ct, eff_aad, nonce, self.key);
                } else {
                    Aead.encrypt(ct, &tag, plaintext, eff_aad, nonce, self.key);
                }
                @memcpy(out[record.header_len + body_len ..][0..record.tag_len], &tag);

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
                return burn.run(burn.frame_burn, RekeyError!void, rekeyBody, .{ self, &new_key, new_epoch });
            }

            /// `rekey` with the new key by pointer (dead-stack-clean).
            pub fn rekeyInto(self: *Sealer, new_key: *const [32]u8, new_epoch: u32) RekeyError!void {
                return burn.run(burn.frame_burn, RekeyError!void, rekeyBody, .{ self, new_key, new_epoch });
            }

            fn rekeyBody(self: *Sealer, new_key: *const [32]u8, new_epoch: u32) RekeyError!void {
                // Constant-time in the key bytes: both operands are the caller's
                // own secrets, and the branch outcome (not the content) is what
                // the caller is told.
                const same_key = std.crypto.timing_safe.eql([32]u8, new_key.*, self.key);
                if (same_key and new_epoch <= self.epoch) return error.NonceSpaceReuse;
                self.key = new_key.*;
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
            /// Accept version-2 (padded) records and strip their padding. Off by
            /// default: a version-2 record is then `UnsupportedVersion`, exactly
            /// as before padding existed. Set it on an opener whose peer uses
            /// `Sealer.sealPadded`. `open` returns the plaintext length WITHOUT
            /// the padding; `out` must still hold the whole encrypted body
            /// (`rec.len - record.overhead` bytes).
            allow_padding: bool = false,
            /// The previous epoch's key and replay window, kept by `rekeyOverlap` /
            /// `bumpEpochOverlap` so records in flight across the change still
            /// open. Null (the default) means no overlap: an old-epoch record is
            /// `EpochMismatch`. Cleared by `dropPrevious` and by any other
            /// `rekey`/`bumpEpoch`; never consulted for sealing (the opener has no
            /// sealing).
            prev: ?Previous = null,

            const Previous = struct {
                key: [32]u8,
                epoch: u32,
                window: replay.ReplayWindow,
            };

            pub fn init(key: [32]u8, epoch: u32) Opener {
                return .{ .key = key, .epoch = epoch };
            }

            /// As `init`, with an explicit replay-window width (1..64).
            pub fn initWindow(key: [32]u8, epoch: u32, window_size: u7) Opener {
                return .{ .key = key, .epoch = epoch, .window = .{ .size = window_size } };
            }

            /// `init` with the key by pointer and the opener built in place
            /// (dead-stack-clean, as `Sealer.initInto`).
            pub fn initInto(out: *Opener, key: *const [32]u8, epoch: u32) void {
                out.* = .{ .key = key.*, .epoch = epoch };
            }

            /// `initWindow` with the key by pointer, built in place.
            pub fn initWindowInto(out: *Opener, key: *const [32]u8, epoch: u32, window_size: u7) void {
                out.* = .{ .key = key.*, .epoch = epoch, .window = .{ .size = window_size } };
            }

            /// Open `rec` (bound to `aad`) into `out`, returning the plaintext
            /// length. Order: parse+bounds-check → epoch check → replay
            /// pre-check → AEAD verify+decrypt → commit the sequence number.
            /// The window is committed ONLY after authentication, so a forged
            /// record can never burn a legitimate replay slot. On any failure
            /// `out[0..ct_len]` is zeroed — never garbage plaintext.
            pub fn open(self: *Opener, out: []u8, rec: []const u8, aad: []const u8) OpenError!usize {
                return burn.run(burn.frame_burn, OpenError!usize, openBody, .{ self, out, rec, aad });
            }

            fn openBody(self: *Opener, out: []u8, rec: []const u8, aad: []const u8) OpenError!usize {
                const p = try record.parseWith(rec, self.allow_padding);
                // The current epoch wins; the retained previous epoch (overlap)
                // opens under its own key and its own window (RFC 9147 §4.5.1:
                // "a separate sliding window is needed for each epoch").
                var key: *const [32]u8 = &self.key;
                var window: *replay.ReplayWindow = &self.window;
                if (p.header.epoch != self.epoch) {
                    const pv = if (self.prev) |*x| x else return error.EpochMismatch;
                    if (p.header.epoch != pv.epoch) return error.EpochMismatch;
                    key = &pv.key;
                    window = &pv.window;
                }
                if (out.len < p.ct_len) return error.BufferTooSmall;
                if (aad.len > max_caller_aad) return error.AadTooLarge;
                if (!window.accepts(p.header.seq)) return error.Replayed;

                const nonce = record.deriveNonce(p.header.epoch, p.header.seq);
                const ct = rec[p.ct_off..][0..p.ct_len];
                var tag: [record.tag_len]u8 = undefined;
                @memcpy(&tag, rec[p.tag_off..][0..record.tag_len]);
                var aad_scratch: [record.header_len + max_caller_aad]u8 = undefined;
                const eff_aad = try effectiveAad(&aad_scratch, rec[0..record.header_len], aad);
                const pt = out[0..p.ct_len];
                Aead.decrypt(pt, ct, tag, eff_aad, nonce, key.*) catch |e| {
                    // Uniform across AEADs: std's AES-GCM leaves `m` undefined
                    // on failure, chachapoly zeroes it. Make the "no garbage
                    // plaintext" contract hold for both.
                    std.crypto.secureZero(u8, pt);
                    return e;
                };
                window.commit(p.header.seq);
                if (!p.padded) return p.ct_len;
                return stripPadding(pt) catch |e| {
                    std.crypto.secureZero(u8, pt);
                    return e;
                };
            }

            /// The plaintext length of an authenticated padded body
            /// `plaintext ‖ zeros ‖ pad(u16 BE)`: the trailer must fit and every
            /// padding byte must be zero (ESP asks the receiver to check its
            /// padding; TLS 1.3 defines it as zeros).
            fn stripPadding(body: []const u8) error{InvalidPadding}!usize {
                // `parseWith` guarantees at least the two trailer bytes.
                const pad = std.mem.readInt(u16, body[body.len - record.pad_trailer_len ..][0..record.pad_trailer_len], .big);
                if (@as(usize, pad) + record.pad_trailer_len > body.len) return error.InvalidPadding;
                const pt_len = body.len - record.pad_trailer_len - pad;
                for (body[pt_len..][0..pad]) |b| if (b != 0) return error.InvalidPadding;
                return pt_len;
            }

            /// Same-key epoch advance: expect the next epoch and reset the
            /// replay window (fresh nonce space ⇒ old sequence numbers void).
            pub fn bumpEpoch(self: *Opener) EpochError!void {
                if (self.epoch == std.math.maxInt(u32)) return error.EpochExhausted;
                self.dropPrevious();
                self.epoch += 1;
                self.window.reset();
            }

            /// `bumpEpoch` that keeps the epoch being left (same key, its replay
            /// window as it stands) for records still in flight: they keep opening
            /// until `dropPrevious` or the next rekey/bump of any kind. Whatever
            /// was retained before is dropped. The sealer side needs nothing: it
            /// only ever seals under its newest epoch.
            pub fn bumpEpochOverlap(self: *Opener) EpochError!void {
                if (self.epoch == std.math.maxInt(u32)) return error.EpochExhausted;
                self.dropPrevious();
                self.prev = .{ .key = self.key, .epoch = self.epoch, .window = self.window };
                self.epoch += 1;
                self.window.reset();
            }

            /// `rekey` that keeps the key and epoch being left, with the replay
            /// window as it stands, so records sealed just before the peer
            /// switched still open. DTLS 1.3 (RFC 9147 §4.2.1) allows an endpoint
            /// to retain the previous epoch's keying material for reordering,
            /// with a window per epoch; ESP keeps the old SA until its delete. The
            /// module has no clock: the overlap lasts until `dropPrevious` or the
            /// next `rekey`/`bumpEpoch` of any kind (which also wipe the retained
            /// key), and the caller bounds it (RFC 9147: up to the TCP MSL). One
            /// previous epoch is kept, never a chain. `error.EpochNotDistinct`
            /// when `new_epoch` equals the current epoch.
            pub fn rekeyOverlap(self: *Opener, new_key: [32]u8, new_epoch: u32) OverlapError!void {
                return burn.run(burn.frame_burn, OverlapError!void, rekeyOverlapBody, .{ self, &new_key, new_epoch });
            }

            /// `rekeyOverlap` with the new key by pointer (dead-stack-clean).
            pub fn rekeyOverlapInto(self: *Opener, new_key: *const [32]u8, new_epoch: u32) OverlapError!void {
                return burn.run(burn.frame_burn, OverlapError!void, rekeyOverlapBody, .{ self, new_key, new_epoch });
            }

            fn rekeyOverlapBody(self: *Opener, new_key: *const [32]u8, new_epoch: u32) OverlapError!void {
                if (new_epoch == self.epoch) return error.EpochNotDistinct;
                self.dropPrevious();
                self.prev = .{ .key = self.key, .epoch = self.epoch, .window = self.window };
                self.key = new_key.*;
                self.epoch = new_epoch;
                self.window.reset();
            }

            /// End an overlap: wipe the retained previous key and refuse that
            /// epoch from now on (`EpochMismatch`). A no-op when none is kept.
            pub fn dropPrevious(self: *Opener) void {
                if (self.prev) |*pv| std.crypto.secureZero(u8, &pv.key);
                self.prev = null;
            }

            /// The epoch kept by an overlap, or null.
            pub fn previousEpoch(self: *const Opener) ?u32 {
                return if (self.prev) |pv| pv.epoch else null;
            }

            /// Rekey to a caller-supplied fresh key + epoch and reset the
            /// replay window. Infallible, unlike `Sealer.rekey`: the receiver
            /// emits no nonce, so there is no nonce space to spend. It only
            /// changes which records it will accept.
            pub fn rekey(self: *Opener, new_key: [32]u8, new_epoch: u32) void {
                burn.run(burn.frame_burn, void, rekeyBody, .{ self, &new_key, new_epoch });
            }

            /// `rekey` with the new key by pointer (dead-stack-clean).
            pub fn rekeyInto(self: *Opener, new_key: *const [32]u8, new_epoch: u32) void {
                burn.run(burn.frame_burn, void, rekeyBody, .{ self, new_key, new_epoch });
            }

            fn rekeyBody(self: *Opener, new_key: *const [32]u8, new_epoch: u32) void {
                self.dropPrevious();
                self.key = new_key.*;
                self.epoch = new_epoch;
                self.window.reset();
            }

            /// Destroy the AEAD key held by this opener — see `Sealer.wipe`.
            /// The replay window is left intact: it is not secret, and it is the
            /// record of what this peer already accepted.
            pub fn wipe(self: *Opener) void {
                std.crypto.secureZero(u8, &self.key);
                self.dropPrevious();
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
            var n = @as([12]u8, @splat(0));
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
//
// ⚠ This harness used to open with
//
//     smith.bytes(&buf);
//     const len: usize = smith.valueRangeAtMost(u8, 0, buf.len);
//
// and carried no corpus. `bytes` consumes what the seed has, and the ranged
// draw then finds fewer than the eight octets it reads as a little-endian u64,
// so `len` was the range MINIMUM — zero. Outside `--fuzz` the target therefore
// ran exactly one input for ever: `open(&out, "", "aad")`, which `record.parse`
// refuses as `Truncated` before anything else runs. The assertion this harness
// exists for — `m + record.overhead <= len` — had never executed once.
//
// ⛔ Arbitrary bytes cannot repair that on their own: a record only gets past
// `Aead.decrypt` if it carries a valid tag over its own header, so the chance
// of drawing one is 2^-128. The corpus below therefore comes out of this
// module's OWN sealer, under the same key/epoch/aad the harness opens with, and
// the near-misses are that record with a single octet changed — the shape that
// reaches past `parse` and into the epoch/replay/AEAD checks behind it.

/// Key, epoch and caller-aad the corpus is sealed under. The harness and the
/// guard both open with exactly these, so "accepted" means the seed's own
/// octets authenticated — not that some other input happened to be legal.
const fuzz_key = @as([32]u8, @splat(0x5A));
const fuzz_epoch: u32 = 0;
const fuzz_aad = "aad";

/// The corpus is built at run time (only the sealer can produce a record), so
/// the guard below builds it from HERE rather than from a second copy — a
/// guard measuring a different corpus is not a guard.
const OpenCorpus = struct {
    const count = 8;
    /// 128 is the harness's buffer; a seed longer than it reads back EMPTY.
    frames: [count][128]u8 = undefined,
    store: [count][4 + 128]u8 = undefined,
    seeds: [count][]const u8 = undefined,

    fn set(self: *OpenCorpus, i: usize, frame: []const u8) void {
        @memcpy(self.frames[i][0..frame.len], frame);
        self.seeds[i] = testkit.fuzz.seedInto(&self.store[i], self.frames[i][0..frame.len]);
    }

    fn setPerturbed(self: *OpenCorpus, i: usize, frame: []const u8, at: usize, mask: u8) void {
        var tmp: [128]u8 = undefined;
        @memcpy(tmp[0..frame.len], frame);
        tmp[at] ^= mask;
        self.set(i, tmp[0..frame.len]);
    }

    fn build(self: *OpenCorpus) void {
        var s = ChaChaChannel.Sealer.init(fuzz_key, fuzz_epoch);
        var rec: [128]u8 = undefined;

        // seq 0: a genuine record. A fresh Opener has committed nothing, so
        // this one authenticates and commits.
        const n0 = s.seal(&rec, "hello", fuzz_aad) catch unreachable;
        self.set(0, rec[0..n0]);
        var real: [128]u8 = undefined;
        @memcpy(real[0..n0], rec[0..n0]);

        // seq 1, empty plaintext: the shortest record that exists (exactly
        // `overhead`), and the boundary `parse` measures `Truncated` against.
        const n1 = s.seal(&rec, "", fuzz_aad) catch unreachable;
        self.set(1, rec[0..n1]);

        // seq 2, the longest record the harness's buffer can carry.
        const big = @as([128 - record.overhead]u8, @splat(0xA5));
        const n2 = s.seal(&rec, &big, fuzz_aad) catch unreachable;
        self.set(2, rec[0..n2]);

        // One ciphertext octet flipped: parses, epoch matches, window admits
        // it, and only Poly1305 refuses — the deepest refusal in `open`.
        self.setPerturbed(3, real[0..n0], record.header_len, 0x01);
        // Version octet wrong: `UnsupportedVersion`, before any AEAD work.
        self.setPerturbed(4, real[0..n0], 0, 0x01);
        // Epoch octet wrong: `EpochMismatch`.
        self.setPerturbed(5, real[0..n0], 1, 0x01);
        // One octet short of `overhead`: `Truncated`.
        self.set(6, real[0 .. record.overhead - 1]);
        // And the input this target used to run for ever.
        self.set(7, "");
    }
};

fn fuzzOpen(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    const len: usize = smith.slice(&buf);
    var out: [128]u8 = undefined;
    var o = ChaChaChannel.Opener.init(fuzz_key, fuzz_epoch);
    // Arbitrary bytes must only ever yield a typed error or a plaintext length
    // <= input — never a panic, OOB, or hang. Bounded allocation (none).
    const m = o.open(&out, buf[0..len], fuzz_aad) catch return;
    try testing.expect(m + record.overhead <= len);
}

test "fuzz: Opener.open never panics on arbitrary bytes" {
    var corpus: OpenCorpus = .{};
    corpus.build();
    try testing.fuzz({}, fuzzOpen, .{ .corpus = &corpus.seeds });
}

test "corpus: every open seed reaches the record parser, counts pinned" {
    var corpus: OpenCorpus = .{};
    corpus.build();

    var nonempty: usize = 0;
    var accepted: usize = 0;
    // ⛔ `accepted > 0` would be no guard here: it is the plaintext OCTETS the
    // collapsed harness cannot produce. `open("")` is refused, and the
    // empty-plaintext record is accepted while yielding nothing, so this second
    // number only moves when a seed's own ciphertext actually decrypted.
    var plaintext_octets: usize = 0;
    for (corpus.seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [128]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var out: [128]u8 = undefined;
        var o = ChaChaChannel.Opener.init(fuzz_key, fuzz_epoch);
        const m = o.open(&out, buf[0..len], fuzz_aad) catch continue;
        accepted += 1;
        plaintext_octets += m;
    }
    try testing.expectEqual(OpenCorpus.count - 1, nonempty); // seed 7 is empty
    try testing.expectEqual(@as(usize, 3), accepted);
    // 5 ("hello") + 0 (empty plaintext) + 99 (the buffer-filling record).
    try testing.expectEqual(@as(usize, 104), plaintext_octets);
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

    const zero = @as([32]u8, @splat(0));
    try testing.expectEqualSlices(u8, &zero, &s.key);
    try testing.expectEqualSlices(u8, &zero, &o.key);
    // Not secret — wipe must not touch these.
    try testing.expectEqual(@as(u64, 1), s.seq);
    try testing.expectEqual(@as(u32, 3), s.epoch);
    try testing.expectEqual(@as(u32, 3), o.epoch);
}

// ── mutation run 2026-10-05 ─────────────────────────────────────────────────

test "AAD of exactly max_caller_aad seals and opens; one octet more is refused" {
    inline for (channels) |Ch| {
        const key = testKey(31);
        var s = Ch.Sealer.init(key, 0);
        var o = Ch.Opener.init(key, 0);
        const aad = @as([max_caller_aad + 1]u8, @splat(0x61));
        var rec: [record.overhead + 2]u8 = undefined;
        _ = try s.seal(&rec, "ok", aad[0..max_caller_aad]);
        var pt: [2]u8 = undefined;
        _ = try o.open(&pt, &rec, aad[0..max_caller_aad]);
        try testing.expectEqualStrings("ok", &pt);
        try testing.expectError(error.AadTooLarge, s.seal(&rec, "ok", &aad));
        try testing.expectError(error.AadTooLarge, o.open(&pt, &rec, &aad));
    }
}

test "bumpEpoch and rekey restart seq at 0 after records were sealed; Opener.rekey restarts the window" {
    // The documented contract: a new (key, epoch) starts its sequence at 0.
    // The tests above only checked it on sealers that had not sealed yet.
    inline for (channels) |Ch| {
        const key = testKey(41);
        var s = Ch.Sealer.init(key, 0);
        var rec: [record.overhead + 1]u8 = undefined;
        for (0..3) |_| _ = try s.seal(&rec, "x", "");
        try s.bumpEpoch();
        try testing.expectEqual(@as(u64, 0), s.seq);
        for (0..3) |_| _ = try s.seal(&rec, "x", "");
        try s.rekey(testKey(42), 9);
        try testing.expectEqual(@as(u64, 0), s.seq);

        // Receiver: a window that has seen seq 0..99 under the old key must
        // not refuse seq 0 under the new one.
        var old_s = Ch.Sealer.init(key, 0);
        var o = Ch.Opener.init(key, 0);
        var pt: [1]u8 = undefined;
        for (0..100) |_| {
            _ = try old_s.seal(&rec, "y", "");
            _ = try o.open(&pt, &rec, "");
        }
        o.rekey(testKey(43), 1);
        var new_s = Ch.Sealer.init(testKey(43), 1);
        _ = try new_s.seal(&rec, "z", "");
        _ = try o.open(&pt, &rec, "");
        try testing.expectEqualStrings("z", &pt);
    }
}

// ── length padding (version-2 records, opt-in) ───────────────────────────────

/// Both AEADs with their instantiation, for the padding tests.
const padding_cases = .{
    .{ ChaChaChannel, chachapoly.ChaCha20Poly1305 },
    .{ AesGcmChannel, std.crypto.aead.aes_gcm.Aes256Gcm },
};

test "padded record: round trip, size, version 2, seq advance; plain seal still version 1 (both AEADs)" {
    inline for (padding_cases) |c| {
        const Ch = c[0];
        var s = Ch.Sealer.init(testKey(21), 4);
        var o = Ch.Opener.init(testKey(21), 4);
        o.allow_padding = true;
        const msg = "padded payload";
        for ([_]u16{ 0, 1, 7, 100 }, 0..) |pad, i| {
            var rec: [record.overhead + msg.len + 100 + record.pad_trailer_len]u8 = undefined;
            const n = try s.sealPadded(&rec, msg, "ctx", pad);
            try testing.expectEqual(Ch.Sealer.sealedLenPadded(msg.len, pad), n);
            try testing.expectEqual(record.overhead + msg.len + pad + 2, n);
            try testing.expectEqual(record.version_padded, rec[0]);
            try testing.expectEqual(@as(u64, i + 1), s.seq);
            var pt: [msg.len + 100 + record.pad_trailer_len]u8 = undefined;
            const m = try o.open(&pt, rec[0..n], "ctx");
            try testing.expectEqualStrings(msg, pt[0..m]);
        }
        // `seal` is untouched: version 1, no trailer, and the same opener reads it.
        var rec: [record.overhead + msg.len]u8 = undefined;
        const n = try s.seal(&rec, msg, "ctx");
        try testing.expectEqual(record.overhead + msg.len, n);
        try testing.expectEqual(record.version, rec[0]);
        var pt: [msg.len]u8 = undefined;
        try testing.expectEqual(msg.len, try o.open(&pt, rec[0..n], "ctx"));
        // An empty plaintext pads too.
        var rec0: [record.overhead + 10 + record.pad_trailer_len]u8 = undefined;
        const n0 = try s.sealPadded(&rec0, "", "", 10);
        var pt0: [10 + record.pad_trailer_len]u8 = undefined;
        try testing.expectEqual(@as(usize, 0), try o.open(&pt0, rec0[0..n0], ""));
    }
}

test "padded record: independent construction pins the bytes (both AEADs)" {
    inline for (padding_cases) |c| {
        const Ch = c[0];
        const Aead = c[1];
        const key = testKey(22);
        var s = Ch.Sealer.init(key, 0x01020304);
        s.seq = 9;
        const msg = "abc";
        const aad = "ad";
        var rec: [record.overhead + msg.len + 5 + record.pad_trailer_len]u8 = undefined;
        const n = try s.sealPadded(&rec, msg, aad, 5);

        // Expected: header v2, body msg ‖ 00×5 ‖ 0005, AAD = header ‖ aad, nonce (epoch, seq).
        var hdr: [record.header_len]u8 = undefined;
        (record.Header{ .epoch = 0x01020304, .seq = 9 }).encodePadded(&hdr);
        try testing.expectEqualSlices(u8, &.{ 2, 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 9 }, &hdr);
        const body = "abc" ++ [_]u8{ 0, 0, 0, 0, 0 } ++ [_]u8{ 0, 5 };
        var eff: [record.header_len + aad.len]u8 = undefined;
        @memcpy(eff[0..record.header_len], &hdr);
        @memcpy(eff[record.header_len..], aad);
        var ct: [body.len]u8 = undefined;
        var tag: [record.tag_len]u8 = undefined;
        Aead.encrypt(&ct, &tag, body, &eff, record.deriveNonce(0x01020304, 9), key);
        try testing.expectEqualSlices(u8, &hdr, rec[0..record.header_len]);
        try testing.expectEqualSlices(u8, &ct, rec[record.header_len..][0..ct.len]);
        try testing.expectEqualSlices(u8, &tag, rec[record.header_len + ct.len ..][0..record.tag_len]);
        try testing.expectEqual(record.header_len + ct.len + record.tag_len, n);
    }
}

test "padded record: an opener without allow_padding refuses version 2 as before" {
    inline for (channels) |Ch| {
        var s = Ch.Sealer.init(testKey(23), 0);
        var rec: [record.overhead + 4 + 3 + record.pad_trailer_len]u8 = undefined;
        const n = try s.sealPadded(&rec, "data", "", 3);
        var o = Ch.Opener.init(testKey(23), 0);
        try testing.expect(!o.allow_padding);
        var pt: [64]u8 = undefined;
        try testing.expectError(error.UnsupportedVersion, o.open(&pt, rec[0..n], ""));
        // The refusal changed nothing: with padding allowed the record opens.
        o.allow_padding = true;
        try testing.expectEqual(@as(usize, 4), try o.open(&pt, rec[0..n], ""));
    }
}

test "padded record: the version byte is authenticated both ways; replays and truncation are refused" {
    inline for (channels) |Ch| {
        var s = Ch.Sealer.init(testKey(24), 0);
        var padded: [record.overhead + 4 + 3 + record.pad_trailer_len]u8 = undefined;
        const pn = try s.sealPadded(&padded, "data", "x", 3);
        var plain: [record.overhead + 4]u8 = undefined;
        const ln = try s.seal(&plain, "data", "x");

        var o = Ch.Opener.init(testKey(24), 0);
        o.allow_padding = true;
        var pt: [64]u8 = undefined;
        // 2 -> 1 and 1 -> 2: the header is in the AAD, so both fail authentication.
        var a = padded;
        a[0] = record.version;
        try testing.expectError(error.AuthenticationFailed, o.open(&pt, a[0..pn], "x"));
        var b = plain;
        b[0] = record.version_padded;
        try testing.expectError(error.AuthenticationFailed, o.open(&pt, b[0..ln], "x"));
        // The genuine records open once, then are replays.
        try testing.expectEqual(@as(usize, 4), try o.open(&pt, padded[0..pn], "x"));
        try testing.expectError(error.Replayed, o.open(&pt, padded[0..pn], "x"));
        try testing.expectEqual(@as(usize, 4), try o.open(&pt, plain[0..ln], "x"));
        // A version-2 record too short for its trailer is truncated; without
        // allow_padding it is the unsupported version it always was.
        var short: [record.overhead]u8 = undefined;
        @memset(&short, 0);
        short[0] = record.version_padded;
        try testing.expectError(error.Truncated, o.open(&pt, &short, ""));
        o.allow_padding = false;
        try testing.expectError(error.UnsupportedVersion, o.open(&pt, &short, ""));
    }
}

test "padded record: an authentic record with a bad trailer is InvalidPadding, consumed and wiped (both AEADs)" {
    inline for (padding_cases) |c| {
        const Ch = c[0];
        const Aead = c[1];
        const key = testKey(25);
        const bodies = [_][]const u8{
            "data" ++ [_]u8{ 0, 1, 0, 0, 3 }, // a non-zero padding byte (middle)
            "data" ++ [_]u8{ 9, 0, 0, 0, 3 }, // ... first
            "data" ++ [_]u8{ 0, 0, 7, 0, 3 }, // ... last
            "data" ++ [_]u8{ 0, 0, 0, 9 }, // pad length longer than the body
            "ab" ++ [_]u8{ 0, 3 }, // pad length 3 > the 0 bytes before the trailer
            &[_]u8{ 0, 3, 0 }, // trailer read from the last two bytes only
            &[_]u8{ 0xff, 0xff }, // pad length 65535 > body
        };
        for (bodies, 0..) |body, i| {
            var hdr: [record.header_len]u8 = undefined;
            (record.Header{ .epoch = 0, .seq = i }).encodePadded(&hdr);
            var rec: [record.overhead + 16]u8 = undefined;
            @memcpy(rec[0..record.header_len], &hdr);
            var tag: [record.tag_len]u8 = undefined;
            Aead.encrypt(rec[record.header_len..][0..body.len], &tag, body, &hdr, record.deriveNonce(0, i), key);
            @memcpy(rec[record.header_len + body.len ..][0..record.tag_len], &tag);
            const n = record.overhead + body.len;

            var o = Ch.Opener.init(key, 0);
            o.allow_padding = true;
            var pt: [16]u8 = undefined;
            @memset(&pt, 0xAA);
            try testing.expectError(error.InvalidPadding, o.open(&pt, rec[0..n], ""));
            for (pt[0..body.len]) |b| try testing.expectEqual(@as(u8, 0), b);
            // Authentic, so consumed: the same record is now a replay.
            try testing.expectError(error.Replayed, o.open(&pt, rec[0..n], ""));
        }
    }
}

test "padded record: the maximum pad, buffer boundaries and block rounding" {
    var s = ChaChaChannel.Sealer.init(testKey(26), 0);
    var o = ChaChaChannel.Opener.init(testKey(26), 0);
    o.allow_padding = true;
    const max_pad: u16 = std.math.maxInt(u16);
    const max_pad_len: usize = max_pad;
    var rec: [record.overhead + 1 + max_pad_len + record.pad_trailer_len]u8 = undefined;
    // One byte short is BufferTooSmall and burns no sequence number.
    try testing.expectError(error.BufferTooSmall, s.sealPadded(rec[0 .. rec.len - 1], "x", "", max_pad));
    try testing.expectEqual(@as(u64, 0), s.seq);
    const n = try s.sealPadded(&rec, "x", "", max_pad);
    try testing.expectEqual(rec.len, n);
    var pt: [1 + max_pad_len + record.pad_trailer_len]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), try o.open(&pt, rec[0..n], ""));
    try testing.expectEqualStrings("x", pt[0..1]);

    // padForBlock: the padded body (plaintext + 2) lands on a multiple of the block.
    try testing.expectEqual(@as(u16, 14), record.padForBlock(0, 16));
    try testing.expectEqual(@as(u16, 0), record.padForBlock(14, 16));
    try testing.expectEqual(@as(u16, 15), record.padForBlock(15, 16));
    try testing.expectEqual(@as(u16, 0), record.padForBlock(5, 0));
    try testing.expectEqual(@as(u16, 0), record.padForBlock(5, 1));
    try testing.expectEqual(@as(u16, 1), record.padForBlock(5, 8));
    try testing.expectEqual(max_pad, record.padForBlock(0, 70000));
    for (0..40) |len| {
        const pad = record.padForBlock(len, 16);
        try testing.expectEqual(@as(usize, 0), (len + pad + record.pad_trailer_len) % 16);
        try testing.expect(pad < 16);
    }
}

// ── multi-epoch opener: overlap window at rekey ──────────────────────────────

test "overlap rekey: in-flight old-epoch records open, windows are per epoch, default is unchanged (both AEADs)" {
    inline for (channels) |Ch| {
        const key_a = testKey(31);
        const key_b = testKey(32);
        var s_old = Ch.Sealer.init(key_a, 0);
        var s_new = Ch.Sealer.init(key_b, 1);
        var old: [4][record.overhead + 1]u8 = undefined;
        for (&old, 0..) |*r, i| _ = try s_old.seal(r, &[_]u8{@intCast('a' + i)}, "c");
        var pt: [1]u8 = undefined;

        // Without overlap, the same switch refuses the in-flight record.
        {
            var plain = Ch.Opener.init(key_a, 0);
            _ = try plain.open(&pt, &old[0], "c");
            plain.rekey(key_b, 1);
            try testing.expectEqual(@as(?u32, null), plain.previousEpoch());
            try testing.expectError(error.EpochMismatch, plain.open(&pt, &old[1], "c"));
        }

        var o = Ch.Opener.init(key_a, 0);
        _ = try o.open(&pt, &old[0], "c"); // seq 0 delivered before the switch
        try o.rekeyOverlap(key_b, 1);
        try testing.expectEqual(@as(?u32, 0), o.previousEpoch());

        // New-epoch traffic races ahead; its window must not affect the old one.
        var n: [record.overhead + 1]u8 = undefined;
        s_new.seq = 50;
        _ = try s_new.seal(&n, "N", "c");
        try testing.expectEqual(@as(usize, 1), try o.open(&pt, &n, "c"));
        try testing.expectEqualStrings("N", &pt);

        // Old records still in flight: seq 2 before seq 1 (reordered), both open once.
        try testing.expectEqual(@as(usize, 1), try o.open(&pt, &old[2], "c"));
        try testing.expectEqualStrings("c", &pt);
        try testing.expectEqual(@as(usize, 1), try o.open(&pt, &old[1], "c"));
        try testing.expectEqualStrings("b", &pt);
        // Replays in the old epoch: seq 0 (opened before the switch) and seq 2.
        try testing.expectError(error.Replayed, o.open(&pt, &old[0], "c"));
        try testing.expectError(error.Replayed, o.open(&pt, &old[2], "c"));
        // An epoch that is neither is still a mismatch.
        var s_x = Ch.Sealer.init(key_b, 2);
        var x: [record.overhead + 1]u8 = undefined;
        _ = try s_x.seal(&x, "x", "c");
        try testing.expectError(error.EpochMismatch, o.open(&pt, &x, "c"));

        // The new epoch has its own fresh window: its seq 0 opens although the old epoch used seq 0.
        var s_fresh = Ch.Sealer.init(key_b, 1);
        var f0: [record.overhead + 1]u8 = undefined;
        _ = try s_fresh.seal(&f0, "F", "c");
        try testing.expectEqual(@as(usize, 1), try o.open(&pt, &f0, "c"));

        // Ending the overlap refuses the old epoch and wipes its key.
        o.dropPrevious();
        try testing.expectEqual(@as(?u32, null), o.previousEpoch());
        try testing.expectError(error.EpochMismatch, o.open(&pt, &old[3], "c"));
        o.dropPrevious(); // a no-op when nothing is kept
    }
}

test "overlap rekey: a forged old-epoch record burns nothing; the retained key is wiped on drop, wipe and any other rekey" {
    inline for (channels) |Ch| {
        const key_a = testKey(33);
        const key_b = testKey(34);
        var s_old = Ch.Sealer.init(key_a, 0);
        var o = Ch.Opener.init(key_a, 0);
        try o.rekeyOverlap(key_b, 1);
        try testing.expectEqualSlices(u8, &key_a, &o.prev.?.key);

        // Same epoch number, wrong key: authentication fails and the slot stays free.
        var forger = Ch.Sealer.init(testKey(99), 0);
        var bad: [record.overhead + 1]u8 = undefined;
        _ = try forger.seal(&bad, "f", "c");
        var pt: [1]u8 = undefined;
        try testing.expectError(error.AuthenticationFailed, o.open(&pt, &bad, "c"));
        var good: [record.overhead + 1]u8 = undefined;
        _ = try s_old.seal(&good, "g", "c");
        try testing.expectEqual(@as(usize, 1), try o.open(&pt, &good, "c"));

        // Another overlap replaces the retained epoch (one, never a chain) and wipes the old key.
        try o.rekeyOverlap(testKey(35), 2);
        try testing.expectEqual(@as(?u32, 1), o.previousEpoch());
        try testing.expectEqualSlices(u8, &key_b, &o.prev.?.key);
        try testing.expectError(error.EpochMismatch, o.open(&pt, &good, "c")); // epoch 0 is gone

        // dropPrevious zeroes the retained key where it lives (the optional's payload outlives the null).
        try o.rekeyOverlap(testKey(60), 7);
        const kept: *const [32]u8 = &o.prev.?.key;
        try testing.expectEqualSlices(u8, &testKey(35), kept);
        o.dropPrevious();
        try testing.expectEqualSlices(u8, &@as([32]u8, @splat(0)), kept);

        // A plain rekey ends it; so does bumpEpoch; so does wipe.
        try o.rekeyOverlap(testKey(61), 8);
        try testing.expect(o.previousEpoch() != null);
        o.rekey(testKey(36), 3);
        try testing.expectEqual(@as(?u32, null), o.previousEpoch());
        try o.rekeyOverlap(testKey(37), 4);
        try o.bumpEpoch();
        try testing.expectEqual(@as(?u32, null), o.previousEpoch());
        try o.rekeyOverlap(testKey(38), 6);
        o.wipe();
        try testing.expectEqual(@as(?u32, null), o.previousEpoch());
    }
}

test "overlap rekey: same-epoch rekey is refused untouched; bumpEpochOverlap keeps the same key and window" {
    inline for (channels) |Ch| {
        const key = testKey(40);
        var o = Ch.Opener.init(key, 5);
        try testing.expectError(error.EpochNotDistinct, o.rekeyOverlap(testKey(41), 5));
        // Any distinct epoch is fine, a lower one too (the caller numbers epochs).
        var lower = Ch.Opener.init(key, 5);
        try lower.rekeyOverlap(testKey(42), 2);
        try testing.expectEqual(@as(?u32, 5), lower.previousEpoch());
        try testing.expectEqual(@as(u32, 2), lower.epoch);
        try testing.expectEqualSlices(u8, &key, &o.key);
        try testing.expectEqual(@as(?u32, null), o.previousEpoch());
        try testing.expectEqual(@as(u32, 5), o.epoch);

        var s = Ch.Sealer.init(key, 5);
        var recs: [3][record.overhead + 1]u8 = undefined;
        for (&recs) |*r| _ = try s.seal(r, "z", "");
        var pt: [1]u8 = undefined;
        _ = try o.open(&pt, &recs[0], "");
        try o.bumpEpochOverlap();
        try testing.expectEqual(@as(u32, 6), o.epoch);
        try testing.expectEqual(@as(?u32, 5), o.previousEpoch());
        try testing.expectError(error.Replayed, o.open(&pt, &recs[0], "")); // its window came along
        try testing.expectEqual(@as(usize, 1), try o.open(&pt, &recs[2], ""));
        try testing.expectEqual(@as(usize, 1), try o.open(&pt, &recs[1], ""));
        // The new epoch opens under the same key with a fresh window.
        try s.bumpEpoch();
        var next: [record.overhead + 1]u8 = undefined;
        _ = try s.seal(&next, "n", "");
        try testing.expectEqual(@as(usize, 1), try o.open(&pt, &next, ""));

        // The epoch ceiling is refused with the state intact.
        var top = Ch.Opener.init(key, std.math.maxInt(u32));
        try testing.expectError(error.EpochExhausted, top.bumpEpochOverlap());
        try testing.expectEqual(@as(?u32, null), top.previousEpoch());
    }
}
