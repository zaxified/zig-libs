// SPDX-License-Identifier: MIT

//! tlsresume.stek — the Session-Ticket Encryption Key (STEK) ring: an N-deep
//! rotating set of symmetric keys a TLS 1.3 server uses to seal/open the
//! opaque `ticket` blob inside a NewSessionTicket (RFC 8446 §4.6.1 calls this
//! blob's *contents and protection* implementation-defined — "the contents
//! of this vector are entirely up to the server" — this file is that
//! implementation).
//!
//! **Ring bookkeeping (real, no crypto):** `rotate`/`findKey`/`activeKey` are
//! plain fixed-size-array management — which key currently encrypts new
//! tickets, and which older keys are still accepted for decrypting tickets
//! issued before the last rotation. No key material is generated here (the
//! engine/caller owns the CSPRNG per this repo's no-hidden-globals rule,
//! CONVENTIONS.md §2); `rotate` only stores what it is given.
//!
//! **Seal/open (REAL — AES-256-GCM):** `seal`/`open` are the one
//! security-critical pair in this file — AES-256-GCM encrypt/decrypt of the
//! caller-serialized session-state bytes, with a fresh per-seal nonce
//! (caller-supplied, since this module owns no RNG). The blob's leading
//! key id is bound as the AEAD's associated data, so a blob cannot be
//! re-pointed at a different ring slot without failing tag verification
//! (std's GCM verifies the tag in constant time internally).
//!
//! Ticket blob wire layout (opaque to the TLS engine and to RFC 8446 — this
//! module's own choice, analogous to the CONVENTIONS.md-cited proven
//! designs; see SPEC.md "STEK ticket blob layout"):
//!
//! ```
//! key_id (1 byte) || nonce (12 bytes) || ciphertext (N bytes) || tag (16 bytes)
//! ```

const std = @import("std");

/// The AEAD this ring seals tickets under (RFC 8446 §4.6.1 leaves the ticket
/// format to the server; AES-256-GCM is this module's fixed choice per the
/// scope in SPEC.md). Exposed so callers can read `key_length`/`nonce_length`
/// / `tag_length` without hardcoding them twice.
pub const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;

pub const key_length = Aead.key_length; // 32
pub const nonce_length = Aead.nonce_length; // 12
pub const tag_length = Aead.tag_length; // 16
/// 1-byte key id (RFC 8446 §4.6.1's ticket blob is entirely server-defined;
/// a single byte supports up to 256 live/rotating STEKs, ample for any
/// realistic rotation cadence). Kept as a named constant, not a literal
/// `u8` scattered through the API, so a future wider id is a one-line change.
pub const key_id_length = 1;

/// `key_id_length` (1) + `nonce_length` (12) + `tag_length` (16) — every
/// sealed ticket blob is this many bytes longer than the plaintext session
/// state it wraps.
pub const overhead = key_id_length + nonce_length + tag_length;

/// One STEK: a key id (the value stamped into every ticket blob sealed
/// under it, so `open` can find the right key without trial-decrypting
/// against all of them), the raw AEAD key, and the wall-clock second it was
/// installed (for expiry/rotation-age bookkeeping — the caller supplies the
/// clock, per this repo's no-wall-clock-inside-a-module convention).
pub const Stek = struct {
    id: u8,
    key: [key_length]u8,
    installed_at_s: i64,
};

pub const SealError = error{
    /// The ring has no active key to seal under (never rotated in one).
    NoActiveKey,
    /// `out` is too small for `plaintext.len + overhead` bytes.
    BufferTooSmall,
};

pub const OpenError = error{
    /// `blob` is shorter than `overhead` bytes, or otherwise structurally
    /// malformed (cannot even contain a key id + nonce + tag).
    Malformed,
    /// The blob's key id does not match any key currently held in the ring
    /// (rotated out already, or never issued by this server/process).
    UnknownKeyId,
    /// AEAD tag verification failed — wrong key, corrupted ciphertext, or a
    /// forged ticket. Never distinguished from `UnknownKeyId` to a remote
    /// peer (both surface as "reject this ticket, fall back to a full
    /// handshake"); kept as a distinct Zig error only for caller-side
    /// diagnostics/metrics.
    DecryptionFailed,
    /// `out` is too small for `blob.len - overhead` bytes.
    BufferTooSmall,
};

/// An N-deep ring of STEKs. `depth` bounds live keys the server accepts for
/// `open` at once (RFC 8446 §4.6.1 / common practice: keep the last 2-3
/// rotations live so tickets issued just before a rotation still work).
/// `rotate` evicts the oldest key once the ring is full. `concurrency`:
/// callers needing thread-safety wrap one instance in their own lock (this
/// type has no internal synchronization — `single_owner`, like this
/// collection's other per-connection/per-process state, e.g. `dtls`'s
/// `Connection`).
pub fn StekRing(comptime depth: usize) type {
    comptime std.debug.assert(depth >= 1);
    return struct {
        const Self = @This();

        /// Fixed-size slots, oldest-first; `null` = never installed.
        keys: [depth]?Stek = [_]?Stek{null} ** depth,
        /// Index of the slot holding the CURRENT encrypt-with key (the most
        /// recently rotated-in one). All other populated slots are
        /// decrypt-only (accepted for `open`, never used by `seal`).
        active: usize = 0,
        /// Count of `rotate` calls ever made — used to compute the next
        /// slot to evict/overwrite (`count % depth`), so rotation is a
        /// simple ring-buffer write, not an explicit shift.
        count: usize = 0,

        pub fn init() Self {
            return .{};
        }

        /// Install a new STEK as the active (encrypt-with) key, evicting the
        /// oldest slot if the ring is full. Key material (`key`) and the id
        /// (`id`) are entirely caller-supplied — this function does no
        /// randomness generation and no uniqueness checking of `id` beyond
        /// what the ring's fixed slots naturally enforce (a colliding id
        /// silently shadows whichever older slot shared it; callers should
        /// pick ids that don't collide across the live rotation window,
        /// e.g. a monotonic counter mod 256).
        pub fn rotate(self: *Self, id: u8, key: [key_length]u8, now_s: i64) void {
            const slot = self.count % depth;
            self.keys[slot] = .{ .id = id, .key = key, .installed_at_s = now_s };
            self.active = slot;
            self.count += 1;
        }

        /// The current encrypt-with key, or `null` if `rotate` was never
        /// called.
        pub fn activeKey(self: *const Self) ?Stek {
            return self.keys[self.active];
        }

        /// Look up a still-live key by the id stamped in a ticket blob.
        /// `null` means the key has rotated out (or never existed) — the
        /// caller should treat the ticket as unusable and fall back to a
        /// full (non-resumed) handshake, not an error condition.
        pub fn findKey(self: *const Self, id: u8) ?Stek {
            for (self.keys) |maybe| {
                const k = maybe orelse continue;
                if (k.id == id) return k;
            }
            return null;
        }

        /// AEAD-seal `plaintext` (the engine's serialized session state —
        /// resumption secret, negotiated cipher suite, ALPN, etc.; this
        /// module has no opinion on that layout) under the ring's current
        /// `activeKey()`. `nonce` MUST be fresh for every call under the
        /// same key (RFC 8446 §4.6.1 does not mandate a scheme; AEAD nonce
        /// reuse under GCM is catastrophic — see SPEC.md's threat model) —
        /// the caller's CSPRNG supplies it, this module owns no RNG.
        /// Writes `key_id_length + nonce_length + plaintext.len +
        /// tag_length` bytes into `out` (see `overhead`) and returns that
        /// slice. `out` must not alias `plaintext`.
        ///
        /// Blob layout (see the module doc comment): `key_id (1) || nonce
        /// (12) || ciphertext (plaintext.len) || tag (16)`, with the key-id
        /// byte bound as the AEAD associated data.
        pub fn seal(
            self: *const Self,
            plaintext: []const u8,
            nonce: [nonce_length]u8,
            out: []u8,
        ) SealError![]u8 {
            const key = self.activeKey() orelse return error.NoActiveKey;
            const total = plaintext.len + overhead;
            if (out.len < total) return error.BufferTooSmall;

            out[0] = key.id;
            @memcpy(out[key_id_length..][0..nonce_length], &nonce);
            const ciphertext = out[key_id_length + nonce_length ..][0..plaintext.len];
            var tag: [tag_length]u8 = undefined;
            // AAD = the key-id prefix: binds the blob to the STEK slot it
            // was sealed under, so an attacker cannot re-point a blob at a
            // different (still-live) key without failing tag verification.
            Aead.encrypt(ciphertext, &tag, plaintext, out[0..key_id_length], nonce, key.key);
            @memcpy(out[key_id_length + nonce_length + plaintext.len ..][0..tag_length], &tag);
            return out[0..total];
        }

        /// The `seal` mirror: parse `blob`'s key id, look it up (rejecting
        /// unknown/rotated-out ids), and AEAD-open the remainder under that
        /// key. Any tag mismatch is `error.DecryptionFailed` — never a
        /// panic, never a timing leak between "unknown key" and "bad tag"
        /// besides what's unavoidable from the lookup itself (see SPEC.md).
        /// Writes `blob.len - overhead` bytes into `out` and returns that
        /// slice. `out` must not alias `blob`.
        pub fn open(self: *const Self, blob: []const u8, out: []u8) OpenError![]u8 {
            if (blob.len < overhead) return error.Malformed;
            const key = self.findKey(blob[0]) orelse return error.UnknownKeyId;

            const plaintext_len = blob.len - overhead;
            if (out.len < plaintext_len) return error.BufferTooSmall;

            const nonce = blob[key_id_length..][0..nonce_length].*;
            const ciphertext = blob[key_id_length + nonce_length ..][0..plaintext_len];
            const tag = blob[key_id_length + nonce_length + plaintext_len ..][0..tag_length].*;
            // Same AAD as `seal` (the key-id prefix); std's GCM verifies
            // the tag in constant time before releasing any plaintext.
            Aead.decrypt(out[0..plaintext_len], ciphertext, tag, blob[0..key_id_length], nonce, key.key) catch
                return error.DecryptionFailed;
            return out[0..plaintext_len];
        }
    };
}

/// A ring depth of 3 is this module's suggested default (current + two
/// prior rotations live) — exposed as a convenience alias; any `depth` is
/// usable via `StekRing(N)` directly.
pub const DefaultRing = StekRing(3);

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "StekRing: rotate installs the active key; findKey/activeKey agree" {
    var ring = DefaultRing.init();
    try testing.expect(ring.activeKey() == null);

    ring.rotate(1, [_]u8{0xAA} ** key_length, 1_000);
    const active = ring.activeKey().?;
    try testing.expectEqual(@as(u8, 1), active.id);
    try testing.expectEqual(@as(i64, 1_000), active.installed_at_s);
    try testing.expectEqualSlices(u8, &active.key, ring.findKey(1).?.key[0..]);
    try testing.expect(ring.findKey(2) == null);
}

test "StekRing: rotating past depth evicts the oldest key (ring-buffer wraparound)" {
    var ring = StekRing(2).init();
    ring.rotate(1, [_]u8{0x01} ** key_length, 1);
    ring.rotate(2, [_]u8{0x02} ** key_length, 2);
    // Both still live (depth = 2, exactly full).
    try testing.expect(ring.findKey(1) != null);
    try testing.expect(ring.findKey(2) != null);

    ring.rotate(3, [_]u8{0x03} ** key_length, 3);
    // Key 1 evicted; 2 and 3 live; 3 is now active.
    try testing.expect(ring.findKey(1) == null);
    try testing.expect(ring.findKey(2) != null);
    try testing.expectEqual(@as(u8, 3), ring.activeKey().?.id);
}

test "overhead constant matches key_id + nonce + tag lengths" {
    try testing.expectEqual(key_id_length + nonce_length + tag_length, overhead);
    try testing.expectEqual(@as(usize, 1 + 12 + 16), overhead);
}

test "seal/open: round-trip, tamper detection, unknown id, malformed, buffer bounds" {
    var ring = DefaultRing.init();
    var blob_buf: [128]u8 = undefined;
    var out_buf: [128]u8 = undefined;
    const nonce = [_]u8{0xA1} ** nonce_length;
    const plaintext = "serialized session state";

    // No key ever rotated in -> NoActiveKey.
    try testing.expectError(error.NoActiveKey, ring.seal(plaintext, nonce, &blob_buf));

    ring.rotate(7, [_]u8{0x42} ** key_length, 1_000);

    // 1. Round-trip.
    const blob = try ring.seal(plaintext, nonce, &blob_buf);
    try testing.expectEqual(plaintext.len + overhead, blob.len);
    try testing.expectEqual(@as(u8, 7), blob[0]);
    const opened = try ring.open(blob, &out_buf);
    try testing.expectEqualSlices(u8, plaintext, opened);

    // 2. Tamper: flip a ciphertext byte, then a tag byte.
    var tampered: [128]u8 = undefined;
    @memcpy(tampered[0..blob.len], blob);
    tampered[key_id_length + nonce_length] ^= 1; // first ciphertext byte
    try testing.expectError(error.DecryptionFailed, ring.open(tampered[0..blob.len], &out_buf));
    @memcpy(tampered[0..blob.len], blob);
    tampered[blob.len - 1] ^= 1; // last tag byte
    try testing.expectError(error.DecryptionFailed, ring.open(tampered[0..blob.len], &out_buf));

    // 3. Unknown/rotated-out key id.
    @memcpy(tampered[0..blob.len], blob);
    tampered[0] = 99;
    try testing.expectError(error.UnknownKeyId, ring.open(tampered[0..blob.len], &out_buf));

    // 4. Structurally malformed (shorter than the fixed overhead).
    try testing.expectError(error.Malformed, ring.open(blob[0 .. overhead - 1], &out_buf));

    // Buffer bounds on both directions.
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, ring.seal(plaintext, nonce, &tiny));
    try testing.expectError(error.BufferTooSmall, ring.open(blob, &tiny));
}

test "seal/open: AAD binds the key id (same key bytes under a different id rejects)" {
    // Two live slots holding IDENTICAL key material — re-pointing a blob's
    // key-id byte at the other slot must still fail, proving the id is
    // authenticated as AAD, not merely used for key lookup.
    var ring = DefaultRing.init();
    const key = [_]u8{0x42} ** key_length;
    ring.rotate(1, key, 1_000);
    ring.rotate(2, key, 2_000);

    var blob_buf: [128]u8 = undefined;
    var out_buf: [128]u8 = undefined;
    var ring_one_active = ring;
    ring_one_active.active = 0; // seal under id 1 explicitly
    const blob = try ring_one_active.seal("state", [_]u8{0xB2} ** nonce_length, &blob_buf);

    var repointed: [128]u8 = undefined;
    @memcpy(repointed[0..blob.len], blob);
    repointed[0] = 2; // same key bytes, different authenticated id
    try testing.expectError(error.DecryptionFailed, ring.open(repointed[0..blob.len], &out_buf));
}

test "seal/open: an older still-live STEK still opens its tickets after rotation" {
    var ring = DefaultRing.init();
    ring.rotate(1, [_]u8{0x01} ** key_length, 1_000);

    var blob_buf: [128]u8 = undefined;
    var out_buf: [128]u8 = undefined;
    const blob = try ring.seal("pre-rotation ticket", [_]u8{0xC3} ** nonce_length, &blob_buf);

    ring.rotate(2, [_]u8{0x02} ** key_length, 2_000); // key 1 now decrypt-only
    const opened = try ring.open(blob, &out_buf);
    try testing.expectEqualSlices(u8, "pre-rotation ticket", opened);

    // New seals go out under the NEW active key.
    var blob_buf2: [128]u8 = undefined;
    const blob2 = try ring.seal("post-rotation ticket", [_]u8{0xC4} ** nonce_length, &blob_buf2);
    try testing.expectEqual(@as(u8, 2), blob2[0]);
}
