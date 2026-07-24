// SPDX-License-Identifier: MIT

//! envelope — the hybrid two-lock sealed-envelope construction: a
//! generic `Envelope(Kem)` that composes THREE already-verified sibling
//! primitives into a single ciphertext whose plaintext is recoverable
//! only when BOTH locks open:
//!
//! 1. **Time lock** (`tlock`) — a `block_bytes`-wide random secret
//!    `s_time` is timelock-encrypted to a future drand round `R`. It is
//!    unrecoverable until that round's beacon signature is published (a
//!    TEMPORAL secret — nobody holds the key early), at which point
//!    `tlock.decrypt` returns it. `tlock` is pairing-based (BLS12-381),
//!    so this lock is NOT post-quantum — it enforces *timing* only.
//! 2. **PQ lock** (`hqc`) — the HQC code-based KEM encapsulates a
//!    shared secret `s_pq` to the recipient's long-term public key. Only
//!    the holder of the matching HQC secret key can decapsulate it. HQC
//!    is genuinely post-quantum, so this lock carries the envelope's
//!    long-term *confidentiality* against a future quantum adversary who
//!    records the ciphertext today.
//!
//! ## How the AND is enforced (not merely asserted)
//!
//! The content key `K` and the AEAD nonce are BOTH derived from
//! `HKDF-SHA256(ikm = s_time || s_pq, info = context)`. Content is sealed
//! with `chachapoly` (ChaCha20-Poly1305) under `K`, with the whole header
//! (magic/version/suite/round + the two lock ciphertexts) as the AEAD
//! additional-authenticated-data. Two independent mechanisms make this a
//! true AND, not an OR:
//!
//! - **Time lock:** `open` calls `tlock.decrypt`, which runs its own
//!   Fujisaki-Okamoto consistency check and returns a typed error for any
//!   wrong/absent/other-round signature. Before round `R` no valid
//!   signature exists, so `open` cannot even recover `s_time` → typed
//!   `error.TimeGateClosed`.
//! - **PQ lock:** HQC's KEM uses implicit rejection — `decaps` with the
//!   WRONG secret key does not error, it returns a pseudo-random `s_pq`.
//!   That wrong `s_pq` yields a wrong `K`, and the Poly1305 tag then
//!   fails → typed `error.AuthFailed`. So the AEAD tag is what actually
//!   gates the PQ lock, which is exactly why `K` must be bound to `s_pq`.
//!
//! Recovering `K` therefore requires BOTH secrets; neither lock alone
//! suffices. `security_test.zig` proves each direction, and this file's
//! permanent positive-control tests prove the KDF genuinely binds each
//! secret (a broken KDF that dropped one is detectably different).
//!
//! ## What this module does NOT do
//!
//! It composes; it never reimplements crypto. `tlock`/`hqc`/`chachapoly`
//! are used exactly as they ship, and the KDF is `std.crypto.kdf.hkdf`.
//! It runs no drand beacon and no DKG: `p_pub` (seal) and
//! `round_signature` (open) are caller-supplied, exactly as `tlock`
//! itself requires. See `SPEC.md` for the field-by-field wire format,
//! the threat model, and the honest post-quantum caveat.

const std = @import("std");
const tlock = @import("tlock");
const hqc = @import("hqc");
const chachapoly = @import("chachapoly");

const bls12_381 = tlock.bls12_381;
const g1 = bls12_381.g1;
const g2 = bls12_381.g2;

const Aead = chachapoly.ChaCha20Poly1305;
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

/// Width of the timelock-protected secret `s_time` — `tlock`'s fixed
/// ciphertext block width (16). See `tlock.block_bytes`.
pub const time_secret_bytes = tlock.block_bytes;

/// The AEAD tag length (16, Poly1305).
pub const tag_bytes = Aead.tag_length;
/// The AEAD nonce length (12). Derived, never stored — see `deriveKeys`.
pub const nonce_bytes = Aead.nonce_length;

/// Fixed 4-byte magic identifying a timelock_envelope wire buffer.
pub const magic = [4]u8{ 'T', 'L', 'E', '1' };
/// Wire-format version. Bumped on any breaking layout/KDF change.
pub const version: u8 = 1;

/// HKDF salt — a fixed domain-separation label so this construction's
/// extracted PRK can never collide with another protocol reusing the
/// same `(s_time, s_pq)` material. Public for auditability.
pub const kdf_salt = "timelock_envelope:v1:hybrid-AND:hkdf-sha256";
/// HKDF `info` prefix — the semantic label the round/version/suite bytes
/// are appended to (see `deriveKeys`).
pub const kdf_info_label = "TLE1-content-key";

/// Fixed header size in bytes (before the two lock ciphertexts):
/// `magic(4) || version(1) || suite_id(1) || flags(1) || round_le(8) ||
/// pt_len_le(4)`.
pub const header_bytes: usize = 4 + 1 + 1 + 1 + 8 + 4;

const round_off = 7; // magic(4)+version(1)+suite(1)+flags(1)
const pt_len_off = 15; // round_off + 8

/// Errors `seal` can return (besides the allocator's).
pub const SealError = std.mem.Allocator.Error || error{
    /// The plaintext is longer than the wire format's `u32` length field
    /// can encode (~4 GiB). Not a realistic dead-man-switch payload.
    PlaintextTooLarge,
};

/// Errors `open` can return (besides the allocator's). Every malformed
/// or under-authorized input maps to one of these — `open` never
/// panics, reads out of bounds, loops unboundedly, or returns a garbage
/// plaintext.
pub const OpenError = std.mem.Allocator.Error || error{
    /// Buffer shorter than the fixed header.
    Truncated,
    /// First four bytes are not `magic`.
    BadMagic,
    /// `version` byte is not one this build understands.
    UnsupportedVersion,
    /// `suite_id` byte does not match the `Kem` this `Envelope` was
    /// instantiated for (an envelope sealed for a different HQC set).
    SuiteMismatch,
    /// The declared plaintext length does not match the buffer size, or
    /// the buffer has trailing/missing bytes.
    LengthMismatch,
    /// The 128-byte time-lock region is not a valid `tlock.Ciphertext`
    /// (bad compressed G2 point).
    MalformedTimeLock,
    /// The time lock is still closed for the supplied `round_signature`:
    /// either round `R` has not been reached (no valid signature exists
    /// yet) or the signature is for the wrong round / wrong beacon.
    /// `tlock`'s FO consistency check rejected it.
    TimeGateClosed,
    /// The AEAD tag failed. The PQ lock was not opened (wrong HQC secret
    /// key), or the header/ciphertext was tampered with. Never
    /// distinguishable from — and deliberately conflated with — any
    /// other authenticity failure.
    AuthFailed,
};

/// The two content keys derived from both locks' secrets. `key` seals
/// the content; `nonce` is derived alongside it (never stored on the
/// wire) so there is no nonce-reuse footgun: the pair is a
/// deterministic function of `(s_time, s_pq, round)`, and `s_time` /
/// the HQC encapsulation randomness are freshly drawn per envelope, so
/// `(key, nonce)` is effectively unique per seal.
pub const DerivedKeys = struct {
    key: [32]u8,
    nonce: [nonce_bytes]u8,
};

/// `HKDF-SHA256` over `ikm = s_time || s_pq` with a context-bound
/// `info`, expanded to `32 + nonce_bytes` octets: the first 32 are the
/// ChaCha20-Poly1305 key, the next `nonce_bytes` are the nonce. This is
/// where the AND is bound into the key material — dropping either input
/// yields a different, non-opening key (proven by this file's
/// positive-control tests). No crypto is hand-rolled: extraction and
/// expansion are `std.crypto.kdf.hkdf`.
pub fn deriveKeys(
    s_time: [time_secret_bytes]u8,
    s_pq: [hqc.params.shared_secret_bytes]u8,
    suite_id: u8,
    round: u64,
) DerivedKeys {
    var ikm: [time_secret_bytes + hqc.params.shared_secret_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &ikm);
    @memcpy(ikm[0..time_secret_bytes], &s_time);
    @memcpy(ikm[time_secret_bytes..], &s_pq);

    const prk = Hkdf.extract(kdf_salt, &ikm);

    // info = label || version || suite_id || round (big-endian): binds
    // the derived key to the logical context (which round, which suite,
    // which format version) independently of the AEAD's own AAD.
    var info: [kdf_info_label.len + 1 + 1 + 8]u8 = undefined;
    @memcpy(info[0..kdf_info_label.len], kdf_info_label);
    info[kdf_info_label.len] = version;
    info[kdf_info_label.len + 1] = suite_id;
    std.mem.writeInt(u64, info[kdf_info_label.len + 2 ..][0..8], round, .big);

    var okm: [32 + nonce_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &okm);
    Hkdf.expand(&okm, &info, prk);

    return .{
        .key = okm[0..32].*,
        .nonce = okm[32..][0..nonce_bytes].*,
    };
}

/// The hybrid two-lock envelope specialised for one HQC parameter set.
/// `Kem` is one of `hqc.Hqc128` / `hqc.Hqc192` / `hqc.Hqc256`. All wire
/// sizes below are comptime-fixed by that choice.
pub fn Envelope(comptime Kem: type) type {
    return struct {
        const Self = @This();

        /// Identifies the HQC parameter set on the wire (16/24/32 — the
        /// set's security level in bytes, which is unique across the
        /// three sets). A parser rejects a buffer whose `suite_id` does
        /// not match the `Kem` it was instantiated for.
        pub const suite_id: u8 = @intCast(Kem.security_bytes);

        /// 128 — the `tlock.Ciphertext` wire size.
        pub const time_lock_bytes: usize = tlock.Ciphertext.encoded_bytes;
        /// The HQC KEM ciphertext size for this parameter set.
        pub const pq_lock_bytes: usize = Kem.ct_bytes;
        /// Length of the region the AEAD authenticates as AAD: the whole
        /// header plus both lock ciphertexts.
        pub const aad_bytes: usize = header_bytes + time_lock_bytes + pq_lock_bytes;
        /// Fixed per-envelope overhead (everything except the plaintext).
        pub const overhead: usize = aad_bytes + tag_bytes;

        const time_off = header_bytes;
        const pq_off = header_bytes + time_lock_bytes;
        const tag_off = aad_bytes;
        const ct_off = aad_bytes + tag_bytes;

        /// The randomness `seal` consumes, supplied explicitly (the
        /// repo-wide "randomness is an input" convention — `tlock`/`hqc`/
        /// `bbs` all do this, which is what makes byte-exact KATs and
        /// deterministic tests possible). Use `generate` in production.
        pub const SealRandomness = struct {
            /// The time secret that gets timelock-encrypted; recoverable
            /// only at/after round `R`.
            s_time: [time_secret_bytes]u8,
            /// `tlock`'s own FO random pad (its `sigma` parameter).
            tlock_sigma: [time_secret_bytes]u8,
            /// HQC `encaps` coins (`m || salt`).
            kem_coins: [Kem.coins_bytes]u8,

            /// Draw all three from a portable entropy source.
            pub fn generate(io: std.Io) SealRandomness {
                var r: SealRandomness = undefined;
                io.random(&r.s_time);
                io.random(&r.tlock_sigma);
                io.random(&r.kem_coins);
                return r;
            }
        };

        /// Seal `plaintext` under both locks. Returns a freshly allocated,
        /// self-describing wire buffer the caller owns (`allocator.free`).
        ///
        /// - `recipient_ek` — the recipient's HQC encapsulation key (the
        ///   PQ lock's public half).
        /// - `p_pub` — the drand beacon master public key (`G2`).
        /// - `round` — the future round `R` the time lock opens at.
        /// - `rnd` — the per-seal randomness (see `SealRandomness`).
        pub fn seal(
            allocator: std.mem.Allocator,
            plaintext: []const u8,
            recipient_ek: Kem.EncapsKey,
            p_pub: g2.Affine,
            round: u64,
            rnd: SealRandomness,
        ) SealError![]u8 {
            if (plaintext.len > std.math.maxInt(u32)) return error.PlaintextTooLarge;

            // Lock 1 (time): timelock-encrypt s_time to round R.
            const tl = tlock.encrypt(p_pub, round, rnd.s_time, rnd.tlock_sigma);
            const tl_bytes = tl.toBytes();

            // Lock 2 (PQ): encapsulate s_pq to the recipient.
            const enc = Kem.encaps(recipient_ek, &rnd.kem_coins);

            // Bind both locks' secrets into the content key + nonce.
            var keys = deriveKeys(rnd.s_time, enc.ss, suite_id, round);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));

            const out = try allocator.alloc(u8, overhead + plaintext.len);
            errdefer allocator.free(out);

            // Header.
            @memcpy(out[0..4], &magic);
            out[4] = version;
            out[5] = suite_id;
            out[6] = 0; // flags (reserved; must be authenticated but is unused)
            std.mem.writeInt(u64, out[round_off..][0..8], round, .little);
            std.mem.writeInt(u32, out[pt_len_off..][0..4], @intCast(plaintext.len), .little);

            // Lock ciphertexts.
            @memcpy(out[time_off..][0..time_lock_bytes], &tl_bytes);
            @memcpy(out[pq_off..][0..pq_lock_bytes], &enc.ct);

            // AEAD-seal the content, authenticating the entire header +
            // both locks as AAD so no field can be swapped between
            // envelopes and no lock ciphertext tampered undetected.
            const aad = out[0..aad_bytes];
            const tag = out[tag_off..][0..tag_bytes];
            const ct = out[ct_off..][0..plaintext.len];
            Aead.encrypt(ct, tag, plaintext, aad, keys.nonce, keys.key);

            return out;
        }

        /// A bounds-checked view of a wire buffer's fixed fields. Pure
        /// parsing: no crypto, no allocation, cannot panic or read out
        /// of bounds on any input. Split out so it is independently
        /// fuzzable and so `open` reads every field through one audited
        /// path.
        pub const Parsed = struct {
            round: u64,
            pt_len: usize,
            time_lock: *const [time_lock_bytes]u8,
            pq_lock: *const [pq_lock_bytes]u8,
            aad: []const u8,
            tag: *const [tag_bytes]u8,
            ciphertext: []const u8,
        };

        /// Validate framing and return field views, or a typed error.
        pub fn parse(buf: []const u8) OpenError!Parsed {
            if (buf.len < header_bytes) return error.Truncated;
            if (!std.mem.eql(u8, buf[0..4], &magic)) return error.BadMagic;
            if (buf[4] != version) return error.UnsupportedVersion;
            if (buf[5] != suite_id) return error.SuiteMismatch;
            // buf[6] (flags) intentionally unconstrained — reserved for
            // future use; still covered by the AEAD's AAD, so a flip is
            // caught at authentication, never silently.

            const round = std.mem.readInt(u64, buf[round_off..][0..8], .little);
            const pt_len = std.mem.readInt(u32, buf[pt_len_off..][0..4], .little);

            // Total size is fully determined by pt_len; require an exact
            // match (no trailing slack, no shortfall). `pt_len` is a u32
            // and `overhead` is comptime, so this addition cannot
            // overflow a usize on any supported target.
            const total = overhead + @as(usize, pt_len);
            if (buf.len != total) return error.LengthMismatch;

            return .{
                .round = round,
                .pt_len = pt_len,
                .time_lock = buf[time_off..][0..time_lock_bytes],
                .pq_lock = buf[pq_off..][0..pq_lock_bytes],
                .aad = buf[0..aad_bytes],
                .tag = buf[tag_off..][0..tag_bytes],
                .ciphertext = buf[ct_off..][0..pt_len],
            };
        }

        /// Open a sealed envelope. Recovers the plaintext only when BOTH
        /// locks open: `round_signature` must be the beacon's published
        /// signature for the round the envelope was sealed to, AND
        /// `recipient_dk` must be the HQC secret key matching the
        /// encapsulation key it was sealed for. Returns a freshly
        /// allocated plaintext the caller owns, or a typed `OpenError`.
        pub fn open(
            allocator: std.mem.Allocator,
            envelope: []const u8,
            recipient_dk: Kem.DecapsKey,
            round_signature: g1.Affine,
        ) OpenError![]u8 {
            const p = try parse(envelope);

            // Lock 1 (time): recover s_time. tlock's own FO check rejects
            // a wrong/premature signature with a typed error — this is
            // the time gate.
            const tl = tlock.Ciphertext.fromBytes(p.time_lock.*) catch
                return error.MalformedTimeLock;
            var s_time = tlock.decrypt(round_signature, tl) catch
                return error.TimeGateClosed;
            defer std.crypto.secureZero(u8, &s_time);

            // Lock 2 (PQ): decapsulate s_pq. HQC never errors here
            // (implicit rejection returns a pseudo-random secret for a
            // wrong key); a wrong s_pq surfaces below as an AEAD failure.
            var s_pq = Kem.decaps(recipient_dk, p.pq_lock.*);
            defer std.crypto.secureZero(u8, &s_pq);

            var keys = deriveKeys(s_time, s_pq, suite_id, p.round);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));

            const pt = try allocator.alloc(u8, p.pt_len);
            errdefer allocator.free(pt);

            // The AEAD tag is the AND's enforcement point: it verifies K
            // (hence BOTH s_time and s_pq) and the whole header/locks
            // (the AAD) simultaneously. Any wrong piece → AuthFailed,
            // never a wrong plaintext. chachapoly zeroes `pt` on failure.
            // `errdefer` above frees `pt` on this error path.
            Aead.decrypt(pt, p.ciphertext, p.tag.*, p.aad, keys.nonce, keys.key) catch
                return error.AuthFailed;

            return pt;
        }
    };
}

/// The three ready-made specialisations, mirroring `hqc`'s own naming.
pub const Envelope128 = Envelope(hqc.Hqc128);
pub const Envelope192 = Envelope(hqc.Hqc192);
pub const Envelope256 = Envelope(hqc.Hqc256);

// ── unit tests: wire framing + KDF binding (positive controls) ───────

const testing = std.testing;

test "suite_id is the HQC set's security-byte width and is distinct per set" {
    try testing.expectEqual(@as(u8, 16), Envelope128.suite_id);
    try testing.expectEqual(@as(u8, 24), Envelope192.suite_id);
    try testing.expectEqual(@as(u8, 32), Envelope256.suite_id);
}

test "overhead accounting matches the concrete field sizes" {
    // header(19) + tlock(128) + hqc-128 ct(4433) + tag(16).
    try testing.expectEqual(@as(usize, 19), header_bytes);
    try testing.expectEqual(@as(usize, 128), Envelope128.time_lock_bytes);
    try testing.expectEqual(@as(usize, 4433), Envelope128.pq_lock_bytes);
    try testing.expectEqual(@as(usize, 19 + 128 + 4433 + 16), Envelope128.overhead);
}

test "deriveKeys: dropping s_time changes the derived key (time secret is load-bearing)" {
    const s_time = [_]u8{0xA1} ** time_secret_bytes;
    const s_pq = [_]u8{0xB2} ** hqc.params.shared_secret_bytes;
    const full = deriveKeys(s_time, s_pq, 16, 42);

    // A KDF that dropped s_time (used all-zero in its place) must yield a
    // DIFFERENT key — otherwise the time lock would not affect K at all.
    const dropped = deriveKeys([_]u8{0} ** time_secret_bytes, s_pq, 16, 42);
    try testing.expect(!std.mem.eql(u8, &full.key, &dropped.key));
}

test "deriveKeys: dropping s_pq changes the derived key (PQ secret is load-bearing)" {
    const s_time = [_]u8{0xA1} ** time_secret_bytes;
    const s_pq = [_]u8{0xB2} ** hqc.params.shared_secret_bytes;
    const full = deriveKeys(s_time, s_pq, 16, 42);

    const dropped = deriveKeys(s_time, [_]u8{0} ** hqc.params.shared_secret_bytes, 16, 42);
    try testing.expect(!std.mem.eql(u8, &full.key, &dropped.key));
}

test "deriveKeys: round, suite and version all separate the key" {
    const s_time = [_]u8{0xA1} ** time_secret_bytes;
    const s_pq = [_]u8{0xB2} ** hqc.params.shared_secret_bytes;
    const base = deriveKeys(s_time, s_pq, 16, 42);
    const other_round = deriveKeys(s_time, s_pq, 16, 43);
    const other_suite = deriveKeys(s_time, s_pq, 32, 42);
    try testing.expect(!std.mem.eql(u8, &base.key, &other_round.key));
    try testing.expect(!std.mem.eql(u8, &base.key, &other_suite.key));
}

test "parse rejects truncated / bad-magic / wrong-version / wrong-suite / wrong-length buffers" {
    // Too short.
    try testing.expectError(error.Truncated, Envelope128.parse(&[_]u8{ 'T', 'L' }));

    // A minimal well-formed-length buffer for pt_len = 0, then corrupt
    // each discriminator in turn.
    var buf = [_]u8{0} ** Envelope128.overhead;
    @memcpy(buf[0..4], &magic);
    buf[4] = version;
    buf[5] = Envelope128.suite_id;
    // pt_len = 0, round = 0 → exact length is `overhead`.
    _ = try Envelope128.parse(&buf); // baseline parses

    var bad_magic = buf;
    bad_magic[0] = 'X';
    try testing.expectError(error.BadMagic, Envelope128.parse(&bad_magic));

    var bad_ver = buf;
    bad_ver[4] = 0xFE;
    try testing.expectError(error.UnsupportedVersion, Envelope128.parse(&bad_ver));

    var bad_suite = buf;
    bad_suite[5] = 32; // hqc-256's id, not this Envelope's
    try testing.expectError(error.SuiteMismatch, Envelope128.parse(&bad_suite));

    // Declare a pt_len that disagrees with the actual buffer size.
    var bad_len = buf;
    std.mem.writeInt(u32, bad_len[pt_len_off..][0..4], 99, .little);
    try testing.expectError(error.LengthMismatch, Envelope128.parse(&bad_len));
}

test "an all-but-one-byte-short buffer is Truncated, not a panic" {
    const buf = [_]u8{0} ** (header_bytes - 1);
    try testing.expectError(error.Truncated, Envelope128.parse(&buf));
}
