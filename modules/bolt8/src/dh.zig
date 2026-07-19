// SPDX-License-Identifier: MIT

//! secp256k1 Diffie-Hellman adapter for BOLT#8's
//! `Noise_XK_secp256k1_ChaChaPoly_SHA256` instantiation. BOLT#8
//! ("Handshake State Initialization", the `ECDH(k, rk)` function
//! definition) fixes the DH primitive as:
//!
//!     ECDH(k, rk) = SHA256(compressed-SEC1(k * rk))
//!
//! i.e. an ORDINARY secp256k1 scalar multiplication of the local private
//! scalar `k` against the remote point `rk`, serialized in 33-byte
//! compressed SEC1 form, then hashed with SHA-256 to fold the output down
//! to a 32-byte symmetric-key-shaped value.
//!
//! This is the one deliberate width split BOLT#8 introduces relative to
//! "vanilla" Noise (spec rev 34 assumes `DHLEN` == pubkey length == DH
//! output length, e.g. 32 for X25519 — see `noise/src/state.zig`'s
//! `Suite.DHLEN = DH.public_length`): here PUBLIC KEYS are 33 bytes
//! (compressed secp256k1, `public_length` below) but the DH OUTPUT fed to
//! `SymmetricState.mixKey` is 32 bytes (a SHA-256 digest, `dh()`'s return
//! type). This is a non-issue for `noise.SymmetricState` (which treats DH
//! output as an opaque `[]const u8`, never a `[DHLEN]u8`-shaped value) but
//! DOES rule out driving this handshake through `noise.HandshakeState` —
//! see `../SPEC.md`'s "Noise-reuse decision" for the exact mechanism
//! (`state.zig`'s `dhName` only recognizes `std.crypto.dh.X25519`).
//!
//! Modeled after this repo's own `sphinx` module's `fromSec1 -> mul ->
//! toCompressedSec1 -> Sha256.hash` chain (BOLT#4 defines an IDENTICAL
//! `ECDH` primitive) and `bip340`'s secp256k1 key-pair conventions — both
//! already verified byte-exact against `std.crypto.ecc.Secp256k1` elsewhere
//! in this repo. This file is REAL, not a Fable stub: plain elliptic-curve
//! arithmetic + SHA-256, no protocol-level design decision is left open
//! here (unlike `handshake.zig`'s act-driver, which decides WHEN each DH
//! happens and what gets mixed with its output).

const std = @import("std");
const Secp256k1 = @import("k256").Secp256k1;
const Sha256 = std.crypto.hash.sha2.Sha256;

// ── noise.Suite(DH, ...) adapter surface ─────────────────────────────────
//
// `noise.Suite(DH, Cipher, Hash)` (state.zig) reads exactly two decls off
// `DH` eagerly at Suite-instantiation time: `DH.public_length` (->
// `Suite.DHLEN`) and `DH.KeyPair` (-> `Suite.KeyPair`, a plain type alias).
// Both are supplied below purely so `noise.Suite(@This-file, ...)`
// type-checks and its DH-agnostic `SymmetricState`/`CipherState` become
// usable (see `handshake.zig`). `DH.scalarmult` is only ever CALLED from
// inside `HandshakeState.mixDh` — a function this module never reaches
// (see SPEC.md) — so it is supplied here purely for API-shape parity with
// `std.crypto.dh.X25519`, never actually invoked by this module; `dh()`
// below is what `handshake.zig`'s act driver calls instead.

/// BOLT#8 public keys are 33-byte SEC1-compressed secp256k1 points.
pub const public_length = 33;
/// A private scalar is a 32-byte value (rejection-sampled into `[1, n-1]`
/// by `KeyPair.generateDeterministic`).
pub const seed_length = 32;

pub const SecretKeyError = error{InvalidSecretKey};

/// A BOLT#8 secp256k1 keypair: a 32-byte private scalar plus its 33-byte
/// SEC1-compressed public point. Field names (`secret_key`/`public_key`)
/// match what `noise`'s generic `Suite(DH,...).KeyPair = DH.KeyPair` alias
/// expects, even though this module never drives `noise.HandshakeState`
/// (see module doc comment) — kept for API-shape parity and so a future
/// wider-Noise consumer of this adapter isn't surprised by different names.
pub const KeyPair = struct {
    secret_key: [32]u8,
    public_key: [33]u8,

    /// Derive the public key from an already-chosen 32-byte scalar —
    /// BOLT#8's Appendix A test-vector convention (fixed `e.priv`/`ls.priv`
    /// values rather than fresh randomness; the spec's own "note: this is
    /// a violation of the spec, which requires randomness" KAT hook).
    /// Rejects `0` and out-of-range scalars, mirroring `bip340.SecretKey.
    /// fromBytes`.
    pub fn generateDeterministic(seed: [32]u8) SecretKeyError!KeyPair {
        const d = Secp256k1.scalar.Scalar.fromBytes(seed, .big) catch
            return error.InvalidSecretKey;
        if (d.isZero()) return error.InvalidSecretKey;
        const p = Secp256k1.combMulBase(seed, .big) catch return error.InvalidSecretKey;
        return .{ .secret_key = seed, .public_key = p.toCompressedSec1() };
    }

    /// Draw a fresh keypair from a CSPRNG (the production path — KATs use
    /// `generateDeterministic` with the spec's fixed scalars instead).
    /// Rejection-samples on the (probability ~2^-128) chance the drawn
    /// scalar is `0` or `>= n`.
    pub fn generate(random: std.Random) KeyPair {
        while (true) {
            var seed: [32]u8 = undefined;
            random.bytes(&seed);
            return generateDeterministic(seed) catch continue;
        }
    }
};

pub const DhError = error{
    /// The remote point failed to parse as a valid on-curve SEC1 point.
    /// BOLT#8's own negative test vectors (`ACT1_BAD_PUBKEY`/
    /// `ACT2_BAD_PUBKEY`/`ACT3_BAD_PUBKEY`) feed an uncompressed-form
    /// (`0x04`) prefix into a still-33-byte slot, which `Secp256k1.fromSec1`
    /// rejects as `error.InvalidEncoding` before any scalar multiply runs
    /// — see this file's own tests below.
    InvalidPublicKey,
    /// The scalar multiplication produced the point at infinity — a
    /// degenerate case with negligible honest-input probability, kept as a
    /// real checked failure (mirrors `sphinx.core`'s `SharedSecretError`
    /// and `bip340`'s handling of `Secp256k1.mul`'s `IdentityElementError`).
    IdentityElement,
};

/// BOLT#8's `ECDH(k, rk)`: `SHA256(compressed(k * rk))`. `remote_pub` is
/// the 33-byte SEC1-compressed point as received on the wire (BOLT#8's
/// `e.pub`/`s.pub` are always serialized compressed). Returns the 32-byte
/// digest fed into `SymmetricState.mixKey` at each act (the `es`/`ee`/`se`
/// DH tokens in the spec's Noise_XK notation) — this is the one place
/// BOLT#8's public keys (33 bytes) and its DH output (32 bytes) part ways;
/// see the module doc comment.
pub fn dh(secret_key: [32]u8, remote_pub: [33]u8) DhError![32]u8 {
    const point = Secp256k1.fromSec1(&remote_pub) catch return error.InvalidPublicKey;
    const shared = point.mul(secret_key, .big) catch return error.IdentityElement;
    const compressed = shared.toCompressedSec1();
    var out: [32]u8 = undefined;
    Sha256.hash(&compressed, &out, .{});
    return out;
}

/// API-shape alias for `noise.Suite(DH,...)`'s `DH.scalarmult` — never
/// actually called by this module (see the adapter-surface doc comment
/// above); `dh()` is the entry point `handshake.zig` uses.
pub fn scalarmult(secret_key: [32]u8, remote_pub: [33]u8) DhError![32]u8 {
    return dh(secret_key, remote_pub);
}

// ── tests: real KATs from BOLT#8 Appendix A "Transport Test Vectors" ────
//
// Source: lightning/bolts, `08-transport.md`, raw GitHub (see ../NOTICE).
// All hex constants live in `kat_vectors.zig` (single source of truth) —
// transcribed verbatim from the spec's "Initiator Tests" / "Responder
// Tests" sections (both the named `*.priv`/`*.pub` fields and the `#
// ss=...` comment lines, which publish the intermediate `ECDH()` output
// for each of the three acts).

const testing = std.testing;
const kv = @import("kat_vectors.zig");

test "KeyPair.generateDeterministic: BOLT#8 Appendix A fixed scalars derive their published pubkeys" {
    try testing.expectEqual((try KeyPair.generateDeterministic(kv.init_ls_priv.*)).public_key, kv.init_ls_pub.*);
    try testing.expectEqual((try KeyPair.generateDeterministic(kv.init_e_priv.*)).public_key, kv.init_e_pub.*);
    try testing.expectEqual((try KeyPair.generateDeterministic(kv.resp_ls_priv.*)).public_key, kv.resp_ls_pub.*);
    try testing.expectEqual((try KeyPair.generateDeterministic(kv.resp_e_priv.*)).public_key, kv.resp_e_pub.*);
}

test "dh: Act One es = ECDH(init.e, resp.ls) == ECDH(resp.ls, init.e) (published ss)" {
    try testing.expectEqual(kv.ss_act1_es.*, try dh(kv.init_e_priv.*, kv.resp_ls_pub.*));
    try testing.expectEqual(kv.ss_act1_es.*, try dh(kv.resp_ls_priv.*, kv.init_e_pub.*));
}

test "dh: Act Two ee = ECDH(resp.e, init.e) == ECDH(init.e, resp.e) (published ss)" {
    try testing.expectEqual(kv.ss_act2_ee.*, try dh(kv.resp_e_priv.*, kv.init_e_pub.*));
    try testing.expectEqual(kv.ss_act2_ee.*, try dh(kv.init_e_priv.*, kv.resp_e_pub.*));
}

test "dh: Act Three se = ECDH(init.ls, resp.e) == ECDH(resp.e, init.ls) (published ss)" {
    try testing.expectEqual(kv.ss_act3_se.*, try dh(kv.init_ls_priv.*, kv.resp_e_pub.*));
    try testing.expectEqual(kv.ss_act3_se.*, try dh(kv.resp_e_priv.*, kv.init_ls_pub.*));
}

test "dh: rejects a malformed (uncompressed-prefix-in-33-byte-slot) public key" {
    // BOLT#8 "transport-initiator act2 bad key serialization test": the
    // act2 e.pub byte is patched from 0x02 to 0x04 without adding the 32
    // extra bytes an uncompressed point would need — `fromSec1` must
    // reject this before any scalar multiply.
    try testing.expectError(error.InvalidPublicKey, dh(kv.init_e_priv.*, kv.bad_pubkey_serialization.*));
}

test "dh: rejects the act3-bad-rs-test's malformed recovered static key" {
    // BOLT#8 "transport-responder act3 bad rs test": the AEAD-decrypted
    // `rs` comes back with a 0x04 prefix (should be 0x02/0x03) — same
    // parse-level rejection as above, independent of the AEAD step that
    // (in the full handshake) would have recovered these bytes.
    try testing.expectError(error.InvalidPublicKey, dh(kv.resp_e_priv.*, kv.bad_recovered_static_key.*));
}

test "meta-shape: public_length/seed_length match BOLT#8's 33/32-byte split" {
    try testing.expectEqual(@as(usize, 33), public_length);
    try testing.expectEqual(@as(usize, 32), seed_length);
}

test "KeyPair.generate: rejects nothing observable, always yields a valid public key" {
    var prng = std.Random.DefaultPrng.init(0xb01783);
    const random = prng.random();
    const kp = KeyPair.generate(random);
    // Round-trips through the curve: re-deriving from the same secret
    // scalar must reproduce the exact same public key.
    const again = try KeyPair.generateDeterministic(kp.secret_key);
    try testing.expectEqual(kp.public_key, again.public_key);
}
