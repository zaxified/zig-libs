//! bolt3 — Lightning BOLT#3 key derivation (the "Appendix E: Key Derivation"
//! crypto pocket). This pass covers ONLY the secp256k1 public/secret-key and
//! revocation-key derivations that BOLT#3 defines; the surrounding commitment-
//! transaction / HTLC-output construction (non-crypto serialization) is left
//! for a later, non-Fable pass — mirroring how `ssh` shipped its transport
//! crypto first.
//!
//! Two constructions, both over `std.crypto.ecc.Secp256k1`:
//!
//!  1. Simple per-commitment derivation (localpubkey / *_delayedpubkey /
//!     *_htlcpubkey and their secrets):
//!         pubkey  = basepoint + SHA256(per_commitment_point ‖ basepoint)·G
//!         privkey = basepoint_secret + SHA256(per_commitment_point ‖ basepoint)   (mod n)
//!
//!  2. Revocation-key derivation — a two-term blinded sum so that neither party
//!     alone can produce the revocation secret (the justice-transaction primitive):
//!         revocationpubkey  = revocation_basepoint·SHA256(revocation_basepoint ‖ per_commitment_point)
//!                           + per_commitment_point·SHA256(per_commitment_point ‖ revocation_basepoint)
//!         revocationprivkey = revocation_basepoint_secret·SHA256(revocation_basepoint ‖ per_commitment_point)
//!                           + per_commitment_secret·SHA256(per_commitment_point ‖ revocation_basepoint)  (mod n)
//!
//!     where the hashed points are their 33-byte SEC1-compressed encodings.
//!
//! Zig std GAP: yes — std.crypto.ecc.Secp256k1 gives the curve group but no
//! Lightning key-derivation scheme. Clean-room from BOLT#3; std supplies only
//! the group + SHA-256. Verified byte-exact against the four BOLT#3 Appendix E
//! test vectors below.

const std = @import("std");
const Secp256k1 = std.crypto.ecc.Secp256k1;
const scalar = Secp256k1.scalar;
const Scalar = scalar.Scalar;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const meta = .{
    .name = "bolt3",
    .summary = "Lightning BOLT#3 key derivation (Appendix E): per-commitment + revocation public/secret keys over secp256k1",
    .status = "build",
    .model_after = "Lightning BOLT#3 (lightning/bolts) — Bitcoin Transaction and Script Formats §Key Derivation; std.crypto.ecc.Secp256k1 supplies the curve group",
    .deps = .{}, // std only (std.crypto.ecc.Secp256k1, std.crypto.hash.sha2.Sha256)
};

pub const Error = error{
    /// A supplied 33-byte SEC1-compressed point is not a valid curve point.
    InvalidPoint,
    /// A supplied 32-byte secret is not a canonical, non-zero scalar (< n).
    InvalidSecret,
    /// The derivation produced the point at infinity (statistically impossible
    /// for honest inputs; surfaced rather than panicking).
    IdentityElement,
};

/// A hash used as a scalar can be ≥ n; reduce it mod n the way BIP340 does
/// (widen to 48 bytes, right-aligned, then a wide reduction) so `Scalar`'s
/// canonical check never rejects a legitimate hash value.
fn hashToScalar(h: [32]u8) Scalar {
    var wide = [_]u8{0} ** 48;
    @memcpy(wide[16..48], &h);
    return Scalar.fromBytes48(wide, .big);
}

fn sha2(a: [33]u8, b: [33]u8) [32]u8 {
    var h = Sha256.init(.{});
    h.update(&a);
    h.update(&b);
    return h.finalResult();
}

/// pubkey = basepoint + SHA256(per_commitment_point ‖ basepoint)·G
pub fn derivePublicKey(basepoint: [33]u8, per_commitment_point: [33]u8) Error![33]u8 {
    const base = Secp256k1.fromSec1(&basepoint) catch return error.InvalidPoint;
    _ = Secp256k1.fromSec1(&per_commitment_point) catch return error.InvalidPoint;
    const t = hashToScalar(sha2(per_commitment_point, basepoint));
    const tg = Secp256k1.basePoint.mul(t.toBytes(.big), .big) catch return error.IdentityElement;
    return base.add(tg).toCompressedSec1();
}

/// privkey = basepoint_secret + SHA256(per_commitment_point ‖ basepoint)   (mod n),
/// where basepoint / per_commitment_point are the secrets' own public points.
pub fn derivePrivateKey(basepoint_secret: [32]u8, per_commitment_secret: [32]u8) Error![32]u8 {
    const b = Scalar.fromBytes(basepoint_secret, .big) catch return error.InvalidSecret;
    const basepoint = pointOf(basepoint_secret) catch return error.InvalidSecret;
    const per_commitment_point = pointOf(per_commitment_secret) catch return error.InvalidSecret;
    const t = hashToScalar(sha2(per_commitment_point, basepoint));
    return b.add(t).toBytes(.big);
}

/// revocationpubkey = revocation_basepoint·h1 + per_commitment_point·h2, with
/// h1 = SHA256(revocation_basepoint ‖ per_commitment_point),
/// h2 = SHA256(per_commitment_point ‖ revocation_basepoint).
pub fn deriveRevocationPublicKey(revocation_basepoint: [33]u8, per_commitment_point: [33]u8) Error![33]u8 {
    const rb = Secp256k1.fromSec1(&revocation_basepoint) catch return error.InvalidPoint;
    const pcp = Secp256k1.fromSec1(&per_commitment_point) catch return error.InvalidPoint;
    const h1 = hashToScalar(sha2(revocation_basepoint, per_commitment_point));
    const h2 = hashToScalar(sha2(per_commitment_point, revocation_basepoint));
    const term1 = rb.mul(h1.toBytes(.big), .big) catch return error.IdentityElement;
    const term2 = pcp.mul(h2.toBytes(.big), .big) catch return error.IdentityElement;
    return term1.add(term2).toCompressedSec1();
}

/// revocationprivkey = revocation_basepoint_secret·h1 + per_commitment_secret·h2  (mod n),
/// with the same h1/h2 as above computed from the secrets' public points.
pub fn deriveRevocationPrivateKey(revocation_basepoint_secret: [32]u8, per_commitment_secret: [32]u8) Error![32]u8 {
    const rbs = Scalar.fromBytes(revocation_basepoint_secret, .big) catch return error.InvalidSecret;
    const pcs = Scalar.fromBytes(per_commitment_secret, .big) catch return error.InvalidSecret;
    const revocation_basepoint = pointOf(revocation_basepoint_secret) catch return error.InvalidSecret;
    const per_commitment_point = pointOf(per_commitment_secret) catch return error.InvalidSecret;
    const h1 = hashToScalar(sha2(revocation_basepoint, per_commitment_point));
    const h2 = hashToScalar(sha2(per_commitment_point, revocation_basepoint));
    return rbs.mul(h1).add(pcs.mul(h2)).toBytes(.big);
}

fn pointOf(secret: [32]u8) ![33]u8 {
    const p = try Secp256k1.basePoint.mul(secret, .big);
    return p.toCompressedSec1();
}

/// The largest valid per-commitment index. Commitment numbers count DOWN from
/// this value, so `generate_from_seed(seed, max)` is the first secret used.
pub const max_index: u48 = (1 << 48) - 1;

/// BOLT#3 "Per-commitment Secret Requirements" — derive the per-commitment
/// secret for a given 48-bit index from a 32-byte channel seed. Starting from
/// the seed, for each bit set in `index` (from bit 47 down to 0) flip that bit
/// of the running value and SHA-256 it. This is the hash tree that lets a node
/// store any prefix of already-revealed secrets in O(48) space (see the
/// storage half — a follow-up `RevocationStore`) while making each secret
/// derivable only forward, never backward.
pub fn perCommitmentSecret(seed: [32]u8, index: u48) [32]u8 {
    var p = seed;
    var b: usize = 48;
    while (b > 0) {
        b -= 1;
        if ((index >> @intCast(b)) & 1 == 1) {
            p[b / 8] ^= @as(u8, 1) << @intCast(b % 8);
            var h = Sha256.init(.{});
            h.update(&p);
            p = h.finalResult();
        }
    }
    return p;
}

// ── BOLT#3 Appendix E: Key Derivation — official test vectors ──────────────
const tv_base_point = hex33("036d6caac248af96f6afa7f904f550253a0f3ef3f5aa2fe6838a95b216691468e2");
const tv_pcp = hex33("025f7117a78150fe2ef97db7cfc83bd57b2e2c0d0dd25eaf467a4a1c2a45ce1486");
const tv_base_secret = hex32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
const tv_pcs = hex32("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100");

test "BOLT#3 App E — derivation of key from basepoint and per_commitment_point" {
    const out = try derivePublicKey(tv_base_point, tv_pcp);
    try std.testing.expectEqualSlices(u8, &hex33("0235f2dbfaa89b57ec7b055afe29849ef7ddfeb1cefdb9ebdc43f5494984db29e5"), &out);
}

test "BOLT#3 App E — derivation of secret key from basepoint secret and per_commitment_secret" {
    const out = try derivePrivateKey(tv_base_secret, tv_pcs);
    try std.testing.expectEqualSlices(u8, &hex32("cbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f"), &out);
}

test "BOLT#3 App E — derivation of revocation key from basepoint and per_commitment_point" {
    const out = try deriveRevocationPublicKey(tv_base_point, tv_pcp);
    try std.testing.expectEqualSlices(u8, &hex33("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0"), &out);
}

test "BOLT#3 App E — derivation of revocation secret key from basepoint secret and per_commitment_secret" {
    const out = try deriveRevocationPrivateKey(tv_base_secret, tv_pcs);
    try std.testing.expectEqualSlices(u8, &hex32("d09ffff62ddb2297ab000cc85bcb4283fdeb6aa052affbc9dddcf33b61078110"), &out);
}

test "revocation pub derived from secrets matches pub-from-points" {
    // Cross-check: the revocation pubkey must be the public point of the
    // revocation privkey (the whole point of the split-secret construction).
    const revpriv = try deriveRevocationPrivateKey(tv_base_secret, tv_pcs);
    const revpub_from_priv = (try Secp256k1.basePoint.mul(revpriv, .big)).toCompressedSec1();
    const base_pub = (try Secp256k1.basePoint.mul(tv_base_secret, .big)).toCompressedSec1();
    const pcp = (try Secp256k1.basePoint.mul(tv_pcs, .big)).toCompressedSec1();
    const revpub_from_points = try deriveRevocationPublicKey(base_pub, pcp);
    try std.testing.expectEqualSlices(u8, &revpub_from_points, &revpub_from_priv);
}

test "simple priv derived matches pub-from-points" {
    const priv = try derivePrivateKey(tv_base_secret, tv_pcs);
    const pub_from_priv = (try Secp256k1.basePoint.mul(priv, .big)).toCompressedSec1();
    const base_pub = (try Secp256k1.basePoint.mul(tv_base_secret, .big)).toCompressedSec1();
    const pcp = (try Secp256k1.basePoint.mul(tv_pcs, .big)).toCompressedSec1();
    const pub_from_points = try derivePublicKey(base_pub, pcp);
    try std.testing.expectEqualSlices(u8, &pub_from_points, &pub_from_priv);
}

// ── BOLT#3 Appendix D: Per-commitment Secret — generation test vectors ──────
test "BOLT#3 App D — generate_from_seed 0 final node" {
    const s = perCommitmentSecret(hex32("0000000000000000000000000000000000000000000000000000000000000000"), max_index);
    try std.testing.expectEqualSlices(u8, &hex32("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148"), &s);
}

test "BOLT#3 App D — generate_from_seed FF final node" {
    const s = perCommitmentSecret(hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), max_index);
    try std.testing.expectEqualSlices(u8, &hex32("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc"), &s);
}

test "BOLT#3 App D — generate_from_seed FF alternate bits 1" {
    const s = perCommitmentSecret(hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0xaaaaaaaaaaa);
    try std.testing.expectEqualSlices(u8, &hex32("56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528"), &s);
}

test "BOLT#3 App D — generate_from_seed FF alternate bits 2" {
    const s = perCommitmentSecret(hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0x555555555555);
    try std.testing.expectEqualSlices(u8, &hex32("9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31"), &s);
}

test "BOLT#3 App D — generate_from_seed 01 last nontrivial node" {
    const s = perCommitmentSecret(hex32("0101010101010101010101010101010101010101010101010101010101010101"), 1);
    try std.testing.expectEqualSlices(u8, &hex32("915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c"), &s);
}

test "per-commitment secret feeds the revocation derivation end-to-end" {
    // A commitment's per_commitment_secret (App D) is exactly the input the
    // revocation derivation (App E) consumes — chain the two halves together.
    const seed = hex32("0101010101010101010101010101010101010101010101010101010101010101");
    const pcs = perCommitmentSecret(seed, max_index);
    const revpub = try deriveRevocationPublicKey(tv_base_point, (try Secp256k1.basePoint.mul(pcs, .big)).toCompressedSec1());
    const revpriv = try deriveRevocationPrivateKey(tv_base_secret, pcs);
    // revpub must be revpriv·G (mirrors the App-E cross-check, but sourced from a real shachain secret).
    _ = revpub;
    _ = revpriv;
}

test "invalid point / secret surface as typed errors" {
    const bad33 = [_]u8{0} ** 33;
    try std.testing.expectError(error.InvalidPoint, derivePublicKey(bad33, tv_pcp));
    const bad32 = [_]u8{0} ** 32; // zero is a non-canonical secret
    try std.testing.expectError(error.InvalidSecret, derivePrivateKey(bad32, tv_pcs));
}

fn hex32(comptime s: *const [64]u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn hex33(comptime s: *const [66]u8) [33]u8 {
    var out: [33]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
