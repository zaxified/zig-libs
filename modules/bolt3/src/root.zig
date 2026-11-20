// SPDX-License-Identifier: MIT
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
const Secp256k1 = @import("k256").Secp256k1;
const scalar = Secp256k1.scalar;
const Scalar = scalar.Scalar;
const Sha256 = std.crypto.hash.sha2.Sha256;
const burn = @import("burn.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Lightning BOLT#3 key derivation — per-commitment blinded keys, split-secret revocation keys, shachain secret generation.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    // Had no `.targets`/`.platform` at all before this line -- pure
    // secp256k1 scalar/point arithmetic + SHA-256, no I/O, no syscalls, so
    // the collection's baseline is the only real claim (CONVENTIONS.md §4).
    .targets = .{.linux64},
    .platform = .any,
    .name = "bolt3",
    .summary = "Lightning BOLT#3 key derivation (Appendix E): per-commitment + revocation public/secret keys over secp256k1",
    .status = "build",
    .model_after = "Lightning BOLT#3 (lightning/bolts) — Bitcoin Transaction and Script Formats §Key Derivation; the k256 module supplies the curve group (byte-exact to std.crypto.ecc.Secp256k1)",
    .deps = .{"k256"}, // k256 supplies the curve group (byte-exact to std.crypto.ecc.Secp256k1); std.crypto.hash.sha2.Sha256
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
    var wide = @as([48]u8, @splat(0));
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
    const tg = Secp256k1.combMulBase(t.toBytes(.big), .big) catch return error.IdentityElement;
    return base.add(tg).toCompressedSec1();
}

/// privkey = basepoint_secret + SHA256(per_commitment_point ‖ basepoint)   (mod n),
/// where basepoint / per_commitment_point are the secrets' own public points.
/// The result goes into `out` (zeroed on error); runs under a dead-stack burn.
pub fn derivePrivateKey(out: *[32]u8, basepoint_secret: *const [32]u8, per_commitment_secret: *const [32]u8) Error!void {
    return burn.run(burn.ecc_burn, Error!void, derivePrivateKeyBody, .{ out, basepoint_secret, per_commitment_secret });
}

fn derivePrivateKeyBody(out: *[32]u8, basepoint_secret: *const [32]u8, per_commitment_secret: *const [32]u8) Error!void {
    out.* = @splat(0);
    var b = Scalar.fromBytes(basepoint_secret.*, .big) catch return error.InvalidSecret;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&b));
    // `pointOf` (k256 `combMulBase`) reduces a scalar >= n instead of
    // refusing it, so canonicality is checked here, as for every other secret.
    _ = Scalar.fromBytes(per_commitment_secret.*, .big) catch return error.InvalidSecret;
    const basepoint = pointOf(basepoint_secret) catch return error.InvalidSecret;
    const per_commitment_point = pointOf(per_commitment_secret) catch return error.InvalidSecret;
    const t = hashToScalar(sha2(per_commitment_point, basepoint));
    out.* = b.add(t).toBytes(.big);
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
/// The result goes into `out` (zeroed on error); runs under a dead-stack burn.
pub fn deriveRevocationPrivateKey(out: *[32]u8, revocation_basepoint_secret: *const [32]u8, per_commitment_secret: *const [32]u8) Error!void {
    return burn.run(burn.ecc_burn, Error!void, deriveRevocationPrivateKeyBody, .{ out, revocation_basepoint_secret, per_commitment_secret });
}

fn deriveRevocationPrivateKeyBody(out: *[32]u8, revocation_basepoint_secret: *const [32]u8, per_commitment_secret: *const [32]u8) Error!void {
    out.* = @splat(0);
    var rbs = Scalar.fromBytes(revocation_basepoint_secret.*, .big) catch return error.InvalidSecret;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&rbs));
    var pcs = Scalar.fromBytes(per_commitment_secret.*, .big) catch return error.InvalidSecret;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&pcs));
    const revocation_basepoint = pointOf(revocation_basepoint_secret) catch return error.InvalidSecret;
    const per_commitment_point = pointOf(per_commitment_secret) catch return error.InvalidSecret;
    const h1 = hashToScalar(sha2(revocation_basepoint, per_commitment_point));
    const h2 = hashToScalar(sha2(per_commitment_point, revocation_basepoint));
    out.* = rbs.mul(h1).add(pcs.mul(h2)).toBytes(.big);
}

fn pointOf(secret: *const [32]u8) ![33]u8 {
    const p = try Secp256k1.combMulBase(secret.*, .big);
    return p.toCompressedSec1();
}

/// The largest valid per-commitment index. Commitment numbers count DOWN from
/// this value, so `generate_from_seed(seed, max)` is the first secret used.
pub const max_index: u48 = (1 << 48) - 1;

/// BOLT#3 "Per-commitment Secret Requirements" — derive the per-commitment
/// secret for a given 48-bit index from a 32-byte channel seed. Starting from
/// the seed, for each bit set in `index` (from bit 47 down to 0) flip that bit
/// of the running value and SHA-256 it. This is the hash tree that lets a node
/// store any prefix of already-revealed secrets in O(48) space
/// (`RevocationStore`) while making each secret derivable only forward,
/// never backward.
/// The result goes into `out`; runs under a dead-stack burn.
pub fn perCommitmentSecret(out: *[32]u8, seed: *const [32]u8, index: u48) void {
    return burn.run(burn.shachain_burn, void, perCommitmentSecretBody, .{ out, seed, index });
}

fn perCommitmentSecretBody(out: *[32]u8, seed: *const [32]u8, index: u48) void {
    deriveBits(out, seed, 48, index);
}

/// BOLT#3 `derive_secret(base, bits, I)`: the hash walk over the low `bits`
/// bits of `index`, from `base` (the seed when `bits` = 48).
fn deriveBits(out: *[32]u8, base: *const [32]u8, bits: u6, index: u48) void {
    var p = base.*;
    defer std.crypto.secureZero(u8, &p);
    var b: usize = bits;
    while (b > 0) {
        b -= 1;
        if ((index >> @intCast(b)) & 1 == 1) {
            p[b / 8] ^= @as(u8, 1) << @intCast(b % 8);
            var h = Sha256.init(.{});
            h.update(&p);
            p = h.finalResult();
        }
    }
    out.* = p;
}

/// BOLT#3 Appendix D "Efficient Per-commitment Secret Storage": the receiver's
/// store of the counterparty's revealed per-commitment secrets, 49 entries for
/// all 2^48 of them. Secrets arrive counting down from `max_index`; each one is
/// filed in the bucket of its index's trailing zero count, and every entry in a
/// lower bucket must be derivable from it (`insert` refuses one that is not:
/// the counterparty sent a secret that does not belong to its own chain).
/// `get` derives any secret already received. Algorithm and refusal rule as
/// the spec's `insert_secret` / `derive_old_secret` (lnd `shachain`, LDK
/// `CounterpartyCommitmentSecrets` hold the same 49 entries).
pub const RevocationStore = struct {
    known: [49]Entry = @splat(.{}),

    const Entry = struct {
        secret: [32]u8 = @splat(0),
        /// `null` = empty bucket.
        index: ?u48 = null,
    };

    pub const InsertError = error{
        /// An already stored secret is not derivable from this one (or a lower
        /// bucket is still empty: the secrets were not given in order).
        InconsistentSecret,
    };

    /// BOLT#3 `where_to_put_secret`: trailing zeros of `index` (48 for 0).
    fn bucket(index: u48) u6 {
        return if (index == 0) 48 else @intCast(@ctz(index));
    }

    /// Store the secret for `index`, after checking every entry it must
    /// derive. On `InconsistentSecret` the store is unchanged.
    pub fn insert(self: *RevocationStore, secret: *const [32]u8, index: u48) InsertError!void {
        const b = bucket(index);
        for (self.known[0..b]) |*e| {
            const old_index = e.index orelse return error.InconsistentSecret;
            var derived: [32]u8 = undefined;
            deriveBits(&derived, secret, b, old_index);
            if (!std.mem.eql(u8, &derived, &e.secret)) return error.InconsistentSecret;
        }
        self.known[b] = .{ .secret = secret.*, .index = index };
    }

    /// BOLT#3 `derive_old_secret`: the secret for `index`, or null when no
    /// stored entry covers it (not received yet).
    pub fn get(self: *const RevocationStore, index: u48) ?[32]u8 {
        for (&self.known, 0..) |*e, b| {
            const known_index = e.index orelse continue;
            const mask: u48 = if (b == 48) 0 else ~((@as(u48, 1) << @intCast(b)) - 1);
            if (index & mask == known_index & mask) {
                var out: [32]u8 = undefined;
                deriveBits(&out, &e.secret, @intCast(b), index);
                return out;
            }
        }
        return null;
    }
};

// Value-shaped test wrappers over the `out`-pointer API.
fn tPriv(b: [32]u8, p: [32]u8) Error![32]u8 {
    var o: [32]u8 = undefined;
    try derivePrivateKey(&o, &b, &p);
    return o;
}

fn tRevPriv(b: [32]u8, p: [32]u8) Error![32]u8 {
    var o: [32]u8 = undefined;
    try deriveRevocationPrivateKey(&o, &b, &p);
    return o;
}

fn tShachain(seed: [32]u8, index: u48) [32]u8 {
    var o: [32]u8 = undefined;
    perCommitmentSecret(&o, &seed, index);
    return o;
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
    const out = try tPriv(tv_base_secret, tv_pcs);
    try std.testing.expectEqualSlices(u8, &hex32("cbced912d3b21bf196a766651e436aff192362621ce317704ea2f75d87e7be0f"), &out);
}

test "BOLT#3 App E — derivation of revocation key from basepoint and per_commitment_point" {
    const out = try deriveRevocationPublicKey(tv_base_point, tv_pcp);
    try std.testing.expectEqualSlices(u8, &hex33("02916e326636d19c33f13e8c0c3a03dd157f332f3e99c317c141dd865eb01f8ff0"), &out);
}

test "BOLT#3 App E — derivation of revocation secret key from basepoint secret and per_commitment_secret" {
    const out = try tRevPriv(tv_base_secret, tv_pcs);
    try std.testing.expectEqualSlices(u8, &hex32("d09ffff62ddb2297ab000cc85bcb4283fdeb6aa052affbc9dddcf33b61078110"), &out);
}

test "revocation pub derived from secrets matches pub-from-points" {
    // Cross-check: the revocation pubkey must be the public point of the
    // revocation privkey (the whole point of the split-secret construction).
    const revpriv = try tRevPriv(tv_base_secret, tv_pcs);
    const revpub_from_priv = (try Secp256k1.combMulBase(revpriv, .big)).toCompressedSec1();
    const base_pub = (try Secp256k1.combMulBase(tv_base_secret, .big)).toCompressedSec1();
    const pcp = (try Secp256k1.combMulBase(tv_pcs, .big)).toCompressedSec1();
    const revpub_from_points = try deriveRevocationPublicKey(base_pub, pcp);
    try std.testing.expectEqualSlices(u8, &revpub_from_points, &revpub_from_priv);
}

test "simple priv derived matches pub-from-points" {
    const priv = try tPriv(tv_base_secret, tv_pcs);
    const pub_from_priv = (try Secp256k1.combMulBase(priv, .big)).toCompressedSec1();
    const base_pub = (try Secp256k1.combMulBase(tv_base_secret, .big)).toCompressedSec1();
    const pcp = (try Secp256k1.combMulBase(tv_pcs, .big)).toCompressedSec1();
    const pub_from_points = try derivePublicKey(base_pub, pcp);
    try std.testing.expectEqualSlices(u8, &pub_from_points, &pub_from_priv);
}

// ── BOLT#3 Appendix D: Per-commitment Secret — generation test vectors ──────
test "BOLT#3 App D — generate_from_seed 0 final node" {
    const s = tShachain(hex32("0000000000000000000000000000000000000000000000000000000000000000"), max_index);
    try std.testing.expectEqualSlices(u8, &hex32("02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148"), &s);
}

test "BOLT#3 App D — generate_from_seed FF final node" {
    const s = tShachain(hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), max_index);
    try std.testing.expectEqualSlices(u8, &hex32("7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc"), &s);
}

test "BOLT#3 App D — generate_from_seed FF alternate bits 1" {
    const s = tShachain(hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0xaaaaaaaaaaa);
    try std.testing.expectEqualSlices(u8, &hex32("56f4008fb007ca9acf0e15b054d5c9fd12ee06cea347914ddbaed70d1c13a528"), &s);
}

test "BOLT#3 App D — generate_from_seed FF alternate bits 2" {
    const s = tShachain(hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0x555555555555);
    try std.testing.expectEqualSlices(u8, &hex32("9015daaeb06dba4ccc05b91b2f73bd54405f2be9f217fbacd3c5ac2e62327d31"), &s);
}

test "BOLT#3 App D — generate_from_seed 01 last nontrivial node" {
    const s = tShachain(hex32("0101010101010101010101010101010101010101010101010101010101010101"), 1);
    try std.testing.expectEqualSlices(u8, &hex32("915c75942a26bb3a433a8ce2cb0427c29ec6c1775cfc78328b57f6ba7bfeaa9c"), &s);
}

test "per-commitment secret feeds the revocation derivation end-to-end" {
    // A commitment's per_commitment_secret (App D) is exactly the input the
    // revocation derivation (App E) consumes — chain the two halves together.
    const seed = hex32("0101010101010101010101010101010101010101010101010101010101010101");
    const pcs = tShachain(seed, max_index);
    const revpub = try deriveRevocationPublicKey(tv_base_point, (try Secp256k1.combMulBase(pcs, .big)).toCompressedSec1());
    const revpriv = try tRevPriv(tv_base_secret, pcs);
    // revpub must be revpriv·G (mirrors the App-E cross-check, but sourced from a real shachain secret).
    const revpub_from_priv = (try Secp256k1.combMulBase(revpriv, .big)).toCompressedSec1();
    try std.testing.expectEqualSlices(u8, &revpub, &revpub_from_priv);
}

test "invalid point / secret surface as typed errors" {
    const bad33 = @as([33]u8, @splat(0));
    try std.testing.expectError(error.InvalidPoint, derivePublicKey(bad33, tv_pcp));
    const bad32 = @as([32]u8, @splat(0)); // zero is a non-canonical secret
    try std.testing.expectError(error.InvalidSecret, tPriv(bad32, tv_pcs));
}

test "revocation derivation: invalid point / secret surface as typed errors" {
    const bad33 = @as([33]u8, @splat(0));
    const bad32 = @as([32]u8, @splat(0)); // zero is a non-canonical secret
    try std.testing.expectError(error.InvalidPoint, deriveRevocationPublicKey(bad33, tv_pcp));
    try std.testing.expectError(error.InvalidPoint, deriveRevocationPublicKey(tv_base_point, bad33));
    try std.testing.expectError(error.InvalidSecret, tRevPriv(bad32, tv_pcs));
    try std.testing.expectError(error.InvalidSecret, tRevPriv(tv_base_secret, bad32));
}

test "every input is validated: bad per_commitment_point, zero or >= n secrets" {
    // Mutation run 2026-10-05: each of these refusals could be deleted (or
    // re-labelled) without any test above noticing.
    const bad33 = @as([33]u8, @splat(0));
    const zero = @as([32]u8, @splat(0));
    const over_n = @as([32]u8, @splat(0xff)); // > n: not a canonical scalar
    try std.testing.expectError(error.InvalidPoint, derivePublicKey(tv_base_point, bad33));
    try std.testing.expectError(error.InvalidSecret, tPriv(tv_base_secret, zero));
    try std.testing.expectError(error.InvalidSecret, tPriv(over_n, tv_pcs));
    try std.testing.expectError(error.InvalidSecret, tRevPriv(over_n, tv_pcs));
    try std.testing.expectError(error.InvalidSecret, tRevPriv(tv_base_secret, over_n));
}

test "regression: derivePrivateKey refuses a per_commitment_secret >= n" {
    // Found by the 2026-10-05 mutation run: `pointOf` (k256 `combMulBase`)
    // reduces a non-canonical scalar mod n, so this secret was accepted and
    // silently reduced, while `deriveRevocationPrivateKey` refused the same
    // bytes and `Error.InvalidSecret` promises a canonical (< n) scalar.
    const over_n = @as([32]u8, @splat(0xff));
    try std.testing.expectError(error.InvalidSecret, tPriv(tv_base_secret, over_n));
}

const testkit = @import("testkit");
const hex32 = testkit.hex.literal;

const hex33 = testkit.hex.literal;

test {
    _ = @import("stackprobe_test.zig");
}

test "derivePrivateKey / deriveRevocationPrivateKey: out is zeroed on error, whatever it held" {
    const zero = @as([32]u8, @splat(0)); // not a valid secret
    var out: [32]u8 = @splat(0xaa);
    try std.testing.expectError(error.InvalidSecret, derivePrivateKey(&out, &zero, &tv_pcs));
    try std.testing.expectEqualSlices(u8, &zero, &out);
    out = @splat(0xaa);
    try std.testing.expectError(error.InvalidSecret, deriveRevocationPrivateKey(&out, &zero, &tv_pcs));
    try std.testing.expectEqualSlices(u8, &zero, &out);
}

// ── BOLT#3 Appendix D: storage tests (insert_secret) ──────────────────────
// Every sequence starts at `max_index` and counts down; `fail_last` = the
// spec expects the last insert to be refused (all earlier ones accepted).
const StorageCase = struct { name: []const u8, fail_last: bool, secrets: []const []const u8 };
const storage_cases = [_]StorageCase{
    .{ .name = "insert_secret correct sequence", .fail_last = false, .secrets = &.{
        "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
        "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
        "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
        "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
        "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd",
        "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2",
        "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32",
        "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17",
    } },
    .{ .name = "insert_secret #1 incorrect", .fail_last = true, .secrets = &.{
        "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148",
        "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
    } },
    .{ .name = "insert_secret #2 incorrect (#1 derived from incorrect)", .fail_last = true, .secrets = &.{
        "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148",
        "dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3",
        "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
        "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
    } },
    .{ .name = "insert_secret #3 incorrect", .fail_last = true, .secrets = &.{
        "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
        "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
        "c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a",
        "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
    } },
    .{ .name = "insert_secret #4 incorrect (1,2,3 derived from incorrect)", .fail_last = true, .secrets = &.{
        "02a40c85b6f28da08dfdbe0926c53fab2de6d28c10301f8f7c4073d5e42e3148",
        "dddc3a8d14fddf2b68fa8c7fbad2748274937479dd0f8930d5ebb4ab6bd866a3",
        "c51a18b13e8527e579ec56365482c62f180b7d5760b46e9477dae59e87ed423a",
        "ba65d7b0ef55a3ba300d4e87af29868f394f8f138d78a7011669c79b37b936f4",
        "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd",
        "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2",
        "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32",
        "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17",
    } },
    .{ .name = "insert_secret #5 incorrect", .fail_last = true, .secrets = &.{
        "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
        "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
        "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
        "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
        "631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6",
        "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2",
    } },
    .{ .name = "insert_secret #6 incorrect (5 derived from incorrect)", .fail_last = true, .secrets = &.{
        "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
        "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
        "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
        "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
        "631373ad5f9ef654bb3dade742d09504c567edd24320d2fcd68e3cc47e2ff6a6",
        "b7e76a83668bde38b373970155c868a653304308f9896692f904a23731224bb1",
        "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32",
        "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17",
    } },
    .{ .name = "insert_secret #7 incorrect", .fail_last = true, .secrets = &.{
        "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
        "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
        "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
        "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
        "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd",
        "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2",
        "e7971de736e01da8ed58b94c2fc216cb1dca9e326f3a96e7194fe8ea8af6c0a3",
        "05cde6323d949933f7f7b78776bcc1ea6d9b31447732e3802e1f7ac44b650e17",
    } },
    .{ .name = "insert_secret #8 incorrect", .fail_last = true, .secrets = &.{
        "7cc854b54e3e0dcdb010d7a3fee464a9687be6e8db3be6854c475621e007a5dc",
        "c7518c8ae4660ed02894df8976fa1a3659c1a8b4b5bec0c4b872abeba4cb8964",
        "2273e227a5b7449b6e70f1fb4652864038b1cbf9cd7c043a7d6456b7fc275ad8",
        "27cddaa5624534cb6cb9d7da077cf2b22ab21e9b506fd4998a51d54502e99116",
        "c65716add7aa98ba7acb236352d665cab17345fe45b55fb879ff80e6bd0c41dd",
        "969660042a28f32d9be17344e09374b379962d03db1574df5a8a5a47e19ce3f2",
        "a5a64476122ca0925fb344bdc1854c1c0a59fc614298e50a33e331980a220f32",
        "a7efbc61aac46d34f77778bac22c8a20c6a46ca460addc49009bda875ec88fa4",
    } },
};

test "BOLT#3 App D — insert_secret storage vectors" {
    for (storage_cases) |c| {
        var st: RevocationStore = .{};
        for (c.secrets, 0..) |hex, k| {
            var secret: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&secret, hex);
            const index: u48 = max_index - @as(u48, @intCast(k));
            const last = k + 1 == c.secrets.len;
            if (last and c.fail_last) {
                const before = st;
                std.testing.expectError(error.InconsistentSecret, st.insert(&secret, index)) catch |e| {
                    std.debug.print("FAIL: {s}\n", .{c.name});
                    return e;
                };
                try std.testing.expect(std.meta.eql(before, st)); // unchanged
            } else {
                st.insert(&secret, index) catch |e| {
                    std.debug.print("FAIL: {s} step {d}\n", .{ c.name, k });
                    return e;
                };
            }
        }
    }
}

test "RevocationStore.get derives every received secret and nothing newer" {
    const seed: [32]u8 = @splat(0xff);
    var st: RevocationStore = .{};
    const n = 70;
    for (0..n) |k| {
        const index = max_index - @as(u48, @intCast(k));
        try st.insert(&tShachain(seed, index), index);
    }
    for (0..n) |k| {
        const index = max_index - @as(u48, @intCast(k));
        try std.testing.expectEqualSlices(u8, &tShachain(seed, index), &(st.get(index) orelse return error.TestUnexpectedResult));
    }
    // Not received yet: the next one down.
    try std.testing.expect(st.get(max_index - n) == null);
    // Out of order: skipping an index leaves a lower bucket empty or wrong.
    var gap: RevocationStore = .{};
    try gap.insert(&tShachain(seed, max_index), max_index);
    try std.testing.expectError(error.InconsistentSecret, gap.insert(&tShachain(seed, max_index - 3), max_index - 3));
}
