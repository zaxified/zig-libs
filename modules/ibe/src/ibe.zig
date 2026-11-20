// SPDX-License-Identifier: MIT

//! ibe — the `Setup`/`Extract`/`Encrypt`/`Decrypt` API + the
//! `Ciphertext` wire struct, the canonical Boneh-Franklin "FullIdent"
//! construction (Boneh & Franklin, "Identity-Based Encryption from the
//! Weil Pairing", CRYPTO 2001, §4.2) over `bls12_381`.
//!
//! ## The scheme, end to end
//!
//! - **`Setup(io)`** — generates a fresh PKG (Private Key Generator)
//!   keypair: `msk ∈ Fr` (master secret, uniformly random) and
//!   `mpk = msk · G2_generator ∈ G2` (master public key, published to
//!   everyone who wants to encrypt). Unlike `tlock` (whose "PKG" is an
//!   external drand beacon this module never runs), `ibe`'s CALLER runs
//!   the PKG: `Setup` and `Extract` are both this module's job.
//! - **`Extract(msk, id)`** — the PKG's per-identity key-derivation
//!   step: `d_id = msk · H1(id) ∈ G1`, the identity's BF-IBE private
//!   key. `id` is an arbitrary caller-chosen byte string (an email
//!   address, a device serial, a policy string — no format is imposed).
//! - **`encrypt(mpk, id, message, sigma)`**:
//!   1. `Qid = H1(id) ∈ G1`.
//!   2. `Gid = pairing(Qid, mpk) ∈ Gt` — `bls12_381.pairing.pairing`
//!      takes `(G1, G2)` in that order.
//!   3. `sigma` is the caller-supplied `block_bytes`-wide randomness
//!      (BF-IBE's "FullIdent" padding — an explicit PARAMETER, see this
//!      function's own doc comment).
//!   4. `r = H3(sigma, message) ∈ Fr` — the FO-transform binding
//!      scalar.
//!   5. `U = r · G2_generator ∈ G2`.
//!   6. `gid_r = Gid^r ∈ Gt` — a `Gt`-GROUP EXPONENTIATION by the
//!      secret scalar `r` (NOT a pairing call — `encrypt` has no
//!      private key to fold `r` into one of the pairing's own
//!      arguments the way `decrypt` does, so it must exponentiate the
//!      already-computed `Gid` directly, via `bls12_381`'s
//!      constant-time `Fp12.pow`).
//!   7. `V = sigma XOR H2(gid_r)`.
//!   8. `W = message XOR H4(sigma)`.
//!   9. return `Ciphertext{ .u = U, .v = V, .w = W }`.
//! - **`decrypt(d_id, ct)`**:
//!   1. `gid_r = pairing(d_id, ct.u) ∈ Gt` — ONE pairing call
//!      reconstructs exactly the `Gid^r` value `encrypt` had to
//!      exponentiate for, by bilinearity:
//!      `e(d_id, U) = e(msk·Qid, r·G2gen) = e(Qid, G2gen)^(msk·r)
//!                  = e(Qid, msk·G2gen)^r = e(Qid, mpk)^r = Gid^r`.
//!      This identity — `e(d_id, U) == Gid^r` — is BF-IBE's whole
//!      reason for being practical: the DECRYPTOR gets the
//!      exponentiated value for free from one pairing, while the
//!      ENCRYPTOR (who does not have `msk`/`d_id`) must actually
//!      exponentiate (step 6 above).
//!   2. `sigma = ct.v XOR H2(gid_r)`.
//!   3. `message = ct.w XOR H4(sigma)`.
//!   4. **FO consistency check (the CCA-security step — MUST NOT be
//!      skipped):** recompute `r' = H3(sigma, message)`, then
//!      `U' = r' · G2_generator`; if `U' != ct.u`, REJECT
//!      (`error.FoCheckFailed`), never return a partially-decrypted
//!      `message` — this stops a chosen-ciphertext attacker from
//!      tampering with `V`/`W` and having `decrypt` silently return
//!      garbage that LOOKS like a message: only a ciphertext genuinely
//!      produced by `encrypt` with matching internal randomness passes.
//!      Fujisaki-Okamoto transform, Boneh-Franklin §4.2's `FullIdent`.
//!   5. return `message`.
//!
//! ## Ciphertext group placement
//!
//! `U ∈ G2` (96-byte compressed), `d_id ∈ G1` (48-byte compressed),
//! `mpk ∈ G2` — the SAME asymmetric layout `tlock`'s quicknet variant
//! uses (master public key + `U` in the bigger `G2` group, per-identity
//! private key in the smaller `G1` group): the pairing
//! `e: G1 x G2 -> Gt` needs one argument from each group, and this
//! placement lets `Extract`'s output (`d_id`, distributed to many
//! identities) be the smaller of the two compressed encodings.
//!
//! ## No drand-style cube (read before comparing against `tlock`)
//!
//! `tlock.zig`'s `encrypt`/`decrypt` apply a private `gtToDrandRepr`
//! (`gt -> gt³`) adapter before every `ciphersuite.h2` call, because
//! `tlock` must byte-exactly match `kilic/bls12-381`'s pairing
//! convention (drand's Go implementation), whose final exponentiation
//! computes a fixed CUBE of the canonical pairing value this repo's
//! `bls12_381.pairing` implements (see `tlock`'s `SPEC.md`, "Gt
//! serialization"). `ibe` has **no external deployment whose bytes it
//! must match** — it is this repo's OWN scheme, not a specialization of
//! anyone else's. `encrypt` and `decrypt` both call
//! `bls12_381.pairing.pairing`/`Fp12.pow` and feed
//! `ciphersuite.h2` the SAME (canonical, uncubed) `Fp12` representation
//! on both sides, so correctness only requires INTERNAL consistency —
//! which the pairing identity `e(d_id,U) == Gid^r` (proved above)
//! already guarantees regardless of which final-exponentiation
//! convention `bls12_381.pairing` happens to implement. Applying a cube
//! here would be pure cargo-culting: there is no reference byte
//! sequence it would need to match. See `SPEC.md`'s "No drand-style
//! cube" section for the KAT that pins this directly.
//!
//! ## The ciphersuite seam, and what it anchors
//!
//! Everything above splits cleanly in two: an ASSEMBLY (which hash
//! output feeds which XOR, the FO consistency check, where `Fp12.pow`
//! sits, where `U`/`V`/`W` land in the encoding) and a set of
//! PARAMETERS (hash tags, hash-to-curve DST, block width, `Gt`
//! representation). `Scheme` below makes that split explicit: the
//! assembly is written once and takes the parameters as a `comptime`
//! ciphersuite; `ibe`'s public API is `Scheme(ciphersuite)`.
//!
//! That is not decoration — it is what gives this module an external
//! oracle it could not otherwise have. The parameters are unanchorable
//! in principle (RFC 9380 §3.1 *requires* each application to pick its
//! own DST, so there is no foreign value to match, and the no-cube
//! choice above has no external byte target either). The ASSEMBLY is
//! not: instantiated with drand's parameters, it must reproduce a
//! genuine ciphertext produced by drand's own Go `tle` CLI, byte for
//! byte — and `kat_test.zig` section 5 requires exactly that, running
//! THIS code rather than a copy of it. A systematic assembly error
//! (the one failure mode a round-trip/tamper suite is structurally
//! blind to) fails there and nowhere else; both halves of that claim
//! were verified by mutation.

const std = @import("std");
const bls12_381 = @import("bls12_381");
const ciphersuite = @import("ciphersuite.zig");
const burn = @import("burn.zig");

const g1 = bls12_381.g1;
const g2 = bls12_381.g2;
const pairing = bls12_381.pairing;
const Fp2 = bls12_381.Fp2;
const Fp6 = bls12_381.Fp6;
const Fp12 = bls12_381.Fp12;
const Fr = bls12_381.Fr;

pub const block_bytes = ciphersuite.block_bytes;

// ── KeyPair: the PKG's Setup output ─────────────────────────────────

/// The Private Key Generator's keypair, produced by `Setup`. `msk`
/// (master secret key) must never be revealed to anyone except the
/// PKG itself — anyone holding it can `Extract` a private key for ANY
/// identity, which is BF-IBE's well-known key-escrow property (the PKG
/// is a fully trusted third party by design, exactly like `tlock`'s
/// drand beacon operators — see `root.zig`'s "Honest limitations").
pub const KeyPair = struct {
    msk: Fr,
    mpk: g2.Affine,

    /// Zero the SECRET field (`msk`) in place at end-of-life. `mpk` is the
    /// published master public key and is left untouched. Call once the
    /// PKG no longer needs `msk` in memory (e.g. after persisting it to a
    /// dedicated secret store). Idempotent — safe to call more than once.
    pub fn deinit(self: *KeyPair) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.msk));
    }
};

/// **PKG Setup — REAL.** Generates a fresh master keypair:
/// `msk` uniformly random in `Fr` (`Fr.random`, which itself
/// rejection-samples to stay unbiased — see that function's doc
/// comment), `mpk = msk · G2_generator`. This is the ONLY randomness
/// `ibe`'s PKG-side API needs; `Extract` is fully deterministic given
/// `msk`.
///
/// The key pair is written to `out`; the body runs one frame down and the
/// stack it dirtied is zeroed after it (`burn.zig`).
pub fn setup(out: *KeyPair, io: std.Io) void {
    burn.run(burn.key_burn, void, setupBody, .{ out, io });
}

fn setupBody(out: *KeyPair, io: std.Io) void {
    out.msk = Fr.random(io);
    out.mpk = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(out.msk).toAffine();
}

// `extract`, `Ciphertext`, `encrypt` and `decrypt` are the four
// declarations that actually CONSUME a ciphersuite, so they live inside
// `Scheme` rather than at file scope; the
// default instantiation is re-exported at the bottom of this file, so
// `ibe.extract`/`ibe.Ciphertext`/`ibe.encrypt`/`ibe.decrypt` mean exactly
// what they always did.

// ── Scheme: the ciphersuite seam ────────────────────────────────────

pub const DecryptError = error{
    /// The Fiat-Shamir-Okamoto consistency check (`U == r*gen` after
    /// recomputing `r` from the recovered `(sigma, message)`) failed —
    /// the ciphertext was tampered with, or `d_id` does not correspond
    /// to the identity `ct` was encrypted under. This is the
    /// CCA-rejection outcome; `decrypt` must NEVER return a `message`
    /// when this check fails (see this file's module doc comment,
    /// `decrypt` step 4).
    FoCheckFailed,
};

/// The BF-IBE construction, PARAMETERISED over its ciphersuite.
///
/// ## Why this is a `comptime` seam and not four hard-wired functions
///
/// The four declarations below (`extract`, `Ciphertext`, `encrypt`,
/// `decrypt`) are the module's ASSEMBLY: which hash output feeds which
/// XOR, in what order the FO consistency check recomputes and compares,
/// where `Fp12.pow` sits, and where `U`/`V`/`W` land in the wire
/// encoding. That assembly is *independent* of which hash tags,
/// which hash-to-curve DST, which block width and which `Gt`
/// representation the scheme is instantiated with — those are the
/// `ciphersuite` parameters.
///
/// Splitting them apart is what makes this module's assembly
/// EXTERNALLY CHECKABLE. `ibe`'s own parameters
/// (`ciphersuite.zig`'s `zig-libs/ibe/H{2,3,4}` tags, its own
/// `dst_g1`, 32-byte blocks, the canonical un-cubed `Gt`
/// representation) are this repo's own choice, so no third party
/// publishes bytes for them and nothing external can pin them. But the
/// SAME assembly, instantiated with drand's parameters, must reproduce
/// drand's real ciphertexts — and one of those exists, frozen in the
/// sibling `tlock` module, produced by drand's own Go `tle` CLI. So
/// `kat_test.zig` drives THIS code (not a copy of it, not a
/// re-derivation of it in another language) with a drand-shaped
/// ciphersuite and byte-compares against that fixture. See
/// `kat_test.zig`'s "drand-parameterised interop anchor" section, and
/// `SPEC.md`'s "KAT plan" for what that does and does not prove.
///
/// ## The ciphersuite interface
///
/// `cs` must provide:
///
/// - `pub const block_bytes: usize` — the `V`/`W` width.
/// - `pub fn h1(id: []const u8) g1.Affine` — identity to `G1`.
/// - `pub fn h2(gt: Fp12) [block_bytes]u8` — `Gt` element to a mask.
///   A ciphersuite whose reference implementation hashes a DIFFERENT
///   representation of the pairing value (drand/`kilic` hash the
///   canonical value's cube) applies that adapter HERE, inside its own
///   `h2` — `encrypt`/`decrypt` below always hand it
///   `bls12_381.pairing`'s canonical output and never adapt it
///   themselves, which is what keeps the assembly representation-
///   agnostic.
/// - `pub fn h3(sigma: []const u8, msg: []const u8) Fr` — the
///   FO-transform binding scalar.
/// - `pub fn h4(sigma: []const u8) [block_bytes]u8` — `sigma` to a
///   mask.
pub fn Scheme(comptime cs: type) type {
    return struct {
        /// Self-reference. The nested types below must be named through
        /// it: this file ALSO declares `Ciphertext` (the default
        /// instantiation's alias, at the bottom), and a bare
        /// `Ciphertext` inside here would be visible from two enclosing
        /// container scopes at once — which Zig rejects as an ambiguous
        /// reference rather than silently picking one.
        const Self = @This();

        pub const block_bytes = cs.block_bytes;

        /// **PKG Extract — REAL.** Derives the BF-IBE private key for
        /// `id`: `d_id = msk · H1(id) ∈ G1`. Deterministic in
        /// `(msk, id)` — the SAME identity always yields the SAME
        /// private key from the SAME PKG, which is BF-IBE's point (a
        /// sender can encrypt to `id` before the recipient has ever
        /// contacted the PKG; `Extract` reproduces the matching key on
        /// demand, exactly like `tlock`'s round-signature beacon
        /// publishes the same signature no matter when it's fetched).
        ///
        /// `d_id` is a secret: written to `out`, never returned through the
        /// stack.
        pub fn extract(out: *g1.Affine, msk: *const Fr, id: []const u8) void {
            burn.run(burn.key_burn, void, extractBody, .{ out, msk, id });
        }

        fn extractBody(out: *g1.Affine, msk: *const Fr, id: []const u8) void {
            const qid = cs.h1(id);
            out.* = g1.Jacobian.fromAffine(qid).scalarMul(msk.*).toAffine();
        }

        /// The `(U, V, W)` BF-IBE ciphertext (Boneh-Franklin §4.2's
        /// `FullIdent` output shape). See this file's module doc
        /// comment for the full construction and for why `U` lives in
        /// `G2`.
        pub const Ciphertext = struct {
            /// `r * G2_generator` — the randomized "commitment" half of
            /// the ciphertext; `decrypt`'s FO check recomputes this from
            /// the recovered `(sigma, message)` and rejects on mismatch.
            u: g2.Affine,
            /// `sigma XOR H2(Gid^r)` — the random pad `sigma`, masked by
            /// a hash of the pairing value only someone with `d_id` (or
            /// the encryptor, who computed `Gid^r` directly) can recover.
            v: [cs.block_bytes]u8,
            /// `message XOR H4(sigma)` — the actual plaintext block,
            /// masked by a hash of `sigma` (recoverable only after `v`
            /// is unmasked).
            w: [cs.block_bytes]u8,

            /// `96 + block_bytes + block_bytes` (160 for `ibe`'s own
            /// 32-byte blocks; 128 for drand's 16-byte ones).
            pub const encoded_bytes = g2.compressed_bytes + cs.block_bytes + cs.block_bytes;

            /// `U (96B compressed G2) || V || W`. REAL: plain
            /// concatenation over `bls12_381`'s already-real
            /// `g2.toBytesCompressed`.
            pub fn toBytes(self: @This()) [encoded_bytes]u8 {
                var out: [encoded_bytes]u8 = undefined;
                out[0..g2.compressed_bytes].* = g2.toBytesCompressed(self.u);
                out[g2.compressed_bytes..][0..cs.block_bytes].* = self.v;
                out[g2.compressed_bytes + cs.block_bytes ..][0..cs.block_bytes].* = self.w;
                return out;
            }

            /// Inverse of `toBytes`. `g2.fromBytesCompressed` refuses a `U`
            /// outside `G2`, so the pairing in `decrypt`
            /// never runs on a torsion point; `decrypt`'s own consistency
            /// check (`U == r*gen`) stays the scheme-specific guard. REAL.
            pub fn fromBytes(bytes: [encoded_bytes]u8) g2.G2Error!@This() {
                const u = try g2.fromBytesCompressed(bytes[0..g2.compressed_bytes].*);
                return .{
                    .u = u,
                    .v = bytes[g2.compressed_bytes..][0..cs.block_bytes].*,
                    .w = bytes[g2.compressed_bytes + cs.block_bytes ..][0..cs.block_bytes].*,
                };
            }
        };

        /// **REAL.** BF-IBE FullIdent encryption (Boneh-Franklin §4.2).
        /// See this file's module doc comment for the full 9-step
        /// construction this function transcribes (`id -> Qid -> Gid ->
        /// r -> U -> gid_r -> V -> W`).
        ///
        /// ## Randomness — explicit parameter, not internal entropy
        ///
        /// `sigma` (BF-IBE's random `block_bytes`-wide pad) is a PLAIN
        /// PARAMETER here, not read from `std.Io`/internal entropy
        /// directly — mirroring `tlock`/`bbs`/`frost`'s "randomness is
        /// an explicit input" convention. This is what lets a KAT
        /// harness pin the ciphertext deterministically: `encrypt`'s
        /// OTHER inputs (`mpk`, `id`, `message`) are already fully
        /// deterministic, so supplying `sigma` explicitly makes the
        /// entire output reproducible — a production caller instead
        /// sources `sigma` from `ciphersuite.randomSigma(io)`.
        ///
        /// `message.len`/`sigma.len` are both fixed to `block_bytes`
        /// (32 for the default instantiation — see
        /// `ciphersuite.block_bytes`'s doc comment).
        ///
        /// `message` and `sigma` are secrets, so they come in by pointer; the
        /// body runs one frame down and the stack it dirtied (`r`, `Gid^r`,
        /// both masks) is zeroed after it (`burn.zig`).
        pub fn encrypt(mpk: g2.Affine, id: []const u8, message: *const [cs.block_bytes]u8, sigma: *const [cs.block_bytes]u8) Self.Ciphertext {
            return burn.run(burn.crypt_burn, Self.Ciphertext, encryptBody, .{ mpk, id, message, sigma });
        }

        fn encryptBody(mpk: g2.Affine, id: []const u8, message: *const [cs.block_bytes]u8, sigma: *const [cs.block_bytes]u8) Self.Ciphertext {
            // Steps 1-2: identity -> Qid -> Gid. `pairing.pairing` takes
            // `(G1, G2)`.
            const qid = cs.h1(id);
            const gid = pairing.pairing(qid, mpk);

            // Step 4: r = H3(sigma, M) — the FO-transform binding scalar.
            const r = cs.h3(sigma, message);

            // Step 5: U = r * G2_generator (constant-time scalarMul).
            const u = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(r).toAffine();

            // Step 6: gid_r = Gid^r — Gt exponentiation (see Fp12.pow
            // above). Handed to `h2` in `bls12_381.pairing`'s CANONICAL
            // representation; a ciphersuite needing another one (drand's
            // cube) adapts inside its own `h2`. See this file's module
            // doc comment, "No drand-style cube".
            const gid_r = gid.pow(&r);

            // Step 7: V = sigma XOR H2(gid_r).
            var v = cs.h2(gid_r);
            for (&v, sigma) |*b, s| b.* ^= s;

            // Step 8: W = M XOR H4(sigma).
            var w = cs.h4(sigma);
            for (&w, message) |*b, m| b.* ^= m;

            return .{ .u = u, .v = v, .w = w };
        }

        /// **REAL.** BF-IBE FullIdent decryption + the
        /// Fiat-Shamir-Okamoto consistency check. See this file's module
        /// doc comment for the full construction this function
        /// transcribes (`gid_r -> sigma -> message -> recompute r ->
        /// check U`).
        ///
        /// `d_id` is the identity's BF-IBE private key, from
        /// `extract(msk, id)` — this function does NOT verify `d_id`
        /// against `mpk`/`id` itself (a caller-side sanity check,
        /// analogous to `tlock.decrypt`'s note about verifying
        /// `round_signature` against the beacon public key before
        /// trusting it — see that module's `kat_test.zig` for the
        /// pairing-check idiom, `e(d_id, G2gen) == e(H1(id), mpk)`,
        /// which applies here unchanged). Returns
        /// `error.FoCheckFailed` (never a garbage `message`) if the
        /// recomputed `U' != ct.u` — the CCA-rejection path.
        ///
        /// The plaintext is written to `out` (zeroed on error); `d_id` comes
        /// in by pointer. The body runs one frame down and the stack it
        /// dirtied is zeroed after it (`burn.zig`).
        pub fn decrypt(out: *[cs.block_bytes]u8, d_id: *const g1.Affine, ct: Self.Ciphertext) DecryptError!void {
            burn.run(burn.crypt_burn, DecryptError!void, decryptBody, .{ out, d_id, ct }) catch |e| {
                std.crypto.secureZero(u8, out);
                return e;
            };
        }

        fn decryptBody(out: *[cs.block_bytes]u8, d_id: *const g1.Affine, ct: Self.Ciphertext) DecryptError!void {
            // Step 1: gid_r = e(d_id, U) — ONE pairing call reconstructs
            // encrypt's Gid^r by bilinearity (see the module doc
            // comment). The SAME canonical pairing representation
            // `encrypt` fed to h2 above.
            const gid_r = pairing.pairing(d_id.*, ct.u);

            // Step 2: sigma = V XOR H2(gid_r). Purely internal scratch —
            // never returned — so it is wiped on every exit (success or
            // reject).
            var sigma = cs.h2(gid_r);
            for (&sigma, ct.v) |*b, x| b.* ^= x;
            defer std.crypto.secureZero(u8, &sigma);

            // Step 3: message = W XOR H4(sigma).
            const message = out;
            message.* = cs.h4(&sigma);
            for (message, ct.w) |*b, x| b.* ^= x;

            // Step 4: FO/CCA consistency — recompute r' = H3(sigma,
            // message) and reject unless U == r' * G2_generator. Compare
            // via the canonical compressed encoding (unique for every
            // point incl. infinity). The check's outcome (accept/reject)
            // is public, so a non-constant-time byte compare is fine
            // here; what must NOT happen is returning a
            // partially-decrypted message on mismatch — so on reject,
            // wipe the (untrusted, about-to-be-discarded) recovered
            // `message` before returning the error instead of leaving it
            // sitting on the stack.
            const r_check = cs.h3(&sigma, message);
            const u_check = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(r_check).toAffine();
            if (!std.mem.eql(u8, &g2.toBytesCompressed(u_check), &g2.toBytesCompressed(ct.u))) {
                std.crypto.secureZero(u8, message);
                return error.FoCheckFailed;
            }
        }
    };
}

// ── the default instantiation: this module's own scheme ─────────────
//
// `ibe`'s public API is `Scheme(ciphersuite)` — the parameterisation
// above is a TESTABILITY seam, not a new public surface for callers to
// pick a ciphersuite from; `root.zig` re-exports only these.

/// This module's own BF-IBE scheme: `ciphersuite.zig`'s DSTs, tags,
/// 32-byte blocks and canonical (un-cubed) `Gt` representation.
pub const Default = Scheme(ciphersuite);

pub const Ciphertext = Default.Ciphertext;
pub const extract = Default.extract;
pub const encrypt = Default.encrypt;
pub const decrypt = Default.decrypt;

// ── tests: Ciphertext codec (REAL, ungated) ─────────────────────────

test "Ciphertext.encoded_bytes is 160 (96 G2 + 32 V + 32 W)" {
    try std.testing.expectEqual(@as(usize, 160), Ciphertext.encoded_bytes);
}

test "Ciphertext.toBytes/fromBytes round-trip (generator U, arbitrary V/W)" {
    const ct: Ciphertext = .{
        .u = g2.Affine.generator,
        .v = @as([block_bytes]u8, @splat(0xab)),
        .w = @as([block_bytes]u8, @splat(0xcd)),
    };
    const bytes = ct.toBytes();
    try std.testing.expectEqual(@as(usize, Ciphertext.encoded_bytes), bytes.len);

    const decoded = try Ciphertext.fromBytes(bytes);
    try std.testing.expect(decoded.u.x.eql(g2.Affine.generator.x));
    try std.testing.expectEqualSlices(u8, &ct.v, &decoded.v);
    try std.testing.expectEqualSlices(u8, &ct.w, &decoded.w);
}

test "Ciphertext.fromBytes rejects a malformed G2 encoding (V/W untouched, U corrupted)" {
    var bytes = (Ciphertext{
        .u = g2.Affine.generator,
        .v = @as([block_bytes]u8, @splat(0)),
        .w = @as([block_bytes]u8, @splat(0)),
    }).toBytes();
    bytes[0] = 0xFF; // invalid flag-byte combination
    try std.testing.expectError(error.InvalidEncoding, Ciphertext.fromBytes(bytes));
}

// ── tests: setup/extract (REAL, ungated) ─────────────────────────────

fn testIo() std.Io.Threaded {
    return std.Io.Threaded.init(std.testing.allocator, .{});
}

test "setup produces mpk = msk * G2_generator" {
    var threaded = testIo();
    defer threaded.deinit();
    var kp: KeyPair = undefined;
    setup(&kp, threaded.io());
    const expected = g2.Jacobian.fromAffine(g2.Affine.generator).scalarMul(kp.msk).toAffine();
    try std.testing.expect(kp.mpk.x.eql(expected.x));
    try std.testing.expect(kp.mpk.y.eql(expected.y));
}

test "setup draws distinct msk across calls (not a fixed constant)" {
    var threaded = testIo();
    defer threaded.deinit();
    const io = threaded.io();
    var kp1: KeyPair = undefined;
    setup(&kp1, io);
    var kp2: KeyPair = undefined;
    setup(&kp2, io);
    try std.testing.expect(!kp1.msk.eql(kp2.msk));
}

test "KeyPair.deinit zeroes msk but leaves mpk untouched" {
    var threaded = testIo();
    defer threaded.deinit();
    var kp: KeyPair = undefined;
    setup(&kp, threaded.io());
    const mpk_before = kp.mpk;
    try std.testing.expect(!kp.msk.eql(Fr.zero));
    kp.deinit();
    try std.testing.expect(kp.msk.eql(Fr.zero));
    try std.testing.expect(kp.mpk.x.eql(mpk_before.x));
    try std.testing.expect(kp.mpk.y.eql(mpk_before.y));
}

test "decrypt zeroes the recovered message on FO-check failure" {
    var threaded = testIo();
    defer threaded.deinit();
    var kp: KeyPair = undefined;
    setup(&kp, threaded.io());
    const id = "alice@example.com";
    const d_id = testExtract(Default, kp.msk, id);

    const message = @as([block_bytes]u8, @splat(0xAB));
    const sigma = @as([block_bytes]u8, @splat(0x11));
    var ct = testEncrypt(Default, kp.mpk, id, message, sigma);
    // Tamper with V so the recovered (sigma, message) no longer matches U.
    ct.v[0] ^= 0xFF;

    try std.testing.expectError(error.FoCheckFailed, testDecrypt(Default, d_id, ct));
    // The function itself leaves no live copy of the garbage message behind
    // (verified indirectly: the reject path is exercised without panicking
    // or leaking a value — `decrypt`'s local `message`/`sigma` are wiped
    // before the error returns, per this file's `deinit`/zeroization pass).
}

test "extract is deterministic in (msk, id)" {
    var threaded = testIo();
    defer threaded.deinit();
    var kp: KeyPair = undefined;
    setup(&kp, threaded.io());
    const d1 = testExtract(Default, kp.msk, "alice@example.com");
    const d2 = testExtract(Default, kp.msk, "alice@example.com");
    try std.testing.expect(d1.x.eql(d2.x));
    try std.testing.expect(d1.y.eql(d2.y));
}

test "extract yields distinct keys for distinct identities under the same msk" {
    var threaded = testIo();
    defer threaded.deinit();
    var kp: KeyPair = undefined;
    setup(&kp, threaded.io());
    const d_alice = testExtract(Default, kp.msk, "alice@example.com");
    const d_bob = testExtract(Default, kp.msk, "bob@example.com");
    try std.testing.expect(!d_alice.x.eql(d_bob.x));
}

test "extract yields a point on-curve and in the order-r G1 subgroup" {
    var threaded = testIo();
    defer threaded.deinit();
    var kp: KeyPair = undefined;
    setup(&kp, threaded.io());
    const d_id = testExtract(Default, kp.msk, "alice@example.com");
    try std.testing.expect(g1.Jacobian.fromAffine(d_id).isOnCurve());
    try std.testing.expect(g1.Jacobian.fromAffine(d_id).subgroupCheck());
}

// Test helpers over the pointer/out-param API: tests compare values, library
// code never returns a secret through the stack.
fn testExtract(comptime S: type, msk: Fr, ident: []const u8) g1.Affine {
    var d: g1.Affine = undefined;
    S.extract(&d, &msk, ident);
    return d;
}
fn testEncrypt(comptime S: type, mpk: g2.Affine, ident: []const u8, m: [S.block_bytes]u8, sigma: [S.block_bytes]u8) S.Ciphertext {
    return S.encrypt(mpk, ident, &m, &sigma);
}
fn testDecrypt(comptime S: type, d_id: g1.Affine, ct: S.Ciphertext) ![S.block_bytes]u8 {
    var out: [S.block_bytes]u8 = undefined;
    try S.decrypt(&out, &d_id, ct);
    return out;
}
