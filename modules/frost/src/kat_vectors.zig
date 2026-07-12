// SPDX-License-Identifier: MIT
//! The official RFC 9591 Appendix E.5 "FROST(secp256k1, SHA-256)" test
//! vector, transcribed verbatim (hex case preserved as published — RFC
//! 9591 uses lowercase hex throughout) from
//! https://www.rfc-editor.org/rfc/rfc9591.txt, Appendix E.5. This is the
//! RFC's own single published test vector for this ciphersuite — a public
//! specification artifact, not copied from any other implementation's test
//! suite; see `../NOTICE`.
//!
//! Only ONE ciphersuite (secp256k1/SHA-256) is embedded — RFC 9591
//! Appendix E also publishes FROST(Ed25519, SHA-512) (§E.1),
//! FROST(Ed448, SHAKE256) (§E.2), FROST(ristretto255, SHA-512) (§E.3),
//! and FROST(P-256, SHA-256) (§E.4) vectors; none of those are embedded
//! here (out of scope for this module — see `root.zig`'s module doc
//! comment).
//!
//! Vector shape (RFC 9591 Appendix E's own description, §"Test
//! Vectors"): configuration (`MAX_PARTICIPANTS`/`MIN_PARTICIPANTS`/
//! `NUM_PARTICIPANTS`), group input parameters (the trusted-dealer group
//! secret/public key, the message, and the ONE random Shamir coefficient
//! `share_polynomial_coefficients[1]` — this vector's polynomial has
//! degree `MIN_PARTICIPANTS - 1 = 1`, so exactly one non-constant
//! coefficient), all 3 participants' signing-key shares, both signing
//! participants' (P1, P3 — `participant_list: 1,3`; P2's share exists
//! only to be reconstructed FROM, never used to sign in this vector)
//! round-1 outputs (nonce randomness seeds, the resulting nonces, their
//! public commitments, the binding-factor input preimage, and the
//! resulting binding factor), both signers' round-2 signature shares,
//! and the final aggregate signature.
//!
//! IMPORTANT — read `root.zig`'s module doc comment's "what the vectors
//! do NOT cover" note: this ciphersuite's Appendix E.5 text does NOT
//! publish a standalone `group_commitment`/`challenge` scalar (unlike
//! `binding_factor_input`/`binding_factor`, which ARE published). Do not
//! add fields here for values the RFC text does not actually give.

pub const config = struct {
    pub const max_participants: u16 = 3;
    pub const min_participants: u16 = 2;
    pub const num_participants: u16 = 2;
    /// The two signers that actually sign in this vector (P2's share is
    /// only used for the `secretShareCombine`/reconstruction check).
    pub const participant_list = [_]u16{ 1, 3 };
};

pub const group = struct {
    pub const secret_key = "0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114";
    pub const public_key = "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f";
    pub const message = "74657374"; // ASCII "test"
    /// `share_polynomial_coefficients[1]` — the ONE random (non-constant)
    /// Shamir coefficient for this degree-1 (`min_participants - 1 = 1`)
    /// polynomial. The 0th coefficient is the group secret key itself
    /// (RFC 9591 Appendix E's own framing: "Note that the 0-th
    /// coefficient is omitted, as this is equal to the group secret
    /// key").
    pub const coefficient_1 = "fbf85eadae3058ea14f19148bb72b45e4399c0b16028acaf0395c9b03c823579";
};

/// All 3 trusted-dealer shares (`P2`'s is never used to sign in this
/// vector — only in `secretShareCombine`/reconstruction checks).
pub const participant_shares = struct {
    pub const p1 = "08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c";
    pub const p2 = "04f0feac2edcedc6ce1253b7fab8c86b856a797f44d83d82a385554e6e401984";
    pub const p3 = "00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc";
};

/// Round-1 outputs for signer P1 (identifier 1).
pub const round1_p1 = struct {
    pub const hiding_nonce_randomness = "7ea5ed09af19f6ff21040c07ec2d2adbd35b759da5a401d4c99dd26b82391cb2";
    pub const binding_nonce_randomness = "47acab018f116020c10cb9b9abdc7ac10aae1b48ca6e36dc15acb6ec9be5cdc5";
    pub const hiding_nonce = "841d3a6450d7580b4da83c8e618414d0f024391f2aeb511d7579224420aa81f0";
    pub const binding_nonce = "8d2624f532af631377f33cf44b5ac5f849067cae2eacb88680a31e77c79b5a80";
    pub const hiding_nonce_commitment = "03c699af97d26bb4d3f05232ec5e1938c12f1e6ae97643c8f8f11c9820303f1904";
    pub const binding_nonce_commitment = "02fa2aaccd51b948c9dc1a325d77226e98a5a3fe65fe9ba213761a60123040a45e";
    pub const binding_factor_input = "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4fff9b5210ffbb3c07a73a7c8935be4a8c62cf015f6cf7ade6efac09a6513540fc3f5a816aaebc2114a811a415d7a55db7c5cbc1cf27183e79dd9def941b5d48010000000000000000000000000000000000000000000000000000000000000001";
    pub const binding_factor = "3e08fe561e075c653cbfd46908a10e7637c70c74f0a77d5fd45d1a750c739ec6";
};

/// Round-1 outputs for signer P3 (identifier 3).
pub const round1_p3 = struct {
    pub const hiding_nonce_randomness = "e6cc56ccbd0502b3f6f831d91e2ebd01c4de0479e0191b66895a4ffd9b68d544";
    pub const binding_nonce_randomness = "7203d55eb82a5ca0d7d83674541ab55f6e76f1b85391d2c13706a89a064fd5b9";
    pub const hiding_nonce = "2b19b13f193f4ce83a399362a90cdc1e0ddcd83e57089a7af0bdca71d47869b2";
    pub const binding_nonce = "7a443bde83dc63ef52dda354005225ba0e553243402a4705ce28ffaafe0f5b98";
    pub const hiding_nonce_commitment = "03077507ba327fc074d2793955ef3410ee3f03b82b4cdc2370f71d865beb926ef6";
    pub const binding_nonce_commitment = "02ad53031ddfbbacfc5fbda3d3b0c2445c8e3e99cbc4ca2db2aa283fa68525b135";
    pub const binding_factor_input = "02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4fff9b5210ffbb3c07a73a7c8935be4a8c62cf015f6cf7ade6efac09a6513540fc3f5a816aaebc2114a811a415d7a55db7c5cbc1cf27183e79dd9def941b5d48010000000000000000000000000000000000000000000000000000000000000003";
    pub const binding_factor = "93f79041bb3fd266105be251adaeb5fd7f8b104fb554a4ba9a0becea48ddbfd7";
};

/// Round-2 outputs (signature shares).
pub const round2 = struct {
    pub const p1_sig_share = "c4fce1775a1e141fb579944166eab0d65eefe7b98d480a569bbbfcb14f91c197";
    pub const p3_sig_share = "0160fd0d388932f4826d2ebcd6b9eaba734f7c71cf25b4279a4ca2581e47b18d";
};

/// The final aggregate signature: `SerializeElement(R) ||
/// SerializeScalar(z)`, 33 + 32 = 65 bytes.
pub const final_signature = "0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324";
