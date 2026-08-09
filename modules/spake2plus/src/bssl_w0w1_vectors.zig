// SPDX-License-Identifier: MIT
//! Frozen cross-implementation vectors for `computeW0W1`, captured from
//! BoringSSL's SPAKE2+ (`bssl::spake2plus::Register`). Audit finding
//! `spake2plus` F1.
//!
//! RFC 9383 Appendix C states "the choice of PBKDF is omitted, and values
//! for w0 and w1 are provided directly", so `kat_vectors.zig`'s official
//! vector starts *after* `computeW0W1` and cannot exercise it. This file is
//! that missing oracle: BoringSSL performs the identical RFC 9383 3.2
//! construction -- an 80-byte KDF output split into two 40-byte big-endian
//! halves, each wide-reduced mod the P-256 group order -- so its outputs
//! pin ours byte for byte.
//!
//! ## Provenance
//!
//! * Reference:  BoringSSL `crypto/spake2plus/spake2plus.cc`, commit
//!               `922245af6eda11b3f101ab5f542093eb5e7d1a74` (2026-08-07).
//! * Licence:    Apache-2.0 (The BoringSSL Authors). Nothing from it is
//!               copied or translated into this repo -- it was built, *run*,
//!               and its outputs recorded, so no foreign condition attaches
//!               here and the root `NOTICE` is unaffected.
//! * Driver:     `~/.cache/zig-libs-spake2plus/capture_w0w1.cc` (outside the
//!               repo; zig-libs keeps zero external dependencies).
//! * Command:    `c++ -std=c++17 -O1 -o capture_w0w1 capture_w0w1.cc \`
//!               `  -I boringssl -I boringssl/include \`
//!               `  boringssl/build/libcrypto.a -lpthread`
//!               `./capture_w0w1 > modules/spake2plus/src/bssl_w0w1_vectors.zig`
//! * Captured:   2026-08-09.
//!
//! ## Two sets
//!
//! `registration` -- `bssl::spake2plus::Register()` driven end to end. It
//! derives its own 80-byte KDF output (scrypt N=32768, r=8, p=1 over the
//! u64-little-endian length-prefixed password/idProver/idVerifier) and does
//! not expose it, so the driver rebuilt that input with the same public
//! `EVP_PBE_scrypt` call and required the reduction of the result to equal
//! Register's own `w0`/`w1` before emitting anything -- the `pbkdf_output`
//! below is therefore provably the one Register used. `l` is Register's
//! registration record, an uncompressed SEC1 `w1xP`, which also anchors
//! `computeL`.
//!
//! `boundary` -- the same reduction (BoringSSL's `bn_big_endian_to_words` +
//! `ec_scalar_reduce`, the two lines `Register` itself uses) on chosen
//! halves: 0, 1, n-1, n, n+1, 2^256-1, 2^320-1. A scrypt output is a random
//! 320-bit number and never lands near the modulus, so without these the
//! anchor would say nothing about the reduction boundary -- which is the
//! part that is easy to get wrong, and the reason a canonical
//! `Scalar.fromBytes` (which rejects rather than reduces) is the wrong
//! primitive here.
//!
//! Both sets are plain hex data: the tests that read them run offline, need
//! no BoringSSL, and have no skip path.

/// One `Register()` run: everything BoringSSL reported for it.
pub const Registration = struct {
    note: []const u8,
    password: []const u8,
    id_prover: []const u8,
    id_verifier: []const u8,
    /// The 80-byte KDF output `Register` reduced (160 hex chars).
    pbkdf_output: []const u8,
    w0: []const u8,
    w1: []const u8,
    /// Registration record: uncompressed SEC1 `w1xP`.
    l: []const u8,
};

/// One chosen 80-byte input and the scalars BoringSSL reduces it to.
pub const Boundary = struct {
    note: []const u8,
    pbkdf_output: []const u8,
    w0: []const u8,
    w1: []const u8,
};

pub const registrations = [_]Registration{
    .{
        .note = "RFC 9383 3.2 registration, ASCII password + short identities",
        .password = "password",
        .id_prover = "client",
        .id_verifier = "server",
        .pbkdf_output = "d335dcea81adf07aa3c1672e5a72286e5d7c266698f3b4665f6a77e95ccbd328" ++
            "27502869dd0780129acee5486a0871ee2daffea4a38dd98078b55ceee691c4c7" ++
            "f6eb7ec257eeb0d8b39e1b54ed0c684f",
        .w0 = "256f57a8058e5b0994d7e3dec112369e896c3b8e407c13161214d3dd3a34ea1d",
        .w1 = "97b870919eb6824aa148a45d3d7b1d62106ae19eb586802b66fc757b636d0239",
        .l = "04e5e8a0bd90bc155a856d869efa3e3486e843d85b4e14cb74c86b099f426e07" ++
            "1ba8ad82edcede3ef8189f045a6065af83e78f7c58f837a0b5798df42390ee74" ++
            "5c",
    },
    .{
        .note = "empty password and empty identities (all three length prefixes zero)",
        .password = "",
        .id_prover = "",
        .id_verifier = "",
        .pbkdf_output = "2c804bf5d0ccb28051f20fb0b99bf7e9a45a67496650536018dd8839d9370748" ++
            "f1ac548a44dde14ef07f306c5fc7fe091054c6374d73d1a4f917a0fbcd8b88b8" ++
            "0308210f26ee8b454c9e5abd471a784c",
        .w0 = "22bec230bc4ef973b004549f04a9d88ede9449555c9fab1a32390d6a6f184ff8",
        .w1 = "701cc43efd2ca33038206c13fc70ade686d11f040825804edaed97a0739edc47",
        .l = "045ae4bef6eb05088e3e44353286f25a7f1364e8af50c09aee11045b20bb36e9" ++
            "1cc0367df38d685cb304c765a7bd4b25e8bd97f94bfa8c1289855f8f32832741" ++
            "bd",
    },
    .{
        .note = "long password and realistic identities",
        .password = "correct horse battery staple",
        .id_prover = "prover@example.com",
        .id_verifier = "verifier.example.com",
        .pbkdf_output = "67d6b277cb91b85601bfeaaef4483ec1e70d1ce0041de502194192bbe87f9ed5" ++
            "a66be03b81c721a4022a25e4eab5471f2986d04d9535f6621ce45f5d2e1f7e19" ++
            "df9cf4d5bc02c3720788a4fe5f4dc28e",
        .w0 = "cd51a303c0dfd3f5024473b57fa0d11f012b1aa30fc41ccc4e0face80d06b5c7",
        .w1 = "143c176ca856895e1d759d7150772973d94cf090b4e92522decb4294094eb04a",
        .l = "04ec4567b463322fd56d92b28e58b315c8590b5398a641db36a5836a24e3b121" ++
            "5ca7b5deacc1264bb1e8c8211425bf5c59fe28065a856c97eb0754cdba8f156e" ++
            "03",
    },
};

pub const boundaries = [_]Boundary{
    .{
        .note = "both halves zero -- w0 and w1 must both reduce to 0",
        .pbkdf_output = "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "00000000000000000000000000000000",
        .w0 = "0000000000000000000000000000000000000000000000000000000000000000",
        .w1 = "0000000000000000000000000000000000000000000000000000000000000000",
    },
    .{
        .note = "halves 0 and 1 -- the smallest nonzero scalar survives unchanged",
        .pbkdf_output = "0000000000000000000000000000000000000000000000000000000000000000" ++
            "0000000000000000000000000000000000000000000000000000000000000000" ++
            "00000000000000000000000000000001",
        .w0 = "0000000000000000000000000000000000000000000000000000000000000000",
        .w1 = "0000000000000000000000000000000000000000000000000000000000000001",
    },
    .{
        .note = "halves n-1 and n -- n-1 is unchanged, n wraps to 0",
        .pbkdf_output = "0000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84" ++
            "f3b9cac2fc6325500000000000000000ffffffff00000000ffffffffffffffff" ++
            "bce6faada7179e84f3b9cac2fc632551",
        .w0 = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550",
        .w1 = "0000000000000000000000000000000000000000000000000000000000000000",
    },
    .{
        .note = "halves n+1 and 2^256-1 -- both exceed a canonical scalar and must reduce, not be rejected",
        .pbkdf_output = "0000000000000000ffffffff00000000ffffffffffffffffbce6faada7179e84" ++
            "f3b9cac2fc6325520000000000000000ffffffffffffffffffffffffffffffff" ++
            "ffffffffffffffffffffffffffffffff",
        .w0 = "0000000000000000000000000000000000000000000000000000000000000001",
        .w1 = "00000000ffffffff00000000000000004319055258e8617b0c46353d039cdaae",
    },
    .{
        .note = "both halves 2^320-1 -- the largest input the format can carry",
        .pbkdf_output = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ++
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ++
            "ffffffffffffffffffffffffffffffff",
        .w0 = "fffffffe00000001431905529c0166cd22159165b6faae70f756a571fc632550",
        .w1 = "fffffffe00000001431905529c0166cd22159165b6faae70f756a571fc632550",
    },
    .{
        .note = "first half 2^320-1, second half 2 -- asymmetric, catches a swapped or duplicated half",
        .pbkdf_output = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ++
            "ffffffffffffffff000000000000000000000000000000000000000000000000" ++
            "00000000000000000000000000000002",
        .w0 = "fffffffe00000001431905529c0166cd22159165b6faae70f756a571fc632550",
        .w1 = "0000000000000000000000000000000000000000000000000000000000000002",
    },
};
