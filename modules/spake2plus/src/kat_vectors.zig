// SPDX-License-Identifier: MIT
//! RFC 9383 Appendix C's OFFICIAL test vector for the
//! `P256-SHA256-HKDF-SHA256-HMAC-SHA256` ciphersuite (the first entry in
//! Appendix C — RFC 9383 publishes one vector per ciphersuite; this is
//! the ONLY one for P-256/SHA-256, so there is no "pick one of several"
//! choice to document). Transcribed byte-exact from the RFC 9383 text
//! (`https://www.rfc-editor.org/rfc/rfc9383.txt`, fetched 2026-07-12) —
//! see `../NOTICE` for the exact provenance/cross-check method.
//!
//! Appendix C's own framing: "the choice of PBKDF is omitted, and values
//! for w0 and w1 are provided directly" — so this vector does NOT
//! exercise `computeW0W1` (there is no raw PBKDF output published for
//! this ciphersuite); every OTHER function in `root.zig`'s public API
//! has a byte-exact target here.
//!
//! Every multi-byte field below was independently verified, OUTSIDE this
//! Zig module (Python, during vector transcription — see `../NOTICE`),
//! by reassembling `tt` from `context`/`id_prover`/`id_verifier`/
//! (M/N re-derived from RFC 9383 §4's own P-256 table)/`share_p`/
//! `share_v`/`z`/`v`/`w0` per `root.zig`'s `computeTranscript` field
//! order and 8-byte-little-endian length prefixes, and confirming the
//! reassembled bytes match `tt` below EXACTLY (570 bytes total) — this
//! is also re-verified INSIDE this Zig module, at test time, by
//! `kat_test.zig`'s "REAL TODAY" section (which calls the actual,
//! already-real `computeTranscript` function, not a re-implementation).
//!
//! `l`, `share_p`, `share_v`, `z`, `v` are all 65-byte UNCOMPRESSED SEC1
//! P-256 points (`0x04` prefix) — RFC 9383 Appendix C states this
//! encoding explicitly for its test vectors.

pub const Vector = struct {
    label: []const u8,
    context: []const u8, // raw bytes, not hex — RFC 9383's Context octet string
    id_prover: []const u8, // raw bytes, not hex
    id_verifier: []const u8, // raw bytes, not hex
    w0: []const u8, // 32 bytes, hex
    w1: []const u8, // 32 bytes, hex
    l: []const u8, // 65 bytes, hex, uncompressed SEC1 — L = w1*P
    x: []const u8, // 32 bytes, hex — Prover's ephemeral scalar
    share_p: []const u8, // 65 bytes, hex, uncompressed SEC1 — X = x*P + w0*M
    y: []const u8, // 32 bytes, hex — Verifier's ephemeral scalar
    share_v: []const u8, // 65 bytes, hex, uncompressed SEC1 — Y = y*P + w0*N
    z: []const u8, // 65 bytes, hex, uncompressed SEC1
    v: []const u8, // 65 bytes, hex, uncompressed SEC1
    tt: []const u8, // 570 bytes, hex — the assembled transcript
    k_main: []const u8, // 32 bytes, hex
    k_confirm_p: []const u8, // 32 bytes, hex
    k_confirm_v: []const u8, // 32 bytes, hex
    confirm_p: []const u8, // 32 bytes, hex — HMAC(K_confirmP, shareV)
    confirm_v: []const u8, // 32 bytes, hex — HMAC(K_confirmV, shareP)
    k_shared: []const u8, // 32 bytes, hex
};

pub const vectors = [_]Vector{
    .{
        .label = "RFC 9383 Appendix C, P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors",
        .context = "SPAKE2+-P256-SHA256-HKDF-SHA256-HMAC-SHA256 Test Vectors",
        .id_prover = "client",
        .id_verifier = "server",
        .w0 = "bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3",
        .w1 = "7e945f34d78785b8a3ef44d0df5a1a97d6b3b460409a345ca7830387a74b1dba",
        .l = "04eb7c9db3d9a9eb1f8adab81b5794c1f13ae3e225efbe91ea487425854c7fc00f00bfedcbd09b2400142d40a14f2064ef31dfaa903b91d1faea7093d835966efd",
        .x = "d1232c8e8693d02368976c174e2088851b8365d0d79a9eee709c6a05a2fad539",
        .share_p = "04ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727",
        .y = "717a72348a182085109c8d3917d6c43d59b224dc6a7fc4f0483232fa6516d8b3",
        .share_v = "04c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048",
        .z = "04bbfce7dd7f277819c8da21544afb7964705569bdf12fb92aa388059408d50091a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd559946ab474356c41839",
        .v = "0458bf27c6bca011c9ce1930e8984a797a3419797b936629a5a937cf2f11c8b9514b82b993da8a46e664f23db7c01edc87faa530db01c2ee405230b18997f16b68",
        .tt = "38000000000000005350414b45322b2d503235362d5348413235362d484b44462d5348413235362d484d41432d534841323536205465737420566563746f72730600000000000000636c69656e740600000000000000736572766572410000000000000004886e2f97ace46e55ba9dd7242579f2993b64e16ef3dcab95afd497333d8fa12f5ff355163e43ce224e0b0e65ff02ac8e5c7be09419c785e0ca547d55a12e2d20410000000000000004d8bbd6c639c62937b04d997f38c3770719c629d7014d49a24b4f98baa1292b4907d60aa6bfade45008a636337f5168c64d9bd36034808cd564490b1e656edbe7410000000000000004ef3bd051bf78a2234ec0df197f7828060fe9856503579bb1733009042c15c0c1de127727f418b5966afadfdd95a6e4591d171056b333dab97a79c7193e341727410000000000000004c0f65da0d11927bdf5d560c69e1d7d939a05b0e88291887d679fcadea75810fb5cc1ca7494db39e82ff2f50665255d76173e09986ab46742c798a9a68437b048410000000000000004bbfce7dd7f277819c8da21544afb7964705569bdf12fb92aa388059408d50091a0c5f1d3127f56813b5337f9e4e67e2ca633117a4fbd559946ab474356c4183941000000000000000458bf27c6bca011c9ce1930e8984a797a3419797b936629a5a937cf2f11c8b9514b82b993da8a46e664f23db7c01edc87faa530db01c2ee405230b18997f16b682000000000000000bb8e1bbcf3c48f62c08db243652ae55d3e5586053fca77102994f23ad95491b3",
        .k_main = "4c59e1ccf2cfb961aa31bd9434478a1089b56cd11542f53d3576fb6c2a438a29",
        .k_confirm_p = "871ae3f7b78445e34438fb284504240239031c39d80ac23eb5ab9be5ad6db58a",
        .k_confirm_v = "ccd53c7c1fa37b64a462b40db8be101cedcf838950162902054e644b400f1680",
        .confirm_p = "926cc713504b9b4d76c9162ded04b5493e89109f6d89462cd33adc46fda27527",
        .confirm_v = "9747bcc4f8fe9f63defee53ac9b07876d907d55047e6ff2def2e7529089d3e68",
        .k_shared = "0c5f8ccd1413423a54f6c1fb26ff01534a87f893779c6e68666d772bfd91f3e7",
    },
};
