// SPDX-License-Identifier: MIT
//! RFC 9497 Appendix A.1 ("ristretto255-SHA512") official test vectors,
//! transcribed byte-exact from the RFC text (see `NOTICE`):
//!   - A.1.1  OPRF mode  (two batch-size-1 vectors)
//!   - A.1.2  VOPRF mode (two batch-size-1 vectors + one batch-size-2)
//!   - A.1.3  POPRF mode (two batch-size-1 vectors + one batch-size-2)
//! All three modes share the same `Seed` and `KeyInfo`; each mode
//! derives its own `skSm`/`pkSm` via §3.2.1 `DeriveKeyPair`.
//! Also carries RFC 9380 Appendix K.3 `expand_message_xmd(SHA-512)`
//! vectors for a standalone check of this module's `expandMessageXmd`.

const std = @import("std");

fn h(comptime s: []const u8) [s.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(20_000);
        var out: [s.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, s) catch unreachable;
        return out;
    }
}

// ── shared key-derivation inputs (Appendix A.1.1/A.1.2/A.1.3 headers) ────

/// `Seed` — identical for all three modes.
pub const seed = h("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");

/// `KeyInfo` = "test key".
pub const key_info = h("74657374206b6579");

// ── vector record types ──────────────────────────────────────────────────

pub const OprfVector = struct {
    input: []const u8,
    blind: [32]u8,
    blinded_element: [32]u8,
    evaluation_element: [32]u8,
    output: [64]u8,
};

pub const VoprfVector = struct {
    input: []const u8,
    blind: [32]u8,
    blinded_element: [32]u8,
    evaluation_element: [32]u8,
    proof: [64]u8,
    proof_random_scalar: [32]u8,
    output: [64]u8,
};

/// Batch-size-2 vector (A.1.2.3 / A.1.3.3): one proof covers both items.
pub const BatchVector = struct {
    input: [2][]const u8,
    blind: [2][32]u8,
    blinded_element: [2][32]u8,
    evaluation_element: [2][32]u8,
    proof: [64]u8,
    proof_random_scalar: [32]u8,
    output: [2][64]u8,
};

pub const PoprfVector = struct {
    input: []const u8,
    info: []const u8,
    blind: [32]u8,
    blinded_element: [32]u8,
    evaluation_element: [32]u8,
    proof: [64]u8,
    proof_random_scalar: [32]u8,
    output: [64]u8,
};

pub const PoprfBatchVector = struct {
    input: [2][]const u8,
    info: []const u8,
    blind: [2][32]u8,
    blinded_element: [2][32]u8,
    evaluation_element: [2][32]u8,
    proof: [64]u8,
    proof_random_scalar: [32]u8,
    output: [2][64]u8,
};

// The two client inputs used by every mode's vectors.
const input_1 = h("00");
const input_2 = h("5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a");

// ── A.1.1 OPRF mode ──────────────────────────────────────────────────────

pub const oprf_sk = h("5ebcea5ee37023ccb9fc2d2019f9d7737be85591ae8652ffa9ef0f4d37063b0e");

pub const oprf_vectors = [_]OprfVector{
    // A.1.1.1 Test Vector 1, Batch Size 1
    .{
        .input = &input_1,
        .blind = h("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
        .blinded_element = h("609a0ae68c15a3cf6903766461307e5c8bb2f95e7e6550e1ffa2dc99e412803c"),
        .evaluation_element = h("7ec6578ae5120958eb2db1745758ff379e77cb64fe77b0b2d8cc917ea0869c7e"),
        .output = h("527759c3d9366f277d8c6020418d96bb393ba2afb20ff90df23fb7708264e2f3ab9135e3bd69955851de4b1f9fe8a0973396719b7912ba9ee8aa7d0b5e24bcf6"),
    },
    // A.1.1.2 Test Vector 2, Batch Size 1
    .{
        .input = &input_2,
        .blind = h("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
        .blinded_element = h("da27ef466870f5f15296299850aa088629945a17d1f5b7f5ff043f76b3c06418"),
        .evaluation_element = h("b4cbf5a4f1eeda5a63ce7b77c7d23f461db3fcab0dd28e4e17cecb5c90d02c25"),
        .output = h("f4a74c9c592497375e796aa837e907b1a045d34306a749db9f34221f7e750cb4f2a6413a6bf6fa5e19ba6348eb673934a722a7ede2e7621306d18951e7cf2c73"),
    },
};

// ── A.1.2 VOPRF mode ─────────────────────────────────────────────────────

pub const voprf_sk = h("e6f73f344b79b379f1a0dd37e07ff62e38d9f71345ce62ae3a9bc60b04ccd909");
pub const voprf_pk = h("c803e2cc6b05fc15064549b5920659ca4a77b2cca6f04f6b357009335476ad4e");

pub const voprf_vectors = [_]VoprfVector{
    // A.1.2.1 Test Vector 1, Batch Size 1
    .{
        .input = &input_1,
        .blind = h("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
        .blinded_element = h("863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"),
        .evaluation_element = h("aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e"),
        .proof = h("ddef93772692e535d1a53903db24367355cc2cc78de93b3be5a8ffcc6985dd066d4346421d17bf5117a2a1ff0fcb2a759f58a539dfbe857a40bce4cf49ec600d"),
        .proof_random_scalar = h("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
        .output = h("b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c"),
    },
    // A.1.2.2 Test Vector 2, Batch Size 1
    .{
        .input = &input_2,
        .blind = h("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
        .blinded_element = h("cc0b2a350101881d8a4cba4c80241d74fb7dcbfde4a61fde2f91443c2bf9ef0c"),
        .evaluation_element = h("60a59a57208d48aca71e9e850d22674b611f752bed48b36f7a91b372bd7ad468"),
        .proof = h("401a0da6264f8cf45bb2f5264bc31e109155600babb3cd4e5af7d181a2c9dc0a67154fabf031fd936051dec80b0b6ae29c9503493dde7393b722eafdf5a50b02"),
        .proof_random_scalar = h("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
        .output = h("8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6"),
    },
};

/// A.1.2.3 Test Vector 3, Batch Size 2.
pub const voprf_batch = BatchVector{
    .input = .{ &input_1, &input_2 },
    .blind = .{
        h("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
        h("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
    },
    .blinded_element = .{
        h("863f330cc1a1259ed5a5998a23acfd37fb4351a793a5b3c090b642ddc439b945"),
        h("90a0145ea9da29254c3a56be4fe185465ebb3bf2a1801f7124bbbadac751e654"),
    },
    .evaluation_element = .{
        h("aa8fa048764d5623868679402ff6108d2521884fa138cd7f9c7669a9a014267e"),
        h("cc5ac221950a49ceaa73c8db41b82c20372a4c8d63e5dded2db920b7eee36a2a"),
    },
    .proof = h("cc203910175d786927eeb44ea847328047892ddf8590e723c37205cb74600b0a5ab5337c8eb4ceae0494c2cf89529dcf94572ed267473d567aeed6ab873dee08"),
    .proof_random_scalar = h("419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c"),
    .output = .{
        h("b58cfbe118e0cb94d79b5fd6a6dafb98764dff49c14e1770b566e42402da1a7da4d8527693914139caee5bd03903af43a491351d23b430948dd50cde10d32b3c"),
        h("8a9a2f3c7f085b65933594309041fc1898d42d0858e59f90814ae90571a6df60356f4610bf816f27afdd84f47719e480906d27ecd994985890e5f539e7ea74b6"),
    },
};

// ── A.1.3 POPRF mode ─────────────────────────────────────────────────────

pub const poprf_sk = h("145c79c108538421ac164ecbe131942136d5570b16d8bf41a24d4337da981e07");
pub const poprf_pk = h("c647bef38497bc6ec077c22af65b696efa43bff3b4a1975a3e8e0a1c5a79d631");

/// `Info` = "test info".
const poprf_info = h("7465737420696e666f");

pub const poprf_vectors = [_]PoprfVector{
    // A.1.3.1 Test Vector 1, Batch Size 1
    .{
        .input = &input_1,
        .info = &poprf_info,
        .blind = h("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
        .blinded_element = h("c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715"),
        .evaluation_element = h("1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874"),
        .proof = h("41ad1a291aa02c80b0915fbfbb0c0afa15a57e2970067a602ddb9e8fd6b7100de32e1ecff943a36f0b10e3dae6bd266cdeb8adf825d86ef27dbc6c0e30c52206"),
        .proof_random_scalar = h("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
        .output = h("ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221"),
    },
    // A.1.3.2 Test Vector 2, Batch Size 1
    .{
        .input = &input_2,
        .info = &poprf_info,
        .blind = h("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
        .blinded_element = h("f0f0b209dd4d5f1844dac679acc7761b91a2e704879656cb7c201e82a99ab07d"),
        .evaluation_element = h("8c3c9d064c334c6991e99f286ea2301d1bde170b54003fb9c44c6d7bd6fc1540"),
        .proof = h("4c39992d55ffba38232cdac88fe583af8a85441fefd7d1d4a8d0394cd1de77018bf135c174f20281b3341ab1f453fe72b0293a7398703384bed822bfdeec8908"),
        .proof_random_scalar = h("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
        .output = h("7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507"),
    },
};

/// A.1.3.3 Test Vector 3, Batch Size 2.
pub const poprf_batch = PoprfBatchVector{
    .input = .{ &input_1, &input_2 },
    .info = &poprf_info,
    .blind = .{
        h("64d37aed22a27f5191de1c1d69fadb899d8862b58eb4220029e036ec4c1f6706"),
        h("222a5e897cf59db8145db8d16e597e8facb80ae7d4e26d9881aa6f61d645fc0e"),
    },
    .blinded_element = .{
        h("c8713aa89241d6989ac142f22dba30596db635c772cbf25021fdd8f3d461f715"),
        h("423a01c072e06eb1cce96d23acce06e1ea64a609d7ec9e9023f3049f2d64e50c"),
    },
    .evaluation_element = .{
        h("1a4b860d808ff19624731e67b5eff20ceb2df3c3c03b906f5693e2078450d874"),
        h("aa1f16e903841036e38075da8a46655c94fc92341887eb5819f46312adfc0504"),
    },
    .proof = h("43fdb53be399cbd3561186ae480320caa2b9f36cca0e5b160c4a677b8bbf4301b28f12c36aa8e11e5a7ef551da0781e863a6dc8c0b2bf5a149c9e00621f02006"),
    .proof_random_scalar = h("419c4f4f5052c53c45f3da494d2b67b220d02118e0857cdbcf037f9ea84bbe0c"),
    .output = .{
        h("ca688351e88afb1d841fde4401c79efebb2eb75e7998fa9737bd5a82a152406d38bd29f680504e54fd4587eddcf2f37a2617ac2fbd2993f7bdf45442ace7d221"),
        h("7c6557b276a137922a0bcfc2aa2b35dd78322bd500235eb6d6b6f91bc5b56a52de2d65612d503236b321f5d0bebcbc52b64b92e426f29c9b8b69f52de98ae507"),
    },
};

// ── RFC 9380 Appendix K.3 expand_message_xmd(SHA-512) vectors ────────────
// (len_in_bytes = 0x20 subset — the ell == 1 case this module implements)

pub const XmdVector = struct {
    msg: []const u8,
    uniform_bytes: [32]u8,
};

pub const xmd_dst = "QUUX-V01-CS02-with-expander-SHA512-256";

pub const xmd_vectors = [_]XmdVector{
    .{
        .msg = "",
        .uniform_bytes = h("6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba"),
    },
    .{
        .msg = "abc",
        .uniform_bytes = h("0da749f12fbe5483eb066a5f595055679b976e93abe9be6f0f6318bce7aca8dc"),
    },
    .{
        .msg = "abcdef0123456789",
        .uniform_bytes = h("087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58"),
    },
};

test "vector shapes are sane" {
    try std.testing.expectEqual(@as(usize, 32), seed.len);
    try std.testing.expectEqual(@as(usize, 8), key_info.len);
    try std.testing.expectEqual(@as(usize, 1), input_1.len);
    try std.testing.expectEqual(@as(usize, 17), input_2.len);
    try std.testing.expectEqual(@as(usize, 2), oprf_vectors.len);
    try std.testing.expectEqual(@as(usize, 2), voprf_vectors.len);
    try std.testing.expectEqual(@as(usize, 2), poprf_vectors.len);
}
