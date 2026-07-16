// SPDX-License-Identifier: MIT
//! Official test vectors for the `BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_`
//! ciphersuite, transcribed verbatim (hex case preserved as published)
//! from `mattrglobal/pairing_crypto`, commit `b91a807d6a2d1d3bb039f2d67
//! a53e21b686b7395`, path `tests/fixtures/bbs/bls12_381_sha_256/` — a
//! reference implementation's OFFICIAL fixture directory whose
//! signature/proof vectors are confirmed (see `../SPEC.md`) to match
//! draft-irtf-cfrg-bbs-signatures-**04** (not the current draft-10 —
//! the ProofGen/Sign wire format changed at drafts 05/06 respectively;
//! see `../SPEC.md`'s version-pinning note for the byte-level evidence).
//! This is a public reference implementation's test-vector JSON, not a
//! copyrightable algorithm description — see `../NOTICE`.
//!
//! All hex strings are exactly as published (lowercase, no `0x`
//! prefix). `messages` (§7.2 of the draft, reproduced in every fixture
//! that signs/proves more than one message) are the SAME 10 messages
//! across every fixture in this file.

/// `key_material`/`key_info`/`SK`/`PK` — `keypair.json`. `keyGen` is
/// REAL and ungated (`keys.zig`); this is a straight KAT, not a
/// Fable-gated fixture.
pub const keypair = struct {
    pub const key_material = "746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579";
    pub const key_info = "746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e";
    pub const sk = "60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc";
    pub const pk = "a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c";
};

/// `generators.json` — `BP` (= `ciphersuite.P1`, the special-seeded
/// generator), `Q1` (the standard sequence's generator_1), and 10
/// `MsgGenerators` (`H_1..H_10`, `createGenerators(11)[1..]`). REAL and
/// ungated (`ciphersuite.createGenerators`/`createGeneratorsWithSeed`).
pub const generators = struct {
    pub const bp = "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9";
    pub const q1 = "a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be";
    pub const msg_generators = [_][]const u8{
        "98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4",
        "a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a",
        "b479263445f4d2108965a9086f9d1fdc8cde77d14a91c856769521ad3344754cc5ce90d9bc4c696dffbc9ef1d6ad1b62",
        "ac0401766d2128d4791d922557c7b4d1ae9a9b508ce266575244a8d6f32110d7b0b7557b77604869633bb49afbe20035",
        "b95d2898370ebc542857746a316ce32fa5151c31f9b57915e308ee9d1de7db69127d919e984ea0747f5223821b596335",
        "8f19359ae6ee508157492c06765b7df09e2e5ad591115742f2de9c08572bb2845cbf03fd7e23b7f031ed9c7564e52f39",
        "abc914abe2926324b2c848e8a411a2b6df18cbe7758db8644145fefb0bf0a2d558a8c9946bd35e00c69d167aadf304c1",
        "80755b3eb0dd4249cbefd20f177cee88e0761c066b71794825c9997b551f24051c352567ba6c01e57ac75dff763eaa17",
        "82701eb98070728e1769525e73abff1783cedc364adb20c05c897a62f2ab2927f86f118dcb7819a7b218d8f3fee4bd7f",
        "a1f229540474f4d6f1134761b92b788128c7ac8dc9b0c52d59493132679673032ac7db3fb3d79b46b13c1c41ee495bca",
    };
};

/// `h2s.json` — a single `hash_to_scalar(message, h2s_dst)` worked
/// example. NOTE: this specific worked example is published unchanged
/// across every draft revision from -03 through -10 (see `SPEC.md`),
/// so it is not itself draft-04-version-sensitive.
pub const h2s = struct {
    pub const message = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02";
    pub const scalar = "0f90cbee27beb214e6545becb8404640d3612da5d6758dffeccd77ed7169807c";
};

/// `MapMessageToScalarAsHash.json` — `messages_to_scalars`, one
/// (message, scalar) pair per §7.2 message `m_1..m_10`.
pub const map_message_to_scalar = [_]struct { message: []const u8, scalar: []const u8 }{
    .{ .message = "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02", .scalar = "1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430" },
    .{ .message = "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80", .scalar = "154249d503c093ac2df516d4bb88b510d54fd97e8d7121aede420a25d9521952" },
    .{ .message = "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73", .scalar = "0c7c4c85cdab32e6fdb0de267b16fa3212733d4e3a3f0d0f751657578b26fe22" },
    .{ .message = "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c", .scalar = "4a196deafee5c23f630156ae13be3e46e53b7e39094d22877b8cba7f14640888" },
    .{ .message = "496694774c5604ab1b2544eababcf0f53278ff50", .scalar = "34c5ea4f2ba49117015a02c711bb173c11b06b3f1571b88a2952b93d0ed4cf7e" },
    .{ .message = "515ae153e22aae04ad16f759e07237b4", .scalar = "4045b39b83055cd57a4d0203e1660800fabe434004dbdc8730c21ce3f0048b08" },
    .{ .message = "d183ddc6e2665aa4e2f088af", .scalar = "064621da4377b6b1d05ecc37cf3b9dfc94b9498d7013dc5c4a82bf3bb1750743" },
    .{ .message = "ac55fb33a75909ed", .scalar = "34ac9196ace0a37e147e32319ea9b3d8cc7d21870d3c3ba071246859cca49b02" },
    .{ .message = "96012096", .scalar = "57eb93f417c43200e9784fa5ea5a59168d3dbc38df707a13bb597c871b2a5f74" },
    .{ .message = "", .scalar = "08e3afeb2b4f2b5f907924ef42856616e6f2d5f1fb373736db1cca32707a7d16" },
};

/// §7.2's 10 messages, in order — used by the multi-message
/// signature/proof fixtures below.
pub const messages = [_][]const u8{
    "9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02",
    "c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80",
    "7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73",
    "77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c",
    "496694774c5604ab1b2544eababcf0f53278ff50",
    "515ae153e22aae04ad16f759e07237b4",
    "d183ddc6e2665aa4e2f088af",
    "ac55fb33a75909ed",
    "96012096",
    "",
};

pub const header = "11223344556677889900aabbccddeeff";
pub const presentation_header = "bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501";

/// `mockedRng.json` — `seeded_random_scalars(SEED, 10)` under this
/// ciphersuite's `MOCK_RANDOM_SCALARS_DST_`. `seed` decodes to the
/// ASCII string `"3.141592653589793238462643383279"` (the first 30
/// digits of pi — a nothing-up-my-sleeve value), confirmed (from
/// `mattrglobal/pairing_crypto`'s `tools/bbs-fixtures-generator/src/
/// mock_rng.rs`) to be the SAME seed reused — with a DIFFERENT `count =
/// 3 + U` each time — for every `proof*.json` fixture in this
/// directory; see `../SPEC.md`.
pub const mocked_rng = struct {
    pub const seed_hex = "332e313431353932363533353839373933323338343632363433333833323739";
    pub const seed_ascii = "3.141592653589793238462643383279";
    pub const dst = "4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4d4f434b5f52414e444f4d5f5343414c4152535f4453545f";
    pub const count = 10;
    pub const mocked_scalars = [_][]const u8{
        "04f8e2518993c4383957ad14eb13a023c4ad0c67d01ec86eeb902e732ed6df3f",
        "5d87c1ba64c320ad601d227a1b74188a41a100325cecf00223729863966392b1",
        "0444607600ac70482e9c983b4b063214080b9e808300aa4cc02a91b3a92858fe",
        "548cd11eae4318e88cda10b4cd31ae29d41c3a0b057196ee9cf3a69d471e4e94",
        "2264b06a08638b69b4627756a62f08e0dc4d8240c1b974c9c7db779a769892f4",
        "4d99352986a9f8978b93485d21525244b21b396cf61f1d71f7c48e3fbc970a42",
        "5ed8be91662386243a6771fbdd2c627de31a44220e8d6f745bad5d99821a4880",
        "62ff1734b939ddd87beeb37a7bbcafa0a274cbc1b07384198f0e88398272208d",
        "05c2a0af016df58e844db8944082dcaf434de1b1e2e7136ec8a99b939b716223",
        "485e2adab17b76f5334c95bf36c03ccf91cef77dcfcdc6b8a69e2090b3156663",
    };
};

/// `signature/signature001.json` — single message (`messages[0]`),
/// valid.
pub const signature001 = struct {
    pub const case_name = "valid single message signature";
    pub const msgs = messages[0..1];
    pub const signature = "88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103";
    pub const valid = true;
};

/// `signature/signature002.json` — signature001's EXACT bytes, verified
/// against a DIFFERENT (single empty) message — "modified message"
/// tamper case, expects `false`.
pub const signature002 = struct {
    pub const case_name = "invalid single message signature (modified message)";
    pub const msgs = [_][]const u8{""};
    pub const signature = signature001.signature; // reused verbatim
    pub const valid = false;
};

/// `signature/signature004.json` — all 10 messages, valid.
pub const signature004 = struct {
    pub const case_name = "valid multi-message signature";
    pub const msgs = messages[0..];
    pub const signature = "895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e";
    pub const valid = true;
};

/// `proof/proof001.json` — single message (`messages[0]`), disclosed
/// index `{0}` (fully revealed), `U = 0` so `random_scalars.len = 3`.
/// Valid.
pub const proof001 = struct {
    pub const case_name = "valid single message signature, single-message revealed proof";
    pub const msgs = messages[0..1];
    pub const disclosed_indexes = [_]usize{0};
    pub const disclosed_messages = messages[0..1];
    pub const random_scalars_count = 3;
    pub const proof = "8e9bc91d68151e4b105ec0d46ca95fe1526672bed27b26541a648ec990b3b11b8905e671fb981f1b9cd1ed64167a7ba18b7697d9bd6f3cac02f75551f2db95bf2707e3790c10d815346a96198327cc7048f220bdc7d6fc5ec41c6d9f89d607ff6ef2eef19447b3e34a14660eedb8b4f6189f202a4fef22e60dd23041e2761a9f18701019b520ed3ccf07a298e349222ab059e7ebd84c65e3a2127ec42f5f357c27d5601b2193b697a576fd9bd896c25a75004f6604a98707741916769c49175f";
    pub const valid = true;
};

/// `proof/proof003.json` — all 10 messages signed, disclosed indexes
/// `{0, 2, 4, 6}` (`U = 6` undisclosed, `random_scalars.len = 9`).
/// Valid.
pub const proof003 = struct {
    pub const case_name = "valid multi-message signature, multiple messages revealed proof";
    pub const msgs = messages[0..];
    pub const disclosed_indexes = [_]usize{ 0, 2, 4, 6 };
    pub const disclosed_messages = [_][]const u8{ messages[0], messages[2], messages[4], messages[6] };
    pub const random_scalars_count = 9;
    pub const proof = "812a204f66c9084feed7383894d910f2c17399b3c4b4bed05660921de8539f5042318c356609496a6ca0a26626661be78ca723b7182ccd314924b93a3997654fcd77e29e3847dc881f422a751017705173ec094d2997221e134710d4fff1bd33111a4b4fc79a2201d18b5cc63fab1252def0d4f020129c7e022f56f505aa977a7240da430bc60a2d4d17897b42228054a2fb4f780fb710268ebea24c9fb0e15e2ac415b99a232b13bfd215af3fb35f5518953eaccc200555eaa69ae434eb623f0a83bb57a8a8e70ba37761ffaeb756d9115c1177ce929f04be23b5636120c7ac0a73546f177a3c3be2d233b3253f31c3468260723c1afa2d0febd38161e16ed0147369bda8b05ec3f6183239c6ecb9fb54b0989160e8cdf8b9f0cf4a46a2150232d96c466fad2d60ff067492c52cc6af1d16e62364ed6d3dc19feaf1fcf9c12750301c2de6541c0edce5ede7425f75e01fd94a7e6137ebf23460bf3f1afec9f21767c467fdd882eb038492a390ee5d0c0f72f50f2ac5cedb705fc465f7bc093b";
    pub const valid = true;
};

/// `proof/proof004.json` — proof003's EXACT proof bytes, verified with
/// a DIFFERENT presentation header — "different presentation header"
/// tamper case, expects `false`.
pub const proof004 = struct {
    pub const case_name = "invalid multi-message signature, all messages revealed proof (different presentation header)";
    pub const msgs = proof003.msgs;
    pub const disclosed_indexes = proof003.disclosed_indexes;
    pub const disclosed_messages = proof003.disclosed_messages;
    pub const presentation_header_tampered = "011594ba7f95b3b470ea4102dd5899de3a042e5104d3ea01d15e6780d831d2be";
    pub const proof = proof003.proof; // reused verbatim
    pub const valid = false;
};
