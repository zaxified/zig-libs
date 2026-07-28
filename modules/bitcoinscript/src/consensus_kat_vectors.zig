// SPDX-License-Identifier: MIT
//! **External** BIP341/BIP342 consensus test vectors, machine-extracted
//! (unmodified) from Bitcoin Core's own `script_assets_test.json` fuzz/unit
//! test corpus (used by Core's `src/test/script_tests.cpp`
//! `script_assets_test`), fetched from
//! `bitcoin-core/qa-assets:unit_test_data/script_assets_test.json`
//! (SHA-256 of the full 9,243,520-byte corpus this file was drawn from:
//! see the coordinator's fetch log; each entry below is reproduced
//! byte-for-byte from that file, only re-formatted as Zig source — no
//! byte was hand-edited).
//!
//! ## Why this file exists
//!
//! `tapscript_test.zig` and `e2e_test.zig` prove the BIP341/342
//! CHECKSIG/CHECKSIGADD/OP_SUCCESS/control-block wiring end-to-end via
//! **self-constructed** spends (this module signs, this module verifies —
//! see `tapscript_test.zig`'s own doc comment, which explicitly flags this
//! as "NOT byte-exact against an external transaction vector"). That
//! leaves the exact question a self-round-trip can never answer open: does
//! this module's taproot verifier agree with Bitcoin Core's on REAL
//! consensus transactions? These five vectors close that gap for a
//! representative slice of the taproot/tapscript surface:
//!
//! - `siglen_empty_keypath` — plain BIP341 key-path spend (single Schnorr
//!   signature, no script tree).
//! - `sighash_annex` — BIP342 script-path spend with a BIP341 annex
//!   present (5th/last witness item after the control block starts
//!   `0x50`).
//! - `opsuccess_bare` — a tapleaf whose script is a single `OP_SUCCESSx`
//!   opcode: the success witness makes it unconditionally valid regardless
//!   of any other stack content (BIP342's upgrade-hook short-circuit); the
//!   corresponding failure witness differs only in that opcode and must
//!   fail.
//! - `spendpath_padshortcontrol` — script-path spend whose SUCCESS control
//!   block is 33 bytes (`m=0` Merkle siblings, leaf-is-root — the
//!   "ordinary" degenerate tapscript shape) and whose FAILURE control
//!   block is 46 bytes (not `33 + 32m` for any `m`) — exercises control-
//!   block length validation, not signature/commitment math.
//! - `unkver_bare` — witness-program version 1 (taproot) output whose
//!   control block encodes an UNKNOWN leaf version: BIP341 mandates
//!   anyone-can-spend for unknown leaf versions (a future-upgrade
//!   escape hatch), so this is a distinct code path from all the above
//!   (`verifyTaprootScriptPath`'s unknown-leaf-version branch).
//!
//! Every entry below carries BOTH a `success` witness (must verify) and a
//! `failure` witness (must fail) for the SAME transaction/prevout/flags —
//! Core's own harness always checks both, so `consensus_kat_test.zig` does
//! too (this is what gives the KAT teeth: flipping a byte in a vector
//! should make the wrong side pass, not just make both sides fail).
//!
//! All five carry the exact same consensus flag set: `P2SH, DERSIG,
//! CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, WITNESS, NULLDUMMY, TAPROOT`
//! (Bitcoin Core's `script_assets_test.json` "flags" string for every
//! taproot-flagged entry we sampled) — `consensus_kat_test.zig` hardcodes
//! this one `ScriptFlags` value rather than parsing the flags string.

pub const Vector = struct {
    comment: []const u8,
    /// Raw transaction, hex.
    tx_hex: []const u8,
    /// One raw serialized `TxOut` (hex) per `tx`'s input, in `vin` order
    /// (BIP341 sighash commits to every input's spent output, not just
    /// the one being verified).
    prevout_hexes: []const []const u8,
    /// Which `vin` index is being verified.
    index: usize,
    /// Witness stack (hex per item, wire order) that MUST verify.
    success_witness: []const []const u8,
    /// Witness stack (hex per item, wire order) that MUST fail.
    failure_witness: []const []const u8,
};

pub const vectors = [_]Vector{
    .{
        .comment = "siglen_empty_keypath (BIP341 key-path spend)",
        .tx_hex = "f705d6e8019870958e85d1d8f94aa6d74746ba974db0f5ccae49a49b32dcada4e19de4eb5ecb00000000925977cc01f9875c000000000016001431d2b00cd4687ceb34008d9894de84062def14aa05406346",
        .prevout_hexes = &.{
            "b4eae1010000000022512039f7e9232896f8100485e38afa652044f855e734a13b840a3f220cbd5d911ad5",
        },
        .index = 0,
        .success_witness = &.{
            "25e45bd4d4b8fcd5933861355a2d376aad8daf1af1588e5fb6dfcea22d0d809acda6fadca11e97f5b5c85af99df27cb24fa69b08fa6c790234cdc671d3af5a7302",
        },
        .failure_witness = &.{
            "",
        },
    },
    .{
        .comment = "sighash_annex (BIP342 script-path spend, annex present)",
        .tx_hex = "6537379b01e96260b51bacbf3bcc52f9f8ef410ca6d3926436027a0898c35f96501eebbe65c901000000ff1175b7014270aa0100000000160014954fe6cd1fc37581fce98eaa194632e1e4bb09e4101e6e1f",
        .prevout_hexes = &.{
            "5f72d301000000002251205281483208ff3be80ab810528bb3ce4525fd0484f10e08ae24f61528d7ac96c5",
        },
        .index = 0,
        .success_witness = &.{
            "837692268bf0037a6ae20a815219666adb0b505161e72c4de74e340e3c4340e349a6a80b3c535c9552df9f4df0364d4f58591e0f9e7fd4592240746ca6172264",
            "2022920252427ba329d09db268924e0a8e26949c64596904ed9b4697d1d8d870d1acab",
            "c1744dc4ed84d14884a4fe357f0b63da5dd458a8b2f5da9bfaed149a5e99ed72bfc6138b4386f236f2f74e9386381a131800723e5b082c91856ecab471ed07c78e",
            "50",
        },
        .failure_witness = &.{
            "a3a775b2d2b273d0006be47fd88e166278b3a2a16874cacb755288de7545aa7e5b29b7c25c0e1eb862392ae361ccb297388ae6fe2aa016b60a6fd7d6d180412e81",
            "2022920252427ba329d09db268924e0a8e26949c64596904ed9b4697d1d8d870d1acab",
            "c1744dc4ed84d14884a4fe357f0b63da5dd458a8b2f5da9bfaed149a5e99ed72bfc6138b4386f236f2f74e9386381a131800723e5b082c91856ecab471ed07c78e",
            "50",
        },
    },
    .{
        .comment = "opsuccess_bare (BIP342 OP_SUCCESSx short-circuit)",
        .tx_hex = "9160bb9d014b16157e691626b48b15e870f15775622e605b8e58d848180f7e69f04dc8566c26010000004a2780d7019c39030100000000160014c31a74b8865860da9b7ecc883449a81cb89ff82658000000",
        .prevout_hexes = &.{
            "76a3c80100000000225120224bbf76723f58e9a569b65f822dd88007c52c0ff2312e693e187c1d08dba3a2",
        },
        .index = 0,
        .success_witness = &.{
            "7e",
            "c1b58b7b45fdaa7254ac3c0ae24b1c9bdb153c6ccbcba010a5e92ae1c8206502f63f60f1b1df11054959e125ddef6c4ca9c53f7f7b19c73a1cf987ee48c1771d07b01277f52423d3d6dbb37e49bee31da0311dc504b756bb94f3399412a994aa491d807ecbfa77d44159a605fbe9f58336e4bba039d2540992b310291192a4a7fa",
        },
        .failure_witness = &.{
            "61",
            "c1b58b7b45fdaa7254ac3c0ae24b1c9bdb153c6ccbcba010a5e92ae1c8206502f6316f539a24ef62b94c4ca6b92ef0b069dbf4fba4a06e41a897ce9195b2b0c8afd73b17a8d3ad6bba04cf32cb42258bd53c2679ef2eb99175cb2f072e6ac892c8612f21dcc83bb59be8c7ccc7ff584abd738bf75fab25e0885c026262aa04d17c",
        },
    },
    .{
        .comment = "spendpath_padshortcontrol (BIP342 script-path, Merkle control block)",
        .tx_hex = "0100000001421be753be706646e9576f46811d76ae273474ffdcafdb1759930380873bd222c100000000e2aee4f70141e9130000000000160014a321411a585947a215b13535bd4e50605722cbd9c07d8945",
        .prevout_hexes = &.{
            "257f86010000000022512044ebf2cbf4a1cd8c74bb7b5ee6adb118c0a6add945388fded74bc4647d6424d2",
        },
        .index = 0,
        .success_witness = &.{
            "34ded7289fc00182235249dc5dd344d1d70bc440c5c285f785e3ef26784e20762a55be4efa62c3118678aee172f6126217d0ef55d3247fb2b29338d9c123edf6",
            "208dac1ce5361e11b1d9a891002ff5d4fbcaabf3e0d7fe8da31d725df16db3d4e9ac",
            "c0f77934fe98f1bb668a3b14e18e363e8fea085c74b7d8ae0e15dfc112b144f010",
        },
        .failure_witness = &.{
            "34ded7289fc00182235249dc5dd344d1d70bc440c5c285f785e3ef26784e20762a55be4efa62c3118678aee172f6126217d0ef55d3247fb2b29338d9c123edf6",
            "208dac1ce5361e11b1d9a891002ff5d4fbcaabf3e0d7fe8da31d725df16db3d4e9ac",
            "c0f77934fe98f1bb668a3b14e18e363e8fea085c74b7d8ae0e15dfc112b144f010aa6e4926e9017943d5b893a072",
        },
    },
    .{
        .comment = "unkver_bare (BIP341 unknown leaf version = anyone-can-spend)",
        .tx_hex = "0200000001d3d2f0976d67794790c9f874f40bc591fe8ebd8ad83377c1a9f5cf5d51930312f10100000082e96cc4016a4ca601000000001600145fdfb9b9d231797765d05fc245c9714dbb14e8407c2ae64f",
        .prevout_hexes = &.{
            "0e92ba0100000000225120995c260ccfd5c31ba34ba028a98486a9bf1ed13cf91fbb2dbfc73a35ac9d5ccf",
        },
        .index = 0,
        .success_witness = &.{
            "61",
            "8eb72183c9f60f81051641ec1119f4ca1048f83f6ebbfa3805731c0479a8c5d8bafbb397947548494548d50e6f6b436d2fda68af07b70b7f66f56c98db81bdc41bf45c0240e4cb2f2d96a2680887aed487322c91ce1c7e839db721c93b3195599ed1cc6539704683b9970669af51e2f3a8a75aa7b1d13b278bca97ad494a5d9220",
        },
        .failure_witness = &.{
            "61",
            "c0b72183c9f60f81051641ec1119f4ca1048f83f6ebbfa3805731c0479a8c5d8ba7442ba539034b2067bd698804af25c3f58d06009743f0ed3b18819eff684c0368a7e9d8f4a71cf5b77c9ed0a0e8c125a5496e4c4f36e045b98cc64f611b56efb2712f4444661e1b026ee1a556cb176264536b2c722475596ff9c7b511a208212",
        },
    },
};
