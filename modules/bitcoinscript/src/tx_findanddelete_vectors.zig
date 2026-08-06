// SPDX-License-Identifier: MIT
//! The `FindAndDelete` / `OP_CODESEPARATOR` / `SCRIPT_VERIFY_CONST_SCRIPTCODE`
//! rows of Bitcoin Core's `src/test/data/tx_valid.json` and `tx_invalid.json`
//! (fetched 2026-08 from `bitcoin/bitcoin` `master`), machine-transcribed
//! verbatim by a one-off Python script — never hand-typed.
//!
//! These are REAL transactions (several of them mainnet/testnet3 spends),
//! serialized exactly as Core stores them, each with its prevout scriptPubKeys
//! in Core's own asm format. They are the external oracle for the legacy
//! `FindAndDelete(scriptCode, CScript() << vchSig)` step: Core's comments say
//! it outright — *"the tests are 'correctly wrong', they should pass by
//! modifying OP_CHECKSIG under interpreter.cpp by replacing (sigversion ==
//! SigVersion::BASE) with (sigversion != SigVersion::BASE)"* — so an
//! implementation that omits the step accepts the `tx_invalid` rows and
//! rejects the `tx_valid` ones. `script_tests.json`, the corpus this module
//! was previously pinned against, contains NO such row (0 rows carry the
//! `CONST_SCRIPTCODE` flag and exactly 1 uses `CODESEPARATOR`), which is why
//! the divergence could sit undetected behind 296 green vectors.
//!
//! Selection predicate (machine-applied, not hand-picked): every row of either
//! file that (a) is a real 3-field test row, (b) is not `BADTX` (those test
//! `CheckTransaction`, not scripts), (c) uses only mnemonics this module's
//! opcode table implements, and (d) either names `CONST_SCRIPTCODE` in its
//! flags field, or contains `CODESEPARATOR` in a prevout script, or is
//! preceded by a comment block mentioning `FindAndDelete`.
//!
//! Flag-field semantics differ between the two files and are preserved here
//! as-written (see `Vector.json_flags`): `tx_valid.json`'s third field is the
//! set of flags that must be EXCLUDED (Core runs `~verify_flags`), while
//! `tx_invalid.json`'s is the set to APPLY.

/// One prevout being spent: Core's `[txid, vout, scriptPubKey asm, amount?]`.
/// `amount` is 0 where the JSON row omits it (only BIP143 sighash reads it,
/// and every amount-less row here is legacy).
pub const Prevout = struct {
    txid_hex: []const u8,
    vout: u32,
    script_asm: []const u8,
    amount: i64,
};

/// The `SCRIPT_VERIFY_*` names Core's `tx_*.json` flag field can contain,
/// as this module's `ScriptFlags` field names.
pub const FlagName = enum {
    p2sh,
    strictenc,
    dersig,
    low_s,
    sigpushonly,
    minimaldata,
    nulldummy,
    discourage_upgradable_nops,
    cleanstack,
    minimalif,
    nullfail,
    checklocktimeverify,
    checksequenceverify,
    witness,
    discourage_upgradable_witness_program,
    witness_pubkeytype,
    const_scriptcode,
    taproot,
    discourage_upgradable_pubkeytype,
    discourage_op_success,
    discourage_upgradable_taproot_version,
};

pub const Vector = struct {
    /// `true` = from `tx_valid.json` (every input must verify), `false` =
    /// from `tx_invalid.json` (at least one input must fail).
    valid: bool,
    prevouts: []const Prevout,
    tx_hex: []const u8,
    /// For a `valid` row: the flags to EXCLUDE from the full set.
    /// For an invalid row: the flags to APPLY.
    json_flags: []const FlagName,
    comment: []const u8,
};

pub const vectors = [_]Vector{
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "cf016927962ec028964c186043d48e465b3d4672f758953b00d3c4682f71cad6", .vout = 0, .script_asm = "HASH160 0x14 0x58a994e9d5ed9baa03ecfd1137592a90ad3cdfc5 EQUAL", .amount = 0 },
        },
        .tx_hex = "0100000001d6ca712f68c4d3003b9558f772463d5b468ed44360184c9628c02e96276901cf000000002f21026d2204a9535443657a88a0724fbd49a0e78d305f50a82f2cc9dd9bea10a6c5cd0c093006020101020101017cacffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "The following is c6c232a36395fa338da458b86ff1327395a9afc28c5d2daa4273e410089fd433 on testnet3 | It contains an OP_CHECKSIG with the shortest valid DER encoded signature (8 bytes w/o sighash flag), i.e. 3006020101020101 (r=1, s=1)",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "0000000000000000000000000000000000000000000000000000000000000100", .vout = 0, .script_asm = "DUP HASH160 0x14 0x5b6462475454710f3c22f5fdf0b40704c92f25c3 EQUALVERIFY CHECKSIGVERIFY 1 0x47 0x3044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a01", .amount = 0 },
        },
        .tx_hex = "01000000010001000000000000000000000000000000000000000000000000000000000000000000006a473044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a012103ba8c8b86dea131c22ab967e6dd99bdae8eff7a1f75a2c35f1f944109e3fe5e22ffffffff010000000000000000015100000000",
        .json_flags = &.{ .cleanstack, .const_scriptcode },
        .comment = "Same as above, but with the signature duplicated in the scriptPubKey with the proper pushdata prefix",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "bc7fd132fcf817918334822ee6d9bd95c889099c96e07ca2c1eb2cc70db63224", .vout = 0, .script_asm = "CODESEPARATOR 0x21 0x038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000012432b60dc72cebc1a27ce0969c0989c895bdd9e62e8234839117f8fc32d17fbc000000004a493046022100a576b52051962c25e642c0fd3d77ee6c92487048e5d90818bcf5b51abaccd7900221008204f8fb121be4ec3b24483b1f92d89b1b0548513a134e345c5442e86e8617a501ffffffff010000000000000000016a00000000",
        .json_flags = &.{ .const_scriptcode, .low_s },
        .comment = "OP_CODESEPARATOR tests | Test that SignatureHash() removes OP_CODESEPARATOR with FindAndDelete()",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "83e194f90b6ef21fa2e3a365b63794fb5daa844bdc9b25de30899fcfe7b01047", .vout = 0, .script_asm = "CODESEPARATOR CODESEPARATOR 0x21 0x038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000014710b0e7cf9f8930de259bdc4b84aa5dfb9437b665a3e3a21ff26e0bf994e183000000004a493046022100a166121a61b4eeb19d8f922b978ff6ab58ead8a5a5552bf9be73dc9c156873ea02210092ad9bc43ee647da4f6652c320800debcf08ec20a094a0aaf085f63ecb37a17201ffffffff010000000000000000016a00000000",
        .json_flags = &.{ .const_scriptcode, .low_s },
        .comment = "",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "326882a7f22b5191f1a0cc9962ca4b878cd969cf3b3a70887aece4d801a0ba5e", .vout = 0, .script_asm = "0x21 0x038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 CODESEPARATOR CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000015ebaa001d8e4ec7a88703a3bcf69d98c874bca6299cca0f191512bf2a7826832000000004948304502203bf754d1c6732fbf87c5dcd81258aefd30f2060d7bd8ac4a5696f7927091dad1022100f5bcb726c4cf5ed0ed34cc13dadeedf628ae1045b7cb34421bc60b89f4cecae701ffffffff010000000000000000016a00000000",
        .json_flags = &.{ .const_scriptcode, .low_s },
        .comment = "Hashed data starts at the CODESEPARATOR",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", .vout = 0, .script_asm = "0x21 0x038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 CHECKSIGVERIFY CODESEPARATOR 0x21 0x038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 CHECKSIGVERIFY CODESEPARATOR 1", .amount = 0 },
        },
        .tx_hex = "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a900000000924830450221009c0a27f886a1d8cb87f6f595fbc3163d28f7a81ec3c4b252ee7f3ac77fd13ffa02203caa8dfa09713c8c4d7ef575c75ed97812072405d932bd11e6a1593a98b679370148304502201e3861ef39a526406bad1e20ecad06be7375ad40ddb582c9be42d26c3a0d7b240221009d0a3985e96522e59635d19cc4448547477396ce0ef17a58e7d74c3ef464292301ffffffff010000000000000000016a00000000",
        .json_flags = &.{ .const_scriptcode, .low_s },
        .comment = "But only if execution has reached it",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", .vout = 0, .script_asm = "IF CODESEPARATOR ENDIF 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 CHECKSIGVERIFY CODESEPARATOR 1", .amount = 0 },
        },
        .tx_hex = "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a48304502207a6974a77c591fa13dff60cabbb85a0de9e025c09c65a4b2285e47ce8e22f761022100f0efaac9ff8ac36b10721e0aae1fb975c90500b50c56e8a0cc52b0403f0425dd0100ffffffff010000000000000000016a00000000",
        .json_flags = &.{ .const_scriptcode, .low_s },
        .comment = "CODESEPARATOR in an unexecuted IF block does not change what is hashed",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", .vout = 0, .script_asm = "IF CODESEPARATOR ENDIF 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 CHECKSIGVERIFY CODESEPARATOR 1", .amount = 0 },
        },
        .tx_hex = "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a483045022100fa4a74ba9fd59c59f46c3960cf90cbe0d2b743c471d24a3d5d6db6002af5eebb02204d70ec490fd0f7055a7c45f86514336e3a7f03503dacecabb247fc23f15c83510151ffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "As above, with the IF block executed",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "ccf7f4053a02e653c36ac75c891b7496d0dc5ce5214f6c913d9cf8f1329ebee0", .vout = 0, .script_asm = "DUP HASH160 0x14 0xee5a6aa40facefb2655ac23c0c28c57c65c41f9b EQUALVERIFY CHECKSIG", .amount = 0 },
        },
        .tx_hex = "0100000001e0be9e32f1f89c3d916c4f21e55cdcd096741b895cc76ac353e6023a05f4f7cc00000000d86149304602210086e5f736a2c3622ebb62bd9d93d8e5d76508b98be922b97160edc3dcca6d8c47022100b23c312ac232a4473f19d2aeb95ab7bdf2b65518911a0d72d50e38b5dd31dc820121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac4730440220508fa761865c8abd81244a168392876ee1d94e8ed83897066b5e2df2400dad24022043f5ee7538e87e9c6aef7ef55133d3e51da7cc522830a9c4d736977a76ef755c0121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000",
        .json_flags = &.{ .sigpushonly, .const_scriptcode, .low_s, .cleanstack },
        .comment = "CHECKSIG is legal in scriptSigs",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "10c9f0effe83e97f80f067de2b11c6a00c3088a4bce42c5ae761519af9306f3c", .vout = 1, .script_asm = "DUP HASH160 0x14 0xee5a6aa40facefb2655ac23c0c28c57c65c41f9b EQUALVERIFY CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000013c6f30f99a5161e75a2ce4bca488300ca0c6112bde67f0807fe983feeff0c91001000000e608646561646265656675ab61493046022100ce18d384221a731c993939015e3d1bcebafb16e8c0b5b5d14097ec8177ae6f28022100bcab227af90bab33c3fe0a9abfee03ba976ee25dc6ce542526e9b2e56e14b7f10121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac493046022100c3b93edcc0fd6250eb32f2dd8a0bba1754b0f6c3be8ed4100ed582f3db73eba2022100bf75b5bd2eff4d6bf2bda2e34a40fcc07d4aa3cf862ceaa77b47b81eff829f9a01ab21038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000",
        .json_flags = &.{ .sigpushonly, .const_scriptcode, .low_s, .cleanstack },
        .comment = "Same semantics for OP_CODESEPARATOR",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "6056ebd549003b10cbbd915cea0d82209fe40b8617104be917a26fa92cbe3d6f", .vout = 0, .script_asm = "DUP HASH160 0x14 0xee5a6aa40facefb2655ac23c0c28c57c65c41f9b EQUALVERIFY CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000016f3dbe2ca96fa217e94b1017860be49f20820dea5c91bdcb103b0049d5eb566000000000fd1d0147304402203989ac8f9ad36b5d0919d97fa0a7f70c5272abee3b14477dc646288a8b976df5022027d19da84a066af9053ad3d1d7459d171b7e3a80bc6c4ef7a330677a6be548140147304402203989ac8f9ad36b5d0919d97fa0a7f70c5272abee3b14477dc646288a8b976df5022027d19da84a066af9053ad3d1d7459d171b7e3a80bc6c4ef7a330677a6be548140121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac47304402203757e937ba807e4a5da8534c17f9d121176056406a6465054bdd260457515c1a02200f02eccf1bec0f3a0d65df37889143c2e88ab7acec61a7b6f5aa264139141a2b0121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000",
        .json_flags = &.{ .sigpushonly, .const_scriptcode, .cleanstack },
        .comment = "Signatures are removed from the script they are in by FindAndDelete() in the CHECKSIG code; even multiple instances of one signature can be removed.",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "5a6b0021a6042a686b6b94abc36b387bef9109847774e8b1e51eb8cc55c53921", .vout = 1, .script_asm = "DUP HASH160 0x14 0xee5a6aa40facefb2655ac23c0c28c57c65c41f9b EQUALVERIFY CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000012139c555ccb81ee5b1e87477840991ef7b386bc3ab946b6b682a04a621006b5a01000000fdb40148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f2204148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390175ac4830450220646b72c35beeec51f4d5bc1cbae01863825750d7f490864af354e6ea4f625e9c022100f04b98432df3a9641719dbced53393022e7249fb59db993af1118539830aab870148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a580039017521038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000",
        .json_flags = &.{ .sigpushonly, .const_scriptcode, .low_s, .cleanstack },
        .comment = "That also includes ahead of the opcode being executed.",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "b5b598de91787439afd5938116654e0b16b7a0d0f82742ba37564219c5afcbf9", .vout = 0, .script_asm = "DUP HASH160 0x14 0xf6f365c40f0739b61de827a44751e5e99032ed8f EQUALVERIFY CHECKSIG", .amount = 0 },
            .{ .txid_hex = "ab9805c6d57d7070d9a42c5176e47bb705023e6b67249fb6760880548298e742", .vout = 0, .script_asm = "HASH160 0x14 0xd8dacdadb7462ae15cd906f1878706d0da8660e6 EQUAL", .amount = 0 },
        },
        .tx_hex = "0100000002f9cbafc519425637ba4227f8d0a0b7160b4e65168193d5af39747891de98b5b5000000006b4830450221008dd619c563e527c47d9bd53534a770b102e40faa87f61433580e04e271ef2f960220029886434e18122b53d5decd25f1f4acb2480659fea20aabd856987ba3c3907e0121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab52a01ffffffff42e7988254800876b69f24676b3e0205b77be476512ca4d970707dd5c60598ab00000000fd260100483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a53034930460221008431bdfa72bc67f9d41fe72e94c88fb8f359ffa30b33c72c121c5a877d922e1002210089ef5fc22dd8bfc6bf9ffdb01a9862d27687d424d1fefbab9e9c7176844a187a014c9052483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c7153aeffffffff01a08601000000000017a914d8dacdadb7462ae15cd906f1878706d0da8660e68700000000",
        .json_flags = &.{ .const_scriptcode, .low_s },
        .comment = "Finally CHECKMULTISIG removes all signatures prior to hashing the script containing those signatures. In conjunction with the SIGHASH_SINGLE bug this lets us test whether or not FindAndDelete() is actually present in scriptPubKey/redeemScript evaluation by including a signature of the digest 0x01 We",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "ceafe58e0f6e7d67c0409fbbf673c84c166e3c5d3c24af58f7175b18df3bb3db", .vout = 0, .script_asm = "DUP HASH160 0x14 0xf6f365c40f0739b61de827a44751e5e99032ed8f EQUALVERIFY CHECKSIG", .amount = 0 },
            .{ .txid_hex = "ceafe58e0f6e7d67c0409fbbf673c84c166e3c5d3c24af58f7175b18df3bb3db", .vout = 1, .script_asm = "2 0x48 0x3045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 3 CHECKMULTISIG", .amount = 0 },
        },
        .tx_hex = "0100000002dbb33bdf185b17f758af243c5d3c6e164cc873f6bb9f40c0677d6e0f8ee5afce000000006b4830450221009627444320dc5ef8d7f68f35010b4c050a6ed0d96b67a84db99fda9c9de58b1e02203e4b4aaa019e012e65d69b487fdf8719df72f488fa91506a80c49a33929f1fd50121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab52a01ffffffffdbb33bdf185b17f758af243c5d3c6e164cc873f6bb9f40c0677d6e0f8ee5afce010000009300483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303ffffffff01a0860100000000001976a9149bc0bbdd3024da4d0c38ed1aecf5c68dd1d3fa1288ac00000000",
        .json_flags = &.{ .const_scriptcode, .low_s },
        .comment = "Same idea, but with bare CHECKMULTISIG",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "f18783ace138abac5d3a7a5cf08e88fe6912f267ef936452e0c27d090621c169", .vout = 7000, .script_asm = "HASH160 0x14 0x0c746489e2d83cdbb5b90b432773342ba809c134 EQUAL", .amount = 200000 },
        },
        .tx_hex = "010000000169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f1581b0000b64830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0121037a3fb04bcdb09eba90f69961ba1692a3528e45e67c85b200df820212d7594d334aad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01ffffffff0101000000000000000000000000",
        .json_flags = &.{ .const_scriptcode, .low_s },
        .comment = "FindAndDelete tests | This is a test of FindAndDelete. The first tx is a spend of normal P2SH and the second tx is a spend of bare P2WSH. | The redeemScript/witnessScript is CHECKSIGVERIFY <0x30450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeef",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "f18783ace138abac5d3a7a5cf08e88fe6912f267ef936452e0c27d090621c169", .vout = 7500, .script_asm = "0x00 0x20 0x9e1be07558ea5cc8e02ed1d80c0911048afad949affa36d5c3951e3159dbea19", .amount = 200000 },
        },
        .tx_hex = "0100000000010169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f14c1d000000ffffffff01010000000000000000034830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e012102a9781d66b61fb5a7ef00ac5ad5bc6ffc78be7b44a566e3c87870e1079368df4c4aad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0100000000",
        .json_flags = &.{.low_s},
        .comment = "BIP143: correct sighash (without FindAndDelete) = 71c9cd9b2869b9c70b01b1f0360c148f42dee72297db312638df136f43311f23",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "9628667ad48219a169b41b020800162287d2c0f713c04157e95c484a8dcb7592", .vout = 7000, .script_asm = "HASH160 0x14 0x5748407f5ca5cdca53ba30b79040260770c9ee1b EQUAL", .amount = 200000 },
        },
        .tx_hex = "01000000019275cb8d4a485ce95741c013f7c0d28722160008021bb469a11982d47a662896581b0000fd6f01004830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c03959601522102cd74a2809ffeeed0092bc124fd79836706e41f048db3f6ae9df8708cefb83a1c2102e615999372426e46fd107b76eaf007156a507584aa2cc21de9eee3bdbd26d36c4c9552af4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c0395960175ffffffff0101000000000000000000000000",
        .json_flags = &.{ .const_scriptcode, .low_s },
        .comment = "This is multisig version of the FindAndDelete tests | Script is 2 CHECKMULTISIGVERIFY <sig1> <sig2> DROP | 52af4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa",
    },
    .{
        .valid = true,
        .prevouts = &.{
            .{ .txid_hex = "9628667ad48219a169b41b020800162287d2c0f713c04157e95c484a8dcb7592", .vout = 7500, .script_asm = "0x00 0x20 0x9b66c15b4e0b4eb49fa877982cafded24859fe5b0e2dbfbe4f0df1de7743fd52", .amount = 200000 },
        },
        .tx_hex = "010000000001019275cb8d4a485ce95741c013f7c0d28722160008021bb469a11982d47a6628964c1d000000ffffffff0101000000000000000007004830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c0395960101022102966f109c54e85d3aee8321301136cedeb9fc710fdef58a9de8a73942f8e567c021034ffc99dd9a79dd3cb31e2ab3e0b09e0e67db41ac068c625cd1f491576016c84e9552af4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c039596017500000000",
        .json_flags = &.{.low_s},
        .comment = "BIP143: correct sighash (without FindAndDelete) = c1628a1e7c67f14ca0c27c06e4fdeec2e6d1a73c7a91d7c046ff83e835aebb72",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "0000000000000000000000000000000000000000000000000000000000000100", .vout = 0, .script_asm = "DUP HASH160 0x14 0x5b6462475454710f3c22f5fdf0b40704c92f25c3 EQUALVERIFY CHECKSIGVERIFY 1 0x4c 0x47 0x3044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a01", .amount = 0 },
        },
        .tx_hex = "01000000010001000000000000000000000000000000000000000000000000000000000000000000006a473044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a012103ba8c8b86dea131c22ab967e6dd99bdae8eff7a1f75a2c35f1f944109e3fe5e22ffffffff010000000000000000015100000000",
        .json_flags = &.{},
        .comment = "This is the nearly-standard transaction with CHECKSIGVERIFY 1 instead of CHECKSIG from tx_valid.json | but with the signature duplicated in the scriptPubKey with a non-standard pushdata prefix | See FindAndDelete, which will only remove if it uses the same pushdata prefix as is standard",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "0000000000000000000000000000000000000000000000000000000000000100", .vout = 0, .script_asm = "DUP HASH160 0x14 0x5b6462475454710f3c22f5fdf0b40704c92f25c3 EQUALVERIFY CHECKSIGVERIFY 1 0x47 0x3044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a81", .amount = 0 },
        },
        .tx_hex = "01000000010001000000000000000000000000000000000000000000000000000000000000000000006a473044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a012103ba8c8b86dea131c22ab967e6dd99bdae8eff7a1f75a2c35f1f944109e3fe5e22ffffffff010000000000000000015100000000",
        .json_flags = &.{},
        .comment = "This is the nearly-standard transaction with CHECKSIGVERIFY 1 instead of CHECKSIG from tx_valid.json | but with the signature duplicated in the scriptPubKey with a different hashtype suffix | See FindAndDelete, which will only remove if the signature, including the hash type, matches",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", .vout = 0, .script_asm = "IF CODESEPARATOR ENDIF 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 CHECKSIGVERIFY CODESEPARATOR 1", .amount = 0 },
        },
        .tx_hex = "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a48304502207a6974a77c591fa13dff60cabbb85a0de9e025c09c65a4b2285e47ce8e22f761022100f0efaac9ff8ac36b10721e0aae1fb975c90500b50c56e8a0cc52b0403f0425dd0151ffffffff010000000000000000016a00000000",
        .json_flags = &.{},
        .comment = "Inverted versions of tx_valid CODESEPARATOR IF block tests | CODESEPARATOR in an unexecuted IF block does not change what is hashed",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", .vout = 0, .script_asm = "IF CODESEPARATOR ENDIF 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 CHECKSIGVERIFY CODESEPARATOR 1", .amount = 0 },
        },
        .tx_hex = "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a483045022100fa4a74ba9fd59c59f46c3960cf90cbe0d2b743c471d24a3d5d6db6002af5eebb02204d70ec490fd0f7055a7c45f86514336e3a7f03503dacecabb247fc23f15c83510100ffffffff010000000000000000016a00000000",
        .json_flags = &.{},
        .comment = "As above, with the IF block executed",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "f18783ace138abac5d3a7a5cf08e88fe6912f267ef936452e0c27d090621c169", .vout = 7000, .script_asm = "HASH160 0x14 0x0c746489e2d83cdbb5b90b432773342ba809c134 EQUAL", .amount = 200000 },
        },
        .tx_hex = "010000000169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f1581b0000b64830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e012103b12a1ec8428fc74166926318c15e17408fea82dbb157575e16a8c365f546248f4aad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e01ffffffff0101000000000000000000000000",
        .json_flags = &.{.p2sh},
        .comment = "FindAndDelete tests | This is a test of FindAndDelete. The first tx is a spend of normal scriptPubKey and the second tx is a spend of bare P2WSH. | The redeemScript/witnessScript is CHECKSIGVERIFY <0x30450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc988",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "f18783ace138abac5d3a7a5cf08e88fe6912f267ef936452e0c27d090621c169", .vout = 7500, .script_asm = "0x00 0x20 0x9e1be07558ea5cc8e02ed1d80c0911048afad949affa36d5c3951e3159dbea19", .amount = 200000 },
        },
        .tx_hex = "0100000000010169c12106097dc2e0526493ef67f21269fe888ef05c7a3a5dacab38e1ac8387f14c1d000000ffffffff01010000000000000000034830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e012102a9d7ed6e161f0e255c10bbfcca0128a9e2035c2c8da58899c54d22d3a31afdef4aad4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0100000000",
        .json_flags = &.{ .p2sh, .witness },
        .comment = "BIP143: wrong sighash (with FindAndDelete) = 71c9cd9b2869b9c70b01b1f0360c148f42dee72297db312638df136f43311f23",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "9628667ad48219a169b41b020800162287d2c0f713c04157e95c484a8dcb7592", .vout = 7000, .script_asm = "HASH160 0x14 0x5748407f5ca5cdca53ba30b79040260770c9ee1b EQUAL", .amount = 200000 },
        },
        .tx_hex = "01000000019275cb8d4a485ce95741c013f7c0d28722160008021bb469a11982d47a662896581b0000fd6f01004830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c039596015221023fd5dd42b44769c5653cbc5947ff30ab8871f240ad0c0e7432aefe84b5b4ff3421039d52178dbde360b83f19cf348deb04fa8360e1bf5634577be8e50fafc2b0e4ef4c9552af4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c0395960175ffffffff0101000000000000000000000000",
        .json_flags = &.{.p2sh},
        .comment = "This is multisig version of the FindAndDelete tests | Script is 2 CHECKMULTISIGVERIFY <sig1> <sig2> DROP | 52af4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "9628667ad48219a169b41b020800162287d2c0f713c04157e95c484a8dcb7592", .vout = 7500, .script_asm = "0x00 0x20 0x9b66c15b4e0b4eb49fa877982cafded24859fe5b0e2dbfbe4f0df1de7743fd52", .amount = 200000 },
        },
        .tx_hex = "010000000001019275cb8d4a485ce95741c013f7c0d28722160008021bb469a11982d47a6628964c1d000000ffffffff0101000000000000000007004830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c03959601010221023cb6055f4b57a1580c5a753e19610cafaedf7e0ff377731c77837fd666eae1712102c1b1db303ac232ffa8e5e7cc2cf5f96c6e40d3e6914061204c0541cb2043a0969552af4830450220487fb382c4974de3f7d834c1b617fe15860828c7f96454490edd6d891556dcc9022100baf95feb48f845d5bfc9882eb6aeefa1bc3790e39f59eaa46ff7f15ae626c53e0148304502205286f726690b2e9b0207f0345711e63fa7012045b9eb0f19c2458ce1db90cf43022100e89f17f86abc5b149eba4115d4f128bcf45d77fb3ecdd34f594091340c039596017500000000",
        .json_flags = &.{ .p2sh, .witness },
        .comment = "BIP143: wrong sighash (with FindAndDelete) = 17c50ec2181ecdfdc85ca081174b248199ba81fff730794d4f69b8ec031f2dce",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "bc7fd132fcf817918334822ee6d9bd95c889099c96e07ca2c1eb2cc70db63224", .vout = 0, .script_asm = "CODESEPARATOR 0x21 0x038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000012432b60dc72cebc1a27ce0969c0989c895bdd9e62e8234839117f8fc32d17fbc000000004a493046022100a576b52051962c25e642c0fd3d77ee6c92487048e5d90818bcf5b51abaccd7900221008204f8fb121be4ec3b24483b1f92d89b1b0548513a134e345c5442e86e8617a501ffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "SCRIPT_VERIFY_CONST_SCRIPTCODE tests | All transactions are copied from OP_CODESEPARATOR tests in tx_valid.json",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "83e194f90b6ef21fa2e3a365b63794fb5daa844bdc9b25de30899fcfe7b01047", .vout = 0, .script_asm = "CODESEPARATOR CODESEPARATOR 0x21 0x038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000014710b0e7cf9f8930de259bdc4b84aa5dfb9437b665a3e3a21ff26e0bf994e183000000004a493046022100a166121a61b4eeb19d8f922b978ff6ab58ead8a5a5552bf9be73dc9c156873ea02210092ad9bc43ee647da4f6652c320800debcf08ec20a094a0aaf085f63ecb37a17201ffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "326882a7f22b5191f1a0cc9962ca4b878cd969cf3b3a70887aece4d801a0ba5e", .vout = 0, .script_asm = "0x21 0x038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 CODESEPARATOR CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000015ebaa001d8e4ec7a88703a3bcf69d98c874bca6299cca0f191512bf2a7826832000000004948304502203bf754d1c6732fbf87c5dcd81258aefd30f2060d7bd8ac4a5696f7927091dad1022100f5bcb726c4cf5ed0ed34cc13dadeedf628ae1045b7cb34421bc60b89f4cecae701ffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", .vout = 0, .script_asm = "0x21 0x038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 CHECKSIGVERIFY CODESEPARATOR 0x21 0x038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041 CHECKSIGVERIFY CODESEPARATOR 1", .amount = 0 },
        },
        .tx_hex = "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a900000000924830450221009c0a27f886a1d8cb87f6f595fbc3163d28f7a81ec3c4b252ee7f3ac77fd13ffa02203caa8dfa09713c8c4d7ef575c75ed97812072405d932bd11e6a1593a98b679370148304502201e3861ef39a526406bad1e20ecad06be7375ad40ddb582c9be42d26c3a0d7b240221009d0a3985e96522e59635d19cc4448547477396ce0ef17a58e7d74c3ef464292301ffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", .vout = 0, .script_asm = "IF CODESEPARATOR ENDIF 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 CHECKSIGVERIFY CODESEPARATOR 1", .amount = 0 },
        },
        .tx_hex = "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a48304502207a6974a77c591fa13dff60cabbb85a0de9e025c09c65a4b2285e47ce8e22f761022100f0efaac9ff8ac36b10721e0aae1fb975c90500b50c56e8a0cc52b0403f0425dd0100ffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "CODESEPARATOR in an unexecuted IF block is still invalid",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "a955032f4d6b0c9bfe8cad8f00a8933790b9c1dc28c82e0f48e75b35da0e4944", .vout = 0, .script_asm = "IF CODESEPARATOR ENDIF 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 CHECKSIGVERIFY CODESEPARATOR 1", .amount = 0 },
        },
        .tx_hex = "010000000144490eda355be7480f2ec828dcc1b9903793a8008fad8cfe9b0c6b4d2f0355a9000000004a483045022100fa4a74ba9fd59c59f46c3960cf90cbe0d2b743c471d24a3d5d6db6002af5eebb02204d70ec490fd0f7055a7c45f86514336e3a7f03503dacecabb247fc23f15c83510151ffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "CODESEPARATOR in an executed IF block is invalid",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "ccf7f4053a02e653c36ac75c891b7496d0dc5ce5214f6c913d9cf8f1329ebee0", .vout = 0, .script_asm = "DUP HASH160 0x14 0xee5a6aa40facefb2655ac23c0c28c57c65c41f9b EQUALVERIFY CHECKSIG", .amount = 0 },
        },
        .tx_hex = "0100000001e0be9e32f1f89c3d916c4f21e55cdcd096741b895cc76ac353e6023a05f4f7cc00000000d86149304602210086e5f736a2c3622ebb62bd9d93d8e5d76508b98be922b97160edc3dcca6d8c47022100b23c312ac232a4473f19d2aeb95ab7bdf2b65518911a0d72d50e38b5dd31dc820121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac4730440220508fa761865c8abd81244a168392876ee1d94e8ed83897066b5e2df2400dad24022043f5ee7538e87e9c6aef7ef55133d3e51da7cc522830a9c4d736977a76ef755c0121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "Using CHECKSIG with signatures in scriptSigs will trigger FindAndDelete, which is invalid",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "10c9f0effe83e97f80f067de2b11c6a00c3088a4bce42c5ae761519af9306f3c", .vout = 1, .script_asm = "DUP HASH160 0x14 0xee5a6aa40facefb2655ac23c0c28c57c65c41f9b EQUALVERIFY CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000013c6f30f99a5161e75a2ce4bca488300ca0c6112bde67f0807fe983feeff0c91001000000e608646561646265656675ab61493046022100ce18d384221a731c993939015e3d1bcebafb16e8c0b5b5d14097ec8177ae6f28022100bcab227af90bab33c3fe0a9abfee03ba976ee25dc6ce542526e9b2e56e14b7f10121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac493046022100c3b93edcc0fd6250eb32f2dd8a0bba1754b0f6c3be8ed4100ed582f3db73eba2022100bf75b5bd2eff4d6bf2bda2e34a40fcc07d4aa3cf862ceaa77b47b81eff829f9a01ab21038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "OP_CODESEPARATOR in scriptSig is invalid",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "6056ebd549003b10cbbd915cea0d82209fe40b8617104be917a26fa92cbe3d6f", .vout = 0, .script_asm = "DUP HASH160 0x14 0xee5a6aa40facefb2655ac23c0c28c57c65c41f9b EQUALVERIFY CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000016f3dbe2ca96fa217e94b1017860be49f20820dea5c91bdcb103b0049d5eb566000000000fd1d0147304402203989ac8f9ad36b5d0919d97fa0a7f70c5272abee3b14477dc646288a8b976df5022027d19da84a066af9053ad3d1d7459d171b7e3a80bc6c4ef7a330677a6be548140147304402203989ac8f9ad36b5d0919d97fa0a7f70c5272abee3b14477dc646288a8b976df5022027d19da84a066af9053ad3d1d7459d171b7e3a80bc6c4ef7a330677a6be548140121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ac47304402203757e937ba807e4a5da8534c17f9d121176056406a6465054bdd260457515c1a02200f02eccf1bec0f3a0d65df37889143c2e88ab7acec61a7b6f5aa264139141a2b0121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "Again, FindAndDelete() in scriptSig",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "5a6b0021a6042a686b6b94abc36b387bef9109847774e8b1e51eb8cc55c53921", .vout = 1, .script_asm = "DUP HASH160 0x14 0xee5a6aa40facefb2655ac23c0c28c57c65c41f9b EQUALVERIFY CHECKSIG", .amount = 0 },
        },
        .tx_hex = "01000000012139c555ccb81ee5b1e87477840991ef7b386bc3ab946b6b682a04a621006b5a01000000fdb40148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390121038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f2204148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a5800390175ac4830450220646b72c35beeec51f4d5bc1cbae01863825750d7f490864af354e6ea4f625e9c022100f04b98432df3a9641719dbced53393022e7249fb59db993af1118539830aab870148304502201723e692e5f409a7151db386291b63524c5eb2030df652b1f53022fd8207349f022100b90d9bbf2f3366ce176e5e780a00433da67d9e5c79312c6388312a296a580039017521038479a0fa998cd35259a2ef0a7a5c68662c1474f88ccb6d08a7677bbec7f22041ffffffff010000000000000000016a00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "b5b598de91787439afd5938116654e0b16b7a0d0f82742ba37564219c5afcbf9", .vout = 0, .script_asm = "DUP HASH160 0x14 0xf6f365c40f0739b61de827a44751e5e99032ed8f EQUALVERIFY CHECKSIG", .amount = 0 },
            .{ .txid_hex = "ab9805c6d57d7070d9a42c5176e47bb705023e6b67249fb6760880548298e742", .vout = 0, .script_asm = "HASH160 0x14 0xd8dacdadb7462ae15cd906f1878706d0da8660e6 EQUAL", .amount = 0 },
        },
        .tx_hex = "0100000002f9cbafc519425637ba4227f8d0a0b7160b4e65168193d5af39747891de98b5b5000000006b4830450221008dd619c563e527c47d9bd53534a770b102e40faa87f61433580e04e271ef2f960220029886434e18122b53d5decd25f1f4acb2480659fea20aabd856987ba3c3907e0121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab52a01ffffffff42e7988254800876b69f24676b3e0205b77be476512ca4d970707dd5c60598ab00000000fd260100483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a53034930460221008431bdfa72bc67f9d41fe72e94c88fb8f359ffa30b33c72c121c5a877d922e1002210089ef5fc22dd8bfc6bf9ffdb01a9862d27687d424d1fefbab9e9c7176844a187a014c9052483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71210378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c7153aeffffffff01a08601000000000017a914d8dacdadb7462ae15cd906f1878706d0da8660e68700000000",
        .json_flags = &.{ .p2sh, .const_scriptcode },
        .comment = "FindAndDelete() in redeemScript",
    },
    .{
        .valid = false,
        .prevouts = &.{
            .{ .txid_hex = "ceafe58e0f6e7d67c0409fbbf673c84c166e3c5d3c24af58f7175b18df3bb3db", .vout = 0, .script_asm = "DUP HASH160 0x14 0xf6f365c40f0739b61de827a44751e5e99032ed8f EQUALVERIFY CHECKSIG", .amount = 0 },
            .{ .txid_hex = "ceafe58e0f6e7d67c0409fbbf673c84c166e3c5d3c24af58f7175b18df3bb3db", .vout = 1, .script_asm = "2 0x48 0x3045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 0x21 0x0378d430274f8c5ec1321338151e9f27f4c676a008bdf8638d07c0b6be9ab35c71 3 CHECKMULTISIG", .amount = 0 },
        },
        .tx_hex = "0100000002dbb33bdf185b17f758af243c5d3c6e164cc873f6bb9f40c0677d6e0f8ee5afce000000006b4830450221009627444320dc5ef8d7f68f35010b4c050a6ed0d96b67a84db99fda9c9de58b1e02203e4b4aaa019e012e65d69b487fdf8719df72f488fa91506a80c49a33929f1fd50121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab52a01ffffffffdbb33bdf185b17f758af243c5d3c6e164cc873f6bb9f40c0677d6e0f8ee5afce010000009300483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303ffffffff01a0860100000000001976a9149bc0bbdd3024da4d0c38ed1aecf5c68dd1d3fa1288ac00000000",
        .json_flags = &.{.const_scriptcode},
        .comment = "FindAndDelete() in bare CHECKMULTISIG",
    },
};
