// SPDX-License-Identifier: MIT
//! Rows pinned in addition to the machine-transcribed `script_tests.json`
//! corpus (`script_tests_vectors.zig`, which is generated and never
//! hand-edited): variants of Core rows run under fewer flags (where Core
//! accepts the script, which the transcribed rows only show under strict
//! flags), `CONST_SCRIPTCODE` rows for `FindAndDelete(vchSig)` (the flag is
//! absent from the corpus; Core's own tests for it are `tx_invalid.json`,
//! see `tx_findanddelete_vectors.zig`), and hand-built X9.62 hybrid-key
//! parity cases (tags 06/07, no `STRICTENC`) using the signature of Core's
//! "P2PK with hybrid pubkey" row. Run by `script_tests_test.zig` like the
//! corpus.

pub const Vector = @import("script_tests_vectors.zig").Vector;

pub const vectors = [_]Vector{
    .{
        .script_sig = "0x4a 0x3047022201010101010101010101010101010101010101010101010101010101010101010101022101010101010101010101010101010101010101010101010101010101010101010101",
        .script_pubkey = "0 CHECKSIG NOT",
        .flags = .{},
        .expect = null,
        .comment = "74-byte signature is correctly encoded",
    },
    .{
        .script_sig = "0x47 0x3043022044dc17b0887c161bb67ba9635bf758735bdde503e4b0a0987f587f14a4e1143d022009a215772d49a85dae40d8ca03955af26ad3978a0ff965faa12915e9586249a501",
        .script_pubkey = "0 CHECKSIG NOT",
        .flags = .{},
        .expect = null,
        .comment = "Total-length byte not covering the entire signature is correctly encoded",
    },
    .{
        .script_sig = "0x03 0x300000",
        .script_pubkey = "0 CHECKSIG NOT",
        .flags = .{},
        .expect = null,
        .comment = "3-byte signature is correctly encoded",
    },
    .{
        .script_sig = "0",
        .script_pubkey = "0x21 0x06865c40293a680cb9c020e7b1e106d8c1916d3cef99aa431a56d253e69256dac0 CHECKSIG NOT",
        .flags = .{},
        .expect = null,
        .comment = "33-byte pubkey with a prefix other than 0x02/0x03 is correctly encoded",
    },
    .{
        .script_sig = "0x09 0x300602010102010100",
        .script_pubkey = "0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
        .flags = .{},
        .expect = null,
        .comment = "P2PK NOT with invalid sig and hashtype 0 but no STRICTENC",
    },
    .{
        .script_sig = "0x02 0x0001",
        .script_pubkey = "0x02 0x0001 DROP 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG",
        .flags = .{ .const_scriptcode = true },
        .expect = "SigFindanddelete",
        .comment = "CHECKSIG fails when the signature push is found in the scriptCode",
    },
    .{
        .script_sig = "0 0x02 0x0001",
        .script_pubkey = "0x02 0x0001 DROP 1 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 1 CHECKMULTISIG",
        .flags = .{ .const_scriptcode = true },
        .expect = "SigFindanddelete",
        .comment = "CHECKMULTISIG fails when a signature push is found in the scriptCode",
    },
    .{
        .script_sig = "0x02 0x0001",
        .script_pubkey = "0x02 0x0001 DROP 0x21 0x038282263212c609d9ea2a6e3e172de238d8c39cabd5ac1ca10646e23fd5f51508 CHECKSIG NOT",
        .flags = .{},
        .expect = null,
        .comment = "Without CONST_SCRIPTCODE, FindAndDelete silently drops the signature push from the scriptCode",
    },
    .{
        .script_sig = "0x47 0x3044022057292e2d4dfe775becdd0a9e6547997c728cdf35390f6a017da56d654d374e4902206b643be2fc53763b4e284845bfea2c597d2dc7759941dce937636c9d341b71ed01",
        .script_pubkey = "0x41 0x0779be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 CHECKSIG",
        .flags = .{},
        .expect = "EvalFalse",
        .comment = "hybrid 07 key (G, y even), tag does not match parity: refused, verify=false",
    },
    .{
        .script_sig = "0x47 0x3044022057292e2d4dfe775becdd0a9e6547997c728cdf35390f6a017da56d654d374e4902206b643be2fc53763b4e284845bfea2c597d2dc7759941dce937636c9d341b71ed01",
        .script_pubkey = "0x41 0x0779be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8 CHECKSIG NOT",
        .flags = .{},
        .expect = null,
        .comment = "same mismatching-parity hybrid key under NOT: the check is false, not an error",
    },
    .{
        .script_sig = "0x47 0x3044022057292e2d4dfe775becdd0a9e6547997c728cdf35390f6a017da56d654d374e4902206b643be2fc53763b4e284845bfea2c597d2dc7759941dce937636c9d341b71ed01",
        .script_pubkey = "0x41 0x0779be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b9 CHECKSIG",
        .flags = .{},
        .expect = "EvalFalse",
        .comment = "hybrid 07 key with an odd y that is not on the curve: verify=false",
    },
    .{
        .script_sig = "0x47 0x3044022057292e2d4dfe775becdd0a9e6547997c728cdf35390f6a017da56d654d374e4902206b643be2fc53763b4e284845bfea2c597d2dc7759941dce937636c9d341b71ed01",
        .script_pubkey = "0x41 0x0679be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4ba CHECKSIG",
        .flags = .{},
        .expect = "EvalFalse",
        .comment = "hybrid 06 key with an even y that is not on the curve: verify=false",
    },
};
