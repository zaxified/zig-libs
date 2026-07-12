// SPDX-License-Identifier: MIT
//! Official BIP327 test vectors, transcribed verbatim (hex case preserved as
//! published) from the JSON files under `bip-0327/vectors/` in the
//! `bitcoin/bips` repository (fetched directly from
//! https://raw.githubusercontent.com/bitcoin/bips/master/bip-0327/vectors/*.json
//! for this pass -- public BIP specification artifacts, not copied from any
//! other implementation's test suite; see `../NOTICE`).
//!
//! Seven of the eight published vector files are embedded here: `key_agg`
//! (including its two tweak-related error cases), `key_sort`, `nonce_gen`,
//! `nonce_agg`, `sign_verify`, `sig_agg`, and `tweak` (tweak_vectors.json,
//! embedded in the tweaking pass). NOT embedded: `det_sign_vectors.json`
//! (the optional single-signer `DeterministicSign` convenience wrapper,
//! not part of the core signing flow this module implements).

// ---- key_agg_vectors.json --------------------------------------------------

pub const key_agg = struct {
    pub const pubkeys: []const []const u8 = &.{
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        "020000000000000000000000000000000000000000000000000000000000000005",
        "02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        "04F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
    };

    pub const tweaks: []const []const u8 = &.{
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        "252E4BD67410A76CDF933D30EAA1608214037F1B105A013ECCD3C5C184A6110B",
    };

    pub const ValidCase = struct { key_indices: []const usize, expected: []const u8 };
    pub const valid_test_cases = [_]ValidCase{
        .{ .key_indices = &.{ 0, 1, 2 }, .expected = "90539EEDE565F5D054F32CC0C220126889ED1E5D193BAF15AEF344FE59D4610C" },
        .{ .key_indices = &.{ 2, 1, 0 }, .expected = "6204DE8B083426DC6EAF9502D27024D53FC826BF7D2012148A0575435DF54B2B" },
        .{ .key_indices = &.{ 0, 0, 0 }, .expected = "B436E3BAD62B8CD409969A224731C193D051162D8C5AE8B109306127DA3AA935" },
        .{ .key_indices = &.{ 0, 0, 1, 1 }, .expected = "69BC22BFA5D106306E48A20679DE1D7389386124D07571D0D872686028C26A3E" },
    };

    /// The `contrib = "pubkey"` cases (indices 0-2 of the published file).
    pub const ErrorCase = struct { key_indices: []const usize, invalid_signer: usize, comment: []const u8 };
    pub const error_test_cases = [_]ErrorCase{
        .{ .key_indices = &.{ 0, 3 }, .invalid_signer = 1, .comment = "Invalid public key" },
        .{ .key_indices = &.{ 0, 4 }, .invalid_signer = 1, .comment = "Public key exceeds field size" },
        .{ .key_indices = &.{ 5, 0 }, .invalid_signer = 0, .comment = "First byte of public key is not 2 or 3" },
    };

    /// The two tweak-related error cases (indices 3/4 of the published
    /// file), transcribed in the tweaking pass: the first has `t = n`
    /// exactly (out of range), the second's tweak is chosen so the plain-
    /// tweaked single-key aggregate lands exactly on the point at infinity.
    pub const TweakErrorCase = struct {
        key_indices: []const usize,
        tweak_indices: []const usize,
        is_xonly: []const bool,
        comment: []const u8,
    };
    pub const tweak_error_test_cases = [_]TweakErrorCase{
        .{ .key_indices = &.{ 0, 1 }, .tweak_indices = &.{0}, .is_xonly = &.{true}, .comment = "Tweak is out of range" },
        .{ .key_indices = &.{6}, .tweak_indices = &.{1}, .is_xonly = &.{false}, .comment = "Intermediate tweaking result is point at infinity" },
    };
};

// ---- key_sort_vectors.json --------------------------------------------------

pub const key_sort = struct {
    pub const pubkeys: []const []const u8 = &.{
        "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EFF",
        "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
    };

    pub const sorted_pubkeys: []const []const u8 = &.{
        "023590A94E768F8E1815C2F24B4D80A8E3149316C3518CE7B7AD338368D038CA66",
        "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "02DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EFF",
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "03DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    };
};

// ---- nonce_gen_vectors.json ---------------------------------------------------

pub const nonce_gen = struct {
    pub const TestCase = struct {
        rand_: []const u8,
        sk: ?[]const u8,
        pk: []const u8,
        aggpk: ?[]const u8,
        msg: ?[]const u8,
        extra_in: ?[]const u8,
        expected_secnonce: []const u8,
        expected_pubnonce: []const u8,
    };
    pub const test_cases = [_]TestCase{
        .{
            .rand_ = "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            .sk = "0202020202020202020202020202020202020202020202020202020202020202",
            .pk = "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
            .aggpk = "0707070707070707070707070707070707070707070707070707070707070707",
            .msg = "0101010101010101010101010101010101010101010101010101010101010101",
            .extra_in = "0808080808080808080808080808080808080808080808080808080808080808",
            .expected_secnonce = "B114E502BEAA4E301DD08A50264172C84E41650E6CB726B410C0694D59EFFB6495B5CAF28D045B973D63E3C99A44B807BDE375FD6CB39E46DC4A511708D0E9D2024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
            .expected_pubnonce = "02F7BE7089E8376EB355272368766B17E88E7DB72047D05E56AA881EA52B3B35DF02C29C8046FDD0DED4C7E55869137200FBDBFE2EB654267B6D7013602CAED3115A",
        },
        .{
            .rand_ = "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            .sk = "0202020202020202020202020202020202020202020202020202020202020202",
            .pk = "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
            .aggpk = "0707070707070707070707070707070707070707070707070707070707070707",
            .msg = "",
            .extra_in = "0808080808080808080808080808080808080808080808080808080808080808",
            .expected_secnonce = "E862B068500320088138468D47E0E6F147E01B6024244AE45EAC40ACE5929B9F0789E051170B9E705D0B9EB49049A323BBBBB206D8E05C19F46C6228742AA7A9024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
            .expected_pubnonce = "023034FA5E2679F01EE66E12225882A7A48CC66719B1B9D3B6C4DBD743EFEDA2C503F3FD6F01EB3A8E9CB315D73F1F3D287CAFBB44AB321153C6287F407600205109",
        },
        .{
            .rand_ = "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            .sk = "0202020202020202020202020202020202020202020202020202020202020202",
            .pk = "024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
            .aggpk = "0707070707070707070707070707070707070707070707070707070707070707",
            .msg = "2626262626262626262626262626262626262626262626262626262626262626262626262626",
            .extra_in = "0808080808080808080808080808080808080808080808080808080808080808",
            .expected_secnonce = "3221975ACBDEA6820EABF02A02B7F27D3A8EF68EE42787B88CBEFD9AA06AF3632EE85B1A61D8EF31126D4663A00DD96E9D1D4959E72D70FE5EBB6E7696EBA66F024D4B6CD1361032CA9BD2AEB9D900AA4D45D9EAD80AC9423374C451A7254D0766",
            .expected_pubnonce = "02E5BBC21C69270F59BD634FCBFA281BE9D76601295345112C58954625BF23793A021307511C79F95D38ACACFF1B4DA98228B77E65AA216AD075E9673286EFB4EAF3",
        },
        .{
            .rand_ = "0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F",
            .sk = null,
            .pk = "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            .aggpk = null,
            .msg = null,
            .extra_in = null,
            .expected_secnonce = "89BDD787D0284E5E4D5FC572E49E316BAB7E21E3B1830DE37DFE80156FA41A6D0B17AE8D024C53679699A6FD7944D9C4A366B514BAF43088E0708B1023DD289702F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            .expected_pubnonce = "02C96E7CB1E8AA5DAC64D872947914198F607D90ECDE5200DE52978AD5DED63C000299EC5117C2D29EDEE8A2092587C3909BE694D5CFF0667D6C02EA4059F7CD9786",
        },
    };
};

// ---- nonce_agg_vectors.json --------------------------------------------------

pub const nonce_agg = struct {
    pub const pnonces: []const []const u8 = &.{
        "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E66603BA47FBC1834437B3212E89A84D8425E7BF12E0245D98262268EBDCB385D50641",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
        "020151C80F435648DF67A22B749CD798CE54E0321D034B92B709B567D60A42E6660279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60379BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "04FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B833",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A60248C264CDD57D3C24D79990B0F865674EB62A0F9018277A95011B41BFC193B831",
        "03FF406FFD8ADB9CD29877E4985014F66A59F6CD01C0E88CAA8E5F3166B1F676A602FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
    };

    pub const ValidCase = struct { pnonce_indices: []const usize, expected: []const u8, comment: []const u8 };
    pub const valid_test_cases = [_]ValidCase{
        .{ .pnonce_indices = &.{ 0, 1 }, .expected = "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B024725377345BDE0E9C33AF3C43C0A29A9249F2F2956FA8CFEB55C8573D0262DC8", .comment = "" },
        .{ .pnonce_indices = &.{ 2, 3 }, .expected = "035FE1873B4F2967F52FEA4A06AD5A8ECCBE9D0FD73068012C894E2E87CCB5804B000000000000000000000000000000000000000000000000000000000000000000", .comment = "Sum of second points encoded in the nonces is point at infinity which is serialized as 33 zero bytes" },
    };

    pub const ErrorCase = struct { pnonce_indices: []const usize, invalid_signer: usize, comment: []const u8 };
    pub const error_test_cases = [_]ErrorCase{
        .{ .pnonce_indices = &.{ 0, 4 }, .invalid_signer = 1, .comment = "Public nonce from signer 1 is invalid due wrong tag, 0x04, in the first half" },
        .{ .pnonce_indices = &.{ 5, 1 }, .invalid_signer = 0, .comment = "Public nonce from signer 0 is invalid because the second half does not correspond to an X coordinate" },
        .{ .pnonce_indices = &.{ 6, 1 }, .invalid_signer = 0, .comment = "Public nonce from signer 0 is invalid because second half exceeds field size" },
    };
};

// ---- sign_verify_vectors.json --------------------------------------------------

pub const sign_verify = struct {
    pub const sk = "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671";

    pub const pubkeys: []const []const u8 = &.{
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA661",
        "020000000000000000000000000000000000000000000000000000000000000007",
    };

    pub const secnonces: []const []const u8 = &.{
        "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
    };

    pub const pnonces: []const []const u8 = &.{
        "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046",
        "0237C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0387BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
        "0200000000000000000000000000000000000000000000000000000000000000090287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
    };

    pub const aggnonces: []const []const u8 = &.{
        "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "048465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9",
        "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61020000000000000000000000000000000000000000000000000000000000000009",
        "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD6102FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
    };

    pub const msgs: []const []const u8 = &.{
        "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF",
        "",
        "2626262626262626262626262626262626262626262626262626262626262626262626262626",
    };

    pub const ValidCase = struct {
        key_indices: []const usize,
        nonce_indices: []const usize,
        aggnonce_index: usize,
        msg_index: usize,
        signer_index: usize,
        expected: []const u8,
        comment: []const u8,
    };
    pub const valid_test_cases = [_]ValidCase{
        .{
            .key_indices = &.{ 0, 1, 2 },
            .nonce_indices = &.{ 0, 1, 2 },
            .aggnonce_index = 0,
            .msg_index = 0,
            .signer_index = 0,
            .expected = "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB",
            .comment = "",
        },
        .{
            .key_indices = &.{ 1, 0, 2 },
            .nonce_indices = &.{ 1, 0, 2 },
            .aggnonce_index = 0,
            .msg_index = 0,
            .signer_index = 1,
            .expected = "9FF2F7AAA856150CC8819254218D3ADEEB0535269051897724F9DB3789513A52",
            .comment = "",
        },
        .{
            .key_indices = &.{ 1, 2, 0 },
            .nonce_indices = &.{ 1, 2, 0 },
            .aggnonce_index = 0,
            .msg_index = 0,
            .signer_index = 2,
            .expected = "FA23C359F6FAC4E7796BB93BC9F0532A95468C539BA20FF86D7C76ED92227900",
            .comment = "",
        },
        .{
            .key_indices = &.{ 0, 1 },
            .nonce_indices = &.{ 0, 3 },
            .aggnonce_index = 1,
            .msg_index = 0,
            .signer_index = 0,
            .expected = "AE386064B26105404798F75DE2EB9AF5EDA5387B064B83D049CB7C5E08879531",
            .comment = "Both halves of aggregate nonce correspond to point at infinity",
        },
        .{
            .key_indices = &.{ 0, 1, 2 },
            .nonce_indices = &.{ 0, 1, 2 },
            .aggnonce_index = 0,
            .msg_index = 1,
            .signer_index = 0,
            .expected = "D7D63FFD644CCDA4E62BC2BC0B1D02DD32A1DC3030E155195810231D1037D82D",
            .comment = "Empty message",
        },
        .{
            .key_indices = &.{ 0, 1, 2 },
            .nonce_indices = &.{ 0, 1, 2 },
            .aggnonce_index = 0,
            .msg_index = 2,
            .signer_index = 0,
            .expected = "E184351828DA5094A97C79CABDAAA0BFB87608C32E8829A4DF5340A6F243B78C",
            .comment = "38-byte message",
        },
    };

    pub const SignErrorCase = struct {
        key_indices: []const usize,
        aggnonce_index: usize,
        msg_index: usize,
        secnonce_index: usize,
        comment: []const u8,
    };
    pub const sign_error_test_cases = [_]SignErrorCase{
        .{
            .key_indices = &.{ 1, 2 },
            .aggnonce_index = 0,
            .msg_index = 0,
            .secnonce_index = 0,
            .comment = "The signers pubkey is not in the list of pubkeys. This test case is optional: it can be skipped by implementations that do not check that the signer's pubkey is included in the list of pubkeys.",
        },
        .{
            .key_indices = &.{ 1, 0, 3 },
            .aggnonce_index = 0,
            .msg_index = 0,
            .secnonce_index = 0,
            .comment = "Signer 2 provided an invalid public key",
        },
        .{
            .key_indices = &.{ 1, 2, 0 },
            .aggnonce_index = 2,
            .msg_index = 0,
            .secnonce_index = 0,
            .comment = "Aggregate nonce is invalid due wrong tag, 0x04, in the first half",
        },
        .{
            .key_indices = &.{ 1, 2, 0 },
            .aggnonce_index = 3,
            .msg_index = 0,
            .secnonce_index = 0,
            .comment = "Aggregate nonce is invalid because the second half does not correspond to an X coordinate",
        },
        .{
            .key_indices = &.{ 1, 2, 0 },
            .aggnonce_index = 4,
            .msg_index = 0,
            .secnonce_index = 0,
            .comment = "Aggregate nonce is invalid because second half exceeds field size",
        },
        .{
            .key_indices = &.{ 0, 1, 2 },
            .aggnonce_index = 0,
            .msg_index = 0,
            .secnonce_index = 1,
            .comment = "Secnonce is invalid which may indicate nonce reuse",
        },
    };

    pub const VerifyFailCase = struct {
        sig: []const u8,
        key_indices: []const usize,
        nonce_indices: []const usize,
        msg_index: usize,
        signer_index: usize,
        comment: []const u8,
    };
    pub const verify_fail_test_cases = [_]VerifyFailCase{
        .{
            .sig = "FED54434AD4CFE953FC527DC6A5E5BE8F6234907B7C187559557CE87A0541C46",
            .key_indices = &.{ 0, 1, 2 },
            .nonce_indices = &.{ 0, 1, 2 },
            .msg_index = 0,
            .signer_index = 0,
            .comment = "Wrong signature (which is equal to the negation of valid signature)",
        },
        .{
            .sig = "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB",
            .key_indices = &.{ 0, 1, 2 },
            .nonce_indices = &.{ 0, 1, 2 },
            .msg_index = 0,
            .signer_index = 1,
            .comment = "Wrong signer",
        },
        .{
            .sig = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
            .key_indices = &.{ 0, 1, 2 },
            .nonce_indices = &.{ 0, 1, 2 },
            .msg_index = 0,
            .signer_index = 0,
            .comment = "Signature exceeds group size",
        },
    };

    pub const VerifyErrorCase = struct {
        sig: []const u8,
        key_indices: []const usize,
        nonce_indices: []const usize,
        msg_index: usize,
        signer_index: usize,
        invalid_contrib: []const u8,
        comment: []const u8,
    };
    pub const verify_error_test_cases = [_]VerifyErrorCase{
        .{
            .sig = "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB",
            .key_indices = &.{ 0, 1, 2 },
            .nonce_indices = &.{ 4, 1, 2 },
            .msg_index = 0,
            .signer_index = 0,
            .invalid_contrib = "pubnonce",
            .comment = "Invalid pubnonce",
        },
        .{
            .sig = "012ABBCB52B3016AC03AD82395A1A415C48B93DEF78718E62A7A90052FE224FB",
            .key_indices = &.{ 3, 1, 2 },
            .nonce_indices = &.{ 0, 1, 2 },
            .msg_index = 0,
            .signer_index = 0,
            .invalid_contrib = "pubkey",
            .comment = "Invalid pubkey",
        },
    };
};

// ---- tweak_vectors.json --------------------------------------------------

pub const tweak = struct {
    pub const sk = "7FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671";

    pub const pubkeys: []const []const u8 = &.{
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
    };

    pub const secnonce = "508B81A611F100A6B2B6B29656590898AF488BCF2E1F55CF22E5CFB84421FE61FA27FD49B1D50085B481285E1CA205D55C82CC1B31FF5CD54A489829355901F703935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9";

    pub const pnonces: []const []const u8 = &.{
        "0337C87821AFD50A8644D820A8F3E02E499C931865C2360FB43D0A0D20DAFE07EA0287BF891D2A6DEAEBADC909352AA9405D1428C15F4B75F04DAE642A95C2548480",
        "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F817980279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        "032DE2662628C90B03F5E720284EB52FF7D71F4284F627B68A853D78C78E1FFE9303E4C5524E83FFE1493B9077CF1CA6BEB2090C93D930321071AD40B2F44E599046",
    };

    pub const aggnonce = "028465FCF0BBDBCF443AABCCE533D42B4B5A10966AC09A49655E8C42DAAB8FCD61037496A3CC86926D452CAFCFD55D25972CA1675D549310DE296BFF42F72EEEA8C9";

    pub const tweaks: []const []const u8 = &.{
        "E8F791FF9225A2AF0102AFFF4A9A723D9612A682A25EBE79802B263CDFCD83BB",
        "AE2EA797CC0FE72AC5B97B97F3C6957D7E4199A167A58EB08BCAFFDA70AC0455",
        "F52ECBC565B3D8BEA2DFD5B75A4F457E54369809322E4120831626F290FA87E0",
        "1969AD73CC177FA0B4FCED6DF1F7BF9907E665FDE9BA196A74FED0A3CF5AEF9D",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    };

    pub const msg = "F95466D086770E689964664219266FE5ED215C92AE20BAB5C9D79ADDDDF3C0CF";

    pub const ValidCase = struct {
        key_indices: []const usize,
        nonce_indices: []const usize,
        tweak_indices: []const usize,
        is_xonly: []const bool,
        signer_index: usize,
        expected: []const u8,
        comment: []const u8,
    };
    pub const valid_test_cases = [_]ValidCase{
        .{
            .key_indices = &.{ 1, 2, 0 },
            .nonce_indices = &.{ 1, 2, 0 },
            .tweak_indices = &.{0},
            .is_xonly = &.{true},
            .signer_index = 2,
            .expected = "E28A5C66E61E178C2BA19DB77B6CF9F7E2F0F56C17918CD13135E60CC848FE91",
            .comment = "A single x-only tweak",
        },
        .{
            .key_indices = &.{ 1, 2, 0 },
            .nonce_indices = &.{ 1, 2, 0 },
            .tweak_indices = &.{0},
            .is_xonly = &.{false},
            .signer_index = 2,
            .expected = "38B0767798252F21BF5702C48028B095428320F73A4B14DB1E25DE58543D2D2D",
            .comment = "A single plain tweak",
        },
        .{
            .key_indices = &.{ 1, 2, 0 },
            .nonce_indices = &.{ 1, 2, 0 },
            .tweak_indices = &.{ 0, 1 },
            .is_xonly = &.{ false, true },
            .signer_index = 2,
            .expected = "408A0A21C4A0F5DACAF9646AD6EB6FECD7F7A11F03ED1F48DFFF2185BC2C2408",
            .comment = "A plain tweak followed by an x-only tweak",
        },
        .{
            .key_indices = &.{ 1, 2, 0 },
            .nonce_indices = &.{ 1, 2, 0 },
            .tweak_indices = &.{ 0, 1, 2, 3 },
            .is_xonly = &.{ false, false, true, true },
            .signer_index = 2,
            .expected = "45ABD206E61E3DF2EC9E264A6FEC8292141A633C28586388235541F9ADE75435",
            .comment = "Four tweaks: plain, plain, x-only, x-only.",
        },
        .{
            .key_indices = &.{ 1, 2, 0 },
            .nonce_indices = &.{ 1, 2, 0 },
            .tweak_indices = &.{ 0, 1, 2, 3 },
            .is_xonly = &.{ true, false, true, false },
            .signer_index = 2,
            .expected = "B255FDCAC27B40C7CE7848E2D3B7BF5EA0ED756DA81565AC804CCCA3E1D5D239",
            .comment = "Four tweaks: x-only, plain, x-only, plain. If an implementation prohibits applying plain tweaks after x-only tweaks, it can skip this test vector or return an error.",
        },
    };

    pub const ErrorCase = struct {
        key_indices: []const usize,
        nonce_indices: []const usize,
        tweak_indices: []const usize,
        is_xonly: []const bool,
        signer_index: usize,
        comment: []const u8,
    };
    pub const error_test_cases = [_]ErrorCase{
        .{
            .key_indices = &.{ 1, 2, 0 },
            .nonce_indices = &.{ 1, 2, 0 },
            .tweak_indices = &.{4},
            .is_xonly = &.{false},
            .signer_index = 2,
            .comment = "Tweak is invalid because it exceeds group size",
        },
    };
};

// ---- sig_agg_vectors.json --------------------------------------------------

pub const sig_agg = struct {
    pub const pubkeys: []const []const u8 = &.{
        "03935F972DA013F80AE011890FA89B67A27B7BE6CCB24D3274D18B2D4067F261A9",
        "02D2DC6F5DF7C56ACF38C7FA0AE7A759AE30E19B37359DFDE015872324C7EF6E05",
        "03C7FB101D97FF930ACD0C6760852EF64E69083DE0B06AC6335724754BB4B0522C",
        "02352433B21E7E05D3B452B81CAE566E06D2E003ECE16D1074AABA4289E0E3D581",
    };

    pub const pnonces: []const []const u8 = &.{
        "036E5EE6E28824029FEA3E8A9DDD2C8483F5AF98F7177C3AF3CB6F47CAF8D94AE902DBA67E4A1F3680826172DA15AFB1A8CA85C7C5CC88900905C8DC8C328511B53E",
        "03E4F798DA48A76EEC1C9CC5AB7A880FFBA201A5F064E627EC9CB0031D1D58FC5103E06180315C5A522B7EC7C08B69DCD721C313C940819296D0A7AB8E8795AC1F00",
        "02C0068FD25523A31578B8077F24F78F5BD5F2422AFF47C1FADA0F36B3CEB6C7D202098A55D1736AA5FCC21CF0729CCE852575C06C081125144763C2C4C4A05C09B6",
        "031F5C87DCFBFCF330DEE4311D85E8F1DEA01D87A6F1C14CDFC7E4F1D8C441CFA40277BF176E9F747C34F81B0D9F072B1B404A86F402C2D86CF9EA9E9C69876EA3B9",
        "023F7042046E0397822C4144A17F8B63D78748696A46C3B9F0A901D296EC3406C302022B0B464292CF9751D699F10980AC764E6F671EFCA15069BBE62B0D1C62522A",
        "02D97DDA5988461DF58C5897444F116A7C74E5711BF77A9446E27806563F3B6C47020CBAD9C363A7737F99FA06B6BE093CEAFF5397316C5AC46915C43767AE867C00",
    };

    pub const tweaks: []const []const u8 = &.{
        "B511DA492182A91B0FFB9A98020D55F260AE86D7ECBD0399C7383D59A5F2AF7C",
        "A815FE049EE3C5AAB66310477FBC8BCCCAC2F3395F59F921C364ACD78A2F48DC",
        "75448A87274B056468B977BE06EB1E9F657577B7320B0A3376EA51FD420D18A8",
    };

    pub const psigs: []const []const u8 = &.{
        "B15D2CD3C3D22B04DAE438CE653F6B4ECF042F42CFDED7C41B64AAF9B4AF53FB",
        "6193D6AC61B354E9105BBDC8937A3454A6D705B6D57322A5A472A02CE99FCB64",
        "9A87D3B79EC67228CB97878B76049B15DBD05B8158D17B5B9114D3C226887505",
        "66F82EA90923689B855D36C6B7E032FB9970301481B99E01CDB4D6AC7C347A15",
        "4F5AEE41510848A6447DCD1BBC78457EF69024944C87F40250D3EF2C25D33EFE",
        "DDEF427BBB847CC027BEFF4EDB01038148917832253EBC355FC33F4A8E2FCCE4",
        "97B890A26C981DA8102D3BC294159D171D72810FDF7C6A691DEF02F0F7AF3FDC",
        "53FA9E08BA5243CBCB0D797C5EE83BC6728E539EB76C2D0BF0F971EE4E909971",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    };

    pub const msg = "599C67EA410D005B9DA90817CF03ED3B1C868E4DA4EDF00A5880B0082C237869";

    pub const ValidCase = struct {
        aggnonce: []const u8,
        nonce_indices: []const usize,
        key_indices: []const usize,
        tweak_indices: []const usize,
        is_xonly: []const bool,
        psig_indices: []const usize,
        expected: []const u8,
    };
    pub const valid_test_cases = [_]ValidCase{
        .{
            .aggnonce = "0341432722C5CD0268D829C702CF0D1CBCE57033EED201FD335191385227C3210C03D377F2D258B64AADC0E16F26462323D701D286046A2EA93365656AFD9875982B",
            .nonce_indices = &.{ 0, 1 },
            .key_indices = &.{ 0, 1 },
            .tweak_indices = &.{},
            .is_xonly = &.{},
            .psig_indices = &.{ 0, 1 },
            .expected = "041DA22223CE65C92C9A0D6C2CAC828AAF1EEE56304FEC371DDF91EBB2B9EF0912F1038025857FEDEB3FF696F8B99FA4BB2C5812F6095A2E0004EC99CE18DE1E",
        },
        .{
            .aggnonce = "0224AFD36C902084058B51B5D36676BBA4DC97C775873768E58822F87FE437D792028CB15929099EEE2F5DAE404CD39357591BA32E9AF4E162B8D3E7CB5EFE31CB20",
            .nonce_indices = &.{ 0, 2 },
            .key_indices = &.{ 0, 2 },
            .tweak_indices = &.{},
            .is_xonly = &.{},
            .psig_indices = &.{ 2, 3 },
            .expected = "1069B67EC3D2F3C7C08291ACCB17A9C9B8F2819A52EB5DF8726E17E7D6B52E9F01800260A7E9DAC450F4BE522DE4CE12BA91AEAF2B4279219EF74BE1D286ADD9",
        },
        .{
            .aggnonce = "0208C5C438C710F4F96A61E9FF3C37758814B8C3AE12BFEA0ED2C87FF6954FF186020B1816EA104B4FCA2D304D733E0E19CEAD51303FF6420BFD222335CAA402916D",
            .nonce_indices = &.{ 0, 3 },
            .key_indices = &.{ 0, 2 },
            .tweak_indices = &.{0},
            .is_xonly = &.{false},
            .psig_indices = &.{ 4, 5 },
            .expected = "5C558E1DCADE86DA0B2F02626A512E30A22CF5255CAEA7EE32C38E9A71A0E9148BA6C0E6EC7683B64220F0298696F1B878CD47B107B81F7188812D593971E0CC",
        },
        .{
            .aggnonce = "02B5AD07AFCD99B6D92CB433FBD2A28FDEB98EAE2EB09B6014EF0F8197CD58403302E8616910F9293CF692C49F351DB86B25E352901F0E237BAFDA11F1C1CEF29FFD",
            .nonce_indices = &.{ 0, 4 },
            .key_indices = &.{ 0, 3 },
            .tweak_indices = &.{ 0, 1, 2 },
            .is_xonly = &.{ true, false, true },
            .psig_indices = &.{ 6, 7 },
            .expected = "839B08820B681DBA8DAF4CC7B104E8F2638F9388F8D7A555DC17B6E6971D7426CE07BF6AB01F1DB50E4E33719295F4094572B79868E440FB3DEFD3FAC1DB589E",
        },
    };

    pub const ErrorCase = struct {
        aggnonce: []const u8,
        nonce_indices: []const usize,
        key_indices: []const usize,
        tweak_indices: []const usize,
        is_xonly: []const bool,
        psig_indices: []const usize,
        invalid_psig_signer: usize,
        comment: []const u8,
    };
    pub const error_test_cases = [_]ErrorCase{
        .{
            .aggnonce = "02B5AD07AFCD99B6D92CB433FBD2A28FDEB98EAE2EB09B6014EF0F8197CD58403302E8616910F9293CF692C49F351DB86B25E352901F0E237BAFDA11F1C1CEF29FFD",
            .nonce_indices = &.{ 0, 4 },
            .key_indices = &.{ 0, 3 },
            .tweak_indices = &.{ 0, 1, 2 },
            .is_xonly = &.{ true, false, true },
            .psig_indices = &.{ 7, 8 },
            .invalid_psig_signer = 1,
            .comment = "Partial signature is invalid because it exceeds group size",
        },
    };
};
