// SPDX-License-Identifier: MIT
//! SELF-AUTHORED reference vectors for Schnorr adaptor signatures.
//!
//! No BIP or other public specification numbers a Schnorr adaptor-signature
//! test suite (unlike `bip340`/`musig2`, which embed the official
//! `bitcoin/bips` vectors verbatim) — this scheme's only "standard" is the
//! scriptless-scripts literature's construction, cross-validated here
//! against secp256kfun's `schnorr_fun::adaptor` Rust implementation (see
//! `../NOTICE`).
//!
//! These six vectors were computed independently in Python (a from-scratch
//! secp256k1 field/point implementation, NOT libsecp256k1 or any Zig code
//! from this module — see `../NOTICE` for the exact generation method),
//! following the identical 9-step `preSign` construction documented in
//! `root.zig`'s doc comments, and cross-checked three ways before being
//! transcribed here:
//!
//!   1. `preVerify`'s equation (independently re-derived in Python) accepts
//!      every one of the six pre-signatures.
//!   2. `adapt`'s output — `sig` below — verifies under a from-scratch
//!      Python re-implementation of PLAIN `bip340.verify`'s own equation
//!      (`s*G - e*P` recomputed from the published test vectors' formulas)
//!      against `px`. This is the scheme's headline property: an adaptor
//!      signature completes into an ORDINARY BIP340 signature.
//!   3. `extract` recovers `recovered_t`, and `recovered_t == t` BYTE-
//!      EXACTLY (not just group-equivalent) for all six.
//!
//! Coverage: `needs_negation` is `true` for vectors 3 and 5, `false` for
//! the rest — both branches of the scheme's central parity subtlety (see
//! `root.zig`'s `PreSignature` doc comment) are exercised. Secret keys for
//! vectors 3 and 4 have an ODD-y public key point (so `bip340.KeyPair`'s
//! own even-y normalization branch, `d = n - d'`, is exercised too,
//! independently of `needs_negation`); the rest have an already-even-y
//! public key. Vector 3 additionally covers the empty message
//! (`msg.len == 0`, mirroring BIP340 test-vector index 15's coverage).

pub const Vector = struct {
    label: []const u8,
    sk: []const u8, // 32 bytes, hex
    t: []const u8, // 32 bytes, hex — the adaptor secret
    msg: []const u8, // raw message bytes (not hex)
    aux_rand: []const u8, // 32 bytes, hex
    adaptor_point: []const u8, // 33 bytes, hex, SEC1-compressed T = t*G
    px: []const u8, // 32 bytes, hex — the even-y-normalized x-only pubkey
    r: []const u8, // 32 bytes, hex — expected PreSignature.r
    s_prime: []const u8, // 32 bytes, hex — expected PreSignature.s_prime
    needs_negation: bool,
    sig: []const u8, // 64 bytes, hex — expected adapt() output
    recovered_t: []const u8, // 32 bytes, hex — expected extract() output (== t)
};

pub const vectors = [_]Vector{
    .{
        .label = "vector 0 - baseline, sk=1, t=2, needs_negation=false",
        .sk = "0000000000000000000000000000000000000000000000000000000000000001",
        .t = "0000000000000000000000000000000000000000000000000000000000000002",
        .msg = "adaptor sig test vector 1 - baseline PTLC-shaped",
        .aux_rand = "0101010101010101010101010101010101010101010101010101010101010101",
        .adaptor_point = "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
        .px = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        .r = "863398BEF6E3EE4E3D40BFD60E06803F429FC05BA5A5A310C3D0D09DBEAC1CA3",
        .s_prime = "95A88D558D9140464AD5670A6AC6122F2B112C768E5D679ECE6B8C81F7ED4200",
        .needs_negation = false,
        .sig = "863398BEF6E3EE4E3D40BFD60E06803F429FC05BA5A5A310C3D0D09DBEAC1CA395A88D558D9140464AD5670A6AC6122F2B112C768E5D679ECE6B8C81F7ED4202",
        .recovered_t = "0000000000000000000000000000000000000000000000000000000000000002",
    },
    .{
        .label = "vector 1 - sk=2, t=3, short message, needs_negation=false",
        .sk = "0000000000000000000000000000000000000000000000000000000000000002",
        .t = "0000000000000000000000000000000000000000000000000000000000000003",
        .msg = "adaptor sig test vector 2",
        .aux_rand = "0202020202020202020202020202020202020202020202020202020202020202",
        .adaptor_point = "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        .px = "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
        .r = "213B33C53D7E5270E93FA5F1B9619A1144A66C4F5E9ADF2A03AE13DE377B6F7C",
        .s_prime = "FD762BB19FD84B75696E67CF1FB7C764CD0748CF4651AD9849C17EB1456D46C3",
        .needs_negation = false,
        .sig = "213B33C53D7E5270E93FA5F1B9619A1144A66C4F5E9ADF2A03AE13DE377B6F7CFD762BB19FD84B75696E67CF1FB7C764CD0748CF4651AD9849C17EB1456D46C6",
        .recovered_t = "0000000000000000000000000000000000000000000000000000000000000003",
    },
    .{
        .label = "vector 2 - large 256-bit sk/t, needs_negation=false",
        .sk = "0FB9E0E687ADA1EEBF7ECFE2F21E73EBDB51A7D450948DFE8D76D7F2D1007671",
        .t = "0C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E75",
        .msg = "adaptor sig test vector 3 - larger scalars",
        .aux_rand = "0303030303030303030303030303030303030303030303030303030303030303",
        .adaptor_point = "02DE19F4EC6232A6365F14A3DDF8D0D0850B189F0B5629F61224EDE9C0A3712C4B",
        .px = "FEA016308F801F22B11DE200313C0E15FA6178B22BE60468E34A67239FDA7DB7",
        .r = "DB05C87BB48BAB5C06940CDC82CC23B50D6D2EC55CA36A87B595AA20C536AEB6",
        .s_prime = "2E94624638D2FA95958E6C56F43787EDB8481B887E7B3FB99804ED105EB49CC0",
        .needs_negation = false,
        .sig = "DB05C87BB48BAB5C06940CDC82CC23B50D6D2EC55CA36A87B595AA20C536AEB63B255FF05AE986B8E1DAD27FAC4549BACAD840690721BC80D825A8FAC265EB35",
        .recovered_t = "0C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E75",
    },
    .{
        .label = "vector 3 - empty message, sk needs even-y normalization, needs_negation=true",
        .sk = "0000000000000000000000000000000000000000000000000000000000003039",
        .t = "0000000000000000000000000000000000000000000000000000000000010932",
        .msg = "",
        .aux_rand = "0404040404040404040404040404040404040404040404040404040404040404",
        .adaptor_point = "0254006A630E70FCA8D45A696D7DBA3A1CB7D81CC830CFCE3BE0F634373AAC3F0A",
        .px = "F01D6B9018AB421DD410404CB869072065522BF85734008F105CF385A023A80F",
        .r = "DF674AA5DECBFBAF1A71793E44A8732867D0A720301C153E5CB114144563E007",
        .s_prime = "2C041FF38462BFAFEE549A28E3D47D25F5713649BE8B4DE0FCC872154E69259B",
        .needs_negation = true,
        .sig = "DF674AA5DECBFBAF1A71793E44A8732867D0A720301C153E5CB114144563E0072C041FF38462BFAFEE549A28E3D47D25F5713649BE8B4DE0FCC872154E681C69",
        .recovered_t = "0000000000000000000000000000000000000000000000000000000000010932",
    },
    .{
        .label = "vector 4 - sk needs even-y normalization, t=5, needs_negation=false",
        .sk = "00000000000000000000000000000000000004EE2D6D415B85ACEF80FFFFFFFF",
        .t = "0000000000000000000000000000000000000000000000000000000000000005",
        .msg = "adaptor sig test vector 5",
        .aux_rand = "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB",
        .adaptor_point = "022F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4",
        .px = "0D06BF768041DBBAC6D365706BF95C2330420D1B714644BB57F49B2A3D94C2EA",
        .r = "F810DB1FCCC1371128BBFF066DAAA1B98D059C88BEE8C803D1607D0777B6C9C2",
        .s_prime = "F38FFF07392D99E781A9169D0D22568A8BE023EB59A60B6933CC0BB9AE4D970C",
        .needs_negation = false,
        .sig = "F810DB1FCCC1371128BBFF066DAAA1B98D059C88BEE8C803D1607D0777B6C9C2F38FFF07392D99E781A9169D0D22568A8BE023EB59A60B6933CC0BB9AE4D9711",
        .recovered_t = "0000000000000000000000000000000000000000000000000000000000000005",
    },
    .{
        .label = "vector 5 - long (121-byte) message, needs_negation=true",
        .sk = "0000000000000000000000000000000000000000000000000000000000000007",
        .t = "00000000000000000000000000000000000000000000000000000062C6D1A9B2",
        .msg = "adaptor sig test vector 6 - long message xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        .aux_rand = "0606060606060606060606060606060606060606060606060606060606060606",
        .adaptor_point = "02C599C1546F2719F078F62FFB9A742FF2B30A3D61532B1A36BDFA3DFE8DD8A94A",
        .px = "5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC",
        .r = "CDDEE4ABEB0DD649D3E59F9073457623ADC015B2C93CDC2368F5316D1B3FB9B7",
        .s_prime = "5CE42D31DC50E899F97F92C258E17F531FA16CA7778FA5F5E774BC8C37FC021E",
        .needs_negation = true,
        .sig = "CDDEE4ABEB0DD649D3E59F9073457623ADC015B2C93CDC2368F5316D1B3FB9B75CE42D31DC50E899F97F92C258E17F531FA16CA7778FA5F5E774BC29712A586C",
        .recovered_t = "00000000000000000000000000000000000000000000000000000062C6D1A9B2",
    },
};
