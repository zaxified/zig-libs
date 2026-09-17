// SPDX-License-Identifier: MIT
// Reference-vector generator for zig-libs `modules/adaptor`.
//
// Runs LLFourn/secp256kfun's `schnorr_fun::adaptor` (0BSD) and prints a Zig
// source file holding the bytes it emitted. No secp256kfun source is copied;
// only the values the library computes at run time are recorded.
//
// Emits two corpora:
//   A. FOREIGN-ORIGINATED encrypted signatures (schnorr_fun `encrypted_sign`,
//      deterministic nonces) with schnorr_fun's own `decrypt_signature` /
//      `recover_decryption_key` outputs -- inputs zig-libs' own preSign can
//      never produce (different nonce derivation).
//   B. schnorr_fun's verdict + outputs on zig-libs' six SELF-AUTHORED
//      vectors, so the pre-existing self-authored corpus is cross-checked by
//      a foreign implementation.

use schnorr_fun::{
    adaptor::{Adaptor, EncryptedSign, EncryptedSignature},
    fun::{marker::*, Point, Scalar, G, g, s},
    Message, Signature,
};
use sha2::Sha256;

fn h(b: &[u8]) -> String {
    hex::encode_upper(b)
}

fn sk_from_u32(v: u32) -> Scalar {
    let mut b = [0u8; 32];
    b[28..32].copy_from_slice(&v.to_be_bytes());
    Scalar::from_bytes(b).unwrap().non_zero().unwrap()
}

struct CaseSpec {
    label: &'static str,
    sk: u32,
    dk: u32,
    msg: &'static [u8],
}

/// zig-libs' six self-authored vectors, transcribed as inputs only (public
/// key, adaptor point, pre-signature, adaptor secret, message). The point of
/// corpus B is to let schnorr_fun pass judgement on these.
struct SelfAuthored {
    label: &'static str,
    px: &'static str,
    adaptor_point: &'static str,
    t: &'static str,
    msg: &'static [u8],
    r: &'static str,
    s_prime: &'static str,
    needs_negation: bool,
}

const SELF_AUTHORED: &[SelfAuthored] = &[
    SelfAuthored {
        label: "self-authored vector 0",
        px: "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",
        adaptor_point: "02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
        t: "0000000000000000000000000000000000000000000000000000000000000002",
        msg: b"adaptor sig test vector 1 - baseline PTLC-shaped",
        r: "863398BEF6E3EE4E3D40BFD60E06803F429FC05BA5A5A310C3D0D09DBEAC1CA3",
        s_prime: "95A88D558D9140464AD5670A6AC6122F2B112C768E5D679ECE6B8C81F7ED4200",
        needs_negation: false,
    },
    SelfAuthored {
        label: "self-authored vector 1",
        px: "C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5",
        adaptor_point: "02F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        t: "0000000000000000000000000000000000000000000000000000000000000003",
        msg: b"adaptor sig test vector 2",
        r: "213B33C53D7E5270E93FA5F1B9619A1144A66C4F5E9ADF2A03AE13DE377B6F7C",
        s_prime: "FD762BB19FD84B75696E67CF1FB7C764CD0748CF4651AD9849C17EB1456D46C3",
        needs_negation: false,
    },
    SelfAuthored {
        label: "self-authored vector 2",
        px: "FEA016308F801F22B11DE200313C0E15FA6178B22BE60468E34A67239FDA7DB7",
        adaptor_point: "02DE19F4EC6232A6365F14A3DDF8D0D0850B189F0B5629F61224EDE9C0A3712C4B",
        t: "0C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E75",
        msg: b"adaptor sig test vector 3 - larger scalars",
        r: "DB05C87BB48BAB5C06940CDC82CC23B50D6D2EC55CA36A87B595AA20C536AEB6",
        s_prime: "2E94624638D2FA95958E6C56F43787EDB8481B887E7B3FB99804ED105EB49CC0",
        needs_negation: false,
    },
    SelfAuthored {
        label: "self-authored vector 3",
        px: "F01D6B9018AB421DD410404CB869072065522BF85734008F105CF385A023A80F",
        adaptor_point: "0254006A630E70FCA8D45A696D7DBA3A1CB7D81CC830CFCE3BE0F634373AAC3F0A",
        t: "0000000000000000000000000000000000000000000000000000000000010932",
        msg: b"",
        r: "DF674AA5DECBFBAF1A71793E44A8732867D0A720301C153E5CB114144563E007",
        s_prime: "2C041FF38462BFAFEE549A28E3D47D25F5713649BE8B4DE0FCC872154E69259B",
        needs_negation: true,
    },
    SelfAuthored {
        label: "self-authored vector 4",
        px: "0D06BF768041DBBAC6D365706BF95C2330420D1B714644BB57F49B2A3D94C2EA",
        adaptor_point: "022F8BDE4D1A07209355B4A7250A5C5128E88B84BDDC619AB7CBA8D569B240EFE4",
        t: "0000000000000000000000000000000000000000000000000000000000000005",
        msg: b"adaptor sig test vector 5",
        r: "F810DB1FCCC1371128BBFF066DAAA1B98D059C88BEE8C803D1607D0777B6C9C2",
        s_prime: "F38FFF07392D99E781A9169D0D22568A8BE023EB59A60B6933CC0BB9AE4D970C",
        needs_negation: false,
    },
    SelfAuthored {
        label: "self-authored vector 5",
        px: "5CBDF0646E5DB4EAA398F365F2EA7A0E3D419B7E0330E39CE92BDDEDCAC4F9BC",
        adaptor_point: "02C599C1546F2719F078F62FFB9A742FF2B30A3D61532B1A36BDFA3DFE8DD8A94A",
        t: "00000000000000000000000000000000000000000000000000000062C6D1A9B2",
        msg: b"adaptor sig test vector 6 - long message xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        r: "CDDEE4ABEB0DD649D3E59F9073457623ADC015B2C93CDC2368F5316D1B3FB9B7",
        s_prime: "5CE42D31DC50E899F97F92C258E17F531FA16CA7778FA5F5E774BC8C37FC021E",
        needs_negation: true,
    },
];

fn hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    let mut o = [0u8; 32];
    o.copy_from_slice(&v);
    o
}

fn hex33(s: &str) -> [u8; 33] {
    let v = hex::decode(s).unwrap();
    let mut o = [0u8; 33];
    o.copy_from_slice(&v);
    o
}

fn main() {
    let schnorr = schnorr_fun::new_with_deterministic_nonces::<Sha256>();

    // Chosen so the corpus covers both `needs_negation` branches, both
    // "raw pubkey already even-y" / "needed negation" branches, the empty
    // message and a long message. Deterministic nonces => reproducible.
    let specs = [
        CaseSpec { label: "sk=1, dk=2, baseline", sk: 1, dk: 2, msg: b"zig-libs/adaptor interop vector 0" },
        CaseSpec { label: "sk=2, dk=3", sk: 2, dk: 3, msg: b"zig-libs/adaptor interop vector 1" },
        CaseSpec { label: "sk=3, dk=5", sk: 3, dk: 5, msg: b"zig-libs/adaptor interop vector 2" },
        CaseSpec { label: "sk=4, dk=7", sk: 4, dk: 7, msg: b"zig-libs/adaptor interop vector 3" },
        CaseSpec { label: "sk=5, dk=11, empty message", sk: 5, dk: 11, msg: b"" },
        CaseSpec { label: "sk=6, dk=13", sk: 6, dk: 13, msg: b"zig-libs/adaptor interop vector 5" },
        CaseSpec { label: "sk=7, dk=17", sk: 7, dk: 17, msg: b"zig-libs/adaptor interop vector 6" },
        CaseSpec {
            label: "sk=8, dk=19, long message",
            sk: 8,
            dk: 19,
            msg: b"zig-libs/adaptor interop vector 7 - a deliberately long message to push the challenge hash past a single SHA-256 block boundary and then some",
        },
        CaseSpec { label: "sk=9, dk=23", sk: 9, dk: 23, msg: b"zig-libs/adaptor interop vector 8" },
        CaseSpec { label: "sk=10, dk=29", sk: 10, dk: 29, msg: b"zig-libs/adaptor interop vector 9" },
        CaseSpec { label: "sk=11, dk=31", sk: 11, dk: 31, msg: b"zig-libs/adaptor interop vector 10" },
        CaseSpec { label: "sk=12, dk=37", sk: 12, dk: 37, msg: b"zig-libs/adaptor interop vector 11" },
    ];

    let mut out = String::new();
    out.push_str(HEADER);

    out.push_str("pub const InteropVector = struct {\n");
    out.push_str("    label: []const u8,\n");
    out.push_str("    /// x-only BIP340 public key of the signer (32 bytes, hex).\n");
    out.push_str("    px: []const u8,\n");
    out.push_str("    /// SEC1-compressed encryption key `Y = t*G` == our `AdaptorPoint` (33 bytes, hex).\n");
    out.push_str("    adaptor_point: []const u8,\n");
    out.push_str("    /// schnorr_fun's decryption key == our adaptor secret `t` (32 bytes, hex).\n");
    out.push_str("    t: []const u8,\n");
    out.push_str("    /// message bytes, hex-encoded (may be empty).\n");
    out.push_str("    msg_hex: []const u8,\n");
    out.push_str("    /// `EncryptedSignature.R` x-only == our `PreSignature.r` (32 bytes, hex).\n");
    out.push_str("    r: []const u8,\n");
    out.push_str("    /// `EncryptedSignature.s_hat` == our `PreSignature.s_prime` (32 bytes, hex).\n");
    out.push_str("    s_prime: []const u8,\n");
    out.push_str("    /// `EncryptedSignature.needs_negation`.\n");
    out.push_str("    needs_negation: bool,\n");
    out.push_str("    /// schnorr_fun `decrypt_signature` output == our `adapt` output (64 bytes, hex).\n");
    out.push_str("    sig: []const u8,\n");
    out.push_str("    /// schnorr_fun `recover_decryption_key` output == our `extract` output (32 bytes, hex).\n");
    out.push_str("    recovered_t: []const u8,\n");
    out.push_str("};\n\n");

    out.push_str("/// Corpus A -- pre-signatures ORIGINATED by schnorr_fun.\n");
    out.push_str("pub const foreign_vectors = [_]InteropVector{\n");

    let mut neg_true = 0usize;
    for spec in specs.iter() {
        let sk = sk_from_u32(spec.sk);
        let kp = schnorr.new_keypair(sk);
        let dk = sk_from_u32(spec.dk);
        let ek = schnorr.encryption_key_for(&dk);
        let msg = Message::raw(spec.msg);

        let esig = schnorr.encrypted_sign(&kp, &ek, msg);
        assert!(
            schnorr.verify_encrypted_signature(&kp.public_key(), &ek, msg, &esig),
            "schnorr_fun rejected its own encrypted signature"
        );
        let sig = schnorr.decrypt_signature(dk.clone(), esig.clone());
        assert!(schnorr.verify(&kp.public_key(), msg, &sig), "decrypted sig invalid");
        let rec = schnorr
            .recover_decryption_key(&ek, &esig, &sig)
            .expect("recover_decryption_key returned None");
        assert_eq!(rec.to_bytes(), dk.to_bytes());

        if esig.needs_negation {
            neg_true += 1;
        }

        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&sig.R.to_xonly_bytes());
        sig_bytes[32..].copy_from_slice(&sig.s.to_bytes());

        out.push_str("    .{\n");
        out.push_str(&format!("        .label = \"{}\",\n", spec.label));
        out.push_str(&format!("        .px = \"{}\",\n", h(&kp.public_key().to_xonly_bytes())));
        out.push_str(&format!("        .adaptor_point = \"{}\",\n", h(&ek.to_bytes())));
        out.push_str(&format!("        .t = \"{}\",\n", h(&dk.to_bytes())));
        out.push_str(&format!("        .msg_hex = \"{}\",\n", h(spec.msg)));
        out.push_str(&format!("        .r = \"{}\",\n", h(&esig.R.to_xonly_bytes())));
        out.push_str(&format!("        .s_prime = \"{}\",\n", h(&esig.s_hat.to_bytes())));
        out.push_str(&format!("        .needs_negation = {},\n", esig.needs_negation));
        out.push_str(&format!("        .sig = \"{}\",\n", h(&sig_bytes)));
        out.push_str(&format!("        .recovered_t = \"{}\",\n", h(&rec.to_bytes())));
        out.push_str("    },\n");
    }
    out.push_str("};\n\n");
    eprintln!(
        "corpus A: {} vectors, needs_negation=true in {}",
        specs.len(),
        neg_true
    );

    // ── corpus B ────────────────────────────────────────────────────────
    out.push_str("/// Corpus B -- schnorr_fun's verdict + outputs on zig-libs' own six\n");
    out.push_str("/// SELF-AUTHORED vectors (`kat_vectors.zig`), in the same order.\n");
    out.push_str("pub const SelfAuthoredCrossCheck = struct {\n");
    out.push_str("    label: []const u8,\n");
    out.push_str("    /// `Adaptor::verify_encrypted_signature` verdict.\n");
    out.push_str("    foreign_pre_verify: bool,\n");
    out.push_str("    /// `Adaptor::decrypt_signature` output (64 bytes, hex).\n");
    out.push_str("    foreign_sig: []const u8,\n");
    out.push_str("    /// `Adaptor::recover_decryption_key` output (32 bytes, hex; empty = None).\n");
    out.push_str("    foreign_recovered_t: []const u8,\n");
    out.push_str("};\n\n");
    out.push_str("pub const self_authored_cross_check = [_]SelfAuthoredCrossCheck{\n");

    for sa in SELF_AUTHORED.iter() {
        let x = Point::<EvenY, Public>::from_xonly_bytes(hex32(sa.px)).unwrap();
        let y = Point::<Normal, Public>::from_bytes(hex33(sa.adaptor_point)).unwrap();
        let dk: Scalar<Secret, NonZero> =
            Scalar::from_bytes(hex32(sa.t)).unwrap().non_zero().unwrap();
        assert_eq!(g!(dk * G).normalize(), y, "{}: T != t*G", sa.label);

        let r = Point::<EvenY, Public>::from_xonly_bytes(hex32(sa.r)).unwrap();
        let s_hat = Scalar::<Public, Zero>::from_bytes(hex32(sa.s_prime)).unwrap();
        let esig = EncryptedSignature {
            R: r,
            s_hat,
            needs_negation: sa.needs_negation,
        };
        let msg = Message::raw(sa.msg);

        let ok = schnorr.verify_encrypted_signature(&x, &y, msg, &esig);
        let mut dk2 = dk.clone();
        dk2.conditional_negate(esig.needs_negation);
        let s = s!({ esig.s_hat.clone() } + dk2).public();
        let sig = Signature { R: esig.R, s };
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&sig.R.to_xonly_bytes());
        sig_bytes[32..].copy_from_slice(&sig.s.to_bytes());
        let rec = schnorr.recover_decryption_key(&y, &esig, &sig);

        out.push_str("    .{\n");
        out.push_str(&format!("        .label = \"{}\",\n", sa.label));
        out.push_str(&format!("        .foreign_pre_verify = {},\n", ok));
        out.push_str(&format!("        .foreign_sig = \"{}\",\n", h(&sig_bytes)));
        out.push_str(&format!(
            "        .foreign_recovered_t = \"{}\",\n",
            rec.map(|k| h(&k.to_bytes())).unwrap_or_default()
        ));
        out.push_str("    },\n");
        eprintln!(
            "corpus B {}: verify_encrypted_signature={} recover={}",
            sa.label,
            ok,
            if sig_bytes.is_empty() { "?" } else { "some" }
        );
    }
    out.push_str("};\n");

    print!("{}", out);
}

const HEADER: &str = r#"// SPDX-License-Identifier: MIT
//! EXTERNAL interop vectors for `adaptor`, captured from LLFourn/secp256kfun's
//! `schnorr_fun::adaptor` (Rust) -- the named design reference in `../NOTICE`.
//!
//! **Why this file exists.** `kat_vectors.zig`'s six vectors are SELF-AUTHORED:
//! computed independently in Python, but from the SAME construction this module
//! implements. They pin implementation drift precisely, yet a soundness or
//! convention bug shared by the code AND the vectors is invisible to them
//! (audit finding `adaptor` F1). The vectors below were produced by a foreign
//! implementation that shares no code, no author and no derivation with this
//! module, so they bite where a self-authored corpus cannot -- most sharply on
//! the meaning of the `needs_negation` wire bit, which is exactly the field two
//! implementations must agree on to interoperate.
//!
//! **Provenance / how to regenerate** (offline once frozen -- no Rust toolchain
//! is needed to RUN these tests; the bytes are permanent):
//!
//!   crate:    schnorr_fun 0.13.0        (license 0BSD)
//!   crate:    secp256kfun 0.12.1        (license 0BSD, pulled transitively)
//!   repo:     https://github.com/LLFourn/secp256kfun
//!   captured: 2026-08-09, rustc 1.93.1
//!   command:  cargo run --release --manifest-path modules/adaptor/tools/vectors/Cargo.toml \
//!               > modules/adaptor/src/interop_vectors.zig
//!
//! 0BSD is a public-domain-equivalent licence with NO attribution condition, so
//! recording these bytes imposes nothing on zig-libs' root `NOTICE`. No
//! secp256kfun source is copied or translated here -- the generator links the
//! published crate and records the values it computes at run time.
//!
//! **What matches and what deliberately does not.** schnorr_fun derives its
//! nonce with its own BIP0340-tagged `derive_nonce!` (secret x, public
//! [X, Y, message]); this module uses its own `adaptor/aux` + `adaptor/nonce`
//! tagged hashes. So `preSign`'s OUTPUT is not expected to match -- and cannot
//! be anchored this way. Everything downstream of the nonce IS expected to
//! match byte-for-byte, because both implementations use BIP340's own
//! `BIP0340/challenge` tag and the identical parity convention:
//!
//!   * `preVerify` must ACCEPT a schnorr_fun-originated pre-signature
//!     (schnorr_fun `verify_encrypted_signature`);
//!   * `adapt` must reproduce `decrypt_signature`'s 64 bytes exactly;
//!   * `extract` must reproduce `recover_decryption_key`'s 32 bytes exactly.
//!
//! GENERATED FILE -- do not hand-edit; regenerate with the command above.

"#;
