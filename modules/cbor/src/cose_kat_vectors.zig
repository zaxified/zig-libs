// SPDX-License-Identifier: MIT
//! External vectors for the COSE layer (`cose.zig`) — RFC 9052 §4.2
//! `COSE_Sign1`. Unlike the CBOR-core vectors in `kat_vectors.zig` (RFC
//! 8949 Appendix A), these exercise `cose.parseSign1`/`cose.sigStructure`
//! specifically: a protected header, the tag-18-wrapped form, the bare-array
//! form, and `Sig_structure` construction with a non-empty `external_aad`.
//!
//! Provenance (each vector's hex is transcribed byte-for-byte, not
//! hand-typed from a paraphrase):
//!
//! - `rfc9052_c2_1` — RFC 9052 Appendix C.2.1 "Single ECDSA Signature", the
//!   COSE spec's own canonical `COSE_Sign1` worked example, taken directly
//!   from the RFC text (https://www.rfc-editor.org/rfc/rfc9052, fetched
//!   2026-07-28). The RFC gives the example in CBOR diagnostic notation plus
//!   a stated total size ("98 bytes"); the hex below was assembled from the
//!   RFC's own field values (protected `h'a10126'`, unprotected `{4: '11'}`,
//!   payload `'This is the content.'`, signature `h'8eb33e4c...cacb36'`) and
//!   independently cross-checked against `cose-wg/Examples`
//!   (github.com/cose-wg/Examples, the COSE working group's own example
//!   repository) `sign1-tests/sign-fail-01.json`, whose `output.cbor` is
//!   byte-identical to this vector except for a deliberately mutated CBOR
//!   tag (998 instead of 18 — that repo's "ChangeCBORTag" failure case, see
//!   `rfc9052_c2_1_wrong_tag` below). Two independent published sources
//!   agreeing on the same bytes is strong provenance; decoded byte length
//!   (98) matches the RFC's own stated size.
//! - `sign_pass_02` — `cose-wg/Examples` `sign1-tests/sign-pass-02.json`
//!   ("External"), fetched 2026-07-28. Same protected/unprotected/payload
//!   shape as the RFC vector but signed with a non-empty `external_aad`;
//!   the file publishes both the final `COSE_Sign1` wire bytes
//!   (`output.cbor`) AND the `Sig_structure` intermediate
//!   (`intermediates.ToBeSign_hex`) that `cose.sigStructure` is checked
//!   against byte-for-byte.
//! - `rfc9052_c2_1_wrong_tag` — the same `cose-wg/Examples` repository's
//!   `sign1-tests/sign-fail-01.json` ("Wrong CBOR Tag"), fetched 2026-07-28:
//!   the RFC 9052 C.2.1 vector re-tagged as CBOR tag 998 instead of 18. This
//!   is a *signature-verification* failure vector from the COSE WG's
//!   perspective (a strict COSE_Sign1 verifier must reject an untagged-as-18
//!   message when it expects one) — not a structural CBOR failure. This
//!   module's `parseSign1` does not check the tag number by design (see
//!   `cose.zig`'s doc comment); `cose_kat_test.zig` uses this vector to
//!   confirm that documented scope boundary against real external test data,
//!   not to assert a rejection.
//!
//! No NOTICE entry: per NOTICE §0, a public RFC/spec is not itself
//! copyrightable, and exercising a third-party test-vector repository's
//! published example DATA (not source code) as a compatibility check needs
//! no attribution entry — same standing as `kat_vectors.zig`'s RFC 8949
//! Appendix A vectors cross-checked against `cbor/test-vectors`.

pub const rfc9052_c2_1 = struct {
    /// Full wire bytes: CBOR tag 18 wrapping the 4-element `COSE_Sign1` array.
    pub const tagged_hex =
        "D28443A10126A10442313154546869732069732074686520636F6E74656E742E" ++
        "58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B01" ++
        "17E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36";
    /// `protected` header bytes (serialized `{1: -7}`, i.e. `alg: ES256`).
    pub const protected_hex = "A10126";
    /// `payload` field content, ASCII "This is the content." (21 bytes).
    pub const payload = "This is the content.";
    /// `signature` field (64 bytes, ECDSA P-256).
    pub const signature_hex =
        "8EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF0B0117" ++
        "E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36";
    /// `Sig_structure` bytes for this vector with an empty `external_aad`
    /// (`cose-wg/Examples` `sign1-tests/sign-fail-01.json`
    /// `intermediates.ToBeSign_hex` — same base vector, see file doc comment).
    pub const sig_structure_hex =
        "846A5369676E61747572653143A101264054546869732069732074686520636F" ++
        "6E74656E742E";
};

pub const sign_pass_02 = struct {
    /// Full wire bytes (CBOR tag 18) — `cose-wg/Examples`
    /// `sign1-tests/sign-pass-02.json` `output.cbor`.
    pub const tagged_hex =
        "D28443A10126A10442313154546869732069732074686520636F6E74656E742E" ++
        "584010729CD711CB3813D8D8E944A8DA7111E7B258C9BDCA6135F7AE1ADBEE950" ++
        "9891267837E1E33BD36C150326AE62755C6BD8E540C3E8F92D7D225E8DB72B8820B";
    /// External AAD used when this vector was signed (not carried on the
    /// wire — a caller must supply it out-of-band to `sigStructure`).
    pub const external_aad_hex = "11AA22BB33CC44DD55006699";
    /// Published `Sig_structure` intermediate
    /// (`intermediates.ToBeSign_hex`), includes the external_aad above.
    pub const sig_structure_hex =
        "846A5369676E61747572653143A101264C11AA22BB33CC44DD5500669954546869" ++
        "732069732074686520636F6E74656E742E";
};

/// `cose-wg/Examples` `sign1-tests/sign-fail-01.json` ("Wrong CBOR Tag") —
/// the RFC 9052 C.2.1 vector re-tagged 998 instead of 18. A COSE-conformant
/// *strict* verifier must reject this; this module's `parseSign1` does not
/// check the tag number (documented scope boundary) and parses it the same
/// as `rfc9052_c2_1` above.
pub const rfc9052_c2_1_wrong_tag = struct {
    pub const tagged_hex =
        "D903E68443A10126A10442313154546869732069732074686520636F6E74656E" ++
        "742E58408EB33E4CA31D1C465AB05AAC34CC6B23D58FEF5C083106C4D25A91AEF" ++
        "0B0117E2AF9A291AA32E14AB834DC56ED2A223444547E01F11D3B0916E5A4C345CACB36";
    pub const tag_number: u64 = 998;
};
