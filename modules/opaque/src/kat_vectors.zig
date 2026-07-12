// SPDX-License-Identifier: MIT
//! RFC 9807 Appendix C.1 official OPAQUE-3DH "Real" test vectors for
//! the **ristretto255-SHA-512** configuration (OPRF ristretto255-SHA512,
//! KDF HKDF-SHA-512, MAC HMAC-SHA-512, Hash SHA-512, KSF Identity,
//! Group ristretto255), extracted byte-exact from the RFC text (see
//! `NOTICE`):
//!   - C.1.1  Real Test Vector 1 — no application identities
//!     (client_identity/server_identity default to the public keys)
//!   - C.1.2  Real Test Vector 2 — client_identity = "alice",
//!     server_identity = "bob" (exercises the identity paths in the
//!     envelope auth_tag and the AKE preamble)
//! Both share every other input, including the shared `Context`
//! ("OPAQUE-POC", C.1.1.1). Per Appendix C, the KSF for these vectors
//! is the identity function: `Stretch(msg) = msg`.
//!
//! Every input, intermediate, and output the RFC publishes is carried
//! here, including intermediates this module never exposes publicly
//! (`auth_key`, `randomized_password`, `handshake_secret`,
//! `server_mac_key`, `client_mac_key`, `oprf_key`) — `kat_test.zig`
//! pins them transitively through the byte-exact message/record/key
//! comparisons (see its doc comment).

const std = @import("std");

fn h(comptime s: []const u8) [s.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(100_000);
        var out: [s.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, s) catch unreachable;
        return out;
    }
}

/// One RFC 9807 Appendix C.1 "Real" vector (ristretto255-SHA-512).
/// Fixed-size fields are typed to the exact RFC wire length, so any
/// extraction length error is a compile error.
pub const RealVector = struct {
    // ── configuration (C.1.x.1) ──────────────────────────────────────────
    context: []const u8,
    // ── inputs (C.1.x.2) ─────────────────────────────────────────────────
    client_identity: ?[]const u8 = null,
    server_identity: ?[]const u8 = null,
    oprf_seed: [64]u8,
    credential_identifier: []const u8,
    password: []const u8,
    envelope_nonce: [32]u8,
    masking_nonce: [32]u8,
    server_private_key: [32]u8,
    server_public_key: [32]u8,
    server_nonce: [32]u8,
    client_nonce: [32]u8,
    client_keyshare_seed: [32]u8,
    server_keyshare_seed: [32]u8,
    blind_registration: [32]u8,
    blind_login: [32]u8,
    // ── intermediates (C.1.x.3) ──────────────────────────────────────────
    client_public_key: [32]u8,
    auth_key: [64]u8,
    randomized_password: [64]u8,
    envelope: [96]u8,
    handshake_secret: [64]u8,
    server_mac_key: [64]u8,
    client_mac_key: [64]u8,
    oprf_key: [32]u8,
    // ── outputs (C.1.x.4) ────────────────────────────────────────────────
    registration_request: [32]u8,
    registration_response: [64]u8,
    registration_upload: [192]u8,
    ke1: [96]u8,
    ke2: [320]u8,
    ke3: [64]u8,
    export_key: [64]u8,
    session_key: [64]u8,
};

/// Appendix C.1.1 — Real Test Vector 1 (no application identities).
pub const real_1 = RealVector{
    .oprf_seed = h("f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fd") ++
        h("c65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef"),
    .credential_identifier = &h("31323334"),
    .password = &h("436f7272656374486f72736542617474657279537461706c65"),
    .envelope_nonce = h("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec"),
    .masking_nonce = h("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d"),
    .server_private_key = h("47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d"),
    .server_public_key = h("b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
    .server_nonce = h("71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1"),
    .client_nonce = h("da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc"),
    .client_keyshare_seed = h("82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b"),
    .server_keyshare_seed = h("05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f"),
    .blind_registration = h("76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01"),
    .blind_login = h("6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308"),
    .client_public_key = h("76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675"),
    .auth_key = h("6cd32316f18d72a9a927a83199fa030663a38ce0c11fbaef82aa90037730494f") ++
        h("c555c4d49506284516edd1628c27965b7555a4ebfed2223199f6c67966dde822"),
    .randomized_password = h("aac48c25ab036e30750839d31d6e73007344cb1155289fb7d329beb932e9adee") ++
        h("a73d5d5c22a0ce1952f8aba6d66007615cd1698d4ac85ef1fcf150031d1435d9"),
    .envelope = h("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec") ++
        h("634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b") ++
        h("8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5"),
    .handshake_secret = h("81263cb85a0cfa12450f0f388de4e92291ec4c7c7a0878b624550ff528726332") ++
        h("f1298fc6cc822a432c89504347c7a2ccd70316ae3da6a15e0399e6db3f7c1b12"),
    .server_mac_key = h("0d36b26cfe38f51f804f0a9361818f32ee1ce2a4e5578653b527184af058d3b2") ++
        h("d8075c296fd84d24677913d1baa109290cd81a13ed383f9091a3804e65298dfc"),
    .client_mac_key = h("91750adbac54a5e8e53b4c233cc8d369fe83b0de1b6a3cd85575eeb0bb01a6a9") ++
        h("0a086a2cf5fe75fff2a9379c30ba9049510a33b5b0b1444a88800fc3eee2260d"),
    .oprf_key = h("5d4c6a8b7c7138182afb4345d1fae6a9f18a1744afbcc3854f8f5a2b4b4c6d05"),
    .registration_request = h("5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71"),
    .registration_response = h("7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019") ++
        h("b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
    .registration_upload = h("76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675") ++
        h("1ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb958") ++
        h("64eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5") ++
        h("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec") ++
        h("634b0f5b96109c198a8027da51854c35bee90d1e1c781806d07d49b76de6a28b") ++
        h("8d9e9b6c93b9f8b64d16dddd9c5bfb5fea48ee8fd2f75012a8b308605cdd8ba5"),
    .ke1 = h("c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44d") ++
        h("da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc") ++
        h("6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326"),
    .ke2 = h("7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb471") ++
        h("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d") ++
        h("d6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146") ++
        h("a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fe") ++
        h("dc80188ca46743c52786e0382f95ad85c08f6afcd1ccfbff95e2bdeb015b166c") ++
        h("6b20b92f832cc6df01e0b86a7efd92c1c804ff865781fa93f2f20b446c8371b6") ++
        h("71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1") ++
        h("c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a") ++
        h("660c48dae03e57aaa38f3d0cffcfc21852ebc8b405d15bd6744945ba1a93438a") ++
        h("162b6111699d98a16bb55b7bdddfe0fc5608b23da246e7bd73b47369169c5c90"),
    .ke3 = h("4455df4f810ac31a6748835888564b536e6da5d9944dfea9e34defb9575fe5e2") ++
        h("661ef61d2ae3929bcf57e53d464113d364365eb7d1a57b629707ca48da18e442"),
    .export_key = h("1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62") ++
        h("950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16"),
    .session_key = h("42afde6f5aca0cfa5c163763fbad55e73a41db6b41bc87b8e7b62214a8eedc67") ++
        h("31fa3cb857d657ab9b3764b89a84e91ebcb4785166fbb02cedfcbdfda215b96f"),
    .context = &h("4f50415155452d504f43"),
};

/// Appendix C.1.2 — Real Test Vector 2 (client_identity = "alice", server_identity = "bob").
pub const real_2 = RealVector{
    .client_identity = &h("616c696365"),
    .server_identity = &h("626f62"),
    .oprf_seed = h("f433d0227b0b9dd54f7c4422b600e764e47fb503f1f9a0f0a47c6606b054a7fd") ++
        h("c65347f1a08f277e22358bbabe26f823fca82c7848e9a75661f4ec5d5c1989ef"),
    .credential_identifier = &h("31323334"),
    .password = &h("436f7272656374486f72736542617474657279537461706c65"),
    .envelope_nonce = h("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec"),
    .masking_nonce = h("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d"),
    .server_private_key = h("47451a85372f8b3537e249d7b54188091fb18edde78094b43e2ba42b5eb89f0d"),
    .server_public_key = h("b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
    .server_nonce = h("71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1"),
    .client_nonce = h("da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc"),
    .client_keyshare_seed = h("82850a697b42a505f5b68fcdafce8c31f0af2b581f063cf1091933541936304b"),
    .server_keyshare_seed = h("05a4f54206eef1ba2f615bc0aa285cb22f26d1153b5b40a1e85ff80da12f982f"),
    .blind_registration = h("76cfbfe758db884bebb33582331ba9f159720ca8784a2a070a265d9c2d6abe01"),
    .blind_login = h("6ecc102d2e7a7cf49617aad7bbe188556792d4acd60a1a8a8d2b65d4b0790308"),
    .client_public_key = h("76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675"),
    .auth_key = h("6cd32316f18d72a9a927a83199fa030663a38ce0c11fbaef82aa90037730494f") ++
        h("c555c4d49506284516edd1628c27965b7555a4ebfed2223199f6c67966dde822"),
    .randomized_password = h("aac48c25ab036e30750839d31d6e73007344cb1155289fb7d329beb932e9adee") ++
        h("a73d5d5c22a0ce1952f8aba6d66007615cd1698d4ac85ef1fcf150031d1435d9"),
    .envelope = h("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec") ++
        h("1ac902dc5589e9a5f0de56ad685ea8486210ef41449cd4d8712828913c5d2b68") ++
        h("0b2b3af4a26c765cff329bfb66d38ecf1d6cfa9e7a73c222c6efe0d9520f7d7c"),
    .handshake_secret = h("5e723bed1e5276de2503419eba9da61ead573109c401226832398c7e08155b88") ++
        h("5bfe7bc93451f9d887a0c1d0c19233e40a8e47b347a9ac3907f94032a4cff64f"),
    .server_mac_key = h("dad66bb9251073d17a13f8e5500f36e5998e3cde520ca0738e7085af62fd9781") ++
        h("2eb79a745c94d0bf8a6ac17f980cf435504cf64041eeb6bb237796d2c7f81e9a"),
    .client_mac_key = h("f816fe2914f7c5b29852385615d7c7f31ac122adf202d7ccd497606d7aabd489") ++
        h("30323d1d02b1cc9ecd456c4de6f46c7950becb18bffd921dd5876381b5486ffe"),
    .oprf_key = h("5d4c6a8b7c7138182afb4345d1fae6a9f18a1744afbcc3854f8f5a2b4b4c6d05"),
    .registration_request = h("5059ff249eb1551b7ce4991f3336205bde44a105a032e747d21bf382e75f7a71"),
    .registration_response = h("7408a268083e03abc7097fc05b587834539065e86fb0c7b6342fcf5e01e5b019") ++
        h("b2fe7af9f48cc502d016729d2fe25cdd433f2c4bc904660b2a382c9b79df1a78"),
    .registration_upload = h("76a845464c68a5d2f7e442436bb1424953b17d3e2e289ccbaccafb57ac5c3675") ++
        h("1ac5844383c7708077dea41cbefe2fa15724f449e535dd7dd562e66f5ecfb958") ++
        h("64eadddec9db5874959905117dad40a4524111849799281fefe3c51fa82785c5") ++
        h("ac13171b2f17bc2c74997f0fce1e1f35bec6b91fe2e12dbd323d23ba7a38dfec") ++
        h("1ac902dc5589e9a5f0de56ad685ea8486210ef41449cd4d8712828913c5d2b68") ++
        h("0b2b3af4a26c765cff329bfb66d38ecf1d6cfa9e7a73c222c6efe0d9520f7d7c"),
    .ke1 = h("c4dedb0ba6ed5d965d6f250fbe554cd45cba5dfcce3ce836e4aee778aa3cd44d") ++
        h("da7e07376d6d6f034cfa9bb537d11b8c6b4238c334333d1f0aebb380cae6a6cc") ++
        h("6e29bee50701498605b2c085d7b241ca15ba5c32027dd21ba420b94ce60da326"),
    .ke2 = h("7e308140890bcde30cbcea28b01ea1ecfbd077cff62c4def8efa075aabcbb471") ++
        h("38fe59af0df2c79f57b8780278f5ae47355fe1f817119041951c80f612fdfc6d") ++
        h("d6ec60bcdb26dc455ddf3e718f1020490c192d70dfc7e403981179d8073d1146") ++
        h("a4f9aa1ced4e4cd984c657eb3b54ced3848326f70331953d91b02535af44d9fe") ++
        h("a502150b67fe36795dd8914f164e49f81c7688a38928372134b7dccd50e09f8f") ++
        h("ed9518b7b2f94835b3c4fe4c8475e7513f20eb97ff0568a39caee3fd6251876f") ++
        h("71cd9960ecef2fe0d0f7494986fa3d8b2bb01963537e60efb13981e138e3d4a1") ++
        h("c4f62198a9d6fa9170c42c3c71f1971b29eb1d5d0bd733e40816c91f7912cc4a") ++
        h("292371e7809a9031743e943fb3b56f51de903552fc91fba4e7419029951c3970") ++
        h("b2e2f0a9dea218d22e9e4e0000855bb6421aa3610d6fc0f4033a6517030d4341"),
    .ke3 = h("7a026de1d6126905736c3f6d92463a08d209833eb793e46d0f7f15b3e0f62c76") ++
        h("43763c02bbc6b8d3d15b63250cae98171e9260f1ffa789750f534ac11a0176d5"),
    .export_key = h("1ef15b4fa99e8a852412450ab78713aad30d21fa6966c9b8c9fb3262a970dc62") ++
        h("950d4dd4ed62598229b1b72794fc0335199d9f7fcc6eaedde92cc04870e63f16"),
    .session_key = h("ae7951123ab5befc27e62e63f52cf472d6236cb386c968cc47b7e34f866aa4bc") ++
        h("7638356a73cfce92becf39d6a7d32a1861f12130e824241fe6cab34fbd471a57"),
    .context = &h("4f50415155452d504f43"),
};
