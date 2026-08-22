// SPDX-License-Identifier: MIT
//! EXTERNAL interop vectors for the Double Ratchet's KDFs, captured from
//! **libsignal** (signalapp/libsignal, Rust) -- the Signal Foundation's own
//! deployed implementation, and the C-reference competitor named in this
//! module's audit.
//!
//! **Why this file exists.** `ratchet.zig`'s correctness rested on
//! self-consistency + spec-adherence only: Alice and Bob agreeing with each
//! other proves they share a convention, not that the convention is the
//! Double Ratchet's (audit finding `signal` F1 -- "a subtle KDF-chaining ...
//! divergence would round-trip cleanly yet not interop"). The bytes below come
//! from an implementation that shares no code, author or derivation with this
//! module.
//!
//! **Scope -- read this before adding to the file.** Byte-exact interop on a
//! whole MESSAGE is impossible here, and deliberately so: this module
//! instantiates the spec's AEAD as ChaCha20-Poly1305 over a fixed 40-byte
//! header, where libsignal uses AES-256-CBC + truncated HMAC-SHA256 over a
//! protobuf `SignalMessage`. The spec explicitly leaves that choice to the
//! application. What the two DO share -- and what these vectors pin -- is the
//! ratchet's KDF core:
//!
//!   * `KDF_CK` is spec-fixed, not application-defined: `HMAC-SHA256(CK, 0x01)`
//!     -> MK and `HMAC-SHA256(CK, 0x02)` -> CK'. libsignal computes exactly
//!     this (`ChainKey::message_keys` / `ChainKey::next_chain_key`), so the
//!     ladders below are a TRUE byte-exact anchor for `kdfCk` -- including the
//!     two things a self-consistent implementation can get wrong invisibly:
//!     which constant produces which output, and which side of the HMAC the
//!     chain key goes on.
//!   * `KDF_RK`'s `info` string IS application-defined (libsignal uses
//!     `WhisperRatchet`; this module uses `kdf_rk_info`), so its bytes cannot
//!     match. Everything else about it can and must: HKDF-Extract with the ROOT
//!     KEY as salt and the DH output as IKM (not the reverse -- the classic
//!     inversion), a 64-byte Expand, and the split `RK' || CK` in that order.
//!     The tests therefore drive `rootRatchetWithInfo` with libsignal's own
//!     info and assert byte-exact equality, which pins the mechanism while
//!     leaving this module's constant free. The constant itself is pinned
//!     separately, by literal, in `interop_test.zig`.
//!
//! **Provenance / how to regenerate** (offline once frozen -- no Rust
//! toolchain, no network and no libsignal checkout are needed to RUN these
//! tests, and none of them skip):
//!
//!   repo:     https://github.com/signalapp/libsignal
//!   commit:   857c4dc ("Remove require_pq_ratio from protocol and bridge.")
//!   crate:    libsignal-protocol 0.1.0 (workspace member `rust/protocol`)
//!   captured: 2026-08-09, rustc 1.93.1
//!   method:   a local-only `#[cfg(test)] mod zig_libs_dump` appended to
//!             `rust/protocol/src/ratchet/keys.rs` in a throwaway checkout
//!             under `~/.cache/zig-libs-signal/`, driving libsignal's OWN
//!             `ChainKey`/`RootKey` (both `pub(crate)`, hence the in-crate
//!             driver) over fixed inputs and printing the results:
//!   command:  PROTOC=<cargo-vendored protoc> \
//!               cargo test -p libsignal-protocol --lib zig_libs_dump -- --nocapture
//!
//! **Licence.** libsignal is AGPL-3.0. NO libsignal source is copied,
//! translated or vendored into this repository, and `build.zig.zon` gains no
//! dependency. What is recorded below are numeric outputs -- HMAC and HKDF
//! values of a PUBLIC specification for fixed inputs, each of them equally
//! derivable from the Double Ratchet spec text plus any HMAC/HKDF
//! implementation. That is the identical posture (and identical reasoning)
//! under which this module already carries libsignal's XEdDSA known-answer
//! vector; see `../NOTICE`, "Test vectors". A program's numeric output is not
//! a derivative work of the program, and the AGPL's network clause is not
//! engaged: libsignal is neither conveyed nor served here. The modified
//! checkout stays outside the repository and is never redistributed.
//!
//! GENERATED FILE -- do not hand-edit; regenerate with the command above.

/// One step of libsignal's symmetric-key (chain) ratchet.
pub const ChainStep = struct {
    /// Chain key entering the step (32 bytes, hex).
    ck: []const u8,
    /// `HMAC-SHA256(ck, 0x01)` -- libsignal's message-key seed, our `MK`.
    mk: []const u8,
    /// `HMAC-SHA256(ck, 0x02)` -- the next chain key.
    next_ck: []const u8,
};

/// A run of consecutive chain-ratchet steps from one starting chain key.
pub const ChainLadder = struct {
    label: []const u8,
    start_ck: []const u8,
    steps: []const ChainStep,
};

const ladder_0_steps = [_]ChainStep{
    .{ .ck = "030E19242F3A45505B66717C87929DA8B3BEC9D4DFEAF5000B16212C37424D58", .mk = "980CCBC80BE72AF7DEFDF2EA454841360D20D28B3BFDCDE29369AE27329ADFAF", .next_ck = "F1A420A7550220B8CEC717694B62B2CFDC64B37971361EB698CDBC6D4091C1C5" },
    .{ .ck = "F1A420A7550220B8CEC717694B62B2CFDC64B37971361EB698CDBC6D4091C1C5", .mk = "407B45EC3C7F0C5855AD74E99B6FA68866F50E009D8EDCDFD8A30C681762BC3A", .next_ck = "212DCEFBD291518DC09A2EE910E904CBC60E67062383C947C828E93D9EC4E3ED" },
    .{ .ck = "212DCEFBD291518DC09A2EE910E904CBC60E67062383C947C828E93D9EC4E3ED", .mk = "5D5BDE36BD9B987EC52232ECEA23B00EBB4EE58DC931E5719BE58DE3B43CCEF1", .next_ck = "7D4DE8FEC344A91867A1E4FFF3005234FB6468DEFA7B1458788A218BB5C5A37E" },
    .{ .ck = "7D4DE8FEC344A91867A1E4FFF3005234FB6468DEFA7B1458788A218BB5C5A37E", .mk = "B71A7D783CFD2759F015EE37EB215B6D0F0EAE897DC9B9E0656C3D955467C883", .next_ck = "BF4DF7D6ADFA196737DA62F0F4AF347574F325009D9C309D8DCC719BA431BBF8" },
    .{ .ck = "BF4DF7D6ADFA196737DA62F0F4AF347574F325009D9C309D8DCC719BA431BBF8", .mk = "8041D2CA6DD68010C332CE07C52AAF0061975E5786E011DB79B7709D2F1AFF9A", .next_ck = "ED74E24258BB7ABE383FC13B9A0A1373B9D1390EBBBFC34702A6FCB43F5A00DF" },
};

const ladder_1_steps = [_]ChainStep{
    .{ .ck = "28333E49545F6A75808B96A1ACB7C2CDD8E3EEF9040F1A25303B46515C67727D", .mk = "7F2D6FC42FB1CE0DE6CD39F57DF789EEE0BC5A38E47C07FD6454AACFACC0A174", .next_ck = "97F73D44A7E4C01EF755260D6013AFD01D30DAAEF112D11EA5DAC85496CC6498" },
    .{ .ck = "97F73D44A7E4C01EF755260D6013AFD01D30DAAEF112D11EA5DAC85496CC6498", .mk = "1D144294F4688CCAA1558EAA95BCA1EEBEA84C002048F1954E6342CD6C4E490F", .next_ck = "4B5ECD4313A4512760DE107B177D5DBE5BDC9D74230AF904DBD3BC993501A142" },
    .{ .ck = "4B5ECD4313A4512760DE107B177D5DBE5BDC9D74230AF904DBD3BC993501A142", .mk = "9A7AC5BEB32CB935813A1F58B02ED97658157C2CE38A7331FD353EC8995BAB22", .next_ck = "736678D8C680C3871E6A94BA39A6BBB2C5ED673220BADAFD57E74B00EAFCCABC" },
    .{ .ck = "736678D8C680C3871E6A94BA39A6BBB2C5ED673220BADAFD57E74B00EAFCCABC", .mk = "C8D9E6604EB59897086A452F8A8256E8DBA2349078EB44DACC73141498C2F6AD", .next_ck = "A714144814E4CD199F20DA893CC727A5FC31BDB0A21959DC19106913660A2E0A" },
    .{ .ck = "A714144814E4CD199F20DA893CC727A5FC31BDB0A21959DC19106913660A2E0A", .mk = "D7FC575602C8F79B5077602FBDFC7F24A75E8DD2830A95DB96EAD0B87EC32B28", .next_ck = "78175A8F41845D9F684F3265254B95065F697DF5392A77DF3447FDBE803BAFCA" },
};

const ladder_2_steps = [_]ChainStep{
    .{ .ck = "4D58636E79848F9AA5B0BBC6D1DCE7F2FD08131E29343F4A55606B76818C97A2", .mk = "3E2744294649F1C5576793A697198403D35885FE1F88A8CF24453955DC4F8961", .next_ck = "443675DF0AB268C3AF38D00BD48683F3AC93DE5B2C254D1301B5C85D052B01F2" },
    .{ .ck = "443675DF0AB268C3AF38D00BD48683F3AC93DE5B2C254D1301B5C85D052B01F2", .mk = "C155E4BA234AB93585017B26EDD07CEAAFB2028329F6E6C72BB437BF260F6B22", .next_ck = "CBFA39688E6DE84563C9E48D39963E174C167874D3BF82465560B31F074D0E30" },
    .{ .ck = "CBFA39688E6DE84563C9E48D39963E174C167874D3BF82465560B31F074D0E30", .mk = "4D04CD303F80A4547C770144DABD4FB3B0E5F3E5F443A3ADB2D99CF8F7B3FFB4", .next_ck = "8586F2886B9B937786845A6DA6B71A2B3AAB84781B15F82E474C5C3985A598AF" },
    .{ .ck = "8586F2886B9B937786845A6DA6B71A2B3AAB84781B15F82E474C5C3985A598AF", .mk = "865FC69EB7FA73A62B3A14564E61A6DCBBFF1BF8A2A49AF0FD3F812412B31E63", .next_ck = "4C55119322532A59F131181501D98ECE6FF0C55993E4B5422B7108A47E9E4590" },
    .{ .ck = "4C55119322532A59F131181501D98ECE6FF0C55993E4B5422B7108A47E9E4590", .mk = "86F234E36FE41A9391D4824CA4E13C1C5F739B52B906C9F961EB19E79666A728", .next_ck = "2F420B3A05B2357418492BE392D901BF7E603EE91E38C8CE64B379E44875DD72" },
};

pub const chain_ladders = [_]ChainLadder{
    .{ .label = "libsignal ChainKey ladder 0", .start_ck = "030E19242F3A45505B66717C87929DA8B3BEC9D4DFEAF5000B16212C37424D58", .steps = &ladder_0_steps },
    .{ .label = "libsignal ChainKey ladder 1", .start_ck = "28333E49545F6A75808B96A1ACB7C2CDD8E3EEF9040F1A25303B46515C67727D", .steps = &ladder_1_steps },
    .{ .label = "libsignal ChainKey ladder 2", .start_ck = "4D58636E79848F9AA5B0BBC6D1DCE7F2FD08131E29343F4A55606B76818C97A2", .steps = &ladder_2_steps },
};

/// One DH-ratchet root step as libsignal performs it: the receiving chain is
/// derived from a DH with our CURRENT ratchet key, then a fresh keypair is
/// generated and the sending chain is derived from a second DH -- with the
/// root key threaded through both. `dh_recv`/`dh_send` are the raw X25519
/// shared secrets, recorded so these vectors pin the KDF composition without
/// depending on either side's private-key encoding or clamping.
pub const RootRatchet = struct {
    label: []const u8,
    /// Root key entering the step (32 bytes, hex).
    rk: []const u8,
    dh_recv: []const u8,
    dh_send: []const u8,
    /// Root key after the RECEIVING chain derivation.
    rk1: []const u8,
    /// The new receiving chain key.
    ckr: []const u8,
    /// Root key after the SENDING chain derivation.
    rk2: []const u8,
    /// The new sending chain key.
    cks: []const u8,
};

/// libsignal's `info` for `KDF_RK`. This module deliberately uses its own
/// (`ratchet.kdf_rk_info`); the vectors below are driven with THIS string so
/// the KDF mechanism can be compared byte-exactly across the two.
pub const libsignal_kdf_rk_info = "WhisperRatchet";

pub const root_ratchets = [_]RootRatchet{
    .{
        .label = "libsignal RootKey::create_chain pair 0",
        .rk = "727D88939EA9B4BFCAD5E0EBF6010C17222D38434E59646F7A85909BA6B1BCC7",
        .dh_recv = "14F0FF39C7B3CF14EBF77BA3D35555F888367F9F023634B1C0B488F865DE0C1C",
        .dh_send = "4757023F906BCA1BC239BB69FE57B28CB9EC181B04DA73EF217225991FBF304B",
        .rk1 = "6C9FA694C29A0ABD6F99709150F3F573A338C702D1E65E838548E7D7D80557B1",
        .ckr = "CA58F1882432AF4473529732FF18B9AFD514E66E1253ED38E1B1A70FDD281017",
        .rk2 = "132C820DC0A05052027F95641D74EEB04C37534C9A7390463E4303F4ECA0C4BD",
        .cks = "4BEB3EC021DE8D20A1FDC29BDCEB097FA6F139D2D991FA5837BA946D93BC576E",
    },
    .{
        .label = "libsignal RootKey::create_chain pair 1",
        .rk = "97A2ADB8C3CED9E4EFFA05101B26313C47525D68737E89949FAAB5C0CBD6E1EC",
        .dh_recv = "9849161F2D042D3E5DD2F33AC29772A269280C54883EFC60AF08488744CFF16E",
        .dh_send = "0C9FA1DA29C3485F11EC28DD5B1804F2A041DC1A810E2E3F0C6F7DA2BBC6F829",
        .rk1 = "95D8266210BF5814AF96406B24752D0D260EA9337B61FF8A559422AD23677D17",
        .ckr = "A4AD227E85CFFF463772450CE69C059AFF88232BA731701332434E04B392B1B9",
        .rk2 = "2ADC49FB99623A066F61F5A7D60BA5CF0EC29B4F536B875EE48EDBADFA50023A",
        .cks = "5A0D0E78D7DC0B279724EC96044E42985EFC4153DD412D8C5F645A279FE8338C",
    },
    .{
        .label = "libsignal RootKey::create_chain pair 2",
        .rk = "BCC7D2DDE8F3FE09141F2A35404B56616C77828D98A3AEB9C4CFDAE5F0FB0611",
        .dh_recv = "60E5E7AE26A55F56B60C2268BA99A9BF1A035E183B7D623A898CB0FBB4571E57",
        .dh_send = "901C53F9E6111B0DA3301392BF8F8D35D1362006B90E2F5F27C29A5FDBA7B121",
        .rk1 = "DC88DC23395E13CCCA4B1BA32719148F81353F98D22A849320D4D4B14196CEEE",
        .ckr = "EE54BD0A3B591C2A3F69E1B8095A81074C63D699BAE0CE3839917AC0FB09F251",
        .rk2 = "EA7D527157B3645DDA9E19B8293C45945B3FF6AF54249C74D59996863FE88F12",
        .cks = "D7B68481554F80558E13F8D64932053E7940025DD5AB319D75A5613CD1014B86",
    },
};

// ── PQXDH key-derivation chain (Part 3) ────────────────────────────────────

/// PQXDH's `SK = KDF(F || DH1 || DH2 || DH3 [|| DH4] || SS)`, computed by an
/// INDEPENDENT implementation: `scripts/pqxdh-kdf-check.py`, written from
/// Python's `hmac`/`hashlib` alone, sharing no code with `pqxdh.zig`.
///
/// Unlike the Double Ratchet vectors above, these are NOT from libsignal, and
/// the difference matters enough to state plainly: **Signal publishes no
/// byte-exact PQXDH vectors** — checked 2026-08-22, neither the spec page nor
/// libsignal's source carries known-answer data for the composed agreement. So
/// this is a weaker class of anchor than the ratchet's: it is a second
/// implementation of the same arithmetic rather than the protocol's authors'
/// own output. It catches the mistake this composition is actually prone to —
/// a term in the wrong order, a missing `F` prefix, the wrong salt length,
/// `info` fed to extract instead of expand — and it does not catch a shared
/// misreading of the spec. `pqxdh.zig`'s module doc comment says the same
/// thing to anyone reading from that side.
///
/// The inputs are deliberately fake and each a distinct constant byte, so
/// swapping any two terms changes the answer. Regenerate with
/// `scripts/pqxdh-kdf-check.py`.
pub const pqxdh_kdf = struct {
    /// `SK` for DH1=0x01.., DH2=0x02.., DH3=0x03.., DH4=0x04.., SS=0x05..
    pub const with_one_time_prekey = "74683c230441224d300be36d3bf9c107172118d271470fd8d71732d1a53d9acd";
    /// The same without `DH4` — Bob published no one-time curve prekey.
    pub const without_one_time_prekey = "479da32b61e31b3fd5cee24c45aff7947f5e100668a8f470bdc876190b15aa0d";
    /// `SS` and `DH3` swapped. A value the implementation must NEVER produce:
    /// it is what putting the KEM secret in the wrong position looks like, and
    /// both sides of a round trip would agree on it just as happily.
    pub const ss_and_dh3_swapped = "a9207c8b993b7c020cd474825e77153c75537d8dd56abda18b1b6decda38325e";
};
