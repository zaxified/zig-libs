// SPDX-License-Identifier: MIT
//! RFC 9180 Appendix A known-answer test vectors, fetched directly from
//! <https://www.rfc-editor.org/rfc/rfc9180> for this module (not copied
//! from any other implementation's test suite).
//!
//! - **A.1** (`DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM`,
//!   base mode, §A.1.1): embedded IN FULL — every field the RFC
//!   publishes (`ikmE`/`pkEm`/`skEm`/`ikmR`/`pkRm`/`skRm`/`enc`/
//!   `shared_secret`/`key_schedule_context`/`secret`/`key`/`base_nonce`/
//!   `exporter_secret`, all 6 published `(seq, pt, aad, nonce, ct)`
//!   encryption tuples, and all 3 exported-value tuples).
//! - **A.2** (`DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305`)
//!   and **A.3** (`DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM`):
//!   header fields only (mode/kem_id/kdf_id/aead_id/info/keys/enc/
//!   shared_secret/key_schedule_context/secret/key/base_nonce/
//!   exporter_secret + one encryption tuple each) — enough to KAT the
//!   DHKEM/key-schedule crypto core for these two suites too, without
//!   this module owning the full encryption-tuple table for every suite
//!   (A.1's is the canonical, fully-worked example).
//! - **A.1.2/A.1.3/A.1.4** (`mode_psk`/`mode_auth`/`mode_auth_psk` over the
//!   A.1 suite) and **A.3.2/A.3.3/A.3.4** (the same three modes over the
//!   P-256 suite): the three NON-base modes, each driven through the whole
//!   chain by `driveVector` below. These are what anchor the mode byte, the
//!   psk/psk_id plumbing and the `AuthEncap`/`AuthDecap` fold to something
//!   OUTSIDE this module — a round-trip test cannot, because a sender and a
//!   recipient built from the same misreading of §5.1 round-trip perfectly.
//!
//! Not embedded: A.4/A.6 (HKDF-SHA512, P-521 — KDF/KEM this module does not
//! instantiate), A.7+ (export-only AEAD), and the mode vectors of A.2/A.5
//! (`ChaCha20Poly1305`), whose only difference from the embedded A.1/A.3
//! mode vectors is the `aead_id` byte inside `suite_id`, already covered by
//! the A.2 base header.
//!
//! The crypto cores (`dhkem.X25519Kem`/`P256Kem` Encap/Decap/AuthEncap/
//! AuthDecap/DeriveKeyPair, `schedule.keySchedule`/`Context.seal`/`.open`/
//! `.exportSecret`, and every §6.1 single-shot `seal*`/`open*` pair) are
//! implemented — every test below drives them for real against these
//! vectors, byte-exact, no skip guards left.

const std = @import("std");
const suite = @import("suite.zig");
const dhkem = @import("dhkem.zig");
const schedule = @import("schedule.zig");

const testing = std.testing;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

fn hexTo(comptime n: usize, s: *const [n * 2]u8) [n]u8 {
    @setEvalBranchQuota(10_000);
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

/// One published `(sequence number, pt, aad, nonce, ct)` tuple from an
/// `A.x.y.1 Encryptions` subsection. File-scope (rather than nested in one
/// vector's namespace) because every vector below shares the shape — the
/// `driveVector` harness is generic over the vector namespace and reads
/// these fields by name.
pub const Encryption = struct { seq: u64, pt: []const u8, aad: []const u8, nonce: [12]u8, ct: []const u8 };

/// One published `(exporter_context, L, exported_value)` tuple from an
/// `A.x.y.2 Exported Values` subsection. Every Appendix A export tuple this
/// module embeds has `L = 32`; `l` is carried anyway so a future vector
/// with a different length can't be silently mis-driven (the harness
/// asserts it).
pub const Export = struct { exporter_context: []const u8, l: usize, exported_value: [32]u8 };

// ── A.1: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM (base) ────

pub const a1 = struct {
    pub const kem_id: u16 = 0x0020;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0001;
    pub const mode: u8 = 0x00; // base

    pub const info = hexTo(20, "4f6465206f6e2061204772656369616e2055726e");

    pub const ikmE = hexTo(32, "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234");
    pub const pkEm = hexTo(32, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    pub const skEm = hexTo(32, "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
    pub const ikmR = hexTo(32, "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037");
    pub const pkRm = hexTo(32, "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
    pub const skRm = hexTo(32, "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");

    pub const enc = hexTo(32, "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431");
    pub const shared_secret = hexTo(32, "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc");
    pub const key_schedule_context = hexTo(65, "00725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449");
    pub const secret = hexTo(32, "12fff91991e93b48de37e7daddb52981084bd8aa64289c3788471d9a9712f397");
    pub const key = hexTo(16, "4531685d41d65f03dc48f6b8302c05b0");
    pub const base_nonce = hexTo(12, "56d890e5accaaf011cff4b7d");
    pub const exporter_secret = hexTo(32, "45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8");

    /// §A.1.1.1 — all 6 published `(sequence number, pt, aad, nonce, ct)`
    /// tuples, INCLUDING the two that skip ahead (seq 4 after 0/1/2, and
    /// seq 256 after 255) — proof a correct `Context` must derive the
    /// nonce from `seq` directly (`base_nonce XOR I2OSP(seq, Nn)`), not
    /// from a running XOR/increment of the previous nonce.
    pub const encryptions = [_]Encryption{
        .{
            .seq = 0,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d30"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4b7d"),
            .ct = &hexTo(45, "f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
        },
        .{
            .seq = 1,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d31"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4b7c"),
            .ct = &hexTo(45, "af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"),
        },
        .{
            .seq = 2,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d32"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4b7f"),
            .ct = &hexTo(45, "498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180"),
        },
        .{
            .seq = 4,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d34"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4b79"),
            .ct = &hexTo(45, "583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d"),
        },
        .{
            .seq = 255,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323535"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4b82"),
            .ct = &hexTo(45, "7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a"),
        },
        .{
            .seq = 256,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323536"),
            .nonce = hexTo(12, "56d890e5accaaf011cff4a7d"),
            .ct = &hexTo(45, "957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2"),
        },
    };

    /// §A.1.1.2 — the 3 published `(exporter_context, L, exported_value)`
    /// tuples.
    pub const exports = [_]Export{
        .{ .exporter_context = "", .l = 32, .exported_value = hexTo(32, "3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee") },
        .{ .exporter_context = &hexTo(1, "00"), .l = 32, .exported_value = hexTo(32, "2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5") },
        .{ .exporter_context = "TestContext", .l = 32, .exported_value = hexTo(32, "e9e43065102c3836401bed8c3c3c75ae46be1639869391d62c61f1ec7af54931") },
    };
};

// ── A.2 header: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 ──

pub const a2 = struct {
    pub const kem_id: u16 = 0x0020;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0003;
    pub const mode: u8 = 0x00;

    pub const skEm = hexTo(32, "f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600");
    pub const pkEm = hexTo(32, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    pub const pkRm = hexTo(32, "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a");
    pub const skRm = hexTo(32, "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb");
    pub const enc = hexTo(32, "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a");
    pub const shared_secret = hexTo(32, "0bbe78490412b4bbea4812666f7916932b828bba79942424abb65244930d69a7");
    pub const secret = hexTo(32, "5b9cd775e64b437a2335cf499361b2e0d5e444d5cb41a8a53336d8fe402282c6");
    pub const key = hexTo(32, "ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91"); // ChaCha20Poly1305: Nk=32
    pub const base_nonce = hexTo(12, "5c4d98150661b848853b547f");
    pub const exporter_secret = hexTo(32, "a3b010d4994890e2c6968a36f64470d3c824c8f5029942feb11e7a74b2921922");

    // §A.2.1.1, sequence number 0.
    pub const seq0_ct = hexTo(45, "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28");
};

// ── A.3 header: DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-128-GCM ─────

pub const a3 = struct {
    pub const kem_id: u16 = 0x0010;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0001;
    pub const mode: u8 = 0x00;

    // SEC1 uncompressed points: 0x04 || X(32) || Y(32) = 65 bytes.
    pub const pkEm = hexTo(65, "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
    pub const skEm = hexTo(32, "4995788ef4b9d6132b249ce59a77281493eb39af373d236a1fe415cb0c2d7beb");
    pub const pkRm = hexTo(65, "04fe8c19ce0905191ebc298a9245792531f26f0cece2460639e8bc39cb7f706a826a779b4cf969b8a0e539c7f62fb3d30ad6aa8f80e30f1d128aafd68a2ce72ea0");
    pub const skRm = hexTo(32, "f3ce7fdae57e1a310d87f1ebbde6f328be0a99cdbcadf4d6589cf29de4b8ffd2");
    pub const enc = hexTo(65, "04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4");
    pub const shared_secret = hexTo(32, "c0d26aeab536609a572b07695d933b589dcf363ff9d93c93adea537aeabb8cb8");
    pub const secret = hexTo(32, "2eb7b6bf138f6b5aff857414a058a3f1750054a9ba1f72c2cf0684a6f20b10e1");
    pub const key = hexTo(16, "868c066ef58aae6dc589b6cfdd18f97e");
    pub const base_nonce = hexTo(12, "4e0bc5018beba4bf004cca59");
    pub const exporter_secret = hexTo(32, "14ad94af484a7ad3ef40e9f3be99ecc6fa9036df9d4920548424df127ee0d99f");

    // §A.3.1.1, sequence number 0.
    pub const seq0_ct = hexTo(45, "5ad590bb8baa577f8619db35a36311226a896e7342a6d836d8b7bcd2f20b6c7f9076ac232e3ab2523f39513434");
};

// ── A.4: DHKEM(P-256, HKDF-SHA256), HKDF-SHA512, AES-128-GCM (base) ─────
//
// The FIRST vector this module drives with an outer key-schedule KDF other
// than HKDF-SHA256 — HKDF-SHA512 (kdf_id 0x0003), Nh=64, paired with the
// SAME DHKEM(P-256, HKDF-SHA256) already anchored by A.3 (whose internal
// KDF stays HKDF-SHA256 regardless — RFC 9180 §7.1 Table 2 fixes a DHKEM's
// own KDF per kem_id, independent of the outer ciphersuite's kdf_id; see
// schedule.zig's module doc comment). `shared_secret` below is still 32
// bytes (the KEM's Nsecret) while `key_schedule_context`/`secret`/
// `exporter_secret` are 64 (Nh) — the clearest possible proof the two KDFs
// are genuinely independent choices, not one hash reused at two widths.
//
// Extracted from RFC 9180 Appendix A.4, cross-checked against a LOCAL
// (offline, no network fetch) copy of the same RFC's own published
// test-vectors.json bundled as Go's standard-library HPKE test fixture —
// `crypto/internal/hpke/testdata/rfc9180-vectors.json` in the Go
// toolchain's module cache on this machine (entry 3 of 6, "DHKEM(P-256,
// HKDF-SHA256), HKDF-SHA512, AES-128-GCM") — not authored by this repo,
// not derived from this module's own output.
pub const a4 = struct {
    pub const kem_id: u16 = 0x0010;
    pub const kdf_id: u16 = 0x0003;
    pub const aead_id: u16 = 0x0001;
    pub const mode: u8 = 0x00;

    pub const info = hexTo(20, "4f6465206f6e2061204772656369616e2055726e");
    pub const ikmE = hexTo(32, "4ab11a9dd78c39668f7038f921ffc0993b368171d3ddde8031501ee1e08c4c9a");
    pub const pkEm = hexTo(65, "0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a15565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580");
    pub const skEm = hexTo(32, "2292bf14bb6e15b8c81a0f45b7a6e93e32d830e48cca702e0affcfb4d07e1b5c");
    pub const ikmR = hexTo(32, "ea9ff7cc5b2705b188841c7ace169290ff312a9cb31467784ca92d7a2e6e1be8");
    pub const pkRm = hexTo(65, "04085aa5b665dc3826f9650ccbcc471be268c8ada866422f739e2d531d4a8818a9466bc6b449357096232919ec4fe9070ccbac4aac30f4a1a53efcf7af90610edd");
    pub const skRm = hexTo(32, "3ac8530ad1b01885960fab38cf3cdc4f7aef121eaa239f222623614b4079fb38");

    pub const enc = hexTo(65, "0493ed86735bdfb978cc055c98b45695ad7ce61ce748f4dd63c525a3b8d53a15565c6897888070070c1579db1f86aaa56deb8297e64db7e8924e72866f9a472580");
    // KEM's OWN Nsecret (32 bytes, HKDF-SHA256) — NOT Nh (64, the outer
    // HKDF-SHA512). See this section's header comment.
    pub const shared_secret = hexTo(32, "02f584736390fc93f5b4ad039826a3fa08e9911bd1215a3db8e8791ba533cafd");
    // key_schedule_context = mode(1) || psk_id_hash(Nh=64) || info_hash(Nh=64) = 129 bytes.
    pub const key_schedule_context = hexTo(129, "005b8a3617af7789ee716e7911c7e77f84cdc4cc46e60fb7e19e4059f9aeadc00585e26874d1ddde76e551a7679cd47168c466f6e1f705cc9374c192778a34fcd5ca221d77e229a9d11b654de7942d685069c633b2362ce3b3d8ea4891c9a2a87a4eb7cdb289ba5e2ecbf8cd2c8498bb4a383dc021454d70d46fcbbad1252ef4f9");
    pub const secret = hexTo(64, "0c7acdab61693f936c4c1256c78e7be30eebfe466812f9cc49f0b58dc970328dfc03ea359be0250a471b1635a193d2dfa8cb23c90aa2e25025b892a725353eeb");
    pub const key = hexTo(16, "090ca96e5f8aa02b69fac360da50ddf9");
    pub const base_nonce = hexTo(12, "9c995e621bf9a20c5ca45546");
    pub const exporter_secret = hexTo(64, "4a7abb2ac43e6553f129b2c5750a7e82d149a76ed56dc342d7bca61e26d494f4855dff0d0165f27ce57756f7f16baca006539bb8e4518987ba610480ac03efa8");

    /// All 6 published `(sequence number, pt, aad, nonce, ct)` tuples
    /// (including the seq 4/255/256 jumps, same convention as A.1.1.1).
    pub const encryptions = [_]Encryption{
        .{
            .seq = 0,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d30"),
            .nonce = hexTo(12, "9c995e621bf9a20c5ca45546"),
            .ct = &hexTo(45, "d3cf4984931484a080f74c1bb2a6782700dc1fef9abe8442e44a6f09044c88907200b332003543754eb51917ba"),
        },
        .{
            .seq = 1,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d31"),
            .nonce = hexTo(12, "9c995e621bf9a20c5ca45547"),
            .ct = &hexTo(45, "d14414555a47269dfead9fbf26abb303365e40709a4ed16eaefe1f2070f1ddeb1bdd94d9e41186f124e0acc62d"),
        },
        .{
            .seq = 2,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d32"),
            .nonce = hexTo(12, "9c995e621bf9a20c5ca45544"),
            .ct = &hexTo(45, "9bba136cade5c4069707ba91a61932e2cbedda2d9c7bdc33515aa01dd0e0f7e9d3579bf4016dec37da4aafa800"),
        },
        .{
            .seq = 4,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d34"),
            .nonce = hexTo(12, "9c995e621bf9a20c5ca45542"),
            .ct = &hexTo(45, "a531c0655342be013bf32112951f8df1da643602f1866749519f5dcb09cc68432579de305a77e6864e862a7600"),
        },
        .{
            .seq = 255,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323535"),
            .nonce = hexTo(12, "9c995e621bf9a20c5ca455b9"),
            .ct = &hexTo(45, "be5da649469efbad0fb950366a82a73fefeda5f652ec7d3731fac6c4ffa21a7004d2ab8a04e13621bd3629547d"),
        },
        .{
            .seq = 256,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323536"),
            .nonce = hexTo(12, "9c995e621bf9a20c5ca45446"),
            .ct = &hexTo(45, "62092672f5328a0dde095e57435edf7457ace60b26ee44c9291110ec135cb0e14b85594e4fea11247d937deb62"),
        },
    };

    // No "Exports" (exported-value) tuples: unlike a1/a1_psk/a1_auth/
    // a1_auth_psk/a3_psk/a3_auth/a3_auth_psk, the offline source this
    // section was extracted from (see header comment) does not carry
    // A.4's §A.4.1.2 exported-value tuples — Go's own HPKE test only
    // exercises Setup+Encryptions, not Export. Rather than fabricate
    // exported-value bytes (this repo's own convention: no self-generated
    // vector dressed up as an anchor), `Context.exportSecret`'s HKDF-SHA512
    // path is exercised only by round trip below, not a byte-exact RFC
    // anchor — an honest, narrower claim than the other vectors in this
    // file make.
};

// ── A.1.2/A.1.3/A.1.4 + A.3.2/A.3.3/A.3.4: the three NON-base modes ─────
//
// The base-mode sections above anchor mode_base (0x00) only. Everything a
// non-base mode adds — the `mode` byte in `key_schedule_context`, the
// `psk_id_hash` over a REAL psk_id (not the empty string), `secret =
// LabeledExtract(shared_secret, "secret", psk)` over a real psk, and the
// KEM's `AuthEncap`/`AuthDecap` `dh || dh2` fold with `pkSm` appended to
// `kem_context` — is exercised ONLY by these vectors. A round trip cannot
// substitute: sender and recipient sharing one wrong reading of §5.1
// round-trips perfectly.
//
// Both KEMs the module instantiates are covered, so the auth-mode KEM fold
// is externally anchored for X25519 (A.1.3/A.1.4) AND P-256 (A.3.3/A.3.4);
// the P-256 sections additionally publish `ikmE`/`ikmR`/`ikmS`, which anchor
// `P256Kem.deriveKeyPair`'s §7.1.3 rejection-sampling loop against the RFC
// for the first time (A.3.1's base header publishes no `ikm` fields, so
// that path had only a self-consistency test).
//
// Volume convention, matching the A.1-vs-A.2/A.3 split above: the X25519
// sections carry all 6 published encryption tuples (including the seq
// 4/255/256 jumps), the P-256 sections carry the first 2 (the nonce-from-seq
// derivation is suite-independent and already proven by A.1); all three
// exported values are carried everywhere.
//
// RFC 9180 fixes `info` ("Ode on a Grecian Urn"), `pt` ("Beauty is truth,
// truth beauty"), `aad` ("Count-<seq>"), `psk` and `psk_id` ("Ennyn Durin
// aran Moria") across every Appendix A section; they are repeated in full
// per vector anyway rather than shared, so each namespace is a standalone
// transcription of one RFC section and a future vector with different
// fixtures cannot silently inherit the wrong ones.

pub const a1_psk = struct {
    pub const kem_id: u16 = 0x0020;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0001;
    pub const mode: u8 = 0x01;

    pub const info = hexTo(20, "4f6465206f6e2061204772656369616e2055726e");
    pub const ikmE = hexTo(32, "78628c354e46f3e169bd231be7b2ff1c77aa302460a26dbfa15515684c00130b");
    pub const pkEm = hexTo(32, "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b");
    pub const skEm = hexTo(32, "463426a9ffb42bb17dbe6044b9abd1d4e4d95f9041cef0e99d7824eef2b6f588");
    pub const ikmR = hexTo(32, "d4a09d09f575fef425905d2ab396c1449141463f698f8efdb7accfaff8995098");
    pub const pkRm = hexTo(32, "9fed7e8c17387560e92cc6462a68049657246a09bfa8ade7aefe589672016366");
    pub const skRm = hexTo(32, "c5eb01eb457fe6c6f57577c5413b931550a162c71a03ac8d196babbd4e5ce0fd");
    pub const psk = hexTo(32, "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    pub const psk_id = hexTo(22, "456e6e796e20447572696e206172616e204d6f726961");

    pub const enc = hexTo(32, "0ad0950d9fb9588e59690b74f1237ecdf1d775cd60be2eca57af5a4b0471c91b");
    pub const shared_secret = hexTo(32, "727699f009ffe3c076315019c69648366b69171439bd7dd0807743bde76986cd");
    pub const key_schedule_context = hexTo(65, "01e78d5cf6190d275863411ff5edd0dece5d39fa48e04eec1ed9b71be34729d18ccb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449");
    pub const secret = hexTo(32, "3728ab0b024b383b0381e432b47cced1496d2516957a76e2a9f5c8cb947afca4");
    pub const key = hexTo(16, "15026dba546e3ae05836fc7de5a7bb26");
    pub const base_nonce = hexTo(12, "9518635eba129d5ce0914555");
    pub const exporter_secret = hexTo(32, "3d76025dbbedc49448ec3f9080a1abab6b06e91c0b11ad23c912f043a0ee7655");

    pub const encryptions = [_]Encryption{
        .{
            .seq = 0,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d30"),
            .nonce = hexTo(12, "9518635eba129d5ce0914555"),
            .ct = &hexTo(45, "e52c6fed7f758d0cf7145689f21bc1be6ec9ea097fef4e959440012f4feb73fb611b946199e681f4cfc34db8ea"),
        },
        .{
            .seq = 1,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d31"),
            .nonce = hexTo(12, "9518635eba129d5ce0914554"),
            .ct = &hexTo(45, "49f3b19b28a9ea9f43e8c71204c00d4a490ee7f61387b6719db765e948123b45b61633ef059ba22cd62437c8ba"),
        },
        .{
            .seq = 2,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d32"),
            .nonce = hexTo(12, "9518635eba129d5ce0914557"),
            .ct = &hexTo(45, "257ca6a08473dc851fde45afd598cc83e326ddd0abe1ef23baa3baa4dd8cde99fce2c1e8ce687b0b47ead1adc9"),
        },
        .{
            .seq = 4,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d34"),
            .nonce = hexTo(12, "9518635eba129d5ce0914551"),
            .ct = &hexTo(45, "a71d73a2cd8128fcccbd328b9684d70096e073b59b40b55e6419c9c68ae21069c847e2a70f5d8fb821ce3dfb1c"),
        },
        .{
            .seq = 255,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323535"),
            .nonce = hexTo(12, "9518635eba129d5ce09145aa"),
            .ct = &hexTo(45, "55f84b030b7f7197f7d7d552365b6b932df5ec1abacd30241cb4bc4ccea27bd2b518766adfa0fb1b71170e9392"),
        },
        .{
            .seq = 256,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323536"),
            .nonce = hexTo(12, "9518635eba129d5ce0914455"),
            .ct = &hexTo(45, "c5bf246d4a790a12dcc9eed5eae525081e6fb541d5849e9ce8abd92a3bc1551776bea16b4a518f23e237c14b59"),
        },
    };

    pub const exports = [_]Export{
        .{ .exporter_context = "", .l = 32, .exported_value = hexTo(32, "dff17af354c8b41673567db6259fd6029967b4e1aad13023c2ae5df8f4f43bf6") },
        .{ .exporter_context = &hexTo(1, "00"), .l = 32, .exported_value = hexTo(32, "6a847261d8207fe596befb52928463881ab493da345b10e1dcc645e3b94e2d95") },
        .{ .exporter_context = &hexTo(11, "54657374436f6e74657874"), .l = 32, .exported_value = hexTo(32, "8aff52b45a1be3a734bc7a41e20b4e055ad4c4d22104b0c20285a7c4302401cd") },
    };
};

pub const a1_auth = struct {
    pub const kem_id: u16 = 0x0020;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0001;
    pub const mode: u8 = 0x02;

    pub const info = hexTo(20, "4f6465206f6e2061204772656369616e2055726e");
    pub const ikmE = hexTo(32, "6e6d8f200ea2fb20c30b003a8b4f433d2f4ed4c2658d5bc8ce2fef718059c9f7");
    pub const pkEm = hexTo(32, "23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76");
    pub const skEm = hexTo(32, "ff4442ef24fbc3c1ff86375b0be1e77e88a0de1e79b30896d73411c5ff4c3518");
    pub const ikmR = hexTo(32, "f1d4a30a4cef8d6d4e3b016e6fd3799ea057db4f345472ed302a67ce1c20cdec");
    pub const pkRm = hexTo(32, "1632d5c2f71c2b38d0a8fcc359355200caa8b1ffdf28618080466c909cb69b2e");
    pub const skRm = hexTo(32, "fdea67cf831f1ca98d8e27b1f6abeb5b7745e9d35348b80fa407ff6958f9137e");
    pub const ikmS = hexTo(32, "94b020ce91d73fca4649006c7e7329a67b40c55e9e93cc907d282bbbff386f58");
    pub const pkSm = hexTo(32, "8b0c70873dc5aecb7f9ee4e62406a397b350e57012be45cf53b7105ae731790b");
    pub const skSm = hexTo(32, "dc4a146313cce60a278a5323d321f051c5707e9c45ba21a3479fecdf76fc69dd");

    pub const enc = hexTo(32, "23fb952571a14a25e3d678140cd0e5eb47a0961bb18afcf85896e5453c312e76");
    pub const shared_secret = hexTo(32, "2d6db4cf719dc7293fcbf3fa64690708e44e2bebc81f84608677958c0d4448a7");
    pub const key_schedule_context = hexTo(65, "02725611c9d98c07c03f60095cd32d400d8347d45ed67097bbad50fc56da742d07cb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449");
    pub const secret = hexTo(32, "56c62333d9d9f7767f5b083fdfce0aa7e57e301b74029bb0cffa7331385f1dda");
    pub const key = hexTo(16, "b062cb2c4dd4bca0ad7c7a12bbc341e6");
    pub const base_nonce = hexTo(12, "a1bc314c1942ade7051ffed0");
    pub const exporter_secret = hexTo(32, "ee1a093e6e1c393c162ea98fdf20560c75909653550540a2700511b65c88c6f1");

    pub const encryptions = [_]Encryption{
        .{
            .seq = 0,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d30"),
            .nonce = hexTo(12, "a1bc314c1942ade7051ffed0"),
            .ct = &hexTo(45, "5fd92cc9d46dbf8943e72a07e42f363ed5f721212cd90bcfd072bfd9f44e06b80fd17824947496e21b680c141b"),
        },
        .{
            .seq = 1,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d31"),
            .nonce = hexTo(12, "a1bc314c1942ade7051ffed1"),
            .ct = &hexTo(45, "d3736bb256c19bfa93d79e8f80b7971262cb7c887e35c26370cfed62254369a1b52e3d505b79dd699f002bc8ed"),
        },
        .{
            .seq = 2,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d32"),
            .nonce = hexTo(12, "a1bc314c1942ade7051ffed2"),
            .ct = &hexTo(45, "122175cfd5678e04894e4ff8789e85dd381df48dcaf970d52057df2c9acc3b121313a2bfeaa986050f82d93645"),
        },
        .{
            .seq = 4,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d34"),
            .nonce = hexTo(12, "a1bc314c1942ade7051ffed4"),
            .ct = &hexTo(45, "dae12318660cf963c7bcbef0f39d64de3bf178cf9e585e756654043cc5059873bc8af190b72afc43d1e0135ada"),
        },
        .{
            .seq = 255,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323535"),
            .nonce = hexTo(12, "a1bc314c1942ade7051ffe2f"),
            .ct = &hexTo(45, "55d53d85fe4d9e1e97903101eab0b4865ef20cef28765a47f840ff99625b7d69dee927df1defa66a036fc58ff2"),
        },
        .{
            .seq = 256,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323536"),
            .nonce = hexTo(12, "a1bc314c1942ade7051fffd0"),
            .ct = &hexTo(45, "42fa248a0e67ccca688f2b1d13ba4ba84755acf764bd797c8f7ba3b9b1dc3330326f8d172fef6003c79ec72319"),
        },
    };

    pub const exports = [_]Export{
        .{ .exporter_context = "", .l = 32, .exported_value = hexTo(32, "28c70088017d70c896a8420f04702c5a321d9cbf0279fba899b59e51bac72c85") },
        .{ .exporter_context = &hexTo(1, "00"), .l = 32, .exported_value = hexTo(32, "25dfc004b0892be1888c3914977aa9c9bbaf2c7471708a49e1195af48a6f29ce") },
        .{ .exporter_context = &hexTo(11, "54657374436f6e74657874"), .l = 32, .exported_value = hexTo(32, "5a0131813abc9a522cad678eb6bafaabc43389934adb8097d23c5ff68059eb64") },
    };
};

pub const a1_auth_psk = struct {
    pub const kem_id: u16 = 0x0020;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0001;
    pub const mode: u8 = 0x03;

    pub const info = hexTo(20, "4f6465206f6e2061204772656369616e2055726e");
    pub const ikmE = hexTo(32, "4303619085a20ebcf18edd22782952b8a7161e1dbae6e46e143a52a96127cf84");
    pub const pkEm = hexTo(32, "820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c");
    pub const skEm = hexTo(32, "14de82a5897b613616a00c39b87429df35bc2b426bcfd73febcb45e903490768");
    pub const ikmR = hexTo(32, "4b16221f3b269a88e207270b5e1de28cb01f847841b344b8314d6a622fe5ee90");
    pub const pkRm = hexTo(32, "1d11a3cd247ae48e901939659bd4d79b6b959e1f3e7d66663fbc9412dd4e0976");
    pub const skRm = hexTo(32, "cb29a95649dc5656c2d054c1aa0d3df0493155e9d5da6d7e344ed8b6a64a9423");
    pub const ikmS = hexTo(32, "62f77dcf5df0dd7eac54eac9f654f426d4161ec850cc65c54f8b65d2e0b4e345");
    pub const pkSm = hexTo(32, "2bfb2eb18fcad1af0e4f99142a1c474ae74e21b9425fc5c589382c69b50cc57e");
    pub const skSm = hexTo(32, "fc1c87d2f3832adb178b431fce2ac77c7ca2fd680f3406c77b5ecdf818b119f4");
    pub const psk = hexTo(32, "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    pub const psk_id = hexTo(22, "456e6e796e20447572696e206172616e204d6f726961");

    pub const enc = hexTo(32, "820818d3c23993492cc5623ab437a48a0a7ca3e9639c140fe1e33811eb844b7c");
    pub const shared_secret = hexTo(32, "f9d0e870aba28d04709b2680cb8185466c6a6ff1d6e9d1091d5bf5e10ce3a577");
    pub const key_schedule_context = hexTo(65, "03e78d5cf6190d275863411ff5edd0dece5d39fa48e04eec1ed9b71be34729d18ccb6cffde367bb0565ba28bb02c90744a20f5ef37f30523526106f637abb05449");
    pub const secret = hexTo(32, "5f96c55e4108c6691829aaabaa7d539c0b41d7c72aae94ae289752f056b6cec4");
    pub const key = hexTo(16, "1364ead92c47aa7becfa95203037b19a");
    pub const base_nonce = hexTo(12, "99d8b5c54669807e9fc70df1");
    pub const exporter_secret = hexTo(32, "f048d55eacbf60f9c6154bd4021774d1075ebf963c6adc71fa846f183ab2dde6");

    pub const encryptions = [_]Encryption{
        .{
            .seq = 0,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d30"),
            .nonce = hexTo(12, "99d8b5c54669807e9fc70df1"),
            .ct = &hexTo(45, "a84c64df1e11d8fd11450039d4fe64ff0c8a99fca0bd72c2d4c3e0400bc14a40f27e45e141a24001697737533e"),
        },
        .{
            .seq = 1,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d31"),
            .nonce = hexTo(12, "99d8b5c54669807e9fc70df0"),
            .ct = &hexTo(45, "4d19303b848f424fc3c3beca249b2c6de0a34083b8e909b6aa4c3688505c05ffe0c8f57a0a4c5ab9da127435d9"),
        },
        .{
            .seq = 2,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d32"),
            .nonce = hexTo(12, "99d8b5c54669807e9fc70df3"),
            .ct = &hexTo(45, "0c085a365fbfa63409943b00a3127abce6e45991bc653f182a80120868fc507e9e4d5e37bcc384fc8f14153b24"),
        },
        .{
            .seq = 4,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d34"),
            .nonce = hexTo(12, "99d8b5c54669807e9fc70df5"),
            .ct = &hexTo(45, "000a3cd3a3523bf7d9796830b1cd987e841a8bae6561ebb6791a3f0e34e89a4fb539faeee3428b8bbc082d2c1a"),
        },
        .{
            .seq = 255,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323535"),
            .nonce = hexTo(12, "99d8b5c54669807e9fc70d0e"),
            .ct = &hexTo(45, "576d39dd2d4cc77d1a14a51d5c5f9d5e77586c3d8d2ab33bdec6379e28ce5c502f0b1cbd09047cf9eb9269bb52"),
        },
        .{
            .seq = 256,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(9, "436f756e742d323536"),
            .nonce = hexTo(12, "99d8b5c54669807e9fc70cf1"),
            .ct = &hexTo(45, "13239bab72e25e9fd5bb09695d23c90a24595158b99127505c8a9ff9f127e0d657f71af59d67d4f4971da028f9"),
        },
    };

    pub const exports = [_]Export{
        .{ .exporter_context = "", .l = 32, .exported_value = hexTo(32, "08f7e20644bb9b8af54ad66d2067457c5f9fcb2a23d9f6cb4445c0797b330067") },
        .{ .exporter_context = &hexTo(1, "00"), .l = 32, .exported_value = hexTo(32, "52e51ff7d436557ced5265ff8b94ce69cf7583f49cdb374e6aad801fc063b010") },
        .{ .exporter_context = &hexTo(11, "54657374436f6e74657874"), .l = 32, .exported_value = hexTo(32, "a30c20370c026bbea4dca51cb63761695132d342bae33a6a11527d3e7679436d") },
    };
};

pub const a3_psk = struct {
    pub const kem_id: u16 = 0x0010;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0001;
    pub const mode: u8 = 0x01;

    pub const info = hexTo(20, "4f6465206f6e2061204772656369616e2055726e");
    pub const ikmE = hexTo(32, "2afa611d8b1a7b321c761b483b6a053579afa4f767450d3ad0f84a39fda587a6");
    pub const pkEm = hexTo(65, "04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f");
    pub const skEm = hexTo(32, "57427244f6cc016cddf1c19c8973b4060aa13579b4c067fd5d93a5d74e32a90f");
    pub const ikmR = hexTo(32, "d42ef874c1913d9568c9405407c805baddaffd0898a00f1e84e154fa787b2429");
    pub const pkRm = hexTo(65, "040d97419ae99f13007a93996648b2674e5260a8ebd2b822e84899cd52d87446ea394ca76223b76639eccdf00e1967db10ade37db4e7db476261fcc8df97c5ffd1");
    pub const skRm = hexTo(32, "438d8bcef33b89e0e9ae5eb0957c353c25a94584b0dd59c991372a75b43cb661");
    pub const psk = hexTo(32, "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    pub const psk_id = hexTo(22, "456e6e796e20447572696e206172616e204d6f726961");

    pub const enc = hexTo(65, "04305d35563527bce037773d79a13deabed0e8e7cde61eecee403496959e89e4d0ca701726696d1485137ccb5341b3c1c7aaee90a4a02449725e744b1193b53b5f");
    pub const shared_secret = hexTo(32, "2e783ad86a1beae03b5749e0f3f5e9bb19cb7eb382f2fb2dd64c99f15ae0661b");
    pub const key_schedule_context = hexTo(65, "01b873cdf2dff4c1434988053b7a775e980dd2039ea24f950b26b056ccedcb933198e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85");
    pub const secret = hexTo(32, "f2f534e55931c62eeb2188c1f53450354a725183937e68c85e68d6b267504d26");
    pub const key = hexTo(16, "55d9eb9d26911d4c514a990fa8d57048");
    pub const base_nonce = hexTo(12, "b595dc6b2d7e2ed23af529b1");
    pub const exporter_secret = hexTo(32, "895a723a1eab809804973a53c0ee18ece29b25a7555a4808277ad2651d66d705");

    pub const encryptions = [_]Encryption{
        .{
            .seq = 0,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d30"),
            .nonce = hexTo(12, "b595dc6b2d7e2ed23af529b1"),
            .ct = &hexTo(45, "90c4deb5b75318530194e4bb62f890b019b1397bbf9d0d6eb918890e1fb2be1ac2603193b60a49c2126b75d0eb"),
        },
        .{
            .seq = 1,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d31"),
            .nonce = hexTo(12, "b595dc6b2d7e2ed23af529b0"),
            .ct = &hexTo(45, "9e223384a3620f4a75b5a52f546b7262d8826dea18db5a365feb8b997180b22d72dc1287f7089a1073a7102c27"),
        },
    };

    pub const exports = [_]Export{
        .{ .exporter_context = "", .l = 32, .exported_value = hexTo(32, "a115a59bf4dd8dc49332d6a0093af8efca1bcbfd3627d850173f5c4a55d0c185") },
        .{ .exporter_context = &hexTo(1, "00"), .l = 32, .exported_value = hexTo(32, "4517eaede0669b16aac7c92d5762dd459c301fa10e02237cd5aeb9be969430c4") },
        .{ .exporter_context = &hexTo(11, "54657374436f6e74657874"), .l = 32, .exported_value = hexTo(32, "164e02144d44b607a7722e58b0f4156e67c0c2874d74cf71da6ca48a4cbdc5e0") },
    };
};

pub const a3_auth = struct {
    pub const kem_id: u16 = 0x0010;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0001;
    pub const mode: u8 = 0x02;

    pub const info = hexTo(20, "4f6465206f6e2061204772656369616e2055726e");
    pub const ikmE = hexTo(32, "798d82a8d9ea19dbc7f2c6dfa54e8a6706f7cdc119db0813dacf8440ab37c857");
    pub const pkEm = hexTo(65, "042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454");
    pub const skEm = hexTo(32, "6b8de0873aed0c1b2d09b8c7ed54cbf24fdf1dfc7a47fa501f918810642d7b91");
    pub const ikmR = hexTo(32, "7bc93bde8890d1fb55220e7f3b0c107ae7e6eda35ca4040bb6651284bf0747ee");
    pub const pkRm = hexTo(65, "04423e363e1cd54ce7b7573110ac121399acbc9ed815fae03b72ffbd4c18b01836835c5a09513f28fc971b7266cfde2e96afe84bb0f266920e82c4f53b36e1a78d");
    pub const skRm = hexTo(32, "d929ab4be2e59f6954d6bedd93e638f02d4046cef21115b00cdda2acb2a4440e");
    pub const ikmS = hexTo(32, "874baa0dcf93595a24a45a7f042e0d22d368747daaa7e19f80a802af19204ba8");
    pub const pkSm = hexTo(65, "04a817a0902bf28e036d66add5d544cc3a0457eab150f104285df1e293b5c10eef8651213e43d9cd9086c80b309df22cf37609f58c1127f7607e85f210b2804f73");
    pub const skSm = hexTo(32, "1120ac99fb1fccc1e8230502d245719d1b217fe20505c7648795139d177f0de9");

    pub const enc = hexTo(65, "042224f3ea800f7ec55c03f29fc9865f6ee27004f818fcbdc6dc68932c1e52e15b79e264a98f2c535ef06745f3d308624414153b22c7332bc1e691cb4af4d53454");
    pub const shared_secret = hexTo(32, "d4aea336439aadf68f9348880aa358086f1480e7c167b6ef15453ba69b94b44f");
    pub const key_schedule_context = hexTo(65, "02b88d4e6d91759e65e87c470e8b9141113e9ad5f0c8ceefc1e088c82e6980500798e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85");
    pub const secret = hexTo(32, "fd0a93c7c6f6b1b0dd6a822d7b16f6c61c83d98ad88426df4613c3581a2319f1");
    pub const key = hexTo(16, "19aa8472b3fdc530392b0e54ca17c0f5");
    pub const base_nonce = hexTo(12, "b390052d26b67a5b8a8fcaa4");
    pub const exporter_secret = hexTo(32, "f152759972660eb0e1db880835abd5de1c39c8e9cd269f6f082ed80e28acb164");

    pub const encryptions = [_]Encryption{
        .{
            .seq = 0,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d30"),
            .nonce = hexTo(12, "b390052d26b67a5b8a8fcaa4"),
            .ct = &hexTo(45, "82ffc8c44760db691a07c5627e5fc2c08e7a86979ee79b494a17cc3405446ac2bdb8f265db4a099ed3289ffe19"),
        },
        .{
            .seq = 1,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d31"),
            .nonce = hexTo(12, "b390052d26b67a5b8a8fcaa5"),
            .ct = &hexTo(45, "b0a705a54532c7b4f5907de51c13dffe1e08d55ee9ba59686114b05945494d96725b239468f1229e3966aa1250"),
        },
    };

    pub const exports = [_]Export{
        .{ .exporter_context = "", .l = 32, .exported_value = hexTo(32, "837e49c3ff629250c8d80d3c3fb957725ed481e59e2feb57afd9fe9a8c7c4497") },
        .{ .exporter_context = &hexTo(1, "00"), .l = 32, .exported_value = hexTo(32, "594213f9018d614b82007a7021c3135bda7b380da4acd9ab27165c508640dbda") },
        .{ .exporter_context = &hexTo(11, "54657374436f6e74657874"), .l = 32, .exported_value = hexTo(32, "14fe634f95ca0d86e15247cca7de7ba9b73c9b9deb6437e1c832daf7291b79d5") },
    };
};

pub const a3_auth_psk = struct {
    pub const kem_id: u16 = 0x0010;
    pub const kdf_id: u16 = 0x0001;
    pub const aead_id: u16 = 0x0001;
    pub const mode: u8 = 0x03;

    pub const info = hexTo(20, "4f6465206f6e2061204772656369616e2055726e");
    pub const ikmE = hexTo(32, "3c1fceb477ec954c8d58ef3249e4bb4c38241b5925b95f7486e4d9f1d0d35fbb");
    pub const pkEm = hexTo(65, "046a1de3fc26a3d43f4e4ba97dbe24f7e99181136129c48fbe872d4743e2b131357ed4f29a7b317dc22509c7b00991ae990bf65f8b236700c82ab7c11a84511401");
    pub const skEm = hexTo(32, "36f771e411cf9cf72f0701ef2b991ce9743645b472e835fe234fb4d6eb2ff5a0");
    pub const ikmR = hexTo(32, "abcc2da5b3fa81d8aabd91f7f800a8ccf60ec37b1b585a5d1d1ac77f258b6cca");
    pub const pkRm = hexTo(65, "04d824d7e897897c172ac8a9e862e4bd820133b8d090a9b188b8233a64dfbc5f725aa0aa52c8462ab7c9188f1c4872f0c99087a867e8a773a13df48a627058e1b3");
    pub const skRm = hexTo(32, "bdf4e2e587afdf0930644a0c45053889ebcadeca662d7c755a353d5b4e2a8394");
    pub const ikmS = hexTo(32, "6262031f040a9db853edd6f91d2272596eabbc78a2ed2bd643f770ecd0f19b82");
    pub const pkSm = hexTo(65, "049f158c750e55d8d5ad13ede66cf6e79801634b7acadcad72044eac2ae1d0480069133d6488bf73863fa988c4ba8bde1c2e948b761274802b4d8012af4f13af9e");
    pub const skSm = hexTo(32, "b0ed8721db6185435898650f7a677affce925aba7975a582653c4cb13c72d240");
    pub const psk = hexTo(32, "0247fd33b913760fa1fa51e1892d9f307fbe65eb171e8132c2af18555a738b82");
    pub const psk_id = hexTo(22, "456e6e796e20447572696e206172616e204d6f726961");

    pub const enc = hexTo(65, "046a1de3fc26a3d43f4e4ba97dbe24f7e99181136129c48fbe872d4743e2b131357ed4f29a7b317dc22509c7b00991ae990bf65f8b236700c82ab7c11a84511401");
    pub const shared_secret = hexTo(32, "d4c27698391db126f1612d9e91a767f10b9b19aa17e1695549203f0df7d9aebe");
    pub const key_schedule_context = hexTo(65, "03b873cdf2dff4c1434988053b7a775e980dd2039ea24f950b26b056ccedcb933198e486f9c9c09c9b5c753ac72d6005de254c607d1b534ed11d493ae1c1d9ac85");
    pub const secret = hexTo(32, "3bf9d4c7955da2740414e73081fa74d6f6f2b4b9645d0685219813ce99a2f270");
    pub const key = hexTo(16, "4d567121d67fae1227d90e11585988fb");
    pub const base_nonce = hexTo(12, "67c9d05330ca21e5116ecda6");
    pub const exporter_secret = hexTo(32, "3f479020ae186788e4dfd4a42a21d24f3faabb224dd4f91c2b2e5e9524ca27b2");

    pub const encryptions = [_]Encryption{
        .{
            .seq = 0,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d30"),
            .nonce = hexTo(12, "67c9d05330ca21e5116ecda6"),
            .ct = &hexTo(45, "b9f36d58d9eb101629a3e5a7b63d2ee4af42b3644209ab37e0a272d44365407db8e655c72e4fa46f4ff81b9246"),
        },
        .{
            .seq = 1,
            .pt = &hexTo(29, "4265617574792069732074727574682c20747275746820626561757479"),
            .aad = &hexTo(7, "436f756e742d31"),
            .nonce = hexTo(12, "67c9d05330ca21e5116ecda7"),
            .ct = &hexTo(45, "51788c4e5d56276771032749d015d3eea651af0c7bb8e3da669effffed299ea1f641df621af65579c10fc09736"),
        },
    };

    pub const exports = [_]Export{
        .{ .exporter_context = "", .l = 32, .exported_value = hexTo(32, "595ce0eff405d4b3bb1d08308d70a4e77226ce11766e0a94c4fdb5d90025c978") },
        .{ .exporter_context = &hexTo(1, "00"), .l = 32, .exported_value = hexTo(32, "110472ee0ae328f57ef7332a9886a1992d2c45b9b8d5abc9424ff68630f7d38d") },
        .{ .exporter_context = &hexTo(11, "54657374436f6e74657874"), .l = 32, .exported_value = hexTo(32, "18ee4d001a9d83a4c67e76f88dd747766576cac438723bad0700a910a4d717e6") },
    };
};

// ── composition tests (real labeledExtract/labeledExpand, no dhkem/schedule) ──

test "A.1/A.2/A.3 header ids match suite.KemId/KdfId/AeadId" {
    try testing.expectEqual(@as(u16, @intFromEnum(suite.KemId.dhkem_x25519_hkdf_sha256)), a1.kem_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.KdfId.hkdf_sha256)), a1.kdf_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.AeadId.aes128gcm)), a1.aead_id);

    try testing.expectEqual(@as(u16, @intFromEnum(suite.KemId.dhkem_x25519_hkdf_sha256)), a2.kem_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.AeadId.chacha20poly1305)), a2.aead_id);

    try testing.expectEqual(@as(u16, @intFromEnum(suite.KemId.dhkem_p256_hkdf_sha256)), a3.kem_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.AeadId.aes128gcm)), a3.aead_id);
}

test "A.1.1: enc == pkEm (base-mode DHKEM's enc IS the ephemeral public key, no extra encoding)" {
    try testing.expectEqualSlices(u8, &a1.pkEm, &a1.enc);
}

test "A.1.1: key_schedule_context/secret/key/base_nonce/exporter_secret, byte-exact via real LabeledExtract/LabeledExpand" {
    // Same chain as suite.zig's own KAT test, driven from this file's copy
    // of the vector — proves the two files agree on both the recipe AND
    // the constants, independent of dhkem/schedule (which the tests
    // further down drive for real).
    const suite_id = suite.suiteId(a1.kem_id, a1.kdf_id, a1.aead_id);
    const psk_id_hash = suite.labeledExtract(HkdfSha256, &suite_id, "", "psk_id_hash", "");
    const info_hash = suite.labeledExtract(HkdfSha256, &suite_id, "", "info_hash", &a1.info);

    var ksc: [65]u8 = undefined;
    ksc[0] = a1.mode;
    ksc[1..33].* = psk_id_hash;
    ksc[33..65].* = info_hash;
    try testing.expectEqualSlices(u8, &a1.key_schedule_context, &ksc);

    const secret = suite.labeledExtract(HkdfSha256, &suite_id, &a1.shared_secret, "secret", "");
    try testing.expectEqualSlices(u8, &a1.secret, &secret);

    var key: [16]u8 = undefined;
    try suite.labeledExpand(HkdfSha256, &suite_id, secret, "key", &ksc, &key);
    try testing.expectEqualSlices(u8, &a1.key, &key);

    var base_nonce: [12]u8 = undefined;
    try suite.labeledExpand(HkdfSha256, &suite_id, secret, "base_nonce", &ksc, &base_nonce);
    try testing.expectEqualSlices(u8, &a1.base_nonce, &base_nonce);

    var exporter_secret: [32]u8 = undefined;
    try suite.labeledExpand(HkdfSha256, &suite_id, secret, "exp", &ksc, &exporter_secret);
    try testing.expectEqualSlices(u8, &a1.exporter_secret, &exporter_secret);
}

test "A.1.1.2: all 3 exported values, byte-exact via real LabeledExpand(exporter_secret, \"sec\", ...)" {
    // RFC 9180 §5.3 Context.Export = LabeledExpand(suite_id,
    // exporter_secret, "sec", exporter_context, L) — driven here through
    // suite.labeledExpand directly (the Context.exportSecret method is
    // exercised separately below), so the raw math and the wrapper are
    // verified independently.
    const suite_id = suite.suiteId(a1.kem_id, a1.kdf_id, a1.aead_id);
    for (a1.exports) |exp| {
        var got: [32]u8 = undefined;
        std.debug.assert(exp.l == 32);
        try suite.labeledExpand(HkdfSha256, &suite_id, a1.exporter_secret, "sec", exp.exporter_context, &got);
        try testing.expectEqualSlices(u8, &exp.exported_value, &got);
    }
}

test "A.1.1.1: nonce = base_nonce XOR I2OSP(seq, Nn), byte-exact for all 6 published seq numbers" {
    for (a1.encryptions) |enc_case| {
        const got = schedule.computeNonce(12, a1.base_nonce, enc_case.seq);
        try testing.expectEqualSlices(u8, &enc_case.nonce, &got);
    }
}

// ── crypto-core tests (formerly stub-blocked, now driven for real) ──────

test "A.1.1: DHKEM(X25519).encapDeterministic(pkRm, {skEm,pkEm}) reproduces enc/shared_secret" {
    const eph = dhkem.X25519Kem.KeyPair{ .secret_key = a1.skEm, .public_key = a1.pkEm };
    const got = try dhkem.X25519Kem.encapDeterministic(a1.pkRm, eph);
    try testing.expectEqualSlices(u8, &a1.enc, &got.enc);
    try testing.expectEqualSlices(u8, &a1.shared_secret, &got.shared_secret);
}

test "A.1.1: DHKEM(X25519).decap(enc, skRm) reproduces shared_secret" {
    const skR = dhkem.X25519Kem.KeyPair{ .secret_key = a1.skRm, .public_key = a1.pkRm };
    const got = try dhkem.X25519Kem.decap(a1.enc, skR);
    try testing.expectEqualSlices(u8, &a1.shared_secret, &got);
}

test "A.1.1: DHKEM(X25519).deriveKeyPair reproduces skEm/pkEm from ikmE and skRm/pkRm from ikmR" {
    const kpE = dhkem.X25519Kem.deriveKeyPair(&a1.ikmE);
    try testing.expectEqualSlices(u8, &a1.skEm, &kpE.secret_key);
    try testing.expectEqualSlices(u8, &a1.pkEm, &kpE.public_key);
    const kpR = dhkem.X25519Kem.deriveKeyPair(&a1.ikmR);
    try testing.expectEqualSlices(u8, &a1.skRm, &kpR.secret_key);
    try testing.expectEqualSlices(u8, &a1.pkRm, &kpR.public_key);
}

test "A.1.1: schedule.keySchedule(.base, shared_secret, info) matches key/base_nonce/exporter_secret" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(a1.kem_id, a1.kdf_id, a1.aead_id);
    const ctx = try schedule.keySchedule(Aes128Gcm, 32, .base, &suite_id, &a1.shared_secret, &a1.info, "", "");
    try testing.expectEqualSlices(u8, &a1.key, &ctx.key);
    try testing.expectEqualSlices(u8, &a1.base_nonce, &ctx.base_nonce);
    try testing.expectEqualSlices(u8, &a1.exporter_secret, &ctx.exporter_secret);
    try testing.expectEqual(@as(u64, 0), ctx.seq);
}

test "A.1.1.1: Context.seal/.open reproduce all 6 published (pt,aad)->ct tuples (seq 0/1/2 sequential; 4/255 via direct seq set)" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(a1.kem_id, a1.kdf_id, a1.aead_id);
    var sender = try schedule.keySchedule(Aes128Gcm, 32, .base, &suite_id, &a1.shared_secret, &a1.info, "", "");
    var receiver = sender;

    for (a1.encryptions) |enc_case| {
        // seq 0/1/2 arrive sequentially via seal's own increment; the
        // vector then skips to 4 and 255 (proof the nonce derives from
        // `seq` directly, not a running counter) — `seq` is a plain pub
        // field, so skipping ahead is a direct assignment (the
        // noise.CipherState.setNonce precedent).
        sender.seq = enc_case.seq;
        var ct: [45]u8 = undefined;
        std.debug.assert(enc_case.ct.len == ct.len);
        try sender.seal(enc_case.aad, enc_case.pt, &ct);
        try testing.expectEqualSlices(u8, enc_case.ct, &ct);
        try testing.expectEqual(enc_case.seq + 1, sender.seq); // advanced exactly once

        receiver.seq = enc_case.seq;
        var pt: [29]u8 = undefined;
        try receiver.open(enc_case.aad, enc_case.ct, &pt);
        try testing.expectEqualSlices(u8, enc_case.pt, &pt);
        try testing.expectEqual(enc_case.seq + 1, receiver.seq);
    }
}

test "A.1.1.2: Context.exportSecret reproduces all 3 exported values (thin wrapper over the already-verified labeledExpand)" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(a1.kem_id, a1.kdf_id, a1.aead_id);
    const ctx = try schedule.keySchedule(Aes128Gcm, 32, .base, &suite_id, &a1.shared_secret, &a1.info, "", "");
    for (a1.exports) |exp| {
        var got: [32]u8 = undefined;
        std.debug.assert(exp.l == 32);
        try ctx.exportSecret(&suite_id, exp.exporter_context, &got);
        try testing.expectEqualSlices(u8, &exp.exported_value, &got);
    }
}

test "A.1: sealBaseDeterministic/openBase reproduce enc + the first ciphertext end-to-end in one call" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const eph = dhkem.X25519Kem.KeyPair{ .secret_key = a1.skEm, .public_key = a1.pkEm };
    const first = a1.encryptions[0];

    var ct: [45]u8 = undefined;
    const sealed = try schedule.sealBaseDeterministic(dhkem.X25519Kem, Aes128Gcm, 32, a1.pkRm, eph, &a1.info, first.aad, first.pt, &ct);
    try testing.expectEqualSlices(u8, &a1.enc, &sealed.enc);
    try testing.expectEqualSlices(u8, first.ct, &ct);

    const skR = dhkem.X25519Kem.KeyPair{ .secret_key = a1.skRm, .public_key = a1.pkRm };
    var pt: [29]u8 = undefined;
    try schedule.openBase(dhkem.X25519Kem, Aes128Gcm, 32, sealed.enc, skR, &a1.info, first.aad, &ct, &pt);
    try testing.expectEqualSlices(u8, first.pt, &pt);
}

test "A.2: X25519 + ChaCha20Poly1305 — Encap/Decap + KeySchedule + seq-0 Seal, byte-exact" {
    const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;

    const eph = dhkem.X25519Kem.KeyPair{ .secret_key = a2.skEm, .public_key = a2.pkEm };
    const got = try dhkem.X25519Kem.encapDeterministic(a2.pkRm, eph);
    try testing.expectEqualSlices(u8, &a2.enc, &got.enc);
    try testing.expectEqualSlices(u8, &a2.shared_secret, &got.shared_secret);
    const skR = dhkem.X25519Kem.KeyPair{ .secret_key = a2.skRm, .public_key = a2.pkRm };
    try testing.expectEqualSlices(u8, &a2.shared_secret, &(try dhkem.X25519Kem.decap(a2.enc, skR)));

    // A.2 uses the same info/pt/aad strings as A.1 (RFC 9180's Appendix A
    // fixes them across all vector sections: info "Ode on a Grecian Urn",
    // pt "Beauty is truth, truth beauty", aad "Count-0").
    const suite_id = suite.suiteId(a2.kem_id, a2.kdf_id, a2.aead_id);
    var ctx = try schedule.keySchedule(ChaCha20Poly1305, 32, .base, &suite_id, &a2.shared_secret, &a1.info, "", "");
    try testing.expectEqualSlices(u8, &a2.key, &ctx.key);
    try testing.expectEqualSlices(u8, &a2.base_nonce, &ctx.base_nonce);
    try testing.expectEqualSlices(u8, &a2.exporter_secret, &ctx.exporter_secret);

    var ct: [45]u8 = undefined;
    try ctx.seal(a1.encryptions[0].aad, a1.encryptions[0].pt, &ct);
    try testing.expectEqualSlices(u8, &a2.seq0_ct, &ct);
}

test "A.3: P-256 + AES-128-GCM — Encap/Decap + KeySchedule + seq-0 Seal, byte-exact" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;

    const eph = dhkem.P256Kem.KeyPair{ .secret_key = a3.skEm, .public_key = a3.pkEm };
    const got = try dhkem.P256Kem.encapDeterministic(a3.pkRm, eph);
    try testing.expectEqualSlices(u8, &a3.enc, &got.enc);
    try testing.expectEqualSlices(u8, &a3.shared_secret, &got.shared_secret);
    const skR = dhkem.P256Kem.KeyPair{ .secret_key = a3.skRm, .public_key = a3.pkRm };
    try testing.expectEqualSlices(u8, &a3.shared_secret, &(try dhkem.P256Kem.decap(a3.enc, skR)));

    // Same fixed info/pt/aad as A.1 (see the A.2 test's note).
    const suite_id = suite.suiteId(a3.kem_id, a3.kdf_id, a3.aead_id);
    var ctx = try schedule.keySchedule(Aes128Gcm, 32, .base, &suite_id, &a3.shared_secret, &a1.info, "", "");
    try testing.expectEqualSlices(u8, &a3.key, &ctx.key);
    try testing.expectEqualSlices(u8, &a3.base_nonce, &ctx.base_nonce);
    try testing.expectEqualSlices(u8, &a3.exporter_secret, &ctx.exporter_secret);

    var ct: [45]u8 = undefined;
    try ctx.seal(a1.encryptions[0].aad, a1.encryptions[0].pt, &ct);
    try testing.expectEqualSlices(u8, &a3.seq0_ct, &ct);
}

// ── A.4: the first HKDF-SHA384/512-widened vector ───────────────────────
//
// Everything above this point drives HKDF-SHA256 (Nh=32) exclusively — A.4
// is the ONE vector in this file that exercises schedule.zig's Nh-dispatch
// (KdfOf/kdfIdOf) with Nh=64 (HKDF-SHA512), proving the widening in
// schedule.zig actually changes the derived bytes rather than silently
// falling back to HKDF-SHA256. See a4's own doc comment for provenance.

test "A.4 header ids match suite.KemId/KdfId/AeadId (kdf_id is hkdf_sha512, NOT hkdf_sha256)" {
    try testing.expectEqual(@as(u16, @intFromEnum(suite.KemId.dhkem_p256_hkdf_sha256)), a4.kem_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.KdfId.hkdf_sha512)), a4.kdf_id);
    try testing.expectEqual(@as(u16, @intFromEnum(suite.AeadId.aes128gcm)), a4.aead_id);
}

test "A.4: DHKEM(P-256).encapDeterministic/.decap reproduce enc/shared_secret — UNCHANGED by the outer kdf_id" {
    // The KEM's own internal KDF (dhkem.zig's ExtractAndExpand) is fixed
    // HKDF-SHA256 by kem_id alone (RFC 9180 §7.1 Table 2) — this must
    // reproduce shared_secret the exact same way A.3's test does, even
    // though A.4's OUTER key schedule below runs HKDF-SHA512. If this KAT
    // passed with a WRONG shared_secret, no later stage could recover.
    const eph = dhkem.P256Kem.KeyPair{ .secret_key = a4.skEm, .public_key = a4.pkEm };
    const got = try dhkem.P256Kem.encapDeterministic(a4.pkRm, eph);
    try testing.expectEqualSlices(u8, &a4.enc, &got.enc);
    try testing.expectEqualSlices(u8, &a4.shared_secret, &got.shared_secret);
    const skR = dhkem.P256Kem.KeyPair{ .secret_key = a4.skRm, .public_key = a4.pkRm };
    try testing.expectEqualSlices(u8, &a4.shared_secret, &(try dhkem.P256Kem.decap(a4.enc, skR)));
}

test "A.4: key_schedule_context/secret, byte-exact via real LabeledExtract with the HKDF-SHA512 Kdf type (Nh=64)" {
    // Same recipe as the A.1.1 KSC test, but with schedule.KdfOf(64) (HKDF-
    // SHA512) instead of HkdfSha256 — checked SEPARATELY from
    // schedule.keySchedule (next test) so a wrong mode byte / suite_id /
    // labeling would name ITS OWN stage instead of surfacing as an opaque
    // wrong `key`.
    const Kdf = schedule.KdfOf(64);
    const suite_id = suite.suiteId(a4.kem_id, a4.kdf_id, a4.aead_id);
    const psk_id_hash = suite.labeledExtract(Kdf, &suite_id, "", "psk_id_hash", "");
    const info_hash = suite.labeledExtract(Kdf, &suite_id, "", "info_hash", &a4.info);

    var ksc: [129]u8 = undefined;
    ksc[0] = a4.mode;
    ksc[1..65].* = psk_id_hash;
    ksc[65..129].* = info_hash;
    try testing.expectEqualSlices(u8, &a4.key_schedule_context, &ksc);

    const secret = suite.labeledExtract(Kdf, &suite_id, &a4.shared_secret, "secret", "");
    try testing.expectEqualSlices(u8, &a4.secret, &secret);
}

test "A.4: schedule.keySchedule(.base, shared_secret, info, Nh=64) matches key/base_nonce/exporter_secret" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(a4.kem_id, a4.kdf_id, a4.aead_id);
    // Nh=64 is the whole point of this test: schedule.keySchedule must
    // dispatch to HKDF-SHA512 (schedule.KdfOf(64)) here, not silently keep
    // using HKDF-SHA256 — a mutation that hardcoded HkdfSha256 back in
    // would still COMPILE (Nh=64 only changes buffer widths, not which
    // Hkdf runs) but every assertion below would go red.
    const ctx = try schedule.keySchedule(Aes128Gcm, 64, .base, &suite_id, &a4.shared_secret, &a4.info, "", "");
    try testing.expectEqualSlices(u8, &a4.key, &ctx.key);
    try testing.expectEqualSlices(u8, &a4.base_nonce, &ctx.base_nonce);
    try testing.expectEqualSlices(u8, &a4.exporter_secret, &ctx.exporter_secret);
    try testing.expectEqual(@as(u64, 0), ctx.seq);
}

test "A.4: Context(Aead,64).seal/.open reproduce all 6 published tuples (seq 0/1/2/4/255/256)" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const suite_id = suite.suiteId(a4.kem_id, a4.kdf_id, a4.aead_id);
    var sender = try schedule.keySchedule(Aes128Gcm, 64, .base, &suite_id, &a4.shared_secret, &a4.info, "", "");
    var receiver = sender;

    for (a4.encryptions) |enc_case| {
        sender.seq = enc_case.seq;
        var ct: [45]u8 = undefined;
        std.debug.assert(enc_case.ct.len == ct.len);
        try sender.seal(enc_case.aad, enc_case.pt, &ct);
        try testing.expectEqualSlices(u8, enc_case.ct, &ct);
        try testing.expectEqual(enc_case.seq + 1, sender.seq);

        receiver.seq = enc_case.seq;
        var pt: [29]u8 = undefined;
        try receiver.open(enc_case.aad, enc_case.ct, &pt);
        try testing.expectEqualSlices(u8, enc_case.pt, &pt);
        try testing.expectEqual(enc_case.seq + 1, receiver.seq);
    }
}

test "A.4: sealBaseDeterministic/openBase (Nh=64) reproduce enc + the first ciphertext end-to-end in one call" {
    // The single-shot §6.1 wrapper path, not just keySchedule/Context
    // directly — proves suiteIdOf(Kem, Aead, Nh=64) (the sealBase/openBase
    // internal suite_id assembly) picks kdf_id=hkdf_sha512, matching the
    // suite_id used above, not the hkdf_sha256 default.
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const eph = dhkem.P256Kem.KeyPair{ .secret_key = a4.skEm, .public_key = a4.pkEm };
    const first = a4.encryptions[0];

    var ct: [45]u8 = undefined;
    const sealed = try schedule.sealBaseDeterministic(dhkem.P256Kem, Aes128Gcm, 64, a4.pkRm, eph, &a4.info, first.aad, first.pt, &ct);
    try testing.expectEqualSlices(u8, &a4.enc, &sealed.enc);
    try testing.expectEqualSlices(u8, first.ct, &ct);

    const skR = dhkem.P256Kem.KeyPair{ .secret_key = a4.skRm, .public_key = a4.pkRm };
    var pt: [29]u8 = undefined;
    try schedule.openBase(dhkem.P256Kem, Aes128Gcm, 64, sealed.enc, skR, &a4.info, first.aad, &ct, &pt);
    try testing.expectEqualSlices(u8, first.pt, &pt);
}

// ── non-base-mode vectors, driven end-to-end ────────────────────────────

/// Drive ONE complete RFC 9180 Appendix A vector through the real
/// implementation, every stage compared byte-for-byte against the RFC's own
/// published intermediate values rather than against a re-derivation:
///
///  1. `DeriveKeyPair(ikmE)`/`(ikmR)` (and `(ikmS)` in auth modes) → the
///     published `skEm`/`pkEm`, `skRm`/`pkRm`, `skSm`/`pkSm` (§7.1.3);
///  2. `Encap`/`AuthEncap` → the published `enc` + `shared_secret`, and
///     `Decap`/`AuthDecap` back to the same `shared_secret` (§4.1);
///  3. `key_schedule_context` reassembled from `suite.labeledExtract` —
///     this is the stage that catches a wrong `mode` byte or a
///     `psk_id_hash` taken over the wrong input, and it is checked
///     SEPARATELY from `keySchedule` so a divergence names the stage
///     instead of surfacing as an opaque wrong `key` (§5.1);
///  4. `keySchedule` → the published `key`/`base_nonce`/`exporter_secret`;
///  5. every published `(seq, pt, aad, ct)` tuple through `Context.seal`
///     AND back through `Context.open` (§5.2);
///  6. every published `(exporter_context, L, exported_value)` through
///     `Context.exportSecret` (§5.3).
///
/// Generic over the vector namespace (`V`), the KEM and the AEAD: the psk
/// and sender-static-key stages are selected by `@hasDecl`/`V.mode`, both
/// comptime-known, so a psk-less vector never instantiates the `ikmS` path
/// and vice versa.
fn driveVector(comptime V: type, comptime Kem: type, comptime Aead: type) !void {
    const mode: suite.Mode = @enumFromInt(V.mode);
    const is_auth = comptime (mode == .auth or mode == .auth_psk);
    // RFC 9180 §5.1's default_psk/default_psk_id are both "" — a non-psk
    // vector passes the empty string, exactly as VerifyPSKInputs expects.
    const psk: []const u8 = if (@hasDecl(V, "psk")) &V.psk else "";
    const psk_id: []const u8 = if (@hasDecl(V, "psk_id")) &V.psk_id else "";

    // 1. DeriveKeyPair for both parties (§7.1.3).
    const kpE = Kem.deriveKeyPair(&V.ikmE);
    try testing.expectEqualSlices(u8, &V.skEm, &kpE.secret_key);
    try testing.expectEqualSlices(u8, &V.pkEm, &kpE.public_key);
    const kpR = Kem.deriveKeyPair(&V.ikmR);
    try testing.expectEqualSlices(u8, &V.skRm, &kpR.secret_key);
    try testing.expectEqualSlices(u8, &V.pkRm, &kpR.public_key);

    // 2. (Auth)Encap / (Auth)Decap (§4.1).
    const encapped, const decapped = blk: {
        if (comptime is_auth) {
            const kpS = Kem.deriveKeyPair(&V.ikmS);
            try testing.expectEqualSlices(u8, &V.skSm, &kpS.secret_key);
            try testing.expectEqualSlices(u8, &V.pkSm, &kpS.public_key);
            break :blk .{
                try Kem.authEncapDeterministic(V.pkRm, kpS, kpE),
                try Kem.authDecap(V.enc, kpR, V.pkSm),
            };
        }
        break :blk .{
            try Kem.encapDeterministic(V.pkRm, kpE),
            try Kem.decap(V.enc, kpR),
        };
    };
    try testing.expectEqualSlices(u8, &V.enc, &encapped.enc);
    try testing.expectEqualSlices(u8, &V.shared_secret, &encapped.shared_secret);
    try testing.expectEqualSlices(u8, &V.shared_secret, &decapped);

    // 3. key_schedule_context + secret, from the §4 primitives directly.
    const suite_id = suite.suiteId(V.kem_id, V.kdf_id, V.aead_id);
    const psk_id_hash = suite.labeledExtract(HkdfSha256, &suite_id, "", "psk_id_hash", psk_id);
    const info_hash = suite.labeledExtract(HkdfSha256, &suite_id, "", "info_hash", &V.info);
    var ksc: [65]u8 = undefined;
    ksc[0] = V.mode;
    ksc[1..33].* = psk_id_hash;
    ksc[33..65].* = info_hash;
    try testing.expectEqualSlices(u8, &V.key_schedule_context, &ksc);
    const secret = suite.labeledExtract(HkdfSha256, &suite_id, &V.shared_secret, "secret", psk);
    try testing.expectEqualSlices(u8, &V.secret, &secret);

    // 4. KeySchedule (§5.1) through the real entry point.
    var sender = try schedule.keySchedule(Aead, 32, mode, &suite_id, &V.shared_secret, &V.info, psk, psk_id);
    try testing.expectEqualSlices(u8, &V.key, &sender.key);
    try testing.expectEqualSlices(u8, &V.base_nonce, &sender.base_nonce);
    try testing.expectEqualSlices(u8, &V.exporter_secret, &sender.exporter_secret);
    try testing.expectEqual(@as(u64, 0), sender.seq);
    var receiver = sender;

    // 5. Every published encryption tuple, sealed AND opened (§5.2). The
    //    published sequence numbers jump (0/1/2 then 4, 255, 256), so `seq`
    //    is assigned directly per tuple — the same `noise.CipherState
    //    .setNonce` precedent the base-mode test uses.
    for (V.encryptions) |enc_case| {
        try testing.expectEqualSlices(u8, &enc_case.nonce, &schedule.computeNonce(12, V.base_nonce, enc_case.seq));

        sender.seq = enc_case.seq;
        var ct: [45]u8 = undefined;
        std.debug.assert(enc_case.ct.len == ct.len);
        try sender.seal(enc_case.aad, enc_case.pt, &ct);
        try testing.expectEqualSlices(u8, enc_case.ct, &ct);
        try testing.expectEqual(enc_case.seq + 1, sender.seq);

        receiver.seq = enc_case.seq;
        var pt: [29]u8 = undefined;
        try receiver.open(enc_case.aad, enc_case.ct, &pt);
        try testing.expectEqualSlices(u8, enc_case.pt, &pt);
        try testing.expectEqual(enc_case.seq + 1, receiver.seq);
    }

    // 6. Every published exported value (§5.3).
    for (V.exports) |exp| {
        std.debug.assert(exp.l == 32);
        var got: [32]u8 = undefined;
        try sender.exportSecret(&suite_id, exp.exporter_context, &got);
        try testing.expectEqualSlices(u8, &exp.exported_value, &got);
    }
}

test "A.1.2 (mode_psk): X25519 + AES-128-GCM, full vector end-to-end, byte-exact" {
    try driveVector(a1_psk, dhkem.X25519Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "A.1.3 (mode_auth): X25519 + AES-128-GCM, full vector end-to-end, byte-exact" {
    try driveVector(a1_auth, dhkem.X25519Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "A.1.4 (mode_auth_psk): X25519 + AES-128-GCM, full vector end-to-end, byte-exact" {
    try driveVector(a1_auth_psk, dhkem.X25519Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "A.3.2 (mode_psk): P-256 + AES-128-GCM, full vector end-to-end, byte-exact" {
    try driveVector(a3_psk, dhkem.P256Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "A.3.3 (mode_auth): P-256 + AES-128-GCM, full vector end-to-end, byte-exact" {
    // Also the FIRST external anchor for `P256Kem.deriveKeyPair` (A.3.3
    // publishes ikmE/ikmR/ikmS; A.3.1's base header does not) and for the
    // P-256 AuthEncap/AuthDecap `dh || dh2` fold.
    try driveVector(a3_auth, dhkem.P256Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "A.3.4 (mode_auth_psk): P-256 + AES-128-GCM, full vector end-to-end, byte-exact" {
    try driveVector(a3_auth_psk, dhkem.P256Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "non-base vectors disagree pairwise: mode byte / psk / sender key each change the outputs" {
    // Guard against a copy-paste that points two vector namespaces at the
    // same bytes: A.1.2/A.1.3/A.1.4 share the same suite and info, so their
    // key/base_nonce/exporter_secret must differ purely because the MODE
    // (and its psk/sender-key inputs) differ.
    try testing.expect(!std.mem.eql(u8, &a1_psk.key, &a1_auth.key));
    try testing.expect(!std.mem.eql(u8, &a1_auth.key, &a1_auth_psk.key));
    try testing.expect(!std.mem.eql(u8, &a1.key, &a1_psk.key));
    // The mode byte is literally byte 0 of key_schedule_context.
    try testing.expectEqual(@as(u8, 0x00), a1.key_schedule_context[0]);
    try testing.expectEqual(@as(u8, 0x01), a1_psk.key_schedule_context[0]);
    try testing.expectEqual(@as(u8, 0x02), a1_auth.key_schedule_context[0]);
    try testing.expectEqual(@as(u8, 0x03), a1_auth_psk.key_schedule_context[0]);
    // base/auth share psk_id_hash (both over the empty psk_id) and
    // psk/auth_psk share theirs — a direct check that psk_id, not the mode,
    // is what feeds psk_id_hash.
    try testing.expectEqualSlices(u8, a1.key_schedule_context[1..33], a1_auth.key_schedule_context[1..33]);
    try testing.expectEqualSlices(u8, a1_psk.key_schedule_context[1..33], a1_auth_psk.key_schedule_context[1..33]);
    try testing.expect(!std.mem.eql(u8, a1.key_schedule_context[1..33], a1_psk.key_schedule_context[1..33]));
    // info is fixed across all of Appendix A, so info_hash must be too.
    try testing.expectEqualSlices(u8, a1.key_schedule_context[33..65], a1_auth_psk.key_schedule_context[33..65]);
}

// ── setup*S/setup*R (RFC 9180 §5.1): the NEW multi-message entry points ──
//
// Everything above drives `Context.exportSecret` against a `Context` either
// built directly by `schedule.keySchedule` (the base-mode tests) or by
// `driveVector`'s hand-composed `Kem.encap*`/`Kem.decap*` +
// `schedule.keySchedule` (the non-base modes) — i.e. the exact sequence
// `schedule.setupBaseS`/`setupPskS`/`setupAuthS`/`setupAuthPskS` (and their
// `setup*R` mirrors) now perform internally, but assembled by hand in the
// test rather than through those entry points. `driveSetupVector` below
// re-drives the SAME vectors through the real `setup*` functions instead,
// which is a strictly stronger check on the new API surface specifically:
// it is the difference between "this module's internals can reproduce the
// RFC" (already proven above) and "the `Context` a `setup*` CALLER actually
// receives reproduces the RFC" — the thing MLS's external-init/
// external-commit (RFC 9420 §8.3/§12.4) will call directly.
fn driveSetupVector(comptime V: type, comptime Kem: type, comptime Aead: type) !void {
    const mode: suite.Mode = @enumFromInt(V.mode);
    const is_psk = comptime (mode == .psk or mode == .auth_psk);

    // RFC 9180 §5.1's default_psk/default_psk_id are both "" (see
    // driveVector's own comment on this).
    const psk: []const u8 = if (comptime is_psk) &V.psk else "";
    const psk_id: []const u8 = if (comptime is_psk) &V.psk_id else "";

    const eph = Kem.KeyPair{ .secret_key = V.skEm, .public_key = V.pkEm };
    const skR = Kem.KeyPair{ .secret_key = V.skRm, .public_key = V.pkRm };

    // Sender side: `setup*SDeterministic` (the KAT seam — same ephemeral
    // pattern as `sealBaseDeterministic` etc.), dispatched on `mode` at
    // comptime so a non-auth vector never has to declare a `skSm`/`pkSm`
    // field it doesn't have (mirrors `driveVector`'s `is_auth` guard).
    var setup = if (comptime mode == .base)
        try schedule.setupBaseSDeterministic(Kem, Aead, 32, V.pkRm, eph, &V.info)
    else if (comptime mode == .psk)
        try schedule.setupPskSDeterministic(Kem, Aead, 32, V.pkRm, eph, &V.info, psk, psk_id)
    else if (comptime mode == .auth) blk: {
        const skS = Kem.KeyPair{ .secret_key = V.skSm, .public_key = V.pkSm };
        break :blk try schedule.setupAuthSDeterministic(Kem, Aead, 32, V.pkRm, skS, eph, &V.info);
    } else blk: {
        const skS = Kem.KeyPair{ .secret_key = V.skSm, .public_key = V.pkSm };
        break :blk try schedule.setupAuthPskSDeterministic(Kem, Aead, 32, V.pkRm, skS, eph, &V.info, psk, psk_id);
    };

    try testing.expectEqualSlices(u8, &V.enc, &setup.enc);
    try testing.expectEqualSlices(u8, &V.key, &setup.context.key);
    try testing.expectEqualSlices(u8, &V.base_nonce, &setup.context.base_nonce);
    try testing.expectEqualSlices(u8, &V.exporter_secret, &setup.context.exporter_secret);
    try testing.expectEqual(@as(u64, 0), setup.context.seq);

    // Receiver side: `setup*R`, given the `enc` the sender side just
    // produced (which already matched `V.enc` above).
    var receiver = if (comptime mode == .base)
        try schedule.setupBaseR(Kem, Aead, 32, setup.enc, skR, &V.info)
    else if (comptime mode == .psk)
        try schedule.setupPskR(Kem, Aead, 32, setup.enc, skR, &V.info, psk, psk_id)
    else if (comptime mode == .auth)
        try schedule.setupAuthR(Kem, Aead, 32, setup.enc, skR, V.pkSm, &V.info)
    else
        try schedule.setupAuthPskR(Kem, Aead, 32, setup.enc, skR, V.pkSm, &V.info, psk, psk_id);

    try testing.expectEqualSlices(u8, &V.key, &receiver.key);
    try testing.expectEqualSlices(u8, &V.base_nonce, &receiver.base_nonce);
    try testing.expectEqualSlices(u8, &V.exporter_secret, &receiver.exporter_secret);

    // §5.2 spot check: the setup-returned `Context` still seals/opens (not
    // this harness's main point — `driveVector` already covers every
    // published tuple — but proof the returned `Context` is a live,
    // correctly-keyed one, not just a struct with the right-looking bytes).
    const first = V.encryptions[0];
    var ct: [45]u8 = undefined;
    try setup.context.seal(first.aad, first.pt, &ct);
    try testing.expectEqualSlices(u8, first.ct, &ct);
    var pt: [29]u8 = undefined;
    try receiver.open(first.aad, &ct, &pt);
    try testing.expectEqualSlices(u8, first.pt, &pt);

    // §5.3 — the point of this harness: every published exported value,
    // through `Context.exportSecret` called on the `setup*`-returned
    // `Context`, on BOTH the sender's copy and the receiver's independently
    // constructed copy.
    const suite_id = suite.suiteId(V.kem_id, V.kdf_id, V.aead_id);
    for (V.exports) |exp| {
        std.debug.assert(exp.l == 32);
        var got_s: [32]u8 = undefined;
        var got_r: [32]u8 = undefined;
        try setup.context.exportSecret(&suite_id, exp.exporter_context, &got_s);
        try receiver.exportSecret(&suite_id, exp.exporter_context, &got_r);
        try testing.expectEqualSlices(u8, &exp.exported_value, &got_s);
        try testing.expectEqualSlices(u8, &exp.exported_value, &got_r);
    }
}

test "setupBaseS/setupBaseR (A.1.1): Context fields + all 3 exports byte-exact through the new §5.1 entry points" {
    try driveSetupVector(a1, dhkem.X25519Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "setupPskS/setupPskR (A.1.2): Context fields + all 3 exports byte-exact through the new §5.1 entry points" {
    try driveSetupVector(a1_psk, dhkem.X25519Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "setupAuthS/setupAuthR (A.1.3): Context fields + all 3 exports byte-exact through the new §5.1 entry points" {
    try driveSetupVector(a1_auth, dhkem.X25519Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "setupAuthPskS/setupAuthPskR (A.1.4): Context fields + all 3 exports byte-exact through the new §5.1 entry points" {
    try driveSetupVector(a1_auth_psk, dhkem.X25519Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "setupPskS/setupPskR (A.3.2): P-256 + AES-128-GCM, Context fields + exports byte-exact through the new entry points" {
    try driveSetupVector(a3_psk, dhkem.P256Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "setupAuthS/setupAuthR (A.3.3): P-256 + AES-128-GCM, Context fields + exports byte-exact through the new entry points" {
    try driveSetupVector(a3_auth, dhkem.P256Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "setupAuthPskS/setupAuthPskR (A.3.4): P-256 + AES-128-GCM, Context fields + exports byte-exact through the new entry points" {
    try driveSetupVector(a3_auth_psk, dhkem.P256Kem, std.crypto.aead.aes_gcm.Aes128Gcm);
}

test "A.1.2/A.1.3/A.1.4: the single-shot sealPsk/sealAuth/sealAuthPsk wrappers reproduce enc + the first ciphertext" {
    // The §6.1 one-call path has its own composition (KEM call + mode byte +
    // psk plumbing) that the multi-step tests above do NOT cover: a wrapper
    // that passed `.base` where it meant `.psk`, or dropped `psk_id`, would
    // still round-trip against its own `open*` counterpart. Only the RFC's
    // published `enc`/`ct` catch it.
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const Kem = dhkem.X25519Kem;

    // mode_psk (A.1.2)
    {
        const V = a1_psk;
        const eph = Kem.KeyPair{ .secret_key = V.skEm, .public_key = V.pkEm };
        const skR = Kem.KeyPair{ .secret_key = V.skRm, .public_key = V.pkRm };
        var ct: [45]u8 = undefined;
        const sealed = try schedule.sealPskDeterministic(Kem, Aes128Gcm, 32, V.pkRm, eph, &V.info, &V.psk, &V.psk_id, V.encryptions[0].aad, V.encryptions[0].pt, &ct);
        try testing.expectEqualSlices(u8, &V.enc, &sealed.enc);
        try testing.expectEqualSlices(u8, V.encryptions[0].ct, &ct);
        var pt: [29]u8 = undefined;
        try schedule.openPsk(Kem, Aes128Gcm, 32, sealed.enc, skR, &V.info, &V.psk, &V.psk_id, V.encryptions[0].aad, &ct, &pt);
        try testing.expectEqualSlices(u8, V.encryptions[0].pt, &pt);
    }

    // mode_auth (A.1.3)
    {
        const V = a1_auth;
        const eph = Kem.KeyPair{ .secret_key = V.skEm, .public_key = V.pkEm };
        const skR = Kem.KeyPair{ .secret_key = V.skRm, .public_key = V.pkRm };
        const skS = Kem.KeyPair{ .secret_key = V.skSm, .public_key = V.pkSm };
        var ct: [45]u8 = undefined;
        const sealed = try schedule.sealAuthDeterministic(Kem, Aes128Gcm, 32, V.pkRm, skS, eph, &V.info, V.encryptions[0].aad, V.encryptions[0].pt, &ct);
        try testing.expectEqualSlices(u8, &V.enc, &sealed.enc);
        try testing.expectEqualSlices(u8, V.encryptions[0].ct, &ct);
        var pt: [29]u8 = undefined;
        try schedule.openAuth(Kem, Aes128Gcm, 32, sealed.enc, skR, V.pkSm, &V.info, V.encryptions[0].aad, &ct, &pt);
        try testing.expectEqualSlices(u8, V.encryptions[0].pt, &pt);
    }

    // mode_auth_psk (A.1.4)
    {
        const V = a1_auth_psk;
        const eph = Kem.KeyPair{ .secret_key = V.skEm, .public_key = V.pkEm };
        const skR = Kem.KeyPair{ .secret_key = V.skRm, .public_key = V.pkRm };
        const skS = Kem.KeyPair{ .secret_key = V.skSm, .public_key = V.pkSm };
        var ct: [45]u8 = undefined;
        const sealed = try schedule.sealAuthPskDeterministic(Kem, Aes128Gcm, 32, V.pkRm, skS, eph, &V.info, &V.psk, &V.psk_id, V.encryptions[0].aad, V.encryptions[0].pt, &ct);
        try testing.expectEqualSlices(u8, &V.enc, &sealed.enc);
        try testing.expectEqualSlices(u8, V.encryptions[0].ct, &ct);
        var pt: [29]u8 = undefined;
        try schedule.openAuthPsk(Kem, Aes128Gcm, 32, sealed.enc, skR, V.pkSm, &V.info, &V.psk, &V.psk_id, V.encryptions[0].aad, &ct, &pt);
        try testing.expectEqualSlices(u8, V.encryptions[0].pt, &pt);
    }
}

test "A.3.2/A.3.3/A.3.4: the same single-shot wrappers over the P-256 KEM (Npk=65) reproduce enc + the first ciphertext" {
    const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const Kem = dhkem.P256Kem;

    {
        const V = a3_psk;
        const eph = Kem.KeyPair{ .secret_key = V.skEm, .public_key = V.pkEm };
        var ct: [45]u8 = undefined;
        const sealed = try schedule.sealPskDeterministic(Kem, Aes128Gcm, 32, V.pkRm, eph, &V.info, &V.psk, &V.psk_id, V.encryptions[0].aad, V.encryptions[0].pt, &ct);
        try testing.expectEqualSlices(u8, &V.enc, &sealed.enc);
        try testing.expectEqualSlices(u8, V.encryptions[0].ct, &ct);
    }
    {
        const V = a3_auth;
        const eph = Kem.KeyPair{ .secret_key = V.skEm, .public_key = V.pkEm };
        const skS = Kem.KeyPair{ .secret_key = V.skSm, .public_key = V.pkSm };
        var ct: [45]u8 = undefined;
        const sealed = try schedule.sealAuthDeterministic(Kem, Aes128Gcm, 32, V.pkRm, skS, eph, &V.info, V.encryptions[0].aad, V.encryptions[0].pt, &ct);
        try testing.expectEqualSlices(u8, &V.enc, &sealed.enc);
        try testing.expectEqualSlices(u8, V.encryptions[0].ct, &ct);
    }
    {
        const V = a3_auth_psk;
        const eph = Kem.KeyPair{ .secret_key = V.skEm, .public_key = V.pkEm };
        const skS = Kem.KeyPair{ .secret_key = V.skSm, .public_key = V.pkSm };
        var ct: [45]u8 = undefined;
        const sealed = try schedule.sealAuthPskDeterministic(Kem, Aes128Gcm, 32, V.pkRm, skS, eph, &V.info, &V.psk, &V.psk_id, V.encryptions[0].aad, V.encryptions[0].pt, &ct);
        try testing.expectEqualSlices(u8, &V.enc, &sealed.enc);
        try testing.expectEqualSlices(u8, V.encryptions[0].ct, &ct);
    }
}

// ── §5.1's REAL random-ephemeral entry points (`setupBaseS`/`setupPskS`/
// `setupAuthS`/`setupAuthPskS`) ─────────────────────────────────────────
//
// Every test above drives ONLY the `*Deterministic` KAT seam — no test
// anywhere in this module ever calls `setupBaseS`/`setupPskS`/`setupAuthS`/
// `setupAuthPskS` themselves (grep confirms zero call sites outside their
// own definitions), even though those four ARE the entry points a real
// caller uses (they draw the ephemeral from `std.Io` via `Kem.
// generateKeyPair(io)` instead of taking one as a KAT-injected parameter).
// There is no RFC vector to check a fresh random ephemeral against, but
// `std.Io.Threaded` (already used elsewhere in this repo, e.g.
// `adaptor/src/kat_test.zig`'s `testIo()`) stands up a real event loop
// cheaply enough to exercise the actual wiring end-to-end: sender and
// receiver must derive the SAME context (key/base_nonce/exporter_secret)
// and a message sealed by one must open under the other — for all four
// modes.
test "setupBaseS/setupPskS/setupAuthS/setupAuthPskS: real std.Io random-ephemeral path round-trips (no test called these before)" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Kem = dhkem.X25519Kem;
    const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
    const info = "hpke setup*S io-path smoke test";
    const psk = [_]u8{0x42} ** 32;
    const psk_id = "psk-id";

    const skR = Kem.generateKeyPair(io);
    const skS = Kem.generateKeyPair(io);

    const Fixture = struct {
        fn check(setup: schedule.Setup(Kem, Aead, 32), receiver: schedule.Context(Aead, 32)) !void {
            try testing.expectEqualSlices(u8, &setup.context.key, &receiver.key);
            try testing.expectEqualSlices(u8, &setup.context.base_nonce, &receiver.base_nonce);
            try testing.expectEqualSlices(u8, &setup.context.exporter_secret, &receiver.exporter_secret);

            var sender_ctx = setup.context;
            var receiver_ctx = receiver;
            const pt = "hpke setup*S/R real io-path round trip";
            var ct: [pt.len + 16]u8 = undefined;
            try sender_ctx.seal("aad", pt, &ct);
            var got_pt: [pt.len]u8 = undefined;
            try receiver_ctx.open("aad", &ct, &got_pt);
            try testing.expectEqualSlices(u8, pt, &got_pt);
        }
    };

    // base
    {
        const setup = try schedule.setupBaseS(Kem, Aead, 32, skR.public_key, io, info);
        const receiver = try schedule.setupBaseR(Kem, Aead, 32, setup.enc, skR, info);
        try Fixture.check(setup, receiver);
    }
    // psk
    {
        const setup = try schedule.setupPskS(Kem, Aead, 32, skR.public_key, io, info, &psk, psk_id);
        const receiver = try schedule.setupPskR(Kem, Aead, 32, setup.enc, skR, info, &psk, psk_id);
        try Fixture.check(setup, receiver);
    }
    // auth
    {
        const setup = try schedule.setupAuthS(Kem, Aead, 32, skR.public_key, skS, io, info);
        const receiver = try schedule.setupAuthR(Kem, Aead, 32, setup.enc, skR, skS.public_key, info);
        try Fixture.check(setup, receiver);
    }
    // auth_psk
    {
        const setup = try schedule.setupAuthPskS(Kem, Aead, 32, skR.public_key, skS, io, info, &psk, psk_id);
        const receiver = try schedule.setupAuthPskR(Kem, Aead, 32, setup.enc, skR, skS.public_key, info, &psk, psk_id);
        try Fixture.check(setup, receiver);
    }
}

test "RFC 9180 A.1.2/A.1.4's own psk is exactly Nh bytes — the §5.1.2 floor keySchedule enforces accepts the spec's vectors" {
    try testing.expectEqual(@as(usize, 32), a1_psk.psk.len);
    try testing.expectEqual(@as(usize, 32), a1_auth_psk.psk.len);
    try testing.expectEqual(@as(usize, 32), a3_psk.psk.len);
    try testing.expectEqual(@as(usize, 32), a3_auth_psk.psk.len);
}
