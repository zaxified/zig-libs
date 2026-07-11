// SPDX-License-Identifier: MIT

//! tlsresume.psk — resumption-PSK derivation and the PSK binder (RFC 8446
//! §7.1 / §4.2.11.2 / §4.6.1). **REAL — KAT-validated byte-exact against
//! RFC 8448 §4's resumed-handshake trace** (see the tests below). This is
//! the single most security-critical file in `tlsresume`: a wrong or
//! skipped binder check lets an attacker splice a PSK identity harvested
//! from one connection into another (RFC 8446 §4.2.11.2's whole reason for
//! existing).
//!
//! **Derivation chain this file implements the shape of** (each function
//! below is one link):
//!
//! ```
//! resumption_master_secret ─┬─ HKDF-Expand-Label(..., "resumption",
//!                           │   ticket_nonce, Hash.length)          -> PSK
//!                           │        (derivePsk)
//! PSK ──────────────────────┴─ HKDF-Extract(salt=0, IKM=PSK)        -> early_secret
//!                                    (earlySecret — same primitive TLS 1.3
//!                                     uses for any PSK, external or
//!                                     resumption; RFC 8446 §7.1)
//! early_secret ─── Derive-Secret(early_secret, "res binder", "")    -> binder_key
//!                       (binderKey — NOTE the label is "res binder" for a
//!                        RESUMPTION psk, vs "ext binder" for an externally
//!                        configured one; this is the one label difference
//!                        from an ext-PSK binder chain such as this repo's
//!                        `dtls` module, which only implements "ext binder")
//! binder_key ─── HKDF-Expand-Label(binder_key, "finished", "",
//!                Hash.length) -> finished_key, then
//!                HMAC(finished_key, Transcript-Hash(truncated ClientHello))
//!                -> binder                                          (computeBinder)
//! ```
//!
//! **`std.crypto.tls.hkdfExpandLabel` (why std's function is used here):**
//! unlike this repo's `dtls` module (which targets DTLS 1.3 and therefore
//! CANNOT use it — RFC 9147 §5.9 changes the label prefix to `"dtls13"`),
//! `tlsresume` targets plain TLS 1.3 resumption, for which std's hardcoded
//! `"tls13 "` prefix is exactly correct per RFC 8446 §7.1. So the functions
//! below are thin wrappers over `std.crypto.tls.hkdfExpandLabel(Hkdf,
//! secret, label, context, len)` + `Hkdf.extract` + `Hmac.create`,
//! mirroring `dtls.keyschedule`'s `deriveSecret`/`hkdfExpandLabel` shape —
//! the value this file adds is pinning the RESUMPTION-specific labels
//! (`"resumption"`, `"res binder"`) and the KAT proof, not novel crypto.
//!
//! Support SHA-256 and SHA-384 (the two TLS 1.3 cipher-suite hash lengths,
//! RFC 8446 §B.4) via the `Hkdf`/`Hmac` comptime type parameters, exactly
//! like `dtls.keyschedule`.

const std = @import("std");

/// RFC 8446 §7.1 / §4.6.1: `PSK = HKDF-Expand-Label(resumption_master_secret,
/// "resumption", ticket_nonce, Hash.length)`. `ticket_nonce` is the value
/// carried in the NewSessionTicket (`ticket.NewSessionTicket.ticket_nonce`).
pub fn derivePsk(
    comptime Hkdf: type,
    resumption_master_secret: [Hkdf.prk_length]u8,
    ticket_nonce: []const u8,
    comptime len: usize,
) [len]u8 {
    return std.crypto.tls.hkdfExpandLabel(Hkdf, resumption_master_secret, "resumption", ticket_nonce, len);
}

/// RFC 8446 §7.1: `Early Secret = HKDF-Extract(salt = 0^Hash.length, IKM =
/// PSK)`. Same primitive as an externally configured PSK's early secret
/// (RFC 8446 draws no distinction here) — the resumption-vs-external split
/// happens one step later, in `binderKey`'s label.
pub fn earlySecret(comptime Hkdf: type, psk: []const u8) [Hkdf.prk_length]u8 {
    const zero_salt = [_]u8{0} ** Hkdf.prk_length;
    return Hkdf.extract(&zero_salt, psk);
}

/// RFC 8446 §7.1: `binder_key = Derive-Secret(early_secret, "res binder",
/// "")` — the RESUMPTION-PSK binder key. (An external PSK instead uses `"ext
/// binder"`; this module only ever derives the resumption path, since it
/// exists to fill DTLS's/this collection's declared resumption gap — see
/// `dtls`'s SPEC.md "out of scope: session resumption".) `empty_transcript_hash`
/// is `Hash("")` — the hash of the empty message list.
pub fn binderKey(
    comptime Hkdf: type,
    early_secret: [Hkdf.prk_length]u8,
    empty_transcript_hash: []const u8,
) [Hkdf.prk_length]u8 {
    // Derive-Secret(early_secret, "res binder", "") = HKDF-Expand-Label(
    // early_secret, "res binder", Transcript-Hash(""), Hash.length).
    return std.crypto.tls.hkdfExpandLabel(Hkdf, early_secret, "res binder", empty_transcript_hash, Hkdf.prk_length);
}

/// RFC 8446 §4.2.11.2: the PSK binder itself — `HMAC(finished_key,
/// Transcript-Hash(Truncate(ClientHello)))` where `finished_key =
/// HKDF-Expand-Label(binder_key, "finished", "", Hash.length)`. The caller
/// (the TLS engine) supplies the transcript hash of the ClientHello
/// truncated to everything up to but EXCLUDING the binders list itself (the
/// binder authenticates all of the ClientHello except its own bytes) — this
/// module never touches transcript/handshake-message bytes directly, only
/// the already-hashed digest, keeping it engine-agnostic.
///
/// **Most security-critical function in this module.** Server side: this
/// is the function `verifyBinder` wraps in a constant-time compare — a
/// skipped or short-circuited call here is a full PSK-binder bypass.
pub fn computeBinder(
    comptime Hkdf: type,
    comptime Hmac: type,
    binder_key: [Hkdf.prk_length]u8,
    truncated_client_hello_transcript_hash: []const u8,
) [Hmac.mac_length]u8 {
    const finished_key = std.crypto.tls.hkdfExpandLabel(Hkdf, binder_key, "finished", "", Hmac.mac_length);
    var out: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&out, truncated_client_hello_transcript_hash, &finished_key);
    return out;
}

/// Server-side verify: recompute the binder via `computeBinder` and compare
/// against the client-offered `offered_binder` in CONSTANT time
/// (`std.crypto.timing_safe.eql`, never `std.mem.eql`) — mirrors
/// `dtls.keyschedule.computeFinishedVerifyData`'s doc-comment guidance for
/// the same reason (a variable-time compare leaks the correct binder one
/// byte at a time to a timing-measuring attacker).
pub fn verifyBinder(
    comptime Hkdf: type,
    comptime Hmac: type,
    binder_key: [Hkdf.prk_length]u8,
    truncated_client_hello_transcript_hash: []const u8,
    offered_binder: [Hmac.mac_length]u8,
) bool {
    const computed = computeBinder(Hkdf, Hmac, binder_key, truncated_client_hello_transcript_hash);
    return std.crypto.timing_safe.eql([Hmac.mac_length]u8, computed, offered_binder);
}

// ── tests: RFC 8448 §4 ("Resumed 0-RTT Handshake") known-answer vectors ──
//
// All values below were fetched from https://www.rfc-editor.org/rfc/rfc8448
// §3/§4 — the resumption_master_secret from §3's simple 1-RTT trace, and
// the derived PSK/binder-key/finished-key/binder chain from §4's resumed
// handshake, which reuses that same resumption_master_secret + a
// ticket_nonce of `00 00`. These are the SAME vectors this repo's `dtls`
// module's `keyschedule.zig` already validates its ext-PSK-binder math
// against (see that file's "RFC 8448 §4: PSK binder" tests) — this file
// asserts the equivalent RESUMPTION-PSK chain (the "res binder" label
// instead of "ext binder"), which is the one place the two chains diverge.

const testing = std.testing;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

fn hexTo(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn emptyHash() [32]u8 {
    var h: [32]u8 = undefined;
    Sha256.hash("", &h, .{});
    return h;
}

// RFC 8448 §3: the resumption_master_secret produced by the FIRST (full)
// handshake, later fed into the resumed handshake's ticket derivation.
const rfc8448_resumption_master_secret = hexTo(32, "7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c");
// RFC 8448 §3's NewSessionTicket carries `ticket_nonce = 00 00` (see
// ticket.zig's own decode test against the same trace).
const rfc8448_ticket_nonce = hexTo(2, "0000");
// RFC 8448 §4: PSK = HKDF-Expand-Label(rms, "resumption", ticket_nonce, 32).
const rfc8448_psk = hexTo(32, "4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
// RFC 8448 §4: early_secret = HKDF-Extract(0, PSK).
const rfc8448_early_secret = hexTo(32, "9b2188e9b2fc6d64d71dc329900e20bb41915000f678aa839cbb797cb7d8332c");
// RFC 8448 §4: binder_key = Derive-Secret(early_secret, "res binder", "").
const rfc8448_binder_key = hexTo(32, "69fe131a3bbad5d63c64eebcc30e395b9d8107726a13d074e389dbc8a4e47256");
// RFC 8448 §4: finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32).
const rfc8448_finished_key = hexTo(32, "5588673e72cb59c87d220caffe94f2dea9a3b1609f7d50e90a48227db9ed7eaa");
// RFC 8448 §4: transcript hash of the truncated (resumed) ClientHello.
const rfc8448_binder_hash = hexTo(32, "63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");
// RFC 8448 §4: the resulting PSK binder.
const rfc8448_binder = hexTo(32, "3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d");

test "sanity: RFC 8448 KAT chain is internally consistent (independent of the stubs)" {
    // This test does NOT call any tlsresume.psk function — it just proves
    // the constants above chain together correctly (HKDF/HMAC math via std
    // directly), so the guarded tests below have a known-good target once
    // unstubbed. Mirrors dtls/keyschedule.zig's own "byte-exact" KAT style.
    const es = HkdfSha256.extract(&[_]u8{0} ** 32, &rfc8448_psk);
    try testing.expectEqualSlices(u8, &rfc8448_early_secret, &es);

    const bk = std.crypto.tls.hkdfExpandLabel(HkdfSha256, es, "res binder", &emptyHash(), 32);
    try testing.expectEqualSlices(u8, &rfc8448_binder_key, &bk);

    const fk = std.crypto.tls.hkdfExpandLabel(HkdfSha256, bk, "finished", "", 32);
    try testing.expectEqualSlices(u8, &rfc8448_finished_key, &fk);

    var binder: [32]u8 = undefined;
    HmacSha256.create(&binder, &rfc8448_binder_hash, &fk);
    try testing.expectEqualSlices(u8, &rfc8448_binder, &binder);
}

test "derivePsk matches RFC 8448 §4 PSK" {
    const got = derivePsk(HkdfSha256, rfc8448_resumption_master_secret, &rfc8448_ticket_nonce, 32);
    try testing.expectEqualSlices(u8, &rfc8448_psk, &got);
}

test "earlySecret matches RFC 8448 §4 early_secret" {
    const got = earlySecret(HkdfSha256, &rfc8448_psk);
    try testing.expectEqualSlices(u8, &rfc8448_early_secret, &got);
}

test "binderKey uses \"res binder\" and matches RFC 8448 §4" {
    const got = binderKey(HkdfSha256, rfc8448_early_secret, &emptyHash());
    try testing.expectEqualSlices(u8, &rfc8448_binder_key, &got);
}

test "computeBinder matches RFC 8448 §4 binder byte-exact" {
    const got = computeBinder(HkdfSha256, HmacSha256, rfc8448_binder_key, &rfc8448_binder_hash);
    try testing.expectEqualSlices(u8, &rfc8448_binder, &got);
}

test "verifyBinder accepts the real binder and rejects a flipped byte" {
    try testing.expect(verifyBinder(HkdfSha256, HmacSha256, rfc8448_binder_key, &rfc8448_binder_hash, rfc8448_binder));
    var bad = rfc8448_binder;
    bad[0] ^= 1;
    try testing.expect(!verifyBinder(HkdfSha256, HmacSha256, rfc8448_binder_key, &rfc8448_binder_hash, bad));
}

test "full chain: rms + nonce -> PSK -> early secret -> binder key -> binder (RFC 8448 §4, end-to-end)" {
    const psk = derivePsk(HkdfSha256, rfc8448_resumption_master_secret, &rfc8448_ticket_nonce, 32);
    const es = earlySecret(HkdfSha256, &psk);
    const bk = binderKey(HkdfSha256, es, &emptyHash());
    const binder = computeBinder(HkdfSha256, HmacSha256, bk, &rfc8448_binder_hash);
    try testing.expectEqualSlices(u8, &rfc8448_binder, &binder);
}

test "SHA-384 suite: chain runs at the 48-byte digest length and is internally consistent" {
    // RFC 8448 carries no SHA-384 resumption vector, so this asserts
    // internal consistency (derive -> verify round-trip) at the larger
    // digest length rather than a byte-exact external target — matching
    // dtls.keyschedule's "SHA-384 suite" test intent.
    const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
    const Hkdf384 = std.crypto.kdf.hkdf.Hkdf(HmacSha384);
    const Sha384 = std.crypto.hash.sha2.Sha384;
    try testing.expectEqual(@as(usize, 48), Hkdf384.prk_length);

    const rms = [_]u8{0x5A} ** 48;
    const nonce = [_]u8{ 0x00, 0x01 };
    const psk = derivePsk(Hkdf384, rms, &nonce, 48);
    const es = earlySecret(Hkdf384, &psk);
    var eh: [48]u8 = undefined;
    Sha384.hash("", &eh, .{});
    const bk = binderKey(Hkdf384, es, &eh);
    var th: [48]u8 = undefined;
    Sha384.hash("fake truncated client hello", &th, .{});
    const binder = computeBinder(Hkdf384, HmacSha384, bk, &th);
    try testing.expect(verifyBinder(Hkdf384, HmacSha384, bk, &th, binder));
    var bad = binder;
    bad[47] ^= 1;
    try testing.expect(!verifyBinder(Hkdf384, HmacSha384, bk, &th, bad));
}
