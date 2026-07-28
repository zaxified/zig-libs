// SPDX-License-Identifier: MIT

//! quic-crypto.headerprot — RFC 9001 §5.4 header protection: the QUIC-specific
//! masking of the first-byte low bits and the Packet Number field, applied on
//! top of packet protection (§5.3) using a 16-byte ciphertext SAMPLE and a
//! `hp` key that never changes across key updates (§6.1). Engine-agnostic:
//! the caller supplies the packet bytes, the `hp` key, the sample, and the
//! packet-number offset — no packet parsing here beyond the first byte's low
//! bits.
//!
//! **Implemented and KAT-validated** against RFC 9001 Appendix A.2/A.3/A.5:
//! the `sanity` tests drive the mask + XOR through `std.crypto` directly
//! (independent oracle), and the API tests drive the same vectors through
//! `computeMask*`/`apply`/`remove` byte-exact — including the receive-side
//! pn_len recovery and the apply/remove round-trip.
//!
//! **Mirrors `dtls/src/aead.zig`'s `encryptSequenceNumberAes`
//! (`AES-ECB(key, sample)`) and `encryptSequenceNumberChaCha20`
//! (`ChaCha20(key, counter=sample[0..4] LE, nonce=sample[4..16])` of zero
//! bytes)** — the SAME two mask primitives. The QUIC variant differs in the
//! XOR STEP: DTLS §4.2.3 masks only the on-wire sequence-number bytes; QUIC
//! §5.4 ALSO masks the low bits of the packet's FIRST byte (4 bits for a long
//! header, 5 for a short header — `mask[0] & 0x0f` / `& 0x1f`) and the
//! packet-number bytes are a VARIABLE 1..4 length. No dtls code is imported
//! or copied (deps `.{}`, std-only); re-expressed QUIC-shaped — see
//! SPEC.md/NOTICE.
//!
//! **The receive-side ordering hazard (§5.4.1).** On `apply` (send) the PN
//! length is known. On `remove` (receive) it is NOT — the low 2 bits of the
//! first byte that encode `pn_length = (first_byte & 0x03) + 1` are
//! THEMSELVES masked. So `remove` MUST: (1) unmask the first byte, (2) read
//! `pn_length` from its now-cleartext low 2 bits, (3) unmask exactly that
//! many PN bytes. `apply` and `remove` are otherwise the same XOR
//! (self-inverse), differing only in this ordering; getting it wrong yields
//! a wrong PN and a downstream AEAD-open failure.

const std = @import("std");

pub const HeaderProtectionError = error{
    /// The 16-byte sample window would run past the end of the packet.
    SampleTooShort,
    /// The masked packet-number length (1..4) would run past the packet end.
    PacketTooShort,
};

/// RFC 9001 §5.4: whether the packet uses a long or short header — selects
/// how many low bits of the first byte are masked (long = 4, short = 5) and
/// is derivable from the first byte's high bit (`0x80` set = long header,
/// per RFC 9000). Carried explicitly so this module never needs to parse a
/// full header.
pub const HeaderForm = enum { long, short };

/// The 5-byte header-protection mask RFC 9001 §5.4.1 XORs into the header.
/// `mask[0]`'s low bits go into the first byte; `mask[1..1+pn_len]` into the
/// packet-number bytes (unused mask bytes for a <4-byte PN are discarded).
pub const Mask = [5]u8;

/// RFC 9001 §5.4.3, AES suites (AEAD_AES_128_GCM / AEAD_AES_256_GCM):
/// `mask = AES-ECB(hp_key, sample)`, first 5 bytes. `hp_key` is 16 (AES-128)
/// or 32 (AES-256) bytes; `sample` is the 16-byte ciphertext window.
///
/// Mirrors `dtls.aead.encryptSequenceNumberAes`'s single-block
/// `std.crypto.core.aes.Aes128/Aes256.initEnc(key).encrypt(...)` — same
/// AES-ECB primitive; QUIC keeps 5 mask bytes (vs DTLS's 2).
pub fn computeMaskAes(hp_key: []const u8, sample: [16]u8) Mask {
    var block: [16]u8 = undefined;
    switch (hp_key.len) {
        16 => std.crypto.core.aes.Aes128.initEnc(hp_key[0..16].*).encrypt(&block, &sample),
        32 => std.crypto.core.aes.Aes256.initEnc(hp_key[0..32].*).encrypt(&block, &sample),
        else => unreachable, // hp_key length is fixed by the negotiated suite
    }
    return block[0..5].*;
}

/// RFC 9001 §5.4.4, ChaCha20 suite (AEAD_CHACHA20_POLY1305):
/// `mask = ChaCha20(hp_key, counter = sample[0..4] little-endian,
/// nonce = sample[4..16], plaintext = 5 zero bytes)`. `hp_key` is 32 bytes.
///
/// Mirrors `dtls.aead.encryptSequenceNumberChaCha20`'s
/// `std.crypto.stream.chacha.ChaCha20IETF.stream(...)` with the counter from
/// `sample[0..4]` LE and nonce from `sample[4..16]` — same primitive; QUIC
/// keeps 5 keystream bytes.
pub fn computeMaskChaCha20(hp_key: []const u8, sample: [16]u8) Mask {
    std.debug.assert(hp_key.len == 32);
    const counter = std.mem.readInt(u32, sample[0..4], .little);
    const chacha_nonce: [12]u8 = sample[4..16].*;
    var keystream: [5]u8 = [_]u8{0} ** 5;
    std.crypto.stream.chacha.ChaCha20IETF.stream(&keystream, counter, hp_key[0..32].*, chacha_nonce);
    return keystream;
}

/// RFC 9001 §5.4.1, SEND side (PN length known): apply `mask` to `packet` in
/// place. `pn_offset` is the byte index where the Packet Number field starts;
/// `pn_len` is its on-wire length (1..4). For `form == .long`,
/// `packet[0] ^= mask[0] & 0x0f`; for `.short`, `& 0x1f`. Then
/// `packet[pn_offset + i] ^= mask[1 + i]` for `i in 0..pn_len`.
///
/// The mask is `computeMaskAes`/`computeMaskChaCha20` of the sample taken at
/// `pn_offset + 4` (§5.4.2 — the PN is treated as its maximum 4-byte length
/// for sampling regardless of its real length).
pub fn apply(
    packet: []u8,
    form: HeaderForm,
    pn_offset: usize,
    pn_len: usize,
    mask: Mask,
) HeaderProtectionError!void {
    std.debug.assert(pn_len >= 1 and pn_len <= 4);
    if (packet.len == 0 or pn_offset > packet.len or pn_len > packet.len - pn_offset)
        return error.PacketTooShort;
    packet[0] ^= mask[0] & firstByteMask(form);
    for (0..pn_len) |i| packet[pn_offset + i] ^= mask[1 + i];
}

/// The number of packet-number bytes `remove` unmasked (1..4), returned so
/// the caller knows the field length for packet-number reconstruction.
pub const Removed = struct { pn_len: usize };

/// RFC 9001 §5.4.1, RECEIVE side (PN length UNKNOWN until the first byte is
/// unmasked). Models the §5.4.1 ordering hazard:
///   1. unmask the first byte (`packet[0] ^= mask[0] & 0x0f`/`0x1f`),
///   2. read `pn_len = (packet[0] & 0x03) + 1` from the now-cleartext low bits,
///   3. unmask exactly `pn_len` packet-number bytes.
/// `mask` is computed from the sample at `pn_offset + 4` (the sample is
/// taken BEFORE any unmasking — it is ciphertext). Returns the recovered
/// `pn_len`. XOR is self-inverse, so the only difference from `apply` is that
/// `pn_len` is discovered here rather than supplied.
pub fn remove(
    packet: []u8,
    form: HeaderForm,
    pn_offset: usize,
    mask: Mask,
) HeaderProtectionError!Removed {
    if (packet.len == 0) return error.PacketTooShort;
    // 1. Unmask the first byte — the PN-length bits are still masked before
    //    this step, so it MUST come first (the §5.4.1 ordering hazard).
    packet[0] ^= mask[0] & firstByteMask(form);
    // 2. Only NOW are the low 2 bits cleartext; read the PN length.
    const pn_len: usize = @as(usize, packet[0] & 0x03) + 1;
    // 3. Unmask exactly that many PN bytes.
    if (pn_offset > packet.len or pn_len > packet.len - pn_offset) {
        packet[0] ^= mask[0] & firstByteMask(form); // restore — fail atomically
        return error.PacketTooShort;
    }
    for (0..pn_len) |i| packet[pn_offset + i] ^= mask[1 + i];
    return .{ .pn_len = pn_len };
}

/// RFC 9001 §5.4.1: how many low bits of the first byte are protected —
/// 4 for a long header (`0x0f`), 5 for a short header (`0x1f`, which also
/// covers the Key Phase bit).
fn firstByteMask(form: HeaderForm) u8 {
    return switch (form) {
        .long => 0x0f,
        .short => 0x1f,
    };
}

// ── tests ────────────────────────────────────────────────────────────────
//
// RFC 9001 Appendix A.2 (client Initial, long header, AES-ECB mask, 4-byte
// PN), A.3 (server Initial, long header, 2-byte PN), A.5 (short header,
// ChaCha20 mask, 3-byte PN). Every hex constant was extracted verbatim from
// https://www.rfc-editor.org/rfc/rfc9001.txt and cross-checked against the
// `cryptography` package (AES-ECB / raw ChaCha20) before commit.

const testing = std.testing;

// ── fuzz: `remove` (receive-side header unprotection), never panic ────────
//
// `remove` is the very first thing this repo's QUIC stack would do to a
// packet off the wire — BEFORE the AEAD tag is checked (packet protection
// removal, §5.3, comes after header protection removal, §5.4). Every byte
// `remove` touches (`packet`, `pn_offset`) is attacker-controlled at that
// point: `pn_offset` is derived from the long/short header's own
// (also-unauthenticated) connection-ID length field. The self-discovered
// `pn_len` (read from the packet's own first byte AFTER this function
// unmasks it) is exactly the kind of "attacker picks the field width" input
// this harness is built to reach — a fixed `pn_offset` alone would only ever
// exercise 4 of the 4 possible `pn_len` values by luck; here `pn_offset` is
// fuzzed too so short/zero-length PN windows and windows that hang off the
// end of `packet` are both hit deliberately.

test "fuzz: remove never panics on arbitrary packet bytes / offsets / masks" {
    try testing.fuzz({}, fuzzRemove, .{});
}

fn fuzzRemove(_: void, smith: *std.testing.Smith) !void {
    var packet: [64]u8 = undefined;
    smith.bytes(&packet);
    const len: usize = smith.valueRangeAtMost(u8, 0, packet.len);

    const form: HeaderForm = if (smith.value(bool)) .long else .short;
    // pn_offset is deliberately allowed to range past packet.len (an
    // attacker-controlled connection-ID length field can claim anything).
    const pn_offset: usize = smith.valueRangeAtMost(u16, 0, packet.len + 8);

    var mask: Mask = undefined;
    smith.bytes(&mask);

    _ = remove(packet[0..len], form, pn_offset, mask) catch {};
}

fn hexTo(comptime n: usize, s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// App. A.2 client Initial (long header): hp key, 16-byte sample, first 5
// mask bytes, unprotected header, protected (post-apply) header. PN length 4,
// pn_offset 18 (the header is 22 bytes: 18 header bytes + 4 PN bytes).
const rfc_client_hp = hexTo(16, "9f50449e04a0e810283a1e9933adedd2");
const rfc_client_sample = hexTo(16, "d1b1c98dd7689fb8ec11d242b123dc9b");
const rfc_client_mask = hexTo(5, "437b9aec36");
const rfc_client_header_plain = hexTo(22, "c300000001088394c8f03e5157080000449e00000002");
const rfc_client_header_prot = hexTo(22, "c000000001088394c8f03e5157080000449e7b9aec34");

// App. A.3 server Initial (long header): 2-byte PN, pn_offset 18 (header 20
// bytes = 18 + 2 PN).
const rfc_server_hp = hexTo(16, "c206b8d9b9f0f37644430b490eeaa314");
const rfc_server_sample = hexTo(16, "2cd0991cd25b0aac406a5816b6394100");
const rfc_server_mask = hexTo(5, "2ec0d8356a");
const rfc_server_header_plain = hexTo(20, "c1000000010008f067a5502a4262b50040750001");
const rfc_server_header_prot = hexTo(20, "cf000000010008f067a5502a4262b5004075c0d9");

// App. A.5 short header: ChaCha20 mask, 3-byte PN, pn_offset 1 (empty DCID,
// header 4 bytes = 1 + 3 PN).
const rfc_a5_hp = hexTo(32, "25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4");
const rfc_a5_sample = hexTo(16, "5e5cd55c41f69080575d7999c25a5bfb");
const rfc_a5_mask = hexTo(5, "aefefe7d03");
const rfc_a5_header_plain = hexTo(4, "4200bff4");
const rfc_a5_header_prot = hexTo(4, "4cfe4189");

fn aesEcbMask5(hp: [16]u8, sample: [16]u8) [5]u8 {
    var block: [16]u8 = undefined;
    std.crypto.core.aes.Aes128.initEnc(hp).encrypt(&block, &sample);
    return block[0..5].*;
}

test "sanity: App. A.2/A.3 AES-ECB mask matches RFC (std.crypto directly)" {
    try testing.expectEqualSlices(u8, &rfc_client_mask, &aesEcbMask5(rfc_client_hp, rfc_client_sample));
    try testing.expectEqualSlices(u8, &rfc_server_mask, &aesEcbMask5(rfc_server_hp, rfc_server_sample));
}

test "sanity: App. A.5 ChaCha20 mask matches RFC (std.crypto directly)" {
    const counter = std.mem.readInt(u32, rfc_a5_sample[0..4], .little);
    const chacha_nonce: [12]u8 = rfc_a5_sample[4..16].*;
    var keystream: [5]u8 = [_]u8{0} ** 5;
    std.crypto.stream.chacha.ChaCha20IETF.stream(&keystream, counter, rfc_a5_hp, chacha_nonce);
    try testing.expectEqualSlices(u8, &rfc_a5_mask, &keystream);
}

test "sanity: App. A.2 long-header apply (4 first-byte bits, 4 PN bytes) matches RFC" {
    var pkt = rfc_client_header_plain;
    pkt[0] ^= rfc_client_mask[0] & 0x0f; // long header: 4 bits
    inline for (0..4) |i| pkt[18 + i] ^= rfc_client_mask[1 + i];
    try testing.expectEqualSlices(u8, &rfc_client_header_prot, &pkt);
}

test "sanity: App. A.3 long-header apply (2 PN bytes) matches RFC" {
    var pkt = rfc_server_header_plain;
    pkt[0] ^= rfc_server_mask[0] & 0x0f;
    inline for (0..2) |i| pkt[18 + i] ^= rfc_server_mask[1 + i];
    try testing.expectEqualSlices(u8, &rfc_server_header_prot, &pkt);
}

test "sanity: App. A.5 short-header apply (5 first-byte bits, 3 PN bytes) matches RFC" {
    var pkt = rfc_a5_header_plain;
    pkt[0] ^= rfc_a5_mask[0] & 0x1f; // short header: 5 bits
    inline for (0..3) |i| pkt[1 + i] ^= rfc_a5_mask[1 + i];
    try testing.expectEqualSlices(u8, &rfc_a5_header_prot, &pkt);
}

test "sanity: receive-side ordering — pn_len read from unmasked first byte (App. A.5)" {
    // Prove the §5.4.1 hazard: unmask the first byte, THEN the low 2 bits
    // give pn_len. For A.5 the protected first byte is 0x4c; unmasking with
    // (mask[0] & 0x1f) restores 0x42, whose low 2 bits => pn_len 3.
    var first = rfc_a5_header_prot[0];
    first ^= rfc_a5_mask[0] & 0x1f;
    try testing.expectEqual(@as(u8, 0x42), first);
    try testing.expectEqual(@as(usize, 3), (first & 0x03) + 1);
}

test "computeMaskAes: App. A.2 client + A.3 server" {
    try testing.expectEqualSlices(u8, &rfc_client_mask, &computeMaskAes(&rfc_client_hp, rfc_client_sample));
    try testing.expectEqualSlices(u8, &rfc_server_mask, &computeMaskAes(&rfc_server_hp, rfc_server_sample));
    // AES-256 dispatch: no published RFC vector, so prove structurally that a
    // 32-byte hp key routes to Aes256 (differs from Aes128 of the same low half).
    var hp32: [32]u8 = undefined;
    for (&hp32, 0..) |*b, i| b.* = @intCast(i);
    const m256 = computeMaskAes(&hp32, rfc_client_sample);
    const m128 = computeMaskAes(hp32[0..16], rfc_client_sample);
    try testing.expect(!std.mem.eql(u8, &m256, &m128));
}

test "computeMaskChaCha20: App. A.5" {
    try testing.expectEqualSlices(u8, &rfc_a5_mask, &computeMaskChaCha20(&rfc_a5_hp, rfc_a5_sample));
}

test "apply: App. A.2 long + A.3 long + A.5 short header byte-exact" {
    var client = rfc_client_header_plain;
    try apply(&client, .long, 18, 4, rfc_client_mask);
    try testing.expectEqualSlices(u8, &rfc_client_header_prot, &client);

    var server = rfc_server_header_plain;
    try apply(&server, .long, 18, 2, rfc_server_mask);
    try testing.expectEqualSlices(u8, &rfc_server_header_prot, &server);

    var short = rfc_a5_header_plain;
    try apply(&short, .short, 1, 3, rfc_a5_mask);
    try testing.expectEqualSlices(u8, &rfc_a5_header_prot, &short);

    // PN field running past the packet end is a typed error, not a panic.
    var tiny = [_]u8{ 0xc3, 0x00 };
    try testing.expectError(error.PacketTooShort, apply(&tiny, .long, 1, 4, rfc_client_mask));
}

test "remove: App. A.5 recovers pn_len 3 + plaintext header; round-trips with apply" {
    // The ordering hazard, end to end: the protected first byte is 0x4c, whose
    // low 2 bits (0b00 => pn_len 1) are WRONG until unmasked; remove must
    // unmask byte 0 first, discover pn_len 3 from the cleartext 0x42, then
    // unmask exactly 3 PN bytes.
    var pkt = rfc_a5_header_prot;
    const r = try remove(&pkt, .short, 1, rfc_a5_mask);
    try testing.expectEqual(@as(usize, 3), r.pn_len);
    try testing.expectEqualSlices(u8, &rfc_a5_header_plain, &pkt);

    // Self-inverse round-trip: apply puts the protection back.
    try apply(&pkt, .short, 1, r.pn_len, rfc_a5_mask);
    try testing.expectEqualSlices(u8, &rfc_a5_header_prot, &pkt);

    // A.2 long header too: pn_len 4 recovered from the unmasked first byte.
    var long = rfc_client_header_prot;
    const rl = try remove(&long, .long, 18, rfc_client_mask);
    try testing.expectEqual(@as(usize, 4), rl.pn_len);
    try testing.expectEqualSlices(u8, &rfc_client_header_plain, &long);

    // Discovered PN running past the packet end fails atomically (typed
    // error, first byte restored to its protected value).
    var tiny = [_]u8{rfc_a5_header_prot[0]};
    try testing.expectError(error.PacketTooShort, remove(&tiny, .short, 1, rfc_a5_mask));
    try testing.expectEqual(rfc_a5_header_prot[0], tiny[0]);
}
