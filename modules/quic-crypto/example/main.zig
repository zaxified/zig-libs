// SPDX-License-Identifier: MIT

//! What a QUIC engine's Initial-packet send/receive path does with
//! `quic-crypto`: derive the client's Initial secret from a FRESH (non-RFC-
//! vector) Destination Connection ID, derive AES-128-GCM packet keys from it
//! (RFC 9001 §5.1/§5.2), AEAD-seal a payload (§5.3), apply header protection
//! on top (§5.4) to get the actual on-the-wire bytes, then run the receive
//! side in the opposite order — remove header protection (discovering the
//! packet-number length from the packet's OWN now-unmasked first byte, the
//! §5.4.1 ordering hazard) before the AEAD tag can even be checked — and
//! recover the original payload. Then a tampered wire packet is rejected by
//! NAME, and one RFC 9001 §6 key update is driven to show the header-
//! protection key (deliberately) does not change across it.
//!
//! This module owns no QUIC transport state: `client_dcid`, the header
//! bytes, the packet number and the payload are all supplied by the caller,
//! exactly as a real engine would supply them after its own header parsing.
//!
//! External oracle actually run (see the report, not restated here): the
//! derived key/iv and the AAD/payload below are FRESH (this connection ID is
//! not RFC 9001 Appendix A's `8394c8f03e515708`), so this is not a KAT
//! restatement. Python's `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
//! (OpenSSL-backed) recomputes `AESGCM(key).encrypt(nonce, payload, aad)` on
//! the exact printed key/nonce/aad/payload and reproduces the ciphertext+tag
//! this example computes, byte-for-byte — confirming the packet-protection
//! AEAD call independently of the module's own RFC 9001 KATs, on input the
//! KATs never cover.
//!
//! Every function used here (`deriveInitialSecrets`, `derivePacketKeys`,
//! `Protection(...).seal`/`.open`, `apply`/`remove`, `advanceKeys`) writes
//! into fixed-size arrays or caller-owned buffers and never allocates. There
//! is nothing for a `DebugAllocator` to catch here: this example holds no
//! heap allocation at all, by construction of the module it exercises.

const std = @import("std");
const qc = @import("quic-crypto");
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub fn main() !void {
    // A fresh, invented Destination Connection ID -- NOT RFC 9001 Appendix
    // A's `8394c8f03e515708`. Everything downstream (secrets, keys, masks)
    // therefore differs from every published KAT in this module.
    const client_dcid: [8]u8 = comptime hexN(8, "deadbeefcafebabe");

    const secrets = qc.deriveInitialSecrets(&client_dcid);
    // Initial-level packets are ALWAYS TLS_AES_128_GCM_SHA256 (RFC 9001
    // §5.2), regardless of whatever suite the handshake later negotiates.
    const client_keys = qc.derivePacketKeys(HkdfSha256, 16, secrets.client_initial_secret);
    std.debug.print("derived client Initial key/iv/hp from a fresh (non-vector) DCID\n", .{});

    // ── assemble an unprotected long-header Initial packet ────────────────
    //
    // 18-byte header prefix (first byte through the length varint) + a
    // 4-byte packet number field = the 22-byte `header` that `Protection.
    // seal` authenticates as additional data (RFC 9001 §5.3: "first header
    // byte through the unprotected packet number"). The first byte's low 2
    // bits (0b11) declare a 4-byte packet-number encoding -- a caller has to
    // get this bit-for-bit right for the receive side's length recovery
    // (below) to land on the same length the sender used.
    const header_prefix: [18]u8 = [_]u8{
        0xc3, // long header, fixed bit, Initial, pn_len-1 = 3 (=> 4-byte PN)
        0x00, 0x00, 0x00, 0x01, // version: QUIC v1
        0x08, // DCID length
    } ++ client_dcid ++ [_]u8{
        0x00, // SCID length: 0
        0x00, // Token length varint: 0
        0x40, 0x28, // Length varint (2-byte form): 4 (PN) + 24 (payload) + 16 (tag) = 44
    };
    const pn_offset = header_prefix.len; // 18: where the PN field starts

    const packet_number: u64 = 7;
    const pn_bytes: [4]u8 = comptime blk: {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(u32, &buf, 7, .big);
        break :blk buf;
    };
    const header: [22]u8 = header_prefix ++ pn_bytes; // the AEAD "header" AAD

    // A fresh (non-vector) 24-byte payload -- stand-in for a CRYPTO frame.
    const payload = "quic-crypto consumer-path demo payload!"[0..24];

    const P = qc.protection.Protection(Aes128Gcm);
    var ciphertext: [payload.len + P.tag_length]u8 = undefined;
    const ct_len = try P.seal(client_keys.key, client_keys.iv, packet_number, &header, payload, &ciphertext);
    std.debug.assert(ct_len == ciphertext.len);

    // Print everything the external oracle needs: key, the nonce
    // `Protection.nonce` derived internally (iv XOR left-pad(pn)), the AAD,
    // the plaintext, and the ciphertext+tag this module produced.
    const npub = P.nonce(client_keys.iv, packet_number);
    std.debug.print("key={x} nonce={x} aad={x} payload={x}\n", .{ client_keys.key, npub, header, payload.* });
    std.debug.print("ciphertext+tag={x}\n", .{ciphertext});

    // ── header protection: assemble the actual wire bytes ──────────────────
    //
    // Buffer sizing is the caller's job: the full wire packet is
    // `header.len + ciphertext.len` bytes, built here by hand with
    // `@memcpy` (not `++`, which is comptime-only and `ciphertext` is a
    // genuine runtime AEAD output).
    var wire_packet: [header.len + ciphertext.len]u8 = undefined;
    @memcpy(wire_packet[0..header.len], &header);
    @memcpy(wire_packet[header.len..], &ciphertext);

    // The header-protection sample is taken at `pn_offset + 4` (§5.4.2: the
    // PN is always treated as its maximum 4-byte length for sampling
    // purposes, regardless of its real on-wire length) -- which, for a
    // 4-byte PN, is exactly where the ciphertext begins.
    const sample: [16]u8 = ciphertext[0..16].*;
    const mask = qc.headerprot.computeMaskAes(&client_keys.hp, sample);
    try qc.headerprot.apply(&wire_packet, .long, pn_offset, 4, mask);
    std.debug.print("header protection applied: {d}-byte wire packet ready to send\n", .{wire_packet.len});

    // ── receive side: header protection comes off BEFORE the PN is even
    // known, then the AEAD tag is checked ──────────────────────────────────
    //
    // `remove` re-derives the SAME mask from the SAME (still-masked, but
    // unaffected by header protection) ciphertext sample, unmasks the first
    // byte, reads `pn_len` from its now-cleartext low 2 bits, and only then
    // unmasks that many PN bytes -- the §5.4.1 ordering hazard the module
    // doc calls out. A receiver that unmasked the PN bytes using a
    // still-masked `pn_len` would corrupt the wrong number of bytes.
    var recv_packet = wire_packet; // a fresh copy: `remove` mutates in place
    const recv_sample: [16]u8 = recv_packet[pn_offset + 4 ..][0..16].*;
    const recv_mask = qc.headerprot.computeMaskAes(&client_keys.hp, recv_sample);
    const removed = try qc.headerprot.remove(&recv_packet, .long, pn_offset, recv_mask);
    std.debug.assert(removed.pn_len == 4);

    const recovered_pn = std.mem.readInt(u32, recv_packet[pn_offset..][0..4], .big);
    std.debug.assert(recovered_pn == packet_number);
    std.debug.print("header protection removed: recovered pn_len={d}, packet_number={d}\n", .{ removed.pn_len, recovered_pn });

    const recv_header = recv_packet[0 .. pn_offset + 4];
    const recv_ciphertext = recv_packet[pn_offset + 4 ..];
    var opened: [payload.len]u8 = undefined;
    const n = try P.open(client_keys.key, client_keys.iv, recovered_pn, recv_header, recv_ciphertext, &opened);
    try std.testing.expectEqualStrings(payload, opened[0..n]);
    std.debug.print("AEAD open: recovered the original {d}-byte payload\n", .{n});

    // ── negative path: a tampered wire packet -> DecryptionFailed ─────────
    //
    // Corrupt the LAST byte of the still-protected wire packet (inside the
    // AEAD tag, which header protection never touches) before running the
    // exact same receive-side steps.
    var tampered_packet = wire_packet;
    tampered_packet[tampered_packet.len - 1] ^= 0x01;
    const t_sample: [16]u8 = tampered_packet[pn_offset + 4 ..][0..16].*;
    const t_mask = qc.headerprot.computeMaskAes(&client_keys.hp, t_sample);
    const t_removed = try qc.headerprot.remove(&tampered_packet, .long, pn_offset, t_mask);
    std.debug.assert(t_removed.pn_len == 4);
    const t_pn = std.mem.readInt(u32, tampered_packet[pn_offset..][0..4], .big);
    var discard: [payload.len]u8 = undefined;
    if (P.open(client_keys.key, client_keys.iv, t_pn, tampered_packet[0 .. pn_offset + 4], tampered_packet[pn_offset + 4 ..], &discard)) |_| {
        unreachable; // a flipped tag byte cannot survive AEAD verification
    } else |err| switch (err) {
        error.DecryptionFailed => std.debug.print("tampered wire packet: open -> DecryptionFailed (expected)\n", .{}),
        else => return err,
    }

    // ── key update (§6): hp is deliberately NOT re-derived ────────────────
    const ku = qc.advanceKeys(HkdfSha256, 16, secrets.client_initial_secret);
    std.debug.assert(!@hasField(@TypeOf(ku), "hp"));
    std.debug.assert(!std.mem.eql(u8, &ku.key, &client_keys.key)); // key DID change
    std.debug.print("key update: new key/iv derived; hp field absent by type (unchanged per RFC 9001 §6.1)\n", .{});
}

fn hexN(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
