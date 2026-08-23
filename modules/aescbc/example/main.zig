// SPDX-License-Identifier: MIT

//! What a `jwe`/`xmlenc`-style consumer does with `aescbc`: pad a fresh
//! (non-block-aligned) plaintext with PKCS#7, encrypt under AES-256-CBC,
//! decrypt and unpad it back, and reject a bit-flipped ciphertext by NAME
//! rather than silently returning garbage. Then a second, shorter pass shows
//! why the module ships TWO unpad functions instead of one: the same
//! decrypted buffer is valid XML-Enc padding but NOT valid PKCS#7 padding,
//! because XML-Enc only constrains the final length byte.
//!
//! External oracle actually run (see the report, not restated here): `openssl
//! enc -aes-256-cbc -K <key> -iv <iv>` on this exact fresh key/iv/plaintext
//! (none of it drawn from the module's own NIST SP800-38A test vectors)
//! reproduces the `expected_ct` bytes below byte-for-byte — this is checked
//! by the `std.debug.assert` right after `encrypt`, so a regression here
//! fails the example, not just a comment.
//!
//! `aescbc.encrypt`/`decrypt`/`padPkcs7`/`unpadPkcs7`/`unpadXmlEnc` never
//! allocate — every buffer below is caller-owned and stack-sized by the
//! functions this module exports (`paddedLenPkcs7`, `block_len`). There is
//! nothing for a `DebugAllocator` to catch here: this example holds no heap
//! allocation at all, by construction of the module it exercises.

const std = @import("std");
const aescbc = @import("aescbc");
const Aes256 = std.crypto.core.aes.Aes256;

pub fn main() !void {
    // Fresh throwaway key/IV/plaintext — invented for this example, NOT
    // copied from the module's NIST SP800-38A KATs. Independently reproduced
    // with `openssl enc -aes-256-cbc -K <key> -iv <iv> -nosalt` while
    // authoring this file (see the module doc comment above).
    const key = hex32("5f2e9a3c714b8d06f19e2b7c4a8d3f605e1c9b7a4f2d8e6c3b1a9f7e5d3c1b09");
    const iv = hex16("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
    const msg = "The quick brown fox jumps over the lazy zig gopher, 2026 edition.";
    // openssl's ciphertext for the exact same key/iv/msg (PKCS#7 padding is
    // openssl's default for `enc`) — the external oracle this example checks
    // against, not a value this module computed for itself.
    const expected_ct = hex80("0a9829ddbe7912c1f7425ba7378e3634da15c0f11b3c59a41eaeda1b26a584d" ++
        "3c976ed078706d96e9b8fb4434109c3c9473c24dea7430c337faecce0320d22" ++
        "79dc1f2b2c9f0271557a052afeb821f451");

    // Buffer sizing is the caller's job: `paddedLenPkcs7` tells you exactly
    // how much room `padPkcs7` needs (msg.len=65 -> 80, one full pad block
    // beyond the 4 whole blocks msg already fills).
    const padded_len = aescbc.paddedLenPkcs7(msg.len);
    std.debug.assert(padded_len == 80);
    var padded: [80]u8 = undefined;
    const n = try aescbc.padPkcs7(msg, &padded);
    std.debug.assert(n == padded_len);

    // Encrypt the padded buffer in place-sized output; ciphertext length
    // equals the padded plaintext length for CBC (no further expansion).
    var ct: [80]u8 = undefined;
    _ = try aescbc.encrypt(Aes256, key, iv, &padded, &ct);
    std.debug.assert(std.mem.eql(u8, &expected_ct, &ct));
    std.debug.print("encrypt: byte-exact match against openssl's independent AES-256-CBC ciphertext\n", .{});

    // Decrypt + unpad recovers the original message.
    var pt: [80]u8 = undefined;
    _ = try aescbc.decrypt(Aes256, key, iv, &ct, &pt);
    const unpadded_len = try aescbc.unpadPkcs7(&pt);
    try std.testing.expectEqualStrings(msg, pt[0..unpadded_len]);
    std.debug.print("decrypt+unpad: recovered original {d}-byte message\n", .{unpadded_len});

    // Tamper: flip the LAST byte of the second-to-last ciphertext block
    // (index 3*block_len + block_len-1 = 63). Raw CBC has no MAC, so
    // `decrypt` itself still "succeeds" — but the CBC XOR chain propagates
    // that flip into the pad-length byte of the FINAL decrypted block, which
    // `unpadPkcs7` must then reject by name. This is deterministic, not
    // probabilistic: flipping ciphertext block N-2's last byte flips
    // plaintext block N-1's last byte by the same XOR delta (P[N-1] =
    // D(C[N-1]) XOR C[N-2]), and the original pad byte here is 0x0F (15) with
    // 15 matching trailing bytes — a single-bit change to the length byte
    // alone can never leave all 14 remaining check bytes still matching.
    var tampered = ct;
    tampered[3 * aescbc.block_len + aescbc.block_len - 1] ^= 0x01;
    var tampered_pt: [80]u8 = undefined;
    _ = try aescbc.decrypt(Aes256, key, iv, &tampered, &tampered_pt);
    if (aescbc.unpadPkcs7(&tampered_pt)) |_| {
        unreachable; // the bit-flip analysis above guarantees rejection
    } else |err| switch (err) {
        error.InvalidPadding => std.debug.print("tampered ciphertext: unpadPkcs7 -> InvalidPadding (expected)\n", .{}),
    }

    // ── XML-Enc vs PKCS#7: why this module ships two unpad functions ──────
    //
    // Build a block whose LAST byte is a valid length (4) but whose
    // preceding pad bytes are garbage rather than all equal to 4. This is
    // valid XML-Enc padding (only the final byte is meaningful) but invalid
    // PKCS#7 padding (every pad byte must equal the length) — the exact
    // distinction a caller porting between `jwe` (PKCS#7) and `xmlenc`
    // (XML-Enc) has to get right, and the reason picking the wrong unpad
    // helper for the wire format you actually have is a real defect class.
    var xmlenc_block = [_]u8{0} ** aescbc.block_len;
    xmlenc_block[aescbc.block_len - 1] = 4; // length byte: valid for both schemes
    xmlenc_block[aescbc.block_len - 2] = 0xAA; // arbitrary — legal under XML-Enc only
    xmlenc_block[aescbc.block_len - 3] = 0x00;
    xmlenc_block[aescbc.block_len - 4] = 0xFF;

    const xml_n = try aescbc.unpadXmlEnc(&xmlenc_block);
    std.debug.print("unpadXmlEnc on arbitrary-non-final-byte padding: accepted, {d} plaintext bytes\n", .{xml_n});

    if (aescbc.unpadPkcs7(&xmlenc_block)) |_| {
        unreachable; // pad bytes 0xAA/0x00/0xFF don't equal the length byte 4
    } else |err| switch (err) {
        error.InvalidPadding => std.debug.print("same buffer via unpadPkcs7: InvalidPadding (expected -- not PKCS#7-shaped)\n", .{}),
    }
}

fn hex32(comptime s: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
fn hex16(comptime s: []const u8) [16]u8 {
    var out: [16]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
fn hex80(comptime s: []const u8) [80]u8 {
    var out: [80]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
