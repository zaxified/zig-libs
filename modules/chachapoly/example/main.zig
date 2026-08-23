// SPDX-License-Identifier: MIT

//! What a WireGuard/TLS-record-style consumer does with `chachapoly`: seal a
//! fresh, multi-block payload with associated data under ChaCha20-Poly1305,
//! open it back, and reject a tampered tag by NAME — with a check that the
//! module's stronger "`m` is always zeroed on auth failure" promise (it
//! deliberately does more than std does here, per the module doc comment)
//! actually holds, not just that an error is returned.
//!
//! This message+AD combination is 100+34 = 134 bytes, above both
//! `delegate_max_bytes` (64) and `aead_delegate_max` (128), so this run
//! exercises the module's OWN SIMD wide path, not std's delegated short-input
//! path — the two engines the module doc's `chacha_path`/`aead_path`
//! witnesses distinguish.
//!
//! External oracle actually run (see the report): Python's `cryptography`
//! package (`ChaCha20Poly1305`, OpenSSL-backed) on this exact fresh key/
//! nonce/AD/plaintext (none of it drawn from the module's own RFC 8439 §2.8.2
//! test vector) reproduces the `expected_ct`/`expected_tag` bytes below
//! byte-for-byte — checked by the `std.debug.assert`s right after `encrypt`,
//! so a regression here fails the example, not just a comment.
//!
//! `ChaCha20.xor`/`ChaCha20Poly1305.encrypt`/`.decrypt` never allocate —
//! every buffer below is caller-owned and sized by hand (`m.len` for the
//! cipher, `+ tag_length` for the AEAD). There is nothing for a
//! `DebugAllocator` to catch here: this example holds no heap allocation at
//! all, by construction of the module it exercises.

const std = @import("std");
const chachapoly = @import("chachapoly");
const ChaCha20Poly1305 = chachapoly.ChaCha20Poly1305;

pub fn main() !void {
    // Fresh throwaway key/nonce/AD/plaintext — invented for this example,
    // NOT copied from the module's RFC 8439 §2.8.2 KAT. Independently
    // reproduced with Python's `cryptography.hazmat.primitives.ciphers.aead.
    // ChaCha20Poly1305` while authoring this file (see module doc above).
    const key = hexN(32, "9e1122339e1122339e1122339e1122339e1122339e1122339e1122339e112233");
    const nonce = hexN(12, "0102030405060708090a0b0c");
    const ad = "zig-libs chachapoly example AAD v1";
    const m = "Consumer-path plaintext spanning more than one ChaCha20 block boundary for a realistic AEAD example.";

    // `cryptography`'s ciphertext+tag for the exact same key/nonce/ad/m — the
    // external oracle this example checks against, not a value this module
    // computed for itself.
    const expected_ct = hexN(100, "c07f5b40ee5905334cecce5c33dee6409b803184b83f77c3b835f399583539" ++
        "a7a6dbc4e8a03cdac5af1747d653e92c1546efedcc7e83a932028ea7a98f5e6" ++
        "332815702067a44c44099b45b89212952664b51fec170a130aa916e8e1df5a" ++
        "c00bf80152e95");
    const expected_tag = hexN(16, "56ff52ecc40abd2d7f1904f83499df17");

    // Buffer sizing is the caller's job: ciphertext is exactly `m.len`
    // (ChaCha20 is a stream cipher, no expansion) and the tag is a fixed
    // `tag_length` (16) written separately, not appended by `encrypt` itself
    // — a caller composing a wire format decides that layout, this module
    // doesn't impose one.
    var ct: [m.len]u8 = undefined;
    var tag: [ChaCha20Poly1305.tag_length]u8 = undefined;
    ChaCha20Poly1305.encrypt(&ct, &tag, m, ad, nonce, key);
    std.debug.assert(std.mem.eql(u8, &expected_ct, &ct));
    std.debug.assert(std.mem.eql(u8, &expected_tag, &tag));
    std.debug.print("encrypt: byte-exact match against the independent OpenSSL-backed ChaCha20-Poly1305 oracle\n", .{});

    var opened: [m.len]u8 = undefined;
    try ChaCha20Poly1305.decrypt(&opened, &ct, tag, ad, nonce, key);
    try std.testing.expectEqualStrings(m, &opened);
    std.debug.print("decrypt: recovered the original {d}-byte message\n", .{m.len});

    // ── negative path: tampered tag -> AuthenticationFailed, `m` zeroed ────
    //
    // The awkward part a consumer must know without it being in the type
    // signature: std's own AEAD documents its output buffer as merely
    // "undefined" on a rejected `decrypt` (and implements that as a
    // `@memset(m, undefined)` hint the optimizer is free to elide in
    // ReleaseFast — a caller's pre-loaded bytes can survive). This module
    // makes the STRONGER promise that `m` is actually, unconditionally
    // zeroed via `std.crypto.secureZero`, in every build mode. Prove it by
    // pre-poisoning the output buffer before the call, not just checking the
    // error.
    var bad_tag = tag;
    bad_tag[0] ^= 0x01;
    var poisoned: [m.len]u8 = [_]u8{0xAA} ** m.len;
    if (ChaCha20Poly1305.decrypt(&poisoned, &ct, bad_tag, ad, nonce, key)) |_| {
        unreachable; // a flipped tag byte cannot survive constant-time comparison
    } else |err| switch (err) {
        error.AuthenticationFailed => {
            std.debug.print("tampered tag: decrypt -> AuthenticationFailed (expected)\n", .{});
            const all_zero = for (poisoned) |b| {
                if (b != 0) break false;
            } else true;
            std.debug.assert(all_zero); // stronger-than-std promise: m is really zeroed
            std.debug.print("output buffer zeroed on failure (stronger than std's 'undefined'): confirmed\n", .{});
        },
    }

    // ── the associated data is authenticated but never encrypted ──────────
    //
    // A caller who forgets this and expects `ad` to be confidential (rather
    // than just tamper-evident) has misused the primitive. Prove the
    // boundary: changing `ad` alone, with the correct tag for the ORIGINAL
    // ad, also fails to open — `ad` is covered by the tag exactly like `m`
    // is, even though it never passes through the cipher.
    if (ChaCha20Poly1305.decrypt(&opened, &ct, tag, "different AAD, same length!!!!!!!!", nonce, key)) |_| {
        unreachable;
    } else |err| switch (err) {
        error.AuthenticationFailed => std.debug.print("wrong AD (correct tag, correct ct): AuthenticationFailed (expected)\n", .{}),
    }
}

fn hexN(comptime n: usize, comptime s: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
