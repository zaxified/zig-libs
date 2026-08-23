// SPDX-License-Identifier: MIT

//! What a Bitcoin-address-derivation-style consumer does with `ripemd160`:
//! hash a fresh, multi-block payload through the STREAMING `update` path in
//! deliberately awkward (37-byte, non-block-divisor) chunks, confirm that
//! agrees byte-exact with the one-shot `hash` AND with an external oracle,
//! then compose `hash160` (`RIPEMD160(SHA256(x))`) over a fresh
//! compressed-pubkey-shaped input the same way `wif`/P2PKH address derivation
//! would.
//!
//! `ripemd160`'s public surface (`init`/`update`/`final`/`hash`/`hash160`) is
//! genuinely infallible — every function returns `void`, there is no error
//! set anywhere in this module, and no input byte sequence is invalid for a
//! hash function. Per CONVENTIONS.md §7.2 ("exercise the effects instead of
//! inventing a failure" — the same carve-out already used for `ramcache`/
//! `liveness-hyst`/`isis-dis`), this example has no named-error negative
//! case to assert; what it proves instead is that two independently-coded
//! call paths (streaming vs. one-shot) produce the identical output, and that
//! output matches a completely independent implementation (openssl).
//!
//! External oracles actually run (see the report): `openssl dgst -rmd160` on
//! this exact fresh 294-byte message, and `openssl dgst -sha256 -binary |
//! openssl dgst -rmd160` (the same SHA256-then-RIPEMD160 chain `hash160`
//! implements) on a fresh 33-byte compressed-pubkey-shaped input — neither
//! drawn from the module's own KATs. Both checked with `std.debug.assert`
//! right after the corresponding call, so a regression fails the example.
//!
//! `Ripemd160`/`hash160` never allocate — the streaming state is a fixed-size
//! struct and every digest is a fixed-size array. There is nothing for a
//! `DebugAllocator` to catch here: this example holds no heap allocation at
//! all, by construction of the module it exercises.

const std = @import("std");
const ripemd160 = @import("ripemd160");
const Ripemd160 = ripemd160.Ripemd160;

pub fn main() !void {
    // Fresh throwaway message — invented for this example, NOT one of the
    // module's official RIPEMD-160 KATs or the million-'a' stress vector.
    // 294 bytes: crosses several 64-byte compression blocks with a partial
    // final block, so the streaming buffer-fill/full-block/remainder logic
    // in `update` (not just `compress` itself, already pinned by the KATs)
    // gets exercised.
    const one_unit = "zig-libs ripemd160 example: streaming a fresh payload across multiple 64-byte compression blocks, ";
    const msg = one_unit ** 3;
    // `openssl dgst -rmd160` on the exact same bytes — the external oracle
    // this example checks against, not a value this module computed for
    // itself.
    const expected_digest = hex20("80b027da9872fbc615682e285959ca2414e647d8");

    // One-shot path.
    var one_shot: [Ripemd160.digest_length]u8 = undefined;
    Ripemd160.hash(msg, &one_shot, .{});
    std.debug.assert(std.mem.eql(u8, &expected_digest, &one_shot));
    std.debug.print("one-shot hash: byte-exact match against openssl's independent RIPEMD-160\n", .{});

    // Streaming path, fed in 37-byte chunks -- not a divisor of the 64-byte
    // block size, so every chunk boundary straddles a different offset
    // within a compression block across the run. This is the buffer-sizing/
    // ordering surface a real caller (reading a file or a socket in
    // whatever chunks arrive) actually exercises, which the KATs' one-shot
    // calls cannot reach.
    var d = Ripemd160.init(.{});
    var off: usize = 0;
    while (off < msg.len) {
        const n = @min(@as(usize, 37), msg.len - off);
        d.update(msg[off..][0..n]);
        off += n;
    }
    var streamed: [Ripemd160.digest_length]u8 = undefined;
    d.final(&streamed);
    try std.testing.expectEqualSlices(u8, &one_shot, &streamed);
    std.debug.print("streaming hash (37-byte chunks): matches one-shot, matches openssl\n", .{});

    // ── hash160: RIPEMD160(SHA256(x)), the Bitcoin pubkey-hash primitive ──
    //
    // A fresh 33-byte compressed-pubkey-SHAPED input (0x02 prefix + 32 bytes)
    // — not a real secp256k1 point (hash160 doesn't validate curve
    // membership, it just hashes bytes) and not the module's own RFC-vector-
    // style test input.
    var pubkey_shaped: [33]u8 = undefined;
    pubkey_shaped[0] = 0x02;
    for (pubkey_shaped[1..], 1..) |*b, i| b.* = @intCast(i);
    // `openssl dgst -sha256 -binary | openssl dgst -rmd160` on the exact same
    // 33 bytes — an independent two-step chain through a completely
    // different SHA-256 implementation than `std.crypto.hash.sha2.Sha256`.
    const expected_hash160 = hex20("2eef74c226d9165fd8bcede31b58bf47300115a0");

    var h160: [Ripemd160.digest_length]u8 = undefined;
    ripemd160.hash160(&pubkey_shaped, &h160);
    std.debug.assert(std.mem.eql(u8, &expected_hash160, &h160));
    std.debug.print("hash160: byte-exact match against openssl's independent SHA256|RIPEMD160 chain\n", .{});
}

fn hex20(comptime s: []const u8) [20]u8 {
    var out: [20]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}
