// SPDX-License-Identifier: MIT
//! Bitcoin's "hash256" (double SHA-256) and its single-hash cousin used by
//! BIP341's taproot commitments. Standalone (no other module dependency)
//! so every sighash/tx file can import it without a cycle.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// `SHA256(SHA256(data))` -- Bitcoin's standard txid/wtxid/merkle/PoW hash.
pub fn sha256d(data: []const u8) [32]u8 {
    var first: [32]u8 = undefined;
    Sha256.hash(data, &first, .{});
    var second: [32]u8 = undefined;
    Sha256.hash(&first, &second, .{});
    return second;
}

/// Plain single SHA-256. BIP341's `sha_prevouts`/`sha_amounts`/
/// `sha_scriptpubkeys`/`sha_sequences`/`sha_outputs` commitments are a
/// single SHA-256 (NOT `sha256d`) -- they feed into `bip340.taggedHash`,
/// which is itself already a domain-separated double-hash construction, so
/// BIP341 deliberately does not double-hash again underneath it.
pub fn sha256(data: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(data, &out, .{});
    return out;
}

test "sha256d is SHA256 applied twice" {
    var once: [32]u8 = undefined;
    Sha256.hash("abc", &once, .{});
    var twice: [32]u8 = undefined;
    Sha256.hash(&once, &twice, .{});
    try std.testing.expectEqualSlices(u8, &twice, &sha256d("abc"));
}

test "sha256 matches std directly" {
    var want: [32]u8 = undefined;
    Sha256.hash("abc", &want, .{});
    try std.testing.expectEqualSlices(u8, &want, &sha256("abc"));
}
