// SPDX-License-Identifier: MIT

//! Killing tests of the 2026-11-25 delta mutation run over `opensshDecryptSection`
//! (public; the `ssh` module calls it directly). Each test drives the public
//! function with an EMPTY passphrase: bcrypt_pbkdf refuses it at once, so a guard
//! that is dropped shows up as `IncorrectPassphrase` (the KDF's refusal) instead
//! of the guard's own error, without paying for a KDF.

const std = @import("std");
const rsa = @import("root.zig");
const testing = std.testing;

fn kdfOptions(buf: *[4 + 16 + 4]u8, salt_len: u32, rounds: u32) []const u8 {
    std.mem.writeInt(u32, buf[0..4], salt_len, .big);
    @memset(buf[4..20], 0x5a);
    // The rounds field follows the salt; a shorter salt moves it down.
    std.mem.writeInt(u32, buf[4 + salt_len ..][0..4], rounds, .big);
    return buf[0 .. 4 + salt_len + 4];
}

test "mutation 2026-11-25: opensshDecryptSection refuses options on an unencrypted container, and a non-bcrypt kdf on an encrypted one" {
    var dst: [32]u8 = undefined;
    const section: [16]u8 = @splat(0);
    // none/none with non-empty kdfoptions.
    try testing.expectError(error.InvalidOpenSSH, rsa.opensshDecryptSection(&dst, "none", "none", "x", &section, ""));
    // aes256-ctr with kdf none, whose options would otherwise parse as bcrypt's.
    var ob: [24]u8 = undefined;
    const opts = kdfOptions(&ob, 16, 2);
    try testing.expectError(error.InvalidOpenSSH, rsa.opensshDecryptSection(&dst, "aes256-ctr", "none", opts, &section, ""));
}

test "mutation 2026-11-25: opensshDecryptSection refuses an empty salt, zero rounds and the section-size mismatches before any KDF work" {
    var dst: [32]u8 = undefined;
    const section: [16]u8 = @splat(0);
    var ob: [24]u8 = undefined;
    // Empty salt.
    try testing.expectError(error.InvalidOpenSSH, rsa.opensshDecryptSection(&dst, "aes256-ctr", "bcrypt", kdfOptions(&ob, 0, 2), &section, ""));
    // Zero rounds.
    try testing.expectError(error.InvalidOpenSSH, rsa.opensshDecryptSection(&dst, "aes256-ctr", "bcrypt", kdfOptions(&ob, 16, 0), &section, ""));
    const ok = kdfOptions(&ob, 16, 2);
    // Empty section (0 % 16 == 0, so only the explicit guard refuses it).
    try testing.expectError(error.InvalidOpenSSH, rsa.opensshDecryptSection(&dst, "aes256-ctr", "bcrypt", ok, "", ""));
    // Not a multiple of the block size (CTR would handle it, so the guard is the only refusal).
    const odd: [17]u8 = @splat(0);
    try testing.expectError(error.InvalidOpenSSH, rsa.opensshDecryptSection(&dst, "aes256-ctr", "bcrypt", ok, &odd, ""));
    // dst shorter than the section.
    const two: [32]u8 = @splat(0);
    try testing.expectError(error.InvalidOpenSSH, rsa.opensshDecryptSection(dst[0..16], "aes256-ctr", "bcrypt", ok, &two, ""));
}

test "mutation 2026-11-25: opensshDecryptSection accepts exactly max_openssh_kdf_rounds" {
    var dst: [32]u8 = undefined;
    const section: [16]u8 = @splat(0);
    var ob: [24]u8 = undefined;
    // At the cap the options pass; the empty passphrase is then the KDF's refusal
    // (a `>=` cap would answer KdfRoundsTooLarge here).
    try testing.expectError(error.IncorrectPassphrase, rsa.opensshDecryptSection(&dst, "aes256-ctr", "bcrypt", kdfOptions(&ob, 16, rsa.max_openssh_kdf_rounds), &section, ""));
    try testing.expectError(error.KdfRoundsTooLarge, rsa.opensshDecryptSection(&dst, "aes256-ctr", "bcrypt", kdfOptions(&ob, 16, rsa.max_openssh_kdf_rounds + 1), &section, ""));
}
