// SPDX-License-Identifier: MIT

//! Vectors for the second-wave formats that the go-playground oracle cannot
//! carry: `non_control_character` (no Go tag; Keats/validator's) and the
//! BIP 350 taproot addresses go refuses (their go verdict is in
//! `go_format_vectors.zig` under the class BECH32M).

const std = @import("std");
const testing = std.testing;
const validate = @import("root.zig");

fn expectAll(f: validate.Format, valid: []const []const u8, invalid: []const []const u8) !void {
    for (valid) |s| try testing.expect(validate.validateFormat(f, s));
    for (invalid) |s| {
        testing.expect(!validate.validateFormat(f, s)) catch |e| {
            std.debug.print("{t}: expected INVALID: \"{f}\"\n", .{ f, std.zig.fmtString(s) });
            return e;
        };
    }
}

test "non_control_character: Cc code points fail, everything else passes" {
    try expectAll(.non_control_character, &.{
        "", "plain text", "tab\xe2\x80\x8bzero-width", "\xc2\xa0nbsp", "\xe6\x97\xa5\xe6\x9c\xac", "\xf0\x9f\x98\x80", "\xc2\xa0",
    }, &.{
        "a\tb", "a\nb", "a\x00b", "\x1f", "a\x7fb", "\xc2\x80", "\xc2\x85", "\xc2\x9f", "\xff", "a\xc3", "\xed\xa0\x80",
    });
}

test "btc_addr_bech32: BIP 350 taproot addresses pass, a wrong checksum constant fails" {
    try expectAll(.btc_addr_bech32, &.{
        "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
        "BC1SW50QGDZ25J",
        "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
    }, &.{
        // version 1 with the bech32 constant, version 0 with the bech32m one
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
        "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", // testnet
        "Bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // mixed case
        "bc1",
        "",
        // BIP 350's non-zero padding case, on mainnet: last program character q -> p
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vplqq80a",
    });
}

test "ulid: the largest value passes, the next first character overflows 128 bits" {
    try expectAll(.ulid, &.{"7ZZZZZZZZZZZZZZZZZZZZZZZZZ"}, &.{ "8ZZZZZZZZZZZZZZZZZZZZZZZZZ", "ZZZZZZZZZZZZZZZZZZZZZZZZZZ" });
}

test "urn_rfc2141: the NID urn and unescaped reserved characters fail (RFC 2141 2.1, 2.3.2)" {
    try expectAll(.urn_rfc2141, &.{ "urn:isbn:a%2Fb", "urn:a:b" }, &.{ "urn:urn:x", "URN:UrN:x", "urn:isbn:a/b", "urn:isbn:a?b", "urn:isbn:a#b" });
}
