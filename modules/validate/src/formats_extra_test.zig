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

// ── mutation run 2026-11-05: boundaries and checksums no vector pinned ──────

test "rgb, rgba: no mixed percent and integer, an alpha above 1 is no alpha" {
    try expectAll(.rgb, &.{"rgb(10%,20%,30%)"}, &.{ "rgb(10%,20,30)", "rgb(10%,20%,30)", "rgb(10,20%,30)" });
    try expectAll(.rgba, &.{ "rgba(0,0,0,1)", "rgba(0,0,0,1.0)", "rgba(0,0,0,0.5)" }, &.{ "rgba(0,0,0,1.5)", "rgba(0,0,0,1.01)" });
}

test "eth_addr_checksum: a letter at the nibble boundaries 8, 'a' and 'F'" {
    try expectAll(.eth_addr_checksum, &.{
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xc5e53Bc704d11230f9251bFF20D33Bbed38D20b5",
    }, &.{
        // Keccak nibble exactly 8 under a lower-case letter (an upper-case one is due)
        "0x8B0E7153BF7C3706d85C524e440066559A6656c9",
        // an 'a' where 'A' is due
        "0x8B0E7153BF7C3706D85C524e440066559a6656c9",
        // an 'F' where 'f' is due
        "0x0bd5482a90a29B9Fa5Ff5180BC0Dbc0E15637Ebb",
    });
}

test "btc_addr_bech32: padding-length classes, witness version 17, program 1 and 41 bytes, v0 of 21 bytes" {
    try expectAll(.btc_addr_bech32, &.{
        "bc1ppppqutr9er", // 2-byte program, the shortest
        "bc1ppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp74qak3", // 40 bytes, the longest
    }, &.{
        // data characters 6, 9, 11: length mod 8 of 0, 3, 5 leaves 6, 5, 7 padding bits (valid checksums, zero padding)
        "bc1ppppppqn3euz5",
        "bc1pppppppppq02pdl6",
        "bc1pppppppppppqm5ufkh",
        "bc13qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0hg8yd", // version 17
        "bc1qppppppppppppppppppppppppppppppppqqnfcdur", // version 0, 21-byte program
        "bc1pqqlppvpg", // 1-byte program
        "bc1pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppqq5lp03l", // 41 bytes
    });
}

test "ulid: I, L, O, U are not Crockford digits" {
    try expectAll(.ulid, &.{ "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01arz3ndektsv4rrffq69g5fav" }, &.{ "0I000000000000000000000000", "0L000000000000000000000000", "0O000000000000000000000000", "0U000000000000000000000000" });
}

test "base32: 8 is no digit" {
    try expectAll(.base32, &.{"AAAAAAA7"}, &.{ "AAAAAAA8", "AAAAAAA1", "AAAAAAA[" });
}

test "datauri: base64 with three paddings or a '.', '/' in the data, DEL and '=' in the type, '~' in the data" {
    try expectAll(.datauri, &.{ "data:;base64,//8=", "data:,a~b" }, &.{
        "data:;base64,A===",
        "data:;base64,.AAA",
        "data:text/pl\x7fain,x",
        "data:te=xt/plain,x",
    });
}

test "urn: '$' in an RFC 2141 NSS, a half escape, '~', '/' and an empty q-component in RFC 8141" {
    try expectAll(.urn_rfc2141, &.{"urn:a:b$c"}, &.{ "urn:isbn:%4G", "urn:isbn:%4" });
    try expectAll(.urn_rfc8141, &.{ "urn:ab:x~y", "urn:ab:x?+r?=q", "urn:ab:x?+a/b" }, &.{ "urn:ab:x?+r?=", "urn:ab:x?+" });
}

test "fqdn: 253 characters pass, 254 do not" {
    var buf: [254]u8 = undefined;
    for ([_]usize{ 253, 254 }) |n| {
        @memset(buf[0..n], 'a');
        for ([_]usize{ 63, 127, 191 }) |p| buf[p] = '.';
        try testing.expectEqual(n == 253, validate.validateFormat(.fqdn, buf[0..n]));
    }
}

test "bcp47: extlang count, variant shapes, private use after an extension, subtag length" {
    try expectAll(.bcp47_language_tag, &.{ "en-abc-def-ghi", "en-a-bbb-X-c", "en-US-1234", "en-US-abcde" }, &.{
        "abcd-xyz", // a 4-letter language takes no extlang
        "en-abc-def-ghi-jkl",
        "en-US-abcd",
        "en-a-123456789",
    });
}

test "bic: the 2022 form takes no digit in the sixth place, and a Z" {
    try expectAll(.bic, &.{"DEUTDEZZ"}, &.{ "DEUTD1ZZ", "DEUT1EZZ" });
}

test "cron: a field may start with a question mark" {
    try expectAll(.cron, &.{"?/5 * * * *"}, &.{});
}
