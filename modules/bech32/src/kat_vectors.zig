// SPDX-License-Identifier: MIT
//! The official BIP173 (bech32) and BIP350 (bech32m) test vectors,
//! transcribed programmatically (not by hand — see below) from the
//! "Test vectors" appendices of:
//!   https://raw.githubusercontent.com/bitcoin/bips/master/bip-0173.mediawiki
//!   https://raw.githubusercontent.com/bitcoin/bips/master/bip-0350.mediawiki
//! fetched directly from the `bitcoin/bips` repository for this pass — a
//! public BIP specification artifact, not copied from any other
//! implementation's test suite (see `../NOTICE`).
//!
//! Transcription method: the two `.mediawiki` sources were parsed with a
//! throwaway Python script (regex over `<tt>...</tt>`) to extract every
//! `<tt>` token verbatim and machine-generate the Zig literals below,
//! specifically to avoid hand-transcription typos in these long strings
//! (one was caught this way: an early hand-copy of the 90-character
//! `11lll...ludsr8` bech32m vector was two `l`s short). Each vector's
//! expected error was independently derived by running BOTH `bech32.zig`'s
//! and `segwit.zig`'s decode logic re-implemented in that same Python
//! script against every vector and cross-checking the result against the
//! BIP's own stated "reason for invalidity" — see `kat_test.zig` for the
//! Zig-side pass that then runs the *actual* module code over this data.
//!
//! One correction versus a literal reading of the BIPs' English reasons:
//! both BIPs list some checksum-region vectors as "Invalid character in
//! checksum" (e.g. bech32m's `mm1crxm3i`, `au1s5cgom`). These decode via
//! `error.InvalidDataChar`, not `error.InvalidChecksum` — the character
//! really is outside the 32-symbol charset (bech32m's checksum vectors use
//! 'i'/'o', which BIP173's charset excludes entirely alongside '1'/'b'),
//! so "invalid character" is exactly what it says: a charset violation, not
//! a checksum-math failure. Confirmed against the Python re-implementation.

const std = @import("std");

/// Strings BIP173 lists as valid bech32 (checksum constant `1`).
pub const valid_bech32 = [_][]const u8{
    "A12UEL5L",
    "a12uel5l",
    "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
    "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
    "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
    "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
    "?1ezyfcl",
};

/// Strings BIP350 lists as valid bech32m (checksum constant `0x2bc830a3`).
pub const valid_bech32m = [_][]const u8{
    "A1LQFN3A",
    "a1lqfn3a",
    "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
    "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
    "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
    "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
    "?1v759aa",
};

pub const InvalidVector = struct {
    s: []const u8,
    err: anyerror,
};

// Three of BIP173's invalid vectors and three of BIP350's are a raw
// out-of-range byte (0x20/0x7F/0x80) prepended to an otherwise-ASCII HRP —
// not expressible as a normal string literal, hence named array constants
// built with `++` instead of inline in the vector tables below.
const b32_space_1nwldj5 = [_]u8{0x20} ++ "1nwldj5".*;
const b32_del_1axkwrx = [_]u8{0x7f} ++ "1axkwrx".*;
const b32_0x80_1eym55h = [_]u8{0x80} ++ "1eym55h".*;
const b32_de1lg7wt_0xff = "de1lg7wt".* ++ [_]u8{0xff};

const b32m_space_1xj0phk = [_]u8{0x20} ++ "1xj0phk".*;
const b32m_del_1g6xzxy = [_]u8{0x7f} ++ "1g6xzxy".*;
const b32m_0x80_1vctc34 = [_]u8{0x80} ++ "1vctc34".*;

/// BIP173 "The following string are not valid Bech32" (12 vectors), each
/// with the typed error this module's `bech32.decode` rejects it with.
pub const invalid_bech32 = [_]InvalidVector{
    .{ .s = &b32_space_1nwldj5, .err = error.HrpCharOutOfRange },
    .{ .s = &b32_del_1axkwrx, .err = error.HrpCharOutOfRange },
    .{ .s = &b32_0x80_1eym55h, .err = error.HrpCharOutOfRange },
    .{ .s = "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx", .err = error.TooLong },
    .{ .s = "pzry9x0s0muk", .err = error.NoSeparator },
    .{ .s = "1pzry9x0s0muk", .err = error.EmptyHrp },
    .{ .s = "x1b4n0q5v", .err = error.InvalidDataChar },
    .{ .s = "li1dgmt3", .err = error.DataTooShort },
    .{ .s = &b32_de1lg7wt_0xff, .err = error.InvalidDataChar },
    .{ .s = "A1G7SGD8", .err = error.InvalidChecksum },
    .{ .s = "10a06t8", .err = error.EmptyHrp },
    .{ .s = "1qzzfhee", .err = error.EmptyHrp },
};

/// BIP350's bech32m analogue of the above (14 vectors).
pub const invalid_bech32m = [_]InvalidVector{
    .{ .s = &b32m_space_1xj0phk, .err = error.HrpCharOutOfRange },
    .{ .s = &b32m_del_1g6xzxy, .err = error.HrpCharOutOfRange },
    .{ .s = &b32m_0x80_1vctc34, .err = error.HrpCharOutOfRange },
    .{ .s = "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4", .err = error.TooLong },
    .{ .s = "qyrz8wqd2c9m", .err = error.NoSeparator },
    .{ .s = "1qyrz8wqd2c9m", .err = error.EmptyHrp },
    .{ .s = "y1b0jsk6g", .err = error.InvalidDataChar },
    .{ .s = "lt1igcx5c0", .err = error.InvalidDataChar },
    .{ .s = "in1muywd", .err = error.DataTooShort },
    .{ .s = "mm1crxm3i", .err = error.InvalidDataChar }, // see file doc comment
    .{ .s = "au1s5cgom", .err = error.InvalidDataChar }, // see file doc comment
    .{ .s = "M1VUXWEZ", .err = error.InvalidChecksum },
    .{ .s = "16plkw9", .err = error.EmptyHrp },
    .{ .s = "1p2gdwpf", .err = error.EmptyHrp },
};

pub const SegwitVector = struct {
    hrp: []const u8,
    address: []const u8,
    witver: u5,
    /// Hex-encoded expected witness program.
    program_hex: []const u8,
};

/// BIP350 "Test vectors for v0-v16 native segregated witness addresses" —
/// valid list (8 vectors; supersedes BIP173's own older segwit-vector list,
/// which predates the bech32m fix and checksums 3 of its 8 addresses with
/// plain bech32 for witness versions >=1 — see SPEC.md).
pub const valid_segwit = [_]SegwitVector{
    .{ .hrp = "bc", .address = "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", .witver = 0, .program_hex = "751e76e8199196d454941c45d1b3a323f1433bd6" },
    .{ .hrp = "tb", .address = "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", .witver = 0, .program_hex = "1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262" },
    .{ .hrp = "bc", .address = "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", .witver = 1, .program_hex = "751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6" },
    .{ .hrp = "bc", .address = "BC1SW50QGDZ25J", .witver = 16, .program_hex = "751e" },
    .{ .hrp = "bc", .address = "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", .witver = 2, .program_hex = "751e76e8199196d454941c45d1b3a323" },
    .{ .hrp = "tb", .address = "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", .witver = 0, .program_hex = "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433" },
    .{ .hrp = "tb", .address = "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", .witver = 1, .program_hex = "000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433" },
    .{ .hrp = "bc", .address = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", .witver = 1, .program_hex = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" },
};

pub const InvalidSegwitVector = struct {
    hrp: []const u8,
    address: []const u8,
    err: anyerror,
};

/// BIP350's "invalid segwit addresses" list (15 vectors) — includes the
/// variant-mismatch cases (BIP350's headline addition over BIP173: v0 must
/// checksum as bech32, v1+ must checksum as bech32m) alongside the
/// witver/program-length/padding/HRP/mixed-case checks BIP173 already had.
pub const invalid_segwit = [_]InvalidSegwitVector{
    .{ .hrp = "bc", .address = "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut", .err = error.InvalidHrp },
    .{ .hrp = "bc", .address = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd", .err = error.InvalidVariant },
    .{ .hrp = "tb", .address = "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf", .err = error.InvalidVariant },
    .{ .hrp = "bc", .address = "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL", .err = error.InvalidVariant },
    .{ .hrp = "bc", .address = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh", .err = error.InvalidVariant },
    .{ .hrp = "tb", .address = "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47", .err = error.InvalidVariant },
    .{ .hrp = "bc", .address = "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4", .err = error.InvalidDataChar },
    .{ .hrp = "bc", .address = "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R", .err = error.InvalidWitnessVersion },
    .{ .hrp = "bc", .address = "bc1pw5dgrnzv", .err = error.InvalidProgramLength },
    .{ .hrp = "bc", .address = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav", .err = error.InvalidProgramLength },
    .{ .hrp = "bc", .address = "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P", .err = error.InvalidProgramLength },
    .{ .hrp = "tb", .address = "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq", .err = error.MixedCase },
    .{ .hrp = "bc", .address = "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf", .err = error.InvalidPadding },
    .{ .hrp = "tb", .address = "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j", .err = error.InvalidPadding },
    .{ .hrp = "bc", .address = "bc1gmk9yu", .err = error.EmptyDataSection },
};
