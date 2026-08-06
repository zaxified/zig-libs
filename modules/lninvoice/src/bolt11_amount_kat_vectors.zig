// SPDX-License-Identifier: MIT
// Transcribed mechanically from bitcoinjs/bolt11's `test/fixtures.json`.
// Do not hand-edit the strings below; re-transcribe instead.

//! External anchor for BOLT#11's HRP amount encoding — in particular the
//! **`n` (nano, 10⁻⁹ BTC) multiplier**, which none of the specification's
//! own example invoices uses (they use `m`, `u`, `p` and no-multiplier
//! only). Without an outside oracle the `n` case is pinned by nothing but
//! this module's own encoder agreeing with its own decoder, and a
//! *consistent* error in both — every `lnbc…n…` amount off by 10× — round
//! trips perfectly. The amount lives in the HRP, which is inside the signed
//! preimage, so such an invoice's signature still verifies: a wallet would
//! pay 10× the intended amount with nothing anywhere reporting an error.
//!
//! Source: https://github.com/bitcoinjs/bolt11 (MIT, see
//! `modules/lninvoice/NOTICE`), `test/fixtures.json` at commit
//! `200c232d5b27f34fa948b35de4d39774ad4b063f` (2021-11-18), fetched
//! 2026-08-06 from
//! https://raw.githubusercontent.com/bitcoinjs/bolt11/master/test/fixtures.json
//!
//! bitcoinjs/bolt11 is an independent JavaScript BOLT#11 implementation
//! (not a fork of, and not sharing code with, anything this module was
//! written from), so its `hrpToSat`/`satToHrp`/`hrpToMillisat`/
//! `millisatToHrp` fixture tables are an outside statement of what an HRP
//! amount string means -- in BOTH directions, which is what a consistent
//! encoder+decoder error needs.
//!
//! Its `satoshis`-denominated rows are converted here to millisatoshis
//! (×1000) because this module's API is msat throughout; the conversion is
//! the only edit, and it cannot mask a multiplier error (a wrong exponent
//! changes the value by a factor of ten, not of a thousand).

/// A `hrpToSat`/`hrpToMillisat` "valid" row: the amount+multiplier suffix
/// of the HRP, and the amount it denotes.
pub const HrpAmount = struct {
    /// The HRP's amount part, i.e. everything after `lnbc`/`lntb`/`lnbcrt`.
    hrp_amount: []const u8,
    msat: u64,
    /// Which upstream fixture table this row came from, verbatim.
    upstream: []const u8,
};

/// Decode direction (`hrpToSat`/`hrpToMillisat` `valid`).
pub const hrp_to_msat = [_]HrpAmount{
    .{ .hrp_amount = "10n", .msat = 1_000, .upstream = "hrpToSat: 10n -> 1 sat" },
    .{ .hrp_amount = "1u", .msat = 100_000, .upstream = "hrpToSat: 1u -> 100 sat" },
    .{ .hrp_amount = "1m", .msat = 100_000_000, .upstream = "hrpToSat: 1m -> 100000 sat" },
    .{ .hrp_amount = "1", .msat = 100_000_000_000, .upstream = "hrpToSat: 1 -> 100000000 sat" },
    .{ .hrp_amount = "1234567890n", .msat = 123_456_789_000, .upstream = "hrpToSat: 1234567890n -> 123456789 sat" },
    .{ .hrp_amount = "1234567u", .msat = 123_456_700_000, .upstream = "hrpToSat: 1234567u -> 123456700 sat" },
    .{ .hrp_amount = "1234m", .msat = 123_400_000_000, .upstream = "hrpToSat: 1234m -> 123400000 sat" },
    .{ .hrp_amount = "10p", .msat = 1, .upstream = "hrpToMillisat: 10p -> 1 msat" },
};

/// Encode direction (`satToHrp`/`millisatToHrp` `valid`) — the shortest
/// representation the amount MUST be written as. This is the half that a
/// round-trip test cannot supply: it says which multiplier an independent
/// implementation picks, and with what digits.
pub const msat_to_hrp = [_]HrpAmount{
    .{ .hrp_amount = "10n", .msat = 1_000, .upstream = "satToHrp: 1 sat -> 10n" },
    .{ .hrp_amount = "100n", .msat = 10_000, .upstream = "satToHrp: 10 sat -> 100n" },
    .{ .hrp_amount = "1u", .msat = 100_000, .upstream = "satToHrp: 100 sat -> 1u" },
    .{ .hrp_amount = "1m", .msat = 100_000_000, .upstream = "satToHrp: 100000 sat -> 1m" },
    .{ .hrp_amount = "1", .msat = 100_000_000_000, .upstream = "satToHrp: 100000000 sat -> 1" },
    .{ .hrp_amount = "1234567890n", .msat = 123_456_789_000, .upstream = "satToHrp: 123456789 sat -> 1234567890n" },
    .{ .hrp_amount = "1234500u", .msat = 123_450_000_000, .upstream = "satToHrp: 123450000 sat -> 1234500u" },
    .{ .hrp_amount = "1234m", .msat = 123_400_000_000, .upstream = "satToHrp: 123400000 sat -> 1234m" },
    .{ .hrp_amount = "10p", .msat = 1, .upstream = "millisatToHrp: 1 msat -> 10p" },
};

/// `hrpToSat`/`hrpToMillisat` "invalid" rows THIS module must also reject.
///
/// Deliberately NOT imported: `9n`, `5670p` and `21000001`. Upstream
/// rejects those from `hrpToSat` because they are not a whole number of
/// satoshis (or exceed 21e6 BTC) — an artefact of that function's
/// satoshi-denominated API, not a BOLT#11 rule. `9n` is 900 msat and
/// `5670p` is 567 msat; both are legal BOLT#11 amounts and this module
/// accepts them, correctly. Importing them would encode someone else's
/// API constraint as if it were the protocol's.
pub const invalid_hrp_amounts = [_][]const u8{
    "10x", // upstream: "Not a valid multiplier for the amount"
    "1f0", // upstream: "Not a valid human readable amount"
    "8p", // upstream (hrpToMillisat): 0.8 msat — sub-millisatoshi precision
};

/// A complete signed invoice whose amount uses the `n` multiplier, with
/// upstream's own decode of it. From the same fixture file's `decode`
/// section (`millisatoshis: "12000"`, `prefix: "lnbcrt120n"`).
///
/// NOTE it cannot be driven through `decode()` end-to-end: it predates
/// BOLT#11's mandatory `s` (`payment_secret`) field and carries none, and
/// this module requires it (see `bolt11.zig`'s "missing required 's'"
/// test). Its value here is that `120n` is an amount an outside
/// implementation *signed and published*, together with what that
/// implementation says the amount is.
pub const nano_invoice = struct {
    pub const payment_request = "lnbcrt120n1psd5ks5pp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqrrsscqpfktzsxs25he76dx2d672r7j4sm7q4quts763pwemg8chgayn96p3sny6cqm0lfxa768cetu7rupzpf7ujmsnmnpsjaukgdah8nkecd4gp6h56uu";
    /// The HRP as upstream reports it, i.e. `ln` + `bcrt` + this amount.
    pub const hrp = "lnbcrt120n";
    pub const hrp_amount = "120n";
    pub const msat: u64 = 12_000;
    pub const payee_node_key_hex = "03e7156ae33b0a208d0744199163177e909e80176e55d97a2f221ede0f934dd9ad";
};
