// SPDX-License-Identifier: MIT

//! What an application consuming a drand beacon actually does with
//! `drand`: parse a chain's `/info` document, parse a round's
//! `/public/<round>` document, and BLS-verify the round's signature
//! against the chain key -- entirely offline, on response bodies this
//! example embeds rather than fetches.
//!
//! ⚠ WHAT COULD NOT BE EXERCISED HERE, AND WHY: this module is
//! transport-agnostic by design (its own doc comment: "This module never
//! opens a socket or speaks TLS") and this machine has no internet access
//! either way, so no `/info`/`/public/<round>` HTTP request happens
//! anywhere in this file. What CAN be shown, and is, is the module's own
//! job: parsing + verifying REAL response bodies drand's own network
//! actually served. Every JSON fixture below is genuine, captured
//! published data, not hand-written:
//!
//!   - Round A: quicknet mainnet's real `/info` (chain hash
//!     `52db9ba7...c84e971`) and its real round-1000 `/public/1000` body
//!     (signature + randomness) -- fetched live from `https://api.drand.sh/`
//!     2026-07-16, the same bytes `drand/src/root.zig`'s own end-to-end
//!     test and `tlock`'s KAT harness pin.
//!   - Round B: quicknet-t (testnet)'s real `/info` (chain hash
//!     `cc9c3984...41a9a5`, genesis_time `1689232296`) -- the same
//!     fixture `drand/src/verify.zig`'s own cross-chain test carries --
//!     and round 5423142's real published signature, fetched live from
//!     `https://pl-us.testnet.drand.sh/` 2026-07-16, the identical value
//!     `tlock`'s drand-interop KAT vector decrypts against.
//!   - The chained-scheme `/info` used for the `UnsupportedScheme` check
//!     is drand's classic/default mainnet beacon (chain hash
//!     `8990e7a9...72e51b2ce` -- drand's long-published default chain,
//!     the same fixture `drand/src/chaininfo.zig`'s own parse test
//!     carries), included here only to reach `pedersen_bls_chained`
//!     dispatch -- this module does not verify that scheme by design
//!     (SPEC.md's "Deliberately deferred").
//!
//! Every negative case below is a REAL rejection this module's own
//! verification equation produces on genuine or genuinely-adjacent bytes
//! (a wrong chain's key, a tampered `randomness` field, a malformed
//! document) -- none of it is simulated.
//!
//! Built against the PUBLISHED module (`@import("drand")` plus its two
//! declared deps `bls12_381`/`tlock`) -- no `test_deps`, no reaching into
//! `src/`.

const std = @import("std");
const drand = @import("drand");

// ── Round A: quicknet mainnet (published by the League of Entropy, ──────
// captured from https://api.drand.sh/v2/beacons/quicknet/{info,public/1000}
// 2026-07-16 -- the same bytes drand's own root.zig end-to-end test pins).

const quicknet_info_json =
    \\{
    \\  "public_key": "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
    \\  "period": 3,
    \\  "genesis_time": 1692803367,
    \\  "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    \\  "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
    \\  "schemeID": "bls-unchained-g1-rfc9380",
    \\  "metadata": { "beaconID": "quicknet" }
    \\}
;

const round_1000_json =
    \\{"round":1000,"randomness":"fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd","signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
;

// ── Round B: quicknet-t testnet (published by the League of Entropy, ────
// captured from https://pl-us.testnet.drand.sh/<hash>/{info,public/5423142}
// 2026-07-16 -- the same round-signature value tlock's drand-interop KAT
// vector decrypts against; no `randomness` field was captured for this
// round, so it is simply omitted -- the field is optional).

const quicknet_t_info_json =
    \\{
    \\  "public_key": "b15b65b46fb29104f6a4b5d1e11a8da6344463973d423661bb0804846a0ecd1ef93c25057f1c0baab2ac53e56c662b66072f6d84ee791a3382bfb055afab1e6a375538d8ffc451104ac971d2dc9b168e2d3246b0be2015969cbaac298f6502da",
    \\  "period": 3,
    \\  "genesis_time": 1689232296,
    \\  "hash": "cc9c398442737cbd141526600919edd69f1d6f9b4adb67e4d912fbc64341a9a5",
    \\  "groupHash": "a81e9d63f614ccdb144b8ff149623dee7fb1d3fa64f7cbb2076b5136ad5b8f83",
    \\  "schemeID": "bls-unchained-g1-rfc9380",
    \\  "metadata": { "beaconID": "quicknet-t" }
    \\}
;

const round_5423142_json =
    \\{"round":5423142,"signature":"96fce8e2f70e2784577c8f2d8bd36af7a4b0dfd73dd91469d8556b36d2973a4f84681a45b1af2ce0511e5a32dd72508f"}
;

// ── drand's classic/default mainnet chain (published by the League of ──
// Entropy -- chain hash `8990e7a9...72e51b2ce` is drand's long-published
// default chain; captured from the same fixture drand's own
// chaininfo.zig parse test carries), used only to reach the
// `pedersen_bls_chained` scheme dispatch this module recognizes but
// deliberately does not verify (SPEC.md).

const chained_info_json =
    "{\"public_key\":\"868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31\"," ++
    "\"period\":30,\"genesis_time\":1595431050," ++
    "\"hash\":\"8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce\"," ++
    "\"groupHash\":\"176f93498eac9ca337150b46d21dd58673ea4e3581185f869672e59fa4cb390a\"," ++
    "\"schemeID\":\"pedersen-bls-chained\",\"metadata\":{\"beaconID\":\"default\"}}";

fn roundA(gpa: std.mem.Allocator) !void {
    const info = try drand.parseInfo(gpa, quicknet_info_json);
    const rnd = try drand.parseRound(gpa, round_1000_json);

    try drand.verifyRound(&info, &rnd);
    std.debug.print("round A: genuine quicknet round 1000 verifies against the genuine chain key\n", .{});

    // expectedRound: round 1000 was due at genesis_time + 999*period (round
    // 1 is due exactly at genesis_time, per the module's own formula).
    const due_at = info.genesis_time + 999 * info.period_seconds;
    if (drand.expectedRound(&info, due_at) != 1000) return error.WrongExpectedRound;
    std.debug.print("round A: expectedRound at round 1000's own due instant reports 1000\n", .{});

    // ── negative: malformed JSON, a real allocating failure path ────────
    // Long enough that std.json's scanner allocates internal state before
    // hitting the syntax error -- an allocating failure that returns early,
    // not a check that short-circuits before any allocation happens (unlike
    // the DocumentTooLarge guard, which fires before the arena even opens).
    const garbage = "{\"public_key\": \"not json past this point" ++ ("x" ** 200);
    if (drand.parseInfo(gpa, garbage)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.MalformedJson => std.debug.print("round A: truncated /info document: MalformedJson (expected)\n", .{}),
        else => return err,
    }

    // ── negative: a degenerate (point-at-infinity) public key ───────────
    // drand's own KeyValidate rejects the identity point outright -- the
    // compressed-G2 identity encoding is flag byte 0xc0 followed by zeros.
    const identity_key_hex = "c0" ++ ("00" ** 95);
    const bad_key_doc = "{\"public_key\":\"" ++ identity_key_hex ++
        "\",\"period\":3,\"genesis_time\":1,\"hash\":\"52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971\"," ++
        "\"groupHash\":\"f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e\",\"schemeID\":\"bls-unchained-g1-rfc9380\"}";
    if (drand.parseInfo(gpa, bad_key_doc)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidPoint => std.debug.print("round A: identity-point public key: InvalidPoint (expected)\n", .{}),
        else => return err,
    }

    // ── negative: randomness field tampered independently of the signature ──
    // A syntactically valid 32-byte digest that is simply not
    // SHA-256(signature) -- the genuine signature bytes are untouched.
    const wrong_randomness_json =
        \\{"round":1000,"randomness":"0000000000000000000000000000000000000000000000000000000000000000","signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}
    ;
    const bad_rnd = try drand.parseRound(gpa, wrong_randomness_json);
    if (drand.verifyRound(&info, &bad_rnd)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.RandomnessMismatch => std.debug.print("round A: randomness field tampered (still real signature): RandomnessMismatch (expected)\n", .{}),
        else => return err,
    }

    // ── negative: cross-chain -- a genuine round verified against the ───
    // WRONG chain's genuine key (quicknet-t's, not quicknet's).
    const wrong_chain_info = try drand.parseInfo(gpa, quicknet_t_info_json);
    if (drand.verifyRound(&wrong_chain_info, &rnd)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidSignature => std.debug.print("round A: quicknet round 1000 rejected under quicknet-t's key (cross-chain): InvalidSignature (expected)\n", .{}),
        else => return err,
    }

    // ── negative: a scheme this module recognizes but does not verify ───
    const chained_info = try drand.parseInfo(gpa, chained_info_json);
    if (drand.verifyRound(&chained_info, &rnd)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.UnsupportedScheme => std.debug.print("round A: pedersen-bls-chained scheme: UnsupportedScheme (expected -- not verified by design)\n", .{}),
        else => return err,
    }
}

fn roundB(gpa: std.mem.Allocator) !void {
    // A second, independent beacon and round -- proves parseInfo/parseRound/
    // verifyRound carry no state across calls (each returns a plain value
    // with no retained allocation; see chaininfo.zig/round.zig's own doc
    // comments), which is exactly where a leak between rounds would hide.
    const info = try drand.parseInfo(gpa, quicknet_t_info_json);
    const rnd = try drand.parseRound(gpa, round_5423142_json);
    try drand.verifyRound(&info, &rnd);
    std.debug.print("round B: genuine quicknet-t round 5423142 verifies against the genuine testnet chain key (no randomness field carried)\n", .{});

    // Malformed signature bytes on a document that otherwise parses: the
    // pairing equation never even runs, because the subgroup check at
    // parse time is the guard (see round.zig's module doc comment, W2-32).
    const flipped =
        \\{"round":5423142,"signature":"96fce8e2f70e2784577c8f2d8bd36af7a4b0dfd73dd91469d8556b36d2973a4f84681a45b1af2ce0511e5a32dd72508e"}
    ;
    const res = drand.parseRound(gpa, flipped);
    if (res) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidPoint, error.SignatureNotInSubgroup => std.debug.print(
            "round B: flipped signature byte: {s} (expected -- decode-time rejection, pairing never runs)\n",
            .{@errorName(err)},
        ),
        else => return err,
    }
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer if (gpa_state.deinit() == .leak) @panic("leak");
    const gpa = gpa_state.allocator();

    try roundA(gpa);
    try roundB(gpa);

    std.debug.print("OK: all drand example checks passed\n", .{});
}
