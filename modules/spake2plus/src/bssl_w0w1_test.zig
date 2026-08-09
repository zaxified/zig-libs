// SPDX-License-Identifier: MIT
//! `computeW0W1` against BoringSSL's SPAKE2+ — audit finding `spake2plus` F1.
//!
//! `computeW0W1`'s own doc comment records that RFC 9383 Appendix C hands `w0`
//! and `w1` over directly ("the choice of PBKDF is omitted"), so the official
//! vector in `kat_vectors.zig` starts *after* this function and every other
//! test in this module takes `w0`/`w1` as given. That left the PBKDF-half wide
//! reduction — the one step where a canonical-or-reject primitive would be
//! silently wrong — with no oracle at all.
//!
//! `bssl_w0w1_vectors.zig` is that oracle: frozen output of BoringSSL's
//! `bssl::spake2plus::Register`, captured once (see that file's provenance
//! header). Everything here reads those bytes and nothing else.
//!
//! **No live counterpart, no skip path.** These tests are pure data
//! comparisons: they run with BoringSSL, cmake and go absent from the machine,
//! and there is no branch in this file that can turn a missed assertion into a
//! pass. (A bare `return;` in a Zig test body reports PASS — this repo has been
//! bitten by exactly that, so the corpus-size assertions below are deliberate:
//! an emptied vector table fails loudly instead of vacuously succeeding.)

const std = @import("std");
const spake2plus = @import("root.zig");
const bssl = @import("bssl_w0w1_vectors.zig");

fn hexN(comptime n: usize, hex_str: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

test "BoringSSL anchor: the frozen corpus is actually populated" {
    // An empty table would make every loop below pass without comparing a
    // single byte. Pin the counts the capture emitted.
    try std.testing.expectEqual(@as(usize, 3), bssl.registrations.len);
    try std.testing.expectEqual(@as(usize, 6), bssl.boundaries.len);
}

test "BoringSSL anchor: computeW0W1 reproduces Register()'s w0/w1 byte-exact" {
    for (bssl.registrations, 0..) |vec, i| {
        errdefer std.debug.print(
            "\nBoringSSL registration vector [{d}] disagreed: {s}\n",
            .{ i, vec.note },
        );
        const got = try spake2plus.computeW0W1(&hexN(80, vec.pbkdf_output));
        try std.testing.expectEqualSlices(u8, &hexN(32, vec.w0), &got.w0);
        try std.testing.expectEqualSlices(u8, &hexN(32, vec.w1), &got.w1);
    }
}

test "BoringSSL anchor: computeL(w1) reproduces Register()'s registration record L" {
    // `Register` returns the record as an uncompressed SEC1 `w1*P`. The RFC
    // vector already pins `computeL` on one input; this widens it to inputs a
    // real registration produced, and closes the loop from `pbkdf_output` all
    // the way to `L` through our own two functions.
    for (bssl.registrations, 0..) |vec, i| {
        errdefer std.debug.print(
            "\nBoringSSL registration vector [{d}] disagreed on L: {s}\n",
            .{ i, vec.note },
        );
        const w0w1 = try spake2plus.computeW0W1(&hexN(80, vec.pbkdf_output));
        const l = try spake2plus.computeL(w0w1.w1);
        try std.testing.expectEqualSlices(u8, &hexN(65, vec.l), &l);
    }
}

test "BoringSSL anchor: computeW0W1 matches BoringSSL's reduction at the modular boundary" {
    // scrypt output is a uniform 320-bit number, so the registration vectors
    // above never land near `n`. These are the chosen inputs (0, 1, n-1, n,
    // n+1, 2^256-1, 2^320-1) where a wide reduction is easy to get wrong —
    // and where a canonical `Scalar.fromBytes` would *reject* instead of
    // reducing, which is the specific mistake this anchor rules out.
    for (bssl.boundaries, 0..) |vec, i| {
        errdefer std.debug.print(
            "\nBoringSSL boundary vector [{d}] disagreed: {s}\n",
            .{ i, vec.note },
        );
        const got = try spake2plus.computeW0W1(&hexN(80, vec.pbkdf_output));
        try std.testing.expectEqualSlices(u8, &hexN(32, vec.w0), &got.w0);
        try std.testing.expectEqualSlices(u8, &hexN(32, vec.w1), &got.w1);
    }
}

test "BoringSSL anchor: the two halves are independent and not interchangeable" {
    // Guards the corpus itself rather than the code: if every captured vector
    // happened to be symmetric (w0 == w1), swapping the halves in
    // `computeW0W1` would pass the tables above unnoticed. At least one
    // vector must distinguish the halves.
    var asymmetric: usize = 0;
    for (bssl.boundaries) |vec| {
        if (!std.mem.eql(u8, vec.w0, vec.w1)) asymmetric += 1;
    }
    for (bssl.registrations) |vec| {
        if (!std.mem.eql(u8, vec.w0, vec.w1)) asymmetric += 1;
    }
    try std.testing.expect(asymmetric >= 5);
}
