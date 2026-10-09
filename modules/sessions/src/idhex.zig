// SPDX-License-Identifier: MIT

//! idhex — constant-time lowercase hex encoding for the two secrets this
//! module writes out as text: the session id (`Manager.newId`) and the CSRF
//! token (`Csrf.token`, an HMAC under the CSRF key) — and the decoder
//! `Csrf.verify` runs on a presented token, which for a legitimate request IS
//! the secret token.
//!
//! `std.fmt.bytesToHex` and the `"0123456789abcdef"[b >> 4]` idiom index a
//! table by the secret nibble — a secret-dependent memory address (cache-line
//! timing in principle; memcheck reports it as a use of an uninitialised value
//! in an address), and `std.fmt.hexToBytes` branches on each character's
//! class. Here every digit is computed arithmetically: each range decision is
//! a borrow turned into a mask, never a branch or an index.
//! Measured by `ctgrind_harness.zig` (`csrf`, `newid`).

const std = @import("std");

/// One nibble (0..15) to its lowercase hex digit, branch- and table-free.
inline fn digit(n: u8) u8 {
    // 9 - n borrows (high byte 0xFF) exactly when n > 9.
    const above9: u8 = @truncate((@as(u16, 9) -% n) >> 8);
    return n + '0' + (above9 & ('a' - '0' - 10));
}

/// 0xFF when `x < n`, else 0 — a borrow, not a comparison branch.
inline fn below(x: u8, n: u8) u8 {
    return @truncate((@as(u16, x) -% n) >> 8);
}

/// One hex character (either case) to its value, plus a 0xFF/0 validity mask.
inline fn value(c: u8) struct { u8, u8 } {
    const d = c -% '0';
    const is_digit = below(d, 10);
    // `| 0x20` folds 'A'..'F' onto 'a'..'f' and maps no other byte there.
    const l = (c | 0x20) -% 'a';
    const is_letter = below(l, 6);
    return .{ (d & is_digit) | ((l +% 10) & is_letter), is_digit | is_letter };
}

/// Decode `in` (2 * `out.len` hex digits, either case — the set
/// `std.fmt.hexToBytes` accepts) into `out`. Returns 1 when every character
/// was a hex digit, else 0; never branches on the characters, so the caller
/// must fold the result in without branching on it before the secret
/// comparison either (`Csrf.verify` ANDs it with the MAC compare).
pub fn decode(out: []u8, in: []const u8) u1 {
    std.debug.assert(in.len == 2 * out.len);
    var ok: u8 = 0xFF;
    for (out, 0..) |*o, i| {
        const hi = value(in[2 * i]);
        const lo = value(in[2 * i + 1]);
        o.* = (hi[0] << 4) | lo[0];
        ok &= hi[1] & lo[1];
    }
    return @truncate(ok);
}

/// Lowercase hex of `in` into `out[0 .. 2 * in.len]`.
pub fn encode(out: []u8, in: []const u8) void {
    std.debug.assert(out.len >= 2 * in.len);
    for (in, 0..) |b, i| {
        out[2 * i] = digit(b >> 4);
        out[2 * i + 1] = digit(b & 0x0f);
    }
}

test "encode agrees with std.fmt.bytesToHex for every byte value" {
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    var got: [512]u8 = undefined;
    encode(&got, &all);
    const want = std.fmt.bytesToHex(all, .lower);
    try std.testing.expectEqualSlices(u8, &want, &got);
}

test "decode agrees with std.fmt.hexToBytes on every character pair" {
    for (0..256) |a| for (0..256) |b| {
        const in = [2]u8{ @intCast(a), @intCast(b) };
        var got: [1]u8 = undefined;
        const ok = decode(&got, &in);
        var want: [1]u8 = undefined;
        if (std.fmt.hexToBytes(&want, &in)) |_| {
            try std.testing.expectEqual(@as(u1, 1), ok);
            try std.testing.expectEqual(want[0], got[0]);
        } else |_| try std.testing.expectEqual(@as(u1, 0), ok);
    };
}
