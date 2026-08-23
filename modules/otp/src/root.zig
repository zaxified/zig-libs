// SPDX-License-Identifier: MIT
//! otp — HOTP (RFC 4226) and TOTP (RFC 6238) one-time passwords.
//!
//! The one-time-password primitives behind 2FA authenticator apps (Google
//! Authenticator, FreeOTP, ...): counter-based HOTP and its time-based
//! extension TOTP, over HMAC-SHA-1/-SHA-256/-SHA-512.
//!
//! **Status: complete** — HOTP dynamic truncation, TOTP time-step mapping,
//! zero-padded formatting, and a ±skew verify helper, KAT-validated
//! byte-exact against RFC 4226 Appendix D (all counts 0..9, including the
//! intermediate HMAC digests and pre-modulo truncated integers) and the
//! full RFC 6238 Appendix B table (all 6 times × SHA-1/SHA-256/SHA-512)
//! — see `kat_test.zig`.
//!
//! **std recon (0.16.0)**: every primitive needed is already in std —
//! `std.crypto.auth.hmac.HmacSha1`, `.sha2.HmacSha256`, `.sha2.HmacSha512`
//! (`.create(out, msg, key)`, keys of any length per RFC 2104) and
//! `std.mem.writeInt(u64, .., .big)` for the 8-byte big-endian counter.
//! Nothing is reimplemented here; this module only adds RFC 4226's
//! dynamic-truncation construction and RFC 6238's time-step mapping.
//!
//! No allocator, no internal clock or RNG: the caller passes the counter
//! (HOTP) or the unix time (TOTP), so every result is reproducible and the
//! RFC vectors are assertable as-is.
//!
//! Provenance: clean-room from RFC 4226 / RFC 6238 (public IETF
//! specifications); test vectors transcribed from the RFC appendices.
//! See `../NOTICE`.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "HOTP + TOTP one-time passwords (RFC 4226 / RFC 6238) — the 2FA-authenticator primitive; caller supplies the counter/time (no wall clock).",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure computation, allocation-free
    .role = .util,
    .concurrency = .reentrant, // all functions are pure
    .model_after = "RFC 4226 / RFC 6238 reference algorithms (pseudocode in the RFCs)",
    .deps = .{}, // std.crypto.auth.hmac only
};

/// HMAC hash function for the OTP, per RFC 6238 §1.2. RFC 4226 HOTP is
/// defined over SHA-1 only; RFC 6238 extends the same construction to
/// SHA-256 and SHA-512.
pub const Algorithm = enum {
    sha1,
    sha256,
    sha512,

    fn Hmac(comptime alg: Algorithm) type {
        return switch (alg) {
            .sha1 => std.crypto.auth.hmac.HmacSha1,
            .sha256 => std.crypto.auth.hmac.sha2.HmacSha256,
            .sha512 => std.crypto.auth.hmac.sha2.HmacSha512,
        };
    }
};

/// Supported code lengths: 1..9 decimal digits. RFC 4226 §5.3 requires at
/// least 6 in deployments (6..8 is what authenticator apps use); 9 is the
/// hard upper bound because the truncated value is 31 bits (< 10^10) and
/// 10^d must fit in u32. Enforced with an assert (illegal digits is a
/// caller bug, not a runtime condition).
pub const min_digits: u5 = 1;
pub const max_digits: u5 = 9;

/// 10^d for d in 0..9.
const pow10 = [_]u32{
    1,       10,        100,        1_000,       10_000,
    100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000,
};

// ── HOTP (RFC 4226) ─────────────────────────────────────────────────────────

/// RFC 4226 §5.3 Step 1+2: `HMAC-alg(key, counter)` (counter as 8-byte
/// big-endian) followed by dynamic truncation — returns the 31-bit integer
/// `P` *before* the `mod 10^digits` reduction (RFC 4226 calls it
/// `Snum`/`DT(HS)`; e.g. count 0 of the Appendix D vectors is
/// `1284755224`, which becomes the 6-digit code `755224`).
///
/// Dynamic truncation (§5.3, extended to longer digests by RFC 6238 the
/// same way): `offset` = low 4 bits of the *last* digest byte; `P` = the 4
/// digest bytes at `offset` read big-endian with the top bit masked off.
pub fn dynamicTruncate(comptime alg: Algorithm, key: []const u8, counter: u64) u32 {
    const H = alg.Hmac();
    var msg: [8]u8 = undefined;
    std.mem.writeInt(u64, &msg, counter, .big);
    var mac: [H.mac_length]u8 = undefined;
    H.create(&mac, &msg, key);
    const offset: usize = mac[H.mac_length - 1] & 0x0f;
    return std.mem.readInt(u32, mac[offset..][0..4], .big) & 0x7fff_ffff;
}

/// RFC 4226 HOTP: `Truncate(HMAC-alg(key, counter)) mod 10^digits`,
/// returned as a number. Left-zero-pad to `digits` when displaying (use
/// `hotpFmt` / `fmtCode` for the exact ASCII form). `digits` must be in
/// `min_digits..max_digits` (asserted).
pub fn hotp(comptime alg: Algorithm, key: []const u8, counter: u64, digits: u5) u32 {
    std.debug.assert(digits >= min_digits and digits <= max_digits);
    return dynamicTruncate(alg, key, counter) % pow10[digits];
}

/// Write `code` as exactly `digits` ASCII decimal digits, left-padded with
/// '0', into the front of `out`; returns the written slice `out[0..digits]`.
/// Asserts `out.len >= digits` and `code < 10^digits`.
pub fn fmtCode(code: u32, digits: u5, out: []u8) []u8 {
    std.debug.assert(digits >= min_digits and digits <= max_digits);
    std.debug.assert(out.len >= digits);
    std.debug.assert(code < pow10[digits]);
    var rem = code;
    var i: usize = digits;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast('0' + rem % 10);
        rem /= 10;
    }
    return out[0..digits];
}

/// `hotp` + `fmtCode` in one call: the zero-left-padded ASCII code (what an
/// authenticator app displays). Returns `out[0..digits]`.
pub fn hotpFmt(comptime alg: Algorithm, key: []const u8, counter: u64, digits: u5, out: []u8) []u8 {
    return fmtCode(hotp(alg, key, counter, digits), digits, out);
}

// ── TOTP (RFC 6238) ─────────────────────────────────────────────────────────

/// RFC 6238 §4.2: the time-step counter `T = floor((unix_time - t0) /
/// period)`. Asserts `period != 0` and `unix_time >= t0` (this module
/// takes unsigned unix time; pre-1970 clocks are out of scope).
pub fn timeStep(unix_time: u64, period: u32, t0: u64) u64 {
    std.debug.assert(period != 0);
    std.debug.assert(unix_time >= t0);
    return (unix_time - t0) / period;
}

/// RFC 6238 TOTP: `HOTP(key, T)` with `T = floor((unix_time - t0) /
/// period)`. RFC defaults: `period = 30`, `t0 = 0`. The caller supplies
/// `unix_time` (no wall-clock is read here).
pub fn totp(comptime alg: Algorithm, key: []const u8, unix_time: u64, period: u32, t0: u64, digits: u5) u32 {
    return hotp(alg, key, timeStep(unix_time, period, t0), digits);
}

/// `totp` + `fmtCode`: the zero-left-padded ASCII code. Returns
/// `out[0..digits]`.
pub fn totpFmt(comptime alg: Algorithm, key: []const u8, unix_time: u64, period: u32, t0: u64, digits: u5, out: []u8) []u8 {
    return fmtCode(totp(alg, key, unix_time, period, t0, digits), digits, out);
}

/// Verify a submitted TOTP `code` against the time steps within
/// `±skew_steps` of the step containing `unix_time` (RFC 6238 §5.2
/// resynchronization window; `skew_steps = 1` is the common "accept the
/// previous/next 30s code" policy, `0` = exact step only). Steps that
/// would underflow below `t0` are skipped.
///
/// The whole window is always evaluated — no early exit on a match — so
/// the *number* of HMAC evaluations does not leak which step matched, and
/// the code equality is checked with `std.crypto.timing_safe.eql`, so the
/// compare itself carries no data-dependent branch on the expected code.
/// (OTP codes are low-entropy short-lived secrets; the guessing attack to
/// rate-limit is online submission, per RFC 4226 §7.3.)
pub fn totpVerify(comptime alg: Algorithm, key: []const u8, unix_time: u64, period: u32, t0: u64, digits: u5, code: u32, skew_steps: u32) bool {
    const step = timeStep(unix_time, period, t0);
    const skew: u64 = skew_steps;
    var matched: u1 = 0;
    var i: u64 = 0;
    while (i <= 2 * skew) : (i += 1) {
        // Candidate step = step - skew + i; skip while it would underflow
        // below step 0 (i.e. predate t0).
        if (step + i < skew) continue;
        const candidate = hotp(alg, key, step + i - skew, digits);
        // Constant-time equality over the 4-byte code representation. A
        // scalar `u32 ==` is already a single-instruction (constant-time)
        // compare, but `timing_safe.eql` makes the intent explicit and
        // keeps any future refactor from reintroducing a branch on `code`.
        const eq = std.crypto.timing_safe.eql([4]u8, @bitCast(candidate), @bitCast(code));
        matched |= @intFromBool(eq);
    }
    return matched == 1;
}

// ── tests ───────────────────────────────────────────────────────────────────

test "fmtCode zero-pads" {
    var buf: [9]u8 = undefined;
    try std.testing.expectEqualStrings("007081804", fmtCode(7_081_804, 9, &buf));
    try std.testing.expectEqualStrings("000000", fmtCode(0, 6, &buf));
    try std.testing.expectEqualStrings("755224", fmtCode(755_224, 6, &buf));
}

test "totpVerify accepts the correct code and rejects wrong ones (constant-time compare)" {
    // RFC 6238 Appendix B secret (SHA-1, "12345678901234567890").
    const key = "12345678901234567890";
    const period: u32 = 30;
    const t0: u64 = 0;
    const digits: u5 = 8;
    const unix_time: u64 = 59; // step 1; RFC vector code = 94287082.

    const correct = totp(.sha1, key, unix_time, period, t0, digits);
    try std.testing.expectEqual(@as(u32, 94287082), correct);

    // Exact step (skew 0): correct accepted, off-by-one rejected.
    try std.testing.expect(totpVerify(.sha1, key, unix_time, period, t0, digits, correct, 0));
    try std.testing.expect(!totpVerify(.sha1, key, unix_time, period, t0, digits, correct +% 1, 0));
    try std.testing.expect(!totpVerify(.sha1, key, unix_time, period, t0, digits, 0, 0));

    // The previous step's code is rejected at skew 0 but accepted at skew 1.
    const prev = totp(.sha1, key, unix_time + period, period, t0, digits); // step 2 code
    try std.testing.expect(!totpVerify(.sha1, key, unix_time, period, t0, digits, prev, 0));
    try std.testing.expect(totpVerify(.sha1, key, unix_time + period, period, t0, digits, prev, 1));

    // The code compare must go through the constant-time primitive: a plain
    // `u32 ==` would still pass this, but referencing the symbol here pins the
    // dependency so a refactor cannot silently drop it.
    try std.testing.expect(std.crypto.timing_safe.eql([4]u8, @as([4]u8, @bitCast(correct)), @as([4]u8, @bitCast(correct))));
    try std.testing.expect(!std.crypto.timing_safe.eql([4]u8, @as([4]u8, @bitCast(correct)), @as([4]u8, @bitCast(correct +% 1))));
}

test {
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}
