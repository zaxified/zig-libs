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
//! `otpauth` parses and formats the `otpauth://totp/...` / `otpauth://hotp/...`
//! provisioning URIs authenticator apps scan (secret in base32, via the
//! `base32` module); the parser is bounded and allocation-free.
//!
//! Provenance: clean-room from RFC 4226 / RFC 6238 (public IETF
//! specifications); test vectors transcribed from the RFC appendices.
//! See `../NOTICE`.

const std = @import("std");
const burn = @import("burn.zig");

/// `otpauth://` provisioning URIs: `parse` (bounded, allocation-free) and
/// `format`. See `otpauth.zig`.
pub const otpauth = @import("otpauth.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "HOTP + TOTP one-time passwords (RFC 4226 / RFC 6238) — the 2FA-authenticator primitive; caller supplies the counter/time (no wall clock); `otpauth://` provisioning-URI parse/format (base32 secrets).",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure computation, allocation-free
    .role = .util,
    .concurrency = .reentrant, // all functions are pure
    .model_after = "RFC 4226 / RFC 6238 reference algorithms (pseudocode in the RFCs)",
    .deps = .{"base32"}, // secret decoding/encoding for otpauth:// URIs; HMAC is std.crypto.auth.hmac
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
///
/// Dead-stack: the HMAC runs one frame down under a burn (`burn.zig`); every
/// other code function here reaches the key only through this one.
pub fn dynamicTruncate(comptime alg: Algorithm, key: []const u8, counter: u64) u32 {
    return burn.run(burn.otp_burn, u32, dynamicTruncateBody, .{ alg, key, counter });
}

fn dynamicTruncateBody(comptime alg: Algorithm, key: []const u8, counter: u64) u32 {
    const H = alg.Hmac();
    var msg: [8]u8 = undefined;
    std.mem.writeInt(u64, &msg, counter, .big);
    var mac: [H.mac_length]u8 = undefined;
    H.create(&mac, &msg, key);
    return truncateCt(H.mac_length, &mac);
}

/// RFC 4226 §5.3 dynamic truncation, constant time. Not
/// `mac[offset..][0..4]`: the offset is the low nibble of a MAC under the
/// secret key, so indexing by it is a secret-dependent load address (memcheck
/// reports it: 18 contexts, ctgrind `otp/code`, 2026-10-10; 0 after). All
/// 16 candidate windows are read and the one at `offset` is selected with a
/// mask built from a borrow.
fn truncateCt(comptime n: usize, mac: *const [n]u8) u32 {
    const offset: u32 = mac[n - 1] & 0x0f;
    var p: u32 = 0;
    inline for (0..16) |o| {
        const d: u32 = @as(u32, o) ^ offset; // 0 iff o == offset (both < 16)
        const sel: u32 = 0 -% ((d -% 1) >> 31); // all-ones iff d == 0
        p |= sel & std.mem.readInt(u32, mac[o..][0..4], .big);
    }
    return p & 0x7fff_ffff;
}

test "truncateCt equals the RFC 4226 indexed truncation for every offset" {
    var mac: [20]u8 = undefined;
    for (&mac, 0..) |*b, i| b.* = @truncate(0x91 +% i *% 37);
    for (0..16) |o| {
        mac[19] = (mac[19] & 0xf0) | @as(u8, @intCast(o));
        const want = std.mem.readInt(u32, mac[o..][0..4], .big) & 0x7fff_ffff;
        try std.testing.expectEqual(want, truncateCt(20, &mac));
    }
}

/// RFC 4226 HOTP: `Truncate(HMAC-alg(key, counter)) mod 10^digits`,
/// returned as a number. Left-zero-pad to `digits` when displaying (use
/// `hotpFmt` / `fmtCode` for the exact ASCII form). `digits` must be in
/// `min_digits..max_digits` (asserted).
pub fn hotp(comptime alg: Algorithm, key: []const u8, counter: u64, digits: u5) u32 {
    std.debug.assert(digits >= min_digits and digits <= max_digits);
    return dynamicTruncate(alg, key, counter) % pow10[digits];
}

pub const FmtCodeError = error{
    /// `out.len < digits`. Returned rather than asserted: `out` is a
    /// caller-supplied buffer, and ReleaseFast compiles the assert (and the
    /// bounds check on the `out[i]` writes below) out together, turning an
    /// undersized buffer into a silent out-of-bounds write in the build
    /// that ships.
    OutputTooSmall,
};

/// Write `code` as exactly `digits` ASCII decimal digits, left-padded with
/// '0', into the front of `out`; returns the written slice `out[0..digits]`.
/// `out.len < digits` is `error.OutputTooSmall`. Asserts `code < 10^digits`
/// (a malformed `code`/`digits` pairing is a caller bug, not a runtime
/// condition — `code` only ever comes from this module's own `hotp`/`totp`,
/// which cannot produce a value out of range for their own `digits`).
pub fn fmtCode(code: u32, digits: u5, out: []u8) FmtCodeError![]u8 {
    std.debug.assert(digits >= min_digits and digits <= max_digits);
    if (out.len < digits) return error.OutputTooSmall;
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
pub fn hotpFmt(comptime alg: Algorithm, key: []const u8, counter: u64, digits: u5, out: []u8) FmtCodeError![]u8 {
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
pub fn totpFmt(comptime alg: Algorithm, key: []const u8, unix_time: u64, period: u32, t0: u64, digits: u5, out: []u8) FmtCodeError![]u8 {
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

// ── HOTP verification with look-ahead (RFC 4226 §7.4–7.5) ───────────────────

/// Hard upper bound on the look-ahead window of `hotpVerify` / `hotpResync`.
/// RFC 4226 §7.4 wants a small window; every extra position is one more HMAC
/// and one more online-guessing chance (§7.3), so a caller cannot ask for an
/// unbounded sweep (`error.WindowTooLarge`).
pub const max_hotp_window: u32 = 1000;

pub const HotpVerifyError = error{
    /// `window > max_hotp_window`.
    WindowTooLarge,
};

/// Constant-time equality of two codes.
fn eqCode(a: u32, b: u32) bool {
    return std.crypto.timing_safe.eql([4]u8, @bitCast(a), @bitCast(b));
}

/// Verify a submitted HOTP `code` against the counters `counter ..
/// counter + window` (RFC 4226 §7.4 look-ahead window; `window = 0` means
/// the exact counter only). `counter` is the server's stored next-expected
/// counter. Returns the matched counter, or null when none matches; on a
/// match the caller must store `matched + 1` as the new counter (§7.2) and
/// should rate-limit failures (§7.3). If several positions produce the same
/// code, the lowest is returned.
///
/// The whole window is always evaluated (no early exit on a match), so the
/// HMAC count does not leak which position matched, and each code is compared
/// with `std.crypto.timing_safe.eql`; the matched counter is picked by mask.
/// The counter `maxInt(u64)` is never a candidate, so `matched + 1` cannot
/// overflow; candidates beyond it are skipped (a public condition). `window >
/// max_hotp_window` is `error.WindowTooLarge`.
pub fn hotpVerify(comptime alg: Algorithm, key: []const u8, counter: u64, digits: u5, code: u32, window: u32) HotpVerifyError!?u64 {
    if (window > max_hotp_window) return error.WindowTooLarge;
    var hit: u64 = 0; // all-ones once a match was taken
    var found: u64 = 0;
    var i: u64 = 0;
    while (i <= window) : (i += 1) {
        if (counter > std.math.maxInt(u64) - 1 - i) break; // counter + i would reach maxInt(u64)
        const c = counter + i;
        const eq = eqCode(hotp(alg, key, c, digits), code);
        const take: u64 = (0 -% @as(u64, @intFromBool(eq))) & ~hit;
        found = (found & ~take) | (c & take);
        hit |= take;
    }
    return if (hit != 0) found else null;
}

/// RFC 4226 §7.4 resynchronisation: the user presses the token twice and
/// submits two consecutive codes. Looks for a position `c` in `counter ..
/// counter + window` with `HOTP(c) == code1` and `HOTP(c + 1) == code2`, and
/// returns `c + 1` (the counter of the second code — store `result + 1` as
/// the new counter, as for `hotpVerify`), or null. Same bounds, constant-HMAC
/// count and constant-time compares as `hotpVerify`; the lowest matching `c`
/// wins and neither `c` nor `c + 1` may be `maxInt(u64)`.
pub fn hotpResync(comptime alg: Algorithm, key: []const u8, counter: u64, digits: u5, code1: u32, code2: u32, window: u32) HotpVerifyError!?u64 {
    if (window > max_hotp_window) return error.WindowTooLarge;
    var hit: u64 = 0;
    var found: u64 = 0;
    var prev_eq = false; // HOTP(counter + i - 1) == code1
    var i: u64 = 0;
    while (i <= @as(u64, window) + 1) : (i += 1) {
        if (counter > std.math.maxInt(u64) - 1 - i) break;
        const c = counter + i;
        const cur = hotp(alg, key, c, digits);
        // i == 0 has no predecessor: prev_eq is false there.
        const both = prev_eq and eqCode(cur, code2);
        const take: u64 = (0 -% @as(u64, @intFromBool(both))) & ~hit;
        found = (found & ~take) | (c & take);
        hit |= take;
        prev_eq = eqCode(cur, code1);
    }
    return if (hit != 0) found else null;
}

// ── tests ───────────────────────────────────────────────────────────────────

test "fmtCode zero-pads" {
    var buf: [9]u8 = undefined;
    try std.testing.expectEqualStrings("007081804", try fmtCode(7_081_804, 9, &buf));
    try std.testing.expectEqualStrings("000000", try fmtCode(0, 6, &buf));
    try std.testing.expectEqualStrings("755224", try fmtCode(755_224, 6, &buf));
}

// fmtCode used to guard out.len >= digits with std.debug.assert, then write
// out[i] in a loop. ReleaseFast compiles the assert (and the bounds check on
// those writes) out together, so an out buffer undersized for the requested
// digit count was a silent out-of-bounds write in the build that ships.
// Written against min_digits/max_digits rather than a literal so it keeps
// measuring the mechanism if those move.
test "fmtCode: an out buffer one byte short of digits is an error, not an assert" {
    var buf: [max_digits]u8 = undefined;
    try std.testing.expectError(error.OutputTooSmall, fmtCode(0, max_digits, buf[0 .. max_digits - 1]));
    // Exact size still works.
    _ = try fmtCode(0, max_digits, buf[0..max_digits]);
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

const rfc4226_codes = [_]u32{ 755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489 };
const rfc4226_key = "12345678901234567890";

test "hotpVerify: RFC 4226 Appendix D, exact and look-ahead" {
    // window 0: only the exact counter.
    for (rfc4226_codes, 0..) |code, n| {
        try std.testing.expectEqual(@as(?u64, n), try hotpVerify(.sha1, rfc4226_key, n, 6, code, 0));
    }
    try std.testing.expectEqual(@as(?u64, null), try hotpVerify(.sha1, rfc4226_key, 0, 6, rfc4226_codes[1], 0));
    // The server is at 2, the token drifted to 7: needs window >= 5.
    try std.testing.expectEqual(@as(?u64, null), try hotpVerify(.sha1, rfc4226_key, 2, 6, rfc4226_codes[7], 4));
    try std.testing.expectEqual(@as(?u64, 7), try hotpVerify(.sha1, rfc4226_key, 2, 6, rfc4226_codes[7], 5));
    try std.testing.expectEqual(@as(?u64, 9), try hotpVerify(.sha1, rfc4226_key, 0, 6, rfc4226_codes[9], 100));
    // A counter behind the server's is never accepted (replay).
    try std.testing.expectEqual(@as(?u64, null), try hotpVerify(.sha1, rfc4226_key, 5, 6, rfc4226_codes[4], 100));
    // Wrong code across the window.
    try std.testing.expectEqual(@as(?u64, null), try hotpVerify(.sha1, rfc4226_key, 0, 6, 123456, 50));
}

test "hotpVerify: window cap, lowest match, counter ceiling" {
    try std.testing.expectEqual(@as(?u64, 0), try hotpVerify(.sha1, rfc4226_key, 0, 6, rfc4226_codes[0], max_hotp_window));
    try std.testing.expectError(error.WindowTooLarge, hotpVerify(.sha1, rfc4226_key, 0, 6, rfc4226_codes[0], max_hotp_window + 1));
    try std.testing.expectError(error.WindowTooLarge, hotpVerify(.sha1, rfc4226_key, 0, 6, 0, std.math.maxInt(u32)));
    // 1-digit codes collide inside a window: the lowest counter wins.
    const one = hotp(.sha1, rfc4226_key, 3, 1);
    const m = (try hotpVerify(.sha1, rfc4226_key, 0, 1, one, 100)).?;
    try std.testing.expect(m <= 3);
    try std.testing.expectEqual(one, hotp(.sha1, rfc4226_key, m, 1));
    for (0..m) |c| try std.testing.expect(hotp(.sha1, rfc4226_key, c, 1) != one);
    // Near the u64 ceiling: window is clipped, maxInt itself is never accepted, no overflow.
    const top = std.math.maxInt(u64);
    const c1 = hotp(.sha1, rfc4226_key, top - 1, 6);
    try std.testing.expectEqual(@as(?u64, top - 1), try hotpVerify(.sha1, rfc4226_key, top - 3, 6, c1, 10));
    const c2 = hotp(.sha1, rfc4226_key, top, 6);
    try std.testing.expectEqual(@as(?u64, null), try hotpVerify(.sha1, rfc4226_key, top - 3, 6, c2, 10));
    try std.testing.expectEqual(@as(?u64, null), try hotpVerify(.sha1, rfc4226_key, top, 6, c2, 10));
}

test "hotpResync: two consecutive RFC 4226 codes" {
    // Consecutive pairs found; result is the counter of the second code.
    try std.testing.expectEqual(@as(?u64, 8), try hotpResync(.sha1, rfc4226_key, 2, 6, rfc4226_codes[7], rfc4226_codes[8], 10));
    try std.testing.expectEqual(@as(?u64, 1), try hotpResync(.sha1, rfc4226_key, 0, 6, rfc4226_codes[0], rfc4226_codes[1], 0));
    try std.testing.expectEqual(@as(?u64, 9), try hotpResync(.sha1, rfc4226_key, 0, 6, rfc4226_codes[8], rfc4226_codes[9], 8));
    // First code at the window's last position is allowed; one further is not.
    try std.testing.expectEqual(@as(?u64, 8), try hotpResync(.sha1, rfc4226_key, 2, 6, rfc4226_codes[7], rfc4226_codes[8], 5));
    try std.testing.expectEqual(@as(?u64, null), try hotpResync(.sha1, rfc4226_key, 2, 6, rfc4226_codes[7], rfc4226_codes[8], 4));
    // Non-consecutive, reversed, and behind-the-counter pairs are refused.
    try std.testing.expectEqual(@as(?u64, null), try hotpResync(.sha1, rfc4226_key, 0, 6, rfc4226_codes[3], rfc4226_codes[5], 20));
    try std.testing.expectEqual(@as(?u64, null), try hotpResync(.sha1, rfc4226_key, 0, 6, rfc4226_codes[4], rfc4226_codes[3], 20));
    try std.testing.expectEqual(@as(?u64, null), try hotpResync(.sha1, rfc4226_key, 5, 6, rfc4226_codes[3], rfc4226_codes[4], 20));
    // Same code twice is not a pair unless the sequence really repeats.
    try std.testing.expectEqual(@as(?u64, null), try hotpResync(.sha1, rfc4226_key, 0, 6, rfc4226_codes[2], rfc4226_codes[2], 20));
    try std.testing.expectError(error.WindowTooLarge, hotpResync(.sha1, rfc4226_key, 0, 6, 0, 0, max_hotp_window + 1));
    // maxInt(u64) is never part of a pair.
    const top = std.math.maxInt(u64);
    const a = hotp(.sha1, rfc4226_key, top - 1, 6);
    const b = hotp(.sha1, rfc4226_key, top, 6);
    try std.testing.expectEqual(@as(?u64, null), try hotpResync(.sha1, rfc4226_key, top - 2, 6, a, b, 10));
    const z = hotp(.sha1, rfc4226_key, top - 2, 6);
    try std.testing.expectEqual(@as(?u64, top - 1), try hotpResync(.sha1, rfc4226_key, top - 3, 6, z, a, 10));
}

test {
    _ = @import("otpauth.zig");
    _ = @import("fuzz_test.zig");
    _ = @import("stackprobe_test.zig");
    _ = @import("kat_vectors.zig");
    _ = @import("kat_test.zig");
}
