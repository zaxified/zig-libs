// SPDX-License-Identifier: MIT

//! What a 2FA authenticator app AND the server verifying it do with `otp`:
//! generate the zero-padded display code for a sequence of HOTP counters
//! and TOTP timestamps (all three hash algorithms), then run the server
//! side's resynchronization-window check against codes the client's clock
//! is ahead of, behind, or badly stale on.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).
//!
//! No `std.heap.DebugAllocator`: this module allocates nowhere (module doc
//! comment: "No allocator, no internal clock or RNG").
//!
//! No `otpauth://` URI form: the module has none (its whole surface is
//! `hotp`/`totp`/`fmtCode`/`totpVerify` plus the RFC math underneath) — so
//! that part of the brief has nothing to exercise here. Noted rather than
//! invented.
//!
//! No named-error negative vectors for HOTP/TOTP itself: `hotp`/`totp` take
//! a caller-owned raw key and counter/time (not untrusted wire bytes), so
//! there is nothing to fail-closed parse. `fmtCode`/`hotpFmt`/`totpFmt` DO
//! return `FmtCodeError!` (an undersized `out` buffer is `error.
//! OutputTooSmall`, not a panic) but every call below sizes its buffer
//! correctly, so that path is `try`d rather than exercised negatively here.
//! The module's one fallible-in-spirit BEHAVIORAL surface is `totpVerify`'s
//! boolean accept/reject, which IS the RFC 6238 resynchronization behavior a
//! server actually depends on — so that is what the "negative" section below
//! exercises, per CONVENTIONS.md §7.2's carve-out for a genuinely infallible
//! (behaviorally) public surface.
//!
//! `modules/otp/src/kat_test.zig` already drives RFC 4226 Appendix D (all
//! counts 0-9, SHA-1) and the full RFC 6238 Appendix B table (6 times ×
//! SHA-1/SHA-256/SHA-512) byte-exact through this module, all under the
//! RFCs' own published secret ("12345678901234567890"/...-32/...-64). This
//! file does NOT restate those — every code below is computed from a FRESH
//! secret (SHA-256 of an example-specific label) at counters/times the KAT
//! table never uses.
//!
//! External judge — ACTUALLY RUN: `pyotp` (MIT), a third, independent
//! Python OTP library distinct from the RFC authors' own vectors this
//! module is already checked against, computed every HOTP/TOTP code below
//! at authoring time; every `expected_*` literal is its output, and all of
//! them matched.

const std = @import("std");
const otp = @import("otp");

// SHA-256("zig-libs otp example secret") — a fresh 32-byte secret, not the
// RFC's own "12345678901234567890"/-32/-64 test key.
const secret_hex = "0077c6dff0553c7a756f4a7860a4e9af850fc1b76d12cc6f8e72eb008ef5ad9f";

fn secretBytes() [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, secret_hex) catch unreachable;
    return out;
}

pub fn main() !void {
    const secret = secretBytes();

    // ── HOTP: an authenticator app's counter-based code sequence ──────────
    // ACTUALLY RUN: `pyotp.HOTP(secret_b32, digits=6, digest=sha1).at(c)`.
    const hotp_cases = [_]struct { counter: u64, expected: []const u8 }{
        .{ .counter = 0, .expected = "867605" },
        .{ .counter = 1, .expected = "987425" },
        .{ .counter = 42, .expected = "859461" },
        .{ .counter = 1_000_000, .expected = "645206" },
    };
    for (hotp_cases) |c| {
        var buf: [6]u8 = undefined;
        const code = try otp.hotpFmt(.sha1, &secret, c.counter, 6, &buf);
        std.debug.assert(std.mem.eql(u8, code, c.expected));
        std.debug.print("HOTP SHA1 counter={d}: {s}\n", .{ c.counter, code });
    }

    // ── TOTP: all three hash algorithms, several timestamps ───────────────
    // ACTUALLY RUN: `pyotp.TOTP(secret_b32, digits=8, digest=<alg>,
    // interval=30).at(t)`.
    const TotpCase = struct { alg: otp.Algorithm, unix_time: u64, expected: []const u8 };
    const totp_cases = [_]TotpCase{
        .{ .alg = .sha1, .unix_time = 0, .expected = "43867605" },
        .{ .alg = .sha256, .unix_time = 0, .expected = "77577200" },
        .{ .alg = .sha512, .unix_time = 0, .expected = "99827555" },
        .{ .alg = .sha1, .unix_time = 59, .expected = "98987425" },
        .{ .alg = .sha256, .unix_time = 59, .expected = "81058191" },
        .{ .alg = .sha512, .unix_time = 59, .expected = "51903603" },
        .{ .alg = .sha1, .unix_time = 1_111_111_109, .expected = "51209950" },
        .{ .alg = .sha256, .unix_time = 1_111_111_109, .expected = "45938421" },
        .{ .alg = .sha512, .unix_time = 1_111_111_109, .expected = "42401939" },
        .{ .alg = .sha1, .unix_time = 20_000_000_000, .expected = "49694118" },
        .{ .alg = .sha256, .unix_time = 20_000_000_000, .expected = "90499732" },
        .{ .alg = .sha512, .unix_time = 20_000_000_000, .expected = "37230227" },
    };
    inline for (.{ otp.Algorithm.sha1, otp.Algorithm.sha256, otp.Algorithm.sha512 }) |alg| {
        for (totp_cases) |c| {
            if (c.alg != alg) continue;
            var buf: [8]u8 = undefined;
            const code = try otp.totpFmt(alg, &secret, c.unix_time, 30, 0, 8, &buf);
            std.debug.assert(std.mem.eql(u8, code, c.expected));
            std.debug.print("TOTP {s} t={d}: {s}\n", .{ @tagName(alg), c.unix_time, code });
        }
    }

    // ── server-side verification: the resynchronization window ────────────
    // A server observes `server_time` and checks a submitted code against
    // the ±1-step window (the common "accept the neighbouring 30s code"
    // policy) — RFC 6238 §5.2. Every case below uses SHA-256, 8 digits,
    // period 30, t0 0, and a server_time/skew this module's own test
    // (SHA-1, RFC's own key, unix_time=59) never touches.
    const period: u32 = 30;
    const digits: u5 = 8;
    const server_time: u64 = 1_700_000_000; // step 56,666,666

    const code_now = otp.totp(.sha256, &secret, server_time, period, 0, digits);
    std.debug.assert(otp.totpVerify(.sha256, &secret, server_time, period, 0, digits, code_now, 1));
    std.debug.print("current-step code accepted at skew=1\n", .{});

    // (1) The PREVIOUS step's code (client clock 30s behind) — accepted
    // within the ±1 window, rejected at exact-match-only (skew=0).
    const code_prev = otp.totp(.sha256, &secret, server_time - period, period, 0, digits);
    std.debug.assert(otp.totpVerify(.sha256, &secret, server_time, period, 0, digits, code_prev, 1));
    std.debug.assert(!otp.totpVerify(.sha256, &secret, server_time, period, 0, digits, code_prev, 0));
    std.debug.print("previous-step code: accepted at skew=1, rejected at skew=0 (expected)\n", .{});

    // (2) A code from TWO steps back — outside even the ±1 window, a stale/
    // replayed submission that must be rejected regardless of skew=1.
    const code_stale = otp.totp(.sha256, &secret, server_time - 2 * period, period, 0, digits);
    std.debug.assert(!otp.totpVerify(.sha256, &secret, server_time, period, 0, digits, code_stale, 1));
    std.debug.print("two-steps-stale code: rejected even at skew=1 (expected)\n", .{});

    // (3) A flat wrong code (not derived from any nearby step at all).
    const wrong_code = code_now +% 1;
    std.debug.assert(wrong_code != code_prev and wrong_code != code_stale);
    std.debug.assert(!otp.totpVerify(.sha256, &secret, server_time, period, 0, digits, wrong_code, 1));
    std.debug.print("unrelated wrong code: rejected (expected)\n", .{});
}
