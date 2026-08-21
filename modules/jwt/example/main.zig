// SPDX-License-Identifier: MIT

//! What a resource server does with `jwt`: take a Bearer token off a
//! request, verify its signature, and refuse anything that doesn't check
//! out — by name, so the caller can answer with the right HTTP status
//! instead of a generic 500.
//!
//! The token here is the RFC 7515 §A.1 / RFC 7519 §3.1 known-answer HS256
//! vector — a real, spec-published token, not one this file invents — so
//! the "verify" step is checking actual HMAC-SHA256 math, not a stub.
//! `jwt.Options.audience` has no default (RFC 8725 §3.9): this legacy
//! example token carries no `aud` claim at all, so accepting it means
//! writing `.any`, the module's explicit, greppable opt-out — exactly the
//! conscious choice the module forces on every caller.
//!
//! Built against the PUBLISHED module (`@import("jwt")`) only — no
//! `test_deps`, no access to the module's own test vectors or helpers.

const std = @import("std");
const jwt = @import("jwt");

// RFC 7515 §A.1.1 / RFC 7519 §3.1: header {"typ":"JWT","alg":"HS256"},
// payload {"iss":"joe","exp":1300819380,"http://example.com/is_root":true}.
const bearer_token =
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9" ++
    "." ++
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ" ++
    "." ++
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

// RFC 7515 §A.1.1's HMAC key, base64url — this is what the issuer and the
// resource server share out of band; a consumer would load it from config.
const hmac_key_b64 = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow";

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var key_buf: [64]u8 = undefined;
    const dec = std.base64.url_safe_no_pad.Decoder;
    const key_len = try dec.calcSizeForSlice(hmac_key_b64);
    try dec.decode(key_buf[0..key_len], hmac_key_b64);
    const secret = key_buf[0..key_len];

    // The token's own `exp` is 2011-03-22T18:43:00Z — treat that instant as
    // "now" so the happy path doesn't also have to fight claim expiry.
    const now_s: i64 = 1300819380 - 1;

    // ── accept ───────────────────────────────────────────────────────────
    // This RFC-era token carries no `aud` at all, so `.any` is the only
    // honest choice — writing `.required = "…"` here would always fail
    // (AudienceMismatch), which is the whole point of making the choice
    // mandatory rather than defaulted.
    var token = try jwt.parseAndVerify(gpa, bearer_token, .{ .hmac = secret }, .{
        .now_s = now_s,
        .issuer = .{ .required = "joe" },
        .audience = .any,
    });
    defer token.deinit();
    std.debug.print("accepted: iss={s} is_root={}\n", .{
        token.claims.iss.?,
        token.claims.claimBool("http://example.com/is_root").?,
    });

    // ── reject: wrong key ───────────────────────────────────────────────
    // A resource server holding the WRONG shared secret (misconfigured, or
    // an attacker guessing) must get a named error it can act on — log and
    // answer 401, never a panic or a silent accept.
    const wrong_secret = "not-the-real-secret";
    _ = jwt.parseAndVerify(gpa, bearer_token, .{ .hmac = wrong_secret }, .{
        .now_s = now_s,
        .issuer = .{ .required = "joe" },
        .audience = .any,
    }) catch |err| switch (err) {
        error.BadSignature => {
            std.debug.print("rejected: BadSignature (wrong key)\n", .{});
        },
        else => return err,
    };

    // ── reject: mandatory audience, no silent skip ──────────────────────
    // Pinning an audience this token never claims must fail closed, not
    // fall back to "no audience configured, so anything goes".
    _ = jwt.parseAndVerify(gpa, bearer_token, .{ .hmac = secret }, .{
        .now_s = now_s,
        .issuer = .{ .required = "joe" },
        .audience = .{ .required = "api://my-service" },
    }) catch |err| switch (err) {
        error.AudienceMismatch => {
            std.debug.print("rejected: AudienceMismatch (token has no aud)\n", .{});
        },
        else => return err,
    };
}
