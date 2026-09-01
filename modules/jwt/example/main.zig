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
//! The second half does the same for a **post-quantum** token (ML-DSA-65,
//! RFC 9964) delivered through a JWKS with a `kty:"AKP"` key — the surface
//! this module gained most recently, and the one a caller is most likely to
//! wire up wrong. It is here because nothing else crosses the published
//! boundary for that path: the module's own ML-DSA tests all live inside the
//! test root.
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

    try postQuantum(gpa);
}

/// The RFC 9964 path, end to end over the published surface: mint an ML-DSA-65
/// token, publish the public half as a `kty:"AKP"` JWK, and verify by `kid`.
///
/// A deterministic seed keeps the example reproducible; a real issuer draws
/// its key from a CSPRNG and never lets the private half near the JWKS —
/// which `parseJwksSource(.network)` now enforces, refusing any published key
/// that carries `d` or `priv`.
fn postQuantum(gpa: std.mem.Allocator) !void {
    const kp = try jwt.MlDsa65.KeyPair.generateDeterministic([_]u8{0x5a} ** 32);

    // The issuer's side: sign `header.payload` with the raw FIPS-204
    // signature, no framing and an empty context — what RFC 9964 §2 fixes.
    const signing_input =
        "eyJhbGciOiJNTC1EU0EtNjUiLCJraWQiOiJwcTEifQ" ++
        "." ++
        "eyJpc3MiOiJodHRwczovL29wLmV4YW1wbGUiLCJhdWQiOiJhcGk6Ly9zdmMiLCJleHAiOjIwMDAwMDAwMDB9";
    const sig = try kp.sign(signing_input, null);
    const sig_bytes = sig.toBytes();

    var token_buf: [8192]u8 = undefined;
    var w = std.Io.Writer.fixed(&token_buf);
    try w.writeAll(signing_input ++ ".");
    var sig_b64: [6000]u8 = undefined;
    try w.writeAll(sig_b64[0..std.base64.url_safe_no_pad.Encoder.encode(&sig_b64, &sig_bytes).len]);
    const pq_token = w.buffered();

    // The resource server's side: the issuer's published JWKS.
    var pub_b64: [4000]u8 = undefined;
    const pk_bytes = kp.public_key.toBytes();
    const pub_s = pub_b64[0..std.base64.url_safe_no_pad.Encoder.encode(&pub_b64, &pk_bytes).len];

    var jwks_doc: std.ArrayList(u8) = .empty;
    defer jwks_doc.deinit(gpa);
    try jwks_doc.appendSlice(gpa, "{\"keys\":[{\"kty\":\"AKP\",\"kid\":\"pq1\",\"use\":\"sig\",\"alg\":\"ML-DSA-65\",\"pub\":\"");
    try jwks_doc.appendSlice(gpa, pub_s);
    try jwks_doc.appendSlice(gpa, "\"}]}");

    var jwks = try jwt.parseJwksSource(gpa, jwks_doc.items, .network);
    defer jwks.deinit();

    var pq = try jwt.parseVerifyJwks(gpa, pq_token, jwks, .{
        .now_s = 1_700_000_000,
        .issuer = .{ .required = "https://op.example" },
        .audience = .{ .required = "api://svc" },
    });
    defer pq.deinit();
    std.debug.print("accepted: ML-DSA-65 token by kid, iss={s}\n", .{pq.claims.iss.?});

    // The same JWKS with the issuer's private seed left in it. Published, that
    // seed lets anyone mint tokens for this issuer, so the key is refused and
    // the reason says which — a misconfiguration that must not verify quietly.
    var leaky: std.ArrayList(u8) = .empty;
    defer leaky.deinit(gpa);
    try leaky.appendSlice(gpa, "{\"keys\":[{\"kty\":\"AKP\",\"kid\":\"pq1\",\"alg\":\"ML-DSA-65\",\"priv\":\"AAAA\",\"pub\":\"");
    try leaky.appendSlice(gpa, pub_s);
    try leaky.appendSlice(gpa, "\"}]}");

    var leaked = try jwt.parseJwksSource(gpa, leaky.items, .network);
    defer leaked.deinit();
    std.debug.print("rejected: published private key, {d} usable key(s), reason={s}\n", .{
        leaked.keys.len,
        @tagName(leaked.skipped[0].reason),
    });
}
