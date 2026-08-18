// SPDX-License-Identifier: MIT

//! webhooksig — HMAC-SHA256 request/webhook signature signing and
//! verification, plus a `router` middleware that gates inbound webhooks
//! (GitHub style: one `<prefix><hex-mac>` header value) on a valid
//! signature header. Stripe's `Stripe-Signature` (`t=…,v1=…`,
//! timestamp-prefixed payload) is a different construction and is NOT
//! implemented — see README.md's "Scope" section.
//!
//! The sender computes `HMAC-SHA256(secret, raw_body)` and presents it in
//! a header, e.g. `X-Signature-256: sha256=<hex-lowercase>` (GitHub) — the
//! header name and the `sha256=` prefix are configurable. The receiver
//! recomputes the MAC over the exact bytes it received and compares in
//! **constant time** (`std.crypto.timing_safe.eql` over the fixed-size raw
//! MAC — never `std.mem.eql` on the signature, which would leak a
//! byte-at-a-time timing oracle an attacker can walk to forge a
//! signature). A small **secret set** is supported for zero-downtime
//! rotation: every configured secret is tried, OR-accumulated without
//! early exit, so neither which secret matched nor whether any did leaks
//! through timing.
//!
//! ## What it provides
//!
//! - `sign` / `signWithPrefix` — produce the `sha256=<hex>` header value
//!   for an outbound webhook (or a test), into a caller buffer.
//! - `verify` / `verifyWithPrefix` — constant-time check of a presented
//!   header value against a single secret.
//! - `computeHex` — the raw lowercase-hex MAC (no prefix), the building
//!   block both of the above share.
//! - `Verifier` + `Verifier.middleware()` — a `router.Middleware` that
//!   reads the request body, verifies the signature against the (possibly
//!   rotated) secret set and short-circuits **401** on a
//!   missing/mismatched signature, else attaches the read body to
//!   `ctx.data` and continues.
//!
//! ## Reading the body consumes the stream
//!
//! The middleware must read the **entire raw body** to compute the MAC —
//! `ctx.req.reader().allocRemaining(gpa, .limited(max))`. That drains the
//! request stream, so a downstream handler **cannot re-read it** from
//! `ctx.req.reader()`. To make the already-read bytes available, the
//! middleware stashes them on `ctx.data` for the duration of the inner
//! chain; the handler retrieves them with `bodyOf(ctx)`. The buffer is
//! freed when the middleware returns — copy anything kept past the
//! handler.
//!
//! ## Secrets in memory
//!
//! Unlike a bearer-token gate (which can store only a digest and compare
//! digests), an HMAC verifier needs the **raw secret** to recompute the
//! MAC over each body, so `Verifier` retains gpa-owned copies of the
//! secrets for its lifetime. Keep the `Verifier` itself out of any
//! serialized/loggable surface.
//!
//! ## Thread-safety
//!
//! `Verifier` is immutable after `init` (no runtime mutation, no shared
//! counters) — safe to share by `*const`/`*` across all of
//! `http.Server`'s connection threads at once (`.threadsafe`). The
//! free functions are pure.

const std = @import("std");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .server,
    // Immutable after init (secret set + config fixed); no shared mutable
    // state, so sharing a single Verifier across all connection threads is
    // safe without locking.
    .concurrency = .threadsafe,
    .model_after = "GitHub webhook HMAC signatures (sha256=<hex>); RFC 2104 HMAC",
    .deps = .{ "router", "http" },
};

const Allocator = std.mem.Allocator;

/// The MAC primitive: HMAC-SHA256 (RFC 2104 + FIPS 180-4).
pub const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

/// Raw MAC length in bytes (32 for HMAC-SHA256).
pub const mac_length = Hmac.mac_length;

/// Length of the lowercase-hex MAC, without any prefix (64).
pub const signature_hex_len = mac_length * 2;

/// Default header carrying the signature (GitHub's `X-Signature-256`).
pub const default_header = "X-Signature-256";

/// Default value prefix (GitHub's `sha256=`); the hex MAC follows it.
pub const default_prefix = "sha256=";

/// `WWW-Authenticate`-style challenge scheme emitted on rejection. HMAC
/// webhooks have no registered auth scheme; `Signature` names the
/// mechanism for symmetry with the AAA layer's `Bearer` challenge.
pub const default_challenge = "Signature";

// ── pure sign / verify ──────────────────────────────────────────────────────

/// The raw lowercase-hex HMAC-SHA256 of `body` under `secret` (no prefix).
/// This is the value that follows `sha256=` in the header.
pub fn computeHex(secret: []const u8, body: []const u8) [signature_hex_len]u8 {
    var mac: [mac_length]u8 = undefined;
    Hmac.create(&mac, body, secret);
    return std.fmt.bytesToHex(mac, .lower);
}

/// Buffer length `signWithPrefix` needs for a given prefix
/// (`prefix.len + signature_hex_len`).
pub fn signatureBufLen(prefix: []const u8) usize {
    return prefix.len + signature_hex_len;
}

/// Write `<prefix><hex-lowercase-mac>` into `out_buf` and return the
/// written slice. `out_buf` must be at least `signatureBufLen(prefix)`
/// bytes. For outbound webhooks and tests.
pub fn signWithPrefix(prefix: []const u8, secret: []const u8, body: []const u8, out_buf: []u8) []const u8 {
    std.debug.assert(out_buf.len >= prefix.len + signature_hex_len);
    @memcpy(out_buf[0..prefix.len], prefix);
    const hex = computeHex(secret, body);
    @memcpy(out_buf[prefix.len..][0..signature_hex_len], &hex);
    return out_buf[0 .. prefix.len + signature_hex_len];
}

/// `signWithPrefix` with the default `sha256=` prefix (GitHub style).
pub fn sign(secret: []const u8, body: []const u8, out_buf: []u8) []const u8 {
    return signWithPrefix(default_prefix, secret, body, out_buf);
}

/// Decode the raw MAC out of a presented header value: strip `prefix`
/// (surrounding SP/TAB tolerated; the prefix compare is a plain byte
/// compare — the prefix is not secret), then hex-decode the remaining
/// `signature_hex_len` chars (case-insensitive). Returns null when the
/// prefix is absent, the length is wrong, or the hex is malformed — none
/// of which involves the secret, so an early return here leaks nothing
/// about it.
fn presentedMac(prefix: []const u8, presented: []const u8) ?[mac_length]u8 {
    const v = std.mem.trim(u8, presented, " \t");
    if (v.len != prefix.len + signature_hex_len) return null;
    if (!std.mem.eql(u8, v[0..prefix.len], prefix)) return null;
    var out: [mac_length]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, v[prefix.len..]) catch return null;
    return out;
}

/// Constant-time check that `presented` is a valid `<prefix><hex>`
/// signature of `body` under `secret`. The recomputed MAC and the decoded
/// presented MAC are compared with `std.crypto.timing_safe.eql` over the
/// fixed-size raw MAC — never `std.mem.eql` on the signature. A
/// malformed/absent-prefix/wrong-length presented value is simply false.
pub fn verifyWithPrefix(prefix: []const u8, secret: []const u8, body: []const u8, presented: []const u8) bool {
    const got = presentedMac(prefix, presented) orelse return false;
    var want: [mac_length]u8 = undefined;
    Hmac.create(&want, body, secret);
    return std.crypto.timing_safe.eql([mac_length]u8, want, got);
}

/// `verifyWithPrefix` with the default `sha256=` prefix (GitHub style).
pub fn verify(secret: []const u8, body: []const u8, presented: []const u8) bool {
    return verifyWithPrefix(default_prefix, secret, body, presented);
}

// ── the middleware verifier ─────────────────────────────────────────────────

pub const Options = struct {
    /// The primary signing secret (raw bytes; retained). Null + empty
    /// `extra_secrets` is a misconfiguration (asserted) — an HMAC gate
    /// with no secret can verify nothing.
    secret: ?[]const u8 = null,
    /// Additional valid secrets (rotation set): a body signed with **any**
    /// configured secret passes. Add the new secret, migrate senders, then
    /// drop the old one. Retained (raw bytes).
    extra_secrets: []const []const u8 = &.{},
    /// Header carrying the signature (case-insensitive lookup). Copied into
    /// the Verifier. Default `X-Signature-256`.
    header: []const u8 = default_header,
    /// Value prefix before the hex MAC. Copied into the Verifier. Default
    /// `sha256=`. Use `""` for a bare-hex header.
    prefix: []const u8 = default_prefix,
    /// Maximum request body read; a body larger than this is rejected
    /// **413** (before any verification). Bounds memory per request.
    max_body_bytes: usize = 1 << 20, // 1 MiB
    /// `WWW-Authenticate` challenge value on rejection. Copied. Default
    /// `Signature`.
    challenge: []const u8 = default_challenge,
};

/// The signature you attached to `ctx.data` on the success path — the raw
/// body the middleware already read (so the handler need not, and cannot,
/// re-read the consumed stream). Valid only for the duration of the inner
/// chain; `ctx.data` is restored and the buffer freed afterwards.
pub const Attached = struct {
    /// The verified raw request body.
    body: []const u8,
};

/// The verified body the middleware attached to this request, or null when
/// no verifier ran / the slot was not set by this module. Only meaningful
/// below a `Verifier.middleware()` in the chain.
pub fn bodyOf(ctx: *const router.Ctx) ?[]const u8 {
    const p = ctx.data orelse return null;
    const a: *Attached = @ptrCast(@alignCast(p));
    return a.body;
}

pub const Verifier = struct {
    gpa: Allocator,
    /// gpa-owned copies of the raw secrets (rotation set).
    secrets: std.ArrayList([]u8) = .empty,
    /// gpa-owned copies.
    header: []const u8,
    prefix: []const u8,
    challenge: []const u8,
    max_body_bytes: usize,

    /// Build a verifier. Secret/header/prefix slices are copied, so the
    /// caller's buffers need not outlive this call (the secrets *are*
    /// retained, as owned copies). Requires at least one secret.
    pub fn init(gpa: Allocator, options: Options) error{OutOfMemory}!Verifier {
        var secrets: std.ArrayList([]u8) = .empty;
        errdefer {
            for (secrets.items) |s| gpa.free(s);
            secrets.deinit(gpa);
        }
        if (options.secret) |s| {
            std.debug.assert(s.len != 0);
            try secrets.append(gpa, try gpa.dupe(u8, s));
        }
        for (options.extra_secrets) |s| {
            std.debug.assert(s.len != 0);
            try secrets.append(gpa, try gpa.dupe(u8, s));
        }
        std.debug.assert(secrets.items.len != 0); // an HMAC gate needs a secret

        std.debug.assert(options.header.len != 0);
        const header = try gpa.dupe(u8, options.header);
        errdefer gpa.free(header);
        const prefix = try gpa.dupe(u8, options.prefix);
        errdefer gpa.free(prefix);
        const challenge = try gpa.dupe(u8, options.challenge);
        errdefer gpa.free(challenge);

        return .{
            .gpa = gpa,
            .secrets = secrets,
            .header = header,
            .prefix = prefix,
            .challenge = challenge,
            .max_body_bytes = options.max_body_bytes,
        };
    }

    pub fn deinit(v: *Verifier) void {
        for (v.secrets.items) |s| v.gpa.free(s);
        v.secrets.deinit(v.gpa);
        v.gpa.free(v.header);
        v.gpa.free(v.prefix);
        v.gpa.free(v.challenge);
        v.* = undefined;
    }

    /// Number of configured secrets (diagnostics / tests).
    pub fn secretCount(v: *const Verifier) usize {
        return v.secrets.items.len;
    }

    /// Constant-time verification of `presented` against the whole secret
    /// set: every secret is tried and the results OR-accumulated **without
    /// early exit**, so neither which secret matched nor whether any did
    /// leaks through timing. A malformed/absent presented value is false.
    pub fn verifyBody(v: *const Verifier, body: []const u8, presented: []const u8) bool {
        const got = presentedMac(v.prefix, presented) orelse return false;
        var ok = false;
        for (v.secrets.items) |secret| {
            var want: [mac_length]u8 = undefined;
            Hmac.create(&want, body, secret);
            ok = std.crypto.timing_safe.eql([mac_length]u8, want, got) or ok;
        }
        return ok;
    }

    /// A `router.Middleware` gating requests on a valid signature. `state`
    /// is the Verifier — register it before the protected routes; the
    /// Verifier must outlive the Router at a stable address.
    pub fn middleware(v: *Verifier) router.Middleware {
        return .{ .state = v, .run = middlewareRun };
    }

    fn reject(v: *const Verifier, ctx: *router.Ctx) anyerror!void {
        ctx.res.setStatus(401);
        try ctx.res.setHeader("WWW-Authenticate", v.challenge);
        try ctx.res.setHeader("Content-Type", "text/plain");
        try ctx.res.writeAll("Invalid signature\n");
    }
};

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const v: *Verifier = @ptrCast(@alignCast(state.?));

    // Absent signature header → 401 without touching the body.
    const presented = ctx.req.header(v.header) orelse return v.reject(ctx);

    // Read the exact raw bytes to compute the MAC over. This consumes the
    // request stream — the handler retrieves the bytes via bodyOf(ctx).
    const body = ctx.req.reader().allocRemaining(v.gpa, .limited(v.max_body_bytes)) catch |err| switch (err) {
        error.StreamTooLong => {
            ctx.res.setStatus(413);
            try ctx.res.setHeader("Content-Type", "text/plain");
            try ctx.res.writeAll("Payload too large\n");
            return;
        },
        error.OutOfMemory => return error.OutOfMemory,
        else => return err, // ReadFailed → server answers 500
    };
    defer v.gpa.free(body);

    if (!v.verifyBody(body, presented)) return v.reject(ctx);

    // Verified: hand the already-read body to the inner chain via ctx.data.
    var attached: Attached = .{ .body = body };
    const saved = ctx.data;
    ctx.data = &attached;
    defer ctx.data = saved;
    return next.run(ctx);
}

// ── tests: pure sign / verify ───────────────────────────────────────────────

const testing = std.testing;

test "sign → verify round-trip (default sha256= prefix)" {
    const secret = "topsecret";
    const body = "{\"hello\":\"world\"}";
    var buf: [signatureBufLen(default_prefix)]u8 = undefined;
    const value = sign(secret, body, &buf);

    try testing.expect(std.mem.startsWith(u8, value, "sha256="));
    try testing.expectEqual(@as(usize, default_prefix.len + signature_hex_len), value.len);
    try testing.expect(verify(secret, body, value)); // the round-trip
}

test "verify: tampered body / wrong secret / malformed all rejected (constant-time compare)" {
    const secret = "topsecret";
    const body = "payload-bytes";
    var buf: [64 + 8]u8 = undefined;
    const value = sign(secret, body, &buf);

    try testing.expect(verify(secret, body, value)); // baseline pass
    try testing.expect(!verify(secret, "payload-byteS", value)); // one body byte flipped
    try testing.expect(!verify("wrongsecret", body, value)); // wrong secret
    try testing.expect(!verify(secret, body, "sha256=deadbeef")); // wrong length
    try testing.expect(!verify(secret, body, "sha1=" ++ ("0" ** 64))); // wrong prefix
    try testing.expect(!verify(secret, body, value[7..])); // prefix stripped by caller
    try testing.expect(!verify(secret, body, "")); // empty
    // Same-length, single hex nibble flipped → must still be denied (proves
    // it is a full MAC compare, not a prefix/length check).
    var tampered = buf;
    tampered[10] = if (tampered[10] == 'a') 'b' else 'a';
    try testing.expect(!verify(secret, body, tampered[0..value.len]));
}

// ── fuzz: verify (presentedMac decode) never panics on arbitrary input ────
//
// `verify`/`verifyWithPrefix` run on the `X-Signature-256` request header —
// an attacker fully controls `presented` (and, for the request-signing use
// case, `body` too). `presentedMac` is the byte-parser underneath: strip a
// prefix, then hex-decode a fixed-width tail. Structured half: builds a
// value shaped like `sha256=<64 hex chars>` (the exact length gate
// `presentedMac` requires to reach `hexToBytes`) with random hex/non-hex
// characters and surrounding whitespace, so the hex-decode path — not just
// the length/prefix check — actually runs.

test "fuzz: verify never panics on arbitrary secret/body/presented" {
    try testing.fuzz({}, fuzzVerify, .{});
}

fn fuzzVerify(_: void, smith: *std.testing.Smith) !void {
    var secret_buf: [32]u8 = undefined;
    smith.bytes(&secret_buf);
    const secret_len: usize = smith.valueRangeAtMost(u8, 1, secret_buf.len); // Verifier requires nonempty; verify() itself has no such requirement but exercising both is fine
    const secret = secret_buf[0..secret_len];

    var body_buf: [64]u8 = undefined;
    smith.bytes(&body_buf);
    const body_len: usize = smith.valueRangeAtMost(u8, 0, body_buf.len);
    const body = body_buf[0..body_len];

    var presented_buf: [96]u8 = undefined;
    const presented: []const u8 = if (smith.value(bool)) blk: {
        // Raw random bytes at random length — the cheap length/prefix gate.
        smith.bytes(&presented_buf);
        const len: usize = smith.valueRangeAtMost(u8, 0, presented_buf.len);
        break :blk presented_buf[0..len];
    } else blk: {
        // "sha256=" (or a random same-length prefix) + 64 mostly-hex chars,
        // optionally padded with tabs/spaces (which presentedMac trims) —
        // gets past the length gate into hexToBytes.
        var w: usize = 0;
        if (smith.value(bool)) {
            presented_buf[0..7].* = "sha256=".*;
            w = 7;
        } else {
            smith.bytes(presented_buf[0..7]);
            w = 7;
        }
        const hex_alphabet = "0123456789abcdefABCDEF ghij"; // last 5: deliberately non-hex
        for (0..signature_hex_len) |_| {
            presented_buf[w] = hex_alphabet[smith.index(hex_alphabet.len)];
            w += 1;
        }
        break :blk presented_buf[0..w];
    };

    _ = verify(secret, body, presented);
    _ = verifyWithPrefix("sha256=", secret, body, presented);
}

test "computeHex is lowercase hex and matches a well-known HMAC-SHA256 demo vector" {
    // NOT an RFC 4231 vector (RFC 4231's HMAC-SHA256 keys/data are the
    // 0x0b*20/"Jefe"/0xaa*20/... test cases) — this key="key" /
    // "The quick brown fox jumps over the lazy dog" pairing is a widely
    // circulated illustrative HMAC-SHA256 example (previously mislabeled
    // here as "RFC-style"); numerically re-verified against `openssl dgst
    // -sha256 -hmac`. See the RFC 4231 / GitHub-docs anchor discussion below
    // for what this module's own external anchor actually is.
    const hex = computeHex("key", "The quick brown fox jumps over the lazy dog");
    try testing.expectEqualStrings(
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
        &hex,
    );
}

// ── external anchor: RFC 4231 refuted, GitHub's own published vector adopted ─
//
// RFC 4231 (HMAC-SHA-224/256/384/512 test vectors) anchors the bare HMAC-
// SHA256 PRIMITIVE — but this module's `Hmac` is `std.crypto.auth.hmac.
// sha2.HmacSha256` used directly (see the type alias above); the primitive
// is already anchored upstream, in Zig std's own test suite. Feeding RFC
// 4231's key/data pairs through `computeHex` would just re-verify
// std.crypto's HMAC through a one-line pass-through, i.e. testing someone
// else's code, not this module's contribution — so those vectors are
// deliberately NOT adopted here.
//
// This module's own contribution is the `sha256=<hex>` GitHub-style webhook
// FRAMING on top (computeHex's hex formatting + sign/verify's prefix
// handling) — RFC 4231 says nothing about that framing. A real external
// anchor for it does exist: GitHub's own webhook-validation docs
// (https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
// publish a canonical secret/payload/signature triple specifically so a
// third-party implementation can self-check against it. Independently
// reproduced here with `openssl dgst -sha256 -hmac "It's a Secret to
// Everybody"` over the literal bytes "Hello, World!", which reproduces
// GitHub's published "sha256=757107ea0eb2..." value exactly — this is the
// module's real framing-level anchor, not RFC 4231.
test "GitHub docs' published canonical webhook signature (framing anchor, not RFC 4231)" {
    const secret = "It's a Secret to Everybody";
    const body = "Hello, World!";
    const want = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    var buf: [signatureBufLen(default_prefix)]u8 = undefined;
    try testing.expectEqualStrings(want, sign(secret, body, &buf));
    try testing.expect(verify(secret, body, want));
}

test "custom prefix (empty / non-default) signs and verifies" {
    const secret = "s";
    const body = "b";
    var buf: [signature_hex_len]u8 = undefined;
    const bare = signWithPrefix("", secret, body, &buf);
    try testing.expectEqual(@as(usize, signature_hex_len), bare.len);
    try testing.expect(verifyWithPrefix("", secret, body, bare));
    // The bare-hex value must not verify under the default prefix.
    try testing.expect(!verify(secret, body, bare));
}

// ── tests: Verifier (secret set) ────────────────────────────────────────────

test "Verifier.verifyBody: rotation — old and new secret both accepted, without early exit" {
    var v = try Verifier.init(testing.allocator, .{
        .secret = "new-secret",
        .extra_secrets = &.{"old-secret"},
    });
    defer v.deinit();
    try testing.expectEqual(@as(usize, 2), v.secretCount());

    const body = "event=push";
    var nbuf: [64 + 8]u8 = undefined;
    var obuf: [64 + 8]u8 = undefined;
    const new_sig = sign("new-secret", body, &nbuf);
    const old_sig = sign("old-secret", body, &obuf);

    try testing.expect(v.verifyBody(body, new_sig)); // current secret
    try testing.expect(v.verifyBody(body, old_sig)); // rotated-out secret still valid
    // `sign` returns a slice INTO its out_buf: signing into `nbuf` here would
    // clobber `new_sig` and silently defang the tampered-body control below.
    var gbuf: [64 + 8]u8 = undefined;
    try testing.expect(!v.verifyBody(body, sign("gone-secret", body, &gbuf))); // never configured
    // Negative control: a signature valid for `body` must NOT verify against a
    // different body — proves the MAC covers the body, not just the secret set.
    try testing.expect(!v.verifyBody("event=pull", new_sig)); // tampered body
}

// ── tests: middleware over the socket-free server codec ──────────────────────

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Drive a router through `http.Server.serveStream` with canned wire bytes
/// (same harness as router/aaa-gate); returns the full response bytes.
fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [1024]u8 = undefined;
    var response_body_buf: [1024]u8 = undefined;
    var chunk_buf: [256]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

/// Build `POST /hook` wire bytes with an optional signature header and a body.
fn buildReq(buf: []u8, sig_header: ?[]const u8, sig_value: ?[]const u8, body: []const u8) []const u8 {
    var w: Writer = .fixed(buf);
    w.writeAll("POST /hook HTTP/1.1\r\nHost: t\r\n") catch unreachable;
    if (sig_value) |val| {
        const name = sig_header orelse default_header;
        w.print("{s}: {s}\r\n", .{ name, val }) catch unreachable;
    }
    w.print("Connection: close\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body }) catch unreachable;
    return w.buffered();
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn bodyOfResp(got: []const u8) []const u8 {
    return got[std.mem.indexOf(u8, got, "\r\n\r\n").? + 4 ..];
}

/// Handler that echoes the verified body it received via `bodyOf` — a
/// missing attachment errors → 500, so a 200 with the echoed body proves
/// both that verification passed and that the body survived the read.
fn hEcho(ctx: *router.Ctx) anyerror!void {
    const body = bodyOf(ctx) orelse return error.NoBody;
    try ctx.res.writeAll(body);
}

fn gatedRouter(v: *Verifier) !router.Router {
    var r = router.Router.init(testing.allocator);
    errdefer r.deinit();
    try r.use(v.middleware());
    try r.post("/hook", hEcho);
    return r;
}

test "middleware: correctly-signed body passes 200 and the handler sees it" {
    var v = try Verifier.init(testing.allocator, .{ .secret = "whsec" });
    defer v.deinit();
    var r = try gatedRouter(&v);
    defer r.deinit();

    const body = "{\"action\":\"opened\"}";
    var sbuf: [64 + 8]u8 = undefined;
    const sig = sign("whsec", body, &sbuf);

    var reqbuf: [512]u8 = undefined;
    var respbuf: [1024]u8 = undefined;
    const got = runWire(&r, buildReq(&reqbuf, null, sig, body), &respbuf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings(body, bodyOfResp(got)); // handler re-read the stashed body
}

test "middleware: missing header, tampered body and wrong secret each → 401" {
    var v = try Verifier.init(testing.allocator, .{ .secret = "whsec" });
    defer v.deinit();
    var r = try gatedRouter(&v);
    defer r.deinit();

    const body = "hello-webhook";
    var sbuf: [64 + 8]u8 = undefined;
    const good = sign("whsec", body, &sbuf);

    var reqbuf: [512]u8 = undefined;
    var respbuf: [1024]u8 = undefined;

    // Missing signature header.
    const miss = runWire(&r, buildReq(&reqbuf, null, null, body), &respbuf);
    try expectStatus(miss, "401");
    try testing.expect(std.mem.indexOf(u8, miss, "\r\nWWW-Authenticate: Signature\r\n") != null);

    // Correct signature but the delivered body was altered in flight.
    var rb2: [512]u8 = undefined;
    const tampered = runWire(&r, buildReq(&rb2, null, good, "hello-webhook!"), &respbuf);
    try expectStatus(tampered, "401");

    // A signature made with a different secret.
    var wbuf: [64 + 8]u8 = undefined;
    const wrong = sign("attacker", body, &wbuf);
    var rb3: [512]u8 = undefined;
    try expectStatus(runWire(&r, buildReq(&rb3, null, wrong, body), &respbuf), "401");

    // The good one still passes (sanity).
    var rb4: [512]u8 = undefined;
    try expectStatus(runWire(&r, buildReq(&rb4, null, good, body), &respbuf), "200");
}

test "middleware: custom header name and rotation both accepted over the wire" {
    var v = try Verifier.init(testing.allocator, .{
        .secret = "new",
        .extra_secrets = &.{"old"},
        .header = "X-Hub-Signature-256",
    });
    defer v.deinit();
    var r = try gatedRouter(&v);
    defer r.deinit();

    const body = "rotate-me";
    var nbuf: [64 + 8]u8 = undefined;
    var obuf: [64 + 8]u8 = undefined;
    const new_sig = sign("new", body, &nbuf);
    const old_sig = sign("old", body, &obuf);

    var reqbuf: [512]u8 = undefined;
    var respbuf: [1024]u8 = undefined;

    // The default header name is now wrong → 401 (verifier reads X-Hub-…).
    try expectStatus(runWire(&r, buildReq(&reqbuf, default_header, new_sig, body), &respbuf), "401");

    // Correct custom header, current secret → 200.
    var rb2: [512]u8 = undefined;
    try expectStatus(runWire(&r, buildReq(&rb2, "X-Hub-Signature-256", new_sig, body), &respbuf), "200");

    // Correct custom header, rotated-out secret → still 200.
    var rb3: [512]u8 = undefined;
    try expectStatus(runWire(&r, buildReq(&rb3, "X-Hub-Signature-256", old_sig, body), &respbuf), "200");
}
