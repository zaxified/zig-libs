// SPDX-License-Identifier: MIT

//! What a webhook receiver does with `webhooksig`: sign an outbound payload,
//! verify it, see a tampered payload rejected, then drive the same signature
//! through the `router` middleware over real HTTP wire bytes (GitHub-style
//! `X-Signature-256: sha256=<hex>`), including a secret-rotation accept.
//!
//! External judge: GitHub's own published webhook-validation example
//! (secret `"It's a Secret to Everybody"`, body `"Hello, World!"` ->
//! `sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17`),
//! independently reproduced with:
//!
//!   printf 'Hello, World!' | openssl dgst -sha256 -hmac "It's a Secret to Everybody"
//!   -> SHA2-256(stdin)= 757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17
//!
//! `verify`/`verifyWithPrefix` return `bool`, not an error union — the
//! module's public surface has no throwing "verify" call to name an error
//! from for the tampered case, so the negative assertion below turns an
//! unexpected accept into a distinctly-named error itself
//! (`error.UnexpectedAccept`) rather than silently swallowing it, same as
//! the `else => return err` fallthrough would for a throwing API.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `webhooksig` (or `router`/`http`) does not export.

const std = @import("std");
const http = @import("http");
const router = @import("router");
const webhooksig = @import("webhooksig");

// GitHub's own published canonical example.
const github_secret = "It's a Secret to Everybody";
const github_body = "Hello, World!";
const github_sig = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

fn hEcho(ctx: *router.Ctx) anyerror!void {
    const body = webhooksig.bodyOf(ctx) orelse return error.NoAttachedBody;
    try ctx.res.writeAll(body);
}

/// Drive a router through the socket-free server codec with canned wire
/// bytes; returns the full response byte stream.
fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
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

fn buildReq(buf: []u8, sig_value: ?[]const u8, body: []const u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll("POST /hook HTTP/1.1\r\nHost: example\r\n") catch unreachable;
    if (sig_value) |val| {
        w.print("{s}: {s}\r\n", .{ webhooksig.default_header, val }) catch unreachable;
    }
    w.print("Connection: close\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body }) catch unreachable;
    return w.buffered();
}

fn statusOf(got: []const u8) []const u8 {
    // "HTTP/1.1 200 OK\r\n..." -> "200"
    return got[9..12];
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── pure sign / verify, against GitHub's published vector ─────────────
    var sig_buf: [webhooksig.signatureBufLen(webhooksig.default_prefix)]u8 = undefined;
    const signed = try webhooksig.sign(github_secret, github_body, &sig_buf);
    if (!std.mem.eql(u8, signed, github_sig)) return error.SignatureMismatch;
    std.debug.print("signed matches GitHub's published vector: {s}\n", .{signed});

    if (!webhooksig.verify(github_secret, github_body, signed)) return error.ExpectedValid;
    std.debug.print("good signature verifies: OK\n", .{});

    // A tampered payload must fail verification under the same signature.
    const tampered_body = "Hello, World?";
    if (webhooksig.verify(github_secret, tampered_body, signed)) return error.UnexpectedAccept;
    std.debug.print("tampered payload rejected: OK\n", .{});

    // ── the middleware, over real HTTP wire bytes, with secret rotation ────
    var verifier = try webhooksig.Verifier.init(gpa, .{
        .secret = "new-secret",
        .extra_secrets = &.{"old-secret"},
    });
    defer verifier.deinit();

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(verifier.middleware());
    try r.post("/hook", hEcho);

    const body = "{\"action\":\"opened\"}";
    var new_buf: [webhooksig.signatureBufLen(webhooksig.default_prefix)]u8 = undefined;
    var old_buf: [webhooksig.signatureBufLen(webhooksig.default_prefix)]u8 = undefined;
    const new_sig = try webhooksig.sign("new-secret", body, &new_buf);
    const old_sig = try webhooksig.sign("old-secret", body, &old_buf);

    var req_buf: [512]u8 = undefined;
    var resp_buf: [1024]u8 = undefined;

    const got_new = runWire(&r, buildReq(&req_buf, new_sig, body), &resp_buf);
    if (!std.mem.eql(u8, statusOf(got_new), "200")) return error.ExpectedOk;
    std.debug.print("current-secret signature over the wire: 200\n", .{});

    var req_buf2: [512]u8 = undefined;
    const got_old = runWire(&r, buildReq(&req_buf2, old_sig, body), &resp_buf);
    if (!std.mem.eql(u8, statusOf(got_old), "200")) return error.ExpectedOk;
    std.debug.print("rotated-out secret still accepted: 200\n", .{});

    var req_buf3: [512]u8 = undefined;
    const got_missing = runWire(&r, buildReq(&req_buf3, null, body), &resp_buf);
    if (!std.mem.eql(u8, statusOf(got_missing), "401")) return error.ExpectedRejected;
    if (std.mem.indexOf(u8, got_missing, "WWW-Authenticate: Signature") == null) return error.MissingChallenge;
    std.debug.print("missing signature header over the wire: 401 with WWW-Authenticate\n", .{});
}
