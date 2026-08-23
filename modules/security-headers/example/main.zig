// SPDX-License-Identifier: MIT

//! What an internet-facing API does with `security-headers`: mount it as
//! global (outermost) `router` middleware in front of a real `http.Server`
//! on real loopback, then read the actual response headers with `curl` -- an
//! outside HTTP client -- and check the real semantics: HSTS's
//! `max-age`/`includeSubDomains` format (RFC 6797), `X-Content-Type-Options:
//! nosniff`, `X-Frame-Options` (RFC 7034), `Referrer-Policy`, and a
//! `Content-Security-Policy` whose *directive grammar* is validated
//! independently rather than just string-compared against this module's own
//! expectation.
//!
//! External judges, ACTUALLY RUN:
//!
//! 1. `curl`, against a real `http.Server` + `router` bound to `127.0.0.1`
//!    on OS-chosen ports -- loopback only, no internet.
//! 2. `python3`, validating the CSP value curl actually received against a
//!    directive grammar built from the CSP spec's own ABNF (`policy =
//!    directive *( ";" *WSP directive )`, `directive = token [ RWS
//!    directive-value ]`) -- run twice: once on the real emitted policy
//!    (must PASS) and once on a deliberately malformed one carrying a raw
//!    control byte (must FAIL), so the grammar check is proven to have
//!    teeth rather than rubber-stamping anything handed to it.
//!
//! Two configuration variants are driven live: the rich default-plus-CSP
//! posture, and "every header disabled" (config-variant coverage the
//! module's own README table enumerates) -- on two separate loopback
//! servers, since `router`'s middleware is process-global-per-instance, not
//! per-route.
//!
//! Also exercises two of the module's own named errors: `SecurityHeaders
//! .init`'s `InitError.HeaderBudgetExceeded` (config-time -- an
//! allocated-then-freed oversized CSP, the module's own leak-relevant
//! failure path since `SecurityHeaders` itself allocates nothing at all —
//! see root.zig, "no allocation, no locks, no clock") and `apply`'s
//! `SetHeaderError.HeaderBytesExhausted` (request-time misuse: something
//! else already spent the response's header budget before this middleware
//! ran, against its own documented "register first" contract).
//!
//! Built against the PUBLISHED module (`@import("security-headers")`,
//! `@import("router")`, `@import("http")` -- its two declared deps) plus
//! plain `std` for the server socket/threads and the `curl`/`python3`
//! subprocess plumbing. `zig build check-examples` builds this against
//! exactly that surface.

const std = @import("std");
const router = @import("router");
const http = @import("http");
const security_headers = @import("security-headers");

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

// ── documented fixtures: the module's own two named error paths ───────────

/// `SecurityHeaders` allocates nothing itself (root.zig: "no allocation, no
/// locks, no clock") -- allocating the oversized CSP here for real gives the
/// `DebugAllocator` leak check an actual failure path to prove: allocate,
/// fail at `init` with a named error, and let `defer` free it regardless.
fn checkHeaderBudgetExceeded(gpa: std.mem.Allocator) !void {
    const huge_csp = try gpa.alloc(u8, 8192); // far past any real per-response header budget
    defer gpa.free(huge_csp);
    @memset(huge_csp, 'a');

    if (security_headers.SecurityHeaders.init(.{ .content_security_policy = huge_csp })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.HeaderBudgetExceeded => std.debug.print(
            "SecurityHeaders.init with an 8192-byte CSP: HeaderBudgetExceeded (expected)\n",
            .{},
        ),
    }
}

/// `apply`'s documented misuse case (root.zig: "res arrived with some of
/// that budget already spent... sh was applied somewhere other than first
/// in the chain"): fill the response's header budget with unrelated headers
/// first, then prove `apply` itself reports `HeaderBytesExhausted` rather
/// than silently dropping headers or panicking. Offline -- a bare
/// `http.Server.ResponseWriter`, no router or socket, same harness the
/// module's own tests use.
fn checkApplyHeaderBytesExhausted() !void {
    var out_buf: [65536]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    // `http.Server.ResponseWriter` caps BOTH the header byte budget (4096,
    // `header_copy_bytes`) AND the header count (32, `max_response_headers`)
    // -- measured directly against this module's own dep, not assumed. 30
    // headers of ~140 bytes each (name+value) sums past the byte budget
    // while staying under the count cap, so this hits `HeaderBytesExhausted`
    // rather than the unrelated `TooManyHeaders`.
    var name_buf: [24]u8 = undefined;
    const filler_value = "x" ** 130;
    var exhausted = false;
    var i: usize = 0;
    while (i < 30) : (i += 1) {
        const name = std.fmt.bufPrint(&name_buf, "X-Filler-{d}", .{i}) catch break;
        rw.setHeader(name, filler_value) catch |err| switch (err) {
            error.HeaderBytesExhausted => {
                exhausted = true;
                break;
            },
            else => return err,
        };
    }
    if (!exhausted) return error.CouldNotExhaustHeaderBudget;

    const sh: security_headers.SecurityHeaders = try .init(.{});
    if (sh.apply(&rw)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.HeaderBytesExhausted => std.debug.print(
            "apply() against an already-full header budget ({d} filler headers set first): HeaderBytesExhausted (expected)\n",
            .{i},
        ),
        else => return err,
    }
}

// ── live section: a real http.Server + router, driven by curl + python3 ───

fn serveThreadMain(server: *http.Server) void {
    server.serve() catch {}; // returns once `shutdown()` is called below
}

fn readAll(io: std.Io, file: std.Io.File, out_buf: []u8) ![]const u8 {
    var rbuf: [256]u8 = undefined;
    var sr = file.reader(io, &rbuf);
    var total: usize = 0;
    while (true) {
        const n = try sr.interface.readSliceShort(out_buf[total..]);
        if (n == 0) break;
        total += n;
    }
    return out_buf[0..total];
}

fn runCurl(io: std.Io, argv: []const []const u8, out_buf: []u8) ![]const u8 {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .close,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    const out = try readAll(io, child.stdout.?, out_buf);
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return error.CurlFailed,
        else => return error.CurlFailed,
    }
    return out;
}

fn headerPresent(headers: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, headers, needle) != null;
}

/// Extract one header's value from a raw `curl -D-` dump ("Name: value\r\n").
fn headerValue(headers: []const u8, comptime name: []const u8) ?[]const u8 {
    const needle = "\r\n" ++ name ++ ": ";
    const start = (std.mem.indexOf(u8, headers, needle) orelse return null) + needle.len;
    const end = std.mem.indexOfPos(u8, headers, start, "\r\n") orelse return null;
    return headers[start..end];
}

/// A regex built straight from the CSP spec's own ABNF: `policy = directive
/// *( ";" *WSP directive )`, `directive = token [ RWS directive-value ]`,
/// `directive-value = *( %x09 / %x20-%x3A / %x3C-%x7E )` (i.e. any byte
/// except ';' and control bytes other than tab). Reads the candidate policy
/// as raw bytes on stdin; prints PASS/FAIL and exits 0/1.
const csp_grammar_script =
    \\import sys, re
    \\
    \\data = sys.stdin.buffer.read()
    \\text = data.decode("utf-8")
    \\directive_value = r'[\x09\x20-\x3a\x3c-\x7e]*'
    \\directive = rf'[a-zA-Z0-9\-]+(?:[ \t]+{directive_value})?'
    \\pattern = rf'^{directive}(?:;[ \t]*{directive}?)*$'
    \\ok = re.match(pattern, text, re.DOTALL) is not None
    \\print("PASS" if ok else f"FAIL {text!r}")
    \\sys.exit(0 if ok else 1)
;

fn runCspGrammarCheck(io: std.Io, csp: []const u8, expect_pass: bool) !void {
    var child = try std.process.spawn(io, .{
        .argv = &.{ "python3", "-c", csp_grammar_script },
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    {
        var wbuf: [256]u8 = undefined;
        var sw = child.stdin.?.writer(io, &wbuf);
        try sw.interface.writeAll(csp);
        try sw.interface.flush();
    }
    child.stdin.?.close(io);
    child.stdin = null;

    var out_buf: [256]u8 = undefined;
    var sr = child.stdout.?.reader(io, &out_buf);
    const line = sr.interface.takeDelimiterInclusive('\n') catch |err| switch (err) {
        error.EndOfStream => "",
        else => return err,
    };
    std.debug.print("python CSP grammar check: {s}", .{line});
    if (line.len == 0) std.debug.print("\n", .{});

    const term = try child.wait(io);
    const passed = switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (passed != expect_pass) return error.CspGrammarCheckUnexpectedResult;
}

fn runFullConfigChecks(io: std.Io, gpa: std.mem.Allocator) !void {
    const sh: security_headers.SecurityHeaders = try .init(.{
        .hsts = .{ .max_age_s = 63_072_000, .include_subdomains = true, .preload = false },
        .content_security_policy = security_headers.csp_helmet_default,
        .permissions_policy = "camera=(), microphone=(), geolocation=()",
        .cross_origin_embedder_policy = "require-corp", // off by default -- opted in here
        .server = "secheaders-example/1.0",
    });

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(sh.middleware()); // GLOBAL, first -- the module's own "register it first" rule
    try r.get("/api", hOk);

    var server: http.Server = .init(io, gpa, .{
        .handler = r.handler(),
        .context = &r,
        .addr = "127.0.0.1",
        .port = 0,
    });
    defer server.deinit();
    try server.bind();
    const port = server.boundAddress().getPort();

    const server_thread = try std.Thread.spawn(.{}, serveThreadMain, .{&server});
    defer {
        server.shutdown();
        server_thread.join();
    }

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/api", .{port});
    var curl_buf: [4096]u8 = undefined;
    const out = try runCurl(io, &.{ "curl", "-sS", "-D-", "-o", "/dev/null", url }, &curl_buf);

    if (!std.mem.startsWith(u8, out, "HTTP/1.1 200")) return error.RequestNot200;
    if (!headerPresent(out, "Strict-Transport-Security: max-age=63072000; includeSubDomains")) return error.WrongHsts;
    if (!headerPresent(out, "X-Content-Type-Options: nosniff")) return error.MissingNosniff;
    if (!headerPresent(out, "X-Frame-Options: DENY")) return error.WrongFrameOptions;
    if (!headerPresent(out, "Referrer-Policy: no-referrer")) return error.WrongReferrerPolicy;
    if (!headerPresent(out, "Permissions-Policy: camera=(), microphone=(), geolocation=()")) return error.WrongPermissionsPolicy;
    if (!headerPresent(out, "Cross-Origin-Opener-Policy: same-origin")) return error.WrongCoop;
    if (!headerPresent(out, "Cross-Origin-Resource-Policy: same-origin")) return error.WrongCorp;
    if (!headerPresent(out, "Cross-Origin-Embedder-Policy: require-corp")) return error.WrongCoep;
    if (!headerPresent(out, "Server: secheaders-example/1.0")) return error.WrongServer;
    std.debug.print("curl full config: 200, HSTS/nosniff/frame/referrer/permissions/COOP/CORP/COEP/Server all as configured\n", .{});

    const csp = headerValue(out, "Content-Security-Policy") orelse return error.MissingCsp;
    if (!std.mem.eql(u8, csp, security_headers.csp_helmet_default)) return error.CspNotByteExact;
    try runCspGrammarCheck(io, csp, true);

    // Negative control: a CSP carrying a raw control byte must FAIL the same
    // grammar check, proving PASS above wasn't a rubber stamp.
    try runCspGrammarCheck(io, "default-src 'self\x01'", false);
}

fn runAllDisabledConfigCheck(io: std.Io, gpa: std.mem.Allocator) !void {
    const sh: security_headers.SecurityHeaders = try .init(.{
        .hsts = null,
        .x_content_type_options = false,
        .x_frame_options = null,
        .referrer_policy = null,
        .cross_origin_opener_policy = null,
        .cross_origin_resource_policy = null,
    });

    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(sh.middleware());
    try r.get("/api", hOk);

    var server: http.Server = .init(io, gpa, .{
        .handler = r.handler(),
        .context = &r,
        .addr = "127.0.0.1",
        .port = 0,
    });
    defer server.deinit();
    try server.bind();
    const port = server.boundAddress().getPort();

    const server_thread = try std.Thread.spawn(.{}, serveThreadMain, .{&server});
    defer {
        server.shutdown();
        server_thread.join();
    }

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/api", .{port});
    var curl_buf: [2048]u8 = undefined;
    const out = try runCurl(io, &.{ "curl", "-sS", "-D-", "-o", "/dev/null", url }, &curl_buf);

    if (!std.mem.startsWith(u8, out, "HTTP/1.1 200")) return error.RequestNot200;
    for ([_][]const u8{
        "Strict-Transport-Security", "X-Content-Type-Options",       "X-Frame-Options",
        "Referrer-Policy",           "Cross-Origin-Opener-Policy",   "Cross-Origin-Resource-Policy",
        "Content-Security-Policy",   "Cross-Origin-Embedder-Policy",
    }) |name| {
        if (headerPresent(out, name)) return error.UnexpectedHeaderWhenAllDisabled;
    }
    std.debug.print("curl all-disabled config: 200, zero security headers (bare response)\n", .{});
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    try checkHeaderBudgetExceeded(gpa);
    try checkApplyHeaderBytesExhausted();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try runFullConfigChecks(io, gpa);
    try runAllDisabledConfigCheck(io, gpa);

    std.debug.print("OK: all security-headers example checks passed\n", .{});
}
