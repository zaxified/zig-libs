// SPDX-License-Identifier: MIT

//! `http-demo` — one binary, two modes (`server` and `client`) that talk to
//! each other over a **real TCP socket**, and that each half can equally be
//! pointed at a foreign implementation: the server at `curl`, the client at
//! any public web site.
//!
//! **The thing worth reading this for is that one `Options.handler` serves
//! both protocols.** Start the server with `--h2c` and it answers HTTP/1.1
//! and cleartext HTTP/2 on the same port, chosen by what the client opens
//! with (the HTTP/2 connection preface, RFC 9113 §3.3 "prior knowledge" —
//! RFC 9113 deleted the `Upgrade: h2c` dance, so the preface is the whole
//! negotiation). `curl --http2-prior-knowledge` speaks it, and so does this
//! demo's own `client --h2c`, which goes through `Client.connectH2c` and
//! multiplexes several requests down that one connection.
//!
//! **This server does not speak https, and that is not a corner cut for the
//! demo.** Zig 0.16's `std.crypto.tls` ships a `Client` and no `Server`, and
//! this collection takes no external dependencies — so there is no TLS server
//! under us to terminate a handshake with, and inventing one here would be a
//! lie a reader would find out about in production. The module says the same
//! thing in its own README ("No TLS in the server — terminate TLS in front"),
//! and it ships the seam instead of the implementation: your TLS library
//! negotiates ALPN offering `http.alpn_offer`, `http.protocolFromAlpn` maps
//! what came back, and `h2_server.serveStream` / `Server.serveStream` take
//! the decrypted stream from there. The startup banner says all of this out
//! loud rather than leaving `https://127.0.0.1:8080` to fail obscurely.
//!
//! **The client's TLS, by contrast, is entirely real** — `http-demo client
//! https://example.com/` does a genuine `std.crypto.tls` handshake against
//! the public internet and verifies the chain against the system CA bundle.
//! One honest limitation is printed with the result: `Client.request` is
//! HTTP/1.1-over-TLS. It does not offer ALPN "h2" on its own; h2 over TLS is
//! `Client.connectH2Over` on a stream whose handshake you drove yourself.
//!
//! **Cancellation has an example surface here and nowhere else.** A
//! `*std.Io.Reader`'s error set is exactly `{ReadFailed, EndOfStream}`
//! (CONVENTIONS.md §2), so a caller streaming a response body cannot tell a
//! `std.Io` cancelation from a dead peer — the distinction is erased by the
//! type. `Response.readFailure()` is the seam that recovers it, and
//! `--cancel-after` drives it for real: the body read parks in the kernel on
//! `/slow`, the read is canceled, and the demo prints both answers side by
//! side. `/truncate` is the control — the same code, a genuinely broken
//! connection, and `readFailure()` says `ReadFailed` there.
//!
//! **Directory serving is deliberately absent.** That is the `staticfiles`
//! module's job, with path-traversal-safe resolution this file has no
//! business reimplementing. What is here is a small routed handler with a
//! handful of explicit paths, which is the honest scope for an example of
//! *this* module.
//!
//! Built against the PUBLISHED module (`@import("http")`) only — no
//! `test_deps`, no reaching into `src/`. If a type needed to call this API is
//! not public, or an error cannot be named from outside, this file stops
//! compiling; the module's own tests cannot notice either, because they live
//! inside it.

const std = @import("std");
const http = @import("http");

const Allocator = std.mem.Allocator;

/// This demo's own failure — a bad option, a refused connect, a TLS error.
/// An HTTP error *status* is a successful conversation with an unwelcome
/// answer and does not land here; `--fail` is what turns 4xx/5xx into an
/// exit code, the way `curl --fail` does.
const local_failure_exit: u8 = 1;

/// Not 80. A demo that needs root to bind teaches the wrong first lesson.
const default_port: u16 = 8080;

const usage_text =
    \\http-demo — an HTTP/1.1 + h2c client/server demo for the `http` module.
    \\
    \\usage:
    \\  http-demo                       self-demo: real server + real client,
    \\                                  loopback only, asserted (no args needed)
    \\  http-demo server [options]
    \\  http-demo client <url> [options]
    \\
    \\server options:
    \\  --listen <addr>     address to bind                (default 127.0.0.1)
    \\  --port <port>       TCP port                       (default 8080)
    \\  --h2c               also serve cleartext HTTP/2 (prior knowledge,
    \\                      RFC 9113 3.3) on the same port, through the SAME
    \\                      handler. `curl --http2-prior-knowledge` speaks it.
    \\  --compress          negotiated gzip response compression
    \\  --once              serve one connection, then exit
    \\  -v                  log every connection state change
    \\  -h, --help          this text
    \\
    \\client options:
    \\  -X <method>         GET HEAD POST PUT DELETE PATCH OPTIONS (default GET)
    \\  -d <data>           request body (implies -X POST unless -X was given)
    \\  -H "N: v"           extra request header; repeatable
    \\  --repeat <n>        issue the request n times on one Client and report
    \\                      the dial count — the keep-alive pool's whole point
    \\  --h2c               talk cleartext HTTP/2 instead (Client.connectH2c);
    \\                      with --repeat n, opens n streams FIRST and collects
    \\                      them after, so the multiplexing is visible
    \\  --cancel-after <ms> cancel the body read after ms and report what
    \\                      Response.readFailure() recovers. h1 only.
    \\  --insecure          skip TLS certificate/hostname verification
    \\  --max-body <n>      bytes of body to print          (default 2048)
    \\  --fail              exit non-zero on a 4xx/5xx status, like curl --fail
    \\  -v                  print every response header
    \\  -h, --help          this text
    \\
    \\Two terminals:
    \\  http-demo server --h2c
    \\  http-demo client http://127.0.0.1:8080/hello?name=Ada
    \\  http-demo client http://127.0.0.1:8080/hello --h2c --repeat 4
    \\
    \\Against real curl (the oracle this module's own live tests use):
    \\  curl -sSD- http://127.0.0.1:8080/hello
    \\  curl -sSD- --http2-prior-knowledge http://127.0.0.1:8080/hello
    \\
    \\Against a real https site, exercising the client's std.crypto.tls:
    \\  http-demo client https://example.com/
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes the example a leak
    // detector for the module's ownership contract (CONVENTIONS.md §7.2) —
    // every `deinit`/`free` below is load-bearing, not decoration. `Client`
    // hands out `Response`s that own a connection and `h2_client.Response`s
    // that own three heap blocks; forgetting either one fails this binary.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.skip(); // argv[0]

    const mode = args.next() orelse return runSelfDemo(gpa, io);

    if (std.mem.eql(u8, mode, "server")) return runServer(gpa, io, &args);
    if (std.mem.eql(u8, mode, "client")) return runClient(gpa, io, &args);
    if (std.mem.eql(u8, mode, "-h") or std.mem.eql(u8, mode, "--help")) {
        std.debug.print("{s}", .{usage_text});
        return 0;
    }

    std.debug.print("http-demo: unknown mode '{s}' (expected `server` or `client`)\n\n{s}", .{ mode, usage_text });
    return local_failure_exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// self-demo (no arguments): a real server and a real client, one process,
// loopback only, every interesting value asserted
// ─────────────────────────────────────────────────────────────────────────────
//
// Reuses the SAME handler (`handle`) that `server` mode serves, and the SAME
// `http.Client` that `client` mode uses — this is not a separate fixture, it
// is the module's server and the module's client, wired to each other. The
// server's accept loop runs as a concurrent task on `io` (`Server.shutdown`
// is documented safe from another task); the main task drives two requests
// over one pooled keep-alive connection, and `--once` on the server means
// that connection closing is what ends the accept loop.

fn runSelfDemo(gpa: Allocator, io: std.Io) !u8 {
    var state: ServerState = .{
        .io = io,
        .verbose = false,
        .h2c = false,
        .once = true, // one connection served, then the accept loop returns
    };
    var server: http.Server = .init(io, gpa, .{
        .handler = handle,
        .context = state.context(),
        .addr = "127.0.0.1",
        .port = 0, // ephemeral: Server.boundAddress() reports what the kernel picked
        .max_body_bytes = 64 << 20,
        .server_name = "http-demo/1.0 (zig-libs-http self-demo)",
        .on_conn_state = onConnState,
        .on_conn_state_ctx = state.context(),
    });
    defer server.deinit();
    state.server = &server;

    server.bind() catch |err| {
        std.debug.print("http-demo self-demo: cannot bind 127.0.0.1:0: {t}\n", .{err});
        return local_failure_exit;
    };
    const port = server.boundAddress().getPort();

    var serve_fut = io.concurrent(http.Server.serve, .{&server}) catch |err| {
        std.debug.print("http-demo self-demo: no concurrency available ({t}); cannot self-demo\n", .{err});
        return local_failure_exit;
    };
    // `Server.deinit` above may only run after `serve` has returned. This
    // defer, declared AFTER `defer server.deinit()`, runs BEFORE it on every
    // exit path (including an early `return` below) — `shutdown` wakes the
    // accept loop and `await` is documented idempotent, so calling it again
    // explicitly on the success path below (to surface a real failure) costs
    // nothing here.
    defer {
        server.shutdown();
        serve_fut.await(io) catch {};
    }

    var client: http.Client = .init(io, gpa, .{ .user_agent = "http-demo-selfdemo/1.0" });
    // Closing the client's pooled connection is what makes the SECOND
    // request's connection close observable to the server if the handler
    // itself has not already done so — see the /truncate request below.
    var client_closed = false;
    defer if (!client_closed) client.deinit();

    var url_buf: [64]u8 = undefined;
    const hello_url = std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/hello?name=selfdemo", .{port}) catch unreachable;

    // ── request 1: GET /hello — the positive path, every field asserted ────
    var res = client.request(.get, hello_url, .{}) catch |err| {
        std.debug.print("http-demo self-demo: GET /hello failed: {t}\n", .{err});
        return local_failure_exit;
    };
    if (res.status != 200) @panic("http-demo self-demo: /hello did not answer 200");
    const content_type = res.header("content-type") orelse @panic("http-demo self-demo: /hello has no content-type");
    if (!std.mem.eql(u8, content_type, "text/plain; charset=utf-8")) {
        @panic("http-demo self-demo: /hello content-type mismatch");
    }
    const route_header = res.header("x-demo-route") orelse @panic("http-demo self-demo: /hello missing X-Demo-Route");
    if (!std.mem.eql(u8, route_header, "/hello")) @panic("http-demo self-demo: X-Demo-Route mismatch");
    const body = res.readAllAlloc(gpa, 8 << 20) catch |err| {
        std.debug.print("http-demo self-demo: reading /hello body failed: {t}\n", .{err});
        return local_failure_exit;
    };
    defer gpa.free(body);
    res.deinit();
    if (!std.mem.startsWith(u8, body, "hello, GET /hello?name=selfdemo\n")) @panic("http-demo self-demo: /hello body prefix mismatch");
    if (std.mem.indexOf(u8, body, "query:      name=selfdemo\n") == null) {
        @panic("http-demo self-demo: /hello did not echo the query string");
    }

    // ── request 2: GET /truncate — the negative path. The handler declares a
    // Content-Length it never honours and then fails (see `serveTruncate`);
    // the head is already on the wire, so the module cannot turn this into a
    // clean error status — it closes the connection instead. A client that
    // read this as a clean EOF would silently accept a truncated body, so
    // `readAllAlloc` FAILING here is the assertion, not an accident. This
    // request rides the SAME pooled connection as request 1 (both to the
    // same host:port), and the server closing it is what makes `--once`'s
    // "one connection served" true and ends the accept loop below. ────────
    var trunc_url_buf: [64]u8 = undefined;
    const trunc_url = std.fmt.bufPrint(&trunc_url_buf, "http://127.0.0.1:{d}/truncate", .{port}) catch unreachable;
    var res2 = client.request(.get, trunc_url, .{}) catch |err| {
        std.debug.print("http-demo self-demo: opening /truncate failed: {t}\n", .{err});
        return local_failure_exit;
    };
    if (res2.status != 200) @panic("http-demo self-demo: /truncate did not answer 200 before truncating");
    const trunc_body_result = res2.readAllAlloc(gpa, 8 << 20);
    if (trunc_body_result) |b| {
        gpa.free(b);
        @panic("http-demo self-demo: /truncate's lying Content-Length was not caught — the body read must fail");
    } else |_| {
        // Any error is the point: the connection died mid-body against a
        // declared length. `readFailure()` (see the client demo's
        // cancellation section) names the precise cause when the caller
        // needs it; here the FAILURE itself is what is being proven.
    }
    res2.deinit();

    client.deinit();
    client_closed = true;

    server.shutdown();
    serve_fut.await(io) catch |err| {
        std.debug.print("http-demo self-demo: server accept loop ended abnormally: {t}\n", .{err});
        return local_failure_exit;
    };

    std.debug.print(
        "http-demo self-demo: OK\n" ++
            "  real http.Server + real http.Client, one process, over 127.0.0.1:{d}.\n" ++
            "  GET /hello?name=selfdemo -> 200, content-type asserted, X-Demo-Route\n" ++
            "  asserted, body prefix and echoed query asserted.\n" ++
            "  GET /truncate -> 200 head, then the body read FAILED as asserted (the\n" ++
            "  handler's lying Content-Length, caught rather than silently truncated).\n" ++
            "  no TLS, no real network beyond loopback.\n" ++
            "  see --help for the server/client subcommands this binary also offers.\n",
        .{port},
    );
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// server mode
// ─────────────────────────────────────────────────────────────────────────────
//
// Everything the server needs is one `ServerState` on `runServer`'s stack,
// reached through `Options.context` → `Request.context`. Two servers in one
// process (a second port, a second policy) would be two of these — no
// globals, which is what that passthrough buys. It matters more here than it
// looks: a `Handler` is a bare `fn(*Request, *ResponseWriter)` with no
// `std.Io` in it, and `/slow` cannot sleep without one.

const ServerState = struct {
    io: std.Io,
    verbose: bool,
    h2c: bool,
    /// Set by `--once`: the lifecycle observer shuts the listener down as
    /// soon as one connection is finished.
    once: bool,
    server: ?*http.Server = null,

    fn context(self: *ServerState) *anyopaque {
        return @ptrCast(self);
    }

    fn of(ctx: ?*anyopaque) *ServerState {
        return @ptrCast(@alignCast(ctx.?));
    }
};

const ServerOptions = struct {
    listen: []const u8 = "127.0.0.1",
    port: u16 = default_port,
    h2c: bool = false,
    compress: bool = false,
    once: bool = false,
    verbose: bool = false,
};

fn runServer(gpa: Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
    const opts = parseServerArgs(args) catch |err| switch (err) {
        error.UsagePrinted => return 0,
        error.BadUsage => return local_failure_exit,
    };

    var state: ServerState = .{
        .io = io,
        .verbose = opts.verbose,
        .h2c = opts.h2c,
        .once = opts.once,
    };

    var server: http.Server = .init(io, gpa, .{
        .handler = handle,
        .context = state.context(),
        .addr = opts.listen,
        .port = opts.port,
        .enable_h2c = opts.h2c,
        // On by default and worth turning off here: 1 MiB is the right
        // internet-facing default, but `/echo` exists to be fed real
        // uploads, so this demo raises it rather than answering 413 to the
        // first `-T bigfile` anybody tries.
        .max_body_bytes = 64 << 20,
        .compression = if (opts.compress) .{} else null,
        .server_name = "http-demo/1.0 (zig-libs-http)",
        .on_conn_state = onConnState,
        .on_conn_state_ctx = state.context(),
    });
    defer server.deinit();
    state.server = &server;

    server.bind() catch |err| {
        // The classified tag alone would not say *why*; `bindErrorName`
        // carries the underlying std error name, which is the half a reader
        // needs ("AddressInUse" vs "AddressUnavailable" are different
        // mistakes).
        std.debug.print("http-demo: cannot bind {s}:{d}: {t} ({s})\n", .{
            opts.listen,
            opts.port,
            err,
            server.bindErrorName() orelse "no detail",
        });
        return local_failure_exit;
    };

    const bound = server.boundAddress();
    printServerBanner(&opts, bound.getPort());

    server.serve() catch |err| {
        std.debug.print("http-demo: accept loop ended: {t}\n", .{err});
        return local_failure_exit;
    };
    return 0;
}

fn parseServerArgs(args: *std.process.Args.Iterator) !ServerOptions {
    var opts: ServerOptions = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return error.UsagePrinted;
        } else if (std.mem.eql(u8, arg, "-v")) {
            opts.verbose = true;
        } else if (std.mem.eql(u8, arg, "--h2c")) {
            opts.h2c = true;
        } else if (std.mem.eql(u8, arg, "--compress")) {
            opts.compress = true;
        } else if (std.mem.eql(u8, arg, "--once")) {
            opts.once = true;
        } else if (std.mem.eql(u8, arg, "--listen")) {
            opts.listen = try nextValue(args, "--listen");
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = try parseIntArg(u16, args, "--port");
        } else {
            std.debug.print("http-demo: unknown server option '{s}' (try --help)\n", .{arg});
            return error.BadUsage;
        }
    }
    return opts;
}

/// Printed once at startup. The TLS paragraph is the important one: it is the
/// question every reader asks first, and answering it in the banner is much
/// better than letting `https://127.0.0.1:8080` fail as a TLS handshake
/// timeout with no explanation anywhere.
fn printServerBanner(opts: *const ServerOptions, port: u16) void {
    std.debug.print(
        \\http-demo: listening on http://{s}:{d}
        \\  protocols: HTTP/1.1{s}
        \\  routes:    /  /hello  /headers  /echo  /slow  /stream  /truncate
        \\
        \\http-demo: there is no https here, and it is not a shortcut.
        \\  Zig 0.16's `std.crypto.tls` ships a Client and NO Server, and this
        \\  collection takes no external dependencies — so there is nothing to
        \\  terminate a handshake with. The module's posture (README: "No TLS
        \\  in the server") is to terminate TLS in FRONT, and it ships the seam
        \\  rather than a stub: negotiate ALPN with `http.alpn_offer`, map the
        \\  result with `http.protocolFromAlpn`, then hand the decrypted
        \\  reader/writer to `h2_server.serveStream` (h2) or
        \\  `Server.serveStream` (http/1.1). The CLIENT half's TLS is real —
        \\  `http-demo client https://example.com/` proves it.
        \\
    , .{ opts.listen, port, if (opts.h2c)
        " + cleartext HTTP/2 (h2c, prior knowledge — RFC 9113 3.3)"
    else
        " only (pass --h2c to add cleartext HTTP/2)" });

    if (!opts.h2c) std.debug.print(
        \\http-demo: without --h2c the server never even peeks at the preface, so
        \\  `curl --http2-prior-knowledge` fails fast rather than hanging: the
        \\  preface opens with a request line the HTTP/1.1 loop can parse and must
        \\  refuse ("PRI * HTTP/2.0"), so it answers 505 HTTP Version Not Supported
        \\  and closes, and curl reports exit 16 ("Remote peer returned unexpected
        \\  data while we expected SETTINGS frame"). Measured, not assumed.
        \\
    , .{});

    std.debug.print("http-demo: try it with real curl:\n" ++
        "  curl -sSD- http://{s}:{d}/hello?name=Ada\n", .{ opts.listen, port });
    if (opts.h2c) std.debug.print(
        "  curl -sSD- --http2-prior-knowledge http://{s}:{d}/hello\n",
        .{ opts.listen, port },
    );
    std.debug.print("\n", .{});
}

/// `Options.on_conn_state` — Go's `ConnState` shape. Used for two things:
/// the `-v` connection log, and `--once`, which has no dedicated option on
/// `Server` and does not need one — `shutdown` is documented safe from
/// another thread, and `.closed` fires on the connection's own task once it
/// is finished.
fn onConnState(ctx: ?*anyopaque, peer: ?std.Io.net.IpAddress, st: http.Server.ConnState) void {
    const state = ServerState.of(ctx);
    if (state.verbose) {
        if (peer) |p| {
            std.debug.print("debug1: connection {f} is {t}\n", .{ p, st });
        } else {
            std.debug.print("debug1: connection (no peer) is {t}\n", .{st});
        }
    }
    if (state.once and st == .closed) {
        std.debug.print("http-demo: --once: one connection served, stopping\n", .{});
        if (state.server) |s| s.shutdown();
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// the handler — one function, both protocols
// ─────────────────────────────────────────────────────────────────────────────

/// ⚠ MODULE GAP, named rather than papered over.
///
/// This handler cannot tell whether it was reached over HTTP/1.1 or over
/// h2c, and neither can any other. The h2 path deliberately synthesizes an
/// h1-shaped `RequestHead` (`:authority` becomes `host`, `http1_0 = false`)
/// so that ONE handler serves both — which is the design and is right — but
/// nothing on `Request` then says which wire delivered it. Go exposes
/// `Request.Proto`/`ProtoMajor`, hyper exposes `Request::version`; we expose
/// nothing, so a handler cannot log the protocol, cannot vary a hint by it,
/// and cannot even count h2 traffic. `ResponseWriter.trailersSupported` is
/// the nearest thing and answers a different question.
///
/// The demo therefore prints what the SERVER was configured with, never what
/// this request arrived on — guessing from lowercase field names would be a
/// heuristic dressed up as an API.
fn handle(req: *http.Server.Request, rw: *http.Server.ResponseWriter) anyerror!void {
    const state = ServerState.of(req.context);

    if (std.mem.eql(u8, req.path, "/")) return serveIndex(state, rw);
    if (std.mem.eql(u8, req.path, "/hello")) return serveHello(state, req, rw);
    if (std.mem.eql(u8, req.path, "/headers")) return serveHeaders(req, rw);
    if (std.mem.eql(u8, req.path, "/echo")) return serveEcho(req, rw);
    if (std.mem.eql(u8, req.path, "/slow")) return serveSlow(state, req, rw);
    if (std.mem.eql(u8, req.path, "/stream")) return serveStreamRoute(rw);
    if (std.mem.eql(u8, req.path, "/truncate")) return serveTruncate(rw);

    rw.setStatus(404);
    try rw.setHeader("Content-Type", "text/plain");
    var buf: [256]u8 = undefined;
    try rw.writeAll(try std.fmt.bufPrint(&buf,
        \\404 no such route: {s}
        \\try / for the list
        \\
    , .{req.path}));
}

fn serveIndex(state: *ServerState, rw: *http.Server.ResponseWriter) !void {
    try rw.setHeader("Content-Type", "text/plain; charset=utf-8");
    try rw.writeAll(
        \\http-demo — the `http` module's example server.
        \\
        \\  /hello?name=…   a small text response; echoes what it was asked
        \\  /headers        every request header, in wire order
        \\  /echo           reads the request body and reports what arrived
        \\  /slow?ms=&n=    n chunks, flushed, ms apart — the route the
        \\                  client's --cancel-after parks a body read on
        \\  /stream         256 KiB in 64 flushed chunks; never held in memory
        \\  /truncate       declares a Content-Length it will not honour and
        \\                  then fails, so the connection dies mid-body — the
        \\                  control case for Response.readFailure()
        \\
    );
    var buf: [256]u8 = undefined;
    try rw.writeAll(try std.fmt.bufPrint(&buf,
        \\
        \\This listener speaks: HTTP/1.1{s}.
        \\It does not speak https — see the startup banner for why that is the
        \\module's architecture and not a missing feature.
        \\
    , .{if (state.h2c) " and cleartext HTTP/2 (h2c)" else " only"}));
}

fn serveHello(state: *ServerState, req: *http.Server.Request, rw: *http.Server.ResponseWriter) !void {
    try rw.setHeader("Content-Type", "text/plain; charset=utf-8");
    // Header VALUES are borrowed, not copied (unlike trailer names) — a
    // static string is always safe, a stack buffer would not be.
    try rw.setHeader("X-Demo-Route", "/hello");

    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("hello, {s} {s}\n", .{ req.method.token(), req.target });
    try w.print("query:      {s}\n", .{if (req.query.len == 0) "(none)" else req.query});
    try w.print("host:       {?s}\n", .{req.head.host});
    try w.print("user-agent: {?s}\n", .{req.header("user-agent")});
    // 0-based ordinal on THIS connection: on a keep-alive h1 connection it
    // counts up as curl reuses the socket, which is the observable half of
    // `max_requests_per_conn`.
    try w.print("request #{d} on this connection\n", .{req.connRequestIndex()});
    if (req.peerAddress()) |p| {
        try w.print("peer:       {f}\n", .{p});
    } else {
        try w.print("peer:       (served socket-free)\n", .{});
    }
    try w.print("listener:   HTTP/1.1{s}\n", .{if (state.h2c) " + h2c" else ""});
    try rw.writeAll(w.buffered());
}

fn serveHeaders(req: *http.Server.Request, rw: *http.Server.ResponseWriter) !void {
    try rw.setHeader("Content-Type", "text/plain; charset=utf-8");
    var it = req.iterateHeaders();
    var n: usize = 0;
    while (it.next()) |entry| {
        n += 1;
        var buf: [1024]u8 = undefined;
        // Header names arrive lowercase over h2 (RFC 9113 §8.2.1) and as the
        // peer typed them over h1. Printing them verbatim is the point — it
        // is the one place the protocol difference is honestly visible, and
        // it is why `Request.header` is case-insensitive.
        try rw.writeAll(try std.fmt.bufPrint(&buf, "{s}: {s}\n", .{ entry.name, entry.value }));
    }
    var tail: [64]u8 = undefined;
    try rw.writeAll(try std.fmt.bufPrint(&tail, "\n{d} header field(s)\n", .{n}));
}

fn serveEcho(req: *http.Server.Request, rw: *http.Server.ResponseWriter) !void {
    // The request body is a `std.Io.Reader` with the framing already decoded
    // — chunked, Content-Length, or h2 DATA frames, the handler cannot tell
    // and does not need to. Drained in fixed-size bites so an upload larger
    // than memory still works.
    const r = req.reader();
    var scratch: [16 * 1024]u8 = undefined;
    var total: u64 = 0;
    var reads: u64 = 0;
    var first: [64]u8 = undefined;
    var first_len: usize = 0;
    while (true) {
        const n = try r.readSliceShort(&scratch);
        if (n == 0) break;
        reads += 1;
        if (first_len < first.len) {
            const take = @min(first.len - first_len, n);
            @memcpy(first[first_len..][0..take], scratch[0..take]);
            first_len += take;
        }
        total += n;
    }

    try rw.setHeader("Content-Type", "text/plain; charset=utf-8");
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.print("read {d} body byte(s) in {d} read(s)\n", .{ total, reads });
    try w.print("content-type: {?s}\n", .{req.header("content-type")});
    try w.print("first {d}: ", .{first_len});
    for (first[0..first_len]) |c| {
        if (std.ascii.isPrint(c)) try w.writeByte(c) else try w.print("\\x{x:0>2}", .{c});
    }
    try w.writeByte('\n');
    try rw.writeAll(w.buffered());
}

/// `/slow?ms=<gap>&n=<chunks>` — the route the cancellation demo aims at.
///
/// Each chunk is written and then **flushed**, which is what puts it on the
/// wire: without the flush the response buffer would hold everything until
/// the handler returned and the whole point (a client parked mid-body) would
/// be gone. The sleep between chunks needs a `std.Io`, which the `Handler`
/// signature does not carry — hence `Options.context`.
fn serveSlow(state: *ServerState, req: *http.Server.Request, rw: *http.Server.ResponseWriter) !void {
    const gap_ms: i64 = @intCast(@min(queryInt(req.query, "ms") orelse 300, 60_000));
    const chunks = @min(queryInt(req.query, "n") orelse 20, 1000);

    try rw.setHeader("Content-Type", "text/plain; charset=utf-8");
    try rw.writeAll("this response arrives one line at a time\n");
    try rw.flush();

    var i: u64 = 0;
    while (i < chunks) : (i += 1) {
        try state.io.sleep(.fromMilliseconds(gap_ms), .awake);
        var buf: [64]u8 = undefined;
        try rw.writeAll(try std.fmt.bufPrint(&buf, "chunk {d}/{d}\n", .{ i + 1, chunks }));
        try rw.flush();
    }
}

const stream_chunk = "abcdefgh" ** 512; // 4 KiB
const stream_chunks = 64; // × 4 KiB = 256 KiB

fn serveStreamRoute(rw: *http.Server.ResponseWriter) !void {
    try rw.setHeader("Content-Type", "text/plain");
    // No Content-Length is ever computed: the length is not known when the
    // head goes out, so h1 gets chunked framing and h2 gets DATA frames
    // ending on an empty one. Neither is a decision this handler makes.
    for (0..stream_chunks) |_| {
        try rw.writeAll(stream_chunk);
        try rw.flush();
    }
}

/// Declares a `Content-Length` it will not honour, then fails. The module
/// answers exactly right: the head is already on the wire, so there is no
/// way to turn this into a 500, and `serveStream` closes the connection
/// rather than leaving a peer to read bytes that will never come. On the
/// client side that surfaces as a truncated body — which is what makes this
/// the control case for `Response.readFailure()`.
fn serveTruncate(rw: *http.Server.ResponseWriter) !void {
    try rw.setHeader("Content-Type", "text/plain");
    try rw.setHeader("Content-Length", "4096");
    try rw.writeAll("this response claims 4096 bytes and stops here.\n");
    try rw.flush();
    return error.DemoDeliberateTruncation;
}

/// `name=<digits>` out of a raw query string, or null.
fn queryInt(query: []const u8, name: []const u8) ?u64 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (!std.mem.eql(u8, pair[0..eq], name)) continue;
        return std.fmt.parseInt(u64, pair[eq + 1 ..], 10) catch null;
    }
    return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// client mode
// ─────────────────────────────────────────────────────────────────────────────

const ClientOptions = struct {
    url: []const u8 = "",
    method: http.Method = .get,
    body: ?[]const u8 = null,
    headers: std.ArrayList(http.Header) = .empty,
    repeat: u32 = 1,
    h2c: bool = false,
    cancel_after_ms: ?u32 = null,
    insecure: bool = false,
    max_body: usize = 2048,
    fail_on_status: bool = false,
    verbose: bool = false,

    fn deinit(self: *ClientOptions, gpa: Allocator) void {
        self.headers.deinit(gpa);
    }
};

fn runClient(gpa: Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var opts = parseClientArgs(gpa, args) catch |err| switch (err) {
        error.UsagePrinted => return 0,
        error.BadUsage => return local_failure_exit,
        else => return err,
    };
    defer opts.deinit(gpa);
    if (opts.url.len == 0) {
        std.debug.print("http-demo: client needs a URL (try --help)\n", .{});
        return local_failure_exit;
    }

    // Parsed here, before any socket exists, purely so a typo is a clear
    // message instead of a connect failure to a misread host.
    const url = http.Url.parse(opts.url) catch |err| {
        std.debug.print("http-demo: cannot parse '{s}': {t}\n", .{ opts.url, err });
        return local_failure_exit;
    };
    if (opts.h2c and url.scheme == .https) {
        std.debug.print(
            \\http-demo: --h2c is CLEARTEXT HTTP/2 (RFC 9113 3.3 prior knowledge) and
            \\  cannot be spoken to an https:// URL. Over TLS, h2 is selected only by
            \\  ALPN — do the handshake with your own TLS library offering
            \\  `http.alpn_offer`, and when `http.protocolFromAlpn` says .h2, hand the
            \\  plaintext stream to `Client.connectH2Over`. This demo has no TLS
            \\  library to do that with.
            \\
        , .{});
        return local_failure_exit;
    }
    if (opts.cancel_after_ms != null and opts.h2c) {
        std.debug.print(
            \\http-demo: --cancel-after is the HTTP/1.1 `Response.readFailure()` seam
            \\  and has no h2 equivalent here: `h2_client` assembles a whole Response,
            \\  so there is no caller-driven `*std.Io.Reader` to cancel mid-body.
            \\
        , .{});
        return local_failure_exit;
    }

    var client: http.Client = .init(io, gpa, .{
        .tls = .{ .verify = if (opts.insecure) .insecure_no_verify else .strict },
        .user_agent = "http-demo/1.0 (zig-libs-http)",
    });
    defer client.deinit();

    if (opts.h2c) return runClientH2c(gpa, &client, url, &opts);
    return runClientH1(gpa, io, &client, &opts, url.scheme);
}

fn parseClientArgs(gpa: Allocator, args: *std.process.Args.Iterator) !ClientOptions {
    var opts: ClientOptions = .{};
    errdefer opts.deinit(gpa);
    var method_given = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return error.UsagePrinted;
        } else if (std.mem.eql(u8, arg, "-v")) {
            opts.verbose = true;
        } else if (std.mem.eql(u8, arg, "--h2c")) {
            opts.h2c = true;
        } else if (std.mem.eql(u8, arg, "--insecure")) {
            opts.insecure = true;
        } else if (std.mem.eql(u8, arg, "--fail")) {
            opts.fail_on_status = true;
        } else if (std.mem.eql(u8, arg, "-X")) {
            const token = try nextValue(args, "-X");
            opts.method = http.Server.methodFromToken(token) orelse {
                std.debug.print("http-demo: -X {s}: not a method this module models\n", .{token});
                return error.BadUsage;
            };
            method_given = true;
        } else if (std.mem.eql(u8, arg, "-d")) {
            opts.body = try nextValue(args, "-d");
            if (!method_given) opts.method = .post;
        } else if (std.mem.eql(u8, arg, "-H")) {
            const text = try nextValue(args, "-H");
            const colon = std.mem.indexOfScalar(u8, text, ':') orelse {
                std.debug.print("http-demo: -H wants \"Name: value\", got '{s}'\n", .{text});
                return error.BadUsage;
            };
            try opts.headers.append(gpa, .{
                .name = text[0..colon],
                .value = std.mem.trim(u8, text[colon + 1 ..], " \t"),
            });
        } else if (std.mem.eql(u8, arg, "--repeat")) {
            opts.repeat = try parseIntArg(u32, args, "--repeat");
        } else if (std.mem.eql(u8, arg, "--cancel-after")) {
            opts.cancel_after_ms = try parseIntArg(u32, args, "--cancel-after");
        } else if (std.mem.eql(u8, arg, "--max-body")) {
            opts.max_body = try parseIntArg(usize, args, "--max-body");
        } else if (std.mem.startsWith(u8, arg, "-")) {
            std.debug.print("http-demo: unknown client option '{s}' (try --help)\n", .{arg});
            return error.BadUsage;
        } else if (opts.url.len == 0) {
            opts.url = arg;
        } else {
            std.debug.print("http-demo: more than one URL given ('{s}')\n", .{arg});
            return error.BadUsage;
        }
    }
    if (opts.repeat == 0) opts.repeat = 1;
    return opts;
}

// ── HTTP/1.1 (and HTTP/1.1-over-TLS) ────────────────────────────────────────

fn runClientH1(
    gpa: Allocator,
    io: std.Io,
    client: *http.Client,
    opts: *const ClientOptions,
    url_scheme: http.Url.Scheme,
) !u8 {
    var last_status: u16 = 0;
    var round: u32 = 0;
    while (round < opts.repeat) : (round += 1) {
        if (opts.repeat > 1) std.debug.print("── request {d}/{d} ──\n", .{ round + 1, opts.repeat });

        var res = client.request(opts.method, opts.url, .{
            .headers = opts.headers.items,
            .body = opts.body,
        }) catch |err| {
            reportClientError(err, opts.url);
            return local_failure_exit;
        };
        defer res.deinit();
        last_status = res.status;

        printResponseHead(&res, opts.verbose);
        if (round == 0 and url_scheme == .https) std.debug.print(
            \\  ^ that head came over a real `std.crypto.tls` handshake, chain and
            \\    hostname verified against the system CA bundle. Note it is
            \\    HTTP/1.1-over-TLS: `Client.request` does not offer ALPN "h2" by
            \\    itself. h2 over TLS is `Client.connectH2Over` on a stream whose
            \\    handshake you drove, offering `http.alpn_offer`.
            \\
        , .{});

        if (opts.cancel_after_ms) |ms| {
            runCancelDemo(io, &res, ms);
        } else {
            // `readAllAlloc` already recovers a cancelation internally; this
            // path is the ordinary one and the body is small by construction
            // (`--max-body` is a print cap, this is the read cap).
            const body = res.readAllAlloc(gpa, 8 << 20) catch |err| {
                std.debug.print("http-demo: reading the body failed: {t}\n", .{err});
                return local_failure_exit;
            };
            defer gpa.free(body);
            printBody(body, opts.max_body);
        }
    }

    if (opts.repeat > 1) std.debug.print(
        \\
        \\http-demo: {d} requests, {d} fresh dial(s), {d} idle connection(s) pooled.
        \\  One dial for many requests is the keep-alive pool working: a
        \\  `Response.deinit` returns its connection when the exchange left it
        \\  clean and fully drained, and the next request to the same
        \\  (scheme, host, port) picks it back up.
        \\
    , .{ opts.repeat, client.dialCount(), client.poolIdleCount() });

    if (opts.fail_on_status and last_status >= 400) return local_failure_exit;
    return 0;
}

fn printResponseHead(res: *http.Client.Response, verbose: bool) void {
    std.debug.print("HTTP/1.{d} {d} {s}\n", .{
        @as(u8, if (res.head.http1_0) 0 else 1),
        res.status,
        res.reason,
    });
    if (verbose) {
        var it = res.head.iterate();
        while (it.next()) |entry| std.debug.print("  {s}: {s}\n", .{ entry.name, entry.value });
    } else {
        if (res.header("content-type")) |v| std.debug.print("  content-type: {s}\n", .{v});
        if (res.header("content-length")) |v| std.debug.print("  content-length: {s}\n", .{v});
        if (res.head.chunked) std.debug.print("  transfer-encoding: chunked\n", .{});
    }
}

fn printBody(body: []const u8, cap: usize) void {
    const shown = @min(body.len, cap);
    std.debug.print("--- body ({d} bytes", .{body.len});
    if (shown < body.len) std.debug.print(", first {d} shown", .{shown});
    std.debug.print(") ---\n{s}", .{body[0..shown]});
    if (body.len == 0 or body[body.len - 1] != '\n') std.debug.print("\n", .{});
    if (shown < body.len) std.debug.print("…\n", .{});
}

fn reportClientError(err: http.Client.Error, url: []const u8) void {
    std.debug.print("http-demo: {s}: {t}\n", .{ url, err });
    switch (err) {
        error.ConnectFailed => std.debug.print(
            "  nothing is listening there (start `http-demo server` in another terminal)\n",
            .{},
        ),
        error.TlsFailed => std.debug.print(
            \\  the TLS handshake failed. If this is the demo's own server: it serves
            \\  PLAINTEXT only — there is no TLS server in this module (see its startup
            \\  banner). Use an http:// URL. --insecure only skips verification; it
            \\  cannot conjure a handshake the peer never offered.
            \\
        , .{}),
        error.CertificateBundleLoadFailure => std.debug.print(
            "  the system CA bundle could not be read; --insecure skips verification\n",
            .{},
        ),
        error.Timeout => std.debug.print(
            "  `Options.total_timeout_ms` (30 s by default) expired before the head arrived\n",
            .{},
        ),
        else => {},
    }
}

// ── the cancellation seam ───────────────────────────────────────────────────
//
// Why this needs its own section: `*std.Io.Reader`'s error set is exactly
// `{ReadFailed, EndOfStream}` (CONVENTIONS.md §2). A caller streaming a body
// through `reader()` therefore CANNOT tell "the task I was running on was
// canceled" from "the peer died" — the type erased it. `readFailure()` is the
// seam that asks the connection what really happened, and this is the only
// place in the repository that shows it from outside the module.
//
// The proof is arranged so it cannot pass by accident: the drain runs on a
// concurrent task, the main thread sleeps, and then cancels it while it is
// parked in a read on `/slow`. `/truncate` is the control — the identical
// drain, a genuinely broken connection, and a different answer.

const Drain = struct {
    res: *http.Client.Response,
    bytes: u64 = 0,
    /// What `reader()` reported, and what `readFailure()` recovered from it.
    reader_said: ?anyerror = null,
    real_cause: ?http.Client.Error = null,

    /// Drain the body, reporting the true cause of a `ReadFailed`.
    ///
    /// The `catch` here is the whole lesson: `error.ReadFailed` is all the
    /// reader can say, and it means at least three different things.
    ///
    /// `stream` rather than `readSliceShort` on purpose — it hands back
    /// whatever arrived in one go, so the byte count below is the count at
    /// the moment of the cancel. `readSliceShort` waits for a full buffer
    /// and DISCARDS its partial progress on `ReadFailed`, which would have
    /// reported 0 bytes for a read that was demonstrably mid-body.
    fn run(d: *Drain) http.Client.Error!u64 {
        const r = d.res.reader();
        var sink_buf: [4096]u8 = undefined;
        while (true) {
            var sink: std.Io.Writer = .fixed(&sink_buf);
            const n = r.stream(&sink, .limited(sink_buf.len)) catch |err| switch (err) {
                error.EndOfStream => break,
                error.WriteFailed => return error.WriteFailed,
                error.ReadFailed => {
                    d.reader_said = err;
                    const cause = d.res.readFailure();
                    d.real_cause = cause;
                    return cause;
                },
            };
            d.bytes += n;
        }
        return d.bytes;
    }
};

fn runCancelDemo(io: std.Io, res: *http.Client.Response, after_ms: u32) void {
    std.debug.print("--- streaming the body, canceling the read after {d} ms ---\n", .{after_ms});

    var drain: Drain = .{ .res = res };
    var fut = io.concurrent(Drain.run, .{&drain}) catch |err| {
        // Documented and real: with no spare unit of concurrency there is no
        // task to cancel, so this whole demonstration is impossible rather
        // than merely slow. Saying so beats pretending.
        std.debug.print("http-demo: no unit of concurrency available ({t}) — nothing to cancel\n", .{err});
        return;
    };
    io.sleep(.fromMilliseconds(after_ms), .awake) catch {};

    const result = fut.cancel(io);
    if (result) |n| {
        std.debug.print(
            \\the body finished before the cancel landed: {d} bytes.
            \\  Try a longer /slow (…/slow?ms=500&n=20) or a shorter --cancel-after.
            \\
        , .{n});
        return;
    } else |err| {
        std.debug.print(
            \\the read was interrupted mid-body, and here are the TWO answers:
            \\  reader() said            {?t}   <- all a *std.Io.Reader can say
            \\  Response.readFailure()   {?t}   <- what actually happened
            \\  the drain returned       {t}
            \\  bytes taken before it    {d}
            \\
        , .{ drain.reader_said, drain.real_cause, err, drain.bytes });
        switch (err) {
            error.Canceled => std.debug.print(
                \\
                \\  `error.Canceled` is the point. `*std.Io.Reader`'s error set is exactly
                \\  {{ReadFailed, EndOfStream}} (CONVENTIONS.md 2), so the cancelation was
                \\  erased by the type before this caller ever saw it — and a client that
                \\  laundered it into a transport failure would treat the connection as
                \\  stale and transparently RETRY, blocking a second time with the
                \\  cancelation already consumed. `Response.readFailure()` is the seam
                \\  that recovers it, and it exists for exactly that.
                \\
            , .{}),
            error.ReadFailed => std.debug.print(
                \\
                \\  `error.ReadFailed` here means the connection genuinely broke — the
                \\  same code path, a different answer. That is what makes the seam worth
                \\  anything: it distinguishes, rather than always saying "canceled".
                \\
            , .{}),
            else => {},
        }
    }
}

// ── HTTP/2, cleartext (h2c) ─────────────────────────────────────────────────

fn runClientH2c(gpa: Allocator, client: *http.Client, url: http.Url, opts: *const ClientOptions) !u8 {
    // Prior knowledge (RFC 9113 §3.3): the client just opens with the HTTP/2
    // connection preface and SETTINGS. There is no upgrade handshake to fail
    // over from — a peer that does not speak h2c reads the preface as an
    // HTTP/1.1 request line and answers 505, which is why this is opt-in on
    // both ends.
    //
    // ⚠ MODULE GAP, found by running this and visible on `/headers`. The
    // automatic request fields are written by the h1 request writer and by
    // nothing else, so the SAME `Client` with the SAME options sends
    //
    //     h1:   Host, User-Agent (Options.user_agent), Accept-Encoding
    //     h2c:  :authority only
    //
    // An `Options.user_agent` a caller set is silently dropped on one of the
    // client's two protocols — `/hello` prints `user-agent: null` for us and
    // `curl/8.18.0` for curl, on the same route. Passing it per request via
    // `RequestOptions.headers` is the workaround; it is not what a
    // client-wide option promises.
    const session = client.connectH2c(url.host, url.port, .{}) catch |err| {
        std.debug.print("http-demo: h2c connect to {s}:{d} failed: {t}\n", .{ url.host, url.port, err });
        if (err == error.ConnectFailed) std.debug.print(
            "  nothing is listening there\n",
            .{},
        );
        return local_failure_exit;
    };
    defer session.close();

    var target_buf: [1024]u8 = undefined;
    const target = if (url.query.len == 0)
        url.path
    else
        try std.fmt.bufPrint(&target_buf, "{s}?{s}", .{ url.path, url.query });

    // The multiplexing is the point, so every stream is OPENED before any is
    // collected. One connection, `--repeat` requests in flight at once,
    // demultiplexed by stream id on the way back — the h1 pool can only ever
    // give you one exchange per connection at a time.
    var ids: [64]u31 = undefined;
    const n = @min(opts.repeat, ids.len);
    for (0..n) |i| {
        ids[i] = session.request(opts.method, target, .{
            .headers = opts.headers.items,
            .body = opts.body,
        }) catch |err| {
            std.debug.print("http-demo: opening h2 stream {d} failed: {t}\n", .{ i, err });
            return local_failure_exit;
        };
    }
    if (n > 1) std.debug.print("http-demo: {d} streams opened on ONE h2c connection: ", .{n});
    if (n > 1) {
        for (0..n) |i| std.debug.print("{d}{s}", .{ ids[i], if (i + 1 == n) "\n" else " " });
    }

    var last_status: u16 = 0;
    for (0..n) |i| {
        var res = session.awaitResponse(ids[i]) catch |err| {
            std.debug.print("http-demo: stream {d} failed: {t}\n", .{ ids[i], err });
            return local_failure_exit;
        };
        defer res.deinit(gpa);
        last_status = res.status;

        std.debug.print("HTTP/2 {d} (stream {d})\n", .{ res.status, ids[i] });
        if (opts.verbose) {
            for (res.headers.fields) |f| std.debug.print("  {s}: {s}\n", .{ f.name, f.value });
        } else {
            if (res.header("content-type")) |v| std.debug.print("  content-type: {s}\n", .{v});
        }
        printBody(res.body, opts.max_body);
    }

    if (opts.fail_on_status and last_status >= 400) return local_failure_exit;
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// small shared helpers
// ─────────────────────────────────────────────────────────────────────────────

fn nextValue(args: *std.process.Args.Iterator, flag: []const u8) ![]const u8 {
    return args.next() orelse {
        std.debug.print("http-demo: {s} needs a value\n", .{flag});
        return error.BadUsage;
    };
}

fn parseIntArg(comptime T: type, args: *std.process.Args.Iterator, flag: []const u8) !T {
    const text = try nextValue(args, flag);
    return std.fmt.parseInt(T, text, 10) catch {
        std.debug.print("http-demo: {s} wants a number, got '{s}'\n", .{ flag, text });
        return error.BadUsage;
    };
}
