// SPDX-License-Identifier: MIT

//! `imap-demo` — one binary, two modes (`server` and `client`) that talk to
//! each other over a **real TCP socket**. Run the server in one terminal, the
//! client in another, and watch a mail-archiving consumer open a session,
//! upgrade it with STARTTLS, log in, ask INBOX which messages are unread and
//! pull their envelopes.
//!
//! **`client` mode is the thing to read**, and it is meant to be pointed at a
//! real server as much as at the prop one:
//!
//!     imap-demo client --host imap.example.com --port 143
//!
//! **`server` mode is a prop, and here is exactly what it is.** This module is
//! a client; it ships no server, and IMAP is far too stateful for forty lines
//! of one to be honest. What the prop below really does is **command-driven**:
//! it reads each command line, takes the client's own tag off it, dispatches on
//! the command word, tracks the authenticated/selected state, and refuses what
//! is illegal in the current state. What it does NOT do is own a mailbox — the
//! `SEARCH` result and the two `FETCH` envelopes are canned, copied from the
//! RFC 9051 examples. So framing, tag matching, state and the error paths are
//! genuinely exercised over TCP; the mailbox *contents* are a fixture. For real
//! mailbox data, point `client` at a real IMAP server.
//!
//! **⚠ NO TLS HAPPENS HERE, IN EITHER MODE.** This repo terminates no TLS by
//! design: `Client` negotiates `STARTTLS` and the caller performs the
//! handshake, then hands the encrypted streams back through `tlsEstablished`.
//! This demo hands back the SAME plaintext socket, and the prop server answers
//! `OK Begin TLS negotiation now` and keeps speaking plaintext. Both halves say
//! so when it happens. What that genuinely exercises is the STARTTLS
//! *negotiation*: the pre-handshake capability list being discarded (RFC 9051
//! §6.2.1), `LOGINDISABLED` and the plaintext-password refusal before it, and
//! `error.PlaintextInjection` when a server pushes bytes across the boundary.
//! What it does not exercise, and must not be read as evidence of, is
//! encryption.
//!
//! Not port 143/993: 143 is conventionally occupied and 993 is implicit-TLS.
//! 1143 is the unprivileged stand-in this module's own live interop test uses.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`deps` only, no `test_deps`, no access to anything the module does
//! not export). If a type needed to call the API is not public, or an error
//! cannot be named from outside, this file stops compiling. The module's own
//! tests cannot notice either, because they live inside it.

const std = @import("std");
const imap = @import("imap");

const local_failure_exit: u8 = 1;
const default_port: u16 = 1143;

const usage_text =
    \\imap-demo — an IMAP4rev2 client demo for the `imap` module, with a prop server.
    \\
    \\usage:
    \\  imap-demo                self-demo: real client + prop server, one
    \\                           process, loopback only, asserted (no args)
    \\  imap-demo server [options]
    \\  imap-demo client [options]
    \\
    \\server options:
    \\  --listen <addr>   address to bind             (default 127.0.0.1)
    \\  --port <port>     TCP port                    (default 1143)
    \\  --no-starttls     do not advertise STARTTLS
    \\  --inject          push a line at the client between `OK Begin TLS
    \\                    negotiation now` and the handshake — the STARTTLS
    \\                    response-injection flaw. The client must abort.
    \\  --once            serve one connection, then exit
    \\  -h, --help        this text
    \\
    \\client options:
    \\  --host <host>     server to connect to        (default 127.0.0.1)
    \\  --port <port>     TCP port                    (default 1143)
    \\  --user <name>     LOGIN user                  (default gray)
    \\  --pass <secret>   LOGIN password              (default hunter2)
    \\  --mailbox <name>  mailbox to select           (default INBOX)
    \\  --no-starttls     do not attempt STARTTLS
    \\  --allow-plaintext-auth
    \\                    permit LOGIN on a link this client has not seen
    \\                    encrypted. The module refuses by default; this is the
    \\                    opt-in for a transport the CALLER knows is trusted.
    \\  -h, --help        this text
    \\
    \\Two terminals:
    \\  imap-demo server --once
    \\  imap-demo client
    \\
    \\Against a foreign implementation — `pymap`, the server this module's own
    \\live interop test uses, started with no TLS at all:
    \\  pymap --host 127.0.0.1 --port 11143 --no-tls dict --demo-data
    \\  imap-demo client --port 11143 --user demouser --pass demopass \
    \\      --no-starttls --allow-plaintext-auth
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // `imap` allocates: the session duplicates capabilities and mailbox state
    // into the caller's allocator, and FETCH/SEARCH results are handed out in
    // an allocator the caller names. A `DebugAllocator` that panics on leak
    // makes this example a check on that ownership contract.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.skip(); // argv[0]

    const mode = args.next() orelse return runSelfDemo(gpa, io);

    if (std.mem.eql(u8, mode, "server")) return runServer(io, &args);
    if (std.mem.eql(u8, mode, "client")) return runClient(gpa, io, &args);
    if (std.mem.eql(u8, mode, "-h") or std.mem.eql(u8, mode, "--help")) {
        std.debug.print("{s}", .{usage_text});
        return 0;
    }

    std.debug.print("imap-demo: unknown mode '{s}' (expected `server` or `client`)\n\n{s}", .{ mode, usage_text });
    return local_failure_exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// self-demo (no arguments): the real client against the prop server, one
// process, every interesting value asserted
// ─────────────────────────────────────────────────────────────────────────────
//
// The prop server IS the fixture peer the module doc talks about: real
// framing, real tag matching, real per-state refusals, over a real loopback
// socket — only the mailbox CONTENTS are canned (RFC 9051's own examples;
// see the file comment). It runs as a concurrent task on an ephemeral port;
// the main task drives `imap.Client` through the exact sequence `client`
// mode does, asserting each step instead of only printing it.

/// Accept exactly one connection and serve it with the prop server's command
/// loop, then return. Split out so the self-demo can run it as a concurrent
/// task against a listener it bound itself (ephemeral port).
fn acceptOneConnection(io: std.Io, listener: *std.Io.net.Server, opts: ServerOptions) !u8 {
    var stream = try listener.accept(io);
    serveConnection(io, opts, &stream);
    stream.close(io);
    return 0;
}

fn runSelfDemo(gpa: std.mem.Allocator, io: std.Io) !u8 {
    const bind_addr = std.Io.net.IpAddress.parse("127.0.0.1", 0) catch unreachable;
    var listener = bind_addr.listen(io, .{}) catch |err| {
        std.debug.print("imap-demo self-demo: cannot listen on 127.0.0.1:0: {t}\n", .{err});
        return local_failure_exit;
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    const server_opts: ServerOptions = .{ .listen = "127.0.0.1", .port = port, .starttls = true, .inject = false, .once = true };
    var accept_fut = io.concurrent(acceptOneConnection, .{ io, &listener, server_opts }) catch |err| {
        std.debug.print("imap-demo self-demo: no concurrency available ({t}); cannot self-demo\n", .{err});
        return local_failure_exit;
    };
    // Idempotent (`Future.await`/`cancel` doc comment): runs on every exit
    // path, including an early `return` below, and costs nothing if the
    // explicit `await` near the end already ran.
    defer _ = accept_fut.cancel(io) catch @as(u8, 0);

    const connect_addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch unreachable;
    var stream = connect_addr.connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("imap-demo self-demo: cannot connect to 127.0.0.1:{d}: {t}\n", .{ port, err });
        return local_failure_exit;
    };
    defer stream.close(io);

    var rbuf: [16384]u8 = undefined;
    var wbuf: [16384]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    defer std.crypto.secureZero(u8, &wbuf);

    var c = imap.Client.init(gpa, &sr.interface, &sw.interface, .{
        .on_unilateral = onUnilateral,
        .allow_plaintext_auth = false,
    });
    defer c.deinit();

    std.debug.print("imap-demo self-demo: connected to an in-process prop server at 127.0.0.1:{d}\n\n", .{port});

    std.debug.print("[1] greeting\n", .{});
    const greeting = try c.greet();
    if (greeting.status != .ok) @panic("imap-demo self-demo: greeting status was not OK");
    if (!c.hasCap("STARTTLS")) @panic("imap-demo self-demo: expected STARTTLS advertised pre-TLS");
    if (!c.hasCap("LOGINDISABLED")) @panic("imap-demo self-demo: expected LOGINDISABLED advertised pre-TLS");

    // The refusal that never reaches the wire: a password over cleartext.
    // The prop server advertises LOGINDISABLED, so the module's own
    // capability check fires before the (also-refused) plaintext check does.
    std.debug.print("\n[2] LOGIN before any encryption — must be refused locally\n", .{});
    if (c.login("gray", "hunter2")) |_| {
        @panic("imap-demo self-demo: plaintext LOGIN was unexpectedly accepted");
    } else |err| switch (err) {
        error.LoginDisabled => {},
        else => {
            std.debug.print("    unexpected error: {s}\n", .{describe(err)});
            return local_failure_exit;
        },
    }

    std.debug.print("\n[3] STARTTLS\n", .{});
    _ = try c.startTls();
    // ⚠ No handshake performed — see the file comment. Still asserted:
    // `tlsEstablished` must accept the same plaintext streams handed back.
    _ = try c.tlsEstablished(&sr.interface, &sw.interface);
    if (c.hasCap("LOGINDISABLED")) @panic("imap-demo self-demo: LOGINDISABLED should be gone from the post-STARTTLS list");
    if (!c.hasCap("AUTH=PLAIN")) @panic("imap-demo self-demo: expected AUTH=PLAIN post-STARTTLS");

    std.debug.print("\n[4] LOGIN\n", .{});
    _ = try c.login("gray", "hunter2");
    if (c.state != .authenticated) @panic("imap-demo self-demo: expected state .authenticated after LOGIN");

    std.debug.print("\n[5] SELECT INBOX\n", .{});
    _ = try c.select("INBOX", false);
    if (c.mailbox.exists != 3) @panic("imap-demo self-demo: expected 3 EXISTS");
    if (c.mailbox.uid_validity != 3857529045) @panic("imap-demo self-demo: UIDVALIDITY mismatch");
    if (c.mailbox.uid_next != 4392) @panic("imap-demo self-demo: UIDNEXT mismatch");
    if (c.mailbox.read_only) @panic("imap-demo self-demo: expected read-write SELECT");

    var results = std.heap.ArenaAllocator.init(gpa);
    defer results.deinit();

    std.debug.print("\n[6] SEARCH NOT SEEN\n", .{});
    const unseen = try c.searchMessages(results.allocator(), false, .{}, &.{ .not_flag = &.{"\\Seen"} });
    if (unseen.numbers.len != 2 or unseen.numbers[0] != 2 or unseen.numbers[1] != 3) {
        @panic("imap-demo self-demo: expected SEARCH to report messages 2 and 3");
    }

    std.debug.print("\n[7] FETCH 2,3 (UID ENVELOPE RFC822.SIZE)\n", .{});
    const msgs = try c.fetchMessages(results.allocator(), "2,3", false, .{
        .uid = true,
        .envelope = true,
        .rfc822_size = true,
    });
    if (msgs.len != 2) @panic("imap-demo self-demo: expected 2 FETCH results");
    var saw_summary = false;
    var saw_reply = false;
    for (msgs) |m| {
        const env = switch (m.find(.envelope) orelse continue) {
            .envelope => |e| e,
            else => continue,
        };
        const subject = env.subject orelse continue;
        if (std.mem.eql(u8, subject, "IMAP4rev2 WG mtg summary and minutes")) saw_summary = true;
        if (std.mem.eql(u8, subject, "Re: minutes")) saw_reply = true;
        std.debug.print("    #{d} uid={?d} \"{s}\"\n", .{ m.seq, m.uid(), subject });
    }
    if (!saw_summary or !saw_reply) @panic("imap-demo self-demo: RFC 9051 example envelopes not found in FETCH results");

    std.debug.print("\n[8] LOGOUT\n", .{});
    try c.logout();
    if (c.state != .logout) @panic("imap-demo self-demo: expected state .logout after LOGOUT");

    const accept_result = accept_fut.await(io) catch |err| {
        std.debug.print("imap-demo self-demo: server task ended abnormally: {t}\n", .{err});
        return local_failure_exit;
    };
    if (accept_result != 0) @panic("imap-demo self-demo: server task reported failure");

    std.debug.print(
        "\nimap-demo self-demo: OK\n" ++
            "  real imap.Client against the prop server (real framing, tags, state\n" ++
            "  and refusals; canned mailbox contents), both in this process, over\n" ++
            "  127.0.0.1 -- greeting, the pre-TLS LOGIN refusal, STARTTLS, LOGIN,\n" ++
            "  SELECT, SEARCH and FETCH were all asserted above.\n" ++
            "  no real network, no root, no external daemon.\n" ++
            "  see --help for the server/client subcommands this binary also offers.\n",
        .{},
    );
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// client mode — what a mail-archiving consumer does with `imap`
// ─────────────────────────────────────────────────────────────────────────────

/// Unsolicited untagged data can land between any two responses, because it
/// reports something the server just learned. A consumer that cares about
/// live mailbox state registers an observer instead of losing it.
fn onUnilateral(ctx: ?*anyopaque, data: imap.response.Data) anyerror!void {
    _ = ctx;
    switch (data) {
        .exists => |n| std.debug.print("    (mailbox now holds {d} messages)\n", .{n}),
        .expunge => |n| std.debug.print("    (message {d} was expunged)\n", .{n}),
        else => {},
    }
}

const ClientOptions = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = default_port,
    user: []const u8 = "gray",
    pass: []const u8 = "hunter2",
    mailbox: []const u8 = "INBOX",
    starttls: bool = true,
    allow_plaintext_auth: bool = false,
};

fn runClient(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var opts: ClientOptions = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return 0;
        } else if (std.mem.eql(u8, arg, "--no-starttls")) {
            opts.starttls = false;
        } else if (std.mem.eql(u8, arg, "--allow-plaintext-auth")) {
            opts.allow_plaintext_auth = true;
        } else if (std.mem.eql(u8, arg, "--host")) {
            opts.host = (try nextValue(args, "--host")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--user")) {
            opts.user = (try nextValue(args, "--user")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--pass")) {
            opts.pass = (try nextValue(args, "--pass")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--mailbox")) {
            opts.mailbox = (try nextValue(args, "--mailbox")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = (try parseIntArg(u16, args, "--port")) orelse return local_failure_exit;
        } else {
            std.debug.print("imap-demo: unknown client option '{s}' (try --help)\n", .{arg});
            return local_failure_exit;
        }
    }

    const addr = std.Io.net.IpAddress.parse(opts.host, opts.port) catch |err| {
        std.debug.print("imap-demo: cannot parse {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return local_failure_exit;
    };
    var stream = addr.connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("imap-demo: cannot connect to {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return local_failure_exit;
    };
    defer stream.close(io);

    // `Client.init` takes a `*std.Io.Reader` and a `*std.Io.Writer` and owns no
    // socket and no TLS — so plain TCP, an encrypted stream and a fixture
    // buffer are all the same thing to it. Here they are a socket's.
    var rbuf: [16384]u8 = undefined;
    var wbuf: [16384]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    // The password is encoded straight into this writer's buffer and the
    // module keeps no copy — clearing that residue is the CALLER's job, and
    // this is the caller.
    defer std.crypto.secureZero(u8, &wbuf);

    var c = imap.Client.init(gpa, &sr.interface, &sw.interface, .{
        .on_unilateral = onUnilateral,
        .allow_plaintext_auth = opts.allow_plaintext_auth,
    });
    defer c.deinit();

    std.debug.print("imap-demo: connected to {s}:{d}\n\n", .{ opts.host, opts.port });

    std.debug.print("[1] greeting\n", .{});
    const greeting = c.greet() catch |err| {
        std.debug.print("    greeting failed: {s}\n", .{describe(err)});
        return local_failure_exit;
    };
    // ⚠ `Completion.text` is a public field that no code path in the module
    // can populate — `client.zig` writes `.text = null` at both of its two
    // construction sites, although `response.Status.text` carries the parsed
    // text and the response layer's own tests assert it. So the greeting's
    // human-readable line ("Service Ready", the server's version banner) is
    // parsed and then dropped, and a caller has no way to reach it.
    std.debug.print("    greeting status: {s}{s}\n", .{
        @tagName(greeting.status),
        if (greeting.text) |t| t else " (Completion.text is always null — see the note above)",
    });
    std.debug.print("    capabilities: IMAP4rev2={} IMAP4rev1={} STARTTLS={} LOGINDISABLED={}\n", .{
        c.hasCap("IMAP4rev2"), c.hasCap("IMAP4rev1"), c.hasCap("STARTTLS"), c.hasCap("LOGINDISABLED"),
    });

    // ── the refusals that never reach the wire ──────────────────────────────
    //
    // A password sent over cleartext is a password given away. The module
    // makes that a LOCAL error rather than a wire event, so it never leaves
    // the process — which also means the demo can show it without leaking
    // anything. Skipped when the caller has explicitly opted in.
    if (!opts.allow_plaintext_auth) {
        std.debug.print("\n[2] LOGIN before any encryption — refused locally\n", .{});
        if (c.login(opts.user, opts.pass)) |_| {
            std.debug.print("    unexpected: plaintext LOGIN was accepted\n", .{});
        } else |err| switch (err) {
            // The server itself said LOGIN is not permitted on this link. The
            // module already parsed that capability; it simply used to never
            // consult it.
            error.LoginDisabled => std.debug.print("    error.LoginDisabled — the server forbids LOGIN before TLS\n", .{}),
            error.PlaintextAuth => std.debug.print("    error.PlaintextAuth — this client refuses to send a password in the clear\n", .{}),
            else => {
                std.debug.print("    login failed for another reason: {s}\n", .{describe(err)});
                return local_failure_exit;
            },
        }
    } else {
        std.debug.print("\n[2] --allow-plaintext-auth: the password WILL go out in the clear.\n" ++
            "    That is the opt-in for a transport the caller knows is trusted (a unix\n" ++
            "    socket, a loopback test server, a tunnel it established itself).\n", .{});
    }

    // ── STARTTLS ────────────────────────────────────────────────────────────
    if (!opts.starttls) {
        std.debug.print("\n[3] STARTTLS skipped (--no-starttls): the link stays as it is\n", .{});
    } else {
        std.debug.print("\n[3] STARTTLS\n", .{});
        if (!c.hasCap("STARTTLS")) {
            std.debug.print("    no STARTTLS offered, giving up (pass --no-starttls to continue anyway)\n", .{});
            return local_failure_exit;
        }
        _ = c.startTls() catch |err| switch (err) {
            // The server sent bytes after its OK, before any peer was
            // authenticated. Replaying those as if they came from inside the
            // tunnel is the classic STARTTLS injection; the module refuses.
            error.PlaintextInjection => {
                std.debug.print("    error.PlaintextInjection — bytes buffered across the TLS boundary, aborting\n", .{});
                return local_failure_exit;
            },
            else => {
                std.debug.print("    STARTTLS failed: {s}\n", .{describe(err)});
                return local_failure_exit;
            },
        };
        // ⚠ The handshake is the caller's job, and this caller does not do
        // one. In a real program the two arguments below are
        // `std.crypto.tls.Client`'s streams; here they are the SAME plaintext
        // socket. See the file comment.
        std.debug.print("    !! STARTTLS accepted — and this demo performs NO handshake.\n" ++
            "       Everything after this line is still plaintext on the wire.\n", .{});
        _ = c.tlsEstablished(&sr.interface, &sw.interface) catch |err| {
            std.debug.print("    tlsEstablished failed: {s}\n", .{describe(err)});
            return local_failure_exit;
        };
        // This list is the SECOND one. RFC 9051 §6.2.1 makes the client throw
        // away everything it learned from an unauthenticated peer, including
        // the encoder policy derived from it, and ask again.
        std.debug.print("    capabilities re-read after the upgrade: LOGINDISABLED={} AUTH=PLAIN={}\n", .{
            c.hasCap("LOGINDISABLED"), c.hasCap("AUTH=PLAIN"),
        });
    }

    // ── login / select / search / fetch ─────────────────────────────────────
    std.debug.print("\n[4] LOGIN\n", .{});
    _ = c.login(opts.user, opts.pass) catch |err| {
        std.debug.print("    login failed: {s}\n", .{describe(err)});
        return local_failure_exit;
    };
    std.debug.print("    authenticated, state {s}\n", .{@tagName(c.state)});

    std.debug.print("\n[5] SELECT {s}\n", .{opts.mailbox});
    _ = c.select(opts.mailbox, false) catch |err| {
        std.debug.print("    select failed: {s}\n", .{describe(err)});
        return local_failure_exit;
    };
    std.debug.print("    {d} messages, uidvalidity {d}, uidnext {d}, {s}\n", .{
        c.mailbox.exists,
        c.mailbox.uid_validity,
        c.mailbox.uid_next,
        if (c.mailbox.read_only) "read-only" else "read-write",
    });

    // Results outlive the response line they arrived on only if they are
    // allocated somewhere that is not the session's per-line arena. That
    // arena is reset on EVERY line, so anything kept has to be copied out —
    // which is why these calls take an allocator of their own.
    var results = std.heap.ArenaAllocator.init(gpa);
    defer results.deinit();

    std.debug.print("\n[6] SEARCH NOT SEEN\n", .{});
    const unseen = c.searchMessages(
        results.allocator(),
        false,
        .{},
        &.{ .not_flag = &.{"\\Seen"} },
    ) catch |err| {
        std.debug.print("    search failed: {s}\n", .{describe(err)});
        return local_failure_exit;
    };
    std.debug.print("    {d} unread message(s)\n", .{unseen.numbers.len});

    // A sequence set built from what the server actually said, not a constant.
    // `fetchMessages` refuses a set that is not a legal seq-set — the encoder
    // will not put a CRLF from a caller's string onto the socket, which is the
    // IMAP command-injection this module's own live test reproduces.
    var seq_buf: [128]u8 = undefined;
    const seq_set = buildSeqSet(&seq_buf, unseen.numbers) orelse blk: {
        std.debug.print("    nothing unread — fetching the whole mailbox instead\n", .{});
        break :blk "1:*";
    };

    std.debug.print("\n[7] FETCH {s} (UID ENVELOPE RFC822.SIZE)\n", .{seq_set});
    const msgs = c.fetchMessages(results.allocator(), seq_set, false, .{
        .uid = true,
        .envelope = true,
        .rfc822_size = true,
    }) catch |err| switch (err) {
        // The server answered NO or BAD. A mailbox that vanished under us is
        // an ordinary outcome for a background sync, not a crash.
        error.CommandFailed => {
            std.debug.print("    server rejected the FETCH\n", .{});
            return local_failure_exit;
        },
        else => {
            std.debug.print("    fetch failed: {s}\n", .{describe(err)});
            return local_failure_exit;
        },
    };

    for (msgs) |m| {
        const env = switch (m.find(.envelope) orelse continue) {
            .envelope => |e| e,
            else => continue,
        };
        std.debug.print("    #{d} uid={?d} \"{s}\"", .{
            m.seq,
            m.uid(),
            env.subject orelse "(no subject)",
        });
        if (env.from.len > 0) {
            const a = env.from[0];
            std.debug.print(" from {s}@{s}", .{ a.mailbox orelse "?", a.host orelse "?" });
        }
        std.debug.print("\n", .{});
    }

    // LOGOUT gets an untagged BYE first; the module treats that as the
    // expected path rather than a connection error.
    std.debug.print("\n[8] LOGOUT\n", .{});
    c.logout() catch |err| {
        std.debug.print("    logout failed: {s}\n", .{describe(err)});
        return local_failure_exit;
    };
    std.debug.print("    state {s}\n", .{@tagName(c.state)});
    return 0;
}

/// `1,4,7` from a search result, or null when there is nothing to fetch. A
/// sequence set is not the same thing as a list of numbers to the server, but
/// a comma-separated list is the legal degenerate case of one.
fn buildSeqSet(buf: []u8, numbers: []const u32) ?[]const u8 {
    if (numbers.len == 0) return null;
    var w = std.Io.Writer.fixed(buf);
    for (numbers, 0..) |n, i| {
        if (i != 0) w.writeByte(',') catch return null;
        w.print("{d}", .{n}) catch return null;
    }
    return w.buffered();
}

fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.ServerClosed => "ServerClosed — the server sent BYE and hung up.",
        error.CommandFailed => "CommandFailed — the server answered NO or BAD.",
        error.BadState => "BadState — that command is not legal in this session state.",
        error.ReadFailed, error.WriteFailed => "the socket itself failed.",
        else => @errorName(err),
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// server mode — a command-driven prop with a canned mailbox
// ─────────────────────────────────────────────────────────────────────────────
//
// State, tags and the illegal-in-this-state refusals are real. The mailbox is
// not: `SEARCH` and `FETCH` answer with fixtures copied from the RFC 9051
// examples, whatever was asked for. Nothing here should be copied into a
// module — there is no mailbox store, no ACL, and it accepts any password.

/// Copied from RFC 9051's own FETCH examples, so the envelopes a reader sees
/// are the ones the specification uses.
const canned_fetch =
    "* 2 FETCH (UID 4827313 ENVELOPE (" ++
    "\"Wed, 17 Jul 1996 02:23:25 -0700 (PDT)\" " ++
    "\"IMAP4rev2 WG mtg summary and minutes\" " ++
    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " ++
    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " ++
    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) " ++
    "((NIL NIL \"imap\" \"cac.washington.edu\")) NIL NIL NIL " ++
    "\"<B27397-0100000@cac.washington.edu>\") RFC822.SIZE 4286)\r\n" ++
    "* 3 FETCH (UID 4827314 ENVELOPE (" ++
    "\"Thu, 18 Jul 1996 09:02:11 -0700\" " ++
    "\"Re: minutes\" " ++
    "((NIL NIL \"klensin\" \"mit.edu\")) NIL NIL " ++
    "((\"Terry Gray\" NIL \"gray\" \"cac.washington.edu\")) NIL NIL " ++
    "\"<B27397-0100000@cac.washington.edu>\" " ++
    "\"<B27401-0100000@mit.edu>\") RFC822.SIZE 998)\r\n";

const ServerOptions = struct {
    listen: []const u8 = "127.0.0.1",
    port: u16 = default_port,
    starttls: bool = true,
    inject: bool = false,
    once: bool = false,
};

fn runServer(io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var opts: ServerOptions = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return 0;
        } else if (std.mem.eql(u8, arg, "--once")) {
            opts.once = true;
        } else if (std.mem.eql(u8, arg, "--no-starttls")) {
            opts.starttls = false;
        } else if (std.mem.eql(u8, arg, "--inject")) {
            opts.inject = true;
        } else if (std.mem.eql(u8, arg, "--listen")) {
            opts.listen = (try nextValue(args, "--listen")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = (try parseIntArg(u16, args, "--port")) orelse return local_failure_exit;
        } else {
            std.debug.print("imap-demo: unknown server option '{s}' (try --help)\n", .{arg});
            return local_failure_exit;
        }
    }

    const addr = std.Io.net.IpAddress.parse(opts.listen, opts.port) catch |err| {
        std.debug.print("imap-demo: cannot parse listen address {s}:{d}: {t}\n", .{ opts.listen, opts.port, err });
        return local_failure_exit;
    };
    // Deliberately NOT `reuse_address`: in `std.Io.net` that sets SO_REUSEPORT
    // too, so a second imap-demo server would silently share the port.
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("imap-demo: cannot listen on {s}:{d}: {t}\n", .{ opts.listen, opts.port, err });
        return local_failure_exit;
    };
    defer listener.deinit(io);

    std.debug.print("imap-demo: prop IMAP4rev2 server on {s}:{d}{s}{s}\n", .{
        opts.listen,
        opts.port,
        if (opts.starttls) ", advertising STARTTLS (with NO handshake behind it)" else ", no STARTTLS",
        if (opts.inject) ", and injecting plaintext across the TLS boundary" else "",
    });
    std.debug.print("  the mailbox is a fixture: SEARCH and FETCH answer with RFC 9051's examples\n", .{});

    while (true) {
        var stream = listener.accept(io) catch |err| {
            std.debug.print("imap-demo: accept failed: {t}\n", .{err});
            return local_failure_exit;
        };
        serveConnection(io, opts, &stream);
        stream.close(io);
        if (opts.once) break;
    }
    return 0;
}

const SessionState = enum { not_authenticated, authenticated, selected, logout };

fn serveConnection(io: std.Io, opts: ServerOptions, stream: *std.Io.net.Stream) void {
    std.debug.print("\n-- client connected\n", .{});
    var rbuf: [16384]u8 = undefined;
    var wbuf: [16384]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    const r = &sr.interface;
    const w = &sw.interface;

    var state: SessionState = .not_authenticated;
    var tls = false;

    var greet_buf: [256]u8 = undefined;
    say(w, std.fmt.bufPrint(&greet_buf, "* OK [CAPABILITY {s}] Service Ready\r\n", .{capabilityList(opts, tls)}) catch return);

    while (true) {
        const line = r.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream => break,
            else => {
                std.debug.print("   read failed: {t}\n", .{err});
                break;
            },
        };
        const text = std.mem.trimEnd(u8, line, "\r\n");
        if (text.len == 0) continue;
        std.debug.print("   <- {s}\n", .{redact(text)});

        // Every IMAP command is `tag SP command [SP args]`, and the tag is the
        // client's — echoing back a tag we invented is the single fastest way
        // to desynchronise a session, which is why this takes it off the line
        // rather than counting.
        var it = std.mem.splitScalar(u8, text, ' ');
        const tag = it.next() orelse continue;
        const cmd = it.next() orelse {
            reply(w, tag, "BAD Missing command\r\n");
            continue;
        };
        const rest = it.rest();

        // A synchronising literal is the one exchange an offline transcript
        // cannot cover, and this prop does not implement it. Say so rather
        // than hanging: an unanswered `{n}` is a deadlock, not a slow server.
        if (std.mem.endsWith(u8, text, "}") and std.mem.lastIndexOfScalar(u8, text, '{') != null) {
            reply(w, tag, "BAD This prop server does not accept literals\r\n");
            continue;
        }

        if (eq(cmd, "CAPABILITY")) {
            var buf: [256]u8 = undefined;
            say(w, std.fmt.bufPrint(&buf, "* CAPABILITY {s}\r\n", .{capabilityList(opts, tls)}) catch continue);
            reply(w, tag, "OK CAPABILITY completed\r\n");
        } else if (eq(cmd, "NOOP")) {
            reply(w, tag, "OK NOOP completed\r\n");
        } else if (eq(cmd, "STARTTLS")) {
            if (!opts.starttls or tls or state != .not_authenticated) {
                reply(w, tag, "BAD STARTTLS not available now\r\n");
                continue;
            }
            if (opts.inject) {
                // The STARTTLS response-injection flaw. After the OK the
                // server must send NOTHING until the handshake; anything here
                // would be read by a naive client as though it had arrived
                // inside the tunnel.
                //
                // ⚠ It goes out in the SAME write as the OK, and that is not
                // cosmetic. The client's guard is "is anything left in the
                // reader's buffer after the OK", and it is exactly as strong
                // as what one read returned — flushing separately leaves the
                // injected line in the kernel socket queue where the check
                // cannot see it. `imap/src/client.zig` documents that ceiling;
                // a real attacker on the path sends one segment.
                std.debug.print("   -> INJECTING a line across the TLS boundary, in the same write\n", .{});
                var buf: [256]u8 = undefined;
                say(w, std.fmt.bufPrint(&buf, "{s} OK Begin TLS negotiation now\r\n" ++
                    "* OK [ALERT] Injected, and a client that reads this is broken\r\n", .{tag}) catch continue);
            } else {
                reply(w, tag, "OK Begin TLS negotiation now\r\n");
            }
            // ⚠ No handshake. The socket stays plaintext; see the file comment.
            std.debug.print("   !! no handshake performed — still plaintext\n", .{});
            tls = true;
        } else if (eq(cmd, "LOGIN")) {
            if (state != .not_authenticated) {
                reply(w, tag, "BAD Already authenticated\r\n");
                continue;
            }
            if (!tls and opts.starttls) {
                // What LOGINDISABLED means, enforced rather than advertised.
                reply(w, tag, "NO [PRIVACYREQUIRED] LOGIN is disabled on this link\r\n");
                continue;
            }
            state = .authenticated;
            var buf: [256]u8 = undefined;
            say(w, std.fmt.bufPrint(&buf, "{s} OK [CAPABILITY {s}] LOGIN completed\r\n", .{ tag, capabilityList(opts, tls) }) catch continue);
        } else if (eq(cmd, "SELECT") or eq(cmd, "EXAMINE")) {
            if (state == .not_authenticated) {
                reply(w, tag, "BAD Not authenticated\r\n");
                continue;
            }
            say(w, "* 3 EXISTS\r\n" ++
                "* OK [UIDVALIDITY 3857529045] UIDs valid\r\n" ++
                "* OK [UIDNEXT 4392] Predicted next UID\r\n" ++
                "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n" ++
                "* OK [PERMANENTFLAGS (\\Deleted \\Seen \\*)] Limited\r\n");
            state = .selected;
            reply(w, tag, if (eq(cmd, "EXAMINE"))
                "OK [READ-ONLY] EXAMINE completed\r\n"
            else
                "OK [READ-WRITE] SELECT completed\r\n");
        } else if (eq(cmd, "SEARCH") or eq(cmd, "UID")) {
            if (state != .selected) {
                reply(w, tag, "BAD No mailbox selected\r\n");
                continue;
            }
            std.debug.print("   (criteria ignored — this prop's mailbox is a fixture: {s})\n", .{rest});
            say(w, "* SEARCH 2 3\r\n");
            reply(w, tag, "OK SEARCH completed\r\n");
        } else if (eq(cmd, "FETCH")) {
            if (state != .selected) {
                reply(w, tag, "BAD No mailbox selected\r\n");
                continue;
            }
            std.debug.print("   (sequence set ignored — fixture: {s})\n", .{rest});
            say(w, canned_fetch);
            reply(w, tag, "OK FETCH completed\r\n");
        } else if (eq(cmd, "LOGOUT")) {
            say(w, "* BYE Logging out\r\n");
            reply(w, tag, "OK LOGOUT completed\r\n");
            state = .logout;
            break;
        } else {
            reply(w, tag, "BAD Command unrecognized\r\n");
        }
    }
    std.debug.print("-- client disconnected\n", .{});
}

fn capabilityList(opts: ServerOptions, tls: bool) []const u8 {
    if (tls or !opts.starttls) return "IMAP4rev2 IMAP4rev1 AUTH=PLAIN";
    // Before the handshake: STARTTLS offered and LOGIN forbidden. The client
    // must discard this whole list once the link is upgraded.
    return "IMAP4rev2 IMAP4rev1 STARTTLS LOGINDISABLED";
}

fn reply(w: *std.Io.Writer, tag: []const u8, tail: []const u8) void {
    var buf: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, "{s} {s}", .{ tag, tail }) catch return;
    say(w, line);
}

fn say(w: *std.Io.Writer, bytes: []const u8) void {
    w.writeAll(bytes) catch return;
    w.flush() catch return;
    var it = std.mem.splitSequence(u8, std.mem.trimEnd(u8, bytes, "\r\n"), "\r\n");
    while (it.next()) |l| std.debug.print("   -> {s}\n", .{summarize(l)});
}

/// FETCH fixtures are long enough to drown the transcript; show the shape.
fn summarize(line: []const u8) []const u8 {
    return if (line.len > 100) line[0..100] else line;
}

/// Never print a credential: `LOGIN` carries one in the clear.
fn redact(text: []const u8) []const u8 {
    var it = std.mem.splitScalar(u8, text, ' ');
    _ = it.next();
    const cmd = it.next() orelse return text;
    if (!eq(cmd, "LOGIN")) return text;
    return "<tag> LOGIN <user> <redacted>";
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

// ─────────────────────────────────────────────────────────────────────────────
// plumbing
// ─────────────────────────────────────────────────────────────────────────────

fn nextValue(args: *std.process.Args.Iterator, flag: []const u8) !?[]const u8 {
    return args.next() orelse {
        std.debug.print("imap-demo: {s} needs a value\n", .{flag});
        return null;
    };
}

fn parseIntArg(comptime T: type, args: *std.process.Args.Iterator, flag: []const u8) !?T {
    const text = (try nextValue(args, flag)) orelse return null;
    return std.fmt.parseInt(T, text, 10) catch {
        std.debug.print("imap-demo: {s} wants a number, got '{s}'\n", .{ flag, text });
        return null;
    };
}
