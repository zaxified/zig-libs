// SPDX-License-Identifier: MIT

//! `smtp-demo` — one binary, two modes (`server` and `client`) that talk to
//! each other over a **real TCP socket**. Run the server in one terminal, the
//! client in another, and watch a report-mailer deliver a multipart message
//! with an attachment to two recipients, one of which bounces.
//!
//! **`client` mode is the thing to read.** It is what a report-mailer consumer
//! does with `smtp`: compose a `multipart/mixed` message with an attachment,
//! open an authenticated session, send it to two recipients, find out that one
//! of them was refused, and keep the exact octets that went out.
//!
//! **`server` mode is a prop, and says so.** This module is a client; it ships
//! no server. The forty lines below are just enough ESMTP to have something
//! real on the other end of the socket — and being real is the point, because
//! the transport, the reply framing across TCP segment boundaries, the
//! pipelined command group and the DATA terminator are exactly what an
//! in-memory transcript cannot exercise. Two pieces of it are the module's
//! own: `Unstuffer` un-does the DATA dot-stuffing, and `Capabilities` is what
//! the client parses the EHLO reply into.
//!
//! **⚠ NO TLS HAPPENS HERE, IN EITHER MODE.** This repo terminates no TLS by
//! design: `Client` negotiates `STARTTLS` and then asks the caller to perform
//! the handshake and hand back an upgraded `Transport`. The upgrade hook below
//! returns the SAME plaintext socket, and the server likewise answers `220
//! Ready to start TLS` and keeps speaking plaintext. Both halves print a line
//! saying so when it happens. What that genuinely exercises is the STARTTLS
//! *negotiation* — the pre-TLS capability list being discarded, EHLO being
//! re-issued, `error.PlaintextInjection` if the server pushes bytes across the
//! boundary, and AUTH being unlocked only by the second capability list. What
//! it does NOT exercise, and what this demo must not be read as evidence of,
//! is encryption: a real consumer's hook wraps the socket in a TLS client, and
//! that is the piece the module deliberately does not own.
//!
//! Not port 25/587: privileged or conventionally occupied. 2525 is the usual
//! unprivileged stand-in.
//!
//! This is an example in the gate sense — it is built against the PUBLISHED
//! module (`deps` only, no `test_deps`, no access to anything the module does
//! not export). If a type needed to call the API is not public, or an error
//! cannot be named from outside, this file stops compiling. The module's own
//! tests cannot notice either, because they live inside it.

const std = @import("std");
const smtp = @import("smtp");

/// Anything that is this demo's own failure rather than the protocol saying
/// no. A rejected recipient is a successful conversation with an unwelcome
/// answer, and exits 0.
const local_failure_exit: u8 = 1;

const default_port: u16 = 2525;

/// The recipient the server refuses by default, so the client has a bounce to
/// report. A partly-accepted transaction is the case a mailer gets wrong.
const default_reject = "archive@example.net";

const usage_text =
    \\smtp-demo — an SMTP client demo for the `smtp` module, with a prop server.
    \\
    \\usage:
    \\  smtp-demo server [options]
    \\  smtp-demo client [options]
    \\
    \\server options:
    \\  --listen <addr>   address to bind                (default 127.0.0.1)
    \\  --port <port>     TCP port                       (default 2525)
    \\  --reject <addr>   refuse this recipient with 550 (default archive@example.net)
    \\  --no-starttls     do not advertise STARTTLS, so a client with
    \\                    `tls = .required` refuses to send at all
    \\  --inject          push a line at the client between `220 Ready to start
    \\                    TLS` and the handshake — the STARTTLS command-injection
    \\                    flaw of 2011. The client must abort.
    \\  --once            serve one connection, then exit
    \\  -h, --help        this text
    \\
    \\client options:
    \\  --host <host>     server to connect to           (default 127.0.0.1)
    \\  --port <port>     TCP port                       (default 2525)
    \\  --tls <policy>    required | opportunistic | disabled (default required)
    \\  -h, --help        this text
    \\
    \\Two terminals:
    \\  smtp-demo server --once
    \\  smtp-demo client
    \\
    \\Against a foreign implementation — any ESMTP server that will take an
    \\unauthenticated relay, or one you have credentials for:
    \\  smtp-demo client --host <a real MTA> --port 2525 --tls opportunistic
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes the example a leak detector
    // for the module's ownership contract: `Client` allocates its read and
    // body buffers, `render` hands back a document the caller must free, and
    // `Unstuffer` owns two lists.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.skip(); // argv[0]

    const mode = args.next() orelse {
        std.debug.print("{s}", .{usage_text});
        return local_failure_exit;
    };

    if (std.mem.eql(u8, mode, "server")) return runServer(gpa, io, &args);
    if (std.mem.eql(u8, mode, "client")) return runClient(gpa, io, &args);
    if (std.mem.eql(u8, mode, "-h") or std.mem.eql(u8, mode, "--help")) {
        std.debug.print("{s}", .{usage_text});
        return 0;
    }

    std.debug.print("smtp-demo: unknown mode '{s}' (expected `server` or `client`)\n\n{s}", .{ mode, usage_text });
    return local_failure_exit;
}

// ─────────────────────────────────────────────────────────────────────────────
// client mode — what a report-mailer consumer does with `smtp`
// ─────────────────────────────────────────────────────────────────────────────

const report_csv =
    "date,host,latency_ms\n" ++
    "2026-08-21,edge-1,12\n" ++
    "2026-08-21,edge-2,41\n";

/// A `Transport` a consumer writes: the two functions in the vtable and the
/// three errors they may report are all the module asks for. Here they sit on
/// a TCP socket; in a downstream test they sit on a fixture buffer, and
/// `Client` cannot tell the difference — which is the whole point of the seam.
const SocketTransport = struct {
    io: std.Io,
    reader: *std.Io.net.Stream.Reader,
    writer: *std.Io.net.Stream.Writer,
    /// Set once the STARTTLS hook has run. Only affects what this demo prints.
    upgraded: bool = false,

    fn transport(s: *SocketTransport) smtp.Transport {
        return .{ .ctx = s, .vtable = &.{ .read = read, .write = write } };
    }

    /// ONE read, returning whatever arrived. Not "fill the buffer": SMTP
    /// replies do not align with TCP segments, a multi-line 250- reply can
    /// span several, and two replies can share one. `Client.pumpOnce` feeds
    /// whatever this returns to an incremental parser precisely so that a
    /// transport never has to know where a reply ends.
    fn read(ctx: *anyopaque, buf: []u8) smtp.TransportError!usize {
        const s: *SocketTransport = @ptrCast(@alignCast(ctx));
        const r = &s.reader.interface;
        r.fill(1) catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            error.ReadFailed => return error.ReadFailed,
        };
        const have = r.buffered();
        const n = @min(have.len, buf.len);
        @memcpy(buf[0..n], have[0..n]);
        r.toss(n);
        return n;
    }

    fn write(ctx: *anyopaque, bytes: []const u8) smtp.TransportError!void {
        const s: *SocketTransport = @ptrCast(@alignCast(ctx));
        const w = &s.writer.interface;
        w.writeAll(bytes) catch return error.WriteFailed;
        w.flush() catch return error.WriteFailed;
    }

    /// The STARTTLS hook. A real consumer performs a TLS handshake on this
    /// socket and returns a `Transport` that reads and writes through
    /// `std.crypto.tls.Client`. ⚠ This one performs NO handshake and returns
    /// the same plaintext socket — see the file comment. It is a stand-in for
    /// the seam, not an implementation of it.
    fn upgrade(ctx: *anyopaque) smtp.TransportError!smtp.Transport {
        const s: *SocketTransport = @ptrCast(@alignCast(ctx));
        s.upgraded = true;
        std.debug.print(
            "    !! STARTTLS accepted — and this demo performs NO handshake.\n" ++
                "       Everything after this line is still plaintext on the wire.\n",
            .{},
        );
        return s.transport();
    }
};

const ClientOptions = struct {
    host: []const u8 = "127.0.0.1",
    port: u16 = default_port,
    tls: smtp.TlsPolicy = .required,
};

fn runClient(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
    var opts: ClientOptions = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{usage_text});
            return 0;
        } else if (std.mem.eql(u8, arg, "--host")) {
            opts.host = (try nextValue(args, "--host")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = (try parseIntArg(u16, args, "--port")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--tls")) {
            const text = (try nextValue(args, "--tls")) orelse return local_failure_exit;
            opts.tls = std.meta.stringToEnum(smtp.TlsPolicy, text) orelse {
                std.debug.print("smtp-demo: --tls wants required|opportunistic|disabled, got '{s}'\n", .{text});
                return local_failure_exit;
            };
        } else {
            std.debug.print("smtp-demo: unknown client option '{s}' (try --help)\n", .{arg});
            return local_failure_exit;
        }
    }

    const addr = std.Io.net.IpAddress.parse(opts.host, opts.port) catch |err| {
        std.debug.print("smtp-demo: cannot parse {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return local_failure_exit;
    };
    var stream = addr.connect(io, .{ .mode = .stream }) catch |err| {
        std.debug.print("smtp-demo: cannot connect to {s}:{d}: {t}\n", .{ opts.host, opts.port, err });
        return local_failure_exit;
    };
    defer stream.close(io);

    var rbuf: [8192]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    var sock: SocketTransport = .{ .io = io, .reader = &sr, .writer = &sw };

    std.debug.print("smtp-demo: connected to {s}:{d}, tls policy .{s}\n\n", .{ opts.host, opts.port, @tagName(opts.tls) });

    var client = try smtp.Client.init(gpa, sock.transport(), .{
        .session = .{
            .ehlo_domain = "reports.example.org",
            // Not `opportunistic` by default: a report with an attachment is
            // worth failing the send over rather than mailing it in the clear.
            .tls = opts.tls,
            .credentials = .{ .username = "reports@example.org", .password = "s3cret" },
        },
        // Absent here would mean "this caller cannot do TLS", and a session
        // that reaches STARTTLS would fail rather than continue unencrypted.
        .tls = .{ .ctx = &sock, .upgrade = SocketTransport.upgrade },
    });
    defer client.deinit();

    std.debug.print("[1] greeting, EHLO, STARTTLS, second EHLO, AUTH\n", .{});
    client.connect() catch |err| switch (err) {
        // The server does not offer STARTTLS and the policy is `.required`.
        error.TlsNotOffered => {
            std.debug.print("    server offers no STARTTLS, refusing to send\n", .{});
            return local_failure_exit;
        },
        // Reached STARTTLS but no upgrade hook was configured.
        error.TlsUnavailable => {
            std.debug.print("    cannot perform the TLS handshake, refusing to send\n", .{});
            return local_failure_exit;
        },
        // AUTH on a link with no TLS, without the explicit opt-in (RFC 4954 §9).
        error.PlaintextAuthRefused => {
            std.debug.print("    refusing to send a password over an unprotected link\n", .{});
            return local_failure_exit;
        },
        error.AuthenticationFailed => {
            std.debug.print("    credentials rejected\n", .{});
            return local_failure_exit;
        },
        // The server sent bytes after its 220 but before the handshake — an
        // injected command that would otherwise be read as if it had come
        // from inside the tunnel.
        error.PlaintextInjection => {
            std.debug.print("    plaintext injected across the TLS boundary, aborting\n", .{});
            return local_failure_exit;
        },
        else => {
            std.debug.print("    connect failed: {s}\n", .{describe(err)});
            return local_failure_exit;
        },
    };

    // This capability set is the SECOND one — the pre-STARTTLS list was
    // discarded (RFC 3207 §4.2) because an active attacker owns every byte of
    // it. Only this one may unlock a password.
    const caps = client.serverCapabilities();
    std.debug.print(
        "    capabilities after the handshake: pipelining={} max_size={?d} 8bitmime={} auth_plain={}\n",
        .{ caps.pipelining, caps.max_size, caps.eightbitmime, caps.auth.plain },
    );

    // The module reads no clock — a timestamp is data the caller supplies,
    // which is also what makes a rendered message reproducible in a test.
    const msg: smtp.Message = .{
        .from = .{ .name = "Nightly Reports", .addr = "reports@example.org" },
        .to = &.{
            .{ .name = "Ops", .addr = "ops@example.net" },
            .{ .addr = "archive@example.net" },
        },
        .subject = "Latency report, 2026-08-21",
        .date = .{ .unix = 1_787_270_400, .offset_minutes = 120 }, // 2026-08-21T00:00Z, rendered +0200
        .body = .{ .multipart = .{
            .subtype = .mixed,
            .parts = &.{
                .{ .text = .{ .body = "Two edges over the 30 ms budget. Details attached.\r\n" } },
                .{ .attachment = .{
                    .filename = "latency-2026-08-21.csv",
                    .content_type = "text/csv",
                    .data = report_csv,
                } },
            },
        } },
    };

    // MIME boundaries must not be guessable by anyone who can influence the
    // body; a real sender seeds this from the OS CSPRNG. A fixed seed keeps
    // an example reproducible, and is the wrong choice in production.
    var prng: std.Random.DefaultPrng = .init(0x5EED_1234);

    std.debug.print("\n[2] MAIL FROM / RCPT TO x2 / DATA\n", .{});
    const doc = client.sendMessage(msg, prng.random(), .{}, .{
        .to = &.{ "ops@example.net", "archive@example.net" },
    }) catch |err| switch (err) {
        // Not a bug in the message: every address the server was offered was
        // refused, so there is no transaction left to run.
        error.AllRecipientsRejected => {
            std.debug.print("    nobody accepted the message\n", .{});
            return local_failure_exit;
        },
        // The composer refuses to emit a boundary that occurs inside a part,
        // rather than producing a document that silently truncates.
        error.BoundaryCollision => {
            std.debug.print("    could not find a MIME boundary unused by the body\n", .{});
            return local_failure_exit;
        },
        // The body needs 8BITMIME (RFC 6152) and the server has none.
        error.EightBitNotSupported => {
            std.debug.print("    server cannot take an 8-bit body\n", .{});
            return local_failure_exit;
        },
        else => {
            std.debug.print("    send failed: {s}\n", .{describe(err)});
            return local_failure_exit;
        },
    };
    // The caller gets the exact octets that went out — what a Sent folder or
    // a golden test needs.
    defer gpa.free(doc);
    std.debug.print("    sent {d} bytes of RFC 5322 document\n", .{doc.len});

    // A partly-accepted transaction still succeeds. Which addresses bounced is
    // per-recipient state, not an error code, and a mailer has to record it.
    var bounced: usize = 0;
    for (client.recipients()) |r| {
        if (r.accepted) continue;
        bounced += 1;
        std.debug.print("    rejected {s}: {d}\n", .{ r.addr, r.code });
    }
    if (bounced == 0) std.debug.print("    every recipient accepted\n", .{});

    std.debug.print("\n[3] QUIT\n", .{});
    client.quit() catch |err| {
        std.debug.print("    quit failed: {s}\n", .{describe(err)});
        return local_failure_exit;
    };
    std.debug.print("    session closed in state {s}\n", .{@tagName(client.state())});
    return 0;
}

fn describe(err: anyerror) []const u8 {
    return switch (err) {
        error.EndOfStream => "EndOfStream — the peer hung up mid-conversation.",
        error.ReadFailed, error.WriteFailed => "the socket itself failed.",
        error.PermanentFailure => "PermanentFailure — a 5yz reply; retrying will not help.",
        error.TransientFailure => "TransientFailure — a 4yz reply; a queue would retry this one.",
        else => @errorName(err),
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// server mode — a prop, not a product
// ─────────────────────────────────────────────────────────────────────────────
//
// Just enough of RFC 5321 to be a real peer on a real socket. It is NOT part
// of the module and nothing here should be copied into one: no queue, no
// relaying decision, no address validation beyond a string compare, and it
// answers `235 Authentication successful` to any credential at all.

const ServerOptions = struct {
    listen: []const u8 = "127.0.0.1",
    port: u16 = default_port,
    reject: []const u8 = default_reject,
    starttls: bool = true,
    inject: bool = false,
    once: bool = false,
};

fn runServer(gpa: std.mem.Allocator, io: std.Io, args: *std.process.Args.Iterator) !u8 {
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
        } else if (std.mem.eql(u8, arg, "--reject")) {
            opts.reject = (try nextValue(args, "--reject")) orelse return local_failure_exit;
        } else if (std.mem.eql(u8, arg, "--port")) {
            opts.port = (try parseIntArg(u16, args, "--port")) orelse return local_failure_exit;
        } else {
            std.debug.print("smtp-demo: unknown server option '{s}' (try --help)\n", .{arg});
            return local_failure_exit;
        }
    }

    const addr = std.Io.net.IpAddress.parse(opts.listen, opts.port) catch |err| {
        std.debug.print("smtp-demo: cannot parse listen address {s}:{d}: {t}\n", .{ opts.listen, opts.port, err });
        return local_failure_exit;
    };
    // Deliberately NOT `reuse_address`: in `std.Io.net` that sets SO_REUSEPORT
    // too, so a second smtp-demo server would silently share the port and a
    // reader's messages would land in a process they cannot see.
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("smtp-demo: cannot listen on {s}:{d}: {t}\n", .{ opts.listen, opts.port, err });
        return local_failure_exit;
    };
    defer listener.deinit(io);

    std.debug.print("smtp-demo: prop ESMTP server on {s}:{d}{s}{s}\n", .{
        opts.listen,
        opts.port,
        if (opts.starttls) ", advertising STARTTLS (with NO handshake behind it)" else ", no STARTTLS",
        if (opts.inject) ", and injecting plaintext across the TLS boundary" else "",
    });
    std.debug.print("  refusing recipient <{s}> with 550\n", .{opts.reject});

    while (true) {
        var stream = listener.accept(io) catch |err| {
            std.debug.print("smtp-demo: accept failed: {t}\n", .{err});
            return local_failure_exit;
        };
        serveConnection(gpa, io, opts, &stream);
        stream.close(io);
        if (opts.once) break;
    }
    return 0;
}

const SessionState = struct {
    ehlo_seen: bool = false,
    tls_negotiated: bool = false,
    authenticated: bool = false,
    sender: bool = false,
    recipients: usize = 0,
};

fn serveConnection(gpa: std.mem.Allocator, io: std.Io, opts: ServerOptions, stream: *std.Io.net.Stream) void {
    std.debug.print("\n-- client connected\n", .{});
    var rbuf: [8192]u8 = undefined;
    var wbuf: [8192]u8 = undefined;
    var sr = stream.reader(io, &rbuf);
    var sw = stream.writer(io, &wbuf);
    const r = &sr.interface;
    const w = &sw.interface;

    var st: SessionState = .{};
    say(w, "220 mail.example.com ESMTP smtp-demo ready\r\n");

    while (true) {
        const line = r.takeDelimiterInclusive('\n') catch |err| switch (err) {
            error.EndOfStream => break,
            else => {
                std.debug.print("   read failed: {t}\n", .{err});
                break;
            },
        };
        const cmd = std.mem.trimEnd(u8, line, "\r\n");
        if (cmd.len == 0) continue;
        std.debug.print("   <- {s}\n", .{redact(cmd)});

        if (startsWithIgnoreCase(cmd, "EHLO ")) {
            st.ehlo_seen = true;
            // The pre-TLS list deliberately advertises no AUTH and the
            // post-TLS one does: a capability list learned in the clear is
            // attacker-controlled, so RFC 3207 §4.2 makes the client throw it
            // away and ask again. Only the second list may unlock a password.
            var reply: [512]u8 = undefined;
            const body = std.fmt.bufPrint(&reply, "250-mail.example.com Hello\r\n" ++
                "250-PIPELINING\r\n" ++
                "250-SIZE 10240000\r\n" ++
                "250-8BITMIME\r\n" ++
                "250{s}", .{
                if (st.tls_negotiated)
                    " AUTH PLAIN LOGIN\r\n"
                else if (opts.starttls)
                    "-STARTTLS\r\n250 HELP\r\n"
                else
                    " HELP\r\n",
            }) catch continue;
            say(w, body);
        } else if (startsWithIgnoreCase(cmd, "HELO ")) {
            st.ehlo_seen = true;
            say(w, "250 mail.example.com Hello\r\n");
        } else if (eqlIgnoreCase(cmd, "STARTTLS")) {
            if (!opts.starttls) {
                say(w, "502 5.5.1 STARTTLS not implemented\r\n");
                continue;
            }
            if (opts.inject) {
                // The 2011 STARTTLS command-injection flaw, from the server
                // side. After the 220 the server must send NOTHING until the
                // handshake; anything here would be read by a naive client as
                // though it had arrived inside the tunnel. `Client` refuses
                // with `error.PlaintextInjection` — that refusal is the thing
                // this flag exists to show.
                //
                // ⚠ It goes out in the SAME write as the 220, and that detail
                // is not cosmetic. The client's guard is `parser.atBoundary()`
                // — "is anything left in the reply parser after the 220" — and
                // it is exactly as strong as what one read returned. Flushing
                // the injected line separately leaves it in the kernel socket
                // queue instead, where the check cannot see it, and the client
                // then swallows it as the next reply. That ceiling is real and
                // documented in `smtp/src/client.zig`; a real attacker on the
                // path sends one segment, which is what this does.
                std.debug.print("   -> INJECTING a line across the TLS boundary, in the same write\n", .{});
                say(w, "220 2.0.0 Ready to start TLS\r\n" ++
                    "250 2.0.0 Injected, and a client that reads this is broken\r\n");
            } else {
                say(w, "220 2.0.0 Ready to start TLS\r\n");
            }
            // ⚠ No handshake. The socket stays plaintext; see the file
            // comment. A real server would hand the socket to a TLS server
            // implementation here, which this repo does not have.
            std.debug.print("   !! no handshake performed — still plaintext\n", .{});
            st.tls_negotiated = true;
            st.ehlo_seen = false;
        } else if (startsWithIgnoreCase(cmd, "AUTH ")) {
            reportAuth(cmd);
            st.authenticated = true;
            say(w, "235 2.7.0 Authentication successful\r\n");
        } else if (startsWithIgnoreCase(cmd, "MAIL FROM:")) {
            if (!st.ehlo_seen) {
                say(w, "503 5.5.1 EHLO first\r\n");
                continue;
            }
            st = .{ .ehlo_seen = true, .tls_negotiated = st.tls_negotiated, .authenticated = st.authenticated, .sender = true };
            say(w, "250 2.1.0 Ok\r\n");
        } else if (startsWithIgnoreCase(cmd, "RCPT TO:")) {
            if (!st.sender) {
                say(w, "503 5.5.1 MAIL first\r\n");
                continue;
            }
            if (std.mem.indexOf(u8, cmd, opts.reject) != null) {
                var reply: [256]u8 = undefined;
                const body = std.fmt.bufPrint(&reply, "550 5.1.1 <{s}>: unknown user\r\n", .{opts.reject}) catch continue;
                say(w, body);
                continue;
            }
            st.recipients += 1;
            say(w, "250 2.1.5 Ok\r\n");
        } else if (eqlIgnoreCase(cmd, "DATA")) {
            if (st.recipients == 0) {
                say(w, "554 5.5.1 No valid recipients\r\n");
                continue;
            }
            say(w, "354 End data with <CR><LF>.<CR><LF>\r\n");
            receiveBody(gpa, r, w);
            st = .{ .ehlo_seen = true, .tls_negotiated = st.tls_negotiated, .authenticated = st.authenticated };
        } else if (eqlIgnoreCase(cmd, "RSET")) {
            st = .{ .ehlo_seen = st.ehlo_seen, .tls_negotiated = st.tls_negotiated, .authenticated = st.authenticated };
            say(w, "250 2.0.0 Ok\r\n");
        } else if (eqlIgnoreCase(cmd, "NOOP")) {
            say(w, "250 2.0.0 Ok\r\n");
        } else if (eqlIgnoreCase(cmd, "QUIT")) {
            say(w, "221 2.0.0 Bye\r\n");
            break;
        } else {
            say(w, "500 5.5.2 Command unrecognized\r\n");
        }
    }
    std.debug.print("-- client disconnected\n", .{});
}

/// Read the DATA body and un-stuff it with the module's own `Unstuffer`.
///
/// This is the one place where the server half is doing something the module
/// actually ships. `CRLF.CRLF` ends the body, a line that begins with a dot
/// had one prepended by the sender, and a BARE LF in the middle is the
/// ambiguity that "SMTP smuggling" turns into message injection —
/// `UnstuffOptions.allow_bare_lf` defaults to false, so this rejects it rather
/// than guessing where the message ends.
fn receiveBody(gpa: std.mem.Allocator, r: *std.Io.Reader, w: *std.Io.Writer) void {
    var un = smtp.Unstuffer.init(gpa, .{});
    defer un.deinit();

    while (true) {
        const chunk = r.takeDelimiterInclusive('\n') catch |err| {
            std.debug.print("   -> body read failed: {t}\n", .{err});
            say(w, "451 4.3.0 Body read failed\r\n");
            return;
        };
        const done = un.feed(chunk) catch |err| {
            std.debug.print("   -> body refused: {t}\n", .{err});
            say(w, "500 5.6.0 Body rejected\r\n");
            return;
        };
        if (done) break;
    }

    const body = un.bytes();
    std.debug.print("   -> body accepted: {d} bytes, {d} lines\n", .{ body.len, std.mem.count(u8, body, "\r\n") });
    if (std.mem.indexOf(u8, body, "boundary=")) |i| {
        const rest = body[i..];
        const end = std.mem.indexOfAny(u8, rest, "\r\n") orelse rest.len;
        std.debug.print("      {s}\n", .{rest[0..end]});
    }
    if (std.mem.indexOf(u8, body, "filename=")) |i| {
        const rest = body[i..];
        const end = std.mem.indexOfAny(u8, rest, "\r\n") orelse rest.len;
        std.debug.print("      {s}\n", .{rest[0..end]});
    }
    say(w, "250 2.0.0 Ok: queued as 3F2A9\r\n");
}

/// Show that the SASL PLAIN initial response really is a base64 blob with NUL
/// separators — and that it is NOT encryption, which is why RFC 4954 §9
/// forbids it on an unprotected link.
fn reportAuth(cmd: []const u8) void {
    const plain_prefix = "AUTH PLAIN ";
    if (cmd.len <= plain_prefix.len or !startsWithIgnoreCase(cmd, plain_prefix)) return;
    const b64 = cmd[plain_prefix.len..];
    var buf: [256]u8 = undefined;
    const dec = std.base64.standard.Decoder;
    const n = dec.calcSizeForSlice(b64) catch return;
    if (n > buf.len) return;
    dec.decode(buf[0..n], b64) catch return;
    var it = std.mem.splitScalar(u8, buf[0..n], 0);
    _ = it.next(); // authzid
    const user = it.next() orelse return;
    std.debug.print("   -> SASL PLAIN decodes to authcid \"{s}\" plus a password, in the CLEAR\n", .{user});
}

/// Never print a credential. The command line itself is logged, so the one
/// command that carries a secret gets its argument replaced.
fn redact(cmd: []const u8) []const u8 {
    if (startsWithIgnoreCase(cmd, "AUTH PLAIN ")) return "AUTH PLAIN <redacted>";
    return cmd;
}

fn say(w: *std.Io.Writer, bytes: []const u8) void {
    w.writeAll(bytes) catch return;
    w.flush() catch return;
    var it = std.mem.splitSequence(u8, std.mem.trimEnd(u8, bytes, "\r\n"), "\r\n");
    while (it.next()) |l| std.debug.print("   -> {s}\n", .{l});
}

// ─────────────────────────────────────────────────────────────────────────────
// plumbing
// ─────────────────────────────────────────────────────────────────────────────

fn startsWithIgnoreCase(haystack: []const u8, prefix: []const u8) bool {
    return haystack.len >= prefix.len and std.ascii.eqlIgnoreCase(haystack[0..prefix.len], prefix);
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn nextValue(args: *std.process.Args.Iterator, flag: []const u8) !?[]const u8 {
    return args.next() orelse {
        std.debug.print("smtp-demo: {s} needs a value\n", .{flag});
        return null;
    };
}

fn parseIntArg(comptime T: type, args: *std.process.Args.Iterator, flag: []const u8) !?T {
    const text = (try nextValue(args, flag)) orelse return null;
    return std.fmt.parseInt(T, text, 10) catch {
        std.debug.print("smtp-demo: {s} wants a number, got '{s}'\n", .{ flag, text });
        return null;
    };
}
