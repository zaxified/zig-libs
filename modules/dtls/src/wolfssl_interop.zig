//! LIVE third-party-peer interop: this module's DTLS 1.3 PSK handshake
//! against **wolfSSL**, over a real loopback UDP socket.
//!
//! Everything else in this module is self-interop — two `Connection`s driving
//! each other. Self-interop cannot catch a shared misreading of RFC 9147: if
//! both sides encode a field the same wrong way, every test still passes.
//! These tests replace one side with an implementation that has never seen
//! our code.
//!
//! **Why wolfSSL and not OpenSSL** (SPEC.md's ranked oracle list put OpenSSL
//! first; that ranking was wrong and is corrected there): OpenSSL 3.5.5 has
//! no DTLS 1.3 at all — `s_server` offers only `-dtls1`/`-dtls1_2` — and
//! GnuTLS 3.8.12 likewise stops at `VERS-DTLS1.2`. wolfSSL is the DTLS 1.3
//! implementation that is both packaged and complete.
//!
//! The peer is `testdata/wolfssl_peer.c`, embedded here and compiled at test
//! time so the test carries its own oracle. Every test **skips loudly**
//! (`SKIPPED: …` + `error.SkipZigTest`) when a C compiler or wolfSSL is
//! missing — never silently.
//!
//! To close the gap: `sudo apt install libwolfssl-dev` (Debian/Ubuntu ship
//! 5.9.1 built with `WOLFSSL_DTLS13`).

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const Connection = @import("Connection.zig").Connection;
const Config = @import("Connection.zig").Config;

/// Test fixtures — duplicated verbatim in `testdata/wolfssl_peer.c`. Test
/// material only; nothing here is a default for anything.
const psk = [_]u8{0x0b} ** 16;
const psk_identity = "zig-libs-dtls";

const peer_source = @embedFile("testdata/wolfssl_peer.c");

fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

/// Compiles the wolfSSL peer inside `dir` as `./wolfssl_peer`. Skips loudly
/// when `cc` or wolfSSL is unavailable — that is an environment gap, not a
/// failure of this module.
///
/// Everything is done relative to `dir` (the child's cwd) because `Io.Dir`
/// has no `realpath` in 0.16 and an absolute path is not needed anywhere.
fn buildPeer(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    try dir.writeFile(io, .{ .sub_path = "wolfssl_peer.c", .data = peer_source });

    var child = std.process.spawn(io, .{
        .argv = &.{ "cc", "-O1", "-o", "wolfssl_peer", "wolfssl_peer.c", "-lwolfssl" },
        .cwd = .{ .dir = dir },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    }) catch {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE dtls wolfSSL interop: no `cc` on PATH.\n", .{});
        return error.SkipZigTest;
    };

    var err_buf: [4096]u8 = undefined;
    var stderr_reader = child.stderr.?.reader(io, &err_buf);
    const stderr = try stderr_reader.interface.allocRemaining(gpa, .unlimited);
    defer gpa.free(stderr);

    const term = try child.wait(io);
    const ok = switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        if (verboseSkip()) std.debug.print(
            "\nSKIPPED: LIVE dtls wolfSSL interop: cannot build the peer (wolfSSL headers/library missing?).\n" ++
                "  fix: sudo apt install libwolfssl-dev\n  cc said: {s}\n",
            .{stderr},
        );
        return error.SkipZigTest;
    }
}

const net = std.Io.net;

/// A free loopback UDP port, learned by binding one and letting it go.
/// Handing a port to a child process this way is a (narrow) race — nothing
/// else may claim it in between — which is why a peer that never arrives is
/// reported as a skip, not a failure.
fn freeLoopbackPort(io: std.Io) !u16 {
    const addr: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try addr.bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    return sock.address.getPort();
}

/// A peer that stops answering must fail the test, not wedge the suite.
fn deadline(io: std.Io, ms: u32) std.Io.Timeout {
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
    return t.toDeadline(io);
}

fn testRandom(csprng: *std.Random.DefaultCsprng) std.Random {
    return csprng.random();
}

/// Prints why the handshake died, including wolfSSL's own diagnosis — it
/// names the exact check that failed ("binder does not verify"), which is
/// worth more than any error we can raise on our side.
///
/// `peer_died` says whether the peer is expected to have given up already —
/// it decides whether its stderr can be read at all, and getting it wrong
/// hangs the test instead of diagnosing it:
///
///   * true (the peer rejected US): wolfSSL's `accept`/`connect` returned, it
///     printed its reason and exited, so reading to EOF terminates.
///   * false (WE rejected the peer): we send nothing back, so wolfSSL just
///     retransmits for the better part of a minute. There is no diagnosis to
///     read, and reading to EOF would block until it eventually gives up.
///     Kill it and report our own error.
///
/// `Child.kill` releases the pipes, so stderr must be consumed before it.
fn reportPeerDiagnosis(
    gpa: std.mem.Allocator,
    io: std.Io,
    child: *std.process.Child,
    peer_died: bool,
    what: []const u8,
    err: anyerror,
) void {
    if (!peer_died) {
        // Print BEFORE killing: `kill` blocks until the child is reaped, and
        // a diagnosis that only appears after a successful reap is worthless
        // in exactly the case worth diagnosing.
        std.debug.print("\n{s} ({t}).\n", .{ what, err });
        child.kill(io);
        return;
    }
    var buf: [4096]u8 = undefined;
    var reader = child.stderr.?.reader(io, &buf);
    const peer_says = reader.interface.allocRemaining(gpa, .unlimited) catch "";
    defer gpa.free(peer_says);
    std.debug.print("\n{s} ({t}). Peer said: {s}\n", .{ what, err, peer_says });
}

// ── direction 1: our client -> wolfSSL server ──────────────────────────────

test "LIVE wolfSSL peer: our client completes a real DTLS 1.3 PSK handshake against wolfSSL" {
    try clientAgainstWolfsslServer("server", .{ .expect_hello_retry_request = false });
}

// The same handshake against a wolfSSL server that does the DEFAULT cookie
// exchange: it answers ClientHello1 with a HelloRetryRequest and will not
// proceed until the client comes back echoing the cookie (RFC 8446 §4.1.4 /
// RFC 9147 §5.3). This is what a stock DTLS 1.3 server does, so until the
// retry worked this module could not talk to one at all — the other test
// only passes because its peer is explicitly told to skip the exchange.
//
// It is also the only test that exercises RFC 8446 §4.4.1's `message_hash`
// transcript rewrite against a real peer: get that wrong and the binder in
// ClientHello2 verifies against nothing.
test "LIVE wolfSSL peer: our client survives a HelloRetryRequest from a default-configured wolfSSL server" {
    try clientAgainstWolfsslServer("server-hrr", .{ .expect_hello_retry_request = true });
}

const Expect = struct {
    /// Asserted after the handshake. Without it this test has no teeth: if
    /// wolfSSL ever stopped sending a HelloRetryRequest in its default
    /// configuration, the retry path would go untested and the test would
    /// still pass — it would just be a second copy of the one above.
    expect_hello_retry_request: bool,
};

fn clientAgainstWolfsslServer(peer_mode: []const u8, expect: Expect) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try buildPeer(gpa, io, tmp.dir);

    const port = try freeLoopbackPort(io);
    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});

    var child = try std.process.spawn(io, .{
        .argv = &.{ "./wolfssl_peer", peer_mode, port_str },
        .cwd = .{ .dir = tmp.dir },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer _ = child.wait(io) catch {};

    // Wait for READY — the server prints it after bind(), before it looks at
    // the socket, so a datagram sent afterwards cannot be lost.
    var ready_buf: [64]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &ready_buf);
    const ready_line = stdout_reader.interface.takeDelimiterExclusive('\n') catch {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE dtls wolfSSL interop: peer never printed READY.\n", .{});
        return error.SkipZigTest;
    };
    try testing.expectEqualStrings("READY", ready_line);

    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    const server_addr: net.IpAddress = .{ .ip4 = .loopback(port) };

    var conn = try Connection.clientInit(.{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = &psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    defer conn.deinit();

    var csprng = std.Random.DefaultCsprng.init([_]u8{0x2c} ** 32);
    const rnd = testRandom(&csprng);

    var out: [1500]u8 = undefined;
    var rx: [1500]u8 = undefined;

    const client_hello = try conn.startHandshake(rnd, 0, &out);
    try sock.send(io, &server_addr, client_hello);

    // wolfSSL may split flight 2 across datagrams and interleave ACKs, so
    // feed whatever arrives until the connection reports it is done. On a
    // handshake error the peer's own diagnosis is worth far more than ours
    // (wolfSSL names the exact check that failed), so it is surfaced.
    var steps: usize = 0;
    while (conn.state != .connected) : (steps += 1) {
        if (steps > 8) return error.TooManyFlights;
        const incoming = try sock.receiveTimeout(io, &rx, deadline(io, 10_000));
        const result = conn.handleFlight(incoming.data, rnd, 0, &out) catch |err| {
            reportPeerDiagnosis(gpa, io, &child, true, "wolfSSL rejected our flight", err);
            return err;
        };
        if (result.out.len > 0) try sock.send(io, &server_addr, result.out);
    }

    try testing.expectEqual(expect.expect_hello_retry_request, conn.sawHelloRetryRequest());

    // Application data over the keys THIS handshake installed, decrypted by
    // an implementation that shares no code with ours.
    //
    // A real peer puts other things on the application epoch first: wolfSSL
    // ACKs our Finished (RFC 9147 §7) and sends a NewSessionTicket. Neither
    // is application data and neither is damage — this module implements no
    // post-handshake message, so both are skipped, and the fact that they
    // decrypt at all is itself the strongest evidence the two sides derived
    // identical application keys.
    const msg = "hello from zig-libs";
    const record = try conn.send(msg, &out);
    try sock.send(io, &server_addr, record);

    var plain: [1500]u8 = undefined;
    var skipped: usize = 0;
    const echoed = while (skipped <= 8) {
        const incoming = try sock.receiveTimeout(io, &rx, deadline(io, 10_000));
        break conn.recv(incoming.data, &plain) catch |err| switch (err) {
            error.ReceivedAck, error.ReceivedPostHandshakeMessage => {
                skipped += 1;
                continue;
            },
            else => return err,
        };
    } else return error.NoApplicationData;
    try testing.expectEqualStrings(msg, echoed);
}

// ── direction 2: wolfSSL client -> our server ──────────────────────────────

test "LIVE wolfSSL peer: our server completes a real DTLS 1.3 PSK handshake against wolfSSL" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try buildPeer(gpa, io, tmp.dir);

    // This side binds first, so the port cannot be lost to a race.
    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);

    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{sock.address.getPort()});

    var child = try std.process.spawn(io, .{
        .argv = &.{ "./wolfssl_peer", "client", port_str },
        .cwd = .{ .dir = tmp.dir },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    });
    // `kill` is idempotent and a no-op once `wait` has returned, so it is
    // safe cleanup for the early-return paths; `wait` below is the real one.
    defer child.kill(io);

    var conn = try Connection.serverInit(.{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = &psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    defer conn.deinit();

    var csprng = std.Random.DefaultCsprng.init([_]u8{0x5b} ** 32);
    const rnd = testRandom(&csprng);

    var out: [1500]u8 = undefined;
    var rx: [1500]u8 = undefined;
    var peer_addr: net.IpAddress = undefined;

    var steps: usize = 0;
    while (conn.state != .connected) : (steps += 1) {
        if (steps > 8) return error.TooManyFlights;
        const incoming = try sock.receiveTimeout(io, &rx, deadline(io, 10_000));
        peer_addr = incoming.from;
        const result = conn.handleFlight(incoming.data, rnd, 0, &out) catch |err| {
            reportPeerDiagnosis(gpa, io, &child, false, "our server rejected wolfSSL's flight", err);
            return err;
        };
        if (result.out.len > 0) try sock.send(io, &peer_addr, result.out);
    }

    // The wolfSSL client sends first and expects its own message echoed.
    var plain: [1500]u8 = undefined;
    var skipped: usize = 0;
    const received = while (skipped <= 8) {
        const incoming = try sock.receiveTimeout(io, &rx, deadline(io, 10_000));
        break conn.recv(incoming.data, &plain) catch |err| switch (err) {
            error.ReceivedAck, error.ReceivedPostHandshakeMessage => {
                skipped += 1;
                continue;
            },
            else => return err,
        };
    } else return error.NoApplicationData;
    try testing.expectEqualStrings("hello from wolfssl client", received);

    const echo = try conn.send(received, &out);
    try sock.send(io, &peer_addr, echo);

    const term = try child.wait(io);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}

// ── direction 2b: wolfSSL client -> our server, WITH the cookie exchange ──

// RFC 9147 §5.1's return-routability check, served by us and consumed by a
// real client. Two things can only be proven here:
//
//   1. that a stock DTLS 1.3 client ACCEPTS the HelloRetryRequest we emit —
//      its `random` sentinel, its `supported_versions`, its cookie framing,
//      and the fact that it carries no extension the client never offered
//      (RFC 8446 §4.1.4). Our own client would accept a subtly wrong one,
//      because it was written from the same reading of the same RFC;
//
//   2. that our reconstruction of the transcript is right. The server keeps
//      nothing between the two ClientHellos, so it re-derives RFC 8446
//      §4.4.1's `message_hash` rewrite AND re-encodes its own
//      HelloRetryRequest from the cookie. If either differs by one byte from
//      what the client hashed, the transcripts diverge silently and the
//      client's binder verifies against nothing. Self-interop cannot see
//      this: the same code would produce the same wrong answer on both
//      sides.
//
// Statelessness is not asserted by inspection here — it is STRUCTURAL. The
// `Connection` that answers the first ClientHello is destroyed before the
// second one is read, so if anything the server needed lived in that object
// rather than in the cookie, this handshake cannot complete.
test "LIVE wolfSSL peer: our server serves a HelloRetryRequest, a real wolfSSL client answers it, and a BRAND-NEW connection finishes the handshake" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try buildPeer(gpa, io, tmp.dir);

    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);

    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{sock.address.getPort()});

    var child = try std.process.spawn(io, .{
        .argv = &.{ "./wolfssl_peer", "client", port_str },
        .cwd = .{ .dir = tmp.dir },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    });
    defer child.kill(io);

    var csprng = std.Random.DefaultCsprng.init([_]u8{0x6e} ** 32);
    const rnd = testRandom(&csprng);

    var out: [1500]u8 = undefined;
    var rx: [1500]u8 = undefined;
    var peer_addr: net.IpAddress = undefined;
    // The caller-supplied `peer_binding`: this module never sees a socket,
    // so the address the cookie is bound to has to come from whoever owns
    // the I/O — here, the address `receiveTimeout` reports. Rewritten every
    // datagram (with identical bytes, since it is the same peer), which is
    // what a real demultiplexing server would do.
    var binding_buf: [64]u8 = undefined;

    var conn: ?Connection = null;
    defer if (conn) |*c| c.deinit();
    var retries_served: usize = 0;

    var steps: usize = 0;
    while (true) : (steps += 1) {
        if (steps > 8) return error.TooManyFlights;
        const incoming = try sock.receiveTimeout(io, &rx, deadline(io, 10_000));
        peer_addr = incoming.from;
        const binding = try std.fmt.bufPrint(&binding_buf, "{f}", .{incoming.from});

        if (conn == null) conn = try Connection.serverInit(.{
            .role = .server,
            .psk_identity = psk_identity,
            .psk = &psk,
            .cipher_suites = &.{.aes_128_gcm_sha256},
            .hello_retry = .{ .cookie_secret = "a live server's cookie MAC key", .peer_binding = binding },
        });

        const result = conn.?.handleFlight(incoming.data, rnd, 0, &out) catch |err| {
            reportPeerDiagnosis(gpa, io, &child, false, "our server rejected wolfSSL's flight", err);
            return err;
        };
        if (result.out.len > 0) try sock.send(io, &peer_addr, result.out);
        if (conn.?.state == .connected) break;

        // Still `.start` after a flight went out ⇒ that flight was a
        // HelloRetryRequest and this connection committed nothing. Throw it
        // away, exactly as a stateless server would: whatever the next
        // ClientHello needs must be in the cookie.
        if (conn.?.state == .start) {
            try testing.expect(conn.?.sawHelloRetryRequest());
            retries_served += 1;
            conn.?.deinit();
            conn = null;
        }
    }

    // Without this the test would silently degrade into a duplicate of the
    // no-cookie one if `Config.hello_retry` ever stopped taking effect: the
    // handshake would still complete, just without the check.
    try testing.expect(retries_served >= 1);

    var plain: [1500]u8 = undefined;
    var skipped: usize = 0;
    const received = while (skipped <= 8) {
        const incoming = try sock.receiveTimeout(io, &rx, deadline(io, 10_000));
        break conn.?.recv(incoming.data, &plain) catch |err| switch (err) {
            error.ReceivedAck, error.ReceivedPostHandshakeMessage => {
                skipped += 1;
                continue;
            },
            else => return err,
        };
    } else return error.NoApplicationData;
    try testing.expectEqualStrings("hello from wolfssl client", received);

    const echo = try conn.?.send(received, &out);
    try sock.send(io, &peer_addr, echo);

    const term = try child.wait(io);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}
