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
const certverify = @import("certverify.zig");
const messages = @import("messages.zig");
const cert_kat = @import("certauth_kat_vectors.zig");

const x25519_group: u16 = @intFromEnum(messages.NamedGroup.x25519);
const secp256r1_group: u16 = @intFromEnum(messages.NamedGroup.secp256r1);

/// Test fixtures — duplicated verbatim in `testdata/wolfssl_peer.c`. Test
/// material only; nothing here is a default for anything.
const psk = [_]u8{0x0b} ** 16;
const psk_identity = "zig-libs-dtls";

const peer_source = @embedFile("testdata/wolfssl_peer.c");

const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

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

/// One line of the peer's stdout, delimiter consumed.
///
/// NOT `takeDelimiterExclusive`: that tosses only the line's own bytes and
/// leaves the `'\n'` in the stream, so the NEXT call sees the delimiter at
/// position 0 and returns an empty slice — forever. A test that reads a
/// single line never notices; one that reads two gets `""` for the second
/// and every one after it. `takeDelimiterInclusive` consumes the delimiter,
/// and the `\n` is trimmed here.
fn peerLine(reader: *std.Io.Reader) ![]const u8 {
    const raw = try reader.takeDelimiterInclusive('\n');
    return std.mem.trimEnd(u8, raw, "\n");
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
    const ready_line = peerLine(&stdout_reader.interface) catch {
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

// ── direction 3: our CERTIFICATE client -> a wolfSSL certificate server ───

/// SEC1 `ECPrivateKey` DER (RFC 5915) for the fixture P-256 leaf, built here
/// from the ONE piece of key material this repo stores (`cert_kat
/// .server_secret_key_bytes`, a raw 32-byte scalar) rather than pasted in as
/// a second encoded copy: the public point is recomputed from the scalar, so
/// the key wolfSSL signs with cannot silently drift from the certificate the
/// Zig side verifies against.
fn serverKeySec1Der() [121]u8 {
    const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const sk = P256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes) catch unreachable;
    const kp = P256.KeyPair.fromSecretKey(sk) catch unreachable;
    const point = kp.public_key.toUncompressedSec1(); // 0x04 || X || Y, 65 bytes

    var out: [121]u8 = undefined;
    var i: usize = 0;
    const put = struct {
        fn f(buf: []u8, at: *usize, bytes: []const u8) void {
            @memcpy(buf[at.*..][0..bytes.len], bytes);
            at.* += bytes.len;
        }
    }.f;
    put(&out, &i, &.{ 0x30, 0x77 }); // SEQUENCE, 119 content bytes
    put(&out, &i, &.{ 0x02, 0x01, 0x01 }); // version = 1
    put(&out, &i, &.{ 0x04, 0x20 }); // privateKey OCTET STRING (32)
    put(&out, &i, &cert_kat.server_secret_key_bytes);
    // [0] parameters: OID 1.2.840.10045.3.1.7 (prime256v1)
    put(&out, &i, &.{ 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 });
    // [1] publicKey: BIT STRING, 0 unused bits, uncompressed point
    put(&out, &i, &.{ 0xa1, 0x44, 0x03, 0x42, 0x00 });
    put(&out, &i, &point);
    std.debug.assert(i == out.len);
    return out;
}

/// A wolfSSL certificate peer needs the leaf, its key and the trust anchor
/// as files; all three come from this repo's own fixtures, so the anchor the
/// Zig side trusts and the material wolfSSL uses are the same blobs by
/// construction — "wolfSSL accepted it" cannot degrade into "wolfSSL trusted
/// something else".
fn writeCertFixtures(io: std.Io, dir: std.Io.Dir) !void {
    try dir.writeFile(io, .{ .sub_path = "server-cert.der", .data = &cert_kat.server_cert_der });
    const key = serverKeySec1Der();
    try dir.writeFile(io, .{ .sub_path = "server-key.der", .data = &key });
    try dir.writeFile(io, .{ .sub_path = "anchor-cert.der", .data = &cert_kat.anchor_cert_der });
}

fn clientEcdsaKeyPair() certverify.SecretKey {
    return .{ .ecdsa_p256 = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.client_secret_key_bytes) catch unreachable };
}

fn serverEcdsaKeyPair() certverify.SecretKey {
    return .{ .ecdsa_p256 = std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(cert_kat.server_secret_key_bytes) catch unreachable };
}

// Certificate mode had never met a third-party peer: every Certificate /
// CertificateVerify this module had ever parsed, it had also produced. That
// is the exact shape of the four PSK wire defects self-interop passed (see
// `root.zig`), and it hid one more — the `.cert_dhe` ClientHello carried no
// `supported_versions`, so a real DTLS 1.3 server negotiated 1.2 and the
// handshake died immediately. Nothing but a live peer could report that.
//
// The MTU is the second half of the point. wolfSSL's Certificate message
// here is a ~390-byte X.509 leaf plus framing; told to keep datagrams at
// 256 bytes it MUST split that message across several of them, so this
// handshake cannot complete at all unless the reassembly is real. Both MTUs
// are exercised — unconstrained (one datagram per message) and constrained
// (message-level fragmentation) — so a regression that breaks only the
// fragmented path cannot hide behind the easy one.

test "LIVE wolfSSL peer: our cert client completes a PSK-less X25519+ECDSA DTLS 1.3 handshake against wolfSSL" {
    try certClientAgainstWolfssl(.{ .peer_mode = "server-cert" });
}

test "LIVE wolfSSL peer: the same certificate handshake at a 256-byte peer MTU — wolfSSL fragments its Certificate and we reassemble it" {
    try certClientAgainstWolfssl(.{ .peer_mode = "server-cert", .mtu = 256 });
}

// ── HelloRetryRequest in CERTIFICATE mode (RFC 8446 §4.1.4) ───────────────
//
// Three live cases, because a HelloRetryRequest can ask for two independent
// things and a client can be wrong about either one alone:
//
//   1. cookie only — a default-configured wolfSSL certificate server. The
//      group is fine; only the return-routability cookie has to come back.
//      This is the same code path the PSK-mode retry test already covers,
//      but reached with a `.cert_dhe` ClientHello, which is a DIFFERENT
//      ClientHello builder: it has to reuse `random`, re-emit every other
//      extension unchanged, and add the cookie.
//
//   2. group change only — wolfSSL restricted to secp256r1, cookie exchange
//      OFF. Our ClientHello offers an x25519 share, which this server cannot
//      use, so it answers with a HelloRetryRequest whose ONLY content is
//      `key_share = secp256r1`. This is the half that did not exist before:
//      the client must generate a FRESH share in the named group, and the
//      handshake then runs on P-256 ECDHE end to end. Nothing in this repo
//      can check that arithmetic against itself — our own server never asks
//      for a group change — so wolfSSL completing the handshake and
//      decrypting our application data is the whole proof.
//
//   3. both at once — cookie AND group change in one retry, which is what a
//      stock server behind a return-routability check actually sends.
//
// The `expect_*` fields are what stops these degrading into copies of the
// no-retry test if wolfSSL's defaults ever change: a run that quietly did
// not retry, or retried but stayed on x25519, fails.

test "LIVE wolfSSL peer: our cert client answers a cookie-only HelloRetryRequest from a default-configured wolfSSL certificate server" {
    try certClientAgainstWolfssl(.{
        .peer_mode = "server-cert-hrr",
        .expect_hello_retry_request = true,
        .expect_group = x25519_group,
    });
}

test "LIVE wolfSSL peer: our cert client answers a GROUP-CHANGE HelloRetryRequest — wolfSSL names secp256r1, we generate a fresh P-256 key_share and the handshake completes on it" {
    try certClientAgainstWolfssl(.{
        .peer_mode = "server-cert-p256",
        .expect_hello_retry_request = true,
        .expect_group = secp256r1_group,
    });
}

test "LIVE wolfSSL peer: a HelloRetryRequest carrying BOTH a cookie and a group change is answered with one ClientHello2 that does both" {
    try certClientAgainstWolfssl(.{
        .peer_mode = "server-cert-p256-hrr",
        .expect_hello_retry_request = true,
        .expect_group = secp256r1_group,
    });
}

// ── mutual authentication, live ──────────────────────────────────────────
//
// Until this test, every Certificate + CertificateVerify our CLIENT had ever
// produced was checked by our own server — the exact self-interop shape that
// hid five wire defects on the PSK/cert side (see `root.zig`). Here wolfSSL
// is configured with `VERIFY_PEER | FAIL_IF_NO_PEER_CERT` and the fixture
// anchor as its only trusted CA, so `wolfSSL_accept` cannot succeed unless a
// third party parsed our certificate chain, chained it to the anchor, and
// verified our CertificateVerify signature over its own transcript.
test "LIVE wolfSSL peer: a wolfSSL server that REQUIRES a client certificate verifies OURS (mutual auth, third-party checked)" {
    try certClientAgainstWolfssl(.{
        .peer_mode = "server-cert-mutual",
        .client_cert = true,
        .expect_peer_cert_subject = "dtls-test-client",
    });
}

const CertCase = struct {
    peer_mode: []const u8,
    /// Non-zero forces wolfSSL to fragment its Certificate flight.
    mtu: u16 = 0,
    /// Asserted after the handshake — see the block comment above.
    expect_hello_retry_request: bool = false,
    /// The group the handshake finally ran on.
    expect_group: u16 = x25519_group,
    /// Present our own client certificate when asked.
    client_cert: bool = false,
    /// When set, the peer must print `PEERCERT <…subject…>` containing this,
    /// i.e. it really looked at the certificate we sent.
    expect_peer_cert_subject: ?[]const u8 = null,
};

fn certClientAgainstWolfssl(case: CertCase) !void {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try buildPeer(gpa, io, tmp.dir);
    try writeCertFixtures(io, tmp.dir);

    const port = try freeLoopbackPort(io);
    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    var mtu_buf: [8]u8 = undefined;
    const mtu_str = try std.fmt.bufPrint(&mtu_buf, "{d}", .{case.mtu});

    var child = try std.process.spawn(io, .{
        .argv = &.{ "./wolfssl_peer", case.peer_mode, port_str, mtu_str },
        .cwd = .{ .dir = tmp.dir },
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer _ = child.wait(io) catch {};

    var ready_buf: [256]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &ready_buf);
    const ready_line = peerLine(&stdout_reader.interface) catch {
        if (verboseSkip()) std.debug.print("\nSKIPPED: LIVE dtls wolfSSL interop: cert peer never printed READY.\n", .{});
        return error.SkipZigTest;
    };
    try testing.expectEqualStrings("READY", ready_line);

    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    const server_addr: net.IpAddress = .{ .ip4 = .loopback(port) };

    var conn = try Connection.clientInit(.{
        .role = .client,
        .key_exchange = .cert_dhe,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        // The chain wolfSSL presents must verify against OUR anchor, with
        // OUR clock — a `.none` policy here would let the test pass on a
        // handshake that authenticated nobody.
        .peer_verify = .{ .trust_anchor = &cert_kat.anchor_cert_der },
        .require_peer_cert = true,
        .now_sec = cert_kat.valid_now_sec,
        .cert = if (case.client_cert) .{
            .chain = &.{&cert_kat.client_cert_der},
            .private_key = clientEcdsaKeyPair(),
        } else null,
    });
    defer conn.deinit();

    var csprng = std.Random.DefaultCsprng.init([_]u8{0x3d} ** 32);
    const rnd = testRandom(&csprng);

    var out: [1500]u8 = undefined;
    var rx: [1500]u8 = undefined;

    const client_hello = try conn.startHandshake(rnd, 0, &out);
    // Every fresh ClientHello offers x25519 — which is what makes the
    // secp256r1 cases a genuine group CHANGE rather than a lucky first pick.
    try testing.expectEqual(x25519_group, conn.ecdhe_group);
    try sock.send(io, &server_addr, client_hello);

    var steps: usize = 0;
    var partial_steps: usize = 0;
    var largest_datagram: usize = 0;
    var flight_bytes: usize = 0;
    while (conn.state != .connected) : (steps += 1) {
        if (steps > 16) return error.TooManyFlights;
        const incoming = try sock.receiveTimeout(io, &rx, deadline(io, 10_000));
        largest_datagram = @max(largest_datagram, incoming.data.len);
        flight_bytes += incoming.data.len;
        const result = conn.handleFlight(incoming.data, rnd, 0, &out) catch |err| {
            reportPeerDiagnosis(gpa, io, &child, true, "wolfSSL's certificate server rejected our flight", err);
            return err;
        };
        if (result.need_more_data) partial_steps += 1;
        if (result.out.len > 0) try sock.send(io, &server_addr, result.out);
    }

    try testing.expectEqual(case.expect_hello_retry_request, conn.sawHelloRetryRequest());
    // The group the session keys were actually derived from. For the
    // secp256r1 cases this is the assertion that the retry was ACTED ON: a
    // client that echoed the cookie but kept its original x25519 share would
    // still be `sawHelloRetryRequest() == true` here.
    try testing.expectEqual(case.expect_group, conn.ecdhe_group);

    if (case.mtu > 0) {
        // Every datagram stayed inside the MTU, and the certificate alone is
        // bigger than one — so its Certificate message cannot have arrived
        // whole in any single datagram.
        try testing.expect(largest_datagram <= case.mtu);
        try testing.expect(cert_kat.server_cert_der.len > case.mtu);
        try testing.expect(flight_bytes > case.mtu);
        // ...and the engine really did have to wait for more datagrams.
        try testing.expect(partial_steps >= 1);
    }

    const msg = "hello from zig-libs, certificate mode";
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

    // The peer's own account of what it verified. Read only AFTER the
    // application-data round trip, so the peer has certainly printed it, and
    // only for the mutual-auth case — the handshake alone already proves
    // wolfSSL accepted our certificate (it was configured to fail without
    // one), but this pins WHICH certificate it saw.
    if (case.expect_peer_cert_subject) |want| {
        // The peer prints `HANDSHAKE <cipher>` first, so scan a couple of
        // lines rather than assuming the next one. All of them are already
        // in the pipe (they precede the echo we just consumed), so this
        // cannot block.
        var lines: usize = 0;
        const found = while (lines < 4) : (lines += 1) {
            const line = peerLine(&stdout_reader.interface) catch break false;
            if (std.mem.startsWith(u8, line, "PEERCERT ")) {
                try testing.expect(std.mem.indexOf(u8, line, want) != null);
                break true;
            }
        } else false;
        try testing.expect(found);
    }
}

// ── direction 4: a wolfSSL CERTIFICATE CLIENT -> our certificate server ───
//
// The other half of the certificate-mode gap. Everything our SERVER had ever
// put on the wire in `.cert_dhe` mode — its ServerHello `key_share`, its
// Certificate message framing, its CertificateVerify over its own transcript
// — had only ever been read by our own client. Here a third party verifies
// the chain we present against the fixture anchor and refuses the handshake
// (`wolfSSL_get_verify_result`, asserted inside the peer) if it does not
// check out, then round-trips application data under the keys our server
// derived.
//
// wolfSSL's client is restricted to x25519, matching what our server's
// `clientHelloShare` prefers — this test is about the certificate direction,
// not about group negotiation, which the HelloRetryRequest tests above cover.
test "LIVE wolfSSL peer: a real wolfSSL certificate CLIENT verifies the chain OUR server presents" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = testing.io;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try buildPeer(gpa, io, tmp.dir);
    try writeCertFixtures(io, tmp.dir);

    // This side binds first, so the port cannot be lost to a race.
    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);

    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{sock.address.getPort()});

    var child = try std.process.spawn(io, .{
        .argv = &.{ "./wolfssl_peer", "client-cert", port_str },
        .cwd = .{ .dir = tmp.dir },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    });
    defer child.kill(io);

    var conn = try Connection.serverInit(.{
        .role = .server,
        .key_exchange = .cert_dhe,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{
            .chain = &.{&cert_kat.server_cert_der},
            .private_key = serverEcdsaKeyPair(),
        },
    });
    defer conn.deinit();

    var csprng = std.Random.DefaultCsprng.init([_]u8{0x4e} ** 32);
    const rnd = testRandom(&csprng);

    var out: [1500]u8 = undefined;
    var rx: [1500]u8 = undefined;
    var peer_addr: net.IpAddress = undefined;

    var steps: usize = 0;
    while (conn.state != .connected) : (steps += 1) {
        if (steps > 16) return error.TooManyFlights;
        const incoming = try sock.receiveTimeout(io, &rx, deadline(io, 10_000));
        peer_addr = incoming.from;
        const result = conn.handleFlight(incoming.data, rnd, 0, &out) catch |err| {
            reportPeerDiagnosis(gpa, io, &child, false, "our cert server rejected wolfSSL's flight", err);
            return err;
        };
        if (result.out.len > 0) try sock.send(io, &peer_addr, result.out);
    }

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
    try testing.expectEqualStrings("hello from wolfssl cert client", received);

    const echo = try conn.send(received, &out);
    try sock.send(io, &peer_addr, echo);

    // The peer exits 0 only after `wolfSSL_get_verify_result` returned
    // X509_V_OK and the echo came back — so a non-zero status here means the
    // chain we presented was not accepted, not merely that the socket closed.
    const term = try child.wait(io);
    try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, term);
}
