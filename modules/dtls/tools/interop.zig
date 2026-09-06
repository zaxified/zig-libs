// SPDX-License-Identifier: MIT

//! LIVE third-party-peer interop for `dtls`: this module's DTLS 1.3 handshakes
//! against **wolfSSL**, over a real loopback UDP socket — and the recorder that
//! turns each of those exchanges into a committed transcript the module can
//! replay with no wolfSSL and no C compiler anywhere near it.
//!
//! ## Why this is a PROGRAM and not a test
//!
//! A zig-libs module is standalone Zig with no external dependency. Until
//! 2026-09-06 this file was `modules/dtls/src/wolfssl_interop.zig`: compiled
//! INTO `test-dtls`, `@embedFile`ing a 555-line C peer (which is why the C had
//! to live under `src/` — a module may not embed a file outside its own package
//! root), shelling out to `cc -lwolfssl` at test time, and skipping loudly when
//! either was missing. So every consumer of the library carried foreign source,
//! `zig build test-dtls` needed a toolchain it had no business needing, and —
//! because CI's peer install is `continue-on-error` — a failed install degraded
//! the whole anchor to a silent skip. The mess was paid for and the anchor still
//! might not run.
//!
//! Now: the TAKING of the anchor lives here, outside the module, where spawning
//! a C compiler is unremarkable. The VALUE of the anchor lives in
//! `src/testdata/wolfssl_transcript.txt` and is replayed by
//! `src/wolfssl_replay.zig`, which is pure Zig and runs everywhere. This program
//! is a pre-release check; the replay is the per-commit one.
//!
//! What only THIS can do, stated so the replay is not mistaken for a
//! replacement: discover a NEW divergence. The transcript is frozen bytes from
//! one wolfSSL release; it can prove we still answer those bytes the way a real
//! peer accepted, and it can never prove a real peer accepts an answer it has
//! not seen. Run this after any wire-visible change, and before a release.
//!
//! ## Usage
//!
//!     zig build interop-dtls                 # run every case live
//!     zig build interop-dtls -- --capture    # ...and rewrite the transcript
//!     zig build interop-dtls -- --case cert-client-mutual
//!     zig build interop-dtls -- --list
//!
//! It reads `modules/dtls/tools/wolfssl_peer.c` and
//! `modules/dtls/src/testdata/certs/*` **from their own paths at run time**,
//! relative to the repository root (which is `zig build`'s working directory);
//! `--repo-root <path>` overrides that. Nothing is embedded, so nothing forces
//! foreign source to live inside the module.
//!
//! Scratch — the compiled peer and the fixtures handed to it — goes in
//! `.zig-cache/dtls-interop/`, which is droppable at any moment.
//!
//! **Why wolfSSL and not OpenSSL** (SPEC.md's ranked oracle list put OpenSSL
//! first; that ranking was wrong and is corrected there): OpenSSL 3.5.5 has no
//! DTLS 1.3 at all — `s_server` offers only `-dtls1`/`-dtls1_2` — and GnuTLS
//! 3.8.12 likewise stops at `VERS-DTLS1.2`. wolfSSL is the DTLS 1.3
//! implementation that is both packaged and complete. To install the peer:
//! `sudo apt install libwolfssl-dev` (Debian/Ubuntu ship 5.9.1 built with
//! `WOLFSSL_DTLS13`).

const std = @import("std");
const dtls = @import("dtls");

const Connection = dtls.Connection;
const Entropy = dtls.Entropy;
const certverify = dtls.certverify;
const net = std.Io.net;

const x25519_group: u16 = @intFromEnum(dtls.messages.NamedGroup.x25519);
const secp256r1_group: u16 = @intFromEnum(dtls.messages.NamedGroup.secp256r1);
const x25519_mlkem768_group: u16 = @intFromEnum(dtls.messages.NamedGroup.x25519_ml_kem768);

/// Test fixtures — duplicated verbatim in `wolfssl_peer.c`. Test material
/// only; nothing here is a default for anything.
const psk = [_]u8{0x0b} ** 16;
const psk_identity = "zig-libs-dtls";

/// The MAC key the stateless-cookie case's server uses. Test material.
const cookie_secret = "a live server's cookie MAC key";

/// The instant the certificate cases run at. It only has to be inside the
/// fixture window (2026-07-21 .. 2036-07-18) and it is the same value
/// `src/certauth_kat_vectors.zig` uses; the transcript RECORDS whichever value
/// a capture ran with and the replay reads it back rather than assuming it, so
/// the two cannot drift into disagreeing about a certificate's validity.
const valid_now_sec: i64 = 1785542400;

const transcript_path = "modules/dtls/src/testdata/wolfssl_transcript.txt";
const peer_source_path = "modules/dtls/tools/wolfssl_peer.c";
const certs_dir = "modules/dtls/src/testdata/certs";
const scratch_dir = ".zig-cache/dtls-interop";

/// The environment handed to every child.
///
/// It has to be passed explicitly. `std.process.SpawnOptions.environ_map` says
/// a null value inherits, and under the `Init.Minimal` main signature there is
/// nothing to inherit FROM: the environment arrives as a parameter instead of
/// living in a process global, so a null here spawns the child with an empty
/// environment. `cc` still starts (Zig resolves argv[0] against the parent's
/// PATH by a separate route) and then fails deep inside GCC — "cannot find
/// 'ld'" — which reads like a broken toolchain and is not one. Set once in
/// `main`, before anything spawns.
var child_env: ?*const std.process.Environ.Map = null;

// ── the case table ────────────────────────────────────────────────────────

const Flow = enum {
    /// Our client drives; wolfSSL is the server.
    client,
    /// wolfSSL's client drives; our server answers, statefully.
    server,
    /// wolfSSL's client drives; our server answers ClientHello1 with a
    /// HelloRetryRequest, THROWS THE CONNECTION AWAY, and finishes the
    /// handshake from a brand-new one that has only the cookie. Statelessness
    /// is not asserted by inspection: it is structural, because the object
    /// that saw ClientHello1 is destroyed before ClientHello2 is read.
    server_cookie,
};

const Case = struct {
    name: []const u8,
    flow: Flow,
    /// argv[1] for `wolfssl_peer`.
    peer_mode: []const u8,
    /// The 32-byte CSPRNG seed, written as one repeated byte. Fixed so a
    /// failing live run can be replayed byte-for-byte — and so the transcript
    /// replays at all.
    seed: u8,
    cert_mode: bool = false,
    /// Non-zero forces wolfSSL to fragment its Certificate flight.
    mtu: u16 = 0,
    /// The group our fresh ClientHello offers its share in.
    offer_group: u16 = x25519_group,
    /// Asserted live, then recorded: a case that quietly stopped retrying, or
    /// retried but stayed on its original group, must not pass as a duplicate
    /// of the no-retry case.
    expect_hrr: bool = false,
    expect_group: u16 = x25519_group,
    /// Present our own client certificate when asked.
    client_cert: bool = false,
    /// When set, the peer must print `PEERCERT <…subject…>` containing this,
    /// i.e. it really looked at the certificate we sent.
    expect_peer_cert_subject: ?[]const u8 = null,
    /// What our side sends once connected, and what it must receive.
    app_send: []const u8 = "",
    app_expect: []const u8,
    /// One line of prose, copied into the transcript, saying what THIS case
    /// proves that no other one does.
    why: []const u8,
};

const cases = [_]Case{
    .{
        .name = "psk-client",
        .flow = .client,
        .peer_mode = "server",
        .seed = 0x2c,
        .app_send = "hello from zig-libs",
        .app_expect = "hello from zig-libs",
        .why = "our client completes a real DTLS 1.3 PSK handshake with no retry",
    },
    .{
        .name = "psk-client-hrr",
        .flow = .client,
        .peer_mode = "server-hrr",
        .seed = 0x2c,
        .expect_hrr = true,
        .app_send = "hello from zig-libs",
        .app_expect = "hello from zig-libs",
        .why = "a DEFAULT wolfSSL server's cookie exchange; the only PSK case that exercises RFC 8446 4.4.1's message_hash rewrite against a real peer",
    },
    .{
        .name = "psk-server",
        .flow = .server,
        .peer_mode = "client",
        .seed = 0x5b,
        .app_expect = "hello from wolfssl client",
        .why = "a real wolfSSL client accepts what OUR server puts on the wire",
    },
    .{
        .name = "psk-server-cookie",
        .flow = .server_cookie,
        .peer_mode = "client",
        .seed = 0x6e,
        .expect_hrr = true,
        .app_expect = "hello from wolfssl client",
        .why = "a stock client accepts the HelloRetryRequest WE emit, and a BRAND-NEW connection re-derives the transcript from the cookie alone",
    },
    .{
        .name = "cert-client",
        .flow = .client,
        .peer_mode = "server-cert",
        .seed = 0x3d,
        .cert_mode = true,
        .app_send = "hello from zig-libs, certificate mode",
        .app_expect = "hello from zig-libs, certificate mode",
        .why = "PSK-less X25519 + ECDSA P-256 certificate handshake, one datagram per message",
    },
    .{
        .name = "cert-client-mtu256",
        .flow = .client,
        .peer_mode = "server-cert",
        .seed = 0x3d,
        .cert_mode = true,
        .mtu = 256,
        .app_send = "hello from zig-libs, certificate mode",
        .app_expect = "hello from zig-libs, certificate mode",
        .why = "the same handshake at a 256-byte peer MTU: wolfSSL MUST split its Certificate, so this cannot complete unless message reassembly is real",
    },
    .{
        .name = "cert-client-hrr-cookie",
        .flow = .client,
        .peer_mode = "server-cert-hrr",
        .seed = 0x3d,
        .cert_mode = true,
        .expect_hrr = true,
        .app_send = "hello from zig-libs, certificate mode",
        .app_expect = "hello from zig-libs, certificate mode",
        .why = "cookie-only retry reached with a .cert_dhe ClientHello, which is a DIFFERENT builder from the PSK one",
    },
    .{
        .name = "cert-client-hrr-p256",
        .flow = .client,
        .peer_mode = "server-cert-p256",
        .seed = 0x3d,
        .cert_mode = true,
        .expect_hrr = true,
        .expect_group = secp256r1_group,
        .app_send = "hello from zig-libs, certificate mode",
        .app_expect = "hello from zig-libs, certificate mode",
        .why = "GROUP-CHANGE retry with no cookie: we must generate a FRESH secp256r1 share and run the handshake on P-256, which nothing in this repo can check against itself",
    },
    .{
        .name = "cert-client-hrr-p256-cookie",
        .flow = .client,
        .peer_mode = "server-cert-p256-hrr",
        .seed = 0x3d,
        .cert_mode = true,
        .expect_hrr = true,
        .expect_group = secp256r1_group,
        .app_send = "hello from zig-libs, certificate mode",
        .app_expect = "hello from zig-libs, certificate mode",
        .why = "cookie AND group change in one retry, answered by one ClientHello2 that does both",
    },
    .{
        .name = "cert-client-mlkem-offered",
        .flow = .client,
        .peer_mode = "server-cert-mlkem",
        .seed = 0x3d,
        .cert_mode = true,
        .offer_group = x25519_mlkem768_group,
        .expect_group = x25519_mlkem768_group,
        .app_send = "hello from zig-libs, certificate mode",
        .app_expect = "hello from zig-libs, certificate mode",
        .why = "X25519MLKEM768 offered directly: the 1216-byte share goes out in ClientHello1 and foreign code derives the same keys from the 64-byte concatenation",
    },
    .{
        .name = "cert-client-mlkem-hrr",
        .flow = .client,
        .peer_mode = "server-cert-mlkem",
        .seed = 0x3d,
        .cert_mode = true,
        .expect_hrr = true,
        .expect_group = x25519_mlkem768_group,
        .app_send = "hello from zig-libs, certificate mode",
        .app_expect = "hello from zig-libs, certificate mode",
        .why = "a hybrid-only server retries our classical offer UP to X25519MLKEM768",
    },
    .{
        .name = "cert-client-mutual",
        .flow = .client,
        .peer_mode = "server-cert-mutual",
        .seed = 0x3d,
        .cert_mode = true,
        .client_cert = true,
        .expect_peer_cert_subject = "dtls-test-client",
        .app_send = "hello from zig-libs, certificate mode",
        .app_expect = "hello from zig-libs, certificate mode",
        .why = "mutual auth: wolfSSL runs VERIFY_PEER|FAIL_IF_NO_PEER_CERT, so the handshake cannot complete unless a third party chained OUR certificate and verified OUR CertificateVerify",
    },
    .{
        .name = "cert-server",
        .flow = .server,
        .peer_mode = "client-cert",
        .seed = 0x4e,
        .cert_mode = true,
        .app_expect = "hello from wolfssl cert client",
        .why = "a real wolfSSL certificate CLIENT verifies the chain OUR server presents (it asserts X509_V_OK before exiting 0)",
    },
    .{
        .name = "cert-server-mlkem",
        .flow = .server,
        .peer_mode = "client-cert-mlkem",
        .seed = 0x4e,
        .cert_mode = true,
        .expect_group = x25519_mlkem768_group,
        .app_expect = "hello from wolfssl cert client",
        .why = "wolfSSL offers the 1216-byte hybrid share and OUR server must encapsulate to it — the server half of the PQ hybrid, checked by foreign code",
    },
};

// ── the recorder ──────────────────────────────────────────────────────────
//
// The transcript is written as the live exchange happens, one line per thing
// our side DID. Recording the OPERATION rather than a bare packet dump is what
// makes the replay executable: `flight in=… out=…` says "feed these bytes to
// `handleFlight` and our answer must be exactly these", which is a check, where
// a packet dump is only a picture.

const Recorder = struct {
    enabled: bool,
    out: *std.Io.Writer,

    fn raw(self: *Recorder, comptime fmt: []const u8, args: anytype) void {
        if (!self.enabled) return;
        self.out.print(fmt, args) catch @panic("OOM writing transcript");
    }

    fn op(self: *Recorder, name: []const u8) void {
        self.raw("{s}", .{name});
    }

    fn hexArg(self: *Recorder, key: []const u8, bytes: []const u8) void {
        if (!self.enabled) return;
        self.raw(" {s}=", .{key});
        for (bytes) |b| self.raw("{x:0>2}", .{b});
    }

    fn strArg(self: *Recorder, key: []const u8, value: []const u8) void {
        self.raw(" {s}={s}", .{ key, value });
    }

    fn numArg(self: *Recorder, key: []const u8, value: anytype) void {
        self.raw(" {s}={d}", .{ key, value });
    }

    fn hex4Arg(self: *Recorder, key: []const u8, value: u16) void {
        self.raw(" {s}={x:0>4}", .{ key, value });
    }

    fn end(self: *Recorder) void {
        self.raw("\n", .{});
    }

    /// A line the replay ignores. For everything the transcript can SHOW but
    /// not CHECK — the peer's own stdout, which is not bytes on the wire.
    fn note(self: *Recorder, comptime fmt: []const u8, args: anytype) void {
        self.raw("# ", .{});
        self.raw(fmt, args);
        self.raw("\n", .{});
    }
};

// ── fixtures, read from disk so the peer and our side share ONE copy ──────

const Fixtures = struct {
    anchor_cert_der: []u8,
    server_cert_der: []u8,
    server_secret_key_bytes: []u8,
    client_cert_der: []u8,
    client_secret_key_bytes: []u8,
    /// The one-element chains `Config.cert.chain` points AT.
    ///
    /// They are fields, and `Fixtures` is passed by pointer, because
    /// `.chain = &.{fx.server_cert_der}` does not do what it looks like: with a
    /// runtime slice inside it, the anonymous array is a local temporary and
    /// `&` hands out a pointer into the frame of whichever function built the
    /// `Config`. It dies on return, and the `Config` then names a chain of
    /// garbage length -- which surfaced as `BufferTooShort` from
    /// `encodeCertificate`, i.e. as a plausible-looking buffer-size bug three
    /// modules away. The original in-module harness never met this because its
    /// literal (`&.{&cert_kat.server_cert_der}`) was comptime-known and
    /// therefore static.
    server_chain: [1][]const u8 = undefined,
    client_chain: [1][]const u8 = undefined,

    fn load(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir) !Fixtures {
        var fx: Fixtures = .{
            .anchor_cert_der = try read(gpa, io, root, "anchor-cert.der"),
            .server_cert_der = try read(gpa, io, root, "server-cert.der"),
            .server_secret_key_bytes = try read(gpa, io, root, "server-key.bin"),
            .client_cert_der = try read(gpa, io, root, "client-cert.der"),
            .client_secret_key_bytes = try read(gpa, io, root, "client-key.bin"),
        };
        fx.server_chain = .{fx.server_cert_der};
        fx.client_chain = .{fx.client_cert_der};
        return fx;
    }

    fn read(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir, name: []const u8) ![]u8 {
        var buf: [256]u8 = undefined;
        const path = std.fmt.bufPrint(&buf, "{s}/{s}", .{ certs_dir, name }) catch unreachable;
        return root.readFileAlloc(io, path, gpa, .limited(64 * 1024)) catch |err| {
            std.debug.print("cannot read {s}: {t}\n", .{ path, err });
            return error.MissingFixture;
        };
    }

    fn scalar32(bytes: []const u8) [32]u8 {
        var out: [32]u8 = undefined;
        @memcpy(&out, bytes[0..32]);
        return out;
    }

    fn clientKey(self: *const Fixtures) certverify.SecretKey {
        const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        return .{ .ecdsa_p256 = P256.SecretKey.fromBytes(scalar32(self.client_secret_key_bytes)) catch unreachable };
    }

    fn serverKey(self: *const Fixtures) certverify.SecretKey {
        const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        return .{ .ecdsa_p256 = P256.SecretKey.fromBytes(scalar32(self.server_secret_key_bytes)) catch unreachable };
    }

    /// SEC1 `ECPrivateKey` DER (RFC 5915) for the fixture P-256 leaf, built
    /// here from the ONE piece of key material this repo stores (a raw 32-byte
    /// scalar) rather than committed as a second encoded copy: the public
    /// point is recomputed from the scalar, so the key wolfSSL signs with
    /// cannot silently drift from the certificate the Zig side verifies
    /// against.
    fn serverKeySec1Der(self: *const Fixtures) [121]u8 {
        const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        const sk = P256.SecretKey.fromBytes(scalar32(self.server_secret_key_bytes)) catch unreachable;
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
        put(&out, &i, self.server_secret_key_bytes[0..32]);
        // [0] parameters: OID 1.2.840.10045.3.1.7 (prime256v1)
        put(&out, &i, &.{ 0xa0, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 });
        // [1] publicKey: BIT STRING, 0 unused bits, uncompressed point
        put(&out, &i, &.{ 0xa1, 0x44, 0x03, 0x42, 0x00 });
        put(&out, &i, &point);
        std.debug.assert(i == out.len);
        return out;
    }

    /// A wolfSSL certificate peer needs the leaf, its key and the trust anchor
    /// as files; all three come from this repo's own fixtures, so the anchor
    /// the Zig side trusts and the material wolfSSL uses are the same blobs by
    /// construction — "wolfSSL accepted it" cannot degrade into "wolfSSL
    /// trusted something else".
    fn writeForPeer(self: *const Fixtures, io: std.Io, dir: std.Io.Dir) !void {
        try dir.writeFile(io, .{ .sub_path = "server-cert.der", .data = self.server_cert_der });
        const key = self.serverKeySec1Der();
        try dir.writeFile(io, .{ .sub_path = "server-key.der", .data = &key });
        try dir.writeFile(io, .{ .sub_path = "anchor-cert.der", .data = self.anchor_cert_der });
    }
};

// ── plumbing ──────────────────────────────────────────────────────────────

/// This harness drives real handshakes from a FIXED seed, so a failing interop
/// run can be replayed byte-for-byte and so the transcript replays at all. That
/// is the legitimate use of `Entropy.seeded_for_test`, and naming the arm here
/// is what keeps it from looking like the shape production code should copy.
fn seededForTest(csprng: *std.Random.DefaultCsprng) Entropy {
    return .{ .seeded_for_test = csprng.random() };
}

/// A free loopback UDP port, learned by binding one and letting it go. Handing
/// a port to a child process this way is a (narrow) race — nothing else may
/// claim it in between.
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
/// position 0 and returns an empty slice — forever.
fn peerLine(reader: *std.Io.Reader) ![]const u8 {
    const raw = try reader.takeDelimiterInclusive('\n');
    return std.mem.trimEnd(u8, raw, "\n");
}

/// A peer that stops answering must fail the run, not wedge it.
fn deadline(io: std.Io, ms: u32) std.Io.Timeout {
    const t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(ms), .clock = .awake } };
    return t.toDeadline(io);
}

/// Prints why the handshake died, including wolfSSL's own diagnosis — it names
/// the exact check that failed ("binder does not verify"), which is worth more
/// than any error we can raise on our side.
///
/// `peer_died` says whether the peer is expected to have given up already — it
/// decides whether its stderr can be read at all, and getting it wrong hangs
/// the run instead of diagnosing it:
///
///   * true (the peer rejected US): wolfSSL's `accept`/`connect` returned, it
///     printed its reason and exited, so reading to EOF terminates.
///   * false (WE rejected the peer): we send nothing back, so wolfSSL just
///     retransmits for the better part of a minute. There is no diagnosis to
///     read, and reading to EOF would block until it eventually gives up.
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
        // Print BEFORE killing: `kill` blocks until the child is reaped, and a
        // diagnosis that only appears after a successful reap is worthless in
        // exactly the case worth diagnosing.
        std.debug.print("\n  {s} ({t}).\n", .{ what, err });
        child.kill(io);
        return;
    }
    var buf: [4096]u8 = undefined;
    var reader = child.stderr.?.reader(io, &buf);
    const peer_says = reader.interface.allocRemaining(gpa, .unlimited) catch "";
    defer gpa.free(peer_says);
    std.debug.print("\n  {s} ({t}). Peer said: {s}\n", .{ what, err, peer_says });
}

fn expectBytes(what: []const u8, want: []const u8, got: []const u8) !void {
    if (std.mem.eql(u8, want, got)) return;
    std.debug.print("  {s}: expected {d} bytes, got {d}\n", .{ what, want.len, got.len });
    return error.Mismatch;
}

fn expectU16(what: []const u8, want: u16, got: u16) !void {
    if (want == got) return;
    std.debug.print("  {s}: expected 0x{x:0>4}, got 0x{x:0>4}\n", .{ what, want, got });
    return error.Mismatch;
}

fn expectBool(what: []const u8, want: bool, got: bool) !void {
    if (want == got) return;
    std.debug.print("  {s}: expected {}, got {}\n", .{ what, want, got });
    return error.Mismatch;
}

// ── building the peer ─────────────────────────────────────────────────────

/// Compiles `wolfssl_peer.c` into the scratch directory, reading it from its
/// own path rather than an embedded copy. Fails with an actionable message
/// when `cc` or wolfSSL is missing — this program is allowed to REQUIRE them,
/// which is the whole point of it not being a test.
fn buildPeer(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir, work: std.Io.Dir) !void {
    const source = root.readFileAlloc(io, peer_source_path, gpa, .limited(1024 * 1024)) catch |err| {
        std.debug.print(
            "cannot read {s} ({t}).\n" ++
                "  This program reads its peer from the repository, so run it from the repository\n" ++
                "  root (`zig build interop-dtls` does) or pass `--repo-root <path>`.\n",
            .{ peer_source_path, err },
        );
        return error.MissingPeerSource;
    };
    defer gpa.free(source);
    try work.writeFile(io, .{ .sub_path = "wolfssl_peer.c", .data = source });

    var child = std.process.spawn(io, .{
        .argv = &.{ "cc", "-O1", "-o", "wolfssl_peer", "wolfssl_peer.c", "-lwolfssl" },
        .cwd = .{ .dir = work },
        .environ_map = child_env,
        // `.expand` makes argv[0] the RESOLVED path (`/usr/bin/cc`) rather than
        // the bare word. GCC's driver locates `cc1` by deriving its own
        // installation prefix from argv[0]; handed a bare `cc` it looks in the
        // wrong place and dies with "cannot execute 'cc1': posix_spawnp: No
        // such file or directory", which reads exactly like a missing wolfSSL
        // and is not one.
        .expand_arg0 = .expand,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    }) catch {
        std.debug.print("no `cc` on PATH — the live interop needs a C compiler.\n", .{});
        return error.NoCompiler;
    };

    var err_buf: [8192]u8 = undefined;
    var stderr_reader = child.stderr.?.reader(io, &err_buf);
    const stderr = try stderr_reader.interface.allocRemaining(gpa, .unlimited);
    defer gpa.free(stderr);

    const term = try child.wait(io);
    const ok = switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!ok) {
        std.debug.print(
            "cannot build the peer (wolfSSL headers/library missing?).\n" ++
                "  fix: sudo apt install libwolfssl-dev\n  cc said: {s}\n",
            .{stderr},
        );
        return error.NoWolfssl;
    }
}

/// `wolfssl_peer version` prints the runtime library version and exits. Asking
/// the peer rather than a constant is what keeps the transcript header honest:
/// the version recorded is the one that produced the bytes under it.
fn readPeerVersion(gpa: std.mem.Allocator, io: std.Io, work: std.Io.Dir) []const u8 {
    var child = std.process.spawn(io, .{
        .argv = &.{ "./wolfssl_peer", "version" },
        .cwd = .{ .dir = work },
        .environ_map = child_env,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .ignore,
    }) catch return "unknown";
    var buf: [256]u8 = undefined;
    var reader = child.stdout.?.reader(io, &buf);
    const text = reader.interface.allocRemaining(gpa, .limited(256)) catch "";
    _ = child.wait(io) catch {};
    const trimmed = std.mem.trim(u8, text, " \r\n\t");
    if (trimmed.len == 0) return "unknown";
    return gpa.dupe(u8, trimmed) catch "unknown";
}

// ── config, built once so the live run and the transcript cannot disagree ──

fn clientConfig(case: Case, fx: *const Fixtures) dtls.Config {
    if (!case.cert_mode) return .{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = &psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
    };
    return .{
        .role = .client,
        .key_exchange = .cert_dhe,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        // The chain wolfSSL presents must verify against OUR anchor, with OUR
        // clock — a `.none` policy here would let the run pass on a handshake
        // that authenticated nobody.
        .peer_verify = .{ .trust_anchor = fx.anchor_cert_der },
        .require_peer_cert = true,
        .now_sec = valid_now_sec,
        .cert = if (case.client_cert) .{
            .chain = &fx.client_chain,
            .private_key = fx.clientKey(),
        } else null,
        .key_share_group = @enumFromInt(case.offer_group),
    };
}

fn serverConfig(case: Case, fx: *const Fixtures, binding: ?[]const u8) dtls.Config {
    if (!case.cert_mode) return .{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = &psk,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .hello_retry = if (binding) |b|
            .{ .cookie_secret = cookie_secret, .peer_binding = b }
        else
            null,
    };
    return .{
        .role = .server,
        .key_exchange = .cert_dhe,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{
            .chain = &fx.server_chain,
            .private_key = fx.serverKey(),
        },
    };
}

/// The `config` line the replay reads back. Written from the same `Case` the
/// live run used, so "what the transcript says we configured" and "what we
/// configured" are one statement, not two.
fn recordConfig(rec: *Recorder, case: Case, seed: [32]u8) void {
    rec.op("config");
    rec.strArg("flow", @tagName(case.flow));
    rec.strArg("key_exchange", if (case.cert_mode) "cert_dhe" else "psk");
    rec.hexArg("seed", &seed);
    rec.strArg("suite", "aes_128_gcm_sha256");
    rec.numArg("now_sec", valid_now_sec);
    rec.hex4Arg("offer_group", case.offer_group);
    rec.numArg("client_cert", @intFromBool(case.client_cert));
    if (!case.cert_mode) {
        rec.hexArg("psk_identity", psk_identity);
        rec.hexArg("psk", &psk);
        rec.hexArg("cookie_secret", cookie_secret);
    }
    rec.end();
}

// ── flow 1: our client against a wolfSSL server ───────────────────────────

fn runClientFlow(
    gpa: std.mem.Allocator,
    io: std.Io,
    work: std.Io.Dir,
    case: Case,
    fx: *const Fixtures,
    rec: *Recorder,
) !void {
    const port = try freeLoopbackPort(io);
    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{port});
    var mtu_buf: [8]u8 = undefined;
    const mtu_str = try std.fmt.bufPrint(&mtu_buf, "{d}", .{case.mtu});

    var child = try std.process.spawn(io, .{
        .argv = if (case.cert_mode)
            &.{ "./wolfssl_peer", case.peer_mode, port_str, mtu_str }
        else
            &.{ "./wolfssl_peer", case.peer_mode, port_str },
        .cwd = .{ .dir = work },
        .environ_map = child_env,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer _ = child.wait(io) catch {};

    // Wait for READY — the server prints it after bind(), before it looks at
    // the socket, so a datagram sent afterwards cannot be lost.
    var ready_buf: [256]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &ready_buf);
    const ready_line = peerLine(&stdout_reader.interface) catch {
        std.debug.print("  peer never printed READY\n", .{});
        return error.PeerNeverReady;
    };
    if (!std.mem.eql(u8, "READY", ready_line)) {
        std.debug.print("  peer said \"{s}\", not READY\n", .{ready_line});
        return error.PeerNeverReady;
    }

    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    const server_addr: net.IpAddress = .{ .ip4 = .loopback(port) };

    const seed = [_]u8{case.seed} ** 32;
    var csprng = std.Random.DefaultCsprng.init(seed);
    const rnd = seededForTest(&csprng);

    recordConfig(rec, case, seed);

    var conn = try Connection.clientInit(clientConfig(case, fx));
    defer conn.deinit();
    rec.op("client_init");
    rec.end();

    var out: [4096]u8 = undefined;
    var rx: [2048]u8 = undefined;

    const client_hello = try conn.startHandshake(rnd, 0, &out);
    // The fresh ClientHello offers exactly the configured group — which is
    // what makes the retry cases a genuine group CHANGE rather than a lucky
    // first pick. PSK mode is `psk_ke`, no (EC)DHE at all, so there is no
    // group to name and `ecdhe_group` stays 0.
    if (case.cert_mode) try expectU16("offered group", case.offer_group, conn.ecdhe_group);
    rec.op("start");
    rec.hexArg("out", client_hello);
    rec.end();
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
            reportPeerDiagnosis(gpa, io, &child, true, "wolfSSL rejected our flight", err);
            return err;
        };
        if (result.need_more_data) partial_steps += 1;
        rec.op("flight");
        rec.hexArg("in", incoming.data);
        rec.hexArg("out", result.out);
        rec.numArg("more", @intFromBool(result.need_more_data));
        rec.end();
        if (result.out.len > 0) try sock.send(io, &server_addr, result.out);
    }

    try expectBool("sawHelloRetryRequest", case.expect_hrr, conn.sawHelloRetryRequest());
    // The group the session keys were actually derived from. For the
    // secp256r1/hybrid cases this is the assertion that the retry was ACTED
    // ON: a client that echoed the cookie but kept its original share would
    // still be `sawHelloRetryRequest() == true` here.
    if (case.cert_mode) try expectU16("negotiated group", case.expect_group, conn.ecdhe_group);
    rec.op("expect");
    rec.numArg("hrr", @intFromBool(case.expect_hrr));
    // The group RECORDED is the one the connection ended on, not the one the
    // case predicted -- the prediction was just checked against it, and a
    // transcript that echoed the prediction back would be checking nothing.
    rec.hex4Arg("group", conn.ecdhe_group);
    if (case.mtu > 0) {
        // Every datagram stayed inside the MTU, and the certificate alone is
        // bigger than one — so its Certificate message cannot have arrived
        // whole in any single datagram...
        if (largest_datagram > case.mtu) return error.PeerIgnoredMtu;
        if (fx.server_cert_der.len <= case.mtu) return error.CertificateTooSmallToFragment;
        if (flight_bytes <= case.mtu) return error.FlightTooSmallToFragment;
        // ...and the engine really did have to wait for more datagrams.
        if (partial_steps < 1) return error.NothingWasReassembled;
        rec.numArg("max_datagram", case.mtu);
        rec.numArg("min_partial", 1);
    }
    rec.end();

    // Application data over the keys THIS handshake installed, decrypted by an
    // implementation that shares no code with ours.
    const record = try conn.send(case.app_send, &out);
    rec.op("send");
    rec.hexArg("in", case.app_send);
    rec.hexArg("out", record);
    rec.end();
    try sock.send(io, &server_addr, record);

    var plain: [2048]u8 = undefined;
    const echoed = try recvApplicationData(io, sock, &conn, &rx, &plain, rec);
    try expectBytes("echoed application data", case.app_expect, echoed);

    // The peer's own account of what it verified. Read only AFTER the
    // application-data round trip, so the peer has certainly printed it, and
    // only for the mutual-auth case — the handshake alone already proves
    // wolfSSL accepted our certificate (it was configured to fail without
    // one), but this pins WHICH certificate it saw.
    //
    // It is recorded as a NOTE, not an assertion: it is the peer's stdout, not
    // bytes on the wire, so the replay can show it and cannot check it.
    if (case.expect_peer_cert_subject) |want| {
        // The peer prints `HANDSHAKE <cipher>` first, so scan a couple of
        // lines rather than assuming the next one. All of them are already in
        // the pipe (they precede the echo we just consumed), so this cannot
        // block.
        var lines: usize = 0;
        const found = while (lines < 4) : (lines += 1) {
            const line = peerLine(&stdout_reader.interface) catch break false;
            if (std.mem.startsWith(u8, line, "PEERCERT ")) {
                if (std.mem.indexOf(u8, line, want) == null) {
                    std.debug.print("  peer saw \"{s}\", which does not name {s}\n", .{ line, want });
                    return error.WrongPeerCertificate;
                }
                rec.note("peer stdout (not replayable): {s}", .{line});
                break true;
            }
        } else false;
        if (!found) return error.PeerNeverReportedOurCertificate;
    }
}

/// The application-data read both directions share. A real peer puts other
/// things on the application epoch first: wolfSSL ACKs our Finished (RFC 9147
/// §7) and sends a NewSessionTicket. Neither is application data and neither is
/// damage — this module implements no post-handshake message, so both are
/// skipped, and the fact that they decrypt at all is itself the strongest
/// evidence the two sides derived identical application keys. The skips are
/// recorded too, because "this datagram must come back as `ReceivedAck`" is
/// exactly as much of a check as the plaintext is.
fn recvApplicationData(
    io: std.Io,
    sock: net.Socket,
    conn: *Connection,
    rx: []u8,
    plain: []u8,
    rec: *Recorder,
) ![]const u8 {
    var skipped: usize = 0;
    while (skipped <= 8) {
        const incoming = try sock.receiveTimeout(io, rx, deadline(io, 10_000));
        const got = conn.recv(incoming.data, plain) catch |err| switch (err) {
            error.ReceivedAck, error.ReceivedPostHandshakeMessage => {
                rec.op("recv");
                rec.hexArg("in", incoming.data);
                rec.strArg("skip", @errorName(err));
                rec.end();
                skipped += 1;
                continue;
            },
            else => return err,
        };
        rec.op("recv");
        rec.hexArg("in", incoming.data);
        rec.hexArg("out", got);
        rec.end();
        return got;
    }
    return error.NoApplicationData;
}

// ── flow 2: a wolfSSL client against our server ───────────────────────────

fn runServerFlow(
    gpa: std.mem.Allocator,
    io: std.Io,
    work: std.Io.Dir,
    case: Case,
    fx: *const Fixtures,
    rec: *Recorder,
) !void {
    // This side binds first, so the port cannot be lost to a race.
    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);

    var port_buf: [8]u8 = undefined;
    const port_str = try std.fmt.bufPrint(&port_buf, "{d}", .{sock.address.getPort()});

    var child = try std.process.spawn(io, .{
        .argv = &.{ "./wolfssl_peer", case.peer_mode, port_str },
        .cwd = .{ .dir = work },
        .environ_map = child_env,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    });
    // `kill` is idempotent and a no-op once `wait` has returned, so it is safe
    // cleanup for the early-return paths; `wait` below is the real one.
    defer child.kill(io);

    const seed = [_]u8{case.seed} ** 32;
    var csprng = std.Random.DefaultCsprng.init(seed);
    const rnd = seededForTest(&csprng);

    recordConfig(rec, case, seed);

    // A hybrid ServerHello makes our flight 2 outgrow an MTU-sized buffer
    // (~1.2 KB ServerHello + certificate + CertificateVerify + Finished in ONE
    // `out`), hence flight-sized rather than 1500.
    var out: [4096]u8 = undefined;
    var rx: [2048]u8 = undefined;
    var peer_addr: net.IpAddress = undefined;
    var binding_buf: [64]u8 = undefined;

    const cookie_mode = case.flow == .server_cookie;
    var conn: ?Connection = null;
    defer if (conn) |*c| c.deinit();
    var retries_served: usize = 0;

    var steps: usize = 0;
    while (true) : (steps += 1) {
        if (steps > 16) return error.TooManyFlights;
        const incoming = try sock.receiveTimeout(io, &rx, deadline(io, 10_000));
        peer_addr = incoming.from;

        if (conn == null) {
            // The caller-supplied `peer_binding`: this module never sees a
            // socket, so the address the cookie is bound to has to come from
            // whoever owns the I/O — here, the address `receiveTimeout`
            // reports. It carries an ephemeral port, so it is DIFFERENT on
            // every capture and the replay has to read it from the transcript
            // rather than reconstruct it.
            const binding = if (cookie_mode)
                try std.fmt.bufPrint(&binding_buf, "{f}", .{incoming.from})
            else
                null;
            conn = try Connection.serverInit(serverConfig(case, fx, binding));
            rec.op("server_init");
            if (binding) |b| rec.hexArg("binding", b);
            rec.end();
        }

        const result = conn.?.handleFlight(incoming.data, rnd, 0, &out) catch |err| {
            reportPeerDiagnosis(gpa, io, &child, false, "our server rejected wolfSSL's flight", err);
            return err;
        };
        rec.op("flight");
        rec.hexArg("in", incoming.data);
        rec.hexArg("out", result.out);
        rec.numArg("more", @intFromBool(result.need_more_data));
        rec.end();
        if (result.out.len > 0) try sock.send(io, &peer_addr, result.out);
        if (conn.?.state == .connected) break;

        // Still `.start` after a flight went out ⇒ that flight was a
        // HelloRetryRequest and this connection committed nothing. Throw it
        // away, exactly as a stateless server would: whatever the next
        // ClientHello needs must be in the cookie.
        if (cookie_mode and conn.?.state == .start) {
            try expectBool("sawHelloRetryRequest after the retry", true, conn.?.sawHelloRetryRequest());
            retries_served += 1;
            conn.?.deinit();
            conn = null;
            rec.op("drop_conn");
            rec.end();
        }
    }

    // Without this the cookie case would silently degrade into a duplicate of
    // the no-cookie one if `Config.hello_retry` ever stopped taking effect: the
    // handshake would still complete, just without the check.
    if (cookie_mode and retries_served < 1) return error.NoRetryWasServed;
    if (case.cert_mode) try expectU16("negotiated group", case.expect_group, conn.?.ecdhe_group);
    rec.op("expect");
    rec.numArg("hrr", @intFromBool(case.expect_hrr));
    rec.hex4Arg("group", conn.?.ecdhe_group);
    if (cookie_mode) rec.numArg("min_retries", 1);
    rec.end();

    // The wolfSSL client sends first and expects its own message echoed.
    var plain: [2048]u8 = undefined;
    const received = try recvApplicationData(io, sock, &conn.?, &rx, &plain, rec);
    try expectBytes("received application data", case.app_expect, received);

    const echo = try conn.?.send(received, &out);
    rec.op("send");
    rec.hexArg("in", received);
    rec.hexArg("out", echo);
    rec.end();
    try sock.send(io, &peer_addr, echo);

    // The peer exits 0 only after `wolfSSL_get_verify_result` returned
    // X509_V_OK (certificate modes) and the echo came back — so a non-zero
    // status here means the chain we presented was not accepted, not merely
    // that the socket closed. The peer's exit status is the peer's verdict;
    // it is recorded as a note because the replay has no peer to ask.
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) {
            std.debug.print("  peer exited {d}, not 0\n", .{code});
            return error.PeerRejectedUs;
        },
        else => return error.PeerDiedAbnormally,
    }
    rec.note("peer exited 0 (not replayable): it accepted our side and, in certificate mode, X509_V_OK'd our chain", .{});
}

// ── the transcript header ─────────────────────────────────────────────────

fn utcDate(buf: []u8) []const u8 {
    var ts: std.os.linux.timespec = undefined;
    if (std.os.linux.clock_gettime(.REALTIME, &ts) != 0) return "unknown";
    const secs: u64 = @intCast(ts.sec);
    const epoch_day = std.time.epoch.EpochSeconds{ .secs = secs };
    const day = epoch_day.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{
        day.year,
        md.month.numeric(),
        md.day_index + 1,
    }) catch "unknown";
}

fn writeHeader(w: *std.Io.Writer, wolfssl_version: []const u8) !void {
    var date_buf: [16]u8 = undefined;
    try w.print(
        \\# dtls ↔ wolfSSL DTLS 1.3 transcript — a RECORDING, not a specification.
        \\#
        \\# Every byte below was taken off a real loopback UDP socket between this
        \\# module and wolfSSL. `modules/dtls/tools/interop.zig` wrote it;
        \\# `modules/dtls/src/wolfssl_replay.zig` replays it with no wolfSSL and no C
        \\# compiler in sight, which is where the anchor's value now lives. Re-taking it
        \\# needs `libwolfssl-dev` and a C compiler:
        \\#
        \\#     wolfSSL:  {s}
        \\#     captured: {s}
        \\#     command:  zig build interop-dtls -- --capture
        \\#
        \\# WHAT PINS IT. Our side draws every random byte from `Entropy`, and these
        \\# runs use its `.seeded_for_test` arm with the fixed seed each case records.
        \\# That is the module's own seam, already there before this file existed — no
        \\# check was weakened and nothing was stubbed to make the replay deterministic.
        \\# Given the same seed and the same inbound datagrams, our ClientHello, our
        \\# ECDHE key, our signatures and our records are the same bytes every time, so
        \\# the peer's recorded answers still verify against our recomputed transcript.
        \\#
        \\# WHAT IT CANNOT DO. Nothing here can discover a NEW divergence: the peer's
        \\# bytes are frozen, so a change that makes us emit different-but-still-valid
        \\# bytes fails the replay without a real peer having refused anything, and a
        \\# change a newer wolfSSL would refuse passes it. A replay failure is a
        \\# summons to re-run `zig build interop-dtls`, not a verdict.
        \\#
        \\# FORMAT. One operation per line; `#` is a comment; hex is lowercase and an
        \\# empty value is an empty byte string. `case <name>` opens a case, `why` is
        \\# prose, `config` carries what the connection was built with, and then:
        \\#
        \\#   client_init / server_init [binding=<hex>]  build the Connection
        \\#   drop_conn                                  destroy it (stateless-cookie proof)
        \\#   start out=<hex>                            startHandshake must return exactly this
        \\#   flight in=<hex> out=<hex> more=<0|1>       handleFlight(in) must return exactly this
        \\#   send in=<hex> out=<hex>                    send(in) must return exactly this
        \\#   recv in=<hex> out=<hex>                    recv(in) must return exactly this plaintext
        \\#   recv in=<hex> skip=<Error>                 recv(in) must fail with exactly this error
        \\#   expect hrr=<0|1> group=<hex4> [...]        the connection's own view, after the handshake
        \\#
        \\format version=1
        \\
        \\
    , .{ wolfssl_version, utcDate(&date_buf) });
}

// ── main ──────────────────────────────────────────────────────────────────

const usage =
    \\dtls live interop against wolfSSL.
    \\
    \\  zig build interop-dtls                  run every case live
    \\  zig build interop-dtls -- --capture     ...and rewrite the committed transcript
    \\  zig build interop-dtls -- --case NAME   run one case (repeatable)
    \\  zig build interop-dtls -- --list        list the case names
    \\  zig build interop-dtls -- --repo-root P read wolfssl_peer.c and the fixtures from P
    \\
    \\Needs a C compiler and libwolfssl-dev. The hermetic half of this — replaying
    \\what a capture recorded — is `zig build test-dtls` and needs neither.
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    // An arena over it: this program is a fixed number of short runs and then
    // it exits, and the alternative is threading `free` through every
    // early-return diagnosis path — where a forgotten one turns a real interop
    // failure into a leak report printed on top of it.
    var arena: std.heap.ArenaAllocator = .init(da.allocator());
    defer arena.deinit();
    const gpa = arena.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var env_map: std.process.Environ.Map = .init(gpa);
    try env_map.putPosixBlock(init.environ.block.view());
    child_env = &env_map;

    var capture = false;
    var repo_root: []const u8 = ".";
    var selected: [cases.len][]const u8 = undefined;
    var selected_len: usize = 0;

    var args = init.args.iterate();
    _ = args.next(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--capture")) {
            capture = true;
        } else if (std.mem.eql(u8, arg, "--list")) {
            for (cases) |c| std.debug.print("{s}\t{s}\n", .{ c.name, c.why });
            return 0;
        } else if (std.mem.eql(u8, arg, "--case")) {
            const name = args.next() orelse {
                std.debug.print("--case needs a name\n{s}", .{usage});
                return 2;
            };
            if (selected_len == selected.len) return 2;
            selected[selected_len] = name;
            selected_len += 1;
        } else if (std.mem.eql(u8, arg, "--repo-root")) {
            repo_root = args.next() orelse {
                std.debug.print("--repo-root needs a path\n{s}", .{usage});
                return 2;
            };
        } else {
            std.debug.print("unknown argument \"{s}\"\n{s}", .{ arg, usage });
            return 2;
        }
    }

    var root = std.Io.Dir.cwd().openDir(io, repo_root, .{}) catch {
        std.debug.print("cannot open repository root \"{s}\"\n", .{repo_root});
        return 2;
    };
    defer root.close(io);

    var fx = Fixtures.load(gpa, io, root) catch return 2;

    // Scratch in `.zig-cache/`, never `/tmp`: the compiled peer and the DER the
    // peer reads are both reproducible by a rebuild, which is exactly what that
    // directory is for.
    var work = root.createDirPathOpen(io, scratch_dir, .{}) catch |err| {
        std.debug.print("cannot create {s}: {t}\n", .{ scratch_dir, err });
        return 2;
    };
    defer work.close(io);

    buildPeer(gpa, io, root, work) catch return 1;
    try fx.writeForPeer(io, work);
    const version = readPeerVersion(gpa, io, work);

    var transcript: std.Io.Writer.Allocating = .init(gpa);
    defer transcript.deinit();
    var rec: Recorder = .{ .enabled = capture, .out = &transcript.writer };
    if (capture) try writeHeader(&transcript.writer, version);

    // A capture of a SUBSET would silently truncate the committed file into
    // something that still looks complete, so the two are refused together.
    if (capture and selected_len > 0) {
        std.debug.print("--capture rewrites the whole transcript; it cannot be combined with --case\n", .{});
        return 2;
    }

    var ran: usize = 0;
    var failed: usize = 0;
    for (cases) |case| {
        if (selected_len > 0) {
            var wanted = false;
            for (selected[0..selected_len]) |name| {
                if (std.mem.eql(u8, name, case.name)) wanted = true;
            }
            if (!wanted) continue;
        }

        std.debug.print("{s} ... ", .{case.name});
        // Marked BEFORE the case header goes in, so a failure rolls back the
        // header too rather than leaving a case with no body.
        const mark = transcript.written().len;
        rec.raw("case {s}\n", .{case.name});
        rec.raw("why {s}\n", .{case.why});
        const result = switch (case.flow) {
            .client => runClientFlow(gpa, io, work, case, &fx, &rec),
            .server, .server_cookie => runServerFlow(gpa, io, work, case, &fx, &rec),
        };
        ran += 1;
        if (result) {
            std.debug.print("ok\n", .{});
            rec.raw("\n", .{});
        } else |err| {
            std.debug.print("FAILED ({t})\n", .{err});
            failed += 1;
            // A half-written case must not reach the committed file: it would
            // be a fixture recording a run that did not work.
            transcript.shrinkRetainingCapacity(mark);
        }
    }

    if (ran == 0) {
        std.debug.print("no case matched\n{s}", .{usage});
        return 2;
    }
    std.debug.print("\n{d}/{d} cases passed against wolfSSL {s}\n", .{ ran - failed, ran, version });

    if (capture) {
        if (failed > 0) {
            std.debug.print("NOT writing the transcript: {d} case(s) failed\n", .{failed});
            return 1;
        }
        try root.writeFile(io, .{ .sub_path = transcript_path, .data = transcript.written() });
        std.debug.print("wrote {s} ({d} bytes)\n", .{ transcript_path, transcript.written().len });
    }
    return if (failed > 0) 1 else 0;
}
