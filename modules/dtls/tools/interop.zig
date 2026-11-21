// SPDX-License-Identifier: MIT

//! LIVE third-party-peer interop for `dtls`: this module's DTLS 1.3 handshakes
//! — and, since 2026-11-17, its DTLS 1.2 ones (`cases12`, recorded into a
//! transcript of their own) — against **wolfSSL**, over a real loopback UDP
//! socket, and the recorder that turns each of those exchanges into a
//! committed transcript the module can replay with no wolfSSL and no C
//! compiler anywhere near it.
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
//!     zig build interop-dtls -- --capture --version 12   # only the 1.2 recording
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
const rsa = @import("rsa");
const net = std.Io.net;

const x25519_group: u16 = @backingInt(dtls.messages.NamedGroup.x25519);
const secp256r1_group: u16 = @backingInt(dtls.messages.NamedGroup.secp256r1);
const x25519_mlkem768_group: u16 = @backingInt(dtls.messages.NamedGroup.x25519_ml_kem768);

/// Test fixtures — duplicated verbatim in `wolfssl_peer.c`. Test material
/// only; nothing here is a default for anything.
const psk = @as([16]u8, @splat(0x0b));
const psk_identity = "zig-libs-dtls";

/// The PSK of the `-aes256` cases: 48 bytes, the length of a SHA-384 output,
/// which is what a `TLS13-AES256-GCM-SHA384` PSK is sized for. Duplicated
/// verbatim in `wolfssl_peer.c` (`kPsk384`). Test material.
const psk384 = @as([48]u8, @splat(0x0c));

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

/// A post-handshake KeyUpdate round after the first echo (client flow only).
const KeyUpdate = enum {
    none,
    /// Our side sends it (`update_requested`); wolfSSL must ACK, answer with its own, and speak under the new keys.
    ours,
    /// wolfSSL sends it (`wolfSSL_update_keys`) and then a message under the new keys.
    theirs,
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
    /// ALPN names our side offers (client) or accepts, in preference order (server).
    alpn: []const []const u8 = &.{},
    /// What `negotiatedAlpn()` must report on our side.
    expect_alpn: ?[]const u8 = null,
    /// The name the peer must print on its `ALPN <name>` line (client flow).
    expect_peer_alpn: ?[]const u8 = null,
    key_update: KeyUpdate = .none,
    /// Run the PSK handshake under `TLS13-AES256-GCM-SHA384` with `psk384`
    /// instead of `TLS13-AES128-GCM-SHA256` with `psk` (PSK cases only).
    sha384: bool = false,
    /// Ask for a connection ID (`zig_cid`); the peer asks for `wolf_cid`.
    cid: bool = false,
    /// One line of prose, copied into the transcript, saying what THIS case
    /// proves that no other one does.
    why: []const u8,
};

/// The connection IDs of the CID cases (RFC 9146, RFC 9147 section 9):
/// duplicated in `tools/wolfssl_peer.c`.
const zig_cid = "zig-libs-cid";
const wolf_cid = "wolf-cid-1";

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
        .name = "psk-client-alpn",
        .flow = .client,
        .peer_mode = "server-alpn",
        .seed = 0x2c,
        .alpn = &.{ "h3", "coap" },
        .expect_alpn = "coap",
        .expect_peer_alpn = "coap",
        .app_send = "hello from zig-libs",
        .app_expect = "hello from zig-libs",
        .why = "ALPN (RFC 7301) against a live server: our ClientHello offers h3 and coap, wolfSSL (which accepts only coap) answers in EncryptedExtensions, and both sides name the same protocol",
    },
    .{
        .name = "psk-server-alpn",
        .flow = .server,
        .peer_mode = "client-alpn",
        .seed = 0x5b,
        .alpn = &.{ "coap", "h3" },
        .expect_alpn = "coap",
        .app_expect = "hello from wolfssl client",
        .why = "ALPN in the other role: wolfSSL offers h3 and coap, OUR server picks its first preference (coap) and the peer exits 0 only if the EncryptedExtensions it parsed name coap",
    },
    .{
        .name = "psk-client-keyupdate-ours",
        .flow = .client,
        .peer_mode = "server-ku-ours",
        .seed = 0x2c,
        .key_update = .ours,
        .app_send = "hello from zig-libs",
        .app_expect = "hello from zig-libs",
        .why = "OUR KeyUpdate (update_requested) against a live peer: wolfSSL ACKs it, answers with its own, and the data after the update is exchanged under epoch-4 keys in both directions",
    },
    .{
        .name = "psk-client-keyupdate-theirs",
        .flow = .client,
        .peer_mode = "server-ku-theirs",
        .seed = 0x2c,
        .key_update = .theirs,
        .app_send = "hello from zig-libs",
        .app_expect = "hello from zig-libs",
        .why = "wolfSSL's KeyUpdate (wolfSSL_update_keys) reaches OUR engine: recv reports ReceivedKeyUpdate, our ACK (and answering update when requested) is accepted, and the message wolfSSL sends under its new keys decrypts",
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
        .name = "psk-client-aes256",
        .flow = .client,
        .peer_mode = "server-aes256",
        .seed = 0x2c,
        .sha384 = true,
        .app_send = "hello from zig-libs",
        .app_expect = "hello from zig-libs",
        .why = "AES-256-GCM-SHA384 with a SHA-384 PSK against a live server: the binder, the key schedule and the Finished MACs run over SHA-384 and the records under AES-256-GCM, all checked by foreign code",
    },
    .{
        .name = "psk-client-aes256-hrr",
        .flow = .client,
        .peer_mode = "server-aes256-hrr",
        .seed = 0x2c,
        .sha384 = true,
        .expect_hrr = true,
        .app_send = "hello from zig-libs",
        .app_expect = "hello from zig-libs",
        .why = "the HelloRetryRequest cookie of a SHA-384 suite from a DEFAULT wolfSSL server: the message_hash rewrite of ClientHello1 is hashed with SHA-384 and the binder of ClientHello2 covers that transcript",
    },
    .{
        .name = "psk-server-aes256",
        .flow = .server,
        .peer_mode = "client-aes256",
        .seed = 0x5b,
        .sha384 = true,
        .app_expect = "hello from wolfssl client",
        .why = "a real wolfSSL client with a SHA-384 PSK accepts what OUR server puts on the wire under AES-256-GCM-SHA384",
    },
    .{
        .name = "psk-server-cookie-aes256",
        .flow = .server_cookie,
        .peer_mode = "client-aes256",
        .seed = 0x6e,
        .sha384 = true,
        .expect_hrr = true,
        .app_expect = "hello from wolfssl client",
        .why = "the HelloRetryRequest WE emit under a SHA-384 suite: the stateless cookie (83 bytes: version, suite, 48-byte ClientHello1 hash, MAC) is accepted by a stock client and a BRAND-NEW connection re-derives the SHA-384 transcript from it alone",
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
    .{
        .name = "psk-client-cid",
        .flow = .client,
        .peer_mode = "server-cid",
        .seed = 0x2c,
        .cid = true,
        .app_send = "hello from zig-libs",
        .app_expect = "hello from zig-libs",
        .why = "DTLS 1.3 connection ID (RFC 9147 section 9) against a live server: both sides ask for one in the hellos, our records carry wolfSSL's CID in the unified header and wolfSSL's carry ours",
    },
    .{
        .name = "psk-server-cid",
        .flow = .server,
        .peer_mode = "client-cid",
        .seed = 0x5b,
        .cid = true,
        .app_expect = "hello from wolfssl client",
        .why = "the connection ID with OUR server answering a wolfSSL client's connection_id in the ServerHello",
    },
    .{
        .name = "psk-server-keyupdate-theirs",
        .flow = .server,
        .peer_mode = "client-ku-theirs",
        .seed = 0x5b,
        .key_update = .theirs,
        .app_expect = "hello from wolfssl client",
        .why = "a wolfSSL CLIENT's KeyUpdate against OUR server: recv reports ReceivedKeyUpdate, our ACK (and our answering update) goes out, the message under its new keys decrypts and our echo is what it reads back",
    },
    .{
        .name = "cert-client-alpn",
        .flow = .client,
        .peer_mode = "server-cert-alpn",
        .seed = 0x3d,
        .cert_mode = true,
        .alpn = &.{ "h3", "coap" },
        .expect_alpn = "coap",
        .expect_peer_alpn = "coap",
        .app_send = "hello from zig-libs, certificate mode",
        .app_expect = "hello from zig-libs, certificate mode",
        .why = "ALPN in certificate mode: the name rides in the EncryptedExtensions of a certificate flight (X25519 + ECDSA P-256), and both sides name coap",
    },
    .{
        .name = "cert-client-keyupdate-ours",
        .flow = .client,
        .peer_mode = "server-cert-ku-ours",
        .seed = 0x3d,
        .cert_mode = true,
        .key_update = .ours,
        .app_send = "hello from zig-libs, certificate mode",
        .app_expect = "hello from zig-libs, certificate mode",
        .why = "OUR KeyUpdate after a certificate handshake (traffic secrets from the (EC)DHE schedule, not a PSK): wolfSSL ACKs, answers with its own, and the data after it moves under epoch-4 keys both ways",
    },
    .{
        .name = "cert-client-keyupdate-theirs",
        .flow = .client,
        .peer_mode = "server-cert-ku-theirs",
        .seed = 0x3d,
        .cert_mode = true,
        .key_update = .theirs,
        .app_send = "hello from zig-libs, certificate mode",
        .app_expect = "hello from zig-libs, certificate mode",
        .why = "wolfSSL's KeyUpdate after a certificate handshake reaches OUR client engine and its message under the new keys decrypts",
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
    rsa12_cert_der: []u8,
    rsa12_key_der: []u8,
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
    rsa12_chain: [1][]const u8 = undefined,

    fn load(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir) !Fixtures {
        var fx: Fixtures = .{
            .anchor_cert_der = try read(gpa, io, root, "anchor-cert.der"),
            .server_cert_der = try read(gpa, io, root, "server-cert.der"),
            .server_secret_key_bytes = try read(gpa, io, root, "server-key.bin"),
            .client_cert_der = try read(gpa, io, root, "client-cert.der"),
            .client_secret_key_bytes = try read(gpa, io, root, "client-key.bin"),
            .rsa12_cert_der = try read(gpa, io, root, "rsa12-cert.der"),
            .rsa12_key_der = try read(gpa, io, root, "rsa12-key.der"),
        };
        fx.server_chain = .{fx.server_cert_der};
        fx.client_chain = .{fx.client_cert_der};
        fx.rsa12_chain = .{fx.rsa12_cert_der};
        return fx;
    }

    fn read(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir, name: []const u8) ![]u8 {
        var buf: [256]u8 = undefined;
        const path = std.mem.print(&buf, "{s}/{s}", .{ certs_dir, name }) catch unreachable;
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

    // `certverify.SecretKey` borrows its key: the storage must outlive the
    // `Config` built from it, so it lives at container level.
    var client_sk: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;
    var server_sk: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey = undefined;

    fn clientKey(self: *const Fixtures) certverify.SecretKey {
        const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        client_sk = P256.SecretKey.fromBytes(scalar32(self.client_secret_key_bytes)) catch unreachable;
        return .{ .ecdsa_p256 = &client_sk };
    }

    fn serverKey(self: *const Fixtures) certverify.SecretKey {
        const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        server_sk = P256.SecretKey.fromBytes(scalar32(self.server_secret_key_bytes)) catch unreachable;
        return .{ .ecdsa_p256 = &server_sk };
    }

    /// SEC1 `ECPrivateKey` DER (RFC 5915) for the fixture P-256 leaf, built
    /// here from the ONE piece of key material this repo stores (a raw 32-byte
    /// scalar) rather than committed as a second encoded copy: the public
    /// point is recomputed from the scalar, so the key wolfSSL signs with
    /// cannot silently drift from the certificate the Zig side verifies
    /// against.
    var rsa12_sk: rsa.SecretKey = undefined;

    fn rsa12Key(self: *const Fixtures) certverify.SecretKey {
        rsa.SecretKey.fromDer(&rsa12_sk, self.rsa12_key_der) catch unreachable;
        return .{ .rsa = &rsa12_sk };
    }

    /// `keySec1Der` of the server leaf's scalar.
    fn serverKeySec1Der(self: *const Fixtures) [121]u8 {
        return keySec1Der(self.server_secret_key_bytes);
    }

    fn keySec1Der(scalar: []const u8) [121]u8 {
        const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        const sk = P256.SecretKey.fromBytes(scalar32(scalar)) catch unreachable;
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
        put(&out, &i, scalar[0..32]);
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
        // The DTLS 1.2 modes: a wolfSSL client presenting the fixture CLIENT
        // certificate, and the RSA identity for ECDHE_RSA.
        try dir.writeFile(io, .{ .sub_path = "client-cert.der", .data = self.client_cert_der });
        const ckey = keySec1Der(self.client_secret_key_bytes);
        try dir.writeFile(io, .{ .sub_path = "client-key.der", .data = &ckey });
        try dir.writeFile(io, .{ .sub_path = "rsa12-cert.der", .data = self.rsa12_cert_der });
        try dir.writeFile(io, .{ .sub_path = "rsa12-key.der", .data = self.rsa12_key_der });
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

fn casePsk(case: Case) []const u8 {
    return if (case.sha384) &psk384 else &psk;
}

fn caseSuites(case: Case) []const dtls.CipherSuite {
    return if (case.sha384) &.{.aes_256_gcm_sha384} else &.{.aes_128_gcm_sha256};
}

fn clientConfig(case: Case, fx: *const Fixtures) dtls.Config {
    var c = clientConfigBase(case, fx);
    if (case.cid) c.connection_id = zig_cid;
    return c;
}

fn serverConfig(case: Case, fx: *const Fixtures, binding: ?[]const u8) dtls.Config {
    var c = serverConfigBase(case, fx, binding);
    if (case.cid) c.connection_id = zig_cid;
    return c;
}

fn clientConfigBase(case: Case, fx: *const Fixtures) dtls.Config {
    if (!case.cert_mode) return .{
        .role = .client,
        .psk_identity = psk_identity,
        .psk = casePsk(case),
        .psk_hash = if (case.sha384) .sha384 else .sha256,
        .cipher_suites = caseSuites(case),
        .alpn_protocols = case.alpn,
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
        .key_share_group = @fromBackingInt(@intCast(case.offer_group)),
        .alpn_protocols = case.alpn,
    };
}

fn serverConfigBase(case: Case, fx: *const Fixtures, binding: ?[]const u8) dtls.Config {
    if (!case.cert_mode) return .{
        .role = .server,
        .psk_identity = psk_identity,
        .psk = casePsk(case),
        .psk_hash = if (case.sha384) .sha384 else .sha256,
        .cipher_suites = caseSuites(case),
        .hello_retry = if (binding) |b|
            .{ .cookie_secret = cookie_secret, .peer_binding = b }
        else
            null,
        .alpn_protocols = case.alpn,
    };
    return .{
        .role = .server,
        .key_exchange = .cert_dhe,
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .cert = .{
            .chain = &fx.server_chain,
            .private_key = fx.serverKey(),
        },
        .alpn_protocols = case.alpn,
    };
}

/// The ALPN names as the `config` line writes them: comma-separated, `-` for none.
fn joinAlpn(buf: []u8, names: []const []const u8) []const u8 {
    if (names.len == 0) return "-";
    var n: usize = 0;
    for (names, 0..) |name, i| {
        if (i > 0) {
            buf[n] = ',';
            n += 1;
        }
        @memcpy(buf[n..][0..name.len], name);
        n += name.len;
    }
    return buf[0..n];
}

/// The `config` line the replay reads back. Written from the same `Case` the
/// live run used, so "what the transcript says we configured" and "what we
/// configured" are one statement, not two.
fn recordConfig(rec: *Recorder, case: Case, seed: [32]u8) void {
    rec.op("config");
    rec.strArg("flow", @tagName(case.flow));
    rec.strArg("key_exchange", if (case.cert_mode) "cert_dhe" else "psk");
    rec.hexArg("seed", &seed);
    rec.strArg("suite", @tagName(caseSuites(case)[0]));
    rec.numArg("now_sec", valid_now_sec);
    rec.hex4Arg("offer_group", case.offer_group);
    rec.numArg("client_cert", @intFromBool(case.client_cert));
    var alpn_buf: [64]u8 = undefined;
    rec.strArg("alpn", joinAlpn(&alpn_buf, case.alpn));
    if (!case.cert_mode) {
        rec.hexArg("psk_identity", psk_identity);
        rec.hexArg("psk", casePsk(case));
        rec.hexArg("cookie_secret", cookie_secret);
    }
    if (case.cid) rec.hexArg("cid", zig_cid);
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
    const port_str = try std.mem.print(&port_buf, "{d}", .{port});
    var mtu_buf: [8]u8 = undefined;
    const mtu_str = try std.mem.print(&mtu_buf, "{d}", .{case.mtu});

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
    // `kill` and not `wait`: a case that fails leaves the peer blocked in its
    // read, and a plain `wait` would then hang the whole run behind the very
    // error that should have been reported. A no-op once the peer has exited.
    defer child.kill(io);

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

    const seed = @as([32]u8, @splat(case.seed));
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
    try expectU16("negotiated suite", @backingInt(caseSuites(case)[0]), @backingInt(conn.suite));
    if (case.cid) try expectBytes("the CID our records carry", wolf_cid, conn.peerConnectionId() orelse "");
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
    if (case.expect_alpn) |want| {
        try expectBytes("negotiated ALPN", want, conn.negotiatedAlpn() orelse "");
        rec.strArg("alpn", want);
    }
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
    const echoed = try recvApplicationData(io, sock, &conn, &rx, &plain, rec, null);
    try expectBytes("echoed application data", case.app_expect, echoed);

    switch (case.key_update) {
        .none => {},
        .ours => try keyUpdateOurs(io, sock, &server_addr, &conn, &out, &rx, &plain, rec),
        .theirs => try keyUpdateTheirs(io, sock, &server_addr, &conn, &out, &rx, &plain, rec),
    }

    // The peer's own `ALPN <name>` line, a NOTE like the certificate subject
    // below: the peer's stdout is not bytes on the wire.
    if (case.expect_peer_alpn) |want| {
        var lines: usize = 0;
        const found = while (lines < 6) : (lines += 1) {
            const line = peerLine(&stdout_reader.interface) catch break false;
            if (std.mem.startsWith(u8, line, "ALPN ")) {
                if (!std.mem.eql(u8, line["ALPN ".len..], want)) {
                    std.debug.print("  peer reported \"{s}\", not ALPN {s}\n", .{ line, want });
                    return error.WrongPeerAlpn;
                }
                rec.note("peer stdout (not replayable): {s}", .{line});
                break true;
            }
        } else false;
        if (!found) return error.PeerNeverReportedAlpn;
    }

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
                if (std.mem.find(u8, line, want) == null) {
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

/// What a KeyUpdate case needs to answer a peer's KeyUpdate: where to send, a
/// buffer, the caller-supplied clock `poll` takes, and a count of the control
/// records sent (an ACK alone is one, an ACK plus our own update is two).
const Flusher = struct {
    peer: *const net.IpAddress,
    out: []u8,
    now: *u64,
    emitted: *usize,
};

/// Drains `poll` (one record per call) onto the wire and records every call,
/// ending with the call that returned `null`. `now` is a fake clock that moves
/// 10 ms per flush: only the retransmit timer reads it.
fn flushPoll(io: std.Io, sock: net.Socket, conn: *Connection, rec: *Recorder, fl: Flusher) !void {
    while (try conn.poll(fl.now.*, fl.out)) |bytes| {
        rec.op("poll");
        rec.numArg("now", fl.now.*);
        rec.hexArg("out", bytes);
        rec.end();
        try sock.send(io, fl.peer, bytes);
        fl.emitted.* += 1;
    }
    rec.op("poll_idle");
    rec.numArg("now", fl.now.*);
    rec.end();
    fl.now.* += 10;
}

/// One datagram that must be a post-handshake control record (an ACK, a
/// KeyUpdate, a ticket); a KeyUpdate is answered at once.
fn recvControl(io: std.Io, sock: net.Socket, conn: *Connection, rx: []u8, plain: []u8, rec: *Recorder, fl: Flusher) !void {
    const incoming = try sock.receiveTimeout(io, rx, deadline(io, 10_000));
    if (conn.recv(incoming.data, plain)) |_| {
        return error.UnexpectedApplicationData;
    } else |err| switch (err) {
        error.ReceivedAck, error.ReceivedPostHandshakeMessage, error.ReceivedKeyUpdate => {
            rec.op("recv");
            rec.hexArg("in", incoming.data);
            rec.strArg("skip", @errorName(err));
            rec.end();
            if (err == error.ReceivedKeyUpdate) try flushPoll(io, sock, conn, rec, fl);
        },
        else => return err,
    }
}

fn recordEpochs(rec: *Recorder, conn: *const Connection) void {
    rec.op("expect_epochs");
    rec.numArg("write", conn.write_epoch);
    rec.numArg("read", conn.read_epoch);
    rec.end();
}

/// Our KeyUpdate against a live peer. Both epochs must advance exactly once:
/// the write one when wolfSSL's ACK names our KeyUpdate record, the read one
/// when wolfSSL answers `update_requested` with its own update.
fn keyUpdateOurs(io: std.Io, sock: net.Socket, peer: *const net.IpAddress, conn: *Connection, out: []u8, rx: []u8, plain: []u8, rec: *Recorder) !void {
    const epoch0 = conn.write_epoch;
    var now: u64 = 1000;
    var emitted: usize = 0;
    const fl: Flusher = .{ .peer = peer, .out = out, .now = &now, .emitted = &emitted };
    try conn.requestKeyUpdate(true);
    rec.op("request_key_update");
    rec.numArg("peer", 1);
    rec.end();
    try flushPoll(io, sock, conn, rec, fl);
    // The first poll may also owe the ACK for wolfSSL's NewSessionTicket, which
    // `recv` skipped earlier, so the count is at least one, not exactly one.
    if (emitted < 1) return error.KeyUpdateNotEmitted;

    var datagrams: usize = 0;
    while ((conn.write_epoch == epoch0 or conn.read_epoch == epoch0) and datagrams < 8) : (datagrams += 1) {
        try recvControl(io, sock, conn, rx, plain, rec, fl);
    }
    if (conn.write_epoch != epoch0 + 1) return error.OurKeyUpdateWasNotAcknowledged;
    if (conn.read_epoch != epoch0 + 1) return error.PeerDidNotAnswerWithItsOwnKeyUpdate;
    recordEpochs(rec, conn);

    const msg = "after our keyupdate";
    const record = try conn.send(msg, out);
    rec.op("send");
    rec.hexArg("in", msg);
    rec.hexArg("out", record);
    rec.end();
    try sock.send(io, peer, record);
    const echoed = try recvApplicationData(io, sock, conn, rx, plain, rec, fl);
    try expectBytes("echo under the updated keys", msg, echoed);
}

/// wolfSSL's KeyUpdate against our engine: it arrives as `ReceivedKeyUpdate`,
/// the ACK goes out, and the message wolfSSL then sends under its new keys
/// decrypts. If wolfSSL asked for an update in return (two control records
/// flushed), the wait for its ACK is part of the case.
fn keyUpdateTheirs(io: std.Io, sock: net.Socket, peer: *const net.IpAddress, conn: *Connection, out: []u8, rx: []u8, plain: []u8, rec: *Recorder) !void {
    const epoch0 = conn.read_epoch;
    var now: u64 = 1000;
    var emitted: usize = 0;
    const fl: Flusher = .{ .peer = peer, .out = out, .now = &now, .emitted = &emitted };
    const note = try recvApplicationData(io, sock, conn, rx, plain, rec, fl);
    try expectBytes("message under wolfSSL's updated keys", "wolfssl after its keyupdate", note);
    if (emitted == 0) return error.NoKeyUpdateWasReceived;
    if (conn.read_epoch != epoch0 + 1) return error.PeerKeyUpdateNotApplied;
    var datagrams: usize = 0;
    while (emitted >= 2 and conn.write_epoch == epoch0 and datagrams < 8) : (datagrams += 1) {
        try recvControl(io, sock, conn, rx, plain, rec, fl);
    }
    recordEpochs(rec, conn);

    const msg = "after wolfssl keyupdate";
    const record = try conn.send(msg, out);
    rec.op("send");
    rec.hexArg("in", msg);
    rec.hexArg("out", record);
    rec.end();
    try sock.send(io, peer, record);
    const echoed = try recvApplicationData(io, sock, conn, rx, plain, rec, fl);
    try expectBytes("echo after wolfSSL's KeyUpdate", msg, echoed);
}

/// A wolfSSL CLIENT's KeyUpdate against our server: as `keyUpdateTheirs`, then
/// the message it sent under its new keys is echoed back, and the peer exits
/// 0 only if the echo is that message.
fn keyUpdateTheirsServer(io: std.Io, sock: net.Socket, peer: *const net.IpAddress, conn: *Connection, out: []u8, rx: []u8, plain: []u8, rec: *Recorder) !void {
    const epoch0 = conn.read_epoch;
    var now: u64 = 1000;
    var emitted: usize = 0;
    const fl: Flusher = .{ .peer = peer, .out = out, .now = &now, .emitted = &emitted };
    const got = try recvApplicationData(io, sock, conn, rx, plain, rec, fl);
    try expectBytes("message under wolfSSL's updated keys", "wolfssl after its keyupdate", got);
    // Copied out: `recvControl` below decrypts into the same buffer.
    var note_buf: [64]u8 = undefined;
    @memcpy(note_buf[0..got.len], got);
    const note = note_buf[0..got.len];
    if (emitted == 0) return error.NoKeyUpdateWasReceived;
    if (conn.read_epoch != epoch0 + 1) return error.PeerKeyUpdateNotApplied;
    var datagrams: usize = 0;
    while (emitted >= 2 and conn.write_epoch == epoch0 and datagrams < 8) : (datagrams += 1) {
        try recvControl(io, sock, conn, rx, plain, rec, fl);
    }
    recordEpochs(rec, conn);
    const record = try conn.send(note_buf[0..note.len], out);
    rec.op("send");
    rec.hexArg("in", note_buf[0..note.len]);
    rec.hexArg("out", record);
    rec.end();
    try sock.send(io, peer, record);
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
    fl: ?Flusher,
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
            // A peer KeyUpdate: the read key moved, and `poll` now owes the
            // peer an ACK (and our own update when it asked for one). Only the
            // KeyUpdate cases pass a `Flusher`; for every other case a
            // KeyUpdate is an error, as before.
            error.ReceivedKeyUpdate => if (fl) |f| {
                rec.op("recv");
                rec.hexArg("in", incoming.data);
                rec.strArg("skip", @errorName(err));
                rec.end();
                try flushPoll(io, sock, conn, rec, f);
                skipped += 1;
                continue;
            } else return err,
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
    const port_str = try std.mem.print(&port_buf, "{d}", .{sock.address.getPort()});

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

    const seed = @as([32]u8, @splat(case.seed));
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
                try std.mem.print(&binding_buf, "{f}", .{incoming.from})
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
    try expectU16("negotiated suite", @backingInt(caseSuites(case)[0]), @backingInt(conn.?.suite));
    if (case.cid) try expectBytes("the CID our records carry", wolf_cid, conn.?.peerConnectionId() orelse "");
    if (case.cert_mode) try expectU16("negotiated group", case.expect_group, conn.?.ecdhe_group);
    rec.op("expect");
    rec.numArg("hrr", @intFromBool(case.expect_hrr));
    rec.hex4Arg("group", conn.?.ecdhe_group);
    if (case.expect_alpn) |want| {
        try expectBytes("negotiated ALPN", want, conn.?.negotiatedAlpn() orelse "");
        rec.strArg("alpn", want);
    }
    if (cookie_mode) rec.numArg("min_retries", 1);
    rec.end();

    // The wolfSSL client sends first and expects its own message echoed.
    var plain: [2048]u8 = undefined;
    const received = try recvApplicationData(io, sock, &conn.?, &rx, &plain, rec, null);
    try expectBytes("received application data", case.app_expect, received);

    const echo = try conn.?.send(received, &out);
    rec.op("send");
    rec.hexArg("in", received);
    rec.hexArg("out", echo);
    rec.end();
    try sock.send(io, &peer_addr, echo);
    switch (case.key_update) {
        .none => {},
        .theirs => try keyUpdateTheirsServer(io, sock, &peer_addr, &conn.?, &out, &rx, &plain, rec),
        .ours => return error.UnsupportedCase,
    }

    // The peer exits 0 only after `wolfSSL_get_verify_result` returned
    // X509_V_OK (certificate modes) and the echo came back — so a non-zero
    // status here means the chain we presented was not accepted, not merely
    // that the socket closed. The peer's exit status is the peer's verdict;
    // it is recorded as a note because the replay has no peer to ask.
    var err_buf: [4096]u8 = undefined;
    var err_reader = child.stderr.?.reader(io, &err_buf);
    const peer_says = err_reader.interface.allocRemaining(gpa, .limited(4096)) catch "";
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) {
            std.debug.print("  peer exited {d}, not 0; it said: {s}\n", .{ code, peer_says });
            return error.PeerRejectedUs;
        },
        else => return error.PeerDiedAbnormally,
    }
    rec.note("peer exited 0 (not replayable): it accepted our side and, in certificate mode, X509_V_OK'd our chain", .{});
}

// ── DTLS 1.2 (RFC 6347): `Connection12` against `wolfDTLSv1_2_*_method` ────
//
// A table, two flows and a transcript of their own (`transcript12_path`), so
// that re-taking the 1.2 anchor does not rewrite the 1.3 one (whose bytes
// also feed `fuzz_corpus.zig`'s pinned counts) and vice versa.

const Connection12 = dtls.Connection12;
const CipherSuite12 = dtls.CipherSuite12;
const transcript12_path = "modules/dtls/src/testdata/wolfssl12_transcript.txt";

/// Every certificate case runs at this instant: inside both the ECDSA
/// (2026-07-21 ..) and the RSA (2026-11-13 ..) fixtures' validity.
const now12_sec: i64 = 1798761600; // 2027-01-01

/// The identity hint our 1.2 PSK server sends (RFC 4279 §2). Test material.
const psk12_hint = "zig-libs-hint";

const Kind12 = enum {
    /// ECDHE_PSK (RFC 5489) against wolfSSL; plain PSK against OpenSSL
    /// (Debian's wolfSSL has no static PSK).
    psk,
    /// ECDHE_ECDSA with the P-256 fixture chain.
    ecdsa,
    /// ECDHE_RSA with the self-signed RSA-2048 fixture.
    rsa,
};

/// Which foreign 1.2 stack a case runs against. OpenSSL covers what Debian's
/// wolfSSL cannot (it is built without static PSK): plain PSK, both roles.
const Peer12 = enum { wolfssl, openssl };

const Case12 = struct {
    name: []const u8,
    flow: Flow,
    peer: Peer12 = .wolfssl,
    peer_mode: []const u8,
    seed: u8,
    kind: Kind12,
    /// Non-zero: wolfSSL fragments what it sends to fit.
    peer_mtu: u16 = 0,
    /// Our `Config.max_datagram_len`: non-zero makes OUR side fragment.
    max_datagram: u16 = 0,
    /// Client flow: present the fixture client certificate. Server flow:
    /// request (and require) one.
    mutual: bool = false,
    expect_suite: CipherSuite12,
    expect_group: u16 = x25519_group,
    /// Client flow: wolfSSL's 1.2 server always runs the cookie exchange.
    expect_hvr: bool = false,
    /// RFC 9146: ask for `zig_cid`; the peer asks for `wolf_cid`. No case
    /// sets it: Debian's wolfSSL 5.9.1 negotiates the 1.2 connection ID but
    /// its client then fails `connect` with -320 (build message failure), and
    /// its server goes silent at our CID-protected Finished — the 1.2 form has
    /// no live wolfSSL peer (`12-*-cid` peer modes kept for a fixed build).
    cid: bool = false,
    expect_peer_cert_subject: ?[]const u8 = null,
    app_send: []const u8 = "hello from zig-libs over dtls 1.2",
    app_expect: []const u8 = "hello from zig-libs over dtls 1.2",
    why: []const u8,
};

const wolfssl12_client_hello = "hello from wolfssl 1.2 client";
/// What the OpenSSL peers send: `s_server` / `s_client` forward their stdin
/// line by line, newline included.
const openssl12_server_hello = "hello from openssl 1.2 server\n";
const openssl12_client_hello = "hello from openssl 1.2 client\n";

const cases12 = [_]Case12{
    .{
        .name = "dtls12-psk-client",
        .flow = .client,
        .peer_mode = "12-server-psk",
        .seed = 0x71,
        .kind = .psk,
        .expect_suite = .ecdhe_psk_with_chacha20_poly1305_sha256,
        .expect_hvr = true,
        .why = "ECDHE_PSK (RFC 5489) ChaCha20-Poly1305 against a live wolfSSL 1.2 server: its HelloVerifyRequest, its identity hint in ServerKeyExchange, the RFC 4279 premaster with a foreign ECDH share",
    },
    .{
        .name = "dtls12-psk-server",
        .flow = .server,
        .peer_mode = "12-client-psk",
        .seed = 0x72,
        .kind = .psk,
        .expect_suite = .ecdhe_psk_with_chacha20_poly1305_sha256,
        .app_expect = wolfssl12_client_hello,
        .why = "a wolfSSL 1.2 PSK client completes against OUR server's ServerKeyExchange (hint + ECDH params) and Finished",
    },
    .{
        .name = "dtls12-psk-server-cookie",
        .flow = .server_cookie,
        .peer_mode = "12-client-psk",
        .seed = 0x73,
        .kind = .psk,
        .expect_suite = .ecdhe_psk_with_chacha20_poly1305_sha256,
        .app_expect = wolfssl12_client_hello,
        .why = "OUR HelloVerifyRequest (RFC 6347 4.2.1) accepted by a stock client, the handshake finished by a BRAND-NEW server connection from the cookie alone",
    },
    .{
        .name = "dtls12-ecdsa-client",
        .flow = .client,
        .peer_mode = "12-server-ecdsa",
        .seed = 0x74,
        .kind = .ecdsa,
        .expect_suite = .ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .expect_hvr = true,
        .why = "ECDHE_ECDSA AES-128-GCM: wolfSSL's Certificate and signed ServerKeyExchange verified by us, our ClientKeyExchange and Finished by it",
    },
    .{
        .name = "dtls12-ecdsa-client-aes256",
        .flow = .client,
        .peer_mode = "12-server-ecdsa-aes256",
        .seed = 0x74,
        .kind = .ecdsa,
        .expect_suite = .ecdhe_ecdsa_with_aes_256_gcm_sha384,
        .expect_hvr = true,
        .why = "the SHA-384 suite: PRF, transcript hash and Finished over SHA-384 (RFC 5289), AES-256-GCM records",
    },
    .{
        .name = "dtls12-ecdsa-client-p256",
        .flow = .client,
        .peer_mode = "12-server-ecdsa-p256",
        .seed = 0x74,
        .kind = .ecdsa,
        .expect_suite = .ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .expect_group = secp256r1_group,
        .expect_hvr = true,
        .why = "a server that accepts only secp256r1 picks it from our supported_groups: our P-256 ECDHE against foreign code",
    },
    .{
        .name = "dtls12-ecdsa-client-mtu256",
        .flow = .client,
        .peer_mode = "12-server-ecdsa",
        .seed = 0x74,
        .kind = .ecdsa,
        .peer_mtu = 256,
        .expect_suite = .ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .expect_hvr = true,
        .why = "wolfSSL at a 256-byte MTU must fragment its Certificate: our 1.2 reassembly against a real fragmenter",
    },
    .{
        .name = "dtls12-ecdsa-client-mutual",
        .flow = .client,
        .peer_mode = "12-server-ecdsa-mutual",
        .seed = 0x74,
        .kind = .ecdsa,
        .mutual = true,
        .expect_suite = .ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .expect_hvr = true,
        .expect_peer_cert_subject = "dtls-test-client",
        .why = "mutual auth: wolfSSL (VERIFY_PEER|FAIL_IF_NO_PEER_CERT) parses our CertificateRequest answer and verifies OUR 1.2 CertificateVerify over the handshake messages",
    },
    .{
        .name = "dtls12-ecdsa-server",
        .flow = .server,
        .peer_mode = "12-client-ecdsa",
        .seed = 0x75,
        .kind = .ecdsa,
        .expect_suite = .ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .app_expect = wolfssl12_client_hello,
        .why = "a wolfSSL 1.2 client verifies OUR chain and signed ServerKeyExchange (it asserts X509_V_OK before exiting 0)",
    },
    .{
        .name = "dtls12-ecdsa-server-chacha",
        .flow = .server,
        .peer_mode = "12-client-ecdsa-chacha",
        .seed = 0x75,
        .kind = .ecdsa,
        .expect_suite = .ecdhe_ecdsa_with_chacha20_poly1305_sha256,
        .app_expect = wolfssl12_client_hello,
        .why = "a client offering only ECDHE-ECDSA-CHACHA20-POLY1305: our server's suite choice and the RFC 7905 record nonce",
    },
    .{
        .name = "dtls12-ecdsa-server-mutual",
        .flow = .server,
        .peer_mode = "12-client-ecdsa-mutual",
        .seed = 0x75,
        .kind = .ecdsa,
        .mutual = true,
        .expect_suite = .ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .app_expect = wolfssl12_client_hello,
        .why = "OUR CertificateRequest answered by a foreign client: its Certificate chained to our anchor and its CertificateVerify verified by us",
    },
    .{
        .name = "dtls12-rsa-client",
        .flow = .client,
        .peer_mode = "12-server-rsa",
        .seed = 0x76,
        .kind = .rsa,
        .expect_suite = .ecdhe_rsa_with_aes_128_gcm_sha256,
        .expect_hvr = true,
        .why = "ECDHE_RSA: wolfSSL's RSA signature over our randoms and its ECDH params, in the scheme it picked from our signature_algorithms",
    },
    .{
        .name = "dtls12-rsa-server",
        .flow = .server,
        .peer_mode = "12-client-rsa",
        .seed = 0x77,
        .kind = .rsa,
        .expect_suite = .ecdhe_rsa_with_aes_128_gcm_sha256,
        .app_expect = wolfssl12_client_hello,
        .why = "OUR RSA ServerKeyExchange signature verified by wolfSSL",
    },
    .{
        .name = "dtls12-ecdsa-server-frag",
        .flow = .server,
        .peer_mode = "12-client-ecdsa",
        .seed = 0x75,
        .kind = .ecdsa,
        .max_datagram = 200,
        .expect_suite = .ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .app_expect = wolfssl12_client_hello,
        .why = "OUR send-side fragmentation (Config.max_datagram_len = 200): the server flight leaves in several datagrams, the Certificate in fragments a real peer must reassemble",
    },
    .{
        .name = "dtls12-ecdsa-client-mutual-frag",
        .flow = .client,
        .peer_mode = "12-server-ecdsa-mutual",
        .seed = 0x74,
        .kind = .ecdsa,
        .mutual = true,
        .max_datagram = 200,
        .expect_suite = .ecdhe_ecdsa_with_aes_128_gcm_sha256,
        .expect_hvr = true,
        .expect_peer_cert_subject = "dtls-test-client",
        .why = "the client side of it: OUR Certificate and CertificateVerify flight in 200-byte datagrams, reassembled and verified by wolfSSL",
    },
    .{
        .name = "dtls12-plainpsk-client-openssl",
        .flow = .client,
        .peer = .openssl,
        .peer_mode = "",
        .seed = 0x78,
        .kind = .psk,
        .expect_suite = .psk_with_aes_128_gcm_sha256,
        .expect_group = 0,
        .expect_hvr = true,
        .app_send = "hello from zig-libs over dtls 1.2\n",
        .app_expect = openssl12_server_hello,
        .why = "plain PSK (RFC 4279 2, PSK-AES128-GCM-SHA256, no ECDHE) against a live OpenSSL s_server -listen: its stateless HelloVerifyRequest, the psk premaster of zeros || psk, EMS",
    },
    .{
        .name = "dtls12-plainpsk-server-openssl",
        .flow = .server,
        .peer = .openssl,
        .peer_mode = "",
        .seed = 0x79,
        .kind = .psk,
        .expect_suite = .psk_with_aes_128_gcm_sha256,
        .expect_group = 0,
        .app_expect = openssl12_client_hello,
        .why = "an OpenSSL s_client offering only PSK-AES128-GCM-SHA256 completes against OUR server: the identity hint in ServerKeyExchange, its identity in ClientKeyExchange, the plain-PSK premaster",
    },
};

const openssl_cipher12 = "PSK-AES128-GCM-SHA256";

fn pskHex() [2 * psk.len]u8 {
    return std.fmt.bytesToHex(psk, .lower);
}

/// Reads the peer's stdout until a line equals `want` (newline stripped);
/// `openssl` prints session details before the data it received.
fn awaitPeerLine(reader: *std.Io.Reader, want: []const u8) !void {
    const w = std.mem.trimEnd(u8, want, "\n");
    var lines: usize = 0;
    while (lines < 200) : (lines += 1) {
        const line = peerLine(reader) catch return error.PeerNeverPrintedOurData;
        if (std.mem.eql(u8, line, w)) return;
    }
    return error.PeerNeverPrintedOurData;
}

/// The handshake loop of `runClientFlow12` for a peer whose output we do not parse.
fn clientHandshake12(io: std.Io, sock: net.Socket, server_addr: *const net.IpAddress, conn: *Connection12, rnd: Entropy, case: Case12, out: []u8, rx: []u8, rec: *Recorder) !void {
    const hello = try conn.startHandshake(rnd, 0, out);
    rec.op("start");
    rec.hexArg("out", hello);
    rec.end();
    _ = try sendDatagrams(io, sock, server_addr, hello, case.max_datagram);
    var steps: usize = 0;
    while (!conn.isConnected()) : (steps += 1) {
        if (steps > 40) return error.TooManyFlights;
        const incoming = try sock.receiveTimeout(io, rx, deadline(io, 10_000));
        const result = conn.handleFlight(incoming.data, rnd, 0, out) catch |err| {
            std.debug.print("\n  our client rejected OpenSSL's flight ({t})\n", .{err});
            return err;
        };
        rec.op("flight");
        rec.hexArg("in", incoming.data);
        rec.hexArg("out", result.out);
        rec.numArg("more", @intFromBool(result.need_more_data));
        rec.end();
        if (result.out.len > 0) _ = try sendDatagrams(io, sock, server_addr, result.out, case.max_datagram);
    }
}

/// Our 1.2 client against `openssl s_server -dtls1_2 -listen` (plain PSK):
/// our line goes up and must appear on its stdout, then the line we write to
/// its stdin must come back to us as application data.
fn runClientFlowOpenssl12(io: std.Io, case: Case12, fx: *const Fixtures, rec: *Recorder) !void {
    const port = try freeLoopbackPort(io);
    var port_buf: [8]u8 = undefined;
    const port_str = try std.mem.print(&port_buf, "{d}", .{port});
    const key_hex = pskHex();
    var child = try std.process.spawn(io, .{
        .argv = &.{ "openssl", "s_server", "-dtls1_2", "-listen", "-port", port_str, "-nocert", "-psk", &key_hex, "-psk_identity", psk_identity, "-cipher", openssl_cipher12, "-naccept", "1" },
        .environ_map = child_env,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    defer child.kill(io);
    var out_buf: [4096]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &out_buf);
    // `ACCEPT` once the socket is bound.
    awaitPeerLine(&stdout_reader.interface, "ACCEPT") catch return error.PeerNeverReady;

    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    const server_addr: net.IpAddress = .{ .ip4 = .loopback(port) };

    const seed = @as([32]u8, @splat(case.seed));
    var csprng = std.Random.DefaultCsprng.init(seed);
    const rnd = seededForTest(&csprng);
    recordConfig12(rec, case, seed);
    var conn = try Connection12.clientInit(config12(case, .client, fx, null));
    defer conn.deinit();
    rec.op("client_init");
    rec.end();

    var out: [8192]u8 = undefined;
    var rx: [4096]u8 = undefined;
    try clientHandshake12(io, sock, &server_addr, &conn, rnd, case, &out, &rx, rec);
    try expectState12(&conn, case);
    try expectBool("HelloVerifyRequest seen", case.expect_hvr, conn.hvr_count > 0);
    recordExpect12(rec, &conn);
    rec.end();

    const record = try conn.send(case.app_send, &out);
    rec.op("send");
    rec.hexArg("in", case.app_send);
    rec.hexArg("out", record);
    rec.end();
    try sock.send(io, &server_addr, record);
    try awaitPeerLine(&stdout_reader.interface, case.app_send);
    rec.note("peer stdout (not replayable): OpenSSL printed our application data", .{});

    var stdin_buf: [256]u8 = undefined;
    var stdin_writer = child.stdin.?.writer(io, &stdin_buf);
    try stdin_writer.interface.writeAll(case.app_expect);
    try stdin_writer.interface.flush();
    var plain: [2048]u8 = undefined;
    const got = try recvApplicationData12(io, sock, &conn, &rx, &plain, rec);
    try expectBytes("OpenSSL's application data", case.app_expect, got);
}

/// `openssl s_client -dtls1_2` (plain PSK only) against our 1.2 server: its
/// stdin line arrives as application data, our echo must appear on its
/// stdout, and it exits 0 at end of input.
fn runServerFlowOpenssl12(io: std.Io, case: Case12, fx: *const Fixtures, rec: *Recorder) !void {
    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var addr_buf: [32]u8 = undefined;
    const addr_str = try std.mem.print(&addr_buf, "127.0.0.1:{d}", .{sock.address.getPort()});
    const key_hex = pskHex();
    var child = try std.process.spawn(io, .{
        .argv = &.{ "openssl", "s_client", "-dtls1_2", "-connect", addr_str, "-psk", &key_hex, "-psk_identity", psk_identity, "-cipher", openssl_cipher12, "-no_ign_eof" },
        .environ_map = child_env,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .ignore,
    });
    defer child.kill(io);
    var stdin_buf: [256]u8 = undefined;
    var stdin_writer = child.stdin.?.writer(io, &stdin_buf);
    try stdin_writer.interface.writeAll(case.app_expect);
    try stdin_writer.interface.flush();

    const seed = @as([32]u8, @splat(case.seed));
    var csprng = std.Random.DefaultCsprng.init(seed);
    const rnd = seededForTest(&csprng);
    recordConfig12(rec, case, seed);

    var out: [8192]u8 = undefined;
    var rx: [4096]u8 = undefined;
    var peer_addr: net.IpAddress = undefined;
    var conn: ?Connection12 = null;
    defer if (conn) |*c| c.deinit();
    var steps: usize = 0;
    while (true) : (steps += 1) {
        if (steps > 40) return error.TooManyFlights;
        const incoming = try sock.receiveTimeout(io, &rx, deadline(io, 10_000));
        peer_addr = incoming.from;
        if (conn == null) {
            conn = try Connection12.serverInit(config12(case, .server, fx, null));
            rec.op("server_init");
            rec.end();
        }
        const result = conn.?.handleFlight(incoming.data, rnd, 0, &out) catch |err| {
            std.debug.print("\n  our server rejected OpenSSL's flight ({t})\n", .{err});
            return err;
        };
        rec.op("flight");
        rec.hexArg("in", incoming.data);
        rec.hexArg("out", result.out);
        rec.numArg("more", @intFromBool(result.need_more_data));
        rec.end();
        if (result.out.len > 0) _ = try sendDatagrams(io, sock, &peer_addr, result.out, case.max_datagram);
        if (conn.?.isConnected()) break;
    }
    try expectState12(&conn.?, case);
    recordExpect12(rec, &conn.?);
    rec.end();

    var plain: [2048]u8 = undefined;
    const received = try recvApplicationData12(io, sock, &conn.?, &rx, &plain, rec);
    try expectBytes("received application data", case.app_expect, received);
    const echo = try conn.?.send(received, &out);
    rec.op("send");
    rec.hexArg("in", received);
    rec.hexArg("out", echo);
    rec.end();
    try sock.send(io, &peer_addr, echo);

    var out_buf: [4096]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &out_buf);
    try awaitPeerLine(&stdout_reader.interface, received);
    child.stdin.?.close(io);
    child.stdin = null;
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) {
            std.debug.print("  openssl s_client exited {d}, not 0\n", .{code});
            return error.PeerRejectedUs;
        },
        else => return error.PeerDiedAbnormally,
    }
    rec.note("peer exited 0 (not replayable): OpenSSL printed our echo and closed at end of input", .{});
}

const v12_only = [_]dtls.ProtocolVersion{.dtls12};

fn config12(case: Case12, role: dtls.Role, fx: *const Fixtures, binding: ?[]const u8) dtls.Config {
    var c: dtls.Config = .{
        .role = role,
        .versions = &v12_only,
        .now_sec = now12_sec,
        .max_datagram_len = case.max_datagram,
    };
    switch (case.kind) {
        .psk => {
            c.psk_identity = psk_identity;
            c.psk = &psk;
            if (role == .server) c.psk_identity_hint = psk12_hint;
        },
        .ecdsa, .rsa => {
            c.key_exchange = .cert_dhe;
            const anchor = if (case.kind == .rsa) fx.rsa12_cert_der else fx.anchor_cert_der;
            switch (role) {
                .client => {
                    c.peer_verify = .{ .trust_anchor = anchor };
                    if (case.mutual) c.cert = .{ .chain = &fx.client_chain, .private_key = fx.clientKey() };
                },
                .server => {
                    c.cert = if (case.kind == .rsa)
                        .{ .chain = &fx.rsa12_chain, .private_key = fx.rsa12Key() }
                    else
                        .{ .chain = &fx.server_chain, .private_key = fx.serverKey() };
                    if (case.mutual) {
                        c.request_client_cert = true;
                        c.require_peer_cert = true;
                        c.peer_verify = .{ .trust_anchor = anchor };
                    }
                },
            }
        },
    }
    if (binding) |b| c.hello_retry = .{ .cookie_secret = cookie_secret, .peer_binding = b };
    if (case.cid) c.connection_id = zig_cid;
    return c;
}

fn recordConfig12(rec: *Recorder, case: Case12, seed: [32]u8) void {
    rec.op("config");
    rec.strArg("flow", @tagName(case.flow));
    rec.strArg("kind", @tagName(case.kind));
    rec.hexArg("seed", &seed);
    rec.numArg("now_sec", now12_sec);
    rec.numArg("mutual", @intFromBool(case.mutual));
    rec.numArg("max_datagram", case.max_datagram);
    rec.hexArg("psk_identity", psk_identity);
    rec.hexArg("psk", &psk);
    rec.hexArg("psk_hint", psk12_hint);
    rec.hexArg("cookie_secret", cookie_secret);
    if (case.cid) rec.hexArg("cid", zig_cid);
    rec.end();
}

/// Sends `bytes` as the datagrams `record.nextDatagram` cuts at `limit` (one
/// datagram when 0), returning how many went out.
fn sendDatagrams(io: std.Io, sock: net.Socket, to: *const net.IpAddress, bytes: []const u8, limit: usize) !usize {
    var rest = bytes;
    var n: usize = 0;
    while (rest.len > 0) {
        const s = dtls.record.nextDatagram(rest, limit);
        if (limit != 0 and s.datagram.len > limit) return error.DatagramOverLimit;
        try sock.send(io, to, s.datagram);
        rest = s.rest;
        n += 1;
    }
    return n;
}

fn expectState12(conn: *const Connection12, case: Case12) !void {
    try expectU16("negotiated suite", @backingInt(case.expect_suite), @backingInt(conn.negotiatedSuite() orelse return error.NotConnected));
    try expectU16("negotiated group", case.expect_group, conn.ecdhe_group);
    try expectBool("extended master secret", true, conn.ems);
    if (case.cid) try expectBytes("the CID our records carry", wolf_cid, conn.peerConnectionId() orelse "");
}

fn recordExpect12(rec: *Recorder, conn: *const Connection12) void {
    rec.op("expect");
    rec.hex4Arg("suite", @backingInt(conn.negotiatedSuite().?));
    rec.hex4Arg("group", conn.ecdhe_group);
    rec.numArg("ems", @intFromBool(conn.ems));
    rec.numArg("hvr", conn.hvr_count);
}

/// The application-data read. A 1.2 peer has nothing else to put on epoch 1
/// after the handshake, but a retransmitted Finished is tolerated (and
/// recorded) as in the 1.3 flows.
fn recvApplicationData12(io: std.Io, sock: net.Socket, conn: *Connection12, rx: []u8, plain: []u8, rec: *Recorder) ![]const u8 {
    var skipped: usize = 0;
    while (skipped <= 4) {
        const incoming = try sock.receiveTimeout(io, rx, deadline(io, 10_000));
        const got = conn.recv(incoming.data, plain) catch |err| switch (err) {
            error.ReceivedPostHandshakeMessage => {
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

/// The peer's `PEERCERT` line, recorded as a note.
fn checkPeerCertLine(reader: *std.Io.Reader, want: []const u8, rec: *Recorder) !void {
    var lines: usize = 0;
    while (lines < 6) : (lines += 1) {
        const line = peerLine(reader) catch break;
        if (std.mem.startsWith(u8, line, "PEERCERT ")) {
            if (std.mem.find(u8, line, want) == null) {
                std.debug.print("  peer saw \"{s}\", which does not name {s}\n", .{ line, want });
                return error.WrongPeerCertificate;
            }
            rec.note("peer stdout (not replayable): {s}", .{line});
            return;
        }
    }
    return error.PeerNeverReportedOurCertificate;
}

fn runClientFlow12(gpa: std.mem.Allocator, io: std.Io, work: std.Io.Dir, case: Case12, fx: *const Fixtures, rec: *Recorder) !void {
    const port = try freeLoopbackPort(io);
    var port_buf: [8]u8 = undefined;
    const port_str = try std.mem.print(&port_buf, "{d}", .{port});
    var mtu_buf: [8]u8 = undefined;
    const mtu_str = try std.mem.print(&mtu_buf, "{d}", .{case.peer_mtu});

    var child = try std.process.spawn(io, .{
        .argv = &.{ "./wolfssl_peer", case.peer_mode, port_str, mtu_str },
        .cwd = .{ .dir = work },
        .environ_map = child_env,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    // Killed, not waited for: a case that fails mid-handshake leaves wolfSSL
    // blocked in `wolfSSL_read` with no timeout, and a wait would hang the
    // whole run (it did, on the first live run).
    defer child.kill(io);

    var ready_buf: [256]u8 = undefined;
    var stdout_reader = child.stdout.?.reader(io, &ready_buf);
    const ready_line = peerLine(&stdout_reader.interface) catch return error.PeerNeverReady;
    if (!std.mem.eql(u8, "READY", ready_line)) {
        std.debug.print("  peer said \"{s}\", not READY\n", .{ready_line});
        return error.PeerNeverReady;
    }

    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    const server_addr: net.IpAddress = .{ .ip4 = .loopback(port) };

    const seed = @as([32]u8, @splat(case.seed));
    var csprng = std.Random.DefaultCsprng.init(seed);
    const rnd = seededForTest(&csprng);
    recordConfig12(rec, case, seed);

    var conn = try Connection12.clientInit(config12(case, .client, fx, null));
    defer conn.deinit();
    rec.op("client_init");
    rec.end();

    var out: [8192]u8 = undefined;
    var rx: [4096]u8 = undefined;
    const hello = try conn.startHandshake(rnd, 0, &out);
    rec.op("start");
    rec.hexArg("out", hello);
    rec.end();
    _ = try sendDatagrams(io, sock, &server_addr, hello, case.max_datagram);

    var steps: usize = 0;
    var partial_steps: usize = 0;
    var largest_datagram: usize = 0;
    var datagrams_out: usize = 0;
    while (!conn.isConnected()) : (steps += 1) {
        if (steps > 40) return error.TooManyFlights;
        const incoming = try sock.receiveTimeout(io, &rx, deadline(io, 10_000));
        largest_datagram = @max(largest_datagram, incoming.data.len);
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
        if (result.out.len > 0) datagrams_out += try sendDatagrams(io, sock, &server_addr, result.out, case.max_datagram);
    }

    try expectState12(&conn, case);
    try expectBool("HelloVerifyRequest seen", case.expect_hvr, conn.hvr_count > 0);
    recordExpect12(rec, &conn);
    if (case.peer_mtu > 0) {
        if (largest_datagram > case.peer_mtu) return error.PeerIgnoredMtu;
        if (fx.server_cert_der.len <= case.peer_mtu) return error.CertificateTooSmallToFragment;
        if (partial_steps < 1) return error.NothingWasReassembled;
        rec.numArg("max_in_datagram", case.peer_mtu);
        rec.numArg("min_partial", 1);
    }
    if (case.max_datagram > 0) {
        // Our certificate flight cannot have fit one datagram.
        if (datagrams_out < 3) return error.OurFlightWasNotFragmented;
    }
    rec.end();

    const record = try conn.send(case.app_send, &out);
    rec.op("send");
    rec.hexArg("in", case.app_send);
    rec.hexArg("out", record);
    rec.end();
    try sock.send(io, &server_addr, record);
    var plain: [2048]u8 = undefined;
    const echoed = recvApplicationData12(io, sock, &conn, &rx, &plain, rec) catch |err| {
        reportPeerDiagnosis(gpa, io, &child, true, "no application data back from wolfSSL", err);
        return err;
    };
    try expectBytes("echoed application data", case.app_expect, echoed);

    if (case.expect_peer_cert_subject) |want| try checkPeerCertLine(&stdout_reader.interface, want, rec);
}

fn runServerFlow12(gpa: std.mem.Allocator, io: std.Io, work: std.Io.Dir, case: Case12, fx: *const Fixtures, rec: *Recorder) !void {
    const local: net.IpAddress = .{ .ip4 = .loopback(0) };
    const sock = try local.bind(io, .{ .mode = .dgram });
    defer sock.close(io);
    var port_buf: [8]u8 = undefined;
    const port_str = try std.mem.print(&port_buf, "{d}", .{sock.address.getPort()});

    var child = try std.process.spawn(io, .{
        .argv = &.{ "./wolfssl_peer", case.peer_mode, port_str },
        .cwd = .{ .dir = work },
        .environ_map = child_env,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .pipe,
    });
    defer child.kill(io);

    const seed = @as([32]u8, @splat(case.seed));
    var csprng = std.Random.DefaultCsprng.init(seed);
    const rnd = seededForTest(&csprng);
    recordConfig12(rec, case, seed);

    var out: [8192]u8 = undefined;
    var rx: [4096]u8 = undefined;
    var peer_addr: net.IpAddress = undefined;
    var binding_buf: [64]u8 = undefined;
    const cookie_mode = case.flow == .server_cookie;
    var conn: ?Connection12 = null;
    defer if (conn) |*c| c.deinit();
    var retries_served: usize = 0;
    var datagrams_out: usize = 0;

    var steps: usize = 0;
    while (true) : (steps += 1) {
        if (steps > 40) return error.TooManyFlights;
        const incoming = sock.receiveTimeout(io, &rx, deadline(io, 10_000)) catch |err| {
            // A client that gave up has exited: its stderr says why.
            if (case.cid) reportPeerDiagnosis(gpa, io, &child, true, "wolfSSL went silent during the handshake", err);
            return err;
        };
        peer_addr = incoming.from;
        if (conn == null) {
            const binding = if (cookie_mode) try std.mem.print(&binding_buf, "{f}", .{incoming.from}) else null;
            conn = try Connection12.serverInit(config12(case, .server, fx, binding));
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
        if (result.out.len > 0) datagrams_out += try sendDatagrams(io, sock, &peer_addr, result.out, case.max_datagram);
        if (conn.?.isConnected()) break;
        // Still `.start` after an answer went out: that was a
        // HelloVerifyRequest and the server kept nothing (RFC 6347 4.2.1).
        // Throw the connection away; ClientHello 2 must stand on its cookie.
        if (cookie_mode and conn.?.state == .start and result.out.len > 0) {
            retries_served += 1;
            conn.?.deinit();
            conn = null;
            rec.op("drop_conn");
            rec.end();
        }
    }

    if (cookie_mode and retries_served < 1) return error.NoRetryWasServed;
    try expectState12(&conn.?, case);
    recordExpect12(rec, &conn.?);
    if (cookie_mode) rec.numArg("min_retries", 1);
    if (case.mutual) {
        if (!conn.?.client_cert_presented) return error.PeerPresentedNoCertificate;
        rec.numArg("client_cert", 1);
    }
    if (case.max_datagram > 0 and datagrams_out < 3) return error.OurFlightWasNotFragmented;
    rec.end();

    var plain: [2048]u8 = undefined;
    const received = recvApplicationData12(io, sock, &conn.?, &rx, &plain, rec) catch |err| {
        reportPeerDiagnosis(gpa, io, &child, true, "no application data from wolfSSL", err);
        return err;
    };
    try expectBytes("received application data", case.app_expect, received);
    const echo = try conn.?.send(received, &out);
    rec.op("send");
    rec.hexArg("in", received);
    rec.hexArg("out", echo);
    rec.end();
    try sock.send(io, &peer_addr, echo);

    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) {
            std.debug.print("  peer exited {d}, not 0\n", .{code});
            return error.PeerRejectedUs;
        },
        else => return error.PeerDiedAbnormally,
    }
    rec.note("peer exited 0 (not replayable): it completed the handshake, in certificate modes after X509_V_OK on our chain, and got its message echoed", .{});
}

// ── the transcript header ─────────────────────────────────────────────────

fn utcDate(buf: []u8) []const u8 {
    var ts: std.os.linux.timespec = undefined;
    if (std.os.linux.clock_gettime(.REALTIME, &ts) != 0) return "unknown";
    const secs: u64 = @intCast(ts.sec);
    const epoch_day = std.time.epoch.EpochSeconds{ .secs = secs };
    const day = epoch_day.getEpochDay().calculateYearDay();
    const md = day.calculateMonthDay();
    return std.mem.print(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{
        day.year,
        md.month.numeric(),
        md.day_index + 1,
    }) catch "unknown";
}

/// `openssl version`, for the 1.2 transcript header (its plain-PSK cases).
fn readOpensslVersion(gpa: std.mem.Allocator, io: std.Io) []const u8 {
    const r = std.process.run(gpa, io, .{ .argv = &.{ "openssl", "version" }, .environ_map = child_env }) catch return "unknown";
    const trimmed = std.mem.trim(u8, r.stdout, " \r\n\t");
    return if (trimmed.len == 0) "unknown" else trimmed;
}

fn writeHeader(w: *std.Io.Writer, wolfssl_version: []const u8, version: Version) !void {
    var date_buf: [16]u8 = undefined;
    try w.print(
        \\# dtls ↔ wolfSSL DTLS {s} transcript — a RECORDING, not a specification.
        \\#
        \\# Every byte below was taken off a real loopback UDP socket between this
        \\# module and wolfSSL. `modules/dtls/tools/interop.zig` wrote it;
        \\# `modules/dtls/src/{s}` replays it with no wolfSSL and no C
        \\# compiler in sight, which is where the anchor's value now lives. Re-taking it
        \\# needs `libwolfssl-dev` and a C compiler:
        \\#
        \\#     wolfSSL:  {s}
        \\#     captured: {s}
        \\#     command:  zig build interop-dtls -- --capture{s}
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
        \\#   request_key_update peer=<0|1>              requestKeyUpdate(peer)
        \\#   poll now=<ms> out=<hex>                    poll(now) must return exactly this control record
        \\#   poll_idle now=<ms>                         poll(now) must return nothing
        \\#   expect_epochs write=<n> read=<n>           the connection's write/read epochs
        \\#   expect hrr=<0|1> group=<hex4> [alpn=<name>] [...]
        \\#                                              the connection's own view, after the handshake
        \\#   expect suite=<hex4> group=<hex4> ems=<0|1> hvr=<n> [...]
        \\#                                              the same, for a DTLS 1.2 connection
        \\#
        \\format version=1
        \\
        \\
    , .{
        if (version == .v12) "1.2" else "1.3",
        if (version == .v12) "wolfssl12_replay.zig" else "wolfssl_replay.zig",
        wolfssl_version,
        utcDate(&date_buf),
        if (version == .v12) " --version 12" else "",
    });
}

/// Which table / transcript a run covers (`--version`).
const Version = enum { v13, v12 };

// ── main ──────────────────────────────────────────────────────────────────

const usage =
    \\dtls live interop against wolfSSL.
    \\
    \\  zig build interop-dtls                  run every case live
    \\  zig build interop-dtls -- --capture     ...and rewrite the committed transcript
    \\  zig build interop-dtls -- --case NAME   run one case (repeatable)
    \\  zig build interop-dtls -- --version 12  only the DTLS 1.2 (or 13) cases; with
    \\                                          --capture, rewrite only that transcript
    \\  zig build interop-dtls -- --list        list the case names
    \\  zig build interop-dtls -- --repo-root P read wolfssl_peer.c and the fixtures from P
    \\
    \\Needs a C compiler and libwolfssl-dev. The hermetic half of this — replaying
    \\what a capture recorded — is `zig build test-dtls` and needs neither.
    \\
;

fn isSelected(selected: []const []const u8, name: []const u8) bool {
    if (selected.len == 0) return true;
    for (selected) |n| {
        if (std.mem.eql(u8, n, name)) return true;
    }
    return false;
}

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
    var only: ?Version = null;
    var repo_root: []const u8 = ".";
    var selected: [cases.len + cases12.len][]const u8 = undefined;
    var selected_len: usize = 0;

    var args = init.args.iterate();
    _ = args.next(); // argv[0]
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--capture")) {
            capture = true;
        } else if (std.mem.eql(u8, arg, "--list")) {
            for (cases) |c| std.debug.print("{s}\t{s}\n", .{ c.name, c.why });
            for (cases12) |c| std.debug.print("{s}\t{s}\n", .{ c.name, c.why });
            return 0;
        } else if (std.mem.eql(u8, arg, "--version")) {
            const v = args.next() orelse "";
            only = if (std.mem.eql(u8, v, "12")) .v12 else if (std.mem.eql(u8, v, "13")) .v13 else {
                std.debug.print("--version takes 12 or 13\n{s}", .{usage});
                return 2;
            };
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

    // A capture of a SUBSET would silently truncate the committed file into
    // something that still looks complete, so the two are refused together.
    // `--version` is not a subset: it rewrites one whole transcript.
    if (capture and selected_len > 0) {
        std.debug.print("--capture rewrites whole transcripts; it cannot be combined with --case\n", .{});
        return 2;
    }

    var ran: usize = 0;
    var failed: usize = 0;
    var t13: std.Io.Writer.Allocating = .init(gpa);
    defer t13.deinit();
    var t12: std.Io.Writer.Allocating = .init(gpa);
    defer t12.deinit();
    var failed13: usize = 0;
    var failed12: usize = 0;

    if (only != .v12) {
        var rec: Recorder = .{ .enabled = capture, .out = &t13.writer };
        if (capture) try writeHeader(&t13.writer, version, .v13);
        for (cases) |case| {
            if (!isSelected(selected[0..selected_len], case.name)) continue;
            std.debug.print("{s} ... ", .{case.name});
            // Marked BEFORE the case header goes in, so a failure rolls back
            // the header too rather than leaving a case with no body.
            const mark = t13.written().len;
            rec.enabled = capture;
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
                failed13 += 1;
                // A half-written case must not reach the committed file: it
                // would be a fixture recording a run that did not work.
                t13.shrinkRetainingCapacity(mark);
            }
        }
    }
    if (only != .v13) {
        var rec: Recorder = .{ .enabled = capture, .out = &t12.writer };
        if (capture) {
            try writeHeader(&t12.writer, version, .v12);
            try t12.writer.print("# The plain-PSK cases ran against {s} (`openssl s_server` / `s_client`).\n\n", .{readOpensslVersion(gpa, io)});
        }
        for (cases12) |case| {
            if (!isSelected(selected[0..selected_len], case.name)) continue;
            std.debug.print("{s} ... ", .{case.name});
            const mark = t12.written().len;
            rec.raw("case {s}\n", .{case.name});
            rec.raw("why {s}\n", .{case.why});
            const result = switch (case.peer) {
                .wolfssl => switch (case.flow) {
                    .client => runClientFlow12(gpa, io, work, case, &fx, &rec),
                    .server, .server_cookie => runServerFlow12(gpa, io, work, case, &fx, &rec),
                },
                .openssl => switch (case.flow) {
                    .client => runClientFlowOpenssl12(io, case, &fx, &rec),
                    .server, .server_cookie => runServerFlowOpenssl12(io, case, &fx, &rec),
                },
            };
            ran += 1;
            if (result) {
                std.debug.print("ok\n", .{});
                rec.raw("\n", .{});
            } else |err| {
                std.debug.print("FAILED ({t})\n", .{err});
                failed12 += 1;
                t12.shrinkRetainingCapacity(mark);
            }
        }
    }
    failed = failed13 + failed12;

    if (ran == 0) {
        std.debug.print("no case matched\n{s}", .{usage});
        return 2;
    }
    std.debug.print("\n{d}/{d} cases passed against wolfSSL {s}\n", .{ ran - failed, ran, version });

    if (capture) {
        if (failed > 0) {
            std.debug.print("NOT writing any transcript: {d} case(s) failed\n", .{failed});
            return 1;
        }
        if (only != .v12) {
            try root.writeFile(io, .{ .sub_path = transcript_path, .data = t13.written() });
            std.debug.print("wrote {s} ({d} bytes)\n", .{ transcript_path, t13.written().len });
        }
        if (only != .v13) {
            try root.writeFile(io, .{ .sub_path = transcript12_path, .data = t12.written() });
            std.debug.print("wrote {s} ({d} bytes)\n", .{ transcript12_path, t12.written().len });
        }
    }
    return if (failed > 0) 1 else 0;
}
