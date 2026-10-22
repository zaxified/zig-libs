// SPDX-License-Identifier: MIT

//! tlsserver — a TLS 1.3 server (RFC 8446), buffer-driven (sans-I/O) with a
//! blocking wrapper on top, built on the collection's `tls13` handshake
//! building blocks and its `aesgcm` / `chachapoly` AEADs. Under construction
//! (plan: milestones M1–M4, `SPEC.md`). Today: `Server`, a sans-I/O full
//! handshake with a certificate (TLS_AES_128_GCM_SHA256,
//! TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256; X25519MLKEM768,
//! X25519, secp256r1, secp384r1), HelloRetryRequest, session tickets and
//! resumption, client certificates (mTLS), then application data with
//! KeyUpdate both ways —
//! `Connection`, the blocking wrapper, and `keys`, the PEM loader. Interoperates with OpenSSL 3.5's s_client.
//!
//! No TLS 1.2, no 0-RTT in v1 (`SPEC.md`, *What is deliberately not done*).

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "TLS 1.3 server (RFC 8446), sans-I/O core with a blocking wrapper, at rustls's server scope: hybrid and classical key exchange, HelloRetryRequest, stateless and stateful tickets, 0-RTT with a replay guard, client certificates and RFC 7250 raw public keys, OCSP/SCT stapling, certificate compression, exporter, kTLS secret hand-over and a QUIC mode (RFC 9001)",
    // Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any (pure computation; the planned blocking wrapper uses std.Io)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .server,
    // One record-protection state per direction per connection; nothing
    // shared or global.
    .concurrency = .single_owner,
    .model_after = "RFC 8446; rustls `ServerConnection` (buffer-driven core) for scope and API split",
    .deps = .{ "tls13", "aesgcm", "chachapoly", "netaddr", "x509", "rsa", "b64ct", "tlsresume", "p521" }, // p521: P-521 private keys (std has no P-521); tls13: key schedule; aesgcm/chachapoly: record AEADs (std AES-GCM is 2.6x slower on Zig 0.17, #36256); netaddr: an IP literal in SNI; x509: the leaf's public key (`keys`); rsa: RSA private keys; b64ct: constant-time PEM of the private key; tlsresume: session tickets (STEK ring, PSK selection)
};

/// The TLS 1.3 record layer: header, `Protection` (seal / open in place).
pub const record = @import("record.zig");

/// Alerts: the message, what a received one means, error → alert.
pub const alert = @import("alert.zig");

/// The receive side: records → handshake messages, alerts, application data.
pub const inbound = @import("inbound.zig");

/// The send side: content framed into records, fragmented and sealed in place.
pub const outbound = @import("outbound.zig");

/// The ClientHello, decoded into slices with every extension checked.
pub const hello = @import("hello.zig");

/// The handshake messages the server writes (ServerHello … Finished).
pub const messages = @import("messages.zig");

/// The sans-I/O server: the full handshake, then application data.
pub const server = @import("server.zig");
pub const Server = server.Server;
pub const Config = server.Config;
pub const CertifiedKey = server.CertifiedKey;
pub const Tickets = server.Tickets;
pub const Ticketer = server.Ticketer;
pub const StekTicketer = server.StekTicketer;
pub const CacheTicketer = server.CacheTicketer;
pub const SessionCache = server.SessionCache;
pub const ClientAuth = server.ClientAuth;
pub const SignatureRequest = server.SignatureRequest;
pub const Signer = server.Signer;
/// `tls13.certverify`: the key and scheme types of `CertifiedKey`, and
/// `signContent` for a signer that holds an offloaded key.
pub const certverify = @import("tls13").certverify;

/// Client certificates: the Certificate / CertificateVerify decoders, the
/// leaf's key, the `ClientCertVerifier` and its `x509` implementation.
pub const clientauth = @import("clientauth.zig");
pub const ClientCertVerifier = clientauth.ClientCertVerifier;
pub const X509Verifier = clientauth.X509Verifier;

/// The blocking wrapper over a `std.Io.Reader` / `Writer` pair.
pub const connection = @import("connection.zig");
pub const Connection = connection.Connection;

/// Loading a certificate chain and its private key from PEM.
pub const keys = @import("keys.zig");
pub const CertKeyPair = keys.CertKeyPair;

/// TEST certificates and private keys (self-signed, CN=tlsserver-test, SAN
/// localhost: ECDSA P-256 and P-384, Ed25519, RSA-2048), published for this module's
/// interop program and for consumers' own tests. The keys are public:
/// never serve anything real with them.
pub const test_fixtures = @import("test_certs.zig");

/// TEST client certificates (a client CA and leaves it issued, with their
/// private keys) for client authentication in this module's interop program
/// and consumers' own tests. The keys are public: never trust anything real
/// with them.
pub const test_client_fixtures = @import("client_certs.zig");

/// TEST private keys in every PEM form `openssl` writes (P-256, P-384,
/// P-521, Ed25519, RSA-2048, ML-DSA-44/65/87), each with a self-signed
/// certificate: the key loader's vectors, and the P-521 and ML-DSA
/// certificates of the interop program. The keys are public.
pub const test_key_vectors = @import("key_vectors.zig");

/// The `test_key_vectors` case called `name` (comptime: a typo is a compile error).
pub fn testKeyVector(comptime name: []const u8) test_key_vectors.Case {
    return comptime for (test_key_vectors.cases) |c| {
        if (std.mem.eql(u8, c.name, name)) break c;
    } else @compileError("no key vector " ++ name);
}

test {
    _ = record;
    _ = alert;
    _ = inbound;
    _ = outbound;
    _ = hello;
    _ = messages;
    _ = server;
    _ = clientauth;
    _ = connection;
    _ = keys;
    _ = @import("zeroize.zig");
    _ = @import("handshake_test.zig");
    _ = @import("interop_replay_test.zig");
    _ = @import("stackprobe_test.zig");
    _ = @import("fuzz_test.zig");
}

test "meta.deps is {tls13, aesgcm, chachapoly, netaddr, x509, rsa, b64ct, tlsresume, p521}" {
    try std.testing.expectEqual(@as(usize, 9), meta.deps.len);
    try std.testing.expectEqualStrings("tls13", meta.deps[0]);
    try std.testing.expectEqualStrings("aesgcm", meta.deps[1]);
    try std.testing.expectEqualStrings("chachapoly", meta.deps[2]);
    try std.testing.expectEqualStrings("netaddr", meta.deps[3]);
    try std.testing.expectEqualStrings("x509", meta.deps[4]);
    try std.testing.expectEqualStrings("rsa", meta.deps[5]);
    try std.testing.expectEqualStrings("b64ct", meta.deps[6]);
    try std.testing.expectEqualStrings("tlsresume", meta.deps[7]);
    try std.testing.expectEqualStrings("p521", meta.deps[8]);
}
