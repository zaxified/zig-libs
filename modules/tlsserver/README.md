# tlsserver

A TLS 1.3 server (RFC 8446) for the collection: a buffer-driven (sans-I/O) core with a blocking
wrapper on top, built on the `tls13` handshake building blocks and the `aesgcm` / `chachapoly`
AEADs. At rustls's server scope (re-surveyed 2026-10-22, grade 2): a full (EC)DHE handshake with
a certificate — TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256;
X25519MLKEM768, X25519, secp256r1, secp384r1 (and ML-KEM-1024 when enabled); ECDSA
P-256/P-384/P-521, Ed25519, RSA-PSS and ML-DSA-44/65/87 certificates or RFC 7250 raw public
keys; SNI certificate selection; ALPN; HelloRetryRequest; KeyUpdate both ways; session tickets
(stateless over a STEK ring, or stateful over a session cache) with PSK resumption and 0-RTT
behind a mandatory replay guard; client certificates or raw public keys (`Config.client_auth`);
OCSP and SCT stapling; RFC 8879 certificate compression (precompressed by the caller); the
RFC 8446 §7.5 exporter; kTLS secret hand-over (`extractSecrets`); and a QUIC mode (RFC 9001,
`Config.quic`: CRYPTO data and traffic secrets per encryption level). Sans-I/O (`Server`) or
blocking (`Connection`), certificate and key from PEM (`keys`). The rustls parity gate runs
with BoGo: the 305 TLS 1.3 server tests rustls passes that apply all pass here (131 more are
disabled with a reason, 0 gaps; `SPEC.md`).

- **Status:** the collection's TLS 1.3 server (with `tlsclient` and `dtls`); qap runs it behind
  `-Dtls-engine=tlsserver` while its fork of a third-party server is still the default.
- **Model after:** RFC 8446; rustls `ServerConnection` for scope and the buffer-driven split.
- **Platform:** any (pure computation; `Connection` uses std.Io). **Role:** server.
  **Concurrency:** single owner. **Deps:** `tls13`, `aesgcm`, `chachapoly`, `netaddr`,
  `x509`, `rsa`, `b64ct`, `tlsresume`.

## Usage

```zig
const tlsserver = @import("tlsserver");

var pair: tlsserver.CertKeyPair = undefined;
try pair.fromPem(gpa, chain_pem, key_pem); // KeyMismatch if the key is not the leaf's
defer pair.deinit(gpa);
const ck = pair.certifiedKey();

const config: tlsserver.Config = .{
    .certificate = .{ .fixed = &ck },
    .alpn_protocols = &.{ "h2", "http/1.1" },
    .random = csprng.random(), // MUST be a CSPRNG
};

// Session tickets and resumption (optional): a STEK ring the application
// rotates (`ring.maybeRotate(policy, &fresh_key, now_s)`, never while a
// connection reads it), a wall clock in milliseconds.
var ring: tlsresume.stek.StekRing(tlsresume.depthFor(.{})) = .init();
ring.rotate(1, &first_key, now_s);
const stek: tlsserver.StekTicketer(@TypeOf(ring)) = .{ .ring = &ring };
const tickets: tlsserver.Tickets = .{ .ticketer = stek.ticketer(), .clock = .{ .now_ms = wallMs } };
// config.tickets = &tickets;  — 2 tickets per handshake, 12 h lifetime (rustls)

// Certificate compression (RFC 8879, optional): compress the Certificate
// message once, when the certificate is loaded, with any compressor —
// here zlib from std (algorithm 1). One entry per algorithm and per set of
// staples sent (`.{ .ocsp = true }` for clients that ask for the staple).
const body = try ck.uncompressedCertificate(&body_buf, .{});
const zlib_data = try zlibCompress(gpa, body); // e.g. std.compress.flate, `.zlib`
var compressed_ck = ck;
compressed_ck.compressed_certificates = &.{.{ .algorithm = 1, .uncompressed_len = @intCast(body.len), .data = zlib_data }};
try compressed_ck.check(); // compress again whenever the chain or a staple is replaced

// Per connection: a joiner, a reader whose buffer holds one whole record
// (`record.max_record_len`), and a stream writer (a socket's) whose buffer
// holds the first flight (`Server.minOutputLen`): records are sealed in it.
var conn: tlsserver.Connection = .init(&config, reader, writer, joiner_buf);
defer conn.deinit();
try conn.handshake();
while (try conn.read()) |data| try conn.writeAll(data); // echo until close_notify
try conn.close();
```

The record layer alone (`tlsserver.record.Protection`: `init` from a traffic secret, `seal` and
`open` in place) is shown in `example/main.zig`.

A failed `open` (`BadRecordMac`, …) leaves the sequence number unchanged and the ciphertext
zeroed; the engine answers it with the matching alert.

## Tests

`zig build test-tlsserver`. Anchors (`SPEC.md` § Anchoring): RFC 8448's records, ClientHellos
and server messages byte-exact; OpenSSL 3.5 `s_client` and Go 1.26 crypto/tls client sessions
(`zig build interop-tlsserver`, replayed byte-exact in the tests); BoringSSL's BoGo suite
(`-- --bogo`, 370 pass, with the rustls parity report); tlsfuzzer's TLS 1.3 scripts
(`-- --tlsfuzzer DIR`, a checkout such as qap's `scripts/tools/tlsfuzzer`; counts held in
`tools/tlsfuzzer/baseline.tsv`); handshakes against Zig std's
client and the collection's `tlsclient`; keys in every PEM form
the OpenSSL command line writes (`tools/key_vectors.py`). Fuzz: `TLSSERVER_FUZZ=<runs>` drives
the `tlsserver-record`, `-inbound`, `-hello`, `-keys`, `-server`, `-keyupdate` and
`-clientauth` harnesses (`SPEC.md` § Fuzzing). Dead
stack: `src/stackprobe_test.zig` (ReleaseFast). Example: `zig build run-example-tlsserver`.

Provenance: clean-room from RFC 8446 (a public standard), no third-party source ported or
studied, so no `NOTICE` entry is required (root [`NOTICE`](../../NOTICE) §0). The test vectors
are RFC 8448's and OpenSSL's output (via Python `cryptography`). tlsfuzzer (GPL-2.0) is only
run against the server as an external oracle, never copied or linked.
