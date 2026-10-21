# tlsserver

A TLS 1.3 server (RFC 8446) for the collection: a buffer-driven (sans-I/O) core with a blocking
wrapper on top, built on the `tls13` handshake building blocks and the `aesgcm` / `chachapoly`
AEADs. **Under construction (milestone M2):** a full (EC)DHE handshake with a certificate —
TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256; X25519MLKEM768,
X25519, secp256r1, secp384r1 (and ML-KEM-1024 when enabled); ECDSA P-256/P-384/P-521,
Ed25519, RSA-PSS and ML-DSA-44/65/87 certificates; SNI
certificate selection; ALPN; HelloRetryRequest for a group the client sent no share for — then application data and close_notify, sans-I/O (`Server`) or
blocking (`Connection`), with the certificate and key loaded from PEM (`keys`), KeyUpdate
both ways, session tickets with PSK resumption (`psk_dhe_ke`, through `tlsresume`), and client
certificates (`Config.client_auth`: a `ClientCertVerifier`, `X509Verifier` over `x509`;
`Server.peerCertificate`), and an OCSP staple and SCT list on the leaf when the client asks
(`CertifiedKey.ocsp_response` / `sct_list`, checked by `CertifiedKey.check`). The rustls parity
gate runs with BoGo: 247 of the 436 TLS 1.3 server tests rustls passes pass here, 140 are
disabled with a reason, 49 are gaps (0-RTT, certificate compression, P-521 / ML-DSA keys,
ML-KEM-1024; `SPEC.md`, *Backlog*).

- **Status:** gap — the collection has a TLS client (`tlsclient`) and DTLS (`dtls`), no TLS
  server; qap runs a fork of a third-party one, which this module is meant to replace.
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
(`-- --bogo`, 339 pass, with the rustls parity report); tlsfuzzer's TLS 1.3 scripts
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
