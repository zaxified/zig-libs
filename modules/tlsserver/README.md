# tlsserver

A TLS 1.3 server (RFC 8446) for the collection: a buffer-driven (sans-I/O) core with a blocking
wrapper on top, built on the `tls13` handshake building blocks and the `aesgcm` / `chachapoly`
AEADs. **Under construction (milestone M2):** a full (EC)DHE handshake with a certificate —
TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256; X25519MLKEM768,
X25519, secp256r1, secp384r1; ECDSA P-256/P-384, Ed25519 and RSA-PSS certificates; SNI
certificate selection; ALPN; HelloRetryRequest for a group the client sent no share for — then application data and close_notify, sans-I/O (`Server`) or
blocking (`Connection`), with the certificate and key loaded from PEM (`keys`), KeyUpdate
both ways, session tickets with PSK resumption (`psk_dhe_ke`, through `tlsresume`), and client
certificates (`Config.client_auth`: a `ClientCertVerifier`, `X509Verifier` over `x509`;
`Server.peerCertificate`), and an OCSP staple and SCT list on the leaf when the client asks
(`CertifiedKey.ocsp_response` / `sct_list`, checked by `CertifiedKey.check`). Next: the rustls
parity gate (`SPEC.md`, *Backlog*).

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

// Per connection: a joiner and an output buffer, and a reader whose buffer
// holds one whole record (`record.max_record_len`).
var conn: tlsserver.Connection = .init(&config, reader, writer, joiner_buf, output_buf);
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
(`-- --bogo`, 286 pass); handshakes against Zig std's
client and the collection's `tlsclient`; keys in every PEM form
the OpenSSL command line writes (`tools/key_vectors.py`). Fuzz: `TLSSERVER_FUZZ=<runs>` drives
the `tlsserver-record`, `-inbound`, `-hello`, `-keys`, `-server`, `-keyupdate` and
`-clientauth` harnesses (`SPEC.md` § Fuzzing). Dead
stack: `src/stackprobe_test.zig` (ReleaseFast). Example: `zig build run-example-tlsserver`.

Provenance: clean-room from RFC 8446 (a public standard), no third-party source ported or
studied, so no `NOTICE` entry is required (root [`NOTICE`](../../NOTICE) §0). The test vectors
are RFC 8448's and OpenSSL's output (via Python `cryptography`).
