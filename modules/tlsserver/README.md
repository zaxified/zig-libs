# tlsserver

A TLS 1.3 server (RFC 8446) for the collection: a buffer-driven (sans-I/O) core with a blocking
wrapper on top, built on the `tls13` handshake building blocks and the `aesgcm` / `chachapoly`
AEADs. **Under construction:** today it is the record layer only — the 5-byte header and
per-direction, in-place record protection for TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
and TLS_CHACHA20_POLY1305_SHA256. The handshake and the connection API come next (`SPEC.md`,
*Backlog*).

- **Status:** gap — the collection has a TLS client (`tlsclient`) and DTLS (`dtls`), no TLS
  server; qap runs a fork of a third-party one, which this module is meant to replace.
- **Model after:** RFC 8446; rustls `ServerConnection` for scope and the buffer-driven split.
- **Platform:** any (pure computation). **Role:** server. **Concurrency:** single owner.
  **Deps:** `tls13`, `aesgcm`, `chachapoly`.

## Usage (record layer)

```zig
const record = @import("tlsserver").record;

var tx: record.Protection = undefined;
try tx.init(.aes_256_gcm_sha384, &server_application_traffic_secret);
defer tx.wipe();

// Content goes at buf[record.header_len..]; seal writes header, type, padding and tag
// around it, in place.
@memcpy(buf[record.header_len..][0..msg.len], msg);
const wire = try tx.seal(&buf, msg.len, .application_data, 0);

var rx: record.Protection = undefined;
try rx.init(.aes_256_gcm_sha384, &client_application_traffic_secret);
const opened = try rx.open(one_whole_record); // decrypts in place
// opened.content_type, opened.content (a slice of one_whole_record)
```

A failed `open` (`BadRecordMac`, …) leaves the sequence number unchanged and the ciphertext
zeroed; the engine answers it with the matching alert.

## Tests

`zig build test-tlsserver`. Anchors: the seven protected records of RFC 8448 §3, sealed
byte-exact and opened back; AES-256-GCM and ChaCha20-Poly1305 records sealed by OpenSSL
(Python `cryptography`) — both produced by `tools/rfc8448_records.py`. Fuzz:
`TLSSERVER_FUZZ=<runs>` drives the `tlsserver-record` harness (`SPEC.md` § Fuzzing). Dead
stack: `src/stackprobe_test.zig` (ReleaseFast). Example: `zig build run-example-tlsserver`.

Provenance: clean-room from RFC 8446 (a public standard), no third-party source ported or
studied, so no `NOTICE` entry is required (root [`NOTICE`](../../NOTICE) §0). The test vectors
are RFC 8448's and OpenSSL's output (via Python `cryptography`).
