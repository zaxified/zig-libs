# tls13

The TLS 1.3 handshake building blocks shared by the collection's TLS-family engines: `dtls`
(DTLS 1.3) and the planned `tlsserver` (TLS 1.3 over TCP). Today that is:

- the RFC 8446 §7.1 key schedule, instantiated once per protocol label prefix —
  `keyschedule.tls13` (`"tls13 "`) and `keyschedule.dtls13` (`"dtls13"`, RFC 9147 §5.9) —
  including the resumption, exporter and KeyUpdate steps;
- `certverify`: the RFC 8446 §4.4.3 CertificateVerify signed content and sign/verify for
  ECDSA P-256/P-384, Ed25519 and RSA-PSS (`rsa_pss_rsae_sha256/384/512`).

Pure functions over caller bytes: no I/O, no allocation, no key storage, no
handshake decisions.

- **Model after:** RFC 8446 §7 and RFC 9147 §5.9; the API split follows rustls's
  `tls13::key_schedule` (one function per derivation, secrets through out-pointers).
- **Platform:** any (pure computation). **Role:** codec. **Concurrency:** reentrant.
  **Deps:** `rsa` (RSA-PSS); otherwise std (HKDF/HMAC, ECDSA, Ed25519).

Provenance: original work of the zig-libs authors (MIT), written from RFC 8446 / RFC 9147 —
public standards, not copyrightable works. The test vectors are RFC 8448's, an independent
Python `hmac`/`hashlib` reimplementation's, and for `certverify` OpenSSL / Python
`cryptography` cross-checked signatures (see `SPEC.md`).

## Usage

```zig
const ks = @import("tls13").keyschedule;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

var early: [32]u8 = undefined;
ks.tls13.earlySecret(HkdfSha256, &early, &psk);
var hs: [32]u8 = undefined;
ks.tls13.deriveHandshakeSecret(HkdfSha256, &hs, &early, &empty_hash, &ecdhe_shared);
var c_hs: [32]u8 = undefined;
var s_hs: [32]u8 = undefined;
ks.tls13.deriveHandshakeTrafficSecrets(HkdfSha256, &c_hs, &s_hs, &hs, &transcript_through_sh);
```

```zig
const cv = @import("tls13").certverify;

var sig_buf: [cv.maxSignatureLen(.ecdsa_secp256r1_sha256)]u8 = undefined;
const sig = try cv.sign(.ecdsa_secp256r1_sha256, .{ .ecdsa_p256 = &secret_key }, .server, &transcript_hash, random, &sig_buf);
try cv.verify(.ecdsa_secp256r1_sha256, .{ .ecdsa_p256 = public_key }, .server, &transcript_hash, sig);
```

Every secret goes in by `*const` and comes out through an out-pointer, never by value, and the
entry points that hold a secret in a local burn their stack (`CONVENTIONS.md` §2.1.1). Compare a
received Finished or binder with `std.crypto.timing_safe.eql`, never `std.mem.eql`.

## Tests

`zig build test-tls13`. Anchors: RFC 8448 §3 (early, handshake, master, traffic, exporter and
resumption master secrets, finished key, traffic key/iv) and §4 (resumption PSK, res binder key,
binder), an independent Python oracle for the `dtls13` prefix, and std's
`std.crypto.tls.hkdfExpandLabel` for `traffic upd` at SHA-256 and SHA-384. `certverify`: the
signed content byte-exact, verify KATs for every scheme (RSA-PSS by OpenSSL, Ed25519 by
`cryptography`), deterministic ECDSA/Ed25519 sign reproduced byte-exact, tamper and reject-path
tests. Fuzz: `TLS13_FUZZ=<runs>` drives the `tls13-certverify` harness (see `SPEC.md`
§ Fuzzing). Example: `zig build run-example-tls13`.
