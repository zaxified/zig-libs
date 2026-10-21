# `tls13` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-21** — `Schedule.exportKeyingMaterial(Hash, Hkdf, out, exporter_master_secret, label,
  context)`: the RFC 8446 §7.5 exporter with a run-time output length (burned like the other
  steps), plus `max_exporter_label_len` and `maxExporterLen`. KATs from an independent Python
  `hmac`/`hashlib` reimplementation over RFC 8448 §3's exporter master secret (SHA-256: 1, 32 and
  100 octets) and a SHA-384 one; a dead-stack probe (`stackprobe_test.zig`) for the label's
  secret.

- **2026-10-21** — ML-KEM-1024 (`kex.mlkem1024_group` 0x0202, out-of-line arms under
  `burn.kex_mlkem1024_burn`; `max_share_len` 1216 → 1568, new `max_server_share_len`), and
  CertificateVerify for `ecdsa_secp521r1_sha512` (the `p521` module, new dep) and pure ML-DSA
  `mldsa44/65/87` (std, empty context; `PublicKey.mldsa*` borrows the encoded key, `SecretKey.mldsa*`
  points to std's expanded key; per-set burns). `max_signature_len` (4627). KATs: P-521 DER byte
  for byte and ML-DSA keys/signatures by SHA-256 against OpenSSL 3.5.5; the certverify and kex
  fuzz harnesses and the stack probe cover the new arms.

- **2026-10-21** — `kex` and `certverify` compute on the collection's curves: X25519 on
  `ct25519` (comb key generation, MULX/ADX ladder), P-256 on `p256`, P-384 on `p384` (key
  generation, ECDH, ECDSA sign and verify); Ed25519 and ML-KEM-768 stay std's. Same octets for
  X25519 and P-256 (dtls's wolfSSL replay and tlsserver's 49 recorded OpenSSL/Go sessions replay
  unchanged); a P-384 signature is now RFC 6979's — the KAT is re-anchored on OpenSSL 3.5.5's
  deterministic ECDSA, byte-exact. A `tlsserver` handshake (P-256 certificate, X25519,
  TLS_AES_256_GCM_SHA384) goes from 2,012 to 6,705 per second server-side, P-384 from 506 to
  1,832. New deps `ct25519`, `p256`, `p384`. The example's wrong-hash-length step (broken since
  `HashLengthMismatch` went) now expects `InvalidSignature`.
- **2026-10-20** — `certverify.canSign(key, scheme)`: the family's candidate and, for RSA-PSS, a
  modulus large enough for the encoding (RFC 8017 §9.1.1: emLen ≥ 2·hLen + 2 — a 1024-bit key
  has no `rsa_pss_rsae_sha512`). Found by BoGo's `RSA-PSS-Large` through `tlsserver`.
- **2026-10-20** — `kex`: secp384r1 (0x0018, std `P384`): `generate`, `sharedSecret` (48-byte X
  coordinate), `serverExchange`; new `scalarLen(group)` (the private prefix a group uses). The NIST
  arms are one generic body for P-256 and P-384. Anchor: `cryptography` 46.0.5 / OpenSSL 3.5.5
  ECDH, both sides. Burn `kex_p384_burn` 112 KiB (measured 27 / 67 / 40 KiB), probed. For
  `tlsserver`, whose qap predecessor serves P-384 by default.
- **2026-10-20** — Fix: `certverify.sign` / `verify` no longer require the transcript hash to
  be as long as the signature scheme's hash (`HashLengthMismatch` is gone). RFC 8446 §4.4.3 signs
  the cipher suite's Transcript-Hash: an `ecdsa_secp256r1_sha256` certificate under
  TLS_AES_256_GCM_SHA384 signs a 48-octet hash, and an RSA key could not sign
  `rsa_pss_rsae_sha384/512` over dtls's SHA-256 transcripts. Found while building `tlsserver`.
- **2026-10-20** — `transcript.Transcript(Hash)`: the RFC 8446 §4.4.1 transcript hash (append,
  current hash, PSK-binder `wouldBeHash`, HelloRetryRequest `resetToMessageHash`), moved from
  `dtls/src/engine.zig` and made generic over the suite hash so SHA-384 suites
  (`TLS_AES_256_GCM_SHA384`) use it too. New anchors: RFC 8448 §3 and §5 (HRR) transcripts
  against the hashes the RFC prints. Fourth step of the `tlsserver` M0.

- **2026-10-20** — `kex`: the (EC)DHE key exchange (x25519, secp256r1, X25519MLKEM768:
  `generate`, `sharedSecret`, `serverExchange`, `expectedShareLen`), moved from
  `dtls/src/Connection.zig` (earlier history there). Secrets now come out through out-pointers,
  each entry point burns per group (96 / 112 / 160 KiB, measured by a new ReleaseFast stack probe)
  and zeroes `out` on an error. Anchors and tests moved with the code; new fuzz harness
  `tls13-kex` (160,000-run verdict clean, four planted mutants caught). Third step of the
  `tlsserver` M0.

- **2026-10-20** — `certverify`: the RFC 8446 §4.4.3 CertificateVerify signed content and
  sign/verify (ECDSA P-256/P-384 and Ed25519 through std, RSA-PSS through `rsa`), moved
  unchanged from `dtls` (earlier history: `modules/dtls/src/certverify.zig`) with its KAT
  vectors (exported as `certverify_kat_vectors`) and signer burns. New dependency: `rsa`.
  New: a deterministic fuzz harness over `certverify.verify` (`TLS13_FUZZ`, 320,000-run verdict
  clean, five planted mutants caught) and `example/main.zig` (a SHA-384 server-side schedule walk
  with a P-384 CertificateVerify). Second step of the `tlsserver` M0.

- **2026-10-20** — New module: the TLS 1.3 handshake building blocks shared by the TLS-family
  engines — first the RFC 8446 §7.1 key schedule, moved from `dtls` (earlier history: `modules/dtls/src/keyschedule.zig`; git does not follow the
  split) and split into one `Schedule(prefix)` per protocol (`tls13`, `dtls13`), plus the steps
  a TLS server needs that DTLS's PSK path did not: `resumptionBinderKey`,
  `deriveExporterMasterSecret`, `deriveResumptionMasterSecret`, `deriveResumptionPsk`,
  `nextApplicationTrafficSecret`. Anchored on RFC 8448 §3/§4 (every step of the `tls13`
  instance, including the new ones), an independent Python oracle for `dtls13`, and std's
  `hkdfExpandLabel` as a differential oracle for `tls13`. First step (M0) of the `tlsserver`
  plan.
