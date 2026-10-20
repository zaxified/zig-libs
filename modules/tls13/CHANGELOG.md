# `tls13` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
