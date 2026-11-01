# `tls13` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-01** — **Added:** `certverify.SecretKey.ed25519_prepared` (`*const Ed25519Signer`): signs and negotiates as `ed25519` through `sign`/`signContent`/`canSign`/`candidateSchemes`. **Performance:** `burn.ed25519_burn` 40 → 8 KiB (~0.8 µs per Ed25519 signature; the new Ed25519 stack probe, per-call key and prepared signer, is clean); with the comb change the prepared signer signs in 12.5 µs = 1.20× aws-lc-rs.
- **2026-11-01** — **Performance + Added:** Ed25519 CertificateVerify verification runs on `ct25519.verifyEd25519Strict` (std's `verifyStrict` verdicts, 1.75× → 0.97× aws-lc-rs); signing shares one field inversion between the two base multiplications. **Added:** `certverify.Ed25519Signer` (`init`/`initWith(sk, .once_at_load | .every_sign)`, `sign`, `signContent`, `deinit`) — the seed expansion and the check that the key's embedded public half is the seed's are done once at load, signing is then ONE base multiplication (4.3× → 1.36× aws-lc-rs with the check once). **Unchanged:** `certverify.sign` / `signContent` with `SecretKey.ed25519` still re-derive and compare the public key on every signature (= `.every_sign`, 2.1× aws-lc-rs); switching a caller to the prepared signer is the opt-in.
- **2026-11-01** — **Added:** `kex` groups secp521r1 (0x0019, RFC 8446 §4.2.8.2; `p521` comb key generation and `ecdhInto`, scalar drawn with the top byte masked to one bit), MLKEM512 (0x0200) and MLKEM768 (0x0201) (draft-ietf-tls-mlkem, same shape as MLKEM1024) on every entry point (`generate`, `serverExchange`, `sharedSecret`, `expand` and the `Expanded` variants; `Expanded` gains a `.mlkem512` arm). New burns, fuzz rotation (10 groups), stack probe, ctgrind rows; OpenSSL 3.5 oracle covers the three groups both ways with malformed-share verdicts; P-521 anchored by a `cryptography`/OpenSSL ECDH KAT. FFDHE stays out. No engine offers the groups yet.
- **2026-11-01** — **Tests:** live differential oracle against OpenSSL 3.5 libcrypto (`zig build interop-tls13`, `tools/interop.zig` + `tools/c_oracle/`): every RFC 8446 §7 secret at SHA-256/384 (against both TLS13-KDF and HKDF), all 7 `kex` groups both ways with OpenSSL's native hybrids plus malformed-share verdicts, all 10 CertificateVerify schemes both ways; its frozen transcript is replayed in `test-tls13` (`src/openssl_oracle_test.zig`). No library change.
- **2026-10-31** — **Added:** `kex.Expanded`, `kex.expand`, `kex.generateExpanded`, `kex.sharedSecretExpanded` (decapsulate with the expanded ML-KEM key kept from key generation; `sharedSecret`/`generate` unchanged). **Performance:** Ed25519 CertificateVerify signs over `ct25519`'s fixed-base comb (RFC 8032 §5.1.6, byte-identical to std's, RFC 8032 §7.1 vectors) — 2.44× → 0.94× OpenSSL; ECDSA P-256 verify no longer pays std's field inversion per key conversion — 1.14× → 0.87×. New `bench-tls13` (vs OpenSSL 3.5.5) and own ctgrind harness (key schedule, kex per group, signers).
- **2026-10-31** — **Added:** `kex` groups SecP256r1MLKEM768 (0x11eb) and SecP384r1MLKEM1024 (0x11ed), draft-ietf-tls-ecdhe-mlkem: ECDH element first in the client share, server share and shared secret (the reverse of X25519MLKEM768); P-256/P-384 through `p256`/`p384`, ML-KEM through std; new burns, fuzz harness and stack probe cover both. **Changed:** `KeyPair.secret` is 112 bytes (was 96), `SharedSecret.bytes` 80 (was 64), `max_share_len` / `max_server_share_len` 1665 (were 1568) -- use `.slice()` and the constants. Anchor: a Go 1.26 composition oracle (`tools/go_hybrid_oracle`, `crypto/ecdh` + `crypto/mlkem`), both directions. Doc comments of `root.zig` and `certverify` refreshed.

- **2026-10-28** — **Changed** (no consumer-reachable panic, CONVENTIONS.md §8): `exportKeyingMaterial` returns `ExportError` (`LabelTooLong`, `OutputTooLong`) instead of leaving the bounds to the caller — past `maxExporterLen` the HKDF counter wrapped silently in ReleaseFast. The `HkdfLabel` bounds (label with prefix, context: 255 octets) are a checked panic in every mode instead of an assert (an out-of-bounds stack write in ReleaseFast); so is a transcript message over the u24 length (it wrapped). `kex`: an error leaves `SharedSecret.len`, `public_len` at 0, so `slice()` stays in bounds. Wipes: the hybrid keygen's expanded ML-KEM-768 secret key, the Ed25519/P-521 signing noise. Audit recorded: review (no correctness finding against RFC 8446), mutation 50/51 (one equivalent); new tests for a share one octet long per curve, the exporter bounds, and Ed25519's cofactorless verify (a torsion component in R).

- **2026-10-22** — **Added:** `certverify.verifyContent` — `verify` over content the caller
  built (RFC 9345's delegated credential signature); `verify` now calls it. KAT: Ed25519.

- **2026-10-22** — **Added:** `certverify.signContent` — `sign` over content already built
  (`buildSignedContent`'s output), for a signer holding a key a TLS stack offloads
  (`tlsserver`'s `CertifiedKey.offload`); `sign` now calls it. KAT: equal to `sign`'s
  signatures (Ed25519, ECDSA P-384).

- **2026-10-21** — **Performance:** a full SHA-384 handshake's key schedule runs ~25 SHA-384
  compressions fewer, and its dead-stack burns zero ~170 KiB less. **Added:**
  `keyschedule.Schedule.deriveHandshakeSecretNoPsk` (the no-PSK early secret's `"derived"` salt
  as a constant, `noPskDerivedSalt`, from an independent Python computation, recomputed in a
  test), `deriveApplicationSecrets` (both application traffic secrets and the exporter master
  secret over one master-secret HMAC key setup) and `keyschedule.emptyTranscriptHash`.
  `deriveHandshakeTrafficSecrets`, `deriveApplicationTrafficSecrets` and `deriveTrafficKeyIv`
  absorb HMAC's key pads once per secret (RFC 2104 §4); outputs unchanged (the RFC 8448 KATs,
  and a test of the new path against HKDF-Expand-Label over both hashes, both prefixes, every
  output length). `certverify` signs ECDSA P-256/P-384 with `signWithSecretKey` (no `d·G` per
  signature; signatures unchanged). `kex`'s X25519MLKEM768 arms are out of line, so a curve
  group's frames are ~2 KiB: `kex_x25519/p256/p384_burn` 96/112/112 → 4 KiB, `ecdsa_burn`
  48 → 8 KiB, `ks_burn` 8 → 6 KiB, all measured by the stack probe with the burn off (new
  probes for ECDSA P-256/P-384 signing and the handshake's key-schedule steps).

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
