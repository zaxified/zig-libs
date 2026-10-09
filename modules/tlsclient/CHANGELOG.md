# `tlsclient` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — **HIGH: the established session's application secrets
  were left on the dead stack by `Client.init`'s by-value return.** New
  `Client.initInto(out: *Client, input, output, options)` writes the session to
  `out` inside the burned call tree; `init` keeps std's shape (doc comment points
  to `initInto`). The stack probe now drives a full server flight
  (EncryptedExtensions, Certificate, CertificateVerify, Finished) per group and
  suite: through `init` 640 needle windows over the 8 sets (client/server
  application traffic secrets and keys, in the wrapper's and the caller's
  frames) → 0 through `initInto`. The full flight reaches 296 KiB below the body,
  so `burn.init_burn` 320 → 384 KiB. Additive API, no wire change.

- **2026-10-09** — **HIGH: the ECDHE key shares and the handshake key schedule
  left their secrets on the dead stack after `Client.init`.** ReleaseFast stack
  probe (`stackprobe_test.zig`) drives `init` with a canned ServerHello per group
  and suite (reach checked via `ssl_key_log`); 16-byte needle windows found in 5
  calls, before → after: `x25519_ml_kem768` 2380 / 2460 (SHA-256 / SHA-384
  suite) → 0, `x25519` 2860 / 2965 → 0, `secp256r1` 2830 / 2930 → 0,
  `secp384r1` 2535 / 2630 → 0 (all four key pairs' seeds and scalars, the
  ML-KEM secret vector, the shared secrets, handshake/master secrets, handshake
  traffic secrets and keys, HMAC pads). `init` runs its body one frame down and
  zeroes 320 KiB afterwards (`burn.zig`; the body's frame is 181 KiB, dirty depth
  up to 237 KiB). No API or wire change. Not covered yet: the application
  traffic secrets and the rest of a full handshake (SPEC "Backlog / deferred").

- **2026-10-09** — **BREAKING, HIGH: the client-certificate signature left the
  key and the nonce on the dead stack; the P-256/P-384 ECDHE secret was
  multiplied in variable time.** New ReleaseFast stack probe
  (`stackprobe_test.zig`), 5 calls each, before → after: P-256 `d` 45, `k` 20,
  `k⁻¹` 20, `r·d`/`e+r·d` 10 each; P-384 `d` 60, `k` 30, `k⁻¹` 25, `r·d` 15,
  `e+r·d` 10; Ed25519 seed 10, scalar 15, prefix 15, nonce 60 — all now 0
  (they sat in std's signer frames, below the locals we already wiped).
  `signCertificateVerify` runs its body one frame down and zeroes 16 KiB after
  it (`burn.zig`; bodies dirtied ≤ 7.3 KiB). `ClientAuth.key` is now
  `*const ClientAuth.PrivateKey` (BREAKING: `.key = &key`), so `Options` copies
  never carry the key. The P-256/P-384 key share used std's `mulPublic` on our
  ephemeral scalar — documented "IN VARIABLE TIME", for public scalars; an
  inherited std bug — now `mul`. Not covered yet: the key shares' own secrets
  in std's frames (SPEC "Backlog / deferred").

- **2026-10-04** — **mvp → core.** Two opt-in additions to std's client, every
  edit marked `zig-libs tlsclient`; with default options the handshake is std's
  byte for byte (tested against std's own ClientHello). **ALPN** (RFC 7301):
  `Options.alpn_protocols`, `Client.alpn_protocol`; the answer must be exactly
  one offered name (`TlsIllegalParameter` otherwise). **TLS 1.3 client
  certificates** (RFC 8446 §4.4.2-4.4.3): `Options.client_auth` (`ClientAuth`:
  DER chain + ECDSA P-256/P-384 or Ed25519 key); a request that excludes our
  scheme gets an empty Certificate (§4.4.2.3); key copies wiped after signing.
  New `InitError` members `AlpnProtocolsInvalid`, `ClientCertificateTooLarge`,
  `ClientKeyInvalid` (reachable only through the new options). openssl
  `s_server` interop for both (loopback, throwaway fixtures); mutation 23
  mutants, 1 surviving with a reason (SPEC). Session resumption, TLS 1.2 client
  auth and RSA client keys stay deferred.
- **2026-09-25** — Test fix: the chain fuzzer's corpus seeds are now wrapped
  by `testkit.fuzz.seedInto`. `Smith.slice` reads a 4-byte length first, so
  the raw seeds lost their first bytes and never reached the verifier. The
  corpus test now reads the seeds back through `Smith`, as the fuzzer does
  (raw seeds fail it). Reported by qap.
- **2026-09-25** — New module: Zig 0.16's `std.crypto.tls.Client` with the
  server chain verified by `x509.verifyChain` (RFC 5280: basicConstraints,
  keyUsage, pathLen, nameConstraints, extKeyUsage serverAuth) and every peer
  certificate guarded by `x509.safe` -- closes ziglang/zig #35877, where any
  certificate holder could impersonate any host. Anchored against
  `openssl s_server` (honest chain accepted, forged chain refused, std's own
  client still accepting it as the retirement tripwire). Found by qap's
  M6.2 security review.
