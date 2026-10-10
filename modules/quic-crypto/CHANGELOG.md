# quic-crypto — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — Constant time: new `src/ctgrind_harness.zig` (targets `aes`, `chacha`, ReleaseFast). A 1-RTT traffic secret is tainted through `derivePacketKeys`, `advanceKeys`, `Protection.seal`/`open` and header protection (`computeMaskAes`/`computeMaskChaCha20`, `apply`, `remove`). 4 in-file contexts per target, none a branch on a key: `headerprot.remove` reading the packet-number length it has just unmasked (RFC 9001 §5.4.1; public to the endpoint) and the AEAD tag-verify outcome. Initial secrets and the Retry key are public by construction and not measured. No code change.
- **2026-10-09** — **BREAKING (dead-stack rule, CONVENTIONS §2.1.1):** secrets in by `*const`, secret results out
  through an `out` pointer, every entry point's body under a burn (new `src/burn.zig`).
  `deriveInitialSecrets(out: *InitialSecrets, dcid)` / `deriveInitialSecretsFor(ver, out, dcid)`;
  `derivePacketKeys(Hkdf, key_len, out: *PacketKeys, secret: *const ..)` / `derivePacketKeysFor(ver, ...)`;
  `advanceKeys(Hkdf, key_len, out: *KeyUpdate, secret: *const ..)` / `advanceKeysFor(ver, ...)` (`out.next_secret`
  may alias `secret`: ratchet in place); `Protection(A).seal/open` take the key as `*const [key_length]u8`.
  Burned: 8 KiB one-shot key derivations, 4 KiB per packet (`seal`/`open`, `computeMaskAes`,
  `computeMaskChaCha20`; their signatures are unchanged). New: `KeyUpdate` exported from `root.zig`. New probe
  `src/stackprobe_test.zig` (testkit engine) over every entry point; `check-secret-api` is at 0. Example and
  README migrated.

- **2026-10-05** — Tests: first dated mutation run (23 mutants, 22 killed, 1 equivalent; `SPEC.md`
  § "Mutation run 2026-10-05"). No defect; new boundary tests for the Retry pseudo-packet (2049
  octets) and `headerprot.apply` (`pn_offset` past the end, PN one octet past the end). No source
  change.

- **2026-09-30** — **Retry Integrity Tag (RFC 9001 §5.8) and QUIC v2 (RFC 9369).**
  New `retry.computeRetryTag` / `verifyRetryTag` (AES-128-GCM over the Retry
  Pseudo-Packet, fixed per-version key/nonce) and `Version` (`.v1`, `.v2`) with
  `deriveInitialSecretsFor`, `derivePacketKeysFor`, `advanceKeysFor` (v2 salt
  and `quicv2 *` labels), plus the v2 Retry key/nonce and the v1/v2 long-header
  packet-type codes. The existing unsuffixed functions are unchanged and mean
  v1. Anchored on RFC 9001 A.4 and RFC 9369 A.1-A.5, byte-exact, with negative
  tests. Scope raised from mvp to core: the module now covers the crypto a
  client or server needs for v1 and v2 including Retry.

- **2026-09-07** — **Test-only: `fuzzRemove` called `remove` with an EMPTY
  packet, a zero offset and an all-zero mask on every run, and so never got
  past its first line.** The harness drew `smith.bytes(&packet)` and then four
  more values: a ranged `len`, `smith.value(bool)` for the header form, a
  ranged `pn_offset`, and `smith.bytes(&mask)`. `bytes` consumes
  `@min(buf.len, in.len)` octets, so every draw after it found an exhausted
  input and returned its minimum — `len` 0, form `.short`, `pn_offset` 0, mask
  all zeroes. `remove` then returned `error.PacketTooShort` from its
  `packet.len == 0` guard. **`firstByteMask` was never evaluated and the
  §5.4.1 pn_len recovery this module exists to model had never executed
  once**, so the harness's own claim that `pn_offset` was "fuzzed too so
  short/zero-length PN windows and windows that hang off the end of `packet`
  are both hit deliberately" was false when it was written. The four arguments
  now come out of ONE `smith.slice` — a 7-octet script prefix (`form`,
  `pn_offset`, the five mask octets) followed by the packet — with a 14-seed
  corpus carrying the RFC 9001 Appendix A.2/A.3/A.5 protected headers at their
  real masks and offsets. Measured 2026-09-07: **0 of 14 seeds arrived
  non-empty and 0 calls got past the first guard before; 13 of 14 seeds, 9
  successful removals over 20 recovered PN octets, and all four on-wire
  `pn_len` values, after; the long-header branch went from 0 rounds to 6.**

- **2026-07-18** — Security audit: no findings. Byte-exact against RFC 9001 Appendix A's
  published test vectors.
- **2026-07-11** — New module: RFC 9001 (Using TLS to Secure QUIC) crypto seam.
