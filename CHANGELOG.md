# Changelog

**Index only.** This file lists which modules each dated tag touched; the
detail lives in `modules/<name>/CHANGELOG.md`, so a consumer of three modules
reads three files instead of scanning every release section here.

Tags are dates (`YYYY-MM-DD`), not semantic versions, and assert one thing:
every module passed every lane at that commit. Policy and the reasoning —
why semver would be both unenforceable and uninformative here — are in
`CONVENTIONS.md` §8. `v0.1.0` remains as history; nothing after it is a
semantic version.

## Unreleased

The collection grew 77 → 225 modules since v0.1.0, spanning pairing/EC
crypto, Bitcoin/Lightning, post-quantum, FHE/ZK/MPC, protocol security,
distributed fabric and kernel/networking. Most of that growth is new
modules with no history yet to record — their existence is what the
77 → 225 count above already says. Only modules that changed after being
introduced, or that carry an individually-named audit or performance
finding, have a changelog file; everything else correctly has none.

### Modules with a changelog

Each entry below is a one-line pointer; the detail lives in the linked
file. A `BREAKING` tag means the module's own changelog flags at least
one breaking change in its `Unreleased` section. Note that `BEHAVIOURAL,
not breaking` — which four of the middleware entries below carry — is a
different thing and is never tagged `BREAKING` here.

`zig build check-changelog` enforces both halves of this list: a module
changelog with no entry here, an entry here pointing at no file, and a
`BREAKING` tag that disagrees with the module's own `Unreleased` section
all fail the gate. See `CONVENTIONS.md` §8.

- [`acme`](modules/acme/CHANGELOG.md) — new `jws.generateKeyPair(io)`;
  both certificate-key draws now fail closed.
- [`bbs`](modules/bbs/CHANGELOG.md) — `proofGen`'s blinding scalars draw
  fail-closed entropy.
- [`bfv`](modules/bfv/CHANGELOG.md) — **BREAKING** — `keyGen`/`encrypt`/
  `genRelinKey` take `std.Io` instead of `std.Random`; the secret draws
  fail closed.
- [`bip340`](modules/bip340/CHANGELOG.md) — runtime-tag tagged hash,
  `xonlyBytesOf`.
- [`bls12_381`](modules/bls12_381/CHANGELOG.md) — `scalar.Fr.random`
  draws fail-closed entropy.
- [`brotli`](modules/brotli/CHANGELOG.md) — encoder now actually
  compresses (LZ77 + Huffman).
- [`chachapoly`](modules/chachapoly/CHANGELOG.md) — SIMD implementation
  (performance campaign).
- [`coconut`](modules/coconut/CHANGELOG.md) — **BREAKING** — `keygen`/
  `proveCredential` take `std.Io` instead of `std.Random`; the secret
  draws fail closed.
- [`cookies`](modules/cookies/CHANGELOG.md) — **BREAKING** — `set` no
  longer takes a caller-supplied buffer; new `max_set_cookie_bytes`.
- [`cors`](modules/cors/CHANGELOG.md) — BEHAVIOURAL, not breaking: the
  204 preflight no longer forces an early `ResponseWriter.end()`.
- [`csvsafe`](modules/csvsafe/CHANGELOG.md) — security-audit fix.
- [`decimal`](modules/decimal/CHANGELOG.md) — `Decimal`/`BigDecimal`
  interop, new `BigDecimal` ops.
- [`dnp3`](modules/dnp3/CHANGELOG.md) — security-audit memory-safety fix.
- [`dnssec`](modules/dnssec/CHANGELOG.md) — security-audit memory-safety
  fix.
- [`dtls`](modules/dtls/CHANGELOG.md) — **BREAKING** — HRR (both sides),
  fragment reassembly, live wolfSSL interop, negotiated
  `signature_algorithms`, anti-replay-window fix.
- [`ed448`](modules/ed448/CHANGELOG.md) — both `KeyPair.generate` entry
  points draw a fail-closed seed.
- [`entropy`](modules/entropy/CHANGELOG.md) — new: the fail-closed
  `fill`/`SecureSource` source for secret-bearing draws
  (`CONVENTIONS.md` §2.2).
- [`fss`](modules/fss/CHANGELOG.md) — **BREAKING** — default PRG swapped
  to fixed-key AES-128; `evalFull` for `Dpf`/`Mpf`.
- [`grpc`](modules/grpc/CHANGELOG.md) — new: gRPC client over HTTP/2.
- [`hpke`](modules/hpke/CHANGELOG.md) — **BREAKING** — RFC 9180 Appendix A
  vectors; PSK length floor.
- [`http`](modules/http/CHANGELOG.md) — **BREAKING** header/trailer
  bytes are copied (use-after-scope fix); new
  `error.HeaderBytesExhausted`.
- [`ibe`](modules/ibe/CHANGELOG.md) — `ciphersuite.randomSigma` draws
  fail-closed entropy; the master secret key follows `bls12_381`.
- [`json5`](modules/json5/CHANGELOG.md) — security-audit fix.
- [`k256`](modules/k256/CHANGELOG.md) — new `ecdsa_recover`; asm/Montgomery
  core (performance campaign).
- [`lninvoice`](modules/lninvoice/CHANGELOG.md) — ECDSA
  sign/recover moved to `k256`, re-exported.
- [`mcp`](modules/mcp/CHANGELOG.md) — server→client requests (sampling,
  elicitation); JSON-RPC fixes; security-audit fix.
- [`mcp-http`](modules/mcp-http/CHANGELOG.md) — transport half of `mcp`'s
  server→client requests; `application/json` body fix.
- [`megolm`](modules/megolm/CHANGELOG.md) — new: Matrix's Megolm group
  ratchet.
- [`minisign`](modules/minisign/CHANGELOG.md) — new: minisign file-format
  sign/verify.
- [`mls`](modules/mls/CHANGELOG.md) — external Commits (RFC 9420
  §12.4.3.2).
- [`montint`](modules/montint/CHANGELOG.md) — timing fix (Montgomery
  final-subtraction leak on the portable path); asm/Montgomery core
  (performance campaign).
- [`opcua`](modules/opcua/CHANGELOG.md) — security-audit memory-safety
  fix.
- [`p256`](modules/p256/CHANGELOG.md) — asm/Montgomery core (performance
  campaign).
- [`pir`](modules/pir/CHANGELOG.md) — malicious-server detection
  (`Verified`); keyword lookup.
- [`poseidon`](modules/poseidon/CHANGELOG.md) — new: Poseidon ZK-friendly
  hash over `bn254`/`bls12_381`.
- [`ramcache`](modules/ramcache/CHANGELOG.md) — new thread-safe `Sharded`
  option.
- [`ratelimit`](modules/ratelimit/CHANGELOG.md) — BEHAVIOURAL, not
  breaking: the 429 deny path no longer forces an early
  `ResponseWriter.end()`.
- [`rescue`](modules/rescue/CHANGELOG.md) — new: Rescue-Prime Optimized
  over Goldilocks.
- [`router`](modules/router/CHANGELOG.md) — BEHAVIOURAL, not breaking:
  the trailing-slash redirect no longer forces an early
  `ResponseWriter.end()`.
- [`saml`](modules/saml/CHANGELOG.md) — **BREAKING** — cross-form
  Holder-of-Key confirmation.
- [`security-headers`](modules/security-headers/CHANGELOG.md) —
  **BREAKING** — `init` now fallible, rejects a CSP that would exceed
  `http`'s header-byte budget at config time instead of 500ing at
  request time.
- [`sessions`](modules/sessions/CHANGELOG.md) — `Manager.newId` mints
  every session id from fail-closed entropy.
- [`signal`](modules/signal/CHANGELOG.md) — new
  `x3dh.generateKeyPair(io)`; all four production key draws fail closed.
- [`snmp`](modules/snmp/CHANGELOG.md) — **BREAKING** — library-generated
  USM privacy salt.
- [`stun`](modules/stun/CHANGELOG.md) — security-audit memory-safety fix.
- [`tfhe`](modules/tfhe/CHANGELOG.md) — **BREAKING** — keygen/encrypt entry
  points take `std.Io` instead of `std.Random`; the secret draws fail
  closed.
- [`threshold_ecdsa`](modules/threshold_ecdsa/CHANGELOG.md) —
  **BREAKING** — Paillier generator bound into Fiat-Shamir transcript.
- [`throttle`](modules/throttle/CHANGELOG.md) — BEHAVIOURAL, not
  breaking: the 503 shed path no longer forces an early
  `ResponseWriter.end()`.
- [`timelock_envelope`](modules/timelock_envelope/CHANGELOG.md) —
  `SealRandomness.generate` draws all three values fail-closed.
- [`tlock`](modules/tlock/CHANGELOG.md) — `ciphersuite.randomSigma`
  draws fail-closed entropy.
- [`tsdb`](modules/tsdb/CHANGELOG.md) — new: time-series persistence over
  `kvtree`.
- [`validate`](modules/validate/CHANGELOG.md) — security-audit O(n²)-DoS
  hardening.
- [`wireguard`](modules/wireguard/CHANGELOG.md) — `Keypair.generate` and
  `CookieChecker`'s three draws fail closed.
- [`x509`](modules/x509/CHANGELOG.md) — new `spkiOf`; security-audit
  memory-safety fix.
- [`zipstream`](modules/zipstream/CHANGELOG.md) — security-audit fix.

### Collection-wide notes (belong to no single module)

- **Security audit:** all CRIT/HIGH findings from a collection-wide audit
  were fixed. Findings named for a specific module are indexed above and
  detailed in that module's own changelog; this line is the pointer for
  the audit as a whole.
- **Performance campaign:** in addition to the per-module wins indexed
  above, audited hot paths across the collection landed within ~≤3× of C
  peers, and several constant-time leaks were fixed, in modules not
  individually named for either.
- **Tooling:** `zig build check-catalog` consistency gate added (found
  and fixed 6 modules missing README catalog rows), and
  `zig build check-changelog` for this index (found 16 module changelogs
  it had never listed — nothing had ever checked it).
- **Policy:** dated-tag versioning + spin-off policy adopted
  (`CONVENTIONS.md` §8); this changelog split is one product of it.

## v0.1.0 — 2026-07-10

Initial public release: 77 modules, 1844 tests, CI green in Debug +
ReleaseFast, MIT (fping-lineage attribution preserved in `NOTICE` §1).
