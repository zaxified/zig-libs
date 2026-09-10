# sealedbox — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see ./README.md (no NOTICE entry — public NaCl standard, no third-party code).

## Design & invariants

- **Sealed box = ephemeral keypair + box:** generate an ephemeral X25519 keypair per message,
  derive the nonce as `blake2b(ephemeral_pk ++ recipient_pk)` (the NaCl seal convention), box the
  plaintext, and prepend the ephemeral public key. `open` recomputes the nonce and unboxes; a
  forged/tampered ciphertext fails the Poly1305 tag (authenticated). Modeled after libsodium
  `crypto_box_seal` / Go `nacl/box` — the public NaCl sealed-box standard; a thin layer over
  `std.crypto` (X25519 + XSalsa20-Poly1305 as provided by std). Original work of the zig-libs
  authors (MIT); no NOTICE entry needed (public NaCl standard, no third-party code).
- **Allocation-free**, reentrant; keys are fixed-size arrays. `publicFromSecret` /
  `keyPairFromSecretKey` recover a keypair from a stored secret (via std `X25519.recoverPublicKey`)
  so a persisted secret round-trips. Serialization is fixed-size base64/hex with typed errors.
- **No bespoke crypto:** every primitive comes from `std.crypto` — this module composes, it does
  not implement, cryptographic primitives.
- **`openAlloc` allocates before the tag is verified** (audit finding L7): the output buffer is
  allocated first and freed via `errdefer` on a failed `open`. The amplification is bounded (1×:
  one allocation the size of the plaintext, freed immediately on failure, never leaked — see the
  example's `DebugAllocator` leak check on exactly this path), so this is not a finding on its own,
  but a caller doing its own accounting for untrusted input should know the allocation happens
  before authentication, not after.

## Threat model / out of scope

- **Confidentiality + integrity to the recipient**, and **sender anonymity** (no sender key, so a
  message carries no sender identity). Tampering is detected (AEAD tag).
- **No sender authentication** — by design; the recipient cannot tell *who* sent a sealed box (a
  full box with both keys, which this module does not expose, is needed for authenticated sender).
- **No forward secrecy** beyond the per-message ephemeral key; recipient secret-key compromise
  decrypts all past sealed boxes to that key.
- **No primitive weakening:** X25519/XSalsa20-Poly1305/BLAKE2b are used exactly as `std.crypto`
  provides them — no custom KDF, no reduced-round variant, no home-rolled AEAD. Nonce derivation is
  deterministic-but-collision-safe by construction (fresh ephemeral key per call ⇒ fresh nonce
  input per call); the module never accepts a caller-supplied nonce that could be reused.
- **Constant-time scope (as implemented, and MEASURED).** The four SECRET-key text codecs —
  `encodeSecretKeyBase64`, `parseSecretKeyBase64`, `encodeSecretKeyHex`, `parseSecretKeyHex` — are
  table-free: no memory access in them has an address derived from key material, and no branch is
  taken on one, except the accept/reject the parsers return anyway. ⛔ This is **not** inherited
  from `std`: `std.base64` and `std.fmt.bytesToHex`/`hexToBytes` are table-driven, and until
  2026-09-09 these functions handed them secrets, which measured as **8 / 7 / 43 / 47** memcheck
  contexts — 95 of them on a LOAD, i.e. `movzbl <table>(%secret)`, the cache-timing class of
  T-table AES. The **public**-key codecs still use `std` on purpose: their input discloses nothing,
  so a table lookup there is not a leak and a hand-written decoder would be a worse trade.
- ⚠ **The claim above is held by optimisation barriers, not by how the code reads.** `ctEq`/`ctGe`
  launder their result mask through an empty `asm volatile` (`blackBox`, the montint `b199192`
  idiom). Measured on this module: with the barrier on the *input* instead, LLVM still recognised
  `ctEq(c,'+') & 62` as "62 or 0" and emitted a `test`/`je`. **Deleting `blackBox` as dead weight
  silently reverts this property**, and no value test can see it — `scripts/ctgrind.sh sealedbox`
  can, and its pins are exact. ⛔⛔ Verified by deploying the defect: with `blackBox` deleted,
  only `b64dec`'s **count** moves (1 → 5) — the other three rows are caught **only** by the
  source digest. On three of four rows the source pin is the whole gate.
- **Out of scope:** key management/storage, secret zeroization, side-channel hardening of the
  seal/open path beyond what `std.crypto` provides (that path is `std.crypto.nacl.SealedBox`
  verbatim), and the full `crypto_box` (authenticated two-party) API.

## Verification

RFC 7748-cross-checked X25519 KATs, end-to-end serialize→deserialize→seal→open, tamper/forgery
rejection, and malformed-key-input typed errors. Run: `zig build test-sealedbox`.

**Constant-time anchor:** `scripts/ctgrind.sh sealedbox` (valgrind/memcheck, ReleaseFast, the
secret — or, for the parsers, the secret-derived text — marked undefined). Pinned in
`scripts/ctgrind-expected.tsv`, exact, with an untainted control row and a no-`-fvalgrind` trap row
at 0 beside each:

| target | in-file | why |
|---|---:|---|
| `hexenc` / `b64enc` | **0** | pure arithmetic; the only indexed load left is `key[i]` over the loop counter |
| `hexdec` / `b64dec` | **1** | `if (invalid != 0)` — the accept/reject the parser returns to its caller. ⛔ A pin of 0 here would be wrong; what the claim forbids is an early exit revealing WHICH character was bad, and the decode loops contribute 0 |

**Value equivalence** is proved separately and exhaustively: every one of the 64 base64 indices, all
256 characters through both parsers, all 16 nibbles, plus 512 random keys checked against the
`std`-backed public-key codecs sitting next to them in the same binary. ⭐ That exhaustive agreement
is also the reminder that it proves the *values*: `hqc`'s table lookup agreed with its replacement
on all 65 536 pairs and still leaked, because what differed was the access pattern.

**External anchor for the seal/open composition (`kat_test.zig` / `kat_vectors.zig`, added
2026-07-28):** the tests above only round-trip through this module's own `seal`/`open` — a shared
misreading of the spec on both sides would still pass. Two independent anchors close that:

1. **Underlying `crypto_box_easy` layer** — the classic djb/NaCl `crypto_box` test vector (Alice's
   secret key + Bob's public key = RFC 7748 §6.1's own X25519 test keypairs, a fixed nonce, and a
   published ciphertext) from libsodium's `test/default/box.c` + `box.exp`
   (github.com/jedisct1/libsodium, fetched 2026-07-28). `std.crypto.nacl.Box.seal`/`.open` — the
   primitive `SealedBox` composes on top of — reproduces the published 147-byte
   `tag ‖ ciphertext` byte-exact on the first try.
2. **The full `crypto_box_seal` composition** (ephemeral key + BLAKE2b nonce + box) — libsodium's
   *own* test suite (`test/default/box_seal.c`) cannot publish a fixed expected ciphertext because
   `crypto_box_seal` uses a random ephemeral key by construction (confirmed by reading that file:
   it only checks a random round-trip). This module's `seal(io, ...)` takes its ephemeral-key
   entropy through the caller-supplied `io: std.Io`, so a test `Io` whose `.random` returns a fixed
   32-byte seed (RFC 7748 "Alice", reused as an arbitrary constant) makes the *entire* composition
   deterministic through the real, unmodified `seal()` — no source change. The expected output was
   computed independently via **PyNaCl** (a CFFI binding to the real libsodium C library, not this
   module) directly calling `crypto_scalarmult_base` / `crypto_generichash` (BLAKE2b-192) /
   `crypto_box` in the same order as libsodium's own `crypto_box_seal.c`
   (confirmed by reading that file). Result: byte-exact match on the first run — no
   interoperability divergence found. Teeth confirmed: corrupting one byte of the expected vector
   produces a real, reported mismatch (verified, then reverted).
3. **What remains unanchored, and why that's the honest limit:** libsodium's own published test
   data for `crypto_box_seal` itself is inherently non-deterministic (random ephemeral key), so no
   third-party-*published* fixed `crypto_box_seal` ciphertext exists anywhere to paste in; the
   vector above is the closest achievable substitute (real libsodium code, fixed inputs we chose),
   not a vector libsodium itself publishes.

## Performance

Audit finding M5: an earlier record (`20260808-zig-libs-audit/modules/sealedbox.md` B3) claimed
this module "INHERITS std X25519 ... (NOT a finding)" citing a measurement against OpenSSL made for
a *different* module, not `crypto_box_seal` against libsodium. Measured directly, same host, three
rounds, `CLOCK_PROCESS_CPUTIME_ID` (`A1/repro/sealedbox/bench.zig` + `bench_sodium.c`):

| operation | size | `sealedbox` (µs/op) | libsodium 1.0.18 (µs/op) | ratio |
|---|---|---|---|---|
| seal | 32 B | 112.7 | 84.9 | 1.33x slower |
| open | 32 B | 54.5 | 43.9 | 1.24x |
| seal | 1 kB | 111.2 | 84.9 | 1.31x |
| open | 1 kB | 61.0 | 45.9 | 1.33x |
| seal | 64 kB | 303.3 | 128.4 | 2.36x slower |
| open | 64 kB | 249.1 | 88.9 | 2.80x slower |

Marginal breakdown (64 kB − 1 kB): the asymmetric part (X25519) is ~1.28x slower than libsodium,
close to the earlier estimate; the symmetric part (XSalsa20-Poly1305) is **4.4x** slower —
std's Salsa20 is scalar, libsodium 1.0.18's is vectorized. Not a defect: this module implements no
symmetric cipher of its own, it composes `std.crypto`. A caller sending large (~64 kB-class)
messages through `sealedbox` should budget for this gap; small (config-key-sized) payloads are
within ~1.3x either way.

## Backlog / deferred

- **Reviewed 2026-07-10** (adversarial security pass, alongside `hashdigest`) — clean: faithful
  `std.crypto` wrapper, no accidental weakening (key/nonce reuse, truncation, or a silent fallback
  to something weaker) found.
- No other gaps found — the full `crypto_box` (authenticated two-party) API and secret zeroization
  are documented out-of-scope, not v1 gaps.

## Status

`extract · any · util · reentrant` + deps: none (`std.crypto` only) — canonical source is
`pub const meta` in src/root.zig.

## Anchoring

**Anchor grade:** class B · oracle EXTERNAL

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** libsodium C lib called via FFI to compute expected ciphertexts (kat_vectors.zig)
