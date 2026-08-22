# signal — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-22** — **New: PQXDH** (`pqxdh.zig`), Signal's post-quantum initial
  key agreement — X3DH plus one ML-KEM-1024 encapsulation against a signed
  post-quantum prekey. Signal has run PQXDH by default since 2023, so X3DH
  alone was the legacy path, not the current one. `initiate`/`respond`,
  `generateKemPreKey`, the bundle and initial-message types, and flat
  `pq*`-prefixed re-exports from the module root.

  Three things a reader should not have to rediscover:

  * **The spec's KEM is not the deployed one.** The PQXDH document still says
    "Crystals-Kyber-1024" and cites the *initial public draft* of FIPS 203.
    Round-3 Kyber and FIPS-203 ML-KEM are not wire-compatible, and libsignal
    keeps them as separate key types. This implements ML-KEM-1024 (final),
    which is what runs.
  * **Every KEM prekey is signed**, one-time and last-resort alike, unlike
    curve one-time prekeys. A curve prekey is authenticated by the DH against
    Bob's identity key; a KEM prekey has no such binding.
  * **The associated data is 1632 bytes, and the ratchet's is still 64.**
    PQXDH's AD includes `Encode(PQPKB)` because ML-KEM's ciphertext does not
    commit to the public key it was made under, so a swapped KEM prekey would
    otherwise go unnoticed. That binding matters for the initial message,
    where the key is used; carrying 1568 extra bytes into every subsequent
    ratchet message would protect a key that no longer participates.
    `Agreement.ratchetAssociatedData()` is the documented bridge.

  Anchoring is weaker than this module's other parts and says so: **Signal
  publishes no byte-exact PQXDH vectors** (checked 2026-08-22, neither the
  spec nor libsignal). XEdDSA still carries libsignal's own vector and
  ML-KEM-1024 is anchored by std's FIPS 203 vectors, but the composition is
  checked against a second implementation of the same arithmetic
  (`scripts/pqxdh-kdf-check.py`, pinned in `interop_vectors.zig`) rather than
  against the protocol's authors. A round trip cannot catch a misplaced KEM
  secret — both sides would agree on the wrong answer — so the wrong answer is
  pinned too.
- **2026-08-13** — New `x3dh.generateKeyPair(io)` — the module's single source of private
  keys — and all four production draws now use it: the X3DH ephemeral
  `EKA` (`x3dh.initiateUnverified`), the signed prekey `SPKB`
  (`x3dh.generateSignedPreKey`), and both Double Ratchet DH keys
  (`ratchet.State.initAlice`, `ratchet.dhRatchet`). It is
  `std.crypto.dh.X25519.KeyPair.generate` verbatim with the seed taken
  from `entropy.fill` (`std.Io.randomSecure`) instead of `io.random`.
  **Not breaking:** `fill` returns `void`, so no signature changed. New
  dep: `entropy`.

  `std.Io.random` is a CSPRNG whose contract permits a silent fallback to
  a weaker seed (`std/Io.zig:2462`) and the default `Io.Threaded` takes
  it, seeding from a zeroed buffer plus an ASLR pointer, the pid and a
  clock. For X25519 the seed IS the secret key, so that fallback would
  have produced the identity, prekey, ephemeral and ratchet keys directly.
  The ratchet key is the sharper of the two: its freshness is the entire
  post-compromise-security claim, and a predictable one locks nobody out.

  This does NOT touch the KAT seam `CONVENTIONS.md` §2.2 names. Signal's
  published vectors are reproducible because `xeddsa.sign` takes its
  randomness `z` as a **parameter**, which the tests fill from
  `io.random`; no vector depends on where a keypair's seed came from.
- **2026-07-18** — Security audit: two findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Modeled on `libsignal` (Rust/C, Signal
  Foundation) (design reference, not a test anchor).
