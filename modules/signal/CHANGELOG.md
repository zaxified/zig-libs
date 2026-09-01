# signal — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-01** — **Security audit: the post-quantum half of the handshake was
  the only part drawn from a source permitted to degrade.** `CONVENTIONS.md`
  §2.2 requires anything that becomes a key or ephemeral key material to come
  from `entropy.fill`/`io.randomSecure`, never `io.random`;
  `x3dh.generateKeyPair` was moved to the fail-closed source on 2026-08-13 for
  exactly that reason. PQXDH's two ML-KEM draws reached `io.random` anyway,
  through std's convenience wrappers: `Kem.KeyPair.generate(io)` mints Bob's
  **long-lived, signed** prekey — reused until rotation when `last_resort` —
  and `encaps(io)` draws the encapsulation message, which *is* `SS`.

  So every X25519 key in the file panicked rather than degrade, while the ML-KEM
  key and the KEM secret did not. On a host where `getrandom(2)` is unavailable
  the Diffie-Hellman half stays strong and the post-quantum contribution
  collapses — `SK` silently reduces to classical X3DH material, which is the
  precise failure PQXDH was added to prevent, with nothing to report it. Both
  now go through `entropy.fill` + `generateDeterministic`/`encapsDeterministic`.
  Pinned by a test that degrades `io.random` while leaving `randomSecure`
  intact; it carries a control assertion showing the curve keys are unaffected
  by the same degradation, so the contrast is the finding rather than a broken
  harness.

- **2026-09-01** — **`pqxdh.zig` claimed an anchor that belongs to another
  algorithm.** It said ML-KEM-1024 was "anchored by `std`'s FIPS 203 vectors".
  std's three `NIST KAT test` blocks are all `d00.Kyber512/768/1024` — the
  round-3 variant the same doc comment spends a paragraph explaining is *not*
  what this file implements. `nist.MLKem1024` has only `"Test happy flow"`, a
  `generateDeterministic → encapsDeterministic → decaps` self round trip. The
  KEM is unanchored and now says so; closing it means NIST ACVP vectors, the
  way `slhdsa` did. The PQXDH *composition* vectors were checked and are
  exactly what they claim to be — a second implementation, correctly labelled.

- **2026-09-01** — **The tool that keeps that anchor honest verified nothing.**
  `scripts/pqxdh-kdf-check.py` documented `--check` ("re-derive and diff
  against the pin"); `main()` ignored `argv`, so `--check` printed the vectors
  and exited 0 whether or not the pin matched. Implemented, and it exits 1 on
  a one-byte corruption. (The pin was in fact correct — all three vectors
  re-derived byte-for-byte.)

- **2026-09-01** — **`KemDecapsulationFailed` cannot fire, and its doc said the
  opposite.** FIPS 203 implicit rejection means std's `decaps` returns
  unconditionally on both branches, `cmov`ing to `J(z‖c)`, so the `catch` arm
  is dead. The error is kept for a future std that gains one, but the doc no
  longer invites a caller to read `respond` succeeding as ciphertext
  validation — a substituted ciphertext surfaces as a mismatched `SK`.

- **2026-09-01** — Smaller items from the same pass: `InitialMessage.deinit`
  now exists (its doc comment named it before it did, so following the
  documentation did not compile); `deriveSharedSecret` zeroizes the buffer
  holding `F ‖ DH1..DH4 ‖ SS` on both the PQXDH and X3DH paths; the example
  compares shared secrets with `timing_safe.eql` rather than `std.mem.eql`;
  `NOTICE` no longer says PQXDH is out of scope and now records the provenance
  class of the new vectors; and the README file table, `meta.doc` and the
  "two-part arc" status lines caught up with Part 3.


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
  spec nor libsignal). XEdDSA still carries libsignal's own vector, and
  the composition is checked against a second implementation of the same
  arithmetic
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
