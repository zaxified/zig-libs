# hpke — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — New: DHKEM(P-521, HKDF-SHA512), kem_id 0x0012 (`P521Kem`: Encap/Decap/AuthEncap/AuthDecap, DeriveKeyPair with RFC 9180 §7.1.3's 0x01 bitmask), on the new `p521` module (new dep). Anchored byte-exact to RFC 9180 A.6.1–A.6.4 (all four modes, every field; `src/kat_rfc9180_a6.zig` from `tools/gen_rfc9180_a6.py`). ctgrind targets `p521_decap`/`p521_authdecap` added.
- **2026-10-10** — Changed: PSKs of 32..Nh-1 bytes are now accepted for SHA-384/512 suites (the RFC's own floor; the old Nh floor refused RFC 9180 A.6 vectors). 31 bytes is still `PskTooShort` at every Nh (test in `schedule.zig`).
- **2026-10-09** — tests: deterministic fuzz driver `HPKE_FUZZ` over the existing harnesses (P-256 and P-384 `decap`/`authDecap` (genuine `enc` agrees with the sender, a damaged one diverges), plus single-shot seal/open over X25519, P-256 and P-384 in base and auth mode (genuine opens, damaged ciphertext, `enc`, aad, info and keys refused)).
- **2026-10-09** — `suite.labeledExtract` and `suite.labeledExpand` (public building blocks) now run under their own burn (`kdf_burn`, 4 KiB; nested in the KEM / key-schedule burns they only add zeroing). No signature changed. Probe: `src/stackprobe2_test.zig`.
- **2026-10-08** — **BREAKING + FIX (secrets on the dead stack, HIGH):** a new ReleaseFast stack probe (`src/stackprobe_test.zig`, the 2026-10-08 engine that also sees the caller's frame) found every secret of the module left in dead frames after every call. Per 5 calls, before: `deriveKeyPair` — `sk` 35 / 20 / 60 (X25519 / P-256 / P-384), `dkp_prk` 10–15; `encapDeterministic`/`decap` — the private key 5–45, the DH output 15–20 (P-256/P-384 also its `y` and both field-element images), `eae_prk` 15–20, the shared secret 10–30; `authEncap`/`authDecap` — both keys, `dh` and `dh2`, the shared secret; `setupBaseR` — `dh`, `eae_prk`, the shared secret, `secret` 20, the AEAD key 15, `exporter_secret` 30; `Context.seal` — the key and 60 AES round-key windows; `exportSecret` — `exporter_secret`; `sealBase`/`openBase` — the ephemeral key, shared secret, AEAD key, exporter secret. P-384 dirtied 12.6 KiB. After: 0 everywhere. **API (BREAKING):** private keys are `*const KeyPair` (`decap`, `authDecap`, `encapDeterministic`, `authEncapDeterministic`, every `setup*`/`seal*`/`open*`); secret results go into an `out` pointer, zeroed on error — `generateKeyPair(out, io)`, `deriveKeyPair(out, ikm)`, `encap(out, pkR, io)`, `encapDeterministic(out, pkR, &eph)`, `decap(out, enc, &skR)`, `authDecap(out, enc, &skR, pkS)`, `keySchedule(Aead, Nh, out, …)`, `setup*S(Kem, Aead, Nh, out: *Setup, …)`, `setup*R(Kem, Aead, Nh, out: *Context, …)`, `suite.labeledExtract(Hkdf, out, …)`; `suite.labeledExpand` takes the PRK by pointer. The single-shot `seal*` still return `Sealed` (only the public `enc`). Error sets are now named: `SetupSError`, `SetupRError`, `SealOnceError`, `OpenOnceError`. Every secret-touching entry point runs its body one frame down and burns (`src/burn.zig`: 32 KiB around a KEM, 8 KiB around `Context`/`keySchedule`). `mls`, the one in-repo consumer, migrated in the same change.

- **2026-09-09** — **NO CONSUMER-VISIBLE CHANGE:** `src/ctgrind_harness.zig` is added (A1 audit finding R2; the tier-A ctgrind queue, 28 modules). Measured ReleaseFast under valgrind, in-file contexts: **x25519_decap 1 / x25519_authdecap 2 / p256_decap 2 / p256_authdecap 4 / p384_decap 2 / p384_authdecap 4 / open 1**. Every target has an untainted control row and a no-`-fvalgrind` trap row, both 0, so the numbers are real taint propagation rather than a silent no-op. All three DHKEMs the module implements, `decap` and `authDecap` for each, plus `Context.open`. Neither `SPEC.md` nor `README.md` contains a constant-time claim; none was added. **Every context is class 2 and every one was disassembled** rather than assumed: the X25519 low-order-point check (`curve25519.zig:77`), P-256's and P-384's `rejectIdentity`, and the AEAD tag-verify branch — all checks the RFCs require and whose outcome the return value already discloses. ⭐ Notable: `p256`'s own harness explicitly declines to target the variable-base `P256.mul` path because "nothing in this module's own shipped API calls it with a secret scalar", and names an ECDH-style caller as the case that would belong elsewhere. DHKEM(P-256) is exactly that caller, so `group.zig:422`'s `mulCtWindowed` is measured here for the first time.

- **2026-09-08** — The four `decap`/`authDecap` fuzz harnesses now carry a
  corpus, and a guard test pins what it reaches. They had none, so each ran
  exactly ONE input: the empty one. `fuzzedSec1Bytes` opens with
  `smith.bytes`, which memsets an exhausted input to zero, and the tag
  selector behind it is a ranged draw, which returns its range MINIMUM when
  fewer than eight octets remain — so `enc[0]` was rewritten to `0x00` on
  every round and `fromSec1` refused on its first octet. Measured: 1 distinct
  tag octet, 0 points decoded, 0 shared secrets — `mul`,
  `affineCoordinates` and `extractAndExpand`, the code these targets exist to
  run on peer-supplied bytes, had never executed under them. The corpus feeds
  each draw the point octets plus the knob's own little-endian words; now 5
  distinct tag octets, 3 accepted and 2 distinct shared secrets per target,
  pinned as exact counts. Test-only; no API or wire change.

  ⚠ Recorded while measuring: selectors 1 and 2 (tags `0x02`/`0x03`) can
  never yield an accepted point in these harnesses, because `enc`/`pkS` are
  `[Npk]u8` arrays and `fromSec1` therefore always sees 65 (or 97) octets and
  refuses a compressed tag on length. They still walk the tag/length
  disagreement path, so they are kept rather than removed.

- **2026-08-14** — Provenance corrected: README and `NOTICE` both claimed no
  third-party implementation had been consulted as a design reference, while
  `src/schedule.zig:99`, `:1024` and `SPEC.md` all cite `jedisct1/zig-hpke`
  by name. It was consulted — the 2026-07-21 "I5" diff against it is what
  found the ReleaseFast-stripped `std.debug.assert` behind `Context.seal`/
  `.open` and produced `error.InvalidLength` (`15c6e89`). Recorded now with
  its licence (MIT). Documentation only; no code change, nothing owed —
  a design reference carries no condition.

- **2026-08-13** — Each KEM's `generateKeyPair` now mints its keypair the way RFC 9180 §4
  defines it — `GenerateKeyPair() = DeriveKeyPair(random(Nsk))` — with
  `random` being `entropy.fill` (`std.Io.randomSecure`). **Not breaking:**
  no signature changes, no wire byte changes, and the KAT-driven
  `deriveKeyPair`/`*Deterministic` entry points are untouched. New dep:
  `entropy`.

  Previously `X25519Kem` forwarded to `std.crypto.dh.X25519.KeyPair.
  generate` and the two NIST KEMs called `P{256,384}.scalar.random(io,
  .big)`. All three take their randomness from `std.Io.random`, whose
  contract permits a silent fallback to a weaker seed (`std/Io.zig:2462`);
  the default `Io.Threaded` takes it, seeding from a zeroed buffer plus an
  ASLR pointer, the pid and a clock. That is the sender's ephemeral key in
  every `encap`/`setup*S`/`seal*` call, i.e. the key the whole
  `shared_secret` rests on, and `generateKeyPair` returns a `KeyPair` with
  no error channel to report a degraded draw on.

  The X25519 KEM could have kept std's shape and swapped only the draw
  (`KeyPair.generateDeterministic` is public); the NIST KEMs could not,
  because `scalar.random`'s rejection loop is std-internal and takes the
  `io` itself. Rather than re-implement that loop, all three now go
  through this module's own `deriveKeyPair` — which means the keygen path
  is covered by the RFC 9180 A.1.1/A.3.3 vectors for the first time
  (`KeyPair.generate` and `scalar.random` never were). `P384Kem` gains no
  such anchor, since Appendix A publishes no P-384 vector.

  `mls` inherits the change through `S.Kem.generateKeyPair` (its
  `UpdatePath` leaf key) without any edit of its own.

- **2026-08-11** — Security audit: two findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against RFC
  9180's published test vectors.
- **2026-07-28** — `mode_psk`, `mode_auth` and `mode_auth_psk` are now anchored to RFC
  9180's own Appendix A vectors (A.1.2/3/4 for X25519, A.3.2/3/4 for
  P-256) instead of only to this module's round-trip; the implementations
  needed no correction. New single-shot wrappers `sealPsk`/`openPsk`,
  `sealAuth`/`openAuth`, `sealAuthPsk`/`openAuthPsk` alongside the
  existing `sealBase`/`openBase`. **BREAKING (behavioral):** a
  psk-bearing mode now rejects a PSK shorter than `Nh` with
  `error.PskTooShort` — deliberately stricter than the RFC's
  `VerifyPSKInputs` pseudocode, on the grounds that §5.1.2's "MUST have
  at least 32 bytes of entropy" cannot hold for a PSK shorter than 32
  bytes, and length is the only checkable projection of that
  requirement. Appendix A's own PSK vectors satisfy the floor.
