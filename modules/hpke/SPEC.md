# hpke — SPEC

See `README.md` for the consumer-facing API summary and Provenance note.

## What this is, in one paragraph

RFC 9180 Hybrid Public Key Encryption: a KEM (Encap/Decap over a DH group)
composed with an HKDF-based key schedule and an AEAD into a "seal to a
public key" / "open with the matching private key" primitive, plus a
multi-message `Context` for streaming use and a secret-export function
(§5.3) higher-level protocols can pull their own derived keys from (e.g.
MLS). This module targets the two DHKEM instantiations `std.crypto` can
drive without a C dependency — `dhkem_x25519_hkdf_sha256` (kem_id
0x0020) and `dhkem_p256_hkdf_sha256` (kem_id 0x0010) — both paired with
HKDF-SHA256, and all three spec-named AEADs (AES-128-GCM, AES-256-GCM,
ChaCha20Poly1305).

## Modes covered (RFC 9180 §5.1 Table 1)

| Mode | Value | Needs |
|---|---|---|
| `base` | 0x00 | nothing extra — `Encap(pkR)` only |
| `psk` | 0x01 | a pre-shared key + its id |
| `auth` | 0x02 | the sender's static KEM keypair (`AuthEncap`/`AuthDecap`) |
| `auth_psk` | 0x03 | both of the above |

All four are represented in `suite.Mode`; `dhkem.zig` implements
`AuthEncap`/`AuthDecap` alongside base `Encap`/`Decap`; `schedule.zig`'s
`keySchedule` takes `psk`/`psk_id` as plain `[]const u8` (empty slices for
`base`/`auth`) rather than an `?[]const u8` — RFC 9180's own
`VerifyPSKInputs` check (documented in `keySchedule`'s doc comment,
`KeyScheduleError.InconsistentPsk`) is the place mode/PSK consistency
gets enforced, not the type system.

**All four modes are externally anchored** (2026-07-28): every mode is
driven end-to-end against RFC 9180's own Appendix A vectors — A.1.1/A.1.2/
A.1.3/A.1.4 over `DHKEM(X25519)+AES-128-GCM` and A.3.1–A.3.4 over
`DHKEM(P-256)+AES-128-GCM` — comparing `DeriveKeyPair` output, `enc`,
`shared_secret`, `key_schedule_context`, `secret`, `key`, `base_nonce`,
`exporter_secret`, the published ciphertexts and the published exported
values byte-for-byte. This matters more for the non-base modes than the
count of extra tests suggests: `psk`/`auth`/`auth_psk` were previously
reachable only through a hand-composed `keySchedule` + KEM call and were
verified only by this module's own round trip, and **a round trip passes
even when the sender and the recipient share the same misreading of §5.1**
(a wrong mode byte, a `psk_id_hash` over the wrong input, a `dh || dh2`
concatenated in the wrong order). Each mode also has a §6.1 single-shot
wrapper pair (`sealPsk`/`openPsk`, `sealAuth`/`openAuth`,
`sealAuthPsk`/`openAuthPsk`) alongside `sealBase`/`openBase`, KATed against
the same vectors' `enc` + first ciphertext.

**One deliberate deviation from the RFC's pseudocode: the PSK-length
floor.** RFC 9180 §5.1.2 — "The PSK MUST have at least 32 bytes of entropy
and SHOULD be of length Nh bytes or longer" — is normative prose that the
spec's own `VerifyPSKInputs()` pseudocode does not encode. A PSK shorter
than 32 bytes cannot carry 32 bytes of entropy, so its LENGTH is the one
checkable projection of that MUST (entropy of a long-enough PSK is not
observable from the bytes), and `keySchedule` rejects it with
`KeyScheduleError.PskTooShort`. The floor is `Nh` (32 for HKDF-SHA256),
inclusive — the RFC's own Appendix A PSK vectors are exactly 32 bytes, so a
stricter floor would reject the spec's test vectors. Consistency
(`VerifyPSKInputs`) is checked FIRST, so a caller with the mode/PSK
combination wrong still gets the RFC's own diagnosis (`InconsistentPsk`)
rather than a length complaint about a PSK that should not have been
supplied at all.

## Design & invariants

**Two-pass shape, following `noise`/`tlsresume`/`ssh`'s precedent — both
passes now done.** The RFC's domain-separation machinery (`suite_id`/
`LabeledExtract`/`LabeledExpand`, §4) landed real in the scaffolding
pass (pure composition over `std.crypto.kdf.hkdf`). The DH exchange, the
key-schedule composition, and the AEAD seal/open — each a
security-critical recipe (which bytes get concatenated in which order,
which value is the salt vs the IKM, when to reject a low-order DH
result) — were filled in by the dedicated crypto-implementation pass
(2026-07-12) and are KAT-validated byte-exact against RFC 9180 Appendix
A.1/A.2/A.3 (see the done-record checklist below).

**`LabeledExtract` streams; `LabeledExpand` doesn't (implementation
detail, not a spec requirement).** `Hkdf.extractInit`/`.update`/`.final`
let `labeledExtract` avoid a fixed-size scratch buffer entirely — `ikm`
(a DH output, or an application PSK) can be arbitrary length. `Hkdf.expand`
takes one contiguous `ctx` slice (re-hashed per output block internally),
so `labeledExpand` assembles `I2OSP(L,2) || "HPKE-v1" || suite_id ||
label || info` into a bounded 512-byte `std.Io.Writer.fixed` scratch
buffer, returning `error.LabelTooLong` rather than silently truncating or
panicking if `info`/`exporter_context` doesn't fit — realistic
application info strings fit comfortably; nothing in RFC 9180 bounds
`info` more tightly than "an octet string."

**Nonce framing.** `schedule.computeNonce` (`base_nonce XOR I2OSP(seq,
Nn)`) and `incrementSeq` (fail-closed at `maxInt(u64)`, no wraparound)
are pure arithmetic, KAT-validated against all 6 of RFC 9180 A.1.1's
published `(seq, nonce)` pairs — including the two that skip ahead (seq
4 after 0/1/2, seq 256 after 255), which specifically proves a correct
implementation must derive the nonce from `seq` directly rather than
incrementally XOR-updating a running nonce value. `Context.seal`/`.open`
additionally fail closed BEFORE touching the AEAD when `seq` sits at the
ceiling (returning a ciphertext alongside a `MessageLimitReached` would
leave a context whose next call reuses the nonce), and `open` advances
`seq` only after a SUCCESSFUL decrypt — see the threat model below for
why this sequencing matters.

**`u64` sequence counter, not the spec's full `2^(8*Nn)-1`.** RFC 9180's
`seq` is conceptually unbounded up to `2^96-1` (Nn=12 for every AEAD this
module targets); this implementation narrows the overflow ceiling to
`maxInt(u64)`. This is a conservative SUB-range of the spec's actual
limit (2^64-1 messages is already far beyond any realistic single
context's lifetime) — `computeNonce`'s big-endian right-alignment is
byte-identical to the full-width spec calculation for every `seq` value
that fits in 64 bits, so nothing in the covered range diverges from RFC
9180; only the point where a real implementation would fail closed moves
earlier (fewer messages before mandatory rekey), never later.

**P-256's DH is an x-coordinate-only ECDH, not std's `X25519.scalarmult`
shape.** `std.crypto.ecc.P256` exposes point arithmetic
(`fromSec1`/`toUncompressedSec1`/`mul`/`affineCoordinates`), not a
packaged "DH function" the way `std.crypto.dh.X25519` does — RFC 9180
§7.1.2's `DH(skX, pkY)` for NIST curves is "the shared point's X
coordinate only" (§7.1.2: "This function can raise a DeserializeError
error... and a DHError error"), which `dhkem.P256Kem`'s
`encapDeterministic`/`decap` implement as
`P256.fromSec1(pk).mul(sk, .big).affineCoordinates().x.toBytes(.big)`
(NOT `.toUncompressedSec1()`, NOT the Y coordinate) — KAT-confirmed by
A.3's `shared_secret`. `P256Kem.KeyPair` is
this module's own struct (`{secret_key: [32]u8, public_key: [65]u8}`) —
std has no built-in P-256 keypair type to borrow the shape from.

**Ephemeral-injected `encapDeterministic`/`authEncapDeterministic` for
KAT reproducibility.** RFC 9180 Appendix A's vectors fix `skEm`/`pkEm` —
matching this repo's `bip340` (`aux_rand` parameter) and `jwe`'s A.3 KAT
(a fixed-stream `random` replacing real CEK/IV generation) precedent, the
deterministic entry points take the ephemeral `KeyPair` as a parameter
rather than drawing one from `std.Io` internally; `encap`/`authEncap` are
thin `generateKeyPair(io)` + `*Deterministic` wrappers for real callers.

## Threat model

- **Nonce reuse under `Context.seal`.** RFC 9180 §5.2 derives each
  message's AEAD nonce from a per-context `seq` counter — reusing a nonce
  under the same key (e.g. skipping the `incrementSeq` call, or calling
  `seal` concurrently on a shared `Context` without external
  synchronization) breaks AES-GCM/ChaCha20-Poly1305 confidentiality
  outright (nonce-reuse forgery, a full plaintext-recovery break for
  GCM). `seal` increments `seq` only after a successful encrypt and
  before returning — never skipped, and a `seq` that could not be
  advanced past the message is rejected BEFORE any ciphertext is
  produced. `Context` has no internal
  locking (`meta.concurrency = .reentrant`, mirroring `noise.CipherState`
  and `dtls`'s AEAD state) — a `Context` shared across threads without
  external synchronization is a caller error, not something this module
  guards against, matching this repo's no-hidden-locking convention.
- **Sequence-number overflow.** `incrementSeq`'s fail-closed
  `error.MessageLimitReached` at `maxInt(u64)` (a conservative sub-limit
  of RFC 9180's actual `2^(8*Nn)-1` ceiling, see Design above) exists
  specifically so a long-lived `Context` cannot be driven into nonce
  reuse by sheer message volume — the caller MUST re-key (a fresh
  `Encap`/`KeySchedule`) rather than continue, and the type never wraps
  silently.
- **KEM low-order/identity-element DH results.** RFC 9180 §7.1.1/§7.1.2
  both require rejecting a DH computation that lands on the identity
  element (X25519's documented all-zero output for a maliciously chosen
  public key, RFC 7748 §6.1; P-256's point-at-infinity) — silently
  proceeding would let a peer force a known, attacker-predictable
  `shared_secret`. Every `Encap`/`Decap`/`AuthEncap`/`AuthDecap` maps
  std's `IdentityElementError` rejection (performed const-time inside
  `X25519.scalarmult`/`P256.mul` themselves) to `error.DhFailed`, and
  the all-zero-pk X25519 case is regression-tested; P-256 additionally
  rejects malformed SEC1 encodings with `error.DeserializeError` before
  any scalar multiplication.
- **`auth`/`auth_psk` mode sender-key confusion.** `AuthEncap`/
  `AuthDecap` bind the SENDER's static key into the shared secret (`dh2 =
  DH(skS, pkR)` / `DH(skR, pkS)`) specifically so a receiver can be
  convinced the message came from a specific sender's static keypair —
  an implementation that accepts `auth` mode but never actually checks
  `pkS` is bound (e.g. silently falling back to unauthenticated `dh` only)
  would defeat the entire point of the mode. The signatures
  (`authEncapDeterministic`/`authDecap` both REQUIRE the extra key
  parameter, no optional-omit path) make that mistake a type error to
  attempt, not a runtime silent-downgrade; the binding is
  regression-tested (a wrong `pkS` decaps to a DIFFERENT shared secret).
- **`I2OSP`/label-buffer sizing.** `labeledExpand`'s bounded 512-byte
  scratch buffer returns `error.LabelTooLong` on overflow rather than
  panicking on caller-supplied `info`/`exporter_context` — an application
  that (unusually) wants to bind gigabytes of exporter context data gets
  a typed error, not an aborted process, on attacker-influenced-length
  input.
- **PSK handling is (almost) entirely the caller's responsibility.** This
  module never generates, stores, or rotates a PSK — `keySchedule` checks
  the mode/PSK-presence *shape* (RFC 9180's `VerifyPSKInputs`,
  `KeyScheduleError.InconsistentPsk`) plus §5.1.2's length floor
  (`KeyScheduleError.PskTooShort`, see "Modes covered" above), and nothing
  else: PSK freshness, rotation, storage and the actual ENTROPY of a
  long-enough PSK are the caller's, mirroring `tlsresume`'s STEK key
  material never being generated by that module either. A 32-byte counter
  passes the length floor and is still a catastrophic PSK; the floor
  removes only the failure mode that is detectable from the bytes.
- **`auth` mode is not a signature.** `AuthEncap`/`AuthDecap` authenticate
  the sender to *the specific recipient whose key was used* and to nobody
  else: the recipient can compute the same `shared_secret` themselves, so
  they can forge any "auth-mode message from that sender to themselves"
  and cannot prove one to a third party. RFC 9180 §9.1 also notes DHKEM's
  key-compromise-impersonation limit — an attacker holding `skR` can craft
  messages that appear to come from any sender. Applications needing
  transferable or third-party-verifiable sender authentication need a
  signature, not `mode_auth`.

## Done-record — crypto-implementation pass (2026-07-12)

The former dependency-ordered TODO(fable) checklist, each item now
implemented and KAT-verified (order preserved):

1. ✅ **`dhkem.X25519Kem.encapDeterministic`/`.decap`** (§4.1/§7.1.1) —
   `X25519.scalarmult` (std's own const-time identity rejection mapped
   to `error.DhFailed`) + the shared `extractAndExpand` helper
   (`labeledExtract("", "eae_prk", dh)` → `labeledExpand(...,
   "shared_secret", enc ‖ pkRm, 32)` under `kemSuiteId`). KAT:
   `kat_rfc9180.a1` `enc`/`shared_secret` byte-exact + Decap round trip;
   all-zero (low-order) pkR regression-tested to fail with
   `error.DhFailed`.
2. ✅ **`dhkem.X25519Kem.deriveKeyPair`** (§7.1.3) — `dkp_prk =
   LabeledExtract("", "dkp_prk", ikm)`; `sk = LabeledExpand(dkp_prk,
   "sk", "", 32)`; `X25519.KeyPair.generateDeterministic(sk)` (seed
   stored verbatim as `secret_key`, clamped at use). KAT: A.1.1's
   `skEm`/`pkEm` from `ikmE` AND `skRm`/`pkRm` from `ikmR`, byte-exact.
3. ✅ **`schedule.keySchedule`** (§5.1) — `VerifyPSKInputs` (psk/psk_id
   present-together + mode-consistency, `error.InconsistentPsk`) then
   the §5.1 psk_id_hash/info_hash/ksc/secret/key/base_nonce/
   exporter_secret chain. KAT: A.1.1's `key`/`base_nonce`/
   `exporter_secret` driven end-to-end from `shared_secret`; all four
   consistent and all four inconsistent mode/PSK combinations tested.
4. ✅ **`schedule.Context.seal`/`.open`** (§5.2) — `Aead.encrypt`/
   `.decrypt` at `computeNonce(seq)`, `incrementSeq` only after success,
   plus a fail-closed pre-check at `seq == maxInt(u64)` BEFORE any
   ciphertext is produced/consumed (see the threat model). KAT: all 6 of
   A.1.1's published `(seq, pt, aad, ct)` tuples through the real
   `Context` (seq 0/1/2 via self-increment, 4/255 via direct `seq`
   assignment — the `noise.CipherState.setNonce` precedent); tamper/
   wrong-aad/truncated-ct rejection without advancing `seq`.
5. ✅ **`schedule.Context.exportSecret`** (§5.3) — thin wrapper over
   `suite.labeledExpand(exporter_secret, "sec", ...)`. KAT: A.1.1.2's 3
   exported values through the method itself.
6. ✅ **`schedule.sealBase`/`.openBase`** (§6.1) — composition of 1+3+4,
   plus `sealBaseDeterministic` (ephemeral-injected KAT seam) and the
   comptime `aeadIdOf`/`suiteIdOf` suite-id assembly. KAT:
   `sealBaseDeterministic(X25519Kem, Aes128Gcm, ...)` reproduces A.1's
   `enc` + first ciphertext in one call; `openBase` recovers the
   plaintext; fresh-random-key round trips (X25519+AES-128-GCM and
   P-256+ChaCha20Poly1305) including a mismatched-`info` rejection.
7. ✅ **`dhkem.P256Kem.encapDeterministic`/`.decap`/`.deriveKeyPair`**
   (§7.1.2/§7.1.3) — x-coordinate-only ECDH
   (`P256.fromSec1(pk).mul(sk,.big).affineCoordinates().x.toBytes(.big)`,
   `error.DeserializeError` on malformed SEC1, `error.DhFailed` on
   identity) and the §7.1.3 rejection-sampling `deriveKeyPair` loop
   (`bitmask = 0xFF` for P-256, candidate rejected iff zero or ≥ n via
   `P256.scalar.rejectNonCanonical`). KAT: `kat_rfc9180.a3`'s
   `enc`/`shared_secret`; deriveKeyPair self-consistency (A.3's header
   publishes no `ikm` fields).
8. ✅ **`AuthEncap`/`AuthDecap`** for both KEMs (§4.1's `dh ‖ dh2` fold,
   one 64-byte ikm to a single `LabeledExtract`; `kem_context = enc ‖
   pkRm ‖ pkSm`) — **byte-exact against A.1.3/A.1.4 (X25519) and
   A.3.3/A.3.4 (P-256)** since 2026-07-28 (item 11); the older
   self-consistency round trips are kept for the property the vectors
   cannot express (a WRONG `pkS` must diverge).
9. ✅ **A.2 (`ChaCha20Poly1305`) end-to-end** — Encap/Decap +
   keySchedule (Nk=32) + seq-0 Seal reproduce `kat_rfc9180.a2`'s
   `shared_secret`/`key`/`base_nonce`/`exporter_secret`/`seq0_ct`.
10. ✅ **`psk`/`auth_psk` PSK-mode KAT** — closed by item 11 (was: "no
    Appendix A PSK-mode vector embedded; fetch §A.x.2 before relying on
    psk/auth_psk modes").

## Done-record — non-base-mode anchoring pass (2026-07-28)

11. ✅ **RFC 9180 A.1.2/A.1.3/A.1.4 + A.3.2/A.3.3/A.3.4 embedded and driven
    end-to-end** (`kat_rfc9180.zig`'s `a1_psk`/`a1_auth`/`a1_auth_psk`/
    `a3_psk`/`a3_auth`/`a3_auth_psk` + the generic `driveVector` harness),
    closing the module's last unanchored surface. Every stage is compared
    against the RFC's own published value, never against a re-derivation:
    `DeriveKeyPair(ikmE/ikmR/ikmS)` → `skEm`/`pkEm`, `skRm`/`pkRm`,
    `skSm`/`pkSm`; `Encap`/`AuthEncap` → `enc` + `shared_secret` and
    `Decap`/`AuthDecap` back; `key_schedule_context` reassembled from the
    §4 primitives (checked SEPARATELY from `keySchedule`, so a wrong mode
    byte or `psk_id_hash` names its own stage instead of surfacing as an
    opaque wrong `key`); `keySchedule` → `key`/`base_nonce`/
    `exporter_secret`; every published `(seq, pt, aad, ct)` tuple sealed
    AND opened; every published exported value. Side effects worth noting:
    A.3.2–A.3.4 publish `ikmE`/`ikmR`/`ikmS`, so **`P256Kem.deriveKeyPair`'s
    §7.1.3 rejection-sampling loop now has an RFC anchor too** (A.3.1's base
    header publishes no `ikm` fields, which is why it previously had only a
    self-consistency test). Each assertion stage was mutation-checked —
    corrupting one byte of `ikmS`, `key_schedule_context`, `shared_secret`,
    a `ct` or an `exported_value` each turns the suite red, so no stage is
    vacuous.
12. ✅ **§6.1 single-shot wrappers for the three non-base modes** —
    `sealPsk`/`openPsk`, `sealAuth`/`openAuth`, `sealAuthPsk`/`openAuthPsk`
    (+ `*Deterministic` KAT seams), mirroring `sealBase`/`openBase`'s shape
    and inferred error set exactly. All four modes now share ONE
    key-schedule-and-seal body (`sealEncapped`/`openDecapped`) instead of a
    per-mode copy — a per-mode copy is exactly where a `mode` or a `psk`
    argument silently goes missing, and such an omission still round-trips.
    KAT: A.1.2/A.1.3/A.1.4 and A.3.2/A.3.3/A.3.4 `enc` + first ciphertext
    through the one-call path.
13. ✅ **§5.1.2 PSK-length floor** (`KeyScheduleError.PskTooShort`) — see
    "Modes covered" above for the MUST-vs-SHOULD reasoning and why the
    floor sits at exactly `Nh`.

## Verification status

1. **KAT (Debug + ReleaseFast):** `zig build test-hpke` — 55/55 tests
   pass, zero skip guards. RFC 9180 Appendix A.1's full vector drives
   DHKEM Encap/Decap/DeriveKeyPair, KeySchedule, all 6 Seal/Open tuples,
   all 3 exports, and single-shot sealBase/openBase end-to-end through
   the real implementation; A.2 (ChaCha20Poly1305) and A.3 (P-256)
   headers byte-exact; and A.1.2/A.1.3/A.1.4 + A.3.2/A.3.3/A.3.4 drive
   the same full chain for `mode_psk`/`mode_auth`/`mode_auth_psk` over
   both KEMs.
2. **Negative-path:** low-order X25519 pkR (`error.DhFailed`), malformed
   P-256 SEC1 (`error.DeserializeError`), AEAD tamper/wrong-aad/
   truncated-ct (`error.DecryptionFailed`, `seq` not advanced),
   wrong-length `out` buffer on `seal`/`open` (`error.InvalidLength`,
   a real runtime check in every build mode, not a `std.debug.assert`
   ReleaseFast/ReleaseSmall would compile out — found in the 2026-07-21
   `zig-hpke` diff audit, `seq` confirmed not advanced), `seq`-ceiling
   fail-closed (`error.MessageLimitReached` before any AEAD call), all
   `VerifyPSKInputs` inconsistencies (`error.InconsistentPsk`), the
   §5.1.2 PSK floor (`error.PskTooShort` at 1/8/16/31 bytes, accepted at
   exactly 32), and per-mode single-shot rejection (wrong `pkS`, wrong
   `psk`, wrong `psk_id`, and opening an `auth_psk` ciphertext with
   `openAuth` or an `auth` ciphertext with `openBase`).
3. **Open:** nothing. Every RFC 9180 surface this module implements now
   has an embedded official vector. The Appendix A sections deliberately
   NOT embedded are the ones for suites this module does not instantiate
   (A.4/A.6's HKDF-SHA512 and P-521, A.7+'s export-only AEAD) plus the
   `ChaCha20Poly1305` mode vectors of A.2/A.5, which differ from the
   embedded A.1/A.3 mode vectors only in the `aead_id` byte of `suite_id`
   — already covered by the A.2 base header.
