# hpke — SPEC

See `README.md` for the consumer-facing API summary and Provenance note.

## What this is, in one paragraph

RFC 9180 Hybrid Public Key Encryption: a KEM (Encap/Decap over a DH group)
composed with an HKDF-based key schedule and an AEAD into a "seal to a
public key" / "open with the matching private key" primitive, plus a
multi-message `Context` for streaming use and a secret-export function
(§5.3) higher-level protocols can pull their own derived keys from (e.g.
MLS). This module targets the three DHKEM instantiations `std.crypto` can
drive without a C dependency — `dhkem_x25519_hkdf_sha256` (kem_id
0x0020), `dhkem_p256_hkdf_sha256` (kem_id 0x0010) and, since 2026-08-06,
`dhkem_p384_hkdf_sha384` (kem_id 0x0011) — each fixed to ITS OWN internal
KDF (HKDF-SHA256 for X25519/P-256, HKDF-SHA384 for P-384, RFC 9180 §7.1
Table 2), all three spec-named AEADs (AES-128-GCM, AES-256-GCM,
ChaCha20Poly1305), and all three spec-named OUTER key-schedule KDFs
(HKDF-SHA256/384/512, `Nh` = 32/48/64 — `schedule.KdfOf`/`kdfIdOf` dispatch
on `Nh`, see `schedule.zig`'s module doc comment) — a DHKEM's own internal
KDF and the ciphersuite's key-schedule KDF are RFC 9180's own SEPARATE
choices (§4.1 vs §7.2), so e.g. `DHKEM(P-256, HKDF-SHA256)` + an
HKDF-SHA512 key schedule (Appendix A.4) is a real, already-KATed
combination, not a hypothetical one — and `DHKEM(P-384, HKDF-SHA384)`
paired with an HKDF-SHA384 key schedule (the natural pairing, `Nh`=48 both
places) works the same way, just without an Appendix A vector to KAT it
against (see the P-384 done-record item below).

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

## Setup layer: `setup*S`/`setup*R` (RFC 9180 §5.1)

§6.1's single-shot `seal*`/`open*` wrappers (above) run `KeySchedule` and
immediately consume the resulting `Context` for exactly one `Seal`/`Open`,
never exposing it. §5.1 itself — `SetupBaseS`/`SetupBaseR` and the psk/
auth/auth_psk variants — is one layer lower: it returns the encapsulation
(sender side) and the `Context` itself, full stop, with no assumption the
caller wants to seal anything at all. Every mode has both halves:
`setupBaseS`/`setupBaseR`, `setupPskS`/`setupPskR`, `setupAuthS`/
`setupAuthR`, `setupAuthPskS`/`setupAuthPskR` (plus the `*Deterministic`
KAT seams on the sender side, same pattern as `sealBaseDeterministic`).

This is what a protocol layered over HPKE that only ever wants
`Context.Export` — never `Seal`/`Open` — needs: MLS (RFC 9420) §8.3
external initialization and §12.4 external commits derive their
`init_secret` this way. Added 2026-07-29 for exactly that consumer
(`modules/mls`); no new crypto — `setup*S`/`setup*R` call the identical
`Kem.encap*`/`Kem.decap*`/`Kem.authEncap*`/`Kem.authDecap*` +
`keySchedule` steps the single-shot wrappers already called, through two
small shared helpers (`setupEncapped`/`setupDecapped`) that `sealEncapped`/
`openDecapped` (the single-shot wrappers' shared body) now compose over
too, so both layers stay provably in sync rather than carrying two copies
of the same recipe.

KAT: every mode is re-driven through the real `setup*S`/`setup*R` entry
points against the same RFC 9180 Appendix A vectors already anchoring
`keySchedule` (A.1.1–A.1.4 over X25519, A.3.2–A.3.4 over P-256) —
`enc` and every `Context` field checked on both sides, one `Seal`/`Open`
round trip, and (the point of this pass) every published exported value
reproduced through `Context.exportSecret` called on the `Context` a
`setup*` caller actually receives, not a hand-built stand-in. Mutation-
checked: corrupting one byte of a published exported value turns the new
`setupBaseS`/`setupBaseR` test red (alongside the two tests that already
covered that byte), confirming the new path is not vacuous.

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
**§4.1**'s `DH(skX, pkY)` for NIST curves yields the X coordinate only,
verbatim: "For P-256, P-384, and P-521, the size Ndh of the Diffie-Hellman
shared secret is equal to 32, 48, and 66, respectively, corresponding to the
x-coordinate of the resulting elliptic curve point [IEEE1363]." (§4.1 also
fixes the failure mode: `DH` "can raise a ValidationError as described in
Section 7.1.4", not a deserialization error.) Earlier revisions of this file
cited §7.1.2 — which is "SerializePrivateKey and DeserializePrivateKey", not
`DH` — and quoted "a DHError error", a name that appears nowhere in RFC 9180
(audit BD-26). `dhkem.P256Kem`'s
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
- **KEM low-order/identity-element DH results.** RFC 9180 **§7.1.4**
  requires rejecting a DH computation that lands on the identity
  element — verbatim: "senders and recipients MUST ensure the Diffie-Hellman
  shared secret is not the point at infinity" and "recipients MUST check
  whether the Diffie-Hellman shared secret is the all-zero value and abort if
  so". (§7.1.1/§7.1.2, cited here before audit BD-26, only cover key
  *serialization* and defer validation to §7.1.4.) That is (X25519's documented all-zero output for a maliciously chosen
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
   (§4.1's x-coordinate rule, §7.1.1's SEC1 deserialization, §7.1.3's
   `DeriveKeyPair`) — x-coordinate-only ECDH
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

## Done-record — §5.1 setup layer for `mls` (2026-07-29)

14. ✅ **`setupBaseS`/`setupBaseR` + `setupPskS`/`setupPskR` +
    `setupAuthS`/`setupAuthR` + `setupAuthPskS`/`setupAuthPskR`** — see
    "Setup layer" above. `Context` and `keySchedule` were ALREADY public
    (re-exported at `hpke.Context`/`hpke.keySchedule`) and already
    KAT-driven directly against every mode's exported values (item 11);
    what was missing was purely the Encap/Decap+KeySchedule convenience
    composition RFC 9180 §5.1 itself names, one layer below §6.1's
    single-shot wrappers. `sealEncapped`/`openDecapped` (the single-shot
    wrappers' shared body) were refactored to compose over the new
    `setupEncapped`/`setupDecapped` helpers — behavior-preserving, verified
    by the full existing `zig build test-hpke` suite staying green
    unchanged. `modules/mls`'s `test-mls` also verified green (its only
    consumption of this module, `sealBase`/`openBase` in `crypto.zig`, is
    untouched).

## Done-record — HKDF-SHA384/SHA512 key-schedule KDF (2026-08-05)

15. ✅ **The outer key-schedule KDF is `Nh`-dispatched, not hard-wired to
    HKDF-SHA256.** Before this pass, `schedule.keySchedule`/
    `Context.exportSecret` called `std.crypto.kdf.hkdf.HkdfSha256` directly
    (a `comptime std.debug.assert(Nh == HkdfSha256.prk_length)` enforced
    the only value `Nh` could legally be), even though `suite.zig`'s
    `labeledExtract`/`labeledExpand` were ALREADY generic over any
    `Hkdf(Hmac)` instantiation — the hardcoding was one layer up, in
    `schedule.zig`. `schedule.KdfOf(Nh)` (public) now maps `Nh` — already
    threaded through every `Context`/`keySchedule`/`setup*`/`seal*`/`open*`
    signature, originally just for buffer sizing — to HKDF-SHA256 (32),
    HKDF-SHA384 (48, built from `std.crypto.kdf.hkdf.Hkdf` over
    `std.crypto.auth.hmac.sha2.HmacSha384`, since `std` names no
    `HkdfSha384` alias the way it does the other two), or HKDF-SHA512 (64);
    `kdfIdOf(Nh)` (private, next to `aeadIdOf`) supplies the matching
    `suite_id` byte so `suiteIdOf` embeds the RIGHT `kdf_id` per `Nh`
    instead of always `hkdf_sha256`. **No public signature changed** — an
    existing caller passing `Nh=32` (every caller before this pass,
    including `modules/mls`'s `sealBase`/`openBase` calls) gets the
    byte-identical HKDF-SHA256 path; the existing A.1/A.1.2/A.1.3/A.1.4/
    A.2/A.3/A.3.2/A.3.3/A.3.4 vectors all still pass unchanged (the
    regression net for this refactor).
    A DHKEM's OWN internal KDF (`dhkem.zig`'s `ExtractAndExpand`) is
    UNTOUCHED and deliberately so — RFC 9180 §7.1 Table 2 fixes it per
    `kem_id`, a separate choice from the ciphersuite's `kdf_id` this item
    widens (§4.1 vs §7.2/§7.2.1). KAT: RFC 9180 Appendix A.4 (`DHKEM(P-256,
    HKDF-SHA256), HKDF-SHA512, AES-128-GCM`) — `kat_rfc9180.zig`'s `a4` —
    is the first vector this module drives with `Nh` != 32: DHKEM
    Encap/Decap reproduce the published `enc`/`shared_secret` (still 32
    bytes, the KEM's `Nsecret`, UNCHANGED by the outer `kdf_id`),
    `key_schedule_context`/`secret` reproduced via
    `suite.labeledExtract(schedule.KdfOf(64), ...)` directly (checked
    separately from `keySchedule`, the same "own stage" discipline item 11
    used), `schedule.keySchedule(Aead, 64, ...)` reproduces
    `key`/`base_nonce`/`exporter_secret` (all 64-byte `Nh`-width, except
    `key`/`base_nonce` which are AEAD/nonce-width as always), all 6
    published `(seq, pt, aad, ct)` tuples sealed AND opened through the
    real `Context(Aead, 64)`, and `sealBaseDeterministic`/`openBase`
    (the §6.1 single-shot pair, exercising `suiteIdOf`'s `Nh`-dispatch too)
    reproduce `enc` + the first ciphertext end-to-end. A.4's vector was
    extracted from a local (no network fetch) copy of the RFC's own
    published `test-vectors.json`, bundled as Go's standard-library HPKE
    test fixture (`crypto/internal/hpke/testdata/rfc9180-vectors.json`) —
    present in this machine's Go module cache — not authored by this repo
    and not derived from this module's own output; A.4 does not carry an
    exported-value (§A.4.1.2) vector in that source, so `Context.
    exportSecret`'s HKDF-SHA512 path (`Context.exportSecret` itself is
    UNCHANGED code, already covered mechanically by `KdfOf`) has no
    byte-exact anchor for `Nh`=64 specifically — an honest narrower claim
    than every other vector in this file. Mutation-checked: temporarily
    mapping `kdfIdOf(64)` to `hkdf_sha384`'s id instead of `hkdf_sha512`'s
    compiles fine (the bug is a wrong CONSTANT, not a type/width error) and
    turns the A.4 `sealBaseDeterministic`/`openBase` KAT red — confirming
    `suiteIdOf`'s `Nh`-dispatch is load-bearing, not vacuous.
    HKDF-SHA384 (`Nh`=48) has no dedicated RFC 9180 Appendix A vector to
    anchor against (no Appendix A section pairs an HKDF-SHA384 key
    schedule with a KEM this module instantiates) — its correctness rests
    on `KdfOf(48)` being the identical `Hkdf(Hmac)` composition `KdfOf(32)`/
    `KdfOf(64)` already use, over `std.crypto.auth.hmac.sha2.HmacSha384`
    (std's own HMAC-SHA384, itself not this module's code), not a
    hand-rolled HKDF variant; there is no independent-of-this-module
    anchor for it, a real (if narrow) coverage gap flagged here rather
    than silently left implicit.

## Done-record — DHKEM(P-384, HKDF-SHA384) (2026-08-06)

16. ✅ **`dhkem.P384Kem`** — a third DHKEM, `kem_id` 0x0011 (RFC 9180 §7.1
    Table 2), structurally identical to `P256Kem`: `Npk`=97 (SEC1
    uncompressed `0x04 || X(48) || Y(48)`), `Nsk`=48, `Nsecret`=48, the same
    x-coordinate-only ECDH (`fromSec1(pk).mul(sk,.big).affineCoordinates().
    x.toBytes(.big)`), the same §7.1.3 rejection-sampling `deriveKeyPair`
    loop (`bitmask`=0xFF — P-384's 384-bit order needs no narrowing, same
    reasoning as P-256, unlike P-521's 0x01), and the same `AuthEncap`/
    `AuthDecap` `dh || dh2` fold. The one real difference: DHKEM(P-384, …)'s
    OWN internal KDF (RFC 9180 §7.1 Table 2) is HKDF-SHA384, not
    HKDF-SHA256 — the first KEM this module instantiates where that's true
    — so `dhkem.zig`'s shared `extractAndExpand` helper (previously
    hardcoded to `HkdfSha256`, correct for both prior KEMs) is now
    parameterized on the `Hkdf` type, with `X25519Kem`/`P256Kem` passing
    `HkdfSha256` explicitly at every call site and `P384Kem` passing a
    locally-built `Hkdf(HmacSha384)` (the same composition
    `schedule.KdfOf(48)` already uses for the OUTER key schedule — a
    coincidence of both landing on `Nh`=48, not a code-sharing shortcut:
    `dhkem.zig` does not import `schedule.zig`, since a DHKEM's own KDF and
    the outer key-schedule KDF are RFC 9180's own separate choices, the
    same discipline `schedule.zig`'s module doc comment already states for
    the reverse direction). `P384Kem`'s curve group is
    `std.crypto.ecc.P384` directly, not a new local perf-specialized
    module the way `p256` is for P-256 — `p256`'s README states its
    reason for existing is a measured perf gap on named hot paths (P2
    HTTPS-API JWT/TLS, 2FA/WebAuthn, `spake2plus`); nothing currently
    calls `hpke`'s P-384 path on such a path, so building on std directly
    (this repo's default posture) is the correct call here, not a
    corner cut.
    **No RFC 9180 Appendix A vector exists for DHKEM(P-384, HKDF-SHA384)
    at all.** This was checked, not assumed: (a) this module's own record
    of Appendix A's contents (done-record item 15 and "Verification
    status" §3 below, both written from an earlier faithful pass over the
    RFC) already enumerates every section — A.1/A.2 (X25519), A.3/A.4/A.5
    (P-256), A.6 (P-521), A.7 (export-only) — and none is P-384; (b) the
    offline `rfc9180-vectors.json` fixture bundled with the Go standard
    library's `crypto/internal/hpke` package (the same local, no-network
    source A.4 was extracted from, present in this machine's Go module
    cache under multiple toolchain versions) contains exactly 6 entries —
    X25519+AES128GCM, X25519+ChaCha, P256+AES128GCM, P256+SHA512+AES128GCM,
    P256+ChaCha, P521+SHA512+AES256GCM — and P-384 is not among them
    either. Go's own HPKE implementation supports P-384 curve arithmetic
    elsewhere (`crypto/ecdh`) yet chose not to include an HPKE P-384 test
    case, consistent with there being no RFC vector to draw one from. A
    wider local search (this machine's Go module cache across many
    toolchain versions, a bundled BoringSSL reference inside the Flutter
    engine checkout — build files only, no source present locally — this
    repo's own `audit/` notes, and the installed wolfSSL headers) turned
    up no P-384 HPKE vector anywhere on this machine, and no network
    fetch was available or used to look further. Per this repo's own
    convention (do not self-generate a vector and present it as an
    anchor — see done-record item 15's A.4-export-value gap and the
    module's history of a previously-reverted self-generated "anchor"),
    `P384Kem` is instead anchored the same way `P256Kem`'s own
    non-KAT-covered surfaces already are: RFC 9180 §7.1 Table 2's
    definitional `Npk`/`Nsk`/`Nsecret` widths and `kem_id` (type-width
    test), a pure-math `basePoint.mul`+`toUncompressedSec1` smoke test
    (scalar=1 → the curve's own basePoint), self-consistency round trips
    for `Encap`/`Decap`, `AuthEncap`/`AuthDecap` (including the
    wrong-`pkS`-diverges property) and `deriveKeyPair` (determinism,
    distinctness, on-curve, Encap/Decap round trip through a derived key),
    malformed-SEC1 rejection (`error.DeserializeError`), and fuzz coverage
    of `decap`/`authDecap` against arbitrary attacker-controlled bytes
    (`fuzzedSec1Bytes` generalized from `P256Kem`'s fuzz harness to a
    comptime-`N` helper so both KEMs' fuzzers share one biasing recipe).
    This is an honest, narrower claim than every A.1/A.2/A.3/A.4-anchored
    surface in this file: round-trip and structural tests cannot catch a
    misreading the sender and recipient share (see "Modes covered" above
    on why that matters), so `P384Kem`'s `AuthEncap`/`AuthDecap` fold in
    particular rests on being byte-for-byte the same recipe as the
    RFC-anchored `X25519Kem`/`P256Kem` folds, not an independent external
    check. Regression: the pre-existing A.1/A.1.2/A.1.3/A.1.4/A.2/A.3/
    A.3.2/A.3.3/A.3.4/A.4 vectors were re-run unchanged after this work —
    all still pass byte-exact — and `modules/mls`'s `test-mls` (the only
    downstream consumer) stays green.
    Teeth (replayed independently): temporarily changing `P384Kem`'s
    `kem_id` inside `extractAndExpand`'s `suite_id` construction (i.e. the
    KEM-context domain separator, analogous to done-record item 15's
    `kdfIdOf` mutation) breaks the `Encap`/`Decap` round trip test — a
    sender and receiver computing `kemSuiteId` from two different `kem_id`
    constants derive two different `eae_prk`s and disagree on
    `shared_secret`, so the mismatch is caught even without an external
    vector. Exit 1 mutated, exit 0 restored — see this repo's task record
    for the exact line and both exit codes.

    ⚠ **Corrected 2026-08-11 (re-audit).** The paragraph above used to be
    the whole teeth story, and it was not enough. The list of anchors above
    leaves ONE parameter unpinned: the KEM's own internal KDF. The
    type-width test asserts `HkdfSha384.prk_length == 48` and
    `P384Kem.Nsecret == 48`, but the first is a property of the *alias* and
    the second is a separately-declared constant that `extractAndExpand`
    takes as its own comptime parameter — `labeledExpand` expands to
    whatever length it is asked for. So swapping `P384Kem`'s four
    `extractAndExpand(HkdfSha384, …)` call sites to `HkdfSha256` (and,
    separately, to HKDF-SHA512) left the ENTIRE suite at **exit 0** — a
    module wire-incompatible with every other HPKE implementation, with
    every round trip still agreeing with itself. `dhkem.zig` now carries a
    discriminating test ("shared_secret matches an independent labeled-HKDF
    derivation") that recomputes `shared_secret` via std's one-shot
    `Hkdf.extract`/`.expand` over hand-concatenated labeled buffers instead
    of `suite.labeledExtract`'s streaming HMAC; the same SHA-256 mutation is
    now **exit 1**, clean tree **exit 0**.

## Verification status

1. **KAT (Debug + ReleaseFast):** `zig build test-hpke` — all tests
   pass, no skip guards. RFC 9180 Appendix A.1's full vector drives
   DHKEM Encap/Decap/DeriveKeyPair, KeySchedule, all 6 Seal/Open tuples,
   all 3 exports, and single-shot sealBase/openBase end-to-end through
   the real implementation; A.2 (ChaCha20Poly1305) and A.3 (P-256)
   headers byte-exact; and A.1.2/A.1.3/A.1.4 + A.3.2/A.3.3/A.3.4 drive
   the same full chain for `mode_psk`/`mode_auth`/`mode_auth_psk` over
   both KEMs. All seven of those vectors are ALSO driven through the
   `setup*S`/`setup*R` entry points directly (`driveSetupVector` in
   `kat_rfc9180.zig`) — `enc`, every `Context` field, one Seal/Open round
   trip, and every published exported value via `Context.exportSecret`
   called on the `Context` the new API hands back. A.4 (`DHKEM(P-256,
   HKDF-SHA256), HKDF-SHA512, AES-128-GCM`) drives the same DHKEM
   Encap/Decap + KeySchedule + all 6 Seal/Open tuples + single-shot
   sealBase/openBase chain with `Nh`=64 (HKDF-SHA512) instead of 32 — see
   done-record item 15. `P384Kem` (done-record item 16) is exercised by
   self-consistency round trips (Encap/Decap, AuthEncap/AuthDecap,
   DeriveKeyPair) and fuzz coverage, NOT an Appendix A vector — see that
   item for why none exists.
2. **Negative-path:** low-order X25519 pkR (`error.DhFailed`), malformed
   P-256/P-384 SEC1 (`error.DeserializeError`), AEAD tamper/wrong-aad/
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
3. **Open:** three narrow, explicitly-flagged gaps (see done-record items
   15/16). HKDF-SHA384 (`Nh`=48, the OUTER key-schedule KDF) has no RFC
   9180 Appendix A vector at all (no section pairs it with a KEM this
   module instantiates), so it rests on being the same `Hkdf(Hmac)`
   composition as the other two widths, not an independent anchor. A.4's
   `Context.exportSecret` output has no byte-exact anchor either (the
   offline `test-vectors.json` copy this module's A.4 was extracted from
   carries Setup+Encryptions but not Export). `P384Kem` (DHKEM(P-384,
   HKDF-SHA384) — the KEM's OWN internal KDF, a separate gap from the
   outer-KDF one above) has NO RFC 9180 Appendix A vector at all, checked
   against both this module's own record of the appendix's contents and
   the offline Go-stdlib `rfc9180-vectors.json` fixture (see done-record
   item 16); it is anchored by type widths, self-consistency round trips
   and malformed-input rejection instead. Otherwise, every RFC 9180
   surface this module implements has an embedded official vector. The
   Appendix A sections still NOT embedded are A.6 (P-521 — a KEM this
   module does not instantiate), A.7+ (export-only AEAD) and the
   `ChaCha20Poly1305` mode vectors of A.2/A.5, which differ from the
   embedded A.1/A.3/A.4 mode vectors only in the `aead_id`/`kdf_id` bytes
   of `suite_id` — already covered by their respective base headers.
