# megolm — SPEC

Matrix's Megolm group ratchet
([megolm.md][spec]); see [README.md](README.md) for purpose and API.
Provenance: see [NOTICE](NOTICE).

## Corrections to the informal description this module was commissioned
## against

The task that produced this module summarized Megolm from memory before
any primary source was read. Two details in that summary turned out
imprecise once the spec and reference implementations were actually
checked:

1. **"advancing part `i` rehashes it and resets every part to its
   right"** — correct in spirit, but the mechanism is not "rehash part
   `i` in place, then separately reset the others." It is: find the
   SLOWEST part `h` whose boundary the new counter crosses, then rehash
   `h` and **every part to `h`'s right** all FROM THE SAME (pre-update)
   value of part `h`, in one cascade — see `ratchet.zig`'s `advanceStep`.
   The distinction matters for the single-step case at index 1 in
   `kat_test.zig`: it does not exercise the cascade at all (nothing is to
   the right of part 3), so a broken implementation that skips the
   cascade entirely would still pass it. Only a boundary-crossing index
   (0x1000000, 0x1041506, or the wraparound cases) exposes the bug — see
   "Verification" below and the mutation-testing note there.
2. **The message cipher** — the task description didn't specify one, but
   it is worth stating precisely since it is NOT a design choice left to
   this module (unlike `signal`'s Double Ratchet, where the spec
   explicitly permits any AEAD): Megolm's spec **mandates** AES-256-CBC +
   PKCS#7 padding + HMAC-SHA-256 (truncated to 8 bytes) — megolm.md
   "Message encryption". This module implements exactly that, over the
   sibling `aescbc` module, and does not offer an AEAD alternative.

No other part of the informal description was found to be wrong; the
128-byte/four-32-byte-part ratchet shape, the "wound forwards, not
backwards" security property, the Ed25519 signature over the message
frame, and the `SESSION_KEY`/export-format existence were all confirmed
against the spec and reference implementations as described.

## Ratchet byte layout (`ratchet.zig`)

`R = R0 ‖ R1 ‖ R2 ‖ R3`, 32 bytes each, 128 bytes total. Advancing:

- `H_j(A) = HMAC-SHA-256(key = A, message = single byte 0x0j)` — the
  ratchet PART is the HMAC **key**, not the message. This detail is
  visible only in the reference implementations (libolm's
  `rehash_part`/vodozemac's `RatchetPart::hash`), not the spec's `H_j(A)`
  math notation, which doesn't say which HMAC argument `A` binds to.
- `advanceStep` (one message): find the slowest part `h` whose boundary
  the incremented counter crosses (part 3 every step, part 2 every 2^8,
  part 1 every 2^16, part 0 every 2^24), then cascade-rehash parts
  `3..h` all from the pre-update value of part `h`.
- `advanceToUnchecked` (arbitrary fast-forward): the same cascade,
  applied once per byte-position of the counter, in at most 4×255 ≈ 1020
  hash operations regardless of distance — this is the whole point of
  the four-part design (a plain single-part hash chain would need one
  hash PER skipped index). This primitive is UNCONDITIONAL: given a
  `target` numerically behind the current counter, it treats the 32-bit
  counter as a wraparound odometer and advances forward around the wrap
  point (a real edge case — see libolm's own `Megolm::advance wraparound`/
  `overflow`/`overflow by one` tests, ported into `kat_test.zig`).
- `advanceTo` (guarded): refuses any `target < counter` with
  `error.CannotRatchetBackward` instead of silently wrapping — every
  session-level caller in this module goes through this, never
  `advanceToUnchecked` directly. See "Threat model" below for why the
  unconditional primitive is not the default.

## Cipher (`cipher.zig`)

```
AES_KEY(32) ‖ HMAC_KEY(32) ‖ AES_IV(16) = HKDF-SHA-256(salt = "", ikm = R_i, info = "MEGOLM_KEYS", L = 80)
```

`salt = ""` (zero-length), not omitted from the call — RFC 5869 §2.2
treats an absent salt as `HashLen` zero bytes internally, and
`HkdfSha256.extract("", ikm)` computes exactly that (HMAC zero-pads a
too-short key regardless of what the padding looks like). AES-256-CBC via
the sibling `aescbc` module (PKCS#7 padding); the wire MAC is
HMAC-SHA-256 over `version ‖ payload`, truncated to its first 8 bytes
(spec: "The first 8 bytes of the MAC are appended to the message").

## Wire formats

**Message** (`message.zig`, spec version `0x03` — the ONLY version this
module implements; see "Scope note" below):

```
version(1) ‖ [tag 0x08, varint message_index] ‖ [tag 0x12, varint len, ciphertext] ‖ mac(8) ‖ signature(64)
```

The payload is a minimal two-field encoding in the shape Protocol Buffers
uses (LEB128 varints, tag-then-value) — not general Protocol Buffers.
The Ed25519 signature covers `version ‖ payload ‖ mac` (everything except
itself); the MAC covers `version ‖ payload` (everything except itself and
the signature). This ordering is why the reject-teeth in
"Verification"/`session.zig`'s module doc comment work out the way they
do: tampering the ciphertext OR the mac invalidates the signature too
(the signature covers both), so an outside attacker cannot produce a
message with a valid signature but a wrong MAC — only this module's OWN
test harness, holding the signing key, can construct that state to prove
the MAC check is a real independent guard.

**Session-sharing format** (`session_key.zig`, `SessionKey`, version
`0x02`): `version(1) ‖ index(4, big-endian) ‖ ratchet(128) ‖ Kpub(32) ‖
signature(64)`, self-certifying (the embedded `Kpub` must validate the
signature over the leading 165 bytes). **Session-export format**
(`ExportedSessionKey`, version `0x01`): identical minus the signature —
used when handing over a RATCHETED-FORWARD copy of a session would
otherwise invalidate the original signature (megolm.md "Session export
format"). Base64 is unpadded standard alphabet (matches both libolm and
vodozemac's own wire encoding).

### Scope note: message-format version 4 not implemented

vodozemac ships an experimental, non-default `Version::V2`/message
version `4` with a FULL (untruncated, 32-byte) MAC, gated behind its own
`experimental-session-config` feature flag and explicitly not the
default. That variant is NOT part of the published Megolm specification
(megolm.md only ever describes the 8-byte truncated MAC) — this module
implements only the spec's version `0x03`.

## Threat model / limitations (the spec's own, not gaps this module adds)

- **Message replays** (megolm.md "Message Replays"): a message can be
  decrypted successfully more than once — nothing in the wire format or
  this module prevents re-delivery of an old, valid message being treated
  as new. megolm.md recommends the APPLICATION track received ratchet
  indices and reject repeats; this module does not do so itself (no
  replay-index store is part of `InboundGroupSession`) — a caller that
  needs replay protection must add it.
- **Lack of transcript consistency** (megolm.md): nothing here guarantees
  every participant in a group received the same messages — out of
  scope, "the subject of future research" per the spec itself.
- **Lack of backward secrecy / post-compromise security** (megolm.md
  "Lack of Backward Secrecy"): compromising a Megolm session's key
  material at any point lets an attacker decrypt every message from that
  point forward — Megolm has no DH ratchet re-randomizing the chain (unlike
  `signal`'s Double Ratchet). Mitigation is session rotation, an
  application-level policy this module does not enforce.
- **Partial forward secrecy** (megolm.md "Partial Forward Secrecy"): an
  `InboundGroupSession`'s stored `initial_ratchet` can decrypt every
  message from `first_known_index` onward, forever, until the caller
  calls `forgetBefore` — the one-way ratchet itself doesn't expire
  anything.
- **`advanceToUnchecked`'s wraparound is intentional, `advanceTo`'s
  refusal is this module's addition, not the spec's.** The spec's own
  headline property is "wound forwards but not backwards"; the raw
  32-bit-counter arithmetic genuinely wraps (a real edge case a byte-exact
  port must handle — see the libolm wraparound/overflow vectors in
  `kat_test.zig`), but treating "wraps forward past 2^32" and "moves to
  an earlier index for free" as the same thing would be a real footgun
  for a caller who reaches for the unconditional primitive by habit. The
  guarded `advanceTo` — and, at the session level, `InboundGroupSession.
  decrypt`'s `error.MessageIndexTooOld` — are this module's own
  defensive additions on top of the spec, not requirements the spec
  states. See "Four distinct reject-teeth" below for why these are two
  DIFFERENT errors at two different layers.
- **`ExportedSessionKey` carries no signature.** Importing one
  (`InboundGroupSession.fromExportedKey`) sets `signing_key_verified =
  false`; authenticating the embedded `Kpub` (if the caller's threat
  model needs it) is entirely the caller's responsibility, exactly as
  vodozemac's own `InboundGroupSession::import` documents.
- **Dependency on the secure channel used to share `SessionKey`/
  `ExportedSessionKey`** (megolm.md "Dependency on secure channel for key
  exchange"): any weakness in that channel (unknown-key-share, replay)
  is inherited by the whole session — this module transports neither
  format itself; see README's "Scope".

## Four distinct reject-teeth

`InboundGroupSession.decrypt` (`session.zig`) returns one of four typed
errors on failure, never a generic "decrypt failed" and never a panic:

1. `error.InvalidSignature` — the Ed25519 signature over the message
   frame doesn't verify. Checked FIRST, before the ratchet is even
   located, so an unauthenticated message can't influence which ratchet
   state gets fast-forwarded.
2. `error.MessageIndexTooOld` — signature is fine, but the message's
   index is earlier than this session's `first_known_index`. A
   SESSION-level "we no longer have (or never had) that ratchet state"
   outcome — the one-way ratchet makes this permanent, by design.
3. `error.InvalidMac` — signature and index are fine, but the HMAC over
   the ciphertext doesn't match. See the "Wire formats" section above
   for why this is reachable in the wild only via a key mismatch, and how
   `kat_test.zig` constructs an honest test for it anyway (holding the
   signing key, corrupting the MAC, then re-signing over the corrupted
   bytes — proving the check is real and independent, not a claim that
   an outside attacker can reach this path without the signature check
   catching them first).
4. `error.InvalidPadding` — MAC passed, but the decrypted bytes aren't
   validly PKCS#7-padded. Reached only after the MAC check (padding-
   oracle discipline — see `cipher.zig`'s `decryptCbc` doc comment).

Separately, `ratchet.Ratchet.advanceTo` has its own
`error.CannotRatchetBackward` — a caller moving the RAW ratchet primitive
backward directly, a proactive guard distinct from `MessageIndexTooOld`'s
reactive "we already forgot that state" (see "Threat model" above).

## Verification / anchoring grades

This module distinguishes three grades of anchoring (see the top-level
task this module was built against): (1) published vectors from the spec
or a reference implementation, (2) in-house re-derivation against an
independent implementation, (3) self round-trip only.

| Area | Grade | Detail |
|---|---|---|
| Ratchet advance (`advanceStep`/`advanceToUnchecked`) | **1** | libolm's own `tests/test_megolm.cpp` — `expected1`/`expected2`/`expected3` byte-exact vectors (single step, a 2^24-boundary fast-forward, a further fast-forward crossing 2^24+2^16+2^8) plus the wraparound/overflow-by-one/double-wraparound vectors. Extracted programmatically (regex over the fetched `.cpp` source — see `kat_test.zig`'s module doc comment for the exact command), not hand-transcribed twice: a first by-eye transcription of the 128-byte ASCII seed misread `"...ABCDEF..."` as `"...ABDEF..."` (missing a `C`) — the programmatic re-extraction caught it before it reached a test. |
| Message/session-key wire codecs + full decrypt (`message.zig`, `session_key.zig`, `session.zig`) | **1 + 2** | Grade 1: a real libolm-produced `session_key` + `message` pair (`tests/test_group_session.cpp`, "Inbound group session export/import" test) decodes and decrypts byte-exactly to plaintext `"Message"` at index 0 through this module's OWN code (`SessionKey.fromBase64` → `InboundGroupSession.fromSessionKey` → `Message.fromBase64` → `.decrypt`). A second such pair from the "Invalid signature group message" test is used both as a positive (decrypts correctly) and negative (libolm's own last-byte-of-signature tamper, reproduced by decoding + flipping the raw byte + re-encoding, rejected as `InvalidSignature`) anchor. Grade 2: BOTH pairs were independently decoded/verified/decrypted end-to-end with a SEPARATE toolchain before being trusted (Python's `cryptography` for AES-CBC + HKDF-SHA256, stdlib `hmac`/`hashlib`, PyNaCl 1.5 for Ed25519) — none of which share code with libolm, vodozemac, or this module. Every layer (self-signature, message signature against the same key, derived keys producing a matching truncated MAC, AES-256-CBC/PKCS7 plaintext) reproduced independently. |
| Payload tag/varint header encoding | **1** | libolm's `tests/test_message.cpp`, "Group message encode test" — `_olm_encode_group_message(version=3, counter=200, ciphertext_len=10, ...)` produces `03 08 C8 01 12 0A`; pinned in `message.zig`. |
| `OutboundSession`↔`InboundGroupSession` round-trip, out-of-order delivery, export/import, forgetBefore | **3** | Self round-trip only — there is no published external vector for a FULL two-sided session exercise (only the single-message decrypt vectors above are published); these behaviors are exercised by this module's own `session.zig` tests instead. |
| The four reject-teeth (`InvalidSignature`/`MessageIndexTooOld`/`InvalidMac`/`InvalidPadding`) and `CannotRatchetBackward` | **1 (signature) + 3 (the rest)** | `InvalidSignature` is grade 1 (libolm's own tampered vector, above). The other three have no external "this exact tamper must fail this exact way" vector to anchor against (they are internal-consistency properties of this module's own layering) — grade 3, exercised directly in `kat_test.zig`/`session.zig`'s own tests, including the honest re-signed-bad-MAC construction described above. |
| `aescbc`/HKDF/HMAC/Ed25519 primitives themselves | n/a (inherited) | Anchored in their own modules (`aescbc`'s own SPEC.md; `std.crypto`'s HKDF/HMAC/Ed25519 are std, not re-verified here). |

### Mutation-testing note (required verification step)

Before this module was reported done, `ratchet.zig`'s `advanceStep` was
deliberately mutated to reseed ONLY the boundary-crossing part `h` itself
(`self.rehash(h, h)`), skipping the cascade into every part to its right
— exactly "the Megolm-specific mistake" this file's module doc comment
warns about, and one that still round-trips against itself (an
`OutboundSession`/`InboundGroupSession` pair running the SAME mutated
code still agree with each other on every message, since both sides
compute the identical, consistently-wrong ratchet). Running
`zig build test-megolm` against the mutated code failed exactly two
tests, both boundary-crossing cross-checks (never the non-boundary
single-step vectors, confirming the mutation is invisible without a
boundary-crossing case):

- `ratchet.zig`'s own "advanceStep and advanceTo(counter+1) agree, at
  every boundary depth" (byte divergence at a 2^8-boundary starting
  counter, where `advanceStep` — mutated — disagreed with the unmutated
  `advanceToUnchecked`).
- `kat_test.zig`'s libolm-vector overflow-by-one test (counter
  `0xffffffff` → `0`, an h=0 full-cascade case), where the mutated
  `advanceStep` disagreed with the correct `advanceToUnchecked`.

The mutation was then reverted via paired editing (not `git checkout`,
per this repository's standing hazard with that command) and the
restoration verified by re-running the full suite green (39/39) —
`modules/megolm/` is untracked (a brand-new module), so `git diff`
itself has no tracked baseline to compare against here; the restoration
was confirmed by direct byte-for-byte comparison of the pre- and
post-mutation source text instead.

[spec]: https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md
