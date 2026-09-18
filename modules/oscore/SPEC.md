# oscore — SPEC

OSCORE (Object Security for Constrained RESTful Environments, RFC 8613):
end-to-end application-layer security for CoAP, AES-CCM-16-64-128 +
HKDF-SHA-256 only. See [README.md](README.md) for purpose and API.
Provenance: see [NOTICE](NOTICE).

**Status: complete.** The §3.2.1 `info` CBOR encoder, the §5.4
`aad_array`/`Enc_structure` CBOR encoders, the §6.1 compressed COSE option
codec, the §3.2.2 anti-replay sliding window, and the six crypto cores
(`deriveKey`, `deriveContext`, `computeNonce`, `buildAad`, `protect`,
`unprotect`) are all implemented — no `@panic`/TODO stub remains in
`root.zig`. See "The six crypto cores" below for what each does and how
it is anchored.

## Design

- **Source of truth**: RFC 8613's own text (fetched from
  `www.rfc-editor.org/rfc/rfc8613.txt`) — no third-party OSCORE
  implementation was read or ported (see `NOTICE`). Only the
  MANDATORY-to-implement ciphersuite is in scope: AES-CCM-16-64-128 (COSE
  algorithm 10) for the AEAD, HKDF-SHA-256 for §3.2.1 key derivation —
  `Algorithm` has exactly one member.
- **`std.crypto.aead.aes_ccm.Aes128Ccm8` IS the exact target AEAD**: `Aes128Ccm8
  = AesCcm(Aes128, tag_len=8, nonce_len=13)` — 128-bit key, 13-byte nonce,
  8-byte tag, matching RFC 8152 §10.2's AES-CCM-16-64-128 definition
  field-for-field. `std.crypto.kdf.hkdf.HkdfSha256` supplies RFC 5869's
  two-phase `extract`/`expand`, exactly what §3.2.1 specifies. Neither is
  a gap; the OSCORE-specific construction AROUND them is.
- **Security context split** (§3.1): `CommonContext` (algorithm + Common
  IV), `SenderContext` (own ID + key + Sender Sequence Number),
  `RecipientContext` (peer ID + key + `ReplayWindow`) — bundled as
  `SecurityContext`. Deliberately mutable, single-owner state (`meta.
  concurrency = .single_owner`, same shape as `bolt8.Transport`): the
  Sender Sequence Number increments on every `protect`, the
  `ReplayWindow` slides on every accepted `unprotect`.
- **CoAP-agnostic by design**: `meta.deps = .{}` — no build dependency on
  the sibling `coap` module, and `protect`/`unprotect` never parse or
  build a CoAP message themselves. They operate on the §5.3 "plaintext"
  and §5.4 "options" as opaque caller-supplied byte strings. **No module
  in this repository calls it** — the sibling `coap` codec does not depend
  on `oscore`, and no seam between the two is built (A1 F16, 2026-09-13:
  the earlier wording promised that integration as if it existed). A
  consumer writes that wiring itself.
- **Exchange tracking is the caller's job**: matching a response back to
  the request that generated it (needed for §5.2's "reuse the request's
  nonce" majority case) is NOT this module's concern — `unprotect`'s
  `request_nonce_source` parameter takes whatever `(id, Partial IV)` the
  caller already tracked. `oscore` itself has no notion of a CoAP Token
  or an in-flight exchange table.

## The §5.2 AEAD nonce — exact byte layout

```text
 <- nonce_length-6 bytes -> <-- 5 bytes -->
+---+-------------------+--------+---------+-----+
| S |   zero padding    | ID_PIV | zero pad| PIV |----+
+---+-------------------+--------+---------+-----+    |
                                                       |
 <---------------- nonce_length ----------------->     |
+------------------------------------------------+    |
|                   Common IV                    |->(XOR)
+------------------------------------------------+    |
                                                       |
 <---------------- nonce_length ----------------->     |
+------------------------------------------------+    |
|                     Nonce                       |<---+
+------------------------------------------------+
```

At this module's only algorithm (`nonce_length = 13`), the ID_PIV field is
`nonce_length - 6 = 7` bytes wide (`id_piv_field_width`). `S` is a single
byte holding `id_piv.len` (NOT the field width — the actual ID length,
0-7). Both `ID_PIV` and the 5-byte `PIV` are LEFT-padded with zero bytes
(the real value right-aligned within its fixed-width field), then the
whole `S || id_piv_padded || piv_padded` block is XORed byte-for-byte
against the Common IV. Hand-verified against Appendix C.1 while writing
`computeNonce`'s doc comment: the client's Sender ID is empty (`S = 0`,
an all-zero block), so its sender nonce equals the Common IV UNCHANGED
(`0x4622d4dd6d944168eefb54987c` both times); its recipient nonce (`S = 1`,
`ID_PIV = 0x01`) differs from the Common IV in exactly the bytes the XOR
of `0x01 00 00 00 00 00 00 01 00 00 00 00 00` against the Common IV
predicts — `0x4722d4dd6d944169eefb54987c`, matching the RFC's published
value byte-for-byte.

## The §5.4 AAD — exact CBOR shape

```text
AAD = Enc_structure = [ "Encrypt0", h'', external_aad ]
external_aad = bstr .cbor aad_array
aad_array = [ oscore_version, [ alg_aead ], request_kid, request_piv, options ]
```

`encodeAadArray` (REAL) builds `aad_array`'s bytes directly. `encodeEncStructure`
(REAL, plain RFC 8152 COSE, not OSCORE-specific) wraps an already-serialized
byte string as `Enc_structure`'s third array element — note that
`external_aad`'s own CBOR encoding IS just "wrap these bytes in a bstr
header"; `encodeEncStructure`'s `external_aad` parameter takes the RAW
`aad_array` bytes and does that wrapping itself, matching the RFC's own
"`external_aad = bstr .cbor aad_array`" notation. `buildAad` is the
two-line composition of both. Every one of these three functions was
hand-verified against Appendix C.4's worked example while writing them:
`aad_array = 0x8501810a40411440` (8 bytes: array(5), uint(1), array(1)
containing uint(10), then three bstrs of length 0/1/0), and the full
`AAD = 0x8368456e63727970743040488501810a40411440` (20 bytes: array(3),
the 9-byte `text(8)"Encrypt0"`, the 1-byte `bstr(0)` protected header, then
`bstr(8)` wrapping those same 8 `aad_array` bytes).

**`request_kid`/`request_piv` are always the ORIGINAL REQUEST's own
values**, even when building the AAD for a RESPONSE (§5.4's own text:
"request_kid: contains the value of the 'kid' in the COSE object of the
request"). Appendix C.7/C.8 (responses to the C.4 request) both use the
SAME `aad_array`/`AAD` bytes as C.4 itself, confirming this: the AAD never
reflects the response's own (absent, or freshly-minted in C.8's case)
Partial IV/kid.

## The §3.2.2 replay window — REAL, not a crypto core

`ReplayWindow` is a sliding bitmap (`highest_seen: u64` + `mask: u64`),
the same algorithm family DTLS/IPsec anti-replay windows use (RFC 8613's
own §3.2.2 names RFC 6347 §4.1.2.6 as its default mechanism). It is
implemented for real (not stubbed) because it is pure integer/bit
bookkeeping over PUBLIC sequence numbers — the AEAD tag is what actually
authenticates a message; the window only decides whether to bother
re-verifying a sequence number that has already been accepted once. Two
invariants matter:

1. **`check` is read-only; `update` must only run AFTER a successful AEAD
   verification.** Recording an unverified sequence number would let an
   on-path attacker "burn" a legitimate future window slot with a forged
   or replayed garbage message, causing the real message (arriving later,
   with that same sequence number) to be wrongly rejected as a replay.
   `unprotect`'s own doc comment spells out the exact check-then-verify-
   then-update ordering (§8.2/§8.4).
2. **Responses are never replay-checked** (§8.4) — not even Appendix
   C.8's response, which carries its own fresh Partial IV. `is_request`
   is an explicit `unprotect` parameter for exactly this reason; it is
   NOT inferred from whether the option carries a Partial IV (C.8 proves
   that inference would be wrong: it has a Partial IV in the option, yet
   is still a response, still never replay-checked).

`window_size` is bounded to 64 by the `u64` bitmap backing — RFC 8613
does not mandate an exact size ("may be different in the two endpoints",
§3.2), and 64 comfortably covers the §3.2.2 stated default of 32.

## Persistence — RFC 8613 §7.5, Appendix B.1 (the state that is NOT the keys)

A `SecurityContext` has two rapidly changing parts that live in RAM:
`sender.sequence_number` and `recipient.replay_window`. §7.5 is normative
about them: an endpoint that keeps a Security Context across a reboot
**MUST NOT reuse a previous Sender Sequence Number and MUST NOT accept
previously received messages**. `deriveContext` cannot help with either —
it is a pure function of the §3.2 inputs, so calling it again after a
restart yields the SAME keys with the sequence number back at 0 and an
EMPTY replay window. Concretely (measured by the 2026-09-05 audit):

- the first message after the re-derivation is sealed under the SAME
  `(key, nonce)` as the first message before it — AES-CCM is CTR mode, so
  the XOR of the two ciphertexts is the XOR of the two plaintexts, and the
  second plaintext falls out **without the key** (a two-time pad);
- every request captured before the restart replays cleanly (500/500 in
  the audit's probe), because the fresh window has nothing to compare
  against.

This module has no nonvolatile storage and no CoAP layer, so it cannot
persist anything itself. What it provides is the two operations Appendix
B.1 describes, so that a caller who owns the storage does not have to
re-derive the arithmetic:

- **Sender side, B.1.1** — `SenderContext.needsCheckpoint(k)` is true
  when the NEXT `protect` will consume a sequence number divisible by `k`;
  the caller then writes `sequence_number` to nonvolatile memory BEFORE
  calling `protect`. After a reboot, `SenderContext.resumeAfterRestart(
  stored, k, f)` sets `SSN2 = SSN1 + K + F` — strictly above any number
  the pre-reboot process can have used, provided `f` covers the storage's
  own write delay (B.1.1: if no such `f` can be guaranteed, this method
  MUST NOT be used; derive a fresh context per Appendix B.2 instead). The
  resume fails with `error.SequenceNumberExhausted` rather than land past
  `max_partial_iv`.
- **Receiver side, B.1.2** — `ReplayWindow.resumeAtLowerLimit(piv)`
  re-initializes the window so that `piv` and everything below it is a
  replay and only `piv + 1` onwards is accepted. B.1.2's source for `piv`
  is the Partial IV of the first request the server has verified FRESH
  after the reboot via the Echo option (RFC 9175) — that challenge/response
  is the CoAP layer's job. A persisted high-water mark is an acceptable
  source ONLY if it was written before the message carrying it was
  accepted (write-ahead); a lazily persisted `highest_seen`/`mask` pair is
  a replay hole exactly as wide as the messages accepted after the last
  write. Do not store and reload the window verbatim.

Both operations are pure bookkeeping on the context and are gated by tests
that run the real `protect`/`unprotect` across a simulated restart
(`kat_test.zig`, "F3" tests). The alternative to all of this is §7.5's
options 2-4: a fresh Master Secret or a fresh ID Context (Appendix B.2,
random `kid context`), i.e. NEW keys — outside this module's scope but
always correct.

## Threat model / limits

- **This module supplies no transport, no exchange tracking, and no CoAP
  parsing.** It is a pure crypto/codec core over caller-supplied byte
  strings; a consumer (a CoAP stack — the sibling `coap` module does not
  do this today) is responsible for extracting the §5.3 plaintext and §5.4
  options from a real CoAP message, tracking which response belongs to
  which request, and calling `protect`/`unprotect` with the right
  parameters. A caller that gets the request/response nonce-reuse
  decision wrong (§5.2) produces messages this module will happily
  protect/verify but that are NOT what RFC 8613 intends — this module
  cannot detect that misuse from the inside.
- **Sequence-number exhaustion**: `protect` MUST fail
  (`error.SequenceNumberExhausted`) rather than wrap the Sender Sequence
  Number past `max_partial_iv` (`2^40 - 1`) — reusing a `(key, nonce)`
  pair is a full AEAD break (RFC 8613 §7.2.1's own warning). A Security
  Context that hits this ceiling MUST be re-established, not patched
  around. **The same ceiling holds on the receive path**: `computeNonce`
  (and `unprotect`, through `request_nonce_source.partial_iv`) fails with
  `error.PartialIvTooLarge` instead of truncating a `>= 2^40` value to its
  low 5 bytes — which would be the nonce of `partial_iv mod 2^40`, i.e. a
  collision. `OscoreOption.decode` can never produce such a value (§6.1
  caps the field at 5 bytes); the caller-tracked `NonceSource` can.
- **AEAD message length**: AES-CCM-16-64-128 frames at most
  `max_plaintext_len = 65 535` bytes per invocation (2-byte CCM length
  field). `protect` fails with `error.MessageTooLong` above it and
  `unprotect` rejects any payload longer than `max_ciphertext_len` (that
  plus the tag) BEFORE touching the AEAD. Without those two checks the
  decrypt path panicked in Debug/ReleaseSafe ahead of the tag check — a
  keyless remote crash on one oversized CoAP payload — and the encrypt
  path in ReleaseFast emitted a length field of `len mod 2^16`. A
  block-wise (RFC 7959) body is protected block by block, never as one
  reassembled message.
- **Context loss across a restart** — see "Persistence" above. Re-deriving
  a context that has already protected a message reuses nonces; a fresh
  replay window accepts old requests.
- **`kid`/`kid context` are selection hints, not checked fields**:
  `unprotect` builds the nonce from `ctx.recipient.id` and never compares
  `option.kid`/`option.kid_context` against the context. The caller
  selects the context from them (§8.2 step 2); a contradiction fails
  only indirectly, via the wrong key failing the AEAD.
- **Never record an unverified sequence number as seen** — see the replay
  window section above; this is the single easiest correctness property
  to get backwards when implementing `unprotect` (check-before-decrypt is
  a valid optimization, but update-before-decrypt is a protocol bug).
- **`buildAad`'s `request_kid`/`request_piv` misuse**: passing the
  RESPONSE's own kid/Partial IV instead of the ORIGINAL REQUEST's into
  `AadParams` when protecting/unprotecting a response silently produces
  an AAD the peer will never be able to reproduce — not a crash, a
  guaranteed `AuthenticationFailed` on the other end. `protect`/
  `unprotect`'s own doc comments call this out explicitly.
- **`SenderContext.id`/`RecipientContext.id` length**: MUST be `<=
  id_piv_field_width` (7 bytes at this algorithm) for `computeNonce` to
  accept it — `error.IdTooLong` otherwise. This is a deployment-level
  Sender/Recipient ID sizing constraint the RFC leaves to the
  application (§3.1: "Maximum length is determined by the AEAD
  Algorithm").
- **Constant-time**: `deriveKey`/`protect`/`unprotect` handle secret key
  material (`master_secret`, the derived Sender/Recipient Key) and MUST
  route it only through `std.crypto`'s own constant-time HMAC/AES-CCM
  implementations — no comparison or branch on key bytes anywhere in this
  module's own code once filled in. `ReplayWindow`/`OscoreOption`/the
  CBOR encoders handle only PUBLIC data (sequence numbers, IDs, option
  bytes) and have no constant-time obligation.

  **Measured since 2026-09-08**, instead of asserted. The instrument is
  committed: [`src/ctgrind_harness.zig`](src/ctgrind_harness.zig), driven by
  `scripts/checks/ctgrind.sh oscore`. Zig 0.16.0, valgrind 3.26.0, x86_64,
  `ReleaseFast`:

  | target | tainted | contexts | in-file | untainted control | no-`-fvalgrind` trap |
  |---|---|---:|---:|---:|---:|
  | `derive` | master secret | 4 | **0** | 0 | 0 |
  | `protect` | derived Sender Key | 2 | **0** | 0 | 0 |
  | `unprotect` | derived Recipient Key | 3 | **1** | 0 | 0 |

  ⚠ **The two zeros are zeros with a witness.** The probe that first took this
  measurement (audit F8) reported `derive` and `protect` as 0 in-file out of a
  total of **0**, and that is not a result — a total of zero is what a harness
  that never reaches the module reports too. This harness prints the derived
  keys and the ciphertext through `std.debug.print`, which is not
  constant-time by design, so the totals of 4 and 2 show the taint arriving and
  the in-file zero means "no branch found".

  The single `unprotect` context is std's `if (!valid)` at `aes_ccm.zig:152`,
  two lines after the `crypto.timing_safe.eql` that produced `valid`. Branching
  on the answer is the API; the comparison is the constant-time one. It appears
  only here because only `unprotect` verifies a tag.

  **Teeth, measured 2026-09-08.** An OR-fold over the Sender Key and a compare,
  injected at the top of `protect`, moves that row from **0 in-file to 1** and
  fails `--check`. Reverted; `cmp` confirmed byte-identical.

  **Limit:** memcheck sees branches and addresses, not cache timing.

## The six crypto cores (all implemented)

The six crypto cores in `root.zig` are all real — no `@panic`/TODO stub
remains. Each function's own doc comment spells out the exact RFC 8613
construction step-by-step:

1. **`deriveKey`** (§3.2.1) — `encodeInfo` (already real) into
   `HkdfSha256.extract`/`.expand`.
2. **`deriveContext`** (§3.2) — three `deriveKey` calls (Sender Key,
   Recipient Key, Common IV — the last ALWAYS with `id = &.{}`) assembled
   into a `SecurityContext`.
3. **`computeNonce`** (§5.2) — the XOR construction detailed above.
4. **`buildAad`** (§5.4) — `encodeAadArray` (already real) wrapped via
   `encodeEncStructure` (already real); a two-line composition kept as
   its own core per this module's task brief (byte-exact-gated
   independently of `protect`/`unprotect`, not just transitively).
5. **`protect`**/**`unprotect`** (§8.1-§8.4) — `computeNonce` +
   `buildAad` + `std.crypto.aead.aes_ccm.Aes128Ccm8.encrypt`/`.decrypt`,
   plus (`unprotect` only) the `ReplayWindow` check-then-verify-then-
   update ordering.

Byte-exact oracle for all six: RFC 8613 Appendix C's official vectors
(`kat_vectors.zig`), exercised by `kat_test.zig` — every C.1-C.3
key-derivation output (both directions), every C.4-C.8 nonce/AAD/
ciphertext/option value, plus a tamper-rejection test, a replay-rejection
test, and an end-to-end round trip with fresh (non-published) key
material.

What Appendix C alone cannot see, and what the module's own tests add on
top of it (A1 audit, 2026-09-06 — each was a mutation that had survived
the Appendix C suite green): a request genuinely delivered twice through
`unprotect`; the default window width exercised at its edge (Partial IV
40, then 8 accepted, 7 rejected); a response opened with a
`request_nonce_source.id` that differs from `recipient.id`; non-empty
Class I `options` changing the tag; `kid` AND `kid context` both
non-empty (every published vector has at most one); and the guards
`MessageTooLong`, `PartialIvTooLarge`, `IdTooLong`, `MissingPartialIv`,
sub-tag-length payloads, and the Appendix B.1 restart procedures.

## Verification

- `zig build test-oscore` and `-Doptimize=ReleaseFast` both go green;
  `zig fmt --check modules/oscore/` clean.
- `zig build run-example-oscore` walks two full exchanges, a replay, a
  tamper, and a simulated reboot with Appendix B.1 recovery.
- **Key material on the dead stack** (audit F7): `deriveContext` wipes its
  three derived-value locals and then zeroes the stack region its HKDF/
  HMAC callees vacated (`scrubStackBelow`, 8 KiB, once per derivation).
  Measured with the audit's probe re-pointed at heap-resident needles so
  the caller's own live copies do not count: in ReleaseSafe/ReleaseFast
  the derived keys were found 1-2 times below the caller before, at most
  once after (that copy sits at the probe wrapper's own return slot). The
  per-message path is NOT scrubbed: `protect`/`unprotect` leave std's
  AES-128 round-key schedule behind (its first round key is the Sender/
  Recipient Key itself) — 6 copies in Debug, 1 in release modes — and a
  per-message scrub would cost as much as the AEAD call it follows. That
  residue is a property of `std.crypto`'s AES, recorded here rather than
  hidden.

## Anchoring

**Anchor grade:** class A · oracle EXTERNAL

- **Class A** — wire/interop format — other implementations must byte-agree with it.
- **Oracle EXTERNAL** — published vectors, goldens captured from a foreign implementation, or a test run against a live foreign peer.

**What the tests actually contain.** RFC 8613 Appendix C official vectors (key derivation + protected-message C.4-C.8)

**Independent re-derivation:** `modules/oscore/tools/README.md` — a third-party crypto stack (python `cryptography`) recomputes every Appendix C field from scratch; 73/73 agree.
