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
  and §5.4 "options" as opaque caller-supplied byte strings. The intended
  integration is `coap` (RFC 7252 message codec, already in this
  repository) assembling those byte strings and wiring `oscore` in as its
  object-security layer — deliberately NOT built in this pass, to keep
  the crypto core testable and reviewable in isolation.
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
"`external_aad = bstr .cbor aad_array`" notation. `buildAad` (STUB) is the
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

## Threat model / limits

- **This module supplies no transport, no exchange tracking, and no CoAP
  parsing.** It is a pure crypto/codec core over caller-supplied byte
  strings; a consumer (the sibling `coap` module, or any other CoAP
  stack) is responsible for extracting the §5.3 plaintext and §5.4
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
  around.
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

## Verification

- `zig build test-oscore` and `-Doptimize=ReleaseFast` both go green;
  `zig fmt --check modules/oscore/` clean.
- Disk-vs-running test count (CONVENTIONS.md §6 step 3):
  `grep -c '^\s*test ' modules/oscore/src/*.zig` summed across files
  equals `zig build test-oscore --summary all`'s reported total.
