# lninvoice — spec

Lightning payment requests: BOLT#11 invoices (full decode+verify / encode+sign) and BOLT#12
offers (decode only). Usage: see ./README.md.

## Design & invariants

- **Four files, each independently testable:** `bech32_raw.zig` (allocator-owned, length-uncapped
  bech32 codec — BOLT#11 explicitly waives BIP173's 90-character ceiling, so the `bech32` module's
  capped `encode`/`decode` can't be reused; also a checksum-less variant for BOLT#12) ·
  `bitpack.zig` (5-bit-quintet ↔ byte/integer conversions, shared by both BOLTs) ·
  `ecdsa_recover.zig` (RFC 6979 deterministic ECDSA sign + standard public-key recovery over
  `k256`'s field/group/scalar — `k256/src/sign.zig` was checked and ships BIP340 Schnorr +
  plain ECDSA *verify* but no ECDSA *sign* and no *recovery*, both needed here) · `bolt11.zig` /
  `bolt12.zig` (the wire formats themselves).

- **`k256` had no recoverable-ECDSA support — this module adds it, not `k256`.** `k256/src/sign.zig`
  is deliberately thin ("a verification harness surface, not the module's reason to exist");
  BOLT#11's recoverable-signature scheme is genuinely lninvoice's own concern (Bitcoin/BIP340 code
  never needed it), so it lives here rather than growing k256's scope. `ecdsa_recover.zig` is
  self-contained and reusable standalone (re-exported at `lninvoice`'s root).

- **Fail-closed throughout, specific typed errors per rejection reason** — `bolt11.DecodeError` is
  a large union covering: bech32-layer failures (`MixedCase`/`NoSeparator`/`InvalidChecksum`/...,
  from `bech32_raw.DecodeError`), HRP parse (`UnknownPrefix`/`UnknownNetwork`), amount parse
  (`InvalidAmountDigits`/`AmountLeadingZero`/`SubMilliSatoshiPrecision`/`AmountTooLarge`), tagged-
  field structure (`TruncatedTaggedField`/`NonMinimalTaggedField`/`BadRouteHintLength`), required-
  field presence (`MissingPaymentHash`/`MissingPaymentSecret`/`MissingDescription`/
  `AmbiguousDescription`), and the signature (`InvalidRecoveryId`/`InvalidSignature`/
  `HighSNotAllowed`/`ecdsa_recover.RecoverError`'s `InvalidScalar`/`NotSquare`/`InvalidPoint`/
  `IdentityElement`). `bolt12.DecodeError` mirrors this at the TLV layer (reusing `lnwire.tlv`'s
  own `StreamError` for the generic ordering/minimality/even-unknown-type rules).

- **The security core is signature verification/recovery, not the field parser.** A `payment_hash`/
  `amount`/anything-in-the-signed-preimage that's been tampered with changes
  `SHA256(hrp || data-without-signature)`, so:
  - with no `n` field: `ecdsa_recover.recoverPubkey` recovers a WRONG (or outright
    non-recoverable — `error.NotSquare`/`InvalidScalar` when the transmitted `r`/recid don't even
    lift to a valid curve point) key, never the real payee's, from a tampered invoice;
  - with an `n` field: the signature is verified directly against it (`k256.sign.ecdsaVerify`) and
    low-S is *required* (BOLT#11: "MUST fail the payment" on high-S when `n` pins the signer —
    recovery-only invoices accept either, per spec — `ecdsa_recover.isLowS`).
  `bolt11.zig`'s tests exercise both paths against BOLT#11's own official vectors, including one
  where the vector's own transmitted recovery id is internally inconsistent with its high-S
  variant (see that test's comment — cross-verified independently against Python's `cryptography`
  library, not a bug in this module).

- **BOLT#11 tagged-field parsing: first CORRECTLY-SIZED occurrence of a fixed-length field
  (`p`/`h`/`s`/`n`) wins; a wrong-length occurrence is silently skipped, never fatal — even if it's
  the first occurrence of that tag.** This was discovered, not assumed: BOLT#11's own "including
  fields which must be ignored" vector ships duplicate `p`/`h`/`s`/`n` fields with deliberately
  wrong lengths, and the FIRST `h` occurrence in that vector is one of the wrong-length ones (the
  real description comes from `d`). The spec's prose ("MUST fail the payment if any field with
  fixed `data_length` ... does not have the correct length") reads as unconditional, but the
  vector only parses successfully under the lenient reading; the module follows the vector (the
  authoritative interop artifact) and documents the divergence at the four `switch` arms in
  `bolt11.zig`'s `decode`. Unrecognized tag types and duplicates of a tag whose slot is already
  filled are unconditionally discarded (same net effect, simpler code path).

- **`f`/`r` are the only multi-occurrence tagged fields** (BOLT#11: "MAY include one or more `f`
  fields" / "MAY include more than one `r` field") — collected into `fallbacks`/`route_hints`
  arrays in encounter order; every other tag is first-occurrence-wins per the point above.

- **`x`/`c` non-minimal encoding is rejected** (`error.NonMinimalTaggedField` on a leading zero
  quintet), per BOLT#11's writer requirement ("MUST use the minimum `data_length` possible") —
  applied on decode too, matching the module's fail-closed posture on the other length-minimality
  rules already enforced elsewhere in the repo (`lnwire`'s BigSize/TLV). NOT applied to `9`
  (features): interpreting individual feature-bit odd/even semantics is BOLT#9's scope, not
  BOLT#11's — `features` is handed back as raw bytes, uninterpreted.

- **Amount encoding/decoding is exact integer arithmetic in `u128`**, never floating point: `msat
  = digits · 10^(11−exp)` for multipliers `none`/`m`/`u`/`n` (exact by construction), and `msat =
  digits / 10` for `p` (exact iff `digits`'s last decimal is 0 — BOLT#11's own rationale for why
  `p` exists: sub-millisatoshi amounts can't be transferred). `formatAmount`'s shortest-
  representation encoder tries `none`→`m`→`u`→`n` in decreasing-precision order before falling
  back to `p` (always exact), matching the writer's "SHOULD use the shortest representation"
  requirement — verified byte-exact against three of the spec's own amount strings (`2500u`,
  `9678785340p`, `20m`).

- **`f` (fallback address) and `r` (routing hint) are stored typed but NOT semantically
  interpreted beyond BOLT#11's own wire layout** — `Fallback{ version, program }` (raw witness-
  version quintet + raw program/hash bytes; Bitcoin address-format rendering — bech32 segwit vs.
  base58 P2PKH/P2SH — is the caller's job, trivially reachable via the sibling `bech32` module) and
  `RouteHop{ pubkey, short_channel_id, fee_base_msat, fee_proportional_millionths,
  cltv_expiry_delta }` (the exact 51-byte-per-hop BOLT#11 defines). This keeps the module from
  growing a second copy of address-format logic `bech32`/sibling modules already own.

## BOLT#12 — offer decode only, `invoice_request`/`invoice` deferred

Implemented: `decodeOffer` — checksum-less bech32-style decode (`lno1...`, `+`-continuation
stripping per BOLT#12 "Requirements"), the `offer` TLV stream via `lnwire.parseTlvStream` (reusing
its generic strictly-increasing-type / minimal-BigSize / even-unknown-type-fails rules), and every
scalar `offer_*` field (chains, metadata, currency, amount, description, features,
absolute_expiry, issuer, quantity_max, issuer_id). `offer_paths` (`blinded_path` entries) are
handed back as raw undecoded bytes — decoding the blinded-path structure is BOLT#4 route-blinding,
a distinct spec.

**Deferred: `invoice_request`/`invoice` parsing and signing.** Offers are an *unsigned* TLV stream
(every top-level type is even/informational) — a clean, self-contained parse this pass completed.
`invoice_request`/`invoice` are signed with a BIP-340 Schnorr signature over a **Merkle root of the
TLV stream** (BOLT#12 "Signature Calculation": a BIP-341-style tree, each leaf paired with a nonce
leaf, tags `H("LnLeaf", tlv)` / `H("LnNonce"||first-tlv, tlv-type)` / `H("LnBranch",
lesser-hash||greater-hash)`) — a self-contained sub-algorithm comparable in scope to this module's
own BOLT#11 recoverable-ECDSA core, on top of the same `offer_paths` blinded-path gap. Bundling
either into this pass would have traded BOLT#11 depth (its official test vectors, the
recovery-security core) for breadth without finishing either well; the TLV plumbing below (`lnwire`
integration, `bitpack`) is already shared and reusable for a follow-on module addition.

## Verification

**BOLT#11**, pinned against the spec's own worked examples (`11-payment-encoding.md` "Examples"):
the donation invoice (no `n` field — full field decode + signature recovery matching the
documented node ID `03e7156ae33b...`), its high-S variant (documented + cross-verified separately
against Python's `cryptography` library — see `bolt11.zig`'s test comment for the recid finding),
the `$3 coffee` amount/expiry vector (`2500u` → 250,000,000 msat), the pico-amount + route-hint
vector (`9678785340p` → 967,878,534 msat, full `r`-field hop decode), the `h`-description-hash
vector, the all-uppercase vector, and the "fields which must be ignored" duplicate/unknown-field
vector. **Hostile/negative**: bad checksum, no separator, mixed case, the spec's own "signature is
not recoverable" vector (`error.InvalidScalar`), invalid multiplier char, sub-millisatoshi
precision, missing `s` field, too-short invoice, and high-S-with-`n`-field (`error.HighSNotAllowed`).
**Round-trip**: `encode`+`decode` with a random key recovers the signer's own pubkey; RFC 6979
signing the donation vector's own hash with its own documented private key reproduces the spec's
exact `(r, s, recid)` byte-for-byte, and recovering from that freshly-signed signature reproduces
the spec's node ID — signer and verifier agree end-to-end.

**BOLT#12**: a hand-built minimal offer round-tripped through `lnwire.tlv.appendStream` →
`bitpack.bytesToQuintets` → `bech32_raw.encodeNoChecksum` → `decodeOffer` (independently
constructed, not hand-typed hex), `+`-continuation stripping, wrong-prefix rejection, and the
generic TLV even/odd-unknown-type rules (reusing `lnwire`'s own machinery, not re-tested from
scratch).

Run: `zig build test-lninvoice` (Debug and `-Doptimize=ReleaseFast`).

## Status

`any (pure codec, no I/O) · codec · reentrant` + deps: `bech32`, `k256`, `lnwire` — canonical
source is `pub const meta` in `src/root.zig`.
