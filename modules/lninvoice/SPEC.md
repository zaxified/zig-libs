# lninvoice — spec

Lightning payment requests: BOLT#11 invoices (full decode+verify / encode+sign) and BOLT#12
offers (decode) + signed `invoice_request`/`invoice` (parse/verify/build/sign via the BOLT#12
Merkle-tree BIP-340 signature). Usage: see ./README.md.

## Design & invariants

- **Four files, each independently testable:** `bech32_raw.zig` (allocator-owned, length-uncapped
  bech32 codec — BOLT#11 explicitly waives BIP173's 90-character ceiling, so the `bech32` module's
  capped `encode`/`decode` can't be reused; also a checksum-less variant for BOLT#12) ·
  `bitpack.zig` (5-bit-quintet ↔ byte/integer conversions, shared by both BOLTs) ·
  `ecdsa_recover.zig` (a thin re-export of `k256.ecdsa_recover` — see below) · `bolt11.zig` /
  `bolt12.zig` (the wire formats themselves).

- **Recoverable ECDSA now lives in `k256`, not here.** BOLT#11's recoverable-signature scheme
  (RFC 6979 deterministic sign + standard public-key recovery, `Q = r⁻¹(sR − eG)`) was originally
  implemented in this module, because at the time `k256/src/sign.zig` shipped only BIP340 Schnorr
  and plain ECDSA *verify* — no ECDSA *sign*, no *recovery* — and no other consumer needed either.
  Once it became clear the functionality is general secp256k1 machinery rather than anything
  BOLT#11-specific, it was moved to `k256/src/ecdsa_recover.zig` (exported as `k256.ecdsa_recover`).
  `lninvoice/src/ecdsa_recover.zig` is now a thin re-export shim, kept so `bolt11.zig`'s existing
  `ecdsa.*` call sites and `lninvoice`'s root-level `sign`/`recoverPubkey`/`Signature`/`isLowS`
  re-exports need no changes.

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

## BOLT#12 — offer decode + signed `invoice_request`/`invoice`

**Offer (`lno1...`):** `decodeOffer` — checksum-less bech32-style decode (`+`-continuation
stripping per BOLT#12 "Requirements"), the `offer` TLV stream via `lnwire.parseTlvStream` (reusing
its generic strictly-increasing-type / minimal-BigSize / even-unknown-type-fails rules), and every
scalar `offer_*` field (chains, metadata, currency, amount, description, features,
absolute_expiry, issuer, quantity_max, issuer_id). Offers are an *unsigned* TLV stream.

**Signature Calculation (`merkleRoot` + `signMerkle`/`verifyMerkle`):** the BOLT#12 Merkle tree over
a TLV stream — leaf `H("LnLeaf", tlv)` (full `type||length||value`), nonce leaf
`H("LnNonce"||first-tlv, tlv-type)` where the *tag* is `"LnNonce"` concatenated with the whole first
TLV record and the *message* is the current record's BigSize type field, branch
`H("LnBranch", lesser||greater)` (lexicographic order), tree built bottom-up with the split at the
largest power of two strictly below the level's node count. Signature TLVs (types 240–1000) are
excluded from the tree. The signed message is `H("lightning"||messagename||fieldname, root)`, fed to
BIP-340 (`bip340` dep). `merkleRoot` is a self-contained, reusable primitive (it re-walks the raw
stream to recover per-record byte ranges, which `lnwire.parseStream` does not expose).

**`invoice_request` (`lnr1...`):** `decodeInvoiceRequest` → `InvoiceRequest` (typed
`invreq_metadata`/`invreq_amount`/`invreq_chain`/`invreq_quantity`/`invreq_payer_id`/
`invreq_payer_note` + copied `offer_currency`/`offer_amount`/`offer_description`/`offer_issuer_id` +
`signature`; `raw` owns the stream, slice fields borrow). `InvoiceRequest.verify` checks the
`signature` (type 240) by `invreq_payer_id` (type 88, verified x-only). `encodeSignedInvoiceRequest`
builds+signs+encodes from caller-supplied ascending signature-free records.

**`invoice` (`lni1...`):** `decodeInvoice` → `Invoice` (typed `invoice_created_at`/
`invoice_relative_expiry`/`invoice_payment_hash`/`invoice_amount`/`invoice_node_id`/`signature`).
`Invoice.verify` checks the signature by `invoice_node_id` (type 176).
`encodeSignedInvoice` builds+signs+encodes.

**Raw (not typed) fields:** `offer_paths`/`invreq_paths`/`invoice_paths` (`blinded_path` entries,
BOLT#4 route-blinding — a distinct spec), and `invoice`'s optional `invoice_blindedpay`/
`invoice_fallbacks` sub-structures. These stay in the record stream / `raw` buffer and are not
decoded; the signed-blob correctness (Merkle root + BIP-340 signature) and mandatory scalar fields
are modelled fully. **Interop-vector caveat, corrected 2026-07-28:** this section previously said the
`invoice` (`lni1`) sign/verify path was validated by sign→verify round-trip ONLY, because
`bolt12/signature-test.json` ships an `invoice_request` worked example but no `invoice` one. That
was true of `signature-test.json` specifically but the claim was checked against the wrong file: the
sibling `bolt12/payer-proof-test.json` (`lightning/bolts`) DOES publish a full `invoice` worked
example (Merkle root, sighash, and BIP-340 signature — its `"full_disclosure"` vector), now wired in
as an external byte-exact KAT (`bolt12.zig`, "BOLT#12 KAT: invoice Merkle root + signature verify").
`invoice`'s Merkle+signature core is now externally anchored, same as `invoice_request`'s; only the
*offer* round-trip (see the BOLT#12 offer note above) remains self-constructed.

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

**BOLT#12 offer**: a hand-built minimal offer round-tripped through `lnwire.tlv.appendStream` →
`bitpack.bytesToQuintets` → `bech32_raw.encodeNoChecksum` → `decodeOffer` (independently
constructed, not hand-typed hex), `+`-continuation stripping, wrong-prefix rejection, and the
generic TLV even/odd-unknown-type rules (reusing `lnwire`'s own machinery, not re-tested from
scratch). **Externally anchored as of 2026-07-28**: `bolt12.zig` now also decodes 3 real `lno1…`
strings byte-for-byte from `lightning/bolts` `bolt12/offers-test.json` ("Minimal bolt12 offer",
"with description (but no amount)", "with currency" — the last cross-checks `currency`/`amount`/
`description`/`issuer_id` all at once against the JSON's own field list) plus 1 real invalid vector
("Malformed: unknown even TLV type 78") proving the even/odd rejection against a genuine malformed
wire string, not just a self-constructed one.

**BOLT#12 offer ENCODE, externally anchored as of 2026-08-02** (closing the
gap this section previously flagged — "BOLT12 offer ENCODE round-trip
self-constructed" in `ANCHOR-TASKS.tsv` — where the only check was feeding
this module's own encode pipeline back into its own decoder): ALL 53 rows of
`lightning/bolts` `bolt12/offers-test.json` are now vendored
(`bolt12_offers_kat_vectors.zig`). The 22 rows carrying a `fields` breakdown
(all 20 `"valid": true` rows, plus 2 wire-well-formed-but-semantically-invalid
`"valid": false` rows) are built from those fields via
`lnwire.tlv.appendStream` → `bitpack.bytesToQuintets` →
`bech32_raw.encodeNoChecksum` and asserted BYTE-EXACT against the vector's own
published `lno1…` string — the first time this module's encoder is checked
against an oracle other than its own decoder. The same 22 rows are also
DECODED and their recovered TLV records compared field-by-field against the
vector's `fields` list. 12 more `"valid": false` rows (out-of-order fields,
truncated-at-type/-in-length/-after-length/-in-description, a non-32-byte
`offer_chains`, a present-but-empty `offer_chains`, TLV type ≥ 80, unknown
even type 1000000002, TLV type > 1999999999, and 5-plus-bit bech32 padding)
are asserted rejected with the SPECIFIC error each names, not just "some
error". The remaining 21 `"valid": false` rows exercise UTF-8 validation,
`offer_paths`/`blinded_path` internal structure, `offer_issuer_id`
curve-point validity, `offer_features` bit semantics, and reader
"MUST NOT respond to the offer" business policy — all explicitly out of this
module's documented scope (see `bolt12.zig`'s comment enumerating each, right
before its Merkle/signature test section) and deliberately not asserted
against. `lightning/bolts` `bolt12/format-string-test.json` (12 rows, the
`+`-continuation / upper-vs-lowercase acceptance rules) is likewise fully
vendored and driven through `decodeOffer`.

Two real bugs surfaced by this sweep, both fixed: `bech32_raw.stripContinuation`
used to strip EVERY `+` unconditionally, when BOLT#12 only permits removing
one that sits between two ordinary characters — a leading/trailing/doubled
`+` was wrongly accepted before the fix (caught by `format-string-test.json`'s
five "+ must be surrounded by bech32 characters" rows). And
`bitpack.quintetsToBytesStrict`'s decode never rejected 5-or-more leftover
padding bits (only a NONZERO remainder), when BOLT#12's checksum-less
whole-data-part conversion requires leftover < 5 bits regardless of value —
now split into a new `quintetsToBytesMinimal` (used by BOLT#12's three
whole-stream decoders) so BOLT#11's per-field decode, which legitimately can
carry ≥5 leftover zero bits, keeps its original (correct, unchanged)
behavior. See both functions' own doc comments.

**BOLT#12 signature calculation**, byte-exact against the spec's own vectors
(`lightning/bolts` `bolt12/signature-test.json`, "Signature Calculation"):
- **`n1` Merkle roots** (1/2/3 leaves) — `merkleRoot` reproduces `b013756c…`, `c3774abb…`,
  `ab2e79b1…` exactly.
- **`invoice_request` worked example** (Alice offer / Bob payer, privkey `0x4242…42`) — the full
  6-leaf Merkle root `608407c1…`, signature *verify* of the published `b8f83ea3…`, AND byte-exact
  signature *reproduction* by signing with Bob's key + BIP-340 `aux_rand=0` (matches `b8f83ea3…`
  to the byte). Also decoded end-to-end from the KAT `lnr1…` string through the
  bech32/bitpack/TLV path.
- **`invoice` worked example, externally anchored as of 2026-07-28** (`lightning/bolts`
  `bolt12/payer-proof-test.json`, "full_disclosure" vector — NOT `signature-test.json`, which has
  no `invoice` example; see the corrected interop-vector caveat above): Merkle root `cb9e0c81…`
  reproduced byte-exact from the vector's raw `invoice_hex` TLV stream, and the published
  `invoice_signature` (`fbb932e6…`) verifies against `invoice_node_id`'s x-only key over
  `merkleRoot`+`invoice_sig_tag`. Run directly through `merkleRoot`/`verifyMerkle` (not
  `decodeInvoice`) since the vector carries payer-proof-specific TLV types this module's typed
  decoder doesn't model.
- **Reject-teeth**: flipped signature bit → verify `false`; corrupted stream byte → verify `false`;
  swapped signer pubkey → verify `false`; length-overrun TLV → `error.Truncated`; empty /
  signature-only stream → `error.EmptyMerkleStream`; signature-TLV-exclusion invariant (a type-240
  record does not change the root).
- **Round-trip**: `encodeSignedInvoiceRequest`/`encodeSignedInvoice` → decode → `verify` for both
  `lnr1`/`lni1`, in addition to (not instead of) the externally-anchored `invoice` Merkle/signature
  KAT above.

Run: `zig build test-lninvoice` (Debug and `-Doptimize=ReleaseFast`).

## Status

`any (pure codec, no I/O) · codec · reentrant` + deps: `bech32`, `k256`, `lnwire`, `bip340` —
canonical source is `pub const meta` in `src/root.zig`.
