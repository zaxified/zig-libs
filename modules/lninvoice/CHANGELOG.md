# lninvoice — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-11-27** — **FIX (blinded paths and payinfo):** `PathIterator` / `HopIterator` / `PayInfoIterator` summed a `u16` length with a constant in `u16` (`35 + enclen`, `PayInfo.fixed_len + flen`), so a hop's `encrypted_recipient_data` or a payinfo's `features` of 65501..65535 bytes (legal for the writers, `appendPath` / `appendPayInfo`) panicked the reader in safe builds and wrapped the cursor in ReleaseFast; the sum is now taken in `usize`. Found by the delta mutation run (a round trip at the writer's maximum).
- **2026-11-27** — **FIX (offer builder):** `offer.encodeOffer` with `.paths = &.{}` and an `issuer_id` wrote an empty type-16 `offer_paths` record, which `readOffer` refuses (`InvalidPaths`); an empty `paths` value is now no record at all (as the issuer-or-paths rule already treated it).
- **2026-11-23** — **NO CONSUMER-VISIBLE CHANGE:** the dead-stack probe (`src/stackprobe_test.zig`) also applies the residue rule (`testkit.stackprobe.residueOf`) to its snapshots. Clean. Test only.
- **2026-11-21** — **New public API: typed BOLT#12 blinded paths, offer rules, offer builder.** `blinded` (`PathIterator`, `Path`, `Hop`, `FirstNode`, `PayInfo`, `PayInfoIterator`, `appendPath`, `appendPayInfo`) with `Offer.blindedPaths`, `InvoiceRequest.blindedPaths` / `record`, `Invoice.blindedPaths` / `blindedPayInfo` / `record`; `offer.readOffer` / `checkOffer` (the reader rules; all 53 `offers-test.json` rows are now asserted as valid or rejected), `offer.encodeOffer` (unsigned offers under the writer rules, byte-exact against the valid vector rows) and `offer.checkInvoiceRequest`.
- **2026-11-17** — **Behaviour change:** a leading zero in the HRP amount is now accepted (`lnbc01u` = `lnbc1u`, `lnbc0001u` likewise, also very many zeros); **API: `AmountLeadingZero` is removed from `AmountError`/`DecodeError` — code that names `error.AmountLeadingZero` (an explicit switch arm or comparison) no longer compiles; drop that arm.** BOLT#11 forbids leading zeros for writers only, and lnd (`zpay32`) and LDK (`lightning-invoice`) both read the digits as an integer. The writer is unchanged (a new test pins that `formatAmount` never emits a leading zero). Delta mutation: 5 mutants, 4 killed, 1 equivalent; card counts cumulative (336/352, 16 eq).

- **2026-11-17** — **NO BEHAVIOUR CHANGE (decision recorded):** a zero amount in the HRP (`lnbc0`, `lnbc0n`) stays accepted as `0` msat. BOLT#11 puts "positive, no leading 0s" on writers only; lnd (`zpay32`) and LDK (`lightning-invoice`) both accept zero through their integer parsers. SPEC records the sources and the one place the module is stricter than both (a leading zero on a non-zero amount is refused).

- **2026-11-17** — Whole-module mutation of `bech32_raw`, `bitpack`, `bolt11`, `bolt12` and `burn` (347 mutants, 332 killed, 15 EQUIVALENT/UNOBSERVABLE; the card now carries whole-module counts). 29 tests added (HRP and case edges, the HRP amount grammar, every network prefix, crafted well-signed invoices for tagged-field layouts, the 1023-quintet cap, BOLT#12 TLV-level lengths, padding, Merkle truncation and `verifyMerkle`'s error/false split); no behaviour change.

- **2026-11-16** — **NEW API:** BOLT#12 `invoice_error` (`InvoiceError`, `decodeInvoiceError`, `encodeInvoiceError`; strict TLV types 1/3/5) and `invoiceRequestIsRefund` (classifies an offer-less `invoice_request`, i.e. a refund; the codec already handled them). No external vector; hand-built fixtures.
- **2026-11-13** — **BEHAVIOUR CHANGE (BOLT#12 signing):** the BIP340 signer now calls `bip340.sign(…, .{})`, bip340's new default, which no longer re-verifies the signature before returning it (libsecp256k1's behaviour; bip340 changelog 2026-11-13). Same signature bytes; no API change here.
- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — Ported to Zig 0.17.0. `strRepeat` helper is now `inline fn` (dangling-temporary fix).
- **2026-10-10** — tests: deterministic fuzz driver `LNINVOICE_FUZZ`: `lninvoice-bech32-decode`, `lninvoice-bolt11-decode` and `lninvoice-bolt12` over the existing script harnesses (generic over their choice source; driver draws a corpus entry with 0-3 octets damaged), plus two oracles: `lninvoice-bech32-roundtrip` (encode -> decode returns the input, upper-case too, one replaced symbol refused, no-checksum pair round-trips) and `lninvoice-bolt11-sign` (a random key signs a random invoice through `encode`; `decode` returns the signer, amount and fields; a replaced character and a truncation are refused; a signed-region quintet replaced with the checksum recomputed is refused or recovers a different key). No source change.
- **2026-10-10** — docs: ct axis recorded as n/a. The only secret is the node signing key. `bolt11.encode` (`.private_key`) and `bolt12.signMerkle` hand it by pointer straight to `k256`'s recoverable ECDSA and `bip340.sign`, both measured by their own ctgrind rows; no lninvoice code reads the key. Everything else (invoice fields, the payment secret carried in the invoice, signatures, node ids) is public (code review).
- **2026-10-09** — Dead-stack rule (CONVENTIONS §2.1.1), no signature change: `bolt11.encode` now runs its body under a 16 KiB stack burn (new `src/burn.zig`; the ECDSA/BIP340 signing underneath was already burned in `k256`/`bip340`), probed by the new `src/stackprobe2_test.zig`. `bolt11.decode` and `bolt12.decodeInvoice` carry `secret-api-ok` markers (the invoice's `payment_secret` is public wire data shared with the payer; the bolt12 `Invoice` holds no secret).

- **2026-10-09** — **TEST ONLY, NO API CHANGE:** dead-stack stack probe (`src/stackprobe_test.zig`, ReleaseFast) over BOLT#11 `encode` with `.private_key`, `signMerkle`, `encodeSignedInvoiceRequest`, `encodeSignedInvoice`: the private key and the ECDSA / BIP340 nonce material in every representation, needles self-checked against the published `R`. 0 residue as shipped (the signers are burned in `k256`/`bip340`; this module's frames hold only pointers).

- **2026-10-08** — **NO CONSUMER-VISIBLE CHANGE:** BOLT11 signing follows k256's pointer `ecdsa_recover.sign`; BOLT12 signing and tests follow bip340's pointer
  `sign` and out-param `KeyPair.fromSecretKey` (bip340 2026-10-08).
- **2026-09-15** — **Internal only, no behaviour change:** `bech32_raw.zig`'s own copies of the
  BCH-checksum generator, `charValue`, `toLower` and HRP expansion (54 non-comment lines,
  byte-for-byte the same algorithm as `bech32`'s) are gone — it now imports `bech32.polymod`/
  `charValue`/`toLower`/`hrpExpandInto` (A1 `bech32` M6, perf pass, round-2 decision Q4). The
  allocator-owned, length-uncapped shape (BOLT#11/#12 waive BIP173's 90-char ceiling) and
  `splitHrp` (no HRP-length cap, unlike `bech32.decode`) are unchanged. `scripts/modtest
  lninvoice`: 91/91 before and after.

- **2026-09-11** — ⛔ `InvoiceRequest.verify`/`Invoice.verify` used to call
  `bip340.xonlyBytesOf(...) catch unreachable` on `invreq_payer_id`/
  `invoice_node_id`, both decoded straight from the wire (BOLT#12 TLV types
  88/176) with only a length check. `bip340` (A1 F11, same commit) now
  rejects a 33-byte point whose leading byte is not `0x02`/`0x03`, which
  would have turned this `unreachable` into a reachable panic on a
  malformed/malicious payload — measured directly (temporarily reverting
  just these two call sites reproduced `thread panic: attempt to unwrap
  error: BadPointPrefix`, a process crash). Both call sites now propagate
  `error.InvalidPublicKey` (already part of `VerifyError`) instead, so a
  bad prefix fails `verify()` closed rather than crashing the process.
- **2026-09-10** — ⛔ `bech32_raw.stripContinuation`'s 2026-08-08 neighbour-charset check (audit
  F6) required both sides of a BOLT#12 `+` to be `1`/`b`/`i`/`o`-excluding bech32-alphabet
  members — but `1`/`b`/`i`/`o` are exactly the letters/separator a human-readable prefix
  (`lno`/`lnr`/`lni` + `1`) is made of, so a `+` landing right after the HRP (`"lno1+..."`) was
  never stripped (wave-2 audit finding F7). Ported core-lightning's actual reference reader
  (`common/bolt12.c` `b12_string_to_data`) instead: position-only (not first/last character of
  the string), no neighbour-charset check at all. Verified against the official
  `lightning/bolts` `bolt12/format-string-test.json` conformance vectors, including the two
  state-machine edge cases they pin (a trailing `+` followed only by whitespace; two adjacent
  `+`) — the audit's own vendored corpus could not distinguish the old and new readings, this
  external oracle can.
- **2026-09-07** — Fuzz reach: all three harnesses are R1 — their FIRST draw was a scalar one —
  and all three ran a single fixed input for their whole life. A scalar `Smith` draw reads eight
  octets as a little-endian u64 and returns the range MINIMUM unless the whole word falls inside
  the range, and after the first short read `Smith` discards the rest of the input, so outside
  `--fuzz` every choice collapsed: `bech32_raw.fuzzDecode` called `decode("")`;
  `bolt11.fuzzDecode` built `lnbc` with a data part of **0 quintets**; `bolt12.fuzzBolt12`'s
  record loop ended before its first iteration, so the stream was empty, the HRP was `hrps[0]`
  and the string damage never ran. None was exempted — a generator driven by a byte script has
  an obvious byte-first form. All three now draw one `smith.slice` and read their choices with
  `testkit.fuzz.Cursor`, over corpora of reviewable scripts with guards pinning measured numbers.
- **2026-09-07** — ⛔ `bolt11.fuzzDecode`'s data buffer was `[200]u5`, and **200 is below every
  real invoice this module owns**: measured over the BOLT#11 vectors in `bolt11.zig`, the
  shortest is 206 quintets, the donation invoice is 293 and the longest is 751. So no invoice
  this module can decode could ever have been built by its own fuzz harness — the same shape as
  a 1024-octet buffer against a 4065-octet reference document. Raised to 800.
- **2026-09-07** — ⛔ Two corpora scored **0 accepted** on their first draft, which is a finding
  rather than a result, and the guards caught both. A bech32 string ends in a checksum and a
  BOLT#11 invoice in a 104-quintet signature over a preimage that includes the HRP, so no
  character or quintet sequence written by hand is one the decoder takes. Both corpora now
  contain scripts that SPELL a real string — one from this module's own `encode`, one the
  BOLT#11 donation invoice — character for character, and the guards pin that the spelling
  reproduces its source. Before → after: `bech32_raw` one empty string → 10 scripts, 206
  characters, 3 decoded, 10 HRP octets; `bolt11` one empty data part → 9 scripts, 1842 quintets,
  all 4 HRP shapes, 1 real invoice decoded; `bolt12` one empty stream → 9 scripts, 276 stream
  octets, 16 TLV records parsed, 5 merkle roots.

- **2026-09-03** — Drift re-audit (last audited `d163578`, ~771 lines since). ⭐ **Nothing
  in the shipped code was broken** — every guard mutated is correct today. What was wrong is
  that a large share of them had no test that would notice if they stopped being, so this
  entry is mostly teeth. Both of the previous audit's ⚠ items are genuinely closed and were
  re-verified rather than read: the `n` amount multiplier now has a discriminating external
  anchor (bitcoinjs/bolt11 fixtures with real `n` rows and a re-takeable recipe, one of them
  re-derived from scratch in Python down to the recovered node key), and `bolt12.zig` is
  fuzzed — a corpus replay shows 39 of 134 saved inputs reaching `parseTlvStream`, 12 of
  them with two or more TLV records, so the harness's own reachability claim is true.
  - **The `n`-present ECDSA verification had no test.** `error.InvalidSignature` appeared in
    no test body anywhere; deleting the `ecdsaVerify` call left all 79 tests green. Without
    it `decode` returns `verification = .declared_node_id` carrying whatever pubkey the
    invoice CLAIMED, and a wallet trusting `verified_pubkey` pays a node id an attacker wrote
    down. Now driven by a forged invoice whose `n` names one key while a different key signs
    — everything else about it well formed, so ECDSA is the only thing that can reject it.
  - **`encode` could emit an expiry `decode` refuses.** `quintetsToUint` capped at 12 digits
    (60 bits) on the strength of a comment about what BOLT#11 fields "are"; its neighbour
    `uintToQuintets` writes up to 13, and `EncodeParams.expiry_seconds` /
    `min_final_cltv_expiry` are plain `u64` with no bound anywhere. At exactly 2^60 this
    module produced a well-formed, correctly signed invoice that this module then rejected.
    A precondition stated as a fact, with the disproof one function away. `quintetsToUint`
    now takes the whole `u64` range and refuses only a genuine overflow
    (`error.IntegerTooLarge`), so the round trip closes at `maxInt(u64)`.
  - **The BOLT#12 signature-type exclusion could be widened DOWNWARDS unnoticed.** The test
    written for exactly this pinned 240, 999, 1000 and 1001 — the upper edge and the range —
    but nothing below 240, so `t >= 200` was green. A TLV excluded from the Merkle tree is a
    field the signature does not commit to, so widening the exclusion downwards lets any
    type-200..239 record be added or rewritten while the BIP-340 signature still verifies.
    Now pinned at 239.
  - **Fixed-width BOLT#12 fields, and both sites of the same rule.** Eight `!= N` length
    checks could each be weakened to `< N` — accept an over-long value and take its first N
    bytes — with the suite green, because the whole vendored corpus is well formed and a
    genuine external corpus cannot exercise a refusal it never triggers. ⚠ Worth keeping:
    `offer_issuer_id` is checked in **two** decoders and a mutation applied to one of them
    reads green, so both are now driven.
  - **`verify()` failed closed only by inspection.** Replacing `orelse return
    error.MissingSignature` with `orelse return true` — an UNSIGNED invoice_request
    verifying — was green. The cryptographic refusal is anchored by the payer-proof KAT; the
    two structural refusals in front of it were not.
  - **`bech32_raw.decode`'s `DataTooShort` bound** — the first thing an untrusted invoice
    string touches, and what keeps `full.len - 6` from wrapping — was reached by no test at
    all: replacing its body with `unreachable` was green, and so was weakening it to `< 1`.
- **2026-09-03** — Docs. The file doc's "every decode path is fail-closed … a signature that
  fails to verify/recover is a typed error" is true and reads as more than it is: on the
  `.recovered` path `decode` **authenticates nothing**, because recovery is a function, not
  a check. Measured by tampering every quintet of the spec donation invoice's signed payload
  with the signature and checksum recomputed: of 5859 single-symbol variants **5430 (92%)
  decoded successfully**, every one returning a different payee key with no error. Correct
  and unavoidable for a recovery-only invoice — and it means the security step belongs to
  the caller, which the module doc and README now say. README's usage snippet also called
  `std.time.timestamp()`, removed in Zig 0.16, so the module's front door did not compile;
  the compiled `example/` never touched that line, which is why no gate caught it.
- **2026-08-08** — ⏪ *Backfilled 2026-09-03; these entries were missing.* **Behavioural:**
  the BOLT#11 `9` field became a real bit vector (`5454b4e2`) — `Invoice.features` for the
  spec's own donation vector changed from `{0x82}` to `{0x41,0x00}` and `encode` now omits an
  all-zero `9`, so every downstream reader of that field sees different bytes. And
  `bech32_raw.stripContinuation`'s neighbour test for a BOLT#12 `+` was tightened from "not
  `+`, not whitespace" to "a member of the 32-symbol bech32 charset" (`03cc7f90`).
  ⛔ **That tightening is unresolved and is recorded here rather than reverted:** `o`, `b`,
  `i` and the separator `1` are not charset members and all occur in the BOLT#12 prefixes
  themselves, so three `+` placements a QR/tweet splitter can legitimately produce in an
  `lno1…` offer are now refused where they previously decoded. The vendored
  `format-string-test.json` passes under BOTH readings — all five of its invalid `+` rows are
  start-of-string, end-of-string or doubled-`+` — so **no external oracle backs either
  reading**, and the commit swapped one unanchored interpretation for another. The direction
  is fail-closed, so this is an interop question, not a security one; settling it needs a
  reference implementation's behaviour, which is out of licence scope here.

- **2026-08-21** — No behaviour change: recorded why the 65-byte signature `assert` in
  `decode` is an invariant rather than a bounds check (the `data.len < 7 + 104` rejection
  above it makes the slice exactly 104 quintets), so a future fail-open sweep does not
  re-flag it.

- **2026-08-06** — Security audit: seven findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against
  BIP-340's published test vectors.
- **2026-07-28** — RFC 6979 deterministic-nonce ECDSA signing and public-key recovery,
  previously implemented locally here because the sibling `k256` module
  shipped only Schnorr and ECDSA *verify*, moved to `k256.ecdsa_recover`.
  This module now re-exports them, so callers are unaffected and the
  algorithm is unchanged.
