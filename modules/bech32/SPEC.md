# bech32 — spec

Bitcoin address encodings: bech32 (BIP173) + bech32m (BIP350) segwit addresses, and
base58/base58check (P2PKH/P2SH/WIF). Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants

- **Three layers, composed but independently usable:** `bech32.zig` (generic BIP173/BIP350
  codec — BCH checksum, HRP expansion, charset, `encode`/`decode` over 5-bit-grouped data, no
  notion of witness versions) `segwit.zig` (BIP141/BIP173/BIP350 segwit-address consensus rules
  layered on top) `base58.zig` (the unrelated, older Base58Check encoding + P2PKH/P2WPKH
  convenience over `ripemd160.hash160`). `root.zig` re-exports the first two flat and namespaces
  the third as `base58` (its own `encode`/`decode` would otherwise collide with the bech32 pair).

- **No allocation:** every function works through fixed-size stack buffers sized to the specs'
  own length ceilings — bech32/bech32m: BIP173's 90-character total-string ceiling (`max_len`);
  base58(check): a generous 128-byte-payload bound (`base58.max_payload_len`) covering every real
  Bitcoin base58 payload (P2PKH/P2SH 21B, WIF 33-34B, xprv/xpub 78B) with headroom — and returns
  owned value types (`Decoded`, `Bech32String`, `SegwitData`) or writes into a caller-supplied
  `out` buffer. `base58.decode`'s untrusted-length input is bounded (`error.InputTooLong`)
  *before* the O(n²) bignum carry loop runs, so an oversized string can't be used to burn CPU on a
  parse that was always going to fail.

- **Fail-closed on untrusted input, with a specific typed error per rejection reason** (not one
  catch-all): `bech32.DecodeError` distinguishes `MixedCase` / `NoSeparator` / `EmptyHrp` /
  `HrpTooLong` / `HrpCharOutOfRange` / `DataTooShort` / `InvalidDataChar` / `InvalidChecksum` /
  `TooLong`; `segwit.SegwitError` adds `InvalidHrp` / `EmptyDataSection` / `InvalidWitnessVersion`
  / `InvalidVariant` (BIP350's headline rule: witver 0 must checksum as bech32, witver 1+ must
  checksum as bech32m — a bech32 string with a v1 witver, or a bech32m string with a v0 witver,
  is rejected here, not silently accepted under the wrong scheme) / `InvalidPadding` (BIP173's
  5-to-8-bit conversion: the discarded tail bits must be 4 or fewer AND all zero — both "an extra
  whole padding group" and "non-zero padding bits" go through this one check, matching the
  reference `convertbits` algorithm's single combined condition) / `InvalidProgramLength`.

- **`quintetsToProgram`'s output buffer is sized for the worst case a checksum-VALID (but
  consensus-invalid) address can produce, not just the 40-byte consensus maximum.** A malicious
  address with a valid checksum but an oversized data section (up to `bech32.max_data_len - 1`
  quintets after the witness-version symbol, since BIP173's `max_len`=90 bounds the whole string)
  converts to up to 50 bytes *before* the subsequent `program.len > 40` check can reject it —
  `SegwitData.program_buf` is sized `max_decode_program_bytes` (50), not `max_program_len` (40),
  specifically so that write can never overrun the buffer regardless of what an attacker's
  checksum-valid-but-oversized address contains. Covered by a dedicated test
  ("malicious oversized data section fails closed, no overflow").

- **Case handling (BIP173 "Uppercase/lowercase"):** the lowercase form is what checksum
  verification runs against — `decode` rejects mixed-case strings outright, then lowercases
  internally before charset/checksum work (an all-uppercase string decodes fine; its HRP's high
  bits, which differ between cases, only match the checksum when the whole string was consistently
  one case). `encode` always emits the canonical all-lowercase form (`Bech32String`/`encodeSegwit`
  output), lowercasing a caller-supplied HRP automatically — case carries no chain-identity
  meaning, so this is a convenience, not data loss.

- **BIP173's own "valid segwit addresses" test-vector list is deliberately NOT used verbatim.**
  It predates BIP350's bech32m fix: 3 of its 8 addresses encode a witness version >= 1 but
  checksum as plain bech32 (BIP173 was written before the Taproot-driven discovery that a v1+
  witness program with a bech32 checksum has a much weaker error-detection guarantee than
  intended — the reason BIP350 exists). Feeding those 3 addresses through this module's
  BIP350-aware `decodeSegwit` correctly rejects them (`error.InvalidVariant`) — that is *this
  module keeping its promise*, not a bug. `kat_vectors.zig` instead pins BIP350's "Test vectors
  for v0-v16 native segregated witness addresses" list, which supersedes BIP173's and is
  internally consistent with the variant rule this module enforces (same v0 addresses,
  corrected checksums for the v1+ ones).

- Reentrant, no shared state, no heap allocation. `deps`: `ripemd160` (`hash160` for the
  P2PKH/P2WPKH helpers) + `std.crypto.hash.sha2.Sha256` (base58check's double-SHA256).

## Threat model / out of scope

Both `bech32.decode`/`decodeSegwit` and `base58.decode`/`checkDecode` are designed to run
directly on untrusted, attacker-controlled address strings (wallet input, QR-code scans, RPC
parameters) and never allocate, panic, or overrun a buffer on any input — every rejection path
returns a typed error. Not covered: this module does not itself validate that a decoded pubkey
hash / witness program corresponds to any real, spendable output — that's a consensus-layer
concern outside an address-encoding module's scope. Base58Check's checksum is a 32-bit
error-detection code (not a MAC) — like the upstream Bitcoin protocol, it is not a defense against
a deliberate forgery by an attacker who can freely compute SHA-256, only against transcription/
transmission errors; `checkDecode`'s bit-flip-detection test exercises exactly that error-detection
property, not cryptographic unforgeability.

## Verification

`zig build test-bech32` (headless; Debug + ReleaseFast). Anchors: the complete BIP173 "Test
vectors" appendix (7 valid + 12 invalid generic bech32 strings) and BIP350's bech32m analogue (7
valid + 14 invalid), each invalid vector asserted against its specific documented typed error;
BIP350's "Test vectors for v0-v16 native segregated witness addresses" (8 valid, checked
witver+program byte-exact against the vectors' own scriptPubKey hex, plus a re-encode round-trip;
15 invalid, each against its typed error) — see `kat_vectors.zig`'s doc comment for the
machine-transcription method (a Python re-implementation of both `decode` and `decodeSegwit` was
run over every vector and cross-checked against the BIP's stated reason before any Zig code was
written, catching one hand-transcription typo in the process). `base58.zig` carries a known
mainnet P2PKH vector (`1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH` <-> version `0x00` + hash160
`751e76e8199196d454941c45d1b3a323f1433bd6`, independently derived via a Python stdlib bignum
base58 decode while authoring this module — notably the same hash160 as BIP173's own segwit
test-vector address, since both encode the same 20-byte pubkey hash via the two different
Bitcoin address schemes) plus a single-bit-flipped-checksum positive control (both for the
segwit bech32m-variant path and for base58check). `segwit.zig` additionally covers the
convertBits round-trip over all program lengths 2..40 and the oversized-data-section
no-overflow case described above.

## Backlog / deferred

- **Bitcoin script-level address type detection** (P2SH-wrapped segwit, decoding a full
  `scriptPubKey` end-to-end) is out of scope — this module handles the two address *encodings*
  (bech32/bech32m and base58check), not Bitcoin Script.
- **Non-Bitcoin bech32 consumers** (Lightning invoices' bech32 layer, other chains' bech32m
  address formats) can reuse `bech32.encode`/`decode` directly today; no dedicated wrapper is
  built since no concrete consumer inside this repo has asked for one yet.

## Status

`extract · any · codec · reentrant` + deps: `ripemd160` — canonical source is `pub const meta` in
src/root.zig.
