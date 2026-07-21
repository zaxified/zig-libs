# bech32

Bitcoin address encodings: **bech32 (BIP173) + bech32m (BIP350)** segwit addresses, and
**base58/base58check** (the older P2PKH/P2SH/WIF encoding). Parses untrusted address strings, so
every decode function is fail-closed — mixed case, out-of-charset characters, a bad checksum, the
wrong bech32-vs-bech32m variant, and every BIP173/BIP350 length/range limit each get rejected with
a specific typed error, never a best-effort partial parse.

- **Model after:** BIP173 (bech32) + BIP350 (bech32m) + Bitcoin Core's `base58.cpp`
  Base58Check algorithm.
- **Platform:** any. **Role:** codec. **Concurrency:** reentrant (no shared state, no
  allocation). **Deps:** `ripemd160` (for `hash160`) + `std.crypto.hash.sha2.Sha256`.

Provenance: original work of the zig-libs authors (MIT), from the public BIP173/BIP350 specs and
the well-known Base58Check bignum technique — no third-party source ported. The BIP173/BIP350 test
vectors are a public specification artifact, fetched directly from the `bitcoin/bips` repository
(see `SPEC.md` for the transcription method).

## bech32 / bech32m — generic codec

```zig
const bech32 = @import("bech32");

const data = [_]u5{ 0, 1, 2, 3 };
const encoded = try bech32.encode("bc", &data, .bech32); // or .bech32m
// encoded.slice() -> "bc1qypqxpq..." (always lowercase — BIP173 "Encoders MUST...")

const decoded = try bech32.decode(encoded.slice());
// decoded.hrp() -> "bc", decoded.data() -> the 5-bit values, decoded.encoding -> .bech32
```

`bech32.DecodeError` has one variant per BIP173 "Test vectors" rejection reason: `MixedCase`,
`NoSeparator`, `EmptyHrp`, `HrpTooLong`, `HrpCharOutOfRange`, `DataTooShort` (checksum too short),
`InvalidDataChar`, `InvalidChecksum`, `TooLong` (>90 chars total). No allocation: `Decoded` and
`Bech32String` are fixed-size value types sized to BIP173's own 90-character ceiling.

## Segwit addresses (BIP141/BIP173/BIP350)

```zig
var program: [20]u8 = ...; // e.g. ripemd160.hash160(pubkey, &program) for P2WPKH

const addr = try bech32.encodeSegwit("bc", 0, &program); // witver 0 -> bech32
// addr.slice() -> "bc1q..."

const dec = try bech32.decodeSegwit("bc", addr.slice());
// dec.witver -> 0, dec.program() -> the 20 bytes back
```

`encodeSegwit`/`decodeSegwit` enforce every BIP141/BIP173/BIP350 consensus rule: witness version
0-16, program 2-40 bytes, **version 0 must be exactly 20 or 32 bytes**, and — BIP350's headline
addition — **version 0 must checksum as bech32, version 1+ must checksum as bech32m**; a
bech32-checksummed v1+ address (or a bech32m-checksummed v0 address) is rejected with
`error.InvalidVariant`, not silently accepted. `segwit.SegwitError` extends `DecodeError` with
`InvalidHrp` (doesn't match the `expected_hrp` you passed in), `EmptyDataSection`,
`InvalidWitnessVersion`, `InvalidVariant`, `InvalidPadding` (BIP173's 5-to-8-bit conversion:
non-canonical padding), and `InvalidProgramLength`.

## base58 / base58check

```zig
const bech32 = @import("bech32");

var out: [64]u8 = undefined;
const s = try bech32.base58.encode(&.{ 0, 1, 2, 3 }, &out); // leading zero byte -> leading "1"

var back: [64]u8 = undefined;
const bytes = try bech32.base58.decode(s, &back);
```

Base58Check wraps that with a 4-byte double-SHA256 checksum
(`base58(payload ++ SHA256(SHA256(payload))[0..4])`):

```zig
var out: [64]u8 = undefined;
const addr = try bech32.base58.checkEncode(payload, &out);

var back: [64]u8 = undefined;
const payload2 = try bech32.base58.checkDecode(addr, &back); // error.ChecksumMismatch on tamper
```

Convenience helpers for the two Bitcoin pubkey-hash address types (caller supplies the raw
public-key bytes; this module hashes them via `ripemd160.hash160`):

```zig
// P2PKH: base58check(version ++ hash160(pubkey))
var out: [64]u8 = undefined;
const p2pkh = try bech32.base58.encodeP2PKH(0x00, pubkey, &out); // 0x00 = mainnet

// P2WPKH witness program: hash160(pubkey) — feed straight to encodeSegwit(hrp, 0, program)
var program: [20]u8 = undefined;
bech32.base58.p2wpkhWitnessProgram(pubkey, &program);
const p2wpkh = try bech32.encodeSegwit("bc", 0, &program);
```

`base58.Error`: `InvalidChar`, `PayloadTooLarge` (`encode`'s input > `max_payload_len`, 128
bytes — generous headroom over P2PKH/WIF/xprv/xpub), `InputTooLong` (`decode`'s untrusted input >
`max_encoded_len`, rejected *before* the O(n²) bignum carry loop runs), `BufferTooSmall`.
`base58.CheckError` adds `TooShort` and `ChecksumMismatch`.

## Tests

`zig build test-bech32` (headless; green in Debug and `-Doptimize=ReleaseFast`). Anchors: the
complete official BIP173 + BIP350 valid/invalid test-vector appendices (generic bech32/bech32m
strings and v0-v16 segwit addresses), each invalid vector checked against its specific typed
error; a known mainnet P2PKH base58check vector (independently derived, not from this module's own
code); single-bit-flipped-checksum positive controls for both bech32m-variant mismatch and
base58check. See `SPEC.md` for the full verification breakdown and design rationale (including why
BIP173's own older segwit test-vector list isn't used verbatim).

## Deferred (not implemented)

- Bitcoin Script-level address-type detection (P2SH-wrapped segwit, full `scriptPubKey` parsing)
  — out of scope; this module handles the two address *encodings*, not Script.
- A dedicated non-Bitcoin bech32 wrapper (e.g. Lightning invoices) — `bech32.encode`/`decode` are
  already reusable directly; no concrete in-repo consumer has asked for a wrapper yet.
