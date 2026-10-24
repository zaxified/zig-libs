# btcaddr — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-24** — **NO CONSUMER-VISIBLE CHANGE:** the `strRepeat` helper (the Zig 0.17 stand-in for `**`) builds its string with one `@splat` + `@bitCast` instead of a comptime loop, which Sema evaluated in O(n²) (http's test binary: 323 s → 13 s). Same bytes, faster compile.

- **2026-10-18** — Ported to Zig 0.17.0. `strRepeat` helper is now `inline fn` (dangling-temporary fix).
- **2026-10-18** — ctgrind target `wif` (new `src/ctgrind_harness.zig`): private key through `wifEncode` → `wifDecode`, 0 in-file contexts; the pre-2026-10-18 early-exit range check gives 6 (negative control). Pinned in `scripts/checks/ctgrind-expected.tsv`. Tool only, no API change.
- **2026-10-18** — constant time on the WIF paths: `wifEncode`/`wifDecode` use `bech32.base58.checkEncodeSecret`/`checkDecodeSecret`, the version byte and compression flag are declassified as public metadata, and `keyInRange` is a borrow-and-mask comparison (was `std.mem.eql` + `std.mem.order`, early exit on the key). Same results and errors; `wifEncode`'s `out` must now hold 51 (uncompressed) / 52 (compressed) bytes, which every WIF needs anyway.
- **2026-10-10** — tests: deterministic fuzz driver `BTCADDR_FUZZ` over the address/WIF decode harness (generic over its choice source) plus a roundtrip oracle (an address issued for a random script decodes to it, a substituted character is refused, a WIF roundtrips). No code change.
- **2026-10-09** — **BREAKING:** `wifDecode(s)` returning `Wif` by value is now `wifDecode(out: *Wif, s) WifDecodeError!void`: the private key is written only into the caller's slot (`out.key` zeroed on error), never returned, and the body runs under an 8 KiB `burn.run`. Migrate `var w = try wifDecode(s)` to `var w: Wif = undefined; try wifDecode(&w, s)`. No caller outside this module's tests and `example/main.zig`. Probed in `stackprobe_test.zig`.
- **2026-10-09** — Dead-stack burn: `wifEncode` (private key, payload, checksum, base58 division) runs its body under `burn.run` (8 KiB, one-shot); new `stackprobe_test.zig` on `testkit.stackprobe`. No signature change.

- **2026-10-03** — **NO CONSUMER-VISIBLE CHANGE:** first audit (review + mutation run, 53
  mutants, 11 survived the first pass, all killed now); three tests added for the template
  bytes, the witness-version opcode range and the 65-byte key prefix. No source change.

- **2026-09-30** — **NO CONSUMER-VISIBLE CHANGE:** a fuzz harness over `toScriptPubKey` and
  `wifDecode` (tests only) and `example/main.zig`, a wallet's send-to field and key import.

- **2026-09-30** — New module: the Bitcoin address layer above `bech32`. scriptPubKey <->
  address for P2PKH, P2SH, P2WPKH, P2WSH, P2TR and witness v1..v16 (BIP350); network
  detection that reports the SET of networks a string is valid on (testnet, signet and regtest
  share encodings); WIF private-key encode/decode with the compressed flag and a curve-order
  range check; P2SH / P2WSH / P2SH-P2WPKH / P2SH-P2WSH script helpers. Verified against all 70
  valid and 70 invalid rows of Bitcoin Core's `key_io_valid.json` / `key_io_invalid.json`,
  plus BIP143/BIP173/BIP350 examples.
