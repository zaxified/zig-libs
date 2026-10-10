# btcaddr — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
