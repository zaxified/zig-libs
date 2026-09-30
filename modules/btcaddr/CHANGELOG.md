# btcaddr — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-30** — New module: the Bitcoin address layer above `bech32`. scriptPubKey <->
  address for P2PKH, P2SH, P2WPKH, P2WSH, P2TR and witness v1..v16 (BIP350); network
  detection that reports the SET of networks a string is valid on (testnet, signet and regtest
  share encodings); WIF private-key encode/decode with the compressed flag and a curve-order
  range check; P2SH / P2WSH / P2SH-P2WPKH / P2SH-P2WSH script helpers. Verified against all 70
  valid and 70 invalid rows of Bitcoin Core's `key_io_valid.json` / `key_io_invalid.json`,
  plus BIP143/BIP173/BIP350 examples.
