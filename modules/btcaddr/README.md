# btcaddr

The Bitcoin address layer above the `bech32` codec: **scriptPubKey <-> address** for P2PKH, P2SH,
P2WPKH, P2WSH, P2TR and future witness versions (v1..v16, BIP350), **network detection** from the
base58 version byte / bech32 HRP, **WIF** private-key encode/decode, and **P2SH / P2WSH /
P2SH-P2WPKH** script helpers. Allocation-free, fail-closed on untrusted strings, one typed error
per rejection reason.

- **Model after:** Bitcoin Core `key_io.cpp` (`DecodeDestination`, `EncodeSecret`) and
  rust-bitcoin `Address`.
- **Platform:** any. **Role:** codec. **Concurrency:** reentrant. **Deps:** `bech32`
  (bech32/bech32m + base58check), `ripemd160` (`hash160`), std SHA-256.

Provenance: original work of the zig-libs authors (MIT), from BIP13/16/141/143/173/350 and the
WIF description; no third-party source read or ported. The test corpus is Bitcoin Core's
`key_io_valid.json` / `key_io_invalid.json` (MIT test data, see `NOTICE`).

```zig
const btcaddr = @import("btcaddr");

// address -> scriptPubKey (+ which networks it is valid on)
const d = try btcaddr.toScriptPubKey("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
// d.script(), d.kind == .p2wpkh, d.payload() (the 20-byte hash), d.chains.unique() == .mainnet

// scriptPubKey -> address on a chosen network
const a = try btcaddr.fromScriptPubKey(d.script(), .testnet);
// a.slice() == "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"

// pin the network when the caller knows it
_ = try btcaddr.toScriptPubKeyFor(str, .signet); // error.WrongNetwork otherwise
```

**Networks.** testnet, signet and regtest share the base58 versions `0x6f`/`0xc4`/`0xef`, and
testnet and signet share the `tb` HRP. `toScriptPubKey` therefore returns a `Chains` set (`bc`
and `0x00/0x05/0x80` -> mainnet; `bcrt` -> regtest; `tb` -> testnet+signet; other base58 ->
all three), never a guess. Encoding takes a concrete `Network`.

**WIF** (`wifEncode`/`wifDecode`): version `0x80` / `0xef`, optional `0x01` compression flag,
key checked to be in `[1, n-1]`. `wifDecode(&out_wif, s)` fills the caller's `Wif` (secret: call `wipe()`); scratch buffers
inside the module are wiped on every exit.

**Helpers:** `p2pkhOfPublicKey`, `p2wpkhOfPublicKey`, `p2shP2wpkhOfPublicKey`,
`p2shOfRedeemScript`, `p2wshOfWitnessScript`, `p2shP2wshOfWitnessScript`, and the raw templates
`scriptP2pkh/P2sh/P2wpkh/P2wsh/P2tr`. Sizes are enforced (redeem script <= 520, witness script
<= 10000; segwit helpers require a compressed key).

**Not here:** script interpretation (anything outside the seven templates is
`error.UnsupportedScript`), key derivation, taproot tweaking, curve-membership checks of public
keys, descriptors. See `SPEC.md`.

## Tests

`scripts/modtest btcaddr`. Anchors: all 70 valid and 70 invalid rows of Bitcoin Core's
`key_io_*.json` (both directions, per chain), BIP143 / BIP173 / BIP350 examples, well-known WIF
strings for key 1.
