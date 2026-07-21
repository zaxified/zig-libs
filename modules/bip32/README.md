# bip32

BIP-39 mnemonic seed phrases + BIP-32 hierarchical-deterministic (HD) keys
over secp256k1 — the key-derivation foundation under every Bitcoin/Lightning
wallet in this collection (and any future one): a 12-24 word recovery
phrase in, a full tree of derived keypairs out.

**Status: complete — BIP-39 (English) entropy↔mnemonic↔seed and BIP-32
master/child derivation + xprv/xpub Base58Check serialization + derivation-
path parsing, all KAT-validated against the official BIP-32 Test Vectors
1/2/3/5 and the BIP-39 Trezor test-vector corpus.** See `SPEC.md` for the
design and threat model.

| File | Contents |
|---|---|
| `wordlist.zig` | The official 2048-word BIP-39 English wordlist |
| `bip39.zig` | `entropyToMnemonic`, `mnemonicToEntropy`, `validateMnemonic`, `mnemonicToSeed` |
| `bip32.zig` | `masterFromSeed`, `ckdPriv`/`ckdPub`, `neuter`, `serializePriv`/`serializePub`/`parseExtended`, `parsePath`/`derivePath` |
| `bip32_vectors.zig` | BIP-32 official Test Vectors 1/2/3/5, embedded |
| `bip39_vectors.zig` | BIP-39 official Trezor English test vectors, embedded |
| `kat_test.zig` | Full KAT assertions across both specs, incl. the BIP-39→BIP-32 seed→master-xprv seam |

## Import

```zig
const bip32 = @import("bip32");
```

## API surface

**BIP-39 — mnemonic ↔ seed** (`bip32.mnemonic`):

```zig
var mnemonic_buf: [bip32.mnemonic.max_mnemonic_len]u8 = undefined;
const phrase = try bip32.mnemonic.entropyToMnemonic(entropy, &mnemonic_buf); // entropy: 16/20/24/28/32 bytes

try bip32.mnemonic.validateMnemonic(phrase); // word count + wordlist + checksum

var entropy_buf: [bip32.mnemonic.max_entropy_bytes]u8 = undefined;
const entropy = try bip32.mnemonic.mnemonicToEntropy(phrase, &entropy_buf); // the inverse

var seed: [64]u8 = undefined;
try bip32.mnemonic.mnemonicToSeed(phrase, "my passphrase", &seed); // PBKDF2-HMAC-SHA512, 2048 rounds
```

**BIP-32 — master key + child derivation:**

```zig
var master = try bip32.masterFromSeed(&seed);
defer master.deinit(); // zeroes the secret privkey/chain_code fields

var hardened_child = try bip32.ckdPriv(master, bip32.hardened_offset + 0); // m/0'
defer hardened_child.deinit();

var normal_child = try bip32.ckdPriv(master, 5); // m/5
defer normal_child.deinit();

const pubkey_only = try bip32.neuter(master); // drop the private key
const via_pub = try bip32.ckdPub(pubkey_only, 5); // watch-only derivation, normal children only
```

**Derivation paths** (`m/44'/0'/0'/0/0`, `'`/`h`/`H` all accepted as hardened):

```zig
var path_buf: [bip32.max_path_depth]u32 = undefined;
const path = try bip32.parsePath("m/44'/0'/0'/0/0", &path_buf);
var derived = try bip32.derivePath(master, path);
defer derived.deinit();
```

**Serialization (xprv/xpub, mainnet):**

```zig
var out: [bip32.max_serialized_len]u8 = undefined;
const xprv = try bip32.serializePriv(master, &out);

const pub_key = try bip32.neuter(master);
const xpub = try bip32.serializePub(pub_key, &out);

const parsed = try bip32.parseExtended(xprv); // ParsedKey union(enum) { private, public }
switch (parsed) {
    .private => |k| { /* ExtendedPrivKey */ },
    .public => |k| { /* ExtendedPubKey */ },
}
```

## Verify

```
zig build test-bip32                       # Debug
zig build test-bip32 -Doptimize=ReleaseFast # ReleaseFast
zig fmt --check modules/bip32/
```

BIP-32 official Test Vectors 1/2/3 (`bip32_vectors.zig`): every chain
link's xprv AND xpub asserted byte-exact against the published strings,
covering hardened + normal derivation and leading-zero-byte retention.
Test Vector 5 (13 invalid extended keys) all rejected. BIP-39 official
Trezor vectors (24 English, `bip39_vectors.zig`): entropy → mnemonic →
seed (passphrase `"TREZOR"`) → BIP-32 master xprv, every step byte-exact,
including a round-trip back to entropy and a checksum-tamper positive
control.

Provenance: see [SPEC.md](SPEC.md) (public-spec merger-doctrine note; no
`NOTICE` entry required for the BIP-39/BIP-32 algorithms themselves).
