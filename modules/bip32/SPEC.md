# bip32 — SPEC

BIP-39 mnemonics + BIP-32 hierarchical-deterministic (HD) keys over
secp256k1; see [README.md](README.md) for purpose and API.

## Design

- **Source of truth**: `bitcoin/bips` BIP-0039 ("Mnemonic code for
  generating deterministic keys") and BIP-0032 ("Hierarchical Deterministic
  Wallets"). Both are public specifications — implementing them, however
  closely, is not "derived from" anyone's source (merger doctrine), so no
  `NOTICE` entry is required for the algorithms themselves. The embedded
  English wordlist (`wordlist.zig`) and the test vectors
  (`bip32_vectors.zig` / `bip39_vectors.zig`) are machine-transcribed
  verbatim from `bitcoin/bips/bip-0039/english.txt`,
  `bitcoin/bips/bip-0032.mediawiki`'s "Test Vectors" section, and
  `trezor/python-mnemonic`'s `vectors.json` (the de-facto standard BIP-39
  cross-implementation test corpus, referenced by BIP-39 implementations
  industry-wide) — reference data, not ported source.
- **Curve/hash deps, on purpose**: this module rides `k256` for secp256k1
  point/scalar arithmetic (`combMulBase` for `k·G`, `.add` for point
  addition, `.scalar.add`/`.rejectNonCanonical` for the mod-`n` scalar ops
  BIP-32 child derivation needs), `ripemd160` for the `hash160` fingerprint
  primitive, and `bech32`'s `base58.checkEncode`/`checkDecode` for the
  xprv/xpub wire format — all three are proven, already-KAT-validated
  modules in this repo; re-deriving any of them here would be pure
  duplication with no independent value.
- **BIP-39 word/entropy mapping** (`bip39.zig`): entropy (16/20/24/28/32
  bytes) → `SHA256(entropy)` → append the top `entropy_bits/32` checksum
  bits → slice the `entropy ‖ checksum` bitstream into 11-bit big-endian
  groups → each group indexes `wordlist.english`. `mnemonicToEntropy` is the
  literal inverse, re-deriving the checksum from the recovered entropy and
  comparing it bit-for-bit against the trailing checksum bits pulled from
  the mnemonic's own word indices — a tampered/forged mnemonic (right word
  count, valid words, wrong checksum) is rejected, exercised by a positive
  control in `bip39.zig`'s tests.
- **BIP-39 seed derivation**: `PBKDF2-HMAC-SHA512(password=mnemonic,
  salt="mnemonic"‖passphrase, rounds=2048, dklen=64)`, via
  `std.crypto.pwhash.pbkdf2` + `std.crypto.auth.hmac.sha2.HmacSha512`
  directly (both from std; the primitive is not reimplemented here). The
  concatenated salt lives in a caller-independent stack buffer
  (`max_passphrase_len = 256` ceiling) that is `secureZero`'d before return.
- **BIP-32 master key**: `HMAC-SHA512(key="Bitcoin seed", data=seed)` splits
  into `IL` (master private scalar) and `IR` (master chain code). Per spec,
  `IL >= n` or `IL == 0` makes the seed invalid (probability ~2^-127); this
  module reports `error.InvalidMasterKey` rather than silently retrying —
  retry/reseed policy is the caller's call, not this module's.
- **CKDpriv / CKDpub** (`ckdPriv`/`ckdPub`): the standard `I =
  HMAC-SHA512(key=chain_code, data = ser_p ‖ ser32(index))` split, where
  `ser_p` is `0x00 ‖ parent_privkey` for a hardened child (index `>=
  2^31`, private-key-only — `ckdPub` on a hardened index returns
  `error.HardenedRequiresPrivateKey` immediately, never touching HMAC) or
  the parent's 33-byte compressed pubkey for a normal child. Child key:
  `k_i = (IL + k_par) mod n` (private) or `K_i = IL·G + K_par` (public, via
  `k256.Secp256k1.combMulBase` + `.add`). Both directions reject the
  BIP-32-documented invalid-child case (`IL >= n` — caught by
  `k256.Secp256k1.scalar`'s canonical check on `add`/`rejectNonCanonical` —
  or the resulting scalar/point being zero/identity) as `error.InvalidChildKey`.
  **One deliberate over-conservative deviation**: `IL ≡ 0 (mod n)` on the
  public-derivation path is treated as an `InvalidChildKey` rejection
  (because `combMulBase` errors on a zero scalar), whereas a strict reading
  of BIP-32 would resolve it to `K_i = K_par` (since `IL·G` is the identity,
  contributing nothing) rather than reject. This only differs from the spec
  in an event with probability ~2^-256 that no published test vector
  exercises, and erring toward rejection is the safer failure mode for a
  module handling key derivation.
- **CKDpriv/CKDpub agreement**: for every NORMAL (non-hardened) index,
  `neuter(ckdPriv(parent, i))` and `ckdPub(neuter(parent), i)` must produce
  the identical pubkey + chain code — this is BIP-32's whole point (a
  watch-only xpub can derive the same normal-child public keys as the full
  xprv) and is asserted directly in `bip32.zig`'s tests and cross-checked
  against every non-hardened step of the official Test Vectors 1/2 in
  `kat_test.zig`.
- **Serialization** (`serializePriv`/`serializePub`/`parseExtended`): the
  78-byte BIP-32 payload (4 version + 1 depth + 4 parent-fingerprint + 4
  child-number + 32 chain-code + 33 key) through `bech32.base58.checkEncode`/
  `checkDecode` — no independent Base58Check implementation here. `parseExtended`
  is fail-closed on every axis the official Test Vector 5 corpus probes:
  version/key-type mismatch (xprv version but a `0x02`/`0x03`/`0x04`-prefixed
  key byte, or vice versa), invalid pubkey prefix, off-curve pubkey (via
  `k256.Secp256k1.fromSec1`'s own `NotSquareError`/`EncodingError`), private
  key `0` or `>= n`, the "zero depth must carry zero parent-fingerprint/
  child-number" invariant, an unrecognized version (including the two
  "unknown extended key version" `DMwo58...` vectors — accepted by
  `base58.checkDecode`'s checksum but rejected by the version-byte switch),
  and a bit-flipped checksum (caught by `base58.checkDecode` itself). All 13
  Test Vector 5 strings are asserted-rejected in `kat_test.zig`.
- **Derivation paths** (`parsePath`/`derivePath`): `m/44'/0'/0'/0/0`-style
  strings, `'`/`h`/`H` all accepted as the hardened marker (all three appear
  in real-world tooling), a leading `m`/`M` segment optional. No BIP-44/49/
  84/86 purpose-field policy is enforced — this module derives whatever path
  string it's given; a wallet layer building on this owns purpose-field
  validation.

## Threat model / scope caveats

- **Secret-material handling**: every stack buffer this module allocates
  that can hold private-key-derived bytes (`HMAC-SHA512` outputs in
  `masterFromSeed`/`ckdPriv`, the hardened-derivation `0x00 ‖ privkey ‖
  index` HMAC input, the PBKDF2 salt buffer holding the passphrase, the
  raw Base58Check-decoded payload in `parseExtended` after the private
  scalar has been copied out) is `secureZero`'d before the owning function
  returns. `ExtendedPrivKey.deinit` zeros the long-lived struct's `privkey`
  + `chain_code` — call it once a derived key is no longer needed. This
  module does **not** claim full constant-time hardening against
  microarchitectural side channels beyond what `k256`'s own field/group/
  scalar operations already provide (the same posture as this repo's other
  Bitcoin/Lightning modules riding `k256`); it defends against
  memory-disclosure-after-use, not power/cache/timing analysis of the CKD
  control flow itself (e.g. the hardened-vs-normal branch on `index` is
  public information anyway — the branch reveals nothing beyond what the
  caller already chose).
- **Unicode normalization not implemented**: BIP-39 mandates NFKD
  normalization of both the mnemonic and the passphrase before PBKDF2. The
  English wordlist is pure ASCII, where NFKD is the identity — so this is a
  no-op for every mnemonic this module itself produces and for any ASCII
  passphrase. A caller mixing in non-ASCII passphrase text, or mnemonic text
  sourced from elsewhere that isn't already NFKD-normalized, must
  pre-normalize it themselves. Multi-language wordlists (BIP-39 defines ten)
  are out of scope entirely — English only.
- **`parsePath` is not a BIP-44 purpose-field validator** — see above.
- **No xprv/xpub testnet version bytes** — only the mainnet constants
  (`0x0488ADE4`/`0x0488B21E`) are wired up; `parseExtended` rejects anything
  else (including testnet's `tprv`/`tpub`) as `error.UnknownVersion`. Adding
  a network parameter is a natural, low-risk follow-up if a testnet consumer
  appears.

## Verification

- **BIP-32 official Test Vectors 1, 2, 3** (`bip32_vectors.zig`, from
  `bitcoin/bips/bip-0032.mediawiki`): every chain link's serialized xprv
  AND xpub asserted byte-exact against the published strings, covering
  hardened derivation (`0'`), normal derivation, a large index
  (`2147483647'`, the max hardened index), and leading-zero-byte retention
  (Test Vector 3). CKDpub/CKDpriv cross-agreement is additionally checked at
  every non-hardened step.
- **BIP-32 official Test Vector 5** (13 invalid extended keys): every one
  rejected by `parseExtended`.
- **BIP-39 official Trezor test vectors** (24 English vectors,
  `bip39_vectors.zig`, from `trezor/python-mnemonic`'s `vectors.json`):
  entropy → mnemonic (byte-exact), mnemonic → entropy (inverse, byte-exact),
  mnemonic + passphrase `"TREZOR"` → 64-byte seed (byte-exact), and seed →
  BIP-32 master xprv (byte-exact) — the last step exercises the BIP-39/
  BIP-32 seam end-to-end, not just each spec in isolation.
- A positive control (`bip39.zig`) tampers a mnemonic's checksum-carrying
  word and asserts `error.InvalidChecksum`, proving the checksum check has
  teeth rather than silently accepting any wordlist-valid phrase.
