# bip32 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-08** — `fuzzParsePath`'s alphabet-bending loop had never executed its body outside
  `--fuzz`. The knob is drawn AFTER the byte draw, and `Smith.slice` leaves the seed exhausted,
  so `boolWeighted(1, 4)` returned its weight minimum: measured **0 `true` in 159 draws** across
  the fifteen path seeds. Two seeds now carry a `u64` word per octet the knob decides (a fully
  bent one that becomes `m/0'/1`, and one where only the first octet is bent), taking the corpus
  to 7 parsed paths / 18 levels / 9 hardened indices and 7 bent octets in 168 draws — all pinned
  in the corpus guard as exact counts, `bend_draws` beside `bent` so a shortened seed is noticed
  as well as a lost tail. Tests only.

- **2026-09-07** — Both fuzz targets had only ever parsed the empty string. `fuzzParseExtended`
  and `fuzzParsePath` each drew their text with `smith.bytes(&buf)` and then took a length from
  `smith.valueRangeAtMost(u8, 0, buf.len)`; a ranged `Smith` draw reads eight octets as a
  little-endian `u64` and returns the range MINIMUM when fewer remain, and `bytes` had already
  consumed them — so `len` was 0 on every input, `parseExtended` failed the Base58 length check
  before touching the checksum, version bytes or key material, and `parsePath` refused an empty
  path, both with the text sitting unread in `buf`. Now one `smith.slice(&buf)` call each. The
  `parseExtended` corpus is built by the module's own `serializePriv`/`serializePub` (an
  `xprv` is Base58**Check**, so a hand-edited literal dies at `ChecksumMismatch` before any
  field is read); the `parsePath` corpus is quoted from the value tests and the F5 regression.
  Measured: **`parseExtended` 0 of 8 seeds non-empty, 0 keys parsed → 7/8 non-empty, 2 private
  + 1 public parsed, 3 checksum failures; `parsePath` 0 of 15 non-empty, 0 parsed, 0 levels →
  14/15 non-empty, 5 parsed, 14 derivation levels, 8 hardened.** ⚠ Found while writing the
  guard: a 97-character path seed against the 96-octet harness buffer reads back EMPTY, not
  truncated, and only the corpus guard's reach count noticed.

- **2026-08-06** — Security audit: six findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). Byte-exact against
  BIP-32's published test vectors.
- **2026-07-21** — New module: BIP-39 mnemonic seed phrases + BIP-32
  hierarchical-deterministic (HD) keys over secp256k1.
