# bip32 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-16** — First ctgrind harness, `src/ctgrind_harness.zig` (A1 M6); no library code
  changed. Targets `master` (seed), `derive` (master scalar along `m/44'/0'/0'/0/0`), `seed`
  (mnemonic → PBKDF2) and `mnemonic` (mnemonic → entropy). In-file 1 / 5 / 0 / 3: the first two
  are verdict branches of BIP-32's validity checks and `k256`'s documented `rejectIdentity`/
  canonical checks; `mnemonic`'s 3 are the known non-constant-time word split and `wordIndex`
  binary search (`SPEC.md`), now pinned so a change either way is visible.

- **2026-09-13** — **BREAKING:** A1 finding L7. `serializePriv(k, network, out)`,
  `serializePub(k, network, out)` and `parseExtended(s, network)` take a new `Network`
  (`.mainnet` / `.testnet`); serialization always wrote mainnet version bytes before.
  `parseExtended` refuses the other network's key with the new `error.WrongNetwork` (a
  `tpub` given to a mainnet parse used to be `error.UnknownVersion`). New constants
  `version_testnet_priv`/`version_testnet_pub`. Testnet KAT: Test Vector 1's master
  re-encoded with testnet version bytes by an independent Python implementation.

- **2026-09-10** — A1 fix campaign: closed 19 of the 21 findings from the 2026-09-06
  audit (`H1`-`H5`, `M1`-`M5`, `M7`-`M9`, `L1`-`L6`), each with a RED-before/GREEN-after
  `scripts/modtest bip32` run. Highlights:
  - **H1** `mnemonicToEntropy`/`validateMnemonic` used `tokenizeScalar`, which silently
    collapses doubled/leading/trailing spaces, while `mnemonicToSeed` hashes the raw
    bytes unmodified — so a doubled space produced the SAME "valid" verdict but a
    DIFFERENT master seed. Now `splitScalar`, matching `parsePath`'s existing
    two-spellings-one-identity defense (wave-2 finding F5).
  - **H2** `validateMnemonic`'s own entropy buffer was never wiped, contradicting the
    module's own zeroization doc comment. Now `defer secureZero`s it (measured: dead-stack
    hits for the entropy pattern 3x -> 2x; two residual copies come from
    `mnemonicToEntropy`'s own internal `idxs`/checksum buffers, a distinct, still-open gap).
  - **H3** `masterFromSeed` had no seed-length bound; BIP-32 requires 128-512 bits.
    New `error.InvalidSeedLength` (additive, module has 0 consumers).
  - **H4** the `xprv` private-key range check was tested only at the exact bit patterns
    of BIP-32 vector 5 (`0` and `n`); a weakened check matching just those two survived
    the whole suite. New ladder tests at `n+1`/`n+2`/`2^256-1`.
  - **H5** `ckdPriv` recomputed the parent's `k·G` on every call — 93.5% of its cost, and
    identical across every sibling. New additive `ckdPrivWithParentPub(parent, parent_pub,
    index)` lets a caller deriving many siblings compute the parent pubkey once. Measured
    1000-sibling scan: 44.4ms -> 2.2ms (**20x**).
  - **M1** four BIP-32-mandated reject branches (`masterFromSeed`'s `IL>=n`/`IL==0`,
    `ckdPriv`'s `child_priv==0`, `ckdPubFromIL`'s identity-point reject) had zero tests;
    all four SURVIVED direct mutation. New test-only seams (`masterFromIL`,
    `ckdPrivFromIL`, mirroring the existing `ckdPubFromIL`) let tests drive each guard
    with the exact synthetic `IL` that triggers it.
  - **M2** the `ckdPubFromIL` non-canonical-`IL` test used a single value (`0xFF*32`); a
    check weakened to match only that exact pattern survived. New tests at `n`/`n+1`.
  - **M3**/**M4** the `idxs[24]` word-count bound and the 78-byte `parseExtended` length
    check were untested; removing either SURVIVED the suite in Debug and caused an
    out-of-bounds read/panic under mutation. New tests for both.
  - **M5** already fixed 2026-09-07/08 (commits `93b87087`, `e816a729`): both fuzz
    harnesses now actually read their input.
  - **M7** added interior-invalid-value tests (word counts 13-23, entropy lengths 17-31)
    alongside the existing edge-only tests.
  - **M8** documented the "watch-only `xpub` + one leaked non-hardened child privkey
    recovers the parent privkey" property in `SPEC.md` (a BIP-32 property, not a defect —
    it's why BIP-44 hardens the first three path levels). `ExtendedPubKey.deinit` now
    zeros `chain_code` (also closes **L3**).
  - **M9** the BIP-39 checksum comparison exited on the first mismatching bit, leaking
    how many leading bits matched. Now accumulates all bits via XOR/OR before checking
    once, so the loop always runs `cs_bits` iterations (closes the iteration-count oracle;
    not itself a constant-time proof — deferred to the ctgrind campaign along with **M6**).
  - **L1** `parsePath` accepted unbounded leading zeros (`m/007` == `m/7`); now rejected,
    matching the `+`/`_` leniency guard already there.
  - **L2** `SPEC.md`/`README.md` said "13 invalid" / vectors "1/2/3/5"; corrected to the
    actual 16 / "1/2/3/4/5".
  - **L4**/**L5**/**L6** verified and closed with no module-level action: L4 (PBKDF2 vs
    OpenSSL) and L6 (`base58.digitValue`) are `std`/`bech32` concerns, not `bip32`'s own
    code; L5's "at parity" claim was in an old, separate audit ledger, not in this
    module's own docs.
  - **M6** (ctgrind coverage) and **L7** (testnet version bytes, an API-changing decision)
    left open — see `A1/bip32.md`'s Dispozice section.
  `scripts/modtest bip32`: 40/40 (Debug and ReleaseFast).

- **2026-09-09** — Licensing: added `NOTICE` (kind `third-party attribution`). No code
  changed. `src/bip32_vectors.zig` and `src/bip39_vectors.zig` had both carried "see
  NOTICE / SPEC.md for provenance" in their own headers while `modules/bip32/NOTICE` did
  not exist — a pointer to nothing. The vectors are BIP-32's own (BSD-2-Clause, author
  Pieter Wuille) and the Trezor English BIP-39 set from `trezor/python-mnemonic` (MIT,
  Copyright 2013-2016 Pavol Rusnak); both licence texts are now reproduced. The
  condition has been in force since the vectors were committed.
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
