# taproot — SPEC

BIP341 key-path output-key tweaking; see [README.md](README.md) for purpose
and API. Provenance: see [NOTICE](NOTICE).

## Design

- **Source of truth**: BIP341 ("Taproot: SegWit version 1 spending rules",
  `bitcoin/bips`), §"Constructing and Spending Taproot Outputs" (the
  key-path tweak). This module does not implement script-path spending, the
  Merkle-tree construction itself, or the sighash algorithm (BIP341's other
  sections) — only the tweak that turns an internal key into an output
  key/scalar, taking the script tree's Merkle root (if any) as an opaque
  32-byte input the caller already computed.
- **Reuse of `bip340`**: the curve group (`std.crypto.ecc.Secp256k1`),
  `XOnlyPublicKey`/`lift_x`, `SecretKey`, and the tagged-hash machinery
  (`bip340.hash.taggedHash`/`taggedHasher`) are all the sibling `bip340`
  module's — this module adds exactly one new thing on top: the
  `"TapTweak"` domain tag and the BIP341-specific tweak algebra
  (`P + t*G` / `d + t mod n`, distinct from BIP340's own sign/verify
  equations).
- **`"TapTweak"` tagged hash** (`tapTweakHash`): `SHA256(SHA256("TapTweak")
  ‖ SHA256("TapTweak") ‖ P_x ‖ merkle_root)` when `merkle_root` is present,
  or the same construction with nothing appended after `P_x` when it is
  `null`. This is real, implemented, and KAT-tested against all 7 rows of
  the official BIP341 wallet test vectors (`kat_test.zig`) — including a
  dedicated test proving `null` (no script tree) and an explicit all-zero
  32-byte root hash to DIFFERENT values, so the two cases can never be
  silently conflated by a future refactor.
- **`TweakedPublicKey`**: unlike `bip340.XOnlyPublicKey` (which always
  represents the even-y resolution and drops parity), a Taproot output key
  needs its y-parity carried explicitly — BIP341 script-path spending
  encodes it in the low bit of a control block's leading byte
  (`leaf_version | parity`). `asXOnly()` is a pure relabeling (32 bytes in,
  32 bytes out) for callers that want to feed the output key into
  `bip340.verify`/`bip340.sign`; it does not re-validate the point (whatever
  produced the `TweakedPublicKey` already established it is a real x-only
  encoding of an on-curve point).
- **`TweakResult`**: bundles the output key with the raw 32-byte tweak hash
  `t` — useful for a verifier that wants to independently recheck a claimed
  tweak against a control block without re-deriving it from scratch.

## Threat model / limits

- **A wrong tweak is a fund-loss bug, not a correctness nitpick.** Two
  failure directions, both severe:
  - **Too permissive** (e.g. skipping the `t ≥ n` rejection, or getting the
    even-y normalization backwards in `tweakSecretKey`): can produce a `q`
    that does NOT actually correspond to the claimed output key `Q`, or —
    worse — one where an attacker who can predict/influence the tweak
    hash's input (e.g. a manipulable Merkle root) gains any leverage over
    the resulting key. BIP341's `t ≥ n` check exists precisely so
    implementations don't silently wrap/reduce into a different, unintended
    scalar.
  - **Too strict or simply wrong arithmetic**: produces an output nobody —
    not even the legitimate owner — can ever spend from (funds
    permanently lost). This is the "unspendable key" failure mode the task
    brief calls out, and it is just as severe as the attacker-spendable
    direction: there is no silent-degradation middle ground with Taproot
    tweaking, only "exactly right" or "funds gone".
- **Even-y interaction (`tweakSecretKey`)**: the additive tweak `+t` MUST
  land on the internal key's even-y-normalized scalar `d` (same
  normalization `bip340.KeyPair.fromSecretKey` already performs for BIP340
  signing), never on the raw, as-stored secret scalar `d0`. Tweaking `d0`
  directly produces a scalar whose public key matches the claimed output
  key only when `d0*G` already happened to have even y — i.e. correct only
  about half the time. This is flagged explicitly in `tweakSecretKey`'s doc
  comment as the single most error-prone step to get right, because it is
  the kind of bug that passes casual testing (any test using an
  even-y-yielding secret key by chance) and fails silently on the other
  half of all possible keys.
- **`null` merkle_root vs. an explicit all-zero root are different
  inputs.** BIP341 leaves "what 32 bytes to pass for script-path-disabled"
  as a caller-level policy choice (e.g. some wallets commit to an
  unspendable script as a defense-in-depth convention); this module treats
  `null` as "no script tree exists, hash `P_x` alone" and any `[32]u8`
  value — including all-zero — as "append these 32 bytes." Conflating the
  two would silently change which spending policies an output actually
  commits to.
- **`t ≥ n` rejection is a real, checked code path**, not a documented-but-
  unenforced edge case — even though it is astronomically unlikely for any
  real SHA-256 output (probability roughly `(2^256 - n) / 2^256`, i.e. the
  curve-order gap below `2^256`), a correct implementation checks it rather
  than assumes it away, per BIP341's own wording ("fails if `t ≥ n`").
- **Constant-time**: `tweakSecretKey` handles secret data (`d`, `q`) and
  uses only `Secp256k1.scalar`'s constant-time field arithmetic for the
  `(d + t) mod n` step; the even-y normalization is delegated verbatim to
  `bip340.KeyPair.fromSecretKey`, so this module introduces no
  secret-dependent branching beyond what the bip340 signing path itself
  already has (the parity branch inside `fromSecretKey` — the identical
  code `bip340.sign` runs). `tweakPublicKey` operates on public data only
  and makes no constant-time claim (mirroring `bip340.verify`'s documented
  exemption).

## Crypto cores — done-record (was: TODO(fable))

Both cores are implemented in `root.zig` (crypto pass 2026-07-12); the
former `@panic` stubs and the `error.SkipZigTest` KAT guards are gone.

1. **`tweakPublicKey`** — BIP341's `taproot_output_key`:
   `t = int(tapTweakHash(internal.toBytes(), merkle_root))`; reject
   `t ≥ n` via `Scalar.fromBytes`'s canonical check (reject, never
   reduce); `P = internal.lift()`; `Q = P + t*G` (one
   `basePoint.mul` + one complete point add; a zero `t` — where `mul`
   refuses to produce the identity — degrades explicitly to `Q = P`, and
   an identity `Q` is rejected defensively since it has no affine
   coordinates); output = x-only(Q), parity = `Q.y.isOdd()`; returns the
   raw 32-byte tweak-hash bytes alongside. KAT: all 7 official vectors'
   `tweakedPubkey` byte-exact + the control-block-recovered parity
   (rows 1-6) + the returned `tweak` field.
2. **`tweakSecretKey`** — the matching secret-key tweak: even-y
   normalization delegated to `bip340.KeyPair.fromSecretKey` itself
   (`kp.secret` = the normalized `d`, `kp.public.x` = `bytes(x(d*G))`),
   so the tweak lands on exactly the scalar BIP340 signing uses — the
   half-the-keys-wrong raw-`d0` pitfall is structurally impossible; `t`
   hashed over that same even-y `internal_x`, rejected if `≥ n`;
   `q = (d + t) mod n` via constant-time scalar add. KAT: all 7 vectors'
   published `tweakedPrivkey` byte-exact, PLUS an operational
   sign→verify round-trip per vector (`bip340.sign` under `q` verifies
   against `Q`'s x-only encoding, and `q`'s own derived x-only public key
   equals `x(Q)`).

Design references: none beyond the BIP341 specification text itself,
`std.crypto.ecc.Secp256k1`, and the sibling `bip340` module (see `NOTICE`).

## Verification

- KAT oracle: the official BIP341 "wallet test vectors",
  `bip-0341/wallet-test-vectors.json` from `bitcoin/bips` (see `NOTICE` for
  the fetch source), re-paired by `internalPubkey` into 7 rows in
  `src/kat_vectors.zig` — 1 key-path-only (`merkle_root = null`) and 6 with
  a real script-tree Merkle root; parity recovered independently from each
  row's `scriptPathControlBlocks[0]` leading byte.
- Exercised (`src/kat_test.zig`): `tapTweakHash` reproduces the published
  `tweak` field for all 7 rows, plus a dedicated test proving the
  `null`-vs-all-zero-root distinction; `tweakPublicKey` reproduces all 7
  rows' `tweakedPubkey` + parity + tweak; `tweakSecretKey` reproduces all
  7 rows' `tweakedPrivkey`; a sign→verify round-trip proves the two cores
  mutually consistent and usable through `bip340` on every row;
  `TweakedPublicKey.toBytes`/`asXOnly` round-trip on a real on-curve value.
- Both `zig build test-taproot` (Debug) and `-Doptimize=ReleaseFast` pass
  — zero skips, no test failures — and `zig fmt --check
  modules/taproot/` is clean.
