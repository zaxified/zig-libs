# rescue

**The other arithmetization-oriented hash.** Same goal as
[`poseidon`](../poseidon/README.md) — be cheap inside an arithmetic circuit —
and the opposite trade on the way there.

Poseidon runs one S-box, `x^5`, in every round. Rescue alternates `x^alpha`
with its **inverse**: the first half of each round raises every state element to
the 7th power, the second half takes a 7th root. The root is an exponentiation
by a full 64-bit exponent — 72 multiplications against the forward S-box's 5 —
so **76% of a Rescue permutation is spent taking roots** (measured, below),
work no Poseidon round does at all. In exchange a *verifier* never computes the
root: it
asserts `y^7 == x`, the same degree-7 constraint as the forward direction. That
buys a shorter and completely uniform algebraic description (7 rounds, all
identical, no full/partial split) which some proof systems price better.

That asymmetry is the entire reason both hashes exist.

**Status: COMPLETE for the shipped instances.** Permutation, both published
sponge framings, both published widths, plus the original Rescue-Prime round
order for comparison.

**Model-after:** the RPO authors' `rescue_prime_optimized.sage` reference,
miden-crypto's `Rpo256` (the deployed one), Winterfell's `Rp64_256`.

## Which should I reach for?

| | reach for `poseidon` | reach for `rescue` |
|---|---|---|
| you hash **outside** a circuit, a lot | ✅ one cheap S-box per round | ❌ the inverse S-box layer is measured at **15.0x** the forward one and 76% of the permutation |
| your circuit is **circom / snarkjs / iden3** | ✅ that ecosystem is Poseidon | ❌ nothing there speaks Rescue |
| you must read a **Miden VM** Merkle root, account commitment or note ID | ❌ | ✅ `Rpo256` is exactly that |
| your field is **BN254 / BLS12-381** | ✅ | ❌ this module is Goldilocks-only |
| your field is **Goldilocks** (`2^64 - 2^32 + 1`), i.e. a 64-bit STARK stack | ❌ no published Poseidon params here | ✅ |
| you want the **shortest algebraic description** (7 uniform rounds) | ❌ 8 + 57 rounds of two kinds | ✅ |

Short version: **if you are not talking to something that already speaks
Rescue, use Poseidon.** Rescue's software cost is real and only a prover gets
paid back for it.

## What is implemented

- **Rescue-Prime Optimized (RPO)** — [eprint 2022/1577] — over the Goldilocks
  field `p = 2^64 - 2^32 + 1`, at both instances the specification defines:
  `m = 12` (128-bit security, 4-element digest) and `m = 16` (160-bit,
  5-element).
- **Both sponge framings that exist for it.** They are different hashes over
  the same permutation and they agree on nothing:
  - `spec128` / `spec160` — the reference implementation's own sponge:
    capacity in the low indices, `1 || 0*` padding with a domain-separation flag
    in `state[0]`.
  - `Rpo256` — miden-crypto's: rate in the low indices, zero padding, length
    flag in the capacity. This is what Miden VM digests are made of.
- **Rescue-XLIX** (`xlix`) — the *original* Rescue-Prime round order from
  [eprint 2020/1143], permutation only, so the paper-vs-deployed divergence is
  something you can run rather than something you read.
- The Goldilocks field (`goldilocks`), in-module by design — see `SPEC.md`.

[eprint 2022/1577]: https://eprint.iacr.org/2022/1577
[eprint 2020/1143]: https://eprint.iacr.org/2020/1143

## Use

```zig
const rescue = @import("rescue");

// Miden-compatible — almost certainly the one you want.
const d  = rescue.Rpo256.hashElements(&.{ 1, 2, 3 });   // [4]u64
const b  = rescue.Rpo256.digestToBytes(d);              // [32]u8
const nd = rescue.Rpo256.merge(left, right);            // Merkle node
const bd = rescue.Rpo256.hash("arbitrary bytes");       // separate domain
const dd = rescue.Rpo256.mergeInDomain(left, right, 7);

// The specification's own sponge.
const s4 = try rescue.spec128.hash(&.{ 1, 2, 3 });      // [4]u64, error.EmptyInput on &.{}
const s5 = try rescue.spec160.hash(&.{ 1, 2, 3 });      // [5]u64

// The bare permutation, for building your own construction.
var st: rescue.Rpo256.State = @splat(0);
rescue.Rpo256.permute(&st);

// The paper's round order, for comparison.
var x: rescue.xlix.State = @splat(1);
rescue.xlix.permute(&x);
```

Field elements are plain `u64`s that are always canonical (`< p`). Use
`rescue.fromU64` to bring an arbitrary `u64` into range;
`rescue.goldilocks` has `add`/`sub`/`mul`/`square`/`pow` if you need to do
arithmetic yourself.

**`Rpo256` and `spec128` are not interchangeable.** Same field, same
permutation, same security, different digests for every input. Pick by what you
must interoperate with.

## Verify

```sh
zig build test-rescue                                  # 43 tests, ~1s
zig build test-rescue -Dstrict-debug                   # real Debug
zig build test-rescue --fuzz --release=safe            # 5 fuzz harnesses
```

## Anchoring — grade 1

**57 published known-answer vectors, byte-exact**, from three independent
upstreams. (`SPEC.md` grades every claim individually; the two weakest are
named there and neither is grade 3.)

| vectors | source | pins |
|---|---|---|
| 19 | RPO report, 128-bit instance | permutation + `spec128` |
| 19 | RPO report, 160-bit instance | permutation + `spec160` (`m = 16`) |
| 19 | miden-crypto's own Rust `EXPECTED` | permutation + `Rpo256` |
| 1 | Winterfell's `apply_permutation` KAT | the Rescue-XLIX permutation |

Round constants are **derived**, not embedded: `params.zig` reproduces the
reference implementation's SHAKE256 generator (seed string
`RPO(18446744069414584321,12,4,128)`, nine bytes per constant, little-endian,
reduced mod `p`) and `constants_test.zig` compares all 168 derived values
element-by-element against the tables miden-crypto ships in its source. The
inverse S-box exponent is produced by the extended Euclidean algorithm and
checked three ways, including replaying the 72-multiply addition chain over
exponents.

Every number taken from an upstream file was extracted by script; the command
and the file's SHA-256 are recorded in `src/upstream_vectors.zig`.

### Mutation testing — evidence the tests bite

Five mutations were introduced and reverted (restore verified by a byte-level
`diff -r` against a pre-mutation copy — the module is untracked, so `git diff`
had no baseline). Each leaves a deterministic, perfectly round-tripping hash
that is not RPO:

| # | mutation | caught by |
|---|---|---|
| 1 | **S-box halves swapped** — `x^(1/7)` first, `x^7` second | all 3 vector sets + both `permuteInverse` round-trips |
| 2 | **`x^7` in both halves** — the inverse S-box dropped entirely | all 3 vector sets + both round-trips |
| 3 | **RPO round order replaced by the paper's** (`S-box → MDS → ARK`), *with `permuteInverse` paired-edited to match* | **the published vectors only** |
| 4 | constant stream read as `[all ARK1][all ARK2]` instead of interleaved | the miden ARK pin (named the layer) + the layout test + vectors |
| 5 | circulant MDS index transposed (`j-i` → `i-j`) | MDS-invertibility + round-trips + vectors |

Mutation 3 is the one that matters: with the inverse paired to it, **every
structural property still held** — injective, invertible, deterministic,
framings consistent, 39 of 43 tests green — and only the external vectors
noticed. Mutation 1 is the trap the task literature warns about and it, too,
survived the injectivity fuzzer.

## Cost

Measured on this host at `ReleaseFast`, `m = 12`:

| | µs |
|---|---|
| full permutation (7 rounds) | 18.15 |
| one inverse S-box layer (12 elements) | 1.978 |
| one forward S-box layer (12 elements) | 0.132 |
| one MDS layer | 0.220 |
| `m = 16` permutation | 24.47 |

The inverse S-box is **15.0x** the forward one and **76% of the whole
permutation**. Hashing 64 field elements (512 bytes, 8 permutations) takes
138 µs against `std.crypto.hash.sha2.Sha256`'s 2.27 µs for the same 512
bytes — **61x slower than SHA-256**. That is the expected shape, not a defect:
this hash is priced in constraints, not cycles.

How it got there: the S-box layers are written lane-parallel (advance all `m`
chains one step at a time) rather than element-at-a-time, because a
72-multiply body is far past any compiler's unroll threshold and the naive form
serialises all 12 chains — **48.0 → 27.4 µs**; then the field's carry handling
moved off `@addWithOverflow` tuples (LLVM was spilling them to stack) to
explicit comparison masks — **27.4 → 18.15 µs**. `SPEC.md` has the rest, plus
what was deliberately left on the table.

**Provenance:** no third-party source code is carried into this repo. Upstream
constant tables and test vectors ARE reproduced as data, extracted by script —
`NOTICE` carries the required attribution for the Winterfell- and
miden-crypto-sourced ones (the RPO report's own published vectors need none,
being specification material) and says what each is; the design references
(the RPO authors' sage reference,
miden-crypto, Winterfell) are named in `SPEC.md`.
