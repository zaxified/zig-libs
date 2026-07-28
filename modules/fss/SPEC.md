# fss — design & threat model (SPEC)

Auditor/design reference. Consumer usage lives in `README.md`; metadata lives
in `src/root.zig`'s `pub const meta`; this file does not restate either.

## What this module is

A 2-party single-point **Distributed Point Function** (DPF), the canonical
instance of **Function Secret Sharing** (FSS). A point function
`f_{α,β}(x) = β if x==α else 0` is split into two short keys `(k0,k1)` so that

```
Eval(0, k0, x) + Eval(1, k1, x) == f_{α,β}(x)   for every x    (correctness)
```

in the output group `Z_{2^{8L}}`, while **either key alone is
computationally independent of `(α,β)`** (security/hiding). DPFs are the
primitive under Prio/Poplar private analytics (deployed in Firefox telemetry
and the Apple–Google exposure-notification system), Riposte metadata-private
messaging, and 2-server PIR.

**Construction:** the Boyle–Gilboa–Ishai *optimized tree* DPF — E. Boyle,
N. Gilboa, Y. Ishai, "Function Secret Sharing: Improvements and Extensions",
ACM CCS 2016, Fig. 1. A GGM-style binary tree of `(seed, control-bit)` pairs
with **one seed correction word + two control-bit correction words per level**
and a **single final output correction word**, giving keys of size
`O(λ·n)` rather than `O(2^n)`. This is clean-room-from-spec; per
`CONVENTIONS.md §5` no `NOTICE` entry is required (a public paper/spec is not
a copyrightable work) — the citation lives here.

## Output group choice + justification

The output group is **`Z_{2^{8L}}`** (integers mod `2^{8L}`, i.e. `L`-byte
little-endian, wrapping add), `L = out_bytes` a compile-time parameter
(`Dpf(n, L)`). Justification:

- It is the **standard** DPF output group in the BGI construction: the final
  output correction word is computed once in the group and the two parties'
  leaf shares are combined by group addition, with party 1 contributing the
  additive inverse so off-target shares cancel to `0` and the on-target shares
  sum to `β`. `Z_{2^k}` is the group used by Prio/Poplar (aggregating counts /
  small integers) and by the reference Google `distributed_point_functions`
  library.
- `+%`/`-%` on an exact-width `uN` already reduce mod `2^{8L}` with no
  conditional, so the group arithmetic is branch-free and trivially constant
  in the value (see `group.zig`).
- The **GF(2)^m XOR group** is the other textbook choice; it is the special
  case where `add == sub == XOR`. It is a trivial variant of the same code
  path (a one-line group swap) and is left as a scoped-out increment rather
  than a second output type in Phase 1.

**Domain parameterization:** the input domain is `{0,1}^n` (indices
`0..2^n`), `n = n_bits` a compile-time parameter, `n ∈ 1..31`. Bits are read
**MSB-first** (`i=1` is the top of the tree). `EvalAll` allocates `2^n`
outputs, so it is only practical for small `n`; large-`n` DPFs use single-point
`Eval`, which is `O(n)`.

## The Fable-core vs mechanical split

**Fable-irreducible core (implemented; `gate.core_implemented = true`) —
exactly two functions in `dpf.zig`:**

- `Dpf(n,L).genWithSeeds(α, β, s0, s1) -> [2]Key` — the per-level
  correction-word derivation loop (compute `s_cw`, `t_cw_l`, `t_cw_r` so the
  two parties' seeds stay **equal off the α-path** and **pseudorandomly
  differ on it**) plus the **final output correction word**.
- `Dpf(n,L).eval(b, key, x) -> Elem` — the matching root-to-leaf traversal
  applying each level's CW **gated by the running control bit**, then the
  output word with party 1 negating.

**Why this is the hard part (honest tiering).** This is not novel-algorithm
invention — the pseudocode is published (BGI16 Fig. 1). It is **subtle,
security-sensitive transcription**: the invariant (`off-path-equal /
on-path-differ`), the exact `t_cw` formulas (`t_cw_l = t0_L⊕t1_L⊕α_i⊕1`,
`t_cw_r = t0_R⊕t1_R⊕α_i`), the `(-1)^{t1[n]}` sign on the final word, and the
`(-1)^b` sign in `Eval` are each a place where **one wrong bit** either breaks
reconstruction or — worse — leaks `α` through a key that no naive correctness
test would catch. That combination of care + security-consequence + hard-to-
eyeball-correctness is what places it at the Fable tier, even though it is
"only" transcription. The rest of the module is genuinely mechanical:

**Mechanical scaffold (REAL and tested today):**

- `prg.zig` — the SHA-256 length-doubling PRG `G` and the seed→group
  `convert` (ordinary hashing; the exact byte definitions are pinned in that
  file's doc comment).
- `group.zig` — `Z2k(L)` add/sub/neg + byte codec.
- `dpf.zig` — the `Cw`/`Key` types, `serializeCw`/`toBytes`/`fromBytes`, the
  mechanical `evalAll` loop over `eval`, and the `firstMismatch` full-domain
  checker.
- `kat_test.zig` — the entire harness.

`evalAll` is deliberately the **naive** loop over `eval` (not the efficient
tree-reuse full-domain evaluator): the efficient version shares `eval`'s exact
per-level logic and would enlarge the Fable surface for an `O(2^n)`-vs-
`O(n·2^n)` speedup that Phase 1 does not need. The optimized `evalFull` is a
scoped-out increment.

## External-reference anchoring (anti-self-consistency)

A self-consistent Gen/Eval pair can reconstruct correctly yet implement a
**nonstandard** construction (e.g. different CW derivation), so full-domain
self-consistency is **not** accepted as the sole correctness signal.

- **No byte-exact PUBLIC test vector was adopted.** Published DPF vectors
  (Google `distributed_point_functions`) are tied to that library's specific
  **fixed-key-AES** PRG / hash construction; matching them byte-exact would
  require reproducing that exact PRG (a non-goal for a pure-Zig, stdlib-only
  Phase 1). Like `bulletproofs`' implementation-defined transcript, this
  module's PRG is **module-defined** (documented in `prg.zig`), so its keys
  are interoperable only with this module's own `Eval`.
- **Anchor actually used: an INDEPENDENT re-derivation.** The construction was
  re-implemented from the BGI16 spec in a separate language (Python, stdlib
  `hashlib`) using the **same** SHA-256 PRG + `convert` + serialization this
  module pins. That reference (a) self-checks full-domain reconstruction over
  many `(n,L,α,β)`, then (b) emits fixed-seed KAT vectors recorded verbatim in
  `src/kat_vectors.zig`. The gated KAT test asserts this module's Gen produces
  the **byte-exact** serialized correction words (`cw`) and Eval the
  **byte-exact** outputs (`eval0`/`eval1` full-domain for the small `n=4`
  cases; selected `spot` points for `n=6`/`n=8`). Because the PRG is shared but
  the **construction logic is independently written**, a Gen that reconstructs
  via a different CW derivation cannot reproduce the recorded `cw` bytes — this
  is what defeats "self-consistent but nonstandard". The generator script is
  archived outside the repo (it is a build-time oracle, not shipped code; per
  `CONVENTIONS.md §5` this needs no `NOTICE` entry).

  *During scaffolding this was validated end-to-end:* a throwaway reference
  implementation of the core was dropped in, the gate flipped, and all 18
  tests — including the byte-exact KAT — passed, confirming the scaffold's
  serialization/endianness match the reference before the core was re-gated.
  So the Fable pass has a byte-exact target, not a moving one.

## Verification harness (`CONVENTIONS.md §7` — pure logic, deterministic)

Verification is **deterministic** (fixed seeds ⇒ Gen is a pure function;
full-domain reconstruction is exhaustive), so every assertion is exact.

1. **Full-domain correctness** (core-dependent): for several `(α,β)` at `n=8`,
   Gen then EvalAll on both keys, assert `firstMismatch == null` — i.e.
   `Eval0(x)+Eval1(x) == f_{α,β}(x)` for **all** `2^8` points.
2. **Byte-exact KAT** (core-dependent): the anti-self-consistency anchor above.
3. **Security smell test** (core-dependent, **heuristic — not a proof**): one key's
   EvalAll must not collapse to a constant and must have many distinct values
   (no `α`-spike). Documents that it is a defense-in-depth smell test, not a
   proof of the hiding property.
4. **Positive controls (harness teeth):**
   - *Core-independent:* `brokenAllBeta` (reconstructs `β` everywhere) and
     `brokenAllZero` (reconstructs `0` everywhere) are fed to `firstMismatch`,
     which MUST reject each — proving the checker catches both a
     spurious-nonzero-off-target and a missing-`β`-on-target sharing
     independent of Gen/Eval.
   - *Core-dependent (stronger):* flip one control-bit CW in a real key and confirm the
     **same** `firstMismatch` catches it — proving the CW anchor and the
     reconstruction check are both load-bearing. Deterministic, so it fails
     deterministically.

The Fable pass implemented the two core functions to reproduce
`kat_vectors.zig` byte-exact and flipped `gate.core_implemented` to `true`, so
every formerly-gated test now runs as an executed assertion (all pass, no
skips, Debug + ReleaseFast). While the flag was `false`, those tests reported **SKIP**
(`error.SkipZigTest`) — a skip was never a pass.

## Scoped out (future increments, NOT Phase 1)

- **DCF / comparison functions** — `f_{α,β}^<(x) = β if x < α else 0`
  (Boyle–Chandran–Gilboa–Jain–Kohl–Scholl et al.); a `dcf.zig` sibling reusing
  this PRG/group. The `Dpf`-now / room-for-`dcf`-later layout is why the module
  is named `fss` rather than `dpf`.
- **General FSS** (multi-point, interval, decision-tree functions).
- **2-server PIR** built on `EvalAll` (a query = a DPF key per server).
- **Fixed-key-AES PRG** — the performance-standard, ~10× faster than SHA-256;
  would additionally enable byte-exact interop with Google's DPF vectors.
- **Efficient tree-reuse `evalFull`** — `O(2^n)` full-domain instead of the
  naive `O(n·2^n)` loop.
- **Constant-time review** of `Eval`'s control-bit-gated branches (side-channel
  hardening) — the branch on the running control bit is data-dependent.
