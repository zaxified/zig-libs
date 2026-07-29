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
**MSB-first** (`i=1` is the top of the tree). `EvalAll` fills `2^n` outputs,
so it is only practical for small `n`; large-`n` DPFs use single-point `Eval`
(`O(n)`) or the tree-reuse `evalFull`/`evalFullWith` over a domain **prefix**
(§"Tree-reuse prefix evaluation" below), which costs `O(out.len)` regardless
of `2^n`.

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
  mechanical `evalAll` loop over `eval`, the tree-reuse `evalFull`/
  `evalFullWith` prefix evaluator (§ below), and the `firstMismatch`
  full-domain checker.
- `kat_test.zig` — the entire harness.

`evalAll` is deliberately the **naive** loop over `eval`, and stays that way
now that the tree-reuse evaluator exists: the naive loop is structurally
independent of the tree walk, which makes it the differential oracle
`evalFull` is tested against element-for-element. The tree-reuse evaluator
itself is mechanical scaffold, not new Fable surface — it re-applies `eval`'s
already-anchored per-level formulas over the shared tree, and every value it
produces is required to be bit-identical to `eval`'s.

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

## Multi-point FSS (`mpf.zig`)

Shares of `f_{A,B}(x) = Σ_j β_j·1{x==α_j}` — non-zero at `k` chosen points.
This was on the scoped-out list below as part of "General FSS"; it is now
built, and the scoped-out entry has been narrowed to what remains.

### Construction chosen, and the trade-off accepted

**`k` independent DPF instances, summed.** `Mpf(n,L,k).Key` is `[k]Dpf.Key`
laid end to end; `Gen` is `k` calls to `Dpf.genWithSeeds` on `k` independent
seed pairs; `eval` adds the `k` sub-evaluations in `Z_{2^{8L}}`. Correctness is
distributivity, and there is no failure case.

The literature's better constructions — batch codes and cuckoo-hashing
multi-point FSS, as used under modern batch-PIR and PSI — partition the domain
into ~`1.5k` buckets holding one point each, so the server evaluates each
bucket over a `1/1.5k` slice of the domain: `O(N)` server work in one pass
instead of `O(k·N)`, with keys over shorter trees. That is a real asymptotic
win. It is not what this module does, and the reasoning is:

| | sum-of-`k`-DPFs (chosen) | cuckoo / batch-code |
|---|---|---|
| key size | `k·O(λ·n)` — linear in `k` | `~1.5k·O(λ·(n−log k))` — mildly sublinear |
| server work | `k` evaluations per record | ~1 evaluation per record |
| failure probability | **none** | placement failure — a parameter to calibrate and a claim to believe |
| new cryptographic surface | **none** — `k` uses of the anchored primitive | bucketing, stash policy, hash choice |
| external anchor | **inherited** — each sub-key is an anchored `dpf` key | would have to be established from scratch |

For a library whose only consumer (`pir`) has no throughput requirement, the
last three rows decide it: a construction with no failure probability and no
assumption beyond "`dpf` is a DPF" can be audited by reading it, and it
inherits `dpf`'s byte-exact external anchor for free. A sophisticated
construction nobody can check is worth less here than a correct one everybody
can.

**What would justify revisiting.** One thing, measured rather than assumed: a
consumer for which `k` passes over the data dominate. Server cost is `k·N`
evaluations of `n` SHA-256 calls; at `k=100, N=2^20` that is ~2·10⁹ hashes per
query, and the bucketed construction earns its failure probability. Note the
cheaper fix came first — the tree-reuse `evalFull` (now built, §"Tree-reuse
prefix evaluation") cuts each pass from `O(N·n)` to `O(N)` hashes with **no**
new cryptography — so the cuckoo revisit bar is now `k` itself, not the
per-pass constant.

### Seed independence is a security requirement, and is enforced

The `2k` seeds must be mutually independent, and the consequence of ignoring
that is specific rather than generic: `Gen`'s state at level `i` is a function
of the seeds and of `α`'s bits `1..i-1`, so **under a reused seed pair, two
indices sharing a `p`-bit prefix produce byte-identical correction words for
exactly those `p` levels**. A server holding one key reads the pairwise
common-prefix length of the client's points straight out of the bytes.
`genWithSeeds` therefore rejects byte-identical seeds (`error.SeedReuse`).

That guard is honest about its scope: it catches the *plumbing* bug (a caller
looping wrong, or passing one pair `k` times). Distinct-but-correlated seeds
pass it and remain the caller's bug — no library can test its caller's
randomness. `mpf_test.zig` measures the leak mechanically (asserting the number
of matching correction-word levels is *exactly* the common-prefix length, so it
is a statement about the mechanism rather than a threshold) and asserts that
with independent seeds not even one level's seed CW matches, for indices with a
long common prefix and for outright equal indices.

### Anchoring — the `dpf` harness extends, by composition

An `Mpf` key is a concatenation of `dpf` keys, and `dpf`'s keys are pinned
byte-exact by `kat_vectors.zig` (the independent Python re-derivation). So
`v0` and `v3` — both `n=4, L=4` — are composed into one `Mpf(4,4,2)` key, and
the test asserts the serialized bytes reproduce **both recorded vectors at the
layout's offsets**, plus both recorded full-domain evaluations per instance.
This is a genuine EXTERNAL anchor for Gen and for the encoding: the bytes came
from outside this repo, and a reordered instance, a stray header, a shared seed
or a wrong offset would all break it.

What is **not** externally anchored, stated rather than blurred: the *summed*
evaluation. No published vector exists for "sum of `k` BGI DPFs" under this
module's PRG, so the sum is checked only as a re-derivation (against the
plaintext multi-point function, and against the sum of the anchored
components). No vector computed by this implementation is presented as an
anchor anywhere.

### The encoding is not injective (finding)

Found by fuzzing under `--release=safe`, and it applies to `dpf`'s existing
codec, not only to `mpf`'s: `serializeCw` writes each control-bit correction
word as a **whole byte** valued 0/1, while `fromBytes` **truncates that byte to
its low bit**. The other seven bits are ignored, so two distinct byte strings
decode to the same key and `toBytes(fromBytes(b)) != b` in general.

Consequences, none of which is a vulnerability here:

- The encoding is *canonical on output* and *tolerant on input*. Re-encoding
  normalizes, and decoding the normalized form is a fixed point — that is the
  property the fuzz harness asserts (asserting the round-trip was the identity
  is what surfaced this).
- Nothing in `fss` or `pir` signs, MACs, hashes or deduplicates a serialized
  key, so malleability has no protocol consequence today.
- A consumer that *does* any of those things must canonicalize first
  (`fromBytes` then `toBytes`) or it will treat equivalent keys as distinct.

## Tree-reuse prefix evaluation (`evalFull` / `evalFullWith`)

This was on the scoped-out list below ("Efficient tree-reuse `evalFull` —
`O(2^n)` full-domain instead of the naive `O(n·2^n)` loop"); it is now built,
and the entry has been removed.

### What was built, and why it lives here and not in `pir`

`eval` expands each on-path node's PRG and **throws away the sibling half** of
every expansion; a full-domain evaluation as `2^n` independent `eval` calls
therefore recomputes every shared ancestor, `O(n·2^n)` PRG calls total.
`evalFull` walks the tree **once**, keeping both children at every internal
node, so each node is expanded exactly once: ~`N` PRG calls for `N` outputs.
The per-level formulas are `eval`'s own (the seed-CW XOR gated by the parent's
control bit, the child control bits from `t_cw_l`/`t_cw_r`, the leaf's
`convert` + `t`-gated `cw_final` + `(-1)^b`) — this is a *traversal-order*
optimization of the anchored construction, not a new construction, which is
why it belongs in this module next to `eval` rather than in any consumer:
it needs `eval`'s internals, and every DPF consumer (`pir`'s value channel,
`pir.Verified`'s tag channel, any future one) gets it from one place.

### The prefix contract is the design point

`evalFull(b, key, out)` evaluates the domain **prefix** `[0, out.len)`,
`out.len ≤ 2^n` — it does NOT require or default to the whole domain. This is
load-bearing for `pir`, whose SPEC documents domain truncation as a feature:
`domain_bits` is picked generously above the record count and **the unused
tail of the domain is never evaluated**. A full-domain-only evaluator would
either break that invariant or regress a small database in a big domain to
`O(2^n)` — the opposite of the intended speedup. The walk prunes any subtree
lying entirely at/past `out.len` *before* its PRG call, so the cost is
`O(out.len)` PRG calls plus at most `n` extra expansions for nodes straddling
the prefix boundary, independent of `2^n`. (Recursion depth is bounded by
`n ≤ 31` with a small frame; no allocation, no explicit stack needed.)

`evalFullWith(b, key, count, ctx, emit)` is the same walk in streaming form:
it calls `emit(ctx, x, value)` once per `x ∈ [0, count)`, in ascending order,
materializing nothing. It exists because `pir` is a no-allocator module whose
record count is a runtime value: the server folds each evaluation into its
answer as the walk produces it, so no `count`-sized buffer exists anywhere.

### Verification and measured effect

Equivalence is exact and asserted, not argued: `kat_test.zig` requires
`evalFull` to reproduce the `eval`/`evalAll` path **bit-for-bit,
element-for-element** — full domains at `n=4` and `n=10`, a 300-point prefix
of an `n=16` domain (α inside, at the prefix's last point, just past it, and
at the far end of the domain), prefix lengths 0/1/257 (a full subtree plus a
straddling leaf), for both parties — with `evalAll`'s naive loop as the
structurally independent oracle, plus a streaming-form test asserting each
index is emitted exactly once, in order. Mutation-tested: mis-gating one
child's seed-CW application (parent's `t` → child's `t`) is caught by three of
these tests; shortening the prefix by one at the consumer is caught by `pir`'s
every-record-influences-the-answer test.

Measured (`FSS_BENCH=1 zig build test-fss -Doptimize=ReleaseFast`, this
host): `n=16` full domain 570 ms → 52 ms (**~11×**, theory `(2n+1)/3 ≈ 11`);
500-point prefix of an `n=20` domain 5.1 ms → 0.36 ms (**~13–15×**), with
`evalFull`'s per-point cost flat (~0.7–0.8 µs) across both — i.e. it follows
the prefix length, not the domain size.

## Scoped out (future increments, NOT Phase 1)

- **DCF / comparison functions** — `f_{α,β}^<(x) = β if x < α else 0`
  (Boyle–Chandran–Gilboa–Jain–Kohl–Scholl et al.); a `dcf.zig` sibling reusing
  this PRG/group. The `Dpf`-now / room-for-`dcf`-later layout is why the module
  is named `fss` rather than `dpf`.
- **General FSS** — interval and decision-tree functions. (Multi-point was on
  this list and is now `mpf.zig`, above.)
- **Sublinear multi-point FSS** — the cuckoo/batch-code construction, with the
  revisit trigger stated above.
- **2-server PIR** built on `EvalAll` — now its own module, `pir`.
- **Fixed-key-AES PRG** — the performance-standard, ~10× faster than SHA-256;
  would additionally enable byte-exact interop with Google's DPF vectors.
  (Tree-reuse `evalFull` was on this list and is now built —
  §"Tree-reuse prefix evaluation" above.)
- **Constant-time review** of `Eval`'s control-bit-gated branches (side-channel
  hardening) — the branch on the running control bit is data-dependent.
