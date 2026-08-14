# pir — design & threat model (SPEC)

Auditor/design reference. Consumer usage lives in `README.md`; metadata lives
in `src/root.zig`'s `pub const meta`; this file does not restate either.

## Why this is a module and not an addition to `fss`

`fss`'s own SPEC lists "2-server PIR built on `EvalAll`" under *Scoped out
(future increments)*, alongside DCF, general FSS, a fixed-key-AES PRG and an
efficient `evalFull`. Every other item on that list is a **primitive** — a
different function family, a faster PRG, a faster evaluator — and belongs
inside a module whose stated shape is "FSS primitives, named `fss` rather than
`dpf` so `dcf.zig` can move in next door". PIR is the odd one out: it is an
**application protocol** over the primitive, with its own wire format, its own
threat model (non-collusion), and its own failure modes (mismatched replicas,
unverifiable answers) that have nothing to do with function secret sharing.

The repo's own precedent is unambiguous and points the same way: `bbs` is a
module over `bls12_381`, not a file inside it; likewise `opaque` over `voprf`,
`tlock` over `bls12_381`, `adaptor` over `bip340`, `bumtree` over `spf-ect`.
In every case a protocol built *on* a primitive got its own module, its own
catalog row and its own SPEC. Folding PIR into `fss` would also have widened
that module's `meta.role` from `.util` to something it is not, and put a
non-collusion threat model into a SPEC whose threat model is a hiding property.

`fss`'s README-catalog row and SPEC both said PIR was future work "out of
Phase 1". The catalog row has been updated to point here; `fss/SPEC.md`'s
scoped-out list is left as the historical record of that module's Phase-1
boundary.

## The composition, and the correction to the textbook description

The one-paragraph account of DPF-based PIR that appears in most papers'
introductions is:

> the client sends each server a DPF key for the point function that is 1 at
> `i`; each server XORs the records its share selects; the client XORs the two
> answers.

**That description does not apply to `fss`'s DPF**, and building to it would
have produced a module that does not work. `fss`'s output group is
`Z_{2^{8L}}` (`fss/SPEC.md` §"Output group choice"), chosen deliberately over
the `GF(2)^m` XOR group. Consequences:

- `Eval(b, k_b, x)` returns a full `L`-byte pseudorandom group element, **not
  a selection bit**. There is no "the records this share selects": off-target
  shares are random values that cancel *in pairs across the two servers*, and
  a single server's share vector has no zeros in it at all.
- Combining is group addition with party 1 contributing the additive inverse
  (`fss/group.zig`), so the client **adds**; XOR would reconstruct nothing.

The correct composition over this DPF is the **inner product in the ring
`Z_{2^{8L}}`**. A record is cut into `L`-byte little-endian words, and

```
answer_b[j] = Σ_{x<N} Eval(b, k_b, x) ·  word_j(record[x])          (mod 2^{8L})

answer_0[j] + answer_1[j]
  = Σ_x (Eval(0,k0,x) + Eval(1,k1,x)) · word_j(record[x])       distributivity
  = Σ_x f_{i,1}(x) · word_j(record[x])                          DPF correctness
  = word_j(record[i])
```

Three things follow that are worth stating because they are easy to get wrong:

1. **Packing record bytes into a word is free, not a hazard.** Carries between
   packed bytes do not corrupt anything: the identity above is exact ring
   arithmetic over whole words, never per-byte arithmetic. So `word_bytes`
   is a pure performance dial — `L`-fold fewer multiplications, same answer
   size up to rounding a record to a whole word.
2. **β must be 1.** The DPF's value parameter scales the retrieved record in
   the ring. Any β other than 1 retrieves `β·record[i]`, which is not
   retrieval. `query` hard-codes it.
3. **The block ("multi-bit") case is the only case, and it came free.**
   Retrieving a `record_len`-byte block costs one DPF evaluation per database
   record *regardless of `record_len`* — the DPF work is amortized over the
   whole record. Classic single-*bit* PIR is the degenerate `record_len == 1`.
   Nothing had to be built for the multi-bit extension, so it is included.

**Truncating the domain is safe.** `2^domain_bits` is almost never equal to
the record count. The server evaluates only `x < N`; since `f_{i,1}(x) = 0`
outside `x = i`, dropping the tail of the domain changes nothing, and querying
a valid-but-unpopulated index reconstructs to all-zero rather than erroring.

**Server cost: ~1 PRG call per record, via `fss`'s tree-reuse `evalFull`.**
The server's inner product is driven by `fss.Dpf.evalFullWith` — one walk of
the DPF tree over the `[0, N)` prefix, streaming each evaluation into the
accumulator — instead of one `O(domain_bits)` root-to-leaf `eval` per record.
Measured ~11× at `domain_bits=16` (see `fss/SPEC.md` §"Tree-reuse prefix
evaluation"). Two properties were load-bearing in the wiring and are pinned by
tests: the walk still **never evaluates the domain's unused tail** (subtrees
past `N` are pruned before their PRG calls — the truncation invariant above,
kept), and it emits every `x < N` exactly once in order with no data-dependent
skip (the access-pattern requirement, still covered by the
every-record-influences-the-answer test). The streaming form is used because
this module has no allocator and no runtime-sized scratch (§"Where the library
stops"): no `N`-sized buffer exists anywhere. The `Verified` layer's tag
channel — another instantiation of the same generic `Dpf` — is wired the same
way.

## Multi-index retrieval, and the correction it required

`Pir(...).Multi(k)` retrieves `k` records per round trip over `fss`'s
multi-point FSS (`fss.Mpf`). The obvious shape — "one multi-point key, one
inner product, one answer" — **does not retrieve `k` records**, and building to
it would have produced a module that returns something else entirely. Composing
a `k`-point function with this module's inner product gives

```
Σ_x f_{A,1}(x) · word_j(record[x])  =  Σ_l word_j(record[α_l])
```

— the **sum** of the `k` records, from which the individual records are
unrecoverable. That is a useful query in its own right (its download is one
record regardless of `k`), and it is exposed as `answerAggregate`, but it is an
aggregate, not retrieval.

Retrieval keeps the `k` instances apart: the server evaluates the components
(`Mpf.evalEachFullWith` — the interleaved walk, see below) and accumulates `k`
separate inner products, so an answer is `k` record-sized blocks and
reconstruction yields all `k` records. There is
no way around the download cost — `k` records of information cannot arrive in
one record of bytes — so "one answer per server" means one *message*, `k`
blocks wide. A test asserts the aggregate's non-invertibility directly: two
different index tuples with the same multiset produce the same aggregate.

### What carried over from the single-index case

Re-checked against `k` points rather than assumed:

1. **The output group is still `Z_{2^{8L}}`, not XOR**, and each component is
   still a full pseudorandom group element rather than a selection bit. Each
   block is the same ring inner product; nothing about the group changed.
2. **β must still be 1**, now `k` times — `query` hard-codes `1` for every
   point. A `β_j ≠ 1` scales block `j`'s record by `β_j`.
3. **Record-length independence still comes free**, for the same reason as
   before: the work is `k` evaluations per *record*, whatever the record's
   length. What is *not* free any more is the factor `k` itself — that is the
   cost of the chosen multi-point construction (`fss/SPEC.md`).
4. **Repeated indices behave differently in the two shapes**, and this is the
   one place the semantics visibly diverge. In retrieval the instances never
   meet, so `.{7, 7}` returns record 7 in both blocks. In the summed function
   those same points add, so the aggregate gives `2·record[7]`. That divergence
   is exactly why retrieval uses the components and not the sum.

The server makes **one pass** over the database, and since the interleaved
evaluator landed it makes it in the evaluator too: `Mpf.evalEachFullWith`
(`fss/SPEC.md` §"Interleaved multi-tree prefix evaluation") descends all `k`
trees together over the `[0, count())` prefix and hands the server every
instance's share at each record as it arrives, so each record's bytes are
decomposed once and each record costs `~k` PRG calls instead of `k·domain_bits`
(~9.5–14× measured). The DPF evaluations are still `k·N` — that factor is the
multi-point construction, not the traversal, and no evaluation strategy
removes it.

Two properties survive the change unaltered, and both are tested rather than
argued: the answer is **word-for-word identical** to the per-point loop it
replaced (which `pir.zig` keeps as a test-only oracle), and the record access
order is still `0, 1, …, count()-1` for every share, because the walk prunes
the domain's unused tail on the index range alone. `privacy_test.zig` pins the
second — and it is not redundant with the correctness tests: a traversal
reorder that is internally consistent leaves every functional test green,
since the answer accumulation is commutative.

## Multi-index privacy — does `k`, or the index relationship, leak?

Two questions the single-index battery does not answer, and they are not
answered by running the old tests `k` times.

**1. Does the share reveal `k`? Yes — and that is the whole leak of `k`.** A
multi-index share is exactly `k` single-index shares long, and a retrieval
answer is exactly `k` blocks wide, so both lengths reveal `k` to any observer.
This is stated as an assertion in `privacy_test.zig` rather than left implicit,
because it is acceptable only under a condition that must hold operationally:
`k` is **public protocol geometry** — a compile-time parameter, identical for
every client and both servers — not a per-query secret. A deployment must not
treat it as one.

What the length does *not* reveal is **how many records the client actually
wanted**. A client needing fewer than `k` pads with dummy indices; every index
is hidden by its own instance, so any padding value works and the padded share
is the same length and shape as a full one. That is the supported way to hide
the effective count, and it is tested.

The aggregate answer is the one shape whose size hides `k`: one record-sized
block whatever `k` is.

**2. Does the *relationship* between the indices leak? Not with independent
seeds — and it would without them.** This is the sharpest question the
multi-point case adds, and the answer has two halves that must be read
together:

- *Structurally, no.* Each instance is generated from its own independent seed
  pair, so instance `j`'s key is a function of instance `j`'s seeds alone and
  the bundle's joint distribution factorises. Nothing about how the indices
  relate survives into the bytes. EXACT tests assert that no correction word is
  shared between instances — not even one level's seed CW — for the three
  relationships that would break it if anything were shared: a 6-bit common
  prefix, adjacency, and **outright equal indices**.
- *And that is bought entirely by seed independence, not by the construction.*
  Under a reused seed pair, two indices sharing a `p`-bit prefix produce
  byte-identical correction words for exactly those `p` levels, and a server
  reads the common-prefix length straight out of the share.
  `fss/mpf_test.zig` demonstrates that leak mechanically; `query` refuses to
  produce it (`error.SeedReuse`). The guard catches the plumbing bug —
  distinct-but-correlated seeds pass it, which a test also pins.

**STAT, extended to relationships.** The two-sample bit-frequency statistic is
reused verbatim (same `m`, same `reject_gap`, same calibration) but the *pairs*
are chosen so that a leak of the **relationship** rather than of an index is
what it is built to see:

- identical indices `(5,5)` vs distinct `(5,200)` — the sharpest relationship
  difference there is, and the one a seed-sharing construction fails;
- adjacent `(0,1)` vs far apart `(0,255)`, holding the first index fixed so the
  first instance is distributionally identical and only the relationship
  differs;
- the *same* relationship at two places in the tree, `(0,1)` vs `(200,201)`.

Its **negative controls are relationship leaks too** — one bit carrying "the
two indices are equal", and one carrying "the two indices share a top bit" —
and both must be rejected by the identical code path and threshold. Without
those the pairs above would prove nothing about the statistic's sensitivity to
this specific class.

**What it still does not establish** is unchanged from the single-index case
and is not weakened here: nothing about computational indistinguishability, and
nothing below the detection floor. It is a marginal, per-bit, first-order
check. A relationship leak spread across bits, or visible only in a joint
distribution, is invisible to it.

**The per-instance claims carry over unchanged.** The level-1 control-bit CW
parity is exactly index-independent (α cancels in BGI's formulas) *per
instance*; the level-1 seed CW *does* depend on the top index bit *per
instance*, taking exactly two values with the seeds held fixed. So privacy
remains **computational** and rests on the PRG — with `k` points as with one.
A census test also asserts that the multi-index share's structurally-constant
bits are exactly the single-index census **tiled with period `share_len`**,
which is what pins that the concatenation introduced no header, separator,
padding or per-instance counter of its own.

## Keyword lookup (`keywordIndex` / `queryKeyword`)

Was scoped out ("Index lookup only; keyword PIR needs a hashing/cuckoo layer
above this"); now built, as the thinnest possible layer: a **public, total,
deterministic hash-to-index map** composed in front of the unchanged index
protocol.

### The construction chosen

`keywordIndex(kw) = LE64(SHA-256(kw)[0..8]) & (2^domain_bits − 1)` — the
domain is a power of two, so the truncation is exact (no modulo bias) — and
`queryKeyword(kw, s0, s1) = query(keywordIndex(kw), s0, s1)`, nothing else.
The database-builder's side of the convention: the record for `kw` is placed
at `keywordIndex(kw)`, and records carry their own key field so a client can
check the match locally (a documented layout convention, not something this
module enforces — the same "Database is a borrowed view" stance as `db.zig`).
The `Verified` layer gets the same one-line wrapper over its own `query`.

### The exact leakage statement

- **A query for a missing keyword is byte- and shape-identical to a query for
  a present one** — *provided the caller never skips a query and never
  retries*. The map is total (every byte string lands on some index),
  deterministic, and unconditional: `queryKeyword` has no database access, no
  existence check, no retry, no probing, and no branch on anything but the
  keyword bytes it hashes. Presence simply does not enter the computation, so
  it cannot leave it. The condition is a real caller obligation, stated in the
  API docs: one lookup, one query, whatever comes back — a client that
  consults a local set/Bloom filter and skips, or re-queries on a local
  mismatch, re-creates the presence leak in its own traffic (a test
  demonstrates the call-count difference of exactly that wrapper).
- **Nothing about the keyword or its hash reaches a server** except through
  the DPF shares: the derived index goes down the exact same `query` path as
  any other index, and the DPF's hiding property covers it. `keywordIndex`
  itself has no secret-dependent branches (SHA-256 and an AND mask are
  data-independent operations), and even that is defense in depth — it runs on
  the client, and its output is then DPF-hidden.
- **Collisions are a correctness cost, never a privacy cost.** Two keywords
  may map to one index; the builder placed one record there, and that record
  is what comes back for both — the losing keyword's record is unreachable (a
  **false negative**), discovered only locally after reconstruction. There is
  no resolution, no rehash, no second slot — deliberately, because every
  resolution strategy is a data-dependent extra query. An executable test
  constructs a real collision and runs the false negative. The caller's
  provisioning obligation, exactly: for `N` keywords,
  `P(any collision) ≈ N²/2^(domain_bits+1)`; keep it below `ε` by choosing
  `domain_bits ≥ 2·log2(N) + log2(1/ε) − 1` (e.g. `N = 1000`,
  `domain_bits = 30` gives `P < 5·10⁻⁴`). Note this couples `domain_bits` to
  the *keyword universe*, not the record count — keyword deployments size the
  domain generously, which is exactly the case `evalFull`'s prefix pruning
  keeps cheap.
- **Repeated-query privacy is unchanged**, because `queryKeyword` reduces to
  `query` with fresh caller seeds: two lookups' shares are two independent DPF
  instances, exactly as two index queries' are. The hash adds no correlation
  between shares beyond the indices themselves (it is a public deterministic
  map — the same statement as "the client queried index 5 twice", which the
  base protocol already covers: with fresh seeds, repeats are computationally
  invisible). Querying the *same* keyword twice is querying the same index
  twice — already the base protocol's story, no weaker here.

### Against the alternatives

- **A published key→index mapping** (resolved locally, so the wire sees plain
  index PIR) removes collisions — the publisher can assign injectively — but
  is leak-free only under the *same* "always query, pad the misses" caller
  discipline this design needs, **plus** an out-of-band publishing and
  freshness pipeline: the mapping must reach every client and track every
  database change, an ongoing service with its own consistency and version
  side channels. A no-I/O module cannot provide, or even meaningfully specify,
  that pipeline (§"Where the library stops"); a deployment that has one can
  simply use index PIR directly — nothing here blocks it.
- **Cuckoo hashing / batch codes** were already consciously rejected for
  `fss`'s multi-point construction, with a stated revisit trigger (`fss`
  SPEC). Nothing about keyword lookup distinguishes it from that rejection —
  the mechanism would buy multi-slot placement (each key gets 2–3 candidate
  slots, resolving collisions by displacement) at the price of the failure
  probability, the stash policy, and — decisive here — **per-lookup
  multi-slot queries whose shape the whole design exists to keep constant**.
  Querying all candidate slots unconditionally (the leak-free way to do
  cuckoo lookup) is `Multi(k)` composed with `keywordIndex` variants, which a
  deployment can build above this layer if collision-freedom is worth k× the
  work; it is not this module's default.

## Threat model

**The assumption.** Exactly one: the two servers do not pool their shares.
Everything else follows.

**What one server sees.** One DPF key, one database it already has, and one
answer it computed itself. The key hides `i` under the DPF's hiding property.

**What two colluding servers see.** `i`, immediately. The two shares differ
*only* in the 16-byte root seed — the correction words are byte-identical —
and evaluating both at every index gives a vector that is zero everywhere
except at `i`. This is a full-domain scan and nothing more. `privacy_test.zig`
executes this attack as a passing test rather than describing it, because a
threat model in prose is a threat model people skip.

**Other real failure modes, none of which the BASE protocol can detect** (the
`Verified` layer detects the first two — see §"Malicious-server detection"):

- *Replica divergence.* Both servers must hold byte-identical databases in the
  same order. Off-target terms cancel term-by-term across the two servers; a
  record that differs between them, or a differing record count, leaves an
  uncancelled term and silently corrupts the answer.
- *Malicious answers.* The base protocol has no verification step. A server
  can return anything; the client reconstructs garbage without noticing.
  `Verified` turns that into an abort — detection, never recovery.
- *Seed reuse.* `query`'s two seeds are the protocol's only randomness and the
  DPF is deterministic given them. Reusing a seed pair across queries for
  different indices hands a server two shares related by a known structure.
  Fresh CSPRNG seeds per query, always.
- *Sending both shares to one server.* Self-evidently fatal; stated because
  `query` returns them as one array and an off-by-one in the caller's plumbing
  is all it takes.
- *Traffic analysis above this layer.* Query timing, frequency and correlation
  with observable events are outside a library with no I/O.

## Malicious-server detection (`verify.zig`)

The base protocol's security model is honest-but-curious: a server learns
nothing about `i`, but is trusted to answer honestly. `Verified(domain_bits,
word_bytes, tag_slack_bytes)` removes the honesty assumption for **integrity**:
a client detects a lying server and aborts. It deliberately does **not**
attempt more than that, and this section is exact about the boundary.

### The construction chosen

**A client-side secret-scalar MAC carried through the protocol's own
linearity, checked in a widened ring.** Alongside the unchanged value channel
(a DPF for `f_{i,1}` in `Z_{2^{8L}}`), the client runs an independent **tag
channel**: a DPF for `f_{i,m}` — the DPF's value parameter β set to a secret
ring element `m` only the client knows — evaluated in the widened ring
`Z_{2^{8(L+S)}}`, `S = tag_slack_bytes`. The server's tag inner product runs
over the *same* `L`-byte record words as the value channel, zero-extended,
plus one extra **presence word** whose coefficient is 1 for every record.
Honest reconstruction therefore yields `t_j = m·w_j` for every value word and
`t_presence = m`, and the client checks exactly that.

Everything a deviating server can do — flip bits, replay an old answer,
answer over a privately modified database, return zeros, return arbitrary
bytes — lands as an additive error `(e_v, e_t)` on the reconstruction,
because the transcript is linear and the honest answers are determined by
(key, database). The whole argument is then two steps:

1. *The error is independent of `m`.* A server's view is its two keys and the
   database; the tag key hides β = m exactly as it hides α (the DPF's hiding
   property covers the pair). So `(e_v, e_t)` is chosen by something that —
   computationally — knows nothing about `m`.
2. *Passing the check requires knowing `m`.* Accepting requires
   `e_t ≡ m·(e_v − δ·2^{8L}) (mod 2^{8(L+S)})` per word, where `δ ∈ {0,1}` is
   the carry of the value word's wrap. For `e_v ≠ 0` the right-hand side is
   `m` times a nonzero integer of 2-adic valuation ≤ `8L−1`, so over a uniform
   odd `m` the adversary's chosen `e_t` matches with probability at most
   `2^{−8S}` per carry guess, `2^{1−8S}` hedging both. An `e_t`-only error
   (`e_v = 0`) is caught deterministically.

**Soundness error: ≤ `2^{1−8S}` + Adv_PRG**, a function of `tag_slack_bytes`
and of nothing else — not of `N`, not of the record length, not of the queried
index. `S = 8` (the recommended default) gives `2^{−63}` plus the PRG term.
`m` is forced odd (one entropy bit spent to remove the even weak class and
make the presence check exact; the bound above already assumes odd `m`) and
must be fresh per query — against a reused `m`, each *rejected* forgery
attempt eliminates candidate values, degrading soundness linearly in the
number of attempts.

**Why the ring is widened.** With `S = 0` the check is not weak but broken:
`m·2^{8L−1} = 2^{8L−1}` for every odd `m` (zero divisors of `Z_{2^k}` — the
standard MAC-over-`Z_{2^k}` failure), so flipping the value's top bit and
adding `2^{8L−1}` to the tag forges with probability 1 and no knowledge of
`m`. Widening is the standard fix (cf. the SPDZ2k MAC): the compensating tag
error becomes `m·2^{8L−1} mod 2^{8(L+S)}`, a function of `8S+1` secret bits of
`m`. `S = 0` is a compile error; the attack is a test, in both forms — it
demonstrably succeeds in the un-widened arithmetic and demonstrably fails
against the widened check.

**Why the presence word exists.** `t = m·v` is satisfied by the all-zero
transcript, and *two malicious servers that each independently zero their own
answers* — no collusion needed — would otherwise make the client accept an
all-zero record. The presence word pins `t_presence = m ≠ 0`, which no
transcript built without `m` can supply. Consequence, chosen deliberately: a
query for an index inside the domain but past the database — an all-zero
reconstruction in the base layer — **rejects** in the verified layer, because
an honest all-zero is indistinguishable from the zeroing forgery. The
verified layer requires `index < db.count()`.

### The exact security statement

- **Detection, not robustness.** On a lie the client gets
  `error.AnswerRejected` — it does not recover the record, and it cannot tell
  *which* server lied (only the sum of the two answers is checkable). With two
  servers and one of them malicious, detect-but-not-recover is the honest
  ceiling for this construction; Byzantine-robust PIR needs more servers.
- **One malicious server:** any deviation that would change the reconstructed
  record is detected except with probability ≤ `2^{1−8S}` + Adv_PRG.
  Deviations that would *not* change the record (tag-only tampering) also
  abort — detection is conservative.
- **Both servers malicious, not colluding:** still detected, same bound —
  their errors add, and the sum is still independent of `m`.
- **Both servers colluding:** no integrity, and no privacy — they pool the tag
  keys, run the same full-domain scan that recovers `i`, read off `m`, and
  forge `e_t = m·(e_v − δ·2^{8L})` exactly (they know `record[i]`, hence the
  carry). Collusion was already total loss in the base protocol; the verified
  layer does not move that boundary, and a test performs the forgery so the
  limitation is executable rather than a footnote.
- **Both servers honestly serving the same wrong database: NOT detected.** The
  MAC binds the answer to the database the two servers *jointly* used, not to
  any database the client expects. A test asserts the acceptance. Binding to
  a published database is authenticated PIR — see below.
- **Privacy holds AT THE RECOMMENDED `S = tag_slack_bytes = 8`, and the
  single-word abort-bit argument below is what the module's own guard test
  exercises there — but the "no selective-failure index test" conclusion does
  NOT extend uniformly down to the permitted floor `S = 1`.** ⚠ **Corrected
  from an earlier draft of this section**, which stated the no-selective-
  failure claim without this scoping. `tag_slack_bytes` is therefore not
  purely an *integrity* knob — it is also a *privacy* parameter, and the
  accept/reject bit's independence from `i` degrades as `S` shrinks, not just
  the soundness bound's magnitude.
  - **Single-word tampering, any `S`.** The tag key is one more DPF key under
    the same hiding assumption; lengths are geometry-only (asserted,
    including across `m` values); and for a tampering confined to ONE value
    word, the abort bit shifts by at most the soundness error across indices
    — a fixed `m`-independent single-word tampering rejects for *every*
    index (this is what the module's guard test at the recommended `S = 8`
    demonstrates). The carve-out, stated exactly: an adversary can make the
    *carry* `δ` of the attacked word depend on `record[i]`, but acceptance
    still requires separately hitting `m` (probability ≤ `2^{1−8S}`), so the
    abort probability varies across indices by at most that same soundness
    bound. At `S = 8` this is `2^{-63}`-scale — privacy-irrelevant in
    practice.
  - **Two-word tampering at `S = 1` is a different, CONCLUSIVE oracle, not a
    smaller-probability version of the same one.** Tamper two DIFFERENT
    value words `j1 ≠ j2` in the SAME query with the same chosen error `e`,
    and mirror it with the same tag-channel error at both tag words. Passing
    the check at both words requires
    `m·(e − δ1·2^{8L}) ≡ m·(e − δ2·2^{8L}) (mod 2^{8(L+S)})`, and since `m`
    is forced odd (hence invertible mod a power of two) this collapses to
    `δ1 ≡ δ2 (mod 2^{8S})`. At `S = 1`, `δ ∈ {0, 1}`, so the reduction is
    exact: `δ1 = δ2`. Both carries are **deterministic functions of
    `record[i]`** (whether `word_{j1}(record[i]) + e` and
    `word_{j2}(record[i]) + e` each overflow `2^{8L}`) — so accept/reject
    becomes a conclusive, adversary-chosen, amplifiable 1-bit oracle on
    `record[i]`, with NO dependence on guessing `m` at all. This is not
    covered by the `2^{1−8S}` soundness bound above, which is a per-word
    statement; it is a distinct two-word interaction the bound does not
    price in. `S = tag_slack_bytes` is a compile-time module parameter with
    an enforced floor of 1 (`S = 0` is a compile error, see above) — `S = 1`
    is therefore a *permitted*, documented configuration, not a
    theoretical/unreachable corner.
  - **Practical bar.** The recommended default is `S = 8`; at that setting
    the two-word attack above requires `δ1 ≡ δ2 (mod 2^{64})` with
    `δ ∈ {0, 1}`, i.e. it degenerates back into the same `2^{1-8S}`-scale
    event the single-word argument already bounds. The conclusive oracle is
    specific to the low-`S` floor, which is exactly why this module
    documents it here rather than only at `S = 1`'s own instantiation site.

### Against the alternatives

- **Authenticated PIR (Colombo et al., USENIX Security 2023) — digest +
  verifiable answers.** Strictly stronger in one dimension: it binds answers
  to a *published* database digest, so even two servers agreeing on a modified
  database are caught. Not chosen because it changes what the system *is*:
  the client must obtain and refresh an authentic digest out of band (a new
  trust anchor and a publishing pipeline), and the scheme dictates the
  database encoding rather than composing over this module's. The chosen
  construction needs no digest, no publisher, no database change and no new
  primitive — and the one property it thereby gives up is stated and tested
  (`ATTACK NOT CAUGHT`) rather than blurred. Where database authenticity
  matters, a digest mechanism *composes on top* (e.g. records carrying
  publisher signatures verified after retrieval) without touching this layer.
- **Cross-checking / repetition.** Repeating the query with fresh keys and
  comparing fails against the simplest adversary: a server that adds the
  *same* constant to its answer every time produces identical wrong
  reconstructions that compare equal. Repetition detects only *inconsistent*
  lying, doubles bandwidth, and its guarantee degrades with an adversary that
  remembers. Rejected outright.
- **Merkle / Poseidon commitment with per-record openings.** Same trust-model
  change as authenticated PIR (an authentic root must reach the client), plus
  a mechanical cost this module would inherit: an opening is `log N` siblings
  whose positions depend on `i`, so retrieving it privately means `log N`
  further PIR queries (or growing every record by the whole path). `poseidon`
  landing in this repo makes the hash cheap, not the protocol — considered
  and declined; it becomes attractive only together with the digest trust
  model, i.e. as part of a future authenticated-PIR module, not as a flag
  here.
- **"Verifiable DPF" (BGI sketching and successors).** Protects the *servers*
  from a malformed client key — the opposite direction from what is wanted
  here, and conflating the two would produce a module that sounds right and
  protects nothing. Nothing in this layer validates the client's key
  (nothing can, in plain two-server PIR); a malicious client can still only
  corrupt its own retrieval.

### Constant-time position

The client's check is a fixed-trip loop of ring multiply/add/xor accumulating
one difference word — no data-dependent branch, no early exit — with a single
final branch on the accept bit, which is the protocol's own public output (the
abort is visible by definition). Timing therefore does not reveal which word
mismatched or by how much. Wide-integer `*%` compiles to branch-free multiply
chains on the supported targets. The DPF evaluation underneath keeps `fss`'s
documented posture (control-bit-gated branches, hardening scoped out there);
this layer adds no new branch on secret data.

### Constant-time PRG selection

`Pir`/`Verified` are generic over `fss`'s DPF, and `fss`'s DEFAULT PRG
(`fss.prg.default` = `Aes128Mmo`) declares
`constant_time = aes.has_hardware_support`: on a target with AES-NI or
ARMv8-AES it is constant-time, but on one without either it falls back to
`std`'s software (T-table) AES implementation, which is NOT constant-time.
The secret this touches is real and named: the client's own DPF-key
generation (`Gen`) walks the domain tree keyed by the query index `i`, so a
co-resident cache-timing attacker observing that soft-AES fallback can
recover bits of `i` — exactly the thing this whole protocol exists to hide.

`fss` already exposes the escape hatch this needs — `Sha256Prg`, a
constant-time PRG built on `std.crypto.hash.sha2.Sha256` — via
`fss.DpfWith`/`fss.MpfWith`. Prior to `PirWith`/`VerifiedWith` existing,
nothing threaded that choice through: `Pir`/`Verified` were hard-wired to
`fss.Dpf`/`fss.Mpf`, i.e. to the default PRG, with no way for a caller on a
soft-AES target to opt into `Sha256Prg` instead. `pir.PirWith(Prg, ...)` and
`verify.VerifiedWith(Prg, ...)` now take the PRG as an explicit parameter,
mirroring `fss.DpfWith`/`fss.MpfWith` exactly; `Pir`/`Verified` remain
`PirWith`/`VerifiedWith` applied to `fss.prg.default`, unchanged for every
existing caller. A caller on a target without AES-NI/ARMv8-AES that cares
about this side channel should instantiate with `fss.prg.Sha256Prg`
explicitly rather than relying on the default.

### Anchoring the verified layer

No external vector exists, for the base protocol's reasons plus one of its
own: the MAC scalar is a per-query client secret, so a published vector would
have to fix it, and there is no published construction to borrow one from —
the layer is a composition (DPF β-programming + SPDZ2k-style widened check)
assembled here, not an implementation of a named scheme's wire format. The
test labels extend the base table with one entry:

| Label | Meaning |
|---|---|
| `ATTACK` | a simulated malicious server; the module plays both attacker and defender. SELF-grade evidence for the *detection* property: it proves the check fires on these concrete deviations (bit flips at every position, zeroing by one and by both servers, replay, one-sided database modification, the top-bit ring forgery) and — just as deliberately — that two specific attacks are **accepted**: the colluding forgery and the agreed-wrong-database, which are the two documented limitations made executable. |

The tag channel's honest value is separately `DERIVED` (recomputed as `m·word`
straight from the plaintext, no DPF), and both new untrusted boundaries (a
server parsing a bundled share; a client parsing four answers) carry the same
exhaustive length sweeps and `std.testing.fuzz` harnesses as the base codec,
including the full hostile-share server path over both channels.

## Privacy — what is and is not established

The security claim is: **the distribution of a single share, given index `i`,
is computationally indistinguishable from its distribution given `i'`.** No
unit test can establish that — it reduces to the PRG being a PRG, which is a
cryptographic assumption, not a testable property. Saying otherwise would be
the exact failure mode the brief warns about: a test that *looks* like it
proves privacy.

So `src/privacy_test.zig` is split into two clearly-labelled kinds, and the
honest summary is that it establishes **this module does not undo the DPF's
hiding property** — no index-derived byte, length or access pattern escapes
into a single server's view — and nothing stronger.

**EXACT** (deterministic, no statistical margin; each pins one structural way
a share could have leaked and did not):

- A serialized share's length is a compile-time constant, identical for every
  index. The first place a length side-channel would appear.
- An answer's length is a function of the database geometry alone. The
  server → client direction of the same concern.
- A share's 16 root-seed bytes are a verbatim copy of the caller's randomness,
  for every index — that component carries exactly zero information about `i`.
- The two shares' correction words are byte-identical, and the collusion
  attack recovers `i`. (An assertion *against* privacy — the threat model.)
- The level-1 control-bit correction words' **parity is exactly
  index-independent**: from BGI's formulas, `t_cw_l ⊕ t_cw_r = t0_L ⊕ t1_L ⊕
  t0_R ⊕ t1_R ⊕ 1` and `α_1` cancels. The one place in a share where
  α-independence is a *fact* rather than an assumption.
- The counterweight, and the most important honest statement in the file: with
  the seeds held fixed, the **level-1 seed correction word takes exactly two
  values across the domain, partitioned by the top bit of the index**. The
  dependence on `i` is real and structural. What hides it is that a server
  never sees two shares under the same seeds. Privacy here is *computational*
  and rests entirely on the PRG — asserted so that nobody reads the parity
  test above as an information-theoretic result.
- A census of which bits of a serialized share are structurally constant: the
  control-bit CWs are stored one per *byte* with values 0/1, so seven bits of
  each such byte are always zero. Asserted to be *exactly* those bits and no
  others — because a blanket "the share looks uniformly random" check would
  fail on them, and loosening a threshold to accommodate that is how a real
  constant gets missed.

**STAT** (one statistic, with a stated detection floor and negative controls):

Sample 512 shares for index `i` and 512 for `i'` from independent
pseudorandom seed streams, and compare per-bit frequencies across all
`share_len·8` positions. Reject if any position's frequency gap exceeds
`0.20 ≈ 6.4σ` (σ = `sqrt(2·0.25/512) ≈ 0.031`), which puts the
false-positive probability around `1e-7` over the ~1300 positions compared —
and the seeds are deterministic, so this test either passes forever or fails
forever, never flakes.

Index pairs are part of the statistic, not a detail: `(0, 200)`, `(1, 255)`
and — deliberately — the **adjacent** pair `(0, 1)`, whose α-paths agree at
every level but the last and whose indices differ only in the low bit. Without
that third pair the test is blind to any leak keyed on the index's low bit,
because every other pair differs only in higher bits. That gap was found by
mutation-testing the harness, not by inspection.

Two **negative controls** run the identical code path and threshold against
deliberately broken shares — the index copied verbatim into a share byte, and
a single bit of the index in a single bit of a share — and must be *rejected*.
Without them the STAT test would prove nothing about its own sensitivity.

**What the STAT test does NOT establish**, stated plainly:

- Nothing about computational indistinguishability. It is a marginal, per-bit,
  first-order check. A leak spread across bits, or visible only in a joint
  distribution, is invisible to it.
- Nothing below its detection floor. A leak that shifts no single bit's
  frequency by more than ~0.20 — anything probabilistic, or diluted across
  many positions — passes. It catches a one-bit *deterministic* leak, which is
  what the negative controls demonstrate, and that is the bound of the claim.

## Anchoring — no external vector exists, and why

`CONVENTIONS.md` §7 asks for an external oracle where one exists. For this
composition **none is obtainable**, and that is a finding rather than an
omission:

- **Two-server PIR is not a standardised protocol.** There is no RFC, no NIST
  document, no published wire format and no KAT for "DPF-based 2-server PIR"
  as such. It is a composition described in paper introductions
  (Gilboa–Ishai EUROCRYPT 2014; Boyle–Gilboa–Ishai CCS 2016), with every
  implementation choosing its own record layout, output group and encoding.
  A search of the PIR literature and of Google's `distributed_point_functions`
  library surfaced DPF vectors and PIR *parameters*, never a retrieval-level
  test vector.
- **Even the DPF layer could not interoperate — but not for the reason this
  section used to give.** `fss`'s *default* PRG is now fixed-key AES
  (`Aes128Mmo`), not a module-defined SHA-256 (that swap happened after this
  paragraph was first written; `Sha256Prg` still exists as a
  correctness-anchoring instantiation and, separately, a caller-selectable
  constant-time-safe alternative — see §"Constant-time PRG selection"). The conclusion is
  unchanged, but for `fss`'s actual reason (`fss/SPEC.md`
  §"External-reference anchoring"): moving to fixed-key AES removes the
  *primitive* as an obstacle to interop with Google's
  `distributed_point_functions`, but not the rest — byte-exactness would also
  need that library's exact fixed AES keys, tweak/counter convention, byte
  order, control-bit extraction, value-correction scheme and protobuf key
  layout, none of which is pinned by a published vector file. `fss`'s PRG and
  key layout remain module-defined regardless of which primitive backs them,
  so any external PIR vector — built on a different DPF library's key format
  — cannot byte-exactly agree with this composition's output either way.
- **The DPF underneath is already anchored**, byte-exact, against an
  independent Python re-derivation of BGI16 Fig. 1 (`fss/kat_vectors.zig`).
  This module leans on that rather than re-proving it: everything below
  `query`/`answer` is `fss`'s, and `fss`'s harness owns it.

Tests here are therefore labelled with what they actually are, and no vector
computed by this implementation is presented as an external anchor:

| Label | Meaning | Examples |
|---|---|---|
| `EXTERNAL` | produced by something outside this repo | **none in this module** |
| `DERIVED` | in-house re-derivation by a structurally different route | the answer recomputed straight from `Σ_x f_{i,1}(x)·word_j(record[x])` with no DPF involved, and required to match the shared computation |
| `SELF` | round-trip or property against this module | exhaustive per-index retrieval; wire round-trips; the length sweep |
| `EXACT` / `STAT` | the privacy battery's two kinds | see above |

The correctness sweep runs **every index** of databases sized to straddle the
DPF's internal tree boundaries — 1 record (the degenerate case, in the
smallest possible 1-bit domain), exact powers of two, one below and one above
— crossed with record lengths straddling the word boundary (1, 3, 4, 5, 7, 16,
33). One further test asserts that **every database record influences the
answer**: if the server ever skipped a record — an early exit, a
zero-share shortcut — perturbing that record would leave the answer unchanged.
That is the access-pattern claim in `answer`'s doc comment, made falsifiable.

### Harness teeth (mutation testing)

The suite was mutation-tested rather than assumed to work. Each mutation was
applied, the suite run, and the mutation reverted:

| Mutation | Caught by |
|---|---|
| `reconstruct` combines with `-` instead of `+` | every correctness test |
| server's loop stops one record short | the retrieval sweep, the `DERIVED` re-derivation, and the every-record-influences test |
| a **real** one-bit index leak into `cw_final` in the live `query` path | the correctness tests **and the STAT privacy test** — which is the evidence that the STAT test fires on a genuine regression, not only on its own synthetic controls |
| `reconstructFromBytes` derives its word count from the **input** buffer instead of the receiver's geometry (the bug shape the brief flags) | the exhaustive length sweep, the geometry-error test, and a hard `SIGABRT` under the standalone hammer |
| **(Verified)** the presence-word check dropped from `reconstruct` | the coordinated-zeroing test, the presence-bit-flip sweep, and the unpopulated-index test — 3 tests, exactly the ones that exist because of that word |
| **(Verified)** the MAC loop checks only word 0 (`per` → `min(per, 1)`) | both bit-flip sweeps, on flips in words ≥ 1 |
| **(Verified)** the tag comparison truncated to the low `8L` bits — an "inconclusive" check that silently reintroduces the un-widened ring | the tag-answer bit-flip sweep (high-bit flips sail through) **and the top-bit ring-forgery test** — the test built to guard the widening catches its removal |

## Fuzzing

Every parser that touches bytes from a peer is held to
`CONVENTIONS.md` §7.1's never-panic bar. There are two such boundaries: a
**server parses a client's share**, and a **client parses two servers'
answers**. Both have `std.testing.fuzz` harnesses, including one that runs the
*whole* server path — parse a hostile share, then compute an answer with it —
because a share that parses is not a share that is valid, and the answer
arithmetic must survive arbitrary key material.

**The count-from-input bug class is absent by construction.** The codec has no
length fields, no headers and no counts anywhere. Every length is either a
compile-time constant (`share_len`) or derived from the *receiver's own*
buffers (`answerFromBytes` computes the required length from `out`, not from
`buf`), and the input is required to match exactly. A share is a fixed-width
read at compile-time-known offsets. There is nothing an attacker can claim a
length about. `Database.init` rejects `record_len == 0` up front so that
`count()`/`record()` are total afterwards and no division by an
attacker-influenced zero exists downstream.

**Two gaps in the standard workflow, stated because they affect what the fuzz
evidence is worth:**

1. ~~`zig build test-pir --fuzz` does not build on this Zig 0.16.0.~~
   **CORRECTED.** The failure is **Debug-only**: `zig build test-pir --fuzz`
   still fails to compile the shipped `lib/compiler/test_runner.zig` under
   `-ffuzz` (`*builtin.StackTrace` vs `*const debug.StackTrace`, re-confirmed),
   but **`zig build test-pir --fuzz --release=safe` builds and runs the real
   fuzzer**. The original claim was too broad, and while it stood, the default
   corpus was all these harnesses had ever run. They have since been run under
   the real fuzzer; see "What the real fuzzer found" below.
2. That corpus was measurably too thin: the deliberate count-from-input
   mutation above **was not caught by the in-repo fuzz harnesses** — only by
   the explicit unit test. Two things were done about it rather than noting it
   and moving on: an **exhaustive deterministic length sweep** was added
   (every combination of two answer-buffer lengths against every record length
   in a small range, asserting both that correct lengths are accepted *and*
   that every other length is rejected — a parser that rejects everything
   would pass a never-panics test while being useless), and it does catch the
   mutation; and a standalone hammer was run outside the repo.

The hammer drove ~300 000 iterations across six `(domain_bits, word_bytes)`
configurations — `(1,1)`, `(8,4)`, `(8,1)`, `(5,32)`, `(16,16)`, `(31,8)` —
feeding arbitrary bytes and arbitrary lengths through every boundary, plus
`Database.init` with `record_len ∈ {0, maxInt(usize), random}` and
`domainBitsFor` over the full `usize` range. Clean in **both Debug and
ReleaseSafe**; it aborts within seconds on the injected count-from-input bug,
so it has teeth. Per `CONVENTIONS.md` §7.1 this is evidence about a Debug or
`ReleaseSafe` build and says nothing about a `ReleaseFast` one.

**No crash was found.** No bug in `fss` was found either — its `Key.fromBytes`
takes a `*const [serialized_len]u8`, a fixed-size array pointer, so the parser
has no length to trust in the first place. The multi-index boundaries preserve
that property exactly: `fss.Mpf`'s key is `k` sub-keys at compile-time-known
offsets, `k` is a compile-time parameter rather than anything read from the
input, and `Multi.shareFromBytes` accepts exactly one length. There is still
no count an attacker can claim.

### What the real fuzzer found

With `--release=safe --fuzz` working, both modules' harnesses were run under
the actual fuzzer rather than the default corpus. Result: **no crash, no
panic** in either — but the fuzzer did immediately reject a wrong *assertion*
that the default corpus had accepted, and the finding is `fss`'s, not this
module's:

> A fuzz harness asserted that decoding a key and re-encoding it reproduces the
> input bytes. It does not. `serializeCw` writes each control-bit correction
> word as a whole byte valued 0/1 while `fromBytes` truncates that byte to its
> low bit, so **the encoding is not injective**: two distinct byte strings
> decode to the same key. See `fss/SPEC.md` §"The encoding is not injective".

No protocol consequence here — nothing in `pir` signs, MACs, hashes or
deduplicates a serialized share, and a share that decodes to an equivalent key
produces an identical answer. It is recorded because a consumer that *does* any
of those things must canonicalize first, and because it is a concrete example
of the default corpus being too thin to be relied on.

## Where the library stops

`CONVENTIONS.md` §2's separation of codec from I/O, applied here:

**In:** query construction, server-side answer computation, reconstruction,
and the byte codecs between them. All pure computation — `meta.platform =
.any`, no allocator, no threads, no clock, and no entropy source (the two
seeds are caller-supplied, exactly as `fss` requires).

**Out:** sockets, framing, retries, a server process or request loop, any
storage format. `Database` is a *borrowed view* over bytes the caller already
has — it never owns, copies, opens or parses anything. Two facts are all the
answer computation needs (how many records, where record `i` starts), and
asking for more would drag a storage opinion into a module whose job is
arithmetic. A caller with a memory-mapped file, a slice-of-slices
(`answerSlices`) or a custom container keeps its own layout.

The seam is deliberately at the same place as the rest of the repo's
protocol modules: bytes in, bytes out, and the transport is the integrator's.

## Scoped out

- ~~**Multi-index queries.**~~ **Built** — `Multi(k)`, above, once `fss` grew
  `Mpf`. The blocker was correctly identified as being in `fss`, not here.
- **Sublinear batch PIR.** `Multi(k)` amortizes the *database pass* (one
  interleaved walk over the record prefix, all `k` trees at once) but still
  costs `k·N` DPF evaluations. The
  cuckoo/batch-code multi-point construction would cut that to `O(N)`; it is
  scoped out in `fss` with its revisit trigger stated there.
- ~~**Answer verification / malicious-server security.**~~ **Built** —
  `Verified`, §"Malicious-server detection" above: detection of a lying
  server via a secret-scalar MAC in a widened ring. What remains scoped out
  of *that* is stated there: recovery/robustness, attribution, binding to a
  published database (authenticated PIR), and a verified `Multi(k)` (`k` tag
  channels compose the same way; nothing new cryptographically, deferred
  until a consumer wants it).
- ~~**PIR by keyword.**~~ **Built** — `keywordIndex`/`queryKeyword`,
  §"Keyword lookup" above: a public total hash-to-index map with no retry and
  no existence check, so a miss is the same call as a hit; collisions are a
  provisioned false-negative cost, not a leak. What remains scoped out of
  *that* is stated there: a published injective mapping (needs an out-of-band
  publishing pipeline this no-I/O module cannot provide) and cuckoo/multi-slot
  placement (rejected in `fss` with a stated trigger; a deployment can compose
  `Multi(k)` over `keywordIndex` variants above this layer).
- **Hiding `k` itself.** `k` is public protocol geometry and the share length
  reveals it; a client hides only its *effective* count, by padding. Making `k`
  itself private would mean padding every share to a deployment-wide maximum,
  which is a protocol decision above this layer.
- ~~**An efficient full-domain evaluator.**~~ **Built, in `fss` as
  predicted** — `Dpf.evalFull`/`evalFullWith` (tree-reuse **prefix**
  evaluation; `fss/SPEC.md` §"Tree-reuse prefix evaluation"), wired into
  `answer`/`answerSlices` and `Verified.answer`'s tag channel
  (§"Server cost" above): ~1 PRG call per record instead of `domain_bits`,
  measured ~11× at `domain_bits=16`, with the unused-tail truncation invariant
  and the access-pattern requirement both preserved and still tested.
  `Multi(k)`'s inner loop is now wired too, and to the shape this entry
  predicted it needed: **not** `k` prefix walks (which would have flipped the
  documented one-pass-over-records property into `k` passes) but `fss`'s
  `Mpf.evalEachFullWith`, a single `k`-tree interleaved walk — ~`k` PRG calls
  per record instead of `k·domain_bits`, measured ~9.5–14×, same keys, same
  construction, answers word-for-word identical to the loop it replaced.

## References

- N. Gilboa, Y. Ishai, "Distributed Point Functions and Their Applications",
  EUROCRYPT 2014 — the DPF and its PIR application.
- E. Boyle, N. Gilboa, Y. Ishai, "Function Secret Sharing: Improvements and
  Extensions", ACM CCS 2016 — the optimized tree construction `fss`
  implements.

Clean-room from these public papers; no third-party source ported and no
third-party implementation consulted, so per `CONVENTIONS.md` §5 no `NOTICE`
entry is required and the citations live here.

## Anchoring

**Anchor grade:** class B · oracle SELF

- **Class B** — published cryptographic or algorithmic construction with published vectors.
- **Oracle SELF** — round-trip and/or hand-authored fixtures only — the weakest grade.

**What the tests actually contain.** SPEC.md: no external test vector exists for this DPF construction

**How it got there.** No external oracle exists for what remains. SPEC.md explicit: no published vector for this DPF-PIR composition exists anywhere
