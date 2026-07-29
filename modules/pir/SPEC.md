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
with `Mpf.evalEach` and accumulates `k` separate inner products, so an answer
is `k` record-sized blocks and reconstruction yields all `k` records. There is
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

The server makes **one pass** over the database (records outside, instances
inside), so each record's bytes are decomposed once. That is a memory-traffic
win only; the DPF evaluations are still `k·N`.

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

**Other real failure modes, none of which this module can detect:**

- *Replica divergence.* Both servers must hold byte-identical databases in the
  same order. Off-target terms cancel term-by-term across the two servers; a
  record that differs between them, or a differing record count, leaves an
  uncancelled term and silently corrupts the answer.
- *Malicious answers.* There is no verification step. A server can return
  anything; the client reconstructs garbage without noticing. Two-server PIR
  has no integrity mechanism, and adding one (e.g. an authenticated variant)
  is a different protocol, not a flag.
- *Seed reuse.* `query`'s two seeds are the protocol's only randomness and the
  DPF is deterministic given them. Reusing a seed pair across queries for
  different indices hands a server two shares related by a known structure.
  Fresh CSPRNG seeds per query, always.
- *Sending both shares to one server.* Self-evidently fatal; stated because
  `query` returns them as one array and an off-by-one in the caller's plumbing
  is all it takes.
- *Traffic analysis above this layer.* Query timing, frequency and correlation
  with observable events are outside a library with no I/O.

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
- **Even the DPF layer could not interoperate.** `fss` deliberately uses a
  module-defined SHA-256 PRG rather than the fixed-key-AES construction of
  Google's library, precisely so its correctness could be anchored against an
  independent re-derivation in another language (`fss/SPEC.md`
  §"External-reference anchoring"). Any external PIR vector would be built on
  that library's PRG, so byte-exact agreement is impossible by `fss`'s own
  design decision — not by an oversight here.
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
- **Sublinear batch PIR.** `Multi(k)` amortizes the *database pass* (records
  outside, instances inside) but still costs `k·N` DPF evaluations. The
  cuckoo/batch-code multi-point construction would cut that to `O(N)`; it is
  scoped out in `fss` with its revisit trigger stated there.
- **Answer verification / malicious-server security.** A different protocol
  (authenticated or verifiable PIR), not a flag on this one.
- **PIR by keyword.** Index lookup only; keyword PIR needs a hashing/cuckoo
  layer above this.
- **Hiding `k` itself.** `k` is public protocol geometry and the share length
  reveals it; a client hides only its *effective* count, by padding. Making `k`
  itself private would mean padding every share to a deployment-wide maximum,
  which is a protocol decision above this layer.
- **An efficient full-domain evaluator.** The server's cost is dominated by
  one `Dpf.eval` per record, each `O(domain_bits)` SHA-256 calls. `fss`'s
  scoped-out tree-reuse `evalFull` would cut that to `O(1)` amortized per
  record and is the single biggest speedup available — it belongs in `fss`.

## References

- N. Gilboa, Y. Ishai, "Distributed Point Functions and Their Applications",
  EUROCRYPT 2014 — the DPF and its PIR application.
- E. Boyle, N. Gilboa, Y. Ishai, "Function Secret Sharing: Improvements and
  Extensions", ACM CCS 2016 — the optimized tree construction `fss`
  implements.

Clean-room from these public papers; no third-party source ported and no
third-party implementation consulted, so per `CONVENTIONS.md` §5 no `NOTICE`
entry is required and the citations live here.
