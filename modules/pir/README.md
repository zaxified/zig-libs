# pir

**Two-server Private Information Retrieval.** Fetch record `i` from a
database that two servers each hold a copy of, without either server learning
`i`. Upload is `O(λ·log N)` — a pair of short keys, not a request naming the
record — and download is one record, against the `O(N)` of downloading the
whole database, which is the trivial alternative and the thing PIR exists to
beat.

Built as a thin composition over this repo's [`fss`](../fss/README.md)
Distributed Point Function. The DPF *is* the primitive two-server PIR is made
of; almost everything hard lives there, and this module is the arithmetic and
the codec that turn it into a retrieval protocol.

**Status: COMPLETE for single-index, multi-index and keyword retrieval, plus
malicious-server DETECTION.** Query construction, both servers' answer
computation, reconstruction, and the wire codecs are implemented and tested
for both. Multi-index retrieval (`Multi(k)`, several records in one round
trip) rides on `fss`'s multi-point FSS (`fss.Mpf`). Keyword lookup
(`queryKeyword`) is a public hash-to-index map in front of the unchanged index
protocol — read its callout below before using it. `Verified` adds a client
that detects a lying server and aborts instead of silently reconstructing a
doctored record — detection, not recovery; see below. Server answers run on
`fss`'s tree-reuse `evalFull` (~1 PRG call per record instead of
`domain_bits`; ~11× measured at `domain_bits=16`).

## Read this first

> **Two colluding servers recover `i` immediately.** The two query shares
> carry byte-identical correction words; anyone holding both evaluates them
> across the domain and reads off the one index where the sum is non-zero. No
> cryptanalysis, no work beyond a full-domain scan. That is the security model
> of two-server PIR, not a defect in this implementation — and if you cannot
> justify non-collusion operationally (separate operators, separate
> infrastructure, separate jurisdictions), the protocol buys you nothing. The
> attack runs as a test in `src/privacy_test.zig` so it is not possible to read
> past it.

> **Reconstruction is `+`, not XOR.** The usual one-paragraph description of
> DPF-based PIR — "each server XORs the records its share selects, the client
> XORs the two answers" — describes a *bit-valued, `GF(2)^m`* DPF. `fss`'s DPF
> is the additive `Z_{2^{8L}}` construction, so `Eval` returns a full
> pseudorandom group element, there is no "the records this share selects",
> and the answer is a **ring inner product**. See `SPEC.md` for the derivation.

## Import

```zig
const pir = @import("pir");
```

## API

```zig
// 1. Describe the database. A borrowed view — no copy, no allocation.
const database = try pir.Database.init(flat_bytes, record_len);
const bits = try pir.domainBitsFor(database.count());   // pick domain_bits

// 2. Instantiate. Both parameters are comptime, because fss.Dpf's are.
const P = pir.Pir(3, 16);       // 2^3 indices, 16-byte arithmetic words

// 3. CLIENT — one share per server. s0/s1 must be fresh, independent,
//    cryptographically random 16-byte seeds, never reused for another query.
const shares = try P.query(want_index, s0, s1);

// 4. SERVERS — server b holds shares[b] and the same database.
const n_words = P.answerWords(database.record_len);
try P.answer(0, shares[0], database, a0[0..n_words]);
try P.answer(1, shares[1], database, a1[0..n_words]);

// 5. CLIENT — combine.
try P.reconstruct(a0[0..n_words], a1[0..n_words], &record_out);
```

`src/root.zig`'s last test *is* that example, so it cannot drift.

### Retrieving `k` records at once

```zig
const M = P.Multi(3);   // 3 records per round trip; k is comptime

// CLIENT — 2k seeds: one INDEPENDENT pair per instance, never reused.
// Byte-identical seeds are rejected (error.SeedReuse) because reusing a pair
// across instances would make the two indices' shared prefix readable.
const shares = try M.query(.{ 4, 1, 6 }, seeds0, seeds1);

// SERVERS — one message each, k record-sized blocks wide.
const n_words = try M.answerWords(database.record_len);
try M.answer(0, shares[0], database, a0[0..n_words]);
try M.answer(1, shares[1], database, a1[0..n_words]);

// CLIENT — all three records, laid end to end (block j at j*record_len).
try M.reconstruct(a0[0..n_words], a1[0..n_words], record_len, &records_out);
```

**`k` records need `k` blocks.** A single multi-point inner product computes
`Σ_j record[α_j]` — the *sum* of the selected records, not the records. That
query is real and is exposed as `answerAggregate` (its download is one record
whatever `k` is), but it cannot be inverted to the individual records, so
retrieval keeps the `k` instances separate. See `SPEC.md`.

Repeated indices are fine in retrieval (`.{7,7}` returns record 7 in both
blocks); in the *aggregate* the same points add, to `2·record[7]`.

> **`k` is public.** The share length is `k ×` the single-index length and the
> answer is `k` blocks wide, so both reveal `k`. That is acceptable only
> because `k` is compile-time protocol geometry, identical for every client —
> never a per-query secret. A client wanting fewer than `k` records pads with
> dummy indices; each index is hidden by its own instance, so padding hides the
> *effective* count for free.

### Looking up by keyword

```zig
// The database-builder places the record for `kw` at P.keywordIndex(kw)
// (SHA-256, truncated to domain_bits — public, deterministic, total), and
// gives every record its own key field so the client can check the match.

// CLIENT — one unconditional query per lookup. Nothing else.
const shares = try P.queryKeyword("alpha", s0, s1);
// …servers answer, client reconstructs exactly as above, then checks the
// record's own key field LOCALLY: match → hit; mismatch/filler → absent.
```

> **A miss is the same call as a hit — as long as you never skip and never
> retry.** `queryKeyword(kw, …)` is exactly `query(keywordIndex(kw), …)`: the
> map is total (every keyword lands on *some* index) and unconditional (no
> existence check, no retry, no probing, no database access), so the servers
> see the identical call shape whether the keyword exists or not, and the
> derived index is hidden by the same DPF property as any other index. That
> holds **only if the caller keeps the discipline: one lookup, one query,
> whatever comes back.** Checking a local set/Bloom filter and skipping the
> query, or re-querying on a mismatch, puts the presence bit back on the wire
> — a test demonstrates exactly that wrapper's leak.
>
> **The cost is collisions, and it is a correctness cost, not a privacy
> cost:** two keywords can hash to one slot; whichever record the builder
> placed there is what comes back for both, and the losing keyword is simply
> unreachable (a false negative you discover locally — nothing branches on
> it). Provision for it: for `N` keywords,
> `P(any collision) ≈ N²/2^(domain_bits+1)` — pick
> `domain_bits ≥ 2·log2(N) + log2(1/ε) − 1` for probability ≤ `ε`
> (e.g. 1000 keywords, `domain_bits = 30` → `P < 5·10⁻⁴`). Oversizing the
> domain is cheap: the unused tail is never evaluated.
>
> **Under `Verified`:** `W.queryKeyword` exists too, but a keyword whose slot
> is past the database **rejects** (`error.AnswerRejected`) — an honest
> all-zero is indistinguishable from a zeroing attack — so "absent" and "a
> server lied" look the same. A deployment wanting a verifiable absent must
> materialize every slot with filler records. See `SPEC.md` §"Keyword lookup".

### Parameters

| Parameter | Meaning |
|---|---|
| `domain_bits` | `1..31`. Addresses `2^domain_bits` indices. Pick it with `domainBitsFor(count)`. A domain **larger** than the database is fine — the unused tail is never evaluated. Smaller is `error.DomainTooSmall`. |
| `word_bytes` | `1..32`. The arithmetic width records are cut into. Larger means fewer multiplications per record and does not change the answer size beyond rounding a record up to a whole word. `16` is a good default; `1` gives byte-exact answer sizes. |

### Wire

Four codecs, all fixed-length, none with a length field or header:

```zig
P.shareToBytes(share, &buf);                    // client → server, P.share_len bytes
const share = try P.shareFromBytes(bytes);      // server parses (untrusted)
try P.answerToBytes(words, buf);                // server → client
try P.answerFromBytes(bytes, words_out);        // client parses (untrusted)
try P.reconstructFromBytes(a0, a1, &record);    // parse + combine, no intermediate
```

`Multi(k)` has the same shape (`shareToBytes`/`shareFromBytes`/
`reconstructFromBytes`, the last taking `record_len` since an answer is `k`
blocks); answers reuse the parent's `answerToBytes`/`answerFromBytes`
unchanged, since those are length-generic.

Framing them for an actual transport is the caller's job — this module has no
sockets and no server loop (see `SPEC.md` §"Where the library stops").

### Records

All records must be the same length. That is a privacy requirement, not a
convenience: an answer is record-sized, so variable-length records would make
the answer size leak which record was retrieved. Pad at ingest.

`answerSlices` takes `[]const []const u8` for callers whose database is not
one contiguous buffer.

### Detecting a lying server — `Verified`

The base protocol trusts servers to answer honestly; a doctored answer
reconstructs silently to garbage. `Verified` removes that trust for
**integrity**: the client MACs its own query through the protocol's linearity
— a second, independent DPF whose secret value parameter `m` only the client
knows, evaluated in a ring widened by `tag_slack_bytes` (soundness error
`2^(1−8·tag_slack_bytes)`; use `8`) — and aborts with `error.AnswerRejected`
when the answers don't carry the matching tags.

```zig
const W = pir.Verified(3, 16, 8);        // == pir.Pir(3, 16).Verified(8)

// CLIENT — four independent seeds + fresh MAC randomness, per query.
const q = try W.query(want_index, mac_rand, s0, s1, s2, s3);

// SERVERS — two answers each: the base value answer plus the tag answer.
const per = W.Value.answerWords(database.record_len);
const tw = W.tagWords(database.record_len);
try W.answer(0, q.shares[0], database, v0[0..per], t0[0..tw]);
try W.answer(1, q.shares[1], database, v1[0..per], t1[0..tw]);

// CLIENT — verify-then-reconstruct; error.AnswerRejected on any lie.
try W.reconstruct(q.secret, v0[0..per], v1[0..per], t0[0..tw], t1[0..tw], &record_out);
```

Read the security statement before relying on it (`SPEC.md`
§"Malicious-server detection"). The short honest version:

- **Detection only.** The client learns the answer is wrong and aborts; with
  two servers it cannot recover the record and cannot tell which server lied.
- Detects any deviation by **one malicious server** — and even by both, as
  long as they do not pool their keys — except with probability
  `2^(1−8·tag_slack_bytes)` plus the PRG advantage.
- **Colluding servers defeat it** (they recover `m` the same way they already
  recover `i`), and **both servers agreeing on the same wrong database passes**
  — the MAC binds to the servers' common database, not to a published one.
  Both non-detections are asserted by tests, not just documented.
- **Privacy is unchanged** — the tag key is one more DPF key, and the abort
  bit carries no usable index information (no selective-failure attack).
- Querying an index past the database **rejects** here (the base layer's
  all-zero convention is indistinguishable from a zeroing attack).
- Costs: 2 keys and ~2 answers of bandwidth, 2 DPF evaluations per record.

### What this does not do

Keyword lookup resolves collisions for nobody: a collision means the losing
keyword is unreachable (provision `domain_bits` for your keyword count — see
the callout), and there is no published-mapping distribution and no
cuckoo/multi-slot placement (see `SPEC.md` §"Keyword lookup" for why both
were declined). `Verified` detects but never repairs — no recovery, no
attribution, no protection when both servers serve the same modified database
(see above). `Multi(k)` amortizes the database *pass* but still costs `k` DPF
evaluations per record — sublinear batch PIR needs the cuckoo/batch-code
multi-point construction, scoped out in `fss` — and has no verified variant
yet; its inner loop also still uses per-point `eval` (the `evalFull` wiring
covers the single-index and `Verified` paths — see `SPEC.md` §"Scoped out").
The base (unverified) protocol remains available where integrity is provided
elsewhere.

## Verify

```
zig build test-pir                          # Debug
zig build test-pir -Doptimize=ReleaseFast
zig build test-pir -Doptimize=ReleaseSafe
zig build test-pir --fuzz --release=safe    # the real fuzzer (NOT Debug — see SPEC.md)
```

What the suite establishes, and what it does not, is set out in `SPEC.md`
§"Anchoring" and §"Privacy — what is and is not established". Short version:
correctness is exhaustive and exact; the privacy tests are a mix of exact
structural assertions and one honestly-labelled statistical test with negative
controls; and **no external test vector exists for this composition** — PIR
over a DPF is not a standardised protocol. The DPF underneath is separately
anchored in `fss`.

**Provenance:** clean-room from the public literature (Gilboa–Ishai
"Distributed Point Functions and Their Applications", EUROCRYPT 2014;
Boyle–Gilboa–Ishai, ACM CCS 2016). No third-party source ported, no
third-party implementation consulted — so per `CONVENTIONS.md` §5 there is no
`NOTICE` entry; the citations live in `SPEC.md`.
