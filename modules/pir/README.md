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

**Status: COMPLETE for single-index and multi-index retrieval.** Query
construction, both servers' answer computation, reconstruction, and the wire
codecs are implemented and tested for both. Multi-index retrieval (`Multi(k)`,
several records in one round trip) rides on `fss`'s multi-point FSS
(`fss.Mpf`) — the blocker that used to be recorded here was in `fss`, and it
is gone.

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

### What this does not do

No verification. A malicious server can return any answer it likes and the
client will reconstruct garbage without noticing — two-server PIR has no
integrity mechanism, and nothing here pretends otherwise. No keyword lookup
(indices only). No protection against a server that returns a *different
database* than its peer. `Multi(k)` amortizes the database *pass* but still
costs `k` DPF evaluations per record — sublinear batch PIR needs the
cuckoo/batch-code multi-point construction, scoped out in `fss`.

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
