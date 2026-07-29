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

**Status: COMPLETE for the single-index, whole-block case**, which is the case
that the underlying DPF supports. Query construction, both servers' answer
computation, reconstruction, and all four wire codecs are implemented and
tested. Multi-*index* queries (several records in one round trip) are out of
scope — they need a multi-point FSS scheme and `fss` ships only the
single-point DPF.

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
(indices only). No batching. No protection against a server that returns a
*different database* than its peer.

## Verify

```
zig build test-pir                          # Debug
zig build test-pir -Doptimize=ReleaseFast
zig build test-pir -Doptimize=ReleaseSafe
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
