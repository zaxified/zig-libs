# brotli — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-14** — Encoder: large-window streams (RFC 9841 §6) with `window_bits` 25..30 (`max_large_window_bits`; `CompressOptions`, `StreamOptions`) — the header, the large distance alphabet; blessed by libbrotli 1.2.0 (a copy from 17 MiB back). Completes R8. Streams at 10..24 unchanged. Additive API.

- **2026-10-14** — Decoder: large-window streams (RFC 9841 §6) with `Options.large_window` (off by default, as google/brotli): WBITS up to 62 (30 on 32-bit targets), the 62-bit distance alphabet read with google/brotli's limit of distances below 2^31. Six libbrotli large-window streams (copies from 17 MiB back) committed under `testdata/ref/large/` and replayed. Additive API.

- **2026-10-14** — Encoder: raw prefix dictionaries (`CompressOptions.dictionary`, `StreamOptions.dictionary`) — sizes within libbrotli's q5–q9 at `.default`, below q9 at `.best` on the interop dictionary cases; 15 of our dictionary streams blessed by libbrotli 1.2.0 and replayed. New `brotli.dcb` (RFC 9842 `Content-Encoding: dcb`: header, compress, decompress; errors `NotDcb`, `DictionaryMismatch`). Completes R6. Streams without a dictionary unchanged. Additive API.

- **2026-10-14** — Decoder: raw prefix dictionaries (RFC 9841 §3.2, what RFC 9842 `dcb` uses) — `Options.dictionary`, in `decompress`, `decompressInto` and `decompressStream`. The interop program gains a second reference, libbrotli itself (`tools/c_oracle/shared_oracle.c`, built with `zig cc`; the Python binding cannot attach a dictionary): 20 of its raw-dictionary streams are committed under `testdata/ref/dict/` and decoded by all three decoders in the replay test. Additive API.

- **2026-10-14** — New `StreamOptions.size_hint` (R3): the stream's match-finder table sized for the expected length instead of the window (a short response no longer allocates and clears 1–2 MiB); with the exact length the stream equals `compressWith`'s bytes for any input. `reset` keeps the table while its size stays. Additive API.

- **2026-10-14** — New `StreamWriter.writeMetadata(bytes)` (R5): a flush, then metadata meta-blocks (up to 16 MiB each) that decoders skip — google/brotli's `EMIT_METADATA`. Interop corpus: a `stream_metadata` variant, blessed by google/brotli 1.2.0 (326 checks, 0 mismatches). Additive API.

- **2026-10-14** — New `compressInto(gpa, out, input, opts)` (no output allocation; `error.OutputTooLarge` only when the stream `compressWith` gives does not fit) and `maxCompressedSize(n, opts)` (exact: incompressible input reaches it) — R4. Streams unchanged. Additive API.

- **2026-10-14** — New `StreamWriter` (R1): a `std.Io.Writer` that compresses into one stream — `flush` byte-aligns everything so far with an empty metadata meta-block (as google/brotli's flush), `finish` ends the stream, `reset` starts the next on the same table and history; without flushes the bytes `compressWith` gives with the same options. New `CompressOptions.window_bits` (10..24; null keeps the old choice, 16 or 21) and `StreamOptions.window_bits` (default 22); `min_window_bits`/`max_window_bits`. `compressWith` and the stream share one encoder core. Interop corpus: encoding variants (windows 10/15/17/24, two streamed with flushes) blessed by google/brotli 1.2.0 (322 checks, 0 mismatches); the 135 existing streams unchanged. Additive API.

- **2026-10-14** — Encoder: `.fast` is an algorithm of its own (`FastMatcher` + `buildCommandsFast`): 4 slots per bucket of a 6-byte hash, a slot picked by the position's bits (an insert is one store, no per-bucket count), the last distance tried first, a lazy step only for matches under 32 bytes, every fourth position inserted inside copies over 32 bytes, growing steps (up to 16) through literal runs over 64 bytes, the literal price from every fourth byte. A context-free block writes two literal codes per bit-writer call. vs google/brotli 1.2.0 q4: fast 1.24–1.40× → 0.96–1.12×; sizes json 31 507 → 31 139, html 17 341 → 17 023, text 54 642 → 55 580 B (q4: 31 748 / 17 370 / 55 504); interop corpus at `.fast` +0.38 % in total (`alpha2_flat` +9.6 %: six hashed bytes over a two-letter alphabet). `.default`/`.best` streams byte-identical. Interop fixtures re-blessed (294 checks, 0 mismatches). No API change.

- **2026-10-14** — Encoder: `.default` and `.best` try the last two distances before the hash bucket (a copy there costs no distance bits; from 3 bytes) — `html` −5 % at both (default 15 364 → 14 546 B, now smaller than q6), `json` −1 %; the match finder prefetches the next position's bucket; a block whose literals are ≥ 95 % ASCII clusters for the UTF8 context mode only (no stream of the interop corpus changed). Bench: the effort ↔ quality pairing is now computed each run (closest sizes), it was a fixed table. vs google/brotli 1.2.0: fast 1.24–1.40× (q4), default 1.02–1.06× (q6), best 0.75–0.91× (q9). Interop fixtures re-blessed (294 checks, 0 mismatches). No API change.

- **2026-10-14** — Encoder faster (bench vs google/brotli 1.2.0 at the paired quality: fast 1.47–1.50× → 1.34–1.48×, default 1.47–1.88× → 1.07–1.17×, best 1.05–1.60× → 0.77–0.95×). The match finder is a bucketed hash (each bucket keeps its last 8/32/256 positions) instead of a hash chain, whose walk was a chain of dependent loads; its table is 2^17/2^19/2^20 slots by effort. A block with several literal codes prices its one-code alternative on exact bits instead of writing it, and length codes come from a table. Compressed sizes move by under 0.3 % (`alice29.txt` default 51 467 → 51 536 B); interop fixtures re-blessed by the reference (294 checks, 0 mismatches). No API change.

- **2026-10-14** — Survey refreshed against google/brotli 1.2.0, RFC 9841 and RFC 9842: `## Compared with` updated, gaps R1–R11 filed in *Backlog* (streaming encoder, raw prefix dictionaries and `dcb`, large window, pull reader, serialized dictionaries for decoding, a q11-class `.max` effort). Docs only.

- **2026-10-11** — New `decompressInto(gpa, out, input, options)`: decode into the caller's buffer
  (`OutputTooLarge` when it does not fit), no output allocation. The differential fuzz driver checks it
  against the other two decoders, with an exact-size buffer and one byte short. Bench: `d_<payload>`
  now pairs it with the reference's preallocated-buffer decode (1.03–1.15×). The allocating
  `decompress` is printed as `d_<payload>_alloc`, for information only.

- **2026-10-11** — Decompression faster again (vs google/brotli: 1.49–1.78× → 1.12–1.28×): short
  back-references are 16/32-byte moves into slack the output keeps instead of `memcpy` calls, the
  bit reader refills only when short of bits, and code tables are built with `@bitReverse`. No API
  change.

- **2026-10-11** — Speed (bench vs google/brotli 1.2.0: 1.41–3.38× → 1.04–1.88×, P3). Decoder:
  two-level prefix tables (8-bit root), an 8-byte bit-reader refill, `memcpy` back-references, one
  output reserve per insert and one growth per meta-block. Encoder: the single-literal-code
  alternative of a block is written to a scratch writer instead of re-writing the winner (output
  byte-identical), the bit writer flushes 32 bits at a time, the match finder no longer clears its
  `prev` chain and fills `head` in vector stores (Zig 0.16's `memset` is byte-wise without libc), and
  match lengths are compared 8 bytes at a time. No API change.

- **2026-10-10** — Comparative benchmark `tools/bench.zig` (`zig build bench-brotli`): **1.41–3.38× google/brotli** — over 2×, P4. Card stays `not measured` with the numbers in *Backlog* until the module is sped up (owner 2026-10-10: a consumed module must grade 3 or better). Tooling only, no code change.

- **2026-10-04** — Builds for 32-bit and Windows: `meta.targets` is now linux64, linux32 (mips32,
  big-endian, soft-float) and windows. Window and table-size exponents are `u5` (a 32-bit `usize`
  shifts by a `u5`; they never exceed 24), and the interop corpus generator took its remainder in
  `usize`, so a 32-bit target generated different input than the reference judged. The whole
  suite passes on big-endian mips32 under qemu-mips. No change on 64-bit.

- **2026-10-04** — Fix (BEHAVIOURAL): a meta-block whose commands produced more than MLEN bytes
  (an insert, a copy or a dictionary word running past the declared length) was accepted and
  decoded to more bytes than MLEN. RFC 7932 section 9.2 requires exactly MLEN; the reference decoder
  rejects such streams, and `decompress`/`decompressStream` now fail with `InvalidLength`. Malformed
  streams that used to decode now fail; valid streams are unaffected. Found by the mutation run below.
- **2026-10-04** — Tests: dated mutation run (132 switches, 110 killed, 22 equivalent; see SPEC).
  New `src/crafted_test.zig` (hand-built RFC 7932 streams, cross-checked with the python reference
  decoder: metadata blocks, header guards, simple/complex prefix-code bounds, block-type switching,
  trivial-literal detection, dictionary and transform limits, window edge 1008/1009, MLEN overshoot,
  ring wrap in the streaming decoder, read-ahead contract), `transformWord` semantics tests
  (UPPERCASE_FIRST/ALL, OMIT_FIRST/LAST 1..9), a WBITS table test, and a `buildComplex` completeness test.

- **2026-09-30** — **Encoder: effort levels and a stronger encoder** (maturity task C19, second half).
  New `compressWith(gpa, input, .{ .effort = .fast | .default | .best })`, `CompressOptions`, `Effort`;
  `compress` = `.default`. Matches are scored by the bits they save (the block's literal entropy
  against the distance's cost) rather than by length, and reach 65 535 bytes (was 512); distance
  short codes and implicit-distance commands mirror the decoder's ring of recent distances; literal
  context modelling (UTF8/LSB6, clustered to ≤ 16 codes, checked on real bits against one code) at
  `.default` and `.best`. `alice29.txt`: 54 605 → 51 467 (default) / 50 736 (best) bytes, reference
  q5 52 809, q9 51 054; `zeros` 651 → 27. ⚠ `compress` output bytes change (still valid `br`,
  re-blessed by google/brotli): the interop fixture now blesses every shape at all three efforts
  (135 streams, `interop_blessed.zig` gains an `effort` field).

- **2026-09-30** — **Streaming decoder: `decompressStream(gpa, reader, writer, options)`** (maturity
  task C19, first half). Memory is the window — grown from 64 KiB only as far as the output needs —
  never the whole output; output reaches the writer at every meta-block end. The one-shot and the
  streaming decoder share one decoding core (`DecoderOf(Sink)`) and one bit reader, and a new
  deterministic differential fuzz driver (`BROTLI_FUZZ`) holds them to the same verdict on damaged
  streams. Also, for both: per-meta-block tables are freed at every meta-block instead of at the end
  (a long stream's tables no longer accumulate). New `StreamError`; `decompress`'s behaviour is
  unchanged (all interop replays pass as before).

- **2026-09-09** — The nine source files without an SPDX header have one: MIT, matching the
  two that already did. 229 of 231 modules carry the header on `root.zig`, and this was one
  of the two that did not — awkwardly, the module that carries an attribution CONDITION for
  its vendored `src/testdata/` corpus. The condition is unchanged and still lives in NOTICE;
  what changed is that each source file now states its own terms.

- **2026-09-07** — Fuzz reach: `fuzzDecompress` decompressed the EMPTY SLICE and nothing
  else, ever. The fourteen google/brotli reference streams were `@embedFile`d into
  `fuzz_seed_corpus` and indexed with `smith.index(...)` — but the array was **never
  handed to `std.testing.fuzz` as a `.corpus`**, so outside `--fuzz` the target ran the
  one input a corpus-less target gets: the empty one, whose every draw collapses to a
  minimum. Traced 2026-09-07: `index(14)` → 0 (`empty.compressed`, 1 octet),
  `boolWeighted(1, 4)` → false, `valueRangeAtMost(u16, 0, 1)` → 0, so `keep` = 0, no
  extension, no point damage, `decompress(allocator, buf[0..0], …)`. The keep/extend/
  damage generator and its two paragraphs of measured design justification never ran in
  the ordinary lane at all; the `@panic`-probe reachability claim was made under `--fuzz`
  and says nothing about it. The generator is gone and the reference streams are now the
  corpus they were always meant to be — a fuzzer handed real streams mutates them, which
  is what the generator was approximating. ⚠ The buffer was also 1024 octets while three
  of this module's own reference streams are 10 004, 50 096 and 50 100, so the largest
  inputs it owns could not have passed through its own harness even with the corpus wired
  up; the buffer is now 51 200 and those three are in the corpus. A corpus guard pins
  19 non-empty seeds, 18 decoded, 2 refused and **981 867 output octets** (0 before).

- **2026-09-06** — **The module no longer ships foreign source, and its test suite no
  longer needs `python3`.** `src/reference_interop.zig` — which embedded a Python
  driver and spawned `python3 -c` from inside `test-brotli` — is gone. The live
  comparison against the reference implementation (google/brotli via the Python
  `brotli` C extension) is now a standalone program, `tools/interop.zig` +
  `tools/reference.py`, run by `zig build interop-brotli` and compile-checked by
  `zig build check-interop`; it is never built by `test-brotli` and never by
  `zig build`. Consumer-visible: `zig build test-brotli` runs 53 tests with **no
  skips** where it previously ran 54 with 4 skipped on any machine without the
  package (i.e. all of CI). `zig build interop-brotli -- --capture` freezes what the
  reference did into two committed fixtures: `src/testdata/ref/*.br`, 24 streams the
  reference compressed (five qualities on `alice29.txt` as before, plus three window
  sizes and q1/q11 over the rest of the corpus — decoder coverage rises from 5 cases
  to 24), and `src/testdata/interop_blessed.zig`, which pins the SHA-256 of the exact
  stream google/brotli accepted for each of the 45 input shapes the sweep covers. An
  encoder change that alters any output now fails `test-brotli` until it is re-blessed
  against a real google/brotli. New `src/interop_corpus.zig` holds the shapes and the
  stream matrix both sides share, exposed as `brotli.interop_corpus` solely so the
  out-of-tree program can reach them; it is not part of the compression API. See
  `NOTICE` for the attribution the new `src/testdata/ref/` files carry.
- **2026-08-06** — Security audit: four findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against RFC 7932 Appendix A's
  published test vectors.
- **2026-07-29** — The encoder now actually compresses. It was store-mode only (ratio
  ~1.0); it now does LZ77 backward references plus a per-meta-block
  Huffman code for literals, insert-and-copy commands and distances, with
  the store path kept as an automatic per-block fallback whenever a
  compressed block would not come out smaller. `alice29.txt`
  152 089 -> 54 605 bytes (2.8x), between reference `brotli` quality 1 and
  5; incompressible input costs the same as it does the reference.
  `compress` keeps its signature and its "fails only on allocation,
  output is always a valid `br` body" guarantee. Not implemented (each
  costing ratio): block splitting, literal context modelling,
  static-dictionary references, `NPOSTFIX`/`NDIRECT` tuning, and distance
  short codes. Validation is anchored on the reference implementation
  rather than on this module's own decoder: `src/reference_interop.zig`
  decompresses everything the encoder emits with google/brotli (Python
  `brotli`) across a property sweep of input shapes, and skips loudly
  when python3 or the package is missing.
