# csvstream — spec

Streaming RFC 4180 CSV reader that preserves byte offsets. Usage: see ./README.md.
Attribution/provenance: the codec itself is clean-room original work (root `NOTICE` §0 — no
entry needed for that). The conformance test suite separately vendors the third-party
`maxogden/csv-spectrum` fixture corpus (test data only) — see this module's own `NOTICE`,
listed in root `NOTICE` §1.

## Design & invariants
- **Two layers, one record model:** both emit `LineSlice { bytes, byte_offset, unbalanced_quote }`.
  In-memory `LineIterator`/`splitFields` (standalone, caller already holds the bytes) and streaming
  `StreamReader` (file → chunks → records, bounded memory — peak is chunk size, not file size).
  `StreamReader` composes a record-aligned `ChunkReader` (file → chunks, each ending on the chunk's
  last `\n`) with a per-chunk `LineIterator`; because every chunk ends on `\n`, no record spans a
  chunk boundary, so offsets compose cleanly across chunks.
- **Deliberate RFC 4180 deviation:** a `\n` always ends a record — quoted fields may not span
  physical lines (à la Go `encoding/csv` LazyQuotes). This turns a stray/unbalanced quote into a
  one-line problem (`LineSlice.unbalanced_quote`) instead of swallowing the rest of the file, and is
  exactly what makes every `\n` a safe chunk boundary for bounded-memory streaming. Quoting still
  protects the delimiter within a line. **Consequence for the writer:** `writeRecord` can correctly
  emit a valid RFC 4180 multi-line quoted field (embedded `\n`/`\r`), but this module's OWN reader
  cannot re-parse it back into one record — that asymmetry is permanent unless the strict-mode item
  below is ever built.
- **Borrow contract:** `StreamReader.next()`'s returned `rec.bytes` is valid only until the next
  `next()` call that advances into a new chunk — callers must copy out anything retained past that.
- **Writing is a separate, independent concern from reading:** `writeField`/`writeRecord`
  (writer.zig) are stateless, streaming to any `*std.Io.Writer`, and quote a field only when it
  actually contains the delimiter/quote/CR/LF. `csvsafe` was evaluated as a potential source for the
  quoting primitive; its own SPEC explicitly defers RFC 4180 quoting to "the CSV writer or
  csvstream" (see modules/csvsafe/SPEC.md "Threat model / out of scope"), so there was nothing to
  reuse — the quoting logic here is original, std-only, no new module dependency.
- **`StreamReader.nextFields`** composes `next()` + `splitFields` using the reader's own configured
  `delimiter`/`quote` (`Options.delimiter`, new), so a caller that wants split fields (not just raw
  record bytes) no longer repeats the delimiter at every call site. `next()` itself is unchanged and
  still delimiter-agnostic.
- **BOM handling:** `StreamReader.next()` detects and strips a leading UTF-8 BOM (`utf8_bom`) on the
  very first chunk only; the first record's `byte_offset` starts right after the BOM, not at 0. The
  standalone `stripBom` helper covers in-memory callers driving `LineIterator` directly.
- **Header/coercion/arity are opt-in helpers, not reader integration:** `Header.init` captures an
  already-split row's fields into owned name→index bookkeeping; `parseInt`/`parseFloat`/`parseBool`
  (coerce.zig) are thin explicit wrappers with no trimming (fields stay verbatim, per the existing
  "spaces are preserved" splitFields test); `Header.validateArity`/`validateArity` are a plain
  length check. None of this is wired automatically into `StreamReader` — reading/skipping a header
  row, coercing a column, and enforcing arity all remain app policy, same rationale as before.
- Reentrant, no shared state, std-only (no C/libc, no new module deps).

## Threat model / out of scope
Not a security boundary — a codec for cooperative/trusted input. Resource bound: bounded memory via
chunked reads (peak = chunk size), so an arbitrarily large file cannot exhaust memory just by being
long; a single pathologically long *line* (no `\n` for the whole chunk window) is the one case not
independently bounded beyond the chunk buffer sizing the caller picks. Failure mode for malformed
quoting is a flagged field (`unbalanced_quote`), never a hang or OOB read.

## Verification
`zig build test-csvstream` (headless; Debug + ReleaseFast). `line.zig` carries the
verbatim oracle tests + `stripBom` tests; `stream.zig` has file/streaming + integration tests
(offsets index the exact source bytes across a multi-chunk file; a positional re-read proves
seek-back) + BOM-strip and `nextFields`/delimiter tests; `writer.zig` covers RFC 4180 quoting
(delimiter/quote/CR/LF triggers, quote-doubling, custom delimiter/quote, `quote == 0` passthrough,
two positive controls that would fail if quoting/escaping were wrong) plus a file round-trip through
`StreamReader`; `header.zig` covers `Header` capture/lookup/arity (incl. a ragged short-row case);
`coerce.zig` covers `parseInt`/`parseFloat`/`parseBool` valid + invalid inputs. `root.zig` is a
dark-tests aggregator (`test { _ = line; _ = stream; _ = writer; _ = header; _ = coerce; }`) so all
submodules' tests run under a bare re-export.

`csv_spectrum_test.zig` + `csv_spectrum_vectors.zig` drive the vendored `maxogden/csv-spectrum`
corpus (12 fixtures) through `LineIterator`/`splitFields`, comparing field-by-field against the
corpus's own expected JSON (never against this module's own output) via an explicit
header→value adapter (built on `Header`, header.zig). A count canary (12 vendored / 4 out-of-scope)
fails loudly if the corpus is re-vendored without re-classifying a case. 8 fixtures are in scope and
assert equality; 4 are out of scope (still driven through the parser to prove no crash, but not
asserted) — see csv_spectrum_vectors.zig for the reason each is excluded.

## Backlog / deferred
From README "Deferred (not implemented in v1)", now trimmed to what's still actually deferred:

- **Distinct quote-vs-escape char.** RFC 4180 reuses the same char for both; some dialects (e.g.
  `\`-escaped) use a different one. Not implemented — would touch both `splitFields`/`LineIterator`
  and the new writer's escaping, and no concrete consumer has asked for a non-RFC dialect yet.
- **Strict RFC 4180 opt-in mode:** (a) multi-line quoted fields spanning `\n` and (b) a
  trailing-delimiter emitting a final empty field. Both still deviate by design (see the
  `splitFields` trailing-delimiter test and the lazy-quotes note above) — (a) in particular would
  force a real parser rewrite (the whole bounded-memory chunking design leans on "every `\n` is a
  safe record boundary"), so it stays deferred rather than being bolted on.

Implemented this round (previously listed here as deferred): configurable delimiter at the
`StreamReader` level (`Options.delimiter` + `nextFields`), BOM detection/stripping (`stripBom`,
automatic in `StreamReader.next`), header-row capture (`Header`), typed field coercion
(`parseInt`/`parseFloat`/`parseBool`), CSV writing (`writeField`/`writeRecord`, RFC 4180 quoting-on-
output), and field-count/arity validation (`Header.validateArity`/`validateArity`).

## Status
`extract · any · codec · reentrant` + deps: none (std only) — canonical source is `pub const meta`
in src/root.zig.
