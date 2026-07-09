# csvstream — spec

Streaming RFC 4180 CSV reader that preserves byte offsets. Usage: see ./README.md.
Attribution/provenance: see /NOTICE.

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
  protects the delimiter within a line.
- **Borrow contract:** `StreamReader.next()`'s returned `rec.bytes` is valid only until the next
  `next()` call that advances into a new chunk — callers must copy out anything retained past that.
- Reentrant, no shared state, std-only (no C/libc).

## Threat model / out of scope
Not a security boundary — a codec for cooperative/trusted input. Resource bound: bounded memory via
chunked reads (peak = chunk size), so an arbitrarily large file cannot exhaust memory just by being
long; a single pathologically long *line* (no `\n` for the whole chunk window) is the one case not
independently bounded beyond the chunk buffer sizing the caller picks. Failure mode for malformed
quoting is a flagged field (`unbalanced_quote`), never a hang or OOB read.

## Verification
`zig build test-csvstream` (headless; Debug + ReleaseFast). 29 tests: `line.zig` carries 22 verbatim
oracle tests ported from the bxp-core seed; `stream.zig` has 6 file/streaming + integration tests
(offsets index the exact source bytes across a multi-chunk file; a positional re-read proves
seek-back); `root.zig` is a dark-tests aggregator (`test { _ = line; _ = stream; }`) so both
submodules' tests run under a bare re-export.

## Backlog / deferred
From README "Deferred (not implemented in v1)": configurable delimiter at the `StreamReader` level
(currently only the quote char is a stream option; delimiter is caller-split) and a distinct
quote-vs-escape char (RFC 4180 reuses the same char; some dialects use `\`); header-row handling (no
built-in capture/name→index map — left to callers, e.g. bxp's `parseCsvHeader` stayed in bxp as app
policy); typed field coercion (fields stay `[]const u8`, no schema); CSV writing (read-only; RFC
4180 quoting-on-output lives with the sibling `csvsafe` injection guard, not general writing); BOM
handling (not detected/stripped); strict RFC 4180 opt-in mode (multi-line quoted fields spanning
`\n`, trailing-delimiter → final empty field — both currently deviate by design); field-count
validation (no per-record arity check against a header/first row).

## Status
`extract · any · codec · reentrant` + deps: none (std only) — canonical source is `pub const meta`
in src/root.zig.
