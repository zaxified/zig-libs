# diagnostics — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-23** — independent review of the 10-20 rewrite: `fromLsp` decoded `%+f` in a related-information
  URI as a byte (`parseInt` takes a sign) — now exactly two hex digits; tests pin that `writeLsp`/`writeJson`
  stay valid UTF-8 JSON for invalid finding text; trailing-CR handling documented as codespan's. Two LOW
  layout/LSP inconsistencies to Backlog.

- **2026-10-23** — **SECURITY (terminal output, LOW–MED):** the bidirectional controls U+202A–U+202E and
  U+2066–U+2069 ("Trojan Source", CVE-2021-42574) went to the terminal unchanged, in the quoted line and in
  finding text, and finding text also passed C1 controls (U+0080–U+009F), U+2028/U+2029 and bytes that are
  not UTF-8 (a lone 0x9B is an 8-bit CSI). The quoted line now shows them as `?`; finding text writes
  `\u{NNNN}` / `\xNN`. codespan-reporting 0.13.1 writes all of these raw (probe through the interop
  oracle); rustc/annotate-snippets replace the bidi set.

- **2026-10-23** — **FIX:** a multi-line span starting after Unicode whitespace other than space/tab
  (U+3000, U+00A0, U+2000–U+200A …) was drawn with a `/----^` top row instead of the corner at the line
  start; `leadingSpace` now counts Unicode White_Space as codespan's `str::trim_start` does. Found by the
  new differential fuzz `zig build interop-diagnostics` (`tools/interop.zig` + an oracle binary in
  `tools/codespan_bench`): 20 000 random cases against codespan-reporting 0.13.1, 39 862 renders
  byte-identical. **Card: Evidence model → model-fuzz (E1).**

- **2026-10-20** — `zig build bench-diagnostics` (`tools/bench.zig` + `tools/codespan_bench`, Rust, pinned
  codespan-reporting 0.13.1 and annotate-snippets 0.12.17): 0.42–0.60× codespan. Info row: with `term_width`
  on a 100 KB line we are ~3× annotate (our cut path still walks the whole line — a Backlog item). Card:
  grade 3 → 2 (scope parity, P2).
- **2026-10-20** — Display width, line endings, terminal width, charsets, context (S2 R5/R6/R7/R9/R10).
  `charWidth` from a table generated from unicode-width 0.2.2 (CJK/emoji 2, combining 0); carets and
  columns use it. Lines end at `\n`/`\r\n` only; lone CR, U+2028/9, C0/C1/DEL and invalid UTF-8 render as
  `?` — **a C1 control (e.g. U+009B, an escape in some terminals) was written raw before**; a BOM takes no
  column. `RenderOptions.term_width` cuts long lines around the span like annotate-snippets 0.12;
  `chars = .unicode` (codespan box drawing); `before_label_lines`/`after_label_lines`; `column = .char`
  (codespan's character column; default stays `.byte`). All 16 codespan snapshots now byte-identical in
  both charsets. Ports: annotate-snippets, unicode-width (MIT option) — NOTICE.
- **2026-10-20** — LSP 3.17 both ways (S2 R3) and a `hint` severity (S2 R8, owner OK).
  `writeLsp`/`writeLspArray` (range, severity 1..4, code, codeDescription, source, tags,
  relatedInformation from labels; `LspOptions.uri_prefix`), `fromLsp`; `lspCharacter`/`byteColumn` convert
  1-based byte columns to 0-based utf8/utf16/utf32 characters and back. New `Tag`, `Diagnostic.tags`.
  **Source-breaking:** `Severity` gains `hint` — an exhaustive `switch` needs an arm (bxp at repin).
  `expr_off`/`expr_len` doc corrected: renderers ignore them.
- **2026-10-20** — **Snippet layout = codespan-reporting 0.13.1's rich ASCII style** (S2 R1/R2; ported,
  Apache-2.0, NOTICE): several labels on one line share the quoted line, sorted; multi-line spans get
  start/end markers, overlapping ones included; gaps become `.` break rows; tabs expand (`tab_width`,
  default 4); `start_context_lines`/`end_context_lines`. Evidence: 13 of codespan's 16 snapshots
  replayed byte-identically (3 listed deviations). **Behaviour change for `.snippet` output** (the
  `short` style and the JSON output are unchanged): ` --> ` gains a leading space, a `|` border row and a
  blank line end each diagnostic, a secondary label no longer gets its own `:::` block, notes precede
  `= at:`. New, additive: `Diagnostic.span_message`, `Label.primary`, `NoteKind.plain` (source-breaking
  only for an exhaustive switch over `NoteKind`), the three render options. Rendering stays
  allocation-free (≤ 64 spans, ≤ 16 multi-line spans per file; the rest become location lines).
- **2026-10-20** — `Source.line_starts` + `Source.indexLines(gpa, text)` (S2 R4): a caller-built line
  index makes each quoted line O(1) instead of a scan from the top of the file per label (N diagnostics
  over a large file were O(N·F)); without it the scan is memchr per line instead of a splitting
  iterator. Render stays allocation-free. Additive (a new defaulted field).
- **2026-10-04** — **mvp → core.** `Diagnostic` gains optional `labels` (`Label`: secondary spans with a
  message, other files allowed), `notes` (`Note`, `NoteKind` note/help), `code_url` and `fix` (`Fix`: replace or
  insert); `snippet` quotes labels under ` ::: ` with `-` marks, `short` appends everything to the one line;
  `RenderOptions.color` (ANSI, off by default; finding text stays escaped). All new fields are null by default
  and omitted from JSON, so existing output is byte-identical. Mutation 13 mutants, 0 surviving. `hint`
  severity deliberately deferred (it would break bxp's exhaustive switches).

- **2026-09-28** — Rendering, JSON and ordering (requested by ttydesk; previously listed as
  deferred): `Diagnostic.file` (optional, defaults to null — no existing literal breaks);
  `renderOne` / `Diagnostics.render` with `RenderOptions{ .style = .short | .snippet, .sources }`
  (compiler-style one line, or rustc-style with the quoted source line and carets; control
  characters from the input are escaped); `writeJsonSlice` / `Diagnostics.writeJson`;
  `Diagnostics.sortByPosition` (stable).
- **2026-07-18** — Security audit: no findings.
- **2026-07-09** — New module: LSP-style structured validation-finding collector —
  severity, dot-path, position, code, suggestion.
