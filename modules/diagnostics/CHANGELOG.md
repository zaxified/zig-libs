# diagnostics — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
