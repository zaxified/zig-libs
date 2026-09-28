# diagnostics — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-28** — Rendering, JSON and ordering (requested by ttydesk; previously listed as
  deferred): `Diagnostic.file` (optional, defaults to null — no existing literal breaks);
  `renderOne` / `Diagnostics.render` with `RenderOptions{ .style = .short | .snippet, .sources }`
  (compiler-style one line, or rustc-style with the quoted source line and carets; control
  characters from the input are escaped); `writeJsonSlice` / `Diagnostics.writeJson`;
  `Diagnostics.sortByPosition` (stable).
- **2026-07-18** — Security audit: no findings.
- **2026-07-09** — New module: LSP-style structured validation-finding collector —
  severity, dot-path, position, code, suggestion.
