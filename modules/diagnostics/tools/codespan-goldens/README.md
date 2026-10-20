# codespan-goldens

Evidence for the `snippet` renderer of `diagnostics`: the test cases and the expected output of
[brendanzab/codespan](https://github.com/brendanzab/codespan) `codespan-reporting` **0.13.1**
("rich" style, no colour; ASCII and box-drawing charsets), replayed byte for byte.

- **Upstream commit (everything below comes from this one):** `decb0a0727e45bf2f04dcd3e4b4deb9517349fdc`
  ("Release: codespan to 0.13.1, codespan-reporting to 0.13.1 ...", 2025-10-22). Licence: Apache-2.0.
- `term.rs` — upstream `codespan-reporting/tests/term.rs`, unmodified. The inputs of the cases (file texts,
  byte ranges, messages) are transcribed from it into `src/codespan_test.zig`.
- `snapshots/*.snap` — upstream `codespan-reporting/tests/snapshots/term__<case>__rich_no_color.snap` (box
  drawing, `Chars::box_drawing()`, all 16 cases) and `…__rich_ascii_no_color.snap` (ASCII, 12 cases), insta
  files, unmodified. Four cases (`multiline_omit`, `unicode`, `unicode_spans`, `surrounding_lines`) have no ASCII
  snapshot upstream; their box-drawing one is mapped to ASCII by `gen.py` character by character (`┌─`→`-->`,
  `│`→`|`, `·`→`.`, `╭`→`/`, `╰`→`\`, `─`→`-`, the table is `Chars::box_drawing()` → `Chars::ascii()` of
  upstream `config.rs`).
- `gen.py` — turns the snapshots into `src/codespan_vectors.zig` (generated, do not edit).

## Refresh

```
python3 -I modules/diagnostics/tools/codespan-goldens/gen.py
zig fmt modules/diagnostics/src/codespan_vectors.zig
scripts/modtest diagnostics
```

To move to a newer upstream: pick ONE commit, fetch `term.rs` and the `.snap` files from it
(`gh api repos/brendanzab/codespan/contents/codespan-reporting/tests/term.rs?ref=<commit>`), re-transcribe
changed inputs into `src/codespan_test.zig`, update the commit here and in the file headers.

## What is ported

The layout code in `src/root.zig` (section "snippet layout") is a port of codespan-reporting 0.13.1:

| Upstream file | What |
|---|---|
| `src/term/views.rs` | `RichDiagnostic::render`: lines shown (`start_context_lines`/`end_context_lines`), single-line labels sorted by range, multi-line columns, the locus, gaps between shown lines, border/notes/empty line |
| `src/term/renderer.rs` | `render_snippet_source/empty/break/note`, `caret_pointers`, multi-line label pieces, `char_metrics` |
| `src/term/config.rs` | `Chars::ascii()`, `Chars::box_drawing()` |

Also in `src/root.zig`, from other projects (MIT OR Apache-2.0): per-character display widths from
unicode-rs/unicode-width 0.2.2 (`src/tables.rs`, via `tools/unicode-width/gen.py` into `src/width_table.zig`;
codespan uses the same crate) and the `term_width` cut from rust-lang/annotate-snippets-rs 0.12.17
(`src/renderer/margin.rs`, the `Margin::new` call and `draw_line` of `src/renderer/graphics.rs`).

Not ported: colour themes (the module colours its own parts only), the `medium`/`short` display styles
(`RenderStyle.short` is the module's own one-line format).

## How a case is compared

Our `Diagnostic` has no "primary label with a message" and no `bug`/`note`/`help` severity, so each upstream
diagnostic is mapped (`convert` in `src/codespan_test.zig`): the first primary label becomes the diagnostic's
span (its message `span_message`), other labels become `labels` (`primary` set), notes become
`NoteKind.plain`, severities `bug`/`error` → `error`, `warning` → `warning`, `note`/`help` → `info`.
The expected text gets the same rewrite of the header word (`bug:`→`error:`, `note:`/`help:`→`info:`), and
trailing newlines are ignored (insta trims them). Nothing else is normalised. Every case is rendered twice,
`.chars = .ascii` against the ASCII text and `.chars = .unicode` against the box-drawing snapshot, with
`.column = .char` (upstream prints character columns in the `-->` line).

## Cases

All 16 cases are **identical** in both charsets (ASCII and box drawing); no deviations.

| Case | ASCII | Box | Notes |
|---|---|---|---|
| empty | identical | identical | (severity words mapped) |
| empty_ranges | identical | identical |  |
| message | identical | identical | (severity words mapped) |
| message_and_notes | identical | identical | (severity words mapped) |
| message_errorcode | identical | identical | (severity words mapped) |
| same_line | identical | identical |  |
| same_ranges | identical | identical |  |
| overlapping | identical | identical | two primaries in one diagnostic, labels in three files |
| multifile | identical | identical | multi-byte characters in the quoted lines |
| fizz_buzz | identical | identical | multi-line spans, subscript digits (one column each) |
| multiline_overlapping | identical | identical | overlapping multi-line spans, a secondary label before the primary one |
| position_indicator | identical | identical |  |
| multiline_omit | identical | identical | a tab inside a note is passed through |
| unicode | identical | identical | R5: `路濫狼` two columns each, combining accents zero (`charWidth`) |
| unicode_spans | identical | identical | R5: emoji two columns; ranges that start/end inside a code point (the `-->` column is the character column before the byte, `.column = .char`) |
| surrounding_lines | identical | identical | `before_label_lines = 2`, `after_label_lines = 1` |

Not replayed at all: `tab_columns`, `tabbed` (tab handling is ported, the cases are not transcribed), the
`medium`/`short`/colour snapshots (styles not implemented).

## Known differences that no case shows

- The position in the `-->` line is the `line`/`col` given in the `Diagnostic` (bytes) unless
  `RenderOptions.column = .char` (the replay uses it; upstream prints a character column).
- Controls (C0, C1, DEL), U+2028/U+2029 and invalid UTF-8 bytes in the quoted source are shown as `?` (one
  column; upstream prints them raw, and gives controls no width), U+FEFF is not written.
- Colour: only marks, gutters and the header are coloured, labels' messages are not.
- Control characters in the quoted source are shown as `?`, in messages as `\xNN` escapes (upstream prints
  them raw); a tab in a `plain` note is the only control character let through.
- Memory: no allocation; at most 64 spans per diagnostic and 16 multi-line spans per file are drawn, any
  further span is listed as a `--> location: message` line (tested in `bounds: ...`).
