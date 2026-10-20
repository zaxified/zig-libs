# codespan-goldens

Evidence for the `snippet` renderer of `diagnostics`: the test cases and the expected output of
[brendanzab/codespan](https://github.com/brendanzab/codespan) `codespan-reporting` **0.13.1**
("rich" style, ASCII charset, no colour), replayed byte for byte.

- **Upstream commit (everything below comes from this one):** `decb0a0727e45bf2f04dcd3e4b4deb9517349fdc`
  ("Release: codespan to 0.13.1, codespan-reporting to 0.13.1 ...", 2025-10-22). Licence: Apache-2.0.
- `term.rs` — upstream `codespan-reporting/tests/term.rs`, unmodified. The inputs of the cases (file texts,
  byte ranges, messages) are transcribed from it into `src/codespan_test.zig`.
- `snapshots/*.snap` — upstream `codespan-reporting/tests/snapshots/term__<case>__rich_ascii_no_color.snap`
  (insta files, unmodified). Four cases (`multiline_omit`, `unicode`, `unicode_spans`, `surrounding_lines`)
  have no ASCII snapshot upstream; their `…__rich_no_color.snap` (box drawing) is taken instead and mapped to
  ASCII by `gen.py` character by character (`┌─`→`-->`, `│`→`|`, `·`→`.`, `╭`→`/`, `╰`→`\`, `─`→`-`,
  the table is `Chars::box_drawing()` → `Chars::ascii()` of upstream `config.rs`).
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
| `src/term/renderer.rs` | `render_snippet_source/empty/break/note`, `caret_pointers`, multi-line label pieces |
| `src/term/config.rs` | `Chars::ascii()` |

Not ported: colour themes (the module colours its own parts only), `before_label_lines`/`after_label_lines`,
`medium`/`short` styles, Unicode box charset, Unicode display width (all backlog items, see SPEC).

## How a case is compared

Our `Diagnostic` has no "primary label with a message" and no `bug`/`note`/`help` severity, so each upstream
diagnostic is mapped (`convert` in `src/codespan_test.zig`): the first primary label becomes the diagnostic's
span (its message `span_message`), other labels become `labels` (`primary` set), notes become
`NoteKind.plain`, severities `bug`/`error` → `error`, `warning` → `warning`, `note`/`help` → `info`.
The expected text gets the same rewrite of the header word (`bug:`→`error:`, `note:`/`help:`→`info:`), and
trailing newlines are ignored (insta trims them). Nothing else is normalised.

## Cases

| Case | Result | Why |
|---|---|---|
| empty | identical | (severity words mapped) |
| empty_ranges | identical | |
| message | identical | (severity words mapped) |
| message_and_notes | identical | (severity words mapped) |
| message_errorcode | identical | (severity words mapped) |
| same_line | identical | |
| same_ranges | identical | |
| overlapping | identical | two primaries in one diagnostic, labels in three files |
| multifile | identical | multi-byte characters in the quoted lines; the `-->` column is a byte column, equal to upstream's character column because every label starts before the first multi-byte character of its line |
| fizz_buzz | identical | multi-line spans, subscript digits (one column each) |
| multiline_overlapping | identical | overlapping multi-line spans, a secondary label before the primary one |
| position_indicator | identical | |
| multiline_omit | identical | against the box-drawing snapshot mapped to ASCII; a tab inside a note is passed through |
| unicode | **deviation** | R5: upstream counts `路濫狼` as two columns each and the combining accents as zero; we count one column per code point, so the caret row is one `^` shorter |
| unicode_spans | **deviation** | R5 (emoji are two columns upstream); upstream also reports `1:1` for a byte range that starts inside a code point and draws the caret over the whole character, we print the byte column (`1:2`) and, where a column is split, differ in width |
| surrounding_lines | **deviation** | R10: `before_label_lines`/`after_label_lines` (context lines around labels) are not ported |

Deviation cases are still rendered by the test (no crash, bounded), just not compared. Not replayed at all:
`tab_columns`, `tabbed` (tab handling is ported, the cases are not transcribed), the `medium`/`short`/colour
snapshots (styles not implemented).

## Known differences that no case shows

- The position in the `-->` line is the `line`/`col` given in the `Diagnostic` (bytes), upstream prints a
  character column.
- Colour: only marks, gutters and the header are coloured, labels' messages are not.
- Control characters in the quoted source are shown as `?`, in messages as `\xNN` escapes (upstream prints
  them raw); a tab in a `plain` note is the only control character let through.
- Memory: no allocation; at most 64 spans per diagnostic and 16 multi-line spans per file are drawn, any
  further span is listed as a `--> location: message` line (tested in `bounds: ...`).
