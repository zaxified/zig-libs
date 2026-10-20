# diagnostics

LSP-style structured validation-finding collector — `error` / `warning` /
`info` findings with a dot-separated tree path, optional 1-based source
line/col (+ end position), an optional in-expression byte offset/length for
token highlighting, a machine-readable code, a message, and an optional
did-you-mean suggestion.

- The structured-finding collector for
  config/json5/expr validation.
- **Model after:** LSP `Diagnostic` / rustc diagnostics.
- **Platform:** any. **Role:** util. **Concurrency:** reentrant (no shared
  state — safe if not shared). **Allocation:** owned by the caller-supplied
  allocator; no internal ownership beyond the `items` list.

Provenance: original work of the zig-libs authors (MIT), except the snippet
layout, ported from codespan-reporting 0.13.1 (Apache-2.0), and its vendored
test snapshots — see NOTICE.

## API

```zig
const diagnostics = @import("diagnostics");

var diag: diagnostics.Diagnostics = .init(allocator);
defer diag.deinit();

try diag.append(.{
    .path = "conversion_templates.x.unknown_key",
    .line = 12,
    .col = 5,
    .severity = .warning,
    .code = "config.unknown_key",
    .message = "unknown key 'unknown_key'",
    .suggest = "did you mean 'file_pattern_in'?",
});

_ = diag.count();                        // total findings
_ = diag.countBySeverity(.@"error");     // e.g. gate saving on zero errors
```

All strings referenced by an appended `Diagnostic` are expected to outlive
the `Diagnostics` collector — typically both live in the same arena, freed in
one shot at the validation boundary. Dupe strings first if they need to
outlive that arena.

### Rendering, JSON, order

```zig
diag.sortByPosition(); // file, line, col; unknowns last; stable

// One line per finding, compiler style:
// export.json5:3:3: warning[config.unknown_key]: unknown key 'file_patern_in' (at a.b); did you mean 'file_pattern_in'?
try diag.render(w, .{});

// rustc style, quoting the source line with carets under the span:
try diag.render(w, .{ .style = .snippet, .sources = &.{.{ .file = "export.json5", .text = text }} });

try diag.writeJson(w); // [{"path":…,"file":…,"line":3,…,"severity":"warning",…}], nulls omitted
```

`Diagnostic.file` names the source a finding is in. `line`/`col` are 1-based
(`col` in bytes), `end_line`/`end_col` end the span exclusively, as in LSP.
The renderer escapes control characters in everything it prints (a key name
carrying an ANSI escape sequence reaches the terminal as `\x1b`), so a
`short` finding is always one line. Carets line up across tabs and multi-byte
UTF-8; double-width characters are not accounted for.

### Labels, notes, fix-its, colour (2026-10-04)

```zig
try diag.append(.{
    .path = "a", .file = "c.json5", .line = 4, .col = 3, .end_line = 4, .end_col = 4,
    .severity = .@"error", .code = "json5.duplicate_key", .message = "duplicate key 'a'",
    .labels = &.{.{ .line = 2, .col = 3, .end_line = 2, .end_col = 4, .message = "first defined here" }},
    .notes = &.{.{ .kind = .note, .message = "the later value would silently win" }},
    .fix = .{ .line = 4, .col = 3, .end_line = 4, .end_col = 4, .replacement = "c" },
    .code_url = "https://example.invalid/json5/duplicate_key",
});
try diag.render(w, .{ .style = .snippet, .sources = &src, .color = true }); // colour: caller decides (isatty, NO_COLOR)
```

```
error[json5.duplicate_key]: duplicate key 'a'
  --> c.json5:4:3
  |
2 |   a: 1,
  |   - first defined here
3 |   b: 2,
4 |   a: 3,
  |   ^
  |
  = note: the later value would silently win
  = at: a
  = fix: replace c.json5:4:3..4:4 with "c"
  = see: https://example.invalid/json5/duplicate_key

```

All four fields are optional and omitted from JSON when unset, so existing
output is byte-identical. Colour wraps only this module's own text; anything
taken from a finding is escaped the same way with colour on.

### Snippet layout (codespan-reporting 0.13.1)

The `snippet` style is the layout of codespan-reporting's "rich" style, ASCII
charset (the layout code is ported from it, Apache-2.0; see `tools/codespan-goldens/README.md`
for the version, the replayed upstream test cases and the known deviations):
labels on one line share the quoted line with carets, a trailing message and
hanging messages; a span over several lines is drawn with `/ |` and `\` markers
in a gutter, long ones with a `.` where lines are left out.

```zig
// The message next to the primary span, a second primary, a multi-line span:
try diag.append(.{
    .path = "", .file = "f.fun", .line = 8, .col = 12, .end_line = 8, .end_col = 15,
    .span_message = "expected `String`, found `Nat`",
    .severity = .@"error", .code = "E0308", .message = "`case` clauses have incompatible types",
    .labels = &.{
        .{ .line = 4, .col = 15, .end_line = 8, .end_col = 15, .message = "`case` clauses have incompatible types" },
        .{ .line = 3, .col = 17, .end_line = 3, .end_col = 23, .message = "expected type `String` found here" },
    },
    .notes = &.{.{ .kind = .plain, .message = "expected type `String`\n   found type `Nat`" }},
});
try diag.render(w, .{ .style = .snippet, .sources = &src, .tab_width = 4 });
```

`NoteKind.plain` is codespan's note (`= text`, a `\n` starts an aligned
continuation line); `Label.primary` draws a label as a second primary span.
No allocation: at most 64 spans and 16 multi-line spans per file are drawn,
the rest is listed as `--> location: message` lines.
