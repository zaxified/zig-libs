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

Provenance: original work of the zig-libs authors (MIT) — no third-party
source copied.

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

## Deferred (not in v1)

- Rendering to a human-readable string (rustc-style caret/source-snippet
  output).
- JSON serialization of diagnostics.
- Sorting diagnostics by source position.
