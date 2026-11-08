# jsontext

Small, dependency-free **JSON text helpers**: write arbitrary bytes as a JSON string
literal (RFC 8259 §7) with an explicit policy for ill-formed UTF-8, and check the
bracket nesting of a buffer before a parser allocates for it.

```zig
const jsontext = @import("jsontext");

// default options: ill-formed UTF-8 becomes U+FFFD
try jsontext.writeString(w, user_agent, .{});

// pure ASCII output, safe inside an HTML <script> element
try jsontext.writeString(w, title, .{ .ascii_only = true, .html_safe = true });

// refuse bytes that are not UTF-8
jsontext.writeString(w, name, .{ .invalid_utf8 = .reject }) catch |e| switch (e) {
    error.InvalidUtf8 => return error.BadName,
    error.WriteFailed => return error.WriteFailed,
};

// cap nesting before std.json sees a hostile document (does not validate)
if (!jsontext.depthWithin(body, 64)) return error.TooDeep;
```

`StringOptions` are `comptime`: `.invalid_utf8` (`replace` | `escape_bytes` |
`reject`), `.ascii_only`, `.html_safe`. `writeStringContents` is the same without
the quotes. See `SPEC.md` for what is deliberately not done and how the values are
anchored.

Status: extract (the escaper is `accesslog`'s, `depthWithin` is `framing`'s).
Model-after: Go `encoding/json`, Rust `serde_json`, CPython `json`.
`zig build test-jsontext`.

DATA: no data files, vectors or third-party code; every test value is written in the source.

Provenance: clean-room — own code, moved from `modules/accesslog` (escaper and UTF-8 classifier) and `modules/framing` (`jsonDepthWithin`); the behaviour of the three reference libraries is taken from their documentation only.
