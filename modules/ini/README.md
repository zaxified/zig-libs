# ini

An INI reader: `[section]` headers, `key = value` entries, comment lines — in
the dialects that matter in practice, with the Python `configparser` and
Desktop Entry (GLib `GKeyFile`) dialects checked against those implementations.

- **Status:** gap (built fresh; requested by a consumer that parsed Midnight
  Commander skins with a 30-line reader of its own).
- **Model after:** Python `configparser`, GLib `GKeyFile`, Go `gopkg.in/ini.v1`.
- **Platform:** any. **Role:** codec. **Concurrency:** reentrant.

## API

```zig
const ini = @import("ini");

var doc = try ini.parse(gpa, text, .{});   // or .python, .desktop, or your own Options
defer doc.deinit();

doc.get("core", "selected");               // ?[]const u8 -- last value wins, across repeated sections
try doc.getBool("server", "debug");        // ?bool -- 1/yes/true/on, 0/no/false/off
doc.hasSection("core");
var it = doc.entries("core");              // every entry in file order, repeats included
while (it.next()) |e| _ = .{ e.key, e.value, e.line };
doc.sections;                              // []const Section{ name, line, entries }

var info: ini.ErrorInfo = .{};
_ = ini.parseDiag(gpa, text, .{}, &info) catch |err| { _ = .{ err, info.line }; };

// Values are raw, as both references return them; resolve quoting yourself:
const s = try ini.unquote(gpa, raw);           // "..." with \\ \" \n \t \r, or '...' literal
const t = try ini.unescapeDesktop(gpa, raw);   // \s \n \t \r \\ (Desktop Entry spec)
```

`Options` knobs: `comment_chars` (`"#;"`), `inline_comments`, `separators`
(`"="`), `trim_values`, `continuation_lines`, `global_entries`,
`header_trailing_text`, `locale_keys`, `case_insensitive_sections` /
`case_insensitive_keys` (lookups only) and `strict` (off: bad lines are
skipped and listed in `Document.skipped`).

| Preset | Comments | Separators | Continuation | Before 1st section | Trailing blanks in value |
|---|---|---|---|---|---|
| `.{}` | `#` `;` | `=` | no | allowed (section `""`) | stripped |
| `.python` | `#` `;` | `=` `:` | indentation | error | stripped |
| `.desktop` | `#` | `=` | no | error | kept |

Every preset is strict. The `Document` owns copies of everything; the input
text can be freed right after `parse`.

## Not here

No writer, no `%(interpolation)s`, no `[DEFAULT]` inheritance, no git-config
subsections (`[remote "origin"]`), no backslash line continuation (PHP), no
typed getters beyond `getBool`. See `SPEC.md`.

Provenance: clean-room. The grammar is this module's own; CPython's
`configparser` (PSF) and GLib's `GKeyFile` (LGPL) were only run as black-box
oracles to capture the goldens (`tools/`), never read, so no `NOTICE` entry
is required (root [`NOTICE`](../../NOTICE) §0).
