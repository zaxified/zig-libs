# ini

An INI reader and writer: `[section]` headers, `key = value` entries, comment
lines — in the dialects that matter in practice, with the Python `configparser`
and Desktop Entry (GLib `GKeyFile`) dialects checked against those
implementations. An edit of a user's file leaves every other byte of it alone.

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
const q = try ini.quote(gpa, s);               // and back: quote, escapeDesktop

// Typed readings. Absent is null, a wrong value is an error:
try doc.getInt(u16, "server", "port");         // Python's int(): base 10, 1_000
try doc.getFloat(f64, "server", "ratio");      // Python's float()
var l = (try doc.getList(gpa, "a", "k", .{})).?; // "a, b" (go-ini); .desktop = "a;b;" (GKeyFile)
defer l.deinit(gpa);
doc.getLocale("Desktop Entry", "Name", "cs_CZ.UTF-8");   // Name[cs_CZ], Name[cs], Name
doc.getInherited("a.b.c", "k", '.');           // [a.b.c], then [a.b], then [a]
const cfg = try doc.mapSection(struct { port: u16 = 80, name: []const u8 = "" }, "server");

// configparser on top of the raw values, each opt-in:
var cp = try ini.parse(gpa, text, .configparser);     // [DEFAULT], blank lines inside values
defer cp.deinit();
cp.get("section", "only_in_default");
const v = try cp.interpolated(gpa, "s", "k", .{});    // %(name)s; .style = .extended: ${s:name}
cp.firstDuplicate();                                  // what strict=True would refuse
var m = cp.merged("s");                               // each key once, defaults last
var names = cp.sectionNames();                        // without [DEFAULT]

// Edit a file: untouched lines come back byte for byte, comments and CRLF too.
var ed = try ini.Editor.init(gpa, text, .python);
defer ed.deinit();
try ed.set("server", "port", "8080");                 // keeps indentation, spacing, inline comment
try ed.set("new section", "key", "line1\nline2");
_ = try ed.remove("server", "debug");
_ = try ed.removeSection("old");
try ed.setComment("server", "port", "the port");
try ed.write(writer);                                 // error.NotRepresentable: refused, nothing changed

// Serialise a Document (order kept, comments gone); .merged = true is configparser.write:
try doc.write(gpa, writer, .{ .options = .python });

// Pull readers, no allocation; StreamScanner holds one line at a time:
var sc = ini.Scanner.init(text, .python);
while (sc.next()) |ev| switch (ev) {
    .section => |h| _ = h.name,
    .entry => |e| _ = .{ e.key, e.value },
    .continuation => |c| _ = c.text,
    .comment, .blank, .invalid => {},
};
var st = ini.StreamScanner.init(reader, .python);     // error.LineTooLong past the reader's buffer
```

`Options` knobs: `comment_chars` (`"#;"`), `inline_comments`, `separators`
(`"="`), `trim_values`, `continuation_lines`, `global_entries`,
`empty_lines_in_values`, `no_value_keys`, `header_trailing_text`, `locale_keys`,
`case_insensitive_sections` / `case_insensitive_keys` (lookups only),
`default_section` and `strict` (off: bad lines are skipped and listed in
`Document.skipped`).

| Preset | Comments | Separators | Continuation | Before 1st section | Trailing blanks in value |
|---|---|---|---|---|---|
| `.{}` | `#` `;` | `=` | no | allowed (section `""`) | stripped |
| `.python` | `#` `;` | `=` `:` | indentation | error | stripped |
| `.configparser` | `#` `;` | `=` `:` | indentation, across blank lines | error | stripped |
| `.desktop` | `#` | `=` | no | error | kept |

Every preset is strict. The `Document` owns copies of everything; the input
text can be freed right after `parse`.

## Not here

No git-config dialect (subsections as such, `include`), no backslash line
continuation or `"""` quoting (go-ini's), no multi-byte separators or comment
prefixes, no file I/O (the caller reads the text). Each with its reason in
`SPEC.md`, § Compared with.

Provenance: clean-room. The grammar is this module's own; CPython's
`configparser` (PSF) and GLib's `GKeyFile` (LGPL) were only run as black-box
oracles to capture the goldens (`tools/`), never read. go-ini (Apache-2.0) was
read for the survey and the benchmark, none of its code is here, so no `NOTICE`
entry is required (root [`NOTICE`](../../NOTICE) §0).
