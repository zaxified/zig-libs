# uci

Parser + serializer + typed model for the **OpenWRT UCI** (Unified
Configuration Interface) file format — `config` / `option` / `list`.

- **Status:** `gap` — no maintained pure-Zig UCI codec exists; this retires
  shelling out to the `uci` binary (axp).
- **Model after:** OpenWRT UCI file format / libuci.
- **Why:** axp manages OpenWRT-style device config; reading and writing UCI
  files natively removes an exec dependency and gives typed access + errors.
- **Platform:** any (pure text codec, no I/O).
  **Role:** codec. **Concurrency:** reentrant (no shared state).
  **Allocation:** model memory lives in an internal arena — one
  `Package.deinit(gpa)` frees everything.

Provenance: clean-room from the documented OpenWRT UCI file format; libuci
(LGPL-2.1) referenced for the format only, no source consulted or copied.

## API

```zig
const uci = @import("uci");

// Parse (typed errors, never panics; parseDiag adds a 1-based line number)
var pkg = try uci.parse(gpa, bytes);            // ParseError!Package
defer pkg.deinit(gpa);
var diag: uci.Diagnostics = .{};
_ = uci.parseDiag(gpa, bytes, &diag) catch |e| {
    // e.g. error.UnterminatedQuote at diag.line
};

// Model
// Package{ name: ?[]const u8, sections: []Section }
// Section{ type, name: ?[]const u8, anonymous: bool, options: []Option }
// Option{ key, kind: .single | .list, values: [][]const u8 }

// Accessors
const lan = pkg.section("interface", "lan").?;  // named lookup
_ = lan.get("proto");                           // ?[]const u8 (first value)
_ = lan.getList("ports");                       // all values, &.{} if absent
var it = pkg.iterate("interface");              // sections by type, file order
while (it.next()) |sec| { ... }

// Serialize to canonical UCI text (round-trip stable)
const text = try uci.serialize(gpa, &pkg);      // SerializeError![]u8
defer gpa.free(text);

// Deep equality (used by the round-trip tests)
_ = pkg.eql(&other);
```

## Format coverage / semantics

- Named and anonymous sections; optional `package <name>` header line.
- Single quotes: no escapes. Double quotes: `\"` `\'` `\\` `\n` `\t` `\r`
  (backslash before any other character yields that character). Bare words;
  adjacent quoted/bare segments of one token concatenate (`'a'"b"c` → `abc`).
- Comments: `#` to end of line at the start of a token; literal inside
  quotes and inside a bare word. Quotes may not span lines; CRLF accepted.
- Repeated `option` under one key: last wins. `list` accumulates in order.
  Mixing `option`/`list` under one key → `error.MixedOptionList`.
- Canonical output: optional `package '<name>'` header, blank line between
  section blocks, tab-indented options, values single-quoted (double-quoted
  with escapes when they contain `'` or control characters).
- Bounded: inputs over 16 MiB → `error.InputTooLarge`; lines over 16 KiB →
  `error.LineTooLong`.

## Notes / deviations

- An empty quoted section name (`config rule ''`) is treated as anonymous.
- Values containing control characters other than `\n` `\t` `\r` cannot be
  represented in UCI text and serialize to `error.UnserializableValue`.
- UCI CLI-level features (`uci set/commit`, `/etc/config` discovery, state
  files) are out of scope — this is the file codec only.
