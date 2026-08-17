# uci

Parser + serializer + typed model for the **OpenWRT UCI** (Unified
Configuration Interface) file format — `config` / `option` / `list`.

- No maintained pure-Zig UCI codec exists; this retires
  shelling out to the `uci` binary for callers that manage OpenWRT-style
  device config.
- **Model after:** OpenWRT UCI file format / libuci.
- **Why:** OpenWRT-style device config is commonly read/written by shelling
  out to `uci`; doing it natively removes an exec dependency and gives typed
  access + errors.
- **Platform:** any (pure text codec, no I/O).
  **Role:** codec. **Concurrency:** reentrant (no shared state).
  **Allocation:** model memory lives in an internal arena — one
  `Package.deinit(gpa)` frees everything.

Provenance: original work of the zig-libs authors (MIT); clean-room from the
documented OpenWRT UCI (Unified Configuration Interface) file format (OpenWRT
wiki/docs) — libuci (LGPL-2.1) is referenced for the format only, no libuci
source was consulted or copied; the file format is the documented interface.
`root.zig`'s "real uci capture" tests freeze raw config bytes and the real `uci`
binary's own `export`/`show` stdout for them, run once inside the `scripts/vm/`
OpenWRT VM, exercising it purely as a black-box test oracle (root `NOTICE` §0 —
no libuci/uci source consulted, needing no attribution); see SPEC.md for the
findings.

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
const lan = pkg.section("interface", "lan").?;  // named lookup (type + name)
_ = lan.get("proto");                           // ?[]const u8 (first value)
_ = lan.getList("ports");                       // all values, &.{} if absent
var it = pkg.iterate("interface");              // sections by type, file order
while (it.next()) |sec| { ... }

// Resolve a `pkg.<name>.<opt>` key path when you only have the name, not
// the type (unlike `section`, which needs both).
_ = pkg.sectionByName("lan");                   // ?*const Section

// Resolve `@type[N]` positional addressing, incl. libuci's negative-index-
// from-the-end form (`-1` = last matching section of that type). Anonymous
// and named sections of `type` both count, in file order. Out-of-range
// (either direction) returns null, matching libuci's own "not found".
_ = pkg.nth("rule", 0);                         // ?*const Section, first
_ = pkg.nth("rule", -1);                        // ?*const Section, last

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
  files) are out of scope — this is the file codec only. In particular: a
  file-only reader loses staged-but-uncommitted state (`uci set` without
  `commit`, common on live devices — LuCI's "Save" without "Apply"); see
  SPEC.md's threat-model section for the concrete trap and for `uci
  revert`'s truncate-not-delete delta-file behavior.
