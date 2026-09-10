# uci

Parser + serializer + typed model for the **OpenWRT UCI** (Unified
Configuration Interface) file format — `config` / `option` / `list`.

- No maintained pure-Zig UCI codec exists; this retires
  shelling out to the `uci` binary for callers that manage OpenWRT-style
  device config.
- **Model after:** OpenWRT UCI file format.
- **Why:** OpenWRT-style device config is commonly read/written by shelling
  out to `uci`; doing it natively removes an exec dependency and gives typed
  access + errors.
- **Platform:** any (pure text codec, no I/O).
  **Role:** codec. **Concurrency:** reentrant (no shared state).
  **Allocation:** model memory lives in an internal arena — one
  `Package.deinit(gpa)` frees everything.

Provenance: original work of the zig-libs authors (MIT); clean-room from the
documented OpenWRT UCI (Unified Configuration Interface) file format (OpenWRT
wiki/docs) — the file format is the documented interface. Every behavioural
claim is settled by RUNNING the real `uci` binary: `root.zig`'s "real uci
capture" and "addressing
probe" sections freeze raw config bytes together with that binary's own
`export`/`show`/`get` stdout, taken inside the `scripts/vm/` OpenWRT VM and
replayed by tests — a black-box oracle, which root `NOTICE` §0 records as owing
no attribution. See SPEC.md for the findings.

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

// Resolve `@type[N]` positional addressing, incl. the negative-index-
// from-the-end form (`-1` = last matching section of that type). Anonymous
// and named sections of `type` both count, in file order. Out-of-range
// (either direction) returns null — the real binary's own "not found".
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
- Single quotes: no escapes — everything between them, `\t`/`\n`/`\r`
  included, is literal. Double quotes: `\" \' \\` are true escapes; a
  backslash before ANY OTHER character (including `n`/`t`/`r`) drops the
  backslash and keeps that character literally — there is no BACKSLASH
  escape that produces an actual control byte (real `uci` binary confirms
  `\n`/`\t`/`\r` are not special-cased; see SPEC.md). That does not mean
  those three bytes can't appear at all: `\t`/`\n`/`\r` are legal LITERAL
  bytes inside either kind of quote (audit A1 U6 — the only three sub-0x20
  bytes real `uci`'s own validator allows in a value) and this module writes
  them back raw, unescaped, same as real `uci export`. Bare words; adjacent
  quoted/bare segments of one token concatenate (`'a'"b"c` → `abc`).
- **A quote (either kind) may span physical lines** (audit A1 U5): a value
  containing a real newline — a certificate, an SSH key, a multi-line LuCI
  form field — is accepted and round-trips as a multi-line quoted literal,
  e.g. `option multi 'line1` + newline + `line2'`, matching real `uci`
  (`uci_getln`, file.c:41). Only running out of input with a quote still
  open is `error.UnterminatedQuote`. Everything OUTSIDE a quote is still
  exactly one physical line — a bare word, `#`, and the statement keyword
  never cross a `\n`.
- Comments: `#` to end of line at the start of a token, OR anywhere inside a
  bare (unquoted) run — either way it truncates the token and discards the
  rest of the *line*, matching real `uci` (audit A1 U4: `a#b` unquoted is
  `a`, not `a#b`). Literal inside quotes. CRLF accepted (statement grammar
  only; not part of a quoted value's own content).
- Repeated `option` under one key: last wins. `list` accumulates in order.
  Mixing `option`/`list` under one key is rejected here as
  `error.MixedOptionList`, and an `option`/`list` with no value as
  `error.MissingArgument` — both are this module's OWN additional
  strictness, not real UCI semantics (audit A1 U11/U12): real `uci` merges a
  mixed option/list (last kind for that key wins) and loads a file with a
  valueless `option` by simply dropping it, rather than rejecting the whole
  file either way.
- Section/option names must be alphanumeric or `_` (not even `-`); section
  types allow any other printable, non-space ASCII byte too. Real `uci`'s own
  validator draws the same line, on both the read AND write path — a name it
  would refuse to load is rejected here too (audit A1 U7, `error.InvalidName`;
  not enforced on an option key when *writing*, see the source for why). A
  zero-length name/type/key is the one exception (see below).
- Two `config` blocks sharing a name are rejected as `error.DuplicateSection`
  regardless of whether they share a type (audit A1 U1) — this module's
  `[]Section` model cannot represent real `uci`'s same-type merge (last
  option value wins), so rather than silently answering every accessor from
  the FIRST block's now-stale values, it refuses the file.
- Canonical output: optional `package <name>` header (bare when
  identifier-safe, quoted otherwise — matches real `uci export`'s own
  rendering), blank line between section blocks, tab-indented options, values
  single-quoted (double-quoted with escapes when they contain `'` or control
  characters).
- Bounded: inputs over 16 MiB → `error.InputTooLarge`; lines over 16 KiB →
  `error.LineTooLong`; the built model over 300000 total items (sections +
  options + values, combined) → `error.MemoryLimitExceeded` (audit A1 U3 —
  the text cap alone let a legal 16 MiB input cost 371+ MB of RSS).

## Notes / deviations

- An empty quoted section name (`config rule ''`) is treated as anonymous;
  an empty quoted section type or option key (`config ''`, `option '' v`) is
  accepted literally — the one case the name/type/key validation above does
  not cover, since real `uci` treats a zero-length argument as "insufficient
  arguments" (a different failure mode) rather than an invalid character.
- Values containing ANY control character below 0x20 — `\n` `\t` `\r`
  included, since none of them has a working escape (see above) — cannot be
  represented in UCI text and serialize to `error.UnserializableValue`.
- UCI CLI-level features (`uci set/commit`, `/etc/config` discovery, state
  files) are out of scope — this is the file codec only. In particular: a
  file-only reader loses staged-but-uncommitted state (`uci set` without
  `commit`, common on live devices — LuCI's "Save" without "Apply"); see
  SPEC.md's threat-model section for the concrete trap and for `uci
  revert`'s truncate-not-delete delta-file behavior.
