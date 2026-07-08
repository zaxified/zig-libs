# SPEC — `uci`

**Purpose** — Parser + serializer + typed model for the OpenWRT UCI (Unified Configuration
Interface) file format (`config` / `option` / `list`). Reads and writes `/etc/config`-style files
natively so OpenWRT tooling (axp) can drop shelling out to the `uci` binary and get typed access
plus typed errors — with stable round-trips (`parse(serialize(m)) == m`, second serialization
byte-identical).

**Model after / Seed** — clean-room from the documented OpenWRT UCI file format (OpenWRT wiki/docs);
libuci (LGPL-2.1) referenced for the *format* only, no source consulted or copied — the file format
is the documented interface. Greenfield, no seed. See `NOTICE`.

**Design & invariants**
- **Typed model, one arena.** `parse`/`parseDiag` build a `Package{ name?, sections:[]Section }`
  (`Section{ type, name?, anonymous, options:[]Option }`, `Option{ key, kind:.single|.list, values }`)
  in an internal arena — one `Package.deinit(gpa)` frees everything. `serialize` writes it back as
  canonical text. Reentrant, no shared state (`gap · any · codec`).
- **Documented quoting, exactly.** Single quotes take no escapes; double quotes take
  `\" \' \\ \n \t \r` (a backslash before any other char yields that char); bare words end at
  whitespace; adjacent segments of one token concatenate (`'a'"b"c` → `abc`); quotes may not span
  lines; `#` starts a comment only at the start of a token (literal inside a token or quotes). CRLF
  accepted.
- **Repeated-key semantics.** A repeated `option` under one key overwrites (last wins, matching
  `uci set`); `list` entries accumulate in order; mixing `option` and `list` under one key →
  `error.MixedOptionList`.
- **Never-panic, line-numbered errors.** Malformed input yields a typed `ParseError`
  (`UnterminatedQuote`, `BadKeyword`, `MissingArgument`, `TooManyArguments`, `OptionOutsideSection`,
  `MixedOptionList`, …); `parseDiag` fills a 1-based `Diagnostics.line` (0 = not line-tied).
  Serialization of a value with a control char that has no UCI escape → `error.UnserializableValue`.
- **Bounded.** Input over 16 MiB → `error.InputTooLarge`; a line over 16 KiB → `error.LineTooLong`.
- **Canonical output:** optional `package '<name>'` header, blank line between section blocks,
  tab-indented options, values single-quoted (double-quoted with escapes only when they contain `'`
  or a control char). Accessors: `section(type,name)`, `get`/`getList`, `iterate(type)`, deep `eql`.

**Threat model / out of scope** — Not security-sensitive; the hardening is denial-of-service and
crash resistance on hostile config text — the input/line-length caps and the never-panic typed-error
contract bound memory and rule out OOB/hang on garbage or bit-flipped input. Deviations to note: an
empty quoted section name (`config rule ''`) is treated as anonymous; values with control chars
other than `\n \t \r` cannot be represented in UCI text and fail serialization. **Out of scope:** the
UCI CLI layer — `uci set/commit`, `/etc/config` discovery, the transactional delta/state files under
`/var/state`, and typed value coercion. This is the file codec only.

**Verification** — Golden tests: parse a realistic `network` config into the model and assert its
structure; round-trip stability (`parse∘serialize` equal, second pass byte-identical) and the exact
canonical serialization bytes. Quoting: double-quote escapes, single-quote literalness, bare words,
mid-word `#`, token concatenation of quoted segments, comments/blank lines, empty quoted value.
Semantics: anonymous sections, list accumulation, duplicate-option last-wins, mixed option/list
rejected. Errors (with asserted line numbers): unterminated single/double quote, option before any
section, bad keyword, missing/too-many arguments, line-too-long, input-too-large. Plus accessor
lookups, CRLF input, `package` header serialization, and quoted keys/types round-tripping.

**Status** — `gap · any · codec · reentrant` · deps: none (std only).
