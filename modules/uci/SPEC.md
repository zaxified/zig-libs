# uci — spec

Design + threat notes for auditors. Usage: see ./README.md. Attribution/provenance: see /NOTICE.

## Design & invariants
Typed model, one arena: `parse`/`parseDiag` build a `Package{ name?, sections:[]Section }`
(`Section{ type, name?, anonymous, options:[]Option }`, `Option{ key, kind:.single|.list, values }`)
in an internal arena — one `Package.deinit(gpa)` frees everything; `serialize` writes it back as
canonical text. Reentrant, no shared state. Documented quoting, exactly: single quotes take no
escapes; double quotes take `\" \' \\ \n \t \r` (a backslash before any other char yields that char);
bare words end at whitespace; adjacent segments of one token concatenate (`'a'"b"c` → `abc`); quotes
may not span lines; `#` starts a comment only at the start of a token; CRLF accepted. Repeated-key
semantics: a repeated `option` under one key overwrites (last wins, matching `uci set`); `list`
entries accumulate in order; mixing `option` and `list` under one key → `error.MixedOptionList`.
Never-panic, line-numbered errors: malformed input yields a typed `ParseError` (`UnterminatedQuote`,
`BadKeyword`, `MissingArgument`, `TooManyArguments`, `OptionOutsideSection`, `MixedOptionList`, …);
`parseDiag` fills a 1-based `Diagnostics.line` (0 = not line-tied). Serialization of a value with a
control char that has no UCI escape → `error.UnserializableValue`. Bounded: input over 16 MiB →
`error.InputTooLarge`; a line over 16 KiB → `error.LineTooLong`. Canonical output: optional `package
'<name>'` header, blank line between section blocks, tab-indented options, values single-quoted
(double-quoted with escapes only when they contain `'` or a control char). Accessors: `section(type,
name)`, `get`/`getList`, `iterate(type)`, deep `eql`. Clean-room from the documented OpenWRT UCI file
format (libuci referenced for the *format* only, no source consulted or copied) — see NOTICE.

## Threat model / out of scope
Not security-sensitive; the hardening is denial-of-service and crash resistance on hostile config
text — the input/line-length caps and the never-panic typed-error contract bound memory and rule out
OOB/hang on garbage or bit-flipped input. Deviations to note: an empty quoted section name (`config
rule ''`) is treated as anonymous; values with control chars other than `\n \t \r` cannot be
represented in UCI text and fail serialization. Out of scope: the UCI CLI layer — `uci set/commit`,
`/etc/config` discovery, the transactional delta/state files under `/var/state`, and typed value
coercion. This is the file codec only.

## Verification
Golden tests: parse a realistic `network` config into the model and assert its structure; round-trip
stability (`parse∘serialize` equal, second pass byte-identical) and the exact canonical serialization
bytes. Quoting: double-quote escapes, single-quote literalness, bare words, mid-word `#`, token
concatenation of quoted segments, comments/blank lines, empty quoted value. Semantics: anonymous
sections, list accumulation, duplicate-option last-wins, mixed option/list rejected. Errors (with
asserted line numbers): unterminated single/double quote, option before any section, bad keyword,
missing/too-many arguments, line-too-long, input-too-large. Plus accessor lookups, CRLF input,
`package` header serialization, and quoted keys/types round-tripping. 30 tests. Run: `zig build
test-uci`.

## Backlog / deferred
None beyond the documented UCI-CLI-layer/typed-coercion out-of-scope
list above.

## Status
`gap · any · codec · reentrant` + deps: none (std only) — canonical source is `pub const meta` in
src/root.zig.
