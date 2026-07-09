# csvsafe — spec

OWASP CSV formula-injection guard — and nothing else. Usage: see ./README.md.
Attribution/provenance: see /NOTICE.

## Design & invariants
- Neutralizes a cell a spreadsheet would read as a formula (leading `=`, `+`, `-`, `@`, tab, CR) by
  prefixing a single apostrophe (`guard_char`), forcing literal-text rendering.
- **Signed-number exception preserved from the seed:** a `+`/`-` lead is guarded only when the byte
  after it is not a digit or the decimal separator — so `-12.34`, `+.5`, and `+420 555 0101` pass
  through unguarded, mirroring the seed's `next_is_numeric` check exactly.
- `needsGuard`/`writeSafe` are allocation-free (stream to `*std.Io.Writer`); only `guard` (returns
  an owned `[]u8`) takes an allocator. `*Sep` variants let a comma-decimal locale recognize
  `-12,34` as a number via `needsGuardSep`/`writeSafeSep`/`guardSep`.
- Pure logic, no OS calls, reentrant, no shared state.

## Threat model / out of scope
Defends against the `=cmd|'/c calc'!A1` / DDE class of CSV formula-injection when the CSV is opened
in a spreadsheet. Out of scope by design (carved deliberately narrow from a seed that fused three
concerns): **RFC 4180 quoting** (delimiter/quote/CR-LF wrapping — the CSV writer's or `csvstream`'s
job, not this guard's); **decimal-separator remapping** for numeric output (this module only *reads*
the separator to spot a signed number, never rewrites it); **Unicode formula-lead lookalikes** (ASCII
leads only — a non-UTF-8/homoglyph lead is unguarded); **configurable guard char** (fixed to `'`,
exposed as `guard_char` for reference only, not a parameter).

## Verification
`zig build test-csvsafe` (+ `-Doptimize=ReleaseFast`; `zig fmt --check modules/csvsafe`). 8 tests:
`needsGuard`/`needsGuardSep` over the dangerous-lead set and the signed-number exception (both
decimal separators), `writeSafe`/`writeSafeSep` streaming output, `guard`/`guardSep` allocation
round-trip.

## Backlog / deferred
From README "DEFER (intentionally out of scope for this v1)": RFC 4180 quoting, decimal-separator
remapping, Unicode formula-lead lookalikes, configurable guard char — all as listed above under
Threat model / out of scope (this module is deliberately narrow; these are permanent scope
boundaries, not TODOs).

## Status
`extract · any · util · reentrant` + deps: none — canonical source is `pub const meta` in
src/root.zig.
