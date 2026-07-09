# csvsafe

OWASP CSV formula-injection guard — and nothing else.

A spreadsheet (Excel, LibreOffice Calc, Google Sheets) treats a cell whose
first byte is `=`, `+`, `-`, `@`, or a leading tab/CR as a **formula** and
evaluates it — the `=cmd|'/c calc'!A1` / DDE class of attack. This module
neutralizes such a cell by prefixing a single apostrophe (`'`), forcing the
spreadsheet to render the cell as literal text.

- **Status:** `extract` — the injection guard only; decimal-separator
  remapping and RFC 4180 quoting are deliberately left to the CSV writer /
  csvstream consumer.
- **Model after:** OWASP CSV Injection prevention.
- **Platform:** any (pure logic, no OS calls). **Role:** util.
  **Concurrency:** reentrant (no shared state). **Allocation:** `needsGuard`
  and `writeSafe` are allocation-free; only `guard` takes an allocator.

Provenance: original work of the zig-libs authors (MIT). No third-party code.

## Signed-number exception

`+` and `-` also legitimately lead a number (`-12.34`, `+5`, `+.5`) or a
`+`-prefixed international phone number (`+420 555 0101`). Guarding those would
corrupt the value, so a `+`/`-` lead is guarded **only** when the byte after it
is not a digit or the decimal separator — i.e. only when it is actually a
formula/comment lead (`+SUM(...)`, `-- comment`, a lone `+`).

## API

```zig
const csvsafe = @import("csvsafe");

pub const guard_char: u8 = '\'';          // the neutralizing prefix
pub const default_decimal_sep: u8 = '.';

// Predicate: would this cell be read as a formula?
fn needsGuard(value: []const u8) bool;
fn needsGuardSep(value: []const u8, decimal_sep: u8) bool;

// Stream the guarded cell (guard prefix if needed, then bytes verbatim).
fn writeSafe(writer: *std.Io.Writer, value: []const u8) std.Io.Writer.Error!void;
fn writeSafeSep(writer: *std.Io.Writer, value: []const u8, decimal_sep: u8) std.Io.Writer.Error!void;

// Allocate a guarded (or plain-copied) cell; caller frees.
fn guard(alloc: std.mem.Allocator, value: []const u8) ![]u8;
fn guardSep(alloc: std.mem.Allocator, value: []const u8, decimal_sep: u8) ![]u8;
```

The `*Sep` variants let a comma-decimal locale recognize `-12,34` as a number.

## Verify

```
zig build test-csvsafe
zig build test-csvsafe -Doptimize=ReleaseFast
zig fmt --check modules/csvsafe
```

## DEFER (intentionally out of scope for this v1)

- **RFC 4180 quoting** — wrapping a cell that contains the delimiter, the quote
  char, CR or LF, and doubling internal quotes. Left to the CSV writer /
  `csvstream` (it owns the delimiter and quote char; the guard does not).
- **Decimal-separator remapping** — converting `.` → `,` for numeric outputs.
  Also a writer/locale concern; `csvsafe` only *reads* the separator to spot a
  signed number, it never rewrites it.
- **Unicode formula-lead lookalikes** — the guard checks ASCII leads only. A
  spreadsheet reading a non-UTF-8 / homoglyph lead is out of scope; add if a
  concrete threat model needs it.
- **Configurable guard char** — fixed to `'` (the spreadsheet-standard literal
  lead). Exposed as `guard_char` for reference, not as a parameter.
