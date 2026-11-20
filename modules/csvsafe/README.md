# csvsafe

OWASP CSV formula-injection guard — and nothing else.

A spreadsheet (Excel, LibreOffice Calc, Google Sheets) treats a cell whose
first byte is `=`, `+`, `-`, `@`, or a leading tab/CR as a **formula** and
evaluates it — the `=cmd|'/c calc'!A1` / DDE class of attack. This module
neutralizes such a cell by prefixing a single apostrophe (`'`), forcing the
spreadsheet to render the cell as literal text. A leading LF, `|` or `%` is
guarded as well (the union of go-safe-csv-writer's and defusedcsv's sets;
hardening beyond OWASP — a value that genuinely starts with `%` or `|` gains
the apostrophe).

- The injection guard only; decimal-separator
  remapping and RFC 4180 quoting are left to the CSV writer (`csvstream`);
  `writeField` / `writeRecord` chain the guard with `csvstream`'s quoting.
- **Model after:** OWASP CSV Injection prevention.
- **Platform:** any (pure logic, no OS calls). **Role:** util.
  **Concurrency:** reentrant (no shared state). **Allocation:** `needsGuard`,
  `writeSafe`, `writeField` and `writeRecord` are allocation-free; only `guard` takes an allocator.
  **Depends on:** `csvstream` (the dialect options of `writeField` / `writeRecord`).

Provenance: original work of the zig-libs authors (MIT). No third-party code.

## Signed-number exception

`+` and `-` also legitimately lead a number (`-12.34`, `+5`, `+.5`) or a
`+`-prefixed international phone number (`+420 555 0101`). Guarding those would
corrupt the value, so a `+`/`-` lead passes unguarded **only** when the byte after
it is a digit or the decimal separator and every following byte is a digit,
`.`, `,`, the separator or a space; anything else is a formula/comment lead
(`+SUM(...)`, `-1+cmd|...`, `-- comment`, a lone `+`) and is guarded.

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

### Guard and quote in one call

```zig
pub const WriteOptions = struct {
    csv: csvstream.WriteOptions = .{}, // the dialect to quote for
    decimal_sep: u8 = default_decimal_sep,
};

// Guard first, then quote (the apostrophe lands inside the quotes).
fn writeField(w: *std.Io.Writer, value: []const u8, opts: WriteOptions) std.Io.Writer.Error!void;
// One record, joined and terminated like csvstream.writeRecord of the guarded fields.
fn writeRecord(w: *std.Io.Writer, fields: []const []const u8, opts: WriteOptions) std.Io.Writer.Error!void;
```

## Verify

```
zig build test-csvsafe
zig build test-csvsafe -Doptimize=ReleaseFast
zig fmt --check modules/csvsafe
```

## Not provided

RFC 4180 quoting by the guard itself, decimal-separator remapping, Unicode lookalike leads and a configurable guard
char are refused by design; see SPEC *What is deliberately not done* (nothing is open in *Backlog / deferred*).
