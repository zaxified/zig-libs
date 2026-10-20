# tz

IANA time-zone offset lookup: zone name → UTC offset/DST/abbreviation at a given instant.

- Composes the `datefmt` module for the POSIX-TZ
  footer's calendar math.
- **Model after:** IANA tzdata (`zic`) + the POSIX `TZ` footer rule
  (RFC 9636 §3.3 / `tzfile(5)`).
- **Platform:** any (pure logic, no OS calls, no filesystem — the whole
  tzdata table is a compiled-in Zig array). **Role:** util.
  **Concurrency:** reentrant (no shared state). **Allocation:** none.

## How it works

Each of the 598 IANA zones carries an explicit list of UTC-offset
transitions from 1970 onward, generated ahead of time from the real tzdata
transition history (`zic` output). `offsetAt` binary-searches that list for
the offset in effect at a given Unix instant. Past the last explicit
transition (tzdata typically stops emitting these around 2037/2038), it
falls back to evaluating the zone's POSIX-TZ footer rule
(`std offset [dst [offset] [, start[/time], end[/time]]]`) for the target
year — the same mechanism `localtime(3)` uses beyond the precomputed table.

## API

```zig
const tz = @import("tz");

const Offset = struct { off: i32, dst: bool }; // off: seconds east of UTC

fn find(name: []const u8) ?*const tz.Zone;         // "Europe/Prague", "UTC", ...
fn offsetAt(zone: *const tz.Zone, unix: i64) Offset;
fn abbrevAt(zone: *const tz.Zone, unix: i64) []const u8; // "CET", "CEST", "+05"
fn canonicalName(zone: *const tz.Zone) []const u8;       // "US/Eastern" -> "America/New_York"

pub const Zone = struct {
    name: []const u8,
    init_off: i32,
    init_dst: bool,
    init_abbr: u16 = 0,        // offset into the table's abbreviation string
    trans: []const Transition, // sorted ascending by ts
    posix: []const u8,         // POSIX-TZ footer string
    footer: ?*const Footer = null,  // `posix`, parsed at generation time
    canonical: ?[]const u8 = null,  // set for links (aliases)
};
pub const Transition = struct { ts: i64, off: i32, dst: bool, abbr: u16 = 0 };
pub const zones: []const Zone; // all 598 zones, sorted by name
```

A zone built by hand (a test, a caller's own `TZ` string) leaves `footer`
null: `offsetAt` then parses `posix` per call, as it did before the footer
was stored. Every shipped zone has `footer` set and `offsetAt` never re-parses
(footer era: about 2.4x faster, 145-165 ns to 63-73 ns per call, ReleaseFast).

`find` binary-searches `zones` by name (case-sensitive, matching IANA
spelling exactly). `offsetAt`:

1. Before the first transition (or a zone with none) → `init_off`/`init_dst`.
2. Between transitions → the rightmost transition with `ts <= unix`.
3. At/after the last transition → the POSIX footer rule for that instant's
   year, falling back to the last transition's offset if the footer can't be
   evaluated (see Defer below).

### Transitions and abbreviations

```zig
const Change = struct { ts: i64, off: i32, dst: bool, abbr: []const u8 };
fn nextTransition(zone: *const tz.Zone, unix: i64) ?Change; // first change with ts > unix
fn prevTransition(zone: *const tz.Zone, unix: i64) ?Change; // last change with ts < unix
```

Both walk the table and then the POSIX footer's DST starts and ends (no end:
`null` means the zone never changes again, or, for `prevTransition`, has not
changed since the table's start at 1970). A change is any difference in
offset, DST flag or abbreviation. Abbreviations are tzdata's: `CET`, `EST`,
and for zones with no letters the signed digits without angle brackets
(`+05`, `-03`, `+0530`).

### Offset formatting

```zig
fn formatOffset(buf: []u8, off: i32, style: tz.OffsetStyle) ![]u8; // buf of tz.max_offset_len always fits
// .colon "+01:00" · .basic "+0100" · .short "+01" (hours only if minutes are 0, else "+0530")
// a non-zero seconds part is kept: "+05:48:28" / "+054828"
```

### Local wall-clock time → UTC

```zig
// `local` is the wall clock read as if it were UTC (datefmt.partsToUnix of the local fields).
fn resolveLocal(zone: *const tz.Zone, local: i64) tz.LocalTime;
// .unique: i64 | .ambiguous: {earlier, later} (fold) | .nonexistent: {earlier, later} (gap)
fn localToUtc(zone: *const tz.Zone, local: i64, policy: tz.Disambiguation) !i64;
// policy: .compatible (fold→earlier, gap→later; java.time/Python fold=0), .earlier, .later,
//         .reject (error.AmbiguousLocalTime / error.NonexistentLocalTime)
```

```zig
// the same from the date and time fields; error.InvalidDateTime for an out-of-range field
fn localToUnix(zone, year: i32, month, day, hour, minute, second: u32, policy) !i64;
```

Prague, 2024-03-31 02:30 (skipped): `.compatible`/`.later` → 01:30Z (reads as
03:30 CEST), `.earlier` → 00:30Z (01:30 CET). 2024-10-27 02:30 (twice):
`.earlier` → 00:30Z (CEST), `.later` → 01:30Z (CET). The policy is an explicit
argument: there is no silent default for a time that does not exist.

## Pre-1970 history

The default table starts at 1970: earlier history is folded into `init_*`, so
a pre-1970 instant gets the state of 1970. `src/tz_data_full.zig` (generated
together with it) keeps the whole history, back to local mean time. It is
NOT imported by default (about +80 KB in a ReleaseSmall binary over the
default table): to use it, change the `tz_data.zig` import in `src/root.zig`
to `tz_data_full.zig`; the types are shared (`src/types.zig`), nothing else
changes. A build option for this needs a `build.zig` change and is not wired.

## Defer (not in this extraction)

- The POSIX footer parser evaluates all three POSIX rule forms: `Mm.w.d`
  (nth/last weekday of a month), `Jn` (1<=n<=365, Julian day, Feb 29 never
  counted), and plain `n` (0<=n<=365, zero-based day of year, Feb 29
  counted). No zone in the current tzdata release actually uses `Jn`/`n` —
  every zone uses `Mm.w.d` — so this is forward cover, exercised by
  synthetic-zone tests rather than a real IANA entry.
- Regenerating `tz_data.zig` from a newer IANA tzdata release: the generator
  (`tz-gen`) is deliberately not part of this module — it reads a compiled
  zoneinfo tree and is the one place `std.Tz` is used, neither of
  which belongs behind the module's no-filesystem/no-syscalls model. It lives
  at [`scripts/gen/tz-gen/`](../../scripts/gen/tz-gen), outside `build.zig.zon`'s
  `.paths`, so it never reaches a consumer. There is still no runtime loader
  to redirect (the table is compile-time-embedded, by design) and no version
  accessor to add; the pinned release and the regeneration command are
  recorded in `tz_data.zig`'s own header comment.

  Run `scripts/gen/tz-gen/fetch-and-build.sh` rather than the generator directly.
  It fetches the pinned release from IANA against a pinned SHA-256, compiles
  it with the system `zic`, and generates from THAT — so the table is derived
  from the release it claims, not from whichever one this machine has
  installed. `--check` verifies the committed tables (default and full)
  reproduce, without writing them. The generator fails if a zone has no
  footer, a footer does not parse, a link target is missing, or a 4-day
  window holds too many changes for `resolveLocal`'s buffer.

Provenance: `src/root.zig`, `src/posix.zig` and `src/types.zig` are original work of the zig-libs authors (MIT);
`src/tz_data.zig` (and `tz_data_full.zig`) is generated data — the UTC-offset transition tables and
POSIX-TZ footer rule per zone (598 zones, transitions from 1970 onward),
produced ahead of time by the `tz-gen` tool from the IANA Time Zone Database
(tzdata 2026a release, <https://www.iana.org/time-zones>), which is in the
PUBLIC DOMAIN ("This file is in the public domain, so clarified as of
2009-05-17 by Arthur David Olson"). Only UTC-offset transition data and
POSIX-TZ footer rules are extracted — not the tz database's source code — and
the offset-lookup logic is the authors' own. Public domain imposes no
redistribution condition; this is provenance only, and no `NOTICE` entry is
required.

## Verify

```
zig build test-tz
zig build test-tz -Doptimize=ReleaseFast
```

`src/all_kat.bin` replays every zone against Python's zoneinfo over the same
tzdata release (1970-2050: offset, DST flag, abbreviation, transitions, local
time under every policy); regenerate with `tools/gen_all_kat.py` (usage in its
docstring).
