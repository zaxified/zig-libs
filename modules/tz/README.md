# tz

IANA time-zone offset lookup: zone name → UTC offset/DST at a given instant.

- **Status:** `extract` — composes the `datefmt` module for the POSIX-TZ
  footer's calendar math.
- **Model after:** IANA tzdata (`zic`) + the POSIX `TZ` footer rule
  (RFC 9636 §3.3 / `tzfile(5)`).
- **Platform:** any (pure logic, no OS calls, no filesystem — the whole
  tzdata table is a compiled-in Zig array). **Role:** util.
  **Concurrency:** reentrant (no shared state). **Allocation:** none.

## How it works

Each of the 600 IANA zones carries an explicit list of UTC-offset
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

pub const Zone = struct {
    name: []const u8,
    init_off: i32,
    init_dst: bool,
    trans: []const Transition, // sorted ascending by ts
    posix: []const u8,         // POSIX-TZ footer string
};
pub const Transition = struct { ts: i64, off: i32, dst: bool };
pub const zones: []const Zone; // all 600 zones, sorted by name
```

`find` binary-searches `zones` by name (case-sensitive, matching IANA
spelling exactly). `offsetAt`:

1. Before the first transition (or a zone with none) → `init_off`/`init_dst`.
2. Between transitions → the rightmost transition with `ts <= unix`.
3. At/after the last transition → the POSIX footer rule for that instant's
   year, falling back to the last transition's offset if the footer can't be
   evaluated (see Defer below).

## Defer (not in this extraction)

- The POSIX footer parser only supports the common `Mm.w.d` rule form
  (nth/last weekday of a month — what every zone in the current tzdata
  release actually uses). The rare `Jn`/`n` Julian-day rule forms are not
  implemented; `offsetAt` falls back to the last explicit transition's
  offset for a zone whose footer uses one of those (none currently do).
- Regenerating `tz_data.zig` from a newer IANA tzdata release: the generator
  (`tz-gen`) is a separate tool, not ported into this module — it is not
  included here, only referenced.

Provenance: `src/root.zig` is original work of the zig-libs authors (MIT);
`src/tz_data.zig` is generated data — the UTC-offset transition tables and
POSIX-TZ footer rule per zone (600 zones, transitions from 1970 onward),
produced ahead of time by the `tz-gen` tool from the IANA Time Zone Database
(tzdata 2026a release, public domain). See `NOTICE`.

## Verify

```
zig build test-tz
zig build test-tz -Doptimize=ReleaseFast
```
