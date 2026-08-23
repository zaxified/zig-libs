# tz

IANA time-zone offset lookup: zone name → UTC offset/DST at a given instant.

- Composes the `datefmt` module for the POSIX-TZ
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
pub const zones: []const Zone; // all 598 zones, sorted by name
```

`find` binary-searches `zones` by name (case-sensitive, matching IANA
spelling exactly). `offsetAt`:

1. Before the first transition (or a zone with none) → `init_off`/`init_dst`.
2. Between transitions → the rightmost transition with `ts <= unix`.
3. At/after the last transition → the POSIX footer rule for that instant's
   year, falling back to the last transition's offset if the footer can't be
   evaluated (see Defer below).

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
  at [`scripts/tz-gen/`](../../scripts/tz-gen), outside `build.zig.zon`'s
  `.paths`, so it never reaches a consumer. There is still no runtime loader
  to redirect (the table is compile-time-embedded, by design) and no version
  accessor to add; the pinned release and the regeneration command are
  recorded in `tz_data.zig`'s own header comment.

  Run `scripts/tz-gen/fetch-and-build.sh` rather than the generator directly.
  It fetches the pinned release from IANA against a pinned SHA-256, compiles
  it with the system `zic`, and generates from THAT — so the table is derived
  from the release it claims, not from whichever one this machine has
  installed. `--check` verifies the committed table reproduces, without
  writing it.

Provenance: `src/root.zig` is original work of the zig-libs authors (MIT);
`src/tz_data.zig` is generated data — the UTC-offset transition tables and
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
