# glibc side of `zig build bench-tz`

`driver.c` is built by `modules/tz/tools/bench.zig` with the system `cc -O3 -march=native`
(linked against the system glibc, which is the reference: `localtime_r`, `mktime`).
It is not a test and runs in no lane.

- Data: the pinned tzdata 2026a tree `.zig-cache/tz-gen/2026a/zoneinfo`
  (`scripts/gen/tz-gen/fetch-and-build.sh`). Its path is passed in `<work dir>/tzdir.txt`
  and exported as `TZDIR`; the host's `/usr/share/zoneinfo` is another release and is
  never read. The driver aborts if a zone file is missing (glibc would fall back to UTC
  silently).
- Zones: one active at a time (`TZ=:<zone>` + `tzset()` between zones, outside the timed
  region). The per-call cost is measured, not `tzset`.
- Modes: `driver <dir> <workload>` prints `name<TAB>ns/op<TAB>count`;
  `driver <dir> <workload> dump <outfile>` writes one i64 per input, which the Zig
  program compares with its own values before anything is timed.
- Inputs: `<dir>/<workload>.in`, written by the Zig program (u64 lens[4], then the four
  zones' inputs).
- `mktime` is called with `tm_isdst = -1`; glibc does not promise which instant it picks
  in a gap or a fold, so the inputs on which it differs from `compatible` are excluded
  by the Zig program from all sides.
