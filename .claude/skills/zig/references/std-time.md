# std.time - Time and Timing (0.16)

Wall-clock timestamps, monotonic timers, high-precision timing, and epoch/calendar utilities.

## Critical: Wall-Clock Timestamps, Instant, and Timer Removed (0.16)

`std.time.timestamp()`, `milliTimestamp()`, `microTimestamp()`, `nanoTimestamp()`, `std.time.Instant`, and `std.time.Timer` are **all removed** in Zig 0.16. `std.time` itself now contains *only* the unit constants (`ns_per_s`, ...) and the `epoch` calendar-conversion module — no clock access at all.

Two 0.16 replacements exist, depending on whether you have an `Io` instance:

- **With an `Io` instance:** use `std.Io.Clock` (`Clock.now(io)`, `Clock.Timestamp`, `Clock.Duration`) — see below. This is the idiomatic 0.16 way and is portable.
- **Without an `Io` instance** (e.g. deep library code): fall back to `std.c.clock_gettime` directly:

```zig
// WRONG (0.16) — functions removed
const secs = std.time.timestamp();
const ms = std.time.milliTimestamp();

// CORRECT — clock_gettime replacements (no Io available)
fn timestampSec() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return ts.sec;
}

fn milliTimestamp() i64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(i64, ts.sec) * 1000 + @divTrunc(@as(i64, ts.nsec), 1_000_000);
}

fn nanoTimestamp() i128 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(.REALTIME, &ts);
    return @as(i128, ts.sec) * 1_000_000_000 + @as(i128, ts.nsec);
}
```

**Important:** `ts.nsec` is signed — use `@divTrunc`, not `/` (0.16 enforces `@divTrunc` for signed integer division).

**Still present in 0.16:** `std.time.ns_per_s` and all the other unit constants, and `std.time.epoch`. **Removed, no `std.time` member at all anymore:** `Instant`, `Timer`, and every timestamp function.

**Also removed in 0.16:** `std.Thread.sleep` — with an `Io`, use `io.sleep(duration, clock)`; without one, nanosleep via `std.c.nanosleep`:
```zig
fn threadSleep(ns: u64) void {
    const ts = std.c.timespec{
        .sec = @intCast(ns / std.time.ns_per_s),
        .nsec = @intCast(ns % std.time.ns_per_s),
    };
    _ = std.c.nanosleep(&ts, null);
}
```

## Quick Reference

| Category | With `Io` (0.16) | Without `Io` (fallback) |
|----------|-------------------|--------------------------|
| Wall-clock timestamp | `Io.Clock.now(io, .real)` → `Io.Timestamp` | `std.c.clock_gettime(.REALTIME, &ts)` |
| Monotonic / elapsed time | `Io.Clock.Timestamp.now(io, .awake)` + `.untilNow(io)` | n/a — needs some clock source |
| Sleep | `io.sleep(duration, clock)` | `std.c.nanosleep` |
| Epoch / calendar | `std.time.epoch.*` (unchanged) | same |
| Constants | `std.time.ns_per_*`, `us_per_*`, `ms_per_*`, `s_per_*` (unchanged) | same |

## Choosing the Right Function

```
Need wall-clock time (date/time)?
├─ Have an Io? → Io.Clock.now(io, .real)
└─ No Io?      → std.c.clock_gettime(.REALTIME, &ts)

Need elapsed time / benchmarking / monotonic guarantee?
├─ Have an Io? → Io.Clock.Timestamp.now(io, .awake), then .untilNow(io)
└─ No Io?      → you need some clock source; std.c.clock_gettime(.MONOTONIC, ...) works too
```

## Wall-Clock Timestamps (with an Io instance)

Get current time relative to Unix epoch (1970-01-01 UTC), via `std.Io.Clock`:

```zig
const std = @import("std");

pub fn main(init: std.process.Init) void {
    const io = init.io;
    // A Timestamp of nanosecond resolution (i96 internally)
    const now: std.Io.Timestamp = std.Io.Clock.now(.real, io);

    const secs = now.toSeconds();        // i64
    const ms = now.toMilliseconds();     // i64
    const us = now.toMicroseconds();     // i64
    const ns = now.toNanoseconds();      // i96
    _ = .{ secs, ms, us, ns };
}
```

**Clock kinds** (`std.Io.Clock`): `.real` (wall clock, like the old `REALTIME`), `.awake` (monotonic, excludes suspend time), `.boot` (monotonic, includes suspend time), `.cpu_process`, `.cpu_thread`.

## Clock.Timestamp - High-Resolution, Clock-Tagged Timestamps

`Io.Clock.Timestamp` replaces `Instant`: it samples a specific clock and remembers which one, so you can later compute the duration since then without re-specifying the clock:

```zig
const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const start: std.Io.Clock.Timestamp = .now(io, .awake);

    // ... work ...

    const elapsed: std.Io.Clock.Duration = start.untilNow(io);
    const elapsed_ns = elapsed.raw.toNanoseconds();  // i96 nanoseconds

    std.debug.print("Elapsed: {d} ns\n", .{elapsed_ns});
}
```

### Clock.Timestamp Methods

```zig
// Get current timestamp on a given clock
const t: std.Io.Clock.Timestamp = .now(io, .awake);

// Compare two timestamps on the SAME clock
const same = t.compare(.eq, other);  // asserts same clock

// Duration between two timestamps on the same clock
const d = earlier.durationTo(later);

// Duration from `t` until now
const since = t.untilNow(io);

// Wait until this timestamp arrives
try t.wait(io);
```

There is no `error.Unsupported` from `.now()` in 0.16 — an unsupported clock simply has `resolution(io)` (via `Clock.resolution`) equal to zero; `.now()` itself does not fail (it is not cancelable, since it does not block).

## Clock.Duration - Monotonic Benchmarking

`Io.Clock.Duration` (a `raw: Io.Duration` tagged with a `clock: Clock`) replaces `Timer`. There is no `.lap()`/`.reset()` — recompute from a stored `Clock.Timestamp` instead:

```zig
const std = @import("std");

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var start: std.Io.Clock.Timestamp = .now(io, .awake);

    // ... first phase ...
    const phase1 = start.untilNow(io);
    start = .now(io, .awake);  // "reset"

    // ... second phase ...
    const phase2 = start.untilNow(io);

    _ = .{ phase1, phase2 };
}
```

### Io.Duration Methods (the `.raw` field of a Clock.Duration)

```zig
const d: std.Io.Duration = elapsed.raw;

d.toNanoseconds();   // i96
d.toMicroseconds();  // i64
d.toMilliseconds();  // i64
d.toSeconds();        // i64

// Construct directly (not tied to a clock)
const half_second = std.Io.Duration.fromMilliseconds(500);
```

## Time Unit Constants

```zig
// Nanosecond divisions
std.time.ns_per_us;    // 1_000
std.time.ns_per_ms;    // 1_000_000
std.time.ns_per_s;     // 1_000_000_000
std.time.ns_per_min;   // 60 * ns_per_s
std.time.ns_per_hour;  // 60 * ns_per_min
std.time.ns_per_day;   // 24 * ns_per_hour
std.time.ns_per_week;  // 7 * ns_per_day

// Microsecond divisions
std.time.us_per_ms;    // 1_000
std.time.us_per_s;     // 1_000_000
// ... us_per_min, us_per_hour, us_per_day, us_per_week

// Millisecond divisions
std.time.ms_per_s;     // 1_000
// ... ms_per_min, ms_per_hour, ms_per_day, ms_per_week

// Second divisions
std.time.s_per_min;    // 60
std.time.s_per_hour;   // 3_600
std.time.s_per_day;    // 86_400
std.time.s_per_week;   // 604_800
```

## Epoch Module - Calendar Conversions

Unchanged in 0.16. Convert epoch timestamps to year/month/day/time components:

### EpochSeconds to Calendar

```zig
const std = @import("std");
const epoch = std.time.epoch;

pub fn main(init: std.process.Init) void {
    const io = init.io;
    const secs: u64 = @intCast(std.Io.Clock.now(.real, io).toSeconds());
    const es = epoch.EpochSeconds{ .secs = secs };

    // Get day and time components
    const day = es.getEpochDay();
    const time = es.getDaySeconds();

    // Get year and day-of-year
    const year_day = day.calculateYearDay();
    // year_day.year: u16 (e.g., 2024)
    // year_day.day: u9 (0-365, day of year)

    // Get month and day-of-month
    const month_day = year_day.calculateMonthDay();
    // month_day.month: Month enum (.jan to .dec)
    // month_day.day_index: u5 (0-30, day of month)

    // Get time of day
    const hours = time.getHoursIntoDay();      // u5 (0-23)
    const minutes = time.getMinutesIntoHour(); // u6 (0-59)
    const seconds = time.getSecondsIntoMinute(); // u6 (0-59)

    std.debug.print("{d}-{d}-{d} {d}:{d}:{d}\n", .{
        year_day.year, @intFromEnum(month_day.month), month_day.day_index + 1,
        hours, minutes, seconds,
    });
}
```

### Month Enum

```zig
const epoch = std.time.epoch;

const month: epoch.Month = .jun;
const num = month.numeric();  // 6 (u4, 1-12)

// All months
// .jan, .feb, .mar, .apr, .may, .jun, .jul, .aug, .sep, .oct, .nov, .dec
```

### Leap Year and Days

```zig
const epoch = std.time.epoch;

// Check leap year
const is_leap = epoch.isLeapYear(2024);  // true

// Days in year
const days = epoch.getDaysInYear(2024);  // 366

// Days in month
const feb_days = epoch.getDaysInMonth(2024, .feb);  // 29
```

### Epoch Reference Values

Convert between epoch systems (values are seconds offset from Unix epoch):

```zig
const epoch = std.time.epoch;

epoch.posix;   // 0          (Jan 01, 1970 - Unix)
epoch.unix;    // 0          (alias for posix)
epoch.dos;     // 315532800  (Jan 01, 1980 - DOS/VFAT/BIOS)
epoch.windows; // -11644473600 (Jan 01, 1601 - NTFS)
epoch.ios;     // 978307200  (Jan 01, 2001 - Apple)
epoch.gps;     // 315964800  (Jan 06, 1980 - GPS/ATSC)
epoch.ntp;     // -2208988800 (Jan 01, 1900 - NTP/z/OS)
epoch.clr;     // -62135769600 (Jan 01, 0001 - .NET/Go)
```

## Common Patterns

### Simple Benchmark

```zig
pub fn benchmark(io: std.Io, comptime func: anytype) i96 {
    const start: std.Io.Clock.Timestamp = .now(io, .awake);
    func();
    return start.untilNow(io).raw.toNanoseconds();
}

// Usage
const ns = benchmark(io, myExpensiveFunction);
std.debug.print("Took {d} ns\n", .{ns});
```

### Format Timestamp as ISO 8601

```zig
fn formatTimestamp(secs: u64, buf: []u8) []u8 {
    const epoch = std.time.epoch;
    const es = epoch.EpochSeconds{ .secs = secs };
    const day = es.getEpochDay();
    const time = es.getDaySeconds();
    const yd = day.calculateYearDay();
    const md = yd.calculateMonthDay();

    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        yd.year,
        md.month.numeric(),
        md.day_index + 1,  // day_index is 0-based
        time.getHoursIntoDay(),
        time.getMinutesIntoHour(),
        time.getSecondsIntoMinute(),
    }) catch buf[0..0];
}
```

### Timeout Loop

```zig
fn waitWithTimeout(io: std.Io, timeout_ns: i96) !void {
    const start: std.Io.Clock.Timestamp = .now(io, .awake);

    while (true) {
        if (try checkCondition()) return;

        if (start.untilNow(io).raw.toNanoseconds() >= timeout_ns) return error.Timeout;

        try io.sleep(.fromMilliseconds(1), .awake);  // 1ms
    }
}
```

### Rate Limiter

```zig
const RateLimiter = struct {
    interval_ns: i96,
    last: ?std.Io.Clock.Timestamp,

    pub fn init(ops_per_second: u64) RateLimiter {
        return .{
            .interval_ns = std.time.ns_per_s / ops_per_second,
            .last = null,
        };
    }

    pub fn acquire(self: *RateLimiter, io: std.Io) !void {
        if (self.last) |last| {
            const elapsed_ns = last.untilNow(io).raw.toNanoseconds();
            if (elapsed_ns < self.interval_ns) {
                try io.sleep(.fromNanoseconds(self.interval_ns - elapsed_ns), .awake);
            }
        }
        self.last = .now(io, .awake);
    }
};
```

### Elapsed Time Formatting

```zig
fn formatElapsed(ns: i96) struct { value: i96, unit: []const u8 } {
    if (ns < std.time.ns_per_us) return .{ .value = ns, .unit = "ns" };
    if (ns < std.time.ns_per_ms) return .{ .value = @divTrunc(ns, std.time.ns_per_us), .unit = "us" };
    if (ns < std.time.ns_per_s) return .{ .value = @divTrunc(ns, std.time.ns_per_ms), .unit = "ms" };
    return .{ .value = @divTrunc(ns, std.time.ns_per_s), .unit = "s" };
}

// Usage
const result = formatElapsed(elapsed.raw.toNanoseconds());
std.debug.print("Elapsed: {d} {s}\n", .{ result.value, result.unit });
```

### Convert Between Epoch Systems

```zig
fn unixToWindows(unix_secs: i64) i64 {
    return unix_secs - std.time.epoch.windows;
}

fn windowsToUnix(windows_secs: i64) i64 {
    return windows_secs + std.time.epoch.windows;
}
```

## Notes

- Wall-clock functions are gone from `std.time`; use `Io.Clock.now(io, .real)` (or `std.c.clock_gettime` with no `Io`) — see migration section above
- `Io.Timestamp`/`Io.Duration` use signed `i96` nanoseconds internally
- `Io.Clock.Timestamp.now()` does not fail — an unsupported clock just has zero `resolution()`, it does not error
- `epoch.EpochSeconds` expects unsigned `u64` (use `@intCast` from a timestamp's `.toSeconds()`)
- Day and month indices in epoch module are 0-based
- For sleeping: `io.sleep(duration, clock)` (0.16, with `Io`) or `nanosleep` via `std.c.nanosleep` (0.16, no `Io` — `Thread.sleep` removed either way)
