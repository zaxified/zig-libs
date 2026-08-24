// SPDX-License-Identifier: MIT

//! Beacon acquisition + round arithmetic.
//!
//! The `drand` module is transport-agnostic by design: it parses and
//! BLS-verifies documents the CALLER fetched. This file is that caller —
//! `http`'s TLS client when online, a local file when offline. Every
//! document goes through `drand.parseInfo`/`parseRound` (+ `verifyRound`
//! at the call sites) no matter where it came from: the transport is
//! never the trust root, the chain public key inside `/info` is.

const std = @import("std");
const drand = @import("drand");
const datefmt = @import("datefmt");
const http = @import("http");

/// League of Entropy **quicknet** — the beacon `tlock` targets (3 s rounds,
/// signatures on G1). The hash names the chain and builds the request URL;
/// what signatures verify against is the chain PUBLIC KEY carried by `/info`.
pub const quicknet_hash_hex = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971";
pub const default_base_url = "https://api.drand.sh";

/// Same cap `drand`'s own parsers enforce; requesting more would only be
/// buffering bytes the parser is going to reject.
pub const max_doc_bytes = 64 * 1024;

pub const FetchError = error{
    /// The round's signature does not exist yet — the time lock working,
    /// not a failure. Measured: api.drand.sh answers a future round with
    /// **425 Too Early**; 404 is kept for mirrors that never learned it.
    RoundNotPublished,
    UnexpectedStatus,
};

fn httpGet(gpa: std.mem.Allocator, io: std.Io, url: []const u8) ![]u8 {
    var client = http.Client.init(io, gpa, .{});
    defer client.deinit();
    var res = try client.request(.get, url, .{});
    defer res.deinit();
    if (res.status == 425 or res.status == 404) return error.RoundNotPublished;
    if (res.status < 200 or res.status >= 300) return error.UnexpectedStatus;
    return res.readAllAlloc(gpa, max_doc_bytes);
}

/// `/info` document bytes: from `file_path` when given (offline / pinned
/// trust root), otherwise fetched from `<base>/<quicknet-hash>/info`.
pub fn infoDoc(gpa: std.mem.Allocator, io: std.Io, file_path: ?[]const u8, base: []const u8) ![]u8 {
    if (file_path) |p|
        return std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(max_doc_bytes));
    const url = try std.fmt.allocPrint(gpa, "{s}/{s}/info", .{ base, quicknet_hash_hex });
    defer gpa.free(url);
    return httpGet(gpa, io, url);
}

/// `/public/<round>` document bytes: from `file_path` when given, otherwise
/// fetched. A 404 comes back as `error.RoundNotPublished`.
pub fn roundDoc(gpa: std.mem.Allocator, io: std.Io, file_path: ?[]const u8, base: []const u8, round: u64) ![]u8 {
    if (file_path) |p|
        return std.Io.Dir.cwd().readFileAlloc(io, p, gpa, .limited(max_doc_bytes));
    const url = try std.fmt.allocPrint(gpa, "{s}/{s}/public/{d}", .{ base, quicknet_hash_hex, round });
    defer gpa.free(url);
    return httpGet(gpa, io, url);
}

/// First round whose signature is published at or after unix time `t`.
/// Round `r` publishes at `genesis + (r-1)*period`, so this is the round
/// to seal to for "unlock no earlier than `t`".
///
/// Every input here is untrusted — `info` comes from a `--chain-info` file or
/// a `--beacon` mirror, `t` from `--at` arithmetic — so this must not panic on
/// a hostile document. A zero `period_seconds` (which real quicknet never has)
/// would divide by zero; treat it as the 3 s quicknet period rather than
/// crash, and saturate every widening cast.
pub fn roundAtOrAfter(info: *const drand.ChainInfo, t: i64) u64 {
    const genesis: i64 = std.math.cast(i64, info.genesis_time) orelse std.math.maxInt(i64);
    if (t <= genesis) return 1;
    const period: u64 = if (info.period_seconds == 0) 3 else info.period_seconds;
    const dt: u64 = @intCast(t - genesis);
    // dt + period - 1 cannot overflow: dt <= i64::max and period is a modest
    // beacon cadence, but round up via u128 to stay panic-proof regardless.
    const rounds_elapsed: u128 = (@as(u128, dt) + period - 1) / period;
    return std.math.cast(u64, rounds_elapsed + 1) orelse std.math.maxInt(u64);
}

/// Unix time at which round `r`'s signature is published.
///
/// `round` is read straight off a capsule an attacker fully controls (the
/// envelope's `parse` does no range check), and `info` is untrusted too, so
/// this is computed in i128 and clamped: a round of 0 or near-`u64::max`, or a
/// giant `genesis_time`/`period_seconds`, yields a saturated timestamp, never
/// an overflow panic (in ReleaseSafe) or a silently wrapped value (in
/// ReleaseFast). A round of 0 does not exist on any drand chain — `readCapsule`
/// rejects it up front — but the arithmetic is safe even if it did not.
pub fn publishTime(info: *const drand.ChainInfo, round: u64) i64 {
    const rounds_before: u128 = if (round == 0) 0 else round - 1;
    const offset: u128 = rounds_before * info.period_seconds;
    const t: u128 = @as(u128, info.genesis_time) + offset;
    return std.math.cast(i64, t) orelse std.math.maxInt(i64);
}

/// Wall clock, seconds. `std.time`'s wall-clock helpers are gone in 0.16;
/// this is the same direct `clock_gettime` the other example apps use.
pub fn wallNow() i64 {
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
    return @intCast(ts.sec);
}

/// `1997-08-29 02:14:00 UTC` — `datefmt`'s civil-calendar core does the
/// date math; rendering stays here so the buffer is the caller's.
pub fn formatUtc(buf: []u8, unix: i64) []const u8 {
    const p = datefmt.unixToParts(unix);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2} UTC", .{
        @as(u32, @intCast(p.year)), p.month, p.day, p.hour, p.minute, p.second,
    }) catch unreachable;
}
