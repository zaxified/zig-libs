// SPDX-License-Identifier: MIT
//! Multithreaded compression of one stream (rust-brotli's
//! `compress_multi`; S2 analysis item C2, 2026-10-16): `compress` cuts the
//! input into jobs of `job_size` bytes, compresses them on up to `threads`
//! workers and joins the parts into one ordinary Brotli stream — any
//! RFC 7932 decoder reads it, nothing in it says it was made in parts.
//!
//! A job is a `Core` (`encoder.Core.startJob`) that sees the window before
//! its input as output already written: those positions go into its match
//! finder's tables, so copies reach back across the cut as in one pass,
//! static-dictionary words count from the stream's real position, and the
//! first literals' contexts are the bytes before them. Each job but the
//! last ends byte-aligned (an empty metadata meta-block where needed, as a
//! flush), so the parts join by concatenation; only the first writes the
//! window header, only the last the final meta-block. The decoder's one
//! state a job cannot know is the ring of the last four distances: a job
//! after the first writes no short code for an old distance until it has
//! written four of its own (`encoder.unknown_ring`).
//!
//! **The bytes depend on the input, the options and `job_size` only** —
//! never on `threads`, nor on which worker ran which job. An input of at
//! most one job is `compressWith`'s bytes. What it costs against one pass:
//! each job's first copies cannot use the ring, and its tables start from
//! the window's positions inserted one by one rather than from the parse.
//!
//! Memory: each worker holds one `Core` (its match finder's tables: up to
//! 4 MiB at `.q6`, 32 MiB at `.q9` for inputs of 1 MiB and more) plus its
//! jobs' output until the parts are joined. `gpa` must be thread-safe.
//! Workers are `io`'s concurrent tasks; where `io` has none to give
//! (`error.ConcurrencyUnavailable`), the calling thread runs the jobs
//! left. The calling thread is always one of the workers.
//!
//! A prefix dictionary (`CompressOptions.dictionary` /
//! `prepared_dictionary`) is not split: with one, the input is compressed
//! in one pass (`compressWith`).

const std = @import("std");
const encoder = @import("encoder.zig");
const Core = encoder.Core;
const CompressOptions = encoder.CompressOptions;

/// The smallest `ParallelOptions.job_size` (a smaller one counts as this):
/// below it a job's output is mostly its own cut.
pub const min_job_size: usize = 64 << 10;

pub const ParallelOptions = struct {
    /// Input bytes per job. The output depends on it (more, smaller jobs:
    /// more cuts). Null: twice the window, at least 1 MiB (`jobSize`) —
    /// each job inserts the window before it into its tables, so a job of
    /// two windows spends a third of its inserts on that; measured on 5.8
    /// and 8 MB inputs, 4 MiB jobs cost 0–9 % more CPU than one pass and
    /// at most +0.03 % of size, 1 MiB jobs 8–25 % and +0.08 % (SPEC,
    /// *Parallel compression*).
    job_size: ?usize = null,
    /// Workers at most, the calling thread one of them; null: the CPU
    /// count.
    threads: ?usize = null,
};

pub const Error = std.mem.Allocator.Error || std.Io.Cancelable;

/// `compressWith(gpa, input, opts)` on up to `par.threads` workers. Caller
/// owns the result.
pub fn compress(gpa: std.mem.Allocator, io: std.Io, input: []const u8, opts: CompressOptions, par: ParallelOptions) Error![]u8 {
    if (opts.dictionary.len != 0 or opts.prepared_dictionary != null) return encoder.compressWith(gpa, input, opts);
    const threads = par.threads orelse (std.Thread.getCpuCount() catch 1);
    const job = par.job_size orelse jobSize(encoder.windowBits(input.len, opts));
    return compressJobs(gpa, io, input, opts, @max(job, min_job_size), @max(threads, 1));
}

/// `ParallelOptions.job_size`'s default for a window of `wbits`.
pub fn jobSize(wbits: u5) usize {
    return @max(@as(usize, 1) << 20, @as(usize, 2) << wbits);
}

/// `compress` with any job size (the tests cut far smaller jobs than
/// `min_job_size`, which is where a cut's mistakes would show).
fn compressJobs(gpa: std.mem.Allocator, io: std.Io, input: []const u8, opts: CompressOptions, job_size: usize, threads: usize) Error![]u8 {
    std.debug.assert(job_size != 0);
    if (input.len <= job_size) return encoder.compressWith(gpa, input, opts);
    const n_jobs = std.math.divCeil(usize, input.len, job_size) catch unreachable;
    const outs = try gpa.alloc([]u8, n_jobs);
    defer gpa.free(outs);
    @memset(outs, &.{});
    defer for (outs) |o| gpa.free(o);

    var shared: Shared = .{
        .gpa = gpa,
        .input = input,
        .opts = opts,
        .wbits = encoder.windowBits(input.len, opts),
        .job_size = job_size,
        .outs = outs,
    };
    var group: std.Io.Group = .init;
    const workers = @min(threads, n_jobs);
    var started: usize = 1; // the calling thread
    while (started < workers) : (started += 1) {
        group.concurrent(io, Shared.work, .{&shared}) catch break;
    }
    shared.work();
    group.await(io) catch |e| {
        group.cancel(io);
        return e;
    };
    if (shared.failed.load(.acquire)) return error.OutOfMemory;

    var total: usize = 0;
    for (outs) |o| total += o.len;
    const result = try gpa.alloc(u8, total);
    var at: usize = 0;
    for (outs) |o| {
        @memcpy(result[at..][0..o.len], o);
        at += o.len;
    }
    return result;
}

const Shared = struct {
    gpa: std.mem.Allocator,
    input: []const u8,
    opts: CompressOptions,
    wbits: u5,
    job_size: usize,
    /// One per job, filled by whichever worker ran it.
    outs: [][]u8,
    next: std.atomic.Value(usize) = .init(0),
    /// A job ran out of memory: the others stop taking jobs.
    failed: std.atomic.Value(bool) = .init(false),

    /// Takes jobs in order until none is left; one `Core`, reinitialised
    /// per job (its tables kept while big enough).
    fn work(s: *Shared) void {
        var core: ?Core = null;
        defer if (core) |*c| c.deinit();
        while (!s.failed.load(.monotonic)) {
            const i = s.next.fetchAdd(1, .monotonic);
            if (i >= s.outs.len) return;
            s.outs[i] = s.job(&core, i) catch {
                s.failed.store(true, .release);
                return;
            };
        }
    }

    fn job(s: *Shared, core: *?Core, i: usize) std.mem.Allocator.Error![]u8 {
        const input = s.input;
        const start = i * s.job_size;
        const end = @min(input.len, start + s.job_size);
        // The window a copy may reach (the decoder's `max_backward`).
        const prefix = @min(start, (@as(usize, 1) << s.wbits) - 16);
        const data = input[start - prefix .. end];
        const size = encoder.tableSize(data.len, s.wbits);
        if (core.*) |*c| {
            try c.reinit(s.opts.effort, s.opts.block_size, s.wbits, size, input.len);
        } else {
            core.* = try Core.init(s.gpa, s.opts.effort, s.opts.block_size, s.wbits, size, input.len);
            core.*.?.keep_temp = true;
        }
        const c = &core.*.?;
        c.mode = s.opts.mode;
        c.startJob(data, prefix, start - prefix);
        if (i == 0) try c.writeHeader();
        const last = end == input.len;
        var off = prefix;
        while (off < data.len) {
            const block_end = off + @min(data.len - off, s.opts.block_size);
            try c.compressBlock(off, block_end, last and block_end == data.len);
            off = block_end;
        }
        if (last) try c.finish() else try c.flushToByte();
        return s.gpa.dupe(u8, c.w.buf.items);
    }
};

// ===========================================================================
// Tests

const testing = std.testing;
const decoder = @import("decoder.zig");
const corpus = @import("interop_corpus.zig");

const all_efforts = .{ encoder.Effort.q0, .q1, .q4, .q6, .q9, .q11 };

fn expectRoundTrip(input: []const u8, stream: []const u8, large_window: bool) !void {
    const back = try decoder.decompress(testing.allocator, stream, .{ .large_window = large_window, .max_output = input.len + 1 });
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, input, back);
}

/// Text with repeats far apart (copies across every cut), random runs
/// (stored blocks at a cut) and font-shaped binary (other distances).
fn mixed(gpa: std.mem.Allocator, n: usize) ![]u8 {
    const out = try gpa.alloc(u8, n);
    errdefer gpa.free(out);
    const font = try corpus.fontLike(gpa, 30_000, 3);
    defer gpa.free(font);
    var rng = std.Random.DefaultPrng.init(0x5eed);
    const r = rng.random();
    const words = [_][]const u8{ "brotli ", "window ", "the ", "distance ", "ring ", "meta-block ", "copy ", "literal ", "\n" };
    var i: usize = 0;
    while (i < n) {
        const kind = r.uintLessThan(u8, 10);
        const run = @min(n - i, 1 + r.uintLessThan(usize, 3_000));
        if (kind < 6) {
            var k: usize = 0;
            while (k < run) {
                const w = words[r.uintLessThan(usize, words.len)];
                const m = @min(w.len, run - k);
                @memcpy(out[i + k ..][0..m], w[0..m]);
                k += m;
            }
        } else if (kind < 8) {
            r.bytes(out[i..][0..run]);
        } else {
            const from = r.uintLessThan(usize, font.len - run);
            @memcpy(out[i..][0..run], font[from..][0..run]);
        }
        i += run;
    }
    return out;
}

test "parallel: one job is compressWith's bytes" {
    const gpa = testing.allocator;
    const input = try mixed(gpa, 50_000);
    defer gpa.free(input);
    inline for (all_efforts) |e| {
        const want = try encoder.compressWith(gpa, input, .{ .effort = e });
        defer gpa.free(want);
        const got = try compress(gpa, testing.io, input, .{ .effort = e }, .{ .threads = 4 });
        defer gpa.free(got);
        try testing.expectEqualSlices(u8, want, got);
    }
}

test "parallel: jobs of any size round-trip at every level, window, mode" {
    const gpa = testing.allocator;
    const input = try mixed(gpa, 90_000);
    defer gpa.free(input);
    // 1 000-byte jobs: dozens of cuts, most of them before a job has
    // written four distances of its own, inside the window.
    inline for (all_efforts) |e| {
        for ([_]usize{ 1_000, 7_777, 40_000 }) |js| {
            const s = try compressJobs(gpa, testing.io, input, .{ .effort = e }, js, 1);
            defer gpa.free(s);
            try expectRoundTrip(input, s, false);
        }
    }
    // Windows smaller and larger than a job; a large window; font mode;
    // small meta-blocks (several a job).
    const cases = [_]CompressOptions{
        .{ .effort = .q6, .window_bits = 10 },
        .{ .effort = .q9, .window_bits = 16 },
        .{ .effort = .q4, .window_bits = 24 },
        .{ .effort = .q6, .window_bits = 26 },
        .{ .effort = .q11, .window_bits = 12 },
        .{ .effort = .q6, .mode = .font },
        .{ .effort = .q1, .block_size = 3_000 },
        .{ .effort = .q9, .block_size = 5_000 },
    };
    for (cases) |o| {
        const s = try compressJobs(gpa, testing.io, input, o, 6_000, 1);
        defer gpa.free(s);
        try expectRoundTrip(input, s, (o.window_bits orelse 0) > encoder.max_window_bits);
    }
}

test "parallel: the bytes do not depend on the worker count (real threads)" {
    const gpa = testing.allocator;
    const input = try mixed(gpa, 200_000);
    defer gpa.free(input);
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    inline for (.{ encoder.Effort.q1, .q6, .q11 }) |e| {
        const one = try compressJobs(gpa, io, input, .{ .effort = e }, 16_384, 1);
        defer gpa.free(one);
        try expectRoundTrip(input, one, false);
        for ([_]usize{ 2, 3, 8 }) |t| {
            const many = try compressJobs(gpa, io, input, .{ .effort = e }, 16_384, t);
            defer gpa.free(many);
            try testing.expectEqualSlices(u8, one, many);
        }
    }
}

test "parallel: a cut costs little against one pass" {
    // The window's positions in the tables keep copies across a cut: with
    // them, 8 KiB jobs of repetitive text stay within a few percent of one
    // pass; without (`startJob` inserting nothing), every job would start
    // from an empty table.
    const gpa = testing.allocator;
    const input = try mixed(gpa, 120_000);
    defer gpa.free(input);
    const whole = try encoder.compressWith(gpa, input, .{ .effort = .q6 });
    defer gpa.free(whole);
    const parts = try compressJobs(gpa, testing.io, input, .{ .effort = .q6 }, 8_192, 1);
    defer gpa.free(parts);
    try testing.expect(parts.len * 100 < whole.len * 104);
}

test "parallel: a job that runs out of memory fails the call, nothing leaks" {
    const gpa = testing.allocator;
    const input = try mixed(gpa, 30_000);
    defer gpa.free(input);
    var fail_at: usize = 0;
    while (true) : (fail_at += 1) {
        var failing = testing.FailingAllocator.init(gpa, .{ .fail_index = fail_at });
        const r = compressJobs(failing.allocator(), testing.io, input, .{ .effort = .q4 }, 4_000, 1);
        if (r) |s| {
            defer failing.allocator().free(s);
            try expectRoundTrip(input, s, false);
            break;
        } else |e| try testing.expectEqual(error.OutOfMemory, e);
    }
}

test "parallel: a dictionary is compressed in one pass" {
    const gpa = testing.allocator;
    const input = try mixed(gpa, 40_000);
    defer gpa.free(input);
    const dict = input[1_000..9_000];
    const want = try encoder.compressWith(gpa, input, .{ .effort = .q6, .dictionary = dict });
    defer gpa.free(want);
    const got = try compress(gpa, testing.io, input, .{ .effort = .q6, .dictionary = dict }, .{ .job_size = 1, .threads = 4 });
    defer gpa.free(got);
    try testing.expectEqualSlices(u8, want, got);
}

test "parallel: the default job is twice the window, at least 1 MiB" {
    try testing.expectEqual(@as(usize, 1 << 20), jobSize(16));
    try testing.expectEqual(@as(usize, 1 << 20), jobSize(19));
    try testing.expectEqual(@as(usize, 4 << 20), jobSize(21));
    try testing.expectEqual(@as(usize, 32 << 20), jobSize(24));
}

// ── deterministic fuzz driver (BROTLI_FUZZ, harness "parallel") ─────────────
//
// An input of text runs, copies of earlier stretches (near and far: across
// the cuts), byte runs and random bytes, cut into jobs of 1..6 000 bytes at
// a random level, window, block size and mode; the joined stream must decode
// to the input. The jobs here are far smaller than `min_job_size` allows, so
// nearly every cut falls inside the window and before a job has written four
// distances of its own — where a mistake about the decoder's ring or the
// stream position would show.

const fuzz_driver = @import("testkit").fuzz.driver;

fn parallelHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [24 << 10]u8 = undefined;
    const efforts = [_]encoder.Effort{ .q0, .q1, .q4, .q6, .q9, .q11 };
    const effort = efforts[src.index(efforts.len)];
    const cap: u32 = if (effort == .q11) 6_000 else buf.len;
    const n: usize = src.valueRangeAtMost(u32, 0, cap);
    var i: usize = 0;
    while (i < n) {
        const run = @min(n - i, @as(usize, src.valueRangeAtMost(u16, 1, 2_000)));
        switch (src.valueRangeAtMost(u8, 0, 4)) {
            0 => src.bytes(buf[i..][0..run]),
            1 => @memset(buf[i..][0..run], src.value(u8)),
            2 => for (buf[i..][0..run]) |*b| {
                b.* = "abcd e\n"[src.index(7)];
            },
            // A copy of an earlier stretch (overlapping: byte by byte).
            else => if (i == 0) src.bytes(buf[i..][0..run]) else {
                const from = src.index(i);
                for (0..run) |k| buf[i + k] = buf[from + k];
            },
        }
        i += run;
    }
    const input = buf[0..n];
    const job: usize = src.valueRangeAtMost(u16, 1, 6_000);
    const large = src.valueRangeAtMost(u8, 0, 9) == 0;
    const wbits: u5 = if (large) src.valueRangeAtMost(u5, 25, encoder.max_large_window_bits) else src.valueRangeAtMost(u5, encoder.min_window_bits, encoder.max_window_bits);
    const block: usize = src.valueRangeAtMost(u16, 1, 20_000);
    const mode: encoder.Mode = if (src.value(bool)) .generic else .font;
    const opts: CompressOptions = .{ .effort = effort, .window_bits = wbits, .block_size = block, .mode = mode };

    const s = try compressJobs(gpa, testing.io, input, opts, job, 1);
    defer gpa.free(s);
    const back = decoder.decompress(gpa, s, .{ .large_window = large, .max_output = n + 1 }) catch |e| {
        std.debug.print("{t} {d} B, jobs of {d}, wbits {d}, blocks of {d}: {t}\n", .{ effort, n, job, wbits, block, e });
        return error.Disagree;
    };
    defer gpa.free(back);
    if (!std.mem.eql(u8, input, back)) return error.Disagree;
    if (n > job) fuzz_driver.hit("jobs") else fuzz_driver.hit("one_job");
    if (n > job and n - job > 3 * job) fuzz_driver.hit("four_jobs_or_more");
    if (large) fuzz_driver.hit("large_window");
}

test "fuzz driver: parallel jobs join into a stream that decodes (BROTLI_FUZZ)" {
    try fuzz_driver.run(parallelHarness, .{ .prefix = "BROTLI_FUZZ", .name = "parallel" });
}
