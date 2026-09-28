// SPDX-License-Identifier: BSD-3-Clause AND MIT
//! `zstd -b`: a port of libzstd 1.5.7's `programs/benchzstd.c` and
//! `benchfn.c` onto zig-libs' zstd module. The same measurement as the C
//! command -- the input cut into `-B` blocks, each compressed by a reused
//! context (`ZSTD_compress2`) and decompressed by a stream
//! (`ZSTD_decompressStream`), timed in runs of about a second until `-i`
//! seconds are spent, the fastest run kept -- and the same output, so the
//! two commands' lines can be set side by side. The bytes being the same,
//! the compressed sizes and ratios are equal; the speeds are what differ.
//!
//! Not here (yet): the synthetic inputs of `-b` without a file (lorem ipsum,
//! `-P#`).

const std = @import("std");
const zstd = @import("zstd");
const disp = @import("display.zig");
const synthetic = @import("synthetic.zig");
const fio = @import("fileio.zig");

const Io = std.Io;

pub const Mode = enum { both, decode_only };

/// `BMK_advancedParams_t`.
pub const Params = struct {
    mode: Mode = .both,
    nb_seconds: u32 = 3,
    block_size: usize = 0,
    target_cblock_size: u32 = 0,
    nb_workers: u32 = 0,
    additional_param: i32 = 0,
    ldm: bool = false,
    ldm_min_match: u32 = 0,
    ldm_hash_log: u32 = 0,
    ldm_bucket_size_log: u32 = 0,
    ldm_hash_rate_log: u32 = 0,
    literal_compression: zstd.Switch = .auto,
    row_match_finder: zstd.Switch = .auto,
};

/// `TIMELOOP_NANOSEC`, `MB_UNIT`, `BMK_RUNTEST_DEFAULT_MS`.
const ns_per_s: f64 = 1e9;
const mb_unit: f64 = 1_000_000;
const run_budget_ms = 1000;

/// `BMK_timedFnState_t`.
const TimedFn = struct {
    time_spent_ns: u64 = 0,
    time_budget_ns: u64,
    run_budget_ns: u64,
    fastest_ns_per_run: f64 = ns_per_s * 2_000_000_000,
    nb_loops: u32 = 1,

    fn init(total_ms: u32, run_ms: u32) TimedFn {
        const t = @max(total_ms, 1);
        const r = @min(@max(run_ms, 1), t);
        return .{ .time_budget_ns = @as(u64, t) * 1_000_000, .run_budget_ns = @as(u64, r) * 1_000_000 };
    }

    fn completed(t: *const TimedFn) bool {
        return t.time_spent_ns >= t.time_budget_ns;
    }
};

const Block = struct {
    src: []const u8,
    c_room: []u8,
    c_size: usize = 0,
    res: []u8,
};

const Ctx = struct {
    env: fio.Env,
    blocks: []Block,
    level: i32,
    params: *const Params,
    cp: fio.CParams,
    dict: ?[]const u8,
    compressor: zstd.Compressor,
    dstream: ?zstd.DecompressStream = null,
    cdict: ?zstd.CDict = null,
};

fn now(io: Io) i96 {
    return Io.Timestamp.now(io, .awake).nanoseconds;
}

/// The compression options `BMK_initCCtx` sets (`nbWorkers` 1 means 0).
fn compressOptions(c: *Ctx) zstd.Options {
    const nz = struct {
        fn f(v: u32) ?u32 {
            return if (v == 0) null else v;
        }
    }.f;
    return .{
        .level = c.level,
        .advanced = .{
            // libzstd clamps the number of workers where the module refuses it
            .nb_workers = if (c.params.nb_workers == 1) 0 else @min(c.params.nb_workers, zstd.limits.nb_workers_max),
            .row_match_finder = c.params.row_match_finder,
            .long_distance_matching = if (c.params.ldm) .enable else .auto,
            .ldm_min_match = nz(c.params.ldm_min_match),
            .ldm_hash_log = nz(c.params.ldm_hash_log),
            .ldm_bucket_size_log = nz(c.params.ldm_bucket_size_log),
            .ldm_hash_rate_log = nz(c.params.ldm_hash_rate_log),
            .window_log = nz(c.cp.window_log),
            .hash_log = nz(c.cp.hash_log),
            .chain_log = nz(c.cp.chain_log),
            .search_log = nz(c.cp.search_log),
            .min_match = nz(c.cp.min_match),
            .target_length = nz(c.cp.target_length),
            .literal_compression = c.params.literal_compression,
            .strategy = fio.strategyOf(c.cp.strategy) catch unreachable, // checkParams

            .target_c_block_size = nz(c.params.target_cblock_size),
        },
        .dictionary = if (c.cdict) |*cd| .{ .cdict = cd } else .none,
    };
}

/// The bounds `BMK_initCCtx`'s `CHECK_Z(ZSTD_CCtx_setParameter(...))`
/// calls enforce, in their order, each failure named by the call's text as
/// the C command prints it.
fn checkParams(c: *Ctx) void {
    const L = zstd.limits;
    const p = c.params;
    const in = struct {
        /// 0 is "not set" (`ZSTD_c_ldm*`, the cParams, the strategy)
        fn opt(v: u32, lo: u32, hi: u32) bool {
            return v == 0 or (v >= lo and v <= hi);
        }
    }.opt;
    const checks = [_]struct { ok: bool, call: []const u8 }{
        .{ .ok = in(p.ldm_min_match, L.ldm_min_match_min, L.ldm_min_match_max), .call = "ZSTD_CCtx_setParameter(ctx, ZSTD_c_ldmMinMatch, adv->ldmMinMatch)" },
        .{ .ok = in(p.ldm_hash_log, L.hash_log_min, L.ldm_hash_log_max), .call = "ZSTD_CCtx_setParameter(ctx, ZSTD_c_ldmHashLog, adv->ldmHashLog)" },
        .{ .ok = in(p.ldm_bucket_size_log, L.ldm_bucket_size_log_min, L.ldm_bucket_size_log_max), .call = "ZSTD_CCtx_setParameter( ctx, ZSTD_c_ldmBucketSizeLog, adv->ldmBucketSizeLog)" },
        .{ .ok = p.ldm_hash_rate_log <= L.ldm_hash_rate_log_max, .call = "ZSTD_CCtx_setParameter( ctx, ZSTD_c_ldmHashRateLog, adv->ldmHashRateLog)" },
        .{ .ok = in(c.cp.window_log, L.window_log_min, L.window_log_max), .call = "ZSTD_CCtx_setParameter( ctx, ZSTD_c_windowLog, (int)comprParams->windowLog)" },
        .{ .ok = in(c.cp.hash_log, L.hash_log_min, L.hash_log_max), .call = "ZSTD_CCtx_setParameter( ctx, ZSTD_c_hashLog, (int)comprParams->hashLog)" },
        .{ .ok = in(c.cp.chain_log, L.chain_log_min, L.chain_log_max), .call = "ZSTD_CCtx_setParameter( ctx, ZSTD_c_chainLog, (int)comprParams->chainLog)" },
        .{ .ok = in(c.cp.search_log, L.search_log_min, L.search_log_max), .call = "ZSTD_CCtx_setParameter( ctx, ZSTD_c_searchLog, (int)comprParams->searchLog)" },
        .{ .ok = in(c.cp.min_match, L.min_match_min, L.min_match_max), .call = "ZSTD_CCtx_setParameter( ctx, ZSTD_c_minMatch, (int)comprParams->minMatch)" },
        .{ .ok = c.cp.target_length <= L.target_length_max, .call = "ZSTD_CCtx_setParameter( ctx, ZSTD_c_targetLength, (int)comprParams->targetLength)" },
        .{ .ok = c.cp.strategy <= @intFromEnum(zstd.Strategy.btultra2), .call = "ZSTD_CCtx_setParameter( ctx, ZSTD_c_strategy, (int)comprParams->strategy)" },
        .{ .ok = p.target_cblock_size <= L.target_length_max, .call = "ZSTD_CCtx_setParameter( ctx, ZSTD_c_targetCBlockSize, (int)adv->targetCBlockSize)" },
    };
    for (checks) |k| if (!k.ok) {
        disp.always("Error : {s} failed : {s} \n", .{ k.call, fio.zstdErrorName(error.ParameterOutOfBound) });
        disp.flush();
        std.process.exit(1);
    };
}

/// `BMK_initCCtx`: the context reset (it keeps its workspace, as
/// `ZSTD_CCtx_reset` does -- `Compressor` gives every frame a fresh
/// context's bytes anyway), and the dictionary digested once for the run
/// (`ZSTD_CCtx_loadDictionary`, digested at the run's first frame).
fn initCompress(c: *Ctx) void {
    checkParams(c);
    if (c.cdict) |*cd| cd.deinit();
    c.cdict = null;
    // as `ZSTD_initLocalDict` digests it: the context's level and
    // parameters, content type auto
    if (c.dict) |d| c.cdict = zstd.CDict.initAdvanced(c.env.gpa, d, .{ .level = c.level, .advanced = compressOptions(c).advanced }) catch |e|
        fio.fatal(1, "{s}", .{fio.zstdErrorName(e)});
}

/// `BMK_initDCtx`: the context reset, keeping its buffers; with a
/// dictionary, a new stream -- `ZSTD_DCtx_loadDictionary` digests it again
/// at every run.
fn initDecompress(c: *Ctx) void {
    if (c.dstream) |*s| {
        if (c.dict == null) {
            s.reset();
            return;
        }
        s.deinit();
    }
    c.dstream = zstd.DecompressStream.init(c.env.gpa, .{ .dictionary = c.dict }) catch |e|
        fio.fatal(1, "{s}", .{fio.zstdErrorName(e)});
}

/// `local_defaultDecompress`: the stream until the frame is flushed.
fn decompressBlock(s: *zstd.DecompressStream, src: []const u8, dst: []u8) !usize {
    var in: zstd.InBuffer = .{ .src = src };
    var out: zstd.OutBuffer = .{ .dst = dst };
    var more: usize = 1;
    while (more != 0) {
        if (out.pos == out.dst.len) return error.DstSizeTooSmall;
        more = try s.decompressStream(&out, &in);
    }
    return out.pos;
}

const Which = enum { compress, decompress };

/// `BMK_benchFunction`: `nb_loops` passes over every block, timed; the
/// returns of the first pass summed. Null on an error.
fn benchFunction(c: *Ctx, which: Which, nb_loops_in: u32) ?struct { ns_per_run: f64, sum: usize } {
    const nb_loops = @max(nb_loops_in, 1);
    for (c.blocks) |b| @memset(if (which == .compress) b.c_room else b.res, 0xE5);
    var sum: usize = 0;
    const start = now(c.env.io);
    if (which == .compress) initCompress(c) else initDecompress(c);
    const opts = if (which == .compress) compressOptions(c) else undefined;
    for (0..nb_loops) |loop| {
        for (c.blocks, 0..) |*b, i| {
            const r = switch (which) {
                .compress => c.compressor.compress(b.c_room, b.src, opts),
                .decompress => decompressBlock(&c.dstream.?, b.c_room[0..b.c_size], b.res),
            } catch |e| {
                if (loop == 0) {
                    disp.at(1, "Function benchmark failed on block {d} (of size {d}) with error {s}", .{ i, b.src.len, @errorName(e) });
                    return null;
                }
                continue;
            };
            if (loop == 0) {
                if (which == .compress) b.c_size = r;
                sum += r;
            }
        }
    }
    const total: f64 = @floatFromInt(now(c.env.io) - start);
    return .{ .ns_per_run = total / @as(f64, @floatFromInt(nb_loops)), .sum = sum };
}

/// `BMK_benchTimedFn`: runs until one lasts at least half the run budget;
/// the fastest so far is the answer.
fn benchTimed(c: *Ctx, which: Which, t: *TimedFn) ?struct { ns_per_run: f64, sum: usize } {
    const run_min_ns = t.run_budget_ns / 2;
    while (true) {
        const r = benchFunction(c, which, t.nb_loops) orelse return null;
        const loop_ns = r.ns_per_run * @as(f64, @floatFromInt(t.nb_loops));
        t.time_spent_ns += @intFromFloat(loop_ns);
        if (loop_ns > @as(f64, @floatFromInt(t.run_budget_ns)) / 50) {
            const fastest = @min(t.fastest_ns_per_run, r.ns_per_run);
            t.nb_loops = @as(u32, @intFromFloat(@as(f64, @floatFromInt(t.run_budget_ns)) / fastest)) + 1;
        } else {
            t.nb_loops *= 10;
        }
        if (loop_ns < @as(f64, @floatFromInt(run_min_ns))) continue;
        if (r.ns_per_run < t.fastest_ns_per_run) t.fastest_ns_per_run = r.ns_per_run;
        return .{ .ns_per_run = t.fastest_ns_per_run, .sum = r.sum };
    }
}

/// `%-17.17s`: the last 17 characters were already kept; pad or cut to 17.
fn name17(w: *std.Io.Writer, name: []const u8) void {
    disp.left(w, name[0..@min(name.len, 17)], 17) catch {};
}

fn progress(w: *std.Io.Writer, mark: []const u8, name: []const u8, src_size: usize, c_size: ?usize, ratio: f64, c_speed: u64, d_speed: ?u64) void {
    var b: [24]u8 = undefined;
    w.writeAll(mark) catch {};
    w.writeAll("-") catch {};
    name17(w, name);
    w.writeAll(" :") catch {};
    disp.right(w, std.fmt.bufPrint(&b, "{d}", .{src_size}) catch unreachable, 10) catch {};
    w.writeAll(" ->") catch {};
    if (c_size) |cs| {
        disp.right(w, std.fmt.bufPrint(&b, "{d}", .{cs}) catch unreachable, 10) catch {};
        const digits: u8 = 1 + @as(u8, @intFromBool(ratio < 100)) + @as(u8, @intFromBool(ratio < 10));
        w.writeAll(" (x") catch {};
        disp.fixed(w, ratio, 5, digits) catch {};
        w.writeAll("), ") catch {};
        const cs_mb = @as(f64, @floatFromInt(c_speed)) / mb_unit;
        disp.fixed(w, cs_mb, 6, if (@as(f64, @floatFromInt(c_speed)) < 10 * mb_unit) 2 else 1) catch {};
        if (d_speed) |ds| {
            w.writeAll(" MB/s, ") catch {};
            disp.fixed(w, @as(f64, @floatFromInt(ds)) / mb_unit, 6, 1) catch {};
            w.writeAll(" MB/s\r") catch {};
        } else w.writeAll(" MB/s \r") catch {};
    } else w.writeAll(" \r") catch {};
    w.flush() catch {};
}

/// `BMK_benchMemAdvancedNoAlloc` for one level: 0 ok, else the error code.
fn benchMem(env: fio.Env, src_in: []const u8, file_sizes: []const usize, level: i32, cp: fio.CParams, dict: ?[]const u8, name_in: []const u8, params: *const Params) u8 {
    const gpa = env.gpa;
    const name = if (name_in.len > 17) name_in[name_in.len - 17 ..] else name_in;
    const src = src_in;
    var src_size = src.len;
    var ratio: f64 = 0;
    var c_size: usize = 0;
    // decode-only: the inputs are frames; what they decode to is the size
    if (params.mode == .decode_only) {
        var total: u64 = 0;
        var off: usize = 0;
        for (file_sizes) |fs| {
            const d = zstd.findDecompressedSize(src[off..][0..fs]) catch {
                disp.at(1, "Error {d} : {s} \n", .{ 32, "Error while trying to assess decompressed size: data may be invalid" });
                return 32;
            } orelse {
                disp.at(1, "Error {d} : {s} \n", .{ 32, "Decompressed size cannot be determined: cannot benchmark" });
                return 32;
            };
            total += d;
            off += fs;
        }
        c_size = src.len;
        src_size = @intCast(total);
        ratio = @as(f64, @floatFromInt(src_size)) / @as(f64, @floatFromInt(c_size));
    }
    const block_size: usize = (if (params.block_size >= 32 and params.mode != .decode_only) params.block_size else src_size) + @intFromBool(src_size == 0);

    // the blocks: per file, cut to block_size (decode-only: one per file)
    var blocks: std.ArrayList(Block) = .empty;
    defer blocks.deinit(gpa);
    var c_total: usize = 0;
    {
        var off: usize = 0;
        for (file_sizes) |fs| {
            var remaining = fs;
            const nb: usize = if (params.mode == .decode_only) 1 else (remaining + block_size - 1) / block_size;
            for (0..nb) |_| {
                const n = if (params.mode == .decode_only) remaining else @min(remaining, block_size);
                blocks.append(gpa, .{ .src = src[off..][0..n], .c_room = &.{}, .res = &.{} }) catch fio.fatal(31, "allocation error : not enough memory", .{});
                c_total += if (params.mode == .decode_only) n else zstd.compressBound(n);
                off += n;
                remaining -= n;
            }
        }
    }
    const c_buf = gpa.alloc(u8, c_total + 1) catch fio.fatal(31, "allocation error : not enough memory", .{});
    defer gpa.free(c_buf);
    const res_buf = gpa.alloc(u8, src_size + 1) catch fio.fatal(31, "allocation error : not enough memory", .{});
    defer gpa.free(res_buf);
    {
        var co: usize = 0;
        var ro: usize = 0;
        for (blocks.items) |*b| {
            const room = if (params.mode == .decode_only) b.src.len else zstd.compressBound(b.src.len);
            b.c_room = c_buf[co..][0..room];
            co += room;
            const rs: usize = if (params.mode == .decode_only) @intCast((zstd.findDecompressedSize(b.src) catch unreachable).?) else b.src.len;
            b.res = res_buf[ro..][0..rs];
            ro += rs;
            if (params.mode == .decode_only) {
                @memcpy(b.c_room, b.src);
                b.c_size = b.src.len;
            }
        }
    }

    var ctx: Ctx = .{ .env = env, .blocks = blocks.items, .level = level, .params = params, .cp = cp, .dict = dict, .compressor = .init(gpa) };
    defer {
        ctx.compressor.deinit();
        if (ctx.dstream) |*s| s.deinit();
        if (ctx.cdict) |*cd| cd.deinit();
    }

    const out = disp.out();
    const crc_orig: u64 = if (params.mode == .decode_only) 0 else std.hash.XxHash64.hash(0, src);
    const marks = [_][]const u8{ " |", " /", " =", " \\" };
    var mark: usize = 0;
    var tc: TimedFn = .init(params.nb_seconds * 1000, run_budget_ms);
    var td: TimedFn = .init(params.nb_seconds * 1000, run_budget_ms);
    var c_done = params.mode == .decode_only;
    var d_done = false;
    var c_speed: u64 = 0;
    var d_speed: u64 = 0;
    if (disp.level >= 2) {
        out.writeAll("\r" ++ " " ** 70 ++ "\r") catch {};
        progress(out, marks[0], name, src_size, null, 0, 0, null);
    }
    while (!(c_done and d_done)) {
        if (!c_done) {
            const r = benchTimed(&ctx, .compress, &tc) orelse {
                disp.at(1, "Error {d} : {s} \n", .{ 30, "compression error" });
                return 30;
            };
            c_size = r.sum;
            ratio = @as(f64, @floatFromInt(src_size)) / @as(f64, @floatFromInt(c_size));
            const s: u64 = @intFromFloat(@as(f64, @floatFromInt(src_size)) * ns_per_s / r.ns_per_run);
            if (s > c_speed) c_speed = s;
            if (disp.level >= 2) progress(out, marks[mark], name, src_size, c_size, ratio, c_speed, null);
            c_done = tc.completed();
        }
        if (!d_done) {
            const r = benchTimed(&ctx, .decompress, &td) orelse {
                disp.at(1, "Error {d} : {s} \n", .{ 30, "decompression error" });
                return 30;
            };
            const s: u64 = @intFromFloat(@as(f64, @floatFromInt(src_size)) * ns_per_s / r.ns_per_run);
            if (s > d_speed) d_speed = s;
            if (disp.level >= 2) progress(out, marks[mark], name, src_size, c_size, ratio, c_speed, d_speed);
            d_done = td.completed();
        }
        mark = (mark + 1) % marks.len;
    }

    const crc_check = std.hash.XxHash64.hash(0, res_buf[0..src_size]);
    if (params.mode == .both and crc_orig != crc_check) {
        disp.always("!!! WARNING !!! ", .{});
        disp.right(disp.err(), name, 14) catch {};
        disp.always(" : Invalid Checksum : {x} != {x}   \n", .{ @as(u32, @truncate(crc_orig)), @as(u32, @truncate(crc_check)) });
    }
    if (disp.level == 1) {
        var b: [24]u8 = undefined;
        out.writeAll("-") catch {};
        disp.left(out, std.fmt.bufPrint(&b, "{d}", .{level}) catch unreachable, 3) catch {};
        disp.right(out, std.fmt.bufPrint(&b, "{d}", .{c_size}) catch unreachable, 11) catch {};
        out.writeAll(" (") catch {};
        disp.fixed(out, ratio, 5, 3) catch {};
        out.writeAll(") ") catch {};
        disp.fixed(out, @as(f64, @floatFromInt(c_speed)) / mb_unit, 6, 2) catch {};
        out.writeAll(" MB/s ") catch {};
        disp.fixed(out, @as(f64, @floatFromInt(d_speed)) / mb_unit, 6, 1) catch {};
        out.print(" MB/s  {s}", .{name}) catch {};
        if (params.additional_param != 0) out.print(" (param={d})", .{params.additional_param}) catch {};
        out.writeAll("\n") catch {};
    }
    if (disp.level >= 2) {
        var b: [16]u8 = undefined;
        disp.right(out, std.fmt.bufPrint(&b, "{d}", .{level}) catch unreachable, 2) catch {};
        out.writeAll("#\n") catch {};
    }
    out.flush() catch {};
    return 0;
}

/// `BMK_benchCLevels`.
fn benchLevels(env: fio.Env, src: []const u8, file_sizes: []const usize, start: i32, end: i32, cp: fio.CParams, dict: ?[]const u8, display_name: []const u8, params: *const Params) u8 {
    const base = if (std.mem.lastIndexOfScalar(u8, display_name, '/')) |i| display_name[i + 1 ..] else display_name;
    if (end > zstd.max_level) {
        disp.at(1, "Invalid Compression Level \n", .{});
        return 15;
    }
    if (end < start) {
        disp.at(1, "Invalid Compression Level Range \n", .{});
        return 15;
    }
    if (disp.level == 1 and params.additional_param == 0) {
        const out = disp.out();
        out.print("bench {s} {s}: input {d} bytes, {d} seconds, {d} KB blocks\n", .{ "1.5.7", "", src.len, params.nb_seconds, params.block_size >> 10 }) catch {};
        out.flush() catch {};
    }
    var level = start;
    while (level <= end) : (level += 1) {
        if (benchMem(env, src, file_sizes, level, cp, dict, base, params) != 0) return 1;
    }
    return 0;
}

/// `BMK_benchFilesAdvanced`: the files read into one buffer (directories
/// and unknown sizes skipped), the dictionary (at most 64 MiB), then the
/// levels.
pub fn benchFiles(env: fio.Env, names: []const []const u8, dict_name: ?[]const u8, start: i32, end: i32, cp: fio.CParams, params: *const Params) u8 {
    const gpa = env.gpa;
    if (end > zstd.max_level) {
        disp.at(1, "Invalid Compression Level", .{});
        return 14;
    }
    var dict: ?[]u8 = null;
    defer if (dict) |d| gpa.free(d);
    if (dict_name) |dn| {
        const st = fio.stat(env, dn) orelse {
            disp.at(1, "error loading {s} : {s} \n", .{ dn, "No such file or directory" });
            disp.at(1, "benchmark aborted", .{});
            return 17;
        };
        if (st.size > 64 << 20) {
            disp.at(1, "dictionary file {s} too large", .{dn});
            return 18;
        }
        dict = Io.Dir.cwd().readFileAlloc(env.io, dn, gpa, .limited(64 << 20)) catch {
            disp.at(1, "Error {d} : cannot open file {s} \n", .{ 10, dn });
            return 10;
        };
    }
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    const sizes = gpa.alloc(usize, names.len) catch fio.fatal(16, "not enough memory for fileSizes", .{});
    defer gpa.free(sizes);
    for (names, 0..) |n, i| {
        sizes[i] = 0;
        const st = fio.stat(env, n);
        if (st != null and st.?.kind == .directory) {
            disp.at(2, "Ignoring {s} directory...       \n", .{n});
            continue;
        }
        if (st == null or st.?.kind != .file) {
            disp.at(2, "Cannot evaluate size of {s}, ignoring ... \n", .{n});
            continue;
        }
        if (disp.level >= 2) {
            disp.out().print("Loading {s}...       \r", .{n}) catch {};
            disp.out().flush() catch {};
        }
        const data = Io.Dir.cwd().readFileAlloc(env.io, n, gpa, .unlimited) catch {
            disp.at(1, "Error {d} : cannot open file {s} \n", .{ 10, n });
            return 10;
        };
        defer gpa.free(data);
        buf.appendSlice(gpa, data) catch fio.fatal(20, "not enough memory for srcBuffer", .{});
        sizes[i] = data.len;
    }
    var mf: [20]u8 = undefined;
    const display_name = if (names.len > 1) std.fmt.bufPrint(&mf, " {d} files", .{names.len}) catch unreachable else names[0];
    return benchLevels(env, buf.items, sizes, start, end, cp, dict, display_name, params);
}

/// `BMK_syntheticTest`: lorem ipsum, or with a compressibility (`-P#`)
/// datagen's data, of the block size or 10 MB.
pub fn syntheticTest(env: fio.Env, compressibility: ?f64, start: i32, end: i32, cp: fio.CParams, params: *const Params) u8 {
    const size: usize = if (params.block_size != 0) params.block_size else 10_000_000;
    const src = env.gpa.alloc(u8, size) catch {
        disp.at(1, "allocation error : not enough memory \n", .{});
        return 16;
    };
    defer env.gpa.free(src);
    var name_buf: [20]u8 = undefined;
    var name: []const u8 = "Lorem ipsum";
    if (compressibility) |c| {
        synthetic.datagen(src, c, 0);
        name = std.fmt.bufPrint(&name_buf, "Synthetic {d}%", .{@as(u32, @intFromFloat(c * 100))}) catch unreachable;
    } else synthetic.lorem(src, 0);
    return benchLevels(env, src, &.{size}, start, end, cp, null, name, params);
}
