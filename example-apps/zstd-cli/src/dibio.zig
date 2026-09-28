// SPDX-License-Identifier: BSD-3-Clause AND MIT
//! `zstd --train`: a port of libzstd 1.5.7's `programs/dibio.c` over the
//! zstd module's `dict_builder` (cover and fastCover, with and without the
//! optimizer). The legacy trainer is not in the module, so `--train-legacy`
//! is refused by name (main.zig). The files are shuffled, loaded as samples
//! (whole, up to 128 KiB each, or cut into `-B#` blocks) and the trainer's
//! messages go to stderr at the command's display level, as in C.

const std = @import("std");
const Io = std.Io;
const zstd = @import("zstd");
const disp = @import("display.zig");
const fio = @import("fileio.zig");

const db = zstd.dict_builder;
const Env = fio.Env;

/// `SAMPLESIZE_MAX`.
const sample_size_max = 128 << 10;
/// `MEMMULT`, `COVER_MEMMULT`, `FASTCOVER_MEMMULT`.
const cover_memmult = 9;
const fastcover_memmult = 1;
/// `g_maxMemory` (64-bit).
const max_memory: u64 = (512 << 20) << @sizeOf(usize);
/// `MAX_SAMPLES_SIZE`.
const max_samples_size: u64 = 2 << 30;

/// Which trainer, and its parameters as the command line gave them.
pub const Method = union(enum) {
    cover: Params,
    fast_cover: Params,
};

/// `ZDICT_cover_params_t` / `ZDICT_fastCover_params_t` as zstdcli.c fills
/// them: 0 is "not given" (the optimizer's default).
pub const Params = struct {
    k: u32 = 0,
    d: u32 = 0,
    f: u32 = 0,
    steps: u32 = 0,
    split_point: f64 = 0,
    accel: u32 = 0,
    /// `shrinkDict` / `shrinkDictMaxRegression`: parsed, and unused by
    /// libzstd 1.5.7's trainers (its optimizers pass 0), as here.
    shrink: bool = false,
    shrink_max_regression: u32 = 0,

    /// `defaultFastCoverParams`: `--train` without a method.
    pub const default_fast_cover: Params = .{ .d = 8, .f = 20, .steps = 4, .split_point = 0.75, .accel = 1, .shrink_max_regression = 1 };
};

/// `DISPLAYLEVEL` with dibio's own level (the command's).
fn at(l: i32, comptime fmt: []const u8, args: anytype) void {
    disp.at(l, fmt, args);
}

/// dibio's `EXM_THROW`: `Error N : ...`, then exit.
fn throw(code: u8, comptime fmt: []const u8, args: anytype) noreturn {
    disp.always("Error {d} : " ++ fmt ++ "\n", .{code} ++ args);
    disp.flush();
    std.process.exit(code);
}

/// `DiB_getFileSize`: null unless a regular file.
fn fileSize(env: Env, name: []const u8) ?u64 {
    const st = fio.stat(env, name) orelse return null;
    return if (st.kind == .file) st.size else null;
}

/// `DiB_rand`.
fn rand(src: *u32) u32 {
    const prime1: u32 = 2654435761;
    const prime2: u32 = 2246822519;
    var r = src.*;
    r *%= prime1;
    r ^= prime2;
    r = std.math.rotl(u32, r, 13);
    src.* = r;
    return r >> 5;
}

/// `DiB_shuffle`: a fixed seed, so the same files give the same order.
fn shuffle(names: [][]const u8) void {
    var seed: u32 = 0xFD2FB528;
    if (names.len == 0) return;
    var i: usize = names.len - 1;
    while (i > 0) : (i -= 1) {
        const j = rand(&seed) % @as(u32, @intCast(i + 1));
        std.mem.swap([]const u8, &names[j], &names[i]);
    }
}

/// `DiB_findMaxMem`: the size rounded up to 8 MiB, plus 8 MiB, at most
/// `g_maxMemory`, less the 8 MiB step taken after the first allocation
/// that succeeds -- here the first always does.
fn findMaxMem(required_in: u64) u64 {
    const step: u64 = 8 << 20;
    var required = ((required_in >> 23) + 1) << 23;
    required += step;
    if (required > max_memory) required = max_memory;
    return required - step;
}

const FileStats = struct {
    total_size_to_load: i64 = 0,
    nb_samples: usize = 0,
    one_sample_too_large: bool = false,
};

/// `DiB_fileStats`.
fn fileStats(env: Env, names: []const []const u8, chunk_size: usize) FileStats {
    var fs: FileStats = .{};
    for (names) |n| {
        // unknown: -1, which counts as it does in C
        const size: i64 = if (fileSize(env, n)) |s| @intCast(s) else -1;
        if (size == 0) {
            at(3, "Sample file '{s}' has zero size, skipping...\n", .{n});
            continue;
        }
        if (chunk_size > 0) {
            const c: i64 = @intCast(chunk_size);
            fs.nb_samples += @intCast(@divTrunc(size + c - 1, c));
            fs.total_size_to_load += size;
        } else {
            if (size > sample_size_max) {
                fs.one_sample_too_large = fs.one_sample_too_large or size > 2 * sample_size_max;
                at(3, "Sample file '{s}' is too large, limiting to {d} KB\n", .{ n, sample_size_max / 1024 });
            }
            fs.nb_samples += 1;
            fs.total_size_to_load += @min(size, sample_size_max);
        }
    }
    at(4, "Found training data {d} files, {d} KB, {d} samples\n", .{ names.len, @as(i32, @truncate(@divTrunc(fs.total_size_to_load, 1024))), fs.nb_samples });
    return fs;
}

/// `DISPLAYUPDATE(2, ...)`: the first message, then at most every 1/6 s.
const Update = struct {
    last: ?i96 = null,

    fn show(u: *Update, io: Io, comptime fmt: []const u8, args: anytype) void {
        if (disp.level < 2) return;
        const now = Io.Timestamp.now(io, .awake).nanoseconds;
        if (u.last) |l| if (now - l <= std.time.ns_per_s / 6 and disp.level < 4) return;
        u.last = now;
        disp.always(fmt, args);
    }
};

/// `DiB_loadFiles`: samples into `buffer` (whole files up to 128 KiB, or
/// `chunk_size` blocks) until it or `sizes` is full. Returns the samples
/// loaded; `loaded` is their total.
fn loadFiles(env: Env, buffer: []u8, loaded: *usize, sizes: []usize, names: []const []const u8, chunk_size: usize) usize {
    var total: usize = 0;
    var nb: usize = 0;
    var update: Update = .{};
    var i: usize = 0;
    while (nb < sizes.len and i < names.len) : (i += 1) {
        const name = names[i];
        const size = fileSize(env, name) orelse continue;
        if (size == 0) continue;
        var file = Io.Dir.cwd().openFile(env.io, name, .{}) catch |e| throw(10, "zstd: dictBuilder: {s} {s} ", .{ name, fio.strerror(e) });
        defer file.close(env.io);
        update.show(env.io, "Loading {s}...       \r", .{name});
        const limit: u64 = if (chunk_size > 0) chunk_size else sample_size_max;
        var file_loaded: usize = @intCast(@min(size, limit));
        if (total + file_loaded > buffer.len) break;
        var r = file.readerStreaming(env.io, &.{});
        r.interface.readSliceAll(buffer[total..][0..file_loaded]) catch throw(11, "Pb reading {s}", .{name});
        sizes[nb] = file_loaded;
        nb += 1;
        total += file_loaded;
        if (chunk_size > 0) {
            while (file_loaded < size and nb < sizes.len) {
                const chunk: usize = @intCast(@min(size - file_loaded, chunk_size));
                if (total + chunk > buffer.len) break;
                r.interface.readSliceAll(buffer[total..][0..chunk]) catch throw(11, "Pb reading {s}", .{name});
                sizes[nb] = chunk;
                nb += 1;
                total += chunk;
                file_loaded += chunk;
            }
        }
    }
    at(2, "\r{s: >79}\r", .{""});
    at(4, "Loaded {d} KB total training data, {d} nb samples \n", .{ total / 1024, nb });
    loaded.* = total;
    return nb;
}

/// `ZDICT_getErrorName` for what the trainers return.
fn errorName(e: anyerror) []const u8 {
    return switch (e) {
        error.ParameterOutOfBound => "Parameter is out of bound",
        error.SrcSizeWrong => "Src size is incorrect",
        error.DstSizeTooSmall => "Destination buffer is too small",
        error.DictionaryCreationFailed => "Cannot create Dictionary from provided samples",
        error.OutOfMemory, error.MemoryLimitExceeded => "Allocation error : not enough memory",
        // no candidate finalized: libzstd's best is still its initial error
        else => "Error (generic)",
    };
}

/// `DiB_trainFromFiles`: 0 on success.
pub fn trainFromFiles(env: Env, dict_name: []const u8, max_dict_size: usize, names: [][]const u8, chunk_size: usize, method: Method, level: i32, dict_id: u32, nb_threads: u32, mem_limit: u32) u8 {
    const gpa = env.gpa;
    const dict_buffer = gpa.alloc(u8, max_dict_size) catch throw(12, "not enough memory for DiB_trainFiles", .{});
    defer gpa.free(dict_buffer);
    // the trainers' `notificationLevel`: the display level as an unsigned
    const notify: db.Notify = .{ .level = @bitCast(disp.level), .writer = disp.err() };

    at(3, "Shuffling input files\n", .{});
    shuffle(names);
    const fs = fileStats(env, names, chunk_size);

    var loaded_size: usize = blk: {
        const mult: u64 = if (method == .cover) cover_memmult else fastcover_memmult;
        const total: u64 = @intCast(@max(fs.total_size_to_load, 0));
        const max_mem = findMaxMem(total *% mult) / mult;
        var size: u64 = @min(@min(max_mem, total), max_samples_size);
        if (fs.total_size_to_load < 0) size = 0;
        if (mem_limit != 0) {
            at(2, "!  Warning : setting manual memory limit for dictionary training data at {d} MB \n", .{mem_limit / (1 << 20)});
            size = @min(size, mem_limit);
        }
        break :blk @intCast(size);
    };
    const src_buffer = gpa.alloc(u8, loaded_size) catch throw(12, "not enough memory for DiB_trainFiles", .{});
    defer gpa.free(src_buffer);
    const sizes = gpa.alloc(usize, fs.nb_samples) catch throw(12, "not enough memory for DiB_trainFiles", .{});
    defer gpa.free(sizes);

    if (fs.one_sample_too_large) {
        at(2, "!  Warning : some sample(s) are very large \n", .{});
        at(2, "!  Note that dictionary is only useful for small samples. \n", .{});
        at(2, "!  As a consequence, only the first {d} bytes of each sample are loaded \n", .{sample_size_max});
    }
    if (fs.nb_samples < 5) {
        at(2, "!  Warning : nb of samples too low for proper processing ! \n", .{});
        at(2, "!  Please provide _one file per sample_. \n", .{});
        at(2, "!  Alternatively, split files into fixed-size blocks representative of samples, with -B# \n", .{});
        throw(14, "nb of samples too low", .{});
    }
    if (fs.total_size_to_load < @as(i64, @intCast(max_dict_size)) * 8) {
        at(2, "!  Warning : data size of samples too small for target dictionary size \n", .{});
        at(2, "!  Samples should be about 100x larger than target dictionary size \n", .{});
    }
    if (@as(i64, @intCast(loaded_size)) < fs.total_size_to_load)
        at(1, "Training samples set too large ({d} MB); training on {d} MB only...\n", .{
            @as(u32, @truncate(@as(u64, @intCast(fs.total_size_to_load)) >> 20)),
            @as(u32, @truncate(loaded_size >> 20)),
        });

    const nb_loaded = loadFiles(env, src_buffer, &loaded_size, sizes, names, chunk_size);
    const samples: db.Samples = .{ .buffer = src_buffer[0..loaded_size], .sizes = sizes[0..nb_loaded] };
    // libzstd clamps a level above the maximum to it; the module refuses one
    const lvl = @min(level, zstd.max_level);
    // libzstd's trainers have no memory ceiling of their own
    const unlimited = std.math.maxInt(usize);

    const dict_size: usize = switch (method) {
        .cover => |p| if (p.k == 0 or p.d == 0) blk: {
            const r = db.optimizeCover(gpa, dict_buffer, samples, .{
                .k = p.k,
                .d = p.d,
                .steps = p.steps,
                .split_point = p.split_point,
                .level = lvl,
                .dict_id = dict_id,
                .memory_limit = unlimited,
                .nb_threads = nb_threads,
                .notify = notify,
            }) catch |e| return failed(e);
            at(2, "k={d}\nd={d}\nsteps={d}\nsplit={d}\n", .{ r.k, r.d, r.steps, splitPercent(r.split_point) });
            break :blk r.size;
        } else db.trainCover(gpa, dict_buffer, samples, .{
            .k = p.k,
            .d = p.d,
            .level = lvl,
            .dict_id = dict_id,
            .memory_limit = unlimited,
            .notify = notify,
        }) catch |e| return failed(e),
        .fast_cover => |p| if (p.k == 0 or p.d == 0) blk: {
            const r = db.optimizeFastCover(gpa, dict_buffer, samples, .{
                .k = p.k,
                .d = p.d,
                .steps = p.steps,
                .split_point = p.split_point,
                .f = p.f,
                .accel = p.accel,
                .level = lvl,
                .dict_id = dict_id,
                .memory_limit = unlimited,
                .nb_threads = nb_threads,
                .notify = notify,
            }) catch |e| return failed(e);
            at(2, "k={d}\nd={d}\nf={d}\nsteps={d}\nsplit={d}\naccel={d}\n", .{ r.k, r.d, r.f, r.steps, splitPercent(r.split_point), r.accel });
            break :blk r.size;
        } else db.trainFastCover(gpa, dict_buffer, samples, .{
            .k = p.k,
            .d = p.d,
            .f = p.f,
            .accel = p.accel,
            .level = lvl,
            .dict_id = dict_id,
            .memory_limit = unlimited,
            .notify = notify,
        }) catch |e| return failed(e),
    };
    at(2, "Save dictionary of size {d} into file {s} \n", .{ dict_size, dict_name });
    saveDict(env, dict_name, dict_buffer[0..dict_size]);
    return 0;
}

/// `(unsigned)(splitPoint * 100)`.
fn splitPercent(split: f64) u32 {
    return @intFromFloat(split * 100);
}

fn failed(e: anyerror) u8 {
    at(1, "dictionary training failed : {s} \n", .{errorName(e)});
    return 1;
}

/// `DiB_saveDict`: created or truncated, whatever was there.
fn saveDict(env: Env, name: []const u8, bytes: []const u8) void {
    const f = Io.Dir.cwd().createFile(env.io, name, .{}) catch throw(3, "cannot open {s} ", .{name});
    defer f.close(env.io);
    f.writeStreamingAll(env.io, bytes) catch throw(4, "{s} : write error", .{name});
}
