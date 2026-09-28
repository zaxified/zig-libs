// SPDX-License-Identifier: BSD-3-Clause AND MIT
//! `zstd`, the command, on zig-libs' zstd module: a port of libzstd
//! 1.5.7's `programs/zstdcli.c` (this file: options, defaults, the
//! decisions about stdin/stdout, dispatch), `programs/fileio.c`
//! (`fileio.zig`, `list.zig`) and the display helpers of `programs/util.c`
//! (`display.zig`). Its frames are the C command's frames, byte for byte,
//! for the same options; its messages are the same text. `smoke.sh` checks
//! both against the real `zstd` when one of version 1.5.7 is installed.
//!
//! What is not ported yet is refused by name, never silently ignored: see
//! `unsupported` below and README.md.

const std = @import("std");
const builtin = @import("builtin");
const zstd = @import("zstd");
const disp = @import("display.zig");
const fio = @import("fileio.zig");
const list = @import("list.zig");
const bench = @import("bench.zig");
const util = @import("util.zig");
const dibio = @import("dibio.zig");

const version = "v1.5.7";
const version_string = "1.5.7";
/// `WELCOME_MESSAGE`: the C command's banner, naming this port.
fn welcome(w: *std.Io.Writer) void {
    w.print("*** Zstandard CLI ({d}-bit) {s}, zig-libs port ***\n", .{ @bitSizeOf(usize), version }) catch {};
}

const clevel_default = 3;
const clevel_max = 19; // without --ultra
const default_max_window_log = 27;

const Operation = enum { compress, decompress, @"test", bench, train, list };

/// Everything `main` in zstdcli.c keeps in locals.
const Cli = struct {
    operation: Operation = .compress,
    prefs: fio.Prefs = .{},
    cp: fio.CParams = .{},
    names: std.ArrayList([]const u8) = .empty,
    out_name: ?[]const u8 = null,
    dict_name: ?[]const u8 = null,
    suffix: []const u8 = ".zst",
    level: i32 = clevel_default,
    ultra: bool = false,
    force_stdin: bool = false,
    force_stdout: bool = false,
    follow_links: bool = false,
    next_are_files: bool = false,
    nb_workers: ?u32 = null, // -1: unset
    single_thread: bool = false,
    mem_limit: u32 = 0,
    ldm: bool = false,
    adapt: bool = false,
    /// `--adapt=min=#,max=#` (`MINCLEVEL`, `MAXCLEVEL` when not given).
    adapt_min: i32 = zstd.min_level,
    adapt_max: i32 = zstd.max_level,
    bench: bench.Params = .{},
    /// `-e#`: the last level benchmarked; below the first means just it.
    level_last: i32 = std.math.minInt(i32),
    separate_files: bool = false,
    /// `-P#`: the synthetic input's compressibility, instead of lorem ipsum.
    compressibility: ?f64 = null,
    show_default_cparams: bool = false,
    recursive: bool = false,
    /// `--filelist`: files whose lines are more input names.
    file_lists: std.ArrayList([]const u8) = .empty,
    out_dir: ?[]const u8 = null,
    out_mirror_dir: ?[]const u8 = null,
    patch_from_name: ?[]const u8 = null,
    /// `dict`, `coverParams` / `fastCoverParams`: the trainer `--train*`
    /// runs.
    train: dibio.Method = .{ .fast_cover = dibio.Params.default_fast_cover },
    /// `dictCLevel`: set by `-#` and `--fast=#`, not by `ZSTD_CLEVEL`.
    dict_level: i32 = 3,
    max_dict_size: u32 = 110 << 10,
    dict_id: u32 = 0,
    /// `-s#`: the legacy trainer's selectivity (that trainer is not here).
    dict_select: u32 = 9,
};

const Env = fio.Env;

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) {
        if (da.deinit() == .leak) @panic("memory leak");
    };
    const gpa = if (builtin.mode == .Debug or builtin.mode == .ReleaseSafe) da.allocator() else std.heap.smp_allocator;
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    disp.init(io);
    defer disp.flush();

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const argv = try init.args.toSlice(arena);
    const env: Env = .{ .gpa = gpa, .io = io };
    const r = run(env, arena, argv, init.environ);
    if (main_pause) waitEnter(io);
    return r;
}

/// `-p`: wait for Enter at the end (`main_pause`), whatever the result --
/// except after an exit on the spot, as in C.
var main_pause = false;

/// `waitEnter`.
fn waitEnter(io: std.Io) void {
    disp.always("Press enter to continue... \n", .{});
    var b: [1]u8 = undefined;
    _ = std.Io.File.stdin().readStreaming(io, &.{&b}) catch 0;
}

fn lastNameFromPath(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[slash + 1 ..];
}

/// `exeNameMatch`: the name, or the name and an extension.
fn exeNameMatch(exe: []const u8, name: []const u8) bool {
    return std.mem.startsWith(u8, exe, name) and (exe.len == name.len or exe[name.len] == '.');
}

/// `readU32FromCharChecked`: digits, then an optional K/KB/KiB/M/MB/MiB.
/// Null on overflow; advances `s`.
fn readU32Checked(s: *[]const u8) ?u32 {
    var r: u32 = 0;
    while (s.len > 0 and s.*[0] >= '0' and s.*[0] <= '9') : (s.* = s.*[1..]) {
        if (r > std.math.maxInt(u32) / 10) return null;
        const last = r;
        r = r *% 10 +% (s.*[0] - '0');
        if (r < last) return null;
    }
    if (s.len > 0 and (s.*[0] == 'K' or s.*[0] == 'M')) {
        const max_k = std.math.maxInt(u32) >> 10;
        if (r > max_k) return null;
        r <<= 10;
        if (s.*[0] == 'M') {
            if (r > max_k) return null;
            r <<= 10;
        }
        s.* = s.*[1..];
        if (s.len > 0 and s.*[0] == 'i') s.* = s.*[1..];
        if (s.len > 0 and s.*[0] == 'B') s.* = s.*[1..];
    }
    return r;
}

/// `parseCompressionParameters`: `--zstd=` into `cp` and the long-distance
/// and overlap settings; false when malformed. Values are not checked here:
/// the compressor refuses what is out of bounds.
fn parseCompressionParameters(s_in: []const u8, cp: *fio.CParams, prefs: *fio.Prefs) bool {
    var s = s_in;
    while (true) {
        if (longCommandWArg(&s, "windowLog=") or longCommandWArg(&s, "wlog=")) {
            cp.window_log = readU32(&s);
        } else if (longCommandWArg(&s, "chainLog=") or longCommandWArg(&s, "clog=")) {
            cp.chain_log = readU32(&s);
        } else if (longCommandWArg(&s, "hashLog=") or longCommandWArg(&s, "hlog=")) {
            cp.hash_log = readU32(&s);
        } else if (longCommandWArg(&s, "searchLog=") or longCommandWArg(&s, "slog=")) {
            cp.search_log = readU32(&s);
        } else if (longCommandWArg(&s, "minMatch=") or longCommandWArg(&s, "mml=")) {
            cp.min_match = readU32(&s);
        } else if (longCommandWArg(&s, "targetLength=") or longCommandWArg(&s, "tlen=")) {
            cp.target_length = readU32(&s);
        } else if (longCommandWArg(&s, "strategy=") or longCommandWArg(&s, "strat=")) {
            cp.strategy = readU32(&s);
        } else if (longCommandWArg(&s, "overlapLog=") or longCommandWArg(&s, "ovlog=")) {
            prefs.overlap_log = readU32(&s);
        } else if (longCommandWArg(&s, "ldmHashLog=") or longCommandWArg(&s, "lhlog=")) {
            prefs.ldm_hash_log = readU32(&s);
        } else if (longCommandWArg(&s, "ldmMinMatch=") or longCommandWArg(&s, "lmml=")) {
            prefs.ldm_min_match = readU32(&s);
        } else if (longCommandWArg(&s, "ldmBucketSizeLog=") or longCommandWArg(&s, "lblog=")) {
            prefs.ldm_bucket_size_log = readU32(&s);
        } else if (longCommandWArg(&s, "ldmHashRateLog=") or longCommandWArg(&s, "lhrlog=")) {
            prefs.ldm_hash_rate_log = readU32(&s);
        } else {
            disp.at(4, "invalid compression parameter \n", .{});
            return false;
        }
        if (s.len > 0 and s[0] == ',') {
            s = s[1..];
            continue;
        }
        break;
    }
    return s.len == 0; // check the end of string
}

/// `parseCoverParameters` / `parseFastCoverParameters`: the fields not given
/// are 0; false when malformed.
fn parseTrainParameters(s_in: []const u8, fast: bool, p: *dibio.Params) bool {
    var s = s_in;
    p.* = .{};
    while (true) {
        if (longCommandWArg(&s, "k=")) {
            p.k = readU32(&s);
        } else if (longCommandWArg(&s, "d=")) {
            p.d = readU32(&s);
        } else if (fast and longCommandWArg(&s, "f=")) {
            p.f = readU32(&s);
        } else if (longCommandWArg(&s, "steps=")) {
            p.steps = readU32(&s);
        } else if (fast and longCommandWArg(&s, "accel=")) {
            p.accel = readU32(&s);
        } else if (longCommandWArg(&s, "split=")) {
            p.split_point = @as(f64, @floatFromInt(readU32(&s))) / 100.0;
        } else if (longCommandWArg(&s, "shrink")) {
            p.shrink_max_regression = 1; // kDefaultRegression
            p.shrink = true;
            if (s.len > 0 and s[0] == '=') {
                s = s[1..];
                p.shrink_max_regression = readU32(&s);
            }
        } else return false;
        if (s.len > 0 and s[0] == ',') {
            s = s[1..];
            continue;
        }
        break;
    }
    if (s.len != 0) return false;
    const split: u32 = @intFromFloat(p.split_point * 100);
    if (fast)
        disp.at(4, "cover: k={d}\nd={d}\nf={d}\nsteps={d}\nsplit={d}\naccel={d}\nshrink={d}\n", .{ p.k, p.d, p.f, p.steps, split, p.accel, p.shrink_max_regression })
    else
        disp.at(4, "cover: k={d}\nd={d}\nsteps={d}\nsplit={d}\nshrink{d}\n", .{ p.k, p.d, p.steps, split, p.shrink_max_regression });
    return true;
}

/// `setMaxCompression`.
fn setMaxCompression(cp: *fio.CParams, prefs: *fio.Prefs) void {
    const L = zstd.limits;
    cp.* = .{
        .window_log = L.window_log_max,
        .chain_log = L.chain_log_max,
        .hash_log = L.hash_log_max,
        .search_log = L.search_log_max,
        .min_match = L.min_match_min,
        .target_length = L.target_length_max,
        .strategy = @intFromEnum(zstd.Strategy.btultra2),
    };
    prefs.overlap_log = L.overlap_log_max;
    prefs.ldm_hash_log = L.ldm_hash_log_max;
    prefs.ldm_hash_rate_log = 0; // automatically derived
    prefs.ldm_min_match = 16; // heuristic
    prefs.ldm_bucket_size_log = L.ldm_bucket_size_log_max;
}

/// `ZSTD_strategyMap`.
fn strategyName(s: zstd.Strategy) []const u8 {
    return switch (s) {
        inline else => |t| "ZSTD_" ++ @tagName(t),
    };
}

/// `UTIL_getFileSize`: null unless a regular file.
fn fileSize(env: Env, name: []const u8) ?u64 {
    const st = fio.stat(env, name) orelse return null;
    return if (st.kind == .file) st.size else null;
}

/// `UTIL_getFileSize` of the dictionary as a `size_t`: an unknown size is
/// `UTIL_FILESIZE_UNKNOWN`, as the C command passes it on.
fn dictFileSize(env: Env, name: ?[]const u8) u64 {
    const n = name orelse return 0;
    return fileSize(env, n) orelse std.math.maxInt(u64);
}

/// `printDefaultCParams`.
fn printDefaultCParams(env: Env, name: []const u8, dict_name: ?[]const u8, level: i32) void {
    const size = fileSize(env, name);
    const cp = zstd.getCParams(level, size, dictFileSize(env, dict_name));
    if (size) |n| disp.always("{s} ({d} bytes)\n", .{ name, n }) else disp.always("{s} (src size unknown)\n", .{name});
    disp.always(" - windowLog     : {d}\n", .{cp.window_log});
    disp.always(" - chainLog      : {d}\n", .{cp.chain_log});
    disp.always(" - hashLog       : {d}\n", .{cp.hash_log});
    disp.always(" - searchLog     : {d}\n", .{cp.search_log});
    disp.always(" - minMatch      : {d}\n", .{cp.min_match});
    disp.always(" - targetLength  : {d}\n", .{cp.target_length});
    disp.always(" - strategy      : {s} ({d})\n", .{ strategyName(cp.strategy), @intFromEnum(cp.strategy) });
}

/// `printActualCParams`: the level's parameters with the explicit ones over
/// them.
fn printActualCParams(env: Env, name: []const u8, dict_name: ?[]const u8, level: i32, cp: fio.CParams) void {
    const d = zstd.getCParams(level, fileSize(env, name), dictFileSize(env, dict_name));
    const pick = struct {
        fn f(explicit: u32, default: u32) u32 {
            return if (explicit == 0) default else explicit;
        }
    }.f;
    disp.always("--zstd=wlog={d},clog={d},hlog={d},slog={d},mml={d},tlen={d},strat={d}\n", .{
        pick(cp.window_log, d.window_log),           pick(cp.chain_log, d.chain_log),
        pick(cp.hash_log, d.hash_log),               pick(cp.search_log, d.search_log),
        pick(cp.min_match, d.min_match),             pick(cp.target_length, d.target_length),
        pick(cp.strategy, @intFromEnum(d.strategy)),
    });
}

/// `FIO_displayCompressionParameters`. The row match finder's words are
/// indexed as in C, `ZSTD_ps_enable` (1) printing `--no-row-match-finder`.
fn displayCompressionParameters(prefs: *const fio.Prefs) void {
    const check = [3][]const u8{ " --no-check", "", " --check" };
    const row = [3][]const u8{ "", " --no-row-match-finder", " --row-match-finder" };
    const lit = [3][]const u8{ "", " --compress-literals", " --no-compress-literals" };
    disp.always("--format=.zst --no-sparse{s}{s} --block-size={d}", .{ if (prefs.dict_id) "" else " --no-dictID", check[prefs.checksum], prefs.block_size });
    if (prefs.adaptive) disp.always(" --adapt=min={d},max={d}", .{ prefs.adapt_min, prefs.adapt_max });
    disp.always("{s}{s}", .{ row[@intFromEnum(prefs.row_match_finder)], if (prefs.rsyncable) " --rsyncable" else "" });
    if (prefs.stream_src_size != 0) disp.always(" --stream-size={d}", .{@as(u32, @truncate(prefs.stream_src_size))});
    if (prefs.src_size_hint != 0) disp.always(" --size-hint={d}", .{@as(i32, @bitCast(prefs.src_size_hint))});
    if (prefs.target_cblock_size != 0) disp.always(" --target-compressed-block-size={d}", .{prefs.target_cblock_size});
    disp.always("{s} --memory={d} --threads={d}{s} --{s}content-size\n", .{
        lit[@intFromEnum(prefs.literal_compression)],
        if (prefs.mem_limit != 0) prefs.mem_limit else 128 << 20,
        prefs.nb_workers,
        if (prefs.exclude_compressed) " --exclude-compressed" else "",
        if (prefs.content_size) "" else "no-",
    });
}

/// `errorOut`.
fn errorOut(msg: []const u8) noreturn {
    disp.at(1, "{s} \n", .{msg});
    disp.flush();
    std.process.exit(1);
}

/// `readU32FromChar`: exits on overflow.
fn readU32(s: *[]const u8) u32 {
    return readU32Checked(s) orelse errorOut("error: numeric value overflows 32-bit unsigned int");
}

/// `readSizeTFromChar` (64-bit).
fn readSizeT(s: *[]const u8) u64 {
    var r: u64 = 0;
    while (s.len > 0 and s.*[0] >= '0' and s.*[0] <= '9') : (s.* = s.*[1..]) {
        r = std.math.mul(u64, r, 10) catch errorOut("error: numeric value overflows size_t");
        r = std.math.add(u64, r, s.*[0] - '0') catch errorOut("error: numeric value overflows size_t");
    }
    if (s.len > 0 and (s.*[0] == 'K' or s.*[0] == 'M')) {
        const max_k = std.math.maxInt(u64) >> 10;
        if (r > max_k) errorOut("error: numeric value overflows size_t");
        r <<= 10;
        if (s.*[0] == 'M') {
            if (r > max_k) errorOut("error: numeric value overflows size_t");
            r <<= 10;
        }
        s.* = s.*[1..];
        if (s.len > 0 and s.*[0] == 'i') s.* = s.*[1..];
        if (s.len > 0 and s.*[0] == 'B') s.* = s.*[1..];
    }
    return r;
}

/// `readIntFromChar`: an optional `-`, then `readU32FromChar`.
fn readInt(s: *[]const u8) i32 {
    var sign: i32 = 1;
    if (s.len > 0 and s.*[0] == '-') {
        s.* = s.*[1..];
        sign = -1;
    }
    return @as(i32, @bitCast(readU32(s))) *% sign;
}

/// `parseAdaptParameters`: `min=#` and `max=#`, comma-separated, in any
/// order; false when malformed or when min is above max.
fn parseAdaptParameters(s_in: []const u8, min: *i32, max: *i32) bool {
    var s = s_in;
    while (true) {
        if (longCommandWArg(&s, "min=")) {
            min.* = readInt(&s);
            if (s.len > 0 and s[0] == ',') {
                s = s[1..];
                continue;
            } else break;
        }
        if (longCommandWArg(&s, "max=")) {
            max.* = readInt(&s);
            if (s.len > 0 and s[0] == ',') {
                s = s[1..];
                continue;
            } else break;
        }
        disp.at(4, "invalid compression parameter \n", .{});
        return false;
    }
    if (s.len != 0) return false; // check the end of string
    if (min.* > max.*) {
        disp.at(4, "incoherent adaptation limits \n", .{});
        return false;
    }
    return true;
}

/// `longCommandWArg`: `arg` starts with `cmd`; advances past it.
fn longCommandWArg(arg: *[]const u8, cmd: []const u8) bool {
    if (!std.mem.startsWith(u8, arg.*, cmd)) return false;
    arg.* = arg.*[cmd.len..];
    return true;
}

fn usage(w: *std.Io.Writer, program: []const u8) void {
    w.writeAll("Compress or decompress the INPUT file(s); reads from STDIN if INPUT is `-` or not provided.\n\n") catch {};
    w.print("Usage: {s} [OPTIONS...] [INPUT... | -] [-o OUTPUT]\n\n", .{program}) catch {};
    w.writeAll("Options:\n") catch {};
    w.writeAll("  -o OUTPUT                     Write output to a single file, OUTPUT.\n") catch {};
    w.writeAll("  -k, --keep                    Preserve INPUT file(s). [Default] \n") catch {};
    w.writeAll("  --rm                          Remove INPUT file(s) after successful (de)compression.\n\n") catch {};
    w.print("  -#                            Desired compression level, where `#` is a number between 1 and {d};\n", .{clevel_max}) catch {};
    w.writeAll("                                lower numbers provide faster compression, higher numbers yield\n") catch {};
    w.print("                                better compression ratios. [Default: {d}]\n\n", .{clevel_default}) catch {};
    w.writeAll(
        \\  -d, --decompress              Perform decompression.
        \\  -D DICT                       Use DICT as the dictionary for compression or decompression.
        \\
        \\  -f, --force                   Disable input and output checks. Allows overwriting existing files,
        \\                                receiving input from the console, printing output to STDOUT, and
        \\                                operating on links, block devices, etc. Unrecognized formats will be
        \\                                passed-through through as-is.
        \\
        \\  -h                            Display short usage and exit.
        \\  -H, --help                    Display full help and exit.
        \\  -V, --version                 Display the program version and exit.
        \\
        \\
    ) catch {};
}

fn usageAdvanced(program: []const u8) void {
    // C's text, less what this port does not have: `--trace`,
    // the gzip/xz/lzma/lz4 formats and the legacy trainer
    const w = disp.out();
    welcome(w);
    w.writeAll("\n") catch {};
    usage(w, program);
    w.writeAll(
        \\Advanced options:
        \\  -c, --stdout                  Write to STDOUT (even if it is a console) and keep the INPUT file(s).
        \\
        \\  -v, --verbose                 Enable verbose output; pass multiple times to increase verbosity.
        \\  -q, --quiet                   Suppress warnings; pass twice to suppress errors.
        \\
        \\  --[no-]progress               Forcibly show/hide the progress counter. NOTE: Any (de)compressed
        \\                                output to terminal will mix with progress counter text.
        \\
        \\  -r                            Operate recursively on directories.
        \\  --filelist LIST               Read a list of files to operate on from LIST.
        \\  --output-dir-flat DIR         Store processed files in DIR.
        \\  --output-dir-mirror DIR       Store processed files in DIR, respecting original directory structure.
        \\  --[no-]asyncio                Use asynchronous IO. [Default: Enabled]
        \\
        \\  --[no-]check                  Add XXH64 integrity checksums during compression. [Default: Add, Validate]
        \\                                If `-d` is present, ignore/validate checksums during decompression.
        \\
        \\  --                            Treat remaining arguments after `--` as files.
        \\
        \\Advanced compression options:
        \\
    ) catch {};
    w.print("  --ultra                       Enable levels beyond {d}, up to {d}; requires more memory.\n", .{ clevel_max, zstd.max_level }) catch {};
    w.print("  --fast[=#]                    Use to very fast compression levels. [Default: {d}]\n", .{1}) catch {};
    w.writeAll("  --adapt                       Dynamically adapt compression level to I/O conditions.\n") catch {};
    w.print("  --long[=#]                    Enable long distance matching with window log #. [Default: {d}]\n", .{default_max_window_log}) catch {};
    w.writeAll(
        \\  --patch-from=REF              Use REF as the reference point for Zstandard's diff engine. 
        \\
        \\  -T#                           Spawn # compression threads. [Default: 1; pass 0 for core count.]
        \\  --single-thread               Share a single thread for I/O and compression (slightly different than `-T1`).
        \\  --auto-threads={physical|logical}
        \\                                Use physical/logical cores when using `-T0`. [Default: Physical]
        \\
        \\  -B#                           Set job size to #. [Default: 0 (automatic)]
        \\
    ) catch {};
    w.writeAll("  --rsyncable                   Compress using a rsync-friendly method (`-B` sets block size). \n") catch {};
    w.writeAll(
        \\
        \\  --exclude-compressed          Only compress files that are not already compressed.
        \\
        \\  --stream-size=#               Specify size of streaming input from STDIN.
        \\  --size-hint=#                 Optimize compression parameters for streaming input of approximately size #.
        \\  --target-compressed-block-size=#
        \\                                Generate compressed blocks of approximately # size.
        \\
        \\  --no-dictID                   Don't write `dictID` into the header (dictionary compression only).
        \\  --[no-]compress-literals      Force (un)compressed literals.
        \\  --[no-]row-match-finder       Explicitly enable/disable the fast, row-based matchfinder for
        \\                                the 'greedy', 'lazy', and 'lazy2' strategies.
        \\
        \\  --format=zstd                 Compress files to the `.zst` format. [Default]
        \\  --[no-]mmap-dict              Memory-map dictionary file rather than mallocing and loading all at once
        \\
        \\Advanced decompression options:
        \\  -l                            Print information about Zstandard-compressed files.
        \\  --test                        Test compressed file integrity.
        \\  -M#                           Set the memory usage limit to # megabytes.
        \\  --[no-]sparse                 Enable sparse mode. [Default: Enabled for files, disabled for STDOUT.]
        \\  --[no-]pass-through           Pass through uncompressed files as-is. [Default: Disabled]
        \\
        \\Dictionary builder:
        \\  --train                       Create a dictionary from a training set of files.
        \\
        \\  --train-cover[=k=#,d=#,steps=#,split=#,shrink[=#]]
        \\                                Use the cover algorithm (with optional arguments).
        \\  --train-fastcover[=k=#,d=#,f=#,steps=#,split=#,accel=#,shrink[=#]]
        \\                                Use the fast cover algorithm (with optional arguments).
        \\
        \\  -o NAME                       Use NAME as dictionary name. [Default: dictionary]
        \\  --maxdict=#                   Limit dictionary to specified size #. [Default: 112640]
        \\  --dictID=#                    Force dictionary ID to #. [Default: Random]
        \\
        \\Benchmark options:
        \\  -b#                           Perform benchmarking with compression level #. [Default: 3]
        \\  -e#                           Test all compression levels up to #; starting level is `-b#`. [Default: 1]
        \\  -i#                           Set the minimum evaluation to time # seconds. [Default: 3]
        \\  -B#                           Cut file into independent chunks of size #. [Default: No chunking]
        \\  -S                            Output one benchmark result per input file. [Default: Consolidated result]
        \\  -D dictionary                 Benchmark using dictionary 
        \\  --priority=rt                 Set process priority to real-time.
        \\
    ) catch {};
    disp.flush();
}

fn printVersion() void {
    const w = disp.out();
    if (disp.level < 2) {
        w.print("{s}\n", .{version_string}) catch {};
        return;
    }
    welcome(w);
    if (disp.level >= 3) w.writeAll("*** supports: zstd\n") catch {};
}

/// `badUsage`.
fn badUsage(program: []const u8, param: []const u8) u8 {
    disp.at(1, "Incorrect parameter: {s} \n", .{param});
    if (disp.level >= 2) {
        usage(disp.err(), program);
        disp.flush();
    }
    return 1;
}

/// An option of the C command this port does not have yet: refused by
/// name rather than parsed and ignored.
fn unsupported(what: []const u8) u8 {
    disp.at(1, "zstd: {s} is not supported by this port yet \n", .{what});
    return 1;
}

fn envLevel(environ: std.process.Environ) i32 {
    const v = environ.getPosix("ZSTD_CLEVEL") orelse return clevel_default;
    var s: []const u8 = v;
    var sign: i32 = 1;
    if (s.len > 0 and s[0] == '-') {
        sign = -1;
        s = s[1..];
    } else if (s.len > 0 and s[0] == '+') s = s[1..];
    if (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
        if (readU32Checked(&s)) |abs| {
            if (s.len == 0) return sign * @as(i32, @intCast(@min(abs, std.math.maxInt(i32))));
        } else {
            disp.at(2, "Ignore environment variable setting {s}={s}: numeric value too large \n", .{ "ZSTD_CLEVEL", v });
            return clevel_default;
        }
    }
    disp.at(2, "Ignore environment variable setting {s}={s}: not a valid integer value \n", .{ "ZSTD_CLEVEL", v });
    return clevel_default;
}

/// `ZSTDCLI_NBTHREADS_DEFAULT` / `ZSTD_NBTHREADS`.
fn defaultThreads(environ: std.process.Environ) u32 {
    const cores: u32 = @intCast(std.Thread.getCpuCount() catch 1);
    const def = @max(1, @min(4, cores / 4));
    const v = environ.getPosix("ZSTD_NBTHREADS") orelse return def;
    var s: []const u8 = v;
    if (s.len > 0 and s[0] >= '0' and s[0] <= '9') {
        if (readU32Checked(&s)) |n| {
            if (s.len == 0) return n;
        } else {
            disp.at(2, "Ignore environment variable setting {s}={s}: numeric value too large \n", .{ "ZSTD_NBTHREADS", v });
            return def;
        }
    }
    disp.at(2, "Ignore environment variable setting {s}={s}: not a valid unsigned value \n", .{ "ZSTD_NBTHREADS", v });
    return def;
}

/// `UTIL_isConsole`, with the `--fake-*-is-console` hooks.
fn isConsole(io: std.Io, f: std.Io.File) bool {
    if (f.handle == std.Io.File.stdin().handle and disp.fake_console.stdin) return true;
    if (f.handle == std.Io.File.stderr().handle and disp.fake_console.stderr) return true;
    if (f.handle == std.Io.File.stdout().handle and disp.fake_console.stdout) return true;
    return f.isTty(io) catch false;
}

/// The benchmark branch of `main` in zstdcli.c.
fn runBench(env: Env, c: *Cli, nb_workers: u32) u8 {
    c.bench.block_size = c.prefs.block_size;
    c.bench.target_cblock_size = c.prefs.target_cblock_size;
    c.bench.nb_workers = nb_workers;
    c.bench.ldm = c.ldm;
    c.bench.ldm_min_match = c.prefs.ldm_min_match;
    c.bench.ldm_hash_log = c.prefs.ldm_hash_log;
    if (c.prefs.ldm_bucket_size_log) |v| c.bench.ldm_bucket_size_log = v;
    if (c.prefs.ldm_hash_rate_log) |v| c.bench.ldm_hash_rate_log = v;
    c.bench.row_match_finder = c.prefs.row_match_finder;
    c.bench.literal_compression = c.prefs.literal_compression;
    var first = c.level;
    var last = c.level_last;
    if (c.bench.mode == .decode_only) {
        first = 0;
        last = 0;
    }
    if (first > zstd.max_level) first = zstd.max_level;
    if (last > zstd.max_level) last = zstd.max_level;
    if (last < first) last = first;
    disp.at(3, "Benchmarking ", .{});
    if (c.names.items.len > 1) disp.at(3, "{d} files ", .{c.names.items.len});
    if (last > first) disp.at(3, "from level {d} to {d} ", .{ first, last }) else disp.at(3, "at level {d} ", .{first});
    disp.at(3, "using {d} threads \n", .{nb_workers});
    if (c.names.items.len == 0) return bench.syntheticTest(env, c.compressibility, first, last, c.cp, &c.bench);
    if (c.separate_files) {
        var r: u8 = 0;
        for (c.names.items) |n| r = bench.benchFiles(env, &.{n}, c.dict_name, first, last, c.cp, &c.bench);
        return r;
    }
    return bench.benchFiles(env, c.names.items, c.dict_name, first, last, c.cp, &c.bench);
}

fn run(env: Env, arena: std.mem.Allocator, argv: []const [:0]const u8, environ: std.process.Environ) u8 {
    var c: Cli = .{};
    const program = lastNameFromPath(argv[0]);
    c.level = envLevel(environ);

    // preset behaviors
    if (exeNameMatch(program, "zstdmt")) {
        c.nb_workers = 0;
        c.single_thread = false;
    }
    if (exeNameMatch(program, "unzstd")) c.operation = .decompress;
    if (exeNameMatch(program, "zstdcat") or exeNameMatch(program, "zcat")) {
        c.operation = .decompress;
        c.prefs.overwrite = true;
        c.force_stdout = true;
        c.follow_links = true;
        c.prefs.pass_through = true;
        c.out_name = fio.stdoutmark;
        disp.level = 1;
    }

    var i: usize = 1;
    while (i < argv.len) : (i += 1) {
        const original: []const u8 = argv[i];
        var a: []const u8 = original;
        if (c.next_are_files) {
            c.names.append(arena, a) catch return 1;
            continue;
        }
        if (std.mem.eql(u8, a, "-")) {
            c.names.append(arena, fio.stdinmark) catch return 1;
            continue;
        }
        if (a.len == 0 or a[0] != '-') {
            c.names.append(arena, a) catch return 1;
            continue;
        }

        // NEXT_FIELD: the value after `=`, or the next argument
        const Field = struct {
            fn next(argv_: []const [:0]const u8, idx: *usize, rest: *[]const u8) ?[]const u8 {
                if (rest.len > 0 and rest.*[0] == '=') {
                    const v = rest.*[1..];
                    rest.* = rest.*[rest.len..];
                    return v;
                }
                idx.* += 1;
                if (idx.* >= argv_.len) {
                    disp.at(1, "error: missing command argument \n", .{});
                    return null;
                }
                const v: []const u8 = argv_[idx.*];
                if (v.len > 0 and v[0] == '-') {
                    disp.at(1, "error: command cannot be separated from its argument by another command \n", .{});
                    return null;
                }
                return v;
            }
            fn nextU32(argv_: []const [:0]const u8, idx: *usize, rest: *[]const u8) ?u32 {
                var v = next(argv_, idx, rest) orelse return null;
                const r = readU32(&v);
                if (v.len != 0) errorOut("error: only numeric values with optional suffixes K, KB, KiB, M, MB, MiB are allowed");
                return r;
            }
            fn nextSize(argv_: []const [:0]const u8, idx: *usize, rest: *[]const u8) ?u64 {
                var v = next(argv_, idx, rest) orelse return null;
                const r = readSizeT(&v);
                if (v.len != 0) errorOut("error: only numeric values with optional suffixes K, KB, KiB, M, MB, MiB are allowed");
                return r;
            }
        };

        if (a.len > 1 and a[1] == '-') {
            const eq = std.mem.eql;
            if (eq(u8, a, "--")) {
                c.next_are_files = true;
                continue;
            }
            if (eq(u8, a, "--list")) {
                c.operation = .list;
                continue;
            }
            if (eq(u8, a, "--compress")) {
                c.operation = .compress;
                continue;
            }
            if (eq(u8, a, "--decompress") or eq(u8, a, "--uncompress")) {
                c.operation = .decompress;
                continue;
            }
            if (eq(u8, a, "--force")) {
                c.prefs.overwrite = true;
                c.force_stdin = true;
                c.force_stdout = true;
                c.follow_links = true;
                c.prefs.allow_block_devices = true;
                continue;
            }
            if (eq(u8, a, "--version")) {
                printVersion();
                return 0;
            }
            if (eq(u8, a, "--help")) {
                usageAdvanced(program);
                return 0;
            }
            if (eq(u8, a, "--verbose")) {
                disp.level += 1;
                continue;
            }
            if (eq(u8, a, "--quiet")) {
                disp.level -= 1;
                continue;
            }
            if (eq(u8, a, "--stdout")) {
                c.force_stdout = true;
                c.out_name = fio.stdoutmark;
                continue;
            }
            if (eq(u8, a, "--ultra")) {
                c.ultra = true;
                continue;
            }
            if (eq(u8, a, "--check")) {
                c.prefs.checksum = 2;
                continue;
            }
            if (eq(u8, a, "--no-check")) {
                c.prefs.checksum = 0;
                continue;
            }
            // output bytes are the same; no sparse writes here, the
            // setting only picks the notes at level 4
            if (eq(u8, a, "--sparse")) {
                fio.sparse = 2;
                continue;
            }
            if (eq(u8, a, "--no-sparse")) {
                fio.sparse = 0;
                continue;
            }
            if (eq(u8, a, "--pass-through")) {
                c.prefs.pass_through = true;
                continue;
            }
            if (eq(u8, a, "--no-pass-through")) {
                c.prefs.pass_through = false;
                continue;
            }
            if (eq(u8, a, "--test")) {
                c.operation = .@"test";
                continue;
            }
            if (eq(u8, a, "--asyncio") or eq(u8, a, "--no-asyncio")) continue; // I/O is synchronous here
            if (eq(u8, a, "--train")) {
                c.operation = .train;
                if (c.out_name == null) c.out_name = "dictionary";
                continue;
            }
            if (eq(u8, a, "--no-dictID")) {
                c.prefs.dict_id = false;
                continue;
            }
            if (eq(u8, a, "--keep")) {
                c.prefs.remove_src = false;
                continue;
            }
            if (eq(u8, a, "--rm")) {
                c.prefs.remove_src = true;
                continue;
            }
            if (eq(u8, a, "--priority=rt")) continue;
            if (eq(u8, a, "--show-default-cparams")) {
                c.show_default_cparams = true;
                continue;
            }
            if (eq(u8, a, "--content-size")) {
                c.prefs.content_size = true;
                continue;
            }
            if (eq(u8, a, "--no-content-size")) {
                c.prefs.content_size = false;
                continue;
            }
            if (eq(u8, a, "--adapt")) {
                c.adapt = true;
                continue;
            }
            if (longCommandWArg(&a, "--adapt=")) {
                c.adapt = true;
                if (!parseAdaptParameters(a, &c.adapt_min, &c.adapt_max)) return badUsage(program, original);
                continue;
            }
            if (eq(u8, a, "--no-row-match-finder")) {
                c.prefs.row_match_finder = .disable;
                continue;
            }
            if (eq(u8, a, "--row-match-finder")) {
                c.prefs.row_match_finder = .enable;
                continue;
            }
            if (eq(u8, a, "--single-thread")) {
                c.nb_workers = 0;
                c.single_thread = true;
                continue;
            }
            if (eq(u8, a, "--format=zstd")) {
                c.suffix = ".zst";
                continue;
            }
            if (eq(u8, a, "--mmap-dict") or eq(u8, a, "--no-mmap-dict")) continue; // the dictionary is read whole
            if (eq(u8, a, "--rsyncable")) {
                c.prefs.rsyncable = true;
                continue;
            }
            if (eq(u8, a, "--compress-literals")) {
                c.prefs.literal_compression = .enable;
                continue;
            }
            if (eq(u8, a, "--no-compress-literals")) {
                c.prefs.literal_compression = .disable;
                continue;
            }
            if (eq(u8, a, "--no-progress")) {
                disp.progress = .never;
                continue;
            }
            if (eq(u8, a, "--progress")) {
                disp.progress = .always;
                continue;
            }
            if (eq(u8, a, "--exclude-compressed")) {
                c.prefs.exclude_compressed = true;
                continue;
            }
            if (eq(u8, a, "--fake-stdin-is-console")) {
                disp.fake_console.stdin = true;
                continue;
            }
            if (eq(u8, a, "--fake-stdout-is-console")) {
                disp.fake_console.stdout = true;
                continue;
            }
            if (eq(u8, a, "--fake-stderr-is-console")) {
                disp.fake_console.stderr = true;
                continue;
            }
            if (eq(u8, a, "--trace-file-stat")) return unsupported(a);
            if (eq(u8, a, "--max")) {
                if (@sizeOf(usize) == 4) {
                    disp.at(2, "--max is incompatible with 32-bit mode \n", .{});
                    return badUsage(program, original);
                }
                c.ultra = true;
                c.ldm = true;
                setMaxCompression(&c.cp, &c.prefs);
                continue;
            }

            if (longCommandWArg(&a, "--train-cover") or longCommandWArg(&a, "--train-fastcover")) {
                const fast = std.mem.startsWith(u8, original, "--train-fastcover");
                c.operation = .train;
                if (c.out_name == null) c.out_name = "dictionary";
                var p: dibio.Params = .{};
                // with no `=`, every parameter left to the optimizer
                if (a.len != 0) {
                    if (a[0] != '=') return badUsage(program, original);
                    if (!parseTrainParameters(a[1..], fast, &p)) return badUsage(program, original);
                }
                c.train = if (fast) .{ .fast_cover = p } else .{ .cover = p };
                continue;
            }
            if (std.mem.startsWith(u8, a, "--train-legacy")) return unsupported("--train-legacy");
            if (longCommandWArg(&a, "--threads")) {
                c.nb_workers = Field.nextU32(argv, &i, &a) orelse return 1;
                continue;
            }
            if (longCommandWArg(&a, "--memlimit-decompress") or longCommandWArg(&a, "--memlimit") or longCommandWArg(&a, "--memory")) {
                c.mem_limit = Field.nextU32(argv, &i, &a) orelse return 1;
                continue;
            }
            if (longCommandWArg(&a, "--block-size")) {
                c.prefs.block_size = @intCast(@min(Field.nextSize(argv, &i, &a) orelse return 1, std.math.maxInt(u32)));
                continue;
            }
            if (longCommandWArg(&a, "--maxdict")) {
                c.max_dict_size = Field.nextU32(argv, &i, &a) orelse return 1;
                continue;
            }
            if (longCommandWArg(&a, "--dictID")) {
                c.dict_id = Field.nextU32(argv, &i, &a) orelse return 1;
                continue;
            }
            if (longCommandWArg(&a, "--zstd=")) {
                if (!parseCompressionParameters(a, &c.cp, &c.prefs)) return badUsage(program, original);
                continue;
            }
            if (longCommandWArg(&a, "--stream-size")) {
                c.prefs.stream_src_size = Field.nextSize(argv, &i, &a) orelse return 1;
                continue;
            }
            if (longCommandWArg(&a, "--target-compressed-block-size")) {
                c.prefs.target_cblock_size = @intCast(@min(Field.nextSize(argv, &i, &a) orelse return 1, std.math.maxInt(u32)));
                continue;
            }
            if (longCommandWArg(&a, "--size-hint")) {
                c.prefs.src_size_hint = @intCast(@min(Field.nextSize(argv, &i, &a) orelse return 1, std.math.maxInt(u32)));
                continue;
            }
            if (longCommandWArg(&a, "--output-dir-flat")) {
                c.out_dir = Field.next(argv, &i, &a) orelse return 1;
                if (c.out_dir.?.len == 0) {
                    disp.at(1, "error: output dir cannot be empty string (did you mean to pass '.' instead?)\n", .{});
                    return 1;
                }
                continue;
            }
            if (longCommandWArg(&a, "--auto-threads")) {
                _ = Field.next(argv, &i, &a) orelse return 1;
                continue;
            }
            if (longCommandWArg(&a, "--trace")) return unsupported("--trace");
            if (longCommandWArg(&a, "--output-dir-mirror")) {
                c.out_mirror_dir = Field.next(argv, &i, &a) orelse return 1;
                if (c.out_mirror_dir.?.len == 0) {
                    disp.at(1, "error: output dir cannot be empty string (did you mean to pass '.' instead?)\n", .{});
                    return 1;
                }
                continue;
            }
            if (longCommandWArg(&a, "--patch-from")) {
                c.patch_from_name = Field.next(argv, &i, &a) orelse return 1;
                c.ultra = true;
                continue;
            }
            if (longCommandWArg(&a, "--long")) {
                var wlog: u32 = default_max_window_log;
                c.ldm = true;
                c.ultra = true;
                if (a.len > 0 and a[0] == '=') {
                    a = a[1..];
                    wlog = readU32(&a);
                } else if (a.len != 0) return badUsage(program, original);
                if (c.cp.window_log == 0) c.cp.window_log = wlog;
                continue;
            }
            if (longCommandWArg(&a, "--fast")) {
                if (a.len > 0 and a[0] == '=') {
                    a = a[1..];
                    const max_fast: u32 = @intCast(-zstd.min_level);
                    const f = @min(readU32(&a), max_fast);
                    if (f == 0) return badUsage(program, original);
                    c.level = -@as(i32, @intCast(f));
                    c.dict_level = c.level;
                } else if (a.len != 0) {
                    return badUsage(program, original);
                } else {
                    c.level = -1;
                }
                continue;
            }
            if (longCommandWArg(&a, "--filelist")) {
                const list_name = Field.next(argv, &i, &a) orelse return 1;
                c.file_lists.append(arena, list_name) catch return 1;
                continue;
            }
            return badUsage(program, original);
        }

        // short options, aggregated
        a = a[1..];
        while (a.len > 0) {
            if (a[0] >= '0' and a[0] <= '9') {
                c.level = @intCast(@min(readU32(&a), std.math.maxInt(i32)));
                c.dict_level = c.level;
                continue;
            }
            switch (a[0]) {
                'V' => {
                    printVersion();
                    return 0;
                },
                'H' => {
                    usageAdvanced(program);
                    return 0;
                },
                'h' => {
                    usage(disp.out(), program);
                    disp.flush();
                    return 0;
                },
                'z' => {
                    c.operation = .compress;
                    a = a[1..];
                },
                'd' => {
                    c.bench.mode = .decode_only;
                    if (c.operation == .bench) {
                        a = a[1..];
                    } else {
                        c.operation = .decompress;
                        a = a[1..];
                    }
                },
                'c' => {
                    c.force_stdout = true;
                    c.out_name = fio.stdoutmark;
                    a = a[1..];
                },
                'o' => {
                    a = a[1..];
                    c.out_name = Field.next(argv, &i, &a) orelse return 1;
                },
                'n' => a = a[1..],
                'D' => {
                    a = a[1..];
                    c.dict_name = Field.next(argv, &i, &a) orelse return 1;
                },
                'f' => {
                    c.prefs.overwrite = true;
                    c.force_stdin = true;
                    c.force_stdout = true;
                    c.follow_links = true;
                    c.prefs.allow_block_devices = true;
                    a = a[1..];
                },
                'v' => {
                    disp.level += 1;
                    a = a[1..];
                },
                'q' => {
                    disp.level -= 1;
                    a = a[1..];
                },
                'k' => {
                    c.prefs.remove_src = false;
                    a = a[1..];
                },
                'C' => {
                    c.prefs.checksum = 2;
                    a = a[1..];
                },
                't' => {
                    c.operation = .@"test";
                    a = a[1..];
                },
                'M' => {
                    a = a[1..];
                    c.mem_limit = readU32(&a);
                },
                'l' => {
                    c.operation = .list;
                    a = a[1..];
                },
                'r' => {
                    c.recursive = true;
                    a = a[1..];
                },
                'b' => {
                    c.operation = .bench;
                    a = a[1..];
                },
                'e' => {
                    a = a[1..];
                    c.level_last = @intCast(@min(readU32(&a), std.math.maxInt(i32)));
                },
                'i' => {
                    a = a[1..];
                    c.bench.nb_seconds = readU32(&a);
                },
                'S' => {
                    c.separate_files = true;
                    a = a[1..];
                },
                'P' => {
                    a = a[1..];
                    c.compressibility = @as(f64, @floatFromInt(readU32(&a))) / 100;
                },
                'B' => {
                    a = a[1..];
                    c.prefs.block_size = readU32(&a);
                },
                'T' => {
                    a = a[1..];
                    c.nb_workers = readU32(&a);
                },
                's' => {
                    a = a[1..];
                    c.dict_select = readU32(&a);
                },
                'p' => {
                    a = a[1..];
                    if (a.len > 0 and a[0] >= '0' and a[0] <= '9') {
                        c.bench.additional_param = @intCast(@min(readU32(&a), std.math.maxInt(i32)));
                    } else main_pause = true;
                },
                else => {
                    const short = [2]u8{ '-', a[0] };
                    return badUsage(program, &short);
                },
            }
        }
    }

    disp.at(3, "*** Zstandard CLI ({d}-bit) {s}, zig-libs port ***\n", .{ @bitSizeOf(usize), version });

    if (c.operation == .decompress and (c.nb_workers orelse 0) > 1)
        disp.at(2, "Warning : decompression does not support multi-threading\n", .{});
    if (c.nb_workers != null and c.nb_workers.? == 0 and !c.single_thread) {
        c.nb_workers = @intCast(std.Thread.getCpuCount() catch 1);
        disp.at(3, "Note: {d} physical core(s) detected \n", .{c.nb_workers.?});
    }
    const nb_workers: u32 = c.nb_workers orelse if (c.operation == .decompress) 1 else defaultThreads(environ);
    disp.at(4, "Compressing with {d} worker threads \n", .{nb_workers});

    // symbolic links
    if (!c.follow_links) {
        var kept: usize = 0;
        const n = c.names.items.len;
        for (c.names.items) |name| {
            if (!std.mem.eql(u8, name, fio.stdinmark) and fio.lstatKind(env, name) == .sym_link and
                (fio.stat(env, name) == null or fio.stat(env, name).?.kind != .named_pipe))
            {
                disp.at(2, "Warning : {s} is a symbolic link, ignoring \n", .{name});
            } else {
                c.names.items[kept] = name;
                kept += 1;
            }
        }
        if (kept == 0 and n > 0) return 1;
        c.names.shrinkRetainingCapacity(kept);
    }

    // read names from a file
    for (c.file_lists.items) |list_name| {
        const more = util.readFileList(env, arena, list_name) orelse {
            disp.at(1, "zstd: error reading {s} \n", .{list_name});
            return 1;
        };
        c.names.appendSlice(arena, more) catch return 1;
    }

    const nb_input_names = c.names.items.len;
    if (c.recursive) {
        const expanded = util.expand(env, arena, c.names.items, c.follow_links);
        c.names = .fromOwnedSlice(@constCast(expanded));
    }

    if (c.operation == .list) {
        return list.listMultiple(env, c.names.items, disp.level, isConsole(env.io, std.Io.File.stdin()));
    }

    if (c.operation == .bench) return runBench(env, &c, nb_workers);

    if (c.operation == .train)
        return dibio.trainFromFiles(env, c.out_name.?, c.max_dict_size, c.names.items, c.prefs.block_size, c.train, c.dict_level, c.dict_id, nb_workers, c.mem_limit);

    if (c.operation == .@"test") {
        c.prefs.test_mode = true;
        c.out_name = fio.nulmark;
        c.prefs.remove_src = false;
    }

    if (c.names.items.len == 0) {
        // the input may have been only empty directories: then not stdin
        if (nb_input_names > 0) {
            disp.at(1, "please provide correct input file(s) or non-empty directories -- ignored \n", .{});
            return 0;
        }
        c.names.append(arena, fio.stdinmark) catch return 1;
    }
    if (c.names.items.len == 1 and std.mem.eql(u8, c.names.items[0], fio.stdinmark) and c.out_name == null)
        c.out_name = fio.stdoutmark;

    const has_stdin = for (c.names.items) |n| {
        if (std.mem.eql(u8, n, fio.stdinmark)) break true;
    } else false;
    if (!c.force_stdin and has_stdin and isConsole(env.io, std.Io.File.stdin())) {
        disp.at(1, "stdin is a console, aborting\n", .{});
        return 1;
    }
    if ((c.out_name == null or std.mem.eql(u8, c.out_name.?, fio.stdoutmark)) and
        isConsole(env.io, std.Io.File.stdout()) and has_stdin and !c.force_stdout and c.operation != .decompress)
    {
        disp.at(1, "stdout is a console, aborting\n", .{});
        return 1;
    }

    {
        const max: i32 = if (c.ultra) zstd.max_level else clevel_max;
        if (c.level > max) {
            disp.at(2, "Warning : compression level higher than max, reduced to {d} \n", .{max});
            c.level = max;
        }
    }

    if (c.show_default_cparams and c.operation == .decompress) {
        disp.at(1, "error : can't use --show-default-cparams in decompression mode \n", .{});
        return 1;
    }

    if (c.dict_name != null and c.patch_from_name != null) {
        disp.at(1, "error : can't use -D and --patch-from=# at the same time \n", .{});
        return 1;
    }
    if (c.patch_from_name != null and c.names.items.len > 1) {
        disp.at(1, "error : can't use --patch-from=# on multiple files \n", .{});
        return 1;
    }

    const has_stdout = c.out_name != null and std.mem.eql(u8, c.out_name.?, fio.stdoutmark);
    if (has_stdout and disp.level == 2) disp.level = 1;
    if (!isConsole(env.io, std.Io.File.stderr()) and disp.progress != .always) disp.progress = .never;
    if (has_stdout and c.prefs.remove_src) {
        disp.at(3, "Note: src files are not removed when output is stdout \n", .{});
        c.prefs.remove_src = false;
    }

    var ctx: fio.Ctx = .{
        .has_stdout_output = has_stdout,
        .nb_files_total = c.names.items.len,
        .has_stdin_input = has_stdin,
    };
    if (c.mem_limit == 0) {
        c.mem_limit = if (c.cp.window_log == 0) @as(u32, 1) << default_max_window_log else @as(u32, 1) << @intCast(c.cp.window_log & 31);
    }
    if (c.patch_from_name) |n| c.dict_name = n;
    c.prefs.patch_from = c.patch_from_name != null;
    c.prefs.mem_limit = c.mem_limit;

    const result: u1 = switch (c.operation) {
        .compress => blk: {
            c.prefs.nb_workers = nb_workers;
            if (c.prefs.overlap_log) |o| if (o != 0 and nb_workers == 0)
                disp.at(2, "Setting overlapLog is useless in single-thread mode \n", .{});
            c.prefs.ldm = c.ldm;
            // FIO_setAdaptiveMode, FIO_setAdaptMin/Max, FIO_setRsyncable
            if (c.adapt and nb_workers == 0) fio.fatal(1, "Adaptive mode is not compatible with single thread mode \n", .{});
            c.prefs.adaptive = c.adapt;
            c.prefs.adapt_min = c.adapt_min;
            c.prefs.adapt_max = c.adapt_max;
            if (c.prefs.rsyncable and nb_workers == 0) fio.fatal(1, "Rsyncable mode is not compatible with single thread mode \n", .{});
            fio.sparse = 0; // FIO_setSparseWrite(prefs, 0)
            if (c.adapt_min > c.level) c.level = c.adapt_min;
            if (c.adapt_max < c.level) c.level = c.adapt_max;
            if (c.show_default_cparams or disp.level >= 4) {
                for (c.names.items) |n| {
                    if (c.show_default_cparams) printDefaultCParams(env, n, c.dict_name, c.level);
                    if (disp.level >= 4) printActualCParams(env, n, c.dict_name, c.level, c.cp);
                }
            }
            if (disp.level >= 4) displayCompressionParameters(&c.prefs);
            if (c.names.items.len == 1 and c.out_name != null)
                break :blk fio.compressFilename(env, &ctx, &c.prefs, c.out_name.?, c.names.items[0], c.dict_name, c.level, c.cp);
            break :blk fio.compressMultiple(env, &ctx, &c.prefs, c.names.items, c.out_mirror_dir, c.out_dir, c.out_name, c.suffix, c.dict_name, c.level, c.cp);
        },
        .decompress, .@"test" => blk: {
            if (c.names.items.len == 1 and c.out_name != null)
                break :blk fio.decompressFilename(env, &ctx, &c.prefs, c.out_name.?, c.names.items[0], c.dict_name);
            break :blk fio.decompressMultiple(env, &ctx, &c.prefs, c.names.items, c.out_mirror_dir, c.out_dir, c.out_name, c.dict_name);
        },
        .bench, .train, .list => unreachable,
    };
    return result;
}

test {
    _ = disp;
    _ = util;
    _ = dibio;
}
