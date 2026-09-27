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
    bench: bench.Params = .{},
    /// `-e#`: the last level benchmarked; below the first means just it.
    level_last: i32 = std.math.minInt(i32),
    separate_files: bool = false,
    /// `-P#`: a synthetic input of this compressibility (not ported).
    compressibility: ?u32 = null,
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
    return run(env, arena, argv, init.environ);
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
    w.print("  --long[=#]                    Enable long distance matching with window log #. [Default: {d}]\n", .{default_max_window_log}) catch {};
    w.writeAll(
        \\  -T#                           Spawn # compression threads. [Default: 1; pass 0 for core count.]
        \\  --single-thread               Share a single thread for I/O and compression (slightly different than `-T1`).
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
        \\
        \\Advanced decompression options:
        \\  -l                            Print information about Zstandard-compressed files.
        \\  --test                        Test compressed file integrity.
        \\  -M#                           Set the memory usage limit to # megabytes.
        \\  --[no-]pass-through           Pass through uncompressed files as-is. [Default: Disabled]
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

fn isConsole(io: std.Io, f: std.Io.File) bool {
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
    if (c.names.items.len == 0) return unsupported("a benchmark without an input file (synthetic data)");
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
            if (eq(u8, a, "--sparse") or eq(u8, a, "--no-sparse")) continue; // output bytes are the same; no sparse writes here
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
            if (eq(u8, a, "--train")) return unsupported("--train");
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
            if (eq(u8, a, "--show-default-cparams")) return unsupported("--show-default-cparams");
            if (eq(u8, a, "--content-size")) {
                c.prefs.content_size = true;
                continue;
            }
            if (eq(u8, a, "--no-content-size")) {
                c.prefs.content_size = false;
                continue;
            }
            if (eq(u8, a, "--adapt") or std.mem.startsWith(u8, a, "--adapt=")) return unsupported("--adapt");
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
            if (eq(u8, a, "--fake-stdin-is-console") or eq(u8, a, "--fake-stdout-is-console") or eq(u8, a, "--fake-stderr-is-console") or eq(u8, a, "--trace-file-stat"))
                return unsupported(a);
            if (eq(u8, a, "--max")) return unsupported("--max");

            if (std.mem.startsWith(u8, a, "--train-")) return unsupported(a);
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
            if (longCommandWArg(&a, "--maxdict") or longCommandWArg(&a, "--dictID")) return unsupported("dictionary training");
            if (longCommandWArg(&a, "--zstd=")) return unsupported("--zstd=");
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
            if (longCommandWArg(&a, "--output-dir-flat") or longCommandWArg(&a, "--output-dir-mirror")) return unsupported("--output-dir-*");
            if (longCommandWArg(&a, "--auto-threads")) {
                _ = Field.next(argv, &i, &a) orelse return 1;
                continue;
            }
            if (longCommandWArg(&a, "--trace")) return unsupported("--trace");
            if (longCommandWArg(&a, "--patch-from")) return unsupported("--patch-from");
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
                } else if (a.len != 0) {
                    return badUsage(program, original);
                } else {
                    c.level = -1;
                }
                continue;
            }
            if (longCommandWArg(&a, "--filelist")) return unsupported("--filelist");
            return badUsage(program, original);
        }

        // short options, aggregated
        a = a[1..];
        while (a.len > 0) {
            if (a[0] >= '0' and a[0] <= '9') {
                c.level = @intCast(@min(readU32(&a), std.math.maxInt(i32)));
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
                'r' => return unsupported("-r"),
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
                    c.compressibility = readU32(&a);
                },
                'B' => {
                    a = a[1..];
                    c.prefs.block_size = readU32(&a);
                },
                'T' => {
                    a = a[1..];
                    c.nb_workers = readU32(&a);
                },
                's' => return unsupported("dictionary training"),
                'p' => {
                    a = a[1..];
                    if (a.len > 0 and a[0] >= '0' and a[0] <= '9') {
                        c.bench.additional_param = @intCast(@min(readU32(&a), std.math.maxInt(i32)));
                    } else return unsupported("-p (pause at the end)");
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

    if (c.operation == .list) {
        return list.listMultiple(env, c.names.items, disp.level, isConsole(env.io, std.Io.File.stdin()));
    }

    if (c.operation == .bench) return runBench(env, &c, nb_workers);

    if (c.operation == .@"test") {
        c.prefs.test_mode = true;
        c.out_name = fio.nulmark;
        c.prefs.remove_src = false;
    }

    if (c.names.items.len == 0) c.names.append(arena, fio.stdinmark) catch return 1;
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
    c.prefs.mem_limit = c.mem_limit;

    const result: u1 = switch (c.operation) {
        .compress => blk: {
            c.prefs.nb_workers = nb_workers;
            c.prefs.ldm = c.ldm;
            if (c.names.items.len == 1 and c.out_name != null)
                break :blk fio.compressFilename(env, &ctx, &c.prefs, c.out_name.?, c.names.items[0], c.dict_name, c.level, c.cp);
            break :blk fio.compressMultiple(env, &ctx, &c.prefs, c.names.items, c.out_name, c.suffix, c.dict_name, c.level, c.cp);
        },
        .decompress, .@"test" => blk: {
            if (c.names.items.len == 1 and c.out_name != null)
                break :blk fio.decompressFilename(env, &ctx, &c.prefs, c.out_name.?, c.names.items[0], c.dict_name);
            break :blk fio.decompressMultiple(env, &ctx, &c.prefs, c.names.items, c.out_name, c.dict_name);
        },
        .bench, .train, .list => unreachable,
    };
    return result;
}

test {
    _ = disp;
}
