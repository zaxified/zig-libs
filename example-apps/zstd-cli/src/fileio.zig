// SPDX-License-Identifier: BSD-3-Clause AND MIT
//! File handling of the `zstd` command: a port of libzstd 1.5.7's
//! `programs/fileio.c` (`FIO_*`) onto `zig-libs`' zstd module and `std.Io`.
//!
//! Compression drives `zstd.Stream` with the plan the C command uses
//! (`FIO_compressZstdFrame`): the input in 128 KiB reads, each handed whole
//! to `compressStream2(continue)`, the last one with `end` (or an empty
//! `end` after the last read when the size is unknown), the file size
//! pledged when known -- so the frames are the C command's, byte for byte.
//! Decompression reads frame by frame as `FIO_decompressFrames` does, so
//! trailing garbage, empty input and unknown formats get the same verdicts
//! and messages.
//!
//! Not here (yet): gzip/xz/lz4 formats (as a libzstd built without zlib,
//! lzma and lz4), sparse output, asynchronous I/O.

const std = @import("std");
const zstd = @import("zstd");
const disp = @import("display.zig");
const util = @import("util.zig");

const Io = std.Io;
const File = Io.File;

pub const stdinmark = "/*stdin*\\";
pub const stdoutmark = "/*stdout*\\";
pub const nulmark = "/dev/null";

/// `ZSTD_CStreamInSize()`, `ZSTD_BLOCKSIZE_MAX`: one read of the input.
const in_chunk = 128 * 1024;
/// `ZSTD_DStreamInSize()`.
const din_size = 128 * 1024 + 3;
/// `ZSTD_CStreamOutSize()`: a block's bound, its header and a checksum.
const cout_size = zstd.compressBound(128 * 1024) + 3 + 4;
/// `ZSTD_DStreamOutSize()`: one block.
const dout_size = 128 * 1024;

/// `prefs->sparseFileSupport`: 0 `--no-sparse` (and compression), 1 the
/// default, 2 `--sparse`. This port never writes sparsely; the setting
/// only decides the notes at level 4, as C's does once, at the first
/// output it opens.
pub var sparse: u2 = 1;
/// `DICTSIZE_MAX`.
const dict_size_max = 32 << 20;

/// `FIO_prefs_t`.
pub const Prefs = struct {
    overwrite: bool = false,
    /// 0 `--no-check`, 1 default, 2 `--check`.
    checksum: u2 = 1,
    dict_id: bool = true,
    remove_src: bool = false,
    /// Decompression window limit in bytes (`--memory`), 0 until resolved.
    mem_limit: u32 = 0,
    nb_workers: u32 = 1,
    /// `ZSTD_c_jobSize` (`-B#`).
    block_size: u32 = 0,
    overlap_log: ?u32 = null,
    ldm: bool = false,
    ldm_hash_log: u32 = 0,
    ldm_min_match: u32 = 0,
    ldm_bucket_size_log: ?u32 = null,
    ldm_hash_rate_log: ?u32 = null,
    rsyncable: bool = false,
    /// `--adapt`: the level follows the output's and the input's speed,
    /// within `adapt_min..adapt_max`.
    adaptive: bool = false,
    adapt_min: i32 = -50,
    adapt_max: i32 = 22,
    stream_src_size: u64 = 0,
    target_cblock_size: u32 = 0,
    src_size_hint: u32 = 0,
    test_mode: bool = false,
    literal_compression: zstd.Switch = .auto,
    row_match_finder: zstd.Switch = .auto,
    exclude_compressed: bool = false,
    allow_block_devices: bool = false,
    /// null: on when `-f` writes to stdout (`passThrough == -1`).
    pass_through: ?bool = null,
    content_size: bool = true,
    /// `--patch-from`: the dictionary is a prefix, the file to diff from.
    patch_from: bool = false,
};

/// `FIO_ctx_t`.
pub const Ctx = struct {
    curr_file_idx: usize = 0,
    has_stdin_input: bool = false,
    has_stdout_output: bool = false,
    nb_files_total: usize = 1,
    nb_files_processed: usize = 0,
    total_in: u64 = 0,
    total_out: u64 = 0,

    /// `FIO_shouldDisplayFileSummary`.
    fn fileSummary(c: *const Ctx) bool {
        return c.nb_files_total <= 1 or disp.level >= 3;
    }
    /// `FIO_shouldDisplayMultipleFileSummary`.
    fn multiSummary(c: *const Ctx) bool {
        return c.nb_files_processed >= 1 and c.nb_files_total > 1;
    }
};

/// Explicit compression parameters (`--zstd=`, `--long=#`); 0 = unset.
pub const CParams = struct {
    window_log: u32 = 0,
    chain_log: u32 = 0,
    hash_log: u32 = 0,
    search_log: u32 = 0,
    min_match: u32 = 0,
    target_length: u32 = 0,
    strategy: u32 = 0,
};

pub const Env = struct {
    gpa: std.mem.Allocator,
    io: Io,
};

// ---------------------------------------------------------------- errors

/// `EXM_THROW`: "zstd: error N : msg" and exit with N.
pub fn fatal(code: u8, comptime fmt: []const u8, args: anytype) noreturn {
    disp.at(1, "zstd: ", .{});
    disp.at(1, "error {d} : ", .{code});
    disp.at(1, fmt, args);
    disp.at(1, " \n", .{});
    disp.flush();
    std.process.exit(code);
}

/// `ZSTD_getErrorName` for the module's errors.
pub fn zstdErrorName(e: anyerror) []const u8 {
    const Map = std.StaticStringMap([]const u8);
    const map: Map = .initComptime(.{
        .{ "CorruptionDetected", "Data corruption detected" },
        .{ "SrcSizeWrong", "Src size is incorrect" },
        .{ "DstSizeTooSmall", "Destination buffer is too small" },
        .{ "DictionaryCorrupted", "Dictionary is corrupted" },
        .{ "DictionaryWrong", "Dictionary mismatch" },
        .{ "LiteralsHeaderWrong", "Header of Literals' block doesn't respect format specification" },
        .{ "ChecksumWrong", "Restored data doesn't match checksum" },
        .{ "PrefixUnknown", "Unknown frame descriptor" },
        .{ "FrameParameterUnsupported", "Unsupported frame parameter" },
        .{ "FrameParameterWindowTooLarge", "Frame requires too much memory for decoding" },
        .{ "OutOfMemory", "Allocation error : not enough memory" },
        .{ "NoForwardProgressDestFull", "Operation made no progress over multiple calls, due to output buffer being full" },
        .{ "NoForwardProgressInputEmpty", "Operation made no progress over multiple calls, due to input being empty" },
        .{ "DstBufferWrong", "Destination buffer is wrong" },
        .{ "ParameterOutOfBound", "Parameter is out of bound" },
        .{ "LevelUnsupported", "Parameter is out of bound" },
        .{ "ParameterUnsupported", "Unsupported parameter" },
        .{ "ParameterCombinationUnsupported", "Unsupported combination of parameters" },
        .{ "StageWrong", "Operation not authorized at current processing stage" },
        .{ "StabilityConditionNotRespected", "pledged buffer stability condition is not respected" },
    });
    return map.get(@errorName(e)) orelse "Error (generic)";
}

/// `strerror(errno)` for the file errors a user meets.
pub fn strerror(e: anyerror) []const u8 {
    const Map = std.StaticStringMap([]const u8);
    const map: Map = .initComptime(.{
        .{ "FileNotFound", "No such file or directory" },
        .{ "AccessDenied", "Permission denied" },
        .{ "PermissionDenied", "Permission denied" },
        .{ "IsDir", "Is a directory" },
        .{ "NotDir", "Not a directory" },
        .{ "NoSpaceLeft", "No space left on device" },
        .{ "ReadOnlyFileSystem", "Read-only file system" },
        .{ "SymLinkLoop", "Too many levels of symbolic links" },
        .{ "NameTooLong", "File name too long" },
        .{ "FileBusy", "Text file busy" },
        .{ "DeviceBusy", "Device or resource busy" },
        .{ "BrokenPipe", "Broken pipe" },
        .{ "InputOutput", "Input/output error" },
        .{ "FileTooBig", "File too large" },
        .{ "ProcessFdQuotaExceeded", "Too many open files" },
    });
    return map.get(@errorName(e)) orelse @errorName(e);
}

// ------------------------------------------------------------- file stat

fn isStdin(name: []const u8) bool {
    return std.mem.eql(u8, name, stdinmark);
}
fn isStdout(name: []const u8) bool {
    return std.mem.eql(u8, name, stdoutmark);
}

pub fn stat(env: Env, name: []const u8) ?File.Stat {
    return Io.Dir.cwd().statFile(env.io, name, .{}) catch null;
}

pub fn lstatKind(env: Env, name: []const u8) ?File.Kind {
    const st = Io.Dir.cwd().statFile(env.io, name, .{ .follow_symlinks = false }) catch return null;
    return st.kind;
}

fn sameFile(a: File.Stat, b: File.Stat) bool {
    return a.inode == b.inode and a.size == b.size and a.mtime.nanoseconds == b.mtime.nanoseconds and a.kind == b.kind;
}

/// `FIO_removeFile`: only a regular file, and quietly nothing otherwise.
fn removeFile(env: Env, name: []const u8) bool {
    const st = stat(env, name) orelse {
        disp.at(2, "zstd: Failed to stat {s} while trying to remove it\n", .{name});
        return true;
    };
    if (st.kind != .file) {
        disp.at(2, "zstd: Refusing to remove non-regular file {s}\n", .{name});
        return true;
    }
    Io.Dir.cwd().deleteFile(env.io, name) catch return false;
    return true;
}

// ------------------------------------------------------------ input side

/// An opened source: the file, whether we own its handle, its stat.
const Src = struct {
    file: File,
    owned: bool,
    st: ?File.Stat,

    fn close(s: Src, io: Io) void {
        if (s.owned) s.file.close(io);
    }

    /// `UTIL_getFileSizeStat`: unknown unless a regular file.
    fn size(s: Src) ?u64 {
        const st = s.st orelse return null;
        return if (st.kind == .file) st.size else null;
    }
};

/// `FIO_openSrcFile`.
fn openSrc(env: Env, prefs: *const Prefs, name: []const u8) ?Src {
    if (isStdin(name)) {
        disp.at(4, "Using stdin for input \n", .{});
        return .{ .file = File.stdin(), .owned = false, .st = null };
    }
    const st = Io.Dir.cwd().statFile(env.io, name, .{}) catch |e| {
        disp.at(1, "zstd: can't stat {s} : {s} -- ignored \n", .{ name, strerror(e) });
        return null;
    };
    if (st.kind != .file and st.kind != .named_pipe and !(prefs.allow_block_devices and st.kind == .block_device)) {
        disp.at(1, "zstd: {s} is not a regular file -- ignored \n", .{name});
        return null;
    }
    const f = Io.Dir.cwd().openFile(env.io, name, .{}) catch |e| {
        disp.at(1, "zstd: {s}: {s} \n", .{ name, strerror(e) });
        return null;
    };
    return .{ .file = f, .owned = true, .st = st };
}

/// The read side of `AIO_ReadPool`: a buffer of loaded bytes that
/// `fill` tops up by one read job of up to 128 KiB (`fread` semantics:
/// full unless the input ends).
const ReadBuf = struct {
    file: File,
    buf: []u8,
    start: usize = 0,
    end: usize = 0,
    eof: bool = false,

    fn loaded(r: *const ReadBuf) []u8 {
        return r.buf[r.start..r.end];
    }

    fn consume(r: *ReadBuf, n: usize) void {
        r.start += n;
        if (r.start == r.end) {
            r.start = 0;
            r.end = 0;
        }
    }

    /// `AIO_ReadPool_fillBuffer(n)`: when fewer than `n` bytes are loaded,
    /// read the next job; returns how many bytes it read.
    fn fill(r: *ReadBuf, io: Io, n: usize) usize {
        if (r.end - r.start >= @min(n, in_chunk)) return 0;
        if (r.start > 0) {
            std.mem.copyForwards(u8, r.buf, r.buf[r.start..r.end]);
            r.end -= r.start;
            r.start = 0;
        }
        return r.readJob(io);
    }

    fn readJob(r: *ReadBuf, io: Io) usize {
        const want = @min(in_chunk, r.buf.len - r.end);
        var got: usize = 0;
        while (got < want and !r.eof) {
            const n = r.file.readStreaming(io, &.{r.buf[r.end + got .. r.end + want]}) catch |e| switch (e) {
                error.EndOfStream => {
                    r.eof = true;
                    break;
                },
                else => fatal(37, "Read error", .{}),
            };
            got += n;
        }
        r.end += got;
        return got;
    }
};

// ----------------------------------------------------------- output side

/// A destination: stdout, a created file, or nothing (test mode).
const Dst = struct {
    file: File,
    owned: bool,
    w: File.Writer,
    written: u64 = 0,

    fn write(d: *Dst, bytes: []const u8) void {
        if (bytes.len >= direct_write_min) {
            // a whole decoder or encoder output buffer: straight from it, as
            // `fileio.c` does, not copied through `dst_buf` first
            d.w.interface.flush() catch fatal(70, "Write error : cannot write block : {s}", .{strerror(d.w.err orelse error.InputOutput)});
            d.file.writeStreamingAll(d.w.io, bytes) catch |e| fatal(70, "Write error : cannot write block : {s}", .{strerror(e)});
        } else {
            d.w.interface.writeAll(bytes) catch fatal(70, "Write error : cannot write block : {s}", .{strerror(d.w.err orelse error.InputOutput)});
        }
        d.written += bytes.len;
    }

    const direct_write_min = 64 << 10;

    /// Flushes and, for a created file, closes it -- after giving it the
    /// source's permissions and times when `st` is set (`UTIL_setFDStat`,
    /// then `UTIL_utime` once nothing more is written); false on a write
    /// error.
    fn close(d: *Dst, io: Io, st: ?File.Stat) bool {
        d.w.interface.flush() catch return false;
        if (st) |s| {
            d.file.setPermissions(io, .fromMode(s.permissions.toMode() & 0o7777)) catch {};
            d.file.setTimestamps(io, .{
                .access_timestamp = .init(s.atime),
                .modify_timestamp = .{ .new = s.mtime },
            }) catch {};
        }
        if (d.owned) d.file.close(io);
        return true;
    }
};

var dst_buf: [1 << 20]u8 = undefined;

/// `FIO_openDstFile`. `mode`: `DEFAULT_FILE_PERMISSIONS` (0666) or, when
/// the source's permissions will be copied afterwards,
/// `TEMPORARY_FILE_PERMISSIONS` (0600).
fn openDst(env: Env, ctx: *const Ctx, prefs: *const Prefs, src_name: ?[]const u8, dst_name: []const u8, mode: std.posix.mode_t) ?Dst {
    if (prefs.test_mode) return null;
    if (isStdout(dst_name)) {
        disp.at(4, "Using stdout for output \n", .{});
        if (sparse == 1) {
            sparse = 0;
            disp.at(4, "Sparse File Support is automatically disabled on stdout ; try --sparse \n", .{});
        }
        const f = File.stdout();
        return .{ .file = f, .owned = false, .w = f.writerStreaming(env.io, &dst_buf) };
    }
    if (src_name) |s| {
        if (!isStdin(s)) {
            if (stat(env, s)) |a| if (stat(env, dst_name)) |b| if (sameFile(a, b)) {
                disp.at(1, "zstd: Refusing to open an output file which will overwrite the input file \n", .{});
                return null;
            };
        }
    }
    const is_reg_file = if (stat(env, dst_name)) |st| st.kind == .file else false;
    if (sparse == 1 and !is_reg_file) {
        sparse = 0;
        disp.at(4, "Sparse File Support is disabled when output is not a file \n", .{});
    }
    if (stat(env, dst_name)) |st| if (st.kind == .file) {
        if (std.mem.eql(u8, dst_name, nulmark))
            fatal(40, "{s} is unexpectedly categorized as a regular file", .{dst_name});
        if (!prefs.overwrite) {
            if (disp.level <= 1) {
                disp.at(1, "zstd: {s} already exists; not overwritten  \n", .{dst_name});
                return null;
            }
            disp.always("zstd: {s} already exists; ", .{dst_name});
            if (requireConfirmation(env, "overwrite (y/n) ? ", "Not overwritten  \n", "yY", ctx.has_stdin_input))
                return null;
        }
        _ = removeFile(env, dst_name);
    };
    const f = Io.Dir.cwd().createFile(env.io, dst_name, .{ .permissions = .fromMode(mode) }) catch |e| {
        disp.at(1, "zstd: {s}: {s}\n", .{ dst_name, strerror(e) });
        return null;
    };
    return .{ .file = f, .owned = true, .w = f.writerStreaming(env.io, &dst_buf) };
}

/// `UTIL_requireUserConfirmation`: true = abort.
fn requireConfirmation(env: Env, prompt: []const u8, abort_msg: []const u8, letters: []const u8, has_stdin_input: bool) bool {
    if (has_stdin_input) {
        disp.always("stdin is an input - not proceeding.\n", .{});
        return true;
    }
    disp.always("{s}", .{prompt});
    var one: [1]u8 = undefined;
    const n = File.stdin().readStreaming(env.io, &.{&one}) catch 0;
    var abort = true;
    if (n == 1 and std.mem.indexOfScalar(u8, letters, one[0]) != null) abort = false;
    if (abort) disp.always("{s} \n", .{abort_msg});
    // flush the rest of the line
    var ch = one[0];
    var got = n;
    while (got == 1 and ch != '\n') {
        got = File.stdin().readStreaming(env.io, &.{&one}) catch 0;
        ch = one[0];
    }
    return abort;
}

// ------------------------------------------------------------ dictionary

/// `FIO_getDictFileStat`: the dictionary's size, which must be a regular
/// file's.
fn dictFileSize(env: Env, name: ?[]const u8) u64 {
    const n = name orelse return 0;
    const st = stat(env, n) orelse fatal(31, "Stat failed on dictionary file {s}: {s}", .{ n, "No such file or directory" });
    if (st.kind != .file) fatal(32, "Dictionary {s} must be a regular file.", .{n});
    return st.size;
}

/// `FIO_initDict` (malloc'd): the whole file, at most 32 MiB -- or, for
/// `--patch-from`, at most the memory limit.
pub fn loadDict(env: Env, prefs: *const Prefs, name: ?[]const u8) ?[]u8 {
    const n = name orelse return null;
    const size = dictFileSize(env, n);
    const max: u64 = if (prefs.patch_from) prefs.mem_limit else dict_size_max;
    if (size > max) fatal(34, "Dictionary file {s} is too large (> {d} bytes)", .{ n, max });
    return Io.Dir.cwd().readFileAlloc(env.io, n, env.gpa, .limited(@intCast(max + 1))) catch |e|
        fatal(33, "Couldn't open dictionary {s}: {s}", .{ n, strerror(e) });
}

/// `FIO_highbit64`: 0 for 0, where C asserts.
fn highbit64(v: u64) u32 {
    return if (v == 0) 0 else 63 - @clz(v);
}

/// `FIO_adjustMemLimitForPatchFromMode`: the limit grows to the larger of
/// the dictionary and the input.
fn adjustMemLimitForPatchFrom(prefs: *Prefs, dict_size: u64, max_src_size: u64) void {
    const max_size = @max(prefs.mem_limit, dict_size, max_src_size);
    const max_window_size: u64 = @as(u64, 1) << zstd.limits.window_log_max;
    if (max_size == unknown_size) fatal(42, "Using --patch-from with stdin requires --stream-size", .{});
    if (max_size > max_window_size) fatal(42, "Can't handle files larger than {d} GB\n", .{max_window_size / (1 << 30)});
    prefs.mem_limit = @intCast(max_size);
}

/// `FIO_adjustParamsForPatchFromMode`: a window covering the input, and
/// long-distance matching when the level's tables do not reach that far.
fn adjustParamsForPatchFrom(prefs: *Prefs, cp: *CParams, dict_size: u64, max_src_size: u64, level: i32) void {
    const L = zstd.limits;
    const file_window_log = highbit64(max_src_size) + 1;
    const d = zstd.getCParams(level, max_src_size, dict_size);
    adjustMemLimitForPatchFrom(prefs, dict_size, max_src_size);
    if (file_window_log > L.window_log_max)
        disp.at(1, "Max window log exceeded by file (compression ratio will suffer)\n", .{});
    cp.window_log = @max(L.window_log_min, @min(L.window_log_max, file_window_log));
    // `ZSTD_cycleLog`
    const cycle_log = d.chain_log - @intFromBool(@intFromEnum(d.strategy) >= @intFromEnum(zstd.Strategy.btlazy2));
    if (file_window_log > cycle_log) {
        if (!prefs.ldm) disp.at(2, "long mode automatically triggered\n", .{});
        prefs.ldm = true;
    }
    if (@intFromEnum(d.strategy) >= @intFromEnum(zstd.Strategy.btopt)) {
        disp.at(4, "[Optimal parser notes] Consider the following to improve patch size at the cost of speed:\n", .{});
        disp.at(4, "- Set a larger targetLength (e.g. --zstd=targetLength=4096)\n", .{});
        disp.at(4, "- Set a larger chainLog (e.g. --zstd=chainLog={d})\n", .{L.chain_log_max});
        disp.at(4, "- Set a larger LDM hashLog (e.g. --zstd=ldmHashLog={d})\n", .{L.ldm_hash_log_max});
        disp.at(4, "- Set a smaller LDM rateLog (e.g. --zstd=ldmHashRateLog={d})\n", .{0});
        disp.at(4, "Also consider playing around with searchLog and hashLog\n", .{});
    }
}

/// `ADAPT_WINDOWLOG_DEFAULT`: 8 MB, unless the window is set or `--long`.
const adapt_window_log_default = 23;

/// `UTIL_FILESIZE_UNKNOWN`.
const unknown_size = std.math.maxInt(u64);

/// `FIO_getLargestFileSize`: an unknown size is the largest.
fn largestFileSize(env: Env, names: []const []const u8) u64 {
    var max: u64 = 0;
    for (names) |n| {
        const st = stat(env, n);
        const size = if (st != null and st.?.kind == .file) st.?.size else unknown_size;
        max = @max(max, size);
    }
    return max;
}

// ------------------------------------------------------------ compression

/// `cRess_t`: one stream reused for every file, its buffers, the dictionary.
pub const CRess = struct {
    stream: zstd.Stream,
    /// The stream's options (`requestedParams`): `--adapt` moves their
    /// level, and the next file starts from where the last one left it,
    /// as the C's context does.
    opts: zstd.StreamOptions,
    /// The command line's level, where each file's adaptation starts
    /// (`FIO_compressZstdFrame`'s `compressionLevel`).
    level: i32,
    dict: ?[]u8,
    dict_name: ?[]const u8,
    dict_stat: ?File.Stat,
    in_buf: []u8,
    out_buf: []u8,
    /// A destination shared by every file (`-o`/`-c` with several inputs).
    shared: ?*Dst = null,

    /// `FIO_createCResources`. `max_src_size`: the largest input's size,
    /// for `--patch-from`.
    pub fn init(env: Env, prefs: *Prefs, dict_name: ?[]const u8, max_src_size: u64, level: i32, cp_in: CParams) CRess {
        disp.at(6, "FIO_createCResources \n", .{});
        var cp = cp_in;
        // the limit is updated before the dictionary is read: it checks it
        if (prefs.patch_from) {
            const dict_size = dictFileSize(env, dict_name);
            adjustParamsForPatchFrom(prefs, &cp, dict_size, if (prefs.stream_src_size > 0) prefs.stream_src_size else max_src_size, level);
        }
        const dict = loadDict(env, prefs, dict_name);
        if (prefs.adaptive and !prefs.ldm and cp.window_log == 0) cp.window_log = adapt_window_log_default;
        var adv: zstd.Advanced = .{
            .content_size = prefs.content_size,
            .dict_id_flag = prefs.dict_id,
            .target_c_block_size = if (prefs.target_cblock_size != 0) prefs.target_cblock_size else null,
            .long_distance_matching = if (prefs.ldm) .enable else .auto,
            .ldm_hash_log = nz(prefs.ldm_hash_log),
            .ldm_min_match = nz(prefs.ldm_min_match),
            .ldm_bucket_size_log = prefs.ldm_bucket_size_log,
            .ldm_hash_rate_log = prefs.ldm_hash_rate_log,
            .row_match_finder = prefs.row_match_finder,
            .window_log = nz(cp.window_log),
            .chain_log = nz(cp.chain_log),
            .hash_log = nz(cp.hash_log),
            .search_log = nz(cp.search_log),
            .min_match = nz(cp.min_match),
            .target_length = nz(cp.target_length),
            .strategy = strategyOf(cp.strategy) catch fatal(11, "{s}", .{zstdErrorName(error.ParameterOutOfBound)}),
            .literal_compression = prefs.literal_compression,
            .enable_dedicated_dict_search = true,
            // libzstd clamps these two where the module refuses them
            .nb_workers = @min(prefs.nb_workers, zstd.limits.nb_workers_max),
            .job_size = @min(prefs.block_size, zstd.limits.job_size_max),
            .rsyncable = prefs.rsyncable,
        };
        // libzstd clamps the overlap log where the module refuses it
        disp.at(5, "set nb workers = {d} \n", .{prefs.nb_workers});
        if (prefs.overlap_log) |o| {
            disp.at(3, "set overlapLog = {d} \n", .{o});
            adv.overlap_log = @min(o, zstd.limits.overlap_log_max);
        }
        const opts: zstd.StreamOptions = .{
            .level = level,
            .checksum = prefs.checksum != 0,
            .src_size_hint = if (prefs.src_size_hint != 0) prefs.src_size_hint else null,
            .advanced = adv,
            .dictionary = if (dict) |d|
                (if (prefs.patch_from) .{ .prefix = .{ .bytes = d } } else .{ .raw = .{ .bytes = d } })
            else
                .none,
        };
        const stream = zstd.Stream.init(env.gpa, opts) catch |e| fatal(11, "{s}", .{zstdErrorName(e)});
        return .{
            .stream = stream,
            .opts = opts,
            .level = level,
            .dict = dict,
            .dict_name = dict_name,
            .dict_stat = if (dict_name) |n| stat(env, n) else null,
            .in_buf = env.gpa.alloc(u8, in_chunk) catch fatal(21, "Allocation error : not enough memory", .{}),
            .out_buf = env.gpa.alloc(u8, cout_size) catch fatal(21, "Allocation error : not enough memory", .{}),
        };
    }

    /// `ZSTD_CCtx_setParameter(ZSTD_c_compressionLevel)`.
    fn setLevel(r: *CRess, level: i32) void {
        r.stream.setLevel(level) catch {};
        r.opts.level = level;
    }

    pub fn deinit(r: *CRess, env: Env) void {
        r.stream.deinit();
        if (r.dict) |d| env.gpa.free(d);
        env.gpa.free(r.in_buf);
        env.gpa.free(r.out_buf);
    }
};

/// `--zstd=strat=#`: 0 is "not set", above `btultra2` out of bounds.
pub fn strategyOf(v: u32) error{ParameterOutOfBound}!?zstd.Strategy {
    if (v == 0) return null;
    return std.enums.fromInt(zstd.Strategy, v) orelse error.ParameterOutOfBound;
}

fn nz(v: u32) ?u32 {
    return if (v == 0) null else v;
}

/// `FIO_compressZstdFrame`: returns the compressed size.
fn compressFrame(env: Env, ctx: *const Ctx, prefs: *const Prefs, ress: *CRess, dst: ?*Dst, src: Src, src_name: []const u8, readsize: *u64) u64 {
    const file_size = src.size();
    var opts = ress.opts;
    disp.at(6, "compression using zstd format \n", .{});
    opts.pledged_size = file_size orelse if (prefs.stream_src_size > 0) prefs.stream_src_size else null;
    ress.stream.reset(opts) catch |e| fatal(11, "{s}", .{zstdErrorName(e)});
    {
        // the window the decoder will need: the explicit one, long mode's
        // default, or the level's for the size
        const window_log: u32 = opts.advanced.window_log orelse if (prefs.ldm)
            27 // ZSTD_WINDOWLOG_LIMIT_DEFAULT
        else
            zstd.getCParams(ress.level, file_size orelse unknown_size, 0).window_log;
        const pledged = opts.pledged_size orelse unknown_size;
        const h = disp.hrs(@max(1, @min(@as(u64, 1) << @intCast(window_log), pledged)));
        if (disp.level >= 4) {
            const w = disp.err();
            w.writeAll("Decompression will require ") catch {};
            disp.fixed(w, h.value, 0, h.precision) catch {};
            w.print("{s} of memory\n", .{h.suffix}) catch {};
            disp.flush();
        }
    }
    var compressed: u64 = 0;
    var adapt: Adapt = .{ .level = ress.level, .last_time = now(env.io) };
    var rb: ReadBuf = .{ .file = src.file, .buf = ress.in_buf };
    var directive: zstd.EndDirective = .@"continue";
    while (directive != .end) {
        const n = rb.readJob(env.io);
        disp.at(6, "fread {d} bytes from source \n", .{n});
        readsize.* += n;
        if (n == 0 or (file_size != null and readsize.* == file_size.?)) directive = .end;
        var in: zstd.InBuffer = .{ .src = rb.loaded() };
        var still: usize = 1;
        while (in.pos != in.src.len or (directive == .end and still != 0)) {
            const old_ipos = in.pos;
            var out: zstd.OutBuffer = .{ .dst = ress.out_buf };
            const to_flush_now = ress.stream.toFlushNow();
            still = ress.stream.compressStream2(&out, &in, directive) catch |e| fatal(11, "{s}", .{zstdErrorName(e)});
            // count stats
            adapt.input_presented += 1;
            // the input buffer is full and can't take any more: input
            // speed is faster than consumption rate
            if (old_ipos == in.pos) adapt.input_blocked += 1;
            if (to_flush_now == 0) adapt.flush_waiting = true;
            disp.at(6, "ZSTD_compress_generic(end:{d}) => input pos({d})<=({d})size ; output generated {d} bytes \n", .{ @intFromEnum(directive), in.pos, in.src.len, out.pos });
            if (out.pos != 0) {
                if (dst) |d| d.write(ress.out_buf[0..out.pos]);
                compressed += out.pos;
            }
            // adaptive mode: statistics measurement and speed correction
            if (prefs.adaptive and @divTrunc(now(env.io) - adapt.last_time, std.time.ns_per_us) > adapt_every_us) {
                adapt.last_time = now(env.io);
                adapt.correct(prefs, ress);
            }
            // display notification
            if (disp.shouldProgress() and disp.readyForUpdate(env.io)) {
                const fp = ress.stream.frameProgression();
                showCompressProgress(env.io, ctx, adapt.level, src_name, file_size, fp.ingested - fp.consumed, fp.consumed, fp.produced);
            }
        }
        rb.consume(rb.end - rb.start);
    }
    if (file_size) |fs| if (readsize.* != fs)
        fatal(27, "Read error : Incomplete read : {d} / {d} B", .{ readsize.*, fs });
    return compressed;
}

fn now(io: Io) i96 {
    return Io.Timestamp.now(io, .awake).nanoseconds;
}

/// `REFRESH_RATE`: how often `--adapt` looks at the stream.
const adapt_every_us = std.time.us_per_s / 6;

/// `--adapt`'s statistics in `FIO_compressZstdFrame`, and its correction:
/// with workers, the level goes up by one when the compression outruns
/// the output or waits for input, and down by one when the input is
/// blocked often while everything produced is flushed and the input keeps
/// up -- at most once per job completed. Only its outcome can be compared
/// with the C command's, never its bytes: both depend on timing.
const Adapt = struct {
    /// `compressionLevel`: the frame's own, from the command line's.
    level: i32,
    last_time: i96,
    speed_change: enum { no_change, slower, faster } = .no_change,
    prev_update: zstd.FrameProgression = zero_progression,
    prev_correction: zstd.FrameProgression = zero_progression,
    flush_waiting: bool = false,
    input_presented: u32 = 0,
    input_blocked: u32 = 0,
    last_job_id: u32 = 0,

    const zero_progression: zstd.FrameProgression = .{ .ingested = 0, .consumed = 0, .produced = 0, .flushed = 0, .current_job_id = 0, .nb_active_workers = 0 };

    fn correct(a: *Adapt, prefs: *const Prefs, ress: *CRess) void {
        const zfp = ress.stream.frameProgression();
        // check output speed
        if (zfp.current_job_id > 1) { // only possible if nbWorkers >= 1
            std.debug.assert(zfp.produced >= a.prev_update.produced);
            std.debug.assert(prefs.nb_workers >= 1);
            const newly_produced = zfp.produced - a.prev_update.produced;
            const newly_flushed = zfp.flushed - a.prev_update.flushed;
            // test if compression is blocked, either because output is
            // slow and all buffers are full, or because input is slow and
            // no job can start while waiting for at least one buffer to be
            // filled. note: exclude starting part, since currentJobID > 1
            if (zfp.consumed == a.prev_update.consumed // no data compressed: no data available, or no more buffer to compress to, OR compression is really slow (compression of a single block is slower than update rate)
            and zfp.nb_active_workers == 0) { // confirmed: no compression ongoing
                disp.at(6, "all buffers full : compression stopped => slow down \n", .{});
                a.speed_change = .slower;
            }
            a.prev_update = zfp;
            if (newly_produced > newly_flushed * 9 / 8 // compression produces more data than output can flush (though production can be spiky, due to work unit: (N==4)*block sizes)
            and !a.flush_waiting) { // flush speed was never slowed by lack of production, so it's operating at max capacity
                disp.at(6, "compression faster than flush ({d} > {d}), and flushed was never slowed down by lack of production => slow down \n", .{ newly_produced, newly_flushed });
                a.speed_change = .slower;
            }
            a.flush_waiting = false;
        }
        // course correct only if there is at least one new job completed
        if (zfp.current_job_id > a.last_job_id) {
            disp.at(6, "compression level adaptation check \n", .{});
            // check input speed
            if (zfp.current_job_id > prefs.nb_workers + 1) { // warm up period, to fill all workers
                if (a.input_blocked == 0) {
                    disp.at(6, "input is never blocked => input is slower than ingestion \n", .{});
                    a.speed_change = .slower;
                } else if (a.speed_change == .no_change) {
                    const newly_ingested = zfp.ingested - a.prev_correction.ingested;
                    const newly_consumed = zfp.consumed - a.prev_correction.consumed;
                    const newly_produced = zfp.produced - a.prev_correction.produced;
                    const newly_flushed = zfp.flushed - a.prev_correction.flushed;
                    a.prev_correction = zfp;
                    std.debug.assert(a.input_presented > 0);
                    disp.at(6, "input blocked {d}/{d}({d:.2}) - ingested:{d} vs {d}:consumed - flushed:{d} vs {d}:produced \n", .{
                        a.input_blocked,
                        a.input_presented,
                        @as(f64, @floatFromInt(a.input_blocked)) / @as(f64, @floatFromInt(a.input_presented)) * 100,
                        @as(u32, @truncate(newly_ingested)),
                        @as(u32, @truncate(newly_consumed)),
                        @as(u32, @truncate(newly_flushed)),
                        @as(u32, @truncate(newly_produced)),
                    });
                    if (a.input_blocked > a.input_presented / 8 // input is waiting often, because input buffers is full: compression or output too slow
                    and newly_flushed * 33 / 32 > newly_produced // flush everything that is produced
                    and newly_ingested * 33 / 32 > newly_consumed) { // input speed as fast or faster than compression speed
                        disp.at(6, "recommend faster as in({d}) >= ({d})comp({d}) <= out({d}) \n", .{ newly_ingested, newly_consumed, newly_produced, newly_flushed });
                        a.speed_change = .faster;
                    }
                }
                a.input_blocked = 0;
                a.input_presented = 0;
            }
            if (a.speed_change == .slower) {
                disp.at(6, "slower speed , higher compression \n", .{});
                a.level += 1;
                if (a.level > zstd.max_level) a.level = zstd.max_level;
                if (a.level > prefs.adapt_max) a.level = prefs.adapt_max;
                a.level += @intFromBool(a.level == 0); // skip 0
                ress.setLevel(a.level);
            }
            if (a.speed_change == .faster) {
                disp.at(6, "faster speed , lighter compression \n", .{});
                a.level -= 1;
                if (a.level < prefs.adapt_min) a.level = prefs.adapt_min;
                a.level -= @intFromBool(a.level == 0); // skip 0
                ress.setLevel(a.level);
            }
            a.speed_change = .no_change;
            a.last_job_id = zfp.current_job_id;
        }
    }
};

/// The progress line of `FIO_compressZstdFrame`.
fn showCompressProgress(io: Io, ctx: *const Ctx, level: i32, src_name: []const u8, file_size: ?u64, buffered: u64, consumed: u64, produced: u64) void {
    const c_share = @as(f64, @floatFromInt(produced)) / @as(f64, @floatFromInt(consumed + @intFromBool(consumed == 0))) * 100;
    const b = disp.hrs(buffered);
    const c = disp.hrs(consumed);
    const p = disp.hrs(produced);
    disp.delayNextUpdate(io);
    disp.clearProgress(); // clear out the current displayed line
    if (!disp.shouldProgress() or disp.level < 1) return;
    const w = disp.err();
    if (disp.level >= 3) {
        // verbose progress update
        w.print("(L{d}) Buffered:", .{level}) catch {};
        disp.fixed(w, b.value, 5, b.precision) catch {};
        w.print("{s} - Consumed:", .{b.suffix}) catch {};
        disp.fixed(w, c.value, 5, c.precision) catch {};
        w.print("{s} - Compressed:", .{c.suffix}) catch {};
        disp.fixed(w, p.value, 5, p.precision) catch {};
        w.print("{s} => ", .{p.suffix}) catch {};
        disp.fixed(w, c_share, 0, 2) catch {};
        w.writeAll("% ") catch {};
    } else {
        if (ctx.nb_files_total > 1) {
            // roughly the same width each time
            w.print("Compress: {d}/{d} files. Current: ", .{ ctx.curr_file_idx + 1, ctx.nb_files_total }) catch {};
            if (src_name.len > 18) {
                w.print("...{s} ", .{src_name[src_name.len - 15 ..]}) catch {};
            } else {
                // `%*s` with a width of 18 - length, as C has it
                disp.right(w, src_name, 18 - src_name.len) catch {};
                w.writeAll(" ") catch {};
            }
        }
        w.writeAll("Read:") catch {};
        disp.fixed(w, c.value, 6, c.precision) catch {};
        disp.right(w, c.suffix, 4) catch {};
        w.writeAll(" ") catch {};
        if (file_size) |fs| {
            const f = disp.hrs(fs);
            w.writeAll("/") catch {};
            disp.fixed(w, f.value, 6, f.precision) catch {};
            disp.right(w, f.suffix, 4) catch {};
        }
        w.writeAll(" ==> ") catch {};
        disp.fixed(w, c_share, 2, 0) catch {};
        w.writeAll("%") catch {};
    }
    disp.flush();
}

/// `FIO_compressFilename_internal`.
fn compressInternal(env: Env, ctx: *Ctx, prefs: *const Prefs, ress: *CRess, dst: ?*Dst, dst_name: []const u8, src: Src, src_name: []const u8) void {
    var readsize: u64 = 0;
    const time_start = Io.Timestamp.now(env.io, .awake).nanoseconds;
    const cpu_start = Io.Timestamp.now(env.io, .cpu_process).nanoseconds;
    disp.at(5, "{s}: {d} bytes \n", .{ src_name, src.size() orelse std.math.maxInt(u64) });
    const compressed = compressFrame(env, ctx, prefs, ress, dst, src, src_name, &readsize);
    ctx.total_in += readsize;
    ctx.total_out += compressed;
    disp.clearProgress();
    if (ctx.fileSummary() and disp.shouldSummary() and disp.level >= 1) {
        const w = disp.err();
        const hi = disp.hrs(readsize);
        const ho = disp.hrs(compressed);
        disp.left(w, src_name, 20) catch {};
        if (readsize == 0) {
            w.writeAll(" :  (") catch {};
        } else {
            w.writeAll(" :") catch {};
            disp.fixed(w, @as(f64, @floatFromInt(compressed)) / @as(f64, @floatFromInt(readsize)) * 100, 6, 2) catch {};
            w.writeAll("%   (") catch {};
        }
        disp.fixed(w, hi.value, 6, hi.precision) catch {};
        w.print("{s} => ", .{hi.suffix}) catch {};
        disp.fixed(w, ho.value, 6, ho.precision) catch {};
        w.print("{s}, {s}) \n", .{ ho.suffix, dst_name }) catch {};
        disp.flush();
    }
    // elapsed time and CPU load
    if (disp.level >= 4) {
        const cpu_s = @as(f64, @floatFromInt(Io.Timestamp.now(env.io, .cpu_process).nanoseconds - cpu_start)) / 1e9;
        const time_s = @as(f64, @floatFromInt(Io.Timestamp.now(env.io, .awake).nanoseconds - time_start)) / 1e9;
        const w = disp.err();
        disp.left(w, src_name, 20) catch {};
        w.writeAll(" : Completed in ") catch {};
        disp.fixed(w, time_s, 0, 2) catch {};
        w.writeAll(" sec  (cpu load : ") catch {};
        disp.fixed(w, cpu_s / time_s * 100, 0, 0) catch {};
        w.writeAll("%)\n") catch {};
        disp.flush();
    }
}

/// `FIO_compressFilename_dstFile`: 0 ok, 1 failed.
fn compressDstFile(env: Env, ctx: *Ctx, prefs: *const Prefs, ress: *CRess, dst_name: []const u8, src: Src, src_name: []const u8) u1 {
    if (ress.shared) |d| {
        compressInternal(env, ctx, prefs, ress, d, dst_name, src, src_name);
        return 0;
    }
    const transfer = !isStdin(src_name) and !isStdout(dst_name) and src.st != null and src.st.?.kind == .file;
    disp.at(6, "FIO_compressFilename_dstFile: opening dst: {s} \n", .{dst_name});
    var dst = openDst(env, ctx, prefs, src_name, dst_name, if (transfer) 0o600 else 0o666) orelse
        return if (prefs.test_mode) blk: {
            compressInternal(env, ctx, prefs, ress, null, dst_name, src, src_name);
            break :blk 0;
        } else 1;
    compressInternal(env, ctx, prefs, ress, &dst, dst_name, src, src_name);
    var result: u1 = 0;
    disp.at(6, "FIO_compressFilename_dstFile: closing dst: {s} \n", .{dst_name});
    if (!dst.close(env.io, if (transfer) src.st.? else null)) {
        disp.at(1, "zstd: {s}: {s} \n", .{ dst_name, "Input/output error" });
        result = 1;
    }
    if (result != 0 and !isStdout(dst_name)) _ = removeFile(env, dst_name);
    return result;
}

/// `compressedFileExtensions` (`--exclude-compressed`).
const compressed_extensions = [_][]const u8{
    ".zst",  ".tzst", ".gz",   ".tgz",  ".lzma",  ".xz",   ".txz",  ".lz4",  ".tlz4", ".7z",
    ".aa3",  ".aac",  ".aar",  ".ace",  ".alac",  ".ape",  ".apk",  ".apng", ".arc",  ".archive",
    ".arj",  ".ark",  ".asf",  ".avi",  ".avif",  ".ba",   ".br",   ".bz2",  ".cab",  ".cdx",
    ".chm",  ".cr2",  ".divx", ".dmg",  ".dng",   ".docm", ".docx", ".dotm", ".dotx", ".dsft",
    ".ear",  ".eftx", ".emz",  ".eot",  ".epub",  ".f4v",  ".flac", ".flv",  ".gho",  ".gif",
    ".gifv", ".gnp",  ".iso",  ".jar",  ".jpeg",  ".jpg",  ".jxl",  ".lz",   ".lzh",  ".m4a",
    ".m4v",  ".mkv",  ".mov",  ".mp2",  ".mp3",   ".mp4",  ".mpa",  ".mpc",  ".mpe",  ".mpeg",
    ".mpg",  ".mpl",  ".mpv",  ".msi",  ".odp",   ".ods",  ".odt",  ".ogg",  ".ogv",  ".otp",
    ".ots",  ".ott",  ".pea",  ".png",  ".pptx",  ".qt",   ".rar",  ".s7z",  ".sfx",  ".sit",
    ".sitx", ".sqx",  ".svgz", ".swf",  ".tbz2",  ".tib",  ".tlz",  ".vob",  ".war",  ".webm",
    ".webp", ".wma",  ".wmv",  ".woff", ".woff2", ".wvl",  ".xlsx", ".xpi",  ".xps",  ".zip",
    ".zipx", ".zoo",  ".zpaq",
};

/// `UTIL_isCompressedFile`: the extension after the last dot.
fn isCompressedFile(name: []const u8) bool {
    const dot = std.mem.lastIndexOfScalar(u8, name, '.') orelse return false;
    for (compressed_extensions) |ext| if (std.mem.eql(u8, name[dot..], ext)) return true;
    return false;
}

/// `FIO_compressFilename_srcFile`: 0 ok, 1 failed.
fn compressSrcFile(env: Env, ctx: *Ctx, prefs: *const Prefs, ress: *CRess, dst_name: []const u8, src_name: []const u8) u1 {
    disp.at(6, "FIO_compressFilename_srcFile: {s} \n", .{src_name});
    if (!isStdin(src_name)) {
        if (stat(env, src_name)) |st| {
            if (st.kind == .directory) {
                disp.at(1, "zstd: {s} is a directory -- ignored \n", .{src_name});
                return 1;
            }
            if (ress.dict_stat) |ds| if (sameFile(st, ds)) {
                disp.at(1, "zstd: cannot use {s} as an input file and dictionary \n", .{src_name});
                return 1;
            };
        }
    }
    if (prefs.exclude_compressed and isCompressedFile(src_name)) {
        disp.at(4, "File is already compressed : {s} \n", .{src_name});
        return 0;
    }
    const src = openSrc(env, prefs, src_name) orelse return 1;
    const result = compressDstFile(env, ctx, prefs, ress, dst_name, src, src_name);
    src.close(env.io);
    if (prefs.remove_src and result == 0 and !isStdin(src_name)) {
        if (!removeFile(env, src_name)) fatal(1, "zstd: {s}: {s}", .{ src_name, "Operation not permitted" });
    }
    return result;
}

/// `FIO_compressFilename`.
pub fn compressFilename(env: Env, ctx: *Ctx, prefs: *Prefs, dst_name: []const u8, src_name: []const u8, dict_name: ?[]const u8, level: i32, cp: CParams) u1 {
    var ress: CRess = .init(env, prefs, dict_name, largestFileSize(env, &.{src_name}), level, cp);
    defer ress.deinit(env);
    return compressSrcFile(env, ctx, prefs, &ress, dst_name, src_name);
}

/// `FIO_multiFilesConcatWarning`: true = abort.
fn multiFilesConcatWarning(env: Env, ctx: *const Ctx, prefs: *Prefs, out_name: []const u8) bool {
    if (ctx.has_stdout_output and prefs.remove_src)
        fatal(43, "It's not allowed to remove input files when processed output is piped to stdout. This scenario is not supposed to be possible. This is a programming error. File an issue for it to be fixed.", .{});
    if (prefs.test_mode) {
        if (prefs.remove_src)
            fatal(43, "Test mode shall not remove input files! This scenario is not supposed to be possible. This is a programming error. File an issue for it to be fixed.", .{});
        return false;
    }
    if (ctx.nb_files_total == 1) return false;
    if (ctx.has_stdout_output) {
        disp.at(2, "zstd: WARNING: all input files will be processed and concatenated into stdout. \n", .{});
    } else {
        disp.at(2, "zstd: WARNING: all input files will be processed and concatenated into a single output file: {s} \n", .{out_name});
    }
    disp.at(2, "The concatenated output CANNOT regenerate original file names nor directory structure. \n", .{});
    if (prefs.remove_src) {
        disp.at(2, "Since it's a destructive operation, input files will not be removed. \n", .{});
        prefs.remove_src = false;
    }
    if (ctx.has_stdout_output) return false;
    if (prefs.overwrite) return false;
    if (disp.level <= 1) {
        disp.at(1, "Concatenating multiple processed inputs into a single output loses file metadata. \n", .{});
        disp.at(1, "Aborting. \n", .{});
        return true;
    }
    return requireConfirmation(env, "Proceed? (y/n): ", "Aborting...", "yY", ctx.has_stdin_input);
}

/// `FIO_compressMultipleFilenames`.
pub fn compressMultiple(env: Env, ctx: *Ctx, prefs: *Prefs, names: []const []const u8, mirror_root: ?[]const u8, out_dir: ?[]const u8, out_name: ?[]const u8, suffix: []const u8, dict_name: ?[]const u8, level: i32, cp: CParams) u1 {
    var ress: CRess = .init(env, prefs, dict_name, largestFileSize(env, names[0..ctx.nb_files_total]), level, cp);
    defer ress.deinit(env);
    var err: u1 = 0;
    if (out_name) |o| {
        if (multiFilesConcatWarning(env, ctx, prefs, o)) return 1;
        var dst = openDst(env, ctx, prefs, null, o, 0o666);
        if (dst == null and !prefs.test_mode) {
            err = 1;
        } else {
            ress.shared = if (dst) |*d| d else null;
            while (ctx.curr_file_idx < ctx.nb_files_total) : (ctx.curr_file_idx += 1) {
                const status = compressSrcFile(env, ctx, prefs, &ress, o, names[ctx.curr_file_idx]);
                if (status == 0) ctx.nb_files_processed += 1;
                err |= status;
            }
            if (dst) |*d| if (!d.close(env.io, null)) fatal(29, "Write error (Input/output error) : cannot properly close {s}", .{o});
        }
    } else {
        var arena_state: std.heap.ArenaAllocator = .init(env.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        if (mirror_root) |root| util.mirrorSourceFilesDirectories(env, arena, names[0..ctx.nb_files_total], root);
        while (ctx.curr_file_idx < ctx.nb_files_total) : (ctx.curr_file_idx += 1) {
            const src_name = names[ctx.curr_file_idx];
            var dir = out_dir;
            if (mirror_root) |root| {
                dir = util.mirroredDestDirName(arena, src_name, root) orelse {
                    disp.at(2, "zstd: --output-dir-mirror cannot compress '{s}' into '{s}' \n", .{ src_name, root });
                    err = 1;
                    continue;
                };
            }
            const dst_name = compressedName(env.gpa, src_name, dir, suffix);
            defer if (!isStdout(dst_name)) env.gpa.free(dst_name);
            const status = compressSrcFile(env, ctx, prefs, &ress, dst_name, src_name);
            if (status == 0) ctx.nb_files_processed += 1;
            err |= status;
        }
        if (out_dir != null) checkFilenameCollisions(env.gpa, names[0..ctx.nb_files_total]);
    }
    if (ctx.multiSummary()) {
        const hi = disp.hrs(ctx.total_in);
        const ho = disp.hrs(ctx.total_out);
        disp.clearProgress();
        if (disp.shouldSummary() and disp.level >= 1) {
            const w = disp.err();
            var nb: [16]u8 = undefined;
            disp.right(w, std.fmt.bufPrint(&nb, "{d}", .{ctx.nb_files_processed}) catch unreachable, 3) catch {};
            if (ctx.total_in == 0) {
                w.writeAll(" files compressed : (") catch {};
            } else {
                w.writeAll(" files compressed : ") catch {};
                disp.fixed(w, @as(f64, @floatFromInt(ctx.total_out)) / @as(f64, @floatFromInt(ctx.total_in)) * 100, 0, 2) catch {};
                w.writeAll("% (") catch {};
            }
            disp.fixed(w, hi.value, 6, hi.precision) catch {};
            disp.right(w, hi.suffix, 4) catch {};
            w.writeAll(" => ") catch {};
            disp.fixed(w, ho.value, 6, ho.precision) catch {};
            disp.right(w, ho.suffix, 4) catch {};
            w.writeAll(")\n") catch {};
            disp.flush();
        }
    }
    return err;
}

/// `FIO_determineCompressedName`.
fn compressedName(gpa: std.mem.Allocator, src_name: []const u8, out_dir: ?[]const u8, suffix: []const u8) []const u8 {
    if (isStdin(src_name)) return stdoutmark;
    const parts = fromOutDir(src_name, out_dir);
    return std.mem.concat(gpa, u8, &.{ parts[0], parts[1], parts[2], suffix }) catch fatal(30, "zstd: Cannot allocate memory", .{});
}

/// `FIO_createFilename_fromOutDir` as three pieces: the directory, a `/`
/// unless it ends with one, and the source's file name. Without a
/// directory, the source name as it is (last).
fn fromOutDir(src_name: []const u8, out_dir: ?[]const u8) [3][]const u8 {
    const d = out_dir orelse return .{ "", "", src_name };
    const base = if (std.mem.lastIndexOfScalar(u8, src_name, '/')) |i| src_name[i + 1 ..] else src_name;
    return .{ d, if (d[d.len - 1] == '/') "" else "/", base };
}

/// `FIO_checkFilenameCollisions`: a warning for each file name (the part
/// after the last `/`) met twice, in sorted order.
fn checkFilenameCollisions(gpa: std.mem.Allocator, names: []const []const u8) void {
    const sorted = gpa.alloc([]const u8, names.len) catch {
        disp.at(1, "Allocation error during filename collision checking \n", .{});
        return;
    };
    defer gpa.free(sorted);
    for (names, sorted) |n, *s| s.* = if (std.mem.lastIndexOfScalar(u8, n, '/')) |i| n[i + 1 ..] else n;
    std.mem.sort([]const u8, sorted, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lt);
    for (sorted[1..], 0..) |n, k| if (std.mem.eql(u8, sorted[k], n))
        disp.at(2, "WARNING: Two files have same filename: {s}\n", .{sorted[k]});
}

// ---------------------------------------------------------- decompression

/// `dRess_t`.
pub const DRess = struct {
    stream: zstd.DecompressStream,
    dict: ?[]u8,
    rb_buf: []u8,
    out_buf: []u8,
    shared: ?*Dst = null,

    /// `FIO_createDResources`.
    pub fn init(env: Env, prefs: *Prefs, dict_name: ?[]const u8) DRess {
        if (prefs.patch_from) adjustMemLimitForPatchFrom(prefs, dictFileSize(env, dict_name), 0);
        const dict = loadDict(env, prefs, dict_name);
        const stream = zstd.DecompressStream.init(env.gpa, .{
            .max_window_size = prefs.mem_limit,
            .ignore_checksum = prefs.checksum == 0,
            .dictionary = if (prefs.patch_from) null else dict,
            // `ZSTD_DCtx_refPrefix`: the first frame only
            .prefix = if (prefs.patch_from) dict else null,
        }) catch |e| fatal(11, "{s}", .{zstdErrorName(e)});
        return .{
            .stream = stream,
            .dict = dict,
            .rb_buf = env.gpa.alloc(u8, 2 * din_size) catch fatal(21, "Allocation error : not enough memory", .{}),
            .out_buf = env.gpa.alloc(u8, dout_size) catch fatal(21, "Allocation error : not enough memory", .{}),
        };
    }

    pub fn deinit(r: *DRess, env: Env) void {
        r.stream.deinit();
        if (r.dict) |d| env.gpa.free(d);
        env.gpa.free(r.rb_buf);
        env.gpa.free(r.out_buf);
    }
};

/// `FIO_zstdErrorHelp`: the one error with advice.
fn zstdErrorHelp(prefs: *const Prefs, e: anyerror, loaded: []const u8, src_name: []const u8) void {
    if (e != error.FrameParameterWindowTooLarge) return;
    const hr = zstd.getFrameHeader(loaded) catch return;
    const h = switch (hr) {
        .header => |h| h,
        .need => return,
    };
    const ws = h.window_size;
    const wlog: u32 = @as(u32, 63 - @clz(ws)) + @intFromBool(ws & (ws - 1) != 0);
    disp.at(1, "{s} : Window size larger than maximum : {d} > {d} \n", .{ src_name, ws, prefs.mem_limit });
    if (wlog <= 31) {
        const wmb = (ws >> 20) + @intFromBool(ws & ((1 << 20) - 1) != 0);
        disp.at(1, "{s} : Use --long={d} or --memory={d}MB \n", .{ src_name, wlog, wmb });
        return;
    }
    disp.at(1, "{s} : Window log larger than ZSTD_WINDOWLOG_MAX={d}; not supported \n", .{ src_name, 31 });
}

/// `FIO_decompressZstdFrame`: the frame's size, or null on an error.
fn decompressFrame(env: Env, ctx: *const Ctx, prefs: *const Prefs, ress: *DRess, rb: *ReadBuf, dst: ?*Dst, src_name: []const u8, already_decoded: u64) ?u64 {
    var frame_size: u64 = 0;
    // display the last 20 characters only when not --verbose
    const name20 = if (src_name.len > 20 and disp.level < 3) src_name[src_name.len - 20 ..] else src_name;
    ress.stream.reset();
    _ = rb.fill(env.io, 18); // ZSTD_FRAMEHEADERSIZE_MAX
    while (true) {
        var in: zstd.InBuffer = .{ .src = rb.loaded() };
        var out: zstd.OutBuffer = .{ .dst = ress.out_buf };
        const hint = ress.stream.decompressStream(&out, &in) catch |e| {
            disp.at(1, "{s} : Decoding error (36) : {s} \n", .{ src_name, zstdErrorName(e) });
            zstdErrorHelp(prefs, e, rb.loaded(), src_name);
            return null;
        };
        // the size before this block's output, as C computes it
        const h = disp.hrs(already_decoded + frame_size);
        if (dst) |d| d.write(ress.out_buf[0..out.pos]);
        frame_size += out.pos;
        if (disp.shouldProgress() and disp.readyForUpdate(env.io)) showDecompressProgress(env.io, ctx, name20, h);
        rb.consume(in.pos);
        if (hint == 0) break;
        const to_decode = @min(hint, din_size);
        if (rb.end - rb.start < to_decode) {
            if (rb.fill(env.io, to_decode) == 0) {
                disp.at(1, "{s} : Read error (39) : premature end \n", .{src_name});
                return null;
            }
        }
    }
    return frame_size;
}

/// The progress line of `FIO_decompressZstdFrame`: `%.*f%s` of the size.
fn showDecompressProgress(io: Io, ctx: *const Ctx, name20: []const u8, h: disp.Hrs) void {
    if (disp.level < 1 or disp.progress == .never) return;
    disp.delayNextUpdate(io);
    const w = disp.err();
    if (ctx.nb_files_total > 1) {
        w.writeAll("\rDecompress: ") catch {};
        var nb: [24]u8 = undefined;
        disp.right(w, std.fmt.bufPrint(&nb, "{d}", .{ctx.curr_file_idx + 1}) catch unreachable, 2) catch {};
        w.writeAll("/") catch {};
        disp.right(w, std.fmt.bufPrint(&nb, "{d}", .{ctx.nb_files_total}) catch unreachable, 2) catch {};
        w.print(" files. Current: {s} : ", .{name20}) catch {};
        disp.fixed(w, h.value, 0, h.precision) catch {};
        w.print("{s}...    ", .{h.suffix}) catch {};
    } else {
        w.writeAll("\r") catch {};
        // `%-20.20s`
        disp.left(w, name20[0..@min(name20.len, 20)], 20) catch {};
        w.writeAll(" : ") catch {};
        disp.fixed(w, h.value, 0, h.precision) catch {};
        w.print("{s}...     ", .{h.suffix}) catch {};
    }
    disp.flush();
}

/// `FIO_passThrough`.
fn passThrough(env: Env, rb: *ReadBuf, dst: ?*Dst) u1 {
    while (true) {
        _ = rb.fill(env.io, 64 * 1024);
        const l = rb.loaded();
        if (l.len == 0) break;
        const n = @min(l.len, 64 * 1024);
        if (dst) |d| d.write(l[0..n]);
        rb.consume(n);
    }
    return 0;
}

/// `FIO_decompressFrames`: 0 ok, 1 failed.
fn decompressFrames(env: Env, ctx: *Ctx, prefs: *const Prefs, ress: *DRess, src: Src, dst: ?*Dst, dst_name: []const u8, src_name: []const u8) u1 {
    var read_something = false;
    var filesize: u64 = 0;
    const pass = prefs.pass_through orelse (prefs.overwrite and isStdout(dst_name));
    var rb: ReadBuf = .{ .file = src.file, .buf = ress.rb_buf };
    while (true) {
        _ = rb.fill(env.io, 4);
        const buf = rb.loaded();
        if (buf.len == 0) {
            if (!read_something) {
                disp.at(1, "zstd: {s}: unexpected end of file \n", .{src_name});
                return 1;
            }
            break;
        }
        read_something = true;
        if (buf.len < 4) {
            if (pass) return passThrough(env, &rb, dst);
            disp.at(1, "zstd: {s}: unknown header \n", .{src_name});
            return 1;
        }
        if (zstd.isFrame(buf)) {
            const fs = decompressFrame(env, ctx, prefs, ress, &rb, dst, src_name, filesize) orelse return 1;
            filesize += fs;
        } else if (buf[0] == 31 and buf[1] == 139) {
            disp.at(1, "zstd: {s}: gzip file cannot be uncompressed (zstd compiled without HAVE_ZLIB) -- ignored \n", .{src_name});
            return 1;
        } else if ((buf[0] == 0xFD and buf[1] == 0x37) or (buf[0] == 0x5D and buf[1] == 0x00)) {
            disp.at(1, "zstd: {s}: xz/lzma file cannot be uncompressed (zstd compiled without HAVE_LZMA) -- ignored \n", .{src_name});
            return 1;
        } else if (std.mem.readInt(u32, buf[0..4], .little) == 0x184D2204) {
            disp.at(1, "zstd: {s}: lz4 file cannot be uncompressed (zstd compiled without HAVE_LZ4) -- ignored \n", .{src_name});
            return 1;
        } else if (pass) {
            return passThrough(env, &rb, dst);
        } else {
            disp.at(1, "zstd: {s}: unsupported format \n", .{src_name});
            return 1;
        }
    }
    ctx.total_out += filesize;
    disp.clearProgress();
    if (ctx.fileSummary()) {
        if (disp.shouldSummary() and disp.level >= 1) {
            const w = disp.err();
            disp.left(w, src_name, 20) catch {};
            w.print(": {d} bytes \n", .{filesize}) catch {};
            disp.flush();
        }
    }
    return 0;
}

/// `FIO_decompressDstFile`.
fn decompressDstFile(env: Env, ctx: *Ctx, prefs: *const Prefs, ress: *DRess, dst_name: []const u8, src: Src, src_name: []const u8) u1 {
    if (ress.shared != null or prefs.test_mode) {
        return decompressFrames(env, ctx, prefs, ress, src, ress.shared, dst_name, src_name);
    }
    const transfer = !isStdin(src_name) and !isStdout(dst_name) and src.st != null and src.st.?.kind == .file;
    var dst = openDst(env, ctx, prefs, src_name, dst_name, if (transfer) 0o600 else 0o666) orelse return 1;
    var result = decompressFrames(env, ctx, prefs, ress, src, &dst, dst_name, src_name);
    if (!dst.close(env.io, if (transfer) src.st.? else null)) {
        disp.at(1, "zstd: {s}: {s} \n", .{ dst_name, "Input/output error" });
        result = 1;
    }
    if (result != 0 and !isStdout(dst_name)) _ = removeFile(env, dst_name);
    return result;
}

/// `FIO_decompressSrcFile`.
fn decompressSrcFile(env: Env, ctx: *Ctx, prefs: *const Prefs, ress: *DRess, dst_name: []const u8, src_name: []const u8) u1 {
    if (stat(env, src_name)) |st| if (st.kind == .directory) {
        disp.at(1, "zstd: {s} is a directory -- ignored \n", .{src_name});
        return 1;
    };
    const src = openSrc(env, prefs, src_name) orelse return 1;
    const result = decompressDstFile(env, ctx, prefs, ress, dst_name, src, src_name);
    src.close(env.io);
    if (prefs.remove_src and result == 0 and !isStdin(src_name)) {
        if (!removeFile(env, src_name)) {
            disp.at(1, "zstd: {s}: {s} \n", .{ src_name, "Operation not permitted" });
            return 1;
        }
    }
    return result;
}

/// `FIO_decompressFilename`.
pub fn decompressFilename(env: Env, ctx: *Ctx, prefs: *Prefs, dst_name: []const u8, src_name: []const u8, dict_name: ?[]const u8) u1 {
    var ress: DRess = .init(env, prefs, dict_name);
    defer ress.deinit(env);
    return decompressSrcFile(env, ctx, prefs, &ress, dst_name, src_name);
}

const suffix_list = [_][]const u8{ ".zst", ".tzst", ".zstd" };
const suffix_list_str = ".zst/.tzst";

/// `FIO_determineDstName`: null when the suffix is unknown.
fn dstName(gpa: std.mem.Allocator, src_name: []const u8, out_dir: ?[]const u8) ?[]const u8 {
    if (isStdin(src_name)) return stdoutmark;
    const dot = std.mem.lastIndexOfScalar(u8, src_name, '.') orelse {
        disp.at(1, "zstd: {s}: unknown suffix ({s} expected). Can't derive the output file name. Specify it with -o dstFileName. Ignoring.\n", .{ src_name, suffix_list_str });
        return null;
    };
    const suffix = src_name[dot..];
    var matched: ?[]const u8 = null;
    for (suffix_list) |s| if (std.mem.eql(u8, s, suffix)) {
        matched = s;
        break;
    };
    if (src_name.len <= suffix.len or matched == null) {
        disp.at(1, "zstd: {s}: unknown suffix ({s} expected). Can't derive the output file name. Specify it with -o dstFileName. Ignoring.\n", .{ src_name, suffix_list_str });
        return null;
    }
    const tail: []const u8 = if (matched.?[1] == 't') ".tar" else "";
    const parts = fromOutDir(src_name, out_dir);
    // the suffix is the end of the file name, so of `parts[2]` too
    const stem = parts[2][0 .. parts[2].len - suffix.len];
    return std.mem.concat(gpa, u8, &.{ parts[0], parts[1], stem, tail }) catch fatal(74, "Cannot allocate memory : not enough memory for dstFileName", .{});
}

/// `FIO_decompressMultipleFilenames`.
pub fn decompressMultiple(env: Env, ctx: *Ctx, prefs: *Prefs, names: []const []const u8, mirror_root: ?[]const u8, out_dir: ?[]const u8, out_name: ?[]const u8, dict_name: ?[]const u8) u1 {
    var ress: DRess = .init(env, prefs, dict_name);
    defer ress.deinit(env);
    var err: u1 = 0;
    if (out_name) |o| {
        if (multiFilesConcatWarning(env, ctx, prefs, o)) return 1;
        var dst: ?Dst = null;
        if (!prefs.test_mode) {
            dst = openDst(env, ctx, prefs, null, o, 0o666) orelse fatal(19, "cannot open {s}", .{o});
        }
        ress.shared = if (dst) |*d| d else null;
        while (ctx.curr_file_idx < ctx.nb_files_total) : (ctx.curr_file_idx += 1) {
            const status = decompressSrcFile(env, ctx, prefs, &ress, o, names[ctx.curr_file_idx]);
            if (status == 0) ctx.nb_files_processed += 1;
            err |= status;
        }
        if (dst) |*d| if (!d.close(env.io, null)) fatal(72, "Write error : Input/output error : cannot properly close output file", .{});
    } else {
        var arena_state: std.heap.ArenaAllocator = .init(env.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        if (mirror_root) |root| util.mirrorSourceFilesDirectories(env, arena, names[0..ctx.nb_files_total], root);
        while (ctx.curr_file_idx < ctx.nb_files_total) : (ctx.curr_file_idx += 1) {
            const src_name = names[ctx.curr_file_idx];
            var dir = out_dir;
            if (mirror_root) |root| {
                dir = util.mirroredDestDirName(arena, src_name, root) orelse {
                    disp.at(2, "zstd: --output-dir-mirror cannot decompress '{s}' into '{s}'\n", .{ src_name, root });
                    err = 1;
                    continue;
                };
            }
            const dst_name = dstName(env.gpa, src_name, dir) orelse {
                err = 1;
                continue;
            };
            defer if (!isStdout(dst_name)) env.gpa.free(dst_name);
            const status = decompressSrcFile(env, ctx, prefs, &ress, dst_name, src_name);
            if (status == 0) ctx.nb_files_processed += 1;
            err |= status;
        }
        if (out_dir != null) checkFilenameCollisions(env.gpa, names[0..ctx.nb_files_total]);
    }
    if (ctx.multiSummary()) {
        disp.clearProgress();
        if (disp.shouldSummary() and disp.level >= 1) {
            const w = disp.err();
            var nb: [24]u8 = undefined;
            w.print("{d} files decompressed : ", .{ctx.nb_files_processed}) catch {};
            disp.right(w, std.fmt.bufPrint(&nb, "{d}", .{ctx.total_out}) catch unreachable, 6) catch {};
            w.writeAll(" bytes total \n") catch {};
            disp.flush();
        }
    }
    return err;
}
