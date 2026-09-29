// SPDX-License-Identifier: BSD-3-Clause AND MIT
//! File-name tables of libzstd 1.5.7's `programs/util.c`: `-r` (directories
//! expanded in `readdir` order), `--filelist` (one name per line) and the
//! directories `--output-dir-mirror` recreates. The messages are the C
//! command's text.

const std = @import("std");
const Io = std.Io;
const disp = @import("display.zig");
const fio = @import("fileio.zig");

const Env = fio.Env;
const Names = std.ArrayList([]const u8);

/// `MAX_FILE_OF_FILE_NAMES_SIZE`.
const max_file_of_names_size = 50 << 20;

/// `UTIL_isDirectory`: follows links.
fn isDirectory(env: Env, name: []const u8) bool {
    const st = fio.stat(env, name) orelse return false;
    return st.kind == .directory;
}

/// `UTIL_isLink`.
fn isLink(env: Env, name: []const u8) bool {
    return fio.lstatKind(env, name) == .sym_link;
}

/// `UTIL_prepareFileList` (POSIX): every non-directory under `dir_name`,
/// depth first, in `readdir` order; symbolic links skipped unless
/// `follow_links`.
fn prepareFileList(env: Env, arena: std.mem.Allocator, dir_name: []const u8, out: *Names, follow_links: bool) void {
    var dir = Io.Dir.cwd().openDir(env.io, dir_name, .{ .iterate = true }) catch |e| {
        disp.at(1, "Cannot open directory '{s}': {s}\n", .{ dir_name, fio.strerror(e) });
        return;
    };
    defer dir.close(env.io);
    var it = dir.iterate();
    while (true) {
        const entry = it.next(env.io) catch |e| {
            // C drops the whole list here (`free(*bufStart)`), which ends
            // the command with an allocation error
            disp.at(1, "readdir({s}) error: {s} \n", .{ dir_name, fio.strerror(e) });
            fio.fatal(1, "zstd: allocation error", .{});
        } orelse break;
        const path = std.mem.concat(arena, u8, &.{ dir_name, "/", entry.name }) catch oom();
        if (!follow_links and isLink(env, path)) {
            disp.at(2, "Warning : {s} is a symbolic link, ignoring\n", .{path});
            continue;
        }
        if (isDirectory(env, path)) {
            prepareFileList(env, arena, path, out, follow_links);
        } else {
            out.append(arena, path) catch oom();
        }
    }
}

fn oom() noreturn {
    fio.fatal(1, "zstd: allocation error", .{});
}

/// `UTIL_expandFNT` / `UTIL_createExpandedFNT`: directories replaced by the
/// files under them, every other name kept as it is.
pub fn expand(env: Env, arena: std.mem.Allocator, names: []const []const u8, follow_links: bool) []const []const u8 {
    var out: Names = .empty;
    for (names) |n| {
        if (isDirectory(env, n)) {
            prepareFileList(env, arena, n, &out, follow_links);
        } else {
            out.append(arena, n) catch oom();
        }
    }
    return out.items;
}

/// `UTIL_createFileNamesTable_fromFileName`: the lines of a regular file of
/// at most 50 MiB, each without its `\n`; null when it cannot be read or
/// has no line.
pub fn readFileList(env: Env, arena: std.mem.Allocator, name: []const u8) ?[]const []const u8 {
    const st = fio.stat(env, name) orelse return null;
    if (st.kind != .file or st.size > max_file_of_names_size) return null;
    const bytes = Io.Dir.cwd().readFileAlloc(env.io, name, arena, .limited(max_file_of_names_size + 1)) catch |e| {
        // `perror("zstd:util:readLinesFromFile")`
        disp.at(1, "zstd:util:readLinesFromFile: {s}\n", .{fio.strerror(e)});
        return null;
    };
    // `fgets` into a buffer of the file's size + 1: every line whole; a
    // line ends at `\n` or at the end of the file, and an empty last
    // piece (the file ends with `\n`) is no line
    var lines: Names = .empty;
    var rest = bytes;
    while (rest.len > 0) {
        const nl = std.mem.indexOfScalar(u8, rest, '\n');
        const end = nl orelse rest.len;
        // `strlen`: a line holding a NUL ends there
        const line = rest[0..end];
        const cut = std.mem.indexOfScalar(u8, line, 0) orelse line.len;
        lines.append(arena, line[0..cut]) catch oom();
        rest = if (nl) |i| rest[i + 1 ..] else rest[rest.len..];
    }
    if (lines.items.len == 0) return null;
    return lines.items;
}

// ------------------------------------------------------ mirrored output

/// `pathnameHas2Dots`: a whole `..` path component.
fn hasDotDot(path: []const u8) bool {
    var i: usize = 0;
    while (std.mem.indexOfPos(u8, path, i, "..")) |p| : (i = p + 1) {
        if ((p == 0 or path[p - 1] == '/') and (p + 2 == path.len or path[p + 2] == '/')) return true;
    }
    return false;
}

/// `trimPath`: a leading `./`, then a leading `/`.
fn trimPath(path: []const u8) []const u8 {
    const p = if (std.mem.startsWith(u8, path, "./")) path[2..] else path;
    return if (p.len > 0 and p[0] == '/') p[1..] else p;
}

/// `mallocAndJoin2Dir`.
fn join2Dir(arena: std.mem.Allocator, dir1: []const u8, dir2: []const u8) []const u8 {
    const sep: []const u8 = if (dir1.len > 0 and dir1[dir1.len - 1] != '/') "/" else "";
    return std.mem.concat(arena, u8, &.{ dir1, sep, dir2 }) catch oom();
}

/// `convertPathnameToDirName`: the part before the last `/`, or `.`. Its
/// loop meant to drop trailing slashes starts at the terminating NUL and
/// never runs, so `a/b/` gives `a/b`, as here.
fn dirName(path: []const u8) []const u8 {
    if (path.len == 0) return path;
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return ".";
    return path[0..slash];
}

/// `UTIL_createMirroredDestDirName`: null when `src` has a `..` component.
pub fn mirroredDestDirName(arena: std.mem.Allocator, src: []const u8, out_root: []const u8) ?[]const u8 {
    if (hasDotDot(src)) return null;
    return dirName(join2Dir(arena, out_root, trimPath(src)));
}

/// `makeDir`: false on an error other than "exists", reported.
fn makeDir(env: Env, dir: []const u8, mode: std.posix.mode_t) bool {
    Io.Dir.cwd().createDir(env.io, dir, .fromMode(mode)) catch |e| switch (e) {
        error.PathAlreadyExists => return true,
        else => {
            disp.always("zstd: failed to create DIR {s}: {s}\n", .{ dir, fio.strerror(e) });
            return false;
        },
    };
    return true;
}

/// `DIR_DEFAULT_MODE`.
const dir_default_mode = 0o755;

/// `getDirMode`.
fn dirMode(env: Env, name: []const u8) std.posix.mode_t {
    const st = Io.Dir.cwd().statFile(env.io, name, .{}) catch |e| {
        disp.always("zstd: failed to get DIR stats {s}: {s}\n", .{ name, fio.strerror(e) });
        return dir_default_mode;
    };
    if (st.kind != .directory) {
        disp.always("zstd: expected directory: {s}\n", .{name});
        return dir_default_mode;
    }
    return st.permissions.toMode();
}

/// `mirrorSrcDir`.
fn mirrorSrcDir(env: Env, arena: std.mem.Allocator, src_dir: []const u8, out_dir: []const u8) bool {
    return makeDir(env, join2Dir(arena, out_dir, trimPath(src_dir)), dirMode(env, src_dir));
}

/// `mirrorSrcDirRecursive`: each ancestor of `src_dir`, then `src_dir`.
fn mirrorSrcDirRecursive(env: Env, arena: std.mem.Allocator, src_dir: []const u8, out_dir: []const u8) void {
    // `trimLeadingCurrentDir`: the walk starts after a leading `./`, the
    // names cut from `src_dir` keep it
    var i: usize = if (std.mem.startsWith(u8, src_dir, "./")) 2 else 0;
    while (std.mem.indexOfScalarPos(u8, src_dir, i, '/')) |sp| : (i = sp + 1) {
        if (sp != i and !mirrorSrcDir(env, arena, src_dir[0..sp], out_dir)) return;
    }
    _ = mirrorSrcDir(env, arena, src_dir, out_dir);
}

/// `firstIsParentOrSameDirOfSecond`.
fn isParentOrSame(first: []const u8, second: []const u8) bool {
    return first.len <= second.len and
        (first.len == second.len or second[first.len] == '/') and
        std.mem.eql(u8, first, second[0..first.len]);
}

/// `UTIL_mirrorSourceFilesDirectories`: `out_dir`, and under it each source
/// file's directory with its mode (sources with a `..` component skipped).
pub fn mirrorSourceFilesDirectories(env: Env, arena: std.mem.Allocator, names: []const []const u8, out_dir: []const u8) void {
    var dirs: Names = .empty;
    for (names) |n| if (!hasDotDot(n)) dirs.append(arena, dirName(n)) catch oom();
    if (dirs.items.len == 0) return;
    _ = makeDir(env, out_dir, dir_default_mode);
    // `makeUniqueMirroredDestDirs`: sorted by trimmed name, only the
    // deepest of a chain of parents
    std.mem.sort([]const u8, dirs.items, {}, struct {
        fn lt(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, trimPath(a), trimPath(b)) == .lt;
        }
    }.lt);
    var unique: Names = .empty;
    unique.append(arena, dirs.items[0]) catch oom();
    for (dirs.items[1..], 0..) |curr, k| {
        if (isParentOrSame(trimPath(dirs.items[k]), trimPath(curr))) {
            unique.items[unique.items.len - 1] = curr;
        } else {
            unique.append(arena, curr) catch oom();
        }
    }
    for (unique.items) |d| mirrorSrcDirRecursive(env, arena, d, out_dir);
}

test "a whole .. component, and the names the mirror joins" {
    try std.testing.expect(hasDotDot(".."));
    try std.testing.expect(hasDotDot("a/../b"));
    try std.testing.expect(hasDotDot("a/.."));
    try std.testing.expect(!hasDotDot("a..b/c"));
    try std.testing.expect(!hasDotDot("..."));
    try std.testing.expectEqualStrings(".", dirName("file"));
    try std.testing.expectEqualStrings("a/b", dirName("a/b/"));
    try std.testing.expectEqualStrings("x/a", dirName("x/a/f"));
    try std.testing.expectEqualStrings("a", trimPath("./a"));
    try std.testing.expectEqualStrings("a", trimPath("/a"));
    // Both steps apply, as in libzstd: `./` goes, then the `/` it left in front.
    try std.testing.expectEqualStrings("a", trimPath(".//a"));
}
