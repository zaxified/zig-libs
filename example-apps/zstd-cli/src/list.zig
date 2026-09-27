// SPDX-License-Identifier: BSD-3-Clause AND MIT
//! `zstd --list`: a port of libzstd 1.5.7's `FIO_listMultipleFiles`
//! (`programs/fileio.c`). Walks the frame and block headers without
//! decoding, as the C command does with `fread`/`fseek` -- here with
//! positional reads, a seek being just a new offset (and, as with `fseek`,
//! allowed past the end of the file, which the end-of-file check catches).

const std = @import("std");
const zstd = @import("zstd");
const disp = @import("display.zig");
const fio = @import("fileio.zig");

const File = std.Io.File;

const FileInfo = struct {
    decompressed_size: u64 = 0,
    compressed_size: u64 = 0,
    window_size: u64 = 0,
    num_actual_frames: i32 = 0,
    num_skippable_frames: i32 = 0,
    decomp_unavailable: bool = false,
    uses_check: bool = false,
    checksum: [4]u8 = .{ 0, 0, 0, 0 },
    nb_files: u32 = 0,
    dict_id: u32 = 0,
};

const InfoError = enum { success, frame_error, not_zstd, file_error, truncated_input };

/// `ERROR_IF`: the message, a line end, and the verdict.
fn fail(e: InfoError, comptime fmt: []const u8, args: anytype) InfoError {
    disp.at(1, fmt, args);
    disp.at(1, " \n", .{});
    return e;
}

/// `fread` at `pos.*`: how many bytes it got, and the position moves on.
fn read(io: std.Io, f: File, buf: []u8, pos: *u64) usize {
    const n = f.readPositionalAll(io, buf, pos.*) catch 0;
    pos.* += n;
    return n;
}

/// `FIO_analyzeFrames`.
fn analyzeFrames(io: std.Io, info: *FileInfo, f: File) InfoError {
    var pos: u64 = 0;
    while (true) {
        var hb: [18]u8 = undefined; // ZSTD_FRAMEHEADERSIZE_MAX
        const n = read(io, f, &hb, &pos);
        const eof = n < hb.len;
        if (n < 6) { // ZSTD_FRAMEHEADERSIZE_MIN(ZSTD_f_zstd1)
            if (eof and n == 0 and info.compressed_size > 0) {
                if (pos != info.compressed_size)
                    return fail(.truncated_input, "Error: seeked to position {d}, which is beyond file size of {d}\n", .{ pos, info.compressed_size });
                break;
            }
            if (eof) return fail(.not_zstd, "Error: reached end of file with incomplete frame", .{});
            return fail(.frame_error, "Error: did not reach end of file but ran out of frames", .{});
        }
        const magic = std.mem.readInt(u32, hb[0..4], .little);
        if (magic == 0xFD2FB528) {
            const head = hb[0..n];
            if (zstd.getFrameContentSize(head)) |cs| {
                if (cs) |s| info.decompressed_size += s else info.decomp_unavailable = true;
            } else |_| info.decomp_unavailable = true;
            const h = switch (zstd.getFrameHeader(head) catch return fail(.frame_error, "Error: could not decode frame header", .{})) {
                .header => |h| h,
                .need => return fail(.frame_error, "Error: could not decode frame header", .{}),
            };
            if (info.dict_id != 0 and info.dict_id != h.dict_id) {
                disp.always("WARNING: File contains multiple frames with different dictionary IDs. Showing dictID 0 instead", .{});
                info.dict_id = 0;
            } else {
                info.dict_id = h.dict_id;
            }
            info.window_size = h.window_size;
            const header_size = zstd.frameHeaderSize(head) catch return fail(.frame_error, "Error: could not determine frame header size", .{});
            pos = pos - n + header_size;
            while (true) {
                var bh: [3]u8 = undefined;
                if (read(io, f, &bh, &pos) != 3) return fail(.frame_error, "Error while reading block header", .{});
                const block_header = std.mem.readInt(u24, &bh, .little);
                const block_type = (block_header >> 1) & 3;
                if (block_type == 3) return fail(.frame_error, "Error: unsupported block type", .{});
                pos += if (block_type == 1) 1 else block_header >> 3;
                if (block_header & 1 == 1) break;
            }
            if (hb[4] & (1 << 2) != 0) {
                info.uses_check = true;
                if (read(io, f, &info.checksum, &pos) != 4) return fail(.frame_error, "Error: could not read checksum", .{});
            }
            info.num_actual_frames += 1;
        } else if (magic & 0xFFFFFFF0 == 0x184D2A50) {
            const frame_size = std.mem.readInt(u32, hb[4..8], .little);
            pos = pos - n + 8 + frame_size;
            info.num_skippable_frames += 1;
        } else {
            return .not_zstd;
        }
    }
    return .success;
}

/// `getFileInfo`.
fn getFileInfo(env: fio.Env, info: *FileInfo, name: []const u8) InfoError {
    const st = fio.stat(env, name);
    if (st == null or st.?.kind != .file) return fail(.file_error, "Error : {s} is not a file", .{name});
    const f = std.Io.Dir.cwd().openFile(env.io, name, .{}) catch |e| {
        disp.at(1, "zstd: {s}: {s} \n", .{ name, fio.strerror(e) });
        return fail(.file_error, "Error: could not open source file {s}", .{name});
    };
    defer f.close(env.io);
    info.compressed_size = st.?.size;
    const status = analyzeFrames(env.io, info, f);
    info.nb_files = 1;
    return status;
}

fn row(w: *std.Io.Writer, frames: i32, skips: i32, compressed: u64, decompressed: ?u64, ratio: f64, check: []const u8, name: []const u8, files: ?u32) void {
    var b: [24]u8 = undefined;
    disp.right(w, std.fmt.bufPrint(&b, "{d}", .{frames}) catch unreachable, 6) catch {};
    w.writeAll("  ") catch {};
    disp.right(w, std.fmt.bufPrint(&b, "{d}", .{skips}) catch unreachable, 5) catch {};
    w.writeAll("  ") catch {};
    const hc = disp.hrs(compressed);
    disp.fixed(w, hc.value, 6, hc.precision) catch {};
    disp.right(w, hc.suffix, 4) catch {};
    if (decompressed) |d| {
        w.writeAll("  ") catch {};
        const hd = disp.hrs(d);
        disp.fixed(w, hd.value, 8, hd.precision) catch {};
        disp.right(w, hd.suffix, 4) catch {};
        w.writeAll("  ") catch {};
        disp.fixed(w, ratio, 5, 3) catch {};
        w.writeAll("  ") catch {};
    } else {
        w.writeAll("                       ") catch {};
    }
    disp.right(w, check, 5) catch {};
    w.writeAll("  ") catch {};
    if (files) |n| w.print("{d} files\n", .{n}) catch {} else w.print("{s}\n", .{name}) catch {};
}

/// `displayInfo`.
fn displayInfo(name: []const u8, info: *const FileInfo, level: i32) void {
    const w = disp.out();
    const ratio: f64 = if (info.compressed_size == 0) 0 else @as(f64, @floatFromInt(info.decompressed_size)) / @as(f64, @floatFromInt(info.compressed_size));
    const check: []const u8 = if (info.uses_check) "XXH64" else "None";
    if (level <= 2) {
        row(w, info.num_skippable_frames + info.num_actual_frames, info.num_skippable_frames, info.compressed_size, if (info.decomp_unavailable) null else info.decompressed_size, ratio, check, name, null);
        return;
    }
    w.print("{s} \n", .{name}) catch {};
    w.print("# Zstandard Frames: {d}\n", .{info.num_actual_frames}) catch {};
    if (info.num_skippable_frames != 0) w.print("# Skippable Frames: {d}\n", .{info.num_skippable_frames}) catch {};
    w.print("DictID: {d}\n", .{info.dict_id}) catch {};
    w.print("Window Size: {f} ({d} B)\n", .{ disp.hrs(info.window_size), info.window_size }) catch {};
    w.print("Compressed Size: {f} ({d} B)\n", .{ disp.hrs(info.compressed_size), info.compressed_size }) catch {};
    if (!info.decomp_unavailable) {
        w.print("Decompressed Size: {f} ({d} B)\n", .{ disp.hrs(info.decompressed_size), info.decompressed_size }) catch {};
        w.writeAll("Ratio: ") catch {};
        disp.fixed(w, ratio, 0, 4) catch {};
        w.writeAll("\n") catch {};
    }
    if (info.uses_check and info.num_actual_frames == 1) {
        w.print("Check: {s} {x:0>2}{x:0>2}{x:0>2}{x:0>2}\n", .{ check, info.checksum[3], info.checksum[2], info.checksum[1], info.checksum[0] }) catch {};
    } else {
        w.print("Check: {s}\n", .{check}) catch {};
    }
    w.writeAll("\n") catch {};
}

/// `FIO_listFile`: 0 ok, 1 failed.
fn listFile(env: fio.Env, total: *FileInfo, name: []const u8, level: i32) u1 {
    var info: FileInfo = .{};
    const e = getFileInfo(env, &info, name);
    const w = disp.out();
    switch (e) {
        .frame_error => disp.at(1, "Error while parsing \"{s}\" \n", .{name}),
        .not_zstd => {
            w.print("File \"{s}\" not compressed by zstd \n", .{name}) catch {};
            if (level > 2) w.writeAll("\n") catch {};
            return 1;
        },
        .file_error => {
            if (level > 2) w.writeAll("\n") catch {};
            return 1;
        },
        .truncated_input => {
            w.print("File \"{s}\" is truncated \n", .{name}) catch {};
            if (level > 2) w.writeAll("\n") catch {};
            return 1;
        },
        .success => {},
    }
    displayInfo(name, &info, level);
    total.num_actual_frames += info.num_actual_frames;
    total.num_skippable_frames += info.num_skippable_frames;
    total.compressed_size += info.compressed_size;
    total.decompressed_size += info.decompressed_size;
    total.decomp_unavailable = total.decomp_unavailable or info.decomp_unavailable;
    total.uses_check = total.uses_check and info.uses_check;
    total.nb_files += info.nb_files;
    return @intFromBool(e != .success);
}

/// `FIO_listMultipleFiles`.
pub fn listMultiple(env: fio.Env, names: []const []const u8, level: i32, stdin_is_console: bool) u8 {
    for (names) |n| if (std.mem.eql(u8, n, fio.stdinmark)) {
        _ = fail(.file_error, "zstd: --list does not support reading from standard input", .{});
        return 1;
    };
    if (names.len == 0) {
        if (!stdin_is_console) disp.at(1, "zstd: --list does not support reading from standard input \n", .{});
        disp.at(1, "No files given \n", .{});
        return 1;
    }
    const w = disp.out();
    if (level <= 2) w.writeAll("Frames  Skips  Compressed  Uncompressed  Ratio  Check  Filename\n") catch {};
    var err: u1 = 0;
    var total: FileInfo = .{ .uses_check = true };
    for (names) |n| err |= listFile(env, &total, n, level);
    if (names.len > 1 and level <= 2) {
        const ratio: f64 = if (total.compressed_size == 0) 0 else @as(f64, @floatFromInt(total.decompressed_size)) / @as(f64, @floatFromInt(total.compressed_size));
        w.writeAll("----------------------------------------------------------------- \n") catch {};
        row(w, total.num_skippable_frames + total.num_actual_frames, total.num_skippable_frames, total.compressed_size, if (total.decomp_unavailable) null else total.decompressed_size, ratio, if (total.uses_check) "XXH64" else "", "", total.nb_files);
    }
    disp.flush();
    return err;
}
