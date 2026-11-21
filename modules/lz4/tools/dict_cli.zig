// SPDX-License-Identifier: MIT

//! Driver for `dict_oracle.py`: our dictionary codec on files. Modes: `fc` frame compress (linked,
//! id 77, content checksum), `fci` frame compress (independent blocks, block checksums), `fd` frame
//! decompress, `bc` block compress, `bd` block decompress (a fifth argument: the decoded size), `hb` / `hf` HC block / frame at the level
//! given as the fifth argument (`dict_oracle.py` runs them against liblz4 and compares sizes).
//! `dict_cli <mode> <dictfile> <infile> <outfile> [size]`.

const std = @import("std");
const lz4 = @import("lz4");
pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args = init.minimal.args.iterate();
    _ = args.next();
    const mode = args.next().?;
    const dict_p = args.next().?;
    const in_p = args.next().?;
    const out_p = args.next().?;
    const cwd = std.Io.Dir.cwd();
    const dict = try cwd.readFileAlloc(io, dict_p, gpa, .unlimited);
    const in = try cwd.readFileAlloc(io, in_p, gpa, .unlimited);
    var res: []u8 = undefined;
    if (std.mem.eql(u8, mode, "fc")) {
        res = try lz4.compressDict(gpa, in, dict, 77, .{ .content_checksum = true });
    } else if (std.mem.eql(u8, mode, "fci")) {
        res = try lz4.compressDict(gpa, in, dict, 77, .{ .independent_blocks = true, .block_checksum = true });
    } else if (std.mem.eql(u8, mode, "fd")) {
        res = try lz4.decompressDict(gpa, in, dict, .{});
    } else if (std.mem.eql(u8, mode, "bc")) {
        const buf = try gpa.alloc(u8, lz4.compressBlockBound(in.len));
        const n = try lz4.compressBlockDict(gpa, in, dict, buf, .{});
        res = buf[0..n];
    } else if (std.mem.eql(u8, mode, "bd")) {
        const size = try std.fmt.parseInt(usize, args.next().?, 10);
        const buf = try gpa.alloc(u8, size);
        const n = try lz4.decompressBlockDict(gpa, in, dict, buf);
        res = buf[0..n];
    } else if (std.mem.eql(u8, mode, "hb")) {
        // HC block, level = 5th argument; the dictionary file is not used.
        const level = try std.fmt.parseInt(u8, args.next().?, 10);
        const buf = try gpa.alloc(u8, lz4.compressBlockBound(in.len));
        const n = try lz4.compressBlock(in, buf, .{ .hc_level = level });
        res = buf[0..n];
    } else if (std.mem.eql(u8, mode, "hf")) {
        // HC frame (linked, content checksum), level = 5th argument.
        const level = try std.fmt.parseInt(u8, args.next().?, 10);
        res = try lz4.compress(gpa, in, .{ .hc_level = level, .content_checksum = true });
    } else unreachable;
    try cwd.writeFile(io, .{ .sub_path = out_p, .data = res });
}
