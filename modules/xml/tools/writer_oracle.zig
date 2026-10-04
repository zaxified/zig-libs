// SPDX-License-Identifier: MIT
//
// Differential oracle for the WRITER: for every file named on the command
// line, parse it (internal entities on, falling back to `.ignore`), write it
// with `writeDocument`, and save the output as <out-dir>/<n>.xml. Then
// `writer_oracle.py` hands each original and each output to libxml2 (lxml)
// and compares their canonical forms. Not part of `zig build`.
//
//   zig build-exe -O ReleaseSafe --dep xml -Mmain=modules/xml/tools/writer_oracle.zig \
//       -Mxml=modules/xml/src/root.zig -femit-bin=<scratch>/writer_oracle
//   python3 modules/xml/tools/writer_oracle.py <scratch>/writer_oracle <scratch>/out
const std = @import("std");
const xml = @import("xml");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3) return error.Usage;
    const out_dir = args[1];
    const cwd = std.Io.Dir.cwd();
    for (args[2..], 0..) |path, n| {
        const src = cwd.readFileAlloc(io, path, gpa, .limited(1 << 24)) catch continue;
        defer gpa.free(src);
        var doc = xml.parse(gpa, src, .{ .doctype = .internal_entities }) catch
            xml.parse(gpa, src, .{ .doctype = .ignore }) catch continue;
        defer doc.deinit();
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        try xml.writeDocument(gpa, &aw.writer, &doc);
        var name_buf: [4096]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "{s}/{d}.xml", .{ out_dir, n });
        try cwd.writeFile(io, .{ .sub_path = name, .data = aw.written() });
    }
}
