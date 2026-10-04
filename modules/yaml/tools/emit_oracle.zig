// SPDX-License-Identifier: MIT
//
// Differential driver for the EMITTER (`emit_oracle.py`): reads `.`-prefixed
// hex YAML records from stdin, one per line (the `ydump` framing), composes
// each with `yaml.composeAll`, writes it back with `yaml.writeAll`, and
// prints the emitted text as one `.`-prefixed hex line (or `ERR:<name>`).
// The Python side loads that text with PyYAML and compares it with the
// yaml-test-suite's `in.json`.
//
//   zig build-exe -O ReleaseSafe --dep yaml -Mmain=modules/yaml/tools/emit_oracle.zig \
//       -Myaml=modules/yaml/src/root.zig -femit-bin=<scratch>/emit_oracle
//   python3 modules/yaml/tools/emit_oracle.py <scratch>/emit_oracle <suite-dir>
const std = @import("std");
const yaml = @import("yaml");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var in_buf: [1 << 16]u8 = undefined;
    var stdin = std.Io.File.stdin().reader(io, &in_buf);
    var out_buf: [1 << 16]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const out = &stdout.interface;
    while (stdin.interface.takeDelimiterExclusive('\n')) |line| {
        stdin.interface.toss(1);
        const hex = if (line.len > 0 and line[0] == '.') line[1..] else line;
        const src = try gpa.alloc(u8, hex.len / 2);
        defer gpa.free(src);
        _ = try std.fmt.hexToBytes(src, hex);
        const all = yaml.composeAll(gpa, src, .{}) catch |e| {
            try out.print("ERR:{s}\n", .{@errorName(e)});
            continue;
        };
        defer all.deinit();
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        yaml.writeAll(gpa, &aw.writer, all.documents) catch |e| {
            try out.print("ERR:{s}\n", .{@errorName(e)});
            continue;
        };
        try out.writeByte('.');
        for (aw.written()) |c| try out.print("{x:0>2}", .{c});
        try out.writeByte('\n');
    } else |e| switch (e) {
        error.EndOfStream => {},
        else => return e,
    }
    try out.flush();
}
