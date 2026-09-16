// SPDX-License-Identifier: MIT
//
// The module side of the structural differential: prints the same canonical,
// quoting-neutral dump `oracle_dump.c` prints from real libuci, so the two can
// be diffed byte for byte.
//
//
// Build (out of the tracked tree, own cache dir):
//   zig build-exe module_dump.zig -O ReleaseFast \
//       --dep uci -Mmain=module_dump.zig -Muci=<zig-libs>/modules/uci/src/root.zig \
//       --cache-dir <scratch>/zc
// Run:
//   ./module_dump < <file>

const std = @import("std");
const uci = @import("uci");

fn writeOut(bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = std.os.linux.write(1, bytes.ptr + off, bytes.len - off);
        const signed: isize = @bitCast(rc);
        if (signed < 0) {
            if (signed == -4) continue; // EINTR
            return error.WriteFailed;
        }
        if (signed == 0) return error.WriteFailed;
        off += @intCast(signed);
    }
}

fn hex(w: *std.Io.Writer, s: ?[]const u8) !void {
    const v = s orelse return w.writeAll("-");
    if (v.len == 0) return w.writeAll(".");
    for (v) |c| try w.print("{x:0>2}", .{c});
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // Config text arrives on stdin (raw read(2) loop — no Io instance
    // needed, and no argv API churn across Zig versions).
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(gpa);
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n = std.posix.read(0, &chunk) catch |e| return e;
        if (n == 0) break;
        try input.appendSlice(gpa, chunk[0..n]);
    }
    const bytes = input.items;

    const out_buf = try gpa.alloc(u8, 64 << 20);
    defer gpa.free(out_buf);
    var fw = std.Io.Writer.fixed(out_buf);
    const w = &fw;

    var diag: uci.Diagnostics = .{};
    var pkg = uci.parseDiag(gpa, bytes, &diag) catch |err| {
        try w.print("ERR 5 {t} line {d}\n", .{ err, diag.line });
        try writeOut(w.buffered());
        return;
    };
    defer pkg.deinit(gpa);

    for (pkg.sections) |*s| {
        try w.writeAll("S ");
        try hex(w, s.type);
        try w.writeAll(" ");
        try hex(w, s.name);
        try w.print(" {c}\n", .{@as(u8, if (s.anonymous) 'A' else 'N')});
        for (s.options) |*o| {
            try w.print("O {c} ", .{@as(u8, switch (o.kind) {
                .single => 's',
                .list => 'l',
            })});
            try hex(w, o.key);
            for (o.values) |v| {
                try w.writeAll(" ");
                try hex(w, v);
            }
            try w.writeAll("\n");
        }
    }
    try writeOut(w.buffered());
}
