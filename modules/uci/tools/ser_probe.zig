// SPDX-License-Identifier: MIT
//
// `uci`: WRITE-path probe. Parse config text from stdin, serialize it back with
// the module, and emit the serialized bytes on stdout — so the result can be
// handed to the REAL libuci and checked for loadability.
//
// ⚠ This is the seam the suite does not have. `real uci capture: our
// serialize() reproduces real `uci export`'s canonical bytes exactly` compares
// against one frozen capture and then re-parses our own output with OUR OWN
// parser, so a shared misunderstanding between this module's reader and writer
// stays invisible: both halves agreeing is not evidence. Feeding these bytes to
// the foreign binary is what makes the writer's output judged by something that
// did not produce it.
//
// Build:
//   zig build-exe -O ReleaseFast --dep uci -Mmain=ser_probe.zig \
//       -Muci=../src/root.zig --cache-dir <scratch>/zc-ser
// Use (with the reference binary built by the recipe in `README.md`):
//   ./ser_probe < some.conf > out.conf && uci_cli -c <dir> export <name>

const std = @import("std");
const uci = @import("uci");

fn writeOut(bytes: []const u8) void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = std.os.linux.write(1, bytes.ptr + off, bytes.len - off);
        const s: isize = @bitCast(rc);
        if (s <= 0) return;
        off += @intCast(s);
    }
}

pub fn main() !void {
    var dbg: std.heap.DebugAllocator(.{}) = .init;
    const gpa = dbg.allocator();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(gpa);
    var chunk: [65536]u8 = undefined;
    while (true) {
        const n = try std.posix.read(0, &chunk);
        if (n == 0) break;
        try input.appendSlice(gpa, chunk[0..n]);
    }
    var pkg = uci.parse(gpa, input.items) catch |e| {
        writeOut("PARSE-FAILED ");
        writeOut(@errorName(e));
        writeOut("\n");
        return;
    };
    defer pkg.deinit(gpa);
    const text = uci.serialize(gpa, &pkg) catch |e| {
        writeOut("SERIALIZE-FAILED ");
        writeOut(@errorName(e));
        writeOut("\n");
        return;
    };
    defer gpa.free(text);
    writeOut(text);
}
