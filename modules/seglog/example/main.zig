// SPDX-License-Identifier: MIT

//! What a consumer does with `seglog`: open a log, rotate to a segment, append
//! records, read them back from a saved position, resume after a "restart"
//! (close and reopen), drop old segments, and meet one error by name.
//!
//! `SimStorage` (re-exported by `seglog`) is the in-memory `Storage` backend;
//! the real thing is `seglog.FsStorage`. Built by `zig build check-examples`
//! against the PUBLISHED module only.

const std = @import("std");
const seglog = @import("seglog");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var sim = seglog.SimStorage.init(gpa);
    defer sim.deinit();

    var saved: ?seglog.Position = null;
    {
        var log = try seglog.Log.open(gpa, sim.storage(), .{ .create = true });
        defer log.close();

        try log.rotate(1); // segment ids only grow (the caller's choice, e.g. a day number)
        _ = try log.append("sample-1");
        _ = try log.append("sample-2");
        try log.rotate(2);
        const last = try log.append("sample-3");
        std.debug.print("last record: lsn {d}, durableLsn() {d}\n", .{ last.lsn, log.durableLsn() });

        // An id that does not grow is refused, by a name the caller can handle.
        log.rotate(1) catch |err| switch (err) {
            error.NonMonotonic => std.debug.print("rotate(1) refused: ids only grow\n", .{}),
            else => return err,
        };

        var it = log.iterator(null);
        defer it.deinit();
        var n: usize = 0;
        while (try it.next()) |rec| {
            std.debug.print("lsn {d}: {s}\n", .{ rec.lsn, rec.payload });
            n += 1;
            if (n == 2) saved = rec.next; // persist this to resume later
        }
    }

    // "Restart": reopen and resume from the saved position.
    var log = try seglog.Log.open(gpa, sim.storage(), .{});
    defer log.close();
    var it = log.iterator(saved);
    defer it.deinit();
    while (try it.next()) |rec| std.debug.print("resumed: lsn {d}: {s}\n", .{ rec.lsn, rec.payload });

    // Retention drops whole segments below an id, never the newest.
    const dropped = try log.dropBefore(2);
    std.debug.print("dropped {d} segment(s)\n", .{dropped});
}
