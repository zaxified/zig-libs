// SPDX-License-Identifier: MIT

//! What a consumer does with `kv`: open a store, write a few records, read
//! one back into a caller-owned buffer, delete a stale one, and confirm a
//! second opener is correctly refused (the store's whole reason to hold a
//! lock at all).
//!
//! `SimStorage` is the module's own in-memory `Storage` backend — the same
//! seam `writebehind`'s example uses for its WAL — so this exercises the real
//! `Db` state machine without touching a real file.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling.

const std = @import("std");
const kv = @import("kv");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var sim = kv.SimStorage.init(gpa);
    defer sim.deinit();

    var db = try kv.Db.open(gpa, sim.storage(), "sessions.kv", .{});
    defer db.close();

    try db.put("session:alice", "role=admin");
    try db.put("session:bob", "role=viewer");
    try db.put("session:carol", "role=viewer");
    try db.delete("session:carol"); // Carol logged out.

    // Caller-owned copy: the module hands back memory the caller must free.
    const role = (try db.get(gpa, "session:alice")) orelse return error.MissingKey;
    defer gpa.free(role);
    std.debug.print("alice: {s}\n", .{role});

    std.debug.print("carol present: {}\n", .{db.exists("session:carol")});
    std.debug.print("live records: {d}\n", .{db.count()});

    // A fixed-size buffer read avoids the allocation entirely, but reports a
    // nameable error when the caller under-sized it — deliberately too small
    // here, to show the error is a real one and not a truncated result.
    var small_buf: [4]u8 = undefined;
    _ = db.getBuf(&small_buf, "session:bob") catch |err| switch (err) {
        error.BufferTooSmall => std.debug.print("bob's value doesn't fit in a 4-byte buffer\n", .{}),
        else => return err,
    };

    // A big-enough buffer succeeds without allocating.
    var buf: [64]u8 = undefined;
    const bob = (try db.getBuf(&buf, "session:bob")) orelse return error.MissingKey;
    std.debug.print("bob: {s}\n", .{bob});

    // A second opener on the same (simulated) backend is refused the lock —
    // the module's whole point, and an error that has to be nameable from
    // outside to be handled at all.
    _ = kv.Db.open(gpa, sim.storage(), "sessions.kv", .{}) catch |err| switch (err) {
        error.Locked => std.debug.print("second opener correctly refused: locked\n", .{}),
        else => return err,
    };
}
