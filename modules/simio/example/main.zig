// SPDX-License-Identifier: MIT

//! What a `std.Io` author does with `simio`: take a small piece of ordinary
//! concurrent code — a ticket counter that hands out seats to several buyer
//! tasks — and run it under many seeds. The buggy version checks availability
//! and then sells after an `Io` call (a clock read, standing in for a database
//! round trip), so some interleavings oversell. The search finds such a seed,
//! the same seed reproduces it with the same schedule fingerprint, and the
//! version that holds an `Io.Mutex` across the check and the sale survives
//! every seed.
//!
//! Built by `zig build check-examples` against the PUBLISHED module only.

const std = @import("std");
const simio = @import("simio");

const Io = std.Io;

const seats_total = 10;

const Box = struct {
    sold: u32 = 0,
    mutex: Io.Mutex = .init,
};

fn buyer(io: Io, box: *Box, wanted: u32, locked: bool) !void {
    for (0..wanted) |_| {
        if (locked) try box.mutex.lock(io);
        defer if (locked) box.mutex.unlock(io);
        if (box.sold >= seats_total) return error.SoldOut;
        _ = Io.Timestamp.now(io, .real); // the round trip between check and act
        box.sold += 1;
    }
}

const Run = struct { sold: u32, fingerprint: u64, sold_out: usize };

fn sell(gpa: std.mem.Allocator, seed: u64, locked: bool) !Run {
    var sim: simio.Sim = undefined;
    sim.init(gpa, .{ .seed = seed, .preempt_permille = 300 });
    defer sim.deinit();
    const host = try sim.addHost(.{});
    var box: Box = .{};
    for (0..4) |_| try host.spawn(buyer, .{ host.io(), &box, 4, locked });
    const r = sim.run();
    if (r.outcome != .quiescent) return error.Stuck;
    // Buyers that found the box empty report it by name; anything else is a bug.
    if (host.failure) |err| if (err != error.SoldOut) return err;
    return .{ .sold = box.sold, .fingerprint = sim.fingerprint(), .sold_out = host.failures };
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    const bad_seed = for (0..500) |seed| {
        const run = try sell(gpa, seed, false);
        if (run.sold > seats_total) break seed;
    } else return error.NoOversellFound;

    const first = try sell(gpa, bad_seed, false);
    const again = try sell(gpa, bad_seed, false);
    if (again.sold != first.sold or again.fingerprint != first.fingerprint) return error.NotReproducible;
    std.debug.print("seed {d}: {d} seats sold of {d}, replayed with fingerprint {x}\n", .{
        bad_seed, first.sold, seats_total, first.fingerprint,
    });

    for (0..500) |seed| {
        const run = try sell(gpa, seed, true);
        if (run.sold != seats_total) return error.MutexVersionWrong;
    }
    std.debug.print("with the mutex: exactly {d} sold on all 500 seeds\n", .{seats_total});
}
