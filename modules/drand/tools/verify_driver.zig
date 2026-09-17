// SPDX-License-Identifier: MIT
//
// This module's half of the drand differential oracle (CONVENTIONS.md §9):
// parses a drand `/info` document and a JSON array of `/public/<round>`
// documents (the shape `fetch.py` writes) through THIS module's own public
// API (`parseInfo`, `parseRound`, `verifyRound`) and reports round-by-round
// verdicts, so they can be held against `go/oracle`'s verdicts on the exact
// same live-fetched bytes -- an independent BLS12-381 library (drand's own
// Go `crypto`/`kyber`) answering the same question this module answers.
//
// ⚠ Deliberately NOT named `interop.zig`: that filename is auto-wired by
// this repo's `build.zig` into `zig build interop-<m>` / `check-interop`
// (CONVENTIONS.md §9), which is a different contract (a program `build.zig`
// itself compiles and can run). This program is `tools/`-only, run by hand,
// like every other instrument in this directory.
//
// Talks to `drand` ONLY through `@import("drand")`'s exports; no module
// source is copied here.
//
// WHAT IT NEEDS: the live module, nothing foreign. The `/info` and rounds
// JSON come from `fetch.py` (this directory) -- run fresh into a scratch
// directory, never committed (`live/` fetched beacon data is not adopted,
// per the audit disposition).
//
// Build (against the LIVE module):
//   zig build-exe -O ReleaseFast --dep drand --dep bls12_381 --dep tlock --dep entropy \
//       -Mmain=verify_driver.zig -Mdrand=../src/root.zig \
//       -Mbls12_381=<repo>/modules/bls12_381/src/root.zig \
//       -Mtlock=<repo>/modules/tlock/src/root.zig \
//       -Mentropy=<repo>/modules/entropy/src/root.zig \
//       --cache-dir <scratch>/zc -femit-bin=<scratch>/verify_driver
// Run:
//   ./verify_driver <info.json> <rounds.json>
//
// Measured 2026-09-17: 60/60 quicknet + 5/5 quicknet-t live rounds verified,
// agreeing exactly with `go/oracle`'s verdict on the same fetched documents
// (see ../README.md).

const std = @import("std");
const drand = @import("drand");

fn roundBytes(gpa: std.mem.Allocator, v: std.json.Value) ![]u8 {
    return std.json.Stringify.valueAlloc(gpa, v, .{});
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var gpa_inst: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_inst.deinit();
    const gpa = gpa_inst.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var it = init.args.iterate();
    _ = it.next();
    const info_path = it.next() orelse {
        std.debug.print("usage: verify_driver <info.json> <rounds.json>\n", .{});
        return 2;
    };
    const rounds_path = it.next() orelse {
        std.debug.print("usage: verify_driver <info.json> <rounds.json>\n", .{});
        return 2;
    };

    const info_bytes = try std.Io.Dir.cwd().readFileAlloc(io, info_path, gpa, .limited(1 << 20));
    defer gpa.free(info_bytes);
    const info = drand.parseInfo(gpa, info_bytes) catch |err| {
        std.debug.print("zig: FATAL parseInfo: {t}\n", .{err});
        return 3;
    };

    const rounds_bytes = try std.Io.Dir.cwd().readFileAlloc(io, rounds_path, gpa, .limited(16 << 20));
    defer gpa.free(rounds_bytes);

    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, rounds_bytes, .{});
    defer parsed.deinit();
    const arr = parsed.value.array.items;

    var ok: usize = 0;
    var bad: usize = 0;
    for (arr) |item| {
        const doc = try roundBytes(gpa, item);
        defer gpa.free(doc);
        const round = drand.parseRound(gpa, doc) catch |err| {
            bad += 1;
            std.debug.print("ZIG parse-reject round doc {s} ({t})\n", .{ doc, err });
            continue;
        };
        if (drand.verifyRound(&info, &round)) |_| {
            ok += 1;
        } else |err| {
            bad += 1;
            std.debug.print("ZIG reject round {d} ({t})\n", .{ round.round, err });
        }
    }
    std.debug.print("ZIG oracle: {d}/{d} live rounds verified (rejected {d})\n", .{ ok, arr.len, bad });
    return if (bad == 0) 0 else 1;
}
