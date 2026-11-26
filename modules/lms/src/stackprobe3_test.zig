// SPDX-License-Identifier: MIT

//! Dead-stack probe (`testkit.stackprobe`) of the tree constructors the older
//! probes do not call: `Tree.initCached`, `Tree.initParallel` and
//! `Tree.initCachedParallel` (h5/w4, one task so every frame is on the
//! measured thread's stack). Residue below each burn, the SEED as a needle.
//! Each call builds and frees its tree (heap, not stack). ReleaseFast/
//! ReleaseSmall only. Coverage sweep 2026-11-26.

const std = @import("std");
const lms = @import("root.zig");
const sp = @import("testkit").stackprobe;

const Tree = lms.Tree;
const P = sp.Probe(.{ .window = 64 * 1024 });
const gpa = std.heap.page_allocator; // global-alloc-ok: the tree's heap nodes are off the measured stack; page_allocator keeps the leak checker's frames out of the measurement

var seed: [32]u8 = undefined;
var id: [16]u8 = undefined;
var tree: Tree = undefined;

fn initCachedW(s: *const [32]u8) !void {
    try Tree.initCached(&tree, gpa, .sha256_m32_h5, .sha256_n32_w4, id, s, 2);
    tree.deinit();
}
fn initParallelW(s: *const [32]u8) !void {
    try Tree.initParallel(&tree, gpa, .sha256_m32_h5, .sha256_n32_w4, id, s, .{ .io = std.testing.io, .threads = 1 });
    tree.deinit();
}
fn initCachedParallelW(s: *const [32]u8) !void {
    try Tree.initCachedParallel(&tree, gpa, .sha256_m32_h5, .sha256_n32_w4, id, s, 2, .{ .io = std.testing.io, .threads = 1 });
    tree.deinit();
}

test "STACKPROBE: Tree.initCached / initParallel / initCachedParallel leave no SEED on the dead stack" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("lms probe3 seed", &seed, .{});
    var h: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("lms probe3 id", &h, .{});
    id = h[0..16].*;
    _ = try P.run("Tree.initCached (c=2)", initCachedW, .{&seed}, &.{&seed}, .{});
    _ = try P.run("Tree.initParallel (1 task)", initParallelW, .{&seed}, &.{&seed}, .{});
    _ = try P.run("Tree.initCachedParallel (c=2, 1 task)", initCachedParallelW, .{&seed}, &.{&seed}, .{});
}
