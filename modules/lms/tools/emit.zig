// SPDX-License-Identifier: MIT
//! Our side of the hash-sigs oracle (`hashsigs_oracle.sh verify`): an HSS key
//! for a parameter set, one signature of a message, both written raw.
//!
//!   zig build-exe -OReleaseFast --dep lms -Mroot=modules/lms/tools/emit.zig \
//!       -Mlms=modules/lms/src/root.zig -femit-bin=.zig-cache/lms-hashsigs/emit
//!   .zig-cache/lms-hashsigs/emit <h/w[,h/w...]> <message file> <out dir>
//!
//! writes <out dir>/key.pub and <out dir>/msg.sig. Seed and I are fixed
//! (bytes 0..31 and 32..47): this is an interop check, not a key.
const std = @import("std");
const lms = @import("lms");

fn level(spec: []const u8) !lms.Level {
    var it = std.mem.splitScalar(u8, spec, '/');
    const h = try std.fmt.parseInt(u8, it.next().?, 10);
    const w = try std.fmt.parseInt(u8, it.next() orelse "8", 10);
    return .{
        .lms = switch (h) {
            5 => .sha256_m32_h5,
            10 => .sha256_m32_h10,
            15 => .sha256_m32_h15,
            else => return error.Height,
        },
        .ots = switch (w) {
            1 => .sha256_n32_w1,
            2 => .sha256_n32_w2,
            4 => .sha256_n32_w4,
            8 => .sha256_n32_w8,
            else => return error.Winternitz,
        },
    };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.Usage;
    var levels: [lms.max_levels]lms.Level = undefined;
    var nl: usize = 0;
    var it = std.mem.splitScalar(u8, args[1], ',');
    while (it.next()) |s| : (nl += 1) levels[nl] = try level(s);
    const cwd = std.Io.Dir.cwd();
    const msg = try cwd.readFileAlloc(io, args[2], gpa, .limited(1 << 20));
    defer gpa.free(msg);
    var seed: [lms.n]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i);
    var id: [lms.id_len]u8 = undefined;
    for (&id, 0..) |*b, i| b.* = @intCast(32 + i);
    var sk: lms.SecretKey = undefined;
    try lms.SecretKey.init(&sk, gpa, levels[0..nl], &seed, id, null);
    defer sk.deinit();
    const buf = try gpa.alloc(u8, sk.signatureLength());
    defer gpa.free(buf);
    const sig = try sk.sign(msg, buf);
    var out = try cwd.openDir(io, args[3], .{});
    defer out.close(io);
    try out.writeFile(io, .{ .sub_path = "key.pub", .data = &sk.publicKey().toBytes() });
    try out.writeFile(io, .{ .sub_path = "msg.sig", .data = sig });
}
