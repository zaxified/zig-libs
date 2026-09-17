// SPDX-License-Identifier: MIT
//! Line-protocol driver for the `sealedbox` module, so a foreign oracle
//! (`diff_pynacl.py`, PyNaCl/libsodium) can drive the real, unmodified module
//! public API over stdin/stdout and compare bytes in both directions.
//! Talks to `sealedbox` only through its exported functions — no source
//! copied, no internals reached.
//!
//! Commands (one per line, hex arguments):
//!   SEALD <seed64> <rpk64> <msghex>   deterministic seal (io.random pinned to seed)
//!   SEAL  <rpk64> <msghex>            seal with real entropy
//!   OPEN  <sk64> <pk64> <sealedhex>   open via the buffer API
//! Replies: "OK <hex>" or "ERR <ErrorName>", one line per command.
//!
//! Build (see `tools/README.md` for the full recipe and measured result):
//!   zig build-exe -OReleaseFast -femit-bin=<scratch>/driver \
//!     --dep sealedbox -Mroot=modules/sealedbox/tools/driver.zig \
//!     -Msealedbox=modules/sealedbox/src/root.zig --cache-dir <scratch>

const std = @import("std");
const sealedbox = @import("sealedbox");

const FixedRandom = struct {
    bytes: [32]u8,
    fn randomFn(userdata: ?*anyopaque, buffer: []u8) void {
        const self: *const FixedRandom = @ptrCast(@alignCast(userdata.?));
        var i: usize = 0;
        while (i < buffer.len) : (i += 1) buffer[i] = self.bytes[i % self.bytes.len];
    }
};

var out_buf: [1 << 16]u8 = undefined;

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer _ = da.deinit();
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var in_buf: [1 << 16]u8 = undefined;
    var fr = std.Io.File.stdin().reader(io, &in_buf);
    const input = try fr.interface.allocRemaining(gpa, .unlimited);
    defer gpa.free(input);

    var w = std.Io.File.stdout().writer(io, &out_buf);
    const o = &w.interface;

    var it = std.mem.splitScalar(u8, input, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \r\t");
        if (line.len == 0) continue;
        handle(gpa, io, o, line) catch |e| {
            try o.print("ERR {s}\n", .{@errorName(e)});
        };
    }
    try o.flush();
}

fn hexToBytesAlloc(gpa: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, hex.len / 2);
    errdefer gpa.free(out);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

fn hex32(hex: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;
    if (hex.len != 64) return error.BadArg;
    _ = try std.fmt.hexToBytes(&out, hex);
    return out;
}

fn handle(gpa: std.mem.Allocator, io: std.Io, o: *std.Io.Writer, line: []const u8) !void {
    var f = std.mem.tokenizeScalar(u8, line, ' ');
    const cmd = f.next() orelse return error.BadArg;

    if (std.mem.eql(u8, cmd, "SEALD") or std.mem.eql(u8, cmd, "SEAL")) {
        var use_io = io;
        var fixed: FixedRandom = undefined;
        var vt: std.Io.VTable = undefined;
        if (std.mem.eql(u8, cmd, "SEALD")) {
            fixed = .{ .bytes = try hex32(f.next() orelse return error.BadArg) };
            vt = io.vtable.*;
            vt.random = FixedRandom.randomFn;
            use_io = .{ .userdata = &fixed, .vtable = &vt };
        }
        const rpk = try hex32(f.next() orelse return error.BadArg);
        const msg_hex = f.next() orelse "";
        const msg = try hexToBytesAlloc(gpa, msg_hex);
        defer gpa.free(msg);
        const ct = try gpa.alloc(u8, sealedbox.sealedLen(msg.len));
        defer gpa.free(ct);
        sealedbox.seal(use_io, ct, msg, rpk) catch |e| {
            try o.print("ERR {s}\n", .{@errorName(e)});
            return;
        };
        try o.print("OK {x}\n", .{ct});
        return;
    }

    if (std.mem.eql(u8, cmd, "OPEN")) {
        const sk = try hex32(f.next() orelse return error.BadArg);
        const pk = try hex32(f.next() orelse return error.BadArg);
        const ct_hex = f.next() orelse "";
        const ct = try hexToBytesAlloc(gpa, ct_hex);
        defer gpa.free(ct);
        const kp = sealedbox.KeyPair{ .public_key = pk, .secret_key = sk };
        const out_len = if (ct.len >= sealedbox.overhead) ct.len - sealedbox.overhead else 0;
        const pt = try gpa.alloc(u8, out_len);
        defer gpa.free(pt);
        sealedbox.open(pt, ct, kp) catch |e| {
            try o.print("ERR {s}\n", .{@errorName(e)});
            return;
        };
        try o.print("OK {x}\n", .{pt});
        return;
    }

    return error.UnknownCommand;
}
