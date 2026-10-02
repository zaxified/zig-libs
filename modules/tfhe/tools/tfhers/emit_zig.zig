// SPDX-License-Identifier: MIT

//! Writes this module's keys, ciphertexts and gate outputs, in tfhe-rs's
//! standard layout, for `tfhe_tfhers_vectors check` (see ../README.md).
//! Records `tag[4] | len u32 | len u32 words` (LE) on stdout:
//!
//!   {S,D}LSK / GSK      the secret keys
//!   {S,D}BSK / KSK      bootstrap key (standard domain) and key-switch key
//!   {S,D}BIT / INP      8 (D) or 32 (S) random bits and their encryptions
//!   {S,D}GT0..GT6       this module's and/nand/or/nor/xor/xnor/mux outputs
//!                       on pairs (2i, 2i+1), control (2i+2) mod count
//!
//! S is tools/tfhers's small k = 2 set, D is `params.tfhers_default` (the D
//! output is ~80 MB: write it under .zig-cache, never commit it). Fresh keys
//! from the OS CSPRNG on every run.

const std = @import("std");
const tfhe = @import("tfhe");

const Small = tfhe.Tfhe(.{
    .n = 16,
    .k = 2,
    .N = 64,
    .bg_bits = 6,
    .ell = 3,
    .bks_bits = 3,
    .ell_ks = 6,
    .lwe_noise = .{ .gaussian = 0x1p-22 },
    .glwe_noise = .{ .gaussian = 0x1p-28 },
});
const Default = tfhe.Tfhe(tfhe.params.tfhers_default);

const Out = struct {
    w: *std.Io.Writer,

    fn record(self: Out, tag: []const u8, len: usize) !void {
        try self.w.writeAll(tag);
        try self.w.writeInt(u32, @intCast(len), .little);
    }
    fn word(self: Out, v: u32) !void {
        try self.w.writeInt(u32, v, .little);
    }
    fn words(self: Out, tag: []const u8, vs: []const u32) !void {
        try self.record(tag, vs.len);
        for (vs) |v| try self.word(v);
    }
    fn lwe(self: Out, ct: anytype) !void {
        for (ct.a) |v| try self.word(v);
        try self.word(ct.b);
    }
};

fn emit(comptime F: type, comptime prefix: []const u8, comptime count: usize, out: Out, gpa: std.mem.Allocator, io: std.Io) !void {
    const N = F.ring_degree;
    const k = F.glwe_dim;
    var ck = F.ClientKey.generate(io);
    defer ck.deinit();
    var bsk = try F.bootstrapKeyGen(gpa, &ck.lwe, &ck.glwe, io);
    defer bsk.deinit(gpa);
    const ksk = try F.keySwitchKeyGen(gpa, &ck.glwe, &ck.lwe, io);

    try out.words(prefix ++ "LSK", &ck.lwe.s);
    try out.record(prefix ++ "GSK", k * N);
    for (ck.glwe.s) |p| for (p.c) |v| try out.word(v);
    try out.record(prefix ++ "BSK", F.lwe_dim * F.ggsw_rows * (k + 1) * N);
    for (bsk.ggsw) |*g| for (&g.rows) |*rw| {
        for (rw.mask) |p| for (p.c) |v| try out.word(v);
        for (rw.body.c) |v| try out.word(v);
    };
    try out.record(prefix ++ "KSK", ksk.rows.len * (F.lwe_dim + 1));
    for (ksk.rows) |r| try out.lwe(r);

    var sk = try F.ServerKey.fromKeys(gpa, &bsk, ksk);
    defer sk.deinit(gpa);

    var bits: [count]bool = undefined;
    var raw: [count]u8 = undefined;
    io.random(&raw);
    for (&bits, raw) |*b, r| b.* = r & 1 == 1;
    var cts: [count]F.LweN = undefined;
    for (&cts, bits) |*c, b| c.* = ck.encrypt(b, io);
    try out.record(prefix ++ "BIT", count);
    for (bits) |b| try out.word(@intFromBool(b));
    try out.record(prefix ++ "INP", count * (F.lwe_dim + 1));
    for (cts) |c| try out.lwe(c);

    const names = [_][]const u8{ "and", "nand", "or", "nor", "xor", "xnor", "mux" };
    inline for (names, 0..) |name, g| {
        try out.record(std.fmt.comptimePrint("{s}GT{d}", .{ prefix, g }), (count / 2) * (F.lwe_dim + 1));
        for (0..count / 2) |i| {
            const a = &cts[2 * i];
            const b = &cts[2 * i + 1];
            const c = &cts[(2 * i + 2) % count];
            const r = if (comptime std.mem.eql(u8, name, "mux")) sk.mux(c, a, b) else @field(F.ServerKey, name)(&sk, a, b);
            try out.lwe(r);
        }
    }
}

pub fn main(init: std.process.Init) !void {
    var buf: [1 << 16]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &buf);
    const out: Out = .{ .w = &stdout.interface };
    try emit(Small, "S", 32, out, init.gpa, init.io);
    try emit(Default, "D", 8, out, init.gpa, init.io);
    try stdout.interface.flush();
}
