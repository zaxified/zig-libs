// SPDX-License-Identifier: MIT

//! Comparative benchmark for `mls`: the bulk application-message path
//! (`PrivateMessage`), the program behind the card's `**Performance:**` line.
//! THIS IS A PROGRAM, NOT A TEST: `zig build bench-mls` runs it (ReleaseFast);
//! run it under `hw run`. Run from the repository root.
//!
//! Reference: OpenMLS 0.9.0 (MIT) with `openmls_rust_crypto` 0.6.0 and basic
//! credentials (`tools/oracle`, Cargo.lock pins the graph; build it once with
//! `cargo build --release --locked` in `modules/mls/tools/oracle`). Suite
//! 0x0001 on both sides; a two-member group (alice, bob), set up untimed.
//!
//! Workloads, per op, identical on both sides:
//!   rt_<n>    alice protects `n` bytes of application data to
//!             `MLSMessage(PrivateMessage)` wire bytes, bob decodes and opens
//!             them to the plaintext (ours: `protectApplication` +
//!             `unprotectApplication`; OpenMLS: `create_message` +
//!             `tls_serialize` / `tls_deserialize` + `process_message`).
//!             count = plaintext length + its last byte.
//!   seal_<n>  alice's half alone; count = wire length (the same bytes on
//!             the wire: same header widths, no padding).
//! Not the same: OpenMLS writes group state to its storage provider on every
//! call (its design); ours frees each message to the allocator. Wall time
//! only (the foreign side counts no cycles). Ratios are ours/OpenMLS.

const std = @import("std");
const bench = @import("benchkit");
const mls = @import("mls");

const S = mls.default_suite;
const G = mls.Group(S);
const bench_name = "bench-mls";
const work_dir = ".zig-cache/bench-mls";
const oracle = "modules/mls/tools/oracle/target/release/mls-oracle";

const Op = enum { rt_64, rt_1024, rt_16384, seal_64, seal_16384 };

const Ctx = struct {
    op: Op = .rt_64,
    gpa: std.mem.Allocator,
    io: std.Io,
    alice: G = undefined,
    bob: G = undefined,
    alice_sig: S.Sig.KeyPair = undefined,
    data: [3][]u8 = undefined,
};

fn sizeIndex(op: Op) usize {
    return switch (op) {
        .rt_64, .seal_64 => 0,
        .rt_1024 => 1,
        .rt_16384, .seal_16384 => 2,
    };
}

fn once(c: *Ctx) u64 {
    const data = c.data[sizeIndex(c.op)];
    const wire = c.alice.protectApplication(c.gpa, .{ .io = c.io, .signature_key_pair = &c.alice_sig, .data = data }) catch @panic("bench-mls: protect");
    defer c.gpa.free(wire);
    switch (c.op) {
        .seal_64, .seal_16384 => return wire.len,
        else => {
            const got = c.bob.unprotectApplication(c.gpa, wire) catch @panic("bench-mls: unprotect");
            defer got.deinit(c.gpa);
            return got.data.len + got.data[got.data.len - 1];
        },
    }
}

const Member = struct {
    sig: S.Sig.KeyPair,
    init_priv: [S.Kem.Nsk]u8,
    enc_priv: [S.Kem.Nsk]u8,
    kp: mls.keypackage.KeyPackage,
    msg: []u8,

    fn init(arena: std.mem.Allocator, name: []const u8, seed: u8) !Member {
        const sig = try S.Sig.KeyPair.generateDeterministic(@splat(seed));
        var init_kp: S.Kem.KeyPair = undefined;
        S.Kem.deriveKeyPair(&init_kp, &@as([32]u8, @splat(seed +% 64)));
        var enc_kp: S.Kem.KeyPair = undefined;
        S.Kem.deriveKeyPair(&enc_kp, &@as([32]u8, @splat(seed +% 128)));
        const kp = try mls.keypackage.create(S, arena, .{
            .signature_key_pair = &sig,
            .init_key = init_kp.public_key,
            .encryption_key = enc_kp.public_key,
            .credential = .{ .basic = name },
            .capabilities = .{ .versions = &.{1}, .cipher_suites = &.{1}, .extensions = &.{}, .proposals = &.{}, .credentials = &.{1} },
            .lifetime = .{ .not_before = 0, .not_after = std.math.maxInt(u64) },
        });
        const m: mls.framing.MLSMessage = .{ .key_package = kp };
        return .{ .sig = sig, .init_priv = init_kp.secret_key, .enc_priv = enc_kp.secret_key, .kp = kp, .msg = try m.encodeAlloc(arena) };
    }
};

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 5;
    const exe = cwd.realPathFileAlloc(io, oracle, arena) catch {
        std.debug.print("{s}: build the OpenMLS side first: (cd modules/mls/tools/oracle && cargo build --release --locked)\n", .{bench_name});
        return 1;
    };

    const gpa = init.gpa;
    var ctx = try arena.create(Ctx);
    ctx.* = .{ .gpa = gpa, .io = io };
    const alice = try Member.init(arena, "alice", 1);
    const bob = try Member.init(arena, "bob", 2);
    ctx.alice_sig = alice.sig;
    // 16 bytes, as OpenMLS's default random group id, so the wire lengths agree.
    try G.create(gpa, .{ .io = io, .group_id = "0123456789abcdef", .key_package_msg = alice.msg, .encryption_priv = &alice.enc_priv }, &ctx.alice);
    defer ctx.alice.deinit();
    {
        const c = try ctx.alice.createCommit(gpa, .{ .io = io, .signature_key_pair = &alice.sig, .proposals = &.{.{ .by_value = .{ .add = bob.kp } }} });
        defer c.deinit(gpa);
        try G.fromWelcome(gpa, .{ .welcome_msg = c.welcome.?, .key_package_msg = bob.msg, .init_priv = &bob.init_priv, .encryption_priv = &bob.enc_priv }, &ctx.bob);
    }
    defer ctx.bob.deinit();
    for ([_]usize{ 64, 1024, 16384 }, 0..) |n, k| {
        const d = try arena.alloc(u8, n);
        for (d, 0..) |*b, i| b.* = @truncate(i * 31 + 7);
        ctx.data[k] = d;
    }

    const W = bench.Work(Op);
    const ws = [_]W{
        .{ .name = "rt_64", .op = .rt_64, .ref = "rt_64", .wall_only = true },
        .{ .name = "rt_1024", .op = .rt_1024, .ref = "rt_1024", .wall_only = true },
        .{ .name = "rt_16384", .op = .rt_16384, .ref = "rt_16384", .wall_only = true },
        .{ .name = "seal_64", .op = .seal_64, .ref = "seal_64", .wall_only = true },
        .{ .name = "seal_16384", .op = .seal_16384, .ref = "seal_16384", .wall_only = true },
    };
    var buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buf);
    const w = &stdout.interface;
    const s = bench.drive(io, arena, .{
        .name = bench_name,
        .exes = &.{exe},
        .abs = abs,
        .filters = if (args.len > 1) args[1..] else &.{},
        .rounds = rounds,
    }, ctx, once, ws, w) catch |e| switch (e) {
        error.CountMismatch => return 1,
        else => return e,
    };
    try w.print("\n{s}\nworst ours/OpenMLS = {d:.2} (best {d:.2})\n", .{ s.banner, s.worst_ref, s.best_ref });
    try w.flush();
    return 0;
}
