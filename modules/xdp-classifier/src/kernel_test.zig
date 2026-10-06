// SPDX-License-Identifier: MIT
//! The real kernel as the oracle for the VLAN / IPv6 packet path: every
//! program variant (`vlan_depth` 0..2 × IPv6 on/off × src/dst key, classifier
//! and steer) is handed to the in-kernel verifier — also under
//! `BPF_F_STRICT_ALIGNMENT`, the check a strict-alignment architecture gets —
//! and then EXECUTED by the kernel on real frames via `BPF_PROG_TEST_RUN`,
//! against real `LPM_TRIE` maps populated through this module's own
//! `populateRuleSet`/`populateRuleSet6`. The class the kernel wrote to the
//! per-CPU scratch map is compared with the hand-written expectation and with
//! `vm.zig`'s interpreter on the same bytes.
//!
//! Needs `CAP_BPF` (or root): every syscall treats `PermissionDenied` as
//! `SkipZigTest`, the same gate as the module's other live tests. ⚠ On a host
//! without it these SKIP, and a skip is a pass — a green unprivileged run
//! says nothing about the kernel. `scripts/vm/run.sh xdp-classifier` runs
//! them as real root.
//!
//! Verification instrument only (CONVENTIONS §9), not public API.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const BPF = linux.BPF;
const ebpf = @import("ebpf");
const classifier = @import("classifier.zig");
const maps = @import("maps.zig");
const rules = @import("rules.zig");
const vm = @import("vm.zig");

const testing = std.testing;

/// `BPF_PROG_TEST_RUN` on one frame; the program's return value. The kernel
/// copies `pkt` into its own buffer, so a `[]const u8` is fine. Frames
/// shorter than `ETH_HLEN` (14) are refused by the kernel with EINVAL.
fn testRun(prog_fd: linux.fd_t, pkt: []const u8) !u32 {
    var attr = std.mem.zeroes(BPF.Attr);
    attr.test_run.prog_fd = prog_fd;
    attr.test_run.data_size_in = @intCast(pkt.len);
    attr.test_run.data_in = @intFromPtr(pkt.ptr);
    attr.test_run.repeat = 1;
    const rc = linux.bpf(.prog_test_run, &attr, @sizeOf(BPF.TestRunAttr));
    return switch (linux.errno(rc)) {
        .SUCCESS => attr.test_run.retval,
        .PERM => error.PermissionDenied,
        else => |e| {
            std.debug.print("BPF_PROG_TEST_RUN: {s} (len {d})\n", .{ @tagName(e), pkt.len });
            return error.Unexpected;
        },
    };
}

/// Load, and on refusal print the verifier's own log before failing.
fn loadOrExplain(insns: []const ebpf.Insn, flags: u32) !linux.fd_t {
    const prog: ebpf.Program = .{ .prog_type = .xdp, .insns = insns };
    return BPF.prog_load(.xdp, insns, null, "GPL", 0, flags) catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => {
            const log = try testing.allocator.alloc(u8, 1 << 20);
            defer testing.allocator.free(log);
            @memset(log, 0);
            _ = ebpf.loadWithLog(prog, "GPL", log, flags) catch {};
            std.debug.print("verifier refused ({s}):\n{s}\n", .{ @errorName(e), std.mem.sliceTo(log, 0) });
            return e;
        },
    };
}

const sentinel: u32 = 0xA5A5_A5A5;

/// Run the classifier on `pkt` in the kernel and return the class it wrote:
/// every CPU's scratch slot is preset to a sentinel, and exactly one slot —
/// the running CPU's — must have changed.
fn kernelClassify(prog_fd: linux.fd_t, scratch_fd: linux.fd_t, pkt: []const u8) !u32 {
    try maps.writeScratchClassAll(testing.allocator, scratch_fd, sentinel);
    try testing.expectEqual(@as(u32, vm.XDP_PASS), try testRun(prog_fd, pkt));
    const slots = try maps.readScratchClassAll(testing.allocator, scratch_fd);
    defer testing.allocator.free(slots);
    var written: ?u32 = null;
    for (slots) |v| {
        if (v == sentinel) continue;
        try testing.expect(written == null);
        written = v;
    }
    return written orelse error.NoScratchWrite;
}

const Maps = struct {
    lpm: linux.fd_t,
    lpm6: linux.fd_t,

    fn create() !Maps {
        const lpm = maps.createLpmTrieMap(64) catch |e| switch (e) {
            error.PermissionDenied => return error.SkipZigTest,
            else => return e,
        };
        errdefer _ = linux.close(lpm);
        const lpm6 = try maps.createLpm6TrieMap(64);
        errdefer _ = linux.close(lpm6);
        const rs4: rules.RuleSet = .{ .rules = &vm.fixed_ruleset };
        try rs4.validate(64);
        try maps.populateRuleSet(lpm, rs4);
        const rs6: rules.RuleSet6 = .{ .rules = &vm.fixed_ruleset6 };
        try rs6.validate(64);
        try maps.populateRuleSet6(lpm6, rs6);
        return .{ .lpm = lpm, .lpm6 = lpm6 };
    }

    fn close(self: Maps) void {
        _ = linux.close(self.lpm);
        _ = linux.close(self.lpm6);
    }
};

const all_configs = blk: {
    var out: [2 * 3 * 2]vm.Config = undefined;
    var i: usize = 0;
    for ([_]classifier.KeyField{ .src, .dst }) |kf| {
        for ([_]classifier.VlanDepth{ .none, .single, .double }) |d| {
            for ([_]bool{ false, true }) |six| {
                out[i] = .{ .key_field = kf, .vlan_depth = d, .v6 = six };
                i += 1;
            }
        }
    }
    break :blk out;
};

test "kernel: every classifier variant passes the verifier (also strict alignment) and classifies real frames, truncated at every length, as written down" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const m = try Maps.create();
    defer m.close();
    const scratch_fd = maps.createScratchMap() catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    defer _ = linux.close(scratch_fd);

    var buf: [128]u8 = undefined;
    var runs: usize = 0;
    for (all_configs) |cfg| {
        const insns = classifier.buildClassifierProgram(.{
            .lpm_map_fd = m.lpm,
            .scratch_map_fd = scratch_fd,
            .key_field = cfg.key_field,
            .default_class = cfg.default_class,
            .vlan_depth = cfg.vlan_depth,
            .lpm6_map_fd = if (cfg.v6) m.lpm6 else null,
        });
        const strict_fd = try loadOrExplain(insns, BPF.F_STRICT_ALIGNMENT);
        _ = linux.close(strict_fd);
        const prog_fd = try loadOrExplain(insns, 0);
        defer _ = linux.close(prog_fd);

        // The same program with the marker fds, for the interpreter.
        const vm_prog = vm.classifierFor(cfg);

        for (vm.cases) |c| {
            const full = vm.buildFrame(&buf, c.tags, c.l3);
            const want_full = vm.expected(c, cfg);
            var len: usize = 14; // ETH_HLEN: the kernel refuses shorter test frames
            while (len <= full.len) : (len += 1) {
                const pkt = full[0..len];
                const want = if (want_full != null and len >= vm.minClassifiedLen(c)) want_full.? else cfg.default_class;
                const got = try kernelClassify(prog_fd, scratch_fd, pkt);
                runs += 1;
                if (got != want) {
                    std.debug.print("KERNEL case '{s}' len {d} cfg {any}: got {d}, want {d}\n", .{ c.name, len, cfg, got, want });
                    return error.TestUnexpectedResult;
                }
                try testing.expectEqual(got, try vm.runClassifier(vm_prog, pkt));
            }
        }
    }
    try testing.expect(runs > 5000);
}

test "kernel: random frames — the kernel, the interpreter and the reference agree" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const m = try Maps.create();
    defer m.close();
    const scratch_fd = maps.createScratchMap() catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    defer _ = linux.close(scratch_fd);

    var prng = std.Random.DefaultPrng.init(0x6E7_0001);
    const rnd = prng.random();
    var buf: [128]u8 = undefined;
    for (all_configs) |cfg| {
        const insns = classifier.buildClassifierProgram(.{
            .lpm_map_fd = m.lpm,
            .scratch_map_fd = scratch_fd,
            .key_field = cfg.key_field,
            .default_class = cfg.default_class,
            .vlan_depth = cfg.vlan_depth,
            .lpm6_map_fd = if (cfg.v6) m.lpm6 else null,
        });
        const prog_fd = try loadOrExplain(insns, 0);
        defer _ = linux.close(prog_fd);
        const vm_prog = vm.classifierFor(cfg);

        var i: usize = 0;
        while (i < 300) : (i += 1) {
            var tags: [3]vm.Tag = undefined;
            const ntags = rnd.uintLessThan(usize, 4);
            for (tags[0..ntags]) |*t| t.* = .{ .tpid = if (rnd.boolean()) 0x8100 else 0x88A8, .vid = rnd.int(u12) };
            var a4: [4]u8 = .{ 10, rnd.uintLessThan(u8, 3), rnd.uintLessThan(u8, 4), rnd.int(u8) };
            if (rnd.uintLessThan(u8, 4) == 0) rnd.bytes(&a4);
            var a6: [16]u8 = vm.addr_v6_sub64;
            rnd.bytes(a6[5..]);
            if (rnd.uintLessThan(u8, 4) == 0) rnd.bytes(&a6);
            const l3: vm.L3 = if (rnd.boolean())
                .{ .v4 = .{ .src = a4, .dst = a4 } }
            else
                .{ .v6 = .{ .src = a6, .dst = a6, .hop_by_hop = rnd.boolean() } };
            const full = vm.buildFrame(&buf, tags[0..ntags], l3);
            const len = @max(14, full.len -| rnd.uintLessThan(usize, 8));
            const pkt = full[0..len];
            const got = try kernelClassify(prog_fd, scratch_fd, pkt);
            try testing.expectEqual(vm.packetDecideReference(pkt, cfg.refConfig(), cfg.default_class), got);
            try testing.expectEqual(got, try vm.runClassifier(vm_prog, pkt));
        }
    }
}

test "kernel: every steer variant passes the verifier and redirects exactly the matched frames" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const m = try Maps.create();
    defer m.close();
    const cpumap_fd = maps.createCpuMap(1) catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    defer _ = linux.close(cpumap_fd);
    try maps.populateCpu(cpumap_fd, 0, 192, null);

    var buf: [128]u8 = undefined;
    for (all_configs) |cfg| {
        const insns = try classifier.buildCpumapSteerProgram(.{
            .lpm_map_fd = m.lpm,
            .cpumap_fd = cpumap_fd,
            .cpu_count = 1,
            .cpumap_max_entries = 1,
            .key_field = cfg.key_field,
            .vlan_depth = cfg.vlan_depth,
            .lpm6_map_fd = if (cfg.v6) m.lpm6 else null,
        });
        const strict_fd = try loadOrExplain(insns, BPF.F_STRICT_ALIGNMENT);
        _ = linux.close(strict_fd);
        const prog_fd = try loadOrExplain(insns, 0);
        defer _ = linux.close(prog_fd);

        for (vm.cases) |c| {
            const full = vm.buildFrame(&buf, c.tags, c.l3);
            var len: usize = 14;
            while (len <= full.len) : (len += 1) {
                const hit = vm.expected(c, cfg) != null and len >= vm.minClassifiedLen(c);
                const got = try testRun(prog_fd, full[0..len]);
                if (got != (if (hit) vm.XDP_REDIRECT else vm.XDP_PASS)) {
                    std.debug.print("KERNEL steer case '{s}' len {d} cfg {any}: ret {d}\n", .{ c.name, len, cfg, got });
                    return error.TestUnexpectedResult;
                }
            }
        }
    }
}

test "kernel positive control: the real verifier refuses the weakened programs the interpreter's model rejects" {
    // vm.zig's bounds-proof model is only worth trusting if it agrees with the
    // kernel on what an unproven read IS. Same two mutations as vm.zig's
    // positive-control test: weaken the first tag level's re-check (34 -> 30)
    // or the IPv6 check (54 -> 34); the verifier must refuse each (EACCES,
    // "invalid access to packet"), while the unmutated program loads.
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const m = try Maps.create();
    defer m.close();
    const scratch_fd = maps.createScratchMap() catch |e| switch (e) {
        error.PermissionDenied => return error.SkipZigTest,
        else => return e,
    };
    defer _ = linux.close(scratch_fd);

    const good = classifier.buildClassifierProgram(.{
        .lpm_map_fd = m.lpm,
        .scratch_map_fd = scratch_fd,
        .key_field = .dst,
        .lpm6_map_fd = m.lpm6,
    });
    const ok_fd = try loadOrExplain(good, 0);
    _ = linux.close(ok_fd);

    var copy: [128]ebpf.Insn = undefined;
    const mutations = [_]struct { from: i32, nth: usize, to: i32 }{
        .{ .from = 34, .nth = 2, .to = 30 },
        .{ .from = 54, .nth = 1, .to = 34 },
    };
    for (mutations) |mu| {
        @memcpy(copy[0..good.len], good);
        var seen: usize = 0;
        for (copy[0..good.len]) |*ins| {
            if (ins.code == 0x07 and ins.dst == 3 and ins.imm == mu.from) {
                seen += 1;
                if (seen == mu.nth) ins.imm = mu.to;
            }
        }
        try testing.expect(seen >= mu.nth);
        if (BPF.prog_load(.xdp, copy[0..good.len], null, "GPL", 0, 0)) |fd| {
            _ = linux.close(fd);
            std.debug.print("verifier ACCEPTED a program with a weakened bounds check ({d} -> {d})\n", .{ mu.from, mu.to });
            return error.TestUnexpectedResult;
        } else |e| try testing.expectEqual(error.UnsafeProgram, e); // EACCES
    }
}
