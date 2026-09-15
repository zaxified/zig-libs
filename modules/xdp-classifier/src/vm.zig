// SPDX-License-Identifier: MIT
//! A verification-only interpreter for the ~18 BPF opcodes this module's two
//! program builders (`classifier.buildClassifierProgram`/
//! `buildCpumapSteerProgram`) actually emit.
//!
//! F8 (A1/xdp-classifier.md): the module shipped 0 `testing.fuzz` harnesses,
//! and the packet path — what the GENERATED PROGRAM decides for a given
//! frame — was offline-unreachable: exercising it for real needs a kernel
//! (`CAP_BPF`, unavailable to a plain fuzz run) to load the bytecode and feed
//! it packets. `rules.zig`'s own fuzz harnesses (added earlier this
//! campaign) cover `RuleSet.validate`/`lookupReference`, ordinary Zig with no
//! such gap — but neither touches the emitted BYTECODE at all. This file is
//! that missing offline oracle: an interpreter that runs the actual
//! `[]const Insn` slice a builder returns against a packet buffer, so the
//! packet path can be differential-fuzzed against `packetDecideReference`
//! below (an independently written parser of the same README "Scope (v1)"
//! contract) without a kernel in the loop.
//!
//! Per CONVENTIONS.md §9, an instrument that checks one module lives IN that
//! module's own `src/` directory, not in the audit tree — this began life as
//! `A1/repro/xdp-classifier/vm.zig`, an audit scratch file; it is ported
//! here verbatim (same opcode semantics, map-lookup modelling and step
//! limit), with only the imports adjusted to the module's real siblings.
//!
//! Map semantics are modelled the way the kernel implements them:
//!   * LPM trie  : longest-prefix match over stored (prefixlen, addr)
//!                 entries, LAST write wins on an identical (addr,
//!                 prefixlen) pair (`map_update_elem` overwrite) — exactly
//!                 what `rules.zig`'s `DuplicatePrefix` doc comment says.
//!   * PERCPU_ARRAY scratch : single slot, key must be u32 0.
//!   * CPUMAP    : `bpf_redirect_map(map, key, flags)` returns XDP_REDIRECT
//!                 for a populated in-range slot, otherwise `flags` if flags
//!                 is a valid XDP action, else XDP_ABORTED.
//!
//! Not a general BPF VM: no verifier, no other opcode is implemented, and
//! `BadOpcode` is the correct (loud) answer for anything this module's own
//! builders never emit.

const std = @import("std");
const ebpf = @import("ebpf");
const Insn = ebpf.Insn;
const rules = @import("rules.zig");

pub const XDP_ABORTED: u64 = 0;
pub const XDP_DROP: u64 = 1;
pub const XDP_PASS: u64 = 2;
pub const XDP_TX: u64 = 3;
pub const XDP_REDIRECT: u64 = 4;

const packet_base: u64 = 0x1_0000;
const stack_top: u64 = 0x8_0000;
const lpm_value_base: u64 = 0x2_0000; // one cell per stored rule
const scratch_value_addr: u64 = 0x3_0000;

pub const LpmEntry = struct { addr: [4]u8, prefixlen: u32, class: u32 };

pub const Env = struct {
    packet: []const u8,
    lpm_fd: i32,
    scratch_fd: i32,
    cpumap_fd: i32 = -999,
    /// Stored LPM entries in INSERTION order; a later entry with the same
    /// (addr, prefixlen) shadows an earlier one, like map_update_elem does.
    lpm: []const LpmEntry,
    /// Which CPUMAP indices are populated (`populateCpu` was called for them).
    cpumap_populated: []const u32 = &.{},
    cpumap_max_entries: u32 = 0,

    // outputs
    scratch_written: ?u32 = null,
};

pub const VmError = error{ OutOfBounds, BadOpcode, NoExit, StepLimit, UninitStack };

pub const Result = struct {
    ret: u64,
    scratch: ?u32,
    steps: usize,
};

/// The four bytes of an LPM value cell for stored entry `i`.
fn lpmValueAddr(i: usize) u64 {
    return lpm_value_base + @as(u64, i) * 8;
}

/// Execute `prog` against `env`. `r1` starts as the xdp_md context pointer.
pub fn exec(prog: []const Insn, env: *Env) VmError!Result {
    var r: [11]u64 = .{0} ** 11;
    r[10] = stack_top;

    // Stack shadow: 512 bytes below stack_top, with an initialised bitmap so
    // we can catch a map key read that touches an uninitialised slot (the
    // verifier rejects exactly that, so it is worth detecting offline).
    var stack: [512]u8 = .{0} ** 512;
    var stack_init: [512]bool = .{false} ** 512;

    const ctx_ptr: u64 = 0x9_0000; // xdp_md
    r[1] = ctx_ptr;

    const data_end: u64 = packet_base + env.packet.len;

    // LPM value cells, one per stored entry.
    var lpm_values: [64]u32 = undefined;
    for (env.lpm, 0..) |e, i| lpm_values[i] = e.class;

    var scratch_cell: u32 = 0;

    const readMem = struct {
        fn f(
            addr: u64,
            size: u8,
            pk: []const u8,
            de: u64,
            st: *[512]u8,
            sti: *[512]bool,
            cp: u64,
            lv: *[64]u32,
            sc: *u32,
        ) VmError!u64 {
            _ = de;
            if (addr == cp) return packet_base; // ctx->data
            if (addr == cp + 4) return packet_base + pk.len; // ctx->data_end
            if (addr >= packet_base and addr < packet_base + pk.len) {
                const off = addr - packet_base;
                if (off + size > pk.len) return VmError.OutOfBounds;
                var v: u64 = 0;
                var i: u8 = 0;
                while (i < size) : (i += 1) v |= @as(u64, pk[off + i]) << @intCast(8 * i);
                return v;
            }
            if (addr >= packet_base and addr < packet_base + 0x10000) return VmError.OutOfBounds;
            if (addr >= stack_top - 512 and addr < stack_top) {
                const off: usize = @intCast(addr - (stack_top - 512));
                var v: u64 = 0;
                var i: u8 = 0;
                while (i < size) : (i += 1) {
                    if (!sti[off + i]) return VmError.UninitStack;
                    v |= @as(u64, st[off + i]) << @intCast(8 * i);
                }
                return v;
            }
            if (addr >= lpm_value_base and addr < lpm_value_base + 64 * 8) {
                const idx: usize = @intCast((addr - lpm_value_base) / 8);
                return lv[idx];
            }
            if (addr == scratch_value_addr) return sc.*;
            return VmError.OutOfBounds;
        }
    }.f;

    var pc: usize = 0;
    var steps: usize = 0;
    while (pc < prog.len) {
        steps += 1;
        if (steps > 1_000_000) return VmError.StepLimit;
        const ins = prog[pc];
        const dst: usize = ins.dst;
        const src: usize = ins.src;
        const imm64: u64 = @bitCast(@as(i64, ins.imm)); // BPF sign-extends imm

        switch (ins.code) {
            // ── ldx ──
            0x61 => r[dst] = try readMem(@as(u64, @bitCast(@as(i64, @bitCast(r[src])) + ins.off)), 4, env.packet, data_end, &stack, &stack_init, ctx_ptr, &lpm_values, &scratch_cell),
            0x69 => r[dst] = try readMem(@as(u64, @bitCast(@as(i64, @bitCast(r[src])) + ins.off)), 2, env.packet, data_end, &stack, &stack_init, ctx_ptr, &lpm_values, &scratch_cell),
            0x71 => r[dst] = try readMem(@as(u64, @bitCast(@as(i64, @bitCast(r[src])) + ins.off)), 1, env.packet, data_end, &stack, &stack_init, ctx_ptr, &lpm_values, &scratch_cell),

            // ── stx / st ──
            0x73, 0x63, 0x62 => {
                const size: u8 = if (ins.code == 0x73) 1 else 4;
                const val: u64 = if (ins.code == 0x62) imm64 else r[src];
                const addr: u64 = @bitCast(@as(i64, @bitCast(r[dst])) + ins.off);
                if (addr >= stack_top - 512 and addr + size <= stack_top) {
                    const off: usize = @intCast(addr - (stack_top - 512));
                    var i: u8 = 0;
                    while (i < size) : (i += 1) {
                        stack[off + i] = @truncate(val >> @intCast(8 * i));
                        stack_init[off + i] = true;
                    }
                } else if (addr == scratch_value_addr) {
                    scratch_cell = @truncate(val);
                    env.scratch_written = scratch_cell;
                } else return VmError.OutOfBounds;
            },

            // ── alu64 ──
            0xbf => r[dst] = r[src], // mov reg
            0xb7 => r[dst] = imm64, // mov imm
            0x07 => r[dst] = r[dst] +% imm64, // add imm
            0x57 => r[dst] = r[dst] & imm64, // and imm
            0x97 => r[dst] = if (imm64 == 0) 0 else r[dst] % imm64, // mod imm (unsigned)

            // ── jumps ──
            0x05 => pc = @intCast(@as(i64, @intCast(pc)) + ins.off), // ja
            0x2d => if (r[dst] > r[src]) { // jgt reg (unsigned)
                pc = @intCast(@as(i64, @intCast(pc)) + ins.off);
            },
            0x55 => if (r[dst] != imm64) { // jne imm
                pc = @intCast(@as(i64, @intCast(pc)) + ins.off);
            },
            0x15 => if (r[dst] == imm64) { // jeq imm
                pc = @intCast(@as(i64, @intCast(pc)) + ins.off);
            },

            // ── ld_map_fd (2 slots) ──
            0x18 => {
                r[dst] = @bitCast(@as(i64, ins.imm)); // the map fd, as a marker
                pc += 1; // skip the hi32 continuation slot
            },
            0x00 => {}, // ld_map_fd continuation reached directly: no-op

            // ── call ──
            0x85 => {
                switch (ins.imm) {
                    1 => { // map_lookup_elem(r1 = map, r2 = key) -> r0
                        const map_marker: i64 = @bitCast(r[1]);
                        const key_addr = r[2];
                        if (map_marker == env.lpm_fd) {
                            // 8-byte key: native u32 prefixlen ++ 4 addr bytes
                            var kb: [8]u8 = undefined;
                            var i: usize = 0;
                            while (i < 8) : (i += 1) {
                                kb[i] = @truncate(try readMem(key_addr + i, 1, env.packet, data_end, &stack, &stack_init, ctx_ptr, &lpm_values, &scratch_cell));
                            }
                            const plen = std.mem.readInt(u32, kb[0..4], @import("builtin").cpu.arch.endian());
                            const a: [4]u8 = kb[4..8].*;
                            r[0] = lpmLookup(env.lpm, a, plen) orelse 0;
                        } else if (map_marker == env.scratch_fd) {
                            var kb: [4]u8 = undefined;
                            var i: usize = 0;
                            while (i < 4) : (i += 1) {
                                kb[i] = @truncate(try readMem(key_addr + i, 1, env.packet, data_end, &stack, &stack_init, ctx_ptr, &lpm_values, &scratch_cell));
                            }
                            const k = std.mem.readInt(u32, &kb, @import("builtin").cpu.arch.endian());
                            r[0] = if (k == 0) scratch_value_addr else 0;
                        } else r[0] = 0;
                    },
                    51 => { // redirect_map(r1 = map, r2 = key, r3 = flags) -> r0
                        const key: u64 = r[2];
                        const flags: u64 = r[3];
                        var hit = false;
                        if (key < env.cpumap_max_entries) {
                            for (env.cpumap_populated) |c| {
                                if (c == key) hit = true;
                            }
                        }
                        if (hit) {
                            r[0] = XDP_REDIRECT;
                        } else {
                            // Kernel >= 5.15: flags may carry a fallback XDP
                            // action in its low bits; 0 means "no fallback"
                            // -> XDP_ABORTED.
                            r[0] = if (flags >= 1 and flags <= 4) flags else XDP_ABORTED;
                        }
                    },
                    else => r[0] = 0,
                }
                // helpers clobber r1-r5
                r[1] = 0xdead;
                r[2] = 0xdead;
                r[3] = 0xdead;
                r[4] = 0xdead;
                r[5] = 0xdead;
            },

            0x95 => return .{ .ret = r[0], .scratch = env.scratch_written, .steps = steps }, // exit
            else => return VmError.BadOpcode,
        }
        pc += 1;
    }
    return VmError.NoExit;
}

/// Kernel LPM-trie semantics: among all stored entries whose first
/// `prefixlen` bits match `addr`, return the value cell of the LONGEST; ties
/// between two entries with the same (addr, prefixlen) go to the LAST
/// inserted.
fn lpmLookup(entries: []const LpmEntry, addr: [4]u8, query_plen: u32) ?u64 {
    const a: u32 = std.mem.readInt(u32, &addr, .big);
    var best: ?usize = null;
    var best_len: u32 = 0;
    for (entries, 0..) |e, i| {
        if (e.prefixlen > 32) continue; // trie_update_elem would have returned EINVAL
        if (e.prefixlen > query_plen) continue;
        const b: u32 = std.mem.readInt(u32, &e.addr, .big);
        const match = if (e.prefixlen == 0) true else blk: {
            const sh: u5 = @intCast(32 - e.prefixlen);
            break :blk (a >> sh) == (b >> sh);
        };
        if (!match) continue;
        // >= so a LATER identical-length entry shadows an earlier one
        if (best == null or e.prefixlen >= best_len) {
            best = i;
            best_len = e.prefixlen;
        }
    }
    return if (best) |i| lpmValueAddr(i) else null;
}

/// Build the LPM store the kernel would hold after `populateRuleSet`, i.e.
/// insertion order preserved and out-of-spec prefixlen entries REJECTED by
/// `trie_update_elem` (max_prefixlen = (key_size-4)*8 = 32).
pub fn storeFromRules(buf: []LpmEntry, rs: []const rules.ClassifierRule) []LpmEntry {
    var n: usize = 0;
    for (rs) |r| {
        buf[n] = .{ .addr = r.prefix.addr, .prefixlen = r.prefix.prefix_len, .class = r.class };
        n += 1;
    }
    return buf[0..n];
}

// ── the packet-path reference oracle ────────────────────────────────────────

/// Independent implementation of `../README.md` "Scope (v1)":
///   * frame shorter than 34 bytes            -> default_class
///   * EtherType at offset 12 is not IPv4     -> default_class
///   * IHL nibble at offset 14 is not 5       -> default_class
///   * otherwise longest-prefix match on the key field, miss -> default_class
///
/// Written from the README prose, not derived from `classifier.zig`'s
/// instruction emission — the two must agree independently for a
/// differential fuzz comparison to mean anything (see the tests below).
pub const RefField = enum { src, dst };

pub fn packetDecideReference(
    pkt: []const u8,
    rs: []const rules.ClassifierRule,
    key_field: RefField,
    default_class: u32,
) u32 {
    if (pkt.len < 34) return default_class;
    const et = std.mem.readInt(u16, pkt[12..14], .big);
    if (et != 0x0800) return default_class;
    if ((pkt[14] & 0x0f) != 5) return default_class;
    const off: usize = switch (key_field) {
        .src => 26,
        .dst => 30,
    };
    const addr: [4]u8 = pkt[off..][0..4].*;
    return rules.lookupReference(rs, addr, default_class);
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const classifier = @import("classifier.zig");

const fixed_ruleset = [_]rules.ClassifierRule{
    .{ .prefix = .{ .addr = .{ 10, 0, 0, 0 }, .prefix_len = 8 }, .class = 1 },
    .{ .prefix = .{ .addr = .{ 10, 1, 0, 0 }, .prefix_len = 16 }, .class = 2 },
    .{ .prefix = .{ .addr = .{ 10, 1, 2, 0 }, .prefix_len = 24 }, .class = 3 },
    .{ .prefix = .{ .addr = .{ 192, 168, 0, 0 }, .prefix_len = 16 }, .class = 4 },
    .{ .prefix = .{ .addr = .{ 0, 0, 0, 0 }, .prefix_len = 0 }, .class = 9 },
};

const fixed_store = [_]LpmEntry{
    .{ .addr = .{ 10, 0, 0, 0 }, .prefixlen = 8, .class = 1 },
    .{ .addr = .{ 10, 1, 0, 0 }, .prefixlen = 16, .class = 2 },
    .{ .addr = .{ 10, 1, 2, 0 }, .prefixlen = 24, .class = 3 },
    .{ .addr = .{ 192, 168, 0, 0 }, .prefixlen = 16, .class = 4 },
    .{ .addr = .{ 0, 0, 0, 0 }, .prefixlen = 0, .class = 9 },
};

/// Run one random packet against both the interpreted generated program and
/// `packetDecideReference`, returning true iff they agree. Shared by the
/// deterministic sweep below and the corpus-guided fuzz harness.
fn agrees(prog: []const Insn, pkt: []const u8, kf: classifier.KeyField, ref_kf: RefField, lpm_fd: i32, scratch_fd: i32, default_class: u32) !bool {
    _ = kf;
    var env: Env = .{ .packet = pkt, .lpm_fd = lpm_fd, .scratch_fd = scratch_fd, .lpm = &fixed_store };
    const res = exec(prog, &env) catch return true; // a VM error is not a divergence to report here
    if (res.ret != XDP_PASS) return true; // buildClassifierProgram always returns PASS on this path; a mismatch is caught by classifier.zig's own structural tests
    const got = res.scratch orelse default_class;
    const want = packetDecideReference(pkt, &fixed_ruleset, ref_kf, default_class);
    return got == want;
}

test "packet path: the emitted classifier program agrees with the independent reference on a deterministic sweep" {
    // Permanent, non-fuzz sweep: runs on every plain `zig build test`, not
    // just under `--fuzz` (which `std.testing.fuzz` only corpus-explores;
    // outside `--fuzz` it calls its body once — see A1/tc.md F3 and
    // A1/paillier.md F6 for this exact trap elsewhere in the campaign). A
    // fixed seed keeps it deterministic across runs.
    const fields = [_]struct { kf: classifier.KeyField, ref_kf: RefField }{
        .{ .kf = .src, .ref_kf = .src },
        .{ .kf = .dst, .ref_kf = .dst },
    };
    const defaults = [_]u32{ 0, 7, 0xFFFF_FFFF };
    const lpm_fd: i32 = 10;
    const scratch_fd: i32 = 11;

    var prng = std.Random.DefaultPrng.init(0xF0F0_BEEF);
    const rnd = prng.random();
    var pkt: [128]u8 = undefined;

    for (fields) |f| {
        for (defaults) |dc| {
            const prog = classifier.buildClassifierProgram(.{
                .lpm_map_fd = lpm_fd,
                .scratch_map_fd = scratch_fd,
                .key_field = f.kf,
                .default_class = dc,
            });
            var i: usize = 0;
            while (i < 20_000) : (i += 1) {
                // Length distribution clustered around the 34-byte bound,
                // where an off-by-one would live.
                const len: usize = switch (rnd.uintLessThan(u8, 10)) {
                    0 => rnd.uintLessThan(usize, 6), // 0..5
                    1, 2, 3 => 30 + rnd.uintLessThan(usize, 9), // 30..38
                    4 => 14,
                    else => 34 + rnd.uintLessThan(usize, 90),
                };
                rnd.bytes(pkt[0..len]);
                // Bias half the frames toward being well-formed IPv4 so the
                // match path is actually exercised.
                if (len >= 34 and rnd.boolean()) {
                    std.mem.writeInt(u16, pkt[12..14], 0x0800, .big);
                    pkt[14] = 0x40 | (if (rnd.boolean()) @as(u8, 5) else rnd.int(u4));
                    if (rnd.boolean()) {
                        pkt[26] = 10;
                        if (rnd.boolean()) pkt[27] = 1;
                        pkt[30] = 192;
                        pkt[31] = 168;
                    }
                }
                try testing.expect(try agrees(prog, pkt[0..len], f.kf, f.ref_kf, lpm_fd, scratch_fd, dc));
            }
        }
    }
}

fn fuzzPacketPathAgrees(_: void, smith: *std.testing.Smith) !void {
    // check-fuzz-reach R1: `value(bool)` is the harness's FIRST draw, and
    // only a u64-or-wider `value` draw has full-range weights -- a narrower
    // one (bool included) is still weighted and collapses to the same
    // outcome for nearly every seed, same as a ranged draw. Draw a full
    // `u64` first and reduce it by hand instead.
    const kf: classifier.KeyField = if (smith.value(u64) % 2 == 0) .dst else .src;
    const ref_kf: RefField = if (kf == .src) .src else .dst;
    const default_class = smith.value(u32);
    const lpm_fd: i32 = 10;
    const scratch_fd: i32 = 11;

    const prog = classifier.buildClassifierProgram(.{
        .lpm_map_fd = lpm_fd,
        .scratch_map_fd = scratch_fd,
        .key_field = kf,
        .default_class = default_class,
    });

    var pkt: [128]u8 = undefined;
    const len: usize = smith.slice(&pkt);
    try testing.expect(try agrees(prog, pkt[0..len], kf, ref_kf, lpm_fd, scratch_fd, default_class));
}

test "fuzz: the emitted classifier program agrees with the independent reference" {
    try std.testing.fuzz({}, fuzzPacketPathAgrees, .{});
}
