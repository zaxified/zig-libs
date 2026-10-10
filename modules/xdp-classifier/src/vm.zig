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
//! below (an independently written parser of the same README "Scope"
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
//!   * LPM6 trie : the same, over the 20-byte IPv6 key (`rules.LpmKey6`).
//!
//! Not a general BPF VM and not a verifier, but it enforces the ONE verifier
//! rule the packet path lives or dies by — **direct packet access must be
//! proven by a preceding `data_end` comparison** — dynamically, on every path
//! it executes: a `jgt rX, data_end` that falls through records `rX` as the
//! proven end of the packet, and any packet read reaching past the largest
//! proven end fails with `UnprovenPacketRead`, however long the actual packet
//! is. The kernel tracks that range per path statically
//! (`find_good_pkt_pointers`); run over packets truncated at every length,
//! the dynamic check visits every path the static one reasons about. No other
//! opcode is implemented, and `BadOpcode` is the correct (loud) answer for
//! anything this module's own builders never emit.

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
const lpm_value_base: u64 = 0x2_0000; // one cell per stored rule (v4: 0..63, v6: 64..127)
const lpm_cells = 128;
const lpm6_cell_base = 64;
const scratch_value_addr: u64 = 0x3_0000;

pub const LpmEntry = struct { addr: [4]u8, prefixlen: u32, class: u32 };
pub const Lpm6Entry = struct { addr: [16]u8, prefixlen: u32, class: u32 };

pub const Env = struct {
    packet: []const u8,
    lpm_fd: i32,
    scratch_fd: i32,
    cpumap_fd: i32 = -999,
    /// Stored LPM entries in INSERTION order; a later entry with the same
    /// (addr, prefixlen) shadows an earlier one, like map_update_elem does.
    lpm: []const LpmEntry,
    /// The IPv6 trie, same semantics; `lpm6_fd` names it.
    lpm6_fd: i32 = -998,
    lpm6: []const Lpm6Entry = &.{},
    /// Which CPUMAP indices are populated (`populateCpu` was called for them).
    cpumap_populated: []const u32 = &.{},
    cpumap_max_entries: u32 = 0,

    // outputs
    scratch_written: ?u32 = null,
};

pub const VmError = error{ OutOfBounds, BadOpcode, NoExit, StepLimit, UninitStack, UnprovenPacketRead, TooManyEntries };

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
    if (env.lpm.len > lpm6_cell_base or env.lpm6.len > lpm_cells - lpm6_cell_base) return VmError.TooManyEntries;
    var lpm_values: [lpm_cells]u32 = undefined;
    for (env.lpm, 0..) |e, i| lpm_values[i] = e.class;
    for (env.lpm6, 0..) |e, i| lpm_values[lpm6_cell_base + i] = e.class;

    // Largest packet address proven `<= data_end` so far on this path.
    var proven_end: u64 = packet_base;

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
            lv: *[lpm_cells]u32,
            sc: *u32,
            pe: u64,
        ) VmError!u64 {
            _ = de;
            if (addr == cp) return packet_base; // ctx->data
            if (addr == cp + 4) return packet_base + pk.len; // ctx->data_end
            if (addr >= packet_base and addr < packet_base + 0x10000 and addr + size > pe) return VmError.UnprovenPacketRead;
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
            if (addr >= lpm_value_base and addr < lpm_value_base + lpm_cells * 8) {
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
            0x61 => r[dst] = try readMem(@as(u64, @bitCast(@as(i64, @bitCast(r[src])) + ins.off)), 4, env.packet, data_end, &stack, &stack_init, ctx_ptr, &lpm_values, &scratch_cell, proven_end),
            0x69 => r[dst] = try readMem(@as(u64, @bitCast(@as(i64, @bitCast(r[src])) + ins.off)), 2, env.packet, data_end, &stack, &stack_init, ctx_ptr, &lpm_values, &scratch_cell, proven_end),
            0x71 => r[dst] = try readMem(@as(u64, @bitCast(@as(i64, @bitCast(r[src])) + ins.off)), 1, env.packet, data_end, &stack, &stack_init, ctx_ptr, &lpm_values, &scratch_cell, proven_end),

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
            } else if (r[src] == data_end and r[dst] >= packet_base and r[dst] <= data_end) {
                // Fell through `if (ptr > data_end) goto fail`: [.., ptr) is proven.
                proven_end = @max(proven_end, r[dst]);
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
                                kb[i] = @truncate(try readMem(key_addr + i, 1, env.packet, data_end, &stack, &stack_init, ctx_ptr, &lpm_values, &scratch_cell, proven_end));
                            }
                            const plen = std.mem.readInt(u32, kb[0..4], @import("builtin").cpu.arch.endian());
                            const a: [4]u8 = kb[4..8].*;
                            r[0] = lpmLookup(env.lpm, a, plen) orelse 0;
                        } else if (map_marker == env.lpm6_fd) {
                            // 20-byte key: native u32 prefixlen ++ 16 addr bytes
                            var kb: [20]u8 = undefined;
                            for (&kb, 0..) |*o, i| {
                                o.* = @truncate(try readMem(key_addr + i, 1, env.packet, data_end, &stack, &stack_init, ctx_ptr, &lpm_values, &scratch_cell, proven_end));
                            }
                            const plen = std.mem.readInt(u32, kb[0..4], @import("builtin").cpu.arch.endian());
                            r[0] = lpm6Lookup(env.lpm6, kb[4..20].*, plen) orelse 0;
                        } else if (map_marker == env.scratch_fd) {
                            var kb: [4]u8 = undefined;
                            var i: usize = 0;
                            while (i < 4) : (i += 1) {
                                kb[i] = @truncate(try readMem(key_addr + i, 1, env.packet, data_end, &stack, &stack_init, ctx_ptr, &lpm_values, &scratch_cell, proven_end));
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

/// The IPv6 trie, same semantics as `lpmLookup` (max prefixlen 128).
fn lpm6Lookup(entries: []const Lpm6Entry, addr: [16]u8, query_plen: u32) ?u64 {
    const a: u128 = std.mem.readInt(u128, &addr, .big);
    var best: ?usize = null;
    var best_len: u32 = 0;
    for (entries, 0..) |e, i| {
        if (e.prefixlen > 128 or e.prefixlen > query_plen) continue;
        const b: u128 = std.mem.readInt(u128, &e.addr, .big);
        const match = e.prefixlen == 0 or (a >> @intCast(128 - e.prefixlen)) == (b >> @intCast(128 - e.prefixlen));
        if (!match) continue;
        if (best == null or e.prefixlen >= best_len) {
            best = i;
            best_len = e.prefixlen;
        }
    }
    return if (best) |i| lpmValueAddr(lpm6_cell_base + i) else null;
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

/// Independent implementation of `../README.md` "Scope", written from that
/// prose and RFC 8200 / IEEE 802.1Q header layouts, NOT from
/// `classifier.zig`'s instruction emission — the two must agree
/// independently for a differential comparison to mean anything:
///   * the EtherType is at frame offset 12; while it is `0x8100` or `0x88A8`
///     and fewer than `vlan_depth` tags have been skipped, skip the 4-byte tag
///     and read the next EtherType;
///   * `0x0800`: the fixed 20-byte IPv4 header must be present and its IHL
///     nibble 5; key = source (header +12) or destination (+16) address;
///   * `0x86DD` with an IPv6 table: the fixed 40-byte IPv6 header must be
///     present and its version nibble 6; key = source (+8) or destination
///     (+24) address; extension headers are irrelevant to the key;
///   * anything else, any truncation, or no matching prefix -> not matched.
pub const RefField = enum { src, dst };

pub const RefConfig = struct {
    key_field: RefField,
    vlan_depth: u2 = 0,
    rules4: []const rules.ClassifierRule,
    /// `null` = no IPv6 map: IPv6 is never classified.
    rules6: ?[]const rules.ClassifierRule6 = null,
};

/// The matched class, or `null` when the packet is not classified (any
/// parse/bounds failure or an LPM miss).
pub fn packetMatchReference(pkt: []const u8, cfg: RefConfig) ?u32 {
    var et_off: usize = 12;
    if (pkt.len < et_off + 2) return null;
    var et = std.mem.readInt(u16, pkt[et_off..][0..2], .big);
    var skipped: u2 = 0;
    while ((et == 0x8100 or et == 0x88A8) and skipped < cfg.vlan_depth) : (skipped += 1) {
        et_off += 4;
        if (pkt.len < et_off + 2) return null;
        et = std.mem.readInt(u16, pkt[et_off..][0..2], .big);
    }
    const l3 = et_off + 2;
    switch (et) {
        0x0800 => {
            if (pkt.len < l3 + 20) return null;
            if (pkt[l3] & 0x0f != 5) return null;
            const at = l3 + @as(usize, if (cfg.key_field == .src) 12 else 16);
            const a: [4]u8 = pkt[at..][0..4].*;
            // Two defaults that cannot both be the answer: a hit returns the
            // same class for both, a miss returns each default.
            const x = rules.lookupReference(cfg.rules4, a, 0);
            return if (x == rules.lookupReference(cfg.rules4, a, 1)) x else null;
        },
        0x86DD => {
            const rs6 = cfg.rules6 orelse return null;
            if (pkt.len < l3 + 40) return null;
            if (pkt[l3] >> 4 != 6) return null;
            const at = l3 + @as(usize, if (cfg.key_field == .src) 8 else 24);
            const a: [16]u8 = pkt[at..][0..16].*;
            const x = rules.lookupReference6(rs6, a, 0);
            return if (x == rules.lookupReference6(rs6, a, 1)) x else null;
        },
        else => return null,
    }
}

pub fn packetDecideReference(pkt: []const u8, cfg: RefConfig, default_class: u32) u32 {
    return packetMatchReference(pkt, cfg) orelse default_class;
}

// ── real frames ─────────────────────────────────────────────────────────────
//
// Shared with `kernel_test.zig`, which runs the same frames through the real
// kernel. Every frame is a complete, well-formed wire frame (Ethernet II,
// IEEE 802.1Q/802.1ad tags, RFC 791 IPv4 with a valid header checksum or
// RFC 8200 IPv6, then an RFC 768 UDP header) unless a field is deliberately
// broken for the case that needs it.

pub const Tag = struct { tpid: u16, vid: u12 };

pub const L3 = union(enum) {
    v4: struct { src: [4]u8, dst: [4]u8, ihl: u4 = 5 },
    v6: struct { src: [16]u8, dst: [16]u8, version: u4 = 6, hop_by_hop: bool = false },
    other: u16, // a bare EtherType (e.g. ARP) and 28 zero bytes
};

/// Write the frame into `buf` and return it. `buf` must hold 128 bytes.
pub fn buildFrame(buf: []u8, tags: []const Tag, l3: L3) []u8 {
    var n: usize = 0;
    const put = struct {
        fn bytes(b: []u8, at: *usize, v: []const u8) void {
            @memcpy(b[at.*..][0..v.len], v);
            at.* += v.len;
        }
        fn be16(b: []u8, at: *usize, v: u16) void {
            std.mem.writeInt(u16, b[at.*..][0..2], v, .big);
            at.* += 2;
        }
    };
    put.bytes(buf, &n, &.{ 0x02, 0, 0, 0, 0, 0x02 }); // dst MAC
    put.bytes(buf, &n, &.{ 0x02, 0, 0, 0, 0, 0x01 }); // src MAC
    for (tags) |t| {
        put.be16(buf, &n, t.tpid);
        put.be16(buf, &n, (@as(u16, 3) << 13) | t.vid); // PCP 3, DEI 0, VID
    }
    const udp = [8]u8{ 0x30, 0x39, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00 }; // 12345 -> 53, len 8
    switch (l3) {
        .v4 => |h| {
            put.be16(buf, &n, 0x0800);
            const hlen: usize = @as(usize, h.ihl) * 4;
            const start = n;
            const total: u16 = @intCast(@max(hlen, 20) + udp.len);
            put.bytes(buf, &n, &.{ 0x40 | @as(u8, h.ihl), 0x00 });
            put.be16(buf, &n, total);
            put.bytes(buf, &n, &.{ 0x1c, 0x46, 0x40, 0x00, 64, 17, 0, 0 }); // id, DF, TTL, UDP, csum=0
            put.bytes(buf, &n, &h.src);
            put.bytes(buf, &n, &h.dst);
            while (n - start < hlen) put.bytes(buf, &n, &.{0x01}); // NOP options
            // RFC 1071 header checksum over the real header length.
            var sum: u32 = 0;
            var i: usize = start;
            while (i < n) : (i += 2) sum += std.mem.readInt(u16, buf[i..][0..2], .big);
            while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
            std.mem.writeInt(u16, buf[start + 10 ..][0..2], ~@as(u16, @intCast(sum)), .big);
            put.bytes(buf, &n, &udp);
        },
        .v6 => |h| {
            put.be16(buf, &n, 0x86DD);
            // version, traffic class 0, flow label 0x12345
            put.bytes(buf, &n, &.{ @as(u8, h.version) << 4, 0x01, 0x23, 0x45 });
            put.be16(buf, &n, if (h.hop_by_hop) 16 else 8);
            put.bytes(buf, &n, &.{ if (h.hop_by_hop) 0 else 17, 64 }); // next header, hop limit
            put.bytes(buf, &n, &h.src);
            put.bytes(buf, &n, &h.dst);
            // Hop-by-Hop: next = UDP, len 0 (8 bytes), PadN(4) — RFC 8200 §4.3.
            if (h.hop_by_hop) put.bytes(buf, &n, &.{ 17, 0, 0x01, 0x04, 0, 0, 0, 0 });
            put.bytes(buf, &n, &udp);
        },
        .other => |et| {
            put.be16(buf, &n, et);
            @memset(buf[n..][0..28], 0);
            n += 28;
        },
    }
    return buf[0..n];
}

// ── shared test fixtures ────────────────────────────────────────────────────

pub const fixed_ruleset = [_]rules.ClassifierRule{
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

fn v6(comptime words: [8]u16) [16]u8 {
    var out: [16]u8 = undefined;
    for (words, 0..) |w, i| std.mem.writeInt(u16, out[i * 2 ..][0..2], w, .big);
    return out;
}

/// No `::/0`, so IPv6 misses are exercised (fe80::/10 matches nothing).
pub const fixed_ruleset6 = [_]rules.ClassifierRule6{
    .{ .prefix = .{ .addr = v6(.{ 0x2001, 0xdb8, 0, 0, 0, 0, 0, 0 }), .prefix_len = 32 }, .class = 11 },
    .{ .prefix = .{ .addr = v6(.{ 0x2001, 0xdb8, 1, 0, 0, 0, 0, 0 }), .prefix_len = 48 }, .class = 12 },
    .{ .prefix = .{ .addr = v6(.{ 0x2001, 0xdb8, 1, 2, 0, 0, 0, 0 }), .prefix_len = 64 }, .class = 13 },
    .{ .prefix = .{ .addr = v6(.{ 0xfd00, 0, 0, 0, 0, 0, 0, 0 }), .prefix_len = 8 }, .class = 14 },
};

const fixed_store6 = blk: {
    var out: [fixed_ruleset6.len]Lpm6Entry = undefined;
    for (fixed_ruleset6, &out) |r, *e| e.* = .{ .addr = r.prefix.addr, .prefixlen = r.prefix.prefix_len, .class = r.class };
    break :blk out;
};

pub const addr_v6_sub64 = v6(.{ 0x2001, 0xdb8, 1, 2, 0, 0, 0, 5 }); // -> 13
pub const addr_v6_ula = v6(.{ 0xfd00, 0, 0, 0, 0, 0, 0, 1 }); // -> 14
pub const addr_v6_link = v6(.{ 0xfe80, 0, 0, 0, 0, 0, 0, 1 }); // -> no match
pub const addr_v6_doc = v6(.{ 0x2001, 0xdb8, 0xffff, 0, 0, 0, 0, 1 }); // -> 11

pub const Config = struct {
    key_field: classifier.KeyField = .src,
    vlan_depth: classifier.VlanDepth = .double,
    v6: bool = true,
    default_class: u32 = 0xDEFA,

    pub fn refConfig(self: Config) RefConfig {
        return .{
            .key_field = if (self.key_field == .src) .src else .dst,
            .vlan_depth = self.vlan_depth.tags(),
            .rules4 = &fixed_ruleset,
            .rules6 = if (self.v6) &fixed_ruleset6 else null,
        };
    }
};

/// One hand-built case: the frame and the class a reader of the spec expects
/// (written down by hand, not computed) for `.src` and `.dst` keys under the
/// default `Config` (double VLAN, IPv6 on). `null` = not classified.
pub const Case = struct {
    name: []const u8,
    tags: []const Tag,
    l3: L3,
    want_src: ?u32,
    want_dst: ?u32,
};

const q100: Tag = .{ .tpid = 0x8100, .vid = 100 };
const ad10: Tag = .{ .tpid = 0x88A8, .vid = 10 };
const v4_pair: L3 = .{ .v4 = .{ .src = .{ 10, 1, 2, 3 }, .dst = .{ 192, 168, 0, 1 } } };
const v6_pair: L3 = .{ .v6 = .{ .src = addr_v6_sub64, .dst = addr_v6_ula } };

pub const cases = [_]Case{
    .{ .name = "untagged IPv4", .tags = &.{}, .l3 = v4_pair, .want_src = 3, .want_dst = 4 },
    .{ .name = "802.1Q IPv4", .tags = &.{q100}, .l3 = v4_pair, .want_src = 3, .want_dst = 4 },
    .{ .name = "802.1Q VID 0 (priority tag) IPv4", .tags = &.{.{ .tpid = 0x8100, .vid = 0 }}, .l3 = v4_pair, .want_src = 3, .want_dst = 4 },
    .{ .name = "802.1ad outer only IPv4", .tags = &.{ad10}, .l3 = v4_pair, .want_src = 3, .want_dst = 4 },
    .{ .name = "QinQ 88A8+8100 IPv4", .tags = &.{ ad10, q100 }, .l3 = v4_pair, .want_src = 3, .want_dst = 4 },
    .{ .name = "double 8100 IPv4", .tags = &.{ q100, .{ .tpid = 0x8100, .vid = 4095 } }, .l3 = v4_pair, .want_src = 3, .want_dst = 4 },
    .{ .name = "triple tag IPv4 (past depth 2)", .tags = &.{ ad10, q100, q100 }, .l3 = v4_pair, .want_src = null, .want_dst = null },
    .{ .name = "0x9100 TPID IPv4 (not recognised)", .tags = &.{.{ .tpid = 0x9100, .vid = 7 }}, .l3 = v4_pair, .want_src = null, .want_dst = null },
    .{ .name = "IPv4 with options (IHL 6)", .tags = &.{q100}, .l3 = .{ .v4 = .{ .src = .{ 10, 1, 2, 3 }, .dst = .{ 192, 168, 0, 1 }, .ihl = 6 } }, .want_src = null, .want_dst = null },
    .{ .name = "untagged IPv6", .tags = &.{}, .l3 = v6_pair, .want_src = 13, .want_dst = 14 },
    .{ .name = "802.1Q IPv6", .tags = &.{q100}, .l3 = v6_pair, .want_src = 13, .want_dst = 14 },
    .{ .name = "QinQ IPv6", .tags = &.{ ad10, q100 }, .l3 = v6_pair, .want_src = 13, .want_dst = 14 },
    .{ .name = "IPv6 + Hop-by-Hop header", .tags = &.{q100}, .l3 = .{ .v6 = .{ .src = addr_v6_sub64, .dst = addr_v6_ula, .hop_by_hop = true } }, .want_src = 13, .want_dst = 14 },
    .{ .name = "IPv6 link-local src / doc dst", .tags = &.{}, .l3 = .{ .v6 = .{ .src = addr_v6_link, .dst = addr_v6_doc } }, .want_src = null, .want_dst = 11 },
    .{ .name = "86DD with version nibble 4", .tags = &.{}, .l3 = .{ .v6 = .{ .src = addr_v6_sub64, .dst = addr_v6_ula, .version = 4 } }, .want_src = null, .want_dst = null },
    .{ .name = "triple tag IPv6", .tags = &.{ ad10, q100, q100 }, .l3 = v6_pair, .want_src = null, .want_dst = null },
    .{ .name = "ARP", .tags = &.{q100}, .l3 = .{ .other = 0x0806 }, .want_src = null, .want_dst = null },
};

/// Smallest frame length at which a case can be classified: the L3 header's
/// fixed part must be wholly present after the tags (34 / 54 + 4 per tag).
pub fn minClassifiedLen(c: Case) usize {
    const t = 4 * c.tags.len;
    return switch (c.l3) {
        .v4 => 34 + t,
        .v6 => 54 + t,
        .other => 0,
    };
}

/// What the default `Config` variant `cfg` should produce for case `c`,
/// derived from the hand-written default-config answer by the two config
/// rules (fewer tags skipped, no IPv6 map) — not by the oracle.
pub fn expected(c: Case, cfg: Config) ?u32 {
    const base = if (cfg.key_field == .src) c.want_src else c.want_dst;
    if (c.tags.len > cfg.vlan_depth.tags()) return null;
    if (c.l3 == .v6 and !cfg.v6) return null;
    return base;
}

pub const lpm_fd_marker: i32 = 10;
pub const scratch_fd_marker: i32 = 11;
pub const lpm6_fd_marker: i32 = 12;
pub const cpumap_fd_marker: i32 = 13;

pub fn classifierFor(cfg: Config) []const Insn {
    return classifier.buildClassifierProgram(.{
        .lpm_map_fd = lpm_fd_marker,
        .scratch_map_fd = scratch_fd_marker,
        .key_field = cfg.key_field,
        .default_class = cfg.default_class,
        .vlan_depth = cfg.vlan_depth,
        .lpm6_map_fd = if (cfg.v6) lpm6_fd_marker else null,
    });
}

/// Interpret a classifier program on `pkt` against the fixed tables; the
/// class it wrote to the scratch map. Any VM error (including an unproven
/// packet read) or a non-PASS return is an error, never a silent pass.
pub fn runClassifier(prog: []const Insn, pkt: []const u8) !u32 {
    var env: Env = .{
        .packet = pkt,
        .lpm_fd = lpm_fd_marker,
        .scratch_fd = scratch_fd_marker,
        .lpm = &fixed_store,
        .lpm6_fd = lpm6_fd_marker,
        .lpm6 = &fixed_store6,
    };
    const res = try exec(prog, &env);
    if (res.ret != XDP_PASS) return error.NotXdpPass;
    return res.scratch orelse error.NoScratchWrite;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const classifier = @import("classifier.zig");

const all_configs = blk: {
    var out: [2 * 3 * 2]Config = undefined;
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

test "packet path: hand-built tagged / QinQ / IPv6 frames classify as written down, in every config" {
    var buf: [128]u8 = undefined;
    for (all_configs) |cfg| {
        const prog = classifierFor(cfg);
        for (cases) |c| {
            const pkt = buildFrame(&buf, c.tags, c.l3);
            const want = expected(c, cfg) orelse cfg.default_class;
            const got = try runClassifier(prog, pkt);
            if (got != want) {
                std.debug.print("case '{s}' cfg {any}: got {d}, want {d}\n", .{ c.name, cfg, got, want });
                return error.TestUnexpectedResult;
            }
            // The independent oracle agrees with the hand-written answer.
            try testing.expectEqual(want, packetDecideReference(pkt, cfg.refConfig(), cfg.default_class));
        }
    }
}

test "packet path: every frame truncated at every length — classified exactly from the fixed-header boundary on" {
    // Covers each bounds check's boundary (34 / 38 / 42 for IPv4 behind 0-2
    // tags, 54 / 58 / 62 for IPv6) from both sides, plus every length in
    // between, under the verifier-dominance model (an unproven read fails).
    var buf: [128]u8 = undefined;
    for (all_configs) |cfg| {
        const prog = classifierFor(cfg);
        for (cases) |c| {
            const full = buildFrame(&buf, c.tags, c.l3);
            const want_full = expected(c, cfg);
            var len: usize = 0;
            while (len <= full.len) : (len += 1) {
                const pkt = full[0..len];
                const want = if (want_full != null and len >= minClassifiedLen(c)) want_full.? else cfg.default_class;
                const got = try runClassifier(prog, pkt);
                if (got != want) {
                    std.debug.print("case '{s}' len {d} cfg {any}: got {d}, want {d}\n", .{ c.name, len, cfg, got, want });
                    return error.TestUnexpectedResult;
                }
                try testing.expectEqual(want, packetDecideReference(pkt, cfg.refConfig(), cfg.default_class));
            }
        }
    }
}

test "packet path: the steer program redirects exactly the frames the classifier matches" {
    var buf: [128]u8 = undefined;
    for (all_configs) |cfg| {
        const prog = try classifier.buildCpumapSteerProgram(.{
            .lpm_map_fd = lpm_fd_marker,
            .cpumap_fd = cpumap_fd_marker,
            .cpu_count = 1,
            .cpumap_max_entries = 1,
            .key_field = cfg.key_field,
            .vlan_depth = cfg.vlan_depth,
            .lpm6_map_fd = if (cfg.v6) lpm6_fd_marker else null,
        });
        for (cases) |c| {
            const full = buildFrame(&buf, c.tags, c.l3);
            var len: usize = 0;
            while (len <= full.len) : (len += 1) {
                var env: Env = .{
                    .packet = full[0..len],
                    .lpm_fd = lpm_fd_marker,
                    .scratch_fd = scratch_fd_marker,
                    .lpm = &fixed_store,
                    .lpm6_fd = lpm6_fd_marker,
                    .lpm6 = &fixed_store6,
                    .cpumap_fd = cpumap_fd_marker,
                    .cpumap_populated = &.{0},
                    .cpumap_max_entries = 1,
                };
                const res = try exec(prog, &env);
                const hit = expected(c, cfg) != null and len >= minClassifiedLen(c);
                try testing.expectEqual(if (hit) XDP_REDIRECT else XDP_PASS, res.ret);
                try testing.expectEqual(packetMatchReference(full[0..len], cfg.refConfig()) != null, hit);
            }
        }
    }
}

/// Random frames biased toward the interesting shapes (tags, both
/// EtherTypes, matching address prefixes, lengths near every boundary).
fn randomFrame(rnd: std.Random, buf: *[128]u8) []u8 {
    var tags: [3]Tag = undefined;
    const ntags = rnd.uintLessThan(usize, 4);
    for (tags[0..ntags]) |*t| t.* = .{
        .tpid = switch (rnd.uintLessThan(u8, 5)) {
            0, 1 => 0x8100,
            2, 3 => 0x88A8,
            else => rnd.int(u16),
        },
        .vid = rnd.int(u12),
    };
    var a4: [4]u8 = undefined;
    rnd.bytes(&a4);
    if (rnd.boolean()) a4[0..2].* = .{ 10, rnd.uintLessThan(u8, 3) };
    var a6: [16]u8 = undefined;
    rnd.bytes(&a6);
    switch (rnd.uintLessThan(u8, 4)) {
        0 => a6[0..6].* = addr_v6_sub64[0..6].*,
        1 => a6[0] = 0xfd,
        else => {},
    }
    const l3: L3 = switch (rnd.uintLessThan(u8, 9)) {
        0, 1, 2 => .{ .v4 = .{ .src = a4, .dst = a4, .ihl = if (rnd.uintLessThan(u8, 8) == 0) rnd.int(u4) else 5 } },
        3, 4, 5 => .{ .v6 = .{ .src = a6, .dst = a6, .version = if (rnd.uintLessThan(u8, 8) == 0) rnd.int(u4) else 6, .hop_by_hop = rnd.boolean() } },
        else => .{ .other = rnd.int(u16) },
    };
    const full = buildFrame(buf, tags[0..ntags], l3);
    const len = switch (rnd.uintLessThan(u8, 4)) {
        0 => rnd.uintAtMost(usize, full.len),
        1 => full.len -| rnd.uintLessThan(usize, 6),
        else => full.len,
    };
    if (rnd.uintLessThan(u8, 10) == 0) rnd.bytes(full[0..len]); // pure noise
    return full[0..len];
}

test "packet path: the emitted program agrees with the independent reference on a deterministic sweep" {
    // Permanent, non-fuzz sweep: runs on every plain `zig build test`, not
    // just under `--fuzz` (see A1/tc.md F3 for that trap). Any VM error —
    // including an unproven packet read — fails it.
    var prng = std.Random.DefaultPrng.init(0xF0F0_BEEF);
    const rnd = prng.random();
    var buf: [128]u8 = undefined;
    for (all_configs) |base| {
        for ([_]u32{ 0, 7, 0xFFFF_FFFF }) |dc| {
            var cfg = base;
            cfg.default_class = dc;
            const prog = classifierFor(cfg);
            var i: usize = 0;
            while (i < 3_000) : (i += 1) {
                const pkt = randomFrame(rnd, &buf);
                const got = try runClassifier(prog, pkt);
                try testing.expectEqual(packetDecideReference(pkt, cfg.refConfig(), dc), got);
            }
        }
    }
}

fn fuzzPacketPathAgrees(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    // check-fuzz-reach R1: the FIRST draw is a full-range u64 and every knob
    // (key field, VLAN depth, IPv6 on/off) is reduced from it by hand.
    const knobs = src.value(u64);
    const cfg: Config = .{
        .key_field = if (knobs % 2 == 0) .dst else .src,
        .vlan_depth = @enumFromInt((knobs / 2) % 3),
        .v6 = (knobs / 6) % 2 == 1,
        .default_class = @truncate(knobs >> 32),
    };
    const prog = classifierFor(cfg);
    var pkt: [128]u8 = undefined;
    // Under the driver, most packets come from `randomFrame` (valid Ethernet /
    // VLAN / IPv4 / IPv6 shapes with matching prefixes and boundary lengths);
    // uniform noise only ever reaches the "not IP" exit.
    var len: usize = undefined;
    if (S == fz.fuzz_driver.Rng and src.value(bool)) {
        len = randomFrame(src.r, &pkt).len;
        PacketMark.mark(.frame);
    } else {
        len = src.slice(&pkt);
        PacketMark.mark(.noise);
    }
    const got = try runClassifier(prog, pkt[0..len]);
    if (got == cfg.default_class) PacketMark.mark(.defaulted) else PacketMark.mark(.matched);
    try testing.expectEqual(packetDecideReference(pkt[0..len], cfg.refConfig(), cfg.default_class), got);
}

const fz = @import("fuzz_test.zig");
const PacketMark = fz.Marker(enum { frame, noise, defaulted, matched });

test "fuzz: the emitted classifier program agrees with the independent reference" {
    try std.testing.fuzz({}, fuzzPacketPathAgreesSmith, .{});
}

test "fuzz driver: XDP_FUZZ (packet)" {
    try fz.fuzz_driver.run(fuzzPacketPathAgrees, .{ .prefix = "XDP_FUZZ", .name = "xdp-packet" });
}

test "fuzz harness: packet, 500 seeds, reaches every outcome" {
    try PacketMark.reach(fuzzPacketPathAgrees, "xdp-packet", 500);
}

fn fuzzPacketPathAgreesSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzPacketPathAgrees(std.testing.Smith, smith, std.testing.allocator);
}

test "positive control: the interpreter's bounds-proof model rejects a weakened VLAN or IPv6 bounds check" {
    // Prove the dominance model bites (otherwise every test above could pass
    // with a check missing). Weaken ONE check in a copy of a real program and
    // the same frame that classifies cleanly must now fail as an unproven
    // read — even at full length, where the bytes physically exist, exactly
    // as the kernel verifier would reject the program regardless of input.
    var buf: [128]u8 = undefined;
    var copy: [128]Insn = undefined;

    const cfg: Config = .{ .key_field = .dst };
    const good = classifierFor(cfg);
    @memcpy(copy[0..good.len], good);

    // (a) the first tag level's re-check: `add r3, 34` -> `add r3, 30`.
    var seen: usize = 0;
    for (copy[0..good.len]) |*ins| {
        if (ins.code == 0x07 and ins.dst == 3 and ins.imm == 34) {
            seen += 1;
            if (seen == 2) ins.imm = 30;
        }
    }
    try testing.expectEqual(@as(usize, 3), seen); // untagged + two tag levels
    const tagged = buildFrame(&buf, &.{q100}, v4_pair);
    try testing.expectEqual(@as(u32, 4), try runClassifier(good, tagged));
    try testing.expectError(error.UnprovenPacketRead, runClassifier(copy[0..good.len], tagged));

    // (b) the IPv6 block's check: `add r3, 54` -> `add r3, 34`.
    @memcpy(copy[0..good.len], good);
    var found = false;
    for (copy[0..good.len]) |*ins| {
        if (ins.code == 0x07 and ins.dst == 3 and ins.imm == 54) {
            ins.imm = 34;
            found = true;
        }
    }
    try testing.expect(found);
    const six = buildFrame(&buf, &.{}, v6_pair);
    try testing.expectEqual(@as(u32, 14), try runClassifier(good, six));
    try testing.expectError(error.UnprovenPacketRead, runClassifier(copy[0..good.len], six));
}

test "structural: the largest program — every jump forward and in range, one exit, stack key <= 20 bytes" {
    for (all_configs) |cfg| {
        const prog = classifierFor(cfg);
        var exits: usize = 0;
        for (prog, 0..) |ins, i| {
            const class = ins.code & 0x07;
            const op = ins.code & 0xf0;
            if (class == 0x05 and op != 0x80 and op != 0x90) { // JMP, not call/exit
                try testing.expect(ins.off >= 0); // forward only: no back-edge for check_cfg
                try testing.expect(i + 1 + @as(usize, @intCast(ins.off)) < prog.len);
            }
            if (ins.code == 0x95) exits += 1;
            if ((ins.code == 0x62 or ins.code == 0x63 or ins.code == 0x73) and ins.dst == 10) {
                try testing.expect(ins.off >= -20 and ins.off < 0);
            }
        }
        try testing.expectEqual(@as(usize, 1), exits);
    }
    // Pinned sizes (SELF-DERIVED from the layout in emitParseAndLookup): the
    // original 38, +7 per VLAN level, +47 for the IPv6 block — far under the
    // verifier's 4096-instruction unprivileged limit and the 128-slot buffer.
    try testing.expectEqual(@as(usize, 38), classifierFor(.{ .vlan_depth = .none, .v6 = false }).len);
    try testing.expectEqual(@as(usize, 52), classifierFor(.{ .vlan_depth = .double, .v6 = false }).len);
    try testing.expectEqual(@as(usize, 99), classifierFor(.{ .vlan_depth = .double, .v6 = true }).len);
}
