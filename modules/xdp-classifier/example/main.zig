// SPDX-License-Identifier: MIT

//! What an edge-shaper consumer does with `xdp-classifier`: validate a rule
//! table, build the classifier's eBPF program (pure bytecode generation —
//! this module ships "no Fable core", see `root.zig`'s own doc comment),
//! cross-check it against the pure userspace LPM reference, and attempt to
//! load it against the real in-kernel verifier.
//!
//! ⚠ WHAT RAN LIVE VS. WHAT DID NOT, AND WHY:
//!
//!  - **ALWAYS, pure, no privilege**: `RuleSet.validate`, `LpmKey` byte
//!    encoding, `buildClassifierProgram`/`buildCpumapSteerProgram` (both
//!    return a fixed instruction STREAM — data, not a live program — see
//!    `classifier.zig`'s doc comment), and `lookupReference` (the pure
//!    userspace longest-prefix-match oracle this module ships specifically
//!    so a ruleset's intent is checkable without a kernel).
//!  - **LIVE, real syscalls, no privilege needed for the negative case**:
//!    `populateRule`/`populateCpu` against a deliberately invalid fd (`-1`)
//!    — the kernel's own fd-lookup rejects it before any capability check,
//!    so `PopulateError.BadFd` is a genuine kernel answer, not a
//!    simulation, and needs no `CAP_BPF`.
//!  - **LIVE, gated on privilege**: creating the LPM-trie/scratch/CPUMAP
//!    maps (`BPF_MAP_CREATE`) and loading the classifier program into the
//!    kernel (`BPF_PROG_LOAD`, the real verifier) both need `CAP_BPF` (or
//!    root pre-5.8). This example calls `createLpmTrieMap` for real and
//!    asserts the named `error.PermissionDenied` it gets without the
//!    capability, following the `traceroute` example's pattern; with it,
//!    it creates both maps, populates a real rule, builds the SAME program
//!    against those real fds, and hands it to `ebpf.load` — the actual
//!    in-kernel verifier, not an assertion about what it would say.
//!
//! Nothing in this module's public API takes an `std.mem.Allocator` (rule
//! validation, key encoding and program building are all fixed-size and
//! allocation-free; map creation/population are direct `bpf(2)` syscalls) —
//! there is no OutOfMemory path to exercise and no `std.heap.DebugAllocator`
//! gate to wrap this example in.

const std = @import("std");
const xdp = @import("xdp-classifier");
const ebpf = @import("ebpf"); // xdp-classifier's one declared dep
const linux = std.os.linux;

pub fn main() !void {
    // ── 1. pure: validate a small ruleset, cross-check with the reference ──

    const rules = [_]xdp.ClassifierRule{
        .{ .prefix = .{ .addr = .{ 10, 0, 0, 0 }, .prefix_len = 8 }, .class = 1 },
        .{ .prefix = .{ .addr = .{ 10, 1, 0, 0 }, .prefix_len = 16 }, .class = 2 },
        .{ .prefix = .{ .addr = .{ 0, 0, 0, 0 }, .prefix_len = 0 }, .class = 9 }, // default route
    };
    const rule_set: xdp.RuleSet = .{ .rules = &rules };
    try rule_set.validate(64);

    // Longest-prefix wins: 10.1.2.3 matches both the /8 and the /16.
    if (xdp.lookupReference(&rules, .{ 10, 1, 2, 3 }, 0) != 2) return error.WrongLookup;
    if (xdp.lookupReference(&rules, .{ 10, 2, 3, 4 }, 0) != 1) return error.WrongLookup;
    if (xdp.lookupReference(&rules, .{ 8, 8, 8, 8 }, 0) != 9) return error.WrongLookup;
    std.debug.print("RuleSet.validate + lookupReference: 3 rules, longest-prefix cross-checked\n", .{});

    // The exact 8-byte wire layout the kernel's LPM trie expects (native
    // prefixlen + address bytes) and what the generated program constructs
    // at runtime from a live packet must agree byte-for-byte (rules.zig's
    // module doc) — checked here from the outside, on the published type.
    const key = xdp.LpmKey.exact(.{ 10, 1, 2, 3 }).toBytes();
    if (key.len != 8) return error.WrongKeyLength;
    if (std.mem.readInt(u32, key[0..4], @import("builtin").cpu.arch.endian()) != 32) return error.WrongPrefixLen;
    if (!std.mem.eql(u8, key[4..8], &.{ 10, 1, 2, 3 })) return error.WrongKeyAddr;

    // ── 2. pure: build the classifier + steer programs (data, not a load) ──

    const insns = xdp.buildClassifierProgram(.{ .lpm_map_fd = 10, .scratch_map_fd = 11, .default_class = 0 });
    if (insns.len == 0) return error.EmptyProgram;
    if (insns[insns.len - 1].code != 0x95) return error.LastInsnNotExit; // BPF exit
    var lpm_lookups: usize = 0;
    for (insns) |ins| {
        if (ins.code == 0x85 and ins.imm == @intFromEnum(linux.BPF.Helper.map_lookup_elem)) lpm_lookups += 1;
    }
    if (lpm_lookups != 2) return error.WrongLookupCallCount; // LPM lookup + scratch-map lookup
    std.debug.print("buildClassifierProgram: {d} instructions, ends in exit, 2 map lookups\n", .{insns.len});

    const steer_insns = try xdp.buildCpumapSteerProgram(.{ .lpm_map_fd = 10, .cpumap_fd = 12, .cpu_count = 4 });
    if (steer_insns.len == 0) return error.EmptyProgram;
    std.debug.print("buildCpumapSteerProgram: {d} instructions built\n", .{steer_insns.len});

    if (xdp.buildCpumapSteerProgram(.{ .lpm_map_fd = 10, .cpumap_fd = 12, .cpu_count = 0 })) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.InvalidCpuCount => std.debug.print("buildCpumapSteerProgram(cpu_count=0): InvalidCpuCount (expected)\n", .{}),
    }

    // ── 3. LIVE, real kernel, no privilege needed for THIS negative case ──

    const throwaway_rule: xdp.ClassifierRule = .{
        .prefix = .{ .addr = .{ 192, 168, 0, 0 }, .prefix_len = 16 },
        .class = 3,
    };
    if (xdp.populateRule(-1, throwaway_rule)) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.BadFd => std.debug.print("populateRule(fd=-1): BadFd (expected -- real kernel fd lookup, no CAP_BPF needed)\n", .{}),
        error.NotFound, error.PermissionDenied, error.Unexpected => return err,
    }

    // ── 4. LIVE, gated on CAP_BPF: real map creation + real verifier load ──

    if (xdp.createLpmTrieMap(16)) |lpm_fd| {
        defer _ = linux.close(lpm_fd);
        const scratch_fd = try xdp.createScratchMap();
        defer _ = linux.close(scratch_fd);

        try xdp.populateRule(lpm_fd, throwaway_rule);
        try xdp.populateRuleSet(lpm_fd, rule_set);

        const real_insns = xdp.buildClassifierProgram(.{ .lpm_map_fd = lpm_fd, .scratch_map_fd = scratch_fd });
        const prog = ebpf.Program{ .prog_type = .xdp, .insns = real_insns };
        const prog_fd = try ebpf.load(prog, "MIT");
        defer _ = linux.close(prog_fd);

        std.debug.print(
            "CAP_BPF IS available: real maps created, {d} rules populated, program LOADED and ACCEPTED by the in-kernel verifier\n",
            .{rules.len},
        );
    } else |err| switch (err) {
        error.PermissionDenied => std.debug.print(
            "createLpmTrieMap: PermissionDenied (expected -- no CAP_BPF on this host; program built and structurally checked above, but never handed to the real verifier)\n",
            .{},
        ),
        error.Unexpected => return err,
    }

    std.debug.print("OK: all xdp-classifier example checks passed\n", .{});
}
