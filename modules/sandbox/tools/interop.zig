// SPDX-License-Identifier: MIT

//! Live interop against the **reference**, libseccomp (the system library,
//! 2.6.x), driven through its public API by `tools/c_oracle/soracle.c` over
//! a pipe. libseccomp is LGPL-2.1: soracle is written from `seccomp.h` and
//! the man pages only, and this program compares BEHAVIOUR -- what the two
//! filters return for a syscall -- never code.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-sandbox` builds and runs
//! it; `zig build check-interop` only compiles it. Per case, a random rule
//! set is compiled by `seccomp.buildRulesWith` (linear and tree dispatch)
//! and by libseccomp (`seccomp_rule_add_exact_array`, optimize levels 1 and
//! 2, `seccomp_export_bpf_mem`); a classic-BPF interpreter written here runs
//! all four programs over `seccomp_data` inputs aimed at the rules' edges
//! (the compared values ±1, the other 32-bit half changed, foreign arches,
//! x32 numbers), and a direct evaluation of the rules (`model`) is the
//! referee. Families:
//!
//!   - `single`  every syscall in at most one rule
//!   - `same`    several rules per syscall, one action per syscall (OR)
//!   - `mixed`   several rules per syscall, any actions
//!
//! Verdicts per input: this module's programs must equal the model exactly
//! (a MISMATCH otherwise). libseccomp's must too, unless its documented
//! semantics differ from this module's on that input -- then the row is a
//! GAP, counted and printed by kind (see `Kind`), and libseccomp's verdict
//! must equal a model of ITS documented semantics instead:
//!
//!   - `u32-width`  a `.u32` condition, with junk in the argument's high
//!                  word: this module compares the low word (what the kernel
//!                  acts on for an `int` parameter); libseccomp's
//!                  `SCMP_A*_32` only casts the datum and compares 64 bits.
//!   - `precedence` two rules of one syscall with different actions that
//!                  both match: this module takes the first; libseccomp has
//!                  its own order (an unconditional rule overrides the rest,
//!                  …), not modelled here -- every such input is this gap.
//!   - `x32`        an x32 number (`__X32_SYSCALL_BIT`) under
//!                  `AUDIT_ARCH_X86_64`: killed here before any rule.
//!
//! One per case in `same` and `mixed`: `lib_refuses`, libseccomp's
//! `seccomp_rule_add` refusing a rule that repeats (-EEXIST) or, in `mixed`,
//! conflicts with (-EINVAL) an earlier one of the same syscall, where this
//! module decides by order. A refusal in `single` stays a MISMATCH. Not
//! generated: `ERRNO(4095)`, which libseccomp refuses (-EINVAL, its range is
//! 1..4094) and the kernel and this module accept (`MAX_ERRNO`).
//!
//! And two where libseccomp is wrong by its own documentation:
//!
//!   - `lib_defect` at most one rule matches (or all that match share one
//!                  action), so the verdict is not a matter of precedence, and
//!                  libseccomp's program still answers otherwise. Seen in
//!                  2.6.0 with several conditional rules on one syscall: a
//!                  rule dropped (`a2 >= 0xffffffff` and later
//!                  `a2 >= 1064063461 && a3 < 0xffffffff` -- the second one is
//!                  missing from `seccomp_export_pfc`, and the kernel running
//!                  the exported program lets a call through that the second
//!                  rule names), and an action taken where no rule matches.
//!                  The first few are printed with their rules.
//!   - `lib_timeout` libseccomp spending over 5 s on one
//! rule set (soracle's watchdog reports it and exits; the peer restarts).
//! This module builds every such set in microseconds.
//!
//! Usage, from the repository root:
//!
//!   zig build interop-sandbox                       # seed 1
//!   zig build interop-sandbox -- --seed 7 --scale 4 # another seed, 4× the cases
//!
//! Needs libseccomp's headers and `libseccomp.so` (Debian/Ubuntu:
//! `libseccomp-dev`); soracle is compiled with `zig cc` into
//! `.zig-cache/interop-sandbox/`, once per change of `soracle.c`. It does not
//! skip: no libseccomp, no run. x86-64 Linux only.

const std = @import("std");
const builtin = @import("builtin");
const sandbox = @import("sandbox");
const seccomp = sandbox.seccomp;
const linux = std.os.linux;

const scratch = ".zig-cache/interop-sandbox";
const oracle_c = "modules/sandbox/tools/c_oracle/soracle.c";

comptime {
    if (builtin.cpu.arch != .x86_64 or builtin.os.tag != .linux) @compileError("interop-sandbox: x86-64 Linux only");
}

const audit_arch_x86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;
const audit_arch_i386: u32 = 3 | 0x4000_0000;
const x32_bit: u32 = 0x4000_0000;

// ── the peer ────────────────────────────────────────────────────────────────

const Reply = union(enum) { ok: []u8, err: struct { step: u32, rc: i32 } };

const Peer = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    child: std.process.Child,
    rbuf: [1 << 16]u8 = undefined,
    wbuf: [1 << 16]u8 = undefined,
    r: std.Io.File.Reader = undefined,
    w: std.Io.File.Writer = undefined,

    fn start(p: *Peer) void {
        p.r = p.child.stdout.?.readerStreaming(p.io, &p.rbuf);
        p.w = p.child.stdin.?.writerStreaming(p.io, &p.wbuf);
    }

    fn spawn(p: *Peer, exe: []const u8) !void {
        p.child = std.process.spawn(p.io, .{ .argv = &.{exe}, .stdin = .pipe, .stdout = .pipe, .stderr = .inherit }) catch |e| {
            std.debug.print("interop-sandbox: could not start {s} ({t})\n", .{ exe, e });
            return error.NoReference;
        };
        p.start();
    }

    fn stop(p: *Peer) void {
        p.child.stdin.?.close(p.io);
        p.child.stdin = null;
        _ = p.child.wait(p.io) catch {};
    }

    fn u8_(p: *Peer, v: u8) !void {
        try p.w.interface.writeByte(v);
    }
    fn u32_(p: *Peer, v: u32) !void {
        try p.w.interface.writeInt(u32, v, .little);
    }
    fn u64_(p: *Peer, v: u64) !void {
        try p.w.interface.writeInt(u64, v, .little);
    }

    fn reply(p: *Peer) !Reply {
        try p.w.interface.flush();
        const st = try p.r.interface.takeByte();
        const n = try p.r.interface.takeInt(u32, .little);
        if (st != 0) return .{ .err = .{ .step = n, .rc = @bitCast(try p.r.interface.takeInt(u32, .little)) } };
        const out = try p.gpa.alloc(u8, n);
        errdefer p.gpa.free(out);
        try p.r.interface.readSliceAll(out);
        return .{ .ok = out };
    }

    fn version(p: *Peer) !Reply {
        try p.u8_('V');
        return p.reply();
    }

    fn build(p: *Peer, rules: []const seccomp.Rule, default: seccomp.Action, optimize: u8) !Reply {
        try p.u8_('B');
        try p.u32_(word(default));
        try p.u32_(word(.kill_process)); // this module's arch guard
        try p.u8_(optimize);
        try p.u32_(@intCast(rules.len));
        for (rules) |r| {
            try p.u32_(word(r.action));
            try p.u32_(@intCast(@backingInt(r.sysno)));
            try p.u32_(@intCast(r.when.len));
            for (r.when) |c| {
                // libseccomp: SCMP_CMP_* numbering; MASKED_EQ takes (mask, value).
                const op: u32 = switch (c.op) {
                    .ne => 1,
                    .lt => 2,
                    .le => 3,
                    .eq => 4,
                    .ge => 5,
                    .gt => 6,
                    .masked_eq => 7,
                };
                // SCMP_CMP32 casts both data to uint32_t (seccomp.h).
                const narrow = c.width == .u32;
                const v = if (narrow) c.value & 0xffff_ffff else c.value;
                const m = if (narrow) c.mask & 0xffff_ffff else c.mask;
                try p.u32_(c.arg);
                try p.u32_(op);
                try p.u64_(if (c.op == .masked_eq) m else v);
                try p.u64_(if (c.op == .masked_eq) v else 0);
            }
        }
        return p.reply();
    }
};

fn freeReply(gpa: std.mem.Allocator, r: Reply) void {
    if (r == .ok) gpa.free(r.ok);
}

/// Builds soracle against the system libseccomp unless a build of the same
/// `soracle.c` is already there. Returns the executable's path.
fn buildOracle(gpa: std.mem.Allocator, io: std.Io) ![]const u8 {
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, scratch);
    const c_src = try cwd.readFileAlloc(io, oracle_c, gpa, .limited(1 << 20));
    defer gpa.free(c_src);
    var h: [8]u8 = undefined;
    std.mem.writeInt(u64, &h, std.hash.Wyhash.hash(0, c_src), .little);
    const stamp_hex = std.fmt.bytesToHex(h, .lower);
    const exe = scratch ++ "/soracle";
    const stamp_path = scratch ++ "/soracle.stamp";
    if (cwd.readFileAlloc(io, stamp_path, gpa, .limited(64))) |old| {
        defer gpa.free(old);
        if (std.mem.eql(u8, old, &stamp_hex)) if (cwd.access(io, exe, .{})) return exe else |_| {};
    } else |_| {}
    std.debug.print("interop-sandbox: building soracle with zig cc against the system libseccomp ...\n", .{});
    const r = try std.process.run(gpa, io, .{ .argv = &.{ "zig", "cc", "-O2", oracle_c, "-lseccomp", "-o", exe } });
    defer gpa.free(r.stdout);
    defer gpa.free(r.stderr);
    if (r.term != .exited or r.term.exited != 0) {
        std.debug.print("interop-sandbox: zig cc failed (libseccomp-dev installed?):\n{s}\n", .{r.stderr});
        return error.NoReference;
    }
    try cwd.writeFile(io, .{ .sub_path = stamp_path, .data = &stamp_hex });
    return exe;
}

// ── classic BPF, as the kernel runs a seccomp filter ────────────────────────

const Insn = sandbox.SockFilter;

/// `struct seccomp_data`: nr, arch, instruction_pointer, args[6].
const Data = struct {
    nr: u32,
    arch: u32,
    ip: u64 = 0,
    args: [6]u64,

    fn bytes(d: Data) [64]u8 {
        var b: [64]u8 = undefined;
        std.mem.writeInt(u32, b[0..4], d.nr, .little);
        std.mem.writeInt(u32, b[4..8], d.arch, .little);
        std.mem.writeInt(u64, b[8..16], d.ip, .little);
        for (d.args, 0..) |a, i| std.mem.writeInt(u64, b[16 + 8 * i ..][0..8], a, .little);
        return b;
    }
};

fn parseProgram(gpa: std.mem.Allocator, raw: []const u8) ![]Insn {
    if (raw.len % 8 != 0) return error.BadProgram;
    const out = try gpa.alloc(Insn, raw.len / 8);
    for (out, 0..) |*o, i| {
        const b = raw[8 * i ..][0..8];
        o.* = .{ .code = std.mem.readInt(u16, b[0..2], .little), .jt = b[2], .jf = b[3], .k = std.mem.readInt(u32, b[4..8], .little) };
    }
    return out;
}

/// Runs `prog` on `d` with the semantics of the kernel's seccomp checker
/// (`seccomp_check_filter` plus the classic interpreter): only the opcodes
/// it admits, aligned 32-bit loads inside `seccomp_data`, forward jumps
/// inside the program, the 16-word scratch memory. Any program the kernel
/// would refuse is an error here, not a verdict.
fn run(prog: []const Insn, d: Data) error{BadProgram}!u32 {
    if (prog.len == 0 or prog.len > 4096) return error.BadProgram;
    const pkt = d.bytes();
    var a: u32 = 0;
    var x: u32 = 0;
    var mem: [16]u32 = @splat(0);
    var pc: usize = 0;
    while (true) {
        if (pc >= prog.len) return error.BadProgram;
        const i = prog[pc];
        pc += 1;
        const src: u32 = if (i.code & 0x08 != 0) x else i.k;
        switch (i.code & 0x07) {
            0x00, 0x01 => { // LD, LDX
                const v: u32 = switch (i.code & 0xe0) {
                    0x00 => i.k, // IMM
                    0x20 => blk: { // ABS (LD only, W only)
                        if (i.code != 0x20 or i.k % 4 != 0 or i.k >= 64) return error.BadProgram;
                        break :blk std.mem.readInt(u32, pkt[i.k..][0..4], .little);
                    },
                    0x60 => blk: { // MEM
                        if (i.k >= 16) return error.BadProgram;
                        break :blk mem[i.k];
                    },
                    0x80 => 64, // LEN
                    else => return error.BadProgram,
                };
                if (i.code & 0x18 != 0) return error.BadProgram; // only W
                if (i.code & 0x07 == 0) a = v else x = v;
            },
            0x02, 0x03 => { // ST, STX
                if (i.k >= 16 or i.code & 0xf8 != 0) return error.BadProgram;
                mem[i.k] = if (i.code & 0x07 == 0x02) a else x;
            },
            0x04 => { // ALU
                a = switch (i.code & 0xf0) {
                    0x00 => a +% src,
                    0x10 => a -% src,
                    0x20 => a *% src,
                    0x30 => if (src == 0) return error.BadProgram else a / src,
                    0x40 => a | src,
                    0x50 => a & src,
                    0x60 => if (src >= 32) 0 else a << @intCast(src),
                    0x70 => if (src >= 32) 0 else a >> @intCast(src),
                    0x80 => 0 -% a,
                    0x90 => if (src == 0) return error.BadProgram else a % src,
                    0xa0 => a ^ src,
                    else => return error.BadProgram,
                };
            },
            0x05 => { // JMP
                const off: usize = switch (i.code & 0xf0) {
                    0x00 => i.k,
                    0x10 => if (a == src) i.jt else i.jf,
                    0x20 => if (a > src) i.jt else i.jf,
                    0x30 => if (a >= src) i.jt else i.jf,
                    0x40 => if (a & src != 0) i.jt else i.jf,
                    else => return error.BadProgram,
                };
                if (pc + off >= prog.len) return error.BadProgram;
                pc += off;
            },
            0x06 => return switch (i.code & 0x18) { // RET
                0x00 => i.k,
                0x10 => a,
                else => error.BadProgram,
            },
            0x07 => switch (i.code & 0xf8) { // MISC
                0x00 => x = a,
                0x80 => a = x,
                else => return error.BadProgram,
            },
            else => unreachable,
        }
    }
}

// ── the referee ─────────────────────────────────────────────────────────────

fn word(a: seccomp.Action) u32 {
    return switch (a) {
        .kill_process => 0x8000_0000,
        .kill_thread => 0,
        .errno => |e| 0x0005_0000 | @as(u32, e),
        .trap => 0x0003_0000,
        .log => 0x7ffc_0000,
        .allow => 0x7fff_0000,
    };
}

/// libseccomp's restrictiveness order of actions (seccomp(2)'s precedence:
/// KILL_PROCESS > KILL_THREAD > TRAP > ERRNO > USER_NOTIF > TRACE > LOG >
/// ALLOW). Lower is more restrictive.
fn rank(w: u32) u32 {
    return switch (w & 0xffff_0000) {
        0x8000_0000 => 0,
        0x0000_0000 => 1,
        0x0003_0000 => 2,
        0x0005_0000 => 3,
        0x7ffc_0000 => 6,
        0x7fff_0000 => 7,
        else => unreachable,
    };
}

const Semantics = enum {
    /// This module's documentation: `.u32` reads the low word; first match.
    ours,
    /// libseccomp's: every compare is 64-bit (a `_32` datum zero-extended);
    /// of several matching rules, the most restrictive action.
    libseccomp,
};

fn condHolds(c: seccomp.ArgCmp, arg: u64, sem: Semantics) bool {
    const narrow = c.width == .u32;
    const x = if (narrow and sem == .ours) arg & 0xffff_ffff else arg;
    const v = if (narrow) c.value & 0xffff_ffff else c.value;
    const m = if (narrow) c.mask & 0xffff_ffff else c.mask;
    return switch (c.op) {
        .eq => x == v,
        .ne => x != v,
        .lt => x < v,
        .le => x <= v,
        .gt => x > v,
        .ge => x >= v,
        .masked_eq => x & m == v & m,
    };
}

fn model(rules: []const seccomp.Rule, default: seccomp.Action, d: Data, sem: Semantics) u32 {
    if (d.arch != audit_arch_x86_64) return word(.kill_process);
    if (sem == .ours and d.nr >= x32_bit) return word(.kill_process);
    var best: ?u32 = null;
    for (rules) |r| {
        if (@as(u32, @intCast(@backingInt(r.sysno))) != d.nr) continue;
        const all = for (r.when) |c| {
            if (!condHolds(c, d.args[c.arg], sem)) break false;
        } else true;
        if (!all) continue;
        const w = word(r.action);
        if (sem == .ours) return w;
        if (best == null or rank(w) < rank(best.?)) best = w;
    }
    return best orelse word(default);
}

// ── generation ──────────────────────────────────────────────────────────────

const Family = enum { single, same, mixed };

const Kind = enum { u32_width, precedence, x32, lib_refuses, lib_defect, lib_timeout };

var checks = std.EnumArray(Family, usize).initFill(0);
var failures = std.EnumArray(Family, usize).initFill(0);
var gaps = std.EnumArray(Kind, usize).initFill(0);
var refused: usize = 0;
var max_report: usize = 10;

/// Syscall numbers libseccomp knows on x86-64 (the table's dense part).
fn randomSys(rand: std.Random) linux.SYS {
    while (true) {
        const n = rand.intRangeAtMost(u32, 0, 334);
        if (std.enums.fromInt(linux.SYS, n)) |s| return s;
    }
}

fn randomAction(rand: std.Random) seccomp.Action {
    return switch (rand.uintLessThan(u8, 6)) {
        0 => .kill_process,
        1 => .kill_thread,
        2 => .trap,
        // libseccomp takes 1..4094; the kernel (and this module) 4095 too.
        3 => .{ .errno = rand.intRangeAtMost(u16, 1, seccomp.max_errno - 1) },
        4 => .log,
        else => .allow,
    };
}

fn interesting(rand: std.Random) u64 {
    return switch (rand.uintLessThan(u8, 8)) {
        0 => 0,
        1 => rand.uintLessThan(u64, 16),
        2 => 0xffff_ffff,
        3 => 0x1_0000_0000,
        4 => std.math.maxInt(u64),
        5 => @as(u64, rand.int(u32)) << 32,
        6 => rand.int(u32),
        else => rand.int(u64),
    };
}

fn randomCond(rand: std.Random, arg: u3) seccomp.ArgCmp {
    const op = rand.enumValue(seccomp.Op);
    var c: seccomp.ArgCmp = .{ .arg = arg, .op = op, .width = rand.enumValue(seccomp.Width), .value = interesting(rand) };
    if (op == .masked_eq) {
        c.mask = interesting(rand);
        // Mostly a value inside the mask (the useful shape); sometimes not.
        if (rand.uintLessThan(u8, 4) != 0) c.value &= c.mask;
    }
    return c;
}

/// Values of argument `i` aimed at the conditions on it.
fn edgeArg(rand: std.Random, conds: []const seccomp.ArgCmp, i: usize) u64 {
    var hits: [8]u64 = undefined;
    var n: usize = 0;
    for (conds) |c| if (c.arg == i and n < hits.len) {
        hits[n] = c.value;
        n += 1;
    };
    if (n == 0 or rand.uintLessThan(u8, 5) == 0) return interesting(rand);
    const v = hits[rand.uintLessThan(usize, n)];
    return switch (rand.uintLessThan(u8, 7)) {
        0 => v,
        1 => v +% 1,
        2 => v -% 1,
        3 => v ^ (@as(u64, rand.int(u32)) << 32), // other high word
        4 => v & 0xffff_ffff, // high word cleared
        5 => v ^ (@as(u64, 1) << rand.int(u6)),
        else => v | 0xffff_ffff_0000_0000,
    };
}

const Case = struct {
    rules: []seccomp.Rule,
    default: seccomp.Action,
    family: Family,
};

const Ctx = struct {
    gpa: std.mem.Allocator,
    peer: *Peer,
    prng: std.Random.DefaultPrng,
    n_inputs: usize,
    exe: []const u8,
};

fn report(comptime fmt: []const u8, args: anytype) void {
    if (max_report == 0) return;
    max_report -= 1;
    std.debug.print(fmt ++ "\n", args);
}

/// The case's rules for syscall `nr` (all of them for `null`).
fn dumpRules(c: Case, nr: ?u32) void {
    if (max_report == 0) return;
    std.debug.print("    default {any}, {d} rules\n", .{ c.default, c.rules.len });
    for (c.rules, 0..) |r, i| {
        if (nr) |n| if (@as(u32, @intCast(@backingInt(r.sysno))) != n) continue;
        std.debug.print("    #{d} {t} -> {any} when {any}\n", .{ i, r.sysno, r.action, r.when });
    }
}

fn oneCase(ctx: *Ctx, c: Case) !void {
    const gpa = ctx.gpa;
    const rand = ctx.prng.random();
    var ours: [2][]Insn = undefined;
    for (&ours, [_]seccomp.Dispatch{ .linear, .tree }) |*o, disp| {
        o.* = try seccomp.buildRulesWith(gpa, c.rules, c.default, .{ .dispatch = disp });
    }
    defer for (ours) |o| gpa.free(o);
    var theirs: [2][]Insn = undefined;
    var n_theirs: usize = 0;
    defer for (theirs[0..n_theirs]) |t| gpa.free(t);
    for ([_]u8{ 1, 2 }) |opt| {
        const r = ctx.peer.build(c.rules, c.default, opt) catch |e| switch (e) {
            error.EndOfStream, error.WriteFailed => {
                ctx.peer.stop();
                try ctx.peer.spawn(ctx.exe);
                gaps.getPtr(.lib_timeout).* += 1;
                return;
            },
            else => return e,
        };
        switch (r) {
            .ok => |raw| {
                defer gpa.free(raw);
                theirs[n_theirs] = try parseProgram(gpa, raw);
                n_theirs += 1;
            },
            .err => |e| {
                if ((c.family != .single and e.rc == -17) or (c.family == .mixed and e.rc == -22)) {
                    gaps.getPtr(.lib_refuses).* += 1;
                    return;
                }
                // libseccomp refuses what this module builds: a finding unless
                // explained; print it and count.
                refused += 1;
                failures.getPtr(c.family).* += 1;
                report("MISMATCH {t}: libseccomp refused at step {d} rc {d} (optimize {d})", .{ c.family, e.step, e.rc, opt });
                dumpRules(c, null);
                return;
            },
        }
    }

    for (0..ctx.n_inputs) |_| {
        var d: Data = .{ .nr = 0, .arch = audit_arch_x86_64, .args = undefined };
        const pick = c.rules[rand.uintLessThan(usize, c.rules.len)];
        const base_nr: u32 = @intCast(@backingInt(pick.sysno));
        d.nr = switch (rand.uintLessThan(u8, 12)) {
            0 => rand.uintLessThan(u32, 500),
            1 => base_nr +% 1,
            2 => base_nr -% 1,
            3 => base_nr | x32_bit,
            4 => 0xffff_ffff,
            else => base_nr,
        };
        d.arch = switch (rand.uintLessThan(u8, 16)) {
            0 => audit_arch_i386,
            1 => rand.int(u32),
            else => audit_arch_x86_64,
        };
        for (&d.args, 0..) |*a, i| a.* = edgeArg(rand, pick.when, i);

        checks.getPtr(c.family).* += 1;
        const want = model(c.rules, c.default, d, .ours);
        for (ours, [_][]const u8{ "linear", "tree" }) |o, name| {
            const got = run(o, d) catch {
                failures.getPtr(c.family).* += 1;
                report("MISMATCH {t}: this module's {s} program is not a valid filter", .{ c.family, name });
                dumpRules(c, null);
                return;
            };
            if (got != want) {
                failures.getPtr(c.family).* += 1;
                report("MISMATCH {t}: ours ({s}) {x} != model {x} on nr {d} arch {x} args {any}", .{ c.family, name, got, want, d.nr, d.arch, d.args });
                dumpRules(c, d.nr);
                return;
            }
        }
        const lib_want = model(c.rules, c.default, d, .libseccomp);
        for (theirs[0..n_theirs], 1..) |t, opt| {
            const got = run(t, d) catch {
                failures.getPtr(c.family).* += 1;
                report("MISMATCH {t}: libseccomp's program (optimize {d}) does not run here", .{ c.family, opt });
                return;
            };
            if (got == want) continue;
            if (got != lib_want) {
                if (ambiguous(c.rules, d)) {
                    gaps.getPtr(.precedence).* += 1;
                    continue;
                }
                gaps.getPtr(.lib_defect).* += 1;
                report("LIB-DEFECT {t}: libseccomp (optimize {d}) {x}, ours {x}, libseccomp model {x} on nr {x} arch {x} args {any} (programs: ours {d}, libseccomp {d})", .{ c.family, opt, got, want, lib_want, d.nr, d.arch, d.args, ours[0].len, t.len });
                dumpRules(c, d.nr);
                continue;
            }
            // Explained by a documented difference: name which one.
            const kind: Kind = if (d.arch == audit_arch_x86_64 and d.nr >= x32_bit)
                .x32
            else if (differsByWidth(c.rules, d))
                .u32_width
            else
                .precedence;
            gaps.getPtr(kind).* += 1;
            continue;
        }
    }
}

/// True when two rules of the input's syscall with different actions both
/// match under libseccomp's reading of the conditions.
fn ambiguous(rules: []const seccomp.Rule, d: Data) bool {
    var first: ?u32 = null;
    for (rules) |r| {
        if (@as(u32, @intCast(@backingInt(r.sysno))) != d.nr) continue;
        const all = for (r.when) |c| {
            if (!condHolds(c, d.args[c.arg], .libseccomp)) break false;
        } else true;
        if (!all) continue;
        const w = word(r.action);
        if (first) |f| {
            if (f != w) return true;
        } else first = w;
    }
    return false;
}

/// True when some `.u32` condition of the input's syscall reads differently
/// under the two semantics.
fn differsByWidth(rules: []const seccomp.Rule, d: Data) bool {
    for (rules) |r| {
        if (@as(u32, @intCast(@backingInt(r.sysno))) != d.nr) continue;
        for (r.when) |c| if (c.width == .u32 and condHolds(c, d.args[c.arg], .ours) != condHolds(c, d.args[c.arg], .libseccomp)) return true;
    }
    return false;
}

fn family(ctx: *Ctx, f: Family, cases: usize) !void {
    const gpa = ctx.gpa;
    const rand = ctx.prng.random();
    var rules: std.ArrayList(seccomp.Rule) = .empty;
    defer rules.deinit(gpa);
    var conds: std.ArrayList(seccomp.ArgCmp) = .empty;
    defer conds.deinit(gpa);
    for (0..cases) |_| {
        rules.clearRetainingCapacity();
        conds.clearRetainingCapacity();
        const default = randomAction(rand);
        var pool: [12]linux.SYS = undefined;
        const n_pool = rand.intRangeAtMost(usize, 1, pool.len);
        for (pool[0..n_pool]) |*p| p.* = randomSys(rand);
        var pool_action: [12]seccomp.Action = undefined;
        for (&pool_action) |*a| a.* = randomAction(rand);
        const n_rules = if (f == .single) n_pool else rand.intRangeAtMost(usize, 1, 24);
        var cond_starts: [25]usize = undefined;
        var used: [12]linux.SYS = undefined;
        var n_used: usize = 0;
        var count: usize = 0;
        for (0..n_rules) |ri| {
            const pi = if (f == .single) ri else rand.uintLessThan(usize, n_pool);
            const sys = pool[pi];
            if (f == .single) {
                if (std.mem.indexOfScalar(linux.SYS, used[0..n_used], sys) != null) continue;
                used[n_used] = sys;
                n_used += 1;
            }
            var action = if (f == .mixed) randomAction(rand) else pool_action[pi];
            // libseccomp refuses a rule whose action is the default (EACCES);
            // in this module such a rule changes nothing. Skip both.
            if (std.meta.eql(action, default)) {
                if (f != .mixed) continue;
                action = if (default == .allow) .kill_process else .allow;
            }
            // libseccomp compares each argument at most once per rule.
            var args_left: u8 = 0b111111;
            cond_starts[count] = conds.items.len;
            for (0..rand.uintLessThan(usize, 5)) |_| {
                const arg: u3 = rand.uintLessThan(u3, 6);
                if (args_left & (@as(u8, 1) << arg) == 0) continue;
                args_left &= ~(@as(u8, 1) << arg);
                try conds.append(gpa, randomCond(rand, arg));
            }
            try rules.append(gpa, .{ .sysno = sys, .action = action });
            count += 1;
        }
        if (count == 0) continue;
        cond_starts[count] = conds.items.len;
        for (rules.items, 0..) |*r, i| r.when = conds.items[cond_starts[i]..cond_starts[i + 1]];
        try oneCase(ctx, .{ .rules = rules.items, .default = default, .family = f });
    }
}

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    var seed: u64 = 1;
    var scale: usize = 1;
    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--seed")) {
            seed = try std.fmt.parseInt(u64, args.next() orelse return error.MissingArgument, 10);
        } else if (std.mem.eql(u8, a, "--scale")) {
            scale = try std.fmt.parseInt(usize, args.next() orelse return error.MissingArgument, 10);
        } else if (std.mem.eql(u8, a, "--all")) {
            max_report = std.math.maxInt(usize);
        } else {
            std.debug.print("usage: interop-sandbox [--seed N] [--scale N] [--all]\n", .{});
            return 2;
        }
    }

    const exe = try buildOracle(gpa, io);
    var peer: Peer = .{ .gpa = gpa, .io = io, .child = undefined };
    try peer.spawn(exe);
    defer peer.stop();
    const v = try peer.version();
    defer freeReply(gpa, v);
    if (v != .ok) return error.NoReference;
    std.debug.print("interop-sandbox: libseccomp {s}, seed {d}, scale {d}\n", .{ v.ok, seed, scale });

    var ctx: Ctx = .{ .gpa = gpa, .peer = &peer, .prng = .init(seed), .n_inputs = 64, .exe = exe };
    for (std.enums.values(Family)) |f| try family(&ctx, f, 400 * scale);

    var total_fail: usize = 0;
    std.debug.print("\n{s:<8} {s:>8} {s:>9}\n", .{ "family", "checks", "mismatch" });
    for (std.enums.values(Family)) |f| {
        std.debug.print("{t:<8} {d:>8} {d:>9}\n", .{ f, checks.get(f), failures.get(f) });
        total_fail += failures.get(f);
    }
    std.debug.print("gaps (documented differences, libseccomp's own semantics held):", .{});
    for (std.enums.values(Kind)) |k| std.debug.print(" {t} {d}", .{ k, gaps.get(k) });
    std.debug.print("\n", .{});
    if (total_fail > 0) {
        std.debug.print("\ninterop-sandbox: {d} MISMATCH(es) against libseccomp -- NOT OK\n", .{total_fail});
        return 1;
    }
    std.debug.print("\ninterop-sandbox: OK\n", .{});
    return 0;
}
