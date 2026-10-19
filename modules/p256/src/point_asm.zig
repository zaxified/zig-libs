// SPDX-License-Identifier: MIT

//! Point formulas as ONE asm block each, generated at comptime from a field
//! program over a scratch frame (amd64 MULX/ADX only; `fast_core.supported`).
//!
//! Why: the Jacobian doubling chain that dominates ECDH was latency/glue
//! bound, not operation bound (SPEC "After the 2026-10-13 pass"). Through
//! `field.Fe` every multiply is its own asm statement taking its operands by
//! pointer, so LLVM parks each value in the frame, copies the input point
//! twice and keeps a call frame per doubling — 350 of `Jac.dbl`'s 1 373
//! instructions were stack moves (perf annotate, 2026-10-14). Here a formula
//! is a list of `Op`s over 32-byte slots of a caller-owned frame; each op
//! reads its operands straight from the frame (`MULX`/`ADC` memory operands)
//! and stores its result to its slot, which is the shape of OpenSSL's
//! nistz256 point routines.
//!
//! The field ops are the SAME text as `fast_core`'s Montgomery core (the CIOS
//! multiply, the dedicated square + REDC tail), rebased onto the frame:
//! `rsi` holds the frame base for the whole block, so the square's reduce
//! constant moves from `rsi` to `rdi`. add/sub are `fast_core.addRegs` /
//! `subRegs` with a memory second operand. So the arithmetic is unchanged —
//! straight-line, no branch, no CMOV, DIT-set instructions only — and the
//! Zig formula in `group.zig` (over `field.Fe`) stays the oracle: the
//! differential there pins every program to it bit for bit.
//!
//! Every slot must hold a canonical (`< p`) Montgomery-form value before an
//! op reads it, as `field.Fe` requires. A destination may alias an operand:
//! each op reads all of its inputs before its first store.

const std = @import("std");
const fast_core = @import("fast_core.zig");

pub const supported = fast_core.supported;

pub const Kind = enum { mul, sq, add, sub, half };

/// One field operation: `slot[d] = slot[a] ∘ slot[b]` (`b` unused by `sq`).
pub const Op = struct {
    kind: Kind,
    d: u8,
    a: u8,
    b: u8 = 0,
};

pub fn mul(d: u8, a: u8, b: u8) Op {
    return .{ .kind = .mul, .d = d, .a = a, .b = b };
}
pub fn sq(d: u8, a: u8) Op {
    return .{ .kind = .sq, .d = d, .a = a };
}
pub fn add(d: u8, a: u8, b: u8) Op {
    return .{ .kind = .add, .d = d, .a = a, .b = b };
}
pub fn sub(d: u8, a: u8, b: u8) Op {
    return .{ .kind = .sub, .d = d, .a = a, .b = b };
}
pub fn half(d: u8, a: u8) Op {
    return .{ .kind = .half, .d = d, .a = a };
}

/// Highest slot index a program touches, plus one.
pub fn slotCount(comptime ops: []const Op) usize {
    var n: usize = 0;
    for (ops) |op| n = @max(n, @as(usize, @max(op.d, op.a, op.b)) + 1);
    return n;
}

/// Rewrite every `N(%%reg)` / `(%%reg)` memory operand of `text` to
/// `N+off(%%rsi)`. Register operands (`%%reg` without parentheses) are left
/// alone.
fn rebase(comptime text: []const u8, comptime reg: []const u8, comptime off: usize) []const u8 {
    @setEvalBranchQuota(200_000);
    const needle = "(%%" ++ reg ++ ")";
    comptime var out: []const u8 = "";
    comptime var i: usize = 0;
    inline while (std.mem.findPos(u8, text, i, needle)) |at| {
        comptime var start = at;
        while (start > i and std.ascii.isDigit(text[start - 1])) start -= 1;
        const disp: usize = if (start == at) 0 else std.fmt.parseInt(usize, text[start..at], 10) catch unreachable;
        out = out ++ text[i..start] ++ std.fmt.comptimePrint("{d}(%%rsi)", .{disp + off});
        i = at + needle.len;
    }
    return out ++ text[i..];
}

fn slotOff(comptime s: u8) usize {
    return @as(usize, s) * 32;
}

fn store(comptime d: u8, comptime r: [4][]const u8) []const u8 {
    const o = slotOff(d);
    return std.fmt.comptimePrint(
        \\ movq %%{s}, {d}(%%rsi)
        \\ movq %%{s}, {d}(%%rsi)
        \\ movq %%{s}, {d}(%%rsi)
        \\ movq %%{s}, {d}(%%rsi)
        \\
    , .{ r[0], o, r[1], o + 8, r[2], o + 16, r[3], o + 24 });
}

/// What `program` decided for one op: where its `a` operand already sits
/// (`fwd`: the registers the previous op left its result in, which is
/// slot `a`) and whether its result must reach the frame (`keep`: some
/// later op reads the slot from memory, or it is a program output).
const Plan = struct {
    fwd: ?[4][]const u8 = null,
    keep: bool = true,
};

const out_mul = [4][]const u8{ "r12", "r13", "r8", "r9" };
const out_r8 = [4][]const u8{ "r8", "r9", "r10", "r11" };

fn storeIf(comptime keep: bool, comptime d: u8, comptime r: [4][]const u8) []const u8 {
    return if (keep) store(d, r) else "";
}

/// `a` into r8..r11: four loads, or nothing / four register moves when the
/// previous op left it in registers.
fn loadA(comptime a: u8, comptime fwd: ?[4][]const u8) []const u8 {
    if (fwd) |r| {
        if (std.mem.eql(u8, r[0], "r8")) return "";
        // (r12, r13, r8, r9) → (r8, r9, r10, r11): the overlapping limbs first.
        return std.fmt.comptimePrint(
            \\ movq %%{s}, %%r11
            \\ movq %%{s}, %%r10
            \\ movq %%{s}, %%r9
            \\ movq %%{s}, %%r8
            \\
        , .{ r[3], r[2], r[1], r[0] });
    }
    const o = slotOff(a);
    return std.fmt.comptimePrint(
        \\ movq {d}(%%rsi), %%r8
        \\ movq {d}(%%rsi), %%r9
        \\ movq {d}(%%rsi), %%r10
        \\ movq {d}(%%rsi), %%r11
        \\
    , .{ o, o + 8, o + 16, o + 24 });
}

/// The four `b` operands of an add/sub: frame memory, or r8..r11 themselves
/// when `b` is the same slot as `a` (a doubling).
fn bOps(comptime op: Op) [4][]const u8 {
    if (op.a == op.b) return .{ "%%r8", "%%r9", "%%r10", "%%r11" };
    const o = slotOff(op.b);
    return .{
        std.fmt.comptimePrint("{d}(%%rsi)", .{o}),
        std.fmt.comptimePrint("{d}(%%rsi)", .{o + 8}),
        std.fmt.comptimePrint("{d}(%%rsi)", .{o + 16}),
        std.fmt.comptimePrint("{d}(%%rsi)", .{o + 24}),
    };
}

fn emitMul(comptime op: Op, comptime plan: Plan) []const u8 {
    // CIOS: a at rsi, b at rbx in the original; both live in the frame here.
    // Its output is (r12, r13, r8, r9).
    const t = rebase(rebase(fast_core.mont_mul_cios, "rsi", slotOff(op.a)), "rbx", slotOff(op.b));
    return t ++ "\n" ++ storeIf(plan.keep, op.d, out_mul);
}

fn emitSq(comptime op: Op, comptime plan: Plan) []const u8 {
    // The reduce tail has no memory operands; its constant register moves
    // from rsi (the frame base here) to rdi.
    const prod = rebase(fast_core.sq_product, "rsi", slotOff(op.a));
    const red = comptime blk: {
        @setEvalBranchQuota(200_000);
        var buf: [fast_core.mont_reduce_core.len]u8 = undefined;
        _ = std.mem.replace(u8, fast_core.mont_reduce_core, "%%rsi", "%%rdi", &buf);
        const final = buf;
        break :blk &final;
    };
    return prod ++ "\n" ++ red ++ "\n" ++ storeIf(plan.keep, op.d, out_r8);
}

fn emitAdd(comptime op: Op, comptime plan: Plan) []const u8 {
    const b = bOps(op);
    return loadA(op.a, plan.fwd) ++ std.fmt.comptimePrint(
        \\ xorl %%eax, %%eax
        \\ addq {s}, %%r8
        \\ adcq {s}, %%r9
        \\ adcq {s}, %%r10
        \\ adcq {s}, %%r11
        \\ adcq $0, %%rax
        \\ movl $4294967295, %%ecx
        \\ movabsq $0xffffffff00000001, %%rdx
        \\ subq $-1, %%r8
        \\ sbbq %%rcx, %%r9
        \\ sbbq $0, %%r10
        \\ sbbq %%rdx, %%r11
        \\ sbbq $0, %%rax
        \\ andq %%rax, %%rcx
        \\ andq %%rax, %%rdx
        \\ addq %%rax, %%r8
        \\ adcq %%rcx, %%r9
        \\ adcq $0, %%r10
        \\ adcq %%rdx, %%r11
        \\
    , .{ b[0], b[1], b[2], b[3] }) ++ storeIf(plan.keep, op.d, out_r8);
}

fn emitSub(comptime op: Op, comptime plan: Plan) []const u8 {
    const b = bOps(op);
    return loadA(op.a, plan.fwd) ++ std.fmt.comptimePrint(
        \\ subq {s}, %%r8
        \\ sbbq {s}, %%r9
        \\ sbbq {s}, %%r10
        \\ sbbq {s}, %%r11
        \\ sbbq %%rax, %%rax
        \\ movq %%rax, %%rcx
        \\ shrq $32, %%rcx
        \\ movabsq $0xffffffff00000001, %%rdx
        \\ andq %%rax, %%rdx
        \\ addq %%rax, %%r8
        \\ adcq %%rcx, %%r9
        \\ adcq $0, %%r10
        \\ adcq %%rdx, %%r11
        \\
    , .{ b[0], b[1], b[2], b[3] }) ++ storeIf(plan.keep, op.d, out_r8);
}

fn emitHalf(comptime op: Op, comptime plan: Plan) []const u8 {
    // a/2 mod p = (a + (a odd ? p : 0)) / 2: add p masked by the low bit
    // into a 257-bit value, then shift the five limbs right by one (`SHRD`,
    // off the flag ports). (a + p)/2 < p and a/2 < p, so the result is
    // canonical.
    return loadA(op.a, plan.fwd) ++
        \\ movl $1, %%eax
        \\ andq %%r8, %%rax
        \\ negq %%rax
        \\ movq %%rax, %%rcx
        \\ shrq $32, %%rcx
        \\ movabsq $0xffffffff00000001, %%rdx
        \\ andq %%rax, %%rdx
        \\ movl $0, %%r12d
        \\ addq %%rax, %%r8
        \\ adcq %%rcx, %%r9
        \\ adcq $0, %%r10
        \\ adcq %%rdx, %%r11
        \\ adcq $0, %%r12
        \\ shrdq $1, %%r9, %%r8
        \\ shrdq $1, %%r10, %%r9
        \\ shrdq $1, %%r11, %%r10
        \\ shrdq $1, %%r12, %%r11
        \\
    ++ storeIf(plan.keep, op.d, out_r8);
}

fn outRegs(comptime k: Kind) [4][]const u8 {
    return if (k == .mul) out_mul else out_r8;
}

/// Does op `o` read slot `s` from the frame (given whether its `a` is
/// forwarded)?
fn readsMem(comptime o: Op, comptime fwd: bool, comptime s: u8) bool {
    return switch (o.kind) {
        .mul => o.a == s or o.b == s,
        .sq => o.a == s,
        .add, .sub => (!fwd and o.a == s) or (o.b == s and o.b != o.a),
        .half => !fwd and o.a == s,
    };
}

/// The asm text of a whole program whose results are slots `0 .. outputs`.
///
/// Register forwarding: an add/sub/half whose `a` is the previous op's
/// destination takes it from the registers that op left it in (an add
/// whose `b` is, swaps its operands); a result reaches the frame only when
/// a later op reads that slot from memory before rewriting it, or it is an
/// output.
pub fn program(comptime ops_in: []const Op, comptime outputs: u8) []const u8 {
    @setEvalBranchQuota(1_000_000);
    comptime var ops: [ops_in.len]Op = ops_in[0..ops_in.len].*;
    comptime var fwd: [ops.len]bool = @splat(false);
    inline for (1..ops.len) |i| {
        const prev = ops[i - 1].d;
        switch (ops[i].kind) {
            .add => {
                if (ops[i].a != prev and ops[i].b == prev) {
                    const t = ops[i].a;
                    ops[i].a = ops[i].b;
                    ops[i].b = t;
                }
                fwd[i] = ops[i].a == prev;
            },
            .sub, .half => fwd[i] = ops[i].a == prev,
            .mul, .sq => {},
        }
    }
    comptime var text: []const u8 = "";
    inline for (ops, 0..) |op, i| {
        const keep = comptime blk: {
            for (ops[i + 1 ..], fwd[i + 1 ..]) |later, lf| {
                if (readsMem(later, lf, op.d)) break :blk true;
                if (later.d == op.d) break :blk false;
            }
            break :blk op.d < outputs;
        };
        const plan = Plan{
            .fwd = if (fwd[i]) outRegs(ops[i - 1].kind) else null,
            .keep = keep,
        };
        text = text ++ switch (op.kind) {
            .mul => emitMul(op, plan),
            .sq => emitSq(op, plan),
            .add => emitAdd(op, plan),
            .sub => emitSub(op, plan),
            .half => emitHalf(op, plan),
        } ++ "\n";
    }
    return text;
}

/// Run `ops` over `frame` (slot `i` = `frame[i]`); slots `0 .. outputs`
/// hold the results afterwards, the others are scratch.
pub inline fn run(comptime ops: []const Op, comptime outputs: u8, frame: *[slotCount(ops)][4]u64) void {
    if (comptime !supported) unreachable;
    const text = comptime program(ops, outputs);
    asm volatile (text
        :
        : [f] "{rsi}" (frame),
        : .{ .rax = true, .rbx = true, .rcx = true, .rdx = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .cc = true, .memory = true });
}

// ── the programs ─────────────────────────────────────────────────────────────

/// Jacobian doubling, `a = −3`, 4M + 4S with 11 add/sub/half — nistz256's
/// operation order (`Z3 = 2·Y·Z`, `S = 4·X·Y²` from `(2Y)²`, `8·Y⁴` as half
/// of `(2Y)⁴`) rather than dbl-2001-b's 3M + 5S + 16 add/sub: a square costs
/// a multiply here, and the add/sub chains are what load the carry ports.
/// The same polynomials as `group.Jac.dblFormula`, so bit-identical. In place
/// on X = 0, Y = 1, Z = 2; scratch 3..7.
pub const jac_dbl = blk: {
    const X = 0;
    const Y = 1;
    const Z = 2;
    const zz = 3;
    const s = 4;
    const m = 5;
    const t = 6;
    const u = 7;
    break :blk [_]Op{
        add(s, Y, Y), // 2Y
        sq(zz, Z),
        sq(s, s), // 4Y²
        mul(Z, Y, Z),
        add(Z, Z, Z), // z3 = 2·Y·Z
        add(t, X, zz),
        sub(u, X, zz),
        mul(m, t, u),
        add(t, m, m),
        add(m, t, m), // M = 3·(X + Z²)·(X − Z²)
        sq(t, s), // 16Y⁴
        mul(s, s, X), // S = 4·X·Y²
        half(Y, t), // 8Y⁴ (Y is dead: z3 is done)
        sq(X, m),
        add(u, s, s),
        sub(X, X, u), // x3 = M² − 2S
        sub(s, s, X),
        mul(s, m, s),
        sub(Y, s, Y), // y3 = M·(S − x3) − 8Y⁴
    };
};

/// Mixed addition, `Q` affine, WITHOUT the exceptional cases (EFD
/// madd-2004-hmv, 8M + 3S with 7 add/sub — the shape of nistz256's
/// `point_add_affine`) — `group.Jac.addMixedCtFormula`, in place on
/// X = 0, Y = 1, Z = 2 with `Q = (qx, qy)` in slots 3, 4; scratch 5..8.
pub const jac_add_mixed = blk: {
    const X = 0;
    const Y = 1;
    const Z = 2;
    const qx = 3;
    const qy = 4;
    const t1 = 5;
    const t2 = 6;
    const t3 = 7;
    const t4 = 8;
    break :blk [_]Op{
        sq(t1, Z),
        mul(t2, t1, Z),
        mul(t1, t1, qx), // U2
        mul(t2, t2, qy), // S2
        sub(t1, t1, X), // H = U2 − X
        sub(t2, t2, Y), // R = S2 − Y
        mul(Z, Z, t1), // z3 = Z·H
        sq(t4, t1), // H²
        mul(t3, t4, t1), // H³
        mul(t4, t4, X), // X·H²
        add(t1, t4, t4),
        sq(X, t2),
        sub(X, X, t1),
        sub(X, X, t3), // x3 = R² − 2·X·H² − H³
        sub(t4, t4, X),
        mul(t4, t4, t2),
        mul(t3, t3, Y),
        sub(Y, t4, t3), // y3 = R·(X·H² − x3) − Y·H³
    };
};
