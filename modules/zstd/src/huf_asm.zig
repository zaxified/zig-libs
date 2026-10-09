// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! The inner loops of the four-stream Huffman fast decoders in assembly
//! (port of libzstd lib/decompress/huf_decompress_amd64.S, v1.5.7): x86-64
//! with BMI2, LLVM builds only. Everywhere else `huf_dec.zig` runs its Zig
//! loops, which compute the same bytes.
//!
//! Why assembly: the X2 loop keeps four bit containers, four output cursors,
//! the table and three scratch registers live across 20 symbol decodes, and
//! reads a cell's bit count with a load of its own so that the next lookup
//! of a stream waits for one shift and one load. LLVM spills that loop to the
//! stack and decodes x-ray's literals in ~1.2× libzstd's cycles (measured
//! 2026-10-09; two Zig rewrites did not close it).
//!
//! Only the loop body is here: `huf_dec.zig` computes the iteration limit
//! and checks the cursors exactly as before, then hands over pointers, and
//! the assembly runs `do { 5 symbols per stream; reload } while (op3 <
//! olimit)` -- `HUF_decompress4X{1,2}_usingDTable_internal_fast_c_loop`'s
//! inner loop, which writes the same bytes and leaves the same cursors.
//!
//! Registers differ from libzstd's: `rbp` stays the frame's, so the input
//! cursors live in `Args` and are touched once per stream per 20 symbols (as
//! libzstd does with three of them). The output cursors are `rsi`, `rbx`,
//! `rcx`, `rdx`: X1 stores a byte from `%ah`, which no instruction with a REX
//! prefix (an r8..r15 base) can encode.

const std = @import("std");
const builtin = @import("builtin");

/// Whether this build has the assembly. LLVM only: the self-hosted backend
/// (Debug edit loop) takes the Zig loop.
pub const supported = builtin.zig_backend == .stage2_llvm and switch (builtin.cpu.arch) {
    .x86_64 => std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2),
    else => false,
};

/// The loop's state in and out, addresses rather than indices. Field
/// offsets are fixed (asserted below): the assembly reads them by number.
pub const Args = extern struct {
    ip: [4]usize, // 0   input cursor of each stream (reads the 8 bytes at it)
    op: [4]usize, // 32  output cursor of each stream
    bits: [4]u64, // 64  bit containers
    dt: usize, // 96     the decoding table's cells
    olimit: usize, // 104 the loop runs while op[3] < olimit
};

comptime {
    // Only where the assembly is built: elsewhere `usize` may be 32 bits.
    if (supported) {
        for (.{ .{ "ip", 0 }, .{ "op", 32 }, .{ "bits", 64 }, .{ "dt", 96 }, .{ "olimit", 104 } }) |f| {
            if (@offsetOf(Args, f[0]) != f[1]) @compileError("huf_asm.Args." ++ f[0] ++ " moved");
        }
    }
}

/// Test hook: counts the loop entries, so a test can tell that the
/// assembly ran. A constant outside tests.
pub const entries = if (builtin.is_test) struct {
    pub var n: usize = 0;
} else struct {
    pub const n: usize = 0;
};

// rdi = args; op0..3 = rsi rbx rcx rdx; bits0..3 = r8 r9 r10 r11;
// r12 = table; rax r13 r14 scratch.
const op_reg = [4][]const u8{ "rsi", "rbx", "rcx", "rdx" };
const bits_reg = [4][]const u8{ "r8", "r9", "r10", "r11" };

fn load() []const u8 {
    comptime var s: []const u8 = "";
    inline for (0..4) |n| {
        s = s ++ std.fmt.comptimePrint(" movq {d}(%%rdi), %%{s}\n movq {d}(%%rdi), %%{s}\n", .{ 32 + 8 * n, op_reg[n], 64 + 8 * n, bits_reg[n] });
    }
    return s ++ " movq 96(%%rdi), %%r12\n";
}

fn store() []const u8 {
    comptime var s: []const u8 = "";
    inline for (0..4) |n| {
        s = s ++ std.fmt.comptimePrint(" movq %%{s}, {d}(%%rdi)\n movq %%{s}, {d}(%%rdi)\n", .{ op_reg[n], 32 + 8 * n, bits_reg[n], 64 + 8 * n });
    }
    return s;
}

/// `RELOAD_BITS`: ctz = tzcnt(bits) (bits holds a set marker bit, never 0);
/// ip -= ctz >> 3; bits = read64(ip) | 1, shifted left by ctz & 7.
/// `op_step`: X1 advances its cursor by the 5 bytes just written here.
fn reload(n: usize, op_step: usize) []const u8 {
    const b = bits_reg[n];
    const step = if (op_step == 0) "" else std.fmt.comptimePrint(" leaq {d}(%%{s}), %%{s}\n", .{ op_step, op_reg[n], op_reg[n] });
    return std.fmt.comptimePrint(
        \\ tzcntq %%{[b]s}, %%{[b]s}
        \\ movq %%{[b]s}, %%rax
        \\ andq $7, %%rax
        \\ shrq $3, %%{[b]s}
        \\{[step]s}
        \\ movq {[ip]d}(%%rdi), %%r13
        \\ subq %%{[b]s}, %%r13
        \\ movq %%r13, {[ip]d}(%%rdi)
        \\ movq (%%r13), %%{[b]s}
        \\ orq $1, %%{[b]s}
        \\ shlxq %%rax, %%{[b]s}, %%{[b]s}
        \\
    , .{ .b = b, .step = step, .ip = 8 * n });
}

/// X1 cell (u16): the byte in bits 8..15, the bit count in bits 0..5 --
/// `shlx` reads only the low 6 bits of its count, so the cell is the count.
fn decodeX1(n: usize, idx: usize) []const u8 {
    return std.fmt.comptimePrint(
        \\ rorxq $53, %%{[b]s}, %%rax
        \\ andl $0x7FF, %%eax
        \\ movzwl (%%r12,%%rax,2), %%eax
        \\ shlxq %%rax, %%{[b]s}, %%{[b]s}
        \\ movb %%ah, {[idx]d}(%%{[o]s})
        \\
    , .{ .b = bits_reg[n], .o = op_reg[n], .idx = idx });
}

/// X2 cell (`HUF_DEltX2`, 4 bytes): the one or two bytes in 0..15, the bit
/// count in byte 2, how many bytes in byte 3.
fn decodeX2(n: usize) []const u8 {
    return std.fmt.comptimePrint(
        \\ movq %%{[b]s}, %%rax
        \\ shrq $53, %%rax
        \\ movzwl (%%r12,%%rax,4), %%r13d
        \\ movzbl 2(%%r12,%%rax,4), %%r14d
        \\ movzbl 3(%%r12,%%rax,4), %%eax
        \\ movw %%r13w, (%%{[o]s})
        \\ shlxq %%r14, %%{[b]s}, %%{[b]s}
        \\ addq %%rax, %%{[o]s}
        \\
    , .{ .b = bits_reg[n], .o = op_reg[n] });
}

fn body(comptime x2: bool) []const u8 {
    comptime var s: []const u8 = load() ++ " .p2align 4\n 1:\n";
    inline for (0..5) |idx| inline for (0..4) |n| {
        s = s ++ if (x2) decodeX2(n) else decodeX1(n, idx);
    };
    inline for (0..4) |n| s = s ++ reload(n, if (x2) 0 else 5);
    return s ++ " cmpq %%rdx, 104(%%rdi)\n ja 1b\n" ++ store();
}

const x1_body = body(false);
const x2_body = body(true);

/// `HUF_decompress4X1_usingDTable_internal_fast_asm_loop`'s inner loop.
pub fn loopX1(a: *Args) void {
    if (builtin.is_test) entries.n += 1;
    asm volatile (x1_body
        :
        : [a] "{rdi}" (a),
        : .{ .rax = true, .rbx = true, .rcx = true, .rdx = true, .rsi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .cc = true, .memory = true });
}

/// `HUF_decompress4X2_usingDTable_internal_fast_asm_loop`'s inner loop.
pub fn loopX2(a: *Args) void {
    if (builtin.is_test) entries.n += 1;
    asm volatile (x2_body
        :
        : [a] "{rdi}" (a),
        : .{ .rax = true, .rbx = true, .rcx = true, .rdx = true, .rsi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .cc = true, .memory = true });
}
