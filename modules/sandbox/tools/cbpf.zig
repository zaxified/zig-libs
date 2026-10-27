// SPDX-License-Identifier: MIT

//! Classic BPF as the kernel runs a seccomp filter, for the tools: the
//! interop oracle (`interop.zig`) runs every program through `run`, and the
//! bench (`bench.zig`) counts the instructions a syscall costs with it.

const std = @import("std");
const sandbox = @import("sandbox");

pub const audit_arch_x86_64: u32 = 62 | 0x8000_0000 | 0x4000_0000;

pub const Insn = sandbox.SockFilter;

/// `struct seccomp_data`: nr, arch, instruction_pointer, args[6].
pub const Data = struct {
    nr: u32,
    arch: u32,
    ip: u64 = 0,
    args: [6]u64,

    pub fn bytes(d: Data) [64]u8 {
        var b: [64]u8 = undefined;
        std.mem.writeInt(u32, b[0..4], d.nr, .little);
        std.mem.writeInt(u32, b[4..8], d.arch, .little);
        std.mem.writeInt(u64, b[8..16], d.ip, .little);
        for (d.args, 0..) |a, i| std.mem.writeInt(u64, b[16 + 8 * i ..][0..8], a, .little);
        return b;
    }
};

pub fn parseProgram(gpa: std.mem.Allocator, raw: []const u8) ![]Insn {
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
pub fn run(prog: []const Insn, d: Data) error{BadProgram}!u32 {
    var steps: usize = 0;
    return runCounting(prog, d, &steps);
}

/// `run`, adding the number of instructions executed to `steps`.
pub fn runCounting(prog: []const Insn, d: Data, steps: *usize) error{BadProgram}!u32 {
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
        steps.* += 1;
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
