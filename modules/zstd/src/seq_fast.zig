// SPDX-License-Identifier: MIT
//! The sequence loop's fast path in assembly (Z35): x86-64 with BMI2, LLVM
//! builds only; every other build takes the Zig loop in `dblock.zig`, which
//! is also the oracle the tests compare this one with (SPEC.md, Z33, Z35).
//!
//! `run` decodes and executes sequences while every margin holds, and
//! returns to the Zig loop as soon as one does not:
//! - before decoding, when one sequence is left (the last one skips the
//!   state update) or fewer than `stream_margin` bytes of the bitstream
//!   remain above its start (both reloads of a sequence then take the
//!   plain path of `DStream.reload`); `status` = `stopped`;
//! - after decoding, when executing the sequence would need anything but
//!   the fast path of `execSequence`: literals past their end, output
//!   within `wildcopy_overlength` of the end, or a match reaching before
//!   the prefix (the dictionary segment). The decoded sequence is left in
//!   `seq_*` for the Zig `execSequence`; `status` = `pending`;
//! - when a reload finds more than 64 bits consumed: only a corrupt stream
//!   gets there, and the Zig loop would end it in an error too (an
//!   overflowed `DStream` never reaches `endOfStream`), possibly a different
//!   one; `status` = `corrupt`.
//!
//! What it executes, it executes as the Zig loop does: the same bit reads,
//! the same repeat-offset updates, and the same bytes in `out[..op]`. Its
//! copies write at most 15 bytes past a sequence's end (the Zig wildcopy:
//! up to 32), inside the same `wildcopy_overlength` margin; those bytes are
//! scratch that the next sequence overwrites, as in libzstd.

const std = @import("std");
const builtin = @import("builtin");

/// Whether this build has the assembly. LLVM only: the self-hosted backend
/// (Debug edit loop) takes the Zig loop.
pub const supported = builtin.zig_backend == .stage2_llvm and switch (builtin.cpu.arch) {
    .x86_64 => std.Target.x86.featureSetHas(builtin.cpu.features, .bmi2),
    else => false,
};

/// Bytes of bitstream above its start that one sequence's two reloads need
/// to stay on `DStream.reload`'s plain path (`ptr >= start + 8` before each,
/// at most 8 bytes taken by each).
pub const stream_margin = 24;

pub const Status = enum(u64) { stopped = 0, pending = 1, corrupt = 2 };

/// The loop's whole state, in and out. Addresses, not indices: the
/// assembly walks pointers. Field offsets are fixed (asserted below), the
/// assembly reads them by number.
pub const FastSeq = extern struct {
    container: u64, // 0   DStream.container
    bits: u64, // 8        DStream.bits_consumed
    ptr: usize, // 16      &buf[DStream.ptr]
    limit: usize, // 24    &buf[start + stream_margin]
    ll_state: u64, // 32
    ml_state: u64, // 40
    of_state: u64, // 48
    ll_cells: usize, // 56  *const [_]SeqSymbol
    ml_cells: usize, // 64
    of_cells: usize, // 72
    prev: [3]u64, // 80    repeat offsets
    lit: usize, // 104     &lit_src[lit_pos]
    lit_end: usize, // 112 &lit_src[lit_end]
    op: usize, // 120      &out[op]
    oend_w: usize, // 128  &out[oend - wildcopy_overlength]
    prefix: usize, // 136  &out[prefix]
    nb_seq: u64, // 144    sequences left, decremented per decoded one
    seq_ll: u64, // 152    the pending sequence
    seq_ml: u64, // 160
    seq_off: u64, // 168
    status: Status, // 176
    dec: usize, // 184     &dec_tables
};

/// `ZSTD_overlapCopy8`'s `dec32table` then `dec64table`, as bytes.
pub const dec_tables = [16]u8{ 0, 1, 2, 1, 4, 4, 4, 4, 8, 8, 8, 7, 8, 9, 10, 11 };

comptime {
    // Only where the assembly is built: elsewhere `usize` may be 32 bits.
    if (supported) {
        const o = [_]struct { []const u8, usize }{
            .{ "container", 0 }, .{ "bits", 8 },      .{ "ptr", 16 },      .{ "limit", 24 },
            .{ "ll_state", 32 }, .{ "ml_state", 40 }, .{ "of_state", 48 }, .{ "ll_cells", 56 },
            .{ "ml_cells", 64 }, .{ "of_cells", 72 }, .{ "prev", 80 },     .{ "lit", 104 },
            .{ "lit_end", 112 }, .{ "op", 120 },      .{ "oend_w", 128 },  .{ "prefix", 136 },
            .{ "nb_seq", 144 },  .{ "seq_ll", 152 },  .{ "seq_ml", 160 },  .{ "seq_off", 168 },
            .{ "status", 176 },  .{ "dec", 184 },
        };
        for (o) |f| if (@offsetOf(FastSeq, f[0]) != f[1]) @compileError("FastSeq." ++ f[0] ++ " moved");
    }
}

/// Test hook: counts the loop entries, so a test can tell that the
/// assembly ran. A constant outside tests.
pub const entries = if (builtin.is_test) struct {
    pub var n: usize = 0;
} else struct {
    pub const n: usize = 0;
};

/// Runs the fast loop over `a` (see the file comment). `a.oend_w` must not
/// lie before `a.op`'s buffer start minus nothing: the caller enters only
/// when the output holds at least `wildcopy_overlength` bytes.
pub fn run(a: *FastSeq) void {
    if (builtin.is_test) entries.n += 1;
    switch (builtin.cpu.arch) {
        .x86_64 => runX86(a),
        else => unreachable,
    }
}

// Registers (x86-64, BMI2): rdi = a, r8 = container, r9 = bits, r10 =
// stream pointer, r11/r12/r13 = ll/ml/of state, r14 = literal pointer, r15
// = output pointer, rbx = prev[0] (prev[1], prev[2] stay in `a`); rax, rcx,
// rdx, rsi, xmm0, xmm1 scratch. In the decode: rdx = offset, rax = literal
// length, the match length in `a.seq_ml` (rbp stays the frame pointer of
// the builds that keep one).
//
// Every read is DStream.lookBits exactly: v = bzhi(shrx(c, -(bits + n)), n);
// bits += n. n = 0 gives 0, so no read needs a branch.
// reload: bits > 64 -> corrupt; ptr -= bits >> 3; bits &= 7; c = *(u64*)ptr
fn runX86(a: *FastSeq) void {
    asm volatile (
        \\ movq 0(%%rdi), %%r8
        \\ movq 8(%%rdi), %%r9
        \\ movq 16(%%rdi), %%r10
        \\ movq 32(%%rdi), %%r11
        \\ movq 40(%%rdi), %%r12
        \\ movq 48(%%rdi), %%r13
        \\ movq 104(%%rdi), %%r14
        \\ movq 120(%%rdi), %%r15
        \\ movq 80(%%rdi), %%rbx
        \\ 20:
        \\ cmpq $1, 144(%%rdi)
        \\ jbe 21f
        \\ cmpq 24(%%rdi), %%r10
        \\ jb 21f
        // ---- offset
        \\ movq 72(%%rdi), %%rsi
        \\ movq (%%rsi,%%r13,8), %%rax
        \\ movzbl 2(%%rsi,%%r13,8), %%ecx
        \\ shrq $32, %%rax
        \\ cmpl $1, %%ecx
        \\ jbe 22f
        \\ leaq (%%r9,%%rcx), %%rdx
        \\ negq %%rdx
        \\ shrxq %%rdx, %%r8, %%rdx
        \\ bzhiq %%rcx, %%rdx, %%rdx
        \\ addq %%rcx, %%r9
        \\ addq %%rax, %%rdx
        \\ movq 88(%%rdi), %%rax
        \\ movq %%rax, 96(%%rdi)
        \\ movq %%rbx, 88(%%rdi)
        \\ movq %%rdx, %%rbx
        \\ jmp 24f
        \\ 22:
        \\ movq 56(%%rdi), %%rsi
        \\ xorl %%edx, %%edx
        \\ cmpl $0, 4(%%rsi,%%r11,8)
        \\ sete %%dl
        \\ testl %%ecx, %%ecx
        \\ jnz 23f
        // of_bits == 0: ll0 = 0 keeps everything; ll0 = 1 swaps prev[0], prev[1]
        \\ testl %%edx, %%edx
        \\ jnz 1f
        \\ movq %%rbx, %%rdx
        \\ jmp 24f
        \\ 1:
        \\ movq 88(%%rdi), %%rdx
        \\ movq %%rbx, 88(%%rdi)
        \\ movq %%rdx, %%rbx
        \\ jmp 24f
        \\ 23:
        // of_bits == 1: offset = base + ll0 + 1 bit, in 1..3
        \\ addq %%rax, %%rdx
        \\ shlxq %%r9, %%r8, %%rsi
        \\ shrq $63, %%rsi
        \\ addq %%rsi, %%rdx
        \\ addq $1, %%r9
        \\ leaq -1(%%rbx), %%rsi
        \\ cmpq $3, %%rdx
        \\ je 2f
        \\ movq 80(%%rdi,%%rdx,8), %%rsi
        \\ 2:
        \\ cmpq $1, %%rsi
        \\ sbbq $0, %%rsi
        \\ cmpq $1, %%rdx
        \\ je 3f
        \\ movq 88(%%rdi), %%rax
        \\ movq %%rax, 96(%%rdi)
        \\ 3:
        \\ movq %%rbx, 88(%%rdi)
        \\ movq %%rsi, %%rbx
        \\ movq %%rsi, %%rdx
        \\ 24:
        // ---- match length into seq_ml (160): rbp stays the frame's
        \\ movq 64(%%rdi), %%rsi
        \\ movq (%%rsi,%%r12,8), %%rax
        \\ movzbl 2(%%rsi,%%r12,8), %%ecx
        \\ shrq $32, %%rax
        \\ leaq (%%r9,%%rcx), %%rsi
        \\ negq %%rsi
        \\ shrxq %%rsi, %%r8, %%rsi
        \\ bzhiq %%rcx, %%rsi, %%rsi
        \\ addq %%rcx, %%r9
        \\ addq %%rsi, %%rax
        \\ movq %%rax, 160(%%rdi)
        // total extra bits >= 31: reload between ml and ll
        \\ movq 56(%%rdi), %%rsi
        \\ movzbl 2(%%rsi,%%r11,8), %%eax
        \\ addl %%eax, %%ecx
        \\ movq 72(%%rdi), %%rsi
        \\ movzbl 2(%%rsi,%%r13,8), %%eax
        \\ addl %%eax, %%ecx
        \\ cmpl $31, %%ecx
        \\ jb 4f
        \\ cmpq $64, %%r9
        \\ ja 25f
        \\ movq %%r9, %%rcx
        \\ shrq $3, %%rcx
        \\ subq %%rcx, %%r10
        \\ andq $7, %%r9
        \\ movq (%%r10), %%r8
        \\ 4:
        // ---- literal length into rax
        \\ movq 56(%%rdi), %%rsi
        \\ movq (%%rsi,%%r11,8), %%rax
        \\ movzbl 2(%%rsi,%%r11,8), %%ecx
        \\ shrq $32, %%rax
        \\ leaq (%%r9,%%rcx), %%rsi
        \\ negq %%rsi
        \\ shrxq %%rsi, %%r8, %%rsi
        \\ bzhiq %%rcx, %%rsi, %%rsi
        \\ addq %%rcx, %%r9
        \\ addq %%rsi, %%rax
        // ---- states: S = next_state + read(nb_bits), ll, ml, of
        \\ movq 56(%%rdi), %%rsi
        \\ movzbl 3(%%rsi,%%r11,8), %%ecx
        \\ movzwl (%%rsi,%%r11,8), %%esi
        \\ leaq (%%r9,%%rcx), %%r11
        \\ negq %%r11
        \\ shrxq %%r11, %%r8, %%r11
        \\ bzhiq %%rcx, %%r11, %%r11
        \\ addq %%rcx, %%r9
        \\ addq %%rsi, %%r11
        \\ movq 64(%%rdi), %%rsi
        \\ movzbl 3(%%rsi,%%r12,8), %%ecx
        \\ movzwl (%%rsi,%%r12,8), %%esi
        \\ leaq (%%r9,%%rcx), %%r12
        \\ negq %%r12
        \\ shrxq %%r12, %%r8, %%r12
        \\ bzhiq %%rcx, %%r12, %%r12
        \\ addq %%rcx, %%r9
        \\ addq %%rsi, %%r12
        \\ movq 72(%%rdi), %%rsi
        \\ movzbl 3(%%rsi,%%r13,8), %%ecx
        \\ movzwl (%%rsi,%%r13,8), %%esi
        \\ leaq (%%r9,%%rcx), %%r13
        \\ negq %%r13
        \\ shrxq %%r13, %%r8, %%r13
        \\ bzhiq %%rcx, %%r13, %%r13
        \\ addq %%rcx, %%r9
        \\ addq %%rsi, %%r13
        // final reload
        \\ cmpq $64, %%r9
        \\ ja 25f
        \\ movq %%r9, %%rcx
        \\ shrq $3, %%rcx
        \\ subq %%rcx, %%r10
        \\ andq $7, %%r9
        \\ movq (%%r10), %%r8
        \\ decq 144(%%rdi)
        // ---- execute: rax = ll, seq_ml = ml, rdx = offset
        \\ leaq (%%r14,%%rax), %%rsi
        \\ cmpq 112(%%rdi), %%rsi
        \\ ja 26f
        \\ leaq (%%r15,%%rax), %%rcx
        \\ movq 160(%%rdi), %%rsi
        \\ addq %%rcx, %%rsi
        \\ cmpq 128(%%rdi), %%rsi
        \\ ja 26f
        \\ subq 136(%%rdi), %%rcx
        \\ cmpq %%rcx, %%rdx
        \\ ja 26f
        // literals: 32 bytes at once (the margins cover them), then 16 at a time
        \\ movdqu (%%r14), %%xmm0
        \\ movdqu 16(%%r14), %%xmm1
        \\ movdqu %%xmm0, (%%r15)
        \\ movdqu %%xmm1, 16(%%r15)
        \\ cmpq $32, %%rax
        \\ ja 6f
        \\ 7:
        \\ addq %%rax, %%r14
        \\ addq %%rax, %%r15
        \\ movq %%r15, %%rsi
        \\ subq %%rdx, %%rsi
        \\ cmpq $16, %%rdx
        \\ jb 9f
        // match, offset >= 16: 16 bytes, then 16 at a time while short of ml
        // (no blind second load: on a long offset it may be a cache line of
        // its own, and a miss)
        \\ movdqu (%%rsi), %%xmm0
        \\ movdqu %%xmm0, (%%r15)
        \\ cmpq $16, 160(%%rdi)
        \\ ja 8f
        \\ addq 160(%%rdi), %%r15
        \\ jmp 20b
        \\ 6:
        \\ movl $32, %%ecx
        \\ 5:
        \\ movdqu (%%r14,%%rcx), %%xmm0
        \\ movdqu %%xmm0, (%%r15,%%rcx)
        \\ addq $16, %%rcx
        \\ cmpq %%rax, %%rcx
        \\ jb 5b
        \\ jmp 7b
        \\ 8:
        \\ movl $16, %%ecx
        \\ 10:
        \\ movdqu (%%rsi,%%rcx), %%xmm0
        \\ movdqu %%xmm0, (%%r15,%%rcx)
        \\ addq $16, %%rcx
        \\ cmpq 160(%%rdi), %%rcx
        \\ jb 10b
        \\ addq 160(%%rdi), %%r15
        \\ jmp 20b
        \\ 9:
        // offset < 16: ZSTD_overlapCopy8, then 8 bytes at a time
        \\ cmpq $8, %%rdx
        \\ jae 11f
        \\ movzbl 0(%%rsi), %%ecx
        \\ movb %%cl, 0(%%r15)
        \\ movzbl 1(%%rsi), %%ecx
        \\ movb %%cl, 1(%%r15)
        \\ movzbl 2(%%rsi), %%ecx
        \\ movb %%cl, 2(%%r15)
        \\ movzbl 3(%%rsi), %%ecx
        \\ movb %%cl, 3(%%r15)
        \\ movq 184(%%rdi), %%rax
        \\ movzbl (%%rax,%%rdx), %%ecx
        \\ addq %%rcx, %%rsi
        \\ movl (%%rsi), %%ecx
        \\ movl %%ecx, 4(%%r15)
        \\ movzbl 8(%%rax,%%rdx), %%ecx
        \\ addq $8, %%rsi
        \\ subq %%rcx, %%rsi
        \\ jmp 12f
        \\ 11:
        \\ movq (%%rsi), %%rcx
        \\ movq %%rcx, (%%r15)
        \\ addq $8, %%rsi
        \\ 12:
        \\ movl $8, %%ecx
        \\ cmpq %%rcx, 160(%%rdi)
        \\ jbe 14f
        \\ 13:
        \\ movq (%%rsi), %%rax
        \\ movq %%rax, (%%r15,%%rcx)
        \\ addq $8, %%rsi
        \\ addq $8, %%rcx
        \\ cmpq 160(%%rdi), %%rcx
        \\ jb 13b
        \\ 14:
        \\ addq 160(%%rdi), %%r15
        \\ jmp 20b
        \\ 25:
        \\ movq $2, 176(%%rdi)
        \\ jmp 27f
        \\ 26:
        \\ movq %%rax, 152(%%rdi)
        \\ movq %%rdx, 168(%%rdi)
        \\ movq $1, 176(%%rdi)
        \\ jmp 27f
        \\ 21:
        \\ movq $0, 176(%%rdi)
        \\ 27:
        \\ movq %%r8, 0(%%rdi)
        \\ movq %%r9, 8(%%rdi)
        \\ movq %%r10, 16(%%rdi)
        \\ movq %%r11, 32(%%rdi)
        \\ movq %%r12, 40(%%rdi)
        \\ movq %%r13, 48(%%rdi)
        \\ movq %%r14, 104(%%rdi)
        \\ movq %%r15, 120(%%rdi)
        \\ movq %%rbx, 80(%%rdi)
        :
        : [a] "{rdi}" (a),
        : .{ .rax = true, .rbx = true, .rcx = true, .rdx = true, .rsi = true, .r8 = true, .r9 = true, .r10 = true, .r11 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .xmm0 = true, .xmm1 = true, .cc = true, .memory = true });
}
