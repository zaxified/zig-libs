// SPDX-License-Identifier: MIT

//! The LZ4 block format (lz4_Block_format.md, LZ4 v1.10.0): a sequence of
//! (token, literals, offset, match length) records, the last of which carries
//! literals only.
//!
//! Decoder: every length and offset is checked against the input, the output
//! slice and the history window before a byte is copied; a malformed block is
//! a typed `Error`, never a panic or an out-of-bounds read.
//!
//! Encoder: a single-probe hash table over 4-byte sequences, greedy parse,
//! the "acceleration" skip of LZ4's default compressor, and the block-end
//! rules of the format (the last 5 bytes are literals, the last match starts
//! at least 12 bytes before the end), so every block it writes is accepted by
//! liblz4's `LZ4_decompress_safe`.

const std = @import("std");
const builtin = @import("builtin");

pub const Error = error{
    /// The block ends inside a sequence (a length, the literals or the
    /// offset run past the input), is empty, or ends right after a match
    /// instead of with a literal-only sequence (format rule 1).
    Truncated,
    /// A match offset of 0 (the format calls it a corrupted block) or one
    /// reaching before the start of the history window.
    BadOffset,
    /// The decoded bytes do not fit the output slice.
    OutputTooSmall,
};

pub const min_match = 4;
/// The last match must start at least this many bytes before the block end.
pub const mf_limit = 12;
/// The last this-many bytes of a block are literals.
pub const last_literals = 5;
/// The window: an offset is a u16, 1..65535.
pub const max_offset = 65535;
/// liblz4's `LZ4_MAX_INPUT_SIZE`: the largest input one block may hold.
pub const max_input_size: usize = 0x7E00_0000;

/// liblz4's `LZ4_COMPRESSBOUND`: the largest block `n` input bytes can
/// compress to (incompressible data: every literal plus the length bytes).
pub fn compressBound(n: usize) usize {
    return std.math.add(usize, n, n / 255 + 16) catch std.math.maxInt(usize);
}

/// A little-endian u16 in one load (`readInt` over a 2-byte array is two
/// byte loads with Zig 0.17.1).
inline fn read16(b: *const [2]u8) u16 {
    return std.mem.littleToNative(u16, @as(*align(1) const u16, @ptrCast(b)).*);
}

fn readLength(src: []const u8, ip: *usize, base: usize) Error!usize {
    var len = base;
    while (true) {
        if (ip.* >= src.len) return error.Truncated;
        const b = src[ip.*];
        ip.* += 1;
        len = std.math.add(usize, len, b) catch return error.OutputTooSmall;
        if (b != 255) return len;
    }
}

/// The fast loop runs while a token has more than this many input bytes
/// after it: one 16-byte literal chunk, which also covers the two offset
/// bytes that follow up to 14 literals.
const fast_in = 16;
/// The overshoot a chunked match copy may write past the match's end.
const wild_room = 32;
/// ... and while at least this much output room is left: up to 14 literals
/// and a match of up to 18 bytes (no length bytes) then always leave
/// `wild_room`, so only a sequence with length bytes needs a room check.
const fast_out = 64;

/// Decode one block into `out[start..]`. `out[prefix_start..start]` is the
/// history a match may reach into (the previous blocks of a linked frame);
/// `prefix_start == start` means none. Returns the end index of the output.
///
/// Two loops (liblz4's `LZ4_decompress_generic` was the design reference):
/// a fast loop while the input and the output are far from their ends, whose
/// copies are whole 16-byte chunks that may overshoot into bytes the next
/// sequence overwrites, and the tail loop with exact copies and every
/// error. The fast loop takes a sequence only when every check passes with
/// its margins; anything else — a malformed sequence, one too close to an
/// end — goes back to the sequence's token and leaves the rest of the block
/// to the tail loop, which decides it with the same rules. So both loops
/// give the same result for every input, and the fast loop has no error
/// path and no call.
pub fn decodeInto(src: []const u8, out: []u8, start: usize, prefix_start: usize) Error!usize {
    std.debug.assert(prefix_start <= start and start <= out.len);
    if (src.len == 0) return error.Truncated;
    var ip: usize = 0;
    var op: usize = start;
    if (src.len > fast_in and out.len >= fast_out) {
        const in_end = src.len - fast_in; // ip < in_end: more than fast_in left
        const out_end = out.len - fast_out; // op <= out_end: fast_out left
        if (comptime fast_asm) {
            fastLoopAsm(src, out, &ip, &op, in_end, out_end, prefix_start);
        } else while (ip < in_end and op <= out_end) {
            const seq = ip;
            const token = src[ip];
            ip += 1;
            var lit: usize = token >> 4;
            if (lit != 15) {
                // Up to 14 literals in one 16-byte chunk; at least 2 input
                // bytes stay after them, so the offset is there and this is
                // not the literal-only last sequence.
                out[op..][0..16].* = src[ip..][0..16].*;
            } else {
                lit = readLength(src, &ip, 15) catch {
                    ip = seq;
                    break;
                };
                // 16 more input bytes than the literals (the chunk
                // overshoot, the offset) and `fast_out` more output bytes
                // (`op <= out_end`, so the subtraction cannot wrap).
                if (src.len - ip < 16 or src.len - ip - 16 < lit or out.len - op - fast_out < lit) {
                    ip = seq;
                    break;
                }
                var i: usize = 0;
                while (i < lit) : (i += 16) out[op + i ..][0..16].* = src[ip + i ..][0..16].*;
            }
            ip += lit;
            const mp = op + lit; // where the match goes; out.len - mp >= 50
            const offset: usize = read16(src[ip..][0..2]);
            ip += 2;
            // 1 <= offset <= mp - prefix_start, in one unsigned compare.
            if (offset -% 1 >= mp - prefix_start) {
                ip = seq;
                break;
            }
            var ml: usize = (token & 15) + min_match;
            if (ml == 15 + min_match) {
                ml = readLength(src, &ip, 15 + min_match) catch {
                    ip = seq;
                    break;
                };
                if (ml > out.len - mp - wild_room) {
                    ip = seq;
                    break;
                }
            }
            wildMatch(out, mp, offset, ml);
            op = mp + ml;
        }
    }
    while (true) {
        if (ip >= src.len) return error.Truncated; // ended after a match
        const token = src[ip];
        ip += 1;

        var lit: usize = token >> 4;
        if (lit == 15) lit = try readLength(src, &ip, 15);
        if (lit > src.len - ip) return error.Truncated;
        if (lit > out.len - op) return error.OutputTooSmall;
        if (lit <= 16 and src.len - ip >= 16 and out.len - op >= 16) {
            // One fixed 16-byte copy; the bytes past `lit` are scratch that
            // the next sequence overwrites (or that stay unused capacity).
            out[op..][0..16].* = src[ip..][0..16].*;
        } else @memcpy(out[op..][0..lit], src[ip..][0..lit]);
        ip += lit;
        op += lit;
        if (ip == src.len) return op; // the literal-only last sequence

        if (src.len - ip < 2) return error.Truncated;
        const offset: usize = std.mem.readInt(u16, src[ip..][0..2], .little);
        ip += 2;
        if (offset == 0 or offset > op - prefix_start) return error.BadOffset;

        // The minimum match is the base of the sum `readLength` checks: on a
        // 32-bit target a long run of 255 bytes cannot wrap the length.
        var ml: usize = (token & 15) + min_match;
        if (ml == 15 + min_match) ml = try readLength(src, &ip, 15 + min_match);
        if (ml > out.len - op) return error.OutputTooSmall;
        if (offset >= 16 and out.len - op - ml >= 16) {
            // 16-byte chunks, overshooting by up to 15 bytes of scratch: no
            // chunk overlaps itself, and a chunk reading what an earlier one
            // wrote reads the right bytes (the copy runs forwards).
            const m = op - offset;
            var i: usize = 0;
            while (i < ml) : (i += 16) out[op + i ..][0..16].* = out[m + i ..][0..16].*;
        } else copyMatch(out, op, offset, ml);
        op += ml;
    }
}

/// Copy a match of `len` bytes from `op - offset` to `op` in whole 16-byte
/// chunks, writing up to `wild_room` bytes past its end (the caller has
/// checked that room). 1 <= offset <= op.
inline fn wildMatch(out: []u8, op: usize, offset: usize, len: usize) void {
    const m = op - offset;
    if (offset >= 16) {
        // One chunk covers the common short match; a chunk never overlaps
        // itself, and one reading what an earlier one wrote reads the right
        // bytes (the copy runs forwards).
        out[op..][0..16].* = out[m..][0..16].*;
        if (len > 16) {
            out[op + 16 ..][0..16].* = out[m + 16 ..][0..16].*;
            if (len > 32) copyLong(out, op, m, len);
        }
        return;
    }
    // A shorter offset repeats the `offset` bytes before `op`: spread them
    // over a 16-byte pattern once (lanes `i % offset`; the bytes loaded past
    // `op` are never selected) and store it every `stride` bytes, the largest
    // multiple of the period that fits in 16.
    switch (offset) {
        inline 1...15 => |o| {
            const stride = o * (16 / o);
            const mask = comptime blk: {
                var lanes: [16]i32 = undefined;
                for (&lanes, 0..) |*l, i| l.* = @intCast(i % o);
                break :blk lanes;
            };
            const v: @Vector(16, u8) = out[m..][0..16].*;
            const pattern: [16]u8 = @shuffle(u8, v, undefined, mask);
            var i: usize = 0;
            while (i < len) : (i += stride) out[op + i ..][0..16].* = pattern;
        },
        else => unreachable, // 1 <= offset < 16 here
    }
}

/// The rest of a match longer than 32 bytes at an offset of at least 16,
/// in 16-byte chunks. Out of line: the common short match then keeps the
/// decoder's loop free of this loop's registers.
noinline fn copyLong(out: []u8, op: usize, m: usize, len: usize) void {
    var i: usize = 32;
    while (i < len) : (i += 16) out[op + i ..][0..16].* = out[m + i ..][0..16].*;
}

/// Whether `decodeInto`'s fast loop runs as `fastLoopAsm` (x86-64 with SSSE3
/// for `pshufb`, LLVM backend for `.p2align`) instead of the Zig loop.
const fast_asm = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .ssse3) and
    builtin.zig_backend == .stage2_llvm;

/// `wildMatch`'s short-offset tables for `fastLoopAsm`: bytes 16·o .. 16·o+15
/// are the lanes `i % o` of offset `o` (1..15; row 0 unused), bytes 256 + o
/// the stride `o · ⌊16 / o⌋`.
const short_offset_tables: [16 * 16 + 16]u8 align(16) = blk: {
    var t: [16 * 16 + 16]u8 = @splat(0);
    for (1..16) |o| {
        for (0..16) |i| t[16 * o + i] = @intCast(i % o);
        t[256 + o] = @intCast(o * (16 / o));
    }
    break :blk t;
};

/// `decodeInto`'s fast loop, the same steps in the same order (each check,
/// each copy and its overshoot, the hand-back to the sequence's token), as
/// ONE asm block behind `.p2align 5` with fixed registers, so its layout is
/// the text below and not where the linker happens to put it.
///
/// Why: Intel's JCC erratum (Skylake … Cascade Lake microcode) sends a jump
/// that crosses or ends on a 32-byte boundary to the legacy decoder. The
/// compiled Zig loop ran 1.22–1.25× liblz4 in a default build and level with
/// it only when padded (`-Djcc-safe`): `perf` 2026-11-25, 39 % of its µops
/// from the legacy decoder unpadded against 3 % padded, 18 % more cycles for
/// the same instructions. `crc32c` fixed the same thing the same way.
///
/// The length sums of `readLength` are not checked for overflow here: they
/// grow by at most 255 per input byte, so they cannot wrap below 2^56 bytes
/// of input. Every other verdict is the Zig loop's.
fn fastLoopAsm(src: []const u8, out: []u8, ip: *usize, op: *usize, in_end: usize, out_end: usize, prefix_start: usize) void {
    var ipp: [*]const u8 = src.ptr + ip.*;
    var opp: [*]u8 = out.ptr + op.*;
    asm volatile (
    // ── hot path: one sequence with short lengths ─────────────────────
        \\ .p2align 5
        \\ 1:
        \\ cmpq %%r8, %%rsi
        \\ jae 9f
        \\ cmpq %%r9, %%rdi
        \\ ja 9f
        \\ movq %%rsi, %%r15
        \\ movzbl (%%rsi), %%eax
        \\ incq %%rsi
        \\ movl %%eax, %%ecx
        \\ shrl $4, %%ecx
        \\ andl $15, %%eax
        \\ cmpl $15, %%ecx
        \\ je 20f
        \\ movdqu (%%rsi), %%xmm0
        \\ movdqu %%xmm0, (%%rdi)
        \\ 2:
        \\ addq %%rcx, %%rsi
        \\ leaq (%%rdi,%%rcx), %%rdx
        \\ movzwl (%%rsi), %%ecx
        \\ addq $2, %%rsi
        \\ movq %%rdx, %%r14
        \\ subq %%r10, %%r14
        \\ decq %%rcx
        \\ cmpq %%r14, %%rcx
        \\ jae 8f
        \\ incq %%rcx
        \\ addl $4, %%eax
        \\ movq %%rdx, %%r14
        \\ subq %%rcx, %%r14
        \\ cmpl $19, %%eax
        \\ je 30f
        \\ 3:
        \\ cmpq $16, %%rcx
        \\ jb 40f
        \\ movdqu (%%r14), %%xmm0
        \\ movdqu %%xmm0, (%%rdx)
        \\ movdqu 16(%%r14), %%xmm0
        \\ movdqu %%xmm0, 16(%%rdx)
        \\ cmpq $32, %%rax
        \\ ja 50f
        \\ 4:
        \\ leaq (%%rdx,%%rax), %%rdi
        \\ jmp 1b
        // ── offset 1..15: a pshufb pattern every stride bytes ───────────
        \\ .p2align 4
        \\ 40:
        \\ movdqu (%%r14), %%xmm0
        \\ movq %%rcx, %%r15
        \\ shlq $4, %%r15
        \\ movdqu (%%r13,%%r15), %%xmm1
        \\ pshufb %%xmm1, %%xmm0
        \\ movzbl 256(%%r13,%%rcx), %%r15d
        \\ xorl %%r14d, %%r14d
        \\ 41:
        \\ movdqu %%xmm0, (%%rdx,%%r14)
        \\ addq %%r15, %%r14
        \\ cmpq %%rax, %%r14
        \\ jb 41b
        \\ jmp 4b
        // ── the rest of a match over 32 bytes, offset >= 16 ─────────────
        \\ .p2align 4
        \\ 50:
        \\ movl $32, %%r15d
        \\ 51:
        \\ movdqu (%%r14,%%r15), %%xmm0
        \\ movdqu %%xmm0, (%%rdx,%%r15)
        \\ addq $16, %%r15
        \\ cmpq %%rax, %%r15
        \\ jb 51b
        \\ jmp 4b
        // ── literal length bytes (lit = 15 + ...) ────────────────────────
        \\ .p2align 4
        \\ 20:
        \\ cmpq %%r11, %%rsi
        \\ jae 8f
        \\ movzbl (%%rsi), %%edx
        \\ incq %%rsi
        \\ addq %%rdx, %%rcx
        \\ cmpl $255, %%edx
        \\ je 20b
        \\ movq %%r11, %%rdx
        \\ subq %%rsi, %%rdx
        \\ cmpq $16, %%rdx
        \\ jb 8f
        \\ subq $16, %%rdx
        \\ cmpq %%rcx, %%rdx
        \\ jb 8f
        \\ movq %%r12, %%rdx
        \\ subq %%rdi, %%rdx
        \\ subq $64, %%rdx
        \\ cmpq %%rcx, %%rdx
        \\ jb 8f
        \\ xorl %%edx, %%edx
        \\ 21:
        \\ movdqu (%%rsi,%%rdx), %%xmm0
        \\ movdqu %%xmm0, (%%rdi,%%rdx)
        \\ addq $16, %%rdx
        \\ cmpq %%rcx, %%rdx
        \\ jb 21b
        \\ jmp 2b
        // ── match length bytes (ml = 19 + ...) ───────────────────────────
        \\ .p2align 4
        \\ 30:
        \\ cmpq %%r11, %%rsi
        \\ jae 8f
        \\ movzbl (%%rsi), %%r14d
        \\ incq %%rsi
        \\ addq %%r14, %%rax
        \\ cmpl $255, %%r14d
        \\ je 30b
        \\ movq %%r12, %%r14
        \\ subq %%rdx, %%r14
        \\ subq $32, %%r14
        \\ cmpq %%r14, %%rax
        \\ ja 8f
        \\ movq %%rdx, %%r14
        \\ subq %%rcx, %%r14
        \\ jmp 3b
        // ── hand back: the sequence starts again at its token ───────────
        \\ 8:
        \\ movq %%r15, %%rsi
        \\ 9:
        : [ip] "={rsi}" (ipp),
          [op] "={rdi}" (opp),
        : [ip_in] "0" (ipp),
          [op_in] "1" (opp),
          [in_end] "{r8}" (src.ptr + in_end),
          [out_end] "{r9}" (out.ptr + out_end),
          [prefix] "{r10}" (out.ptr + prefix_start),
          [src_end] "{r11}" (src.ptr + src.len),
          [out_lim] "{r12}" (out.ptr + out.len),
          [tables] "{r13}" (&short_offset_tables),
        : .{ .rax = true, .rcx = true, .rdx = true, .r14 = true, .r15 = true, .xmm0 = true, .xmm1 = true, .cc = true, .memory = true });
    ip.* = @intFromPtr(ipp) - @intFromPtr(src.ptr);
    op.* = @intFromPtr(opp) - @intFromPtr(out.ptr);
}

/// Copy `len` bytes from `op - offset` to `op`, overlap allowed (the copy is
/// defined byte by byte, so a short offset repeats a pattern).
inline fn copyMatch(out: []u8, op: usize, offset: usize, len: usize) void {
    const m = op - offset;
    if (offset >= len) {
        @memcpy(out[op..][0..len], out[m..][0..len]);
    } else if (offset == 1) {
        @memset(out[op..][0..len], out[m]);
    } else {
        // The pattern repeats with period `offset`. Copying from `m` while
        // `done` is a multiple of the period doubles the run each pass, and
        // the source `out[m..][0..offset + done]` never overlaps the target.
        var done: usize = 0;
        while (done < len) {
            const k = @min(offset + done, len - done);
            @memcpy(out[op + done ..][0..k], out[m..][0..k]);
            done += k;
        }
    }
}

/// Decode one block into `dst` (no history). Returns the decoded length.
/// `dst.len` is the output budget, as `dstCapacity` is for liblz4's
/// `LZ4_decompress_safe`; like it, the decoder may use `dst` past the
/// returned length as scratch (those bytes are unspecified afterwards).
pub fn decompress(src: []const u8, dst: []u8) Error!usize {
    return decodeInto(src, dst, 0, 0);
}

// ── encoder ─────────────────────────────────────────────────────────────

pub const hash_log = 12;
pub const hash_size = 1 << hash_log;
/// After this many misses in a row the search step grows by one (LZ4's
/// `skipTrigger`).
const skip_trigger = 6;

/// A hash table of input positions, reused across the blocks of a frame.
pub const Table = [hash_size]u32;

/// liblz4's `LZ4_64Klimit`: a single block shorter than this has every
/// position below 65536, so `compress` keeps them as u16 in a table of twice
/// as many entries in the same 16 KiB (liblz4's `byU16` table, hash log 13).
const small_limit = 65536 + mf_limit - 1;
const small_hash_log = 13;

/// How a table stores positions: `Entry` per slot, `log` bits of hash.
fn Layout(comptime Entry: type, comptime log: comptime_int) type {
    return struct {
        const Pos = Entry;
        const Slots = [1 << log]Entry;
        inline fn hash(v: u32) usize {
            return @intCast((v *% 2654435761) >> (32 - log));
        }
    };
}
const Wide = Layout(u32, hash_log);
const Small = Layout(u16, small_hash_log);

inline fn read32(b: []const u8, i: usize) u32 {
    return std.mem.readInt(u32, b[i..][0..4], .little);
}

const Sink = struct {
    dst: []u8,
    at: usize = 0,

    fn byte(s: *Sink, b: u8) error{NoSpaceLeft}!void {
        if (s.at >= s.dst.len) return error.NoSpaceLeft;
        s.dst[s.at] = b;
        s.at += 1;
    }

    fn bytes(s: *Sink, b: []const u8) error{NoSpaceLeft}!void {
        if (b.len > s.dst.len - s.at) return error.NoSpaceLeft;
        @memcpy(s.dst[s.at..][0..b.len], b);
        s.at += b.len;
    }

    fn length(s: *Sink, rest: usize) error{NoSpaceLeft}!void {
        var r = rest;
        while (r >= 255) : (r -= 255) try s.byte(255);
        try s.byte(@intCast(r));
    }

    /// A sequence with a match: literals `buf[anchor..][0..lits]`, then
    /// `offset` and the match length `ml`. When the room left holds the
    /// sequence's worst case plus 16 bytes, every byte is written without a
    /// per-byte room check (liblz4 skips its checks altogether when the
    /// output holds `LZ4_COMPRESSBOUND`; this is the per-sequence form of
    /// that); otherwise the checked writer below gives the exact
    /// `error.NoSpaceLeft`.
    inline fn matchSequence(s: *Sink, buf: []const u8, anchor: usize, lits: usize, offset: u16, ml: usize) error{NoSpaceLeft}!void {
        // Token, literal length bytes (at most lits / 255 + 1), literals,
        // offset, match length bytes (at most ml / 255 + 1); a shift by 7
        // bounds a division by 255 from above without a multiply.
        const worst = lits + (lits >> 7) + (ml >> 7) + 5;
        const room = s.dst.len - s.at;
        if (room < 16 or room - 16 < worst) return s.sequence(buf[anchor..][0..lits], offset, ml);
        const d = s.dst;
        var at = s.at;
        const token_at = at;
        at += 1;
        var token: u8 = undefined;
        if (lits >= 15) {
            token = 15 << 4;
            var r = lits - 15;
            while (r >= 255) : (r -= 255) {
                d[at] = 255;
                at += 1;
            }
            d[at] = @intCast(r);
            at += 1;
        } else token = @as(u8, @intCast(lits)) << 4;
        if (lits <= 8) {
            // One 8-byte chunk. The bytes past the literals are overwritten
            // by the offset (2) and the block's last sequence (a token and
            // at least 5 literals) before the encoder returns, so nothing
            // past the block's end changes. The source has them: a match
            // starts at most `end - mf_limit`, 12 bytes before the end.
            d[at..][0..8].* = buf[anchor..][0..8].*;
        } else if (lits <= 16) {
            // Two 8-byte chunks, the second ending exactly at the last literal.
            d[at..][0..8].* = buf[anchor..][0..8].*;
            d[at + lits - 8 ..][0..8].* = buf[anchor + lits - 8 ..][0..8].*;
        } else {
            // 16-byte chunks, the last one ending exactly at the last literal.
            var i: usize = 0;
            while (i + 16 < lits) : (i += 16) d[at + i ..][0..16].* = buf[anchor + i ..][0..16].*;
            d[at + lits - 16 ..][0..16].* = buf[anchor + lits - 16 ..][0..16].*;
        }
        at += lits;
        d[at] = @truncate(offset);
        d[at + 1] = @truncate(offset >> 8);
        at += 2;
        const mcode = ml - min_match;
        if (mcode >= 15) {
            token |= 15;
            var r = mcode - 15;
            while (r >= 255) : (r -= 255) {
                d[at] = 255;
                at += 1;
            }
            d[at] = @intCast(r);
            at += 1;
        } else token |= @intCast(mcode);
        d[token_at] = token;
        s.at = at;
    }

    /// The checked writer: the block's last sequence, and a sequence near
    /// the end of `dst`. Out of line, so the encoder's loop does not carry
    /// its registers.
    noinline fn sequence(s: *Sink, lits: []const u8, offset: ?u16, ml: usize) error{NoSpaceLeft}!void {
        const ln: u8 = if (lits.len >= 15) 15 else @intCast(lits.len);
        const mcode = if (offset == null) 0 else ml - min_match;
        const mn: u8 = if (mcode >= 15) 15 else @intCast(mcode);
        try s.byte(ln << 4 | mn);
        if (lits.len >= 15) try s.length(lits.len - 15);
        try s.bytes(lits);
        const off = offset orelse return;
        try s.byte(@truncate(off));
        try s.byte(@truncate(off >> 8));
        if (mcode >= 15) try s.length(mcode - 15);
    }
};

/// Compress `buf[start..end]` as one block into `dst`. Matches may reach back
/// into `buf[history_start..start]` (a linked frame's previous blocks), never
/// further than 65535 bytes. `table` holds positions in `buf` from earlier
/// calls over the same `buf`; positions below `history_start` are ignored.
/// `acceleration` >= 1: larger is faster and compresses less (LZ4's knob).
pub fn encodeRange(
    buf: []const u8,
    start: usize,
    end: usize,
    history_start: usize,
    table: *Table,
    acceleration: u32,
    dst: []u8,
) error{NoSpaceLeft}!usize {
    std.debug.assert(end <= std.math.maxInt(u32));
    return encodeWith(Wide, buf, start, end, history_start, table, acceleration, dst);
}

fn encodeWith(
    comptime L: type,
    buf: []const u8,
    start: usize,
    end: usize,
    history_start: usize,
    table: *L.Slots,
    acceleration: u32,
    dst: []u8,
) error{NoSpaceLeft}!usize {
    std.debug.assert(history_start <= start and start <= end and end <= buf.len);
    const hash = L.hash;
    var s: Sink = .{ .dst = dst };
    const n = end - start;
    var anchor = start;
    if (n >= mf_limit + 1) {
        const match_limit = end - mf_limit; // a match starts at or before this
        const extend_limit = end - last_literals; // and ends at or before this
        var ip = start;
        if (ip == history_start) {
            table[hash(read32(buf, ip))] = @intCast(ip);
            ip += 1;
        }
        outer: while (true) {
            // Search for a match (here ip <= match_limit). The next
            // position's bytes and hash are read before this probe is
            // judged, so the two do not wait on each other (liblz4's
            // `forwardH`); the read is clamped to `match_limit` so it stays
            // in the block when the search is about to end.
            var misses: u32 = acceleration << skip_trigger;
            var cand: usize = undefined;
            var v = read32(buf, ip);
            var h = hash(v);
            while (true) {
                const next = ip + (misses >> skip_trigger);
                misses += 1;
                cand = table[h];
                table[h] = @intCast(ip);
                const vn = read32(buf, @min(next, match_limit));
                // The table holds only positions already passed (cand < ip):
                // a candidate is usable when it is in the history and at most
                // 65535 bytes back.
                if (cand >= @max(history_start, ip -| max_offset) and read32(buf, cand) == v) break;
                if (next > match_limit) break :outer;
                ip = next;
                v = vn;
                h = hash(vn);
            }
            // Extend backwards into pending literals.
            if (ip > anchor and cand > history_start) {
                const k = backExtend(buf, ip, cand, @min(ip - anchor, cand - history_start));
                ip -= k;
                cand -= k;
            }
            // Extend forwards.
            var e = ip + min_match;
            var c = cand + min_match;
            while (e + 8 <= extend_limit) {
                const x = std.mem.readInt(u64, buf[e..][0..8], .little) ^ std.mem.readInt(u64, buf[c..][0..8], .little);
                if (x != 0) {
                    e += @ctz(x) / 8;
                    break;
                }
                e += 8;
                c += 8;
            } else {
                while (e < extend_limit and buf[e] == buf[c]) {
                    e += 1;
                    c += 1;
                }
            }
            try s.matchSequence(buf, anchor, ip - anchor, @intCast(ip - cand), e - ip);
            ip = e;
            anchor = ip;
            if (ip > match_limit) break;
            // Seed the table with a position inside the match, as LZ4 does.
            table[hash(read32(buf, ip - 2))] = @intCast(ip - 2);
        }
    }
    try s.sequence(buf[anchor..end], null, 0);
    return s.at;
}

/// How many bytes before `ip` equal those before `cand`, at most `max`.
/// Out of line: inlined, its loop made LLVM step a dozen values derived
/// from `ip` with it, all spilled.
noinline fn backExtend(buf: []const u8, ip: usize, cand: usize, max: usize) usize {
    var k: usize = 0;
    while (k < max and buf[ip - 1 - k] == buf[cand - 1 - k]) k += 1;
    return k;
}

pub const CompressOptions = struct {
    /// 3..12 selects the HC matcher (`encodeHc`: hash chains, lazy matching;
    /// slower, a smaller block, the same format); 0 (default), 1 and 2 are the
    /// fast matcher and `acceleration` applies; above 12 is 12. `compress` with
    /// a level keeps the matcher's tables (about 192 KiB) on the stack.
    hc_level: u8 = 0,
    /// LZ4's acceleration: 1 (the default) is LZ4's default level; each step
    /// up makes the match search skip faster over incompressible data.
    /// 0 is taken as 1; above 65537 is taken as 65537 (liblz4's bounds).
    acceleration: u32 = 1,
};

/// Clamp an acceleration the way liblz4 does.
pub fn clampAcceleration(a: u32) u32 {
    return std.math.clamp(a, 1, 65537);
}

/// Compress `src` as one independent block into `dst`. `compressBound(src.len)`
/// bytes always fit; with less room `error.NoSpaceLeft` may come back.
pub fn compress(src: []const u8, dst: []u8, opts: CompressOptions) error{ NoSpaceLeft, InputTooLarge }!usize {
    if (src.len > max_input_size) return error.InputTooLarge;
    if (opts.hc_level >= hc_min_level) return compressHcStack(src, dst, opts.hc_level);
    const accel = clampAcceleration(opts.acceleration);
    if (src.len < small_limit) {
        // Every position a probe or a seed enters is at most
        // `src.len - mf_limit` < 65536.
        var small: Small.Slots = @splat(0);
        return encodeWith(Small, src, 0, src.len, 0, &small, accel, dst);
    }
    var table: Table = @splat(0);
    return encodeRange(src, 0, src.len, 0, &table, accel, dst);
}

// ── HC encoder ──────────────────────────────────────────────────────────

pub const hc_hash_log = 15;
pub const hc_min_level = 3;
pub const hc_max_level = 12;

/// The HC matcher's state, reused across the blocks of a frame: the newest
/// position per 4-byte hash and, per position (mod 64 Ki), the distance to
/// the previous position with the same hash (liblz4's `LZ4HC_CCtx_internal`
/// `hashTable` and `chainTable`).
pub const HcTable = struct {
    head: [1 << hc_hash_log]u32,
    chain: [1 << 16]u16,
    /// Every position below this is in the table.
    next: usize,

    pub fn init(t: *HcTable) void {
        t.head = @splat(0);
        t.chain = @splat(0);
        t.next = 0;
    }
};

inline fn hcHash(v: u32) usize {
    return @intCast((v *% 2654435761) >> (32 - hc_hash_log));
}

/// How many chain links a level follows: 16 at level 3, doubling per level.
fn hcAttempts(level: u8) u32 {
    const l = std.math.clamp(level, hc_min_level, hc_max_level);
    return @as(u32, 1) << @intCast(l + 1);
}

inline fn hcInsert(t: *HcTable, buf: []const u8, upto: usize) void {
    var p = t.next;
    while (p < upto) : (p += 1) {
        const h = hcHash(read32(buf, p));
        const delta = p - t.head[h];
        t.chain[p & 0xFFFF] = @intCast(@min(delta, 0xFFFF));
        t.head[h] = @intCast(p);
    }
    if (upto > t.next) t.next = upto;
}

const HcMatch = struct { len: usize, cand: usize };

/// The longest match at `ip` longer than `min_len` (null if none): walk the
/// chain of positions with the same hash, at most `attempts` links, within
/// the window `[low, ip)`. Positions below `ip` must be inserted.
fn hcLongest(t: *const HcTable, buf: []const u8, ip: usize, extend_limit: usize, low: usize, attempts: u32, min_len: usize) ?HcMatch {
    if (ip + min_match > extend_limit) return null;
    const v = read32(buf, ip);
    var best: ?HcMatch = null;
    var best_len = min_len;
    var cand: usize = t.head[hcHash(v)];
    var left = attempts;
    while (left > 0 and cand >= low) {
        if (cand >= ip) {
            // Positions at or past `ip` can be in the table when a parse looked
            // ahead and came back; step over them without spending an attempt.
            const delta: usize = t.chain[cand & 0xFFFF];
            if (delta == 0 or cand < delta) break;
            cand -= delta;
            continue;
        }
        left -= 1;
        // A longer match must also agree at `best_len`; a cheap reject first.
        if (ip + best_len < extend_limit and buf[cand + best_len] == buf[ip + best_len] and read32(buf, cand) == v) {
            var e = ip + min_match;
            var c = cand + min_match;
            while (e < extend_limit and buf[e] == buf[c]) {
                e += 1;
                c += 1;
            }
            const len = e - ip;
            if (len > best_len) {
                best_len = len;
                best = .{ .len = len, .cand = cand };
            }
        }
        const delta: usize = t.chain[cand & 0xFFFF];
        if (delta == 0 or cand < delta) break;
        cand -= delta;
    }
    return best;
}

/// The HC counterpart of `encodeRange`: hash chains and lazy matching for
/// `level` 3..9 (2^(level+1) links); from level 10 on, the optimal parser
/// `encodeOpt`. A match at `ip` is replaced by a longer one a byte later (up
/// to two bytes of lookahead), then written.
pub fn encodeHc(
    buf: []const u8,
    start: usize,
    end: usize,
    history_start: usize,
    t: *HcTable,
    level: u8,
    dst: []u8,
) error{NoSpaceLeft}!usize {
    std.debug.assert(history_start <= start and start <= end and end <= buf.len);
    std.debug.assert(end <= std.math.maxInt(u32));
    if (level >= opt_min_level) return encodeOpt(buf, start, end, history_start, t, level, dst);
    var s: Sink = .{ .dst = dst };
    const attempts = hcAttempts(level);
    var anchor = start;
    if (t.next < history_start) t.next = history_start;
    if (end - start >= mf_limit + 1) {
        const match_limit = end - mf_limit; // a match starts at or before this
        const extend_limit = end - last_literals; // and ends at or before this
        var ip = start;
        while (ip <= match_limit) {
            hcInsert(t, buf, ip);
            var m = hcLongest(t, buf, ip, extend_limit, @max(history_start, ip -| max_offset), attempts, min_match - 1) orelse {
                ip += 1;
                continue;
            };
            // Lazy: a longer match one or two bytes on wins; the bytes skipped
            // become literals.
            var look: u8 = 0;
            while (look < 2 and ip + 1 <= match_limit) : (look += 1) {
                hcInsert(t, buf, ip + 1);
                const m2 = hcLongest(t, buf, ip + 1, extend_limit, @max(history_start, ip + 1 -| max_offset), attempts, m.len) orelse break;
                ip += 1;
                m = m2;
                look = 0; // a new anchor of comparison: two more bytes of lookahead
                if (m.len >= 256) break; // long enough: stop looking
            }
            var cand = m.cand;
            var len = m.len;
            // Extend backwards into the pending literals.
            if (ip > anchor and cand > history_start) {
                const k = backExtend(buf, ip, cand, @min(ip - anchor, cand - history_start));
                ip -= k;
                cand -= k;
                len += k;
            }
            try s.matchSequence(buf, anchor, ip - anchor, @intCast(ip - cand), len);
            ip += len;
            anchor = ip;
        }
    }
    try s.sequence(buf[anchor..end], null, 0);
    return s.at;
}

// ── optimal parser (levels 10..12) ──────────────────────────────────────

pub const opt_min_level = 10;
/// How far the parse looks ahead before it commits what it has.
const opt_window = 2048;
/// A match this long is taken without weighing it (liblz4's `targetLength` of
/// the level: 64, 128 and its `LZ4_OPT_NUM` of 4096).
fn optTarget(level: u8) usize {
    return switch (level) {
        10 => 64,
        11 => 128,
        else => 4096,
    };
}
/// Chain links followed per position: liblz4's 96, 512 and 16384 at levels
/// 10..12. This chain search gets less out of each link than liblz4's finder,
/// so levels 10 and 11 can come out a little larger than `lz4 -10` / `-11`.
fn optAttempts(level: u8) u32 {
    return switch (level) {
        10 => 96,
        11 => 512,
        else => 16384,
    };
}

/// Bytes the literals of a run of `ll` take: themselves and the length bytes
/// past the token's 15.
inline fn litPrice(ll: u32) u32 {
    return ll + (if (ll >= 15) 1 + (ll - 15) / 255 else 0);
}

/// Bytes of a whole sequence: token, two offset bytes, the literals, the
/// match length bytes past the token's 15 (the match length minus 4).
inline fn seqPrice(ll: u32, ml: u32) u32 {
    return 3 + litPrice(ll) + (if (ml >= 19) (ml - 19) / 255 + 1 else 0);
}

const OptNode = struct {
    /// Bytes to code everything before this position, the pending literals
    /// (`litlen`) included but not the token that will follow them.
    price: u32,
    litlen: u32,
    /// The match that ends here (0: this position was reached by a literal).
    mlen: u16,
    off: u16,
};

const OptSeq = struct { start: u32, len: u32, off: u32 };

/// Write one sequence of the chosen path, taking the match back into the
/// literals before it as far as they agree (every byte so saved is a byte
/// fewer to write).
fn emitOptSeq(s: *Sink, buf: []const u8, anchor: *usize, history_start: usize, sq: OptSeq) error{NoSpaceLeft}!void {
    var st: usize = sq.start;
    var cand: usize = st - sq.off;
    var len: usize = sq.len;
    if (st > anchor.* and cand > history_start) {
        const k = backExtend(buf, st, cand, @min(st - anchor.*, cand - history_start));
        st -= k;
        cand -= k;
        len += k;
    }
    try s.matchSequence(buf, anchor.*, st - anchor.*, @intCast(st - cand), len);
    anchor.* = st + len;
}

/// Optimal parsing for levels 10..12: a dynamic programme over the next
/// `opt_window` positions that prices every way to reach each one (a literal
/// from the previous position, or a match of any length from an earlier one)
/// in the bytes the format spends, and commits the cheapest path. The match
/// finder is the chain search of `encodeHc` (`optAttempts` links); a match at
/// least `optTarget` long is taken at once. Offsets all cost two bytes, so one
/// longest match per position stands for every shorter length at it.
fn encodeOpt(
    buf: []const u8,
    start: usize,
    end: usize,
    history_start: usize,
    t: *HcTable,
    level: u8,
    dst: []u8,
) error{NoSpaceLeft}!usize {
    var s: Sink = .{ .dst = dst };
    var anchor = start;
    if (t.next < history_start) t.next = history_start;
    if (end - start >= mf_limit + 1) {
        const attempts = optAttempts(level);
        const target = optTarget(level);
        const match_limit = end - mf_limit; // a match starts at or before this
        const extend_limit = end - last_literals; // and ends at or before this
        var nodes: [opt_window + 4096 + 2]OptNode = undefined;
        var path: [(opt_window + 4096) / min_match + 2]OptSeq = undefined;
        var ip = start;
        while (ip <= match_limit) {
            hcInsert(t, buf, ip);
            const first = hcLongest(t, buf, ip, extend_limit, @max(history_start, ip -| max_offset), attempts, min_match - 1) orelse {
                ip += 1;
                continue;
            };
            var npath: usize = 0;
            const ll0: u32 = @intCast(ip - anchor);
            nodes[0] = .{ .price = litPrice(ll0), .litlen = ll0, .mlen = 0, .off = 0 };
            var last_pos: usize = 0;
            var cur: usize = 0;
            var end_pos: usize = 0; // where the committed path ends (relative to ip)
            var forced: ?OptSeq = null; // a match taken without weighing it
            var m: ?HcMatch = first;
            while (true) {
                const p = ip + cur;
                if (cur > 0) {
                    m = null;
                    if (p <= match_limit) {
                        hcInsert(t, buf, p);
                        m = hcLongest(t, buf, p, extend_limit, @max(history_start, p -| max_offset), attempts, min_match - 1);
                    }
                }
                const n = nodes[cur];
                if (m) |mm| {
                    if (mm.len >= target) {
                        forced = .{ .start = @intCast(p), .len = @intCast(mm.len), .off = @intCast(p - mm.cand) };
                        end_pos = cur;
                        break;
                    }
                    const base = n.price - litPrice(n.litlen);
                    var ml: usize = min_match;
                    while (ml <= mm.len) : (ml += 1) {
                        const price = base + seqPrice(n.litlen, @intCast(ml));
                        const at = cur + ml;
                        if (at > last_pos) {
                            // Positions this match skips over are reached by literals only.
                            var q = last_pos + 1;
                            while (q < at) : (q += 1) nodes[q] = .{ .price = std.math.maxInt(u32), .litlen = 0, .mlen = 0, .off = 0 };
                            nodes[at] = .{ .price = price, .litlen = 0, .mlen = @intCast(ml), .off = @intCast(p - mm.cand) };
                            last_pos = at;
                        } else if (price < nodes[at].price) {
                            nodes[at] = .{ .price = price, .litlen = 0, .mlen = @intCast(ml), .off = @intCast(p - mm.cand) };
                        }
                    }
                }
                if (cur >= last_pos or cur + 1 >= opt_window) {
                    end_pos = last_pos;
                    break;
                }
                // The literal way to the next position.
                const lit = n.price + litPrice(n.litlen + 1) - litPrice(n.litlen);
                if (lit < nodes[cur + 1].price) {
                    nodes[cur + 1] = .{ .price = lit, .litlen = n.litlen + 1, .mlen = 0, .off = 0 };
                }
                cur += 1;
            }
            // Walk back from the end to the sequences, newest first.
            var pos = end_pos;
            while (pos > 0) {
                const nd = nodes[pos];
                if (nd.mlen > 0) {
                    path[npath] = .{ .start = @intCast(ip + pos - nd.mlen), .len = nd.mlen, .off = nd.off };
                    npath += 1;
                    pos -= nd.mlen;
                } else pos -= 1;
            }
            // Emit oldest first, the match taken without weighing last.
            const before = anchor;
            var i = npath;
            while (i > 0) {
                i -= 1;
                try emitOptSeq(&s, buf, &anchor, history_start, path[i]);
            }
            if (forced) |f| try emitOptSeq(&s, buf, &anchor, history_start, f);
            if (anchor > before) ip = anchor else ip += 1;
        }
    }
    try s.sequence(buf[anchor..end], null, 0);
    return s.at;
}

// ── dictionaries ────────────────────────────────────────────────────────

/// The part of `dict` a block can use: its last 64 KiB - 1 bytes, the reach
/// of an offset (liblz4's `LZ4_loadDict` keeps the same).
pub fn dictTail(dict: []const u8) []const u8 {
    return dict[dict.len -| max_offset..];
}

/// `compress` with `dict` as the bytes before `src`: matches may point into
/// it (liblz4's `LZ4_compress_fast_continue` after `LZ4_loadDict`). Only the
/// last 64 KiB - 1 of `dict` count. The block decodes with `decompressDict`
/// over the same dictionary. Allocates `dictTail(dict).len + src.len` bytes
/// of scratch (the encoder reads history and input from one buffer).
pub fn compressDict(
    gpa: std.mem.Allocator,
    src: []const u8,
    dict: []const u8,
    dst: []u8,
    opts: CompressOptions,
) (error{ NoSpaceLeft, InputTooLarge, OutOfMemory })!usize {
    if (src.len > max_input_size) return error.InputTooLarge;
    const d = dictTail(dict);
    if (d.len == 0) return compress(src, dst, opts) catch |e| return e;
    const buf = try gpa.alloc(u8, d.len + src.len);
    defer gpa.free(buf);
    @memcpy(buf[0..d.len], d);
    @memcpy(buf[d.len..], src);
    if (opts.hc_level >= hc_min_level) {
        // The matcher inserts the dictionary's positions itself (its first call
        // starts below them).
        const t = try gpa.create(HcTable);
        defer gpa.destroy(t);
        t.init();
        return encodeHc(buf, d.len, buf.len, 0, t, opts.hc_level, dst);
    }
    var table: Table = @splat(0);
    seedTable(buf[0..d.len], &table);
    return encodeRange(buf, d.len, buf.len, 0, &table, clampAcceleration(opts.acceleration), dst);
}

/// Seed `table` with the dictionary's positions, every third byte as liblz4's
/// `LZ4_loadDict` does (a coarser table is faster to build and finds nearly
/// the same matches, since the search also probes the byte after).
pub fn seedTable(d: []const u8, table: *Table) void {
    if (d.len < 4) return;
    var i: usize = 0;
    while (i + 4 <= d.len) : (i += 3) table[Wide.hash(read32(d, i))] = @intCast(i);
}

/// `decompress` of a block made with a dictionary (`compressDict`, or liblz4's
/// `LZ4_compress_fast_continue` / python-lz4's `dict=`): offsets may reach
/// into `dict`'s last 64 KiB - 1 bytes. Allocates that plus `dst.len` bytes
/// of scratch (the decoder reads history and output from one buffer).
pub fn decompressDict(gpa: std.mem.Allocator, src: []const u8, dict: []const u8, dst: []u8) (Error || error{OutOfMemory})!usize {
    const d = dictTail(dict);
    if (d.len == 0) return decompress(src, dst);
    const buf = try gpa.alloc(u8, d.len + dst.len);
    defer gpa.free(buf);
    @memcpy(buf[0..d.len], d);
    const end = try decodeInto(src, buf, d.len, 0);
    @memcpy(dst[0 .. end - d.len], buf[d.len..end]);
    return end - d.len;
}

/// `compress` at an HC level; out of line so the fast path's frame does not
/// carry the matcher's 192 KiB.
noinline fn compressHcStack(src: []const u8, dst: []u8, level: u8) error{NoSpaceLeft}!usize {
    var t: HcTable = undefined;
    t.init();
    return encodeHc(src, 0, src.len, 0, &t, level, dst);
}

// ── tests ───────────────────────────────────────────────────────────────

const testing = std.testing;

fn roundTrip(input: []const u8, accel: u32) !void {
    const gpa = testing.allocator;
    const z = try gpa.alloc(u8, compressBound(input.len));
    defer gpa.free(z);
    const zn = try compress(input, z, .{ .acceleration = accel });
    try testing.expect(zn <= compressBound(input.len));
    const back = try gpa.alloc(u8, input.len);
    defer gpa.free(back);
    try testing.expectEqual(input.len, try decompress(z[0..zn], back));
    try testing.expectEqualSlices(u8, input, back);
}

test "block: hand-built sequences decode" {
    var out: [64]u8 = undefined;
    // Literals only.
    try testing.expectEqual(@as(usize, 1), try decompress("\x10a", &out));
    try testing.expectEqualStrings("a", out[0..1]);
    // The empty block is a single zero token.
    try testing.expectEqual(@as(usize, 0), try decompress("\x00", &out));
    try testing.expectEqual(@as(usize, 0), try decompress("\x00", out[0..0]));
    // 'a', a match of 4 at offset 1, then 'b': overlap repeats the byte.
    try testing.expectEqual(@as(usize, 6), try decompress("\x10a\x01\x00\x10b", &out));
    try testing.expectEqualStrings("aaaaab", out[0..6]);
    // Offset 3 over "abc", length 4+15+1 = 20: a repeating pattern.
    try testing.expectEqual(@as(usize, 24), try decompress("\x3fabc\x03\x00\x01\x10z", &out));
    try testing.expectEqualStrings("abcabcabcabcabcabcabcabz", out[0..24]);
    // A 15-literal run needs the extension byte (0 here).
    try testing.expectEqual(@as(usize, 15), try decompress("\xf0\x00xxxxxxxxxxxxxxx", &out));
    // 15 + 255 + 2 literals: two extension bytes.
    var big: [3 + 272]u8 = undefined;
    big[0] = 0xf0;
    big[1] = 255;
    big[2] = 2;
    @memset(big[3..], 'q');
    var out2: [300]u8 = undefined;
    try testing.expectEqual(@as(usize, 272), try decompress(&big, &out2));
}

test "block: malformed blocks are typed errors" {
    var out: [64]u8 = undefined;
    try testing.expectError(error.Truncated, decompress("", &out));
    try testing.expectError(error.Truncated, decompress("\x20a", &out)); // literals past end
    try testing.expectError(error.Truncated, decompress("\xf0", &out)); // missing extension
    try testing.expectError(error.Truncated, decompress("\xf0\xff", &out)); // extension continues
    try testing.expectError(error.Truncated, decompress("\x10a\x01", &out)); // half an offset
    try testing.expectError(error.Truncated, decompress("\x10a\x01\x00", &out)); // ends with a match
    try testing.expectError(error.Truncated, decompress("\x1fa\x01\x00", &out)); // match length ext missing
    try testing.expectError(error.BadOffset, decompress("\x10a\x00\x00\x10b", &out)); // offset 0
    try testing.expectError(error.BadOffset, decompress("\x10a\x02\x00\x10b", &out)); // before the start
    try testing.expectError(error.BadOffset, decompress("\x00\x01\x00\x10b", &out)); // no history at all
    try testing.expectError(error.OutputTooSmall, decompress("\x30abc", out[0..2])); // literals
    try testing.expectError(error.OutputTooSmall, decompress("\x10a\x01\x00\x10b", out[0..4])); // match
    try testing.expectError(error.OutputTooSmall, decompress("\x10a\x01\x00\x10b", out[0..5])); // last literal
    // Trailing bytes after the literal-only sequence are a new token that
    // runs out: not silently ignored.
    try testing.expectError(error.Truncated, decompress("\x10ab", &out));
}

test "block: a match may reach into the history prefix and no further" {
    var out: [32]u8 = undefined;
    @memcpy(out[0..5], "hello");
    // At position 5 with history [0, 5): offset 5 length 4 = "hell", then "!".
    try testing.expectEqual(@as(usize, 10), try decodeInto("\x00\x05\x00\x10!", &out, 5, 0));
    try testing.expectEqualStrings("hellohell!", out[0..10]);
    // The same block with history [2, 5): offset 5 reaches before it.
    try testing.expectError(error.BadOffset, decodeInto("\x00\x05\x00\x10!", &out, 5, 2));
    try testing.expectEqual(@as(usize, 10), try decodeInto("\x00\x03\x00\x10!", &out, 5, 2));
    try testing.expectEqualStrings("llollol!", out[2..10]);
}

test "block: the fast loop's offset check against the history prefix" {
    // A sequence the fast loop takes (enough input and output left): three
    // literals and an 8-byte match whose offset is 0, reaches the oldest
    // history byte exactly, or one byte before the history.
    var hist: [256]u8 = undefined;
    for (&hist, 0..) |*c, i| c.* = @truncate(i *% 7 +% 3);
    const start = 100;
    const prefix_start = 40;
    const oldest = start + 3 - prefix_start;
    for ([_]usize{ 0, oldest, oldest + 1 }) |off| {
        var out = hist;
        var src: [1 + 3 + 2 + 2 + 20]u8 = undefined;
        src[0] = 0x34; // 3 literals, match length 4 + 4
        @memcpy(src[1..4], "xyz");
        src[4] = @truncate(off);
        src[5] = @truncate(off >> 8);
        src[6] = 0xf0; // the last sequence: 15 + 5 literals
        src[7] = 5;
        @memset(src[8..], 'q');
        const r = decodeInto(&src, &out, start, prefix_start);
        if (off == oldest) {
            try testing.expectEqual(@as(usize, start + 3 + 8 + 20), try r);
            try testing.expectEqualSlices(u8, hist[prefix_start..][0..8], out[start + 3 ..][0..8]);
        } else try testing.expectError(error.BadOffset, r);
    }
}

test "block: the encoder writes nothing past its output, and NoSpaceLeft exactly when it does not fit" {
    const gpa = testing.allocator;
    const shapes = @import("shapes.zig");
    var prng = std.Random.DefaultPrng.init(9);
    const r = prng.random();
    // Text, noisy text, runs, literal runs of 300 bytes between matches, and
    // a first sequence with over 20 length bytes each for its literals and
    // for its match (more than the 16 spare bytes of the room check).
    var lits: [4000]u8 = undefined;
    for (&lits, 0..) |*c, i| c.* = if (i % 400 < 300) r.int(u8) else "matchmatch"[i % 10];
    var long: [6000 + 6000 + 12]u8 = undefined;
    r.bytes(long[0..6000]);
    @memset(long[6000..12000], 0);
    for (long[12000..], 1..) |*c, i| c.* = @intCast(i);
    const inputs = [_]shapes.Shape{
        .{ .name = "text", .kind = .text, .len = 3000 },
        .{ .name = "noisy", .kind = .noisy_text, .len = 3000, .param = 8 },
        .{ .name = "runs", .kind = .runs, .len = 3000, .param = 300 },
    };
    var bufs: [inputs.len + 2][]u8 = undefined;
    for (inputs, 0..) |shape, i| bufs[i] = try shapes.generate(gpa, shape);
    bufs[inputs.len] = try gpa.dupe(u8, &lits);
    bufs[inputs.len + 1] = try gpa.dupe(u8, &long);
    defer for (bufs) |b| gpa.free(b);
    for (bufs) |input| {
        const full = try gpa.alloc(u8, compressBound(input.len));
        defer gpa.free(full);
        const z = try compress(input, full, .{});
        const dst = try gpa.alloc(u8, z + 64);
        defer gpa.free(dst);
        var cap = z -| 48;
        while (cap <= z + 48) : (cap += 1) {
            @memset(dst, 0xa5);
            if (compress(input, dst[0..cap], .{})) |n| {
                try testing.expectEqual(z, n);
                try testing.expectEqualSlices(u8, full[0..z], dst[0..z]);
                for (dst[z..]) |c| try testing.expectEqual(@as(u8, 0xa5), c);
            } else |e| {
                try testing.expectEqual(error.NoSpaceLeft, e);
                try testing.expect(cap < z);
            }
        }
    }
}

test "block: the u16 table up to liblz4's 64 KiB limit" {
    // Zeros, then 12 other bytes: one match ends exactly at the last
    // position a match may start (`len - 12`), so the search probes and
    // enters that position: 65535 for the last length that takes the u16
    // table, 65536 for the first that does not.
    const gpa = testing.allocator;
    for ([_]usize{ small_limit - 2, small_limit - 1, small_limit, small_limit + 1 }) |len| {
        const input = try gpa.alloc(u8, len);
        defer gpa.free(input);
        @memset(input, 0);
        for (input[len - 12 ..], 1..) |*c, i| c.* = @intCast(i);
        try roundTrip(input, 1);
    }
}

test "block: compressBound matches liblz4's macro" {
    try testing.expectEqual(@as(usize, 16), compressBound(0));
    try testing.expectEqual(@as(usize, 272), compressBound(255));
    try testing.expectEqual(@as(usize, 65536 + 257 + 16), compressBound(65536));
}

test "block: round trips over shapes and accelerations" {
    var buf: [70_000]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(7);
    const r = prng.random();
    for (0..13) |n| {
        for (buf[0..n], 0..) |*b, i| b.* = @intCast(i % 3);
        try roundTrip(buf[0..n], 1);
    }
    @memset(&buf, 'z');
    try roundTrip(&buf, 1);
    r.bytes(&buf);
    try roundTrip(&buf, 1);
    try roundTrip(&buf, 9);
    for (&buf, 0..) |*b, i| b.* = "the quick brown fox "[i % 20] ^ @as(u8, @intFromBool(r.uintLessThan(u8, 50) == 0));
    try roundTrip(&buf, 1);
    try roundTrip(&buf, 65537);
    try roundTrip(&buf, 0);
}

test "block: compressed sizes are those of a working matcher" {
    var buf: [65_536]u8 = undefined;
    @memset(&buf, 0);
    var z: [compressBound(65_536)]u8 = undefined;
    // All zeros: one literal, one long match, five literals.
    const n = try compress(&buf, &z, .{});
    try testing.expect(n < 300);
    // Incompressible: within the bound, larger than the input.
    var prng = std.Random.DefaultPrng.init(1);
    prng.random().bytes(&buf);
    const m = try compress(&buf, &z, .{});
    try testing.expect(m > buf.len and m <= compressBound(buf.len));
}

test "block: the encoder honours the end-of-block rules" {
    // For every input, the last match ends no later than 5 bytes before the end
    // and starts at least 12 bytes before it. Walk the encoder's own output.
    var buf: [200]u8 = undefined;
    @memset(&buf, 'a');
    var z: [compressBound(200)]u8 = undefined;
    for (13..200) |len| {
        const zn = try compress(buf[0..len], &z, .{});
        var ip: usize = 0;
        var op: usize = 0;
        var last_match_start: usize = 0;
        var last_match_end: usize = 0;
        while (true) {
            const t = z[ip];
            ip += 1;
            var lit: usize = t >> 4;
            if (lit == 15) lit = try readLength(z[0..zn], &ip, 15);
            ip += lit;
            op += lit;
            if (ip == zn) break;
            ip += 2;
            var ml: usize = t & 15;
            if (ml == 15) ml = try readLength(z[0..zn], &ip, 15);
            last_match_start = op;
            op += ml + 4;
            last_match_end = op;
        }
        try testing.expectEqual(len, op);
        try testing.expect(last_match_start + mf_limit <= len);
        try testing.expect(last_match_end + last_literals <= len);
    }
}

test "block: output too small for the encoder is NoSpaceLeft" {
    var buf: [100]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(3);
    prng.random().bytes(&buf);
    var z: [50]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, compress(&buf, &z, .{}));
    try testing.expectError(error.NoSpaceLeft, compress("", z[0..0], .{}));
}

test "block: the 13-byte minimum and the window edge" {
    var z: [compressBound(3000)]u8 = undefined;
    // 12 bytes: literals only (1 token + 12). 13 zeros: 1 literal, a 7-byte
    // match ending 5 bytes before the end, 5 literals = 10 bytes.
    const zeros: [13]u8 = @splat(0);
    try testing.expectEqual(@as(usize, 13), try compress(zeros[0..12], &z, .{}));
    try testing.expectEqual(@as(usize, 10), try compress(&zeros, &z, .{}));
    // A 1000-byte repeat at offset 65535 is found; at 65536 it is out of
    // the window and the block stays (valid) literals.
    const shapes = @import("shapes.zig");
    var sizes: [2]usize = undefined;
    for ([_]u32{ 64_535, 64_536 }, 0..) |param, i| {
        const s: shapes.Shape = .{ .name = "far", .kind = .far_repeat, .len = 0, .param = param };
        const input = try testing.allocator.alloc(u8, shapes.length(s));
        defer testing.allocator.free(input);
        shapes.fill(s, input);
        const zz = try testing.allocator.alloc(u8, compressBound(input.len));
        defer testing.allocator.free(zz);
        sizes[i] = try compress(input, zz, .{});
        const back = try testing.allocator.alloc(u8, input.len);
        defer testing.allocator.free(back);
        try testing.expectEqual(input.len, try decompress(zz[0..sizes[i]], back));
        try testing.expectEqualSlices(u8, input, back);
    }
    try testing.expect(sizes[0] + 900 < sizes[1]);
}

test "block: a higher acceleration trades size for speed" {
    var buf: [65_536]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(4);
    const r = prng.random();
    for (&buf, 0..) |*c, i| c.* = if (r.uintLessThan(u8, 6) == 0) r.int(u8) else "acceleration knob "[i % 18];
    var z: [compressBound(65_536)]u8 = undefined;
    const slow = try compress(&buf, &z, .{});
    const fast = try compress(&buf, &z, .{ .acceleration = 64 });
    try testing.expect(fast > slow + 1000);
}
