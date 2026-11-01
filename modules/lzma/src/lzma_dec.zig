// SPDX-License-Identifier: MIT

//! The LZMA symbol decoder over a ring-buffer dictionary. The same state
//! machine liblzma's `lzma_decoder.c` implements (a range decoder over
//! adaptive bit models), written as a pull decoder: it reads the bytes it
//! needs from a `std.Io.Reader` as it goes, so there is nothing to suspend
//! except a match that does not fit the output window.

const std = @import("std");
const Reader = std.Io.Reader;
const c = @import("common.zig");

pub const RunError = error{ CorruptData, TruncatedInput, ReadFailed };

/// The dictionary: a ring of `buf.len` bytes. `buf.len` is a multiple of 16
/// whenever the ring can wrap, so `pos & 15` stays the position modulo 16
/// (the lp/pb position bits are at most four).
pub const Dict = struct {
    /// The ring. `overshoot` more bytes follow it in the allocation: a match
    /// copy may write (and read) up to that far past its end.
    buf: []u8,
    pos: usize = 0,
    /// The window: a distance must be below it. A ring that can wrap is
    /// `overshoot` bytes longer than its window, so the bytes a copy writes
    /// past its end are never ones a valid distance can still reach.
    win: usize = 0,
    /// The bytes valid before `pos` was last reset or wrapped; `full()` adds
    /// what was decoded since, so the hot loop need not count.
    base_full: usize = 0,

    pub fn reset(d: *Dict) void {
        d.pos = 0;
        d.base_full = 0;
    }

    /// Bytes written since the last reset, capped at the window: a match
    /// distance must be below it.
    pub inline fn full(d: *const Dict) usize {
        return @min(d.base_full + d.pos, d.win);
    }

    /// A copy of `n` bytes writes (and reads) fewer than this many bytes
    /// past `n`. A position `k < overshoot` bytes ahead of the write position
    /// is `buf.len - k - 1 >= win` bytes back, so no valid distance reads it.
    pub const overshoot = 16;

    /// The write position wraps to the start of the ring.
    pub fn wrap(d: *Dict) void {
        d.base_full = d.full();
        d.pos = 0;
    }

    pub inline fn prev(d: *const Dict) u8 {
        if (d.pos == 0 and d.base_full == 0) return 0;
        return d.buf[if (d.pos == 0) d.buf.len - 1 else d.pos - 1];
    }

    /// The byte `dist + 1` back (dist 0 = the last byte); `dist < full()`.
    pub inline fn at(d: *const Dict, dist: usize) u8 {
        const i = if (d.pos > dist) d.pos - dist - 1 else d.pos + d.buf.len - dist - 1;
        return d.buf[i];
    }

    pub inline fn put(d: *Dict, b: u8) void {
        d.buf[d.pos] = b;
        d.pos += 1;
    }

    inline fn move(comptime T: type, buf: []u8, dst: usize, src: usize) void {
        const sp: *align(1) const T = @ptrCast(buf[src..][0..@sizeOf(T)]);
        const dp: *align(1) T = @ptrCast(buf[dst..][0..@sizeOf(T)]);
        dp.* = sp.*;
    }

    /// Append `n` bytes that are `dist + 1` back; `n <= buf.len - pos`.
    inline fn copyMatch(d: *Dict, dist: usize, n: usize) void {
        if (n == 0) return;
        const len = d.buf.len;
        const pos = d.pos;
        var src = if (pos > dist) pos - dist - 1 else pos + len - dist - 1;
        d.pos = pos + n;
        const buf = d.buf;
        if (src + n <= len) {
            if (src + n <= pos or src >= pos + n) {
                // The areas are disjoint: whole 16-byte moves, the last one
                // running up to `overshoot - 1` bytes past the match (into
                // bytes no valid distance reaches, see `win`), so there is no
                // branch on the length (it mispredicts on every match). Each
                // move loads before it stores; a later move's source is never
                // an earlier move's destination (src + n <= pos, or the
                // source lies ahead of the whole destination).
                const V = @Vector(16, u8);
                const p = buf.ptr;
                var i: usize = 0;
                while (true) {
                    const v: V = @as(*align(1) const V, @ptrCast(p + src + i)).*;
                    @as(*align(1) V, @ptrCast(p + pos + i)).* = v;
                    i += 16;
                    if (i >= n) break;
                }
                return;
            }
            // Overlapping (a run or a short period): eight bytes at a time
            // when a chunk cannot overlap itself, the tail byte by byte.
            var i: usize = 0;
            if (dist >= 7 or src > pos) {
                while (i + 8 <= n) : (i += 8) {
                    const v = std.mem.readInt(u64, buf[src + i ..][0..8], .little);
                    std.mem.writeInt(u64, buf[pos + i ..][0..8], v, .little);
                }
            }
            while (i < n) : (i += 1) buf[pos + i] = buf[src + i];
        } else {
            var dst = pos;
            const end = pos + n;
            while (dst < end) : (dst += 1) {
                buf[dst] = buf[src];
                src += 1;
                if (src == len) src = 0;
            }
        }
    }
};

/// More than any single symbol can read (liblzma proves 20).
const fast_need = 24;

/// The bit trees in liblzma's x86-64 assembly (`treeAsm`). LLVM only: the
/// templates use operand modifiers and numeric local labels.
const use_asm = @import("builtin").cpu.arch == .x86_64 and @import("builtin").zig_backend != .stage2_x86_64;

const FastSrc = struct {
    /// The next unread byte; `fast_need` bytes are readable per symbol (the
    /// caller checks before each one).
    p: [*]const u8,
    inline fn next(s: *FastSrc) error{}!u8 {
        const v = s.p[0];
        s.p += 1;
        return v;
    }
};

const SlowSrc = struct {
    in: *Reader,
    budget: *u64,
    const E = error{ EndOfStream, ReadFailed, ChunkOverrun };
    fn next(s: *SlowSrc) E!u8 {
        if (s.budget.* == 0) return error.ChunkOverrun;
        const v = try s.in.takeByte();
        s.budget.* -= 1;
        return v;
    }
};

pub const Run = enum { limit, eopm };

/// The registers of the decoder: kept apart from the model so that the hot
/// loop can work on a local copy the optimiser keeps in machine registers.
const Regs = struct {
    range: u32,
    code: u32,
    state: u8,
    rep: [4]u32,
    /// Bytes of the current match not yet copied (the window was full).
    pending: u32,
};

pub const Lzma = struct {
    probs: c.Probs,
    r: Regs = .{ .range = 0xFFFF_FFFF, .code = 0, .state = 0, .rep = .{ 0, 0, 0, 0 }, .pending = 0 },
    lc: u5 = 0,
    lp: u5 = 0,
    pos_mask: usize = 0,

    pub fn pending(l: *const Lzma) u32 {
        return l.r.pending;
    }

    pub fn reset(l: *Lzma, p: c.Lclppb) void {
        l.lc = @intCast(p.lc);
        l.lp = @intCast(p.lp);
        l.pos_mask = (@as(usize, 1) << @intCast(p.pb)) - 1;
        l.probs.reset(p.lc, p.lp);
        l.r.state = 0;
        l.r.rep = .{ 0, 0, 0, 0 };
        l.r.pending = 0;
    }

    /// Start a range-coded run: five bytes, the first is zero.
    pub fn initRc(l: *Lzma, in: *Reader, budget: *u64) RunError!void {
        var s: SlowSrc = .{ .in = in, .budget = budget };
        const first = try slowByte(&s);
        if (first != 0) return error.CorruptData;
        var v: u32 = 0;
        for (0..4) |_| v = (v << 8) | try slowByte(&s);
        l.r.code = v;
        l.r.range = 0xFFFF_FFFF;
    }

    fn slowByte(s: *SlowSrc) RunError!u8 {
        return s.next() catch |e| switch (e) {
            error.EndOfStream => error.TruncatedInput,
            error.ReadFailed => error.ReadFailed,
            error.ChunkOverrun => error.CorruptData,
        };
    }

    inline fn norm(r: *Regs, src: anytype) !void {
        if (r.range < c.top_value) {
            r.range <<= 8;
            r.code = (r.code << 8) | try src.next();
        }
    }

    inline fn bit(r: *Regs, src: anytype, p: *u16) !u1 {
        try norm(r, src);
        const bound = (r.range >> c.prob_bits) * p.*;
        if (r.code < bound) {
            r.range = bound;
            p.* += (2048 - p.*) >> c.move_bits;
            return 0;
        }
        r.range -= bound;
        r.code -= bound;
        p.* -= p.* >> c.move_bits;
        return 1;
    }

    /// The same step without a branch on the decoded bit (the bits of a
    /// literal are close to random, so the branch is mispredicted a lot).
    inline fn bitSel(r: *Regs, src: anytype, p: *u16) !u1 {
        return bitSelP(r, src, p, p.*);
    }

    /// `bitSel` with the probability already loaded (`pv == p.*`): a bit
    /// tree loads both children of the next node before this bit is known,
    /// so the load is off the chain range -> bound -> bit -> next index.
    /// The refill is the plain branch: a select-based refill (read the byte
    /// whether or not it is needed) cost ~7 more instructions a bit, and
    /// LLVM turned it back into a branch anyway (measured 2026-10-31).
    inline fn bitSelP(r: *Regs, src: anytype, p: *u16, pv: u32) !u1 {
        try norm(r, src);
        const bound = (r.range >> c.prob_bits) * pv;
        // The borrow of code - bound is the 0 bit; it also gives the new code.
        const sb = @subWithOverflow(r.code, bound);
        const zero = sb[1] != 0;
        r.range = if (zero) bound else r.range -% bound;
        r.code = if (zero) r.code else sb[0];
        // A 1 bit: pv -= pv >> 5. A 0 bit: pv += (2048 - pv) >> 5, which is
        // pv -= (pv + 31 - 2048) >> 5 with an arithmetic shift; modulo 2^32
        // the logical shift gives the same low 16 bits. One select, no branch.
        const t: u32 = if (zero) pv +% c.move_offset else pv;
        p.* = @truncate(pv -% (t >> c.move_bits));
        return @intFromBool(!zero);
    }

    inline fn direct(r: *Regs, src: anytype, n: u32) !u32 {
        var v: u32 = 0;
        var k = n;
        while (k > 0) : (k -= 1) {
            try norm(r, src);
            r.range >>= 1;
            // code < 2 * range here, so the difference is a 31-bit value
            // whose sign bit tells the decoded bit (a cmov pair, as in
            // liblzma's assembly).
            const d = r.code -% r.range;
            const one = @as(i32, @bitCast(d)) >= 0;
            r.code = if (one) d else r.code;
            v = if (one) (v << 1) + 1 else v << 1;
        }
        return v;
    }

    /// `rc_asm_normalize`: the refill as a short forward branch; the new
    /// byte is moved into the low byte the shift just cleared.
    const norm_s =
        "cmpl $0x1000000, %[range]\n\t" ++
        "jae 1f\n\t" ++
        "shll $8, %[code]\n\t" ++
        "movb (%[in_ptr]), %[code:b]\n\t" ++
        "shll $8, %[range]\n\t" ++
        "incq %[in_ptr]\n" ++
        "1:\n\t";

    /// `rc_asm_calc`: bound into `range`, both candidate results kept.
    const calc_s =
        "movl %[range], %[t0]\n\t" ++
        "shrl $11, %[range]\n\t" ++
        "imull %[prob], %[range]\n\t" ++
        "subl %[range], %[t0]\n\t" ++
        "movl %[code], %[t1]\n\t" ++
        "subl %[range], %[code]\n\t";

    /// liblzma's `rc_asm_matched_literal`: one bit of a literal coded
    /// against the byte at rep0.
    fn matchedAsm() []const u8 {
        var out: []const u8 = "";
        for (0..8) |k| {
            const nonlast = k < 7;
            out = out ++ "addl %[offset], %[symbol]\n\t" ++
                "andl %[offset], %[match_bit]\n\t" ++
                "addl %[match_bit], %[symbol]\n\t" ++
                "movzwl (%[probs], %[symbol:q], 2), %[prob]\n\t" ++
                "addl %[symbol], %[symbol]\n\t";
            if (nonlast) out = out ++ "xorl %[match_bit], %[offset]\n\t" ++
                "addl %[match_byte], %[match_byte]\n\t";
            out = out ++ norm_s ++ calc_s ++
                "cmovael %[t0], %[range]\n\t" ++
                "leal -2017(%[prob:q]), %[t0]\n\t" ++
                "cmovbl %[t1], %[code]\n\t" ++
                "movl %[symbol], %[t1]\n\t" ++
                "cmovael %[prob], %[t0]\n\t";
            if (nonlast) out = out ++ "cmovael %[match_bit], %[offset]\n\t" ++
                "movl %[match_byte], %[match_bit]\n\t";
            out = out ++ "sbbl $-1, %[symbol]\n\t" ++
                "shrl $5, %[t0]\n\t" ++
                "andl $0x1FF, %[symbol]\n\t" ++
                "subl %[t0], %[prob]\n\t" ++
                "movw %[prob:w], (%[probs], %[t1:q], 1)\n\t";
        }
        return out;
    }

    inline fn matchedLiteralAsm(r: *Regs, src: *FastSrc, probs: [*]u16, match_byte: u8) u32 {
        var range = r.range;
        var code = r.code;
        var ip = src.p;
        var t0: u32 = undefined;
        var t1: u32 = undefined;
        var prob: u32 = undefined;
        var mbyte: u32 = @as(u32, match_byte) << 1;
        var mbit: u32 = mbyte;
        var offset: u32 = 0x100;
        var sv: u32 = 1;
        asm volatile (matchedAsm()
            : [range] "+&r" (range),
              [code] "+&r" (code),
              [t0] "=&r" (t0),
              [t1] "=&r" (t1),
              [prob] "=&r" (prob),
              [match_bit] "+&r" (mbit),
              [symbol] "+&r" (sv),
              [match_byte] "+&r" (mbyte),
              [offset] "+&r" (offset),
              [in_ptr] "+&r" (ip),
            : [probs] "r" (probs),
            : .{ .cc = true, .memory = true });
        r.range = range;
        r.code = code;
        src.p = ip;
        return sv;
    }

    /// liblzma's `rc_direct` loop: `n` (>= 1) bits at probability one half
    /// shifted into `dest`.
    inline fn directAsm(r: *Regs, src: *FastSrc, dest_in: u32, n: u32) u32 {
        var range = r.range;
        var code = r.code;
        var ip = src.p;
        var t0: u32 = undefined;
        var t1: u32 = undefined;
        var dest = dest_in;
        var count = n;
        asm volatile ("2:\n\t" ++
                "addl %[dest], %[dest]\n\t" ++
                "leal 1(%[dest:q]), %[t1]\n\t" ++
                norm_s ++
                "shrl $1, %[range]\n\t" ++
                "movl %[code], %[t0]\n\t" ++
                "subl %[range], %[code]\n\t" ++
                "cmovnsl %[t1], %[dest]\n\t" ++
                "cmovsl %[t0], %[code]\n\t" ++
                "decl %[count]\n\t" ++
                "jnz 2b\n\t"
            : [range] "+&r" (range),
              [code] "+&r" (code),
              [t0] "=&r" (t0),
              [t1] "=&r" (t1),
              [dest] "+&r" (dest),
              [count] "+&r" (count),
              [in_ptr] "+&r" (ip),
            :
            : .{ .cc = true, .memory = true });
        r.range = range;
        r.code = code;
        src.p = ip;
        return dest;
    }

    /// liblzma's x86-64 bit-tree step (`rc_asm_bittree` in
    /// `rangecoder/range_decoder.h`, 0BSD; see NOTICE): the range coder's
    /// registers stay in machine registers across all `bits` steps, the
    /// refill is the short branch, the next node's two probabilities are
    /// loaded before the bit is known and one is picked by CMOV on the
    /// carry of `code - bound`, which is also the (negated) decoded bit.
    /// The template alternates two probability registers so that no move
    /// is needed between steps. Returns the leaf index + `final_add`.
    fn bittreeAsm(comptime bits: u5, comptime final_add: i32) []const u8 {
        // One bit would preload probs[2..3] past a two-entry tree.
        if (bits < 2) @compileError("bittreeAsm needs at least two bits");
        const calc = struct {
            fn f(comptime a: []const u8) []const u8 {
                return "movl %[range], %[t0]\n\t" ++
                    "shrl $11, %[range]\n\t" ++
                    "imull %[prob" ++ a ++ "], %[range]\n\t" ++
                    "subl %[range], %[t0]\n\t" ++
                    "movl %[code], %[t1]\n\t" ++
                    "subl %[range], %[code]\n\t";
            }
        }.f;
        var out: []const u8 = "";
        for (0..bits) |k| {
            const a = if (k % 2 == 0) "0" else "1";
            const b = if (k % 2 == 0) "1" else "0";
            const first = k == 0;
            const last = k + 1 == bits;
            if (first) {
                out = out ++ "movzwl 2(%[probs]), %[prob" ++ a ++ "]\n\t" ++
                    "movl $2, %[symbol]\n\t" ++
                    "movzwl 4(%[probs]), %[prob" ++ b ++ "]\n\t";
            } else if (!last) {
                out = out ++ "movzwl (%[probs], %[symbol:q], 4), %[prob" ++ b ++ "]\n\t";
            } else {
                out = out ++ "addl %[symbol], %[symbol]\n\t";
            }
            out = out ++ norm_s ++ calc(a) ++ "cmovael %[t0], %[range]\n\t";
            if (first) {
                out = out ++ "movzwl 6(%[probs]), %[t0]\n\t" ++
                    "cmovael %[t0], %[prob" ++ b ++ "]\n\t";
            } else if (!last) {
                out = out ++ "movzwl 2(%[probs], %[symbol:q], 4), %[t0]\n\t" ++
                    "leal (%[symbol:q], %[symbol:q]), %[symbol]\n\t" ++
                    "cmovael %[t0], %[prob" ++ b ++ "]\n\t";
            }
            out = out ++ "leal -2017(%[prob" ++ a ++ ":q]), %[t0]\n\t" ++
                "cmovbl %[t1], %[code]\n\t" ++
                "movl %[symbol], %[t1]\n\t" ++
                "cmovael %[prob" ++ a ++ "], %[t0]\n\t";
            if (!last) {
                out = out ++ "sbbl $-1, %[symbol]\n\t";
            } else {
                out = out ++ std.fmt.comptimePrint("sbbl ${d}, %[symbol]\n\t", .{-1 - final_add});
            }
            out = out ++ "shrl $5, %[t0]\n\t" ++
                "subl %[t0], %[prob" ++ a ++ "]\n\t" ++
                "movw %[prob" ++ a ++ ":w], (%[probs], %[t1:q], 1)\n\t";
        }
        return out;
    }

    inline fn treeAsm(r: *Regs, src: *FastSrc, probs: [*]u16, comptime bits: u5, comptime final_add: i32) u32 {
        var range = r.range;
        var code = r.code;
        var ip = src.p;
        var sv: u32 = undefined;
        var t0: u32 = undefined;
        var t1: u32 = undefined;
        var p0: u32 = undefined;
        var p1: u32 = undefined;
        asm volatile (bittreeAsm(bits, final_add)
            : [range] "+&r" (range),
              [code] "+&r" (code),
              [t0] "=&r" (t0),
              [t1] "=&r" (t1),
              [prob0] "=&r" (p0),
              [prob1] "=&r" (p1),
              [symbol] "=&r" (sv),
              [in_ptr] "+&r" (ip),
            : [probs] "r" (probs),
            : .{ .cc = true, .memory = true });
        r.range = range;
        r.code = code;
        src.p = ip;
        return sv;
    }

    inline fn tree(r: *Regs, src: anytype, probs: []u16, comptime bits: u5) !u32 {
        if (comptime use_asm and @TypeOf(src.*) == FastSrc)
            return treeAsm(r, src, probs.ptr, bits, -(@as(i32, 1) << bits));
        var m: u32 = 1;
        var pv: u32 = probs[1];
        inline for (0..bits) |k| {
            const n0: u32 = if (k + 1 < bits) probs[2 * m] else 0;
            const n1: u32 = if (k + 1 < bits) probs[2 * m + 1] else 0;
            const b = try bitSelP(r, src, &probs[m], pv);
            m = (m << 1) | b;
            pv = if (b == 1) n1 else n0;
        }
        return m - (1 << bits);
    }

    inline fn lenDecode(r: *Regs, src: anytype, lp: *c.LenProbs, pos_state: usize) !u32 {
        if (try bit(r, src, &lp.choice) == 0)
            return c.match_len_min + try tree(r, src, &lp.low[pos_state], 3);
        if (try bit(r, src, &lp.choice2) == 0)
            return c.match_len_min + c.len_low_symbols + try tree(r, src, &lp.mid[pos_state], 3);
        return c.match_len_min + c.len_low_symbols + c.len_mid_symbols + try tree(r, src, &lp.high, 8);
    }

    /// One symbol. `target` is the position the caller wants to stop at: a
    /// symbol that would write at or past it is only legal as the end marker.
    inline fn symbol(l: *Lzma, r: *Regs, dict: *Dict, src: anytype, target: usize, eopm_ok: bool) !Run {
        const pos_state = dict.pos & l.pos_mask;
        const st = r.state;
        if (try bit(r, src, &l.probs.is_match[st][pos_state]) == 0) {
            if (dict.pos >= target) return error.CorruptData;
            const mask: usize = (@as(usize, 0x100) << l.lp) - (@as(usize, 0x100) >> l.lc);
            const sub = (((dict.pos << 8) + dict.prev()) & mask) << l.lc;
            const probs = l.probs.literal[sub * 3 ..][0..c.literal_coder_size];
            var sym: u32 = 1;
            if (comptime use_asm and @TypeOf(src.*) == FastSrc) {
                if (c.isLiteralState(st)) {
                    sym = treeAsm(r, src, probs.ptr, 8, 0);
                    r.state = c.updateLiteral(st);
                    dict.put(@truncate(sym));
                    return .limit;
                }
            }
            if (c.isLiteralState(st)) {
                var pv: u32 = probs[1];
                inline for (0..8) |k| {
                    // Both children of the next node, loaded before this bit is known.
                    const n0: u32 = if (k < 7) probs[2 * sym] else 0;
                    const n1: u32 = if (k < 7) probs[2 * sym + 1] else 0;
                    const b = try bitSelP(r, src, &probs[sym], pv);
                    sym = (sym << 1) | b;
                    pv = if (b == 1) n1 else n0;
                }
            } else if (comptime use_asm and @TypeOf(src.*) == FastSrc) {
                sym = matchedLiteralAsm(r, src, probs.ptr, dict.at(r.rep[0]));
            } else {
                var match: u32 = @as(u32, dict.at(r.rep[0])) << 1;
                var offset: u32 = 0x100;
                inline for (0..8) |_| {
                    const match_bit = match & offset;
                    const b = try bitSel(r, src, &probs[offset + match_bit + sym]);
                    sym = (sym << 1) | b;
                    offset &= if (b == 1) match_bit else ~match_bit;
                    match <<= 1;
                }
            }
            r.state = c.updateLiteral(st);
            dict.put(@truncate(sym));
            return .limit;
        }

        var len: u32 = undefined;
        if (try bit(r, src, &l.probs.is_rep[st]) == 0) {
            // A new distance.
            r.state = c.updateMatch(st);
            r.rep[3] = r.rep[2];
            r.rep[2] = r.rep[1];
            r.rep[1] = r.rep[0];
            len = try lenDecode(r, src, &l.probs.match_len, pos_state);
            const slot = try tree(r, src, &l.probs.dist_slot[c.distState(len)], 6);
            var rep0: u32 = undefined;
            if (slot < c.dist_model_start) {
                rep0 = slot;
            } else {
                const limit: u5 = @intCast((slot >> 1) - 1);
                rep0 = 2 | (slot & 1);
                if (slot < c.dist_model_end) {
                    rep0 <<= limit;
                    // The bit tree starts at probs[1]; the C original points
                    // one element before the array for it.
                    const base: usize = rep0 - slot;
                    var m: u32 = 1;
                    var i: u5 = 0;
                    while (i < limit) : (i += 1) {
                        const b = try bitSel(r, src, &l.probs.pos_special[base + m - 1]);
                        m = (m << 1) | b;
                        rep0 += @as(u32, b) << i;
                    }
                } else {
                    rep0 = if (comptime use_asm and @TypeOf(src.*) == FastSrc)
                        directAsm(r, src, rep0, limit - c.align_bits)
                    else
                        (rep0 << (limit - c.align_bits)) | try direct(r, src, limit - c.align_bits);
                    rep0 <<= c.align_bits;
                    var m: u32 = 1;
                    var i: u5 = 0;
                    while (i < c.align_bits) : (i += 1) {
                        const b = try bitSel(r, src, &l.probs.pos_align[m]);
                        m = (m << 1) | b;
                        rep0 += @as(u32, b) << i;
                    }
                    if (rep0 == c.eopm_distance) {
                        if (!eopm_ok) return error.CorruptData;
                        return .eopm;
                    }
                }
            }
            r.rep[0] = rep0;
            if (rep0 >= dict.full()) return error.CorruptData;
        } else {
            const full = dict.full();
            if (full == 0) return error.CorruptData;
            if (try bit(r, src, &l.probs.is_rep0[st]) == 0) {
                if (try bit(r, src, &l.probs.is_rep0_long[st][pos_state]) == 0) {
                    // Short repeat: one byte at rep0.
                    if (dict.pos >= target) return error.CorruptData;
                    if (r.rep[0] >= full) return error.CorruptData;
                    r.state = c.updateShortRep(st);
                    dict.put(dict.at(r.rep[0]));
                    return .limit;
                }
            } else {
                var dist: u32 = undefined;
                if (try bit(r, src, &l.probs.is_rep1[st]) == 0) {
                    dist = r.rep[1];
                } else {
                    if (try bit(r, src, &l.probs.is_rep2[st]) == 0) {
                        dist = r.rep[2];
                    } else {
                        dist = r.rep[3];
                        r.rep[3] = r.rep[2];
                    }
                    r.rep[2] = r.rep[1];
                }
                r.rep[1] = r.rep[0];
                r.rep[0] = dist;
            }
            r.state = c.updateLongRep(st);
            len = try lenDecode(r, src, &l.probs.rep_len, pos_state);
            if (r.rep[0] >= full) return error.CorruptData;
        }

        if (dict.pos >= target) return error.CorruptData;
        const n = @min(len, target - dict.pos);
        dict.copyMatch(r.rep[0], n);
        r.pending = len - @as(u32, @intCast(n));
        return .limit;
    }

    /// Decode symbols until `max_out` more bytes are in the dictionary (the
    /// caller keeps `dict.pos + max_out <= dict.buf.len`) or the end marker.
    /// `budget` counts the input bytes the stream may still use.
    pub fn run(l: *Lzma, dict: *Dict, in: *Reader, budget: *u64, max_out: usize, eopm_ok: bool) RunError!Run {
        const target = dict.pos + max_out;
        while (true) {
            if (l.r.pending > 0) {
                const n = @min(@as(usize, l.r.pending), target - dict.pos);
                dict.copyMatch(l.r.rep[0], n);
                l.r.pending -= @intCast(n);
            }
            if (dict.pos >= target) return .limit;

            if (in.buffer.len >= fast_need) {
                // One read at most: never wait for more than the next byte needs.
                if (in.bufferedLen() < fast_need) in.fillMore() catch |e| switch (e) {
                    error.ReadFailed => return error.ReadFailed,
                    error.EndOfStream => {},
                };
                const buffered = in.buffered();
                const avail: usize = @intCast(@min(buffered.len, budget.*));
                if (avail >= fast_need) {
                    // Local copies of the registers and the ring cursor.
                    const base = buffered.ptr;
                    const stop = base + (avail - fast_need);
                    var fs: FastSrc = .{ .p = base };
                    var regs = l.r;
                    var dl = dict.*;
                    var result: ?Run = null;
                    var failed = false;
                    while (dl.pos < target and @intFromPtr(fs.p) <= @intFromPtr(stop)) {
                        const res = l.symbol(&regs, &dl, &fs, target, eopm_ok) catch {
                            failed = true;
                            break;
                        };
                        if (res == .eopm) {
                            result = .eopm;
                            break;
                        }
                        if (regs.pending > 0) break;
                    }
                    l.r = regs;
                    dict.* = dl;
                    if (failed) return error.CorruptData;
                    const used = @intFromPtr(fs.p) - @intFromPtr(base);
                    in.toss(used);
                    budget.* -= used;
                    if (result) |res| return res;
                    continue;
                }
            }

            var ss: SlowSrc = .{ .in = in, .budget = budget };
            const res = l.symbol(&l.r, dict, &ss, target, eopm_ok) catch |e| switch (e) {
                error.EndOfStream => return error.TruncatedInput,
                error.ReadFailed => return error.ReadFailed,
                error.ChunkOverrun, error.CorruptData => return error.CorruptData,
            };
            if (res == .eopm) return .eopm;
        }
    }

    /// After the last byte of a stream whose size was known: the next symbol
    /// must be the end marker.
    pub fn endMarker(l: *Lzma, dict: *Dict, in: *Reader, budget: *u64) RunError!void {
        var ss: SlowSrc = .{ .in = in, .budget = budget };
        const res = l.symbol(&l.r, dict, &ss, dict.pos, true) catch |e| switch (e) {
            error.EndOfStream => return error.TruncatedInput,
            error.ReadFailed => return error.ReadFailed,
            error.ChunkOverrun, error.CorruptData => return error.CorruptData,
        };
        if (res != .eopm) return error.CorruptData;
    }

    /// After the last byte: read the byte a final normalisation may need and
    /// report whether the range coder is in its clean end state (code == 0).
    pub fn finished(l: *Lzma, in: *Reader, budget: *u64) RunError!bool {
        var ss: SlowSrc = .{ .in = in, .budget = budget };
        norm(&l.r, &ss) catch |e| switch (e) {
            error.EndOfStream => return error.TruncatedInput,
            error.ReadFailed => return error.ReadFailed,
            error.ChunkOverrun => return error.CorruptData,
        };
        return l.r.code == 0;
    }
};
