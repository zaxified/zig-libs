// SPDX-License-Identifier: MIT

//! The encoder's input window and match finders, a port of liblzma's
//! `lz_encoder.c` / `lz_encoder_mf.c`: a sliding buffer, hash chains (hc3,
//! hc4) and binary trees (bt2, bt3, bt4) over a cyclic array. Positions are
//! 32-bit, offset so that 0 means "empty", and normalised before they wrap.
//!
//! The data structures, the search order and every limit are liblzma's on
//! purpose: the optimal parser's choices depend on exactly which matches
//! the finder reports, so byte parity needs the finder to be the same.

const std = @import("std");

pub const MatchFinder = enum(u8) {
    hc3 = 0x03,
    hc4 = 0x04,
    bt2 = 0x12,
    bt3 = 0x13,
    bt4 = 0x14,

    pub fn hashBytes(m: MatchFinder) u32 {
        return @backingInt(m) & 0x0F;
    }
    fn isBt(m: MatchFinder) bool {
        return @backingInt(m) & 0x10 != 0;
    }
};

pub const Action = enum { run, finish };

pub const Match = struct { len: u32, dist: u32 };

pub const Options = struct {
    before_size: u32,
    dict_size: u32,
    after_size: u32,
    match_len_max: u32,
    nice_len: u32,
    match_finder: MatchFinder,
    depth: u32,
};

pub const dict_size_min = 4096;
pub const dict_size_max: u32 = (1 << 30) + (1 << 29);

const hash_2_size = 1 << 10;
const hash_3_size = 1 << 16;
const hash_2_mask = hash_2_size - 1;
const hash_3_mask = hash_3_size - 1;
const fix_3_hash_size = hash_2_size;
const fix_4_hash_size = hash_2_size + hash_3_size;
const memcmplen_extra = 16;
const must_normalize_pos = std.math.maxInt(u32);

/// `lzma_crc32_table[0]`, which liblzma uses to scramble the hash bytes.
const hash_table: [256]u32 = blk: {
    @setEvalBranchQuota(10_000);
    var t: [256]u32 = undefined;
    for (&t, 0..) |*e, i| {
        var v: u32 = @intCast(i);
        for (0..8) |_| v = if (v & 1 != 0) (v >> 1) ^ 0xEDB8_8320 else v >> 1;
        e.* = v;
    }
    break :blk t;
};

pub const Mf = struct {
    buffer: []u8,
    size: u32,
    keep_size_before: u32,
    keep_size_after: u32,
    offset: u32 = 0,
    read_pos: u32 = 0,
    read_ahead: u32 = 0,
    read_limit: u32 = 0,
    write_pos: u32 = 0,
    pending: u32 = 0,
    hash: []u32,
    son: []u32,
    cyclic_pos: u32 = 0,
    cyclic_size: u32,
    hash_mask: u32,
    depth: u32,
    nice_len: u32,
    match_len_max: u32,
    action: Action = .run,
    kind: MatchFinder,

    pub const Error = error{ OutOfMemory, OptionsError };

    pub fn init(gpa: std.mem.Allocator, o: Options) Error!Mf {
        if (o.dict_size < dict_size_min or o.dict_size > dict_size_max or o.nice_len > o.match_len_max) return error.OptionsError;
        const keep_before = o.before_size + o.dict_size;
        const keep_after = o.after_size + o.match_len_max;
        var reserve: u32 = o.dict_size / 2;
        if (reserve > (1 << 30)) reserve /= 2;
        reserve += (o.before_size + o.match_len_max + o.after_size) / 2 + (1 << 19);
        const size = std.math.add(u32, std.math.add(u32, keep_before, reserve) catch return error.OptionsError, keep_after) catch return error.OptionsError;

        const hash_bytes = o.match_finder.hashBytes();
        const is_bt = o.match_finder.isBt();
        var hs: u32 = undefined;
        if (hash_bytes == 2) {
            hs = 0xFFFF;
        } else {
            hs = o.dict_size - 1;
            hs |= hs >> 1;
            hs |= hs >> 2;
            hs |= hs >> 4;
            hs |= hs >> 8;
            hs >>= 1;
            hs |= 0xFFFF;
            if (hs > (1 << 24)) {
                if (hash_bytes == 3) hs = (1 << 24) - 1 else hs >>= 1;
            }
        }
        const hash_mask = hs;
        hs += 1;
        if (hash_bytes > 2) hs += hash_2_size;
        if (hash_bytes > 3) hs += hash_3_size;
        const cyclic_size = o.dict_size + 1;
        const sons: usize = @as(usize, cyclic_size) * @as(usize, if (is_bt) 2 else 1);
        var depth = o.depth;
        if (depth == 0) depth = if (is_bt) 16 + o.nice_len / 2 else 4 + o.nice_len / 4;

        const buffer = try gpa.alloc(u8, @as(usize, size) + memcmplen_extra);
        errdefer gpa.free(buffer);
        @memset(buffer[size..], 0);
        const hash = try gpa.alloc(u32, hs);
        errdefer gpa.free(hash);
        @memset(hash, 0);
        const son = try gpa.alloc(u32, sons);
        return .{
            .buffer = buffer,
            .size = size,
            .keep_size_before = keep_before,
            .keep_size_after = keep_after,
            .offset = cyclic_size,
            .hash = hash,
            .son = son,
            .cyclic_size = cyclic_size,
            .hash_mask = hash_mask,
            .depth = depth,
            .nice_len = o.nice_len,
            .match_len_max = o.match_len_max,
            .kind = o.match_finder,
        };
    }

    pub fn deinit(mf: *Mf, gpa: std.mem.Allocator) void {
        gpa.free(mf.buffer);
        gpa.free(mf.hash);
        gpa.free(mf.son);
        mf.* = undefined;
    }

    // ── the window ──────────────────────────────────────────────────────

    fn moveWindow(mf: *Mf) void {
        const move_offset = (mf.read_pos - mf.keep_size_before) & ~@as(u32, 15);
        const move_size = mf.write_pos - move_offset;
        std.mem.copyForwards(u8, mf.buffer[0..move_size], mf.buffer[move_offset..][0..move_size]);
        mf.offset +%= move_offset;
        mf.read_pos -= move_offset;
        mf.read_limit -= move_offset;
        mf.write_pos -= move_offset;
    }

    /// Copy input into the window. Returns true when the end of the input has
    /// been reached under `action != .run` (the encoder may then use every
    /// byte).
    pub fn fillWindow(mf: *Mf, in: []const u8, in_pos: *usize, action: Action) bool {
        if (mf.read_pos >= mf.size - mf.keep_size_after) mf.moveWindow();
        const n = @min(in.len - in_pos.*, mf.size - mf.write_pos);
        @memcpy(mf.buffer[mf.write_pos..][0..n], in[in_pos.*..][0..n]);
        in_pos.* += n;
        mf.write_pos += @intCast(n);
        @memset(mf.buffer[mf.write_pos..][0..memcmplen_extra], 0);
        const end = action != .run and in_pos.* == in.len;
        if (end) {
            mf.action = action;
            mf.read_limit = mf.write_pos;
        } else if (mf.write_pos > mf.keep_size_after) {
            mf.read_limit = mf.write_pos - mf.keep_size_after;
        }
        return end;
    }

    pub inline fn avail(mf: *const Mf) u32 {
        return mf.write_pos - mf.read_pos;
    }
    pub inline fn unencoded(mf: *const Mf) u32 {
        return mf.write_pos - mf.read_pos + mf.read_ahead;
    }
    pub inline fn position(mf: *const Mf) u32 {
        return mf.read_pos - mf.read_ahead;
    }

    /// `lzma_memcmplen`: the common prefix of `buffer[a..]` and `buffer[b..]`,
    /// starting the comparison at `len` and stopping at `limit`.
    pub inline fn memcmplen(mf: *const Mf, a: usize, b: usize, len_in: u32, limit: u32) u32 {
        // Eight bytes at a time like liblzma's; the window ends in zero bytes
        // so the last word never reads out of the buffer, and the result is
        // clamped to `limit`.
        var len = len_in;
        const buf = mf.buffer;
        while (len < limit) {
            const x = std.mem.readInt(u64, buf[a + len ..][0..8], .little) ^ std.mem.readInt(u64, buf[b + len ..][0..8], .little);
            if (x != 0) {
                len += @as(u32, @ctz(x)) >> 3;
                break;
            }
            len += 8;
        }
        return @min(len, limit);
    }

    /// `mf_skip`: skip `amount` bytes and count them as read ahead.
    pub inline fn skipRa(mf: *Mf, amount: u32) void {
        if (amount != 0) {
            mf.skip(amount);
            mf.read_ahead += amount;
        }
    }

    /// `lzma_mf_find`: the matches at the next position, and the longest
    /// length (extended up to `match_len_max` when it reached `nice_len`).
    pub fn find(mf: *Mf, count_ptr: *u32, matches: []Match) u32 {
        const count = mf.findRaw(matches);
        var len_best: u32 = 0;
        if (count > 0) {
            len_best = matches[count - 1].len;
            if (len_best == mf.nice_len) {
                var limit = mf.avail() + 1;
                if (limit > mf.match_len_max) limit = mf.match_len_max;
                const p1: usize = mf.read_pos - 1;
                const p2: usize = p1 - matches[count - 1].dist - 1;
                len_best = mf.memcmplen(p1, p2, len_best, limit);
            }
        }
        count_ptr.* = count;
        mf.read_ahead += 1;
        return len_best;
    }

    fn findRaw(mf: *Mf, matches: []Match) u32 {
        return switch (mf.kind) {
            .hc3 => mf.hc3Find(matches),
            .hc4 => mf.hc4Find(matches),
            .bt2 => mf.bt2Find(matches),
            .bt3 => mf.bt3Find(matches),
            .bt4 => mf.bt4Find(matches),
        };
    }

    pub fn skip(mf: *Mf, amount: u32) void {
        switch (mf.kind) {
            .hc3 => mf.hc3Skip(amount),
            .hc4 => mf.hc4Skip(amount),
            .bt2 => mf.bt2Skip(amount),
            .bt3 => mf.bt3Skip(amount),
            .bt4 => mf.bt4Skip(amount),
        }
    }

    // ── shared pieces ───────────────────────────────────────────────────

    fn normalize(mf: *Mf) void {
        const subvalue = must_normalize_pos - mf.cyclic_size;
        for (mf.hash) |*h| h.* = if (h.* <= subvalue) 0 else h.* - subvalue;
        for (mf.son) |*s| s.* = if (s.* <= subvalue) 0 else s.* - subvalue;
        mf.offset -= subvalue;
    }

    inline fn movePos(mf: *Mf) void {
        mf.cyclic_pos += 1;
        if (mf.cyclic_pos == mf.cyclic_size) mf.cyclic_pos = 0;
        mf.read_pos += 1;
        if (mf.read_pos +% mf.offset == std.math.maxInt(u32)) mf.normalize();
    }

    inline fn movePending(mf: *Mf) void {
        mf.read_pos += 1;
        mf.pending += 1;
    }

    /// The `header` macro: the length limit, or null when too few bytes are
    /// left for this finder (the byte is then only counted as pending).
    inline fn header(mf: *Mf, len_min: u32) ?u32 {
        var len_limit = mf.avail();
        if (mf.nice_len <= len_limit) {
            len_limit = mf.nice_len;
        } else if (len_limit < len_min) {
            mf.movePending();
            return null;
        }
        return len_limit;
    }

    inline fn hash3(cur: []const u8, mask: u32) struct { h2: u32, h: u32 } {
        const temp = hash_table[cur[0]] ^ cur[1];
        return .{ .h2 = temp & hash_2_mask, .h = (temp ^ (@as(u32, cur[2]) << 8)) & mask };
    }

    inline fn hash4(cur: []const u8, mask: u32) struct { h2: u32, h3: u32, h: u32 } {
        const temp = hash_table[cur[0]] ^ cur[1];
        return .{
            .h2 = temp & hash_2_mask,
            .h3 = (temp ^ (@as(u32, cur[2]) << 8)) & hash_3_mask,
            .h = (temp ^ (@as(u32, cur[2]) << 8) ^ (hash_table[cur[3]] << 5)) & mask,
        };
    }

    // ── hash chains ─────────────────────────────────────────────────────

    /// `hc_find_func`: returns the new match count.
    fn hcFind(mf: *Mf, len_limit: u32, pos: u32, cur_pos: usize, cur_match_in: u32, matches: []Match, count_in: u32, len_best_in: u32) u32 {
        const son = mf.son;
        const cyclic_pos = mf.cyclic_pos;
        const cyclic_size = mf.cyclic_size;
        var cur_match = cur_match_in;
        var len_best = len_best_in;
        var count = count_in;
        var depth = mf.depth;
        son[cyclic_pos] = cur_match;
        while (true) {
            const delta = pos -% cur_match;
            if (depth == 0 or delta >= cyclic_size) return count;
            depth -= 1;
            const pb = cur_pos - delta;
            cur_match = son[cyclic_pos -% delta +% (if (delta > cyclic_pos) cyclic_size else 0)];
            if (mf.buffer[pb + len_best] == mf.buffer[cur_pos + len_best] and mf.buffer[pb] == mf.buffer[cur_pos]) {
                const len = mf.memcmplen(pb, cur_pos, 1, len_limit);
                if (len_best < len) {
                    len_best = len;
                    matches[count] = .{ .len = len, .dist = delta - 1 };
                    count += 1;
                    if (len == len_limit) return count;
                }
            }
        }
    }

    fn hc3Find(mf: *Mf, matches: []Match) u32 {
        const len_limit = mf.header(3) orelse return 0;
        const cur_pos: usize = mf.read_pos;
        const cur = mf.buffer[cur_pos..];
        const pos = mf.read_pos +% mf.offset;
        const h = hash3(cur, mf.hash_mask);
        const delta2 = pos -% mf.hash[h.h2];
        const cur_match = mf.hash[fix_3_hash_size + h.h];
        mf.hash[h.h2] = pos;
        mf.hash[fix_3_hash_size + h.h] = pos;
        var len_best: u32 = 2;
        var count: u32 = 0;
        if (delta2 < mf.cyclic_size and mf.buffer[cur_pos - delta2] == cur[0]) {
            len_best = mf.memcmplen(cur_pos - delta2, cur_pos, len_best, len_limit);
            matches[0] = .{ .len = len_best, .dist = delta2 - 1 };
            count = 1;
            if (len_best == len_limit) {
                mf.son[mf.cyclic_pos] = cur_match;
                mf.movePos();
                return 1;
            }
        }
        const n = mf.hcFind(len_limit, pos, cur_pos, cur_match, matches, count, len_best);
        mf.movePos();
        return n;
    }

    fn hc3Skip(mf: *Mf, amount_in: u32) void {
        var amount = amount_in;
        while (true) {
            if (mf.avail() < 3) {
                mf.movePending();
            } else {
                const cur = mf.buffer[mf.read_pos..];
                const pos = mf.read_pos +% mf.offset;
                const h = hash3(cur, mf.hash_mask);
                const cur_match = mf.hash[fix_3_hash_size + h.h];
                mf.hash[h.h2] = pos;
                mf.hash[fix_3_hash_size + h.h] = pos;
                mf.son[mf.cyclic_pos] = cur_match;
                mf.movePos();
            }
            amount -= 1;
            if (amount == 0) break;
        }
    }

    fn hc4Find(mf: *Mf, matches: []Match) u32 {
        const len_limit = mf.header(4) orelse return 0;
        const cur_pos: usize = mf.read_pos;
        const cur = mf.buffer[cur_pos..];
        const pos = mf.read_pos +% mf.offset;
        const h = hash4(cur, mf.hash_mask);
        var delta2 = pos -% mf.hash[h.h2];
        const delta3 = pos -% mf.hash[fix_3_hash_size + h.h3];
        const cur_match = mf.hash[fix_4_hash_size + h.h];
        mf.hash[h.h2] = pos;
        mf.hash[fix_3_hash_size + h.h3] = pos;
        mf.hash[fix_4_hash_size + h.h] = pos;
        var len_best: u32 = 1;
        var count: u32 = 0;
        if (delta2 < mf.cyclic_size and mf.buffer[cur_pos - delta2] == cur[0]) {
            len_best = 2;
            matches[0] = .{ .len = 2, .dist = delta2 - 1 };
            count = 1;
        }
        if (delta2 != delta3 and delta3 < mf.cyclic_size and mf.buffer[cur_pos - delta3] == cur[0]) {
            len_best = 3;
            matches[count].dist = delta3 - 1;
            count += 1;
            delta2 = delta3;
        }
        if (count != 0) {
            len_best = mf.memcmplen(cur_pos - delta2, cur_pos, len_best, len_limit);
            matches[count - 1].len = len_best;
            if (len_best == len_limit) {
                mf.son[mf.cyclic_pos] = cur_match;
                mf.movePos();
                return count;
            }
        }
        if (len_best < 3) len_best = 3;
        const n = mf.hcFind(len_limit, pos, cur_pos, cur_match, matches, count, len_best);
        mf.movePos();
        return n;
    }

    fn hc4Skip(mf: *Mf, amount_in: u32) void {
        var amount = amount_in;
        while (true) {
            if (mf.avail() < 4) {
                mf.movePending();
            } else {
                const cur = mf.buffer[mf.read_pos..];
                const pos = mf.read_pos +% mf.offset;
                const h = hash4(cur, mf.hash_mask);
                const cur_match = mf.hash[fix_4_hash_size + h.h];
                mf.hash[h.h2] = pos;
                mf.hash[fix_3_hash_size + h.h3] = pos;
                mf.hash[fix_4_hash_size + h.h] = pos;
                mf.son[mf.cyclic_pos] = cur_match;
                mf.movePos();
            }
            amount -= 1;
            if (amount == 0) break;
        }
    }

    // ── binary trees ────────────────────────────────────────────────────

    fn btFind(mf: *Mf, len_limit: u32, pos: u32, cur_pos: usize, cur_match_in: u32, matches: []Match, count_in: u32, len_best_in: u32) u32 {
        const son = mf.son;
        const cyclic_pos = mf.cyclic_pos;
        const cyclic_size = mf.cyclic_size;
        var cur_match = cur_match_in;
        var len_best = len_best_in;
        var count = count_in;
        var depth = mf.depth;
        var ptr0: usize = (@as(usize, cyclic_pos) << 1) + 1;
        var ptr1: usize = @as(usize, cyclic_pos) << 1;
        var len0: u32 = 0;
        var len1: u32 = 0;
        while (true) {
            const delta = pos -% cur_match;
            if (depth == 0 or delta >= cyclic_size) {
                son[ptr0] = 0;
                son[ptr1] = 0;
                return count;
            }
            depth -= 1;
            const pair: usize = @as(usize, cyclic_pos -% delta +% (if (delta > cyclic_pos) cyclic_size else 0)) << 1;
            const pb = cur_pos - delta;
            var len = @min(len0, len1);
            if (mf.buffer[pb + len] == mf.buffer[cur_pos + len]) {
                len = mf.memcmplen(pb, cur_pos, len + 1, len_limit);
                if (len_best < len) {
                    len_best = len;
                    matches[count] = .{ .len = len, .dist = delta - 1 };
                    count += 1;
                    if (len == len_limit) {
                        son[ptr1] = son[pair];
                        son[ptr0] = son[pair + 1];
                        return count;
                    }
                }
            }
            if (mf.buffer[pb + len] < mf.buffer[cur_pos + len]) {
                son[ptr1] = cur_match;
                ptr1 = pair + 1;
                cur_match = son[ptr1];
                len1 = len;
            } else {
                son[ptr0] = cur_match;
                ptr0 = pair;
                cur_match = son[ptr0];
                len0 = len;
            }
        }
    }

    fn btSkipFunc(mf: *Mf, len_limit: u32, pos: u32, cur_pos: usize, cur_match_in: u32) void {
        const son = mf.son;
        const cyclic_pos = mf.cyclic_pos;
        const cyclic_size = mf.cyclic_size;
        var cur_match = cur_match_in;
        var depth = mf.depth;
        var ptr0: usize = (@as(usize, cyclic_pos) << 1) + 1;
        var ptr1: usize = @as(usize, cyclic_pos) << 1;
        var len0: u32 = 0;
        var len1: u32 = 0;
        while (true) {
            const delta = pos -% cur_match;
            if (depth == 0 or delta >= cyclic_size) {
                son[ptr0] = 0;
                son[ptr1] = 0;
                return;
            }
            depth -= 1;
            const pair: usize = @as(usize, cyclic_pos -% delta +% (if (delta > cyclic_pos) cyclic_size else 0)) << 1;
            const pb = cur_pos - delta;
            var len = @min(len0, len1);
            if (mf.buffer[pb + len] == mf.buffer[cur_pos + len]) {
                len = mf.memcmplen(pb, cur_pos, len + 1, len_limit);
                if (len == len_limit) {
                    son[ptr1] = son[pair];
                    son[ptr0] = son[pair + 1];
                    return;
                }
            }
            if (mf.buffer[pb + len] < mf.buffer[cur_pos + len]) {
                son[ptr1] = cur_match;
                ptr1 = pair + 1;
                cur_match = son[ptr1];
                len1 = len;
            } else {
                son[ptr0] = cur_match;
                ptr0 = pair;
                cur_match = son[ptr0];
                len0 = len;
            }
        }
    }

    inline fn btSkip(mf: *Mf, len_limit: u32, pos: u32, cur_pos: usize, cur_match: u32) void {
        mf.btSkipFunc(len_limit, pos, cur_pos, cur_match);
        mf.movePos();
    }

    fn bt2Find(mf: *Mf, matches: []Match) u32 {
        const len_limit = mf.header(2) orelse return 0;
        const cur_pos: usize = mf.read_pos;
        const pos = mf.read_pos +% mf.offset;
        const hv: u32 = @as(u32, mf.buffer[cur_pos]) | (@as(u32, mf.buffer[cur_pos + 1]) << 8);
        const cur_match = mf.hash[hv];
        mf.hash[hv] = pos;
        const n = mf.btFind(len_limit, pos, cur_pos, cur_match, matches, 0, 1);
        mf.movePos();
        return n;
    }

    fn bt2Skip(mf: *Mf, amount_in: u32) void {
        var amount = amount_in;
        while (true) {
            if (mf.header(2)) |len_limit| {
                const cur_pos: usize = mf.read_pos;
                const pos = mf.read_pos +% mf.offset;
                const hv: u32 = @as(u32, mf.buffer[cur_pos]) | (@as(u32, mf.buffer[cur_pos + 1]) << 8);
                const cur_match = mf.hash[hv];
                mf.hash[hv] = pos;
                mf.btSkip(len_limit, pos, cur_pos, cur_match);
            }
            amount -= 1;
            if (amount == 0) break;
        }
    }

    fn bt3Find(mf: *Mf, matches: []Match) u32 {
        const len_limit = mf.header(3) orelse return 0;
        const cur_pos: usize = mf.read_pos;
        const cur = mf.buffer[cur_pos..];
        const pos = mf.read_pos +% mf.offset;
        const h = hash3(cur, mf.hash_mask);
        const delta2 = pos -% mf.hash[h.h2];
        const cur_match = mf.hash[fix_3_hash_size + h.h];
        mf.hash[h.h2] = pos;
        mf.hash[fix_3_hash_size + h.h] = pos;
        var len_best: u32 = 2;
        var count: u32 = 0;
        if (delta2 < mf.cyclic_size and mf.buffer[cur_pos - delta2] == cur[0]) {
            len_best = mf.memcmplen(cur_pos, cur_pos - delta2, len_best, len_limit);
            matches[0] = .{ .len = len_best, .dist = delta2 - 1 };
            count = 1;
            if (len_best == len_limit) {
                mf.btSkip(len_limit, pos, cur_pos, cur_match);
                return 1;
            }
        }
        const n = mf.btFind(len_limit, pos, cur_pos, cur_match, matches, count, len_best);
        mf.movePos();
        return n;
    }

    fn bt3Skip(mf: *Mf, amount_in: u32) void {
        var amount = amount_in;
        while (true) {
            if (mf.header(3)) |len_limit| {
                const cur_pos: usize = mf.read_pos;
                const cur = mf.buffer[cur_pos..];
                const pos = mf.read_pos +% mf.offset;
                const h = hash3(cur, mf.hash_mask);
                const cur_match = mf.hash[fix_3_hash_size + h.h];
                mf.hash[h.h2] = pos;
                mf.hash[fix_3_hash_size + h.h] = pos;
                mf.btSkip(len_limit, pos, cur_pos, cur_match);
            }
            amount -= 1;
            if (amount == 0) break;
        }
    }

    fn bt4Find(mf: *Mf, matches: []Match) u32 {
        const len_limit = mf.header(4) orelse return 0;
        const cur_pos: usize = mf.read_pos;
        const cur = mf.buffer[cur_pos..];
        const pos = mf.read_pos +% mf.offset;
        const h = hash4(cur, mf.hash_mask);
        var delta2 = pos -% mf.hash[h.h2];
        const delta3 = pos -% mf.hash[fix_3_hash_size + h.h3];
        const cur_match = mf.hash[fix_4_hash_size + h.h];
        mf.hash[h.h2] = pos;
        mf.hash[fix_3_hash_size + h.h3] = pos;
        mf.hash[fix_4_hash_size + h.h] = pos;
        var len_best: u32 = 1;
        var count: u32 = 0;
        if (delta2 < mf.cyclic_size and mf.buffer[cur_pos - delta2] == cur[0]) {
            len_best = 2;
            matches[0] = .{ .len = 2, .dist = delta2 - 1 };
            count = 1;
        }
        if (delta2 != delta3 and delta3 < mf.cyclic_size and mf.buffer[cur_pos - delta3] == cur[0]) {
            len_best = 3;
            matches[count].dist = delta3 - 1;
            count += 1;
            delta2 = delta3;
        }
        if (count != 0) {
            len_best = mf.memcmplen(cur_pos, cur_pos - delta2, len_best, len_limit);
            matches[count - 1].len = len_best;
            if (len_best == len_limit) {
                mf.btSkip(len_limit, pos, cur_pos, cur_match);
                return count;
            }
        }
        if (len_best < 3) len_best = 3;
        const n = mf.btFind(len_limit, pos, cur_pos, cur_match, matches, count, len_best);
        mf.movePos();
        return n;
    }

    fn bt4Skip(mf: *Mf, amount_in: u32) void {
        var amount = amount_in;
        while (true) {
            if (mf.header(4)) |len_limit| {
                const cur_pos: usize = mf.read_pos;
                const cur = mf.buffer[cur_pos..];
                const pos = mf.read_pos +% mf.offset;
                const h = hash4(cur, mf.hash_mask);
                const cur_match = mf.hash[fix_4_hash_size + h.h];
                mf.hash[h.h2] = pos;
                mf.hash[fix_3_hash_size + h.h3] = pos;
                mf.hash[fix_4_hash_size + h.h] = pos;
                mf.btSkip(len_limit, pos, cur_pos, cur_match);
            }
            amount -= 1;
            if (amount == 0) break;
        }
    }
};
