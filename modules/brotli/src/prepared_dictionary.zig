// SPDX-License-Identifier: MIT
//! `PreparedDictionary`: a raw prefix dictionary (RFC 9841 §3.2; RFC 9842
//! `dcb`) hashed once, for any number of compressions against it — a server
//! answering response after response from one shared dictionary pays the
//! dictionary's positions once, not per response (SPEC.md backlog R6).
//!
//! Port of google/brotli 1.2.0's lean prepared dictionary
//! (`c/enc/compound_dictionary.c`, `CreatePreparedDictionaryWithParams`,
//! MIT, copyright Google Inc., see this module's NOTICE): every position's
//! first five bytes hashed to a bucket, the newest `bucket_limit` positions
//! of each bucket kept, the buckets grouped into slots so that a bucket's
//! head is a 16-bit offset into its slot's run of items. The encoder looks a
//! position up here beside its own match finder (`FindCompoundDictionaryMatch`
//! in google's `hash.h`); nothing here changes while it compresses, so one
//! dictionary serves concurrent compressions.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Bytes read at a position to hash it (of which `hash_bytes` count).
const read_bytes = 8;
/// google's `hash_bits` 40: the first five bytes.
const hash_bytes = 5;
/// google `kPreparedDictionaryHashMul64Long`.
const hash_mul: u64 = 0x1FE35A7B_D3579BD3;
/// Positions kept per bucket (google `bucket_limit`).
const bucket_limit = 32;
/// The last item of a bucket's run.
const last_bit: u32 = 0x8000_0000;
/// A bucket with no items.
const empty_head: u16 = 0xffff;

pub const PreparedDictionary = struct {
    /// The dictionary (its last `max_len` bytes when longer), not copied:
    /// it must outlive this.
    source: []const u8,
    /// SHA-256 of `source`: what a `dcb` body's header names
    /// (`dcb.headerFrom`). Zeros when made with `.digest = false`.
    digest: [Sha256.digest_length]u8,
    bucket_bits: u5,
    slot_bits: u5,
    /// Per slot, where its run of items starts in `items`.
    slot_offsets: []u32,
    /// Per bucket, its first item's offset in its slot's run, or
    /// `empty_head`.
    heads: []u16,
    /// Positions in `source`, newest first per bucket, the last one of each
    /// bucket with `last_bit`.
    items: []u32,
    /// The three above.
    mem: []u32,

    /// `init`'s most slots (2^7 up to 2 MiB, 2^12 from 64 MiB).
    const max_slots = 1 << 12;

    /// Positions past this are never indexed: an item keeps 31 bits.
    pub const max_len = std.math.maxInt(u31);
    pub const read_len = read_bytes;

    pub const Options = struct {
        /// Hash `source` into `digest` (a `dcb` header names it). The
        /// encoder preparing a raw dictionary for one call skips it.
        digest: bool = true,
    };

    /// `source` prepared (google `CreatePreparedDictionary`: 2^17 buckets
    /// of up to 32 positions for up to 2 MiB, twice the buckets per doubling
    /// up to 2^22). Only the last `max_len` bytes are searchable.
    pub fn init(gpa: std.mem.Allocator, source: []const u8) std.mem.Allocator.Error!PreparedDictionary {
        return initOptions(gpa, source, .{});
    }

    pub fn initOptions(gpa: std.mem.Allocator, source: []const u8, opts: Options) std.mem.Allocator.Error!PreparedDictionary {
        var bucket_bits: u5 = 17;
        var slot_bits: u5 = 7;
        var volume: usize = 16 << 17;
        while (volume < source.len and bucket_bits < 22) {
            bucket_bits += 1;
            slot_bits += 1;
            volume <<= 1;
        }
        // Only the last `max_len` bytes are indexed, and `source` becomes
        // that tail: positions in it fit an item's 31 bits. Indexed from the
        // whole of a longer one they took bit 31 (`last_bit`) from 2 GiB and
        // failed their `u32` cast from 4 GiB, UB in ReleaseFast (no-panic
        // sweep 2026-10-28, B-7). A copy's distance counts back from the
        // dictionary's end, so the tail gives the distances the whole would
        // (nothing further back is in reach: the window is at most 2^30).
        const tail = source[source.len -| max_len..];
        var d = try initWith(gpa, tail, bucket_bits, slot_bits);
        if (opts.digest) Sha256.hash(source, &d.digest, .{});
        return d;
    }

    fn initWith(gpa: std.mem.Allocator, source: []const u8, bucket_bits: u5, slot_bits: u5) std.mem.Allocator.Error!PreparedDictionary {
        std.debug.assert(slot_bits <= 16 and slot_bits <= bucket_bits and bucket_bits - slot_bits <= 11);
        const num_slots = @as(usize, 1) << slot_bits;
        const num_buckets = @as(usize, 1) << bucket_bits;
        const first = 0; // `source` is at most `max_len` (`initOptions`)

        // Step 1: every bucket's count, capped. (google links each bucket's
        // positions into a chain here, in an array of 4 bytes per position,
        // and walks the chains in step 3. Step 3 below hashes the positions
        // again instead, newest first, and drops each into its bucket's run
        // while the run has room: the same items without that array — 64
        // MiB for a 16 MiB dictionary — in about the same time, 2026-10-16.)
        const num = try gpa.alloc(u16, num_buckets);
        defer gpa.free(num);
        zero(u16, num);
        const n_pos = if (source.len >= read_bytes) source.len - read_bytes + 1 else 0;
        var i: usize = first;
        while (i < n_pos) : (i += 1) {
            const k = keyAt(source, i, bucket_bits);
            num[k] = @min(num[k] + 1, bucket_limit);
        }

        // Step 2: each slot's run. google also lowers a slot's per-bucket
        // limit until the run's heads fit 16 bits; with at most 2^11
        // buckets a slot (asserted above) the last head is at most
        // (2^11 - 1) * 32 = 65 504, so no limit is ever lowered.
        var slot_size_buf: [max_slots]u32 = undefined;
        const slot_size = slot_size_buf[0..num_slots];
        @memset(slot_size, 0);
        for (num, 0..) |c, b| slot_size[b & (num_slots - 1)] += c;
        var total: usize = 0;
        for (slot_size) |sz| total += sz;

        // Step 3: the runs.
        // One block, as google's.
        const mem = try gpa.alloc(u32, num_slots + num_buckets / 2 + total);
        const slot_offsets = mem[0..num_slots];
        const heads = @as([*]u16, @ptrCast(mem[num_slots..].ptr))[0..num_buckets];
        const items = mem[num_slots + num_buckets / 2 ..][0..total];
        var run: u32 = 0;
        for (slot_offsets, slot_size) |*o, *sz| {
            o.* = run;
            run += sz.*;
            sz.* = 0;
        }
        for (0..num_buckets) |b| {
            const s = b & (num_slots - 1);
            const count = num[b];
            if (count == 0) {
                heads[b] = empty_head;
                continue;
            }
            heads[b] = @intCast(slot_size[s]);
            slot_size[s] += count;
        }
        // Newest first, each position into its bucket's run while the run
        // has room; `num`'s high byte counts what is placed.
        i = n_pos;
        while (i > first) {
            i -= 1;
            const k = keyAt(source, i, bucket_bits);
            const v = num[k];
            const s = k & (num_slots - 1);
            const count = v & 0xff;
            const placed = v >> 8;
            if (placed == count) continue;
            items[slot_offsets[s] + heads[k] + placed] = @as(u32, @intCast(i)) | if (placed + 1 == count) last_bit else 0;
            num[k] = v + 0x100;
        }

        return .{
            .source = source,
            .digest = @splat(0),
            .bucket_bits = bucket_bits,
            .slot_bits = slot_bits,
            .mem = mem,
            .slot_offsets = slot_offsets,
            .heads = heads,
            .items = items,
        };
    }

    pub fn deinit(d: *PreparedDictionary, gpa: std.mem.Allocator) void {
        gpa.free(d.mem);
        d.* = undefined;
    }

    /// The bucket of the `read_bytes` bytes at `at[0..]`.
    inline fn key(bytes: *const [read_bytes]u8, bucket_bits: u5) usize {
        const v = std.mem.readInt(u64, bytes, .little) & ((@as(u64, 1) << (8 * hash_bytes)) - 1);
        return @intCast((v *% hash_mul) >> @intCast(64 - @as(u7, bucket_bits)));
    }

    fn keyAt(source: []const u8, i: usize, bucket_bits: u5) usize {
        return key(source[i..][0..read_bytes], bucket_bits);
    }

    /// The positions whose first five bytes may be those of `bytes`, newest
    /// first (the walk stops after the one with `last_bit`): empty when the
    /// bucket is.
    pub inline fn chain(d: *const PreparedDictionary, bytes: *const [read_bytes]u8) Chain {
        const k = key(bytes, d.bucket_bits);
        const head = d.heads[k];
        if (head == empty_head) return .{ .items = d.items[0..0] };
        const slot = k & ((@as(usize, 1) << d.slot_bits) - 1);
        return .{ .items = d.items[d.slot_offsets[slot] + head ..] };
    }

    pub const Chain = struct {
        items: []const u32,
        at: usize = 0,
        done: bool = false,

        /// The next position, or null after the bucket's last.
        pub inline fn next(c: *Chain) ?u32 {
            if (c.done or c.at == c.items.len) return null;
            const it = c.items[c.at];
            c.at += 1;
            c.done = it & last_bit != 0;
            return it & ~last_bit;
        }
    };
};

/// `@memset(buf, 0)` in vector stores: Zig 0.16 lowers `@memset` without
/// libc to a byte-at-a-time `compiler_rt.memset` (as `encoder.Matcher.fillZero`;
/// delete with it).
fn zero(comptime T: type, buf: []T) void {
    const V = @Vector(32 / @sizeOf(T), T);
    const p: [*]volatile T = buf.ptr;
    var i: usize = 0;
    while (i + 32 / @sizeOf(T) <= buf.len) : (i += 32 / @sizeOf(T)) {
        const w: *align(@alignOf(T)) volatile V = @ptrCast(p + i);
        w.* = @splat(0);
    }
    while (i < buf.len) : (i += 1) p[i] = 0;
}

const testing = std.testing;

test "every chain holds exactly its bucket's newest positions, newest first" {
    const gpa = testing.allocator;
    var prng: std.Random.DefaultPrng = .init(0x9842);
    const src = try gpa.alloc(u8, 40_000);
    defer gpa.free(src);
    // A small alphabet: buckets past the limit, and many empty ones.
    for (src) |*b| b.* = "abcd"[prng.random().uintLessThan(usize, 4)];
    var d = try PreparedDictionary.initWith(gpa, src, 12, 4);
    defer d.deinit(gpa);
    // The model: positions per bucket from the newest, `bucket_limit` at most.
    var seen: std.AutoHashMapUnmanaged(usize, void) = .empty;
    defer seen.deinit(gpa);
    var total: usize = 0;
    var i: usize = src.len - read_bytes + 1;
    while (i > 0) {
        i -= 1;
        const k = PreparedDictionary.keyAt(src, i, 12);
        if (seen.contains(k)) continue;
        try seen.put(gpa, k, {});
        var want: [bucket_limit]u32 = undefined;
        var n: usize = 0;
        var j: usize = i + 1;
        while (j > 0 and n < bucket_limit) {
            j -= 1;
            if (PreparedDictionary.keyAt(src, j, 12) == k) {
                want[n] = @intCast(j);
                n += 1;
            }
        }
        var c = d.chain(src[i..][0..read_bytes]);
        var got: usize = 0;
        while (c.next()) |pos| : (got += 1) {
            try testing.expect(got < n);
            try testing.expectEqual(want[got], pos);
        }
        try testing.expectEqual(n, got);
        total += n;
    }
    // Every item belongs to one bucket's chain: none left over.
    try testing.expectEqual(d.items.len, total);
}

test "an empty or short dictionary: no chains; digest is SHA-256" {
    const gpa = testing.allocator;
    var d = try PreparedDictionary.init(gpa, "short");
    defer d.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), d.items.len);
    var c = d.chain("shortxyz");
    try testing.expectEqual(@as(?u32, null), c.next());
    var want: [32]u8 = undefined;
    Sha256.hash("short", &want, .{});
    try testing.expectEqualSlices(u8, &want, &d.digest);
}
