// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Dictionary training, content selection (port of libzstd
//! lib/dictBuilder/cover.c and fastcover.c, v1.5.7).
//!
//! libzstd's trainers pick a dictionary's CONTENT -- segments of the
//! samples, best first at the end -- and then `ZDICT_finalizeDictionary`
//! puts the header and the entropy tables in front of it. This file is the
//! first half: the content, byte for byte what the trainers place in the
//! dictionary buffer before finalization (`dict + tail .. dict + capacity`).
//! That content is a usable raw-content dictionary by itself.
//!
//! `cover` sorts every d-byte substring of the samples (a partial suffix
//! array, `COVER_ctx_init`) and scores segments by how many samples each of
//! their d-mers occurs in; `fastCover` scores by hashed d-mer frequencies in
//! a 2^f table instead, which needs no sort and memory independent of the
//! sample size. Both cut the samples into epochs and take the best k-byte
//! segment from each in turn (`COVER_computeEpochs`), filling the buffer
//! from the back, until it is full or the scores run out.
//!
//! Not here (finalization and scoring compress with a dictionary): the
//! header and entropy tables (`ZDICT_finalizeDictionary`), and the
//! compressed-size score `ZDICT_optimizeTrainFromBuffer_*` ranks candidates
//! by (`COVER_selectDict`). `optimizeCover` / `optimizeFastCover` run the
//! optimizer's grid of (k, d) over one shared context each, as libzstd does
//! single-threaded, and leave the score to a caller-supplied `scorer`.
//!
//! Memory: cover needs 8 bytes per sample byte (the suffix array, then the
//! frequencies, and the position-to-d-mer map) plus the offsets and the
//! active-d-mer map; fastCover 6 bytes per table entry (2^f frequencies and
//! 2^f 16-bit in-segment counts) plus the offsets. `estimateCoverMemory` /
//! `estimateFastCoverMemory` give the exact bytes the trainers allocate
//! besides the dictionary itself, and every trainer refuses with
//! `error.MemoryLimitExceeded` rather than allocate past `memory_limit`.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// `ZDICT_DICTSIZE_MIN`: the smallest dictionary buffer a trainer accepts.
pub const dict_size_min = 256;
/// `COVER_MAX_SAMPLES_SIZE` / `FASTCOVER_MAX_SAMPLES_SIZE` (64-bit): the
/// samples' total size must stay below this (positions are 32-bit).
pub const max_samples_size: u64 = std.math.maxInt(u32);
/// `FASTCOVER_MAX_F`.
pub const fastcover_max_f = 31;
/// `FASTCOVER_MAX_ACCEL`.
pub const fastcover_max_accel = 10;
/// `DEFAULT_F`: fastCover's f when 0 is given.
pub const fastcover_default_f = 20;
/// `DEFAULT_ACCEL`: fastCover's accel when 0 is given.
pub const fastcover_default_accel = 1;
/// `COVER_DEFAULT_SPLITPOINT`: the optimizer's split when 0 is given (cover).
pub const cover_default_split_point = 1.0;
/// `FASTCOVER_DEFAULT_SPLITPOINT`: the optimizer's split when 0 is given
/// (fastCover).
pub const fastcover_default_split_point = 0.75;
/// The working-memory ceiling a trainer applies unless told otherwise:
/// enough for cover over about 30 MB of samples, or fastCover up to f = 25.
pub const default_memory_limit: usize = 256 << 20;

/// Errors named after libzstd's (`ZSTD_error_*`), plus the ceiling.
pub const Error = error{
    /// Parameters out of range (`parameter_outOfBound`): k or d of 0, d
    /// above k, k above the capacity, fastCover's d not 6 or 8, f or accel
    /// out of range, a split point outside (0, 1].
    ParameterOutOfBound,
    /// Samples the trainer cannot use (`srcSize_wrong`): none, fewer than 5
    /// in the training share or none left to test, a total below 8 bytes (or
    /// d) or at 4 GiB and up, or sizes summing past the buffer.
    SrcSizeWrong,
    /// Capacity below `dict_size_min` (`dstSize_tooSmall`).
    DstSizeTooSmall,
    /// The working memory the parameters need exceeds `memory_limit`
    /// (no allocation was made).
    MemoryLimitExceeded,
    OutOfMemory,
};

/// Training samples as libzstd takes them (`samplesBuffer`, `samplesSizes`):
/// all samples back to back in `buffer`, and each one's size in order. The
/// representation is libzstd's on purpose: cover's d-mers and the chosen
/// segments run across sample boundaries, so the samples must be
/// contiguous anyway, and the bytes stay where the caller has them.
pub const Samples = struct {
    buffer: []const u8,
    sizes: []const usize,

    /// `COVER_sum` of all sizes (saturating instead of wrapping).
    pub fn totalSize(s: Samples) u64 {
        return sum(s.sizes);
    }
};

fn sum(sizes: []const usize) u64 {
    var t: u64 = 0;
    for (sizes) |n| t +|= n;
    return t;
}

/// `ZDICT_cover_params_t` as `ZDICT_trainFromBuffer_cover` reads it.
pub const CoverParams = struct {
    /// Segment size (required, `d` ≤ k ≤ capacity).
    k: u32,
    /// d-mer size (required, 1 ≤ d ≤ k; libzstd's optimizer tries 6 and 8).
    d: u32,
    /// Working-memory ceiling; see `estimateCoverMemory`.
    memory_limit: usize = default_memory_limit,
};

/// `ZDICT_fastCover_params_t` as `ZDICT_trainFromBuffer_fastCover` reads it.
pub const FastCoverParams = struct {
    /// Segment size (required, `d` ≤ k ≤ capacity).
    k: u32,
    /// d-mer size (required): 6 or 8.
    d: u32,
    /// log2 of the frequency table (1..31); 0 means `fastcover_default_f`.
    f: u32 = fastcover_default_f,
    /// Acceleration (1..10): count every accel-th d-mer only; 0 means
    /// `fastcover_default_accel`. It also sets the share of samples
    /// finalization uses (`Accel.finalize`).
    accel: u32 = fastcover_default_accel,
    /// Working-memory ceiling; see `estimateFastCoverMemory`.
    memory_limit: usize = default_memory_limit,
};

// ---------------------------------------------------------------------------
// Shared pieces (cover.c / cover.h)

/// `COVER_segment_t`: a range of d-mer positions and its score.
pub const Segment = struct { begin: u32 = 0, end: u32 = 0, score: u32 = 0 };

/// `COVER_epoch_info_t`.
pub const Epochs = struct { num: u32, size: u32 };

/// `COVER_computeEpochs`: split `nb_dmers` into epochs of at least 10·k
/// d-mers, aiming at `passes` passes over the corpus. `nb_dmers` ≥ 1.
pub fn computeEpochs(max_dict_size: u32, nb_dmers: u32, k: u32, passes: u32) Epochs {
    const min_epoch_size = k *% 10;
    var e: Epochs = .{ .num = @max(1, max_dict_size / k / passes), .size = 0 };
    e.size = nb_dmers / e.num;
    if (e.size >= min_epoch_size) {
        std.debug.assert(@as(u64, e.size) * e.num <= nb_dmers);
        return e;
    }
    e.size = @min(min_epoch_size, nb_dmers);
    e.num = nb_dmers / e.size;
    std.debug.assert(@as(u64, e.size) * e.num <= nb_dmers);
    return e;
}

/// `COVER_warnOnSmallCorpus`'s condition: libzstd warns (at display level
/// 1 and up) when there are fewer than ten d-mers per dictionary byte, "This
/// may lead to a subpar dictionary". The trainers here print nothing; a
/// caller that wants the warning asks this.
pub fn smallCorpus(max_dict_size: usize, nb_dmers: usize) bool {
    const ratio = @as(f64, @floatFromInt(nb_dmers)) / @as(f64, @floatFromInt(max_dict_size));
    return !(ratio >= 10);
}

/// The number of d-mers a trainer sees (`suffixSize` / `nbDmers`): one per
/// position with `max(d, 8)` bytes left in the training share, or 0 when
/// the share is shorter than that.
pub fn dmerCount(training_size: u64, d: u32) u64 {
    const read_len: u64 = @max(d, 8);
    return if (training_size < read_len) 0 else training_size - read_len + 1;
}

/// How `COVER_ctx_init` / `FASTCOVER_ctx_init` split the samples into a
/// training and a testing share, with their checks.
pub const Split = struct {
    nb_train_samples: usize,
    nb_test_samples: usize,
    total_size: u64,
    training_size: u64,

    pub fn init(samples: Samples, d: u32, split_point: f64) Error!Split {
        // libzstd's callers check the split point before the context; the
        // context-level API here checks it itself (NaN passes, as there).
        if (split_point <= 0 or split_point > 1) return error.ParameterOutOfBound;
        const nb: usize = samples.sizes.len;
        const total = samples.totalSize();
        // This port's own check: libzstd cannot see the buffer's length.
        if (total > samples.buffer.len or nb > std.math.maxInt(u32)) return error.SrcSizeWrong;
        const nb_train: usize = if (split_point < 1.0) @intFromFloat(@as(f64, @floatFromInt(nb)) * split_point) else nb;
        const nb_test: usize = if (split_point < 1.0) nb - nb_train else nb;
        const training_size = if (split_point < 1.0) sum(samples.sizes[0..nb_train]) else total;
        if (total < @max(d, 8) or total >= max_samples_size) return error.SrcSizeWrong;
        if (nb_train < 5) return error.SrcSizeWrong;
        if (nb_test < 1) return error.SrcSizeWrong;
        // A training share shorter than one d-mer: libzstd's size arithmetic
        // underflows there (reachable only with a split point below 1);
        // refused here instead.
        if (training_size < @max(d, 8)) return error.SrcSizeWrong;
        return .{ .nb_train_samples = nb_train, .nb_test_samples = nb_test, .total_size = total, .training_size = training_size };
    }

    pub fn nbDmers(s: Split, d: u32) u64 {
        return dmerCount(s.training_size, d);
    }
};

fn offsetsOf(gpa: Allocator, sizes: []const usize) Allocator.Error![]usize {
    const offsets = try gpa.alloc(usize, sizes.len + 1);
    offsets[0] = 0;
    for (sizes, 1..) |n, i| offsets[i] = offsets[i - 1] + n;
    return offsets;
}

inline fn readLE64(b: []const u8, i: usize) u64 {
    return std.mem.readInt(u64, b[i..][0..8], .little);
}

// ---------------------------------------------------------------------------
// cover: the active-d-mer map (cover.c "Hash table")

const map_empty_value: u32 = std.math.maxInt(u32);
const prime4bytes: u32 = 2654435761;

/// `COVER_map_t`: d-mer id → occurrences in the active segment; linear
/// probing, load below 0.5, never resized.
pub const ActiveDmers = struct {
    const Pair = extern struct { key: u32, value: u32 };

    data: []Pair,
    size_log: u5,
    mask: u32,

    /// `COVER_map_init`'s size for `size` elements: 2^(highbit(size) + 2)
    /// pairs, or null when that is past 2^31 (libzstd's shift overflows).
    pub fn slots(size: u32) ?u64 {
        const log = 31 - @as(u32, @clz(size)) + 2;
        if (log > 31) return null;
        return @as(u64, 1) << @intCast(log);
    }

    pub fn bytes(size: u32) ?u64 {
        return if (slots(size)) |n| n * @sizeOf(Pair) else null;
    }

    /// `COVER_map_init`; `size` ≥ 1.
    pub fn init(gpa: Allocator, size: u32) Error!ActiveDmers {
        const n = slots(size) orelse return error.ParameterOutOfBound;
        const log: u5 = @intCast(std.math.log2_int(u64, n));
        var m: ActiveDmers = .{ .data = try gpa.alloc(Pair, @intCast(n)), .size_log = log, .mask = @intCast(n - 1) };
        m.clear();
        return m;
    }

    pub fn deinit(m: *ActiveDmers, gpa: Allocator) void {
        gpa.free(m.data);
        m.* = undefined;
    }

    /// `COVER_map_clear`.
    pub fn clear(m: *ActiveDmers) void {
        @memset(m.data, .{ .key = map_empty_value, .value = map_empty_value });
    }

    fn hash(m: *const ActiveDmers, key: u32) u32 {
        return (key *% prime4bytes) >> @intCast(@as(u6, 32) - m.size_log);
    }

    /// `COVER_map_index`.
    fn index(m: *const ActiveDmers, key: u32) u32 {
        var i = m.hash(key);
        while (true) : (i = (i +% 1) & m.mask) {
            const pos = &m.data[i];
            if (pos.value == map_empty_value) return i;
            if (pos.key == key) return i;
        }
    }

    /// `COVER_map_at`: the value for `key`, inserted as 0 when absent.
    fn at(m: *ActiveDmers, key: u32) *u32 {
        const pos = &m.data[m.index(key)];
        if (pos.value == map_empty_value) {
            pos.key = key;
            pos.value = 0;
        }
        return &pos.value;
    }

    /// `COVER_map_remove`: backward-shift deletion.
    fn remove(m: *ActiveDmers, key: u32) void {
        var i = m.index(key);
        var del = &m.data[i];
        var shift: u32 = 1;
        if (del.value == map_empty_value) return;
        i = (i +% 1) & m.mask;
        while (true) : (i = (i +% 1) & m.mask) {
            const pos = &m.data[i];
            if (pos.value == map_empty_value) {
                del.value = map_empty_value;
                return;
            }
            if (((i -% m.hash(pos.key)) & m.mask) >= shift) {
                del.key = pos.key;
                del.value = pos.value;
                del = pos;
                shift = 1;
            } else {
                shift += 1;
            }
        }
    }
};

// ---------------------------------------------------------------------------
// cover: the context

/// `COVER_ctx_t` after `COVER_ctx_init`: the d-mer id of every training
/// position and, per id, the number of samples the d-mer occurs in. It
/// depends on d and the split only, so the optimizer builds it once per d
/// and tries every k on copies of `freqs`.
pub const CoverContext = struct {
    samples: []const u8,
    sizes: []const usize,
    /// Start of every sample, and the total at the end (nb + 1 entries).
    offsets: []usize,
    nb_train_samples: usize,
    nb_test_samples: usize,
    /// Training positions with a d-mer (`suffixSize`).
    suffix_size: usize,
    /// Per d-mer id (the id is the d-mer's first index in the sorted suffix
    /// array): the number of samples it occurs in (`ctx->freqs`).
    freqs: []u32,
    /// Per position: its d-mer id (`ctx->dmerAt`).
    dmer_at: []u32,
    d: u32,

    /// The bytes `init` allocates.
    pub fn memory(nb_samples: usize, suffix_size: u64) u64 {
        return (@as(u64, nb_samples) + 1) * @sizeOf(usize) + 2 * suffix_size * @sizeOf(u32);
    }

    /// `COVER_ctx_init`. Refuses (`error.MemoryLimitExceeded`) before
    /// allocating when `memory` exceeds `memory_limit`.
    pub fn init(gpa: Allocator, samples: Samples, d: u32, split_point: f64, memory_limit: usize) Error!CoverContext {
        const split: Split = try .init(samples, d, split_point);
        const suffix_size = split.nbDmers(d);
        if (memory(samples.sizes.len, suffix_size) > memory_limit) return error.MemoryLimitExceeded;
        const offsets = try offsetsOf(gpa, samples.sizes);
        errdefer gpa.free(offsets);
        const suffix = try gpa.alloc(u32, @intCast(suffix_size));
        errdefer gpa.free(suffix);
        const dmer_at = try gpa.alloc(u32, @intCast(suffix_size));
        errdefer gpa.free(dmer_at);
        var ctx: CoverContext = .{
            .samples = samples.buffer,
            .sizes = samples.sizes,
            .offsets = offsets,
            .nb_train_samples = split.nb_train_samples,
            .nb_test_samples = split.nb_test_samples,
            .suffix_size = @intCast(suffix_size),
            .freqs = suffix,
            .dmer_at = dmer_at,
            .d = d,
        };
        // The partial suffix array: positions sorted by their first d bytes.
        // libzstd's qsort_r comparator (`COVER_strict_cmp[8]`) breaks ties by
        // the element's address and glibc's qsort_r is a merge sort, so
        // within a d-mer the positions stay ascending; the (d-mer, position)
        // order here is that same total order, whatever the sort.
        for (suffix, 0..) |*s, i| s.* = @intCast(i);
        std.sort.pdq(u32, suffix, &ctx, strictLessThan);
        // `COVER_groupBy` with `COVER_group`: each run of equal d-mers.
        var start: usize = 0;
        while (start < suffix.len) {
            var end = start + 1;
            while (end < suffix.len and ctx.cmp(suffix[start], suffix[end]) == .eq) end += 1;
            ctx.group(suffix, start, end);
            start = end;
        }
        return ctx;
    }

    pub fn deinit(ctx: *CoverContext, gpa: Allocator) void {
        gpa.free(ctx.offsets);
        gpa.free(ctx.freqs);
        gpa.free(ctx.dmer_at);
        ctx.* = undefined;
    }

    /// `COVER_cmp8` (d ≤ 8: the d-mer as a little-endian integer) or
    /// `COVER_cmp` (memcmp of d bytes).
    fn cmp(ctx: *const CoverContext, l: u32, r: u32) std.math.Order {
        if (ctx.d <= 8) {
            const mask: u64 = if (ctx.d == 8) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(8 * ctx.d)) - 1;
            return std.math.order(readLE64(ctx.samples, l) & mask, readLE64(ctx.samples, r) & mask);
        }
        return std.mem.order(u8, ctx.samples[l..][0..ctx.d], ctx.samples[r..][0..ctx.d]);
    }

    fn strictLessThan(ctx: *const CoverContext, l: u32, r: u32) bool {
        return switch (ctx.cmp(l, r)) {
            .lt => true,
            .gt => false,
            .eq => l < r,
        };
    }

    /// `COVER_group`: one d-mer's positions `suffix[start..end]`, ascending.
    /// Records the d-mer id of each and counts the samples it occurs in --
    /// the first occurrence in each sample only, since later ones can match
    /// the earlier. The count goes to `suffix[start]`, which is never read
    /// again, so the suffix array becomes the frequency table.
    fn group(ctx: *CoverContext, suffix: []u32, start: usize, end: usize) void {
        const dmer_id: u32 = @intCast(start);
        var freq: u32 = 0;
        var cur_offset: usize = 0; // index into offsets
        const offsets_end = ctx.offsets.len - 1; // nbSamples
        var cur_sample_end: usize = ctx.offsets[0];
        var g = start;
        while (g != end) : (g += 1) {
            const pos = suffix[g];
            ctx.dmer_at[pos] = dmer_id;
            if (pos < cur_sample_end) continue;
            freq +%= 1;
            // In the common case of the last position there is nothing left
            // to find the sample of.
            if (g + 1 != end) {
                const sample_end = lowerBound(ctx.offsets, cur_offset, offsets_end, pos);
                cur_sample_end = ctx.offsets[sample_end];
                cur_offset = sample_end + 1;
            }
        }
        suffix[dmer_id] = freq;
    }

    /// `COVER_selectSegment`: the best segment of at most k bytes in
    /// [begin, end), scored by the frequencies of its distinct d-mers,
    /// trimmed of zero-frequency d-mers at both ends; its d-mers' frequencies
    /// are zeroed.
    pub fn selectSegment(ctx: *const CoverContext, freqs: []u32, active: *ActiveDmers, begin: u32, end: u32, k: u32, d: u32) Segment {
        const dmers_in_k = k - d + 1;
        var best: Segment = .{};
        var seg: Segment = .{ .begin = begin, .end = begin, .score = 0 };
        active.clear();
        while (seg.end < end) {
            const new_dmer = ctx.dmer_at[seg.end];
            const new_occ = active.at(new_dmer);
            if (new_occ.* == 0) seg.score +%= freqs[new_dmer];
            seg.end += 1;
            new_occ.* += 1;
            if (seg.end - seg.begin == dmers_in_k +% 1) {
                const del_dmer = ctx.dmer_at[seg.begin];
                const del_occ = active.at(del_dmer);
                seg.begin += 1;
                del_occ.* -= 1;
                if (del_occ.* == 0) {
                    active.remove(del_dmer);
                    seg.score -%= freqs[del_dmer];
                }
            }
            if (seg.score > best.score) best = seg;
        }
        {
            // Trim off the zero-frequency head and tail.
            var new_begin = best.end;
            var new_end = best.begin;
            var pos = best.begin;
            while (pos != best.end) : (pos +%= 1) {
                if (freqs[ctx.dmer_at[pos]] != 0) {
                    new_begin = @min(new_begin, pos);
                    new_end = pos + 1;
                }
            }
            best.begin = new_begin;
            best.end = new_end;
        }
        var pos = best.begin;
        while (pos != best.end) : (pos +%= 1) freqs[ctx.dmer_at[pos]] = 0;
        return best;
    }

    /// `COVER_buildDictionary`: fill `dict` from the back with one segment
    /// per epoch in turn (four passes over the corpus planned) until it is
    /// full or 10..100 epochs in a row score nothing. Returns the tail: the
    /// content is `dict[tail..]`. Consumes `freqs` (a copy of `ctx.freqs`,
    /// or `ctx.freqs` itself for a single build).
    pub fn buildDictionary(ctx: *const CoverContext, freqs: []u32, active: *ActiveDmers, dict: []u8, k: u32, d: u32) usize {
        var tail = dict.len;
        const epochs = computeEpochs(@truncate(dict.len), @intCast(ctx.suffix_size), k, 4);
        const max_zero_score_run: usize = @max(10, @min(100, epochs.num >> 3));
        var zero_score_run: usize = 0;
        var epoch: usize = 0;
        while (tail > 0) : (epoch = (epoch + 1) % epochs.num) {
            const epoch_begin: u32 = @intCast(epoch * epochs.size);
            const epoch_end = epoch_begin + epochs.size;
            const segment = ctx.selectSegment(freqs, active, epoch_begin, epoch_end, k, d);
            // A segment covering no d-mers: this epoch is out of content;
            // others may still have some, for a while.
            if (segment.score == 0) {
                zero_score_run += 1;
                if (zero_score_run >= max_zero_score_run) break;
                continue;
            }
            zero_score_run = 0;
            const segment_size = @min(@as(usize, (segment.end -% segment.begin) +% d -% 1), tail);
            if (segment_size < d) break;
            // From the back: the best segments get the smallest offsets.
            tail -= segment_size;
            @memcpy(dict[tail..][0..segment_size], ctx.samples[segment.begin..][0..segment_size]);
        }
        return tail;
    }
};

/// `COVER_lower_bound` over `offsets[first..last)`: the first index whose
/// offset is not below `value`, or `last`.
fn lowerBound(offsets: []const usize, first_in: usize, last: usize, value: usize) usize {
    var first = first_in;
    std.debug.assert(last >= first);
    var count = last - first;
    while (count != 0) {
        const step = count / 2;
        const p = first + step;
        if (offsets[p] < value) {
            first = p + 1;
            count -= step + 1;
        } else {
            count = step;
        }
    }
    return first;
}

/// `COVER_checkParameters`.
pub fn checkCoverParameters(k: u32, d: u32, split_point: f64, max_dict_size: usize) bool {
    if (d == 0 or k == 0) return false;
    if (k > max_dict_size) return false;
    if (d > k) return false;
    if (split_point <= 0 or split_point > 1) return false;
    return true;
}

/// The bytes `trainCover` / `trainCoverInto` allocate for `nb_samples`
/// samples of `total_samples_size` bytes (besides the dictionary): offsets,
/// suffix array, d-mer map, active-d-mer map. `maxInt(u64)` when the
/// active-d-mer map cannot exist (k - d + 1 ≥ 2^30). Parameters are not
/// checked here.
pub fn estimateCoverMemory(total_samples_size: u64, nb_samples: usize, params: CoverParams) u64 {
    const map = if (params.k >= params.d) ActiveDmers.bytes(params.k - params.d + 1) orelse return std.math.maxInt(u64) else 0;
    return CoverContext.memory(nb_samples, dmerCount(total_samples_size, params.d)) +| map;
}

/// `ZDICT_trainFromBuffer_cover` up to its finalization: the content
/// libzstd places at the end of a `dict.len`-byte dictionary buffer, which
/// is `dict[dict.len - n ..]` for the returned n (the rest of `dict` is
/// left as it was). Checks in libzstd's order, then the memory ceiling.
pub fn trainCoverInto(gpa: Allocator, dict: []u8, samples: Samples, params: CoverParams) Error!usize {
    if (!checkCoverParameters(params.k, params.d, 1.0, dict.len)) return error.ParameterOutOfBound;
    if (samples.sizes.len == 0) return error.SrcSizeWrong;
    if (dict.len < dict_size_min) return error.DstSizeTooSmall;
    const split: Split = try .init(samples, params.d, 1.0);
    if (estimateCoverMemory(split.total_size, samples.sizes.len, params) > params.memory_limit) return error.MemoryLimitExceeded;
    var ctx: CoverContext = try .init(gpa, samples, params.d, 1.0, params.memory_limit);
    defer ctx.deinit(gpa);
    var active: ActiveDmers = try .init(gpa, params.k - params.d + 1);
    defer active.deinit(gpa);
    const tail = ctx.buildDictionary(ctx.freqs, &active, dict, params.k, params.d);
    return dict.len - tail;
}

/// `trainCoverInto` into a `capacity`-byte buffer; returns the content
/// alone, owned by the caller.
pub fn trainCover(gpa: Allocator, samples: Samples, capacity: usize, params: CoverParams) Error![]u8 {
    return trainAlloc(gpa, capacity, samples, params, trainCoverInto);
}

fn trainAlloc(gpa: Allocator, capacity: usize, samples: Samples, params: anytype, comptime into: anytype) Error![]u8 {
    const dict = try gpa.alloc(u8, capacity);
    defer gpa.free(dict);
    const n = try into(gpa, dict, samples, params);
    return gpa.dupe(u8, dict[capacity - n ..]);
}

// ---------------------------------------------------------------------------
// fastCover (fastcover.c)

/// `FASTCOVER_accel_t`.
pub const Accel = struct {
    /// Percentage of training samples `ZDICT_finalizeDictionary` uses.
    finalize: u32,
    /// d-mers skipped between two counted ones in the frequency count.
    skip: u32,
};

/// `FASTCOVER_defaultAccelParameters`, by accel (0 is never used).
pub const accel_table = [fastcover_max_accel + 1]Accel{
    .{ .finalize = 100, .skip = 0 }, // accel = 0, defaults to accel = 1
    .{ .finalize = 100, .skip = 0 }, // accel = 1
    .{ .finalize = 50, .skip = 1 }, // accel = 2
    .{ .finalize = 34, .skip = 2 }, // accel = 3
    .{ .finalize = 25, .skip = 3 }, // accel = 4
    .{ .finalize = 20, .skip = 4 }, // accel = 5
    .{ .finalize = 17, .skip = 5 }, // accel = 6
    .{ .finalize = 14, .skip = 6 }, // accel = 7
    .{ .finalize = 13, .skip = 7 }, // accel = 8
    .{ .finalize = 11, .skip = 8 }, // accel = 9
    .{ .finalize = 10, .skip = 9 }, // accel = 10
};

const prime6bytes: u64 = 227718039650203;
const prime8bytes: u64 = 0xCF1BBCDCB7A56463;

/// `FASTCOVER_hashPtrToIndex`: `ZSTD_hash6Ptr` for d = 6, else
/// `ZSTD_hash8Ptr`, to f bits (reads 8 bytes).
fn hashPtrToIndex(samples: []const u8, pos: usize, f: u32, d: u32) usize {
    const v = readLE64(samples, pos);
    const sh: u6 = @intCast(64 - f);
    if (d == 6) return @intCast(((v << 16) *% prime6bytes) >> sh);
    return @intCast((v *% prime8bytes) >> sh);
}

/// `FASTCOVER_ctx_t` after `FASTCOVER_ctx_init`: the hashed d-mer
/// frequencies of the training share. It depends on d, f, accel and the
/// split only.
pub const FastCoverContext = struct {
    samples: []const u8,
    sizes: []const usize,
    offsets: []usize,
    nb_train_samples: usize,
    nb_test_samples: usize,
    nb_dmers: usize,
    /// 2^f counts of d-mers by hash, over the training share.
    freqs: []u32,
    d: u32,
    f: u32,
    accel: Accel,

    /// The bytes `init` allocates.
    pub fn memory(nb_samples: usize, f: u32) u64 {
        return (@as(u64, nb_samples) + 1) * @sizeOf(usize) + (@as(u64, 1) << @intCast(f)) * @sizeOf(u32);
    }

    /// `FASTCOVER_ctx_init` (with `FASTCOVER_computeFrequency`). f in
    /// 1..31. Refuses before allocating when `memory` exceeds
    /// `memory_limit`.
    pub fn init(gpa: Allocator, samples: Samples, d: u32, split_point: f64, f: u32, accel: Accel, memory_limit: usize) Error!FastCoverContext {
        const split: Split = try .init(samples, d, split_point);
        if (memory(samples.sizes.len, f) > memory_limit) return error.MemoryLimitExceeded;
        const offsets = try offsetsOf(gpa, samples.sizes);
        errdefer gpa.free(offsets);
        const freqs = try gpa.alloc(u32, @as(usize, 1) << @intCast(f));
        @memset(freqs, 0);
        var ctx: FastCoverContext = .{
            .samples = samples.buffer,
            .sizes = samples.sizes,
            .offsets = offsets,
            .nb_train_samples = split.nb_train_samples,
            .nb_test_samples = split.nb_test_samples,
            .nb_dmers = @intCast(split.nbDmers(d)),
            .freqs = freqs,
            .d = d,
            .f = f,
            .accel = accel,
        };
        ctx.computeFrequency(freqs);
        return ctx;
    }

    pub fn deinit(ctx: *FastCoverContext, gpa: Allocator) void {
        gpa.free(ctx.offsets);
        gpa.free(ctx.freqs);
        ctx.* = undefined;
    }

    /// `FASTCOVER_computeFrequency`: every (skip+1)-th d-mer that lies
    /// wholly inside a training sample (8 bytes read), by hash.
    fn computeFrequency(ctx: *const FastCoverContext, freqs: []u32) void {
        const read_length: usize = @max(ctx.d, 8);
        const step: usize = @as(usize, ctx.accel.skip) + 1;
        std.debug.assert(ctx.nb_train_samples >= 5);
        std.debug.assert(ctx.nb_train_samples <= ctx.sizes.len);
        for (0..ctx.nb_train_samples) |i| {
            var start = ctx.offsets[i];
            const sample_end = ctx.offsets[i + 1];
            while (start + read_length <= sample_end) : (start += step) {
                const idx = hashPtrToIndex(ctx.samples, start, ctx.f, ctx.d);
                freqs[idx] +%= 1;
            }
        }
    }

    /// `FASTCOVER_selectSegment`: the best segment of at most k bytes in
    /// [begin, end), scored by the frequencies of its distinct d-mer hashes
    /// (no trimming, unlike cover); the hashes' frequencies are zeroed.
    /// `segment_freqs` (2^f entries) must be all zero, and is left so.
    pub fn selectSegment(ctx: *const FastCoverContext, freqs: []u32, begin: u32, end: u32, k: u32, d: u32, segment_freqs: []u16) Segment {
        const dmers_in_k = k - d + 1;
        const f = ctx.f;
        var best: Segment = .{};
        var seg: Segment = .{ .begin = begin, .end = begin, .score = 0 };
        while (seg.end < end) {
            const idx = hashPtrToIndex(ctx.samples, seg.end, f, d);
            if (segment_freqs[idx] == 0) seg.score +%= freqs[idx];
            seg.end += 1;
            segment_freqs[idx] +%= 1;
            if (seg.end - seg.begin == dmers_in_k +% 1) {
                const del = hashPtrToIndex(ctx.samples, seg.begin, f, d);
                segment_freqs[del] -%= 1;
                if (segment_freqs[del] == 0) seg.score -%= freqs[del];
                seg.begin += 1;
            }
            if (seg.score > best.score) best = seg;
        }
        // Zero out the rest of segment_freqs.
        while (seg.begin < end) : (seg.begin += 1) {
            const del = hashPtrToIndex(ctx.samples, seg.begin, f, d);
            segment_freqs[del] -%= 1;
        }
        var pos = best.begin;
        while (pos != best.end) : (pos +%= 1) freqs[hashPtrToIndex(ctx.samples, pos, f, d)] = 0;
        return best;
    }

    /// `FASTCOVER_buildDictionary`: as `CoverContext.buildDictionary`, with
    /// one pass planned and a stop after 10 empty epochs in a row.
    pub fn buildDictionary(ctx: *const FastCoverContext, freqs: []u32, dict: []u8, k: u32, d: u32, segment_freqs: []u16) usize {
        var tail = dict.len;
        const epochs = computeEpochs(@truncate(dict.len), @intCast(ctx.nb_dmers), k, 1);
        const max_zero_score_run: usize = 10;
        var zero_score_run: usize = 0;
        var epoch: usize = 0;
        while (tail > 0) : (epoch = (epoch + 1) % epochs.num) {
            const epoch_begin: u32 = @intCast(epoch * epochs.size);
            const epoch_end = epoch_begin + epochs.size;
            const segment = ctx.selectSegment(freqs, epoch_begin, epoch_end, k, d, segment_freqs);
            if (segment.score == 0) {
                zero_score_run += 1;
                if (zero_score_run >= max_zero_score_run) break;
                continue;
            }
            zero_score_run = 0;
            const segment_size = @min(@as(usize, (segment.end -% segment.begin) +% d -% 1), tail);
            if (segment_size < d) break;
            tail -= segment_size;
            @memcpy(dict[tail..][0..segment_size], ctx.samples[segment.begin..][0..segment_size]);
        }
        return tail;
    }

    /// `nbFinalizeSamples`: how many training samples finalization uses
    /// for this accel.
    pub fn nbFinalizeSamples(ctx: *const FastCoverContext) usize {
        return @intCast(@as(u64, ctx.nb_train_samples) * ctx.accel.finalize / 100);
    }
};

/// `FASTCOVER_checkParameters`.
pub fn checkFastCoverParameters(k: u32, d: u32, split_point: f64, max_dict_size: usize, f: u32, accel: u32) bool {
    if (d == 0 or k == 0) return false;
    if (d != 6 and d != 8) return false;
    if (k > max_dict_size) return false;
    if (d > k) return false;
    if (f > fastcover_max_f or f == 0) return false;
    if (split_point <= 0 or split_point > 1) return false;
    if (accel > fastcover_max_accel or accel == 0) return false;
    return true;
}

fn resolvedF(f: u32) u32 {
    return if (f == 0) fastcover_default_f else f;
}

fn resolvedAccel(accel: u32) u32 {
    return if (accel == 0) fastcover_default_accel else accel;
}

/// The bytes `trainFastCover` / `trainFastCoverInto` allocate for
/// `nb_samples` samples (besides the dictionary): offsets, 2^f frequencies
/// and 2^f in-segment counts. Independent of the samples' size. f is
/// resolved (0 → default) but not checked; above 31 gives `maxInt(u64)`.
pub fn estimateFastCoverMemory(nb_samples: usize, params: FastCoverParams) u64 {
    const f = resolvedF(params.f);
    if (f > fastcover_max_f) return std.math.maxInt(u64);
    return FastCoverContext.memory(nb_samples, f) + (@as(u64, 1) << @intCast(f)) * @sizeOf(u16);
}

/// `ZDICT_trainFromBuffer_fastCover` up to its finalization; see
/// `trainCoverInto`.
pub fn trainFastCoverInto(gpa: Allocator, dict: []u8, samples: Samples, params: FastCoverParams) Error!usize {
    const f = resolvedF(params.f);
    const accel = resolvedAccel(params.accel);
    if (!checkFastCoverParameters(params.k, params.d, 1.0, dict.len, f, accel)) return error.ParameterOutOfBound;
    if (samples.sizes.len == 0) return error.SrcSizeWrong;
    if (dict.len < dict_size_min) return error.DstSizeTooSmall;
    _ = try Split.init(samples, params.d, 1.0);
    if (estimateFastCoverMemory(samples.sizes.len, params) > params.memory_limit) return error.MemoryLimitExceeded;
    var ctx: FastCoverContext = try .init(gpa, samples, params.d, 1.0, f, accel_table[accel], params.memory_limit);
    defer ctx.deinit(gpa);
    const segment_freqs = try gpa.alloc(u16, @as(usize, 1) << @intCast(f));
    defer gpa.free(segment_freqs);
    @memset(segment_freqs, 0);
    const tail = ctx.buildDictionary(ctx.freqs, dict, params.k, params.d, segment_freqs);
    return dict.len - tail;
}

/// `trainFastCoverInto` into a `capacity`-byte buffer; returns the content
/// alone, owned by the caller.
pub fn trainFastCover(gpa: Allocator, samples: Samples, capacity: usize, params: FastCoverParams) Error![]u8 {
    return trainAlloc(gpa, capacity, samples, params, trainFastCoverInto);
}

// ---------------------------------------------------------------------------
// The optimizer's grid (`ZDICT_optimizeTrainFromBuffer_*`), without its score

/// `ZDICT_cover_params_t` / `ZDICT_fastCover_params_t` as the optimizers
/// read them: 0 in k, d, steps, split_point (and f, accel) means libzstd's
/// default. `ZDICT_trainFromBuffer` is fastCover with d = 8, steps = 4.
pub const OptimizeParams = struct {
    k: u32 = 0,
    d: u32 = 0,
    steps: u32 = 0,
    split_point: f64 = 0,
    /// fastCover only.
    f: u32 = 0,
    /// fastCover only.
    accel: u32 = 0,
    /// Ceiling for one context plus one candidate's working memory
    /// (the scorer's own memory is its business).
    memory_limit: usize = default_memory_limit,
};

pub const Trainer = enum { cover, fast_cover };

/// The (d, k) grid the optimizers walk: d from `d_min` to `d_max` by 2,
/// and for each d, k from `k_min` while ≤ `k_max` by `k_step_size`.
pub const OptimizeGrid = struct {
    d_min: u32,
    d_max: u32,
    k_min: u32,
    k_max: u32,
    steps: u32,
    k_step_size: u32,
    /// `kIterations` (libzstd's progress denominator).
    iterations: u32,
    split_point: f64,
    f: u32,
    accel: u32,

    /// The optimizer's defaults and up-front checks, in libzstd's order.
    pub fn init(trainer: Trainer, p: OptimizeParams, nb_samples: usize, capacity: usize) Error!OptimizeGrid {
        const default_split: f64 = if (trainer == .cover) cover_default_split_point else fastcover_default_split_point;
        var g: OptimizeGrid = .{
            .split_point = if (p.split_point <= 0.0) default_split else p.split_point,
            .d_min = if (p.d == 0) 6 else p.d,
            .d_max = if (p.d == 0) 8 else p.d,
            .k_min = if (p.k == 0) 50 else p.k,
            .k_max = if (p.k == 0) 2000 else p.k,
            .steps = if (p.steps == 0) 40 else p.steps,
            .k_step_size = 0,
            .iterations = 0,
            .f = resolvedF(p.f),
            .accel = resolvedAccel(p.accel),
        };
        if (g.split_point <= 0 or g.split_point > 1) return error.ParameterOutOfBound;
        if (trainer == .fast_cover and (g.accel == 0 or g.accel > fastcover_max_accel)) return error.ParameterOutOfBound;
        if (g.k_min < g.d_max or g.k_max < g.k_min) return error.ParameterOutOfBound;
        if (nb_samples == 0) return error.SrcSizeWrong;
        if (capacity < dict_size_min) return error.DstSizeTooSmall;
        g.k_step_size = @max((g.k_max - g.k_min) / g.steps, 1);
        g.iterations = (1 + (g.d_max - g.d_min) / 2) *% (1 + (g.k_max - g.k_min) / g.k_step_size);
        return g;
    }
};

/// One candidate content for the scorer, with what `COVER_selectDict`
/// takes besides it.
pub const Candidate = struct {
    /// The raw content (`dict + tail`), `capacity - tail` bytes.
    content: []const u8,
    capacity: usize,
    k: u32,
    d: u32,
    split_point: f64,
    /// Samples finalization uses (cover: all training samples; fastCover:
    /// `nbFinalizeSamples` for the accel).
    nb_finalize_samples: usize,
    /// The samples scored start here (the testing share; or all samples
    /// when the split point is 1).
    nb_train_samples: usize,
    samples: Samples,
    /// Sample starts (`ctx->offsets`), nb + 1 entries.
    offsets: []const usize,
};

/// What a scorer makes of a candidate (`COVER_dictSelection_t`): the
/// dictionary it would output and its total compressed size.
pub const Selection = struct {
    /// Owned by the scorer until `optimize*` copies it.
    dict: []const u8,
    total_compressed_size: u64,
};

/// The optimizer's result: the winning dictionary's size (copied to the
/// front of `dict`) and parameters.
pub const Optimized = struct { size: usize, k: u32, d: u32, split_point: f64, steps: u32, f: u32, accel: u32 };

/// `ZDICT_optimizeTrainFromBuffer_cover` single-threaded, with
/// `COVER_selectDict` replaced by `scorer.select(Candidate) !?Selection`
/// (null: the candidate failed, as a `COVER_dictSelectionIsError` result;
/// an error ends the search). The first candidate with the strictly
/// smallest total compressed size wins, as `COVER_best_finish` decides in
/// submission order; `scorer.release(Selection)` is called for every
/// selection once it has been compared. No winner: `error.NoCandidate`
/// (libzstd returns `GENERIC`).
pub fn optimizeCover(gpa: Allocator, dict: []u8, samples: Samples, params: OptimizeParams, scorer: anytype) !Optimized {
    return optimize(.cover, gpa, dict, samples, params, scorer);
}

/// `ZDICT_optimizeTrainFromBuffer_fastCover`; see `optimizeCover`.
pub fn optimizeFastCover(gpa: Allocator, dict: []u8, samples: Samples, params: OptimizeParams, scorer: anytype) !Optimized {
    return optimize(.fast_cover, gpa, dict, samples, params, scorer);
}

fn optimize(comptime trainer: Trainer, gpa: Allocator, dict: []u8, samples: Samples, params: OptimizeParams, scorer: anytype) !Optimized {
    const grid: OptimizeGrid = try .init(trainer, params, samples.sizes.len, dict.len);
    const scratch = try gpa.alloc(u8, dict.len);
    defer gpa.free(scratch);
    var best: ?Optimized = null;
    var best_size: u64 = std.math.maxInt(u64);
    // u64 counters: libzstd's unsigned ones wrap (and loop forever) when
    // d or k is near 2^32.
    var d64: u64 = grid.d_min;
    while (d64 <= grid.d_max) : (d64 += 2) {
        const d: u32 = @intCast(d64);
        const Ctx = if (trainer == .cover) CoverContext else FastCoverContext;
        var ctx: Ctx = if (trainer == .cover)
            try .init(gpa, samples, d, grid.split_point, params.memory_limit)
        else
            try .init(gpa, samples, d, grid.split_point, grid.f, accel_table[grid.accel], params.memory_limit);
        defer ctx.deinit(gpa);
        const candidate_memory: u64 = if (trainer == .cover)
            @as(u64, ctx.suffix_size) * @sizeOf(u32) + (ActiveDmers.bytes(grid.k_max -| d + 1) orelse std.math.maxInt(u64))
        else
            (@as(u64, 1) << @intCast(grid.f)) * (@sizeOf(u32) + @sizeOf(u16));
        if (Ctx.memory(samples.sizes.len, if (trainer == .cover) ctx.suffix_size else grid.f) +| candidate_memory > params.memory_limit)
            return error.MemoryLimitExceeded;
        const freqs = try gpa.alloc(u32, ctx.freqs.len);
        defer gpa.free(freqs);
        var k64: u64 = grid.k_min;
        while (k64 <= grid.k_max) : (k64 += grid.k_step_size) {
            const k: u32 = @intCast(k64);
            const ok = if (trainer == .cover)
                checkCoverParameters(k, d, grid.split_point, dict.len)
            else
                checkFastCoverParameters(k, d, grid.split_point, dict.len, ctx.f, grid.accel);
            if (!ok) continue;
            @memcpy(freqs, ctx.freqs);
            const tail = if (trainer == .cover) blk: {
                var active: ActiveDmers = try .init(gpa, k - d + 1);
                defer active.deinit(gpa);
                break :blk ctx.buildDictionary(freqs, &active, scratch, k, d);
            } else blk: {
                const segment_freqs = try gpa.alloc(u16, ctx.freqs.len);
                defer gpa.free(segment_freqs);
                @memset(segment_freqs, 0);
                break :blk ctx.buildDictionary(freqs, scratch, k, d, segment_freqs);
            };
            const selection = (try scorer.select(Candidate{
                .content = scratch[tail..],
                .capacity = dict.len,
                .k = k,
                .d = d,
                .split_point = grid.split_point,
                .nb_finalize_samples = if (trainer == .cover) ctx.nb_train_samples else ctx.nbFinalizeSamples(),
                .nb_train_samples = ctx.nb_train_samples,
                .samples = samples,
                .offsets = ctx.offsets,
            })) orelse continue;
            defer scorer.release(selection);
            if (selection.total_compressed_size < best_size) {
                best_size = selection.total_compressed_size;
                @memcpy(dict[0..selection.dict.len], selection.dict);
                best = .{ .size = selection.dict.len, .k = k, .d = d, .split_point = grid.split_point, .steps = grid.steps, .f = grid.f, .accel = grid.accel };
            }
        }
    }
    return best orelse error.NoCandidate;
}

// ---------------------------------------------------------------------------
// Tests (byte-exactness against libzstd: dict_golden_test.zig)

const testing = std.testing;
const test_samples = @import("testdata/dict_samples.zig");

fn testSet(name: []const u8) !test_samples.Generated {
    return test_samples.generate(testing.allocator, test_samples.find(name));
}

test "computeEpochs: at least 10·k d-mers per epoch, as libzstd splits" {
    // enough d-mers: capacity / k / passes epochs
    try testing.expectEqual(Epochs{ .num = 5, .size = 20000 }, computeEpochs(4000, 100000, 200, 4));
    // too few: epochs of exactly 10·k
    try testing.expectEqual(Epochs{ .num = 10, .size = 2000 }, computeEpochs(1 << 20, 20001, 200, 1));
    // fewer d-mers than 10·k: one epoch of all of them
    try testing.expectEqual(Epochs{ .num = 1, .size = 150 }, computeEpochs(1 << 20, 150, 200, 1));
    // capacity below k·passes: still one epoch
    try testing.expectEqual(Epochs{ .num = 1, .size = 5000 }, computeEpochs(256, 5000, 100, 4));
}

test "smallCorpus is COVER_warnOnSmallCorpus's condition" {
    try testing.expect(smallCorpus(1000, 9999));
    try testing.expect(!smallCorpus(1000, 10000));
}

test "ActiveDmers: inserts, counts and removes under collisions" {
    const gpa = testing.allocator;
    var m: ActiveDmers = try .init(gpa, 5); // 2^(2+2) = 16 slots
    defer m.deinit(gpa);
    try testing.expectEqual(@as(usize, 16), m.data.len);
    // keys that share a home slot, plus others
    var keys: [7]u32 = undefined;
    var n: usize = 0;
    var key: u32 = 0;
    const home = m.hash(1);
    while (n < 4) : (key += 1) if (m.hash(key) == home) {
        keys[n] = key;
        n += 1;
    };
    keys[4] = 1000;
    keys[5] = 2000;
    keys[6] = 3000;
    for (keys, 1..) |k, i| m.at(k).* = @intCast(i);
    // remove from the middle of the collision run; the rest stay reachable
    m.remove(keys[1]);
    m.remove(keys[4]);
    m.remove(424242); // absent: nothing happens
    for (keys, 1..) |k, i| {
        const v = m.at(k).*;
        if (k == keys[1] or k == keys[4]) try testing.expectEqual(@as(u32, 0), v) else try testing.expectEqual(@as(u32, @intCast(i)), v);
    }
    var live: usize = 0;
    for (m.data) |p| live += @intFromBool(p.value != map_empty_value);
    try testing.expectEqual(@as(usize, 7), live);
    m.clear();
    try testing.expectEqual(@as(u32, 0), m.at(keys[0]).*);
    try testing.expectEqual(@as(?u64, null), ActiveDmers.slots(1 << 30));
    try testing.expectEqual(@as(?u64, 1 << 31), ActiveDmers.slots((1 << 30) - 1));
}

test "memory estimates are exactly what the trainers allocate" {
    const gen = try testSet("json-200");
    defer gen.deinit(testing.allocator);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var dict: [4096]u8 = undefined;
    for ([_]CoverParams{ .{ .k = 200, .d = 8 }, .{ .k = 1000, .d = 12 }, .{ .k = 16, .d = 3 } }) |p| {
        var fa: testing.FailingAllocator = .init(testing.allocator, .{});
        _ = try trainCoverInto(fa.allocator(), &dict, s, p);
        try testing.expectEqual(estimateCoverMemory(s.totalSize(), s.sizes.len, p), fa.allocated_bytes);
        try testing.expectEqual(fa.allocated_bytes, fa.freed_bytes);
    }
    for ([_]FastCoverParams{ .{ .k = 200, .d = 8 }, .{ .k = 50, .d = 6, .f = 9, .accel = 3 }, .{ .k = 50, .d = 6, .f = 0 } }) |p| {
        var fa: testing.FailingAllocator = .init(testing.allocator, .{});
        _ = try trainFastCoverInto(fa.allocator(), &dict, s, p);
        try testing.expectEqual(estimateFastCoverMemory(s.sizes.len, p), fa.allocated_bytes);
    }
}

test "the memory ceiling refuses before allocating anything" {
    const gen = try testSet("json-200");
    defer gen.deinit(testing.allocator);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var dict: [4096]u8 = undefined;
    const cp: CoverParams = .{ .k = 200, .d = 8 };
    const need = estimateCoverMemory(s.totalSize(), s.sizes.len, cp);
    var fa: testing.FailingAllocator = .init(testing.allocator, .{ .fail_index = 0 });
    var low = cp;
    low.memory_limit = @intCast(need - 1);
    try testing.expectError(error.MemoryLimitExceeded, trainCoverInto(fa.allocator(), &dict, s, low));
    low.memory_limit = @intCast(need);
    try testing.expectError(error.OutOfMemory, trainCoverInto(fa.allocator(), &dict, s, low)); // it tried
    const fp: FastCoverParams = .{ .k = 200, .d = 8, .f = 31 };
    try testing.expectEqual((@as(u64, 1) << 31) * 6 + (s.sizes.len + 1) * 8, estimateFastCoverMemory(s.sizes.len, fp));
    try testing.expectError(error.MemoryLimitExceeded, trainFastCoverInto(fa.allocator(), &dict, s, fp));
    // the default ceiling holds cover over ~30 MB of samples, not over 40
    try testing.expect(estimateCoverMemory(30 << 20, 1000, .{ .k = 1000, .d = 8 }) <= default_memory_limit);
    try testing.expect(estimateCoverMemory(40 << 20, 1000, .{ .k = 1000, .d = 8 }) > default_memory_limit);
}

test "refusals: libzstd's, and sizes past the buffer" {
    const gen = try testSet("json-200");
    defer gen.deinit(testing.allocator);
    const gpa = testing.allocator;
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var dict: [1024]u8 = undefined;
    // sizes summing past the buffer (libzstd would read past it)
    const short: Samples = .{ .buffer = gen.buffer[0 .. gen.buffer.len - 1], .sizes = gen.sizes };
    try testing.expectError(error.SrcSizeWrong, trainCoverInto(gpa, &dict, short, .{ .k = 50, .d = 6 }));
    try testing.expectError(error.SrcSizeWrong, trainFastCoverInto(gpa, &dict, short, .{ .k = 50, .d = 6 }));
    // no samples
    const none: Samples = .{ .buffer = "", .sizes = &.{} };
    try testing.expectError(error.SrcSizeWrong, trainCoverInto(gpa, &dict, none, .{ .k = 50, .d = 6 }));
    try testing.expectError(error.SrcSizeWrong, trainFastCoverInto(gpa, &dict, none, .{ .k = 50, .d = 6 }));
    // fewer than 5 samples, and fewer than 8 bytes
    try testing.expectError(error.SrcSizeWrong, trainCoverInto(gpa, &dict, .{ .buffer = s.buffer, .sizes = s.sizes[0..4] }, .{ .k = 50, .d = 6 }));
    try testing.expectError(error.SrcSizeWrong, trainFastCoverInto(gpa, &dict, .{ .buffer = "abcdefg", .sizes = &.{ 1, 1, 1, 1, 3 } }, .{ .k = 50, .d = 6 }));
    // d above the samples' total
    try testing.expectError(error.SrcSizeWrong, trainCoverInto(gpa, &dict, .{ .buffer = "abcdefghij", .sizes = &.{ 2, 2, 2, 2, 2 } }, .{ .k = 50, .d = 11 }));
    // parameter checks come first
    try testing.expectError(error.ParameterOutOfBound, trainCoverInto(gpa, dict[0..10], none, .{ .k = 50, .d = 6 }));
    try testing.expectError(error.DstSizeTooSmall, trainCoverInto(gpa, dict[0..100], s, .{ .k = 50, .d = 6 }));
    // a split point out of (0, 1] at the context level
    try testing.expectError(error.ParameterOutOfBound, CoverContext.init(gpa, s, 8, 0, default_memory_limit));
    try testing.expectError(error.ParameterOutOfBound, FastCoverContext.init(gpa, s, 8, 1.5, 20, accel_table[1], default_memory_limit));
    // a training share shorter than one d-mer (libzstd underflows)
    try testing.expectError(error.SrcSizeWrong, CoverContext.init(gpa, .{ .buffer = "abcdefghijklmnopqrstuvwxyz", .sizes = &.{ 1, 1, 1, 1, 1, 1, 20 } }, 8, 0.8, default_memory_limit));
}

test "trainCover / trainFastCover return the content trainInto places at the tail" {
    const gpa = testing.allocator;
    const gen = try testSet("words-300");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var dict: [3000]u8 = undefined;
    @memset(&dict, 0xAA);
    const n = try trainCoverInto(gpa, &dict, s, .{ .k = 100, .d = 6 });
    const c = try trainCover(gpa, s, dict.len, .{ .k = 100, .d = 6 });
    defer gpa.free(c);
    try testing.expectEqualSlices(u8, dict[dict.len - n ..], c);
    const zeros = try testSet("zeros-20");
    defer zeros.deinit(gpa);
    // a short content leaves the head of the buffer untouched
    @memset(&dict, 0xAA);
    const m = try trainFastCoverInto(gpa, &dict, .{ .buffer = zeros.buffer, .sizes = zeros.sizes }, .{ .k = 64, .d = 8 });
    try testing.expectEqual(@as(usize, 8), m);
    for (dict[0 .. dict.len - m]) |b| try testing.expectEqual(@as(u8, 0xAA), b);
    const fc = try trainFastCover(gpa, .{ .buffer = zeros.buffer, .sizes = zeros.sizes }, dict.len, .{ .k = 64, .d = 8 });
    defer gpa.free(fc);
    try testing.expectEqualSlices(u8, dict[dict.len - m ..], fc);
}

test "optimizer grid: libzstd's defaults, checks and iteration count" {
    const g: OptimizeGrid = try .init(.cover, .{}, 100, 4096);
    try testing.expectEqual(@as(u32, 6), g.d_min);
    try testing.expectEqual(@as(u32, 8), g.d_max);
    try testing.expectEqual(@as(u32, 48), g.k_step_size); // (2000 - 50) / 40
    try testing.expectEqual(@as(u32, 82), g.iterations);
    try testing.expectEqual(@as(f64, 1.0), g.split_point);
    // ZDICT_trainFromBuffer's parameters: fastCover, d = 8, steps = 4
    const t: OptimizeGrid = try .init(.fast_cover, .{ .d = 8, .steps = 4 }, 100, 4096);
    try testing.expectEqual(@as(u32, 487), t.k_step_size);
    try testing.expectEqual(@as(u32, 5), t.iterations);
    try testing.expectEqual(@as(f64, 0.75), t.split_point);
    try testing.expectEqual(@as(u32, 20), t.f);
    try testing.expectEqual(@as(u32, 1), t.accel);
    try testing.expectError(error.ParameterOutOfBound, OptimizeGrid.init(.cover, .{ .split_point = 1.5 }, 100, 4096));
    try testing.expectError(error.ParameterOutOfBound, OptimizeGrid.init(.fast_cover, .{ .accel = 11 }, 100, 4096));
    try testing.expectError(error.ParameterOutOfBound, OptimizeGrid.init(.cover, .{ .k = 7, .d = 8 }, 100, 4096));
    try testing.expectError(error.SrcSizeWrong, OptimizeGrid.init(.cover, .{}, 0, 4096));
    try testing.expectError(error.DstSizeTooSmall, OptimizeGrid.init(.cover, .{}, 100, 255));
}

/// A stand-in for Z5b's `COVER_selectDict`: scores a candidate by a hash of
/// its content, records the order it was asked in.
const MockScorer = struct {
    seen: std.ArrayList([2]u32) = .empty,
    contents: std.ArrayList([]u8) = .empty,
    fail_k: u32 = 0,
    released: usize = 0,

    fn select(m: *MockScorer, c: Candidate) !?Selection {
        try m.seen.append(testing.allocator, .{ c.d, c.k });
        try m.contents.append(testing.allocator, try testing.allocator.dupe(u8, c.content));
        if (c.k == m.fail_k) return null;
        return .{ .dict = c.content, .total_compressed_size = std.hash.Wyhash.hash(0, c.content) % 5 };
    }
    fn release(m: *MockScorer, _: Selection) void {
        m.released += 1;
    }
    fn deinit(m: *MockScorer) void {
        for (m.contents.items) |c| testing.allocator.free(c);
        m.contents.deinit(testing.allocator);
        m.seen.deinit(testing.allocator);
    }
};

test "optimizer: walks the grid in libzstd's order, first strict minimum wins" {
    const gpa = testing.allocator;
    const gen = try testSet("json-2000");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var dict: [1500]u8 = undefined;
    inline for (.{ Trainer.cover, Trainer.fast_cover }) |trainer| {
        var m: MockScorer = .{ .fail_k = 50 + 3 * 48 };
        defer m.deinit();
        const p: OptimizeParams = .{};
        const r = if (trainer == .cover) try optimizeCover(gpa, &dict, s, p, &m) else try optimizeFastCover(gpa, &dict, s, p, &m);
        // k above the capacity (1500) is skipped: 50 + 48·j ≤ 1500 → 31 per d
        try testing.expectEqual(@as(usize, 62), m.seen.items.len);
        try testing.expectEqual(@as(usize, 60), m.released);
        for (m.seen.items, 0..) |dk, i| {
            try testing.expectEqual(@as(u32, if (i < 31) 6 else 8), dk[0]);
            try testing.expectEqual(@as(u32, @intCast(50 + 48 * (i % 31))), dk[1]);
        }
        // the winner: the first candidate with the smallest score
        var best: usize = 0;
        var best_score: u64 = std.math.maxInt(u64);
        for (m.contents.items, m.seen.items, 0..) |c, dk, i| {
            if (dk[1] == m.fail_k) continue;
            const sc = std.hash.Wyhash.hash(0, c) % 5;
            if (sc < best_score) {
                best_score = sc;
                best = i;
            }
        }
        try testing.expectEqual(m.seen.items[best][0], r.d);
        try testing.expectEqual(m.seen.items[best][1], r.k);
        try testing.expectEqualSlices(u8, m.contents.items[best], dict[0..r.size]);
        // each candidate is the content of a single build on the same split
        const pick = 40; // d = 8, k = 50 + 48·9
        const k: u32 = 50 + 48 * 9;
        var one: [1500]u8 = undefined;
        if (trainer == .cover) {
            const n = try trainCoverInto(gpa, &one, s, .{ .k = k, .d = 8 });
            try testing.expectEqualSlices(u8, one[one.len - n ..], m.contents.items[pick]);
        } else {
            var ctx: FastCoverContext = try .init(gpa, s, 8, 0.75, 20, accel_table[1], default_memory_limit);
            defer ctx.deinit(gpa);
            const seg = try gpa.alloc(u16, ctx.freqs.len);
            defer gpa.free(seg);
            @memset(seg, 0);
            const tail = ctx.buildDictionary(ctx.freqs, &one, k, 8, seg);
            try testing.expectEqualSlices(u8, one[tail..], m.contents.items[pick]);
            try testing.expectEqual(@as(usize, 1500), ctx.nb_train_samples);
        }
    }
    // no candidate succeeds
    var m: MockScorer = .{ .fail_k = 100 };
    defer m.deinit();
    try testing.expectError(error.NoCandidate, optimizeCover(gpa, &dict, s, .{ .k = 100, .d = 8 }, &m));
}
