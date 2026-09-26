// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Dictionary training (port of libzstd lib/dictBuilder/cover.c and
//! fastcover.c, v1.5.7; finalization in zdict.zig).
//!
//! libzstd's trainers pick a dictionary's CONTENT -- segments of the
//! samples, best first at the end -- and then `ZDICT_finalizeDictionary`
//! puts the header and the entropy tables in front of it. The content alone
//! (`coverContent*`, `fastCoverContent*`) is byte for byte what the
//! trainers place in the dictionary buffer before finalization (`dict +
//! tail .. dict + capacity`), a usable raw-content dictionary by itself;
//! `trainCover`, `trainFastCover`, `optimizeCover`, `optimizeFastCover`
//! and `train` give the finished dictionary.
//!
//! `cover` sorts every d-byte substring of the samples (a partial suffix
//! array, `COVER_ctx_init`) and scores segments by how many samples each of
//! their d-mers occurs in; `fastCover` scores by hashed d-mer frequencies in
//! a 2^f table instead, which needs no sort and memory independent of the
//! sample size. Both cut the samples into epochs and take the best k-byte
//! segment from each in turn (`COVER_computeEpochs`), filling the buffer
//! from the back, until it is full or the scores run out.
//!
//! The optimizers (`ZDICT_optimizeTrainFromBuffer_*`) walk a grid of
//! (k, d) over one shared context per d, as libzstd does single-threaded,
//! and rank candidates by `COVER_selectDict` (`selectDict`): finalize, then
//! compress the testing samples with the dictionary. `optimize*With` takes
//! a caller's score instead.
//!
//! Memory: cover needs 8 bytes per sample byte (the suffix array, then the
//! frequencies, and the position-to-d-mer map) plus the offsets and the
//! active-d-mer map; fastCover 6 bytes per table entry (2^f frequencies and
//! 2^f 16-bit in-segment counts) plus the offsets. `estimateCoverMemory` /
//! `estimateFastCoverMemory` give the exact bytes the trainers allocate
//! besides the dictionary itself, and every trainer refuses with
//! `error.MemoryLimitExceeded` rather than allocate past `memory_limit`;
//! the complete trainers count finalization and scoring against it too
//! (`LimitedAllocator`).

const std = @import("std");
const builtin = @import("builtin");
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
    /// (no allocation was made), or the trainer's working memory would
    /// have gone past it (an allocation was refused).
    MemoryLimitExceeded,
    OutOfMemory,
    /// Finalization (`zdict.Error`): content too large for the offset
    /// codes (`dictionaryCreation_failed`).
    DictionaryCreationFailed,
    /// Finalization: an entropy table could not be built or written
    /// (`GENERIC`).
    Generic,
    /// A finalization level above 22 (libzstd clamps it).
    LevelUnsupported,
    /// The optimizer found no candidate that finalized and compressed
    /// (libzstd: `GENERIC`).
    NoCandidate,
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
    /// d-mer size (1 ≤ d ≤ k); 8 as the `zstd` CLI's default (libzstd's
    /// optimizer tries 6 and 8).
    d: u32 = 8,
    /// `zParams.compressionLevel`: the level finalization measures the
    /// entropy tables with; 0 = 3.
    level: i32 = 0,
    /// `zParams.dictID`: 0 = derived from the content.
    dict_id: u32 = 0,
    /// Working-memory ceiling (the dictionary buffer not counted); see
    /// `estimateCoverMemory` for the content selection's share.
    memory_limit: usize = default_memory_limit,
};

/// `ZDICT_fastCover_params_t` as `ZDICT_trainFromBuffer_fastCover` reads it.
pub const FastCoverParams = struct {
    /// Segment size (required, `d` ≤ k ≤ capacity).
    k: u32,
    /// d-mer size: 6 or 8 (the `zstd` CLI's default).
    d: u32 = 8,
    /// log2 of the frequency table (1..31); 0 means `fastcover_default_f`.
    f: u32 = fastcover_default_f,
    /// Acceleration (1..10): count every accel-th d-mer only; 0 means
    /// `fastcover_default_accel`. It also sets the share of samples
    /// finalization uses (`Accel.finalize`).
    accel: u32 = fastcover_default_accel,
    /// See `CoverParams.level`.
    level: i32 = 0,
    /// See `CoverParams.dict_id`.
    dict_id: u32 = 0,
    /// Working-memory ceiling (the dictionary buffer not counted); see
    /// `estimateFastCoverMemory` for the content selection's share.
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

/// The bytes `coverContent` / `coverContentInto` allocate for `nb_samples`
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
pub fn coverContentInto(gpa: Allocator, dict: []u8, samples: Samples, params: CoverParams) Error!usize {
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

/// `coverContentInto` into a `capacity`-byte buffer; returns the content
/// alone, owned by the caller.
pub fn coverContent(gpa: Allocator, samples: Samples, capacity: usize, params: CoverParams) Error![]u8 {
    return trainAlloc(gpa, capacity, samples, params, coverContentInto);
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

/// The bytes `fastCoverContent` / `fastCoverContentInto` allocate for
/// `nb_samples` samples (besides the dictionary): offsets, 2^f frequencies
/// and 2^f in-segment counts. Independent of the samples' size. f is
/// resolved (0 → default) but not checked; above 31 gives `maxInt(u64)`.
pub fn estimateFastCoverMemory(nb_samples: usize, params: FastCoverParams) u64 {
    const f = resolvedF(params.f);
    if (f > fastcover_max_f) return std.math.maxInt(u64);
    return FastCoverContext.memory(nb_samples, f) + (@as(u64, 1) << @intCast(f)) * @sizeOf(u16);
}

/// `ZDICT_trainFromBuffer_fastCover` up to its finalization; see
/// `coverContentInto`.
pub fn fastCoverContentInto(gpa: Allocator, dict: []u8, samples: Samples, params: FastCoverParams) Error!usize {
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

/// `fastCoverContentInto` into a `capacity`-byte buffer; returns the content
/// alone, owned by the caller.
pub fn fastCoverContent(gpa: Allocator, samples: Samples, capacity: usize, params: FastCoverParams) Error![]u8 {
    return trainAlloc(gpa, capacity, samples, params, fastCoverContentInto);
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
    /// See `CoverParams.level`.
    level: i32 = 0,
    /// See `CoverParams.dict_id`.
    dict_id: u32 = 0,
    /// Working-memory ceiling (the dictionary buffer not counted).
    /// `optimize*With` checks one context plus one candidate's content
    /// selection against it up front and leaves the scorer's memory to the
    /// scorer; `optimizeCover` / `optimizeFastCover` hold all of it,
    /// scoring included, below the ceiling.
    memory_limit: usize = default_memory_limit,
    /// `nbThreads`: candidates built and scored at once, each on a thread
    /// of its own (0 and 1: one, on the calling thread). The result is the
    /// same for every count: the candidates are compared in grid order, as
    /// libzstd compares them single-threaded, where libzstd with threads
    /// keeps whichever of two equally good candidates finishes first. Each
    /// candidate needs its own working memory; `memory_limit` bounds the
    /// sum: fewer run at once when the ceiling does not hold this many
    /// content selections next to the context, and a candidate refused by
    /// the ceiling while others held memory is run again with half as many
    /// at once (refused alone, it is `error.MemoryLimitExceeded`, as with
    /// one thread). The allocator must be thread-safe.
    nb_threads: u32 = 1,
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
    /// The candidate's whole buffer, `capacity` bytes, `content` at its end
    /// (`COVER_selectDict`'s shrinking reads before the content).
    buffer: []const u8,
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
    /// For the scorer's own allocations: the optimizer's allocator, or,
    /// under a memory ceiling, this candidate's share of it (so that a
    /// refusal is told apart when candidates run in parallel).
    gpa: Allocator,
};

/// What a scorer makes of a candidate (`COVER_dictSelection_t`): the
/// dictionary it would output and its total compressed size.
pub const Selection = struct {
    /// Owned by the scorer until `optimize*` copies it.
    dict: []const u8,
    total_compressed_size: u64,
    /// The allocation `dict` lies in, if the scorer wants it back.
    buffer: []u8 = &.{},
};

/// The optimizer's result: the winning dictionary's size (copied to the
/// front of `dict`) and parameters.
pub const Optimized = struct { size: usize, k: u32, d: u32, split_point: f64, steps: u32, f: u32, accel: u32 };

/// `ZDICT_optimizeTrainFromBuffer_cover`, with `COVER_selectDict` replaced
/// by `scorer.select(Candidate) !?Selection` (null: the candidate failed,
/// as a `COVER_dictSelectionIsError` result; an error ends the search).
/// The first candidate in grid order with the strictly smallest total
/// compressed size wins, as `COVER_best_finish` decides when the
/// candidates finish in submission order (libzstd single-threaded);
/// `scorer.release(Selection)` is called for every selection once it has
/// been compared. No winner: `error.NoCandidate` (libzstd returns
/// `GENERIC`). With `params.nb_threads` above 1, `select` runs on several
/// threads at once and must be thread-safe, as must `gpa` (`release` is
/// called on the calling thread only); the result does not change (see
/// `OptimizeParams.nb_threads`).
pub fn optimizeCoverWith(gpa: Allocator, dict: []u8, samples: Samples, params: OptimizeParams, scorer: anytype) !Optimized {
    return optimize(.cover, gpa, null, dict, samples, params, scorer);
}

/// `ZDICT_optimizeTrainFromBuffer_fastCover`; see `optimizeCoverWith`.
pub fn optimizeFastCoverWith(gpa: Allocator, dict: []u8, samples: Samples, params: OptimizeParams, scorer: anytype) !Optimized {
    return optimize(.fast_cover, gpa, null, dict, samples, params, scorer);
}

/// The futex of the process-global `std.Io.Threaded` (its futex calls use
/// no state of the instance), as `zstdmt.zig` uses it: no libc, and no
/// `Io` from the caller.
const Futex = struct {
    fn io() std.Io {
        return std.Io.Threaded.global_single_threaded.io();
    }
    fn wait(word: *const std.atomic.Value(u32), expected: u32) void {
        io().futexWaitUncancelable(u32, &word.raw, expected);
    }
    fn wake(word: *const std.atomic.Value(u32), n: u32) void {
        io().futexWake(u32, &word.raw, n);
    }
};

/// The optimizers' engine. libzstd with `nbThreads > 1` posts each (k, d)
/// candidate to a pool and keeps whichever strictly smaller total
/// finishes first (`COVER_best_finish` under a mutex), so of two
/// candidates with the same total it may keep either. Here the candidates
/// of one d are built and scored `n_par` at a time (one worker thread per
/// slot) but compared on the calling thread in grid order, so the winner
/// is the single-threaded one whatever the thread count or the timing.
/// A slot holds its candidate -- in flight, or done and waiting for its
/// turn -- until it is compared, so no more than `n_par` candidates' memory
/// is ever live.
fn Optimizer(comptime trainer: Trainer, comptime ScorerPtr: type) type {
    return struct {
        const Self = @This();
        const Ctx = if (trainer == .cover) CoverContext else FastCoverContext;
        const Scorer = switch (@typeInfo(ScorerPtr)) {
            .pointer => |p| p.child,
            else => ScorerPtr,
        };
        const SelectReturn = @typeInfo(@TypeOf(Scorer.select)).@"fn".return_type.?;
        pub const Err = @typeInfo(SelectReturn).error_union.error_set || Error;
        const Result = Err!?Selection;

        const idle = 0;
        const posted = 1;
        const done = 2;
        const shutdown = 3;

        const Slot = struct {
            /// The futex word: `idle`, `posted`, `done` or `shutdown`.
            state: std.atomic.Value(u32) = .init(idle),
            owner: *Self,
            k: u32 = 0,
            /// This slot's share of the ceiling, when there is one: tells a
            /// refusal of its own allocations from any other failure.
            view: LimitedAllocator.View = undefined,
            /// The candidate's buffer (its content at the end), kept until
            /// the candidate is compared: the selection may point into it.
            scratch: []u8 = &.{},
            result: Result = null,

            fn allocator(slot: *Slot) Allocator {
                return if (slot.owner.budget != null) slot.view.allocator() else slot.owner.gpa;
            }

            fn refused(slot: *const Slot) bool {
                return slot.owner.budget != null and slot.view.refused;
            }
        };

        gpa: Allocator,
        budget: ?*LimitedAllocator,
        /// For the slots and threads: bookkeeping that does not grow with
        /// the input, kept out of the ceiling so that a candidate run
        /// alone sees the same budget whatever the thread count.
        meta: Allocator,
        scorer: ScorerPtr,
        grid: OptimizeGrid,
        capacity: usize,
        samples: Samples,
        ctx: *const Ctx = undefined,
        d: u32 = 0,
        slots: []Slot = &.{},
        threads: []std.Thread = &.{},

        /// One candidate (`COVER_tryParameters`): its content built on a
        /// copy of the context's frequencies, then scored.
        fn run(o: *Self, slot: *Slot) Result {
            const a = slot.allocator();
            const k = slot.k;
            const d = o.d;
            const ctx = o.ctx;
            slot.scratch = try a.alloc(u8, o.capacity);
            const tail = blk: {
                // Copy the frequencies because we need to modify them
                const freqs = try a.alloc(u32, ctx.freqs.len);
                defer a.free(freqs);
                @memcpy(freqs, ctx.freqs);
                if (trainer == .cover) {
                    var active: ActiveDmers = try .init(a, k - d + 1);
                    defer active.deinit(a);
                    break :blk ctx.buildDictionary(freqs, &active, slot.scratch, k, d);
                } else {
                    const segment_freqs = try a.alloc(u16, ctx.freqs.len);
                    defer a.free(segment_freqs);
                    @memset(segment_freqs, 0);
                    break :blk ctx.buildDictionary(freqs, slot.scratch, k, d, segment_freqs);
                }
            };
            return o.scorer.select(Candidate{
                .content = slot.scratch[tail..],
                .buffer = slot.scratch,
                .capacity = o.capacity,
                .k = k,
                .d = d,
                .split_point = o.grid.split_point,
                .nb_finalize_samples = if (trainer == .cover) ctx.nb_train_samples else ctx.nbFinalizeSamples(),
                .nb_train_samples = ctx.nb_train_samples,
                .samples = o.samples,
                .offsets = ctx.offsets,
                .gpa = a,
            });
        }

        fn worker(o: *Self, slot: *Slot) void {
            while (true) {
                const s = slot.state.load(.acquire);
                if (s == shutdown) return;
                if (s != posted) {
                    Futex.wait(&slot.state, s);
                    continue;
                }
                slot.result = o.run(slot);
                slot.state.store(done, .release);
                Futex.wake(&slot.state, 1);
            }
        }

        fn post(o: *Self, slot: *Slot, k: u32) void {
            slot.k = k;
            slot.result = null;
            slot.scratch = &.{};
            if (o.budget) |b| slot.view = .{ .parent = b };
            if (o.threads.len == 0) {
                slot.result = o.run(slot);
                slot.state.store(done, .monotonic);
                return;
            }
            slot.state.store(posted, .release);
            Futex.wake(&slot.state, 1);
        }

        fn wait(slot: *Slot) void {
            while (true) {
                const s = slot.state.load(.acquire);
                if (s == done or s == idle) return;
                Futex.wait(&slot.state, s);
            }
        }

        /// Done with the slot's candidate: its selection released, its
        /// buffer freed.
        fn clear(o: *Self, slot: *Slot) void {
            if (slot.result) |sel| {
                if (sel) |x| o.scorer.release(x);
            } else |_| {}
            slot.result = null;
            if (slot.scratch.len != 0) slot.allocator().free(slot.scratch);
            slot.scratch = &.{};
            slot.state.store(idle, .monotonic);
        }

        /// Waits for every slot in flight and drops what it made.
        fn drain(o: *Self) void {
            for (o.slots) |*s| {
                wait(s);
                o.clear(s);
            }
        }

        /// `n` slots; with more than one, a worker thread for each.
        fn start(o: *Self, n: usize) error{OutOfMemory}!void {
            o.slots = try o.meta.alloc(Slot, n);
            for (o.slots) |*s| s.* = .{ .owner = o };
            if (n < 2) return;
            const threads = try o.meta.alloc(std.Thread, n);
            for (threads, 0..) |*t, i| {
                t.* = std.Thread.spawn(.{}, worker, .{ o, &o.slots[i] }) catch {
                    o.threads = threads[0..i];
                    o.stop();
                    o.meta.free(threads);
                    return error.OutOfMemory;
                };
            }
            o.threads = threads;
        }

        /// Joins the workers (idle: every posted candidate was waited
        /// for) and frees the slots.
        fn stop(o: *Self) void {
            for (o.slots[0..o.threads.len]) |*s| {
                s.state.store(shutdown, .release);
                Futex.wake(&s.state, 1);
            }
            for (o.threads) |t| t.join();
            if (o.threads.len == o.slots.len and o.threads.len != 0) o.meta.free(o.threads);
            o.threads = &.{};
            o.meta.free(o.slots);
            o.slots = &.{};
        }

        /// The next k of the grid for this d, from `next.*` (`k += kStepSize`
        /// while `k <= kMaxK`) that passes `COVER_checkParameters`.
        fn nextK(o: *const Self, next: *u64) ?u32 {
            while (next.* <= o.grid.k_max) {
                const k: u32 = @intCast(next.*);
                next.* += o.grid.k_step_size;
                const ok = if (trainer == .cover)
                    checkCoverParameters(k, o.d, o.grid.split_point, o.capacity)
                else
                    checkFastCoverParameters(k, o.d, o.grid.split_point, o.capacity, o.ctx.f, o.grid.accel);
                if (ok) return k;
            }
            return null;
        }
    };
}

/// Test seams: how often a candidate refused under contention was run again;
/// the slot count of the last run and the static count of its last d.
var optimize_retries: std.atomic.Value(u32) = .init(0);
var optimize_slots: std.atomic.Value(usize) = .init(0);
var optimize_static_par: std.atomic.Value(usize) = .init(0);

fn optimize(comptime trainer: Trainer, gpa: Allocator, budget: ?*LimitedAllocator, dict: []u8, samples: Samples, params: OptimizeParams, scorer: anytype) (Optimizer(trainer, @TypeOf(scorer)).Err || Error)!Optimized {
    const grid: OptimizeGrid = try .init(trainer, params, samples.sizes.len, dict.len);
    const O = Optimizer(trainer, @TypeOf(scorer));
    var o: O = .{ .gpa = gpa, .budget = budget, .meta = if (budget) |b| b.child else gpa, .scorer = scorer, .grid = grid, .capacity = dict.len, .samples = samples };
    // no more slots than one d has candidates
    const per_d: u64 = 1 + (grid.k_max - grid.k_min) / grid.k_step_size;
    const threads: u64 = if (builtin.single_threaded) 1 else @max(params.nb_threads, 1);
    try o.start(@intCast(@min(threads, per_d)));
    defer o.stop();
    optimize_slots.store(o.slots.len, .monotonic);
    var best: ?Optimized = null;
    var best_size: u64 = std.math.maxInt(u64);
    // u64 counters: libzstd's unsigned ones wrap (and loop forever) when
    // d or k is near 2^32.
    var d64: u64 = grid.d_min;
    while (d64 <= grid.d_max) : (d64 += 2) {
        const d: u32 = @intCast(d64);
        var ctx: O.Ctx = if (trainer == .cover)
            try .init(gpa, samples, d, grid.split_point, params.memory_limit)
        else
            try .init(gpa, samples, d, grid.split_point, grid.f, accel_table[grid.accel], params.memory_limit);
        defer ctx.deinit(gpa);
        o.ctx = &ctx;
        o.d = d;
        const ctx_memory = O.Ctx.memory(samples.sizes.len, if (trainer == .cover) ctx.suffix_size else grid.f);
        const candidate_memory: u64 = if (trainer == .cover)
            @as(u64, ctx.suffix_size) * @sizeOf(u32) + (ActiveDmers.bytes(grid.k_max -| d + 1) orelse std.math.maxInt(u64))
        else
            (@as(u64, 1) << @intCast(grid.f)) * (@sizeOf(u32) + @sizeOf(u16));
        if (ctx_memory +| candidate_memory > params.memory_limit) return error.MemoryLimitExceeded;
        // As many candidates at once as the ceiling holds next to the
        // context (each: its content selection and its buffer)
        var n_par: usize = @intCast(@min(o.slots.len, @max(1, (params.memory_limit - ctx_memory) / (candidate_memory +| dict.len))));
        optimize_static_par.store(n_par, .monotonic);

        var next: u64 = grid.k_min; // the next k to post
        var head: usize = 0; // the slot compared next
        var in_flight: usize = 0;
        while (true) {
            while (in_flight < n_par) : (in_flight += 1) {
                const k = o.nextK(&next) orelse break;
                o.post(&o.slots[(head + in_flight) % n_par], k);
            }
            if (in_flight == 0) break;
            const slot = &o.slots[head];
            O.wait(slot);
            const selection = slot.result catch |e| {
                if (e == error.OutOfMemory and slot.refused() and n_par > 1) {
                    // Refused by the ceiling while other candidates held
                    // memory: drop them all and go on from this one with
                    // half as many at once. Alone, a refusal is final --
                    // as it is with one thread.
                    next = slot.k;
                    _ = optimize_retries.fetchAdd(1, .monotonic);
                    o.drain();
                    n_par = @max(1, n_par / 2);
                    head = 0;
                    in_flight = 0;
                    continue;
                }
                o.drain();
                return e;
            };
            if (selection) |sel| {
                // COVER_best_finish: if the new dictionary is better
                if (sel.total_compressed_size < best_size) {
                    best_size = sel.total_compressed_size;
                    @memcpy(dict[0..sel.dict.len], sel.dict);
                    best = .{ .size = sel.dict.len, .k = slot.k, .d = d, .split_point = grid.split_point, .steps = grid.steps, .f = grid.f, .accel = grid.accel };
                }
            }
            o.clear(slot);
            head = (head + 1) % n_par;
            in_flight -= 1;
        }
    }
    return best orelse error.NoCandidate;
}

// ---------------------------------------------------------------------------
// Finalization, scoring and the complete trainers (zdict.c, cover.c)

pub const zdict = @import("zdict.zig");
const frame = @import("frame.zig");
const cdict_mod = @import("cdict.zig");

/// `ZDICT_getDictID`.
pub const getDictId = zdict.getDictId;
/// `ZDICT_getDictHeaderSize`.
pub const getDictHeaderSize = zdict.getDictHeaderSize;
/// `ZDICT_params_t`.
pub const FinalizeParams = struct {
    /// `compressionLevel`: 0 = 3.
    level: i32 = 0,
    /// `dictID`: 0 = derived from the content (`zdict.defaultDictId`).
    dict_id: u32 = 0,
    /// Working-memory ceiling: the compressor and `CDict` that measure the
    /// samples (the dictionary buffer not counted).
    memory_limit: usize = default_memory_limit,
};

/// An allocator that refuses (`OutOfMemory`) any allocation taking the
/// bytes it has live past `limit`, and remembers that it did. The complete
/// trainers run on it so that every piece of their working memory --
/// contexts, candidates, compressors, `CDict`s -- counts against
/// `memory_limit`. Thread-safe when `child` is: the parallel optimizers
/// charge it from several threads, each candidate through a `View`. Read
/// `live`, `peak` and `refused` once no other thread uses it. (std has no
/// such wrapper outside `DebugAllocator`.)
pub const LimitedAllocator = struct {
    child: Allocator,
    limit: usize,
    live: usize = 0,
    /// The most bytes live at once.
    peak: usize = 0,
    refused: bool = false,

    pub fn init(child: Allocator, limit: usize) LimitedAllocator {
        return .{ .child = child, .limit = limit };
    }

    pub fn allocator(l: *LimitedAllocator) Allocator {
        return .{ .ptr = l, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    /// A share of a `LimitedAllocator`: its allocations count against the
    /// parent's limit, and it remembers whether the parent refused one of
    /// ITS allocations.
    pub const View = struct {
        parent: *LimitedAllocator,
        refused: bool = false,

        pub fn allocator(v: *View) Allocator {
            return .{ .ptr = v, .vtable = &.{ .alloc = viewAlloc, .resize = viewResize, .remap = viewRemap, .free = viewFree } };
        }

        fn viewAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
            const v: *View = @ptrCast(@alignCast(ctx));
            return v.parent.doAlloc(&v.refused, len, alignment, ra);
        }
        fn viewResize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
            const v: *View = @ptrCast(@alignCast(ctx));
            return v.parent.doResize(&v.refused, memory, alignment, new_len, ra);
        }
        fn viewRemap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
            const v: *View = @ptrCast(@alignCast(ctx));
            return v.parent.doRemap(&v.refused, memory, alignment, new_len, ra);
        }
        fn viewFree(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
            const v: *View = @ptrCast(@alignCast(ctx));
            v.parent.doFree(memory, alignment, ra);
        }
    };

    /// Takes `n` more bytes live, unless that passes the limit.
    fn reserve(l: *LimitedAllocator, n: usize, refused: *bool) bool {
        var cur = @atomicLoad(usize, &l.live, .monotonic);
        while (true) {
            if (n > l.limit - cur) {
                @atomicStore(bool, &l.refused, true, .monotonic);
                refused.* = true;
                return false;
            }
            cur = @cmpxchgWeak(usize, &l.live, cur, cur + n, .monotonic, .monotonic) orelse break;
        }
        const now = cur + n;
        var p = @atomicLoad(usize, &l.peak, .monotonic);
        while (now > p) p = @cmpxchgWeak(usize, &l.peak, p, now, .monotonic, .monotonic) orelse break;
        return true;
    }

    fn unreserve(l: *LimitedAllocator, n: usize) void {
        _ = @atomicRmw(usize, &l.live, .Sub, n, .monotonic);
    }

    fn doAlloc(l: *LimitedAllocator, refused: *bool, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        if (!l.reserve(len, refused)) return null;
        return l.child.rawAlloc(len, alignment, ra) orelse {
            l.unreserve(len);
            return null;
        };
    }

    fn doResize(l: *LimitedAllocator, refused: *bool, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        if (new_len > memory.len and !l.reserve(new_len - memory.len, refused)) return false;
        if (!l.child.rawResize(memory, alignment, new_len, ra)) {
            if (new_len > memory.len) l.unreserve(new_len - memory.len);
            return false;
        }
        if (new_len < memory.len) l.unreserve(memory.len - new_len);
        return true;
    }

    fn doRemap(l: *LimitedAllocator, refused: *bool, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        if (new_len > memory.len and !l.reserve(new_len - memory.len, refused)) return null;
        const p = l.child.rawRemap(memory, alignment, new_len, ra) orelse {
            if (new_len > memory.len) l.unreserve(new_len - memory.len);
            return null;
        };
        if (new_len < memory.len) l.unreserve(memory.len - new_len);
        return p;
    }

    fn doFree(l: *LimitedAllocator, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        l.child.rawFree(memory, alignment, ra);
        l.unreserve(memory.len);
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const l: *LimitedAllocator = @ptrCast(@alignCast(ctx));
        var r = false;
        return l.doAlloc(&r, len, alignment, ra);
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const l: *LimitedAllocator = @ptrCast(@alignCast(ctx));
        var r = false;
        return l.doResize(&r, memory, alignment, new_len, ra);
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const l: *LimitedAllocator = @ptrCast(@alignCast(ctx));
        var r = false;
        return l.doRemap(&r, memory, alignment, new_len, ra);
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const l: *LimitedAllocator = @ptrCast(@alignCast(ctx));
        l.doFree(memory, alignment, ra);
    }

    /// An error of work done on this allocator, with a refusal of its own
    /// named as the ceiling.
    fn map(l: *const LimitedAllocator, e: anytype) @TypeOf(e) {
        return if (e == error.OutOfMemory and l.refused) error.MemoryLimitExceeded else e;
    }
};

fn finalizeError(e: zdict.Error) Error {
    return switch (e) {
        error.DictionaryCorrupted => unreachable, // getDictHeaderSize's alone
        inline else => |x| @field(Error, @errorName(x)),
    };
}

fn zdictSamples(s: Samples, nb: usize) zdict.Samples {
    return .{ .buffer = s.buffer, .sizes = s.sizes[0..nb] };
}

/// `ZDICT_finalizeDictionary` (see `zdict.finalizeDictionary`) with the
/// memory ceiling: `content` (anywhere, `dict` included) into a zstd
/// dictionary in `dict`, entropy tables from all of `samples`. Returns its
/// size.
pub fn finalizeDictionary(gpa: Allocator, dict: []u8, content: []const u8, samples: Samples, p: FinalizeParams) Error!usize {
    var lim: LimitedAllocator = .init(gpa, p.memory_limit);
    return zdict.finalizeDictionary(lim.allocator(), dict, content, zdictSamples(samples, samples.sizes.len), .{ .level = p.level, .dict_id = p.dict_id }) catch |e| lim.map(finalizeError(e));
}

/// `ZDICT_addEntropyTablesFromBuffer` (`_advanced`; see
/// `zdict.addEntropyTablesFromBuffer`): the content is the last
/// `content_size` bytes of `dict`.
pub fn addEntropyTablesFromBuffer(gpa: Allocator, dict: []u8, content_size: usize, samples: Samples, p: FinalizeParams) Error!usize {
    var lim: LimitedAllocator = .init(gpa, p.memory_limit);
    return zdict.addEntropyTablesFromBuffer(lim.allocator(), dict, content_size, zdictSamples(samples, samples.sizes.len), .{ .level = p.level, .dict_id = p.dict_id }) catch |e| lim.map(finalizeError(e));
}

/// `COVER_checkTotalCompressedSize`: the finished dictionary's size plus
/// every checked sample compressed with it (`ZSTD_createCDict` at `level`,
/// `ZSTD_compress_usingCDict` on one context) -- the testing share
/// `[nb_train_samples..]` for a split below 1, else all samples. Null when
/// libzstd's would fail (a compression error); out of memory is an error.
fn checkTotalCompressedSize(gpa: Allocator, dict: []const u8, level: i32, samples: Samples, offsets: []const usize, nb_train_samples: usize, split_point: f64) Allocator.Error!?u64 {
    const first: usize = if (split_point < 1.0) nb_train_samples else 0;
    // enough space to compress the maximum sized sample
    var max_sample_size: usize = 0;
    for (samples.sizes[first..]) |n| max_sample_size = @max(max_sample_size, n);
    const dst = try gpa.alloc(u8, frame.compressBound(max_sample_size));
    defer gpa.free(dst);
    var comp: frame.Compressor = .initEmpty(gpa);
    defer comp.deinit();
    var cdict = cdict_mod.CDict.init(gpa, dict, level) catch |e| return switch (e) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
    defer cdict.deinit();
    var total: u64 = dict.len;
    for (first..samples.sizes.len) |i| {
        const src = samples.buffer[offsets[i]..][0..samples.sizes[i]];
        total += comp.compressUsingCDict(dst, src, &cdict, .{}) catch |e| return switch (e) {
            error.OutOfMemory => error.OutOfMemory,
            else => null,
        };
    }
    return total;
}

/// What `COVER_selectDict` takes besides the content.
pub const SelectParams = struct {
    /// `zParams.compressionLevel` (0 = 3) and `dictID` (0 = derived).
    level: i32 = 0,
    dict_id: u32 = 0,
    /// `shrinkDict`: try dictionaries of 256 bytes and up (doubling) and
    /// take the first whose total compresses within
    /// `shrink_max_regression` percent of the full one's. libzstd 1.5.7's
    /// optimizers always pass 0, so no public libzstd trainer shrinks.
    shrink: bool = false,
    /// `shrinkDictMaxRegression`, in percent.
    shrink_max_regression: u32 = 0,
};

/// `COVER_selectDict`: finalize the content `buffer[buffer.len - content_len
/// ..]` into a dictionary of up to `buffer.len` bytes (entropy tables from
/// the first `nb_finalize_samples` samples), and score it by
/// `checkTotalCompressedSize`; with `p.shrink`, try shorter ones -- the
/// last n bytes of `buffer` for n = 256, then twice each finished size,
/// reading before the content when n passes it, as libzstd does. Null when
/// finalization or compression fails (`COVER_dictSelectionIsError`). The
/// selection's `buffer` is allocated from `gpa`; free it with
/// `freeSelection`.
pub fn selectDict(gpa: Allocator, buffer: []const u8, content_len: usize, samples: Samples, offsets: []const usize, nb_finalize_samples: usize, nb_train_samples: usize, split_point: f64, p: SelectParams) Error!?Selection {
    const capacity = buffer.len;
    const content = buffer[capacity - content_len ..];
    const regression_tolerance = @as(f64, @floatFromInt(p.shrink_max_regression)) / 100.0 + 1.00;
    const zp: zdict.Params = .{ .level = p.level, .dict_id = p.dict_id };
    const fs = zdictSamples(samples, nb_finalize_samples);

    const largest_buf = try gpa.alloc(u8, capacity);
    var keep_largest = false;
    defer if (!keep_largest) gpa.free(largest_buf);
    // Initial dictionary size and compressed size
    const largest_dict = zdict.finalizeDictionary(gpa, largest_buf, content, fs, zp) catch |e| return switch (e) {
        error.OutOfMemory, error.LevelUnsupported => finalizeError(e),
        else => null,
    };
    const largest_compressed = try checkTotalCompressedSize(gpa, largest_buf[0..largest_dict], p.level, samples, offsets, nb_train_samples, split_point) orelse return null;
    if (!p.shrink) {
        keep_largest = true;
        return .{ .dict = largest_buf[0..largest_dict], .total_compressed_size = largest_compressed, .buffer = largest_buf };
    }

    const candidate_buf = try gpa.alloc(u8, capacity);
    var keep_candidate = false;
    defer if (!keep_candidate) gpa.free(candidate_buf);
    // Largest dict is initially at least ZDICT_DICTSIZE_MIN
    var size: usize = dict_size_min;
    while (size < largest_dict) {
        // (libzstd copies the largest dictionary into the candidate buffer
        // first; finalization overwrites what it returns, so that is not
        // observable)
        size = zdict.finalizeDictionary(gpa, candidate_buf, buffer[capacity - size ..], fs, zp) catch |e| return switch (e) {
            error.OutOfMemory, error.LevelUnsupported => finalizeError(e),
            else => null,
        };
        const total = try checkTotalCompressedSize(gpa, candidate_buf[0..size], p.level, samples, offsets, nb_train_samples, split_point) orelse return null;
        if (@as(f64, @floatFromInt(total)) <= @as(f64, @floatFromInt(largest_compressed)) * regression_tolerance) {
            keep_candidate = true;
            return .{ .dict = candidate_buf[0..size], .total_compressed_size = total, .buffer = candidate_buf };
        }
        size *= 2;
    }
    keep_largest = true;
    return .{ .dict = largest_buf[0..largest_dict], .total_compressed_size = largest_compressed, .buffer = largest_buf };
}

/// Frees a `selectDict` selection.
pub fn freeSelection(gpa: Allocator, s: Selection) void {
    gpa.free(s.buffer);
}

/// The optimizers' scorer: `COVER_selectDict` without shrinking, as
/// libzstd 1.5.7's optimizers call it.
const SelectScorer = struct {
    gpa: Allocator,
    level: i32,
    dict_id: u32,

    fn select(s: *SelectScorer, c: Candidate) Error!?Selection {
        return selectDict(c.gpa, c.buffer, c.content.len, c.samples, c.offsets, c.nb_finalize_samples, c.nb_train_samples, c.split_point, .{ .level = s.level, .dict_id = s.dict_id });
    }

    fn release(s: *SelectScorer, sel: Selection) void {
        freeSelection(s.gpa, sel);
    }
};

/// `ZDICT_optimizeTrainFromBuffer_cover`: every (k, d) of the grid (see
/// `OptimizeParams`, `OptimizeGrid`) trained on the training share,
/// finalized and scored by compressing the testing share
/// (`COVER_selectDict`); the dictionary with the smallest total -- the first
/// of equals in grid order -- ends up in `dict[0..size]`. That is libzstd's
/// single-threaded result for any `p.nb_threads` (libzstd with several
/// threads keeps whichever of equals finishes first). `error.NoCandidate`
/// when no candidate finalizes.
pub fn optimizeCover(gpa: Allocator, dict: []u8, samples: Samples, p: OptimizeParams) Error!Optimized {
    return optimizeFinished(.cover, gpa, dict, samples, p);
}

/// `ZDICT_optimizeTrainFromBuffer_fastCover`; see `optimizeCover`.
pub fn optimizeFastCover(gpa: Allocator, dict: []u8, samples: Samples, p: OptimizeParams) Error!Optimized {
    return optimizeFinished(.fast_cover, gpa, dict, samples, p);
}

fn optimizeFinished(comptime trainer: Trainer, gpa: Allocator, dict: []u8, samples: Samples, p: OptimizeParams) Error!Optimized {
    if (p.level > max_level) return error.LevelUnsupported;
    var lim: LimitedAllocator = .init(gpa, p.memory_limit);
    const a = lim.allocator();
    var scorer: SelectScorer = .{ .gpa = a, .level = p.level, .dict_id = p.dict_id };
    return optimize(trainer, a, &lim, dict, samples, p, &scorer) catch |e| lim.map(e);
}

const max_level = @import("params.zig").max_level;

/// `ZDICT_trainFromBuffer`: `optimizeFastCover` with d = 8, steps = 4
/// (k from 50 to 2000 in steps of 487, split 0.75, f 20, accel 1) at level
/// 3 -- the `zstd --train` default. Returns the dictionary's size in
/// `dict`.
pub fn train(gpa: Allocator, dict: []u8, samples: Samples) Error!usize {
    return (try optimizeFastCover(gpa, dict, samples, default_train_params)).size;
}

/// `ZDICT_trainFromBuffer`'s parameters.
pub const default_train_params: OptimizeParams = .{ .d = 8, .steps = 4, .level = 3 };

/// `ZDICT_trainFromBuffer_cover`: the content (`coverContentInto`), then
/// `ZDICT_finalizeDictionary` on the training samples; the finished
/// dictionary is `dict[0..n]` for the returned n. When the header does not
/// fit in front of the content, the content's head is kept (libzstd's
/// finalization).
pub fn trainCover(gpa: Allocator, dict: []u8, samples: Samples, p: CoverParams) Error!usize {
    if (p.level > max_level) return error.LevelUnsupported;
    var lim: LimitedAllocator = .init(gpa, p.memory_limit);
    return trainCoverImpl(lim.allocator(), dict, samples, p) catch |e| lim.map(e);
}

fn trainCoverImpl(gpa: Allocator, dict: []u8, samples: Samples, p: CoverParams) Error!usize {
    const n = try coverContentInto(gpa, dict, samples, p);
    return zdict.finalizeDictionary(gpa, dict, dict[dict.len - n ..], zdictSamples(samples, samples.sizes.len), .{ .level = p.level, .dict_id = p.dict_id }) catch |e| finalizeError(e);
}

/// `ZDICT_trainFromBuffer_fastCover`; see `trainCover`. Finalization uses
/// the first `accel_table[accel].finalize` percent of the samples.
pub fn trainFastCover(gpa: Allocator, dict: []u8, samples: Samples, p: FastCoverParams) Error!usize {
    if (p.level > max_level) return error.LevelUnsupported;
    var lim: LimitedAllocator = .init(gpa, p.memory_limit);
    return trainFastCoverImpl(lim.allocator(), dict, samples, p) catch |e| lim.map(e);
}

fn trainFastCoverImpl(gpa: Allocator, dict: []u8, samples: Samples, p: FastCoverParams) Error!usize {
    const n = try fastCoverContentInto(gpa, dict, samples, p);
    // nbFinalizeSamples: of the training samples (all of them: split 1)
    const nb_finalize: usize = @intCast(@as(u64, samples.sizes.len) * accel_table[resolvedAccel(p.accel)].finalize / 100);
    return zdict.finalizeDictionary(gpa, dict, dict[dict.len - n ..], zdictSamples(samples, nb_finalize), .{ .level = p.level, .dict_id = p.dict_id }) catch |e| finalizeError(e);
}

/// A trainer and its parameters, for `trainFromSlices`.
pub const Method = union(enum) {
    /// `ZDICT_trainFromBuffer` (`train`), under this ceiling.
    default: usize,
    cover: CoverParams,
    fast_cover: FastCoverParams,
    optimize_cover: OptimizeParams,
    optimize_fast_cover: OptimizeParams,

    fn memoryLimit(m: Method) usize {
        return switch (m) {
            .default => |l| l,
            inline else => |p| p.memory_limit,
        };
    }
};

/// Any trainer over samples given one slice each: they are COPIED into one
/// contiguous buffer first (libzstd's trainers, and so these, take them
/// back to back, since segments run across sample boundaries), and that
/// copy counts against the method's `memory_limit`. Returns the finished
/// dictionary's size in `dict`.
pub fn trainFromSlices(gpa: Allocator, dict: []u8, slices: []const []const u8, method: Method) Error!usize {
    var lim: LimitedAllocator = .init(gpa, method.memoryLimit());
    const a = lim.allocator();
    return trainSlicesImpl(a, &lim, dict, slices, method) catch |e| lim.map(e);
}

fn trainSlicesImpl(a: Allocator, lim: *LimitedAllocator, dict: []u8, slices: []const []const u8, method: Method) Error!usize {
    var total: usize = 0;
    for (slices) |s| total +|= s.len;
    const sizes = try a.alloc(usize, slices.len);
    defer a.free(sizes);
    const buffer = try a.alloc(u8, total);
    defer a.free(buffer);
    var at: usize = 0;
    for (slices, sizes) |s, *n| {
        @memcpy(buffer[at..][0..s.len], s);
        at += s.len;
        n.* = s.len;
    }
    const samples: Samples = .{ .buffer = buffer, .sizes = sizes };
    switch (method) {
        .default => |limit| {
            var dp = default_train_params;
            dp.memory_limit = limit;
            var scorer: SelectScorer = .{ .gpa = a, .level = dp.level, .dict_id = 0 };
            return (try optimize(.fast_cover, a, lim, dict, samples, dp, &scorer)).size;
        },
        .cover => |p| {
            if (p.level > max_level) return error.LevelUnsupported;
            return trainCoverImpl(a, dict, samples, p);
        },
        .fast_cover => |p| {
            if (p.level > max_level) return error.LevelUnsupported;
            return trainFastCoverImpl(a, dict, samples, p);
        },
        inline .optimize_cover, .optimize_fast_cover => |p, tag| {
            if (p.level > max_level) return error.LevelUnsupported;
            var scorer: SelectScorer = .{ .gpa = a, .level = p.level, .dict_id = p.dict_id };
            return (try optimize(if (tag == .optimize_cover) .cover else .fast_cover, a, lim, dict, samples, p, &scorer)).size;
        },
    }
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
        _ = try coverContentInto(fa.allocator(), &dict, s, p);
        try testing.expectEqual(estimateCoverMemory(s.totalSize(), s.sizes.len, p), fa.allocated_bytes);
        try testing.expectEqual(fa.allocated_bytes, fa.freed_bytes);
    }
    for ([_]FastCoverParams{ .{ .k = 200, .d = 8 }, .{ .k = 50, .d = 6, .f = 9, .accel = 3 }, .{ .k = 50, .d = 6, .f = 0 } }) |p| {
        var fa: testing.FailingAllocator = .init(testing.allocator, .{});
        _ = try fastCoverContentInto(fa.allocator(), &dict, s, p);
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
    try testing.expectError(error.MemoryLimitExceeded, coverContentInto(fa.allocator(), &dict, s, low));
    low.memory_limit = @intCast(need);
    try testing.expectError(error.OutOfMemory, coverContentInto(fa.allocator(), &dict, s, low)); // it tried
    const fp: FastCoverParams = .{ .k = 200, .d = 8, .f = 31 };
    try testing.expectEqual((@as(u64, 1) << 31) * 6 + (s.sizes.len + 1) * 8, estimateFastCoverMemory(s.sizes.len, fp));
    try testing.expectError(error.MemoryLimitExceeded, fastCoverContentInto(fa.allocator(), &dict, s, fp));
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
    try testing.expectError(error.SrcSizeWrong, coverContentInto(gpa, &dict, short, .{ .k = 50, .d = 6 }));
    try testing.expectError(error.SrcSizeWrong, fastCoverContentInto(gpa, &dict, short, .{ .k = 50, .d = 6 }));
    // no samples
    const none: Samples = .{ .buffer = "", .sizes = &.{} };
    try testing.expectError(error.SrcSizeWrong, coverContentInto(gpa, &dict, none, .{ .k = 50, .d = 6 }));
    try testing.expectError(error.SrcSizeWrong, fastCoverContentInto(gpa, &dict, none, .{ .k = 50, .d = 6 }));
    // fewer than 5 samples, and fewer than 8 bytes
    try testing.expectError(error.SrcSizeWrong, coverContentInto(gpa, &dict, .{ .buffer = s.buffer, .sizes = s.sizes[0..4] }, .{ .k = 50, .d = 6 }));
    try testing.expectError(error.SrcSizeWrong, fastCoverContentInto(gpa, &dict, .{ .buffer = "abcdefg", .sizes = &.{ 1, 1, 1, 1, 3 } }, .{ .k = 50, .d = 6 }));
    // d above the samples' total
    try testing.expectError(error.SrcSizeWrong, coverContentInto(gpa, &dict, .{ .buffer = "abcdefghij", .sizes = &.{ 2, 2, 2, 2, 2 } }, .{ .k = 50, .d = 11 }));
    // parameter checks come first
    try testing.expectError(error.ParameterOutOfBound, coverContentInto(gpa, dict[0..10], none, .{ .k = 50, .d = 6 }));
    try testing.expectError(error.DstSizeTooSmall, coverContentInto(gpa, dict[0..100], s, .{ .k = 50, .d = 6 }));
    // a split point out of (0, 1] at the context level
    try testing.expectError(error.ParameterOutOfBound, CoverContext.init(gpa, s, 8, 0, default_memory_limit));
    try testing.expectError(error.ParameterOutOfBound, FastCoverContext.init(gpa, s, 8, 1.5, 20, accel_table[1], default_memory_limit));
    // a training share shorter than one d-mer (libzstd underflows)
    try testing.expectError(error.SrcSizeWrong, CoverContext.init(gpa, .{ .buffer = "abcdefghijklmnopqrstuvwxyz", .sizes = &.{ 1, 1, 1, 1, 1, 1, 20 } }, 8, 0.8, default_memory_limit));
}

test "samples of 2^32 - 1 bytes and up are refused, just below are not" {
    // Split.init reads only the sizes and the buffer's length, so a length
    // stands in for the bytes (never read: the checks come first).
    var byte: u8 = 0;
    const many: [*]const u8 = @ptrCast(&byte);
    const top: usize = std.math.maxInt(u32);
    const at: Samples = .{ .buffer = many[0..top], .sizes = &.{ top - 4, 1, 1, 1, 1 } };
    try testing.expectError(error.SrcSizeWrong, Split.init(at, 8, 1.0));
    const below: Samples = .{ .buffer = many[0..top], .sizes = &.{ top - 5, 1, 1, 1, 1 } };
    const sp = try Split.init(below, 8, 1.0);
    try testing.expectEqual(@as(u64, top - 1), sp.total_size);
}

test "parameter checks reject what the trainers resolve before them" {
    // f and accel of 0 are resolved to the defaults before the check, so
    // the check's own zero cases are reachable only directly.
    try testing.expect(checkFastCoverParameters(50, 8, 1.0, 1024, 20, 1));
    try testing.expect(!checkFastCoverParameters(50, 8, 1.0, 1024, 0, 1));
    try testing.expect(!checkFastCoverParameters(50, 8, 1.0, 1024, 20, 0));
    try testing.expect(!checkFastCoverParameters(50, 0, 1.0, 1024, 20, 1));
    try testing.expect(!checkCoverParameters(50, 0, 1.0, 1024));
    try testing.expect(checkCoverParameters(8, 8, 1.0, 1024));
}

test "coverContent / fastCoverContent return the content trainInto places at the tail" {
    const gpa = testing.allocator;
    const gen = try testSet("words-300");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var dict: [3000]u8 = undefined;
    @memset(&dict, 0xAA);
    const n = try coverContentInto(gpa, &dict, s, .{ .k = 100, .d = 6 });
    const c = try coverContent(gpa, s, dict.len, .{ .k = 100, .d = 6 });
    defer gpa.free(c);
    try testing.expectEqualSlices(u8, dict[dict.len - n ..], c);
    const zeros = try testSet("zeros-20");
    defer zeros.deinit(gpa);
    // a short content leaves the head of the buffer untouched
    @memset(&dict, 0xAA);
    const m = try fastCoverContentInto(gpa, &dict, .{ .buffer = zeros.buffer, .sizes = zeros.sizes }, .{ .k = 64, .d = 8 });
    try testing.expectEqual(@as(usize, 8), m);
    for (dict[0 .. dict.len - m]) |b| try testing.expectEqual(@as(u8, 0xAA), b);
    const fc = try fastCoverContent(gpa, .{ .buffer = zeros.buffer, .sizes = zeros.sizes }, dict.len, .{ .k = 64, .d = 8 });
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
    // a narrow k range: steps of 1, not less
    const n: OptimizeGrid = try .init(.cover, .{ .k = 0, .d = 8, .steps = 40 }, 100, 4096);
    try testing.expectEqual(@as(u32, 48), n.k_step_size);
    const narrow: OptimizeGrid = try .init(.cover, .{ .d = 8, .steps = 3000 }, 100, 4096);
    try testing.expectEqual(@as(u32, 1), narrow.k_step_size);
    try testing.expectEqual(@as(u32, 1951), narrow.iterations);
    // k = d is allowed (k_min < d_max is not)
    const kd: OptimizeGrid = try .init(.cover, .{ .k = 8, .d = 8 }, 100, 4096);
    try testing.expectEqual(@as(u32, 1), kd.iterations);
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
    finalize: usize = 0,

    fn select(m: *MockScorer, c: Candidate) !?Selection {
        m.finalize = c.nb_finalize_samples;
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
    const gen = try testSet("json-200");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var dict: [1500]u8 = undefined;
    inline for (.{ Trainer.cover, Trainer.fast_cover }) |trainer| {
        var m: MockScorer = .{ .fail_k = 50 + 3 * 48 };
        defer m.deinit();
        const p: OptimizeParams = .{};
        const r = if (trainer == .cover) try optimizeCoverWith(gpa, &dict, s, p, &m) else try optimizeFastCoverWith(gpa, &dict, s, p, &m);
        // k above the capacity (1500) is skipped: 50 + 48·j ≤ 1500 → 31 per d
        try testing.expectEqual(@as(usize, 62), m.seen.items.len);
        // accel 1 finalizes on all training samples: 200 · 0.75 (fastCover), 200
        try testing.expectEqual(@as(usize, if (trainer == .cover) 200 else 150), m.finalize);
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
            const n = try coverContentInto(gpa, &one, s, .{ .k = k, .d = 8 });
            try testing.expectEqualSlices(u8, one[one.len - n ..], m.contents.items[pick]);
        } else {
            var ctx: FastCoverContext = try .init(gpa, s, 8, 0.75, 20, accel_table[1], default_memory_limit);
            defer ctx.deinit(gpa);
            const seg = try gpa.alloc(u16, ctx.freqs.len);
            defer gpa.free(seg);
            @memset(seg, 0);
            const tail = ctx.buildDictionary(ctx.freqs, &one, k, 8, seg);
            try testing.expectEqualSlices(u8, one[tail..], m.contents.items[pick]);
            try testing.expectEqual(@as(usize, 150), ctx.nb_train_samples);
        }
    }
    // accel 4: a quarter of the training samples
    {
        var m4: MockScorer = .{};
        defer m4.deinit();
        _ = try optimizeFastCoverWith(gpa, &dict, s, .{ .k = 100, .d = 8, .accel = 4 }, &m4);
        try testing.expectEqual(@as(usize, 150 * 25 / 100), m4.finalize);
    }
    // no candidate succeeds
    var m: MockScorer = .{ .fail_k = 100 };
    defer m.deinit();
    try testing.expectError(error.NoCandidate, optimizeCoverWith(gpa, &dict, s, .{ .k = 100, .d = 8 }, &m));
}

/// A thread-safe scorer with many ties: a hash of the content, mod 5.
const TieScorer = struct {
    released: std.atomic.Value(usize) = .init(0),

    fn select(_: *TieScorer, c: Candidate) !?Selection {
        if (c.k == 50 + 3 * 48) return null;
        return .{ .dict = c.content, .total_compressed_size = std.hash.Wyhash.hash(0, c.content) % 5 };
    }
    fn release(m: *TieScorer, _: Selection) void {
        _ = m.released.fetchAdd(1, .monotonic);
    }
};

test "optimizer: every thread count keeps the single-threaded winner, ties included" {
    const gpa = testing.allocator;
    const gen = try testSet("json-200");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var one: [1500]u8 = undefined;
    var many: [1500]u8 = undefined;
    inline for (.{ Trainer.cover, Trainer.fast_cover }) |trainer| {
        const f = if (trainer == .cover) optimizeCoverWith else optimizeFastCoverWith;
        var m1: TieScorer = .{};
        const want = try f(gpa, &one, s, .{}, &m1);
        try testing.expectEqual(@as(usize, 60), m1.released.load(.monotonic));
        for ([_]u32{ 0, 2, 3, 4, 8, 64 }) |n| {
            var m: TieScorer = .{};
            const got = try f(gpa, &many, s, .{ .nb_threads = n }, &m);
            try testing.expectEqual(want, got);
            try testing.expectEqualSlices(u8, one[0..want.size], many[0..got.size]);
            try testing.expectEqual(@as(usize, 60), m.released.load(.monotonic));
        }
        // several candidates tie at the winning total
        var ties: usize = 0;
        var k: u32 = 50;
        while (k <= 1500) : (k += 48) {
            if (k == 50 + 3 * 48) continue;
            var buf: [1500]u8 = undefined;
            const n = if (trainer == .cover) try coverContentInto(gpa, &buf, .{ .buffer = s.buffer, .sizes = s.sizes }, .{ .k = k, .d = want.d }) else 0;
            if (trainer == .cover and std.hash.Wyhash.hash(0, buf[buf.len - n ..]) % 5 == std.hash.Wyhash.hash(0, one[0..want.size]) % 5) ties += 1;
        }
        if (trainer == .cover) try testing.expect(ties > 1);
    }
}

test "parallel optimizers: memory_limit bounds the sum; the result does not change" {
    const gpa = testing.allocator;
    const gen = try testSet("json-200");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var a: [4096]u8 = undefined;
    var b: [4096]u8 = undefined;
    inline for (.{ Trainer.cover, Trainer.fast_cover }) |trainer| {
        const f = if (trainer == .cover) optimizeCover else optimizeFastCover;
        var p: OptimizeParams = .{ .d = 8, .steps = 3, .f = 10, .split_point = 0.75, .level = 5 };
        const want = try f(gpa, &a, s, p);
        // no ceiling to speak of: four at once, more memory at once
        var lim1: LimitedAllocator = .init(gpa, std.math.maxInt(usize));
        _ = try f(lim1.allocator(), &b, s, p);
        var lim4: LimitedAllocator = .init(gpa, std.math.maxInt(usize));
        p.nb_threads = 4;
        try testing.expectEqual(want, try f(lim4.allocator(), &b, s, p));
        try testing.expectEqualSlices(u8, a[0..want.size], b[0..want.size]);
        try testing.expect(lim4.peak > lim1.peak);
        // the smallest ceiling one thread gets through with
        p.nb_threads = 1;
        var lo: usize = 0; // fails
        var hi: usize = lim1.peak; // succeeds
        while (hi - lo > 1) {
            p.memory_limit = lo + (hi - lo) / 2;
            if (f(gpa, &b, s, p)) |_| {
                hi = p.memory_limit;
            } else |e| {
                try testing.expectEqual(error.MemoryLimitExceeded, e);
                lo = p.memory_limit;
            }
        }
        // four threads under it: fewer at once, the same winner
        // (candidates refused under contention run again); one byte less
        // is refused, as for one thread
        p.nb_threads = 4;
        p.memory_limit = hi;
        optimize_retries.store(0, .monotonic);
        // (fastCover's content selection is small next to its scoring:
        // four fit the static count, and the scorers contend -- unless the
        // threads happen to run one after another, so a few attempts)
        for (0..5) |_| {
            var lim4l: LimitedAllocator = .init(gpa, std.math.maxInt(usize));
            try testing.expectEqual(want, try f(lim4l.allocator(), &b, s, p));
            try testing.expectEqualSlices(u8, a[0..want.size], b[0..want.size]);
            // (the slots and threads are not counted)
            try testing.expect(lim4l.peak <= hi + 4096);
            if (optimize_retries.load(.monotonic) > 0) break;
        }
        if (trainer == .fast_cover) try testing.expect(optimize_retries.load(.monotonic) > 0);
        p.memory_limit = lo;
        try testing.expectError(error.MemoryLimitExceeded, f(gpa, &b, s, p));
    }
}

/// A scorer that holds `hog` bytes of the ceiling per selection until it
/// is released, and records the order selections are released in: grid
/// order once compared, and any order when dropped for a rerun.
const HogScorer = struct {
    gpa: Allocator,
    hog: usize,
    released: std.ArrayList(u32) = .empty,

    fn select(h: *HogScorer, c: Candidate) !?Selection {
        const buf = try c.gpa.alloc(u8, h.hog);
        std.mem.writeInt(u32, buf[0..4], c.k, .little);
        // ties: every third k scores the same
        return .{ .dict = c.content, .total_compressed_size = (c.k / 48) % 3, .buffer = buf };
    }
    fn release(h: *HogScorer, sel: Selection) void {
        h.released.append(testing.allocator, std.mem.readInt(u32, sel.buffer[0..4], .little)) catch unreachable;
        h.gpa.free(sel.buffer);
    }
};

test "parallel optimizers: candidates refused under contention are rerun, compared once each, in order" {
    const gpa = testing.allocator;
    const gen = try testSet("json-200");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var one: [1500]u8 = undefined;
    var many: [1500]u8 = undefined;
    const hog = 1 << 20;
    const p: OptimizeParams = .{ .d = 8, .f = 10 };
    // one thread: its peak, and the order
    var lim1: LimitedAllocator = .init(gpa, std.math.maxInt(usize));
    var h1: HogScorer = .{ .gpa = lim1.allocator(), .hog = hog };
    defer h1.released.deinit(testing.allocator);
    const want = try optimize(.fast_cover, lim1.allocator(), &lim1, &one, s, p, &h1);
    try testing.expectEqual(@as(usize, 31), h1.released.items.len);
    // a ceiling that holds one hog only; the static count (from
    // `memory_limit`) still starts four at once
    optimize_retries.store(0, .monotonic);
    for (0..6) |_| {
        var lim: LimitedAllocator = .init(gpa, lim1.peak + hog / 2);
        var h: HogScorer = .{ .gpa = lim.allocator(), .hog = hog };
        defer h.released.deinit(testing.allocator);
        var p4 = p;
        p4.nb_threads = 4;
        const got = try optimize(.fast_cover, lim.allocator(), &lim, &many, s, p4, &h);
        try testing.expectEqual(want, got);
        try testing.expectEqualSlices(u8, one[0..want.size], many[0..got.size]);
        // each k's last release is its comparison: in grid order, each once
        var last: std.ArrayList(u32) = .empty;
        defer last.deinit(testing.allocator);
        for (h.released.items, 0..) |k, i| {
            if (std.mem.indexOfScalar(u32, h.released.items[i + 1 ..], k) == null) try last.append(testing.allocator, k);
        }
        try testing.expectEqualSlices(u32, h1.released.items, last.items);
        try testing.expectEqual(@as(usize, 0), lim.live);
    }
    try testing.expect(optimize_retries.load(.monotonic) > 0);
}

/// Counts the candidates scored on a thread other than the caller's.
const ThreadScorer = struct {
    caller: std.Thread.Id,
    elsewhere: std.atomic.Value(u32) = .init(0),

    fn select(t: *ThreadScorer, c: Candidate) !?Selection {
        if (std.Thread.getCurrentId() != t.caller) _ = t.elsewhere.fetchAdd(1, .monotonic);
        return .{ .dict = c.content, .total_compressed_size = c.k % 7 };
    }
    fn release(_: *ThreadScorer, _: Selection) void {}
};

test "parallel optimizers: one thread runs on the caller, no more slots than a d has candidates, as many at once as the ceiling holds" {
    const gpa = testing.allocator;
    const gen = try testSet("json-200");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var dict: [1500]u8 = undefined;
    for ([_]u32{ 0, 1 }) |n| {
        var t: ThreadScorer = .{ .caller = std.Thread.getCurrentId() };
        _ = try optimizeCoverWith(gpa, &dict, s, .{ .d = 8, .nb_threads = n }, &t);
        try testing.expectEqual(@as(u32, 0), t.elsewhere.load(.monotonic));
        try testing.expectEqual(@as(usize, 1), optimize_slots.load(.monotonic));
    }
    // libzstd's grid: k from 50 to 2000 in steps of (2000 - 50) / 40 = 48,
    // 41 per d (the checks skip some later; the slots are counted before)
    var t: ThreadScorer = .{ .caller = std.Thread.getCurrentId() };
    _ = try optimizeCoverWith(gpa, &dict, s, .{ .d = 8, .nb_threads = 64 }, &t);
    try testing.expectEqual(@as(usize, 41), optimize_slots.load(.monotonic));
    try testing.expect(t.elsewhere.load(.monotonic) > 0);
    inline for (.{ Trainer.cover, Trainer.fast_cover }) |trainer| {
        const f = if (trainer == .cover) optimizeCover else optimizeFastCover;
        // a small grid (5 k per d) is enough for four slots
        var p: OptimizeParams = .{ .d = 8, .f = 10, .steps = 4, .nb_threads = 4 };
        // no ceiling to speak of: all four at once
        var lim: LimitedAllocator = .init(gpa, std.math.maxInt(usize));
        _ = try f(lim.allocator(), &dict, s, p);
        try testing.expectEqual(@as(usize, 4), optimize_static_par.load(.monotonic));
        // the lowest ceiling the up-front check lets through holds one
        // candidate: one at a time (the count is set before the first runs)
        var lo: usize = 0; // refused up front
        var hi: usize = lim.peak; // let through
        while (hi - lo > 1) {
            p.memory_limit = lo + (hi - lo) / 2;
            optimize_static_par.store(0, .monotonic);
            _ = f(gpa, &dict, s, p) catch {};
            if (optimize_static_par.load(.monotonic) != 0) hi = p.memory_limit else lo = p.memory_limit;
        }
        p.memory_limit = hi;
        optimize_static_par.store(0, .monotonic);
        _ = f(gpa, &dict, s, p) catch {};
        try testing.expectEqual(@as(usize, 1), optimize_static_par.load(.monotonic));
    }
}

/// Makes the ceiling refuse at a chosen grid position whatever the
/// scheduling: in the first round, positions below `hold` each take `hog`
/// bytes of it and wait until the other `4 - hold` have tried the same (and
/// been refused); the last refusal disarms it. Once disarmed nothing hogs,
/// and position `fail_at` fails with an OutOfMemory of its own -- not the
/// ceiling's. Scores tie in threes; selections are released in the order
/// recorded (on the main thread).
const GateScorer = struct {
    gpa: Allocator,
    hog: usize,
    hold: u32,
    fail_at: ?u32 = null,
    armed: std.atomic.Value(bool) = .init(true),
    held: std.atomic.Value(u32) = .init(0),
    refusals: std.atomic.Value(u32) = .init(0),
    leaked_through: std.atomic.Value(bool) = .init(false),
    released: std.ArrayList(u32) = .empty,

    fn waitFor(v: *std.atomic.Value(u32), n: u32) void {
        // bounded: a gate that cannot close fails the test instead of hanging it
        var spins: usize = 0;
        while (v.load(.acquire) < n and spins < 50_000_000) : (spins += 1) std.Thread.yield() catch {};
    }

    fn select(g: *GateScorer, c: Candidate) !?Selection {
        const i = (c.k - 50) / 48;
        const score = (c.k / 48) % 3;
        if (g.armed.load(.acquire)) {
            if (i < g.hold) {
                const buf = try c.gpa.alloc(u8, g.hog);
                std.mem.writeInt(u32, buf[0..4], c.k, .little);
                _ = g.held.fetchAdd(1, .acq_rel);
                waitFor(&g.refusals, 4 - g.hold);
                return .{ .dict = c.content, .total_compressed_size = score, .buffer = buf };
            }
            waitFor(&g.held, g.hold);
            if (c.gpa.alloc(u8, g.hog)) |buf| {
                g.leaked_through.store(true, .monotonic);
                std.mem.writeInt(u32, buf[0..4], c.k, .little);
                return .{ .dict = c.content, .total_compressed_size = score, .buffer = buf };
            } else |e| {
                if (g.refusals.fetchAdd(1, .acq_rel) + 1 == 4 - g.hold) g.armed.store(false, .release);
                return e;
            }
        }
        if (g.fail_at == i) return error.OutOfMemory;
        const buf = try c.gpa.alloc(u8, 4);
        std.mem.writeInt(u32, buf[0..4], c.k, .little);
        return .{ .dict = c.content, .total_compressed_size = score, .buffer = buf };
    }
    fn release(g: *GateScorer, sel: Selection) void {
        g.released.append(testing.allocator, std.mem.readInt(u32, sel.buffer[0..4], .little)) catch unreachable;
        g.gpa.free(sel.buffer);
    }
};

test "parallel optimizers: a refusal at any position is rerun from it, in grid order; a failure of its own is final" {
    const gpa = testing.allocator;
    const gen = try testSet("json-200");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var one: [1500]u8 = undefined;
    var many: [1500]u8 = undefined;
    const hog = 1 << 20;
    const p: OptimizeParams = .{ .d = 8, .f = 10 };
    var lim1: LimitedAllocator = .init(gpa, std.math.maxInt(usize));
    var g1: GateScorer = .{ .gpa = lim1.allocator(), .hog = hog, .hold = 0, .armed = .init(false) };
    defer g1.released.deinit(testing.allocator);
    const want = try optimize(.fast_cover, lim1.allocator(), &lim1, &one, s, p, &g1);
    var p4 = p;
    p4.nb_threads = 4;
    // refused at position 1, 2 and 3: the rerun starts from there, with
    // the head of the ring anywhere
    for ([_]u32{ 1, 2, 3 }) |hold| {
        var lim: LimitedAllocator = .init(gpa, lim1.peak + hold * hog + hog / 2);
        var g: GateScorer = .{ .gpa = lim.allocator(), .hog = hog, .hold = hold };
        defer g.released.deinit(testing.allocator);
        optimize_retries.store(0, .monotonic);
        const got = try optimize(.fast_cover, lim.allocator(), &lim, &many, s, p4, &g);
        try testing.expect(!g.leaked_through.load(.monotonic));
        try testing.expectEqual(@as(u32, 4 - hold), g.refusals.load(.monotonic));
        try testing.expectEqual(@as(u32, 1), optimize_retries.load(.monotonic));
        try testing.expectEqual(want, got);
        try testing.expectEqualSlices(u8, one[0..want.size], many[0..got.size]);
        // each k's last release is its comparison: in grid order, each once
        var last: std.ArrayList(u32) = .empty;
        defer last.deinit(testing.allocator);
        for (g.released.items, 0..) |k, i| {
            if (std.mem.indexOfScalar(u32, g.released.items[i + 1 ..], k) == null) try last.append(testing.allocator, k);
        }
        try testing.expectEqualSlices(u32, g1.released.items, last.items);
        try testing.expectEqual(@as(usize, 0), lim.live);
    }
    // after the rerun (two at once), position 2 runs on a slot refused in
    // the first round; its own OutOfMemory is final, not another rerun --
    // with two at once, as it would be alone
    {
        var lim: LimitedAllocator = .init(gpa, lim1.peak + hog + hog / 2);
        var g: GateScorer = .{ .gpa = lim.allocator(), .hog = hog, .hold = 1, .fail_at = 2 };
        defer g.released.deinit(testing.allocator);
        optimize_retries.store(0, .monotonic);
        try testing.expectError(error.OutOfMemory, optimize(.fast_cover, lim.allocator(), &lim, &many, s, p4, &g));
        try testing.expectEqual(@as(u32, 1), optimize_retries.load(.monotonic));
        try testing.expectEqual(@as(usize, 0), lim.live);
    }
}

test "LimitedAllocator: refuses past the limit, counts what is live" {
    var lim: LimitedAllocator = .init(testing.allocator, 1000);
    const a = lim.allocator();
    const x = try a.alloc(u8, 600);
    try testing.expectError(error.OutOfMemory, a.alloc(u8, 401));
    try testing.expect(lim.refused);
    const y = try a.alloc(u8, 400);
    try testing.expectEqual(@as(usize, 1000), lim.live);
    a.free(x);
    const z = try a.realloc(y, 550); // (moved, or grown in place)
    try testing.expectEqual(@as(usize, 550), lim.live);
    a.free(z);
    try testing.expectEqual(@as(usize, 0), lim.live);
    try testing.expectEqual(@as(usize, 1000), lim.peak);
    try testing.expectEqual(error.MemoryLimitExceeded, lim.map(@as(Error, error.OutOfMemory)));
}

test "LimitedAllocator: a failure of the allocator below gives its bytes back, and is not a refusal" {
    var failing: std.testing.FailingAllocator = .init(testing.allocator, .{ .fail_index = 0 });
    var lim: LimitedAllocator = .init(failing.allocator(), 1000);
    try testing.expectError(error.OutOfMemory, lim.allocator().alloc(u8, 600));
    try testing.expectEqual(@as(usize, 0), lim.live);
    try testing.expect(!lim.refused);
    try testing.expectEqual(error.OutOfMemory, lim.map(@as(Error, error.OutOfMemory)));
}

test "LimitedAllocator: shrunk in place, the difference is live no more" {
    var buf: [1000]u8 = undefined;
    var fba: std.heap.FixedBufferAllocator = .init(&buf);
    var lim: LimitedAllocator = .init(fba.allocator(), 1000);
    const a = lim.allocator();
    const x = try a.alloc(u8, 600);
    try testing.expect(a.resize(x, 200));
    try testing.expectEqual(@as(usize, 200), lim.live);
    // the 400 given back are there to take again
    const y = try a.alloc(u8, 800);
    try testing.expectEqual(@as(usize, 1000), lim.live);
    a.free(y);
    const shrunk: []u8 = x[0..200];
    a.free(shrunk);
    try testing.expectEqual(@as(usize, 0), lim.live);
}

test "the complete trainers hold their working memory under memory_limit" {
    const gpa = testing.allocator;
    const gen = try testSet("json-2000");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var dict: [4096]u8 = undefined;
    try testing.expectError(error.MemoryLimitExceeded, trainFastCover(gpa, &dict, s, .{ .k = 200, .f = 10, .level = 19, .memory_limit = 64 << 10 }));
    try testing.expectError(error.MemoryLimitExceeded, optimizeFastCover(gpa, &dict, s, .{ .d = 8, .steps = 1, .f = 10, .memory_limit = 64 << 10 }));
    // the peak is what it takes: a ceiling at it succeeds, one below fails
    {
        var lim: LimitedAllocator = .init(gpa, std.math.maxInt(usize));
        const want = try trainFastCover(lim.allocator(), &dict, s, .{ .k = 200, .f = 12 });
        const peak = lim.peak;
        try testing.expectEqual(want, try trainFastCover(gpa, &dict, s, .{ .k = 200, .f = 12, .memory_limit = peak }));
        try testing.expectError(error.MemoryLimitExceeded, trainFastCover(gpa, &dict, s, .{ .k = 200, .f = 12, .memory_limit = peak - 1 }));
    }
    {
        // cover's peak is its content selection (8 bytes per sample byte),
        // finalization's compressor at level 19 comes after it
        var lim: LimitedAllocator = .init(gpa, std.math.maxInt(usize));
        const want = try trainCover(lim.allocator(), &dict, s, .{ .k = 200, .level = 19 });
        const peak = lim.peak;
        try testing.expect(peak >= estimateCoverMemory(s.totalSize(), s.sizes.len, .{ .k = 200 }));
        try testing.expectEqual(want, try trainCover(gpa, &dict, s, .{ .k = 200, .level = 19, .memory_limit = peak }));
        try testing.expectError(error.MemoryLimitExceeded, trainCover(gpa, &dict, s, .{ .k = 200, .level = 19, .memory_limit = peak - 1 }));
    }
    // levels above 22 are refused, not clamped
    try testing.expectError(error.LevelUnsupported, trainCover(gpa, &dict, s, .{ .k = 200, .level = 23 }));
    try testing.expectError(error.LevelUnsupported, optimizeCover(gpa, &dict, s, .{ .level = 23 }));
    try testing.expectError(error.LevelUnsupported, finalizeDictionary(gpa, &dict, s.buffer[0..1000], s, .{ .level = 23 }));
}

test "trainFromSlices copies the samples and trains as the contiguous trainers do" {
    const gpa = testing.allocator;
    const gen = try testSet("words-300");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    const slices = try gpa.alloc([]const u8, s.sizes.len);
    defer gpa.free(slices);
    var at: usize = 0;
    for (slices, s.sizes) |*sl, n| {
        sl.* = s.buffer[at..][0..n];
        at += n;
    }
    var want: [4096]u8 = undefined;
    var got: [4096]u8 = undefined;
    const methods = [_]Method{
        .{ .cover = .{ .k = 100, .level = 5 } },
        .{ .fast_cover = .{ .k = 100, .d = 6, .accel = 2 } },
        .{ .optimize_cover = .{ .k = 200, .d = 8 } },
        .{ .optimize_fast_cover = .{ .d = 8, .steps = 2, .dict_id = 77 } },
        .{ .default = default_memory_limit },
    };
    for (methods) |m| {
        const n = switch (m) {
            .cover => |p| try trainCover(gpa, &want, s, p),
            .fast_cover => |p| try trainFastCover(gpa, &want, s, p),
            .optimize_cover => |p| (try optimizeCover(gpa, &want, s, p)).size,
            .optimize_fast_cover => |p| (try optimizeFastCover(gpa, &want, s, p)).size,
            .default => try train(gpa, &want, s),
        };
        const k = try trainFromSlices(gpa, &got, slices, m);
        try testing.expectEqualSlices(u8, want[0..n], got[0..k]);
    }
    // `.default` is `train`: on a set where its grid's k matters
    {
        const j = try testSet("json-2000");
        defer j.deinit(gpa);
        const js: Samples = .{ .buffer = j.buffer, .sizes = j.sizes };
        const jslices = try gpa.alloc([]const u8, js.sizes.len);
        defer gpa.free(jslices);
        var jat: usize = 0;
        for (jslices, js.sizes) |*sl, n| {
            sl.* = js.buffer[jat..][0..n];
            jat += n;
        }
        const n = try train(gpa, &want, js);
        try testing.expectEqualSlices(u8, want[0..n], got[0..try trainFromSlices(gpa, &got, jslices, .{ .default = default_memory_limit })]);
    }
    // the copy counts: a ceiling of the samples' size refuses
    try testing.expectError(error.MemoryLimitExceeded, trainFromSlices(gpa, &got, slices, .{ .cover = .{ .k = 100, .memory_limit = s.buffer.len } }));
    try testing.expectEqual(@as(u32, 77), getDictId(got[0..try trainFromSlices(gpa, &got, slices, methods[3])]));
}

test "a finished dictionary compresses its samples, and decodes them back" {
    const gpa = testing.allocator;
    const gen = try testSet("json-2000");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var dict: [8192]u8 = undefined;
    const n = try train(gpa, &dict, s);
    const d = dict[0..n];
    try testing.expect(getDictId(d) >= 32768);
    const hdr = try getDictHeaderSize(d);
    try testing.expect(hdr > 8 and hdr < 256);
    var cd = try cdict_mod.CDict.init(gpa, d, 3);
    defer cd.deinit();
    var comp: frame.Compressor = .initEmpty(gpa);
    defer comp.deinit();
    const dec = @import("decompress.zig");
    var dd = try @import("ddict.zig").DDict.init(gpa, d, .auto);
    defer dd.deinit(gpa);
    var dctx = try dec.Decompressor.init(gpa, .{ .ddict = &dd });
    defer dctx.deinit();
    var dst: [2048]u8 = undefined;
    var back: [1024]u8 = undefined;
    var with: usize = 0;
    var at: usize = 0;
    for (s.sizes[0..200]) |len| {
        const src = s.buffer[at..][0..len];
        at += len;
        const c = try comp.compressUsingCDict(&dst, src, &cd, .{});
        with += c;
        const m = try dctx.decompress(&back, dst[0..c]);
        try testing.expectEqualSlices(u8, src, back[0..m]);
    }
    // and it pays: the same samples without it take far more
    var without: usize = 0;
    at = 0;
    for (s.sizes[0..200]) |len| {
        without += try frame.compress(gpa, &dst, s.buffer[at..][0..len], .{ .level = 3, .checksum = false });
        at += len;
    }
    try testing.expect(with * 2 < without);
}

test "content of 2 GiB - 128 KiB and up cannot be finalized (offset codes above 30)" {
    // addEntropyTablesFromBuffer checks before reading the content, so a
    // length stands in for the bytes
    var byte: u8 = 0;
    const many: [*]u8 = @ptrCast(&byte);
    const top: usize = (1 << 31) - (128 << 10);
    const s: Samples = .{ .buffer = "", .sizes = &.{} };
    try testing.expectError(error.DictionaryCreationFailed, addEntropyTablesFromBuffer(testing.allocator, many[0..top], top, s, .{}));
    try testing.expectError(error.DictionaryCreationFailed, addEntropyTablesFromBuffer(testing.allocator, many[0 .. top + 9], top + 9, s, .{}));
}

test "addEntropyTablesFromBuffer: the caller's ID, and a buffer too small for the header" {
    const gpa = testing.allocator;
    const gen = try testSet("json-200");
    defer gen.deinit(gpa);
    const s: Samples = .{ .buffer = gen.buffer, .sizes = gen.sizes };
    var dict: [2048]u8 = undefined;
    @memcpy(dict[dict.len - 1000 ..], s.buffer[0..1000]);
    const n = try addEntropyTablesFromBuffer(gpa, &dict, 1000, s, .{ .dict_id = 7 });
    try testing.expectEqual(@as(u32, 7), getDictId(dict[0..n]));
    var tiny: [7]u8 = undefined;
    try testing.expectError(error.DstSizeTooSmall, addEntropyTablesFromBuffer(gpa, &tiny, 0, s, .{}));
    try testing.expectError(error.DstSizeTooSmall, addEntropyTablesFromBuffer(gpa, dict[0..100], 101, s, .{}));
}
