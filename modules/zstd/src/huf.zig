// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Huffman literal encoder (port of libzstd lib/compress/huf_compress.c, v1.5.7).
//!
//! `readCTable` is `HUF_readCTable`, for a dictionary's table. The
//! "optimal depth" table-log search libzstd enables from `btultra` up is
//! `optimalTableLog`. The
//! symbol sort keeps libzstd's bucket sort *and* its unstable quicksort, because
//! the order of equal counts decides which symbol gets which code, and so
//! reaches the output bytes.

const std = @import("std");
const bitstream = @import("bitstream.zig");
const fse = @import("fse.zig");
const hist = @import("hist.zig");

pub const Error = error{ DstSizeTooSmall, Generic };

pub const table_log_max = 12;
pub const table_log_default = 11;
pub const symbol_value_max = 255;
pub const block_size_max = 128 * 1024;

/// `HUF_repeat`: whether the previous table may be reused -- `check`
/// after validating it against the literals, `valid` without (a
/// dictionary's table giving every byte a code).
pub const Repeat = enum { none, check, valid };

pub const CElt = struct {
    nb_bits: u8 = 0,
    value: u16 = 0,
};

pub const CTable = struct {
    table_log: u32 = 0,
    max_symbol: u32 = 0,
    elt: [symbol_value_max + 1]CElt = [_]CElt{.{}} ** (symbol_value_max + 1),
};

pub const Flags = struct {
    prefer_repeat: bool = false,
    suspect_uncompressible: bool = false,
    /// `HUF_flags_optimalDepth`: search the table log by trial encoding.
    optimal_depth: bool = false,
};

// ── tree construction ───────────────────────────────────────────────────────

const Node = struct {
    count: u32 = 0,
    parent: u16 = 0,
    byte: u8 = 0,
    nb_bits: u8 = 0,
};

const start_node = symbol_value_max + 1;
/// `huffNodeTable`, plus the sentinel slot libzstd keeps at `huffNode[-1]`.
const node_table_len = 2 * (symbol_value_max + 1);

const rank_position_table_size = 192;
const rank_position_max_count_log = 32;
const rank_position_log_buckets_begin = (rank_position_table_size - 1) - rank_position_max_count_log - 1;
const rank_position_distinct_count_cutoff = rank_position_log_buckets_begin + 7; // + highbit32(158)

const RankPos = struct { base: u16 = 0, curr: u16 = 0 };

fn getIndex(c: u32) u32 {
    return if (c < rank_position_distinct_count_cutoff) c else fse.highbit32(c) + rank_position_log_buckets_begin;
}

fn insertionSort(nodes: []Node, low: i32, high: i32) void {
    const size = high - low + 1;
    const arr = nodes[@intCast(low)..];
    var i: i32 = 1;
    while (i < size) : (i += 1) {
        const key = arr[@intCast(i)];
        var j = i - 1;
        while (j >= 0 and arr[@intCast(j)].count < key.count) {
            arr[@intCast(j + 1)] = arr[@intCast(j)];
            j -= 1;
        }
        arr[@intCast(j + 1)] = key;
    }
}

fn quickSortPartition(arr: []Node, low: i32, high: i32) i32 {
    const pivot = arr[@intCast(high)].count;
    var i = low - 1;
    var j = low;
    while (j < high) : (j += 1) {
        if (arr[@intCast(j)].count > pivot) {
            i += 1;
            std.mem.swap(Node, &arr[@intCast(i)], &arr[@intCast(j)]);
        }
    }
    std.mem.swap(Node, &arr[@intCast(i + 1)], &arr[@intCast(high)]);
    return i + 1;
}

fn simpleQuickSort(arr: []Node, low_in: i32, high_in: i32) void {
    const insertion_sort_threshold = 8;
    var low = low_in;
    var high = high_in;
    if (high - low < insertion_sort_threshold) {
        insertionSort(arr, low, high);
        return;
    }
    while (low < high) {
        const idx = quickSortPartition(arr, low, high);
        if (idx - low < high - idx) {
            simpleQuickSort(arr, low, idx - 1);
            low = idx + 1;
        } else {
            simpleQuickSort(arr, idx + 1, high);
            high = idx - 1;
        }
    }
}

/// `HUF_sort`: descending by count; exact counts below the cutoff are bucketed
/// stably (by symbol), larger counts share log buckets and are quicksorted.
fn sort(huff_node: []Node, counts: []const u32, max_symbol: u32) void {
    var rank_position = [_]RankPos{.{}} ** rank_position_table_size;
    const max_sv1 = max_symbol + 1;
    var n: u32 = 0;
    while (n < max_sv1) : (n += 1) {
        rank_position[getIndex(counts[n])].base += 1;
    }
    n = rank_position_table_size - 1;
    while (n > 0) : (n -= 1) {
        rank_position[n - 1].base += rank_position[n].base;
        rank_position[n - 1].curr = rank_position[n - 1].base;
    }
    n = 0;
    while (n < max_sv1) : (n += 1) {
        const c = counts[n];
        const r = getIndex(c) + 1;
        const pos = rank_position[r].curr;
        rank_position[r].curr += 1;
        huff_node[pos].count = c;
        huff_node[pos].byte = @intCast(n);
    }
    n = rank_position_distinct_count_cutoff;
    while (n < rank_position_table_size - 1) : (n += 1) {
        const bucket_size: i32 = @as(i32, rank_position[n].curr) - @as(i32, rank_position[n].base);
        const bucket_start = rank_position[n].base;
        if (bucket_size > 1) simpleQuickSort(huff_node[bucket_start..], 0, bucket_size - 1);
    }
}

/// `HUF_buildTree`. `node0[0]` is the sentinel, `node0[1..]` is `huffNode`.
fn buildTree(node0: []Node, max_symbol: u32) i32 {
    const hn = node0[1..];
    var non_null_rank: i32 = @intCast(max_symbol);
    while (hn[@intCast(non_null_rank)].count == 0) non_null_rank -= 1;
    var low_s: i32 = non_null_rank;
    var node_nb: i32 = start_node;
    const node_root: i32 = node_nb + low_s - 1;
    var low_n: i32 = node_nb;
    hn[@intCast(node_nb)].count = hn[@intCast(low_s)].count + hn[@intCast(low_s - 1)].count;
    hn[@intCast(low_s)].parent = @intCast(node_nb);
    hn[@intCast(low_s - 1)].parent = @intCast(node_nb);
    node_nb += 1;
    low_s -= 2;
    var n = node_nb;
    while (n <= node_root) : (n += 1) hn[@intCast(n)].count = 1 << 30;
    node0[0].count = 1 << 31; // fake entry, strong barrier

    // create parents
    while (node_nb <= node_root) {
        const n1 = if (count(node0, low_s) < count(node0, low_n)) blk: {
            low_s -= 1;
            break :blk low_s + 1;
        } else blk: {
            low_n += 1;
            break :blk low_n - 1;
        };
        const n2 = if (count(node0, low_s) < count(node0, low_n)) blk: {
            low_s -= 1;
            break :blk low_s + 1;
        } else blk: {
            low_n += 1;
            break :blk low_n - 1;
        };
        hn[@intCast(node_nb)].count = hn[@intCast(n1)].count + hn[@intCast(n2)].count;
        hn[@intCast(n1)].parent = @intCast(node_nb);
        hn[@intCast(n2)].parent = @intCast(node_nb);
        node_nb += 1;
    }

    // distribute weights (unlimited tree height)
    hn[@intCast(node_root)].nb_bits = 0;
    n = node_root - 1;
    while (n >= start_node) : (n -= 1) hn[@intCast(n)].nb_bits = hn[hn[@intCast(n)].parent].nb_bits + 1;
    n = 0;
    while (n <= non_null_rank) : (n += 1) hn[@intCast(n)].nb_bits = hn[hn[@intCast(n)].parent].nb_bits + 1;
    return non_null_rank;
}

/// `huffNode[i].count` with libzstd's `huffNode[-1]` sentinel reachable at i == -1.
inline fn count(node0: []const Node, i: i32) u32 {
    return node0[@intCast(i + 1)].count;
}

/// `HUF_setMaxHeight`: cap the tree at `target_nb_bits`, repaying the Kraft debt.
fn setMaxHeight(hn: []Node, last_non_null: u32, target_nb_bits: u32) u32 {
    const largest_bits: u32 = hn[last_non_null].nb_bits;
    if (largest_bits <= target_nb_bits) return largest_bits;

    var total_cost: i32 = 0;
    const base_cost: i32 = @as(i32, 1) << @intCast(largest_bits - target_nb_bits);
    var n: i32 = @intCast(last_non_null);

    while (hn[@intCast(n)].nb_bits > target_nb_bits) {
        total_cost += base_cost - (@as(i32, 1) << @intCast(largest_bits - hn[@intCast(n)].nb_bits));
        hn[@intCast(n)].nb_bits = @intCast(target_nb_bits);
        n -= 1;
    }
    while (hn[@intCast(n)].nb_bits == target_nb_bits) n -= 1;

    total_cost >>= @intCast(largest_bits - target_nb_bits);

    const no_symbol: u32 = 0xF0F0F0F0;
    var rank_last = [_]u32{no_symbol} ** (table_log_max + 2);
    {
        var current_nb_bits = target_nb_bits;
        var pos = n;
        while (pos >= 0) : (pos -= 1) {
            if (hn[@intCast(pos)].nb_bits >= current_nb_bits) continue;
            current_nb_bits = hn[@intCast(pos)].nb_bits;
            rank_last[target_nb_bits - current_nb_bits] = @intCast(pos);
        }
    }

    while (total_cost > 0) {
        var nb_bits_to_decrease: u32 = fse.highbit32(@intCast(total_cost)) + 1;
        while (nb_bits_to_decrease > 1) : (nb_bits_to_decrease -= 1) {
            const high_pos = rank_last[nb_bits_to_decrease];
            const low_pos = rank_last[nb_bits_to_decrease - 1];
            if (high_pos == no_symbol) continue;
            if (low_pos == no_symbol) break;
            const high_total = hn[high_pos].count;
            const low_total = 2 * hn[low_pos].count;
            if (high_total <= low_total) break;
        }
        while (nb_bits_to_decrease <= table_log_max and rank_last[nb_bits_to_decrease] == no_symbol)
            nb_bits_to_decrease += 1;
        total_cost -= @as(i32, 1) << @intCast(nb_bits_to_decrease - 1);
        hn[rank_last[nb_bits_to_decrease]].nb_bits += 1;
        if (rank_last[nb_bits_to_decrease - 1] == no_symbol)
            rank_last[nb_bits_to_decrease - 1] = rank_last[nb_bits_to_decrease];
        if (rank_last[nb_bits_to_decrease] == 0) {
            rank_last[nb_bits_to_decrease] = no_symbol;
        } else {
            rank_last[nb_bits_to_decrease] -= 1;
            if (hn[rank_last[nb_bits_to_decrease]].nb_bits != target_nb_bits - nb_bits_to_decrease)
                rank_last[nb_bits_to_decrease] = no_symbol;
        }
    }

    while (total_cost < 0) {
        if (rank_last[1] == no_symbol) {
            while (hn[@intCast(n)].nb_bits == target_nb_bits) n -= 1;
            hn[@intCast(n + 1)].nb_bits -= 1;
            rank_last[1] = @intCast(n + 1);
            total_cost += 1;
            continue;
        }
        hn[rank_last[1] + 1].nb_bits -= 1;
        rank_last[1] += 1;
        total_cost += 1;
    }
    return target_nb_bits;
}

fn buildCTableFromTree(ct: *CTable, hn: []const Node, non_null_rank: i32, max_symbol: u32, max_nb_bits: u32) void {
    var nb_per_rank = [_]u16{0} ** (table_log_max + 1);
    var val_per_rank = [_]u16{0} ** (table_log_max + 1);
    const alphabet_size = max_symbol + 1;
    var n: i32 = 0;
    while (n <= non_null_rank) : (n += 1) nb_per_rank[hn[@intCast(n)].nb_bits] += 1;
    {
        var min: u16 = 0;
        var r: u32 = max_nb_bits;
        while (r > 0) : (r -= 1) {
            val_per_rank[r] = min;
            min += nb_per_rank[r];
            min >>= 1;
        }
    }
    var s: u32 = 0;
    while (s < alphabet_size) : (s += 1) ct.elt[hn[s].byte] = .{ .nb_bits = hn[s].nb_bits };
    s = 0;
    while (s < alphabet_size) : (s += 1) {
        const nb = ct.elt[s].nb_bits;
        if (nb > 0) ct.elt[s].value = val_per_rank[nb];
        val_per_rank[nb] +%= 1;
    }
    // Entries above the alphabet are never read (every reader stops at
    // `max_symbol`); clear them rather than carry stale codes.
    while (s <= symbol_value_max) : (s += 1) ct.elt[s] = .{};
    ct.table_log = max_nb_bits;
    ct.max_symbol = max_symbol;
}

/// `HUF_buildCTable_wksp`. Returns the table log actually used.
pub fn buildCTable(ct: *CTable, counts: []const u32, max_symbol: u32, max_nb_bits_in: u32) Error!u32 {
    var max_nb_bits = max_nb_bits_in;
    if (max_nb_bits == 0) max_nb_bits = table_log_default;
    if (max_symbol > symbol_value_max) return error.Generic;
    var node0 = [_]Node{.{}} ** node_table_len;
    const hn = node0[1..];
    sort(hn, counts, max_symbol);
    const non_null_rank = buildTree(&node0, max_symbol);
    max_nb_bits = setMaxHeight(hn, @intCast(non_null_rank), max_nb_bits);
    if (max_nb_bits > table_log_max) return error.Generic;
    buildCTableFromTree(ct, hn, non_null_rank, max_symbol, max_nb_bits);
    return max_nb_bits;
}

pub fn estimateCompressedSize(ct: *const CTable, counts: []const u32, max_symbol: u32) usize {
    var nb_bits: usize = 0;
    var s: u32 = 0;
    while (s <= max_symbol) : (s += 1) nb_bits += @as(usize, ct.elt[s].nb_bits) * counts[s];
    return nb_bits >> 3;
}

pub fn validateCTable(ct: *const CTable, counts: []const u32, max_symbol: u32) bool {
    if (ct.max_symbol < max_symbol) return false;
    var s: u32 = 0;
    while (s <= max_symbol) : (s += 1) {
        if (counts[s] != 0 and ct.elt[s].nb_bits == 0) return false;
    }
    return true;
}

/// `HUF_optimalTableLog`. Without `optimal_depth` the cheap FSE-based guess;
/// with it, every log from the smallest that fits the alphabet up is tried
/// and the one with the smallest table + payload estimate wins.
pub fn optimalTableLog(max_table_log: u32, src_len: usize, max_symbol: u32, counts: []const u32, optimal_depth: bool) u32 {
    if (!optimal_depth) return fse.optimalTableLogInternal(max_table_log, src_len, max_symbol, 1);
    var cardinality: u32 = 0;
    for (counts[0 .. max_symbol + 1]) |c| cardinality += @intFromBool(c != 0);
    const min_table_log = fse.highbit32(cardinality) + 1; // HUF_minTableLog
    var opt_size: usize = std.math.maxInt(usize) - 1;
    var opt_log = max_table_log;
    var guess = min_table_log;
    // Search until size increases
    while (guess <= max_table_log) : (guess += 1) {
        var ct: CTable = .{};
        const max_bits = buildCTable(&ct, counts, max_symbol, guess) catch continue;
        if (max_bits < guess and guess > min_table_log) break;
        var header: [1024]u8 = undefined;
        const h_size = writeCTable(&header, &ct, max_symbol, max_bits) catch continue;
        const new_size = estimateCompressedSize(&ct, counts, max_symbol) + h_size;
        if (new_size > opt_size + 1) break;
        if (new_size < opt_size) {
            opt_size = new_size;
            opt_log = guess;
        }
    }
    return opt_log;
}

/// `HUF_readCTable`: the table a header written by `writeCTable` (a
/// dictionary's) describes, into `ct`. Returns the header's size, and
/// whether some symbol up to the last has no code (`hasZeroWeights`).
pub fn readCTable(ct: *CTable, src: []const u8, has_zero_weights: *bool) Error!usize {
    const huf_dec = @import("huf_dec.zig");
    var huff_weight: [symbol_value_max + 1]u8 = undefined;
    var rank_val: [huf_dec.tablelog_max + 1]u32 = undefined;
    var table_log: u32 = 0;
    var nb_symbols: u32 = 0;
    // get symbol weights
    const read_size = huf_dec.readStats(&huff_weight, &rank_val, &nb_symbols, &table_log, src) catch return error.Generic;
    has_zero_weights.* = rank_val[0] > 0;
    // check result
    if (table_log > table_log_max) return error.Generic;
    if (nb_symbols > symbol_value_max + 1) return error.Generic;
    ct.table_log = table_log;
    ct.max_symbol = nb_symbols - 1;
    // fill nbBits
    for (huff_weight[0..nb_symbols], ct.elt[0..nb_symbols]) |w, *e|
        e.nb_bits = if (w != 0) @intCast(table_log + 1 - w) else 0;
    // fill val
    var nb_per_rank = [_]u16{0} ** (table_log_max + 2); // support w=0=>n=tableLog+1
    var val_per_rank = [_]u16{0} ** (table_log_max + 2);
    for (ct.elt[0..nb_symbols]) |e| nb_per_rank[e.nb_bits] += 1;
    // determine starting value per rank
    val_per_rank[table_log + 1] = 0; // for w==0
    {
        var min: u16 = 0;
        var n: u32 = table_log;
        while (n > 0) : (n -= 1) { // start at n=tablelog <-> w=1
            val_per_rank[n] = min; // get starting value within each rank
            min += nb_per_rank[n];
            min >>= 1;
        }
    }
    // assign value within rank, symbol order
    for (ct.elt[0..nb_symbols]) |*e| {
        e.value = val_per_rank[e.nb_bits];
        val_per_rank[e.nb_bits] +%= 1;
    }
    return read_size;
}

// ── table header ────────────────────────────────────────────────────────────

const max_fse_table_log_for_huff_header = 6;

/// `HUF_compressWeights`: FSE-code the weight table. 0 = not compressible,
/// 1 = a single repeated weight.
fn compressWeights(dst: []u8, weights: []const u8) Error!usize {
    var max_symbol: u32 = table_log_max;
    var counts: [table_log_max + 1]u32 = undefined;
    var norm: [table_log_max + 1]i16 = undefined;
    if (weights.len <= 1) return 0;
    const max_count = hist.count(&counts, &max_symbol, weights);
    if (max_count == weights.len) return 1;
    if (max_count == 1) return 0;

    const table_log = fse.optimalTableLog(max_fse_table_log_for_huff_header, weights.len, max_symbol);
    _ = try fse.normalizeCount(&norm, table_log, &counts, weights.len, max_symbol, false);
    var op = try fse.writeNCount(dst, &norm, max_symbol, table_log);
    var ct: fse.CTable = .{};
    try ct.build(&norm, max_symbol, table_log);
    const c_size = fse.compressUsingCTable(dst[op..], weights, &ct);
    if (c_size == 0) return 0;
    op += c_size;
    return op;
}

/// `HUF_writeCTable_wksp`: serialise the code lengths as weights.
pub fn writeCTable(dst: []u8, ct: *const CTable, max_symbol: u32, huff_log: u32) Error!usize {
    var bits_to_weight: [table_log_max + 1]u8 = undefined;
    var huff_weight: [symbol_value_max + 1]u8 = undefined;
    if (max_symbol > symbol_value_max) return error.Generic;

    bits_to_weight[0] = 0;
    var n: u32 = 1;
    while (n < huff_log + 1) : (n += 1) bits_to_weight[n] = @intCast(huff_log + 1 - n);
    n = 0;
    while (n < max_symbol) : (n += 1) huff_weight[n] = bits_to_weight[ct.elt[n].nb_bits];

    if (dst.len < 1) return error.DstSizeTooSmall;
    const h_size = try compressWeights(dst[1..], huff_weight[0..max_symbol]);
    if (h_size > 1 and h_size < max_symbol / 2) { // FSE compressed
        dst[0] = @intCast(h_size);
        return h_size + 1;
    }

    // raw values, 4 bits each
    if (max_symbol > (256 - 128)) return error.Generic;
    if (((max_symbol + 1) / 2) + 1 > dst.len) return error.DstSizeTooSmall;
    dst[0] = @intCast(128 + (max_symbol - 1));
    huff_weight[max_symbol] = 0;
    n = 0;
    while (n < max_symbol) : (n += 2) dst[(n / 2) + 1] = (huff_weight[n] << 4) + huff_weight[n + 1];
    return ((max_symbol + 1) / 2) + 1;
}

// ── bit streams ─────────────────────────────────────────────────────────────

/// `HUF_compress1X_usingCTable_internal`: symbols are written last-to-first.
/// Returns 0 when the stream does not fit.
pub fn compress1X(dst: []u8, src: []const u8, ct: *const CTable) usize {
    if (dst.len < 8) return 0;
    var bits = bitstream.CStream.init(dst) catch return 0;
    var n = src.len;
    // Flush every 4 symbols: 4 * 12 bits + 7 pending never fill the container.
    var since_flush: u32 = 0;
    while (n > 0) {
        n -= 1;
        const e = ct.elt[src[n]];
        bits.addBits(e.value, e.nb_bits);
        since_flush += 1;
        if (since_flush == 4) {
            bits.flush();
            since_flush = 0;
        }
    }
    bits.flush();
    return bits.close();
}

/// `HUF_compress4X_usingCTable_internal`: jump table + four 1X streams.
pub fn compress4X(dst: []u8, src: []const u8, ct: *const CTable) usize {
    const segment_size = (src.len + 3) / 4;
    if (dst.len < 6 + 1 + 1 + 1 + 8) return 0; // minimum space to compress successfully
    if (src.len < 12) return 0; // no saving possible: input too small
    var op: usize = 6; // jump table
    var ip: usize = 0;
    for (0..3) |k| {
        const c_size = compress1X(dst[op..], src[ip .. ip + segment_size], ct);
        if (c_size == 0 or c_size > 65535) return 0;
        std.mem.writeInt(u16, dst[2 * k ..][0..2], @intCast(c_size), .little);
        op += c_size;
        ip += segment_size;
    }
    const c_size = compress1X(dst[op..], src[ip..], ct);
    if (c_size == 0 or c_size > 65535) return 0;
    op += c_size;
    return op;
}

pub const Streams = enum { single, four };

/// `HUF_compressCTable_internal`. `table_size` is what already sits at
/// `dst[0..table_size]` (the serialised table, or 0 when reusing).
fn compressWithTable(dst: []u8, table_size: usize, src: []const u8, streams: Streams, ct: *const CTable) usize {
    const out = dst[table_size..];
    const c_size = switch (streams) {
        .single => compress1X(out, src, ct),
        .four => compress4X(out, src, ct),
    };
    if (c_size == 0) return 0;
    const total = table_size + c_size;
    // check compressibility
    if (total >= src.len - 1) return 0;
    return total;
}

const suspect_incompressible_sample_size = 4096;
const suspect_incompressible_sample_ratio = 10;

/// `HUF_compress_internal` for `HUF_compress{1,4}X_repeat`.
///
/// `old` is the previous block's table and receives the new one when a new one
/// is built; `repeat` says whether `old` may be reused. Returns the literal
/// payload size, 0 for "not compressible", 1 for "single symbol" (`dst[0]`
/// holds it).
pub fn compress(dst: []u8, src: []const u8, huff_log_in: u32, streams: Streams, old: *CTable, repeat: *Repeat, flags: Flags) Error!usize {
    if (src.len == 0) return 0;
    if (dst.len == 0) return 0;
    if (src.len > block_size_max) return error.Generic;
    var huff_log = huff_log_in;
    if (huff_log == 0) huff_log = table_log_default;
    var max_symbol: u32 = symbol_value_max;
    var counts: [symbol_value_max + 1]u32 = undefined;

    // Heuristic : If old table is valid, use it for small inputs
    if (flags.prefer_repeat and repeat.* == .valid) return compressWithTable(dst, 0, src, streams, old);

    // If uncompressible data is suspected, do a smaller sampling first.
    if (flags.suspect_uncompressible and src.len >= suspect_incompressible_sample_size * suspect_incompressible_sample_ratio) {
        var largest_total: usize = 0;
        var m1: u32 = max_symbol;
        largest_total += hist.count(&counts, &m1, src[0..suspect_incompressible_sample_size]);
        var m2: u32 = max_symbol;
        largest_total += hist.count(&counts, &m2, src[src.len - suspect_incompressible_sample_size ..]);
        if (largest_total <= ((2 * suspect_incompressible_sample_size) >> 7) + 4) return 0;
    }

    const largest = hist.count(&counts, &max_symbol, src);
    if (largest == src.len) {
        dst[0] = src[0];
        return 1;
    }
    if (largest <= (src.len >> 7) + 4) return 0; // heuristic: probably not compressible enough

    if (repeat.* == .check and !validateCTable(old, &counts, max_symbol)) repeat.* = .none;
    if (flags.prefer_repeat and repeat.* != .none) return compressWithTable(dst, 0, src, streams, old);

    huff_log = optimalTableLog(huff_log, src.len, max_symbol, &counts, flags.optimal_depth);
    var ct: CTable = .{};
    huff_log = try buildCTable(&ct, &counts, max_symbol, huff_log);

    const h_size = try writeCTable(dst, &ct, max_symbol, huff_log);
    if (repeat.* != .none) {
        const old_size = estimateCompressedSize(old, &counts, max_symbol);
        const new_size = estimateCompressedSize(&ct, &counts, max_symbol);
        if (old_size <= h_size + new_size or h_size + 12 >= src.len) {
            return compressWithTable(dst, 0, src, streams, old);
        }
    }
    if (h_size + 12 >= src.len) return 0;
    repeat.* = .none;
    old.* = ct;
    return compressWithTable(dst, h_size, src, streams, old);
}

test "two-symbol alphabet codes each symbol in one bit" {
    var counts = [_]u32{0} ** 256;
    counts['a'] = 10;
    counts['b'] = 5;
    var ct: CTable = .{};
    const log = try buildCTable(&ct, &counts, 'b', 11);
    try std.testing.expectEqual(@as(u32, 1), log);
    try std.testing.expectEqual(@as(u8, 1), ct.elt['a'].nb_bits);
    try std.testing.expectEqual(@as(u8, 1), ct.elt['b'].nb_bits);
}

test "setMaxHeight keeps the Kraft sum at one" {
    // Fibonacci counts force a deep tree that must be flattened to 11 bits.
    var counts = [_]u32{0} ** 256;
    var a: u32 = 1;
    var b: u32 = 1;
    for (0..20) |i| {
        counts[i] = a;
        const t = a + b;
        a = b;
        b = t;
    }
    var ct: CTable = .{};
    const log = try buildCTable(&ct, &counts, 19, 11);
    try std.testing.expectEqual(@as(u32, 11), log);
    var kraft: u64 = 0;
    for (ct.elt[0..20]) |e| {
        try std.testing.expect(e.nb_bits >= 1 and e.nb_bits <= 11);
        kraft += @as(u64, 1) << @intCast(11 - e.nb_bits);
    }
    try std.testing.expectEqual(@as(u64, 1 << 11), kraft);
}
