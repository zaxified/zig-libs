// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Compression dictionaries (port of libzstd lib/compress/zstd_compress.c,
//! v1.5.7): loading a dictionary into a match state and a block state
//! (`ZSTD_compress_insertDictionary`, `ZSTD_loadZstdDictionary`,
//! `ZSTD_loadCEntropy`, `ZSTD_loadDictionaryContent`), and `CDict`, a
//! dictionary digested once for many frames (`ZSTD_createCDict_advanced2`,
//! with the dedicated dictionary search's parameters).
//!
//! A dictionary is either raw content -- bytes the input is likely to
//! repeat -- or a "full" zstd dictionary: magic number, ID, the entropy
//! tables a first block may reuse, three repcodes, then the content
//! (RFC 8878, *Dictionary Format*). Loading puts the content into the
//! window as a prefix and fills the match finder's tables with it; the
//! frame's input then follows as a new segment, so the content becomes the
//! window's extDict and every strategy's extDict match finder searches it.
//! A `CDict` holds its own filled tables, which a context either copies
//! (`frame.Compressor`, `resetByCopyingCDict`) or, for small inputs,
//! attaches and searches in place (`dict_match_state`, see SPEC.md).

const std = @import("std");
const params = @import("params.zig");
const match = @import("match.zig");
const lazy = @import("lazy.zig");
const opt = @import("opt.zig");
const ldm = @import("ldm.zig");
const frame = @import("frame.zig");
const huf = @import("huf.zig");
const fse = @import("fse.zig");
const sequences = @import("sequences.zig");
const dbits = @import("dbits.zig");

/// `ZSTD_dictContentType_e`.
pub const ContentType = enum {
    /// `ZSTD_dct_auto`: a full dictionary if it starts with the dictionary
    /// magic number, else raw content.
    auto,
    /// `ZSTD_dct_rawContent`: raw content whatever it starts with.
    raw_content,
    /// `ZSTD_dct_fullDict`: must be a full dictionary.
    full,
};

/// `ZSTD_MAGIC_DICTIONARY`.
pub const magic_dictionary: u32 = 0xEC30A437;

pub const Error = error{
    /// A full dictionary's entropy tables or repcodes are invalid
    /// (`dictionary_corrupted`).
    DictionaryCorrupted,
    /// `ContentType.full` for bytes that are not a full dictionary
    /// (`dictionary_wrong`).
    DictionaryWrong,
};

/// What of the context's parameters loading reads besides the match state's
/// own (`ZSTD_CCtx_params`).
pub const LoadParams = struct {
    /// `fParams.noDictIDFlag`: the returned ID is 0.
    no_dict_id: bool = false,
    /// `forceWindow`: the dictionary counts only within the window
    /// (`loaded_dict_end` stays 0).
    force_window: bool = false,
    /// `deterministicRefPrefix`.
    deterministic_ref_prefix: bool = false,
    /// `ZSTD_WINDOW_OVERFLOW_CORRECT_FREQUENTLY` (test seam, see frame.zig).
    overflow_correct_frequently: bool = false,
};

/// `ZSTD_compress_insertDictionary`: load `dict` into `ms` (and `ls`, the
/// long-distance matcher's table, for raw content) and, for a full
/// dictionary, its entropy tables and repcodes into `bs`. Returns the
/// dictionary's ID (0 for raw content, or with `no_dict_id`). A dictionary
/// under 8 bytes is ignored.
pub fn insertDictionary(bs: *frame.BlockState, ms: *match.MatchState, ls: ?*ldm.State, dict: []const u8, content_type: ContentType, dtlm: match.TableLoad, tfp: match.FillPurpose, lp: LoadParams) Error!u32 {
    if (dict.len < 8) {
        if (content_type == .full) return error.DictionaryWrong;
        return 0;
    }
    bs.* = .{}; // ZSTD_reset_compressedBlockState
    // dict restricted modes
    if (content_type == .raw_content) {
        loadDictionaryContent(ms, ls, dict, dtlm, tfp, lp);
        return 0;
    }
    if (std.mem.readInt(u32, dict[0..4], .little) != magic_dictionary) {
        if (content_type == .auto) { // raw content dictionary detected
            loadDictionaryContent(ms, ls, dict, dtlm, tfp, lp);
            return 0;
        }
        return error.DictionaryWrong;
    }
    // dict as full zstd dictionary: ZSTD_loadZstdDictionary
    const dict_id: u32 = if (lp.no_dict_id) 0 else std.mem.readInt(u32, dict[4..8], .little);
    const e_size = try loadCEntropy(bs, dict);
    loadDictionaryContent(ms, null, dict[e_size..], dtlm, tfp, lp);
    return dict_id;
}

/// `ZSTD_dictNCountRepeat`: a table that gives every symbol up to `max` a
/// nonzero probability may be reused without checking (`valid`); one that
/// assigns some a zero probability must be checked (FSE cannot encode
/// them).
fn dictNCountRepeat(norm: []const i16, dict_max_symbol: u32, max: u32) sequences.FseRepeat {
    if (dict_max_symbol < max) return .check;
    for (norm[0 .. max + 1]) |n| if (n == 0) return .check;
    return .valid;
}

/// `ZSTD_loadCEntropy`: the Huffman table, the offset, match-length and
/// literal-length FSE tables and the three repcodes of the full dictionary
/// `dict` into `bs`. Returns the size of that header (the content follows).
pub fn loadCEntropy(bs: *frame.BlockState, dict: []const u8) Error!usize {
    var p: usize = 8; // skip magic num and dict ID
    bs.huf.repeat = .check;
    {
        var has_zero_weights = true;
        const huf_header_size = huf.readCTable(&bs.huf.table, dict[p..], &has_zero_weights) catch return error.DictionaryCorrupted;
        // Only a table giving every byte a code is valid without a check
        if (!has_zero_weights and bs.huf.table.max_symbol == 255) bs.huf.repeat = .valid;
        p += huf_header_size;
    }

    // The tables are zeroed first: libzstd leaves the entries past a table's
    // last symbol as they were, and the optimal parser's seeding may read
    // them (see SPEC.md).
    var offcode_ncount: [sequences.max_off + 1]i16 = undefined;
    var offcode_max_value: u32 = sequences.max_off;
    {
        var offcode_log: u32 = undefined;
        const header_size = dbits.readNCount(&offcode_ncount, &offcode_max_value, &offcode_log, dict[p..]) catch return error.DictionaryCorrupted;
        if (offcode_log > sequences.off_fse_log) return error.DictionaryCorrupted;
        // fill all offset symbols to avoid garbage at end of table
        bs.fse.of = zeroedCTable();
        bs.fse.of.build(&offcode_ncount, sequences.max_off, offcode_log) catch return error.DictionaryCorrupted;
        // Defer checking offcodeMaxValue because we need to know the size
        // of the dictionary content
        p += header_size;
    }
    {
        var ml_ncount: [sequences.max_ml + 1]i16 = undefined;
        var ml_max_value: u32 = sequences.max_ml;
        var ml_log: u32 = undefined;
        const header_size = dbits.readNCount(&ml_ncount, &ml_max_value, &ml_log, dict[p..]) catch return error.DictionaryCorrupted;
        if (ml_log > sequences.ml_fse_log) return error.DictionaryCorrupted;
        bs.fse.ml = zeroedCTable();
        bs.fse.ml.build(&ml_ncount, ml_max_value, ml_log) catch return error.DictionaryCorrupted;
        bs.fse.ml_repeat = dictNCountRepeat(&ml_ncount, ml_max_value, sequences.max_ml);
        p += header_size;
    }
    {
        var ll_ncount: [sequences.max_ll + 1]i16 = undefined;
        var ll_max_value: u32 = sequences.max_ll;
        var ll_log: u32 = undefined;
        const header_size = dbits.readNCount(&ll_ncount, &ll_max_value, &ll_log, dict[p..]) catch return error.DictionaryCorrupted;
        if (ll_log > sequences.ll_fse_log) return error.DictionaryCorrupted;
        bs.fse.ll = zeroedCTable();
        bs.fse.ll.build(&ll_ncount, ll_max_value, ll_log) catch return error.DictionaryCorrupted;
        bs.fse.ll_repeat = dictNCountRepeat(&ll_ncount, ll_max_value, sequences.max_ll);
        p += header_size;
    }

    if (p + 12 > dict.len) return error.DictionaryCorrupted;
    for (&bs.rep, 0..) |*r, u| r.* = std.mem.readInt(u32, dict[p + 4 * u ..][0..4], .little);
    p += 12;

    {
        const dict_content_size = dict.len - p;
        var offcode_max: u32 = sequences.max_off;
        if (dict_content_size <= std.math.maxInt(u32) - (128 << 10)) {
            // The maximum offset that must be supported
            const max_offset: u32 = @intCast(dict_content_size + (128 << 10));
            // Calculate minimum offset code required to represent maxOffset
            offcode_max = fse.highbit32(max_offset);
        }
        // All offset values <= dictContentSize + 128 KB must be representable
        // for a valid table
        bs.fse.of_repeat = dictNCountRepeat(&offcode_ncount, offcode_max_value, @min(offcode_max, sequences.max_off));
        // All repCodes must be <= dictContentSize and != 0
        for (bs.rep) |r| if (r == 0 or r > dict_content_size) return error.DictionaryCorrupted;
    }
    return p;
}

/// `ZSTD_dedicatedDictSearch_getCParams`: the level's parameters for a
/// CDict of `dict_size` bytes (sized for an input of 0 bytes, not a small
/// one), the hash log 2 larger for `greedy`..`lazy2`.
fn ddsGetCParams(level: i32, dict_size: usize) params.CParams {
    var cp = params.getInternal(level, 0, dict_size, .create_cdict);
    switch (cp.strategy) {
        .fast, .dfast => {},
        .greedy, .lazy, .lazy2 => cp.hash_log += lazy.ddss_bucket_log,
        .btlazy2, .btopt, .btultra, .btultra2 => {},
    }
    return cp;
}

/// `ZSTD_dedicatedDictSearch_isSupported`.
fn ddsIsSupported(cp: params.CParams) bool {
    return @intFromEnum(cp.strategy) >= @intFromEnum(params.Strategy.greedy) and
        @intFromEnum(cp.strategy) <= @intFromEnum(params.Strategy.lazy2) and
        cp.hash_log > cp.chain_log and
        cp.chain_log <= 24;
}

/// `ZSTD_dedicatedDictSearch_revertCParams`: the parameters a context
/// attaching a dedicated-search CDict sizes its own tables from.
pub fn ddsRevertCParams(cp: *params.CParams) void {
    switch (cp.strategy) {
        .fast, .dfast => {},
        .greedy, .lazy, .lazy2 => cp.hash_log = @max(cp.hash_log - lazy.ddss_bucket_log, params.hash_log_min),
        .btlazy2, .btopt, .btultra, .btultra2 => {},
    }
}

fn zeroedCTable() fse.CTable {
    var ct: fse.CTable = .{};
    @memset(&ct.state_table, 0);
    @memset(&ct.symbol_tt, .{});
    return ct;
}

/// `ZSTD_loadDictionaryContent`: `content` becomes the window's prefix and
/// its positions go into the strategy's tables (`dtlm` and `tfp` as
/// `match.fillHashTableFor` takes them); with `ls`, into the long-distance
/// matcher's table too. Too long a dictionary loads only its end: what
/// indices up to `ZSTD_CURRENT_MAX` (or, tagged, 2^24) can hold, and then
/// for the tables what their size can reach.
pub fn loadDictionaryContent(ms: *match.MatchState, ls: ?*ldm.State, content: []const u8, dtlm: match.TableLoad, tfp: match.FillPurpose, lp: LoadParams) void {
    const cp = ms.cp;
    var src = content;
    {
        // Ensure large dictionaries can't cause index overflow: allow the
        // dictionary to set indices up to exactly ZSTD_CURRENT_MAX.
        var max_dict_size: usize = match.current_max - match.window_start;
        if (params.cdictIndicesAreTagged(cp) and tfp == .for_cdict) {
            // "Short cache" keeps the low ZSTD_SHORT_CACHE_TAG_BITS of each
            // CDict entry for a tag: its indices must not reach them.
            const short_cache_max_dict_size: usize = (@as(usize, 1) << (32 - params.short_cache_tag_bits)) - match.window_start;
            max_dict_size = @min(max_dict_size, short_cache_max_dict_size);
            std.debug.assert(ls == null);
        }
        // If the dictionary is too large, only load the suffix of the dictionary.
        if (src.len > max_dict_size) src = src[src.len - max_dict_size ..];
    }

    _ = ms.windowUpdate(src, false);

    if (ls) |l| { // Load the entire dict into LDM matchfinders.
        l.windowUpdate(src);
        l.loaded_dict_end = if (lp.force_window) 0 else @intCast(l.src_base + l.src.len);
        l.fillHashTable(src);
    }

    // If the dict is larger than we can reasonably index in our tables, only
    // load the suffix.
    {
        const shift: u32 = @min(@max(cp.hash_log + 3, cp.chain_log + 1), 31);
        const max_dict_size: usize = @as(usize, 1) << @intCast(shift);
        if (src.len > max_dict_size) src = src[src.len - max_dict_size ..];
    }

    const index = struct {
        fn of(m: *const match.MatchState, ptr: [*]const u8) u32 {
            return @intCast(m.src_base + (@intFromPtr(ptr) - @intFromPtr(m.src.ptr)));
        }
    }.of;
    const iend_ptr = src.ptr + src.len;
    ms.next_to_update = index(ms, src.ptr);
    ms.loaded_dict_end = if (lp.force_window) 0 else index(ms, iend_ptr);
    ms.force_non_contiguous = lp.deterministic_ref_prefix;

    if (src.len <= match.hash_read_size) return;

    _ = ms.overflowCorrectIfNeeded(lp.overflow_correct_frequently, index(ms, src.ptr), index(ms, iend_ptr));
    const iend = index(ms, iend_ptr);

    switch (cp.strategy) {
        .fast => match.fillHashTableFor(ms, iend, dtlm, tfp),
        .dfast => match.fillDoubleHashTableFor(ms, iend, dtlm, tfp),
        .greedy, .lazy, .lazy2 => if (ms.dedicated_dict_search) {
            std.debug.assert(ms.chain_table.len != 0);
            lazy.ddsLoadDictionary(ms, iend - match.hash_read_size);
        } else if (ms.use_row) {
            @memset(ms.tag_table, 0);
            lazy.rowUpdateDictionary(ms, iend - match.hash_read_size);
        } else {
            lazy.insertDictionary(ms, iend - match.hash_read_size);
        },
        // we want the dictionary table fully sorted
        .btlazy2, .btopt, .btultra, .btultra2 => opt.updateTreeDictionary(ms, iend - match.hash_read_size, iend),
    }
    ms.next_to_update = iend;
}

/// A dictionary digested for compression (`ZSTD_CDict`): its content (a
/// copy, unless made by a context for one frame), its entropy tables and
/// repcodes, and the match tables filled from its content with its own
/// parameters, which a context copies or attaches at the start of a frame.
/// Read-only once made: any number of contexts may use one at a time.
pub const CDict = struct {
    gpa: std.mem.Allocator,
    /// `dictContent`: the whole dictionary as given, header included.
    content: []const u8,
    /// Owned copy of `content`, if any.
    owned: ?[]u8,
    content_type: ContentType,
    /// `dictID`: the full dictionary's ID; 0 for raw content, or when
    /// made with `Advanced.dict_id_flag` false.
    dict_id: u32,
    /// `compressionLevel`: the level it was made for (`init`), or 0 for
    /// `ZSTD_NO_CLEVEL` (`initAdvanced`), which makes contexts use its
    /// parameters for any input size.
    compression_level: i32,
    /// `useRowMatchFinder`.
    use_row: bool,
    /// `matchState.dedicatedDictSearch`: made with
    /// `Advanced.enable_dedicated_dict_search` where libzstd supports it
    /// (`greedy`..`lazy2`); its hash table is laid out in buckets, its
    /// parameters (`compressionParameters`) have a hash log 2 larger, and
    /// a context always attaches it.
    dedicated_dict_search: bool,
    /// `matchState`: the window (the content as its prefix) and the filled
    /// tables, `fast`/`dfast` ones tagged. An attached CDict is searched
    /// through it (`MatchState.dict_match_state`).
    ms: match.MatchState,
    /// `cBlockState`: the entropy tables and repcodes a frame starts from.
    block_state: frame.BlockState,
    tables: []u32,
    tag_table: []u8,

    pub const Options = struct {
        /// The level whose parameters (for an input of unknown size) the
        /// dictionary is digested with; 0 for the default.
        level: i32 = params.default_level,
        content_type: ContentType = .auto,
        /// Parameters over the level's (as for a context); `dict_id_flag`,
        /// `force_max_window` and `deterministic_ref_prefix` also apply.
        advanced: params.Advanced = .{},
        /// `ZSTD_c_srcSizeHint`: size the parameters for inputs of about
        /// this many bytes rather than small ones.
        src_size_hint: ?u32 = null,
    };

    pub const InitError = Error || params.Advanced.CheckError || error{ OutOfMemory, LevelUnsupported };

    /// `ZSTD_createCDict`: `dict` digested with `level`'s parameters for
    /// small inputs; contexts use those for inputs up to 128 KB (or six
    /// times the dictionary), and reload the dictionary with the input's
    /// own parameters above that. The content is copied.
    pub fn init(gpa: std.mem.Allocator, dict: []const u8, level: i32) InitError!CDict {
        var cd = try create(gpa, dict, .{ .level = level }, true);
        cd.compression_level = if (level == 0) params.default_level else level;
        return cd;
    }

    /// `ZSTD_createCDict_advanced2` (by copy): `dict` digested with the
    /// parameters `opts` gives a context, whatever the input size.
    pub fn initAdvanced(gpa: std.mem.Allocator, dict: []const u8, opts: Options) InitError!CDict {
        return create(gpa, dict, opts, true);
    }

    /// `ZSTD_createCDict_advanced2` by reference (`ZSTD_dlm_byRef`):
    /// `dict` must outlive it. As in libzstd, its window ends in the
    /// caller's memory, so an input placed right after `dict` continues it
    /// (one segment, not an extDict) and may compress differently from one
    /// elsewhere. `Options.dictionary = .raw` does not use it: it copies,
    /// as `ZSTD_CCtx_loadDictionary` does.
    pub fn initReference(gpa: std.mem.Allocator, dict: []const u8, opts: Options) InitError!CDict {
        return create(gpa, dict, opts, false);
    }

    /// The parameters a CDict for `dict_size` bytes gets with `opts`
    /// (`ZSTD_getCParamsFromCCtxParams(..., ZSTD_cpm_createCDict)`, or
    /// `ZSTD_dedicatedDictSearch_getCParams` with the explicit parameters
    /// over it when `Advanced.enable_dedicated_dict_search` applies).
    pub fn paramsFor(dict_size: usize, opts: Options) params.CParams {
        return resolveParams(dict_size, opts)[0];
    }

    /// `ZSTD_createCDict_advanced2`'s choice: the parameters, and whether
    /// the CDict gets the dedicated dictionary search (asked for, and
    /// supported with the parameters it would get; else the plain ones).
    fn resolveParams(dict_size: usize, opts: Options) struct { params.CParams, bool } {
        if (opts.advanced.enable_dedicated_dict_search) {
            var cp = ddsGetCParams(opts.level, dict_size);
            params.overrideCParams(&cp, opts.advanced);
            if (ddsIsSupported(cp)) return .{ cp, true };
        }
        // Fall back to non-DDSS params
        const size_hint: u64 = if (opts.src_size_hint) |h| h else params.unknown_size;
        return .{ params.getFromCCtxParams(opts.level, size_hint, dict_size, .create_cdict, opts.advanced), false };
    }

    fn create(gpa: std.mem.Allocator, dict: []const u8, opts: Options, copy: bool) InitError!CDict {
        if (opts.level > params.max_level) return error.LevelUnsupported;
        try opts.advanced.check();
        const cp, const dds = resolveParams(dict.len, opts);
        const use_row = params.resolveRowMatchFinder(opts.advanced.row_match_finder, cp);
        // ZSTD_allocateChainTable: not for fast, not with the row match
        // finder -- always for the dedicated search, whose table layout
        // lives in it
        const chain_len: usize = if (dds or (cp.strategy != .fast and !use_row)) @as(usize, 1) << @intCast(cp.chain_log) else 0;
        const hash_len: usize = @as(usize, 1) << @intCast(cp.hash_log);

        const owned: ?[]u8 = if (copy and dict.len != 0) try gpa.dupe(u8, dict) else null;
        errdefer if (owned) |o| gpa.free(o);
        const tables = try gpa.alloc(u32, hash_len + chain_len);
        errdefer gpa.free(tables);
        @memset(tables, 0);
        const tag_table = try gpa.alloc(u8, if (use_row) hash_len else 0);
        errdefer gpa.free(tag_table);
        @memset(tag_table, 0);

        var cd: CDict = .{
            .gpa = gpa,
            .content = if (owned) |o| o else dict,
            .owned = owned,
            .content_type = opts.content_type,
            .dict_id = 0,
            .compression_level = 0, // ZSTD_NO_CLEVEL: signals advanced API usage
            .use_row = use_row,
            .dedicated_dict_search = dds,
            .ms = .{
                .src = &.{},
                .cp = cp,
                .hash_table = tables[0..hash_len],
                .chain_table = tables[hash_len..],
                .tag_table = tag_table,
                .use_row = use_row,
                .row_hash_log = if (use_row) cp.hash_log - params.rowLog(cp) else 0,
                // a CDict never salts its row hashes
                .hash_salt = 0,
                .dedicated_dict_search = dds,
            },
            .block_state = .{},
            .tables = tables,
            .tag_table = tag_table,
        };
        // ZSTD_initCDict_internal: (maybe) load the dictionary; one under 8
        // bytes is skipped
        cd.dict_id = try insertDictionary(&cd.block_state, &cd.ms, null, cd.content, opts.content_type, .full, .for_cdict, .{
            .no_dict_id = !opts.advanced.dict_id_flag,
            .force_window = opts.advanced.force_max_window,
            .deterministic_ref_prefix = opts.advanced.deterministic_ref_prefix,
        });
        return cd;
    }

    pub fn deinit(cd: *CDict) void {
        cd.gpa.free(cd.tables);
        cd.gpa.free(cd.tag_table);
        if (cd.owned) |o| cd.gpa.free(o);
        cd.* = undefined;
    }

    /// `ZSTD_getDictID_fromCDict`.
    pub fn dictId(cd: *const CDict) u32 {
        return cd.dict_id;
    }

    /// `ZSTD_getCParamsFromCDict`: the parameters its tables were made with.
    pub fn compressionParameters(cd: *const CDict) params.CParams {
        return cd.ms.cp;
    }

    /// The memory it holds besides the struct (`ZSTD_sizeof_CDict`, for
    /// this port's layout).
    pub fn memorySize(cd: *const CDict) usize {
        return cd.tables.len * @sizeOf(u32) + cd.tag_table.len + if (cd.owned) |o| o.len else 0;
    }
};

test "a dictionary under 8 bytes is ignored, unless it must be full" {
    const gpa = std.testing.allocator;
    var cd = try CDict.init(gpa, "abcdefg", 3);
    defer cd.deinit();
    try std.testing.expectEqual(@as(u32, 0), cd.dictId());
    try std.testing.expectEqual(@as(u32, match.window_start), cd.ms.src_base);
    try std.testing.expectEqual(@as(usize, 0), cd.ms.src.len);
    try std.testing.expectError(error.DictionaryWrong, CDict.initAdvanced(gpa, "abcdefg", .{ .content_type = .full }));
    try std.testing.expectError(error.DictionaryWrong, CDict.initAdvanced(gpa, "not a full dictionary", .{ .content_type = .full }));
}

test "raw content fills the window from index 2 and marks the dictionary loaded" {
    const gpa = std.testing.allocator;
    var buf: [5000]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @truncate(i * 7 + i / 13);
    var cd = try CDict.init(gpa, &buf, 1);
    defer cd.deinit();
    try std.testing.expectEqual(@as(u32, 0), cd.dictId());
    try std.testing.expectEqual(@as(u32, 2 + buf.len), cd.ms.loaded_dict_end);
    try std.testing.expectEqual(@as(u32, 2 + buf.len), cd.ms.next_to_update);
    // fast: tagged entries, every one a valid index shifted by 8
    var n: usize = 0;
    for (cd.ms.hash_table) |e| if (e != 0) {
        n += 1;
        try std.testing.expect(e >> 8 >= 2 and e >> 8 < 2 + buf.len);
    };
    try std.testing.expect(n > 100);
}

test "a full dictionary with a bad repcode is corrupted" {
    // magic, ID, then a header too short for any table
    const bytes = [_]u8{ 0x37, 0xa4, 0x30, 0xec, 1, 0, 0, 0, 0xff, 0xff };
    try std.testing.expectError(error.DictionaryCorrupted, CDict.init(std.testing.allocator, &bytes, 3));
}

/// A full dictionary from a Huffman table built on `lit_counts`, flat FSE
/// tables (every code nonzero), repcodes 1 4 8 and `content`.
fn testDictionary(buf: []u8, lit_counts: []const u32, max_symbol: u32, of_max: comptime_int, content: []const u8) !usize {
    std.mem.writeInt(u32, buf[0..4], magic_dictionary, .little);
    std.mem.writeInt(u32, buf[4..8], 7, .little);
    var p: usize = 8;
    var ct: huf.CTable = .{};
    const log = try huf.buildCTable(&ct, lit_counts, max_symbol, 11);
    p += try huf.writeCTable(buf[p..], &ct, max_symbol, log);
    inline for (.{ .{ of_max, 5 }, .{ sequences.max_ml, 6 }, .{ sequences.max_ll, 6 } }) |t| {
        var norm = [_]i16{1} ** (t[0] + 1);
        const sum: i16 = t[0] + 1;
        norm[0] += (@as(i16, 1) << t[1]) - sum;
        p += try fse.writeNCount(buf[p..], &norm, t[0], t[1]);
    }
    for ([_]u32{ 1, 4, 8 }) |r| {
        std.mem.writeInt(u32, buf[p..][0..4], r, .little);
        p += 4;
    }
    @memcpy(buf[p..][0..content.len], content);
    return p + content.len;
}

test "a Huffman table is valid only with every byte and no zero weight" {
    var buf: [2048]u8 = undefined;
    const content = "0123456789abcdef" ** 4;
    var counts: [256]u32 = undefined;
    for (&counts, 0..) |*c, i| c.* = 1 + @as(u32, @intCast(i % 7));
    var bs: frame.BlockState = .{};
    // all 256 bytes: valid, and so are the flat FSE tables
    var n = try testDictionary(&buf, &counts, 255, sequences.max_off, content);
    _ = try loadCEntropy(&bs, buf[0..n]);
    try std.testing.expectEqual(huf.Repeat.valid, bs.huf.repeat);
    try std.testing.expectEqual(sequences.FseRepeat.valid, bs.fse.ml_repeat);
    try std.testing.expectEqual(sequences.FseRepeat.valid, bs.fse.ll_repeat);
    try std.testing.expectEqual(sequences.FseRepeat.valid, bs.fse.of_repeat);
    // one byte without a code
    counts[5] = 0;
    n = try testDictionary(&buf, &counts, 255, sequences.max_off, content);
    _ = try loadCEntropy(&bs, buf[0..n]);
    try std.testing.expectEqual(huf.Repeat.check, bs.huf.repeat);
    // 128 bytes, every one with a code
    counts[5] = 1;
    n = try testDictionary(&buf, &counts, 127, sequences.max_off, content);
    _ = try loadCEntropy(&bs, buf[0..n]);
    try std.testing.expectEqual(huf.Repeat.check, bs.huf.repeat);
}

test "an FSE table is valid only when every code up to the largest has a probability" {
    var norm = [_]i16{ 2, 1, -1, 3 };
    try std.testing.expectEqual(sequences.FseRepeat.valid, dictNCountRepeat(&norm, 3, 3));
    try std.testing.expectEqual(sequences.FseRepeat.check, dictNCountRepeat(&norm, 2, 3));
    norm[3] = 0; // the last one
    try std.testing.expectEqual(sequences.FseRepeat.check, dictNCountRepeat(&norm, 3, 3));
    try std.testing.expectEqual(sequences.FseRepeat.valid, dictNCountRepeat(&norm, 3, 2));
}

test "an 8-byte dictionary is loaded: magic and ID alone are corrupted" {
    const gpa = std.testing.allocator;
    const magic8 = [_]u8{ 0x37, 0xa4, 0x30, 0xec, 1, 0, 0, 0 };
    try std.testing.expectError(error.DictionaryCorrupted, CDict.init(gpa, &magic8, 3));
    var cd = try CDict.init(gpa, "12345678", 3);
    defer cd.deinit();
    try std.testing.expectEqual(@as(u32, 2 + 8), cd.ms.loaded_dict_end);
}

test "a CDict made without the ID flag has ID 0" {
    const gpa = std.testing.allocator;
    var buf: [2048]u8 = undefined;
    var counts: [256]u32 = undefined;
    for (&counts, 0..) |*c, i| c.* = 1 + @as(u32, @intCast(i % 7));
    const n = try testDictionary(&buf, &counts, 255, sequences.max_off, "0123456789abcdef" ** 4);
    var with = try CDict.init(gpa, buf[0..n], 3);
    defer with.deinit();
    try std.testing.expectEqual(@as(u32, 7), with.dictId());
    var without = try CDict.initAdvanced(gpa, buf[0..n], .{ .advanced = .{ .dict_id_flag = false } });
    defer without.deinit();
    try std.testing.expectEqual(@as(u32, 0), without.dictId());
}

test "the offset table must reach the code of the content size + 128 KB" {
    // content of 64 bytes: offsets up to 64 + 2^17 need code 17
    var buf: [2048]u8 = undefined;
    var counts: [256]u32 = undefined;
    for (&counts, 0..) |*c, i| c.* = 1 + @as(u32, @intCast(i % 7));
    var bs: frame.BlockState = .{};
    var n = try testDictionary(&buf, &counts, 255, 17, "0123456789abcdef" ** 4);
    _ = try loadCEntropy(&bs, buf[0..n]);
    try std.testing.expectEqual(sequences.FseRepeat.valid, bs.fse.of_repeat);
    n = try testDictionary(&buf, &counts, 255, 16, "0123456789abcdef" ** 4);
    _ = try loadCEntropy(&bs, buf[0..n]);
    try std.testing.expectEqual(sequences.FseRepeat.check, bs.fse.of_repeat);
}

test "repcodes must be nonzero and within the content" {
    var buf: [2048]u8 = undefined;
    var counts: [256]u32 = undefined;
    for (&counts, 0..) |*c, i| c.* = 1 + @as(u32, @intCast(i % 7));
    var bs: frame.BlockState = .{};
    const content = "0123456789abcdef";
    const n = try testDictionary(&buf, &counts, 255, sequences.max_off, content);
    const reps = n - content.len - 12;
    std.mem.writeInt(u32, buf[reps..][0..4], content.len, .little); // the whole content back: fine
    _ = try loadCEntropy(&bs, buf[0..n]);
    std.mem.writeInt(u32, buf[reps..][0..4], content.len + 1, .little);
    try std.testing.expectError(error.DictionaryCorrupted, loadCEntropy(&bs, buf[0..n]));
    std.mem.writeInt(u32, buf[reps + 8 ..][0..4], 0, .little);
    std.mem.writeInt(u32, buf[reps..][0..4], 1, .little);
    try std.testing.expectError(error.DictionaryCorrupted, loadCEntropy(&bs, buf[0..n]));
}

test "a Huffman header's zero weight is a symbol without a code" {
    var buf: [2048]u8 = undefined;
    var counts: [256]u32 = undefined;
    for (&counts, 0..) |*c, i| c.* = 1 + @as(u32, @intCast(i % 7));
    counts[200] = 0;
    const n = try testDictionary(&buf, &counts, 255, sequences.max_off, "0123456789abcdef");
    var ct: huf.CTable = .{};
    var zero = false;
    _ = try huf.readCTable(&ct, buf[8..n], &zero);
    try std.testing.expect(zero);
    try std.testing.expectEqual(@as(u8, 0), ct.elt[200].nb_bits);
    try std.testing.expect(ct.elt[199].nb_bits != 0);
}

test "the dedicated dictionary search's support and parameters are libzstd's" {
    var cp = params.getInternal(5, 0, 30000, .create_cdict);
    try std.testing.expect(ddsIsSupported(ddsGetCParams(5, 30000)));
    try std.testing.expectEqual(cp.hash_log + lazy.ddss_bucket_log, ddsGetCParams(5, 30000).hash_log);
    // a chain log above 24, or a hash log not above the chain log
    cp.strategy = .lazy2;
    cp.chain_log = 25;
    cp.hash_log = 26;
    try std.testing.expect(!ddsIsSupported(cp));
    cp.chain_log = 24;
    try std.testing.expect(ddsIsSupported(cp));
    cp.hash_log = 24;
    try std.testing.expect(!ddsIsSupported(cp));
    cp.hash_log = 25;
    cp.strategy = .btlazy2;
    try std.testing.expect(!ddsIsSupported(cp));
    cp.strategy = .dfast;
    try std.testing.expect(!ddsIsSupported(cp));
    // reverting never goes below the smallest hash log
    cp.strategy = .greedy;
    cp.hash_log = 7;
    ddsRevertCParams(&cp);
    try std.testing.expectEqual(@as(u32, params.hash_log_min), cp.hash_log);
    cp.hash_log = 20;
    ddsRevertCParams(&cp);
    try std.testing.expectEqual(@as(u32, 18), cp.hash_log);
    // fast, dfast and the binary trees keep theirs
    const fast = ddsGetCParams(1, 30000);
    try std.testing.expectEqual(params.getInternal(1, 0, 30000, .create_cdict).hash_log, fast.hash_log);
    var bt = ddsGetCParams(13, 30000);
    const bt_hash = bt.hash_log;
    ddsRevertCParams(&bt);
    try std.testing.expectEqual(bt_hash, bt.hash_log);
}
