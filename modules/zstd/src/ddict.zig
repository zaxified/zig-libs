// SPDX-License-Identifier: BSD-3-Clause AND MIT (port of libzstd 1.5.7 -- see ../NOTICE)
//! Digested dictionaries for the decoder: a dictionary's entropy tables
//! read once (`ZSTD_loadDEntropy`) and reused across frames.
//!
//! Port of lib/decompress/zstd_ddict.c and the `ZSTD_loadDEntropy` /
//! `ZSTD_getDictID_from*` parts of lib/decompress/zstd_decompress.c
//! (v1.5.7).
//!
//! libzstd treats a dictionary's *whole* buffer -- the magic number,
//! dictionary ID and entropy tables included, when present -- as reachable
//! match history once it is digested into a `ZSTD_DDict`
//! (`ZSTD_copyDDictParameters` sets `prefixStart`/`dictEnd` from
//! `ddict->dictContent`/`dictSize`, unmodified). Only the separate,
//! undigested one-shot path (`ZSTD_decompress_usingDict`, this port's
//! `Decompressor.decompress` with `Options.dictionary` raw bytes) strips
//! the entropy header first (`ZSTD_decompress_insertDictionary`): its
//! history is the content bytes *after* `loadDEntropy`'s return value.
//! Both are ported faithfully; see decompress.zig and SPEC.md, §
//! Dictionaries.

const std = @import("std");
const dbits = @import("dbits.zig");
const huf = @import("huf_dec.zig");
const dblock = @import("dblock.zig");
const seqs = @import("sequences.zig");
const cdict_mod = @import("cdict.zig");
const readLE32 = dbits.readLE32;

/// `ZSTD_MAGIC_DICTIONARY`.
pub const magic_dictionary: u32 = 0xEC30A437;
/// `ZSTD_FRAMEIDSIZE`.
const frame_id_size = 4;

pub const Error = error{DictionaryCorrupted};

/// `ZSTD_dictContentType_e`. One enum shared with the compressor
/// (`cdict.ContentType`, same libzstd type): rebased alongside the
/// encoder-side dictionary work (Z4/D0), which defined it first, so this
/// module reuses that definition instead of a second copy of the same
/// three tags.
pub const DictContentType = cdict_mod.ContentType;

/// The part of `ZSTD_entropyDTables_t` the decoder needs: the Huffman
/// table, the three FSE tables and the three repeat offsets.
pub const Entropy = struct {
    huf: huf.DTable = .{},
    ll: dblock.SeqTable = .{},
    of: dblock.SeqTable = .{},
    ml: dblock.SeqTable = .{},
    rep: [3]u32 = .{ 1, 4, 8 },
};

/// A digested dictionary (`ZSTD_DDict`): its content (by copy or by
/// reference) and, for a zstd-format dictionary, the entropy tables read
/// from it once.
pub const DDict = struct {
    /// The whole dictionary buffer, as given to `init`/`initByReference`
    /// -- reachable as history in full, header included (see above).
    content: []const u8,
    /// Set when `content` is an owned copy (`init`), freed by `deinit`.
    owned: bool = false,
    /// `ZSTD_getDictID_fromDDict`: 0 for a raw-content dictionary or one
    /// too short / without the magic number.
    dict_id: u32 = 0,
    entropy_present: bool = false,
    entropy: Entropy = .{},

    /// `ZSTD_createDDict_advanced` with `ZSTD_dlm_byCopy`: copies `dict`.
    pub fn init(gpa: std.mem.Allocator, dict: []const u8, content_type: DictContentType) (error{OutOfMemory} || Error)!DDict {
        const buf = try gpa.dupe(u8, dict);
        errdefer gpa.free(buf);
        var d: DDict = .{ .content = buf, .owned = true };
        try d.loadEntropy(content_type);
        return d;
    }

    /// `ZSTD_createDDict_advanced` with `ZSTD_dlm_byRef`: `dict` must
    /// outlive the `DDict`.
    pub fn initByReference(dict: []const u8, content_type: DictContentType) Error!DDict {
        var d: DDict = .{ .content = dict };
        try d.loadEntropy(content_type);
        return d;
    }

    pub fn deinit(d: *DDict, gpa: std.mem.Allocator) void {
        if (d.owned) gpa.free(@constCast(d.content));
        d.* = undefined;
    }

    /// `ZSTD_getDictID_fromDDict`.
    pub fn dictId(d: *const DDict) u32 {
        return d.dict_id;
    }

    /// `ZSTD_loadEntropy_intoDDict`.
    fn loadEntropy(d: *DDict, content_type: DictContentType) Error!void {
        d.dict_id = 0;
        d.entropy_present = false;
        if (content_type == .raw_content) return;
        if (d.content.len < 8) {
            if (content_type == .full) return error.DictionaryCorrupted;
            return; // pure content mode
        }
        if (readLE32(d.content, 0) != magic_dictionary) {
            if (content_type == .full) return error.DictionaryCorrupted;
            return; // pure content mode
        }
        d.dict_id = readLE32(d.content, frame_id_size);
        _ = loadDEntropy(&d.entropy, d.content) catch return error.DictionaryCorrupted;
        d.entropy_present = true;
    }
};

/// `ZSTD_getDictID_fromDict`: 0 when `dict` is not a conformant zstd
/// dictionary (too short, or missing the magic number) -- it can still be
/// loaded, as a content-only dictionary.
pub fn getDictId(dict: []const u8) u32 {
    if (dict.len < 8) return 0;
    if (readLE32(dict, 0) != magic_dictionary) return 0;
    return readLE32(dict, frame_id_size);
}

/// `ZSTD_buildFSETable` wrapper for one of `loadDEntropy`'s three tables:
/// reads the normalized counts (`FSE_readNCount`) then builds the table.
/// Returns the header bytes consumed.
fn readEntropyFse(space: *dblock.SeqTable, src: []const u8, max_sv_declared: u32, max_log: u32, base: []const u32, nb_add: []const u8) Error!usize {
    var norm: [dblock.max_ml + 1]i16 = undefined;
    var max_sv = max_sv_declared;
    var table_log: u32 = undefined;
    const header_size = dbits.readNCount(&norm, &max_sv, &table_log, src) catch return error.DictionaryCorrupted;
    if (max_sv > max_sv_declared) return error.DictionaryCorrupted;
    if (table_log > max_log) return error.DictionaryCorrupted;
    dblock.buildFseTable(space, &norm, max_sv, base, nb_add, table_log);
    return header_size;
}

/// `ZSTD_loadDEntropy`: `dict` must start at the dictionary's magic
/// number (`ZSTD_MAGIC_DICTIONARY`) and hold more than 8 bytes. Reads the
/// Huffman table (X2, as libzstd's default, non-`HUF_FORCE_DECOMPRESS_X1`
/// build), the offset/match-length/literal-length FSE tables in that
/// order, and the three repeat offsets, validating each repeat offset
/// against the dictionary content size that follows. Returns the bytes
/// consumed (header through the repeat offsets); the rest of `dict` is
/// its content.
pub fn loadDEntropy(entropy: *Entropy, dict: []const u8) Error!usize {
    if (dict.len <= 8) return error.DictionaryCorrupted;
    var pos: usize = 8; // magic (4) + dictID (4)

    pos += huf.readDTableX2(&entropy.huf, dict[pos..]) catch return error.DictionaryCorrupted;
    if (pos > dict.len) return error.DictionaryCorrupted;

    pos += try readEntropyFse(&entropy.of, dict[pos..], dblock.max_off, dblock.off_fse_log, &dblock.of_base, &dblock.of_bits);
    if (pos > dict.len) return error.DictionaryCorrupted;
    pos += try readEntropyFse(&entropy.ml, dict[pos..], dblock.max_ml, dblock.ml_fse_log, &dblock.ml_base, &seqs.ml_bits);
    if (pos > dict.len) return error.DictionaryCorrupted;
    pos += try readEntropyFse(&entropy.ll, dict[pos..], dblock.max_ll, dblock.ll_fse_log, &dblock.ll_base, &seqs.ll_bits);
    if (pos > dict.len) return error.DictionaryCorrupted;

    if (pos + 12 > dict.len) return error.DictionaryCorrupted;
    const content_size = dict.len - (pos + 12);
    for (0..3) |i| {
        const rep = readLE32(dict, pos);
        pos += 4;
        if (rep == 0 or rep > content_size) return error.DictionaryCorrupted;
        entropy.rep[i] = rep;
    }
    return pos;
}
