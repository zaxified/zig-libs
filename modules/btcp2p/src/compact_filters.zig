// SPDX-License-Identifier: MIT
//! The six BIP157 compact-block-filter messages a light client and a
//! `-peerblockfilters` node exchange: `getcfilters` / `cfilter`,
//! `getcfheaders` / `cfheaders` and `getcfcheckpt` / `cfcheckpt`. They are
//! fixed fields plus lists of 32-byte hashes; the filter itself (`cfilter`'s
//! `filter` bytes, a BIP158 Golomb-coded set) is carried opaque, and the BIP157
//! header chain helpers `filterHash` / `filterHeader` are provided here.
//!
//! Filter type 0 is the BIP158 "basic" filter (`FILTER_TYPE_BASIC`); other
//! types are carried through unchanged. Bitcoin Core serves at most
//! `MAX_GETCFILTERS` filters per `getcfilters` and `MAX_GETCFHEADERS` headers
//! per `getcfheaders`; those constants are for the caller to check against
//! `stop_height - start_height` (the codec does not know block heights).
//!
//! Decoded `filter` bytes borrow the caller's input; the hash lists are
//! allocated.

const std = @import("std");
const Allocator = std.mem.Allocator;
const bitcointx = @import("bitcointx");
const message = @import("message.zig");
const Reader = message.Reader;
const Writer = message.Writer;

/// Command names, as `envelope.encodeMessage` takes them.
pub const command = struct {
    pub const getcfilters = "getcfilters";
    pub const cfilter = "cfilter";
    pub const getcfheaders = "getcfheaders";
    pub const cfheaders = "cfheaders";
    pub const getcfcheckpt = "getcfcheckpt";
    pub const cfcheckpt = "cfcheckpt";
};

/// BIP158's basic filter type.
pub const FILTER_TYPE_BASIC: u8 = 0;
/// Core's per-request limits (`MAX_GETCFILTERS_SIZE`, `MAX_GETCFHEADERS_SIZE`).
pub const MAX_GETCFILTERS: u32 = 1000;
pub const MAX_GETCFHEADERS: u32 = 2000;

pub const DecodeError = message.ReadError || message.CompactSizeError || error{ TooManyItems, UnexpectedPayload };

/// `getcfilters` and `getcfheaders` share one payload:
/// `filter_type(1) || start_height(4, LE) || stop_hash(32)`.
pub const FilterRange = struct {
    filter_type: u8,
    start_height: u32,
    stop_hash: [32]u8,
};

pub fn decodeFilterRange(bytes: []const u8) DecodeError!FilterRange {
    var r: Reader = .{ .bytes = bytes };
    const v: FilterRange = .{ .filter_type = try r.byte(), .start_height = try r.u32le(), .stop_hash = try r.takeArray(32) };
    if (r.remaining() != 0) return error.UnexpectedPayload;
    return v;
}

pub fn serializeFilterRange(allocator: Allocator, v: FilterRange) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU8(allocator, v.filter_type);
    try w.putU32le(allocator, v.start_height);
    try w.putBytes(allocator, &v.stop_hash);
    return w.toOwned(allocator);
}

pub const GetCFilters = FilterRange;
pub const GetCFHeaders = FilterRange;
pub const decodeGetCFilters = decodeFilterRange;
pub const serializeGetCFilters = serializeFilterRange;
pub const decodeGetCFHeaders = decodeFilterRange;
pub const serializeGetCFHeaders = serializeFilterRange;

/// `getcfcheckpt`: `filter_type(1) || stop_hash(32)`.
pub const GetCFCheckpt = struct {
    filter_type: u8,
    stop_hash: [32]u8,
};

pub fn decodeGetCFCheckpt(bytes: []const u8) DecodeError!GetCFCheckpt {
    var r: Reader = .{ .bytes = bytes };
    const v: GetCFCheckpt = .{ .filter_type = try r.byte(), .stop_hash = try r.takeArray(32) };
    if (r.remaining() != 0) return error.UnexpectedPayload;
    return v;
}

pub fn serializeGetCFCheckpt(allocator: Allocator, v: GetCFCheckpt) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU8(allocator, v.filter_type);
    try w.putBytes(allocator, &v.stop_hash);
    return w.toOwned(allocator);
}

/// `cfilter`: `filter_type(1) || block_hash(32) || filter(var_bytes)`.
pub const CFilter = struct {
    filter_type: u8,
    block_hash: [32]u8,
    /// The BIP158 filter, borrowed from the input.
    filter: []const u8,
};

pub fn decodeCFilter(bytes: []const u8) DecodeError!CFilter {
    var r: Reader = .{ .bytes = bytes };
    const v: CFilter = .{ .filter_type = try r.byte(), .block_hash = try r.takeArray(32), .filter = try r.varBytes() };
    if (r.remaining() != 0) return error.UnexpectedPayload;
    return v;
}

pub fn serializeCFilter(allocator: Allocator, v: CFilter) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU8(allocator, v.filter_type);
    try w.putBytes(allocator, &v.block_hash);
    try w.putVarBytes(allocator, v.filter);
    return w.toOwned(allocator);
}

fn decodeHashes(allocator: Allocator, r: *Reader) (DecodeError || Allocator.Error)![][32]u8 {
    const count = try r.compactSize();
    if (count > r.remaining() / 32) return error.TooManyItems;
    const n: usize = @intCast(count);
    const out = try allocator.alloc([32]u8, n);
    errdefer allocator.free(out);
    for (out) |*h| h.* = try r.takeArray(32);
    return out;
}

/// `cfheaders`: `filter_type(1) || stop_hash(32) || previous_filter_header(32)
/// || filter_hashes(CompactSize count, 32 each)`.
pub const CFHeaders = struct {
    filter_type: u8,
    stop_hash: [32]u8,
    previous_filter_header: [32]u8,
    filter_hashes: [][32]u8,

    pub fn deinit(self: *CFHeaders, allocator: Allocator) void {
        allocator.free(self.filter_hashes);
        self.filter_hashes = &.{};
    }
};

pub fn decodeCFHeaders(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!CFHeaders {
    var r: Reader = .{ .bytes = bytes };
    const ft = try r.byte();
    const stop = try r.takeArray(32);
    const prev = try r.takeArray(32);
    const hashes = try decodeHashes(allocator, &r);
    errdefer allocator.free(hashes);
    if (r.remaining() != 0) return error.UnexpectedPayload;
    return .{ .filter_type = ft, .stop_hash = stop, .previous_filter_header = prev, .filter_hashes = hashes };
}

pub fn serializeCFHeaders(allocator: Allocator, v: CFHeaders) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU8(allocator, v.filter_type);
    try w.putBytes(allocator, &v.stop_hash);
    try w.putBytes(allocator, &v.previous_filter_header);
    try w.putCompactSize(allocator, v.filter_hashes.len);
    for (v.filter_hashes) |h| try w.putBytes(allocator, &h);
    return w.toOwned(allocator);
}

/// `cfcheckpt`: `filter_type(1) || stop_hash(32) || filter_headers(CompactSize
/// count, 32 each)`: the filter header of every 1000th block up to `stop_hash`.
pub const CFCheckpt = struct {
    filter_type: u8,
    stop_hash: [32]u8,
    filter_headers: [][32]u8,

    pub fn deinit(self: *CFCheckpt, allocator: Allocator) void {
        allocator.free(self.filter_headers);
        self.filter_headers = &.{};
    }
};

pub fn decodeCFCheckpt(allocator: Allocator, bytes: []const u8) (DecodeError || Allocator.Error)!CFCheckpt {
    var r: Reader = .{ .bytes = bytes };
    const ft = try r.byte();
    const stop = try r.takeArray(32);
    const hashes = try decodeHashes(allocator, &r);
    errdefer allocator.free(hashes);
    if (r.remaining() != 0) return error.UnexpectedPayload;
    return .{ .filter_type = ft, .stop_hash = stop, .filter_headers = hashes };
}

pub fn serializeCFCheckpt(allocator: Allocator, v: CFCheckpt) Allocator.Error![]u8 {
    var w: Writer = .{};
    defer w.deinit(allocator);
    try w.putU8(allocator, v.filter_type);
    try w.putBytes(allocator, &v.stop_hash);
    try w.putCompactSize(allocator, v.filter_headers.len);
    for (v.filter_headers) |h| try w.putBytes(allocator, &h);
    return w.toOwned(allocator);
}

/// BIP157: a filter's hash is the double SHA-256 of its serialization (the
/// bytes of `CFilter.filter`, including the leading CompactSize element count).
pub fn filterHash(filter: []const u8) [32]u8 {
    return bitcointx.hash256.sha256d(filter);
}

/// BIP157: `filter_header = sha256d(filter_hash || previous_filter_header)`;
/// the header of the genesis block's filter chains from 32 zero octets.
pub fn filterHeader(filter_hash: [32]u8, previous_header: [32]u8) [32]u8 {
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..32], &filter_hash);
    @memcpy(buf[32..64], &previous_header);
    return bitcointx.hash256.sha256d(&buf);
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

test "getcfilters / getcfheaders: 37 octets, start height little-endian" {
    const a = testing.allocator;
    const stop: [32]u8 = @splat(0xab);
    const bytes = try serializeFilterRange(a, .{ .filter_type = 0, .start_height = 0x01020304, .stop_hash = stop });
    defer a.free(bytes);
    try testing.expectEqual(@as(usize, 37), bytes.len);
    try testing.expectEqualSlices(u8, &.{ 0, 4, 3, 2, 1 }, bytes[0..5]);
    const v = try decodeGetCFilters(bytes);
    try testing.expectEqual(@as(u32, 0x01020304), v.start_height);
    try testing.expectEqual(stop, v.stop_hash);
    try testing.expectError(error.Truncated, decodeGetCFHeaders(bytes[0..36]));
    const longer = try std.mem.concat(a, u8, &.{ bytes, &.{0} });
    defer a.free(longer);
    try testing.expectError(error.UnexpectedPayload, decodeGetCFHeaders(longer));
}

test "getcfcheckpt and cfilter round trip, trailing bytes refused" {
    const a = testing.allocator;
    const h: [32]u8 = @splat(7);
    const b1 = try serializeGetCFCheckpt(a, .{ .filter_type = 0, .stop_hash = h });
    defer a.free(b1);
    try testing.expectEqual(@as(usize, 33), b1.len);
    try testing.expectEqual(h, (try decodeGetCFCheckpt(b1)).stop_hash);
    const filt = [_]u8{ 3, 0xde, 0xad, 0xbe, 0xef };
    const b2 = try serializeCFilter(a, .{ .filter_type = 0, .block_hash = h, .filter = &filt });
    defer a.free(b2);
    try testing.expectEqual(@as(u8, 5), b2[33]); // var_bytes length
    const c = try decodeCFilter(b2);
    try testing.expectEqualSlices(u8, &filt, c.filter);
    try testing.expectError(error.Truncated, decodeCFilter(b2[0 .. b2.len - 1]));
    const longer = try std.mem.concat(a, u8, &.{ b2, &.{0} });
    defer a.free(longer);
    try testing.expectError(error.UnexpectedPayload, decodeCFilter(longer));
}

test "cfheaders and cfcheckpt: hash lists, bounds, round trip" {
    const a = testing.allocator;
    var hashes = [_][32]u8{ @splat(1), @splat(2), @splat(3) };
    const bytes = try serializeCFHeaders(a, .{ .filter_type = 0, .stop_hash = @splat(9), .previous_filter_header = @splat(8), .filter_hashes = &hashes });
    defer a.free(bytes);
    try testing.expectEqual(@as(usize, 1 + 32 + 32 + 1 + 96), bytes.len);
    var d = try decodeCFHeaders(a, bytes);
    defer d.deinit(a);
    try testing.expectEqual(@as(usize, 3), d.filter_hashes.len);
    try testing.expectEqual(@as([32]u8, @splat(8)), d.previous_filter_header);
    try testing.expectEqual(@as([32]u8, @splat(3)), d.filter_hashes[2]);
    // A count the bytes cannot hold.
    const lie = try std.mem.concat(a, u8, &.{ bytes[0..65], &.{ 200, 1, 2 } });
    defer a.free(lie);
    try testing.expectError(error.TooManyItems, decodeCFHeaders(a, lie));
    const longer = try std.mem.concat(a, u8, &.{ bytes, &.{0} });
    defer a.free(longer);
    try testing.expectError(error.UnexpectedPayload, decodeCFHeaders(a, longer));
    const cp = try serializeCFCheckpt(a, .{ .filter_type = 0, .stop_hash = @splat(5), .filter_headers = &hashes });
    defer a.free(cp);
    var cd = try decodeCFCheckpt(a, cp);
    defer cd.deinit(a);
    try testing.expectEqual(@as(usize, 3), cd.filter_headers.len);
    const none = try std.mem.concat(a, u8, &.{ cp[0..33], &.{0} });
    defer a.free(none);
    var empty = try decodeCFCheckpt(a, none);
    defer empty.deinit(a);
    try testing.expectEqual(@as(usize, 0), empty.filter_headers.len);
}

test "BIP157 header chain: genesis filter header from 32 zero octets" {
    // The filter of an empty element set is one octet, 0x00 (a zero count).
    const fh = filterHash(&.{0});
    const h0 = filterHeader(fh, @splat(0));
    var buf: [64]u8 = undefined;
    @memcpy(buf[0..32], &fh);
    @memset(buf[32..], 0);
    try testing.expectEqual(bitcointx.hash256.sha256d(&buf), h0);
    try testing.expect(!std.mem.eql(u8, &h0, &fh));
}
