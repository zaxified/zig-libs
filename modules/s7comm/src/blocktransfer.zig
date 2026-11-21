// SPDX-License-Identifier: MIT

//! Block upload and download (job functions `0x1A`-`0x1F`) and the `_INSE`
//! program-invocation service that activates a downloaded block: the pure
//! parameter and data codecs. The flows live in `client.zig` and `server.zig`.
//!
//! Layouts (all multi-octet fields big-endian):
//!
//! ```text
//! start upload  job   1D 00 00 00 <id:4> 09 <name:9>
//! start upload  ack   1D 00 01 00 <id:4> <n> <n ASCII digits: block length>
//! upload        job   1E 00 00 00 <id:4>
//! upload        ack   1E <status>            data: <len:2> 00 FB <payload>
//! end upload    job   1F 00 00 00 <id:4>      ack: 1F
//! request dl    job   1A 01 00 00 00 00 00 00 09 <name:9> 0D '1' <load:6> <mc7:6>
//! request dl    ack   1A
//! download blk  job   1B 00 00 00 <id:4> 09 <name:9>   (sent BY the CPU)
//! download blk  ack   1B <status>            data: <len:2> 00 FB <payload>
//! download end  job   1C 00 00 00 <id:4> 09 <name:9>   ack: 1C
//! insert        job   28 00 00 00 00 00 00 FD 00 0A 01 00 <name:8> 05 "_INSE"
//! ```
//!
//! `<name>` is `_` + `0` + the block type character (`A` for a DB, `8` OB,
//! ...) + five ASCII digits + the destination file system (`A` active, `P`
//! passive), e.g. `_0A00001P`. `<status>` bit 0 means "more data follows".
//! In a download the CPU is the one that asks for the data (job `1B`); the
//! client answers it with an Ack-Data.
//!
//! The layouts were checked with Wireshark's s7comm dissector (run as a
//! black box through `rawshark`, see SPEC "Block transfer"); the direction of
//! the download chunks and the status-bit polarity follow Snap7's behaviour as
//! described there. No CPU was available.

const std = @import("std");
const userdata = @import("userdata.zig");

pub const Error = error{
    /// A block-transfer parameter or data block of the wrong shape.
    BadBlockTransfer,
    /// The caller's output buffer is too small.
    BufferTooSmall,
};

pub const fn_start_upload: u8 = 0x1D;
pub const fn_upload: u8 = 0x1E;
pub const fn_end_upload: u8 = 0x1F;
pub const fn_request_download: u8 = 0x1A;
pub const fn_download_block: u8 = 0x1B;
pub const fn_download_ended: u8 = 0x1C;
pub const fn_pi_service: u8 = 0x28;

/// Wire length of a file name: `_0A00001P`.
pub const name_len: usize = 9;
/// Name of the program-invocation service that activates a downloaded block.
pub const insert_service = "_INSE";
/// Octets in front of the payload of a data chunk: length and `00 FB`.
pub const chunk_header_len: usize = 4;
/// Largest block length the six-digit length fields of a download request carry.
pub const max_download_len: u32 = 999_999;
/// Largest length a start-upload answer announces (seven digits).
pub const max_upload_len: u32 = 9_999_999;

pub const FileName = struct {
    block_type: userdata.BlockType,
    number: u16,
    /// `'A'` (active) or `'P'` (passive) file system.
    destination: u8 = 'P',
};

fn be16(b: []const u8) u16 {
    return (@as(u16, b[0]) << 8) | b[1];
}

fn be32(b: []const u8) u32 {
    return std.mem.readInt(u32, b[0..4], .big);
}

fn putDigits(out: []u8, v: u32) void {
    var x = v;
    var i = out.len;
    while (i > 0) {
        i -= 1;
        out[i] = '0' + @as(u8, @intCast(x % 10));
        x /= 10;
    }
}

fn readDigits(b: []const u8) Error!u32 {
    if (b.len == 0 or b.len > 9) return error.BadBlockTransfer;
    var n: u32 = 0;
    for (b) |c| {
        if (c < '0' or c > '9') return error.BadBlockTransfer;
        n = n * 10 + (c - '0');
    }
    return n;
}

/// `_0A00001P` without the leading underscore (what `_INSE` carries).
fn putNameBody(f: FileName, out: *[8]u8) void {
    out[0] = '0';
    out[1] = @backingInt(f.block_type);
    putDigits(out[2..7], f.number);
    out[7] = f.destination;
}

fn putName(f: FileName, out: *[name_len]u8) void {
    out[0] = '_';
    putNameBody(f, out[1..9]);
}

fn nameFromBody(b: []const u8) Error!FileName {
    if (b.len != 8 or b[0] != '0') return error.BadBlockTransfer;
    const n = try readDigits(b[2..7]);
    if (n > 0xFFFF) return error.BadBlockTransfer;
    return .{
        .block_type = @fromBackingInt(@intCast(b[1])),
        .number = @intCast(n),
        .destination = b[7],
    };
}

fn decodeName(b: []const u8) Error!FileName {
    if (b.len != name_len or b[0] != '_') return error.BadBlockTransfer;
    return nameFromBody(b[1..]);
}

// ── upload ──────────────────────────────────────────────────────────────────

pub const start_upload_request_len: usize = 18;

pub fn encodeStartUpload(name: FileName, out: []u8) Error![]u8 {
    if (out.len < start_upload_request_len) return error.BufferTooSmall;
    @memcpy(out[0..8], &[_]u8{ fn_start_upload, 0, 0, 0, 0, 0, 0, 0 });
    out[8] = name_len;
    putName(name, out[9..18]);
    return out[0..start_upload_request_len];
}

pub fn decodeStartUpload(params: []const u8) Error!FileName {
    if (params.len != start_upload_request_len or params[0] != fn_start_upload or params[8] != name_len)
        return error.BadBlockTransfer;
    return decodeName(params[9..18]);
}

pub const start_upload_reply_len: usize = 9 + 7;

/// The answer to a start-upload: the upload id and the block length.
pub fn encodeStartUploadReply(id: u32, length: u32, out: []u8) Error![]u8 {
    if (length > max_upload_len) return error.BadBlockTransfer;
    if (out.len < start_upload_reply_len) return error.BufferTooSmall;
    out[0] = fn_start_upload;
    out[1] = 0;
    out[2] = 1;
    out[3] = 0;
    std.mem.writeInt(u32, out[4..8], id, .big);
    out[8] = 7;
    putDigits(out[9..16], length);
    return out[0..start_upload_reply_len];
}

pub const StartUploadReply = struct { id: u32, length: u32 };

pub fn decodeStartUploadReply(params: []const u8) Error!StartUploadReply {
    if (params.len < 10 or params[0] != fn_start_upload) return error.BadBlockTransfer;
    const n: usize = params[8];
    if (n == 0 or params.len != 9 + n) return error.BadBlockTransfer;
    return .{ .id = be32(params[4..8]), .length = try readDigits(params[9..][0..n]) };
}

pub const id_job_len: usize = 8;

/// `1E`/`1F`/`1C`-style job carrying only an upload id.
pub fn encodeIdJob(function: u8, id: u32, out: []u8) Error![]u8 {
    if (out.len < id_job_len) return error.BufferTooSmall;
    out[0] = function;
    out[1] = 0;
    out[2] = 0;
    out[3] = 0;
    std.mem.writeInt(u32, out[4..8], id, .big);
    return out[0..id_job_len];
}

pub fn decodeIdJob(params: []const u8, function: u8) Error!u32 {
    if (params.len != id_job_len or params[0] != function) return error.BadBlockTransfer;
    return be32(params[4..8]);
}

/// Parameter block of an Ack-Data that carries a data chunk (`1E` or `1B`).
pub fn encodeChunkParams(function: u8, more: bool, out: []u8) Error![]u8 {
    if (out.len < 2) return error.BufferTooSmall;
    out[0] = function;
    out[1] = @intFromBool(more);
    return out[0..2];
}

/// The "more follows" bit of a chunk Ack-Data's parameter block.
pub fn decodeChunkParams(params: []const u8, function: u8) Error!bool {
    if (params.len != 2 or params[0] != function or params[1] > 1) return error.BadBlockTransfer;
    return params[1] == 1;
}

/// The four octets in front of a chunk's payload: length and `00 FB`.
pub fn chunkHeader(payload_len: u16) [chunk_header_len]u8 {
    return .{ @intCast(payload_len >> 8), @intCast(payload_len & 0xFF), 0x00, 0xFB };
}

/// Data block of a chunk: `<len:2> 00 FB <payload>`.
pub fn encodeChunk(payload: []const u8, out: []u8) Error![]u8 {
    if (payload.len > 0xFFFF) return error.BadBlockTransfer;
    if (out.len < chunk_header_len + payload.len) return error.BufferTooSmall;
    out[0..chunk_header_len].* = chunkHeader(@intCast(payload.len));
    @memcpy(out[chunk_header_len..][0..payload.len], payload);
    return out[0 .. chunk_header_len + payload.len];
}

pub fn decodeChunk(data: []const u8) Error![]const u8 {
    if (data.len < chunk_header_len or data[2] != 0x00 or data[3] != 0xFB) return error.BadBlockTransfer;
    if (@as(usize, be16(data[0..2])) != data.len - chunk_header_len) return error.BadBlockTransfer;
    return data[chunk_header_len..];
}

// ── download ────────────────────────────────────────────────────────────────

pub const request_download_len: usize = 32;

pub fn encodeRequestDownload(name: FileName, load_len: u32, mc7_len: u32, out: []u8) Error![]u8 {
    if (load_len > max_download_len or mc7_len > max_download_len) return error.BadBlockTransfer;
    if (out.len < request_download_len) return error.BufferTooSmall;
    @memcpy(out[0..8], &[_]u8{ fn_request_download, 1, 0, 0, 0, 0, 0, 0 });
    out[8] = name_len;
    putName(name, out[9..18]);
    out[18] = 0x0D;
    out[19] = '1';
    putDigits(out[20..26], load_len);
    putDigits(out[26..32], mc7_len);
    return out[0..request_download_len];
}

pub const RequestDownload = struct { name: FileName, load_len: u32, mc7_len: u32 };

pub fn decodeRequestDownload(params: []const u8) Error!RequestDownload {
    if (params.len != request_download_len or params[0] != fn_request_download or
        params[8] != name_len or params[18] != 0x0D or params[19] != '1') return error.BadBlockTransfer;
    return .{
        .name = try decodeName(params[9..18]),
        .load_len = try readDigits(params[20..26]),
        .mc7_len = try readDigits(params[26..32]),
    };
}

pub const block_job_len: usize = 18;

/// The CPU's `1B` (download block) job or the client's `1C` (download ended).
pub fn encodeBlockJob(function: u8, id: u32, name: FileName, out: []u8) Error![]u8 {
    if (out.len < block_job_len) return error.BufferTooSmall;
    _ = try encodeIdJob(function, id, out);
    out[8] = name_len;
    putName(name, out[9..18]);
    return out[0..block_job_len];
}

pub const BlockJob = struct { id: u32, name: FileName };

pub fn decodeBlockJob(params: []const u8, function: u8) Error!BlockJob {
    if (params.len != block_job_len or params[0] != function or params[8] != name_len)
        return error.BadBlockTransfer;
    return .{ .id = be32(params[4..8]), .name = try decodeName(params[9..18]) };
}

// ── insert (_INSE) ──────────────────────────────────────────────────────────

pub const insert_request_len: usize = 26;

pub fn encodeInsert(name: FileName, out: []u8) Error![]u8 {
    if (out.len < insert_request_len) return error.BufferTooSmall;
    @memcpy(out[0..7], &[_]u8{ fn_pi_service, 0, 0, 0, 0, 0, 0 });
    out[7] = 0xFD;
    out[8] = 0;
    out[9] = 10;
    out[10] = 1;
    out[11] = 0;
    putNameBody(name, out[12..20][0..8]);
    out[20] = insert_service.len;
    @memcpy(out[21..26], insert_service);
    return out[0..insert_request_len];
}

/// The service name of a program-invocation job (`_INSE`, `P_PROGRAM`, ...),
/// or null when the parameter block is not well formed.
pub fn piServiceName(params: []const u8) ?[]const u8 {
    if (params.len < 11 or params[0] != fn_pi_service) return null;
    const pos = 10 + @as(usize, be16(params[8..10]));
    if (pos >= params.len) return null;
    const n: usize = params[pos];
    if (pos + 1 + n != params.len) return null;
    return params[pos + 1 ..][0..n];
}

/// The block an `_INSE` job names.
pub fn decodeInsert(params: []const u8) Error!FileName {
    const svc = piServiceName(params) orelse return error.BadBlockTransfer;
    if (!std.mem.eql(u8, svc, insert_service)) return error.BadBlockTransfer;
    const arg_len = be16(params[8..10]);
    if (arg_len != 10 or params[10] != 1 or params[11] != 0) return error.BadBlockTransfer;
    return nameFromBody(params[12..20]);
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn hexBuf(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const db1 = FileName{ .block_type = .db, .number = 1, .destination = 'A' };

test "start upload request: bytes as the Wireshark s7comm dissector decodes them" {
    var buf: [32]u8 = undefined;
    const got = try encodeStartUpload(db1, &buf);
    try testing.expectEqualSlices(u8, &hexBuf("1d000000" ++ "00000000" ++ "09" ++ "5f30413030303031" ++ "41"), got);
    try testing.expectEqual(db1, try decodeStartUpload(got));
}

test "start upload reply carries the id and the length" {
    var buf: [32]u8 = undefined;
    const got = try encodeStartUploadReply(1, 234, &buf);
    try testing.expectEqualSlices(u8, &hexBuf("1d000100" ++ "00000001" ++ "07" ++ "30303030323334"), got);
    const r = try decodeStartUploadReply(got);
    try testing.expectEqual(@as(u32, 1), r.id);
    try testing.expectEqual(@as(u32, 234), r.length);
    try testing.expectError(error.BadBlockTransfer, encodeStartUploadReply(1, max_upload_len + 1, &buf));
    try testing.expectError(error.BadBlockTransfer, decodeStartUploadReply(got[0 .. got.len - 1]));
}

test "id jobs and chunk blocks round-trip, and refuse every damaged shape" {
    var buf: [64]u8 = undefined;
    const j = try encodeIdJob(fn_upload, 7, &buf);
    try testing.expectEqualSlices(u8, &hexBuf("1e00000000000007"), j);
    try testing.expectEqual(@as(u32, 7), try decodeIdJob(j, fn_upload));
    try testing.expectError(error.BadBlockTransfer, decodeIdJob(j, fn_end_upload));
    try testing.expectError(error.BadBlockTransfer, decodeIdJob(j[0..7], fn_upload));

    const c = try encodeChunk("abc", &buf);
    try testing.expectEqualSlices(u8, &hexBuf("000300fb616263"), c);
    try testing.expectEqualSlices(u8, "abc", try decodeChunk(c));
    try testing.expectError(error.BadBlockTransfer, decodeChunk(c[0 .. c.len - 1]));
    var bad = hexBuf("000300fa616263");
    try testing.expectError(error.BadBlockTransfer, decodeChunk(&bad));
    try testing.expectError(error.BufferTooSmall, encodeChunk("abc", buf[0..6]));

    try testing.expectEqual(true, try decodeChunkParams(try encodeChunkParams(fn_upload, true, &buf), fn_upload));
    try testing.expectEqual(false, try decodeChunkParams(try encodeChunkParams(fn_upload, false, &buf), fn_upload));
    try testing.expectError(error.BadBlockTransfer, decodeChunkParams(&hexBuf("1e02"), fn_upload));
}

test "request download: bytes as the dissector decodes them (type, number, destination, lengths)" {
    var buf: [40]u8 = undefined;
    const nm = FileName{ .block_type = .db, .number = 1, .destination = 'P' };
    const got = try encodeRequestDownload(nm, 240, 100, &buf);
    try testing.expectEqualSlices(
        u8,
        &hexBuf("1a010000" ++ "00000000" ++ "09" ++ "5f3041303030303150" ++ "0d" ++ "31" ++ "303030323430" ++ "303030313030"),
        got,
    );
    const r = try decodeRequestDownload(got);
    try testing.expectEqual(nm, r.name);
    try testing.expectEqual(@as(u32, 240), r.load_len);
    try testing.expectEqual(@as(u32, 100), r.mc7_len);
    try testing.expectError(error.BadBlockTransfer, encodeRequestDownload(nm, max_download_len + 1, 0, &buf));
    var damaged: [32]u8 = got[0..32].*;
    damaged[19] = '2';
    try testing.expectError(error.BadBlockTransfer, decodeRequestDownload(&damaged));
    damaged = got[0..32].*;
    damaged[22] = 'x';
    try testing.expectError(error.BadBlockTransfer, decodeRequestDownload(&damaged));
}

test "block jobs and _INSE" {
    var buf: [40]u8 = undefined;
    const nm = FileName{ .block_type = .fc, .number = 12, .destination = 'P' };
    const j = try encodeBlockJob(fn_download_block, 1, nm, &buf);
    try testing.expectEqualSlices(u8, &hexBuf("1b000000" ++ "00000001" ++ "09" ++ "5f3043303030313250"), j);
    const d = try decodeBlockJob(j, fn_download_block);
    try testing.expectEqual(nm, d.name);
    try testing.expectError(error.BadBlockTransfer, decodeBlockJob(j, fn_download_ended));

    var ib: [40]u8 = undefined;
    const ins = try encodeInsert(nm, &ib);
    try testing.expectEqualSlices(
        u8,
        &hexBuf("28000000" ++ "000000fd" ++ "000a" ++ "0100" ++ "3043303030313250" ++ "05" ++ "5f494e5345"),
        ins,
    );
    try testing.expectEqualStrings("_INSE", piServiceName(ins).?);
    try testing.expectEqual(nm, try decodeInsert(ins));
    try testing.expectError(error.BadBlockTransfer, decodeInsert(ins[0 .. ins.len - 1]));
    // The hot/cold restart shapes are not an insert.
    try testing.expect(piServiceName(&hexBuf("28000000000000fd0000" ++ "09" ++ "505f50524f4752414d")).?.len == 9);
    try testing.expectError(error.BadBlockTransfer, decodeInsert(&hexBuf("28000000000000fd0000" ++ "09" ++ "505f50524f4752414d")));
}

test "file names: unknown type characters and numbers past 16 bits are refused" {
    try testing.expectError(error.BadBlockTransfer, decodeName("_1A00001A"));
    try testing.expectError(error.BadBlockTransfer, decodeName("_0A70000A"));
    try testing.expectError(error.BadBlockTransfer, decodeName("_0Ax0001A"));
    try testing.expectError(error.BadBlockTransfer, decodeName("0A00001AA"));
    try testing.expectEqual(@as(u16, 65535), (try decodeName("_0A65535A")).number);
}
