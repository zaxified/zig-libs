// SPDX-License-Identifier: MIT
//! `Content-Encoding: dcb` (RFC 9842 §4, "Dictionary-Compressed Brotli"): a
//! 36-byte header — the magic `ff 44 43 42` and the SHA-256 of the dictionary
//! — then a Brotli stream compressed against that dictionary as a raw prefix
//! dictionary (RFC 9841 §3.2), with a window of at most 16 MiB (any stream
//! this module writes: WBITS ≤ 24).
//!
//! The dictionary itself is negotiated over HTTP (`Use-As-Dictionary`,
//! `Available-Dictionary`), which is the caller's business; here are the
//! body's two directions. A streamed body is `header(dict)` written first,
//! then a `StreamWriter` with `.dictionary = dict`.

const std = @import("std");
const encoder = @import("encoder.zig");
const decoder = @import("decoder.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const magic = [4]u8{ 0xff, 0x44, 0x43, 0x42 };
pub const header_len = magic.len + Sha256.digest_length;

pub const Error = decoder.BrotliError || error{
    /// Not a `dcb` body: shorter than the header, or another magic.
    NotDcb,
    /// The body was compressed against another dictionary (the header's
    /// SHA-256 is not the given dictionary's).
    DictionaryMismatch,
};

/// The header a body compressed against `dict` starts with.
pub fn header(dict: []const u8) [header_len]u8 {
    var h: [header_len]u8 = undefined;
    h[0..magic.len].* = magic;
    Sha256.hash(dict, h[magic.len..], .{});
    return h;
}

/// The Brotli stream after `body`'s header, once the header names `dict`.
pub fn stream(body: []const u8, dict: []const u8) Error![]const u8 {
    if (body.len < header_len or !std.mem.eql(u8, body[0..magic.len], &magic)) return error.NotDcb;
    const want = header(dict);
    // Not a secret: a plain comparison.
    if (!std.mem.eql(u8, body[magic.len..header_len], want[magic.len..])) return error.DictionaryMismatch;
    return body[header_len..];
}

/// `input` as a `dcb` body against `dict` (`opts.dictionary` is set to it).
/// Caller owns the result.
pub fn compress(gpa: std.mem.Allocator, input: []const u8, dict: []const u8, opts: encoder.CompressOptions) std.mem.Allocator.Error![]u8 {
    var o = opts;
    o.dictionary = dict;
    const br = try encoder.compressWith(gpa, input, o);
    defer gpa.free(br);
    const out = try gpa.alloc(u8, header_len + br.len);
    out[0..header_len].* = header(dict);
    @memcpy(out[header_len..], br);
    return out;
}

/// A `dcb` body back to its content, against `dict` (`options.dictionary`
/// is set to it). Caller owns the result.
pub fn decompress(gpa: std.mem.Allocator, body: []const u8, dict: []const u8, options: decoder.Options) Error![]u8 {
    var o = options;
    o.dictionary = dict;
    return decoder.decompress(gpa, try stream(body, dict), o);
}

const testing = std.testing;

test "dcb: round trip; the header names the dictionary" {
    const gpa = testing.allocator;
    const dict = "<html><head><script src=app.v1.js></script></head><body>hello, version one</body></html>";
    const page = "<html><head><script src=app.v2.js></script></head><body>hello, version two</body></html>";
    const body = try compress(gpa, page, dict, .{});
    defer gpa.free(body);
    try testing.expectEqualSlices(u8, &magic, body[0..4]);
    var sha: [32]u8 = undefined;
    Sha256.hash(dict, &sha, .{});
    try testing.expectEqualSlices(u8, &sha, body[4..36]);
    const back = try decompress(gpa, body, dict, .{});
    defer gpa.free(back);
    try testing.expectEqualStrings(page, back);
    // The dictionary paid: shorter than the header plus a plain stream.
    const plain = try encoder.compress(gpa, page);
    defer gpa.free(plain);
    try testing.expect(body.len - header_len < plain.len);
}

test "dcb: another dictionary, another magic, a short body" {
    const gpa = testing.allocator;
    const body = try compress(gpa, "content", "dictionary one", .{});
    defer gpa.free(body);
    try testing.expectError(error.DictionaryMismatch, decompress(gpa, body, "dictionary two", .{}));
    var bad = try gpa.dupe(u8, body);
    defer gpa.free(bad);
    bad[3] ^= 1;
    try testing.expectError(error.NotDcb, decompress(gpa, bad, "dictionary one", .{}));
    try testing.expectError(error.NotDcb, decompress(gpa, body[0 .. header_len - 1], "dictionary one", .{}));
    // Header alone: the stream is empty, which is truncated input.
    try testing.expectError(error.TruncatedInput, decompress(gpa, body[0..header_len], "dictionary one", .{}));
}
