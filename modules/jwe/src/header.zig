// SPDX-License-Identifier: MIT

//! jwe.header — the JWE Protected Header (RFC 7516 §4): build it for
//! `encryptCompact` and parse it for `decryptCompact`. Pure wire-format code,
//! no crypto — `std.json` for the object, `std.base64.url_safe_no_pad` for
//! the byte-carrying members (`iv`/`tag`/`p2s`).
//!
//! `zip` (Compression Algorithm, RFC 7516 §4.1.3) is REJECTED whenever
//! present, encode or decode: this module implements no decompression, and
//! "decrypt untrusted ciphertext, then decompress the result" is exactly the
//! shape of a compression/zip-bomb amplification attack (also the CRIME/BREACH
//! family's root cause when compression crosses a trust boundary) — refusing
//! it outright is cheaper and safer than bounding it. See SPEC.md.

const std = @import("std");
const b64 = std.base64.url_safe_no_pad;

const root = @import("root.zig");
const Alg = root.Alg;
const Enc = root.Enc;

/// Conservative cap on the ENCODED (base64url) header segment length this
/// module will parse. Bounds the allocation a decrypt call performs on
/// attacker-controlled input before any crypto has run — part of the
/// "don't let untrusted framing dictate unbounded work" posture (see
/// SPEC.md threat model). 16 KiB is generous for every legitimate header
/// this module writes (a few dozen bytes) plus a large `kid`/`cty`.
pub const max_header_b64_len: usize = 16 * 1024;

/// Largest JOSE header this module's own `encode` will produce. Callers
/// supply `kid`/`cty`; oversized values fail closed with
/// `error.BufferTooSmall` rather than truncating.
pub const max_header_json_len: usize = 2048;

/// Largest base64url-decoded value for `iv`/`tag`/`p2s` this module accepts.
/// GCM tags/IVs are tiny (<=16B); PBES2 salts are conventionally 8-64B. A
/// generous ceiling still bounds decode-side allocation.
pub const max_member_len: usize = 128;

pub const ParseError = error{
    OutOfMemory,
    /// Not valid base64url-without-padding.
    InvalidBase64,
    /// Not valid JSON.
    InvalidJson,
    /// Valid JSON but not an object.
    NotAnObject,
    /// `alg` is absent or not a string (REQUIRED, RFC 7516 §4.1.1).
    MissingAlg,
    /// `enc` is absent or not a string (REQUIRED, RFC 7516 §4.1.2).
    MissingEnc,
    /// `zip` is present — always rejected (see module doc comment).
    UnsupportedZip,
    /// A known member has the wrong JSON type, or a base64 member decodes
    /// to more than `max_member_len` bytes.
    InvalidHeaderField,
};

/// The subset of RFC 7516 §4.1 / RFC 7518 §4.7/§4.8 header parameters this
/// module understands. Slices/decoded bytes are owned by the caller's arena
/// (see `parse`).
pub const Parsed = struct {
    alg: Alg,
    enc: Enc,
    kid: ?[]const u8 = null,
    cty: ?[]const u8 = null,
    /// AxxxGCMKW wrap IV (RFC 7518 §4.7.1.1) — always 12 bytes when present.
    iv: ?[]const u8 = null,
    /// AxxxGCMKW wrap tag (§4.7.1.2) — always 16 bytes when present.
    tag: ?[]const u8 = null,
    /// PBES2 salt input (§4.8.1.1), the raw `p2s` bytes (NOT yet prefixed
    /// with `Alg || 0x00` — `alg.pbes2DeriveKek` does that).
    p2s: ?[]const u8 = null,
    /// PBES2 iteration count (§4.8.1.2).
    p2c: ?u32 = null,
};

/// Parse a JWE Protected Header JSON object. `arena` owns every returned
/// slice; the caller frees them together (typically an arena scoped to one
/// `decryptCompact` call). Malformed input never panics — everything maps to
/// a `ParseError`.
pub fn parse(arena: std.mem.Allocator, header_json: []const u8) ParseError!Parsed {
    const val = std.json.parseFromSliceLeaky(std.json.Value, arena, header_json, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidJson,
    };
    if (val != .object) return error.NotAnObject;
    const obj = val.object;

    if (obj.get("zip") != null) return error.UnsupportedZip;

    const alg_str = try requiredString(obj, "alg") orelse return error.MissingAlg;
    const enc_str = try requiredString(obj, "enc") orelse return error.MissingEnc;

    return .{
        .alg = Alg.fromString(alg_str),
        .enc = Enc.fromString(enc_str),
        .kid = try optionalString(obj, "kid"),
        .cty = try optionalString(obj, "cty"),
        .iv = try optionalBase64(arena, obj, "iv"),
        .tag = try optionalBase64(arena, obj, "tag"),
        .p2s = try optionalBase64(arena, obj, "p2s"),
        .p2c = try optionalUint(obj, "p2c"),
    };
}

fn requiredString(obj: std.json.ObjectMap, name: []const u8) error{InvalidHeaderField}!?[]const u8 {
    const v = obj.get(name) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => error.InvalidHeaderField,
    };
}

fn optionalString(obj: std.json.ObjectMap, name: []const u8) error{InvalidHeaderField}!?[]const u8 {
    return requiredString(obj, name);
}

fn optionalUint(obj: std.json.ObjectMap, name: []const u8) error{InvalidHeaderField}!?u32 {
    const v = obj.get(name) orelse return null;
    return switch (v) {
        .integer => |i| std.math.cast(u32, i) orelse error.InvalidHeaderField,
        else => error.InvalidHeaderField,
    };
}

fn optionalBase64(
    arena: std.mem.Allocator,
    obj: std.json.ObjectMap,
    name: []const u8,
) (error{OutOfMemory} || error{InvalidHeaderField})!?[]const u8 {
    const s = (try optionalString(obj, name)) orelse return null;
    const n = b64.Decoder.calcSizeForSlice(s) catch return error.InvalidHeaderField;
    if (n > max_member_len) return error.InvalidHeaderField;
    const buf = try arena.alloc(u8, n);
    b64.Decoder.decode(buf, s) catch return error.InvalidHeaderField;
    return buf;
}

/// What `encode` writes — the fields an `encryptCompact` call has decided on
/// (the raw `alg`/`enc` JOSE names plus whichever wrap/KDF params that
/// algorithm produced).
pub const EncodeParams = struct {
    alg: []const u8,
    enc: []const u8,
    kid: ?[]const u8 = null,
    cty: ?[]const u8 = null,
    iv: ?[]const u8 = null,
    tag: ?[]const u8 = null,
    p2s: ?[]const u8 = null,
    p2c: ?u32 = null,
};

pub const EncodeError = error{BufferTooSmall};

/// Serialize `params` as a compact JOSE header JSON object into `buf`.
/// Returns the written prefix (`buf` must be at least
/// `max_header_json_len` to guarantee success for any legitimate input this
/// module produces). Field order: `alg`, `enc`, then the rest in the order
/// listed on `EncodeParams` — stable but not meaningful (JOSE consumers must
/// not depend on member order).
pub fn encode(buf: []u8, params: EncodeParams) EncodeError![]const u8 {
    var fw = std.Io.Writer.fixed(buf);
    var js: std.json.Stringify = .{ .writer = &fw, .options = .{} };
    writeAll(&js, params) catch |err| switch (err) {
        error.WriteFailed => return error.BufferTooSmall,
    };
    return fw.buffered();
}

fn writeAll(js: *std.json.Stringify, params: EncodeParams) std.Io.Writer.Error!void {
    var iv_b64_buf: [b64.Encoder.calcSize(max_member_len)]u8 = undefined;
    var tag_b64_buf: [b64.Encoder.calcSize(max_member_len)]u8 = undefined;
    var p2s_b64_buf: [b64.Encoder.calcSize(max_member_len)]u8 = undefined;

    try js.beginObject();
    try js.objectField("alg");
    try js.write(params.alg);
    try js.objectField("enc");
    try js.write(params.enc);
    if (params.kid) |v| {
        try js.objectField("kid");
        try js.write(v);
    }
    if (params.cty) |v| {
        try js.objectField("cty");
        try js.write(v);
    }
    if (params.iv) |v| {
        try js.objectField("iv");
        try js.write(b64.Encoder.encode(&iv_b64_buf, v));
    }
    if (params.tag) |v| {
        try js.objectField("tag");
        try js.write(b64.Encoder.encode(&tag_b64_buf, v));
    }
    if (params.p2s) |v| {
        try js.objectField("p2s");
        try js.write(b64.Encoder.encode(&p2s_b64_buf, v));
    }
    if (params.p2c) |v| {
        try js.objectField("p2c");
        try js.write(v);
    }
    try js.endObject();
}

test "encode + parse round-trip: plain alg/enc" {
    var buf: [max_header_json_len]u8 = undefined;
    const json = try encode(&buf, .{ .alg = "dir", .enc = "A256GCM" });
    try std.testing.expectEqualStrings("{\"alg\":\"dir\",\"enc\":\"A256GCM\"}", json);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try parse(arena.allocator(), json);
    try std.testing.expectEqual(Alg.dir, parsed.alg);
    try std.testing.expectEqual(Enc.A256GCM, parsed.enc);
    try std.testing.expectEqual(@as(?[]const u8, null), parsed.kid);
}

test "encode + parse round-trip: GCMKW iv/tag + kid" {
    var buf: [max_header_json_len]u8 = undefined;
    const iv = [_]u8{1} ** 12;
    const tag = [_]u8{2} ** 16;
    const json = try encode(&buf, .{
        .alg = "A128GCMKW",
        .enc = "A128GCM",
        .kid = "key-1",
        .iv = &iv,
        .tag = &tag,
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try parse(arena.allocator(), json);
    try std.testing.expectEqual(Alg.A128GCMKW, parsed.alg);
    try std.testing.expectEqualStrings("key-1", parsed.kid.?);
    try std.testing.expectEqualSlices(u8, &iv, parsed.iv.?);
    try std.testing.expectEqualSlices(u8, &tag, parsed.tag.?);
}

test "encode + parse round-trip: PBES2 p2s/p2c" {
    var buf: [max_header_json_len]u8 = undefined;
    const salt = [_]u8{9} ** 16;
    const json = try encode(&buf, .{
        .alg = "PBES2-HS256+A128KW",
        .enc = "A128CBC-HS256",
        .p2s = &salt,
        .p2c = 600_000,
    });

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try parse(arena.allocator(), json);
    try std.testing.expectEqual(Alg.@"PBES2-HS256+A128KW", parsed.alg);
    try std.testing.expectEqualSlices(u8, &salt, parsed.p2s.?);
    try std.testing.expectEqual(@as(?u32, 600_000), parsed.p2c);
}

test "parse rejects zip" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(error.UnsupportedZip, parse(arena.allocator(), "{\"alg\":\"dir\",\"enc\":\"A128GCM\",\"zip\":\"DEF\"}"));
}

test "parse rejects missing alg/enc, non-object, bad json" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try std.testing.expectError(error.MissingAlg, parse(a, "{\"enc\":\"A128GCM\"}"));
    try std.testing.expectError(error.MissingEnc, parse(a, "{\"alg\":\"dir\"}"));
    try std.testing.expectError(error.NotAnObject, parse(a, "[1,2,3]"));
    try std.testing.expectError(error.InvalidJson, parse(a, "{not json"));
}

test "parse maps unknown alg/enc names to .unknown, not an error" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try parse(arena.allocator(), "{\"alg\":\"bogus\",\"enc\":\"bogus\"}");
    try std.testing.expectEqual(Alg.unknown, parsed.alg);
    try std.testing.expectEqual(Enc.unknown, parsed.enc);
}
