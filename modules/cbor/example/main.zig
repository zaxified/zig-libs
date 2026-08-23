// SPDX-License-Identifier: MIT

//! What a WebAuthn/COSE-adjacent consumer does with `cbor`: decode a handful
//! of the RFC 8949 Appendix A test vectors verbatim (the spec's own
//! known-answer table — the external judge for this module), re-encode them
//! and check the "preferred serialization" round-trip is byte-exact, build
//! and canonical-encode a small map, and reject truncated/trailing-garbage
//! input by name.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const cbor = @import("cbor");
const Value = cbor.Value;

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // RFC 8949 Appendix A, verbatim: 1000000 -> 0x1a000f4240.
    {
        const wire = [_]u8{ 0x1a, 0x00, 0x0f, 0x42, 0x40 };
        const v = try cbor.decode(gpa, &wire, .{});
        defer cbor.freeValue(gpa, v);
        std.debug.assert(v == .uint and v.uint == 1000000);
        const re = try cbor.encode(gpa, v, .{});
        defer gpa.free(re);
        std.debug.assert(std.mem.eql(u8, re, &wire));
        std.debug.print("A.1 1000000: decoded + re-encoded byte-exact\n", .{});
    }

    // RFC 8949 Appendix A: -100 -> 0x3863 (negint magnitude 99, real value
    // -1-99 = -100).
    {
        const wire = [_]u8{ 0x38, 0x63 };
        const v = try cbor.decode(gpa, &wire, .{});
        defer cbor.freeValue(gpa, v);
        std.debug.assert(v.toI64().? == -100);
        std.debug.print("A.1 -100: toI64() == -100\n", .{});
    }

    // RFC 8949 Appendix A: "IETF" -> 0x6449455446 (text string, 4 bytes).
    {
        const wire = [_]u8{ 0x64, 0x49, 0x45, 0x54, 0x46 };
        const v = try cbor.decode(gpa, &wire, .{});
        defer cbor.freeValue(gpa, v);
        std.debug.assert(v == .text and std.mem.eql(u8, v.text, "IETF"));
        std.debug.print("A.1 \"IETF\": {s}\n", .{v.text});
    }

    // RFC 8949 Appendix A: [1, 2, 3] -> 0x83010203.
    {
        const wire = [_]u8{ 0x83, 0x01, 0x02, 0x03 };
        const v = try cbor.decode(gpa, &wire, .{});
        defer cbor.freeValue(gpa, v);
        std.debug.assert(v == .array and v.array.len == 3);
        std.debug.assert(v.array[0].uint == 1 and v.array[1].uint == 2 and v.array[2].uint == 3);
        const re = try cbor.encode(gpa, v, .{});
        defer gpa.free(re);
        std.debug.assert(std.mem.eql(u8, re, &wire));
        std.debug.print("A.1 [1,2,3]: decoded + re-encoded byte-exact\n", .{});
    }

    // RFC 8949 Appendix A: {"a": 1, "b": [2, 3]} -> 0xa26161016162820203.
    {
        const wire = [_]u8{ 0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03 };
        const v = try cbor.decode(gpa, &wire, .{});
        defer cbor.freeValue(gpa, v);
        std.debug.assert(v == .map and v.map.len == 2);
        std.debug.assert(std.mem.eql(u8, v.map[0].key.text, "a") and v.map[0].value.uint == 1);
        std.debug.assert(std.mem.eql(u8, v.map[1].key.text, "b") and v.map[1].value.array.len == 2);
        std.debug.print("A.1 {{\"a\":1,\"b\":[2,3]}}: fields check out\n", .{});
    }

    // RFC 8949 Appendix A: half-float 1.5 -> 0xf93e00.
    {
        const wire = [_]u8{ 0xf9, 0x3e, 0x00 };
        const v = try cbor.decode(gpa, &wire, .{});
        defer cbor.freeValue(gpa, v);
        std.debug.assert(v == .f16 and v.f16 == 1.5);
        std.debug.print("A.1 f16 1.5: decoded exact\n", .{});
    }

    // A caller-assembled map, encoded with EncodeOptions.canonical = true:
    // RFC 8949 §4.2.1 sorts entries by the bytewise order of their *encoded*
    // key bytes. "b" (0x6162) sorts before "aa" (0x62 61 61) because it is
    // shorter, even though "aa" < "b" lexically as text.
    {
        const entries = [_]cbor.MapEntry{
            .{ .key = .{ .text = "aa" }, .value = .{ .uint = 1 } },
            .{ .key = .{ .text = "b" }, .value = .{ .uint = 2 } },
        };
        const v: Value = .{ .map = &entries };
        const encoded = try cbor.encode(gpa, v, .{ .canonical = true });
        defer gpa.free(encoded);
        const decoded = try cbor.decode(gpa, encoded, .{});
        defer cbor.freeValue(gpa, decoded);
        std.debug.assert(std.mem.eql(u8, decoded.map[0].key.text, "b"));
        std.debug.assert(std.mem.eql(u8, decoded.map[1].key.text, "aa"));
        std.debug.print("canonical map: \"b\" (shorter key) sorts before \"aa\"\n", .{});
    }

    // A COSE-shaped input, attacker-truncated one byte short: array(2) whose
    // second element never arrives. Must fail by name, not panic.
    if (cbor.decode(gpa, &[_]u8{ 0x82, 0x01 }, .{})) |_| {
        unreachable;
    } else |err| switch (err) {
        error.Truncated => std.debug.print("truncated array(2): Truncated (expected)\n", .{}),
        else => return err,
    }

    // A complete, valid item followed by an unexpected extra byte.
    if (cbor.decode(gpa, &[_]u8{ 0x41, 0x61, 0x02 }, .{})) |_| {
        unreachable;
    } else |err| switch (err) {
        error.TrailingGarbage => std.debug.print("byte-string + trailing byte: TrailingGarbage (expected)\n", .{}),
        else => return err,
    }
}
