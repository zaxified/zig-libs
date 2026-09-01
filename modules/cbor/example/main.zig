// SPDX-License-Identifier: MIT

//! What a WebAuthn/COSE-adjacent consumer does with `cbor`: decode a handful
//! of the RFC 8949 Appendix A test vectors verbatim (the spec's own
//! known-answer table — the external judge for this module), re-encode them
//! and check the "preferred serialization" round-trip is byte-exact, build
//! and canonical-encode a small map, reject truncated/trailing-garbage
//! input by name, and then drive the COSE layer itself: parse RFC 9052
//! Appendix C.2.1's published `COSE_Sign1`, confirm `protected` comes back as
//! the original serialized bytes (the property that closes the
//! re-encode-what-was-signed forgery seam), rebuild its `Sig_structure` and
//! compare against the bytes `cose-wg/Examples` publishes for that vector,
//! and refuse an unmodelled `kty` by name.
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

    // The COSE layer, which is the half a WebAuthn-adjacent consumer actually
    // reaches for. RFC 9052 Appendix C.2.1's own `COSE_Sign1` worked example,
    // tag-18 wrapped, verbatim.
    {
        const wire = [_]u8{
            0xd2, 0x84, 0x43, 0xa1, 0x01, 0x26, 0xa1, 0x04, 0x42, 0x31, 0x31, 0x54,
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
            0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2e, 0x58, 0x40, 0x8e, 0xb3,
            0x3e, 0x4c, 0xa3, 0x1d, 0x1c, 0x46, 0x5a, 0xb0, 0x5a, 0xac, 0x34, 0xcc,
            0x6b, 0x23, 0xd5, 0x8f, 0xef, 0x5c, 0x08, 0x31, 0x06, 0xc4, 0xd2, 0x5a,
            0x91, 0xae, 0xf0, 0xb0, 0x11, 0x7e, 0x2a, 0xf9, 0xa2, 0x91, 0xaa, 0x32,
            0xe1, 0x4a, 0xb8, 0x34, 0xdc, 0x56, 0xed, 0x2a, 0x22, 0x34, 0x44, 0x54,
            0x7e, 0x01, 0xf1, 0x1d, 0x3b, 0x09, 0x16, 0xe5, 0xa4, 0xc3, 0x45, 0xca,
            0xcb, 0x36,
        };
        const v = try cbor.decode(gpa, &wire, .{});
        defer cbor.freeValue(gpa, v);

        const s1 = try cbor.cose.parseSign1(v);
        std.debug.assert(std.mem.eql(u8, s1.payload.?, "This is the content."));

        // The property this layer exists to protect: `protected` is handed back
        // as the ORIGINAL serialized bytes, so what gets verified is what was
        // signed. Re-encoding `{1: -7}` here instead would be the classic
        // COSE forgery seam.
        std.debug.assert(std.mem.eql(u8, s1.protected, &[_]u8{ 0xa1, 0x01, 0x26 }));

        // `Sig_structure` — the exact bytes a signature covers. Compared against
        // the value published in `cose-wg/Examples` sign1-tests/sign-fail-01.json
        // as `intermediates.ToBeSign_hex`, which is this same vector.
        const tbs = try cbor.cose.sigStructure(gpa, s1.protected, "", s1.payload.?);
        defer gpa.free(tbs);
        const published_tbs = [_]u8{
            0x84, 0x6a, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
            0x43, 0xa1, 0x01, 0x26, 0x40, 0x54, 0x54, 0x68, 0x69, 0x73, 0x20, 0x69,
            0x73, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6f, 0x6e, 0x74, 0x65, 0x6e,
            0x74, 0x2e,
        };
        std.debug.assert(std.mem.eql(u8, tbs, &published_tbs));
        std.debug.print("COSE_Sign1 (RFC 9052 C.2.1): protected kept verbatim, Sig_structure matches the published bytes\n", .{});
    }

    // A COSE_Key whose `kty` this module does not model must be refused by
    // name, not guessed at.
    {
        const entries = [_]cbor.MapEntry{
            .{ .key = .{ .uint = 1 }, .value = .{ .uint = 4 } }, // kty = 4 (symmetric)
        };
        if (cbor.cose.parseKey(.{ .map = &entries })) |_| {
            unreachable;
        } else |err| switch (err) {
            error.UnsupportedKty => std.debug.print("COSE_Key kty=4 (symmetric): UnsupportedKty (expected)\n", .{}),
            else => return err,
        }
    }
}
