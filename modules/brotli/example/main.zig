// SPDX-License-Identifier: MIT

//! What an HTTP client/server does with `brotli`: compress a response body
//! for the wire (`Content-Encoding: br`), decompress it back on the other
//! end, and bound decompression against a compression-bomb using
//! `Options.max_output` — the guard a server terminating untrusted `br`
//! bodies actually needs.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const brotli = @import("brotli");

/// A check that survives EVERY optimize mode, unlike a debug-only assert:
/// `-Doptimize=ReleaseFast` compiles those out, and `scripts/test.sh` does not
/// merely BUILD the examples, it RUNS them in the lane's own optimize mode --
/// so in a release lane the check vanished and the example went on printing
/// that it had passed. See `scripts/checks/check-example-assert.py`.
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

const body = "The quick brown fox jumps over the lazy dog. " ** 40;

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // Compress a response body for the wire.
    const compressed = try brotli.compress(gpa, body);
    defer gpa.free(compressed);
    std.debug.print("compressed {d} bytes to {d}\n", .{ body.len, compressed.len });

    // Decompress it back on the receiving end, with default options.
    const decompressed = try brotli.decompress(gpa, compressed, .{});
    defer gpa.free(decompressed);
    must(std.mem.eql(u8, body, decompressed), @src());
    std.debug.print("round-trip verified, {d} bytes\n", .{decompressed.len});

    // A server terminating an untrusted `br` body must bound the output
    // size — this compressed body decompresses well past a 100-byte cap,
    // and that must surface as a nameable error, not an unbounded
    // allocation.
    if (brotli.decompress(gpa, compressed, .{ .max_output = 100 })) |leaked| {
        gpa.free(leaked);
        unreachable; // the cap must have fired
    } else |err| switch (err) {
        error.OutputTooLarge => std.debug.print("oversized output correctly rejected\n", .{}),
        error.TruncatedInput,
        error.ReservedBitSet,
        error.InvalidWindowBits,
        error.InvalidLength,
        error.InvalidPadding,
        error.InvalidHuffman,
        error.DuplicateSimpleSymbol,
        error.InvalidContextMap,
        error.InvalidDistance,
        error.InvalidDictionary,
        error.TrailingData,
        error.OutOfMemory,
        => return err,
    }

    // Truncated/hostile input must also fail cleanly, never panic.
    if (brotli.decompress(gpa, "", .{})) |leaked| {
        gpa.free(leaked);
        unreachable;
    } else |err| switch (err) {
        error.TruncatedInput => std.debug.print("empty input correctly rejected\n", .{}),
        else => return err,
    }
}
