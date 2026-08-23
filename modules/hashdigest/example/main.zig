// SPDX-License-Identifier: MIT

//! What a content-addressed blob store does with `hashdigest`: compute a
//! digest under a caller-chosen algorithm, allocate the hex string to store
//! alongside the blob, then verify an incoming blob against an announced
//! digest before trusting it.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `hashdigest` does not export.

const std = @import("std");
const hashdigest = @import("hashdigest");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    const blob = "release-manifest-v3: 42 objects, digest algo blake3";

    // The store wants BLAKE3 for new objects: allocate the hex digest to
    // persist next to the blob. Caller owns the returned slice.
    const digest = try hashdigest.hexAlloc(gpa, .blake3, blob);
    defer gpa.free(digest);
    std.debug.print("stored digest (blake3): {s}\n", .{digest});

    // A second copy of the same bytes arrives over the wire; verify it
    // against the announced digest before accepting it into the store.
    const incoming = "release-manifest-v3: 42 objects, digest algo blake3";
    if (hashdigest.matchesAlgo(.blake3, incoming, digest)) {
        std.debug.print("incoming blob verified against announced digest\n", .{});
    } else {
        return error.IdenticalBlobUnexpectedlyRejected;
    }

    // A tampered blob must not verify — content-address check protects the
    // store from silently accepting corrupted data.
    const tampered = "release-manifest-v3: 42 objects, digest algo blake2";
    if (!hashdigest.matchesAlgo(.blake3, tampered, digest)) {
        std.debug.print("tampered blob correctly rejected\n", .{});
    } else {
        return error.TamperedBlobUnexpectedlyAccepted;
    }

    // A streaming hasher for a blob assembled from several network reads,
    // using the runtime-dispatched multi-algorithm hasher (SHA3-256 here,
    // e.g. because the store's manifest pins a FIPS-approved algorithm).
    var mh = hashdigest.MultiHasher.init(.sha3_256);
    mh.update("release-manifest-v3: ");
    mh.update("42 objects, ");
    mh.update("digest algo blake3");
    var stream_buf: [hashdigest.max_hex_len]u8 = undefined;
    const stream_hex = try mh.finalHex(&stream_buf);
    std.debug.print("streamed sha3-256 digest: {s}\n", .{stream_hex});

    // A too-small destination buffer must fail by name, not overflow or
    // panic — a caller building a fixed-size manifest record depends on
    // this being a nameable error, not a crash.
    var tiny: [8]u8 = undefined;
    if (hashdigest.hex(.sha3_256, blob, &tiny)) |_| {
        return error.TinyBufferUnexpectedlyFit;
    } else |err| switch (err) {
        error.ShortBuffer => std.debug.print("tiny record buffer correctly rejected (ShortBuffer)\n", .{}),
    }

    // Read the manifest's own source file on disk (EOF-based, correct even
    // on size-0 virtual files) and print its SHA-256 for a build log.
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var file_hex: [hashdigest.hex_len]u8 = undefined;
    if (hashdigest.sha256File(io, "modules/hashdigest/example/main.zig", &file_hex)) |n| {
        std.debug.print("this example file: {d} bytes, sha256={s}\n", .{ n, file_hex });
    } else {
        return error.ExampleFileUnexpectedlyUnreadable;
    }
}
