// SPDX-License-Identifier: MIT
//! Encrypted entries against foreign implementations: archives 7-Zip wrote
//! (WinZip AES-128/192/256, Deflate and Store) and Info-ZIP wrote
//! (ZipCrypto), of our own content, must decrypt here; our AES archive
//! (`testdata/crypto/ours_aes.zip`, which 7-Zip tested and extracted when it
//! was taken — `tools/crypto_fixtures.sh`) must be what the writer still
//! produces. Plus wrong passwords and tampered ciphertext.

const std = @import("std");
const testing = std.testing;
const zs = @import("root.zig");

const password = "secret";

/// The fixtures' big.txt (crypto_fixtures.sh writes the same lines).
fn bigText(a: std.mem.Allocator) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    for (0..300) |i| try out.writer.print("line {d}: Příliš žluťoučký kůň úpěl ďábelské ódy\n", .{i});
    return out.toOwnedSlice();
}

fn open(a: std.mem.Allocator, archive: *zs.Archive, bytes: []const u8, ms: *zs.MemorySource) !void {
    ms.* = .{ .bytes = bytes };
    try archive.initSource(a, ms.source(), .{});
}

fn readEntry(a: std.mem.Allocator, archive: *zs.Archive, e: *const zs.Entry, pw: ?[]const u8) ![]u8 {
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var er: zs.EntryReader = undefined;
    try er.open(archive, e, &window, .{ .password = pw });
    defer er.deinit();
    var out: std.Io.Writer.Allocating = .init(a);
    errdefer out.deinit();
    _ = try er.reader().streamRemaining(&out.writer);
    return out.toOwnedSlice();
}

const fixtures = [_]struct { file: []const u8, data: []const u8, aes: bool }{
    .{ .file = "7z_aes128_deflate.zip", .data = @embedFile("testdata/crypto/7z_aes128_deflate.zip"), .aes = true },
    .{ .file = "7z_aes128_store.zip", .data = @embedFile("testdata/crypto/7z_aes128_store.zip"), .aes = true },
    .{ .file = "7z_aes192_deflate.zip", .data = @embedFile("testdata/crypto/7z_aes192_deflate.zip"), .aes = true },
    .{ .file = "7z_aes192_store.zip", .data = @embedFile("testdata/crypto/7z_aes192_store.zip"), .aes = true },
    .{ .file = "7z_aes256_deflate.zip", .data = @embedFile("testdata/crypto/7z_aes256_deflate.zip"), .aes = true },
    .{ .file = "7z_aes256_store.zip", .data = @embedFile("testdata/crypto/7z_aes256_store.zip"), .aes = true },
    .{ .file = "zc_deflate.zip", .data = @embedFile("testdata/crypto/zc_deflate.zip"), .aes = false },
    .{ .file = "zc_store.zip", .data = @embedFile("testdata/crypto/zc_store.zip"), .aes = false },
};

test "7-Zip WinZip AES and Info-ZIP ZipCrypto archives decrypt to their content" {
    const a = testing.allocator;
    const big = try bigText(a);
    defer a.free(big);
    for (fixtures) |f| {
        var ms: zs.MemorySource = undefined;
        var archive: zs.Archive = undefined;
        try open(a, &archive, f.data, &ms);
        defer archive.deinit();
        try testing.expectEqual(@as(usize, 2), archive.entries.items.len);
        for (archive.entries.items) |*e| {
            try testing.expect(e.encrypted);
            try testing.expectEqual(f.aes, e.aes != null);
            const want: []const u8 = if (std.mem.eql(u8, e.name, "big.txt")) big else "tiny\n";
            const got = readEntry(a, &archive, e, password) catch |err| {
                std.debug.print("{s}/{s}: {t}\n", .{ f.file, e.name, err });
                return err;
            };
            defer a.free(got);
            try testing.expectEqualSlices(u8, want, got);
            // Without a password: refused, never garbage.
            try testing.expectError(error.ZipEncryptedEntry, readEntry(a, &archive, e, null));
        }
    }
}

test "a wrong password is refused up front (AES verifier; ZipCrypto check byte)" {
    const a = testing.allocator;
    for (fixtures) |f| {
        var ms: zs.MemorySource = undefined;
        var archive: zs.Archive = undefined;
        try open(a, &archive, f.data, &ms);
        defer archive.deinit();
        const e = archive.find("big.txt").?;
        if (f.aes) {
            try testing.expectError(error.ZipBadPassword, readEntry(a, &archive, e, "Secret"));
        } else {
            // 1 in 256 wrong passwords pass the check byte; this one must not
            // get through both it and the CRC.
            if (readEntry(a, &archive, e, "Secret")) |got| {
                a.free(got);
                return error.WrongPasswordAccepted;
            } else |_| {}
        }
    }
}

test "a flipped ciphertext byte fails AES authentication (and never completes)" {
    const a = testing.allocator;
    for (fixtures) |f| {
        if (!f.aes) continue;
        var ms0: zs.MemorySource = undefined;
        var probe: zs.Archive = undefined;
        try open(a, &probe, f.data, &ms0);
        const e0 = probe.find("big.txt").?.*;
        probe.deinit();
        const bytes = try a.dupe(u8, f.data);
        defer a.free(bytes);
        // The local header of big.txt, then 30 + name + extra, then salt ‖ pv,
        // then ciphertext: flip a byte well inside the ciphertext.
        const lh = e0.file_offset;
        const nl = std.mem.readInt(u16, bytes[lh + 26 ..][0..2], .little);
        const xl = std.mem.readInt(u16, bytes[lh + 28 ..][0..2], .little);
        const data = lh + 30 + nl + xl;
        bytes[data + e0.aes.?.strength.saltLen() + 2 + 40] ^= 0x01;
        var ms: zs.MemorySource = undefined;
        var archive: zs.Archive = undefined;
        try open(a, &archive, bytes, &ms);
        defer archive.deinit();
        const e = archive.find("big.txt").?;
        var window: [std.compress.flate.max_window_len]u8 = undefined;
        var er: zs.EntryReader = undefined;
        try er.open(&archive, e, &window, .{ .password = password });
        defer er.deinit();
        var out: std.Io.Writer.Allocating = .init(a);
        defer out.deinit();
        if (er.reader().streamRemaining(&out.writer)) |_| {
            return error.TamperedEntryCompleted;
        } else |_| {}
        // Stored entries reach the code; a deflate stream may fail earlier
        // on garbage — either way it never completes.
        if (std.mem.endsWith(u8, f.file, "store.zip")) try testing.expect(er.authFailed());
    }
}

/// Builds the same archive as tools/aes_golden.zig (keep the two in step).
fn oursAes(a: std.mem.Allocator) ![]u8 {
    const files = [_]struct { name: []const u8, method: zs.WriteMethod, strength: zs.AesStrength, streamed: bool }{
        .{ .name = "aes256_deflate.txt", .method = .deflate, .strength = .aes256, .streamed = false },
        .{ .name = "aes128_store.txt", .method = .store, .strength = .aes128, .streamed = false },
        .{ .name = "aes192_deflate_streamed.txt", .method = .deflate, .strength = .aes192, .streamed = true },
    };
    const text = try bigText(a);
    defer a.free(text);
    var aw: std.Io.Writer.Allocating = .init(a);
    errdefer aw.deinit();
    var zw = zs.ArchiveWriter.init(a, &aw.writer);
    defer zw.deinit();
    const salt: [16]u8 = "0123456789abcdef".*;
    for (files) |f| {
        const opts: zs.AddEntryOptions = .{
            .method = f.method,
            .mtime = 1_700_000_000,
            .encryption = .{ .password = password, .strength = f.strength, .salt = salt[0..f.strength.saltLen()] },
        };
        if (f.streamed) {
            const w = try zw.beginEntry(f.name, opts);
            try w.writeAll(text);
            try zw.endEntry();
        } else try zw.addEntry(f.name, text, opts);
    }
    try zw.finish();
    return aw.toOwnedSlice();
}

test "the writer reproduces the AES archive 7-Zip tested, and reads it back" {
    const a = testing.allocator;
    const ours = try oursAes(a);
    defer a.free(ours);
    try testing.expectEqualSlices(u8, @embedFile("testdata/crypto/ours_aes.zip"), ours);
    const big = try bigText(a);
    defer a.free(big);
    var ms: zs.MemorySource = undefined;
    var archive: zs.Archive = undefined;
    try open(a, &archive, ours, &ms);
    defer archive.deinit();
    for (archive.entries.items) |*e| {
        try testing.expectEqual(@as(u16, 2), e.aes.?.version); // AE-2
        try testing.expectEqual(@as(u32, 0), e.crc32);
        const got = try readEntry(a, &archive, e, password);
        defer a.free(got);
        try testing.expectEqualSlices(u8, big, got);
    }
}

test "AES with a random salt (io) round-trips; two archives differ" {
    const a = testing.allocator;
    var outs: [2][]u8 = undefined;
    for (&outs) |*o| {
        var aw: std.Io.Writer.Allocating = .init(a);
        var zw = zs.ArchiveWriter.init(a, &aw.writer);
        defer zw.deinit();
        try zw.addEntry("x.txt", "payload", .{ .encryption = .{ .password = "p", .io = testing.io } });
        try zw.finish();
        o.* = try aw.toOwnedSlice();
    }
    defer for (outs) |o| a.free(o);
    try testing.expect(!std.mem.eql(u8, outs[0], outs[1]));
    var ms: zs.MemorySource = undefined;
    var archive: zs.Archive = undefined;
    try open(a, &archive, outs[0], &ms);
    defer archive.deinit();
    const got = try readEntry(a, &archive, &archive.entries.items[0], "p");
    defer a.free(got);
    try testing.expectEqualStrings("payload", got);
}
