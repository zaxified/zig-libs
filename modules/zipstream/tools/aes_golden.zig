// SPDX-License-Identifier: MIT
//! Writes the WinZip AES golden archive `src/testdata/crypto/ours_aes.zip`
//! (fixed salts, so the bytes are reproducible) that `tools/crypto_fixtures.sh`
//! hands to 7-Zip and that `src/crypto_test.zig` requires the writer to
//! reproduce. THIS IS A PROGRAM, NOT A TEST: run by `crypto_fixtures.sh`.

const std = @import("std");
const zs = @import("zipstream");

pub const password = "secret";
pub const files = [_]struct { name: []const u8, method: zs.WriteMethod, strength: zs.AesStrength, streamed: bool }{
    .{ .name = "aes256_deflate.txt", .method = .deflate, .strength = .aes256, .streamed = false },
    .{ .name = "aes128_store.txt", .method = .store, .strength = .aes128, .streamed = false },
    .{ .name = "aes192_deflate_streamed.txt", .method = .deflate, .strength = .aes192, .streamed = true },
};

pub fn content(a: std.mem.Allocator) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(a);
    for (0..300) |i| try out.writer.print("line {d}: Příliš žluťoučký kůň úpěl ďábelské ódy\n", .{i});
    return out.toOwnedSlice();
}

pub fn build(a: std.mem.Allocator) ![]u8 {
    const text = try content(a);
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

pub fn main(init: std.process.Init) !void {
    const a = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const bytes = try build(a);
    defer a.free(bytes);
    try std.Io.Dir.cwd().writeFile(init.io, .{ .sub_path = args[1], .data = bytes });
}
