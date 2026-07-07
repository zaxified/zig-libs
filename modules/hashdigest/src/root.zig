// SPDX-License-Identifier: MIT
//! hashdigest — streaming SHA-256 helpers (one-shot, chunked, and file).
//!
//! Thin over `std.crypto.hash.sha2.Sha256`. The point of the module over calling
//! std directly: lowercase-hex output, a content-address `matches()` helper, an
//! incremental `Hasher`, and `sha256File` that hashes a file **by reading to EOF**
//! — so it is correct on size-0 virtual files (e.g. `/proc/*`, `/sys/*`) whose
//! `stat().size == 0` but which still yield bytes. Never trust the reported size.
//!
//! Provenance: extracted from the authors' axp project — `axp-core/src/digest.zig`
//! (`sha256Hex`, `matches`) and `axp-core/src/task.zig` (`sha256FileHex`, the
//! read-to-EOF streaming loop); Apache-2.0, relicensed MIT by the copyright
//! holder. Model after Go `crypto/sha256` streaming. No third-party source copied.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    .status = .extract,
    .platform = .any, // file API goes through std.Io; pure hashing is allocation-free
    .role = .util,
    .concurrency = .reentrant, // one-shot fns are pure; Hasher is single-owner
    .model_after = "Go crypto/sha256 streaming",
    .deps = .{},
};

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Length of a lowercase-hex SHA-256 digest (64).
pub const hex_len = Sha256.digest_length * 2;

// ── one-shot ─────────────────────────────────────────────────────────────────

/// Write the lowercase-hex SHA-256 of `data` into `out`. (Seed: axp digest.zig.)
pub fn sha256Hex(out: *[hex_len]u8, data: []const u8) void {
    var raw: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(data, &raw, .{});
    out.* = std.fmt.bytesToHex(raw, .lower);
}

/// Return the lowercase-hex SHA-256 of `data` as an array (ergonomic form).
pub fn sha256HexBuf(data: []const u8) [hex_len]u8 {
    var out: [hex_len]u8 = undefined;
    sha256Hex(&out, data);
    return out;
}

/// True iff the lowercase-hex SHA-256 of `data` equals `announced`. Content-address
/// check for the reconcile channel ("device is the final authority"). (Seed: axp.)
pub fn matches(data: []const u8, announced: []const u8) bool {
    if (announced.len != hex_len) return false;
    var hex: [hex_len]u8 = undefined;
    sha256Hex(&hex, data);
    return std.mem.eql(u8, &hex, announced);
}

// ── streaming ────────────────────────────────────────────────────────────────

/// Incremental hasher: feed chunks, then finalize to lowercase hex. Single-owner.
pub const Hasher = struct {
    inner: Sha256,

    pub fn init() Hasher {
        return .{ .inner = Sha256.init(.{}) };
    }

    /// Feed a chunk. Call any number of times.
    pub fn update(self: *Hasher, bytes: []const u8) void {
        self.inner.update(bytes);
    }

    /// Finalize into `out` (consumes the hasher's state).
    pub fn finalHex(self: *Hasher, out: *[hex_len]u8) void {
        var raw: [Sha256.digest_length]u8 = undefined;
        self.inner.final(&raw);
        out.* = std.fmt.bytesToHex(raw, .lower);
    }
};

// ── file (size-0 / virtual-file safe) ─────────────────────────────────────────

/// Hash the file at `path` by streaming to EOF; write lowercase hex into `out`,
/// return the byte count, or `null` on open/read error. Correct on size-0 virtual
/// files (reads until EOF, does not trust `stat().size`). (Seed: axp task.zig.)
pub fn sha256File(io: std.Io, path: []const u8, out: *[hex_len]u8) ?u64 {
    var file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return null;
    defer file.close(io);
    var buf: [64 * 1024]u8 = undefined;
    var fr = std.Io.File.Reader.initStreaming(file, io, &buf);
    var h = Sha256.init(.{});
    var total: u64 = 0;
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n = fr.interface.readSliceShort(&chunk) catch return null;
        if (n == 0) break;
        h.update(chunk[0..n]);
        total += n;
    }
    var raw: [Sha256.digest_length]u8 = undefined;
    h.final(&raw);
    out.* = std.fmt.bytesToHex(raw, .lower);
    return total;
}

// ── tests ────────────────────────────────────────────────────────────────────

const empty_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const abc_hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

test "sha256Hex known-answer vectors, lowercase" {
    var out: [hex_len]u8 = undefined;

    sha256Hex(&out, "");
    try std.testing.expectEqualStrings(empty_hex, &out);

    sha256Hex(&out, "abc");
    try std.testing.expectEqualStrings(abc_hex, &out);

    // assert lowercase: no byte in A-F range
    for (out) |c| try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
}

test "sha256HexBuf matches sha256Hex" {
    var out: [hex_len]u8 = undefined;
    sha256Hex(&out, "hello world");
    const buf = sha256HexBuf("hello world");
    try std.testing.expectEqualStrings(&out, &buf);
}

test "Hasher: chunked feed equals one-shot" {
    var h = Hasher.init();
    h.update("a");
    h.update("bc");
    var streamed: [hex_len]u8 = undefined;
    h.finalHex(&streamed);
    try std.testing.expectEqualStrings(abc_hex, &streamed);

    // empty stream (no update calls) equals one-shot of ""
    var h2 = Hasher.init();
    var empty_out: [hex_len]u8 = undefined;
    h2.finalHex(&empty_out);
    try std.testing.expectEqualStrings(empty_hex, &empty_out);
}

test "matches: right hex true; wrong, short, tampered false; no panic" {
    try std.testing.expect(matches("abc", abc_hex));
    try std.testing.expect(!matches("abc", empty_hex)); // wrong digest
    try std.testing.expect(!matches("abc", "deadbeef")); // short garbage — must not panic
    try std.testing.expect(!matches("abc", "")); // empty announced
    try std.testing.expect(!matches("abd", abc_hex)); // tampered data
    // right length but uppercase (we emit lowercase only)
    var upper: [hex_len]u8 = undefined;
    for (abc_hex, 0..) |c, i| upper[i] = std.ascii.toUpper(c);
    try std.testing.expect(!matches("abc", &upper));
}

test "sha256File: temp file matches in-memory hash and byte count" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const data = "The quick brown fox jumps over the lazy dog";
    try tmp.dir.writeFile(io, .{ .sub_path = "hashme.bin", .data = data });

    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/hashme.bin", .{&tmp.sub_path});

    var file_hex: [hex_len]u8 = undefined;
    const n = sha256File(io, path, &file_hex) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, data.len), n);

    var mem_hex: [hex_len]u8 = undefined;
    sha256Hex(&mem_hex, data);
    try std.testing.expectEqualStrings(&mem_hex, &file_hex);
}

test "sha256File: missing file returns null" {
    const io = std.testing.io;
    var out: [hex_len]u8 = undefined;
    try std.testing.expect(sha256File(io, "no/such/file.bin", &out) == null);
}

test "sha256File: reads size-0 virtual file to EOF (Linux /proc)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const io = std.testing.io;
    var out: [hex_len]u8 = undefined;
    // /proc/version reports stat().size == 0 but yields bytes until EOF.
    const n = sha256File(io, "/proc/version", &out) orelse return error.SkipZigTest;
    try std.testing.expect(n > 0);
    // the digest of a non-empty read must not be the empty-string digest
    try std.testing.expect(!std.mem.eql(u8, &out, empty_hex));
}
