// SPDX-License-Identifier: MIT
//! hashdigest — streaming multi-algorithm digest helpers (one-shot, chunked, file).
//!
//! Thin over `std.crypto.hash`. The point of the module over calling std directly:
//! lowercase-hex output, content-address `matches()`/`matchesAlgo()` helpers,
//! incremental hashers (`Hasher` for SHA-256, `MultiHasher` for any `Algorithm`),
//! and file hashing (`sha256File`/`hashFile`) **by reading to EOF** — so it is
//! correct on size-0 virtual files (e.g. `/proc/*`, `/sys/*`) whose
//! `stat().size == 0` but which still yield bytes. Never trust the reported size.
//!
//! Algorithms: SHA-224/256/384/512, SHA-512/256, SHA3-256/512, BLAKE2b-256,
//! BLAKE3 — all composed from `std.crypto.hash`; nothing reimplemented here.
//! The SHA-256 names (`sha256Hex`, `Hasher`, `sha256File`, ...) are kept as
//! stable conveniences; the `Algorithm`-parameterized API generalizes them.
//!
//! Provenance: extracted from the authors' axp project — `axp-core/src/digest.zig`
//! (`sha256Hex`, `matches`) and `axp-core/src/task.zig` (`sha256FileHex`, the
//! read-to-EOF streaming loop); Apache-2.0, relicensed MIT by the copyright
//! holder. Multi-algorithm layer written for this module; the constructions are
//! the public SHA-2 / SHA-3 / BLAKE2 / BLAKE3 standards via `std.crypto`.
//! Model after Go `crypto/sha256` streaming. No third-party source copied.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    .status = .extract,
    .platform = .any, // file API goes through std.Io; pure hashing is allocation-free
    .role = .util,
    .concurrency = .reentrant, // one-shot fns are pure; Hasher/MultiHasher are single-owner
    .model_after = "Go crypto/sha256 streaming, generalized multi-algorithm over std.crypto.hash",
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
    var hx: [hex_len]u8 = undefined;
    sha256Hex(&hx, data);
    return std.mem.eql(u8, &hx, announced);
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

// ── multi-algorithm layer ────────────────────────────────────────────────────

/// Digest algorithms available through the unified API. Each maps 1:1 onto a
/// `std.crypto.hash` type; nothing is reimplemented here.
pub const Algorithm = enum {
    sha256,
    sha512,
    sha384,
    sha224,
    /// NIST SHA-512/256 (FIPS 180-4 distinct IV) — `std.crypto.hash.sha2.Sha512_256`,
    /// not the plain-truncation `Sha512T256`.
    sha512_256,
    sha3_256,
    sha3_512,
    blake2b256,
    blake3,

    /// The underlying `std.crypto.hash` type for `algo` (comptime).
    pub fn Impl(comptime algo: Algorithm) type {
        return switch (algo) {
            .sha256 => std.crypto.hash.sha2.Sha256,
            .sha512 => std.crypto.hash.sha2.Sha512,
            .sha384 => std.crypto.hash.sha2.Sha384,
            .sha224 => std.crypto.hash.sha2.Sha224,
            .sha512_256 => std.crypto.hash.sha2.Sha512_256,
            .sha3_256 => std.crypto.hash.sha3.Sha3_256,
            .sha3_512 => std.crypto.hash.sha3.Sha3_512,
            .blake2b256 => std.crypto.hash.blake2.Blake2b256,
            .blake3 => std.crypto.hash.Blake3,
        };
    }
};

/// Largest raw digest across all `Algorithm`s (bytes); `max_hex_len` = 2x.
/// Sized so a single stack buffer fits any algorithm's output.
pub const max_digest_len = blk: {
    var m: usize = 0;
    for (std.enums.values(Algorithm)) |a| m = @max(m, Algorithm.Impl(a).digest_length);
    break :blk m;
};
pub const max_hex_len = max_digest_len * 2;

/// Raw digest length of `algo` in bytes (runtime dispatch).
pub fn digestLength(algo: Algorithm) usize {
    return switch (algo) {
        inline else => |a| Algorithm.Impl(a).digest_length,
    };
}

/// Lowercase-hex digest length of `algo` (= 2 x `digestLength`).
pub fn hexLength(algo: Algorithm) usize {
    return digestLength(algo) * 2;
}

/// Fixed hex-array type for a comptime-known algorithm: `HexOf(.sha512)` is `[128]u8`.
pub fn HexOf(comptime algo: Algorithm) type {
    return [Algorithm.Impl(algo).digest_length * 2]u8;
}

/// One-shot lowercase hex for a comptime-known algorithm; returns a fixed array
/// (no allocation, no length check needed). Generalizes `sha256HexBuf`.
pub fn hexOf(comptime algo: Algorithm, data: []const u8) HexOf(algo) {
    const T = Algorithm.Impl(algo);
    var raw: [T.digest_length]u8 = undefined;
    T.hash(data, &raw, .{});
    return std.fmt.bytesToHex(raw, .lower);
}

/// One-shot lowercase hex of `data` under `algo`, written into `out` (which must
/// hold at least `hexLength(algo)` bytes — a `max_hex_len` buffer always fits).
/// Returns the written subslice of `out`, or `error.ShortBuffer` — never panics.
pub fn hex(algo: Algorithm, data: []const u8, out: []u8) error{ShortBuffer}![]u8 {
    switch (algo) {
        inline else => |a| {
            const hx = hexOf(a, data);
            if (out.len < hx.len) return error.ShortBuffer;
            @memcpy(out[0..hx.len], &hx);
            return out[0..hx.len];
        },
    }
}

/// One-shot lowercase hex of `data` under `algo` as a freshly allocated string
/// of exactly `hexLength(algo)` bytes. Caller owns the result (free with `gpa`).
pub fn hexAlloc(gpa: std.mem.Allocator, algo: Algorithm, data: []const u8) std.mem.Allocator.Error![]u8 {
    const out = try gpa.alloc(u8, hexLength(algo));
    _ = hex(algo, data, out) catch unreachable; // out is exactly hexLength(algo)
    return out;
}

/// True iff the lowercase-hex digest of `data` under `algo` equals `announced`.
/// Generalizes `matches` (which is fixed to SHA-256). Never panics on bad input.
pub fn matchesAlgo(algo: Algorithm, data: []const u8, announced: []const u8) bool {
    if (announced.len != hexLength(algo)) return false;
    var buf: [max_hex_len]u8 = undefined;
    const hx = hex(algo, data, &buf) catch return false;
    return std.mem.eql(u8, hx, announced);
}

/// Incremental hasher with runtime algorithm dispatch. Same contract as `Hasher`
/// (feed chunks, finalize once, single-owner) for any `Algorithm`.
pub const MultiHasher = struct {
    state: State,

    const State = union(Algorithm) {
        sha256: Algorithm.Impl(.sha256),
        sha512: Algorithm.Impl(.sha512),
        sha384: Algorithm.Impl(.sha384),
        sha224: Algorithm.Impl(.sha224),
        sha512_256: Algorithm.Impl(.sha512_256),
        sha3_256: Algorithm.Impl(.sha3_256),
        sha3_512: Algorithm.Impl(.sha3_512),
        blake2b256: Algorithm.Impl(.blake2b256),
        blake3: Algorithm.Impl(.blake3),
    };

    pub fn init(algo: Algorithm) MultiHasher {
        switch (algo) {
            inline else => |a| return .{
                .state = @unionInit(State, @tagName(a), Algorithm.Impl(a).init(.{})),
            },
        }
    }

    /// The algorithm this hasher was initialized with.
    pub fn algorithm(self: *const MultiHasher) Algorithm {
        return self.state;
    }

    /// Feed a chunk. Call any number of times.
    pub fn update(self: *MultiHasher, bytes: []const u8) void {
        switch (self.state) {
            inline else => |*st| st.update(bytes),
        }
    }

    /// Finalize to lowercase hex in `out` (>= `hexLength(algorithm())` bytes;
    /// a `max_hex_len` buffer always fits). Returns the written subslice, or
    /// `error.ShortBuffer` — never panics. Consumes the hasher's state.
    pub fn finalHex(self: *MultiHasher, out: []u8) error{ShortBuffer}![]u8 {
        switch (self.state) {
            inline else => |*st, tag| {
                const T = Algorithm.Impl(tag);
                const hl = T.digest_length * 2;
                if (out.len < hl) return error.ShortBuffer;
                var raw: [T.digest_length]u8 = undefined;
                st.final(&raw);
                const hx = std.fmt.bytesToHex(raw, .lower);
                @memcpy(out[0..hl], &hx);
                return out[0..hl];
            },
        }
    }

    /// Finalize to a freshly allocated lowercase-hex string of exactly
    /// `hexLength(algorithm())` bytes. Caller owns the result.
    pub fn finalHexAlloc(self: *MultiHasher, gpa: std.mem.Allocator) std.mem.Allocator.Error![]u8 {
        const out = try gpa.alloc(u8, hexLength(self.algorithm()));
        _ = self.finalHex(out) catch unreachable; // out is exactly hexLength
        return out;
    }
};

/// Hash the file at `path` under `algo` by streaming to EOF (same size-0
/// virtual-file semantics as `sha256File`). Writes lowercase hex into `out`
/// (>= `hexLength(algo)` bytes, checked — `error.ShortBuffer`, never panics).
/// Returns the byte count, or `null` on open/read error.
pub fn hashFile(algo: Algorithm, io: std.Io, path: []const u8, out: []u8) error{ShortBuffer}!?u64 {
    if (out.len < hexLength(algo)) return error.ShortBuffer;
    var file = std.Io.Dir.cwd().openFile(io, path, .{}) catch return null;
    defer file.close(io);
    var buf: [64 * 1024]u8 = undefined;
    var fr = std.Io.File.Reader.initStreaming(file, io, &buf);
    var h = MultiHasher.init(algo);
    var total: u64 = 0;
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n = fr.interface.readSliceShort(&chunk) catch return null;
        if (n == 0) break;
        h.update(chunk[0..n]);
        total += n;
    }
    _ = h.finalHex(out) catch unreachable; // length checked on entry
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

// ── multi-algorithm tests ────────────────────────────────────────────────────

// Official known-answer vectors: NIST FIPS 180-4 (SHA-2), FIPS 202 (SHA-3),
// RFC 7693 / BLAKE2 reference vectors (BLAKE2b-256), official BLAKE3 vectors.
const kat = [_]struct { algo: Algorithm, empty: []const u8, abc: []const u8 }{
    .{ .algo = .sha256, .empty = empty_hex, .abc = abc_hex },
    .{
        .algo = .sha512,
        .empty = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" ++
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        .abc = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" ++
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    },
    .{
        .algo = .sha384,
        .empty = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
        .abc = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
    },
    .{
        .algo = .sha224,
        .empty = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
        .abc = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
    },
    .{
        .algo = .sha512_256,
        .empty = "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
        .abc = "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
    },
    .{
        .algo = .sha3_256,
        .empty = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
        .abc = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    },
    .{
        .algo = .sha3_512,
        .empty = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6" ++
            "15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
        .abc = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e" ++
            "10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    },
    .{
        .algo = .blake2b256,
        .empty = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8",
        .abc = "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    },
    .{
        .algo = .blake3,
        .empty = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        .abc = "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
    },
};

test "hex: known-answer vectors, all algorithms, lowercase" {
    var buf: [max_hex_len]u8 = undefined;
    for (kat) |v| {
        const got_empty = try hex(v.algo, "", &buf);
        try std.testing.expectEqualStrings(v.empty, got_empty);
        const got_abc = try hex(v.algo, "abc", &buf);
        try std.testing.expectEqualStrings(v.abc, got_abc);
        for (got_abc) |c|
            try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'));
    }
}

test "hexAlloc: exact-length allocation, matches vectors" {
    const gpa = std.testing.allocator;
    for (kat) |v| {
        const got = try hexAlloc(gpa, v.algo, "abc");
        defer gpa.free(got);
        try std.testing.expectEqual(hexLength(v.algo), got.len);
        try std.testing.expectEqualStrings(v.abc, got);
    }
}

test "digestLength / hexLength / max_hex_len" {
    try std.testing.expectEqual(@as(usize, 32), digestLength(.sha256));
    try std.testing.expectEqual(@as(usize, 64), digestLength(.sha512));
    try std.testing.expectEqual(@as(usize, 48), digestLength(.sha384));
    try std.testing.expectEqual(@as(usize, 28), digestLength(.sha224));
    try std.testing.expectEqual(@as(usize, 32), digestLength(.sha512_256));
    try std.testing.expectEqual(@as(usize, 32), digestLength(.sha3_256));
    try std.testing.expectEqual(@as(usize, 64), digestLength(.sha3_512));
    try std.testing.expectEqual(@as(usize, 32), digestLength(.blake2b256));
    try std.testing.expectEqual(@as(usize, 32), digestLength(.blake3));
    for (std.enums.values(Algorithm)) |a| {
        try std.testing.expectEqual(digestLength(a) * 2, hexLength(a));
        try std.testing.expect(hexLength(a) <= max_hex_len);
    }
    try std.testing.expectEqual(@as(usize, 128), max_hex_len);
}

test "hexOf comptime form: fixed array, matches runtime hex" {
    const fixed = hexOf(.sha3_256, "abc");
    try std.testing.expectEqual(@as(usize, 64), fixed.len);
    comptime std.debug.assert(HexOf(.sha3_256) == [64]u8);
    var buf: [max_hex_len]u8 = undefined;
    const rt = try hex(.sha3_256, "abc", &buf);
    try std.testing.expectEqualStrings(rt, &fixed);
    // and the multi sha256 path agrees with the legacy SHA-256 names
    const legacy = sha256HexBuf("abc");
    const multi = hexOf(.sha256, "abc");
    try std.testing.expectEqualStrings(&legacy, &multi);
}

test "hex: too-short buffer returns error.ShortBuffer, no panic" {
    var tiny: [10]u8 = undefined;
    try std.testing.expectError(error.ShortBuffer, hex(.sha256, "abc", &tiny));
    var zero: [0]u8 = undefined;
    try std.testing.expectError(error.ShortBuffer, hex(.blake3, "abc", &zero));
    // exactly hexLength is fine
    var exact: [64]u8 = undefined;
    _ = try hex(.sha256, "abc", &exact);
    // 64 is enough for sha256 but short for sha512
    try std.testing.expectError(error.ShortBuffer, hex(.sha512, "abc", &exact));
}

test "MultiHasher: chunked feed equals one-shot (sha512, blake3)" {
    var buf: [max_hex_len]u8 = undefined;
    inline for (.{ Algorithm.sha512, Algorithm.blake3, Algorithm.sha3_256 }) |algo| {
        var h = MultiHasher.init(algo);
        try std.testing.expectEqual(algo, h.algorithm());
        h.update("a");
        h.update("");
        h.update("bc");
        const streamed = try h.finalHex(&buf);
        var one_shot: [max_hex_len]u8 = undefined;
        try std.testing.expectEqualStrings(try hex(algo, "abc", &one_shot), streamed);
    }
    // empty stream equals one-shot of ""
    var h = MultiHasher.init(.blake2b256);
    var empty_out: [max_hex_len]u8 = undefined;
    try std.testing.expectEqualStrings(
        try hex(.blake2b256, "", &empty_out),
        try h.finalHex(&buf),
    );
    // short buffer on finalize errors, no panic
    var h2 = MultiHasher.init(.sha512);
    var tiny: [8]u8 = undefined;
    try std.testing.expectError(error.ShortBuffer, h2.finalHex(&tiny));
}

test "MultiHasher.finalHexAlloc" {
    const gpa = std.testing.allocator;
    var h = MultiHasher.init(.sha3_512);
    h.update("ab");
    h.update("c");
    const got = try h.finalHexAlloc(gpa);
    defer gpa.free(got);
    try std.testing.expectEqual(hexLength(.sha3_512), got.len);
    var buf: [max_hex_len]u8 = undefined;
    try std.testing.expectEqualStrings(try hex(.sha3_512, "abc", &buf), got);
}

test "matchesAlgo: right hex true; wrong, short, uppercase false; no panic" {
    for (kat) |v| {
        try std.testing.expect(matchesAlgo(v.algo, "abc", v.abc));
        try std.testing.expect(matchesAlgo(v.algo, "", v.empty));
        try std.testing.expect(!matchesAlgo(v.algo, "abd", v.abc)); // tampered data
        try std.testing.expect(!matchesAlgo(v.algo, "abc", "deadbeef")); // short garbage
        try std.testing.expect(!matchesAlgo(v.algo, "abc", "")); // empty announced
    }
    // wrong-algorithm digest of the right length is false (sha256 vs sha3_256)
    try std.testing.expect(!matchesAlgo(.sha3_256, "abc", abc_hex));
    // right length but uppercase (we emit lowercase only)
    var upper: [hex_len]u8 = undefined;
    for (abc_hex, 0..) |c, i| upper[i] = std.ascii.toUpper(c);
    try std.testing.expect(!matchesAlgo(.sha256, "abc", &upper));
    // matchesAlgo(.sha256, ...) agrees with legacy matches()
    try std.testing.expectEqual(matches("abc", abc_hex), matchesAlgo(.sha256, "abc", abc_hex));
}

test "hashFile: temp file matches in-memory digest (blake3), count correct" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const data = "The quick brown fox jumps over the lazy dog";
    try tmp.dir.writeFile(io, .{ .sub_path = "hashme3.bin", .data = data });

    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, ".zig-cache/tmp/{s}/hashme3.bin", .{&tmp.sub_path});

    var file_hex: [max_hex_len]u8 = undefined;
    const n = (try hashFile(.blake3, io, path, &file_hex)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u64, data.len), n);

    var mem_hex: [max_hex_len]u8 = undefined;
    try std.testing.expectEqualStrings(
        try hex(.blake3, data, &mem_hex),
        file_hex[0..hexLength(.blake3)],
    );
}

test "hashFile: missing file null; short buffer error; sha256 path matches sha256File" {
    const io = std.testing.io;
    var out: [max_hex_len]u8 = undefined;
    try std.testing.expect((try hashFile(.sha512, io, "no/such/file.bin", &out)) == null);
    var tiny: [16]u8 = undefined;
    try std.testing.expectError(error.ShortBuffer, hashFile(.sha512, io, "no/such/file.bin", &tiny));
    if (builtin.os.tag == .linux) {
        // same read-to-EOF semantics as sha256File on a size-0 virtual file
        var legacy: [hex_len]u8 = undefined;
        const n1 = sha256File(io, "/proc/version", &legacy) orelse return error.SkipZigTest;
        const n2 = (try hashFile(.sha256, io, "/proc/version", &out)) orelse return error.SkipZigTest;
        try std.testing.expectEqual(n1, n2);
        try std.testing.expectEqualStrings(&legacy, out[0..hex_len]);
    }
}
