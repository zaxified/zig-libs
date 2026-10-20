// SPDX-License-Identifier: MIT

//! Comparative benchmark: `encoding` against Rust `encoding_rs` 0.8.42 (the
//! reference AND the fastest implementation in the field: WHATWG semantics,
//! SSE2/AVX2 ASCII and UTF-8 paths) with Go `golang.org/x/text` v0.42.0 as a
//! second column -- the program behind the `**Performance:**` line of the
//! maturity card (CONVENTIONS.md §9, kept instrument kind 3).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build bench-encoding` runs it (always
//! ReleaseFast); `zig build check-interop` compiles it. Run from the repository
//! root. Needs `go` (x/text from the module cache, built offline, `GOPROXY=off`;
//! `tools/go_bench`) and `cargo` (`tools/rust_bench`, encoding_rs pinned
//! `=0.8.42`, `Cargo.lock` committed, built `--locked --offline` with
//! `RUSTFLAGS=-C target-cpu=native` -- our side is built for the native CPU too
//! -- into `.zig-cache/bench-encoding/target`; run `cargo fetch` once for the
//! registry).
//!
//! The data is generated once (seeded PRNG) into `.zig-cache/bench-encoding/
//! *-v1.*` and read by all three sides from the same files; an existing file is
//! reused (bump the `-v1` suffix here and in both foreign programs if a
//! generator changes). Inputs are 32 MiB (cells: 1 000 000 x 20 bytes).
//!
//!   dec_1250_ascii  windows-1250 -> UTF-8, 100 % ASCII
//!   dec_1250_czech  windows-1250 -> UTF-8, 10 % high bytes (21 Czech letters)
//!   enc_1250_ascii  UTF-8 -> windows-1250, 100 % ASCII          (extra row)
//!   enc_1250_czech  UTF-8 -> windows-1250, the same Czech text, 10 % non-ASCII
//!   enc_1250_unmap  the same plus 1 % unmappable characters (U+03A9, U+00F1,
//!                   U+6F22, U+1F600) -> `?`
//!   dec_utf8_ascii  UTF-8 decode (replacement), pure ASCII
//!   dec_utf8_multi  valid multilingual text (ASCII, Latin, Cyrillic, Greek,
//!                   Hebrew, Arabic, CJK, emoji; 1-4 byte sequences)
//!   dec_utf8_bad    the same kind of text with ~5 % invalid bytes inserted
//!                   (0xFF 0xFE 0xC0 0xC1 0xF5 0x80 0xBF at character boundaries:
//!                   each is exactly one maximal subpart, so a per-byte and a
//!                   maximal-subpart replacer agree -- truncated sequences are
//!                   the normative tests' business, not the bench's)
//!   u16_to_utf8     UTF-16LE -> UTF-8 (the multilingual text, with surrogate pairs)
//!   utf8_to_u16     UTF-8 -> UTF-16LE
//!   stream_1250     the streaming `Decoder` over 4 KiB chunks vs encoding_rs
//!                   `Decoder::decode_to_utf8` (Czech windows-1250)
//!   stream_utf8     the same for the multilingual UTF-8 (sequences split by
//!                   the chunk boundaries)
//!   cell_dec        1 000 000 20-byte windows-1250 cells (Czech mix), one
//!                   whole-buffer decode per cell
//!   cell_enc        the same cells as UTF-8, one whole-buffer encode per cell
//!   dec_sjis/euckr/gb18030/big5  `encoding.cjk` decode of ~16-22 MiB of two-byte
//!                   text (~10 % ASCII; ranges all three sides agree on, see the
//!                   generator); enc_* the same text as UTF-8 -> legacy bytes
//!   dec_iso2022jp / enc_iso2022jp  ASCII words + kanji + kana runs (escapes)
//!   stream_sjis     the streaming `cjk.Decoder` over 4 KiB chunks (Shift_JIS)
//!
//! Every op is the whole input through the whole-buffer API and leaves an OWNED
//! output allocated for that op (ours `page_allocator` for the 32 MiB rows --
//! mmap/munmap like glibc's large allocations -- `smp_allocator` for the cells;
//! encoding_rs `into_owned()` where it would return a borrowed `Cow`; Go
//! `Bytes()`). The output length is the op's count. The streaming rows reuse one
//! output buffer drained per chunk on every side.
//!
//! HOW THE ROWS ARE MADE COMPARABLE where the default behaviours differ:
//!   * Unmappable characters: encoding_rs' `encode` writes an HTML numeric
//!     reference (`&#128512;`), x/text's `ReplaceUnsupported` the byte 0x1A, ours
//!     `?`. The foreign sides therefore run the encoder RAW and write `?`
//!     themselves (encoding_rs: `encode_from_utf8_without_replacement` in a
//!     loop; x/text: `Transform` in a loop on its RepertoireError).
//!   * UTF-16 output: encoding_rs has no UTF-16 encoder in its Encoding API
//!     (`output_encoding()` of UTF-16 is UTF-8); it uses `mem::convert_str_to_utf16`
//!     into a `Vec<u16>` whose little-endian bytes are compared.
//!   * encoding_rs' encoders take `&str`: its input is validated once, untimed
//!     (ours takes bytes and treats invalid ones as a pass-through case).
//!
//! BEFORE ANYTHING IS TIMED each foreign program runs in `check` mode and its
//! output length and FNV-1a-64 over the whole output must equal ours on every
//! selected row, for BOTH foreign sides, or the bench fails. (Also: our decode
//! of the windows-1250 file must equal the UTF-8 file generated beside it.) The
//! sides then alternate for BENCH_ROUNDS (default 3) rounds, each keeping its
//! best of five batches; ratio = ours/theirs by wall time; the verdict is the
//! worst row against encoding_rs. GB/s = input bytes / best time. Arguments
//! filter workloads (substring).

const std = @import("std");
const bench = @import("testkit").bench;
const encoding = @import("encoding");

const bench_name = "bench-encoding";
const work_dir = ".zig-cache/bench-encoding";
const go_dir = "modules/encoding/tools/go_bench";
const cargo_manifest = "modules/encoding/tools/rust_bench/Cargo.toml";

const big: usize = 32 << 20;
const n_cells = 1_000_000;
const cell_len = 20;
const chunk = 4096;

const fnv_off: u64 = 0xcbf29ce484222325;
const fnv_prime: u64 = 0x100000001b3;

const cjk = encoding.cjk;
const Kind = enum { dec1250, decutf8, u16dec, u16enc, enc1250, stream1250, streamutf8, celldec, cellenc, cjkdec, cjkenc, streamcjk };
const Work = struct { name: []const u8, kind: Kind, file: []const u8, cjk: cjk.Cjk = .shift_jis };
const works = [_]Work{
    .{ .name = "dec_1250_ascii", .kind = .dec1250, .file = "ascii-v1.bin" },
    .{ .name = "dec_1250_czech", .kind = .dec1250, .file = "cz1250-v1.bin" },
    .{ .name = "enc_1250_ascii", .kind = .enc1250, .file = "ascii-v1.bin" },
    .{ .name = "enc_1250_czech", .kind = .enc1250, .file = "czutf8-v1.txt" },
    .{ .name = "enc_1250_unmap", .kind = .enc1250, .file = "unmap-v1.txt" },
    .{ .name = "dec_utf8_ascii", .kind = .decutf8, .file = "ascii-v1.bin" },
    .{ .name = "dec_utf8_multi", .kind = .decutf8, .file = "multi-v1.txt" },
    .{ .name = "dec_utf8_bad", .kind = .decutf8, .file = "bad-v1.txt" },
    .{ .name = "u16_to_utf8", .kind = .u16dec, .file = "multi16-v1.bin" },
    .{ .name = "utf8_to_u16", .kind = .u16enc, .file = "multi-v1.txt" },
    .{ .name = "stream_1250", .kind = .stream1250, .file = "cz1250-v1.bin" },
    .{ .name = "stream_utf8", .kind = .streamutf8, .file = "multi-v1.txt" },
    .{ .name = "cell_dec", .kind = .celldec, .file = "cells1250-v1.bin" },
    .{ .name = "cell_enc", .kind = .cellenc, .file = "cellsutf8-v1.bin" },
    .{ .name = "dec_sjis", .kind = .cjkdec, .file = "cjk-sjis-v1.bin", .cjk = .shift_jis },
    .{ .name = "enc_sjis", .kind = .cjkenc, .file = "cjk-sjis-v1.txt", .cjk = .shift_jis },
    .{ .name = "dec_euckr", .kind = .cjkdec, .file = "cjk-euckr-v1.bin", .cjk = .euc_kr },
    .{ .name = "enc_euckr", .kind = .cjkenc, .file = "cjk-euckr-v1.txt", .cjk = .euc_kr },
    .{ .name = "dec_gb18030", .kind = .cjkdec, .file = "cjk-gb18030-v1.bin", .cjk = .gb18030 },
    .{ .name = "enc_gb18030", .kind = .cjkenc, .file = "cjk-gb18030-v1.txt", .cjk = .gb18030 },
    .{ .name = "dec_big5", .kind = .cjkdec, .file = "cjk-big5-v1.bin", .cjk = .big5 },
    .{ .name = "enc_big5", .kind = .cjkenc, .file = "cjk-big5-v1.txt", .cjk = .big5 },
    .{ .name = "dec_iso2022jp", .kind = .cjkdec, .file = "cjk-iso2022jp-v1.bin", .cjk = .iso_2022_jp },
    .{ .name = "enc_iso2022jp", .kind = .cjkenc, .file = "cjk-iso2022jp-v1.txt", .cjk = .iso_2022_jp },
    .{ .name = "stream_sjis", .kind = .streamcjk, .file = "cjk-sjis-v1.bin", .cjk = .shift_jis },
};

/// Output sink: the length always, FNV-1a-64 only in check mode.
const Out = struct {
    n: u64 = 0,
    h: u64 = fnv_off,
    hashing: bool = false,

    inline fn take(o: *Out, s: []const u8) void {
        o.n += s.len;
        if (o.hashing) {
            var h = o.h;
            for (s) |b| h = (h ^ b) *% fnv_prime;
            o.h = h;
        } else std.mem.doNotOptimizeAway(s.len);
    }
};

const Ctx = struct {
    op: usize = 0,
    data: []const u8 = &.{},
    cells: []const []const u8 = &.{},
};

fn run(c: *const Ctx, wk: Work, o: *Out) void {
    const a = if (wk.kind == .celldec or wk.kind == .cellenc) std.heap.smp_allocator else std.heap.page_allocator;
    switch (wk.kind) {
        .dec1250 => {
            const r = encoding.decodeToUtf8(a, c.data, .windows_1250) catch @panic("oom");
            o.take(r);
            a.free(r);
        },
        .decutf8 => {
            const r = encoding.decodeToUtf8(a, c.data, .utf8) catch @panic("oom");
            o.take(r);
            a.free(r);
        },
        .u16dec => {
            const r = encoding.decodeUtf16(a, c.data, .le) catch @panic("oom");
            o.take(r);
            a.free(r);
        },
        .u16enc => {
            const r = encoding.encodeUtf16(a, c.data, .le, false) catch @panic("oom");
            o.take(r);
            a.free(r);
        },
        .enc1250 => {
            const r = encoding.encodeFromUtf8(a, c.data, .windows_1250) catch @panic("oom");
            o.take(r);
            a.free(r);
        },
        .cjkdec => {
            const r = cjk.decodeToUtf8(a, c.data, wk.cjk) catch @panic("oom");
            o.take(r);
            a.free(r);
        },
        .cjkenc => {
            const r = cjk.encodeFromUtf8(a, c.data, wk.cjk, .{}) catch @panic("oom");
            o.take(r);
            a.free(r);
        },
        .streamcjk => {
            var d: cjk.Decoder = .init(wk.cjk, .{});
            var buf: std.ArrayList(u8) = .empty;
            defer buf.deinit(a);
            buf.ensureTotalCapacity(a, 3 * chunk + 16) catch @panic("oom");
            var i: usize = 0;
            while (i < c.data.len) {
                const e = @min(i + chunk, c.data.len);
                d.feed(a, &buf, c.data[i..e]) catch @panic("feed");
                o.take(buf.items);
                buf.clearRetainingCapacity();
                i = e;
            }
            d.finish(a, &buf) catch @panic("finish");
            o.take(buf.items);
        },
        .stream1250, .streamutf8 => {
            var d: encoding.Decoder = .init(.{ .encoding = if (wk.kind == .stream1250) .windows_1250 else .utf8 }, .{});
            var buf: std.ArrayList(u8) = .empty;
            defer buf.deinit(a);
            buf.ensureTotalCapacity(a, 3 * chunk + 8) catch @panic("oom");
            var i: usize = 0;
            while (i < c.data.len) {
                const e = @min(i + chunk, c.data.len);
                d.feed(a, &buf, c.data[i..e]) catch @panic("feed");
                o.take(buf.items);
                buf.clearRetainingCapacity();
                i = e;
            }
            d.finish(a, &buf) catch @panic("finish");
            o.take(buf.items);
        },
        .celldec => for (c.cells) |cell| {
            const r = encoding.decodeToUtf8(a, cell, .windows_1250) catch @panic("oom");
            o.take(r);
            a.free(r);
        },
        .cellenc => for (c.cells) |cell| {
            const r = encoding.encodeFromUtf8(a, cell, .windows_1250) catch @panic("oom");
            o.take(r);
            a.free(r);
        },
    }
}

fn once(c: *Ctx) u64 {
    var o: Out = .{};
    run(c, works[c.op], &o);
    return o.n;
}

// ── data generator ───────────────────────────────────────────────────────────

const Czech = struct { b: u8, cp: u21 };
const czech = [_]Czech{
    .{ .b = 0xE1, .cp = 0xE1 },  .{ .b = 0xE8, .cp = 0x10D }, .{ .b = 0xEF, .cp = 0x10F }, .{ .b = 0xE9, .cp = 0xE9 },
    .{ .b = 0xEC, .cp = 0x11B }, .{ .b = 0xED, .cp = 0xED },  .{ .b = 0xF2, .cp = 0x148 }, .{ .b = 0xF3, .cp = 0xF3 },
    .{ .b = 0xF8, .cp = 0x159 }, .{ .b = 0x9A, .cp = 0x161 }, .{ .b = 0x9D, .cp = 0x165 }, .{ .b = 0xFA, .cp = 0xFA },
    .{ .b = 0xF9, .cp = 0x16F }, .{ .b = 0xFD, .cp = 0xFD },  .{ .b = 0x9E, .cp = 0x17E }, .{ .b = 0xC1, .cp = 0xC1 },
    .{ .b = 0xC8, .cp = 0x10C }, .{ .b = 0xCC, .cp = 0x11A }, .{ .b = 0x8A, .cp = 0x160 }, .{ .b = 0xD8, .cp = 0x158 },
    .{ .b = 0x8E, .cp = 0x17D },
};
const unmappable = [_]u21{ 0x3A9, 0xF1, 0x6F22, 0x1F600 };
const bad_bytes = [_]u8{ 0xFF, 0xFE, 0xC0, 0xC1, 0xF5, 0x80, 0xBF };

const FileSink = struct {
    f: std.Io.File,
    buf: [64 * 1024]u8 = undefined,
    fw: std.Io.File.Writer = undefined,

    fn open(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8) !*FileSink {
        const s = try arena.create(FileSink);
        s.f = try dir.createFile(io, name, .{});
        s.fw = s.f.writer(io, &s.buf);
        return s;
    }
    fn w(s: *FileSink) *std.Io.Writer {
        return &s.fw.interface;
    }
    fn close(s: *FileSink, io: std.Io) !void {
        try s.fw.interface.flush();
        s.f.close(io);
    }
};

fn exists(io: std.Io, dir: std.Io.Dir, names: []const []const u8) bool {
    for (names) |n| {
        const f = dir.openFile(io, n, .{}) catch return false;
        f.close(io);
    }
    return true;
}

fn asciiChar(r: std.Random) u8 {
    const x = r.uintLessThan(u8, 100);
    if (x < 75) return 'a' + r.uintLessThan(u8, 26);
    if (x < 80) return 'A' + r.uintLessThan(u8, 26);
    if (x < 94) return ' ';
    if (x < 96) return ',';
    if (x < 97) return '.';
    if (x < 98) return '\n';
    return '0' + r.uintLessThan(u8, 10);
}

fn putUtf8(w: *std.Io.Writer, cp: u21) !void {
    var b: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(cp, &b) catch unreachable;
    try w.writeAll(b[0..n]);
}

fn putUtf16(w: *std.Io.Writer, cp: u21) !void {
    if (cp >= 0x10000) {
        const v = cp - 0x10000;
        try w.writeInt(u16, @intCast(0xD800 + (v >> 10)), .little);
        try w.writeInt(u16, @intCast(0xDC00 + (v & 0x3FF)), .little);
    } else try w.writeInt(u16, @intCast(cp), .little);
}

fn genAscii(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    if (exists(io, dir, &.{"ascii-v1.bin"})) return;
    std.debug.print("{s}: generating ascii-v1.bin ...\n", .{bench_name});
    var prng = std.Random.DefaultPrng.init(0x656e_6301);
    const r = prng.random();
    const s = try FileSink.open(arena, io, dir, "ascii-v1.bin");
    for (0..big) |_| try s.w().writeByte(asciiChar(r));
    try s.close(io);
}

/// Czech-like text: 10 % of the characters are one of 21 Czech letters, the
/// rest ASCII. `w1250` gets the windows-1250 bytes (one per character),
/// `w8` the UTF-8. With `unmap_pm` > 0 that many per mille of the characters are
/// unmappable ones (UTF-8 output only).
fn genCzech(r: std.Random, n_chars: usize, unmap_pm: u16, w1250: ?*std.Io.Writer, w8: *std.Io.Writer) !void {
    for (0..n_chars) |_| {
        const x = r.uintLessThan(u16, 1000);
        if (x < unmap_pm) {
            try putUtf8(w8, unmappable[r.uintLessThan(usize, unmappable.len)]);
        } else if (x < unmap_pm + 100) {
            const cz = czech[r.uintLessThan(usize, czech.len)];
            if (w1250) |w| try w.writeByte(cz.b);
            try putUtf8(w8, cz.cp);
        } else {
            const c = asciiChar(r);
            if (w1250) |w| try w.writeByte(c);
            try w8.writeByte(c);
        }
    }
}

fn genCz(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    if (!exists(io, dir, &.{ "cz1250-v1.bin", "czutf8-v1.txt" })) {
        std.debug.print("{s}: generating cz1250-v1.bin, czutf8-v1.txt ...\n", .{bench_name});
        var prng = std.Random.DefaultPrng.init(0x656e_6302);
        const a = try FileSink.open(arena, io, dir, "cz1250-v1.bin");
        const b = try FileSink.open(arena, io, dir, "czutf8-v1.txt");
        try genCzech(prng.random(), big, 0, a.w(), b.w());
        try a.close(io);
        try b.close(io);
    }
    if (!exists(io, dir, &.{"unmap-v1.txt"})) {
        std.debug.print("{s}: generating unmap-v1.txt ...\n", .{bench_name});
        var prng = std.Random.DefaultPrng.init(0x656e_6303);
        const b = try FileSink.open(arena, io, dir, "unmap-v1.txt");
        try genCzech(prng.random(), big, 10, null, b.w());
        try b.close(io);
    }
}

/// One multilingual codepoint run (a "word" of 2..9 characters in one script).
fn multiWord(r: std.Random, w8: *std.Io.Writer, w16: ?*std.Io.Writer, bad_pct: u8, written: *usize) !void {
    const script = r.uintLessThan(u8, 100);
    const len = r.intRangeAtMost(u8, 2, 9);
    for (0..len + 1) |i| {
        var cp: u21 = ' ';
        if (i < len) cp = if (script < 55)
            asciiChar(r)
        else if (script < 65)
            (if (r.boolean()) asciiChar(r) else ([_]u21{ 0xE9, 0xFC, 0xDF, 0xF1, 0xF8, 0xE5, 0x142, 0x159 })[r.uintLessThan(usize, 8)])
        else if (script < 75)
            r.intRangeAtMost(u21, 0x430, 0x44F)
        else if (script < 80)
            r.intRangeAtMost(u21, 0x3B1, 0x3C9)
        else if (script < 85)
            r.intRangeAtMost(u21, 0x5D0, 0x5EA)
        else if (script < 90)
            r.intRangeAtMost(u21, 0x627, 0x64A)
        else if (script < 96)
            r.intRangeAtMost(u21, 0x4E00, 0x9FA5)
        else
            r.intRangeAtMost(u21, 0x1F600, 0x1F64F);
        try putUtf8(w8, cp);
        written.* += std.unicode.utf8CodepointSequenceLength(cp) catch unreachable;
        if (w16) |w| try putUtf16(w, cp);
        if (bad_pct != 0 and r.uintLessThan(u8, 100) < bad_pct) {
            try w8.writeByte(bad_bytes[r.uintLessThan(usize, bad_bytes.len)]);
            written.* += 1;
        }
    }
}

fn genMulti(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    if (!exists(io, dir, &.{ "multi-v1.txt", "multi16-v1.bin" })) {
        std.debug.print("{s}: generating multi-v1.txt, multi16-v1.bin ...\n", .{bench_name});
        var prng = std.Random.DefaultPrng.init(0x656e_6304);
        const a = try FileSink.open(arena, io, dir, "multi-v1.txt");
        const b = try FileSink.open(arena, io, dir, "multi16-v1.bin");
        var n: usize = 0;
        while (n < big) try multiWord(prng.random(), a.w(), b.w(), 0, &n);
        try a.close(io);
        try b.close(io);
    }
    if (!exists(io, dir, &.{"bad-v1.txt"})) {
        std.debug.print("{s}: generating bad-v1.txt ...\n", .{bench_name});
        var prng = std.Random.DefaultPrng.init(0x656e_6305);
        const a = try FileSink.open(arena, io, dir, "bad-v1.txt");
        var n: usize = 0;
        while (n < big) try multiWord(prng.random(), a.w(), null, 8, &n);
        try a.close(io);
    }
}

fn genCells(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    if (exists(io, dir, &.{ "cells1250-v1.bin", "cellsutf8-v1.bin" })) return;
    std.debug.print("{s}: generating cells ...\n", .{bench_name});
    var prng = std.Random.DefaultPrng.init(0x656e_6306);
    const r = prng.random();
    const a = try FileSink.open(arena, io, dir, "cells1250-v1.bin");
    const b = try FileSink.open(arena, io, dir, "cellsutf8-v1.bin");
    var c1250: [cell_len]u8 = undefined;
    var c8: [4 * cell_len]u8 = undefined;
    for (0..n_cells) |_| {
        var w8: std.Io.Writer = .fixed(&c8);
        for (&c1250) |*ch| {
            if (r.uintLessThan(u8, 100) < 10) {
                const cz = czech[r.uintLessThan(usize, czech.len)];
                ch.* = cz.b;
                try putUtf8(&w8, cz.cp);
            } else {
                ch.* = asciiChar(r);
                try w8.writeByte(ch.*);
            }
        }
        try a.w().writeByte(cell_len);
        try a.w().writeAll(&c1250);
        try b.w().writeByte(@intCast(w8.end));
        try b.w().writeAll(w8.buffered());
    }
    try a.close(io);
    try b.close(io);
}

// ── CJK data ─────────────────────────────────────────────────────────────────
//
// Text of the script's own kind: ~10 % ASCII, the rest two-byte characters
// drawn from the ranges where all three implementations agree (JIS X 0208
// level 1 kanji + kana, KS X 1001 hangul, GB2312 hanzi, Big5 frequent hanzi;
// no gb18030 four-byte forms and no 2022 additions -- x/text lags GB18030-2022).
// The legacy bytes are made by OUR encoder from the UTF-8 text and verified by
// our strict decoder (round trip) at generation time; every side then decodes
// the same file and the pre-check compares the three outputs.

const CjkSpec = struct { enc: cjk.Cjk, bin: []const u8, txt: []const u8, seed: u64 };
const cjk_specs = [_]CjkSpec{
    .{ .enc = .shift_jis, .bin = "cjk-sjis-v1.bin", .txt = "cjk-sjis-v1.txt", .seed = 0x656e_6310 },
    .{ .enc = .euc_kr, .bin = "cjk-euckr-v1.bin", .txt = "cjk-euckr-v1.txt", .seed = 0x656e_6311 },
    .{ .enc = .gb18030, .bin = "cjk-gb18030-v1.bin", .txt = "cjk-gb18030-v1.txt", .seed = 0x656e_6312 },
    .{ .enc = .big5, .bin = "cjk-big5-v1.bin", .txt = "cjk-big5-v1.txt", .seed = 0x656e_6313 },
    .{ .enc = .iso_2022_jp, .bin = "cjk-iso2022jp-v1.bin", .txt = "cjk-iso2022jp-v1.txt", .seed = 0x656e_6314 },
};
const cjk_utf8_target: usize = 24 << 20;

const SjisClass = enum { hiragana, katakana, kanji };

fn sjisPair(r: std.Random, class: SjisClass) [2]u8 {
    switch (class) {
        .hiragana => return .{ 0x82, 0x9F + r.uintLessThan(u8, 83) },
        .katakana => {
            var t: u8 = 0x40 + r.uintLessThan(u8, 86);
            if (t >= 0x7F) t += 1;
            return .{ 0x83, t };
        },
        .kanji => {
            var t: u8 = 0x40 + r.uintLessThan(u8, 188);
            if (t >= 0x7F) t += 1;
            return .{ 0x89 + r.uintLessThan(u8, 15), t };
        },
    }
}

fn cjkPair(r: std.Random, enc: cjk.Cjk) [2]u8 {
    switch (enc) {
        .shift_jis => {
            const x = r.uintLessThan(u8, 100);
            return sjisPair(r, if (x < 12) .hiragana else if (x < 25) .katakana else .kanji);
        },
        .euc_kr => return .{ 0xB0 + r.uintLessThan(u8, 25), 0xA1 + r.uintLessThan(u8, 94) },
        .gb18030 => {
            const n = r.uintLessThan(u8, 71);
            return .{ if (n < 39) 0xB0 + n else 0xD8 + (n - 39), 0xA1 + r.uintLessThan(u8, 94) };
        },
        .big5 => {
            const n = r.uintLessThan(u8, 157);
            return .{ 0xA4 + r.uintLessThan(u8, 34), if (n < 63) 0x40 + n else 0xA1 + (n - 63) };
        },
        else => unreachable,
    }
}

/// The code point of a two-byte character (our strict decoder; any error is a
/// generator bug).
fn pairCp(enc: cjk.Cjk, pair: [2]u8) u21 {
    var d: cjk.Decoder = .init(enc, .{ .fatal = true });
    var out: [16]u8 = undefined;
    const p = d.decodeInto(&pair, &out, true);
    if (p.status != .input_empty or p.written == 0 or p.replaced) @panic("cjk generator: pair does not decode");
    return std.unicode.utf8Decode(out[0..p.written]) catch @panic("cjk generator: utf8");
}

fn appendCp(a: std.mem.Allocator, v: *std.ArrayList(u8), cp: u21) !void {
    var b: [4]u8 = undefined;
    const n = std.unicode.utf8Encode(cp, &b) catch unreachable;
    try v.appendSlice(a, b[0..n]);
}

/// Big5 maps some characters from two pointers (the HKSCS compatibility rows);
/// the Standard's encoder takes the LAST, x/text's the other, both valid. The
/// generator drops those characters (a cell in `dup` is any code point decoded
/// from more than one two-byte pair).
fn big5Duplicates(a: std.mem.Allocator) !std.AutoHashMap(u21, u8) {
    var m: std.AutoHashMap(u21, u8) = .init(a);
    var lead: u16 = 0x81;
    while (lead <= 0xFE) : (lead += 1) {
        var trail: u16 = 0x40;
        while (trail <= 0xFE) : (trail += 1) {
            if (trail > 0x7E and trail < 0xA1) continue;
            var d: cjk.Decoder = .init(.big5, .{ .fatal = true });
            var out: [16]u8 = undefined;
            const pair = [2]u8{ @intCast(lead), @intCast(trail) };
            const p = d.decodeInto(&pair, &out, true);
            if (p.status != .input_empty or p.written == 0) continue;
            const cp = std.unicode.utf8Decode(out[0..p.written]) catch continue; // two-code-point pointers
            const e = try m.getOrPut(cp);
            e.value_ptr.* = if (e.found_existing) 2 else 1;
        }
    }
    return m;
}

fn genCjkText(a: std.mem.Allocator, r: std.Random, enc: cjk.Cjk) !std.ArrayList(u8) {
    var dup: std.AutoHashMap(u21, u8) = if (enc == .big5) try big5Duplicates(a) else .init(a);
    defer dup.deinit();
    var v: std.ArrayList(u8) = .empty;
    try v.ensureTotalCapacity(a, cjk_utf8_target + 64);
    if (enc == .iso_2022_jp) {
        // ASCII words, then kanji and kana runs: every switch is an escape sequence.
        while (v.items.len < cjk_utf8_target) {
            for (0..r.intRangeAtMost(u8, 3, 8)) |_| {
                const c = asciiChar(r);
                try v.append(a, if (c == '\n') ' ' else c);
            }
            for (0..r.intRangeAtMost(u8, 1, 5)) |_| try appendCp(a, &v, pairCp(.shift_jis, sjisPair(r, .kanji)));
            for (0..r.intRangeAtMost(u8, 1, 4)) |_| try appendCp(a, &v, pairCp(.shift_jis, sjisPair(r, if (r.boolean()) .hiragana else .katakana)));
        }
        return v;
    }
    while (v.items.len < cjk_utf8_target) {
        if (r.uintLessThan(u8, 100) < 10) {
            try v.append(a, asciiChar(r));
        } else {
            const cp = pairCp(enc, cjkPair(r, enc));
            if (dup.get(cp) orelse 1 > 1) continue;
            try appendCp(a, &v, cp);
        }
    }
    return v;
}

fn genCjk(arena: std.mem.Allocator, io: std.Io, dir: std.Io.Dir) !void {
    const pa = std.heap.page_allocator;
    for (cjk_specs) |sp| {
        if (exists(io, dir, &.{ sp.bin, sp.txt })) continue;
        std.debug.print("{s}: generating {s}, {s} ...\n", .{ bench_name, sp.bin, sp.txt });
        var prng = std.Random.DefaultPrng.init(sp.seed);
        var txt = try genCjkText(pa, prng.random(), sp.enc);
        defer txt.deinit(pa);
        const bin = try cjk.encodeFromUtf8(pa, txt.items, sp.enc, .{ .unmappable = .fatal });
        defer pa.free(bin);
        const back = try cjk.decodeFatal(pa, bin, sp.enc);
        defer pa.free(back);
        if (!std.mem.eql(u8, back, txt.items)) @panic("cjk generator: round trip differs");
        const a = try FileSink.open(arena, io, dir, sp.bin);
        try a.w().writeAll(bin);
        try a.close(io);
        const b = try FileSink.open(arena, io, dir, sp.txt);
        try b.w().writeAll(txt.items);
        try b.close(io);
    }
}

fn splitCells(arena: std.mem.Allocator, data: []const u8) ![]const []const u8 {
    var v: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < data.len) {
        const n = data[i];
        try v.append(arena, data[i + 1 ..][0..n]);
        i += 1 + n;
    }
    return v.items;
}

// ── check mode ───────────────────────────────────────────────────────────────

const Check = struct { n: u64, h: u64 };

fn foreignCheck(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8, name: []const u8) !Check {
    const res = try std.process.run(arena, io, .{ .argv = &.{ exe, abs, name, "check" } });
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} check of {s} failed:\n{s}\n", .{ bench_name, exe, name, res.stderr });
        return error.ForeignFailed;
    }
    var it = std.mem.tokenizeAny(u8, res.stdout, " \n");
    const n = try std.fmt.parseInt(u64, it.next() orelse return error.BadForeignOutput, 10);
    const h = try std.fmt.parseInt(u64, it.next() orelse return error.BadForeignOutput, 10);
    return .{ .n = n, .h = h };
}

fn runCmd(arena: std.mem.Allocator, io: std.Io, argv: []const []const u8, env: ?*const std.process.Environ.Map, what: []const u8) !void {
    const res = std.process.run(arena, io, .{ .argv = argv, .environ_map = env }) catch |e| {
        std.debug.print("{s}: could not run {s} ({t}) -- the benchmark needs it\n", .{ bench_name, argv[0], e });
        return error.BuildFailed;
    };
    if (res.term != .exited or res.term.exited != 0) {
        std.debug.print("{s}: {s} failed:\n{s}\n", .{ bench_name, what, res.stderr });
        return error.BuildFailed;
    }
}

fn setData(c: *Ctx, io: std.Io, arena: std.mem.Allocator, wk: Work) !void {
    var b: [128]u8 = undefined;
    const p = try std.fmt.bufPrint(&b, work_dir ++ "/{s}", .{wk.file});
    c.data = try std.Io.Dir.cwd().readFileAlloc(io, p, arena, .limited(1 << 28));
    c.cells = if (wk.kind == .celldec or wk.kind == .cellenc) try splitCells(arena, c.data) else &.{};
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};
    const rounds: usize = if (init.environ_map.get("BENCH_ROUNDS")) |r| try std.fmt.parseInt(usize, r, 10) else 3;

    try genAscii(arena, io, dir);
    try genCz(arena, io, dir);
    try genMulti(arena, io, dir);
    try genCells(arena, io, dir);
    try genCjk(arena, io, dir);

    const gexe = try bench.goBuild(arena, io, bench_name, init.environ_map, .{ .exe = "go", .dir = go_dir, .abs = abs });
    var env = try init.environ_map.clone(arena);
    const target = try arena.print("{s}/target", .{abs});
    try env.put("CARGO_TARGET_DIR", target);
    try env.put("RUSTFLAGS", "-C target-cpu=native");
    std.debug.print("{s}: building the Rust side ...\n", .{bench_name});
    runCmd(arena, io, &.{ "cargo", "build", "--release", "--locked", "--offline", "--quiet", "--manifest-path", cargo_manifest }, &env, "cargo build (cargo fetch once for the registry)") catch return 1;
    const rexe = try arena.print("{s}/release/rust_bench", .{target});

    var ctx: Ctx = .{};
    var sizes: [works.len]u64 = undefined;
    var wbuf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &wbuf);
    const w = &stdout.interface;

    // Generator self-check: our decode of the windows-1250 file is the UTF-8 file.
    {
        var a = Ctx{};
        try setData(&a, io, arena, works[1]);
        const dec = try encoding.decodeToUtf8(arena, a.data, .windows_1250);
        var b = Ctx{};
        try setData(&b, io, arena, works[3]);
        if (!std.mem.eql(u8, dec, b.data)) {
            try w.writeAll(bench_name ++ ": FAILED -- cz1250-v1.bin does not decode to czutf8-v1.txt (generator table)\n");
            try w.flush();
            return 1;
        }
    }

    // ── pre-check: both foreign sides against ours, per selected row ─────────
    for (works, 0..) |wk, wi| {
        if (!bench.selected(wk.name, filters)) continue;
        try setData(&ctx, io, arena, wk);
        sizes[wi] = ctx.data.len;
        var o: Out = .{ .hashing = true };
        run(&ctx, wk, &o);
        const r = try foreignCheck(arena, io, rexe, abs, wk.name);
        const g = try foreignCheck(arena, io, gexe, abs, wk.name);
        const rok = r.n == o.n and r.h == o.h;
        const gok = g.n == o.n and g.h == o.h;
        try w.print("pre-check {s:<15} ours {d} {x}; encoding_rs {d} {x} {s}; x/text {d} {x} {s}\n", .{
            wk.name, o.n, o.h,
            r.n,     r.h, if (rok) "agree" else "DISAGREE",
            g.n,     g.h, if (gok) "agree" else "DISAGREE",
        });
        try w.flush();
        if (!rok or !gok) {
            try w.print("{s}: FAILED -- {s} disagrees with a foreign side\n", .{ bench_name, wk.name });
            try w.flush();
            return 1;
        }
    }

    // ── timing ───────────────────────────────────────────────────────────────
    const cyc: bench.Cycles = .open();
    var s: bench.Summary = .{};
    var worst_go: f64 = 0;
    try w.print("{s:<15} {s:>12} {s:>12} {s:>12} {s:>8} {s:>8} {s:>7} {s:>7} {s:>7} {s:>6} {s:>6} {s:>6}\n", .{ "workload", "ours ns", "rs ns", "go ns", "ours/rs", "ours/go", "ours", "rs", "go", "spr us", "spr rs", "spr go" });
    try w.print("{s:<15} {s:>12} {s:>12} {s:>12} {s:>8} {s:>8} {s:>7} {s:>7} {s:>7}\n", .{ "", "", "", "", "", "", "GB/s", "GB/s", "GB/s" });
    try w.flush();
    for (works, 0..) |wk, wi| {
        if (!bench.selected(wk.name, filters)) continue;
        try setData(&ctx, io, arena, wk);
        ctx.op = wi;
        var ours: bench.Side = .{};
        var rs: bench.Side = .{};
        var go: bench.Side = .{};
        for (0..rounds) |_| {
            rs.add(try bench.foreign(arena, io, bench_name, rexe, abs, wk.name, &s.banner));
            ours.add(bench.timeIt(io, cyc, once, .{&ctx}, true));
            go.add(try bench.foreign(arena, io, bench_name, gexe, abs, wk.name, &s.alt_banner));
        }
        const l = bench.score(ours, rs, go, false);
        s.add(l);
        const r_go = ours.best_ns / go.best_ns;
        worst_go = @max(worst_go, r_go);
        const in: f64 = @floatFromInt(sizes[wi]);
        try w.print("{s:<15} {d:>12.0} {d:>12.0} {d:>12.0} {d:>8.3} {d:>8.3} {d:>7.2} {d:>7.2} {d:>7.2} {d:>5.1}% {d:>5.1}% {d:>5.1}%{s}\n", .{
            wk.name,                  ours.best_ns,           rs.best_ns,
            go.best_ns,               l.ref,                  r_go,
            in / ours.best_ns,        in / rs.best_ns,        in / go.best_ns,
            100 * ours.spread(false), 100 * rs.spread(false), 100 * go.spread(false),
            if (!l.same_count) " ≠" else "",
        });
        try w.flush();
    }
    try w.print("rounds: {d}; ratios by wall time; largest spread {d:.1}%{s}\n", .{ rounds, 100 * s.max_spread, if (s.max_spread > 0.05) " (OVER 5 %: noisy run, repeat)" else "" });
    if (s.mismatch) {
        try w.print("{s}: FAILED -- an output length differs between the sides\n", .{bench_name});
        try w.flush();
        return 1;
    }
    try w.print("reference: {s}\ncolumn 2:  {s}\nworst ours/encoding_rs = {d:.3} (best {d:.3}); worst ours/x-text = {d:.3} -> {s}\n", .{
        std.mem.trimEnd(u8, s.banner, "\n"),
        std.mem.trimEnd(u8, s.alt_banner, "\n"),
        s.worst_ref,
        s.best_ref,
        worst_go,
        if (s.worst_ref <= 1.1) "P2 met (every row <= 1.1x)" else "P2 NOT met",
    });
    if (filters.len == 0)
        try w.print("card: **Performance:** ref {d:.2}–{d:.2}× encoding_rs 0.8.42 ({d} rows, wall time, whole-buffer API) · worst {d:.2}× x/text\n", .{ s.best_ref, s.worst_ref, works.len, worst_go });
    try w.flush();
    return 0;
}
