//! brotli — pure-Zig Brotli (RFC 7932) decompressor + minimal encoder.
//!
//! Decoder: byte-exact RFC 7932 decompression (bit stream, meta-blocks,
//! simple + complex Huffman codes, block-type/count machinery, literal context
//! modeling, the postfix/direct/ring-buffer distance model, and the normative
//! static dictionary + transforms of Appendix A/B). Malformed input never
//! panics — it returns a typed `BrotliError`. Output is bounded by
//! `Options.max_output` (a decompression-bomb guard).
//!
//! Encoder: LZ77 backward references plus a per-meta-block Huffman code for
//! literals, insert-and-copy commands and distances, with a store-mode fallback
//! for anything that would not shrink. Roughly 2.8x on English text. Its output
//! is checked against the reference implementation (google/brotli), not only
//! against this module's own decoder; see SPEC.md.

const std = @import("std");

const decoder = @import("decoder.zig");
const encoder = @import("encoder.zig");

pub const BrotliError = @import("errors.zig").BrotliError;
pub const Options = decoder.Options;

/// Decompress a complete Brotli stream. Caller owns the returned slice.
pub const decompress = decoder.decompress;

/// Compress `input` into a valid Brotli stream. Caller owns the returned slice.
/// Fails only on allocation: any block that will not compress is stored
/// verbatim, so the result is always a conformant `br` body.
pub const compress = encoder.compress;

// ===========================================================================
// Tests
// ===========================================================================
const testing = std.testing;

test {
    // Live interop against the reference implementation (skips loudly when
    // python3 / the `brotli` package is unavailable).
    _ = @import("reference_interop.zig");
}

fn expectDecodes(comptime name: []const u8) !void {
    const plain = @embedFile("testdata/" ++ name);
    const comp = @embedFile("testdata/" ++ name ++ ".compressed");
    const got = try decompress(testing.allocator, comp, .{});
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, plain, got);
}

test "decode: empty stream" {
    try expectDecodes("empty");
}

test "decode: single byte (x)" {
    try expectDecodes("x");
}

test "decode: short literals (xyzzy)" {
    try expectDecodes("xyzzy");
}

test "decode: simple LZ77 (10x10y)" {
    try expectDecodes("10x10y");
}

test "decode: run copy (64x)" {
    try expectDecodes("64x");
}

test "decode: static dictionary (quickfox)" {
    try expectDecodes("quickfox");
}

test "decode: dictionary + backward refs (quickfox_repeated)" {
    try expectDecodes("quickfox_repeated");
}

test "decode: classic (ukkonooa)" {
    try expectDecodes("ukkonooa");
}

test "decode: long run of zeros (zeros)" {
    try expectDecodes("zeros");
}

test "decode: zeros + dictionary (zerosukkanooa)" {
    try expectDecodes("zerosukkanooa");
}

test "decode: mixed text (monkey)" {
    try expectDecodes("monkey");
}

test "decode: large backward window (backward65536)" {
    try expectDecodes("backward65536");
}

test "decode: incompressible random (random_org_10k.bin)" {
    try expectDecodes("random_org_10k.bin");
}

test "decode: compressed-then-recompressed (compressed_file)" {
    try expectDecodes("compressed_file");
}

test "decode: UTF-8 text (cp852-utf8)" {
    try expectDecodes("cp852-utf8");
}

test "decode: UTF-16LE bytes (cp1251-utf16le)" {
    try expectDecodes("cp1251-utf16le");
}

test "decode: full English text, complex Huffman (alice29.txt)" {
    try expectDecodes("alice29.txt");
}

test "decode: output cap enforced (DoS guard)" {
    const comp = @embedFile("testdata/zeros.compressed");
    try testing.expectError(error.OutputTooLarge, decompress(testing.allocator, comp, .{ .max_output = 1000 }));
}

test "F3 regression: DEFAULT options bound output relative to input size, not just the 256 MiB absolute cap" {
    // Before the fix, `Options.max_output`'s default (256 MiB) was the ONLY
    // guard: a several-KB `br` body could legitimately cost up to 256 MiB
    // of RSS with the caller never having opted into anything but the
    // defaults (wave-2 audit finding `brotli` F3). This 14-byte stream
    // (produced independently by the reference `brotli` Python package --
    // `brotli.compress(b'\x00' * 4*1024*1024)` -- not this module's own
    // encoder) decompresses to 4 MiB of zeros, a ~300000x ratio. Under
    // completely default `Options{}` it must now be refused: 4 MiB is far
    // past both the 1 MiB floor and any reasonable ratio of a 14-byte input.
    const bomb = [_]u8{ 0x9b, 0xff, 0xff, 0x3f, 0xf8, 0x27, 0x00, 0xe2, 0xb1, 0x40, 0x20, 0xf7, 0xfe, 0x07 };
    try testing.expectError(error.OutputTooLarge, decompress(testing.allocator, &bomb, .{}));
    // Positive control: the same bytes DO decode correctly once a caller
    // deliberately opts out of the ratio guard too (raising `max_output`
    // alone is not enough -- `max_ratio`/`min_output_floor` are separate
    // knobs precisely so raising the absolute ceiling doesn't silently
    // also waive the ratio policy), so the rejection above is the
    // ratio/floor guard, not a decoder bug on this input.
    const out = try decompress(testing.allocator, &bomb, .{
        .max_output = 8 * 1024 * 1024,
        .min_output_floor = 8 * 1024 * 1024,
    });
    defer testing.allocator.free(out);
    try testing.expectEqual(@as(usize, 4 * 1024 * 1024), out.len);
    for (out) |b| try testing.expectEqual(@as(u8, 0), b);

    // Positive control: the guard does NOT fire for a legitimately small
    // decompressed size at a tiny ratio (the existing `zeros` fixture, 13
    // bytes -> 256 KiB, already exercised via `expectDecodes` elsewhere in
    // this file with default options -- this makes the "the floor rescues
    // it" reasoning explicit and pinned).
    const zeros_comp = @embedFile("testdata/zeros.compressed");
    const zeros_out = try decompress(testing.allocator, zeros_comp, .{});
    defer testing.allocator.free(zeros_out);
    try testing.expectEqual(@as(usize, 256 * 1024), zeros_out.len);
}

test "decode: truncated input errors, never panics" {
    const comp = @embedFile("testdata/alice29.txt.compressed");
    // A batch of truncations must all error cleanly (no panic, no crash).
    var len: usize = 0;
    while (len < comp.len) : (len += 97) {
        const r = decompress(testing.allocator, comp[0..len], .{});
        if (r) |ok| testing.allocator.free(ok) else |_| {}
    }
}

test "decode: hostile garbage errors, never panics" {
    var seed: u32 = 0x1234_5678;
    var i: usize = 0;
    while (i < 400) : (i += 1) {
        var buf: [64]u8 = undefined;
        for (&buf) |*b| {
            seed = seed *% 1664525 +% 1013904223;
            b.* = @truncate(seed >> 16);
        }
        const r = decompress(testing.allocator, &buf, .{ .max_output = 1 << 20 });
        if (r) |ok| testing.allocator.free(ok) else |_| {}
    }
}

test "decode: empty input is truncated error" {
    try testing.expectError(error.TruncatedInput, decompress(testing.allocator, "", .{}));
}

// --- W2-P07 (brotli F2): transform buffer sizing ---------------------------
// `transforms.transformWord` writes prefix + word + suffix into the caller's
// buffer with no internal bounds error path. It is safe in the decoder only
// because the buffer is large enough for the worst-case transform. That worst
// case is a property of the RFC 7932 pool + transform tables, so this test
// asserts, by brute force over every transform and every legal word length,
// that `transforms.maxOutputLen` really bounds the output — and that the
// decoder's buffer is sized from it. Undersize the buffer (revert the fix) and
// the writes run past the `dst` slice: a Debug/ReleaseSafe bounds panic here,
// a silent stack smash under ReleaseFast.
test "transform: maxOutputLen bounds every transform's output" {
    const transforms = @import("transforms.zig");
    const dict = @import("dictionary.zig");

    const cap = transforms.maxOutputLen(dict.max_word_length);
    // A guard region after the slice we hand to transformWord; if the bound is
    // wrong the writes spill into it (and, because we pass an exact-size slice,
    // trip the bounds check first).
    var backing: [512]u8 = undefined;
    const guard = 0xAA;

    var ti: usize = 0;
    while (ti < transforms.num_transforms) : (ti += 1) {
        var wlen: usize = dict.min_word_length;
        while (wlen <= dict.max_word_length) : (wlen += 1) {
            // A word made of letters so UPPERCASE_* transforms do real work.
            var word: [dict.max_word_length]u8 = undefined;
            for (word[0..wlen], 0..) |*b, i| b.* = @intCast('a' + (i % 26));

            @memset(&backing, guard);
            const out = transforms.transformWord(backing[0..cap], word[0..wlen], wlen, ti);
            try testing.expect(out <= cap);
            for (backing[cap..]) |b| try testing.expectEqual(@as(u8, guard), b);
        }
    }
}

// --- W2-P07 continued: end-to-end max-length transform ---------------------
// The `quickfox`/`ukkonooa` fixtures already exercise the dictionary path; this
// pins that the maximum-output transform decodes correctly through the resized
// buffer. (See the transform unit test above for the biting invariant.)
test "decode: dictionary transforms decode correctly (regression corpus)" {
    try expectDecodes("quickfox");
    try expectDecodes("zerosukkanooa");
}

// --- W2-P07: F4 was NOT a defect — parity with google/brotli ---------------
// F4 suspected a non-terminating / zero-progress loop from a dictionary
// reference whose transform yields zero output (`transformWord` returns 0),
// which the guard at decoder.zig only rejects for `distance <= 120`. A zeroing
// transform (OMIT_* >= word length) has transform index >= 34, so its address
// is >= 34*2^shift and the distance is always >> 120 — the guard can never fire
// for a genuine zero-output word, so such a reference is accepted. The stream
// below is hand-crafted to hit exactly that path (transform 34, a 4-byte word
// omitted whole, distance 34818). Both this decoder AND the google/brotli
// reference decode it to "AA": accepting it is conformant, not a bug. This test
// is a characterisation lock so the guard is not "hardened" into divergence.
test "decode: zero-output dictionary transform matches reference (parity)" {
    const comp = &[_]u8{ 0x22, 0x00, 0x00, 0x00, 0x44, 0x50, 0x28, 0x12, 0x6a, 0x01, 0x02 };
    const got = try decompress(testing.allocator, comp, .{});
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, "AA", got);
}

fn roundTrip(data: []const u8) !void {
    const comp = try compress(testing.allocator, data);
    defer testing.allocator.free(comp);
    const back = try decompress(testing.allocator, comp, .{});
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, data, back);
}

test "encode: round-trip empty" {
    try roundTrip("");
}

test "encode: round-trip small text" {
    try roundTrip("Hello, Brotli! The quick brown fox jumps over the lazy dog.");
}

test "encode: round-trip highly repetitive" {
    const data = "abcabcabc" ** 5000;
    try roundTrip(data);
}

test "encode: round-trip incompressible random" {
    var buf: [4096]u8 = undefined;
    var seed: u32 = 0xC0FFEE;
    for (&buf) |*b| {
        seed = seed *% 1664525 +% 1013904223;
        b.* = @truncate(seed >> 16);
    }
    try roundTrip(&buf);
}

test "encode: multi-block (> 16 MiB) round-trip" {
    const gpa = testing.allocator;
    const size = (16 * 1024 * 1024) + 4096; // spans two uncompressed meta-blocks
    const data = try gpa.alloc(u8, size);
    defer gpa.free(data);
    var seed: u32 = 42;
    for (data) |*b| {
        seed = seed *% 1103515245 +% 12345;
        b.* = @truncate(seed >> 16);
    }
    const comp = try compress(gpa, data);
    defer gpa.free(comp);
    const back = try decompress(gpa, comp, .{});
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, data, back);
}

test "encode: output is a valid stream our decoder accepts for real corpus" {
    const plain = @embedFile("testdata/alice29.txt");
    try roundTrip(plain);
}

// --- encoder: compression, and the store-mode fallback ----------------------

test "encode: really compresses English text" {
    const plain = @embedFile("testdata/alice29.txt");
    const comp = try compress(testing.allocator, plain);
    defer testing.allocator.free(comp);
    // Store mode would be ~1.00; the reference manages ~2.9x at quality 1.
    // Anything above half the original means the compressed path silently
    // stopped being taken.
    try testing.expect(comp.len * 2 < plain.len);
    const back = try decompress(testing.allocator, comp, .{});
    defer testing.allocator.free(back);
    try testing.expectEqualSlices(u8, plain, back);
}

test "encode: incompressible input falls back to store mode" {
    var buf: [4096]u8 = undefined;
    var seed: u32 = 0xBADF00D;
    for (&buf) |*b| {
        seed = seed *% 1664525 +% 1013904223;
        b.* = @truncate(seed >> 16);
    }
    const comp = try compress(testing.allocator, &buf);
    defer testing.allocator.free(comp);
    // Store mode costs the window bits, one meta-block header, byte alignment
    // and the final empty meta-block — a handful of bytes, never a factor.
    try testing.expect(comp.len <= buf.len + 8);
    try roundTrip(&buf);
}

test "encode: output never blows up, whatever the input looks like" {
    const gpa = testing.allocator;
    var seed: u64 = 0x1234_5678_9abc_def0;
    var iter: usize = 0;
    while (iter < 60) : (iter += 1) {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        const n: usize = @as(usize, @truncate(seed >> 12)) % 9000;
        const alphabet: usize = 1 + @as(usize, @truncate(seed >> 40)) % 256;
        const data = try gpa.alloc(u8, n);
        defer gpa.free(data);
        for (data) |*b| {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            b.* = @intCast(@as(usize, @truncate(seed >> 21)) % alphabet);
        }
        const comp = try compress(gpa, data);
        defer gpa.free(comp);
        // Worst case is store mode plus its framing; a compressed block is only
        // kept when it is strictly smaller than storing the same bytes.
        try testing.expect(comp.len <= n + 16);
        const back = try decompress(gpa, comp, .{});
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, data, back);
    }
}

test "encode: round-trip every input shape" {
    const gpa = testing.allocator;
    try roundTrip("a");
    try roundTrip("ab");
    try roundTrip("abc");
    try roundTrip(&[_]u8{0} ** 5);
    try roundTrip(&[_]u8{0xff} ** 100000);
    {
        // Every byte value present, so the literal code spans the alphabet.
        var buf: [256]u8 = undefined;
        for (&buf, 0..) |*b, i| b.* = @intCast(i);
        try roundTrip(&buf);
    }
    {
        // Matches at exactly the window edge, both sides of the wbits switch.
        for ([_]usize{ 65519, 65520, 65521 }) |n| {
            const buf = try gpa.alloc(u8, n + 8);
            defer gpa.free(buf);
            @memset(buf, 'z');
            @memcpy(buf[0..8], "preamble");
            @memcpy(buf[n..][0..8], "preamble");
            try roundTrip(buf);
        }
    }
    {
        // Two meta-blocks of compressible data.
        const alice = @embedFile("testdata/alice29.txt");
        const buf = try gpa.alloc(u8, (1 << 20) + 5000);
        defer gpa.free(buf);
        for (buf, 0..) |*b, i| b.* = alice[i % alice.len];
        try roundTrip(buf);
    }
}

// ── fuzz: the decompressor over attacker-shaped `br` bodies ──────────────
//
// This is a `Content-Encoding: br` decoder — the input is whatever a
// remote server or an on-path attacker chose to send — and until this
// harness existed the module carried no `testing.fuzz(` call, so
// `scripts/fuzz-sweep.sh` (target list = `grep -rl 'testing.fuzz('
// modules/*/src/*.zig`) had never covered it once.
//
// What stood in for a harness was the "hostile garbage" test above: 400
// LCG-generated 64-byte buffers. That is not a substitute, and the reason
// is worth stating because it is the general trap. Uniform random bytes do
// get past `decodeWindowBits` (bit 0 == 0 means wbits 16, so half of them
// do), and some get past `decodeMetaBlockLength`, but essentially none get
// past `readHuffmanCode`: a complex prefix code has to satisfy KRAFT
// EQUALITY over its code lengths (`huffman.zig`), which random bit strings
// do not. So the Huffman-table construction, the context maps, the
// distance LUT and the static-dictionary/transform paths — i.e. all the
// interesting arithmetic — were unreachable from that generator no matter
// how long it ran, and it was not coverage-guided either.
//
// The fix is to hand the fuzzer a foothold: EVERY input starts as a
// stream from the google/brotli REFERENCE CORPUS already committed in
// `src/testdata/` (the same streams the byte-exact decode tests use, so
// between them they cover simple and complex Huffman codes, context
// modeling, backward references at the window edge and the static
// dictionary), and the fuzzer decides how much of it survives and what
// damage is done to it. `max_output` is bounded at 1 MiB so a legitimate
// expansion cannot be mistaken for a bug.
//
// Two things about this shape were measured rather than guessed, because
// both cut the other way from the obvious design:
//   - Damage must be SMALL. An earlier version applied up to 24 random
//     byte replacements; instrumented counters showed such streams die in
//     the header and reach the command loop essentially never, while
//     single-bit damage to a valid stream reaches the static-dictionary
//     branch hundreds of times per input.
//   - A separate "pure entropy" branch is not worth its budget; `keep ==
//     0` already produces one, and the header reject paths are cheap to
//     reach anyway.
//
// Reachability check: a temporary `@panic` on `decoder.zig`'s
// out-of-range `transform_idx` reject — inside the static-dictionary
// branch, and a path NO corpus seed reaches, since every seed is a valid
// stream. A 240 s `scripts/fuzz-sweep.sh 240 brotli` run FOUND it
// (verdict FINDING, crashing input preserved); the probe was then
// removed. The old LCG generator cannot make that claim: instrumented
// counters put its reach into that branch at zero.
const fuzz_seed_corpus = [_][]const u8{
    @embedFile("testdata/empty.compressed"),
    @embedFile("testdata/x.compressed"),
    @embedFile("testdata/xyzzy.compressed"),
    @embedFile("testdata/10x10y.compressed"),
    @embedFile("testdata/64x.compressed"),
    @embedFile("testdata/zeros.compressed"),
    @embedFile("testdata/backward65536.compressed"),
    @embedFile("testdata/quickfox.compressed"),
    @embedFile("testdata/quickfox_repeated.compressed"), // dictionary + backward refs
    @embedFile("testdata/ukkonooa.compressed"),
    @embedFile("testdata/zerosukkanooa.compressed"),
    @embedFile("testdata/cp852-utf8.compressed"), // complex Huffman, context modeling
    @embedFile("testdata/monkey.compressed"),
    @embedFile("testdata/cp1251-utf16le.compressed"),
};

test "fuzz: decompress never panics on arbitrary or mutated br streams" {
    try testing.fuzz({}, fuzzDecompress, .{});
}

fn fuzzDecompress(_: void, smith: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;

    // Every input starts as a REFERENCE STREAM and is damaged from there.
    // There is no "pure entropy" branch, because `keep == 0` already is
    // one: the whole point is that the fuzzer should spend its budget on
    // inputs that get past the header and the Huffman tables, and only a
    // stream the reference produced does that reliably.
    const seed = fuzz_seed_corpus[smith.index(fuzz_seed_corpus.len)];
    const seed_cap: u16 = @intCast(@min(seed.len, buf.len));
    const keep: usize = if (smith.boolWeighted(1, 4))
        seed_cap // 4/5: the whole stream survives, then gets point damage
    else
        smith.valueRangeAtMost(u16, 0, seed_cap); // a valid prefix, then fuzzer bytes
    @memcpy(buf[0..keep], seed[0..keep]);
    var len: usize = keep;

    // Optionally continue the stream with fuzzer bytes — a hostile
    // second meta-block behind a header the decoder already accepted.
    if (len < buf.len and smith.boolWeighted(2, 1)) len += smith.slice(buf[len..]);

    // Point damage inside the surviving part. Kept SMALL on purpose: a
    // handful of edits leaves the stream decodable far enough to reach the
    // command loop, the context maps and the static dictionary, whereas
    // heavy damage is rejected in the header and tests nothing.
    var muts: usize = 0;
    while (muts < 8 and len > 0 and !smith.eosWeightedSimple(2, 1)) : (muts += 1) {
        const i = smith.index(len);
        buf[i] = switch (smith.value(enum { flip, byte, zero, ones })) {
            .flip => buf[i] ^ (@as(u8, 1) << smith.valueRangeAtMost(u3, 0, 7)),
            .byte => smith.value(u8),
            .zero => 0,
            .ones => 0xff,
        };
    }

    const r = decompress(testing.allocator, buf[0..len], .{ .max_output = 1 << 20 });
    if (r) |ok| testing.allocator.free(ok) else |_| {}
}
