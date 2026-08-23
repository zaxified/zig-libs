// SPDX-License-Identifier: MIT

//! `qr-demo` — encode a string into a QR symbol and write it out as a PNG, an
//! SVG, or half-block text on the terminal.
//!
//! The module is a codec: it computes a grid and has no pixel format anywhere
//! in it (README, "Rendering"). SVG and terminal output therefore come straight
//! from `qr.writeSvg`/`qr.writeTerminal`; **PNG is this example's own code**,
//! because a PNG is the one thing a reader actually wants to hand to a scanner
//! and there is no image module in this collection to produce it. That code is
//! confined to the "PNG" section at the bottom of this file and is deliberately
//! narrow — 8-bit grayscale, non-interlaced, one `IDAT` — which is all a QR
//! symbol needs and much less than the format allows. `modules/qrscan`'s
//! example reads the same narrow shape back.
//!
//! What it demonstrates, beyond "call encode":
//!
//!   * **Automatic selection.** With no flags, `encode` picks the most compact
//!     mode the input allows, the smallest version that fits and the
//!     lowest-penalty mask. `-e/-v/--mask/--mode` force each one, and the
//!     report line says which of the three were chosen and which were dictated
//!     — the difference is the whole reason `Options` has nullable fields.
//!   * **The decoder, on our own output.** Every run decodes the symbol it just
//!     built and compares it to the input, so a broken encode is caught here
//!     and not by the person holding the phone.
//!   * **Structured append** (`--seq N`, ISO/IEC 18004 §8.4.6): a message split
//!     across up to sixteen linked symbols. `--seq` also reassembles them
//!     through `decodePart` and checks `qr.sequenceParity`, because reassembly
//!     is the caller's job — the module allocates nothing and cannot hold
//!     sixteen fragments for you — and showing the split without the join would
//!     be showing half the feature.
//!
//! Built against the PUBLISHED module (`@import("qr")`) only.

const std = @import("std");
const qr = @import("qr");

const Allocator = std.mem.Allocator;

/// Version 40-L holds 2953 bytes; nothing `decode` can return is longer.
const max_message = 3000;

const usage_text =
    \\qr-demo -- encode text into a QR symbol (PNG, SVG or terminal).
    \\
    \\usage:
    \\  qr-demo [options] TEXT
    \\
    \\  -e, --ecc L|M|Q|H     error-correction level          (default: M)
    \\  -v, --version 1..40   force a version                 (default: smallest that fits)
    \\      --mask 0..7       force a mask pattern            (default: lowest penalty)
    \\      --mode N|A|B      force numeric/alphanumeric/byte (default: most compact)
    \\  -o, --png FILE        write a PNG                     (default: qr.png)
    \\      --svg FILE        write an SVG
    \\  -t, --term            draw the symbol on this terminal
    \\      --light-term      the terminal has a LIGHT background (see below)
    \\  -s, --scale N         pixels per module in the PNG    (default: 8)
    \\      --quiet N         quiet zone in modules           (default: 4, the standard's)
    \\      --seq N           structured append: split across at most N symbols (2..16)
    \\      --no-png          write no PNG
    \\  -h, --help            this text
    \\
    \\--light-term is not cosmetic: glyphs are drawn in the foreground colour, so on a
    \\dark terminal it is the LIGHT module that has to get a glyph. Set it wrong and
    \\what is on screen is a photographic negative, which scanners refuse.
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes the example a leak detector
    // for the module's ownership contract (CONVENTIONS.md §7.2). The module
    // itself allocates nothing — every buffer below is this file's own.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.next(); // argv[0]

    // No arguments at all -> self-demo. `probe` is a value copy (the POSIX
    // iterator is just a slice), so peeking here does not consume anything
    // `parseArgs` below would otherwise see.
    var probe = args;
    if (probe.next() == null) return runSelfDemo(gpa, io);

    const opts = parseArgs(&args) catch |err| switch (err) {
        error.BadUsage => {
            try printOut(io, "{s}", .{usage_text});
            return 1;
        },
    };
    if (opts.help) {
        try printOut(io, "{s}", .{usage_text});
        return 0;
    }

    return if (opts.sequence) |n|
        runSequence(gpa, io, opts, n)
    else
        runSingle(gpa, io, opts);
}

// ─────────────────────────────────────────────────────────────────────────────
// no arguments — self-demo
// ─────────────────────────────────────────────────────────────────────────────
//
// Round-trips two symbols through a REAL PNG file on disk: encode, write the
// narrow PNG this file's own `renderPng` produces, read the bytes back with
// `readPngLuma` below (a reader that trusts only the shape this encoder
// actually emits — 8-bit grayscale, filter None on every row, one IDAT — and
// refuses anything else by name), resample module centres off the pixels, and
// `qr.decode()` the RECONSTRUCTED matrix. That is a different code path from
// `runSingle`'s self-check, which decodes the in-memory `Matrix` `encode` just
// filled in directly: this proves the PNG on disk actually carries the
// symbol, not just that `encode`/`decode` agree with each other in RAM.
//
// `qr` depends on nothing (`meta.deps = .{}`), so `qrscan`'s finder/binariser
// is not reachable from here — this file cannot demonstrate LOCATING a symbol
// in a photograph, only that the bits a real image file carries decode back
// to the input. That coverage gap is `qrscan`'s self-demo, not this one's.

fn runSelfDemo(gpa: Allocator, io: std.Io) !u8 {
    try selfDemoCase(gpa, io, ".zig-cache/qr-selfdemo-1.png", "zig-libs qr module -- self-demo round trip", .{});

    // The "not trivially easy" case: long enough to force a multi-block
    // symbol (several version steps up from the short case above) and at the
    // highest error-correction level, so the codeword layout this exercises
    // is the one with the most Reed-Solomon blocks to get right.
    const hard_text = "zig-libs qr module self-demo, harder case: a longer payload at ECC level H, " ++
        "forcing a bigger version with several interleaved Reed-Solomon blocks instead of the single " ++
        "block the short case above uses. Round-tripped through the same real PNG file and byte-for-byte " ++
        "compared against this exact string once decoded back out of the image that was written to disk.";
    try selfDemoCase(gpa, io, ".zig-cache/qr-selfdemo-2.png", hard_text, .{ .ecc = .high });

    try printOut(io, "self-demo passed: both symbols round-tripped through a real PNG file byte-for-byte\n", .{});
    return 0;
}

fn selfDemoCase(gpa: Allocator, io: std.Io, path: []const u8, text: []const u8, opts: qr.Options) !void {
    var m: qr.Matrix = undefined;
    try qr.encode(&m, text, opts);

    const scale: u32 = 4;
    const quiet: u8 = qr.quiet_zone;
    const bytes = try renderPng(gpa, &m, scale, quiet);
    defer gpa.free(bytes);
    try writeWholeFile(io, path, bytes);
    // Delete the file regardless of what happens below -- this demo must
    // leave nothing behind, success or failure.
    defer std.Io.Dir.cwd().deleteFile(io, path) catch |err| {
        std.debug.print("qr-demo: self-demo: could not remove {s}: {t}\n", .{ path, err });
    };

    const raster = try readPngLuma(gpa, io, path);
    defer gpa.free(raster.pixels);

    var reconstructed: qr.Matrix = .{ .size = m.size };
    @memset(&reconstructed.bits, 0);
    for (0..m.size) |y| {
        for (0..m.size) |x| {
            // Sample the centre of the module's block, exactly as `renderPng`
            // laid it out: `quiet` modules of border, then `scale` pixels per
            // module.
            const px = (quiet + x) * scale + scale / 2;
            const py = (quiet + y) * scale + scale / 2;
            const v = raster.pixels[py * raster.width + px];
            reconstructed.setDark(@intCast(x), @intCast(y), v < 128);
        }
    }

    var buf: [max_message]u8 = undefined;
    const got = qr.decode(&reconstructed, &buf) catch |err| {
        std.debug.print("qr-demo: self-demo: {s} did not decode back off disk: {t}\n", .{ path, err });
        return err;
    };
    if (!std.mem.eql(u8, got, text)) @panic("qr-demo: self-demo: decoded text read back from the PNG does not match the input");

    try printOut(io, "{s}: version {d} ({d}x{d} modules), {d}x{d} px PNG, decoded {d} bytes back off disk, matches input\n", .{
        path, m.version, m.size, m.size, raster.width, raster.height, got.len,
    });
}

/// Read back exactly the narrow shape `renderPng` writes: 8-bit grayscale
/// (colour type 0), non-interlaced, filter None on every row, one `IDAT`. Not
/// a general PNG reader -- see `modules/qrscan/example/main.zig`'s `decodePng`
/// for one of those; this one is deliberately as narrow as its writer and
/// refuses anything its writer would never produce, by name.
const PngLuma = struct { pixels: []u8, width: u32, height: u32 };

fn readPngLuma(gpa: Allocator, io: std.Io, path: []const u8) !PngLuma {
    const file = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024 * 1024));
    defer gpa.free(file);

    if (file.len < png_signature.len or !std.mem.eql(u8, file[0..png_signature.len], &png_signature))
        return error.NotAPng;

    var width: u32 = 0;
    var height: u32 = 0;
    var have_ihdr = false;
    var idat: std.Io.Writer.Allocating = .init(gpa);
    defer idat.deinit();

    var off: usize = png_signature.len;
    while (true) {
        if (off + 8 > file.len) return error.CorruptPng;
        const len = std.mem.readInt(u32, file[off..][0..4], .big);
        const kind = file[off + 4 ..][0..4];
        if (off + 12 + len > file.len) return error.CorruptPng;
        const data = file[off + 8 ..][0..len];
        off += 12 + len;

        if (std.mem.eql(u8, kind, "IHDR")) {
            if (len != 13) return error.CorruptPng;
            width = std.mem.readInt(u32, data[0..4], .big);
            height = std.mem.readInt(u32, data[4..8], .big);
            if (data[8] != 8) return error.UnexpectedPngShape; // bit depth
            if (data[9] != 0) return error.UnexpectedPngShape; // colour type: grayscale
            if (data[12] != 0) return error.UnexpectedPngShape; // interlace: none
            have_ihdr = true;
        } else if (std.mem.eql(u8, kind, "IDAT")) {
            if (!have_ihdr) return error.CorruptPng;
            try idat.writer.writeAll(data);
        } else if (std.mem.eql(u8, kind, "IEND")) {
            break;
        }
    }
    if (!have_ihdr or width == 0 or height == 0) return error.CorruptPng;

    const row_bytes = width; // 8-bit grayscale: one sample byte per pixel
    const raw = try gpa.alloc(u8, (row_bytes + 1) * height);
    defer gpa.free(raw);

    var src: std.Io.Reader = .fixed(idat.written());
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var inflate: std.compress.flate.Decompress = .init(&src, .zlib, &window);
    inflate.reader.readSliceAll(raw) catch return error.CorruptPng;

    const pixels = try gpa.alloc(u8, @as(usize, width) * height);
    errdefer gpa.free(pixels);
    for (0..height) |y| {
        const filter = raw[y * (row_bytes + 1)];
        // This file's own writer (`renderPng`) always writes filter 0
        // ("None") -- anything else means the writer changed shape and this
        // reader's narrowing assumption no longer holds.
        if (filter != 0) return error.UnexpectedPngShape;
        const row = raw[y * (row_bytes + 1) + 1 ..][0..row_bytes];
        @memcpy(pixels[y * width ..][0..width], row);
    }
    return .{ .pixels = pixels, .width = width, .height = height };
}

// ─────────────────────────────────────────────────────────────────────────────
// arguments
// ─────────────────────────────────────────────────────────────────────────────

const Options = struct {
    help: bool = false,
    text: []const u8 = "",
    enc: qr.Options = .{},
    png_path: ?[]const u8 = "qr.png",
    svg_path: ?[]const u8 = null,
    terminal: bool = false,
    dark_background: bool = true,
    scale: u32 = 8,
    quiet: u8 = qr.quiet_zone,
    sequence: ?usize = null,
};

fn parseArgs(args: *std.process.Args.Iterator) error{BadUsage}!Options {
    var o: Options = .{};
    var have_text = false;

    while (args.next()) |arg| {
        if (eq(arg, "-h") or eq(arg, "--help")) {
            o.help = true;
            return o;
        } else if (eq(arg, "-e") or eq(arg, "--ecc")) {
            const v = try next(args, "--ecc");
            o.enc.ecc = if (eqIgnoreCase(v, "L")) .low else if (eqIgnoreCase(v, "M")) .medium else if (eqIgnoreCase(v, "Q")) .quartile else if (eqIgnoreCase(v, "H")) .high else {
                std.debug.print("qr-demo: --ecc takes L, M, Q or H, not '{s}'\n", .{v});
                return error.BadUsage;
            };
        } else if (eq(arg, "-v") or eq(arg, "--version")) {
            o.enc.version = @intCast(try intArg(args, "--version", 1, 40));
        } else if (eq(arg, "--mask")) {
            o.enc.mask = @intCast(try intArg(args, "--mask", 0, 7));
        } else if (eq(arg, "--mode")) {
            const v = try next(args, "--mode");
            o.enc.mode = if (eqIgnoreCase(v, "N") or eqIgnoreCase(v, "numeric"))
                .numeric
            else if (eqIgnoreCase(v, "A") or eqIgnoreCase(v, "alnum") or eqIgnoreCase(v, "alphanumeric"))
                .alphanumeric
            else if (eqIgnoreCase(v, "B") or eqIgnoreCase(v, "byte"))
                .byte
            else {
                std.debug.print("qr-demo: --mode takes N, A or B, not '{s}'\n", .{v});
                return error.BadUsage;
            };
        } else if (eq(arg, "-o") or eq(arg, "--png")) {
            o.png_path = try next(args, "--png");
        } else if (eq(arg, "--no-png")) {
            o.png_path = null;
        } else if (eq(arg, "--svg")) {
            o.svg_path = try next(args, "--svg");
        } else if (eq(arg, "-t") or eq(arg, "--term")) {
            o.terminal = true;
        } else if (eq(arg, "--light-term")) {
            o.terminal = true;
            o.dark_background = false;
        } else if (eq(arg, "-s") or eq(arg, "--scale")) {
            o.scale = @intCast(try intArg(args, "--scale", 1, 64));
        } else if (eq(arg, "--quiet")) {
            o.quiet = @intCast(try intArg(args, "--quiet", 0, 32));
        } else if (eq(arg, "--seq")) {
            o.sequence = try intArg(args, "--seq", 2, 16);
        } else if (arg.len > 1 and arg[0] == '-' and !have_text) {
            std.debug.print("qr-demo: unknown option '{s}'\n", .{arg});
            return error.BadUsage;
        } else {
            if (have_text) {
                std.debug.print("qr-demo: more than one TEXT argument; quote it\n", .{});
                return error.BadUsage;
            }
            o.text = arg;
            have_text = true;
        }
    }

    if (!have_text) return error.BadUsage;
    return o;
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn next(args: *std.process.Args.Iterator, flag: []const u8) error{BadUsage}![]const u8 {
    return args.next() orelse {
        std.debug.print("qr-demo: {s} needs a value\n", .{flag});
        return error.BadUsage;
    };
}

fn intArg(args: *std.process.Args.Iterator, flag: []const u8, lo: usize, hi: usize) error{BadUsage}!usize {
    const raw = try next(args, flag);
    const v = std.fmt.parseInt(usize, raw, 10) catch {
        std.debug.print("qr-demo: {s} takes a number, not '{s}'\n", .{ flag, raw });
        return error.BadUsage;
    };
    if (v < lo or v > hi) {
        std.debug.print("qr-demo: {s} must be {d}..{d}, got {d}\n", .{ flag, lo, hi, v });
        return error.BadUsage;
    }
    return v;
}

// ─────────────────────────────────────────────────────────────────────────────
// one symbol
// ─────────────────────────────────────────────────────────────────────────────

fn runSingle(gpa: Allocator, io: std.Io, opts: Options) !u8 {
    var describe_buf: [256]u8 = undefined;
    // 3.9 KB of bits regardless of version, so it goes on the frame; the module
    // takes it by pointer and writes nothing else anywhere.
    var m: qr.Matrix = undefined;
    qr.encode(&m, opts.text, opts.enc) catch |err| return reportEncodeError(err, opts);

    try printOut(io, "encoded {d} byte{s} into {s}\n", .{
        opts.text.len,
        if (opts.text.len == 1) "" else "s",
        try describe(&describe_buf, &m, opts),
    });

    // Decode our own output. `encode` and `decode` share no code path — the
    // decoder rebuilds the function-pattern map from the version alone and
    // walks the codewords back — so this is a real check, and it is the check
    // that would otherwise be made by someone holding a phone.
    var buf: [max_message]u8 = undefined;
    const got = qr.decode(&m, &buf) catch |err| {
        std.debug.print("qr-demo: the symbol just encoded does not decode: {t}\n", .{err});
        return 1;
    };
    if (!std.mem.eql(u8, got, opts.text)) {
        std.debug.print("qr-demo: round-trip mismatch: encoded {d} bytes, decoded {d}\n", .{ opts.text.len, got.len });
        return 1;
    }
    try printOut(io, "self-check: decoded back {d} byte{s}, identical to the input\n", .{
        got.len,
        if (got.len == 1) "" else "s",
    });

    if (opts.png_path) |path| try emitPng(gpa, io, path, &m, opts);
    if (opts.svg_path) |path| try emitSvg(gpa, io, path, &m, opts);
    if (opts.terminal) try emitTerminal(io, &m, opts);
    return 0;
}

/// Every branch of `qr.Error` by name — CONVENTIONS.md §7.2 asks an example to
/// handle at least one, and here all three are worth distinguishing: they mean
/// three different things to whoever typed the command.
fn reportEncodeError(err: qr.Error, opts: Options) u8 {
    switch (err) {
        error.TooLong => if (opts.enc.version) |v| {
            std.debug.print(
                "qr-demo: {d} bytes do not fit a version {d} symbol at level {s}." ++
                    " Drop --version, lower --ecc, or split it with --seq.\n",
                .{ opts.text.len, v, eccName(opts.enc.ecc) },
            );
        } else {
            std.debug.print(
                "qr-demo: {d} bytes do not fit any single symbol at level {s}" ++
                    " (version 40 holds at most 2953). Lower --ecc or split it with --seq.\n",
                .{ opts.text.len, eccName(opts.enc.ecc) },
            );
        },
        error.ModeMismatch => std.debug.print(
            "qr-demo: the input cannot be expressed in the forced --mode." ++
                " Numeric is 0-9 only; alphanumeric is 0-9 A-Z space and $%*+-./: -- UPPER case only.\n",
            .{},
        ),
        // Unreachable from this CLI (`--version` is range-checked in
        // `parseArgs`), but naming it here is the point: a caller that takes the
        // version from somewhere else gets a distinct error rather than
        // `TooLong`, and the example should not pretend the branch is not there.
        error.BadVersion => std.debug.print("qr-demo: --version must be 1..40\n", .{}),
    }
    return 1;
}

fn eccName(e: qr.Ecc) []const u8 {
    return switch (e) {
        .low => "L (~7 %)",
        .medium => "M (~15 %)",
        .quartile => "Q (~25 %)",
        .high => "H (~30 %)",
    };
}

/// The report line, and the reason `Options`' fields are nullable: it says of
/// each of the three choices whether the module made it or the caller did.
fn describe(buf: []u8, m: *const qr.Matrix, opts: Options) ![]const u8 {
    return std.fmt.bufPrint(buf, "version {d} ({d}x{d} modules), level {s}, mask {d} -- version {s}, mask {s}, mode {s}", .{
        m.version,
        m.size,
        m.size,
        eccName(m.ecc),
        m.mask,
        if (opts.enc.version == null) "chosen" else "forced",
        if (opts.enc.mask == null) "chosen" else "forced",
        if (opts.enc.mode == null) "chosen" else "forced",
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// structured append (--seq)
// ─────────────────────────────────────────────────────────────────────────────

fn runSequence(gpa: Allocator, io: std.Io, opts: Options, room: usize) !u8 {
    // 16 matrices is 63 KB. Heap rather than the frame: an example should not
    // be the thing that teaches a reader to put 63 KB on a stack that a thread
    // pool might have sized at 64.
    var describe_buf: [256]u8 = undefined;
    const symbols = try gpa.alloc(qr.Matrix, room);
    defer gpa.free(symbols);

    const seq = qr.encodeSequence(symbols, opts.text, opts.enc) catch |err| return reportEncodeError(err, opts);

    try printOut(io, "split {d} bytes across {d} symbols, each {s}\n", .{
        opts.text.len,
        seq.len,
        try describe(&describe_buf, &seq[0], opts),
    });

    // Reassembly is the caller's — this is what that looks like. The parity
    // byte is what makes it safe: it is the same in every symbol of one
    // sequence and different between sequences, so it distinguishes "a symbol
    // is missing" from "two different messages were scanned into one buffer",
    // which an index and a count cannot.
    const joined = try gpa.alloc(u8, opts.text.len + max_message);
    defer gpa.free(joined);
    var used: usize = 0;
    var parity: ?u8 = null;

    for (seq, 0..) |*sym, i| {
        var buf: [max_message]u8 = undefined;
        const part = qr.decodePart(sym, &buf) catch |err| {
            std.debug.print("qr-demo: symbol {d} does not decode: {t}\n", .{ i + 1, err });
            return 1;
        };
        const s = part.sequence orelse {
            std.debug.print("qr-demo: symbol {d} carries no structured-append header\n", .{i + 1});
            return 1;
        };
        if (parity) |p| {
            if (p != s.parity) {
                std.debug.print("qr-demo: symbol {d} belongs to a different sequence (parity {x:0>2} vs {x:0>2})\n", .{ i + 1, s.parity, p });
                return 1;
            }
        } else parity = s.parity;
        if (s.index != i) {
            std.debug.print("qr-demo: symbol {d} says it is index {d}\n", .{ i + 1, s.index });
            return 1;
        }
        @memcpy(joined[used..][0..part.data.len], part.data);
        used += part.data.len;
        try printOut(io, "  symbol {d}/{d}: {d} bytes, parity {x:0>2}\n", .{ s.index + 1, s.total, part.data.len, s.parity });
    }

    const message = joined[0..used];
    if (qr.sequenceParity(message) != parity.?) {
        std.debug.print("qr-demo: reassembled message fails the parity check -- a symbol is missing or foreign\n", .{});
        return 1;
    }
    if (!std.mem.eql(u8, message, opts.text)) {
        std.debug.print("qr-demo: reassembled {d} bytes, expected {d}\n", .{ message.len, opts.text.len });
        return 1;
    }
    try printOut(io, "self-check: reassembled {d} bytes, parity ok, identical to the input\n", .{message.len});

    // A plain `decode` must REFUSE a part rather than hand back a fragment: a
    // caller told nothing about the other fifteen symbols would act on a
    // truncated message. Worth showing, because it is the one place the API
    // returns an error for a symbol that is perfectly well formed.
    var buf: [max_message]u8 = undefined;
    if (qr.decode(&seq[0], &buf)) |_| {
        std.debug.print("qr-demo: decode() returned a bare fragment; it should refuse one\n", .{});
        return 1;
    } else |err| if (err != error.StructuredAppend) {
        std.debug.print("qr-demo: decode() of a part gave {t}, expected StructuredAppend\n", .{err});
        return 1;
    }
    try printOut(io, "decode() refuses a single part with error.StructuredAppend, as it should\n", .{});

    for (seq, 0..) |*sym, i| {
        if (opts.png_path) |path| {
            const p = try numberedPath(gpa, path, i + 1, seq.len);
            defer gpa.free(p);
            try emitPng(gpa, io, p, sym, opts);
        }
        if (opts.svg_path) |path| {
            const p = try numberedPath(gpa, path, i + 1, seq.len);
            defer gpa.free(p);
            try emitSvg(gpa, io, p, sym, opts);
        }
        if (opts.terminal) {
            try printOut(io, "-- symbol {d}/{d} --\n", .{ i + 1, seq.len });
            try emitTerminal(io, sym, opts);
        }
    }
    return 0;
}

/// `out.png` + symbol 2 of 3 -> `out-2of3.png`. Inserted before the extension
/// so the file still opens in whatever is registered for `.png`.
fn numberedPath(gpa: Allocator, path: []const u8, index: usize, total: usize) ![]u8 {
    const dot = std.mem.lastIndexOfScalar(u8, path, '.') orelse path.len;
    return std.fmt.allocPrint(gpa, "{s}-{d}of{d}{s}", .{ path[0..dot], index, total, path[dot..] });
}

// ─────────────────────────────────────────────────────────────────────────────
// output
// ─────────────────────────────────────────────────────────────────────────────

fn emitSvg(gpa: Allocator, io: std.Io, path: []const u8, m: *const qr.Matrix, opts: Options) !void {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try qr.writeSvg(&aw.writer, m, .{
        .scale = opts.scale,
        .quiet = opts.quiet,
        .title = opts.text,
    });
    try writeWholeFile(io, path, aw.written());
    try printOut(io, "wrote {s} ({d} bytes, {d}x{d} px)\n", .{
        path,
        aw.written().len,
        (@as(u32, m.size) + 2 * @as(u32, opts.quiet)) * opts.scale,
        (@as(u32, m.size) + 2 * @as(u32, opts.quiet)) * opts.scale,
    });
}

fn emitTerminal(io: std.Io, m: *const qr.Matrix, opts: Options) !void {
    // Two module rows per line, so a version 40 is 185 characters wide and
    // needs a wide window; that is the format's doing, not the renderer's.
    var buf: [8192]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try qr.writeTerminal(&w.interface, m, .{
        .quiet = opts.quiet,
        .dark_background = opts.dark_background,
    });
    try w.interface.flush();
}

fn emitPng(gpa: Allocator, io: std.Io, path: []const u8, m: *const qr.Matrix, opts: Options) !void {
    const bytes = try renderPng(gpa, m, opts.scale, opts.quiet);
    defer gpa.free(bytes);
    try writeWholeFile(io, path, bytes);
    const px = (@as(u32, m.size) + 2 * @as(u32, opts.quiet)) * opts.scale;
    try printOut(io, "wrote {s} ({d} bytes, {d}x{d} px, {d} px per module)\n", .{ path, bytes.len, px, px, opts.scale });
}

fn writeWholeFile(io: std.Io, path: []const u8, bytes: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var buf: [4096]u8 = undefined;
    var fw = file.writer(io, &buf);
    try fw.interface.writeAll(bytes);
    try fw.interface.flush();
}

fn printOut(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [1024]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.print(fmt, args);
    try w.interface.flush();
}

// ─────────────────────────────────────────────────────────────────────────────
// PNG — this example's own code, not the module's
// ─────────────────────────────────────────────────────────────────────────────
//
// There is no image module in this collection, and an example is given only its
// own module and that module's declared dependencies, so a PNG writer cannot be
// factored out anywhere. It lives here, and it is deliberately the narrowest
// PNG that exists: 8-bit grayscale (colour type 0), non-interlaced, one `IDAT`,
// no ancillary chunks. That is a legal PNG every decoder reads, and it is not a
// general-purpose encoder — it cannot write colour, transparency, palettes or
// 16-bit samples, and it never needs to, because a QR symbol is one bit per
// module.
//
// Only the framing is written by hand: the signature, `IHDR`/`IDAT`/`IEND` with
// their length + type + CRC-32 envelope. The compression is `std.compress.flate`
// with a zlib container, which is what `IDAT` holds — no third-party code, and
// none of this reaches into the `qr` module, which has no pixel format at all.

const png_signature = [_]u8{ 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a };

/// Render `m` as a complete PNG file and return the bytes (caller frees).
fn renderPng(gpa: Allocator, m: *const qr.Matrix, scale: u32, quiet: u8) ![]u8 {
    const n: u32 = @as(u32, m.size) + 2 * @as(u32, quiet);
    const px = n * scale;

    // One PNG scanline is a filter byte followed by the row's samples. Filter 0
    // ("None") throughout: a QR symbol at any scale is long runs of one value,
    // which deflate already compresses to nothing, and choosing filters per row
    // is the part of PNG encoding that has real complexity for no gain here.
    var raw: std.Io.Writer.Allocating = try .initCapacity(gpa, (px + 1) * px);
    defer raw.deinit();
    var y: u32 = 0;
    while (y < px) : (y += 1) {
        try raw.writer.writeByte(0); // filter: None
        const my = y / scale;
        var x: u32 = 0;
        while (x < px) : (x += 1) {
            const mx = x / scale;
            const dark = mx >= quiet and my >= quiet and
                mx < @as(u32, quiet) + m.size and my < @as(u32, quiet) + m.size and
                m.isDark(@intCast(mx - quiet), @intCast(my - quiet));
            try raw.writer.writeByte(if (dark) 0x00 else 0xff);
        }
    }

    var idat: std.Io.Writer.Allocating = try .initCapacity(gpa, 4096);
    defer idat.deinit();
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var deflate = try std.compress.flate.Compress.init(&idat.writer, &window, .zlib, .default);
    try deflate.writer.writeAll(raw.written());
    try deflate.finish();

    var out: std.Io.Writer.Allocating = try .initCapacity(gpa, idat.written().len + 128);
    errdefer out.deinit();
    try out.writer.writeAll(&png_signature);

    var ihdr: [13]u8 = undefined;
    std.mem.writeInt(u32, ihdr[0..4], px, .big);
    std.mem.writeInt(u32, ihdr[4..8], px, .big);
    ihdr[8] = 8; // bit depth
    ihdr[9] = 0; // colour type: grayscale
    ihdr[10] = 0; // compression: deflate (the only value the format defines)
    ihdr[11] = 0; // filter method: the adaptive set (the only value)
    ihdr[12] = 0; // interlace: none
    try writeChunk(&out.writer, "IHDR", &ihdr);
    try writeChunk(&out.writer, "IDAT", idat.written());
    try writeChunk(&out.writer, "IEND", "");

    return out.toOwnedSlice();
}

/// `length | type | data | CRC-32(type ++ data)`, all big-endian. The CRC covers
/// the type as well as the data, which is the detail a hand-written PNG writer
/// gets wrong first.
fn writeChunk(w: *std.Io.Writer, kind: *const [4]u8, data: []const u8) !void {
    var crc: std.hash.Crc32 = .init();
    crc.update(kind);
    crc.update(data);
    try w.writeInt(u32, @intCast(data.len), .big);
    try w.writeAll(kind);
    try w.writeAll(data);
    try w.writeInt(u32, crc.final(), .big);
}
