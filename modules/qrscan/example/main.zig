// SPDX-License-Identifier: MIT

//! `qrscan-demo` — read an image file and print what the QR code in it says.
//!
//! `qrscan` takes luminance and a stride, never a file: the two real sources of
//! an image are a V4L2 camera plane (already 8-bit luma, padded rows) and a
//! browser canvas (RGBA, tight rows), and neither is a PNG (README, "Luminance
//! in, not a file"). Decoding a container is a job for a module about images,
//! and there is no such module here — and an example is given only its own
//! module and that module's declared dependencies, so this file cannot factor
//! the decoding out anywhere. It therefore carries its own readers, in the
//! "image files" section at the bottom:
//!
//!   * **PNG**, deliberately narrow: non-interlaced, colour types 0/2/4/6
//!     (grey, RGB, grey+alpha, RGBA) at 8 bits, plus 1/2/4-bit grey — which is
//!     not an exotic corner but the common one, since a QR code has two colours
//!     and ImageMagick writes any two-colour image as 1-bit grey. No palettes,
//!     no 16-bit samples, no Adam7. Inflation is `std.compress.flate`; only the
//!     chunk framing, the sample unpacking and the five row filters are here.
//!   * **PGM (P5)**, twenty lines, and the reason it is here: `magick x.jpg
//!     x.pgm` turns *anything* ImageMagick reads into a file this tool
//!     accepts, so the narrowness above costs a reader nothing.
//!
//! The format is chosen by magic bytes, not by the extension.
//!
//! What it demonstrates about the module, beyond "call scan":
//!
//!   * **What it took to get there.** `scan` reports `module_px`, the estimated
//!     module size in pixels, and the grid it returns carries the version, the
//!     level and the mask it read out of the format information. `-v` prints
//!     all of it, plus how the module size compares to the three-pixel floor
//!     below which binarisation is deciding modules from single pixels. A
//!     reader learns more from a tool that says so than from one that prints a
//!     string.
//!   * **Two failures that are not the same failure.** `Error.NotFound` means
//!     no symbol was located — a scanner problem, and the place to quote the
//!     module's stated limits. `qr.DecodeError.Uncorrectable` means one was
//!     located and read, and the Reed-Solomon blocks carried more damage than
//!     the level can repair — a decode problem. `qrscan` deliberately does not
//!     merge them, and neither does this tool.
//!   * **Structured append across several files.** Give it more than one image
//!     and it reassembles the parts in index order and checks
//!     `qr.sequenceParity`, which is what distinguishes a missing symbol from
//!     two different messages scanned into the same buffer.
//!
//! Built against the PUBLISHED modules (`@import("qrscan")` and its one
//! declared dependency, `@import("qr")`) only.

const std = @import("std");
const qrscan = @import("qrscan");
const qr = @import("qr");

const Allocator = std.mem.Allocator;

/// Version 40-L holds 2953 bytes; nothing `qr.decode` can return is longer.
const max_message = 3000;
/// `qrscan.max_dimension` is 8192, so an 8-bit sample plane is at most 64 MiB;
/// a PNG's inflated scanlines with RGBA and a filter byte per row are at most
/// four times that plus the row prefixes. Rounded up, and a cap rather than a
/// promise: a file bigger than this is refused with a message instead of being
/// discovered to be too big somewhere deeper.
const max_file_bytes: usize = 300 * 1024 * 1024;

const usage_text =
    \\qrscan-demo -- find a QR symbol in an image and print what it says.
    \\
    \\usage:
    \\  qrscan-demo [options] IMAGE [IMAGE ...]
    \\
    \\  -v, --verbose   report the geometry the scanner recovered, not just the text
    \\  -q, --quiet     print only the decoded message
    \\  -h, --help      this text
    \\
    \\Accepts PNG (8-bit, non-interlaced) and PGM (P5), chosen by magic bytes rather
    \\than by the extension. Anything else:  magick photo.jpg photo.pgm
    \\
    \\More than one IMAGE is treated as the parts of one structured-append sequence
    \\and reassembled in index order, with the parity byte checked.
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes the example a leak detector
    // for the module's ownership contract (CONVENTIONS.md §7.2). `qrscan`
    // allocates nothing itself — it takes one caller-owned scratch buffer,
    // sized by `qrscan.scratchSize` — so what this proves is that the sizing
    // contract is followable from outside without leaking the buffer.
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.next(); // argv[0]

    // No arguments at all -> self-demo. `probe` is a value copy (the POSIX
    // iterator is just a slice), so peeking here consumes nothing the loop
    // below would otherwise see.
    var probe = args;
    if (probe.next() == null) return runSelfDemo(gpa, io);

    var verbose = false;
    var quiet = false;
    var paths: std.ArrayList([]const u8) = .empty;
    defer paths.deinit(gpa);

    while (args.next()) |arg| {
        if (eq(arg, "-h") or eq(arg, "--help")) {
            try printOut(io, "{s}", .{usage_text});
            return 0;
        } else if (eq(arg, "-v") or eq(arg, "--verbose")) {
            verbose = true;
        } else if (eq(arg, "-q") or eq(arg, "--quiet")) {
            quiet = true;
        } else if (arg.len > 1 and arg[0] == '-') {
            std.debug.print("qrscan-demo: unknown option '{s}'\n", .{arg});
            return 1;
        } else {
            try paths.append(gpa, arg);
        }
    }

    if (paths.items.len == 0) {
        try printOut(io, "{s}", .{usage_text});
        return 1;
    }

    return if (paths.items.len == 1)
        scanOne(gpa, io, paths.items[0], verbose, quiet)
    else
        scanSequence(gpa, io, paths.items, verbose, quiet);
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

// ─────────────────────────────────────────────────────────────────────────────
// no arguments — self-demo
// ─────────────────────────────────────────────────────────────────────────────
//
// `qrscan` has no encoder of its own (`meta.deps = .{"qr"}`, one-directional):
// its self-demo therefore encodes with `qr.encode`, rasterises the symbol
// into an actual pixel bitmap, writes that bitmap as a REAL PGM file on disk
// (the twenty-line format this program already reads for any input `magick`
// cannot produce directly), and then reads it back through this program's
// OWN `loadImage` -> `qrscan.scan` -> `qr.decodePart` path — the exact code
// `scanOne` runs against a file from the command line. That is a genuine
// exercise of the finder/binariser, not a shortcut that hands `scan` a matrix
// it already knows the answer to.

fn runSelfDemo(gpa: Allocator, io: std.Io) !u8 {
    try selfDemoCase(gpa, io, ".zig-cache/qrscan-selfdemo-1.pgm", "zig-libs qrscan module -- self-demo round trip", .{});

    // The "not trivially easy" case: a long payload at the highest
    // error-correction level, forcing a bigger, denser symbol than the short
    // case above -- more modules for the finder/binariser to get right, not
    // just more bytes for the codec.
    const hard_text = "zig-libs qrscan module self-demo, harder case: a longer payload at ECC level H, " ++
        "forcing a bigger, denser version than the short case above. Rasterised to a real PGM file, " ++
        "located and sampled back by qrscan.scan() -- not handed the matrix directly -- decoded with " ++
        "qr.decodePart(), and compared byte-for-byte against this exact string.";
    try selfDemoCase(gpa, io, ".zig-cache/qrscan-selfdemo-2.pgm", hard_text, .{ .ecc = .high });

    try printOut(io, "self-demo passed: both symbols were located and decoded back off a real PGM file\n", .{});
    return 0;
}

fn selfDemoCase(gpa: Allocator, io: std.Io, path: []const u8, text: []const u8, opts: qr.Options) !void {
    var m: qr.Matrix = undefined;
    try qr.encode(&m, text, opts);

    // 6 px/module is comfortably above the module's stated 3 px/module floor
    // (see `marginNote` below), so this proves normal-condition scanning, not
    // a worst-case angle or resolution.
    const scale: u32 = 6;
    const quiet: u32 = qr.quiet_zone;
    const raster = try rasterizeMatrix(gpa, &m, scale, quiet);
    defer gpa.free(raster.luma);

    try writePgmFile(io, path, raster);
    // Delete the file regardless of what happens below -- this demo must
    // leave nothing behind, success or failure.
    defer std.Io.Dir.cwd().deleteFile(io, path) catch |err| {
        std.debug.print("qrscan-demo: self-demo: could not remove {s}: {t}\n", .{ path, err });
    };

    // From here down this is exactly `readAndDecode`'s body: load the file
    // this program's own reader understands, size the scratch buffer with
    // `qrscan.scratchSize` (never guessed), scan, and decode the part.
    var image = try loadImage(gpa, io, path);
    defer image.deinit(gpa);

    const scratch = try gpa.alloc(u8, qrscan.scratchSize(image.width, image.height));
    defer gpa.free(scratch);
    const img: qrscan.Image = .{ .luma = image.luma, .width = image.width, .height = image.height, .stride = image.width };
    const found = qrscan.scan(img, scratch) catch |err| {
        std.debug.print("qrscan-demo: self-demo: {s} was not located: {t}\n", .{ path, err });
        return err;
    };

    var buf: [max_message]u8 = undefined;
    const part = qr.decodePart(&found.matrix, &buf) catch |err| {
        std.debug.print("qrscan-demo: self-demo: {s} was located but did not decode: {t}\n", .{ path, err });
        return err;
    };
    if (part.sequence != null) @panic("qrscan-demo: self-demo: symbol unexpectedly carries a structured-append header");
    if (!std.mem.eql(u8, part.data, text)) @panic("qrscan-demo: self-demo: decoded text read back off the PGM does not match the input");

    try printOut(io, "{s}: {d}x{d} px, module_px {d:.2}, decoded {d} bytes correctly\n", .{
        path, image.width, image.height, found.module_px, part.data.len,
    });
}

const Raster = struct { luma: []u8, width: u32, height: u32 };

/// Render `m` to a tight-row 8-bit luma bitmap: `quiet` modules of white
/// border, then `scale` pixels per module, matching `modules/qr/example`'s
/// `renderPng` layout exactly -- this file just skips PNG's compression and
/// framing, since PGM does not have any.
fn rasterizeMatrix(gpa: Allocator, m: *const qr.Matrix, scale: u32, quiet: u32) !Raster {
    const n = @as(u32, m.size) + 2 * quiet;
    const px = n * scale;
    const luma = try gpa.alloc(u8, @as(usize, px) * px);
    errdefer gpa.free(luma);
    for (0..px) |y| {
        const my = @as(u32, @intCast(y)) / scale;
        for (0..px) |x| {
            const mx = @as(u32, @intCast(x)) / scale;
            const dark = mx >= quiet and my >= quiet and
                mx < quiet + m.size and my < quiet + m.size and
                m.isDark(@intCast(mx - quiet), @intCast(my - quiet));
            luma[y * px + x] = if (dark) 0 else 255;
        }
    }
    return .{ .luma = luma, .width = px, .height = px };
}

/// `P5\n{width} {height}\n255\n` then raw samples -- the format `decodePgm`
/// below reads, written by hand rather than through any image library.
fn writePgmFile(io: std.Io, path: []const u8, raster: Raster) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    var wbuf: [256]u8 = undefined;
    var fw = file.writer(io, &wbuf);
    try fw.interface.print("P5\n{d} {d}\n255\n", .{ raster.width, raster.height });
    try fw.interface.writeAll(raster.luma);
    try fw.interface.flush();
}

// ─────────────────────────────────────────────────────────────────────────────
// scanning
// ─────────────────────────────────────────────────────────────────────────────

/// One image, scanned and decoded. Held apart from the printing so the
/// single-image and sequence paths share exactly one implementation of "what
/// does `scan` + `decode` do to a file".
const Read = struct {
    image: Image,
    found: qrscan.Found,
    part: qr.Part,
    buf: []u8,

    fn deinit(self: *Read, gpa: Allocator) void {
        gpa.free(self.buf);
        self.image.deinit(gpa);
    }
};

/// `null` means the failure has already been reported.
fn readAndDecode(gpa: Allocator, io: std.Io, path: []const u8, verbose: bool) !?Read {
    var image = loadImage(gpa, io, path) catch |err| {
        reportImageError(err, path);
        return null;
    };
    errdefer image.deinit(gpa);

    // The module publishes the size rather than a maximum, and the README says
    // to call it rather than work the number out: it covers the bitmap, the
    // per-block means and the labeller's runs, and what it covers has changed
    // before. So this is `scratchSize`, never an arithmetic guess.
    const scratch = try gpa.alloc(u8, qrscan.scratchSize(image.width, image.height));
    defer gpa.free(scratch);

    const img: qrscan.Image = .{
        .luma = image.luma,
        .width = image.width,
        .height = image.height,
        // Tight, because these two file formats are tight. A camera plane is
        // not, which is why the field exists at all.
        .stride = image.width,
    };

    const found = qrscan.scan(img, scratch) catch |err| {
        reportScanError(err, path, image, verbose);
        image.deinit(gpa);
        return null;
    };

    const buf = try gpa.alloc(u8, max_message);
    errdefer gpa.free(buf);

    // `decodePart`, not `decode`: a symbol that is one of sixteen is a perfectly
    // good symbol, and `decode` refuses it (`error.StructuredAppend`) precisely
    // so that a caller cannot act on a fragment by accident. A scanner is the
    // caller that *does* want the fragment.
    const part = qr.decodePart(&found.matrix, buf) catch |err| {
        reportDecodeError(err, path, found);
        gpa.free(buf);
        image.deinit(gpa);
        return null;
    };

    return .{ .image = image, .found = found, .part = part, .buf = buf };
}

fn scanOne(gpa: Allocator, io: std.Io, path: []const u8, verbose: bool, quiet: bool) !u8 {
    var r = (try readAndDecode(gpa, io, path, verbose)) orelse return 1;
    defer r.deinit(gpa);

    if (verbose) try reportGeometry(io, path, r.image, r.found);

    if (r.part.sequence) |s| {
        if (!quiet) {
            try printOut(io,
                \\{s}: symbol {d} of {d} of a structured-append sequence (parity {x:0>2}).
                \\This is a fragment, not the message -- pass the other {d} image{s} too.
                \\
            , .{ path, @as(u16, s.index) + 1, s.total, s.parity, s.total - 1, if (s.total == 2) "" else "s" });
        }
        try printOut(io, "{s}\n", .{r.part.data});
        return 0;
    }

    if (!quiet) try printOut(io, "{s}: ", .{path});
    try printOut(io, "{s}\n", .{r.part.data});
    return 0;
}

fn scanSequence(gpa: Allocator, io: std.Io, paths: []const []const u8, verbose: bool, quiet: bool) !u8 {
    // Sixteen fragments at version 40 is under 48 KB; the module cannot hold
    // them for you (it allocates nothing), so reassembly looks like this.
    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(gpa);

    var parity: ?u8 = null;
    var expected_total: ?u5 = null;
    var next_index: u16 = 0;

    for (paths) |path| {
        var r = (try readAndDecode(gpa, io, path, verbose)) orelse return 1;
        defer r.deinit(gpa);

        if (verbose) try reportGeometry(io, path, r.image, r.found);

        const s = r.part.sequence orelse {
            std.debug.print(
                "qrscan-demo: {s} is a whole message, not part of a sequence;" ++
                    " pass one image at a time for those\n",
                .{path},
            );
            return 1;
        };
        // The parity byte is the check that makes reassembly safe: it is the
        // same in every symbol of one sequence and different between sequences,
        // so it tells "a symbol is missing" from "two different messages were
        // scanned into one buffer". An index and a count cannot.
        if (parity) |p| {
            if (p != s.parity) {
                std.debug.print(
                    "qrscan-demo: {s} has parity {x:0>2} but the sequence so far has {x:0>2}" ++
                        " -- these are symbols of two different messages\n",
                    .{ path, s.parity, p },
                );
                return 1;
            }
        } else parity = s.parity;
        if (expected_total) |t| {
            if (t != s.total) {
                std.debug.print("qrscan-demo: {s} says the sequence has {d} symbols, an earlier one said {d}\n", .{ path, s.total, t });
                return 1;
            }
        } else expected_total = s.total;
        if (s.index != next_index) {
            std.debug.print("qrscan-demo: {s} is symbol {d}; expected {d} -- pass the images in index order\n", .{ path, @as(u16, s.index) + 1, next_index + 1 });
            return 1;
        }
        next_index += 1;

        try joined.appendSlice(gpa, r.part.data);
        if (!quiet) try printOut(io, "{s}: symbol {d}/{d}, {d} bytes\n", .{ path, @as(u16, s.index) + 1, s.total, r.part.data.len });
    }

    if (next_index != expected_total.?) {
        std.debug.print("qrscan-demo: got {d} of {d} symbols\n", .{ next_index, expected_total.? });
        return 1;
    }
    if (qr.sequenceParity(joined.items) != parity.?) {
        std.debug.print("qrscan-demo: the reassembled message fails the parity check\n", .{});
        return 1;
    }
    if (!quiet) try printOut(io, "reassembled {d} bytes from {d} symbols, parity {x:0>2} ok\n", .{ joined.items.len, next_index, parity.? });
    try printOut(io, "{s}\n", .{joined.items});
    return 0;
}

/// Everything the module tells a caller about how the symbol was found.
///
/// Note what is *not* printed: the error-correction level and the mask. `scan`
/// fills in only `size` on the grid it returns — `version`, `ecc` and `mask` are
/// still `qr.Matrix`'s field defaults (0, `.medium`, 0), so printing them would
/// be printing a default and calling it a measurement. `qr.decodePart` does read
/// the real level and mask out of the format information, and does not return
/// them. The version below is therefore derived from the grid's own side length,
/// which is exact — `size == 17 + 4v` is the standard's definition, not an
/// inference — and the rest is left out rather than guessed at.
fn reportGeometry(io: std.Io, path: []const u8, image: Image, found: qrscan.Found) !void {
    const size = found.matrix.size;
    const version = (size - 17) / 4;
    const span = found.module_px * @as(f32, @floatFromInt(size));
    try printOut(io,
        \\{s}: {s}, {d}x{d} px
        \\  symbol   version {d}, {d}x{d} modules
        \\  sampling {d:.2} px per module, so the symbol spans about {d:.0} px of {d}
        \\  margin   {s}
        \\
    , .{
        path,
        image.source,
        image.width,
        image.height,
        version,
        size,
        size,
        found.module_px,
        span,
        @min(image.width, image.height),
        marginNote(found.module_px),
    });
}

/// Three pixels per module is the module's stated floor: below it binarisation
/// is deciding modules from single pixels. At three, a version 37 reads at about
/// 94 % of angles and a version 1 at about 79 %; at four, both are 100 %.
fn marginNote(module_px: f32) []const u8 {
    if (module_px < 3) return "BELOW the 3 px/module floor -- this read was luck, move closer";
    if (module_px < 4) return "at the 3-4 px/module edge, where some angles fail";
    return "comfortably above the 3 px/module floor";
}

/// `qrscan`'s three errors, each named. `NotFound` is the interesting one and
/// the only place worth quoting the module's limits — the other two are the
/// caller having got the call wrong, not the picture being hard.
fn reportScanError(err: qrscan.Error, path: []const u8, image: Image, verbose: bool) void {
    switch (err) {
        error.NotFound => {
            std.debug.print("qrscan-demo: {s}: no QR symbol located in {d}x{d} px\n", .{ path, image.width, image.height });
            if (verbose) std.debug.print(
                \\  The module locates finders by the rotation-invariant 1:1:3:1:1 ratio, so
                \\  rotation is not the usual reason. Its stated limits are:
                \\    * tilt to about 15-25 deg off-axis, not to 60 -- and a version 1 to
                \\      about 10, because it has no alignment patterns for a projective fit
                \\    * three pixels per module is the floor
                \\    * curvature is not modelled at all
                \\    * one symbol per image: several are found, only the best is sampled
                \\
            , .{});
        },
        // Unreachable from this tool, which sizes the buffer with
        // `qrscan.scratchSize` -- named anyway, because a caller who guessed
        // the size instead lands here and the message should say so.
        error.ScratchTooSmall => std.debug.print(
            "qrscan-demo: {s}: scratch buffer too small -- size it with qrscan.scratchSize()\n",
            .{path},
        ),
        error.BadImage => std.debug.print(
            "qrscan-demo: {s}: {d}x{d} px is not a scannable image -- under 21 px holds no legal symbol," ++
                " and over {d} (qrscan.max_dimension) is refused\n",
            .{ path, image.width, image.height, qrscan.max_dimension },
        ),
    }
}

/// A located symbol that will not read is a different event from a symbol that
/// was never located, and `Uncorrectable` in particular is the module keeping a
/// promise: past the level's capability it declines rather than returning a
/// plausible wrong string, which is the failure that actually costs somebody
/// something.
fn reportDecodeError(err: qr.DecodeError, path: []const u8, found: qrscan.Found) void {
    const m = found.matrix;
    // Derived from the side length, not read off `m.version`: see
    // `reportGeometry` for why a scanned grid's `version` field is a default.
    const version = (m.size - 17) / 4;
    switch (err) {
        error.Uncorrectable => std.debug.print(
            "qrscan-demo: {s}: found a version {d} symbol at {d:.2} px per module, but its Reed-Solomon blocks" ++
                " carry more damage than its level can repair. It declines rather than guessing.\n",
            .{ path, version, found.module_px },
        ),
        error.BadFormat => std.debug.print(
            "qrscan-demo: {s}: a {d}x{d} grid was sampled but neither copy of its format information is valid" ++
                " -- usually the grid is off by a module, so the sampling missed\n",
            .{ path, m.size, m.size },
        ),
        error.BadData => std.debug.print(
            "qrscan-demo: {s}: the codewords corrected cleanly but are not a well-formed segment stream\n",
            .{path},
        ),
        error.BadSize => std.debug.print(
            "qrscan-demo: {s}: sampled a {d}x{d} grid, which is not 17 + 4v for any version\n",
            .{ path, m.size, m.size },
        ),
        error.BufferTooSmall => std.debug.print(
            "qrscan-demo: {s}: the message is longer than this tool's {d}-byte buffer\n",
            .{ path, max_message },
        ),
        // `readAndDecode` calls `decodePart`, which returns the fragment rather
        // than refusing it, so this cannot arrive -- named so the switch stays
        // exhaustive and a reader can see which call site the distinction
        // belongs to.
        error.StructuredAppend => std.debug.print(
            "qrscan-demo: {s}: structured-append symbol reached the wrong path\n",
            .{path},
        ),
    }
}

/// The readers below are narrow on purpose, so their refusals have to say what
/// would widen them — and for every one of them the answer is the same single
/// `magick` command, which is the whole argument for carrying a PGM reader.
fn reportImageError(err: anyerror, path: []const u8) void {
    switch (err) {
        error.NotAnImage => std.debug.print(
            "qrscan-demo: {s}: not a PNG or a PGM (P5), judging by its first bytes." ++
                " Convert it:  magick {s} out.pgm\n",
            .{ path, path },
        ),
        error.UnsupportedPng => std.debug.print(
            "qrscan-demo: {s}: a PNG this reader does not do -- it does 1/2/4/8-bit grey and" ++
                " 8-bit RGB/grey+alpha/RGBA, non-interlaced, and not palettes, 16-bit samples" ++
                " or Adam7.  magick {s} out.pgm\n",
            .{ path, path },
        ),
        error.UnsupportedPgm => std.debug.print(
            "qrscan-demo: {s}: a PGM this reader does not do (16-bit, or a malformed header)." ++
                "  magick {s} -depth 8 out.pgm\n",
            .{ path, path },
        ),
        error.ImageTooLarge => std.debug.print(
            "qrscan-demo: {s}: larger than qrscan.max_dimension ({d} px on a side)\n",
            .{ path, qrscan.max_dimension },
        ),
        error.CorruptImage => std.debug.print("qrscan-demo: {s}: truncated or corrupt\n", .{path}),
        else => std.debug.print("qrscan-demo: {s}: {t}\n", .{ path, err }),
    }
}

fn printOut(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.print(fmt, args);
    try w.interface.flush();
}

// ─────────────────────────────────────────────────────────────────────────────
// image files — this example's own code, not the module's
// ─────────────────────────────────────────────────────────────────────────────
//
// `qrscan` takes luma and a stride and says so on purpose; turning a container
// into that is a job for a module about images, and there is none here. So this
// section exists, and it is kept as small as the job allows: two formats, one
// sample depth, no interlacing. Anything else is one `magick` invocation away
// from being a P5, which is what makes that narrowness affordable.

const ImageError = error{
    NotAnImage,
    UnsupportedPng,
    UnsupportedPgm,
    CorruptImage,
    ImageTooLarge,
} || Allocator.Error;

const Image = struct {
    /// 8-bit luminance, tight rows (`stride == width`).
    luma: []u8,
    width: u32,
    height: u32,
    /// For the `-v` report: which reader produced this and from what.
    source: []const u8,

    fn deinit(self: *Image, gpa: Allocator) void {
        gpa.free(self.luma);
        self.* = undefined;
    }
};

fn loadImage(gpa: Allocator, io: std.Io, path: []const u8) !Image {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(max_file_bytes));
    defer gpa.free(bytes);

    // By magic bytes, not by extension: a file named `.png` that a pipeline
    // actually wrote as a PGM is a real thing, and guessing from the name gets
    // it wrong in the direction that produces a confusing error.
    if (bytes.len >= 8 and std.mem.eql(u8, bytes[0..8], &png_signature)) return decodePng(gpa, bytes);
    if (bytes.len >= 2 and bytes[0] == 'P' and bytes[1] == '5') return decodePgm(gpa, bytes);
    return ImageError.NotAnImage;
}

// ── PNG ─────────────────────────────────────────────────────────────────────

const png_signature = [_]u8{ 0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a };

fn decodePng(gpa: Allocator, file: []const u8) !Image {
    var width: u32 = 0;
    var height: u32 = 0;
    var channels: u32 = 0;
    var depth: u8 = 0;
    var have_ihdr = false;

    var idat: std.ArrayList(u8) = .empty;
    defer idat.deinit(gpa);

    var off: usize = png_signature.len;
    while (true) {
        if (off + 8 > file.len) return ImageError.CorruptImage;
        const len = std.mem.readInt(u32, file[off..][0..4], .big);
        const kind = file[off + 4 ..][0..4];
        if (off + 12 + len > file.len) return ImageError.CorruptImage;
        const data = file[off + 8 ..][0..len];
        const want = std.mem.readInt(u32, file[off + 8 + len ..][0..4], .big);

        // The CRC covers the type as well as the data. Checked rather than
        // skipped: this reader is handed files from outside, and a truncated
        // download that still parses is exactly how a scanner ends up blaming
        // the camera for a network problem.
        var crc: std.hash.Crc32 = .init();
        crc.update(kind);
        crc.update(data);
        if (crc.final() != want) return ImageError.CorruptImage;
        off += 12 + len;

        if (std.mem.eql(u8, kind, "IHDR")) {
            if (len != 13) return ImageError.CorruptImage;
            width = std.mem.readInt(u32, data[0..4], .big);
            height = std.mem.readInt(u32, data[4..8], .big);
            depth = data[8];
            const colour = data[9];
            const interlace = data[12];
            // The narrowness, stated once and enforced once.
            if (interlace != 0) return ImageError.UnsupportedPng; // no Adam7
            channels = switch (colour) {
                0 => 1, // grey
                2 => 3, // RGB
                4 => 2, // grey + alpha
                6 => 4, // RGBA
                else => return ImageError.UnsupportedPng, // 3 == palette
            };
            // 1, 2 and 4-bit grey is not an exotic corner here, it is the
            // COMMON case: a QR code has two colours, and ImageMagick writes
            // any two-colour image as 1-bit grey. `magick base.png -rotate 90
            // rot.png` produces one. Refusing it would make the tool refuse
            // most of the files a reader would actually try. 16-bit is still
            // out — nothing produces a 16-bit QR code — and so is the palette.
            const ok_depth = switch (channels) {
                1 => depth == 1 or depth == 2 or depth == 4 or depth == 8,
                else => depth == 8,
            };
            if (!ok_depth) return ImageError.UnsupportedPng;
            have_ihdr = true;
        } else if (std.mem.eql(u8, kind, "IDAT")) {
            if (!have_ihdr) return ImageError.CorruptImage;
            try idat.appendSlice(gpa, data);
        } else if (std.mem.eql(u8, kind, "IEND")) {
            break;
        }
    }
    if (!have_ihdr or width == 0 or height == 0) return ImageError.CorruptImage;
    if (width > qrscan.max_dimension or height > qrscan.max_dimension) return ImageError.ImageTooLarge;

    // One filter byte per row, then the row's samples packed end to end —
    // rounded up to a byte, which is where the sub-byte depths differ.
    const row_bytes = (@as(usize, width) * channels * depth + 7) / 8;
    const raw = try gpa.alloc(u8, (row_bytes + 1) * height);
    defer gpa.free(raw);

    {
        var src: std.Io.Reader = .fixed(idat.items);
        var window: [std.compress.flate.max_window_len]u8 = undefined;
        var inflate: std.compress.flate.Decompress = .init(&src, .zlib, &window);
        inflate.reader.readSliceAll(raw) catch return ImageError.CorruptImage;
    }

    const luma = try gpa.alloc(u8, @as(usize, width) * height);
    errdefer gpa.free(luma);

    // Undo the row filters in place, then take luminance. Both loops walk the
    // rows once; `prev` is the already-unfiltered row above, which is what the
    // Up/Average/Paeth predictors are defined against.
    // Filtering is defined on BYTES, offset by one whole pixel — and for a
    // sub-byte depth "one whole pixel" rounds down to one byte, which is the
    // detail that makes 1/2/4-bit rows come out right.
    const bpp = @max(1, channels * depth / 8);

    // One RGBA row, and only when there is RGB to widen into it — see the
    // colour-type-2 branch below.
    const rgba_row: ?[]u8 = if (channels == 3) try gpa.alloc(u8, @as(usize, width) * 4) else null;
    defer if (rgba_row) |r| gpa.free(r);

    var y: usize = 0;
    var prev: []const u8 = &.{};
    while (y < height) : (y += 1) {
        const filter = raw[y * (row_bytes + 1)];
        const row = raw[y * (row_bytes + 1) + 1 ..][0..row_bytes];
        unfilter(filter, row, prev, bpp) catch return ImageError.CorruptImage;
        prev = row;

        const out = luma[y * width ..][0..width];
        if (depth != 8) {
            // 1/2/4-bit grey, big-endian within the byte. Scaled to full range
            // rather than left as 0/1: `255 / (2^d - 1)` is the spec's own
            // sample-depth scaling, and handing the binariser an image whose
            // "white" is 1 would leave it no contrast to find.
            const maxval: u32 = (@as(u32, 1) << @intCast(depth)) - 1;
            const per_byte = 8 / depth;
            for (0..width) |x| {
                const byte = row[x / per_byte];
                const shift: u3 = @intCast(8 - depth * (@as(u8, @intCast(x % per_byte)) + 1));
                const v: u32 = (byte >> shift) & @as(u8, @intCast(maxval));
                out[x] = @intCast(v * 255 / maxval);
            }
            continue;
        }
        switch (channels) {
            1 => @memcpy(out, row),
            // Grey + alpha: the alpha is dropped, which is right for a scanner —
            // a transparent pixel over an unknown background is not information.
            2 => for (0..width) |x| {
                out[x] = row[x * 2];
            },
            // The module publishes the RGBA conversion (BT.601 in fixed point,
            // the same weights every scanner uses) because a browser canvas
            // hands out exactly that layout. Use it rather than writing the
            // weights again here.
            4 => qrscan.lumaFromRgba(row, out),
            // RGB has no such helper, so it is widened into the layout that
            // does. Costs one row of scratch, and keeps one implementation of
            // the coefficients in the program.
            3 => {
                const rgba = rgba_row.?;
                for (0..width) |x| {
                    rgba[x * 4 + 0] = row[x * 3 + 0];
                    rgba[x * 4 + 1] = row[x * 3 + 1];
                    rgba[x * 4 + 2] = row[x * 3 + 2];
                    rgba[x * 4 + 3] = 255;
                }
                qrscan.lumaFromRgba(rgba, out);
            },
            else => unreachable,
        }
    }

    return .{ .luma = luma, .width = width, .height = height, .source = "PNG" };
}

/// The five PNG row filters (ISO/IEC 15948 §9.2), applied in place. `a` is the
/// byte one pixel to the left, `b` the byte above, `c` the byte above-left;
/// each is zero where it falls outside the image, which is what makes the first
/// row and the first pixel work without a special case.
fn unfilter(filter: u8, row: []u8, prev: []const u8, bpp: usize) !void {
    switch (filter) {
        0 => {},
        1 => for (bpp..row.len) |i| {
            row[i] +%= row[i - bpp];
        },
        2 => if (prev.len != 0) for (0..row.len) |i| {
            row[i] +%= prev[i];
        },
        3 => for (0..row.len) |i| {
            const a: u32 = if (i >= bpp) row[i - bpp] else 0;
            const b: u32 = if (prev.len != 0) prev[i] else 0;
            row[i] +%= @intCast((a + b) / 2);
        },
        4 => for (0..row.len) |i| {
            const a: i32 = if (i >= bpp) row[i - bpp] else 0;
            const b: i32 = if (prev.len != 0) prev[i] else 0;
            const c: i32 = if (i >= bpp and prev.len != 0) prev[i - bpp] else 0;
            row[i] +%= @intCast(paeth(a, b, c));
        },
        else => return ImageError.CorruptImage,
    }
}

fn paeth(a: i32, b: i32, c: i32) u8 {
    const p = a + b - c;
    const pa = @abs(p - a);
    const pb = @abs(p - b);
    const pc = @abs(p - c);
    if (pa <= pb and pa <= pc) return @intCast(a);
    if (pb <= pc) return @intCast(b);
    return @intCast(c);
}

// ── PGM (P5) ────────────────────────────────────────────────────────────────

/// `P5`, three integers, one whitespace byte, then the samples. Twenty lines,
/// and they buy this tool every format ImageMagick reads: `magick photo.jpg
/// photo.pgm`. That is what makes the PNG reader above affordable at its
/// deliberately narrow width.
fn decodePgm(gpa: Allocator, file: []const u8) !Image {
    var p: usize = 2; // past "P5"
    const width = try pgmInt(file, &p);
    const height = try pgmInt(file, &p);
    const maxval = try pgmInt(file, &p);
    if (p >= file.len or !std.ascii.isWhitespace(file[p])) return ImageError.UnsupportedPgm;
    p += 1; // exactly one whitespace byte separates the header from the samples

    if (width == 0 or height == 0) return ImageError.UnsupportedPgm;
    if (width > qrscan.max_dimension or height > qrscan.max_dimension) return ImageError.ImageTooLarge;
    // 16-bit PGM is legal and this reader does not do it -- `magick -depth 8`
    // is the fix, and saying so beats silently taking every other byte.
    if (maxval == 0 or maxval > 255) return ImageError.UnsupportedPgm;

    const n = @as(usize, width) * height;
    if (file.len - p < n) return ImageError.CorruptImage;

    const luma = try gpa.alloc(u8, n);
    errdefer gpa.free(luma);
    if (maxval == 255) {
        @memcpy(luma, file[p..][0..n]);
    } else {
        // A maxval below 255 is a smaller scale, not a smaller range; leaving it
        // unscaled would hand the binariser an image with 1/4 of the contrast.
        for (0..n) |i| luma[i] = @intCast(@as(u32, file[p + i]) * 255 / maxval);
    }
    return .{ .luma = luma, .width = width, .height = height, .source = "PGM (P5)" };
}

fn pgmInt(file: []const u8, p: *usize) !u32 {
    // Whitespace and `#` comments may appear anywhere between header fields.
    while (p.* < file.len) {
        if (std.ascii.isWhitespace(file[p.*])) {
            p.* += 1;
        } else if (file[p.*] == '#') {
            while (p.* < file.len and file[p.*] != '\n') p.* += 1;
        } else break;
    }
    const start = p.*;
    while (p.* < file.len and std.ascii.isDigit(file[p.*])) p.* += 1;
    if (p.* == start) return ImageError.UnsupportedPgm;
    return std.fmt.parseInt(u32, file[start..p.*], 10) catch ImageError.UnsupportedPgm;
}
