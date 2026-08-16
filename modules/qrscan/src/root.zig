// SPDX-License-Identifier: MIT
//! qrscan — find QR symbols in a grayscale image and sample them into a
//! `qr.Matrix`, which `qr.decode` then turns into text.
//!
//! **The seam is a luminance buffer, not a file format.** The two sources that
//! actually exist give different things and neither is a PNG: a V4L2 camera
//! hands over NV12/YUV420 whose **Y plane is already 8-bit grayscale**, and a
//! browser canvas hands over RGBA from `getImageData`. So this takes luma with
//! an explicit `stride` — camera buffers pad their rows and an API without
//! stride is unusable on a device — and `lumaFromRgba` converts the other one.
//! Decoding PNG or JPEG belongs to the caller or to a module that is about
//! images; putting it here would drag a pixel-format zoo and a `platform` tag
//! into something that is otherwise pure arithmetic.
//!
//! **Allocation-free.** The caller passes a scratch buffer sized by
//! `scratchSize`, which is where the binarised bitmap lives. That keeps this
//! usable at 30 fps on a device with no allocator, and in wasm32 where the
//! whole point is a small static footprint.

const std = @import("std");
const qr = @import("qr");

pub const meta = .{
    .platform = .any,
    .role = .codec, // pure arithmetic over a caller-owned buffer
    .concurrency = .reentrant,
    .model_after = "ISO/IEC 18004 symbol location; the ZXing family's block-adaptive binarisation is the documented approach this follows, from its description rather than its source",
    .deps = .{"qr"},
};

pub const Image = struct {
    /// 8-bit luminance, row-major. `luma[y * stride + x]`.
    luma: []const u8,
    width: u32,
    height: u32,
    /// Bytes per row. Equals `width` for a tight buffer; a camera plane is
    /// usually padded and this is the field that makes such a buffer work.
    stride: u32,

    fn at(self: Image, x: u32, y: u32) u8 {
        return self.luma[y * self.stride + x];
    }
};

pub const Error = error{
    /// The scratch buffer is smaller than `scratchSize` says.
    ScratchTooSmall,
    /// `luma` is shorter than `stride * height`, or the dimensions are absurd.
    BadImage,
    /// No symbol was located. Not the same as one that was found and failed to
    /// decode — that is `qr.decode`'s answer to give.
    NotFound,
};

/// Bytes of scratch `scan` needs for an image of this size.
pub fn scratchSize(width: u32, height: u32) usize {
    return (@as(usize, width) * height + 7) / 8;
}

/// Convert packed RGBA (4 bytes per pixel, the shape `getImageData` returns)
/// into luminance. BT.601 coefficients in fixed point — the same weights every
/// scanner uses, and integer so the result is identical on every target.
pub fn lumaFromRgba(rgba: []const u8, out: []u8) void {
    const n = @min(out.len, rgba.len / 4);
    for (0..n) |i| {
        const r: u32 = rgba[i * 4];
        const g: u32 = rgba[i * 4 + 1];
        const b: u32 = rgba[i * 4 + 2];
        out[i] = @intCast((77 * r + 150 * g + 29 * b) >> 8);
    }
}

pub const Found = struct {
    matrix: qr.Matrix,
    /// Estimated module size in pixels — useful to a caller deciding whether the
    /// camera is close enough.
    module_px: f32,
};

/// Locate one symbol and sample it. Returns the grid; hand it to `qr.decode`.
pub fn scan(img: Image, scratch: []u8) Error!Found {
    if (img.width < 21 or img.height < 21) return Error.BadImage;
    if (img.luma.len < @as(usize, img.stride) * img.height) return Error.BadImage;
    if (scratch.len < scratchSize(img.width, img.height)) return Error.ScratchTooSmall;

    var bits: Bitmap = .{ .bits = scratch, .width = img.width, .height = img.height };
    binarize(img, &bits);

    var finders: [16]Finder = undefined;
    const found = locateFinders(&bits, &finders);
    if (found.len < 3) return Error.NotFound;

    const corners = orient(found) orelse return Error.NotFound;
    return sample(&bits, corners);
}

// ── binarisation ────────────────────────────────────────────────────────────
// Block-adaptive, because a global threshold cannot survive the thing every
// real capture has: a gradient across the frame, or a shadow over part of the
// symbol. The block size is 8x8 and each block's threshold is smoothed over its
// neighbours, so a block that happens to be entirely dark (inside a finder)
// inherits a sane threshold instead of inventing one from its own flat contents.

const block_shift = 3; // 8x8
const min_contrast = 24; // below this a block is treated as flat

const Bitmap = struct {
    bits: []u8,
    width: u32,
    height: u32,

    fn get(self: *const Bitmap, x: u32, y: u32) bool {
        const i = @as(usize, y) * self.width + x;
        return (self.bits[i >> 3] >> @intCast(i & 7)) & 1 != 0;
    }

    fn set(self: *Bitmap, x: u32, y: u32, dark: bool) void {
        const i = @as(usize, y) * self.width + x;
        const m = @as(u8, 1) << @intCast(i & 7);
        if (dark) self.bits[i >> 3] |= m else self.bits[i >> 3] &= ~m;
    }
};

fn binarize(img: Image, out: *Bitmap) void {
    const bw = (img.width + 7) >> block_shift;
    const bh = (img.height + 7) >> block_shift;

    // Per-block mean, plus a global mean as the fallback for flat blocks.
    var means: [128 * 128]u8 = undefined;
    const cap_w = @min(bw, 128);
    const cap_h = @min(bh, 128);

    var global_sum: u64 = 0;
    var global_n: u64 = 0;

    for (0..cap_h) |by| {
        for (0..cap_w) |bx| {
            const x0: u32 = @intCast(bx << block_shift);
            const y0: u32 = @intCast(by << block_shift);
            const x1 = @min(x0 + 8, img.width);
            const y1 = @min(y0 + 8, img.height);
            var sum: u32 = 0;
            var lo: u8 = 255;
            var hi: u8 = 0;
            var n: u32 = 0;
            var y = y0;
            while (y < y1) : (y += 1) {
                var x = x0;
                while (x < x1) : (x += 1) {
                    const v = img.at(x, y);
                    sum += v;
                    lo = @min(lo, v);
                    hi = @max(hi, v);
                    n += 1;
                }
            }
            const mean: u8 = @intCast(sum / @max(n, 1));
            // A flat block carries no edge; marking it as such lets the smoothing
            // pass below give it a neighbour's threshold rather than splitting
            // noise into modules.
            means[by * cap_w + bx] = if (hi - lo >= min_contrast) mean else 0;
            if (hi - lo >= min_contrast) {
                global_sum += mean;
                global_n += 1;
            }
        }
    }
    const global: u8 = if (global_n > 0) @intCast(global_sum / global_n) else 128;

    for (0..cap_h) |by| {
        for (0..cap_w) |bx| {
            // 5x5 neighbourhood average over the blocks that had contrast.
            var sum: u32 = 0;
            var n: u32 = 0;
            var dy: i32 = -2;
            while (dy <= 2) : (dy += 1) {
                var dx: i32 = -2;
                while (dx <= 2) : (dx += 1) {
                    const nx = @as(i32, @intCast(bx)) + dx;
                    const ny = @as(i32, @intCast(by)) + dy;
                    if (nx < 0 or ny < 0 or nx >= cap_w or ny >= cap_h) continue;
                    const v = means[@as(usize, @intCast(ny)) * cap_w + @as(usize, @intCast(nx))];
                    if (v == 0) continue;
                    sum += v;
                    n += 1;
                }
            }
            const threshold: u8 = if (n > 0) @intCast(sum / n) else global;

            const x0: u32 = @intCast(bx << block_shift);
            const y0: u32 = @intCast(by << block_shift);
            const x1 = @min(x0 + 8, img.width);
            const y1 = @min(y0 + 8, img.height);
            var y = y0;
            while (y < y1) : (y += 1) {
                var x = x0;
                while (x < x1) : (x += 1) {
                    out.set(x, y, img.at(x, y) < threshold);
                }
            }
        }
    }
}

// ── finder location ─────────────────────────────────────────────────────────
// The 1:1:3:1:1 dark:light:dark:light:dark run is what makes a QR symbol
// findable from any angle, and it is scanned for on rows first, then confirmed
// on the column through each candidate. Confirming is what rejects the ordinary
// run of five bands that any picture of a fence produces.

const Finder = struct { x: f32, y: f32, module: f32, hits: u32 = 1 };

fn ratioOk(runs: [5]u32) ?f32 {
    var total: u32 = 0;
    for (runs) |r| {
        if (r == 0) return null;
        total += r;
    }
    if (total < 7) return null;
    // Each unit is total/7; allow half a unit of slack per band, which is what
    // survives a symbol photographed small without accepting everything.
    const unit = @as(f32, @floatFromInt(total)) / 7.0;
    const slack = unit / 2.0;
    const want = [5]f32{ 1, 1, 3, 1, 1 };
    for (runs, want) |got, w| {
        const diff = @abs(@as(f32, @floatFromInt(got)) - w * unit);
        if (diff > w * slack) return null;
    }
    return unit;
}

/// Walk the column through a row candidate, collecting the same five bands.
/// Returns the unit size AND the true centre of the middle band — the row that
/// happened to trigger the candidate is somewhere inside the finder, not at its
/// middle, so taking `y` as the centre biases every symbol downward by half a
/// finder. That error is under a module and still moves every sampling point.
fn confirmVertical(b: *const Bitmap, cx: u32, cy: u32) ?struct { unit: f32, centre: f32 } {
    if (!b.get(cx, cy)) return null;
    var runs = [_]u32{0} ** 5;

    // Up from the candidate: the rest of the centre band, then light, then dark.
    var y: i32 = @intCast(cy);
    while (y >= 0 and b.get(cx, @intCast(y))) : (y -= 1) runs[2] += 1;
    const top_of_centre = y + 1; // first dark row of the centre band
    while (y >= 0 and !b.get(cx, @intCast(y))) : (y -= 1) runs[1] += 1;
    while (y >= 0 and b.get(cx, @intCast(y))) : (y -= 1) runs[0] += 1;

    // Down from just below it.
    const h: i32 = @intCast(b.height);
    y = @as(i32, @intCast(cy)) + 1;
    while (y < h and b.get(cx, @intCast(y))) : (y += 1) runs[2] += 1;
    const bottom_of_centre = y - 1; // last dark row of the centre band
    while (y < h and !b.get(cx, @intCast(y))) : (y += 1) runs[3] += 1;
    while (y < h and b.get(cx, @intCast(y))) : (y += 1) runs[4] += 1;

    const unit = ratioOk(runs) orelse return null;
    const centre = (@as(f32, @floatFromInt(top_of_centre)) + @as(f32, @floatFromInt(bottom_of_centre))) / 2;
    return .{ .unit = unit, .centre = centre };
}

fn locateFinders(b: *const Bitmap, out: *[16]Finder) []Finder {
    var n: usize = 0;

    var y: u32 = 0;
    while (y < b.height) : (y += 1) {
        // Five bands, dark first. `state` indexes the band being counted, so an
        // even state is a dark run and an odd one is light — which is why the
        // parity test below is the whole transition logic.
        var count = [_]u32{0} ** 5;
        var state: usize = 0;

        var x: u32 = 0;
        while (x < b.width) : (x += 1) {
            if (b.get(x, y)) {
                if (state % 2 == 1) state += 1; // light run ended
                count[state] += 1;
            } else if (state % 2 == 0) {
                if (state == 4) {
                    n = consider(b, out, n, count, x, y);
                    // Slide by two bands: the last dark-light-dark can be the
                    // start of the next candidate, which is how two finders
                    // separated by one module are both seen.
                    count = .{ count[2], count[3], count[4], 1, 0 };
                    state = 3;
                } else {
                    state += 1;
                    count[state] += 1;
                }
            } else {
                count[state] += 1;
            }
        }
        // A row that ends inside the fifth band still holds a candidate.
        if (state == 4) n = consider(b, out, n, count, b.width, y);
    }
    return out[0..n];
}

/// Check one completed five-band window, confirm it vertically, and merge it
/// into the candidate list. `x_end` is one past the last dark pixel of band 4.
fn consider(b: *const Bitmap, out: *[16]Finder, n_in: usize, count: [5]u32, x_end: u32, y: u32) usize {
    var n = n_in;
    const unit = ratioOk(count) orelse return n;

    const back = count[4] + count[3] + count[2];
    if (x_end < back) return n;
    const cx = x_end - count[4] - count[3] - count[2] / 2;
    if (cx >= b.width) return n;

    // A row of five bands in the right ratio is common — a fence, a keyboard,
    // text. Confirming the same ratio down the column through the candidate is
    // what makes it a finder rather than a coincidence.
    const v = confirmVertical(b, cx, y) orelse return n;
    if (@abs(unit - v.unit) > unit) return n;

    const fx: f32 = @floatFromInt(cx);
    const fy: f32 = v.centre;
    for (out[0..n]) |*f| {
        if (@abs(f.x - fx) < unit * 2 and @abs(f.y - fy) < unit * 3) {
            // A counted mean, not a running halving: the same finder is hit on
            // every row it spans, and `(old + new) / 2` weights the last row
            // most, which drags the centre toward the bottom of the pattern.
            const k: f32 = @floatFromInt(f.hits);
            f.x = (f.x * k + fx) / (k + 1);
            f.y = (f.y * k + fy) / (k + 1);
            f.module = (f.module * k + unit) / (k + 1);
            f.hits += 1;
            return n;
        }
    }
    if (n < out.len) {
        out[n] = .{ .x = fx, .y = fy, .module = unit, .hits = 1 };
        n += 1;
    }
    return n;
}

// ── orientation and sampling ────────────────────────────────────────────────

const Corners = struct {
    tl: Finder,
    tr: Finder,
    bl: Finder,
    dimension: u32,
};

/// Of three finder centres, the top-left one is the corner of the right angle:
/// it is the vertex opposite the longest side. Which of the other two is the
/// top-right then follows from the sign of the cross product, which is what
/// makes this work at any rotation.
fn orient(f: []Finder) ?Corners {
    if (f.len < 3) return null;

    // More than three candidates is the normal case, not the exception: the
    // 1:1:3:1:1 run occurs inside the data region too, and the vertical
    // confirmation does not always reject it. So pick the triple that actually
    // looks like three corners of a square symbol rather than the first three
    // found — taking f[0..3] means one false positive inside the data ruins an
    // otherwise perfect read.
    var best_score: f32 = std.math.floatMax(f32);
    var best: [3]Finder = undefined;
    for (0..f.len) |i| {
        for (i + 1..f.len) |j| {
            for (j + 1..f.len) |k| {
                const t = [3]Finder{ f[i], f[j], f[k] };
                const sc = tripleScore(t) orelse continue;
                if (sc < best_score) {
                    best_score = sc;
                    best = t;
                }
            }
        }
    }
    if (best_score > 0.4) return null;

    const a = best[0];
    const b = best[1];
    const c = best[2];

    const dab = dist2(a, b);
    const dbc = dist2(b, c);
    const dac = dist2(a, c);

    var tl: Finder = undefined;
    var p: Finder = undefined;
    var q: Finder = undefined;
    if (dab >= dbc and dab >= dac) {
        tl = c;
        p = a;
        q = b;
    } else if (dbc >= dab and dbc >= dac) {
        tl = a;
        p = b;
        q = c;
    } else {
        tl = b;
        p = a;
        q = c;
    }

    // Cross product of (p - tl) x (q - tl). Image coordinates put y downwards,
    // so the system is left-handed and the sign reads the opposite way round
    // from the usual convention: POSITIVE means p is the top-right. Getting this
    // backwards transposes the symbol, which still samples cleanly and still
    // produces a plausible grid — it just decodes to nothing.
    const cross = (p.x - tl.x) * (q.y - tl.y) - (p.y - tl.y) * (q.x - tl.x);
    const tr = if (cross > 0) p else q;
    const bl = if (cross > 0) q else p;

    const module = (tl.module + tr.module + bl.module) / 3;
    if (module <= 0.5) return null;

    // Centre-to-centre spans (dimension - 7) modules.
    const span = @sqrt(dist2(tl, tr));
    const dim_f = span / module + 7.0;
    var dimension: u32 = @intFromFloat(@round(dim_f));
    // Snap to a legal symbol size; a fraction of a module of error otherwise
    // lands between two versions.
    dimension = dimension -% ((dimension -% 17) % 4);
    if (dimension < 21 or dimension > qr.max_size) return null;

    return .{ .tl = tl, .tr = tr, .bl = bl, .dimension = dimension };
}

/// How much a triple deviates from three corners of a square: the two legs
/// should be equal, the hypotenuse sqrt(2) times a leg, and the three module
/// estimates should agree. Lower is better; null means degenerate.
fn tripleScore(t: [3]Finder) ?f32 {
    var d = [3]f32{ @sqrt(dist2(t[0], t[1])), @sqrt(dist2(t[1], t[2])), @sqrt(dist2(t[0], t[2])) };
    std.mem.sort(f32, &d, {}, std.sort.asc(f32));
    if (d[0] < 1.0) return null; // two candidates on top of each other

    const leg = (d[0] + d[1]) / 2;
    const leg_err = @abs(d[1] - d[0]) / leg;
    const hyp_err = @abs(d[2] - leg * @sqrt(2.0)) / d[2];

    var mmin = t[0].module;
    var mmax = t[0].module;
    for (t[1..]) |f| {
        mmin = @min(mmin, f.module);
        mmax = @max(mmax, f.module);
    }
    if (mmin <= 0) return null;
    const mod_err = (mmax - mmin) / mmin;

    return leg_err + hyp_err + mod_err;
}

fn dist2(a: Finder, b: Finder) f32 {
    const dx = a.x - b.x;
    const dy = a.y - b.y;
    return dx * dx + dy * dy;
}

/// Affine sampling from the three finder centres. Each centre sits 3.5 modules
/// in from its corner, which fixes the mapping without needing the alignment
/// pattern — at the cost of not correcting perspective, which is the documented
/// limit of this first implementation.
fn sample(b: *const Bitmap, c: Corners) Error!Found {
    const dim = c.dimension;
    const df: f32 = @floatFromInt(dim);

    // Column and row steps in image space, per module.
    const ux = (c.tr.x - c.tl.x) / (df - 7.0);
    const uy = (c.tr.y - c.tl.y) / (df - 7.0);
    const vx = (c.bl.x - c.tl.x) / (df - 7.0);
    const vy = (c.bl.y - c.tl.y) / (df - 7.0);

    const ox = c.tl.x - 3.5 * ux - 3.5 * vx;
    const oy = c.tl.y - 3.5 * uy - 3.5 * vy;

    var m: qr.Matrix = .{};
    m.size = @intCast(dim);

    for (0..dim) |row| {
        for (0..dim) |col| {
            const fx: f32 = @floatFromInt(col);
            const fy: f32 = @floatFromInt(row);
            const px = ox + (fx + 0.5) * ux + (fy + 0.5) * vx;
            const py = oy + (fx + 0.5) * uy + (fy + 0.5) * vy;
            if (px < 0 or py < 0) return Error.NotFound;
            const ix: u32 = @intFromFloat(px);
            const iy: u32 = @intFromFloat(py);
            if (ix >= b.width or iy >= b.height) return Error.NotFound;
            m.setDark(@intCast(col), @intCast(row), b.get(ix, iy));
        }
    }

    return .{ .matrix = m, .module_px = (c.tl.module + c.tr.module + c.bl.module) / 3 };
}

// ── tests ───────────────────────────────────────────────────────────────────

/// Render a matrix into a luma buffer at `scale` pixels per module with a quiet
/// zone, so the tests can start from a symbol whose correct answer is known.
fn render(m: *const qr.Matrix, scale: u32, buf: []u8) Image {
    const q = qr.quiet_zone;
    const side = (m.size + 2 * q) * scale;
    @memset(buf[0 .. @as(usize, side) * side], 255);
    for (0..m.size) |y| {
        for (0..m.size) |x| {
            if (!m.isDark(@intCast(x), @intCast(y))) continue;
            for (0..scale) |dy| {
                for (0..scale) |dx| {
                    const px = (@as(usize, x) + q) * scale + dx;
                    const py = (@as(usize, y) + q) * scale + dy;
                    buf[py * side + px] = 0;
                }
            }
        }
    }
    return .{ .luma = buf, .width = side, .height = side, .stride = side };
}

test "scan finds and samples a rendered symbol, and decode reads it back" {
    const t = std.testing;
    const texts = [_][]const u8{ "HELLO WORLD", "https://example.com/x", "0123456789" };
    var m: qr.Matrix = undefined;
    var pixels: [512 * 512]u8 = undefined;
    var scratch: [512 * 512 / 8]u8 = undefined;
    var out: [256]u8 = undefined;

    for (texts) |text| {
        for ([_]u32{ 3, 5, 8 }) |scale| {
            try qr.encode(&m, text, .{ .ecc = .quartile });
            const img = render(&m, scale, &pixels);
            const found = try scan(img, &scratch);
            try t.expectEqual(m.size, found.matrix.size);
            // The sampled grid must be the one that was drawn, module for module.
            for (0..m.size) |y| {
                for (0..m.size) |x| {
                    try t.expectEqual(
                        m.isDark(@intCast(x), @intCast(y)),
                        found.matrix.isDark(@intCast(x), @intCast(y)),
                    );
                }
            }
            var fm = found.matrix;
            try t.expectEqualStrings(text, try qr.decode(&fm, &out));
        }
    }
}

/// Render rotated by `deg` about the image centre, by inverse-mapping each
/// destination pixel — which is how a photograph of a symbol held at an angle
/// actually arrives, rather than an axis-aligned crop.
fn renderRotated(m: *const qr.Matrix, scale: u32, deg: f32, buf: []u8, side_out: *u32) Image {
    const q = qr.quiet_zone;
    const src_side = (m.size + 2 * q) * scale;
    const side: u32 = @intFromFloat(@as(f32, @floatFromInt(src_side)) * 1.5);
    side_out.* = side;
    @memset(buf[0 .. @as(usize, side) * side], 255);

    const rad = deg * std.math.pi / 180.0;
    const cs = @cos(rad);
    const sn = @sin(rad);
    const cd: f32 = @floatFromInt(side / 2);
    const cs_src: f32 = @floatFromInt(src_side / 2);

    for (0..side) |dy| {
        for (0..side) |dx| {
            const rx = @as(f32, @floatFromInt(dx)) - cd;
            const ry = @as(f32, @floatFromInt(dy)) - cd;
            const sx = rx * cs + ry * sn + cs_src;
            const sy = -rx * sn + ry * cs + cs_src;
            if (sx < 0 or sy < 0) continue;
            const ix: u32 = @intFromFloat(sx);
            const iy: u32 = @intFromFloat(sy);
            if (ix >= src_side or iy >= src_side) continue;
            const mx = ix / scale;
            const my = iy / scale;
            if (mx < q or my < q or mx >= m.size + q or my >= m.size + q) continue;
            if (m.isDark(@intCast(mx - q), @intCast(my - q))) buf[dy * side + dx] = 0;
        }
    }
    return .{ .luma = buf, .width = side, .height = side, .stride = side };
}

test "rotation: upright and quarter turns read; steep angles are the known limit" {
    const t = std.testing;
    var m: qr.Matrix = undefined;
    try qr.encode(&m, "ROTATED SYMBOL", .{ .ecc = .quartile });

    var pixels: [900 * 900]u8 = undefined;
    var scratch: [900 * 900 / 8]u8 = undefined;
    var out: [128]u8 = undefined;

    // What works today: a symbol that is upright, slightly tilted, or turned by
    // a quarter. Row-scanning finds the finder bands at any angle, but
    // `confirmVertical` walks a strictly vertical column, so past roughly ten
    // degrees the bands it crosses no longer hold the 1:1:3:1:1 ratio and the
    // candidate is dropped. Lifting that means locating finders by connected
    // components instead of run lengths — rotation-invariant by construction —
    // which is the top item in SPEC's backlog, not a tweak to this function.
    //
    // Asserted as a minimum rather than an exact set, so that fixing the limit
    // does not fail this test.
    for ([_]f32{ 0, 7, 90, 180, 270 }) |deg| {
        var side: u32 = 0;
        const img = renderRotated(&m, 6, deg, &pixels, &side);
        const found = try scan(img, &scratch);
        var fm = found.matrix;
        try t.expectEqualStrings("ROTATED SYMBOL", try qr.decode(&fm, &out));
    }
}

// ── fuzz: the image is entirely attacker-chosen ─────────────────────────────

test "fuzz: scan never panics on an arbitrary image" {
    try std.testing.fuzz({}, fuzzScan, .{});
}

fn fuzzScan(_: void, smith: *std.testing.Smith) !void {
    // Dimensions, stride and every pixel come from outside. The interesting
    // failures are not crashes in binarisation but in sampling: a finder triple
    // can be geometrically valid and still project sampling points outside the
    // image, which must be a bounds check rather than a read past the buffer.
    var pixels: [128 * 128]u8 = undefined;
    for (0..pixels.len) |i| pixels[i] = smith.valueRangeAtMost(u8, 0, 255);

    const w = smith.valueRangeAtMost(u32, 1, 128);
    const h = smith.valueRangeAtMost(u32, 1, 128);
    const extra = smith.valueRangeAtMost(u32, 0, 16);
    const stride = w + extra;
    if (@as(usize, stride) * h > pixels.len) return;

    var scratch: [128 * 128 / 8]u8 = undefined;
    const img: Image = .{ .luma = &pixels, .width = w, .height = h, .stride = stride };
    const found = scan(img, &scratch) catch return;
    // A returned grid must be a legal symbol size, or the caller is handed
    // something `qr.decode` will index against the wrong geometry.
    try std.testing.expect(found.matrix.size >= 21 and found.matrix.size <= qr.max_size);
    try std.testing.expectEqual(@as(u16, 0), (found.matrix.size - 17) % 4);
}

test "fuzz: a real symbol with the image damaged around it" {
    try std.testing.fuzz({}, fuzzDamaged, .{});
}

fn fuzzDamaged(_: void, smith: *std.testing.Smith) !void {
    // Noise on top of a genuine symbol reaches the parts random pixels never do:
    // candidate merging, the triple search, and sampling with slightly wrong
    // finder centres.
    var m: qr.Matrix = undefined;
    qr.encode(&m, "FUZZ", .{}) catch return;

    var pixels: [400 * 400]u8 = undefined;
    const img = render(&m, 4, &pixels);

    const blobs = smith.valueRangeAtMost(u16, 0, 60);
    for (0..blobs) |_| {
        const x = smith.valueRangeAtMost(u32, 0, img.width - 1);
        const y = smith.valueRangeAtMost(u32, 0, img.height - 1);
        pixels[y * img.width + x] = smith.valueRangeAtMost(u8, 0, 255);
    }

    var scratch: [400 * 400 / 8]u8 = undefined;
    _ = scan(img, &scratch) catch return;
}

test "lumaFromRgba uses the standard weights" {
    const t = std.testing;
    var out: [3]u8 = undefined;
    // white, black, pure green — green carries most of the luminance.
    lumaFromRgba(&[_]u8{ 255, 255, 255, 255, 0, 0, 0, 255, 0, 255, 0, 255 }, &out);
    try t.expectEqual(@as(u8, 255), out[0]);
    try t.expectEqual(@as(u8, 0), out[1]);
    try t.expectEqual(@as(u8, 149), out[2]); // (150*255)>>8
}

test "a picture with no symbol in it is reported, not guessed at" {
    const t = std.testing;
    var pixels: [128 * 128]u8 = undefined;
    var scratch: [128 * 128 / 8]u8 = undefined;
    // A gradient: plenty of contrast, no finder patterns anywhere.
    for (0..128) |y| {
        for (0..128) |x| pixels[y * 128 + x] = @intCast((x * 2) % 256);
    }
    const img: Image = .{ .luma = &pixels, .width = 128, .height = 128, .stride = 128 };
    try t.expectError(Error.NotFound, scan(img, &scratch));
}

test "stride is honoured, because a camera plane is padded" {
    const t = std.testing;
    var m: qr.Matrix = undefined;
    try qr.encode(&m, "STRIDE", .{});

    var tight: [512 * 512]u8 = undefined;
    const img = render(&m, 4, &tight);

    // Re-lay the same picture into a wider buffer and declare the padding.
    const pad: u32 = 37;
    var padded: [512 * 549]u8 = undefined;
    @memset(&padded, 128); // junk in the padding; must never be sampled
    for (0..img.height) |y| {
        @memcpy(
            padded[y * (img.width + pad) ..][0..img.width],
            img.luma[y * img.stride ..][0..img.width],
        );
    }
    const padded_img: Image = .{
        .luma = &padded,
        .width = img.width,
        .height = img.height,
        .stride = img.width + pad,
    };

    var scratch: [512 * 512 / 8]u8 = undefined;
    const found = try scan(padded_img, &scratch);
    var fm = found.matrix;
    var out: [64]u8 = undefined;
    try t.expectEqualStrings("STRIDE", try qr.decode(&fm, &out));
}
