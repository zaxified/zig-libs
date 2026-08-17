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
//! **Any rotation.** The finder pattern's 1:1:3:1:1 ratio holds along a line
//! through its centre at any angle, so a row scan locates finders on a symbol
//! held sideways as readily as an upright one. The length that comes with the
//! ratio does not hold — see `orient`, where the tilt is taken back out of it,
//! because that single factor is the difference between a symbol that reads and
//! one whose every intermediate step looks correct.
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

    var finders: [max_candidates]Finder = undefined;

    // Two passes, strict first. The strict pass demands the ring: the outer
    // bands either side of the centre must be one connected region. That is
    // what a finder is, and requiring it throws away almost every coincidence
    // the data region produces — which is what makes a large symbol readable at
    // all, since its own data otherwise fills the candidate list.
    //
    // It also fails on a *small* symbol, where the light band between ring and
    // centre is three pixels wide and binarisation can weld them together or
    // break the ring. So when the strict pass does not yield a symbol, the scan
    // is repeated without the ring requirement. The order matters: relaxed
    // first would let a version 37's data outvote its own finders.
    var best: ?Found = null;
    var best_score: f32 = -1;
    for ([_]bool{ true, false }) |strict| {
        const found = locateFinders(&bits, &finders, strict);
        if (found.len < 3) continue;
        const corners = orient(found) orelse continue;
        const got = sampleBestDimension(&bits, corners) catch continue;
        // The timing patterns can tell a grid that is one version out from one
        // that is not; at version 1 they are five modules long and can barely
        // tell anything. So the pass that wins is the one whose grid actually
        // decodes, and the timing score only breaks the tie when neither does.
        //
        // This does not make the scanner a decoder — the caller still gets the
        // grid and still has to decode it, and a symbol that scans but cannot
        // be read is still `qr.decode`'s verdict to give, not this module's.
        // What it does is choose between two grids of our own making.
        if (readable(&got.found.matrix)) return got.found;
        if (got.score > best_score) {
            best_score = got.score;
            best = got.found;
        }
    }
    return best orelse Error.NotFound;
}

/// Whether `qr` can read this grid. `BufferTooSmall` counts as yes: the format
/// information and every Reed-Solomon block had to be sound for the segment
/// parser to run at all, and the message being longer than a scratch buffer
/// says nothing about the grid.
fn readable(m: *const qr.Matrix) bool {
    var buf: [256]u8 = undefined;
    var copy = m.*;
    if (qr.decode(&copy, &buf)) |_| {
        return true;
    } else |e| return switch (e) {
        error.BufferTooSmall, error.StructuredAppend => true,
        else => false,
    };
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

const Finder = struct {
    x: f32,
    y: f32,
    /// Mean of the scan-line unit over every row that hit this pattern. Stable,
    /// and what the triple search compares between candidates.
    module: f32,
    /// Largest unit any single row measured. That row is the one through the
    /// centre, which is the only chord whose length is a fixed function of the
    /// tilt; see `orient`.
    peak: f32,
    hits: u32 = 1,
};

/// How many candidates are kept. The 1:1:3:1:1 run occurs inside the data
/// region too, and more often the larger the symbol is — a list of sixteen
/// fills with false positives before the third real finder is reached, and the
/// symbol is then missed for want of a slot rather than for anything to do with
/// the picture. The ring test in `locateFinders` removes most of them, but the
/// relaxed pass has no such filter and is exactly the pass small, marginal
/// symbols depend on. Sixty-four holds every case measured; the cost of the
/// ceiling is the triple search below, which is cubic.
const max_candidates = 64;

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

// ── connected components ────────────────────────────────────────────────────
// A finder is a dark ring with a dark square inside it, and "inside" is a
// statement about connectivity: the outer band left of the centre and the outer
// band right of it are THE SAME dark region, joined above and below where the
// scan line cannot see. A fence, a barcode, a line of text — everything else
// that produces a 1:1:3:1:1 run — has three separate regions instead.
//
// That test needs component labels, and labels normally need an integer per
// pixel, which is 16x this module's whole scratch buffer. They do not have to:
// labelling by RUNS rather than pixels needs one row of runs plus a union-find
// over the labels themselves, and the row scan already produces the runs. The
// candidate test then reads the labels of the three dark runs it is looking at,
// in the same pass, with nothing stored per pixel at all.

const max_labels = 4096;
const max_runs = 512;

const Run = struct {
    x0: u32,
    x1: u32, // inclusive
    label: u16, // 0 = none available; the test then falls back
};

/// Union-find over run labels. Label 0 means "no label was available", which
/// happens when a picture has more dark regions than the table holds; the
/// candidate test treats it as "cannot tell" and falls back, rather than as a
/// rejection, because an unlabelled finder is still a finder.
const Labels = struct {
    parent: [max_labels]u16 = undefined,
    n: u16 = 1,

    fn create(self: *Labels) u16 {
        if (self.n >= max_labels) return 0;
        const l = self.n;
        self.parent[l] = l;
        self.n += 1;
        return l;
    }

    fn find(self: *Labels, a: u16) u16 {
        if (a == 0) return 0;
        var r = a;
        while (self.parent[r] != r) r = self.parent[r];
        // Path compression, so a long chain of merges stays cheap on the next
        // row rather than being walked again for every run in it.
        var walk = a;
        while (self.parent[walk] != r) {
            const next = self.parent[walk];
            self.parent[walk] = r;
            walk = next;
        }
        return r;
    }

    fn merge(self: *Labels, a: u16, b: u16) u16 {
        if (a == 0 or b == 0) return if (a == 0) b else a;
        const ra = self.find(a);
        const rb = self.find(b);
        if (ra == rb) return ra;
        // Lower label wins, which keeps the parent chains pointing backwards in
        // creation order and so keeps `find` shallow.
        const lo = @min(ra, rb);
        const hi = @max(ra, rb);
        self.parent[hi] = lo;
        return lo;
    }
};

/// Dark runs of one row, labelled by overlap with the row above.
fn scanRow(b: *const Bitmap, y: u32, out: *[max_runs]Run) []Run {
    var n: usize = 0;
    var x: u32 = 0;
    while (x < b.width and n < max_runs) {
        if (!b.get(x, y)) {
            x += 1;
            continue;
        }
        const start = x;
        while (x < b.width and b.get(x, y)) x += 1;
        out[n] = .{ .x0 = start, .x1 = x - 1, .label = 0 };
        n += 1;
    }
    return out[0..n];
}

fn labelRow(labels: *Labels, prev: []const Run, cur: []Run) void {
    for (cur) |*r| {
        var mine: u16 = 0;
        for (prev) |p| {
            // 8-connectivity: a rotated pattern's rows step sideways by less
            // than a pixel per row at shallow angles but by a whole one at
            // steep angles, and 4-connectivity splits the ring in two there.
            if (p.x1 + 1 < r.x0 or r.x1 + 1 < p.x0) continue;
            mine = if (mine == 0) labels.find(p.label) else labels.merge(mine, p.label);
        }
        r.label = if (mine == 0) labels.create() else mine;
    }
}

fn locateFinders(b: *const Bitmap, out: *[max_candidates]Finder, strict: bool) []Finder {
    var n: usize = 0;

    var labels: Labels = .{};
    var buf_a: [max_runs]Run = undefined;
    var buf_b: [max_runs]Run = undefined;
    var prev: []Run = buf_a[0..0];
    var cur_buf = &buf_b;
    var prev_buf = &buf_a;

    var y: u32 = 0;
    while (y < b.height) : (y += 1) {
        const cur = scanRow(b, y, cur_buf);
        labelRow(&labels, prev, cur);

        // Every three consecutive dark runs are a candidate: the two gaps
        // between them are the light bands, so the five counts fall out without
        // a state machine, and a run can open one candidate while closing
        // another — which is how two finders one module apart are both seen.
        if (cur.len >= 3) {
            for (0..cur.len - 2) |i| {
                const d0 = cur[i];
                const d1 = cur[i + 1];
                const d2 = cur[i + 2];
                const counts = [5]u32{
                    d0.x1 - d0.x0 + 1,
                    d1.x0 - d0.x1 - 1,
                    d1.x1 - d1.x0 + 1,
                    d2.x0 - d1.x1 - 1,
                    d2.x1 - d2.x0 + 1,
                };
                const ring = labels.find(d0.label) == labels.find(d2.label) and
                    labels.find(d0.label) != labels.find(d1.label) and
                    labels.find(d0.label) != 0;
                n = consider(b, out, n, counts, (d1.x0 + d1.x1) / 2, y, ring or !strict);
            }
        }

        prev = cur;
        const t = prev_buf;
        prev_buf = cur_buf;
        cur_buf = t;
    }
    return out[0..n];
}

/// Check one five-band window and merge it into the candidate list. `cx` is the
/// middle of the centre band; `ring` says the outer bands were found to be one
/// connected region and the centre band another.
fn consider(b: *const Bitmap, out: *[max_candidates]Finder, n_in: usize, count: [5]u32, cx: u32, y: u32, ring: bool) usize {
    var n = n_in;
    const unit = ratioOk(count) orelse return n;
    if (cx >= b.width) return n;

    // A row of five bands in the right ratio is common — a fence, a keyboard,
    // text. Two independent things reject it, and either will do.
    //
    // `ring` is the stronger and is what makes this rotation- and
    // damage-tolerant: it is a fact about the shape, needing no second scan
    // line to be intact. The vertical confirmation is the fallback for when the
    // label table ran out, and it is the weaker test — it requires the column
    // through the candidate to carry the ratio too, which a scratched finder
    // may not.
    if (!ring) return n;
    const v = confirmVertical(b, cx, y) orelse return n;
    if (@abs(unit - v.unit) > unit) return n;
    const fy: f32 = v.centre;

    const fx: f32 = @floatFromInt(cx);
    for (out[0..n]) |*f| {
        if (@abs(f.x - fx) < unit * 2 and @abs(f.y - fy) < unit * 3) {
            // A counted mean, not a running halving: the same finder is hit on
            // every row it spans, and `(old + new) / 2` weights the last row
            // most, which drags the centre toward the bottom of the pattern.
            const k: f32 = @floatFromInt(f.hits);
            f.x = (f.x * k + fx) / (k + 1);
            f.y = (f.y * k + fy) / (k + 1);
            f.module = (f.module * k + unit) / (k + 1);
            f.peak = @max(f.peak, unit);
            f.hits += 1;
            return n;
        }
    }
    if (n < out.len) {
        out[n] = .{ .x = fx, .y = fy, .module = unit, .peak = unit, .hits = 1 };
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
    /// Module size in pixels, corrected for the symbol's tilt — not the average
    /// of the three finders' estimates, which is what the scan lines measured.
    module: f32,
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

    // The module estimates arrive from horizontal and vertical scan lines, and
    // those chords are longer than a module whenever the symbol is rotated: a
    // line through the centre of a square whose sides sit at angle t to the
    // axes crosses it in s / cos(t), for every one of the concentric rings
    // alike. So the 1:1:3:1:1 ratio survives any rotation — which is why the
    // finders are still located — while the SIZE that comes with it is
    // inflated by 1 / cos(t), and it is the size that sets the version.
    //
    // t is the angle of the top edge, which is the direction tl -> tr. A square
    // is unchanged by a quarter turn, so wrap into [-45, 45]: past that the
    // scan line is crossing what is now the other pair of sides.
    const quarter: f32 = std.math.pi / 2.0;
    const raw = std.math.atan2(tr.y - tl.y, tr.x - tl.x);
    const tilt = @mod(raw + quarter / 2.0, quarter) - quarter / 2.0;

    const module = (tl.peak + tr.peak + bl.peak) / 3 * @cos(tilt);
    if (module <= 0.5) return null;

    // Centre-to-centre spans (dimension - 7) modules.
    const span = @sqrt(dist2(tl, tr));
    const dim_f = span / module + 7.0;
    var dimension: u32 = @intFromFloat(@round(dim_f));
    // Snap to a legal symbol size; a fraction of a module of error otherwise
    // lands between two versions.
    dimension = dimension -% ((dimension -% 17) % 4);
    if (dimension < 21 or dimension > qr.max_size) return null;

    return .{ .tl = tl, .tr = tr, .bl = bl, .dimension = dimension, .module = module };
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

/// Module coordinates to image coordinates: `x' = a*x + b*y + c`, and likewise
/// for y. Affine and not projective, deliberately — see `refine`.
const Grid = struct {
    ax: f32,
    bx: f32,
    cx: f32,
    ay: f32,
    by: f32,
    cy: f32,

    /// Image position of the centre of module (col, row).
    fn at(self: Grid, col: f32, row: f32) [2]f32 {
        const x = col + 0.5;
        const y = row + 0.5;
        return .{ self.ax * x + self.bx * y + self.cx, self.ay * x + self.by * y + self.cy };
    }
};

/// The grid the three finder centres imply. Each sits 3.5 modules in from its
/// corner, which is what fixes the mapping from three points.
fn gridFromCorners(c: Corners) Grid {
    const df: f32 = @floatFromInt(c.dimension);
    const ux = (c.tr.x - c.tl.x) / (df - 7.0);
    const uy = (c.tr.y - c.tl.y) / (df - 7.0);
    const vx = (c.bl.x - c.tl.x) / (df - 7.0);
    const vy = (c.bl.y - c.tl.y) / (df - 7.0);
    return .{
        .ax = ux,
        .bx = vx,
        .cx = c.tl.x - 3.5 * ux - 3.5 * vx,
        .ay = uy,
        .by = vy,
        .cy = c.tl.y - 3.5 * uy - 3.5 * vy,
    };
}

fn sample(b: *const Bitmap, c: Corners, grid: Grid) Error!Found {
    const dim = c.dimension;
    var m: qr.Matrix = .{};
    m.size = @intCast(dim);

    for (0..dim) |row| {
        for (0..dim) |col| {
            const p = grid.at(@floatFromInt(col), @floatFromInt(row));
            if (p[0] < 0 or p[1] < 0) return Error.NotFound;
            const ix: u32 = @intFromFloat(p[0]);
            const iy: u32 = @intFromFloat(p[1]);
            if (ix >= b.width or iy >= b.height) return Error.NotFound;
            m.setDark(@intCast(col), @intCast(row), b.get(ix, iy));
        }
    }

    return .{ .matrix = m, .module_px = c.module };
}

// ── grid refinement ─────────────────────────────────────────────────────────
// Three points fix an affine map exactly, which sounds sufficient and is not:
// "exactly" means every measurement error in those three points lands undiluted
// in the map, and the map is then extrapolated across the whole symbol. At
// version 37 the far corner is 158 modules from the origin, so half a pixel of
// error in a finder centre is half a module of error where it matters, and the
// sampler reads the neighbouring module. Measured: a rotated version 37 at 3
// pixels per module read about 40 % of the time.
//
// The alignment patterns are the fix, and they are the reason they exist. They
// are landmarks with known module coordinates spread over the whole symbol, so
// fitting the map to all of them by least squares both anchors the far corner
// and averages the noise down instead of extrapolating it up.
//
// Still affine, not projective. A photograph taken off-axis needs a projective
// map and this is not one; what this does is stop an *affine* symbol from
// drifting, which is the failure that was measured. See SPEC.

/// Least-squares fit of a `Grid` to correspondences (module centre -> image
/// point). Accumulated in f64: at version 40 the normal equations carry sums of
/// squares of coordinates up to 170, over up to 49 points, and f32 loses the
/// small corrections that are the entire point of doing this.
const Fit = struct {
    n: f64 = 0,
    sx: f64 = 0,
    sy: f64 = 0,
    sxx: f64 = 0,
    sxy: f64 = 0,
    syy: f64 = 0,
    tx: f64 = 0,
    ty: f64 = 0,
    txx: f64 = 0,
    txy: f64 = 0,
    tyx: f64 = 0,
    tyy: f64 = 0,

    /// `mx`, `my` are module indices; the +0.5 is what makes them module
    /// *centres*, which is the convention `Grid.at` samples on. Fitting on the
    /// index and sampling on the centre differ by half a module in both axes —
    /// a grid that is uniformly wrong, which decodes exactly never and looks
    /// like a detection problem.
    fn add(self: *Fit, mx: f32, my: f32, ix: f32, iy: f32) void {
        const x: f64 = mx + 0.5;
        const y: f64 = my + 0.5;
        const u: f64 = ix;
        const v: f64 = iy;
        self.n += 1;
        self.sx += x;
        self.sy += y;
        self.sxx += x * x;
        self.sxy += x * y;
        self.syy += y * y;
        self.tx += u;
        self.ty += v;
        self.txx += x * u;
        self.txy += y * u;
        self.tyx += x * v;
        self.tyy += y * v;
    }

    /// Solve both 3x3 normal-equation systems. They share a matrix, so it is
    /// inverted once by cofactors; null when the points are collinear, which
    /// makes the determinant vanish and any "solution" arbitrary.
    fn solve(self: Fit) ?Grid {
        const m = [3][3]f64{
            .{ self.sxx, self.sxy, self.sx },
            .{ self.sxy, self.syy, self.sy },
            .{ self.sx, self.sy, self.n },
        };
        const c00 = m[1][1] * m[2][2] - m[1][2] * m[2][1];
        const c01 = m[1][2] * m[2][0] - m[1][0] * m[2][2];
        const c02 = m[1][0] * m[2][1] - m[1][1] * m[2][0];
        const det = m[0][0] * c00 + m[0][1] * c01 + m[0][2] * c02;
        if (@abs(det) < 1e-9) return null;

        const c10 = m[0][2] * m[2][1] - m[0][1] * m[2][2];
        const c11 = m[0][0] * m[2][2] - m[0][2] * m[2][0];
        const c12 = m[0][1] * m[2][0] - m[0][0] * m[2][1];
        const c20 = m[0][1] * m[1][2] - m[0][2] * m[1][1];
        const c21 = m[0][2] * m[1][0] - m[0][0] * m[1][2];
        const c22 = m[0][0] * m[1][1] - m[0][1] * m[1][0];

        const inv = [3][3]f64{
            .{ c00 / det, c10 / det, c20 / det },
            .{ c01 / det, c11 / det, c21 / det },
            .{ c02 / det, c12 / det, c22 / det },
        };
        const rx = [3]f64{ self.txx, self.txy, self.tx };
        const ry = [3]f64{ self.tyx, self.tyy, self.ty };

        var g: Grid = undefined;
        g.ax = @floatCast(inv[0][0] * rx[0] + inv[0][1] * rx[1] + inv[0][2] * rx[2]);
        g.bx = @floatCast(inv[1][0] * rx[0] + inv[1][1] * rx[1] + inv[1][2] * rx[2]);
        g.cx = @floatCast(inv[2][0] * rx[0] + inv[2][1] * rx[1] + inv[2][2] * rx[2]);
        g.ay = @floatCast(inv[0][0] * ry[0] + inv[0][1] * ry[1] + inv[0][2] * ry[2]);
        g.by = @floatCast(inv[1][0] * ry[0] + inv[1][1] * ry[1] + inv[1][2] * ry[2]);
        g.cy = @floatCast(inv[2][0] * ry[0] + inv[2][1] * ry[1] + inv[2][2] * ry[2]);
        return g;
    }
};

/// Refit the grid to every alignment pattern that can be found. Returns the
/// original grid when there are too few to improve on it — version 1 has none
/// at all, and a symbol whose alignment patterns are unreadable is better served
/// by the finder-only grid than by a fit to two points.
fn refine(b: *const Bitmap, c: Corners, grid: Grid) Grid {
    const version: u6 = @intCast((c.dimension - 17) / 4);
    var centres_buf: [7]u16 = undefined;
    const centres = qr.alignmentCentres(version, &centres_buf);
    if (centres.len == 0) return grid;

    var fit: Fit = .{};
    // The finder centres are measurements too, and good ones — they anchor the
    // three corners no alignment pattern reaches.
    const dim_f: f32 = @floatFromInt(c.dimension);
    fit.add(3.0, 3.0, c.tl.x, c.tl.y);
    fit.add(dim_f - 4.0, 3.0, c.tr.x, c.tr.y);
    fit.add(3.0, dim_f - 4.0, c.bl.x, c.bl.y);

    var found: u32 = 0;
    for (centres) |ay| {
        for (centres) |ax| {
            // The three corners carry finders, not alignment patterns.
            const first = centres[0];
            const last = centres[centres.len - 1];
            if ((ax == first and ay == first) or
                (ax == last and ay == first) or
                (ax == first and ay == last)) continue;

            const mx: f32 = @floatFromInt(ax);
            const my: f32 = @floatFromInt(ay);
            const predicted = grid.at(mx, my);
            const hit = findAlignment(b, predicted, c.module) orelse continue;
            fit.add(mx, my, hit[0], hit[1]);
            found += 1;
        }
    }

    if (found < 2) return grid;
    return fit.solve() orelse grid;
}

/// Locate one alignment pattern near where the grid says it should be.
///
/// The pattern is 5x5: a dark ring, a light ring, one dark module in the middle.
/// What is looked for is that middle module — a dark run about one module wide
/// with light either side — because it is the only feature whose centre is a
/// point rather than an edge, and because finding it re-uses no assumption about
/// the ring the sampler is about to rely on.
fn findAlignment(b: *const Bitmap, predicted: [2]f32, module: f32) ?[2]f32 {
    if (predicted[0] < 0 or predicted[1] < 0) return null;
    const px: i32 = @intFromFloat(predicted[0]);
    const py: i32 = @intFromFloat(predicted[1]);

    // Search a window of about +-1.5 modules: further than the drift this is
    // correcting, and closer than the neighbouring dark ring.
    const reach: i32 = @max(2, @as(i32, @intFromFloat(module * 1.5)));
    const w: i32 = @intCast(b.width);
    const h: i32 = @intCast(b.height);

    var best: ?[2]f32 = null;
    var best_d2: f32 = std.math.floatMax(f32);

    var dy: i32 = -reach;
    while (dy <= reach) : (dy += 1) {
        var dx: i32 = -reach;
        while (dx <= reach) : (dx += 1) {
            const x = px + dx;
            const y = py + dy;
            if (x < 0 or y < 0 or x >= w or y >= h) continue;
            if (!b.get(@intCast(x), @intCast(y))) continue;

            const hx = alignmentRun(b, x, y, .horizontal, module) orelse continue;
            const hy = alignmentRun(b, x, y, .vertical, module) orelse continue;
            const cand = [2]f32{ hx, hy };
            const ddx = cand[0] - predicted[0];
            const ddy = cand[1] - predicted[1];
            const d2 = ddx * ddx + ddy * ddy;
            if (d2 < best_d2) {
                best_d2 = d2;
                best = cand;
            }
        }
    }
    return best;
}

const Axis = enum { horizontal, vertical };

/// Centre of the alignment pattern's middle module, if the line through (x, y)
/// crosses a whole one.
///
/// A one-module dark run is not evidence of anything — the data region is full
/// of them, and the search window reaches into it. What is checked is the whole
/// dark-light-dark-light-dark crossing, five runs of one module each, which is
/// what an alignment pattern is and what a data module is not. Getting this
/// wrong is not a missed pattern but a *wrong* one: a stray data module fed to
/// the least-squares fit drags the grid instead of anchoring it.
fn alignmentRun(b: *const Bitmap, x: i32, y: i32, axis: Axis, module: f32) ?f32 {
    const limit: i32 = @intCast(if (axis == .horizontal) b.width else b.height);
    const start: i32 = if (axis == .horizontal) x else y;

    // The centre run first, then one light and one dark run either side.
    var lo = start;
    while (lo - 1 >= 0 and isDarkAt(b, x, y, axis, lo - 1)) lo -= 1;
    var hi = start;
    while (hi + 1 < limit and isDarkAt(b, x, y, axis, hi + 1)) hi += 1;
    if (lo == 0 or hi == limit - 1) return null;

    var runs: [5]f32 = undefined;
    runs[2] = @floatFromInt(hi - lo + 1);

    var p = lo - 1;
    var light: i32 = 0;
    while (p >= 0 and !isDarkAt(b, x, y, axis, p)) : (p -= 1) light += 1;
    runs[1] = @floatFromInt(light);
    var dark: i32 = 0;
    while (p >= 0 and isDarkAt(b, x, y, axis, p)) : (p -= 1) dark += 1;
    runs[0] = @floatFromInt(dark);

    p = hi + 1;
    light = 0;
    while (p < limit and !isDarkAt(b, x, y, axis, p)) : (p += 1) light += 1;
    runs[3] = @floatFromInt(light);
    dark = 0;
    while (p < limit and isDarkAt(b, x, y, axis, p)) : (p += 1) dark += 1;
    runs[4] = @floatFromInt(dark);

    // Half a module of slack per run: the same tolerance the finder ratio uses,
    // and it is what a symbol photographed small still satisfies.
    for (runs) |r| {
        if (r < module * 0.5 or r > module * 1.5) return null;
    }
    return (@as(f32, @floatFromInt(lo)) + @as(f32, @floatFromInt(hi)) + 1) / 2;
}

fn isDarkAt(b: *const Bitmap, x: i32, y: i32, axis: Axis, at: i32) bool {
    return switch (axis) {
        .horizontal => b.get(@intCast(at), @intCast(y)),
        .vertical => b.get(@intCast(x), @intCast(at)),
    };
}

/// The dimension out of `orient` is a measurement rounded to the nearest legal
/// symbol size, and a measurement that lands one version out still samples
/// cleanly: every module gets a value, the grid looks like a QR code, and
/// `qr.decode` reports a format error that reads like a problem with the
/// picture. So sample the neighbouring legal sizes as well and keep the one the
/// symbol agrees with.
///
/// The timing patterns are the referee. They are the one part of a symbol whose
/// content is fixed by the standard rather than by the message — row 6 and
/// column 6 alternate, dark on even coordinates — so they say whether the grid
/// was laid over the modules or across them, and they say it before any
/// error correction gets a chance to hide the answer.
fn sampleBestDimension(b: *const Bitmap, c: Corners) Error!struct { found: Found, score: f32 } {
    var best: ?Found = null;
    var best_score: f32 = -1;

    // Nearest first, so an exact tie keeps the measured dimension.
    for ([_]i32{ 0, -4, 4, -8, 8 }) |delta| {
        const dim = @as(i32, @intCast(c.dimension)) + delta;
        if (dim < 21 or dim > qr.max_size) continue;

        var candidate = c;
        candidate.dimension = @intCast(dim);
        const coarse = gridFromCorners(candidate);
        // Refine against the alignment patterns before scoring: a wrong
        // dimension predicts alignment patterns where there are none, so the
        // refinement quietly declines to make a wrong grid look better.
        const got = sample(b, candidate, refine(b, candidate, coarse)) catch continue;

        const score = timingScore(&got.matrix);
        if (score > best_score) {
            best_score = score;
            best = got;
        }
        if (score == 1.0) break;
    }

    // Deliberately no minimum score. A real symbol with a damaged timing pattern
    // still decodes — the data is protected and the timing is not — so a
    // threshold here would reject reads that currently succeed. The score picks
    // between candidates; it does not get a veto.
    return .{ .found = best orelse return Error.NotFound, .score = best_score };
}

/// How much of the two timing patterns alternates the way the standard says.
fn timingScore(m: *const qr.Matrix) f32 {
    const dim = m.size;
    var ok: u32 = 0;
    var total: u32 = 0;
    var i: u16 = 8;
    while (i + 9 <= dim) : (i += 1) {
        const want = i % 2 == 0;
        if (m.isDark(i, 6) == want) ok += 1;
        if (m.isDark(6, i) == want) ok += 1;
        total += 2;
    }
    if (total == 0) return 0;
    return @as(f32, @floatFromInt(ok)) / @as(f32, @floatFromInt(total));
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

test "rotation: a symbol reads at any angle" {
    const t = std.testing;
    var pixels: [900 * 900]u8 = undefined;
    var scratch: [900 * 900 / 8]u8 = undefined;
    var out: [512]u8 = undefined;
    var m: qr.Matrix = undefined;

    // Two sizes, because the two things that break under rotation break at
    // different scales: the module estimate is wrong at every size, and the
    // candidate list overflows only once the data region is large enough to
    // hold false positives of its own.
    const texts = [_][]const u8{
        "ROTATED SYMBOL",
        "https://example.com/a-longer-url-that-needs-a-considerably-bigger-symbol/12345",
    };
    for (texts) |text| {
        try qr.encode(&m, text, .{ .ecc = .quartile });
        var deg: f32 = 0;
        while (deg < 360) : (deg += 15) {
            var side: u32 = 0;
            const img = renderRotated(&m, 4, deg, &pixels, &side);
            const found = scan(img, &scratch) catch |e| {
                std.debug.print("scan failed at {d} degrees, version {d}: {s}\n", .{ deg, m.version, @errorName(e) });
                return e;
            };
            var fm = found.matrix;
            const got = qr.decode(&fm, &out) catch |e| {
                std.debug.print("decode failed at {d} degrees, version {d}: {s}\n", .{ deg, m.version, @errorName(e) });
                return e;
            };
            try t.expectEqualStrings(text, got);
        }
    }
}

test "the module size a scan line measures is inflated by the tilt" {
    const t = std.testing;
    var m: qr.Matrix = undefined;
    try qr.encode(&m, "TILT", .{ .ecc = .quartile });

    var pixels: [900 * 900]u8 = undefined;
    var scratch: [900 * 900 / 8]u8 = undefined;

    // 45 degrees is the worst case: a horizontal line through the centre of a
    // square tilted that far crosses it in side / cos(45) = 1.41 sides, and the
    // same factor applies to every concentric ring, which is exactly why the
    // 1:1:3:1:1 ratio still holds and the finder is still found. Uncorrected,
    // the version comes out four sizes small and the symbol is unreadable while
    // every intermediate step looks fine.
    var side: u32 = 0;
    const img = renderRotated(&m, 6, 45, &pixels, &side);
    var bits: Bitmap = .{ .bits = &scratch, .width = img.width, .height = img.height };
    binarize(img, &bits);

    var finders: [max_candidates]Finder = undefined;
    const found = locateFinders(&bits, &finders, true);
    try t.expect(found.len >= 3);

    const c = orient(found) orelse return error.NoCorners;
    try t.expectEqual(@as(u32, m.size), c.dimension);
    // The corrected module is the rendered one, not the 1.41x the scan measured.
    // Corrected, the estimate is the module that was rendered; raw, it is that
    // module times 1 / cos(45) = 1.41, which is where the four versions went.
    try t.expect(@abs(c.module - 6.0) < 0.5);
    try t.expect((c.tl.peak + c.tr.peak + c.bl.peak) / 3 > 7.5);
}

test "a dimension one version out is rejected by the timing pattern" {
    const t = std.testing;
    var m: qr.Matrix = undefined;
    try qr.encode(&m, "https://example.com/dimension-check", .{ .ecc = .quartile });

    var pixels: [512 * 512]u8 = undefined;
    var scratch: [512 * 512 / 8]u8 = undefined;
    const img = render(&m, 4, &pixels);
    var bits: Bitmap = .{ .bits = &scratch, .width = img.width, .height = img.height };
    binarize(img, &bits);

    var finders: [max_candidates]Finder = undefined;
    const found = locateFinders(&bits, &finders, true);
    var c = orient(found) orelse return error.NoCorners;
    try t.expectEqual(@as(u32, m.size), c.dimension);

    // Hand the sampler a dimension one version too large, the way a module
    // estimate half a percent off would. The wrong grid samples perfectly well
    // — this is the failure mode that looks like a picture problem — so the
    // timing pattern has to be what rejects it.
    const off_by_one: Corners = .{ .tl = c.tl, .tr = c.tr, .bl = c.bl, .module = c.module, .dimension = c.dimension + 4 };
    const wrong = sample(&bits, off_by_one, gridFromCorners(off_by_one)) catch
        return error.WrongDimensionDidNotEvenSample;
    try t.expect(timingScore(&wrong.matrix) < 0.9);

    c.dimension += 4;
    const best = (try sampleBestDimension(&bits, c)).found;
    try t.expectEqual(m.size, best.matrix.size);

    var fm = best.matrix;
    var out: [128]u8 = undefined;
    try t.expectEqualStrings("https://example.com/dimension-check", try qr.decode(&fm, &out));
}

test "the ring test is what keeps a large symbol's own data from crowding it out" {
    const t = std.testing;
    var m: qr.Matrix = undefined;
    try qr.encode(&m, "N" ** 300, .{ .ecc = .quartile });

    var pixels: [900 * 900]u8 = undefined;
    var scratch: [900 * 900 / 8]u8 = undefined;
    var side: u32 = 0;
    const img = renderRotated(&m, 4, 20, &pixels, &side);
    var bits: Bitmap = .{ .bits = &scratch, .width = img.width, .height = img.height };
    binarize(img, &bits);

    var finders: [max_candidates]Finder = undefined;
    const relaxed = locateFinders(&bits, &finders, false).len;
    const strict = locateFinders(&bits, &finders, true).len;

    // The numbers are incidental (3 against 15 as measured); the relationship
    // is not. Without the ring requirement this symbol's own data region
    // produces several times as many candidates as there are finders, and every
    // one of them is something the triple search has to be talked out of.
    try t.expect(strict >= 3);
    try t.expect(relaxed >= strict * 3);
    try t.expect(orient(locateFinders(&bits, &finders, true)) != null);
}

test "the least-squares fit reproduces the grid it was sampled from" {
    const t = std.testing;
    // A grid with rotation, scale and translation in it, so a fit that is right
    // only for the axis-aligned case cannot pass.
    const truth: Grid = .{ .ax = 4.1, .bx = -1.7, .cx = 31.5, .ay = 1.6, .by = 4.3, .cy = -12.25 };

    var fit: Fit = .{};
    for ([_][2]f32{ .{ 3, 3 }, .{ 60, 3 }, .{ 3, 60 }, .{ 30, 30 }, .{ 58, 46 }, .{ 12, 51 } }) |mp| {
        const p = truth.at(mp[0], mp[1]);
        fit.add(mp[0], mp[1], p[0], p[1]);
    }
    const got = fit.solve() orelse return error.Singular;

    // The half-module offset is the trap: `Fit.add` takes module indices and
    // `Grid.at` samples module centres, so a fit built on one convention and
    // sampled on the other is out by half a module everywhere — uniformly, so
    // every intermediate value still looks reasonable.
    for ([_][2]f32{ .{ 0, 0 }, .{ 40, 7 }, .{ 64, 64 } }) |mp| {
        const want = truth.at(mp[0], mp[1]);
        const have = got.at(mp[0], mp[1]);
        try t.expect(@abs(want[0] - have[0]) < 0.01);
        try t.expect(@abs(want[1] - have[1]) < 0.01);
    }
}

test "a broken ring has the finder ratio in both axes and is still not a finder" {
    const t = std.testing;
    // A finder pattern with the four corners of its outer ring erased. Every
    // run-length test a scanner can apply still passes — the middle row is
    // 1:1:3:1:1 and so is the middle column — and it is not a finder, because
    // the outer band is four separate bars rather than one ring. This is the
    // shape that separates the two tests; a fence cannot, since a fence fails
    // the vertical check anyway.
    const s = 6;
    var pixels: [200 * 200]u8 = undefined;
    @memset(&pixels, 255);
    for (0..7) |my| {
        for (0..7) |mx| {
            const ring = mx == 0 or mx == 6 or my == 0 or my == 6;
            // Erase the corner of the ring far enough that the bars do not
            // touch even diagonally — the labelling is 8-connected, so a single
            // erased module leaves them joined at the corner and the ring
            // intact.
            const corner = @min(mx, 6 - mx) + @min(my, 6 - my) <= 1;
            const centre = mx >= 2 and mx <= 4 and my >= 2 and my <= 4;
            if (!((ring and !corner) or centre)) continue;
            for (0..s) |dy| {
                for (0..s) |dx| {
                    pixels[(40 + my * s + dy) * 200 + (40 + mx * s + dx)] = 0;
                }
            }
        }
    }
    const img: Image = .{ .luma = &pixels, .width = 200, .height = 200, .stride = 200 };
    var scratch: [200 * 200 / 8]u8 = undefined;
    var bits: Bitmap = .{ .bits = &scratch, .width = 200, .height = 200 };
    binarize(img, &bits);

    var finders: [max_candidates]Finder = undefined;
    try t.expect(locateFinders(&bits, &finders, false).len > 0);
    try t.expectEqual(@as(usize, 0), locateFinders(&bits, &finders, true).len);
}

test "a large symbol needs the alignment patterns, not just its corners" {
    const t = std.testing;
    var m: qr.Matrix = undefined;
    try qr.encode(&m, "N" ** 2000, .{ .ecc = .quartile });
    try t.expect(m.size >= 145); // version 33 or larger

    var pixels: [900 * 900]u8 = undefined;
    var scratch: [900 * 900 / 8]u8 = undefined;
    var side: u32 = 0;
    const img = renderRotated(&m, 3, 20, &pixels, &side);
    var bits: Bitmap = .{ .bits = &scratch, .width = img.width, .height = img.height };
    binarize(img, &bits);

    // What the scanner settles on, so the comparison below is about the grid
    // and not about the dimension search.
    const found = try scan(img, &scratch);
    try t.expectEqual(@as(u16, m.size), found.matrix.size);

    var finders: [max_candidates]Finder = undefined;
    var c = orient(locateFinders(&bits, &finders, true)) orelse return error.NoCorners;
    c.dimension = m.size;

    const coarse = gridFromCorners(c);
    const refined = refine(&bits, c, coarse);

    // The refinement moved the far corner by enough to change which module it
    // samples, which is the whole point: three corner points fix an affine map
    // exactly and then extrapolate every measurement error across the symbol.
    const far_coarse = coarse.at(@floatFromInt(m.size - 1), @floatFromInt(m.size - 1));
    const far_refined = refined.at(@floatFromInt(m.size - 1), @floatFromInt(m.size - 1));
    const moved = @abs(far_coarse[0] - far_refined[0]) + @abs(far_coarse[1] - far_refined[1]);
    try t.expect(moved > 0.5);

    // And it moved it the right way.
    const with = try sample(&bits, c, refined);
    var fm = with.matrix;
    var out: [3000]u8 = undefined;
    try t.expectEqualStrings("N" ** 2000, try qr.decode(&fm, &out));
}

test "rotation holds at the largest versions, where the grid has furthest to drift" {
    const t = std.testing;
    var m: qr.Matrix = undefined;
    try qr.encode(&m, "N" ** 2000, .{ .ecc = .quartile });

    var pixels: [900 * 900]u8 = undefined;
    var scratch: [900 * 900 / 8]u8 = undefined;
    var out: [3000]u8 = undefined;

    var ok: u32 = 0;
    var total: u32 = 0;
    var deg: f32 = 0;
    while (deg < 360) : (deg += 15) {
        var side: u32 = 0;
        const img = renderRotated(&m, 3, deg, &pixels, &side);
        total += 1;
        const found = scan(img, &scratch) catch continue;
        var fm = found.matrix;
        const got = qr.decode(&fm, &out) catch continue;
        if (std.mem.eql(u8, got, "N" ** 2000)) ok += 1;
    }

    // Three pixels per module across 165 of them is the bottom of what this
    // samples, so it is asserted as a floor rather than as a rate — improving
    // it must not fail the test. Before the grid was fitted to the alignment
    // patterns and the ring test cleared the candidate list, it was 9 in 72.
    try t.expect(ok * 4 >= total * 3);
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
