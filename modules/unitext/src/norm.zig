// SPDX-License-Identifier: MIT

//! Unicode normalization forms NFC, NFD, NFKC, NFKD (UAX #15, Unicode 17) of UTF-8
//! strings, and the quick-check / is-normalized tests.
//!
//! Behaviour is CPython's `unicodedata.normalize` / `is_normalized`, Rust's
//! `unicode-normalization` crate and Go's `golang.org/x/text/unicode/norm`: the same
//! algorithm, checked against Unicode's own NormalizationTest.txt. They take a `str`
//! (Python, Rust) so ill-formed bytes cannot reach them; here the `invalid_utf8` option
//! decides.
//!
//! The text is cut into segments at every starter that cannot combine with what
//! precedes it (combining class 0 and NFC_QC=Yes); each segment is decomposed,
//! stably sorted by combining class, and (NFC, NFKC) composed. A segment is held in
//! memory, which is why `Options.max_segment` exists: a text with millions of marks in
//! a row is one segment. The Stream-Safe Text Format is not enforced.

const std = @import("std");
const ucd = @import("ucd.zig");
const utf8 = @import("utf8.zig");
const t = @import("tables.zig");
const common = @import("common.zig");

pub const Options = common.Options;
pub const Error = common.Error;
pub const WriteAllocError = common.WriteAllocError;
const Emitter = common.Emitter;
const hangul = ucd.hangul;

/// A normalization form (UAX #15 §1.2).
pub const Form = enum {
    /// Canonical decomposition, then canonical composition (the form of most text on the web).
    nfc,
    /// Canonical decomposition.
    nfd,
    /// Compatibility decomposition, then canonical composition.
    nfkc,
    /// Compatibility decomposition (ﬁ -> fi, ① -> 1, ² -> 2, full-width -> ASCII).
    nfkd,
};

const mask: u32 = 0xFFFFFF;

fn lessCcc(_: void, a: u32, b: u32) bool {
    return (a >> 24) < (b >> 24);
}

fn sortMarks(items: []u32) void {
    var i: usize = 0;
    while (i < items.len) {
        if (items[i] >> 24 == 0) {
            i += 1;
            continue;
        }
        var j = i + 1;
        while (j < items.len and items[j] >> 24 != 0) j += 1;
        if (j - i > 1) {
            if (j - i <= 16) {
                std.sort.insertion(u32, items[i..j], {}, lessCcc);
            } else {
                std.sort.block(u32, items[i..j], {}, lessCcc);
            }
        }
        i = j;
    }
}

fn composePair(first: u32, second: u32) ?u21 {
    // Hangul: L + V -> LV, LV + T -> LVT (algorithmic, §3.12)
    if (first >= hangul.l_base and first < hangul.l_base + hangul.l_count and
        second >= hangul.v_base and second < hangul.v_base + hangul.v_count)
    {
        const l = first - hangul.l_base;
        const v = second - hangul.v_base;
        return @intCast(hangul.s_base + (l * hangul.v_count + v) * hangul.t_count);
    }
    if (first >= hangul.s_base and first < hangul.s_base + hangul.s_count and
        (first - hangul.s_base) % hangul.t_count == 0 and
        second > hangul.t_base and second < hangul.t_base + hangul.t_count)
    {
        return @intCast(first + (second - hangul.t_base));
    }
    var lo: usize = 0;
    var hi: usize = t.compose_pairs.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const p = t.compose_pairs[mid];
        if (p.a == first and p.b == second) return @intCast(p.c);
        if (p.a < first or (p.a == first and p.b < second)) lo = mid + 1 else hi = mid;
    }
    return null;
}

/// UAX #15 canonical composition of a canonically ordered segment, in place; returns the new length.
fn compose(items: []u32) usize {
    var out: usize = 0;
    var starter: ?usize = null;
    var kept_after = false; // a non-starter was kept after the starter
    var last_ccc: u32 = 0; // its combining class
    for (items) |e| {
        const c = e & mask;
        const cc = e >> 24;
        if (starter) |si| {
            const blocked = kept_after and last_ccc >= cc;
            if (!blocked) {
                if (composePair(items[si] & mask, c)) |comp| {
                    items[si] = comp | (@as(u32, ucd.ccc(comp)) << 24);
                    continue;
                }
            }
        }
        items[out] = e;
        if (cc == 0) {
            starter = out;
            kept_after = false;
            last_ccc = 0;
        } else if (starter != null) {
            kept_after = true;
            last_ccc = cc;
        }
        out += 1;
    }
    return out;
}

fn flushSegment(seg: *std.ArrayList(u32), em: anytype, comp: bool) !void {
    if (seg.items.len == 0) return;
    sortMarks(seg.items);
    const n = if (comp) compose(seg.items) else seg.items.len;
    for (seg.items[0..n]) |e| try em.cp(@intCast(e & mask));
    seg.clearRetainingCapacity();
}

fn addCp(gpa: std.mem.Allocator, seg: *std.ArrayList(u32), em: anytype, comp: bool, cp: u21, max: usize) !void {
    const info = ucd.normInfo(cp);
    const cc: u32 = info & 0xFF;
    if (cc == 0 and (!comp or ((info >> 8) & 3) == 0)) try flushSegment(seg, em, comp);
    if (seg.items.len >= max) return error.TooLarge;
    try seg.append(gpa, @as(u32, cp) | (cc << 24));
}

fn addDecomposed(gpa: std.mem.Allocator, seg: *std.ArrayList(u32), em: anytype, comp: bool, compat: bool, cp: u21, max: usize) !void {
    if (hangul.isSyllable(cp)) {
        const si = cp - hangul.s_base;
        try addCp(gpa, seg, em, comp, hangul.l_base + si / hangul.n_count, max);
        try addCp(gpa, seg, em, comp, hangul.v_base + (si % hangul.n_count) / hangul.t_count, max);
        const ti = si % hangul.t_count;
        if (ti != 0) try addCp(gpa, seg, em, comp, hangul.t_base + ti, max);
        return;
    }
    const rec = ucd.look(t.decomp, cp);
    const len: usize = if (compat) rec.nfkd_len else rec.nfd_len;
    if (len == 0) return addCp(gpa, seg, em, comp, cp, max);
    const off: usize = if (compat) rec.nfkd_off else rec.nfd_off;
    for (t.decomp_pool[off..][0..len]) |d| try addCp(gpa, seg, em, comp, @intCast(d), max);
}

/// Normalize `s` to `form` into `out` (a `common` sink). `gpa` holds the working segment.
pub fn run(gpa: std.mem.Allocator, out: anytype, s: []const u8, form: Form, opts: Options) !void {
    const Out = @typeInfo(@TypeOf(out)).pointer.child;
    var em: Emitter(Out) = .{ .out = out };
    var seg: std.ArrayList(u32) = .empty;
    defer seg.deinit(gpa);
    const compat = form == .nfkc or form == .nfkd;
    const comp = form == .nfc or form == .nfkc;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] < 0x80) {
            // ASCII is a starter that nothing composes into, and (as the first of a pair) only
            // the last byte of the run can combine with a following mark.
            try flushSegment(&seg, &em, comp);
            var j = i + 1;
            while (j < s.len and s[j] < 0x80) j += 1;
            if (comp and j < s.len) {
                try em.bytes(s[i .. j - 1]);
                try addCp(gpa, &seg, &em, comp, s[j - 1], opts.max_segment);
            } else {
                try em.bytes(s[i..j]);
            }
            i = j;
            continue;
        }
        const u = try utf8.unit(s, i, opts.invalid_utf8);
        const start = i;
        i += u.len;
        if (u.raw) {
            try flushSegment(&seg, &em, comp);
            try em.bytes(s[start..i]);
            continue;
        }
        try addDecomposed(gpa, &seg, &em, comp, compat, u.cp, opts.max_segment);
    }
    try flushSegment(&seg, &em, comp);
    try em.flush();
}

// ── public API ──────────────────────────────────────────────────────────────

/// Python `unicodedata.normalize(form, s)` / Rust `unicode-normalization` / Go `norm.Form.String`:
/// `s` in the given normalization form, newly allocated (caller frees with `a`).
/// The result is canonically equivalent (compatibility-equivalent for NFKC/NFKD) to `s`;
/// ill-formed bytes follow `opts.invalid_utf8`.
pub fn normalize(a: std.mem.Allocator, s: []const u8, form: Form, opts: Options) Error![]u8 {
    var o: common.ListOut = .{ .a = a, .cap = opts.max_output };
    errdefer o.deinit();
    try o.list.ensureTotalCapacity(a, @min(s.len, opts.max_output));
    try run(a, &o, s, form, opts);
    return o.toOwned();
}

/// Writer form of `normalize`. `gpa` is only used for the working segment buffer
/// (`opts.max_segment` code points at most); the output is streamed to `w`.
pub fn normalizeTo(gpa: std.mem.Allocator, w: *std.Io.Writer, s: []const u8, form: Form, opts: Options) WriteAllocError!void {
    var o: common.WriterOut = .{ .w = w };
    return run(gpa, &o, s, form, opts);
}

/// The answer of a quick-check (UAX #15 §9.1).
pub const QuickCheck = enum { yes, no, maybe };

/// UAX #15 quick check: `.yes` / `.no` are certain, `.maybe` needs the full test
/// (`isNormalized`). Needs no allocation; one pass, two table lookups per code point.
/// CPython's `is_normalized` does the same quick check and then the full comparison.
/// Ill-formed UTF-8 is `error.InvalidUtf8`.
pub fn quickCheck(s: []const u8, form: Form) error{InvalidUtf8}!QuickCheck {
    return quickCheckPolicy(s, form, .reject);
}

fn quickCheckPolicy(s: []const u8, form: Form, policy: utf8.InvalidUtf8) error{InvalidUtf8}!QuickCheck {
    var result: QuickCheck = .yes;
    var last_cc: u8 = 0;
    var i: usize = 0;
    while (i < s.len) {
        const u = try utf8.unit(s, i, policy);
        i += u.len;
        if (u.raw) {
            last_cc = 0;
            continue;
        }
        const info = ucd.normInfo(u.cp);
        const cc: u8 = @truncate(info);
        if (cc != 0 and last_cc > cc) return .no;
        last_cc = cc;
        switch (form) {
            .nfd => if (info & (1 << 12) != 0 or hangul.isSyllable(u.cp)) return .no,
            .nfkd => if (info & (1 << 13) != 0 or hangul.isSyllable(u.cp)) return .no,
            .nfc => switch ((info >> 8) & 3) {
                2 => return .no,
                1 => result = .maybe,
                else => {},
            },
            .nfkc => switch ((info >> 10) & 3) {
                2 => return .no,
                1 => result = .maybe,
                else => {},
            },
        }
    }
    return result;
}

const CompareOut = struct {
    src: []const u8,
    pos: usize = 0,
    pub const Error = error{Mismatch};
    pub fn put(self: *CompareOut, bytes: []const u8) CompareOut.Error!void {
        if (bytes.len > self.src.len - self.pos or !std.mem.eql(u8, self.src[self.pos..][0..bytes.len], bytes)) return error.Mismatch;
        self.pos += bytes.len;
    }
};

/// Python `unicodedata.is_normalized(form, s)`: whether `s` is already in `form`.
/// The quick check decides when it can; on `.maybe` the string is normalized and compared
/// segment by segment against the input (no output is built; `gpa` holds one segment).
/// Under `.replace` and `.pass_through` an ill-formed stretch is neutral (a starter that
/// is its own normal form); `.reject` returns `error.InvalidUtf8`.
pub fn isNormalized(gpa: std.mem.Allocator, s: []const u8, form: Form, opts: Options) error{ InvalidUtf8, OutOfMemory, TooLarge }!bool {
    const policy: utf8.InvalidUtf8 = if (opts.invalid_utf8 == .reject) .reject else .pass_through;
    switch (try quickCheckPolicy(s, form, policy)) {
        .yes => return true,
        .no => return false,
        .maybe => {},
    }
    var cmp: CompareOut = .{ .src = s };
    var o = opts;
    o.invalid_utf8 = policy;
    run(gpa, &cmp, s, form, o) catch |e| switch (e) {
        error.Mismatch => return false,
        else => |other| return other,
    };
    return cmp.pos == s.len;
}

comptime {
    // `run`'s ASCII shortcut relies on no composition pair ending in ASCII.
    for (t.compose_pairs) |p| if (p.b < 0x80) @compileError("a composition pair ends in ASCII");
}
