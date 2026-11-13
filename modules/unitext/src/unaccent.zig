// SPDX-License-Identifier: MIT

//! `unaccent`: fold accented letters to their base letters.
//!
//! The ICU recipe "NFD; remove [:Nonspacing Mark:]; NFC", plus two additions that
//! decomposition cannot give (tables derived from UCD names by `tools/ucd_gen/gen.py`):
//!
//!   * letters with no canonical decomposition named "LATIN SMALL|CAPITAL LETTER X WITH ..."
//!     (X one letter): ł -> l, ø -> o, đ -> d, ħ -> h, ŧ -> t, ɓ -> b, ...; the letters whose
//!     name is another word that stands for one letter (DOTLESS I/J, ETH, ENG, KRA, LONG S,
//!     OPEN E, U BAR, SCRIPT G, the insular letters, ...: ŋ -> n, ĸ -> q, ſ -> s), with or
//!     without "WITH ..."; and the small capitals, which fold to the capital (ᴀ -> A);
//!   * (`expand_ligatures`, default on) the ligatures and double letters that stand for
//!     several letters: æ -> ae, œ -> oe, ĳ -> ij, ß -> ss, þ -> th, ﬀ ﬁ ﬂ ﬃ ﬄ ﬅ ﬆ, the
//!     digraph letters Ǆ ǅ ǆ -> DZ Dz dz, Ǉ ǈ ǉ -> LJ Lj lj, Ǌ ǋ ǌ -> NJ Nj nj, Ǳ ǲ ǳ -> DZ Dz dz,
//!     the medievalist ligatures (Ꜳ -> AA, ꝏ -> oo, ...) and the IPA digraphs (ʦ -> ts, ...).
//!
//! This is what PostgreSQL's `unaccent` and ICU's "Latin-ASCII" give for Latin letters
//! (checked against `uconv -x Latin-ASCII` by `tools/latin_ascii_diff.py`; SPEC.md lists
//! where they differ) and what Python's `unidecode` gives for the covered letters; scikit-learn's
//! `strip_accents_unicode` is "NFKD; drop marks" and leaves ł, ø, æ, ß alone.
//! Nonspacing marks of EVERY script are removed (Hebrew points, Arabic harakat,
//! Devanagari vowel signs of category Mn), not only Latin accents; text in such
//! scripts loses information. Compatibility decompositions are not applied (use
//! NFKD for that).

const std = @import("std");
const ucd = @import("ucd.zig");
const utf8 = @import("utf8.zig");
const t = @import("tables.zig");
const common = @import("common.zig");
const norm = @import("norm.zig");

pub const Error = common.Error;
pub const WriteAllocError = common.WriteAllocError;

/// Options of `unaccent`.
pub const UnaccentOptions = struct {
    invalid_utf8: common.InvalidUtf8 = .reject,
    /// Cap on the result of an allocating form, and on each intermediate buffer, in bytes.
    max_output: usize = 1 << 30,
    /// Cap on one normalization segment; see `common.Options.max_segment`.
    max_segment: usize = 1 << 24,
    /// Expand ligatures and double letters (æ -> ae, ß -> ss, ﬁ -> fi, ...). False keeps
    /// them as they are (sklearn `strip_accents` behaviour for these).
    expand_ligatures: bool = true,
};

comptime {
    // The in-place filter below writes at most as many bytes as it reads.
    for (t.unaccent_expansions) |e| {
        var buf: [4]u8 = undefined;
        if (e.len > utf8.encode(e.cp, &buf)) @compileError("an unaccent expansion is longer than its source");
    }
    for (t.unaccent_letters) |e| if (e.cp < 0x80) @compileError("an unaccent letter is ASCII");
}

fn letterOf(cp: u21) ?u8 {
    var lo: usize = 0;
    var hi: usize = t.unaccent_letters.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const e = t.unaccent_letters[mid];
        if (e.cp == cp) return e.ascii;
        if (e.cp < cp) lo = mid + 1 else hi = mid;
    }
    return null;
}

fn expansionOf(cp: u21) ?t.UnaccentExpansion {
    var lo: usize = 0;
    var hi: usize = t.unaccent_expansions.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const e = t.unaccent_expansions[mid];
        if (e.cp == cp) return e;
        if (e.cp < cp) lo = mid + 1 else hi = mid;
    }
    return null;
}

/// NFD, filter, then NFC into `out`.
fn run(gpa: std.mem.Allocator, out: anytype, s: []const u8, opts: UnaccentOptions) !void {
    const base: common.Options = .{ .invalid_utf8 = opts.invalid_utf8, .max_output = opts.max_output, .max_segment = opts.max_segment };
    var tmp: common.ListOut = .{ .a = gpa, .cap = opts.max_output };
    defer tmp.deinit();
    try tmp.list.ensureTotalCapacity(gpa, @min(s.len, opts.max_output));
    try norm.run(gpa, &tmp, s, .nfd, base);
    // In place: the output never outruns the input (comptime-checked above).
    const buf = tmp.list.items;
    var w: usize = 0;
    var i: usize = 0;
    while (i < buf.len) {
        const st = utf8.step(buf, i);
        const n: usize = st.len;
        if (!st.valid or st.cp < 0x80) {
            std.mem.copyForwards(u8, buf[w..][0..n], buf[i..][0..n]);
            w += n;
        } else if (ucd.category(st.cp) == .Mn) {
            // dropped
        } else if (letterOf(st.cp)) |a| {
            buf[w] = a;
            w += 1;
        } else if (opts.expand_ligatures) {
            if (expansionOf(st.cp)) |e| {
                @memcpy(buf[w..][0..e.len], e.ascii[0..e.len]);
                w += e.len;
            } else {
                std.mem.copyForwards(u8, buf[w..][0..n], buf[i..][0..n]);
                w += n;
            }
        } else {
            std.mem.copyForwards(u8, buf[w..][0..n], buf[i..][0..n]);
            w += n;
        }
        i += n;
    }
    // Ill-formed bytes (only under .pass_through) are neutral to the composition too.
    var second = base;
    second.invalid_utf8 = .pass_through;
    try norm.run(gpa, out, buf[0..w], .nfc, second);
}

/// Fold accents and the letters listed in the module doc; see there for the rules and for
/// how this differs from Python/ICU/PostgreSQL. `"ŽLUŤOUČKÝ KŮŇ"` -> `"ZLUTOUCKY KUN"`,
/// `"Łódź"` -> `"Lodz"`, `"Straße"` -> `"Strasse"`.
pub fn unaccent(a: std.mem.Allocator, s: []const u8, opts: UnaccentOptions) Error![]u8 {
    var o: common.ListOut = .{ .a = a, .cap = opts.max_output };
    errdefer o.deinit();
    try o.list.ensureTotalCapacity(a, @min(s.len, opts.max_output));
    try run(a, &o, s, opts);
    return o.toOwned();
}

/// Writer form of `unaccent`. `gpa` holds the intermediate NFD text (up to
/// `opts.max_output` bytes) and one normalization segment.
pub fn unaccentTo(gpa: std.mem.Allocator, w: *std.Io.Writer, s: []const u8, opts: UnaccentOptions) WriteAllocError!void {
    var o: common.WriterOut = .{ .w = w };
    return run(gpa, &o, s, opts);
}
