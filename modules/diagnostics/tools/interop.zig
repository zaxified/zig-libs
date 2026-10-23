// SPDX-License-Identifier: MIT

//! Differential fuzz of the `snippet` renderer against codespan-reporting
//! 0.13.1 (Rust, Apache-2.0), the implementation its layout is ported from: the
//! **Evidence** line of the maturity card (`model-fuzz`).
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-diagnostics` runs it,
//! `zig build check-interop` compiles it. It needs no network, but it needs
//! `cargo` and the crates of `tools/codespan_bench` in the local registry
//! (`cargo fetch` once; pinned by its `Cargo.toml`/`Cargo.lock`); the oracle,
//! `tools/codespan_bench/src/bin/oracle.rs`, is built offline and `--locked`
//! into `.zig-cache/interop-diagnostics/target`. A missing one is a failure, not
//! a skip. Run from the repository root.
//!
//!   zig build interop-diagnostics                     # 20 000 seeds from 1
//!   zig build interop-diagnostics -- --seeds N --from S
//!   zig build interop-diagnostics -- --seed S         # replay one, print both sides
//!   zig build interop-diagnostics -- --lead           # the card's Ahead claim (raw control characters)
//!
//! Every seed is one case: 1-2 files of random text (ASCII, tabs, 2-, 3- and
//! 4-byte UTF-8, wide CJK and emoji, combining marks, CRLF, empty lines, with
//! or without a final newline), 1-2 diagnostics of every severity codespan has
//! an equivalent for (`note` is our `info`; the oracle rewrites its header
//! word), an optional code, 0-4 labels (primary and secondary, empty,
//! one-line, multi-line and end-of-file spans, across both files), 0-2 notes,
//! and random context-line settings. Each case is rendered by both sides in
//! both charsets (`ascii`, `unicode` = codespan's `Chars::box_drawing()`), with
//! `.column = .char` as codespan counts columns in characters, and must be
//! byte-identical. Generated but not compared (counted apart): three or more
//! single-line labels over one range, whose order codespan leaves to
//! `binary_search_by` (`unspecifiedOrder`).
//!
//! What is NOT generated, because the two sides differ on purpose (README,
//! "Rendering"): control characters in the source or in any message (ours
//! escapes them, codespan writes them raw), a lone CR, U+2028/U+2029 and a BOM
//! (line-ending handling, SPEC R6), a label edge between the `\r` and the `\n`
//! of a CRLF (ours: the `\r` belongs to the break, so the `-->` column is the
//! one after the line's last character; codespan counts the `\r` first),
//! `term_width` cutting (codespan has none) and
//! the `tab_width`-aware layout beyond codespan's default of 4.

const std = @import("std");
const dg = @import("diagnostics");

const scratch = ".zig-cache/interop-diagnostics";
const cargo_manifest = "modules/diagnostics/tools/codespan_bench/Cargo.toml";

const File = struct { name: []const u8, text: []const u8 };
const Lab = struct { primary: bool, file: usize, start: usize, end: usize, msg: []const u8 };
const Diag = struct {
    sev: dg.Severity,
    code: []const u8,
    msg: []const u8,
    labels: []const Lab,
    notes: []const []const u8,
};
const Case = struct {
    id: u64,
    ctx: [4]u32,
    files: []const File,
    diags: []const Diag,
};

// ── the generator ────────────────────────────────────────────────────────────

/// Pieces of source text; every one is valid UTF-8 and holds no control
/// character other than tab and the newline pieces.
const atoms = [_][]const u8{
    "a",        "b",        "x",        "fn", "let", "_", "0", "9", "{", "}", "(", ")", ";", ":",
    " ",        " ",        "  ",       "\t",
    "é",
    "ß",
    "ж",
    "λ",
    "中",
    "文",
    "한",
    "🦀",
    "e\u{301}", "\u{200b}", "\u{3000}",
    "ｱ",
    "→",
    "·",
};
const newlines = [_][]const u8{ "\n", "\n", "\n", "\r\n" };

const messages = [_][]const u8{
    "",                                               "here",       "expected `u32`, found `&str`", "first defined here",
    "x",
    "zpráva s diakritikou",
    "類型不匹配",
    "a much longer message that goes on for a while", "trailing  ",
    "🦀 crab",
};

fn pick(r: std.Random, comptime T: type, xs: []const T) T {
    return xs[r.uintLessThan(usize, xs.len)];
}

fn genText(r: std.Random, arena: std.mem.Allocator) ![]const u8 {
    var t: std.ArrayList(u8) = .empty;
    const nlines = r.intRangeAtMost(usize, 1, 14);
    for (0..nlines) |i| {
        const natoms = if (r.uintLessThan(u8, 6) == 0) 0 else r.intRangeAtMost(usize, 1, 24);
        for (0..natoms) |_| try t.appendSlice(arena, pick(r, []const u8, &atoms));
        if (i + 1 < nlines or r.boolean()) try t.appendSlice(arena, pick(r, []const u8, &newlines));
    }
    return t.items;
}

/// Byte offsets at char boundaries of `text`, including `text.len`, except the
/// one between the `\r` and the `\n` of a CRLF (see the header).
fn boundaries(arena: std.mem.Allocator, text: []const u8) ![]usize {
    var v: std.ArrayList(usize) = .empty;
    var i: usize = 0;
    while (i < text.len) {
        if (!(i > 0 and text[i - 1] == '\r' and text[i] == '\n')) try v.append(arena, i);
        i += std.unicode.utf8ByteSequenceLength(text[i]) catch unreachable;
    }
    try v.append(arena, text.len);
    return v.items;
}

fn genLabel(r: std.Random, files: []const File, bounds: []const []const usize, primary: bool) Lab {
    const fi = r.uintLessThan(usize, files.len);
    const b = bounds[fi];
    const a = r.uintLessThan(usize, b.len);
    // Mostly short spans; sometimes empty, sometimes long (several lines), now and then to the end.
    const len: usize = switch (r.uintLessThan(u8, 10)) {
        0 => 0,
        1, 2 => r.uintLessThan(usize, b.len - a),
        3 => b.len - 1 - a,
        else => @min(r.intRangeAtMost(usize, 1, 6), b.len - 1 - a),
    };
    return .{ .primary = primary, .file = fi, .start = b[a], .end = b[a + len], .msg = pick(r, []const u8, &messages) };
}

fn genCase(arena: std.mem.Allocator, id: u64) !Case {
    var prng = std.Random.DefaultPrng.init(id *% 0x9e37_79b9_7f4a_7c15);
    const r = prng.random();
    const nfiles = r.intRangeAtMost(usize, 1, 2);
    const files = try arena.alloc(File, nfiles);
    const bounds = try arena.alloc([]const usize, nfiles);
    for (files, bounds, 0..) |*f, *b, i| {
        f.* = .{ .name = if (i == 0) "src/main.rs" else "lib/other.txt", .text = try genText(r, arena) };
        b.* = try boundaries(arena, f.text);
    }
    const diags = try arena.alloc(Diag, r.intRangeAtMost(usize, 1, 2));
    for (diags) |*d| {
        const labels = try arena.alloc(Lab, r.uintLessThan(usize, 5));
        for (labels, 0..) |*l, i| l.* = genLabel(r, files, bounds, if (i == 0) r.uintLessThan(u8, 8) != 0 else r.uintLessThan(u8, 6) == 0);
        const notes = try arena.alloc([]const u8, r.uintLessThan(usize, 3));
        for (notes) |*n| n.* = pick(r, []const u8, messages[1..]);
        d.* = .{
            .sev = pick(r, dg.Severity, &.{ .@"error", .warning, .info }),
            .code = if (r.boolean()) "" else pick(r, []const u8, &.{ "E0308", "W1", "lint::x" }),
            .msg = pick(r, []const u8, &messages),
            .labels = labels,
            .notes = notes,
        };
    }
    const dflt = [4]u32{ 3, 1, 0, 0 };
    var ctx: [4]u32 = undefined;
    for (&ctx, dflt) |*c, d| c.* = if (r.boolean()) d else r.uintLessThan(u32, 4);
    return .{ .id = id, .ctx = ctx, .files = files, .diags = diags };
}

// ── the cases file the oracle reads ──────────────────────────────────────────

fn hex(w: *std.Io.Writer, s: []const u8) !void {
    if (s.len == 0) return w.writeByte('-');
    for (s) |c| try w.print("{x:0>2}", .{c});
}

fn writeCase(w: *std.Io.Writer, c: Case) !void {
    try w.print("case {d}\ncfg {d} {d} {d} {d}\n", .{ c.id, c.ctx[0], c.ctx[1], c.ctx[2], c.ctx[3] });
    for (c.files) |f| {
        try w.writeAll("file ");
        try hex(w, f.name);
        try w.writeByte(' ');
        try hex(w, f.text);
        try w.writeByte('\n');
    }
    for (c.diags) |d| {
        try w.print("diag {s} ", .{switch (d.sev) {
            .@"error" => "e",
            .warning => "w",
            else => "n",
        }});
        try hex(w, d.code);
        try w.writeByte(' ');
        try hex(w, d.msg);
        try w.writeByte('\n');
        for (d.labels) |l| {
            try w.print("label {s} {d} {d} {d} ", .{ if (l.primary) "p" else "s", l.file, l.start, l.end });
            try hex(w, l.msg);
            try w.writeByte('\n');
        }
        for (d.notes) |n| {
            try w.writeAll("note ");
            try hex(w, n);
            try w.writeByte('\n');
        }
    }
    try w.writeAll("end\n");
}

// ── our side (the mapping of src/codespan_test.zig) ──────────────────────────

/// 1-based line and byte column of a byte offset.
fn at(text: []const u8, off: usize) struct { line: u32, col: u32 } {
    const line: u32 = @intCast(std.mem.count(u8, text[0..off], "\n") + 1);
    const ls = if (std.mem.findScalarLast(u8, text[0..off], '\n')) |nl| nl + 1 else 0;
    return .{ .line = line, .col = @intCast(off - ls + 1) };
}

fn convert(arena: std.mem.Allocator, files: []const File, cd: Diag) !dg.Diagnostic {
    var d: dg.Diagnostic = .{ .path = "", .severity = cd.sev, .code = cd.code, .message = cd.msg };
    var labels: std.ArrayList(dg.Label) = .empty;
    // The primary span is the first label when that one is primary; otherwise every label stays in
    // `labels` (with its `primary` flag), so the order codespan groups files by is kept.
    var have_primary = cd.labels.len == 0 or !cd.labels[0].primary;
    for (cd.labels) |l| {
        const text = files[l.file].text;
        const a = at(text, l.start);
        const b = at(text, l.end);
        if (l.primary and !have_primary) {
            have_primary = true;
            d.file = files[l.file].name;
            d.line = a.line;
            d.col = a.col;
            d.end_line = b.line;
            d.end_col = b.col;
            d.span_message = l.msg;
        } else try labels.append(arena, .{
            .file = files[l.file].name,
            .line = a.line,
            .col = a.col,
            .end_line = b.line,
            .end_col = b.col,
            .message = l.msg,
            .primary = l.primary,
        });
    }
    if (labels.items.len > 0) d.labels = labels.items;
    if (cd.notes.len > 0) {
        const notes = try arena.alloc(dg.Note, cd.notes.len);
        for (cd.notes, notes) |n, *o| o.* = .{ .kind = .plain, .message = n };
        d.notes = notes;
    }
    return d;
}

fn renderOurs(arena: std.mem.Allocator, c: Case, chars: dg.CharSet) ![]const u8 {
    const sources = try arena.alloc(dg.Source, c.files.len);
    for (c.files, sources) |f, *s| s.* = .{ .file = f.name, .text = f.text };
    var out: std.Io.Writer.Allocating = .init(arena);
    for (c.diags) |cd| try dg.renderOne(&out.writer, try convert(arena, c.files, cd), .{
        .style = .snippet,
        .sources = sources,
        .start_context_lines = c.ctx[0],
        .end_context_lines = c.ctx[1],
        .before_label_lines = c.ctx[2],
        .after_label_lines = c.ctx[3],
        .chars = chars,
        .column = .char,
    });
    return out.written();
}

// ── where codespan's output is not defined ──────────────────────────────────

/// True when a diagnostic has three or more single-line labels over the same
/// range of one line. codespan places each label with `slice::binary_search_by`
/// and inserts at the index it returns; for equal elements that index is
/// unspecified ("any one of the matches could be returned", Rust docs), so their
/// order is whatever the Rust standard library of the day does. Two equal labels
/// come out the same either way (reverse of the order given, which is ours).
fn unspecifiedOrder(c: Case) bool {
    for (c.diags) |d| {
        for (d.labels, 0..) |a, i| {
            var same: usize = 1;
            for (d.labels[i + 1 ..]) |b| {
                if (sameSingleRange(c.files, a, b)) same += 1;
            }
            if (same >= 3 and singleLine(c.files[a.file].text, a)) return true;
        }
    }
    return false;
}

fn singleLine(text: []const u8, l: Lab) bool {
    return std.mem.count(u8, text[0..l.start], "\n") == std.mem.count(u8, text[0..l.end], "\n");
}

fn sameSingleRange(files: []const File, a: Lab, b: Lab) bool {
    const t = files[a.file].text;
    return a.file == b.file and singleLine(t, a) and singleLine(t, b) and a.start == b.start and
        @max(a.end, a.start + 1) == @max(b.end, b.start + 1);
}

// ── reach ────────────────────────────────────────────────────────────────────

const Reach = struct {
    multi_line: u64 = 0,
    overlapping_multi: u64 = 0,
    empty: u64 = 0,
    at_eof: u64 = 0,
    two_files: u64 = 0,
    secondary_first: u64 = 0,
    same_line_pair: u64 = 0,
    crlf_file: u64 = 0,
    wide: u64 = 0,
    context_changed: u64 = 0,

    fn add(r: *Reach, c: Case) void {
        for (c.files) |f| {
            if (std.mem.find(u8, f.text, "\r\n") != null) r.crlf_file += 1;
            if (std.mem.find(u8, f.text, "中") != null or std.mem.find(u8, f.text, "🦀") != null) r.wide += 1;
        }
        if (c.ctx[0] != 3 or c.ctx[1] != 1 or c.ctx[2] != 0 or c.ctx[3] != 0) r.context_changed += 1;
        for (c.diags) |d| {
            var nmulti: usize = 0;
            for (d.labels, 0..) |l, i| {
                const t = c.files[l.file].text;
                if (!singleLine(t, l)) nmulti += 1;
                if (l.start == l.end) r.empty += 1;
                if (l.end == t.len) r.at_eof += 1;
                if (l.file != d.labels[0].file) r.two_files += 1;
                for (d.labels[i + 1 ..]) |m| {
                    if (m.file == l.file and singleLine(t, l) and singleLine(t, m) and
                        std.mem.count(u8, t[0..l.start], "\n") == std.mem.count(u8, t[0..m.start], "\n")) r.same_line_pair += 1;
                }
            }
            r.multi_line += nmulti;
            if (nmulti >= 2) r.overlapping_multi += 1;
            if (d.labels.len > 1 and !d.labels[0].primary) r.secondary_first += 1;
        }
    }
};

// ── the lead (the card's **Ahead:** line) ────────────────────────────────────

/// Terminal-control characters a hostile key name carries into a finding: ESC
/// (an OSC title change and a screen clear), BEL, and the bidi override U+202E
/// of "Trojan Source" (CVE-2021-42574).
const hostile_key = "key\x1b]0;pwned\x07\x1b[2J\u{202e}";
const raw_controls = [_][]const u8{ "\x1b", "\x07", "\u{202e}" };

/// `--lead`: one finding quoting `hostile_key` in the source, the message, a
/// label and a note, rendered by codespan and by us; counts the raw control
/// characters that reach the output. Ours must be 0, codespan's is the lead.
fn lead(arena: std.mem.Allocator, io: std.Io, exe: []const u8, abs: []const u8) !u8 {
    const src = "{\"" ++ hostile_key ++ "\": 1}\n";
    const labels = [_]Lab{.{ .primary = true, .file = 0, .start = 1, .end = 1 + hostile_key.len + 2, .msg = "unknown " ++ hostile_key }};
    const notes = [_][]const u8{"did you mean " ++ hostile_key ++ "?"};
    const diags = [_]Diag{.{ .sev = .@"error", .code = "", .msg = "unknown key '" ++ hostile_key ++ "'", .labels = &labels, .notes = &notes }};
    const files = [_]File{.{ .name = "f.json", .text = src }};
    const c: Case = .{ .id = 0, .ctx = .{ 3, 1, 0, 0 }, .files = &files, .diags = &diags };
    var file: std.Io.Writer.Allocating = .init(arena);
    try writeCase(&file.writer, c);
    const cwd = std.Io.Dir.cwd();
    const cases_path = try arena.print("{s}/lead.txt", .{abs});
    const out_path = try arena.print("{s}/lead.out", .{abs});
    try cwd.writeFile(io, .{ .sub_path = cases_path, .data = file.written() });
    const ran = try std.process.run(arena, io, .{ .argv = &.{ exe, cases_path, out_path } });
    if (ran.term != .exited or ran.term.exited != 0) return 1;
    const theirs_all = try cwd.readFileAlloc(io, out_path, arena, .limited(1 << 20));
    var pos: usize = 0;
    const theirs = try nextRecord(theirs_all, &pos, 0, .ascii);
    const ours = try renderOurs(arena, c, .ascii);
    var ours_n: usize = 0;
    var theirs_n: usize = 0;
    for (raw_controls) |r| {
        ours_n += std.mem.count(u8, ours, r);
        theirs_n += std.mem.count(u8, theirs.text, r);
    }
    std.debug.print("lead: raw ESC/BEL/U+202E in the output -- codespan-reporting 0.13.1: {d}, ours: {d}\n", .{ theirs_n, ours_n });
    return if (ours_n == 0 and theirs_n > 0) 0 else 1;
}

// ── driver ───────────────────────────────────────────────────────────────────

const Theirs = struct { panicked: bool, text: []const u8 };

/// Reads one `<id> <charset> ok|panic <len>\n<bytes>\n` record.
fn nextRecord(data: []const u8, pos: *usize, id: u64, chars: dg.CharSet) !Theirs {
    const nl = std.mem.findScalarPos(u8, data, pos.*, '\n') orelse return error.OracleOutputTruncated;
    var f = std.mem.splitScalar(u8, data[pos.*..nl], ' ');
    const rid = try std.fmt.parseInt(u64, f.next().?, 10);
    const rch = f.next().?;
    const kind = f.next().?;
    const len = try std.fmt.parseInt(usize, f.next().?, 10);
    if (rid != id or !std.mem.eql(u8, rch, @tagName(chars))) return error.OracleOutputOutOfStep;
    const text = data[nl + 1 ..][0..len];
    pos.* = nl + 1 + len + 1;
    return .{ .panicked = std.mem.eql(u8, kind, "panic"), .text = text };
}

fn buildOracle(arena: std.mem.Allocator, io: std.Io, env_in: *const std.process.Environ.Map, abs: []const u8) ![]const u8 {
    var env = try env_in.clone(arena);
    const target = try arena.print("{s}/target", .{abs});
    try env.put("CARGO_TARGET_DIR", target);
    const built = std.process.run(arena, io, .{
        .argv = &.{ "cargo", "build", "--release", "--locked", "--offline", "--quiet", "--bin", "oracle", "--manifest-path", cargo_manifest },
        .environ_map = &env,
    }) catch |e| {
        std.debug.print("interop-diagnostics: could not run cargo ({t}) -- the oracle needs it\n", .{e});
        return error.NoCargo;
    };
    if (built.term != .exited or built.term.exited != 0) {
        std.debug.print("interop-diagnostics: cargo build failed:\n{s}\n", .{built.stderr});
        return error.CargoFailed;
    }
    return arena.print("{s}/release/oracle", .{target});
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    var from: u64 = 1;
    var seeds: u64 = 20_000;
    var replay: ?u64 = null;
    var lead_only = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const val = if (i + 1 < args.len) args[i + 1] else "";
        if (std.mem.eql(u8, a, "--seeds")) {
            seeds = try std.fmt.parseInt(u64, val, 10);
        } else if (std.mem.eql(u8, a, "--from")) {
            from = try std.fmt.parseInt(u64, val, 10);
        } else if (std.mem.eql(u8, a, "--seed")) {
            replay = try std.fmt.parseInt(u64, val, 10);
        } else if (std.mem.eql(u8, a, "--lead")) {
            lead_only = true;
            continue;
        } else {
            std.debug.print("usage: interop-diagnostics [--seeds N] [--from S] [--seed S] [--lead]\n", .{});
            return 2;
        }
        i += 1;
    }
    if (replay) |s| {
        from = s;
        seeds = 1;
    }

    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, scratch);
    const abs = try cwd.realPathFileAlloc(io, scratch, arena);
    const exe = buildOracle(arena, io, init.environ_map, abs) catch return 1;
    if (lead_only) return lead(arena, io, exe, abs);

    // Our side renders while the cases file is written; the oracle then renders all of them in one run.
    const cases = try arena.alloc(Case, seeds);
    var file: std.Io.Writer.Allocating = .init(arena);
    for (cases, 0..) |*c, k| {
        c.* = try genCase(arena, from + k);
        try writeCase(&file.writer, c.*);
    }
    const cases_path = try arena.print("{s}/cases.txt", .{abs});
    const out_path = try arena.print("{s}/codespan.out", .{abs});
    try cwd.writeFile(io, .{ .sub_path = cases_path, .data = file.written() });
    const ran = try std.process.run(arena, io, .{ .argv = &.{ exe, cases_path, out_path } });
    if (ran.term != .exited or ran.term.exited != 0) {
        std.debug.print("interop-diagnostics: the oracle failed:\n{s}\n", .{ran.stderr});
        return 1;
    }
    const theirs = try cwd.readFileAlloc(io, out_path, arena, .limited(1 << 30));

    var pos: usize = 0;
    var same: u64 = 0;
    var differ: u64 = 0;
    var panicked: u64 = 0;
    var unspecified: u64 = 0;
    var first_bad: ?u64 = null;
    var reach: Reach = .{};
    for (cases) |c| {
        reach.add(c);
        var scratch_arena = std.heap.ArenaAllocator.init(std.heap.smp_allocator);
        defer scratch_arena.deinit();
        for ([_]dg.CharSet{ .ascii, .unicode }) |chars| {
            const t = try nextRecord(theirs, &pos, c.id, chars);
            const mine = try renderOurs(scratch_arena.allocator(), c, chars);
            if (t.panicked) {
                panicked += 1;
            } else if (unspecifiedOrder(c)) {
                unspecified += 1;
            } else if (std.mem.eql(u8, mine, t.text)) {
                same += 1;
            } else {
                differ += 1;
                if (first_bad == null) first_bad = c.id;
                if (differ <= 10) std.debug.print("DIFF seed={d} {t}: first difference at byte {d} (ours {d} bytes, codespan {d})\n", .{
                    c.id, chars, std.mem.findDiff(u8, mine, t.text) orelse @min(mine.len, t.text.len), mine.len, t.text.len,
                });
            }
            if (replay != null) std.debug.print("── {t} ── ours:\n{s}\n── codespan{s}:\n{s}\n", .{ chars, mine, if (t.panicked) " (PANICKED)" else "", t.text });
        }
    }
    std.debug.print("interop-diagnostics: seeds {d}..{d}: {d} renders byte-identical, {d} differ, {d} where codespan panicked, {d} not compared (label order unspecified in codespan)\n", .{ from, from + seeds - 1, same, differ, panicked, unspecified });
    std.debug.print("reach: {d} multi-line labels, {d} diagnostics with 2+ of them, {d} empty spans, {d} spans to end of file, {d} labels in a second file, {d} diagnostics led by a secondary, {d} same-line label pairs, {d} CRLF files, {d} files with wide characters, {d} cases with non-default context lines\n", .{
        reach.multi_line, reach.overlapping_multi, reach.empty, reach.at_eof, reach.two_files, reach.secondary_first, reach.same_line_pair, reach.crlf_file, reach.wide, reach.context_changed,
    });
    if (first_bad) |s| std.debug.print("replay: zig build interop-diagnostics -- --seed {d}\n", .{s});
    return if (differ == 0) 0 else 1;
}
