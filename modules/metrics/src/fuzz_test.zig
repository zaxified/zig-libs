// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver and harnesses for `metrics` (added 2026-11-21).
//!
//! Driver: `METRICS_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `METRICS_FUZZ_ONLY=<substring>` selects a harness by name, `_MS`,
//! `_SEEDFILE`, `_INPUT` as documented there). Harness names:
//! `metrics-negotiate`, `metrics-wire`, `metrics-registry`, `metrics-collector`,
//! `metrics-numeric`, `metrics-process`.
//!
//! Every harness is generic over its source of choices, `fn(comptime S, *S,
//! gpa)`. Its FIRST draw is one faithful block of bytes (`fill`); every later
//! choice is decoded from those bytes by `Dec`, so a `Smith` corpus entry and
//! a driver seed mean the same thing and no ranged draw collapses to its
//! minimum.
//!
//! What the harnesses judge (not only "no panic"): a scrape that succeeds is
//! parsed back by an independent strict checker (`Check`: UTF-8, HELP/TYPE
//! lines, sample grammar and escapes, no duplicate sample, family grouping,
//! cumulative buckets, OpenMetrics `# EOF` and exemplar rules, no exemplar in
//! the text format); two scrapes of an unchanged registry are byte-identical;
//! a label value the registry accepted is found, escaped, in the exposition.

const std = @import("std");
const testing = std.testing;
const builtin = @import("builtin");
const testkit = @import("testkit");
const clock_lib = @import("clock");
const router = @import("router");
const http = @import("http");
const metrics = @import("root.zig");

const fuzz_driver = testkit.fuzz.driver;
const Rng = fuzz_driver.Rng;
const hit = fuzz_driver.hit;

// ── input decoding ──────────────────────────────────────────────────────────

/// One harness input into `buf`; returns its length. Faithful under both
/// sources (`slice` under `Smith`, a full random block under the driver).
fn fill(comptime S: type, src: *S, buf: []u8) usize {
    if (S == Rng) {
        src.bytes(buf);
        return buf.len;
    }
    return src.slice(buf);
}

/// A cursor over the drawn bytes; past the end every read is 0.
const Dec = struct {
    b: []const u8,
    at: usize = 0,

    fn byte(d: *Dec) u8 {
        if (d.at >= d.b.len) return 0;
        defer d.at += 1;
        return d.b[d.at];
    }
    fn below(d: *Dec, n: usize) usize {
        return d.byte() % n;
    }
    fn u16le(d: *Dec) u16 {
        const lo: u16 = d.byte();
        return lo | @as(u16, d.byte()) << 8;
    }
    fn u64le(d: *Dec) u64 {
        var v: u64 = 0;
        for (0..8) |i| v |= @as(u64, d.byte()) << @intCast(8 * i);
        return v;
    }
    fn chunk(d: *Dec, n: usize) []const u8 {
        const e = @min(d.at + n, d.b.len);
        defer d.at = e;
        return d.b[@min(d.at, e)..e];
    }

    /// A string of up to `out.len` bytes: vocabulary tokens, raw chunks and
    /// (rarely) a long run, so names, escapes and the length limits are all
    /// reached.
    fn str(d: *Dec, out: []u8, vocab: []const []const u8) []const u8 {
        var n: usize = 0;
        const segs = d.below(7);
        for (0..segs) |_| {
            const tag = d.byte();
            if (tag >= 250) {
                const k = @min(d.u16le() % (out.len + 1), out.len - n);
                @memset(out[n..][0..k], 'q');
                n += k;
                continue;
            }
            const piece: []const u8 = if (tag < 140) vocab[tag % vocab.len] else d.chunk(1 + tag % 8);
            const k = @min(piece.len, out.len - n);
            @memcpy(out[n..][0..k], piece[0..k]);
            n += k;
        }
        return out[0..n];
    }

    /// `str` with every byte forced into printable ASCII (a header value
    /// the HTTP parser lets through).
    fn strAscii(d: *Dec, out: []u8, vocab: []const []const u8) []u8 {
        const t = d.str(out, vocab);
        const m = out[0..t.len];
        for (m) |*b| if (b.* < 0x20 or b.* > 0x7e) {
            b.* = 0x20 + b.* % 0x5f;
        };
        return m;
    }

    /// An Accept header: mostly well-formed clauses (type, version, q), so
    /// both formats and every tie-break are reached; sometimes raw damage.
    /// The clauses drawn are left in `cl` (`n` of them, 0 for raw damage), so
    /// `fuzzNegotiate` can judge the answer against a model.
    fn accept(d: *Dec, out: []u8, cl: *[4]Clause, n: *usize) []const u8 {
        n.* = 0;
        if (d.byte() < 70) return d.strAscii(out, &accept_vocab);
        var w: std.Io.Writer = .fixed(out);
        for (0..1 + d.below(4)) |i| {
            if (i != 0) w.writeAll(if (d.byte() < 200) "," else ", ") catch break;
            const c: Clause = .{ .ty = d.below(a_types.len), .ver = d.below(a_versions.len), .q = d.below(a_qs.len) };
            w.print("{s}{s}{s}", .{ a_types[c.ty], a_versions[c.ver], a_qs[c.q] }) catch break;
            cl[n.*] = c;
            n.* += 1;
        }
        return w.buffered();
    }

    fn f64v(d: *Dec) f64 {
        const specials = [_]f64{
            0,                      -0.0,                    1,                          -1,     0.5,   std.math.nan(f64),  std.math.inf(f64), -std.math.inf(f64),
            std.math.floatMax(f64), -std.math.floatMax(f64), std.math.floatMin(f64) / 4, 1e-300, 1e300, 9007199254740993.0, 1.7e9,
        };
        return switch (d.byte() % 4) {
            0 => specials[d.below(specials.len)],
            1 => @bitCast(d.u64le()),
            2 => @floatFromInt(@as(i16, @bitCast(d.u16le()))),
            else => @as(f64, @floatFromInt(d.u16le())) / 64.0,
        };
    }
};

const Clause = struct { ty: usize, ver: usize, q: usize };
const a_types = [_][]const u8{ "application/openmetrics-text", "text/plain", "*/*", "text/*", "application/*", "application/json", "TEXT/PLAIN", "Application/OpenMetrics-Text" };
const a_versions = [_][]const u8{ "", ";version=1.0.0", ";version=0.0.1", ";version=0.0.4", ";version=2", ";version=\"1.0.0\"", ";charset=utf-8", ";escaping=underscores" };
const a_qs = [_][]const u8{ "", ";q=1", ";q=0.5", ";q=0", ";q=0.001", ";q=0.9", ";q=1.0", ";q=x", ";Q=0.2" };
const q_milli = [_]u16{ 1000, 1000, 500, 0, 1, 900, 1000, 0, 0 };

/// The expected answer for well-formed clauses, derived from `negotiate`'s
/// documented rule (prometheus/common `NegotiateIncludingOpenMetrics`):
/// clauses by descending q, ties a concrete type before `*`, the first that
/// matches OpenMetrics 1.0.0 / 0.0.1 or text 0.0.4 wins, q=0 skipped, nothing
/// matching: text. `null` when a clause is one the model does not judge.
fn modelNegotiate(cl: []const Clause) ?metrics.Format {
    var order: [4]Clause = undefined;
    for (cl, 0..) |c, i| {
        if (c.q == 7 or c.q == 8 or c.ver == 5) return null;
        order[i] = c;
    }
    const rank = struct {
        fn of(c: Clause) u8 {
            const t = a_types[c.ty];
            const slash = std.mem.findScalar(u8, t, '/').?;
            return @as(u8, @intFromBool(!std.mem.eql(u8, t[0..slash], "*"))) + @intFromBool(!std.mem.eql(u8, t[slash + 1 ..], "*"));
        }
    };
    // stable insertion sort, best first
    for (1..cl.len) |i| {
        var j = i;
        while (j > 0) : (j -= 1) {
            const a = order[j - 1];
            const b = order[j];
            const b_first = q_milli[b.q] > q_milli[a.q] or (q_milli[b.q] == q_milli[a.q] and rank.of(b) > rank.of(a));
            if (!b_first) break;
            order[j - 1] = b;
            order[j] = a;
        }
    }
    for (order[0..cl.len]) |c| {
        if (q_milli[c.q] == 0) continue;
        const t = a_types[c.ty];
        const slash = std.mem.findScalar(u8, t, '/').?;
        const ty = t[0..slash];
        const sub = t[slash + 1 ..];
        const explicit: ?[]const u8 = switch (c.ver) {
            1 => "1.0.0",
            2 => "0.0.1",
            3 => "0.0.4",
            4 => "2",
            else => null,
        };
        const offers = [_]struct { []const u8, []const u8, []const u8, metrics.Format }{
            .{ "application", "openmetrics-text", "1.0.0", .openmetrics },
            .{ "application", "openmetrics-text", "0.0.1", .openmetrics },
            .{ "text", "plain", "0.0.4", .text },
        };
        for (offers) |o| {
            const ty_ok = std.mem.eql(u8, ty, "*") or std.ascii.eqlIgnoreCase(ty, o[0]);
            const sub_ok = std.mem.eql(u8, sub, "*") or std.ascii.eqlIgnoreCase(sub, o[1]);
            if (!ty_ok or !sub_ok) continue;
            const exact = std.ascii.eqlIgnoreCase(ty, o[0]) and std.ascii.eqlIgnoreCase(sub, o[1]);
            // A missing version means 0.0.1 for OpenMetrics, 0.0.4 for text,
            // and only on the exact type.
            const dflt: []const u8 = if (std.mem.eql(u8, o[1], "plain")) "0.0.4" else "0.0.1";
            const eff = explicit orelse (if (exact) dflt else "");
            if (std.mem.eql(u8, eff, o[2])) return o[3];
        }
    }
    return .text;
}

const accept_vocab = [_][]const u8{
    "application/openmetrics-text", "text/plain",     "*/*", "application/*", "text/*",                                           ";version=1.0.0",
    ";version=0.0.1",               ";version=0.0.4", ";q=", ";q=0",          ";q=0.5",                                           ";q=1",
    ",",                            " ",              ";",   "=",             "\"",                                               ";escaping=underscores",
    ";charset=utf-8",               "1",              "0.",  "999999",        "application/json",                                 "version=1.0.0",
    "q=0.001",                      ";q=1.0000",      "\t",  "/",             "openmetrics-text",                                 "application/openmetrics-text; version=1.0.0",
    "text/plain;version=0.0.4",     "q",              "\\",  ",,",            "application/openmetrics-text;version=0.0.1;q=0.2",
};
const label_vocab = [_][]const u8{
    "\\",           "\"",               "\n",   "\r",  "\xc3\xa9", "\xff", "\xc0\x80", "\xf0\x9f\x98\x80", "\xed\xa0\x80", "{",
    "}",            "#",                " ",    "=",   ",",        "a",    "_",        "\x00",             "\\n",          "\\\"",
    "\xe2\x80\xa8", "\xf4\x90\x80\x80", "+Inf", "NaN", "# EOF",    "\\\\", "le",       "quantile",
};
const name_vocab = [_][]const u8{
    "http_requests_total", "a",    "_",        ":",   "x_total", "le", "quantile", "__",     "9", "-",   "_bucket", "_sum",
    "_count",              "name", "\xc3\xa9", "a:b", "code",    "A",  "z9_",      "x_info", "y", "__x", "m_total", " ",
};
const label_ok_vocab = [_][]const u8{ "\\", "\"", "\n", "\xc3\xa9", "\xf0\x9f\x98\x80", "{", "}", "#", " ", "=", ",", "a", "_", "\\n", "\xe2\x80\xa8", "+Inf", "NaN", "# EOF" };
const pool_names = [_][]const u8{ "fz_a_total", "fz_b", "fz_c_seconds", "fz_d", "fz_e_total", "fz_f" };
const pool_labels = [_][]const u8{ "a", "b", "method", "code_x", "p", "q" };

// ── the independent exposition checker ──────────────────────────────────────

const Bad = error{
    BadUtf8,
    BadLine,
    BadName,
    BadLabel,
    BadValue,
    BadEscape,
    Duplicate,
    NoEof,
    Family,
    Buckets,
    BadTrailer,
    Exemplar,
    NoNewline,
    OutOfMemory,
};

const Pair = struct { name: []const u8, value: []const u8 };

fn nameOk(s: []const u8, colon: bool) bool {
    if (s.len == 0) return false;
    for (s, 0..) |c, i| {
        const ok = std.ascii.isAlphabetic(c) or c == '_' or (colon and c == ':') or (i > 0 and std.ascii.isDigit(c));
        if (!ok) return false;
    }
    return true;
}

fn numberOk(tok: []const u8) bool {
    if (std.mem.eql(u8, tok, "+Inf") or std.mem.eql(u8, tok, "-Inf") or std.mem.eql(u8, tok, "NaN")) return true;
    if (tok.len == 0) return false;
    for (tok) |c| if (std.mem.findScalar(u8, "0123456789+-.eE", c) == null) return false;
    _ = std.fmt.parseFloat(f64, tok) catch return false;
    return true;
}

/// Runes of one exemplar label block, as `renderExemplarLabels` counts them
/// (name bytes, then the value's code points; an escape is one rune).
fn runesOf(pairs: []const Pair) usize {
    var n: usize = 0;
    for (pairs) |p| {
        n += p.name.len;
        var i: usize = 0;
        while (i < p.value.len) : (i += 1) {
            if (p.value[i] == '\\') {
                i += 1; // an escape is one rune
                n += 1;
            } else if ((p.value[i] & 0xC0) != 0x80) n += 1;
        }
    }
    return n;
}

const Check = struct {
    gpa: std.mem.Allocator,
    om: bool,
    /// Retained as an option, but no harness sets it any more: `Sink` refuses
    /// a repeated label-value tuple (`error.DuplicateSample`), so a scrape
    /// that succeeds never carries one.
    dups_ok: bool = false,
    seen: std.StringHashMapUnmanaged(void) = .empty,
    typed: std.StringHashMapUnmanaged(void) = .empty,
    family: []const u8 = "",
    family_kind: []const u8 = "",
    prev_series: u64 = 0,
    prev_count: u64 = 0,
    /// The last bucket line was `le="+Inf"`: the series ended there.
    prev_inf: bool = false,
    eof: bool = false,

    fn deinit(c: *Check) void {
        c.seen.deinit(c.gpa);
        c.typed.deinit(c.gpa);
    }

    fn run(c: *Check, text: []const u8) Bad!void {
        if (!std.unicode.utf8ValidateSlice(text)) return error.BadUtf8;
        if (text.len == 0) {
            if (c.om) return error.NoEof;
            return;
        }
        if (text[text.len - 1] != '\n') return error.NoNewline;
        var lines = std.mem.splitScalar(u8, text[0 .. text.len - 1], '\n');
        while (lines.next()) |line| {
            if (c.eof) return error.BadTrailer;
            try c.oneLine(line);
        }
        if (c.om and !c.eof) return error.NoEof;
    }

    fn oneLine(c: *Check, line: []const u8) Bad!void {
        if (line.len == 0) return error.BadLine;
        if (line[0] == '#') {
            if (std.mem.eql(u8, line, "# EOF")) {
                if (!c.om) return error.BadTrailer;
                c.eof = true;
                return;
            }
            if (std.mem.startsWith(u8, line, "# HELP ")) return c.helpLine(line["# HELP ".len..]);
            if (std.mem.startsWith(u8, line, "# TYPE ")) return c.typeLine(line["# TYPE ".len..]);
            return error.BadLine;
        }
        return c.sample(line);
    }

    fn helpLine(c: *Check, rest: []const u8) Bad!void {
        const sp = std.mem.findScalar(u8, rest, ' ') orelse return error.BadLine;
        if (!nameOk(rest[0..sp], true)) return error.BadName;
        const text = rest[sp + 1 ..];
        var i: usize = 0;
        while (i < text.len) : (i += 1) {
            if (text[i] != '\\') continue;
            i += 1;
            if (i >= text.len) return error.BadEscape;
            switch (text[i]) {
                '\\', 'n' => {},
                '"' => if (!c.om) return error.BadEscape,
                else => return error.BadEscape,
            }
        }
    }

    fn typeLine(c: *Check, rest: []const u8) Bad!void {
        const sp = std.mem.findScalar(u8, rest, ' ') orelse return error.BadLine;
        const name = rest[0..sp];
        if (!nameOk(name, true)) return error.BadName;
        const kind = rest[sp + 1 ..];
        const known = [_][]const u8{ "counter", "gauge", "histogram", "summary", "unknown", "untyped" };
        var known_kind = false;
        for (known) |k| known_kind = known_kind or std.mem.eql(u8, k, kind);
        if (!known_kind) return error.BadLine;
        const gop = try c.typed.getOrPut(c.gpa, name);
        if (gop.found_existing) return error.Duplicate; // a repeated # TYPE fails the whole scrape
        // OpenMetrics announces a counter without its `_total` suffix.
        if (c.om and std.mem.eql(u8, kind, "counter") and std.mem.endsWith(u8, name, "_total")) return error.Family;
        c.family = name;
        c.family_kind = kind;
        c.prev_series = 0;
        c.prev_count = 0;
        c.prev_inf = false;
    }

    /// `{name="value",...}` from just after the `{`; index after the `}`.
    fn labels(line: []const u8, start: usize, out: []Pair, n: *usize) Bad!usize {
        var i = start;
        n.* = 0;
        if (i < line.len and line[i] == '}') return i + 1;
        while (true) {
            const ns = i;
            while (i < line.len and (std.ascii.isAlphanumeric(line[i]) or line[i] == '_')) i += 1;
            const name = line[ns..i];
            if (!nameOk(name, false)) return error.BadLabel;
            for (out[0..n.*]) |p| if (std.mem.eql(u8, p.name, name)) return error.Duplicate;
            if (i >= line.len or line[i] != '=') return error.BadLabel;
            i += 1;
            if (i >= line.len or line[i] != '"') return error.BadLabel;
            i += 1;
            const vs = i;
            while (i < line.len and line[i] != '"') {
                if (line[i] == '\\') {
                    i += 1;
                    if (i >= line.len) return error.BadEscape;
                    switch (line[i]) {
                        '\\', '"', 'n' => {},
                        else => return error.BadEscape,
                    }
                }
                i += 1;
            }
            if (i >= line.len) return error.BadLabel;
            if (n.* == out.len) return error.BadLabel;
            out[n.*] = .{ .name = name, .value = line[vs..i] };
            n.* += 1;
            i += 1;
            if (i < line.len and line[i] == ',') {
                i += 1;
                continue;
            }
            if (i < line.len and line[i] == '}') return i + 1;
            return error.BadLabel;
        }
    }

    fn token(line: []const u8, i: *usize) []const u8 {
        const s = i.*;
        while (i.* < line.len and line[i.*] != ' ') i.* += 1;
        return line[s..i.*];
    }

    fn sample(c: *Check, line: []const u8) Bad!void {
        var i: usize = 0;
        while (i < line.len and (std.ascii.isAlphanumeric(line[i]) or line[i] == '_' or line[i] == ':')) i += 1;
        const name = line[0..i];
        if (!nameOk(name, true)) return error.BadName;
        if (c.family.len == 0 or !std.mem.startsWith(u8, name, c.family)) return error.Family;
        // ... and its samples carry it (a counter without one is typed `unknown`).
        if (c.om and std.mem.eql(u8, c.family_kind, "counter") and !std.mem.endsWith(u8, name, "_total") and !std.mem.endsWith(u8, name, "_created")) return error.Family;
        var pairs: [24]Pair = undefined;
        var np: usize = 0;
        if (i < line.len and line[i] == '{') i = try labels(line, i + 1, &pairs, &np);
        const series_end = i;
        if (i >= line.len or line[i] != ' ') return error.BadLine;
        i += 1;
        const value = token(line, &i);
        if (!numberOk(value)) return error.BadValue;

        const gop = try c.seen.getOrPut(c.gpa, line[0..series_end]);
        if (gop.found_existing and !c.dups_ok) return error.Duplicate;

        // cumulative buckets of one series, in order
        if (std.mem.endsWith(u8, name, "_bucket") and std.mem.eql(u8, c.family_kind, "histogram")) {
            var h = std.hash.Wyhash.init(0);
            h.update(name);
            var has_le = false;
            for (pairs[0..np]) |p| {
                if (std.mem.eql(u8, p.name, "le")) {
                    has_le = true;
                    continue;
                }
                h.update(p.name);
                h.update(p.value);
            }
            if (!has_le) return error.Buckets;
            const key = h.final();
            const cnt = std.fmt.parseInt(u64, value, 10) catch return error.Buckets;
            // (a repeated series, from a collector, restarts after its +Inf)
            if (c.prev_series == key and !c.prev_inf and cnt < c.prev_count) return error.Buckets;
            c.prev_series = key;
            c.prev_count = cnt;
            c.prev_inf = false;
            for (pairs[0..np]) |p| if (std.mem.eql(u8, p.name, "le") and std.mem.eql(u8, p.value, "+Inf")) {
                c.prev_inf = true;
            };
        }

        if (i < line.len) {
            i += 1; // the space
            if (i < line.len and line[i] != '#') {
                const ts = token(line, &i);
                if (!numberOk(ts)) return error.BadValue;
                if (!c.om and std.mem.findAny(u8, ts, ".eE") != null) return error.BadValue;
                if (i < line.len) i += 1;
            }
            if (i < line.len) {
                // exemplar: OpenMetrics only, on a counter sample or a bucket
                if (!c.om) return error.Exemplar;
                if (!std.mem.startsWith(u8, line[i..], "# {")) return error.Exemplar;
                // expfmt (the reference) writes an exemplar on any counter
                // sample, `_total` or not (then typed `unknown`), and
                // Prometheus' parser takes it; so does this checker.
                if (!(std.mem.endsWith(u8, name, "_total") or std.mem.endsWith(u8, name, "_bucket") or std.mem.eql(u8, c.family_kind, "unknown"))) return error.Exemplar;
                if (std.mem.eql(u8, c.family_kind, "unknown")) hit("exemplar-on-unknown");
                var ex: [24]Pair = undefined;
                var ne: usize = 0;
                i = try labels(line, i + 3, &ex, &ne);
                if (runesOf(ex[0..ne]) > metrics.max_exemplar_runes) return error.Exemplar;
                if (i >= line.len or line[i] != ' ') return error.Exemplar;
                i += 1;
                const ev = token(line, &i);
                if (!numberOk(ev)) return error.Exemplar;
                if (i < line.len) {
                    i += 1;
                    const ets = token(line, &i);
                    if (!numberOk(ets)) return error.Exemplar;
                }
                if (i != line.len) return error.Exemplar;
            }
        }
    }
};

/// Scrape `reg` in `format`; run the checker; scrape again and compare.
fn scrapeChecked(gpa: std.mem.Allocator, reg: *metrics.Registry, format: metrics.Format) !void {
    return scrapeCheckedOpt(gpa, reg, format, false, true);
}

fn scrapeCheckedOpt(gpa: std.mem.Allocator, reg: *metrics.Registry, format: metrics.Format, dups_ok: bool, stable: bool) !void {
    var a: std.Io.Writer.Allocating = .init(gpa);
    defer a.deinit();
    reg.write(&a.writer, format) catch |err| {
        hit("scrape-failed");
        return err;
    };
    const out = a.written();
    if (out.len > 16 << 20) return error.UnboundedExposition;
    var chk: Check = .{ .gpa = gpa, .om = format == .openmetrics, .dups_ok = dups_ok };
    defer chk.deinit();
    chk.run(out) catch |err| {
        std.debug.print("exposition rejected ({t}):\n{s}\n", .{ err, out });
        return err;
    };
    var b: std.Io.Writer.Allocating = .init(gpa);
    defer b.deinit();
    try reg.write(&b.writer, format);
    if (stable and !std.mem.eql(u8, out, b.written())) return error.ScrapesDiffer;
    if (format == .text) hit("scrape-text-ok") else hit("scrape-om-ok");
    if (out.len > 0) hit("scrape-nonempty");
}

// ── harness 1: Accept negotiation ───────────────────────────────────────────

fn containsIgnoreCase(hay: []const u8, needle: []const u8) bool {
    if (needle.len > hay.len) return false;
    for (0..hay.len - needle.len + 1) |i| if (std.ascii.eqlIgnoreCase(hay[i..][0..needle.len], needle)) return true;
    return false;
}

fn fuzzNegotiate(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    var raw: [1536]u8 = undefined;
    const n = fill(S, src, &raw);
    var d: Dec = .{ .b = raw[0..n] };
    var buf: [900]u8 = undefined;
    var cl: [4]Clause = undefined;
    var ncl: usize = 0;
    const accept = if (d.byte() < 40) d.chunk(900) else d.accept(&buf, &cl, &ncl);
    const f = metrics.Format.negotiate(accept);
    if (ncl != 0) if (modelNegotiate(cl[0..ncl])) |want| {
        if (want != f) {
            std.debug.print("Accept: {s}\nmodel {t}, negotiate {t}\n", .{ accept, want, f });
            return error.NegotiateDisagreesWithModel;
        }
        hit("negotiate-model-agrees");
    };
    if (f != metrics.Format.negotiate(accept)) return error.NotDeterministic;
    switch (f) {
        .text => hit("negotiate-text"),
        .openmetrics => hit("negotiate-om"),
    }
    if (accept.len == 0 and f != .text) return error.EmptyAcceptNotText;
    // The two content types are fixed strings, whatever the input was.
    const ct = f.contentType();
    if (!std.mem.startsWith(u8, ct, "text/plain; version=0.0.4") and !std.mem.startsWith(u8, ct, "application/openmetrics-text; version=1.0.0")) return error.BadContentType;
    // OpenMetrics only on an explicit offer of it: never from a text-only or
    // foreign Accept (every clause names another type).
    if (f == .openmetrics and !containsIgnoreCase(accept, "openmetrics-text") and std.mem.find(u8, accept, "*") == null) return error.OpenMetricsWithoutOffer;
}

// ── harness 2: the scrape endpoint on the wire ──────────────────────────────

fn hookOnRequest(_: ?*anyopaque, e: metrics.AccessEntry) void {
    hit("hook");
    std.mem.doNotOptimizeAway(e.path.len + e.status + (e.bytes orelse 0) + e.req.target.len);
}

fn okHandler(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

const method_vocab = [_][]const u8{ "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "BREW", "get", "G\x00T", "" };
const path_vocab = [_][]const u8{ "/metrics", "/metrics?x=1", "/metrics/", "/x", "/", "/metric", "*", "http://h/metrics", "%2fmetrics", "/metrics#f", "\xff", " " };
const hname_vocab = [_][]const u8{ "X-A", "Host", "Content-Length", "Connection", "Accept-Encoding", "Transfer-Encoding", "accept", "ACCEPT", "Expect", "Range" };

fn fuzzWire(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [2048]u8 = undefined;
    const n = fill(S, src, &raw);
    var d: Dec = .{ .b = raw[0..n] };

    var reg = metrics.Registry.init(gpa);
    defer reg.deinit();
    var rm = try metrics.RequestMetrics.init(&reg, .{
        .request_size_buckets = &.{ 100, 1000, 100000 },
        .response_size_buckets = &.{ 10, 1000 },
        .status = if (d.byte() & 1 == 0) .class else .code,
        .on_request = hookOnRequest,
    });
    const open_metrics = d.byte() < 230;
    var ep: metrics.Endpoint = .{
        .registry = &reg,
        .open_metrics = open_metrics,
        .max_in_flight = if (d.byte() % 5 == 0) @as(u32, @intCast(d.below(3))) else null,
    };
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(rm.middleware());
    try r.use(ep.middleware());
    try r.get("/x", okHandler);

    var req_buf: [3072]u8 = undefined;
    var w: std.Io.Writer = .fixed(&req_buf);
    var mbuf: [16]u8 = undefined;
    var tbuf: [64]u8 = undefined;
    const method: []const u8 = if (d.byte() < 200) "GET" else d.str(&mbuf, &method_vocab);
    const target: []const u8 = if (d.byte() < 150) "/metrics" else d.str(&tbuf, &path_vocab);
    var accept_buf: [600]u8 = undefined;
    var cl: [4]Clause = undefined;
    var ncl: usize = 0;
    const accept = d.accept(&accept_buf, &cl, &ncl);
    w.print("{s} {s} HTTP/1.1\r\nHost: t\r\nAccept: {s}\r\n", .{ method, target, accept }) catch {};
    for (0..d.below(4)) |_| {
        var nb: [40]u8 = undefined;
        var vb: [120]u8 = undefined;
        const hn: []const u8 = if (d.byte() < 220) hname_vocab[d.below(hname_vocab.len)] else d.strAscii(&nb, &hname_vocab);
        const hv = if (d.byte() < 200) d.strAscii(&vb, &accept_vocab) else d.str(&vb, &label_vocab);
        w.print("{s}: {s}\r\n", .{ hn, hv }) catch {};
    }
    if (d.byte() < 90) {
        // Peer-declared lengths: anywhere in u64, and right at its top, where
        // a request-size sum overflows.
        const cl_len: u64 = if (d.byte() < 128) d.u64le() else std.math.maxInt(u64) - d.below(400);
        w.print("Content-Length: {d}\r\n", .{cl_len}) catch {};
    }
    w.writeAll("Connection: close\r\n\r\n") catch {};

    var in: std.Io.Reader = .fixed(w.buffered());
    var out_buf: [24 * 1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [4096]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = &r,
        .server_name = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    const got = out.buffered();
    if (got.len != 0 and !std.mem.startsWith(u8, got, "HTTP/1.1 ")) return error.NotHttp;
    if (got.len == 0) {
        hit("wire-no-response");
    } else if (std.mem.startsWith(u8, got, "HTTP/1.1 200") and std.mem.eql(u8, target, "/metrics") and
        (std.mem.eql(u8, method, "GET") or std.mem.eql(u8, method, "HEAD")))
    {
        hit("wire-scrape-200");
        const modelled: ?metrics.Format = if (ncl != 0) modelNegotiate(cl[0..ncl]) else null;
        const fmt = modelled orelse metrics.Format.negotiate(std.mem.trim(u8, accept, " \t"));
        const want = (if (open_metrics) fmt else metrics.Format.text).contentType();
        var hdrs = std.mem.splitSequence(u8, got, "\r\n");
        var found = false;
        while (hdrs.next()) |l| {
            if (l.len == 0) break;
            if (std.ascii.startsWithIgnoreCase(l, "content-type:")) {
                found = true;
                if (!std.mem.eql(u8, std.mem.trim(u8, l["content-type:".len..], " "), want)) return error.ContentTypeNotNegotiated;
            }
        }
        if (!found) return error.NoContentType;
        if (std.mem.eql(u8, want, metrics.Format.openmetrics.contentType())) hit("wire-om") else hit("wire-text");
    } else if (std.mem.startsWith(u8, got, "HTTP/1.1 503")) {
        hit("wire-503");
    } else if (std.mem.startsWith(u8, got, "HTTP/1.1 4")) {
        hit("wire-4xx");
    }
    try scrapeChecked(gpa, &reg, .text);
    try scrapeChecked(gpa, &reg, .openmetrics);
}

// ── harness 3: registration, Vec.with label values, exemplars ───────────────

const AnyVec = union(enum) {
    counter: metrics.CounterVec,
    gauge: metrics.GaugeVec,
    histogram: metrics.HistogramVec,
    summary: metrics.SummaryVec,
};
const VecRow = struct { live: bool = true, vec: AnyVec, name: []const u8, nlabels: usize, label_names: [3][]const u8 };

fn escapeInto(w: *std.Io.Writer, v: []const u8) !void {
    for (v) |c| switch (c) {
        '\\' => try w.writeAll("\\\\"),
        '"' => try w.writeAll("\\\""),
        '\n' => try w.writeAll("\\n"),
        else => try w.writeByte(c),
    };
}

fn drawBuckets(d: *Dec, out: *[4]f64) []const f64 {
    const nb = d.below(5);
    if (d.byte() < 200) {
        var v: f64 = @floatFromInt(d.below(8));
        for (out[0..nb]) |*o| {
            v += 0.25 + @as(f64, @floatFromInt(d.below(64))) / 8.0;
            o.* = v;
        }
    } else for (out[0..nb]) |*o| {
        o.* = d.f64v();
    }
    return out[0..nb];
}

fn readF(ctx: ?*anyopaque) f64 {
    return @as(*const f64, @ptrCast(@alignCast(ctx.?))).*;
}

fn fuzzRegistry(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [3072]u8 = undefined;
    const n = fill(S, src, &raw);
    var d: Dec = .{ .b = raw[0..n] };

    var mc = clock_lib.ManualClock.init(1_000_000_000);
    var fval: f64 = 0; // read by the callback series; outlives the registry
    var reg = metrics.Registry.init(gpa);
    defer reg.deinit();
    reg.clock = mc.clock();
    reg.max_label_value_len = 48;
    reg.max_series_per_family = 3;

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    var fams: [8]VecRow = undefined;
    var nf: usize = 0;
    var buckets: [4]f64 = undefined;

    for (0..8 + d.below(28)) |_| {
        const op = d.below(15);
        switch (op) {
            0, 1, 2, 3 => { // register a Vec
                if (nf == fams.len) continue;
                var nbuf: [96]u8 = undefined;
                const name: []const u8 = if (d.byte() < 190) pool_names[d.below(pool_names.len)] else d.str(&nbuf, &name_vocab);
                var hbuf: [64]u8 = undefined;
                const help = d.str(&hbuf, &label_vocab);
                var lns: [3][]const u8 = undefined;
                var lbufs: [3][24]u8 = undefined;
                const nl = d.below(4);
                for (lns[0..nl], lbufs[0..nl]) |*ln, *lb| {
                    ln.* = if (d.byte() < 200) pool_labels[d.below(pool_labels.len)] else d.str(lb, &name_vocab);
                }
                const bk = drawBuckets(&d, &buckets);
                const row_or_err: metrics.RegisterError!AnyVec = switch (op) {
                    0 => if (reg.counterVec(name, help, lns[0..nl])) |v| .{ .counter = v } else |e| e,
                    1 => if (reg.gaugeVec(name, help, lns[0..nl])) |v| .{ .gauge = v } else |e| e,
                    2 => if (reg.histogramVec(name, help, lns[0..nl], bk)) |v| .{ .histogram = v } else |e| e,
                    else => blk: {
                        var objs: [2]metrics.Objective = undefined;
                        const no = d.below(3);
                        for (objs[0..no]) |*o| o.* = .{ .quantile = @as(f64, @floatFromInt(d.byte())) / 255.0, .epsilon = 0.001 + @as(f64, @floatFromInt(d.below(100))) / 1000.0 };
                        break :blk if (reg.summaryVec(name, help, lns[0..nl], .{ .objectives = objs[0..no], .max_age_ns = 1 + d.u64le() % 100_000_000_000, .age_buckets = @intCast(1 + d.below(6)), .buf_cap = @intCast(1 + d.below(40)) })) |v| .{ .summary = v } else |e| e;
                    },
                };
                if (row_or_err) |vec| {
                    hit("register-ok");
                    var row: VecRow = .{ .vec = vec, .name = try a.dupe(u8, name), .nlabels = nl, .label_names = undefined };
                    for (lns[0..nl], 0..) |ln, k| row.label_names[k] = try a.dupe(u8, ln);
                    fams[nf] = row;
                    nf += 1;
                } else |_| hit("register-refused");
            },
            4, 5, 6, 7 => { // with(values) + record
                if (nf == 0) continue;
                // mostly the first two Vecs, so one family fills up to its series cap
                const row = &fams[d.below(if (d.byte() < 160) @min(nf, 2) else nf)];
                var vbufs: [3][96]u8 = undefined;
                var vals: [3][]const u8 = undefined;
                const nv = if (d.byte() < 210) row.nlabels else d.below(4);
                for (vals[0..nv], vbufs[0..nv]) |*v, *vb| v.* = d.str(vb, &label_vocab);
                switch (row.vec) {
                    inline .counter, .gauge, .histogram, .summary => |vec, tag| {
                        if (vec.with(vals[0..nv])) |m| {
                            hit("with-" ++ @tagName(tag));
                            // What an accepted tuple must satisfy (the registry's
                            // limits above and the UTF-8 rule of `Label`).
                            for (vals[0..nv]) |v| {
                                if (v.len > reg.max_label_value_len) return error.LongValueAccepted;
                                if (!std.unicode.utf8ValidateSlice(v)) return error.InvalidUtf8Accepted;
                            }
                            if (vec.len() > reg.max_series_per_family) return error.TooManySeriesAccepted;
                            switch (tag) {
                                .counter => m.add(d.u16le()),
                                .gauge => m.set(d.f64v()),
                                .histogram => m.observe(d.f64v()),
                                .summary => {
                                    mc.advance(d.u64le() % 3_000_000_000);
                                    m.observe(d.f64v());
                                },
                            }
                            if (tag == .counter or tag == .gauge) try expectSeriesInText(gpa, &reg, row, vals[0..nv]);
                        } else |_| hit("with-refused");
                    },
                }
            },
            8, 9 => { // exemplar on a counter child or a histogram child
                if (nf == 0) continue;
                const row = &fams[d.below(nf)];
                var vbufs: [3][96]u8 = undefined;
                var vals: [3][]const u8 = undefined;
                for (vals[0..row.nlabels], vbufs[0..row.nlabels]) |*v, *vb| v.* = d.str(vb, &label_ok_vocab);
                var exl: [4]metrics.Label = undefined;
                var enb: [4][20]u8 = undefined;
                var evb: [4][72]u8 = undefined;
                const ne = d.below(5);
                const estart = d.below(pool_labels.len);
                for (exl[0..ne], enb[0..ne], evb[0..ne], 0..) |*l, *nb, *vb, ek| {
                    // Some values run to the rune cap (128 runes in all) or past it.
                    const long = d.byte() < 110;
                    l.* = .{
                        .name = switch (d.byte()) {
                            0...199 => pool_labels[(estart + ek) % pool_labels.len],
                            200...234 => pool_labels[d.below(pool_labels.len)], // may repeat
                            else => d.str(nb, &name_vocab),
                        },
                        .value = if (long) blk: {
                            const k = 20 + d.below(vb.len - 20);
                            @memset(vb[0..k], 'x');
                            break :blk vb[0..k];
                        } else d.str(vb, &label_vocab),
                    };
                }
                const ts: ?f64 = if (d.byte() < 128) d.f64v() else null;
                switch (row.vec) {
                    .counter => |vec| if (vec.with(vals[0..row.nlabels])) |c| {
                        if (c.addWithExemplar(1, exl[0..ne], ts)) |_| hit("exemplar-ok") else |_| hit("exemplar-refused");
                        try scrapeChecked(gpa, &reg, .openmetrics);
                    } else |_| {},
                    .histogram => |vec| if (vec.with(vals[0..row.nlabels])) |h| {
                        if (h.observeWithExemplar(d.f64v(), exl[0..ne], ts)) |_| hit("exemplar-ok") else |_| hit("exemplar-refused");
                        try scrapeChecked(gpa, &reg, .openmetrics);
                    } else |_| {},
                    else => {},
                }
            },
            10 => { // delete / reset
                if (nf == 0) continue;
                const row = &fams[d.below(nf)];
                var vbufs: [3][96]u8 = undefined;
                var vals: [3][]const u8 = undefined;
                const nv = d.below(4);
                for (vals[0..nv], vbufs[0..nv]) |*v, *vb| v.* = d.str(vb, &label_vocab);
                switch (row.vec) {
                    inline else => |vec| {
                        if (d.byte() < 200) _ = vec.delete(vals[0..nv]) else _ = vec.reset();
                    },
                }
            },
            11 => { // unregister
                var nbuf: [48]u8 = undefined;
                const name: []const u8 = if (nf != 0 and d.byte() < 200) fams[d.below(nf)].name else d.str(&nbuf, &name_vocab);
                if (reg.unregister(name)) {
                    // A Vec handle outlives its family (documented): it keeps
                    // working but is no longer exposed.
                    for (fams[0..nf]) |*f| if (std.mem.eql(u8, f.name, name)) {
                        f.live = false;
                    };
                }
            },
            12 => { // plain instruments with labels
                var nbuf: [48]u8 = undefined;
                const name: []const u8 = if (d.byte() < 190) pool_names[d.below(pool_names.len)] else d.str(&nbuf, &name_vocab);
                var lbs: [metrics.max_labels + 1]metrics.Label = undefined;
                var lnb: [metrics.max_labels + 1][16]u8 = undefined;
                var lvb: [metrics.max_labels + 1][48]u8 = undefined;
                const nl = d.below(metrics.max_labels + 2);
                const start = d.below(pool_labels.len);
                for (lbs[0..nl], lnb[0..nl], lvb[0..nl], 0..) |*l, *nb, *vb, k| {
                    // mostly distinct names (a repeat is refused, and then the values are never looked at)
                    l.* = .{ .name = if (d.byte() < 235) pool_labels[(start + k) % pool_labels.len] else d.str(nb, &name_vocab), .value = d.str(vb, &label_vocab) };
                }
                const bk = drawBuckets(&d, &buckets);
                const before = reg.families.items.len;
                const ok = switch (d.below(3)) {
                    0 => if (reg.counter(name, "plain", lbs[0..nl])) |c| blk: {
                        c.inc();
                        break :blk true;
                    } else |_| false,
                    1 => if (reg.gauge(name, "plain", lbs[0..nl])) |g| blk: {
                        g.set(d.f64v());
                        break :blk true;
                    } else |_| false,
                    else => if (reg.histogram(name, "plain", lbs[0..nl], bk)) |h| blk: {
                        h.observe(d.f64v());
                        break :blk true;
                    } else |_| false,
                };
                // A refused registration leaves no family behind.
                if (!ok and reg.families.items.len != before) return error.RefusedRegistrationLeftAFamily;
                if (ok) {
                    hit("plain-registered");
                    for (lbs[0..nl]) |l| {
                        if (l.value.len > reg.max_label_value_len) return error.LongValueAccepted;
                        if (!std.unicode.utf8ValidateSlice(l.value)) return error.InvalidUtf8Accepted;
                    }
                }
            },
            14 => { // callback series (counterFunc / gaugeFunc) with labels
                var nbuf: [48]u8 = undefined;
                const name: []const u8 = if (d.byte() < 190) pool_names[d.below(pool_names.len)] else d.str(&nbuf, &name_vocab);
                var lbs: [3]metrics.Label = undefined;
                var lnb: [3][16]u8 = undefined;
                var lvb: [3][48]u8 = undefined;
                const nl = d.below(4);
                const start = d.below(pool_labels.len);
                for (lbs[0..nl], lnb[0..nl], lvb[0..nl], 0..) |*l, *nb, *vb, k| {
                    l.* = .{ .name = if (d.byte() < 235) pool_labels[(start + k) % pool_labels.len] else d.str(nb, &name_vocab), .value = d.str(vb, &label_vocab) };
                }
                fval = d.f64v();
                const r = if (d.byte() & 1 == 0) reg.counterFunc(name, "fn", lbs[0..nl], &fval, readF) else reg.gaugeFunc(name, "fn", lbs[0..nl], &fval, readF);
                if (r) |_| {
                    hit("func-ok");
                    for (lbs[0..nl]) |l| {
                        if (l.value.len > reg.max_label_value_len) return error.LongValueAccepted;
                        if (!std.unicode.utf8ValidateSlice(l.value)) return error.InvalidUtf8Accepted;
                    }
                } else |_| {}
            },
            else => try scrapeChecked(gpa, &reg, if (d.byte() & 1 == 0) .text else .openmetrics), // a scrape mid-way
        }
    }
    try scrapeChecked(gpa, &reg, .text);
    try scrapeChecked(gpa, &reg, .openmetrics);
}

/// The value tuple the registry accepted must be in the text exposition,
/// escaped by an independent rule.
fn expectSeriesInText(gpa: std.mem.Allocator, reg: *metrics.Registry, row: *const VecRow, vals: []const []const u8) !void {
    if (vals.len != row.nlabels or !row.live) return;
    var exp_buf: [2048]u8 = undefined;
    var ew: std.Io.Writer = .fixed(&exp_buf);
    ew.writeAll(row.name) catch return;
    if (row.nlabels != 0) {
        ew.writeByte('{') catch return;
        for (vals, 0..) |v, i| {
            if (i != 0) ew.writeByte(',') catch return;
            ew.print("{s}=\"", .{row.label_names[i]}) catch return;
            escapeInto(&ew, v) catch return;
            ew.writeByte('"') catch return;
        }
        ew.writeByte('}') catch return;
    }
    ew.writeByte(' ') catch return;
    var a: std.Io.Writer.Allocating = .init(gpa);
    defer a.deinit();
    try reg.write(&a.writer, .text);
    if (std.mem.find(u8, a.written(), ew.buffered()) == null) {
        std.debug.print("series not in exposition: {s}\n---\n{s}\n", .{ ew.buffered(), a.written() });
        return error.AcceptedSeriesMissing;
    }
    hit("series-roundtrip");
}

// ── harness 4: a collector writing arbitrary samples through the Sink ───────

const SinkOp = struct {
    kind: u8,
    desc: usize,
    nvals: usize,
    vals: [3][]const u8,
    v: f64,
    nb: usize,
    bounds: [4]f64,
    cum: [4]u64,
    sum: f64,
    count: u64,
    quants: [3]metrics.Objective,
    nq: usize,
    qvals: [3]f64,
};
const Plan = struct { ops: [10]SinkOp, n: usize };

fn collectPlan(ctx: ?*anyopaque, sink: *metrics.Sink) anyerror!void {
    const p: *const Plan = @ptrCast(@alignCast(ctx.?));
    for (p.ops[0..p.n]) |o| {
        const vals = o.vals[0..o.nvals];
        switch (o.kind) {
            0 => try sink.counter(o.desc, vals, o.v),
            1 => try sink.gauge(o.desc, vals, o.v),
            2 => try sink.histogram(o.desc, vals, o.bounds[0..o.nb], o.cum[0..o.nb], o.sum, o.count),
            else => try sink.summary(o.desc, vals, o.quants[0..o.nq], o.qvals[0..o.nq], o.sum, o.count),
        }
    }
}

fn fuzzCollector(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [3072]u8 = undefined;
    const n = fill(S, src, &raw);
    var d: Dec = .{ .b = raw[0..n] };

    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    var plan: Plan = .{ .ops = undefined, .n = if (d.byte() < 200) d.below(4) else d.below(11) };
    const valid_values = d.byte() < 200;
    for (plan.ops[0..plan.n]) |*o| {
        o.kind = @intCast(d.below(4));
        // Mostly the descriptor of the matching kind (0..3 = counter, gauge,
        // histogram, summary), sometimes any, sometimes out of range.
        o.desc = if (d.byte() < 245) @as(usize, o.kind) else d.below(6);
        o.nvals = if (d.byte() < 245) switch (o.desc) {
            0 => 1,
            1 => 2,
            3 => 1,
            else => 0,
        } else d.below(4);
        for (o.vals[0..o.nvals]) |*v| {
            const buf = try a.alloc(u8, 40);
            v.* = d.str(buf, if (valid_values) &label_ok_vocab else &label_vocab);
        }
        o.v = d.f64v();
        o.sum = d.f64v();
        o.count = if (d.byte() < 200) d.below(30) else d.u16le();
        o.nb = d.below(5);
        var b: f64 = 0;
        var c: u64 = 0;
        for (o.bounds[0..o.nb], o.cum[0..o.nb]) |*bo, *co| {
            if (d.byte() < 220) {
                b += 0.5 + @as(f64, @floatFromInt(d.below(10)));
                c += d.below(5);
                bo.* = b;
                co.* = c;
            } else {
                bo.* = d.f64v();
                co.* = d.u16le();
            }
        }
        o.nq = d.below(4);
        var q: f64 = 0;
        for (o.quants[0..o.nq], o.qvals[0..o.nq]) |*qo, *qv| {
            q += @as(f64, @floatFromInt(d.below(40))) / 100.0;
            qo.* = .{ .quantile = if (d.byte() < 230) q else d.f64v(), .epsilon = 0.01 };
            qv.* = d.f64v();
        }
    }

    // Samples must come in descriptor order; mostly they do.
    if (d.byte() < 230) std.mem.sortUnstable(SinkOp, plan.ops[0..plan.n], {}, struct {
        fn lt(_: void, x: SinkOp, y: SinkOp) bool {
            return x.desc < y.desc;
        }
    }.lt);

    var reg = metrics.Registry.init(gpa);
    defer reg.deinit();
    const descs = [_]metrics.Desc{
        .{ .name = "col_c_total", .help = "c", .kind = .counter, .label_names = &.{"a"} },
        .{ .name = "col_g", .help = "g", .kind = .gauge, .label_names = &.{ "a", "b" } },
        .{ .name = "col_h", .help = "h", .kind = .histogram },
        .{ .name = "col_s", .help = "s", .kind = .summary, .label_names = &.{"a"} },
    };
    try reg.registerCollector(&descs, .{ .ctx = &plan, .collect = collectPlan });
    _ = try reg.counter("col_before_total", "b", &.{});

    inline for (.{ metrics.Format.text, metrics.Format.openmetrics }) |f| {
        var w: std.Io.Writer.Allocating = .init(gpa);
        defer w.deinit();
        if (reg.write(&w.writer, f)) |_| {
            hit("collector-ok");
            if (std.mem.find(u8, w.written(), "col_h_bucket") != null) hit("collector-histogram");
            if (std.mem.find(u8, w.written(), "quantile=") != null) hit("collector-summary");
            if (std.mem.find(u8, w.written(), "col_g{") != null) hit("collector-gauge");
            try scrapeCheckedOpt(gpa, &reg, f, false, true);
        } else |_| {
            hit("collector-refused");
            if (reg.lastCollectorError().? == error.DuplicateSample) hit("collector-duplicate-sample");
            if (reg.lastCollectorError() == null) return error.CollectorErrorNotKept;
        }
    }
}

// ── harness 5: numeric extremes through the instruments and the Summary ─────

fn fuzzNumeric(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [2048]u8 = undefined;
    const n = fill(S, src, &raw);
    var d: Dec = .{ .b = raw[0..n] };

    var mc = clock_lib.ManualClock.init(d.u64le());
    var reg = metrics.Registry.init(gpa);
    defer reg.deinit();
    reg.clock = mc.clock();

    var bk: [6]f64 = undefined;
    const nb = d.below(7);
    var b: f64 = d.f64v();
    for (bk[0..nb]) |*o| {
        o.* = b;
        b = if (d.byte() < 200) b + 0.5 + @as(f64, @floatFromInt(d.below(5))) else d.f64v();
    }
    const h = reg.histogram("num_h", "h", &.{}, bk[0..nb]) catch |e| blk: {
        if (e != error.InvalidBuckets) return e;
        hit("buckets-refused");
        break :blk try reg.histogram("num_h", "h", &.{}, &.{ 1, 10 });
    };
    const g = try reg.gauge("num_g", "g", &.{});
    const c = try reg.counter("num_c_total", "c", &.{});
    var objs: [3]metrics.Objective = undefined;
    const no = d.below(4);
    for (objs[0..no], 0..) |*o, i| o.* = .{ .quantile = 0.1 + 0.3 * @as(f64, @floatFromInt(i)), .epsilon = metrics.min_epsilon * @as(f64, @floatFromInt(1 + d.below(500))) };
    const s = try reg.summary("num_s", "s", &.{}, .{
        .objectives = objs[0..no],
        .max_age_ns = 1 + d.u64le() % 20_000_000_000,
        .age_buckets = @intCast(1 + d.below(8)),
        .buf_cap = @intCast(1 + d.below(30)),
    });

    var last_count: u64 = 0;
    for (0..d.below(120)) |_| {
        switch (d.below(9)) {
            0, 1, 2 => h.observe(d.f64v()),
            3 => g.set(d.f64v()),
            4 => g.add(d.f64v()),
            5 => c.add(d.u64le() % 1000),
            6 => mc.advance(switch (d.below(3)) {
                0 => d.u64le(),
                1 => d.u16le(),
                else => d.u64le() % 40_000_000_000,
            }),
            7 => s.observe(d.f64v()),
            else => {
                var q: [4]f64 = @splat(-1);
                const snap = s.snapshot(q[0..d.below(5)]);
                if (snap.count < last_count) return error.CountWentBackwards;
                last_count = snap.count;
                hit("summary-snapshot");
            },
        }
    }
    // Histogram internals: cumulative buckets never decrease and never exceed count.
    var prev: u64 = 0;
    for (0..nb + 1) |i| {
        const cb = h.cumulativeBucket(i);
        if (cb < prev) return error.BucketsNotCumulative;
        prev = cb;
    }
    if (prev > h.count()) return error.BucketAboveCount;
    // Exemplars with extreme values.
    const ex_labels = [_]metrics.Label{.{ .name = "trace_id", .value = "abc" }};
    c.addWithExemplar(1, &ex_labels, if (d.byte() & 1 == 0) d.f64v() else null) catch {};
    h.observeWithExemplar(d.f64v(), &ex_labels, d.f64v()) catch {};
    // The bucket helpers on arbitrary parameters (like client_golang's they do
    // not promise increasing values; registration is the judge: it accepts a
    // list or says `InvalidBuckets`, never anything else).
    var out: [5]f64 = undefined;
    const cnt = 1 + d.below(5);
    inline for (0..3) |k| {
        const r = switch (k) {
            0 => metrics.fillLinearBuckets(out[0..cnt], d.f64v(), d.f64v()),
            1 => metrics.fillExponentialBuckets(out[0..cnt], d.f64v(), d.f64v()),
            else => metrics.fillExponentialBucketsRange(out[0..cnt], d.f64v(), d.f64v()),
        };
        if (r) |_| {
            if (reg.histogram("num_fill", "f", &.{}, out[0..cnt])) |_| {
                for (out[1..cnt], out[0 .. cnt - 1]) |x, y| if (!(x > y)) return error.AcceptedNonIncreasing;
                hit("fill-registered");
                _ = reg.unregister("num_fill");
            } else |e| if (e != error.InvalidBuckets) return e;
        } else |_| hit("fill-refused");
    }

    try scrapeChecked(gpa, &reg, .text);
    try scrapeChecked(gpa, &reg, .openmetrics);
}

// ── harness 6: the process collector on arbitrary pids and namespaces ───────

fn fuzzProcess(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var raw: [256]u8 = undefined;
    const n = fill(S, src, &raw);
    var d: Dec = .{ .b = raw[0..n] };
    if (comptime builtin.os.tag != .linux) return;

    var reg = metrics.Registry.init(gpa);
    defer reg.deinit();
    var pc: metrics.ProcessCollector = .{
        .gpa = gpa,
        .io = testing.io,
        .ref = switch (d.below(4)) {
            0, 1 => .self,
            2 => .{ .pid = 1 },
            else => .{ .pid = std.math.cast(u32, d.u64le()) orelse 1 },
        },
    };
    var nsb: [200]u8 = undefined;
    const ns: []const u8 = switch (d.below(3)) {
        0 => "",
        1 => "fz",
        else => d.str(&nsb, &name_vocab),
    };
    pc.register(&reg, ns) catch |e| {
        hit("process-register-refused");
        if (e != error.InvalidName) return e;
        return;
    };
    hit("process-registered");
    try scrapeCheckedOpt(gpa, &reg, .text, false, false); // /proc moves between scrapes
    try scrapeCheckedOpt(gpa, &reg, .openmetrics, false, false);
}

// ── the tests: `--fuzz` entries, the driver, a reach check in the suite ─────

fn smithNegotiate(_: void, smith: *testing.Smith) !void {
    fuzzNegotiate(testing.Smith, smith, testing.allocator) catch |e| return failed("negotiate", e);
}
fn smithWire(_: void, smith: *testing.Smith) !void {
    fuzzWire(testing.Smith, smith, testing.allocator) catch |e| return failed("wire", e);
}
fn smithRegistry(_: void, smith: *testing.Smith) !void {
    fuzzRegistry(testing.Smith, smith, testing.allocator) catch |e| return failed("registry", e);
}
fn smithCollector(_: void, smith: *testing.Smith) !void {
    fuzzCollector(testing.Smith, smith, testing.allocator) catch |e| return failed("collector", e);
}
fn smithNumeric(_: void, smith: *testing.Smith) !void {
    fuzzNumeric(testing.Smith, smith, testing.allocator) catch |e| return failed("numeric", e);
}

fn failed(name: []const u8, e: anyerror) anyerror {
    std.debug.print("{s}: {t}\n", .{ name, e });
    return e;
}

const accept_seeds = [_][]const u8{
    testkit.fuzz.seed("application/openmetrics-text; version=1.0.0; charset=utf-8,text/plain;version=0.0.4;q=0.5,*/*;q=0.1"),
    testkit.fuzz.seed("text/plain;version=0.0.4"),
};

test "fuzz: negotiate never panics and answers one of two formats" {
    try testing.fuzz({}, smithNegotiate, .{ .corpus = &accept_seeds });
}
test "fuzz: scrape endpoint on the wire" {
    try testing.fuzz({}, smithWire, .{ .corpus = &accept_seeds });
}
test "fuzz: registration, label values and exemplars render a valid exposition" {
    try testing.fuzz({}, smithRegistry, .{ .corpus = &accept_seeds });
}
test "fuzz: collector samples through the Sink" {
    try testing.fuzz({}, smithCollector, .{ .corpus = &accept_seeds });
}
test "fuzz: numeric extremes through instruments and Summary" {
    try testing.fuzz({}, smithNumeric, .{ .corpus = &accept_seeds });
}

test "fuzz driver: METRICS_FUZZ" {
    try fuzz_driver.runAll(.{
        .{ fuzzNegotiate, .{ .prefix = "METRICS_FUZZ", .name = "metrics-negotiate" } },
        .{ fuzzWire, .{ .prefix = "METRICS_FUZZ", .name = "metrics-wire", .scale = 4 } },
        .{ fuzzRegistry, .{ .prefix = "METRICS_FUZZ", .name = "metrics-registry", .scale = 4 } },
        .{ fuzzCollector, .{ .prefix = "METRICS_FUZZ", .name = "metrics-collector", .scale = 2 } },
        .{ fuzzNumeric, .{ .prefix = "METRICS_FUZZ", .name = "metrics-numeric", .scale = 2 } },
        .{ fuzzProcess, .{ .prefix = "METRICS_FUZZ", .name = "metrics-process", .scale = 100 } },
    });
}

/// In-suite smoke: a few hundred seeds per harness, and the checker itself is
/// not vacuous (it rejects what it should).
fn smoke(comptime harness: anytype, name: []const u8, seeds: usize) !void {
    fuzz_driver.resetReach();
    defer fuzz_driver.resetReach();
    for (0..seeds) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: Rng = .{ .r = prng.random() };
        harness(Rng, &rng, testing.allocator) catch |err| {
            std.debug.print("{s} seed {d}: {t}\n", .{ name, seed, err });
            return err;
        };
    }
}

test "fuzz harness: 200 seeds of every harness run clean" {
    try smoke(fuzzNegotiate, "negotiate", 200);
    try smoke(fuzzWire, "wire", 60);
    try smoke(fuzzRegistry, "registry", 60);
    try smoke(fuzzCollector, "collector", 60);
    try smoke(fuzzNumeric, "numeric", 60);
}

test "fuzz checker: rejects what a Prometheus parser rejects" {
    const bad = [_]struct { []const u8, bool }{
        .{ "# TYPE x counter\nx{a=\"1\\q\"} 1\n", false }, // unknown escape
        .{ "# TYPE x counter\nx{a=\"1\",a=\"2\"} 1\n", false }, // repeated label
        .{ "# TYPE x counter\nx 1\nx 2\n", false }, // duplicate sample
        .{ "# TYPE x counter\n# TYPE x gauge\nx 1\n", false }, // repeated TYPE
        .{ "# TYPE x counter\nx 1", false }, // no final newline
        .{ "# TYPE x counter\nx 1\n# EOF\n", false }, // EOF in text format
        .{ "# TYPE x counter\nx nope\n", false },
        .{ "# TYPE x counter\nx 1 # {a=\"b\"} 1\n", false }, // exemplar in text format
        .{ "# TYPE x histogram\nx_bucket{le=\"1\"} 5\nx_bucket{le=\"2\"} 4\n", false }, // not cumulative
        .{ "# TYPE y counter\nx 1\n", false }, // sample outside its family
        .{ "# TYPE x counter\nx{a=\"\xff\"} 1\n", false }, // invalid UTF-8
        .{ "# TYPE x counter\nx{a=\"1\"} 1\n", true },
        .{ "# HELP x line\\nbreak and \\\\ slash\n# TYPE x gauge\nx +Inf\n", true },
    };
    for (bad) |row| {
        var chk: Check = .{ .gpa = testing.allocator, .om = false };
        defer chk.deinit();
        const r = chk.run(row[0]);
        if (row[1]) try r else try testing.expect(std.meta.isError(r));
    }
    var om: Check = .{ .gpa = testing.allocator, .om = true };
    defer om.deinit();
    try om.run("# TYPE x counter\nx_total 1 # {a=\"b\"} 1 1.5\n# EOF\n");
    var om2: Check = .{ .gpa = testing.allocator, .om = true };
    defer om2.deinit();
    try testing.expect(std.meta.isError(om2.run("# TYPE x counter\nx_total 1\n")));
}
