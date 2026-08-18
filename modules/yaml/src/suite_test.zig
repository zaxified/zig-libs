// SPDX-License-Identifier: MIT
//! The external anchors: **yaml-test-suite**, both layers, run in full against
//! one committed ledger.
//!
//! Every other test in this module was written by the same hands that wrote the
//! parser, so all of them share whatever this code misreads about YAML 1.2.
//! These do not. `github.com/yaml/yaml-test-suite` (`data` branch) ships 402
//! cases produced by implementations that have never seen this code:
//!
//!  * `test.event` — a byte-exact expected event dump, for **Part 1** (the
//!    scanner + parser). 402 cases, 94 of them inputs that must be *rejected*.
//!  * `in.json` — the same document as JSON, for **Part 2** (the composer +
//!    core schema). 282 files, less the 3 belonging to must-reject cases, so
//!    **279** real oracles. The other 29 non-error cases have no JSON form at
//!    all: their YAML has non-string mapping keys, which JSON cannot express.
//!
//! The suite is not vendored — it is a separate repository with its own
//! history, and pinning a copy here would turn a live oracle into a stale one.
//! Fetch it and point `ZIG_LIBS_YAML_SUITE` at the checkout:
//!
//! ```
//! git clone -b data --depth 1 https://github.com/yaml/yaml-test-suite \
//!     ~/.cache/zig-libs-yaml/yaml-test-suite-data
//! ```
//!
//! Without it these tests skip rather than pass: `error.SkipZigTest`, which
//! `--summary all` reports as skipped, plus a `SKIPPED: …` line naming the
//! missing path under `ZIG_LIBS_VERBOSE_SKIP=1`. The notice is opt-in for the
//! reason given on `verbose()` below — a green run must leave stderr clean —
//! and this is the same posture `dtls`'s live-interop tests take.
//!
//! ## Why a ledger and not just a pass count
//!
//! A count can be met by a parser that passes a different 402 cases than it did
//! yesterday. `testdata/ledger.txt` gives every case one row carrying *all* its
//! expected outcomes, and the assertion runs in both directions: a listed pass
//! that fails is red, and a known-fail that starts passing is red too. The id
//! set must equal the suite's exactly, and each column is cross-checked against
//! the suite's own files, so a case added, removed or reclassified upstream is
//! red as well. A ledger that is allowed to be approximately true is worse than
//! no ledger.
//!
//! ## Why the JSON comparison is structural
//!
//! It compares `Value` against `std.json.Value` node by node, on the kind and
//! then the payload — never by rendering either to text. A formatting round
//! trip is exactly what would hide the bugs this oracle exists to catch: a
//! core-schema slip that leaves `1` as the string `"1"`, or reads `0777` as
//! octal, prints almost alike and would silently normalise into agreement.
//!
//! **What this oracle cannot police is int vs float**, and it is worth being
//! precise about why rather than pretending otherwise. JSON has one number
//! type; whether a literal carries a `.` is a choice made by whatever
//! serialiser wrote the file, and `std.json`'s `.integer`/`.float` split is a
//! property of that text. The suite settles it: `UGM3`'s YAML says `450.00` —
//! a float beyond argument — and its `in.json` says `450`. So numbers are
//! compared **by value across both kinds** (see `numbersEqual`), while every
//! distinction JSON genuinely makes stays exact. The int/float resolution
//! itself is pinned by `compose.zig`'s unit tests, which is the only place it
//! can be. `test "the JSON comparison separates a number from a string, and
//! values from each other"` below keeps both halves of that from drifting.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const yaml = @import("root.zig");

const Value = yaml.Value;

const ledger_text = @embedFile("testdata/ledger.txt");

const default_suite = ".cache/zig-libs-yaml/yaml-test-suite-data";

/// Portable env-var read for tests — see `testkit.getEnv`'s doc comment for
/// why the plain `std.testing.environ.getPosix` idiom does not compile for
/// `x86_64-windows-gnu` (its own body references `GlobalBlock.view()`, which
/// does not exist). Duplicated here rather than routed through `testkit`
/// because `yaml` does not carry `testkit` as a `test_deps` entry in
/// `build.zig` — wiring that up is out of scope for this fix.
fn envRead(name: []const u8) ?[]const u8 {
    if (builtin.target.os.tag == .windows) return null;
    return std.process.Environ.getPosix(testing.environ, name);
}

/// Nothing may reach stderr on a green run: `scripts/test.sh` treats a step
/// that writes to stderr as failed, precisely so a test cannot warn its way
/// past the gate. The skip notice and the score line are therefore opt-in,
/// behind the same `ZIG_LIBS_VERBOSE_SKIP` switch `dtls` uses. A skipped test
/// is still visible without it — `--summary all` reports it as skipped.
fn verbose() bool {
    const v = envRead("ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

/// Part 1 expectation, against `test.event`.
const EvExpect = enum { event, reject, fail };
/// Part 2 expectation, against `in.json`.
const JsExpect = enum { json, none, fail };

const Entry = struct {
    id: []const u8,
    ev: EvExpect,
    js: JsExpect,
    reason: []const u8,
};

fn parseLedger(gpa: std.mem.Allocator) ![]Entry {
    var out: std.ArrayList(Entry) = .empty;
    errdefer out.deinit(gpa);
    var lines = std.mem.splitScalar(u8, ledger_text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        var it = std.mem.tokenizeAny(u8, line, " \t");
        const id = it.next() orelse return error.MalformedLedger;
        const ev_tok = it.next() orelse return error.MalformedLedger;
        const js_tok = it.next() orelse return error.MalformedLedger;
        const ev = std.meta.stringToEnum(EvExpect, ev_tok) orelse return error.MalformedLedger;
        const js = std.meta.stringToEnum(JsExpect, js_tok) orelse return error.MalformedLedger;
        const reason = std.mem.trim(u8, it.rest(), " \t");
        // A known-fail with no specific reason is exactly the rot this file
        // exists to prevent.
        if ((ev == .fail or js == .fail) and reason.len == 0) return error.KnownFailNeedsReason;
        // What does not parse cannot compose; a row claiming otherwise is
        // incoherent rather than merely wrong.
        if (ev == .fail and js != .none) return error.IncoherentLedgerRow;
        try out.append(gpa, .{ .id = id, .ev = ev, .js = js, .reason = reason });
    }
    return out.toOwnedSlice(gpa);
}

fn hasFile(gpa: std.mem.Allocator, io: std.Io, dir: std.Io.Dir, name: []const u8, leaf: []const u8) !bool {
    const p = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ name, leaf });
    defer gpa.free(p);
    dir.access(io, p, .{}) catch return false;
    return true;
}

/// Case directories are those containing `in.yaml`. Most are one level down
/// (`229Q/`), but 69 are nested one deeper (`UKK6/00/`), so both depths are
/// collected rather than assuming a fixed shape. `name/` and `tags/` are
/// symlink indexes onto the same cases and are skipped — descending them would
/// count many cases several times over.
fn collectCases(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir, out: *std.ArrayList([]u8)) !void {
    var dir = try root.openDir(io, ".", .{ .iterate = true });
    defer dir.close(io);
    var it = dir.iterate();
    while (try it.next(io)) |e| {
        if (e.kind != .directory) continue;
        if (std.mem.eql(u8, e.name, "name") or std.mem.eql(u8, e.name, "tags")) continue;
        if (try hasFile(gpa, io, root, e.name, "in.yaml")) {
            try out.append(gpa, try gpa.dupe(u8, e.name));
            continue;
        }
        var sub = root.openDir(io, e.name, .{ .iterate = true }) catch continue;
        defer sub.close(io);
        var sit = sub.iterate();
        while (try sit.next(io)) |se| {
            if (se.kind != .directory) continue;
            if (try hasFile(gpa, io, sub, se.name, "in.yaml"))
                try out.append(gpa, try std.fmt.allocPrint(gpa, "{s}/{s}", .{ e.name, se.name }));
        }
    }
}

fn suitePath(gpa: std.mem.Allocator) !?[]u8 {
    if (envRead("ZIG_LIBS_YAML_SUITE")) |p| {
        if (p.len > 0) return try gpa.dupe(u8, p);
    }
    const home = envRead("HOME") orelse return null;
    return try std.fs.path.join(gpa, &.{ home, default_suite });
}

fn openSuite(gpa: std.mem.Allocator, io: std.Io) !?std.Io.Dir {
    const path = (try suitePath(gpa)) orelse {
        if (verbose())
            std.debug.print("\nSKIPPED: yaml-test-suite anchor: neither ZIG_LIBS_YAML_SUITE nor HOME is set.\n", .{});
        return null;
    };
    defer gpa.free(path);
    return std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true }) catch {
        if (verbose()) std.debug.print(
            "\nSKIPPED: yaml-test-suite anchor: no suite at '{s}'.\n" ++
                "  git clone -b data --depth 1 https://github.com/yaml/yaml-test-suite ~/{s}\n" ++
                "  (or set ZIG_LIBS_YAML_SUITE to an existing checkout)\n",
            .{ path, default_suite },
        );
        return null;
    };
}

fn readCaseFile(gpa: std.mem.Allocator, io: std.Io, root: std.Io.Dir, id: []const u8, name: []const u8) ![]u8 {
    const p = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ id, name });
    defer gpa.free(p);
    return root.readFileAlloc(io, p, gpa, .limited(1 << 20));
}

fn lessThanSlice(_: void, a: []u8, b: []u8) bool {
    return std.mem.lessThan(u8, a, b);
}

// ── the JSON comparison ─────────────────────────────────────────────────────

/// Reads every top-level JSON value in `text`. `in.json` holds **one value per
/// YAML document**, concatenated (`9KAX` has seven), which `parseFromSlice`
/// cannot express — it asserts end-of-input after the first value. Driving the
/// scanner directly is the std-native way to read a value stream.
fn parseJsonDocs(arena: std.mem.Allocator, text: []const u8) ![]std.json.Value {
    var out: std.ArrayList(std.json.Value) = .empty;
    var rest = text;
    while (true) {
        rest = std.mem.trimStart(u8, rest, " \t\r\n");
        if (rest.len == 0) break;
        // A fresh scanner per value: once a `Scanner` has completed a top-level
        // value it is in `.post_value`, where anything but whitespace or EOF is
        // a syntax error. Its public `cursor` says where the value ended, which
        // is all that is needed to start the next one.
        var scanner = std.json.Scanner.initCompleteInput(arena, rest);
        defer scanner.deinit();
        const v = try std.json.innerParse(std.json.Value, arena, &scanner, .{
            .max_value_len = rest.len,
            .allocate = .alloc_always,
            .duplicate_field_behavior = .use_last,
        });
        try out.append(arena, v);
        rest = rest[scanner.cursor..];
    }
    return out.items;
}

/// True when a YAML number and a JSON number denote the same value.
///
/// **JSON cannot express the int/float distinction that YAML's core schema
/// makes**, and the suite proves it: `UGM3`'s YAML says `450.00` — a float
/// beyond argument — and its `in.json` says `450`. A JSON number is just a
/// number; whether the literal carries a `.` is a choice made by whatever
/// serialiser wrote the file, and `std.json`'s `.integer`/`.float` split is a
/// property of that text, not a claim about the value.
///
/// So this compares numbers *by value*, across the two kinds, and never through
/// a formatted string. What stays strict is every distinction JSON really does
/// make — number vs string vs bool vs null vs array vs object — which is where
/// the core-schema bugs worth catching actually live (`0777` as a string,
/// `yes` as a bool, `1:30` as a sexagesimal). The int/float resolution itself
/// is pinned by the unit tests in `compose.zig`, which is the only place it can
/// be pinned.
fn numbersEqual(y: Value, j: std.json.Value) bool {
    const jf: f64 = switch (j) {
        .integer => |x| @floatFromInt(x),
        .float => |f| f,
        else => return false,
    };
    switch (y) {
        .int => |i| {
            if (j == .integer) return j.integer == i;
            // Exact only: require the float to name this integer precisely.
            const back: f64 = @floatFromInt(i);
            return back == jf and jf == @trunc(jf);
        },
        .float => |f| return f == jf,
        else => return false,
    }
}

const Cmp = struct {
    gpa: std.mem.Allocator,
    path: std.ArrayList(u8) = .empty,
    detail: std.ArrayList(u8) = .empty,

    fn deinit(self: *Cmp) void {
        self.path.deinit(self.gpa);
        self.detail.deinit(self.gpa);
    }

    fn note(self: *Cmp, comptime fmt: []const u8, args: anytype) !void {
        var buf: [256]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, fmt, args) catch "…";
        self.detail.clearRetainingCapacity();
        try self.detail.appendSlice(self.gpa, s);
    }

    fn push(self: *Cmp, comptime fmt: []const u8, args: anytype) !usize {
        const mark = self.path.items.len;
        var buf: [128]u8 = undefined;
        const s = std.fmt.bufPrint(&buf, fmt, args) catch "…";
        try self.path.appendSlice(self.gpa, s);
        return mark;
    }

    /// Structural equality, kind-exact for every distinction JSON can express
    /// and value-exact for numbers. Nothing is compared through a formatted
    /// string — see `numbersEqual` for why the numeric case is the one place
    /// JSON is weaker than YAML's core schema.
    fn eq(self: *Cmp, y: Value, j: std.json.Value) !bool {
        switch (y) {
            .null => if (j == .null) return true,
            .bool => |b| if (j == .bool and j.bool == b) return true,
            .int, .float => if (numbersEqual(y, j)) return true,
            .string => |s| if (j == .string and std.mem.eql(u8, s, j.string)) return true,
            .sequence => |items| {
                if (j != .array) {
                    try self.note("yaml=sequence json={s}", .{@tagName(j)});
                    return false;
                }
                const arr = j.array.items;
                if (arr.len != items.len) {
                    try self.note("sequence length yaml={d} json={d}", .{ items.len, arr.len });
                    return false;
                }
                for (items, arr, 0..) |yi, ji, idx| {
                    const mark = try self.push("[{d}]", .{idx});
                    if (!try self.eq(yi, ji)) return false;
                    self.path.shrinkRetainingCapacity(mark);
                }
                return true;
            },
            .mapping => |pairs| {
                if (j != .object) {
                    try self.note("yaml=mapping json={s}", .{@tagName(j)});
                    return false;
                }
                const obj = j.object;
                if (obj.count() != pairs.len) {
                    try self.note("mapping size yaml={d} json={d}", .{ pairs.len, obj.count() });
                    return false;
                }
                // Compared by key lookup rather than positionally: JSON objects
                // are unordered by their own spec, so insisting on the suite's
                // key order would assert something JSON does not promise.
                for (pairs) |p| {
                    const key = switch (p.key) {
                        .string => |k| k,
                        else => {
                            try self.note("non-string mapping key ({s}) has no JSON form", .{@tagName(p.key)});
                            return false;
                        },
                    };
                    const mark = try self.push(".{s}", .{key});
                    const jv = obj.get(key) orelse {
                        try self.note("key missing from the JSON object", .{});
                        return false;
                    };
                    if (!try self.eq(p.value, jv)) return false;
                    self.path.shrinkRetainingCapacity(mark);
                }
                return true;
            },
        }
        try self.note("yaml={s} json={s}", .{ @tagName(y), @tagName(j) });
        return false;
    }
};

// ── the harness ─────────────────────────────────────────────────────────────

test "yaml-test-suite: every case reaches exactly its ledger outcome" {
    const gpa = testing.allocator;
    const io = testing.io;

    const entries = try parseLedger(gpa);
    defer gpa.free(entries);

    var root = (try openSuite(gpa, io)) orelse return error.SkipZigTest;
    defer root.close(io);

    var ids: std.ArrayList([]u8) = .empty;
    defer {
        for (ids.items) |i| gpa.free(i);
        ids.deinit(gpa);
    }
    try collectCases(gpa, io, root, &ids);
    std.mem.sort([]u8, ids.items, {}, lessThanSlice);

    // ── direction 1: the id sets must be equal ──────────────────────────────
    // Without this the ledger could go stale by omission: a case the suite
    // gains would simply never run, and one it loses would never be noticed.
    var listed: std.StringHashMapUnmanaged(Entry) = .empty;
    defer listed.deinit(gpa);
    for (entries) |e| {
        const prev = try listed.fetchPut(gpa, e.id, e);
        if (prev != null) {
            std.debug.print("ledger lists '{s}' twice\n", .{e.id});
            return error.DuplicateLedgerEntry;
        }
    }
    var set_bad: usize = 0;
    for (ids.items) |id| {
        if (listed.get(id) == null) {
            std.debug.print("suite case '{s}' is not in the ledger\n", .{id});
            set_bad += 1;
        }
    }
    for (entries) |e| {
        const found = for (ids.items) |id| {
            if (std.mem.eql(u8, id, e.id)) break true;
        } else false;
        if (!found) {
            std.debug.print("ledger lists '{s}', which the suite does not have\n", .{e.id});
            set_bad += 1;
        }
    }
    if (set_bad != 0) return error.LedgerIdSetMismatch;

    // ── direction 2: every case reaches exactly its listed outcome ──────────
    var off_ledger: usize = 0;
    var unexpectedly_passing: usize = 0;
    var ev_pass: usize = 0;
    var js_pass: usize = 0;
    var js_total: usize = 0;

    for (ids.items) |id| {
        const entry = listed.get(id).?;

        const src = try readCaseFile(gpa, io, root, id, "in.yaml");
        defer gpa.free(src);
        const must_error = try hasFile(gpa, io, root, id, "error");
        const has_json = try hasFile(gpa, io, root, id, "in.json");

        // The ledger's own classification is checked against the suite, so an
        // upstream case that flips valid/invalid, or gains or loses its JSON
        // form, cannot hide behind a still-green assertion.
        if (entry.ev != .fail and (entry.ev == .reject) != must_error) {
            std.debug.print("{s}: ledger says {s}, suite says {s}\n", .{
                id, @tagName(entry.ev), if (must_error) "must-reject" else "must-parse",
            });
            off_ledger += 1;
            continue;
        }
        // A must-reject case's in.json is a prefix artefact, not a pass
        // condition — the same trap `test.event` sets in Part 1.
        const oracle_exists = has_json and !must_error;
        if ((entry.js != .none) != oracle_exists) {
            std.debug.print("{s}: ledger says json={s} but the suite {s} usable in.json\n", .{
                id, @tagName(entry.js), if (oracle_exists) "has a" else "has no",
            });
            off_ledger += 1;
            continue;
        }

        // ── Part 1: events ──────────────────────────────────────────────────
        const got: ?[]u8 = yaml.dumpEvents(gpa, src) catch null;
        defer if (got) |g| gpa.free(g);

        const ev_reached: bool = if (must_error) got == null else blk: {
            const g = got orelse break :blk false;
            const want = try readCaseFile(gpa, io, root, id, "test.event");
            defer gpa.free(want);
            break :blk std.mem.eql(u8, g, want);
        };
        if (ev_reached) ev_pass += 1;

        switch (entry.ev) {
            .event, .reject => if (!ev_reached) {
                std.debug.print("{s}: [events] ledger says {s}, but the case does not pass\n", .{ id, @tagName(entry.ev) });
                off_ledger += 1;
            },
            .fail => if (ev_reached) {
                std.debug.print("{s}: [events] ledger says KNOWN-FAIL ({s}) but it passes now — update the ledger\n", .{ id, entry.reason });
                unexpectedly_passing += 1;
            },
        }

        // ── Part 2: compose + core schema, against in.json ──────────────────
        if (!oracle_exists) continue;
        js_total += 1;

        var arena = std.heap.ArenaAllocator.init(gpa);
        defer arena.deinit();
        const aa = arena.allocator();

        const json_text = try readCaseFile(gpa, io, root, id, "in.json");
        defer gpa.free(json_text);

        var cmp: Cmp = .{ .gpa = gpa };
        defer cmp.deinit();

        const js_reached: bool = blk: {
            const want_docs = parseJsonDocs(aa, json_text) catch {
                try cmp.note("the harness could not parse in.json", .{});
                break :blk false;
            };
            const composed = yaml.composeAllLeaky(aa, src, .{}) catch |e| {
                try cmp.note("compose failed: {s}", .{@errorName(e)});
                break :blk false;
            };
            if (composed.len != want_docs.len) {
                try cmp.note("document count yaml={d} json={d}", .{ composed.len, want_docs.len });
                break :blk false;
            }
            for (composed, want_docs, 0..) |yv, jv, di| {
                const mark = try cmp.push("doc{d}", .{di});
                if (!try cmp.eq(yv, jv)) break :blk false;
                cmp.path.shrinkRetainingCapacity(mark);
            }
            break :blk true;
        };
        if (js_reached) js_pass += 1;

        switch (entry.js) {
            .json => if (!js_reached) {
                std.debug.print("{s}: [json] ledger says json, mismatch at {s}: {s}\n", .{
                    id, if (cmp.path.items.len == 0) "<root>" else cmp.path.items, cmp.detail.items,
                });
                off_ledger += 1;
            },
            .fail => if (js_reached) {
                std.debug.print("{s}: [json] ledger says KNOWN-FAIL ({s}) but it passes now — update the ledger\n", .{ id, entry.reason });
                unexpectedly_passing += 1;
            },
            .none => unreachable, // excluded by `oracle_exists` above
        }
    }

    const bad = off_ledger != 0 or unexpectedly_passing != 0;
    if (bad or verbose())
        std.debug.print("\nyaml-test-suite: events {d}/{d} · json {d}/{d}\n", .{ ev_pass, ids.items.len, js_pass, js_total });
    if (bad) {
        std.debug.print("{d} case(s) off the ledger, {d} known-fail(s) now passing\n", .{ off_ledger, unexpectedly_passing });
        return error.LedgerMismatch;
    }
}

test "the ledger itself is well formed" {
    const gpa = testing.allocator;
    const entries = try parseLedger(gpa);
    defer gpa.free(entries);
    // Guards the harness against a ledger truncated to nothing, which would
    // make every assertion above vacuously true.
    try testing.expect(entries.len >= 400);
    var rejects: usize = 0;
    var oracles: usize = 0;
    for (entries) |e| {
        try testing.expect(e.id.len > 0);
        if (e.ev == .reject) rejects += 1;
        if (e.js == .json or e.js == .fail) oracles += 1;
        if (e.ev == .fail or e.js == .fail) try testing.expect(e.reason.len > 0);
    }
    try testing.expect(rejects >= 90);
    try testing.expect(oracles >= 270);
}

test "the JSON comparison separates a number from a string, and values from each other" {
    // Exactly what this oracle can and cannot police, pinned so neither half
    // drifts. `"1"` is a different JSON *kind* from `1`, so it must never
    // compare equal to a number — that is the distinction the core-schema bugs
    // worth catching actually turn on. `1` vs `1.0` is NOT a distinction JSON
    // makes (see `numbersEqual`, and `UGM3` in the suite), so those do compare
    // equal here and are pinned by `compose.zig`'s unit tests instead.
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const as_int = (try parseJsonDocs(aa, "1"))[0];
    const as_float = (try parseJsonDocs(aa, "1.0"))[0];
    const as_str = (try parseJsonDocs(aa, "\"1\""))[0];
    const other = (try parseJsonDocs(aa, "2"))[0];

    var cmp: Cmp = .{ .gpa = gpa };
    defer cmp.deinit();

    // A number is never a string, in either direction.
    try testing.expect(!try cmp.eq(.{ .int = 1 }, as_str));
    try testing.expect(!try cmp.eq(.{ .float = 1.0 }, as_str));
    try testing.expect(!try cmp.eq(.{ .string = "1" }, as_int));
    try testing.expect(!try cmp.eq(.{ .string = "1" }, as_float));
    try testing.expect(try cmp.eq(.{ .string = "1" }, as_str));

    // Numbers compare by value, across JSON's single number kind.
    try testing.expect(try cmp.eq(.{ .int = 1 }, as_int));
    try testing.expect(try cmp.eq(.{ .int = 1 }, as_float));
    try testing.expect(try cmp.eq(.{ .float = 1.0 }, as_int));
    try testing.expect(try cmp.eq(.{ .float = 1.0 }, as_float));

    // But a *different* value never passes, which is the part that matters.
    try testing.expect(!try cmp.eq(.{ .int = 1 }, other));
    try testing.expect(!try cmp.eq(.{ .float = 1.5 }, as_int));
    try testing.expect(!try cmp.eq(.{ .bool = true }, as_int));
    try testing.expect(!try cmp.eq(.null, as_int));
}

test "in.json may hold several documents" {
    const gpa = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const docs = try parseJsonDocs(arena.allocator(), "\"a\"\n\"b\"\nnull\n");
    try testing.expectEqual(@as(usize, 3), docs.len);
    try testing.expectEqualStrings("a", docs[0].string);
    try testing.expect(docs[2] == .null);
}
