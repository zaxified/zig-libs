// SPDX-License-Identifier: MIT
//! yaml — a YAML **1.2** reader: scanner + parser + composer, from source bytes
//! to native `Value` trees, with core-schema tag resolution.
//!
//! ## Pipeline
//!
//! ```text
//! bytes ─► scanner.zig ─► parser.zig ─► Event ─► compose.zig ─► Value
//!          tokens         state machine          + core schema
//!                                       └──────► events.zig (test-suite text)
//! ```
//!
//! The staging is the one every production YAML implementation converged on,
//! and it is load-bearing rather than decorative: indentation and the "is this
//! scalar a mapping key?" lookahead are *scanner* problems (the scanner
//! synthesizes `BlockMappingStart`/`BlockEnd` tokens that have no textual form
//! and splices `Key` tokens in retroactively), node shape and implicit empty
//! scalars are *parser* problems, and anchors, aliases and tag resolution are
//! *composer* problems. Fusing any two produces the classic YAML parser that
//! cannot decide where a block ends.
//!
//! ## Two entry points
//!
//! Most callers want `composeAll` / `compose` — native `Value` trees with the
//! YAML 1.2 core schema applied. Reach for `Parser` directly when the event
//! stream itself is the point: streaming over a document too large to hold, or
//! preserving distinctions the value layer deliberately drops (scalar style,
//! which nodes were aliases, tag text on unknown tags).
//!
//! ```zig
//! // values
//! const doc = try yaml.compose(gpa, "port: 8080\nhosts: [a, b]\n", .{});
//! defer doc.deinit();
//! const port = doc.root.get("port").?.int; // 8080, an int — not "8080"
//!
//! // events
//! var p = yaml.Parser.init(gpa, source);
//! defer p.deinit();
//! while (try p.next()) |ev| switch (ev) {
//!     .scalar => |s| std.debug.print("scalar {s}\n", .{s.value}),
//!     else => {},
//! };
//! ```
//!
//! ## Lifetime
//!
//! Both layers are arena-backed. `Parser` owns an arena and every slice
//! reachable from an `Event` lives in it until `deinit()`. `Composed`/`Single`
//! own one too — necessarily, because aliases *share* nodes rather than copying
//! them, and a shared DAG cannot be freed node by node. Pass your own arena to
//! `composeAllLeaky` if you would rather own the lifetime. In every case the
//! source slice is borrowed only for the duration of the call.
//!
//! ## Verification
//!
//! The oracle is the **yaml-test-suite** (`github.com/yaml/yaml-test-suite`,
//! `data` branch), both layers: 402 byte-exact event dumps (94 of them inputs
//! that must be *rejected*) and 279 `in.json` value oracles.
//! `src/suite_test.zig` runs every case and asserts a committed ledger
//! (`src/testdata/ledger.txt`) exactly — in both directions, so a case that
//! starts passing without the ledger being updated fails the build just as
//! loudly as a regression. See SPEC.md.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "YAML 1.2 spec (yaml.org/spec/1.2.2) + libyaml's scanner/parser staging",
    .deps = .{}, // std only
};

pub const scanner = @import("scanner.zig");
pub const parser = @import("parser.zig");
pub const events = @import("events.zig");
pub const compose_mod = @import("compose.zig");

pub const Parser = parser.Parser;
pub const Event = parser.Event;
pub const ScalarStyle = parser.ScalarStyle;
pub const CollectionStyle = parser.CollectionStyle;
pub const Mark = parser.Mark;

/// `error.InvalidYaml` for every malformed input; `Parser.problem` /
/// `Parser.problem_mark` carry the human-readable detail.
pub const Error = parser.Error;

pub const Value = compose_mod.Value;
pub const Pair = compose_mod.Pair;
pub const Composed = compose_mod.Composed;
pub const Single = compose_mod.Single;
pub const ComposeOptions = compose_mod.Options;
pub const ComposeError = compose_mod.Error;

/// Compose every document in `source` into native `Value` trees (Part 2).
pub const composeAll = compose_mod.composeAll;
/// As `composeAll`, allocating from a caller-owned arena and freeing nothing.
pub const composeAllLeaky = compose_mod.composeAllLeaky;
/// Compose a stream that must hold exactly one document.
pub const compose = compose_mod.compose;

pub const Token = scanner.Token;
pub const TokenKind = scanner.TokenKind;

/// Parse `source` and render the whole event stream in yaml-test-suite
/// `test.event` form. Caller owns the returned bytes.
///
/// On a malformed input this returns the parse error, having already written
/// nothing — use `Parser` directly if the events emitted before the error are
/// wanted (the test-suite `error` cases keep a truncated prefix that way).
pub fn dumpEvents(gpa: std.mem.Allocator, source: []const u8) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    var p = Parser.init(gpa, source);
    defer p.deinit();
    while (try p.next()) |ev| {
        events.writeEvent(&aw.writer, ev) catch return error.OutOfMemory;
    }
    return gpa.dupe(u8, aw.written());
}

// Multi-file module: the aggregator below is what pulls each submodule's
// tests into the test binary (CONVENTIONS.md §6.3 — a bare `pub const`
// re-export does not).
test {
    _ = scanner;
    _ = parser;
    _ = events;
    _ = compose_mod;
    _ = @import("suite_test.zig");
}

// ── unit tests ──────────────────────────────────────────────────────────────

const testing = std.testing;

fn expectEvents(source: []const u8, want: []const u8) !void {
    const got = try dumpEvents(testing.allocator, source);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(want, got);
}

fn expectReject(source: []const u8) !void {
    const got = dumpEvents(testing.allocator, source) catch return;
    testing.allocator.free(got);
    return error.TestExpectedRejection;
}

test "block mapping" {
    try expectEvents("a: 1\nb: 2\n",
        \\+STR
        \\+DOC
        \\+MAP
        \\=VAL :a
        \\=VAL :1
        \\=VAL :b
        \\=VAL :2
        \\-MAP
        \\-DOC
        \\-STR
        \\
    );
}

test "block sequence with nested mapping" {
    try expectEvents("- x: 1\n- y\n",
        \\+STR
        \\+DOC
        \\+SEQ
        \\+MAP
        \\=VAL :x
        \\=VAL :1
        \\-MAP
        \\=VAL :y
        \\-SEQ
        \\-DOC
        \\-STR
        \\
    );
}

test "flow collections carry the flow marker" {
    try expectEvents("[a, {b: c}]\n",
        \\+STR
        \\+DOC
        \\+SEQ []
        \\=VAL :a
        \\+MAP {}
        \\=VAL :b
        \\=VAL :c
        \\-MAP
        \\-SEQ
        \\-DOC
        \\-STR
        \\
    );
}

test "literal and folded block scalars" {
    try expectEvents("l: |\n  a\n  b\nf: >\n  a\n  b\n",
        \\+STR
        \\+DOC
        \\+MAP
        \\=VAL :l
        \\=VAL |a\nb\n
        \\=VAL :f
        \\=VAL >a b\n
        \\-MAP
        \\-DOC
        \\-STR
        \\
    );
}

test "chomping indicators" {
    try expectEvents("s: |-\n  a\n\nk: |+\n  a\n\n",
        \\+STR
        \\+DOC
        \\+MAP
        \\=VAL :s
        \\=VAL |a
        \\=VAL :k
        \\=VAL |a\n\n
        \\-MAP
        \\-DOC
        \\-STR
        \\
    );
}

test "double-quoted escapes and folding" {
    try expectEvents("\"a\\tb\\nc\"\n",
        \\+STR
        \\+DOC
        \\=VAL "a\tb\nc
        \\-DOC
        \\-STR
        \\
    );
}

test "anchors, aliases and tag shorthands" {
    try expectEvents("- &a !!str x\n- *a\n",
        \\+STR
        \\+DOC
        \\+SEQ
        \\=VAL &a <tag:yaml.org,2002:str> :x
        \\=ALI *a
        \\-SEQ
        \\-DOC
        \\-STR
        \\
    );
}

test "explicit document markers and directives" {
    try expectEvents("%YAML 1.2\n---\nx\n...\n",
        \\+STR
        \\+DOC ---
        \\=VAL :x
        \\-DOC ...
        \\-STR
        \\
    );
}

test "custom %TAG handle" {
    try expectEvents("%TAG !e! tag:example.com,2000:app/\n---\n!e!foo bar\n",
        \\+STR
        \\+DOC ---
        \\=VAL <tag:example.com,2000:app/foo> :bar
        \\-DOC
        \\-STR
        \\
    );
}

test "explicit key syntax" {
    try expectEvents("? a\n: b\n",
        \\+STR
        \\+DOC
        \\+MAP
        \\=VAL :a
        \\=VAL :b
        \\-MAP
        \\-DOC
        \\-STR
        \\
    );
}

test "rejects an undefined tag handle" {
    try expectReject("!e!foo bar\n");
}

test "rejects a value indicator with no key context" {
    try expectReject("- a\n- b: c\n  d: e\n  - f\n");
}

test "arbitrary input never panics" {
    // A parser that touches bytes it did not produce is held to a never-panic
    // threat model (CONVENTIONS.md §7.1). Short adversarial strings over the
    // full indicator alphabet, all outcomes acceptable except a crash.
    const alphabet = "-?:,[]{}#&*!|>'\"%@` \tabc\n";
    var seed: u64 = 0x9E3779B97F4A7C15;
    var buf: [24]u8 = undefined;
    for (0..4000) |_| {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        var s = seed;
        // `s % buf.len` is always `< buf.len` (24) regardless of `s`'s width,
        // so the cast can never truncate a value that reaches it — this is
        // a fuzz byte-count bound, not a quantity that needed `u64`.
        const n: usize = 1 + @as(usize, @intCast(s % buf.len));
        for (buf[0..n]) |*b| {
            s = s *% 6364136223846793005 +% 1442695040888963407;
            // Same always-in-range modulo as `n` above.
            b.* = alphabet[@as(usize, @intCast((s >> 33) % alphabet.len))];
        }
        const out = dumpEvents(testing.allocator, buf[0..n]) catch continue;
        testing.allocator.free(out);
    }
}
