// SPDX-License-Identifier: MIT
//! yaml — a YAML **1.2** scanner + parser producing a streaming *event* view
//! of a document stream (Part 1 of the module: no native-value composer yet).
//!
//! ## Pipeline
//!
//! ```text
//! bytes ──► scanner.zig ──► parser.zig ──► Event stream ──► events.zig (text)
//!           tokens          state machine                   test-suite form
//! ```
//!
//! The three-stage split is the one every production YAML implementation
//! converged on, and it is load-bearing rather than decorative: indentation
//! and the "is this scalar a mapping key?" lookahead are *scanner* problems
//! (the scanner synthesizes `BlockMappingStart`/`BlockEnd` tokens that have no
//! textual form and splices `Key` tokens in retroactively), while node shape
//! and implicit empty scalars are *parser* problems. Fusing them produces the
//! classic YAML parser that cannot decide where a block ends.
//!
//! ## Scope of this part
//!
//! Everything up to and including events: block and flow collections, the five
//! scalar styles with their folding/chomping rules, multi-document streams,
//! `%YAML`/`%TAG` directives, anchors/aliases, explicit `?`/`:` keys, tag
//! shorthands and verbatim tags. **Not** here: the composer (alias resolution
//! into a graph), the core schema (`null`/`bool`/`int`/`float` recognition)
//! and any native-value API. Those are Part 2 — an event consumer, not a
//! change to this layer.
//!
//! ## Lifetime
//!
//! `Parser` owns an arena. Every slice reachable from an `Event` — scalar
//! text, anchor names, resolved tags — lives in that arena and stays valid
//! until `deinit()`. Events are therefore cheap to hold on to across `next()`
//! calls, at the cost of the arena growing with the document. A consumer that
//! must bound memory over a huge stream should copy what it needs and run one
//! `Parser` per document.
//!
//! ## Verification
//!
//! The oracle is the **yaml-test-suite** (`github.com/yaml/yaml-test-suite`,
//! `data` branch): 402 cases, each a byte-exact expected event dump, 94 of
//! them inputs that must be *rejected*. `src/suite_test.zig` runs all 402 and
//! asserts a committed ledger (`src/testdata/ledger.txt`) exactly — in both
//! directions, so a case that starts passing without the ledger being updated
//! fails the build just as loudly as a regression. See SPEC.md.
//!
//! ```zig
//! var p = yaml.Parser.init(gpa, source);
//! defer p.deinit();
//! while (try p.next()) |ev| switch (ev) {
//!     .scalar => |s| std.debug.print("scalar {s}\n", .{s.value}),
//!     else => {},
//! }
//! ```

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

pub const Parser = parser.Parser;
pub const Event = parser.Event;
pub const ScalarStyle = parser.ScalarStyle;
pub const CollectionStyle = parser.CollectionStyle;
pub const Mark = parser.Mark;

/// `error.InvalidYaml` for every malformed input; `Parser.problem` /
/// `Parser.problem_mark` carry the human-readable detail.
pub const Error = parser.Error;

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
        const n = 1 + (s % buf.len);
        for (buf[0..n]) |*b| {
            s = s *% 6364136223846793005 +% 1442695040888963407;
            b.* = alphabet[(s >> 33) % alphabet.len];
        }
        const out = dumpEvents(testing.allocator, buf[0..n]) catch continue;
        testing.allocator.free(out);
    }
}
