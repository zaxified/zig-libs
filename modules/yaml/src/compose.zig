// SPDX-License-Identifier: MIT
//! Stage 3: the **composer** — the event stream of `parser.zig` turned into a
//! native `Value` tree, with YAML 1.2 **core schema** tag resolution (§10.2).
//!
//! This is where anchors and aliases stop being syntax and become structure,
//! and where an untagged plain `123` stops being the three bytes `123` and
//! becomes an integer.
//!
//! ## What an alias produces
//!
//! An alias **shares** the anchored node; it does not copy it. `Value` is a
//! small by-value union whose collection variants are slices into the arena, so
//! two aliases of one anchor carry the same slice pointer and the children are
//! genuinely shared. The result is a DAG, not a tree.
//!
//! Sharing is also the defence against the "billion laughs" expansion bomb
//! (`&a [x,x]`, `&b [*a,*a]`, `&c [*b,*b]`, …): each alias costs one 24-byte
//! union copy rather than a deep copy, so an input that would expand to 2^n
//! nodes composes into n. A consumer that walks the DAG *as if* it were a tree
//! still sees 2^n paths — that is inherent to the format, and it is why
//! `Options.max_nodes` exists as well.
//!
//! ## Cycles are rejected — see SPEC.md §7 for the full reasoning
//!
//! YAML 1.2 §3.2.1 permits a cyclic representation graph (an alias may name an
//! ancestor). This composer rejects that with `error.AliasCycle`. The detection
//! is structural rather than a post-hoc graph search: a collection registers its
//! anchor *before* composing its children, marked in-progress, and an alias that
//! resolves to an in-progress anchor is by definition an ancestor reference. A
//! cycle is therefore never constructed, which is what lets `Value` stay a
//! by-value union that any consumer can walk without a visited-set.

const std = @import("std");
const parser = @import("parser.zig");

const Event = parser.Event;

/// A composed YAML node.
///
/// Owns nothing: every slice — `string`, `sequence`, `mapping` — is allocated
/// from whatever allocator produced the tree (an arena, in practice, because
/// aliases share nodes and a shared DAG cannot be freed node-by-node).
pub const Value = union(enum) {
    null,
    bool: bool,
    /// `tag:yaml.org,2002:int`. Values outside `i64` stay `.string`; see
    /// `resolvePlain`.
    int: i64,
    float: f64,
    string: []const u8,
    sequence: []const Value,
    /// An **ordered** list of pairs, not a hash map: YAML mapping keys may be
    /// any node (a sequence, a mapping, an empty scalar), and the format does
    /// not require them to be unique. Both facts are preserved here rather than
    /// flattened into something that cannot express them.
    mapping: []const Pair,

    /// The value for the first pair whose key is exactly the string `key`.
    /// Only string keys are considered — a non-string key can never equal one.
    pub fn get(self: Value, key: []const u8) ?Value {
        const pairs = switch (self) {
            .mapping => |m| m,
            else => return null,
        };
        for (pairs) |p| switch (p.key) {
            .string => |k| if (std.mem.eql(u8, k, key)) return p.value,
            else => {},
        };
        return null;
    }

    /// The `i`-th element of a sequence, or null for a non-sequence / out of
    /// range.
    pub fn at(self: Value, i: usize) ?Value {
        const items = switch (self) {
            .sequence => |s| s,
            else => return null,
        };
        return if (i < items.len) items[i] else null;
    }

    pub fn isNull(self: Value) bool {
        return self == .null;
    }
};

pub const Pair = struct {
    key: Value,
    value: Value,
};

pub const Error = parser.Error || error{
    /// An alias named an anchor that is still being composed — i.e. one of its
    /// own ancestors. See the module doc-comment and SPEC.md §7.
    AliasCycle,
    /// An alias named an anchor that has not been defined.
    UnknownAlias,
    /// An explicit core-schema tag whose content does not match it, e.g.
    /// `!!int nope`.
    BadTaggedScalar,
    /// `Options.max_nodes` or `Options.max_depth` exceeded.
    TooManyNodes,
    TooDeep,
};

pub const Options = struct {
    /// Total composed nodes across the stream. Aliases share rather than copy,
    /// so this bounds real memory rather than expanded size.
    max_nodes: usize = 10_000_000,
    /// Nesting depth. The parser already refuses to nest past
    /// `scanner.max_depth`, so this is a second, independent bound that also
    /// keeps `composeNode`'s recursion off the end of the stack.
    max_depth: usize = 1024,
};

/// A composed stream that owns its own arena. Mirrors `std.json.Parsed`: the
/// arena lives behind a pointer so the struct is freely movable.
pub const Composed = struct {
    arena: *std.heap.ArenaAllocator,
    /// One entry per document in the stream. A stream may legitimately have
    /// none (`...` alone), and an empty document's root is `.null`.
    documents: []const Value,

    pub fn deinit(self: Composed) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

/// Compose every document in `source`. The returned `Composed` owns an arena;
/// call `deinit`. `source` is borrowed only for the duration of the call —
/// every byte reachable from a `Value` is copied into the arena.
pub fn composeAll(gpa: std.mem.Allocator, source: []const u8, options: Options) Error!Composed {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    errdefer gpa.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();

    const docs = try composeAllLeaky(arena.allocator(), source, options);
    return .{ .arena = arena, .documents = docs };
}

/// As `composeAll`, but allocating everything from `alloc` and freeing nothing.
/// Pass an arena you already own. Mirrors `std.json.parseFromSliceLeaky`.
pub fn composeAllLeaky(alloc: std.mem.Allocator, source: []const u8, options: Options) Error![]const Value {
    var p = parser.Parser.init(alloc, source);
    defer p.deinit();

    var c: Composer = .{ .alloc = alloc, .p = &p, .options = options };
    return c.run();
}

/// Compose a stream that must hold exactly one document, and return its root.
/// `error.ExpectedSingleDocument` for zero or several.
pub fn compose(gpa: std.mem.Allocator, source: []const u8, options: Options) (Error || error{ExpectedSingleDocument})!Single {
    const all = try composeAll(gpa, source, options);
    errdefer all.deinit();
    if (all.documents.len != 1) return error.ExpectedSingleDocument;
    return .{ .arena = all.arena, .root = all.documents[0] };
}

pub const Single = struct {
    arena: *std.heap.ArenaAllocator,
    root: Value,

    pub fn deinit(self: Single) void {
        const gpa = self.arena.child_allocator;
        self.arena.deinit();
        gpa.destroy(self.arena);
    }
};

// ── the composer ────────────────────────────────────────────────────────────

/// An anchor's binding. `in_progress` is the cycle detector: it is true from
/// the moment a collection's anchor is registered until that collection is
/// closed, which is exactly the window in which an alias to it would be an
/// ancestor reference.
const Anchor = struct {
    name: []const u8,
    value: Value,
    in_progress: bool,
};

const Composer = struct {
    alloc: std.mem.Allocator,
    p: *parser.Parser,
    options: Options,
    anchors: std.ArrayList(Anchor) = .empty,
    nodes: usize = 0,
    /// One-event pushback, so a collection can test for its end marker.
    peeked: ?Event = null,

    fn next(self: *Composer) Error!?Event {
        if (self.peeked) |e| {
            self.peeked = null;
            return e;
        }
        return self.p.next();
    }

    fn peek(self: *Composer) Error!?Event {
        if (self.peeked == null) self.peeked = try self.p.next();
        return self.peeked;
    }

    fn run(self: *Composer) Error![]const Value {
        var docs: std.ArrayList(Value) = .empty;

        const first = try self.next();
        if (first == null or first.? != .stream_start) return error.InvalidYaml;

        while (true) {
            const ev = (try self.next()) orelse break;
            switch (ev) {
                .stream_end => break,
                .document_start => {
                    // Anchors do not cross document boundaries (YAML 1.2 §3.2.2).
                    self.anchors.clearRetainingCapacity();
                    const root = try self.composeNode(0);
                    const end = (try self.next()) orelse return error.InvalidYaml;
                    if (end != .document_end) return error.InvalidYaml;
                    try docs.append(self.alloc, root);
                },
                else => return error.InvalidYaml,
            }
        }
        return docs.items;
    }

    fn account(self: *Composer, depth: usize) Error!void {
        self.nodes += 1;
        if (self.nodes > self.options.max_nodes) return error.TooManyNodes;
        if (depth > self.options.max_depth) return error.TooDeep;
    }

    /// Registers `name` before the node exists, so an alias inside the node
    /// sees `in_progress`. Returns the slot index for `finishAnchor`.
    fn beginAnchor(self: *Composer, name: ?[]const u8) Error!?usize {
        const n = name orelse return null;
        // A repeated anchor name rebinds it; later aliases see the newer node
        // (YAML 1.2 §3.2.2 — anchors are not required to be unique).
        for (self.anchors.items, 0..) |*a, i| {
            if (std.mem.eql(u8, a.name, n)) {
                a.* = .{ .name = a.name, .value = .null, .in_progress = true };
                return i;
            }
        }
        try self.anchors.append(self.alloc, .{ .name = n, .value = .null, .in_progress = true });
        return self.anchors.items.len - 1;
    }

    fn finishAnchor(self: *Composer, slot: ?usize, v: Value) void {
        const i = slot orelse return;
        self.anchors.items[i].value = v;
        self.anchors.items[i].in_progress = false;
    }

    fn composeNode(self: *Composer, depth: usize) Error!Value {
        try self.account(depth);
        const ev = (try self.next()) orelse return error.InvalidYaml;
        switch (ev) {
            .alias => |a| {
                for (self.anchors.items) |anc| {
                    if (!std.mem.eql(u8, anc.name, a.anchor)) continue;
                    if (anc.in_progress) return error.AliasCycle;
                    return anc.value;
                }
                return error.UnknownAlias;
            },
            .scalar => |s| {
                const slot = try self.beginAnchor(s.anchor);
                const v = try self.resolveScalar(s.value, s.style, s.tag);
                self.finishAnchor(slot, v);
                return v;
            },
            .sequence_start => |c| {
                const slot = try self.beginAnchor(c.anchor);
                var items: std.ArrayList(Value) = .empty;
                while (true) {
                    const nxt = (try self.peek()) orelse return error.InvalidYaml;
                    if (nxt == .sequence_end) {
                        _ = try self.next();
                        break;
                    }
                    try items.append(self.alloc, try self.composeNode(depth + 1));
                }
                const v: Value = .{ .sequence = items.items };
                self.finishAnchor(slot, v);
                return v;
            },
            .mapping_start => |c| {
                const slot = try self.beginAnchor(c.anchor);
                var pairs: std.ArrayList(Pair) = .empty;
                while (true) {
                    const nxt = (try self.peek()) orelse return error.InvalidYaml;
                    if (nxt == .mapping_end) {
                        _ = try self.next();
                        break;
                    }
                    const k = try self.composeNode(depth + 1);
                    const val = try self.composeNode(depth + 1);
                    try pairs.append(self.alloc, .{ .key = k, .value = val });
                }
                const v: Value = .{ .mapping = pairs.items };
                self.finishAnchor(slot, v);
                return v;
            },
            else => return error.InvalidYaml,
        }
    }

    fn resolveScalar(self: *Composer, text: []const u8, style: parser.ScalarStyle, tag: ?[]const u8) Error!Value {
        const owned = try self.alloc.dupe(u8, text);
        if (tag) |t| return resolveTagged(owned, t);
        // Only *plain* scalars are resolved by the schema. A quoted, literal or
        // folded scalar is a string however it reads — `"true"` is not a bool
        // (YAML 1.2 §10.2.2).
        if (style != .plain) return .{ .string = owned };
        return resolvePlain(owned);
    }
};

// ── core schema resolution (YAML 1.2 §10.2.2) ───────────────────────────────

const core_null = "tag:yaml.org,2002:null";
const core_bool = "tag:yaml.org,2002:bool";
const core_int = "tag:yaml.org,2002:int";
const core_float = "tag:yaml.org,2002:float";
const core_str = "tag:yaml.org,2002:str";

/// An explicit tag overrides schema resolution. A tag this schema does not know
/// — `!foo`, `!<!bar>`, `tag:example.com,2000:app/light` — leaves the scalar as
/// its literal text: only the application that defined the tag can say what it
/// means, and guessing would be worse than handing over the bytes. The suite
/// agrees (`5TYM`, `CC74`, `6WLZ`, `7FWL` all expect the raw string).
fn resolveTagged(text: []const u8, tag: []const u8) Error!Value {
    if (std.mem.eql(u8, tag, core_str)) return .{ .string = text };
    if (std.mem.eql(u8, tag, core_null)) return .null;
    if (std.mem.eql(u8, tag, core_bool)) {
        return parseBool(text) orelse error.BadTaggedScalar;
    }
    if (std.mem.eql(u8, tag, core_int)) {
        if (!isIntShape(text)) return error.BadTaggedScalar;
        // Same rule as untagged: an int too large for `i64` keeps its text
        // rather than being reinterpreted.
        return parseInt(text) orelse .{ .string = text };
    }
    if (std.mem.eql(u8, tag, core_float)) {
        // `parseFloat` already accepts an integer-shaped body, so `!!float 1`
        // is the float 1.0 without a separate integer path.
        return parseFloat(text) orelse error.BadTaggedScalar;
    }
    return .{ .string = text };
}

/// The core schema's resolution order for an untagged plain scalar:
/// null, then bool, then int, then float, then str (§10.2.2).
///
/// This is the **1.2 core** schema, not 1.1: no `yes`/`no`/`on`/`off` booleans,
/// no sexagesimals, no bare-leading-zero octal (`0777` is decimal 777), and
/// octal is spelled `0o`.
fn resolvePlain(text: []const u8) Value {
    if (parseNull(text)) return .null;
    if (parseBool(text)) |b| return b;
    // Int is tested by *shape* first, and a shape match never falls through to
    // float. It would otherwise: `parseFloat` accepts bare digits, so an
    // integer too large for `i64` would silently become
    // `1.2345678901234568e29` — a lossy reinterpretation of a value the schema
    // says is an integer. Keeping the exact text is the honest answer.
    if (isIntShape(text)) return parseInt(text) orelse .{ .string = text };
    if (parseFloat(text)) |f| return f;
    return .{ .string = text };
}

fn parseNull(t: []const u8) bool {
    return t.len == 0 or
        std.mem.eql(u8, t, "~") or
        std.mem.eql(u8, t, "null") or
        std.mem.eql(u8, t, "Null") or
        std.mem.eql(u8, t, "NULL");
}

fn parseBool(t: []const u8) ?Value {
    if (std.mem.eql(u8, t, "true") or std.mem.eql(u8, t, "True") or std.mem.eql(u8, t, "TRUE"))
        return .{ .bool = true };
    if (std.mem.eql(u8, t, "false") or std.mem.eql(u8, t, "False") or std.mem.eql(u8, t, "FALSE"))
        return .{ .bool = false };
    return null;
}

/// `[-+]? [0-9]+` | `0o [0-7]+` | `0x [0-9a-fA-F]+`
///
/// A value that matches but does not fit an `i64` stays a **string** holding
/// the original text — see SPEC.md §8. No suite case exercises it; the unit
/// test below pins the behaviour so it cannot change by accident.
fn isIntShape(t: []const u8) bool {
    if (t.len == 0) return false;
    if (std.mem.startsWith(u8, t, "0o")) {
        if (t.len == 2) return false;
        for (t[2..]) |c| if (c < '0' or c > '7') return false;
        return true;
    }
    if (std.mem.startsWith(u8, t, "0x")) {
        if (t.len == 2) return false;
        for (t[2..]) |c| if (!std.ascii.isHex(c)) return false;
        return true;
    }
    var i: usize = 0;
    if (t[0] == '-' or t[0] == '+') i = 1;
    if (i >= t.len) return false;
    for (t[i..]) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// Null both for "not an integer" and for "an integer that does not fit
/// `i64`"; callers distinguish with `isIntShape`.
fn parseInt(t: []const u8) ?Value {
    if (!isIntShape(t)) return null;
    const v = if (std.mem.startsWith(u8, t, "0o"))
        std.fmt.parseInt(i64, t[2..], 8) catch return null
    else if (std.mem.startsWith(u8, t, "0x"))
        std.fmt.parseInt(i64, t[2..], 16) catch return null
    else
        std.fmt.parseInt(i64, t, 10) catch return null;
    return .{ .int = v };
}

/// `[-+]? ( \.[0-9]+ | [0-9]+ ( \.[0-9]* )? ) ( [eE] [-+]? [0-9]+ )?`
/// | `[-+]? ( \.inf | \.Inf | \.INF )` | `\.nan | \.NaN | \.NAN`
///
/// The shape is validated here rather than delegated to `std.fmt.parseFloat`,
/// which is far more permissive: it would accept bare `inf`, `nan` and hex
/// floats, none of which the core schema resolves as numbers.
fn parseFloat(t: []const u8) ?Value {
    if (std.mem.eql(u8, t, ".nan") or std.mem.eql(u8, t, ".NaN") or std.mem.eql(u8, t, ".NAN"))
        return .{ .float = std.math.nan(f64) };

    var s = t;
    var neg = false;
    if (s.len > 0 and (s[0] == '-' or s[0] == '+')) {
        neg = s[0] == '-';
        s = s[1..];
    }
    if (std.mem.eql(u8, s, ".inf") or std.mem.eql(u8, s, ".Inf") or std.mem.eql(u8, s, ".INF"))
        return .{ .float = if (neg) -std.math.inf(f64) else std.math.inf(f64) };

    // mantissa
    var i: usize = 0;
    var saw_digit = false;
    if (i < s.len and s[i] == '.') {
        i += 1;
        const start = i;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
        if (i == start) return null; // `.` alone, or `.e5`
        saw_digit = true;
    } else {
        const start = i;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
        if (i == start) return null;
        saw_digit = true;
        if (i < s.len and s[i] == '.') {
            i += 1;
            while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
        }
    }
    if (!saw_digit) return null;
    // exponent
    if (i < s.len and (s[i] == 'e' or s[i] == 'E')) {
        i += 1;
        if (i < s.len and (s[i] == '-' or s[i] == '+')) i += 1;
        const start = i;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
        if (i == start) return null;
    }
    if (i != s.len) return null;

    const f = std.fmt.parseFloat(f64, t) catch return null;
    return .{ .float = f };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn single(src: []const u8) !Single {
    return compose(testing.allocator, src, .{});
}

test "core schema resolves the five kinds" {
    const r = try single("a: null\nb: true\nc: 42\nd: 0.5\ne: hello\n");
    defer r.deinit();
    try testing.expect(r.root.get("a").?.isNull());
    try testing.expectEqual(true, r.root.get("b").?.bool);
    try testing.expectEqual(@as(i64, 42), r.root.get("c").?.int);
    try testing.expectEqual(@as(f64, 0.5), r.root.get("d").?.float);
    try testing.expectEqualStrings("hello", r.root.get("e").?.string);
}

test "every core-schema spelling, including the ones no oracle reaches" {
    // ⭐ Nothing else pins these. The suite has no case where a bare `~` or a
    // capitalised `NULL`/`True` is a resolved scalar with a JSON oracle beside
    // it, and JSON cannot express infinity or NaN at all — so for half of these
    // an external vector does not merely happen to be missing, it cannot exist.
    //
    // Not a hypothetical gap: making `~` resolve to a string instead of null
    // left all 39 test blocks AND all 402 suite cases green.
    const r = try single(
        \\a: ~
        \\b: Null
        \\c: NULL
        \\d: True
        \\e: TRUE
        \\f: False
        \\g: FALSE
        \\h: .Inf
        \\i: .INF
        \\j: -.Inf
        \\k: .NaN
        \\l: .NAN
        \\
    );
    defer r.deinit();
    try testing.expect(r.root.get("a").?.isNull());
    try testing.expect(r.root.get("b").?.isNull());
    try testing.expect(r.root.get("c").?.isNull());
    try testing.expectEqual(true, r.root.get("d").?.bool);
    try testing.expectEqual(true, r.root.get("e").?.bool);
    try testing.expectEqual(false, r.root.get("f").?.bool);
    try testing.expectEqual(false, r.root.get("g").?.bool);
    try testing.expect(std.math.isPositiveInf(r.root.get("h").?.float));
    try testing.expect(std.math.isPositiveInf(r.root.get("i").?.float));
    try testing.expect(std.math.isNegativeInf(r.root.get("j").?.float));
    try testing.expect(std.math.isNan(r.root.get("k").?.float));
    try testing.expect(std.math.isNan(r.root.get("l").?.float));
}

test "core schema is 1.2, not 1.1" {
    const r = try single("a: yes\nb: no\nc: on\nd: off\ne: 0777\nf: 1:30\n");
    defer r.deinit();
    // 1.1 would make these booleans; the core schema does not.
    try testing.expectEqualStrings("yes", r.root.get("a").?.string);
    try testing.expectEqualStrings("no", r.root.get("b").?.string);
    try testing.expectEqualStrings("on", r.root.get("c").?.string);
    try testing.expectEqualStrings("off", r.root.get("d").?.string);
    // 1.1 would read this as octal 511; core schema says decimal.
    try testing.expectEqual(@as(i64, 777), r.root.get("e").?.int);
    // 1.1 sexagesimal; core schema says string.
    try testing.expectEqualStrings("1:30", r.root.get("f").?.string);
}

test "only plain scalars are resolved" {
    const r = try single("a: \"true\"\nb: '42'\nc: |\n  null\n");
    defer r.deinit();
    try testing.expectEqualStrings("true", r.root.get("a").?.string);
    try testing.expectEqualStrings("42", r.root.get("b").?.string);
    try testing.expectEqualStrings("null\n", r.root.get("c").?.string);
}

test "int forms and float forms" {
    const r = try single("a: 0x1F\nb: 0o17\nc: -7\nd: +7\ne: 1e3\nf: .5\ng: 1998.\nh: .inf\ni: -.inf\n");
    defer r.deinit();
    try testing.expectEqual(@as(i64, 31), r.root.get("a").?.int);
    try testing.expectEqual(@as(i64, 15), r.root.get("b").?.int);
    try testing.expectEqual(@as(i64, -7), r.root.get("c").?.int);
    try testing.expectEqual(@as(i64, 7), r.root.get("d").?.int);
    try testing.expectEqual(@as(f64, 1000), r.root.get("e").?.float);
    try testing.expectEqual(@as(f64, 0.5), r.root.get("f").?.float);
    try testing.expectEqual(@as(f64, 1998), r.root.get("g").?.float);
    try testing.expect(std.math.isPositiveInf(r.root.get("h").?.float));
    try testing.expect(std.math.isNegativeInf(r.root.get("i").?.float));
}

test ".nan resolves to a float NaN" {
    // No suite case covers `.inf`/`.nan` at all — the JSON oracle cannot
    // express them — so these are pinned here or nowhere.
    const r = try single("x: .nan\n");
    defer r.deinit();
    try testing.expect(std.math.isNan(r.root.get("x").?.float));
}

test "near-miss numbers stay strings" {
    const r = try single("a: 1e\nb: .\nc: 0x\nd: 0o9\ne: inf\nf: nan\ng: 1_000\nh: +-3\n");
    defer r.deinit();
    for ([_][]const u8{ "a", "b", "c", "d", "e", "f", "g", "h" }) |k| {
        try testing.expect(r.root.get(k).? == .string);
    }
}

test "an integer too large for i64 stays a string holding its text" {
    // Documented limitation (SPEC.md §8): no suite case exercises it, so this
    // test is the only thing keeping the behaviour deliberate.
    const r = try single("x: 123456789012345678901234567890\n");
    defer r.deinit();
    try testing.expectEqualStrings("123456789012345678901234567890", r.root.get("x").?.string);
}

test "explicit tags override resolution" {
    const r = try single("a: !!str 42\nb: !!int 7\nc: !!float 1\nd: !!bool true\ne: !!null x\n");
    defer r.deinit();
    try testing.expectEqualStrings("42", r.root.get("a").?.string);
    try testing.expectEqual(@as(i64, 7), r.root.get("b").?.int);
    try testing.expectEqual(@as(f64, 1), r.root.get("c").?.float);
    try testing.expectEqual(true, r.root.get("d").?.bool);
    try testing.expect(r.root.get("e").?.isNull());
}

test "an unknown tag leaves the literal text" {
    const r = try single("x: !mytag 42\n");
    defer r.deinit();
    try testing.expectEqualStrings("42", r.root.get("x").?.string);
}

test "a core tag whose body does not match is rejected" {
    try testing.expectError(error.BadTaggedScalar, single("x: !!int nope\n"));
    try testing.expectError(error.BadTaggedScalar, single("x: !!bool maybe\n"));
}

test "aliases share the anchored node" {
    const r = try single("a: &x [1, 2]\nb: *x\n");
    defer r.deinit();
    const a = r.root.get("a").?.sequence;
    const b = r.root.get("b").?.sequence;
    // Same slice, not a copy — this is the billion-laughs defence.
    try testing.expectEqual(a.ptr, b.ptr);
}

test "an alias to an ancestor is a cycle and is rejected" {
    try testing.expectError(error.AliasCycle, single("&a [ *a ]\n"));
    try testing.expectError(error.AliasCycle, single("&m { self: *m }\n"));
    // Nested a few levels down is still an ancestor.
    try testing.expectError(error.AliasCycle, single("&a [ [ [ *a ] ] ]\n"));
}

test "a sibling alias is not a cycle" {
    const r = try single("- &a [1]\n- [ *a ]\n");
    defer r.deinit();
    try testing.expectEqual(@as(usize, 2), r.root.sequence.len);
}

test "an undefined alias is rejected" {
    try testing.expectError(error.UnknownAlias, single("x: *nope\n"));
}

test "anchors do not cross documents" {
    try testing.expectError(error.UnknownAlias, single("--- &a 1\n--- *a\n"));
}

test "mapping keys may be non-strings and are kept in order" {
    const r = try single("? [a, b]\n: v\n1: one\n");
    defer r.deinit();
    const m = r.root.mapping;
    try testing.expectEqual(@as(usize, 2), m.len);
    try testing.expect(m[0].key == .sequence);
    try testing.expectEqual(@as(i64, 1), m[1].key.int);
    try testing.expectEqualStrings("one", m[1].value.string);
}

test "duplicate keys are preserved, not collapsed" {
    const r = try single("a: 1\na: 2\n");
    defer r.deinit();
    try testing.expectEqual(@as(usize, 2), r.root.mapping.len);
}

test "multi-document streams and empty documents" {
    const all = try composeAll(testing.allocator, "---\n---\n", .{});
    defer all.deinit();
    try testing.expectEqual(@as(usize, 2), all.documents.len);
    try testing.expect(all.documents[0].isNull());
    try testing.expect(all.documents[1].isNull());

    // `...` alone is a footer, not a document.
    const none = try composeAll(testing.allocator, "...\n", .{});
    defer none.deinit();
    try testing.expectEqual(@as(usize, 0), none.documents.len);
}

test "compose rejects a stream that is not exactly one document" {
    try testing.expectError(error.ExpectedSingleDocument, single("--- 1\n--- 2\n"));
    try testing.expectError(error.ExpectedSingleDocument, single("...\n"));
}

test "the node budget bounds a hostile input" {
    try testing.expectError(error.TooManyNodes, compose(testing.allocator, "[1,2,3,4,5,6]\n", .{ .max_nodes = 3 }));
    try testing.expectError(error.TooDeep, compose(testing.allocator, "[[[[[1]]]]]\n", .{ .max_depth = 2 }));
}

test "a malformed document still fails as a parse error" {
    try testing.expectError(error.InvalidYaml, single("[\n"));
}
