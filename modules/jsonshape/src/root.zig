// SPDX-License-Identifier: MIT
//! jsonshape — reshape JSON into a canonical `dataset`: path descent to
//! array item(s) + typed column projection (jq-style minimal subset — a
//! bounded JSONPath dialect, not the full JSONPath spec).
//!
//! Remote-feed shaping (`getDataview` / `dataviewGet`): resolve `spec.path`
//! to the item(s) to project, then project each item into columns. The path
//! is one of two auto-detected dialects: the original **legacy dot-path**
//! (a dot-separated chain of object-key lookups to one array node, e.g.
//! `"data.prices"`), or **RFC 9535 JSONPath** — names, indices (negative
//! from the end), slices, wildcards, unions, descendants, and filters with
//! `&&`/`||`/`!`, existence tests and `length`/`count`/`value` (no
//! `match`/`search`). Projection
//! has two modes:
//!   * **columns** (generic): `[]JsonCol{name,key,type}` — one column per field.
//!   * **[x,y] default** (when `columns` is empty): 2 columns from
//!     `x`/`y` keys, or positional `item[0]/item[1]` for array items, or
//!     `[index, item]` for scalars.
//!
//! Values are parsed into canonical `dataset.Value`s honoring each column's
//! declared `ColumnType`. Allocates into `a` (a caller-owned arena); the parsed
//! JSON tree lives in the same arena, so string cells borrow it.
//!
//! Provenance: original work of the zig-libs authors (MIT).

const std = @import("std");
const ds = @import("dataset");
const Dataset = ds.Dataset;
const Column = ds.Column;
const ColumnType = ds.ColumnType;
const Value = ds.Value;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "JSON → `dataset` reshaping — dot-path descent and typed column projection (a minimal jq-style subset).",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "jq-style path projection (minimal: one dot-path + field extraction)",
    .deps = .{"dataset"},
};

// ── public API ──────────────────────────────────────────────────────────────

pub const Error = error{
    BadJson,
    OutOfMemory,
    /// The path matched more nodes than `ShapeSpec.max_matches` allows. A
    /// refusal rather than a truncated result — see `MAX_MATCHES`.
    TooManyMatches,
};

pub const JsonCol = struct {
    name: []const u8,
    /// Field name inside each item (object key). Empty = the whole item.
    /// A key containing `.` or `[` that is NOT itself a
    /// field of the item is a path, evaluated from the item with the same
    /// engine as `ShapeSpec.path` (`meta.ts`, `tags[0]`, `prices[-1].v`; a
    /// leading `$` starts at the document root); the cell is the first node
    /// it selects, or null.
    key: []const u8 = "",
    type: ColumnType = .float,
};

pub const ShapeSpec = struct {
    /// Dot-path from the root to the array node (e.g. "data.prices"). Empty = root.
    path: []const u8 = "",
    /// Generic projection. When empty, falls back to the poc `[x,y]` default.
    columns: []const JsonCol = &.{},
    /// poc-compatible shorthand (only used when `columns` is empty).
    x: []const u8 = "",
    y: []const u8 = "",
    /// Refuse a path that yields more than this many nodes — counted BOTH as
    /// matched nodes and as the items those matches flatten into, because one
    /// match that is a large array becomes that many rows while the match
    /// counter still reads 1. See `MAX_MATCHES` for why this refuses rather
    /// than truncating.
    max_matches: usize = MAX_MATCHES,
};

/// Parse `bytes`, resolve `spec.path` to array item(s), project each item to a row.
///
/// `spec.path` accepts two dialects:
///   * **legacy dot-path** (back-compat, unchanged semantics): a plain
///     dot-separated chain of object-key lookups to exactly one array node
///     (e.g. `"data.prices"`). A single non-array match → empty dataset.
///   * **RFC 9535 JSONPath** (triggered by any of `[`, `*`, `?`, `..`, or a
///     leading `$`): see the engine section below. May yield multiple matched nodes (e.g.
///     paginated arrays under a wildcard); each match contributes rows: an
///     `.array` match is flattened (its elements become items), any other
///     match becomes a single item itself.
pub fn shape(a: std.mem.Allocator, bytes: []const u8, spec: ShapeSpec) Error!Dataset {
    const root = std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{}) catch return Error.BadJson;
    const items = try resolveItems(a, root, spec.path, spec.max_matches);

    if (spec.columns.len == 0) return shapeXY(a, root, items, spec);

    const cols = try a.alloc(Column, spec.columns.len);
    const keys = try a.alloc(KeyRef, spec.columns.len);
    for (spec.columns, 0..) |jc, i| {
        cols[i] = .{ .name = jc.name, .type = jc.type };
        keys[i] = try keyRef(a, jc.key);
    }

    const rows = try a.alloc([]const Value, items.len);
    for (items, 0..) |item, ri| {
        const row = try a.alloc(Value, spec.columns.len);
        for (spec.columns, keys, 0..) |jc, kr, ci| {
            const jv: ?std.json.Value = if (jc.key.len == 0) item else try resolveKey(a, root, item, kr, spec.max_matches);
            row[ci] = if (jv) |v| try jsonToValue(a, v, jc.type) else .null;
        }
        rows[ri] = row;
    }
    return .{ .columns = cols, .rows = rows };
}

/// A column key, parsed once: a plain field name, or a path (see `JsonCol.key`).
const KeyRef = struct { key: []const u8, segs: ?[]const Seg };

fn keyRef(a: std.mem.Allocator, key: []const u8) Error!KeyRef {
    const is_path = std.mem.indexOfAny(u8, key, ".[") != null;
    return .{ .key = key, .segs = if (is_path) try parsePath(a, key) else null };
}

/// The item's own field named `kr.key` first — v1 behaviour, so an existing
/// key that merely contains a dot still reads that field — else the first node
/// the key's path selects (from the item, or from the root for `$…`).
fn resolveKey(a: std.mem.Allocator, root: std.json.Value, item: std.json.Value, kr: KeyRef, limit: usize) Error!?std.json.Value {
    if (itemField(item, kr.key)) |v| return v;
    const segs = kr.segs orelse return null;
    var ctx: Ctx = .{ .a = a, .root = root, .stop_after = 1, .limit = limit };
    try evalSegs(&ctx, if (kr.key[0] == '$') root else item, segs, 0);
    return ctx.found;
}

/// poc `[x,y]` default: 2 columns, one row per item.
fn shapeXY(a: std.mem.Allocator, root: std.json.Value, items: []const std.json.Value, spec: ShapeSpec) Error!Dataset {
    const xk = try keyRef(a, spec.x);
    const yk = try keyRef(a, spec.y);
    const cols = try a.alloc(Column, 2);
    cols[0] = .{ .name = "x", .type = .text };
    cols[1] = .{ .name = "y", .type = .float };
    const rows = try a.alloc([]const Value, items.len);
    for (items, 0..) |item, ri| {
        const row = try a.alloc(Value, 2);
        const xv: ?std.json.Value, const yv: ?std.json.Value = switch (item) {
            .object => .{
                if (spec.x.len > 0) try resolveKey(a, root, item, xk, spec.max_matches) else null,
                if (spec.y.len > 0) try resolveKey(a, root, item, yk, spec.max_matches) else null,
            },
            .array => |arr| .{
                if (arr.items.len > 0) arr.items[0] else null,
                if (arr.items.len > 1) arr.items[1] else null,
            },
            else => .{ null, item }, // scalar → [index, item]
        };
        // `cols[0]` is declared `.text`, so the fallback index must be text
        // too. It used to be stored as `.int`, which made the column
        // heterogeneous and the declaration a lie: a consumer trusting the
        // declared type and reading `.text` panics on the union, and one
        // using `dataset.Value.asText()` silently gets null for exactly the
        // rows that took this branch. Found by mutation audit (1A).
        row[0] = if (xv) |v|
            try jsonToValue(a, v, .text)
        else
            .{ .text = try std.fmt.allocPrint(a, "{d}", .{ri}) };
        row[1] = if (yv) |v| try jsonToValue(a, v, .float) else .null;
        rows[ri] = row;
    }
    return .{ .columns = cols, .rows = rows };
}

fn descend(root: std.json.Value, path: []const u8) std.json.Value {
    if (path.len == 0) return root;
    var node = root;
    var it = std.mem.splitScalar(u8, path, '.');
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        node = switch (node) {
            .object => |o| o.get(seg) orelse return .null,
            else => return .null,
        };
    }
    return node;
}

// ── JSONPath subset (indices, wildcards, recursive descent, filters) ──────────
//
// `descend` above stays untouched and is the sole code path for legacy plain
// dot-paths, guaranteeing byte-identical back-compat. Any path using `[`,
// `*`, `?`, `..`, or a leading `$` routes through this richer engine instead.

/// Bounds recursive-descent (`..name`) and general segment-eval recursion so
/// a crafted path can't blow the stack on a deeply-nested document.
///
/// ⚠ **This bounds DEPTH, and depth is not the quantity that grows.** The
/// README advertised it as the module's DoS control; it is not one on its own.
/// `recursiveFind` visits every value at every level, so the number of MATCHES
/// grows with the document's branching, not its depth, and each match is then
/// flattened into rows. Measured on a **fixed, operator-written 6-byte path**
/// (`..a..a`) where only the document is hostile:
///
///   doc     163,831 B  ->  393,220 rows,  peak RSS  65 MiB   (~417x)
///   doc      40,951 B  ->   81,924 rows,  peak RSS  16 MiB
///
/// — superlinear, and nothing above stopped it. `MAX_MATCHES` below is the
/// bound on the quantity that actually grows. Raising `MAX_PATH_DEPTH` alone
/// is not a knob for that, and lowering it does not substitute for one.
const MAX_PATH_DEPTH: u32 = 64;

/// Ceiling on how many nodes a path may match before `shape` refuses.
///
/// This is the DoS control `MAX_PATH_DEPTH` was mistaken for. It is deliberately
/// a **refusal, not a truncation**: silently returning the first N rows of a
/// projection is a wrong answer that looks like a right one, and this module
/// already had one silent-truncation bug (the depth cap quietly dropping deep
/// matches while the README promised "every `name` anywhere"). A caller that
/// legitimately wants more sets `ShapeSpec.max_matches`.
///
/// ⚠ **It bounds the ANSWER, not the WORK.** The counter advances only where a
/// match is recorded, so a path whose FINAL name never occurs matches nothing,
/// the cap cannot fire, and `recursiveFind` still visits every value in the
/// document. `MAX_PATH_DEPTH` keeps that walk from compounding per level, which
/// leaves its cost a function of the document's SIZE — the caller's to bound
/// when it accepts untrusted input, not something this cap does for it.
pub const MAX_MATCHES: usize = 1 << 16;

const CmpOp = enum { eq, ne, lt, le, gt, ge };

/// Bounds a filter expression's nesting — parentheses, `!`, function
/// arguments, filters inside filter queries — so the parser and the evaluator
/// recurse at most this deep whatever the path text says.
const MAX_EXPR_DEPTH: u32 = 32;

const J = std.json.Value;

/// RFC 9535 §2.3.4: `[start:end:step]`; an absent bound takes its default for
/// the step's direction.
const Slice = struct { start: ?i64 = null, end: ?i64 = null, step: i64 = 1 };

const Selector = union(enum) {
    name: []const u8,
    /// Negative counts from the end (RFC 9535 §2.3.3).
    index: i64,
    wildcard,
    slice: Slice,
    filter: *const Expr,
};

const Seg = union(enum) {
    /// `.name`, `.*`, `[sel, sel, …]`: the selectors applied to the node.
    child: []const Selector,
    /// `..name`, `..*`, `..[sel, …]`: applied to the node and every
    /// descendant, in document (pre-)order.
    descendant: []const Selector,
    /// A syntactically-invalid segment: matches nothing, but doesn't fail
    /// the whole shape() call — same "degrade, don't error" philosophy as
    /// the rest of this module (only malformed *JSON* raises Error.BadJson).
    never,
};

const Query = struct {
    /// `$…` (from the document root) rather than `@…` (from the current node).
    absolute: bool,
    segs: []const Seg,

    /// RFC 9535 §2.3.5.1: only name and index selectors, one per segment —
    /// a query that yields at most one node, so it can be compared.
    fn isSingular(q: Query) bool {
        for (q.segs) |s| switch (s) {
            .child => |sels| if (sels.len != 1 or (sels[0] != .name and sels[0] != .index)) return false,
            else => return false,
        };
        return true;
    }
};

const Lit = union(enum) { number: f64, string: []const u8, boolean: bool, null };

/// A value-typed operand of a comparison (RFC 9535 `comparable`).
const Comparable = union(enum) {
    lit: Lit,
    /// A singular query (checked at parse time).
    query: Query,
    /// `length(x)`: characters of a string, elements of an array, members of
    /// an object; Nothing for anything else.
    length: *const Comparable,
    /// `count(q)`: how many nodes `q` selects.
    count: Query,
    /// `value(q)`: the node, when `q` selects exactly one; else Nothing.
    value: Query,
};

const Expr = union(enum) {
    @"or": [2]*const Expr,
    @"and": [2]*const Expr,
    not: *const Expr,
    /// Existence test: true when the query selects at least one node.
    exists: Query,
    cmp: struct { l: Comparable, op: CmpOp, r: Comparable },
};

fn isLegacyPath(path: []const u8) bool {
    if (path.len > 0 and path[0] == '$') return false;
    for (path) |c| {
        if (c == '[' or c == '*' or c == '?') return false;
    }
    if (std.mem.indexOf(u8, path, "..") != null) return false;
    return true;
}

/// Resolve `path` to the item list rows get projected from. Legacy dot-paths
/// go through `descend` unchanged; anything else through the segment engine,
/// flattening `.array` matches (their elements become items) and treating
/// any other match as a single item itself.
fn resolveItems(a: std.mem.Allocator, root: J, path: []const u8, limit: usize) Error![]const J {
    if (isLegacyPath(path)) {
        const node = descend(root, path);
        return switch (node) {
            .array => |arr| arr.items,
            else => &.{}, // not an array → empty dataset with the declared columns
        };
    }

    const segs = try parsePath(a, path);
    var matches: std.ArrayList(J) = .empty;
    var ctx: Ctx = .{ .a = a, .root = root, .out = &matches, .limit = limit };
    try evalSegs(&ctx, root, segs, 0);

    // ⚠ Bounding MATCHES is not bounding ITEMS, and items are what become
    // rows. A single match that is a ten-million-element array flattens into
    // ten million rows while the match counter reads 1 — the same
    // "cap bounds the wrong quantity" shape this cap exists to close, one
    // level down. Both are bounded, against the same limit.
    var items: std.ArrayList(J) = .empty;
    for (matches.items) |m| {
        switch (m) {
            .array => |arr| {
                if (items.items.len + arr.items.len > limit) return Error.TooManyMatches;
                try items.appendSlice(a, arr.items);
            },
            else => {
                if (items.items.len >= limit) return Error.TooManyMatches;
                try items.append(a, m);
            },
        }
    }
    return try items.toOwnedSlice(a);
}

// ── path parser ──────────────────────────────────────────────────────────────

const ParseError = error{ Syntax, OutOfMemory };

const Parser = struct {
    a: std.mem.Allocator,
    s: []const u8,
    i: usize = 0,
    depth: u32 = 0,

    fn peek(p: *const Parser) ?u8 {
        return if (p.i < p.s.len) p.s[p.i] else null;
    }
    fn skipWs(p: *Parser) void {
        while (p.i < p.s.len and (p.s[p.i] == ' ' or p.s[p.i] == '\t' or p.s[p.i] == '\n' or p.s[p.i] == '\r')) p.i += 1;
    }
    fn eat(p: *Parser, tok: []const u8) bool {
        if (!std.mem.startsWith(u8, p.s[p.i..], tok)) return false;
        p.i += tok.len;
        return true;
    }
    fn enter(p: *Parser) ParseError!void {
        p.depth += 1;
        if (p.depth > MAX_EXPR_DEPTH) return error.Syntax;
    }
};

/// Tokenize `path` into segments. Never fails on bad syntax — the first
/// segment that does not parse becomes `.never` (matches nothing) and ends
/// the path, so a malformed path degrades to an empty dataset like
/// everything else here.
fn parsePath(a: std.mem.Allocator, path: []const u8) Error![]Seg {
    var p: Parser = .{ .a = a, .s = path };
    if (path.len > 0 and path[0] == '$') p.i = 1;
    return parseSegs(&p, false) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Syntax => blk: {
            // The segments that did parse no longer matter: `.never` matches
            // nothing, so the whole path matches nothing.
            const never = try a.alloc(Seg, 1);
            never[0] = .never;
            break :blk never;
        },
    };
}

/// Member names. At the top level a name runs to the next `.` or `[` (the
/// permissive v1 rule, so keys like `a-b c` keep working); inside a filter it
/// is RFC 9535's name characters (plus `-`, accepted since v1), because a
/// filter query ends at an operator or a blank.
fn scanName(p: *Parser, in_filter: bool) []const u8 {
    const start = p.i;
    while (p.i < p.s.len) : (p.i += 1) {
        const c = p.s[p.i];
        if (in_filter) {
            if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c >= 0x80)) break;
        } else if (c == '.' or c == '[') break;
    }
    return p.s[start..p.i];
}

fn one(p: *Parser, sel: Selector) ParseError![]const Selector {
    const s = try p.a.alloc(Selector, 1);
    s[0] = sel;
    return s;
}

fn parseSegs(p: *Parser, in_filter: bool) ParseError![]Seg {
    var segs: std.ArrayList(Seg) = .empty;
    while (p.peek()) |c| {
        if (c == '.') {
            p.i += 1;
            if (p.peek() == '.') {
                p.i += 1;
                if (p.peek() == '[') {
                    try segs.append(p.a, .{ .descendant = try parseBracket(p) });
                } else {
                    const name = scanName(p, in_filter);
                    if (name.len == 0) {
                        if (p.peek() != '*') return error.Syntax;
                        p.i += 1;
                        try segs.append(p.a, .{ .descendant = try one(p, .wildcard) });
                    } else if (std.mem.eql(u8, name, "*")) {
                        try segs.append(p.a, .{ .descendant = try one(p, .wildcard) });
                    } else try segs.append(p.a, .{ .descendant = try one(p, .{ .name = name }) });
                }
            } else {
                if (in_filter and p.peek() == '*') {
                    p.i += 1;
                    try segs.append(p.a, .{ .child = try one(p, .wildcard) });
                    continue;
                }
                const name = scanName(p, in_filter);
                if (name.len == 0) {
                    if (in_filter) return error.Syntax;
                    continue; // tolerate stray/doubled '.' like legacy descend
                }
                const sel: Selector = if (std.mem.eql(u8, name, "*")) .wildcard else .{ .name = name };
                try segs.append(p.a, .{ .child = try one(p, sel) });
            }
        } else if (c == '[') {
            try segs.append(p.a, .{ .child = try parseBracket(p) });
        } else if (in_filter) {
            break; // the query ends here; the expression parser takes over
        } else {
            const name = scanName(p, false);
            const sel: Selector = if (std.mem.eql(u8, name, "*")) .wildcard else .{ .name = name };
            try segs.append(p.a, .{ .child = try one(p, sel) });
        }
    }
    return segs.toOwnedSlice(p.a);
}

/// `[sel, sel, …]` — RFC 9535 bracketed selection; `p.i` is at the `[`.
fn parseBracket(p: *Parser) ParseError![]const Selector {
    p.i += 1;
    var sels: std.ArrayList(Selector) = .empty;
    while (true) {
        p.skipWs();
        const c = p.peek() orelse return error.Syntax;
        if (c == '*') {
            p.i += 1;
            try sels.append(p.a, .wildcard);
        } else if (c == '\'' or c == '"') {
            try sels.append(p.a, .{ .name = try parseString(p) });
        } else if (c == '?') {
            p.i += 1;
            const e = try p.a.create(Expr);
            e.* = try parseOr(p);
            try sels.append(p.a, .{ .filter = e });
        } else if (c == ':' or c == '-' or std.ascii.isDigit(c)) {
            try sels.append(p.a, try parseIndexOrSlice(p));
        } else return error.Syntax;
        p.skipWs();
        if (p.eat(",")) continue;
        if (p.eat("]")) break;
        return error.Syntax;
    }
    return sels.toOwnedSlice(p.a);
}

/// RFC 9535 `int`: `0`, or an optional `-` and a nonzero digit first (no
/// leading zeros, no `-0`), within I-JSON's exact range ±(2^53 − 1).
fn parseInt(p: *Parser) ParseError!i64 {
    const start = p.i;
    if (p.peek() == '-') p.i += 1;
    const ds_start = p.i;
    while (p.peek()) |c| {
        if (!std.ascii.isDigit(c)) break;
        p.i += 1;
    }
    const digits = p.s[ds_start..p.i];
    if (digits.len == 0) return error.Syntax;
    if (digits[0] == '0' and (digits.len > 1 or ds_start != start)) return error.Syntax;
    const v = std.fmt.parseInt(i64, p.s[start..p.i], 10) catch return error.Syntax;
    const max_exact: i64 = (1 << 53) - 1;
    if (v > max_exact or v < -max_exact) return error.Syntax;
    return v;
}

fn parseIndexOrSlice(p: *Parser) ParseError!Selector {
    var sl: Slice = .{};
    p.skipWs();
    if (p.peek() != ':') {
        const v = try parseInt(p);
        p.skipWs();
        if (p.peek() != ':') return .{ .index = v };
        sl.start = v;
    }
    p.i += 1; // first ':'
    p.skipWs();
    if (p.peek()) |c| if (c == '-' or std.ascii.isDigit(c)) {
        sl.end = try parseInt(p);
        p.skipWs();
    };
    if (p.eat(":")) {
        p.skipWs();
        if (p.peek()) |c| if (c == '-' or std.ascii.isDigit(c)) {
            sl.step = try parseInt(p);
        };
    }
    return .{ .slice = sl };
}

/// A quoted string (`'…'` or `"…"`) with RFC 9535's escapes: `\b \f \n \r
/// \t \/ \\`, the quote itself, and `\uXXXX` (a surrogate pair for a
/// character above U+FFFF). The unescaped text is allocated in `p.a`.
fn parseString(p: *Parser) ParseError![]const u8 {
    const q = p.s[p.i];
    p.i += 1;
    var out: std.ArrayList(u8) = .empty;
    while (true) {
        const c = p.peek() orelse return error.Syntax;
        p.i += 1;
        if (c == q) break;
        if (c < 0x20) return error.Syntax; // control characters must be escaped
        if (c != '\\') {
            try out.append(p.a, c);
            continue;
        }
        const e = p.peek() orelse return error.Syntax;
        p.i += 1;
        switch (e) {
            'b' => try out.append(p.a, 0x08),
            'f' => try out.append(p.a, 0x0c),
            'n' => try out.append(p.a, '\n'),
            'r' => try out.append(p.a, '\r'),
            't' => try out.append(p.a, '\t'),
            '/', '\\' => try out.append(p.a, e),
            'u' => {
                var cp: u21 = try hex4(p);
                if (cp >= 0xD800 and cp <= 0xDBFF) {
                    if (!p.eat("\\u")) return error.Syntax;
                    const lo = try hex4(p);
                    if (lo < 0xDC00 or lo > 0xDFFF) return error.Syntax;
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                } else if (cp >= 0xDC00 and cp <= 0xDFFF) return error.Syntax;
                var buf: [4]u8 = undefined;
                const n = std.unicode.utf8Encode(cp, &buf) catch return error.Syntax;
                try out.appendSlice(p.a, buf[0..n]);
            },
            else => if (e == q) try out.append(p.a, e) else return error.Syntax,
        }
    }
    return out.toOwnedSlice(p.a);
}

fn hex4(p: *Parser) ParseError!u21 {
    if (p.i + 4 > p.s.len) return error.Syntax;
    const v = std.fmt.parseInt(u16, p.s[p.i .. p.i + 4], 16) catch return error.Syntax;
    // parseInt takes a sign; a \u escape does not.
    for (p.s[p.i .. p.i + 4]) |c| if (!std.ascii.isHex(c)) return error.Syntax;
    p.i += 4;
    return v;
}

// ── filter expressions (RFC 9535 §2.3.5) ─────────────────────────────────────

fn parseOr(p: *Parser) ParseError!Expr {
    try p.enter();
    defer p.depth -= 1;
    var l = try parseAnd(p);
    while (true) {
        p.skipWs();
        if (!p.eat("||")) return l;
        const lp = try p.a.create(Expr);
        lp.* = l;
        const rp = try p.a.create(Expr);
        rp.* = try parseAnd(p);
        l = .{ .@"or" = .{ lp, rp } };
    }
}

fn parseAnd(p: *Parser) ParseError!Expr {
    var l = try parseBasic(p);
    while (true) {
        p.skipWs();
        if (!p.eat("&&")) return l;
        const lp = try p.a.create(Expr);
        lp.* = l;
        const rp = try p.a.create(Expr);
        rp.* = try parseBasic(p);
        l = .{ .@"and" = .{ lp, rp } };
    }
}

fn parseBasic(p: *Parser) ParseError!Expr {
    try p.enter();
    defer p.depth -= 1;
    p.skipWs();
    if (p.peek() == '!') {
        p.i += 1;
        p.skipWs();
        const inner = try p.a.create(Expr);
        if (p.peek() == '(') {
            inner.* = try parseParen(p);
        } else {
            // `!` applies to a test (an existence query), never to a comparison.
            const q = try parseQuery(p) orelse return error.Syntax;
            inner.* = .{ .exists = q };
        }
        return .{ .not = inner };
    }
    if (p.peek() == '(') return parseParen(p);
    if (try parseQuery(p)) |q| {
        p.skipWs();
        const op = parseOp(p) orelse return .{ .exists = q };
        if (!q.isSingular()) return error.Syntax; // only a singular query compares
        return .{ .cmp = .{ .l = .{ .query = q }, .op = op, .r = try parseComparable(p) } };
    }
    const l = try parseComparable(p);
    p.skipWs();
    const op = parseOp(p) orelse return error.Syntax; // a value is not a test
    return .{ .cmp = .{ .l = l, .op = op, .r = try parseComparable(p) } };
}

fn parseParen(p: *Parser) ParseError!Expr {
    p.i += 1; // '('
    const e = try parseOr(p);
    p.skipWs();
    if (!p.eat(")")) return error.Syntax;
    return e;
}

fn parseOp(p: *Parser) ?CmpOp {
    const ops = [_]struct { []const u8, CmpOp }{
        .{ "==", .eq }, .{ "!=", .ne }, .{ "<=", .le }, .{ ">=", .ge }, .{ "<", .lt }, .{ ">", .gt },
    };
    for (ops) |o| if (p.eat(o[0])) return o[1];
    return null;
}

/// `@…` or `$…`, or null (nothing consumed) when the text is not a query.
fn parseQuery(p: *Parser) ParseError!?Query {
    const c = p.peek() orelse return null;
    if (c != '@' and c != '$') return null;
    p.i += 1;
    try p.enter();
    defer p.depth -= 1;
    return .{ .absolute = c == '$', .segs = try parseSegs(p, true) };
}

fn parseComparable(p: *Parser) ParseError!Comparable {
    p.skipWs();
    const c = p.peek() orelse return error.Syntax;
    if (try parseQuery(p)) |q| {
        if (!q.isSingular()) return error.Syntax;
        return .{ .query = q };
    }
    if (c == '\'' or c == '"') return .{ .lit = .{ .string = try parseString(p) } };
    if (c == '-' or std.ascii.isDigit(c)) return .{ .lit = .{ .number = try parseNumber(p) } };
    if (p.eat("true")) return .{ .lit = .{ .boolean = true } };
    if (p.eat("false")) return .{ .lit = .{ .boolean = false } };
    if (p.eat("null")) return .{ .lit = .null };
    inline for (.{ "length", "count", "value" }) |fname| {
        if (p.eat(fname ++ "(")) {
            try p.enter();
            defer p.depth -= 1;
            p.skipWs();
            const out: Comparable = if (comptime std.mem.eql(u8, fname, "length")) blk: {
                const arg = try p.a.create(Comparable);
                arg.* = try parseComparable(p);
                break :blk .{ .length = arg };
            } else blk: {
                const q = try parseQuery(p) orelse return error.Syntax;
                break :blk if (comptime std.mem.eql(u8, fname, "count")) .{ .count = q } else .{ .value = q };
            };
            p.skipWs();
            if (!p.eat(")")) return error.Syntax;
            return out;
        }
    }
    return error.Syntax;
}

/// A JSON number (RFC 8259 grammar): `-? (0 | [1-9][0-9]*) (.[0-9]+)? ([eE][+-]?[0-9]+)?`.
fn parseNumber(p: *Parser) ParseError!f64 {
    const start = p.i;
    if (p.peek() == '-') p.i += 1;
    const int_start = p.i;
    while (p.peek()) |c| {
        if (!std.ascii.isDigit(c)) break;
        p.i += 1;
    }
    const int_len = p.i - int_start;
    if (int_len == 0 or (p.s[int_start] == '0' and int_len > 1)) return error.Syntax;
    if (p.peek() == '.') {
        p.i += 1;
        const f = p.i;
        while (p.peek()) |c| {
            if (!std.ascii.isDigit(c)) break;
            p.i += 1;
        }
        if (p.i == f) return error.Syntax;
    }
    if (p.peek()) |e| if (e == 'e' or e == 'E') {
        p.i += 1;
        if (p.peek()) |sg| if (sg == '+' or sg == '-') {
            p.i += 1;
        };
        const f = p.i;
        while (p.peek()) |c| {
            if (!std.ascii.isDigit(c)) break;
            p.i += 1;
        }
        if (p.i == f) return error.Syntax;
    };
    return std.fmt.parseFloat(f64, p.s[start..p.i]) catch error.Syntax;
}

// ── evaluation ───────────────────────────────────────────────────────────────

/// One query evaluation. `out` set: every match is appended (the path, a
/// `count`). `out` null: only the first match is kept, in `found`, and the
/// walk stops after `stop_after` matches (an existence test, a column key,
/// `value()`). `n` counts matches either way and is held to `limit`.
const Ctx = struct {
    a: std.mem.Allocator,
    root: J,
    out: ?*std.ArrayList(J) = null,
    found: ?J = null,
    n: usize = 0,
    stop_after: usize = std.math.maxInt(usize),
    limit: usize,

    fn done(c: *const Ctx) bool {
        return c.n >= c.stop_after;
    }
};

fn evalSegs(ctx: *Ctx, node: J, segs: []const Seg, depth: u32) Error!void {
    if (depth > MAX_PATH_DEPTH or ctx.done()) return;
    if (segs.len == 0) {
        // Checked at the ONE place a match is recorded, so no caller can add a
        // new recursion arm that bypasses it.
        if (ctx.n >= ctx.limit) return Error.TooManyMatches;
        ctx.n += 1;
        if (ctx.out) |o| try o.append(ctx.a, node) else if (ctx.found == null) {
            ctx.found = node;
        }
        return;
    }
    const rest = segs[1..];
    switch (segs[0]) {
        .never => {},
        .child => |sels| for (sels) |sel| try select(ctx, node, sel, rest, depth),
        .descendant => |sels| try descendAll(ctx, node, sels, rest, depth),
    }
}

/// RFC 9535 §2.5.2: the selectors applied to `node`, then to each of its
/// descendants, depth-first in document order.
fn descendAll(ctx: *Ctx, node: J, sels: []const Selector, rest: []const Seg, depth: u32) Error!void {
    if (depth > MAX_PATH_DEPTH or ctx.done()) return;
    for (sels) |sel| try select(ctx, node, sel, rest, depth);
    switch (node) {
        .object => |o| for (o.values()) |v| try descendAll(ctx, v, sels, rest, depth + 1),
        .array => |arr| for (arr.items) |it| try descendAll(ctx, it, sels, rest, depth + 1),
        else => {},
    }
}

fn select(ctx: *Ctx, node: J, sel: Selector, rest: []const Seg, depth: u32) Error!void {
    switch (sel) {
        .name => |k| switch (node) {
            .object => |o| if (o.get(k)) |v| try evalSegs(ctx, v, rest, depth + 1),
            else => {},
        },
        .index => |idx| switch (node) {
            .array => |arr| if (normIndex(idx, arr.items.len)) |i| try evalSegs(ctx, arr.items[i], rest, depth + 1),
            else => {},
        },
        .wildcard => switch (node) {
            .array => |arr| for (arr.items) |it| try evalSegs(ctx, it, rest, depth + 1),
            .object => |o| for (o.values()) |v| try evalSegs(ctx, v, rest, depth + 1),
            else => {},
        },
        .slice => |sl| switch (node) {
            .array => |arr| try selectSlice(ctx, arr.items, sl, rest, depth),
            else => {},
        },
        .filter => |e| switch (node) {
            .array => |arr| for (arr.items) |it| {
                if (try evalExpr(ctx, it, e, depth + 1)) try evalSegs(ctx, it, rest, depth + 1);
            },
            .object => |o| for (o.values()) |v| {
                if (try evalExpr(ctx, v, e, depth + 1)) try evalSegs(ctx, v, rest, depth + 1);
            },
            else => {},
        },
    }
}

/// An index (negative counts from the end) as an in-bounds position, or null.
fn normIndex(idx: i64, len: usize) ?usize {
    const l: i64 = @intCast(@min(len, std.math.maxInt(i64)));
    const i = if (idx < 0) l + idx else idx;
    if (i < 0 or i >= l) return null;
    return @intCast(i);
}

/// RFC 9535 §2.3.4.2.2, the normative slice algorithm, verbatim in shape.
fn selectSlice(ctx: *Ctx, items: []const J, sl: Slice, rest: []const Seg, depth: u32) Error!void {
    if (sl.step == 0) return; // selects nothing
    const len: i64 = @intCast(@min(items.len, std.math.maxInt(i64)));
    const step = sl.step;
    const start = sl.start orelse if (step >= 0) 0 else len - 1;
    const end = sl.end orelse if (step >= 0) len else -len - 1;
    const n_start = if (start >= 0) start else len + start;
    const n_end = if (end >= 0) end else len + end;
    if (step > 0) {
        const lower = @min(@max(n_start, 0), len);
        const upper = @min(@max(n_end, 0), len);
        var i = lower;
        while (i < upper) : (i += step) try evalSegs(ctx, items[@intCast(i)], rest, depth + 1);
    } else {
        const upper = @min(@max(n_start, -1), len - 1);
        const lower = @min(@max(n_end, -1), len - 1);
        var i = upper;
        while (lower < i) : (i += step) try evalSegs(ctx, items[@intCast(i)], rest, depth + 1);
    }
}

fn evalExpr(ctx: *Ctx, cur: J, e: *const Expr, depth: u32) Error!bool {
    if (depth > MAX_PATH_DEPTH) return false;
    return switch (e.*) {
        .@"or" => |lr| try evalExpr(ctx, cur, lr[0], depth) or try evalExpr(ctx, cur, lr[1], depth),
        .@"and" => |lr| try evalExpr(ctx, cur, lr[0], depth) and try evalExpr(ctx, cur, lr[1], depth),
        .not => |inner| !try evalExpr(ctx, cur, inner, depth),
        .exists => |q| (try runQuery(ctx, cur, q, 1, depth)).n > 0,
        .cmp => |c| compare(try evalComparable(ctx, cur, c.l, depth), c.op, try evalComparable(ctx, cur, c.r, depth)),
    };
}

/// Run a filter's sub-query from `cur` (or the root), keeping the first match
/// and stopping after `stop_after`. Its matches count against the same
/// `limit` as the path's own.
fn runQuery(ctx: *Ctx, cur: J, q: Query, stop_after: usize, depth: u32) Error!Ctx {
    var sub: Ctx = .{ .a = ctx.a, .root = ctx.root, .stop_after = stop_after, .limit = ctx.limit };
    try evalSegs(&sub, if (q.absolute) ctx.root else cur, q.segs, depth + 1);
    return sub;
}

/// A comparable's value; null is RFC 9535's "Nothing" (no node), distinct
/// from a JSON `null`.
fn evalComparable(ctx: *Ctx, cur: J, c: Comparable, depth: u32) Error!?J {
    return switch (c) {
        .lit => |l| switch (l) {
            .number => |n| J{ .float = n },
            .string => |s| J{ .string = s },
            .boolean => |b| J{ .bool = b },
            .null => J.null,
        },
        .query => |q| (try runQuery(ctx, cur, q, 1, depth)).found,
        .length => |arg| switch ((try evalComparable(ctx, cur, arg.*, depth)) orelse return null) {
            .string => |s| J{ .integer = @intCast(std.unicode.utf8CountCodepoints(s) catch return null) },
            .array => |arr| J{ .integer = @intCast(arr.items.len) },
            .object => |o| J{ .integer = @intCast(o.count()) },
            else => null,
        },
        .count => |q| J{ .integer = @intCast((try runQuery(ctx, cur, q, std.math.maxInt(usize), depth)).n) },
        .value => |q| blk: {
            const r = try runQuery(ctx, cur, q, 2, depth);
            break :blk if (r.n == 1) r.found else null;
        },
    };
}

/// RFC 9535 §2.3.5.2.2. Nothing equals only Nothing; `<` holds only between
/// two numbers or two strings (strings by Unicode scalar value, which UTF-8
/// byte order preserves); `<=` is `<` or `==`; `!=` is not `==`.
fn compare(l: ?J, op: CmpOp, r: ?J) bool {
    const eq = if (l == null or r == null) l == null and r == null else jsonEq(l.?, r.?, 0);
    return switch (op) {
        .eq => eq,
        .ne => !eq,
        .lt => l != null and r != null and jsonLt(l.?, r.?),
        .le => eq or (l != null and r != null and jsonLt(l.?, r.?)),
        .gt => l != null and r != null and jsonLt(r.?, l.?),
        .ge => eq or (l != null and r != null and jsonLt(r.?, l.?)),
    };
}

fn jsonNum(v: J) ?f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

fn jsonEq(a: J, b: J, depth: u32) bool {
    if (depth > MAX_PATH_DEPTH) return false;
    if (a == .integer and b == .integer) return a.integer == b.integer;
    if (jsonNum(a)) |x| return if (jsonNum(b)) |y| x == y else false;
    return switch (a) {
        .string => |s| b == .string and std.mem.eql(u8, s, b.string),
        .bool => |x| b == .bool and b.bool == x,
        .null => b == .null,
        .array => |x| blk: {
            if (b != .array or b.array.items.len != x.items.len) break :blk false;
            for (x.items, b.array.items) |p, q| if (!jsonEq(p, q, depth + 1)) break :blk false;
            break :blk true;
        },
        .object => |x| blk: {
            if (b != .object or b.object.count() != x.count()) break :blk false;
            var it = x.iterator();
            while (it.next()) |kv| {
                const other = b.object.get(kv.key_ptr.*) orelse break :blk false;
                if (!jsonEq(kv.value_ptr.*, other, depth + 1)) break :blk false;
            }
            break :blk true;
        },
        .integer, .float, .number_string => unreachable, // handled above
    };
}

fn jsonLt(a: J, b: J) bool {
    if (a == .integer and b == .integer) return a.integer < b.integer;
    if (jsonNum(a)) |x| return if (jsonNum(b)) |y| x < y else false;
    if (a == .string and b == .string) return std.mem.order(u8, a.string, b.string) == .lt;
    return false;
}

fn itemField(item: std.json.Value, key: []const u8) ?std.json.Value {
    return switch (item) {
        .object => |o| o.get(key),
        else => null,
    };
}

/// Coerce a JSON value into a canonical Value honoring `want` (the column type).
fn jsonToValue(a: std.mem.Allocator, jv: std.json.Value, want: ColumnType) Error!Value {
    return switch (want) {
        .int => .{ .int = jsonToInt(jv) orelse return .null },
        .float => .{ .float = jsonToFloat(jv) orelse return .null },
        .bool => switch (jv) {
            .bool => |b| .{ .bool = b },
            else => .null,
        },
        .text, .date => switch (jv) {
            .string => |s| .{ .text = s }, // borrows arena-backed parse tree
            .number_string => |s| .{ .text = s },
            .integer => |i| .{ .text = try std.fmt.allocPrint(a, "{d}", .{i}) },
            .float => |f| .{ .text = try std.fmt.allocPrint(a, "{d}", .{f}) },
            .bool => |b| .{ .text = if (b) "true" else "false" },
            else => .null,
        },
        // JSON has no fixed-point type; go through the same numeric parse as
        // .float, then widen via Value.cast (float*scale, truncated — see
        // dataset's Value.cast doc comment). No dependency on the `decimal`
        // module for text parsing here (same limitation `Value.cast` documents).
        .decimal => blk: {
            const f = jsonToFloat(jv) orelse break :blk .null;
            break :blk (Value{ .float = f }).cast(.decimal) orelse .null;
        },
        // An instant: an ISO 8601 / RFC 3339 string, or a number already in
        // the column's unit (microseconds since the epoch) — `Value.cast`'s
        // rules, so a JSON feed and a cast agree. Anything else → null.
        .timestamp => blk: {
            const v: Value = switch (jv) {
                .string => |s| .{ .text = s },
                .integer => |i| .{ .int = i },
                // A numeric literal std.json kept as text: exact when it is an
                // integer, else through f64 like `.float`.
                .number_string => |s| if (std.fmt.parseInt(i64, s, 10)) |i|
                    .{ .int = i }
                else |_| if (std.fmt.parseFloat(f64, s)) |f| .{ .float = f } else |_| break :blk .null,
                .float => |f| .{ .float = f },
                else => break :blk .null,
            };
            break :blk v.cast(.timestamp) orelse .null;
        },
    };
}

fn jsonToFloat(jv: std.json.Value) ?f64 {
    return switch (jv) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
        .string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

fn jsonToInt(jv: std.json.Value) ?i64 {
    return switch (jv) {
        .integer => |i| i,
        // ⚠ This was a bare `@intFromFloat(f)`. The number comes off the wire,
        // so `1e300` into an `.int` column was undefined behaviour: SIGABRT in
        // Debug and ReleaseSafe, silent `i64` minimum in ReleaseFast — against
        // SPEC.md's "a shape mismatch never panics or propagates as an error".
        // Out of range now degrades to `.null`, like every other mismatch here.
        .float => |f| Value.floatToInt(i64, f),
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        .string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────
const testing = std.testing;

test "shape: dotpath + generic columns" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{ "data": { "prices": [
        \\   { "d": "2024-01-01", "close": 100.5, "vol": 10 },
        \\   { "d": "2024-01-02", "close": 101, "vol": 20 }
        \\ ] } }
    ;
    const d = try shape(a, json, .{
        .path = "data.prices",
        .columns = &.{
            .{ .name = "date", .key = "d", .type = .date },
            .{ .name = "close", .key = "close", .type = .float },
            .{ .name = "vol", .key = "vol", .type = .int },
        },
    });
    try testing.expectEqual(@as(usize, 2), d.rows.len);
    try testing.expectEqualStrings("2024-01-01", d.cell(0, "date").?.text);
    try testing.expectEqual(@as(f64, 100.5), d.cell(0, "close").?.float);
    try testing.expectEqual(@as(f64, 101), d.cell(1, "close").?.float); // int coerced to float
    try testing.expectEqual(@as(i64, 20), d.cell(1, "vol").?.int);
}

test "shape: poc [x,y] default from object items" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\[ { "t": "2024-01-01", "v": 1.5 }, { "t": "2024-01-02", "v": 2.5 } ]
    ;
    const d = try shape(a, json, .{ .x = "t", .y = "v" });
    try testing.expectEqual(@as(usize, 2), d.columns.len);
    try testing.expectEqualStrings("x", d.columns[0].name);
    try testing.expectEqualStrings("2024-01-02", d.cell(1, "x").?.text);
    try testing.expectEqual(@as(f64, 1.5), d.cell(0, "y").?.float);
}

test "shape: [x,y] default from array items" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "[[1, 10], [2, 20], [3, 30]]", .{});
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    try testing.expectEqualStrings("2", d.cell(1, "x").?.text);
    try testing.expectEqual(@as(f64, 30), d.cell(2, "y").?.float);
}

test "shape: missing path node → empty dataset (not an error)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "{\"a\":1}", .{ .path = "nope.array", .columns = &.{
        .{ .name = "v", .key = "v", .type = .float },
    } });
    try testing.expectEqual(@as(usize, 0), d.rows.len);
    try testing.expectEqual(@as(usize, 1), d.columns.len);
}

test "shape: a missing intermediate segment fails the whole path — a sibling key of the SAME name is not picked up" {
    // Audit F1. The `orelse return .null` in `descend` must abandon the walk at
    // the FIRST missing segment. The existing "missing path" test above cannot
    // see this: mutate that line to `orelse node` (silently stay put) and its
    // `{"a":1}` / `"nope.array"` case still lands on a non-array node, so it
    // still passes. The decoy here is the point — the root object also carries
    // an `"array"` key, so a `descend` that skips the missing `"nope"` segment
    // instead of failing walks straight into the SIBLING and returns rows that
    // the requested path does not name at all.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{"a":1,"array":[{"v":7},{"v":8}]}
    ;
    const d = try shape(a, json, .{ .path = "nope.array", .columns = &.{
        .{ .name = "v", .key = "v", .type = .float },
    } });
    try testing.expectEqual(@as(usize, 0), d.rows.len);

    // Control: the same document at the path that DOES exist yields the rows,
    // so the assertion above is about the missing segment and not about the
    // fixture being unreadable.
    const ok = try shape(a, json, .{ .path = "array", .columns = &.{
        .{ .name = "v", .key = "v", .type = .float },
    } });
    try testing.expectEqual(@as(usize, 2), ok.rows.len);
    try testing.expectEqual(@as(f64, 7), ok.cell(0, "v").?.float);

    // The same trap one level deeper: a missing FINAL segment must not resolve
    // to the object it was looked up in.
    const deep = try shape(a, "{\"outer\":{\"a\":1,\"array\":[{\"v\":9}]}}", .{ .path = "outer.nope.array", .columns = &.{
        .{ .name = "v", .key = "v", .type = .float },
    } });
    try testing.expectEqual(@as(usize, 0), deep.rows.len);
}

test "shape: malformed JSON → BadJson" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    try testing.expectError(Error.BadJson, shape(arena.allocator(), "{not json", .{}));
}

test "shape: back-compat — existing legacy dot-path resolves identically" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{ "data": { "prices": [
        \\   { "d": "2024-01-01", "close": 100.5, "vol": 10 },
        \\   { "d": "2024-01-02", "close": 101, "vol": 20 }
        \\ ] } }
    ;
    // Same spec as the "dotpath + generic columns" test above — the path
    // contains none of `[ * ? ..` so it must route through the untouched
    // legacy `descend`, with byte-identical results before and after the
    // JSONPath-subset engine was added.
    const d = try shape(a, json, .{
        .path = "data.prices",
        .columns = &.{
            .{ .name = "date", .key = "d", .type = .date },
            .{ .name = "close", .key = "close", .type = .float },
            .{ .name = "vol", .key = "vol", .type = .int },
        },
    });
    try testing.expectEqual(@as(usize, 2), d.rows.len);
    try testing.expectEqualStrings("2024-01-01", d.cell(0, "date").?.text);
    try testing.expectEqual(@as(f64, 100.5), d.cell(0, "close").?.float);
    try testing.expectEqual(@as(i64, 20), d.cell(1, "vol").?.int);
}

test "shape: JSONPath array index — a.b[2]" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "{\"a\":{\"b\":[10,20,30,40]}}", .{
        .path = "a.b[2]",
        .columns = &.{.{ .name = "v", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 1), d.rows.len);
    try testing.expectEqual(@as(i64, 30), d.cell(0, "v").?.int);
}

test "shape: JSONPath array wildcard — a.b[*]" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"a\":{\"b\":[{\"n\":1},{\"n\":2},{\"n\":3}]}}";
    const d = try shape(a, json, .{
        .path = "a.b[*]",
        .columns = &.{.{ .name = "n", .key = "n", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    try testing.expectEqual(@as(i64, 1), d.cell(0, "n").?.int);
    try testing.expectEqual(@as(i64, 2), d.cell(1, "n").?.int);
    try testing.expectEqual(@as(i64, 3), d.cell(2, "n").?.int);
}

test "shape: JSONPath object wildcard — a.*" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "{\"a\":{\"x\":1,\"y\":2,\"z\":3}}", .{
        .path = "a.*",
        .columns = &.{.{ .name = "v", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    try testing.expectEqual(@as(i64, 1), d.cell(0, "v").?.int);
    try testing.expectEqual(@as(i64, 2), d.cell(1, "v").?.int);
    try testing.expectEqual(@as(i64, 3), d.cell(2, "v").?.int);
}

test "shape: JSONPath recursive descent — ..name" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{ "a": { "name": "top", "b": { "name": "nested1", "c": [
        \\   { "name": "deep1" }, { "other": 1 }
        \\ ] } } }
    ;
    const d = try shape(a, json, .{
        .path = "..name",
        .columns = &.{.{ .name = "v", .type = .text }},
    });
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    try testing.expectEqualStrings("top", d.cell(0, "v").?.text);
    try testing.expectEqualStrings("nested1", d.cell(1, "v").?.text);
    try testing.expectEqualStrings("deep1", d.cell(2, "v").?.text);
}

test "shape: JSONPath multiple array nodes concatenate — pages[*].items" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"pages\":[{\"items\":[1,2]},{\"items\":[3,4,5]}]}";
    const d = try shape(a, json, .{
        .path = "pages[*].items",
        .columns = &.{.{ .name = "v", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 5), d.rows.len);
    try testing.expectEqual(@as(i64, 1), d.cell(0, "v").?.int);
    try testing.expectEqual(@as(i64, 5), d.cell(4, "v").?.int);
}

test "shape: filter expression selects exactly the matching elements" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{ "list": [
        \\  { "id": 1, "status": "ok" },
        \\  { "id": 2, "status": "bad" },
        \\  { "id": 3, "status": "ok" }
        \\ ] }
    ;
    const d = try shape(a, json, .{
        .path = "list[?(@.status == \"ok\")]",
        .columns = &.{
            .{ .name = "id", .key = "id", .type = .int },
            .{ .name = "status", .key = "status", .type = .text },
        },
    });
    try testing.expectEqual(@as(usize, 2), d.rows.len);
    try testing.expectEqual(@as(i64, 1), d.cell(0, "id").?.int);
    try testing.expectEqual(@as(i64, 3), d.cell(1, "id").?.int);
    // Positive control: id=2 ("bad") must be excluded, not merely
    // deprioritized — assert it's gone from every row.
    for (0..d.rows.len) |ri| {
        try testing.expect(d.cell(ri, "id").?.int != 2);
    }
}

test "shape: numeric filter operators (>, no spaces around op)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "{\"arr\":[{\"n\":1},{\"n\":10},{\"n\":5}]}", .{
        .path = "arr[?(@.n>5)]",
        .columns = &.{.{ .name = "n", .key = "n", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 1), d.rows.len);
    try testing.expectEqual(@as(i64, 10), d.cell(0, "n").?.int);
}

test "shape: numeric filter operators — ne, lt, le, ge (all previously untested)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"arr\":[{\"n\":1},{\"n\":5},{\"n\":10}]}";

    const ne = try shape(a, json, .{ .path = "arr[?(@.n != 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 2), ne.rows.len);

    const lt = try shape(a, json, .{ .path = "arr[?(@.n < 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 1), lt.rows.len);
    try testing.expectEqual(@as(i64, 1), lt.cell(0, "n").?.int);

    const le = try shape(a, json, .{ .path = "arr[?(@.n <= 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 2), le.rows.len);

    // `>=` — distinguishes from `>`: 5 must be INCLUDED here.
    const ge = try shape(a, json, .{ .path = "arr[?(@.n >= 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 2), ge.rows.len);
    try testing.expectEqual(@as(i64, 5), ge.cell(0, "n").?.int);
    try testing.expectEqual(@as(i64, 10), ge.cell(1, "n").?.int);
}

test "shape: string filter operators — ne, lt, le, gt, ge (all previously untested)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"arr\":[{\"s\":\"a\"},{\"s\":\"b\"},{\"s\":\"c\"}]}";

    const ne = try shape(a, json, .{ .path = "arr[?(@.s != \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 2), ne.rows.len);

    const lt = try shape(a, json, .{ .path = "arr[?(@.s < \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 1), lt.rows.len);
    try testing.expectEqualStrings("a", lt.cell(0, "s").?.text);

    const gt = try shape(a, json, .{ .path = "arr[?(@.s > \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 1), gt.rows.len);
    try testing.expectEqualStrings("c", gt.cell(0, "s").?.text);

    // `<=` / `>=` must include the boundary "b", distinguishing them from `<`/`>`.
    const le = try shape(a, json, .{ .path = "arr[?(@.s <= \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 2), le.rows.len);

    const ge = try shape(a, json, .{ .path = "arr[?(@.s >= \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 2), ge.rows.len);
}

test "shape: boolean and null filter literals (cmpBool/cmpNull were entirely dead code)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{ "arr": [
        \\  { "id": 1, "active": true },
        \\  { "id": 2, "active": false },
        \\  { "id": 3, "note": null }
        \\ ] }
    ;

    const eq_true = try shape(a, json, .{ .path = "arr[?(@.active == true)]", .columns = &.{.{ .name = "id", .key = "id", .type = .int }} });
    try testing.expectEqual(@as(usize, 1), eq_true.rows.len);
    try testing.expectEqual(@as(i64, 1), eq_true.cell(0, "id").?.int);

    // RFC 9535 §2.3.5.2.2 (Table 11: `$.absent != 'g'` is true): an ABSENT
    // member is Nothing, and Nothing != true. Element 3 has no `active`, so it
    // matches too. (Before 2026-10-04 a missing field failed every comparison,
    // `!=` included — not RFC behaviour.)
    const ne_true = try shape(a, json, .{ .path = "arr[?(@.active != true)]", .columns = &.{.{ .name = "id", .key = "id", .type = .int }} });
    try testing.expectEqual(@as(usize, 2), ne_true.rows.len);
    try testing.expectEqual(@as(i64, 2), ne_true.cell(0, "id").?.int);
    try testing.expectEqual(@as(i64, 3), ne_true.cell(1, "id").?.int);

    const is_null = try shape(a, json, .{ .path = "arr[?(@.note == null)]", .columns = &.{.{ .name = "id", .key = "id", .type = .int }} });
    try testing.expectEqual(@as(usize, 1), is_null.rows.len);
    try testing.expectEqual(@as(i64, 3), is_null.cell(0, "id").?.int);
}

test "shape: [x,y] default from a top-level array of bare scalars (else branch of shapeXY, untested)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "[10, 20, 30]", .{});
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    // scalar item → x = positional index, y = the scalar itself. The index is
    // TEXT: `cols[0]` declares `.text`, and this branch used to contradict it
    // by storing `.int` (fixed in the 1A audit — see `shapeXY`).
    try testing.expectEqualStrings("1", d.cell(1, "x").?.text);
    try testing.expectEqual(@as(f64, 20), d.cell(1, "y").?.float);
}

test "shape: stringified-number JSON values coerce through number_string/string paths (untested)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"arr\":[{\"n\":\"42\"}]}";
    const d = try shape(a, json, .{
        .path = "arr",
        .columns = &.{
            .{ .name = "as_int", .key = "n", .type = .int },
            .{ .name = "as_float", .key = "n", .type = .float },
        },
    });
    try testing.expectEqual(@as(usize, 1), d.rows.len);
    try testing.expectEqual(@as(i64, 42), d.cell(0, "as_int").?.int);
    try testing.expectEqual(@as(f64, 42), d.cell(0, "as_float").?.float);
}

test "shape: malformed JSONPath syntax → empty dataset, not a crash" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Unterminated '[' — invalid syntax degrades to "no match", same
    // leniency contract as a missing key.
    const d = try shape(a, "{\"a\":[1,2,3]}", .{
        .path = "a[0",
        .columns = &.{.{ .name = "v", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 0), d.rows.len);
}

test "shape: the x column honours its declared .text type on every branch" {
    // The declared type is the contract `dataset` consumers rely on. Before
    // this, the index fallback stored `.int` into a column declared `.text`,
    // so the two branches of the same column had different active union
    // fields — invisible to every test that only exercised the object branch.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // A top-level array of bare scalars takes the index fallback for x.
    const d = try shape(a, "[10, 20, 30]", .{});
    try testing.expectEqual(ColumnType.text, d.columns[0].type);
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    for (d.rows, 0..) |row, i| {
        // `.asText()` must answer for EVERY row, not just the ones that
        // happened to come from an object.
        const got = row[0].asText() orelse return error.XColumnNotText;
        var buf: [8]u8 = undefined;
        try testing.expectEqualStrings(try std.fmt.bufPrint(&buf, "{d}", .{i}), got);
    }
}

// ── TEETH: the three guarantees that had no gate ────────────────────────────

test "TEETH: an out-of-range JSON number degrades to null instead of panicking" {
    // SPEC.md: "a shape mismatch never panics or propagates as an error."
    // `jsonToInt` used a bare `@intFromFloat`, so a remote `1e300` into an
    // `.int` column was undefined behaviour: SIGABRT in Debug and ReleaseSafe,
    // silent i64-minimum in ReleaseFast. Three modes, three different answers,
    // none of them the documented one.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    for ([_][]const u8{
        "{\"r\":[{\"v\":1e300}]}",
        "{\"r\":[{\"v\":-1e300}]}",
        "{\"r\":[{\"v\":1e400}]}", // parses as +inf
    }) |doc| {
        const out_ds = try shape(a, doc, .{
            .path = "r",
            .columns = &.{.{ .name = "v", .key = "v", .type = .int }},
        });
        try testing.expectEqual(@as(usize, 1), out_ds.rows.len);
        try testing.expect(out_ds.rows[0][0] == .null);
    }
    // A value that DOES fit still converts, so the guard is not simply
    // rejecting everything.
    const ok = try shape(a, "{\"r\":[{\"v\":42.9}]}", .{
        .path = "r",
        .columns = &.{.{ .name = "v", .key = "v", .type = .int }},
    });
    try testing.expectEqual(@as(i64, 42), ok.rows[0][0].int);
}

test "TEETH: an out-of-range JSON number degrades to null in a .decimal column too" {
    // Distinct from the test above: `dataset`'s `Value.cast(.decimal)` guarded
    // `isFinite(f)` while converting `f * 1e12`, so `1e30` — finite, and well
    // inside f64 — reached `@intFromFloat` as `1e42`, which does not fit i128.
    // The check was on a different number from the cast.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const out_ds = try shape(a, "{\"r\":[{\"v\":1e30}]}", .{
        .path = "r",
        .columns = &.{.{ .name = "v", .key = "v", .type = .decimal }},
    });
    try testing.expect(out_ds.rows[0][0] == .null);
    const ok = try shape(a, "{\"r\":[{\"v\":1.5}]}", .{
        .path = "r",
        .columns = &.{.{ .name = "v", .key = "v", .type = .decimal }},
    });
    try testing.expect(ok.rows[0][0] == .decimal);
}

test "shape: a .timestamp column reads RFC 3339 strings and microsecond numbers" {
    // 2009-02-13T23:31:30Z is Unix time 1234567890 (a published anchor); the
    // column unit is microseconds, so the cell is that times 1e6. A number is
    // taken as already being in that unit (dataset's `Value.cast` rule); text
    // that is not an instant, a bool, and an out-of-range float are null.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a,
        \\{"r":[{"t":"2009-02-14T00:31:30+01:00"},{"t":1234567890000000},{"t":2.5},
        \\{"t":"yesterday"},{"t":true},{"t":1e300},{"t":"2009-02-13"}]}
    , .{
        .path = "r",
        .columns = &.{.{ .name = "t", .key = "t", .type = .timestamp }},
    });
    try testing.expectEqual(@as(usize, 7), d.rows.len);
    try testing.expectEqual(Value{ .int = 1234567890_000000 }, d.rows[0][0]);
    try testing.expectEqual(Value{ .int = 1234567890_000000 }, d.rows[1][0]);
    try testing.expectEqual(Value{ .int = 2 }, d.rows[2][0]);
    try testing.expect(d.rows[3][0] == .null);
    try testing.expect(d.rows[4][0] == .null);
    try testing.expect(d.rows[5][0] == .null);
    // 2009-02-13 UTC midnight = 1234567890 - (23*3600 + 31*60 + 30) = 1234483200.
    try testing.expectEqual(Value{ .int = 1234483200_000000 }, d.rows[6][0]);
}

test "TEETH: MAX_PATH_DEPTH is load-bearing and is actually applied" {
    // The depth cap is what stops a deeply nested document blowing the stack,
    // and NOTHING tested it: raising the constant to 4,000,000 left the whole
    // suite green while a 1.2 MB document segfaulted. A cap nothing exercises
    // is indistinguishable from a comment.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // Nest deeper than the cap, with the target key only at the bottom.
    const depth = MAX_PATH_DEPTH + 10;
    var doc: std.ArrayList(u8) = .empty;
    for (0..depth) |_| try doc.appendSlice(a, "{\"n\":");
    try doc.appendSlice(a, "{\"leaf\":[1,2]}");
    for (0..depth) |_| try doc.append(a, '}');

    // Reaching it needs more recursion than the cap allows, so the cap turns
    // this into an empty result rather than unbounded descent.
    const out_ds = try shape(a, doc.items, .{
        .path = "..leaf",
        .columns = &.{.{ .name = "v", .key = "", .type = .float }},
    });
    try testing.expectEqual(@as(usize, 0), out_ds.rows.len);

    // Control: the SAME path against a shallow document does find it, so the 0
    // above is the depth cap and not a broken fixture.
    const shallow = try shape(a, "{\"n\":{\"leaf\":[1,2]}}", .{
        .path = "..leaf",
        .columns = &.{.{ .name = "v", .key = "", .type = .float }},
    });
    try testing.expectEqual(@as(usize, 2), shallow.rows.len);
    try testing.expectEqual(@as(u32, 64), MAX_PATH_DEPTH);
}

test "TEETH: an out-of-range array index is refused, not read" {
    // `.index` is the newest segment type and its bounds check had no test:
    // deleting `if (idx < arr.items.len)` left all 21 tests green while giving
    // an out-of-bounds read of a std.json.Value union.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = "{\"a\":{\"b\":[[1],[2]]}}";

    // One past the end, and far past it.
    for ([_][]const u8{ "a.b[2]", "a.b[99999]" }) |path| {
        const out_ds = try shape(a, doc, .{
            .path = path,
            .columns = &.{.{ .name = "v", .key = "", .type = .float }},
        });
        try testing.expectEqual(@as(usize, 0), out_ds.rows.len);
    }
    // Control: the last VALID index still resolves, so the guard is off by
    // nothing in the other direction.
    const ok = try shape(a, doc, .{
        .path = "a.b[1]",
        .columns = &.{.{ .name = "v", .key = "", .type = .float }},
    });
    try testing.expectEqual(@as(usize, 1), ok.rows.len);
}

test "TEETH: a fixed path on a hostile document is REFUSED, not amplified" {
    // `MAX_PATH_DEPTH` was advertised as the DoS control. It bounds DEPTH, and
    // depth is not what grows: `recursiveFind` visits every value at every
    // level, so matches grow with the document's BRANCHING. Measured before
    // this cap existed, with an operator-written 6-byte path where only the
    // document is hostile: 163,831 B -> 393,220 rows, peak RSS 65 MiB (~417x).
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // `{"a":[<2 children>]}` nested 12 deep — ~41 KB, superlinear in matches.
    var doc: std.ArrayList(u8) = .empty;
    try buildBranching(a, &doc, 12, 2);

    try testing.expectError(Error.TooManyMatches, shape(a, doc.items, .{
        .path = "..a..a",
        .columns = &.{.{ .name = "v", .key = "", .type = .float }},
    }));

    // Raising the caller's own ceiling lets it through, so this is a bound and
    // not a broken path expression.
    const out_ds = try shape(a, doc.items, .{
        .path = "..a..a",
        .columns = &.{.{ .name = "v", .key = "", .type = .float }},
        .max_matches = 1 << 22,
    });
    try testing.expect(out_ds.rows.len > 65_536);
}

/// `{"a":[ <b copies> ]}` nested `d` deep — branching, which is the shape that
/// amplifies. A chain of the same byte length does not.
fn buildBranching(a: std.mem.Allocator, out: *std.ArrayList(u8), d: usize, b: usize) !void {
    if (d == 0) {
        try out.appendSlice(a, "1");
        return;
    }
    try out.appendSlice(a, "{\"a\":[");
    for (0..b) |i| {
        if (i > 0) try out.append(a, ',');
        try buildBranching(a, out, d - 1, b);
    }
    try out.appendSlice(a, "]}");
}

test "TEETH: a legacy dot-path really is routed to the legacy engine" {
    // The existing back-compat test could not see the routing it was named
    // for: forcing `isLegacyPath` to return false left it green, because both
    // engines happen to agree on its fixture. They do NOT agree in general —
    // a legacy path to a NON-array node yields no rows by design, while the
    // JSONPath engine treats that match as a single item. Pinning the
    // disagreement is what makes the routing observable.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"a\":{\"n\":1}}";
    const cols = [_]JsonCol{.{ .name = "n", .key = "n", .type = .float }};

    // Legacy: "a" is an object, not an array -> empty dataset.
    const legacy = try shape(a, json, .{ .path = "a", .columns = &cols });
    try testing.expectEqual(@as(usize, 0), legacy.rows.len);

    // JSONPath (the leading `$` is what switches engines): the same node
    // becomes one item.
    const jsonpath = try shape(a, json, .{ .path = "$.a", .columns = &cols });
    try testing.expectEqual(@as(usize, 1), jsonpath.rows.len);

    // And the predicate itself, so a future refactor of the trigger set is
    // caught at its source and not only through this behavioural difference.
    try testing.expect(isLegacyPath("a.b"));
    try testing.expect(!isLegacyPath("$.a"));
    try testing.expect(!isLegacyPath("a.b[0]"));
    try testing.expect(!isLegacyPath("a.*"));
    try testing.expect(!isLegacyPath("..a"));
    try testing.expect(!isLegacyPath("a[?(@.x == 1)]"));
}

// ── RFC 9535 conformance (2026-10-04) ───────────────────────────────────────
//
// Expected node lists are the RFC's own examples (RFC 9535 §2.3–§2.5 example
// tables and Table 11), re-typed from the RFC text, not produced by this code.

/// The node list `path` selects from `doc`, as compact JSON.
fn nodes(a: std.mem.Allocator, doc: []const u8, path: []const u8) ![]const u8 {
    const root = try std.json.parseFromSliceLeaky(J, a, doc, .{});
    const segs = try parsePath(a, path);
    var out: std.ArrayList(J) = .empty;
    var ctx: Ctx = .{ .a = a, .root = root, .out = &out, .limit = MAX_MATCHES };
    try evalSegs(&ctx, root, segs, 0);
    return std.json.Stringify.valueAlloc(a, out.items, .{});
}

fn expectNodes(a: std.mem.Allocator, doc: []const u8, path: []const u8, want: []const u8) !void {
    const got = try nodes(a, doc, path);
    if (!std.mem.eql(u8, got, want)) {
        std.debug.print("path {s}\n  want {s}\n  got  {s}\n", .{ path, want, got });
        return error.TestUnexpectedResult;
    }
}

test "RFC 9535 §2.3.1–2.3.4: name, wildcard, index and slice selectors" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // §2.3.1.3
    const names =
        \\{"o": {"j j": {"k.k": 3}}, "'": {"@": 2}}
    ;
    try expectNodes(a, names, "$.o['j j']", "[{\"k.k\":3}]");
    try expectNodes(a, names, "$.o['j j']['k.k']", "[3]");
    try expectNodes(a, names, "$.o[\"j j\"][\"k.k\"]", "[3]");
    try expectNodes(a, names, "$[\"'\"][\"@\"]", "[2]");
    // §2.3.2.3
    const wild =
        \\{"o": {"j": 1, "k": 2}, "a": [5, 3]}
    ;
    try expectNodes(a, wild, "$[*]", "[{\"j\":1,\"k\":2},[5,3]]");
    try expectNodes(a, wild, "$.o[*]", "[1,2]");
    try expectNodes(a, wild, "$.o[*, *]", "[1,2,1,2]");
    try expectNodes(a, wild, "$.a[*]", "[5,3]");
    // §2.3.3.3
    try expectNodes(a, "[\"a\",\"b\"]", "$[1]", "[\"b\"]");
    try expectNodes(a, "[\"a\",\"b\"]", "$[-2]", "[\"a\"]");
    try expectNodes(a, "[\"a\",\"b\"]", "$[-3]", "[]");
    try expectNodes(a, "[\"a\",\"b\"]", "$[2]", "[]");
    // §2.3.4.3
    const s =
        \\["a", "b", "c", "d", "e", "f", "g"]
    ;
    try expectNodes(a, s, "$[1:3]", "[\"b\",\"c\"]");
    try expectNodes(a, s, "$[5:]", "[\"f\",\"g\"]");
    try expectNodes(a, s, "$[1:5:2]", "[\"b\",\"d\"]");
    try expectNodes(a, s, "$[5:1:-2]", "[\"f\",\"d\"]");
    try expectNodes(a, s, "$[::-1]", "[\"g\",\"f\",\"e\",\"d\",\"c\",\"b\",\"a\"]");
    // Derived from the §2.3.4.2.2 algorithm: step 0 selects nothing; bounds clamp.
    try expectNodes(a, s, "$[::0]", "[]");
    try expectNodes(a, s, "$[-2:]", "[\"f\",\"g\"]");
    try expectNodes(a, s, "$[-100:2]", "[\"a\",\"b\"]");
    try expectNodes(a, s, "$[:-5]", "[\"a\",\"b\"]");
    try expectNodes(a, s, "$[ 0 : 7 : 3 ]", "[\"a\",\"d\",\"g\"]");
    try expectNodes(a, s, "$[1, -1, 0:2]", "[\"b\",\"g\",\"a\",\"b\"]");
}

test "RFC 9535 §2.3.5.3: filter selector examples" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\{"a": [3, 5, 1, 2, 4, 6, {"b": "j"}, {"b": "k"}, {"b": {}}, {"b": "kilo"}],
        \\ "o": {"p": 1, "q": 2, "r": 3, "s": 5, "t": {"u": 6}}, "e": "f"}
    ;
    const arr_a = "[3,5,1,2,4,6,{\"b\":\"j\"},{\"b\":\"k\"},{\"b\":{}},{\"b\":\"kilo\"}]";
    try expectNodes(a, doc, "$.a[?@.b == 'kilo']", "[{\"b\":\"kilo\"}]");
    try expectNodes(a, doc, "$.a[?(@.b == 'kilo')]", "[{\"b\":\"kilo\"}]");
    try expectNodes(a, doc, "$.a[?@>3.5]", "[5,4,6]");
    try expectNodes(a, doc, "$.a[?@.b]", "[{\"b\":\"j\"},{\"b\":\"k\"},{\"b\":{}},{\"b\":\"kilo\"}]");
    try expectNodes(a, doc, "$[?@.*]", "[" ++ arr_a ++ ",{\"p\":1,\"q\":2,\"r\":3,\"s\":5,\"t\":{\"u\":6}}]");
    try expectNodes(a, doc, "$[?@[?@.b]]", "[" ++ arr_a ++ "]");
    try expectNodes(a, doc, "$.o[?@<3, ?@<3]", "[1,2,1,2]");
    try expectNodes(a, doc, "$.a[?@<2 || @.b == \"k\"]", "[1,{\"b\":\"k\"}]");
    try expectNodes(a, doc, "$.o[?@>1 && @<4]", "[2,3]");
    try expectNodes(a, doc, "$.o[?@.u || @.x]", "[{\"u\":6}]");
    try expectNodes(a, doc, "$.a[?@.b == $.x]", "[3,5,1,2,4,6]");
    try expectNodes(a, doc, "$.a[?@ == @]", arr_a);
    // `!` negates a test; `&&` binds tighter than `||` (RFC 9535 Table 10).
    try expectNodes(a, doc, "$.a[?!@.b]", "[3,5,1,2,4,6]");
    try expectNodes(a, doc, "$.o[?@ == 1 || @ == 2 && @ == 3]", "[1]");
    try expectNodes(a, doc, "$.o[?(@ == 1 || @ == 2) && @ == 2]", "[2]");
    try expectNodes(a, doc, "$.o[?!(@ == 1 || @ == 2)]", "[3,5,{\"u\":6}]");
}

test "RFC 9535 Table 11: comparison semantics, Nothing included" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\{"obj": {"x": "y"}, "arr": [2, 3], "one": [0]}
    ;
    const Row = struct { []const u8, bool };
    const table = [_]Row{
        .{ "$.absent1 == $.absent2", true },
        .{ "$.absent1 <= $.absent2", true },
        .{ "$.absent == 'g'", false },
        .{ "$.absent1 != $.absent2", false },
        .{ "$.absent != 'g'", true },
        .{ "1 <= 2", true },
        .{ "1 > 2", false },
        .{ "13 == '13'", false },
        .{ "'a' <= 'b'", true },
        .{ "'a' > 'b'", false },
        .{ "$.obj == $.arr", false },
        .{ "$.obj != $.arr", true },
        .{ "$.obj == $.obj", true },
        .{ "$.obj != $.obj", false },
        .{ "$.arr == $.arr", true },
        .{ "$.arr != $.arr", false },
        .{ "$.obj == 17", false },
        .{ "$.obj != 17", true },
        .{ "$.obj <= $.arr", false },
        .{ "$.obj < $.arr", false },
        .{ "$.obj <= $.obj", true },
        .{ "$.arr <= $.arr", true },
        .{ "1 <= $.arr", false },
        .{ "1 >= $.arr", false },
        .{ "1 > $.arr", false },
        .{ "1 < $.arr", false },
        .{ "true <= true", true },
        .{ "true > true", false },
    };
    for (table) |row| {
        const path = try std.fmt.allocPrint(a, "$.one[?{s}]", .{row[0]});
        try expectNodes(a, doc, path, if (row[1]) "[0]" else "[]");
    }
    // Numbers compare by value across integer/float spellings; two integers
    // beyond 2^53 still compare exactly (they are not routed through f64).
    // (std.json writes the float 1.0 back as `1`; it is the first element.)
    try expectNodes(a, "[1.0, 2, 9007199254740993]", "$[?@ == 1]", "[1]");
    try expectNodes(a, "[9007199254740992, 9007199254740993]", "$[?@ == $[1]]", "[9007199254740993]");
}

test "RFC 9535 §2.5.2.3: descendant segment examples" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\{"o": {"j": 1, "k": 2}, "a": [5, 3, [{"j": 4}, {"k": 6}]]}
    ;
    try expectNodes(a, doc, "$..j", "[1,4]");
    try expectNodes(a, doc, "$..[0]", "[5,{\"j\":4}]");
    const all = "[{\"j\":1,\"k\":2},[5,3,[{\"j\":4},{\"k\":6}]],1,2,5,3,[{\"j\":4},{\"k\":6}],{\"j\":4},{\"k\":6},4,6]";
    try expectNodes(a, doc, "$..[*]", all);
    try expectNodes(a, doc, "$..*", all);
    try expectNodes(a, doc, "$.o..[*, *]", "[1,2,1,2]");
    try expectNodes(a, doc, "$.a..[0, 1]", "[5,3,{\"j\":4},{\"k\":6}]");
}

test "RFC 9535 §2.4: length / count / value functions" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\{"s": "héllo", "a": [1, 2, 3], "o": {"x": 1}, "one": [0]}
    ;
    const Row = struct { []const u8, bool };
    const table = [_]Row{
        .{ "length($.s) == 5", true }, // 5 Unicode scalar values, 6 UTF-8 bytes
        .{ "length($.a) == 3", true },
        .{ "length($.o) == 1", true },
        .{ "length(1) == 1", false }, // a number has no length: Nothing
        .{ "length($.absent) == $.absent", true }, // Nothing == Nothing
        .{ "length('ab') == 2", true },
        .{ "count($.a[*]) == 3", true },
        // `$..*` from the root: the four members (s, a, o, one), a's three
        // elements, o's one member and one's one element = 9 nodes.
        .{ "count($..*) == 9", true },
        .{ "count($..*) == 8", false },
        .{ "value($.a[0]) == 1", true },
        .{ "value($.a[*]) == 1", false }, // three nodes: Nothing
        .{ "value($.absent) == $.absent", true },
    };
    for (table) |row| {
        const path = try std.fmt.allocPrint(a, "$.one[?{s}]", .{row[0]});
        try expectNodes(a, doc, path, if (row[1]) "[0]" else "[]");
    }
}

test "RFC 9535 syntax: what is not well-formed or well-typed selects nothing" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\{"a": [1, 2], "01": 7, "x y": {"z": 1}}
    ;
    const bad = [_][]const u8{
        "$[01]", // leading zero
        "$.a[-0]", // RFC int has no -0
        "$.a[1 2]", // two selectors need a comma
        "$['a]", // unterminated string
        "$.a[?@.b == 1", // unterminated filter
        "$.a[?@.* == 1]", // a non-singular query cannot be compared
        "$.a[?length(@)]", // a value-typed function is not a test
        "$.a[?@ = 1]", // `=` is not an operator
        "$.a[?@ == 01]", // JSON numbers have no leading zero
        "$.a[?@ == 1.]", // nor an empty fraction
        "$['\\uD800']", // lone surrogate
        "$['\\q']", // unknown escape
        "$.a[9007199254740992]", // beyond I-JSON's exact integers
        "$.a[?@ == 'x' && ]", // dangling operator
        "$.a[?nosuch(@) == 1]", // unknown function
    };
    for (bad) |path| try expectNodes(a, doc, path, "[]");
    // Controls: the same shapes, well-formed, do select.
    try expectNodes(a, doc, "$['01']", "[7]");
    try expectNodes(a, doc, "$.a[0]", "[1]");
    try expectNodes(a, doc, "$.a[1, 0]", "[2,1]");
    try expectNodes(a, doc, "$.a[?@ == 1]", "[1]");
    try expectNodes(a, doc, "$['x y'].z", "[1]");
    try expectNodes(a, doc, "$['\\u0078 y']['z']", "[1]"); // x is "x"
    try expectNodes(a, "{\"a\\\"b\": 1, \"\\ud83d\\ude00\": 2}", "$[\"a\\\"b\"]", "[1]");
    try expectNodes(a, "{\"\\ud83d\\ude00\": 2}", "$['\\uD83D\\uDE00']", "[2]"); // surrogate pair → U+1F600
    // Expression nesting is bounded: 10 parentheses parse, 40 do not.
    const p10 = "$.a[?" ++ "(" ** 10 ++ "@ == 1" ++ ")" ** 10 ++ "]";
    try expectNodes(a, doc, p10, "[1]");
    const p40 = "$.a[?" ++ "(" ** 40 ++ "@ == 1" ++ ")" ** 40 ++ "]";
    try expectNodes(a, doc, p40, "[]");
}

test "filter sub-queries count against max_matches" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // count($..*) walks 12 nodes for every element; the cap is 10.
    const doc = "{\"r\":[1,2],\"d\":[1,2,3,4,5,6,7,8]}";
    try testing.expectError(Error.TooManyMatches, shape(a, doc, .{
        .path = "$.r[?count($..*) > 0]",
        .columns = &.{.{ .name = "v", .key = "", .type = .float }},
        .max_matches = 10,
    }));
    const ok = try shape(a, doc, .{
        .path = "$.r[?count($..*) > 0]",
        .columns = &.{.{ .name = "v", .key = "", .type = .float }},
        .max_matches = 100,
    });
    try testing.expectEqual(@as(usize, 2), ok.rows.len);
}

test "shape: a column key can be a path into the row item" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc =
        \\{"title": "T", "r": [
        \\  {"id": 1, "meta": {"ts": "2024-01-01", "tags": ["x", "y"]}},
        \\  {"id": 2, "meta": {}},
        \\  {"id": 3, "a.b": 7, "a": {"b": 9}}
        \\]}
    ;
    const d = try shape(a, doc, .{ .path = "r", .columns = &.{
        .{ .name = "ts", .key = "meta.ts", .type = .text },
        .{ .name = "last_tag", .key = "meta.tags[-1]", .type = .text },
        .{ .name = "ab", .key = "a.b", .type = .int },
        .{ .name = "title", .key = "$.title", .type = .text },
        .{ .name = "first_tag", .key = "meta['tags'][0]", .type = .text },
    } });
    try testing.expectEqual(@as(usize, 3), d.rows.len);
    try testing.expectEqualStrings("2024-01-01", d.rows[0][0].text);
    try testing.expect(d.rows[1][0] == .null);
    try testing.expectEqualStrings("y", d.rows[0][1].text);
    try testing.expect(d.rows[2][1] == .null);
    // Row 3 HAS a field literally named "a.b": the exact field wins (v1
    // behaviour), the path `a` → `b` (9) is not consulted.
    try testing.expectEqual(@as(i64, 7), d.rows[2][2].int);
    try testing.expect(d.rows[0][2] == .null);
    // `$…` reads from the document root, the same for every row.
    for (d.rows) |r| try testing.expectEqualStrings("T", r[3].text);
    try testing.expectEqualStrings("x", d.rows[0][4].text);
    // The [x,y] shorthand takes paths too.
    const xy = try shape(a, "[{\"p\":{\"t\":\"d1\",\"v\":[5]}}]", .{ .path = "$", .x = "p.t", .y = "p.v[0]" });
    try testing.expectEqualStrings("d1", xy.rows[0][0].text);
    try testing.expectEqual(@as(f64, 5), xy.rows[0][1].float);
}

test "RFC 9535 edges the mutation run asked for" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Deep equality: an object with an extra member, an array with an extra
    // element, are different values (RFC 9535 §2.3.5.2.2: same members / same
    // elements pairwise).
    const doc =
        \\{"o1": {"x": 1}, "o2": {"x": 1, "y": 2}, "a1": [1], "a2": [1, 2], "one": [0]}
    ;
    try expectNodes(a, doc, "$.one[?$.o1 == $.o2]", "[]");
    try expectNodes(a, doc, "$.one[?$.o2 == $.o1]", "[]");
    try expectNodes(a, doc, "$.one[?$.a1 == $.a2]", "[]");
    try expectNodes(a, doc, "$.one[?$.a1 != $.a2]", "[0]");
    try expectNodes(a, doc, "$.one[?$.o1 == {}]", "[]"); // `{}` is not a literal
    // A non-singular query never compares, even where its first node would match.
    try expectNodes(a, "{\"a\": [[1], [2]]}", "$.a[?@.* == 1]", "[]");
    try expectNodes(a, "{\"a\": [[1], [2]]}", "$.a[?@[0] == 1]", "[[1]]");
    // Strings order by code point; a non-ASCII member name works in a filter.
    try expectNodes(a, "[{\"\u{e9}\": \"b\"}, {\"\u{e9}\": \"a\"}]", "$[?@.\u{e9} < 'b']", "[{\"\u{e9}\":\"a\"}]");
    try expectNodes(a, "[\"a\", \"b\", 1]", "$[?@ < 'b']", "[\"a\"]");
    try expectNodes(a, "[1, 2, \"1\"]", "$[?@ >= 2]", "[2]");
    // A raw control character in a quoted name must be escaped.
    try expectNodes(a, "{\"a\\tb\": 1}", "$['a\tb']", "[]");
    try expectNodes(a, "{\"a\\tb\": 1}", "$['a\\tb']", "[1]");
    // A high surrogate must be followed by a LOW one; a \u escape takes hex only.
    try expectNodes(a, "{\"A\": 1}", "$['\\uD83D\\u0041']", "[]");
    try expectNodes(a, "{\"A\": 1}", "$['\\u+041']", "[]");
    try expectNodes(a, "{\"A\": 1}", "$['\\u0041']", "[1]");
}

test "max_matches: exactly the limit passes, one more is refused" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const doc = "{\"o\": {\"a\": 1, \"b\": 2, \"c\": 3}}";
    const col = [_]JsonCol{.{ .name = "v", .key = "", .type = .float }};
    const ok = try shape(a, doc, .{ .path = "$.o.*", .columns = &col, .max_matches = 3 });
    try testing.expectEqual(@as(usize, 3), ok.rows.len);
    try testing.expectError(Error.TooManyMatches, shape(a, doc, .{ .path = "$.o.*", .columns = &col, .max_matches = 2 }));
}

test "RFC 9535 edges the mutation run asked for, part 2" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s7 = "[\"a\", \"b\", \"c\", \"d\", \"e\", \"f\", \"g\"]";
    // An int beyond ±(2^53 − 1) is not well-formed, even where clamping
    // would have made it harmless: as a slice start it would select everything.
    try expectNodes(a, s7, "$[-9007199254740992:]", "[]");
    try expectNodes(a, s7, "$[-9007199254740991:2]", "[\"a\",\"b\"]");
    // §2.3.4.2.2 with a negative step: a start before the array clamps to −1,
    // so nothing is selected (clamping to 0 would select "a").
    try expectNodes(a, s7, "$[-100::-1]", "[]");
    try expectNodes(a, s7, "$[-7::-1]", "[\"a\"]");
    // Step 0 selects nothing, whatever the bounds (and must not loop).
    try expectNodes(a, s7, "$[5:1:0]", "[]");
    // The `\\` and `\/` escapes.
    try expectNodes(a, "{\"a\\\\b\": 1, \"a/b\": 2}", "$['a\\\\b']", "[1]");
    try expectNodes(a, "{\"a\\\\b\": 1, \"a/b\": 2}", "$['a\\/b']", "[2]");
    // A sub-query is held to max_matches at its own boundary: count() over
    // exactly the limit passes, one more is refused.
    const col = [_]JsonCol{.{ .name = "v", .key = "", .type = .float }};
    const doc = "{\"r\":[1],\"d\":[1,2,3,4,5,6,7,8,9]}";
    try testing.expectError(Error.TooManyMatches, shape(a, doc, .{ .path = "$.r[?count($.d[*]) > 0]", .columns = &col, .max_matches = 8 }));
    const ok = try shape(a, doc, .{ .path = "$.r[?count($.d[*]) == 9]", .columns = &col, .max_matches = 9 });
    try testing.expectEqual(@as(usize, 1), ok.rows.len);
}
