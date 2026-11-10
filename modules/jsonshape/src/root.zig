// SPDX-License-Identifier: MIT
//! jsonshape — reshape JSON into a `dataframe.Frame`: path descent to
//! array item(s) + typed column projection, and RFC 9535 JSONPath as a query
//! API of its own (`compile`, `query`, `queryFirst`, `queryLocated`).
//!
//! Remote-feed shaping (`getDataview` / `dataviewGet`): resolve `spec.path`
//! to the item(s) to project, then project each item into columns. The path
//! is one of two auto-detected dialects: the original **legacy dot-path**
//! (a dot-separated chain of object-key lookups to one array node, e.g.
//! `"data.prices"`), or **RFC 9535 JSONPath** — names, indices (negative
//! from the end), slices, wildcards, unions, descendants, and filters with
//! `&&`/`||`/`!`, existence tests and all five functions. `shape` reads it
//! permissively (a bad path selects nothing); `compile` by the RFC's grammar.
//! Projection
//! has two modes:
//!   * **columns** (generic): `[]JsonCol{name,key,type}` — one column per field.
//!   * **[x,y] default** (when `columns` is empty): 2 columns from
//!     `x`/`y` keys, or positional `item[0]/item[1]` for array items, or
//!     `[index, item]` for scalars.
//!
//! Values are parsed into `dataframe.Value`s honoring each column's
//! declared `ColumnType`. Allocates into `a` (a caller-owned arena); the parsed
//! JSON tree lives in the same arena, so string cells borrow it.
//!
//! Provenance: original work of the zig-libs authors (MIT).

const std = @import("std");
const df = @import("dataframe");
const regex = @import("regex");
const jsontext = @import("jsontext");
const iregexp = @import("iregexp.zig");
const Frame = df.Frame;
const Column = df.Column;
const ColumnType = df.ColumnType;
const Value = df.Value;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "JSON → `dataframe.Frame` reshaping and RFC 9535 JSONPath queries — path to items, typed column projection, Normalized Paths.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "RFC 9535 JSONPath for the paths; typed rows are its own",
    // `regex`: RFC 9535 `match()`/`search()`, through the I-Regexp check in
    // src/iregexp.zig. Linear-time, so a hostile pattern has no backtracking.
    .deps = .{ "dataframe", "regex", "jsontext" },
};

// ── public API ──────────────────────────────────────────────────────────────

pub const Error = error{
    BadJson,
    OutOfMemory,
    /// The path matched more nodes than `ShapeSpec.max_matches` allows. A
    /// refusal rather than a truncated result — see `MAX_MATCHES`.
    TooManyMatches,
    /// Evaluating the path (descents, filters, column-key paths, comparisons)
    /// took more steps than `ShapeSpec.max_work` allows. Distinct from
    /// `TooManyMatches`: the answer may be small while the walk is not.
    WorkLimit,
    /// The document nests deeper than `ShapeSpec.max_depth`. The input is valid
    /// JSON, so this is not `BadJson`: the feed exceeds the caller's limit.
    DepthLimit,
};

/// What `shape` returns: `Error`, and a refusal that only a column list can cause.
pub const ShapeError = Error || error{
    /// A declared column is `.list` or `.@"struct"`: `shape` builds scalar cells only
    /// (SPEC § Backlog). Checked before any cell is read.
    UnsupportedColumnType,
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
    /// Budget of evaluation steps for the whole `shape` call (every path node
    /// visit, descent, filter evaluation, comparison node and `length()`
    /// character, across the path and all column-key paths). `max_matches`
    /// bounds the ANSWER; this bounds the WORK: a fixed path such as
    /// `$[?count($..*) > 0]` or `$..*..*..*..*..x` is quadratic or exponential
    /// in a small hostile document while matching nothing. Exceeding it is
    /// `error.WorkLimit`. `null` = automatic: `1_000_000 + 16 * bytes.len`
    /// (saturating), enough for a handful of descendant segments over any
    /// document.
    max_work: ?usize = null,
    /// Refuse a document nested deeper than this (`error.DepthLimit`) BEFORE it
    /// is parsed: `std.json.Value` parsing keeps one stack entry per open
    /// container, so a feed of 16 MiB of `[` otherwise costs gigabytes.
    max_depth: u32 = 512,
    /// A document repeating an object key. `.reject` (`error.BadJson`) is the
    /// safe reading: two parsers of one feed can disagree on it. `.last` keeps
    /// the last value, as serde_json, Go's `encoding/json` and jq do.
    duplicate_keys: DuplicateKeys = .reject,
};

/// Same type as `dataframe.JsonDuplicateKeys` (`.reject` | `.last`).
pub const DuplicateKeys = df.JsonDuplicateKeys;

/// Step counter shared by every evaluation context of one `shape` or `query`
/// call, with the patterns from the document `match()`/`search()` have compiled.
const Work = struct {
    used: usize = 0,
    limit: usize,
    regexes: ?*RegexCache = null,

    fn charge(w: *Work, n: usize) Error!void {
        w.used +|= n;
        if (w.used > w.limit) return Error.WorkLimit;
    }
};

/// Max container nesting of `bytes`, outside strings, stopping as soon as it
/// exceeds `max`. Agrees with the parser on every valid prefix; an invalid
/// document is rejected by the parser at its first bad token, before it can
/// nest further.
fn checkDepth(bytes: []const u8, max: u32) Error!void {
    if (!jsontext.depthWithin(bytes, max)) return Error.DepthLimit;
}

/// Parse `bytes`, resolve `spec.path` to array item(s), project each item to a row.
///
/// `spec.path` accepts two dialects:
///   * **legacy dot-path** (back-compat, unchanged semantics): a plain
///     dot-separated chain of object-key lookups to exactly one array node
///     (e.g. `"data.prices"`). A single non-array match → empty frame.
///   * **RFC 9535 JSONPath** (triggered by any of `[`, `*`, `?`, `..`, or a
///     leading `$`): see the engine section below. May yield multiple matched nodes (e.g.
///     paginated arrays under a wildcard); each match contributes rows: an
///     `.array` match is flattened (its elements become items), any other
///     match becomes a single item itself.
///
/// The result is a `dataframe.Frame`: one typed array per column, text copied (nothing
/// borrows the JSON tree, though the tree still sits in `a`), a declared column whose
/// cells come out of more than one kind boxed, a `.categorical` column stored encoded.
/// A `.list` or `.@"struct"` declared column is `error.UnsupportedColumnType`.
pub fn shape(a: std.mem.Allocator, bytes: []const u8, spec: ShapeSpec) ShapeError!Frame {
    const root = try parseDocument(a, bytes, .{ .max_depth = spec.max_depth, .duplicate_keys = spec.duplicate_keys });
    var work: Work = .{ .limit = spec.max_work orelse 1_000_000 +| 16 *| bytes.len };
    const items = try resolveItems(a, root, spec.path, spec.max_matches, &work);

    if (spec.columns.len == 0) return shapeXY(a, root, items, spec, &work);

    // Every output row and cell is work, charged BEFORE it is allocated: the
    // legacy dot-path ignores `max_matches` (unchanged behaviour), and items x
    // columns (a user-supplied column list) is not bounded by it either.
    try work.charge(items.len *| (spec.columns.len +| 1));
    // After the charge: it saturates on a column count that is a lie, and the list is
    // not read before it.
    for (spec.columns) |jc| {
        if (jc.type == .list or jc.type == .array or jc.type == .@"struct") return error.UnsupportedColumnType;
    }
    const cols = try a.alloc(Column, spec.columns.len);
    const keys = try a.alloc(KeyRef, spec.columns.len);
    for (spec.columns, 0..) |jc, i| {
        cols[i] = .{ .name = jc.name, .type = jc.type };
        keys[i] = try keyRef(a, jc.key);
    }
    var b = try df.FrameBuilder.init(a, cols, items.len);
    const row = try a.alloc(Value, spec.columns.len);
    for (items) |item| {
        for (spec.columns, keys, row) |jc, kr, *cell| {
            const jv: ?std.json.Value = if (jc.key.len == 0) item else try resolveKey(a, root, item, kr, spec.max_matches, &work);
            cell.* = if (jv) |v| try jsonToValue(a, &work, v, jc.type) else .null;
        }
        b.appendRow(row) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.RowLength => unreachable, // `row` is as wide as `cols`
        };
    }
    return encodeCategorical(a, try b.toOwned());
}

/// Deprecated: `shape` returns a `Frame` since 2026-11-08; this alias stays one release.
pub const shapeFrame = shape;

/// Store every `.categorical` column dictionary-encoded (`dataframe.cast` to its own type).
fn encodeCategorical(a: std.mem.Allocator, f: Frame) Error!Frame {
    var out = f;
    for (f.columns) |c| {
        if (c.type != .categorical) continue;
        out = df.cast(a, out, .{ .col = c.name, .to = .categorical }) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.WorkLimit, // past u32 rows; the work budget normally refuses first
        };
    }
    return out;
}

pub const DocumentOptions = struct {
    max_depth: u32 = 512,
    duplicate_keys: DuplicateKeys = .reject,
};

/// A JSON document as the tree `query` walks, allocated in `a`; strings may
/// borrow `bytes`. `shape`'s own parse, with the same refusals.
pub fn parseDocument(a: std.mem.Allocator, bytes: []const u8, opts: DocumentOptions) Error!std.json.Value {
    try checkDepth(bytes, opts.max_depth);
    return std.json.parseFromSliceLeaky(std.json.Value, a, bytes, .{
        .duplicate_field_behavior = switch (opts.duplicate_keys) {
            .reject => .@"error",
            .last => .use_last,
        },
    }) catch |e| switch (e) {
        error.OutOfMemory => Error.OutOfMemory,
        else => Error.BadJson,
    };
}

// ── RFC 9535 query API ──────────────────────────────────────────────────────

/// A path that is well-formed and well-typed under RFC 9535, from `compile`.
/// Immutable and independent of any document: compile once, query many times,
/// from any number of threads. It lives in the allocator given to `compile` and
/// does not borrow `text`: names and patterns are copied.
pub const Path = struct { segs: []const Seg };

pub const CompileError = error{
    /// Not a well-formed, well-typed RFC 9535 query, or past a limit of ours
    /// (filter nesting `MAX_EXPR_DEPTH`, `MAX_PATH_REGEXES`).
    InvalidPath,
    OutOfMemory,
};

pub const Diagnostic = struct {
    /// Byte offset of the failure in the path text. 0 when the text is not
    /// UTF-8 or does not start with `$`.
    offset: usize = 0,
};

/// Parse `text` strictly: RFC 9535's grammar and nothing else, unlike
/// `ShapeSpec.path`, which keeps its permissive names and degrades a bad path
/// to no rows. All of RFC 9535 §2.4's functions; no function extension point.
pub fn compile(a: std.mem.Allocator, text: []const u8, diag: ?*Diagnostic) CompileError!Path {
    var p: Parser = .{ .a = a, .s = text, .strict = true };
    if (text.len > 0 and text[0] == '$' and std.unicode.utf8ValidateSlice(text)) {
        p.i = 1;
        if (parseSegs(&p, false)) |segs| {
            return .{ .segs = segs };
        } else |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Syntax => {},
        }
    }
    if (diag) |d| d.offset = p.i;
    return error.InvalidPath;
}

pub const QueryOptions = struct {
    /// `ShapeSpec.max_matches`: more matches is `error.TooManyMatches`.
    max_matches: usize = MAX_MATCHES,
    /// `ShapeSpec.max_work` for one query. A tree does not say how large its
    /// text was, so the automatic budget has nothing to scale with: the default
    /// is a fixed 2^28 steps, of the order of a second. Raise it for documents
    /// of hundreds of megabytes.
    max_work: usize = 1 << 28,
};

/// A node with its RFC 9535 §2.7 Normalized Path (`$['a'][0]`).
pub const Located = struct { path: []const u8, value: std.json.Value };

/// RFC 9535 §2.1.2: the nodelist `path` selects from `root`, in order.
pub fn query(a: std.mem.Allocator, root: std.json.Value, path: Path, opts: QueryOptions) Error![]const std.json.Value {
    var work: Work = .{ .limit = opts.max_work };
    var out: std.ArrayList(J) = .empty;
    var ctx: Ctx = .{ .a = a, .root = root, .out = &out, .limit = opts.max_matches, .work = &work };
    try evalSegs(&ctx, root, path.segs, 0);
    return out.toOwnedSlice(a);
}

/// The first node `path` selects, without walking the rest of the document.
pub fn queryFirst(a: std.mem.Allocator, root: std.json.Value, path: Path, opts: QueryOptions) Error!?std.json.Value {
    var work: Work = .{ .limit = opts.max_work };
    var ctx: Ctx = .{ .a = a, .root = root, .stop_after = 1, .limit = opts.max_matches, .work = &work };
    try evalSegs(&ctx, root, path.segs, 0);
    return ctx.found;
}

/// `query`, each node with its Normalized Path.
pub fn queryLocated(a: std.mem.Allocator, root: std.json.Value, path: Path, opts: QueryOptions) Error![]const Located {
    var work: Work = .{ .limit = opts.max_work };
    var out: std.ArrayList(Located) = .empty;
    var trail: Trail = .{};
    var ctx: Ctx = .{ .a = a, .root = root, .located = &out, .trail = &trail, .limit = opts.max_matches, .work = &work };
    try evalSegs(&ctx, root, path.segs, 0);
    return out.toOwnedSlice(a);
}

/// A column key, parsed once: a plain field name, or a path (see `JsonCol.key`).
const KeyRef = struct { key: []const u8, segs: ?[]const Seg };

fn keyRef(a: std.mem.Allocator, key: []const u8) Error!KeyRef {
    const is_path = std.mem.findAny(u8, key, ".[") != null;
    return .{ .key = key, .segs = if (is_path) try parsePath(a, key) else null };
}

/// The item's own field named `kr.key` first — v1 behaviour, so an existing
/// key that merely contains a dot still reads that field — else the first node
/// the key's path selects (from the item, or from the root for `$…`).
fn resolveKey(a: std.mem.Allocator, root: std.json.Value, item: std.json.Value, kr: KeyRef, limit: usize, work: *Work) Error!?std.json.Value {
    try work.charge(kr.key.len / 64); // hashing the key
    if (itemField(item, kr.key)) |v| return v;
    const segs = kr.segs orelse return null;
    var ctx: Ctx = .{ .a = a, .root = root, .stop_after = 1, .limit = limit, .work = work };
    try evalSegs(&ctx, if (kr.key[0] == '$') root else item, segs, 0);
    return ctx.found;
}

/// poc `[x,y]` default: 2 columns, one row per item.
fn shapeXY(a: std.mem.Allocator, root: std.json.Value, items: []const std.json.Value, spec: ShapeSpec, work: *Work) Error!Frame {
    const xk = try keyRef(a, spec.x);
    const yk = try keyRef(a, spec.y);
    try work.charge(items.len *| 3); // one row + two cells per item
    const cols = try a.alloc(Column, 2);
    cols[0] = .{ .name = "x", .type = .text };
    cols[1] = .{ .name = "y", .type = .float };
    var b = try df.FrameBuilder.init(a, cols, items.len);
    var row: [2]Value = undefined;
    for (items, 0..) |item, ri| {
        const xv: ?std.json.Value, const yv: ?std.json.Value = switch (item) {
            .object => .{
                if (spec.x.len > 0) try resolveKey(a, root, item, xk, spec.max_matches, work) else null,
                if (spec.y.len > 0) try resolveKey(a, root, item, yk, spec.max_matches, work) else null,
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
        // using `Value.asText()` silently gets null for exactly the
        // rows that took this branch. Found by mutation audit (1A).
        row[0] = if (xv) |v|
            try jsonToValue(a, work, v, .text)
        else
            .{ .text = try a.print("{d}", .{ri}) };
        row[1] = if (yv) |v| try jsonToValue(a, work, v, .float) else .null;
        b.appendRow(&row) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.RowLength => unreachable, // `row` is as wide as `cols`
        };
    }
    return b.toOwned();
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

// ── RFC 9535 engine (indices, wildcards, recursive descent, filters) ─────────
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

/// `integer` is a literal written as one that fits: it compares exactly with an
/// integer of the document, not through f64.
const Lit = union(enum) { integer: i64, number: f64, string: []const u8, boolean: bool, null };

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
    /// n-ary (a flat list, evaluated by a loop): a chain `a||b||c||…` of any
    /// length must not make evaluation recurse once per term.
    @"or": []const Expr,
    @"and": []const Expr,
    not: *const Expr,
    /// Existence test: true when the query selects at least one node.
    exists: Query,
    cmp: struct { l: Comparable, op: CmpOp, r: Comparable },
    /// `match()` (`full`) or `search()`.
    regex: struct { subject: Comparable, pattern: Pattern, full: bool },
};

const Pattern = union(enum) {
    /// A string literal, compiled once when the path is parsed. Null: anything
    /// that is not a valid I-Regexp string, which makes the function false.
    literal: ?*const regex.Regex,
    /// Read from the document at each evaluation (see `dynamicRegex`).
    dynamic: Comparable,
};

/// `match()`/`search()` calls one path may hold. A path is text a caller may
/// take from elsewhere, and 8 bytes of `a{1000}` compile to 1000 instructions:
/// without this a megabyte of path costs gigabytes before evaluation starts.
const MAX_PATH_REGEXES: u32 = 64;

/// What a compile needs only while it runs, kept so it is allocated once: `a` may
/// be an arena, and `regex.Regex.compile` would leave 80 KiB to 2 MiB in it per
/// call. With a `Builder` a program is at most 1024 instructions; a larger one is
/// `PatternTooLarge`, so the function is false (the engine's plain `compile` would
/// go to 4096).
const RegexScratch = struct {
    builder: regex.Builder,
    text: [iregexp.max_output]u8,
};

/// The engine's compiled form of an I-Regexp, allocated in `a`, or null when
/// `pattern` is not one or the engine refuses it (too large, `[z-a]`): RFC 9535
/// makes the function false in that case, so no engine error goes further than this.
fn compileRegex(a: std.mem.Allocator, scratch: *RegexScratch, pattern: []const u8) error{OutOfMemory}!?regex.Regex {
    const text = iregexp.translate(&scratch.text, pattern) orelse return null;
    return regex.Regex.compileUsing(a, &scratch.builder, text) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
}

/// Patterns read from the document in one call, the last few of them: a column of
/// equal or alternating patterns compiles each once. A fixed number of slots, each
/// reusing its own memory when its pattern is replaced, so what distinct patterns
/// cost in memory does not grow with their number, only in steps.
const RegexCache = struct {
    const n_slots = 8;
    const Slot = struct {
        pattern: ?[]const u8 = null,
        /// Null with a `pattern`: refused, which is worth remembering too.
        re: ?regex.Regex = null,
        arena: std.heap.ArenaAllocator,
    };

    scratch: RegexScratch,
    slots: [n_slots]Slot,
    next: usize,
};

/// A compile's cost in steps, where a step is about 10 ns. Measured with
/// `compileUsing`: 1 to 30 us for an ordinary pattern, `(a*){100}` 305 us for 304
/// instructions, `a{1000}` 12 us for 1003. Those points say the cost is not linear
/// in the program; the square is a conservative guess from them, not a measured
/// curve, chosen so that the short ordinary pattern pays little.
fn regexCompileWork(pattern_len: usize, insts: usize) usize {
    return 1024 +| pattern_len +| insts *| insts / 4;
}

/// The compiled form of a pattern from the document, valid until the next call
/// (the caller matches with it at once).
fn dynamicRegex(ctx: *Ctx, pattern: []const u8) Error!?*const regex.Regex {
    const w = ctx.work;
    const cache = w.regexes orelse blk: {
        const c = try ctx.a.create(RegexCache);
        c.next = 0;
        for (&c.slots) |*slot| slot.* = .{ .arena = std.heap.ArenaAllocator.init(ctx.a) };
        w.regexes = c;
        break :blk c;
    };
    try w.charge(pattern.len / 64 +| RegexCache.n_slots);
    for (&cache.slots) |*slot| {
        const known = slot.pattern orelse continue;
        if (std.mem.eql(u8, known, pattern)) return if (slot.re) |*re| re else null;
    }
    try w.charge(regexCompileWork(pattern.len, 0));
    const slot = &cache.slots[cache.next];
    cache.next = (cache.next + 1) % RegexCache.n_slots;
    slot.pattern = null;
    slot.re = null;
    _ = slot.arena.reset(.retain_capacity);
    slot.re = try compileRegex(slot.arena.allocator(), &cache.scratch, pattern);
    slot.pattern = pattern;
    const re = if (slot.re) |*re| re else return null;
    try w.charge(regexCompileWork(0, re.insts.len) -| 1024);
    return re;
}

fn isLegacyPath(path: []const u8) bool {
    if (path.len > 0 and path[0] == '$') return false;
    for (path) |c| {
        if (c == '[' or c == '*' or c == '?') return false;
    }
    if (std.mem.find(u8, path, "..") != null) return false;
    return true;
}

/// Resolve `path` to the item list rows get projected from. Legacy dot-paths
/// go through `descend` unchanged; anything else through the segment engine,
/// flattening `.array` matches (their elements become items) and treating
/// any other match as a single item itself.
fn resolveItems(a: std.mem.Allocator, root: J, path: []const u8, limit: usize, work: *Work) Error![]const J {
    if (isLegacyPath(path)) {
        const node = descend(root, path);
        return switch (node) {
            .array => |arr| arr.items,
            else => &.{}, // not an array → empty frame with the declared columns
        };
    }

    const segs = try parsePath(a, path);
    var matches: std.ArrayList(J) = .empty;
    var ctx: Ctx = .{ .a = a, .root = root, .out = &matches, .limit = limit, .work = work };
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
    /// RFC 9535's grammar exactly (`compile`), rather than `ShapeSpec.path`'s
    /// permissive top-level names, stray dots and `-` in names.
    strict: bool = false,
    regexes: u32 = 0,
    regex_scratch: ?*RegexScratch = null,

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
/// the path, so a malformed path degrades to an empty frame like
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
    if (p.strict) {
        // RFC 9535 `member-name-shorthand`. Any byte >= 0x80 is part of a code
        // point in `name-first`: `compile` checked the text is UTF-8.
        while (p.i < p.s.len) : (p.i += 1) {
            const c = p.s[p.i];
            const first_ok = std.ascii.isAlphabetic(c) or c == '_' or c >= 0x80;
            if (!(first_ok or (p.i > start and std.ascii.isDigit(c)))) break;
        }
        return p.s[start..p.i];
    }
    while (p.i < p.s.len) : (p.i += 1) {
        const c = p.s[p.i];
        if (in_filter) {
            if (!(std.ascii.isAlphanumeric(c) or c == '_' or c == '-' or c >= 0x80)) break;
        } else if (c == '.' or c == '[') break;
    }
    return p.s[start..p.i];
}

/// A shorthand name is a slice of the text. A `Path` must outlive that (`compile`
/// promises it), so there it is copied; `shape` parses and evaluates in one call.
fn ownName(p: *Parser, name: []const u8) ParseError![]const u8 {
    return if (p.strict) try p.a.dupe(u8, name) else name;
}

fn one(p: *Parser, sel: Selector) ParseError![]const Selector {
    const s = try p.a.alloc(Selector, 1);
    s[0] = sel;
    return s;
}

fn parseSegs(p: *Parser, in_filter: bool) ParseError![]Seg {
    var segs: std.ArrayList(Seg) = .empty;
    while (true) {
        // RFC 9535 `segments = *(S segment)`: blanks may lead to a segment.
        // In a filter they may equally lead to an operator: give them back.
        const before = p.i;
        if (p.strict or in_filter) p.skipWs();
        const c = p.peek() orelse {
            if (in_filter) {
                p.i = before;
            } else if (p.i != before) {
                return error.Syntax; // a query does not end in a blank
            }
            break;
        };
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
                    } else try segs.append(p.a, .{ .descendant = try one(p, .{ .name = try ownName(p, name) }) });
                }
            } else {
                if ((in_filter or p.strict) and p.peek() == '*') {
                    p.i += 1;
                    try segs.append(p.a, .{ .child = try one(p, .wildcard) });
                    continue;
                }
                const name = scanName(p, in_filter);
                if (name.len == 0) {
                    if (in_filter or p.strict) return error.Syntax;
                    continue; // tolerate stray/doubled '.' like legacy descend
                }
                const sel: Selector = if (std.mem.eql(u8, name, "*")) .wildcard else .{ .name = try ownName(p, name) };
                try segs.append(p.a, .{ .child = try one(p, sel) });
            }
        } else if (c == '[') {
            try segs.append(p.a, .{ .child = try parseBracket(p) });
        } else if (in_filter) {
            p.i = before;
            break; // the query ends here; the expression parser takes over
        } else if (p.strict) {
            return error.Syntax;
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
    const first = try parseAnd(p);
    var terms: std.ArrayList(Expr) = .empty;
    while (true) {
        p.skipWs();
        if (!p.eat("||")) break;
        if (terms.items.len == 0) try terms.append(p.a, first);
        try terms.append(p.a, try parseAnd(p));
    }
    if (terms.items.len == 0) return first;
    return .{ .@"or" = try terms.toOwnedSlice(p.a) };
}

fn parseAnd(p: *Parser) ParseError!Expr {
    const first = try parseBasic(p);
    var terms: std.ArrayList(Expr) = .empty;
    while (true) {
        p.skipWs();
        if (!p.eat("&&")) break;
        if (terms.items.len == 0) try terms.append(p.a, first);
        try terms.append(p.a, try parseBasic(p));
    }
    if (terms.items.len == 0) return first;
    return .{ .@"and" = try terms.toOwnedSlice(p.a) };
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
        } else if (try parseRegexCall(p)) |call| {
            inner.* = call;
        } else {
            // `!` applies to a test (an existence query), never to a comparison.
            const q = try parseQuery(p) orelse return error.Syntax;
            inner.* = .{ .exists = q };
        }
        return .{ .not = inner };
    }
    if (p.peek() == '(') return parseParen(p);
    if (try parseRegexCall(p)) |call| return call;
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

/// `match(value, pattern)` or `search(value, pattern)`, or null (nothing
/// consumed). They return LogicalType: a test, never an operand of a comparison,
/// so a `==` after one fails in the caller. RFC 9535 §2.4.6, §2.4.7.
fn parseRegexCall(p: *Parser) ParseError!?Expr {
    const full = if (p.eat("match(")) true else if (p.eat("search(")) false else return null;
    try p.enter();
    defer p.depth -= 1;
    p.regexes += 1;
    if (p.regexes > MAX_PATH_REGEXES) return error.Syntax;
    const subject = try parseComparable(p);
    p.skipWs();
    if (!p.eat(",")) return error.Syntax;
    const arg = try parseComparable(p);
    p.skipWs();
    if (!p.eat(")")) return error.Syntax;
    const pattern: Pattern = switch (arg) {
        .lit => |l| .{ .literal = switch (l) {
            .string => |s| try literalRegex(p, s),
            else => null,
        } },
        else => .{ .dynamic = arg },
    };
    return .{ .regex = .{ .subject = subject, .pattern = pattern, .full = full } };
}

fn literalRegex(p: *Parser, pattern: []const u8) ParseError!?*const regex.Regex {
    const scratch = p.regex_scratch orelse blk: {
        const s = try p.a.create(RegexScratch);
        p.regex_scratch = s;
        break :blk s;
    };
    const re = (try compileRegex(p.a, scratch, pattern)) orelse return null;
    const owned = try p.a.create(regex.Regex);
    owned.* = re;
    return owned;
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
    if (c == '-' or std.ascii.isDigit(c)) return .{ .lit = try parseNumber(p) };
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
fn parseNumber(p: *Parser) ParseError!Lit {
    const start = p.i;
    var integral = true;
    if (p.peek() == '-') p.i += 1;
    const int_start = p.i;
    while (p.peek()) |c| {
        if (!std.ascii.isDigit(c)) break;
        p.i += 1;
    }
    const int_len = p.i - int_start;
    if (int_len == 0 or (p.s[int_start] == '0' and int_len > 1)) return error.Syntax;
    if (p.peek() == '.') {
        integral = false;
        p.i += 1;
        const f = p.i;
        while (p.peek()) |c| {
            if (!std.ascii.isDigit(c)) break;
            p.i += 1;
        }
        if (p.i == f) return error.Syntax;
    }
    if (p.peek()) |e| if (e == 'e' or e == 'E') {
        integral = false;
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
    if (integral) if (std.fmt.parseInt(i64, p.s[start..p.i], 10)) |v| return .{ .integer = v } else |_| {};
    return .{ .number = std.fmt.parseFloat(f64, p.s[start..p.i]) catch return error.Syntax };
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
    work: *Work,
    /// `queryLocated`: matches go here, with what `trail` says at that moment.
    located: ?*std.ArrayList(Located) = null,
    trail: ?*Trail = null,

    fn done(c: *const Ctx) bool {
        return c.n >= c.stop_after;
    }
    fn push(c: *Ctx, step: Step) void {
        if (c.trail) |t| {
            t.steps[t.len] = step;
            t.len += 1;
        }
    }
    fn pop(c: *Ctx) void {
        if (c.trail) |t| t.len -= 1;
    }
};

const Step = union(enum) { name: []const u8, index: usize };

/// The way from the root to the current node. One step per level of `depth`,
/// and `depth` stops at `MAX_PATH_DEPTH + 1`, so it cannot overflow.
const Trail = struct {
    steps: [MAX_PATH_DEPTH + 2]Step = undefined,
    len: usize = 0,

    /// RFC 9535 §2.7: `$`, then `['name']` or `[index]` per step. Every byte written
    /// is charged: a long key under many children is a small document and a large
    /// sum of paths. The length before escapes goes first, so that memory is not
    /// spent past the budget; escapes after, at most one path late.
    fn normalized(t: *const Trail, ctx: *Ctx) Error![]const u8 {
        var cost: usize = 1;
        for (t.steps[0..t.len]) |s| cost +|= switch (s) {
            .name => |n| n.len +| 4,
            .index => 12,
        };
        try ctx.work.charge(cost);
        var out = try std.ArrayList(u8).initCapacity(ctx.a, cost);
        try out.append(ctx.a, '$');
        for (t.steps[0..t.len]) |s| switch (s) {
            .index => |i| try out.print(ctx.a, "[{d}]", .{i}),
            .name => |n| {
                try out.appendSlice(ctx.a, "['");
                for (n) |c| switch (c) {
                    0x08 => try out.appendSlice(ctx.a, "\\b"),
                    0x09 => try out.appendSlice(ctx.a, "\\t"),
                    0x0a => try out.appendSlice(ctx.a, "\\n"),
                    0x0c => try out.appendSlice(ctx.a, "\\f"),
                    0x0d => try out.appendSlice(ctx.a, "\\r"),
                    '\'' => try out.appendSlice(ctx.a, "\\'"),
                    '\\' => try out.appendSlice(ctx.a, "\\\\"),
                    0x00...0x07, 0x0b, 0x0e...0x1f => try out.print(ctx.a, "\\u{x:0>4}", .{c}),
                    else => try out.append(ctx.a, c),
                };
                try out.appendSlice(ctx.a, "']");
            },
        };
        try ctx.work.charge(out.items.len -| cost);
        return out.toOwnedSlice(ctx.a);
    }
};

fn evalSegs(ctx: *Ctx, node: J, segs: []const Seg, depth: u32) Error!void {
    try ctx.work.charge(1); // charged FIRST: no iteration is free, even one that returns at once
    if (depth > MAX_PATH_DEPTH) return Error.DepthLimit; // never a silent drop
    if (ctx.done()) return;
    if (segs.len == 0) {
        // Checked at the ONE place a match is recorded, so no caller can add a
        // new recursion arm that bypasses it.
        if (ctx.n >= ctx.limit) return Error.TooManyMatches;
        ctx.n += 1;
        if (ctx.out) |o| {
            try o.append(ctx.a, node);
        } else if (ctx.located) |o| {
            try o.append(ctx.a, .{ .path = try ctx.trail.?.normalized(ctx), .value = node });
        } else if (ctx.found == null) {
            ctx.found = node;
        }
        return;
    }
    const rest = segs[1..];
    switch (segs[0]) {
        .never => {},
        .child => |sels| {
            try ctx.work.charge(sels.len); // one lookup per selector
            for (sels) |sel| {
                if (ctx.done()) return;
                try select(ctx, node, sel, rest, depth);
            }
        },
        .descendant => |sels| try descendAll(ctx, node, sels, rest, depth),
    }
}

/// RFC 9535 §2.5.2: the selectors applied to `node`, then to each of its
/// descendants, depth-first in document order.
fn descendAll(ctx: *Ctx, node: J, sels: []const Selector, rest: []const Seg, depth: u32) Error!void {
    try ctx.work.charge(1 +| sels.len); // charged first; one lookup per selector per node
    if (depth > MAX_PATH_DEPTH) return Error.DepthLimit; // never a silent drop
    if (ctx.done()) return;
    for (sels) |sel| {
        if (ctx.done()) return;
        try select(ctx, node, sel, rest, depth);
    }
    switch (node) {
        .object => |o| for (o.keys(), o.values()) |k, v| {
            if (ctx.done()) return;
            ctx.push(.{ .name = k });
            try descendAll(ctx, v, sels, rest, depth + 1);
            ctx.pop();
        },
        .array => |arr| for (arr.items, 0..) |it, i| {
            if (ctx.done()) return;
            ctx.push(.{ .index = i });
            try descendAll(ctx, it, sels, rest, depth + 1);
            ctx.pop();
        },
        else => {},
    }
}

/// `evalSegs` on a child of the current node, with its step on the trail.
fn evalChild(ctx: *Ctx, child: J, step: Step, rest: []const Seg, depth: u32) Error!void {
    ctx.push(step);
    try evalSegs(ctx, child, rest, depth + 1);
    ctx.pop();
}

fn select(ctx: *Ctx, node: J, sel: Selector, rest: []const Seg, depth: u32) Error!void {
    switch (sel) {
        .name => |k| switch (node) {
            .object => |o| {
                try ctx.work.charge(k.len / 64); // hashing the name
                if (o.get(k)) |v| try evalChild(ctx, v, .{ .name = k }, rest, depth);
            },
            else => {},
        },
        .index => |idx| switch (node) {
            .array => |arr| if (normIndex(idx, arr.items.len)) |i| try evalChild(ctx, arr.items[i], .{ .index = i }, rest, depth),
            else => {},
        },
        .wildcard => switch (node) {
            .array => |arr| for (arr.items, 0..) |it, i| {
                if (ctx.done()) return;
                try evalChild(ctx, it, .{ .index = i }, rest, depth);
            },
            .object => |o| for (o.keys(), o.values()) |k, v| {
                if (ctx.done()) return;
                try evalChild(ctx, v, .{ .name = k }, rest, depth);
            },
            else => {},
        },
        .slice => |sl| switch (node) {
            .array => |arr| try selectSlice(ctx, arr.items, sl, rest, depth),
            else => {},
        },
        .filter => |e| switch (node) {
            .array => |arr| for (arr.items, 0..) |it, i| {
                if (ctx.done()) return;
                if (try evalExpr(ctx, it, e, depth + 1)) try evalChild(ctx, it, .{ .index = i }, rest, depth);
            },
            .object => |o| for (o.keys(), o.values()) |k, v| {
                if (ctx.done()) return;
                if (try evalExpr(ctx, v, e, depth + 1)) try evalChild(ctx, v, .{ .name = k }, rest, depth);
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
        while (i < upper) : (i += step) {
            if (ctx.done()) return;
            const at: usize = @intCast(i);
            try evalChild(ctx, items[at], .{ .index = at }, rest, depth);
        }
    } else {
        const upper = @min(@max(n_start, -1), len - 1);
        const lower = @min(@max(n_end, -1), len - 1);
        var i = upper;
        while (lower < i) : (i += step) {
            if (ctx.done()) return;
            const at: usize = @intCast(i);
            try evalChild(ctx, items[at], .{ .index = at }, rest, depth);
        }
    }
}

fn evalExpr(ctx: *Ctx, cur: J, e: *const Expr, depth: u32) Error!bool {
    try ctx.work.charge(1);
    if (depth > MAX_PATH_DEPTH) return Error.DepthLimit;
    return switch (e.*) {
        .@"or" => |terms| {
            for (terms) |*t| if (try evalExpr(ctx, cur, t, depth)) return true;
            return false;
        },
        .@"and" => |terms| {
            for (terms) |*t| if (!try evalExpr(ctx, cur, t, depth)) return false;
            return true;
        },
        .not => |inner| !try evalExpr(ctx, cur, inner, depth),
        .exists => |q| (try runQuery(ctx, cur, q, 1, depth)).n > 0,
        .cmp => |c| try compare(ctx, try evalComparable(ctx, cur, c.l, depth), c.op, try evalComparable(ctx, cur, c.r, depth)),
        .regex => |r| {
            const subject = (try evalComparable(ctx, cur, r.subject, depth)) orelse return false;
            if (subject != .string) return false;
            const re: *const regex.Regex = switch (r.pattern) {
                .literal => |l| l orelse return false,
                .dynamic => |d| blk: {
                    const pattern = (try evalComparable(ctx, cur, d, depth)) orelse return false;
                    if (pattern != .string) return false;
                    break :blk (try dynamicRegex(ctx, pattern.string)) orelse return false;
                },
            };
            // Linear in the subject, times what the engine runs per byte: a lazy DFA
            // up to 128 instructions (2 ns per byte), which falls back on the Pike
            // VM when its states run out; past that always the VM, about 9 ns per
            // byte and instruction, measured: 8.4 s for 908 instructions over 1 MiB.
            // regex's `Dfa.max_insts` is private, so 128 is written here.
            const insts = re.insts.len;
            const per_byte = if (insts <= 128) insts / 8 + 1 else insts;
            try ctx.work.charge(subject.string.len *| per_byte);
            return if (r.full) re.fullMatch(subject.string) else re.isMatch(subject.string);
        },
    };
}

/// Run a filter's sub-query from `cur` (or the root), keeping the first match
/// and stopping after `stop_after`. Its matches count against the same
/// `limit` as the path's own.
fn runQuery(ctx: *Ctx, cur: J, q: Query, stop_after: usize, depth: u32) Error!Ctx {
    var sub: Ctx = .{ .a = ctx.a, .root = ctx.root, .stop_after = stop_after, .limit = ctx.limit, .work = ctx.work };
    try evalSegs(&sub, if (q.absolute) ctx.root else cur, q.segs, depth + 1);
    return sub;
}

/// A comparable's value; null is RFC 9535's "Nothing" (no node), distinct
/// from a JSON `null`.
fn evalComparable(ctx: *Ctx, cur: J, c: Comparable, depth: u32) Error!?J {
    return switch (c) {
        .lit => |l| switch (l) {
            .integer => |n| J{ .integer = n },
            .number => |n| J{ .float = n },
            .string => |s| J{ .string = s },
            .boolean => |b| J{ .bool = b },
            .null => J.null,
        },
        .query => |q| (try runQuery(ctx, cur, q, 1, depth)).found,
        .length => |arg| switch ((try evalComparable(ctx, cur, arg.*, depth)) orelse return null) {
            .string => |s| blk: {
                try ctx.work.charge(s.len); // O(len) per evaluation
                break :blk J{ .integer = @intCast(std.unicode.utf8CountCodepoints(s) catch return null) };
            },
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
fn compare(ctx: *Ctx, l: ?J, op: CmpOp, r: ?J) Error!bool {
    const eq = if (l == null or r == null) l == null and r == null else try jsonEq(ctx, l.?, r.?, 0);
    return switch (op) {
        .eq => eq,
        .ne => !eq,
        .lt => l != null and r != null and (try jsonLt(ctx, l.?, r.?)),
        .le => eq or (l != null and r != null and (try jsonLt(ctx, l.?, r.?))),
        .gt => l != null and r != null and (try jsonLt(ctx, r.?, l.?)),
        .ge => eq or (l != null and r != null and (try jsonLt(ctx, r.?, l.?))),
    };
}

fn jsonNum(ctx: *Ctx, v: J) Error!?f64 {
    return switch (v) {
        .integer => |i| @as(f64, @floatFromInt(i)),
        .float => |f| f,
        .number_string => |s| blk: {
            try ctx.work.charge(s.len / 64); // parseFloat is O(len)
            break :blk std.fmt.parseFloat(f64, s) catch null;
        },
        else => null,
    };
}

fn jsonEq(ctx: *Ctx, a: J, b: J, depth: u32) Error!bool {
    try ctx.work.charge(1);
    if (depth > MAX_PATH_DEPTH) return Error.DepthLimit;
    if (a == .integer and b == .integer) return a.integer == b.integer;
    if (try jsonNum(ctx, a)) |x| return if (try jsonNum(ctx, b)) |y| x == y else false;
    return switch (a) {
        .string => |s| blk: {
            try ctx.work.charge(s.len / 64); // memcmp is O(len)
            break :blk b == .string and std.mem.eql(u8, s, b.string);
        },
        .bool => |x| b == .bool and b.bool == x,
        .null => b == .null,
        .array => |x| blk: {
            if (b != .array or b.array.items.len != x.items.len) break :blk false;
            for (x.items, b.array.items) |p, q| if (!try jsonEq(ctx, p, q, depth + 1)) break :blk false;
            break :blk true;
        },
        .object => |x| blk: {
            if (b != .object or b.object.count() != x.count()) break :blk false;
            var it = x.iterator();
            while (it.next()) |kv| {
                try ctx.work.charge(kv.key_ptr.len / 64);
                const other = b.object.get(kv.key_ptr.*) orelse break :blk false;
                if (!try jsonEq(ctx, kv.value_ptr.*, other, depth + 1)) break :blk false;
            }
            break :blk true;
        },
        // A number that did not read as one (`jsonNum` above) equals nothing.
        .integer, .float, .number_string => false,
    };
}

fn jsonLt(ctx: *Ctx, a: J, b: J) Error!bool {
    if (a == .integer and b == .integer) return a.integer < b.integer;
    if (try jsonNum(ctx, a)) |x| return if (try jsonNum(ctx, b)) |y| x < y else false;
    if (a == .string and b == .string) {
        try ctx.work.charge(@min(a.string.len, b.string.len) / 64);
        return std.mem.order(u8, a.string, b.string) == .lt;
    }
    return false;
}

fn itemField(item: std.json.Value, key: []const u8) ?std.json.Value {
    return switch (item) {
        .object => |o| o.get(key),
        else => null,
    };
}

/// Coerce a JSON value into a canonical Value honoring `want` (the column type).
fn jsonToValue(a: std.mem.Allocator, work: *Work, jv: std.json.Value, want: ColumnType) Error!Value {
    // Number/timestamp parsing and text handling are O(len) of a payload that
    // many cells can reach (an absolute key re-reads the same node per row).
    switch (jv) {
        .string, .number_string => |t| try work.charge(t.len / 64),
        else => {},
    }
    return switch (want) {
        .list, .array, .@"struct" => unreachable, // refused by `shape` before any cell is read
        .int => .{ .int = jsonToInt(jv) orelse return .null },
        .float => .{ .float = jsonToFloat(jv) orelse return .null },
        // dataframe's width types (W11): the integer (a UInt64 above maxInt(i64) arrives as a
        // number string) or the float, then the width's range by `Value.cast` (out of it: null).
        .int8, .int16, .int32, .uint8, .uint16, .uint32, .uint64 => blk: {
            const v: Value = if (jsonToInt(jv)) |i| .{ .int = i } else switch (jv) {
                .number_string => |s| if (std.fmt.parseInt(u64, s, 10)) |u| .{ .uint = u } else |_| break :blk .null,
                else => break :blk .null,
            };
            break :blk v.cast(want) orelse .null;
        },
        .float32 => (Value{ .float = jsonToFloat(jv) orelse return .null }).cast(.float32) orelse .null,
        .bool => switch (jv) {
            .bool => |b| .{ .bool = b },
            else => .null,
        },
        // dataframe's Binary (2026-11-10): a JSON string is base64, as dataframe writes and
        // reads it (`Value.cast(.binary)` of text is its UTF-8 bytes, not a decode).
        .binary => switch (jv) {
            .string => |s| (try df.parseBinary(a, s)) orelse .null,
            else => .null,
        },
        .text, .date, .categorical => switch (jv) {
            .string => |s| .{ .text = s }, // the frame builder copies it
            .number_string => |s| .{ .text = s },
            .integer => |i| .{ .text = try a.print("{d}", .{i}) },
            .float => |f| .{ .text = try a.print("{d}", .{f}) },
            .bool => |b| .{ .text = if (b) "true" else "false" },
            else => .null,
        },
        // JSON has no fixed-point type; go through the same numeric parse as
        // .float, then widen via Value.cast (float*scale, truncated — see
        // dataframe's Value.cast doc comment). No dependency on the `decimal`
        // module for text parsing here (same limitation `Value.cast` documents).
        .decimal => blk: {
            const f = jsonToFloat(jv) orelse break :blk .null;
            break :blk (Value{ .float = f }).cast(.decimal) orelse .null;
        },
        // An instant or a length of time: an ISO 8601 / RFC 3339 (resp. ISO 8601 duration)
        // string, or a number already in the column's unit (microseconds) — `Value.cast`'s
        // rules, so a JSON feed and a cast agree. A time of day the same way (`"01:02:03"` or
        // microseconds since midnight; outside one day null). Anything else → null.
        .timestamp, .duration, .time => blk: {
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
            break :blk v.cast(want) orelse .null;
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
    try testing.expectEqual(@as(usize, 2), d.len);
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
    try testing.expectEqual(@as(usize, 3), d.len);
    try testing.expectEqualStrings("2", d.cell(1, "x").?.text);
    try testing.expectEqual(@as(f64, 30), d.cell(2, "y").?.float);
}

test "shape: missing path node → empty frame (not an error)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "{\"a\":1}", .{ .path = "nope.array", .columns = &.{
        .{ .name = "v", .key = "v", .type = .float },
    } });
    try testing.expectEqual(@as(usize, 0), d.len);
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
    try testing.expectEqual(@as(usize, 0), d.len);

    // Control: the same document at the path that DOES exist yields the rows,
    // so the assertion above is about the missing segment and not about the
    // fixture being unreadable.
    const ok = try shape(a, json, .{ .path = "array", .columns = &.{
        .{ .name = "v", .key = "v", .type = .float },
    } });
    try testing.expectEqual(@as(usize, 2), ok.len);
    try testing.expectEqual(@as(f64, 7), ok.cell(0, "v").?.float);

    // The same trap one level deeper: a missing FINAL segment must not resolve
    // to the object it was looked up in.
    const deep = try shape(a, "{\"outer\":{\"a\":1,\"array\":[{\"v\":9}]}}", .{ .path = "outer.nope.array", .columns = &.{
        .{ .name = "v", .key = "v", .type = .float },
    } });
    try testing.expectEqual(@as(usize, 0), deep.len);
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
    try testing.expectEqual(@as(usize, 2), d.len);
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
    try testing.expectEqual(@as(usize, 1), d.len);
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
    try testing.expectEqual(@as(usize, 3), d.len);
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
    try testing.expectEqual(@as(usize, 3), d.len);
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
    try testing.expectEqual(@as(usize, 3), d.len);
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
    try testing.expectEqual(@as(usize, 5), d.len);
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
    try testing.expectEqual(@as(usize, 2), d.len);
    try testing.expectEqual(@as(i64, 1), d.cell(0, "id").?.int);
    try testing.expectEqual(@as(i64, 3), d.cell(1, "id").?.int);
    // Positive control: id=2 ("bad") must be excluded, not merely
    // deprioritized — assert it's gone from every row.
    for (0..d.len) |ri| {
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
    try testing.expectEqual(@as(usize, 1), d.len);
    try testing.expectEqual(@as(i64, 10), d.cell(0, "n").?.int);
}

test "shape: numeric filter operators — ne, lt, le, ge (all previously untested)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"arr\":[{\"n\":1},{\"n\":5},{\"n\":10}]}";

    const ne = try shape(a, json, .{ .path = "arr[?(@.n != 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 2), ne.len);

    const lt = try shape(a, json, .{ .path = "arr[?(@.n < 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 1), lt.len);
    try testing.expectEqual(@as(i64, 1), lt.cell(0, "n").?.int);

    const le = try shape(a, json, .{ .path = "arr[?(@.n <= 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 2), le.len);

    // `>=` — distinguishes from `>`: 5 must be INCLUDED here.
    const ge = try shape(a, json, .{ .path = "arr[?(@.n >= 5)]", .columns = &.{.{ .name = "n", .key = "n", .type = .int }} });
    try testing.expectEqual(@as(usize, 2), ge.len);
    try testing.expectEqual(@as(i64, 5), ge.cell(0, "n").?.int);
    try testing.expectEqual(@as(i64, 10), ge.cell(1, "n").?.int);
}

test "shape: string filter operators — ne, lt, le, gt, ge (all previously untested)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json = "{\"arr\":[{\"s\":\"a\"},{\"s\":\"b\"},{\"s\":\"c\"}]}";

    const ne = try shape(a, json, .{ .path = "arr[?(@.s != \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 2), ne.len);

    const lt = try shape(a, json, .{ .path = "arr[?(@.s < \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 1), lt.len);
    try testing.expectEqualStrings("a", lt.cell(0, "s").?.text);

    const gt = try shape(a, json, .{ .path = "arr[?(@.s > \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 1), gt.len);
    try testing.expectEqualStrings("c", gt.cell(0, "s").?.text);

    // `<=` / `>=` must include the boundary "b", distinguishing them from `<`/`>`.
    const le = try shape(a, json, .{ .path = "arr[?(@.s <= \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 2), le.len);

    const ge = try shape(a, json, .{ .path = "arr[?(@.s >= \"b\")]", .columns = &.{.{ .name = "s", .key = "s", .type = .text }} });
    try testing.expectEqual(@as(usize, 2), ge.len);
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
    try testing.expectEqual(@as(usize, 1), eq_true.len);
    try testing.expectEqual(@as(i64, 1), eq_true.cell(0, "id").?.int);

    // RFC 9535 §2.3.5.2.2 (Table 11: `$.absent != 'g'` is true): an ABSENT
    // member is Nothing, and Nothing != true. Element 3 has no `active`, so it
    // matches too. (Before 2026-10-04 a missing field failed every comparison,
    // `!=` included — not RFC behaviour.)
    const ne_true = try shape(a, json, .{ .path = "arr[?(@.active != true)]", .columns = &.{.{ .name = "id", .key = "id", .type = .int }} });
    try testing.expectEqual(@as(usize, 2), ne_true.len);
    try testing.expectEqual(@as(i64, 2), ne_true.cell(0, "id").?.int);
    try testing.expectEqual(@as(i64, 3), ne_true.cell(1, "id").?.int);

    const is_null = try shape(a, json, .{ .path = "arr[?(@.note == null)]", .columns = &.{.{ .name = "id", .key = "id", .type = .int }} });
    try testing.expectEqual(@as(usize, 1), is_null.len);
    try testing.expectEqual(@as(i64, 3), is_null.cell(0, "id").?.int);
}

test "shape: [x,y] default from a top-level array of bare scalars (else branch of shapeXY, untested)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a, "[10, 20, 30]", .{});
    try testing.expectEqual(@as(usize, 3), d.len);
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
    try testing.expectEqual(@as(usize, 1), d.len);
    try testing.expectEqual(@as(i64, 42), d.cell(0, "as_int").?.int);
    try testing.expectEqual(@as(f64, 42), d.cell(0, "as_float").?.float);
}

test "shape: malformed JSONPath syntax → empty frame, not a crash" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Unterminated '[' — invalid syntax degrades to "no match", same
    // leniency contract as a missing key.
    const d = try shape(a, "{\"a\":[1,2,3]}", .{
        .path = "a[0",
        .columns = &.{.{ .name = "v", .type = .int }},
    });
    try testing.expectEqual(@as(usize, 0), d.len);
}

test "shape: the x column honours its declared .text type on every branch" {
    // The declared type is the contract frame consumers rely on. Before
    // this, the index fallback stored `.int` into a column declared `.text`,
    // so the two branches of the same column had different active union
    // fields — invisible to every test that only exercised the object branch.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    // A top-level array of bare scalars takes the index fallback for x.
    const d = try shape(a, "[10, 20, 30]", .{});
    try testing.expectEqual(ColumnType.text, d.columns[0].type);
    try testing.expectEqual(@as(usize, 3), d.len);
    for (0..d.len) |i| {
        // `.asText()` must answer for EVERY row, not just the ones that
        // happened to come from an object.
        const got = d.columnAt(0).get(i).asText() orelse return error.XColumnNotText;
        var buf: [8]u8 = undefined;
        try testing.expectEqualStrings(try std.mem.print(&buf, "{d}", .{i}), got);
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
        try testing.expectEqual(@as(usize, 1), out_ds.len);
        try testing.expect(out_ds.columnAt(0).get(0) == .null);
    }
    // A value that DOES fit still converts, so the guard is not simply
    // rejecting everything.
    const ok = try shape(a, "{\"r\":[{\"v\":42.9}]}", .{
        .path = "r",
        .columns = &.{.{ .name = "v", .key = "v", .type = .int }},
    });
    try testing.expectEqual(@as(i64, 42), ok.columnAt(0).get(0).int);
}

test "TEETH: an out-of-range JSON number degrades to null in a .decimal column too" {
    // Distinct from the test above: `dataframe`'s `Value.cast(.decimal)` guarded
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
    try testing.expect(out_ds.columnAt(0).get(0) == .null);
    const ok = try shape(a, "{\"r\":[{\"v\":1.5}]}", .{
        .path = "r",
        .columns = &.{.{ .name = "v", .key = "v", .type = .decimal }},
    });
    try testing.expect(ok.columnAt(0).get(0) == .decimal);
}

test "shape: a .timestamp column reads RFC 3339 strings and microsecond numbers" {
    // 2009-02-13T23:31:30Z is Unix time 1234567890 (a published anchor); the
    // column unit is microseconds, so the cell is that times 1e6. A number is
    // taken as already being in that unit (dataframe's `Value.cast` rule); text
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
    try testing.expectEqual(@as(usize, 7), d.len);
    try testing.expectEqual(Value{ .int = 1234567890_000000 }, d.columnAt(0).get(0));
    try testing.expectEqual(Value{ .int = 1234567890_000000 }, d.columnAt(0).get(1));
    try testing.expectEqual(Value{ .int = 2 }, d.columnAt(0).get(2));
    try testing.expect(d.columnAt(0).get(3) == .null);
    try testing.expect(d.columnAt(0).get(4) == .null);
    try testing.expect(d.columnAt(0).get(5) == .null);
    // 2009-02-13 UTC midnight = 1234567890 - (23*3600 + 31*60 + 30) = 1234483200.
    try testing.expectEqual(Value{ .int = 1234483200_000000 }, d.columnAt(0).get(6));
}

test "shape: a .time column reads HH:MM:SS text and microseconds since midnight" {
    // dataframe's time of day (2026-11-10): `Value.cast(.time)` on the JSON value, so a
    // feed and a cast agree; outside one day, or not a time, null.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a,
        \\{"r":[{"t":"01:02:03"},{"t":3723000000},{"t":"25:00"},{"t":-1},{"t":true},{"t":"00:00:00.120"}]}
    , .{
        .path = "r",
        .columns = &.{.{ .name = "t", .key = "t", .type = .time }},
    });
    try testing.expectEqual(@as(usize, 6), d.len);
    try testing.expectEqual(Value{ .int = 3_723_000_000 }, d.columnAt(0).get(0));
    try testing.expectEqual(Value{ .int = 3_723_000_000 }, d.columnAt(0).get(1));
    try testing.expect(d.columnAt(0).get(2) == .null);
    try testing.expect(d.columnAt(0).get(3) == .null);
    try testing.expect(d.columnAt(0).get(4) == .null);
    try testing.expectEqual(Value{ .int = 120_000 }, d.columnAt(0).get(5));
}

test "shape: a .binary column reads base64 strings, as dataframe writes them" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const d = try shape(a,
        \\{"r":[{"b":"AGFi"},{"b":"//4="},{"b":"not base64!"},{"b":7},{"b":""}]}
    , .{
        .path = "r",
        .columns = &.{.{ .name = "b", .key = "b", .type = .binary }},
    });
    try testing.expectEqualStrings("\x00ab", d.columnAt(0).get(0).text);
    try testing.expectEqualStrings("\xff\xfe", d.columnAt(0).get(1).text);
    try testing.expect(d.columnAt(0).get(2) == .null);
    try testing.expect(d.columnAt(0).get(3) == .null);
    try testing.expectEqualStrings("", d.columnAt(0).get(4).text);
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
    // this into `error.DepthLimit` (it used to be a silently EMPTY result: a
    // wrong answer that looked like a right one) rather than unbounded descent.
    try testing.expectError(error.DepthLimit, shape(a, doc.items, .{
        .path = "..leaf",
        .columns = &.{.{ .name = "v", .key = "", .type = .float }},
    }));

    // Control: the SAME path against a shallow document does find it, so the 0
    // above is the depth cap and not a broken fixture.
    const shallow = try shape(a, "{\"n\":{\"leaf\":[1,2]}}", .{
        .path = "..leaf",
        .columns = &.{.{ .name = "v", .key = "", .type = .float }},
    });
    try testing.expectEqual(@as(usize, 2), shallow.len);
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
        try testing.expectEqual(@as(usize, 0), out_ds.len);
    }
    // Control: the last VALID index still resolves, so the guard is off by
    // nothing in the other direction.
    const ok = try shape(a, doc, .{
        .path = "a.b[1]",
        .columns = &.{.{ .name = "v", .key = "", .type = .float }},
    });
    try testing.expectEqual(@as(usize, 1), ok.len);
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
    try testing.expect(out_ds.len > 65_536);
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

    // Legacy: "a" is an object, not an array -> empty frame.
    const legacy = try shape(a, json, .{ .path = "a", .columns = &cols });
    try testing.expectEqual(@as(usize, 0), legacy.len);

    // JSONPath (the leading `$` is what switches engines): the same node
    // becomes one item.
    const jsonpath = try shape(a, json, .{ .path = "$.a", .columns = &cols });
    try testing.expectEqual(@as(usize, 1), jsonpath.len);

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
    var work: Work = .{ .limit = std.math.maxInt(usize) };
    var ctx: Ctx = .{ .a = a, .root = root, .out = &out, .limit = MAX_MATCHES, .work = &work };
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
        const path = try a.print("$.one[?{s}]", .{row[0]});
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
        const path = try a.print("$.one[?{s}]", .{row[0]});
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
    const p10 = "$.a[?" ++ strRepeat("(", 10) ++ "@ == 1" ++ strRepeat(")", 10) ++ "]";
    try expectNodes(a, doc, p10, "[1]");
    const p40 = "$.a[?" ++ strRepeat("(", 40) ++ "@ == 1" ++ strRepeat(")", 40) ++ "]";
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
    try testing.expectEqual(@as(usize, 2), ok.len);
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
    try testing.expectEqual(@as(usize, 3), d.len);
    try testing.expectEqualStrings("2024-01-01", d.columnAt(0).get(0).text);
    try testing.expect(d.columnAt(0).get(1) == .null);
    try testing.expectEqualStrings("y", d.columnAt(1).get(0).text);
    try testing.expect(d.columnAt(1).get(2) == .null);
    // Row 3 HAS a field literally named "a.b": the exact field wins (v1
    // behaviour), the path `a` → `b` (9) is not consulted.
    try testing.expectEqual(@as(i64, 7), d.columnAt(2).get(2).int);
    try testing.expect(d.columnAt(2).get(0) == .null);
    // `$…` reads from the document root, the same for every row.
    for (0..d.len) |ri| try testing.expectEqualStrings("T", d.columnAt(3).get(ri).text);
    try testing.expectEqualStrings("x", d.columnAt(4).get(0).text);
    // The [x,y] shorthand takes paths too.
    const xy = try shape(a, "[{\"p\":{\"t\":\"d1\",\"v\":[5]}}]", .{ .path = "$", .x = "p.t", .y = "p.v[0]" });
    try testing.expectEqualStrings("d1", xy.columnAt(0).get(0).text);
    try testing.expectEqual(@as(f64, 5), xy.columnAt(1).get(0).float);
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
    try testing.expectEqual(@as(usize, 3), ok.len);
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
    try testing.expectEqual(@as(usize, 1), ok.len);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

const fz = @import("fuzz_test.zig");

test "fuzz: no panic, and the query entry points, Normalized Paths and models agree" {
    try testing.fuzz({}, fuzzPath, .{ .corpus = &.{ "", "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b" } });
}

fn fuzzPath(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len: usize = smith.slice(&buf);
    var src: fz.ScriptSource = .{ .bytes = buf[0..len] };
    try fz.pathHarness(fz.ScriptSource, &src, testing.allocator);
}

test {
    _ = @import("sweep_test.zig");
    _ = @import("iregexp.zig");
    _ = @import("cts_test.zig");
    _ = @import("query_test.zig");
    _ = @import("fuzz_test.zig");
}

const sf_scale = df.decimal_scale;
const ShapeCase = struct { doc: []const u8, spec: ShapeSpec, want: []const []const Value };

// The expected cells are worked out by hand from the document and the declared types.
const shape_frame_docs = [_]ShapeCase{
    .{
        .doc = "{\"data\":{\"p\":[{\"t\":\"a\",\"v\":1},{\"t\":\"b\",\"v\":2.5},{\"t\":null}]}}",
        .spec = .{ .path = "data.p", .columns = &.{ .{ .name = "t", .key = "t", .type = .text }, .{ .name = "v", .key = "v", .type = .float } } },
        .want = &.{
            &.{ .{ .text = "a" }, .{ .float = 1 } },
            &.{ .{ .text = "b" }, .{ .float = 2.5 } },
            &.{ .null, .null },
        },
    },
    .{
        // `whole` is the item itself, an object: no text. `a.b[0]` of ["x"] is no int.
        .doc = "[{\"a\":{\"b\":[1,2,3]}},{\"a\":{\"b\":[\"x\"]}},{}]",
        .spec = .{ .path = "$[*]", .columns = &.{ .{ .name = "n", .key = "a.b[0]", .type = .int }, .{ .name = "whole", .type = .text } } },
        .want = &.{
            &.{ .{ .int = 1 }, .null },
            &.{ .null, .null },
            &.{ .null, .null },
        },
    },
    .{
        // Array items: positional x and y (an int prints as text, a null stays null).
        .doc = "{\"r\":[[1,2],[3,4.5],[\"x\",null]]}",
        .spec = .{ .path = "r", .x = "0", .y = "1" },
        .want = &.{
            &.{ .{ .text = "1" }, .{ .float = 2 } },
            &.{ .{ .text = "3" }, .{ .float = 4.5 } },
            &.{ .{ .text = "x" }, .null },
        },
    },
    .{
        // "t" is no bool, "s" no float; 2.5 as a decimal is 5 * scale / 2.
        .doc = "[{\"k\":1,\"m\":\"t\"},{\"k\":\"s\",\"m\":true},{\"k\":2.5,\"m\":false}]",
        .spec = .{ .columns = &.{ .{ .name = "k", .key = "k", .type = .float }, .{ .name = "m", .key = "m", .type = .bool }, .{ .name = "d", .key = "k", .type = .decimal } } },
        .want = &.{
            &.{ .{ .float = 1 }, .null, .{ .decimal = sf_scale } },
            &.{ .null, .{ .bool = true }, .null },
            &.{ .{ .float = 2.5 }, .{ .bool = false }, .{ .decimal = @divExact(5 * sf_scale, 2) } },
        },
    },
    .{ .doc = "{\"a\":1}", .spec = .{ .path = "a", .columns = &.{.{ .name = "x", .key = "x" }} }, .want = &.{} },
    .{ .doc = "[]", .spec = .{ .columns = &.{.{ .name = "x", .key = "x" }} }, .want = &.{} },
};

test "shape: the cells `shape` gives, and its refusals" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for (shape_frame_docs) |c| {
        const f = try shape(a, c.doc, c.spec);
        try std.testing.expectEqual(c.want.len, f.len);
        for (c.want, 0..) |r, ri| {
            try std.testing.expectEqual(f.columns.len, r.len);
            for (r, 0..) |cell, ci| {
                const g = f.columnAt(ci).get(ri);
                try std.testing.expectEqual(std.meta.activeTag(cell), std.meta.activeTag(g));
                switch (cell) {
                    .text => |t| try std.testing.expectEqualStrings(t, g.text),
                    .float => |x| try std.testing.expectEqual(x, g.float),
                    .int => |x| try std.testing.expectEqual(x, g.int),
                    .uint => |x| try std.testing.expectEqual(x, g.uint),
                    .bool => |x| try std.testing.expectEqual(x, g.bool),
                    .decimal => |x| try std.testing.expectEqual(x, g.decimal),
                    .null => {},
                    .list, .record => unreachable,
                }
            }
        }
    }
    const cols: []const JsonCol = &.{.{ .name = "x", .key = "x" }};
    try std.testing.expectError(error.BadJson, shape(a, "{", .{ .columns = cols }));
    try std.testing.expectError(error.DepthLimit, shape(a, "[[[[", .{ .columns = cols, .max_depth = 2 }));
    try std.testing.expectError(error.WorkLimit, shape(a, "[{},{},{}]", .{ .columns = cols, .max_work = 1 }));
    try std.testing.expectError(error.TooManyMatches, shape(a, "[1,2,3]", .{ .path = "$[*]", .columns = cols, .max_matches = 1 }));
}

test "shape: typed arrays, and text that outlives nothing of the tree's" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try shape(a, "[{\"v\":1.5,\"t\":\"a\"},{\"v\":2,\"t\":\"b\"}]", .{ .columns = &.{ .{ .name = "v", .key = "v" }, .{ .name = "t", .key = "t", .type = .text } } });
    try std.testing.expect(f.data[0] == .float);
    try std.testing.expect(f.data[1] == .text);
}

test "shape: a categorical column is stored encoded, a duration parses, list and struct are refused" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const f = try shape(a, "[{\"c\":\"b\",\"d\":\"PT1S\"},{\"c\":\"a\",\"d\":5},{\"c\":\"b\",\"d\":null}]", .{ .columns = &.{
        .{ .name = "c", .key = "c", .type = .categorical },
        .{ .name = "d", .key = "d", .type = .duration },
    } });
    try std.testing.expect(f.data[0] == .categorical);
    try std.testing.expectEqualStrings("b", f.columnAt(0).get(0).text);
    try std.testing.expectEqualStrings("a", f.columnAt(0).get(1).text);
    try std.testing.expectEqual(@as(i64, 1_000_000), f.columnAt(1).get(0).int); // PT1S, in microseconds
    try std.testing.expectEqual(@as(i64, 5), f.columnAt(1).get(1).int); // a number is already in the unit
    try std.testing.expect(f.columnAt(1).get(2) == .null);
    for ([_]ColumnType{ .list, .array, .@"struct" }) |t| {
        try std.testing.expectError(error.UnsupportedColumnType, shape(a, "[]", .{ .columns = &.{.{ .name = "n", .key = "n", .type = t }} }));
    }
}
