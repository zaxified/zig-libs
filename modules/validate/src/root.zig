// SPDX-License-Identifier: MIT

//! validate — request input validation (body / query / path params) with
//! aggregated, machine-readable errors, as `router` middleware + a standalone
//! validator core.
//!
//! An internet-facing API must reject malformed input uniformly at the edge,
//! not with ad-hoc per-handler checks. This module is that layer, in three
//! tiers that peel apart cleanly:
//!
//! - **Validator core** (no HTTP anywhere): a `Rule` set — `required`, type
//!   (`string`/`int`/`float`/`bool`/`array`/`object`), `min`/`max` (numeric,
//!   inclusive), `min_len`/`max_len` (string chars / array items), `one_of`
//!   (the JSON-Schema `enum` keyword — `enum` is a Zig keyword), `pattern`
//!   (literal/prefix/suffix/charset — **regex is out of scope**, see TODO
//!   below), `format` (the JSON Schema 2020-12 `format` vocabulary as
//!   assertions: `email`, `uri`/`uri_reference`, `uuid`, `ipv4`/`ipv6`,
//!   `hostname`, `date`/`time`/`date_time`, `duration`, `json_pointer` —
//!   also standalone via `validateFormat`) and a `custom` predicate —
//!   validated against a `std.json.Value`.
//!   Every error is **aggregated** into `{ path, code, message }` — never
//!   fail-fast; users hate fixing one field at a time (pydantic behavior).
//! - **Body**: the idiomatic **typed** style `parseInto(T, gpa, body)` — a
//!   comptime-reflected schema derived from struct `T` (field types → kinds,
//!   optionals → nullability, defaults → not-required, int bit-width → value
//!   bounds, enums → `one_of`), validated first so JSON type errors become
//!   pathed validation errors instead of parse crashes, then decoded into `T`
//!   with `std.json.parseFromValue`. And the **runtime schema** style:
//!   `validateJson(gpa, body, schema)` over `std.json.Value` for schemas not
//!   known at compile time. Malformed JSON is a clean `json_invalid` error,
//!   never a panic.
//! - **Middleware**: `Body` (runtime schema) / `TypedBody(T)` (typed) /
//!   `Query` / `PathParams` plug into `router` group or router chains. On
//!   failure they answer **400** with `{"errors":[{path,code,message},…]}`
//!   (pydantic-ish shape) and do **not** call `next`; on success the parsed
//!   data is available to the handler via the `ctx.data` slot (`bodyValue` /
//!   `TypedBody(T).get` / `queryValues` getters — stackable, see below).
//!
//! Error `code`s follow **pydantic v2** vocabulary (`missing`, `int_type`,
//! `greater_than_equal`, `string_too_short`, `too_long`, `enum`, `format`,
//! `string_pattern_mismatch`, `int_parsing`, `json_invalid`, …), with
//! `array_type`/`object_type` renamed from pydantic's `list_type`/`dict_type`
//! to match JSON vocabulary. Keyword *meanings* follow JSON Schema 2020-12:
//! `1.0` is a valid integer, `null` fails every typed kind (use `allow_null`),
//! extra fields are permitted, `min`/`max` are inclusive. See the README for
//! the full code table.
//!
//! Memory: allocator-explicit, no globals. A validation run allocates one
//! arena that the returned `Report` owns (`Report.deinit` frees everything);
//! codes are static strings; composed paths and formatted messages live in
//! the arena; simple paths borrow `Rule.field` — the schema (and any custom
//! rule's code/message strings) must outlive the Report. Middleware state is
//! an immutable struct the `router.Middleware.state` pointer references —
//! init once, share across all connection threads (reentrant).
//!
//! `ctx.data` protocol: each success slot is pushed with a `prev` link and
//! popped after `next` returns, so `Query` + `Body` middleware stack on one
//! route and both getters work. Getters walk only validate-owned slots
//! (magic-tagged); middleware from other modules sitting *between* a validate
//! middleware and the handler must preserve `ctx.data` (the router's
//! cooperative-scratch convention) or the getters return null.
//!
//! TODO(regex): `pattern` is deliberately literal/prefix/suffix/charset only —
//! a regex engine is a future ADOPT dependency; when it lands, add
//! `.regex: []const u8` to `Pattern` and map it to `string_pattern_mismatch`.

const std = @import("std");
const router = @import("router");
const http = @import("http");
const netaddr = @import("netaddr");

pub const meta = .{
    .platform = .any,
    .role = .util,
    // The validator core is pure; middleware state is immutable after init
    // and every per-request allocation is request-scoped — reentrant across
    // all of http.Server's connection threads.
    .concurrency = .reentrant,
    .model_after = "pydantic v2 (error shape + codes) + JSON Schema 2020-12 (keyword semantics + format vocabulary) + go-playground/validator (middleware ergonomics)",
    .deps = .{ "router", "http", "netaddr" },
};

const Allocator = std.mem.Allocator;
const Value = std.json.Value;

// ── the rule vocabulary ─────────────────────────────────────────────────────

/// Expected JSON type of a field. `.any` skips the type gate (only
/// `required`/`allow_null`/`custom` apply).
pub const Kind = enum { string, int, float, bool, array, object, any };

/// Simple string pattern — deliberately not regex (see the module TODO).
pub const Pattern = union(enum) {
    /// Exact match.
    literal: []const u8,
    /// Must start with.
    prefix: []const u8,
    /// Must end with.
    suffix: []const u8,
    /// Every byte must be in this set (e.g. "0123456789abcdef-").
    charset: []const u8,
};

/// String format assertions — the JSON Schema 2020-12 `format` vocabulary
/// with **assertion** behavior (a mismatch is a validation error, not an
/// annotation). Checked by `validateFormat` and the `Rule.format` constraint.
/// Semantics per format (see the validators below for the exact profiles):
///
/// - `email` — practical RFC 5321 subset: dot-atom local part (1–64 chars,
///   no quoted strings) `@` a hostname containing a dot, ≤ 254 total.
/// - `uri` — RFC 3986 structural check: valid scheme + only URI characters,
///   well-formed `%XX` escapes, at most one `#`. `uri_reference` is the
///   same without requiring a scheme ("" and relative refs are valid).
/// - `uuid` — the 8-4-4-4-12 hex shape, case-insensitive. The variant and
///   version nibbles are deliberately **not** checked (any hex accepted).
/// - `ipv4` / `ipv6` — `netaddr.parseIp`, asserting the parsed family.
/// - `hostname` — RFC 1123: labels 1–63 alnum/hyphen chars, hyphen not at
///   label ends, ≤ 253 total, no empty labels.
/// - `date` / `time` / `date_time` — RFC 3339 profile with real range
///   checks (month 1–12, day per month incl. leap years, hour ≤ 23,
///   minute ≤ 59, second ≤ 60 — `23:59:60` is accepted since RFC 3339
///   permits leap seconds). The UTC offset (`Z` / `±HH:MM`) is validated
///   strictly when present but is **optional** (offset-less local times
///   are accepted — ISO 8601 profile, slightly laxer than RFC 3339).
/// - `duration` — the RFC 3339 appendix-A ISO 8601 grammar (`P…` with
///   ordered Y/M/D and T-separated H/M/S components, or the week form).
/// - `json_pointer` — RFC 6901: "" or `/`-prefixed, `~` only as `~0`/`~1`.
pub const Format = enum {
    email,
    uri,
    uri_reference,
    uuid,
    ipv4,
    ipv6,
    hostname,
    date,
    time,
    date_time,
    duration,
    json_pointer,
};

/// Caller-supplied predicate, run after all built-in checks pass the type
/// gate. Runs on the request thread — must be fast and thread-safe.
pub const Custom = struct {
    ctx: ?*anyopaque = null,
    /// For body validation `value` is the field's JSON value; for query/path
    /// validation it is the *coerced* value (`.integer`/`.float`/`.bool`/
    /// `.string` per the rule's kind).
    check: *const fn (ctx: ?*anyopaque, value: Value) bool,
    /// Error code/message emitted when `check` returns false. Both are
    /// borrowed — they must outlive any Report produced with this rule.
    code: []const u8 = "custom",
    message: []const u8 = "Invalid value",
};

/// One field rule. Constraints apply per kind: `min`/`max` to numerics,
/// `min_len`/`max_len` to strings (bytes) and arrays (items), `one_of`,
/// `pattern` and `format` to strings, `fields` to objects, `items` to
/// arrays. Constraints for other kinds are ignored.
pub const Rule = struct {
    /// Object key this rule applies to (ignored on `items` element rules).
    field: []const u8,
    kind: Kind = .any,
    /// Absent field → `missing` error. An explicit JSON `null` is *present*
    /// (it fails the type gate unless `allow_null`) — pydantic semantics.
    required: bool = false,
    /// Accept an explicit JSON `null` regardless of `kind` (constraints and
    /// `custom` are then skipped for the null).
    allow_null: bool = false,
    /// Inclusive numeric bounds (JSON Schema `minimum`/`maximum`). Compared
    /// as f64 — exact for integers up to 2^53.
    min: ?f64 = null,
    max: ?f64 = null,
    /// String length in bytes / array length in items.
    min_len: ?usize = null,
    max_len: ?usize = null,
    /// One-of allow-list for strings (the JSON Schema `enum` keyword; named
    /// `one_of` because `enum` is a Zig keyword).
    one_of: ?[]const []const u8 = null,
    pattern: ?Pattern = null,
    /// String format assertion (JSON Schema 2020-12 `format` keyword);
    /// a mismatch yields the `format` error code.
    format: ?Format = null,
    custom: ?Custom = null,
    /// Nested rules for `.object` fields (JSON Schema `properties`); error
    /// paths become "parent.child".
    fields: ?[]const Rule = null,
    /// Rule applied to every element of an `.array` field (JSON Schema
    /// `items`); error paths become "field[i]".
    items: ?*const Rule = null,
};

// ── the error shape ─────────────────────────────────────────────────────────

/// One validation failure. Serialized field order is the wire shape:
/// `{"path":…,"code":…,"message":…}`.
pub const Error = struct {
    /// Dotted/indexed location: "name", "user.email", "items[2]"; "" = the
    /// input as a whole (root type error, malformed JSON).
    path: []const u8,
    /// Stable machine-readable code (pydantic v2 vocabulary — see README).
    code: []const u8,
    /// Human-readable explanation.
    message: []const u8,
};

/// The aggregated result of one validation run. Owns every allocation behind
/// `errors` (single arena); free with `deinit`.
pub const Report = struct {
    arena: std.heap.ArenaAllocator,
    errors: []const Error,

    /// True when the input passed every rule.
    pub fn ok(r: *const Report) bool {
        return r.errors.len == 0;
    }

    /// First error with this exact path, or null (test/introspection helper).
    pub fn find(r: *const Report, path: []const u8) ?*const Error {
        for (r.errors) |*e| {
            if (std.mem.eql(u8, e.path, path)) return e;
        }
        return null;
    }

    /// Serialize as the wire shape `{"errors":[{path,code,message},…]}`.
    pub fn writeJson(r: *const Report, w: *std.Io.Writer) std.Io.Writer.Error!void {
        return writeErrorsJson(r.errors, w);
    }

    pub fn deinit(r: *Report) void {
        r.arena.deinit();
        r.* = undefined;
    }
};

/// The 400 wire shape, also usable standalone: `{"errors":[…]}`.
pub fn writeErrorsJson(errors: []const Error, w: *std.Io.Writer) std.Io.Writer.Error!void {
    return std.json.Stringify.value(.{ .errors = errors }, .{}, w);
}

/// Error accumulator: one arena for paths/messages/the list itself;
/// `finish` hands the arena to the Report, `abort` discards it.
const Builder = struct {
    arena: std.heap.ArenaAllocator,
    list: std.ArrayList(Error),

    fn init(gpa: Allocator) Builder {
        return .{ .arena = std.heap.ArenaAllocator.init(gpa), .list = .empty };
    }

    fn a(b: *Builder) Allocator {
        return b.arena.allocator();
    }

    fn append(b: *Builder, path: []const u8, code: []const u8, message: []const u8) Allocator.Error!void {
        // Dedupe exact (path, code) repeats: the typed style runs the derived
        // schema and then T.validate_rules over the same document, and a field
        // failing the same way in both passes is one error, not two.
        for (b.list.items) |e| {
            if (std.mem.eql(u8, e.path, path) and std.mem.eql(u8, e.code, code)) return;
        }
        try b.list.append(b.a(), .{ .path = path, .code = code, .message = message });
    }

    fn appendf(b: *Builder, path: []const u8, code: []const u8, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        try b.append(path, code, try std.fmt.allocPrint(b.a(), fmt, args));
    }

    fn fieldPath(b: *Builder, prefix: []const u8, field: []const u8) Allocator.Error![]const u8 {
        if (prefix.len == 0) return field; // borrows the schema's string
        return std.fmt.allocPrint(b.a(), "{s}.{s}", .{ prefix, field });
    }

    fn indexPath(b: *Builder, prefix: []const u8, i: usize) Allocator.Error![]const u8 {
        return std.fmt.allocPrint(b.a(), "{s}[{d}]", .{ prefix, i });
    }

    fn finish(b: *Builder) Report {
        return .{ .arena = b.arena, .errors = b.list.items };
    }

    fn abort(b: *Builder) void {
        b.arena.deinit();
    }
};

// ── the validator core (no HTTP) ────────────────────────────────────────────

/// Validate an already-parsed JSON value against a schema, aggregating every
/// failure. The schema strings must outlive the Report (simple paths borrow
/// `Rule.field`); the Report never references `value`'s memory.
pub fn validateValue(gpa: Allocator, value: Value, schema: []const Rule) Allocator.Error!Report {
    var b = Builder.init(gpa);
    errdefer b.abort();
    try checkValue(&b, "", value, schema);
    return b.finish();
}

/// Parse a JSON document and validate it, with the default structural
/// `Limits` applied first. Malformed JSON (syntax error, truncation, empty
/// input) yields a single `json_invalid` error; a document that breaches a
/// structural limit yields the matching `too_deep` / `array_too_large` /
/// `too_many_fields` / `too_many_nodes` error (see `validateJsonLimited`) —
/// never a panic, never a parse crash.
pub fn validateJson(gpa: Allocator, body: []const u8, schema: []const Rule) Allocator.Error!Report {
    return validateJsonLimited(gpa, body, schema, .{});
}

/// Like `validateJson`, but with caller-chosen structural `Limits`. The body
/// is first scanned by a fail-fast token walk (`jsonLimitError`); a document
/// that exceeds any bound is rejected *before* it is materialized into a
/// value tree, so an over-limit payload cannot blow up memory/CPU (JSON DoS).
/// Only when the scan passes is the document parsed and validated normally.
pub fn validateJsonLimited(gpa: Allocator, body: []const u8, schema: []const Rule, limits: Limits) Allocator.Error!Report {
    if (try jsonLimitError(gpa, body, limits)) |e| return singleErrorReport(gpa, e);
    var parsed = std.json.parseFromSlice(Value, gpa, body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return jsonInvalidReport(gpa, err),
    };
    defer parsed.deinit();
    return validateValue(gpa, parsed.value, schema);
}

fn jsonInvalidReport(gpa: Allocator, err: anyerror) Allocator.Error!Report {
    var b = Builder.init(gpa);
    errdefer b.abort();
    try b.appendf("", "json_invalid", "Invalid JSON: {s}", .{@errorName(err)});
    return b.finish();
}

/// A Report carrying exactly one (static-string) error — used for the
/// structural-limit rejections, which are not tied to any schema field.
fn singleErrorReport(gpa: Allocator, e: Error) Allocator.Error!Report {
    var b = Builder.init(gpa);
    errdefer b.abort();
    try b.append(e.path, e.code, e.message);
    return b.finish();
}

// ── JSON structural limits (DoS mitigation) ─────────────────────────────────
//
// The byte cap (`max_body_bytes` → 413) bounds size, not shape: a 1 MiB body
// that is deeply nested brackets, one gigantic array, or one object with a
// huge member count is cheap to send yet expensive to fully parse into a
// std.json.Value tree (unbounded recursion / allocation). These limits are
// enforced by a streaming token scan (`std.json.Scanner`) that rejects as
// soon as a bound is crossed — the over-limit document is never materialized.
// Clean-room: generic JSON-DoS mitigation, no third-party source.

/// Structural bounds enforced during a fail-fast token scan of a JSON body,
/// *before* it is parsed into a value tree. The defaults are generous enough
/// for ordinary API payloads while still cutting off pathological shapes, and
/// are applied by every JSON body path in this module out of the box.
pub const Limits = struct {
    /// Maximum nesting depth of objects/arrays (the top-level container is
    /// depth 1). Deeper → `too_deep`.
    max_depth: usize = 32,
    /// Maximum number of elements in any single array. Over → `array_too_large`.
    max_array_elements: usize = 10_000,
    /// Maximum number of members in any single object. Over → `too_many_fields`.
    max_object_members: usize = 1_000,
    /// Maximum total JSON value nodes (scalars + containers; object keys are
    /// not counted). Over → `too_many_nodes`. Set to a very large value to
    /// effectively disable this overall cap.
    max_total_nodes: usize = 1_000_000,
};

const limit_too_deep: Error = .{ .path = "", .code = "too_deep", .message = "JSON nesting is too deep" };
const limit_array_too_large: Error = .{ .path = "", .code = "array_too_large", .message = "JSON array has too many elements" };
const limit_too_many_fields: Error = .{ .path = "", .code = "too_many_fields", .message = "JSON object has too many members" };
const limit_too_many_nodes: Error = .{ .path = "", .code = "too_many_nodes", .message = "JSON document has too many nodes" };

const ContainerKind = enum { object, array };

/// Streaming structural-scan state: one `Frame` per currently-open container.
/// The frame stack never grows past `max_depth` (we reject on the token that
/// would exceed it), so it is bounded regardless of input size.
const LimitScan = struct {
    gpa: Allocator,
    limits: Limits,
    frames: std.ArrayList(Frame),
    nodes: usize = 0,

    const Frame = struct {
        kind: ContainerKind,
        /// Array elements or object members seen so far in this container.
        count: usize = 0,
        /// Objects only: the next item token is a key (vs. that key's value).
        expect_key: bool = true,
    };

    fn top(s: *LimitScan) ?*Frame {
        if (s.frames.items.len == 0) return null;
        return &s.frames.items[s.frames.items.len - 1];
    }

    /// Register the start of one item — a value, or an object key. Sets
    /// `is_value` (false only for an object key) and returns the first limit
    /// violation, or null. Values bump the total-node count; keys do not.
    fn begin(s: *LimitScan, is_value: *bool) Allocator.Error!?Error {
        if (s.top()) |t| {
            if (t.kind == .object and t.expect_key) {
                t.count += 1;
                t.expect_key = false;
                is_value.* = false;
                if (t.count > s.limits.max_object_members) return limit_too_many_fields;
                return null;
            }
            if (t.kind == .array) {
                t.count += 1;
                if (t.count > s.limits.max_array_elements) return limit_array_too_large;
            }
        }
        is_value.* = true;
        s.nodes += 1;
        if (s.nodes > s.limits.max_total_nodes) return limit_too_many_nodes;
        return null;
    }

    /// Register that a value finished (a scalar just read, or a container just
    /// closed): its enclosing object may expect the next key again.
    fn complete(s: *LimitScan) void {
        if (s.top()) |t| {
            if (t.kind == .object) t.expect_key = true;
        }
    }

    /// Enter a nested container (always a value): count it, enforce depth,
    /// then push its frame.
    fn enter(s: *LimitScan, kind: ContainerKind) Allocator.Error!?Error {
        var is_value: bool = undefined;
        if (try s.begin(&is_value)) |v| return v;
        if (s.frames.items.len + 1 > s.limits.max_depth) return limit_too_deep;
        try s.frames.append(s.gpa, .{ .kind = kind });
        return null;
    }
};

/// Scan `body` for the first structural-limit violation without materializing
/// it, returning a ready-to-report `Error` (all-static strings, path "") or
/// null. A malformed document also returns null: the syntax error is left for
/// the real parser to surface as `json_invalid`, so this never changes the
/// diagnosis of bad JSON — it only adds the structural caps. Allocation is
/// transient (the scanner's bit-stack), freed before return.
pub fn jsonLimitError(gpa: Allocator, body: []const u8, limits: Limits) Allocator.Error!?Error {
    var scanner = std.json.Scanner.initCompleteInput(gpa, body);
    defer scanner.deinit();

    var scan: LimitScan = .{ .gpa = gpa, .limits = limits, .frames = .empty };
    defer scan.frames.deinit(gpa);

    // std.json.Scanner emits strings (and, across escapes, numbers) as a run
    // of partial_* tokens ending in the whole token, even for complete input.
    // Collapse each run to a single item: act on its first token only.
    var in_string = false;
    var in_number = false;
    var string_is_value = false;

    while (true) {
        const token = scanner.next() catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return null, // malformed JSON → defer to the parser's json_invalid
        };
        switch (token) {
            .object_begin => if (try scan.enter(.object)) |v| return v,
            .array_begin => if (try scan.enter(.array)) |v| return v,
            .object_end, .array_end => {
                _ = scan.frames.pop();
                scan.complete();
            },
            .true, .false, .null => {
                var is_value: bool = undefined;
                if (try scan.begin(&is_value)) |v| return v;
                scan.complete(); // scalars are always values, and complete at once
            },
            // A number is always a value; count it once at its first token.
            .number, .allocated_number => {
                if (!in_number) {
                    var is_value: bool = undefined;
                    if (try scan.begin(&is_value)) |v| return v;
                }
                in_number = false;
                scan.complete();
            },
            .partial_number => {
                if (!in_number) {
                    var is_value: bool = undefined;
                    if (try scan.begin(&is_value)) |v| return v;
                    in_number = true;
                }
            },
            // A string may be an object key or a value; count it once at its
            // first token, and only complete() the value case.
            .string, .allocated_string => {
                if (in_string) {
                    in_string = false;
                    if (string_is_value) scan.complete();
                } else {
                    var is_value: bool = undefined;
                    if (try scan.begin(&is_value)) |v| return v;
                    if (is_value) scan.complete();
                }
            },
            .partial_string,
            .partial_string_escaped_1,
            .partial_string_escaped_2,
            .partial_string_escaped_3,
            .partial_string_escaped_4,
            => {
                if (!in_string) {
                    var is_value: bool = undefined;
                    if (try scan.begin(&is_value)) |v| return v;
                    string_is_value = is_value;
                    in_string = true;
                }
            },
            .end_of_document => break,
        }
    }
    return null;
}

/// Apply object-field rules to `value` (which must itself be an object).
fn checkValue(b: *Builder, prefix: []const u8, value: Value, rules: []const Rule) Allocator.Error!void {
    if (value != .object) {
        try b.append(prefix, "object_type", "Input should be a valid object");
        return;
    }
    for (rules) |*rule| {
        const path = try b.fieldPath(prefix, rule.field);
        if (value.object.get(rule.field)) |v| {
            try checkRule(b, path, v, rule);
        } else if (rule.required) {
            try b.append(path, "missing", "Field required");
        }
    }
}

/// Check one value against one rule: the type gate first (a wrong-typed
/// value gets exactly one `<kind>_type` error and no constraint noise —
/// pydantic behavior), then the kind's constraints, then `custom`.
fn checkRule(b: *Builder, path: []const u8, v: Value, rule: *const Rule) Allocator.Error!void {
    if (v == .null) {
        if (rule.allow_null) return; // explicit null accepted as-is
        if (rule.kind != .any) {
            try appendTypeError(b, path, rule.kind);
            return;
        }
    } else if (!typeGate(v, rule.kind)) {
        try appendTypeError(b, path, rule.kind);
        return;
    }

    switch (rule.kind) {
        .int, .float => {
            const n = numValue(v);
            if (rule.min) |m| if (n < m)
                try b.appendf(path, "greater_than_equal", "Input should be greater than or equal to {d}", .{m});
            if (rule.max) |m| if (n > m)
                try b.appendf(path, "less_than_equal", "Input should be less than or equal to {d}", .{m});
        },
        .string => {
            const s = v.string;
            if (rule.min_len) |m| if (s.len < m)
                try b.appendf(path, "string_too_short", "String should have at least {d} characters", .{m});
            if (rule.max_len) |m| if (s.len > m)
                try b.appendf(path, "string_too_long", "String should have at most {d} characters", .{m});
            if (rule.one_of) |allowed| {
                if (!containsString(allowed, s)) {
                    const joined = try std.mem.join(b.a(), ", ", allowed);
                    try b.appendf(path, "enum", "Input should be one of: {s}", .{joined});
                }
            }
            if (rule.pattern) |p| try checkPattern(b, path, s, p);
            if (rule.format) |f| if (!validateFormat(f, s))
                try b.append(path, "format", formatMessage(f));
        },
        .array => {
            const items = v.array.items;
            if (rule.min_len) |m| if (items.len < m)
                try b.appendf(path, "too_short", "Array should have at least {d} items", .{m});
            if (rule.max_len) |m| if (items.len > m)
                try b.appendf(path, "too_long", "Array should have at most {d} items", .{m});
            if (rule.items) |item_rule| {
                for (items, 0..) |item, i| {
                    try checkRule(b, try b.indexPath(path, i), item, item_rule);
                }
            }
        },
        .object => {
            if (rule.fields) |fields| try checkValue(b, path, v, fields);
        },
        .bool, .any => {},
    }

    if (rule.custom) |c| {
        if (!c.check(c.ctx, v)) try b.append(path, c.code, c.message);
    }
}

/// JSON-Schema type semantics: `1.0` is a valid integer; a huge number that
/// std.json kept as `number_string` counts as int only when it parses as one.
fn typeGate(v: Value, kind: Kind) bool {
    return switch (kind) {
        .any => true,
        .string => v == .string,
        .bool => v == .bool,
        .int => switch (v) {
            .integer => true,
            .float => |f| std.math.isFinite(f) and @floor(f) == f,
            .number_string => |s| blk: {
                _ = std.fmt.parseInt(i64, s, 10) catch break :blk false;
                break :blk true;
            },
            else => false,
        },
        .float => v == .integer or v == .float or v == .number_string,
        .array => v == .array,
        .object => v == .object,
    };
}

fn appendTypeError(b: *Builder, path: []const u8, kind: Kind) Allocator.Error!void {
    const ce: struct { []const u8, []const u8 } = switch (kind) {
        .string => .{ "string_type", "Input should be a valid string" },
        .int => .{ "int_type", "Input should be a valid integer" },
        .float => .{ "float_type", "Input should be a valid number" },
        .bool => .{ "bool_type", "Input should be a valid boolean" },
        .array => .{ "array_type", "Input should be a valid array" },
        .object => .{ "object_type", "Input should be a valid object" },
        .any => unreachable, // .any has no type gate
    };
    try b.append(path, ce[0], ce[1]);
}

/// Numeric value for bounds checks; caller guarantees the type gate passed.
fn numValue(v: Value) f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        // Guaranteed valid JSON number grammar; overflow saturates to ±inf,
        // which still orders correctly against finite bounds.
        .number_string => |s| std.fmt.parseFloat(f64, s) catch 0,
        else => unreachable,
    };
}

fn containsString(list: []const []const u8, s: []const u8) bool {
    for (list) |candidate| {
        if (std.mem.eql(u8, candidate, s)) return true;
    }
    return false;
}

fn checkPattern(b: *Builder, path: []const u8, s: []const u8, p: Pattern) Allocator.Error!void {
    switch (p) {
        .literal => |lit| if (!std.mem.eql(u8, s, lit))
            try b.appendf(path, "string_pattern_mismatch", "String should be \"{s}\"", .{lit}),
        .prefix => |pre| if (!std.mem.startsWith(u8, s, pre))
            try b.appendf(path, "string_pattern_mismatch", "String should start with \"{s}\"", .{pre}),
        .suffix => |suf| if (!std.mem.endsWith(u8, s, suf))
            try b.appendf(path, "string_pattern_mismatch", "String should end with \"{s}\"", .{suf}),
        .charset => |set| for (s) |ch| {
            if (std.mem.indexOfScalar(u8, set, ch) == null) {
                try b.append(path, "string_pattern_mismatch", "String contains characters outside the allowed set");
                break;
            }
        },
    }
}

// ── string format validators (JSON Schema 2020-12 `format`) ─────────────────
//
// Clean-room from the JSON Schema 2020-12 format-annotation vocabulary and
// the underlying RFCs (5321, 3986, 4122, 1123, 3339, 6901). Pure functions:
// no allocation, never panic — any byte sequence (empty, huge, non-UTF-8)
// is simply valid or not.

/// True when `s` conforms to `format` (see `Format` for each profile).
/// Standalone entry point; the schema path uses it via `Rule.format`.
pub fn validateFormat(format: Format, s: []const u8) bool {
    return switch (format) {
        .email => isEmail(s),
        .uri => isUri(s, true),
        .uri_reference => isUri(s, false),
        .uuid => isUuid(s),
        .ipv4 => if (netaddr.parseIp(s)) |ip| ip == .v4 else false,
        .ipv6 => if (netaddr.parseIp(s)) |ip| ip == .v6 else false,
        .hostname => isHostname(s),
        .date => isDate(s),
        .time => isTime(s),
        .date_time => isDateTime(s),
        .duration => isDuration(s),
        .json_pointer => isJsonPointer(s),
    };
}

/// Static (arena-free) message for the `format` error code.
fn formatMessage(format: Format) []const u8 {
    return switch (format) {
        .email => "Input should be a valid email address",
        .uri => "Input should be a valid URI",
        .uri_reference => "Input should be a valid URI reference",
        .uuid => "Input should be a valid UUID",
        .ipv4 => "Input should be a valid IPv4 address",
        .ipv6 => "Input should be a valid IPv6 address",
        .hostname => "Input should be a valid hostname",
        .date => "Input should be a valid date",
        .time => "Input should be a valid time",
        .date_time => "Input should be a valid date-time",
        .duration => "Input should be a valid duration",
        .json_pointer => "Input should be a valid JSON Pointer",
    };
}

/// Practical RFC 5321 subset: dot-atom local part `@` dotted hostname.
/// No quoted-string locals, no address literals, no full RFC 5322.
fn isEmail(s: []const u8) bool {
    if (s.len < 3 or s.len > 254) return false;
    const at = std.mem.indexOfScalar(u8, s, '@') orelse return false;
    if (std.mem.indexOfScalarPos(u8, s, at + 1, '@') != null) return false;
    const local = s[0..at];
    const domain = s[at + 1 ..];
    if (local.len == 0 or local.len > 64) return false;
    if (local[0] == '.' or local[local.len - 1] == '.') return false;
    var prev_dot = false;
    for (local) |c| {
        if (c == '.') {
            if (prev_dot) return false; // no ".." (dot-atom)
            prev_dot = true;
        } else {
            prev_dot = false;
            if (!isAtext(c)) return false;
        }
    }
    // Deliverable addresses need a dotted FQDN, not a bare label.
    return isHostname(domain) and std.mem.indexOfScalar(u8, domain, '.') != null;
}

/// RFC 5321 atext: the characters allowed in an unquoted local-part atom.
fn isAtext(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or
        std.mem.indexOfScalar(u8, "!#$%&'*+-/=?^_`{|}~", c) != null;
}

/// RFC 3986 structural check: every byte a valid URI character, `%XX`
/// escapes well-formed, at most one `#`. With `require_scheme` the string
/// must additionally start `scheme:` (ALPHA *(ALPHA/DIGIT/"+"/"-"/".")) —
/// that is `uri`; without, any (even empty) relative reference passes —
/// that is `uri_reference`. Not a full parser: component splitting and
/// authority shape are out of scope.
fn isUri(s: []const u8, require_scheme: bool) bool {
    var fragments: usize = 0;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c == '%') {
            if (i + 2 >= s.len) return false;
            if (!std.ascii.isHex(s[i + 1]) or !std.ascii.isHex(s[i + 2])) return false;
            i += 2;
        } else if (c == '#') {
            fragments += 1;
            if (fragments > 1) return false;
        } else if (!isUriChar(c)) {
            return false;
        }
    }
    if (!require_scheme) return true;
    const colon = std.mem.indexOfScalar(u8, s, ':') orelse return false;
    if (colon == 0 or !std.ascii.isAlphabetic(s[0])) return false;
    for (s[1..colon]) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '-' and c != '.') return false;
    }
    // The first ':' must be the scheme separator, not path/query/fragment.
    return std.mem.indexOfAny(u8, s[0..colon], "/?#") == null;
}

/// unreserved / gen-delims / sub-delims ('%' and '#' are handled above).
fn isUriChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or
        std.mem.indexOfScalar(u8, "-._~:/?[]@!$&'()*+,;=", c) != null;
}

/// The canonical 8-4-4-4-12 hex shape, case-insensitive. Shape only: the
/// RFC 4122 variant/version nibbles are not asserted (documented choice —
/// JSON Schema test-suite behavior, and NIL/max UUIDs stay valid).
fn isUuid(s: []const u8) bool {
    if (s.len != 36) return false;
    for (s, 0..) |c, i| {
        switch (i) {
            8, 13, 18, 23 => if (c != '-') return false,
            else => if (!std.ascii.isHex(c)) return false,
        }
    }
    return true;
}

/// RFC 1123 hostname: dot-separated labels of 1–63 alphanumeric/hyphen
/// characters, hyphen not at label ends, 253 bytes total. No trailing dot
/// (an empty label anywhere is rejected); all-numeric labels are allowed.
fn isHostname(s: []const u8) bool {
    if (s.len == 0 or s.len > 253) return false;
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;
        if (label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
        }
    }
    return true;
}

/// RFC 3339 full-date `YYYY-MM-DD` with real calendar ranges: month 1–12,
/// day 1–{28,29,30,31} per month with Gregorian leap years.
fn isDate(s: []const u8) bool {
    if (s.len != 10 or s[4] != '-' or s[7] != '-') return false;
    const y = parseDigits(s[0..4]) orelse return false;
    const m = parseDigits(s[5..7]) orelse return false;
    const d = parseDigits(s[8..10]) orelse return false;
    if (m < 1 or m > 12) return false;
    return d >= 1 and d <= daysInMonth(y, m);
}

/// `HH:MM:SS[.frac][Z|±HH:MM]` with ranges: hour ≤ 23, minute ≤ 59,
/// second ≤ 60 (60 = leap second, which RFC 3339 permits — accepted at any
/// time of day since the grammar cannot know the leap-second table). The
/// offset is validated strictly when present but is optional (ISO 8601
/// local-time profile; RFC 3339 proper would require it).
fn isTime(s: []const u8) bool {
    if (s.len < 8 or s[2] != ':' or s[5] != ':') return false;
    const h = parseDigits(s[0..2]) orelse return false;
    const m = parseDigits(s[3..5]) orelse return false;
    const sec = parseDigits(s[6..8]) orelse return false;
    if (h > 23 or m > 59 or sec > 60) return false;
    var i: usize = 8;
    if (i < s.len and s[i] == '.') {
        i += 1;
        const start = i;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
        if (i == start) return false; // '.' needs at least one digit
    }
    if (i == s.len) return true; // offset-less local time
    return isUtcOffset(s[i..]);
}

/// `Z`/`z` or `±HH:MM` (hour ≤ 23, minute ≤ 59).
fn isUtcOffset(s: []const u8) bool {
    if (s.len == 1 and (s[0] == 'Z' or s[0] == 'z')) return true;
    if (s.len != 6 or (s[0] != '+' and s[0] != '-') or s[3] != ':') return false;
    const h = parseDigits(s[1..3]) orelse return false;
    const m = parseDigits(s[4..6]) orelse return false;
    return h <= 23 and m <= 59;
}

/// RFC 3339 date-time: `full-date "T" time` (`T` case-insensitive; a space
/// separator is rejected). Offset optionality follows `isTime`.
fn isDateTime(s: []const u8) bool {
    if (s.len < 12) return false;
    if (s[10] != 'T' and s[10] != 't') return false;
    return isDate(s[0..10]) and isTime(s[11..]);
}

/// ISO 8601 duration per the RFC 3339 appendix-A grammar (what JSON Schema
/// `duration` cites): `P` + date components in Y→M→D order and/or `T` +
/// time components in H→M→S order, each at most once, at least one overall;
/// or the exclusive week form `P<n>W`.
fn isDuration(s: []const u8) bool {
    if (s.len < 3 or s[0] != 'P') return false;
    const body = s[1..];
    if (body[body.len - 1] == 'W') return allDigits(body[0 .. body.len - 1]);
    var i: usize = 0;
    var in_time = false;
    var order: usize = 0; // strictly increasing index into "YMD" / "HMS"
    var any = false;
    while (i < body.len) {
        if (!in_time and body[i] == 'T') {
            in_time = true;
            order = 0;
            i += 1;
            if (i == body.len) return false; // bare trailing 'T'
            continue;
        }
        const start = i;
        while (i < body.len and std.ascii.isDigit(body[i])) i += 1;
        if (i == start or i == body.len) return false; // need digits + unit
        const units: []const u8 = if (in_time) "HMS" else "YMD";
        const pos = std.mem.indexOfScalar(u8, units, body[i]) orelse return false;
        if (pos < order) return false; // out of order or repeated
        order = pos + 1;
        i += 1;
        any = true;
    }
    return any;
}

/// RFC 6901 JSON Pointer: "" (whole document) or `/`-prefixed tokens where
/// `~` appears only as the escapes `~0` / `~1`.
fn isJsonPointer(s: []const u8) bool {
    if (s.len == 0) return true;
    if (s[0] != '/') return false;
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '~') {
            if (i + 1 >= s.len or (s[i + 1] != '0' and s[i + 1] != '1')) return false;
            i += 1;
        }
    }
    return true;
}

/// Fixed-width all-digit parse (≤ 4 chars at every call site — no overflow).
fn parseDigits(s: []const u8) ?u32 {
    var v: u32 = 0;
    for (s) |c| {
        if (!std.ascii.isDigit(c)) return null;
        v = v * 10 + (c - '0');
    }
    return v;
}

fn allDigits(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }
    return true;
}

fn daysInMonth(y: u32, m: u32) u32 {
    return switch (m) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(y)) @as(u32, 29) else 28,
        else => unreachable, // caller checked 1–12
    };
}

fn isLeapYear(y: u32) bool {
    return (y % 4 == 0 and y % 100 != 0) or y % 400 == 0;
}

// ── query + path params (strings → coerce + check) ──────────────────────────

/// Validate an `http.Server.Request.query` string ("a=1&b=x", no leading '?')
/// against a rule set. Names and values are percent-decoded ('+' = space,
/// invalid escapes pass through literally); for duplicate keys the first
/// occurrence wins (Go net/url semantics). Values are coerced per the rule's
/// kind — unparseable coercions yield `int_parsing`/`float_parsing`/
/// `bool_parsing` (pydantic codes); `.array`/`.object` kinds are not
/// representable in a query string and always fail their type gate.
pub fn validateQuery(gpa: Allocator, query: []const u8, schema: []const Rule) Allocator.Error!Report {
    var b = Builder.init(gpa);
    errdefer b.abort();
    for (schema) |*rule| {
        if (try findQueryParam(b.a(), query, rule.field)) |raw| {
            try checkCoerced(&b, rule.field, raw, rule);
        } else if (rule.required) {
            try b.append(rule.field, "missing", "Field required");
        }
    }
    return b.finish();
}

/// Validate `router` path params of the matched route. Values are the raw
/// path segments (the router matches byte-for-byte, no percent-decoding —
/// its documented policy), coerced per the rule's kind like `validateQuery`.
pub fn validateParams(gpa: Allocator, params: *const router.Params, schema: []const Rule) Allocator.Error!Report {
    var b = Builder.init(gpa);
    errdefer b.abort();
    for (schema) |*rule| {
        if (params.get(rule.field)) |raw| {
            try checkCoerced(&b, rule.field, raw, rule);
        } else if (rule.required) {
            try b.append(rule.field, "missing", "Field required");
        }
    }
    return b.finish();
}

/// Coerce one string value to the rule's kind, then run the shared checks.
fn checkCoerced(b: *Builder, path: []const u8, s: []const u8, rule: *const Rule) Allocator.Error!void {
    const v: Value = switch (rule.kind) {
        .string, .any => .{ .string = s },
        .int => .{ .integer = std.fmt.parseInt(i64, s, 10) catch {
            try b.append(path, "int_parsing", "Input should be a valid integer, unable to parse string as an integer");
            return;
        } },
        .float => .{ .float = std.fmt.parseFloat(f64, s) catch {
            try b.append(path, "float_parsing", "Input should be a valid number, unable to parse string as a number");
            return;
        } },
        .bool => .{ .bool = parseBool(s) orelse {
            try b.append(path, "bool_parsing", "Input should be a valid boolean, unable to interpret input");
            return;
        } },
        .array, .object => {
            try appendTypeError(b, path, rule.kind);
            return;
        },
    };
    try checkRule(b, path, v, rule);
}

fn parseBool(s: []const u8) ?bool {
    if (std.ascii.eqlIgnoreCase(s, "true") or std.mem.eql(u8, s, "1")) return true;
    if (std.ascii.eqlIgnoreCase(s, "false") or std.mem.eql(u8, s, "0")) return false;
    return null;
}

const RawPair = struct { name: []const u8, value: []const u8 };

/// Split "a=1&b=&c" into raw (undecoded) pairs; empty segments are skipped,
/// a segment without '=' is a name with value "".
const QueryIter = struct {
    rest: ?[]const u8,

    fn init(query: []const u8) QueryIter {
        return .{ .rest = if (query.len == 0) null else query };
    }

    fn next(it: *QueryIter) ?RawPair {
        while (it.rest) |r| {
            var seg = r;
            if (std.mem.indexOfScalar(u8, r, '&')) |i| {
                seg = r[0..i];
                it.rest = r[i + 1 ..];
            } else {
                it.rest = null;
            }
            if (seg.len == 0) continue;
            if (std.mem.indexOfScalar(u8, seg, '=')) |eq|
                return .{ .name = seg[0..eq], .value = seg[eq + 1 ..] };
            return .{ .name = seg, .value = "" };
        }
        return null;
    }
};

/// First (decoded) value of `name` in the query string, or null.
fn findQueryParam(a: Allocator, query: []const u8, name: []const u8) Allocator.Error!?[]const u8 {
    var it = QueryIter.init(query);
    while (it.next()) |p| {
        if (std.mem.eql(u8, try decodeComponent(a, p.name), name))
            return try decodeComponent(a, p.value);
    }
    return null;
}

/// Percent-decode a query component: '+' → space, %XX → byte; an invalid or
/// truncated escape passes through literally (lenient, like most parsers).
/// Returns the input slice unchanged when nothing needs decoding.
fn decodeComponent(a: Allocator, s: []const u8) Allocator.Error![]const u8 {
    if (std.mem.indexOfAny(u8, s, "%+") == null) return s;
    const out = try a.alloc(u8, s.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        const c = s[i];
        if (c == '+') {
            out[n] = ' ';
            n += 1;
            i += 1;
            continue;
        }
        if (c == '%' and i + 2 < s.len) {
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch 255;
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch 255;
            if (hi != 255 and lo != 255) {
                out[n] = @intCast(hi * 16 + lo);
                n += 1;
                i += 3;
                continue;
            }
        }
        out[n] = c;
        n += 1;
        i += 1;
    }
    return out[0..n];
}

// ── the typed style: comptime schema from a struct ──────────────────────────

/// Derive a validation schema from struct `T` by reflection (evaluated at
/// comptime, cached by the compiler):
///
/// - field with a default value → not required (matches std.json, which fills
///   defaults and errors on other missing fields);
/// - `?U` → `allow_null` (an explicit JSON null is accepted);
/// - `bool`/ints/floats → `.bool`/`.int`/`.float`; integer types up to 53
///   bits (exactly representable in f64) get `min`/`max` from their bit
///   width, wider unsigned ones keep `min = 0`;
/// - `[]const u8` → `.string`; `[N]u8` → `.string` with exact length;
/// - other slices → `.array` with a recursive element rule; `[N]U` adds the
///   exact length;
/// - nested structs → `.object` with recursive `fields`;
/// - enums → `.string` with `one_of` = the enum's field names;
/// - anything else → compile error.
pub fn rulesFor(comptime T: type) []const Rule {
    comptime {
        const info = @typeInfo(T);
        if (info != .@"struct")
            @compileError("validate.rulesFor: " ++ @typeName(T) ++ " is not a struct");
        const fields = info.@"struct".fields;
        var rules: [fields.len]Rule = undefined;
        for (fields, 0..) |f, i| {
            var rule = ruleForType(f.type);
            rule.field = f.name;
            rule.required = f.default_value_ptr == null;
            rules[i] = rule;
        }
        const final = rules;
        return &final;
    }
}

fn ruleForType(comptime T: type) Rule {
    comptime {
        switch (@typeInfo(T)) {
            .optional => |oi| {
                var rule = ruleForType(oi.child);
                rule.allow_null = true;
                return rule;
            },
            .bool => return .{ .field = "", .kind = .bool },
            .int => |ii| {
                var rule: Rule = .{ .field = "", .kind = .int };
                if (ii.bits <= 53) {
                    // Exactly representable in f64 → full bounds.
                    rule.min = @floatFromInt(std.math.minInt(T));
                    rule.max = @floatFromInt(std.math.maxInt(T));
                } else if (ii.signedness == .unsigned) {
                    rule.min = 0;
                }
                return rule;
            },
            .float => return .{ .field = "", .kind = .float },
            .@"enum" => |ei| {
                var names: [ei.fields.len][]const u8 = undefined;
                for (ei.fields, 0..) |f, i| names[i] = f.name;
                const final = names;
                return .{ .field = "", .kind = .string, .one_of = &final };
            },
            .pointer => |pi| {
                if (pi.size != .slice)
                    @compileError("validate: unsupported field type " ++ @typeName(T));
                if (pi.child == u8) return .{ .field = "", .kind = .string };
                const elem = ruleForType(pi.child);
                return .{ .field = "", .kind = .array, .items = &elem };
            },
            .array => |ai| {
                if (ai.child == u8)
                    return .{ .field = "", .kind = .string, .min_len = ai.len, .max_len = ai.len };
                const elem = ruleForType(ai.child);
                return .{ .field = "", .kind = .array, .min_len = ai.len, .max_len = ai.len, .items = &elem };
            },
            .@"struct" => return .{ .field = "", .kind = .object, .fields = rulesFor(T) },
            else => @compileError("validate: unsupported field type " ++ @typeName(T)),
        }
    }
}

/// Outcome of `parseInto`: a fully decoded `T` or the aggregated errors.
/// Always `deinit` (both arms own memory).
pub fn ParseResult(comptime T: type) type {
    return union(enum) {
        /// `value` is valid against the derived schema (and `T.validate_rules`
        /// when declared). Owns its memory via the std.json arena.
        ok: std.json.Parsed(T),
        invalid: Report,

        pub fn deinit(self: *@This()) void {
            switch (self.*) {
                .ok => |parsed| parsed.deinit(),
                .invalid => |*report| report.deinit(),
            }
            self.* = undefined;
        }
    };
}

/// The typed body style: parse `body` as JSON, validate it against the
/// schema derived from `T` (see `rulesFor`) — plus `T.validate_rules`
/// (`pub const validate_rules: []const validate.Rule`) when declared, for
/// constraints reflection cannot see (lengths, patterns, one-of, custom) —
/// and decode into `T`. JSON type errors come back as pathed validation
/// errors, never as parse crashes; unknown fields are ignored (JSON Schema
/// default). Only allocation errors propagate as Zig errors.
pub fn parseInto(comptime T: type, gpa: Allocator, body: []const u8) Allocator.Error!ParseResult(T) {
    return parseIntoLimited(T, gpa, body, .{});
}

/// Like `parseInto`, but with caller-chosen structural `Limits`. The body is
/// scanned for limit breaches first (`jsonLimitError`) and rejected before it
/// is materialized, so an over-limit payload becomes a clean validation error
/// (`too_deep` / `array_too_large` / `too_many_fields` / `too_many_nodes`)
/// instead of an expensive parse.
pub fn parseIntoLimited(comptime T: type, gpa: Allocator, body: []const u8, limits: Limits) Allocator.Error!ParseResult(T) {
    if (try jsonLimitError(gpa, body, limits)) |e|
        return .{ .invalid = try singleErrorReport(gpa, e) };

    const schema = comptime rulesFor(T);

    var parsed = std.json.parseFromSlice(Value, gpa, body, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .invalid = try jsonInvalidReport(gpa, err) },
    };
    defer parsed.deinit();

    var b = Builder.init(gpa);
    errdefer b.abort();
    try checkValue(&b, "", parsed.value, schema);
    if (@hasDecl(T, "validate_rules"))
        try checkValue(&b, "", parsed.value, T.validate_rules);
    if (b.list.items.len != 0) return .{ .invalid = b.finish() };
    b.abort();

    const typed = std.json.parseFromValue(T, gpa, parsed.value, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Defensive: validation passed but the decode still refused (e.g. an
        // i64/u64 field outside the f64-expressible bounds the derived schema
        // could not carry). Surface as a validation error, never a crash.
        else => {
            var db = Builder.init(gpa);
            errdefer db.abort();
            try db.appendf("", "invalid", "Input could not be decoded: {s}", .{@errorName(err)});
            return .{ .invalid = db.finish() };
        },
    };
    return .{ .ok = typed };
}

// ── middleware (router + http) ──────────────────────────────────────────────

/// Runtime-schema JSON body validation middleware. Register on the group (or
/// router) whose routes carry JSON bodies — it validates every request it
/// sees, so keep it off bodyless GET/HEAD routes. The struct must outlive the
/// router at a stable address (`Middleware.state` points at it).
///
/// On success the parsed body is available to inner middleware/handlers via
/// `validate.bodyValue(ctx)`.
pub const Body = struct {
    gpa: Allocator,
    schema: []const Rule,
    /// Request bodies beyond this answer 413 (the middleware buffers the
    /// body to parse it; `http.Server.max_body_bytes` caps the wire side).
    max_body_bytes: usize = 1 << 20,
    /// Structural JSON caps enforced (fail-fast) before the body is parsed.
    limits: Limits = .{},

    pub fn middleware(v: *const Body) router.Middleware {
        // state is a mutable pointer by type only — run() never writes.
        return .{ .state = @constCast(v), .run = runBody };
    }

    fn runBody(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
        const v: *const Body = @ptrCast(@alignCast(state.?));
        const raw = (try readBody(ctx, v.gpa, v.max_body_bytes)) orelse return;
        defer v.gpa.free(raw);

        // Structural DoS caps, enforced before the value tree is built.
        if (try jsonLimitError(v.gpa, raw, v.limits)) |e|
            return respondInvalid(ctx.res, &.{e}); // no next

        var parsed = std.json.parseFromSlice(Value, v.gpa, raw, .{}) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                var report = try jsonInvalidReport(v.gpa, err);
                defer report.deinit();
                return respondInvalid(ctx.res, report.errors);
            },
        };
        defer parsed.deinit();

        var report = try validateValue(v.gpa, parsed.value, v.schema);
        defer report.deinit();
        if (!report.ok()) return respondInvalid(ctx.res, report.errors); // no next

        var validated: ValidatedBody = .{ .value = parsed.value, .raw = raw };
        var slot: Slot = .{ .kind = .body, .payload = &validated, .prev = ctx.data };
        ctx.data = &slot;
        defer ctx.data = slot.prev;
        try next.run(ctx);
    }
};

/// What `Body` leaves for the handler (valid for the handler call only).
pub const ValidatedBody = struct {
    /// The parsed JSON document, already validated against the schema.
    value: Value,
    /// The raw body bytes.
    raw: []const u8,
};

/// The `Body` middleware's parsed+validated request body, or null when no
/// `Body` middleware ran on this route.
pub fn bodyValue(ctx: *router.Ctx) ?*const ValidatedBody {
    const slot = findSlot(ctx, .body, null) orelse return null;
    return @ptrCast(@alignCast(slot.payload));
}

/// Typed JSON body validation middleware over `parseInto(T, …)` — the
/// pydantic-model shape. Same registration/lifetime rules as `Body`. On
/// success the decoded `T` is available via `TypedBody(T).get(ctx)`.
pub fn TypedBody(comptime T: type) type {
    return struct {
        gpa: Allocator,
        /// See `Body.max_body_bytes`.
        max_body_bytes: usize = 1 << 20,
        /// See `Body.limits`.
        limits: Limits = .{},

        const Self = @This();

        pub fn middleware(v: *const Self) router.Middleware {
            return .{ .state = @constCast(v), .run = run };
        }

        /// The decoded body for handlers behind this middleware, or null
        /// when it did not run on this route.
        pub fn get(ctx: *router.Ctx) ?*const T {
            const slot = findSlot(ctx, .typed, @typeName(T)) orelse return null;
            return @ptrCast(@alignCast(slot.payload));
        }

        fn run(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
            const v: *const Self = @ptrCast(@alignCast(state.?));
            const raw = (try readBody(ctx, v.gpa, v.max_body_bytes)) orelse return;
            defer v.gpa.free(raw);

            var result = try parseIntoLimited(T, v.gpa, raw, v.limits);
            defer result.deinit();
            switch (result) {
                .invalid => |report| return respondInvalid(ctx.res, report.errors), // no next
                .ok => |parsed| {
                    var slot: Slot = .{
                        .kind = .typed,
                        .type_name = @typeName(T),
                        .payload = &parsed.value,
                        .prev = ctx.data,
                    };
                    ctx.data = &slot;
                    defer ctx.data = slot.prev;
                    try next.run(ctx);
                },
            }
        }
    };
}

/// Query-string validation middleware (`validateQuery` semantics). On
/// success the decoded pairs are available via `validate.queryValues(ctx)`.
/// Same registration/lifetime rules as `Body`.
pub const Query = struct {
    gpa: Allocator,
    schema: []const Rule,

    pub fn middleware(v: *const Query) router.Middleware {
        return .{ .state = @constCast(v), .run = runQuery };
    }

    fn runQuery(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
        const v: *const Query = @ptrCast(@alignCast(state.?));
        var report = try validateQuery(v.gpa, ctx.req.query, v.schema);
        defer report.deinit();
        if (!report.ok()) return respondInvalid(ctx.res, report.errors); // no next

        var arena = std.heap.ArenaAllocator.init(v.gpa);
        defer arena.deinit();
        const values: ValidatedQuery = .{ .pairs = try decodePairs(arena.allocator(), ctx.req.query) };
        var slot: Slot = .{ .kind = .query, .payload = &values, .prev = ctx.data };
        ctx.data = &slot;
        defer ctx.data = slot.prev;
        try next.run(ctx);
    }
};

/// What `Query` leaves for the handler: all pairs, percent-decoded, in wire
/// order (valid for the handler call only).
pub const ValidatedQuery = struct {
    pairs: []const Pair,

    pub const Pair = struct { name: []const u8, value: []const u8 };

    /// First value of `name`, or null.
    pub fn get(q: *const ValidatedQuery, name: []const u8) ?[]const u8 {
        for (q.pairs) |p| {
            if (std.mem.eql(u8, p.name, name)) return p.value;
        }
        return null;
    }
};

/// The `Query` middleware's decoded pairs, or null when it did not run.
pub fn queryValues(ctx: *router.Ctx) ?*const ValidatedQuery {
    const slot = findSlot(ctx, .query, null) orelse return null;
    return @ptrCast(@alignCast(slot.payload));
}

fn decodePairs(a: Allocator, query: []const u8) Allocator.Error![]const ValidatedQuery.Pair {
    var list: std.ArrayList(ValidatedQuery.Pair) = .empty;
    var it = QueryIter.init(query);
    while (it.next()) |p| {
        try list.append(a, .{
            .name = try decodeComponent(a, p.name),
            .value = try decodeComponent(a, p.value),
        });
    }
    return list.items;
}

/// Path-param validation middleware (`validateParams` semantics). Handlers
/// keep reading `ctx.params` directly — the values are unchanged; this only
/// gates them. Named to avoid clashing with `router.Params`.
pub const PathParams = struct {
    gpa: Allocator,
    schema: []const Rule,

    pub fn middleware(v: *const PathParams) router.Middleware {
        return .{ .state = @constCast(v), .run = runParams };
    }

    fn runParams(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
        const v: *const PathParams = @ptrCast(@alignCast(state.?));
        var report = try validateParams(v.gpa, &ctx.params, v.schema);
        defer report.deinit();
        if (!report.ok()) return respondInvalid(ctx.res, report.errors); // no next
        try next.run(ctx);
    }
};

/// Buffer the whole request body, or answer 413 and return null when it
/// exceeds `max` (the JSON must be in memory to parse). Wire-level read
/// failures propagate — the serving loop owns that connection's fate.
fn readBody(ctx: *router.Ctx, gpa: Allocator, max: usize) anyerror!?[]u8 {
    return ctx.req.reader().allocRemaining(gpa, .limited(max)) catch |err| switch (err) {
        error.StreamTooLong => {
            ctx.res.setStatus(413);
            try ctx.res.setHeader("Content-Type", "application/json");
            try ctx.res.writeAll(
                \\{"errors":[{"path":"","code":"too_large","message":"Request body too large"}]}
            );
            return null;
        },
        else => |e| return e,
    };
}

/// The 400 short-circuit: status + JSON error body, handler never runs.
fn respondInvalid(res: *http.Server.ResponseWriter, errors: []const Error) anyerror!void {
    res.setStatus(400);
    try res.setHeader("Content-Type", "application/json");
    try writeErrorsJson(errors, res.writer());
}

// ── the ctx.data slot protocol ──────────────────────────────────────────────

/// Randomly-chosen tag so getters can tell validate-owned `ctx.data` slots
/// from foreign data without dereferencing blindly.
const slot_magic: u64 = 0x7f9c_51e3_76a1_d84b;

const SlotKind = enum { body, typed, query };

/// A stack-frame cell linking one middleware's payload into `ctx.data`;
/// `prev` restores the previous value after `next` returns, so validate
/// middleware stack freely.
const Slot = struct {
    magic: u64 = slot_magic,
    kind: SlotKind,
    /// `@typeName(T)` for `.typed` slots (distinguishes stacked TypedBody
    /// middleware of different T).
    type_name: []const u8 = "",
    payload: *const anyopaque,
    prev: ?*anyopaque,
};

fn findSlot(ctx: *router.Ctx, kind: SlotKind, type_name: ?[]const u8) ?*const Slot {
    var cur: ?*anyopaque = ctx.data;
    while (cur) |p| {
        // Unaligned probe first: a foreign ctx.data value may be less
        // aligned than Slot; only after the magic matches is it ours.
        const probe: *align(1) const u64 = @ptrCast(p);
        if (probe.* != slot_magic) return null;
        const slot: *const Slot = @ptrCast(@alignCast(p));
        if (slot.kind == kind and
            (type_name == null or std.mem.eql(u8, slot.type_name, type_name.?)))
            return slot;
        cur = slot.prev;
    }
    return null;
}

// ── tests: validator core ───────────────────────────────────────────────────

const testing = std.testing;

fn expectError(report: *const Report, path: []const u8, code: []const u8) !void {
    const e = report.find(path) orelse {
        std.debug.print("no error at path \"{s}\" (have {d} errors)\n", .{ path, report.errors.len });
        return error.TestExpectedError;
    };
    try testing.expectEqualStrings(code, e.code);
}

test "required: missing field → missing; present passes; valid input → ok" {
    const schema = [_]Rule{
        .{ .field = "name", .kind = .string, .required = true },
        .{ .field = "note", .kind = .string }, // optional
    };
    var bad = try validateJson(testing.allocator, "{}", &schema);
    defer bad.deinit();
    try testing.expectEqual(@as(usize, 1), bad.errors.len);
    try expectError(&bad, "name", "missing");
    try testing.expectEqualStrings("Field required", bad.errors[0].message);

    var good = try validateJson(testing.allocator, "{\"name\":\"x\"}", &schema);
    defer good.deinit();
    try testing.expect(good.ok());
}

test "type gates: every kind produces its <kind>_type code at the right path" {
    const schema = [_]Rule{
        .{ .field = "s", .kind = .string },
        .{ .field = "i", .kind = .int },
        .{ .field = "f", .kind = .float },
        .{ .field = "b", .kind = .bool },
        .{ .field = "a", .kind = .array },
        .{ .field = "o", .kind = .object },
    };
    var r = try validateJson(testing.allocator,
        \\{"s":1,"i":"x","f":true,"b":3,"a":{},"o":[]}
    , &schema);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 6), r.errors.len);
    try expectError(&r, "s", "string_type");
    try expectError(&r, "i", "int_type");
    try expectError(&r, "f", "float_type");
    try expectError(&r, "b", "bool_type");
    try expectError(&r, "a", "array_type");
    try expectError(&r, "o", "object_type");
}

test "int gate: integral float accepted (JSON Schema), fractional rejected; int passes float" {
    const schema = [_]Rule{
        .{ .field = "n", .kind = .int },
        .{ .field = "x", .kind = .float },
    };
    var ok = try validateJson(testing.allocator, "{\"n\":2.0,\"x\":3}", &schema);
    defer ok.deinit();
    try testing.expect(ok.ok());

    var bad = try validateJson(testing.allocator, "{\"n\":2.5}", &schema);
    defer bad.deinit();
    try expectError(&bad, "n", "int_type");
}

test "null: typed kind rejects, allow_null accepts, .any accepts; constraint skipped on allowed null" {
    const schema = [_]Rule{
        .{ .field = "a", .kind = .int },
        .{ .field = "b", .kind = .int, .allow_null = true, .min = 5 },
        .{ .field = "c", .kind = .any },
    };
    var r = try validateJson(testing.allocator, "{\"a\":null,\"b\":null,\"c\":null}", &schema);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.errors.len);
    try expectError(&r, "a", "int_type");
}

test "min/max: inclusive bounds → greater_than_equal / less_than_equal" {
    const schema = [_]Rule{
        .{ .field = "n", .kind = .int, .min = 1, .max = 10 },
    };
    var low = try validateJson(testing.allocator, "{\"n\":0}", &schema);
    defer low.deinit();
    try expectError(&low, "n", "greater_than_equal");
    try testing.expectEqualStrings("Input should be greater than or equal to 1", low.errors[0].message);

    var high = try validateJson(testing.allocator, "{\"n\":11}", &schema);
    defer high.deinit();
    try expectError(&high, "n", "less_than_equal");

    var edge = try validateJson(testing.allocator, "{\"n\":10}", &schema);
    defer edge.deinit();
    try testing.expect(edge.ok()); // inclusive
}

test "length: string codes differ from array codes (pydantic)" {
    const schema = [_]Rule{
        .{ .field = "s", .kind = .string, .min_len = 2, .max_len = 4 },
        .{ .field = "a", .kind = .array, .min_len = 1, .max_len = 2 },
    };
    var short = try validateJson(testing.allocator, "{\"s\":\"x\",\"a\":[]}", &schema);
    defer short.deinit();
    try expectError(&short, "s", "string_too_short");
    try expectError(&short, "a", "too_short");

    var long = try validateJson(testing.allocator, "{\"s\":\"abcde\",\"a\":[1,2,3]}", &schema);
    defer long.deinit();
    try expectError(&long, "s", "string_too_long");
    try expectError(&long, "a", "too_long");
}

test "one_of → enum code with the allowed list in the message" {
    const schema = [_]Rule{
        .{ .field = "color", .kind = .string, .one_of = &.{ "red", "green", "blue" } },
    };
    var bad = try validateJson(testing.allocator, "{\"color\":\"mauve\"}", &schema);
    defer bad.deinit();
    try expectError(&bad, "color", "enum");
    try testing.expectEqualStrings("Input should be one of: red, green, blue", bad.errors[0].message);

    var good = try validateJson(testing.allocator, "{\"color\":\"green\"}", &schema);
    defer good.deinit();
    try testing.expect(good.ok());
}

test "pattern: literal / prefix / suffix / charset → string_pattern_mismatch" {
    const schema = [_]Rule{
        .{ .field = "lit", .kind = .string, .pattern = .{ .literal = "on" } },
        .{ .field = "pre", .kind = .string, .pattern = .{ .prefix = "usr_" } },
        .{ .field = "suf", .kind = .string, .pattern = .{ .suffix = ".txt" } },
        .{ .field = "hex", .kind = .string, .pattern = .{ .charset = "0123456789abcdef" } },
    };
    var good = try validateJson(testing.allocator,
        \\{"lit":"on","pre":"usr_7","suf":"a.txt","hex":"c0ffee"}
    , &schema);
    defer good.deinit();
    try testing.expect(good.ok());

    var bad = try validateJson(testing.allocator,
        \\{"lit":"off","pre":"grp_7","suf":"a.png","hex":"c0ffee!"}
    , &schema);
    defer bad.deinit();
    try testing.expectEqual(@as(usize, 4), bad.errors.len);
    for (bad.errors) |e| try testing.expectEqualStrings("string_pattern_mismatch", e.code);
}

// ── tests: string formats ───────────────────────────────────────────────────

fn expectFormat(f: Format, valid: []const []const u8, invalid: []const []const u8) !void {
    for (valid) |s| {
        if (!validateFormat(f, s)) {
            std.debug.print("{s}: expected VALID: \"{s}\"\n", .{ @tagName(f), s });
            return error.TestUnexpectedResult;
        }
    }
    for (invalid) |s| {
        if (validateFormat(f, s)) {
            std.debug.print("{s}: expected INVALID: \"{s}\"\n", .{ @tagName(f), s });
            return error.TestUnexpectedResult;
        }
    }
}

test "format truth table: email" {
    try expectFormat(.email, &.{
        "a@b.com",
        "user.name+tag@example.co.uk",
        "x_1!#$%&'*=?@foo-bar.example.com",
        "1@2.3", // all-numeric labels are RFC 1123 legal
    }, &.{
        "",
        "a@b", // no dot in domain
        "@b.com", // empty local
        "a@", // empty domain
        "a b@c.com", // space
        "a@@b.com", // two '@'
        "a@b..com", // empty domain label
        ".a@b.com", // dot at local start
        "a.@b.com", // dot at local end
        "a..b@c.com", // consecutive dots
        "a@-b.com", // hyphen at label start
        ("a" ** 65) ++ "@b.com", // local > 64
    });
}

test "format truth table: uri + uri_reference" {
    try expectFormat(.uri, &.{
        "https://example.com/path?q=1#frag",
        "mailto:user@example.com",
        "urn:isbn:0451450523",
        "ftp://ftp.example.com:21/files",
        "a+b-c.d://x", // exotic but legal scheme chars
    }, &.{
        "",
        "example.com/path", // no scheme
        "//host/path", // scheme-relative, not absolute
        "http://exa mple.com", // space
        "1http://x", // scheme starts with a digit
        "http://x/%zz", // bad percent escape
        "http://x/%4", // truncated percent escape
        "http://x#a#b", // two fragments
        "http://x/\x01", // control byte
    });
    try expectFormat(.uri_reference, &.{
        "", // empty relative ref is valid (RFC 3986)
        "/path/to?x=1",
        "//host/p",
        "#frag",
        "foo/bar",
        "https://e.com",
    }, &.{
        "a b", // space
        "%3", // truncated escape
        "%GG", // non-hex escape
        "\xff\xfe", // non-URI bytes
    });
}

test "format truth table: uuid (shape only, case-insensitive)" {
    try expectFormat(.uuid, &.{
        "123e4567-e89b-12d3-a456-426614174000",
        "123E4567-E89B-12D3-A456-426614174000",
        "00000000-0000-0000-0000-000000000000", // NIL — version not asserted
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
    }, &.{
        "",
        "123e4567-e89b-12d3-a456-42661417400", // 35 chars
        "123e4567-e89b-12d3-a456-4266141740000", // 37 chars
        "123e4567e89b12d3a456426614174000", // no hyphens
        "123e4567-e89b-12d3-a456-42661417400g", // non-hex
        "123e4567_e89b_12d3_a456_426614174000", // wrong separators
    });
}

test "format truth table: ipv4 + ipv6 (via netaddr, family asserted)" {
    try expectFormat(.ipv4, &.{
        "192.0.2.1",
        "0.0.0.0",
        "255.255.255.255",
    }, &.{
        "",
        "256.0.0.1", // octet out of range
        "::1", // v6 is not v4
        "1.2.3",
        "1.2.3.4.5",
        "01.2.3.4", // leading zero
        "1.2.3.x",
    });
    try expectFormat(.ipv6, &.{
        "2001:db8::1",
        "::1",
        "::",
        "::ffff:192.0.2.1", // v4-mapped parses as the v6 family
        "2001:0db8:0000:0000:0000:0000:0000:0001",
    }, &.{
        "",
        "192.0.2.1", // v4 is not v6
        "2001:db8::1::2", // two '::'
        "gggg::1", // non-hex group
        "2001:db8", // too few groups
        "fe80::1%eth0", // zone rejected by netaddr policy
    });
}

test "format truth table: hostname" {
    try expectFormat(.hostname, &.{
        "foo.example.com",
        "localhost",
        "a",
        "xn--nxasmq6b.example", // punycode shape
        "123.example",
        ("a" ** 63) ++ ".example", // longest legal label
    }, &.{
        "",
        "-bad.example", // hyphen at label start
        "bad-.example", // hyphen at label end
        "a..b", // empty label
        "foo.example.com.", // trailing dot = empty last label
        "foo_bar.example", // underscore
        ("a" ** 64) ++ ".example", // label > 63
        // 257 bytes of valid labels → total-length limit trips:
        ("a" ** 63) ++ "." ++ ("b" ** 63) ++ "." ++ ("c" ** 63) ++ "." ++ ("d" ** 63) ++ ".e",
    });
}

test "format truth table: date (calendar-correct, incl. leap years)" {
    try expectFormat(.date, &.{
        "2024-02-29", // leap year
        "2000-02-29", // 400-rule leap year
        "2023-12-31",
        "2023-01-01",
        "2023-04-30",
    }, &.{
        "",
        "2023-02-29", // not a leap year
        "1900-02-29", // 100-rule non-leap
        "2024-13-01", // month 13
        "2024-00-10", // month 0
        "2024-01-00", // day 0
        "2024-01-32", // day 32
        "2024-04-31", // April has 30
        "2024-1-01", // not zero-padded
        "20240101", // no separators
        "2024/01/01",
    });
}

test "format truth table: time (leap second 23:59:60 ACCEPTED per RFC 3339)" {
    try expectFormat(.time, &.{
        "00:00:00",
        "23:59:59",
        "23:59:60", // leap second — documented accept
        "12:30:45.123",
        "12:30:45Z",
        "12:30:45z",
        "12:30:45.5+02:00",
        "12:30:45-23:59",
    }, &.{
        "",
        "24:00:00", // hour 24
        "12:60:00", // minute 60
        "12:00:61", // second 61
        "12:00:00.", // empty fraction
        "12:00:00+2:00", // unpadded offset hour
        "12:00:00+24:00", // offset hour out of range
        "12:00:00+02:60", // offset minute out of range
        "12:00:00X", // junk suffix
        "1:00:00", // not zero-padded
    });
}

test "format truth table: date_time (combined form; T required)" {
    try expectFormat(.date_time, &.{
        "2024-01-02T03:04:05Z",
        "2024-01-02T03:04:05+02:00",
        "2024-01-02t03:04:05z", // lowercase t/z (RFC 3339 case-insensitive)
        "2024-02-29T23:59:60Z", // leap day + leap second
        "2024-01-02T03:04:05.123-07:00",
        "2024-01-02T03:04:05", // offset-less accepted (documented ISO profile)
    }, &.{
        "",
        "2024-01-02 03:04:05Z", // space instead of T
        "2024-01-0203:04:05Z", // missing separator entirely
        "2023-02-29T00:00:00Z", // invalid date part
        "2024-01-02T25:00:00Z", // invalid time part
        "2024-01-02T03:04:05+2:00", // bad offset
        "2024-01-02T", // no time
        "03:04:05Z", // no date
    });
}

test "format truth table: duration + json_pointer (optional formats)" {
    try expectFormat(.duration, &.{
        "P1Y2M3DT4H5M6S",
        "P1D",
        "PT1S",
        "PT0S",
        "P1W", // week form
        "P3Y6M4DT12H30M5S",
    }, &.{
        "",
        "P", // no components
        "PT", // bare T
        "1Y", // missing P
        "P1S", // time unit in the date part
        "P1D2Y", // out of order
        "PT1S2H", // out of order
        "P1Y1Y", // repeated unit
        "P1W2D", // week form is exclusive
        "-P1D",
        "P1.5D", // fractions not in the cited grammar
    });
    try expectFormat(.json_pointer, &.{
        "", // whole document
        "/",
        "/foo/bar",
        "/a~0b/c~1d", // ~0 and ~1 escapes
        "/foo/0",
    }, &.{
        "foo", // must start with '/'
        "/a~2", // bad escape
        "/a~", // dangling '~'
    });
}

test "format robustness: every format rejects hostile input without panicking" {
    const hostile = [_][]const u8{
        "", // empty
        "\xff\xfe\x80garbage\x00", // non-UTF-8 bytes + NUL
        "a" ** 5000, // huge
        "%", "~", "-", ".", ":", "@", // lone specials near each grammar
    };
    inline for (@typeInfo(Format).@"enum".fields) |f| {
        const format: Format = @enumFromInt(f.value);
        for (hostile) |s| _ = validateFormat(format, s);
    }
    // And the huge/garbage cases really are invalid everywhere.
    inline for (@typeInfo(Format).@"enum".fields) |f| {
        const format: Format = @enumFromInt(f.value);
        try testing.expect(!validateFormat(format, "\xff\xfe\x80garbage\x00"));
    }
}

test "format rule: aggregated errors with field paths + the format code" {
    const schema = [_]Rule{
        .{ .field = "email", .kind = .string, .required = true, .format = .email },
        .{ .field = "host", .kind = .string, .format = .hostname },
        .{ .field = "when", .kind = .string, .format = .date_time },
        .{ .field = "peer", .kind = .object, .fields = &.{
            .{ .field = "ip", .kind = .string, .format = .ipv6 },
        } },
    };
    var bad = try validateJson(testing.allocator,
        \\{"email":"not-an-email","host":"-x.example","when":"2024-13-01T00:00:00Z","peer":{"ip":"192.0.2.1"}}
    , &schema);
    defer bad.deinit();
    try testing.expectEqual(@as(usize, 4), bad.errors.len);
    try expectError(&bad, "email", "format");
    try expectError(&bad, "host", "format");
    try expectError(&bad, "when", "format");
    try expectError(&bad, "peer.ip", "format"); // nested path composes
    try testing.expectEqualStrings("Input should be a valid email address", bad.errors[0].message);
    try testing.expectEqualStrings("Input should be a valid IPv6 address", bad.errors[3].message);

    var good = try validateJson(testing.allocator,
        \\{"email":"a@b.com","host":"x.example","when":"2024-01-02T03:04:05Z","peer":{"ip":"2001:db8::1"}}
    , &schema);
    defer good.deinit();
    try testing.expect(good.ok());

    // Wrong type → one <kind>_type error, format never runs (type gate).
    var wrong = try validateJson(testing.allocator, "{\"email\":5}", &schema);
    defer wrong.deinit();
    try expectError(&wrong, "email", "string_type");
    try testing.expect(wrong.find("email").?.code.len > 0);
    for (wrong.errors) |e| try testing.expect(!std.mem.eql(u8, e.code, "format"));
}

test "format rule: applies to coerced query strings too" {
    const schema = [_]Rule{
        .{ .field = "cb", .kind = .string, .required = true, .format = .uri },
    };
    var bad = try validateQuery(testing.allocator, "cb=not%20a%20uri", &schema);
    defer bad.deinit();
    try expectError(&bad, "cb", "format");

    var good = try validateQuery(testing.allocator, "cb=https%3A%2F%2Fe.com%2Fhook", &schema);
    defer good.deinit();
    try testing.expect(good.ok());
}

fn evenCheck(ctx: ?*anyopaque, v: Value) bool {
    const counter: *u32 = @ptrCast(@alignCast(ctx.?));
    counter.* += 1;
    return v == .integer and @rem(v.integer, 2) == 0;
}

test "custom predicate: ctx passthrough, own code/message, runs after type gate" {
    var calls: u32 = 0;
    const schema = [_]Rule{
        .{ .field = "n", .kind = .int, .custom = .{
            .ctx = &calls,
            .check = evenCheck,
            .code = "not_even",
            .message = "Input should be even",
        } },
    };
    var bad = try validateJson(testing.allocator, "{\"n\":3}", &schema);
    defer bad.deinit();
    try expectError(&bad, "n", "not_even");
    try testing.expectEqualStrings("Input should be even", bad.errors[0].message);

    var good = try validateJson(testing.allocator, "{\"n\":4}", &schema);
    defer good.deinit();
    try testing.expect(good.ok());
    try testing.expectEqual(@as(u32, 2), calls);

    // Wrong type → type error only; the predicate never runs.
    var wrong = try validateJson(testing.allocator, "{\"n\":\"x\"}", &schema);
    defer wrong.deinit();
    try expectError(&wrong, "n", "int_type");
    try testing.expectEqual(@as(u32, 2), calls);
}

test "nesting: object fields → dotted paths, array items → indexed paths" {
    const schema = [_]Rule{
        .{ .field = "user", .kind = .object, .required = true, .fields = &.{
            .{ .field = "name", .kind = .string, .required = true },
            .{ .field = "age", .kind = .int, .min = 0 },
        } },
        .{ .field = "tags", .kind = .array, .items = &.{ .field = "", .kind = .string, .min_len = 2 } },
    };
    var r = try validateJson(testing.allocator,
        \\{"user":{"age":-1},"tags":["ok","x",3]}
    , &schema);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 4), r.errors.len);
    try expectError(&r, "user.name", "missing");
    try expectError(&r, "user.age", "greater_than_equal");
    try expectError(&r, "tags[1]", "string_too_short");
    try expectError(&r, "tags[2]", "string_type");
}

test "aggregation: multi-field bad input → ALL errors, in schema order" {
    const schema = [_]Rule{
        .{ .field = "a", .kind = .string, .required = true },
        .{ .field = "b", .kind = .int, .min = 10 },
        .{ .field = "c", .kind = .bool, .required = true },
    };
    var r = try validateJson(testing.allocator, "{\"b\":3}", &schema);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 3), r.errors.len);
    try testing.expectEqualStrings("a", r.errors[0].path);
    try testing.expectEqualStrings("missing", r.errors[0].code);
    try testing.expectEqualStrings("b", r.errors[1].path);
    try testing.expectEqualStrings("greater_than_equal", r.errors[1].code);
    try testing.expectEqualStrings("c", r.errors[2].path);
    try testing.expectEqualStrings("missing", r.errors[2].code);
}

test "root: non-object input → object_type at path \"\"" {
    const schema = [_]Rule{.{ .field = "x", .kind = .int }};
    inline for ([_][]const u8{ "[1,2]", "\"str\"", "42", "null", "true" }) |doc| {
        var r = try validateJson(testing.allocator, doc, &schema);
        defer r.deinit();
        try testing.expectEqual(@as(usize, 1), r.errors.len);
        try expectError(&r, "", "object_type");
    }
}

test "malformed JSON: clean json_invalid error, never a panic" {
    const schema = [_]Rule{.{ .field = "x", .kind = .int }};
    inline for ([_][]const u8{ "", "{", "{\"a\":}", "\x00", "{\"a\":1,}", "[1,", "nul" }) |doc| {
        var r = try validateJson(testing.allocator, doc, &schema);
        defer r.deinit();
        try testing.expectEqual(@as(usize, 1), r.errors.len);
        try expectError(&r, "", "json_invalid");
    }
}

// ── tests: JSON structural limits (DoS) ─────────────────────────────────────

test "limits: depth beyond max_depth → too_deep, rejected before schema runs" {
    // Schema demands a "name" field; the doc is over-deep AND lacks it. The
    // fail-fast scan must win, yielding ONLY too_deep — proof the document is
    // never parsed/validated against the schema.
    const schema = [_]Rule{.{ .field = "name", .kind = .string, .required = true }};
    var r = try validateJsonLimited(testing.allocator, "[[[[[[1]]]]]]", &schema, .{ .max_depth = 4 });
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.errors.len);
    try expectError(&r, "", "too_deep");
    try testing.expectEqualStrings("JSON nesting is too deep", r.errors[0].message);

    // At the boundary (exactly max_depth) the scan passes → normal validation
    // runs (root is an array, not an object → object_type, not too_deep).
    var ok = try validateJsonLimited(testing.allocator, "[[[[1]]]]", &schema, .{ .max_depth = 4 });
    defer ok.deinit();
    try expectError(&ok, "", "object_type");
}

test "limits: array beyond max_array_elements → array_too_large" {
    const schema = [_]Rule{.{ .field = "x", .kind = .int }};
    var r = try validateJsonLimited(testing.allocator, "{\"x\":[1,2,3,4]}", &schema, .{ .max_array_elements = 3 });
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.errors.len);
    try expectError(&r, "", "array_too_large");

    var ok = try validateJsonLimited(testing.allocator, "{\"x\":1}", &schema, .{ .max_array_elements = 3 });
    defer ok.deinit();
    try testing.expect(ok.ok()); // 3-or-fewer arrays fine; x=1 passes .int
}

test "limits: object beyond max_object_members → too_many_fields" {
    const schema = [_]Rule{.{ .field = "a", .kind = .int }};
    var r = try validateJsonLimited(testing.allocator, "{\"a\":1,\"b\":2,\"c\":3}", &schema, .{ .max_object_members = 2 });
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.errors.len);
    try expectError(&r, "", "too_many_fields");

    // Nested object members are counted per-object, not globally.
    var nested = try validateJsonLimited(testing.allocator, "{\"a\":1,\"b\":{\"p\":1,\"q\":2}}", &schema, .{ .max_object_members = 2 });
    defer nested.deinit();
    try testing.expect(nested.ok());
}

test "limits: total node cap → too_many_nodes" {
    const schema = [_]Rule{.{ .field = "x", .kind = .any }};
    // Object(node) + array(node) + 3 ints = 5 value nodes; keys don't count.
    var r = try validateJsonLimited(testing.allocator, "{\"x\":[1,2,3]}", &schema, .{ .max_total_nodes = 4 });
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.errors.len);
    try expectError(&r, "", "too_many_nodes");

    var ok = try validateJsonLimited(testing.allocator, "{\"x\":[1,2,3]}", &schema, .{ .max_total_nodes = 5 });
    defer ok.deinit();
    try testing.expect(ok.ok());
}

test "limits: a document within limits parses and validates as usual" {
    const schema = [_]Rule{
        .{ .field = "name", .kind = .string, .required = true, .min_len = 1 },
        .{ .field = "tags", .kind = .array, .items = &.{ .field = "", .kind = .string } },
    };
    // Well within every default bound.
    var good = try validateJson(testing.allocator,
        \\{"name":"ok","tags":["a","b","c"]}
    , &schema);
    defer good.deinit();
    try testing.expect(good.ok());

    // Escaped strings (which the scanner emits as partial-token runs) are
    // handled: keys and values both counted correctly, no false positive.
    var esc = try validateJsonLimited(testing.allocator,
        \\{"na\tme":"a\"b","tags":["x\ny"]}
    , &([_]Rule{.{ .field = "tags", .kind = .array }}), .{ .max_object_members = 2, .max_array_elements = 2 });
    defer esc.deinit();
    try testing.expect(esc.ok());
}

test "limits: defaults protect a caller who sets nothing (via validateJson)" {
    const schema = [_]Rule{.{ .field = "x", .kind = .int }};
    // 40 levels of nesting > the default max_depth of 32 → rejected out of the
    // box, no explicit Limits passed.
    const deep = ("[" ** 40) ++ ("]" ** 40);
    var r = try validateJson(testing.allocator, deep, &schema);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.errors.len);
    try expectError(&r, "", "too_deep");
}

test "limits: malformed JSON still surfaces json_invalid, not a limit code" {
    const schema = [_]Rule{.{ .field = "x", .kind = .int }};
    // Over-deep for this tiny limit AND truncated: the scan defers to the
    // parser, so the diagnosis stays json_invalid.
    var r = try validateJsonLimited(testing.allocator, "{\"a\":", &schema, .{ .max_depth = 1 });
    defer r.deinit();
    try expectError(&r, "", "json_invalid");
}

test "limits: parseIntoLimited rejects over-limit body before decoding T" {
    var result = try parseIntoLimited(Widget, testing.allocator,
        \\{"name":"n","qty":1,"tags":["a","b","c","d"]}
    , .{ .max_array_elements = 2 });
    defer result.deinit();
    try testing.expect(result == .invalid);
    try testing.expectEqual(@as(usize, 1), result.invalid.errors.len);
    try expectError(&result.invalid, "", "array_too_large");
}

test "limits: jsonLimitError is null within bounds, set past them" {
    try testing.expectEqual(@as(?Error, null), try jsonLimitError(testing.allocator, "{\"a\":[1,2,3]}", .{}));
    const v = (try jsonLimitError(testing.allocator, "[1,2,3,4,5]", .{ .max_array_elements = 4 })).?;
    try testing.expectEqualStrings("array_too_large", v.code);
    try testing.expectEqualStrings("", v.path);
}

test "golden: the 400 error-body JSON is well-formed and byte-stable" {
    const schema = [_]Rule{
        .{ .field = "name", .kind = .string, .required = true },
        .{ .field = "qty", .kind = .int, .min = 1 },
    };
    var r = try validateJson(testing.allocator, "{\"qty\":0}", &schema);
    defer r.deinit();

    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try r.writeJson(&w);
    try testing.expectEqualStrings(
        \\{"errors":[{"path":"name","code":"missing","message":"Field required"},{"path":"qty","code":"greater_than_equal","message":"Input should be greater than or equal to 1"}]}
    , w.buffered());

    // And it round-trips as JSON.
    var parsed = try std.json.parseFromSlice(Value, testing.allocator, w.buffered(), .{});
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 2), parsed.value.object.get("errors").?.array.items.len);
}

// ── tests: query + path params ──────────────────────────────────────────────

test "query: coercion int/float/bool + parsing-failure codes" {
    const schema = [_]Rule{
        .{ .field = "n", .kind = .int, .required = true },
        .{ .field = "x", .kind = .float },
        .{ .field = "b", .kind = .bool },
    };
    var good = try validateQuery(testing.allocator, "n=42&x=3.5&b=true", &schema);
    defer good.deinit();
    try testing.expect(good.ok());

    var good2 = try validateQuery(testing.allocator, "n=-7&b=0", &schema);
    defer good2.deinit();
    try testing.expect(good2.ok());

    var bad = try validateQuery(testing.allocator, "n=abc&x=1e&b=yep", &schema);
    defer bad.deinit();
    try testing.expectEqual(@as(usize, 3), bad.errors.len);
    try expectError(&bad, "n", "int_parsing");
    try expectError(&bad, "x", "float_parsing");
    try expectError(&bad, "b", "bool_parsing");
}

test "query: constraints run on the coerced values" {
    const schema = [_]Rule{
        .{ .field = "limit", .kind = .int, .min = 1, .max = 100 },
        .{ .field = "sort", .kind = .string, .one_of = &.{ "asc", "desc" } },
        .{ .field = "q", .kind = .string, .required = true, .min_len = 2 },
    };
    var bad = try validateQuery(testing.allocator, "limit=500&sort=up", &schema);
    defer bad.deinit();
    try testing.expectEqual(@as(usize, 3), bad.errors.len);
    try expectError(&bad, "limit", "less_than_equal");
    try expectError(&bad, "sort", "enum");
    try expectError(&bad, "q", "missing");
}

test "query: percent-decoding, '+' → space, first duplicate wins, valueless key" {
    const schema = [_]Rule{
        .{ .field = "name", .kind = .string, .pattern = .{ .literal = "John Doe" } },
        .{ .field = "sym", .kind = .string, .pattern = .{ .literal = "a&b=c" } },
        .{ .field = "n", .kind = .int, .max = 1 },
        .{ .field = "flag", .kind = .string, .max_len = 0 },
    };
    // name: '+' decodes; sym: %26='&' %3D='='; n twice → first (1) wins;
    // flag has no '=' → value "".
    var r = try validateQuery(testing.allocator, "name=John+Doe&sym=a%26b%3Dc&n=1&n=9&flag", &schema);
    defer r.deinit();
    try testing.expect(r.ok());

    // Invalid escapes pass through literally (lenient).
    const lenient = [_]Rule{.{ .field = "v", .kind = .string, .pattern = .{ .literal = "%zz%4" } }};
    var l = try validateQuery(testing.allocator, "v=%zz%4", &lenient);
    defer l.deinit();
    try testing.expect(l.ok());
}

test "params: validateParams over router.Params (raw segments, coerce+check)" {
    var params: router.Params = .{};
    params.entries[0] = .{ .name = "id", .value = "42" };
    params.entries[1] = .{ .name = "slug", .value = "hello-world" };
    params.len = 2;

    const schema = [_]Rule{
        .{ .field = "id", .kind = .int, .required = true, .min = 1 },
        .{ .field = "slug", .kind = .string, .pattern = .{ .charset = "abcdefghijklmnopqrstuvwxyz-" } },
        .{ .field = "missing_one", .kind = .string, .required = true },
    };
    var r = try validateParams(testing.allocator, &params, &schema);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.errors.len);
    try expectError(&r, "missing_one", "missing");

    params.entries[0].value = "0";
    var low = try validateParams(testing.allocator, &params, &schema);
    defer low.deinit();
    try expectError(&low, "id", "greater_than_equal");
}

// ── tests: the typed style ──────────────────────────────────────────────────

const Color = enum { red, green, blue };

const Widget = struct {
    name: []const u8,
    qty: u8,
    price: ?f64 = null,
    color: Color = .red,
    tags: []const []const u8 = &.{},
    dims: Dims = .{},

    const Dims = struct {
        w: u32 = 1,
        h: u32 = 1,
    };

    pub const validate_rules: []const Rule = &.{
        .{ .field = "name", .kind = .string, .min_len = 1, .max_len = 32 },
    };
};

test "rulesFor: derived schema shape (required/defaults/bounds/enum/nesting)" {
    const schema = comptime rulesFor(Widget);
    try testing.expectEqual(@as(usize, 6), schema.len);

    try testing.expectEqualStrings("name", schema[0].field);
    try testing.expectEqual(Kind.string, schema[0].kind);
    try testing.expect(schema[0].required);

    try testing.expectEqual(Kind.int, schema[1].kind);
    try testing.expectEqual(@as(?f64, 0), schema[1].min);
    try testing.expectEqual(@as(?f64, 255), schema[1].max);

    try testing.expect(!schema[2].required); // has default
    try testing.expect(schema[2].allow_null); // optional
    try testing.expectEqual(Kind.float, schema[2].kind);

    try testing.expectEqual(Kind.string, schema[3].kind); // enum → string
    try testing.expectEqual(@as(usize, 3), schema[3].one_of.?.len);
    try testing.expectEqualStrings("red", schema[3].one_of.?[0]);

    try testing.expectEqual(Kind.array, schema[4].kind);
    try testing.expectEqual(Kind.string, schema[4].items.?.kind);

    try testing.expectEqual(Kind.object, schema[5].kind);
    try testing.expectEqual(@as(usize, 2), schema[5].fields.?.len);
}

test "parseInto: valid body → fully decoded T (nested, slice, enum, optional, defaults)" {
    var result = try parseInto(Widget, testing.allocator,
        \\{"name":"gear","qty":7,"price":9.5,"color":"blue","tags":["a","b"],"dims":{"w":2,"h":3}}
    );
    defer result.deinit();
    try testing.expect(result == .ok);
    const w = result.ok.value;
    try testing.expectEqualStrings("gear", w.name);
    try testing.expectEqual(@as(u8, 7), w.qty);
    try testing.expectEqual(@as(?f64, 9.5), w.price);
    try testing.expectEqual(Color.blue, w.color);
    try testing.expectEqual(@as(usize, 2), w.tags.len);
    try testing.expectEqualStrings("b", w.tags[1]);
    try testing.expectEqual(@as(u32, 2), w.dims.w);

    // Defaults fill; explicit null accepted for the optional.
    var minimal = try parseInto(Widget, testing.allocator,
        \\{"name":"n","qty":1,"price":null}
    );
    defer minimal.deinit();
    try testing.expect(minimal == .ok);
    try testing.expectEqual(Color.red, minimal.ok.value.color);
    try testing.expectEqual(@as(?f64, null), minimal.ok.value.price);
    try testing.expectEqual(@as(u32, 1), minimal.ok.value.dims.h);
}

test "parseInto: JSON type errors become pathed validation errors, aggregated" {
    var result = try parseInto(Widget, testing.allocator,
        \\{"name":5,"qty":"x","tags":[1],"dims":{"w":"wide"}}
    );
    defer result.deinit();
    try testing.expect(result == .invalid);
    const r = &result.invalid;
    try testing.expectEqual(@as(usize, 4), r.errors.len);
    try expectError(r, "name", "string_type");
    try expectError(r, "qty", "int_type");
    try expectError(r, "tags[0]", "string_type");
    try expectError(r, "dims.w", "int_type");
}

test "parseInto: missing required → missing; type-derived int bounds enforced" {
    var missing = try parseInto(Widget, testing.allocator, "{}");
    defer missing.deinit();
    try testing.expect(missing == .invalid);
    try expectError(&missing.invalid, "name", "missing");
    try expectError(&missing.invalid, "qty", "missing");

    // u8 → max 255 from the bit width.
    var big = try parseInto(Widget, testing.allocator,
        \\{"name":"n","qty":300}
    );
    defer big.deinit();
    try testing.expect(big == .invalid);
    try expectError(&big.invalid, "qty", "less_than_equal");
}

test "parseInto: enum field rejects unknown value with the one_of message" {
    var result = try parseInto(Widget, testing.allocator,
        \\{"name":"n","qty":1,"color":"mauve"}
    );
    defer result.deinit();
    try testing.expect(result == .invalid);
    try expectError(&result.invalid, "color", "enum");
    try testing.expectEqualStrings("Input should be one of: red, green, blue", result.invalid.errors[0].message);
}

test "parseInto: T.validate_rules constraints apply on top of the derived schema" {
    var result = try parseInto(Widget, testing.allocator,
        \\{"name":"","qty":1}
    );
    defer result.deinit();
    try testing.expect(result == .invalid);
    try expectError(&result.invalid, "name", "string_too_short");
}

test "parseInto: malformed JSON → json_invalid, unknown fields ignored" {
    var bad = try parseInto(Widget, testing.allocator, "{\"name\":");
    defer bad.deinit();
    try testing.expect(bad == .invalid);
    try expectError(&bad.invalid, "", "json_invalid");

    var extra = try parseInto(Widget, testing.allocator,
        \\{"name":"n","qty":1,"totally_unknown":123}
    );
    defer extra.deinit();
    try testing.expect(extra == .ok);
}

test "parseInto: 54+-bit int fields fall back to a defensive decode error, not a crash" {
    const Wide = struct { n: u64 };
    // Negative value: passes the schema (u64 keeps only min=0 → -1 < 0 caught)…
    var neg = try parseInto(Wide, testing.allocator, "{\"n\":-1}");
    defer neg.deinit();
    try testing.expect(neg == .invalid);
    try expectError(&neg.invalid, "n", "greater_than_equal");

    const WideSigned = struct { n: i64 };
    var ok = try parseInto(WideSigned, testing.allocator, "{\"n\":9007199254740993}");
    defer ok.deinit();
    try testing.expect(ok == .ok);
    try testing.expectEqual(@as(i64, 9007199254740993), ok.ok.value.n);
}

// ── tests: middleware, offline over http.Server.serveStream ─────────────────

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Drive a router through the socket-free server codec with canned wire
/// bytes; returns the full response byte stream (router test harness shape).
fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [1024]u8 = undefined;
    var response_body_buf: [1024]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null, // keep goldens free of Server/Date noise
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn postWire(comptime target: []const u8, comptime body: []const u8) []const u8 {
    return "POST " ++ target ++ " HTTP/1.1\r\nHost: t\r\n" ++
        "Content-Type: application/json\r\n" ++
        std.fmt.comptimePrint("Content-Length: {d}\r\n", .{body.len}) ++
        "Connection: close\r\n\r\n" ++ body;
}

fn getWire(comptime target: []const u8) []const u8 {
    return "GET " ++ target ++ " HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n";
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn bodyOf(got: []const u8) []const u8 {
    return got[std.mem.indexOf(u8, got, "\r\n\r\n").? + 4 ..];
}

/// Shared per-test probe, reachable from handlers via ctx.state.
const Probe = struct {
    invoked: bool = false,

    fn of(ctx: *router.Ctx) *Probe {
        return @ptrCast(@alignCast(ctx.state.?));
    }
};

const thing_schema = [_]Rule{
    .{ .field = "name", .kind = .string, .required = true, .min_len = 1 },
    .{ .field = "qty", .kind = .int, .required = true, .min = 1, .max = 100 },
};

fn hEchoBody(ctx: *router.Ctx) anyerror!void {
    Probe.of(ctx).invoked = true;
    const vb = bodyValue(ctx).?;
    // The validated document is directly usable — no re-checking.
    const name = vb.value.object.get("name").?.string;
    try ctx.res.writeAll("name=");
    try ctx.res.writeAll(name);
}

test "Body middleware: invalid POST → golden 400 JSON, handler NOT invoked" {
    var probe: Probe = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &probe;
    const body_mw: Body = .{ .gpa = testing.allocator, .schema = &thing_schema };
    try r.use(body_mw.middleware());
    try r.post("/things", hEchoBody);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, postWire("/things",
        \\{"qty":0}
    ), &buf);
    try testing.expectEqualStrings("HTTP/1.1 400 Bad Request\r\n" ++
        "Content-Type: application/json\r\n" ++
        "Connection: close\r\n" ++
        "Content-Length: 170\r\n" ++
        "\r\n" ++
        \\{"errors":[{"path":"name","code":"missing","message":"Field required"},{"path":"qty","code":"greater_than_equal","message":"Input should be greater than or equal to 1"}]}
    , got);
    try testing.expect(!probe.invoked);
}

test "Body middleware: valid POST → handler runs and reads the parsed body" {
    var probe: Probe = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &probe;
    const body_mw: Body = .{ .gpa = testing.allocator, .schema = &thing_schema };
    try r.use(body_mw.middleware());
    try r.post("/things", hEchoBody);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, postWire("/things",
        \\{"name":"gizmo","qty":5}
    ), &buf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings("name=gizmo", bodyOf(got));
    try testing.expect(probe.invoked);
}

test "Body middleware: malformed / empty body → 400 json_invalid, no panic" {
    var probe: Probe = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &probe;
    const body_mw: Body = .{ .gpa = testing.allocator, .schema = &thing_schema };
    try r.use(body_mw.middleware());
    try r.post("/things", hEchoBody);

    var buf: [2048]u8 = undefined;
    const garbled = runWire(&r, postWire("/things", "{\"name\":"), &buf);
    try expectStatus(garbled, "400");
    try testing.expect(std.mem.indexOf(u8, garbled, "\"code\":\"json_invalid\"") != null);
    try testing.expect(!probe.invoked);

    const empty = runWire(&r, postWire("/things", ""), &buf);
    try expectStatus(empty, "400");
    try testing.expect(std.mem.indexOf(u8, empty, "\"code\":\"json_invalid\"") != null);
    try testing.expect(!probe.invoked);
}

test "Body middleware: over-limit body → 413" {
    var probe: Probe = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &probe;
    const body_mw: Body = .{ .gpa = testing.allocator, .schema = &thing_schema, .max_body_bytes = 8 };
    try r.use(body_mw.middleware());
    try r.post("/things", hEchoBody);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, postWire("/things",
        \\{"name":"gizmo","qty":5}
    ), &buf);
    try expectStatus(got, "413");
    try testing.expect(std.mem.indexOf(u8, got, "\"code\":\"too_large\"") != null);
    try testing.expect(!probe.invoked);
}

test "Body middleware: structurally over-limit body → 400 too_deep, handler NOT invoked" {
    var probe: Probe = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &probe;
    const body_mw: Body = .{
        .gpa = testing.allocator,
        .schema = &thing_schema,
        .limits = .{ .max_depth = 3 },
    };
    try r.use(body_mw.middleware());
    try r.post("/things", hEchoBody);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, postWire("/things",
        \\{"a":{"b":{"c":{"d":1}}}}
    ), &buf);
    try expectStatus(got, "400");
    try testing.expect(std.mem.indexOf(u8, got, "\"code\":\"too_deep\"") != null);
    try testing.expect(!probe.invoked);
}

const contact_schema = [_]Rule{
    .{ .field = "email", .kind = .string, .required = true, .format = .email },
    .{ .field = "website", .kind = .string, .format = .uri },
};

fn hContact(ctx: *router.Ctx) anyerror!void {
    Probe.of(ctx).invoked = true;
    try ctx.res.writeAll("contact ok");
}

test "Body middleware: format failure → aggregated 400 with path + format code" {
    var probe: Probe = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &probe;
    const body_mw: Body = .{ .gpa = testing.allocator, .schema = &contact_schema };
    try r.use(body_mw.middleware());
    try r.post("/contacts", hContact);

    var buf: [2048]u8 = undefined;
    const bad = runWire(&r, postWire("/contacts",
        \\{"email":"nope","website":"not a uri"}
    ), &buf);
    try expectStatus(bad, "400");
    try testing.expectEqualStrings(
        \\{"errors":[{"path":"email","code":"format","message":"Input should be a valid email address"},{"path":"website","code":"format","message":"Input should be a valid URI"}]}
    , bodyOf(bad));
    try testing.expect(!probe.invoked);

    const good = runWire(&r, postWire("/contacts",
        \\{"email":"a@b.com","website":"https://example.com/x"}
    ), &buf);
    try expectStatus(good, "200");
    try testing.expectEqualStrings("contact ok", bodyOf(good));
    try testing.expect(probe.invoked);
}

const TypedThing = TypedBody(Widget);

fn hTypedThing(ctx: *router.Ctx) anyerror!void {
    Probe.of(ctx).invoked = true;
    const w = TypedThing.get(ctx).?;
    try ctx.res.writer().print("name={s} qty={d} color={s}", .{
        w.name, w.qty, @tagName(w.color),
    });
}

test "TypedBody middleware: valid POST → handler gets *const T; invalid → 400" {
    var probe: Probe = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &probe;
    const typed_mw: TypedThing = .{ .gpa = testing.allocator };
    try r.use(typed_mw.middleware());
    try r.post("/widgets", hTypedThing);

    var buf: [2048]u8 = undefined;
    const good = runWire(&r, postWire("/widgets",
        \\{"name":"gear","qty":7,"color":"blue"}
    ), &buf);
    try expectStatus(good, "200");
    try testing.expectEqualStrings("name=gear qty=7 color=blue", bodyOf(good));
    try testing.expect(probe.invoked);

    probe = .{};
    const bad = runWire(&r, postWire("/widgets",
        \\{"name":"gear","qty":"many"}
    ), &buf);
    try expectStatus(bad, "400");
    try testing.expect(std.mem.indexOf(u8, bad, "\"path\":\"qty\",\"code\":\"int_type\"") != null);
    try testing.expect(!probe.invoked);
}

const search_schema = [_]Rule{
    .{ .field = "q", .kind = .string, .required = true, .min_len = 2 },
    .{ .field = "limit", .kind = .int, .min = 1, .max = 100 },
};

fn hSearch(ctx: *router.Ctx) anyerror!void {
    Probe.of(ctx).invoked = true;
    const qv = queryValues(ctx).?;
    try ctx.res.writeAll("q=");
    try ctx.res.writeAll(qv.get("q").?);
}

test "Query middleware: bad param → 400; good → handler + decoded queryValues" {
    var probe: Probe = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &probe;
    const query_mw: Query = .{ .gpa = testing.allocator, .schema = &search_schema };
    try r.use(query_mw.middleware());
    try r.get("/search", hSearch);

    var buf: [2048]u8 = undefined;
    const bad = runWire(&r, getWire("/search?q=ab&limit=999"), &buf);
    try expectStatus(bad, "400");
    try testing.expect(std.mem.indexOf(u8, bad, "\"path\":\"limit\",\"code\":\"less_than_equal\"") != null);
    try testing.expect(!probe.invoked);

    const missing = runWire(&r, getWire("/search"), &buf);
    try expectStatus(missing, "400");
    try testing.expect(std.mem.indexOf(u8, missing, "\"path\":\"q\",\"code\":\"missing\"") != null);

    // '+' decodes to a space in the value the handler sees.
    const good = runWire(&r, getWire("/search?q=zig+libs&limit=5"), &buf);
    try expectStatus(good, "200");
    try testing.expectEqualStrings("q=zig libs", bodyOf(good));
    try testing.expect(probe.invoked);
}

const id_schema = [_]Rule{
    .{ .field = "id", .kind = .int, .required = true, .min = 1 },
};

fn hUserById(ctx: *router.Ctx) anyerror!void {
    Probe.of(ctx).invoked = true;
    try ctx.res.writeAll("user=");
    try ctx.res.writeAll(ctx.params.get("id").?);
}

test "PathParams middleware: bad path param → 400; good → handler runs" {
    var probe: Probe = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &probe;
    const params_mw: PathParams = .{ .gpa = testing.allocator, .schema = &id_schema };
    try r.use(params_mw.middleware());
    try r.get("/users/:id", hUserById);

    var buf: [2048]u8 = undefined;
    const bad = runWire(&r, getWire("/users/abc"), &buf);
    try expectStatus(bad, "400");
    try testing.expect(std.mem.indexOf(u8, bad, "\"path\":\"id\",\"code\":\"int_parsing\"") != null);
    try testing.expect(!probe.invoked);

    const good = runWire(&r, getWire("/users/42"), &buf);
    try expectStatus(good, "200");
    try testing.expectEqualStrings("user=42", bodyOf(good));
}

fn hBoth(ctx: *router.Ctx) anyerror!void {
    Probe.of(ctx).invoked = true;
    // Both slots resolve through the ctx.data chain.
    const vb = bodyValue(ctx).?;
    const qv = queryValues(ctx).?;
    try ctx.res.writer().print("q={s} name={s}", .{
        qv.get("q").?,
        vb.value.object.get("name").?.string,
    });
}

test "stacked Query + Body middleware: both getters work via the slot chain" {
    var probe: Probe = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &probe;
    const query_mw: Query = .{ .gpa = testing.allocator, .schema = &search_schema };
    const body_mw: Body = .{ .gpa = testing.allocator, .schema = &thing_schema };
    try r.use(query_mw.middleware());
    try r.use(body_mw.middleware());
    try r.post("/combo", hBoth);

    var buf: [2048]u8 = undefined;
    const got = runWire(&r, postWire("/combo?q=ok&limit=3",
        \\{"name":"n","qty":2}
    ), &buf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings("q=ok name=n", bodyOf(got));
    try testing.expect(probe.invoked);

    // A failing outer (query) short-circuits before the body is touched.
    probe = .{};
    const bad = runWire(&r, postWire("/combo?q=x",
        \\{"name":"n","qty":2}
    ), &buf);
    try expectStatus(bad, "400");
    try testing.expect(std.mem.indexOf(u8, bad, "string_too_short") != null);
    try testing.expect(!probe.invoked);
}

test "getters return null when no validate middleware ran" {
    var req: http.Server.Request = undefined;
    var res: http.Server.ResponseWriter = undefined;
    var ctx: router.Ctx = .{ .req = &req, .res = &res, .params = .{}, .state = null };
    try testing.expectEqual(@as(?*const ValidatedBody, null), bodyValue(&ctx));
    try testing.expectEqual(@as(?*const ValidatedQuery, null), queryValues(&ctx));
    try testing.expectEqual(@as(?*const Widget, null), TypedThing.get(&ctx));
}

// ── tests: in-process integration (router + http.Server + http.Client) ──────

fn serveWrap(s: *http.Server) void {
    s.serve() catch {};
}

test "integration: 400 on invalid body/query over a real socket; valid body reaches the handler" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var probe: Probe = .{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    r.state = &probe;

    const typed_mw: TypedThing = .{ .gpa = testing.allocator };
    const query_mw: Query = .{ .gpa = testing.allocator, .schema = &search_schema };
    const things = try r.group("/things");
    try things.use(typed_mw.middleware());
    try things.post("/create", hTypedThing);
    const search = try r.group("/search");
    try search.use(query_mw.middleware());
    try search.get("/run", hSearch);

    var server = http.Server.init(io, testing.allocator, .{
        .handler = r.handler(),
        .context = &r,
    });
    defer server.deinit();
    server.bind() catch |err| {
        std.debug.print("loopback bind failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    const thread = try std.Thread.spawn(.{}, serveWrap, .{&server});
    defer thread.join();
    defer server.shutdown();

    const port = server.boundAddress().getPort();
    var client = http.Client.init(io, testing.allocator, .{});
    defer client.deinit();
    var url_buf: [64]u8 = undefined;
    const json_hdr = [_]http.Header{.{ .name = "Content-Type", .value = "application/json" }};

    { // invalid body → 400 with the field-error JSON; handler not invoked
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/things/create", .{port});
        var res = try client.request(.post, url, .{
            .body =
            \\{"name":"gear","qty":"lots"}
            ,
            .headers = &json_hdr,
        });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 400), res.status);
        try testing.expectEqualStrings("application/json", res.header("content-type").?);
        const body = try res.readAllAlloc(testing.allocator, 4096);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings(
            \\{"errors":[{"path":"qty","code":"int_type","message":"Input should be a valid integer"}]}
        , body);
        try testing.expect(!probe.invoked);
    }

    { // valid body → handler runs and sees the decoded struct
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/things/create", .{port});
        var res = try client.request(.post, url, .{
            .body =
            \\{"name":"gear","qty":7,"color":"green"}
            ,
            .headers = &json_hdr,
        });
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, 4096);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("name=gear qty=7 color=green", body);
        try testing.expect(probe.invoked);
    }

    { // bad query param → 400; handler not invoked
        probe = .{};
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/search/run?q=zig&limit=0", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 400), res.status);
        const body = try res.readAllAlloc(testing.allocator, 4096);
        defer testing.allocator.free(body);
        try testing.expect(std.mem.indexOf(u8, body, "\"path\":\"limit\",\"code\":\"greater_than_equal\"") != null);
        try testing.expect(!probe.invoked);
    }

    { // good query → 200 through the middleware
        const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/search/run?q=zig&limit=10", .{port});
        var res = try client.request(.get, url, .{});
        defer res.deinit();
        try testing.expectEqual(@as(u16, 200), res.status);
        const body = try res.readAllAlloc(testing.allocator, 4096);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("q=zig", body);
        try testing.expect(probe.invoked);
    }
}
