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
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Request body/query/params validation → aggregated 400 (typed + schema + string-format checks) + JSON DoS caps (depth/array/field size)",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
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

/// Expected JSON type of a field.
///
/// `.any` skips the TYPE GATE and nothing else: whatever type arrives is
/// still held to the constraints the rule states — a string to `min_len`,
/// `format`, `one_of`, `pattern`; a number to `min`/`max`; an array to
/// `items`; an object to `fields`.
///
/// ⛔ It used to skip every constraint, and since it is the DEFAULT `kind`
/// that made a forgotten `.kind = .string` into a silent no-op: a rule
/// carrying `required`, `format`, `min_len`, `max_len`, `one_of` and
/// `pattern` returned `ok() == true` for input that violated all of them.
/// A validator that fails open by default is worse than no validator, because
/// someone is relying on it. Audit 2026-09-02.
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
/// `min_len`/`max_len` to strings (**Unicode code points**, pydantic's
/// contract) and arrays (items), `min_bytes`/`max_bytes` to a string's
/// ENCODED length, `one_of`, `pattern` and `format` to strings, `fields` to
/// objects, `items` to arrays.
///
/// ⚠ `kind = .any` does not switch the constraints off — see `Kind.any`.
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
    /// String length in Unicode code points (pydantic contract) / array
    /// length in items. Invalid UTF-8 fails closed (`string_unicode`).
    min_len: ?usize = null,
    max_len: ?usize = null,
    /// String length in BYTES, for the callers who mean bytes — a fixed-width
    /// buffer, a column width, a wire field.
    ///
    /// ⛔ It exists because the two are not interchangeable and the derived
    /// schema needs the byte one. `rulesFor(struct { fixed: [16]u8 })` used to
    /// emit `min_len = max_len = 16`, which after the code-point fix meant 16
    /// CHARACTERS while `std.json` still decodes 16 BYTES: `"éééééééé"` (16
    /// bytes, 8 code points) was rejected as too short although it decodes
    /// perfectly, and a 16-code-point/17-byte string passed the rule and then
    /// failed inside `parseFromValue` as an unpathed root `invalid`. Audit
    /// 2026-09-02.
    min_bytes: ?usize = null,
    max_bytes: ?usize = null,
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

    /// Serialize as an RFC 9457 `application/problem+json` body: `p`'s
    /// standard members plus an `errors` extension member carrying the same
    /// `[{path,code,message},…]` list `writeJson` writes.
    pub fn writeProblem(r: *const Report, w: *std.Io.Writer, p: http.problem.Problem) std.Io.Writer.Error!void {
        return writeErrorsProblem(r.errors, p, w);
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

/// The problem-details wire shape (RFC 9457), also usable standalone:
/// `{"type":…,"status":…,"title":…,…,"errors":[…]}`. Send it with
/// `Content-Type: http.problem.content_type` and the status in `p.status`.
/// Error paths and messages are valid UTF-8 whatever the input was: paths
/// come from the schema or from keys a JSON parser already validated, and
/// messages never quote the rejected value.
pub fn writeErrorsProblem(errors: []const Error, p: http.problem.Problem, w: *std.Io.Writer) std.Io.Writer.Error!void {
    return http.problem.write(w, p, .{ .errors = errors });
}

/// Hard cap on aggregated errors per `Report`. Bounds worst-case aggregation
/// work (see `dedupeFrom`) and keeps a maliciously huge failing body from
/// growing the error list — and the 400 response body — without limit.
const max_errors: usize = 1000;

/// Error accumulator: one arena for paths/messages/the list itself;
/// `finish` hands the arena to the Report, `abort` discards it.
const Builder = struct {
    arena: std.heap.ArenaAllocator,
    list: std.ArrayList(Error),
    /// Errors kept, at most: `max_errors`, or a caller's lower
    /// `Limits.max_errors`. Never 0 -- a builder that could keep nothing
    /// would report an invalid document as valid.
    cap: usize = max_errors,

    fn init(gpa: Allocator) Builder {
        return .{ .arena = std.heap.ArenaAllocator.init(gpa), .list = .empty };
    }

    fn initCapped(gpa: Allocator, cap: usize) Builder {
        var b = init(gpa);
        b.cap = @max(1, @min(cap, max_errors));
        return b;
    }

    fn a(b: *Builder) Allocator {
        return b.arena.allocator();
    }

    /// Append one error. A single `checkValue` pass over one schema never
    /// produces a duplicate (path, code) pair (each field/rule is visited
    /// once), so this does *not* dedupe — a per-append linear scan over the
    /// whole list made aggregation O(n^2) (reproduced: ~196ms ReleaseFast for
    /// a 10,000-element failing array). The one place a real duplicate can
    /// arise — the typed double-pass in `parseIntoLimited` (derived schema,
    /// then `T.validate_rules`, over the same document) — dedupes itself via
    /// `dedupeFrom` after the second pass, bounded by `max_errors` on both
    /// sides rather than by attacker-controlled input size.
    fn append(b: *Builder, path: []const u8, code: []const u8, message: []const u8) Allocator.Error!void {
        if (b.list.items.len >= b.cap) return;
        try b.list.append(b.a(), .{ .path = path, .code = code, .message = message });
    }

    /// Remove entries appended since `first_pass_len` that duplicate
    /// (path, code) with an entry from before it. Used only by the
    /// `parseIntoLimited` double-pass (derived schema + `T.validate_rules`)
    /// to restore "one error, not two" for a field failing the same way in
    /// both passes. Cost is O(first_pass_len * (list.items.len -
    /// first_pass_len)), both bounded by `max_errors`, so it stays cheap
    /// regardless of how large the failing input is.
    fn dedupeFrom(b: *Builder, first_pass_len: usize) void {
        if (first_pass_len == 0 or first_pass_len >= b.list.items.len) return;
        const prior = b.list.items[0..first_pass_len];
        var write = first_pass_len;
        for (b.list.items[first_pass_len..]) |e| {
            var dup = false;
            for (prior) |p| {
                if (std.mem.eql(u8, p.path, e.path) and std.mem.eql(u8, p.code, e.code)) {
                    dup = true;
                    break;
                }
            }
            if (!dup) {
                b.list.items[write] = e;
                write += 1;
            }
        }
        b.list.shrinkRetainingCapacity(write);
    }

    /// True once the error list is full: nothing more will be retained, so
    /// nothing more needs to be BUILT.
    fn full(b: *const Builder) bool {
        return b.list.items.len >= b.cap;
    }

    fn appendf(b: *Builder, path: []const u8, code: []const u8, comptime fmt: []const u8, args: anytype) Allocator.Error!void {
        // ⛔ The cap is checked BEFORE the message is formatted. It used to be
        // checked only inside `append`, so every error past the cap still
        // paid an `allocPrint` into the report arena and was then dropped on
        // the floor. Measured (audit 2026-09-02): a 996 KiB body of 340 000
        // nodes -- all of it inside the DEFAULT `Limits` -- built 339 000
        // formatted messages nobody could read and left an 18 802 KiB report
        // arena behind, for the 1000 errors it retained. `Builder.append`'s
        // own doc said the cap "bounds worst-case aggregation work"; it
        // bounded `dedupeFrom`.
        if (b.full()) return;
        try b.append(path, code, try std.fmt.allocPrint(b.a(), fmt, args));
    }

    fn fieldPath(b: *Builder, prefix: []const u8, field: []const u8) Allocator.Error![]const u8 {
        if (prefix.len == 0) return field; // borrows the schema's string
        return std.fmt.allocPrint(b.a(), "{s}.{s}", .{ prefix, field });
    }

    fn indexPath(b: *Builder, prefix: []const u8, i: usize) Allocator.Error![]const u8 {
        // Same reasoning as `appendf`: once the list is full this path can
        // only ever be discarded, and it was being allocated for EVERY array
        // element regardless of outcome -- 2 829 KiB of arena for a *valid*
        // 1015 KiB body. The empty path is safe here because a full builder
        // appends nothing that could carry it.
        if (b.full()) return "";
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
    var b = Builder.initCapped(gpa, limits.max_errors);
    errdefer b.abort();
    try checkValue(&b, "", parsed.value, schema);
    return b.finish();
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
    /// Errors kept per report, at most; the rest are not built at all. Only
    /// lowers the module's own hard cap of 1000, and 0 counts as 1 (an
    /// invalid document always carries at least one error). A caller that
    /// holds the report in a fixed buffer sizes it with this: aggregating
    /// 1000 errors costs more memory than most bodies do.
    max_errors: usize = max_errors,
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

    // ⛔ `.any` constrains the VALUE, not nothing. It is the DEFAULT `kind`,
    // and it used to skip every constraint on the rule -- so a rule that
    // forgot `.kind = .string` silently became a no-op: `format`, `min_len`,
    // `max_len`, `one_of` and `pattern` all present, `ok() == true` on input
    // that violates every one of them, with no comptime or runtime signal.
    // Fail-open by default is the worst shape a validator can have.
    //
    // `.any` now means "any TYPE is acceptable"; whatever type does arrive is
    // held to the constraints the rule states. A rule with no constraints is
    // unaffected, which is what `.any` was for. Audit 2026-09-02.
    const effective: Kind = if (rule.kind != .any) rule.kind else switch (v) {
        .string => .string,
        .integer, .number_string => .int,
        .float => .float,
        .array => .array,
        .object => .object,
        .bool, .null => .bool,
    };

    switch (effective) {
        .int, .float => {
            if (numValue(v)) |n| {
                if (rule.min) |m| if (n < m)
                    try b.appendf(path, "greater_than_equal", "Input should be greater than or equal to {d}", .{m});
                if (rule.max) |m| if (n > m)
                    try b.appendf(path, "less_than_equal", "Input should be less than or equal to {d}", .{m});
            } else {
                // A value that survived the type gate but whose numeric text
                // cannot be parsed fails CLOSED — never silently treated as 0.
                try appendTypeError(b, path, rule.kind);
            }
        },
        .string => {
            const s = v.string;
            // Length constraints count Unicode code points, not bytes — the
            // pydantic contract (Python `len(str)` is code points, and the
            // module doc advertises "string chars"). Invalid/truncated UTF-8
            // fails closed with `string_unicode` rather than being silently
            // measured in bytes.
            if (rule.min_len != null or rule.max_len != null) {
                if (std.unicode.utf8CountCodepoints(s)) |count| {
                    if (rule.min_len) |m| if (count < m)
                        try b.appendf(path, "string_too_short", "String should have at least {d} characters", .{m});
                    if (rule.max_len) |m| if (count > m)
                        try b.appendf(path, "string_too_long", "String should have at most {d} characters", .{m});
                } else |_| {
                    try b.append(path, "string_unicode", "Input should be a valid string, unable to parse as unicode");
                }
            }
            if (rule.min_bytes) |m| if (s.len < m)
                try b.appendf(path, "string_bytes_too_short", "String should have at least {d} bytes", .{m});
            if (rule.max_bytes) |m| if (s.len > m)
                try b.appendf(path, "string_bytes_too_long", "String should have at most {d} bytes", .{m});
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

/// Numeric value for bounds checks. Returns `null` when the value has no
/// parseable numeric meaning — an unparseable `.number_string` — so the caller
/// can fail closed instead of silently substituting 0. Well-formed but
/// out-of-range number strings still saturate to ±inf, which orders correctly
/// against finite bounds.
fn numValue(v: Value) ?f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
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
/// `duration` cites): `P` + date components and/or `T` + time components, or
/// the exclusive week form `P<n>W`. The grammar is not just "increasing
/// order" — each section (`dur-year = N "Y" [dur-month]`, `dur-month = N "M"
/// [dur-day]`; `dur-hour = N "H" [dur-minute]`, `dur-minute = N "M"
/// [dur-second]`) only ever permits the immediately NEXT unit, so a
/// component may START at any position (`Y`, `M`, or `D` alone are each a
/// valid `dur-date`) but once started, subsequent components must be
/// contiguous with no gaps: `P1Y2D` (year + day, no month) and `PT1H2S`
/// (hour + second, no minute) are both invalid, not merely "out of order".
fn isDuration(s: []const u8) bool {
    if (s.len < 3 or s[0] != 'P') return false;
    const body = s[1..];
    if (body[body.len - 1] == 'W') return allDigits(body[0 .. body.len - 1]);
    var i: usize = 0;
    var in_time = false;
    // The unit index the NEXT component must land on, or null if this
    // section (date/time) hasn't seen a component yet (any starting unit is
    // allowed once, per the grammar's YM D / HMS chain each being optional).
    var next: ?usize = null;
    var any = false;
    while (i < body.len) {
        if (!in_time and body[i] == 'T') {
            in_time = true;
            next = null;
            i += 1;
            if (i == body.len) return false; // bare trailing 'T'
            continue;
        }
        const start = i;
        while (i < body.len and std.ascii.isDigit(body[i])) i += 1;
        if (i == start or i == body.len) return false; // need digits + unit
        const units: []const u8 = if (in_time) "HMS" else "YMD";
        const pos = std.mem.indexOfScalar(u8, units, body[i]) orelse return false;
        if (next) |want| {
            if (pos != want) return false; // gap or repeat: not the immediate next unit
        }
        next = pos + 1;
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

/// Validate the path params of a matched route. Values are the raw path
/// segments (the router matches byte-for-byte, no percent-decoding — its
/// documented policy), coerced per the rule's kind like `validateQuery`.
///
/// `params` is any name → value lookup: a value or pointer whose
/// `get(name: []const u8) ?[]const u8` returns the segment bound to `name`
/// — `*const router.Params`, or a server's own params type that does not
/// come from `router` at all.
pub fn validateParams(gpa: Allocator, params: anytype, schema: []const Rule) Allocator.Error!Report {
    comptime assertLookup(@TypeOf(params));
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

/// Compile error unless `P` (or what it points to) has
/// `get([]const u8) ?[]const u8` — says what is missing instead of failing
/// deep inside `validateParams`.
fn assertLookup(comptime P: type) void {
    const T = switch (@typeInfo(P)) {
        .pointer => |ptr| ptr.child,
        else => P,
    };
    const ok = switch (@typeInfo(T)) {
        .@"struct", .@"union", .@"enum", .@"opaque" => @hasDecl(T, "get") and
            @TypeOf(T.get(undefined, undefined)) == ?[]const u8,
        else => false,
    };
    if (!ok) @compileError("validateParams: " ++ @typeName(P) ++
        " is not a param lookup -- it needs `get(name: []const u8) ?[]const u8`");
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
                    // BYTES, not code points: `std.json` fills these `ai.len`
                    // bytes, so a code-point bound rejects strings that decode
                    // and accepts strings that do not. See `Rule.min_bytes`.
                    return .{ .field = "", .kind = .string, .min_bytes = ai.len, .max_bytes = ai.len };
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

    // Scoped so the builder's `errdefer` ends with it: on the success path
    // the builder is aborted here, and an `errdefer` still armed below would
    // free its arena a SECOND time when the decode that follows runs out of
    // memory -- a double free, found by a sizing probe on a
    // FixedBufferAllocator (2026-09-22), whose `free` asserts ownership.
    {
        var b = Builder.initCapped(gpa, limits.max_errors);
        errdefer b.abort();
        try checkValue(&b, "", parsed.value, schema);
        if (@hasDecl(T, "validate_rules")) {
            const first_pass_len = b.list.items.len;
            try checkValue(&b, "", parsed.value, T.validate_rules);
            b.dedupeFrom(first_pass_len);
        }
        if (b.list.items.len != 0) return .{ .invalid = b.finish() };
        b.abort();
    }

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

// ── the streaming path: no value tree ───────────────────────────────────────
//
// `parseIntoLimited` / `validateJsonLimited` build the whole document as a
// `std.json.Value` tree and then walk it. That tree is what their memory is:
// measured 2026-09-22, the smallest FixedBufferAllocator `parseIntoLimited`
// completes in is 4.4 KiB for a 118-byte body, 47 KiB for 1.1 KiB and 955 KiB
// for 16.5 KiB (peak live bytes on a heap: 4.3 / 31 / 449 KiB) -- 30-60x the
// body, which rules out a server that decodes into a fixed per-request buffer.
//
// The streaming path validates straight off the `std.json.Scanner` tokens:
//
//  * a scalar becomes a one-node `Value` and goes through the SAME `checkRule`
//    as the tree path, so the type gate, every constraint and every message
//    are shared, not re-implemented;
//  * containers are walked in place: object members are matched to rules by
//    key, array items by position; `required` is settled at the object's end
//    and `min_len`/`max_len` at the array's end;
//  * a container whose rule carries `custom` is the one exception -- the
//    predicate takes a `Value`, so that subtree (and only it) is materialized
//    and handed to `checkRule` whole;
//  * error paths are a chain of stack frames, rendered into the report only
//    when an error is recorded -- a valid document allocates no path at all;
//  * duplicate object keys are refused at every depth, known field or not,
//    exactly as the tree parser refuses them (`DuplicateField` → json_invalid).
//
// What differs from the tree path, by design: errors come in DOCUMENT order
// (the tree path reports in schema order), and when more than `max_errors`
// are found a different subset may be kept. The set of errors is the same --
// a differential fuzz target pins that.

/// Outcome of `parseIntoLeaky`.
pub fn LeakyResult(comptime T: type) type {
    return union(enum) {
        /// Decoded and valid. Lives in the allocator passed in; its strings
        /// may point into `body` (they do whenever the JSON string had no
        /// escapes), so `body` must outlive it too.
        ok: T,
        /// Owns its memory like any Report (`deinit`).
        invalid: Report,
    };
}

/// `parseIntoLimited` without the value tree: the same rules (`rulesFor(T)`
/// plus `T.validate_rules`), the same error codes and messages, validated in
/// one streaming pass, then decoded by `std.json.parseFromSliceLeaky` with
/// strings borrowed from `body`. Memory is of the order of the body, not a
/// multiple of it, so `arena` can be a fixed per-request buffer. Pass an
/// arena-like allocator: the decoded `T` is never freed piecemeal (the
/// `Leaky` convention of `std.json`). Errors come in document order.
pub fn parseIntoLeaky(comptime T: type, arena: Allocator, body: []const u8, limits: Limits) Allocator.Error!LeakyResult(T) {
    const extra: []const Rule = if (@hasDecl(T, "validate_rules")) T.validate_rules else &.{};
    {
        var report = try streamValidate(arena, body, comptime rulesFor(T), extra, limits);
        if (!report.ok()) return .{ .invalid = report };
        report.deinit();
    }
    const value = std.json.parseFromSliceLeaky(T, arena, body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_if_needed,
        .max_value_len = body.len,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        // Defensive, as in `parseIntoLimited`: valid against the schema, yet
        // the decode refused (a 64-bit integer past what f64 bounds express).
        else => {
            var db = Builder.init(arena);
            errdefer db.abort();
            try db.appendf("", "invalid", "Input could not be decoded: {s}", .{@errorName(err)});
            return .{ .invalid = db.finish() };
        },
    };
    return .{ .ok = value };
}

/// `validateJsonLimited` without the value tree (see `parseIntoLeaky`). Any
/// allocator; every temporary is freed before return, and the Report owns
/// what it keeps. Errors come in document order.
pub fn validateJsonStreaming(gpa: Allocator, body: []const u8, schema: []const Rule, limits: Limits) Allocator.Error!Report {
    return streamValidate(gpa, body, schema, &.{}, limits);
}

/// Validate `body` against `schema` and, as a second rule set over the same
/// document, `extra` (a typed `T.validate_rules`), deduplicating the second
/// set's (path, code) pairs against the first -- the `parseIntoLimited`
/// double-pass, done in one walk.
fn streamValidate(gpa: Allocator, body: []const u8, schema: []const Rule, extra: []const Rule, limits: Limits) Allocator.Error!Report {
    if (try jsonLimitError(gpa, body, limits)) |e| return singleErrorReport(gpa, e);

    // No `errdefer` over the builder: the json_invalid branch below aborts it
    // and then allocates again, and an armed errdefer would free it twice on
    // that allocation's failure (the bug fixed in `parseIntoLimited`).
    var b = Builder.initCapped(gpa, limits.max_errors);
    const bad_json = walkDocument(&b, gpa, body, schema, extra) catch |err| {
        b.abort();
        return err;
    };
    if (bad_json) |err| {
        b.abort();
        return jsonInvalidReport(gpa, err);
    }
    return b.finish();
}

/// Walk the whole document into `b`. Returns the error a tree parse would
/// have failed with (syntax, truncation, duplicate key) -- the caller turns
/// it into json_invalid and drops whatever validation errors were found --
/// or null. Only `OutOfMemory` propagates.
fn walkDocument(b: *Builder, gpa: Allocator, body: []const u8, schema: []const Rule, extra: []const Rule) Allocator.Error!?anyerror {
    var s: Stream = .{
        .scanner = std.json.Scanner.initCompleteInput(gpa, body),
        .gpa = gpa,
        .body_len = body.len,
        .b = b,
    };
    defer s.deinit();

    // The document root is held to an implicit `.object` rule per rule set,
    // which is `checkValue`'s root behaviour: a non-object root is one
    // `object_type` error at path "".
    const roots = [2]Rule{
        .{ .field = "", .kind = .object, .fields = schema },
        .{ .field = "", .kind = .object, .fields = extra },
    };
    const actives = [2]Active{ .{ .rule = &roots[0], .pass = 0 }, .{ .rule = &roots[1], .pass = 1 } };
    const active: []const Active = if (extra.len == 0) actives[0..1] else actives[0..2];

    // A non-OOM error here is the document's, not ours: it is the VALUE this
    // function returns, hence the `@as` -- a bare `return err` would raise it.
    s.walkValue(null, active) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return @as(?anyerror, err),
    };
    const last = s.scanner.next() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return @as(?anyerror, err),
    };
    if (last != .end_of_document) return @as(?anyerror, error.SyntaxError);

    // Merge the second rule set's errors after the first's, minus the pairs
    // the first already reported.
    s.use(0);
    const first_len = b.list.items.len;
    for (s.other.items) |e| {
        if (b.full()) break;
        try b.list.append(b.a(), e);
    }
    b.dedupeFrom(first_len);
    return null;
}

/// One rule applying to the value being walked, and which rule set it came
/// from (0 = the schema, 1 = `T.validate_rules`).
const Active = struct { rule: *const Rule, pass: u1 };

/// A node's place in the document, as a chain up to the root. Rendered to the
/// report's path syntax ("a.b", "a[2].c") only when an error needs it.
const Seg = struct {
    parent: ?*Seg,
    /// A rule's `field` string (schema memory, so a rendered path may borrow
    /// it), or unused for an array item.
    field: []const u8 = "",
    index: usize = 0,
    is_index: bool = false,
    rendered: ?[]const u8 = null,
};

const Stream = struct {
    scanner: std.json.Scanner,
    gpa: Allocator,
    body_len: usize,
    b: *Builder,
    /// The list of the rule set NOT currently in `b.list` (see `use`).
    other: std.ArrayList(Error) = .empty,
    current: u1 = 0,
    /// Keys of every object currently open, innermost last -- the duplicate
    /// check. `owned` keys were unescaped into `gpa` and are freed when their
    /// object closes.
    keys: std.ArrayList(Key) = .empty,

    const Key = struct { name: []const u8, owned: bool };

    const WalkError = std.json.Scanner.AllocError || error{ DuplicateField, BufferUnderrun };

    fn deinit(s: *Stream) void {
        s.freeKeysFrom(0);
        s.keys.deinit(s.gpa);
        s.scanner.deinit();
    }

    fn freeKeysFrom(s: *Stream, mark: usize) void {
        var i = s.keys.items.len;
        while (i > mark) {
            i -= 1;
            const k = s.keys.items[i];
            if (k.owned) s.gpa.free(k.name);
        }
        s.keys.shrinkRetainingCapacity(mark);
    }

    /// Point `b.list` at rule set `pass`'s error list. Both lists allocate
    /// from `b`'s arena, so either can end up in the Report.
    fn use(s: *Stream, pass: u1) void {
        if (s.current == pass) return;
        std.mem.swap(std.ArrayList(Error), &s.b.list, &s.other);
        s.current = pass;
    }

    fn path(s: *Stream, seg: ?*Seg) Allocator.Error![]const u8 {
        const node = seg orelse return "";
        if (node.rendered) |r| return r;
        const r = if (node.parent) |p| blk: {
            const prefix = try s.path(p);
            break :blk if (node.is_index)
                try std.fmt.allocPrint(s.b.a(), "{s}[{d}]", .{ prefix, node.index })
            else if (prefix.len == 0)
                node.field
            else
                try std.fmt.allocPrint(s.b.a(), "{s}.{s}", .{ prefix, node.field });
        } else if (node.is_index)
            try std.fmt.allocPrint(s.b.a(), "[{d}]", .{node.index})
        else
            node.field;
        node.rendered = r;
        return r;
    }

    /// Run `checkRule` for a value it can see whole. The path is rendered
    /// only if the rule reported something: `checkRule` is given a
    /// placeholder, and the entries it appended are repointed afterwards.
    /// A container's rule recurses with its path, so it gets the real one.
    fn check(s: *Stream, seg: ?*Seg, v: Value, a: Active) Allocator.Error!void {
        s.use(a.pass);
        if (s.b.full()) return;
        if (v == .array or v == .object) return checkRule(s.b, try s.path(seg), v, a.rule);
        const mark = s.b.list.items.len;
        try checkRule(s.b, "", v, a.rule);
        if (s.b.list.items.len == mark) return;
        const p = try s.path(seg);
        for (s.b.list.items[mark..]) |*e| e.path = p;
    }

    fn walkValue(s: *Stream, seg: ?*Seg, active: []const Active) WalkError!void {
        switch (try s.scanner.peekNextTokenType()) {
            .object_begin, .array_begin => {
                for (active) |a| if (a.rule.custom != null) return s.materialize(seg, active);
                if (try s.scanner.peekNextTokenType() == .object_begin)
                    return s.walkObject(seg, active);
                return s.walkArray(seg, active);
            },
            else => return s.walkScalar(seg, active),
        }
    }

    fn walkScalar(s: *Stream, seg: ?*Seg, active: []const Active) WalkError!void {
        const token = try s.scanner.nextAllocMax(s.gpa, .alloc_if_needed, s.body_len);
        var owned: ?[]const u8 = null;
        defer if (owned) |o| s.gpa.free(o);
        const v: Value = switch (token) {
            .string => |str| .{ .string = str },
            .allocated_string => |str| blk: {
                owned = str;
                break :blk .{ .string = str };
            },
            .number => |n| Value.parseFromNumberSlice(n),
            .allocated_number => |n| blk: {
                owned = n;
                break :blk Value.parseFromNumberSlice(n);
            },
            .true => .{ .bool = true },
            .false => .{ .bool = false },
            .null => .null,
            else => unreachable, // peeked: not a container, not an end
        };
        for (active) |a| try s.check(seg, v, a);
    }

    /// A subtree some rule needs as a `Value` (its `custom` predicate): parse
    /// just that subtree and let the tree path check it.
    fn materialize(s: *Stream, seg: ?*Seg, active: []const Active) WalkError!void {
        var arena = std.heap.ArenaAllocator.init(s.gpa);
        defer arena.deinit();
        const v = std.json.Value.jsonParse(arena.allocator(), &s.scanner, .{
            .max_value_len = s.body_len,
            .allocate = .alloc_always,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.DuplicateField => return error.DuplicateField,
            error.SyntaxError => return error.SyntaxError,
            error.UnexpectedEndOfInput => return error.UnexpectedEndOfInput,
            error.ValueTooLong => return error.ValueTooLong,
            else => return error.SyntaxError, // type-directed errors: unreachable for Value
        };
        for (active) |a| try s.check(seg, v, a);
    }

    /// The container type gate of `checkRule`, for rule `a` and a container
    /// of `kind` (.array / .object): true when the rule's constraints apply.
    fn gate(s: *Stream, seg: ?*Seg, a: Active, kind: Kind) Allocator.Error!bool {
        if (a.rule.kind == .any or a.rule.kind == kind) return true;
        s.use(a.pass);
        if (!s.b.full()) try appendTypeError(s.b, try s.path(seg), a.rule.kind);
        return false;
    }

    fn walkObject(s: *Stream, seg: ?*Seg, active: []const Active) WalkError!void {
        _ = try s.scanner.next(); // .object_begin

        var fallback = std.heap.stackFallback(256, s.gpa);
        const scratch = fallback.get();

        // One entry per rule that passed the gate and has fields to match.
        const Fields = struct { rules: []const Rule, pass: u1, seen: []bool };
        var sets: std.ArrayList(Fields) = .empty;
        defer {
            for (sets.items) |f| scratch.free(f.seen);
            sets.deinit(scratch);
        }
        for (active) |a| {
            if (!try s.gate(seg, a, .object)) continue;
            const rules = a.rule.fields orelse continue;
            const seen = try scratch.alloc(bool, rules.len);
            @memset(seen, false);
            sets.append(scratch, .{ .rules = rules, .pass = a.pass, .seen = seen }) catch |err| {
                scratch.free(seen);
                return err;
            };
        }

        const mark = s.keys.items.len;
        defer s.freeKeysFrom(mark);
        var children: std.ArrayList(Active) = .empty;
        defer children.deinit(scratch);

        while (true) {
            const token = try s.scanner.nextAllocMax(s.gpa, .alloc_if_needed, s.body_len);
            const key: Key = switch (token) {
                .object_end => break,
                .string => |k| .{ .name = k, .owned = false },
                .allocated_string => |k| .{ .name = k, .owned = true },
                else => unreachable, // the scanner only yields a key here
            };
            s.keys.append(s.gpa, key) catch |err| {
                if (key.owned) s.gpa.free(key.name);
                return err;
            };
            var duplicate = false;
            for (s.keys.items[mark .. s.keys.items.len - 1]) |k| {
                if (std.mem.eql(u8, k.name, key.name)) duplicate = true;
            }

            children.clearRetainingCapacity();
            var child: Seg = .{ .parent = seg };
            for (sets.items) |set| {
                for (set.rules, set.seen) |*r, *seen| {
                    if (!std.mem.eql(u8, r.field, key.name)) continue;
                    seen.* = true;
                    child.field = r.field;
                    try children.append(scratch, .{ .rule = r, .pass = set.pass });
                }
            }
            try s.walkValue(&child, children.items);
            // Reported after the value, as the tree parser does: an error
            // inside the duplicate's value wins over the duplicate itself.
            if (duplicate) return error.DuplicateField;
        }

        for (sets.items) |set| {
            for (set.rules, set.seen) |r, seen| {
                if (seen or !r.required) continue;
                s.use(set.pass);
                if (s.b.full()) continue;
                var missing: Seg = .{ .parent = seg, .field = r.field };
                try s.b.append(try s.path(&missing), "missing", "Field required");
            }
        }
    }

    fn walkArray(s: *Stream, seg: ?*Seg, active: []const Active) WalkError!void {
        _ = try s.scanner.next(); // .array_begin

        var fallback = std.heap.stackFallback(128, s.gpa);
        const scratch = fallback.get();
        var gated: std.ArrayList(Active) = .empty;
        defer gated.deinit(scratch);
        var items: std.ArrayList(Active) = .empty;
        defer items.deinit(scratch);
        for (active) |a| {
            if (!try s.gate(seg, a, .array)) continue;
            try gated.append(scratch, a);
            if (a.rule.items) |r| try items.append(scratch, .{ .rule = r, .pass = a.pass });
        }

        var count: usize = 0;
        while (try s.scanner.peekNextTokenType() != .array_end) : (count += 1) {
            var child: Seg = .{ .parent = seg, .index = count, .is_index = true };
            try s.walkValue(&child, items.items);
        }
        _ = try s.scanner.next(); // .array_end

        for (gated.items) |a| {
            s.use(a.pass);
            if (s.b.full()) continue;
            if (a.rule.min_len) |m| if (count < m)
                try s.b.appendf(try s.path(seg), "too_short", "Array should have at least {d} items", .{m});
            if (a.rule.max_len) |m| if (count > m)
                try s.b.appendf(try s.path(seg), "too_long", "Array should have at most {d} items", .{m});
        }
    }
};

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
        // `router` F6 (A1/router.md): `ctx.params` is already `*const
        // router.Params` now, not a value -- no `&` needed (that used to
        // take `&Params`, now it would take `*const *const Params`).
        var report = try validateParams(v.gpa, ctx.params, v.schema);
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

test "length: string constraints count code points, not bytes (pydantic)" {
    const schema = [_]Rule{
        .{ .field = "s", .kind = .string, .min_len = 4, .max_len = 4 },
    };
    // "café" = 4 code points but 5 UTF-8 bytes (é = 0xC3 0xA9). Byte counting
    // would flag string_too_long; code-point counting accepts it.
    var ok_cp = try validateJson(testing.allocator, "{\"s\":\"café\"}", &schema);
    defer ok_cp.deinit();
    try testing.expect(ok_cp.ok());

    // A 3-code-point multibyte string is below min_len = 4 → string_too_short,
    // even though its byte length (>4) would sneak past a byte comparison.
    var short = try validateJson(testing.allocator, "{\"s\":\"háj\"}", &schema);
    defer short.deinit();
    try expectError(&short, "s", "string_too_short");
}

test "length: invalid UTF-8 under a length rule fails closed (string_unicode)" {
    const schema = [_]Rule{
        .{ .field = "s", .kind = .string, .max_len = 100 },
    };
    // Build a Value with an invalid UTF-8 string directly (JSON parsing would
    // reject such bytes). Fail-closed: no silent byte-length pass.
    var obj: std.json.ObjectMap = .empty;
    defer obj.deinit(testing.allocator);
    try obj.put(testing.allocator, "s", .{ .string = "\xff\xfe\xff" });
    var rep = try validateValue(testing.allocator, .{ .object = obj }, &schema);
    defer rep.deinit();
    try expectError(&rep, "s", "string_unicode");
}

test "numeric: unparseable number_string fails closed, never silently 0" {
    const schema = [_]Rule{
        .{ .field = "x", .kind = .float, .min = -1000, .max = 1000 },
    };
    // A garbage number_string that passes the float type gate but cannot be
    // parsed used to fall back to 0.0 (inside [-1000, 1000]) and pass. It must
    // now produce a validation error instead.
    var obj: std.json.ObjectMap = .empty;
    defer obj.deinit(testing.allocator);
    try obj.put(testing.allocator, "x", .{ .number_string = "not-a-number" });
    var bad = try validateValue(testing.allocator, .{ .object = obj }, &schema);
    defer bad.deinit();
    try testing.expect(!bad.ok());
    try expectError(&bad, "x", "float_type");

    // A well-formed number_string still validates normally (regression guard).
    var obj2: std.json.ObjectMap = .empty;
    defer obj2.deinit(testing.allocator);
    try obj2.put(testing.allocator, "x", .{ .number_string = "42.5" });
    var good = try validateValue(testing.allocator, .{ .object = obj2 }, &schema);
    defer good.deinit();
    try testing.expect(good.ok());
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

test "pattern: charset stops at the FIRST bad byte — one error, not one per bad byte" {
    // The single-bad-char case above ("c0ffee!") can't distinguish a codec
    // that breaks on the first violation from one that keeps scanning and
    // appends once per violating byte — both produce exactly one error when
    // there is only one bad byte. A string with several bytes outside the
    // set is the only way to tell them apart.
    const schema = [_]Rule{
        .{ .field = "hex", .kind = .string, .pattern = .{ .charset = "0123456789abcdef" } },
    };
    var r = try validateJson(testing.allocator,
        \\{"hex":"c0!ffee!!"}
    , &schema);
    defer r.deinit();
    try testing.expectEqual(@as(usize, 1), r.errors.len);
    try expectError(&r, "hex", "string_pattern_mismatch");
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

test "Builder.dedupeFrom: only a matching (path, code) PAIR is a duplicate" {
    // A second-pass entry that shares only the path (not the code) with a
    // first-pass entry, or only the code (not the path), is a genuinely
    // distinct error and must survive. Testing this only through
    // `parseIntoLimited`'s two real schema passes made it hard to force a
    // partial-match case on purpose, so this drives `dedupeFrom` directly.
    var b = Builder.init(testing.allocator);
    defer b.abort();
    try b.append("a", "code1", "first-pass entry on a");
    try b.append("b", "code2", "first-pass entry on b");
    const first_pass_len = b.list.items.len;
    try testing.expectEqual(@as(usize, 2), first_pass_len);

    // Second pass: same path as the first entry, but a different code —
    // NOT a duplicate of it.
    try b.append("a", "code2", "second-pass entry on a, different code");
    // Second pass: same code as the second entry, but a different path —
    // NOT a duplicate of it either.
    try b.append("c", "code2", "second-pass entry on c, same code as b");
    // Second pass: an exact (path, code) repeat of the first entry — THIS
    // one is the real duplicate `dedupeFrom` exists to remove.
    try b.append("a", "code1", "second-pass exact repeat of the first entry");

    b.dedupeFrom(first_pass_len);

    try testing.expectEqual(@as(usize, 4), b.list.items.len);
    try testing.expectEqualStrings("a", b.list.items[0].path);
    try testing.expectEqualStrings("code1", b.list.items[0].code);
    try testing.expectEqualStrings("b", b.list.items[1].path);
    try testing.expectEqualStrings("code2", b.list.items[1].code);
    try testing.expectEqualStrings("a", b.list.items[2].path);
    try testing.expectEqualStrings("code2", b.list.items[2].code);
    try testing.expectEqualStrings("c", b.list.items[3].path);
    try testing.expectEqualStrings("code2", b.list.items[3].code);
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

test "params: validateParams over a lookup that is not router.Params" {
    // A server with its own params type (no `router` in its API) — anything
    // with `get(name) ?[]const u8`, by value or by pointer.
    const Pairs = struct {
        names: []const []const u8,
        values: []const []const u8,
        fn get(p: @This(), name: []const u8) ?[]const u8 {
            for (p.names, p.values) |n, v| if (std.mem.eql(u8, n, name)) return v;
            return null;
        }
    };
    const pairs: Pairs = .{ .names = &.{ "id", "tag" }, .values = &.{ "x7", "ok" } };
    const schema = [_]Rule{
        .{ .field = "id", .kind = .int, .required = true },
        .{ .field = "tag", .kind = .string, .one_of = &.{ "ok", "no" } },
        .{ .field = "absent", .kind = .string, .required = true },
    };
    inline for (.{ pairs, &pairs }) |lookup| {
        var r = try validateParams(testing.allocator, lookup, &schema);
        defer r.deinit();
        try testing.expectEqual(@as(usize, 2), r.errors.len);
        try expectError(&r, "id", "int_parsing");
        try expectError(&r, "absent", "missing");
    }
}

test "every allocation failure point: no leak, no double free" {
    // `checkAllAllocationFailures` fails each allocation in turn; the testing
    // allocator reports a leak or a double free on any of those paths.
    const T = struct {
        name: []const u8,
        age: u8,
        tags: []const []const u8 = &.{},
        pub const validate_rules: []const Rule = &.{.{ .field = "name", .kind = .string, .min_len = 2 }};
    };
    const bodies = [_][]const u8{
        \\{"name":"Ada","age":36,"tags":["a","b"]}
        , // valid: fails inside the decode after validation passed
        \\{"name":"A","age":"x","tags":[1]}
        , // invalid: fails while aggregating errors
        \\{"name":
        , // malformed
    };
    const schema = [_]Rule{
        .{ .field = "name", .kind = .string, .required = true, .min_len = 2 },
        .{ .field = "age", .kind = .int, .min = 0 },
        .{ .field = "tags", .kind = .array, .max_len = 4 },
    };
    const S = struct {
        fn parse(gpa: Allocator, body: []const u8) !void {
            var r = try parseIntoLimited(T, gpa, body, .{});
            r.deinit();
        }
        fn json(gpa: Allocator, body: []const u8, rules: []const Rule) !void {
            var r = try validateJsonLimited(gpa, body, rules, .{});
            r.deinit();
        }
        fn query(gpa: Allocator, q: []const u8, rules: []const Rule) !void {
            var r = try validateQuery(gpa, q, rules);
            r.deinit();
        }
    };
    for (bodies) |body| {
        try testing.checkAllAllocationFailures(testing.allocator, S.parse, .{body});
        try testing.checkAllAllocationFailures(testing.allocator, S.json, .{ body, @as([]const Rule, &schema) });
    }
    const qschema = [_]Rule{
        .{ .field = "name", .kind = .string, .required = true, .min_len = 2 },
        .{ .field = "age", .kind = .int },
    };
    try testing.checkAllAllocationFailures(testing.allocator, S.query, .{ "name=a%20b&age=x", @as([]const Rule, &qschema) });
}

// ── tests: the streaming path agrees with the tree path ────────────────────

fn lessError(_: void, x: Error, y: Error) bool {
    return switch (std.mem.order(u8, x.path, y.path)) {
        .lt => true,
        .gt => false,
        .eq => switch (std.mem.order(u8, x.code, y.code)) {
            .lt => true,
            .gt => false,
            .eq => std.mem.lessThan(u8, x.message, y.message),
        },
    };
}

/// Same errors, order aside (the streaming path reports in document order).
fn expectSameErrors(want: []const Error, got: []const Error) !void {
    const a = try testing.allocator.dupe(Error, want);
    defer testing.allocator.free(a);
    const b = try testing.allocator.dupe(Error, got);
    defer testing.allocator.free(b);
    std.mem.sort(Error, a, {}, lessError);
    std.mem.sort(Error, b, {}, lessError);
    if (a.len != b.len) {
        std.debug.print("\ntree: {d} errors, stream: {d}\n", .{ a.len, b.len });
        for (a) |e| std.debug.print("  tree   {s} {s} {s}\n", .{ e.path, e.code, e.message });
        for (b) |e| std.debug.print("  stream {s} {s} {s}\n", .{ e.path, e.code, e.message });
        return error.TestExpectedEqual;
    }
    for (a, b) |x, y| {
        try testing.expectEqualStrings(x.path, y.path);
        try testing.expectEqualStrings(x.code, y.code);
        try testing.expectEqualStrings(x.message, y.message);
    }
}

/// Run both runtime-schema paths on `body` and require the same outcome.
fn expectSchemaAgrees(body: []const u8, schema: []const Rule) !void {
    var tree = try validateJson(testing.allocator, body, schema);
    defer tree.deinit();
    var stream = try validateJsonStreaming(testing.allocator, body, schema, .{});
    defer stream.deinit();
    try expectSameErrors(tree.errors, stream.errors);
}

/// Run both typed paths on `body` and require the same outcome: the same
/// errors, or equal decoded values.
fn expectTypedAgrees(comptime T: type, body: []const u8) !void {
    var tree = try parseIntoLimited(T, testing.allocator, body, .{});
    defer tree.deinit();
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var stream = try parseIntoLeaky(T, arena.allocator(), body, .{});
    switch (tree) {
        .ok => |parsed| {
            if (stream != .ok) {
                std.debug.print("\ntree ok, stream invalid:\n", .{});
                for (stream.invalid.errors) |e| std.debug.print("  {s} {s} {s}\n", .{ e.path, e.code, e.message });
                return error.TestExpectedEqual;
            }
            try testing.expectEqualDeep(parsed.value, stream.ok);
        },
        .invalid => |r| {
            if (stream != .invalid) {
                std.debug.print("\ntree invalid ({d} errors), stream ok\n", .{r.errors.len});
                return error.TestExpectedEqual;
            }
            defer stream.invalid.deinit();
            try expectSameErrors(r.errors, stream.invalid.errors);
        },
    }
}

const StreamAddr = struct { street: []const u8, city: []const u8, zip: ?[5]u8 = null };
const StreamColor = enum { red, green, blue };
const StreamUser = struct {
    name: []const u8,
    age: u8,
    score: f64 = 0,
    admin: bool = false,
    color: StreamColor = .red,
    tags: []const []const u8 = &.{},
    address: ?StreamAddr = null,
    history: []const StreamAddr = &.{},
    big: i64 = 0,

    fn noSpaces(_: ?*anyopaque, v: Value) bool {
        return v != .string or std.mem.indexOfScalar(u8, v.string, ' ') == null;
    }
    fn fewerThanThree(_: ?*anyopaque, v: Value) bool {
        return v != .array or v.array.items.len < 3;
    }
    pub const validate_rules: []const Rule = &.{
        .{ .field = "name", .kind = .string, .min_len = 2, .custom = .{ .check = noSpaces, .code = "no_spaces", .message = "No spaces" } },
        // The same field, the same failure as the derived rule: deduplicated.
        .{ .field = "age", .kind = .int, .max = 150 },
        // `custom` on a container: this subtree is materialized.
        .{ .field = "history", .kind = .array, .custom = .{ .check = fewerThanThree, .code = "too_much_history", .message = "At most two" } },
        .{ .field = "address", .kind = .object, .allow_null = true, .fields = &.{
            .{ .field = "city", .kind = .string, .one_of = &.{ "Praha", "Brno" } },
        } },
    };
};

test "streaming: typed decode agrees with parseIntoLimited" {
    const bodies = [_][]const u8{
        \\{"name":"Ada","age":36}
        ,
        \\{"name":"Ada","age":36,"score":1,"admin":true,"color":"blue","tags":["a","b\"c"],"address":{"street":"S","city":"Brno","zip":"12345"},"history":[{"street":"x","city":"Praha"}],"big":9007199254740993,"extra":{"deep":[1,{"k":null}]}}
        ,
        // Escapes everywhere: in keys, in values, in unknown fields.
        \\{"n\u0061me":"\u0041da","age":1,"x\n":"\ud83d\ude00"}
        ,
        // Every kind wrong.
        \\{"name":1,"age":"x","score":"s","admin":0,"color":"pink","tags":[1,[]],"address":[],"history":{},"big":1.5}
        ,
        // Bounds: u8 overflow, float for an int, an integral float.
        \\{"name":"Ada","age":256}
        ,
        \\{"name":"Ada","age":36.0}
        ,
        \\{"name":"Ada","age":-1}
        ,
        // Missing required fields, at the root and nested.
        \\{}
        ,
        \\{"name":"Ada","age":1,"address":{"street":"s"}}
        ,
        \\{"name":"Ada","age":1,"history":[{"city":"Praha"},{"street":"x"}]}
        ,
        // validate_rules: custom on a scalar, custom on a container, nested one_of.
        \\{"name":"A B","age":1}
        ,
        \\{"name":"Ada","age":1,"history":[{"street":"a","city":"b"},{"street":"a","city":"b"},{"street":"a","city":"b"}]}
        ,
        \\{"name":"Ada","age":1,"address":{"street":"s","city":"Ostrava"}}
        ,
        \\{"name":"Ada","age":1,"address":null}
        ,
        // Fixed-size byte array: bytes, not code points.
        \\{"name":"Ada","age":1,"address":{"street":"s","city":"Brno","zip":"1234"}}
        ,
        \\{"name":"Ada","age":1,"address":{"street":"s","city":"Brno","zip":"éé1"}}
        ,
        // Huge numbers: number_string on the tree side.
        \\{"name":"Ada","age":1,"big":123456789012345678901234567890}
        ,
        \\{"name":"Ada","age":1,"score":1e400}
        ,
        // Not an object at the root.
        \\[1,2]
        ,
        \\null
        ,
        \\"x"
        ,
        // Malformed: json_invalid, whatever validation found first.
        "",
        \\{"name":1,
        ,
        \\{"name":"Ada","age":1}x
        ,
        \\{"age":"x","name":}
        ,
        // Duplicate keys: known, unknown, nested, escaped, and one whose
        // value is itself malformed (the syntax error wins, as in a tree parse).
        \\{"name":"Ada","age":1,"name":"Bob"}
        ,
        \\{"name":"Ada","age":1,"u":1,"u":2}
        ,
        \\{"name":"Ada","age":1,"extra":{"a":{"b":1,"b":2}}}
        ,
        \\{"name":"Ada","age":1,"a":1,"\u0061":2}
        ,
        \\{"name":"Ada","age":1,"d":1,"d":[1,}
        ,
        // Duplicate inside a materialized subtree.
        \\{"name":"Ada","age":1,"history":[{"street":"a","city":"b","city":"c"}]}
        ,
    };
    for (bodies) |body| {
        expectTypedAgrees(StreamUser, body) catch |err| {
            std.debug.print("body: {s}\n", .{body});
            return err;
        };
    }
}

test "streaming: runtime schema agrees with validateJson" {
    const schema = [_]Rule{
        .{ .field = "a", .kind = .any, .min_len = 2, .max = 3, .format = .email },
        .{ .field = "b", .kind = .array, .min_len = 1, .max_len = 2, .items = &.{ .field = "", .kind = .object, .fields = &.{
            .{ .field = "c", .kind = .int, .required = true },
        } } },
        .{ .field = "d", .kind = .object, .required = true, .fields = &.{
            .{ .field = "e", .kind = .any, .fields = &.{.{ .field = "f", .kind = .bool, .required = true }} },
        } },
        // Two rules for one field: both apply.
        .{ .field = "g", .kind = .string, .pattern = .{ .prefix = "x" } },
        .{ .field = "g", .kind = .string, .max_len = 2 },
        .{ .field = "h", .kind = .float, .allow_null = true, .min = 0 },
    };
    const bodies = [_][]const u8{
        \\{"d":{}}
        ,
        \\{"a":"x","b":[],"d":{"e":{}},"g":"yyy","h":null}
        ,
        \\{"a":5,"b":[{"c":1},{"c":"2"},{}],"d":{"e":{"f":1}},"g":"x","h":-1}
        ,
        \\{"a":[1],"b":{},"d":[],"g":1,"h":"1"}
        ,
        \\{"a":{"x":1},"d":{"e":[1,2]}}
        ,
        \\{"a":null,"b":null,"d":null}
        ,
        \\{"a":"bad@","d":{"e":"s"},"b":[{"c":1.5},{"c":1e2}]}
        ,
    };
    for (bodies) |body| {
        expectSchemaAgrees(body, &schema) catch |err| {
            std.debug.print("body: {s}\n", .{body});
            return err;
        };
    }
}

test "streaming: a valid document allocates no error path, and decodes into a body-sized buffer" {
    // The measurement that motivated the streaming path, pinned: a 16.5 KiB
    // body of 1500 strings decoded into a FixedBufferAllocator of 3x its size.
    // The tree path needs 955 KiB for the same body.
    const T = struct { name: []const u8, tags: []const []const u8 };
    var body_buf: [20000]u8 = undefined;
    var w: std.Io.Writer = .fixed(&body_buf);
    try w.writeAll("{\"name\":\"n\",\"tags\":[");
    for (0..1500) |i| try w.print("{s}\"tag-{d:0>4}\"", .{ if (i == 0) "" else ",", i });
    try w.writeAll("]}");
    const body = w.buffered();

    const mem = try testing.allocator.alloc(u8, 3 * body.len);
    defer testing.allocator.free(mem);
    var fba: std.heap.FixedBufferAllocator = .init(mem);
    const r = try parseIntoLeaky(T, fba.allocator(), body, .{});
    try testing.expect(r == .ok);
    try testing.expectEqual(@as(usize, 1500), r.ok.tags.len);
    try testing.expectEqualStrings("tag-1499", r.ok.tags[1499]);
    // Unescaped strings are borrowed from the body, not copied.
    try testing.expect(@intFromPtr(r.ok.name.ptr) >= @intFromPtr(body.ptr) and
        @intFromPtr(r.ok.name.ptr) < @intFromPtr(body.ptr) + body.len);
}

test "Limits.max_errors lowers the cap on every limited path, and never to zero" {
    const schema = [_]Rule{.{ .field = "a", .kind = .array, .items = &.{ .field = "", .kind = .string } }};
    const body = "{\"a\":[1,2,3,4,5,6,7,8,9,10]}";
    var tree = try validateJsonLimited(testing.allocator, body, &schema, .{ .max_errors = 3 });
    defer tree.deinit();
    try testing.expectEqual(@as(usize, 3), tree.errors.len);
    var stream = try validateJsonStreaming(testing.allocator, body, &schema, .{ .max_errors = 3 });
    defer stream.deinit();
    try testing.expectEqual(@as(usize, 3), stream.errors.len);
    const T = struct { a: []const []const u8 };
    var typed = try parseIntoLimited(T, testing.allocator, body, .{ .max_errors = 2 });
    defer typed.deinit();
    try testing.expectEqual(@as(usize, 2), typed.invalid.errors.len);
    // 0 is 1: an invalid document is never reported valid.
    var zero = try validateJsonStreaming(testing.allocator, body, &schema, .{ .max_errors = 0 });
    defer zero.deinit();
    try testing.expectEqual(@as(usize, 1), zero.errors.len);
    // Above the module's own cap: the module's cap.
    var many = try validateJsonLimited(testing.allocator, "{\"a\":[" ++ "1," ** 1200 ++ "1]}", &schema, .{ .max_errors = 5000 });
    defer many.deinit();
    try testing.expectEqual(max_errors, many.errors.len);
}

test "streaming: every allocation failure point, no leak, no double free" {
    const S = struct {
        fn stream(gpa: Allocator, body: []const u8) !void {
            var r = try validateJsonStreaming(gpa, body, &fuzz_schema, .{});
            r.deinit();
        }
        fn typed(gpa: Allocator, body: []const u8) !void {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            var r = try parseIntoLeaky(StreamUser, arena.allocator(), body, .{});
            if (r == .invalid) r.invalid.deinit();
        }
    };
    const bodies = [_][]const u8{
        \\{"name":"ok","age":1,"tags":["a","b"],"meta":{"id":1,"active":true},"x\u0041":{"k":[1,"\u00e9"]}}
        ,
        \\{"name":7,"age":"x","tags":[1,2,3,4,5,6],"meta":{"active":1}}
        ,
        \\{"name":"A B","age":300,"history":[{"street":"a","city":"b"},{},{}],"address":{"city":"x"}}
        ,
        \\{"name":"a","name":"b"}
        ,
        \\{"name":
        ,
    };
    for (bodies) |body| {
        try testing.checkAllAllocationFailures(testing.allocator, S.stream, .{body});
        try testing.checkAllAllocationFailures(testing.allocator, S.typed, .{body});
    }
}

test "writeProblem: RFC 9457 body carrying the aggregated errors" {
    var r = try validateJson(testing.allocator, "{\"age\":\"x\"}", &.{
        .{ .field = "age", .kind = .int },
        .{ .field = "name", .kind = .string, .required = true },
    });
    defer r.deinit();
    var buf: [512]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try r.writeProblem(&w, .{ .status = 422 });
    try testing.expectEqualStrings(
        \\{"type":"about:blank","status":422,"title":"Unprocessable Content","errors":[{"path":"age","code":"int_type","message":"Input should be a valid integer"},{"path":"name","code":"missing","message":"Field required"}]}
    , w.buffered());

    // Same `errors` array as the plain 400 shape.
    var plain_buf: [512]u8 = undefined;
    var plain: std.Io.Writer = .fixed(&plain_buf);
    try r.writeJson(&plain);
    const list = plain.buffered()["{\"errors\":".len .. plain.buffered().len - 1];
    try testing.expect(std.mem.indexOf(u8, w.buffered(), list) != null);
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

fn nowNsMonotonic() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

test "aggregation: a 10,000-element failing array completes fast and is capped at max_errors" {
    // Reproduces the audit's O(n^2) scenario: a body that complies with the
    // default structural limits (array elements <= Limits.max_array_elements
    // == 10_000) but fails a per-element rule, so every element produces a
    // distinct-path error. Before the fix, `Builder.append`'s per-append
    // linear dedupe scan made aggregating N such errors O(n^2) (~196ms
    // ReleaseFast at N=10,000). This locks in that the error list no longer
    // grows unbounded (capped at `max_errors`) and that building the report
    // completes without the quadratic blowup.
    const schema = [_]Rule{
        .{ .field = "items", .kind = .array, .items = &.{ .field = "", .kind = .string, .min_len = 1 } },
    };

    const n = 10_000;
    var body: std.ArrayList(u8) = try .initCapacity(testing.allocator, n * 3 + 16);
    defer body.deinit(testing.allocator);
    try body.appendSlice(testing.allocator, "{\"items\":[");
    for (0..n) |i| {
        if (i != 0) try body.append(testing.allocator, ',');
        try body.appendSlice(testing.allocator, "\"\"");
    }
    try body.appendSlice(testing.allocator, "]}");

    const start_ns = nowNsMonotonic();
    var r = try validateJson(testing.allocator, body.items, &schema);
    defer r.deinit();
    const elapsed_ns = nowNsMonotonic() -| start_ns;

    // Every element is "" and fails min_len=1, so the pre-fix code would
    // have produced 10,000 distinct errors via an O(n^2) dedupe scan; the
    // fix caps aggregation at `max_errors` regardless of input size.
    try testing.expectEqual(max_errors, r.errors.len);
    try expectError(&r, "items[0]", "string_too_short");

    // Generous linear-time bound: the reproduced quadratic path took
    // ~196ms in ReleaseFast at this size (and much longer in Debug); a
    // linear/capped pass is expected to be well under a second even in
    // Debug. This is a loose regression trip-wire, not a tight benchmark.
    try testing.expect(elapsed_ns < 5 * std.time.ns_per_s);
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
    // `router` F6 (A1/router.md): `Ctx.params` is now `*const router.Params`,
    // not a value -- needs an addressable local.
    var empty_params: router.Params = .{};
    var ctx: router.Ctx = .{ .req = &req, .res = &res, .params = &empty_params, .state = null };
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

// ── fuzz: validateJson / validateFormat never panic on arbitrary input ────
//
// This module is the edge gate for request bodies/query/path params — every
// byte `validateJson` sees is an untrusted client-supplied body, and every
// string `validateFormat` checks is a client-supplied field value (email/
// URI/UUID/hostname/date/…). Two harnesses:
//
//  1. `validateJson` against a FIXED schema that exercises string/int/array/
//     object/format/pattern/nested-object/nested-array rules all at once —
//     the schema stays constant so only the body varies, and the body is
//     either raw random bytes (rejects at `json_invalid`, the cheap half) or
//     built from a small set of JSON skeletons whose shape matches the
//     schema (object with the right keys) but whose values are randomized —
//     this is what actually reaches the per-kind/format/pattern/nested
//     validators instead of bailing out at the parse step.
//  2. `validateFormat` over every `Format` value with both raw random
//     strings and near-miss structured strings (containing the separators
//     each format's validator looks for: `@`, `.`, `:`, `-`), so the deeper
//     per-character validators in each format run, not just the trivial
//     empty/too-long rejections.

const fuzz_schema = [_]Rule{
    .{ .field = "name", .kind = .string, .required = true, .min_len = 1, .max_len = 32 },
    .{ .field = "age", .kind = .int, .min = 0, .max = 150 },
    .{ .field = "email", .kind = .string, .format = .email },
    .{ .field = "code", .kind = .string, .pattern = .{ .prefix = "ID-" } },
    .{ .field = "tags", .kind = .array, .min_len = 0, .max_len = 5, .items = &.{ .field = "", .kind = .string } },
    .{ .field = "meta", .kind = .object, .fields = &.{
        .{ .field = "id", .kind = .int, .required = true },
        .{ .field = "active", .kind = .bool },
    } },
};

const fuzzseed = @import("testkit").fuzz;

// ⛔ Neither of these two targets had a corpus, so outside `--fuzz` the runner
// gave each ONE input: `in = ""`. Every draw then returned its minimum.
// `fuzzValidateJson`'s opening `smith.value(bool)` was false, every per-field
// `smith.value(bool)` was false too, and the body it built was `"{}"` — so
// the type gate, the format and pattern checks, the min_len/max_len bounds and
// the nested object/array walk, which the comment above lists as the whole
// reason the shape generator exists, had never run once. `fuzzValidateFormat`
// was worse: `smith.value(Format)` gave `.email` for ever and the string was
// empty, so **eleven of the twelve formats had never been called at all**.
// Measured 2026-09-07: 1 body, 1 format, 0 non-empty strings.

const json_buf_len = 512;
const format_buf_len = 128;

/// Octet 0 selects: `0x00` means the rest of the seed IS the body, verbatim;
/// anything else means the rest is a script assembling an object from the
/// schema's own field names.
const json_seeds = [_][]const u8{
    fuzzseed.seed("\x00" ++ "{}"), // the empty object: what this target ran for ever
    fuzzseed.seed("\x00" ++ "{\"name\":\"ok\",\"meta\":{\"id\":1}}"), // ⭐ the minimum that satisfies both required rules
    fuzzseed.seed("\x00" ++ "{\"name\":\"ok\",\"age\":42,\"email\":\"a@b.co\",\"code\":\"ID-7\",\"tags\":[\"x\"],\"meta\":{\"id\":1,\"active\":true}}"), // ⭐ every rule satisfied
    fuzzseed.seed("\x00" ++ "{\"name\":\"\",\"meta\":{\"id\":1}}"), // ⭐ `min_len` 1 violated by the empty string
    fuzzseed.seed("\x00" ++ "{\"name\":\"" ++ "x" ** 40 ++ "\",\"meta\":{\"id\":1}}"), // `max_len` 32 exceeded
    fuzzseed.seed("\x00" ++ "{\"name\":\"ok\",\"age\":151,\"meta\":{\"id\":1}}"), // ⭐ `max` 150 exceeded by one
    fuzzseed.seed("\x00" ++ "{\"name\":\"ok\",\"age\":-1,\"meta\":{\"id\":1}}"), // `min` 0 violated
    fuzzseed.seed("\x00" ++ "{\"name\":\"ok\",\"email\":\"not-an-email\",\"meta\":{\"id\":1}}"), // ⭐ the `.email` format check
    fuzzseed.seed("\x00" ++ "{\"name\":\"ok\",\"code\":\"XX-7\",\"meta\":{\"id\":1}}"), // ⭐ the `ID-` prefix pattern
    fuzzseed.seed("\x00" ++ "{\"name\":\"ok\",\"tags\":[\"a\",\"b\",\"c\",\"d\",\"e\",\"f\"],\"meta\":{\"id\":1}}"), // the array `max_len` of 5
    fuzzseed.seed("\x00" ++ "{\"name\":\"ok\",\"tags\":[1,2],\"meta\":{\"id\":1}}"), // ⭐ items of the wrong kind inside the array
    fuzzseed.seed("\x00" ++ "{\"name\":\"ok\",\"meta\":{\"active\":true}}"), // the nested required `id` missing
    fuzzseed.seed("\x00" ++ "{\"name\":123,\"meta\":{\"id\":\"x\"}}"), // both kinds wrong: the type gate at two depths
    fuzzseed.seed("\x00" ++ "[1,2,3]"), // JSON, but not an object
    fuzzseed.seed("\x00" ++ "{not json"), // not JSON at all
    fuzzseed.seed("\x00"), // the empty body
    fuzzseed.seed("\x01" ++ "\x3f\x01\x00\x02\x03\x04\x05"), // script: all six fields, one value kind each
    fuzzseed.seed("\x01" ++ "\x21\x01\x05"), // script: `name` and `meta` only, with the nested-object value
};

/// Octet 0 picks the `Format`, octet 1 picks arbitrary vs near-miss, the rest
/// is the string.
const format_seeds = [_][]const u8{
    fuzzseed.seed("\x00\x00" ++ "user@example.com"), // ⭐ email, valid
    fuzzseed.seed("\x00\x00" ++ "user@@example.com"), // email, two at-signs
    fuzzseed.seed("\x00\x00" ++ "@example.com"), // email with an empty local part
    fuzzseed.seed("\x01\x00" ++ "https://example.com/a?b=c#d"), // ⭐ uri
    fuzzseed.seed("\x02\x00" ++ "/a/b?c"), // uri_reference
    fuzzseed.seed("\x03\x00" ++ "f81d4fae-7dec-11d0-a765-00a0c91e6bf6"), // ⭐ uuid
    fuzzseed.seed("\x03\x00" ++ "f81d4fae7dec11d0a76500a0c91e6bf6"), // uuid without its dashes
    fuzzseed.seed("\x04\x00" ++ "192.168.0.1"), // ⭐ ipv4
    fuzzseed.seed("\x04\x00" ++ "256.1.1.1"), // ipv4 with an octet out of range
    fuzzseed.seed("\x05\x00" ++ "2001:db8::1"), // ⭐ ipv6
    fuzzseed.seed("\x06\x00" ++ "host.example.com"), // hostname
    fuzzseed.seed("\x07\x00" ++ "2026-09-07"), // ⭐ date
    fuzzseed.seed("\x07\x00" ++ "2026-02-30"), // a date that does not exist
    fuzzseed.seed("\x08\x00" ++ "23:59:60Z"), // ⭐ time, with a leap second
    fuzzseed.seed("\x09\x00" ++ "2026-09-07T12:00:00Z"), // ⭐ date_time
    fuzzseed.seed("\x0a\x00" ++ "P3Y6M4DT12H30M5S"), // ⭐ duration
    fuzzseed.seed("\x0b\x00" ++ "/foo/0/a~1b~0c"), // ⭐ json_pointer with both escapes
    fuzzseed.seed("\x0b\x00" ++ "/foo/~2"), // an escape that does not exist
    fuzzseed.seed("\x00\x01" ++ "\x01\x02\x03\x04\x05"), // near-miss alphabet, email
    fuzzseed.seed("\x05\x01" ++ "\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11"), // near-miss alphabet, ipv6
    fuzzseed.seed("\x0b\x01" ++ "\x11\x12\x13"), // near-miss alphabet, json_pointer
    fuzzseed.seed(""), // the empty seed: `.email` and the empty string, which is what this target ran
};

test "fuzz: validateJson never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzValidateJson, .{ .corpus = &json_seeds });
}

/// Turn a drawn seed into a request body. Shared with the corpus guard so the
/// guard measures the same bodies the harness builds.
fn buildJsonBody(seed: []const u8, buf: []u8) []const u8 {
    if (seed.len == 0) return buf[0..0];
    if (seed[0] == 0) {
        const body = seed[1..];
        const n = @min(body.len, buf.len);
        @memcpy(buf[0..n], body[0..n]);
        return buf[0..n];
    }
    // Shape-matching skeleton: an object with (some of) the schema's keys,
    // varied-typed values, so the field-level validators (type gate, format,
    // pattern, min_len/max_len, nested object/array) run instead of
    // json_invalid. Octet 1 of the script is a bitmask over the six fields;
    // one octet per included field then picks its value kind.
    var script: fuzzseed.Cursor = .{ .bytes = seed[1..] };
    const present = script.byte();
    var w: std.Io.Writer = .fixed(buf);
    w.writeByte('{') catch return buf[0..0];
    const fields = [_][]const u8{ "name", "age", "email", "code", "tags", "meta" };
    var first = true;
    for (fields, 0..) |f, i| {
        if (present & (@as(u8, 1) << @intCast(i)) == 0) continue;
        if (!first) w.writeByte(',') catch return w.buffered();
        first = false;
        w.print("\"{s}\":", .{f}) catch return w.buffered();
        switch (script.ranged(0, 5)) {
            0 => w.print("{d}", .{@as(i32, @bitCast((@as(u32, script.word()) << 16) | @as(u32, script.word())))}) catch return w.buffered(),
            1 => {
                const n = script.ranged(0, 24);
                w.writeByte('"') catch return w.buffered();
                var j: u32 = 0;
                while (j < n) : (j += 1) {
                    // Keep it valid-ish JSON string content (skip the two
                    // bytes that would need escaping); this is a shape
                    // generator, not a JSON-string fuzzer.
                    const c = script.byte();
                    if (c == '"' or c == '\\') continue;
                    w.writeByte(c) catch return w.buffered();
                }
                w.writeByte('"') catch return w.buffered();
            },
            2 => w.writeAll(if (script.byte() & 1 == 1) "true" else "false") catch return w.buffered(),
            3 => w.writeAll("null") catch return w.buffered(),
            4 => {
                w.writeByte('[') catch return w.buffered();
                const n_items = script.ranged(0, 4);
                var k: u32 = 0;
                while (k < n_items) : (k += 1) {
                    if (k != 0) w.writeByte(',') catch return w.buffered();
                    w.print("\"t{d}\"", .{script.byte()}) catch return w.buffered();
                }
                w.writeByte(']') catch return w.buffered();
            },
            else => w.writeAll("{\"id\":1,\"active\":true}") catch return w.buffered(),
        }
    }
    w.writeByte('}') catch return w.buffered();
    return w.buffered();
}

fn fuzzValidateJson(_: void, smith: *std.testing.Smith) !void {
    // ⚠ ONE byte-first draw. See the note above the corpus for what the
    // `smith.value(bool)` chain did with no corpus at all.
    var raw: [1 + json_buf_len]u8 = undefined;
    const n: usize = smith.slice(&raw);
    var buf: [json_buf_len]u8 = undefined;
    const body = buildJsonBody(raw[0..n], &buf);

    var r = validateJson(testing.allocator, body, &fuzz_schema) catch return;
    defer r.deinit();
}

/// The fuzz schema as a typed struct, carrying the schema itself as
/// `validate_rules` -- so the typed differential also runs the second rule set
/// and its deduplication on every input.
const FuzzTyped = struct {
    name: []const u8,
    age: ?i32 = null,
    email: ?[]const u8 = null,
    code: []const u8 = "",
    tags: []const []const u8 = &.{},
    meta: ?struct { id: i64, active: bool = false } = null,
    pub const validate_rules: []const Rule = &fuzz_schema;
};

test "fuzz: the streaming path agrees with the tree path" {
    try testing.fuzz({}, fuzzStreamingAgrees, .{ .corpus = &json_seeds });
}

fn fuzzStreamingAgrees(_: void, smith: *std.testing.Smith) !void {
    var raw: [1 + json_buf_len]u8 = undefined;
    const n: usize = smith.slice(&raw);
    var buf: [json_buf_len]u8 = undefined;
    const body = buildJsonBody(raw[0..n], &buf);
    try expectSchemaAgrees(body, &fuzz_schema);
    try expectTypedAgrees(FuzzTyped, body);
}

test "corpus: every body reaches validateJson, and the violations reported are pinned" {
    // ⭐ Acceptance is the wrong number twice over: `{}` is refused (two
    // required rules), and a body that satisfies every rule is refused by
    // nothing — so a corpus stuck on either extreme reads as a clean pass.
    // What is pinned is the total number of VIOLATIONS reported, which counts
    // how many distinct rules the corpus actually reached.
    var nonempty: usize = 0;
    var octets: usize = 0;
    var valid: usize = 0;
    var violations: usize = 0;
    for (json_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [1 + json_buf_len]u8 = undefined;
        const n: usize = smith.slice(&raw);
        var buf: [json_buf_len]u8 = undefined;
        const body = buildJsonBody(raw[0..n], &buf);
        if (body.len != 0) nonempty += 1;
        octets += body.len;
        var r = validateJson(testing.allocator, body, &fuzz_schema) catch continue;
        defer r.deinit();
        if (r.ok()) valid += 1;
        violations += r.errors.len;
    }
    // Measured 2026-09-07. The single body this target used to build was
    // `"{}"`, which reports exactly the two missing required fields.
    try testing.expectEqual(@as(usize, 17), nonempty);
    try testing.expectEqual(@as(usize, 692), octets);
    try testing.expectEqual(@as(usize, 2), valid);
    try testing.expectEqual(@as(usize, 23), violations);
}

test "fuzz: validateFormat never panics on any Format + arbitrary/near-miss strings" {
    try testing.fuzz({}, fuzzValidateFormat, .{ .corpus = &format_seeds });
}

/// Octet 0 picks the format, octet 1 picks the string mode (0 = the rest is
/// the string verbatim, anything else = build it from the near-miss
/// alphabet), and the rest is the payload.
fn buildFormatCase(seed: []const u8, buf: []u8) struct { Format, []const u8 } {
    const formats = std.enums.values(Format);
    if (seed.len == 0) return .{ formats[0], buf[0..0] };
    const format = formats[seed[0] % formats.len];
    if (seed.len == 1) return .{ format, buf[0..0] };
    const payload = seed[2..];
    if (seed[1] == 0) {
        const n = @min(payload.len, buf.len);
        @memcpy(buf[0..n], payload[0..n]);
        return .{ format, buf[0..n] };
    }
    // Near-miss: a string built from an alphabet that includes the separators
    // each format's grammar hinges on, so the deeper per-character walk (not
    // just a length/emptiness bail-out) actually runs.
    const alphabet = "abcAZ09@.:-_[]%/T+ \t";
    var script: fuzzseed.Cursor = .{ .bytes = payload };
    const n = @min(@as(usize, script.ranged(0, @intCast(buf.len))), buf.len);
    for (buf[0..n]) |*b| b.* = alphabet[script.ranged(0, alphabet.len - 1)];
    return .{ format, buf[0..n] };
}

fn fuzzValidateFormat(_: void, smith: *std.testing.Smith) !void {
    // ⚠ ONE byte-first draw. `smith.value(Format)` used to come first, which
    // meant `.email` on every input the ordinary lane can carry — eleven of
    // the twelve formats were never called.
    var raw: [2 + format_buf_len]u8 = undefined;
    const n: usize = smith.slice(&raw);
    var buf: [format_buf_len]u8 = undefined;
    const case = buildFormatCase(raw[0..n], &buf);
    _ = validateFormat(case[0], case[1]);
}

test "corpus: every Format is exercised, and the strings each accepts are pinned" {
    // ⭐ The number that was 1 before, and the only one that says this target
    // is no longer stuck on `.email`: how many DISTINCT formats the corpus
    // selects. Twelve of twelve, and the accepted count beside it so a corpus
    // of refusals only would be visible.
    const formats = std.enums.values(Format);
    var seen = [_]bool{false} ** 12;
    var nonempty: usize = 0;
    var accepted: usize = 0;
    for (format_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [2 + format_buf_len]u8 = undefined;
        const n: usize = smith.slice(&raw);
        var buf: [format_buf_len]u8 = undefined;
        const case = buildFormatCase(raw[0..n], &buf);
        seen[@intFromEnum(case[0])] = true;
        if (case[1].len != 0) nonempty += 1;
        if (validateFormat(case[0], case[1])) accepted += 1;
    }
    try testing.expectEqual(@as(usize, 12), formats.len);
    for (seen) |v| try testing.expect(v);
    // Measured 2026-09-07. Before: 1 format, 0 non-empty strings, 0 accepted.
    try testing.expectEqual(@as(usize, 21), nonempty);
    try testing.expectEqual(@as(usize, 12), accepted);
}

// ── external anchor: json-schema-org/JSON-Schema-Test-Suite (format) ───────
// See json_schema_format_test.zig / json_schema_format_vectors.zig / NOTICE.
test {
    _ = @import("json_schema_format_vectors.zig");
    _ = @import("json_schema_format_test.zig");
}

test "a rule that forgot its kind is not a no-op: .any constrains the value" {
    // ⛔ MEDIUM regression (audit 2026-09-02). `.any` is the DEFAULT kind and
    // used to void every constraint, so one omitted `.kind = .string` turned
    // a fully specified rule into nothing at all — with no signal.
    const rules = [_]Rule{.{
        .field = "email",
        .required = true,
        .format = .email,
        .min_len = 5,
        .max_len = 10,
        .one_of = &.{"x"},
        .pattern = .{ .literal = "zz" },
    }};
    var report = try validateJson(testing.allocator, "{\"email\":\"not-an-email at all, way too long\"}", &rules);
    defer report.deinit();
    try testing.expect(!report.ok());

    // Nested rules too: `.any` with `fields` used to skip the object.
    const inner = [_]Rule{.{ .field = "id", .kind = .int, .required = true }};
    const outer = [_]Rule{.{ .field = "u", .fields = &inner }};
    var r2 = try validateJson(testing.allocator, "{\"u\":{}}", &outer);
    defer r2.deinit();
    try testing.expect(!r2.ok());

    // And a rule with NO constraints still accepts anything, which is what
    // `.any` is for — the fix must not have turned it into a type gate.
    const loose = [_]Rule{.{ .field = "whatever" }};
    var r3 = try validateJson(testing.allocator, "{\"whatever\":[1,2,3]}", &loose);
    defer r3.deinit();
    try testing.expect(r3.ok());
    var r4 = try validateJson(testing.allocator, "{\"whatever\":\"a string\"}", &loose);
    defer r4.deinit();
    try testing.expect(r4.ok());
}

test "a derived [N]u8 rule counts BYTES, because that is what the decoder fills" {
    // The code-point fix silently broke the derived rule: 16 code points is
    // not 16 bytes, so a string that decodes perfectly was rejected and one
    // that does not was passed through to fail unpathed inside
    // `parseFromValue`. Audit 2026-09-02.
    const T = struct { fixed: [16]u8 };
    const rules = comptime rulesFor(T);
    try testing.expectEqual(@as(?usize, 16), rules[0].min_bytes);
    try testing.expectEqual(@as(?usize, 16), rules[0].max_bytes);
    try testing.expectEqual(@as(?usize, null), rules[0].min_len);

    // 16 bytes, 8 code points: decodes, and must validate.
    var ok_report = try validateJson(testing.allocator, "{\"fixed\":\"éééééééé\"}", rules);
    defer ok_report.deinit();
    try testing.expect(ok_report.ok());

    // 16 code points, 17 bytes: does NOT decode, and must be rejected here
    // rather than deeper down with no path.
    var bad = try validateJson(testing.allocator, "{\"fixed\":\"0123456789abcdéf\"}", rules);
    defer bad.deinit();
    try testing.expect(!bad.ok());
    try testing.expectEqualStrings("string_bytes_too_long", bad.errors[0].code);
}

test "the Limits defaults are the security control, so each one is pinned" {
    // ⛔ Three of the four defaults SPEC names as the control had nothing
    // behind them: raising `max_array_elements` 10 000 → 1e8,
    // `max_object_members` 1 000 → 1e8 or `max_total_nodes` 1e6 → 1e11 each
    // left the whole suite green (audit 2026-09-02). The one test that
    // claimed to cover this exercised `max_depth` alone; every other limit
    // test passes its own `Limits`. The defaults worked — nothing would have
    // noticed them stopping.
    const gpa = testing.allocator;

    // An array one past the default element cap, in a body that is otherwise
    // trivially valid.
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        try body.appendSlice(gpa, "{\"a\":[");
        for (0..10_001) |i| {
            if (i != 0) try body.append(gpa, ',');
            try body.append(gpa, '0');
        }
        try body.appendSlice(gpa, "]}");
        var report = try validateJson(gpa, body.items, &.{});
        defer report.deinit();
        try testing.expect(!report.ok());
        try testing.expectEqualStrings("array_too_large", report.errors[0].code);
    }

    // An object one past the default member cap.
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(gpa);
        try body.append(gpa, '{');
        for (0..1001) |i| {
            if (i != 0) try body.append(gpa, ',');
            var key_buf: [32]u8 = undefined;
            const key = try std.fmt.bufPrint(&key_buf, "\"k{d}\":0", .{i});
            try body.appendSlice(gpa, key);
        }
        try body.append(gpa, '}');
        var report = try validateJson(gpa, body.items, &.{});
        defer report.deinit();
        try testing.expect(!report.ok());
        try testing.expectEqualStrings("too_many_fields", report.errors[0].code);
    }
}

test "isEmail's documented 254-byte ceiling is enforced" {
    // Documented, and nothing pinned it: removing the check left the suite
    // green while 255..318-byte addresses became acceptable (audit
    // 2026-09-02). The corpus has no long-address case.
    const gpa = testing.allocator;
    // local(60) + '@' + labels of 'b' separated by dots + ".com", built to
    // exactly 254 bytes and then to 255.
    var addr: std.ArrayList(u8) = .empty;
    defer addr.deinit(gpa);
    try addr.appendNTimes(gpa, 'a', 60);
    try addr.append(gpa, '@');
    while (addr.items.len < 254 - 4) {
        // 60-byte labels keep every label inside the 63-byte hostname cap.
        const room = 254 - 4 - addr.items.len;
        const chunk = @min(room, @as(usize, 60));
        try addr.appendNTimes(gpa, 'b', chunk);
        if (addr.items.len < 254 - 4) try addr.append(gpa, '.');
    }
    try addr.appendSlice(gpa, ".com");
    try testing.expectEqual(@as(usize, 254), addr.items.len);
    try testing.expect(validateFormat(.email, addr.items));

    try addr.insert(gpa, 61, 'b');
    try testing.expectEqual(@as(usize, 255), addr.items.len);
    try testing.expect(!validateFormat(.email, addr.items));
}

test "the error cap bounds the WORK, not just the list" {
    // ⛔ MEDIUM regression (audit 2026-09-02). `max_errors` capped the error
    // LIST inside `append`, but `appendf` formatted its message first — so a
    // 996 KiB body of 340 000 nodes, every part of it inside the DEFAULT
    // `Limits`, built 339 000 messages nobody could read and left an 18 802
    // KiB report arena behind for the 1000 errors it kept.
    //
    // Measured here as bytes still outstanding when the report comes back:
    // the parse arena is freed by then, so what remains IS the report arena.
    // The ceiling is ~5x the fixed cost, and the defect overshoots it by an
    // order of magnitude.
    const Counting = struct {
        inner: Allocator,
        outstanding: usize = 0,

        fn allocator(self: *@This()) Allocator {
            return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
        }
        fn alloc(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const p = self.inner.rawAlloc(len, al, ra) orelse return null;
            self.outstanding += len;
            return p;
        }
        fn resize(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, new_len: usize, ra: usize) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (!self.inner.rawResize(m, al, new_len, ra)) return false;
            self.outstanding = self.outstanding + new_len - m.len;
            return true;
        }
        fn remap(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            const p = self.inner.rawRemap(m, al, new_len, ra) orelse return null;
            self.outstanding = self.outstanding + new_len - m.len;
            return p;
        }
        fn free(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, ra: usize) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.inner.rawFree(m, al, ra);
            self.outstanding -= m.len;
        }
    };

    var counting: Counting = .{ .inner = testing.allocator };
    const gpa = counting.allocator();

    // 34 arrays of 10 000 empty strings: 340 000 nodes, every one of which
    // fails a `min_len` rule on the element.
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    try body.appendSlice(testing.allocator, "{\"g\":[");
    for (0..34) |outer| {
        if (outer != 0) try body.append(testing.allocator, ',');
        try body.append(testing.allocator, '[');
        for (0..10_000) |i| {
            if (i != 0) try body.append(testing.allocator, ',');
            try body.appendSlice(testing.allocator, "\"\"");
        }
        try body.append(testing.allocator, ']');
    }
    try body.appendSlice(testing.allocator, "]}");

    const elem: Rule = .{ .field = "", .kind = .string, .min_len = 1 };
    const inner: Rule = .{ .field = "", .kind = .array, .items = &elem };
    const rules = [_]Rule{.{ .field = "g", .kind = .array, .items = &inner }};

    var report = try validateJson(gpa, body.items, &rules);
    const held = counting.outstanding;
    report.deinit();
    try testing.expectEqual(@as(usize, 0), counting.outstanding); // no leak either

    try testing.expect(!report.ok());
    if (held > 4 * 1024 * 1024) {
        std.debug.print("\nreport arena held {d} KiB for {d} errors — the cap is bounding the list, not the work\n", .{ held / 1024, report.errors.len });
        return error.ErrorCapDoesNotBoundWork;
    }
}

test "the offset-optional date-time profile is a CHOICE, and this is where it is written down" {
    // `date_time`/`time` accept a local time with no UTC offset, which RFC
    // 3339 proper forbids and the `Format` doc calls a deliberate ISO 8601
    // profile. Nothing pinned it: the vendored corpus has no date-time case
    // at all and reaches the `time` one only through a documented skip, so
    // the choice could have been reversed by accident in either direction
    // (audit 2026-09-02). If a future change makes the offset mandatory, this
    // test is the conversation, not a surprise.
    try testing.expect(validateFormat(.date_time, "1998-12-31T23:59:59"));
    try testing.expect(validateFormat(.date_time, "1998-12-31T23:59:59Z"));
    try testing.expect(validateFormat(.date_time, "1998-12-31T23:59:59+01:00"));
    try testing.expect(validateFormat(.time, "23:59:59"));
    try testing.expect(validateFormat(.time, "23:59:59Z"));

    // What is NOT lax: the offset is still validated when it is there, and
    // the calendar/clock ranges are real.
    try testing.expect(!validateFormat(.date_time, "1998-12-31T23:59:59+99:00"));
    try testing.expect(!validateFormat(.date_time, "1998-13-31T23:59:59Z"));
    try testing.expect(!validateFormat(.time, "24:00:00"));
}
