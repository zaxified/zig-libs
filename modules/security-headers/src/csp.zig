// SPDX-License-Identifier: MIT

//! Content-Security-Policy builder: typed directives, helmet's `useDefaults`
//! merge semantics, validation, and per-response nonces.
//!
//! One rendering core serves both worlds:
//!
//! - `build(comptime spec)` -- the whole policy is rendered, merged and
//!   validated at compile time; the result is a `[]const u8` in rodata, fit
//!   for `Options.content_security_policy` (and therefore `applyStatic`).
//!   Every validation failure is a `@compileError`.
//! - `render(spec, out)` / `renderNonce(spec, nonce, nonce_in, out)` -- the
//!   same core at run time, into a caller buffer: no allocation, no globals.
//!   Failures are errors (`Error`).
//!
//! Output format is helmet's: directives joined by `;` with no space, values
//! joined by a single space, directives in helmet's default order first and
//! caller-added ones appended in the order given (an override keeps the
//! position of the default it replaces).
//!
//! Validation (helmet 8 refuses unquoted keywords; this goes further because
//! the value goes onto the wire verbatim):
//!
//! - a source-list value that is one of the CSP keywords written *without*
//!   quotes (`self`, `none`, `unsafe-inline`, ...) is `UnquotedKeyword` --
//!   in a browser `self` is a host named "self", never the keyword;
//! - quotes must be balanced (`'self'`), `MalformedQuote` otherwise;
//! - a value is one token: no space, no `;` (would start a new directive),
//!   no `,` (would start a new policy), no control characters, no non-ASCII
//!   -- `InvalidCharacter`;
//! - an empty value, or a source-list directive with no value at all
//!   (silently `'none'` in a browser) -- `EmptyValue` / `EmptyDirective`;
//! - values on `upgrade-insecure-requests` / `block-all-mixed-content`
//!   -- `UnexpectedValues`; the same directive twice -- `DuplicateDirective`.

const std = @import("std");

/// Every directive this builder knows. The wire name is the tag name with
/// `_` turned into `-`.
pub const Name = enum {
    default_src,
    script_src,
    script_src_elem,
    script_src_attr,
    style_src,
    style_src_elem,
    style_src_attr,
    img_src,
    font_src,
    connect_src,
    media_src,
    object_src,
    child_src,
    frame_src,
    worker_src,
    manifest_src,
    base_uri,
    form_action,
    frame_ancestors,
    sandbox,
    report_uri,
    report_to,
    require_trusted_types_for,
    trusted_types,
    upgrade_insecure_requests,
    block_all_mixed_content,

    /// Fetch directives and navigation/ancestor source lists: these get the
    /// keyword-quoting check and must not be empty.
    fn isSourceList(n: Name) bool {
        return switch (n) {
            .sandbox, .report_uri, .report_to, .require_trusted_types_for, .trusted_types, .upgrade_insecure_requests, .block_all_mixed_content => false,
            else => true,
        };
    }

    fn isFlag(n: Name) bool {
        return n == .upgrade_insecure_requests or n == .block_all_mixed_content;
    }

    fn mayBeEmpty(n: Name) bool {
        return n.isFlag() or n == .sandbox;
    }
};

/// One directive: its name and its values (source expressions), already in
/// final spelling -- keywords with their quotes (`"'self'"`).
pub const Directive = struct {
    name: Name,
    values: []const []const u8 = &.{},
};

/// A policy description.
pub const Spec = struct {
    /// Start from helmet 8.3.0's `useDefaults` directives (`default_directives`).
    use_defaults: bool = true,
    /// Directives to add; one that is already present (from the defaults)
    /// replaces the default's values in place (helmet's merge rule).
    directives: []const Directive = &.{},
    /// Default directives to drop (helmet: `name: null`). Naming one that is
    /// also in `directives` is `ConflictingRemove`.
    remove: []const Name = &.{},
};

/// helmet 8.3.0's default directives, in its order.
pub const default_directives = [_]Directive{
    .{ .name = .default_src, .values = &.{"'self'"} },
    .{ .name = .base_uri, .values = &.{"'self'"} },
    .{ .name = .font_src, .values = &.{ "'self'", "https:", "data:" } },
    .{ .name = .form_action, .values = &.{"'self'"} },
    .{ .name = .frame_ancestors, .values = &.{"'self'"} },
    .{ .name = .img_src, .values = &.{ "'self'", "data:" } },
    .{ .name = .object_src, .values = &.{"'none'"} },
    .{ .name = .script_src, .values = &.{"'self'"} },
    .{ .name = .script_src_attr, .values = &.{"'none'"} },
    .{ .name = .style_src, .values = &.{ "'self'", "https:", "'unsafe-inline'" } },
    .{ .name = .upgrade_insecure_requests },
};

pub const Error = error{
    UnquotedKeyword,
    MalformedQuote,
    InvalidCharacter,
    EmptyValue,
    EmptyDirective,
    UnexpectedValues,
    DuplicateDirective,
    ConflictingRemove,
    /// The resulting policy has no directive at all.
    NoDirectives,
    /// `nonce_in` names a directive the policy does not contain (adding a
    /// lone `script-src 'nonce-..'` would silently drop what `default-src`
    /// allowed).
    NonceDirectiveMissing,
    /// `nonce_in` names a directive that is not a source list (`sandbox`,
    /// `report-to`, …) or whose source list is `'none'` — a nonce next to
    /// `'none'` silently turns "nothing" into "this nonce" (review
    /// 2026-10-17).
    NonceDirectiveInvalid,
    NoSpaceLeft,
};

const keywords = [_][]const u8{
    "self",                   "none",             "unsafe-inline",            "unsafe-eval",
    "unsafe-hashes",          "strict-dynamic",   "report-sample",            "wasm-unsafe-eval",
    "unsafe-allow-redirects", "allow-duplicates", "inline-speculation-rules", "trusted-types-eval",
};

fn checkValue(name: Name, v: []const u8) Error!void {
    if (v.len == 0) return error.EmptyValue;
    for (v) |c| {
        if (c <= 0x20 or c >= 0x7f or c == ';' or c == ',') return error.InvalidCharacter;
    }
    if (!name.isSourceList()) return;
    const q_first = v[0] == '\'';
    const q_last = v[v.len - 1] == '\'';
    if (q_first or q_last) {
        if (v.len < 2 or !q_first or !q_last) return error.MalformedQuote;
        if (std.mem.indexOfScalar(u8, v[1 .. v.len - 1], '\'') != null) return error.MalformedQuote;
        return;
    }
    for (keywords) |k| if (std.ascii.eqlIgnoreCase(k, v)) return error.UnquotedKeyword;
}

const n_names = @typeInfo(Name).@"enum".field_names.len;

/// Output sink: counts when `buf` is null, so one pass sizes and a second
/// fills (the comptime path needs the exact length for its array).
const Out = struct {
    buf: ?[]u8,
    n: usize = 0,

    fn put(o: *Out, s: []const u8) Error!void {
        if (o.buf) |b| {
            if (o.n + s.len > b.len) return error.NoSpaceLeft;
            @memcpy(b[o.n..][0..s.len], s);
        }
        o.n += s.len;
    }

    fn putName(o: *Out, n: Name) Error!void {
        const t = @tagName(n);
        if (o.buf) |b| {
            if (o.n + t.len > b.len) return error.NoSpaceLeft;
            for (t, 0..) |c, i| b[o.n + i] = if (c == '_') '-' else c;
        }
        o.n += t.len;
    }
};

fn renderImpl(spec: Spec, nonce: ?[]const u8, nonce_in: []const Name, buf: ?[]u8) Error!usize {
    var present = @as([n_names]bool, @splat(false));
    var vals: [n_names][]const []const u8 = undefined;
    var order: [n_names]Name = undefined;
    var count: usize = 0;

    if (spec.use_defaults) {
        for (default_directives) |d| {
            const i = @backingInt(d.name);
            present[i] = true;
            vals[i] = d.values;
            order[count] = d.name;
            count += 1;
        }
    }
    for (spec.remove) |r| {
        for (spec.directives) |d| if (d.name == r) return error.ConflictingRemove;
        const i = @backingInt(r);
        if (!present[i]) continue;
        present[i] = false;
        var k: usize = 0;
        for (order[0..count]) |o| {
            if (o != r) {
                order[k] = o;
                k += 1;
            }
        }
        count = k;
    }
    var seen = @as([n_names]bool, @splat(false));
    for (spec.directives) |d| {
        const i = @backingInt(d.name);
        if (seen[i]) return error.DuplicateDirective;
        seen[i] = true;
        if (!present[i]) {
            present[i] = true;
            order[count] = d.name;
            count += 1;
        }
        vals[i] = d.values;
    }
    if (count == 0) return error.NoDirectives;
    for (nonce_in) |n| {
        if (!present[@backingInt(n)]) return error.NonceDirectiveMissing;
        if (!n.isSourceList()) return error.NonceDirectiveInvalid;
        for (vals[@backingInt(n)]) |v| if (std.ascii.eqlIgnoreCase(v, "'none'")) return error.NonceDirectiveInvalid;
    }

    var out: Out = .{ .buf = buf };
    for (order[0..count], 0..) |name, idx| {
        const values = vals[@backingInt(name)];
        if (name.isFlag() and values.len != 0) return error.UnexpectedValues;
        var with_nonce = false;
        if (nonce != null) {
            for (nonce_in) |n| {
                if (n == name) with_nonce = true;
            }
        }
        if (values.len == 0 and !with_nonce and !name.mayBeEmpty()) return error.EmptyDirective;
        for (values) |v| try checkValue(name, v);

        if (idx != 0) try out.put(";");
        try out.putName(name);
        for (values) |v| {
            try out.put(" ");
            try out.put(v);
        }
        if (with_nonce) {
            try out.put(" 'nonce-");
            try out.put(nonce.?);
            try out.put("'");
        }
    }
    return out.n;
}

/// Render `spec` at compile time. Any validation failure is a compile error
/// (`csp: <ErrorName>`).
pub fn build(comptime spec: Spec) []const u8 {
    const result = comptime blk: {
        @setEvalBranchQuota(100_000);
        const n = renderImpl(spec, null, &.{}, null) catch |e| @compileError("csp: " ++ @errorName(e));
        var arr: [n]u8 = undefined;
        _ = renderImpl(spec, null, &.{}, &arr) catch unreachable;
        const final = arr;
        break :blk &final;
    };
    return result;
}

/// Render `spec` into `out` at run time; returns the used prefix.
pub fn render(spec: Spec, out: []u8) Error![]const u8 {
    const n = try renderImpl(spec, null, &.{}, out);
    return out[0..n];
}

/// Render `spec` with `'nonce-<nonce>'` appended to each directive in
/// `nonce_in` (typically `&.{ .script_src, .style_src }`), into `out`.
/// ⚠ CSP semantics, not a bug: a browser that understands nonces IGNORES
/// `'unsafe-inline'` in a directive that also carries one — helmet's default
/// `style-src ... 'unsafe-inline'` plus a nonce means un-nonced inline styles
/// stop working (the `'unsafe-inline'` stays only as the fallback for
/// pre-CSP2 browsers, the strict-CSP recommendation).
pub fn renderNonce(spec: Spec, nonce: *const Nonce, nonce_in: []const Name, out: []u8) Error![]const u8 {
    const n = try renderImpl(spec, nonce.slice(), nonce_in, out);
    return out[0..n];
}

/// A per-response CSP nonce: 128 random bits, base64 (RFC 4648 standard
/// alphabet, unpadded -- valid `base64-value` in CSP) = 22 characters.
/// Generate a FRESH one for every response; a reused nonce is no nonce.
pub const Nonce = struct {
    text: [text_len]u8,

    pub const raw_len = 16;
    pub const text_len = 22;

    /// Encode caller-supplied random bytes (any source the caller trusts:
    /// `io.randomSecure`, a test vector, an HSM).
    pub fn fromBytes(raw: *const [raw_len]u8) Nonce {
        var n: Nonce = .{ .text = undefined };
        _ = std.base64.standard_no_pad.Encoder.encode(&n.text, raw);
        return n;
    }

    /// Fresh nonce from the `std.Io` secure random source -- no global RNG.
    pub fn secure(io: std.Io) std.Io.RandomSecureError!Nonce {
        var raw: [raw_len]u8 = undefined;
        try io.randomSecure(&raw);
        defer std.crypto.secureZero(u8, &raw);
        return fromBytes(&raw);
    }

    /// The base64 text: put it in the HTML as `<script nonce="...">`.
    pub fn slice(n: *const Nonce) []const u8 {
        return &n.text;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

// helmet 8.3.0 README, "Content-Security-Policy" default, byte for byte
// (directives joined by ";" without a space).
const helmet_default_csp = "default-src 'self';base-uri 'self';font-src 'self' https: data:;" ++
    "form-action 'self';frame-ancestors 'self';img-src 'self' data:;" ++
    "object-src 'none';script-src 'self';script-src-attr 'none';" ++
    "style-src 'self' https: 'unsafe-inline';upgrade-insecure-requests";

test "renderNonce: a nonce on 'none' or on a non-source-list directive is refused" {
    var buf: [1024]u8 = undefined;
    const nonce = Nonce.fromBytes(&@splat(7));
    // helmet's defaults have script-src-attr 'none'.
    try testing.expectError(error.NonceDirectiveInvalid, renderNonce(.{}, &nonce, &.{.script_src_attr}, &buf));
    try testing.expectError(error.NonceDirectiveInvalid, renderNonce(.{ .directives = &.{.{ .name = .sandbox }} }, &nonce, &.{.sandbox}, &buf));
    _ = try renderNonce(.{}, &nonce, &.{ .script_src, .style_src }, &buf);
}

test "build: helmet useDefaults output, comptime" {
    try testing.expectEqualStrings(helmet_default_csp, comptime build(.{}));
}

test "build: override keeps the default's position, new directive appended, remove drops" {
    const got = comptime build(.{
        .directives = &.{
            .{ .name = .script_src, .values = &.{ "'self'", "https://cdn.example" } },
            .{ .name = .connect_src, .values = &.{"'self'"} },
        },
        .remove = &.{ .upgrade_insecure_requests, .font_src },
    });
    try testing.expectEqualStrings("default-src 'self';base-uri 'self';form-action 'self';" ++
        "frame-ancestors 'self';img-src 'self' data:;object-src 'none';" ++
        "script-src 'self' https://cdn.example;script-src-attr 'none';" ++
        "style-src 'self' https: 'unsafe-inline';connect-src 'self'", got);
}

test "build: without defaults only the given directives; flag and sandbox without values" {
    const got = comptime build(.{ .use_defaults = false, .directives = &.{
        .{ .name = .default_src, .values = &.{"'none'"} },
        .{ .name = .sandbox },
        .{ .name = .block_all_mixed_content },
        .{ .name = .report_uri, .values = &.{"/csp-report"} },
    } });
    try testing.expectEqualStrings("default-src 'none';sandbox;block-all-mixed-content;report-uri /csp-report", got);
}

test "render (runtime) equals build (comptime) and honours the buffer size" {
    const spec: Spec = .{ .directives = &.{.{ .name = .img_src, .values = &.{ "'self'", "https://i.example" } }} };
    var buf: [512]u8 = undefined;
    try testing.expectEqualStrings(comptime build(spec), try render(spec, &buf));
    var tiny: [10]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, render(spec, &tiny));
    // exact fit works, one byte less does not
    const want = comptime build(spec);
    var exact: [want.len]u8 = undefined;
    try testing.expectEqualStrings(want, try render(spec, &exact));
    var short: [want.len - 1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, render(spec, &short));
}

fn one(name: Name, v: []const u8) Error!void {
    var buf: [512]u8 = undefined;
    const vs = [_][]const u8{v};
    _ = try render(.{ .use_defaults = false, .directives = &.{.{ .name = name, .values = &vs }} }, &buf);
}

test "validation: unquoted keywords are refused, every keyword, any case" {
    for (keywords) |k| try testing.expectError(error.UnquotedKeyword, one(.script_src, k));
    try testing.expectError(error.UnquotedKeyword, one(.default_src, "SELF"));
    try testing.expectError(error.UnquotedKeyword, one(.style_src, "Unsafe-Inline"));
    // quoted is fine; host that merely starts like a keyword is fine
    try one(.script_src, "'self'");
    try one(.script_src, "'unsafe-inline'");
    try one(.script_src, "selfish.example");
    try one(.script_src, "https:");
    // keyword check is for source lists: sandbox / trusted-types take plain tokens
    try one(.sandbox, "allow-scripts");
    try one(.trusted_types, "none");
}

test "validation: quotes must be balanced" {
    try testing.expectError(error.MalformedQuote, one(.script_src, "'self"));
    try testing.expectError(error.MalformedQuote, one(.script_src, "self'"));
    try testing.expectError(error.MalformedQuote, one(.script_src, "'"));
    try testing.expectError(error.MalformedQuote, one(.script_src, "'a'b'"));
}

test "validation: injection characters inside values are refused" {
    try testing.expectError(error.InvalidCharacter, one(.script_src, "a.example;script-src *"));
    try testing.expectError(error.InvalidCharacter, one(.script_src, "a.example,b.example"));
    try testing.expectError(error.InvalidCharacter, one(.script_src, "a b"));
    try testing.expectError(error.InvalidCharacter, one(.script_src, "a\r\nX-Evil: 1"));
    try testing.expectError(error.InvalidCharacter, one(.script_src, "a\x00b"));
    try testing.expectError(error.InvalidCharacter, one(.script_src, "a\x7fb"));
    try testing.expectError(error.InvalidCharacter, one(.script_src, "caf\xc3\xa9.example"));
    try testing.expectError(error.InvalidCharacter, one(.report_uri, "/r;x"));
    try testing.expectError(error.EmptyValue, one(.script_src, ""));
}

test "validation: structure errors" {
    var buf: [256]u8 = undefined;
    try testing.expectError(error.EmptyDirective, render(.{ .use_defaults = false, .directives = &.{.{ .name = .script_src }} }, &buf));
    try testing.expectError(error.UnexpectedValues, render(.{ .directives = &.{.{ .name = .upgrade_insecure_requests, .values = &.{"x"} }} }, &buf));
    try testing.expectError(error.DuplicateDirective, render(.{ .directives = &.{
        .{ .name = .img_src, .values = &.{"'self'"} },
        .{ .name = .img_src, .values = &.{"'none'"} },
    } }, &buf));
    try testing.expectError(error.ConflictingRemove, render(.{ .directives = &.{.{ .name = .img_src, .values = &.{"'self'"} }}, .remove = &.{.img_src} }, &buf));
    try testing.expectError(error.NoDirectives, render(.{ .use_defaults = false }, &buf));
}

test "nonce: fromBytes is base64 of the bytes, 22 chars, standard alphabet" {
    const raw = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const n = Nonce.fromBytes(&raw);
    try testing.expectEqualStrings("AAECAwQFBgcICQoLDA0ODw", n.slice());
    const ff = Nonce.fromBytes(&(@as([16]u8, @splat(0xfb))));
    try testing.expectEqual(@as(usize, Nonce.text_len), ff.slice().len);
    try testing.expectEqualStrings("+/v7+/v7+/v7+/v7+/v7+w", ff.slice());
}

test "nonce: secure() yields distinct well-formed values" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var prev: Nonce = try Nonce.secure(io);
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        const n = try Nonce.secure(io);
        try testing.expect(!std.mem.eql(u8, &prev.text, &n.text));
        for (n.slice()) |c| try testing.expect(std.ascii.isAlphanumeric(c) or c == '+' or c == '/');
        prev = n;
    }
}

test "renderNonce: nonce appended to the named directives only; missing directive refused" {
    const nonce = Nonce.fromBytes(&(@as([16]u8, @splat(0))));
    const zero_nonce = strRepeat("A", 22);
    var buf: [1024]u8 = undefined;
    const got = try renderNonce(.{}, &nonce, &.{ .script_src, .style_src }, &buf);
    try testing.expectEqualStrings("default-src 'self';base-uri 'self';font-src 'self' https: data:;" ++
        "form-action 'self';frame-ancestors 'self';img-src 'self' data:;" ++
        "object-src 'none';script-src 'self' 'nonce-" ++ zero_nonce ++ "';script-src-attr 'none';" ++
        "style-src 'self' https: 'unsafe-inline' 'nonce-" ++ zero_nonce ++ "';upgrade-insecure-requests", got);
    try testing.expectError(error.NonceDirectiveMissing, renderNonce(.{ .use_defaults = false, .directives = &.{.{ .name = .default_src, .values = &.{"'self'"} }} }, &nonce, &.{.script_src}, &buf));
    // no nonce_in -> identical to render
    try testing.expectEqualStrings(helmet_default_csp, try renderNonce(.{}, &nonce, &.{}, &buf));
}

// ── audit 2026-10-18: runtime-path tests asked for by mutation survivors ────
// (the comptime `build` tests above exercise the same core at compile time;
// these pin the rules through the run-time entry points `render` /
// `renderNonce`, where a defect in the shared core is also reachable.)

test "render (runtime): override position, append and remove equal the comptime build" {
    const spec: Spec = .{
        .directives = &.{
            .{ .name = .script_src, .values = &.{ "'self'", "https://cdn.example" } },
            .{ .name = .connect_src, .values = &.{"'self'"} },
        },
        .remove = &.{ .upgrade_insecure_requests, .font_src },
    };
    var buf: [512]u8 = undefined;
    const got = try render(spec, &buf);
    try testing.expectEqualStrings("default-src 'self';base-uri 'self';form-action 'self';" ++
        "frame-ancestors 'self';img-src 'self' data:;object-src 'none';" ++
        "script-src 'self' https://cdn.example;script-src-attr 'none';" ++
        "style-src 'self' https: 'unsafe-inline';connect-src 'self'", got);
    try testing.expectEqualStrings(comptime build(spec), got);
    // the defaults themselves, run-time
    try testing.expectEqualStrings(helmet_default_csp, try render(.{}, &buf));
}

test "render (runtime): flags and sandbox take no value and may stay empty; a flag with a value is refused" {
    var buf: [256]u8 = undefined;
    const got = try render(.{ .use_defaults = false, .directives = &.{
        .{ .name = .sandbox },
        .{ .name = .block_all_mixed_content },
        .{ .name = .upgrade_insecure_requests },
    } }, &buf);
    try testing.expectEqualStrings("sandbox;block-all-mixed-content;upgrade-insecure-requests", got);
    try testing.expectError(error.UnexpectedValues, render(.{ .use_defaults = false, .directives = &.{
        .{ .name = .block_all_mixed_content, .values = &.{"x"} },
    } }, &buf));
    // a source list may not stay empty
    try testing.expectError(error.EmptyDirective, render(.{ .use_defaults = false, .directives = &.{.{ .name = .img_src }} }, &buf));
}

test "validation: report-to / report-uri values are plain tokens, keyword look-alikes included" {
    // A reporting group may be named `self`; a relative URL may read `none`.
    // Only source lists get the keyword-quoting check.
    try one(.report_to, "self");
    try one(.report_uri, "none");
    try one(.report_to, "'q");
}

test "render: a buffer that fits exactly works when the LAST write is a value, one byte less does not" {
    const spec: Spec = .{ .use_defaults = false, .directives = &.{.{ .name = .img_src, .values = &.{"'self'"} }} };
    const want = "img-src 'self'";
    var exact: [want.len]u8 = undefined;
    try testing.expectEqualStrings(want, try render(spec, &exact));
    var short: [want.len - 1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, render(spec, &short));
    // same for the closing quote of a nonce (the final write there)
    const nonce = Nonce.fromBytes(&(@as([16]u8, @splat(0))));
    const want_n = "script-src 'nonce-" ++ (strRepeat("A", 22)) ++ "'";
    const spec_n: Spec = .{ .use_defaults = false, .directives = &.{.{ .name = .script_src }} };
    var exact_n: [want_n.len]u8 = undefined;
    try testing.expectEqualStrings(want_n, try renderNonce(spec_n, &nonce, &.{.script_src}, &exact_n));
    var short_n: [want_n.len - 1]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, renderNonce(spec_n, &nonce, &.{.script_src}, &short_n));
}

test "renderNonce: an empty source list is allowed only because the nonce fills it; 'none' is refused in any case" {
    const nonce = Nonce.fromBytes(&(@as([16]u8, @splat(0))));
    var buf: [256]u8 = undefined;
    const spec: Spec = .{ .use_defaults = false, .directives = &.{.{ .name = .script_src }} };
    try testing.expectError(error.EmptyDirective, render(spec, &buf));
    try testing.expectError(error.EmptyDirective, renderNonce(spec, &nonce, &.{}, &buf));
    try testing.expectEqualStrings("script-src 'nonce-" ++ (strRepeat("A", 22)) ++ "'", try renderNonce(spec, &nonce, &.{.script_src}, &buf));
    // `'none'` is matched case-insensitively (CSP keywords are)
    try testing.expectError(error.NonceDirectiveInvalid, renderNonce(.{ .use_defaults = false, .directives = &.{
        .{ .name = .script_src, .values = &.{"'NONE'"} },
    } }, &nonce, &.{.script_src}, &buf));
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    const rep_result = comptime blk: {
        @setEvalBranchQuota(n * (s.len + 4) + 1000);
        var buf: [s.len * n:0]u8 = undefined;
        for (0..n) |i| @memcpy(buf[i * s.len ..][0..s.len], s);
        const rep_final = buf;
        break :blk rep_final;
    };
    return &rep_result;
}
