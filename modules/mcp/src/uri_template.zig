// SPDX-License-Identifier: MIT
//! RFC 6570 URI Templates (levels 1-4) for MCP resource templates: parse,
//! expand, and — the part the RFC leaves out (§1.4) — match a concrete URI
//! back to the variables that produced it. `resources/templates/list` hands
//! out `uriTemplate`s such as `file:///{+path}` or `users://{id}/posts{?page}`;
//! `resources/read` carries a concrete URI. `Template.match` is how a server
//! gets from the second to the arguments of the first without every handler
//! parsing `req.uri` itself, as the official SDKs do.
//!
//! Expansion is the RFC's, with two documented gaps: a variable's value is a
//! string or a list of strings (`Value`) — associative arrays ("keys" in the
//! RFC examples) are not modelled — and a prefix modifier (`{var:3}`) on a
//! list value is ignored (RFC §2.4.1: undefined for composite values).
//!
//! Matching semantics (ported from modelcontextprotocol/python-sdk v2.3.0
//! src/mcp/shared/uri_template.py, MIT — see ../NOTICE — with the stricter
//! percent-decoding noted below):
//!
//!   - literal text matches exactly; the variable parts are what is captured;
//!   - `{v}` captures up to the next `/ ? # & ,` and `{.v}`, `{/v}`, `{;v}`,
//!     `{?v}`, `{&v}` up to their own delimiters (never across `/` for the
//!     simple form); a percent-encoded `%2F` still decodes to `/` in the value;
//!   - `{+v}` and `{#v}` may contain `/` (and `,`); they stop at `?` and `#`
//!     (`{#v}` at nothing) so `{+path}{?q}` can separate path from query;
//!   - `{/v*}`, `{.v*}`, `{;v*}` match several segments into a `.list`;
//!   - a trailing `{?a,b}{&c}` run is matched LENIENTLY: the query string is
//!     split on `&`, parameters may come in any order, may be missing (then the
//!     variable is absent from the result), unknown parameters are ignored,
//!     the first occurrence of a name wins; names are compared undecoded;
//!   - a fragment (`#...`) is ignored when such a query tail exists;
//!   - every captured value is percent-decoded; a malformed escape or a result
//!     that is not valid UTF-8 fails the match (Python's `unquote` is lenient
//!     here; this matcher is deliberately not);
//!   - `{v:N}` matches like `{v}` but fails if the decoded value is longer than
//!     N code points.
//!
//! Not every valid template is MATCHABLE. These parse and expand but have no
//! deterministic inverse, and `match` on them returns null (check
//! `Template.unmatchable`, e.g. when registering): a variable name used twice;
//! two `{?...}` expressions; two multi-segment variables (`{+a}`, `{#a}`,
//! explode; each variable of `{+a,b}` counts) in one template; two variables adjacent with no literal between
//! them (`{a}{b}`, `{+path}{ext}` — `{+path}{.ext}` is fine, the operator's own
//! lead character is the literal); explode on `{v*}`, `{+v*}`, `{#v*}`, `{?v*}`,
//! `{&v*}`; an explode variable that is not first in its expression.
//!
//! Complexity: no backtracking and no recursion. The bounded variables left of
//! the multi-segment variable match lazily (first occurrence of the next
//! literal), those right of it greedily (last occurrence of the previous
//! literal), a template without one matches greedily throughout. Every
//! variable costs one linear scan plus one substring search, so a match is
//! O(v·n·m) in the worst case (v variables, URI length n, longest literal m),
//! practically linear; there is no input that makes it super-polynomial.
//! Templates are capped at `max_template_len` bytes and `max_variables`
//! variables, URIs at `max_uri_len` bytes (longer ones do not match).
//!
//! Round trips hold when a value does not contain its operator's delimiter
//! unencoded: `{.ext}` with `ext="tar.gz"` expands to `.tar.gz` and does not
//! match back (the scan stops `ext` at the first `.`), RFC 6570 §1.4's
//! inherent limitation; a `{+v}`/`{#v}` value containing `?` or `#` likewise.
//!
//! The syntax accepted is the RFC's: operators `+ # . / ; ? &`; the reserved
//! operators `= , ! @ |` are an error; variable names are `[A-Za-z0-9_]` with
//! single dots in between (percent-encoded name characters are not accepted);
//! literals may not contain the characters the RFC excludes (space, controls,
//! `" ' < > \ ^ ` | }`) and `%` must start a valid triplet.

const std = @import("std");

/// A variable's value: a string, or a list of strings (RFC 6570's "list").
pub const Value = union(enum) { string: []const u8, list: []const []const u8 };

/// A name/value pair, for `expand` input and `match` output.
pub const Var = struct { name: []const u8, value: Value };

pub const ParseError = error{ InvalidTemplate, OutOfMemory };

/// Longest template `parse` accepts (bytes).
pub const max_template_len = 8192;
/// Most variables `parse` accepts across all expressions.
pub const max_variables = 256;
/// Longest URI `match` looks at; a longer one does not match.
pub const max_uri_len = 65536;

/// RFC 6570 §2.2 expression type.
pub const Operator = enum { simple, reserved, fragment, label, path, param, query, query_cont };

/// One `name`, `name*` or `name:N` in an expression.
pub const VarSpec = struct {
    name: []const u8,
    explode: bool,
    /// Prefix length in code points (`name:N`), 0 for none.
    max_len: u16,
    /// Position among all the template's variables (index into `varNames`).
    index: usize,
};

/// A `{...}` expression: one operator, one or more variables.
pub const Expression = struct { op: Operator, vars: []const VarSpec };

/// Literal text or an expression, in template order.
pub const Part = union(enum) { literal: []const u8, expr: Expression };

/// Expansion behaviour of an operator (RFC 6570 §3.2.1 and Appendix A).
const OpInfo = struct {
    /// Emitted before the first defined variable.
    first: ?u8,
    /// Emitted between defined variables / list items.
    sep: u8,
    /// `name=value` instead of `value`.
    named: bool,
    /// Reserved characters and pct-triplets pass unencoded.
    reserved: bool,
    /// An empty value still gets its `=` (`?`/`&`); `;` emits the bare name.
    empty_eq: bool,
    /// Bytes that end a bounded variable's value when matching.
    stops: []const u8,
};

fn info(op: Operator) OpInfo {
    return switch (op) {
        .simple => .{ .first = null, .sep = ',', .named = false, .reserved = false, .empty_eq = false, .stops = "/?#&," },
        .reserved => .{ .first = null, .sep = ',', .named = false, .reserved = true, .empty_eq = false, .stops = "?#" },
        .fragment => .{ .first = '#', .sep = ',', .named = false, .reserved = true, .empty_eq = false, .stops = "" },
        .label => .{ .first = '.', .sep = '.', .named = false, .reserved = false, .empty_eq = false, .stops = "./?#" },
        .path => .{ .first = '/', .sep = '/', .named = false, .reserved = false, .empty_eq = false, .stops = "/?#" },
        .param => .{ .first = ';', .sep = ';', .named = true, .reserved = false, .empty_eq = false, .stops = ";/?#" },
        .query => .{ .first = '?', .sep = '&', .named = true, .reserved = false, .empty_eq = true, .stops = "&#" },
        .query_cont => .{ .first = '&', .sep = '&', .named = true, .reserved = false, .empty_eq = true, .stops = "&#" },
    };
}

/// A capture in the flattened match-atom sequence.
const Cap = struct {
    index: usize,
    name: []const u8,
    op: Operator,
    explode: bool,
    /// `;name` / `;name=value` (RFC `ifemp`): the scan must accept both forms.
    ifemp: bool,
    max_len: u16,
};

const Atom = union(enum) { lit: []const u8, cap: Cap };

const QueryVar = struct { index: usize, name: []const u8, max_len: u16 };

/// A parsed URI template. All memory (parts, names, match plan) comes from
/// the arena given to `parse`; literals alias the template text, which must
/// outlive the `Template`.
pub const Template = struct {
    parts: []const Part,
    names: []const []const u8,
    /// Match plan, see the module doc. `prefix` / `greedy` / `suffix`: atoms
    /// before, the one multi-segment capture, atoms after (no greedy capture:
    /// everything is in `suffix`).
    prefix: []const Atom = &.{},
    greedy: ?Cap = null,
    suffix: []const Atom = &.{},
    query: []const QueryVar = &.{},
    /// Why `match` cannot work on this template, or null if it can.
    unmatchable: ?[]const u8 = null,

    /// Parses `text`. `InvalidTemplate`: unclosed or stray brace, empty
    /// expression, bad or reserved operator, bad variable name or modifier,
    /// a character the RFC forbids in literals, or `max_template_len` /
    /// `max_variables` exceeded.
    pub fn parse(arena: std.mem.Allocator, text: []const u8) ParseError!Template {
        if (text.len > max_template_len) return error.InvalidTemplate;
        var parts: std.ArrayList(Part) = .empty;
        var names: std.ArrayList([]const u8) = .empty;
        var i: usize = 0;
        while (i < text.len) {
            if (text[i] == '{') {
                const rel = std.mem.findScalar(u8, text[i + 1 ..], '}') orelse return error.InvalidTemplate;
                const expr = try parseExpression(arena, text[i + 1 ..][0..rel], &names);
                try parts.append(arena, .{ .expr = expr });
                i += rel + 2;
            } else {
                const end = std.mem.findScalar(u8, text[i..], '{') orelse text.len - i;
                try checkLiteral(text[i..][0..end]);
                try parts.append(arena, .{ .literal = text[i..][0..end] });
                i += end;
            }
        }
        var t: Template = .{
            .parts = try parts.toOwnedSlice(arena),
            .names = try names.toOwnedSlice(arena),
        };
        try t.plan(arena);
        return t;
    }

    /// The variable names in order of appearance (a name used twice appears
    /// twice). For completion: these are the arguments a client may complete.
    /// Valid as long as the template.
    pub fn varNames(self: Template) []const []const u8 {
        return self.names;
    }

    /// RFC 6570 expansion (§3.2). A variable absent from `vars` is undefined
    /// and skipped; an expression whose variables are all undefined (or empty
    /// lists) expands to nothing. If `vars` names a variable twice the first
    /// wins.
    pub fn expand(self: Template, w: *std.Io.Writer, vars: []const Var) std.Io.Writer.Error!void {
        for (self.parts) |part| switch (part) {
            .literal => |l| try w.writeAll(l),
            .expr => |e| try expandExpression(e, w, vars),
        };
    }

    /// Matches `uri` against the template; null when it does not match (or
    /// the template is `unmatchable`, or `uri` is longer than `max_uri_len`).
    /// The result holds the variables that were present, in template order:
    /// all of them except trailing-query variables that the URI omitted.
    /// `.string` for ordinary variables, `.list` for explode variables. Values
    /// are percent-decoded copies in `arena`; the names alias the template.
    pub fn match(self: Template, arena: std.mem.Allocator, uri: []const u8) error{OutOfMemory}!?[]Var {
        if (self.unmatchable != null or uri.len > max_uri_len) return null;
        const slots = try arena.alloc(?Value, self.names.len);
        @memset(slots, null);
        var m: Matcher = .{ .arena = arena, .uri = uri, .slots = slots };
        var query: ?[]const u8 = null;
        if (self.query.len > 0) {
            // The template's {?...} tail never describes a fragment.
            const no_frag = uri[0 .. std.mem.findScalar(u8, uri, '#') orelse uri.len];
            const q = std.mem.findScalar(u8, no_frag, '?');
            m.uri = no_frag[0 .. q orelse no_frag.len];
            if (q) |p| query = no_frag[p + 1 ..];
        }
        if (!try m.scan(self)) return null;
        if (query) |qs| if (!try m.applyQuery(self.query, qs)) return null;
        var out: std.ArrayList(Var) = .empty;
        for (slots, 0..) |slot, i| {
            if (slot) |v| try out.append(arena, .{ .name = self.names[i], .value = v });
        }
        return try out.toOwnedSlice(arena);
    }

    /// Builds the match plan; sets `unmatchable` instead of failing.
    fn plan(self: *Template, arena: std.mem.Allocator) error{OutOfMemory}!void {
        // Repeated names would need back-references.
        for (self.names, 0..) |a, i| {
            for (self.names[i + 1 ..]) |b| {
                if (std.mem.eql(u8, a, b)) {
                    self.unmatchable = "a variable name is used more than once";
                    return;
                }
            }
        }
        var queries: usize = 0;
        for (self.parts) |part| {
            const e = switch (part) {
                .literal => continue,
                .expr => |e| e,
            };
            if (e.op == .query) queries += 1;
            for (e.vars, 0..) |v, k| {
                if (!v.explode) continue;
                switch (e.op) {
                    .label, .path, .param => {},
                    else => {
                        self.unmatchable = "explode modifier on an operator whose lists cannot be matched";
                        return;
                    },
                }
                if (k != 0) {
                    self.unmatchable = "an explode variable must be first in its expression";
                    return;
                }
            }
        }
        if (queries > 1) {
            self.unmatchable = "more than one {?...} expression";
            return;
        }

        // A trailing {?..}{&..} run is matched as a query string. It needs a
        // leading {?..} (a lone {&x} emits no '?' to split on) and a path
        // portion without a literal ? or # or a ?/# expression (those would
        // swallow the split).
        var split = self.parts.len;
        while (split > 0 and isQueryExpr(self.parts[split - 1])) split -= 1;
        var path_parts = self.parts;
        if (split < self.parts.len and self.parts[split].expr.op == .query and pathHasNoSplit(self.parts[0..split])) {
            var qv: std.ArrayList(QueryVar) = .empty;
            for (self.parts[split..]) |part| {
                for (part.expr.vars) |v| {
                    try qv.append(arena, .{ .index = v.index, .name = v.name, .max_len = v.max_len });
                }
            }
            self.query = try qv.toOwnedSlice(arena);
            path_parts = self.parts[0..split];
        }

        const atoms = try flatten(arena, path_parts);
        var greedy_idx: ?usize = null;
        for (atoms, 0..) |atom, i| {
            const cap = switch (atom) {
                .lit => continue,
                .cap => |c| c,
            };
            if (i > 0 and atoms[i - 1] == .cap) {
                self.unmatchable = "two variables are adjacent with no literal between them";
                return;
            }
            if (cap.explode or cap.op == .reserved or cap.op == .fragment) {
                if (greedy_idx != null) {
                    self.unmatchable = "more than one multi-segment variable ({+v}, {#v}, explode)";
                    return;
                }
                greedy_idx = i;
            }
        }
        if (greedy_idx) |g| {
            self.prefix = atoms[0..g];
            self.greedy = atoms[g].cap;
            self.suffix = atoms[g + 1 ..];
        } else {
            self.suffix = atoms;
        }
    }
};

fn isQueryExpr(p: Part) bool {
    return switch (p) {
        .literal => false,
        .expr => |e| e.op == .query or e.op == .query_cont,
    };
}

fn pathHasNoSplit(parts: []const Part) bool {
    for (parts) |p| switch (p) {
        .literal => |l| if (std.mem.findAny(u8, l, "?#") != null) return false,
        .expr => |e| if (e.op == .query or e.op == .fragment) return false,
    };
    return true;
}

/// Lowers the expressions to literals and single captures: operator prefixes
/// and separators become literal atoms (adjacent literals merged, so the
/// anchors are the longest available); an explode capture carries its own
/// separators and so has no lead literal.
fn flatten(arena: std.mem.Allocator, parts: []const Part) error{OutOfMemory}![]const Atom {
    var atoms: std.ArrayList(Atom) = .empty;
    var lit: std.ArrayList(u8) = .empty;
    for (parts) |part| switch (part) {
        .literal => |l| try lit.appendSlice(arena, l),
        .expr => |e| {
            const oi = info(e.op);
            for (e.vars, 0..) |v, k| {
                const lead_c: ?u8 = if (k == 0) oi.first else oi.sep;
                var cap: Cap = .{ .index = v.index, .name = v.name, .op = e.op, .explode = v.explode, .ifemp = false, .max_len = v.max_len };
                if (!v.explode) {
                    if (lead_c) |c| try lit.append(arena, c);
                    if (oi.named) {
                        try lit.appendSlice(arena, v.name);
                        if (e.op == .param) cap.ifemp = true else try lit.append(arena, '=');
                    }
                }
                if (lit.items.len > 0) {
                    try atoms.append(arena, .{ .lit = try arena.dupe(u8, lit.items) });
                    lit.clearRetainingCapacity();
                }
                try atoms.append(arena, .{ .cap = cap });
            }
        },
    };
    if (lit.items.len > 0) try atoms.append(arena, .{ .lit = try arena.dupe(u8, lit.items) });
    return try atoms.toOwnedSlice(arena);
}

// ── parsing ──────────────────────────────────────────────────────────────

fn parseExpression(arena: std.mem.Allocator, body: []const u8, names: *std.ArrayList([]const u8)) ParseError!Expression {
    if (body.len == 0) return error.InvalidTemplate;
    var op: Operator = .simple;
    var rest = body;
    switch (body[0]) {
        '+' => op = .reserved,
        '#' => op = .fragment,
        '.' => op = .label,
        '/' => op = .path,
        ';' => op = .param,
        '?' => op = .query,
        '&' => op = .query_cont,
        // Reserved for future extensions (RFC 6570 §2.2).
        '=', ',', '!', '@', '|' => return error.InvalidTemplate,
        else => {},
    }
    if (op != .simple) rest = body[1..];
    if (rest.len == 0) return error.InvalidTemplate;
    var vars: std.ArrayList(VarSpec) = .empty;
    var it = std.mem.splitScalar(u8, rest, ',');
    while (it.next()) |spec| {
        if (names.items.len >= max_variables) return error.InvalidTemplate;
        var name = spec;
        var explode = false;
        var max_len: u16 = 0;
        if (spec.len > 0 and spec[spec.len - 1] == '*') {
            explode = true;
            name = spec[0 .. spec.len - 1];
        } else if (std.mem.findScalar(u8, spec, ':')) |c| {
            name = spec[0..c];
            max_len = try parseMaxLen(spec[c + 1 ..]);
        }
        if (!validName(name)) return error.InvalidTemplate;
        try vars.append(arena, .{ .name = name, .explode = explode, .max_len = max_len, .index = names.items.len });
        try names.append(arena, name);
    }
    return .{ .op = op, .vars = try vars.toOwnedSlice(arena) };
}

/// RFC 6570 `max-length = %x31-39 0*3DIGIT`.
fn parseMaxLen(s: []const u8) error{InvalidTemplate}!u16 {
    if (s.len == 0 or s.len > 4 or s[0] == '0') return error.InvalidTemplate;
    var n: u16 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return error.InvalidTemplate;
        n = n * 10 + (c - '0');
    }
    return n;
}

/// `varname = varchar *( ["."] varchar )`, varchar = ALPHA / DIGIT / "_".
fn validName(s: []const u8) bool {
    if (s.len == 0 or s[0] == '.' or s[s.len - 1] == '.') return false;
    var prev_dot = false;
    for (s) |c| {
        if (c == '.') {
            if (prev_dot) return false;
            prev_dot = true;
        } else {
            if (!std.ascii.isAlphanumeric(c) and c != '_') return false;
            prev_dot = false;
        }
    }
    return true;
}

/// RFC 6570 §2.1 `literals`: no controls or space, none of `" ' < > \ ^ ` | { }`,
/// and `%` only as a pct-triplet. Non-ASCII bytes pass (ucschar / iprivate).
fn checkLiteral(s: []const u8) error{InvalidTemplate}!void {
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (c <= 0x20 or c == 0x7f or std.mem.findScalar(u8, "\"'<>\\^`|{}", c) != null) return error.InvalidTemplate;
        if (c == '%') {
            if (i + 2 >= s.len) return error.InvalidTemplate;
            if (!std.ascii.isHex(s[i + 1]) or !std.ascii.isHex(s[i + 2])) return error.InvalidTemplate;
            i += 2;
        }
    }
}

// ── expansion ────────────────────────────────────────────────────────────

fn lookup(vars: []const Var, name: []const u8) ?Value {
    for (vars) |v| if (std.mem.eql(u8, v.name, name)) return v.value;
    return null;
}

fn lead(w: *std.Io.Writer, oi: OpInfo, first: *bool) std.Io.Writer.Error!void {
    if (first.*) {
        first.* = false;
        if (oi.first) |c| try w.writeByte(c);
    } else try w.writeByte(oi.sep);
}

/// One `name=value` / `value` item (RFC 3.2.1 with `ifemp`).
fn writeItem(w: *std.Io.Writer, oi: OpInfo, name: []const u8, s: []const u8) std.Io.Writer.Error!void {
    if (oi.named) {
        try w.writeAll(name);
        if (s.len == 0) {
            if (oi.empty_eq) try w.writeByte('=');
            return;
        }
        try w.writeByte('=');
    }
    try writeEncoded(w, s, oi.reserved);
}

fn expandExpression(e: Expression, w: *std.Io.Writer, vars: []const Var) std.Io.Writer.Error!void {
    const oi = info(e.op);
    var first = true;
    for (e.vars) |spec| {
        const value = lookup(vars, spec.name) orelse continue;
        switch (value) {
            .string => |s| {
                try lead(w, oi, &first);
                try writeItem(w, oi, spec.name, if (spec.max_len != 0) truncate(s, spec.max_len) else s);
            },
            .list => |items| {
                if (items.len == 0) continue; // an empty list is undefined
                if (spec.explode) {
                    for (items) |item| {
                        try lead(w, oi, &first);
                        try writeItem(w, oi, spec.name, item);
                    }
                } else {
                    try lead(w, oi, &first);
                    const all_empty = items.len == 1 and items[0].len == 0;
                    if (oi.named) {
                        try w.writeAll(spec.name);
                        if (all_empty) {
                            if (oi.empty_eq) try w.writeByte('=');
                            continue;
                        }
                        try w.writeByte('=');
                    }
                    for (items, 0..) |item, i| {
                        if (i != 0) try w.writeByte(',');
                        try writeEncoded(w, item, oi.reserved);
                    }
                }
            },
        }
    }
}

fn isUnreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~';
}

const reserved_chars = ":/?#[]@!$&'()*+,;=";

/// Percent-encodes `s`: everything but unreserved characters, and for
/// `reserved` (`{+v}`, `{#v}`) also the reserved set and existing `%XX`
/// triplets pass; a lone `%` is always `%25`.
fn writeEncoded(w: *std.Io.Writer, s: []const u8, reserved: bool) std.Io.Writer.Error!void {
    const hex = "0123456789ABCDEF";
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        const c = s[i];
        if (isUnreserved(c) or (reserved and std.mem.findScalar(u8, reserved_chars, c) != null)) {
            try w.writeByte(c);
        } else if (reserved and c == '%' and i + 2 < s.len and std.ascii.isHex(s[i + 1]) and std.ascii.isHex(s[i + 2])) {
            try w.writeAll(s[i..][0..3]);
            i += 2;
        } else {
            try w.writeAll(&.{ '%', hex[c >> 4], hex[c & 15] });
        }
    }
}

/// The prefix of `s` holding at most `n` code points (invalid bytes count 1).
fn truncate(s: []const u8, n: usize) []const u8 {
    var i: usize = 0;
    var count: usize = 0;
    while (i < s.len and count < n) : (count += 1) {
        i += @min(std.unicode.utf8ByteSequenceLength(s[i]) catch 1, s.len - i);
    }
    return s[0..i];
}

fn codepoints(s: []const u8) usize {
    var i: usize = 0;
    var count: usize = 0;
    while (i < s.len) : (count += 1) {
        i += @min(std.unicode.utf8ByteSequenceLength(s[i]) catch 1, s.len - i);
    }
    return count;
}

// ── matching ─────────────────────────────────────────────────────────────

/// Percent-decodes `raw` into a copy; null on a malformed escape or when the
/// result is not valid UTF-8.
fn decode(arena: std.mem.Allocator, raw: []const u8) error{OutOfMemory}!?[]const u8 {
    var out = try arena.alloc(u8, raw.len);
    var n: usize = 0;
    var i: usize = 0;
    while (i < raw.len) : (n += 1) {
        if (raw[i] == '%') {
            if (i + 2 >= raw.len) return null;
            const hi = std.fmt.charToDigit(raw[i + 1], 16) catch return null;
            const lo = std.fmt.charToDigit(raw[i + 2], 16) catch return null;
            out[n] = hi * 16 + lo;
            i += 3;
        } else {
            out[n] = raw[i];
            i += 1;
        }
    }
    if (!std.unicode.utf8ValidateSlice(out[0..n])) return null;
    return out[0..n];
}

const Matcher = struct {
    arena: std.mem.Allocator,
    uri: []const u8,
    slots: []?Value,

    fn put(self: *Matcher, index: usize, max_len: u16, raw: []const u8) error{OutOfMemory}!bool {
        const dec = (try decode(self.arena, raw)) orelse return false;
        if (max_len != 0 and codepoints(dec) > max_len) return false;
        self.slots[index] = .{ .string = dec };
        return true;
    }

    fn scan(self: *Matcher, t: Template) error{OutOfMemory}!bool {
        const n = self.uri.len;
        const g = t.greedy orelse {
            // The suffix is the whole template, anchored at position 0.
            const start = (try self.scanSuffix(t.suffix, n, true)) orelse return false;
            return start == 0;
        };
        // The parser rejected a capture next to the greedy one, so a non-empty
        // suffix starts with a literal: its anchor does not depend on how far
        // the prefix reaches. Scan it first, then bound the prefix by it.
        const suffix_start = (try self.scanSuffix(t.suffix, n, false)) orelse return false;
        const prefix_end = (try self.scanPrefix(t.prefix, suffix_start)) orelse return false;
        if (suffix_start < prefix_end) return false;
        const value = (try self.extractGreedy(g, self.uri[prefix_end..suffix_start])) orelse return false;
        self.slots[g.index] = value;
        return true;
    }

    /// Atoms right to left from `end`; returns where they start. Each bounded
    /// capture takes the shortest span that lets the literal before it match
    /// (rightmost occurrence), the first atom is pinned to 0 when `anchored`.
    fn scanSuffix(self: *Matcher, atoms: []const Atom, end: usize, anchored: bool) error{OutOfMemory}!?usize {
        const uri = self.uri;
        var pos = end;
        var i = atoms.len;
        while (i > 0) {
            i -= 1;
            switch (atoms[i]) {
                .lit => |text| {
                    if (pos < text.len or !std.mem.eql(u8, uri[pos - text.len .. pos], text)) return null;
                    pos -= text.len;
                },
                .cap => |c| {
                    const stops = info(c.op).stops;
                    const prev: ?[]const u8 = if (i > 0) atoms[i - 1].lit else null;
                    var earliest = pos;
                    while (earliest > 0 and std.mem.findScalar(u8, stops, uri[earliest - 1]) == null) earliest -= 1;
                    if (c.ifemp) {
                        // ";name" then optionally "=value"; try the bare form first.
                        if (std.mem.endsWith(u8, uri[0..pos], prev.?)) {
                            if (!try self.put(c.index, c.max_len, "")) return null;
                            continue;
                        }
                        const eq = std.mem.findScalar(u8, uri[earliest..pos], '=') orelse return null;
                        if (!try self.put(c.index, c.max_len, uri[earliest + eq + 1 .. pos])) return null;
                        pos = earliest + eq;
                        continue;
                    }
                    var start: usize = earliest;
                    if (prev) |p| {
                        if (anchored and i == 1) {
                            // The template's first literal is fixed at 0; rfind
                            // would land inside the value if it repeats there.
                            start = p.len;
                            if (start < earliest or start > pos) return null;
                        } else {
                            const idx = std.mem.findLast(u8, uri[0..pos], p) orelse return null;
                            if (idx + p.len < earliest) return null;
                            start = idx + p.len;
                        }
                    }
                    if (!try self.put(c.index, c.max_len, uri[start..pos])) return null;
                    pos = start;
                },
            }
        }
        return pos;
    }

    /// Atoms left to right from 0, not past `limit`; returns where they end.
    /// Each bounded capture takes the shortest span up to the next literal
    /// (first occurrence), leaving the greedy capture as much as possible.
    fn scanPrefix(self: *Matcher, atoms: []const Atom, limit: usize) error{OutOfMemory}!?usize {
        const uri = self.uri;
        var pos: usize = 0;
        for (atoms, 0..) |atom, i| {
            switch (atom) {
                .lit => |text| {
                    const end = pos + text.len;
                    if (end > limit or !std.mem.eql(u8, uri[pos..end], text)) return null;
                    pos = end;
                },
                .cap => |c| {
                    const nxt = atoms[i + 1].lit;
                    if (c.ifemp) {
                        if (std.mem.startsWith(u8, uri[pos..], nxt)) {
                            // The next literal starts here: the value is empty.
                            if (!try self.put(c.index, c.max_len, "")) return null;
                            continue;
                        }
                        if (pos < limit and uri[pos] == '=') pos += 1 else return null;
                    }
                    const stops = info(c.op).stops;
                    var latest = pos;
                    while (latest < limit and std.mem.findScalar(u8, stops, uri[latest]) == null) latest += 1;
                    const hi = @min(uri.len, latest + nxt.len);
                    const rel = std.mem.find(u8, uri[pos..hi], nxt) orelse return null;
                    if (!try self.put(c.index, c.max_len, uri[pos..][0..rel])) return null;
                    pos += rel;
                },
            }
        }
        return pos;
    }

    /// Decodes the span the multi-segment capture got. Scalar: validated
    /// against the operator's stop set. Explode: must be empty or start with
    /// the separator and splits into items (`;` items are `name=value`).
    fn extractGreedy(self: *Matcher, c: Cap, raw: []const u8) error{OutOfMemory}!?Value {
        const oi = info(c.op);
        if (!c.explode) {
            if (std.mem.findAny(u8, raw, oi.stops) != null) return null;
            const dec = (try decode(self.arena, raw)) orelse return null;
            if (c.max_len != 0 and codepoints(dec) > c.max_len) return null;
            return .{ .string = dec };
        }
        if (raw.len == 0) return .{ .list = &.{} };
        if (raw[0] != oi.sep) return null;
        for (raw) |ch| {
            if (ch != oi.sep and std.mem.findScalar(u8, oi.stops, ch) != null) return null;
        }
        var items: std.ArrayList([]const u8) = .empty;
        var it = std.mem.splitScalar(u8, raw[1..], oi.sep);
        while (it.next()) |seg0| {
            var seg = seg0;
            if (oi.named) {
                if (seg.len > c.name.len and std.mem.startsWith(u8, seg, c.name) and seg[c.name.len] == '=') {
                    seg = seg[c.name.len + 1 ..];
                } else if (std.mem.eql(u8, seg, c.name)) {
                    seg = "";
                } else return null;
            }
            try items.append(self.arena, (try decode(self.arena, seg)) orelse return null);
        }
        return .{ .list = try items.toOwnedSlice(self.arena) };
    }

    /// Lenient query: any order, missing ones stay absent, extras ignored,
    /// first occurrence wins, names compared undecoded.
    fn applyQuery(self: *Matcher, qvars: []const QueryVar, query: []const u8) error{OutOfMemory}!bool {
        var it = std.mem.splitScalar(u8, query, '&');
        while (it.next()) |pair| {
            const eq = std.mem.findScalar(u8, pair, '=');
            const name = pair[0 .. eq orelse pair.len];
            const raw = if (eq) |p| pair[p + 1 ..] else "";
            if (name.len == 0) continue;
            for (qvars) |q| {
                if (!std.mem.eql(u8, q.name, name) or self.slots[q.index] != null) continue;
                if (!try self.put(q.index, q.max_len, raw)) return false;
            }
        }
        return true;
    }
};

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

fn sv(name: []const u8, v: []const u8) Var {
    return .{ .name = name, .value = .{ .string = v } };
}

fn lv(name: []const u8, v: []const []const u8) Var {
    return .{ .name = name, .value = .{ .list = v } };
}

/// The variables of RFC 6570 §1.2 / §3.2 (the associative-array "keys" and
/// "empty_keys" are not modelled by `Value`; their examples are not tested).
const rfc_vars = [_]Var{
    sv("var", "value"),
    sv("hello", "Hello World!"),
    sv("empty", ""),
    sv("path", "/foo/bar"),
    sv("x", "1024"),
    sv("y", "768"),
    sv("who", "fred"),
    sv("half", "50%"),
    sv("dub", "me/too"),
    sv("base", "http://example.com/home/"),
    sv("v", "6"),
    lv("list", &.{ "red", "green", "blue" }),
    lv("count", &.{ "one", "two", "three" }),
    lv("dom", &.{ "example", "com" }),
};

const Case = struct { []const u8, []const u8 };

fn expandToOwned(arena: std.mem.Allocator, tpl: []const u8, vars: []const Var) ![]const u8 {
    const t = try Template.parse(arena, tpl);
    var aw: std.Io.Writer.Allocating = .init(arena);
    try t.expand(&aw.writer, vars);
    return aw.written();
}

fn expectExpansions(cases: []const Case) !void {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    for (cases) |c| {
        const got = try expandToOwned(arena_state.allocator(), c[0], &rfc_vars);
        testing.expectEqualStrings(c[1], got) catch |err| {
            std.debug.print("template: {s}\n", .{c[0]});
            return err;
        };
    }
}

test "RFC 6570 section 1.2: level 1 and 2 examples" {
    try expectExpansions(&.{
        .{ "{var}", "value" },
        .{ "{hello}", "Hello%20World%21" },
        .{ "{+var}", "value" },
        .{ "{+hello}", "Hello%20World!" },
        .{ "{+path}/here", "/foo/bar/here" },
        .{ "here?ref={+path}", "here?ref=/foo/bar" },
        .{ "X{#var}", "X#value" },
        .{ "X{#hello}", "X#Hello%20World!" },
    });
}

test "RFC 6570 section 1.2: level 3 examples" {
    try expectExpansions(&.{
        .{ "map?{x,y}", "map?1024,768" },
        .{ "{x,hello,y}", "1024,Hello%20World%21,768" },
        .{ "{+x,hello,y}", "1024,Hello%20World!,768" },
        .{ "{+path,x}/here", "/foo/bar,1024/here" },
        .{ "{#x,hello,y}", "#1024,Hello%20World!,768" },
        .{ "{#path,x}/here", "#/foo/bar,1024/here" },
        .{ "X{.var}", "X.value" },
        .{ "X{.x,y}", "X.1024.768" },
        .{ "{/var}", "/value" },
        .{ "{/var,x}/here", "/value/1024/here" },
        .{ "{;x,y}", ";x=1024;y=768" },
        .{ "{;x,y,empty}", ";x=1024;y=768;empty" },
        .{ "{?x,y}", "?x=1024&y=768" },
        .{ "{?x,y,empty}", "?x=1024&y=768&empty=" },
        .{ "?fixed=yes{&x}", "?fixed=yes&x=1024" },
        .{ "{&x,y,empty}", "&x=1024&y=768&empty=" },
    });
}

test "RFC 6570 section 1.2: level 4 examples" {
    try expectExpansions(&.{
        .{ "{var:3}", "val" },
        .{ "{var:30}", "value" },
        .{ "{list}", "red,green,blue" },
        .{ "{list*}", "red,green,blue" },
        .{ "{+path:6}/here", "/foo/b/here" },
        .{ "{+list}", "red,green,blue" },
        .{ "{+list*}", "red,green,blue" },
        .{ "{#path:6}/here", "#/foo/b/here" },
        .{ "{#list}", "#red,green,blue" },
        .{ "{#list*}", "#red,green,blue" },
        .{ "X{.var:3}", "X.val" },
        .{ "X{.list}", "X.red,green,blue" },
        .{ "X{.list*}", "X.red.green.blue" },
        .{ "{/var:1,var}", "/v/value" },
        .{ "{/list}", "/red,green,blue" },
        .{ "{/list*}", "/red/green/blue" },
        .{ "{/list*,path:4}", "/red/green/blue/%2Ffoo" },
        .{ "{;hello:5}", ";hello=Hello" },
        .{ "{;list}", ";list=red,green,blue" },
        .{ "{;list*}", ";list=red;list=green;list=blue" },
        .{ "{?var:3}", "?var=val" },
        .{ "{?list}", "?list=red,green,blue" },
        .{ "{?list*}", "?list=red&list=green&list=blue" },
        .{ "{&var:3}", "&var=val" },
        .{ "{&list}", "&list=red,green,blue" },
        .{ "{&list*}", "&list=red&list=green&list=blue" },
    });
}

test "RFC 6570 section 3.2: per-operator examples" {
    try expectExpansions(&.{
        // 3.2.1 lists
        .{ "{count}", "one,two,three" },
        .{ "{count*}", "one,two,three" },
        .{ "{/count}", "/one,two,three" },
        .{ "{/count*}", "/one/two/three" },
        .{ "{;count}", ";count=one,two,three" },
        .{ "{;count*}", ";count=one;count=two;count=three" },
        .{ "{?count}", "?count=one,two,three" },
        .{ "{?count*}", "?count=one&count=two&count=three" },
        .{ "{&count*}", "&count=one&count=two&count=three" },
        // 3.2.2
        .{ "{half}", "50%25" },
        .{ "O{empty}X", "OX" },
        .{ "O{undef}X", "OX" },
        .{ "{x,y}", "1024,768" },
        .{ "?{x,empty}", "?1024," },
        .{ "?{x,undef}", "?1024" },
        .{ "?{undef,y}", "?768" },
        // 3.2.3
        .{ "{+half}", "50%25" },
        .{ "{base}index", "http%3A%2F%2Fexample.com%2Fhome%2Findex" },
        .{ "{+base}index", "http://example.com/home/index" },
        .{ "O{+empty}X", "OX" },
        .{ "O{+undef}X", "OX" },
        .{ "up{+path}{var}/here", "up/foo/barvalue/here" },
        // 3.2.4
        .{ "{#half}", "#50%25" },
        .{ "foo{#empty}", "foo#" },
        .{ "foo{#undef}", "foo" },
        // 3.2.5
        .{ "{.who}", ".fred" },
        .{ "{.who,who}", ".fred.fred" },
        .{ "{.half,who}", ".50%25.fred" },
        .{ "www{.dom*}", "www.example.com" },
        .{ "X{.empty}", "X." },
        .{ "X{.undef}", "X" },
        // 3.2.6
        .{ "{/who}", "/fred" },
        .{ "{/who,who}", "/fred/fred" },
        .{ "{/half,who}", "/50%25/fred" },
        .{ "{/who,dub}", "/fred/me%2Ftoo" },
        .{ "{/var,empty}", "/value/" },
        .{ "{/var,undef}", "/value" },
        // 3.2.7
        .{ "{;who}", ";who=fred" },
        .{ "{;half}", ";half=50%25" },
        .{ "{;empty}", ";empty" },
        .{ "{;v,empty,who}", ";v=6;empty;who=fred" },
        .{ "{;v,bar,who}", ";v=6;who=fred" },
        .{ "{;x,y,undef}", ";x=1024;y=768" },
        // 3.2.8
        .{ "{?who}", "?who=fred" },
        .{ "{?half}", "?half=50%25" },
        .{ "{?x,y,undef}", "?x=1024&y=768" },
        // 3.2.9
        .{ "{&who}", "&who=fred" },
        .{ "{&half}", "&half=50%25" },
        .{ "{&x,y,undef}", "&x=1024&y=768" },
    });
}

test "expand edge cases: empty list, prefix on code points, first duplicate wins" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const none: []const []const u8 = &.{};
    try testing.expectEqualStrings("a", try expandToOwned(a, "a{?q}", &.{lv("q", none)}));
    try testing.expectEqualStrings("%C3%A1b", try expandToOwned(a, "{w:2}", &.{sv("w", "\u{e1}bc")}));
    try testing.expectEqualStrings("1", try expandToOwned(a, "{k}", &.{ sv("k", "1"), sv("k", "2") }));
    // A list with a single empty item behaves like an empty string under ifemp.
    const one_empty: []const []const u8 = &.{""};
    try testing.expectEqualStrings(";k", try expandToOwned(a, "{;k}", &.{lv("k", one_empty)}));
    try testing.expectEqualStrings("?k=", try expandToOwned(a, "{?k}", &.{lv("k", one_empty)}));
}

fn valueEql(a: Value, b: Value) bool {
    switch (a) {
        .string => |x| return b == .string and std.mem.eql(u8, x, b.string),
        .list => |x| {
            if (b != .list or x.len != b.list.len) return false;
            for (x, b.list) |p, q| if (!std.mem.eql(u8, p, q)) return false;
            return true;
        },
    }
}

fn varsEql(want: []const Var, got: []const Var) bool {
    if (want.len != got.len) return false;
    for (want, got) |w, g| {
        if (!std.mem.eql(u8, w.name, g.name) or !valueEql(w.value, g.value)) return false;
    }
    return true;
}

fn expectMatch(arena: std.mem.Allocator, tpl: []const u8, uri: []const u8, want: []const Var) !void {
    const t = try Template.parse(arena, tpl);
    const got = (try t.match(arena, uri)) orelse {
        std.debug.print("no match: {s} <- {s}\n", .{ tpl, uri });
        return error.TestExpectedMatch;
    };
    if (!varsEql(want, got)) {
        std.debug.print("wrong vars: {s} <- {s}\n", .{ tpl, uri });
        return error.TestExpectedEqual;
    }
}

fn expectNoMatch(arena: std.mem.Allocator, tpl: []const u8, uri: []const u8) !void {
    const t = try Template.parse(arena, tpl);
    if (try t.match(arena, uri)) |got| {
        std.debug.print("unexpected match: {s} <- {s} ({d} vars)\n", .{ tpl, uri, got.len });
        return error.TestExpectedNoMatch;
    }
}

test "match round trips: expand with the RFC variables, match gives them back" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // Templates from the RFC examples whose inverse is defined: no prefix
    // modifier (lossy), no repeated name, no simple-operator explode, no
    // non-explode list (its value contains the ',' that a simple variable
    // stops at).
    const templates = [_][]const u8{
        "{var}",          "{hello}",      "{half}",           "{+var}",
        "{+hello}",       "{+path}/here", "here?ref={+path}", "X{#var}",
        "X{#hello}",      "map?{x,y}",    "{x,hello,y}",      "X{.var}",
        "X{.x,y}",        "{/var}",       "{/var,x}/here",    "{;x,y}",
        "{;x,y,empty}",   "{?x,y}",       "{?x,y,empty}",     "?fixed=yes{&x}",
        "{&x,y,empty}",   "O{empty}X",    "?{x,empty}",       "foo{#empty}",
        "X{.empty}",      "{/who,dub}",   "{/var,empty}",     "{/half,who}",
        "{;v,empty,who}", "{;half}",      "{?half}",          "{&half}",
        "{base}index",    "{+base}index", "{/list*}",         "{/count*}",
        "X{.list*}",      "www{.dom*}",   "{;list*}",         "{;count*}",
        "{.half,who}",    "{#half}",
    };
    for (templates) |tpl| {
        const t = try Template.parse(a, tpl);
        if (t.unmatchable) |why| {
            std.debug.print("unmatchable: {s}: {s}\n", .{ tpl, why });
            return error.TestUnexpectedResult;
        }
        const uri = try expandToOwned(a, tpl, &rfc_vars);
        const got = (try t.match(a, uri)) orelse {
            std.debug.print("round trip lost: {s} -> {s}\n", .{ tpl, uri });
            return error.TestExpectedMatch;
        };
        try testing.expectEqual(t.varNames().len, got.len);
        for (got) |g| {
            const orig = lookup(&rfc_vars, g.name).?;
            if (!valueEql(orig, g.value)) {
                std.debug.print("round trip differs: {s} -> {s} var {s}\n", .{ tpl, uri, g.name });
                return error.TestExpectedEqual;
            }
        }
    }
}

test "match: specific shapes" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // `var` is used twice: unmatchable by design.
    try expectNoMatch(a, "{/var:1,var}", "/v/value");
    try expectMatch(a, "{var:3}", "val", &.{sv("var", "val")});
    try expectNoMatch(a, "{var:3}", "value");
    try expectMatch(a, "{;x}", ";x", &.{sv("x", "")});
    try expectMatch(a, "{;x}{;y}", ";x=1;y", &.{ sv("x", "1"), sv("y", "") });
    try expectNoMatch(a, "{;x}", ";xy=1");
    try expectMatch(a, "{+path}{.ext}", "/a/b.txt", &.{ sv("path", "/a/b"), sv("ext", "txt") });
    try expectMatch(a, "a/{x}/b/{y}", "a/1/b/2", &.{ sv("x", "1"), sv("y", "2") });
    try expectMatch(a, "{/seg*}", "", &.{lv("seg", &.{})});
    try expectMatch(a, "/files{/path*}", "/files/a//c", &.{lv("path", &.{ "a", "", "c" })});
    try expectMatch(a, "/files{/path*}/raw", "/files/a/b/raw", &.{lv("path", &.{ "a", "b" })});
    try expectNoMatch(a, "/files{/path*}", "/files/a?x");
    try expectNoMatch(a, "/files{/path*}", "/filesa");
    try expectNoMatch(a, "{/seg*}", "x");
}

test "match: users://{id}/posts{?page} and lenient queries" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const tpl = "users://{id}/posts{?page}";
    try expectMatch(a, tpl, "users://42/posts", &.{sv("id", "42")});
    try expectMatch(a, tpl, "users://42/posts?page=3", &.{ sv("id", "42"), sv("page", "3") });
    try expectMatch(a, tpl, "users://42/posts?x=1&page=3&y=2#frag", &.{ sv("id", "42"), sv("page", "3") });
    try expectMatch(a, tpl, "users://42/posts?page=1&page=2", &.{ sv("id", "42"), sv("page", "1") });
    try expectMatch(a, tpl, "users://42/posts?page", &.{ sv("id", "42"), sv("page", "") });
    try expectMatch(a, tpl, "users://a%20b/posts?page=%E2%82%AC", &.{ sv("id", "a b"), sv("page", "\u{20ac}") });
    // Any order, partial, with a continuation expression.
    const logs = "logs://{service}{?since,level}{&limit}";
    try expectMatch(a, logs, "logs://api?level=error&since=5m", &.{ sv("service", "api"), sv("since", "5m"), sv("level", "error") });
    try expectMatch(a, logs, "logs://api", &.{sv("service", "api")});
    try expectMatch(a, logs, "logs://api?limit=9", &.{ sv("service", "api"), sv("limit", "9") });
    // Names are compared undecoded: %74oken is not "token".
    try expectMatch(a, "x{?token}", "x?%74oken=evil&token=real", &.{sv("token", "real")});
    try expectNoMatch(a, tpl, "users://42/post?page=3");
    try expectNoMatch(a, tpl, "users://4/2/posts");
    // A bad escape in a wanted parameter fails, in an unknown one is ignored.
    try expectNoMatch(a, tpl, "users://42/posts?page=%zz");
    try expectMatch(a, tpl, "users://42/posts?other=%zz", &.{sv("id", "42")});
}

test "MCP spec example: file:///{path}" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // docs/specification/2026-07-28/server/resources.mdx
    try expectMatch(a, "file:///{path}", "file:///example.txt", &.{sv("path", "example.txt")});
    try expectMatch(a, "file:///{path}", "file:///hello%20world.txt", &.{sv("path", "hello world.txt")});
    // A simple variable never spans '/': the spec's multi-segment example
    // URI needs {+path} (or an encoded %2F, which decodes to '/').
    try expectNoMatch(a, "file:///{path}", "file:///project/src/main.rs");
    try expectMatch(a, "file:///{path}", "file:///project%2Fsrc%2Fmain.rs", &.{sv("path", "project/src/main.rs")});
    try expectMatch(a, "file:///{+path}", "file:///project/src/main.rs", &.{sv("path", "project/src/main.rs")});
    try expectMatch(a, "file:///{+path}", "file:///", &.{sv("path", "")});
    const t = try Template.parse(a, "file:///{path}");
    try testing.expectEqual(@as(usize, 1), t.varNames().len);
    try testing.expectEqualStrings("path", t.varNames()[0]);
}

test "negative: wrong literal, extra segment, bad escape, bad UTF-8" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    try expectNoMatch(a, "mem://file/{name}", "mem://files/a");
    try expectNoMatch(a, "mem://file/{name}", "mem://file");
    try expectNoMatch(a, "mem://file/{name}", "xmem://file/a");
    try expectNoMatch(a, "mem://file/{name}", "mem://file/a/b");
    try expectNoMatch(a, "mem://file/{name}", "mem://file/a?b");
    try expectNoMatch(a, "mem://file/{name}", "mem://file/a%2");
    try expectNoMatch(a, "mem://file/{name}", "mem://file/a%zz");
    try expectNoMatch(a, "mem://file/{name}", "mem://file/%");
    try expectNoMatch(a, "mem://file/{name}", "mem://file/%FF");
    try expectNoMatch(a, "mem://file/{name}", "mem://file/%C3");
    try expectNoMatch(a, "mem://file/{+name}", "mem://file/a%zz");
    try expectNoMatch(a, "a{/p*}", "a/%zz");
    try expectNoMatch(a, "{.ext}", ".tar.gz");
    // Longer than max_uri_len never matches.
    const long = try a.alloc(u8, max_uri_len + 1);
    @memset(long, 'a');
    try expectNoMatch(a, "{+all}", long);
}

test "negative: invalid templates" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const bad = [_][]const u8{
        "{",      "{var",  "a{b",       "}",    "a}b",   "{}",     "{+}",   "{/}",    "{a{b}",  "{=a}", "{,a}",  "{!a}",   "{@a}",      "{|a}",
        "{a b}",  "{a-b}", "{.a}{",     "{a,}", "{,}",   "{a,,b}", "{.a.}", "{a..b}", "{a%41}", "{a:}", "{a:0}", "{a:01}", "{a:12345}", "{a:x}",
        "{a:3*}", "{a*3}", "{a**}",     "{*}",  "{a/b}", "{$a}",   "a b",   "a<b",    "a\"b",   "a%",   "a%4",   "a%zz",   "a\\b",      "a^b",
        "a|b",    "a`b",   "tab\there",
    };
    for (bad) |tpl| {
        testing.expectError(error.InvalidTemplate, Template.parse(a, tpl)) catch |err| {
            std.debug.print("accepted: {s}\n", .{tpl});
            return err;
        };
    }
    const too_long = try a.alloc(u8, max_template_len + 1);
    @memset(too_long, 'a');
    try testing.expectError(error.InvalidTemplate, Template.parse(a, too_long));
    var many: std.ArrayList(u8) = .empty;
    try many.append(a, '{');
    for (0..max_variables + 1) |i| try many.print(a, "{s}v{d}", .{ if (i == 0) "" else ",", i });
    try many.append(a, '}');
    try testing.expectError(error.InvalidTemplate, Template.parse(a, many.items));
}

test "valid but unmatchable templates parse, expand, and never match" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const hard = [_][]const u8{
        "{a}{b}", // adjacent variables
        "{+path}{ext}", // multi-segment next to a variable
        "{+a}/x/{#b}", // two multi-segment variables
        "{/a*}/x{/b*}",
        "{a}/{a}", // repeated name
        "{list*}", // explode on a simple operator
        "{+list*}",
        "{?list*}",
        "{?a}x{?b}", // two {?...}
        "{/a,b*}", // explode not first
        "{+x,hello,y}", // each variable of {+a,b} is multi-segment
        "{#path,x}/here",
    };
    for (hard) |tpl| {
        const t = try Template.parse(a, tpl);
        try testing.expect(t.unmatchable != null);
        try testing.expect((try t.match(a, "anything/x/y")) == null);
    }
    // And the adjacent-operator forms that ARE fine.
    for ([_][]const u8{ "{+path}{.ext}", "{a}{.b}", "{a}{/b}", "{a}x{b}" }) |tpl| {
        const t = try Template.parse(a, tpl);
        try testing.expect(t.unmatchable == null);
    }
}

test "varNames lists every variable in order" {
    var arena_state: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena_state.deinit();
    const t = try Template.parse(arena_state.allocator(), "a/{x,y}/{+z}{?p,q*}");
    const names = t.varNames();
    try testing.expectEqual(@as(usize, 5), names.len);
    for ([_][]const u8{ "x", "y", "z", "p", "q" }, names) |want, got| try testing.expectEqualStrings(want, got);
    const dotted = try Template.parse(arena_state.allocator(), "{a.b_c1}");
    try testing.expectEqualStrings("a.b_c1", dotted.varNames()[0]);
}
