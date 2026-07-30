// SPDX-License-Identifier: MIT
//! The render-time value model, plus the Python-compatible textual rendering
//! and operator semantics the reference implementation exposes to templates.
//!
//! Why this type exists at all is argued in SPEC.md §2: neither `std.json.Value`
//! nor `yaml.Value` can express the two distinctions Jinja *requires* at render
//! time — "undefined" as something other than null, and "this string is already
//! markup" as something other than a string. Both are load-bearing (one decides
//! whether a missing variable is an error, the other decides whether output is
//! escaped), so the render value is ours; ingress from caller data is a
//! conversion (`from`, `fromJson`), not a second value model.

const std = @import("std");

pub const Error = error{
    OutOfMemory,
    /// An operation that an undefined value does not support.
    UndefinedValue,
    /// Operand types the operator does not accept (Python `TypeError`).
    TypeMismatch,
    DivisionByZero,
    /// An integer left `i64`, or a construction exceeded a documented cap.
    OutOfRange,
    /// A filter/test/method argument was wrong in kind or count.
    BadArgument,
    /// Reached a corner this engine deliberately does not implement; the
    /// divergence table in SPEC.md names every one.
    Unsupported,
};

/// A string plus the one bit markupsafe carries: whether it is already markup
/// and must not be escaped again. `|safe` sets it, `|escape` produces it.
pub const Str = struct {
    bytes: []const u8,
    safe: bool = false,
};

pub const Pair = struct {
    key: Value,
    value: Value,
};

/// An **ordered** mapping — a slice of pairs in insertion order, never a hash
/// map. Config output order is frequently significant, and both candidate
/// ingress types (`std.json.Value.object` is a `StringArrayHashMap`,
/// `yaml.Value.mapping` is a pair slice) are insertion-ordered, so preserving
/// order here loses nothing and flattening it would.
pub const Map = struct {
    pairs: []const Pair,

    pub fn get(self: Map, key: []const u8) ?Value {
        for (self.pairs) |p| switch (p.key) {
            .string => |s| if (std.mem.eql(u8, s.bytes, key)) return p.value,
            else => {},
        };
        return null;
    }
};

/// A `namespace()` object: the one mutable value in the model, and the only
/// way a `{% set %}` inside a `{% for %}` body can outlive the loop's scope.
pub const Namespace = struct {
    pairs: std.ArrayList(Pair) = .empty,

    pub fn get(self: *const Namespace, key: []const u8) ?Value {
        for (self.pairs.items) |p| switch (p.key) {
            .string => |s| if (std.mem.eql(u8, s.bytes, key)) return p.value,
            else => {},
        };
        return null;
    }

    pub fn set(self: *Namespace, gpa: std.mem.Allocator, key: []const u8, v: Value) !void {
        for (self.pairs.items) |*p| switch (p.key) {
            .string => |s| if (std.mem.eql(u8, s.bytes, key)) {
                p.value = v;
                return;
            },
            else => {},
        };
        try self.pairs.append(gpa, .{ .key = .{ .string = .{ .bytes = key } }, .value = v });
    }
};

/// The `loop` object of a `{% for %}` body. Mutable because `loop.changed()`
/// and `loop.cycle()` are stateful in the reference implementation.
pub const Loop = struct {
    items: []const Value,
    index0: usize = 0,
    depth0: usize = 0,
    last_changed: ?[]const Value = null,
};

/// A missing name, or the result of an operation the reference implementation
/// answers with `Undefined`. `name` is what the message will blame.
pub const Undefined = struct {
    name: []const u8 = "",
};

/// A macro — a `{% macro %}`, or the body a `{% call %}` block hands to
/// `caller()` — closed over the scope it was defined in.
///
/// The payload is **opaque here on purpose**. A macro necessarily refers to
/// syntax (`ast`) and to live scopes (`render`), and both of those sit above
/// this file in the import graph; making `Value` name them would put a cycle at
/// the very bottom of the module. `render.zig` allocates the implementation and
/// owns the only casts of `impl`, so the unsafety is one file wide. `name` is
/// carried in the clear because `repr()` and `macro.name` need it without a
/// cast.
pub const MacroRef = struct {
    name: []const u8,
    impl: *const anyopaque,
};

pub const Value = union(enum) {
    undef: Undefined,
    none,
    boolean: bool,
    integer: i64,
    float: f64,
    string: Str,
    list: []const Value,
    /// Distinct from `list` because Python's `repr` is — `('a', 1)` rather
    /// than `['a', 1]` — and `dictsort`/`items` produce tuples that templates
    /// routinely render directly.
    tuple: []const Value,
    map: Map,
    namespace: *Namespace,
    loop: *Loop,
    macro: MacroRef,

    pub const empty_string: Value = .{ .string = .{ .bytes = "" } };

    pub fn str(bytes: []const u8) Value {
        return .{ .string = .{ .bytes = bytes } };
    }

    pub fn markup(bytes: []const u8) Value {
        return .{ .string = .{ .bytes = bytes, .safe = true } };
    }

    pub fn isUndefined(self: Value) bool {
        return self == .undef;
    }

    /// Python truthiness: 0, 0.0, "", [], {}, None, False are falsey.
    /// Undefined is falsey under the lenient policy; the strict policy refuses
    /// the question before it reaches here (see render.zig).
    pub fn truthy(self: Value) bool {
        return switch (self) {
            .undef => false,
            .none => false,
            .boolean => |b| b,
            .integer => |i| i != 0,
            .float => |f| f != 0.0,
            .string => |s| s.bytes.len != 0,
            .list, .tuple => |l| l.len != 0,
            .map => |m| m.pairs.len != 0,
            .namespace => true,
            .loop => |l| l.items.len != 0,
            .macro => true,
        };
    }

    /// The Python type name, for error messages and the `is` tests.
    pub fn typeName(self: Value) []const u8 {
        return switch (self) {
            .undef => "undefined",
            .none => "NoneType",
            .boolean => "bool",
            .integer => "int",
            .float => "float",
            .string => "str",
            .list => "list",
            .tuple => "tuple",
            .macro => "macro",
            .map, .namespace, .loop => "dict",
        };
    }
};

// ── ingress ─────────────────────────────────────────────────────────────────

/// Build a `Value` from ordinary Zig data at comptime-known types. Structs
/// become **ordered** maps in field-declaration order, `[]const u8` becomes a
/// string (not a list of ints), optionals become `none` when null, enums become
/// their tag name, and a `Value` passes through untouched.
///
/// Everything is allocated from `arena`; nothing is copied that does not have
/// to be (string bytes are borrowed from `v`, so `v`'s backing memory must
/// outlive the render).
pub fn from(arena: std.mem.Allocator, v: anytype) Error!Value {
    const T = @TypeOf(v);
    if (T == Value) return v;
    if (T == Str) return .{ .string = v };
    return switch (@typeInfo(T)) {
        .null, .void => .none,
        .bool => .{ .boolean = v },
        .int, .comptime_int => .{ .integer = std.math.cast(i64, v) orelse return error.OutOfRange },
        .float, .comptime_float => .{ .float = @floatCast(v) },
        .@"enum" => Value.str(@tagName(v)),
        .enum_literal => Value.str(@tagName(v)),
        .optional => if (v) |inner| try from(arena, inner) else .none,
        .array => try fromSlice(arena, &v),
        .pointer => |p| switch (p.size) {
            .one => switch (@typeInfo(p.child)) {
                .array => try fromSlice(arena, @as([]const std.meta.Elem(p.child), v)),
                else => try from(arena, v.*),
            },
            .slice => try fromSlice(arena, v),
            else => error.Unsupported,
        },
        .@"struct" => |s| blk: {
            if (s.is_tuple) {
                var items = try arena.alloc(Value, s.fields.len);
                inline for (s.fields, 0..) |f, i| items[i] = try from(arena, @field(v, f.name));
                break :blk .{ .tuple = items };
            }
            var pairs = try arena.alloc(Pair, s.fields.len);
            inline for (s.fields, 0..) |f, i| {
                pairs[i] = .{ .key = Value.str(f.name), .value = try from(arena, @field(v, f.name)) };
            }
            break :blk .{ .map = .{ .pairs = pairs } };
        },
        else => error.Unsupported,
    };
}

fn fromSlice(arena: std.mem.Allocator, s: anytype) Error!Value {
    const Elem = std.meta.Elem(@TypeOf(s));
    if (Elem == u8) return Value.str(s);
    var items = try arena.alloc(Value, s.len);
    for (s, 0..) |e, i| items[i] = try from(arena, e);
    return .{ .list = items };
}

/// Adapter for `std.json.Value` — std only, so using it costs no module
/// dependency. Object order is preserved (`ObjectMap` is a
/// `StringArrayHashMap`). JSON has no undefined and no markup, so every string
/// arrives unsafe, which is the correct default for untrusted data.
pub fn fromJson(arena: std.mem.Allocator, v: std.json.Value) Error!Value {
    return switch (v) {
        .null => .none,
        .bool => |b| .{ .boolean = b },
        .integer => |i| .{ .integer = i },
        .float => |f| .{ .float = f },
        .number_string => |s| Value.str(s),
        .string => |s| Value.str(s),
        .array => |a| blk: {
            const items = try arena.alloc(Value, a.items.len);
            for (a.items, 0..) |e, i| items[i] = try fromJson(arena, e);
            break :blk .{ .list = items };
        },
        .object => |o| blk: {
            const pairs = try arena.alloc(Pair, o.count());
            var it = o.iterator();
            var i: usize = 0;
            while (it.next()) |e| : (i += 1) {
                pairs[i] = .{ .key = Value.str(e.key_ptr.*), .value = try fromJson(arena, e.value_ptr.*) };
            }
            break :blk .{ .map = .{ .pairs = pairs } };
        },
    };
}

// ── textual rendering (Python `str()` / `repr()`) ────────────────────────────

/// markupsafe's escape set, exactly: `&<>` plus **numeric** entities for the
/// two quotes (`&#34;`/`&#39;`, not `&quot;`/`&#x27;`).
pub fn escapeTo(writer: *std.Io.Writer, bytes: []const u8) Error!void {
    for (bytes) |c| {
        const rep: ?[]const u8 = switch (c) {
            '&' => "&amp;",
            '<' => "&lt;",
            '>' => "&gt;",
            '"' => "&#34;",
            '\'' => "&#39;",
            else => null,
        };
        if (rep) |r| writer.writeAll(r) catch return error.OutOfMemory else writer.writeByte(c) catch return error.OutOfMemory;
    }
}

pub fn escapeAlloc(arena: std.mem.Allocator, bytes: []const u8) Error![]const u8 {
    var aw: std.Io.Writer.Allocating = .init(arena);
    try escapeTo(&aw.writer, bytes);
    return aw.written();
}

fn w(writer: *std.Io.Writer, bytes: []const u8) Error!void {
    writer.writeAll(bytes) catch return error.OutOfMemory;
}

/// `str(v)` — what `{{ v }}` puts in the output before escaping. Undefined
/// renders as the empty string (the lenient policy; the strict policy never
/// gets here).
pub fn strTo(writer: *std.Io.Writer, v: Value) Error!void {
    switch (v) {
        .undef => {},
        .none => try w(writer, "None"),
        .boolean => |b| try w(writer, if (b) "True" else "False"),
        .integer => |i| writer.print("{d}", .{i}) catch return error.OutOfMemory,
        .float => |f| try floatTo(writer, f),
        .string => |s| try w(writer, s.bytes),
        else => try reprTo(writer, v),
    }
}

pub fn strAlloc(arena: std.mem.Allocator, v: Value) Error![]const u8 {
    if (v == .string) return v.string.bytes;
    var aw: std.Io.Writer.Allocating = .init(arena);
    try strTo(&aw.writer, v);
    return aw.written();
}

/// `repr(v)` — the form used for elements *inside* a container, which is why
/// `{{ ['a'] }}` renders `['a']` and not `[a]`.
pub fn reprTo(writer: *std.Io.Writer, v: Value) Error!void {
    switch (v) {
        .string => |s| try reprStrTo(writer, s.bytes),
        .list => |items| {
            try w(writer, "[");
            for (items, 0..) |e, i| {
                if (i != 0) try w(writer, ", ");
                try reprTo(writer, e);
            }
            try w(writer, "]");
        },
        .tuple => |items| {
            try w(writer, "(");
            for (items, 0..) |e, i| {
                if (i != 0) try w(writer, ", ");
                try reprTo(writer, e);
            }
            // Python disambiguates a 1-tuple from a parenthesised value.
            if (items.len == 1) try w(writer, ",");
            try w(writer, ")");
        },
        .map => |m| try reprPairs(writer, m.pairs),
        .namespace => |ns| try reprPairs(writer, ns.pairs.items),
        .loop => try w(writer, "<loop>"),
        .macro => |m| {
            try w(writer, "<Macro '");
            try w(writer, m.name);
            try w(writer, "'>");
        },
        else => try strTo(writer, v),
    }
}

fn reprPairs(writer: *std.Io.Writer, pairs: []const Pair) Error!void {
    try w(writer, "{");
    for (pairs, 0..) |p, i| {
        if (i != 0) try w(writer, ", ");
        try reprTo(writer, p.key);
        try w(writer, ": ");
        try reprTo(writer, p.value);
    }
    try w(writer, "}");
}

/// Python string repr: single quotes, switching to double quotes when the text
/// holds a `'` but no `"`. Bytes >= 0x80 pass through — for valid UTF-8 that
/// matches CPython, which prints printable non-ASCII verbatim.
fn reprStrTo(writer: *std.Io.Writer, bytes: []const u8) Error!void {
    var has_single = false;
    var has_double = false;
    for (bytes) |c| {
        if (c == '\'') has_single = true;
        if (c == '"') has_double = true;
    }
    const q: u8 = if (has_single and !has_double) '"' else '\'';
    writer.writeByte(q) catch return error.OutOfMemory;
    for (bytes) |c| switch (c) {
        '\\' => try w(writer, "\\\\"),
        '\n' => try w(writer, "\\n"),
        '\r' => try w(writer, "\\r"),
        '\t' => try w(writer, "\\t"),
        else => {
            if (c == q) {
                writer.writeByte('\\') catch return error.OutOfMemory;
                writer.writeByte(c) catch return error.OutOfMemory;
            } else if (c < 0x20 or c == 0x7f) {
                writer.print("\\x{x:0>2}", .{c}) catch return error.OutOfMemory;
            } else {
                writer.writeByte(c) catch return error.OutOfMemory;
            }
        },
    };
    writer.writeByte(q) catch return error.OutOfMemory;
}

/// CPython's `repr(float)`: shortest round-trip digits, rendered fixed unless
/// the decimal exponent is `< -4` or `>= 16`, and always carrying a `.0` when
/// there is no fractional part. `1e15` is `1000000000000000.0`; `1e16` is
/// `1e+16`; `1e-5` is `1e-05`.
pub fn floatTo(writer: *std.Io.Writer, f: f64) Error!void {
    if (std.math.isNan(f)) return w(writer, "nan");
    if (std.math.isInf(f)) return w(writer, if (f < 0) "-inf" else "inf");

    var buf: [64]u8 = undefined;
    // Zig's `{e}` is shortest-round-trip scientific: `[-]D[.DDDD]e[-]E`.
    const sci = std.fmt.bufPrint(&buf, "{e}", .{f}) catch return error.OutOfRange;
    const e_at = std.mem.indexOfScalar(u8, sci, 'e').?;
    var mant = sci[0..e_at];
    const exp = std.fmt.parseInt(i32, sci[e_at + 1 ..], 10) catch return error.OutOfRange;

    var neg = false;
    if (mant.len > 0 and mant[0] == '-') {
        neg = true;
        mant = mant[1..];
    }
    // Digits of the mantissa, dot removed: `1.25` -> `125`.
    var digits: [32]u8 = undefined;
    var n: usize = 0;
    for (mant) |c| if (c != '.') {
        digits[n] = c;
        n += 1;
    };

    if (neg) writer.writeByte('-') catch return error.OutOfMemory;
    if (exp < -4 or exp >= 16) {
        writer.writeByte(digits[0]) catch return error.OutOfMemory;
        if (n > 1) {
            writer.writeByte('.') catch return error.OutOfMemory;
            try w(writer, digits[1..n]);
        }
        writer.print("e{c}{d:0>2}", .{ @as(u8, if (exp < 0) '-' else '+'), @abs(exp) }) catch return error.OutOfMemory;
        return;
    }
    if (exp < 0) {
        try w(writer, "0.");
        var z: i32 = -1;
        while (z > exp) : (z -= 1) writer.writeByte('0') catch return error.OutOfMemory;
        try w(writer, digits[0..n]);
        return;
    }
    const int_len: usize = @intCast(exp + 1);
    if (n >= int_len) {
        try w(writer, digits[0..int_len]);
        if (n > int_len) {
            writer.writeByte('.') catch return error.OutOfMemory;
            try w(writer, digits[int_len..n]);
        } else {
            try w(writer, ".0");
        }
    } else {
        try w(writer, digits[0..n]);
        var pad = int_len - n;
        while (pad > 0) : (pad -= 1) writer.writeByte('0') catch return error.OutOfMemory;
        try w(writer, ".0");
    }
}

// ── operators ───────────────────────────────────────────────────────────────

pub const BinOp = enum { add, sub, mul, div, floordiv, mod, pow, concat };
pub const CmpOp = enum { eq, ne, lt, le, gt, ge, in, not_in };

fn asFloat(v: Value) ?f64 {
    return switch (v) {
        .integer => |i| @floatFromInt(i),
        .float => |f| f,
        .boolean => |b| if (b) 1.0 else 0.0,
        else => null,
    };
}

fn asInt(v: Value) ?i64 {
    return switch (v) {
        .integer => |i| i,
        .boolean => |b| @intFromBool(b),
        else => null,
    };
}

fn isNumeric(v: Value) bool {
    return v == .integer or v == .float or v == .boolean;
}

/// Arithmetic with Python 3 semantics: `/` is always float, `//` and `%` floor
/// (so `-7 // 2 == -4` and `-7 % 2 == 1`), `**` stays integral only for a
/// non-negative integer exponent, `+` concatenates strings and lists, and `*`
/// repeats a string or list by an integer.
///
/// `autoescape` only reaches markup propagation: joining a safe string with an
/// unsafe one escapes the unsafe half, mirroring `Markup.__add__`.
pub fn binary(arena: std.mem.Allocator, op: BinOp, a: Value, b: Value) Error!Value {
    if (a == .undef or b == .undef) return error.UndefinedValue;

    if (op == .concat) return concat(arena, &.{ a, b }, false);

    if (op == .add) {
        if (a == .string and b == .string) return joinStrings(arena, a.string, b.string);
        if (a == .list and b == .list) {
            const out = try arena.alloc(Value, a.list.len + b.list.len);
            @memcpy(out[0..a.list.len], a.list);
            @memcpy(out[a.list.len..], b.list);
            return .{ .list = out };
        }
        if (a == .tuple and b == .tuple) {
            const out = try arena.alloc(Value, a.tuple.len + b.tuple.len);
            @memcpy(out[0..a.tuple.len], a.tuple);
            @memcpy(out[a.tuple.len..], b.tuple);
            return .{ .tuple = out };
        }
    }
    if (op == .mul) {
        if (a == .string and isNumeric(b) and b != .float) return repeatStr(arena, a.string, asInt(b).?);
        if (b == .string and isNumeric(a) and a != .float) return repeatStr(arena, b.string, asInt(a).?);
        if (a == .list and isNumeric(b) and b != .float) return repeatList(arena, a.list, asInt(b).?);
        if (b == .list and isNumeric(a) and a != .float) return repeatList(arena, b.list, asInt(a).?);
        if (a == .tuple and isNumeric(b) and b != .float) return repeatTuple(arena, a.tuple, asInt(b).?);
        if (b == .tuple and isNumeric(a) and a != .float) return repeatTuple(arena, b.tuple, asInt(a).?);
    }

    if (!isNumeric(a) or !isNumeric(b)) return error.TypeMismatch;

    const both_int = a != .float and b != .float;
    if (op == .div) {
        const y = asFloat(b).?;
        if (y == 0.0) return error.DivisionByZero;
        return .{ .float = asFloat(a).? / y };
    }
    if (both_int) {
        const x = asInt(a).?;
        const y = asInt(b).?;
        return switch (op) {
            .add => intOf(std.math.add(i64, x, y)),
            .sub => intOf(std.math.sub(i64, x, y)),
            .mul => intOf(std.math.mul(i64, x, y)),
            .floordiv => if (y == 0) error.DivisionByZero else .{ .integer = pyFloorDiv(x, y) },
            .mod => if (y == 0) error.DivisionByZero else .{ .integer = pyMod(x, y) },
            .pow => intPow(x, y),
            .div, .concat => unreachable,
        };
    }
    const x = asFloat(a).?;
    const y = asFloat(b).?;
    return switch (op) {
        .add => .{ .float = x + y },
        .sub => .{ .float = x - y },
        .mul => .{ .float = x * y },
        .floordiv => if (y == 0.0) error.DivisionByZero else .{ .float = @floor(x / y) },
        .mod => if (y == 0.0) error.DivisionByZero else .{ .float = pyFmod(x, y) },
        .pow => .{ .float = std.math.pow(f64, x, y) },
        .div, .concat => unreachable,
    };
}

fn intOf(r: anytype) Error!Value {
    return .{ .integer = r catch return error.OutOfRange };
}

/// Python's `//` and `%`: the quotient floors and the remainder takes the sign
/// of the DIVISOR, so `-7 // 2 == -4` and `7 % -2 == -1`. Zig's `@mod`/`@divFloor`
/// are only defined for a positive divisor, so this is spelled out.
fn pyFloorDiv(x: i64, y: i64) i64 {
    const q = @divTrunc(x, y);
    const r = @rem(x, y);
    return if (r != 0 and ((r < 0) != (y < 0))) q - 1 else q;
}

fn pyMod(x: i64, y: i64) i64 {
    const r = @rem(x, y);
    return if (r != 0 and ((r < 0) != (y < 0))) r + y else r;
}

fn pyFmod(x: f64, y: f64) f64 {
    const r = @rem(x, y);
    return if (r != 0 and ((r < 0) != (y < 0))) r + y else r;
}

fn intPow(x: i64, y: i64) Error!Value {
    if (y < 0) {
        const fx: f64 = @floatFromInt(x);
        const fy: f64 = @floatFromInt(y);
        return .{ .float = std.math.pow(f64, fx, fy) };
    }
    var acc: i64 = 1;
    var i: i64 = 0;
    while (i < y) : (i += 1) {
        acc = std.math.mul(i64, acc, x) catch return error.OutOfRange;
    }
    return .{ .integer = acc };
}

fn joinStrings(arena: std.mem.Allocator, a: Str, b: Str) Error!Value {
    // Markup semantics: if either side is markup the result is markup and the
    // other half is escaped on the way in.
    if (a.safe or b.safe) {
        const ab = if (a.safe) a.bytes else try escapeAlloc(arena, a.bytes);
        const bb = if (b.safe) b.bytes else try escapeAlloc(arena, b.bytes);
        return .{ .string = .{ .bytes = try std.mem.concat(arena, u8, &.{ ab, bb }), .safe = true } };
    }
    return Value.str(try std.mem.concat(arena, u8, &.{ a.bytes, b.bytes }));
}

fn repeatStr(arena: std.mem.Allocator, s: Str, times: i64) Error!Value {
    if (times <= 0) return .{ .string = .{ .bytes = "", .safe = s.safe } };
    const n: usize = @intCast(times);
    if (s.bytes.len * n > max_alloc) return error.OutOfRange;
    const out = try arena.alloc(u8, s.bytes.len * n);
    var i: usize = 0;
    while (i < n) : (i += 1) @memcpy(out[i * s.bytes.len ..][0..s.bytes.len], s.bytes);
    return .{ .string = .{ .bytes = out, .safe = s.safe } };
}

fn repeatList(arena: std.mem.Allocator, l: []const Value, times: i64) Error!Value {
    if (times <= 0) return .{ .list = &.{} };
    const n: usize = @intCast(times);
    if (l.len * n > max_items) return error.OutOfRange;
    const out = try arena.alloc(Value, l.len * n);
    var i: usize = 0;
    while (i < n) : (i += 1) @memcpy(out[i * l.len ..][0..l.len], l);
    return .{ .list = out };
}

fn repeatTuple(arena: std.mem.Allocator, l: []const Value, times: i64) Error!Value {
    const as_list = try repeatList(arena, l, times);
    return .{ .tuple = as_list.list };
}

/// Guardrails on the two operations that can multiply memory from a template
/// literal (`'x' * n`, `range(n)`), so a hostile template cannot exhaust the
/// arena in one expression. Documented in SPEC.md §6.
pub const max_alloc: usize = 1 << 26;
pub const max_items: usize = 1 << 22;

/// `~` (and the autoescape-aware join underneath it). With `autoescape` on this
/// is markupsafe's `markup_join`: every non-markup part is escaped and the
/// result is markup; with it off it is a plain `str.join`.
pub fn concat(arena: std.mem.Allocator, parts: []const Value, autoescape: bool) Error!Value {
    var aw: std.Io.Writer.Allocating = .init(arena);
    for (parts) |p| {
        if (p == .undef) return error.UndefinedValue;
        if (autoescape and !(p == .string and p.string.safe)) {
            var tmp: std.Io.Writer.Allocating = .init(arena);
            try strTo(&tmp.writer, p);
            try escapeTo(&aw.writer, tmp.written());
        } else {
            try strTo(&aw.writer, p);
        }
    }
    return .{ .string = .{ .bytes = aw.written(), .safe = autoescape } };
}

/// `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `not in`.
///
/// Equality never raises: mismatched types are simply unequal, exactly as in
/// Python. Ordering does raise on mismatched types — `1 < 'a'` is a
/// `TypeError` in Python 3 and `error.TypeMismatch` here.
pub fn compare(op: CmpOp, a: Value, b: Value) Error!bool {
    switch (op) {
        .in, .not_in => {
            const found = try contains(b, a);
            return if (op == .in) found else !found;
        },
        .eq, .ne => {
            const e = valueEql(a, b);
            return if (op == .eq) e else !e;
        },
        else => {},
    }
    if (a == .undef or b == .undef) return error.UndefinedValue;

    const ord: std.math.Order = blk: {
        if (isNumeric(a) and isNumeric(b)) {
            if (a != .float and b != .float) break :blk std.math.order(asInt(a).?, asInt(b).?);
            break :blk std.math.order(asFloat(a).?, asFloat(b).?);
        }
        if (a == .string and b == .string) break :blk std.mem.order(u8, a.string.bytes, b.string.bytes);
        if (a == .list and b == .list) break :blk try orderLists(a.list, b.list);
        if (a == .tuple and b == .tuple) break :blk try orderLists(a.tuple, b.tuple);
        return error.TypeMismatch;
    };
    return switch (op) {
        .lt => ord == .lt,
        .le => ord != .gt,
        .gt => ord == .gt,
        .ge => ord != .lt,
        else => unreachable,
    };
}

fn orderLists(a: []const Value, b: []const Value) Error!std.math.Order {
    var i: usize = 0;
    while (i < a.len and i < b.len) : (i += 1) {
        if (valueEql(a[i], b[i])) continue;
        return if (try compare(.lt, a[i], b[i])) .lt else .gt;
    }
    return std.math.order(a.len, b.len);
}

/// Python `==`. Numbers compare across int/float/bool; everything else must
/// match in kind. Two undefineds are equal (mirroring `Undefined.__eq__`),
/// and an undefined equals nothing else.
pub fn valueEql(a: Value, b: Value) bool {
    if (a == .undef or b == .undef) return a == .undef and b == .undef;
    if (isNumeric(a) and isNumeric(b)) {
        if (a != .float and b != .float) return asInt(a).? == asInt(b).?;
        return asFloat(a).? == asFloat(b).?;
    }
    return switch (a) {
        .none => b == .none,
        .string => |s| b == .string and std.mem.eql(u8, s.bytes, b.string.bytes),
        .list => |l| b == .list and listEql(l, b.list),
        .tuple => |l| b == .tuple and listEql(l, b.tuple),
        .map => |m| b == .map and pairsEql(m.pairs, b.map.pairs),
        .namespace => |n| b == .namespace and n == b.namespace,
        .loop => |l| b == .loop and l == b.loop,
        .macro => |m| b == .macro and m.impl == b.macro.impl,
        else => false,
    };
}

fn listEql(a: []const Value, b: []const Value) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| if (!valueEql(x, y)) return false;
    return true;
}

fn pairsEql(a: []const Pair, b: []const Pair) bool {
    if (a.len != b.len) return false;
    // Python dict equality ignores order.
    for (a) |p| {
        var found = false;
        for (b) |q| {
            if (valueEql(p.key, q.key)) {
                if (!valueEql(p.value, q.value)) return false;
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    return true;
}

/// `needle in haystack`: substring for strings, membership for lists, **key**
/// membership for maps.
pub fn contains(haystack: Value, needle: Value) Error!bool {
    return switch (haystack) {
        .string => |s| blk: {
            if (needle != .string) return error.TypeMismatch;
            break :blk std.mem.indexOf(u8, s.bytes, needle.string.bytes) != null;
        },
        .list, .tuple => |l| blk: {
            for (l) |e| if (valueEql(e, needle)) break :blk true;
            break :blk false;
        },
        .map => |m| blk: {
            for (m.pairs) |p| if (valueEql(p.key, needle)) break :blk true;
            break :blk false;
        },
        .namespace => |ns| blk: {
            for (ns.pairs.items) |p| if (valueEql(p.key, needle)) break :blk true;
            break :blk false;
        },
        .undef => error.UndefinedValue,
        else => error.TypeMismatch,
    };
}

/// Split a string into its characters the way Python does — by **codepoint**,
/// not by byte, so `len('ěš') == 2`. Invalid UTF-8 degrades to one byte per
/// character rather than failing; a template engine must not reject data it
/// merely has to copy through.
pub fn chars(arena: std.mem.Allocator, s: Str) Error![]const Value {
    var out: std.ArrayList(Value) = .empty;
    var i: usize = 0;
    while (i < s.bytes.len) {
        const n = std.unicode.utf8ByteSequenceLength(s.bytes[i]) catch 1;
        const end = @min(i + n, s.bytes.len);
        try out.append(arena, .{ .string = .{ .bytes = s.bytes[i..end], .safe = s.safe } });
        i = end;
    }
    return out.items;
}

/// The sequence a `{% for %}` or a sequence filter walks.
pub fn iterate(arena: std.mem.Allocator, v: Value) Error![]const Value {
    return switch (v) {
        .list, .tuple => |l| l,
        .string => |s| try chars(arena, s),
        .map => |m| blk: {
            const out = try arena.alloc(Value, m.pairs.len);
            for (m.pairs, 0..) |p, i| out[i] = p.key;
            break :blk out;
        },
        .namespace => |ns| blk: {
            const out = try arena.alloc(Value, ns.pairs.items.len);
            for (ns.pairs.items, 0..) |p, i| out[i] = p.key;
            break :blk out;
        },
        .undef => error.UndefinedValue,
        else => error.TypeMismatch,
    };
}

/// `len(v)`. Strings count **codepoints**, matching Python.
pub fn length(v: Value) Error!usize {
    return switch (v) {
        .string => |s| std.unicode.utf8CountCodepoints(s.bytes) catch s.bytes.len,
        .list, .tuple => |l| l.len,
        .map => |m| m.pairs.len,
        .namespace => |ns| ns.pairs.items.len,
        .undef => error.UndefinedValue,
        else => error.TypeMismatch,
    };
}
