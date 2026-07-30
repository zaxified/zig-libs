// SPDX-License-Identifier: MIT
//! Walks the tree and writes the output.
//!
//! Scoping is the part worth reading twice: a `{% for %}` (and `{% with %}`)
//! pushes a frame, `{% if %}` does not, and `{% set %}` always writes to the
//! innermost frame. That is what makes `{% set total = total + 1 %}` inside a
//! loop *not* survive the loop — a behaviour that surprises everyone once and
//! is nonetheless the reference's, which is why `namespace()` exists.

const std = @import("std");
const ast = @import("ast.zig");
const value = @import("value.zig");
const filters = @import("filters.zig");
const Diagnostic = @import("diag.zig").Diagnostic;

const Value = value.Value;
const Expr = ast.Expr;
const Node = ast.Node;

pub const Error = value.Error || error{
    /// The output exceeded `Options.max_output_bytes`.
    OutputTooLarge,
    /// Called something that is not callable, or a method a value does not have.
    NotCallable,
    /// A filter/test named at compile time vanished from the registry.
    UnknownFilter,
};

pub const UndefinedPolicy = enum {
    /// Any *use* of an undefined value is an error, including rendering it.
    /// The default here, and a deliberate divergence from the reference — see
    /// README.md and SPEC.md §4.
    strict,
    /// The reference implementation's default `Undefined`: renders as the empty
    /// string and is falsey, but errors on attribute access, iteration and
    /// arithmetic.
    lenient,
};

pub const Options = struct {
    /// HTML-escape every rendered value that is not marked safe. Explicit in
    /// both directions; there is no per-extension guessing.
    autoescape: bool = false,
    undefined_policy: UndefinedPolicy = .strict,
    /// A ceiling on rendered bytes, so a runaway loop fails loudly rather than
    /// eating the machine.
    max_output_bytes: usize = 64 << 20,
};

/// How the renderer reaches the environment's filter/test registries without
/// this file depending on the environment.
pub const Lookup = struct {
    ctx: *const anyopaque,
    filter: *const fn (ctx: *const anyopaque, name: []const u8) ?filters.Fn,
    test_fn: *const fn (ctx: *const anyopaque, name: []const u8) ?filters.TestFn,
};

const Frame = std.StringArrayHashMapUnmanaged(Value);

pub fn render(
    arena: std.mem.Allocator,
    nodes: []const Node,
    context: Value,
    opts: Options,
    lookup: Lookup,
    out: *std.Io.Writer,
    diag: *Diagnostic,
) Error!void {
    var counting: Counting = .{ .inner = out, .limit = opts.max_output_bytes };
    var r: Renderer = .{
        .arena = arena,
        .opts = opts,
        .lookup = lookup,
        .out = &counting,
        .diag = diag,
        .context = context,
    };
    try r.frames.append(arena, .empty);
    try r.renderNodes(nodes);
}

/// Enforces `max_output_bytes`. Not a `std.Io.Writer` implementation — the
/// renderer only ever appends whole slices, so a two-method shim is enough and
/// avoids a vtable in the hot path.
const Counting = struct {
    inner: *std.Io.Writer,
    limit: usize,
    written: usize = 0,

    fn writeAll(self: *Counting, bytes: []const u8) Error!void {
        self.written += bytes.len;
        if (self.written > self.limit) return error.OutputTooLarge;
        self.inner.writeAll(bytes) catch return error.OutOfMemory;
    }
};

const Renderer = struct {
    arena: std.mem.Allocator,
    opts: Options,
    lookup: Lookup,
    out: *Counting,
    diag: *Diagnostic,
    context: Value,
    frames: std.ArrayList(Frame) = .empty,
    /// Bound while a `{% filter %}`/`{% set %}` block's chain is evaluated.
    block_input: ?Value = null,

    fn fail(self: *Renderer, line: usize, comptime fmt: []const u8, args: anytype, e: Error) Error {
        self.diag.set(line, fmt, args);
        return e;
    }

    // ── scopes ──────────────────────────────────────────────────────────────

    fn push(self: *Renderer) Error!void {
        try self.frames.append(self.arena, .empty);
    }

    fn pop(self: *Renderer) void {
        _ = self.frames.pop();
    }

    fn define(self: *Renderer, name: []const u8, v: Value) Error!void {
        const top = &self.frames.items[self.frames.items.len - 1];
        try top.put(self.arena, name, v);
    }

    fn resolve(self: *Renderer, name: []const u8) Value {
        var i = self.frames.items.len;
        while (i > 0) {
            i -= 1;
            if (self.frames.items[i].get(name)) |v| return v;
        }
        switch (self.context) {
            .map => |m| if (m.get(name)) |v| return v,
            .namespace => |ns| if (ns.get(name)) |v| return v,
            else => {},
        }
        return .{ .undef = .{ .name = name } };
    }

    // ── nodes ───────────────────────────────────────────────────────────────

    fn renderNodes(self: *Renderer, nodes: []const Node) Error!void {
        for (nodes) |n| try self.renderNode(n);
    }

    fn renderNode(self: *Renderer, n: Node) Error!void {
        switch (n) {
            .text => |t| try self.out.writeAll(t),
            .output => |o| {
                const v = try self.eval(o.expr, o.line);
                try self.emit(v, o.line);
            },
            .if_ => |b| {
                if (try self.truthy(b.cond, 0)) try self.renderNodes(b.body) else try self.renderNodes(b.orelse_);
            },
            .for_ => |f| try self.renderFor(f),
            .set => |s| {
                const v = try self.eval(s.expr, 0);
                try self.assign(s.target, v, 0);
            },
            .set_block => |s| {
                var aw: std.Io.Writer.Allocating = .init(self.arena);
                var sub: Counting = .{ .inner = &aw.writer, .limit = self.out.limit };
                const saved = self.out;
                self.out = &sub;
                self.renderNodes(s.body) catch |e| {
                    self.out = saved;
                    return e;
                };
                self.out = saved;
                var v: Value = .{ .string = .{ .bytes = aw.written(), .safe = self.opts.autoescape } };
                if (s.filter) |chain| v = try self.evalWithBlockInput(chain, v);
                try self.assign(s.target, v, 0);
            },
            .filter_block => |fb| {
                var aw: std.Io.Writer.Allocating = .init(self.arena);
                var sub: Counting = .{ .inner = &aw.writer, .limit = self.out.limit };
                const saved = self.out;
                self.out = &sub;
                self.renderNodes(fb.body) catch |e| {
                    self.out = saved;
                    return e;
                };
                self.out = saved;
                const input: Value = .{ .string = .{ .bytes = aw.written(), .safe = self.opts.autoescape } };
                const v = try self.evalWithBlockInput(fb.filter, input);
                try self.emit(v, 0);
            },
            .with => |wth| {
                try self.push();
                defer self.pop();
                for (wth.assignments) |a| {
                    const v = try self.eval(a.expr, 0);
                    try self.assign(a.target, v, 0);
                }
                try self.renderNodes(wth.body);
            },
            .do => |d| _ = try self.eval(d.expr, d.line),
        }
    }

    fn evalWithBlockInput(self: *Renderer, chain: *const Expr, input: Value) Error!Value {
        const saved = self.block_input;
        self.block_input = input;
        defer self.block_input = saved;
        return self.eval(chain, 0);
    }

    fn renderFor(self: *Renderer, f: ast.For) Error!void {
        const seq_val = try self.eval(f.iterable, 0);
        if (seq_val == .undef and self.opts.undefined_policy == .strict)
            return self.fail(0, "'{s}' is undefined", .{seq_val.undef.name}, error.UndefinedValue);
        // Verified against the reference: its default `Undefined` iterates as
        // EMPTY rather than raising, unlike attribute access on it.
        const raw: []const Value = if (seq_val == .undef) &.{} else try value.iterate(self.arena, seq_val);

        try self.push();
        defer self.pop();

        var items: []const Value = raw;
        if (f.cond) |c| {
            var kept: std.ArrayList(Value) = .empty;
            for (raw) |item| {
                try self.bindTarget(f.target, item);
                if (try self.truthy(c, 0)) try kept.append(self.arena, item);
            }
            items = kept.items;
        }

        if (items.len == 0) {
            try self.renderNodes(f.empty);
            return;
        }

        const loop = try self.arena.create(value.Loop);
        loop.* = .{ .items = items };
        try self.define("loop", .{ .loop = loop });
        for (items, 0..) |item, i| {
            loop.index0 = i;
            try self.bindTarget(f.target, item);
            try self.renderNodes(f.body);
        }
    }

    fn bindTarget(self: *Renderer, t: ast.Target, item: Value) Error!void {
        switch (t) {
            .name => |n| try self.define(n, item),
            .tuple => |names| {
                const parts = value.iterate(self.arena, item) catch return error.TypeMismatch;
                if (parts.len != names.len) return error.BadArgument;
                for (names, parts) |n, p| try self.define(n, p);
            },
            .attr => return error.BadArgument,
        }
    }

    fn assign(self: *Renderer, t: ast.Target, v: Value, line: usize) Error!void {
        switch (t) {
            .name, .tuple => try self.bindTarget(t, v),
            .attr => |a| {
                const obj = self.resolve(a.object);
                if (obj != .namespace)
                    return self.fail(line, "`{s}.{s} = …` needs `{s}` to be a namespace()", .{ a.object, a.name, a.object }, error.TypeMismatch);
                try obj.namespace.set(self.arena, a.name, v);
            },
        }
    }

    fn emit(self: *Renderer, v: Value, line: usize) Error!void {
        if (v == .undef) {
            if (self.opts.undefined_policy == .strict)
                return self.fail(line, "'{s}' is undefined", .{v.undef.name}, error.UndefinedValue);
            return;
        }
        if (!self.opts.autoescape or (v == .string and v.string.safe)) {
            var aw: std.Io.Writer.Allocating = .init(self.arena);
            try value.strTo(&aw.writer, v);
            return self.out.writeAll(aw.written());
        }
        var raw: std.Io.Writer.Allocating = .init(self.arena);
        try value.strTo(&raw.writer, v);
        var esc: std.Io.Writer.Allocating = .init(self.arena);
        try value.escapeTo(&esc.writer, raw.written());
        try self.out.writeAll(esc.written());
    }

    fn truthy(self: *Renderer, e: *const Expr, line: usize) Error!bool {
        const v = try self.eval(e, line);
        if (v == .undef and self.opts.undefined_policy == .strict)
            return self.fail(line, "'{s}' is undefined", .{v.undef.name}, error.UndefinedValue);
        return v.truthy();
    }

    // ── expressions ─────────────────────────────────────────────────────────

    fn eval(self: *Renderer, e: *const Expr, line: usize) Error!Value {
        switch (e.*) {
            .literal => |v| return v,
            .name => |n| {
                if (self.block_input) |bi| {
                    if (std.mem.eql(u8, n, ast.filter_block_input.name)) return bi;
                }
                return self.resolve(n);
            },
            .list => |items| {
                const out = try self.arena.alloc(Value, items.len);
                for (items, 0..) |it, i| out[i] = try self.eval(it, line);
                return .{ .list = out };
            },
            .tuple => |items| {
                const out = try self.arena.alloc(Value, items.len);
                for (items, 0..) |it, i| out[i] = try self.eval(it, line);
                return .{ .tuple = out };
            },
            .dict => |entries| {
                const pairs = try self.arena.alloc(value.Pair, entries.len);
                for (entries, 0..) |en, i| {
                    pairs[i] = .{ .key = try self.eval(en.key, line), .value = try self.eval(en.value, line) };
                }
                return .{ .map = .{ .pairs = pairs } };
            },
            .getattr => |g| {
                const obj = try self.eval(g.obj, line);
                return self.getAttr(obj, g.name, line);
            },
            .getitem => |g| {
                const obj = try self.eval(g.obj, line);
                const idx = try self.eval(g.index, line);
                return self.getItem(obj, idx, line);
            },
            .slice => |s| return self.evalSlice(s, line),
            .binop => |b| {
                const lhs = try self.eval(b.lhs, line);
                const rhs = try self.eval(b.rhs, line);
                if (b.op == .concat) return value.concat(self.arena, &.{ lhs, rhs }, self.opts.autoescape);
                return value.binary(self.arena, b.op, lhs, rhs) catch |err| return self.opError(line, err);
            },
            .neg => |inner| {
                const v = try self.eval(inner, line);
                return switch (v) {
                    .integer => |i| .{ .integer = std.math.negate(i) catch return error.OutOfRange },
                    .float => |f| .{ .float = -f },
                    .boolean => |b| .{ .integer = if (b) -1 else 0 },
                    .undef => self.fail(line, "'{s}' is undefined", .{v.undef.name}, error.UndefinedValue),
                    else => error.TypeMismatch,
                };
            },
            .pos => |inner| {
                const v = try self.eval(inner, line);
                return switch (v) {
                    .integer, .float => v,
                    .boolean => |b| .{ .integer = @intFromBool(b) },
                    else => error.TypeMismatch,
                };
            },
            .not => |inner| return .{ .boolean = !(try self.truthy(inner, line)) },
            .compare => |c| {
                var left = try self.eval(c.first, line);
                for (c.links) |lnk| {
                    const right = try self.eval(lnk.right, line);
                    const ok = value.compare(lnk.op, left, right) catch |err| return self.opError(line, err);
                    if (!ok) return .{ .boolean = false };
                    left = right;
                }
                return .{ .boolean = true };
            },
            .logical => |l| {
                // Python semantics: the operand is the result, not a bool.
                const lhs = try self.eval(l.lhs, line);
                const lhs_true = blk: {
                    if (lhs == .undef and self.opts.undefined_policy == .strict)
                        return self.fail(line, "'{s}' is undefined", .{lhs.undef.name}, error.UndefinedValue);
                    break :blk lhs.truthy();
                };
                if (l.op == .@"and") return if (!lhs_true) lhs else self.eval(l.rhs, line);
                return if (lhs_true) lhs else self.eval(l.rhs, line);
            },
            .cond => |c| {
                if (try self.truthy(c.cond, line)) return self.eval(c.then, line);
                if (c.otherwise) |o| return self.eval(o, line);
                return .{ .undef = .{ .name = "the else-less conditional expression" } };
            },
            .filter => |f| {
                const input = try self.eval(f.input, f.line);
                const args = try self.evalArgs(f.args, f.line);
                return self.applyFilter(f.name, input, args, f.line);
            },
            .do_test => |t| {
                const input = try self.eval(t.input, t.line);
                const args = try self.evalArgs(t.args, t.line);
                const fn_ptr = self.lookup.test_fn(self.lookup.ctx, t.name) orelse
                    return self.fail(t.line, "unknown test '{s}'", .{t.name}, error.UnknownFilter);
                var ctx = self.filterCtx();
                const res = fn_ptr(&ctx, input, args) catch |err| return self.opError(t.line, err);
                return .{ .boolean = if (t.negated) !res else res };
            },
            .call => |c| return self.evalCall(c),
            .method => |m| {
                const obj = try self.eval(m.obj, m.line);
                const args = try self.evalArgs(m.args, m.line);
                return self.callMethod(obj, m.name, args, m.line);
            },
        }
    }

    fn opError(self: *Renderer, line: usize, err: Error) Error {
        if (self.diag.len == 0) self.diag.set(line, "{s}", .{@errorName(err)});
        return err;
    }

    fn evalArgs(self: *Renderer, a: ast.Args, line: usize) Error!filters.Args {
        const pos = try self.arena.alloc(Value, a.positional.len);
        for (a.positional, 0..) |p, i| pos[i] = try self.eval(p, line);
        const kw = try self.arena.alloc(filters.Kwarg, a.keyword.len);
        for (a.keyword, 0..) |k, i| kw[i] = .{ .name = k.name, .value = try self.eval(k.value, line) };
        return .{ .pos = pos, .kw = kw };
    }

    fn filterCtx(self: *Renderer) filters.Ctx {
        return .{
            .arena = self.arena,
            .autoescape = self.opts.autoescape,
            .strict = self.opts.undefined_policy == .strict,
            .user = self,
            .callFilter = callFilterThunk,
            .callTest = callTestThunk,
        };
    }

    fn callFilterThunk(ctx: *filters.Ctx, name: []const u8, input: Value, args: filters.Args) filters.Error!Value {
        const self: *Renderer = @ptrCast(@alignCast(@constCast(ctx.user)));
        return self.applyFilter(name, input, args, 0) catch |e| switch (e) {
            error.OutputTooLarge, error.NotCallable, error.UnknownFilter => error.BadArgument,
            else => |other| other,
        };
    }

    fn callTestThunk(ctx: *filters.Ctx, name: []const u8, input: Value, args: filters.Args) filters.Error!bool {
        const self: *Renderer = @ptrCast(@alignCast(@constCast(ctx.user)));
        const fn_ptr = self.lookup.test_fn(self.lookup.ctx, name) orelse return error.BadArgument;
        var sub = self.filterCtx();
        return fn_ptr(&sub, input, args);
    }

    fn applyFilter(self: *Renderer, name: []const u8, input: Value, args: filters.Args, line: usize) Error!Value {
        const fn_ptr = self.lookup.filter(self.lookup.ctx, name) orelse
            return self.fail(line, "unknown filter '{s}'", .{name}, error.UnknownFilter);
        var ctx = self.filterCtx();
        return fn_ptr(&ctx, input, args) catch |err| {
            if (self.diag.len == 0) self.diag.set(line, "filter '{s}': {s}", .{ name, @errorName(err) });
            return err;
        };
    }

    fn evalCall(self: *Renderer, c: anytype) Error!Value {
        if (c.callee.* == .name) {
            const name = c.callee.name;
            const args = try self.evalArgs(c.args, c.line);
            if (std.mem.eql(u8, name, "range")) return self.globalRange(args, c.line);
            if (std.mem.eql(u8, name, "dict")) return self.globalDict(args);
            if (std.mem.eql(u8, name, "namespace")) return self.globalNamespace(args);
            if (std.mem.eql(u8, name, "lipsum") or std.mem.eql(u8, name, "cycler") or std.mem.eql(u8, name, "joiner"))
                return self.fail(c.line, "global '{s}' is not implemented (see SPEC.md)", .{name}, error.NotCallable);
            return self.fail(c.line, "'{s}' is not callable", .{name}, error.NotCallable);
        }
        return self.fail(c.line, "only the built-in globals are callable in this module (see SPEC.md)", .{}, error.NotCallable);
    }

    fn globalRange(self: *Renderer, args: filters.Args, line: usize) Error!Value {
        if (args.pos.len == 0 or args.pos.len > 3) return error.BadArgument;
        var start: i64 = 0;
        var stop: i64 = 0;
        var step: i64 = 1;
        const nums = args.pos;
        if (nums.len == 1) {
            stop = try intOf(nums[0]);
        } else {
            start = try intOf(nums[0]);
            stop = try intOf(nums[1]);
            if (nums.len == 3) step = try intOf(nums[2]);
        }
        if (step == 0) return error.BadArgument;
        var count: usize = 0;
        if (step > 0 and stop > start) count = @intCast(@divTrunc(stop - start + step - 1, step));
        if (step < 0 and stop < start) count = @intCast(@divTrunc(start - stop - step - 1, -step));
        if (count > value.max_items)
            return self.fail(line, "range() of {d} items exceeds the {d}-item cap", .{ count, value.max_items }, error.OutOfRange);
        const out = try self.arena.alloc(Value, count);
        var v = start;
        for (out) |*slot| {
            slot.* = .{ .integer = v };
            v += step;
        }
        return .{ .list = out };
    }

    fn globalDict(self: *Renderer, args: filters.Args) Error!Value {
        if (args.pos.len != 0) return error.BadArgument;
        const pairs = try self.arena.alloc(value.Pair, args.kw.len);
        for (args.kw, 0..) |k, i| pairs[i] = .{ .key = Value.str(k.name), .value = k.value };
        return .{ .map = .{ .pairs = pairs } };
    }

    fn globalNamespace(self: *Renderer, args: filters.Args) Error!Value {
        const ns = try self.arena.create(value.Namespace);
        ns.* = .{};
        for (args.pos) |p| {
            const pairs = switch (p) {
                .map => |m| m.pairs,
                else => return error.BadArgument,
            };
            for (pairs) |pr| switch (pr.key) {
                .string => |s| try ns.set(self.arena, s.bytes, pr.value),
                else => return error.BadArgument,
            };
        }
        for (args.kw) |k| try ns.set(self.arena, k.name, k.value);
        return .{ .namespace = ns };
    }

    // ── attribute / item / method access ────────────────────────────────────

    fn getAttr(self: *Renderer, obj: Value, name: []const u8, line: usize) Error!Value {
        switch (obj) {
            .undef => return self.fail(line, "'{s}' is undefined, so '.{s}' cannot be read", .{ obj.undef.name, name }, error.UndefinedValue),
            .map => |m| return m.get(name) orelse .{ .undef = .{ .name = name } },
            .namespace => |ns| return ns.get(name) orelse .{ .undef = .{ .name = name } },
            .loop => |l| return self.loopAttr(l, name),
            else => return .{ .undef = .{ .name = name } },
        }
    }

    fn loopAttr(self: *Renderer, l: *value.Loop, name: []const u8) Error!Value {
        const len = l.items.len;
        if (std.mem.eql(u8, name, "index")) return .{ .integer = @intCast(l.index0 + 1) };
        if (std.mem.eql(u8, name, "index0")) return .{ .integer = @intCast(l.index0) };
        if (std.mem.eql(u8, name, "revindex")) return .{ .integer = @intCast(len - l.index0) };
        if (std.mem.eql(u8, name, "revindex0")) return .{ .integer = @intCast(len - l.index0 - 1) };
        if (std.mem.eql(u8, name, "first")) return .{ .boolean = l.index0 == 0 };
        if (std.mem.eql(u8, name, "last")) return .{ .boolean = l.index0 + 1 == len };
        if (std.mem.eql(u8, name, "length")) return .{ .integer = @intCast(len) };
        if (std.mem.eql(u8, name, "depth")) return .{ .integer = @intCast(l.depth0 + 1) };
        if (std.mem.eql(u8, name, "depth0")) return .{ .integer = @intCast(l.depth0) };
        if (std.mem.eql(u8, name, "previtem"))
            return if (l.index0 == 0) .{ .undef = .{ .name = "previtem" } } else l.items[l.index0 - 1];
        if (std.mem.eql(u8, name, "nextitem"))
            return if (l.index0 + 1 >= len) .{ .undef = .{ .name = "nextitem" } } else l.items[l.index0 + 1];
        _ = self;
        return .{ .undef = .{ .name = name } };
    }

    fn getItem(self: *Renderer, obj: Value, idx: Value, line: usize) Error!Value {
        switch (obj) {
            .undef => return self.fail(line, "'{s}' is undefined, so it cannot be subscripted", .{obj.undef.name}, error.UndefinedValue),
            .list, .tuple => |items| {
                const i = pyIndex(idx, items.len) orelse return .{ .undef = .{ .name = "index" } };
                return items[i];
            },
            .string => |s| {
                const cs = try value.chars(self.arena, s);
                const i = pyIndex(idx, cs.len) orelse return .{ .undef = .{ .name = "index" } };
                return cs[i];
            },
            .map => |m| {
                for (m.pairs) |p| if (value.valueEql(p.key, idx)) return p.value;
                return .{ .undef = .{ .name = "key" } };
            },
            .namespace => |ns| {
                for (ns.pairs.items) |p| if (value.valueEql(p.key, idx)) return p.value;
                return .{ .undef = .{ .name = "key" } };
            },
            .loop => |l| {
                if (idx == .string) return self.loopAttr(l, idx.string.bytes);
                return .{ .undef = .{ .name = "key" } };
            },
            else => return .{ .undef = .{ .name = "item" } },
        }
    }

    fn evalSlice(self: *Renderer, s: anytype, line: usize) Error!Value {
        const obj = try self.eval(s.obj, line);
        const start = if (s.start) |e| try self.eval(e, line) else Value.none;
        const stop = if (s.stop) |e| try self.eval(e, line) else Value.none;
        const step = if (s.step) |e| try self.eval(e, line) else Value.none;
        const items: []const Value = switch (obj) {
            .list, .tuple => |l| l,
            .string => |str| try value.chars(self.arena, str),
            .undef => return self.fail(line, "'{s}' is undefined, so it cannot be sliced", .{obj.undef.name}, error.UndefinedValue),
            else => return error.TypeMismatch,
        };
        const picked = try pySlice(self.arena, items, start, stop, step);
        if (obj == .tuple) return .{ .tuple = picked };
        if (obj == .string) {
            var aw: std.Io.Writer.Allocating = .init(self.arena);
            for (picked) |c| aw.writer.writeAll(c.string.bytes) catch return error.OutOfMemory;
            return .{ .string = .{ .bytes = aw.written(), .safe = obj.string.safe } };
        }
        return .{ .list = picked };
    }

    fn callMethod(self: *Renderer, obj: Value, name: []const u8, args: filters.Args, line: usize) Error!Value {
        if (obj == .loop) {
            const l = obj.loop;
            if (std.mem.eql(u8, name, "cycle")) {
                if (args.pos.len == 0) return error.BadArgument;
                return args.pos[l.index0 % args.pos.len];
            }
            if (std.mem.eql(u8, name, "changed")) {
                const prev = l.last_changed;
                const now = try self.arena.dupe(Value, args.pos);
                l.last_changed = now;
                if (prev == null) return .{ .boolean = true };
                if (prev.?.len != now.len) return .{ .boolean = true };
                for (prev.?, now) |a, b| if (!value.valueEql(a, b)) return .{ .boolean = true };
                return .{ .boolean = false };
            }
        }
        return filters.callMethod(self.arena, obj, name, args, self.opts.autoescape) catch |err| switch (err) {
            error.Unsupported => self.fail(line, "'{s}' objects have no method '{s}' in this module (see SPEC.md)", .{ obj.typeName(), name }, error.NotCallable),
            else => |other| other,
        };
    }
};

fn intOf(v: Value) Error!i64 {
    return switch (v) {
        .integer => |i| i,
        .boolean => |b| @intFromBool(b),
        .float => |f| @intFromFloat(f),
        else => error.BadArgument,
    };
}

/// Python's negative-index rule; null when out of range (which the caller turns
/// into undefined, as the reference does).
fn pyIndex(idx: Value, len: usize) ?usize {
    const i: i64 = switch (idx) {
        .integer => |n| n,
        .boolean => |b| @intFromBool(b),
        else => return null,
    };
    const l: i64 = @intCast(len);
    const eff = if (i < 0) i + l else i;
    if (eff < 0 or eff >= l) return null;
    return @intCast(eff);
}

fn clampIndex(i: i64, len: i64) i64 {
    const eff = if (i < 0) i + len else i;
    return @max(0, @min(eff, len));
}

fn pySlice(
    arena: std.mem.Allocator,
    items: []const Value,
    start_v: Value,
    stop_v: Value,
    step_v: Value,
) Error![]const Value {
    const len: i64 = @intCast(items.len);
    const step: i64 = if (step_v == .none) 1 else try intOf(step_v);
    if (step == 0) return error.BadArgument;

    var out: std.ArrayList(Value) = .empty;
    if (step > 0) {
        const start = if (start_v == .none) 0 else clampIndex(try intOf(start_v), len);
        const stop = if (stop_v == .none) len else clampIndex(try intOf(stop_v), len);
        var i = start;
        while (i < stop) : (i += step) try out.append(arena, items[@intCast(i)]);
    } else {
        const start = if (start_v == .none) len - 1 else blk: {
            const raw = try intOf(start_v);
            const eff = if (raw < 0) raw + len else raw;
            break :blk @min(eff, len - 1);
        };
        const stop = if (stop_v == .none) @as(i64, -1) else blk: {
            const raw = try intOf(stop_v);
            const eff = if (raw < 0) raw + len else raw;
            break :blk @max(eff, -1);
        };
        var i = start;
        while (i > stop) : (i += step) {
            if (i < 0 or i >= len) break;
            try out.append(arena, items[@intCast(i)]);
        }
    }
    return out.items;
}
