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
const loader_mod = @import("loader.zig");
const parser = @import("parser.zig");
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
    /// A composition tag named a template the loader does not have.
    TemplateNotFound,
    /// A composition tag was reached with no loader configured.
    NoLoader,
    /// `a extends b extends a` — caught structurally, before it can recurse.
    TemplateCycle,
    /// A depth cap was hit: template nesting, macro calls, or `loop()`.
    TooDeep,
    /// A loaded template failed to compile.
    TemplateSyntaxError,
    /// `{% block x required %}` reached without a derived template overriding
    /// it, or `{{ super() }}` with no parent definition.
    BlockError,
    /// A macro was called with arguments it does not accept.
    BadCall,
    /// The loader itself failed (I/O, size cap, a name it refuses).
    LoaderFailed,
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
    /// How deeply templates may nest through `{% extends %}`, `{% include %}`
    /// and `{% import %}` combined. A cycle in the inheritance chain is caught
    /// exactly by its names; this bounds everything else.
    max_template_depth: usize = 32,
    /// How deeply macros (and `{% call %}` bodies, and `loop()`) may nest.
    max_call_depth: usize = 64,
    /// How many distinct templates one render may load.
    max_templates: usize = 256,
};

/// How the renderer reaches the environment's filter/test registries without
/// this file depending on the environment.
pub const Lookup = struct {
    ctx: *const anyopaque,
    filter: *const fn (ctx: *const anyopaque, name: []const u8) ?filters.Fn,
    test_fn: *const fn (ctx: *const anyopaque, name: []const u8) ?filters.TestFn,
    /// Where `{% extends %}`/`{% include %}`/`{% import %}` get their bytes.
    /// `null` makes every composition tag `error.NoLoader` — a template that
    /// names another template on an environment with no loader is a mistake
    /// worth reporting, not something to render around.
    loader: ?loader_mod.Loader = null,
    /// Compiles loaded source into a tree using the render arena. Owned by the
    /// environment so this file never has to know about filter registries.
    compile: *const fn (
        ctx: *const anyopaque,
        arena: std.mem.Allocator,
        source: []const u8,
        diag: *Diagnostic,
    ) parser.Error!ast.Parsed,
};

/// A scope. Held by POINTER everywhere (`[]const *Frame`), never by value: a
/// macro closes over the frames it was defined in, and a hash map copied by
/// value would be left pointing at freed storage the moment the original grew.
const Frame = std.StringArrayHashMapUnmanaged(Value);

/// One loaded, compiled template.
const Unit = struct {
    name: []const u8,
    parsed: ast.Parsed,
};

/// The scope a macro carries with it, allocated in the render arena so it
/// outlives the statement that created it. `render.zig` owns every cast of
/// `value.MacroRef.impl` to this type.
const MacroImpl = struct {
    def: *const ast.MacroDef,
    /// The frame stack visible to the body, innermost last.
    captured: []const *Frame,
    /// Whether the render context is still visible. `{% import %}` without
    /// context hides it; a locally defined macro keeps it.
    keep_context: bool,
    /// A block rendered through `self.name()` — it must not be re-entered as a
    /// chain block, and it has no parameters.
    block_body: ?[]const Node = null,
};

/// The state a `{% for … recursive %}` body needs so `loop()` can re-enter it.
const RecursiveLoop = struct {
    def: ast.For,
    depth: usize,
};

/// A macro with no parameters and no body of its own — the shape `self.x()`
/// needs, where the body comes from `MacroImpl.block_body`.
const empty_macro_def: ast.MacroDef = .{ .name = "block", .params = &.{}, .body = &.{} };

/// One entry of the block-resolution stack, so `{{ super() }}` knows which
/// definition it is standing on.
const BlockFrame = struct {
    name: []const u8,
    /// Index into `chain` of the definition currently rendering.
    chain_index: usize,
};

pub fn render(
    arena: std.mem.Allocator,
    parsed: ast.Parsed,
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
    const entry = try arena.create(Unit);
    entry.* = .{ .name = "<string>", .parsed = parsed };
    try r.pushFrame();
    try r.renderUnit(entry);
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
    frames: std.ArrayList(*Frame) = .empty,
    /// Bound while a `{% filter %}`/`{% set %}` block's chain is evaluated.
    block_input: ?Value = null,
    /// The inheritance chain, most-derived first. Empty until a unit renders.
    chain: []const *Unit = &.{},
    /// Which block definitions are currently on the stack, for `super()`.
    block_stack: std.ArrayList(BlockFrame) = .empty,
    /// The `{% call %}` body available to the macro being rendered.
    caller: ?Value = null,
    /// The loop a `{% for … recursive %}` body may re-enter via `loop()`.
    recursive: ?RecursiveLoop = null,
    /// Per-render template cache: a name is loaded and compiled at most once.
    cache: std.StringHashMapUnmanaged(*Unit) = .empty,
    template_depth: usize = 0,
    call_depth: usize = 0,
    loads: usize = 0,
    /// Set while a child template's top-level nodes run for their side effects
    /// only — output goes nowhere and block positions are skipped.
    prelude: bool = false,
    /// Lazily built `self` object.
    self_ns: ?*value.Namespace = null,
    /// Set by an `{% extends %}` node during a prelude pass.
    pending_parent: ?[]const u8 = null,
    /// The `{% call %}` body waiting to be handed to the macro being invoked.
    pending_caller: ?Value = null,
    /// True while an `{% import %}`ed template runs, so macros defined there
    /// do not capture the importing render's context.
    in_module: bool = false,

    fn fail(self: *Renderer, line: usize, comptime fmt: []const u8, args: anytype, e: Error) Error {
        self.diag.set(line, fmt, args);
        return e;
    }

    // ── scopes ──────────────────────────────────────────────────────────────

    fn newFrame(self: *Renderer) Error!*Frame {
        const f = try self.arena.create(Frame);
        f.* = .empty;
        return f;
    }

    fn pushFrame(self: *Renderer) Error!void {
        try self.frames.append(self.arena, try self.newFrame());
    }

    fn pop(self: *Renderer) void {
        _ = self.frames.pop();
    }

    fn define(self: *Renderer, name: []const u8, v: Value) Error!void {
        try self.frames.items[self.frames.items.len - 1].put(self.arena, name, v);
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
        if (std.mem.eql(u8, name, "self")) {
            if (self.selfObject()) |ns| return .{ .namespace = ns } else |_| {}
        }
        return .{ .undef = .{ .name = name } };
    }

    /// Swap in a whole new scope stack — what a macro call, an `{% import %}`
    /// and a non-`scoped` block all need. The caller restores.
    fn swapFrames(self: *Renderer, frames: std.ArrayList(*Frame)) std.ArrayList(*Frame) {
        const old = self.frames;
        self.frames = frames;
        return old;
    }

    fn framesFrom(self: *Renderer, captured: []const *Frame) Error!std.ArrayList(*Frame) {
        var list: std.ArrayList(*Frame) = .empty;
        try list.appendSlice(self.arena, captured);
        try list.append(self.arena, try self.newFrame());
        return list;
    }

    // ── nodes ───────────────────────────────────────────────────────────────

    fn renderNodes(self: *Renderer, nodes: []const Node) Error!void {
        for (nodes) |n| try self.renderNode(n);
    }

    fn renderNode(self: *Renderer, n: Node) Error!void {
        switch (n) {
            .text => |t| if (!self.prelude) try self.out.writeAll(t),
            .output => |o| {
                // In a child template's prelude, output is suppressed and the
                // expression is not evaluated at all — the reference discards
                // everything outside a block, and evaluating it anyway would
                // invent errors a real render never sees.
                if (self.prelude) return;
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
                try self.pushFrame();
                defer self.pop();
                for (wth.assignments) |a| {
                    const v = try self.eval(a.expr, 0);
                    try self.assign(a.target, v, 0);
                }
                try self.renderNodes(wth.body);
            },
            .do => |d| _ = try self.eval(d.expr, d.line),

            // ── composition ────────────────────────────────────────────────
            .extends => |e| {
                // Only ever reached inside a prelude pass; `renderUnit` has
                // already decided the template extends something, and the name
                // is evaluated HERE so it can depend on a `{% set %}` above it.
                const name = try self.eval(e.name, e.line);
                self.pending_parent = try self.templateName(name, e.line);
            },
            .block => |b| {
                if (self.prelude) return;
                try self.renderBlockNamed(b.name, b.line);
            },
            .include => |i| try self.renderInclude(i),
            .import => |i| {
                const ns = try self.importModule(i.name, i.with_context, i.line);
                try self.define(i.target, .{ .namespace = ns });
            },
            .from_import => |i| {
                const ns = try self.importModule(i.template, i.with_context, i.line);
                for (i.names) |alias| {
                    // A name the module does not define is undefined, not an
                    // error — verified against the reference.
                    try self.define(alias.as, ns.get(alias.name) orelse .{ .undef = .{ .name = alias.name } });
                }
            },
            .macro => |m| try self.define(m.def.name, try self.makeMacro(m.def, null)),
            .call_block => |c| try self.renderCallBlock(c),
        }
    }

    // ── templates: loading, the inheritance chain, blocks ───────────────────

    fn templateName(self: *Renderer, v: Value, line: usize) Error![]const u8 {
        if (v == .undef) return self.fail(line, "template name '{s}' is undefined", .{v.undef.name}, error.UndefinedValue);
        if (v != .string) return self.fail(line, "a template name must be a string, not {s}", .{v.typeName()}, error.TypeMismatch);
        return v.string.bytes;
    }

    /// Load + compile `name`, or null when the loader has no such template.
    /// Cached for the whole render, so a template included in a loop compiles
    /// once and a diamond inheritance graph loads each side once.
    fn loadUnit(self: *Renderer, name: []const u8, line: usize) Error!?*Unit {
        if (self.cache.get(name)) |u| return u;
        const ldr = self.lookup.loader orelse
            return self.fail(line, "'{s}' cannot be loaded: this environment has no loader", .{name}, error.NoLoader);
        if (self.loads >= self.opts.max_templates)
            return self.fail(line, "this render has already loaded {d} templates", .{self.loads}, error.TooDeep);

        const source = ldr.load(ldr.ctx, self.arena, name) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.LoaderFailed => return self.fail(line, "the loader refused or failed on '{s}'", .{name}, error.LoaderFailed),
        } orelse return null;

        self.loads += 1;
        const parsed = self.lookup.compile(self.lookup.ctx, self.arena, source, self.diag) catch {
            // The compile diagnostic lives in `self.diag`'s own buffer, so it
            // has to be copied out before that buffer is rewritten — printing
            // straight from it aliases source and destination.
            var copy: [512]u8 = undefined;
            const msg = self.diag.message();
            const n = @min(msg.len, copy.len);
            @memcpy(copy[0..n], msg[0..n]);
            return self.fail(self.diag.line, "in template '{s}': {s}", .{ name, copy[0..n] }, error.TemplateSyntaxError);
        };

        const u = try self.arena.create(Unit);
        u.* = .{ .name = try self.arena.dupe(u8, name), .parsed = parsed };
        try self.cache.put(self.arena, u.name, u);
        return u;
    }

    fn requireUnit(self: *Renderer, name: []const u8, line: usize) Error!*Unit {
        return (try self.loadUnit(name, line)) orelse
            self.fail(line, "template '{s}' not found", .{name}, error.TemplateNotFound);
    }

    /// Render one template as the entry of its own inheritance chain.
    ///
    /// A template that extends does not render its own body: its top-level
    /// nodes run once for their side effects (a `{% set %}` there IS visible to
    /// the blocks — verified against the reference), output suppressed, and the
    /// chain's ROOT-most template is what actually produces bytes, with block
    /// positions resolving to the most derived definition.
    fn renderUnit(self: *Renderer, entry: *Unit) Error!void {
        if (self.template_depth >= self.opts.max_template_depth)
            return self.fail(0, "template nesting deeper than {d}", .{self.opts.max_template_depth}, error.TooDeep);
        self.template_depth += 1;
        defer self.template_depth -= 1;

        const saved_chain = self.chain;
        defer self.chain = saved_chain;

        if (entry.parsed.extends == null) {
            const one = try self.arena.alloc(*Unit, 1);
            one[0] = entry;
            self.chain = one;
            return self.renderNodes(entry.parsed.nodes);
        }

        var chain: std.ArrayList(*Unit) = .empty;
        try chain.append(self.arena, entry);

        var cur = entry;
        while (cur.parsed.extends != null) {
            // The prelude runs the child's top-level statements for effect.
            const was_prelude = self.prelude;
            self.prelude = true;
            self.pending_parent = null;
            self.renderNodes(cur.parsed.nodes) catch |e| {
                self.prelude = was_prelude;
                return e;
            };
            self.prelude = was_prelude;

            const parent_name = self.pending_parent orelse
                return self.fail(0, "template extends something that never resolved", .{}, error.TemplateNotFound);
            self.pending_parent = null;

            for (chain.items) |seen| if (std.mem.eql(u8, seen.name, parent_name))
                return self.fail(0, "inheritance cycle: '{s}' is already in the chain", .{parent_name}, error.TemplateCycle);
            if (chain.items.len >= self.opts.max_template_depth)
                return self.fail(0, "inheritance chain longer than {d}", .{self.opts.max_template_depth}, error.TooDeep);

            const parent = try self.requireUnit(parent_name, 0);
            try chain.append(self.arena, parent);
            cur = parent;
        }

        self.chain = chain.items;
        try self.renderNodes(cur.parsed.nodes);
    }

    /// The most derived definition of `name`, as an index into `chain`.
    fn resolveBlock(self: *Renderer, name: []const u8, from: usize) ?struct { idx: usize, def: ast.BlockDef } {
        var i = from;
        while (i < self.chain.len) : (i += 1) {
            for (self.chain[i].parsed.blocks) |b| {
                if (std.mem.eql(u8, b.name, name)) return .{ .idx = i, .def = b };
            }
        }
        return null;
    }

    fn renderBlockNamed(self: *Renderer, name: []const u8, line: usize) Error!void {
        const found = self.resolveBlock(name, 0) orelse return;
        try self.renderBlockDef(name, found.idx, found.def, line);
    }

    fn renderBlockDef(self: *Renderer, name: []const u8, idx: usize, def: ast.BlockDef, line: usize) Error!void {
        if (def.required)
            return self.fail(line, "required block '{s}' was not overridden by a derived template", .{name}, error.BlockError);

        try self.block_stack.append(self.arena, .{ .name = name, .chain_index = idx });
        defer _ = self.block_stack.pop();

        if (def.scoped) {
            // `scoped` is the opt-in that lets the body see the enclosing
            // loop's variables.
            try self.pushFrame();
            defer self.pop();
            return self.renderNodes(def.body);
        }
        // Without it a block sees only template-level names — which is why a
        // block inside a `{% for %}` cannot read the loop variable.
        var sub: std.ArrayList(*Frame) = .empty;
        try sub.append(self.arena, self.frames.items[0]);
        try sub.append(self.arena, try self.newFrame());
        const saved = self.swapFrames(sub);
        defer _ = self.swapFrames(saved);
        try self.renderNodes(def.body);
    }

    /// `{{ super() }}` — the next definition of the block currently rendering.
    fn doSuper(self: *Renderer, line: usize) Error!Value {
        if (self.block_stack.items.len == 0)
            return self.fail(line, "super() outside a block", .{}, error.BlockError);
        const top = self.block_stack.items[self.block_stack.items.len - 1];
        const found = self.resolveBlock(top.name, top.chain_index + 1) orelse
            return self.fail(line, "super() in block '{s}' has no parent definition", .{top.name}, error.BlockError);

        var aw: std.Io.Writer.Allocating = .init(self.arena);
        var sub: Counting = .{ .inner = &aw.writer, .limit = self.out.limit, .written = self.out.written };
        const saved = self.out;
        self.out = &sub;
        self.renderBlockDef(top.name, found.idx, found.def, line) catch |e| {
            self.out = saved;
            return e;
        };
        self.out = saved;
        self.out.written = sub.written;
        return .{ .string = .{ .bytes = aw.written(), .safe = self.opts.autoescape } };
    }

    /// `self` — every block of the current chain as a callable, resolved the
    /// same way a block position resolves.
    fn selfObject(self: *Renderer) Error!*value.Namespace {
        if (self.self_ns) |ns| return ns;
        const ns = try self.arena.create(value.Namespace);
        ns.* = .{};
        for (self.chain) |u| {
            for (u.parsed.blocks) |b| {
                if (ns.get(b.name) != null) continue;
                const found = self.resolveBlock(b.name, 0) orelse continue;
                const impl = try self.arena.create(MacroImpl);
                impl.* = .{
                    .def = &empty_macro_def,
                    .captured = try self.arena.dupe(*Frame, self.frames.items[0..1]),
                    .keep_context = true,
                    .block_body = found.def.body,
                };
                try ns.set(self.arena, b.name, .{ .macro = .{ .name = b.name, .impl = impl } });
            }
        }
        self.self_ns = ns;
        return ns;
    }

    // ── include / import ───────────────────────────────────────────────────

    fn renderInclude(self: *Renderer, i: ast.Include) Error!void {
        const v = try self.eval(i.names, i.line);
        const candidates: []const Value = switch (v) {
            .list, .tuple => |items| items,
            else => blk: {
                const one = try self.arena.alloc(Value, 1);
                one[0] = v;
                break :blk one;
            },
        };
        for (candidates) |c| {
            const name = try self.templateName(c, i.line);
            const unit = try self.loadUnit(name, i.line) orelse continue;
            return self.renderNested(unit, i.with_context);
        }
        if (i.ignore_missing) return;
        return self.fail(i.line, "none of the included templates could be loaded", .{}, error.TemplateNotFound);
    }

    /// Render `unit` inside the current render. With context it sees everything
    /// currently in scope (including loop variables) but its own `{% set %}`s
    /// do not leak back; without context it starts from nothing at all — not
    /// even the render context, which the reference also hides.
    fn renderNested(self: *Renderer, unit: *Unit, with_context: bool) Error!void {
        const saved_ctx = self.context;
        const saved_self = self.self_ns;
        defer {
            self.context = saved_ctx;
            self.self_ns = saved_self;
        }
        self.self_ns = null;

        var frames: std.ArrayList(*Frame) = .empty;
        if (with_context) {
            try frames.appendSlice(self.arena, self.frames.items);
        } else {
            self.context = .{ .map = .{ .pairs = &.{} } };
        }
        try frames.append(self.arena, try self.newFrame());
        const saved = self.swapFrames(frames);
        defer _ = self.swapFrames(saved);

        try self.renderUnit(unit);
    }

    /// `{% import %}` / `{% from … import … %}` — run a template for its
    /// definitions, discard its output, and hand back its namespace.
    fn importModule(self: *Renderer, name_expr: *const Expr, with_context: bool, line: usize) Error!*value.Namespace {
        const name = try self.templateName(try self.eval(name_expr, line), line);
        const unit = try self.requireUnit(name, line);

        const module_frame = try self.newFrame();
        if (with_context) {
            // A snapshot, not a live view: the reference passes the context at
            // import time, so a `{% set %}` after the import is not visible.
            switch (self.context) {
                .map => |m| for (m.pairs) |pr| switch (pr.key) {
                    .string => |k| try module_frame.put(self.arena, k.bytes, pr.value),
                    else => {},
                },
                .namespace => |ns| for (ns.pairs.items) |pr| switch (pr.key) {
                    .string => |k| try module_frame.put(self.arena, k.bytes, pr.value),
                    else => {},
                },
                else => {},
            }
            for (self.frames.items) |f| {
                var it = f.iterator();
                while (it.next()) |e| try module_frame.put(self.arena, e.key_ptr.*, e.value_ptr.*);
            }
        }

        var frames: std.ArrayList(*Frame) = .empty;
        try frames.append(self.arena, module_frame);

        const saved_ctx = self.context;
        const saved_module = self.in_module;
        const saved_self = self.self_ns;
        self.context = .{ .map = .{ .pairs = &.{} } };
        self.in_module = true;
        self.self_ns = null;
        const saved_frames = self.swapFrames(frames);

        var aw: std.Io.Writer.Allocating = .init(self.arena);
        var sink: Counting = .{ .inner = &aw.writer, .limit = self.out.limit };
        const saved_out = self.out;
        self.out = &sink;

        const result = self.renderUnit(unit);

        self.out = saved_out;
        _ = self.swapFrames(saved_frames);
        self.context = saved_ctx;
        self.in_module = saved_module;
        self.self_ns = saved_self;
        try result;

        const ns = try self.arena.create(value.Namespace);
        ns.* = .{};
        var it = module_frame.iterator();
        while (it.next()) |e| try ns.set(self.arena, e.key_ptr.*, e.value_ptr.*);
        return ns;
    }

    // ── macros ─────────────────────────────────────────────────────────────

    fn makeMacro(self: *Renderer, def: *const ast.MacroDef, block_body: ?[]const Node) Error!Value {
        const impl = try self.arena.create(MacroImpl);
        impl.* = .{
            .def = def,
            // The frames are captured by POINTER, so a macro defined before a
            // later `{% set %}` still sees it — which is what the reference
            // does.
            .captured = try self.arena.dupe(*Frame, self.frames.items),
            .keep_context = !self.in_module,
            .block_body = block_body,
        };
        return .{ .macro = .{ .name = def.name, .impl = impl } };
    }

    fn callMacro(self: *Renderer, ref: value.MacroRef, args: filters.Args, line: usize) Error!Value {
        const impl: *const MacroImpl = @ptrCast(@alignCast(ref.impl));
        const def = impl.def;

        if (self.call_depth >= self.opts.max_call_depth)
            return self.fail(line, "macro/loop recursion deeper than {d} — '{s}'", .{ self.opts.max_call_depth, ref.name }, error.TooDeep);
        self.call_depth += 1;
        defer self.call_depth -= 1;

        const supplied_caller = self.pending_caller;
        self.pending_caller = null;
        if (supplied_caller != null and !def.uses_caller and impl.block_body == null)
            return self.fail(line, "macro '{s}' does not use caller(), so it cannot take a {{% call %}} body", .{ref.name}, error.BadCall);

        const frames = try self.framesFrom(impl.captured);
        const params_frame = frames.items[frames.items.len - 1];

        const saved_ctx = self.context;
        const saved_caller = self.caller;
        const saved_recursive = self.recursive;
        const saved_self = self.self_ns;
        if (!impl.keep_context) self.context = .{ .map = .{ .pairs = &.{} } };
        // A macro body is not inside the caller's loop.
        self.recursive = null;
        self.self_ns = null;
        const saved_frames = self.swapFrames(frames);
        defer {
            _ = self.swapFrames(saved_frames);
            self.context = saved_ctx;
            self.caller = saved_caller;
            self.recursive = saved_recursive;
            self.self_ns = saved_self;
        }

        if (impl.block_body == null) try self.bindMacroArgs(def, params_frame, args, ref.name, line);
        if (supplied_caller) |c| try params_frame.put(self.arena, "caller", c);

        var aw: std.Io.Writer.Allocating = .init(self.arena);
        var sink: Counting = .{ .inner = &aw.writer, .limit = self.out.limit, .written = self.out.written };
        const saved_out = self.out;
        self.out = &sink;
        const body = impl.block_body orelse def.body;
        const result = self.renderNodes(body);
        self.out = saved_out;
        self.out.written = sink.written;
        try result;

        return .{ .string = .{ .bytes = aw.written(), .safe = self.opts.autoescape } };
    }

    fn bindMacroArgs(
        self: *Renderer,
        def: *const ast.MacroDef,
        frame: *Frame,
        args: filters.Args,
        name: []const u8,
        line: usize,
    ) Error!void {
        const used_kw = try self.arena.alloc(bool, args.kw.len);
        @memset(used_kw, false);

        for (def.params, 0..) |p, i| {
            var bound: ?Value = null;
            if (i < args.pos.len) {
                bound = args.pos[i];
            } else {
                for (args.kw, 0..) |k, ki| {
                    if (std.mem.eql(u8, k.name, p.name)) {
                        bound = k.value;
                        used_kw[ki] = true;
                        break;
                    }
                }
            }
            if (bound == null and p.default != null) bound = try self.eval(p.default.?, line);
            // A parameter with no argument and no default is undefined, not an
            // error — the reference renders it as empty under its default
            // policy rather than refusing the call.
            try frame.put(self.arena, p.name, bound orelse .{ .undef = .{ .name = p.name } });
        }

        if (args.pos.len > def.params.len) {
            if (!def.catch_varargs)
                return self.fail(line, "macro '{s}' takes at most {d} positional argument(s)", .{ name, def.params.len }, error.BadCall);
            try frame.put(self.arena, "varargs", .{ .tuple = args.pos[def.params.len..] });
        } else if (def.catch_varargs) {
            try frame.put(self.arena, "varargs", .{ .tuple = &.{} });
        }

        var extra: std.ArrayList(value.Pair) = .empty;
        for (args.kw, 0..) |k, ki| {
            if (used_kw[ki]) continue;
            try extra.append(self.arena, .{ .key = Value.str(k.name), .value = k.value });
        }
        if (extra.items.len != 0 and !def.catch_kwargs)
            return self.fail(line, "macro '{s}' got an unexpected keyword argument '{s}'", .{ name, extra.items[0].key.string.bytes }, error.BadCall);
        if (def.catch_kwargs) try frame.put(self.arena, "kwargs", .{ .map = .{ .pairs = extra.items } });
    }

    fn renderCallBlock(self: *Renderer, c: ast.CallBlock) Error!void {
        const caller_macro = try self.makeMacro(&c.caller, null);
        const saved = self.pending_caller;
        self.pending_caller = caller_macro;
        defer self.pending_caller = saved;
        const v = try self.eval(c.call, c.line);
        try self.emit(v, c.line);
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

        try self.pushFrame();
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
        try self.runLoop(f, items, 0);
    }

    /// One level of a loop. `depth` is non-zero only for a `recursive` loop
    /// re-entered through `loop()`.
    fn runLoop(self: *Renderer, f: ast.For, items: []const Value, depth: usize) Error!void {
        const loop = try self.arena.create(value.Loop);
        loop.* = .{ .items = items, .depth0 = depth };
        try self.define("loop", .{ .loop = loop });

        const saved_recursive = self.recursive;
        defer self.recursive = saved_recursive;
        self.recursive = if (f.recursive) .{ .def = f, .depth = depth } else null;

        for (items, 0..) |item, i| {
            loop.index0 = i;
            try self.bindTarget(f.target, item);
            try self.renderNodes(f.body);
        }
    }

    /// `{{ loop(children) }}` inside a `{% for … recursive %}` body.
    fn recurseLoop(self: *Renderer, args: filters.Args, line: usize) Error!Value {
        const rec = self.recursive orelse
            return self.fail(line, "loop() is only callable inside a `{{% for … recursive %}}` body", .{}, error.NotCallable);
        if (args.pos.len != 1) return self.fail(line, "loop() takes exactly one sequence", .{}, error.BadCall);
        if (self.call_depth >= self.opts.max_call_depth)
            return self.fail(line, "recursive loop deeper than {d}", .{self.opts.max_call_depth}, error.TooDeep);
        self.call_depth += 1;
        defer self.call_depth -= 1;

        const items = try value.iterate(self.arena, args.pos[0]);

        var aw: std.Io.Writer.Allocating = .init(self.arena);
        var sink: Counting = .{ .inner = &aw.writer, .limit = self.out.limit, .written = self.out.written };
        const saved_out = self.out;
        self.out = &sink;

        try self.pushFrame();
        const result = if (items.len == 0)
            self.renderNodes(rec.def.empty)
        else
            self.runLoop(rec.def, items, rec.depth + 1);
        self.pop();

        self.out = saved_out;
        self.out.written = sink.written;
        try result;
        return .{ .string = .{ .bytes = aw.written(), .safe = self.opts.autoescape } };
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
            // A plain string needs no formatting at all — write it straight
            // through, the same short-circuit `value.strAlloc` already takes,
            // instead of copying it into a throwaway arena buffer first.
            if (v == .string) return self.out.writeAll(v.string.bytes);
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
            error.OutOfMemory => error.OutOfMemory,
            error.UndefinedValue => error.UndefinedValue,
            error.TypeMismatch => error.TypeMismatch,
            error.DivisionByZero => error.DivisionByZero,
            error.OutOfRange => error.OutOfRange,
            error.BadArgument => error.BadArgument,
            error.Unsupported => error.Unsupported,
            // Everything a nested filter can raise that the filter ABI has no
            // word for collapses to BadArgument; the diagnostic already carries
            // the real reason.
            else => error.BadArgument,
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
            if (std.mem.eql(u8, name, "super") and self.block_stack.items.len != 0)
                return self.doSuper(c.line);
            const bound = self.resolve(name);
            if (bound == .macro) return self.callMacro(bound.macro, args, c.line);
            if (std.mem.eql(u8, name, "loop")) return self.recurseLoop(args, c.line);
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
        // `stop - start` is a subtraction of two numbers the template or the
        // context supplied, so it is done in `i128`: `range(-2^63, 2^63-1)`
        // overflows `i64` here and the count never reaches the cap below.
        // (The reference raises `OverflowError` on the same input.)
        const span: i128 = @as(i128, stop) - @as(i128, start);
        const st: i128 = step;
        const wanted: i128 = if (step > 0 and span > 0)
            @divTrunc(span + st - 1, st)
        else if (step < 0 and span < 0)
            @divTrunc(-span - st - 1, -st)
        else
            0;
        if (wanted > value.max_items)
            return self.fail(line, "range() of {d} items exceeds the {d}-item cap", .{ wanted, value.max_items }, error.OutOfRange);
        const count: usize = @intCast(wanted);
        const out = try self.arena.alloc(Value, count);
        var v = start;
        for (out) |*slot| {
            slot.* = .{ .integer = v };
            // Saturating for the same reason as `pySlice`: the *last* increment
            // walks one step past the final element, and with `start` near an
            // `i64` end and a large `step` that step leaves the range. No
            // earlier increment can, because `count` proves they land inside.
            v +|= step;
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
            .macro => |m| return self.macroAttr(m, name),
            else => return .{ .undef = .{ .name = name } },
        }
    }

    fn macroAttr(self: *Renderer, m: value.MacroRef, name: []const u8) Error!Value {
        const impl: *const MacroImpl = @ptrCast(@alignCast(m.impl));
        if (std.mem.eql(u8, name, "name")) return Value.str(m.name);
        if (std.mem.eql(u8, name, "arguments")) {
            const out = try self.arena.alloc(Value, impl.def.params.len);
            for (impl.def.params, 0..) |p, i| out[i] = Value.str(p.name);
            return .{ .tuple = out };
        }
        if (std.mem.eql(u8, name, "catch_varargs")) return .{ .boolean = impl.def.catch_varargs };
        if (std.mem.eql(u8, name, "catch_kwargs")) return .{ .boolean = impl.def.catch_kwargs };
        if (std.mem.eql(u8, name, "caller")) return .{ .boolean = impl.def.uses_caller };
        return .{ .undef = .{ .name = name } };
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
        // `{% import 'm' as m %}{{ m.hello() }}` — the attribute IS the macro.
        switch (obj) {
            .namespace => |ns| if (ns.get(name)) |v| {
                if (v == .macro) return self.callMacro(v.macro, args, line);
            },
            .map => |m| if (m.get(name)) |v| {
                if (v == .macro) return self.callMacro(v.macro, args, line);
            },
            else => {},
        }
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
        // `range(1e300)` and `[1,2,3][1.0e300:]` reach here. The reference
        // refuses a float in either position (`TypeError`, which `getitem`
        // turns into Undefined for the slice); this module truncates integral
        // floats but names the out-of-range case instead of trapping.
        .float => |f| filters.intFromFloatChecked(f),
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
        // Saturating, not wrapping: `step` comes from the template or the
        // context, and `i += 9223372036854775807` overflows `i64` after the
        // first element. Saturating reproduces the reference exactly, because
        // an index past the end ends the walk either way — Jinja2 3.1.6 renders
        // `[1,2,3][::9223372036854775807]` as `[1]` and `[1,2,3][1::…]` as `[2]`.
        while (i < stop) : (i +|= step) try out.append(arena, items[@intCast(i)]);
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
        // Plain `+=` is safe here, unlike the forward branch: `i` enters at
        // `<= len - 1` and the body breaks as soon as it goes negative, so
        // `i + step` never leaves `i64` for any `step`.
        while (i > stop) : (i += step) {
            if (i < 0 or i >= len) break;
            try out.append(arena, items[@intCast(i)]);
        }
    }
    return out.items;
}
