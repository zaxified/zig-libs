// SPDX-License-Identifier: MIT
//! jinja — a Jinja2-compatible template engine.
//!
//! ```zig
//! var env = try jinja.Environment.init(gpa, .{});
//! defer env.deinit();
//!
//! var tmpl = try env.compile(
//!     \\interface {{ name }}
//!     \\{%- for v in vlans %}
//!     \\ switchport trunk allowed vlan add {{ v }}
//!     \\{%- endfor %}
//! , null);
//! defer tmpl.deinit();
//!
//! var arena: std.heap.ArenaAllocator = .init(gpa);
//! defer arena.deinit();
//! const ctx = try jinja.valueFrom(arena.allocator(), .{
//!     .name = "Gi1/0/1",
//!     .vlans = [_]u16{ 10, 20, 30 },
//! });
//! const out = try tmpl.render(gpa, ctx, null);
//! defer gpa.free(out);
//! ```
//!
//! ## What is covered
//!
//! `{{ … }}`, `{# … #}`, `{% if/elif/else %}`, `{% for %}` (with the full
//! `loop` object, an inline `if` filter and `{% else %}`), `{% set %}` in both
//! inline and block form, `{% filter %}`, `{% with %}`, `{% do %}`,
//! `{% raw %}`, the whole expression grammar including chained comparisons,
//! conditional expressions, slices, filters and tests, and every whitespace
//! control (`{%-`, `-%}`, `trim_blocks`, `lstrip_blocks`,
//! `keep_trailing_newline`). Template **inheritance and reuse** —
//! `{% extends %}`, `{% block %}`, `{% include %}`, `{% import %}`,
//! `{% macro %}` — are not implemented; naming one is a compile error, never a
//! silent no-op.
//!
//! ## Two things a caller must decide, and this module refuses to guess
//!
//! **Undefined.** The default here is `.strict`: using a variable the context
//! does not have is an error. The reference implementation's default is the
//! opposite, and renders empty. For the workload this module exists for —
//! generating device configuration — an empty string where an address belonged
//! is worse than a failed render, so the default is inverted deliberately. Pass
//! `.undefined_policy = .lenient` for the reference's behaviour. Documented as
//! divergence D1 in SPEC.md.
//!
//! **Autoescaping.** Off unless `.autoescape = true`. There is no guessing from
//! a file extension (this module has no file loader), and `|safe`/`|escape`
//! behave as markupsafe's `Markup` does in both settings.
//!
//! ## Verification
//!
//! Every construct is anchored **byte-for-byte** against Python **Jinja2
//! 3.1.6** two ways: a live oracle that renders the same corpus in a
//! subprocess and compares (`reference_test.zig`), and a committed golden file
//! produced by that same reference so an offline run still asserts something
//! (`testdata/golden.json`). See SPEC.md for why both are kept.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "Jinja2 3.1.x (pallets/jinja) — behaviour anchored byte-for-byte against it",
    .deps = .{}, // std only
};

const lexer = @import("lexer.zig");
const parser = @import("parser.zig");
const ast = @import("ast.zig");
const value_mod = @import("value.zig");
const render_mod = @import("render.zig");
const filters_mod = @import("filters.zig");

pub const Value = value_mod.Value;
pub const Str = value_mod.Str;
pub const Pair = value_mod.Pair;
pub const Map = value_mod.Map;
pub const Namespace = value_mod.Namespace;
pub const Undefined = value_mod.Undefined;

/// Build a `Value` from ordinary Zig data — structs become ordered maps in
/// field order, `[]const u8` becomes a string, slices become lists.
pub const valueFrom = value_mod.from;
/// Adapter for `std.json.Value`. See SPEC.md §2 for why this, and not a
/// dependency on the `yaml` module, is the shipped adapter.
pub const valueFromJson = value_mod.fromJson;
/// markupsafe's escape set, exposed because callers registering their own
/// filters need exactly it.
pub const escapeAlloc = value_mod.escapeAlloc;

pub const Diagnostic = @import("diag.zig").Diagnostic;
pub const UndefinedPolicy = render_mod.UndefinedPolicy;

pub const Options = struct {
    autoescape: bool = false,
    undefined_policy: UndefinedPolicy = .strict,
    trim_blocks: bool = false,
    lstrip_blocks: bool = false,
    keep_trailing_newline: bool = false,
    max_output_bytes: usize = 64 << 20,
};

pub const CompileError = parser.Error;
pub const RenderError = render_mod.Error;
pub const Error = CompileError || RenderError;

/// Filter/test authoring surface, for `Environment.addFilter`/`addTest`.
pub const FilterCtx = filters_mod.Ctx;
pub const FilterFn = filters_mod.Fn;
pub const TestFn = filters_mod.TestFn;
pub const FilterArgs = filters_mod.Args;
pub const FilterError = filters_mod.Error;
pub const FilterKwarg = filters_mod.Kwarg;

/// Owns the filter and test registries and the syntax options. Compiling a
/// template resolves every filter and test name against this environment, so
/// an environment must outlive the templates compiled from it.
pub const Environment = struct {
    gpa: std.mem.Allocator,
    options: Options,
    filters: std.StringHashMapUnmanaged(FilterFn) = .empty,
    tests: std.StringHashMapUnmanaged(TestFn) = .empty,

    pub fn init(gpa: std.mem.Allocator, options: Options) error{OutOfMemory}!Environment {
        var env: Environment = .{ .gpa = gpa, .options = options };
        errdefer env.deinit();
        for (filters_mod.builtin_filters) |e| try env.filters.put(gpa, e.name, e.func);
        for (filters_mod.builtin_tests) |e| try env.tests.put(gpa, e.name, e.func);
        return env;
    }

    pub fn deinit(self: *Environment) void {
        self.filters.deinit(self.gpa);
        self.tests.deinit(self.gpa);
        self.* = undefined;
    }

    /// Register (or replace) a filter. `name` is borrowed and must outlive the
    /// environment.
    pub fn addFilter(self: *Environment, name: []const u8, func: FilterFn) error{OutOfMemory}!void {
        try self.filters.put(self.gpa, name, func);
    }

    pub fn addTest(self: *Environment, name: []const u8, func: TestFn) error{OutOfMemory}!void {
        try self.tests.put(self.gpa, name, func);
    }

    /// Parse `source` into a reusable `Template`. The template copies the
    /// source, so `source` need not outlive the call. `diag` (optional) is
    /// filled in on `error.TemplateSyntaxError`.
    pub fn compile(self: *const Environment, source: []const u8, diag: ?*Diagnostic) CompileError!Template {
        var scratch: Diagnostic = .{};
        const d = diag orelse &scratch;

        var arena: std.heap.ArenaAllocator = .init(self.gpa);
        errdefer arena.deinit();
        const a = arena.allocator();
        const owned = try a.dupe(u8, source);

        const lexed = lexer.lex(a, owned, .{
            .trim_blocks = self.options.trim_blocks,
            .lstrip_blocks = self.options.lstrip_blocks,
            .keep_trailing_newline = self.options.keep_trailing_newline,
        }, d) catch |e| return e;

        const nodes = try parser.parse(a, lexed.pieces, .{
            .ctx = self,
            .hasFilter = hasFilterThunk,
            .hasTest = hasTestThunk,
        }, d);

        return .{ .arena = arena, .nodes = nodes, .env = self };
    }

    /// Compile and render in one step, for the one-shot case.
    pub fn renderAlloc(
        self: *const Environment,
        gpa: std.mem.Allocator,
        source: []const u8,
        context: Value,
        diag: ?*Diagnostic,
    ) Error![]u8 {
        var tmpl = try self.compile(source, diag);
        defer tmpl.deinit();
        return tmpl.render(gpa, context, diag);
    }

    fn hasFilterThunk(ctx: *const anyopaque, name: []const u8) bool {
        const self: *const Environment = @ptrCast(@alignCast(ctx));
        return self.filters.contains(name);
    }

    fn hasTestThunk(ctx: *const anyopaque, name: []const u8) bool {
        const self: *const Environment = @ptrCast(@alignCast(ctx));
        return self.tests.contains(name);
    }

    fn filterLookup(ctx: *const anyopaque, name: []const u8) ?FilterFn {
        const self: *const Environment = @ptrCast(@alignCast(ctx));
        return self.filters.get(name);
    }

    fn testLookup(ctx: *const anyopaque, name: []const u8) ?TestFn {
        const self: *const Environment = @ptrCast(@alignCast(ctx));
        return self.tests.get(name);
    }
};

/// A compiled template: an arena holding the source copy and the tree, plus a
/// borrowed pointer to the environment that compiled it. Immutable after
/// compilation, so one template may be rendered from several threads at once
/// (each render allocates its own scratch arena).
pub const Template = struct {
    arena: std.heap.ArenaAllocator,
    nodes: []const ast.Node,
    env: *const Environment,

    pub fn deinit(self: *Template) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// Render to a freshly allocated buffer owned by the caller.
    pub fn render(
        self: *const Template,
        gpa: std.mem.Allocator,
        context: Value,
        diag: ?*Diagnostic,
    ) RenderError![]u8 {
        var aw: std.Io.Writer.Allocating = .init(gpa);
        errdefer aw.deinit();
        try self.renderTo(gpa, &aw.writer, context, diag);
        return aw.toOwnedSlice() catch error.OutOfMemory;
    }

    /// Render into `out`. `gpa` backs a scratch arena that is released before
    /// this returns, so intermediate values never outlive the call.
    pub fn renderTo(
        self: *const Template,
        gpa: std.mem.Allocator,
        out: *std.Io.Writer,
        context: Value,
        diag: ?*Diagnostic,
    ) RenderError!void {
        var scratch: Diagnostic = .{};
        const d = diag orelse &scratch;
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        try render_mod.render(arena.allocator(), self.nodes, context, .{
            .autoescape = self.env.options.autoescape,
            .undefined_policy = self.env.options.undefined_policy,
            .max_output_bytes = self.env.options.max_output_bytes,
        }, .{
            .ctx = self.env,
            .filter = Environment.filterLookup,
            .test_fn = Environment.testLookup,
        }, out, d);
    }
};

/// The one-liner: default options, compile and render, caller owns the result.
pub fn renderAlloc(
    gpa: std.mem.Allocator,
    source: []const u8,
    context: Value,
    options: Options,
    diag: ?*Diagnostic,
) Error![]u8 {
    var env = try Environment.init(gpa, options);
    defer env.deinit();
    return env.renderAlloc(gpa, source, context, diag);
}

test {
    _ = @import("value.zig");
    _ = @import("lexer.zig");
    _ = @import("parser.zig");
    _ = @import("ast.zig");
    _ = @import("render.zig");
    _ = @import("filters.zig");
    _ = @import("diag.zig");
    _ = @import("engine_test.zig");
    _ = @import("corpus.zig");
    _ = @import("golden_test.zig");
    _ = @import("reference_test.zig");
    _ = @import("fuzz_test.zig");
}
