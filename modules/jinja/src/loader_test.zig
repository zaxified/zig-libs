// SPDX-License-Identifier: MIT
//! The loader is the module's attack surface, so these are attack tests, not
//! happy-path tests.
//!
//! Two failure classes are covered, and both are asserted by *doing* the bad
//! thing rather than by asserting that a guard exists:
//!
//! 1. **Escaping the root.** A real directory tree is built with a secret
//!    outside it and symlinks pointing at that secret, and every route to it is
//!    attempted through the loader — `../`, absolute paths, a symlinked file, a
//!    symlinked *directory component*, and a name that arrives from the render
//!    context rather than from the template source.
//! 2. **Unbounded expansion.** Template bombs are compiled and rendered, and
//!    the assertion is not merely "it errors" but "it errors *with our
//!    structural cap*, while confined to a small fixed buffer" — a bomb that
//!    exhausted memory first would come back `OutOfMemory` and fail these
//!    tests.

const std = @import("std");
const testing = std.testing;
const jinja = @import("root.zig");

// ── filesystem containment ──────────────────────────────────────────────────

/// A root with a template in it, a secret next to it, and the symlinks an
/// attacker would plant.
const Tree = struct {
    tmp: testing.TmpDir,
    io: std.Io,
    root: std.Io.Dir,
    symlinks: bool,

    fn init(io: std.Io) !Tree {
        var tmp = testing.tmpDir(.{});
        errdefer tmp.cleanup();

        try tmp.dir.writeFile(io, .{ .sub_path = "SECRET", .data = "TOP SECRET" });
        try tmp.dir.createDirPath(io, "root");
        try tmp.dir.createDirPath(io, "root/sub");
        try tmp.dir.writeFile(io, .{ .sub_path = "root/ok.j2", .data = "ok:{{ v }}" });
        try tmp.dir.writeFile(io, .{ .sub_path = "root/sub/deep.j2", .data = "deep" });

        var symlinks = true;
        // A symlinked FILE inside the root pointing at the secret…
        tmp.dir.symLink(io, "../SECRET", "root/leak.j2", .{}) catch {
            symlinks = false;
        };
        // …and a symlinked DIRECTORY component, which refusing to follow only
        // the final component would not catch.
        if (symlinks) {
            tmp.dir.symLink(io, "..", "root/up", .{ .is_directory = true }) catch {
                symlinks = false;
            };
        }

        const root = try tmp.dir.openDir(io, "root", .{});
        return .{ .tmp = tmp, .io = io, .root = root, .symlinks = symlinks };
    }

    fn deinit(self: *Tree) void {
        self.root.close(self.io);
        self.tmp.cleanup();
    }
};

fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

test "DirLoader serves what is inside the root" {
    var tree = try Tree.init(testing.io);
    defer tree.deinit();
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const dl: jinja.DirLoader = .{ .io = tree.io, .root = tree.root, .options = .{ .suffix = ".j2" } };
    const l = dl.loader();

    try testing.expectEqualStrings("ok:{{ v }}", (try l.load(l.ctx, a, "ok")).?);
    try testing.expectEqualStrings("deep", (try l.load(l.ctx, a, "sub/deep")).?);
    try testing.expect((try l.load(l.ctx, a, "absent")) == null);
}

test "DirLoader refuses every route out of the root" {
    var tree = try Tree.init(testing.io);
    defer tree.deinit();

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const dl: jinja.DirLoader = .{ .io = tree.io, .root = tree.root };
    const l = dl.loader();

    const attacks = [_][]const u8{
        "../SECRET",
        "../../SECRET",
        "sub/../../SECRET",
        "./../SECRET",
        "/etc/passwd",
        "//etc/passwd",
        "sub/../../../../../../etc/passwd",
        "..",
        "sub/..",
        "\\..\\SECRET",
        "..\\SECRET",
        "SECRET\x00.j2",
    };
    for (attacks) |name| {
        const got = l.load(l.ctx, a, name) catch |e| {
            // A refusal is fine however it is spelled.
            try testing.expect(e == error.LoaderFailed);
            continue;
        };
        if (got) |bytes| {
            std.debug.print("\nDirLoader SERVED a hostile name '{s}': '{s}'\n", .{ name, bytes });
            return error.ContainmentBreached;
        }
    }
}

test "DirLoader does not traverse a symlink, file or directory component" {
    var tree = try Tree.init(testing.io);
    defer tree.deinit();
    if (!tree.symlinks) {
        if (verboseSkip()) std.debug.print("SKIPPED: this filesystem does not support symlinks\n", .{});
        return error.SkipZigTest;
    }

    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    const dl: jinja.DirLoader = .{ .io = tree.io, .root = tree.root };
    const l = dl.loader();

    // Both names are lexically innocent and live inside the root; only
    // refusing to follow the link keeps the secret in.
    for ([_][]const u8{ "leak.j2", "up/SECRET" }) |name| {
        const got = l.load(l.ctx, a, name) catch |e| {
            try testing.expect(e == error.LoaderFailed);
            continue;
        };
        if (got) |bytes| {
            std.debug.print("\nDirLoader followed a symlink out of the root via '{s}': '{s}'\n", .{ name, bytes });
            return error.ContainmentBreached;
        }
    }
}

test "a template cannot escape the root through a name taken from the context" {
    const gpa = testing.allocator;
    var tree = try Tree.init(testing.io);
    defer tree.deinit();

    const dl: jinja.DirLoader = .{ .io = tree.io, .root = tree.root };
    var env = try jinja.Environment.initWithLoader(gpa, .{ .undefined_policy = .lenient }, dl.loader());
    defer env.deinit();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const ctx = try jinja.valueFrom(arena.allocator(), .{ .theme = "../SECRET" });

    // A hostile name is refused LOUDLY (`LoaderFailed`), not reported as
    // merely absent: `{% include theme ignore missing %}` must not swallow an
    // escape attempt as if the file simply were not there.
    var diag: jinja.Diagnostic = .{};
    try testing.expectError(
        error.LoaderFailed,
        env.renderAlloc(gpa, "{% include theme %}", ctx, &diag),
    );
    try testing.expect(std.mem.indexOf(u8, diag.message(), "refused") != null);

    var diag2: jinja.Diagnostic = .{};
    try testing.expectError(
        error.LoaderFailed,
        env.renderAlloc(gpa, "{% include theme ignore missing %}", ctx, &diag2),
    );
}

test "DirLoader refuses a template over its size cap" {
    const gpa = testing.allocator;
    var tree = try Tree.init(testing.io);
    defer tree.deinit();

    const big = try gpa.alloc(u8, 4096);
    defer gpa.free(big);
    @memset(big, 'x');
    try tree.tmp.dir.writeFile(tree.io, .{ .sub_path = "root/big", .data = big });

    const dl: jinja.DirLoader = .{ .io = tree.io, .root = tree.root, .options = .{ .max_bytes = 1024 } };
    const l = dl.loader();
    try testing.expectError(error.LoaderFailed, l.load(l.ctx, gpa, "big"));
}

// ── cycles and unbounded expansion ──────────────────────────────────────────

/// Render `src` against `templates` with the render arena confined to `budget`
/// bytes, and return whatever error comes back.
///
/// The budget is the point. A bomb that outran its structural cap would exhaust
/// the buffer and surface as `OutOfMemory`, so asserting the *specific* cap
/// error is what proves the bound holds before memory grows — rather than
/// proving only that something eventually went wrong.
fn renderBombErr(
    templates: []const jinja.MapLoader.Entry,
    src: []const u8,
    budget: usize,
) anyerror {
    const gpa = testing.allocator;
    const buf = gpa.alloc(u8, budget) catch return error.OutOfMemory;
    defer gpa.free(buf);
    var fba: std.heap.FixedBufferAllocator = .init(buf);

    var map: jinja.MapLoader = .{ .entries = templates };
    var env = jinja.Environment.initWithLoader(gpa, .{ .undefined_policy = .lenient }, map.loader()) catch |e| return e;
    defer env.deinit();

    var tmpl = env.compile(src, null) catch |e| return e;
    defer tmpl.deinit();

    const out = tmpl.render(fba.allocator(), .{ .map = .{ .pairs = &.{} } }, null) catch |e| return e;
    fba.allocator().free(out);
    return error.BombRenderedSuccessfully;
}

test "an inheritance cycle is caught by name, not by running out of stack" {
    try testing.expectEqual(@as(anyerror, error.TemplateCycle), renderBombErr(&.{
        .{ .name = "a", .source = "{% extends 'b' %}" },
        .{ .name = "b", .source = "{% extends 'a' %}" },
    }, "{% extends 'a' %}", 1 << 20));
}

test "a self-extending template is caught immediately" {
    try testing.expectEqual(
        @as(anyerror, error.TemplateCycle),
        renderBombErr(&.{.{ .name = "a", .source = "{% extends 'a' %}" }}, "{% extends 'a' %}", 1 << 20),
    );
}

test "a three-template inheritance cycle is caught" {
    try testing.expectEqual(@as(anyerror, error.TemplateCycle), renderBombErr(&.{
        .{ .name = "a", .source = "{% extends 'b' %}" },
        .{ .name = "b", .source = "{% extends 'c' %}" },
        .{ .name = "c", .source = "{% extends 'a' %}" },
    }, "{% extends 'a' %}", 1 << 20));
}

test "an include that includes itself hits the depth cap inside a small budget" {
    try testing.expectEqual(
        @as(anyerror, error.TooDeep),
        renderBombErr(&.{.{ .name = "a", .source = "x{% include 'a' %}" }}, "{% include 'a' %}", 1 << 20),
    );
}

test "a mutually-including pair hits the depth cap" {
    try testing.expectEqual(@as(anyerror, error.TooDeep), renderBombErr(&.{
        .{ .name = "a", .source = "{% include 'b' %}" },
        .{ .name = "b", .source = "{% include 'a' %}" },
    }, "{% include 'a' %}", 1 << 20));
}

test "an exponential include bomb is stopped by the depth cap, not by memory" {
    // Each level includes the next TWICE, so an unbounded engine expands
    // 2^depth times. This is the shape that cost a desktop 15.4 GB elsewhere in
    // this repository; here it must die at the cap, inside 1 MiB.
    try testing.expectEqual(@as(anyerror, error.TooDeep), renderBombErr(&.{
        .{ .name = "a", .source = "{% include 'b' %}{% include 'b' %}" },
        .{ .name = "b", .source = "{% include 'a' %}{% include 'a' %}" },
    }, "{% include 'a' %}", 1 << 20));
}

test "an infinitely recursive macro hits the call cap" {
    try testing.expectEqual(
        @as(anyerror, error.TooDeep),
        renderBombErr(&.{}, "{% macro f() %}{{ f() }}{% endmacro %}{{ f() }}", 1 << 20),
    );
}

test "a mutually recursive macro pair hits the call cap" {
    try testing.expectEqual(@as(anyerror, error.TooDeep), renderBombErr(
        &.{},
        "{% macro a() %}{{ b() }}{% endmacro %}{% macro b() %}{{ a() }}{% endmacro %}{{ a() }}",
        1 << 20,
    ));
}

test "a self-feeding recursive loop hits the call cap" {
    try testing.expectEqual(
        @as(anyerror, error.TooDeep),
        renderBombErr(&.{}, "{% for i in [1] recursive %}{{ loop([1]) }}{% endfor %}", 1 << 20),
    );
}

test "an import cycle hits the depth cap" {
    try testing.expectEqual(@as(anyerror, error.TooDeep), renderBombErr(&.{
        .{ .name = "a", .source = "{% import 'b' as b %}" },
        .{ .name = "b", .source = "{% import 'a' as a %}" },
    }, "{% import 'a' as a %}", 1 << 20));
}

test "the caps are configurable and the error names the limit" {
    const gpa = testing.allocator;
    var map: jinja.MapLoader = .{ .entries = &.{.{ .name = "a", .source = "{% include 'a' %}" }} };
    var env = try jinja.Environment.initWithLoader(
        gpa,
        .{ .max_template_depth = 4, .undefined_policy = .lenient },
        map.loader(),
    );
    defer env.deinit();

    var diag: jinja.Diagnostic = .{};
    try testing.expectError(
        error.TooDeep,
        env.renderAlloc(gpa, "{% include 'a' %}", .{ .map = .{ .pairs = &.{} } }, &diag),
    );
    try testing.expect(std.mem.indexOf(u8, diag.message(), "4") != null);
}

test "a legitimate deep chain still renders — the cap is not just 'no nesting'" {
    const gpa = testing.allocator;
    var map: jinja.MapLoader = .{ .entries = &.{
        .{ .name = "l1", .source = "1{% include 'l2' %}" },
        .{ .name = "l2", .source = "2{% include 'l3' %}" },
        .{ .name = "l3", .source = "3{% include 'l4' %}" },
        .{ .name = "l4", .source = "4" },
    } };
    var env = try jinja.Environment.initWithLoader(gpa, .{}, map.loader());
    defer env.deinit();
    const out = try env.renderAlloc(gpa, "[{% include 'l1' %}]", .{ .map = .{ .pairs = &.{} } }, null);
    defer gpa.free(out);
    try testing.expectEqualStrings("[1234]", out);
}

test "a template included in a loop is loaded and compiled once" {
    const gpa = testing.allocator;
    var map: jinja.MapLoader = .{ .entries = &.{.{ .name = "row", .source = "<{{ i }}>" }} };
    var env = try jinja.Environment.initWithLoader(gpa, .{}, map.loader());
    defer env.deinit();
    const out = try env.renderAlloc(
        gpa,
        "{% for i in range(5) %}{% include 'row' %}{% endfor %}",
        .{ .map = .{ .pairs = &.{} } },
        null,
    );
    defer gpa.free(out);
    try testing.expectEqualStrings("<0><1><2><3><4>", out);
}
