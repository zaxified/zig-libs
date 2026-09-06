// SPDX-License-Identifier: MIT
//! Shared machinery for the conformance replay: decode one case out of the
//! committed transcript, run it through *this* engine, and compare the outcome
//! against the reference's.
//!
//! Kept separate from the test that drives it so that "rendering a case" has
//! one definition — the transcript records the inputs the reference was given,
//! and this file is where those inputs become a call into the public API. If
//! the two drifted, the comparison would stop being about the same thing.
//!
//! Nothing here spawns anything: the reference's side of every comparison
//! arrives as bytes from `testdata/golden.json`. See
//! `reference_replay_test.zig` for how that file is taken.

const std = @import("std");
const jinja = @import("root.zig");

/// An extra template the case's loader can serve, so composition tags have
/// something to name.
pub const Tpl = struct {
    name: []const u8,
    source: []const u8,
};

/// One corpus case, exactly as the transcript records the reference having been
/// given it. The authoring form lives in `tools/corpus.zig`; this is the decoded
/// form, with slices pointing into the parsed JSON.
pub const Case = struct {
    name: []const u8,
    template: []const u8,
    /// The loader's contents. Zig builds a `MapLoader`; the reference driver
    /// built a `DictLoader` from the same table.
    templates: []const Tpl = &.{},
    /// The render context, as JSON (so both sides got it verbatim).
    context: []const u8 = "{}",
    autoescape: bool = false,
    /// `true` selected `StrictUndefined` on the Python side and `.strict` here;
    /// `false` selected the reference's default `Undefined` and `.lenient`.
    strict: bool = false,
    trim_blocks: bool = false,
    lstrip_blocks: bool = false,
    keep_trailing_newline: bool = false,
    /// The reference was expected to raise. We then require that we fail too —
    /// with any error, since the exception *types* are Python's, not ours.
    expect_error: bool = false,
};

/// Decodes one entry of the transcript's `cases` array. `arena` owns only the
/// `templates` slice; every string points into `parsed`.
pub fn caseFromJson(arena: std.mem.Allocator, v: std.json.Value) !Case {
    const o = v.object;
    const tpls = o.get("templates").?.object;
    var entries = try arena.alloc(Tpl, tpls.count());
    var it = tpls.iterator();
    var i: usize = 0;
    while (it.next()) |e| : (i += 1) {
        entries[i] = .{ .name = e.key_ptr.*, .source = e.value_ptr.*.string };
    }
    return .{
        .name = o.get("name").?.string,
        .template = o.get("template").?.string,
        .templates = entries,
        .context = o.get("context").?.string,
        .autoescape = o.get("autoescape").?.bool,
        .strict = o.get("strict").?.bool,
        .trim_blocks = o.get("trim_blocks").?.bool,
        .lstrip_blocks = o.get("lstrip_blocks").?.bool,
        .keep_trailing_newline = o.get("keep_trailing_newline").?.bool,
        .expect_error = o.get("expect_error").?.bool,
    };
}

pub const Outcome = union(enum) {
    ok: []u8,
    /// The engine refused. The text is ours, never compared with Python's — the
    /// exception *types* are Python's and mean nothing here. Only the fact of
    /// failing is compared.
    failed: []const u8,

    pub fn deinit(self: Outcome, gpa: std.mem.Allocator) void {
        switch (self) {
            .ok => |b| gpa.free(b),
            .failed => {},
        }
    }
};

/// Render `c` with this module. The JSON context goes in through
/// `valueFromJson`, which is also the ingress path a real caller uses.
pub fn renderCase(gpa: std.mem.Allocator, c: Case) !Outcome {
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const a = arena.allocator();

    const parsed = std.json.parseFromSlice(std.json.Value, a, c.context, .{}) catch
        return .{ .failed = "context is not valid JSON" };
    const ctx = try jinja.valueFromJson(a, parsed.value);

    var entries = try a.alloc(jinja.MapLoader.Entry, c.templates.len);
    for (c.templates, 0..) |t, i| entries[i] = .{ .name = t.name, .source = t.source };
    var map: jinja.MapLoader = .{ .entries = entries };

    var env = try jinja.Environment.initWithLoader(gpa, .{
        .autoescape = c.autoescape,
        .undefined_policy = if (c.strict) .strict else .lenient,
        .trim_blocks = c.trim_blocks,
        .lstrip_blocks = c.lstrip_blocks,
        .keep_trailing_newline = c.keep_trailing_newline,
    }, map.loader());
    defer env.deinit();

    var diag: jinja.Diagnostic = .{};
    var tmpl = env.compile(c.template, &diag) catch return .{ .failed = "compile error" };
    defer tmpl.deinit();
    const out = tmpl.render(gpa, ctx, &diag) catch return .{ .failed = "render error" };
    return .{ .ok = out };
}

/// One reference result, decoded from the transcript.
pub const RefOutcome = struct {
    ok: bool,
    out: []const u8 = "",
    kind: []const u8 = "",
};

pub fn refFromJson(v: std.json.Value) RefOutcome {
    const o = v.object;
    if (std.mem.eql(u8, o.get("status").?.string, "ok"))
        return .{ .ok = true, .out = o.get("out").?.string };
    return .{ .ok = false, .kind = o.get("kind").?.string };
}

/// Compare one case, printing enough on failure to debug it without rerunning.
pub fn expectMatch(gpa: std.mem.Allocator, c: Case, ref: RefOutcome, label: []const u8) !void {
    const mine = try renderCase(gpa, c);
    defer mine.deinit(gpa);

    if (!ref.ok) {
        if (mine == .ok) {
            std.debug.print(
                "\n[{s}] case '{s}': the reference raised {s} but we rendered:\n---\n{s}\n---\n",
                .{ label, c.name, ref.kind, mine.ok },
            );
            return error.ShouldHaveFailed;
        }
        if (!c.expect_error) {
            std.debug.print(
                "\n[{s}] case '{s}': both refused ({s}), but the corpus does not mark it expect_error\n",
                .{ label, c.name, ref.kind },
            );
            return error.UnexpectedFailureAgreement;
        }
        return;
    }
    if (mine == .failed) {
        std.debug.print(
            "\n[{s}] case '{s}': the reference rendered:\n---\n{s}\n---\nbut we failed: {s}\n",
            .{ label, c.name, ref.out, mine.failed },
        );
        return error.RenderFailed;
    }
    if (c.expect_error) {
        std.debug.print("\n[{s}] case '{s}': marked expect_error, yet both rendered fine\n", .{ label, c.name });
        return error.StaleExpectError;
    }
    if (!std.mem.eql(u8, mine.ok, ref.out)) {
        std.debug.print(
            "\n[{s}] case '{s}' MISMATCH\n reference: {f}\n ours     : {f}\n",
            .{ label, c.name, Escaped{ .b = ref.out }, Escaped{ .b = mine.ok } },
        );
        return error.ByteMismatch;
    }
}

/// Renders bytes with newlines/tabs visible, so a whitespace-control failure is
/// legible in the test log instead of being invisible.
const Escaped = struct {
    b: []const u8,

    pub fn format(self: Escaped, w: *std.Io.Writer) std.Io.Writer.Error!void {
        try w.writeByte('"');
        for (self.b) |ch| switch (ch) {
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            '"' => try w.writeAll("\\\""),
            else => try w.writeByte(ch),
        };
        try w.writeByte('"');
    }
};
