// SPDX-License-Identifier: MIT
//! Shared machinery for the two conformance oracles: run one corpus case
//! through *this* engine, and compare an outcome against a reference outcome.
//!
//! Kept separate so the golden test and the live-peer test agree on what
//! "rendering a case" means — if that drifted, the two oracles would stop
//! being about the same thing.

const std = @import("std");
const jinja = @import("root.zig");
const corpus = @import("corpus.zig");

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
pub fn renderCase(gpa: std.mem.Allocator, c: corpus.Case) !Outcome {
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

/// One reference result, decoded from the driver's JSON.
pub const RefOutcome = struct {
    ok: bool,
    out: []const u8 = "",
    kind: []const u8 = "",
};

pub fn refOutcome(cases: std.json.Value, name: []const u8) ?RefOutcome {
    const entry = cases.object.get(name) orelse return null;
    const status = entry.object.get("status").?.string;
    if (std.mem.eql(u8, status, "ok")) return .{ .ok = true, .out = entry.object.get("out").?.string };
    return .{ .ok = false, .kind = entry.object.get("kind").?.string };
}

/// Compare one case, printing enough on failure to debug it without rerunning.
pub fn expectMatch(gpa: std.mem.Allocator, c: corpus.Case, ref: RefOutcome, label: []const u8) !void {
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
