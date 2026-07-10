// SPDX-License-Identifier: MIT
//! diagnostics — LSP-style structured validation-finding collector.
//!
//! A `Diagnostics` collector accumulates `Diagnostic` findings (error /
//! warning / info) emitted while validating a config / json5 / expression
//! tree, each carrying a dot-separated tree path, optional 1-based source
//! line/col (and end position), an optional in-expression byte offset/length
//! for token highlighting, a machine-readable code, a human message, and an
//! optional did-you-mean suggestion.
//!
//! All strings referenced by a `Diagnostic` are expected to outlive the
//! `Diagnostics` collector — typically both live in the same arena, freed in
//! one shot at the validation boundary. Callers that need diagnostics to
//! outlive that arena should dupe the strings first.
//!
//! Provenance: original work of the zig-libs authors (MIT). See ../README.md.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .reentrant,
    .model_after = "LSP Diagnostic / rustc diagnostics",
    .deps = .{},
};

/// Finding severity.
pub const Severity = enum { @"error", warning, info };

/// One validation finding. `path` is dot-separated and points at a node in
/// the validated tree (not necessarily the raw source). Source position
/// fields are 1-based and may be null when the emit site has no ready access
/// to scanner position (e.g. a cross-node invariant detected at end of load).
pub const Diagnostic = struct {
    path: []const u8,
    line: ?u32 = null,
    col: ?u32 = null,
    end_line: ?u32 = null,
    end_col: ?u32 = null,
    /// Byte offset inside an expression string for expr-internal findings.
    /// Useful for token highlighting in a GUI's expression panel. Null for
    /// non-expr diagnostics.
    expr_off: ?u32 = null,
    expr_len: ?u32 = null,
    severity: Severity,
    /// Machine-readable code, e.g. "config.unknown_key",
    /// "expr.unknown_function", "json5.duplicate_key". Used for icon/route
    /// selection and for filtering.
    code: []const u8,
    message: []const u8,
    /// Optional suggestion ("did you mean 'COALESCE'?"). Owned by the same
    /// allocator as the rest of the strings.
    suggest: ?[]const u8 = null,
};

/// Owned collector. All strings referenced by appended `Diagnostic`s are
/// expected to live as long as this collector — typically a shared arena
/// freed in one shot when validation is done. Callers that need persistent
/// ownership across allocator boundaries should dupe before append.
pub const Diagnostics = struct {
    items: std.ArrayList(Diagnostic),
    alloc: std.mem.Allocator,

    pub fn init(alloc: std.mem.Allocator) Diagnostics {
        return .{ .items = .empty, .alloc = alloc };
    }

    pub fn deinit(self: *Diagnostics) void {
        self.items.deinit(self.alloc);
    }

    pub fn append(self: *Diagnostics, d: Diagnostic) !void {
        try self.items.append(self.alloc, d);
    }

    pub fn count(self: *const Diagnostics) usize {
        return self.items.items.len;
    }

    /// Number of diagnostics matching the given severity. Used e.g. by a
    /// pre-save guard (only `.@"error"` blocks save) and by a validation
    /// summary line.
    pub fn countBySeverity(self: *const Diagnostics, sev: Severity) usize {
        var n: usize = 0;
        for (self.items.items) |d| {
            if (d.severity == sev) n += 1;
        }
        return n;
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "Diagnostics: append + count + countBySeverity" {
    var diag: Diagnostics = .init(testing.allocator);
    defer diag.deinit();

    try diag.append(.{
        .path = "conversion_templates.x.data_dir",
        .severity = .@"error",
        .code = "config.empty_required",
        .message = "data_dir must not be empty",
    });
    try diag.append(.{
        .path = "conversion_templates.x.unknown_key",
        .line = 12,
        .col = 5,
        .severity = .warning,
        .code = "config.unknown_key",
        .message = "unknown key 'unknown_key'",
        .suggest = "did you mean 'file_pattern_in'?",
    });
    try diag.append(.{
        .path = "conversion_templates.x.maps",
        .severity = .info,
        .code = "config.empty_optional",
        .message = "empty map; no remapping will occur",
    });

    try testing.expectEqual(@as(usize, 3), diag.count());
    try testing.expectEqual(@as(usize, 1), diag.countBySeverity(.@"error"));
    try testing.expectEqual(@as(usize, 1), diag.countBySeverity(.warning));
    try testing.expectEqual(@as(usize, 1), diag.countBySeverity(.info));
}

test "Diagnostics: empty collector" {
    var diag: Diagnostics = .init(testing.allocator);
    defer diag.deinit();

    try testing.expectEqual(@as(usize, 0), diag.count());
    try testing.expectEqual(@as(usize, 0), diag.countBySeverity(.@"error"));
    try testing.expectEqual(@as(usize, 0), diag.countBySeverity(.warning));
    try testing.expectEqual(@as(usize, 0), diag.countBySeverity(.info));
}

test "Diagnostic: suggest field defaults to null and optional positions stay null" {
    var diag: Diagnostics = .init(testing.allocator);
    defer diag.deinit();

    try diag.append(.{
        .path = "conversion_templates.x.data_dir",
        .severity = .@"error",
        .code = "config.empty_required",
        .message = "data_dir must not be empty",
    });

    const d = diag.items.items[0];
    try testing.expectEqual(@as(?[]const u8, null), d.suggest);
    try testing.expectEqual(@as(?u32, null), d.line);
    try testing.expectEqual(@as(?u32, null), d.col);
    try testing.expectEqual(@as(?u32, null), d.end_line);
    try testing.expectEqual(@as(?u32, null), d.end_col);
    try testing.expectEqual(@as(?u32, null), d.expr_off);
    try testing.expectEqual(@as(?u32, null), d.expr_len);
}

test "Diagnostics: countBySeverity across a mixed, unbalanced set" {
    var diag: Diagnostics = .init(testing.allocator);
    defer diag.deinit();

    // Two errors, three warnings, one info — deliberately unbalanced to
    // catch an off-by-one or wrong-severity bug in the counting loop.
    const severities = [_]Severity{
        .@"error", .warning, .warning, .@"error", .warning, .info,
    };
    for (severities) |sev| {
        try diag.append(.{
            .path = "p",
            .severity = sev,
            .code = "c",
            .message = "m",
        });
    }

    try testing.expectEqual(@as(usize, 6), diag.count());
    try testing.expectEqual(@as(usize, 2), diag.countBySeverity(.@"error"));
    try testing.expectEqual(@as(usize, 3), diag.countBySeverity(.warning));
    try testing.expectEqual(@as(usize, 1), diag.countBySeverity(.info));
}
