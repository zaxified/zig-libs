// SPDX-License-Identifier: MIT

//! What a config validator does with `diagnostics`: walk a small config tree,
//! collect findings (missing required key, unknown key with a suggestion,
//! empty-but-optional map) into one collector, then apply the pre-save guard
//! a real editor would — block the save only when an `.@"error"` finding is
//! present, warnings and info pass through.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, this file stops compiling.

const std = @import("std");
const diagnostics = @import("diagnostics");

/// One raw config field as a loader would see it, before validation.
const RawField = struct { path: []const u8, key: []const u8, value: []const u8 };

const known_keys = [_][]const u8{ "data_dir", "file_pattern_in", "maps" };

pub fn main() !void {
    // The module's own doc says strings referenced by a `Diagnostic` are
    // expected to live as long as the collector, typically a shared arena
    // freed in one shot — exactly what a validation pass does.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var diag: diagnostics.Diagnostics = .init(arena);
    defer diag.deinit();

    const fields = [_]RawField{
        .{ .path = "conversion_templates.export.data_dir", .key = "data_dir", .value = "" },
        .{ .path = "conversion_templates.export.file_patern_in", .key = "file_patern_in", .value = "*.csv" }, // typo
        .{ .path = "conversion_templates.export.maps", .key = "maps", .value = "" },
    };

    for (fields) |f| {
        if (std.mem.eql(u8, f.key, "data_dir") and f.value.len == 0) {
            try diag.append(.{
                .path = f.path,
                .severity = .@"error",
                .code = "config.empty_required",
                .message = "data_dir must not be empty",
            });
            continue;
        }
        if (!isKnownKey(f.key)) {
            // The formatted message is the one allocation on this path; a
            // real caller wants OOM handled by name here rather than folded
            // into a generic error return, since it means "stop validating
            // and surface a degraded result" rather than "this field is bad".
            const msg = std.fmt.allocPrint(arena, "unknown key '{s}'", .{f.key}) catch |err| switch (err) {
                error.OutOfMemory => {
                    std.debug.print("out of memory formatting a diagnostic message\n", .{});
                    return err;
                },
            };
            try diag.append(.{
                .path = f.path,
                .severity = .warning,
                .code = "config.unknown_key",
                .message = msg,
                .suggest = closestKnownKey(f.key),
            });
            continue;
        }
        if (std.mem.eql(u8, f.key, "maps") and f.value.len == 0) {
            try diag.append(.{
                .path = f.path,
                .severity = .info,
                .code = "config.empty_optional",
                .message = "empty map; no remapping will occur",
            });
        }
    }

    std.debug.print("{d} finding(s): {d} error, {d} warning, {d} info\n", .{
        diag.count(),
        diag.countBySeverity(.@"error"),
        diag.countBySeverity(.warning),
        diag.countBySeverity(.info),
    });
    for (diag.items.items) |d| {
        std.debug.print("  [{s}] {s}: {s}", .{ @tagName(d.severity), d.path, d.message });
        if (d.suggest) |s| std.debug.print(" (did you mean '{s}'?)", .{s});
        std.debug.print("\n", .{});
    }

    // The pre-save guard: only `.@"error"` blocks a save.
    if (diag.countBySeverity(.@"error") > 0) {
        std.debug.print("save blocked: {d} error(s) must be fixed first\n", .{diag.countBySeverity(.@"error")});
    } else {
        std.debug.print("save allowed\n", .{});
    }
}

fn isKnownKey(key: []const u8) bool {
    for (known_keys) |k| if (std.mem.eql(u8, k, key)) return true;
    return false;
}

/// A tiny fixed table stand-in for a real did-you-mean lookup: nearest known
/// key by Levenshtein distance 1 or 2, else null.
fn closestKnownKey(key: []const u8) ?[]const u8 {
    var best: ?[]const u8 = null;
    var best_dist: usize = std.math.maxInt(usize);
    for (known_keys) |k| {
        const d = levenshtein(key, k);
        if (d < best_dist) {
            best_dist = d;
            best = k;
        }
    }
    return if (best_dist <= 2) best else null;
}

fn levenshtein(a: []const u8, b: []const u8) usize {
    var buf: [64]usize = undefined;
    std.debug.assert(b.len < buf.len);
    for (0..b.len + 1) |j| buf[j] = j;
    for (a, 1..) |ca, i| {
        var prev = buf[0];
        buf[0] = i;
        for (b, 1..) |cb, j| {
            const tmp = buf[j];
            buf[j] = if (ca == cb) prev else 1 + @min(prev, @min(buf[j], buf[j - 1]));
            prev = tmp;
        }
    }
    return buf[b.len];
}
