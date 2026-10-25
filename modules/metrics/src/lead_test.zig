// SPDX-License-Identifier: MIT

//! The card's correctness lead (`**Ahead:**` in SPEC.md), pinned. Six rows,
//! each a thing an instrumented service does and each with one right scrape
//! result: what the Prometheus server's own parser (model/textparse
//! v0.315.0) must read back. `tools/go_field_probe` judged the field on
//! 2026-10-25 (the verdicts are recorded per row below) and, with
//! `METRICS_LEAD_OUT=<dir>` set while these tests run, judges this module's
//! own expositions too (`<dir>/ours_<row>.txt`). Here the bytes are pinned,
//! so the lead cannot regress without a failing test.
//!
//! Field result (off of 6): prometheus/client_golang v1.24.1 1 (`big`: the
//! counter is exposed as a float), VictoriaMetrics/metrics v1.44.1 1
//! (`negative`: dropped; `help` n/a, it has no HELP text), prometheus-client
//! 0.25.1 3 (`quote`, `newline`: label value written unescaped, the scrape
//! fails; `help`: HELP written unescaped, a line of it is read as a sample).

const std = @import("std");
const testing = std.testing;
const metrics = @import("root.zig");

const Row = struct {
    name: []const u8,
    /// The exact exposition this module writes.
    want: []const u8,
    /// Which of the three measured libraries got the row wrong.
    off: []const u8,
};

const rows = [_]Row{
    .{ .name = "quote", .off = "client_rust (scrape fails)", .want =
    \\# HELP probe_total probe
    \\# TYPE probe_total counter
    \\probe_total{path="a\"b"} 1
    \\
    },
    .{ .name = "newline", .off = "client_rust (scrape fails)", .want =
    \\# HELP probe_total probe
    \\# TYPE probe_total counter
    \\probe_total{path="a\nb"} 1
    \\
    },
    .{ .name = "backslash", .off = "none", .want =
    \\# HELP probe_total probe
    \\# TYPE probe_total counter
    \\probe_total{path="a\\b"} 1
    \\
    },
    .{ .name = "help", .off = "client_rust (injected sample)", .want =
    \\# HELP probe_total x\nprobe_injected 7
    \\# TYPE probe_total counter
    \\probe_total 1
    \\
    },
    .{ .name = "negative", .off = "VictoriaMetrics (observation dropped)", .want =
    \\# HELP probe_seconds probe
    \\# TYPE probe_seconds histogram
    \\probe_seconds_bucket{le="0.005"} 1
    \\probe_seconds_bucket{le="0.01"} 1
    \\probe_seconds_bucket{le="0.025"} 1
    \\probe_seconds_bucket{le="0.05"} 1
    \\probe_seconds_bucket{le="0.1"} 1
    \\probe_seconds_bucket{le="0.25"} 1
    \\probe_seconds_bucket{le="0.5"} 1
    \\probe_seconds_bucket{le="1"} 1
    \\probe_seconds_bucket{le="2.5"} 1
    \\probe_seconds_bucket{le="5"} 1
    \\probe_seconds_bucket{le="10"} 1
    \\probe_seconds_bucket{le="+Inf"} 1
    \\probe_seconds_sum -1
    \\probe_seconds_count 1
    \\
    },
    .{ .name = "big", .off = "client_golang (9.007199254740992e+15)", .want =
    \\# HELP probe_total probe
    \\# TYPE probe_total counter
    \\probe_total 9007199254740993
    \\
    },
};

fn expose(gpa: std.mem.Allocator, row: []const u8, out: *std.Io.Writer) !void {
    var reg = metrics.Registry.init(gpa);
    defer reg.deinit();
    if (std.mem.eql(u8, row, "help")) {
        (try reg.counter("probe_total", "x\nprobe_injected 7", &.{})).inc();
    } else if (std.mem.eql(u8, row, "negative")) {
        (try reg.histogram("probe_seconds", "probe", &.{}, &metrics.default_buckets)).observe(-1);
    } else if (std.mem.eql(u8, row, "big")) {
        const c = try reg.counter("probe_total", "probe", &.{});
        c.add(1 << 53);
        c.inc();
    } else {
        const v: []const u8 = if (std.mem.eql(u8, row, "quote")) "a\"b" else if (std.mem.eql(u8, row, "newline")) "a\nb" else "a\\b";
        (try reg.counter("probe_total", "probe", &.{.{ .name = "path", .value = v }})).inc();
    }
    try reg.writeText(out);
}

test "lead: six scrape-decided rows, none off, where client_golang, VictoriaMetrics and client_rust are each off on at least one" {
    const out_dir = testing.environ.getPosix("METRICS_LEAD_OUT");
    var field_off: usize = 0;
    for (rows) |r| {
        var out: std.Io.Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        try expose(testing.allocator, r.name, &out.writer);
        try testing.expectEqualStrings(r.want, out.written());
        if (!std.mem.eql(u8, r.off, "none")) field_off += 1;
        if (out_dir) |dir| {
            var path_buf: [std.fs.max_path_bytes]u8 = undefined;
            const path = try std.fmt.bufPrint(&path_buf, "{s}/ours_{s}.txt", .{ dir, r.name });
            try std.Io.Dir.cwd().writeFile(testing.io, .{ .sub_path = path, .data = out.written() });
        }
    }
    try testing.expectEqual(@as(usize, 5), field_off);
}
