// SPDX-License-Identifier: MIT

//! OFFLINE replay of the client_golang / expfmt / textparse oracle
//! (`tools/interop.zig` + `tools/go_oracle`, frozen in
//! `go_oracle_vectors.zig`). Each script's operations ran on this module's
//! Registry and on client_golang's; prometheus/common's expfmt parsed our
//! exposition into the same families client_golang gathered (help, type,
//! series, values, cumulative buckets, sum, count), and the Prometheus
//! server's own scrape parser (model/textparse) read the same samples
//! without error. No Go at test time: the replay runs the operations again
//! and requires the very bytes that were judged.

const std = @import("std");
const testing = std.testing;
const metrics = @import("root.zig");
const vectors = @import("go_oracle_vectors.zig");

/// One script on a fresh registry (tools/interop.zig's `run`, over the
/// frozen form).
fn apply(gpa: std.mem.Allocator, sc: vectors.Script, out: *std.Io.Writer.Allocating) !void {
    var r = metrics.Registry.init(gpa);
    defer r.deinit();
    var ls_buf: [metrics.max_labels]metrics.Label = undefined;
    for (sc.ops) |op| {
        const f = sc.families[op.fam];
        const ls = ls_buf[0..f.labels.len];
        for (ls, f.labels, op.values) |*l, n, v| l.* = .{ .name = n, .value = v };
        switch (f.kind) {
            .counter => {
                const c = try r.counter(f.name, f.help, ls);
                if (op.op == .inc) c.inc() else c.add(op.n);
            },
            .gauge => {
                const g = try r.gauge(f.name, f.help, ls);
                switch (op.op) {
                    .set => g.set(op.v),
                    .add => g.add(op.v),
                    .sub => g.sub(op.v),
                    .inc => g.inc(),
                    .dec => g.dec(),
                    .observe => unreachable,
                }
            },
            .histogram => (try r.histogram(f.name, f.help, ls, f.buckets)).observe(op.v),
        }
    }
    try r.writeText(&out.writer);
}

test "go oracle: every script's exposition is the one client_golang's parsers judged" {
    var bad: usize = 0;
    var empty_buckets: usize = 0;
    for (vectors.scripts, 0..) |sc, i| {
        if (!std.mem.eql(u8, sc.class, "") and !std.mem.eql(u8, sc.class, "EMPTY_BUCKETS")) {
            bad += 1;
            std.debug.print("script {d}: class {s} -- a verdict nobody accepted\n", .{ i, sc.class });
            continue;
        }
        if (std.mem.eql(u8, sc.class, "EMPTY_BUCKETS")) empty_buckets += 1;
        var out: std.Io.Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        try apply(testing.allocator, sc, &out);
        if (!std.mem.eql(u8, out.written(), sc.text)) {
            bad += 1;
            if (bad <= 5) std.debug.print("script {d}: wrote\n{s}--- judged\n{s}---\n", .{ i, out.written(), sc.text });
        }
    }
    try testing.expectEqual(@as(usize, 0), bad);
    // The one documented difference is still exercised.
    try testing.expect(empty_buckets > 0);
}
