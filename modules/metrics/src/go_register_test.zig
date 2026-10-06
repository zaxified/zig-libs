// SPDX-License-Identifier: MIT

//! OFFLINE anchor for the registration rules: each case is a sequence of
//! get-or-register calls that also ran on client_golang v1.24.1 (Register,
//! WithLabelValues, then Gather and a Prometheus textparse scrape, so a call
//! accepted there that breaks the scrape counts as refused), with metric and
//! label names judged by prometheus/common's legacy rules
//! (`tools/go_oracle register`, frozen in `go_register_vectors.zig`). The
//! Registry must accept or refuse each call as `want` says. No Go at test time.

const std = @import("std");
const testing = std.testing;
const metrics = @import("root.zig");
const vectors = @import("go_register_vectors.zig");

test "go register oracle: the Registry accepts and refuses what client_golang does" {
    var bad: usize = 0;
    var seen = [_]usize{0} ** vectors.classes.len;
    for (vectors.cases, 0..) |ops, ci| {
        var reg = metrics.Registry.init(testing.allocator);
        defer reg.deinit();
        for (ops, 0..) |o, oi| {
            var labels: [16]metrics.Label = undefined;
            for (o.labels, 0..) |l, i| labels[i] = .{ .name = l.name, .value = l.value };
            const ls = labels[0..o.labels.len];
            const res: anyerror!void = switch (o.kind) {
                .counter => if (reg.counter(o.name, o.help, ls)) |_| {} else |e| e,
                .gauge => if (reg.gauge(o.name, o.help, ls)) |_| {} else |e| e,
                .histogram => if (reg.histogram(o.name, o.help, ls, o.buckets)) |_| {} else |e| e,
            };
            const ok = if (res) |_| true else |_| false;
            if (ok != o.want) {
                bad += 1;
                std.debug.print("case {d} op {d}: {s} {f} labels={d}: want {s} (client_golang: '{s}', class '{s}'), ours {s}\n", .{
                    ci,                                 oi,   @tagName(o.kind), std.json.fmt(o.name, .{}),                      o.labels.len,
                    if (o.want) "accept" else "refuse", o.go, o.class,          if (res) |_| "accepted" else |e| @errorName(e),
                });
            }
            if (o.class.len != 0) {
                for (vectors.classes, &seen) |name, *n| {
                    if (std.mem.eql(u8, name, o.class)) {
                        n.* += 1;
                        break;
                    }
                } else {
                    bad += 1;
                    std.debug.print("unknown class '{s}'\n", .{o.class});
                }
            }
        }
        // Whatever was accepted must still scrape: the exposition writes.
        var out: std.Io.Writer.Allocating = .init(testing.allocator);
        defer out.deinit();
        try reg.writeText(&out.writer);
    }
    for (vectors.classes, seen) |name, n| if (n == 0) {
        bad += 1;
        std.debug.print("class {s}: no case\n", .{name});
    };
    try testing.expectEqual(@as(usize, 0), bad);
}
