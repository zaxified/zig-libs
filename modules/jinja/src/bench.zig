// SPDX-License-Identifier: MIT
//! Opt-in profile of the one cost SPEC §9 says to measure before changing the
//! loader's design. Off by default (`error.SkipZigTest`); run it with
//! `JINJA_BENCH`:
//!
//!   JINJA_BENCH=1 scripts/capped zig build test-jinja -Doptimize=ReleaseFast
//!
//! **The question it answers.** §9 makes the template cache per-render, in the
//! render arena, so `Environment` stays `const` and `Template` stays immutable
//! and thread-shareable. The stated cost is that a template pulled in by
//! `{% extends %}`/`{% include %}` is re-lexed and re-parsed on every render,
//! where the reference implementation caches the *compiled* template on the
//! environment. §9 also names the condition for revisiting that: "if
//! recompilation ever shows up in a profile". This is that profile.
//!
//! It measures the composition-heavy shape the audit finding described — a
//! page that extends a base layout and includes a row partial inside a loop —
//! and splits the render into what a caller-owned cache COULD remove
//! (compiling the loaded templates) and what it could not (everything else).
//! The ratio is the whole result; absolute numbers on a mobile CPU are noise.
//!
//! Sizing: the working set is a few kilobytes of template text and one output
//! buffer. Nothing here allocates a large working set — a previous oversized
//! benchmark in this repo OOM-killed the host's editor. Run under
//! `scripts/capped`.

const std = @import("std");
const root = @import("root.zig");

fn nowNs() u64 {
    var ts: std.os.linux.timespec = undefined;
    _ = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

/// A base layout of the size a real page has (nav, header, footer, a few
/// blocks), the row partial an `{% include %}` in a loop pulls in, and the
/// page that composes them.
const bench_templates = [_]root.MapLoader.Entry{
    .{ .name = "base.html", .source =
    \\<!doctype html><html><head><title>{% block title %}untitled{% endblock %}</title>
    \\<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    \\<link rel="stylesheet" href="/static/app.css"></head>
    \\<body><header class="topbar"><a class="brand" href="/">{{ site }}</a>
    \\<nav><ul>{% for item in nav %}<li><a href="{{ item.href }}">{{ item.label }}</a></li>{% endfor %}</ul></nav>
    \\</header><main id="content">{% block content %}{% endblock %}</main>
    \\<footer><p>&copy; {{ year }} {{ site }}</p><p>{% block footer %}all rights reserved{% endblock %}</p></footer>
    \\</body></html>
    },
    .{ .name = "row.html", .source =
    \\<tr class="{{ row.css }}"><td>{{ row.id }}</td><td>{{ row.name }}</td>
    \\<td class="num">{{ row.amount }}</td><td>{% if row.active %}yes{% else %}no{% endif %}</td></tr>
    },
    .{ .name = "page.html", .source =
    \\{% extends "base.html" %}
    \\{% block title %}{{ site }} — report{% endblock %}
    \\{% block content %}<table><tbody>
    \\{% for row in rows %}{% include "row.html" %}{% endfor %}
    \\</tbody></table>{% endblock %}
    },
};

/// The SAME page written without composition: no `{% extends %}`, no
/// `{% include %}`, so no template is loaded or recompiled at render time.
/// Its output is asserted equal (ignoring whitespace) to the composed one, so
/// the difference in render time is the composition machinery — of which the
/// recompilation a caller-owned cache would remove is a part.
const inlined_page =
    \\<!doctype html><html><head><title>{{ site }} — report</title>
    \\<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    \\<link rel="stylesheet" href="/static/app.css"></head>
    \\<body><header class="topbar"><a class="brand" href="/">{{ site }}</a>
    \\<nav><ul>{% for item in nav %}<li><a href="{{ item.href }}">{{ item.label }}</a></li>{% endfor %}</ul></nav>
    \\</header><main id="content"><table><tbody>
    \\{% for row in rows %}<tr class="{{ row.css }}"><td>{{ row.id }}</td><td>{{ row.name }}</td>
    \\<td class="num">{{ row.amount }}</td><td>{% if row.active %}yes{% else %}no{% endif %}</td></tr>
    \\{% endfor %}
    \\</tbody></table></main>
    \\<footer><p>&copy; {{ year }} {{ site }}</p><p>all rights reserved</p></footer>
    \\</body></html>
;

/// True when two renders differ only in whitespace — the check that keeps the
/// composed/inlined comparison honest.
fn sameIgnoringSpace(a: []const u8, b: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (true) {
        while (i < a.len and std.ascii.isWhitespace(a[i])) i += 1;
        while (j < b.len and std.ascii.isWhitespace(b[j])) j += 1;
        if (i == a.len or j == b.len) return i == a.len and j == b.len;
        if (a[i] != b[j]) return false;
        i += 1;
        j += 1;
    }
}

const Pair = @import("value.zig").Pair;

fn pair(key: []const u8, v: root.Value) Pair {
    return .{ .key = .{ .string = .{ .bytes = key } }, .value = v };
}

fn benchContext(arena: std.mem.Allocator, n_rows: usize) !root.Value {
    const rows = try arena.alloc(root.Value, n_rows);
    for (rows, 0..) |*r, i| {
        const fields = try arena.alloc(Pair, 5);
        fields[0] = pair("id", .{ .integer = @intCast(i) });
        fields[1] = pair("name", root.Value.str("a reasonably typical row label"));
        fields[2] = pair("amount", .{ .integer = @intCast(i * 37) });
        fields[3] = pair("active", .{ .boolean = i % 3 != 0 });
        fields[4] = pair("css", root.Value.str(if (i % 2 == 0) "even" else "odd"));
        r.* = .{ .map = .{ .pairs = fields } };
    }

    const nav_fields = try arena.alloc(Pair, 2);
    nav_fields[0] = pair("href", root.Value.str("/reports"));
    nav_fields[1] = pair("label", root.Value.str("Reports"));
    const nav_items = try arena.alloc(root.Value, 4);
    for (nav_items) |*it| it.* = .{ .map = .{ .pairs = nav_fields } };

    const ctx = try arena.alloc(Pair, 4);
    ctx[0] = pair("site", root.Value.str("example.co"));
    ctx[1] = pair("year", .{ .integer = 2026 });
    ctx[2] = pair("nav", .{ .list = nav_items });
    ctx[3] = pair("rows", .{ .list = rows });
    return .{ .map = .{ .pairs = ctx } };
}

test "bench (opt-in via JINJA_BENCH): what a caller-owned template cache would buy" {
    if (std.testing.environ.getPosix("JINJA_BENCH") == null) return error.SkipZigTest;
    // NOT `std.testing.allocator`: that is a `DebugAllocator` with guard pages
    // and per-allocation bookkeeping, and it costs ~50 us per render here —
    // an order of magnitude more than anything jinja does, which would drown
    // the very ratio this bench exists to report. Measured with the testing
    // allocator first, and that is exactly what happened. `smp_allocator` is
    // what a server would actually run.
    const gpa = std.heap.smp_allocator;

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();

    var map: root.MapLoader = .{ .entries = &bench_templates };
    var env = try root.Environment.initWithLoader(gpa, .{}, map.loader());
    defer env.deinit();

    var page = try env.compile(bench_templates[2].source, null);
    defer page.deinit();
    var inlined = try env.compile(inlined_page, null);
    defer inlined.deinit();
    var trivial = try env.compile("{{ site }}", null);
    defer trivial.deinit();

    // n = 0 isolates the FIXED composition cost — the part that does not
    // scale with the page, i.e. the recompilation a cache would remove.
    const row_counts = [_]usize{ 0, 1, 10, 100, 1000 };
    const iters: usize = 500;

    std.debug.print("\njinja: what a caller-owned template cache could remove (SPEC §9)\n", .{});
    std.debug.print("  composed = extends base.html + include row.html per row\n", .{});
    std.debug.print("  inlined  = byte-equivalent page with no loader use at all\n", .{});
    std.debug.print("  rows   composed/op   inlined/op   composition   as share of composed\n", .{});

    var overhead_at: [row_counts.len]u64 = undefined;
    for (row_counts, 0..) |n, idx| {
        const ctx = try benchContext(arena.allocator(), n);

        // Same page, two ways — asserted, not assumed.
        {
            const a = try page.render(gpa, ctx, null);
            defer gpa.free(a);
            const b = try inlined.render(gpa, ctx, null);
            defer gpa.free(b);
            try std.testing.expect(sameIgnoringSpace(a, b));
        }

        const t0 = nowNs();
        for (0..iters) |_| {
            const out = try page.render(gpa, ctx, null);
            gpa.free(out);
        }
        const composed_ns = (nowNs() - t0) / iters;

        const t1 = nowNs();
        for (0..iters) |_| {
            const out = try inlined.render(gpa, ctx, null);
            gpa.free(out);
        }
        const inlined_ns = (nowNs() - t1) / iters;

        const delta = composed_ns -| inlined_ns;
        const share = 100.0 * @as(f64, @floatFromInt(delta)) /
            @as(f64, @floatFromInt(composed_ns));
        overhead_at[idx] = delta;
        std.debug.print(
            "  {d:>4}  {d:>10} ns {d:>10} ns {d:>10} ns {d:>18.1} %\n",
            .{ n, composed_ns, inlined_ns, delta, share },
        );
    }

    // Split the composition column into the part that does not scale with the
    // page (recompiling the two loaded templates + the loader lookup — what a
    // cache removes) and the part that does (executing one `{% include %}` per
    // row — what it does not, and what the reference pays too).
    const fixed_ns = overhead_at[0];
    const per_row_ns = (overhead_at[row_counts.len - 1] -| fixed_ns) /
        row_counts[row_counts.len - 1];
    std.debug.print(
        "  => fixed (cache-removable, UPPER bound): {d} ns/render, flat\n" ++
            "  => per-row include execution:            {d} ns/row (a cache removes none of this)\n",
        .{ fixed_ns, per_row_ns },
    );

    // The per-render floor, for scale: whatever the numbers above are, a cache
    // can never take a render below this.
    const t2 = nowNs();
    for (0..iters) |_| {
        const out = try trivial.render(gpa, .{ .map = .{ .pairs = &.{
            pair("site", root.Value.str("example.co")),
        } } }, null);
        gpa.free(out);
    }
    std.debug.print("  floor: an empty-ish render is {d} ns/op\n", .{(nowNs() - t2) / iters});
    std.debug.print(
        "  The `composition` column is an UPPER bound on the cache's win: it also\n" ++
            "  contains the loader lookup and the block/inheritance machinery, which a\n" ++
            "  cache does not remove.\n",
        .{},
    );
}
