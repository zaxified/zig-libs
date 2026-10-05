// SPDX-License-Identifier: MIT

//! OFFLINE differential anchor: OpenTelemetry Go's W3C Trace Context
//! propagator (`propagation.TraceContext`, otel v1.46.0, Apache-2.0) as an
//! independent implementation. The request headers are ours
//! (`tools/go_oracle/main.go`); what otel extracts from them is in
//! `otel_vectors.zig`. Each case is sent through this module's middleware
//! over the offline wire harness (`root.runWire`) and the response compared:
//!  - otel continues the trace: so must we -- same trace-id, same sampled bit;
//!  - otel refuses it: we must start a new trace;
//!  - the tracestate we carry must be the list members otel keeps.
//! Only otel's observable answers were recorded; no otel source was read.
//! Every case answered differently is listed in `divergences` with the
//! judgement; a differing case without an entry fails, and so does an entry
//! whose case has started to agree.

const std = @import("std");
const testing = std.testing;
const mem = std.mem;
const root = @import("root.zig");
const router = @import("router");
const vectors = @import("otel_vectors.zig");

const Divergence = struct { id: []const u8, why: []const u8 };

const divergences = [_]Divergence{
    // Unknown trace-flags bits: otel refuses the header; the spec forbids
    // refusing it -- "Vendors MUST set all unparsed / unknown trace-flags to 0
    // on outgoing requests" -- so we continue the trace and send `sampled`
    // only (checked for every case below).
    .{ .id = "shape02", .why = "flags ff: otel restarts the trace; W3C: accept, zero the unknown bits on the way out (we send ...-01)" },
    .{ .id = "shape04", .why = "flags 09: as shape02" },
    .{ .id = "sub53f", .why = "flags f1: as shape02" },
    .{ .id = "sub54f", .why = "flags 0f: as shape02" },
    .{ .id = "shape13", .why = "version 00 followed by '-': otel reads it as the Level 1 prefix; version 00 is exactly 55 characters (W3C conformance suite test_traceparent_version_0x00 restarts on any suffix), so we restart" },
    .{ .id = "dup_same", .why = "two traceparent fields: otel takes the first; the W3C conformance suite (test_traceparent_duplicated) requires a restart, as we do" },
    .{ .id = "dup_diff", .why = "as dup_same" },
    .{ .id = "dup_bad_second", .why = "as dup_same" },
    .{ .id = "state_split", .why = "tracestate in two fields: otel reads only the first; W3C: 'they MUST be combined into a single header' (RFC 9110 §5.3), as we do -- a=1,b=2" },
    .{ .id = "state_split_dup", .why = "as state_split; the combined a=1,a=2 is then carried by our light guard" },
    // Invalid list-member grammar: otel discards the whole tracestate; W3C
    // makes validation optional ("MAY validate ... MAY discard"), and this
    // module carries it unchanged by design (isValidState; the conformance
    // suite gates these behind STRICT_LEVEL >= 2).
    .{ .id = "state10", .why = "uppercase key: light guard, see above" },
    .{ .id = "state11", .why = "space in key: light guard" },
    .{ .id = "state12", .why = "key starts with a digit: light guard" },
    .{ .id = "state15", .why = "uppercase system id: light guard" },
    .{ .id = "state16", .why = "empty tenant id: light guard" },
    .{ .id = "state17", .why = "empty system id: light guard" },
    .{ .id = "state19", .why = "empty value: light guard" },
    .{ .id = "state20", .why = "empty key: light guard" },
    .{ .id = "state21", .why = "member without '=': light guard" },
    .{ .id = "state22", .why = "'=' in value: light guard" },
    .{ .id = "state25", .why = "empty value then a comma: light guard" },
    .{ .id = "state27", .why = "duplicated key: light guard (W3C: one entry per key, enforcement is the vendor's on re-entry)" },
    .{ .id = "state28", .why = "';' separated: light guard" },
    .{ .id = "state31", .why = "257-character key: light guard" },
    .{ .id = "state33", .why = "257-character value: light guard" },
    .{ .id = "state35", .why = "33 members: light guard (W3C caps at 32; truncation is the vendor's)" },
};

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

/// The list members of a tracestate, OWS trimmed, empty ones dropped,
/// joined by ',' -- the form otel re-serializes to.
fn members(buf: []u8, v: []const u8) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    var it = mem.splitScalar(u8, v, ',');
    var first = true;
    while (it.next()) |m| {
        const t = mem.trim(u8, m, " \t");
        if (t.len == 0) continue;
        if (!first) w.writeByte(',') catch unreachable;
        w.writeAll(t) catch unreachable;
        first = false;
    }
    return w.buffered();
}

test "otel oracle: the middleware continues, restarts and carries state as OpenTelemetry Go does" {
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    const tc: root.TraceContext = .{};
    try r.use(tc.middleware());
    try r.get("/", hOk);

    var seen = [_]bool{false} ** divergences.len;
    var bad: usize = 0;
    var continued: usize = 0;
    var restarted: usize = 0;
    var refused: usize = 0;
    for (vectors.cases) |c| {
        var req_buf: [8192]u8 = undefined;
        var w: std.Io.Writer = .fixed(&req_buf);
        try w.writeAll("GET / HTTP/1.1\r\nHost: t\r\n");
        for (c.headers) |h| try w.print("{s}: {s}\r\n", .{ h.name, h.value });
        try w.writeAll("Connection: close\r\n\r\n");
        var out: [8192]u8 = undefined;
        const got = root.runWire(&r, w.buffered(), &out);

        // A control character in a field value: the HTTP layer refuses the
        // request before the middleware runs, as any server must.
        if (!c.wire_ok) {
            if (mem.startsWith(u8, got, "HTTP/1.1 400")) {
                refused += 1;
                continue;
            }
            bad += 1;
            std.debug.print("{s}: a control character in a header was not refused\n", .{c.id});
            continue;
        }

        var why_bad: ?[]const u8 = null;
        const resp_tp = root.headerValue(got, "traceparent") orelse "";
        const parsed = root.TraceParent.parse(resp_tp) catch null;
        var hexbuf: [32]u8 = undefined;
        const resp_trace: []const u8 = if (parsed) |p| std.fmt.bufPrint(&hexbuf, "{x}", .{&p.trace_id}) catch unreachable else "";
        if (parsed == null) {
            why_bad = "no valid traceparent on the response";
        } else if (parsed.?.flags & ~root.flag_sampled != 0) {
            why_bad = "an unknown trace-flags bit went out non-zero";
        } else if (c.valid) {
            if (!mem.eql(u8, resp_trace, c.trace_id)) {
                why_bad = "otel continues the trace, we restarted it";
            } else if ((parsed.?.flags & 1) != (c.flags & 1)) {
                why_bad = "sampled bit differs";
            } else continued += 1;
        } else {
            var reused = false;
            for (c.headers) |h| if (mem.indexOf(u8, h.value, resp_trace) != null) {
                reused = true;
            };
            if (reused) why_bad = "otel restarts the trace, we continued it" else restarted += 1;
        }
        if (why_bad == null) {
            var b1: [4096]u8 = undefined;
            var b2: [4096]u8 = undefined;
            const ours_ts = members(&b1, root.headerValue(got, "tracestate") orelse "");
            const otel_ts = members(&b2, c.tracestate);
            if (!mem.eql(u8, ours_ts, otel_ts)) why_bad = "tracestate differs";
        }
        const reason = why_bad orelse continue;
        var listed = false;
        for (divergences, 0..) |d, i| if (mem.eql(u8, d.id, c.id)) {
            seen[i] = true;
            listed = true;
        };
        if (listed) continue;
        bad += 1;
        std.debug.print("{s}: {s}; headers", .{ c.id, reason });
        for (c.headers) |h| std.debug.print(" {s}={f}", .{ h.name, std.zig.fmtString(h.value) });
        std.debug.print("\n   otel valid={} flags={d} ts={f} | ours tp={s} ts={f}\n", .{
            c.valid, c.flags, std.zig.fmtString(c.tracestate), resp_tp, std.zig.fmtString(root.headerValue(got, "tracestate") orelse ""),
        });
    }
    for (divergences, seen) |d, s| if (!s) {
        std.debug.print("divergence {s} agrees now: delete it\n", .{d.id});
        bad += 1;
    };
    if (bad != 0) std.debug.print("{d} differ; {d} continued, {d} restarted as otel does, {d} refused\n", .{ bad, continued, restarted, refused });
    try testing.expectEqual(@as(usize, 0), bad);
    // 2026-10-05: most evidence is agreement -- 140+ continued, 340+
    // restarted as otel does.
    try testing.expect(continued >= 120 and restarted >= 300 and refused == 4);
}
