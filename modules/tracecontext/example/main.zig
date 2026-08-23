// SPDX-License-Identifier: MIT

//! What a distributed-tracing consumer does with `tracecontext`: register the
//! middleware outermost, send a real request carrying the W3C spec's own
//! published example `traceparent`, and see the trace-id kept with a fresh
//! span-id minted for this hop (`current()` agreeing with the response
//! header). Then, standalone (no router), reject every invalid form the W3C
//! Trace Context spec itself calls out by name.
//!
//! External judge: the W3C Trace Context Level 1 recommendation. The sample
//! `traceparent` below (`00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`)
//! is the spec's own worked example (§3.2, "Examples of HTTP headers"); the
//! four rejected forms are each a case the spec's normative text singles out:
//! all-zero trace-id and all-zero parent-id are explicitly invalid (§3.2.2.2 /
//! §3.2.2.4), version `ff` is reserved/invalid (§3.2.2.3), and a header
//! missing a required `-` field separator does not match the ABNF the spec
//! defines for `traceparent` (§3.2.1) at all.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `tracecontext` (or `router`/`http`) does not export.

const std = @import("std");
const http = @import("http");
const router = @import("router");
const tracecontext = @import("tracecontext");

// The W3C spec's own worked example (§3.2).
const spec_sample = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const spec_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
const spec_parent_id = "00f067aa0ba902b7";

fn hEchoCurrent(ctx: *router.Ctx) anyerror!void {
    if (tracecontext.current()) |tp| {
        var b: [tracecontext.TraceParent.header_len]u8 = undefined;
        try ctx.res.writeAll(tp.write(&b));
    } else {
        try ctx.res.writeAll("<none>");
    }
}

/// Drive the router through the socket-free server codec with canned wire
/// bytes; returns the full response byte stream (headers + body). Same shape
/// as `modules/router/example/main.zig`'s own helper.
fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name))
            return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var tc = tracecontext.TraceContext{};
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(tc.middleware()); // outermost, per the module's own docs
    try r.get("/", hEchoCurrent);

    // A real request carrying the spec's own worked example traceparent.
    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: example\r\n" ++
        "traceparent: " ++ spec_sample ++ "\r\nConnection: close\r\n\r\n", &buf);

    const out_header = headerValue(got, "traceparent") orelse return error.MissingHeader;
    std.debug.print("outgoing traceparent: {s}\n", .{out_header});

    // Trace-id and flags are carried from the incoming header …
    if (!std.mem.eql(u8, out_header[3..35], spec_trace_id)) return error.TraceIdNotCarried;
    if (out_header[53..55].len != 2 or out_header[53] != '0' or out_header[54] != '1')
        return error.FlagsNotCarried;
    // … but a fresh span-id was minted for this hop.
    if (std.mem.eql(u8, out_header[36..52], spec_parent_id)) return error.SpanIdNotFresh;
    std.debug.print("trace-id kept, span-id freshly minted for this hop: OK\n", .{});

    // The handler's current() view matches the header actually sent on the wire.
    const body_start = std.mem.indexOf(u8, got, "\r\n\r\n").? + 4;
    if (!std.mem.eql(u8, got[body_start..], out_header)) return error.CurrentMismatch;
    std.debug.print("current() agrees with the response header: OK\n", .{});

    // Every form the W3C spec itself calls out as invalid, rejected by name.
    // All-zero trace-id (§3.2.2.2 — the all-zero value is invalid).
    if (tracecontext.TraceParent.parse(
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
    )) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.ZeroTraceId => std.debug.print("all-zero trace-id: ZeroTraceId (expected)\n", .{}),
        else => return err,
    }

    // All-zero parent-id (§3.2.2.4 — the all-zero value is invalid).
    if (tracecontext.TraceParent.parse(
        "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
    )) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.ZeroParentId => std.debug.print("all-zero parent-id: ZeroParentId (expected)\n", .{}),
        else => return err,
    }

    // Version `ff` is reserved as invalid (§3.2.2.3).
    if (tracecontext.TraceParent.parse(
        "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    )) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.BadVersion => std.debug.print("reserved version ff: BadVersion (expected)\n", .{}),
        else => return err,
    }

    // Wrong field count: the trace-id/parent-id separator is missing, so the
    // header does not match the spec's `traceparent` ABNF (§3.2.1) at all.
    if (tracecontext.TraceParent.parse(
        "00-4bf92f3577b34da6a3ce929d0e0e4736_00f067aa0ba902b7-01",
    )) |_| {
        return error.UnexpectedAccept;
    } else |err| switch (err) {
        error.BadFormat => std.debug.print("missing field separator: BadFormat (expected)\n", .{}),
        else => return err,
    }
}
