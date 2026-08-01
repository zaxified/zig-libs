// SPDX-License-Identifier: MIT
//! Drives this module's `TraceContext` middleware through the vendored W3C
//! `trace-context` conformance vectors (`w3c_vectors.zig`; see ../NOTICE for
//! provenance), both directions: MUST-ACCEPT (a trusted incoming traceparent
//! continued, a tracestate combined/kept) and MUST-REJECT (malformed
//! version/trace-id/parent-id/flags, ambiguous duplicated traceparent,
//! all-zero ids).
//!
//! Every vector is run through the SAME offline wire harness
//! (`root.runWire`) the module's own hand-written tests already use --
//! `http.Server.serveStream` end to end, no network, no mocks of our own
//! parsing/combining logic.
//!
//! Exclusion categories (`out_of_scope` on a vector, still counted by the
//! canary below, never silently dropped):
//!
//!   - forward-compat traceparent versions ("cc" and friends): this module
//!     rejects any non-"00" version outright rather than implementing the
//!     spec's SHOULD-level forward-compatible fallback parse for higher
//!     versions. See `w3c_vectors.zig`'s `reason_forward_compat` and
//!     SPEC.md's Backlog.
//!   - strict tracestate list-member GRAMMAR (illegal key/value characters,
//!     the 256-char key cap, the 32-member cap): this module's tracestate
//!     validation is a deliberate light byte-class guard over the WHOLE
//!     combined value, not a per-member parser -- see root.zig's
//!     `isValidState` doc. Every excluded vector here comes from an upstream
//!     test the suite itself gates behind `STRICT_LEVEL >= 2`, so upstream
//!     already treats this as an opt-in stricter tier, not a Level-1
//!     baseline.
//!   - session/connection-repetition tests (`AdvancedTest`): these assert
//!     properties of a STATEFUL vendor HTTP service handling several
//!     round trips (same trace-id across callbacks, distinct parent-ids
//!     each time) -- already covered by this module's own pre-existing
//!     "childOf keeps the trace and generated ids are unique / non-zero"
//!     test, and orthogonal to header-parsing correctness.
//!   - Trace Context Level 2 (`TraceContext2Test`, the random-trace-id
//!     flag): explicitly out of this module's documented Level-1-only
//!     scope (root.zig module doc, SPEC.md Threat model), and gated by the
//!     suite's own `SPEC_LEVEL >= 2` (off by default).
//!
//! The count canary at the bottom fails loudly if the vendored/executed/
//! excluded totals drift without a matching update here -- the same
//! contract json5_tests_test.zig / csv_spectrum_test.zig use.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const router = @import("router");
const vectors_mod = @import("w3c_vectors.zig");
const Vector = vectors_mod.Vector;

fn hOk(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

/// Serialize `headers` (in order, duplicates allowed) into a raw HTTP/1.1
/// request and run it through `root.runWire`.
fn buildRequest(buf: []u8, headers: []const vectors_mod.Header) []const u8 {
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll("GET / HTTP/1.1\r\nHost: t\r\n") catch unreachable;
    for (headers) |h| w.print("{s}: {s}\r\n", .{ h.name, h.value }) catch unreachable;
    w.writeAll("Connection: close\r\n\r\n") catch unreachable;
    return w.buffered();
}

/// Each of `needles` must appear in `hay`, at strictly increasing byte
/// offsets -- mirrors upstream's own chained `str.index(a) < str.index(b)`.
fn expectOrderedContains(hay: []const u8, needles: []const []const u8) !void {
    var from: usize = 0;
    for (needles) |n| {
        const idx = std.mem.indexOfPos(u8, hay, from, n) orelse {
            std.debug.print("expected '{s}' at or after offset {d} in '{s}'\n", .{ n, from, hay });
            return error.SubstringNotFoundInOrder;
        };
        from = idx + n.len;
    }
}

fn runVector(v: Vector) !void {
    var tcm = root.TraceContext{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tcm.middleware());
    try r.get("/", hOk);

    var req_buf: [8192]u8 = undefined;
    const req = buildRequest(&req_buf, v.headers);
    var wire_buf: [4096]u8 = undefined;
    const got = root.runWire(&r, req, &wire_buf);

    const tp_hdr = root.headerValue(got, "traceparent") orelse return error.MissingTraceparent;
    _ = try root.TraceParent.parse(tp_hdr); // always a well-formed traceparent
    const got_trace_id = tp_hdr[3..35];

    switch (v.traceparent) {
        .any_valid => {},
        .preserved => |want| try testing.expectEqualStrings(want, got_trace_id),
        .changed_from => |olds| for (olds) |old| {
            try testing.expect(!std.mem.eql(u8, old, got_trace_id));
        },
    }

    const ts_hdr = root.headerValue(got, "tracestate");
    switch (v.tracestate) {
        .none => {},
        .absent => try testing.expectEqual(@as(?[]const u8, null), ts_hdr),
        .exact => |want| try testing.expectEqualStrings(want, ts_hdr orelse return error.MissingTracestate),
        .contains => |needles| {
            const hay = ts_hdr orelse return error.MissingTracestate;
            if (v.ordered) {
                try expectOrderedContains(hay, needles);
            } else {
                for (needles) |n| {
                    if (std.mem.indexOf(u8, hay, n) == null) {
                        std.debug.print("expected '{s}' in tracestate '{s}'\n", .{ n, hay });
                        return error.SubstringNotFound;
                    }
                }
            }
        },
    }
}

test "W3C trace-context conformance corpus: must-accept/must-reject vectors" {
    var executed: usize = 0;
    var excluded: usize = 0;
    for (vectors_mod.vectors) |v| {
        if (v.out_of_scope != null) {
            excluded += 1;
            continue;
        }
        executed += 1;
        runVector(v) catch |err| {
            std.debug.print(
                "VECTOR FAILED: {s} -- {s}\n",
                .{ v.source_test, v.doc },
            );
            return err;
        };
    }
    try testing.expectEqual(@as(usize, 58), executed);
    try testing.expectEqual(@as(usize, 15), excluded);
}

test "W3C trace-context conformance corpus: vendored count matches expectation (canary)" {
    // Re-vendoring (adding/removing/reclassifying a vector) MUST update this
    // number in the same commit -- see the module-doc comment above for why.
    try testing.expectEqual(@as(usize, 73), vectors_mod.vectors.len);
}
