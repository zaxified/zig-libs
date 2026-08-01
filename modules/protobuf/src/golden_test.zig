// SPDX-License-Identifier: MIT

//! Offline anchor: the same case tables `reference_interop.zig` drives live
//! against the Python `protobuf` package, checked here against bytes that
//! package already produced — captured once into `testdata/golden_bytes.zig`
//! and committed. No python3, no subprocess, no skip path: these tests run
//! everywhere, including CI, which never has `google.protobuf` installed.
//!
//! Why this exists alongside the live tests rather than instead of them: a
//! live oracle is strictly stronger evidence (it re-derives the bytes from
//! the reference's *own* encoder every run), but it can only anchor a
//! machine that has the reference installed — which is exactly the gap this
//! file closes. Losing the oracle relationship entirely whenever python3 is
//! absent would silently fall back to self-round-trip, which `SPEC.md`'s
//! mutation table (M1/M2/M3/M9) shows is blind to real, shipping-grade bugs.
//! Frozen bytes from a real external encoder, checked unconditionally,
//! keep that anchor everywhere the live test cannot reach.
//!
//! Two assertions per case, neither needing python at run time:
//!   - our encoder reproduces the golden bytes exactly (catches an encoder
//!     that has drifted from the spec — M1, M2, M3, M9 in SPEC.md);
//!   - decoding the golden bytes with our decoder recovers the same value
//!     the live test's case table declares (catches a decoder that reads
//!     spec-conformant bytes wrong, independently of whatever our own
//!     encoder does — the "consistent bug in both halves" blind spot).
//!
//! Every case in `reference_interop.zig`'s tables must have a golden entry
//! here by name, checked at comptime (`@compileError` if not) — nothing is
//! silently skipped — and the count canary below fails loudly if the two
//! tables drift apart in size.
//!
//! Not covered here, with reasons (see SPEC.md "Not implemented"):
//!   - `map<k,v>` — not implemented; there is no map `Kind` to generate a
//!     case for. Its wire form (repeated `{key,value}` submessage) IS
//!     exercised indirectly by `rep_message`.
//!   - groups (wire types 3/4) — removed from proto3 and not implemented;
//!     `wire.Cursor.tag` rejects them by name (see wire.zig's own tests).
//!   - `oneof`, `Any`, well-known types, JSON mapping — not implemented.
//!   - the packing-flip and partial-schema-forwarding semantic tests in
//!     `reference_interop.zig` ("accepts our packing flipped", "a message
//!     proxied through a partial schema is unchanged") are deliberately
//!     NOT frozen here: what they check is that a *live* foreign parser
//!     accepts shapes it would never itself emit, which is a claim about
//!     the reference implementation's behaviour, not just about our bytes.
//!     Freezing them would only re-check our own decoder against itself.
//!     `codec_test.zig` already covers the same shapes offline via
//!     hand-derived bytes ("decoder accepts both packed and unpacked
//!     forms", the unknown-field-preservation tests); those, plus the two
//!     directions checked below, are what make python3's absence harmless.

const std = @import("std");
const testing = std.testing;
const pb = @import("root.zig");
const ct = @import("codec_test.zig");
const ri = @import("reference_interop.zig");
const golden = @import("testdata/golden_bytes.zig");

/// Golden bytes for `name`, or a compile error if none were captured —
/// every live case must have a frozen counterpart, not silently fewer.
fn find(comptime table: anytype, comptime name: []const u8) []const u8 {
    inline for (table) |e| {
        if (comptime std.mem.eql(u8, e.name, name)) return e.bytes;
    }
    @compileError("no golden entry for case '" ++ name ++ "' — regenerate testdata/golden_bytes.zig");
}

fn checkCases(comptime T: type, comptime cases: []const ri.Case(T), comptime table: anytype) !void {
    const gpa = testing.allocator;
    inline for (cases) |c| {
        const want_bytes = comptime find(table, c.name);

        // Direction 1: our encoder must reproduce the reference's bytes.
        const ours = try pb.encodeAlloc(gpa, c.value, .{});
        defer gpa.free(ours);
        testing.expectEqualSlices(u8, want_bytes, ours) catch |e| {
            std.debug.print("golden byte mismatch on case '{s}'\n", .{c.name});
            return e;
        };

        // Direction 2: our decoder must recover the same value from those
        // bytes, independent of whether our own encoder agrees.
        var decoded = pb.decode(T, gpa, want_bytes, .{}) catch |e| {
            std.debug.print("we could not decode the golden bytes for '{s}'\n", .{c.name});
            return e;
        };
        defer decoded.deinit();
        ri.expectMessageEqual(T, c.value, decoded.value) catch |e| {
            std.debug.print("value mismatch decoding golden bytes for '{s}'\n", .{c.name});
            return e;
        };
    }
}

test "golden: byte-exact both ways over every scalar kind, no python required" {
    try checkCases(ct.Wide, &ri.wide_cases, golden.wide);
}

test "golden: byte-exact both ways over repeated and packed fields, no python required" {
    try checkCases(ct.Repeated, &ri.repeated_cases, golden.repeated);
}

test "golden: proto3 presence rules match frozen reference bytes, no python required" {
    try checkCases(ct.Presence, &ri.presence_cases, golden.presence);
}

test "golden: a boxed recursive chain matches frozen reference bytes, no python required" {
    const gpa = testing.allocator;

    const c3 = ct.Chain{ .depth = 3 };
    const c2 = ct.Chain{ .depth = 2, .next = &c3 };
    const c1 = ct.Chain{ .depth = 1, .next = &c2 };

    const ours = try pb.encodeAlloc(gpa, c1, .{});
    defer gpa.free(ours);
    try testing.expectEqualSlices(u8, golden.chain3, ours);

    var decoded = try pb.decode(ct.Chain, gpa, golden.chain3, .{});
    defer decoded.deinit();
    try testing.expectEqual(@as(i32, 1), decoded.value.depth);
    try testing.expectEqual(@as(i32, 2), decoded.value.next.?.depth);
    try testing.expectEqual(@as(i32, 3), decoded.value.next.?.next.?.depth);
    try testing.expect(decoded.value.next.?.next.?.next == null);
}

// ── count canary ─────────────────────────────────────────────────────────
//
// Guards against the two tables silently drifting apart: someone adds a
// case to `reference_interop.zig` and forgets to capture+add its golden
// (already loud, via `find`'s @compileError — but only for entries actually
// iterated above); someone deletes a case from the live table without
// noticing its golden entry is now dead weight nobody checks. Pinning the
// exact counts, not just "the sets happen to match right now", also catches
// a golden capture run that silently produced fewer entries than it meant
// to (e.g. a `CASES` iteration that returned early).

test "golden: vector count canary — 36 named cases plus chain3, none silently dropped" {
    try testing.expectEqual(@as(usize, 20), ri.wide_cases.len);
    try testing.expectEqual(@as(usize, 20), golden.wide.len);
    try testing.expectEqual(@as(usize, 10), ri.repeated_cases.len);
    try testing.expectEqual(@as(usize, 10), golden.repeated.len);
    try testing.expectEqual(@as(usize, 5), ri.presence_cases.len);
    try testing.expectEqual(@as(usize, 5), golden.presence.len);
    // chain3 is checked structurally above; its presence here is the count
    // canary's acknowledgement that it exists and is not forgotten.
    try testing.expect(golden.chain3.len > 0);
}
