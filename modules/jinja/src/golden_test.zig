// SPDX-License-Identifier: MIT
//! The OFFLINE half of the conformance anchor: every corpus case checked
//! against a committed file of outputs that Python Jinja2 3.1.6 produced.
//!
//! This is not redundant with `reference_test.zig`, and neither subsumes the
//! other. A live peer catches the class of bug where our own committed
//! expectations agree with our own mistake — it is the only oracle that has
//! never seen this code. A committed golden catches the opposite class: a peer
//! that is *tolerant* of something (or a host where the peer is simply absent)
//! leaves nothing asserted at all, and then a regression lands silently on
//! every machine without Python. Together they cover both.
//!
//! Regenerate after changing the corpus:
//!
//! ```sh
//! ZIG_LIBS_JINJA_REGEN=$PWD/modules/jinja/src/testdata/golden.json \
//!   zig build test-jinja
//! ```
//!
//! The provenance of the file (which reference, which version, which command)
//! is recorded in the file itself and in SPEC.md.

const std = @import("std");
const testing = std.testing;
const corpus = @import("corpus.zig");
const conform = @import("conform.zig");

pub const golden_json = @embedFile("testdata/golden.json");

fn parseGolden(gpa: std.mem.Allocator) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, gpa, golden_json, .{});
}

test "golden: every corpus case matches the committed reference output" {
    const gpa = testing.allocator;
    var parsed = try parseGolden(gpa);
    defer parsed.deinit();
    const cases = parsed.value.object.get("cases").?;

    var failures: usize = 0;
    for (corpus.cases) |c| {
        const ref = conform.refOutcome(cases, c.name) orelse {
            std.debug.print("\ngolden: no entry for case '{s}' — regenerate the golden file\n", .{c.name});
            failures += 1;
            continue;
        };
        conform.expectMatch(gpa, c, ref, "golden") catch {
            failures += 1;
        };
    }
    if (failures != 0) {
        std.debug.print("\ngolden: {d} of {d} cases failed\n", .{ failures, corpus.cases.len });
        return error.GoldenMismatch;
    }
}

test "golden: the file has no entries the corpus no longer defines" {
    const gpa = testing.allocator;
    var parsed = try parseGolden(gpa);
    defer parsed.deinit();
    const cases = parsed.value.object.get("cases").?;

    var it = cases.object.iterator();
    while (it.next()) |e| {
        var found = false;
        for (corpus.cases) |c| {
            if (std.mem.eql(u8, c.name, e.key_ptr.*)) {
                found = true;
                break;
            }
        }
        if (!found) {
            std.debug.print("\ngolden: stale entry '{s}' — regenerate the golden file\n", .{e.key_ptr.*});
            return error.StaleGoldenEntry;
        }
    }
}

test "golden: records which reference produced it" {
    const gpa = testing.allocator;
    var parsed = try parseGolden(gpa);
    defer parsed.deinit();
    const version = parsed.value.object.get("jinja2") orelse return error.MissingProvenance;
    try testing.expect(std.mem.startsWith(u8, version.string, "3."));
}
