// SPDX-License-Identifier: MIT
//! Drives `validate.validateFormat` through the vendored
//! json-schema-org/JSON-Schema-Test-Suite `optional/format/*.json` corpus
//! (json_schema_format_vectors.zig; provenance: ../../NOTICE).
//!
//! Each vendored file is a JSON array of "groups": `{description, schema:
//! {format}, tests: [{description, data, valid}, ...]}`. Per JSON Schema
//! `format`-as-assertion semantics, the keyword only constrains instances of
//! the type it applies to (a string, for every format this module
//! implements) -- an instance of any other JSON type is trivially valid
//! regardless of `format`. That is not a scope limit of this module: it is
//! how the corpus itself is written (every file opens with six "all string
//! formats ignore <type>" cases asserting exactly this), so the harness
//! applies it uniformly rather than special-casing each format.
//!
//! `group_skips` / `case_skips` name corpus material this module's SPEC.md /
//! README explicitly document as out of scope, with a reason each. Every
//! skip is counted, never silently dropped -- the canary test below fails
//! loudly if the vendored corpus changes shape without this file being
//! reconsidered.

const std = @import("std");
const testing = std.testing;
const validate = @import("root.zig");
const vectors_mod = @import("json_schema_format_vectors.zig");

/// An entire schema group excluded from assertion (but not from being run --
/// it still must not crash). Keyed by (vendored file, group description).
const GroupSkip = struct {
    path: []const u8,
    group: []const u8,
    reason: []const u8,
};

const group_skips = [_]GroupSkip{
    .{
        .path = "hostname.json",
        .group = "validation of A-label (punycode) host names",
        .reason = "tests IDNA A-label semantic validity (RFC 5891/5892 Punycode " ++
            "decoding + Unicode BIDI/contextual class rules) -- a fundamentally " ++
            "different, Unicode-table-dependent validation surface. isHostname is " ++
            "documented (root.zig Format doc, README) as RFC 1123 label SHAPE only " ++
            "(1-63 alnum/hyphen chars, ASCII) and never claimed to decode or " ++
            "semantically validate Punycode -- every case in this group is a " ++
            "syntactically well-formed RFC-1123 label (ASCII alnum/hyphen only), so " ++
            "this module accepts all of them regardless of the BIDI verdict the " ++
            "corpus expects.",
    },
};

/// One specific test case excluded from assertion. Keyed by (vendored file,
/// case description).
const CaseSkip = struct {
    path: []const u8,
    case: []const u8,
    reason: []const u8,
};

const case_skips = [_]CaseSkip{
    .{
        .path = "email.json",
        .case = "a quoted string with a space in the local part is valid",
        .reason = "quoted-string local part -- isEmail's doc comment states " ++
            "\"No quoted-string locals\" (dot-atom only); README/SPEC.md list the " ++
            "same limit.",
    },
    .{
        .path = "email.json",
        .case = "a quoted string with a double dot in the local part is valid",
        .reason = "quoted-string local part -- see above.",
    },
    .{
        .path = "email.json",
        .case = "a quoted string with a @ in the local part is valid",
        .reason = "quoted-string local part -- see above.",
    },
    .{
        .path = "email.json",
        .case = "an IPv4-address-literal after the @ is valid",
        .reason = "domain address-literal (`[127.0.0.1]`) -- isEmail's doc comment " ++
            "states \"no address literals\"; the domain must be a dotted hostname.",
    },
    .{
        .path = "email.json",
        .case = "an IPv6-address-literal after the @ is valid",
        .reason = "domain address-literal (`[IPv6:::1]`) -- see above.",
    },
    .{
        .path = "date-time.json",
        .case = "an invalid date-time with leap second on a wrong hour, UTC",
        .reason = "leap-second-anywhere -- isTime's doc comment states seconds " ++
            "\"= 60 (leap second) ... accepted at any time of day since the " ++
            "grammar cannot know the leap-second table\", a pre-existing " ++
            "documented design choice, not an oversight.",
    },
    .{
        .path = "date-time.json",
        .case = "an invalid date-time with leap second on a wrong minute, UTC",
        .reason = "leap-second-anywhere -- see above.",
    },
    .{
        .path = "time.json",
        .case = "invalid leap second, Zulu (wrong hour)",
        .reason = "leap-second-anywhere -- see the date-time.json entries above; " ++
            "same documented isTime design choice.",
    },
    .{
        .path = "time.json",
        .case = "invalid leap second, Zulu (wrong minute)",
        .reason = "leap-second-anywhere -- see above.",
    },
    .{
        .path = "time.json",
        .case = "invalid leap second, zero time-offset (wrong hour)",
        .reason = "leap-second-anywhere -- see above.",
    },
    .{
        .path = "time.json",
        .case = "invalid leap second, zero time-offset (wrong minute)",
        .reason = "leap-second-anywhere -- see above.",
    },
    .{
        .path = "time.json",
        .case = "invalid leap second, positive time-offset (wrong hour)",
        .reason = "leap-second-anywhere -- see above.",
    },
    .{
        .path = "time.json",
        .case = "invalid leap second, positive time-offset (wrong minute)",
        .reason = "leap-second-anywhere -- see above.",
    },
    .{
        .path = "time.json",
        .case = "invalid leap second, negative time-offset (wrong hour)",
        .reason = "leap-second-anywhere -- see above.",
    },
    .{
        .path = "time.json",
        .case = "invalid leap second, negative time-offset (wrong minute)",
        .reason = "leap-second-anywhere -- see above.",
    },
    .{
        .path = "time.json",
        .case = "an invalid time string with invalid leap second (wrong hour)",
        .reason = "leap-second-anywhere -- see above.",
    },
    .{
        .path = "time.json",
        .case = "an invalid time string with invalid leap second (wrong minute)",
        .reason = "leap-second-anywhere -- see above.",
    },
    .{
        .path = "time.json",
        .case = "no time offset",
        .reason = "offset-optional -- isTime's doc comment states the UTC offset " ++
            "\"is optional (offset-less local times are accepted -- ISO 8601 " ++
            "profile, slightly laxer than RFC 3339)\", a pre-existing documented " ++
            "design choice: this format implements an ISO 8601 local-time " ++
            "profile, not RFC 3339 proper (which mandates an offset).",
    },
    .{
        .path = "time.json",
        .case = "no time offset with second fraction",
        .reason = "offset-optional -- see above.",
    },
    .{
        .path = "uri.json",
        .case = "invalid userinfo",
        .reason = "authority-shape (userinfo) validation -- isUri's doc comment " ++
            "states \"Not a full parser: component splitting and authority shape " ++
            "are out of scope\"; this checker validates the character grammar " ++
            "only, not URI component structure.",
    },
    .{
        .path = "uri.json",
        .case = "non-numeric port is invalid",
        .reason = "authority-shape (port) validation -- see above.",
    },
};

fn findGroupSkip(path: []const u8, group: []const u8) ?[]const u8 {
    for (group_skips) |s| {
        if (std.mem.eql(u8, s.path, path) and std.mem.eql(u8, s.group, group)) return s.reason;
    }
    return null;
}

fn findCaseSkip(path: []const u8, case: []const u8) ?[]const u8 {
    for (case_skips) |s| {
        if (std.mem.eql(u8, s.path, path) and std.mem.eql(u8, s.case, case)) return s.reason;
    }
    return null;
}

const Tally = struct {
    total: usize = 0,
    executed: usize = 0,
    skipped: usize = 0,
    mismatches: usize = 0,
};

/// Run every vendored file's every case (skips still run, just unasserted,
/// so a skip can never hide a crash) and accumulate counts + print every
/// mismatch instead of failing at the first one.
fn runAll(alloc: std.mem.Allocator) !Tally {
    var tally: Tally = .{};
    for (vectors_mod.files) |fv| {
        var parsed = try std.json.parseFromSlice(std.json.Value, alloc, fv.content, .{});
        defer parsed.deinit();
        const groups = parsed.value.array.items;
        for (groups) |group| {
            const group_desc = group.object.get("description").?.string;
            const group_reason = findGroupSkip(fv.path, group_desc);
            const cases = group.object.get("tests").?.array.items;
            for (cases) |case| {
                tally.total += 1;
                const case_desc = case.object.get("description").?.string;
                const data = case.object.get("data").?;
                const expected = case.object.get("valid").?.bool;

                // Always compute the actual verdict, even for skipped cases,
                // so a skip can never mask a crash/panic in the validator.
                const actual: bool = if (data != .string)
                    true // format is a string-only assertion; other types trivially pass
                else
                    validate.validateFormat(fv.format, data.string);

                if (group_reason != null or findCaseSkip(fv.path, case_desc) != null) {
                    tally.skipped += 1;
                    continue;
                }

                if (actual != expected) {
                    std.debug.print(
                        "MISMATCH {s} :: \"{s}\": data={f} expected valid={} got valid={}\n",
                        .{ fv.path, case_desc, std.json.fmt(data, .{}), expected, actual },
                    );
                    tally.mismatches += 1;
                }
                tally.executed += 1;
            }
        }
    }
    return tally;
}

test "json-schema-test-suite format corpus: vendored file count matches expectation (canary)" {
    // If this trips, the optional/format/ file selection changed (re-vendor
    // added/removed a format this module implements) without updating
    // json_schema_format_vectors.zig -- reconsider the list, don't adjust
    // this number to match.
    try testing.expectEqual(@as(usize, 12), vectors_mod.files.len);
}

test "json-schema-test-suite format corpus: total/skip counts match expectation (canary)" {
    const alloc = testing.allocator;
    const tally = try runAll(alloc);
    // If this trips, the vendored corpus changed shape (re-vendored at a
    // different commit, or a file/group/case count moved) -- investigate and
    // update these numbers deliberately, don't silently accept a new shape.
    try testing.expectEqual(@as(usize, 485), tally.total);
    try testing.expectEqual(@as(usize, 59), tally.skipped);
    try testing.expectEqual(@as(usize, 426), tally.executed);
}

test "json-schema-test-suite format corpus: every in-scope case agrees with validateFormat" {
    const alloc = testing.allocator;
    const tally = try runAll(alloc);
    try testing.expectEqual(@as(usize, 0), tally.mismatches);
}
