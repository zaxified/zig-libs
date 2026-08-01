// SPDX-License-Identifier: MIT
//! Drives `parse` through the vendored W3C XML Conformance Test Suite
//! (xmlconf_vectors.zig; see NOTICE for provenance) in both directions:
//! `reject_vectors` (xmlconf TYPE="not-wf") must fail to parse under default
//! Options; `accept_vectors` (xmlconf TYPE="valid", i.e. well-formed) must
//! parse successfully with Options{.doctype = .ignore} (see
//! xmlconf_vectors.zig's header for why every accept vector needs that).
//!
//! Scope recap (full reasoning + counts live in NOTICE): this module is a
//! non-validating, XML-1.0-only, UTF-8-only parser with no external-entity/
//! DTD-content support by design. xmlconf's "invalid" and "error" categories
//! are entirely out of scope (DTD validity constraints / optional-error
//! conditions), as are XML/Namespaces 1.1 cases, wide-encoded (e.g. UTF-16)
//! cases, cases needing external-subset access, and -- for the reject
//! direction specifically -- any not-wf case whose labeled defect lives
//! inside a DOCTYPE (our default policy rejects the DOCTYPE itself before
//! ever looking at what's wrong inside it, which would make the vector
//! trivially "pass" without exercising the labeled defect at all).
//!
//! `known_disagreements` are asserted against the OPPOSITE of the vector's
//! expectation: a real, confirmed gap between this module and the xmlconf
//! oracle. See the comment beside `known_disagreements` below for each case.

const std = @import("std");
const testing = std.testing;
const xml = @import("root.zig");
const vectors_mod = @import("xmlconf_vectors.zig");

/// Real disagreements between this module and xmlconf, found by running the
/// corpus. Each entry names a case this module currently gets wrong relative
/// to the labeled xmlconf verdict. Fix what's small and obviously correct;
/// what's listed here has NOT been fixed -- see NOTICE / the task report for
/// why, one line per case.
const KnownDisagreement = struct {
    id: []const u8,
    /// true if this is a reject_vector expected to (wrongly) parse instead
    /// of erroring; false if it's an accept_vector expected to (wrongly)
    /// error instead of parsing.
    is_reject_vector: bool,
};

const known_disagreements = [_]KnownDisagreement{};

fn findDisagreement(id: []const u8, is_reject_vector: bool) bool {
    for (known_disagreements) |kd| {
        if (kd.is_reject_vector == is_reject_vector and std.mem.eql(u8, kd.id, id)) return true;
    }
    return false;
}

test "xmlconf corpus: vendored count matches expectation (canary)" {
    // If this trips, testdata/xmlconf/ was re-vendored or hand-edited without
    // regenerating xmlconf_vectors.zig -- regenerate it, don't adjust these
    // numbers to match. See NOTICE for the full include/exclude accounting
    // (1377 xmlconf TEST entries parsed; 25 + 105 = 130 vendored here -- see
    // NOTICE for why the xmltest sub-suite, the largest single chunk of
    // xmlconf, is excluded entirely on license grounds rather than scope).
    try testing.expectEqual(@as(usize, 25), vectors_mod.reject_vectors.len);
    try testing.expectEqual(@as(usize, 105), vectors_mod.accept_vectors.len);
}

test "xmlconf corpus: not-wf vectors are rejected under default options" {
    const alloc = testing.allocator;
    var checked: usize = 0;
    var mismatches: usize = 0;

    for (vectors_mod.reject_vectors) |v| {
        const known = findDisagreement(v.id, true);
        var doc = xml.parse(alloc, v.content, .{}) catch |err| {
            if (known) {
                std.debug.print(
                    "known_disagreements entry '{s}' now correctly rejects ({s}) -- " ++
                        "the disagreement is gone; remove it from known_disagreements.\n",
                    .{ v.id, @errorName(err) },
                );
                mismatches += 1;
            }
            checked += 1;
            continue;
        };
        doc.deinit();
        if (!known) {
            std.debug.print(
                "MISMATCH not-wf case '{s}' ({s}, sections {s}): expected rejection, " ++
                    "but it parsed. \"{s}\"\n",
                .{ v.id, v.suite, v.sections, v.desc },
            );
            mismatches += 1;
        }
        checked += 1;
    }

    try testing.expectEqual(vectors_mod.reject_vectors.len, checked);
    try testing.expectEqual(@as(usize, 0), mismatches);
}

test "xmlconf corpus: valid (well-formed) vectors parse under doctype=.ignore" {
    const alloc = testing.allocator;
    var checked: usize = 0;
    var mismatches: usize = 0;

    for (vectors_mod.accept_vectors) |v| {
        const known = findDisagreement(v.id, false);
        const opts = xml.Options{ .doctype = if (v.needs_doctype_ignore) .ignore else .reject };
        var doc = xml.parse(alloc, v.content, opts) catch |err| {
            if (err == error.OutOfMemory) return err;
            if (!known) {
                std.debug.print(
                    "MISMATCH valid case '{s}' ({s}, sections {s}): expected to parse, " ++
                        "got {s}. \"{s}\"\n",
                    .{ v.id, v.suite, v.sections, @errorName(err), v.desc },
                );
                mismatches += 1;
            }
            checked += 1;
            continue;
        };
        doc.deinit();
        if (known) {
            std.debug.print(
                "known_disagreements entry '{s}' now correctly parses -- " ++
                    "the disagreement is gone; remove it from known_disagreements.\n",
                .{v.id},
            );
            mismatches += 1;
        }
        checked += 1;
    }

    try testing.expectEqual(vectors_mod.accept_vectors.len, checked);
    try testing.expectEqual(@as(usize, 0), mismatches);
}
