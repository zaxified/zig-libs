// SPDX-License-Identifier: MIT
//! The conformance anchor, replayed: every case in `testdata/golden.json`
//! rendered by this engine and compared byte for byte with what Python Jinja2
//! produced for the same inputs — with no child process, no Python and no
//! foreign source anywhere in the module.
//!
//! ## Where the transcript comes from
//!
//! `tools/interop.zig` renders `tools/corpus.zig` with the reference and
//! captures inputs *and* outputs:
//!
//! ```sh
//! zig build interop-jinja -- --capture   # re-take it (needs python3+jinja2)
//! zig build interop-jinja                # re-run the peer, diff, no rewrite
//! ```
//!
//! Until 2026-09-06 half of this ran here, spawning `python3` from inside
//! `zig build test-jinja` and skipping loudly without it. A skip is not an
//! assertion, and CI's peer install is `continue-on-error`, so the live half
//! could quietly assert nothing while every consumer of the library still
//! carried an embedded Python driver. The anchor's *taking* now lives in
//! `tools/`; its *value* lives here, in the lane that runs everywhere.
//!
//! ## Why this is not the whole story, and what still needs the peer
//!
//! A committed transcript catches a regression in this engine on every host.
//! What it cannot catch is the reference *changing* — a Jinja2 upgrade that
//! moves a rendered byte. That is what `zig build interop-jinja` is for, as a
//! pre-release check. The two cover different classes and neither subsumes the
//! other; what changed is only which of them has to run per commit.
//!
//! ## Determinism
//!
//! Rendering depends on more than the template — the Jinja2 version, MarkupSafe,
//! the per-case autoescape/undefined/whitespace knobs, the delimiters, the
//! `policies` table and Python's float repr. All of it is recorded in the
//! transcript's header (per-case knobs in the case), and the last test in this
//! file requires it to be there. Nothing is made deterministic by comparing
//! less: every case is compared, and on the full rendered byte string.

const std = @import("std");
const testing = std.testing;
const conform = @import("conform.zig");

pub const golden_json = @embedFile("testdata/golden.json");

/// The corpus size at the last capture. A replay that passes because it stopped
/// looking is worse than no replay, and the corpus now lives outside the module
/// (`tools/corpus.zig`), so this is the module's own floor on how much of the
/// anchor it is allowed to hold. Raise it when the corpus grows; it may not
/// fall without a CHANGELOG entry saying which cases went and why.
const min_cases = 351;

fn parseGolden(gpa: std.mem.Allocator) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, gpa, golden_json, .{});
}

test "replay: every recorded case matches the reference's output byte for byte" {
    const gpa = testing.allocator;
    var parsed = try parseGolden(gpa);
    defer parsed.deinit();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();

    const cases = parsed.value.object.get("cases").?.array.items;
    var failures: usize = 0;
    for (cases) |entry| {
        const c = try conform.caseFromJson(arena.allocator(), entry);
        conform.expectMatch(gpa, c, conform.refFromJson(entry), "replay") catch {
            failures += 1;
        };
    }
    if (failures != 0) {
        std.debug.print("\nreplay: {d} of {d} cases failed\n", .{ failures, cases.len });
        return error.ReferenceMismatch;
    }
}

test "replay: the transcript still covers the whole corpus" {
    const gpa = testing.allocator;
    var parsed = try parseGolden(gpa);
    defer parsed.deinit();
    const cases = parsed.value.object.get("cases").?.array.items;

    if (cases.len < min_cases) {
        std.debug.print(
            "\nthe transcript holds {d} cases, down from {d} — coverage shrank\n",
            .{ cases.len, min_cases },
        );
        return error.CoverageShrank;
    }

    // Names are the key the transcript is read back by, and a duplicate would
    // silently halve what one of them asserts.
    var seen: std.StringHashMapUnmanaged(void) = .empty;
    defer seen.deinit(gpa);
    for (cases) |c| {
        const gop = try seen.getOrPut(gpa, c.object.get("name").?.string);
        try testing.expect(!gop.found_existing);
    }
}

test "replay: every recorded case carries the inputs it was rendered from" {
    // The transcript is input-to-output pairs, not outputs alone: that is what
    // lets `tools/interop.zig` re-run the reference on exactly these inputs
    // without the Zig corpus, and what makes a fixture entry self-describing.
    const gpa = testing.allocator;
    var parsed = try parseGolden(gpa);
    defer parsed.deinit();

    var with_loader: usize = 0;
    var expecting_error: usize = 0;
    var autoescaped: usize = 0;
    for (parsed.value.object.get("cases").?.array.items) |c| {
        inline for (.{ "name", "template", "context", "templates", "status" }) |k| {
            if (c.object.get(k) == null) {
                std.debug.print("\ntranscript entry is missing '{s}'\n", .{k});
                return error.MissingInput;
            }
        }
        inline for (.{ "autoescape", "strict", "trim_blocks", "lstrip_blocks", "keep_trailing_newline", "expect_error" }) |k| {
            _ = c.object.get(k).?.bool;
        }
        if (c.object.get("templates").?.object.count() != 0) with_loader += 1;
        if (c.object.get("expect_error").?.bool) expecting_error += 1;
        if (c.object.get("autoescape").?.bool) autoescaped += 1;
    }

    // The corners this corpus exists for have to be present in numbers, not in
    // principle: a transcript of 351 happy-path cases would satisfy every
    // assertion above and be worth much less. The floors are the counts at the
    // 2026-09-06 capture (51 / 30 / 36), rounded down.
    try testing.expect(with_loader >= 50);
    try testing.expect(expecting_error >= 30);
    try testing.expect(autoescaped >= 35);

    // `expect_error` must describe the transcript, not merely sit in it: every
    // case the corpus marks has to be one the reference actually refused.
    var refused: usize = 0;
    for (parsed.value.object.get("cases").?.array.items) |c| {
        if (std.mem.eql(u8, c.object.get("status").?.string, "error")) {
            try testing.expect(c.object.get("expect_error").?.bool);
            refused += 1;
        }
    }
    try testing.expectEqual(expecting_error, refused);
}

test "replay: the transcript records which reference produced it" {
    // Provenance is part of the artifact, not of a comment that can drift from
    // it. `determinism` is the half that makes a re-capture comparable: the
    // knobs outside the template that decide the bytes above.
    const gpa = testing.allocator;
    var parsed = try parseGolden(gpa);
    defer parsed.deinit();
    const o = parsed.value.object;

    const version = o.get("jinja2") orelse return error.MissingProvenance;
    try testing.expect(std.mem.startsWith(u8, version.string, "3."));
    inline for (.{ "markupsafe", "python", "captured", "command", "driver" }) |k| {
        const v = o.get(k) orelse {
            std.debug.print("\ntranscript header is missing '{s}'\n", .{k});
            return error.MissingProvenance;
        };
        try testing.expect(v.string.len > 0);
    }

    const det = (o.get("determinism") orelse return error.MissingProvenance).object;
    inline for (.{
        "process_env",
        "float_repr_style",
        "autoescape_default",
        "undefined_default",
        "newline_sequence",
        "delimiters",
        "extensions",
        "policies",
    }) |k| {
        if (det.get(k) == null) {
            std.debug.print("\ntranscript determinism block is missing '{s}'\n", .{k});
            return error.MissingProvenance;
        }
    }
    // The capture must have pinned hash randomisation rather than inheriting
    // whatever the operator's shell had.
    const env = det.get("process_env").?.object;
    try testing.expectEqualStrings("0", env.get("PYTHONHASHSEED").?.string);
    // No extensions were loaded, so no case can depend on one being present.
    try testing.expectEqual(@as(usize, 0), det.get("extensions").?.array.items.len);
}
