// SPDX-License-Identifier: MIT

//! Live interop against the **reference** Protocol Buffers implementation —
//! the Python `protobuf` package, which is Google's own.
//!
//! THIS IS A PROGRAM, NOT A TEST. It is built and run by
//! `zig build interop-protobuf`, compiled (never run) by
//! `zig build check-interop`, and is not part of `test-protobuf` or of the
//! `protobuf` module. Until 2026-09-06 it was `src/reference_interop.zig`: a
//! test inside the module that `@embedFile`d a Python driver and spawned
//! `python3` from inside the test suite. Every consumer of the module then
//! carried foreign source, and the suite could not run without a toolchain it
//! had no business needing — it "skipped loudly" instead, which in CI (where
//! the peer install is `continue-on-error`) is a skip nobody reads.
//!
//! The split leaves the anchor's VALUE in the module and its TAKING here:
//!
//!   - `--capture` runs the reference and freezes what it produced into
//!     `src/testdata/` — `golden_bytes.zig` (the reference's ENCODER output
//!     for every canonical case) and `interop_vectors.zig` (the reference's
//!     PARSER verdict on every byte string a canonical encoder would never
//!     emit). Both are committed, and `golden_test.zig` +
//!     `interop_replay_test.zig` replay them with no python3 anywhere.
//!   - the default mode re-derives all of that from the reference and
//!     compares — against our codec, and against the committed fixtures. It
//!     is what discovers a NEW divergence, and it is a pre-release check
//!     rather than a per-commit one.
//!
//! A protobuf codec that only ever talks to itself is close to worthless as
//! evidence. The strongest defects in this format are *consistent* between
//! encoder and decoder: drop the zigzag transform in both halves, or encode a
//! negative `int32` in five bytes instead of ten, and every round trip in this
//! repository still passes while every other implementation on the network
//! reads a different number. Only an outside implementation sees that.
//!
//! Usage, from the repository root:
//!
//!   zig build interop-protobuf                  # live check against python3
//!   zig build interop-protobuf -- --capture     # …and rewrite the fixtures
//!   zig build interop-protobuf -- --driver P    # non-default reference.py
//!
//! Needs `python3` with `pip install protobuf`. It does not skip: an absent
//! reference is a failure here, because running this program IS the request to
//! consult the reference.

const std = @import("std");
const pb = @import("protobuf");
const conf = pb.conformance;

const default_driver = "modules/protobuf/tools/reference.py";
const default_scratch = ".zig-cache/interop-protobuf";
const golden_path = "modules/protobuf/src/testdata/golden_bytes.zig";
const vectors_path = "modules/protobuf/src/testdata/interop_vectors.zig";

/// Anything the reference is asked about goes through here.
const Ref = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    driver: []const u8,
    scratch: []const u8,
    dir: std.Io.Dir,

    const in_bin = "in.bin";
    const out_bin = "out.bin";
    const out_txt = "out.txt";

    fn init(gpa: std.mem.Allocator, io: std.Io, driver: []const u8, scratch: []const u8) !Ref {
        // Scratch lives under `.zig-cache/`, never `/tmp`: a failing case's
        // bytes stay on disk next to the build that produced them.
        var dir = try std.Io.Dir.cwd().createDirPathOpen(io, scratch, .{});
        errdefer dir.close(io);
        return .{ .gpa = gpa, .io = io, .driver = driver, .scratch = scratch, .dir = dir };
    }

    fn deinit(self: *Ref) void {
        self.dir.close(self.io);
    }

    /// `error.ReferenceRejected` means the driver exited non-zero — for the
    /// parse ops that is the reference REFUSING the input, which is itself a
    /// verdict this program records.
    fn call(self: *Ref, argv: []const []const u8, quiet: bool) !void {
        var child = std.process.spawn(self.io, .{
            .argv = argv,
            .stdin = .close,
            .stdout = .ignore,
            .stderr = if (quiet) .ignore else .inherit,
        }) catch |e| {
            std.debug.print("could not spawn python3 ({s}) — the reference is required, not optional\n", .{@errorName(e)});
            return error.NoReference;
        };
        const term = try child.wait(self.io);
        switch (term) {
            .exited => |code| if (code != 0) return error.ReferenceRejected,
            else => return error.ReferenceCrashed,
        }
    }

    fn path(self: *Ref, name: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.gpa, "{s}/{s}", .{ self.scratch, name });
    }

    fn read(self: *Ref, name: []const u8) ![]u8 {
        return self.dir.readFileAlloc(self.io, name, self.gpa, .limited(1 << 20));
    }

    fn version(self: *Ref) ![]u8 {
        const out = try self.path(out_txt);
        defer self.gpa.free(out);
        try self.call(&.{ "python3", self.driver, "version", out }, false);
        return self.read(out_txt);
    }

    /// The bytes the reference emits for a named case.
    fn refEncode(self: *Ref, case: []const u8) ![]u8 {
        const out = try self.path(out_bin);
        defer self.gpa.free(out);
        try self.call(&.{ "python3", self.driver, "ref_encode", case, out }, false);
        return self.read(out_bin);
    }

    /// The reference's own parse of `bytes`, as a deterministic value dump.
    fn refDump(self: *Ref, case: []const u8, bytes: []const u8) ![]u8 {
        try self.dir.writeFile(self.io, .{ .sub_path = in_bin, .data = bytes });
        const in = try self.path(in_bin);
        defer self.gpa.free(in);
        const out = try self.path(out_txt);
        defer self.gpa.free(out);
        try self.call(&.{ "python3", self.driver, "dump", case, in, out }, true);
        return self.read(out_txt);
    }

    /// The dump the reference produces from its OWN value for that case.
    fn refExpect(self: *Ref, case: []const u8) ![]u8 {
        const out = try self.path(out_txt);
        defer self.gpa.free(out);
        try self.call(&.{ "python3", self.driver, "expect_dump", case, out }, false);
        return self.read(out_txt);
    }

    /// The reference's parse of `bytes` as message `msg`, re-serialized
    /// canonically — the verdict `interop_vectors.zig` freezes. A rejection
    /// surfaces as `error.ReferenceRejected`.
    fn normalize(self: *Ref, msg: []const u8, bytes: []const u8) ![]u8 {
        try self.dir.writeFile(self.io, .{ .sub_path = in_bin, .data = bytes });
        const in = try self.path(in_bin);
        defer self.gpa.free(in);
        const out = try self.path(out_bin);
        defer self.gpa.free(out);
        try self.call(&.{ "python3", self.driver, "normalize", msg, in, out }, true);
        return self.read(out_bin);
    }
};

// ── the live comparison ─────────────────────────────────────────────────────

var checks: usize = 0;
var failures: usize = 0;

fn ok(comptime fmt: []const u8, args: anytype) void {
    checks += 1;
    _ = fmt;
    _ = args;
}

fn bad(comptime fmt: []const u8, args: anytype) void {
    checks += 1;
    failures += 1;
    std.debug.print("MISMATCH  " ++ fmt ++ "\n", args);
}

fn expectBytes(what: []const u8, want: []const u8, got: []const u8) void {
    if (std.mem.eql(u8, want, got)) {
        ok("{s}", .{what});
    } else {
        bad("{s}\n  reference: {x}\n  ours:      {x}", .{ what, want, got });
    }
}

fn expectText(what: []const u8, want: []const u8, got: []const u8) void {
    if (std.mem.eql(u8, want, got)) {
        ok("{s}", .{what});
    } else {
        bad("{s}\n  reference: {s}\n  ours:      {s}", .{ what, want, got });
    }
}

fn runCases(ref: *Ref, comptime T: type, comptime cases: []const conf.Case(T)) !void {
    const gpa = ref.gpa;
    inline for (cases) |c| {
        const theirs = try ref.refEncode(c.name);
        defer gpa.free(theirs);

        // Direction 1: our bytes must be THEIR bytes, exactly.
        const ours = try pb.encodeAlloc(gpa, c.value, .{});
        defer gpa.free(ours);
        expectBytes(c.name, theirs, ours);

        // Direction 2: their bytes, decoded by us, must be the same values.
        if (pb.decode(T, gpa, theirs, .{})) |d| {
            var decoded = d;
            defer decoded.deinit();
            conf.expectMessageEqual(T, c.value, decoded.value) catch {
                bad("{s}: value mismatch after decoding the reference's bytes", .{c.name});
            };
        } else |e| {
            bad("{s}: we could not decode the reference's bytes ({s})", .{ c.name, @errorName(e) });
        }
    }
}

fn liveCheck(ref: *Ref) !void {
    const gpa = ref.gpa;

    try runCases(ref, conf.Wide, &conf.wide_cases);
    try runCases(ref, conf.Repeated, &conf.repeated_cases);
    try runCases(ref, conf.Presence, &conf.presence_cases);

    // The boxed recursive chain, whose value no flat case table can hold.
    {
        const theirs = try ref.refEncode("chain3");
        defer gpa.free(theirs);
        const ours = try pb.encodeAlloc(gpa, conf.chain3, .{});
        defer gpa.free(ours);
        expectBytes("chain3", theirs, ours);

        var decoded = try pb.decode(conf.Chain, gpa, theirs, .{});
        defer decoded.deinit();
        if (decoded.value.depth != 1 or decoded.value.next.?.depth != 2 or
            decoded.value.next.?.next.?.depth != 3)
            bad("chain3: decoded depths are not 1/2/3", .{});
    }

    // Their parser reading OUR bytes, against their own value dump. Byte
    // equality already implies this for the canonical cases, but this is the
    // check that stays meaningful for any case where it does not.
    inline for (conf.wide_cases) |c| {
        const ours = try pb.encodeAlloc(gpa, c.value, .{});
        defer gpa.free(ours);
        const got = try ref.refDump(c.name, ours);
        defer gpa.free(got);
        const want = try ref.refExpect(c.name);
        defer gpa.free(want);
        expectText("dump " ++ c.name, want, got);
    }

    // Packing flipped both ways: legal on the wire, never emitted by either
    // encoder, and a conforming parser must accept it.
    {
        const flipped = try pb.encodeAlloc(gpa, conf.Flipped{
            .nums = &.{ 1, 2, 150 },
            .unpacked = &.{ 1, 2, 150 },
        }, .{});
        defer gpa.free(flipped);
        const canonical = try pb.encodeAlloc(gpa, conf.Repeated{
            .nums = &.{ 1, 2, 150 },
            .unpacked = &.{ 1, 2, 150 },
        }, .{});
        defer gpa.free(canonical);
        if (std.mem.eql(u8, flipped, canonical)) bad("flipped packing produced the canonical bytes", .{});

        const dump_flipped = try ref.refDump("packed", flipped);
        defer gpa.free(dump_flipped);
        const dump_canonical = try ref.refDump("packed", canonical);
        defer gpa.free(dump_canonical);
        expectText("flipped packing reads the same as canonical", dump_canonical, dump_flipped);
        if (std.mem.indexOf(u8, dump_flipped, "nums=[1,2,150]") == null or
            std.mem.indexOf(u8, dump_flipped, "unpacked=[1,2,150]") == null)
            bad("flipped packing: the reference did not read 1,2,150 back", .{});
    }

    // The `MergeFrom` rule, and its absence for repeated message fields.
    {
        const two_copies = conf.semantic_cases[1].input;
        const theirs = try ref.refDump("submessage", two_copies);
        defer gpa.free(theirs);
        const merged = try pb.encodeAlloc(gpa, conf.Wide{ .inner = .{ .v = 1, .note = "x" } }, .{});
        defer gpa.free(merged);
        const want = try ref.refDump("submessage", merged);
        defer gpa.free(want);
        expectText("two singular submessages merge", want, theirs);

        const rep_two = conf.semantic_cases[2].input;
        const rep_theirs = try ref.refDump("rep_message", rep_two);
        defer gpa.free(rep_theirs);
        var rep_decoded = try pb.decode(conf.Repeated, gpa, rep_two, .{});
        defer rep_decoded.deinit();
        const rep_ours = try pb.encodeAlloc(gpa, rep_decoded.value, .{});
        defer gpa.free(rep_ours);
        const rep_want = try ref.refDump("rep_message", rep_ours);
        defer gpa.free(rep_want);
        expectText("repeated submessages do not merge", rep_want, rep_theirs);
        if (rep_decoded.value.inners.len != 2) bad("repeated submessage: expected 2 elements", .{});
    }

    // A message proxied through a partial schema keeps what it does not know.
    for (conf.forwarded_cases) |case| {
        const theirs = try ref.refEncode(case);
        defer gpa.free(theirs);

        var partial = try pb.decode(conf.WidePartial, gpa, theirs, .{});
        defer partial.deinit();
        if (partial.value.unknown.isEmpty()) {
            bad("{s}: nothing was preserved as unknown — the case is no longer a test", .{case});
            continue;
        }
        const forwarded = try pb.encodeAlloc(gpa, partial.value, .{});
        defer gpa.free(forwarded);

        const before = try ref.refDump("strings", theirs);
        defer gpa.free(before);
        const after = try ref.refDump("strings", forwarded);
        defer gpa.free(after);
        expectText("unknown fields preserved through a partial schema", before, after);
    }

    // Finally: does the committed record still say what the reference says?
    // This is the check that turns a stale fixture into a loud failure rather
    // than a replay of what the reference used to think.
    for (conf.semantic_cases) |c| {
        const frozen = findVerdict(c.name);
        if (ref.normalize(conf.schemaName(c.msg), c.input)) |got| {
            defer gpa.free(got);
            switch (frozen) {
                .missing => bad("{s}: no frozen verdict — run with --capture", .{c.name}),
                .rejected => bad("{s}: the fixture records a rejection, the reference accepted it", .{c.name}),
                .normalized => |want| if (c.expect != .accept)
                    bad("{s}: the reference now ACCEPTS what the case table says it rejects", .{c.name})
                else
                    expectBytes(c.name, want, got),
            }
        } else |e| switch (e) {
            error.ReferenceRejected => switch (frozen) {
                .missing => bad("{s}: no frozen verdict — run with --capture", .{c.name}),
                .normalized => bad("{s}: the fixture records an acceptance, the reference rejected it", .{c.name}),
                .rejected => if (c.expect == .accept)
                    bad("{s}: the reference now REJECTS what the case table says it accepts", .{c.name})
                else
                    ok("{s}", .{c.name}),
            },
            else => return e,
        }
    }
}

/// The committed verdict for `name`. `.missing` is not an error here — this
/// program is what fills the fixture in — but it IS a compile error in the
/// module's replay test, where a case with no frozen verdict would be a case
/// that silently stopped being checked.
const Frozen = union(enum) { missing, rejected, normalized: []const u8 };

fn findVerdict(name: []const u8) Frozen {
    for (conf.vectors.verdicts) |v| {
        if (std.mem.eql(u8, v.name, name)) return if (v.normalized) |n| .{ .normalized = n } else .rejected;
    }
    return .missing;
}

// ── the capture ─────────────────────────────────────────────────────────────

fn hexBytes(out: *std.ArrayList(u8), gpa: std.mem.Allocator, bytes: []const u8) !void {
    if (bytes.len == 0) {
        try out.appendSlice(gpa, "&.{}");
        return;
    }
    try out.appendSlice(gpa, "&.{ ");
    for (bytes, 0..) |b, i| {
        if (i != 0) try out.appendSlice(gpa, ", ");
        try out.print(gpa, "0x{x:0>2}", .{b});
    }
    try out.appendSlice(gpa, " }");
}

fn captureGolden(ref: *Ref, provenance: []const u8) !void {
    const gpa = ref.gpa;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try out.print(gpa,
        \\// SPDX-License-Identifier: MIT
        \\
        \\//! Golden bytes captured from the reference `google.protobuf` Python
        \\//! package -- the same package `tools/reference.py` drives live -- and
        \\//! committed here so the anchor holds everywhere python3 and the
        \\//! `protobuf` package are not installed, including CI, which never has it.
        \\//!
        \\//! These are not hand-derived: each entry is the literal
        \\//! `msg.SerializeToString(deterministic=True)` output for the value
        \\//! `tools/reference.py`'s `CASES` table builds for that name -- genuinely
        \\//! produced by Google's own encoder, not by our reading of the spec.
        \\//! `golden_test.zig` asserts both directions against them without ever
        \\//! invoking python: our encoder must reproduce these bytes exactly, and
        \\//! our decoder must recover the matching value from them.
        \\//!
        \\//! DETERMINISM. `deterministic=True` is what makes the capture a pure
        \\//! function of the case: without it the reference is free to order map
        \\//! entries (and, historically, unknown fields) however it likes. proto3
        \\//! field-number order then makes the encoding canonical for these
        \\//! messages, which is why `golden_test.zig` can assert byte equality
        \\//! rather than "it parses".
        \\//!
        \\//! GENERATED FILE -- do NOT hand-edit the byte arrays below. Regenerate:
        \\//!
        \\//!   zig build interop-protobuf -- --capture
        \\//!
        \\//! Reference: {s}
        \\
        \\const Entry = struct {{ name: []const u8, bytes: []const u8 }};
        \\
        \\
    , .{provenance});

    inline for (.{
        .{ "wide", conf.wide_cases },
        .{ "repeated", conf.repeated_cases },
        .{ "presence", conf.presence_cases },
    }) |group| {
        try out.print(gpa, "pub const {s} = [_]Entry{{\n", .{group[0]});
        inline for (group[1]) |c| {
            const bytes = try ref.refEncode(c.name);
            defer gpa.free(bytes);
            try out.print(gpa, "    .{{ .name = \"{s}\", .bytes = ", .{c.name});
            try hexBytes(&out, gpa, bytes);
            try out.appendSlice(gpa, " },\n");
        }
        try out.appendSlice(gpa, "};\n\n");
    }

    {
        const bytes = try ref.refEncode("chain3");
        defer gpa.free(bytes);
        try out.appendSlice(gpa,
            \\/// `Chain{depth=1, next=Chain{depth=2, next=Chain{depth=3}}}` -- the same
            \\/// value `conformance.zig`'s `chain3` builds.
            \\pub const chain3: []const u8 =
        );
        try out.appendSlice(gpa, " ");
        try hexBytes(&out, gpa, bytes);
        try out.appendSlice(gpa, ";\n");
    }

    try std.Io.Dir.cwd().writeFile(ref.io, .{ .sub_path = golden_path, .data = out.items });
    std.debug.print("wrote {s} ({d} bytes)\n", .{ golden_path, out.items.len });
}

fn captureVectors(ref: *Ref, provenance: []const u8) !void {
    const gpa = ref.gpa;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try out.print(gpa,
        \\// SPDX-License-Identifier: MIT
        \\
        \\//! The reference PARSER's verdict on every byte string in
        \\//! `conformance.zig`'s `semantic_cases` -- shapes a canonical encoder
        \\//! never emits, so no round trip through our own codec can settle any of
        \\//! them. Captured from the Python `protobuf` package and committed, which
        \\//! is what lets `interop_replay_test.zig` hold the same ground with no
        \\//! python3 anywhere.
        \\//!
        \\//! Each entry is `msg.ParseFromString(input)` followed by
        \\//! `SerializeToString(deterministic=True)`: the reference's own reading of
        \\//! the input, written back out canonically. `null` means the reference
        \\//! REFUSED the input (its parser raised), which for the `utf8_bad_*` cases
        \\//! is the verdict being recorded.
        \\//!
        \\//! Why the canonical re-serialization rather than the reference's text
        \\//! dump: it is the same information -- the dump lists every field
        \\//! including defaults, and a value that decoded wrongly to a default
        \\//! shortens the canonical bytes just as visibly -- without needing a Zig
        \\//! re-implementation of Python's float formatting to compare against.
        \\//!
        \\//! GENERATED FILE. Regenerate:
        \\//!
        \\//!   zig build interop-protobuf -- --capture
        \\//!
        \\//! Reference: {s}
        \\
        \\pub const Verdict = struct {{
        \\    name: []const u8,
        \\    /// The reference's canonical re-serialization of its own parse, or
        \\    /// `null` when the reference refused the input.
        \\    normalized: ?[]const u8,
        \\}};
        \\
        \\pub const verdicts = [_]Verdict{{
        \\
    , .{provenance});

    inline for (conf.semantic_cases) |c| {
        try out.print(gpa, "    .{{ .name = \"{s}\", .normalized = ", .{c.name});
        if (ref.normalize(conf.schemaName(c.msg), c.input)) |bytes| {
            defer gpa.free(bytes);
            if (c.expect != .accept) {
                std.debug.print("REFUSING TO CAPTURE: '{s}' is declared {s} but the reference accepted it\n", .{ c.name, @tagName(c.expect) });
                return error.ReferenceChangedItsMind;
            }
            try hexBytes(&out, gpa, bytes);
        } else |e| switch (e) {
            error.ReferenceRejected => {
                if (c.expect == .accept) {
                    std.debug.print("REFUSING TO CAPTURE: '{s}' is declared accept but the reference rejected it\n", .{c.name});
                    return error.ReferenceChangedItsMind;
                }
                try out.appendSlice(gpa, "null");
            },
            else => return e,
        }
        try out.appendSlice(gpa, " },\n");
    }
    try out.appendSlice(gpa, "};\n");

    try std.Io.Dir.cwd().writeFile(ref.io, .{ .sub_path = vectors_path, .data = out.items });
    std.debug.print("wrote {s} ({d} bytes)\n", .{ vectors_path, out.items.len });
}

// ── entry point ─────────────────────────────────────────────────────────────

pub fn main(init: std.process.Init.Minimal) !u8 {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var driver: []const u8 = default_driver;
    var scratch: []const u8 = default_scratch;
    var capture = false;

    var args = init.args.iterate();
    _ = args.skip();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--capture")) {
            capture = true;
        } else if (std.mem.eql(u8, a, "--driver")) {
            driver = args.next() orelse return usage();
        } else if (std.mem.eql(u8, a, "--scratch")) {
            scratch = args.next() orelse return usage();
        } else {
            std.debug.print("unknown argument '{s}'\n", .{a});
            return usage();
        }
    }

    var ref = Ref.init(gpa, io, driver, scratch) catch |e| {
        std.debug.print("could not open scratch dir '{s}': {s}\n", .{ scratch, @errorName(e) });
        return 2;
    };
    defer ref.deinit();

    const provenance = ref.version() catch |e| {
        std.debug.print(
            \\could not run the reference driver '{s}': {s}
            \\
            \\This program needs python3 with `pip install protobuf`, and it must be
            \\run from the repository root (`zig build interop-protobuf`).
            \\
        , .{ driver, @errorName(e) });
        return 2;
    };
    defer gpa.free(provenance);
    std.debug.print("reference: {s}\n", .{provenance});

    if (capture) {
        // Capture and stop. The live check compares against the fixtures as
        // this binary was COMPILED with, which the writes above just made
        // stale — reporting on that would be reporting on nothing.
        try captureGolden(&ref, provenance);
        try captureVectors(&ref, provenance);
        std.debug.print("fixtures rewritten — re-run `zig build interop-protobuf` to verify them\n", .{});
        return 0;
    }

    try liveCheck(&ref);
    std.debug.print("{d} checks, {d} mismatches\n", .{ checks, failures });
    return if (failures == 0) 0 else 1;
}

fn usage() u8 {
    std.debug.print(
        \\usage: zig build interop-protobuf -- [--capture] [--driver PATH] [--scratch DIR]
        \\
    , .{});
    return 2;
}
