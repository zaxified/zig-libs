// SPDX-License-Identifier: MIT

//! Live interop against the **reference** Protocol Buffers implementation —
//! the Python `protobuf` package, which is Google's own.
//!
//! A protobuf codec that only ever talks to itself is close to worthless as
//! evidence. The strongest defects in this format are *consistent* between
//! encoder and decoder: drop the zigzag transform in both halves, or encode
//! a negative `int32` in five bytes instead of ten, and every round trip in
//! this repository still passes while every other implementation on the
//! network reads a different number. Only an outside implementation sees it,
//! which is why this file, not `codec_test.zig`, is the module's real anchor.
//!
//! Both directions are exercised, plus the byte-exact one:
//!   - our encoder's bytes are compared **byte for byte** with what the
//!     reference emits for the same values (proto3 field-number order makes
//!     the encoding canonical for these messages, so equality is the right
//!     assertion, not merely "it parses");
//!   - the reference's bytes are decoded by us and compared field by field;
//!   - our bytes are handed to the reference's *parser* in shapes the
//!     reference itself would never emit (packing flipped both ways, and a
//!     message reassembled from preserved unknown fields).
//!
//! The schemas are built at runtime out of `descriptor_pb2` +
//! `descriptor_pool` + `message_factory`, so no `.proto` file and no
//! `protoc` are involved — see `testdata/reference.py`. Its `CASES` table
//! mirrors `cases` below name for name; that shared table is the whole
//! marshalling protocol between the two processes.
//!
//! Every test **skips loudly** when python3 or the `protobuf` package is
//! missing — never silently, and never as a failure. Set
//! `ZIG_LIBS_VERBOSE_SKIP` to see the reason.

const std = @import("std");
const testing = std.testing;
const pb = @import("root.zig");
const ct = @import("codec_test.zig");
const schema = @import("schema.zig");

const Field = pb.Field;

fn verboseSkip() bool {
    const v = std.process.Environ.getPosix(std.testing.environ, "ZIG_LIBS_VERBOSE_SKIP") orelse return false;
    return v.len > 0;
}

fn skip(comptime reason: []const u8) error{SkipZigTest} {
    if (verboseSkip()) std.debug.print("SKIPPED: " ++ reason ++ "\n", .{});
    return error.SkipZigTest;
}

fn requirePython(io: std.Io) error{SkipZigTest}!void {
    var child = std.process.spawn(io, .{
        .argv = &.{ "python3", "-c", "import google.protobuf" },
        .stdin = .close,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return skip("python3 not found — reference-interop tests need it");
    const term = child.wait(io) catch return skip("python3 could not be waited on");
    switch (term) {
        .exited => |code| if (code != 0)
            return skip("python3 has no `protobuf` module (pip install protobuf)"),
        else => return skip("python3 terminated abnormally"),
    }
}

/// A scratch directory used as the reference driver's cwd.
const Ref = struct {
    tmp: testing.TmpDir,
    io: std.Io,
    gpa: std.mem.Allocator,

    const driver = @embedFile("testdata/reference.py");

    fn init(gpa: std.mem.Allocator, io: std.Io) error{SkipZigTest}!Ref {
        try requirePython(io);
        return .{ .tmp = testing.tmpDir(.{}), .io = io, .gpa = gpa };
    }

    fn deinit(self: *Ref) void {
        self.tmp.cleanup();
    }

    fn run(self: *Ref, op: []const u8, case: []const u8, out_file: []const u8) ![]u8 {
        self.tmp.dir.deleteFile(self.io, out_file) catch {};
        var child = try std.process.spawn(self.io, .{
            .argv = &.{ "python3", "-c", driver, op, case },
            .cwd = .{ .dir = self.tmp.dir },
            .stdin = .close,
            .stdout = .ignore,
            .stderr = .ignore,
        });
        const term = try child.wait(self.io);
        switch (term) {
            .exited => |code| if (code != 0) return error.ReferenceRejected,
            else => return error.ReferenceCrashed,
        }
        return self.tmp.dir.readFileAlloc(self.io, out_file, self.gpa, .limited(1 << 20));
    }

    /// The bytes the reference emits for a named case.
    fn refEncode(self: *Ref, case: []const u8) ![]u8 {
        return self.run("ref_encode", case, "out.bin");
    }

    /// The reference's own parse of `bytes`, as a deterministic value dump.
    /// `error.ReferenceRejected` means the reference refused our stream.
    fn refDump(self: *Ref, case: []const u8, bytes: []const u8) ![]u8 {
        try self.tmp.dir.writeFile(self.io, .{ .sub_path = "in.bin", .data = bytes });
        return self.run("dump", case, "out.txt");
    }

    /// The dump the reference produces from its OWN value for that case —
    /// the expected right-hand side for `refDump`.
    fn refExpect(self: *Ref, case: []const u8) ![]u8 {
        return self.run("expect_dump", case, "out.txt");
    }
};

// ── generic structural comparison ───────────────────────────────────────────

fn expectMessageEqual(comptime T: type, want: T, got: T) !void {
    inline for (comptime schema.infos(T)) |info| {
        const a = @field(want, info.name);
        const b = @field(got, info.name);
        switch (info.card) {
            .singular => try expectElemEqual(info.kind, info.Elem, a, b),
            .optional => {
                if (a == null or b == null) {
                    try testing.expect((a == null) == (b == null));
                } else if (info.boxed) {
                    try expectElemEqual(info.kind, info.Elem, a.?.*, b.?.*);
                } else {
                    try expectElemEqual(info.kind, info.Elem, a.?, b.?);
                }
            },
            .repeated => {
                try testing.expectEqual(a.len, b.len);
                for (a, b) |x, y| try expectElemEqual(info.kind, info.Elem, x, y);
            },
        }
    }
}

fn expectElemEqual(comptime kind: pb.Kind, comptime E: type, a: E, b: E) !void {
    switch (kind) {
        .string, .bytes => try testing.expectEqualSlices(u8, a, b),
        .message => try expectMessageEqual(E, a, b),
        else => try testing.expectEqual(a, b),
    }
}

// ── the shared case table ───────────────────────────────────────────────────

fn Case(comptime T: type) type {
    return struct { name: []const u8, value: T };
}

const MIN32 = std.math.minInt(i32);
const MAX32 = std.math.maxInt(i32);
const MIN64 = std.math.minInt(i64);
const MAX64 = std.math.maxInt(i64);

const wide_cases = [_]Case(ct.Wide){
    .{ .name = "spec150", .value = .{ .i32_ = 150 } },
    .{ .name = "neg_int32", .value = .{ .i32_ = -1 } },
    .{ .name = "neg_int64", .value = .{ .i64_ = -2 } },
    .{ .name = "min_int32", .value = .{ .i32_ = MIN32 } },
    .{ .name = "min_int64", .value = .{ .i64_ = MIN64 } },
    .{ .name = "zigzag_neg", .value = .{ .s32 = -1, .s64 = -1 } },
    .{ .name = "zigzag_pos", .value = .{ .s32 = 1, .s64 = 1 } },
    .{ .name = "zigzag_min", .value = .{ .s32 = MIN32, .s64 = MIN64 } },
    .{ .name = "zigzag_max", .value = .{ .s32 = MAX32, .s64 = MAX64 } },
    .{ .name = "unsigned_max", .value = .{ .u32_ = std.math.maxInt(u32), .u64_ = std.math.maxInt(u64) } },
    .{ .name = "varint_edges", .value = .{ .u64_ = 127 } },
    .{ .name = "varint_128", .value = .{ .u64_ = 128 } },
    .{ .name = "bool_enum", .value = .{ .b = true, .color = .green } },
    .{ .name = "enum_open", .value = .{ .color = @enumFromInt(9999) } },
    .{ .name = "fixed_all", .value = .{
        .f64_ = std.math.maxInt(u64),
        .sf64 = MIN64,
        .f32_ = std.math.maxInt(u32),
        .sf32 = MIN32,
    } },
    .{ .name = "floats", .value = .{ .d = -1.5e300, .f = 3.5 } },
    .{ .name = "float_frac", .value = .{ .d = 0.1, .f = 0.1 } },
    .{ .name = "strings", .value = .{
        .s = "unicode: ěščřž 🎉",
        .raw = &.{ 0x00, 0xff, 0x7f, 0x80 },
    } },
    .{ .name = "submessage", .value = .{ .inner = .{ .v = -9, .note = "n" } } },
    .{ .name = "empty", .value = .{} },
};

const repeated_cases = [_]Case(ct.Repeated){
    .{ .name = "packed", .value = .{ .nums = &.{ 1, 2, 150 } } },
    .{ .name = "packed_neg", .value = .{ .nums = &.{ -1, 0, 1, 150, MAX32 } } },
    .{ .name = "unpacked", .value = .{ .unpacked = &.{ 1, 2, 150 } } },
    .{ .name = "rep_zigzag", .value = .{ .zz = &.{ -1, 1, MIN64 } } },
    .{ .name = "rep_fixed", .value = .{ .fixed = &.{ 0, 0xdeadbeef } } },
    .{ .name = "rep_bool", .value = .{ .flags = &.{ true, false, true } } },
    .{ .name = "rep_enum", .value = .{ .colors = &.{ .red, .green, @enumFromInt(77) } } },
    .{ .name = "rep_string", .value = .{ .names = &.{ "", "a", "long-ish string" } } },
    .{ .name = "rep_message", .value = .{ .inners = &.{ .{ .v = 1 }, .{ .v = 2, .note = "x" } } } },
    .{ .name = "rep_empty", .value = .{} },
};

const presence_cases = [_]Case(ct.Presence){
    .{ .name = "pres_default", .value = .{ .implicit = 0 } },
    .{ .name = "pres_set", .value = .{ .implicit = 1 } },
    .{ .name = "pres_expl_0", .value = .{ .explicit = 0 } },
    .{ .name = "pres_expl_5", .value = .{ .explicit = 5 } },
    .{ .name = "pres_str_0", .value = .{ .explicit_str = "" } },
};

fn runCases(ref: *Ref, comptime T: type, comptime cases: []const Case(T)) !void {
    const gpa = ref.gpa;
    inline for (cases) |c| {
        const theirs = ref.refEncode(c.name) catch |e| {
            std.debug.print("reference failed to encode case '{s}'\n", .{c.name});
            return e;
        };
        defer gpa.free(theirs);

        // Direction 1: our bytes must be THEIR bytes, exactly.
        const ours = try pb.encodeAlloc(gpa, c.value, .{});
        defer gpa.free(ours);
        testing.expectEqualSlices(u8, theirs, ours) catch |e| {
            std.debug.print("byte mismatch on case '{s}'\n", .{c.name});
            return e;
        };

        // Direction 2: their bytes, decoded by us, must be the same values.
        var decoded = pb.decode(T, gpa, theirs, .{}) catch |e| {
            std.debug.print("we could not decode the reference's bytes for '{s}'\n", .{c.name});
            return e;
        };
        defer decoded.deinit();
        expectMessageEqual(T, c.value, decoded.value) catch |e| {
            std.debug.print("value mismatch after decoding reference bytes for '{s}'\n", .{c.name});
            return e;
        };
    }
}

// ── the anchor tests ────────────────────────────────────────────────────────

test "reference: byte-exact both ways over every scalar kind" {
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();
    try runCases(&ref, ct.Wide, &wide_cases);
}

test "reference: byte-exact both ways over repeated and packed fields" {
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();
    try runCases(&ref, ct.Repeated, &repeated_cases);
}

test "reference: proto3 presence rules match the reference exactly" {
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();
    try runCases(&ref, ct.Presence, &presence_cases);
}

test "reference: a boxed recursive chain matches the reference" {
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();
    const gpa = testing.allocator;

    const c3 = ct.Chain{ .depth = 3 };
    const c2 = ct.Chain{ .depth = 2, .next = &c3 };
    const c1 = ct.Chain{ .depth = 1, .next = &c2 };

    const theirs = try ref.refEncode("chain3");
    defer gpa.free(theirs);
    const ours = try pb.encodeAlloc(gpa, c1, .{});
    defer gpa.free(ours);
    try testing.expectEqualSlices(u8, theirs, ours);

    var decoded = try pb.decode(ct.Chain, gpa, theirs, .{});
    defer decoded.deinit();
    try testing.expectEqual(@as(i32, 1), decoded.value.depth);
    try testing.expectEqual(@as(i32, 2), decoded.value.next.?.depth);
    try testing.expectEqual(@as(i32, 3), decoded.value.next.?.next.?.depth);
}

// ── shapes the reference would never emit, but must accept ──────────────────

/// `nums` is field 1, which proto3 packs by default; here it is forced
/// unpacked. `unpacked` is field 2, which the reference's schema marks
/// `[packed=false]`; here it is forced packed. Both are legal on the wire
/// and a conforming parser must accept them — a rule a self round trip can
/// never test, because our own decoder would just mirror our own encoder.
const Flipped = struct {
    nums: []const i32 = &.{},
    unpacked: []const i32 = &.{},

    pub const pb_fields = .{
        .nums = Field{ .number = 1, .kind = .int32, .packed_encoding = false },
        .unpacked = Field{ .number = 2, .kind = .int32 },
    };
};

test "reference: accepts our packing flipped in both directions" {
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();
    const gpa = testing.allocator;

    const ours = try pb.encodeAlloc(gpa, Flipped{
        .nums = &.{ 1, 2, 150 },
        .unpacked = &.{ 1, 2, 150 },
    }, .{});
    defer gpa.free(ours);

    // Deliberately NOT the reference's own byte string for these values.
    const canonical = try pb.encodeAlloc(gpa, ct.Repeated{
        .nums = &.{ 1, 2, 150 },
        .unpacked = &.{ 1, 2, 150 },
    }, .{});
    defer gpa.free(canonical);
    try testing.expect(!std.mem.eql(u8, ours, canonical));

    // …and yet the reference must read the same values out of both.
    const dump_flipped = try ref.refDump("packed", ours);
    defer gpa.free(dump_flipped);
    const dump_canonical = try ref.refDump("packed", canonical);
    defer gpa.free(dump_canonical);
    try testing.expectEqualStrings(dump_canonical, dump_flipped);
    try testing.expect(std.mem.indexOf(u8, dump_flipped, "nums=[1,2,150]") != null);
    try testing.expect(std.mem.indexOf(u8, dump_flipped, "unpacked=[1,2,150]") != null);
}

// ── unknown-field preservation, judged by the reference ─────────────────────

/// The same message as `ct.Wide` with almost every field removed — an old
/// build talking to a new peer. Everything it does not know must survive.
const WidePartial = struct {
    i32_: i32 = 0,
    s: []const u8 = "",
    unknown: pb.Unknown = .empty,

    pub const pb_fields = .{
        .i32_ = Field{ .number = 1, .kind = .int32 },
        .s = Field{ .number = 15, .kind = .string },
    };
};

test "reference: a message proxied through a partial schema is unchanged" {
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();
    const gpa = testing.allocator;

    // Every case that actually has fields outside WidePartial's schema.
    for ([_][]const u8{ "strings", "submessage", "fixed_all", "floats", "bool_enum", "zigzag_min" }) |case| {
        const theirs = try ref.refEncode(case);
        defer gpa.free(theirs);

        var partial = try pb.decode(WidePartial, gpa, theirs, .{});
        defer partial.deinit();
        // It really is carrying fields it does not understand.
        try testing.expect(!partial.value.unknown.isEmpty());

        const forwarded = try pb.encodeAlloc(gpa, partial.value, .{});
        defer gpa.free(forwarded);

        // The reference must read exactly what it originally wrote.
        const before = try ref.refDump("strings", theirs);
        defer gpa.free(before);
        const after = try ref.refDump("strings", forwarded);
        defer gpa.free(after);
        testing.expectEqualStrings(before, after) catch |e| {
            std.debug.print("unknown fields were not preserved for case '{s}'\n", .{case});
            return e;
        };
    }
}

test "reference: our own dump of each case matches the reference's" {
    // Their parser reading our bytes, compared against their own value dump.
    // Byte equality already implies this for the canonical cases, but this
    // check is what stays meaningful for any case where it does not.
    var ref = try Ref.init(testing.allocator, testing.io);
    defer ref.deinit();
    const gpa = testing.allocator;

    inline for (wide_cases) |c| {
        const ours = try pb.encodeAlloc(gpa, c.value, .{});
        defer gpa.free(ours);
        const got = try ref.refDump(c.name, ours);
        defer gpa.free(got);
        const want = try ref.refExpect(c.name);
        defer gpa.free(want);
        testing.expectEqualStrings(want, got) catch |e| {
            std.debug.print("reference read different values out of our bytes for '{s}'\n", .{c.name});
            return e;
        };
    }
}
