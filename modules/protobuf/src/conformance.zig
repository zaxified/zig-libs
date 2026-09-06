// SPDX-License-Identifier: MIT

//! The conformance corpus: the message fixtures and the case tables that both
//! the module's own hermetic tests and the out-of-tree interop program
//! (`tools/interop.zig`) work from.
//!
//! It exists as its own file, reachable from `root.zig`, for one structural
//! reason. Until 2026-09-06 the case tables lived in `src/reference_interop.zig`
//! — inside the module, spawning `python3` from inside `test-protobuf`. That
//! file is now a standalone program under `tools/`, and a program cannot
//! `@import` a path outside its own module root. The tables have to live
//! somewhere BOTH can reach, and the only such place is the module itself.
//! Keeping one table is the point: the live run and the frozen replay must
//! judge the same cases, or the replay quietly stops covering what the live
//! run covers.
//!
//! Nothing here is part of the codec API. `root.zig` exposes it as
//! `protobuf.conformance` purely so the interop program can import it.

const std = @import("std");
const testing = std.testing;
const pb = @import("root.zig");

const Field = pb.Field;

// ── message fixtures ────────────────────────────────────────────────────────

pub const Color = enum(i32) {
    unspecified = 0,
    red = 1,
    green = 2,
    _, // open, as proto3 enums are
};

pub const Inner = struct {
    v: i32 = 0,
    note: []const u8 = "",
    pub const pb_fields = .{
        .v = Field{ .number = 1, .kind = .int32 },
        .note = Field{ .number = 2, .kind = .string },
    };
};

pub const Wide = struct {
    i32_: i32 = 0,
    i64_: i64 = 0,
    u32_: u32 = 0,
    u64_: u64 = 0,
    s32: i32 = 0,
    s64: i64 = 0,
    b: bool = false,
    color: Color = .unspecified,
    f64_: u64 = 0,
    sf64: i64 = 0,
    d: f64 = 0,
    f32_: u32 = 0,
    sf32: i32 = 0,
    f: f32 = 0,
    s: []const u8 = "",
    raw: []const u8 = "",
    inner: ?Inner = null,

    pub const pb_fields = .{
        .i32_ = Field{ .number = 1, .kind = .int32 },
        .i64_ = Field{ .number = 2, .kind = .int64 },
        .u32_ = Field{ .number = 3, .kind = .uint32 },
        .u64_ = Field{ .number = 4, .kind = .uint64 },
        .s32 = Field{ .number = 5, .kind = .sint32 },
        .s64 = Field{ .number = 6, .kind = .sint64 },
        .b = Field{ .number = 7, .kind = .bool },
        .color = Field{ .number = 8, .kind = .@"enum" },
        .f64_ = Field{ .number = 9, .kind = .fixed64 },
        .sf64 = Field{ .number = 10, .kind = .sfixed64 },
        .d = Field{ .number = 11, .kind = .double },
        .f32_ = Field{ .number = 12, .kind = .fixed32 },
        .sf32 = Field{ .number = 13, .kind = .sfixed32 },
        .f = Field{ .number = 14, .kind = .float },
        .s = Field{ .number = 15, .kind = .string },
        .raw = Field{ .number = 16, .kind = .bytes },
        .inner = Field{ .number = 17, .kind = .message },
    };
};

pub const Repeated = struct {
    nums: []const i32 = &.{},
    unpacked: []const i32 = &.{},
    zz: []const i64 = &.{},
    fixed: []const u32 = &.{},
    flags: []const bool = &.{},
    colors: []const Color = &.{},
    names: []const []const u8 = &.{},
    inners: []const Inner = &.{},

    pub const pb_fields = .{
        .nums = Field{ .number = 1, .kind = .int32 },
        .unpacked = Field{ .number = 2, .kind = .int32, .packed_encoding = false },
        .zz = Field{ .number = 3, .kind = .sint64 },
        .fixed = Field{ .number = 4, .kind = .fixed32 },
        .flags = Field{ .number = 5, .kind = .bool },
        .colors = Field{ .number = 6, .kind = .@"enum" },
        .names = Field{ .number = 7, .kind = .string },
        .inners = Field{ .number = 8, .kind = .message },
    };
};

pub const Presence = struct {
    implicit: i32 = 0,
    explicit: ?i32 = null,
    implicit_str: []const u8 = "",
    explicit_str: ?[]const u8 = null,

    pub const pb_fields = .{
        .implicit = Field{ .number = 1, .kind = .int32 },
        .explicit = Field{ .number = 2, .kind = .int32 },
        .implicit_str = Field{ .number = 3, .kind = .string },
        .explicit_str = Field{ .number = 4, .kind = .string },
    };
};

/// A message that keeps what it does not understand.
pub const Keeps = struct {
    known: i32 = 0,
    unknown: pb.Unknown = .empty,
    pub const pb_fields = .{
        .known = Field{ .number = 1, .kind = .int32 },
    };
};

/// The same field numbers, minus the fields a newer peer knows about.
pub const Drops = struct {
    known: i32 = 0,
    pub const pb_fields = .{
        .known = Field{ .number = 1, .kind = .int32 },
    };
};

/// Self-recursive via a boxed optional — the shape a linked structure needs.
pub const Chain = struct {
    depth: i32 = 0,
    next: ?*const Chain = null,
    pub const pb_fields = .{
        .depth = Field{ .number = 1, .kind = .int32 },
        .next = Field{ .number = 2, .kind = .message },
    };
};

/// `nums` is field 1, which proto3 packs by default; here it is forced
/// unpacked. `unpacked` is field 2, which the reference's schema marks
/// unpackable; here it is forced packed. Both are legal on the wire and a
/// conforming parser must accept them — a rule a self round trip can never
/// test, because our own decoder would just mirror our own encoder.
pub const Flipped = struct {
    nums: []const i32 = &.{},
    unpacked: []const i32 = &.{},

    pub const pb_fields = .{
        .nums = Field{ .number = 1, .kind = .int32, .packed_encoding = false },
        .unpacked = Field{ .number = 2, .kind = .int32 },
    };
};

/// The same message as `Wide` with almost every field removed — an old build
/// talking to a new peer. Everything it does not know must survive.
pub const WidePartial = struct {
    i32_: i32 = 0,
    s: []const u8 = "",
    unknown: pb.Unknown = .empty,

    pub const pb_fields = .{
        .i32_ = Field{ .number = 1, .kind = .int32 },
        .s = Field{ .number = 15, .kind = .string },
    };
};

// ── the shared case table ───────────────────────────────────────────────────

pub fn Case(comptime T: type) type {
    return struct { name: []const u8, value: T };
}

const MIN32 = std.math.minInt(i32);
const MAX32 = std.math.maxInt(i32);
const MIN64 = std.math.minInt(i64);
const MAX64 = std.math.maxInt(i64);

pub const wide_cases = [_]Case(Wide){
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

pub const repeated_cases = [_]Case(Repeated){
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

pub const presence_cases = [_]Case(Presence){
    .{ .name = "pres_default", .value = .{ .implicit = 0 } },
    .{ .name = "pres_set", .value = .{ .implicit = 1 } },
    .{ .name = "pres_expl_0", .value = .{ .explicit = 0 } },
    .{ .name = "pres_expl_5", .value = .{ .explicit = 5 } },
    .{ .name = "pres_str_0", .value = .{ .explicit_str = "" } },
};

/// The one case the three tables above cannot hold, because its value is a
/// linked structure: `Chain{1 -> 2 -> 3}`, named `chain3` on both sides.
pub const chain3: Chain = .{ .depth = 1, .next = &.{ .depth = 2, .next = &.{ .depth = 3 } } };

/// The six `Wide` cases that carry fields outside `WidePartial`'s schema —
/// i.e. the ones for which forwarding through the partial schema actually has
/// unknown fields to preserve.
pub const forwarded_cases = [_][]const u8{
    "strings", "submessage", "fixed_all", "floats", "bool_enum", "zigzag_min",
};

// ── inputs the reference itself would never emit ────────────────────────────

pub const Msg = enum { wide, repeated, presence, chain };

/// What the reference implementation is expected to do with the input. The
/// FIXTURE records what it actually did (`testdata/interop_vectors.zig`); this
/// field is the hand-written claim the capture cross-checks against, so a
/// reference that changes its mind fails the capture instead of being
/// silently written into the record.
pub const Expect = enum { accept, reject_invalid_utf8 };

/// A byte string a conforming parser has to judge, together with the message
/// type it is judged as. None of these are shapes a canonical encoder emits,
/// so a round trip through our own codec cannot settle any of them — only an
/// outside parser can, and `testdata/interop_vectors.zig` is that parser's
/// recorded verdict.
pub const Semantic = struct {
    name: []const u8,
    msg: Msg,
    input: []const u8,
    expect: Expect,
};

pub const semantic_cases = [_]Semantic{
    // Packing flipped in both directions. `interop_replay_test.zig` also
    // asserts that our encoder still produces exactly these bytes for
    // `Flipped{ .nums = .{1,2,150}, .unpacked = .{1,2,150} }`, so the
    // reference's verdict cannot drift away from what we emit today.
    .{
        .name = "flipped_packing",
        .msg = .repeated,
        .input = &.{ 0x08, 0x01, 0x08, 0x02, 0x08, 0x96, 0x01, 0x12, 0x04, 0x01, 0x02, 0x96, 0x01 },
        .expect = .accept,
    },

    // The encoding spec's `MergeFrom` rule for embedded messages: two
    // occurrences of a singular submessage field merge rather than replace.
    // Replacing lets a sender hide a field — append a second, near-empty copy
    // and everything the first copy set reverts to its default.
    // `Wide.inner` is field 17 (tag 8a 01): inner{v:1} then inner{note:"x"}.
    .{
        .name = "merge_two_copies",
        .msg = .wide,
        .input = &.{ 0x8a, 0x01, 0x02, 0x08, 0x01, 0x8a, 0x01, 0x03, 0x12, 0x01, 0x78 },
        .expect = .accept,
    },
    // A *repeated* message field is not merged: one element per occurrence.
    // `Repeated.inners` is field 8 (tag 0x42).
    .{
        .name = "merge_rep_two",
        .msg = .repeated,
        .input = &.{ 0x42, 0x02, 0x08, 0x01, 0x42, 0x03, 0x12, 0x01, 0x78 },
        .expect = .accept,
    },

    // `Wide.s` is field 15 (tag 0x7a), kind `string`, which proto3 defines as
    // UTF-8. The reference's ParseFromString raises UnicodeDecodeError on each
    // of these, so its recorded verdict is a rejection, not a normalization.
    .{ .name = "utf8_bad_lone_ff", .msg = .wide, .input = &.{ 0x7a, 0x01, 0xff }, .expect = .reject_invalid_utf8 },
    .{ .name = "utf8_bad_overlong", .msg = .wide, .input = &.{ 0x7a, 0x02, 0xc0, 0x80 }, .expect = .reject_invalid_utf8 },
    .{ .name = "utf8_bad_surrogate", .msg = .wide, .input = &.{ 0x7a, 0x03, 0xed, 0xa0, 0x80 }, .expect = .reject_invalid_utf8 },
    .{ .name = "utf8_bad_truncated", .msg = .wide, .input = &.{ 0x7a, 0x01, 0xc3 }, .expect = .reject_invalid_utf8 },
    // `Wide.raw` is field 16 (tag 82 01), kind `bytes`: the same octet is fine
    // for both sides, so the four rejections above are a check on `string`,
    // not a blanket byte filter.
    .{ .name = "utf8_raw_ff_ok", .msg = .wide, .input = &.{ 0x82, 0x01, 0x01, 0xff }, .expect = .accept },
};

/// The Zig type a `Msg` names.
pub fn Type(comptime m: Msg) type {
    return switch (m) {
        .wide => Wide,
        .repeated => Repeated,
        .presence => Presence,
        .chain => Chain,
    };
}

/// The reference driver's name for a `Msg` — `reference.py`'s `SCHEMAS` key.
pub fn schemaName(m: Msg) []const u8 {
    return switch (m) {
        .wide => "Wide",
        .repeated => "Repeated",
        .presence => "Presence",
        .chain => "Chain",
    };
}

// ── the frozen record ───────────────────────────────────────────────────────

/// What the reference's ENCODER produced for every canonical case.
pub const golden = @import("testdata/golden_bytes.zig");

/// What the reference's PARSER did with every `semantic_cases` input.
/// Re-exported here (rather than imported straight from `testdata/`) because
/// `tools/interop.zig` cannot reach into `src/` — it needs the committed
/// record to tell a stale fixture from a real divergence.
pub const vectors = @import("testdata/interop_vectors.zig");

// ── generic structural comparison ───────────────────────────────────────────

pub fn expectMessageEqual(comptime T: type, want: T, got: T) !void {
    inline for (comptime pb.infos(T)) |info| {
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
