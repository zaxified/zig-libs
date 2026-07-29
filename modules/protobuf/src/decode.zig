// SPDX-License-Identifier: MIT

//! Decoder — protobuf wire bytes to a Zig value.
//!
//! Threat model: **every byte here came from someone else.** Two bounds are
//! load-bearing and both are enforced here rather than left to the caller:
//!
//!  1. **Declared lengths.** A length-delimited field states its size in the
//!     input. Nothing is allocated, sliced or looped over on the strength of
//!     that number until `wire.Cursor.take` has confirmed the buffer really
//!     holds it. A five-byte message claiming a 4 GiB submessage fails with
//!     `error.Truncated` having allocated zero bytes. Because `take` is the
//!     only route to a declared length, there is no unchecked path to reach
//!     for by accident. A corollary worth stating: every repeated field's
//!     element count is bounded by bytes already proven present, so no loop
//!     here is bounded by an attacker's number.
//!
//!  2. **Nesting depth.** Embedded messages recurse, and the input decides
//!     how deep. `Options.max_depth` (default 64) caps it; a chain of
//!     `0x0a 0x0a 0x0a …` — two bytes of stack per byte of input otherwise —
//!     stops with `error.DepthExceeded`.
//!
//! Everything the decoder produces is owned by one arena, so the caller
//! frees with a single `deinit()` and cannot leak a partially built message
//! on an error path.

const std = @import("std");
const wire = @import("wire.zig");
const schema = @import("schema.zig");

const Kind = schema.Kind;
const Unknown = schema.Unknown;
const Cursor = wire.Cursor;

pub const Options = struct {
    /// Maximum embedded-message nesting. The input controls the depth, so
    /// this is a hard cap, not a hint. protoc's own limit is 100.
    max_depth: u8 = 64,
    /// Copy `string`/`bytes` payloads into the arena so the decoded value
    /// outlives the input buffer. Set false for a zero-copy decode whose
    /// slices alias `input` — faster, but the caller must keep `input`
    /// alive and unmodified for as long as the value is used.
    copy_strings: bool = true,
    /// Fail on a field the schema does not describe, instead of preserving
    /// it (or dropping it, if the message declares no `Unknown` sink).
    /// For a strict receiver that must not forward what it cannot check.
    reject_unknown_fields: bool = false,
};

pub const Error = wire.Error || error{
    /// Nesting exceeded `Options.max_depth`.
    DepthExceeded,
    /// An enum value outside an exhaustive Zig enum. Declare proto enums
    /// non-exhaustive (`enum(i32) { …, _ }`) to accept a newer peer's value.
    InvalidEnumValue,
    /// `reject_unknown_fields` was set and the input carried one.
    UnknownField,
    OutOfMemory,
};

/// A decoded message plus the arena that owns every slice inside it.
pub fn Decoded(comptime T: type) type {
    return struct {
        value: T,
        arena: std.heap.ArenaAllocator,

        pub fn deinit(self: *@This()) void {
            self.arena.deinit();
            self.* = undefined;
        }
    };
}

/// Decode `input` as message `T`. On any error nothing is leaked: the arena
/// is torn down whole.
pub fn decode(
    comptime T: type,
    gpa: std.mem.Allocator,
    input: []const u8,
    options: Options,
) Error!Decoded(T) {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();

    var cur = Cursor.init(input);
    const value = try decodeMessage(T, arena.allocator(), &cur, options, 0);
    return .{ .value = value, .arena = arena };
}

// ── the per-message loop ────────────────────────────────────────────────────

/// The set of ArrayLists a message needs while decoding: one per repeated
/// field, plus one for captured unknown bytes. Generated so a repeated field
/// grows amortised instead of reallocating per element.
fn Lists(comptime T: type) type {
    comptime {
        const inf = schema.infos(T);
        const Attrs = std.builtin.Type.StructField.Attributes;
        var names: [inf.len + 1][]const u8 = undefined;
        var types: [inf.len + 1]type = undefined;
        var attrs: [inf.len + 1]Attrs = undefined;
        var n: usize = 0;
        for (inf) |i| {
            if (i.card != .repeated) continue;
            const L = std.ArrayList(i.Elem);
            names[n] = i.name;
            types[n] = L;
            attrs[n] = .{ .default_value_ptr = emptyListPtr(L) };
            n += 1;
        }
        if (unknownFieldName(T)) |name| {
            const L = std.ArrayList(u8);
            names[n] = name;
            types[n] = L;
            attrs[n] = .{ .default_value_ptr = emptyListPtr(L) };
            n += 1;
        }
        const fn_names = names[0..n].*;
        const fn_types = types[0..n].*;
        const fn_attrs = attrs[0..n].*;
        return @Struct(.auto, null, &fn_names, &fn_types, &fn_attrs);
    }
}

fn emptyListPtr(comptime L: type) *const anyopaque {
    const d: L = .empty;
    return @ptrCast(&d);
}

fn unknownFieldName(comptime T: type) ?[]const u8 {
    @setEvalBranchQuota(20_000);
    for (@typeInfo(T).@"struct".fields) |sf| {
        if (sf.type == Unknown) return sf.name;
    }
    return null;
}

fn decodeMessage(
    comptime T: type,
    arena: std.mem.Allocator,
    cur: *Cursor,
    options: Options,
    depth: u8,
) Error!T {
    if (depth >= options.max_depth) return error.DepthExceeded;

    var out: T = .{};
    var lists: Lists(T) = .{};

    while (!cur.atEnd()) {
        const tag_start = cur.pos;
        const tag = try cur.tag();

        var consumed = false;
        inline for (comptime schema.infos(T)) |info| {
            if (!consumed and tag.number == info.number and accepts(info, tag.wire)) {
                try readField(T, info, &out, &lists, arena, cur, tag.wire, options, depth);
                consumed = true;
            }
        }
        if (!consumed) {
            // Not in the schema, or the wire type disagrees with the schema
            // (protobuf's rule: such a field is unknown, not an error). Keep
            // the tag as well as the value so re-emission is byte-identical.
            if (options.reject_unknown_fields) return error.UnknownField;
            _ = try cur.skipValue(tag.wire);
            if (comptime unknownFieldName(T)) |name|
                try @field(lists, name).appendSlice(arena, cur.buf[tag_start..cur.pos]);
        }
    }

    inline for (comptime schema.infos(T)) |info| {
        if (info.card == .repeated)
            @field(out, info.name) = try @field(lists, info.name).toOwnedSlice(arena);
    }
    if (comptime unknownFieldName(T)) |name|
        @field(out, name) = .{ .raw = try @field(lists, name).toOwnedSlice(arena) };

    return out;
}

/// Does this wire type belong to this field? A repeated packable field
/// accepts both forms — a conforming decoder must, because a peer may have
/// been built from a `.proto` that said `[packed=false]`, or be an older
/// implementation that never packed at all.
fn accepts(comptime info: schema.Info, w: wire.WireType) bool {
    if (w == info.kind.wireType()) return true;
    return info.card == .repeated and info.kind.packable() and w == .len;
}

fn readField(
    comptime T: type,
    comptime info: schema.Info,
    out: *T,
    lists: *Lists(T),
    arena: std.mem.Allocator,
    cur: *Cursor,
    w: wire.WireType,
    options: Options,
    depth: u8,
) Error!void {
    const E = info.Elem;

    if (info.card == .repeated) {
        // Which form arrived is decided by the wire type, not by what this
        // side would have emitted — `accepts` let both through on purpose.
        if (comptime info.kind.packable()) {
            if (w == .len) {
                // Packed: one length, then values back to back. `take`
                // validates the length against the real buffer first, so the
                // loop below is bounded by bytes that provably exist.
                const n = try cur.varint();
                var sub = Cursor.init(try cur.take(n));
                while (!sub.atEnd())
                    try @field(lists, info.name).append(arena, try readValue(info.kind, E, arena, &sub, options, depth));
                return;
            }
        }
        // Unpacked element (also the only legal form for string/bytes/message).
        try @field(lists, info.name).append(arena, try readValue(info.kind, E, arena, cur, options, depth));
        return;
    }

    const v = try readValue(info.kind, E, arena, cur, options, depth);
    switch (info.card) {
        // Last occurrence wins, per the encoding spec's merge rule.
        .singular => @field(out, info.name) = v,
        .optional => if (info.boxed) {
            const boxed = try arena.create(E);
            boxed.* = v;
            @field(out, info.name) = boxed;
        } else {
            @field(out, info.name) = v;
        },
        .repeated => comptime unreachable,
    }
}

fn readValue(
    comptime kind: Kind,
    comptime E: type,
    arena: std.mem.Allocator,
    cur: *Cursor,
    options: Options,
    depth: u8,
) Error!E {
    return switch (kind) {
        .int32 => @bitCast(@as(u32, @truncate(try cur.varint()))),
        .int64 => @bitCast(try cur.varint()),
        .uint32 => @truncate(try cur.varint()),
        .uint64 => try cur.varint(),
        .sint32 => @truncate(wire.zigzagDecode(try cur.varint())),
        .sint64 => wire.zigzagDecode(try cur.varint()),
        .bool => (try cur.varint()) != 0,
        .@"enum" => blk: {
            const raw: i32 = @bitCast(@as(u32, @truncate(try cur.varint())));
            if (@typeInfo(E).@"enum".is_exhaustive) {
                break :blk std.enums.fromInt(E, raw) orelse return error.InvalidEnumValue;
            }
            break :blk @enumFromInt(raw);
        },
        .fixed32 => try cur.fixed32(),
        .sfixed32 => @bitCast(try cur.fixed32()),
        .float => @bitCast(try cur.fixed32()),
        .fixed64 => try cur.fixed64(),
        .sfixed64 => @bitCast(try cur.fixed64()),
        .double => @bitCast(try cur.fixed64()),
        .string, .bytes => blk: {
            const n = try cur.varint();
            const raw = try cur.take(n); // bounds check before anything else
            break :blk if (options.copy_strings) try arena.dupe(u8, raw) else raw;
        },
        .message => blk: {
            const n = try cur.varint();
            var sub = Cursor.init(try cur.take(n)); // ditto
            break :blk try decodeMessage(E, arena, &sub, options, depth + 1);
        },
    };
}
