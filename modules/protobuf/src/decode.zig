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
    /// alive and unmodified for as long as the value is used. (The one
    /// exception is a submessage that arrived in more than one piece: its
    /// payloads are concatenated into the arena to be merged, so strings
    /// inside it alias the arena rather than `input` — strictly the safer
    /// of the two, and the arena is what `Decoded.deinit` frees anyway.)
    copy_strings: bool = true,
    /// Fail on a field the schema does not describe, instead of preserving
    /// it (or dropping it, if the message declares no `Unknown` sink).
    /// For a strict receiver that must not forward what it cannot check.
    reject_unknown_fields: bool = false,
};

pub const Error = wire.Error || error{
    /// Nesting exceeded `Options.max_depth`.
    DepthExceeded,
    /// A `string` field carried bytes that are not valid UTF-8. `bytes` is
    /// the field kind for arbitrary octets; `string` promises text, and the
    /// reference implementation refuses the stream rather than hand a
    /// consumer a value its type lies about.
    InvalidUtf8,
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

/// Accumulator for the payloads of a **singular/optional message** field.
///
/// The encoding spec's merge rule applies to embedded messages: when the
/// same singular message field appears more than once, the later copies are
/// *merged* into the earlier one (`MergeFrom`), not substituted for it, so a
/// field set only in the first copy survives. Replacing instead of merging
/// is a field-hiding primitive — a sender appends a second, near-empty copy
/// and every field the first copy set reverts to its default in front of
/// whatever authorisation decision reads the value.
///
/// The spec also states the equivalence exploited here: parsing the
/// concatenation of two encodings of a message is the same as parsing each
/// and merging. Concatenating the *payload bytes* and decoding once is why
/// this is linear: decode-then-merge would have to re-copy every element of
/// every already-decoded repeated field on each further occurrence, and the
/// number of occurrences is the sender's to choose — quadratic in the input.
/// The single-occurrence case, which is essentially all real traffic, copies
/// nothing at all: the payload stays a borrowed slice.
const MergeBuf = struct {
    /// The sole payload, borrowed from the input, while `count == 1`.
    one: []const u8 = &.{},
    /// `one` followed by every later payload, once `count > 1`.
    joined: std.ArrayList(u8) = .empty,
    count: usize = 0,

    fn add(self: *MergeBuf, arena: std.mem.Allocator, payload: []const u8) !void {
        switch (self.count) {
            0 => self.one = payload,
            1 => {
                try self.joined.ensureTotalCapacity(arena, self.one.len + payload.len);
                self.joined.appendSliceAssumeCapacity(self.one);
                self.joined.appendSliceAssumeCapacity(payload);
            },
            else => try self.joined.appendSlice(arena, payload),
        }
        self.count += 1;
    }

    /// The bytes to decode, or null if the field never appeared. An absent
    /// field and a present-but-empty one stay distinguishable: a zero-length
    /// submessage still yields an empty slice, not null.
    fn bytes(self: MergeBuf) ?[]const u8 {
        return switch (self.count) {
            0 => null,
            1 => self.one,
            else => self.joined.items,
        };
    }
};

/// The per-message scratch state: one ArrayList per repeated field, one
/// `MergeBuf` per singular/optional message field, plus one list for
/// captured unknown bytes. Generated so a repeated field grows amortised
/// instead of reallocating per element.
fn Lists(comptime T: type) type {
    comptime {
        const inf = schema.infos(T);
        const Attrs = std.builtin.Type.StructField.Attributes;
        var names: [inf.len + 1][]const u8 = undefined;
        var types: [inf.len + 1]type = undefined;
        var attrs: [inf.len + 1]Attrs = undefined;
        var n: usize = 0;
        for (inf) |i| {
            if (i.card != .repeated) {
                if (i.kind == .message) {
                    names[n] = i.name;
                    types[n] = MergeBuf;
                    attrs[n] = .{ .default_value_ptr = emptyMergeBufPtr() };
                    n += 1;
                }
                continue;
            }
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

fn emptyMergeBufPtr() *const anyopaque {
    const d: MergeBuf = .{};
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
        if (info.card == .repeated) {
            @field(out, info.name) = try @field(lists, info.name).toOwnedSlice(arena);
        } else if (info.kind == .message) {
            // Every occurrence of this field, concatenated, decoded once —
            // which is exactly `MergeFrom` over the occurrences. See MergeBuf.
            if (@field(lists, info.name).bytes()) |payload| {
                var sub = Cursor.init(payload);
                const v = try decodeMessage(info.Elem, arena, &sub, options, depth + 1);
                if (comptime info.boxed) {
                    const boxed = try arena.create(info.Elem);
                    boxed.* = v;
                    @field(out, info.name) = boxed;
                } else {
                    @field(out, info.name) = v;
                }
            }
        }
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

    if (comptime info.kind == .message) {
        // A singular/optional submessage is *not* decoded here: the merge
        // rule needs every occurrence in hand before any of them can be
        // read, so the payload is only bounds-checked and set aside. The
        // decode happens once, over the concatenation, in `decodeMessage`.
        const n = try cur.varint();
        try @field(lists, info.name).add(arena, try cur.take(n));
        return;
    }

    const v = try readValue(info.kind, E, arena, cur, options, depth);
    switch (info.card) {
        // Scalars, strings and bytes are last-occurrence-wins; only embedded
        // messages merge (handled above).
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
        .bytes => blk: {
            const n = try cur.varint();
            const raw = try cur.take(n); // bounds check before anything else
            break :blk if (options.copy_strings) try arena.dupe(u8, raw) else raw;
        },
        .string => blk: {
            const n = try cur.varint();
            const raw = try cur.take(n); // bounds check before anything else
            // proto3 requires a `string` field to hold valid UTF-8 and the
            // reference implementation enforces it *at parse time* — the
            // Python runtime raises `UnicodeDecodeError` out of
            // `ParseFromString`, so the whole message is refused. Accepting
            // it here would make this decoder the hole in a mixed fleet
            // (a filter built on it passes a message every reference peer
            // rejects) and would hand a consumer a `[]const u8` whose type
            // promises text. `.bytes` is deliberately untouched: that is the
            // kind for arbitrary octets, and the reference accepts 0xff there.
            if (!std.unicode.utf8ValidateSlice(raw)) return error.InvalidUtf8;
            break :blk if (options.copy_strings) try arena.dupe(u8, raw) else raw;
        },
        .message => blk: {
            const n = try cur.varint();
            var sub = Cursor.init(try cur.take(n)); // ditto
            break :blk try decodeMessage(E, arena, &sub, options, depth + 1);
        },
    };
}
