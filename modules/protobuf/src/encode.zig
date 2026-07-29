// SPDX-License-Identifier: MIT

//! Encoder — a Zig value to protobuf wire bytes.
//!
//! Two passes, exactly as the upstream C++ implementation does it
//! (`ByteSizeLong` then `SerializeWithCachedSizes`): a submessage is
//! length-prefixed, so its size has to be known before its first byte is
//! written. The alternative — serialising each submessage into a scratch
//! buffer and prepending the length — costs an allocation per nesting level
//! and gives the module an allocating-only encode path; this way
//! `encodeInto` writes into a caller's buffer with no allocator at all,
//! which is what a gRPC framer wants.
//!
//! The risk of two passes is that they disagree. That is made loud rather
//! than silent: `encodeInto` sizes the buffer from pass one and asserts pass
//! two filled it **exactly**, so any divergence trips an assertion in the
//! very first test that runs, instead of emitting a truncated message.
//!
//! Cost note: nested sizes are recomputed per level rather than cached, so
//! sizing is O(depth x fields). The upstream fix is a per-message size cache;
//! it is not implemented here (see SPEC.md, "Not implemented").

const std = @import("std");
const wire = @import("wire.zig");
const schema = @import("schema.zig");

const Kind = schema.Kind;
const Unknown = schema.Unknown;

pub const Options = struct {
    /// Maximum message nesting the encoder will follow. A boxed
    /// self-recursive message can be arbitrarily deep at runtime, so the
    /// encoder is bounded for the same reason the decoder is.
    max_depth: u8 = 64,
};

pub const Error = error{DepthExceeded};

/// Byte length of `value` on the wire. Also the framing length a gRPC
/// message header needs, which is why it is public.
pub fn encodedSize(value: anytype, options: Options) Error!usize {
    return messageSize(@TypeOf(value), value, options, 0);
}

/// Encode into `buf`, which must be at least `encodedSize(value)` bytes.
/// Returns the number of bytes written. No allocation.
pub fn encodeInto(buf: []u8, value: anytype, options: Options) (Error || error{NoSpaceLeft})!usize {
    const size = try encodedSize(value, options);
    if (buf.len < size) return error.NoSpaceLeft;
    var e = wire.Emitter.init(buf[0..size]);
    try emitMessage(@TypeOf(value), value, &e, options, 0);
    // Pass one and pass two must agree to the byte.
    std.debug.assert(e.pos == size);
    return size;
}

/// Encode into a freshly allocated, exactly-sized buffer owned by the caller.
pub fn encodeAlloc(
    gpa: std.mem.Allocator,
    value: anytype,
    options: Options,
) (Error || std.mem.Allocator.Error)![]u8 {
    const size = try encodedSize(value, options);
    const buf = try gpa.alloc(u8, size);
    errdefer gpa.free(buf);
    var e = wire.Emitter.init(buf);
    try emitMessage(@TypeOf(value), value, &e, options, 0);
    std.debug.assert(e.pos == size);
    return buf;
}

// ── sizing pass ─────────────────────────────────────────────────────────────

fn messageSize(comptime T: type, value: T, options: Options, depth: u8) Error!usize {
    if (depth >= options.max_depth) return error.DepthExceeded;
    var total: usize = 0;

    inline for (comptime schema.infos(T)) |info| {
        const f = @field(value, info.name);
        switch (info.card) {
            .singular => {
                if (!isDefault(info.kind, info.Elem, f))
                    total += wire.tagLen(info.number, info.kind.wireType()) +
                        try valueSize(info.kind, info.Elem, f, options, depth);
            },
            .optional => {
                if (f) |present| {
                    total += wire.tagLen(info.number, info.kind.wireType());
                    total += if (info.boxed)
                        try valueSize(info.kind, info.Elem, present.*, options, depth)
                    else
                        try valueSize(info.kind, info.Elem, present, options, depth);
                }
            },
            .repeated => {
                // An empty repeated field is not transmitted — not even as a
                // zero-length packed payload.
                if (f.len != 0) {
                    if (info.is_packed) {
                        var payload: usize = 0;
                        for (f) |elem| payload += try valueSize(info.kind, info.Elem, elem, options, depth);
                        total += wire.tagLen(info.number, .len) + wire.varintLen(payload) + payload;
                    } else {
                        for (f) |elem| {
                            total += wire.tagLen(info.number, info.kind.wireType()) +
                                try valueSize(info.kind, info.Elem, elem, options, depth);
                        }
                    }
                }
            },
        }
    }

    total += unknownOf(T, value).raw.len;
    return total;
}

fn valueSize(
    comptime kind: Kind,
    comptime E: type,
    elem: E,
    options: Options,
    depth: u8,
) Error!usize {
    return switch (kind) {
        .int32, .int64, .uint32, .uint64, .sint32, .sint64, .bool, .@"enum" => wire.varintLen(varintOf(kind, E, elem)),
        .fixed64, .sfixed64, .double => 8,
        .fixed32, .sfixed32, .float => 4,
        .string, .bytes => wire.varintLen(elem.len) + elem.len,
        .message => blk: {
            const inner = try messageSize(E, elem, options, depth + 1);
            break :blk wire.varintLen(inner) + inner;
        },
    };
}

// ── emit pass ───────────────────────────────────────────────────────────────

fn emitMessage(comptime T: type, value: T, e: *wire.Emitter, options: Options, depth: u8) Error!void {
    if (depth >= options.max_depth) return error.DepthExceeded;

    inline for (comptime schema.infos(T)) |info| {
        const f = @field(value, info.name);
        switch (info.card) {
            .singular => {
                if (!isDefault(info.kind, info.Elem, f)) {
                    e.tag(info.number, info.kind.wireType());
                    try emitValue(info.kind, info.Elem, f, e, options, depth);
                }
            },
            .optional => {
                if (f) |present| {
                    e.tag(info.number, info.kind.wireType());
                    if (info.boxed)
                        try emitValue(info.kind, info.Elem, present.*, e, options, depth)
                    else
                        try emitValue(info.kind, info.Elem, present, e, options, depth);
                }
            },
            .repeated => {
                if (f.len != 0) {
                    if (info.is_packed) {
                        var payload: usize = 0;
                        for (f) |elem| payload += try valueSize(info.kind, info.Elem, elem, options, depth);
                        e.tag(info.number, .len);
                        e.varint(payload);
                        for (f) |elem| try emitValue(info.kind, info.Elem, elem, e, options, depth);
                    } else {
                        for (f) |elem| {
                            e.tag(info.number, info.kind.wireType());
                            try emitValue(info.kind, info.Elem, elem, e, options, depth);
                        }
                    }
                }
            },
        }
    }

    // Unknown fields ride at the end, byte-for-byte as they arrived. Field
    // order carries no meaning in protobuf, so appending is lossless.
    e.bytes(unknownOf(T, value).raw);
}

fn emitValue(
    comptime kind: Kind,
    comptime E: type,
    elem: E,
    e: *wire.Emitter,
    options: Options,
    depth: u8,
) Error!void {
    switch (kind) {
        .int32, .int64, .uint32, .uint64, .sint32, .sint64, .bool, .@"enum" => e.varint(varintOf(kind, E, elem)),
        .fixed64 => e.fixed64(elem),
        .sfixed64 => e.fixed64(@bitCast(elem)),
        .double => e.fixed64(@bitCast(elem)),
        .fixed32 => e.fixed32(elem),
        .sfixed32 => e.fixed32(@bitCast(elem)),
        .float => e.fixed32(@bitCast(elem)),
        .string, .bytes => {
            e.varint(elem.len);
            e.bytes(elem);
        },
        .message => {
            const inner = try messageSize(E, elem, options, depth + 1);
            e.varint(inner);
            try emitMessage(E, elem, e, options, depth + 1);
        },
    }
}

// ── scalar helpers ──────────────────────────────────────────────────────────

/// The varint payload for a varint-typed value.
///
/// `int32`/`int64`/`enum` sign-extend to 64 bits — a negative is always ten
/// bytes. `sint32`/`sint64` zigzag instead. Getting either wrong is
/// invisible to a self round trip and obvious to any other implementation.
fn varintOf(comptime kind: Kind, comptime E: type, elem: E) u64 {
    return switch (kind) {
        .int32 => wire.signExtend(@as(i64, elem)),
        .int64 => wire.signExtend(elem),
        .uint32 => @as(u64, elem),
        .uint64 => elem,
        .sint32 => wire.zigzagEncode(@as(i64, elem)),
        .sint64 => wire.zigzagEncode(elem),
        .bool => @intFromBool(elem),
        .@"enum" => wire.signExtend(@as(i64, @intFromEnum(elem))),
        else => comptime unreachable,
    };
}

/// proto3 implicit presence: a singular scalar equal to its type default is
/// not transmitted at all. (An `optional` field has explicit presence and is
/// transmitted whenever it is non-null, default value or not.)
fn isDefault(comptime kind: Kind, comptime E: type, elem: E) bool {
    return switch (kind) {
        .string, .bytes => elem.len == 0,
        .bool => !elem,
        .@"enum" => @intFromEnum(elem) == 0,
        .message => comptime unreachable, // singular message is always optional
        else => elem == 0,
    };
}

fn unknownOf(comptime T: type, value: T) Unknown {
    inline for (@typeInfo(T).@"struct".fields) |sf| {
        if (sf.type == Unknown) return @field(value, sf.name);
    }
    return .empty;
}
