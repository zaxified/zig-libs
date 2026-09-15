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
//! Cost note (F6, A1/protobuf.md): a submessage `depth` levels deep used to
//! cost O(depth^2) to ENCODE, not because sizing itself is expensive (a
//! single top-down `messageSize` call is O(depth), like any tree walk) but
//! because the EMIT pass asked `messageSize` to recompute each nested
//! submessage's size again, right before emitting it — and that recompute
//! itself recurses all the way to the bottom of what remains. A chain `d`
//! deep costs `d + (d-1) + ... + 1` calls that way.
//!
//! `encodeAlloc` (the path with a `gpa` to spend — and the confirmed hot
//! path, `grpc.Stream.sendInner`) now avoids the recompute: its sizing pass
//! builds a `SizeTree` — the size of every submessage it visits, in a real
//! tree shape mirroring `T` itself, not a flat list (a flat list does not
//! work here: the SIZING pass finishes each node's children before
//! recording the node itself, depth-first, but the EMIT pass needs a node's
//! own size BEFORE it needs any of that node's children — reversing a
//! child-before-parent order only reproduces a parent-before-children order
//! for a pure chain, not once there is more than one message-typed field at
//! any level; a real tree, one node holding exactly its own children in
//! field order, sidesteps the question entirely, since each node's children
//! are consulted independently of its siblings'). Its `gpa`, wrapped in a
//! throwaway arena, pays for that tree; the tree is freed before
//! `encodeAlloc` returns and never appears in the returned buffer or the
//! public API.
//!
//! `encodeInto`'s allocation-free contract is UNCHANGED and still pays the
//! O(depth^2) cost it always has: it has no allocator to build a `SizeTree`
//! with, and that absence is the entire reason this module exists in this
//! shape (a gRPC framer wants zero allocations per frame). The two code
//! paths share `messageSize`/`valueSize`/`emitMessage`/`emitValue`,
//! specialised via a `comptime` flag rather than forked into two copies —
//! so the allocation-free instantiation's compiled code is bit-for-bit what
//! it always was (the caching branch is pruned at compile time, not skipped
//! at runtime), and there is exactly one implementation of the sizing/emit
//! logic to keep in sync, not two that could drift apart.

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
    return messageSize(@TypeOf(value), value, options, 0, false, {});
}

/// Encode into `buf`, which must be at least `encodedSize(value)` bytes.
/// Returns the number of bytes written. No allocation.
pub fn encodeInto(buf: []u8, value: anytype, options: Options) (Error || error{NoSpaceLeft})!usize {
    const size = try encodedSize(value, options);
    if (buf.len < size) return error.NoSpaceLeft;
    var e = wire.Emitter.init(buf[0..size]);
    try emitMessage(@TypeOf(value), value, &e, options, 0, null);
    // Pass one and pass two must agree to the byte, in every build mode (F8).
    if (e.pos != size) @panic(wire.size_mismatch_message);
    return size;
}

/// Encode into a freshly allocated, exactly-sized buffer owned by the caller.
///
/// Sizes every submessage exactly ONCE (F6, A1/protobuf.md) using a `SizeTree`
/// built in a throwaway arena over `gpa` — see the module doc comment. The
/// arena, and everything in it, is gone before this function returns; only
/// the exactly-sized `buf` it allocated directly from `gpa` survives.
pub fn encodeAlloc(
    gpa: std.mem.Allocator,
    value: anytype,
    options: Options,
) (Error || std.mem.Allocator.Error)![]u8 {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var root_children: std.ArrayList(SizeTree) = .empty;
    const size = try messageSize(@TypeOf(value), value, options, 0, true, .{ .arena = arena, .out = &root_children });

    const buf = try gpa.alloc(u8, size);
    errdefer gpa.free(buf);
    var e = wire.Emitter.init(buf);
    var consume: Consume = .{ .nodes = try root_children.toOwnedSlice(arena) };
    try emitMessage(@TypeOf(value), value, &e, options, 0, &consume);
    if (e.pos != size) @panic(wire.size_mismatch_message);
    return buf;
}

// ── size cache (F6) ─────────────────────────────────────────────────────────

/// One entry per `.message`-typed field VALUE encountered while sizing a
/// message (one per element for a repeated, non-packed message field),
/// holding that submessage's own total plus a `SizeTree` for each message
/// field IT contains, in the same order. Built once by `messageSize`
/// (`caching = true`) and walked in lockstep by `emitMessage` so a nested
/// submessage's size is looked up instead of recomputed.
const SizeTree = struct {
    total: usize,
    children: []const SizeTree,
};

/// Where `valueSize`'s `.message` case appends the `SizeTree` it just built
/// for a submessage — `out` belongs to that submessage's PARENT (it is the
/// parent's list of its own message-typed fields' sizes), which is why
/// `valueSize` always constructs a fresh, empty list to pass down as the
/// child's own `CacheBuild.out` before recursing.
const CacheBuild = struct {
    arena: std.mem.Allocator,
    out: *std.ArrayList(SizeTree),
};

/// Read side of `SizeTree`: `nodes` is one message's own list of child
/// sizes (schema field order, array order within a repeated field), read
/// once each via `next()` in the exact order `emitMessage`'s field loop
/// visits them — the same order `messageSize` appended them in, because
/// both walk `schema.infos(T)` identically.
const Consume = struct {
    nodes: []const SizeTree,
    idx: usize = 0,

    fn next(self: *Consume) SizeTree {
        defer self.idx += 1;
        return self.nodes[self.idx];
    }
};

// ── sizing pass ─────────────────────────────────────────────────────────────

fn messageSize(
    comptime T: type,
    value: T,
    options: Options,
    depth: u8,
    comptime caching: bool,
    cache: if (caching) CacheBuild else void,
) (if (caching) (Error || std.mem.Allocator.Error) else Error)!usize {
    if (depth >= options.max_depth) return error.DepthExceeded;
    var total: usize = 0;

    inline for (comptime schema.infos(T)) |info| {
        const f = @field(value, info.name);
        switch (info.card) {
            .singular => {
                if (!isDefault(info.kind, info.Elem, f))
                    total += wire.tagLen(info.number, info.kind.wireType()) +
                        try valueSize(info.kind, info.Elem, f, options, depth, caching, cache);
            },
            .optional => {
                if (f) |present| {
                    total += wire.tagLen(info.number, info.kind.wireType());
                    total += if (info.boxed)
                        try valueSize(info.kind, info.Elem, present.*, options, depth, caching, cache)
                    else
                        try valueSize(info.kind, info.Elem, present, options, depth, caching, cache);
                }
            },
            .repeated => {
                // An empty repeated field is not transmitted — not even as a
                // zero-length packed payload.
                if (f.len != 0) {
                    if (info.is_packed) {
                        // Packable kinds are never `.message` (Kind.packable
                        // returns false whenever wireType() == .len), so this
                        // branch never needs the cache.
                        var payload: usize = 0;
                        for (f) |elem| payload += try valueSize(info.kind, info.Elem, elem, options, depth, false, {});
                        total += wire.tagLen(info.number, .len) + wire.varintLen(payload) + payload;
                    } else {
                        for (f) |elem| {
                            total += wire.tagLen(info.number, info.kind.wireType()) +
                                try valueSize(info.kind, info.Elem, elem, options, depth, caching, cache);
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
    comptime caching: bool,
    cache: if (caching) CacheBuild else void,
) (if (caching) (Error || std.mem.Allocator.Error) else Error)!usize {
    return switch (kind) {
        .int32, .int64, .uint32, .uint64, .sint32, .sint64, .bool, .@"enum" => wire.varintLen(varintOf(kind, E, elem)),
        .fixed64, .sfixed64, .double => 8,
        .fixed32, .sfixed32, .float => 4,
        .string, .bytes => wire.varintLen(elem.len) + elem.len,
        .message => blk: {
            if (comptime caching) {
                var node_children: std.ArrayList(SizeTree) = .empty;
                const inner = try messageSize(E, elem, options, depth + 1, true, .{ .arena = cache.arena, .out = &node_children });
                try cache.out.append(cache.arena, .{ .total = inner, .children = try node_children.toOwnedSlice(cache.arena) });
                break :blk wire.varintLen(inner) + inner;
            }
            const inner = try messageSize(E, elem, options, depth + 1, false, {});
            break :blk wire.varintLen(inner) + inner;
        },
    };
}

// ── emit pass ───────────────────────────────────────────────────────────────

fn emitMessage(comptime T: type, value: T, e: *wire.Emitter, options: Options, depth: u8, cache: ?*Consume) Error!void {
    // A1/protobuf.md F10: no depth check here. `encodeInto`/`encodeAlloc`
    // always call `messageSize` (via `encodedSize`) first, threading the
    // exact same `depth` through the exact same recursion shape — so
    // `messageSize`'s own check (above) has already rejected any value deep
    // enough to trip this one before `emitMessage` is ever reached with it.
    // A second copy of the same check here was dead code that looked like a
    // guard: deleting it (mutation D4 in the audit's repro) changes no test
    // outcome, because there is no reachable path where it would have fired.

    inline for (comptime schema.infos(T)) |info| {
        const f = @field(value, info.name);
        switch (info.card) {
            .singular => {
                if (!isDefault(info.kind, info.Elem, f)) {
                    e.tag(info.number, info.kind.wireType());
                    try emitValue(info.kind, info.Elem, f, e, options, depth, cache);
                }
            },
            .optional => {
                if (f) |present| {
                    e.tag(info.number, info.kind.wireType());
                    if (info.boxed)
                        try emitValue(info.kind, info.Elem, present.*, e, options, depth, cache)
                    else
                        try emitValue(info.kind, info.Elem, present, e, options, depth, cache);
                }
            },
            .repeated => {
                if (f.len != 0) {
                    if (info.is_packed) {
                        var payload: usize = 0;
                        for (f) |elem| payload += try valueSize(info.kind, info.Elem, elem, options, depth, false, {});
                        e.tag(info.number, .len);
                        e.varint(payload);
                        for (f) |elem| try emitValue(info.kind, info.Elem, elem, e, options, depth, cache);
                    } else {
                        for (f) |elem| {
                            e.tag(info.number, info.kind.wireType());
                            try emitValue(info.kind, info.Elem, elem, e, options, depth, cache);
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
    cache: ?*Consume,
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
            if (cache) |c| {
                const node = c.next();
                e.varint(node.total);
                var child_consume: Consume = .{ .nodes = node.children };
                try emitMessage(E, elem, e, options, depth + 1, &child_consume);
            } else {
                const inner = try messageSize(E, elem, options, depth + 1, false, {});
                e.varint(inner);
                try emitMessage(E, elem, e, options, depth + 1, null);
            }
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
