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
const builtin = @import("builtin");
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
    return messageSize(@TypeOf(value), value, options, 0, .plain, {});
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

/// Below this nesting depth, `encodeAlloc` skips the size cache entirely and
/// costs exactly what it did before F6 (A1/protobuf.md): a plain, allocation-
/// free sizing pass plus an emit pass that recomputes nested sizes as it
/// goes. Chosen from F6's own hybrid A/B (see SPEC.md): the crossover where
/// the cache's fixed arena/allocation overhead stops outweighing what it
/// saves sits between depth 4 and depth 16, and 8 is the measured wash point
/// (old and new within noise of each other there) -- below it the cache is a
/// net loss, at and above it a net win that grows with depth.
const size_cache_min_depth: u8 = 8;

/// Test-only: counts how many times `encodeAlloc` has taken the `.caching`
/// branch. Wire bytes are IDENTICAL whichever branch runs (that is the
/// entire point of the hybrid), so a differential byte comparison alone
/// cannot tell a correct threshold from a mutant that pins it to 0 (always
/// cache) or `maxInt(u8)` (never cache) — both still produce the right
/// bytes. This lets a test assert on the PATH, not just the output; see the
/// "F6 hybrid" tests at the bottom of this file, and
/// `encodeAllocCachePathCallsForTesting` below.
var cache_path_calls_for_testing: usize = 0;

/// Encode into a freshly allocated, exactly-sized buffer owned by the caller.
///
/// Hybrid (F6 + coordinator review, A1/protobuf.md): a first, allocation-free
/// sizing pass (the SAME one `encodedSize`/`encodeInto` use, `.plain`) also
/// tracks the deepest nesting it actually saw, for free -- `depth` is already
/// threaded through every recursive call, so this is one extra comparison
/// per submessage, not a second traversal. Only when that depth reaches
/// `size_cache_min_depth` does a SizeTree get built at all (a second,
/// allocating pass, `.caching`) and consulted during emit; below the
/// threshold, emit recomputes nested sizes exactly as `encodeInto` does, so
/// a typical shallow gRPC message (depth 1-4) pays what it always paid --
/// zero extra allocation, zero extra arena -- and only a pathologically deep
/// one pays for, and benefits from, the cache. Depth (not submessage count)
/// is the signal: F6's cost is specifically O(depth^2), driven by
/// RECURSION depth, not breadth -- a wide-but-shallow message (many sibling
/// submessages at depth 1) costs the cache-free path no more per node than
/// it always did, so counting nodes would trigger the cache in cases it
/// cannot help.
pub fn encodeAlloc(
    gpa: std.mem.Allocator,
    value: anytype,
    options: Options,
) (Error || std.mem.Allocator.Error)![]u8 {
    var max_depth_seen: u8 = 0;
    const size = try messageSize(@TypeOf(value), value, options, 0, .probing, &max_depth_seen);

    const buf = try gpa.alloc(u8, size);
    errdefer gpa.free(buf);
    var e = wire.Emitter.init(buf);

    if (max_depth_seen < size_cache_min_depth) {
        // Shallow: identical cost shape to before F6 -- no cache, no arena.
        try emitMessage(@TypeOf(value), value, &e, options, 0, null);
    } else {
        if (comptime builtin.is_test) cache_path_calls_for_testing += 1;
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        var root_children: std.ArrayList(SizeTree) = .empty;
        // Recomputes `size` (discarded -- already have it from the probing
        // pass above); the redundant O(depth) pass is negligible next to
        // the O(depth^2) it replaces on the emit side for a value deep
        // enough to reach this branch at all.
        _ = try messageSize(@TypeOf(value), value, options, 0, .caching, .{ .arena = arena, .out = &root_children });
        var consume: Consume = .{ .nodes = try root_children.toOwnedSlice(arena) };
        try emitMessage(@TypeOf(value), value, &e, options, 0, &consume);
    }

    if (e.pos != size) @panic(wire.size_mismatch_message);
    return buf;
}

// ── size cache (F6) ─────────────────────────────────────────────────────────

/// One entry per `.message`-typed field VALUE encountered while sizing a
/// message (one per element for a repeated, non-packed message field),
/// holding that submessage's own total plus a `SizeTree` for each message
/// field IT contains, in the same order. Built once by `messageSize`
/// (`mode = .caching`) and walked in lockstep by `emitMessage` so a nested
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

/// Three ways to run the sizing pass, chosen at comptime so `.plain`'s
/// compiled code is bit-for-bit what it was before F6 existed (the branches
/// for the other two modes are pruned at compile time, not skipped at
/// runtime) — see `encodeInto`/`encodeAlloc`'s doc comments for who uses
/// which:
/// - `.plain` — just the total size, no side channel. `encodedSize` and
///   `encodeInto` always use this; `encodeAlloc` uses it for the emit-side
///   recompute below `size_cache_min_depth`.
/// - `.probing` — the total size, AND the deepest nesting actually seen
///   (`ctx` is an out-pointer, updated for free alongside work already
///   being done). `encodeAlloc`'s first pass.
/// - `.caching` — the total size, AND a `SizeTree` recording every nested
///   submessage's size for the emit pass to consume instead of
///   recomputing. `encodeAlloc`'s second pass, only once `.probing` found
///   the value deep enough to be worth it.
const SizeMode = enum { plain, probing, caching };

fn SizeModeCtx(comptime mode: SizeMode) type {
    return switch (mode) {
        .plain => void,
        .probing => *u8,
        .caching => CacheBuild,
    };
}

// ── sizing pass ─────────────────────────────────────────────────────────────

fn messageSize(
    comptime T: type,
    value: T,
    options: Options,
    depth: u8,
    comptime mode: SizeMode,
    ctx: SizeModeCtx(mode),
) (if (mode == .caching) (Error || std.mem.Allocator.Error) else Error)!usize {
    if (depth >= options.max_depth) return error.DepthExceeded;
    if (comptime mode == .probing) {
        if (depth > ctx.*) ctx.* = depth;
    }
    var total: usize = 0;

    inline for (comptime schema.infos(T)) |info| {
        const f = @field(value, info.name);
        switch (info.card) {
            .singular => {
                if (!isDefault(info.kind, info.Elem, f))
                    total += wire.tagLen(info.number, info.kind.wireType()) +
                        try valueSize(info.kind, info.Elem, f, options, depth, mode, ctx);
            },
            .optional => {
                if (f) |present| {
                    total += wire.tagLen(info.number, info.kind.wireType());
                    total += if (info.boxed)
                        try valueSize(info.kind, info.Elem, present.*, options, depth, mode, ctx)
                    else
                        try valueSize(info.kind, info.Elem, present, options, depth, mode, ctx);
                }
            },
            .repeated => {
                // An empty repeated field is not transmitted — not even as a
                // zero-length packed payload.
                if (f.len != 0) {
                    if (info.is_packed) {
                        // Packable kinds are never `.message` (Kind.packable
                        // returns false whenever wireType() == .len), so this
                        // branch never needs the cache or the depth probe.
                        var payload: usize = 0;
                        for (f) |elem| payload += try valueSize(info.kind, info.Elem, elem, options, depth, .plain, {});
                        total += wire.tagLen(info.number, .len) + wire.varintLen(payload) + payload;
                    } else {
                        for (f) |elem| {
                            total += wire.tagLen(info.number, info.kind.wireType()) +
                                try valueSize(info.kind, info.Elem, elem, options, depth, mode, ctx);
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
    comptime mode: SizeMode,
    ctx: SizeModeCtx(mode),
) (if (mode == .caching) (Error || std.mem.Allocator.Error) else Error)!usize {
    return switch (kind) {
        .int32, .int64, .uint32, .uint64, .sint32, .sint64, .bool, .@"enum" => wire.varintLen(varintOf(kind, E, elem)),
        .fixed64, .sfixed64, .double => 8,
        .fixed32, .sfixed32, .float => 4,
        .string, .bytes => wire.varintLen(elem.len) + elem.len,
        .message => blk: {
            switch (comptime mode) {
                .plain => {
                    const inner = try messageSize(E, elem, options, depth + 1, .plain, {});
                    break :blk wire.varintLen(inner) + inner;
                },
                .probing => {
                    const inner = try messageSize(E, elem, options, depth + 1, .probing, ctx);
                    break :blk wire.varintLen(inner) + inner;
                },
                .caching => {
                    var node_children: std.ArrayList(SizeTree) = .empty;
                    const inner = try messageSize(E, elem, options, depth + 1, .caching, .{ .arena = ctx.arena, .out = &node_children });
                    try ctx.out.append(ctx.arena, .{ .total = inner, .children = try node_children.toOwnedSlice(ctx.arena) });
                    break :blk wire.varintLen(inner) + inner;
                },
            }
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
                        for (f) |elem| payload += try valueSize(info.kind, info.Elem, elem, options, depth, .plain, {});
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
                const inner = try messageSize(E, elem, options, depth + 1, .plain, {});
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

// ── F6 hybrid: which path did encodeAlloc actually take? ───────────────────
//
// The differential tests in codec_test.zig prove `encodeInto` and
// `encodeAlloc` produce the SAME bytes at every depth, including on both
// sides of `size_cache_min_depth`. That is necessary but not sufficient: a
// mutant that pins the threshold to 0 (always cache) or to
// `maxInt(u8)` (never cache) still produces identical bytes — caching is an
// internal cost decision, invisible on the wire by construction — so a
// byte-only test cannot tell a working threshold from a disabled one. This
// is the test that can, via `cache_path_calls_for_testing`.

const testing = std.testing;

fn buildTestChain(buf: []TestChainNode, depth: usize) TestChainNode {
    if (depth == 0) return .{};
    var i: usize = depth;
    while (i > 0) : (i -= 1) {
        buf[i - 1] = .{ .v = @intCast(i), .next = if (i < depth) &buf[i] else null };
    }
    return buf[0];
}

const TestChainNode = struct {
    v: i32 = 0,
    next: ?*const @This() = null,

    pub const pb_fields = .{
        .v = schema.Field{ .number = 1, .kind = .int32 },
        .next = schema.Field{ .number = 2, .kind = .message },
    };
};

test "F6 hybrid: encodeAlloc only takes the .caching path at/above size_cache_min_depth" {
    // Fixed literal depths, deliberately NOT derived from
    // `size_cache_min_depth` (an expression like `size_cache_min_depth + 2`
    // sizing the node array would overflow `u8` under the very mutant this
    // test exists to catch, threshold pinned to `maxInt(u8)` — a mutant
    // that fails to COMPILE is not RED, see FIXER-AGENT-BRIEF.md). `shallow`
    // sits well below any sane threshold (including today's 8), `deep`
    // well above it, so the assertions below are meaningful whether
    // `size_cache_min_depth` is correct, 0, or `maxInt(u8)` — a wrong
    // threshold flips exactly one of the two `expectEqual`s.
    const shallow_depth = 3;
    const deep_depth = 20;
    const gpa = testing.allocator;
    var nodes: [deep_depth]TestChainNode = undefined;
    cache_path_calls_for_testing = 0;

    {
        const shallow = buildTestChain(&nodes, shallow_depth);
        const out = try encodeAlloc(gpa, shallow, .{});
        defer gpa.free(out);
    }
    try testing.expectEqual(@as(usize, 0), cache_path_calls_for_testing);

    {
        const deep = buildTestChain(&nodes, deep_depth);
        const out = try encodeAlloc(gpa, deep, .{});
        defer gpa.free(out);
    }
    try testing.expectEqual(@as(usize, 1), cache_path_calls_for_testing);
}
