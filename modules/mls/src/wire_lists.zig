// SPDX-License-Identifier: MIT
//! mls.wire_lists — small generic helpers for the ONE wire-encoding shape
//! `codec.zig` (Part 1) deliberately left to each caller: a `T foo<V>`
//! vector whose ELEMENTS are themselves variable-width (so the outer
//! varint length prefix can't be computed as `count * fixed_width` the
//! way a `uint16 foo<V>` list can — `Capabilities`' five lists in
//! `tree.zig` do that arithmetic inline, no helper needed). RFC 9420 has
//! several of these: `Extension extensions<V>` (`tree.zig`), `Certificate
//! certificates<V>` (`tree.zig`'s x509 `Credential`), `HPKECiphertext
//! encrypted_path_secret<V>` and `UpdatePathNode nodes<V>` (`treekem.zig`).
//!
//! Every list here follows the SAME two-pass shape: `encodedLen` sums each
//! element's own `encodedLen()` (no allocation, no scratch buffer — every
//! element bottoms out in already-in-memory byte slices or fixed-width
//! ints, so its encoded length is pure arithmetic); `encode` writes the
//! summed varint prefix then each element in turn into a caller-sized
//! `codec.Writer`; `decode` walks the vector's aliased byte range and
//! allocator-owns the resulting `[]T` slice (each element's OWN fields may
//! still alias the input buffer, matching `codec.Reader`'s no-copy
//! convention — only the outer slice-of-T is a fresh allocation, the same
//! shape `ssh.messages.readNameList` already uses for a dynamic list this
//! repo's `codec.Reader` itself has no notion of since Part 1 never needed
//! one).
//!
//! Model: no RFC section of its own — this is this Part's own
//! implementation-detail helper factoring out a repeated wire-encoding
//! shape, the same role `codec.Writer.writeVectorConcat` plays for Part 1.

const std = @import("std");
const codec = @import("codec.zig");

/// The smallest `codec.varint` prefix `body_len` bytes would need — pure
/// arithmetic mirror of `codec.varint.encodedLen` that never errors
/// (callers needing the `VarintTooLarge` failure mode get it for free from
/// `codec.Writer.writeVarint` itself when `encode` actually runs; `encodedLen`
/// only needs a syntactically-plausible SIZE ESTIMATE for allocating a
/// destination buffer, not a policy decision).
pub fn varintLen(value: usize) usize {
    if (value <= 63) return 1;
    if (value <= 16383) return 2;
    return 4;
}

/// `encodedLen` for a `T foo<V>` vector of fixed-width elements (e.g.
/// `uint16`/`uint32` lists — `Capabilities`' five lists, `ParentNode
/// .unmerged_leaves`) — `elem_width` bytes each, no per-element method
/// needed.
pub fn fixedVecLen(count: usize, elem_width: usize) usize {
    const body = count * elem_width;
    return varintLen(body) + body;
}

/// Writes a `uint16 foo<V>` vector.
pub fn encodeU16Vec(w: *codec.Writer, items: []const u16) codec.Error!void {
    try w.writeVarint(items.len * 2);
    for (items) |v| try w.writeU16(v);
}

/// Reads a `uint16 foo<V>` vector into a freshly allocated slice (caller
/// frees with `allocator.free`).
pub fn decodeU16Vec(allocator: std.mem.Allocator, r: *codec.Reader) ![]u16 {
    const bytes = try r.readVector();
    if (bytes.len % 2 != 0) return error.Malformed;
    const out = try allocator.alloc(u16, bytes.len / 2);
    errdefer allocator.free(out);
    var i: usize = 0;
    while (i < out.len) : (i += 1) out[i] = std.mem.readInt(u16, bytes[i * 2 ..][0..2], .big);
    return out;
}

/// Writes a `uint32 foo<V>` vector (`ParentNode.unmerged_leaves`).
pub fn encodeU32Vec(w: *codec.Writer, items: []const u32) codec.Error!void {
    try w.writeVarint(items.len * 4);
    for (items) |v| try w.writeU32(v);
}

pub fn decodeU32Vec(allocator: std.mem.Allocator, r: *codec.Reader) ![]u32 {
    const bytes = try r.readVector();
    if (bytes.len % 4 != 0) return error.Malformed;
    const out = try allocator.alloc(u32, bytes.len / 4);
    errdefer allocator.free(out);
    var i: usize = 0;
    while (i < out.len) : (i += 1) out[i] = std.mem.readInt(u32, bytes[i * 4 ..][0..4], .big);
    return out;
}

/// `encodedLen` for a `T foo<V>` vector of VARIABLE-width elements, given
/// each element's own `encodedLen()`.
pub fn varVecLen(comptime T: type, items: []const T) usize {
    var body: usize = 0;
    for (items) |it| body += it.encodedLen();
    return varintLen(body) + body;
}

/// Writes a `T foo<V>` vector of variable-width elements, each via its own
/// `encode(w)`.
pub fn encodeVarVec(comptime T: type, w: *codec.Writer, items: []const T) codec.Error!void {
    var body: usize = 0;
    for (items) |it| body += it.encodedLen();
    try w.writeVarint(body);
    for (items) |it| try it.encode(w);
}

/// `encodeVarVec` for element types whose own `encode` returns a WIDER
/// error set than `codec.Error` — e.g. `content.ProposalOrRef`, which can
/// bottom out in a `tree.LeafNode` (`error.Malformed` for a `select`-guarded
/// field missing) or a `KeyPackage`. Identical body; the only difference is
/// the inferred error set, which `encodeVarVec`'s explicit `codec.Error!void`
/// cannot widen to without changing every existing caller's contract.
pub fn encodeVarVecAny(comptime T: type, w: *codec.Writer, items: []const T) !void {
    var body: usize = 0;
    for (items) |it| body += it.encodedLen();
    try w.writeVarint(body);
    for (items) |it| try it.encode(w);
}

/// Reads a `T foo<V>` vector of variable-width elements by repeatedly
/// calling `T.decode` until the vector's aliased byte range is exhausted —
/// works for both allocator-free element decoders (`fn (*codec.Reader)
/// codec.Error!T`) and allocator-owning ones (`fn (std.mem.Allocator,
/// *codec.Reader) !T`), selected by `comptime needs_allocator`.
pub fn decodeVarVec(
    comptime T: type,
    comptime needs_allocator: bool,
    allocator: std.mem.Allocator,
    r: *codec.Reader,
    comptime decodeItem: if (needs_allocator) fn (std.mem.Allocator, *codec.Reader) anyerror!T else fn (*codec.Reader) codec.Error!T,
) ![]T {
    const bytes = try r.readVector();
    var sub = codec.Reader.init(bytes);
    var list: std.ArrayList(T) = .empty;
    errdefer list.deinit(allocator);
    while (!sub.atEnd()) {
        const item = if (needs_allocator) try decodeItem(allocator, &sub) else try decodeItem(&sub);
        try list.append(allocator, item);
    }
    return try list.toOwnedSlice(allocator);
}
