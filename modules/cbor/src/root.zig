// SPDX-License-Identifier: MIT
//! cbor — Concise Binary Object Representation (RFC 8949) codec, plus a
//! minimal COSE (RFC 9052) layer built on top (`cose.zig`): parsing
//! `COSE_Key` (EC2/OKP) and `COSE_Sign1`, and building the `Sig_structure`
//! bytes a signer/verifier needs. This is the keystone that unblocks
//! WebAuthn/FIDO2 (attestation objects, authenticator data, COSE public
//! keys) and any other CBOR/COSE-based wire format in this collection.
//!
//! **Decode → `Value`, a tagged union covering all 8 RFC 8949 major types**
//! (0 uint / 1 negint / 2 byte-string / 3 text-string / 4 array / 5 map /
//! 6 tag / 7 simple+float), both definite- and indefinite-length forms.
//! Indefinite byte/text/array/map are decoded into the same definite `Value`
//! shape as their definite counterparts (chunks concatenated, items
//! collected) — decode does not distinguish "was this indefinite on the
//! wire", by design (see README "Deferred"). `decode()` returns everything
//! newly allocated via the caller's `allocator` (arena-friendly, **not**
//! arena-required): the input `bytes` slice can be freed or reused the moment
//! `decode()` returns, and the tree itself is released either by freeing the
//! arena or — for a caller on a plain allocator — with the public
//! `freeValue(allocator, value)`.
//!
//! **Encode ← `Value`.** `encode()` always emits definite-length,
//! shortest-form integers/lengths (RFC 8949 §4.1 "preferred serialization").
//! `EncodeOptions.canonical = true` additionally sorts every map's entries
//! by the bytewise order of their *encoded* keys (RFC 8949 §4.2.1 core
//! deterministic encoding's map-key rule) — together this produces
//! core-deterministic output. Float width is never re-minimized: a
//! `Value.f64` always re-encodes as an 8-byte float, matching whatever width
//! `decode()` (or the caller) chose — see README for why.
//!
//! **Untrusted-input hardening** (this parses hostile bytes, e.g. an
//! attacker-controlled WebAuthn attestation object): a nesting-depth cap
//! (`DecodeOptions.max_depth`, default 64) on arrays/maps/tags; byte/text
//! strings are sliced+duped from the *actual remaining input*, never
//! pre-allocated from an attacker-declared length header (a length of
//! `2^64-1` costs one bounds check, not a 16-exabyte allocation); arrays/
//! maps grow one decoded element at a time (`std.ArrayList.append`), so a
//! bogus huge element count is bounded by how many elements the input bytes
//! can actually supply, not by the declared count; every malformed/
//! truncated/trailing-garbage input is a typed `Error`, never a panic or
//! out-of-bounds read (see the fuzz tests and the hostile-input KATs in
//! `kat_test.zig`).
//!
//! Provenance: RFC 8949 (STD 94) is the normative spec; clean-room from the
//! spec text, no third-party CBOR implementation ported or consulted as a
//! design reference (merger doctrine — see CONVENTIONS.md §5 — no NOTICE
//! entry needed). RFC 9052 for the COSE layer in `cose.zig`.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "CBOR (RFC 8949) codec — all 8 major types, canonical encoding option, untrusted-input hardened; plus a minimal COSE (RFC 9052) layer.",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "RFC 8949 (CBOR) + RFC 9052 (COSE) — clean-room from the specs",
    .deps = .{},
};

// ── errors ──────────────────────────────────────────────────────────────────

/// Decode-time failures. Every one is fail-closed: a `Decode` error means
/// "this byte sequence is not valid CBOR" (or violates a hardening limit),
/// never a panic/OOB read. `OutOfMemory` is the allocator's, not the wire's.
pub const DecodeError = error{
    /// A header or content byte was needed but the input ended first
    /// (a truncated multi-byte length/argument, or a string/array/map
    /// whose declared or actual content runs past the end of `bytes`).
    Truncated,
    /// A syntactically-invalid encoding: a reserved additional-info value
    /// (28–30), an indefinite-length marker (31) on a major type that
    /// doesn't support it (uint/negint/tag), a "break" (0xff) outside an
    /// indefinite-length context, an indefinite byte/text-string chunk that
    /// is itself indefinite or of the wrong major type, or invalid UTF-8 in
    /// a text string.
    Malformed,
    /// Nesting (array/map/tag recursion) exceeded `DecodeOptions.max_depth`
    /// — the hostile-input depth-bomb guard.
    DepthLimitExceeded,
    /// `decode()` consumed a complete, valid CBOR item but bytes remained
    /// after it.
    TrailingGarbage,
    OutOfMemory,
};

pub const EncodeError = Allocator.Error;

// ── Value: the decoded-value representation ─────────────────────────────────

/// One CBOR item, decoded or hand-built for encoding. Owns no external
/// resources — `bytes`/`text`/`array`/`map` slices and `tag.value` are all
/// allocated via whatever `Allocator` produced them (the `allocator` you
/// pass to `decode`, typically an arena).
pub const Value = union(enum) {
    /// Major type 0 — an unsigned integer, value == the field directly.
    uint: u64,
    /// Major type 1 — a negative integer; the actual mathematical value is
    /// `-1 - negint` (RFC 8949 §3.1). Stored as the unsigned magnitude `n`
    /// (not `i65`) so every representable CBOR negint round-trips; use
    /// `toI64` for the common case where it fits an `i64`.
    negint: u64,
    /// Major type 2 — a byte string.
    bytes: []const u8,
    /// Major type 3 — a UTF-8 text string (validated on decode).
    text: []const u8,
    /// Major type 4 — an array of items, in order.
    array: []const Value,
    /// Major type 5 — a map, as an ordered list of entries (insertion/wire
    /// order preserved; see `MapEntry`). CBOR does not require unique keys;
    /// this type doesn't enforce it either — same "decode is lenient"
    /// stance as the rest of this module.
    map: []const MapEntry,
    /// Major type 6 — a tagged value.
    tag: Tag,
    /// Major type 7, simple value (not bool/null/undefined/float): either
    /// the direct 0–19 form or the 1-byte 32–255 form. 20–31 are reserved
    /// for bool/null/undefined/float/break and never appear here.
    simple: u8,
    /// Major type 7 — `false`/`true`.
    bool: bool,
    /// Major type 7 — the `null` simple value (additional info 22).
    null_value,
    /// Major type 7 — the `undefined` simple value (additional info 23).
    undefined_value,
    /// Major type 7 — an IEEE 754 binary16 float (additional info 25).
    f16: f16,
    /// Major type 7 — an IEEE 754 binary32 float (additional info 26).
    f32: f32,
    /// Major type 7 — an IEEE 754 binary64 float (additional info 27).
    f64: f64,

    pub const Tag = struct {
        number: u64,
        value: *const Value,
    };

    /// The integer value as an `i64`, if it fits (covers both `uint` and
    /// `negint`); `null` for non-integer variants or magnitudes outside
    /// `i64`'s range. COSE labels/algorithm identifiers are always small
    /// signed integers, so this is the accessor the `cose` layer uses.
    pub fn toI64(self: Value) ?i64 {
        return switch (self) {
            .uint => |u| if (u <= @as(u64, @intCast(std.math.maxInt(i64)))) @intCast(u) else null,
            .negint => |n| if (n <= @as(u64, @intCast(std.math.maxInt(i64)))) -1 - @as(i64, @intCast(n)) else null,
            else => null,
        };
    }

    /// Build the `Value` for a signed label/integer `i`: `.uint` for `i >=
    /// 0`, `.negint` for `i < 0` (per the `-1 - negint` mapping). Used by
    /// the `cose` layer to build COSE integer map keys (labels are often
    /// negative, e.g. `crv` = -1) and can double as a small-integer
    /// constructor for hand-built `Value` trees.
    pub fn fromI64(i: i64) Value {
        if (i >= 0) return .{ .uint = @intCast(i) };
        return .{ .negint = @intCast(-1 - i) };
    }
};

pub const MapEntry = struct {
    key: Value,
    value: Value,
};

// ── decode ──────────────────────────────────────────────────────────────────

pub const DecodeOptions = struct {
    /// Cap on array/map/tag nesting depth — the depth-bomb guard against a
    /// maliciously deeply-nested input. RFC 8949 sets no limit; 64 comfortably
    /// covers every real CBOR/COSE structure in this collection (a COSE_Sign1
    /// carrying a COSE_Key is 3–4 levels deep) while bounding stack use.
    ///
    /// ⚠ **Raising this converts the guard into the thing it guards against.**
    /// `decodeValue` is recursive, so the cap is what keeps a depth bomb off
    /// the stack; past a few thousand levels the recursion overflows it and
    /// the process dies with SIGSEGV, which no `DecodeError` can report.
    /// Measured on the audited host (8 MiB stack, audit 2026-09-01) with
    /// nested `0x81` arrays and `max_depth` raised to match: **Debug 4096 OK /
    /// 8192 SIGSEGV, ReleaseFast 16384 OK / 32768 SIGSEGV.** The default
    /// leaves a 64–256× margin. A consumer that "generously" sets this to
    /// 10 000 has replaced a typed `DepthLimitExceeded` with a crash, on
    /// input an attacker chooses. Raise it only against a stack you have
    /// measured, and never past low thousands.
    max_depth: u32 = 64,
};

/// Recursively releases everything a decoded `Value` owns (`bytes`/`text`
/// slices, `array`/`map` backing storage and every element inside, `tag`'s
/// heap-allocated inner value) via `allocator` — which **must** be the same
/// allocator the `Value` was `decode`d with.
///
/// This is the counterpart to `decode`, and it is public because the module
/// claims to be *arena-friendly, not arena-required*. It was private, and the
/// only documented cleanup contract was "free the arena" — which meant that
/// posture was not actually deliverable: a caller on a plain allocator had no
/// supported way to release a decoded tree at all, and would have had to walk
/// the `Value` union themselves (and get `tag`'s heap-allocated inner value
/// and the `array`/`map` backing slices right) to avoid leaking.
///
/// Only call it on a `Value` that came out of `decode`. A `Value` a caller
/// built by hand may point at string literals or stack buffers, and a
/// `Value` returned by a *failed* `decode` does not exist — `decode` unwinds
/// its own partial tree before returning an error.
pub fn freeValue(allocator: Allocator, v: Value) void {
    switch (v) {
        .bytes, .text => |s| allocator.free(s),
        .array => |a| {
            for (a) |item| freeValue(allocator, item);
            allocator.free(a);
        },
        .map => |m| {
            for (m) |entry| {
                freeValue(allocator, entry.key);
                freeValue(allocator, entry.value);
            }
            allocator.free(m);
        },
        .tag => |t| {
            freeValue(allocator, t.value.*);
            allocator.destroy(t.value);
        },
        .uint, .negint, .simple, .bool, .null_value, .undefined_value, .f16, .f32, .f64 => {},
    }
}

/// Decode exactly one CBOR item from `bytes`. Fails `error.TrailingGarbage`
/// if bytes remain after the item (use a length-prefixing framing, e.g.
/// `framing`, if you need to pack multiple CBOR items back to back).
/// Everything in the returned `Value` tree is allocated via `allocator`;
/// `bytes` need not outlive the call. Release it with `freeValue(allocator,
/// value)`, or — if `allocator` is an arena — by freeing the arena. On an
/// error return there is nothing to release: the partial tree is unwound
/// before the error leaves this function.
pub fn decode(allocator: Allocator, bytes: []const u8, options: DecodeOptions) DecodeError!Value {
    var d: Decoder = .{ .bytes = bytes, .pos = 0, .allocator = allocator, .max_depth = options.max_depth };
    const v = try d.decodeValue(0);
    if (d.pos != bytes.len) {
        // A fully-decoded tree that turns out to have trailing garbage is
        // still an error return — free it rather than hand the caller
        // nothing while the allocator keeps it alive.
        freeValue(allocator, v);
        return error.TrailingGarbage;
    }
    return v;
}

const Arg = union(enum) { value: u64, indefinite };

const Decoder = struct {
    bytes: []const u8,
    pos: usize,
    allocator: Allocator,
    max_depth: u32,

    fn readByte(self: *Decoder) DecodeError!u8 {
        if (self.pos >= self.bytes.len) return error.Truncated;
        const b = self.bytes[self.pos];
        self.pos += 1;
        return b;
    }

    fn peekByte(self: *Decoder) DecodeError!u8 {
        if (self.pos >= self.bytes.len) return error.Truncated;
        return self.bytes[self.pos];
    }

    fn readUintN(self: *Decoder, comptime nbytes: usize) DecodeError!u64 {
        if (nbytes > self.bytes.len - self.pos) return error.Truncated;
        const T = std.meta.Int(.unsigned, nbytes * 8);
        const v = std.mem.readInt(T, self.bytes[self.pos..][0..nbytes], .big);
        self.pos += nbytes;
        return @as(u64, v);
    }

    /// Slice+dupe `len` bytes from the current position. `len` is an
    /// attacker-declared u64 but we only ever bounds-check it against the
    /// *actual* remaining input before touching the allocator — a huge
    /// declared length costs one comparison, not an allocation attempt.
    fn readBytes(self: *Decoder, len: u64) DecodeError![]const u8 {
        const remaining = self.bytes.len - self.pos;
        if (len > remaining) return error.Truncated;
        const n: usize = @intCast(len);
        const start = self.pos;
        self.pos += n;
        return try self.allocator.dupe(u8, self.bytes[start..self.pos]);
    }

    /// Read the additional-info argument, allowing the major types (2/3/4/5)
    /// that permit indefinite length to report it.
    fn readArgFull(self: *Decoder, info: u5) DecodeError!Arg {
        return switch (info) {
            0...23 => .{ .value = info },
            24 => .{ .value = try self.readUintN(1) },
            25 => .{ .value = try self.readUintN(2) },
            26 => .{ .value = try self.readUintN(4) },
            27 => .{ .value = try self.readUintN(8) },
            28, 29, 30 => error.Malformed,
            31 => .indefinite,
        };
    }

    /// Read the argument for a major type that must be definite (0, 1, 6).
    fn readArg(self: *Decoder, info: u5) DecodeError!u64 {
        return switch (try self.readArgFull(info)) {
            .value => |v| v,
            .indefinite => error.Malformed,
        };
    }

    fn decodeValue(self: *Decoder, depth: u32) DecodeError!Value {
        if (depth > self.max_depth) return error.DepthLimitExceeded;
        const head = try self.readByte();
        const major: u3 = @intCast(head >> 5);
        const info: u5 = @intCast(head & 0x1f);
        return switch (major) {
            0 => .{ .uint = try self.readArg(info) },
            1 => .{ .negint = try self.readArg(info) },
            2 => .{ .bytes = try self.readByteString(info) },
            3 => .{ .text = try self.readTextString(info) },
            4 => .{ .array = try self.readArray(info, depth) },
            5 => .{ .map = try self.readMap(info, depth) },
            6 => blk: {
                const tag_num = try self.readArg(info);
                const inner = try self.allocator.create(Value);
                errdefer self.allocator.destroy(inner);
                inner.* = try self.decodeValue(depth + 1);
                break :blk .{ .tag = .{ .number = tag_num, .value = inner } };
            },
            7 => try self.decodeSimpleOrFloat(info),
        };
    }

    fn readByteString(self: *Decoder, info: u5) DecodeError![]const u8 {
        switch (try self.readArgFull(info)) {
            .value => |len| return try self.readBytes(len),
            .indefinite => {
                var list: std.ArrayList(u8) = .empty;
                errdefer list.deinit(self.allocator);
                while (true) {
                    if (try self.peekByte() == 0xff) {
                        _ = try self.readByte();
                        break;
                    }
                    const chunk_head = try self.readByte();
                    const chunk_major: u3 = @intCast(chunk_head >> 5);
                    if (chunk_major != 2) return error.Malformed;
                    const chunk_info: u5 = @intCast(chunk_head & 0x1f);
                    const chunk_len = switch (try self.readArgFull(chunk_info)) {
                        .value => |v| v,
                        .indefinite => return error.Malformed, // chunks may not nest
                    };
                    const chunk = try self.readBytes(chunk_len);
                    // `chunk` is a standalone dupe; appendSlice copies its
                    // bytes into `list`'s own buffer and does not take
                    // ownership, so `chunk` must be freed here regardless of
                    // whether the append (or a later iteration) succeeds.
                    defer self.allocator.free(chunk);
                    try list.appendSlice(self.allocator, chunk);
                }
                return try list.toOwnedSlice(self.allocator);
            },
        }
    }

    fn readTextString(self: *Decoder, info: u5) DecodeError![]const u8 {
        switch (try self.readArgFull(info)) {
            .value => |len| {
                const s = try self.readBytes(len);
                if (!std.unicode.utf8ValidateSlice(s)) {
                    self.allocator.free(s);
                    return error.Malformed;
                }
                return s;
            },
            .indefinite => {
                var list: std.ArrayList(u8) = .empty;
                errdefer list.deinit(self.allocator);
                while (true) {
                    if (try self.peekByte() == 0xff) {
                        _ = try self.readByte();
                        break;
                    }
                    const chunk_head = try self.readByte();
                    const chunk_major: u3 = @intCast(chunk_head >> 5);
                    if (chunk_major != 3) return error.Malformed;
                    const chunk_info: u5 = @intCast(chunk_head & 0x1f);
                    const chunk_len = switch (try self.readArgFull(chunk_info)) {
                        .value => |v| v,
                        .indefinite => return error.Malformed,
                    };
                    const chunk = try self.readBytes(chunk_len);
                    defer self.allocator.free(chunk);
                    if (!std.unicode.utf8ValidateSlice(chunk)) return error.Malformed;
                    try list.appendSlice(self.allocator, chunk);
                }
                return try list.toOwnedSlice(self.allocator);
            },
        }
    }

    fn readArray(self: *Decoder, info: u5, depth: u32) DecodeError![]const Value {
        var list: std.ArrayList(Value) = .empty;
        // Any error from here on must not leak the elements already
        // decoded and appended (each may own further allocations of its
        // own — nested arrays/maps/tags/strings) nor the list's own
        // backing buffer.
        errdefer {
            for (list.items) |v| freeValue(self.allocator, v);
            list.deinit(self.allocator);
        }
        switch (try self.readArgFull(info)) {
            .value => |n| {
                var i: u64 = 0;
                // Bounded by actual input, not by `n`: each iteration must
                // consume >=1 real byte via decodeValue, so a bogus huge `n`
                // fails Truncated long before the allocator is stressed.
                while (i < n) : (i += 1) {
                    const item = try self.decodeValue(depth + 1);
                    errdefer freeValue(self.allocator, item);
                    try list.append(self.allocator, item);
                }
            },
            .indefinite => {
                while (try self.peekByte() != 0xff) {
                    const item = try self.decodeValue(depth + 1);
                    errdefer freeValue(self.allocator, item);
                    try list.append(self.allocator, item);
                }
                _ = try self.readByte();
            },
        }
        return try list.toOwnedSlice(self.allocator);
    }

    fn readMap(self: *Decoder, info: u5, depth: u32) DecodeError![]const MapEntry {
        var list: std.ArrayList(MapEntry) = .empty;
        errdefer {
            for (list.items) |e| {
                freeValue(self.allocator, e.key);
                freeValue(self.allocator, e.value);
            }
            list.deinit(self.allocator);
        }
        switch (try self.readArgFull(info)) {
            .value => |n| {
                var i: u64 = 0;
                while (i < n) : (i += 1) {
                    const k = try self.decodeValue(depth + 1);
                    errdefer freeValue(self.allocator, k);
                    const v = try self.decodeValue(depth + 1);
                    errdefer freeValue(self.allocator, v);
                    try list.append(self.allocator, .{ .key = k, .value = v });
                }
            },
            .indefinite => {
                while (try self.peekByte() != 0xff) {
                    const k = try self.decodeValue(depth + 1);
                    errdefer freeValue(self.allocator, k);
                    const v = try self.decodeValue(depth + 1);
                    errdefer freeValue(self.allocator, v);
                    try list.append(self.allocator, .{ .key = k, .value = v });
                }
                _ = try self.readByte();
            },
        }
        return try list.toOwnedSlice(self.allocator);
    }

    fn decodeSimpleOrFloat(self: *Decoder, info: u5) DecodeError!Value {
        return switch (info) {
            0...19 => .{ .simple = info },
            20 => .{ .bool = false },
            21 => .{ .bool = true },
            22 => .null_value,
            23 => .undefined_value,
            24 => blk: {
                const b = try self.readUintN(1);
                // Values 0-31 must use the direct 1-byte-head form (info
                // 0-19) or a named form (20-23); re-encoding them via the
                // 1-byte-argument form (info 24) is non-canonical/invalid
                // per RFC 8949 §3.3.
                if (b < 32) return error.Malformed;
                break :blk .{ .simple = @intCast(b) };
            },
            25 => .{ .f16 = @bitCast(@as(u16, @intCast(try self.readUintN(2)))) },
            26 => .{ .f32 = @bitCast(@as(u32, @intCast(try self.readUintN(4)))) },
            27 => .{ .f64 = @bitCast(try self.readUintN(8)) },
            28, 29, 30 => error.Malformed,
            31 => error.Malformed, // "break" outside an indefinite-length context
        };
    }
};

// ── encode ──────────────────────────────────────────────────────────────────

pub const EncodeOptions = struct {
    /// RFC 8949 §4.2.1 core-deterministic map-key ordering: sort every
    /// map's entries by the bytewise order of their *encoded* key bytes.
    /// Default `false` preserves the `Value.map` slice's given order
    /// (typically wire/insertion order, e.g. after a decode round-trip).
    /// Length/integer encoding is always shortest-form and arrays/maps are
    /// always definite-length regardless of this flag (RFC 8949 §4.1
    /// "preferred serialization") — `canonical` only changes map-key order.
    canonical: bool = false,
};

/// Encode `value` to freshly `allocator`-owned bytes.
pub fn encode(allocator: Allocator, value: Value, options: EncodeOptions) EncodeError![]u8 {
    var list: std.ArrayList(u8) = .empty;
    // Without this, a failure anywhere inside `encodeInto` -- or in
    // `toOwnedSlice`'s own final resize -- returns `OutOfMemory` and abandons
    // every byte already produced. Third instance of this class in this
    // module: `decode`'s partial tree (audit 2026-08-06) and `encodeMap`'s
    // canonical scratch (`14ef4331`) were the first two, and this was the one
    // entry point left. Measured before the fix with
    // `std.testing.checkAllAllocationFailures`: 129 bytes allocated, 0 freed,
    // on both the plain and the canonical path.
    errdefer list.deinit(allocator);
    try encodeInto(&list, allocator, value, options);
    return try list.toOwnedSlice(allocator);
}

fn appendBE(list: *std.ArrayList(u8), a: Allocator, v: anytype) EncodeError!void {
    const T = @TypeOf(v);
    var buf: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &buf, v, .big);
    try list.appendSlice(a, &buf);
}

/// Write a major-type head with shortest-form argument encoding.
fn writeHead(list: *std.ArrayList(u8), a: Allocator, major: u3, arg: u64) EncodeError!void {
    const mt: u8 = @as(u8, major) << 5;
    if (arg < 24) {
        try list.append(a, mt | @as(u8, @intCast(arg)));
    } else if (arg <= 0xff) {
        try list.append(a, mt | 24);
        try list.append(a, @intCast(arg));
    } else if (arg <= 0xffff) {
        try list.append(a, mt | 25);
        try appendBE(list, a, @as(u16, @intCast(arg)));
    } else if (arg <= 0xffff_ffff) {
        try list.append(a, mt | 26);
        try appendBE(list, a, @as(u32, @intCast(arg)));
    } else {
        try list.append(a, mt | 27);
        try appendBE(list, a, arg);
    }
}

fn encodeInto(list: *std.ArrayList(u8), a: Allocator, value: Value, options: EncodeOptions) EncodeError!void {
    switch (value) {
        .uint => |v| try writeHead(list, a, 0, v),
        .negint => |v| try writeHead(list, a, 1, v),
        .bytes => |b| {
            try writeHead(list, a, 2, @intCast(b.len));
            try list.appendSlice(a, b);
        },
        .text => |t| {
            try writeHead(list, a, 3, @intCast(t.len));
            try list.appendSlice(a, t);
        },
        .array => |items| {
            try writeHead(list, a, 4, @intCast(items.len));
            for (items) |it| try encodeInto(list, a, it, options);
        },
        .map => |entries| try encodeMap(list, a, entries, options),
        .tag => |t| {
            try writeHead(list, a, 6, t.number);
            try encodeInto(list, a, t.value.*, options);
        },
        .simple => |s| {
            if (s < 20) {
                try list.append(a, 0xe0 | s);
            } else {
                try list.append(a, 0xf8);
                try list.append(a, s);
            }
        },
        .bool => |b| try list.append(a, if (b) 0xf5 else 0xf4),
        .null_value => try list.append(a, 0xf6),
        .undefined_value => try list.append(a, 0xf7),
        .f16 => |f| {
            try list.append(a, 0xf9);
            try appendBE(list, a, @as(u16, @bitCast(f)));
        },
        .f32 => |f| {
            try list.append(a, 0xfa);
            try appendBE(list, a, @as(u32, @bitCast(f)));
        },
        .f64 => |f| {
            try list.append(a, 0xfb);
            try appendBE(list, a, @as(u64, @bitCast(f)));
        },
    }
}

fn encodeMap(list: *std.ArrayList(u8), a: Allocator, entries: []const MapEntry, options: EncodeOptions) EncodeError!void {
    try writeHead(list, a, 5, @intCast(entries.len));
    if (!options.canonical or entries.len < 2) {
        for (entries) |e| {
            try encodeInto(list, a, e.key, options);
            try encodeInto(list, a, e.value, options);
        }
        return;
    }

    // `pairs` and each `key_bytes` scratch buffer below are this function's
    // own allocations, not part of the returned CBOR bytes (which land in
    // `list`) — they must be freed here regardless of how this function
    // returns. Previously they were never freed at all; every module test
    // exercising this path used an ArenaAllocator (kat_test.zig), so the
    // leak was invisible there and only showed up under a plain allocator —
    // exactly the class of defect `example/main.zig`'s `DebugAllocator` is
    // for. `built` tracks how many `pairs[i].key_bytes` are actually owned
    // allocations at the time the deferred free runs, whether this function
    // returns normally or via an error partway through the build loop.
    const Pair = struct { key_bytes: []const u8, entry: MapEntry };
    const pairs = try a.alloc(Pair, entries.len);
    defer a.free(pairs);
    var built: usize = 0;
    defer for (pairs[0..built]) |p| a.free(p.key_bytes);
    for (entries, 0..) |e, i| {
        var kbuf: std.ArrayList(u8) = .empty;
        errdefer kbuf.deinit(a);
        try encodeInto(&kbuf, a, e.key, options);
        pairs[i] = .{ .key_bytes = try kbuf.toOwnedSlice(a), .entry = e };
        built = i + 1;
    }
    std.mem.sort(Pair, pairs, {}, struct {
        fn lessThan(_: void, x: Pair, y: Pair) bool {
            return std.mem.order(u8, x.key_bytes, y.key_bytes) == .lt;
        }
    }.lessThan);
    for (pairs) |p| {
        try list.appendSlice(a, p.key_bytes);
        try encodeInto(list, a, p.entry.value, options);
    }
}

// ── COSE (RFC 9052) — minimal COSE_Key + COSE_Sign1 layer ──────────────────

pub const cose = @import("cose.zig");

// Dark-tests aggregator (CONVENTIONS.md §6.3): a bare re-export does not
// pull a submodule's tests into the test binary — this reference does.
test {
    _ = cose;
    _ = @import("kat_test.zig");
    _ = @import("cose_kat_test.zig");
}

// P-20: `decode` leaked the partially built tree on every error path with a
// non-arena allocator (no `errdefer` anywhere in `readArray`/`readMap`/
// `readByteString`/`readTextString`, nor around the tag `create`, nor at
// `decode`'s own `TrailingGarbage` check). All 12 hostile-input tests in
// `kat_test.zig` use an `ArenaAllocator`, so this class was invisible to the
// suite — `std.testing.allocator` fails the test on any leak, which is
// exactly what makes it the right oracle here.
test "decode does not leak on error paths with a non-arena allocator" {
    const a = std.testing.allocator;

    // The audit's reproducer: array(2) whose 2nd element is truncated.
    try std.testing.expectError(error.Truncated, decode(a, &[_]u8{ 0x82, 0x01 }, .{}));

    // A map whose value is truncated after the key decoded successfully.
    try std.testing.expectError(error.Truncated, decode(a, &[_]u8{ 0xa1, 0x01 }, .{}));

    // A tagged value whose inner item is truncated (exercises the
    // `allocator.create(Value)` for the tag's heap-allocated inner pointer).
    try std.testing.expectError(error.Truncated, decode(a, &[_]u8{ 0xc1, 0x18 }, .{}));

    // An indefinite byte string whose second chunk is truncated, after a
    // valid first chunk was already decoded, duped and appended.
    try std.testing.expectError(
        error.Truncated,
        decode(a, &[_]u8{ 0x5f, 0x41, 0xaa, 0x41 }, .{}),
    );

    // An indefinite text string whose second chunk is invalid UTF-8, after a
    // valid first chunk was already decoded, duped and appended.
    try std.testing.expectError(
        error.Malformed,
        decode(a, &[_]u8{ 0x7f, 0x61, 0x61, 0x61, 0xff }, .{}),
    );

    // A definite text string that is not valid UTF-8.
    try std.testing.expectError(error.Malformed, decode(a, &[_]u8{ 0x61, 0xff }, .{}));

    // array(2): a byte string that decodes fully, then a nested array whose
    // one declared element is missing entirely. The outer `list` already
    // holds the completed byte string when the second element fails, so its
    // errdefer must free that byte string's allocation too, not just the
    // outer list's own buffer.
    try std.testing.expectError(
        error.Truncated,
        decode(a, &[_]u8{ 0x82, 0x41, 0x61, 0x81 }, .{}),
    );

    // A fully-decoded byte string (an owned allocation) with trailing
    // garbage after it — exercises `decode()`'s own `TrailingGarbage` free;
    // an all-`uint` item here would own nothing to leak in the first place.
    try std.testing.expectError(
        error.TrailingGarbage,
        decode(a, &[_]u8{ 0x41, 0x61, 0x02 }, .{}),
    );
}

// ── the fuzz harness that can see a leak, and can see depth ────────────────
//
// W2 A3 (F5) recorded that the module's only harness lived in `kat_test.zig`,
// capped its input at 512 octets and ran `decode` against an `ArenaAllocator`.
// Both halves of that hid something. The arena hid the whole class the test
// above was written for — with an arena, an `errdefer` that stops freeing is
// invisible, because the arena frees it anyway. And a corpus of arbitrary
// octets essentially never spells a container nesting more than a handful of
// levels deep, so the depth guard, and the unwinding of a *deep* partially
// built tree, were unreachable however long the harness ran.
//
// This harness fixes both: `std.testing.allocator` (the fuzz runner checks it
// for leaks after every single input, and `freeValue` is in scope here, which
// is why the harness lives in this file rather than beside the other one), and
// a generator that emits nesting on purpose.
test "fuzz: decode releases every allocation it made, whatever the input" {
    try std.testing.fuzz({}, fuzzDecodeNoLeak, .{ .corpus = cbor_seeds });
}

fn fuzzDecodeNoLeak(_: void, smith: *std.testing.Smith) !void {
    var buf: [4096]u8 = undefined;
    const input = buildNested(smith, &buf);
    const a = std.testing.allocator;
    // The depth cap is drawn too, so the boundary is approached from both
    // sides rather than only from far below a fixed 64.
    const opts = DecodeOptions{ .max_depth = smith.valueRangeAtMost(u32, 1, 96) };
    const v = decode(a, input, opts) catch return;
    freeValue(a, v);
}

/// Either arbitrary octets, or a run of container headers with an arbitrary
/// tail — `81` (array(1)), `9f` (indefinite array), `a1` (map(1)) and `c1`
/// (tag), the four openers whose bodies allocate and therefore have something
/// to leak when the item inside them turns out to be malformed.
fn buildNested(smith: *std.testing.Smith, buf: []u8) []const u8 {
    const opener: u8 = switch (smith.valueRangeAtMost(u8, 0, 4)) {
        0 => {
            smith.bytes(buf);
            return buf[0..smith.valueRangeAtMost(u16, 0, @intCast(buf.len))];
        },
        1 => 0x81,
        2 => 0x9f,
        3 => 0xa1,
        else => 0xc1,
    };
    const depth: usize = smith.valueRangeAtMost(u16, 0, 200);
    var n: usize = @min(depth, buf.len);
    @memset(buf[0..n], opener);
    var tail: [96]u8 = undefined;
    smith.bytes(&tail);
    const tail_len = @min(@as(usize, smith.valueRangeAtMost(u8, 0, tail.len)), buf.len - n);
    @memcpy(buf[n..][0..tail_len], tail[0..tail_len]);
    n += tail_len;
    return buf[0..n];
}

/// See `iec61850/src/goose.zig` for the reasoning: without `--fuzz` the runner
/// feeds only `options.corpus` plus one empty input, and an empty input makes
/// every draw return its range minimum — mode 0, length 0, nothing decoded.
/// `Smith` reads one little-endian `u64` per scalar draw and discards any word
/// that falls outside that draw's range, so the words are kept small.
fn cborSeed(comptime first_word: u64, comptime bits: u64, comptime n: usize) [n]u8 {
    @setEvalBranchQuota(100_000);
    var out: [n]u8 = undefined;
    std.mem.writeInt(u64, out[0..8], first_word, .little);
    var i: usize = 8;
    var w: u6 = 0;
    while (i + 8 <= n) : (i += 8) {
        std.mem.writeInt(u64, out[i..][0..8], (bits >> w) & 0x7F, .little);
        w +%= 1;
    }
    return out;
}

const cbor_seeds: []const []const u8 = &.{
    &cborSeed(1, 0x9E37_79B9_7F4A_7C15, 256), // array(1) nesting
    &cborSeed(2, 0x0123_4567_89AB_CDEF, 256), // indefinite arrays
    &cborSeed(3, 0xF0E1_D2C3_B4A5_9687, 256), // map(1) nesting
    &cborSeed(4, 0x6C62_1F4D_3A98_5E27, 256), // tag nesting
    &cborSeed(0, 0xD5B8_0E93_C741_A26F, 256), // arbitrary octets
};

test "smoke: encode/decode round-trip a small map" {
    const a = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const aa = arena.allocator();

    const entries = [_]MapEntry{
        .{ .key = .{ .uint = 1 }, .value = .{ .text = "a" } },
        .{ .key = .{ .uint = 2 }, .value = .{ .bool = true } },
    };
    const v: Value = .{ .map = &entries };
    const bytes = try encode(aa, v, .{});
    const decoded = try decode(aa, bytes, .{});
    try std.testing.expect(decoded == .map);
    try std.testing.expectEqual(@as(usize, 2), decoded.map.len);
    try std.testing.expectEqualStrings("a", decoded.map[0].value.text);
}
