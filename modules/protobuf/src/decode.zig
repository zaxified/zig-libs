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
        // Truncate to 32 bits *before* the zigzag transform, matching the
        // reference (`ZigZagDecode32(static_cast<uint32>(v))`): a varint
        // >= 2^32 in a `sint32` field is truncated first, then interpreted
        // as a zigzagged 32-bit value. Doing zigzag on the full 64 bits and
        // truncating afterwards (the old order here) agrees for varints
        // below 2^32 but disagrees above it — wave-3 audit finding
        // `protobuf` F2, verified against `google.protobuf` 4.21.12.
        .sint32 => wire.zigzagDecode32(@truncate(try cur.varint())),
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

// ── fuzz: decode on arbitrary bytes never panics or leaks ──────────────────
//
// W2 A3 (protobuf F3): CLASS A, zero `testing.fuzz(` harnesses anywhere in
// this module before this — `adversarial.zig`'s existing coverage is real
// but entirely deterministic, hand-seeded from exactly two hand-built
// attack messages (a lying length, an over-deep chain). This module's own
// doc comment names the two properties that have to hold for *arbitrary*
// input, not just those two: declared lengths are bounds-checked against
// the real buffer before anything is allocated or looped over, and nesting
// depth is capped by `Options.max_depth` regardless of what the input asks
// for. The harness below drives real random bytes at four schema shapes
// (scalar-heavy `Wide`, `Repeated`, unknown-field-capturing `Keeps`, and
// self-recursive `Chain`) so the unknown-field-capture path and the message
// merge path both get adversarial input too, not just the scalar loop.
const ct = @import("codec_test.zig");
const encode_mod = @import("encode.zig");
const conformance = @import("conformance.zig");
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing
/// and the `Cursor` the depth-boundary harness reads its script from.
const testkit = @import("testkit");

/// One corpus entry: the message as a `testkit.fuzz` slice seed, then the
/// `u64` words the four knobs after it read.
///
/// ⛔ Both halves matter. The old draw order was `len` FIRST (a ranged draw,
/// which returns the range minimum unless a whole eight-octet word lands in
/// range) and `bytes` into `buf[0..len]` after it — so with no corpus, `len`
/// was 0 and `input` was the EMPTY slice on every round this target ever ran
/// outside `--fuzz`. An empty protobuf message is *legal*: it decodes to the
/// all-defaults value for every one of the four shapes. So the target had a
/// 100% acceptance rate while parsing nothing at all, which is exactly why the
/// guard below pins fields walked and not `accepted > 0`.
///
/// And the knobs are drawn AFTER the byte draw, so on a corpus replay they are
/// dead unless the seed leaves a tail: `max_depth` would be 1, both booleans
/// false, and the shape word 0 — meaning `Repeated`, `Keeps` and `Chain` would
/// never be selected however many message seeds were added.
const DecodeCorpus = struct {
    // audit F14 (2026-09-11): `Presence` -- the one schema shape with
    // OPTIONAL fields (`?i32`/`?[]const u8`, proto3 explicit presence) --
    // was never one of the four shapes this harness could select, so no
    // amount of `--fuzz` time could reach whatever `decode.zig` does
    // differently for a nullable field's presence bit. Not a guess: `Wide`/
    // `Repeated`/`Keeps`/`Chain` (shapes 0-3 below) are all REQUIRED/
    // implicit-presence fields; `Presence` is the only shape with `?T`
    // fields in its schema at all (`conformance.zig`'s own struct
    // definitions). Added as shape 4.
    const cap = conformance.wide_cases.len + conformance.repeated_cases.len + conformance.presence_cases.len + 12;
    store: [cap * (4 + 512 + 4 * 8)]u8 = undefined,
    used: usize = 0,
    entries: [cap][]const u8 = undefined,
    n: usize = 0,

    /// `shape`: 0 `Wide`, 1 `Repeated`, 2 `Keeps`, 3 `Chain`, 4 `Presence`.
    fn push(self: *DecodeCorpus, frame: []const u8, max_depth: u64, copy: u64, reject: u64, shape: u64) void {
        const start = self.used;
        var at = start + testkit.fuzz.seedInto(self.store[start..], frame).len;
        for ([_]u64{ max_depth, copy, reject, shape }) |w| {
            std.mem.writeInt(u64, self.store[at..][0..8], w, .little);
            at += 8;
        }
        self.entries[self.n] = self.store[start..at];
        self.used = at;
        self.n += 1;
    }

    fn build(self: *DecodeCorpus, a: std.mem.Allocator) []const []const u8 {
        // ⛔ A protobuf message an arbitrary byte draw would produce is
        // essentially never a message: every length-delimited field needs a
        // prefix that exactly covers what follows it. The accepted frames
        // therefore come from the module's OWN encoder, over the same case
        // tables `conformance.zig` checks byte-exactly.
        for (conformance.wide_cases) |c| {
            const bytes = encode_mod.encodeAlloc(a, c.value, .{}) catch unreachable;
            self.push(bytes, 64, 1, 0, 0);
        }
        for (conformance.repeated_cases) |c| {
            const bytes = encode_mod.encodeAlloc(a, c.value, .{}) catch unreachable;
            self.push(bytes, 64, 1, 0, 1);
        }
        for (conformance.presence_cases) |c| {
            const bytes = encode_mod.encodeAlloc(a, c.value, .{}) catch unreachable;
            self.push(bytes, 64, 1, 0, 4);
        }
        const chain = encode_mod.encodeAlloc(a, conformance.chain3, .{ .max_depth = 255 }) catch unreachable;
        self.push(chain, 64, 0, 0, 3); // Chain, and `copy_strings = false`
        self.push(chain, 2, 0, 0, 3); // the same, under a cap the chain exceeds
        // Unknown fields, read as `Keeps` — the capture path — and once with
        // `reject_unknown_fields`, the branch that turns capture into refusal.
        const widest = encode_mod.encodeAlloc(a, conformance.wide_cases[17].value, .{}) catch unreachable;
        self.push(widest, 64, 1, 0, 2);
        self.push(widest, 64, 1, 1, 2);
        // The hostile frames `adversarial.zig` names, so the corpus is not
        // "accepted messages only".
        self.push(&[_]u8{ 0x7a, 0xff, 0xff, 0xff, 0xff, 0x0f }, 64, 1, 0, 0); // string length past the buffer
        self.push(&[_]u8{ 0x8a, 0x01, 0xff, 0xff, 0xff, 0xff, 0x07, 0x08 }, 64, 1, 0, 0); // submessage length lies
        self.push(&[_]u8{ 0x0a, 0x80, 0x80, 0x40, 0x01, 0x02 }, 64, 1, 0, 1); // packed field length lies
        self.push(&[_]u8{ 0x9a, 0x06, 0xff, 0xff, 0xff, 0xff, 0x0f }, 64, 1, 0, 2); // unknown-field length lies
        self.push(&[_]u8{ 0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }, 64, 1, 0, 2); // varint overflow
        self.push("", 64, 1, 0, 0); // the input this target used to run for ever
        return self.entries[0..self.n];
    }
};

test "fuzz: decode never panics or leaks, across every message shape the schema exposes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var corpus: DecodeCorpus = .{};
    try std.testing.fuzz({}, fuzzDecodeNeverPanics, .{ .corpus = corpus.build(arena.allocator()) });
}

fn fuzzDecodeNeverPanics(_: void, smith: *std.testing.Smith) !void {
    // ⚠ One `smith.slice` call, the FIRST draw. The old order drew `len` from
    // a ranged draw before the bytes, which returns the range MINIMUM unless a
    // whole eight-octet word lands inside it — so `input` was empty on every
    // round outside `--fuzz`.
    var buf: [4096]u8 = undefined;
    const len: usize = smith.slice(&buf);
    const input = buf[0..len];

    const options: Options = .{
        .max_depth = smith.valueRangeAtMost(u8, 1, 96),
        .copy_strings = smith.value(bool),
        .reject_unknown_fields = smith.value(bool),
    };

    switch (smith.valueRangeAtMost(u3, 0, 4)) {
        0 => try fuzzOne(ct.Wide, input, options),
        1 => try fuzzOne(ct.Repeated, input, options),
        2 => try fuzzOne(ct.Keeps, input, options),
        3 => try fuzzOne(ct.Chain, input, options),
        4 => try fuzzOne(ct.Presence, input, options),
        else => unreachable,
    }
}

fn fuzzOne(comptime T: type, input: []const u8, options: Options) !void {
    var d = decode(T, std.testing.allocator, input, options) catch return;
    defer d.deinit();
}

test "corpus: every decode seed reaches the parser, and the counts are pinned" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var corpus: DecodeCorpus = .{};
    var nonempty: usize = 0;
    var accepted: usize = 0;
    // ⛔ The number the EMPTY input cannot produce. `decode` of `""` succeeds
    // for all four shapes — an empty protobuf message is legal — so an
    // `accepted > 0` guard would have read 100% over a corpus that reached
    // nothing. `octets` is the total length actually handed to the parser.
    var octets: usize = 0;
    var shapes_seen: [5]bool = @splat(false);
    var depths_seen: [2]bool = @splat(false); // the drawn cap, split at 32
    // ⛔ Two of this target's four knobs had no number at all: the guard drew
    // `copy_strings` and `reject_unknown_fields` to stay in step with the
    // harness's word stream and then dropped them on the floor, so the seeds
    // that turn the string-copy path and the unknown-field REFUSAL branch on
    // were pinned by nothing. Both are the range minimum — `false` — on a
    // tail-less seed, which is `copies = 0` and `rejects = 0`.
    var copies: usize = 0;
    var rejects: usize = 0;
    for (corpus.build(arena.allocator())) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [4096]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        octets += len;
        const options: Options = .{
            .max_depth = smith.valueRangeAtMost(u8, 1, 96),
            .copy_strings = smith.value(bool),
            .reject_unknown_fields = smith.value(bool),
        };
        depths_seen[if (options.max_depth < 32) 0 else 1] = true;
        if (options.copy_strings) copies += 1;
        if (options.reject_unknown_fields) rejects += 1;
        const shape = smith.valueRangeAtMost(u3, 0, 4);
        shapes_seen[shape] = true;
        const ok = switch (shape) {
            0 => blk: {
                var d = decode(ct.Wide, std.testing.allocator, buf[0..len], options) catch break :blk false;
                d.deinit();
                break :blk true;
            },
            1 => blk: {
                var d = decode(ct.Repeated, std.testing.allocator, buf[0..len], options) catch break :blk false;
                d.deinit();
                break :blk true;
            },
            2 => blk: {
                var d = decode(ct.Keeps, std.testing.allocator, buf[0..len], options) catch break :blk false;
                d.deinit();
                break :blk true;
            },
            3 => blk: {
                var d = decode(ct.Chain, std.testing.allocator, buf[0..len], options) catch break :blk false;
                d.deinit();
                break :blk true;
            },
            4 => blk: {
                var d = decode(ct.Presence, std.testing.allocator, buf[0..len], options) catch break :blk false;
                d.deinit();
                break :blk true;
            },
            else => unreachable,
        };
        if (ok) accepted += 1;
    }
    // audit F14 (2026-09-11): counts below re-derived after adding the
    // `Presence` shape (`conformance.presence_cases`, 5 entries, all
    // nonempty and all legal). See the comment on the pre-`Presence`
    // numbers this replaced in git history for the "37 of 40" trap this
    // module sits in generally — an empty protobuf is legal and decodes
    // for every shape, so these numbers are about reach, not legality.
    try std.testing.expectEqual(@as(usize, 41), nonempty);
    try std.testing.expectEqual(@as(usize, 38), accepted);
    try std.testing.expectEqual(@as(usize, 458), octets);
    // The knobs are alive on a corpus replay: all five shapes and both
    // sides of the depth cap ran, where a tail-less seed would have pinned
    // every one of them at `Wide` with `max_depth = 1`.
    for (shapes_seen) |s| try std.testing.expect(s);
    for (depths_seen) |d| try std.testing.expect(d);
    try std.testing.expectEqual(@as(usize, 43), copies);
    try std.testing.expectEqual(@as(usize, 1), rejects);
}

// ── fuzz: the depth cap holds at exactly the boundary the input picks ──────
//
// Pure random bytes essentially never spell a genuinely nested submessage
// chain — every level needs a length prefix that correctly covers everything
// inside it, which is astronomically unlikely by chance (this is the same
// obstacle `43c99ad` documents for `cbor`/`isis`). So the harness above,
// however long it runs, cannot be trusted to have ever exercised the depth
// cap's actual boundary. This one builds a REAL nested `Chain` with the
// module's own encoder — the one piece of machinery in this repo that is
// guaranteed to produce a message nested to an exact, chosen depth — and
// then decodes it under an independently fuzzed `max_depth`, asserting the
// precise boundary: a chain of `n` linked nodes must decode whole when
// `n <= max_depth` and must fail with exactly `error.DepthExceeded`
// otherwise. (A round trip alone would not prove this: encode and decode
// share the same depth-counting convention, so a consistent off-by-one in
// both would be invisible to a bytes-match check. The boundary assertion
// below does not compare encode's and decode's counters against each other,
// it compares decode's outcome against the caller-known true nesting depth
// `n`, which is independent of either implementation.)
/// ⛔ The measurement that made this rewrite necessary: BOTH draws were ranged
/// and there was no corpus, so `true_len` and `max_depth` were the range
/// minimum — **1 and 1** — on every input this target ever ran outside
/// `--fuzz`. It built a one-node chain, decoded it under a cap of 1, and took
/// the success path. The `error.DepthExceeded` branch this test exists to
/// assert had never executed once, and the boundary was only ever approached
/// from the safe side.
///
/// The harness now reads its two numbers from one `smith.slice`, so the byte
/// draw comes first and a seed is a readable pair. `Cursor.ranged(1, 200)` is
/// `1 + b % 200`, so the script octet is the value minus one.
const depth_seeds = [_][]const u8{
    testkit.fuzz.seed(&[_]u8{ 0, 0 }), // 1 / 1 — what this target used to be
    testkit.fuzz.seed(&[_]u8{ 63, 63 }), // 64 / 64 — exactly at the cap
    testkit.fuzz.seed(&[_]u8{ 64, 63 }), // 65 / 64 — one over: DepthExceeded
    testkit.fuzz.seed(&[_]u8{ 62, 63 }), // 63 / 64 — one under
    testkit.fuzz.seed(&[_]u8{ 199, 0 }), // 200 / 1 — far over
    testkit.fuzz.seed(&[_]u8{ 0, 199 }), // 1 / 200 — far under
    testkit.fuzz.seed(&[_]u8{ 199, 199 }), // 200 / 200 — the deepest legal chain
    testkit.fuzz.seed(""), // the empty script: 1 / 1 again
};

test "fuzz: the nesting-depth cap fires at exactly the boundary the input asks for" {
    try std.testing.fuzz({}, fuzzDepthCapBoundary, .{ .corpus = &depth_seeds });
}

fn fuzzDepthCapBoundary(_: void, smith: *std.testing.Smith) !void {
    var script: [16]u8 = undefined;
    const script_len: usize = smith.slice(&script);
    var cur: testkit.fuzz.Cursor = .{ .bytes = script[0..script_len] };
    const true_len: u8 = @intCast(cur.ranged(1, 200));
    const max_depth: u8 = @intCast(cur.ranged(1, 200));

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var chain: ?*const ct.Chain = null;
    var i: u8 = 0;
    while (i < true_len) : (i += 1) {
        const node = try a.create(ct.Chain);
        node.* = .{ .depth = i, .next = chain };
        chain = node;
    }
    const root = chain.?.*;

    // Encoder's own depth cap is independent of the decoder's; keep it out
    // of the way (255, the type's max) so only the decoder's cap is under
    // test here.
    const bytes = encode_mod.encodeAlloc(a, root, .{ .max_depth = 255 }) catch |err| switch (err) {
        error.DepthExceeded => return, // true_len > 255: cannot happen (u8), kept for exhaustiveness
        else => return err,
    };

    var d = decode(ct.Chain, std.testing.allocator, bytes, .{ .max_depth = max_depth }) catch |err| {
        if (err == error.DepthExceeded) {
            try std.testing.expect(true_len > max_depth);
            return;
        }
        return err;
    };
    defer d.deinit();

    try std.testing.expect(true_len <= max_depth);
    var got: usize = 1;
    var walk: ?*const ct.Chain = d.value.next;
    while (walk) |c| : (got += 1) walk = c.next;
    try std.testing.expectEqual(@as(usize, true_len), got);
}

test "corpus: the depth seeds drive both sides of the boundary, and the counts are pinned" {
    var nonempty: usize = 0;
    // ⛔ The two numbers that matter here, neither of which the collapsed draw
    // could produce: how many seeds land ABOVE the cap (the `DepthExceeded`
    // branch, which had never executed) and how deep the deepest chain got.
    // With `true_len = max_depth = 1` for every input, `over` was 0 and
    // `deepest` was 1.
    var over: usize = 0;
    var deepest: usize = 0;
    for (depth_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [16]u8 = undefined;
        const script_len: usize = smith.slice(&script);
        if (script_len != 0) nonempty += 1;
        var cur: testkit.fuzz.Cursor = .{ .bytes = script[0..script_len] };
        const true_len: u8 = @intCast(cur.ranged(1, 200));
        const max_depth: u8 = @intCast(cur.ranged(1, 200));
        if (true_len > max_depth) over += 1;
        deepest = @max(deepest, @as(usize, true_len));
    }
    try std.testing.expectEqual(depth_seeds.len - 1, nonempty); // all but the empty script
    try std.testing.expectEqual(@as(usize, 2), over);
    try std.testing.expectEqual(@as(usize, 200), deepest);
}
