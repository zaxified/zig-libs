// SPDX-License-Identifier: MIT
//! ethtool netlink **bitsets** — the part of this family that is easy to get
//! wrong, because the same attribute arrives in two completely different
//! encodings depending on one flag in the *request*.
//!
//! ## The two encodings
//!
//! ```text
//! compact                              verbose
//! ───────                              ───────
//! ETHTOOL_A_BITSET_NOMASK   (flag)     ETHTOOL_A_BITSET_NOMASK   (flag)
//! ETHTOOL_A_BITSET_SIZE     u32        ETHTOOL_A_BITSET_SIZE     u32
//! ETHTOOL_A_BITSET_VALUE    u32[n]     ETHTOOL_A_BITSET_BITS     nest
//! ETHTOOL_A_BITSET_MASK     u32[n]       BITS_BIT nest
//!                                          BIT_INDEX  u32
//!                                          BIT_NAME   string
//!                                          BIT_VALUE  flag (absent = clear)
//! ```
//!
//! **Which one does the kernel send?** Whichever the request asked for: a
//! reply uses the compact form **iff** the request's
//! `ETHTOOL_A_HEADER_FLAGS` carried `ETHTOOL_FLAG_COMPACT_BITSETS`; otherwise
//! it uses the verbose form. Nothing else influences it — same kernel, same
//! device, same attribute. Both forms are pinned here by real captures: `ethtool
//! <dev>` asks *without* the flag and gets verbose link modes, while `ethtool
//! -a <dev>` and `ethtool -k <dev>` ask *with* it and get compact ones (see
//! `goldens.zig`).
//!
//! Requests may use either form too, and `ethtool` itself mixes them: it sends
//! *verbose, name-keyed* bitsets when the user named things ("`--groups
//! eth-mac`", "`-K dev tso off`") because userspace does not want to hardcode
//! bit numbers, and would send compact ones for index-keyed selections.
//!
//! ## `NOMASK` — "list", not "bitmap"
//!
//! A bitset with `ETHTOOL_A_BITSET_NOMASK` has no mask half: every bit it
//! carries is meaningful and the rest are simply not part of the set. Without
//! it the set is a (value, mask) pair, and a bit outside the mask means "not
//! applicable / unsupported" — not "off". `Bitset.inMask` is the accessor that
//! keeps those apart; `isSet` alone would silently conflate them.
//!
//! ### The trap: `NOMASK` changes what a verbose entry *means*
//!
//! `ETHTOOL_A_BITSET_BIT_VALUE` is a flag, and the kernel only emits it for a
//! **masked** verbose bitset. In a `NOMASK` verbose bitset it emits *only the
//! set bits*, each with an index and a name and **no `VALUE` flag at all** —
//! presence is the value. Reading `bit.value` directly there gives `false` for
//! every bit in a list that is, by construction, entirely made of set bits.
//!
//! Both shapes are pinned by real replies from the same kernel seconds apart
//! (`goldens.zig`, `reply_features_verbose`): its `hw` bitset is masked and
//! lists all 64 bits with `VALUE` on the capable ones, while its `active`
//! bitset is `NOMASK` and lists only the nine that are on, none of them
//! carrying `VALUE`. `isSet` / `isSetByName` apply the rule; `Bit.value` is
//! the raw wire flag and is deliberately left raw.
//!
//! ## Sizes
//!
//! The compact form's word count is `ceil(size / 32)`, which this decoder
//! enforces: a `VALUE`/`MASK` payload that does not match the declared `SIZE`
//! is a malformed reply, not something to guess at. Verbose bitsets in
//! *requests* legitimately omit `SIZE` (and often `INDEX`), so `size` is
//! optional here.

const std = @import("std");
const netlink = @import("netlink");
const codec = netlink.codec;
const uapi = @import("uapi.zig");
// Test-only (`build.zig`'s `test_deps`, never `deps`): the fuzz corpus seed
// helpers, in the format `std.testing.Smith` actually reads.
const testkit = @import("testkit");

pub const Error = codec.Error || error{OutOfMemory};

/// The **encode**-side error set. Deliberately disjoint from `Error`: an
/// encoder cannot meet a truncated or badly-framed message, it can only be
/// handed arguments the wire format cannot express. Reporting those as
/// `codec.Error.BadLength` — which is what these functions used to do — made
/// `client.zig` classify a caller-argument fault as `MalformedReply`, i.e. as
/// the *peer's* fault, for a request that was never sent. Same shape as
/// `header.Error` (W2 re-audit 2026-09-02, `ethtool` F3).
pub const BuildError = error{ OutOfMemory, InvalidRequest };

/// Refuse to allocate for an absurd `SIZE`. The biggest real bitset in this
/// family is the link-mode set (126 bits as of Linux 7.0); 64 Ki bits is four
/// orders of magnitude of headroom and still bounds a hostile/corrupt reply.
pub const max_bits: u32 = 1 << 16;

/// One entry of a verbose bitset. A request may carry only `name`, only
/// `index`, or both; a reply from the kernel carries both.
pub const Bit = struct {
    index: ?u32 = null,
    /// Owned by the `Bitset`; NUL stripped.
    name: ?[]const u8 = null,
    /// `ETHTOOL_A_BITSET_BIT_VALUE` is a *flag*: present = set, absent = clear.
    value: bool = false,
};

/// A decoded ethtool bitset, in whichever encoding the kernel used. Owns its
/// allocations — free with `deinit`.
pub const Bitset = struct {
    /// `ETHTOOL_A_BITSET_SIZE`, when the sender included it.
    size: ?u32 = null,
    /// `ETHTOOL_A_BITSET_NOMASK` — the set is a list, not a (value, mask) pair.
    nomask: bool = false,
    /// Compact encoding: value words, host byte order. Null for verbose sets.
    value_words: ?[]u32 = null,
    /// Compact encoding: mask words. Null when `nomask`, or when verbose.
    mask_words: ?[]u32 = null,
    /// Verbose encoding: one entry per bit the sender chose to mention. Null
    /// for compact sets.
    bits: ?[]Bit = null,

    pub const Encoding = enum { compact, verbose };

    pub fn deinit(bs: *Bitset, gpa: std.mem.Allocator) void {
        if (bs.value_words) |w| gpa.free(w);
        if (bs.mask_words) |w| gpa.free(w);
        if (bs.bits) |list| {
            for (list) |b| if (b.name) |n| gpa.free(n);
            gpa.free(list);
        }
        bs.* = .{};
    }

    pub fn encoding(bs: Bitset) Encoding {
        return if (bs.bits != null) .verbose else .compact;
    }

    /// Is bit `index` **set**?
    ///
    /// For a masked set this answers only half the question — a clear bit that
    /// is also outside the mask means "unsupported", not "off". Pair it with
    /// `inMask`.
    ///
    /// In a `NOMASK` verbose set, being listed *is* being set (see the file
    /// header): the kernel omits the `VALUE` flag there entirely.
    pub fn isSet(bs: Bitset, index: u32) bool {
        if (bs.bits) |list| {
            for (list) |b| {
                if (b.index) |i| {
                    if (i == index) return bs.nomask or b.value;
                }
            }
            return false;
        }
        return wordBit(bs.value_words, index);
    }

    /// Is the bit the kernel calls `name` set? Verbose sets only — a compact
    /// set carries no names and answers null.
    ///
    /// Null also means "this masked set does not mention that bit", which is
    /// not the same as "off": in a `FEATURES_GET` reply's `hw` bitset it means
    /// the kernel does not know the feature at all. A `NOMASK` list *does*
    /// know its whole universe, so an absent name there is a definite `false`.
    pub fn isSetByName(bs: Bitset, name: []const u8) ?bool {
        const list = bs.bits orelse return null;
        for (list) |b| {
            if (b.name) |n| {
                if (std.mem.eql(u8, n, name)) return bs.nomask or b.value;
            }
        }
        return if (bs.nomask) false else null;
    }

    /// Is bit `index` part of the set at all — i.e. inside the mask (masked
    /// form), present in the list (verbose), or below `size` (a `NOMASK`
    /// compact set, where every bit is meaningful)?
    pub fn inMask(bs: Bitset, index: u32) bool {
        if (bs.bits) |list| {
            // A verbose list knows its whole universe from SIZE; a verbose
            // masked set knows it from which bits it bothered to send.
            if (bs.nomask) {
                if (bs.size) |n| return index < n;
            }
            for (list) |b| {
                if (b.index) |i| {
                    if (i == index) return true;
                }
            }
            return false;
        }
        if (bs.mask_words) |_| return wordBit(bs.mask_words, index);
        // No mask: everything the set declares is meaningful.
        if (bs.size) |n| return index < n;
        return wordBit(bs.value_words, index);
    }

    /// The kernel's name for bit `index`, when the verbose encoding was used.
    /// Compact sets carry no names — resolve them with a `STRSET_GET` of
    /// `.link_modes` / `.features` instead.
    pub fn nameOf(bs: Bitset, index: u32) ?[]const u8 {
        const list = bs.bits orelse return null;
        for (list) |b| {
            if (b.index) |i| {
                if (i == index) return b.name;
            }
        }
        return null;
    }

    /// Look a bit up by the kernel's name (verbose sets only).
    pub fn byName(bs: Bitset, name: []const u8) ?Bit {
        const list = bs.bits orelse return null;
        for (list) |b| {
            if (b.name) |n| {
                if (std.mem.eql(u8, n, name)) return b;
            }
        }
        return null;
    }

    /// Number of set bits.
    pub fn count(bs: Bitset) u32 {
        if (bs.bits) |list| {
            if (bs.nomask) return @intCast(list.len); // listed = set
            var n: u32 = 0;
            for (list) |b| n += @intFromBool(b.value);
            return n;
        }
        const words = bs.value_words orelse return 0;
        var n: u32 = 0;
        for (words) |w| n += @popCount(w);
        return n;
    }

    /// How many bits this set actually says something about — the size of its
    /// mask. For a masked set that is the mask's population count; for a
    /// `NOMASK` list every bit it carries is in scope. Distinct from `count`,
    /// which counts *set* bits: a mask entry whose value is 0 means "this bit
    /// was mentioned and it is off", which `count` cannot express.
    pub fn maskCount(bs: Bitset) u32 {
        if (bs.bits) |list| {
            if (bs.nomask) return @intCast(list.len);
            var n: u32 = 0;
            for (list) |b| n += @intFromBool(b.index != null);
            return n;
        }
        if (bs.mask_words) |words| {
            var n: u32 = 0;
            for (words) |w| n += @popCount(w);
            return n;
        }
        return bs.size orelse bs.count();
    }

    fn wordBit(words: ?[]const u32, index: u32) bool {
        const w = words orelse return false;
        const word = index / 32;
        if (word >= w.len) return false;
        return (w[word] >> @intCast(index % 32)) & 1 != 0;
    }
};

// ── decoding ───────────────────────────────────────────────────────────────

/// Decode a bitset from the attribute bytes *inside* the bitset nest (i.e.
/// `attr.data` of `ETHTOOL_A_LINKMODES_OURS`, `ETHTOOL_A_FEATURES_HW`, …).
pub fn parse(gpa: std.mem.Allocator, nest_bytes: []const u8) Error!Bitset {
    var out: Bitset = .{};
    errdefer out.deinit(gpa);

    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| switch (a.type) {
        uapi.BITSET.NOMASK => out.nomask = true,
        uapi.BITSET.SIZE => {
            const n = try a.asU32();
            if (n > max_bits) return error.BadLength;
            out.size = n;
        },
        uapi.BITSET.VALUE => {
            if (out.value_words != null) return error.BadLength; // duplicate
            out.value_words = try parseWords(gpa, a.data);
        },
        uapi.BITSET.MASK => {
            if (out.mask_words != null) return error.BadLength;
            out.mask_words = try parseWords(gpa, a.data);
        },
        uapi.BITSET.BITS => {
            if (out.bits != null) return error.BadLength;
            out.bits = try parseBits(gpa, a.data);
        },
        else => {},
    };

    // A compact set's word count is fixed by SIZE — the kernel writes exactly
    // ceil(size/32) words, so anything else is a reply this module refuses to
    // interpret rather than index into.
    if (out.size) |n| {
        const want = (n + 31) / 32;
        if (out.value_words) |w| {
            if (w.len != want) return error.BadLength;
        }
        if (out.mask_words) |w| {
            if (w.len != want) return error.BadLength;
        }
    }
    // A set cannot be both encodings at once.
    if (out.bits != null and (out.value_words != null or out.mask_words != null))
        return error.BadLength;
    // NOMASK and a mask contradict each other.
    if (out.nomask and out.mask_words != null) return error.BadLength;
    return out;
}

fn parseWords(gpa: std.mem.Allocator, data: []const u8) Error![]u32 {
    if (data.len % 4 != 0) return error.BadLength;
    if (data.len / 4 > max_bits / 32) return error.BadLength;
    const words = try gpa.alloc(u32, data.len / 4);
    errdefer gpa.free(words);
    for (words, 0..) |*w, i| {
        w.* = std.mem.readInt(u32, data[i * 4 ..][0..4], native_endian);
    }
    return words;
}

fn parseBits(gpa: std.mem.Allocator, nest_bytes: []const u8) Error![]Bit {
    var out: std.ArrayList(Bit) = .empty;
    errdefer {
        for (out.items) |b| if (b.name) |n| gpa.free(n);
        out.deinit(gpa);
    }
    var it: codec.AttrIterator = .{ .buf = nest_bytes };
    while (try it.next()) |a| {
        if (a.type != uapi.BITSET_BITS.BIT) continue;
        if (out.items.len >= max_bits) return error.BadLength;
        var bit: Bit = .{};
        var inner: codec.AttrIterator = .{ .buf = a.data };
        errdefer if (bit.name) |n| gpa.free(n);
        while (try inner.next()) |x| switch (x.type) {
            uapi.BITSET_BIT.INDEX => {
                const i = try x.asU32();
                if (i >= max_bits) return error.BadLength;
                bit.index = i;
            },
            uapi.BITSET_BIT.NAME => {
                if (bit.name != null) return error.BadLength;
                bit.name = try gpa.dupe(u8, x.asString());
            },
            uapi.BITSET_BIT.VALUE => bit.value = true,
            else => {},
        };
        try out.append(gpa, bit);
    }
    return out.toOwnedSlice(gpa);
}

// ── encoding ───────────────────────────────────────────────────────────────

/// Append a **compact** bitset nest: `SIZE` + `VALUE` (+ `MASK`, or `NOMASK`
/// when there is none). `value`/`mask` are host-order words and must both be
/// `ceil(size/32)` long — the same invariant the decoder enforces.
pub fn appendCompact(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    size: u32,
    value: []const u32,
    mask: ?[]const u32,
) BuildError!void {
    if (size > max_bits) return error.InvalidRequest;
    const want = (size + 31) / 32;
    if (value.len != want) return error.InvalidRequest;
    if (mask) |m| {
        if (m.len != want) return error.InvalidRequest;
    }

    const nest = try codec.nestBegin(gpa, list, attr_type | codec.NLA_F_NESTED);
    if (mask == null) try appendFlag(gpa, list, uapi.BITSET.NOMASK);
    try codec.appendAttrU32(gpa, list, uapi.BITSET.SIZE, size);
    try appendWords(gpa, list, uapi.BITSET.VALUE, value);
    if (mask) |m| try appendWords(gpa, list, uapi.BITSET.MASK, m);
    codec.nestEnd(list, nest) catch return error.InvalidRequest;
}

/// Append a **verbose, name-keyed list** bitset: `NOMASK` + one `BIT { NAME }`
/// per name, no values. This is the shape `ethtool -S <dev> --groups eth-mac …`
/// puts on the wire, and it is byte-pinned by a capture.
pub fn appendNameList(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    names: []const []const u8,
) BuildError!void {
    const nest = try codec.nestBegin(gpa, list, attr_type | codec.NLA_F_NESTED);
    try appendFlag(gpa, list, uapi.BITSET.NOMASK);
    const bits = try codec.nestBegin(gpa, list, uapi.BITSET.BITS | codec.NLA_F_NESTED);
    for (names) |n| {
        const bit = try codec.nestBegin(gpa, list, uapi.BITSET_BITS.BIT | codec.NLA_F_NESTED);
        codec.appendAttrString(gpa, list, uapi.BITSET_BIT.NAME, n) catch |e| switch (e) {
            error.AttrTooLong => return error.InvalidRequest,
            error.OutOfMemory => return error.OutOfMemory,
        };
        codec.nestEnd(list, bit) catch return error.InvalidRequest;
    }
    codec.nestEnd(list, bits) catch return error.InvalidRequest;
    codec.nestEnd(list, nest) catch return error.InvalidRequest;
}

/// One entry of a name-keyed *masked* bitset request: "set this named bit to
/// `on`". Bits not mentioned are left alone (that is what the absent mask
/// means).
pub const NamedValue = struct { name: []const u8, on: bool };

/// Append a **verbose, name-keyed masked** bitset: one `BIT { NAME[, VALUE] }`
/// per entry and *no* `NOMASK`, so the kernel changes exactly the named bits.
/// This is the shape `ethtool -K <dev> tso off` puts on the wire.
pub fn appendNamedValues(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    entries: []const NamedValue,
) BuildError!void {
    const nest = try codec.nestBegin(gpa, list, attr_type | codec.NLA_F_NESTED);
    const bits = try codec.nestBegin(gpa, list, uapi.BITSET.BITS | codec.NLA_F_NESTED);
    for (entries) |e| {
        const bit = try codec.nestBegin(gpa, list, uapi.BITSET_BITS.BIT | codec.NLA_F_NESTED);
        codec.appendAttrString(gpa, list, uapi.BITSET_BIT.NAME, e.name) catch |err| switch (err) {
            error.AttrTooLong => return error.InvalidRequest,
            error.OutOfMemory => return error.OutOfMemory,
        };
        if (e.on) try appendFlag(gpa, list, uapi.BITSET_BIT.VALUE);
        codec.nestEnd(list, bit) catch return error.InvalidRequest;
    }
    codec.nestEnd(list, bits) catch return error.InvalidRequest;
    codec.nestEnd(list, nest) catch return error.InvalidRequest;
}

/// One entry of an index-keyed masked bitset request.
pub const IndexedValue = struct { index: u32, on: bool };

/// Append a **verbose, index-keyed masked** bitset. Same shape as
/// `appendNamedValues` but keyed by `ETHTOOL_A_BITSET_BIT_INDEX`, which is what
/// a caller uses when it already has bit numbers (e.g. link-mode indices read
/// back out of a reply) instead of names.
pub fn appendIndexedValues(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    entries: []const IndexedValue,
) BuildError!void {
    const nest = try codec.nestBegin(gpa, list, attr_type | codec.NLA_F_NESTED);
    const bits = try codec.nestBegin(gpa, list, uapi.BITSET.BITS | codec.NLA_F_NESTED);
    for (entries) |e| {
        if (e.index >= max_bits) return error.InvalidRequest;
        const bit = try codec.nestBegin(gpa, list, uapi.BITSET_BITS.BIT | codec.NLA_F_NESTED);
        try codec.appendAttrU32(gpa, list, uapi.BITSET_BIT.INDEX, e.index);
        if (e.on) try appendFlag(gpa, list, uapi.BITSET_BIT.VALUE);
        codec.nestEnd(list, bit) catch return error.InvalidRequest;
    }
    codec.nestEnd(list, bits) catch return error.InvalidRequest;
    codec.nestEnd(list, nest) catch return error.InvalidRequest;
}

fn appendFlag(gpa: std.mem.Allocator, list: *std.ArrayList(u8), attr_type: u16) BuildError!void {
    codec.appendAttr(gpa, list, attr_type, &.{}) catch |e| switch (e) {
        error.AttrTooLong => unreachable, // 4 bytes total
        error.OutOfMemory => return error.OutOfMemory,
    };
}

fn appendWords(
    gpa: std.mem.Allocator,
    list: *std.ArrayList(u8),
    attr_type: u16,
    words: []const u32,
) BuildError!void {
    const total = codec.attr_header_len + words.len * 4;
    if (total > std.math.maxInt(u16)) return error.InvalidRequest;
    var hdr: [codec.attr_header_len]u8 = undefined;
    std.mem.writeInt(u16, hdr[0..2], @intCast(total), native_endian);
    std.mem.writeInt(u16, hdr[2..4], attr_type, native_endian);
    try list.appendSlice(gpa, &hdr);
    for (words) |w| {
        var raw: [4]u8 = undefined;
        std.mem.writeInt(u32, &raw, w, native_endian);
        try list.appendSlice(gpa, &raw);
    }
}

const native_endian = @import("builtin").cpu.arch.endian();

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

test "compact round-trip: value + mask" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);

    const value = [_]u32{ 0b1011, 0x8000_0001 };
    const mask = [_]u32{ 0xffff_ffff, 0x8000_000f };
    try appendCompact(gpa, &list, 3, 64, &value, &mask);

    var it: codec.AttrIterator = .{ .buf = list.items };
    const a = (try it.next()).?;
    try testing.expectEqual(@as(u16, 3), a.type);
    var bs = try parse(gpa, a.data);
    defer bs.deinit(gpa);

    try testing.expectEqual(Bitset.Encoding.compact, bs.encoding());
    try testing.expectEqual(@as(?u32, 64), bs.size);
    try testing.expect(!bs.nomask);
    try testing.expect(bs.isSet(0));
    try testing.expect(bs.isSet(1));
    try testing.expect(!bs.isSet(2));
    try testing.expect(bs.isSet(3));
    try testing.expect(bs.isSet(63)); // bit 31 of word 1
    try testing.expect(bs.isSet(32));
    // 3 bits in word 0 (0b1011) + 2 in word 1 (0x8000_0001).
    try testing.expectEqual(@as(u32, 5), bs.count());
    // The mask (0xffff_ffff, 0x8000_000f) says something about 37 bits,
    // of which 5 are on.
    try testing.expectEqual(@as(u32, 37), bs.maskCount());
    // Mask semantics: bit 5 is clear *and* supported; bit 40 is neither.
    try testing.expect(bs.inMask(5));
    try testing.expect(!bs.isSet(5));
    try testing.expect(!bs.inMask(40));
    // Out of range never reads out of bounds.
    try testing.expect(!bs.isSet(1_000_000));
    try testing.expect(!bs.inMask(1_000_000));
    try testing.expectEqual(@as(?[]const u8, null), bs.nameOf(0));
}

test "compact round-trip: NOMASK list" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);

    const value = [_]u32{0b0101};
    try appendCompact(gpa, &list, 4, 32, &value, null);
    var it: codec.AttrIterator = .{ .buf = list.items };
    var bs = try parse(gpa, (try it.next()).?.data);
    defer bs.deinit(gpa);

    try testing.expect(bs.nomask);
    try testing.expect(bs.mask_words == null);
    try testing.expect(bs.isSet(0));
    try testing.expect(!bs.isSet(1));
    // Without a mask, every bit below SIZE is meaningful.
    try testing.expect(bs.inMask(1));
    try testing.expect(!bs.inMask(32));
}

test "appendCompact rejects a word count that contradicts SIZE" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    const one = [_]u32{0};
    try testing.expectError(error.InvalidRequest, appendCompact(gpa, &list, 3, 64, &one, null));
    try testing.expectError(error.InvalidRequest, appendCompact(gpa, &list, 3, 32, &one, &[_]u32{ 0, 0 }));
    try testing.expectError(error.InvalidRequest, appendCompact(gpa, &list, 3, max_bits + 1, &one, null));
}

test "verbose round-trip: name-keyed list (the --groups shape)" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendNameList(gpa, &list, 3, &.{ "eth-mac", "rmon" });

    var it: codec.AttrIterator = .{ .buf = list.items };
    var bs = try parse(gpa, (try it.next()).?.data);
    defer bs.deinit(gpa);

    try testing.expectEqual(Bitset.Encoding.verbose, bs.encoding());
    try testing.expect(bs.nomask);
    try testing.expectEqual(@as(usize, 2), bs.bits.?.len);
    try testing.expectEqualStrings("eth-mac", bs.bits.?[0].name.?);
    try testing.expectEqualStrings("rmon", bs.bits.?[1].name.?);
    // A name list carries no indices, so index lookups find nothing.
    try testing.expect(!bs.isSet(0));
    try testing.expect(bs.byName("rmon") != null);
    try testing.expect(bs.byName("eth-phy") == null);
    // …but by name, presence is the value — and the list knows its own
    // universe, so an absent name is a definite "off", not "unknown".
    try testing.expectEqual(@as(?bool, true), bs.isSetByName("rmon"));
    try testing.expectEqual(@as(?bool, false), bs.isSetByName("eth-phy"));
    // The raw wire flag is left raw: no BIT_VALUE was sent for either.
    try testing.expect(!bs.byName("rmon").?.value);
    try testing.expectEqual(@as(u32, 2), bs.count());
}

test "verbose round-trip: name-keyed values (the -K shape)" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendNamedValues(gpa, &list, 3, &.{
        .{ .name = "tx-tcp-segmentation", .on = false },
        .{ .name = "rx-checksum", .on = true },
    });

    var it: codec.AttrIterator = .{ .buf = list.items };
    var bs = try parse(gpa, (try it.next()).?.data);
    defer bs.deinit(gpa);
    try testing.expect(!bs.nomask); // masked: only the named bits change
    try testing.expectEqual(@as(usize, 2), bs.bits.?.len);
    try testing.expect(!bs.byName("tx-tcp-segmentation").?.value);
    try testing.expect(bs.byName("rx-checksum").?.value);
    // Masked: the VALUE flag decides, and a name that was never mentioned is
    // "unknown", not "off".
    try testing.expectEqual(@as(?bool, false), bs.isSetByName("tx-tcp-segmentation"));
    try testing.expectEqual(@as(?bool, true), bs.isSetByName("rx-checksum"));
    try testing.expectEqual(@as(?bool, null), bs.isSetByName("highdma"));
    try testing.expectEqual(@as(u32, 1), bs.count());
}

test "verbose round-trip: index-keyed values" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    try appendIndexedValues(gpa, &list, 3, &.{
        .{ .index = uapi.LINK_MODE.@"1000baseT_Full", .on = true },
        .{ .index = uapi.LINK_MODE.@"100baseT_Full", .on = false },
    });

    var it: codec.AttrIterator = .{ .buf = list.items };
    var bs = try parse(gpa, (try it.next()).?.data);
    defer bs.deinit(gpa);
    try testing.expect(bs.isSet(uapi.LINK_MODE.@"1000baseT_Full"));
    try testing.expect(!bs.isSet(uapi.LINK_MODE.@"100baseT_Full"));
    // Both are *mentioned*, which is what the mask means for a verbose set.
    try testing.expect(bs.inMask(uapi.LINK_MODE.@"100baseT_Full"));
    try testing.expect(!bs.inMask(uapi.LINK_MODE.@"10baseT_Half"));
}

test "hostile: contradictory, oversized and truncated bitsets are rejected" {
    const gpa = testing.allocator;

    // SIZE says 64 bits (2 words) but VALUE carries 1 word.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try codec.appendAttrU32(gpa, &list, uapi.BITSET.SIZE, 64);
        try appendWords(gpa, &list, uapi.BITSET.VALUE, &.{0});
        try testing.expectError(error.BadLength, parse(gpa, list.items));
    }
    // VALUE payload that is not a whole number of u32 words.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try codec.appendAttr(gpa, &list, uapi.BITSET.VALUE, &.{ 1, 2, 3 });
        try testing.expectError(error.BadLength, parse(gpa, list.items));
    }
    // Both encodings at once.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try appendWords(gpa, &list, uapi.BITSET.VALUE, &.{0});
        const bits = try codec.nestBegin(gpa, &list, uapi.BITSET.BITS);
        codec.nestEnd(&list, bits) catch return error.BadLength;
        try testing.expectError(error.BadLength, parse(gpa, list.items));
    }
    // NOMASK together with a MASK.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try codec.appendAttr(gpa, &list, uapi.BITSET.NOMASK, &.{});
        try appendWords(gpa, &list, uapi.BITSET.MASK, &.{0});
        try testing.expectError(error.BadLength, parse(gpa, list.items));
    }
    // An absurd SIZE must not become an allocation.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try codec.appendAttrU32(gpa, &list, uapi.BITSET.SIZE, 0xffff_ffff);
        try testing.expectError(error.BadLength, parse(gpa, list.items));
    }
    // Duplicate VALUE attributes.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try appendWords(gpa, &list, uapi.BITSET.VALUE, &.{0});
        try appendWords(gpa, &list, uapi.BITSET.VALUE, &.{1});
        try testing.expectError(error.BadLength, parse(gpa, list.items));
    }
    // A truncated TLV inside the nest.
    try testing.expectError(error.Truncated, parse(gpa, &.{ 0x40, 0x00, 0x03, 0x00, 0x01 }));
    // A truncated TLV inside the BITS nest.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try codec.appendAttr(gpa, &list, uapi.BITSET.BITS, &.{ 0x40, 0x00, 0x01, 0x00, 0x02 });
        try testing.expectError(error.Truncated, parse(gpa, list.items));
    }
    // A bit index past the ceiling.
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        const bits = try codec.nestBegin(gpa, &list, uapi.BITSET.BITS);
        const bit = try codec.nestBegin(gpa, &list, uapi.BITSET_BITS.BIT);
        try codec.appendAttrU32(gpa, &list, uapi.BITSET_BIT.INDEX, max_bits);
        codec.nestEnd(&list, bit) catch return error.BadLength;
        codec.nestEnd(&list, bits) catch return error.BadLength;
        try testing.expectError(error.BadLength, parse(gpa, list.items));
    }
}

test "empty bitset decodes to an empty set, not an error" {
    const gpa = testing.allocator;
    var bs = try parse(gpa, &.{});
    defer bs.deinit(gpa);
    try testing.expectEqual(@as(u32, 0), bs.count());
    try testing.expect(!bs.isSet(0));
    try testing.expect(!bs.inMask(0));
    try testing.expectEqual(Bitset.Encoding.compact, bs.encoding());
}

/// `ETHTOOL_A_*_BITSET` nest bodies for `fuzzBitset`, laid out the way its
/// draws read them: a `testkit.fuzz` slice seed (u32 length + bytes) and then
/// an eight-octet little-endian word carrying the bit index to probe.
///
/// ⭐ Built at run time by this file's own encoders rather than quoted as hex:
/// a bitset is a tree of netlink TLVs, whose lengths and scalars are HOST byte
/// order, so a hex corpus would be a little-endian one and the counts pinned
/// below would be false on a big-endian target instead of failing there.
///
/// ⛔ The probe word is not decoration. `isSet`, `inMask` and `nameOf` all take
/// a bit index, and it used to be drawn with `valueRangeAtMost(u32, 0, 100_000)`
/// — the range minimum, i.e. **bit 0 on every seed**. Bit 0 of the first word
/// is the one index that needs no arithmetic to reach; every bounds check in
/// those three accessors was untested by this harness.
const BitsetCorpus = struct {
    scratch: [8192]u8 = undefined,
    store: [8192]u8 = undefined,
    used: usize = 0,
    entries: [10][]const u8 = undefined,
    probes: [10]u32 = undefined,
    n: usize = 0,

    fn push(self: *BitsetCorpus, frame: []const u8, probe: u32) void {
        const head = testkit.fuzz.seedInto(self.store[self.used..], frame);
        std.mem.writeInt(u64, self.store[self.used + head.len ..][0..8], probe, .little);
        self.entries[self.n] = self.store[self.used..][0 .. head.len + 8];
        self.probes[self.n] = probe;
        self.used += head.len + 8;
        self.n += 1;
    }

    /// The nest BODY, which is what `parse` takes — one level in from what
    /// `appendCompact` and friends emit.
    fn body(list: *std.ArrayList(u8)) ![]const u8 {
        var it: codec.AttrIterator = .{ .buf = list.items };
        return ((try it.next()) orelse return error.BadLength).data;
    }

    fn build(self: *BitsetCorpus) ![]const []const u8 {
        var fba = std.heap.FixedBufferAllocator.init(&self.scratch);
        const gpa = fba.allocator();

        // Compact, value + mask, 64 bits. Probed at 63 — the last bit of the
        // second word, which bit 0 can never stand in for.
        var compact: std.ArrayList(u8) = .empty;
        try appendCompact(gpa, &compact, 3, 64, &[_]u32{ 0b1011, 0x8000_0001 }, &[_]u32{ 0xffff_ffff, 0x8000_000f });
        self.push(try body(&compact), 63);

        // Compact, NOMASK. Probed past SIZE, where `inMask` must say no.
        var nomask: std.ArrayList(u8) = .empty;
        try appendCompact(gpa, &nomask, 4, 32, &[_]u32{0b0101}, null);
        self.push(try body(&nomask), 32);

        // Verbose, name-keyed list (the `--groups` shape).
        var names: std.ArrayList(u8) = .empty;
        try appendNameList(gpa, &names, 3, &.{ "eth-mac", "rmon" });
        self.push(try body(&names), 1);

        // Verbose, name-keyed values (the `-K` shape).
        var named_values: std.ArrayList(u8) = .empty;
        try appendNamedValues(gpa, &named_values, 3, &.{
            .{ .name = "tx-tcp-segmentation", .on = false },
            .{ .name = "rx-checksum", .on = true },
        });
        self.push(try body(&named_values), 0);

        // Verbose, index-keyed values.
        var indexed: std.ArrayList(u8) = .empty;
        try appendIndexedValues(gpa, &indexed, 3, &.{
            .{ .index = uapi.LINK_MODE.@"1000baseT_Full", .on = true },
            .{ .index = uapi.LINK_MODE.@"100baseT_Full", .on = false },
        });
        self.push(try body(&indexed), uapi.LINK_MODE.@"1000baseT_Full");

        // ── the refusals ───────────────────────────────────────────────────
        // SIZE says 64 bits but VALUE carries one word.
        var contradiction: std.ArrayList(u8) = .empty;
        try codec.appendAttrU32(gpa, &contradiction, uapi.BITSET.SIZE, 64);
        try appendWords(gpa, &contradiction, uapi.BITSET.VALUE, &.{0});
        self.push(contradiction.items, 0);
        // NOMASK together with a MASK.
        var both: std.ArrayList(u8) = .empty;
        try codec.appendAttr(gpa, &both, uapi.BITSET.NOMASK, &.{});
        try appendWords(gpa, &both, uapi.BITSET.MASK, &.{0});
        self.push(both.items, 0);
        // An absurd SIZE that must not become an allocation.
        var absurd: std.ArrayList(u8) = .empty;
        try codec.appendAttrU32(gpa, &absurd, uapi.BITSET.SIZE, 0xffff_ffff);
        self.push(absurd.items, 0);
        // A truncated TLV in the nest, and a bit index past the ceiling.
        self.push(&[_]u8{ 0x40, 0x00, 0x03, 0x00, 0x01 }, 0);
        var past_ceiling: std.ArrayList(u8) = .empty;
        {
            const bits = try codec.nestBegin(gpa, &past_ceiling, uapi.BITSET.BITS);
            const bit = try codec.nestBegin(gpa, &past_ceiling, uapi.BITSET_BITS.BIT);
            try codec.appendAttrU32(gpa, &past_ceiling, uapi.BITSET_BIT.INDEX, max_bits);
            try codec.nestEnd(&past_ceiling, bit);
            try codec.nestEnd(&past_ceiling, bits);
        }
        self.push(past_ceiling.items, max_bits);

        return self.entries[0..self.n];
    }
};

test "fuzz: bitset decoding never crashes or over-reads" {
    var corpus: BitsetCorpus = .{};
    try testing.fuzz({}, fuzzBitset, .{ .corpus = try corpus.build() });
}

fn fuzzBitset(_: void, smith: *std.testing.Smith) !void {
    var raw: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(raw.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM,
    // so `len` was 0 for every seed and `parse` was handed an empty nest with
    // the bitset sitting unread in `raw`.
    //
    // ⛔ And it looked HEALTHIER that way. The test twenty lines up says it in
    // as many words: "empty bitset decodes to an empty set, not an error". So
    // `parse("")` SUCCEEDED every round and the harness ran all six accessors
    // on an empty `Bitset`. Measured 2026-09-07 over the corpus above: **0 of
    // 10 seeds non-empty, 10 of 10 "parsed" and 0 bits set before; 10 of 10
    // non-empty, 5 parsed and 11 bits set after.**
    const len: usize = smith.slice(&raw);
    var bs = parse(testing.allocator, raw[0..len]) catch return;
    defer bs.deinit(testing.allocator);
    // ⚠ `value(u64)` and a `%`, not `valueRangeAtMost(u32, 0, 100_000)`: a
    // ranged draw is the range minimum, so this probed bit 0 for every seed —
    // the one index that reaches no bounds arithmetic in `isSet`, `inMask` or
    // `nameOf`. The probe now travels in the seed. (Five of the ten seeds here
    // probe bit 0 legitimately, which is why the guard pins the probe against
    // what was written rather than merely against zero.)
    const probe: u32 = @intCast(smith.value(u64) % 100_001);
    std.mem.doNotOptimizeAway(bs.isSet(probe));
    std.mem.doNotOptimizeAway(bs.inMask(probe));
    std.mem.doNotOptimizeAway(bs.count());
    _ = bs.nameOf(probe);
    _ = bs.byName("x");
    _ = bs.isSetByName("x");
}

test "corpus: every bitset seed reaches the parser, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets. `nonempty` is the reach claim and the only
    // check that catches a seed grown past the harness's buffer, which
    // `Smith.slice` reads back as the EMPTY one, silently. The second number
    // is what the first cannot say: an empty attribute list is a legal reply
    // here — this file has a test called "empty bitset decodes to an empty
    // set, not an error" — so "parsed" alone counts a harness that walks
    // nothing as a complete success.
    //
    // `probes` pins that the probe word arrived as written — without it the
    // accessor half of the harness silently goes back to asking about bit 0.
    var corpus: BitsetCorpus = .{};
    const entries = try corpus.build();
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var set_bits: usize = 0;
    var probes: usize = 0;
    for (entries, corpus.probes[0..corpus.n]) |sd, want_probe| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [512]u8 = undefined;
        const len: usize = smith.slice(&raw);
        if (len != 0) nonempty += 1;
        var bs = parse(testing.allocator, raw[0..len]) catch {
            _ = smith.value(u64);
            continue;
        };
        defer bs.deinit(testing.allocator);
        parsed += 1;
        const probe: u32 = @intCast(smith.value(u64) % 100_001);
        if (probe == want_probe) probes += 1;
        set_bits += bs.count();
        std.mem.doNotOptimizeAway(bs.isSet(probe));
        std.mem.doNotOptimizeAway(bs.inMask(probe));
        _ = bs.nameOf(probe);
    }
    try testing.expectEqual(entries.len, nonempty);
    try testing.expectEqual(@as(usize, 5), parsed);
    try testing.expectEqual(@as(usize, 5), probes);
    try testing.expectEqual(@as(usize, 11), set_bits);
}

// A nest whose payload does not fit the 16-bit `nla_len` used to be closed
// silently: `codec.nestEnd` truncated the length and returned `void`, so the
// encoders reported success and put a header on the wire covering a fraction
// of its own payload. `nestEnd` was given `error{AttrTooLong}` repo-wide on
// 2026-09-02 and every call site here maps it — but nothing in this module
// drove a nest past the limit, so deleting the whole guard left the suite
// green (W2 re-audit 2026-09-02, `ethtool` F1). These tests are the guard:
// one per verbose encoder, each just over 65535 bytes of nest.
test "a verbose bitset larger than a nest can express is refused, not truncated" {
    const gpa = testing.allocator;

    // ~20 bytes per entry (BIT nest + 8-byte NAME + VALUE flag): 6000 entries
    // is ~120 KB, comfortably past `maxInt(u16)`.
    const names = try gpa.alloc(NamedValue, 6000);
    defer gpa.free(names);
    for (names) |*n| n.* = .{ .name = "aaaaaaaa", .on = true };
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try testing.expectError(
            error.InvalidRequest,
            appendNamedValues(gpa, &list, uapi.FEATURES.WANTED, names),
        );
    }

    const plain = try gpa.alloc([]const u8, 6000);
    defer gpa.free(plain);
    for (plain) |*n| n.* = "aaaaaaaa";
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try testing.expectError(
            error.InvalidRequest,
            appendNameList(gpa, &list, uapi.STATS.GROUPS, plain),
        );
    }

    const idx = try gpa.alloc(IndexedValue, 6000);
    defer gpa.free(idx);
    for (idx, 0..) |*e, i| e.* = .{ .index = @intCast(i), .on = true };
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(gpa);
        try testing.expectError(
            error.InvalidRequest,
            appendIndexedValues(gpa, &list, uapi.LINKMODES.OURS, idx),
        );
    }
}

test "the compact bitset ceiling is pinned at the value, not near it" {
    const gpa = testing.allocator;
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(gpa);
    // Both calls carry a correctly sized `value`, so the only thing that can
    // refuse the second one is the ceiling itself. Sizing both from `max_bits`
    // instead made the over-limit call fail the `value.len != want` check, and
    // widening `max_bits` by 8 then left this test green — it pinned the
    // existence of a check, not its value.
    const words_at = try gpa.alloc(u32, (max_bits + 31) / 32);
    defer gpa.free(words_at);
    @memset(words_at, 0);
    const words_over = try gpa.alloc(u32, (max_bits + 1 + 31) / 32);
    defer gpa.free(words_over);
    @memset(words_over, 0);
    try appendCompact(gpa, &list, uapi.FEATURES.WANTED, max_bits, words_at, null);
    try testing.expectError(
        error.InvalidRequest,
        appendCompact(gpa, &list, uapi.FEATURES.WANTED, max_bits + 1, words_over, null),
    );
}
