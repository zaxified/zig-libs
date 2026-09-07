// SPDX-License-Identifier: MIT

//! tsdb key codec — the byte layout every other part of the module depends on.
//!
//! The whole module rests on ONE identity:
//!
//! ```
//! std.mem.order(u8, encode(a), encode(b)) == logicalOrder(a, b)
//! ```
//!
//! A time-series read is nothing but `seek(series, from)` + `next()` until the
//! timestamp leaves the window. That only works if byte-lexicographic order over
//! the encoded key equals logical `(series, timestamp)` order — so this file's
//! job is not "round-trips" (a little-endian codec round-trips perfectly and is
//! still catastrophically wrong here), it is *order preservation*. The tests
//! assert the identity, not examples.
//!
//! Two consequences drive the layout:
//!
//! 1. **Fixed-width big-endian.** Variable-width or little-endian fields break
//!    lexicographic order immediately (`0x0100` < `0x02` byte-wise but 256 > 2).
//! 2. **Sign-flipped timestamps.** Negative (pre-epoch) timestamps ARE admitted
//!    — historical backfill is a normal thing to do — and two's-complement bytes
//!    sort wrongly: `-1` is `0xFFFF…` which lexicographically exceeds `+1`'s
//!    `0x0000…01`. Flipping the sign bit maps `i64` onto `u64` monotonically
//!    (`minInt → 0`, `maxInt → maxInt`), restoring the identity.

const std = @import("std");
/// Test-only (`build.zig`'s `test_deps`, never `deps`): fuzz corpus framing.
const testkit = @import("testkit");

const Allocator = std.mem.Allocator;

/// Timestamp type. Units are the caller's choice (Unix milliseconds is the
/// conventional pick) — the module only requires that ordering is numeric and
/// that retention cutoffs use the same unit. Negative values are legal.
pub const Timestamp = i64;

/// Stable, restart-surviving identifier for one (metric name, label set).
pub const SeriesId = u64;

// ── keyspace tags ────────────────────────────────────────────────────────────
//
// One kvtree holds everything; the leading tag byte partitions it. Ordering
// between partitions matters: points must form ONE contiguous, scannable run,
// so nothing may sort between two point keys.

/// Module metadata (series-id counter, retention resume record).
pub const tag_meta: u8 = 0x00;
/// A sample: `tag | series_id(BE u64) | orderedTs(BE u64)` → f64 bits (BE).
pub const tag_point: u8 = 0x01;
/// Series index: `tag | canonical(name, labels)` → series_id (BE u64).
pub const tag_series_index: u8 = 0x02;
/// Reverse index: `tag | series_id(BE u64)` → canonical(name, labels).
pub const tag_series_rev: u8 = 0x03;

pub const point_key_len = 1 + 8 + 8;
/// A point key plus one byte — the successor used to resume a scan strictly
/// after a given point (see `pointKeySuccessor`).
pub const max_scan_key_len = point_key_len + 1;

pub const meta_key_next_series = [_]u8{ tag_meta, 's' };
pub const meta_key_retention = [_]u8{ tag_meta, 'r' };

// ── order-preserving scalar encodings ────────────────────────────────────────

/// Map `i64` onto `u64` monotonically by flipping the sign bit: for all a,b
/// `a < b  <=>  orderedTs(a) < orderedTs(b)`. Without this, negative
/// timestamps sort ABOVE positive ones once written big-endian.
pub fn orderedTs(ts: Timestamp) u64 {
    return @as(u64, @bitCast(ts)) ^ (@as(u64, 1) << 63);
}

/// Inverse of `orderedTs`.
pub fn unorderedTs(u: u64) Timestamp {
    return @bitCast(u ^ (@as(u64, 1) << 63));
}

// ── point keys ───────────────────────────────────────────────────────────────

pub const PointRef = struct { series: SeriesId, ts: Timestamp };

/// `tag_point | series(BE) | orderedTs(BE)` — fixed width, so byte order over
/// the whole key equals `(series, ts)` lexicographic order.
pub fn pointKey(series: SeriesId, ts: Timestamp) [point_key_len]u8 {
    var out: [point_key_len]u8 = undefined;
    out[0] = tag_point;
    std.mem.writeInt(u64, out[1..9], series, .big);
    std.mem.writeInt(u64, out[9..17], orderedTs(ts), .big);
    return out;
}

/// Decode a point key, or null if `key` is not one.
pub fn decodePointKey(key: []const u8) ?PointRef {
    if (key.len != point_key_len or key[0] != tag_point) return null;
    return .{
        .series = std.mem.readInt(u64, key[1..9], .big),
        .ts = unorderedTs(std.mem.readInt(u64, key[9..17], .big)),
    };
}

/// The smallest key that could belong to `series` (its `minInt(i64)` sample).
pub fn seriesStartKey(series: SeriesId) [point_key_len]u8 {
    return pointKey(series, std.math.minInt(Timestamp));
}

/// The smallest key strictly greater than `key`. Every point key is exactly
/// `point_key_len` bytes, so appending a 0x00 byte yields a key that sorts
/// after `key` and before every other point key — exactly the "resume after
/// this one" position a chunked scan needs.
pub fn pointKeySuccessor(key: [point_key_len]u8) [max_scan_key_len]u8 {
    var out: [max_scan_key_len]u8 = undefined;
    @memcpy(out[0..point_key_len], &key);
    out[point_key_len] = 0;
    return out;
}

// ── sample values ────────────────────────────────────────────────────────────

/// f64 → 8 bytes. Values are never ordered, so the endianness here is a free
/// choice; big-endian keeps the whole format one convention.
pub fn encodeValue(v: f64) [8]u8 {
    var out: [8]u8 = undefined;
    std.mem.writeInt(u64, &out, @bitCast(v), .big);
    return out;
}

pub fn decodeValue(bytes: []const u8) ?f64 {
    if (bytes.len != 8) return null;
    return @bitCast(std.mem.readInt(u64, bytes[0..8], .big));
}

// ── series identity ──────────────────────────────────────────────────────────

pub const Label = struct { name: []const u8, value: []const u8 };

/// Longest metric name / label name / label value, and the longest canonical
/// form. kvtree stores a whole entry inside one 4 KiB page, so the index entry
/// (canonical form + tag + the 8-byte id) has a hard ceiling; this bound sits
/// comfortably under it and is enforced instead of surfacing kvtree's
/// `EntryTooLarge` from deep inside a commit.
pub const max_component_len = 1024;
pub const max_canonical_len = 3072;

pub const CanonError = error{
    ComponentTooLong,
    DuplicateLabel,
    SeriesTooLong,
    OutOfMemory,
};

/// Canonical, order-independent, INJECTIVE encoding of (name, labels):
///
/// ```
/// u16 BE name.len | name | u16 BE label_count | (u16 klen | k | u16 vlen | v)*
/// ```
///
/// - **Order-independent**: labels are sorted by name before encoding, so
///   `{a=1,b=2}` and `{b=2,a=1}` produce identical bytes and therefore resolve
///   to the same series id.
/// - **Injective**: every component is length-prefixed, so no separator can be
///   forged from inside a name or value (`{"a=b": "c"}` vs `{"a": "b=c"}` would
///   collide under a delimiter-joined scheme).
/// - Duplicate label names are rejected rather than silently deduplicated —
///   `{a=1,a=2}` has no defensible meaning and would otherwise depend on sort
///   stability.
///
/// Writes `tag_series_index`-free bytes into `out` (which the caller prefixes).
pub fn canonicalize(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    name: []const u8,
    labels: []const Label,
) CanonError!void {
    if (name.len > max_component_len) return error.ComponentTooLong;
    if (labels.len > std.math.maxInt(u16)) return error.SeriesTooLong;

    // Sort a scratch copy by label name; the caller's slice is not mutated.
    var sorted: std.ArrayList(Label) = .empty;
    defer sorted.deinit(gpa);
    try sorted.appendSlice(gpa, labels);
    std.sort.pdq(Label, sorted.items, {}, lessByName);

    for (sorted.items, 0..) |l, i| {
        if (l.name.len > max_component_len or l.value.len > max_component_len)
            return error.ComponentTooLong;
        if (i > 0 and std.mem.eql(u8, sorted.items[i - 1].name, l.name))
            return error.DuplicateLabel;
    }

    try appendLenPrefixed(gpa, out, name);
    try appendU16(gpa, out, @intCast(sorted.items.len));
    for (sorted.items) |l| {
        try appendLenPrefixed(gpa, out, l.name);
        try appendLenPrefixed(gpa, out, l.value);
    }
    if (out.items.len > max_canonical_len) return error.SeriesTooLong;
}

fn lessByName(_: void, a: Label, b: Label) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

fn appendU16(gpa: Allocator, out: *std.ArrayList(u8), v: u16) Allocator.Error!void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .big);
    try out.appendSlice(gpa, &b);
}

fn appendLenPrefixed(gpa: Allocator, out: *std.ArrayList(u8), s: []const u8) Allocator.Error!void {
    try appendU16(gpa, out, @intCast(s.len));
    try out.appendSlice(gpa, s);
}

/// A decoded canonical form. `deinit` frees the label slice; the name/label
/// slices themselves borrow the input bytes.
pub const Descriptor = struct {
    name: []const u8,
    labels: []Label,

    pub fn deinit(self: *Descriptor, gpa: Allocator) void {
        gpa.free(self.labels);
        self.* = undefined;
    }
};

pub const ParseError = error{ Malformed, OutOfMemory };

/// Inverse of `canonicalize` (labels come back in canonical, name-sorted
/// order). Used by ops/introspection and by the tests that check injectivity
/// from both sides.
pub fn parseCanonical(gpa: Allocator, bytes: []const u8) ParseError!Descriptor {
    var r = Cursor{ .b = bytes };
    const name = try r.takeLenPrefixed();
    const count = try r.takeU16();
    const labels = try gpa.alloc(Label, count);
    errdefer gpa.free(labels);
    for (labels) |*l| {
        l.name = try r.takeLenPrefixed();
        l.value = try r.takeLenPrefixed();
    }
    if (r.i != bytes.len) return error.Malformed;
    return .{ .name = name, .labels = labels };
}

const Cursor = struct {
    b: []const u8,
    i: usize = 0,

    fn takeU16(self: *Cursor) error{Malformed}!u16 {
        if (self.i + 2 > self.b.len) return error.Malformed;
        const v = std.mem.readInt(u16, self.b[self.i..][0..2], .big);
        self.i += 2;
        return v;
    }

    fn takeLenPrefixed(self: *Cursor) error{Malformed}![]const u8 {
        const n = try self.takeU16();
        if (self.i + n > self.b.len) return error.Malformed;
        defer self.i += n;
        return self.b[self.i..][0..n];
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Deterministic splitmix64 — no OS randomness, so a failure reproduces.
const Prng = struct {
    s: u64,
    fn next(self: *Prng) u64 {
        self.s +%= 0x9e3779b97f4a7c15;
        var z = self.s;
        z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
        return z ^ (z >> 31);
    }
};

fn logicalOrder(a: PointRef, b: PointRef) std.math.Order {
    if (a.series != b.series) return std.math.order(a.series, b.series);
    return std.math.order(a.ts, b.ts);
}

// THE property. Not a round-trip: a fully little-endian codec round-trips
// perfectly and destroys every range scan in the module. Only an ORDER
// assertion catches that, so this is the assertion.
test "property: byte order over encoded point keys == logical (series, ts) order" {
    // Boundaries first — the values where a sign-flip bug or a width bug shows.
    const edge_ts = [_]Timestamp{
        std.math.minInt(i64), std.math.minInt(i64) + 1, -(1 << 40), -1_000_000,               -256,
        -255,                 -1,                       0,          1,                        255,
        256,                  1_000_000,                1 << 40,    std.math.maxInt(i64) - 1, std.math.maxInt(i64),
    };
    const edge_series = [_]SeriesId{ 0, 1, 255, 256, 257, 1 << 32, std.math.maxInt(u64) - 1, std.math.maxInt(u64) };

    var pts: std.ArrayList(PointRef) = .empty;
    defer pts.deinit(testing.allocator);
    for (edge_series) |s| for (edge_ts) |t| try pts.append(testing.allocator, .{ .series = s, .ts = t });

    // …then a random cloud, including a bias toward small magnitudes (both
    // signs) where adjacent-value ordering is easiest to get wrong.
    var rng = Prng{ .s = 0x7501d6b1e5 };
    for (0..2000) |i| {
        const raw: i64 = @bitCast(rng.next());
        const ts: Timestamp = if (i % 3 == 0) @rem(raw, 4096) else raw;
        try pts.append(testing.allocator, .{ .series = rng.next() % 8, .ts = ts });
    }

    for (pts.items) |a| {
        const ka = pointKey(a.series, a.ts);
        // Decoding must agree too — but that is the WEAK half of the contract.
        const back = decodePointKey(&ka).?;
        try testing.expectEqual(a.series, back.series);
        try testing.expectEqual(a.ts, back.ts);

        for (pts.items) |b| {
            const kb = pointKey(b.series, b.ts);
            try testing.expectEqual(logicalOrder(a, b), std.mem.order(u8, &ka, &kb));
        }
    }
}

test "property: sorting encoded keys yields logical order (the scan's premise)" {
    var rng = Prng{ .s = 0xabcdef01 };
    var refs: [512]PointRef = undefined;
    for (&refs) |*r| r.* = .{ .series = rng.next() % 4, .ts = @rem(@as(i64, @bitCast(rng.next())), 1 << 20) };

    var keys: [512][point_key_len]u8 = undefined;
    for (refs, &keys) |r, *k| k.* = pointKey(r.series, r.ts);

    const byBytes = struct {
        fn lt(_: void, a: [point_key_len]u8, b: [point_key_len]u8) bool {
            return std.mem.lessThan(u8, &a, &b);
        }
    }.lt;
    std.sort.pdq([point_key_len]u8, &keys, {}, byBytes);

    var prev: ?PointRef = null;
    for (keys) |k| {
        const cur = decodePointKey(&k).?;
        if (prev) |p| try testing.expect(logicalOrder(p, cur) != .gt);
        prev = cur;
    }
}

test "point keys sort inside the point tag partition, never outside it" {
    // A scan walks forward until the tag byte changes; nothing may sort
    // between two point keys, and the meta partition must sort BELOW them.
    const lo = seriesStartKey(0);
    const hi = pointKey(std.math.maxInt(u64), std.math.maxInt(i64));
    try testing.expect(std.mem.order(u8, &meta_key_next_series, &lo) == .lt);
    try testing.expect(std.mem.order(u8, &meta_key_retention, &lo) == .lt);
    try testing.expect(std.mem.order(u8, &hi, &[_]u8{tag_series_index}) == .lt);
    try testing.expect(std.mem.order(u8, &hi, &[_]u8{tag_series_rev}) == .lt);
}

test "seriesStartKey is the infimum of its series and successor skips exactly one key" {
    const s: SeriesId = 7;
    const start = seriesStartKey(s);
    for ([_]Timestamp{ std.math.minInt(i64), -1, 0, 1, std.math.maxInt(i64) }) |t| {
        const k = pointKey(s, t);
        try testing.expect(std.mem.order(u8, &start, &k) != .gt);
    }
    // Successor sits strictly after its key and strictly before the next one.
    const k1 = pointKey(s, 100);
    const k2 = pointKey(s, 101);
    const succ = pointKeySuccessor(k1);
    try testing.expect(std.mem.order(u8, &k1, &succ) == .lt);
    try testing.expect(std.mem.order(u8, &succ, &k2) == .lt);
    // …and before the next series' first key.
    const next_series = seriesStartKey(s + 1);
    const last_of_series = pointKey(s, std.math.maxInt(i64));
    try testing.expect(std.mem.order(u8, &last_of_series, &next_series) == .lt);
}

test "canonicalize: label order does not change the bytes" {
    const gpa = testing.allocator;
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(gpa);
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(gpa);

    try canonicalize(gpa, &a, "http_requests", &.{
        .{ .name = "a", .value = "1" },
        .{ .name = "b", .value = "2" },
        .{ .name = "c", .value = "3" },
    });
    try canonicalize(gpa, &b, "http_requests", &.{
        .{ .name = "c", .value = "3" },
        .{ .name = "a", .value = "1" },
        .{ .name = "b", .value = "2" },
    });
    try testing.expectEqualSlices(u8, a.items, b.items);
}

test "canonicalize is injective where a delimiter scheme would collide" {
    const gpa = testing.allocator;
    var a: std.ArrayList(u8) = .empty;
    defer a.deinit(gpa);
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(gpa);

    // Under `name{k=v,k=v}` string-joining these two are the same string.
    try canonicalize(gpa, &a, "m", &.{.{ .name = "a=b", .value = "c" }});
    try canonicalize(gpa, &b, "m", &.{.{ .name = "a", .value = "b=c" }});
    try testing.expect(!std.mem.eql(u8, a.items, b.items));

    // Same for a name that swallows the brace.
    a.clearRetainingCapacity();
    b.clearRetainingCapacity();
    try canonicalize(gpa, &a, "m{x", &.{.{ .name = "y", .value = "1" }});
    try canonicalize(gpa, &b, "m", &.{ .{ .name = "x", .value = "" }, .{ .name = "y", .value = "1" } });
    try testing.expect(!std.mem.eql(u8, a.items, b.items));
}

test "canonicalize rejects duplicate labels and oversize components" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    try testing.expectError(error.DuplicateLabel, canonicalize(gpa, &out, "m", &.{
        .{ .name = "a", .value = "1" },
        .{ .name = "a", .value = "2" },
    }));

    out.clearRetainingCapacity();
    const long = "x" ** (max_component_len + 1);
    try testing.expectError(error.ComponentTooLong, canonicalize(gpa, &out, long, &.{}));

    out.clearRetainingCapacity();
    try testing.expectError(error.ComponentTooLong, canonicalize(gpa, &out, "m", &.{
        .{ .name = "k", .value = long },
    }));

    // Many medium labels blow the canonical ceiling, not a component one.
    out.clearRetainingCapacity();
    var labels: [8]Label = undefined;
    var names: [8][4]u8 = undefined;
    const val = "v" ** 512;
    for (&labels, &names, 0..) |*l, *n, i| {
        n.* = .{ 'l', @intCast('0' + i), 0, 0 };
        l.* = .{ .name = n[0..2], .value = val };
    }
    try testing.expectError(error.SeriesTooLong, canonicalize(gpa, &out, "m", &labels));
}

test "canonical round trip through parseCanonical" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try canonicalize(gpa, &out, "cpu_seconds", &.{
        .{ .name = "zone", .value = "eu" },
        .{ .name = "host", .value = "a\x00b" }, // NUL inside a value is fine
        .{ .name = "mode", .value = "" }, // empty value is fine
    });

    var d = try parseCanonical(gpa, out.items);
    defer d.deinit(gpa);
    try testing.expectEqualStrings("cpu_seconds", d.name);
    try testing.expectEqual(@as(usize, 3), d.labels.len);
    try testing.expectEqualStrings("host", d.labels[0].name);
    try testing.expectEqualStrings("a\x00b", d.labels[0].value);
    try testing.expectEqualStrings("mode", d.labels[1].name);
    try testing.expectEqualStrings("", d.labels[1].value);
    try testing.expectEqualStrings("zone", d.labels[2].name);
}

test "parseCanonical rejects truncated and trailing-garbage input" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try canonicalize(gpa, &out, "m", &.{.{ .name = "k", .value = "v" }});

    try testing.expectError(error.Malformed, parseCanonical(gpa, out.items[0 .. out.items.len - 1]));

    try out.append(gpa, 0xff);
    try testing.expectError(error.Malformed, parseCanonical(gpa, out.items));
}

test "value codec round trip incl. non-finite samples" {
    for ([_]f64{ 0, -0.0, 1, -1, 1e308, -1e308, 5e-324, std.math.inf(f64), -std.math.inf(f64) }) |v| {
        const b = encodeValue(v);
        try testing.expectEqual(v, decodeValue(&b).?);
    }
    const nan = encodeValue(std.math.nan(f64));
    try testing.expect(std.math.isNan(decodeValue(&nan).?));
    try testing.expect(decodeValue(&[_]u8{ 1, 2, 3 }) == null);
}

// ── fuzz: parseCanonical / decodePointKey over arbitrary bytes ───────────
//
// F2: tsdb had no fuzz harness at all and was absent from every repo-wide
// sweep. `SPEC.md` explicitly admits untrusted key bytes ("the tree can be
// shared, so decodePointKey validates…"), and `parseCanonical` is a real
// length-prefixed decoder with a caller-influenced `count` driving
// `gpa.alloc(Label, count)` — exactly the shape a fuzzer exists to check,
// CLASS C ("no wire interop") notwithstanding.

fn fuzzParseCanonical(_: void, smith: *std.testing.Smith) !void {
    const gpa = std.testing.allocator;
    var buf: [256]u8 = undefined;
    // ⚠ One `smith.slice` call, never `bytes` followed by a ranged length: the
    // latter drew `len == 0` on every input this target ever ran outside
    // `--fuzz` (a ranged draw needs eight octets and `bytes` had eaten them),
    // so `parseCanonical` was handed a zero-length slice every round and
    // failed at `takeLenPrefixed` with the descriptor unread in `buf`.
    const len: usize = smith.slice(&buf);
    var d = parseCanonical(gpa, buf[0..len]) catch return;
    d.deinit(gpa);
}

/// ⛔ Built from `canonicalize`, the module's own encoder: a canonical
/// descriptor is a nest of length-prefixed components, and arbitrary octets
/// essentially never spell one (the `count` and every prefix have to agree
/// with the bytes that follow, and the trailing-byte check has to come out
/// exact). The refusals are hand-built, because those a draw CAN produce.
const CanonCorpus = struct {
    store: [12 * (4 + 256)]u8 = undefined,
    used: usize = 0,
    entries: [12][]const u8 = undefined,
    n: usize = 0,

    fn push(self: *CanonCorpus, frame: []const u8) void {
        const sd = testkit.fuzz.seedInto(self.store[self.used..], frame);
        self.entries[self.n] = self.store[self.used..][0..sd.len];
        self.used += sd.len;
        self.n += 1;
    }

    fn encoded(gpa: Allocator, name: []const u8, labels: []const Label) []const u8 {
        var out: std.ArrayList(u8) = .empty;
        canonicalize(gpa, &out, name, labels) catch unreachable;
        return out.items;
    }

    fn build(self: *CanonCorpus, gpa: Allocator) []const []const u8 {
        const two = encoded(gpa, "http_requests_total", &.{
            .{ .name = "method", .value = "GET" },
            .{ .name = "status", .value = "200" },
        });
        self.push(two); // two labels, sorted
        self.push(encoded(gpa, "up", &.{})); // count = 0: header only
        self.push(encoded(gpa, "", &.{.{ .name = "", .value = "" }})); // empty components
        // ⛔ The finding this decoder's shape invites: `count` drives
        // `gpa.alloc(Label, count)`. Here it claims 65535 labels over a frame
        // that carries two — the allocation must not be committed to.
        const lying = gpa.dupe(u8, two) catch unreachable;
        const count_at = 2 + "http_requests_total".len;
        std.mem.writeInt(u16, lying[count_at..][0..2], 0xffff, .big);
        self.push(lying);
        const count_off = gpa.dupe(u8, two) catch unreachable;
        std.mem.writeInt(u16, count_off[count_at..][0..2], 1, .big); // one label short: trailing bytes
        self.push(count_off);
        self.push(two[0 .. two.len - 1]); // truncated inside the last value
        self.push(two[0..1]); // a length prefix with nothing behind it
        var trailing = gpa.alloc(u8, two.len + 1) catch unreachable;
        @memcpy(trailing[0..two.len], two);
        trailing[two.len] = 0xff; // one octet past a complete descriptor
        self.push(trailing);
        self.push(""); // and the input this target used to run for ever
        return self.entries[0..self.n];
    }
};

test "fuzz: parseCanonical never panics or leaks on arbitrary bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var corpus: CanonCorpus = .{};
    try testing.fuzz({}, fuzzParseCanonical, .{ .corpus = corpus.build(arena.allocator()) });
}

test "corpus: every canonical seed reaches the parser, and the counts are pinned" {
    const gpa = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var corpus: CanonCorpus = .{};
    var nonempty: usize = 0;
    var accepted: usize = 0;
    // ⛔ The number the empty replay cannot produce, and that `accepted > 0`
    // could not have held up: labels actually decoded. The `count = 0`
    // descriptor is accepted while walking no label at all.
    var labels: usize = 0;
    for (corpus.build(arena.allocator())) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [256]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        var d = parseCanonical(gpa, buf[0..len]) catch continue;
        defer d.deinit(gpa);
        accepted += 1;
        labels += d.labels.len;
    }
    try testing.expectEqual(corpus.n - 1, nonempty); // all but the empty seed
    try testing.expectEqual(@as(usize, 3), accepted);
    try testing.expectEqual(@as(usize, 3), labels);
}

/// A point key is exactly `point_key_len` octets and a fixed tag; the only
/// interesting inputs are that length and the ones around it.
const point_key_seeds = [_][]const u8{
    testkit.fuzz.seed(&pointKey(1, 0)), // a real key at the epoch
    testkit.fuzz.seed(&pointKey(0xdead_beef_dead_beef, std.math.minInt(Timestamp))),
    testkit.fuzz.seed(&pointKey(7, std.math.maxInt(Timestamp))),
    testkit.fuzz.seed(&(pointKey(1, 0) ++ [_]u8{0})), // one octet too long
    testkit.fuzz.seed(pointKey(1, 0)[0 .. point_key_len - 1]), // one too short
    testkit.fuzz.seed(&([_]u8{0xff} ++ pointKey(1, 0)[1..].*)), // the wrong tag
    testkit.fuzz.seed(""), // and the input this target used to run for ever
};

fn fuzzDecodePointKey(_: void, smith: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    // ⚠ Same as above: this target's length draw was 0 on every input, so
    // `decodePointKey` never saw a key of the one length it accepts.
    const len: usize = smith.slice(&buf);
    _ = decodePointKey(buf[0..len]);
}

test "fuzz: decodePointKey never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzDecodePointKey, .{ .corpus = &point_key_seeds });
}

test "corpus: the point-key seeds reach the decoder, and the counts are pinned" {
    var nonempty: usize = 0;
    var decoded: usize = 0;
    // The round trip is the second number: a decoded key must carry back the
    // series and timestamp its own octets encode, which an all-zero replay
    // (or any wrong-length seed) cannot demonstrate.
    var round_tripped: usize = 0;
    for (point_key_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [64]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        const ref = decodePointKey(buf[0..len]) orelse continue;
        decoded += 1;
        if (std.mem.eql(u8, buf[0..len], &pointKey(ref.series, ref.ts))) round_tripped += 1;
    }
    try testing.expectEqual(point_key_seeds.len - 1, nonempty); // all but the empty seed
    try testing.expectEqual(@as(usize, 3), decoded);
    try testing.expectEqual(@as(usize, 3), round_tripped);
}
