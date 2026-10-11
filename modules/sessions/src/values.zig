// SPDX-License-Identifier: MIT

//! Key/value layer over a session's opaque data blob (`Session.data()`).
//!
//! Encoding: an empty blob holds no values. Otherwise byte 0 is `tag` (0xA1)
//! and entries follow, each `[key_len u8, 1..255][key][val_len u16 LE][val]`.
//! Keys are unique; order is insertion order (a put of an existing key
//! replaces it in place). A blob that does not start with `tag`, or does not
//! parse exactly to its end, is `error.Malformed` -- an application that mixes
//! raw `setData` and this layer on one session gets an error, never a wrong
//! value and never an out-of-bounds access.
//!
//! Every function here is pure over a byte buffer: it scans the WHOLE blob
//! before it answers (a blob is at most a few KiB), so a corrupt tail is found
//! even when the key sits in the valid prefix, and a failed mutation leaves
//! the buffer untouched.

const std = @import("std");

/// First byte of a non-empty blob written by this layer.
pub const tag: u8 = 0xA1;
pub const max_key_len = 255;
pub const max_val_len = std.math.maxInt(u16);

pub const Error = error{ Malformed, Overflow, InvalidKey };

pub const Entry = struct { key: []const u8, val: []const u8 };

const Located = struct { start: usize, end: usize, val: []const u8 };

/// Walks the entries in insertion order. After an error the iterator is spent.
pub const Iterator = struct {
    blob: []const u8,
    pos: usize = 0,

    pub fn init(blob: []const u8) Iterator {
        return .{ .blob = blob };
    }

    pub fn next(it: *Iterator) error{Malformed}!?Entry {
        const b = it.blob;
        if (it.pos >= b.len) return null;
        if (it.pos == 0) {
            if (b[0] != tag) return it.fail();
            it.pos = 1;
            if (b.len == 1) return null; // a tag alone: no entries (also valid)
        }
        const klen: usize = b[it.pos];
        if (klen == 0) return it.fail();
        const key_at = it.pos + 1;
        if (b.len - key_at < klen + 2) return it.fail();
        const vlen: usize = std.mem.readInt(u16, b[key_at + klen ..][0..2], .little);
        const val_at = key_at + klen + 2;
        if (b.len - val_at < vlen) return it.fail();
        it.pos = val_at + vlen;
        return .{ .key = b[key_at..][0..klen], .val = b[val_at..][0..vlen] };
    }

    fn fail(it: *Iterator) error{Malformed} {
        it.pos = it.blob.len;
        return error.Malformed;
    }
};

/// Scan the whole blob; the entry for `key`, if any.
fn locate(blob: []const u8, key: []const u8) error{Malformed}!?Located {
    var it = Iterator.init(blob);
    var found: ?Located = null;
    var prev_end: usize = if (blob.len == 0) 0 else 1;
    while (try it.next()) |e| {
        if (found == null and std.mem.eql(u8, e.key, key))
            found = .{ .start = prev_end, .end = it.pos, .val = e.val };
        prev_end = it.pos;
    }
    return found;
}

/// The value stored under `key` (a slice into `blob`), or null.
pub fn get(blob: []const u8, key: []const u8) error{Malformed}!?[]const u8 {
    const l = (try locate(blob, key)) orelse return null;
    return l.val;
}

fn overlaps(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;
    const a0 = @intFromPtr(a.ptr);
    const b0 = @intFromPtr(b.ptr);
    return a0 < b0 + b.len and b0 < a0 + a.len;
}

/// Insert or replace `key` in `buf[0..len]`; returns the new length. `key` and
/// `val` may point into `buf` itself (e.g. a value just read); they are copied
/// aside first. On any error `buf` is unchanged.
pub fn put(comptime cap: usize, buf: *[cap]u8, len: usize, key: []const u8, val: []const u8) Error!usize {
    if (key.len == 0 or key.len > max_key_len) return error.InvalidKey;
    if (val.len > max_val_len) return error.Overflow;
    const loc = try locate(buf[0..len], key);
    const entry_len = 1 + key.len + 2 + val.len;
    const base = if (len == 0) 1 else len;
    const old_len = if (loc) |l| l.end - l.start else 0;
    const new_len = base - old_len + entry_len;
    if (new_len > cap) return error.Overflow;

    var key_tmp: [max_key_len]u8 = undefined;
    var val_tmp: [cap]u8 = undefined;
    var k = key;
    var v = val;
    if (overlaps(key, buf)) {
        @memcpy(key_tmp[0..key.len], key);
        k = key_tmp[0..key.len];
    }
    if (overlaps(val, buf)) {
        @memcpy(val_tmp[0..val.len], val);
        v = val_tmp[0..val.len];
    }

    var at: usize = undefined;
    if (loc) |l| {
        // Move the tail so the new entry fits exactly where the old one was.
        @memmove(buf[l.start + entry_len .. new_len], buf[l.end..len]);
        at = l.start;
    } else {
        buf[0] = tag;
        at = base;
    }
    buf[at] = @intCast(k.len);
    @memcpy(buf[at + 1 ..][0..k.len], k);
    std.mem.writeInt(u16, buf[at + 1 + k.len ..][0..2], @intCast(v.len), .little);
    @memcpy(buf[at + 3 + k.len ..][0..v.len], v);
    return new_len;
}

/// Remove `key` from `buf[0..len]`. Returns the new length (0 once the last
/// entry is gone -- the canonical empty blob) and whether the key was there.
pub fn remove(buf: []u8, len: usize, key: []const u8) error{Malformed}!struct { len: usize, removed: bool } {
    const l = (try locate(buf[0..len], key)) orelse return .{ .len = len, .removed = false };
    @memmove(buf[l.start .. len - (l.end - l.start)], buf[l.end..len]);
    const new_len = len - (l.end - l.start);
    return .{ .len = if (new_len <= 1) 0 else new_len, .removed = true };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const tcap = 64;

test "put/get/remove on a small buffer: insertion order, in-place replace, canonical empty" {
    var buf: [tcap]u8 = undefined;
    var len: usize = 0;
    len = try put(tcap, &buf, len, "a", "1");
    len = try put(tcap, &buf, len, "bb", "22");
    try testing.expectEqualSlices(u8, &.{ tag, 1, 'a', 1, 0, '1', 2, 'b', 'b', 2, 0, '2', '2' }, buf[0..len]);
    // Replace with a longer and a shorter value: order is kept.
    len = try put(tcap, &buf, len, "a", "xyz");
    try testing.expectEqualStrings("xyz", (try get(buf[0..len], "a")).?);
    try testing.expectEqualStrings("22", (try get(buf[0..len], "bb")).?);
    len = try put(tcap, &buf, len, "a", "");
    try testing.expectEqualStrings("", (try get(buf[0..len], "a")).?);
    var it = Iterator.init(buf[0..len]);
    try testing.expectEqualStrings("a", (try it.next()).?.key);
    try testing.expectEqualStrings("bb", (try it.next()).?.key);
    try testing.expect((try it.next()) == null);

    const r1 = try remove(&buf, len, "nope");
    try testing.expect(!r1.removed);
    const r2 = try remove(&buf, len, "a");
    try testing.expect(r2.removed);
    try testing.expectEqualStrings("22", (try get(buf[0..r2.len], "bb")).?);
    try testing.expect((try get(buf[0..r2.len], "a")) == null);
    const r3 = try remove(&buf, r2.len, "bb");
    try testing.expectEqual(@as(usize, 0), r3.len); // no tag-only blob left behind
}

test "put refuses what does not fit and leaves the buffer untouched" {
    var buf: [tcap]u8 = undefined;
    var len = try put(tcap, &buf, 0, "k", "v");
    const snapshot = buf;
    const before = snapshot[0..len];
    try testing.expectError(error.InvalidKey, put(tcap, &buf, len, "", "v"));
    try testing.expectError(error.InvalidKey, put(tcap, &buf, len, &@as([256]u8, @splat('k')), "v"));
    try testing.expectError(error.Overflow, put(tcap, &buf, len, "big", &@as([tcap]u8, @splat('x'))));
    try testing.expectEqualSlices(u8, before, buf[0..len]);
    // Exactly full is fine: tag + (1+1+2+v) = tcap.
    len = try put(tcap, &buf, len, "k", &@as([tcap - 5]u8, @splat('y')));
    try testing.expectEqual(@as(usize, tcap), len);
    try testing.expectError(error.Overflow, put(tcap, &buf, len, "z", ""));
    // A 255-byte key is valid when it fits.
    var big: [512]u8 = undefined;
    const l2 = try put(512, &big, 0, &@as([255]u8, @splat('K')), "v");
    try testing.expectEqual(@as(usize, 1 + 1 + 255 + 2 + 1), l2);
}

test "put with a key or value that points into the buffer itself" {
    var buf: [tcap]u8 = undefined;
    var len = try put(tcap, &buf, 0, "a", "hello");
    len = try put(tcap, &buf, len, "b", "w");
    // copy a's value over b, and a's value into a new key, from slices into buf
    len = try put(tcap, &buf, len, "b", (try get(buf[0..len], "a")).?);
    try testing.expectEqualStrings("hello", (try get(buf[0..len], "b")).?);
    len = try put(tcap, &buf, len, "a", (try get(buf[0..len], "b")).?[1..4]);
    try testing.expectEqualStrings("ell", (try get(buf[0..len], "a")).?);
    len = try put(tcap, &buf, len, (try get(buf[0..len], "a")).?[0..1], "k");
    try testing.expectEqualStrings("k", (try get(buf[0..len], "e")).?);
}

test "malformed blobs are errors, never a value" {
    const bad = [_][]const u8{
        &.{0x00}, // wrong tag
        &.{ 0xA0, 1, 'a', 0, 0 },
        &.{ tag, 0, 0, 0 }, // zero-length key
        &.{ tag, 1 }, // truncated after key_len
        &.{ tag, 1, 'a', 1 }, // truncated val_len
        &.{ tag, 1, 'a', 2, 0, 'x' }, // val shorter than val_len
        &.{ tag, 1, 'a', 0, 0, 9 }, // trailing garbage
        &.{ tag, 1, 'a', 1, 0, 'x', 3, 'b' }, // valid entry then garbage
    };
    for (bad) |b| {
        try testing.expectError(error.Malformed, get(b, "a"));
        var buf: [tcap]u8 = undefined;
        @memcpy(buf[0..b.len], b);
        try testing.expectError(error.Malformed, put(tcap, &buf, b.len, "a", "v"));
        try testing.expectError(error.Malformed, remove(&buf, b.len, "a"));
        try testing.expectEqualSlices(u8, b, buf[0..b.len]);
    }
    // A bare tag is a valid empty set.
    try testing.expect((try get(&.{tag}, "a")) == null);
}
