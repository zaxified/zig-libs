// SPDX-License-Identifier: MIT
//! Hostile kernel-reply probe: drives the SHIPPED module with the malformed
//! payload shapes its own suite never produces.
//!
//! Run it (from the repository root):
//!
//!     scripts/capped zig test --cache-dir .zig-cache \
//!       --dep tc -Mroot=modules/tc/tools/probe_hostile.zig \
//!       --dep netlink --dep testkit -Mtc=modules/tc/src/root.zig \
//!       -Mnetlink=modules/netlink/src/root.zig \
//!       -Mtestkit=modules/testkit/src/root.zig
//!
//! Every input here is one the 2026-09-04 mutation battery (M11..M17) showed no
//! test exercises: a length gate standing between kernel bytes and a fixed-size
//! read, where removing the gate left the suite green. These are not mutations —
//! the module is unmodified — they are the inputs that make those gates matter.
//!
//! ⚠ It is a `zig test` over the real module graph on purpose, not a copy of
//! the parsers next to the probe: `--dep netlink --dep testkit` is what
//! `build.zig` declares for this module, so the dependency set stays correct by
//! construction rather than by a hand-kept list that rots. Measured 2026-09-16
//! against the live module: **11/11 pass, exit 0.**
const std = @import("std");
const tc = @import("tc");
const testing = std.testing;

var buf: [8192]u8 = undefined;

fn attr(out: []u8, atype: u16, data: []const u8) usize {
    const total = 4 + data.len;
    std.mem.writeInt(u16, out[0..2], @intCast(total), .little);
    std.mem.writeInt(u16, out[2..4], atype, .little);
    @memcpy(out[4..][0..data.len], data);
    const padded = std.mem.alignForward(usize, total, 4);
    @memset(out[total..padded], 0);
    return padded;
}

// ── TCA_ACT_KIND longer than kind_max=16 (action.zig copyKind) ──────────────

test "HOSTILE: TCA_ACT_KIND of 17 bytes is rejected, not written past kind_buf" {
    var n: usize = 0;
    n += attr(buf[n..], 1, "0123456789abcdefg"); // TCA_ACT_KIND, 17 bytes
    try testing.expectError(error.BadLength, tc.action.parseAction(1, buf[0..n]));
}

test "HOSTILE: TCA_ACT_KIND of 4000 bytes is rejected" {
    const long = [_]u8{'a'} ** 4000;
    var n: usize = 0;
    n += attr(buf[n..], 1, &long);
    try testing.expectError(error.BadLength, tc.action.parseAction(1, buf[0..n]));
}

test "HOSTILE: exactly 16 bytes of TCA_ACT_KIND is still accepted" {
    var n: usize = 0;
    n += attr(buf[n..], 1, "0123456789abcdef");
    const a = try tc.action.parseAction(1, buf[0..n]);
    try testing.expectEqualStrings("0123456789abcdef", a.kind());
}

// ── TCA_ACT_COOKIE longer than TC_COOKIE_MAX_SIZE=16 ────────────────────────

test "HOSTILE: a 4000-byte TCA_ACT_COOKIE truncates to 16, no overflow" {
    const long = [_]u8{0xAB} ** 4000;
    var n: usize = 0;
    n += attr(buf[n..], 1, "gact");
    n += attr(buf[n..], 6, &long); // TCA_ACT_COOKIE
    const a = try tc.action.parseAction(1, buf[0..n]);
    try testing.expectEqual(@as(u8, 16), a.cookie_len);
    for (a.cookie()) |b| try testing.expectEqual(@as(u8, 0xAB), b);
}

// ── u32 selector claiming more keys than U32Wire.keys can hold ──────────────

test "HOSTILE: u32 SEL with 40 real keys fills 8 and reports the kernel's nkeys" {
    var sel: [16 + 40 * 16]u8 = @splat(0);
    sel[2] = 40; // tc_u32_sel.nkeys
    for (0..40) |i| sel[16 + i * 16] = @intCast(i);
    var n: usize = 0;
    n += attr(buf[n..], 5, &sel); // TCA_U32_SEL
    const w = try tc.filter.parseU32Options(buf[0..n]);
    try testing.expectEqual(@as(u8, 40), w.nkeys);
    try testing.expectEqual(@as(u8, 8), w.keys_len);
}

test "HOSTILE: u32 SEL declaring nkeys=255 with an empty key area decodes 0 keys" {
    var sel: [16]u8 = @splat(0);
    sel[2] = 255;
    var n: usize = 0;
    n += attr(buf[n..], 5, &sel);
    const w = try tc.filter.parseU32Options(buf[0..n]);
    try testing.expectEqual(@as(u8, 255), w.nkeys);
    try testing.expectEqual(@as(u8, 0), w.keys_len);
}

test "HOSTILE: u32 SEL one byte short of tc_u32_sel_len is BadLength" {
    const sel: [15]u8 = @splat(0);
    var n: usize = 0;
    n += attr(buf[n..], 5, &sel);
    try testing.expectError(error.BadLength, tc.filter.parseU32Options(buf[0..n]));
}

// ── truncated fixed structs on the class / action paths ─────────────────────

test "HOSTILE: TCA_HTB_PARMS one byte short is BadLength" {
    const parms: [43]u8 = @splat(0); // tc_htb_opt is 44
    var n: usize = 0;
    n += attr(buf[n..], 1, &parms); // TCA_HTB_PARMS
    try testing.expectError(error.BadLength, tc.qdisc.parseHtbClassOptions(buf[0..n]));
}

test "HOSTILE: TCA_POLICE_TBF one byte short is BadLength" {
    const tbf: [55]u8 = @splat(0); // tc_police is 56
    var opts: usize = 0;
    var obuf: [256]u8 = undefined;
    opts += attr(obuf[opts..], 1, &tbf); // TCA_POLICE_TBF
    var n: usize = 0;
    n += attr(buf[n..], 1, "police");
    n += attr(buf[n..], 2, obuf[0..opts]); // TCA_ACT_OPTIONS
    try testing.expectError(error.BadLength, tc.action.parseAction(1, buf[0..n]));
}

test "HOSTILE: TCA_MIRRED_PARMS one byte short is BadLength" {
    const parms: [27]u8 = @splat(0); // tc_mirred is 28
    var obuf: [256]u8 = undefined;
    const opts = attr(obuf[0..], 2, &parms); // TCA_MIRRED_PARMS
    var n: usize = 0;
    n += attr(buf[n..], 1, "mirred");
    n += attr(buf[n..], 2, obuf[0..opts]);
    try testing.expectError(error.BadLength, tc.action.parseAction(1, buf[0..n]));
}

// ── nesting depth: an action list whose entries are themselves nests ────────

test "HOSTILE: a 32-deep self-similar nest does not recurse without bound" {
    // TCA_ACT_TAB payload built as ordinal-1 nests inside each other. The
    // module's decode depth is fixed (list -> ordinal -> options), so this
    // must terminate regardless of how deep the bytes go.
    var inner: [4096]u8 = @splat(0);
    var len: usize = 0;
    for (0..32) |_| {
        var next: [4096]u8 = undefined;
        const w = attr(next[0..], 1, inner[0..len]);
        @memcpy(inner[0..w], next[0..w]);
        len = w;
    }
    var acts = tc.action.actionsOf(inner[0..len]) catch return;
    var count: usize = 0;
    while (acts.?.next() catch return) |_| {
        count += 1;
        if (count > 1000) return error.Unbounded;
    }
}
