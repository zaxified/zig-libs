// SPDX-License-Identifier: MIT

//! The x/crypto amd64 engine (`xcrypto_amd64.s`) against the module's own Zig wide
//! path, which the rest of the suite anchors to std, Wycheproof and libsodium:
//! every length 0..1100 and the group seams to 20 KiB, several AD lengths, in place
//! and apart, a wrong tag (output zeroed), and guard pages right after the input
//! and the output, which catch a read or write past the message — the two tails
//! `tools/xcrypto_asm.py` rewrote (Go relied on the tag sitting there). Skipped
//! where the build has no engine.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;
const cp = @import("root.zig");
const A = cp.ChaCha20Poly1305;

fn fill(buf: []u8, seed: u64) void {
    var r = std.Random.DefaultPrng.init(seed);
    r.random().bytes(buf);
}

/// Seal and open through the engine and through the Zig path; both must agree.
fn both(m: []const u8, ad: []const u8, npub: [12]u8, k: [32]u8, c_x: []u8, c_z: []u8) !void {
    var tag_x: [16]u8 = undefined;
    var tag_z: [16]u8 = undefined;
    A.encrypt(c_x, &tag_x, m, ad, npub, k);
    cp.force_no_xcrypto = true;
    A.encrypt(c_z, &tag_z, m, ad, npub, k);
    cp.force_no_xcrypto = false;
    try testing.expectEqualSlices(u8, c_z, c_x);
    try testing.expectEqualSlices(u8, &tag_z, &tag_x);
}

test "xcrypto: the engine is in this build where the target has AVX2, BMI2, SSSE3 on ELF" {
    if (!cp.xcrypto_engine) return error.SkipZigTest;
    try testing.expect(builtin.cpu.arch == .x86_64);
}

test "xcrypto: seal and open agree with the Zig wide path, every length 0..1100 and the seams" {
    if (!cp.xcrypto_engine) return error.SkipZigTest;
    const gpa = testing.allocator;
    const max = 20 * 1024 + 70;
    const m = try gpa.alloc(u8, max);
    defer gpa.free(m);
    const c_x = try gpa.alloc(u8, max);
    defer gpa.free(c_x);
    const c_z = try gpa.alloc(u8, max);
    defer gpa.free(c_z);
    const back = try gpa.alloc(u8, max);
    defer gpa.free(back);
    var ad_buf: [300]u8 = undefined;
    fill(&ad_buf, 7);
    fill(m, 1);
    var k: [32]u8 = undefined;
    fill(&k, 2);
    var npub: [12]u8 = undefined;
    fill(&npub, 3);

    var lens: std.ArrayList(usize) = .empty;
    defer lens.deinit(gpa);
    for (0..1101) |n| try lens.append(gpa, n);
    for ([_]usize{ 1420, 1424, 1500, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 20 * 1024 + 69 }) |n| try lens.append(gpa, n);

    cp.force_xcrypto_all = true;
    defer cp.force_xcrypto_all = false;
    for (lens.items) |n| {
        for ([_]usize{ 0, 1, 13, 16, 17, 193, 300 }) |al| {
            // Only lengths the wide path takes reach the engine; the others run the
            // short engine twice, which is harmless.
            const ad = ad_buf[0..al];
            try both(m[0..n], ad, npub, k, c_x[0..n], c_z[0..n]);
            var tag: [16]u8 = undefined;
            A.encrypt(c_x[0..n], &tag, m[0..n], ad, npub, k);
            try A.decrypt(back[0..n], c_x[0..n], tag, ad, npub, k);
            try testing.expectEqualSlices(u8, m[0..n], back[0..n]);
            // In place.
            @memcpy(back[0..n], c_x[0..n]);
            try A.decrypt(back[0..n], back[0..n], tag, ad, npub, k);
            try testing.expectEqualSlices(u8, m[0..n], back[0..n]);
            // A wrong tag: refused, and the output zeroed.
            var bad = tag;
            bad[n % 16] ^= 0x40;
            @memset(back[0..n], 0xaa);
            try testing.expectError(error.AuthenticationFailed, A.decrypt(back[0..n], c_x[0..n], bad, ad, npub, k));
            for (back[0..n]) |b| try testing.expectEqual(@as(u8, 0), b);
            // A flipped ciphertext byte: refused.
            if (n > 0) {
                c_x[n / 2] ^= 1;
                try testing.expectError(error.AuthenticationFailed, A.decrypt(back[0..n], c_x[0..n], tag, ad, npub, k));
                c_x[n / 2] ^= 1;
            }
        }
    }
}

test "xcrypto: routing takes exactly the calls the engine can run (aliasing, length bound, counter wrap)" {
    const takes = cp.test_hooks.takes;
    var buf: [8300]u8 = undefined;
    // In place, and apart on either side (adjacent counts as apart).
    try testing.expect(takes(buf[0..300], buf[0..300], buf[1000..1013]));
    try testing.expect(takes(buf[0..300], buf[300..600], buf[1000..1013]));
    try testing.expect(takes(buf[300..600], buf[0..300], buf[1000..1013]));
    // One byte of overlap, either way round, and a heavier one: the Zig path.
    try testing.expect(!takes(buf[0..300], buf[299..599], buf[1000..1013]));
    try testing.expect(!takes(buf[299..599], buf[0..300], buf[1000..1013]));
    try testing.expect(!takes(buf[0..300], buf[5..305], buf[1000..1013]));
    try testing.expect(!takes(buf[5..305], buf[0..300], buf[1000..1013]));
    // The output must be apart from the AD; the AD may overlap the input.
    try testing.expect(!takes(buf[0..300], buf[0..300], buf[100..113]));
    try testing.expect(!takes(buf[0..300], buf[0..300], buf[299..312]));
    try testing.expect(takes(buf[0..300], buf[0..300], buf[300..313]));
    try testing.expect(takes(buf[0..300], buf[0..300], buf[100..100]));
    try testing.expect(takes(buf[1000..1300], buf[0..300], buf[10..23]));
    // The length bound is inclusive.
    try testing.expect(takes(buf[0..cp.xcrypto_max], buf[0..cp.xcrypto_max], buf[5000..5013]));
    try testing.expect(!takes(buf[0 .. cp.xcrypto_max + 1], buf[0 .. cp.xcrypto_max + 1], buf[5000..5013]));
    // Past the 32-bit block counter (from counter 1) the engine is never taken, even
    // with the length bound lifted; the slices are fabricated, `takes` only compares
    // addresses and lengths.
    cp.force_xcrypto_all = true;
    defer cp.force_xcrypto_all = false;
    const last: usize = 64 * ((1 << 32) - 1);
    const base: usize = 4096;
    const no_ad = buf[0..0];
    const o_ok = @as([*]u8, @ptrFromInt(base))[0..last];
    const i_ok = @as([*]const u8, @ptrFromInt(base))[0..last];
    try testing.expect(takes(o_ok, i_ok, no_ad));
    const o_wrap = @as([*]u8, @ptrFromInt(base))[0 .. last + 1];
    const i_wrap = @as([*]const u8, @ptrFromInt(base))[0 .. last + 1];
    try testing.expect(!takes(o_wrap, i_wrap, no_ad));
}

test "xcrypto: a seal or open the routing accepts reaches the engine, any other does not" {
    if (!cp.xcrypto_engine) return error.SkipZigTest;
    const hooks = cp.test_hooks;
    var m: [cp.xcrypto_max + 1]u8 = undefined;
    fill(&m, 21);
    var c: [cp.xcrypto_max + 1]u8 = undefined;
    var k: [32]u8 = undefined;
    fill(&k, 22);
    const npub: [12]u8 = @splat(6);
    var ad: [13]u8 = undefined;
    fill(&ad, 23);
    var tag: [16]u8 = undefined;

    var calls = hooks.xcrypto_calls;
    // Wide path, in range: both directions reach the engine, apart and in place.
    A.encrypt(c[0..300], &tag, m[0..300], &ad, npub, k);
    try testing.expectEqual(calls + 1, hooks.xcrypto_calls);
    calls = hooks.xcrypto_calls;
    var back: [300]u8 = undefined;
    try A.decrypt(&back, c[0..300], tag, &ad, npub, k);
    try testing.expectEqual(calls + 1, hooks.xcrypto_calls);
    try testing.expectEqualSlices(u8, m[0..300], &back);
    calls = hooks.xcrypto_calls;
    @memcpy(back[0..300], m[0..300]);
    A.encrypt(&back, &tag, &back, &ad, npub, k);
    try testing.expectEqual(calls + 1, hooks.xcrypto_calls);
    // The last length the engine takes, and the first it does not.
    calls = hooks.xcrypto_calls;
    A.encrypt(c[0..cp.xcrypto_max], &tag, m[0..cp.xcrypto_max], &ad, npub, k);
    try testing.expectEqual(calls + 1, hooks.xcrypto_calls);
    calls = hooks.xcrypto_calls;
    A.encrypt(&c, &tag, &m, &ad, npub, k);
    try testing.expectEqual(calls, hooks.xcrypto_calls);
    try A.decrypt(&m, &c, tag, &ad, npub, k);
    try testing.expectEqual(calls, hooks.xcrypto_calls);
    // Short engine (<= 192 B of message plus AD) and the switched-off engine.
    A.encrypt(c[0..100], &tag, m[0..100], &ad, npub, k);
    try testing.expectEqual(calls, hooks.xcrypto_calls);
    cp.force_no_xcrypto = true;
    defer cp.force_no_xcrypto = false;
    A.encrypt(c[0..300], &tag, m[0..300], &ad, npub, k);
    try testing.expectEqual(calls, hooks.xcrypto_calls);
}

/// Two pages, the second PROT_NONE: `buf[4096 - n ..][0..n]` ends at the guard.
const Guarded = struct {
    pages: []align(4096) u8,
    fn init() !Guarded {
        const p = try std.heap.page_allocator.alignedAlloc(u8, .fromByteUnits(4096), 2 * 4096); // global-alloc-ok: a guard page needs whole OS pages; test helper only
        try testing.expectEqual(@as(usize, 0), std.os.linux.mprotect(p.ptr + 4096, 4096, .{}));
        return .{ .pages = p };
    }
    fn end(g: Guarded, n: usize) []u8 {
        return g.pages[4096 - n .. 4096];
    }
    fn deinit(g: Guarded) void {
        _ = std.os.linux.mprotect(g.pages.ptr + 4096, 4096, .{ .READ = true, .WRITE = true });
        std.heap.page_allocator.free(g.pages); // global-alloc-ok: frees the pages above
    }
};

test "xcrypto: no byte read or written past the message (guard pages after input and output)" {
    if (!cp.xcrypto_engine or builtin.os.tag != .linux) return error.SkipZigTest;
    const gin = try Guarded.init();
    defer gin.deinit();
    const gout = try Guarded.init();
    defer gout.deinit();
    var k: [32]u8 = undefined;
    fill(&k, 11);
    const npub: [12]u8 = @splat(5);
    var ad: [40]u8 = undefined;
    fill(&ad, 12);
    cp.force_xcrypto_all = true;
    defer cp.force_xcrypto_all = false;
    var n: usize = 0;
    while (n <= 2100) : (n += 1) {
        for ([_]usize{ 0, 13, 40 }) |al| {
            const m = gin.end(n);
            fill(m, n);
            const c = gout.end(n);
            var tag: [16]u8 = undefined;
            A.encrypt(c, &tag, m, ad[0..al], npub, k);
            // Open with the ciphertext ending at a guard and the plaintext ending at one.
            const cin = gin.end(n);
            @memcpy(cin, c);
            const mout = gout.end(n);
            try A.decrypt(mout, cin, tag, ad[0..al], npub, k);
            var want: [2100]u8 = undefined;
            fill(want[0..n], n);
            try testing.expectEqualSlices(u8, want[0..n], mout);
        }
    }
}
