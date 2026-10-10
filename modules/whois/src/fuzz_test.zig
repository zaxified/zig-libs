// SPDX-License-Identifier: MIT

//! Shared plumbing for whois's deterministic fuzz driver (added 2026-10-10).
//!
//! The referral harness body stays in `root.zig` beside its corpus, generic
//! over its source of choices, `fn(comptime S, *S, gpa)`; `testing.fuzz` hands
//! it a `std.testing.Smith` (corpus seeds replay as before). This file holds
//! what it shares with the driver -- reach counters, the input draw -- and
//! the oracles: a referral written in any of the registries' forms parses back
//! to its host and port (also when buried in a reply), a query with CR/LF is
//! refused and one without is exactly one CRLF-terminated line, and the SSRF
//! guard `isSpecialUseHost` refuses every private / loopback / link-local
//! address however it is spelled (dotted, IPv4-mapped, trailing dot).
//!
//! Driver: `WHOIS_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness). Harness names: `whois-referral`, `whois-roundtrip`,
//! `whois-ssrf`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
const whois = @import("root.zig");

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the bend words after the frame are dropped) with 0-3 octets
/// damaged and maybe truncated: random text almost never passes the checksum.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    return damage(src, buf, frame);
}

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated (the
/// driver's `Rng` only; the damage is drawn from `src`).
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels. `mark` also feeds the
/// driver's `REACH` report; `reach` runs `seeds` seeds in the ordinary test
/// binary and fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

// ── oracles ──────────────────────────────────────────────────────────────

const RoundMark = Marker(enum { bare, url, v6, with_port, nested_in_reply, query_ok, query_injection_refused });

const host_set = "abcdefghijklmnopqrstuvwxyz0123456789-.";

fn fuzzRoundtrip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var host_buf: [60]u8 = undefined;
    const host_len = 1 + src.index(host_buf.len);
    for (host_buf[0..host_len]) |*c| c.* = host_set[src.index(host_set.len)];
    const v6 = src.valueRangeAtMost(u8, 0, 5) == 0;
    const host: []const u8 = if (v6) "2001:db8::43" else host_buf[0..host_len];
    const want_port: u16 = if (src.value(bool)) 1 + src.valueRangeAtMost(u16, 0, 65534) else whois.default_port;
    const explicit = want_port != whois.default_port or src.value(bool);
    const url = src.value(bool);

    var line_buf: [160]u8 = undefined;
    var w: std.Io.Writer = .fixed(&line_buf);
    if (src.value(bool)) try w.writeAll("  ");
    if (url) try w.writeAll("whois://");
    if (v6) {
        // Bare v6 has no port; bracketed carries one.
        if (explicit) try w.print("[{s}]:{d}", .{ host, want_port }) else try w.writeAll(host);
    } else if (explicit) try w.print("{s}:{d}", .{ host, want_port }) else try w.writeAll(host);
    if (url and src.value(bool)) try w.writeAll("/");
    const line = w.buffered();
    if (v6) RoundMark.mark(.v6) else if (url) RoundMark.mark(.url) else RoundMark.mark(.bare);
    if (explicit) RoundMark.mark(.with_port);

    const r = whois.parseServerRef(line) orelse return error.GenuineReferralRefused;
    if (!std.mem.eql(u8, r.host, host) or r.port != (if (explicit) want_port else whois.default_port)) return error.ReferralMismatch;

    // The same line inside a multi-line reply, behind noise, under each key.
    var reply_buf: [512]u8 = undefined;
    var rw: std.Io.Writer = .fixed(&reply_buf);
    try rw.writeAll("% comment\r\nrefer-not: nope\r\n");
    const key = whois.referral_keys[src.index(whois.referral_keys.len)];
    try rw.print("{s}: {s}\r\nother: x\r\n", .{ key, std.mem.trim(u8, line, " ") });
    const n = whois.nextServer(rw.buffered()) orelse return error.ReferralLostInReply;
    if (!std.mem.eql(u8, n.host, host)) return error.ReplyReferralMismatch;
    RoundMark.mark(.nested_in_reply);

    // Query formatting.
    var q: [40]u8 = undefined;
    const ql = src.index(q.len + 1);
    for (q[0..ql]) |*c| c.* = " abcxyz019.-:/\r\n"[src.index(17)];
    var out: [64]u8 = undefined;
    const has_crlf = std.mem.indexOfAny(u8, q[0..ql], "\r\n") != null;
    if (whois.formatQuery(&out, q[0..ql])) |f| {
        if (has_crlf) return error.QueryInjectionAccepted;
        if (!std.mem.endsWith(u8, f, "\r\n") or std.mem.indexOfAny(u8, f[0 .. f.len - 2], "\r\n") != null) return error.QueryNotOneLine;
        RoundMark.mark(.query_ok);
    } else |_| {
        if (!has_crlf) return error.CleanQueryRefused;
        RoundMark.mark(.query_injection_refused);
    }
}

const SsrfMark = Marker(enum { v4_private, mapped, dotted, localhost, link_local, v6_local });

/// The SSRF guard refuses every non-routable spelling.
fn fuzzSsrf(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var b: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&b);
    const o2 = src.value(u8);
    const o3 = src.value(u8);
    const o4 = src.value(u8);
    switch (src.valueRangeAtMost(u8, 0, 7)) {
        0 => {
            try w.print("10.{d}.{d}.{d}", .{ o2, o3, o4 });
            SsrfMark.mark(.v4_private);
        },
        1 => try w.print("127.{d}.{d}.{d}", .{ o2, o3, o4 }),
        2 => try w.print("192.168.{d}.{d}", .{ o3, o4 }),
        3 => try w.print("172.{d}.{d}.{d}", .{ 16 + (o2 % 16), o3, o4 }),
        4 => {
            try w.print("169.254.{d}.{d}", .{ o3, o4 });
            SsrfMark.mark(.link_local);
        },
        5 => {
            try w.print("::ffff:10.{d}.{d}.{d}", .{ o2, o3, o4 });
            SsrfMark.mark(.mapped);
        },
        6 => {
            try w.writeAll(if (src.value(bool)) "LocalHost" else "foo.localhost");
            SsrfMark.mark(.localhost);
        },
        else => {
            const v6s = [_][]const u8{ "::1", "fe80::1", "fd00::5", "fc00::1", "::", "ff02::1" };
            try w.writeAll(v6s[src.index(v6s.len)]);
            SsrfMark.mark(.v6_local);
        },
    }
    var dots: usize = 0;
    while (dots < src.valueRangeAtMost(u8, 0, 2)) : (dots += 1) try w.writeByte('.');
    if (dots > 0) SsrfMark.mark(.dotted);
    if (!whois.isSpecialUseHost(w.buffered())) {
        std.debug.print("SSRF guard passed {s}\n", .{w.buffered()});
        return error.SpecialUseHostPassed;
    }
}

test "fuzz driver: WHOIS_FUZZ (roundtrip)" {
    try fuzz_driver.run(fuzzRoundtrip, .{ .prefix = "WHOIS_FUZZ", .name = "whois-roundtrip" });
}
test "fuzz driver: WHOIS_FUZZ (ssrf)" {
    try fuzz_driver.run(fuzzSsrf, .{ .prefix = "WHOIS_FUZZ", .name = "whois-ssrf" });
}
test "fuzz harness: roundtrip and ssrf, 500 seeds, reach every outcome" {
    try RoundMark.reach(fuzzRoundtrip, "whois-roundtrip", 500);
    try SsrfMark.reach(fuzzSsrf, "whois-ssrf", 500);
}

fn roundtripSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzRoundtrip(testkit.fuzz.ScriptSource, &src, testing.allocator);
}
fn ssrfSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzSsrf(testkit.fuzz.ScriptSource, &src, testing.allocator);
}
test "fuzz: roundtrip, exploration" {
    try testing.fuzz({}, roundtripSmith, .{});
}
test "fuzz: ssrf, exploration" {
    try testing.fuzz({}, ssrfSmith, .{});
}

// ── inet_aton oracle (independent of the module's own parser) ────────────

/// The address `a.b.c.d` spelled as 1-4 `inet_aton` parts, each in a random
/// radix (decimal, 0-octal, 0x-hex): the first n-1 parts are single octets, the
/// last holds the remaining bytes as one integer.
fn atonText(src: anytype, w: *std.Io.Writer, o: [4]u8) !void {
    const n = 1 + src.index(4);
    for (0..n) |i| {
        var v: u64 = 0;
        if (i < n - 1) {
            v = o[i];
        } else for (o[i..]) |b| {
            v = (v << 8) | b;
        }
        if (i != 0) try w.writeByte('.');
        switch (src.index(3)) {
            0 => try w.print("{d}", .{v}),
            1 => if (v == 0) try w.writeAll("0") else try w.print("0{o}", .{v}),
            else => try w.print("0x{x}", .{v}),
        }
    }
}

/// Expected verdict for an address, for the classes asserted here; null where
/// the module's policy is not under test.
fn atonExpected(o: [4]u8) ?bool {
    if (o[0] == 10 or o[0] == 127) return true;
    if (o[0] == 172 and o[1] >= 16 and o[1] <= 31) return true;
    if (o[0] == 192 and o[1] == 168) return true;
    if (o[0] == 169 and o[1] == 254) return true;
    if (o[0] >= 224 and o[0] <= 239) return true;
    if (o[0] == 0 and o[1] == 0 and o[2] == 0 and o[3] == 0) return true;
    if (o[0] >= 11 and o[0] <= 99) return false;
    return null;
}

test "fuzz driver: WHOIS_FUZZ (inet_aton)" {
    try fuzz_driver.run(fuzzAton, .{ .prefix = "WHOIS_FUZZ", .name = "whois-ssrf-aton" });
}

const AtonMark = Marker(enum { private, public, invalid });

/// `isSpecialUseHost` against the address an `inet_aton`-style spelling
/// denotes (any radix, any part count), and numeric-shaped invalid forms.
fn fuzzAton(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var o: [4]u8 = undefined;
    src.bytes(&o);
    const firsts = [_]u8{ 10, 127, 172, 192, 169, 224, 0 };
    if (src.value(bool)) o[0] = firsts[src.index(firsts.len)];
    if (o[0] == 172) o[1] = 16 + (o[1] % 16);
    if (o[0] == 192 and src.value(bool)) o[1] = 168;
    if (o[0] == 169) o[1] = 254;
    if (o[0] == 0) o = .{ 0, 0, 0, 0 };
    var b: [96]u8 = undefined;
    var w: std.Io.Writer = .fixed(&b);
    if (src.valueRangeAtMost(u8, 0, 7) == 0) {
        // Invalid: a part past its width.
        try w.print("{d}.{d}", .{ 256 + src.valueRangeAtMost(u16, 0, 1000), o[3] });
        if (!whois.isSpecialUseHost(w.buffered())) return error.InvalidNumericFormPassed;
        AtonMark.mark(.invalid);
        return;
    }
    try atonText(src, &w, o);
    // One trailing dot is the same address; two are an invalid form.
    switch (src.index(4)) {
        0 => try w.writeByte('.'),
        1 => {
            try w.writeAll("..");
            if (!whois.isSpecialUseHost(w.buffered())) return error.DoubleTrailingDotPassed;
            AtonMark.mark(.invalid);
            return;
        },
        else => {},
    }
    const text = w.buffered();
    const want = atonExpected(o) orelse return;
    if (whois.isSpecialUseHost(text) != want) {
        std.debug.print("inet_aton '{s}' ({d}.{d}.{d}.{d}) classified {}, want {}\n", .{ text, o[0], o[1], o[2], o[3], !want, want });
        return error.AtonClassificationWrong;
    }
    if (want) AtonMark.mark(.private) else AtonMark.mark(.public);
}

test "fuzz harness: inet_aton, 500 seeds, reaches every outcome" {
    try AtonMark.reach(fuzzAton, "whois-ssrf-aton", 500);
}
