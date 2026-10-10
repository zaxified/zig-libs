// SPDX-License-Identifier: MIT

//! Shared plumbing for rdap's deterministic fuzz driver (added 2026-10-10).
//!
//! The two parser harness bodies stay in `root.zig` beside their corpora,
//! generic over their source of choices, `fn(comptime S, *S, gpa)`;
//! `testing.fuzz` hands them a `std.testing.Smith` (corpus seeds replay as
//! before). This file holds what they share with the driver -- reach counters
//! and the input draw -- and the oracles: a response / bootstrap file built
//! from known values maps back to them, `buildUrl` percent-encoding decodes to
//! the query value, and the destination gate `checkDestination` refuses every
//! private / loopback / link-local / documentation destination however the URL
//! spells it (userinfo, port, bracketed v6, IPv4-mapped, trailing dot,
//! upper case), and plaintext http.
//!
//! Driver: `RDAP_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness). Harness names: `rdap-response`, `rdap-bootstrap`,
//! `rdap-roundtrip`, `rdap-destination`.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
const rdap = @import("root.zig");

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

const RoundMark = Marker(enum { response, bootstrap, url, genuine_accepted });

const text_set = "abcXYZ 019.-_:/\"\\\t\xc3\xa9";

fn fillText(src: anytype, buf: []u8) []const u8 {
    // Octets drawn so that multi-byte sequences stay valid: the two-octet
    // e-acute is appended whole or not at all.
    var n: usize = 0;
    const want = src.index(buf.len + 1);
    while (n < want) {
        if (src.valueRangeAtMost(u8, 0, 9) == 0 and n + 2 <= buf.len) {
            buf[n] = 0xc3;
            buf[n + 1] = 0xa9;
            n += 2;
        } else {
            const c = "abcXYZ 019.-_:/\"\\\t"[src.index(17)];
            buf[n] = c;
            n += 1;
        }
    }
    return buf[0..n];
}

/// A response built from known values maps back to them; a bootstrap file
/// built from known services resolves each TLD to its URLs; `buildUrl`'s
/// percent-encoding decodes back to the value.
fn fuzzRoundtrip(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    // ── response
    var handle_buf: [40]u8 = undefined;
    var ldh_buf: [40]u8 = undefined;
    var st_buf: [3][20]u8 = undefined;
    const handle = fillText(src, &handle_buf);
    const ldh = fillText(src, &ldh_buf);
    const n_status = src.index(4);
    var statuses: [3][]const u8 = undefined;
    for (statuses[0..@min(n_status, 3)], 0..) |*s, i| s.* = fillText(src, &st_buf[i]);
    const ns = @min(n_status, 3);
    var doc: std.Io.Writer.Allocating = .init(gpa);
    defer doc.deinit();
    const w = &doc.writer;
    try w.writeAll("{\"objectClassName\":\"domain\",\"handle\":");
    try std.json.Stringify.encodeJsonString(handle, .{}, w);
    try w.writeAll(",\"ldhName\":");
    try std.json.Stringify.encodeJsonString(ldh, .{}, w);
    try w.writeAll(",\"status\":[");
    for (statuses[0..ns], 0..) |s, i| {
        if (i != 0) try w.writeAll(",");
        try std.json.Stringify.encodeJsonString(s, .{}, w);
    }
    try w.writeAll("]}");
    {
        var p = rdap.parseResponse(gpa, doc.written()) catch return error.GenuineResponseRefused;
        defer p.deinit();
        const o = switch (p.document) {
            .object => |o| o,
            .rdap_error => return error.ObjectBecameError,
        };
        if (o.object_class != .domain) return error.ClassMismatch;
        if (!std.mem.eql(u8, o.handle orelse return error.HandleLost, handle)) return error.HandleMismatch;
        if (!std.mem.eql(u8, o.ldh_name orelse return error.LdhLost, ldh)) return error.LdhMismatch;
        if (o.status.len != ns) return error.StatusCountMismatch;
        for (o.status, statuses[0..ns]) |g, want| if (!std.mem.eql(u8, g, want)) return error.StatusMismatch;
        RoundMark.mark(.response);
    }

    // ── bootstrap: distinct TLDs t<i>x, 1-3 services, 1-2 URLs each
    var bdoc: std.Io.Writer.Allocating = .init(gpa);
    defer bdoc.deinit();
    const bw = &bdoc.writer;
    const n_svc = 1 + src.index(3);
    try bw.writeAll("{\"version\":\"1.0\",\"services\":[");
    var url_counts: [3]usize = undefined;
    for (0..n_svc) |i| {
        if (i != 0) try bw.writeAll(",");
        url_counts[i] = 1 + src.index(2);
        try bw.print("[[\"t{d}x\"],[", .{i});
        for (0..url_counts[i]) |u| {
            if (u != 0) try bw.writeAll(",");
            try bw.print("\"https://rdap{d}-{d}.example/\"", .{ i, u });
        }
        try bw.writeAll("]]");
    }
    try bw.writeAll("]}");
    {
        var b = rdap.parseBootstrap(gpa, bdoc.written()) catch return error.GenuineBootstrapRefused;
        defer b.deinit();
        if (b.services.len != n_svc) return error.ServiceCountMismatch;
        for (0..n_svc) |i| {
            var dom: [32]u8 = undefined;
            const d = try std.fmt.bufPrint(&dom, "www.t{d}x", .{i});
            const urls = b.lookupDomain(d) orelse return error.TldNotResolved;
            if (urls.len != url_counts[i]) return error.UrlCountMismatch;
        }
        if (b.lookupDomain("www.t9x") != null) return error.UnknownTldResolved;
        RoundMark.mark(.bootstrap);
    }

    // ── URL percent-encoding
    var vbuf: [24]u8 = undefined;
    const value = fillText(src, &vbuf);
    if (value.len != 0) {
        var ubuf: [200]u8 = undefined;
        const url = rdap.buildUrl(&ubuf, "https://rdap.example/v1", .domain, value) catch return error.BuildUrlRefused;
        const prefix = "https://rdap.example/v1/domain/";
        if (!std.mem.startsWith(u8, url, prefix)) return error.UrlPrefixMismatch;
        var dec: [24]u8 = undefined;
        var n: usize = 0;
        var i: usize = prefix.len;
        while (i < url.len) : (i += 1) {
            if (url[i] == '%') {
                dec[n] = try std.fmt.parseInt(u8, url[i + 1 .. i + 3], 16);
                i += 2;
            } else {
                // A literal octet must be unreserved or ':'.
                if (!(std.ascii.isAlphanumeric(url[i]) or std.mem.indexOfScalar(u8, "-._~:", url[i]) != null)) return error.ReservedOctetUnencoded;
                dec[n] = url[i];
            }
            n += 1;
        }
        if (!std.mem.eql(u8, dec[0..n], value)) return error.UrlRoundtripMismatch;
        RoundMark.mark(.url);
    }
    RoundMark.mark(.genuine_accepted);
}

const DestMark = Marker(enum { private, mapped, userinfo, port, bracketed, upper, plain_http, public_ok });

/// `checkDestination` refuses every non-routable destination (and plaintext
/// http) however the URL spells it, and admits an https public one.
fn fuzzDestination(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var b: [160]u8 = undefined;
    var w: std.Io.Writer = .fixed(&b);
    const o2 = src.value(u8);
    const o3 = src.value(u8);
    const o4 = src.value(u8);
    const upper = src.value(bool);
    try w.writeAll(if (upper) "HTTPS://" else "https://");
    if (upper) DestMark.mark(.upper);
    const userinfo = src.valueRangeAtMost(u8, 0, 3) == 0;
    if (userinfo) {
        try w.writeAll("user:pw@");
        DestMark.mark(.userinfo);
    }
    var host_buf: [64]u8 = undefined;
    var hw: std.Io.Writer = .fixed(&host_buf);
    var bracket = false;
    var public = false;
    switch (src.valueRangeAtMost(u8, 0, 8)) {
        0 => try hw.print("10.{d}.{d}.{d}", .{ o2, o3, o4 }),
        1 => try hw.print("127.{d}.{d}.{d}", .{ o2, o3, o4 }),
        2 => try hw.print("192.168.{d}.{d}", .{ o3, o4 }),
        3 => try hw.print("172.{d}.{d}.{d}", .{ 16 + (o2 % 16), o3, o4 }),
        4 => try hw.print("169.254.{d}.{d}", .{ o3, o4 }),
        5 => {
            bracket = true;
            DestMark.mark(.mapped);
            try hw.print("::ffff:10.{d}.{d}.{d}", .{ o2, o3, o4 });
        },
        6 => try hw.writeAll(if (src.value(bool)) "LocalHost" else "svc.localhost"),
        7 => {
            bracket = true;
            const v6s = [_][]const u8{ "::1", "fe80::1", "fd00::5", "fc00::1", "::", "2001:db8::1" };
            try hw.writeAll(v6s[src.index(v6s.len)]);
        },
        else => {
            public = true;
            try hw.print("{d}.{d}.{d}.{d}", .{ 11 + (o2 % 80), o3, o4, 1 + (o4 % 200) });
        },
    }
    if (!public) DestMark.mark(.private);
    const dots: usize = if (public or bracket) 0 else src.index(3);
    if (bracket) {
        try w.print("[{s}]", .{hw.buffered()});
        DestMark.mark(.bracketed);
    } else {
        try w.writeAll(hw.buffered());
        for (0..dots) |_| try w.writeByte('.');
    }
    if (src.value(bool)) {
        try w.print(":{d}", .{1 + src.valueRangeAtMost(u16, 0, 65534)});
        DestMark.mark(.port);
    }
    try w.writeAll("/rdap/x");
    const url = w.buffered();
    // `http.Url.parse` refuses userinfo outright, so any such URL is refused.
    if (public and !userinfo) {
        rdap.checkDestination(url, .{}) catch |e| {
            std.debug.print("public destination refused: {s}\n", .{url});
            return e;
        };
        DestMark.mark(.public_ok);
        return;
    }
    if (rdap.checkDestination(url, .{})) |_| {
        std.debug.print("destination gate passed {s}\n", .{url});
        return error.SpecialUseDestinationPassed;
    } else |_| {}
    // And plaintext http is refused under the default policy, whatever the host.
    var hb: [200]u8 = undefined;
    const http_url = try std.fmt.bufPrint(&hb, "http{s}", .{url[5..]});
    if (rdap.checkDestination(http_url, .{})) |_| return error.PlaintextAccepted else |_| DestMark.mark(.plain_http);
}

test "fuzz driver: RDAP_FUZZ (roundtrip)" {
    try fuzz_driver.run(fuzzRoundtrip, .{ .prefix = "RDAP_FUZZ", .name = "rdap-roundtrip" });
}
test "fuzz driver: RDAP_FUZZ (destination)" {
    try fuzz_driver.run(fuzzDestination, .{ .prefix = "RDAP_FUZZ", .name = "rdap-destination" });
}
test "fuzz harness: roundtrip and destination, 500 seeds, reach every outcome" {
    try RoundMark.reach(fuzzRoundtrip, "rdap-roundtrip", 500);
    try DestMark.reach(fuzzDestination, "rdap-destination", 500);
}

fn roundtripSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzRoundtrip(testkit.fuzz.ScriptSource, &src, testing.allocator);
}
fn destinationSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [1024]u8 = undefined;
    var src: testkit.fuzz.ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzDestination(testkit.fuzz.ScriptSource, &src, testing.allocator);
}
test "fuzz: roundtrip, exploration" {
    try testing.fuzz({}, roundtripSmith, .{});
}
test "fuzz: destination, exploration" {
    try testing.fuzz({}, destinationSmith, .{});
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

test "fuzz driver: RDAP_FUZZ (inet_aton)" {
    try fuzz_driver.run(fuzzAton, .{ .prefix = "RDAP_FUZZ", .name = "rdap-destination-aton" });
}

const AtonMark = Marker(enum { private, public, invalid });

/// `checkDestination` against the address an `inet_aton`-style spelling
/// denotes (any radix, any part count), and numeric-shaped invalid forms.
fn blocked(host: []const u8) bool {
    var ub: [128]u8 = undefined;
    const url = std.fmt.bufPrint(&ub, "https://{s}/rdap/x", .{host}) catch return true;
    rdap.checkDestination(url, .{}) catch return true;
    return false;
}

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
        if (!blocked(w.buffered())) return error.InvalidNumericFormPassed;
        AtonMark.mark(.invalid);
        return;
    }
    try atonText(src, &w, o);
    // One trailing dot is the same address; two are an invalid form.
    switch (src.index(4)) {
        0 => try w.writeByte('.'),
        1 => {
            try w.writeAll("..");
            if (!blocked(w.buffered())) return error.DoubleTrailingDotPassed;
            AtonMark.mark(.invalid);
            return;
        },
        else => {},
    }
    const text = w.buffered();
    const want = atonExpected(o) orelse return;
    if (blocked(text) != want) {
        std.debug.print("inet_aton '{s}' ({d}.{d}.{d}.{d}) classified {}, want {}\n", .{ text, o[0], o[1], o[2], o[3], !want, want });
        return error.AtonClassificationWrong;
    }
    if (want) AtonMark.mark(.private) else AtonMark.mark(.public);
}

test "fuzz harness: inet_aton, 500 seeds, reaches every outcome" {
    try AtonMark.reach(fuzzAton, "rdap-destination-aton", 500);
}
