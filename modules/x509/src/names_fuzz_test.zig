// SPDX-License-Identifier: MIT
//! Fuzz harness `x509-names` (driver `X509_FUZZ`, see `fuzz_test.zig`):
//! `names.matchDomain`, `hostname.matchDnsName`, `names.parseIp4/parseIp6`
//! and `names.GeneralNameIterator` against naive reference implementations
//! written here in a different shape (label lists instead of suffix
//! arithmetic, print-and-reparse for addresses).

const std = @import("std");
const names = @import("names.zig");
const hostname = @import("hostname.zig");
const fz = @import("fuzz_test.zig");

const Mark = fz.Marker(enum {
    dns_inside,
    dns_outside,
    dns_unsupported,
    dns_leading_dot,
    dns_empty_constraint,
    wild_match,
    wild_refused,
    host_exact,
    ip4_parsed,
    ip6_parsed,
    ip6_compressed,
    gn_entries,
});

test "fuzz driver: X509_FUZZ (names)" {
    try fz.fuzz_driver.run(harness, .{ .prefix = "X509_FUZZ", .name = "x509-names", .scale = 8 });
}

test "fuzz harness: names, 400 seeds, reaches every outcome" {
    try Mark.reach(harness, "x509-names", 400);
}

const alphabet = "ab.*-_1@:/[]A0f";
const labels_pool = [_][]const u8{ "a", "b", "ex", "EX", "*", "com", "x-y", "f*", "", "1", "_a" };

/// A random domain-like string: mostly labels from the pool joined by dots
/// (so matches actually happen), sometimes raw bytes.
fn domainish(comptime S: type, src: *S, buf: []u8) []const u8 {
    if (src.valueRangeAtMost(u8, 0, 4) == 0) {
        const n = src.valueRangeAtMost(u8, 0, 12);
        for (buf[0..n]) |*b| b.* = alphabet[src.index(alphabet.len)];
        return buf[0..n];
    }
    var n: usize = 0;
    if (src.valueRangeAtMost(u8, 0, 5) == 0) {
        buf[0] = '.';
        n = 1;
    }
    const k = src.valueRangeAtMost(u8, 1, 4);
    for (0..k) |i| {
        if (i != 0) {
            buf[n] = '.';
            n += 1;
        }
        const l = labels_pool[src.index(labels_pool.len)];
        @memcpy(buf[n..][0..l.len], l);
        n += l.len;
    }
    if (src.valueRangeAtMost(u8, 0, 7) == 0) {
        buf[n] = '.';
        n += 1;
    }
    return buf[0..n];
}

fn harness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var b1: [64]u8 = undefined;
    var b2: [64]u8 = undefined;

    // matchDomain vs label-list reference. Build the name as a suffix
    // extension of the constraint half the time, so `inside` is reached.
    {
        const c = domainish(S, src, &b2);
        var name: []const u8 = undefined;
        if (src.value(bool) and c.len + 4 <= b1.len) {
            const pre = labels_pool[src.index(labels_pool.len)];
            @memcpy(b1[0..pre.len], pre);
            var n = pre.len;
            const cc = if (c.len != 0 and c[0] == '.') c[1..] else c;
            if (src.value(bool)) {
                b1[n] = '.';
                n += 1;
                @memcpy(b1[n..][0..cc.len], cc);
                n += cc.len;
                name = b1[0..n];
            } else {
                @memcpy(b1[0..cc.len], cc);
                name = b1[0..cc.len];
            }
        } else name = domainish(S, src, &b1);
        const got = names.matchDomain(name, c);
        const want = refMatchDomain(name, c);
        if (got != want) {
            std.debug.print("matchDomain(\"{s}\", \"{s}\") = {t}, reference {t}\n", .{ name, c, got, want });
            return error.MatchDomainDisagrees;
        }
        switch (got) {
            .inside => Mark.mark(.dns_inside),
            .outside => Mark.mark(.dns_outside),
            .unsupported => Mark.mark(.dns_unsupported),
        }
        if (got != .unsupported and c.len != 0 and c[0] == '.') Mark.mark(.dns_leading_dot);
        if (c.len == 0 and got == .inside) Mark.mark(.dns_empty_constraint);
    }

    // hostname.matchDnsName vs label-list reference.
    {
        const presented = domainish(S, src, &b1);
        var host = domainish(S, src, &b2);
        if (src.value(bool) and presented.len >= 2 and presented[0] == '*' and presented[1] == '.') {
            // A host shaped to fit the wildcard.
            const l = labels_pool[src.index(labels_pool.len)];
            var tmp: [64]u8 = undefined;
            @memcpy(tmp[0..l.len], l);
            @memcpy(tmp[l.len..][0 .. presented.len - 1], presented[1..]);
            @memcpy(b2[0 .. l.len + presented.len - 1], tmp[0 .. l.len + presented.len - 1]);
            host = b2[0 .. l.len + presented.len - 1];
        }
        const got = hostname.matchDnsName(presented, host);
        const want = refMatchHost(presented, host);
        if (got != want) {
            std.debug.print("matchDnsName(\"{s}\", \"{s}\") = {}, reference {}\n", .{ presented, host, got, want });
            return error.MatchDnsNameDisagrees;
        }
        const wild = presented.len >= 2 and presented[0] == '*' and presented[1] == '.';
        if (wild and got) Mark.mark(.wild_match);
        if (wild and !got) Mark.mark(.wild_refused);
        if (!wild and got) Mark.mark(.host_exact);
    }

    // Addresses: print canonically, parse back.
    {
        var a4: [4]u8 = undefined;
        for (&a4) |*x| x.* = src.value(u8);
        var t: [64]u8 = undefined;
        const s4 = try std.fmt.bufPrint(&t, "{d}.{d}.{d}.{d}", .{ a4[0], a4[1], a4[2], a4[3] });
        const p4 = names.parseIp4(s4) orelse return error.Ip4RoundTrip;
        if (!std.mem.eql(u8, &p4, &a4)) return error.Ip4RoundTrip;
        Mark.mark(.ip4_parsed);

        var a6: [16]u8 = undefined;
        for (&a6) |*x| x.* = if (src.value(bool)) 0 else src.value(u8);
        const full = try fmtIp6(&t, a6, false);
        const p6 = names.parseIp6(full) orelse {
            std.debug.print("parseIp6(\"{s}\") = null\n", .{full});
            return error.Ip6RoundTrip;
        };
        if (!std.mem.eql(u8, &p6, &a6)) return error.Ip6RoundTrip;
        var t2: [64]u8 = undefined;
        const short = try fmtIp6(&t2, a6, true);
        const q6 = names.parseIp6(short) orelse {
            std.debug.print("parseIp6(\"{s}\") = null\n", .{short});
            return error.Ip6RoundTrip;
        };
        if (!std.mem.eql(u8, &q6, &a6)) return error.Ip6RoundTrip;
        Mark.mark(.ip6_parsed);
        if (std.mem.indexOf(u8, short, "::") != null) Mark.mark(.ip6_compressed);

        // Random text: whatever parses must print back to the same bytes.
        const n = src.valueRangeAtMost(u8, 0, 24);
        const hex = "0123456789abcdefABCDEF:.";
        for (b1[0..n]) |*x| x.* = hex[src.index(hex.len)];
        if (names.parseIp6(b1[0..n])) |r6| {
            const again = names.parseIp6(try fmtIp6(&t, r6, false)) orelse return error.Ip6RoundTrip;
            if (!std.mem.eql(u8, &again, &r6)) return error.Ip6RoundTrip;
        }
        if (names.parseIp4(b1[0..n])) |r4| {
            const back = try std.fmt.bufPrint(&t2, "{d}.{d}.{d}.{d}", .{ r4[0], r4[1], r4[2], r4[3] });
            if (!std.mem.eql(u8, back, b1[0..n])) return error.Ip4NotCanonical;
        }
    }

    // GeneralNameIterator over arbitrary bytes never misbehaves, and every
    // entry it yields lies inside the input.
    {
        var raw: [48]u8 = undefined;
        var n: usize = 0;
        if (src.value(bool)) {
            n = src.slice(&raw);
        } else {
            // A well-formed GeneralNames with a few short entries, then
            // maybe damaged — random bytes alone rarely open the SEQUENCE.
            var k: usize = 2;
            const count = src.valueRangeAtMost(u8, 1, 4);
            for (0..count) |_| {
                const len = src.valueRangeAtMost(u8, 0, 6);
                raw[k] = 0x80 | src.valueRangeAtMost(u8, 0, 9);
                raw[k + 1] = len;
                for (raw[k + 2 ..][0..len]) |*x| x.* = alphabet[src.index(alphabet.len)];
                k += 2 + len;
            }
            raw[0] = 0x30;
            raw[1] = @intCast(k - 2);
            var clean: [48]u8 = undefined;
            @memcpy(clean[0..k], raw[0..k]);
            n = fz.damage(src, &raw, clean[0..k]);
        }
        var it = names.GeneralNameIterator.init(raw[0..n]) catch return;
        var k: usize = 0;
        while (it.next() catch return) |gn| : (k += 1) {
            const lo = @intFromPtr(gn.value.ptr);
            if (lo < @intFromPtr(&raw) or lo + gn.value.len > @intFromPtr(&raw) + n) return error.EntryOutsideInput;
            _ = names.match(gn.tag, gn.value, gn.value);
            if (k > 64) return error.IteratorRunaway;
        }
        if (k != 0) Mark.mark(.gn_entries);
    }
}

fn fmtIp6(buf: []u8, a: [16]u8, compress: bool) ![]const u8 {
    var g: [8]u16 = undefined;
    for (&g, 0..) |*x, i| x.* = std.mem.readInt(u16, a[i * 2 ..][0..2], .big);
    // Longest run of zero groups (length ≥ 2) becomes `::`.
    var best_at: usize = 8;
    var best_len: usize = 0;
    if (compress) {
        var i: usize = 0;
        while (i < 8) {
            if (g[i] != 0) {
                i += 1;
                continue;
            }
            var j = i;
            while (j < 8 and g[j] == 0) j += 1;
            if (j - i > best_len and j - i >= 2) {
                best_at = i;
                best_len = j - i;
            }
            i = j;
        }
    }
    var w: std.Io.Writer = .fixed(buf);
    var i: usize = 0;
    while (i < 8) {
        if (i == best_at) {
            try w.writeAll("::");
            i += best_len;
            continue;
        }
        if (i != 0 and i != best_at + best_len) try w.writeByte(':');
        try w.print("{x}", .{g[i]});
        i += 1;
    }
    return w.buffered();
}

// ── references ───────────────────────────────────────────────────────────

fn refValid(d: []const u8) bool {
    if (d.len == 0 or d.len > 253) return false;
    var it = std.mem.splitScalar(u8, d, '.');
    while (it.next()) |l| {
        if (l.len == 0 or l.len > 63) return false;
        for (l) |c| if (c < 0x21 or c > 0x7e) return false;
    }
    return true;
}

fn labels(d: []const u8, out: *[64][]const u8) []const []const u8 {
    var n: usize = 0;
    var it = std.mem.splitScalar(u8, d, '.');
    while (it.next()) |l| : (n += 1) out[n] = l;
    return out[0..n];
}

fn refMatchDomain(name: []const u8, c: []const u8) names.Match {
    if (!refValid(name)) return .unsupported;
    if (c.len == 0) return .inside;
    const sub = c[0] == '.';
    const cc = if (sub) c[1..] else c;
    if (!refValid(cc)) return .unsupported;
    var nb: [64][]const u8 = undefined;
    var cb: [64][]const u8 = undefined;
    const nl = labels(name, &nb);
    const cl = labels(cc, &cb);
    if (nl.len < cl.len or (sub and nl.len == cl.len)) return .outside;
    for (cl, nl[nl.len - cl.len ..]) |x, y| if (!std.ascii.eqlIgnoreCase(x, y)) return .outside;
    return .inside;
}

fn refHostLabel(l: []const u8) bool {
    if (l.len == 0 or l.len > 63) return false;
    for (l) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_')) return false;
    return true;
}

fn refMatchHost(presented: []const u8, host: []const u8) bool {
    var pb: [64][]const u8 = undefined;
    var hb: [64][]const u8 = undefined;
    const pl = labels(presented, &pb);
    const hl = labels(host, &hb);
    var ok_host = host.len != 0 and host.len <= 253;
    for (hl) |l| ok_host = ok_host and refHostLabel(l);
    const wild = pl.len != 0 and std.mem.eql(u8, pl[0], "*");
    var ok_pres = presented.len != 0 and presented.len <= 253 and (!wild or pl.len >= 3);
    for (pl, 0..) |l, i| ok_pres = ok_pres and ((i == 0 and wild) or refHostLabel(l));
    if (!ok_host or !ok_pres) return presented.len != 0 and std.ascii.eqlIgnoreCase(presented, host);
    if (pl.len != hl.len) return false;
    for (pl, hl, 0..) |p, h, i| {
        if (i == 0 and wild) continue;
        if (!std.ascii.eqlIgnoreCase(p, h)) return false;
    }
    return true;
}
