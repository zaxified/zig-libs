// SPDX-License-Identifier: MIT

//! `dns.update` + `dns.tsig` against a live RFC 2136 server — the half of
//! `tools/update_server.py check` that is ours. Reached as
//! `zig build interop-dns -- --update-server PORT`; the plain `interop-dns`
//! run never gets here, so it still needs no peer.
//!
//! The server (dnspython, keys `<alg>.key.` with secret SHA-256(name)) has
//! already taken one update from BIND's `nsupdate` (`from-nsupdate`) by the
//! time this runs; the script reads back what this leaves with `dig`.
//! Every check reads its result with the module's own resolver, RD clear —
//! the shape of a DNS-01 propagation check against an authoritative server.

const std = @import("std");
const dns = @import("dns");
const netaddr = @import("netaddr");

const update = dns.update;
const tsig = dns.tsig;

const loopback: netaddr.Ip = .{ .v4 = .{ 127, 0, 0, 1 } };

const Ctx = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    port: u16,
    bad: usize = 0,

    fn resolver(c: *Ctx, rd: bool) dns.Resolver {
        return dns.Resolver.init(c.io, c.gpa, .{
            .servers = &.{loopback},
            .port = c.port,
            .timeout_ms = 3000,
            .attempts = 1,
            .use_hosts = false,
            .use_search = false,
            .recursion_desired = rd,
        });
    }

    fn check(c: *Ctx, ok: bool, what: []const u8) void {
        std.debug.print("{s}: {s}\n", .{ if (ok) "ok" else "FAIL", what });
        if (!ok) c.bad += 1;
    }

    /// Send `b` and compare the rcode (or error) with `want`.
    fn expect(c: *Ctx, b: *update.Builder, key: ?*const tsig.Key, want: anyerror!dns.Rcode, what: []const u8) void {
        var r = c.resolver(true);
        defer r.deinit();
        const got = update.send(&r, loopback, b, .{ .key = key });
        const same = if (want) |w| (if (got) |g| g == w else |_| false) else |we| (if (got) |_| false else |ge| ge == we);
        if (!same) {
            if (got) |g| std.debug.print("  got rcode {t}\n", .{g}) else |e| std.debug.print("  got error {t}\n", .{e});
        }
        c.check(same, what);
    }

    /// The TXT strings at `name`, concatenated per record, joined with '|'
    /// (sorted, so the server's order does not matter); "" for none.
    fn txt(c: *Ctx, name: []const u8) ![]const u8 {
        var r = c.resolver(false);
        defer r.deinit();
        var msg = try r.query(name, .txt);
        defer msg.deinit();
        var values: std.ArrayList([]const u8) = .empty;
        for (msg.answers) |rec| {
            if (try rec.txtConcat(c.gpa)) |v| try values.append(c.gpa, v);
        }
        std.mem.sort([]const u8, values.items, {}, struct {
            fn lt(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lt);
        return std.mem.join(c.gpa, "|", values.items);
    }

    fn expectTxt(c: *Ctx, name: []const u8, want: []const u8, what: []const u8) void {
        const got = c.txt(name) catch |e| {
            std.debug.print("  read {s}: {t}\n", .{ name, e });
            c.check(false, what);
            return;
        };
        if (!std.mem.eql(u8, got, want)) std.debug.print("  {s}: want \"{s}\", got \"{s}\"\n", .{ name, want, got });
        c.check(std.mem.eql(u8, got, want), what);
    }
};

const Keys = struct {
    secrets: [5][32]u8,
    names: [5][]const u8,
    keys: [5]tsig.Key,

    fn init(k: *Keys) void {
        const algs = [_]tsig.Algorithm{ .hmac_sha1, .hmac_sha224, .hmac_sha256, .hmac_sha384, .hmac_sha512 };
        const names = [_][]const u8{ "hmac-sha1.key.", "hmac-sha224.key.", "hmac-sha256.key.", "hmac-sha384.key.", "hmac-sha512.key." };
        for (algs, names, 0..) |a, n, i| {
            std.crypto.hash.sha2.Sha256.hash(n, &k.secrets[i], .{});
            k.names[i] = n;
            k.keys[i] = .{ .name = n, .algorithm = a, .secret = &k.secrets[i] };
        }
    }
};

pub fn run(io: std.Io, gpa: std.mem.Allocator, port: u16) !u8 {
    var c: Ctx = .{ .io = io, .gpa = gpa, .port = port };
    var keys: Keys = undefined;
    keys.init();
    const k256 = &keys.keys[2];
    var buf: [2048]u8 = undefined;
    var rd: [1024]u8 = undefined;

    // 0. The control: what BIND's nsupdate wrote, read with our resolver.
    c.expectTxt("from-nsupdate.example.org", "nsupdate-was-here", "nsupdate's record is visible (RD clear)");

    // 1. One signed add per algorithm.
    for (&keys.keys) |*key| {
        var name_buf: [64]u8 = undefined;
        const name = try std.mem.print(&name_buf, "{s}.example.org", .{key.algorithm.name()});
        var b = try update.Builder.init(&buf, "example.org");
        try b.add(name, .txt, 60, try update.txtRdata(&rd, key.algorithm.name()));
        c.expect(&b, key, .no_error, name);
        c.expectTxt(name, key.algorithm.name(), "  ...and it is there");
    }

    // 2. Prerequisites: the name must not be in use, then it is.
    {
        var b = try update.Builder.init(&buf, "example.org");
        try b.requireNameNotInUse("from-zig.example.org");
        try b.add("from-zig.example.org", .txt, 60, try update.txtRdata(&rd, "zig-was-here"));
        c.expect(&b, k256, .no_error, "requireNameNotInUse + add");
        c.expect(&b, k256, .yx_domain, "the same again: YXDOMAIN");
    }
    {
        var b = try update.Builder.init(&buf, "example.org");
        try b.requireRrsetAbsent("from-zig.example.org", .txt);
        try b.add("from-zig.example.org", .txt, 60, try update.txtRdata(&rd, "never"));
        c.expect(&b, k256, .yx_rrset, "requireRrsetAbsent on a present RRset: YXRRSET");
    }
    {
        var b = try update.Builder.init(&buf, "example.org");
        try b.requireNameInUse("nothing.example.org");
        c.expect(&b, k256, .nx_domain, "requireNameInUse on a missing name: NXDOMAIN");
    }
    {
        var b = try update.Builder.init(&buf, "example.org");
        try b.requireRrsetExists("from-zig.example.org", .a);
        c.expect(&b, k256, .nx_rrset, "requireRrsetExists on a missing type: NXRRSET");
    }
    {
        var b = try update.Builder.init(&buf, "example.org");
        try b.requireRecord("from-zig.example.org", .txt, try update.txtRdata(&rd, "wrong"));
        c.expect(&b, k256, .nx_rrset, "requireRecord with another value: NXRRSET");
    }
    {
        var b = try update.Builder.init(&buf, "example.org");
        try b.requireRecord("from-zig.example.org", .txt, try update.txtRdata(&rd, "zig-was-here"));
        try b.requireRrsetExists("from-zig.example.org", .txt);
        try b.requireNameInUse("from-zig.example.org");
        c.expect(&b, k256, .no_error, "requireRecord / RrsetExists / NameInUse, all true");
    }

    // 3. DNS-01's own shape: add a second value, delete exactly one.
    {
        var b = try update.Builder.init(&buf, "example.org");
        try b.add("_acme-challenge.example.org", .txt, 60, try update.txtRdata(&rd, "token-a"));
        try b.add("_acme-challenge.example.org", .txt, 60, try update.txtRdata(&rd, "token-b"));
        c.expect(&b, k256, .no_error, "two values at one name (wildcard + base)");
        c.expectTxt("_acme-challenge.example.org", "token-a|token-b", "  ...both there");
        b = try update.Builder.init(&buf, "example.org");
        try b.delete("_acme-challenge.example.org", .txt, try update.txtRdata(&rd, "token-a"));
        c.expect(&b, k256, .no_error, "delete one value");
        c.expectTxt("_acme-challenge.example.org", "token-b", "  ...the other stays");
    }

    // 4. Deleting an RRset and a whole name.
    {
        var b = try update.Builder.init(&buf, "example.org");
        try b.deleteRrset("hmac-sha1.example.org", .txt);
        try b.deleteName("hmac-sha224.example.org");
        c.expect(&b, &keys.keys[4], .no_error, "deleteRrset + deleteName (signed hmac-sha512)");
        c.expectTxt("hmac-sha1.example.org", "", "  ...RRset gone");
        c.expectTxt("hmac-sha224.example.org", "", "  ...name gone");
    }

    // 5. The server's refusals.
    {
        var b = try update.Builder.init(&buf, "example.org");
        try b.add("elsewhere.test", .txt, 60, try update.txtRdata(&rd, "x"));
        c.expect(&b, k256, .not_zone, "a name outside the zone: NOTZONE");
        b = try update.Builder.init(&buf, "other.test");
        try b.add("x.other.test", .txt, 60, try update.txtRdata(&rd, "x"));
        c.expect(&b, k256, .not_auth, "a zone the server does not serve: NOTAUTH");
        b = try update.Builder.init(&buf, "example.org");
        try b.add("unsigned.example.org", .txt, 60, try update.txtRdata(&rd, "x"));
        c.expect(&b, null, .refused, "unsigned: REFUSED");
    }

    // 6. TSIG failures, as BIND reports them (unsigned NOTAUTH + TSIG error).
    {
        var b = try update.Builder.init(&buf, "example.org");
        try b.add("bad.example.org", .txt, 60, try update.txtRdata(&rd, "x"));
        const wrong_secret: tsig.Key = .{ .name = "hmac-sha256.key.", .secret = "not the secret" };
        c.expect(&b, &wrong_secret, error.PeerBadSig, "wrong secret: PeerBadSig");
        const unknown: tsig.Key = .{ .name = "nobody.key.", .secret = &keys.secrets[2] };
        c.expect(&b, &unknown, error.PeerBadKey, "unknown key: PeerBadKey");
        const wrong_alg: tsig.Key = .{ .name = "hmac-sha256.key.", .algorithm = .hmac_sha512, .secret = &keys.secrets[2] };
        c.expect(&b, &wrong_alg, error.PeerBadKey, "right name, wrong algorithm: PeerBadKey");
        c.expectTxt("bad.example.org", "", "  ...none of them applied");
    }

    // 7. Over 512 bytes: the update goes over TCP, and so does the read
    //    (the server truncates the UDP answer).
    {
        var value: [608]u8 = @splat('y');
        @memcpy(value[0..8], "via-tcp-");
        var b = try update.Builder.init(&buf, "delegated.test");
        try b.add("_acme-challenge.delegated.test", .txt, 60, try update.txtRdata(&rd, &value));
        c.check(b.len > 512, "the message is over 512 bytes");
        c.expect(&b, k256, .no_error, "a large update (TCP)");
        c.expectTxt("_acme-challenge.delegated.test", &value, "  ...read back over TCP after TC");
    }

    std.debug.print("dns update interop: {d} failure(s)\n", .{c.bad});
    return if (c.bad == 0) 0 else 1;
}
