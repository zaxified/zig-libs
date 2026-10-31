// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver over the two things `acmedns` reads from the
//! other side, both generic over their source of choices (`fn(comptime S,
//! *S, gpa)`):
//!
//!   - `registration`: an acme-dns `/register` reply, a valid one with a few
//!     octets damaged and maybe cut short, through `AcmeDns.parseRegistration`;
//!   - `txt`: an authoritative server's TXT reply (two records, one carrying
//!     the value in two strings), damaged the same way, decoded by `dns` and
//!     matched by `zone.txtPresent` — the verdict the propagation check acts on.
//!
//! Driver: `ACMEDNS_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_MS`,
//! `_SEEDFILE`, `_INPUT`, `_ONLY` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const dns = @import("dns");
const publishers = @import("publishers.zig");
const zone = @import("zone.zig");

pub const Label = enum { json_rejected, json_parsed, txt_rejected, txt_absent, txt_found };
var reach: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

fn mark(comptime l: Label) void {
    reach[@backingInt(l)] += 1;
    fuzz_driver.hit(@tagName(l));
}

const registration_json =
    \\{"username":"eabcdb41-d89f-4580-826f-3e62e9755ef2","password":"pbAXVjlIOE01xbut7YnAbkhMQIkcwoHO0ek2j4Q0",
    \\"fulldomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.org","subdomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf","allowfrom":[]}
;

const value = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0";

/// A reply to TXT `_acme-challenge.example.org`: question, then a TXT with an
/// unrelated value and one with `value` split into two strings (the second
/// owner name compressed), as an authoritative server sends it.
const txt_reply =
    "\x12\x34\x84\x00\x00\x01\x00\x02\x00\x00\x00\x00" ++
    "\x0f_acme-challenge\x07example\x03org\x00\x00\x10\x00\x01" ++
    "\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x06\x05other" ++
    "\xc0\x0c\x00\x10\x00\x01\x00\x00\x00\x3c\x00\x2d\x14" ++ value[0..20] ++ "\x17" ++ value[20..];

fn damage(comptime S: type, src: *S, out: []u8, base: []const u8) usize {
    @memcpy(out[0..base.len], base);
    var len = base.len;
    for (0..src.valueRangeAtMost(u8, 0, 4)) |_| {
        const at = src.index(len);
        out[at] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) len = src.index(len) + 1;
    return len;
}

fn registrationHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [registration_json.len]u8 = undefined;
    const len = damage(S, src, &buf, registration_json);
    var parsed = publishers.AcmeDns.parseRegistration(gpa, buf[0..len]) catch {
        mark(.json_rejected);
        return;
    };
    defer parsed.deinit();
    mark(.json_parsed);
}

fn txtHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [txt_reply.len]u8 = undefined;
    const len = damage(S, src, &buf, txt_reply);
    var msg = dns.decode(gpa, buf[0..len]) catch {
        mark(.txt_rejected);
        return;
    };
    defer msg.deinit();
    if (zone.txtPresent(&msg, "_acme-challenge.example.org", value)) mark(.txt_found) else mark(.txt_absent);
}

/// `testing.fuzz`'s source: every choice read by a cursor from one `slice`.
const ScriptSource = struct {
    cur: testkit.fuzz.Cursor,

    pub fn valueRangeAtMost(self: *ScriptSource, comptime T: type, at_least: T, at_most: T) T {
        return @intCast(self.cur.ranged(at_least, at_most));
    }
    pub fn value(self: *ScriptSource, comptime T: type) T {
        return switch (T) {
            u8 => self.cur.byte(),
            else => @compileError("ScriptSource.value: unsupported type"),
        };
    }
    pub fn index(self: *ScriptSource, len: usize) usize {
        return self.cur.ranged(0, @intCast(len - 1));
    }
};

fn fuzzScript(comptime harness: anytype) fn (void, *testing.Smith) anyerror!void {
    return struct {
        fn f(_: void, smith: *testing.Smith) anyerror!void {
            var script: [256]u8 = undefined;
            const n = smith.slice(&script);
            var src: ScriptSource = .{ .cur = .{ .bytes = script[0..n] } };
            return harness(ScriptSource, &src, testing.allocator);
        }
    }.f;
}

test "fuzz: parseRegistration never crashes or leaks on a damaged reply" {
    try testing.fuzz({}, fuzzScript(registrationHarness), .{});
}

test "fuzz: txtPresent never crashes on a damaged TXT reply" {
    try testing.fuzz({}, fuzzScript(txtHarness), .{});
}

test "fuzz driver: ACMEDNS_FUZZ" {
    try fuzz_driver.runAll(.{
        .{ registrationHarness, .{ .prefix = "ACMEDNS_FUZZ", .name = "acmedns-registration" } },
        .{ txtHarness, .{ .prefix = "ACMEDNS_FUZZ", .name = "acmedns-txt" } },
    });
}

test "fuzz harness: 500 seeds in every test run, and they get everywhere" {
    reach = @splat(0);
    for (0..500) |seed| {
        var prng = std.Random.DefaultPrng.init(seed);
        var rng: fuzz_driver.Rng = .{ .r = prng.random() };
        try registrationHarness(fuzz_driver.Rng, &rng, testing.allocator);
        try txtHarness(fuzz_driver.Rng, &rng, testing.allocator);
    }
    for (reach, 0..) |n, i| if (n == 0) {
        std.debug.print("reach: label {t} never hit in 500 seeds\n", .{@as(Label, @fromBackingInt(@intCast(i)))});
        return error.HarnessDoesNotReach;
    };
}

test "the undamaged inputs: registration parses, the value is found" {
    var parsed = try publishers.AcmeDns.parseRegistration(testing.allocator, registration_json);
    defer parsed.deinit();
    try testing.expectEqualStrings("d420c923-bbd7-4056-ab64-c3ca54c9b3cf", parsed.value.subdomain);
    var msg = try dns.decode(testing.allocator, txt_reply);
    defer msg.deinit();
    try testing.expect(zone.txtPresent(&msg, "_acme-challenge.example.org", value));
    try testing.expect(!zone.txtPresent(&msg, "_acme-challenge.example.org", "other"[0..4]));
}
