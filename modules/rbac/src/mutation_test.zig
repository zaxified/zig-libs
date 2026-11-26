// SPDX-License-Identifier: MIT
//! Delta mutation tests for `policy.zig` (2026-11-25): exact text, declaration sources, quoting corners,
//! break checks and Domains lifetime.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const Engine = root.rbac.Engine;
const Domains = root.rbac.Domains;
const Diag = root.rbac.PolicyDiag;

fn savedText(e: anytype) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try e.savePolicy(&aw.writer);
    return testing.allocator.dupe(u8, aw.written());
}

test "mutation 2026-11-25: savePolicy writes exactly the documented order (roles, permissions, hierarchy, SoD, assignments, each sorted)" {
    var e = Engine.init(testing.allocator);
    defer e.deinit();
    for ([_][]const u8{ "zeta", "alpha", "mid", "omega", "beta" }) |r| try e.addRole(r);
    try e.addPermission("zeta", .{ .resource = "/c", .action = "x" });
    try e.addPermission("alpha", .{ .resource = "/b", .action = "write" });
    try e.addPermission("alpha", .{ .resource = "/b", .action = "read" });
    try e.addPermission("alpha", .{ .resource = "/a", .action = "zz" });
    try e.addHierarchy("zeta", "mid");
    try e.addHierarchy("alpha", "omega");
    try e.addHierarchy("alpha", "beta");
    try e.addStaticSoD("zeta", "alpha");
    try e.addStaticSoD("mid", "beta");
    try e.addStaticSoD("mid", "alpha");
    try e.assignRole("u3", "zeta");
    try e.assignRole("u2", "beta");
    try e.assignRole("u2", "alpha");
    try e.assignRole("u1", "omega");
    try e.assignRole("u1", "mid");
    const text = try savedText(&e);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        \\r, alpha
        \\r, beta
        \\r, mid
        \\r, omega
        \\r, zeta
        \\p, alpha, /a, zz
        \\p, alpha, /b, read
        \\p, alpha, /b, write
        \\p, zeta, /c, x
        \\g2, alpha, beta
        \\g2, alpha, omega
        \\g2, zeta, mid
        \\sod, alpha, mid
        \\sod, alpha, zeta
        \\sod, beta, mid
        \\g, u1, mid
        \\g, u1, omega
        \\g, u2, alpha
        \\g, u2, beta
        \\g, u3, zeta
        \\
    , text);
}

test "mutation 2026-11-25: Domains.savePolicy writes domains in byte order, the domain field last (after the role for p)" {
    var d = try Domains.fromPolicy(testing.allocator, .exact,
        \\r, z, t0
        \\p, a, t1, /x, read
        \\g, u, a, t1
        \\sod, b, c, t2
        \\g2, b, c, t2
        \\
    , null);
    defer d.deinit();
    const text = try savedText(&d);
    defer testing.allocator.free(text);
    try testing.expectEqualStrings(
        \\r, z, t0
        \\r, a, t1
        \\p, a, t1, /x, read
        \\g, u, a, t1
        \\r, b, t2
        \\r, c, t2
        \\g2, b, c, t2
        \\sod, b, c, t2
        \\
    , text);
}

test "mutation 2026-11-25: names that need quoting survive save and load, and are written quoted" {
    var e = Engine.init(testing.allocator);
    defer e.deinit();
    for ([_][]const u8{ "", " lead", "trail ", "\"q\"", "a,b" }) |r| try e.addRole(r);
    const text = try savedText(&e);
    defer testing.allocator.free(text);
    for ([_][]const u8{ "r, \"\"\n", "r, \" lead\"\n", "r, \"trail \"\n", "r, \"\"\"q\"\"\"\n", "r, \"a,b\"\n" }) |line| {
        try testing.expect(std.mem.find(u8, text, line) != null);
    }
    var again = try Engine.fromPolicy(testing.allocator, .exact, text, null);
    defer again.deinit();
    for ([_][]const u8{ "", " lead", "trail ", "\"q\"", "a,b" }) |r| try testing.expect(again.roles.contains(r));
    try testing.expectEqual(@as(usize, 5), again.roles.count());
}

test "mutation 2026-11-25: every record kind declares the roles it mentions on its own" {
    var e = Engine.init(testing.allocator);
    defer e.deinit();
    try e.loadPolicy("r, solo\np, rp, /x, read\ng, u, role_g\ng2, aa, bb\nsod, cc, dd\n", null);
    for ([_][]const u8{ "solo", "rp", "role_g", "aa", "bb", "cc", "dd" }) |r| try testing.expect(e.roles.contains(r));
    try testing.expect(e.assignments.get("u").?.contains("role_g"));
}

test "mutation 2026-11-25: CRLF line ends, a blank before a comma after a closing quote, text glued to a closing quote" {
    var e = Engine.init(testing.allocator);
    defer e.deinit();
    try e.loadPolicy("r, c1\r\nr, \"c2\"\r\n", null);
    try testing.expect(e.roles.contains("c1"));
    try testing.expect(e.roles.contains("c2"));
    try e.loadPolicy("r, role_h\ng, \"al\" , role_h\n", null);
    try testing.expect(e.assignments.get("al").?.contains("role_h"));
    // `x` stands where the comma must be: a lenient parser would read p, r1, /data, read.
    var diag: Diag = .{};
    try testing.expectError(error.InvalidPolicy, e.loadPolicy("p, \"r1\"x/data, read\n", &diag));
    try testing.expectEqual(@as(usize, 1), diag.line);
}

test "mutation 2026-11-25: save refuses a line break (CR or LF) in a permission, in a user name, and in Domains" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    inline for ([_][2][]const u8{ .{ "a\nb", "/x" }, .{ "a", "/x\ny" }, .{ "a\rb", "/x" } }) |ar| {
        var e = Engine.init(testing.allocator);
        defer e.deinit();
        try e.addRole("r1");
        try e.addPermission("r1", .{ .action = ar[0], .resource = ar[1] });
        try testing.expectError(error.Unrepresentable, e.savePolicy(&aw.writer));
    }
    {
        var e = Engine.init(testing.allocator);
        defer e.deinit();
        try e.addRole("r1");
        try e.assignRole("us\ner", "r1");
        try testing.expectError(error.Unrepresentable, e.savePolicy(&aw.writer));
    }
    {
        var e = Engine.init(testing.allocator);
        defer e.deinit();
        try e.addRole("r\r1");
        try testing.expectError(error.Unrepresentable, e.savePolicy(&aw.writer));
    }
    {
        var d = Domains.init(testing.allocator);
        defer d.deinit();
        try (try d.engine("ok")).addRole("bad\nrole");
        try testing.expectError(error.Unrepresentable, d.savePolicy(&aw.writer));
    }
    {
        var d = Domains.init(testing.allocator);
        defer d.deinit();
        _ = try d.engine("bad\ndomain");
        try testing.expectError(error.Unrepresentable, d.savePolicy(&aw.writer));
    }
    try testing.expectEqual(@as(usize, 0), aw.written().len);
}

test "mutation 2026-11-25: Domains engines use the Domains match mode; a failed Domains.fromPolicy frees everything" {
    var d = try Domains.fromPolicy(testing.allocator, .key_match, "p, r1, d1, /api/*, read\ng, u, r1, d1\n", null);
    defer d.deinit();
    try testing.expect(d.check("d1", "u", "read", "/api/x/y").isPermit());
    // The leak check of the testing allocator is the assertion for the failing load.
    try testing.expectError(error.CyclicHierarchy, Domains.fromPolicy(testing.allocator, .exact, "g2, a, b, dd\ng2, b, a, dd\n", null));
}
