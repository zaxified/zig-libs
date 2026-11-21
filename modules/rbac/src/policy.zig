// SPDX-License-Identifier: MIT
//! Policy text for `rbac.Engine` and `rbac.Domains`, in the CSV shape of Casbin policy files (`p, alice, data1,
//! read`): one record per line, fields separated by commas, blank lines and lines starting with `#` ignored,
//! surrounding spaces trimmed, a field in double quotes may hold commas, spaces and `""` for a quote.
//!
//!     r,   <role>                      a role, even when nothing else mentions it
//!     p,   <role>, <resource>, <action>   a permission (Casbin's `p, sub, obj, act`)
//!     g,   <user>, <role>              a user holds a role (Casbin's `g, user, role`)
//!     g2,  <senior>, <junior>          the senior role inherits the junior's permissions
//!     sod, <role>, <role>              a static separation-of-duty pair
//!
//! A `Domains` policy has one more field per record, the domain, in Casbin's place for it: `p, role, domain,
//! resource, action`, `g, user, role, domain`, `g2, senior, junior, domain`, `sod, a, b, domain`, `r, role,
//! domain`. A role is declared by any mention in a role position, so a file need not list `r` lines and need
//! not be ordered: loading declares every role first, then applies permissions, hierarchy edges, SoD pairs and
//! assignments (in that order, so a SoD pair also constrains the assignments of the same file).

const std = @import("std");
const root = @import("root.zig");
const Allocator = std.mem.Allocator;
const Engine = root.rbac.Engine;

pub const Error = root.rbac.Error || error{
    /// A line is not one of the records above, has the wrong number of fields, or a quoted field is malformed.
    InvalidPolicy,
    /// `save`: a name holds a line break, which a line-based file cannot carry.
    Unrepresentable,
};

pub const Diag = struct {
    /// The 1-based line the error refers to (0: none).
    line: usize = 0,
};

const Kind = enum { r, p, g, g2, sod };

const Record = struct {
    kind: Kind,
    /// Up to three payload fields (borrowed from the text or from the line's scratch arena).
    f: [3][]const u8 = undefined,
    n: usize = 0,
    domain: ?[]const u8 = null,
};

/// Fields a record of `kind` has before the domain.
fn arity(kind: Kind) usize {
    return switch (kind) {
        .r => 1,
        .p => 3,
        .g, .g2, .sod => 2,
    };
}

fn isBlank(c: u8) bool {
    return c == ' ' or c == '\t';
}

/// Splits one line into fields; quoted fields are copied into `arena`.
fn splitFields(arena: Allocator, line: []const u8, out: *std.ArrayList([]const u8)) Error!void {
    var i: usize = 0;
    while (true) {
        while (i < line.len and isBlank(line[i])) i += 1;
        if (i < line.len and line[i] == '"') {
            i += 1;
            var buf: std.ArrayList(u8) = .empty;
            while (true) {
                if (i >= line.len) return error.InvalidPolicy; // unterminated quote
                if (line[i] == '"') {
                    if (i + 1 < line.len and line[i + 1] == '"') {
                        try buf.append(arena, '"');
                        i += 2;
                        continue;
                    }
                    i += 1;
                    break;
                }
                try buf.append(arena, line[i]);
                i += 1;
            }
            while (i < line.len and isBlank(line[i])) i += 1;
            if (i < line.len and line[i] != ',') return error.InvalidPolicy; // text after the closing quote
            try out.append(arena, buf.items);
        } else {
            const start = i;
            while (i < line.len and line[i] != ',') i += 1;
            try out.append(arena, std.mem.trimEnd(u8, line[start..i], " \t"));
        }
        if (i >= line.len) return;
        i += 1; // the comma
    }
}

fn parseLine(arena: Allocator, line_in: []const u8, with_domain: bool) Error!?Record {
    const line = std.mem.trim(u8, line_in, " \t\r");
    if (line.len == 0 or line[0] == '#') return null;
    var fields: std.ArrayList([]const u8) = .empty;
    try splitFields(arena, line, &fields);
    const kind = std.meta.stringToEnum(Kind, fields.items[0]) orelse return error.InvalidPolicy;
    const want = arity(kind);
    if (fields.items.len != 1 + want + @as(usize, @intFromBool(with_domain))) return error.InvalidPolicy;
    var rec: Record = .{ .kind = kind, .n = want };
    const fs = fields.items[1..];
    if (with_domain and kind == .p) {
        // Casbin's order: sub, dom, obj, act.
        rec.f = .{ fs[0], fs[2], fs[3] };
        rec.domain = fs[1];
    } else {
        for (0..want) |k| rec.f[k] = fs[k];
        if (with_domain) rec.domain = fs[want];
    }
    return rec;
}

/// Pass numbers: 0 syntax only, 1 declare roles, 2 permissions, 3 hierarchy, 4 SoD, 5 assignments.
fn apply(target: anytype, text: []const u8, with_domain: bool, diag: ?*Diag) (Error)!void {
    var pass: usize = 0;
    while (pass <= 5) : (pass += 1) {
        var arena_state = std.heap.ArenaAllocator.init(target.allocator());
        defer arena_state.deinit();
        var lines = std.mem.splitScalar(u8, text, '\n');
        var no: usize = 0;
        while (lines.next()) |raw| {
            no += 1;
            _ = arena_state.reset(.retain_capacity);
            const rec = parseLine(arena_state.allocator(), raw, with_domain) catch |err| {
                if (diag) |d| d.line = no;
                return err;
            } orelse continue;
            if (pass == 0) continue;
            applyRecord(target, rec, pass) catch |err| {
                if (diag) |d| d.line = no;
                return err;
            };
        }
    }
}

fn applyRecord(target: anytype, rec: Record, pass: usize) Error!void {
    const e = try target.engineFor(rec.domain);
    switch (pass) {
        1 => switch (rec.kind) {
            .r => try e.addRole(rec.f[0]),
            .p => try e.addRole(rec.f[0]),
            .g => try e.addRole(rec.f[1]),
            .g2, .sod => {
                try e.addRole(rec.f[0]);
                try e.addRole(rec.f[1]);
            },
        },
        2 => if (rec.kind == .p) try e.addPermission(rec.f[0], .{ .resource = rec.f[1], .action = rec.f[2] }),
        3 => if (rec.kind == .g2) try e.addHierarchy(rec.f[0], rec.f[1]),
        4 => if (rec.kind == .sod) try e.addStaticSoD(rec.f[0], rec.f[1]),
        5 => if (rec.kind == .g) try e.assignRole(rec.f[0], rec.f[1]),
        else => unreachable,
    }
}

/// Wraps one engine as a `apply` target.
const Single = struct {
    e: *Engine,
    fn allocator(s: Single) Allocator {
        return s.e.gpa;
    }
    fn engineFor(s: Single, _: ?[]const u8) Error!*Engine {
        return s.e;
    }
};

/// Adds the records of `text` to `e` (additive: records are idempotent adds). Not atomic: a record that fails
/// (`UnknownRole`/`CyclicHierarchy`/`ConflictingRole`, or `InvalidPolicy` on any line, which is found before
/// anything is applied) leaves the earlier ones in place; `Engine.fromPolicy` is the all-or-nothing form.
pub fn load(e: *Engine, text: []const u8, diag: ?*Diag) Error!void {
    return apply(Single{ .e = e }, text, false, diag);
}

pub fn fromPolicy(gpa: Allocator, match: root.rbac.Match, text: []const u8, diag: ?*Diag) Error!Engine {
    var e = Engine.initWithMatch(gpa, match);
    errdefer e.deinit();
    try load(&e, text, diag);
    return e;
}

// ── save ────────────────────────────────────────────────────────────────

fn hasBreak(s: []const u8) bool {
    return std.mem.findAny(u8, s, "\r\n") != null;
}

fn needsQuote(s: []const u8) bool {
    if (s.len == 0) return true;
    if (isBlank(s[0]) or isBlank(s[s.len - 1])) return true;
    return std.mem.findAny(u8, s, ",\"") != null;
}

fn writeField(w: *std.Io.Writer, s: []const u8) std.Io.Writer.Error!void {
    try w.writeAll(", ");
    if (!needsQuote(s)) return w.writeAll(s);
    try w.writeByte('"');
    for (s) |c| {
        if (c == '"') try w.writeByte('"');
        try w.writeByte(c);
    }
    try w.writeByte('"');
}

fn lessStr(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

fn checkBreaks(e: *const Engine) error{Unrepresentable}!void {
    var rit = e.roles.iterator();
    while (rit.next()) |kv| {
        if (hasBreak(kv.key_ptr.*)) return error.Unrepresentable;
        for (kv.value_ptr.permissions.items) |p| if (hasBreak(p.action) or hasBreak(p.resource)) return error.Unrepresentable;
        for (kv.value_ptr.juniors.items) |j| if (hasBreak(j)) return error.Unrepresentable;
    }
    var ait = e.assignments.keyIterator();
    while (ait.next()) |u| if (hasBreak(u.*)) return error.Unrepresentable;
}

/// One engine's records, in a fixed order (roles, permissions, hierarchy, SoD, assignments; each sorted), so the
/// output of equal policies is equal text. `domain` is the extra field of a `Domains` file.
fn writeEngine(gpa: Allocator, e: *const Engine, w: *std.Io.Writer, domain: ?[]const u8) (Allocator.Error || std.Io.Writer.Error)!void {
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(gpa);
    var rit = e.roles.keyIterator();
    while (rit.next()) |k| try names.append(gpa, k.*);
    std.mem.sort([]const u8, names.items, {}, lessStr);

    for (names.items) |r| {
        try w.writeAll("r");
        try writeField(w, r);
        if (domain) |d| try writeField(w, d);
        try w.writeByte('\n');
    }
    const Perm = root.rbac.Permission;
    for (names.items) |r| {
        const rd = e.roles.get(r).?;
        const perms = try gpa.dupe(Perm, rd.permissions.items);
        defer gpa.free(perms);
        std.mem.sort(Perm, perms, {}, struct {
            fn less(_: void, a: Perm, b: Perm) bool {
                const o = std.mem.order(u8, a.resource, b.resource);
                if (o != .eq) return o == .lt;
                return std.mem.lessThan(u8, a.action, b.action);
            }
        }.less);
        for (perms) |p| {
            try w.writeAll("p");
            try writeField(w, r);
            if (domain) |d| try writeField(w, d);
            try writeField(w, p.resource);
            try writeField(w, p.action);
            try w.writeByte('\n');
        }
    }
    for (names.items) |r| {
        const rd = e.roles.get(r).?;
        const js = try gpa.dupe([]const u8, rd.juniors.items);
        defer gpa.free(js);
        std.mem.sort([]const u8, js, {}, lessStr);
        for (js) |j| {
            try w.writeAll("g2");
            try writeField(w, r);
            try writeField(w, j);
            if (domain) |d| try writeField(w, d);
            try w.writeByte('\n');
        }
    }
    const Pair = struct { a: []const u8, b: []const u8 };
    var pairs: std.ArrayList(Pair) = .empty;
    defer pairs.deinit(gpa);
    for (e.sod.items) |p| {
        const swap = std.mem.lessThan(u8, p.b, p.a);
        try pairs.append(gpa, if (swap) .{ .a = p.b, .b = p.a } else .{ .a = p.a, .b = p.b });
    }
    std.mem.sort(Pair, pairs.items, {}, struct {
        fn less(_: void, x: Pair, y: Pair) bool {
            const o = std.mem.order(u8, x.a, y.a);
            if (o != .eq) return o == .lt;
            return std.mem.lessThan(u8, x.b, y.b);
        }
    }.less);
    for (pairs.items) |p| {
        try w.writeAll("sod");
        try writeField(w, p.a);
        try writeField(w, p.b);
        if (domain) |d| try writeField(w, d);
        try w.writeByte('\n');
    }
    var users: std.ArrayList([]const u8) = .empty;
    defer users.deinit(gpa);
    var uit = e.assignments.keyIterator();
    while (uit.next()) |u| try users.append(gpa, u.*);
    std.mem.sort([]const u8, users.items, {}, lessStr);
    for (users.items) |u| {
        const set = e.assignments.get(u).?;
        var held: std.ArrayList([]const u8) = .empty;
        defer held.deinit(gpa);
        var hit = set.keyIterator();
        while (hit.next()) |k| try held.append(gpa, k.*);
        std.mem.sort([]const u8, held.items, {}, lessStr);
        for (held.items) |r| {
            try w.writeAll("g");
            try writeField(w, u);
            try writeField(w, r);
            if (domain) |d| try writeField(w, d);
            try w.writeByte('\n');
        }
    }
}

pub const SaveError = Allocator.Error || std.Io.Writer.Error || error{Unrepresentable};

/// Writes `e` as policy text (the file `load` reads back to an equal policy). Nothing is written when a name
/// holds a line break (`Unrepresentable`). `Engine.match` is not part of the text: give it again at `fromPolicy`.
pub fn save(e: *const Engine, w: *std.Io.Writer) SaveError!void {
    try checkBreaks(e);
    try writeEngine(e.gpa, e, w, null);
}

// ── Domains ─────────────────────────────────────────────────────────────

pub const Domains = struct {
    gpa: Allocator,
    match: root.rbac.Match = .exact,
    map: std.StringHashMapUnmanaged(*Engine) = .empty,

    pub fn init(gpa: Allocator) Domains {
        return .{ .gpa = gpa };
    }

    /// Every domain's engine uses `match` for its permissions (`Engine.initWithMatch`).
    pub fn initWithMatch(gpa: Allocator, match: root.rbac.Match) Domains {
        return .{ .gpa = gpa, .match = match };
    }

    pub fn deinit(d: *Domains) void {
        var it = d.map.iterator();
        while (it.next()) |kv| {
            kv.value_ptr.*.deinit();
            d.gpa.destroy(kv.value_ptr.*);
            d.gpa.free(kv.key_ptr.*);
        }
        d.map.deinit(d.gpa);
        d.* = undefined;
    }

    /// The engine of `domain`, created empty when there is none. The pointer stays valid until
    /// `removeDomain(domain)` or `deinit`.
    pub fn engine(d: *Domains, domain: []const u8) Allocator.Error!*Engine {
        if (d.map.get(domain)) |e| return e;
        const key = try d.gpa.dupe(u8, domain);
        errdefer d.gpa.free(key);
        const e = try d.gpa.create(Engine);
        errdefer d.gpa.destroy(e);
        e.* = Engine.initWithMatch(d.gpa, d.match);
        try d.map.put(d.gpa, key, e);
        return e;
    }

    /// The engine of `domain`, or null when no record ever created it.
    pub fn get(d: *const Domains, domain: []const u8) ?*Engine {
        return d.map.get(domain);
    }

    /// Drops a domain with all its roles, permissions, hierarchy, SoD pairs and assignments. False when absent.
    pub fn removeDomain(d: *Domains, domain: []const u8) bool {
        const kv = d.map.fetchRemove(domain) orelse return false;
        kv.value.deinit();
        d.gpa.destroy(kv.value);
        d.gpa.free(kv.key);
        return true;
    }

    /// `Engine.check` inside `domain`. A user's roles, a role's permissions and the hierarchy are all per domain
    /// (Casbin's "RBAC with domains"): a user with a role in one domain has nothing in another. An unknown
    /// domain denies.
    pub fn check(d: *const Domains, domain: []const u8, user: []const u8, action: []const u8, resource: []const u8) root.Decision {
        const e = d.map.get(domain) orelse return .{ .result = .deny, .reason = "unknown domain (default-deny)" };
        return e.check(user, action, resource);
    }

    fn allocator(d: *const Domains) Allocator {
        return d.gpa;
    }

    fn engineFor(d: *Domains, domain: ?[]const u8) Error!*Engine {
        return d.engine(domain.?);
    }

    /// Adds the records of a domain policy file (see the file header); additive and not atomic, like `load`.
    pub fn loadPolicy(d: *Domains, text: []const u8, diag: ?*Diag) Error!void {
        return apply(d, text, true, diag);
    }

    /// A new `Domains` from policy text; freed again when any record fails.
    pub fn fromPolicy(gpa: Allocator, match: root.rbac.Match, text: []const u8, diag: ?*Diag) Error!Domains {
        var d = Domains.initWithMatch(gpa, match);
        errdefer d.deinit();
        try d.loadPolicy(text, diag);
        return d;
    }

    /// Writes every domain's records, domains in byte order (a domain with no records leaves no trace).
    pub fn savePolicy(d: *const Domains, w: *std.Io.Writer) SaveError!void {
        var doms: std.ArrayList([]const u8) = .empty;
        defer doms.deinit(d.gpa);
        var it = d.map.iterator();
        while (it.next()) |kv| {
            try checkBreaks(kv.value_ptr.*);
            if (hasBreak(kv.key_ptr.*)) return error.Unrepresentable;
            try doms.append(d.gpa, kv.key_ptr.*);
        }
        std.mem.sort([]const u8, doms.items, {}, lessStr);
        for (doms.items) |name| try writeEngine(d.gpa, d.map.get(name).?, w, name);
    }
};

// ── tests ───────────────────────────────────────────────────────────────

const testing = std.testing;

fn saved(e: anytype) ![]u8 {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try e.savePolicy(&aw.writer);
    return testing.allocator.dupe(u8, aw.written());
}

const sample =
    \\# a Casbin-style file, in no particular order
    \\g, alice, admin
    \\g, bob, reader
    \\
    \\p, admin, /data/*, write
    \\  p ,reader, /data/*, read
    \\g2, admin, reader
    \\sod, admin, auditor
    \\r, auditor
    \\
;

test "policy: a hand-written file loads in any order and decides like the API-built engine" {
    var e = try Engine.fromPolicy(testing.allocator, .key_match, sample, null);
    defer e.deinit();
    try testing.expect(e.check("alice", "write", "/data/x").isPermit());
    try testing.expect(e.check("alice", "read", "/data/x").isPermit()); // inherited from reader
    try testing.expect(e.check("bob", "read", "/data/x/y").isPermit());
    try testing.expect(!e.check("bob", "write", "/data/x").isPermit());
    try testing.expect(!e.check("carol", "read", "/data/x").isPermit());
    // The SoD pair of the file constrains assignments made afterwards.
    try testing.expectError(error.ConflictingRole, e.assignRole("alice", "auditor"));
    try testing.expect(e.roles.contains("auditor")); // declared by an `r` line alone
}

test "policy: save then load is a fixed point, with commas, quotes and spaces in names" {
    var e = Engine.initWithMatch(testing.allocator, .key_match);
    defer e.deinit();
    try e.addRole("ops, night shift");
    try e.addRole("say \"hi\"");
    try e.addRole(" padded ");
    try e.addRole("lonely");
    try e.addPermission("ops, night shift", .{ .action = "read", .resource = "/a,b" });
    try e.addPermission("ops, night shift", .{ .action = "write", .resource = "/a,b" });
    try e.addHierarchy("ops, night shift", "say \"hi\"");
    try e.addStaticSoD("say \"hi\"", " padded ");
    try e.assignRole("u1", "ops, night shift");
    try e.assignRole("u1", "lonely");
    try e.assignRole("u1", "say \"hi\"");

    const text = try saved(&e);
    defer testing.allocator.free(text);
    var again = try Engine.fromPolicy(testing.allocator, .key_match, text, null);
    defer again.deinit();
    const text2 = try saved(&again);
    defer testing.allocator.free(text2);
    try testing.expectEqualStrings(text, text2);
    try testing.expect(again.check("u1", "read", "/a,b").isPermit());
    try testing.expectError(error.ConflictingRole, again.assignRole("u1", " padded "));
    try testing.expect(again.roles.contains("lonely"));
}

test "policy: errors carry the line; a bad line anywhere stops before anything is applied" {
    var diag: Diag = .{};
    var e = Engine.init(testing.allocator);
    defer e.deinit();
    try testing.expectError(error.InvalidPolicy, e.loadPolicy("r, a\np, a, /x\n", &diag));
    try testing.expectEqual(@as(usize, 2), diag.line);
    try testing.expectEqual(@as(usize, 0), e.roles.count()); // line 1 was not applied either
    try testing.expectError(error.InvalidPolicy, e.loadPolicy("x, a\n", &diag));
    try testing.expectError(error.InvalidPolicy, e.loadPolicy("r, \"a\n", &diag)); // unterminated quote
    try testing.expectError(error.InvalidPolicy, e.loadPolicy("r, \"a\" b\n", &diag)); // text after the quote
    try testing.expectError(error.InvalidPolicy, e.loadPolicy("r, a, b\n", &diag)); // too many fields
    try testing.expectError(error.InvalidPolicy, e.loadPolicy("r, a, b\n", null));

    // Semantic errors name their line; fromPolicy leaves nothing behind (the leak check proves it).
    try testing.expectError(error.CyclicHierarchy, Engine.fromPolicy(testing.allocator, .exact, "g2, a, b\n# c\ng2, b, a\n", &diag));
    try testing.expectEqual(@as(usize, 3), diag.line);
    try testing.expectError(error.ConflictingRole, Engine.fromPolicy(testing.allocator, .exact, "sod, a, b\ng, u, a\ng, u, b\n", &diag));
    try testing.expectEqual(@as(usize, 3), diag.line);
}

test "policy: a name with a line break cannot be saved, and nothing is written" {
    var e = Engine.init(testing.allocator);
    defer e.deinit();
    try e.addRole("ok");
    try e.addRole("two\nlines");
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try testing.expectError(error.Unrepresentable, e.savePolicy(&aw.writer));
    try testing.expectEqual(@as(usize, 0), aw.written().len);
}

const tenants =
    \\p, admin, acme, /billing, read
    \\p, admin, globex, /reports, read
    \\g, alice, admin, acme
    \\g, alice, viewer, globex
    \\g2, admin, viewer, acme
    \\p, viewer, globex, /dash, read
    \\sod, admin, viewer, globex
;

test "domains: roles, permissions and hierarchy are per tenant; unknown tenants deny" {
    var d = try Domains.fromPolicy(testing.allocator, .exact, tenants, null);
    defer d.deinit();
    try testing.expect(d.check("acme", "alice", "read", "/billing").isPermit());
    try testing.expect(!d.check("acme", "alice", "read", "/reports").isPermit());
    // In globex alice is only a viewer.
    try testing.expect(d.check("globex", "alice", "read", "/dash").isPermit());
    try testing.expect(!d.check("globex", "alice", "read", "/reports").isPermit());
    try testing.expect(!d.check("globex", "alice", "read", "/billing").isPermit());
    // Another tenant knows neither alice nor the roles.
    try testing.expect(!d.check("initech", "alice", "read", "/billing").isPermit());
    try testing.expect(d.get("initech") == null);
    // The SoD pair of globex does not constrain acme.
    const acme = d.get("acme").?;
    try acme.assignRole("alice", "viewer");
    try testing.expectError(error.ConflictingRole, d.get("globex").?.assignRole("alice", "admin"));
}

test "domains: save then load is a fixed point; removeDomain drops a tenant" {
    var d = try Domains.fromPolicy(testing.allocator, .exact, tenants, null);
    defer d.deinit();
    const text = try saved(&d);
    defer testing.allocator.free(text);
    // Casbin's column order: `p, role, domain, resource, action`.
    try testing.expect(std.mem.find(u8, text, "p, admin, acme, /billing, read\n") != null);
    try testing.expect(std.mem.find(u8, text, "g, alice, admin, acme\n") != null);
    var again = try Domains.fromPolicy(testing.allocator, .exact, text, null);
    defer again.deinit();
    const text2 = try saved(&again);
    defer testing.allocator.free(text2);
    try testing.expectEqualStrings(text, text2);

    try testing.expect(again.removeDomain("acme"));
    try testing.expect(!again.removeDomain("acme"));
    try testing.expect(!again.check("acme", "alice", "read", "/billing").isPermit());
    try testing.expect(again.check("globex", "alice", "read", "/dash").isPermit());
    // A domain file needs the domain field; a plain file does not accept one.
    try testing.expectError(error.InvalidPolicy, Domains.fromPolicy(testing.allocator, .exact, "r, a\n", null));
    try testing.expectError(error.InvalidPolicy, Engine.fromPolicy(testing.allocator, .exact, "r, a, acme\n", null));
}
