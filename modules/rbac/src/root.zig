// SPDX-License-Identifier: MIT
//! rbac — authorization decision engine: RBAC (role-based) + ABAC
//! (attribute-based access control).
//!
//! Two independent, composable models sharing one `Decision` result shape:
//!
//!   * `rbac.Engine` — NIST RBAC core + hierarchical RBAC (INCITS 359-2012):
//!     roles, permissions, user→role assignment, role→role seniority
//!     (senior roles inherit junior permissions, cycle-checked at insert
//!     time), and static separation-of-duty (a user may never hold two
//!     roles declared mutually exclusive). Every add has a remove
//!     (`unassignRole`, `removePermission`, `removeRole`, `removeHierarchy`).
//!   * `abac` — a small, depth-bounded policy-expression evaluator: a typed
//!     condition tree (`Eq`/`Ne`/`Lt`/`Le`/`Gt`/`Ge`/`In`/`And`/`Or`/`Not`)
//!     over `{subject, resource, action, environment}` attributes, combined
//!     across a rule set with an XACML-style combining algorithm
//!     (`deny_overrides` default, `permit_overrides` also supported).
//!
//! This is a decision engine, not a persistence layer: both models are
//! built/loaded into memory by the caller (`rbac.Engine` owns its own
//! duped strings and frees them on removal; `abac.Policy`/`abac.Attributes` borrow
//! whatever the caller passes in and must outlive the `evaluate` call).
//!
//! No crypto, no I/O, no external policy-file format — see SPEC.md for what
//! is deliberately out of scope (dynamic/session SoD, full XACML request
//! context, a string policy DSL).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Authorization decision engine — NIST RBAC (hierarchical + static SoD) and a depth-bounded ABAC condition-tree evaluator with structural default-deny",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure in-memory logic, no OS calls
    .role = .util,
    .concurrency = .reentrant, // no shared global state; caller owns each Engine/Policy/Attributes instance
    .model_after = "NIST RBAC core + hierarchical RBAC (INCITS 359-2012); XACML 3.0 combining algorithms for the ABAC half",
    .deps = .{}, // std only
};

// ── shared decision shape ───────────────────────────────────────────────────

/// Binary authorization result. Default-deny is structural: the only way to
/// get `.permit` is an explicit matching grant/rule; everything else —
/// unknown subject, no matching rule, a bounded-evaluation error — comes
/// back `.deny`. See `abac.RuleOutcome`/`abac.evaluateDetailed` for the
/// richer XACML four-valued view (Permit/Deny/NotApplicable/Indeterminate)
/// used internally by the ABAC combining algorithms and available to
/// callers that want to log *why* a Deny happened.
pub const Result = enum { permit, deny };

/// Unified decision returned by both `rbac.Engine.check` and `abac.evaluate`
/// — one shape callers can log/branch on regardless of which model decided.
pub const Decision = struct {
    result: Result,
    /// Borrowed, human-readable reason for logging/audit — never allocated.
    /// Either a `root.zig` string literal or a caller-owned id (an
    /// `abac.Rule.id`, valid as long as the `Policy` outlives the call; an
    /// `rbac` role name, valid as long as the `Engine` outlives the call).
    reason: []const u8,

    pub fn isPermit(self: Decision) bool {
        return self.result == .permit;
    }
};

fn permit(reason: []const u8) Decision {
    return .{ .result = .permit, .reason = reason };
}
fn deny(reason: []const u8) Decision {
    return .{ .result = .deny, .reason = reason };
}

// ── RBAC: role-based access control ─────────────────────────────────────────

pub const rbac = struct {
    pub const Permission = struct {
        action: []const u8,
        resource: []const u8,
    };

    pub const Error = error{
        OutOfMemory,
        UnknownRole,
        CyclicHierarchy,
        ConflictingRole,
    };

    const RoleData = struct {
        permissions: std.ArrayListUnmanaged(Permission) = .empty,
        /// Direct junior roles: this role inherits their permissions,
        /// transitively — "senior roles inherit junior permissions".
        juniors: std.ArrayListUnmanaged([]const u8) = .empty,

        fn deinit(self: *RoleData, gpa: Allocator) void {
            for (self.permissions.items) |p| {
                gpa.free(p.action);
                gpa.free(p.resource);
            }
            self.permissions.deinit(gpa);
            for (self.juniors.items) |j| gpa.free(j);
            self.juniors.deinit(gpa);
        }
    };

    const SoDPair = struct { a: []const u8, b: []const u8 };

    /// The set of role names directly assigned to one user (keys owned).
    const RoleSet = std.StringHashMapUnmanaged(void);

    /// In-memory RBAC engine: roles, permissions, hierarchy, user
    /// assignments, static separation-of-duty. Every string handed to a
    /// mutating method is duped into an individually owned allocation, so
    /// callers never need to keep their arguments alive, and every removal
    /// (`unassignRole`, `removePermission`, `removeRole`, `removeHierarchy`,
    /// `removeStaticSoD`) frees what it drops — memory tracks the LIVE
    /// policy, not the history of changes. `deinit` frees everything.
    ///
    /// Every add operation is idempotent (re-adding something present is a
    /// no-op that allocates nothing), so repeated add/remove of the same
    /// item cannot grow the engine.
    pub const Engine = struct {
        gpa: Allocator,
        roles: std.StringHashMapUnmanaged(RoleData) = .empty,
        /// user -> set of directly assigned role names. A user with no
        /// remaining roles has NO entry (removed with its last role).
        assignments: std.StringHashMapUnmanaged(RoleSet) = .empty,
        sod: std.ArrayListUnmanaged(SoDPair) = .empty,

        pub fn init(allocator: Allocator) Engine {
            return .{ .gpa = allocator };
        }

        pub fn deinit(self: *Engine) void {
            const gpa = self.gpa;
            var rit = self.roles.iterator();
            while (rit.next()) |e| {
                gpa.free(e.key_ptr.*);
                e.value_ptr.deinit(gpa);
            }
            self.roles.deinit(gpa);
            var ait = self.assignments.iterator();
            while (ait.next()) |e| {
                gpa.free(e.key_ptr.*);
                freeRoleSet(gpa, e.value_ptr);
            }
            self.assignments.deinit(gpa);
            for (self.sod.items) |p| {
                gpa.free(p.a);
                gpa.free(p.b);
            }
            self.sod.deinit(gpa);
            self.* = undefined;
        }

        fn freeRoleSet(gpa: Allocator, set: *RoleSet) void {
            var it = set.keyIterator();
            while (it.next()) |k| gpa.free(k.*);
            set.deinit(gpa);
        }

        fn dupe(self: *Engine, s: []const u8) Error![]const u8 {
            return try self.gpa.dupe(u8, s);
        }

        /// Idempotent: re-adding a known role name is a no-op.
        pub fn addRole(self: *Engine, name: []const u8) Error!void {
            if (self.roles.contains(name)) return;
            const owned = try self.dupe(name);
            errdefer self.gpa.free(owned);
            try self.roles.put(self.gpa, owned, .{});
        }

        /// Idempotent: granting a permission the role already holds
        /// directly is a no-op.
        pub fn addPermission(self: *Engine, role: []const u8, perm: Permission) Error!void {
            const rd = self.roles.getPtr(role) orelse return error.UnknownRole;
            if (self.roleGrantsDirect(role, perm.action, perm.resource)) return;
            const action = try self.dupe(perm.action);
            errdefer self.gpa.free(action);
            const resource = try self.dupe(perm.resource);
            errdefer self.gpa.free(resource);
            try rd.permissions.append(self.gpa, .{ .action = action, .resource = resource });
        }

        /// Revoke the direct grant `perm` from `role`. Returns `true` if the
        /// grant was present, `false` if the role never held it (no-op).
        /// Only the DIRECT grant is removed: a senior role that also
        /// reaches the same permission through another junior keeps it.
        /// `error.UnknownRole` if `role` does not exist.
        pub fn removePermission(self: *Engine, role: []const u8, perm: Permission) error{UnknownRole}!bool {
            const rd = self.roles.getPtr(role) orelse return error.UnknownRole;
            var removed = false;
            var i: usize = 0;
            while (i < rd.permissions.items.len) {
                const p = rd.permissions.items[i];
                if (std.mem.eql(u8, p.action, perm.action) and std.mem.eql(u8, p.resource, perm.resource)) {
                    self.gpa.free(p.action);
                    self.gpa.free(p.resource);
                    _ = rd.permissions.orderedRemove(i);
                    removed = true;
                } else i += 1;
            }
            return removed;
        }

        /// `senior` inherits every permission `junior` has, directly and
        /// transitively (hierarchical RBAC). Rejects a self-edge or an edge
        /// that would close a cycle (`error.CyclicHierarchy`) — checked
        /// BEFORE the edge is added, so the juniors graph is always a DAG
        /// and permission resolution (`check`) never needs its own cycle
        /// guard. Idempotent: an existing edge is a no-op.
        pub fn addHierarchy(self: *Engine, senior: []const u8, junior: []const u8) Error!void {
            if (!self.roles.contains(senior)) return error.UnknownRole;
            if (!self.roles.contains(junior)) return error.UnknownRole;
            if (std.mem.eql(u8, senior, junior)) return error.CyclicHierarchy;
            const rd = self.roles.getPtr(senior).?;
            for (rd.juniors.items) |j| {
                if (std.mem.eql(u8, j, junior)) return;
            }
            if (try self.reachable(junior, senior)) return error.CyclicHierarchy;
            const owned = try self.dupe(junior);
            errdefer self.gpa.free(owned);
            try rd.juniors.append(self.gpa, owned);
        }

        /// Drop the direct inheritance edge `senior` -> `junior`. Returns
        /// `true` if the edge existed, `false` otherwise (no-op). Only that
        /// one edge goes: permissions `senior` still reaches through another
        /// path (a diamond) are kept; everything reachable only through the
        /// edge is revoked transitively — `check` walks the live graph, there
        /// is no cached closure to go stale. `error.UnknownRole` if either
        /// role does not exist.
        pub fn removeHierarchy(self: *Engine, senior: []const u8, junior: []const u8) error{UnknownRole}!bool {
            const rd = self.roles.getPtr(senior) orelse return error.UnknownRole;
            if (!self.roles.contains(junior)) return error.UnknownRole;
            for (rd.juniors.items, 0..) |j, i| {
                if (std.mem.eql(u8, j, junior)) {
                    self.gpa.free(j);
                    _ = rd.juniors.orderedRemove(i);
                    return true;
                }
            }
            return false;
        }

        /// Iterative DFS over the juniors graph: is `to` reachable from `from`?
        fn reachable(self: *Engine, from: []const u8, to: []const u8) Error!bool {
            var arena = std.heap.ArenaAllocator.init(self.gpa);
            defer arena.deinit();
            const scratch = arena.allocator();
            var visited: std.StringHashMapUnmanaged(void) = .empty;
            var stack: std.ArrayListUnmanaged([]const u8) = .empty;
            try stack.append(scratch, from);
            while (stack.pop()) |cur| {
                if (std.mem.eql(u8, cur, to)) return true;
                if (visited.contains(cur)) continue;
                try visited.put(scratch, cur, {});
                const rd = self.roles.get(cur) orelse continue;
                for (rd.juniors.items) |j| try stack.append(scratch, j);
            }
            return false;
        }

        /// Static separation-of-duty: `role_a` and `role_b` may never both
        /// be assigned to the same user. Dynamic (session-based) SoD is out
        /// of scope for this module — see SPEC.md. Idempotent (either
        /// order). Declaring a pair does not inspect existing assignments.
        pub fn addStaticSoD(self: *Engine, role_a: []const u8, role_b: []const u8) Error!void {
            if (!self.roles.contains(role_a)) return error.UnknownRole;
            if (!self.roles.contains(role_b)) return error.UnknownRole;
            if (self.conflicts(role_a, role_b)) return;
            const a = try self.dupe(role_a);
            errdefer self.gpa.free(a);
            const b = try self.dupe(role_b);
            errdefer self.gpa.free(b);
            try self.sod.append(self.gpa, .{ .a = a, .b = b });
        }

        /// Lift a static SoD declaration (either order). Returns `true` if
        /// the pair was declared. Existing assignments are untouched.
        /// `error.UnknownRole` if either role does not exist.
        pub fn removeStaticSoD(self: *Engine, role_a: []const u8, role_b: []const u8) error{UnknownRole}!bool {
            if (!self.roles.contains(role_a)) return error.UnknownRole;
            if (!self.roles.contains(role_b)) return error.UnknownRole;
            var removed = false;
            var i: usize = 0;
            while (i < self.sod.items.len) {
                const pair = self.sod.items[i];
                if ((std.mem.eql(u8, pair.a, role_a) and std.mem.eql(u8, pair.b, role_b)) or
                    (std.mem.eql(u8, pair.a, role_b) and std.mem.eql(u8, pair.b, role_a)))
                {
                    self.gpa.free(pair.a);
                    self.gpa.free(pair.b);
                    _ = self.sod.orderedRemove(i);
                    removed = true;
                } else i += 1;
            }
            return removed;
        }

        fn conflicts(self: *const Engine, a: []const u8, b: []const u8) bool {
            for (self.sod.items) |pair| {
                if ((std.mem.eql(u8, pair.a, a) and std.mem.eql(u8, pair.b, b)) or
                    (std.mem.eql(u8, pair.a, b) and std.mem.eql(u8, pair.b, a))) return true;
            }
            return false;
        }

        /// Assign `role` to `user`. Rejects (`error.ConflictingRole`) if the
        /// user already holds a role declared statically mutually exclusive
        /// with `role`. Idempotent for an existing assignment.
        pub fn assignRole(self: *Engine, user: []const u8, role: []const u8) Error!void {
            if (!self.roles.contains(role)) return error.UnknownRole;
            if (self.assignments.getPtr(user)) |existing| {
                var it = existing.keyIterator();
                while (it.next()) |held| {
                    if (self.conflicts(held.*, role)) return error.ConflictingRole;
                }
                if (existing.contains(role)) return;
                const r = try self.dupe(role);
                errdefer self.gpa.free(r);
                try existing.put(self.gpa, r, {});
                return;
            }
            const u = try self.dupe(user);
            errdefer self.gpa.free(u);
            const r = try self.dupe(role);
            errdefer self.gpa.free(r);
            var set: RoleSet = .empty;
            errdefer set.deinit(self.gpa);
            try set.put(self.gpa, r, {});
            try self.assignments.put(self.gpa, u, set);
        }

        /// Take `role` away from `user`. Returns `true` if the user held it
        /// directly, `false` otherwise (no-op). A user's last role removes
        /// the user's entry entirely. Roles the user still reaches through
        /// the hierarchy of another assigned role are unaffected.
        /// `error.UnknownRole` if `role` does not exist (mirrors
        /// `assignRole`; a role deleted by `removeRole` is no longer known).
        pub fn unassignRole(self: *Engine, user: []const u8, role: []const u8) error{UnknownRole}!bool {
            if (!self.roles.contains(role)) return error.UnknownRole;
            const set = self.assignments.getPtr(user) orelse return false;
            const kv = set.fetchRemove(role) orelse return false;
            self.gpa.free(kv.key);
            if (set.count() == 0) {
                var removed = self.assignments.fetchRemove(user).?;
                freeRoleSet(self.gpa, &removed.value);
                self.gpa.free(removed.key);
            }
            return true;
        }

        /// NIST `DeleteRole`: delete `name` and everything that refers to
        /// it — its direct permissions, every assignment of it to a user
        /// (users left with no roles are dropped), every hierarchy edge into
        /// or out of it, and every static SoD pair naming it. Cascade, not
        /// refuse. Inheritance is NOT bridged: with A > B > C, deleting B
        /// leaves A without C (add `addHierarchy(A, C)` first to keep it).
        /// Other roles are otherwise unaffected. `error.UnknownRole` if the
        /// role does not exist. Cannot fail with OutOfMemory (frees only).
        pub fn removeRole(self: *Engine, name: []const u8) error{UnknownRole}!void {
            const gpa = self.gpa;
            var kv = self.roles.fetchRemove(name) orelse return error.UnknownRole;
            kv.value.deinit(gpa);
            gpa.free(kv.key);

            // Hierarchy edges into the role.
            var rit = self.roles.valueIterator();
            while (rit.next()) |rd| {
                var i: usize = 0;
                while (i < rd.juniors.items.len) {
                    const j = rd.juniors.items[i];
                    if (std.mem.eql(u8, j, name)) {
                        gpa.free(j);
                        _ = rd.juniors.orderedRemove(i);
                    } else i += 1;
                }
            }

            // Assignments; drop users left without roles. Removing the
            // current entry during iteration is safe: removal only marks
            // the slot, it never moves or reallocates.
            var ait = self.assignments.iterator();
            while (ait.next()) |e| {
                if (e.value_ptr.fetchRemove(name)) |k| gpa.free(k.key);
                if (e.value_ptr.count() == 0) {
                    const user = e.key_ptr.*;
                    freeRoleSet(gpa, e.value_ptr);
                    self.assignments.removeByPtr(e.key_ptr);
                    gpa.free(user);
                }
            }

            // SoD pairs naming the role.
            var i: usize = 0;
            while (i < self.sod.items.len) {
                const pair = self.sod.items[i];
                if (std.mem.eql(u8, pair.a, name) or std.mem.eql(u8, pair.b, name)) {
                    gpa.free(pair.a);
                    gpa.free(pair.b);
                    _ = self.sod.orderedRemove(i);
                } else i += 1;
            }
        }

        fn roleGrantsDirect(self: *const Engine, role: []const u8, action: []const u8, resource: []const u8) bool {
            const rd = self.roles.get(role) orelse return false;
            for (rd.permissions.items) |p| {
                if (std.mem.eql(u8, p.action, action) and std.mem.eql(u8, p.resource, resource)) return true;
            }
            return false;
        }

        /// Does `role` grant this permission via an inherited (junior)
        /// role? Safe to recurse: `addHierarchy` guarantees the juniors
        /// graph is acyclic.
        fn roleGrantsTransitive(self: *const Engine, role: []const u8, action: []const u8, resource: []const u8) bool {
            const rd = self.roles.get(role) orelse return false;
            for (rd.juniors.items) |j| {
                if (self.roleGrantsDirect(j, action, resource)) return true;
                if (self.roleGrantsTransitive(j, action, resource)) return true;
            }
            return false;
        }

        /// Resolve `user`'s assigned + inherited roles against
        /// `action`/`resource`. Default-deny: an unknown user, a user with
        /// no roles assigned, or a user whose roles (direct + inherited)
        /// don't cover this permission all return `.deny`.
        pub fn check(self: *const Engine, user: []const u8, action: []const u8, resource: []const u8) Decision {
            const held = self.assignments.getPtr(user) orelse
                return deny("no roles assigned to this user (default-deny)");
            var it = held.keyIterator();
            while (it.next()) |r| {
                if (self.roleGrantsDirect(r.*, action, resource)) return permit("granted directly by an assigned role");
            }
            it = held.keyIterator();
            while (it.next()) |r| {
                if (self.roleGrantsTransitive(r.*, action, resource)) return permit("granted via role hierarchy inheritance");
            }
            return deny("no assigned or inherited role grants this permission (default-deny)");
        }
    };
};

// ── ABAC: attribute-based access control ────────────────────────────────────

pub const abac = struct {
    pub const Category = enum { subject, resource, action, environment };

    /// Attribute values. `list` is used both as a literal RHS for `in` and
    /// as the type an attribute must hold to be the RHS of `in`.
    pub const Value = union(enum) {
        string: []const u8,
        int: i64,
        boolean: bool,
        list: []const Value,

        /// Type-checked equality; `null` = type mismatch (caller surfaces
        /// this as Indeterminate, never a silent `false`).
        fn eqlValue(a: Value, b: Value) ?bool {
            return switch (a) {
                .string => |sa| switch (b) {
                    .string => |sb| std.mem.eql(u8, sa, sb),
                    else => null,
                },
                .int => |ia| switch (b) {
                    .int => |ib| ia == ib,
                    else => null,
                },
                .boolean => |ba| switch (b) {
                    .boolean => |bb| ba == bb,
                    else => null,
                },
                .list => null, // lists compare only via `in`, never `eq`/`ne`
            };
        }

        /// Numeric ordering — only defined for `int`; `null` = type mismatch
        /// or an unorderable type (string/bool/list ordering is deliberately
        /// not supported, see SPEC.md).
        fn order(a: Value, b: Value) ?std.math.Order {
            return switch (a) {
                .int => |ia| switch (b) {
                    .int => |ib| std.math.order(ia, ib),
                    else => null,
                },
                else => null,
            };
        }
    };

    pub const AttrRef = struct {
        category: Category,
        name: []const u8,
    };

    pub const Operand = union(enum) {
        attr: AttrRef,
        literal: Value,
    };

    // ── typed builder API (no string DSL — see SPEC.md) ─────────────────────

    pub fn attr(category: Category, name: []const u8) AttrRef {
        return .{ .category = category, .name = name };
    }
    pub fn of(a: AttrRef) Operand {
        return .{ .attr = a };
    }
    pub fn lit(v: Value) Operand {
        return .{ .literal = v };
    }
    pub fn str(s: []const u8) Value {
        return .{ .string = s };
    }
    pub fn int(i: i64) Value {
        return .{ .int = i };
    }
    pub fn boolean(b: bool) Value {
        return .{ .boolean = b };
    }
    pub fn list(vs: []const Value) Value {
        return .{ .list = vs };
    }

    pub const Compare = struct { lhs: AttrRef, rhs: Operand };
    /// Membership test: `lhs`'s value must equal one element of `rhs`'s
    /// resolved value, which must itself be a `.list`.
    pub const In = struct { lhs: AttrRef, rhs: Operand };

    /// A typed condition-tree node. Built with the helper functions below
    /// (`eq`, `andAll`, …) rather than parsed from a string — see SPEC.md
    /// for why this module ships a typed AST, not a DSL parser.
    pub const Condition = union(enum) {
        eq: Compare,
        ne: Compare,
        lt: Compare,
        le: Compare,
        gt: Compare,
        ge: Compare,
        in: In,
        and_: []const Condition,
        or_: []const Condition,
        not: *const Condition,
    };

    pub fn eq(lhs: AttrRef, rhs: Operand) Condition {
        return .{ .eq = .{ .lhs = lhs, .rhs = rhs } };
    }
    pub fn ne(lhs: AttrRef, rhs: Operand) Condition {
        return .{ .ne = .{ .lhs = lhs, .rhs = rhs } };
    }
    pub fn lt(lhs: AttrRef, rhs: Operand) Condition {
        return .{ .lt = .{ .lhs = lhs, .rhs = rhs } };
    }
    pub fn le(lhs: AttrRef, rhs: Operand) Condition {
        return .{ .le = .{ .lhs = lhs, .rhs = rhs } };
    }
    pub fn gt(lhs: AttrRef, rhs: Operand) Condition {
        return .{ .gt = .{ .lhs = lhs, .rhs = rhs } };
    }
    pub fn ge(lhs: AttrRef, rhs: Operand) Condition {
        return .{ .ge = .{ .lhs = lhs, .rhs = rhs } };
    }
    pub fn inList(lhs: AttrRef, rhs: Operand) Condition {
        return .{ .in = .{ .lhs = lhs, .rhs = rhs } };
    }
    pub fn andAll(conds: []const Condition) Condition {
        return .{ .and_ = conds };
    }
    pub fn orAny(conds: []const Condition) Condition {
        return .{ .or_ = conds };
    }
    pub fn not(c: *const Condition) Condition {
        return .{ .not = c };
    }

    /// Attribute store for one evaluation request:
    /// `{subject, resource, action, environment}`, each a flat name→`Value`
    /// map. Borrows whatever `[]const u8`/`[]const Value` data the caller
    /// puts in — that data must outlive the `evaluate`/`evalCondition` call,
    /// same borrow contract as `Condition`.
    pub const Attributes = struct {
        subject: std.StringHashMapUnmanaged(Value) = .empty,
        resource: std.StringHashMapUnmanaged(Value) = .empty,
        action: std.StringHashMapUnmanaged(Value) = .empty,
        environment: std.StringHashMapUnmanaged(Value) = .empty,

        pub fn deinit(self: *Attributes, allocator: Allocator) void {
            self.subject.deinit(allocator);
            self.resource.deinit(allocator);
            self.action.deinit(allocator);
            self.environment.deinit(allocator);
            self.* = undefined;
        }

        pub fn put(self: *Attributes, allocator: Allocator, category: Category, name: []const u8, value: Value) Allocator.Error!void {
            const map: *std.StringHashMapUnmanaged(Value) = switch (category) {
                .subject => &self.subject,
                .resource => &self.resource,
                .action => &self.action,
                .environment => &self.environment,
            };
            try map.put(allocator, name, value);
        }

        pub fn get(self: *const Attributes, ref: AttrRef) ?Value {
            return switch (ref.category) {
                .subject => self.subject.get(ref.name),
                .resource => self.resource.get(ref.name),
                .action => self.action.get(ref.name),
                .environment => self.environment.get(ref.name),
            };
        }
    };

    pub const EvalError = error{
        /// Condition tree recursed past `Policy.max_depth` — the DoS bound
        /// (adversarially deep And/Or/Not nesting cannot exhaust the stack).
        MaxDepthExceeded,
        /// A `Condition` referenced an attribute not present in `Attributes`.
        MissingAttribute,
        /// Compared/ordered two `Value`s of incompatible kinds (or ordered a
        /// non-`int`, or used `in` against a non-`list` RHS).
        TypeMismatch,
    };

    pub const default_max_depth: u32 = 32;

    fn resolveOperand(op: Operand, attrs: *const Attributes) EvalError!Value {
        return switch (op) {
            .literal => |v| v,
            .attr => |a| attrs.get(a) orelse error.MissingAttribute,
        };
    }

    fn evalCompareOp(comptime kind: enum { eq, ne, lt, le, gt, ge }, c: Compare, attrs: *const Attributes) EvalError!bool {
        const lv = attrs.get(c.lhs) orelse return error.MissingAttribute;
        const rv = try resolveOperand(c.rhs, attrs);
        switch (kind) {
            .eq => return Value.eqlValue(lv, rv) orelse error.TypeMismatch,
            .ne => return !(Value.eqlValue(lv, rv) orelse return error.TypeMismatch),
            .lt, .le, .gt, .ge => {
                const ord = Value.order(lv, rv) orelse return error.TypeMismatch;
                return switch (kind) {
                    .lt => ord == .lt,
                    .le => ord != .gt,
                    .gt => ord == .gt,
                    .ge => ord != .lt,
                    else => unreachable,
                };
            },
        }
    }

    fn evalIn(c: In, attrs: *const Attributes) EvalError!bool {
        const lv = attrs.get(c.lhs) orelse return error.MissingAttribute;
        const rv = try resolveOperand(c.rhs, attrs);
        const items = switch (rv) {
            .list => |l| l,
            else => return error.TypeMismatch,
        };
        for (items) |item| {
            if (Value.eqlValue(lv, item) orelse false) return true;
        }
        return false;
    }

    /// Bounded-depth evaluation of a condition tree against `attrs`.
    pub fn evalCondition(cond: Condition, attrs: *const Attributes, max_depth: u32) EvalError!bool {
        return evalConditionDepth(cond, attrs, 0, max_depth);
    }

    fn evalConditionDepth(cond: Condition, attrs: *const Attributes, depth: u32, max_depth: u32) EvalError!bool {
        if (depth > max_depth) return error.MaxDepthExceeded;
        return switch (cond) {
            .eq => |c| evalCompareOp(.eq, c, attrs),
            .ne => |c| evalCompareOp(.ne, c, attrs),
            .lt => |c| evalCompareOp(.lt, c, attrs),
            .le => |c| evalCompareOp(.le, c, attrs),
            .gt => |c| evalCompareOp(.gt, c, attrs),
            .ge => |c| evalCompareOp(.ge, c, attrs),
            .in => |c| evalIn(c, attrs),
            .and_ => |conds| blk: {
                for (conds) |sub| {
                    if (!(try evalConditionDepth(sub, attrs, depth + 1, max_depth))) break :blk false;
                }
                break :blk true;
            },
            .or_ => |conds| blk: {
                for (conds) |sub| {
                    if (try evalConditionDepth(sub, attrs, depth + 1, max_depth)) break :blk true;
                }
                break :blk false;
            },
            .not => |sub| !(try evalConditionDepth(sub.*, attrs, depth + 1, max_depth)),
        };
    }

    pub const Effect = enum { permit, deny };

    pub const Rule = struct {
        /// Logged in `Decision.reason` — pick something greppable.
        id: []const u8,
        effect: Effect,
        condition: Condition,
    };

    /// XACML-style combining algorithm for a rule set.
    pub const CombiningAlgorithm = enum { deny_overrides, permit_overrides };

    pub const Policy = struct {
        rules: []const Rule,
        /// Default `.deny_overrides` — a Deny anywhere in the rule set wins
        /// even if other rules Permit; see SPEC.md for why this is the
        /// recommended default over `.permit_overrides`.
        algorithm: CombiningAlgorithm = .deny_overrides,
        max_depth: u32 = default_max_depth,
    };

    /// Full XACML four-valued rule/policy outcome. `evaluate` collapses
    /// this to the binary `Decision` most callers want; `evaluateDetailed`
    /// exposes it directly for auditors who want to distinguish "no rule
    /// matched" from "a rule errored" from an explicit Deny.
    pub const RuleOutcome = enum { permit, deny, not_applicable, indeterminate };

    pub const DetailedDecision = struct {
        outcome: RuleOutcome,
        reason: []const u8,
    };

    fn reasonForErr(err: EvalError) []const u8 {
        return switch (err) {
            error.MaxDepthExceeded => "indeterminate: condition tree exceeded max evaluation depth",
            error.MissingAttribute => "indeterminate: referenced attribute not present",
            error.TypeMismatch => "indeterminate: operand type mismatch",
        };
    }

    /// One rule's outcome against a specific evaluation:
    ///   - condition true  → the rule's effect fires (Permit or Deny)
    ///   - condition false → NotApplicable (this rule abstains)
    ///   - evaluation error → Indeterminate
    fn evalRuleDetailed(rule: Rule, attrs: *const Attributes, max_depth: u32) DetailedDecision {
        const matched = evalCondition(rule.condition, attrs, max_depth) catch |err| {
            return .{ .outcome = .indeterminate, .reason = reasonForErr(err) };
        };
        if (!matched) return .{ .outcome = .not_applicable, .reason = rule.id };
        return .{
            .outcome = if (rule.effect == .permit) .permit else .deny,
            .reason = rule.id,
        };
    }

    fn combineDenyOverrides(rules: []const Rule, attrs: *const Attributes, max_depth: u32) DetailedDecision {
        var saw_permit: ?DetailedDecision = null;
        var saw_indeterminate: ?DetailedDecision = null;
        for (rules) |rule| {
            const d = evalRuleDetailed(rule, attrs, max_depth);
            switch (d.outcome) {
                .deny => return d, // Deny always wins immediately
                .permit => if (saw_permit == null) {
                    saw_permit = d;
                },
                .indeterminate => if (saw_indeterminate == null) {
                    saw_indeterminate = d;
                },
                .not_applicable => {},
            }
        }
        if (saw_indeterminate) |d| return d;
        if (saw_permit) |d| return d;
        return .{ .outcome = .not_applicable, .reason = "no rule matched" };
    }

    fn combinePermitOverrides(rules: []const Rule, attrs: *const Attributes, max_depth: u32) DetailedDecision {
        var saw_deny: ?DetailedDecision = null;
        var saw_indeterminate: ?DetailedDecision = null;
        for (rules) |rule| {
            const d = evalRuleDetailed(rule, attrs, max_depth);
            switch (d.outcome) {
                .permit => return d, // Permit always wins immediately
                .deny => if (saw_deny == null) {
                    saw_deny = d;
                },
                .indeterminate => if (saw_indeterminate == null) {
                    saw_indeterminate = d;
                },
                .not_applicable => {},
            }
        }
        if (saw_indeterminate) |d| return d;
        if (saw_deny) |d| return d;
        return .{ .outcome = .not_applicable, .reason = "no rule matched" };
    }

    /// The full XACML four-valued combining result — see `RuleOutcome`.
    pub fn evaluateDetailed(policy: Policy, attrs: *const Attributes) DetailedDecision {
        return switch (policy.algorithm) {
            .deny_overrides => combineDenyOverrides(policy.rules, attrs, policy.max_depth),
            .permit_overrides => combinePermitOverrides(policy.rules, attrs, policy.max_depth),
        };
    }

    /// Binary default-deny decision: only an explicit Permit rule firing
    /// authorizes. NotApplicable (no rule matched) and Indeterminate
    /// (evaluation error — depth bound, missing attribute, type mismatch)
    /// both collapse to Deny, the module's one fail-safe rule.
    pub fn evaluate(policy: Policy, attrs: *const Attributes) Decision {
        const d = evaluateDetailed(policy, attrs);
        return switch (d.outcome) {
            .permit => .{ .result = .permit, .reason = d.reason },
            .deny => .{ .result = .deny, .reason = d.reason },
            .not_applicable => .{ .result = .deny, .reason = "default-deny: no rule matched" },
            .indeterminate => .{ .result = .deny, .reason = d.reason },
        };
    }
};

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

// -- RBAC --------------------------------------------------------------------

fn buildBasicEngine(a: Allocator) !rbac.Engine {
    var e = rbac.Engine.init(a);
    try e.addRole("viewer");
    try e.addRole("editor");
    try e.addPermission("viewer", .{ .action = "read", .resource = "doc" });
    try e.addPermission("editor", .{ .action = "write", .resource = "doc" });
    return e;
}

test "rbac: direct grant permits" {
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();
    try e.assignRole("alice", "viewer");

    const d = e.check("alice", "read", "doc");
    try testing.expectEqual(Result.permit, d.result);
}

test "rbac: direct grant sibling — wrong action denies" {
    // Minimal flip of the above: same assignment, action the role does NOT hold.
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();
    try e.assignRole("alice", "viewer");

    const d = e.check("alice", "write", "doc");
    try testing.expectEqual(Result.deny, d.result);
}

test "rbac: inherited grant through hierarchy permits" {
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();
    // editor is senior to viewer -> editor inherits viewer's "read doc".
    try e.addHierarchy("editor", "viewer");
    try e.assignRole("bob", "editor");

    const d = e.check("bob", "read", "doc");
    try testing.expectEqual(Result.permit, d.result);
    try testing.expect(std.mem.indexOf(u8, d.reason, "hierarchy") != null);
}

test "rbac: inherited grant sibling — without hierarchy edge denies" {
    // Minimal flip: identical setup, but the hierarchy edge is never added.
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();
    try e.assignRole("bob", "editor");

    const d = e.check("bob", "read", "doc");
    try testing.expectEqual(Result.deny, d.result);
}

test "rbac: denial when unassigned" {
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();

    const d = e.check("nobody", "read", "doc");
    try testing.expectEqual(Result.deny, d.result);
}

test "rbac: denial sibling — assigning the role flips it to permit" {
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();
    try testing.expectEqual(Result.deny, e.check("carol", "read", "doc").result);

    try e.assignRole("carol", "viewer");
    try testing.expectEqual(Result.permit, e.check("carol", "read", "doc").result);
}

test "rbac: cycle detection rejects a cyclic hierarchy" {
    var e = rbac.Engine.init(testing.allocator);
    defer e.deinit();
    try e.addRole("a");
    try e.addRole("b");
    try e.addRole("c");
    try e.addHierarchy("a", "b"); // a senior-of b
    try e.addHierarchy("b", "c"); // b senior-of c
    // c -> a would close the cycle a -> b -> c -> a.
    try testing.expectError(error.CyclicHierarchy, e.addHierarchy("c", "a"));
    // A direct self-edge is rejected too.
    try testing.expectError(error.CyclicHierarchy, e.addHierarchy("a", "a"));
}

test "rbac: cycle detection sibling — a non-cyclic edge succeeds" {
    // Minimal flip: same chain, but an edge that does NOT close a cycle.
    var e = rbac.Engine.init(testing.allocator);
    defer e.deinit();
    try e.addRole("a");
    try e.addRole("b");
    try e.addRole("c");
    try e.addHierarchy("a", "b");
    try e.addHierarchy("b", "c");
    try e.addRole("d");
    try e.addHierarchy("d", "a"); // d senior-of a: extends the DAG, no cycle
}

test "rbac: static SoD rejects a conflicting assignment" {
    var e = rbac.Engine.init(testing.allocator);
    defer e.deinit();
    try e.addRole("payer");
    try e.addRole("approver");
    try e.addStaticSoD("payer", "approver");
    try e.assignRole("dave", "payer");

    try testing.expectError(error.ConflictingRole, e.assignRole("dave", "approver"));
    // Order independence: the reverse direction is also caught for a fresh user.
    try e.assignRole("erin", "approver");
    try testing.expectError(error.ConflictingRole, e.assignRole("erin", "payer"));
}

test "rbac: static SoD sibling — a non-conflicting role assigns fine" {
    // Minimal flip: same SoD pair, but assigning an unrelated third role.
    var e = rbac.Engine.init(testing.allocator);
    defer e.deinit();
    try e.addRole("payer");
    try e.addRole("approver");
    try e.addRole("viewer");
    try e.addStaticSoD("payer", "approver");
    try e.assignRole("dave", "payer");

    try e.assignRole("dave", "viewer"); // no conflict declared with "viewer"
}

test "rbac: addRole is idempotent — re-adding a known role does not wipe its permissions" {
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();
    try e.assignRole("alice", "viewer");
    try testing.expectEqual(Result.permit, e.check("alice", "read", "doc").result);

    // Documented contract: "re-adding a known role name is a no-op."
    try e.addRole("viewer");
    try testing.expectEqual(Result.permit, e.check("alice", "read", "doc").result);
}

test "rbac: addPermission/addHierarchy/addStaticSoD reject an unknown role" {
    var e = rbac.Engine.init(testing.allocator);
    defer e.deinit();
    try e.addRole("known");

    try testing.expectError(error.UnknownRole, e.addPermission("ghost", .{ .action = "x", .resource = "y" }));
    try testing.expectError(error.UnknownRole, e.addHierarchy("known", "ghost"));
    try testing.expectError(error.UnknownRole, e.addHierarchy("ghost", "known"));
    try testing.expectError(error.UnknownRole, e.addStaticSoD("known", "ghost"));
    try testing.expectError(error.UnknownRole, e.assignRole("someone", "ghost"));
}

// -- RBAC: revoke / remove -----------------------------------------------------

fn expectPermit(e: *const rbac.Engine, user: []const u8, action: []const u8, resource: []const u8) !void {
    try testing.expectEqual(Result.permit, e.check(user, action, resource).result);
}
fn expectDeny(e: *const rbac.Engine, user: []const u8, action: []const u8, resource: []const u8) !void {
    try testing.expectEqual(Result.deny, e.check(user, action, resource).result);
}

test "rbac: unassignRole revokes the grant (sibling: other users and roles keep theirs)" {
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();
    try e.assignRole("alice", "viewer");
    try e.assignRole("alice", "editor");
    try e.assignRole("bob", "viewer");
    try expectPermit(&e, "alice", "read", "doc");

    try testing.expect(try e.unassignRole("alice", "viewer"));
    try expectDeny(&e, "alice", "read", "doc");
    try expectPermit(&e, "alice", "write", "doc"); // her other role stays
    try expectPermit(&e, "bob", "read", "doc"); // other users unaffected

    // Last role gone: the user is dropped, still default-deny.
    try testing.expect(try e.unassignRole("alice", "editor"));
    try expectDeny(&e, "alice", "write", "doc");
    try testing.expectEqual(@as(usize, 1), e.assignments.count());
    // Assign again after revoke works.
    try e.assignRole("alice", "viewer");
    try expectPermit(&e, "alice", "read", "doc");
}

test "rbac: unassignRole of a role held only via inheritance is a no-op" {
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();
    try e.addHierarchy("editor", "viewer");
    try e.assignRole("bob", "editor");
    try testing.expect(!(try e.unassignRole("bob", "viewer"))); // never assigned directly
    try expectPermit(&e, "bob", "read", "doc"); // inheritance intact
}

test "rbac: removePermission revokes the direct grant and inherited copies" {
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();
    try e.addPermission("viewer", .{ .action = "list", .resource = "doc" });
    try e.addHierarchy("editor", "viewer");
    try e.assignRole("alice", "viewer");
    try e.assignRole("bob", "editor");
    try expectPermit(&e, "alice", "read", "doc");
    try expectPermit(&e, "bob", "read", "doc");

    try testing.expect(try e.removePermission("viewer", .{ .action = "read", .resource = "doc" }));
    try expectDeny(&e, "alice", "read", "doc");
    try expectDeny(&e, "bob", "read", "doc"); // inherited copy gone too
    try expectPermit(&e, "alice", "list", "doc"); // sibling permission stays
    try expectPermit(&e, "bob", "write", "doc"); // senior's own permission stays
    // Only the exact (action, resource) pair goes.
    try e.addPermission("viewer", .{ .action = "read", .resource = "other" });
    try testing.expect(!(try e.removePermission("viewer", .{ .action = "read", .resource = "doc" })));
    try expectPermit(&e, "alice", "read", "other");
}

test "rbac: addPermission/addHierarchy/addStaticSoD are idempotent, one removal undoes them" {
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();
    try e.addPermission("viewer", .{ .action = "read", .resource = "doc" }); // duplicate
    try e.addHierarchy("editor", "viewer");
    try e.addHierarchy("editor", "viewer"); // duplicate
    try e.addStaticSoD("editor", "viewer");
    try e.addStaticSoD("viewer", "editor"); // duplicate, other order
    try testing.expectEqual(@as(usize, 1), e.roles.get("viewer").?.permissions.items.len);
    try testing.expectEqual(@as(usize, 1), e.roles.get("editor").?.juniors.items.len);
    try testing.expectEqual(@as(usize, 1), e.sod.items.len);

    try e.assignRole("bob", "editor");
    try testing.expect(try e.removePermission("viewer", .{ .action = "read", .resource = "doc" }));
    try expectDeny(&e, "bob", "read", "doc"); // a single removal fully revokes
    try testing.expect(try e.removeHierarchy("editor", "viewer"));
    try testing.expect(!(try e.removeHierarchy("editor", "viewer")));
    try testing.expect(try e.removeStaticSoD("viewer", "editor"));
    try testing.expect(!(try e.removeStaticSoD("editor", "viewer")));
}

test "rbac: removeRole cascades — assignments, permissions, edges, SoD; others unaffected" {
    var e = rbac.Engine.init(testing.allocator);
    defer e.deinit();
    for ([_][]const u8{ "admin", "editor", "viewer", "auditor" }) |r| try e.addRole(r);
    try e.addPermission("admin", .{ .action = "delete", .resource = "doc" });
    try e.addPermission("editor", .{ .action = "write", .resource = "doc" });
    try e.addPermission("viewer", .{ .action = "read", .resource = "doc" });
    try e.addPermission("auditor", .{ .action = "audit", .resource = "log" });
    try e.addHierarchy("admin", "editor");
    try e.addHierarchy("editor", "viewer");
    try e.addStaticSoD("editor", "auditor");
    try e.assignRole("alice", "editor"); // holds the doomed role only
    try e.assignRole("bob", "editor");
    try e.assignRole("bob", "viewer"); // holds another role too
    try e.assignRole("carol", "admin"); // reaches it only via hierarchy
    try e.assignRole("dave", "auditor");
    try expectPermit(&e, "carol", "write", "doc");

    try e.removeRole("editor");

    try testing.expect(!e.roles.contains("editor"));
    try expectDeny(&e, "alice", "write", "doc"); // former holder
    try expectDeny(&e, "alice", "read", "doc");
    try expectDeny(&e, "bob", "write", "doc");
    try expectPermit(&e, "bob", "read", "doc"); // bob's other role survives
    try expectDeny(&e, "carol", "write", "doc"); // inherited grant gone
    try expectPermit(&e, "carol", "delete", "doc"); // admin's own stays
    try expectDeny(&e, "carol", "read", "doc"); // not bridged through the hole
    try expectPermit(&e, "dave", "audit", "log"); // unrelated role unaffected
    try testing.expect(!e.assignments.contains("alice")); // user without roles dropped
    try testing.expectEqual(@as(usize, 0), e.roles.get("admin").?.juniors.items.len);
    try testing.expectEqual(@as(usize, 1), e.roles.get("viewer").?.permissions.items.len);
    try testing.expectEqual(@as(usize, 0), e.sod.items.len);
    // Assigning/unassigning the deleted role is now UnknownRole.
    try testing.expectError(error.UnknownRole, e.assignRole("alice", "editor"));
    try testing.expectError(error.UnknownRole, e.unassignRole("bob", "editor"));
    try testing.expectError(error.UnknownRole, e.addHierarchy("admin", "editor"));
    // Re-creating the name yields a fresh, empty role (nothing resurrected).
    try e.addRole("editor");
    try e.assignRole("erin", "editor");
    try expectDeny(&e, "erin", "write", "doc");
    try expectDeny(&e, "alice", "write", "doc");
    try e.assignRole("dave", "editor"); // the old editor/auditor SoD is gone
}

test "rbac: removeHierarchy in a chain A>B>C revokes C's permission from A" {
    var e = rbac.Engine.init(testing.allocator);
    defer e.deinit();
    for ([_][]const u8{ "a", "b", "c" }) |r| try e.addRole(r);
    try e.addPermission("c", .{ .action = "read", .resource = "c" });
    try e.addPermission("b", .{ .action = "read", .resource = "b" });
    try e.addHierarchy("a", "b");
    try e.addHierarchy("b", "c");
    try e.assignRole("u", "a");
    try expectPermit(&e, "u", "read", "c");
    try expectPermit(&e, "u", "read", "b");

    // Middle edge: A keeps B, loses C.
    try testing.expect(try e.removeHierarchy("b", "c"));
    try expectDeny(&e, "u", "read", "c");
    try expectPermit(&e, "u", "read", "b");

    // Sibling: the edge can be restored, and removing the TOP edge instead
    // drops both B and C from A.
    try e.addHierarchy("b", "c");
    try expectPermit(&e, "u", "read", "c");
    try testing.expect(try e.removeHierarchy("a", "b"));
    try expectDeny(&e, "u", "read", "c");
    try expectDeny(&e, "u", "read", "b");
    // Removal reopens what the cycle check forbade: c > a is now legal.
    try e.addHierarchy("c", "a");
}

test "rbac: removeHierarchy in a diamond keeps the permission reachable via the other path" {
    var e = rbac.Engine.init(testing.allocator);
    defer e.deinit();
    for ([_][]const u8{ "a", "b", "c", "d" }) |r| try e.addRole(r);
    try e.addPermission("d", .{ .action = "read", .resource = "d" });
    try e.addHierarchy("a", "b");
    try e.addHierarchy("a", "c");
    try e.addHierarchy("b", "d");
    try e.addHierarchy("c", "d");
    try e.assignRole("u", "a");

    try testing.expect(try e.removeHierarchy("a", "b"));
    try expectPermit(&e, "u", "read", "d"); // still via a > c > d
    try testing.expect(try e.removeHierarchy("a", "c"));
    try expectDeny(&e, "u", "read", "d"); // last path gone
}

test "rbac: SoD interaction — unassign frees the conflict, removeStaticSoD lifts it" {
    var e = rbac.Engine.init(testing.allocator);
    defer e.deinit();
    try e.addRole("payer");
    try e.addRole("approver");
    try e.addStaticSoD("payer", "approver");
    try e.assignRole("dave", "payer");
    try testing.expectError(error.ConflictingRole, e.assignRole("dave", "approver"));

    try testing.expect(try e.unassignRole("dave", "payer"));
    try e.assignRole("dave", "approver"); // no longer conflicts
    try testing.expectError(error.ConflictingRole, e.assignRole("dave", "payer"));

    try testing.expect(try e.removeStaticSoD("approver", "payer"));
    try e.assignRole("dave", "payer"); // constraint lifted
    // Lifting SoD leaves existing assignments alone; re-declaring is allowed.
    try e.addStaticSoD("payer", "approver");
    try testing.expectEqual(@as(usize, 2), e.assignments.get("dave").?.count());
}

test "rbac: removing a missing item — unknown role errors, absent relation is a no-op false" {
    var e = try buildBasicEngine(testing.allocator);
    defer e.deinit();
    const p: rbac.Permission = .{ .action = "read", .resource = "doc" };

    try testing.expectError(error.UnknownRole, e.removeRole("ghost"));
    try testing.expectError(error.UnknownRole, e.unassignRole("alice", "ghost"));
    try testing.expectError(error.UnknownRole, e.removePermission("ghost", p));
    try testing.expectError(error.UnknownRole, e.removeHierarchy("ghost", "viewer"));
    try testing.expectError(error.UnknownRole, e.removeHierarchy("viewer", "ghost"));
    try testing.expectError(error.UnknownRole, e.removeStaticSoD("ghost", "viewer"));

    try testing.expect(!(try e.unassignRole("nobody", "viewer")));
    try testing.expect(!(try e.removePermission("editor", p)));
    try testing.expect(!(try e.removeHierarchy("editor", "viewer")));
    try testing.expect(!(try e.removeStaticSoD("editor", "viewer")));
    try e.removeRole("editor");
    try testing.expectError(error.UnknownRole, e.removeRole("editor")); // second delete
    // The engine is intact after all of the above.
    try e.assignRole("alice", "viewer");
    try expectPermit(&e, "alice", "read", "doc");
}

test "rbac: churn — assign/unassign and friends 10k times keep memory bounded" {
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
    var e = rbac.Engine.init(fa.allocator());
    defer e.deinit();
    try e.addRole("keep");
    try e.addPermission("keep", .{ .action = "read", .resource = "doc" });
    try e.assignRole("holder", "keep");

    const Round = struct {
        fn run(eng: *rbac.Engine, i: usize) !void {
            var buf: [24]u8 = undefined;
            const user = std.fmt.bufPrint(&buf, "user-{d}", .{i}) catch unreachable;
            try eng.assignRole("u", "keep"); // the same pair over and over
            try eng.assignRole("u", "keep"); // duplicate assign must not allocate
            _ = try eng.unassignRole("u", "keep");
            try eng.assignRole(user, "keep"); // a fresh user every round
            _ = try eng.unassignRole(user, "keep");
            try eng.addRole("tmp");
            try eng.addPermission("tmp", .{ .action = "x", .resource = "y" });
            try eng.addPermission("tmp", .{ .action = "x", .resource = "y" });
            try eng.addHierarchy("tmp", "keep");
            try eng.addStaticSoD("tmp", "keep");
            try eng.assignRole("t", "tmp");
            if (i % 2 == 0) {
                try eng.removeRole("tmp"); // cascade path
            } else {
                _ = try eng.unassignRole("t", "tmp");
                _ = try eng.removePermission("tmp", .{ .action = "x", .resource = "y" });
                _ = try eng.removeHierarchy("tmp", "keep");
                _ = try eng.removeStaticSoD("tmp", "keep");
                try eng.removeRole("tmp");
            }
        }
    };

    // Warm up (hash maps reach their working capacity), then measure.
    for (0..16) |i| try Round.run(&e, i);
    const live_before = fa.allocated_bytes - fa.freed_bytes;
    for (16..10_016) |i| try Round.run(&e, i); // 10k: a leak of even one byte per round would show
    const live_after = fa.allocated_bytes - fa.freed_bytes;

    try testing.expect(live_after <= live_before + 256); // slack for map capacity steps
    try testing.expectEqual(@as(usize, 1), e.roles.count());
    try testing.expectEqual(@as(usize, 1), e.assignments.count());
    try testing.expectEqual(@as(usize, 0), e.sod.items.len);
    try expectPermit(&e, "holder", "read", "doc");
}

/// Naive reference model of the whole engine over a tiny universe:
/// boolean matrices, effective permissions recomputed from scratch.
const RefModel = struct {
    const R = 5;
    const U = 3;
    const P = 3;
    exists: [R]bool,
    perm: [R][P]bool,
    edge: [R][R]bool, // edge[s][j]: s is senior of j
    assign: [U][R]bool,
    sod: [R][R]bool, // symmetric

    fn reaches(m: *const RefModel, from: usize, to: usize) bool {
        if (from == to) return true;
        for (0..R) |j| {
            if (m.edge[from][j] and m.reaches(j, to)) return true;
        }
        return false;
    }

    fn effective(m: *const RefModel, u: usize, p: usize) bool {
        for (0..R) |r| {
            if (!m.assign[u][r]) continue;
            for (0..R) |t| {
                if (m.reaches(r, t) and m.perm[t][p]) return true;
            }
        }
        return false;
    }
};

test "rbac: random add/remove sequences agree with a naive recomputation" {
    const role_names = [_][]const u8{ "r0", "r1", "r2", "r3", "r4" };
    const user_names = [_][]const u8{ "u0", "u1", "u2" };
    const actions = [_][]const u8{ "p0", "p1", "p2" };
    const R = RefModel.R;
    const U = RefModel.U;
    const P = RefModel.P;

    var prng = std.Random.DefaultPrng.init(0x5eed_0b1e);
    const rnd = prng.random();

    for (0..6) |_| { // six independent engines from one deterministic stream
        var e = rbac.Engine.init(testing.allocator);
        defer e.deinit();
        var m = std.mem.zeroes(RefModel);

        for (0..1500) |step| {
            const r = rnd.uintLessThan(usize, R);
            const r2 = rnd.uintLessThan(usize, R);
            const u = rnd.uintLessThan(usize, U);
            const p = rnd.uintLessThan(usize, P);
            const perm: rbac.Permission = .{ .action = actions[p], .resource = "res" };
            switch (rnd.uintLessThan(u8, 10)) {
                0 => {
                    try e.addRole(role_names[r]);
                    m.exists[r] = true;
                },
                1 => {
                    if (m.exists[r]) {
                        try e.removeRole(role_names[r]);
                        m.exists[r] = false;
                        m.perm[r] = @splat(false);
                        for (0..R) |j| {
                            m.edge[r][j] = false;
                            m.edge[j][r] = false;
                            m.sod[r][j] = false;
                            m.sod[j][r] = false;
                        }
                        for (0..U) |k| m.assign[k][r] = false;
                    } else try testing.expectError(error.UnknownRole, e.removeRole(role_names[r]));
                },
                2 => {
                    if (m.exists[r]) {
                        try e.addPermission(role_names[r], perm);
                        m.perm[r][p] = true;
                    } else try testing.expectError(error.UnknownRole, e.addPermission(role_names[r], perm));
                },
                3 => {
                    if (m.exists[r]) {
                        try testing.expectEqual(m.perm[r][p], try e.removePermission(role_names[r], perm));
                        m.perm[r][p] = false;
                    } else try testing.expectError(error.UnknownRole, e.removePermission(role_names[r], perm));
                },
                4 => {
                    const res = e.addHierarchy(role_names[r], role_names[r2]);
                    if (!m.exists[r] or !m.exists[r2]) {
                        try testing.expectError(error.UnknownRole, res);
                    } else if (r == r2 or m.reaches(r2, r)) {
                        try testing.expectError(error.CyclicHierarchy, res);
                    } else {
                        try res;
                        m.edge[r][r2] = true;
                    }
                },
                5 => {
                    if (m.exists[r] and m.exists[r2]) {
                        try testing.expectEqual(m.edge[r][r2], try e.removeHierarchy(role_names[r], role_names[r2]));
                        m.edge[r][r2] = false;
                    } else try testing.expectError(error.UnknownRole, e.removeHierarchy(role_names[r], role_names[r2]));
                },
                6 => {
                    const res = e.assignRole(user_names[u], role_names[r]);
                    if (!m.exists[r]) {
                        try testing.expectError(error.UnknownRole, res);
                    } else {
                        var clash = false;
                        for (0..R) |h| {
                            if (m.assign[u][h] and m.sod[h][r]) clash = true;
                        }
                        if (clash) {
                            try testing.expectError(error.ConflictingRole, res);
                        } else {
                            try res;
                            m.assign[u][r] = true;
                        }
                    }
                },
                7 => {
                    if (m.exists[r]) {
                        try testing.expectEqual(m.assign[u][r], try e.unassignRole(user_names[u], role_names[r]));
                        m.assign[u][r] = false;
                    } else try testing.expectError(error.UnknownRole, e.unassignRole(user_names[u], role_names[r]));
                },
                8 => {
                    if (m.exists[r] and m.exists[r2]) {
                        try e.addStaticSoD(role_names[r], role_names[r2]);
                        m.sod[r][r2] = true;
                        m.sod[r2][r] = true;
                    } else try testing.expectError(error.UnknownRole, e.addStaticSoD(role_names[r], role_names[r2]));
                },
                else => {
                    if (m.exists[r] and m.exists[r2]) {
                        try testing.expectEqual(m.sod[r][r2], try e.removeStaticSoD(role_names[r], role_names[r2]));
                        m.sod[r][r2] = false;
                        m.sod[r2][r] = false;
                    } else try testing.expectError(error.UnknownRole, e.removeStaticSoD(role_names[r], role_names[r2]));
                },
            }
            // Full comparison of every decision after every step.
            for (0..U) |k| {
                for (0..P) |q| {
                    const want = m.effective(k, q);
                    const got = e.check(user_names[k], actions[q], "res").isPermit();
                    if (want != got) {
                        std.debug.print("mismatch at step {d}: user {d} perm {d} want {} got {}\n", .{ step, k, q, want, got });
                        return error.TestExpectedEqual;
                    }
                }
            }
        }
    }
}

// -- ABAC ---------------------------------------------------------------------

fn deptAttrs(sub_dept: []const u8, res_dept: []const u8) !abac.Attributes {
    var attrs: abac.Attributes = .{};
    try attrs.put(testing.allocator, .subject, "department", abac.str(sub_dept));
    try attrs.put(testing.allocator, .resource, "owner_dept", abac.str(res_dept));
    return attrs;
}

test "abac: eq operator matches / mismatches" {
    var attrs = try deptAttrs("eng", "eng");
    defer attrs.deinit(testing.allocator);
    const cond = abac.eq(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept")));
    try testing.expect(try abac.evalCondition(cond, &attrs, abac.default_max_depth));
}

test "abac: eq operator sibling — mismatched departments is false" {
    var attrs = try deptAttrs("eng", "sales");
    defer attrs.deinit(testing.allocator);
    const cond = abac.eq(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept")));
    try testing.expect(!(try abac.evalCondition(cond, &attrs, abac.default_max_depth)));
}

test "abac: ne operator" {
    var attrs = try deptAttrs("eng", "sales");
    defer attrs.deinit(testing.allocator);
    const cond = abac.ne(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept")));
    try testing.expect(try abac.evalCondition(cond, &attrs, abac.default_max_depth));
}

test "abac: ne operator sibling — equal departments is false" {
    var attrs = try deptAttrs("eng", "eng");
    defer attrs.deinit(testing.allocator);
    const cond = abac.ne(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept")));
    try testing.expect(!(try abac.evalCondition(cond, &attrs, abac.default_max_depth)));
}

fn hourAttrs(hour: i64) !abac.Attributes {
    var attrs: abac.Attributes = .{};
    try attrs.put(testing.allocator, .environment, "hour", abac.int(hour));
    return attrs;
}

test "abac: lt/le/gt/ge operators" {
    var attrs = try hourAttrs(10);
    defer attrs.deinit(testing.allocator);
    const h = abac.attr(.environment, "hour");

    try testing.expect(try abac.evalCondition(abac.lt(h, abac.lit(abac.int(11))), &attrs, abac.default_max_depth));
    try testing.expect(try abac.evalCondition(abac.le(h, abac.lit(abac.int(10))), &attrs, abac.default_max_depth));
    try testing.expect(try abac.evalCondition(abac.gt(h, abac.lit(abac.int(9))), &attrs, abac.default_max_depth));
    try testing.expect(try abac.evalCondition(abac.ge(h, abac.lit(abac.int(10))), &attrs, abac.default_max_depth));
}

test "abac: lt/le/gt/ge operators sibling — boundary flips" {
    var attrs = try hourAttrs(10);
    defer attrs.deinit(testing.allocator);
    const h = abac.attr(.environment, "hour");

    // Minimal flips of the boundary values above.
    try testing.expect(!(try abac.evalCondition(abac.lt(h, abac.lit(abac.int(10))), &attrs, abac.default_max_depth)));
    try testing.expect(!(try abac.evalCondition(abac.le(h, abac.lit(abac.int(9))), &attrs, abac.default_max_depth)));
    try testing.expect(!(try abac.evalCondition(abac.gt(h, abac.lit(abac.int(10))), &attrs, abac.default_max_depth)));
    try testing.expect(!(try abac.evalCondition(abac.ge(h, abac.lit(abac.int(11))), &attrs, abac.default_max_depth)));
}

test "abac: order comparison on non-int is a type mismatch" {
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .subject, "name", abac.str("alice"));
    const cond = abac.lt(abac.attr(.subject, "name"), abac.lit(abac.int(1)));
    try testing.expectError(error.TypeMismatch, abac.evalCondition(cond, &attrs, abac.default_max_depth));
}

test "abac: in operator — membership" {
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .environment, "day", abac.str("sat"));
    const weekend = [_]abac.Value{ abac.str("sat"), abac.str("sun") };
    const cond = abac.inList(abac.attr(.environment, "day"), abac.lit(abac.list(&weekend)));
    try testing.expect(try abac.evalCondition(cond, &attrs, abac.default_max_depth));
}

test "abac: in operator sibling — non-member is false" {
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .environment, "day", abac.str("mon"));
    const weekend = [_]abac.Value{ abac.str("sat"), abac.str("sun") };
    const cond = abac.inList(abac.attr(.environment, "day"), abac.lit(abac.list(&weekend)));
    try testing.expect(!(try abac.evalCondition(cond, &attrs, abac.default_max_depth)));
}

fn businessHoursAttrs(hour: i64, dept_match: bool) !abac.Attributes {
    var attrs: abac.Attributes = .{};
    try attrs.put(testing.allocator, .environment, "hour", abac.int(hour));
    try attrs.put(testing.allocator, .subject, "department", abac.str("eng"));
    try attrs.put(testing.allocator, .resource, "owner_dept", abac.str(if (dept_match) "eng" else "sales"));
    return attrs;
}

test "abac: And composition — all must hold" {
    var attrs = try businessHoursAttrs(10, true);
    defer attrs.deinit(testing.allocator);
    const h = abac.attr(.environment, "hour");
    const cond = abac.andAll(&.{
        abac.eq(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept"))),
        abac.ge(h, abac.lit(abac.int(9))),
        abac.lt(h, abac.lit(abac.int(17))),
    });
    try testing.expect(try abac.evalCondition(cond, &attrs, abac.default_max_depth));
}

test "abac: And composition sibling — one false clause fails the whole tree" {
    // Minimal flip: outside business hours.
    var attrs = try businessHoursAttrs(20, true);
    defer attrs.deinit(testing.allocator);
    const h = abac.attr(.environment, "hour");
    const cond = abac.andAll(&.{
        abac.eq(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept"))),
        abac.ge(h, abac.lit(abac.int(9))),
        abac.lt(h, abac.lit(abac.int(17))),
    });
    try testing.expect(!(try abac.evalCondition(cond, &attrs, abac.default_max_depth)));
}

test "abac: Or composition — any may hold" {
    var attrs = try businessHoursAttrs(20, true); // out of hours, but dept matches
    defer attrs.deinit(testing.allocator);
    const h = abac.attr(.environment, "hour");
    const cond = abac.orAny(&.{
        abac.eq(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept"))),
        abac.ge(h, abac.lit(abac.int(9))),
    });
    try testing.expect(try abac.evalCondition(cond, &attrs, abac.default_max_depth));
}

test "abac: Or composition sibling — all clauses false fails" {
    var attrs = try businessHoursAttrs(20, false); // out of hours AND dept mismatch
    defer attrs.deinit(testing.allocator);
    const cond = abac.orAny(&.{
        abac.eq(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept"))),
        abac.lt(abac.attr(.environment, "hour"), abac.lit(abac.int(9))),
    });
    try testing.expect(!(try abac.evalCondition(cond, &attrs, abac.default_max_depth)));
}

test "abac: Not composition negates" {
    var attrs = try deptAttrs("eng", "sales");
    defer attrs.deinit(testing.allocator);
    const inner = abac.eq(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept")));
    const cond = abac.not(&inner);
    try testing.expect(try abac.evalCondition(cond, &attrs, abac.default_max_depth));
}

test "abac: Not composition sibling — negating a true condition is false" {
    var attrs = try deptAttrs("eng", "eng");
    defer attrs.deinit(testing.allocator);
    const inner = abac.eq(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept")));
    const cond = abac.not(&inner);
    try testing.expect(!(try abac.evalCondition(cond, &attrs, abac.default_max_depth)));
}

test "abac: default-deny when no rule matches" {
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .subject, "department", abac.str("sales"));
    const rules = [_]abac.Rule{
        .{ .id = "eng-only", .effect = .permit, .condition = abac.eq(abac.attr(.subject, "department"), abac.lit(abac.str("eng"))) },
    };
    const d = abac.evaluate(.{ .rules = &rules }, &attrs);
    try testing.expectEqual(Result.deny, d.result);
}

test "abac: default-deny sibling — matching the rule flips it to permit" {
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .subject, "department", abac.str("eng"));
    const rules = [_]abac.Rule{
        .{ .id = "eng-only", .effect = .permit, .condition = abac.eq(abac.attr(.subject, "department"), abac.lit(abac.str("eng"))) },
    };
    const d = abac.evaluate(.{ .rules = &rules }, &attrs);
    try testing.expectEqual(Result.permit, d.result);
}

test "abac: deny-overrides — a matching Deny beats a matching Permit" {
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .subject, "role", abac.str("contractor"));
    const rules = [_]abac.Rule{
        .{ .id = "allow-all", .effect = .permit, .condition = abac.eq(abac.attr(.subject, "role"), abac.lit(abac.str("contractor"))) },
        .{ .id = "deny-contractors", .effect = .deny, .condition = abac.eq(abac.attr(.subject, "role"), abac.lit(abac.str("contractor"))) },
    };
    const d = abac.evaluate(.{ .rules = &rules, .algorithm = .deny_overrides }, &attrs);
    try testing.expectEqual(Result.deny, d.result);
    try testing.expectEqualStrings("deny-contractors", d.reason);
}

test "abac: permit-overrides sibling — the SAME rule set flips to permit" {
    // Minimal flip: identical rules and attributes as the deny-overrides
    // test above, only the combining algorithm changes — proving the
    // algorithm (not rule order) decides the outcome.
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .subject, "role", abac.str("contractor"));
    const rules = [_]abac.Rule{
        .{ .id = "allow-all", .effect = .permit, .condition = abac.eq(abac.attr(.subject, "role"), abac.lit(abac.str("contractor"))) },
        .{ .id = "deny-contractors", .effect = .deny, .condition = abac.eq(abac.attr(.subject, "role"), abac.lit(abac.str("contractor"))) },
    };
    const d = abac.evaluate(.{ .rules = &rules, .algorithm = .permit_overrides }, &attrs);
    try testing.expectEqual(Result.permit, d.result);
    try testing.expectEqualStrings("allow-all", d.reason);
}

test "abac: permit-overrides with only a matching Deny (no Permit) falls back to Deny" {
    // Unlike the deny/permit-both-match sibling test above, exercise
    // combinePermitOverrides' NON-immediate-return path: no rule in the set
    // ever permits, so the loop must fall through to the accumulated
    // `saw_deny` result rather than the immediate `.permit => return d` leaf.
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .subject, "role", abac.str("contractor"));
    const rules = [_]abac.Rule{
        .{ .id = "deny-contractors", .effect = .deny, .condition = abac.eq(abac.attr(.subject, "role"), abac.lit(abac.str("contractor"))) },
    };
    const d = abac.evaluate(.{ .rules = &rules, .algorithm = .permit_overrides }, &attrs);
    try testing.expectEqual(Result.deny, d.result);
    try testing.expectEqualStrings("deny-contractors", d.reason);
}

test "abac: permit-overrides sibling — no rule matches at all falls to not_applicable/deny" {
    // Minimal flip: the rule's condition never matches, so the loop
    // contributes nothing (not_applicable) — the true fallback branch of
    // combinePermitOverrides, distinct from the saw_deny case above.
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .subject, "role", abac.str("employee"));
    const rules = [_]abac.Rule{
        .{ .id = "deny-contractors", .effect = .deny, .condition = abac.eq(abac.attr(.subject, "role"), abac.lit(abac.str("contractor"))) },
    };
    const d = abac.evaluate(.{ .rules = &rules, .algorithm = .permit_overrides }, &attrs);
    try testing.expectEqual(Result.deny, d.result);
    try testing.expectEqualStrings("default-deny: no rule matched", d.reason);
}

test "abac: default combining algorithm is deny_overrides" {
    const p: abac.Policy = .{ .rules = &.{} };
    try testing.expectEqual(abac.CombiningAlgorithm.deny_overrides, p.algorithm);
}

test "abac: depth-bound rejects an over-deep condition tree" {
    // Build a chain of 40 nested `not` nodes — deeper than default_max_depth (32).
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .subject, "flag", abac.boolean(true));

    const depth = 40;
    var nodes: [depth]abac.Condition = undefined;
    nodes[0] = abac.eq(abac.attr(.subject, "flag"), abac.lit(abac.boolean(true)));
    var i: usize = 1;
    while (i < depth) : (i += 1) {
        nodes[i] = abac.not(&nodes[i - 1]);
    }

    try testing.expectError(error.MaxDepthExceeded, abac.evalCondition(nodes[depth - 1], &attrs, abac.default_max_depth));
}

test "abac: depth-bound sibling — the same shape under the bound evaluates fine" {
    // Minimal flip: fewer nesting levels (10, well under 32) succeeds and
    // the odd/even `not` parity is still correct.
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .subject, "flag", abac.boolean(true));

    const depth = 10;
    var nodes: [depth]abac.Condition = undefined;
    nodes[0] = abac.eq(abac.attr(.subject, "flag"), abac.lit(abac.boolean(true)));
    var i: usize = 1;
    while (i < depth) : (i += 1) {
        nodes[i] = abac.not(&nodes[i - 1]);
    }

    // 9 `not`s wrap the innermost true condition -> odd number of negations -> false.
    try testing.expect(!(try abac.evalCondition(nodes[depth - 1], &attrs, abac.default_max_depth)));
}

test "abac: depth-bound collapses to Deny via evaluate (default-deny fail-safe)" {
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    try attrs.put(testing.allocator, .subject, "flag", abac.boolean(true));

    const depth = 40;
    var nodes: [depth]abac.Condition = undefined;
    nodes[0] = abac.eq(abac.attr(.subject, "flag"), abac.lit(abac.boolean(true)));
    var i: usize = 1;
    while (i < depth) : (i += 1) {
        nodes[i] = abac.not(&nodes[i - 1]);
    }
    const rules = [_]abac.Rule{
        .{ .id = "too-deep", .effect = .permit, .condition = nodes[depth - 1] },
    };
    const d = abac.evaluate(.{ .rules = &rules }, &attrs);
    try testing.expectEqual(Result.deny, d.result);
}

test "abac: missing attribute is Indeterminate, collapses to Deny" {
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(testing.allocator);
    const rules = [_]abac.Rule{
        .{ .id = "needs-missing-attr", .effect = .permit, .condition = abac.eq(abac.attr(.subject, "nope"), abac.lit(abac.str("x"))) },
    };
    const d = abac.evaluate(.{ .rules = &rules }, &attrs);
    try testing.expectEqual(Result.deny, d.result);

    try testing.expectError(error.MissingAttribute, abac.evalCondition(rules[0].condition, &attrs, abac.default_max_depth));
}

test "Decision.isPermit collapses non-permit results" {
    try testing.expect((Decision{ .result = .permit, .reason = "x" }).isPermit());
    try testing.expect(!(Decision{ .result = .deny, .reason = "x" }).isPermit());
}
