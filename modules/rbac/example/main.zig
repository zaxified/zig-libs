// SPDX-License-Identifier: MIT

//! What an authorization consumer does with `rbac`: build a role graph for
//! a small document service, decide whether a request is permitted, and
//! see the default-deny posture in action — an unassigned user, an
//! unknown role, and a separation-of-duty conflict are all refused, each
//! with a nameable error or a `Decision.deny` a caller can log and act on.
//! `rbac` answers only "is this already-identified subject authorized" —
//! see `jwt` for who the subject is.
//!
//! Everything is in-memory logic; the module does no I/O of its own.
//!
//! Built against the PUBLISHED module (`@import("rbac")`) only — no
//! `test_deps`.

const std = @import("std");
const rbac = @import("rbac").rbac;
const abac = @import("rbac").abac;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── RBAC: roles, hierarchy, assignment ──────────────────────────────
    var engine = rbac.Engine.init(gpa);
    defer engine.deinit();

    try engine.addRole("viewer");
    try engine.addRole("editor");
    try engine.addRole("payer");
    try engine.addRole("approver");
    try engine.addPermission("viewer", .{ .action = "read", .resource = "doc" });
    try engine.addPermission("editor", .{ .action = "write", .resource = "doc" });

    // A senior role inherits everything a junior role grants.
    try engine.addHierarchy("editor", "viewer");

    // Static separation-of-duty: a payer can never also be an approver.
    try engine.addStaticSoD("payer", "approver");

    try engine.assignRole("alice", "editor");

    // ── accept: direct + inherited grants ───────────────────────────────
    const can_write = engine.check("alice", "write", "doc");
    std.debug.print("alice write doc: {s} ({s})\n", .{ @tagName(can_write.result), can_write.reason });
    const can_read = engine.check("alice", "read", "doc"); // inherited via viewer
    std.debug.print("alice read doc: {s} ({s})\n", .{ @tagName(can_read.result), can_read.reason });

    // ── reject: default-deny for an unassigned user ─────────────────────
    // No error, no exception — the everyday entry point's TYPE is the
    // two-valued Decision, so "unknown user" and "known user, wrong
    // permission" both come back the same shape a caller already branches
    // on.
    const stranger = engine.check("mallory", "write", "doc");
    std.debug.print("mallory write doc: {s} ({s})\n", .{ @tagName(stranger.result), stranger.reason });
    if (stranger.isPermit()) return error.ExpectedDefaultDeny;

    // ── reject: unknown role, named error ───────────────────────────────
    engine.assignRole("bob", "owner") catch |err| switch (err) {
        error.UnknownRole => std.debug.print("rejected: UnknownRole (\"owner\" was never declared)\n", .{}),
        else => return err,
    };

    // ── reject: separation-of-duty conflict ─────────────────────────────
    try engine.assignRole("carol", "payer");
    engine.assignRole("carol", "approver") catch |err| switch (err) {
        error.ConflictingRole => std.debug.print("rejected: ConflictingRole (payer + approver on one user)\n", .{}),
        else => return err,
    };

    // ── ABAC: same-department, business-hours policy ────────────────────
    var attrs: abac.Attributes = .{};
    defer attrs.deinit(gpa);
    try attrs.put(gpa, .subject, "department", abac.str("eng"));
    try attrs.put(gpa, .resource, "owner_dept", abac.str("eng"));
    try attrs.put(gpa, .environment, "hour", abac.int(10));

    const cond = abac.andAll(&.{
        abac.eq(abac.attr(.subject, "department"), abac.of(abac.attr(.resource, "owner_dept"))),
        abac.ge(abac.attr(.environment, "hour"), abac.lit(abac.int(9))),
        abac.lt(abac.attr(.environment, "hour"), abac.lit(abac.int(17))),
    });
    const rules = [_]abac.Rule{
        .{ .id = "business-hours-same-dept", .effect = .permit, .condition = cond },
    };
    const policy: abac.Policy = .{ .rules = &rules, .algorithm = .deny_overrides };

    const during_hours = abac.evaluate(policy, &attrs);
    std.debug.print("abac during business hours: {s}\n", .{@tagName(during_hours.result)});

    // ── reject: outside business hours, deny-overrides default ──────────
    // No rule matches at 22:00, and `deny_overrides` collapses "no rule
    // matched" into the same `.deny` a caller already branches on —
    // default-deny by construction, not by an extra check the caller has
    // to remember.
    try attrs.put(gpa, .environment, "hour", abac.int(22));
    const after_hours = abac.evaluate(policy, &attrs);
    std.debug.print("abac after hours: {s}\n", .{@tagName(after_hours.result)});
    if (after_hours.isPermit()) return error.ExpectedDefaultDeny;
}
