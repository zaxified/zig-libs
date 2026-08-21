// SPDX-License-Identifier: MIT

//! What a JSON API consumer does with `validate`: describe a request body
//! as a plain Zig struct, parse+validate it in one call, and get every
//! problem back at once — not just the first one — as machine-readable
//! `{path, code, message}` errors a client can act on. This is the
//! standalone "no HTTP" style from the README; the `router` middleware
//! wraps the same core for services that want it wired into request
//! handling directly.
//!
//! Built against the PUBLISHED module (`@import("validate")`) only — no
//! `test_deps`, no `router`/`http` request plumbing needed for this path.

const std = @import("std");
const validate = @import("validate");

const CreateThing = struct {
    name: []const u8, // required (no default), string
    qty: u8, // required, int, bounds 0…255 from the type
    price: ?f64 = null, // optional + nullable
    color: enum { red, blue } = .red, // string with one_of from the enum

    // Extra constraints reflection cannot see:
    pub const validate_rules: []const validate.Rule = &.{
        .{ .field = "name", .kind = .string, .min_len = 1, .max_len = 64 },
    };
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── accept ───────────────────────────────────────────────────────────
    const good_body =
        \\{"name":"widget","qty":3,"price":9.99,"color":"blue"}
    ;
    var good = try validate.parseInto(CreateThing, gpa, good_body);
    defer good.deinit();
    switch (good) {
        .ok => |parsed| std.debug.print("accepted: name={s} qty={d}\n", .{ parsed.value.name, parsed.value.qty }),
        .invalid => return error.ExpectedValid,
    }

    // ── reject: several problems at once, aggregated ────────────────────
    // Empty name (violates the min_len=1 custom rule), qty out of the u8
    // range the type derives (0..255), and a color the enum doesn't name —
    // all three come back together, not just whichever the validator hit
    // first. A client can fix everything in one round trip instead of
    // playing whack-a-mole with a fail-fast API.
    const bad_body =
        \\{"name":"","qty":999,"color":"purple"}
    ;
    var bad = try validate.parseInto(CreateThing, gpa, bad_body);
    defer bad.deinit();
    switch (bad) {
        .ok => return error.ExpectedInvalid,
        .invalid => |report| {
            std.debug.print("rejected ({d} error(s)):\n", .{report.errors.len});
            for (report.errors) |e| {
                std.debug.print("  path={s} code={s} message={s}\n", .{ e.path, e.code, e.message });
            }
        },
    }

    // ── reject: malformed JSON never panics, always a clean report ──────
    var garbage = try validate.parseInto(CreateThing, gpa, "{not json");
    defer garbage.deinit();
    switch (garbage) {
        .ok => return error.ExpectedInvalid,
        .invalid => |report| {
            const e = report.errors[0];
            std.debug.print("rejected: path=\"{s}\" code={s}\n", .{ e.path, e.code });
        },
    }
}
