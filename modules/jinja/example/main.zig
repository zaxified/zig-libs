// SPDX-License-Identifier: MIT

//! What a config-generation consumer does with `jinja`: render a device
//! config from a template + typed Zig data, and get a hard error — not an
//! empty string spliced into the middle of a config file — when the
//! template references a field that isn't there. `undefined_policy` in
//! `README.md` calls this out as the module's one deliberate divergence
//! from the reference implementation's default, precisely because a
//! silently-empty IP address in generated network config is worse than a
//! failed render.
//!
//! Built against the PUBLISHED module (`@import("jinja")`) only — no
//! `test_deps`.

const std = @import("std");
const jinja = @import("jinja");

const Interface = struct {
    name: []const u8,
    address: []const u8,
    mask: []const u8,
    shutdown: bool,
};

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var env = try jinja.Environment.init(gpa, .{
        .trim_blocks = true,
        .lstrip_blocks = true,
    });
    defer env.deinit();

    // ── render a good template ──────────────────────────────────────────
    var good = try env.compile(
        \\hostname {{ host }}
        \\{% for i in interfaces %}
        \\interface {{ i.name }}
        \\ ip address {{ i.address }} {{ i.mask }}
        \\ {{ 'shutdown' if i.shutdown else 'no shutdown' }}
        \\!
        \\{% endfor %}
    , null);
    defer good.deinit();

    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    const ctx = try jinja.valueFrom(arena.allocator(), .{
        .host = "sw1",
        .interfaces = [_]Interface{
            .{ .name = "Gi0/1", .address = "10.0.0.1", .mask = "255.255.255.0", .shutdown = false },
        },
    });

    const out = try good.render(gpa, ctx, null);
    defer gpa.free(out);
    std.debug.print("{s}\n", .{out});

    // ── reject: a typo'd field name must not render as an empty string ──
    // `i.addr` (not `i.address`) is exactly the mistake a config template
    // author makes; under the strict default (`undefined_policy = .strict`,
    // the module's inverted-from-reference default) this is a hard error
    // with a line number, not a device config missing its IP.
    var diag: jinja.Diagnostic = .{};
    var typo = env.compile(
        \\interface {{ i.name }}
        \\ ip address {{ i.addr }} {{ i.mask }}
    , &diag) catch |err| {
        std.debug.print("compile error: {f}\n", .{&diag});
        return err;
    };
    defer typo.deinit();

    const single_iface = try jinja.valueFrom(arena.allocator(), .{
        .i = Interface{ .name = "Gi0/2", .address = "10.0.0.2", .mask = "255.255.255.0", .shutdown = false },
    });
    _ = typo.render(gpa, single_iface, &diag) catch |err| switch (err) {
        error.UndefinedValue => {
            std.debug.print("rejected: {f}\n", .{&diag});
        },
        else => return err,
    };
}
