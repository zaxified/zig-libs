// SPDX-License-Identifier: MIT

//! What a config loader does with `yaml`: compose one document into a
//! `Value` tree, walk it with `get`/`at` rather than hand-rolled tree code,
//! and see an anchor/alias pair resolve to genuinely shared structure. Then
//! show the strict-by-default duplicate-key reject a permissive parser would
//! have silently swallowed.

const std = @import("std");
const yaml = @import("yaml");

const config_doc =
    \\defaults: &defaults
    \\  timeout_ms: 500
    \\  retries: 3
    \\service: web
    \\replicas: 3
    \\upstreams:
    \\  - host: 10.0.0.1
    \\    port: 8080
    \\  - host: 10.0.0.2
    \\    port: 8080
    \\overrides: *defaults
    \\
;

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var doc = try yaml.compose(gpa, config_doc, .{});
    defer doc.deinit();

    const service = doc.root.get("service").?.string;
    const replicas = doc.root.get("replicas").?.int;
    std.debug.print("service={s} replicas={d}\n", .{ service, replicas });

    const upstreams = doc.root.get("upstreams").?;
    var i: usize = 0;
    while (upstreams.at(i)) |u| : (i += 1) {
        std.debug.print("upstream[{d}]: {s}:{d}\n", .{ i, u.get("host").?.string, u.get("port").?.int });
    }

    // `overrides: *defaults` is an ALIAS, not a copy: the composer shares the
    // anchored mapping's slice rather than duplicating it, so both fields
    // read back identically without the document repeating them on the wire.
    const defaults = doc.root.get("defaults").?;
    const overrides = doc.root.get("overrides").?;
    std.debug.print(
        "defaults.timeout_ms={d} overrides.timeout_ms={d} (same slice: {})\n",
        .{ defaults.get("timeout_ms").?.int, overrides.get("timeout_ms").?.int, defaults.mapping.ptr == overrides.mapping.ptr },
    );

    // A repeated mapping key is a classic smuggled-disagreement bug (which
    // value actually wins?) — the composer rejects it by default rather than
    // silently picking first-or-last, and the error has to be nameable so a
    // config loader can report the file, not just "parse failed".
    const dup_doc = "a: 1\na: 2\n";
    if (yaml.compose(gpa, dup_doc, .{})) |_| {
        std.debug.print("unexpected: duplicate key accepted\n", .{});
    } else |err| switch (err) {
        error.DuplicateKey => std.debug.print("compose(duplicate key): DuplicateKey (expected)\n", .{}),
        else => return err,
    }
}
