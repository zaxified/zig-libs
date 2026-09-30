// SPDX-License-Identifier: MIT

//! What a config-file consumer does with `json5`: preprocess a JSON5-ish
//! config (comments, unquoted keys, single-quoted strings, trailing commas —
//! forms the json5.org spec documents) into standard JSON and hand it to
//! `std.json`, then use the lenient `preprocessAnnotated` entry point the
//! way a GUI editor would — recover from a malformed document instead of
//! failing outright, and surface the recovered problem as data.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const json5 = @import("json5");

/// A check that survives EVERY optimize mode, unlike a debug-only assert:
/// `-Doptimize=ReleaseFast` compiles those out, and `scripts/test.sh` does not
/// merely BUILD the examples, it RUNS them in the lane's own optimize mode --
/// so in a release lane the check vanished and the example went on printing
/// that it had passed. See `scripts/checks/check-example-assert.py`.
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // A config in the json5.org forms this module actually implements
    // (see its README "Deferred" list for what it doesn't): `//` and `/*
    // */` comments, unquoted object keys, single-quoted strings, and a
    // trailing comma before `}`/`]`.
    const src =
        \\{
        \\  // build config
        \\  name: 'zig-libs',
        \\  tags: ['codec', 'json5',],
        \\  /* stable since */
        \\  version: 3,
        \\}
    ;
    const out = try json5.preprocess(gpa, src);
    defer gpa.free(out);

    var parsed = try std.json.parseFromSlice(std.json.Value, gpa, out, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    std.debug.print("name={s} version={d} tags={d}\n", .{
        obj.get("name").?.string,
        obj.get("version").?.integer,
        obj.get("tags").?.array.items.len,
    });

    // JSON5 numbers standard JSON lacks (hex, a leading `+`, a bare leading
    // or trailing `.`) are rewritten into decimal JSON numbers, so std.json
    // reads them as values instead of stopping at a SyntaxError.
    const num_src = "{ code: 0x1A, gain: +.5 }";
    const num_out = try json5.preprocess(gpa, num_src);
    defer gpa.free(num_out);
    var nums = try std.json.parseFromSlice(std.json.Value, gpa, num_out, .{});
    defer nums.deinit();
    must(nums.value.object.get("code").?.integer == 26, @src());
    must(nums.value.object.get("gain").?.float == 0.5, @src());
    std.debug.print("JSON5 numbers: {s} -> {s}\n", .{ num_src, num_out });

    // preprocessAnnotated: the GUI/editor entry point. Fed a document with a
    // missing colon (`bad value` has no `:`), it recovers instead of
    // failing, and reports the problem as a synthetic "$err_trace_<N>"
    // sibling entry rather than crashing the caller's parser.
    const broken = "{ good: 1, bad value, ok: 2 }";
    const r = try json5.preprocessAnnotated(gpa, broken);
    defer gpa.free(r.out);
    std.debug.print("recovered doc is valid JSON, next_id={d}: {s}\n", .{ r.next_id, r.out });

    var recovered = try std.json.parseFromSlice(std.json.Value, gpa, r.out, .{});
    defer recovered.deinit();
    var saw_err_entry = false;
    var it = recovered.value.object.iterator();
    while (it.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, "$err_")) saw_err_entry = true;
    }
    must(saw_err_entry, @src());
    must(recovered.value.object.get("good").?.integer == 1, @src());
    must(recovered.value.object.get("ok").?.integer == 2, @src());
    std.debug.print("recovery: good/ok survived, malformed entry surfaced as $err_* data\n", .{});
}
