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

    // The json5.org spec also documents hex numeric literals (`0x1A`) as a
    // valid JSON5 number. This module's README lists that as a documented
    // gap: the preprocessor never touches numeric-literal bytes, so a hex
    // literal passes through unrewritten and standard JSON — what
    // `preprocess`'s output must satisfy — has no hex-literal production.
    // `preprocess` itself does not fail (it only rewrites comments/keys/
    // commas/quotes); the spec gap only becomes visible one layer down, at
    // `std.json`, which is exactly the case an outside caller would hit.
    const hex_src = "{ code: 0x1A }";
    const hex_out = try json5.preprocess(gpa, hex_src);
    defer gpa.free(hex_out);
    if (std.json.parseFromSlice(std.json.Value, gpa, hex_out, .{})) |_| {
        unreachable; // would mean std.json started accepting hex numbers
    } else |err| switch (err) {
        error.SyntaxError => std.debug.print(
            "hex literal (documented gap): preprocess() passes \"0x1A\" through unrewritten, std.json.SyntaxError downstream (expected)\n",
            .{},
        ),
        else => return err,
    }

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
    std.debug.assert(saw_err_entry);
    std.debug.assert(recovered.value.object.get("good").?.integer == 1);
    std.debug.assert(recovered.value.object.get("ok").?.integer == 2);
    std.debug.print("recovery: good/ok survived, malformed entry surfaced as $err_* data\n", .{});
}
