// SPDX-License-Identifier: MIT

//! Differential driver for `compare.py` / `volume.py` (`CONVENTIONS.md` §9):
//! reads YAML records from stdin, one per line, HEX-encoded and `.`-prefixed
//! (a record may contain NUL or a literal newline, so no in-band separator
//! survives; hex does) — composes each through this module's PUBLIC
//! `yaml.composeAll`, and prints one canonical, typed rendering per record
//! (or `ERR:<name>`). Deliberately does not use this or any library's own
//! JSON/YAML writer, so the encoding is a private wire format the Python
//! side decodes independently — not a restatement of either side's printer.
//! Talks to the module only through `composeAll`/`Value`; no module source
//! is copied here.
//!
//! Build + run: see `tools/README.md` for the exact command and measured
//! result.

const std = @import("std");
const yaml = @import("yaml");

fn emit(b: *std.ArrayList(u8), gpa: std.mem.Allocator, v: yaml.Value, depth: usize) !void {
    if (depth > 200) {
        try b.appendSlice(gpa, "<deep>");
        return;
    }
    switch (v) {
        .null => try b.appendSlice(gpa, "N"),
        .bool => |x| try b.appendSlice(gpa, if (x) "B:true" else "B:false"),
        .int => |x| try b.print(gpa, "I:{d}", .{x}),
        .float => |x| try b.print(gpa, "F:{d}", .{x}),
        .string => |s| {
            try b.appendSlice(gpa, "S:");
            for (s) |c| {
                const safe = (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or (c >= '0' and c <= '9') or c == ' ';
                if (!safe) {
                    try b.print(gpa, "\\x{x:0>2}", .{c});
                } else try b.append(gpa, c);
            }
        },
        .sequence => |items| {
            try b.appendSlice(gpa, "[");
            for (items, 0..) |it, i| {
                if (i != 0) try b.appendSlice(gpa, ",");
                try emit(b, gpa, it, depth + 1);
            }
            try b.appendSlice(gpa, "]");
        },
        .mapping => |pairs| {
            try b.appendSlice(gpa, "{");
            for (pairs, 0..) |p, i| {
                if (i != 0) try b.appendSlice(gpa, ",");
                try emit(b, gpa, p.key, depth + 1);
                try b.appendSlice(gpa, "=>");
                try emit(b, gpa, p.value, depth + 1);
            }
            try b.appendSlice(gpa, "}");
        },
    }
}

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // 1 MiB per line: comfortably above volume.py's 4096-byte records
    // (8192 hex chars) and compare.py's yaml-test-suite fixtures.
    var in_buf: [1 << 20]u8 = undefined;
    var fr = std.Io.File.stdin().reader(io, &in_buf);
    const r = &fr.interface;

    var out_buf: [1 << 16]u8 = undefined;
    var fw = std.Io.File.stdout().writer(io, &out_buf);
    const o = &fw.interface;

    var line: std.ArrayList(u8) = .empty;
    defer line.deinit(gpa);
    var dec: std.ArrayList(u8) = .empty;
    defer dec.deinit(gpa);

    while (try r.takeDelimiter('\n')) |raw| {
        if (raw.len == 0) continue; // trailing newline only
        const hexline = raw[1..]; // leading '.' keeps an EMPTY record a record
        dec.clearRetainingCapacity();
        try dec.resize(gpa, hexline.len / 2);
        const src = std.fmt.hexToBytes(dec.items, hexline) catch {
            try o.writeAll("ERR:BADHEX\n");
            continue;
        };
        line.clearRetainingCapacity();
        if (yaml.composeAll(gpa, src, .{})) |ok| {
            defer ok.deinit();
            try line.print(gpa, "OK:{d}:", .{ok.documents.len});
            for (ok.documents, 0..) |d, i| {
                if (i != 0) try line.appendSlice(gpa, "|");
                try emit(&line, gpa, d, 0);
            }
        } else |e| {
            try line.print(gpa, "ERR:{s}", .{@errorName(e)});
        }
        try line.append(gpa, '\n');
        try o.writeAll(line.items);
    }
    try o.flush();
}
