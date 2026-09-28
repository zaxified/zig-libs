// SPDX-License-Identifier: MIT

//! Reading three real kinds of INI file with `ini`: a Midnight Commander
//! skin (sections read case-insensitively, `;` inside values), a Desktop
//! Entry (localized keys, escapes resolved on request) and a Python-style
//! config (continuation lines, `:` separators, a boolean) -- and what a
//! strict parse says about a broken line.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const ini = @import("ini");

/// A check that survives every optimize mode (the lanes RUN the examples).
fn must(ok: bool, src: std.builtin.SourceLocation) void {
    if (!ok) std.debug.panic("example check failed at {s}:{d}", .{ src.file, src.line });
}

const skin =
    \\[skin]
    \\    description = Blue on grey
    \\[Core]
    \\    _default_ = lightgray;blue
    \\    selected = black;cyan
;

const desktop_entry =
    \\[Desktop Entry]
    \\Type=Application
    \\Name=Files
    \\Name[cs]=Soubory
    \\Comment=Browse\sthe\sfile\ssystem
;

const python_cfg =
    \\[server]
    \\hosts = alpha
    \\    beta
    \\    gamma
    \\port: 8080
    \\debug = yes
;

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    {
        var doc = try ini.parse(gpa, skin, .{ .case_insensitive_sections = true });
        defer doc.deinit();
        const sel = doc.get("core", "selected").?;
        std.debug.print("mc skin: [core] selected = {s}\n", .{sel});
        must(std.mem.eql(u8, sel, "black;cyan"), @src());
    }
    {
        var doc = try ini.parse(gpa, desktop_entry, .desktop);
        defer doc.deinit();
        const comment = try ini.unescapeDesktop(gpa, doc.get("Desktop Entry", "Comment").?);
        defer gpa.free(comment);
        std.debug.print("desktop: Name[cs] = {s}, Comment = {s}\n", .{ doc.get("Desktop Entry", "Name[cs]").?, comment });
        must(std.mem.eql(u8, comment, "Browse the file system"), @src());
    }
    {
        var doc = try ini.parse(gpa, python_cfg, .python);
        defer doc.deinit();
        const hosts = doc.get("server", "hosts").?;
        var it = std.mem.splitScalar(u8, hosts, '\n');
        var n: usize = 0;
        while (it.next()) |h| : (n += 1) std.debug.print("python: host {d} = {s}\n", .{ n + 1, h });
        must(n == 3, @src());
        must((try doc.getBool("server", "debug")).? == true, @src());
        must(std.mem.eql(u8, doc.get("server", "port").?, "8080"), @src());
    }
    {
        var info: ini.ErrorInfo = .{};
        const broken = "[a]\nk = v\nthis line has no separator\n";
        if (ini.parseDiag(gpa, broken, .{}, &info)) |d| {
            var doc = d;
            doc.deinit();
            must(false, @src());
        } else |err| {
            std.debug.print("strict: {t} at line {d}\n", .{ err, info.line });
            must(err == error.MissingSeparator and info.line == 3, @src());
        }
    }
}
