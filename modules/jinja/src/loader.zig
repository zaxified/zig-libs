// SPDX-License-Identifier: MIT
//! Where `{% extends %}`, `{% include %}` and `{% import %}` get their bytes.
//!
//! A loader is the module's only path from a template *name* to template
//! *source*, which makes it the module's only real attack surface: the name is
//! frequently attacker-influenced (`{% include 'themes/' ~ theme %}`), and a
//! loader that can be talked into reading `/etc/shadow` turns a template engine
//! into a file-disclosure primitive. `DirLoader` is therefore written as a
//! containment device that happens to read files, not as a file reader with
//! some checks bolted on — see `SPEC.md` §10 for the guarantee and its limits.

const std = @import("std");

pub const Error = error{
    OutOfMemory,
    /// The loader could not answer — an I/O failure, a file too large, a name
    /// the loader refuses. Distinct from "not found", which is `null`.
    LoaderFailed,
};

/// The seam. `load` returns the source for `name` allocated from `arena`, or
/// `null` when there is no such template — `null` is what `ignore missing` and
/// the candidate-list form of `{% include %}` test for, so a loader must not
/// signal absence with an error.
pub const Loader = struct {
    ctx: *const anyopaque,
    load: *const fn (ctx: *const anyopaque, arena: std.mem.Allocator, name: []const u8) Error!?[]const u8,
};

// ── in-memory ───────────────────────────────────────────────────────────────

/// Templates held in memory, looked up by exact name. The whole table can be a
/// comptime constant, which is what makes it the natural loader for tests, for
/// embedded template sets (`@embedFile`) and for callers that fetch their
/// templates from somewhere that is not a filesystem.
pub const MapLoader = struct {
    entries: []const Entry,

    pub const Entry = struct {
        name: []const u8,
        source: []const u8,
    };

    pub fn loader(self: *const MapLoader) Loader {
        return .{ .ctx = self, .load = load };
    }

    fn load(ctx: *const anyopaque, arena: std.mem.Allocator, name: []const u8) Error!?[]const u8 {
        _ = arena;
        const self: *const MapLoader = @ptrCast(@alignCast(ctx));
        for (self.entries) |e| if (std.mem.eql(u8, e.name, name)) return e.source;
        return null;
    }
};

// ── filesystem ──────────────────────────────────────────────────────────────

pub const NameError = error{
    /// The name is empty, over the length cap, or has an empty component.
    MalformedName,
    /// An absolute path, a `..` or `.` component, a backslash, or an embedded
    /// NUL — every lexical way out of the root.
    EscapingName,
};

/// Lexical validation, exported because it is the half of containment that can
/// be tested without touching a filesystem.
///
/// Accepts only a relative, slash-separated path of ordinary components. It
/// rejects `..` outright rather than resolving it: a name that *means* the
/// root after normalization (`a/../b`) is still refused, because accepting it
/// would mean the checker and the kernel have to agree about normalization,
/// and every containment bug in this class is a disagreement about exactly
/// that.
pub fn checkName(name: []const u8) NameError!void {
    if (name.len == 0 or name.len > max_name_len) return error.MalformedName;
    if (name[0] == '/') return error.EscapingName;
    // A Windows drive letter or UNC path is not relative either.
    if (name.len >= 2 and name[1] == ':') return error.EscapingName;

    var it = std.mem.splitScalar(u8, name, '/');
    var components: usize = 0;
    while (it.next()) |c| {
        components += 1;
        if (c.len == 0) return error.MalformedName;
        if (c.len > max_component_len) return error.MalformedName;
        if (std.mem.eql(u8, c, ".") or std.mem.eql(u8, c, "..")) return error.EscapingName;
        for (c) |ch| {
            if (ch == 0) return error.EscapingName;
            // `\` is a separator on Windows; treating it as an ordinary
            // character here would let `..\..\x` through on the one platform
            // where it means something.
            if (ch == '\\') return error.EscapingName;
        }
    }
    if (components > max_components) return error.MalformedName;
}

pub const max_name_len: usize = 1024;
pub const max_component_len: usize = 255;
pub const max_components: usize = 32;

/// Templates read from a directory, contained within it.
///
/// Containment is enforced twice over, and the second half is why this is not
/// just `dir.openFile(name)`:
///
/// 1. **Lexically** (`checkName`): no absolute paths, no `..`, no `.`, no
///    backslashes, no NULs, no empty components.
/// 2. **Structurally**: the path is walked one component at a time, each
///    directory opened relative to the previous handle with
///    `follow_symlinks = false`, and the final file opened the same way. No
///    symlink anywhere along the path is ever traversed, so a symlink planted
///    inside the root cannot redirect a read outside it — and because every
///    open is relative to a held handle rather than to a re-resolved string,
///    there is no window between checking and opening for anything to be
///    swapped underneath.
///
/// `resolve_beneath` is requested as well, where the kernel supports it. It is
/// belt and braces: std documents it as *silently ignored* when unsupported, so
/// nothing here depends on it.
///
/// Set `allow_symlinks` to trade the portable guarantee for the kernel's: with
/// it on, symlinks are followed and containment falls back to `resolve_beneath`
/// alone, which is airtight on a Linux with `openat2` and **absent** elsewhere.
/// Off (the default) is the guarantee this module is willing to state.
pub const DirLoader = struct {
    io: std.Io,
    root: std.Io.Dir,
    options: Options = .{},

    pub const Options = struct {
        /// Appended to every name, so callers can keep `{% extends 'base' %}`
        /// while files are `base.j2`.
        suffix: []const u8 = "",
        /// Refuse a template larger than this rather than allocating it.
        max_bytes: usize = 1 << 20,
        /// See the type doc: leaving this off is what makes containment
        /// portable rather than kernel-dependent.
        allow_symlinks: bool = false,
    };

    pub fn loader(self: *const DirLoader) Loader {
        return .{ .ctx = self, .load = load };
    }

    fn load(ctx: *const anyopaque, arena: std.mem.Allocator, name: []const u8) Error!?[]const u8 {
        const self: *const DirLoader = @ptrCast(@alignCast(ctx));

        var buf: [max_name_len + 64]u8 = undefined;
        const full = if (self.options.suffix.len == 0)
            name
        else blk: {
            if (name.len + self.options.suffix.len > buf.len) return error.LoaderFailed;
            @memcpy(buf[0..name.len], name);
            @memcpy(buf[name.len..][0..self.options.suffix.len], self.options.suffix);
            break :blk buf[0 .. name.len + self.options.suffix.len];
        };

        checkName(full) catch return error.LoaderFailed;

        // Walk the directory components, never following a link.
        var dir = self.root;
        var opened = false;
        defer if (opened) dir.close(self.io);

        var it = std.mem.splitScalar(u8, full, '/');
        var pending: []const u8 = it.next().?;
        while (it.next()) |next_component| {
            const child = dir.openDir(self.io, pending, .{
                .follow_symlinks = self.options.allow_symlinks,
            }) catch |e| switch (e) {
                error.FileNotFound, error.AccessDenied => return null,
                // A symlink escape attempt is a signal, not a missing file
                // (D17). `error.SymLinkLoop` (`ELOOP`) is the textbook errno
                // for "refused to follow a symlink" — but for a *directory*
                // component opened with `O_DIRECTORY | O_NOFOLLOW`, Linux
                // reports the refused symlink as `ENOTDIR`
                // (`error.NotDir`) instead, because the kernel resolves
                // O_DIRECTORY's "is this a directory" check against the
                // unfollowed symlink itself. Both therefore fall through to
                // `LoaderFailed` here rather than reading as "absent" and
                // letting `ignore missing` swallow them (wave-2 audit
                // `jinja` F13).
                else => return error.LoaderFailed,
            };
            if (opened) dir.close(self.io);
            dir = child;
            opened = true;
            pending = next_component;
        }

        var file = dir.openFile(self.io, pending, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = self.options.allow_symlinks,
            .resolve_beneath = true,
        }) catch |e| switch (e) {
            error.FileNotFound, error.IsDir, error.AccessDenied, error.NotDir => return null,
            // See the matching comment above: a symlink escape reads as a
            // refusal (`LoaderFailed`), not as "file absent".
            else => return error.LoaderFailed,
        };
        defer file.close(self.io);

        var read_buf: [4096]u8 = undefined;
        var reader = file.reader(self.io, &read_buf);
        const data = reader.interface.allocRemaining(arena, .limited(self.options.max_bytes)) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.LoaderFailed,
        };
        return data;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "checkName refuses every lexical way out of the root" {
    for ([_][]const u8{
        "/etc/passwd",
        "../secret",
        "a/../../secret",
        "./a",
        "a/./b",
        "a/../b",
        "..",
        "a/..",
        "sub/../../../etc/passwd",
        "..\\windows",
        "a\\b",
        "C:/windows",
        "a//b",
        "/",
        "a/",
        "/a",
        "",
    }) |bad| {
        // Either refusal is fine — `MalformedName` and `EscapingName` are both
        // "no". What must never happen is acceptance.
        if (checkName(bad)) |_| {
            std.debug.print("\ncheckName ACCEPTED a hostile name: '{s}'\n", .{bad});
            return error.NameAccepted;
        } else |_| {}
    }
}

test "checkName accepts ordinary relative names" {
    for ([_][]const u8{ "base.html", "a/b/c.j2", "deep/nested/path/x", "with.dots.in.name" }) |ok| {
        try checkName(ok);
    }
}

test "checkName rejects a NUL-truncation attempt" {
    try testing.expectError(error.EscapingName, checkName("safe\x00/../../etc/passwd"));
}

test "checkName bounds name and component length" {
    const long_component = "a" ** (max_component_len + 1);
    try testing.expectError(error.MalformedName, checkName(long_component));
    var buf: [max_name_len + 2]u8 = undefined;
    @memset(&buf, 'a');
    try testing.expectError(error.MalformedName, checkName(&buf));
}

test "MapLoader answers by exact name and null otherwise" {
    const m: MapLoader = .{ .entries = &.{ .{ .name = "a", .source = "A" }, .{ .name = "b/c", .source = "BC" } } };
    const l = m.loader();
    const a = testing.allocator;
    try testing.expectEqualStrings("A", (try l.load(l.ctx, a, "a")).?);
    try testing.expectEqualStrings("BC", (try l.load(l.ctx, a, "b/c")).?);
    try testing.expect((try l.load(l.ctx, a, "nope")) == null);
    try testing.expect((try l.load(l.ctx, a, "")) == null);
}
