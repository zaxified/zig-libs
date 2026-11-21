// SPDX-License-Identifier: MIT
//! Kernel configuration for `extern ... __kconfig` variables: parse the
//! running kernel's `.config` and write each requested value into the
//! `.kconfig` map's value, typed by the object's BTF, as libbpf does.
//!
//! ## Where the configuration comes from
//!
//! `/proc/config.gz` (gzip, `CONFIG_IKCONFIG_PROC`) first, then
//! `/boot/config-<release>`, the order libbpf tries. Only `CONFIG_*=value`
//! lines count: `# CONFIG_X is not set` is a comment, so an option that is
//! off is *absent*, not "n" (a strong extern for it is an error, a `__weak` one
//! reads 0), exactly libbpf's behaviour. `LINUX_KERNEL_VERSION` is not in the
//! file: it is the running release as `(major << 16) + (minor << 8) + patch`
//! (patch clamped to 255, as `KERNEL_VERSION` does).
//!
//! ## What a variable's BTF type says it can hold
//!
//! | declared as | accepts |
//! |---|---|
//! | `_Bool` (1-byte INT with the BOOL encoding) | `y`, `n` (`m` is an error) |
//! | `enum libbpf_tristate` | `y`, `n`, `m` (1, 0, 2) |
//! | `char` | `y`/`n`/`m` as that character, or a small number |
//! | `char[N]` | a string, which must fit in `N - 1` bytes |
//! | an integer of 1, 2, 4 or 8 bytes | a decimal / `0x` hex number that fits its width and sign |
//!
//! Anything else is `error.UnsupportedType`, a value that does not fit is
//! `error.OutOfRange`: a clamped or truncated configuration value would make
//! a program take the wrong branch silently.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const btf = @import("btf.zig");
const elfsym = @import("elfsym.zig");

pub const Value = union(enum) {
    /// `y`, `m` or `n` (`CONFIG_X=y`).
    tristate: u8,
    /// A number, with its sign kept apart so `u64` values above `i64` max fit.
    int: struct { negative: bool, magnitude: u64 },
    string: []const u8,
};

pub const Config = struct {
    arena: std.heap.ArenaAllocator,
    entries: std.StringHashMapUnmanaged(Value),

    pub fn deinit(self: *Config) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn get(self: *const Config, name: []const u8) ?Value {
        return self.entries.get(name);
    }
};

pub const ParseError = error{ BadLine, OutOfMemory };

/// Parse a kernel `.config`. A malformed `CONFIG_` line is `error.BadLine`
/// (libbpf refuses the whole file too); everything that does not start with
/// `CONFIG_` is ignored.
pub fn parse(gpa: std.mem.Allocator, text: []const u8) ParseError!Config {
    var cfg: Config = .{ .arena = .init(gpa), .entries = .empty };
    errdefer cfg.arena.deinit();
    const a = cfg.arena.allocator();
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (!std.mem.startsWith(u8, line, "CONFIG_")) continue;
        const eq = std.mem.findScalar(u8, line, '=') orelse return error.BadLine;
        const key = line[0..eq];
        const val = line[eq + 1 ..];
        if (val.len == 0) return error.BadLine;
        const v: Value = switch (val[0]) {
            'y', 'm', 'n' => blk: {
                if (val.len != 1) return error.BadLine;
                break :blk .{ .tristate = val[0] };
            },
            '"' => blk: {
                if (val.len < 2 or val[val.len - 1] != '"') return error.BadLine;
                break :blk .{ .string = a.dupe(u8, val[1 .. val.len - 1]) catch return error.OutOfMemory };
            },
            else => blk: {
                var neg = false;
                var digits = val;
                if (digits[0] == '-') {
                    neg = true;
                    digits = digits[1..];
                }
                const m = std.fmt.parseInt(u64, digits, 0) catch return error.BadLine;
                break :blk .{ .int = .{ .negative = neg, .magnitude = m } };
            },
        };
        cfg.entries.put(a, a.dupe(u8, key) catch return error.OutOfMemory, v) catch return error.OutOfMemory;
    }
    return cfg;
}

/// `KERNEL_VERSION(major, minor, patch)` of a release string such as
/// `"6.8.0-45-generic"`; `null` when it does not start with `N.N`.
pub fn kernelVersionCode(release: []const u8) ?u32 {
    var it = std.mem.splitScalar(u8, release, '.');
    const maj = digitsPrefix(it.next() orelse return null) orelse return null;
    const min = digitsPrefix(it.next() orelse return null) orelse return null;
    const pat = if (it.next()) |p| (digitsPrefix(p) orelse 0) else 0;
    if (maj > 255 or min > 255) return null;
    return (maj << 16) + (min << 8) + @min(pat, 255);
}

fn digitsPrefix(s: []const u8) ?u32 {
    var n: usize = 0;
    while (n < s.len and std.ascii.isDigit(s[n])) n += 1;
    if (n == 0) return null;
    return std.fmt.parseInt(u32, s[0..n], 10) catch null;
}

pub const FillError = error{ UnsupportedType, OutOfRange, BadValue };

const Class = enum { bool_, tristate, char, char_array, int };

const Shape = struct { class: Class, size: u32, signed: bool };

fn classify(b: *const btf.Btf, type_id: u32) FillError!Shape {
    const t = b.resolve(type_id) catch return error.UnsupportedType;
    switch (t.kind) {
        .int => {
            const info = b.intInfo(t) catch return error.UnsupportedType;
            const size = t.size_type;
            if (info.offset != 0) return error.UnsupportedType;
            if (info.isBool() and size == 1) return .{ .class = .bool_, .size = 1, .signed = false };
            if (info.isChar() and size == 1) return .{ .class = .char, .size = 1, .signed = info.isSigned() };
            switch (size) {
                1, 2, 4, 8 => return .{ .class = .int, .size = size, .signed = info.isSigned() },
                else => return error.UnsupportedType,
            }
        },
        .@"enum" => {
            const name = b.str(t.name_off) orelse return error.UnsupportedType;
            if (!std.mem.eql(u8, name, "libbpf_tristate") or t.size_type != 4) return error.UnsupportedType;
            return .{ .class = .tristate, .size = 4, .signed = false };
        },
        .array => {
            const a = b.arrayInfo(t) catch return error.UnsupportedType;
            const e = b.resolve(a.elem_type) catch return error.UnsupportedType;
            if (e.kind != .int or e.size_type != 1) return error.UnsupportedType;
            return .{ .class = .char_array, .size = a.nelems, .signed = false };
        },
        else => return error.UnsupportedType,
    }
}

/// The number of bytes the variable of BTF type `type_id` occupies, and its
/// alignment: what the `.kconfig` map layout is built from.
pub fn sizeAlign(b: *const btf.Btf, type_id: u32) FillError!struct { size: u32, align_: u32 } {
    const sh = try classify(b, type_id);
    return .{ .size = sh.size, .align_ = switch (sh.class) {
        .char_array => 1,
        else => sh.size,
    } };
}

/// Write `value` into `out[0..size]` as the BTF type `type_id` requires.
pub fn fill(b: *const btf.Btf, type_id: u32, value: Value, out: []u8) FillError!void {
    const sh = try classify(b, type_id);
    if (out.len < sh.size) return error.OutOfRange;
    const end = builtin.cpu.arch.endian();
    switch (value) {
        .tristate => |c| switch (sh.class) {
            .bool_ => {
                if (c == 'm') return error.BadValue;
                out[0] = @intFromBool(c == 'y');
            },
            .tristate => std.mem.writeInt(u32, out[0..4], switch (c) {
                'y' => 1,
                'm' => 2,
                else => 0,
            }, end),
            .char => out[0] = c,
            else => return error.BadValue,
        },
        .int => |n| switch (sh.class) {
            .int, .char => try writeNumber(out[0..sh.size], n.negative, n.magnitude, sh.signed, end),
            else => return error.BadValue,
        },
        .string => |s| switch (sh.class) {
            .char_array => {
                if (s.len + 1 > sh.size) return error.OutOfRange;
                @memcpy(out[0..s.len], s);
                @memset(out[s.len..sh.size], 0);
            },
            else => return error.BadValue,
        },
    }
}

fn writeNumber(dst: []u8, negative: bool, magnitude: u64, signed: bool, end: std.builtin.Endian) FillError!void {
    const bits: u7 = @intCast(dst.len * 8);
    if (signed) {
        // [-2^(bits-1), 2^(bits-1) - 1]
        const limit: u64 = @as(u64, 1) << @intCast(bits - 1);
        if (negative) {
            if (magnitude > limit) return error.OutOfRange;
        } else if (magnitude >= limit) return error.OutOfRange;
    } else {
        if (negative and magnitude != 0) return error.OutOfRange;
        if (bits < 64 and magnitude >= (@as(u64, 1) << @intCast(bits))) return error.OutOfRange;
    }
    const v: u64 = if (negative) 0 -% magnitude else magnitude;
    switch (dst.len) {
        1 => dst[0] = @truncate(v),
        2 => std.mem.writeInt(u16, dst[0..2], @truncate(v), end),
        4 => std.mem.writeInt(u32, dst[0..4], @truncate(v), end),
        8 => std.mem.writeInt(u64, dst[0..8], v, end),
        else => return error.UnsupportedType,
    }
}

// ── reading the running kernel's configuration ──────────────────────────────

/// Read a whole file that does not report its size (`/proc` files).
pub fn readStreaming(gpa: std.mem.Allocator, path: [:0]const u8, max: usize) error{ OpenFailed, ReadFailed, TooLarge, OutOfMemory }![]u8 {
    if (comptime builtin.os.tag != .linux) @compileError("ebpf.kconfig is Linux-only");
    const rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.OpenFailed;
    const fd: linux.fd_t = @intCast(rc);
    defer _ = linux.close(fd);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var chunk: [16 * 1024]u8 = undefined;
    while (true) {
        const r = linux.read(fd, &chunk, chunk.len);
        switch (linux.errno(r)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        if (r == 0) break;
        if (out.items.len + r > max) return error.TooLarge;
        out.appendSlice(gpa, chunk[0..r]) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice(gpa) catch return error.OutOfMemory;
}

/// The address of kernel symbol `name` in `/proc/kallsyms`-formatted `text`
/// (`addr type name [module]`), or `null` — also when the address reads 0,
/// which is what an unprivileged reader (`kptr_restrict`) is shown.
pub fn kallsymsAddress(text: []const u8, name: []const u8) ?u64 {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        var f = std.mem.tokenizeAny(u8, line, " \t");
        const addr = f.next() orelse continue;
        _ = f.next() orelse continue; // type letter
        const sym = f.next() orelse continue;
        if (!std.mem.eql(u8, sym, name)) continue;
        const v = std.fmt.parseInt(u64, addr, 16) catch continue;
        if (v == 0) return null;
        return v;
    }
    return null;
}

pub const ReadError = error{ NoKernelConfig, BadConfig } || ParseError;

/// The running kernel's configuration: `/proc/config.gz`, else
/// `/boot/config-<release>` (`release` as `uname -r` says).
pub fn readKernelConfig(gpa: std.mem.Allocator) ReadError!Config {
    if (comptime builtin.os.tag != .linux) @compileError("ebpf.kconfig is Linux-only");
    if (readStreaming(gpa, "/proc/config.gz", 8 << 20)) |gz| {
        defer gpa.free(gz);
        var in: std.Io.Reader = .fixed(gz);
        var window: [std.compress.flate.max_window_len]u8 = undefined;
        var d: std.compress.flate.Decompress = .init(&in, .gzip, &window);
        const text = d.reader.allocRemaining(gpa, .limited(32 << 20)) catch return error.BadConfig;
        defer gpa.free(text);
        return parse(gpa, text);
    } else |_| {}
    var uts: linux.utsname = undefined;
    if (linux.errno(linux.uname(&uts)) != .SUCCESS) return error.NoKernelConfig;
    const release = std.mem.sliceTo(&uts.release, 0);
    var path_buf: [128]u8 = undefined;
    const path = std.mem.print(&path_buf, "/boot/config-{s}", .{release}) catch return error.NoKernelConfig;
    const text = elfsym.readFileAlloc(gpa, path, 32 << 20) catch return error.NoKernelConfig;
    defer gpa.free(text);
    return parse(gpa, text);
}

/// `LINUX_KERNEL_VERSION` of the running kernel.
pub fn runningKernelVersion() ?u32 {
    var uts: linux.utsname = undefined;
    if (linux.errno(linux.uname(&uts)) != .SUCCESS) return null;
    return kernelVersionCode(std.mem.sliceTo(&uts.release, 0));
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const RawBtf = btf.RawBtf;

test "parse: only CONFIG_ lines count, every value form" {
    const gpa = testing.allocator;
    var c = try parse(gpa,
        \\# Automatically generated
        \\# CONFIG_OFF is not set
        \\CONFIG_BPF=y
        \\CONFIG_TUN=m
        \\CONFIG_HZ=250
        \\CONFIG_NEG=-5
        \\CONFIG_BASE=0xff
        \\CONFIG_NAME="(none)"
        \\CONFIG_EMPTY=""
        \\ CONFIG_INDENT=y 
        \\NOT_CONFIG=1
        \\
    );
    defer c.deinit();
    try testing.expectEqual(@as(u8, 'y'), c.get("CONFIG_BPF").?.tristate);
    try testing.expectEqual(@as(u8, 'm'), c.get("CONFIG_TUN").?.tristate);
    try testing.expectEqual(@as(u64, 250), c.get("CONFIG_HZ").?.int.magnitude);
    try testing.expect(c.get("CONFIG_NEG").?.int.negative);
    try testing.expectEqual(@as(u64, 0xff), c.get("CONFIG_BASE").?.int.magnitude);
    try testing.expectEqualStrings("(none)", c.get("CONFIG_NAME").?.string);
    try testing.expectEqualStrings("", c.get("CONFIG_EMPTY").?.string);
    try testing.expectEqual(@as(u8, 'y'), c.get("CONFIG_INDENT").?.tristate);
    // an option that is off is absent, never "n"
    try testing.expect(c.get("CONFIG_OFF") == null);
    try testing.expect(c.get("NOT_CONFIG") == null);
    for ([_][]const u8{ "CONFIG_X", "CONFIG_X=", "CONFIG_X=yy", "CONFIG_X=\"abc", "CONFIG_X=12abc", "CONFIG_X=0xzz" }) |bad| {
        try testing.expectError(error.BadLine, parse(gpa, bad));
    }
}

test "kernelVersionCode: KERNEL_VERSION(major, minor, patch) with the patch clamped" {
    try testing.expectEqual(@as(?u32, (6 << 16) + (8 << 8) + 0), kernelVersionCode("6.8.0-45-generic"));
    try testing.expectEqual(@as(?u32, (5 << 16) + (15 << 8) + 12), kernelVersionCode("5.15.12"));
    try testing.expectEqual(@as(?u32, (7 << 16) + (0 << 8) + 0), kernelVersionCode("7.0.0-44-generic"));
    try testing.expectEqual(@as(?u32, (4 << 16) + (19 << 8) + 255), kernelVersionCode("4.19.300")); // clamped
    try testing.expectEqual(@as(?u32, (6 << 16) + (1 << 8) + 0), kernelVersionCode("6.1")); // no patch
    try testing.expect(kernelVersionCode("") == null);
    try testing.expect(kernelVersionCode("six.eight") == null);
    try testing.expect(kernelVersionCode("6") == null);
}

fn mkTypes(gpa: std.mem.Allocator) !struct { blob: []u8, ids: struct { b: u32, u8_: u32, i8_: u32, chr: u32, u32_: u32, i32_: u32, u64_: u32, tri: u32, arr: u32, ptr: u32 } } {
    var r = try RawBtf.init(gpa);
    defer r.deinit(gpa);
    const n_tri = try r.str(gpa, "libbpf_tristate");
    const n_y = try r.str(gpa, "TRI_YES");
    const bool_t = try r.rec(gpa, 0, btf.K_INT, 0, false, 1, &.{(4 << 24) | 8});
    const u8_t = try r.rec(gpa, 0, btf.K_INT, 0, false, 1, &.{8});
    const i8_t = try r.rec(gpa, 0, btf.K_INT, 0, false, 1, &.{(1 << 24) | 8});
    const chr = try r.rec(gpa, 0, btf.K_INT, 0, false, 1, &.{(3 << 24) | 8}); // signed + char
    const u32_t = try r.rec(gpa, 0, btf.K_INT, 0, false, 4, &.{32});
    const i32_t = try r.rec(gpa, 0, btf.K_INT, 0, false, 4, &.{(1 << 24) | 32});
    const u64_t = try r.rec(gpa, 0, btf.K_INT, 0, false, 8, &.{64});
    const tri = try r.rec(gpa, n_tri, btf.K_ENUM, 1, false, 4, &.{ n_y, 1 });
    const arr = try r.rec(gpa, 0, btf.K_ARRAY, 0, false, 0, &.{ chr, u32_t, 8 });
    const ptr = try r.rec(gpa, 0, btf.K_PTR, 0, false, u32_t, &.{});
    return .{ .blob = try r.finish(gpa), .ids = .{ .b = bool_t, .u8_ = u8_t, .i8_ = i8_t, .chr = chr, .u32_ = u32_t, .i32_ = i32_t, .u64_ = u64_t, .tri = tri, .arr = arr, .ptr = ptr } };
}

test "fill: each declared type accepts what libbpf accepts and nothing else" {
    const gpa = testing.allocator;
    const m = try mkTypes(gpa);
    defer gpa.free(m.blob);
    var b = try btf.parse(gpa, m.blob, .{});
    defer b.deinit();
    const ids = m.ids;
    var out: [16]u8 = @splat(0xaa);

    // bool: y/n, not m
    try fill(&b, ids.b, .{ .tristate = 'y' }, &out);
    try testing.expectEqual(@as(u8, 1), out[0]);
    try fill(&b, ids.b, .{ .tristate = 'n' }, &out);
    try testing.expectEqual(@as(u8, 0), out[0]);
    try testing.expectError(error.BadValue, fill(&b, ids.b, .{ .tristate = 'm' }, &out));
    try testing.expectError(error.BadValue, fill(&b, ids.b, .{ .int = .{ .negative = false, .magnitude = 1 } }, &out));
    // tristate enum
    try fill(&b, ids.tri, .{ .tristate = 'm' }, &out);
    try testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, out[0..4], .little));
    try fill(&b, ids.tri, .{ .tristate = 'n' }, &out);
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, out[0..4], .little));
    // integers: width and sign are enforced
    try fill(&b, ids.u32_, .{ .int = .{ .negative = false, .magnitude = 4294967295 } }, &out);
    try testing.expectEqual(@as(u32, 0xffff_ffff), std.mem.readInt(u32, out[0..4], .little));
    try testing.expectError(error.OutOfRange, fill(&b, ids.u32_, .{ .int = .{ .negative = false, .magnitude = 4294967296 } }, &out));
    try testing.expectError(error.OutOfRange, fill(&b, ids.u32_, .{ .int = .{ .negative = true, .magnitude = 1 } }, &out));
    try fill(&b, ids.i32_, .{ .int = .{ .negative = true, .magnitude = 2147483648 } }, &out);
    try testing.expectEqual(@as(i32, std.math.minInt(i32)), std.mem.readInt(i32, out[0..4], .little));
    try testing.expectError(error.OutOfRange, fill(&b, ids.i32_, .{ .int = .{ .negative = false, .magnitude = 2147483648 } }, &out));
    try fill(&b, ids.u64_, .{ .int = .{ .negative = false, .magnitude = std.math.maxInt(u64) } }, &out);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), std.mem.readInt(u64, out[0..8], .little));
    try fill(&b, ids.i8_, .{ .int = .{ .negative = true, .magnitude = 128 } }, &out);
    try testing.expectEqual(@as(u8, 0x80), out[0]);
    try testing.expectError(error.OutOfRange, fill(&b, ids.u8_, .{ .int = .{ .negative = false, .magnitude = 256 } }, &out));
    // a tristate letter on an int is refused (libbpf: "implies tristate or char type")
    try testing.expectError(error.BadValue, fill(&b, ids.u32_, .{ .tristate = 'y' }, &out));
    // char takes a letter; char[N] a string that fits with its NUL
    try fill(&b, ids.chr, .{ .tristate = 'y' }, &out);
    try testing.expectEqual(@as(u8, 'y'), out[0]);
    @memset(&out, 0xaa);
    try fill(&b, ids.arr, .{ .string = "abcdefg" }, &out);
    try testing.expectEqualSlices(u8, "abcdefg\x00", out[0..8]);
    try testing.expectEqual(@as(u8, 0xaa), out[8]); // nothing past the array is touched
    try testing.expectError(error.OutOfRange, fill(&b, ids.arr, .{ .string = "abcdefgh" }, &out));
    try testing.expectError(error.BadValue, fill(&b, ids.u32_, .{ .string = "x" }, &out));
    // a pointer is not a configuration value
    try testing.expectError(error.UnsupportedType, fill(&b, ids.ptr, .{ .tristate = 'y' }, &out));
    // size and alignment for layout
    const sa = try sizeAlign(&b, ids.arr);
    try testing.expectEqual(@as(u32, 8), sa.size);
    try testing.expectEqual(@as(u32, 1), sa.align_);
    try testing.expectEqual(@as(u32, 4), (try sizeAlign(&b, ids.tri)).align_);
}

test "readKernelConfig: reads this machine's configuration, or says there is none" {
    const gpa = testing.allocator;
    if (readKernelConfig(gpa)) |c| {
        var cfg = c;
        defer cfg.deinit();
        // every kernel that can run BPF programs has these
        try testing.expect(cfg.get("CONFIG_BPF") != null or cfg.get("CONFIG_BPF_SYSCALL") != null or cfg.entries.count() > 0);
    } else |e| try testing.expect(e == error.NoKernelConfig or e == error.BadConfig);
    try testing.expect(runningKernelVersion() != null);
}

test "kallsymsAddress: exact names, the first match, and the zero an unprivileged reader sees" {
    const text =
        \\ffffffff81000000 T _stext
        \\ffffffff81001000 t bpf_prog_active
        \\ffffffffc0001000 t bpf_prog_active_x [some_mod]
        \\0000000000000000 d hidden_symbol
        \\garbage
    ;
    try testing.expectEqual(@as(?u64, 0xffffffff81001000), kallsymsAddress(text, "bpf_prog_active"));
    try testing.expectEqual(@as(?u64, 0xffffffffc0001000), kallsymsAddress(text, "bpf_prog_active_x"));
    try testing.expectEqual(@as(?u64, null), kallsymsAddress(text, "hidden_symbol"));
    try testing.expectEqual(@as(?u64, null), kallsymsAddress(text, "absent"));
    try testing.expectEqual(@as(?u64, null), kallsymsAddress(text, "bpf_prog"));
}
