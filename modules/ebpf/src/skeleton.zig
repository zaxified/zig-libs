// SPDX-License-Identifier: MIT
//! A Zig skeleton for a BPF object: `bpftool gen skeleton`'s job, written as
//! Zig source from the object's BTF.
//!
//! `generate` reads an opened `Object` and writes a `.zig` file with
//!
//! - `object_bytes`, the object embedded with `@embedFile`;
//! - one `extern struct` per data section (`Rodata`, `Data`, `Bss`, ...) whose
//!   fields are the section's global variables, laid out at the offsets the
//!   `DATASEC` says (explicit padding between them, `comptime` offset checks),
//!   so a `const volatile` configuration is a field assignment;
//! - `Program` and `Map` enums of the object's program and map names;
//! - a `Skeleton` wrapper: `open`, `load`, `deinit`, `seed<Section>()` (a typed,
//!   writable pointer at the section's initial contents, valid before `load`),
//!   `map<Section>()` (the live mapping after `load`, `ebpf.MappedData`),
//!   `programFd` and `mapFd`.
//!
//! The struct types come from the BTF: integers by size and sign, `bool`,
//! floats, enums by size, pointers as `u64`, arrays, nested structs and unions.
//! A struct that has a bitfield (or anything that cannot be mirrored with Zig's
//! `extern` layout rules) is emitted as an opaque `[size]u8`, so the offsets
//! around it still hold. Layout is asserted at compile time, never trusted.

const std = @import("std");
const object = @import("object.zig");
const btf = @import("btf.zig");

const Object = object.Object;
const Btf = btf.Btf;

pub const Options = struct {
    /// What the generated file passes to `@embedFile`: the object's path
    /// relative to the generated file.
    object_path: []const u8,
    /// How the generated file imports this module.
    ebpf_import: []const u8 = "ebpf",
};

pub const Error = std.Io.Writer.Error || object.ParseError || error{OutOfMemory};

/// A Zig identifier for a section name: `.rodata` -> `Rodata`, `.data.foo` ->
/// `DataFoo`. `buf` must be at least as long as `sec`.
fn sectionIdent(buf: []u8, sec: []const u8) []const u8 {
    var n: usize = 0;
    var up = true;
    for (sec) |c| {
        if (std.ascii.isAlphanumeric(c)) {
            buf[n] = if (up) std.ascii.toUpper(c) else c;
            up = false;
            n += 1;
        } else up = true;
    }
    if (n == 0) {
        buf[0] = 'S';
        n = 1;
    }
    return buf[0..n];
}

/// The same, lower-cased start: `Rodata` -> `rodata` (a method suffix).
fn id(w: *std.Io.Writer, name: []const u8) std.Io.Writer.Error!void {
    try w.print("{f}", .{std.zig.fmtId(name)});
}

const max_depth: u32 = 12;

/// Write the Zig type for BTF type `type_id`. `false` when it has to be an
/// opaque byte array (the caller then writes `[size]u8`).
fn writeType(b: *const Btf, type_id: u32, w: *std.Io.Writer, depth: u32) Error!bool {
    if (depth > max_depth) return false;
    if (type_id == 0) return false;
    const t = b.resolve(type_id) catch return false;
    switch (t.kind) {
        .int => {
            const info = b.intInfo(t) catch return false;
            const size = t.size_type;
            if (info.offset != 0) return false;
            if (info.isBool() and size == 1) {
                try w.writeAll("bool");
                return true;
            }
            switch (size) {
                1, 2, 4, 8, 16 => {
                    try w.print("{c}{d}", .{ @as(u8, if (info.isSigned()) 'i' else 'u'), size * 8 });
                    return true;
                },
                else => return false,
            }
        },
        .@"enum", .enum64 => {
            switch (t.size_type) {
                1, 2, 4, 8 => {
                    try w.print("{c}{d}", .{ @as(u8, if (t.kind_flag) 'i' else 'u'), t.size_type * 8 });
                    return true;
                },
                else => return false,
            }
        },
        .float => switch (t.size_type) {
            4 => {
                try w.writeAll("f32");
                return true;
            },
            8 => {
                try w.writeAll("f64");
                return true;
            },
            else => return false,
        },
        .ptr => {
            try w.writeAll("u64");
            return true;
        },
        .array => {
            const a = b.arrayInfo(t) catch return false;
            // a flexible array (0 elements) keeps its place as a zero-length array
            try w.print("[{d}]", .{a.nelems});
            if (!try writeType(b, a.elem_type, w, depth + 1)) {
                const esz = b.sizeOf(a.elem_type) catch return false;
                try w.print("[{d}]u8", .{esz});
            }
            return true;
        },
        .@"struct", .@"union" => return writeComposite(b, t, w, depth),
        else => return false,
    }
}

fn writeComposite(b: *const Btf, t: btf.Type, w: *std.Io.Writer, depth: u32) Error!bool {
    // A bitfield, or an unnamed member, cannot be mirrored as a field.
    var i: u16 = 0;
    while (i < t.vlen) : (i += 1) {
        const m = b.member(t, i) catch return false;
        if (m.bitfield_size != 0) return false;
        if (m.bit_offset % 8 != 0) return false;
    }
    const is_union = t.kind == .@"union";
    try w.writeAll(if (is_union) "extern union { " else "extern struct { ");
    var at: u64 = 0; // byte offset reached so far
    var pad: u32 = 0;
    i = 0;
    while (i < t.vlen) : (i += 1) {
        const m = b.member(t, i) catch return false;
        const off = m.bit_offset / 8;
        const name = b.str(m.name_off) orelse "";
        if (!is_union and off > at) {
            try w.print("_pad{d}: [{d}]u8, ", .{ pad, off - at });
            pad += 1;
        }
        if (name.len == 0) {
            try w.print("_anon{d}: ", .{i});
        } else {
            try id(w, name);
            try w.writeAll(": ");
        }
        if (!try writeType(b, m.type_id, w, depth + 1)) {
            const sz = b.sizeOf(m.type_id) catch return false;
            try w.print("[{d}]u8", .{sz});
        }
        try w.writeAll(", ");
        const sz = b.sizeOf(m.type_id) catch return false;
        if (!is_union) at = off + sz;
    }
    if (!is_union and t.size_type > at) try w.print("_pad{d}: [{d}]u8, ", .{ pad, t.size_type - at });
    try w.writeAll("}");
    return true;
}

fn writeDataStruct(
    obj: *Object,
    m: object.MapSpec,
    name: []const u8,
    w: *std.Io.Writer,
) Error!void {
    const b = &(obj.btf orelse return);
    const vars = try obj.dataVariables(m.name);
    try w.print("\n/// The `{s}` section: its global variables at their section offsets.\n", .{m.name});
    try w.print("pub const {s} = extern struct {{\n", .{name});
    var at: u64 = 0;
    var pad: u32 = 0;
    // variables in offset order (the DATASEC is sorted by `fixupDatasecs`)
    for (vars) |v| {
        if (v.offset > at) {
            try w.print("    _pad{d}: [{d}]u8,\n", .{ pad, v.offset - at });
            pad += 1;
        }
        try w.writeAll("    ");
        try id(w, v.name);
        try w.writeAll(": ");
        if (!try writeType(b, v.type_id, w, 0)) try w.print("[{d}]u8", .{v.size});
        try w.writeAll(",\n");
        at = @as(u64, v.offset) + v.size;
    }
    if (m.value_size > at) try w.print("    _pad{d}: [{d}]u8,\n", .{ pad, m.value_size - at });
    try w.writeAll("};\n");
    try w.writeAll("comptime {\n");
    for (vars) |v| {
        try w.writeAll("    std.debug.assert(@offsetOf(");
        try w.print("{s}, \"{s}\") == {d});\n", .{ name, v.name, v.offset });
    }
    try w.print("    std.debug.assert(@sizeOf({s}) == {d});\n}}\n", .{ name, m.value_size });
}

/// Write the skeleton for `obj` (opened, not loaded) to `w`.
pub fn generate(gpa: std.mem.Allocator, obj: *Object, opts: Options, w: *std.Io.Writer) Error!void {
    try w.print("// Generated by ebpf.skeleton from {s}. Do not edit.\n", .{opts.object_path});
    try w.print("const std = @import(\"std\");\nconst ebpf = @import(\"{s}\");\n\n", .{opts.ebpf_import});
    try w.print("pub const object_bytes = @embedFile(\"{s}\");\n", .{opts.object_path});

    // data sections
    var names: std.ArrayList([]const u8) = .empty;
    defer names.deinit(gpa);
    var bufs: std.ArrayList([]u8) = .empty;
    defer {
        for (bufs.items) |bb| gpa.free(bb);
        bufs.deinit(gpa);
    }
    var maps_with_data: std.ArrayList(usize) = .empty;
    defer maps_with_data.deinit(gpa);
    for (obj.maps, 0..) |m, mi| {
        if (m.origin != .internal) continue;
        const vars = try obj.dataVariables(m.name);
        if (vars.len == 0) continue;
        const buf = gpa.alloc(u8, m.name.len + 1) catch return error.OutOfMemory;
        bufs.append(gpa, buf) catch {
            gpa.free(buf);
            return error.OutOfMemory;
        };
        const nm = sectionIdent(buf, m.name);
        names.append(gpa, nm) catch return error.OutOfMemory;
        maps_with_data.append(gpa, mi) catch return error.OutOfMemory;
        try writeDataStruct(obj, m, nm, w);
    }

    try w.writeAll("\npub const Program = enum {\n");
    for (obj.programs) |p| {
        try w.writeAll("    ");
        try id(w, p.name);
        try w.writeAll(",\n");
    }
    try w.writeAll("};\n\npub const Map = enum {\n");
    for (obj.maps) |m| {
        try w.writeAll("    ");
        try id(w, m.name);
        try w.writeAll(",\n");
    }
    try w.writeAll("};\n");

    try w.writeAll(
        \\
        \\pub const Skeleton = struct {
        \\    obj: ebpf.Object,
        \\
        \\    pub fn open(gpa: std.mem.Allocator) ebpf.ObjectOpenError!Skeleton {
        \\        return .{ .obj = try ebpf.openObject(gpa, object_bytes, .{}) };
        \\    }
        \\
        \\    pub fn deinit(self: *Skeleton) void {
        \\        self.obj.deinit();
        \\    }
        \\
        \\    pub fn load(self: *Skeleton, opts: ebpf.ObjectLoadOptions) ebpf.ObjectLoadError!void {
        \\        return ebpf.loadObject(&self.obj, opts);
        \\    }
        \\
        \\    pub fn programFd(self: *Skeleton, p: Program) ?std.os.linux.fd_t {
        \\        return self.obj.programFd(@tagName(p));
        \\    }
        \\
        \\    pub fn mapFd(self: *Skeleton, m: Map) ?std.os.linux.fd_t {
        \\        return self.obj.mapFd(@tagName(m));
        \\    }
        \\
    );
    for (names.items, maps_with_data.items) |nm, mi| {
        const m = obj.maps[mi];
        try w.print(
            \\
            \\    /// The `{[sec]s}` contents the map is seeded with: edit before `load`.
            \\    pub fn seed{[n]s}(self: *Skeleton) *{[n]s} {{
            \\        return @ptrCast(@alignCast(self.obj.initialData("{[sec]s}").?.ptr));
            \\    }}
            \\
            \\    /// The live `{[sec]s}` after `load`; `deinit` the result.
            \\    pub fn map{[n]s}(self: *Skeleton) ebpf.object.MapDataError!ebpf.object.MappedData {{
            \\        return self.obj.mapData("{[sec]s}");
            \\    }}
            \\
        , .{ .sec = m.name, .n = nm });
    }
    try w.writeAll("};\n");
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const fx_rodata = @embedFile("testdata/rodata_const.bpf.o");
const fx_mapinmap = @embedFile("testdata/mapinmap.bpf.o");
const fx_core = @embedFile("testdata/core_reloc.bpf.o");

fn generated(gpa: std.mem.Allocator, bytes: []const u8) ![:0]u8 {
    var obj = try object.open(gpa, bytes, .{});
    defer obj.deinit();
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    try generate(gpa, &obj, .{ .object_path = "probe.bpf.o" }, &aw.writer);
    return gpa.dupeSentinel(u8, aw.written(), 0);
}

fn parsesClean(gpa: std.mem.Allocator, src: [:0]const u8) !void {
    var ast = try std.zig.Ast.parse(gpa, src, .{});
    defer ast.deinit(gpa);
    try testing.expectEqual(@as(usize, 0), ast.errors.len);
}

test "skeleton: .rodata becomes an extern struct at the DATASEC offsets" {
    const gpa = testing.allocator;
    const src = try generated(gpa, fx_rodata);
    defer gpa.free(src);
    try parsesClean(gpa, src);
    try testing.expect(std.mem.find(u8, src, "pub const object_bytes = @embedFile(\"probe.bpf.o\");") != null);
    try testing.expect(std.mem.find(u8, src, "pub const Rodata = extern struct {") != null);
    try testing.expect(std.mem.find(u8, src, "    threshold: u32,\n") != null);
    // 4 bytes of padding between `threshold` (0..4) and `tag` (8..16)
    try testing.expect(std.mem.find(u8, src, "    _pad0: [4]u8,\n") != null);
    try testing.expect(std.mem.find(u8, src, "    tag: u64,\n") != null);
    try testing.expect(std.mem.find(u8, src, "@offsetOf(Rodata, \"tag\") == 8") != null);
    try testing.expect(std.mem.find(u8, src, "@sizeOf(Rodata) == 16") != null);
    try testing.expect(std.mem.find(u8, src, "pub const Program = enum {\n    filter,\n};") != null);
    try testing.expect(std.mem.find(u8, src, "pub fn seedRodata(self: *Skeleton) *Rodata") != null);
    try testing.expect(std.mem.find(u8, src, "pub fn mapRodata(self: *Skeleton)") != null);
}

test "skeleton: maps and programs without data sections, names quoted where needed" {
    const gpa = testing.allocator;
    const src = try generated(gpa, fx_mapinmap);
    defer gpa.free(src);
    try parsesClean(gpa, src);
    try testing.expect(std.mem.find(u8, src, "pub const Map = enum {\n    inner_a,\n    inner_b,\n    outer,\n    jumps,\n    hmap,\n};") != null);
    try testing.expect(std.mem.find(u8, src, "    entry,\n") != null);
    try testing.expect(std.mem.find(u8, src, "    target,\n") != null);
    try testing.expect(std.mem.find(u8, src, "seed") == null); // no data section: no seed/map accessors
    // the internal map's name is not an identifier: it is quoted in `Map`
    const r = try generated(gpa, fx_rodata);
    defer gpa.free(r);
    try testing.expect(std.mem.find(u8, r, "    @\".rodata\",\n") != null);
}

test "skeleton: a real object with several data sections still parses" {
    const gpa = testing.allocator;
    const src = try generated(gpa, fx_core);
    defer gpa.free(src);
    try parsesClean(gpa, src);
}

test "writeType: the BTF kinds the skeleton mirrors, and the ones it makes opaque" {
    const gpa = testing.allocator;
    var r = try btf.RawBtf.init(gpa);
    defer r.deinit(gpa);
    const n_s = try r.str(gpa, "S");
    const n_a = try r.str(gpa, "a");
    const n_b = try r.str(gpa, "b");
    const n_c = try r.str(gpa, "c");
    const u32_t = try r.rec(gpa, 0, btf.K_INT, 0, false, 4, &.{32}); // 1
    const i8_t = try r.rec(gpa, 0, btf.K_INT, 0, false, 1, &.{(1 << 24) | 8}); // 2: signed
    const bool_t = try r.rec(gpa, 0, btf.K_INT, 0, false, 1, &.{(4 << 24) | 8}); // 3
    const arr = try r.rec(gpa, 0, btf.K_ARRAY, 0, false, 0, &.{ u32_t, u32_t, 3 }); // 4
    const ptr = try r.rec(gpa, 0, btf.K_PTR, 0, false, u32_t, &.{}); // 5
    // struct S { u32 a @0; i8 b @8; u32[3] c @16 }  size 28 -> padding 4 after a, 7 after b
    const st = try r.rec(gpa, n_s, btf.K_STRUCT, 3, false, 28, &.{ n_a, u32_t, 0, n_b, i8_t, 64, n_c, arr, 128 }); // 6
    // a bitfield member makes the whole struct opaque
    const bf = try r.rec(gpa, n_s, btf.K_STRUCT, 1, true, 4, &.{ n_a, u32_t, (3 << 24) | 0 }); // 7
    const un = try r.rec(gpa, 0, btf.K_UNION, 2, false, 8, &.{ n_a, u32_t, 0, n_b, ptr, 0 }); // 8
    const blob = try r.finish(gpa);
    defer gpa.free(blob);
    var b = try btf.parse(gpa, blob, .{});
    defer b.deinit();

    const out = struct {
        fn of(bb: *const Btf, tid: u32, alloc: std.mem.Allocator) !?[]u8 {
            var aw: std.Io.Writer.Allocating = .init(alloc);
            errdefer aw.deinit();
            if (!try writeType(bb, tid, &aw.writer, 0)) {
                aw.deinit();
                return null;
            }
            return try aw.toOwnedSlice();
        }
    }.of;
    for ([_]struct { id: u32, want: ?[]const u8 }{
        .{ .id = u32_t, .want = "u32" },
        .{ .id = i8_t, .want = "i8" },
        .{ .id = bool_t, .want = "bool" },
        .{ .id = arr, .want = "[3]u32" },
        .{ .id = ptr, .want = "u64" },
        .{ .id = st, .want = "extern struct { a: u32, _pad0: [4]u8, b: i8, _pad1: [7]u8, c: [3]u32, }" },
        .{ .id = bf, .want = null },
        .{ .id = un, .want = "extern union { a: u32, b: u64, }" },
    }) |c| {
        const got = try out(&b, c.id, gpa);
        defer if (got) |g| gpa.free(g);
        if (c.want) |wnt| {
            try testing.expectEqualStrings(wnt, got.?);
        } else try testing.expect(got == null);
    }
}

test "skeleton: the .kconfig map is the externs' fields at the loader's offsets" {
    const gpa = testing.allocator;
    const src = try generated(gpa, @embedFile("testdata/externs.bpf.o"));
    defer gpa.free(src);
    try parsesClean(gpa, src);
    try testing.expect(std.mem.find(u8, src, "pub const Kconfig = extern struct {") != null);
    try testing.expect(std.mem.find(u8, src, "    LINUX_KERNEL_VERSION: u32,\n") != null);
    try testing.expect(std.mem.find(u8, src, "    CONFIG_BPF: bool,\n") != null);
    try testing.expect(std.mem.find(u8, src, "    CONFIG_DEFAULT_HOSTNAME: [16]i8,\n") != null);
    try testing.expect(std.mem.find(u8, src, "@offsetOf(Kconfig, \"CONFIG_ZL_NOT_THERE\") == 32") != null);
    try testing.expect(std.mem.find(u8, src, "@sizeOf(Kconfig) == 40") != null);
}
