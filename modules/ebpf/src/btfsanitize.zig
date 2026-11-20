// SPDX-License-Identifier: MIT
//! `.BTF` downgrading for older kernels: rewrite the BTF kinds the running
//! kernel's BTF verifier does not know into kinds it does, the way libbpf's
//! `sanitize_btf` does, so a program built with a recent clang still loads.
//!
//! ## What is rewritten, and why each stays valid
//!
//! Every replacement keeps the record **the same size** (so the type section
//! needs no re-layout and every type id stays what `func_info`, `line_info` and
//! the maps' `btf_key_type_id`s say it is), except the one that must invent a
//! type, which is appended at the end:
//!
//! | missing | replaced by |
//! |---|---|
//! | `DATASEC` | a `STRUCT` of the same size: one member per variable (named like the variable, at `offset * 8`), the section name's `.` / `?` turned into `_` |
//! | `VAR` | a 1-byte `INT` |
//! | `FUNC_PROTO` | an `ENUM` (parameters become enumerators of value 0) |
//! | `FUNC` | a `TYPEDEF` of the (now enum) proto |
//! | global `FUNC` linkage | `static` |
//! | `FLOAT` | an empty `STRUCT` of the same size |
//! | `DECL_TAG` | a 1-byte `INT` |
//! | `TYPE_TAG` | an anonymous `CONST` of the same target |
//! | `ENUM64` | a `UNION` whose members are an appended 1-byte placeholder `INT` |
//!
//! Without `FUNC` support the programs' `func_info` is meaningless (the
//! functions are typedefs now): `Features.func == false` is the caller's cue to
//! drop it (`object.load` does).
//!
//! ## Which kinds the kernel has
//!
//! `probeFeatures` asks the kernel, as libbpf does: it loads one tiny BTF blob
//! per kind with `BPF_BTF_LOAD` and records whether the BTF verifier accepted
//! it. That needs `CAP_BPF`; without it the answer is
//! `error.PermissionDenied` and nothing can be sanitized (nor loaded).

const std = @import("std");
const builtin = @import("builtin");

const btf = @import("btf.zig");
const native_endian = builtin.cpu.arch.endian();

/// What the running kernel's BTF verifier accepts. A caller that knows better
/// (a fixed minimum kernel) can construct one by hand.
pub const Features = struct {
    func: bool = true,
    func_global: bool = true,
    datasec: bool = true,
    float: bool = true,
    decl_tag: bool = true,
    type_tag: bool = true,
    enum64: bool = true,

    /// Every kind a modern kernel has.
    pub const all: Features = .{};

    pub fn needsRewrite(self: Features) bool {
        return !(self.func and self.func_global and self.datasec and self.float and self.decl_tag and self.type_tag and self.enum64);
    }
};

pub const Error = btf.ParseError || error{ OutOfMemory, BtfTooLarge };

// ── the rewrite ─────────────────────────────────────────────────────────────

const K_INT: u32 = 1;
const K_STRUCT: u32 = 4;
const K_UNION: u32 = 5;
const K_ENUM: u32 = 6;
const K_TYPEDEF: u32 = 8;
const K_CONST: u32 = 10;

fn rd(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], native_endian);
}
fn wr(b: []u8, off: usize, v: u32) void {
    std.mem.writeInt(u32, b[off..][0..4], v, native_endian);
}
fn info(kind: u32, vlen: u32, kflag: bool) u32 {
    return vlen | (kind << 24) | (@as(u32, @intFromBool(kflag)) << 31);
}

/// Rewrite `blob` for a kernel with `features`. Returns `null` when nothing in
/// it needs rewriting; otherwise a new blob (header + types + strings, the
/// caller frees it). Type ids are unchanged.
pub fn sanitize(gpa: std.mem.Allocator, blob: []const u8, features: Features) Error!?[]u8 {
    if (!features.needsRewrite()) return null;
    var b = try btf.parse(gpa, blob, .{});
    defer b.deinit();

    // Fresh layout: header, the type records, the strings.
    var types: std.ArrayList(u8) = .empty;
    defer types.deinit(gpa);
    types.appendSlice(gpa, b.types) catch return error.OutOfMemory;
    var strings: std.ArrayList(u8) = .empty;
    defer strings.deinit(gpa);
    strings.appendSlice(gpa, b.strings) catch return error.OutOfMemory;

    var changed = false;
    const type_count = b.typeCount();

    var i: u32 = 0;
    while (i < type_count) : (i += 1) {
        const id = b.start_id + i;
        const t = b.byId(id) catch return error.MalformedBtf;
        const at: usize = b.offsets[i];
        const rec = types.items;
        switch (t.kind) {
            .datasec => if (!features.datasec) {
                // name: '.' and '?' are not allowed in a STRUCT name
                const noff: usize = t.name_off;
                if (noff < strings.items.len) {
                    var k = noff;
                    while (k < strings.items.len and strings.items[k] != 0) : (k += 1) {
                        if (strings.items[k] == '.' or strings.items[k] == '?') strings.items[k] = '_';
                    }
                }
                var j: u32 = 0;
                while (j < t.vlen) : (j += 1) {
                    const e = at + 12 + j * 12;
                    const var_id = rd(rec, e);
                    const off = rd(rec, e + 4);
                    const vt = b.byId(var_id) catch return error.MalformedBtf;
                    wr(types.items, e, vt.name_off); // member name: the variable's
                    wr(types.items, e + 4, var_id); // member type
                    wr(types.items, e + 8, off *% 8); // member bit offset
                }
                wr(types.items, at + 4, info(K_STRUCT, t.vlen, false));
                changed = true;
            },
            .@"var" => if (!features.datasec) {
                wr(types.items, at + 4, info(K_INT, 0, false));
                wr(types.items, at + 8, 1);
                wr(types.items, at + 12, 8); // BTF_INT_ENC(0, 0, 8)
                changed = true;
            },
            .func_proto => if (!features.func) {
                var j: u32 = 0;
                while (j < t.vlen) : (j += 1) {
                    const e = at + 12 + j * 8;
                    wr(types.items, e + 4, 0); // enumerator value
                }
                wr(types.items, at + 4, info(K_ENUM, t.vlen, false));
                wr(types.items, at + 8, 4); // the kernel insists on 4
                changed = true;
            },
            .func => {
                if (!features.func) {
                    wr(types.items, at + 4, info(K_TYPEDEF, 0, false));
                    changed = true;
                } else if (!features.func_global and t.vlen == @backingInt(btf.FuncLinkage.global)) {
                    wr(types.items, at + 4, info(@backingInt(btf.Kind.func), 0, false)); // linkage: static
                    changed = true;
                }
            },
            .float => if (!features.float) {
                wr(types.items, at + 4, info(K_STRUCT, 0, false));
                changed = true;
            },
            .decl_tag => if (!features.decl_tag) {
                wr(types.items, at + 4, info(K_INT, 0, false));
                wr(types.items, at + 8, 1);
                wr(types.items, at + 12, 8);
                changed = true;
            },
            .type_tag => if (!features.type_tag) {
                wr(types.items, at, 0); // anonymous
                wr(types.items, at + 4, info(K_CONST, 0, false));
                changed = true;
            },
            .enum64 => if (!features.enum64) {
                changed = true; // the members are rewritten below, once the placeholder exists
            },
            else => {},
        }
    }

    if (!changed) return null;

    // ENUM64 -> UNION needs a member type: one appended 1-byte INT.
    var has_enum64_rewrite = false;
    if (!features.enum64) {
        i = 0;
        while (i < type_count) : (i += 1) {
            const t = b.byId(b.start_id + i) catch return error.MalformedBtf;
            if (t.kind == .enum64) has_enum64_rewrite = true;
        }
    }
    if (has_enum64_rewrite) {
        const name_off: u32 = @intCast(strings.items.len);
        strings.appendSlice(gpa, "enum64_placeholder\x00") catch return error.OutOfMemory;
        const ph_id: u32 = b.start_id + type_count;
        var rec: [16]u8 = undefined;
        wr(&rec, 0, name_off);
        wr(&rec, 4, info(K_INT, 0, false));
        wr(&rec, 8, 1);
        wr(&rec, 12, 8);
        types.appendSlice(gpa, &rec) catch return error.OutOfMemory;
        i = 0;
        while (i < type_count) : (i += 1) {
            const t = b.byId(b.start_id + i) catch return error.MalformedBtf;
            if (t.kind != .enum64) continue;
            const at: usize = b.offsets[i];
            var j: u32 = 0;
            while (j < t.vlen) : (j += 1) {
                const e = at + 12 + j * 12;
                wr(types.items, e + 4, ph_id); // member type
                wr(types.items, e + 8, 0); // member offset
            }
            wr(types.items, at + 4, info(K_UNION, t.vlen, false));
        }
    }

    const hdr = btf.header_size;
    const out = gpa.alloc(u8, hdr + types.items.len + strings.items.len) catch return error.OutOfMemory;
    @memset(out[0..hdr], 0);
    std.mem.writeInt(u16, out[0..2], btf.magic, native_endian);
    out[2] = btf.version;
    wr(out, 4, @intCast(hdr));
    wr(out, 8, 0);
    wr(out, 12, @intCast(types.items.len));
    wr(out, 16, @intCast(types.items.len));
    wr(out, 20, @intCast(strings.items.len));
    @memcpy(out[hdr..][0..types.items.len], types.items);
    @memcpy(out[hdr + types.items.len ..][0..strings.items.len], strings.items);
    return out;
}

// ── probing the kernel ──────────────────────────────────────────────────────

const Probe = enum { func, func_global, datasec, float, decl_tag, type_tag, enum64 };

/// The tiny blob that tells whether the kernel knows `which`. Layout: header,
/// the type words, the strings.
fn probeBlob(buf: *[160]u8, which: Probe) []const u8 {
    // type words (after the implicit `void`)
    var w: [32]u32 = undefined;
    var n: usize = 0;
    var s: [32]u8 = undefined;
    var sn: usize = 0;
    s[0] = 0;
    sn = 1;
    const addStr = struct {
        fn f(str: *[32]u8, len: *usize, text: []const u8) u32 {
            const off: u32 = @intCast(len.*);
            @memcpy(str[len.*..][0..text.len], text);
            str[len.* + text.len] = 0;
            len.* += text.len + 1;
            return off;
        }
    }.f;
    const int_rec = [_]u32{ 0, info(K_INT, 0, false), 4, 32 }; // id 1: int
    @memcpy(w[0..4], &int_rec);
    n = 4;
    const name_a = addStr(&s, &sn, "a");
    switch (which) {
        .func, .func_global => {
            // 2: func_proto void() ; 3: func a(proto)
            const lk: u32 = if (which == .func_global) 1 else 0;
            const rec = [_]u32{ 0, info(13, 0, false), 0, name_a, info(12, lk, false), 2 };
            @memcpy(w[n..][0..rec.len], &rec);
            n += rec.len;
        },
        .datasec => {
            const nm = addStr(&s, &sn, ".data");
            // 2: var a: int ; 3: datasec .data { var 2 @0 size 4 }
            const rec = [_]u32{ name_a, info(14, 0, false), 1, 1, nm, info(15, 1, false), 4, 2, 0, 4 };
            @memcpy(w[n..][0..rec.len], &rec);
            n += rec.len;
        },
        .float => {
            const nm = addStr(&s, &sn, "float");
            const rec = [_]u32{ nm, info(16, 0, false), 4 };
            @memcpy(w[n..][0..rec.len], &rec);
            n += rec.len;
        },
        .decl_tag => {
            // 2: var a ; 3: decl_tag "a" on type 2, component -1
            const rec = [_]u32{ name_a, info(14, 0, false), 1, 1, name_a, info(17, 0, false), 2, 0xffff_ffff };
            @memcpy(w[n..][0..rec.len], &rec);
            n += rec.len;
        },
        .type_tag => {
            // 2: type_tag "a" -> int ; 3: ptr -> 2
            const rec = [_]u32{ name_a, info(18, 0, false), 1, 0, info(2, 0, false), 2 };
            @memcpy(w[n..][0..rec.len], &rec);
            n += rec.len;
        },
        .enum64 => {
            const rec = [_]u32{ name_a, info(19, 1, false), 8, name_a, 0, 0 };
            // replaces the int: an enum64 alone is a valid blob
            @memcpy(w[0..rec.len], &rec);
            n = rec.len;
        },
    }
    const type_len = n * 4;
    const total = btf.header_size + type_len + sn;
    @memset(buf[0..btf.header_size], 0);
    std.mem.writeInt(u16, buf[0..2], btf.magic, native_endian);
    buf[2] = btf.version;
    wr(buf, 4, btf.header_size);
    wr(buf, 12, @intCast(type_len));
    wr(buf, 16, @intCast(type_len));
    wr(buf, 20, @intCast(sn));
    for (w[0..n], 0..) |word, k| wr(buf, btf.header_size + k * 4, word);
    @memcpy(buf[btf.header_size + type_len ..][0..sn], s[0..sn]);
    return buf[0..total];
}

/// Ask the running kernel which of the downgradable kinds it accepts.
/// `error.PermissionDenied` without `CAP_BPF`.
pub fn probeFeatures() btf.KernelLoadError!Features {
    var f: Features = .{};
    inline for (comptime std.enums.values(Probe)) |p| {
        var buf: [160]u8 = undefined;
        const blob = probeBlob(&buf, p);
        const ok: bool = if (btf.loadIntoKernel(blob, null)) |fd| blk: {
            _ = std.os.linux.close(fd);
            break :blk true;
        } else |e| switch (e) {
            error.InvalidBtf => false,
            else => return e,
        };
        switch (p) {
            .func => f.func = ok,
            .func_global => f.func_global = ok,
            .datasec => f.datasec = ok,
            .float => f.float = ok,
            .decl_tag => f.decl_tag = ok,
            .type_tag => f.type_tag = ok,
            .enum64 => f.enum64 = ok,
        }
    }
    // a kernel without FUNC cannot have global FUNC either
    if (!f.func) f.func_global = false;
    return f;
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;
const RawBtf = btf.RawBtf;

test "probe blobs are valid BTF the parser accepts" {
    inline for (comptime std.enums.values(Probe)) |p| {
        var buf: [160]u8 = undefined;
        const blob = probeBlob(&buf, p);
        var b = try btf.parse(testing.allocator, blob, .{});
        defer b.deinit();
        try b.validateReferences(null);
        try testing.expect(b.typeCount() >= 1);
    }
}

test "features: all-true needs no rewrite and returns null" {
    try testing.expect(!Features.all.needsRewrite());
    var r = try RawBtf.init(testing.allocator);
    defer r.deinit(testing.allocator);
    _ = try r.rec(testing.allocator, 0, btf.K_INT, 0, false, 4, &.{32});
    const blob = try r.finish(testing.allocator);
    defer testing.allocator.free(blob);
    try testing.expect((try sanitize(testing.allocator, blob, .all)) == null);
    // and a blob with nothing to downgrade stays untouched under an all-false set
    try testing.expect((try sanitize(testing.allocator, blob, .{ .func = false, .func_global = false, .datasec = false, .float = false, .decl_tag = false, .type_tag = false, .enum64 = false })) == null);
}

test "sanitize: each missing kind becomes the kind libbpf substitutes, ids unchanged" {
    const gpa = testing.allocator;
    var r = try RawBtf.init(gpa);
    defer r.deinit(gpa);
    const n_a = try r.str(gpa, "a");
    const n_sec = try r.str(gpa, ".data.x?");
    const n_f = try r.str(gpa, "float");
    const n_fn = try r.str(gpa, "fn");
    const n_tag = try r.str(gpa, "tag");
    const n_e = try r.str(gpa, "E");
    const int1 = try r.rec(gpa, 0, btf.K_INT, 0, false, 4, &.{32}); // 1
    const var1 = try r.rec(gpa, n_a, btf.K_VAR, 0, false, int1, &.{1}); // 2
    const sec = try r.rec(gpa, n_sec, btf.K_DATASEC, 1, false, 4, &.{ var1, 0, 4 }); // 3
    const flt = try r.rec(gpa, n_f, 16, 0, false, 4, &.{}); // 4: float
    const proto = try r.rec(gpa, 0, btf.K_FUNC_PROTO, 1, false, int1, &.{ n_a, int1 }); // 5
    const func = try r.rec(gpa, n_fn, btf.K_FUNC, 1, false, proto, &.{}); // 6: global
    const tag = try r.rec(gpa, n_tag, btf.K_DECL_TAG, 0, false, var1, &.{0xffff_ffff}); // 7
    const tt = try r.rec(gpa, n_a, 18, 0, false, int1, &.{}); // 8: type_tag
    const e64 = try r.rec(gpa, n_e, btf.K_ENUM64, 2, false, 8, &.{ n_a, 5, 1, n_f, 6, 0 }); // 9
    const blob = try r.finish(gpa);
    defer gpa.free(blob);

    const out = (try sanitize(gpa, blob, .{ .func = false, .func_global = false, .datasec = false, .float = false, .decl_tag = false, .type_tag = false, .enum64 = false })).?;
    defer gpa.free(out);
    var b = try btf.parse(gpa, out, .{});
    defer b.deinit();
    try b.validateReferences(null);
    try testing.expectEqual(@as(u32, 10), b.typeCount()); // the enum64 placeholder was appended
    const kind = struct {
        fn of(x: *const btf.Btf, id: u32) btf.Kind {
            return (x.byId(id) catch unreachable).kind;
        }
    }.of;
    try testing.expectEqual(btf.Kind.int, kind(&b, var1));
    try testing.expectEqual(btf.Kind.@"struct", kind(&b, sec));
    try testing.expectEqual(btf.Kind.@"struct", kind(&b, flt));
    try testing.expectEqual(btf.Kind.@"enum", kind(&b, proto));
    try testing.expectEqual(btf.Kind.typedef, kind(&b, func));
    try testing.expectEqual(btf.Kind.int, kind(&b, tag));
    try testing.expectEqual(btf.Kind.@"const", kind(&b, tt));
    try testing.expectEqual(btf.Kind.@"union", kind(&b, e64));
    try testing.expectEqual(btf.Kind.int, kind(&b, 10));
    // the datasec became a struct of the same size, member named like the variable, at bit offset 0
    const st = try b.byId(sec);
    try testing.expectEqual(@as(u16, 1), st.vlen);
    try testing.expectEqual(@as(u32, 4), st.size_type);
    const m = try b.member(st, 0);
    try testing.expectEqualStrings("a", b.str(m.name_off).?);
    try testing.expectEqual(var1, m.type_id);
    // the section name lost its '.' and '?'
    try testing.expectEqualStrings("_data_x_", b.str(st.name_off).?);
    // the float stayed 4 bytes; the type tag lost its name; the proto is a 4-byte enum
    try testing.expectEqual(@as(u32, 4), (try b.byId(flt)).size_type);
    try testing.expectEqual(@as(u32, 0), (try b.byId(tt)).name_off);
    try testing.expectEqual(@as(u32, 4), (try b.byId(proto)).size_type);
    // the union's members are the placeholder, at offset 0, keeping the enumerator names
    const u = try b.byId(e64);
    try testing.expectEqual(@as(u16, 2), u.vlen);
    const um = try b.member(u, 1);
    try testing.expectEqual(@as(u32, 10), um.type_id);
    try testing.expectEqualStrings("float", b.str(um.name_off).?); // name_off 'n_f' = "float", kept
    // each rewrite is independent: only `float` missing changes only the float
    const only = (try sanitize(gpa, blob, .{ .float = false })).?;
    defer gpa.free(only);
    var ob = try btf.parse(gpa, only, .{});
    defer ob.deinit();
    try testing.expectEqual(btf.Kind.@"struct", kind(&ob, flt));
    try testing.expectEqual(btf.Kind.datasec, kind(&ob, sec));
    try testing.expectEqual(btf.Kind.func, kind(&ob, func));
    try testing.expectEqual(@as(u32, 9), ob.typeCount()); // no placeholder
}

test "sanitize: a global function becomes static, a static one is left alone" {
    const gpa = testing.allocator;
    var r = try RawBtf.init(gpa);
    defer r.deinit(gpa);
    const n = try r.str(gpa, "f");
    const proto = try r.rec(gpa, 0, btf.K_FUNC_PROTO, 0, false, 0, &.{});
    const g = try r.rec(gpa, n, btf.K_FUNC, 1, false, proto, &.{});
    const s = try r.rec(gpa, n, btf.K_FUNC, 0, false, proto, &.{});
    const blob = try r.finish(gpa);
    defer gpa.free(blob);
    const out = (try sanitize(gpa, blob, .{ .func_global = false })).?;
    defer gpa.free(out);
    var b = try btf.parse(gpa, out, .{});
    defer b.deinit();
    try testing.expectEqual(@as(?btf.FuncLinkage, .static), (try b.byId(g)).funcLinkage());
    try testing.expectEqual(@as(?btf.FuncLinkage, .static), (try b.byId(s)).funcLinkage());
}

test "unprivileged: probing the kernel is an error, not a crash" {
    if (probeFeatures()) |f| {
        _ = f; // privileged: any answer is a real one
    } else |e| try testing.expect(e == error.PermissionDenied or e == error.Unexpected or e == error.SystemResources);
}
