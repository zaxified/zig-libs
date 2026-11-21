// SPDX-License-Identifier: MIT
//! The `bpf(2)` commands that act on *kernel objects in general* rather than
//! on one kind of attachment: pinning into bpffs, finding a BTF object by id
//! and reading it back, and `BPF_PROG_QUERY`. std declares the command numbers
//! and a few attr structs (several truncated, which is why some layouts are
//! restated here with the kernel's full tail); nothing else here wraps them.
//!
//! Every layout is checked against `<linux/bpf.h>` (`tools/uapi_layout.c`
//! prints the offsets the tests pin), and every wrapper maps `errno` onto one
//! small `Error` set. Pure builders (`buildQueryAttr`, ...) keep the exact
//! bytes the kernel receives testable without `CAP_BPF`.

const std = @import("std");
const builtin = @import("builtin");

const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;
const linux = std.os.linux;
const BPF = linux.BPF;

const btf = @import("btf.zig");
const ringbuf = @import("ringbuf.zig");

/// `struct bpf_map_info` (the prefix `ringbuf.zig` already declares).
pub const MapInfo = ringbuf.MapInfo;

pub const Error = error{
    PermissionDenied,
    /// No such pin / object / id.
    NotFound,
    /// A path component is not a directory, or the path is not on a bpffs.
    NotBpffs,
    AlreadyExists,
    InvalidArgument,
    /// The kernel does not implement the command or one of its fields.
    NotSupported,
    PathTooLong,
    SystemResources,
    OutOfMemory,
    Unexpected,
};

fn mapErrno(e: linux.E) Error {
    return switch (e) {
        .PERM, .ACCES => error.PermissionDenied,
        .NOENT => error.NotFound,
        .EXIST => error.AlreadyExists,
        .INVAL, .BADF, .FAULT => error.InvalidArgument,
        .NOSYS, .OPNOTSUPP => error.NotSupported,
        .NOTDIR => error.NotBpffs,
        .NOMEM, .NOSPC, .MFILE, .NFILE => error.SystemResources,
        else => error.Unexpected,
    };
}

/// `struct bpf_attr` `obj_*` arm, with the kernel's `path_fd` tail (std's
/// `ObjAttr` stops after `file_flags`).
pub const ObjAttr = extern struct {
    pathname: u64,
    bpf_fd: i32,
    file_flags: u32,
    /// Must be 0 unless `file_flags` has `BPF_F_PATH_FD` (the kernel answers
    /// EINVAL otherwise, e.g. for `AT_FDCWD`): the pathname is resolved as given.
    path_fd: i32,
};

/// `bpf_attr.query` including the fields 6.6+ appended (`link_ids`,
/// `revision`); `BPF.QueryAttr` in std stops at `prog_cnt`.
pub const QueryAttr = extern struct {
    target_fd: u32,
    attach_type: u32,
    query_flags: u32,
    attach_flags: u32,
    prog_ids: u64,
    prog_cnt: u32,
    _pad: u32 = 0,
    prog_attach_flags: u64 = 0,
    link_ids: u64 = 0,
    link_attach_flags: u64 = 0,
    revision: u64 = 0,
};

/// `struct bpf_btf_info`.
pub const BtfInfo = extern struct {
    btf: u64,
    btf_size: u32,
    id: u32,
    name: u64,
    name_len: u32,
    kernel_btf: u32,
};

const AttrBuf = extern union {
    base: BPF.Attr,
    obj: ObjAttr,
    query: QueryAttr,
    get_id: BPF.GetIdAttr,
    info: BPF.InfoAttr,
};

// ── pinning ─────────────────────────────────────────────────────────────────

fn pathZ(buf: *[4096]u8, path: []const u8) Error![*:0]const u8 {
    if (path.len == 0 or path.len >= buf.len) return error.PathTooLong;
    if (std.mem.findScalar(u8, path, 0) != null) return error.InvalidArgument;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return @ptrCast(buf);
}

/// Pure: the attr `BPF_OBJ_PIN` / `BPF_OBJ_GET` send.
pub fn buildObjAttr(path_z: [*:0]const u8, fd: i32, file_flags: u32) ObjAttr {
    return .{
        .pathname = @intFromPtr(path_z),
        .bpf_fd = fd,
        .file_flags = file_flags,
        .path_fd = 0,
    };
}

/// `bpf(BPF_OBJ_PIN)`: make a map, program or link visible at `path` on a
/// bpffs, which keeps it alive after this process (and every fd) is gone.
/// The parent directory must exist; `error.AlreadyExists` when `path` does.
pub fn objPin(fd: linux.fd_t, path: []const u8) Error!void {
    if (comptime builtin.os.tag != .linux) @compileError("ebpf.bpfsys is Linux-only (bpf() raw syscall)");
    var pb: [4096]u8 = undefined;
    var buf: AttrBuf = .{ .obj = buildObjAttr(try pathZ(&pb, path), fd, 0) };
    const rc = linux.bpf(.obj_pin, @ptrCast(&buf), @sizeOf(ObjAttr));
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |e| return mapErrno(e),
    }
}

/// `bpf(BPF_OBJ_GET)`: open the object pinned at `path`. `file_flags` is
/// `BPF_F_RDONLY` (8) / `BPF_F_WRONLY` (16) or 0.
pub fn objGet(path: []const u8, file_flags: u32) Error!linux.fd_t {
    if (comptime builtin.os.tag != .linux) @compileError("ebpf.bpfsys is Linux-only (bpf() raw syscall)");
    var pb: [4096]u8 = undefined;
    var buf: AttrBuf = .{ .obj = buildObjAttr(try pathZ(&pb, path), 0, file_flags) };
    const rc = linux.bpf(.obj_get, @ptrCast(&buf), @sizeOf(ObjAttr));
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => |e| mapErrno(e),
    };
}

/// Remove a pin: a pinned object is a file on bpffs and `unlink(2)` is the
/// only operation that removes it.
pub fn objUnpin(path: []const u8) Error!void {
    var pb: [4096]u8 = undefined;
    const rc = linux.unlink(try pathZ(&pb, path));
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |e| return mapErrno(e),
    }
}

// ── BTF objects by id ───────────────────────────────────────────────────────

/// `bpf(BPF_BTF_GET_NEXT_ID)`: the id of the BTF object after `start_id`
/// (0 starts the walk), or `null` at the end. Needs `CAP_SYS_ADMIN`.
pub fn btfNextId(start_id: u32) Error!?u32 {
    var buf: AttrBuf = .{ .get_id = .{ .id = .{ .start_id = start_id }, .next_id = 0, .open_flags = 0 } };
    const rc = linux.bpf(.btf_get_next_id, @ptrCast(&buf), @sizeOf(BPF.GetIdAttr));
    return switch (linux.errno(rc)) {
        .SUCCESS => buf.get_id.next_id,
        .NOENT => null,
        else => |e| mapErrno(e),
    };
}

/// `bpf(BPF_BTF_GET_FD_BY_ID)`. The caller closes the fd.
pub fn btfFdById(id: u32) Error!linux.fd_t {
    var buf: AttrBuf = .{ .get_id = .{ .id = .{ .btf_id = id }, .next_id = 0, .open_flags = 0 } };
    const rc = linux.bpf(.btf_get_fd_by_id, @ptrCast(&buf), @sizeOf(BPF.GetIdAttr));
    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => |e| mapErrno(e),
    };
}

/// `BPF_OBJ_GET_INFO_BY_FD` into `out` (any prefix of the kernel's info
/// struct: the kernel copies `min(len, its size)` bytes and zero is what a
/// field an older kernel lacks reads as).
pub fn objInfo(fd: linux.fd_t, out: []u8) Error!void {
    var buf: AttrBuf = .{ .info = .{ .bpf_fd = fd, .info_len = @intCast(out.len), .info = @intFromPtr(out.ptr) } };
    const rc = linux.bpf(.obj_get_info_by_fd, @ptrCast(&buf), @sizeOf(BPF.InfoAttr));
    return switch (linux.errno(rc)) {
        .SUCCESS => {},
        else => |e| mapErrno(e),
    };
}

/// What `btfNameInfo` learned about a BTF object.
pub const BtfName = struct {
    /// A kernel BTF (vmlinux or a module's) rather than a user-loaded one.
    kernel_btf: bool,
    name: []const u8,
};

/// The name (`"vmlinux"`, a module's) and kernel-ness of the BTF object behind
/// `btf_fd`; `name` points into `name_buf`.
pub fn btfNameInfo(btf_fd: linux.fd_t, name_buf: []u8) Error!BtfName {
    var info: BtfInfo = std.mem.zeroes(BtfInfo);
    info.name = @intFromPtr(name_buf.ptr);
    info.name_len = @intCast(name_buf.len);
    try objInfo(btf_fd, std.mem.asBytes(&info));
    const n = @min(std.mem.findScalar(u8, name_buf, 0) orelse name_buf.len, name_buf.len);
    return .{ .kernel_btf = info.kernel_btf != 0, .name = name_buf[0..n] };
}

/// Ceiling on a BTF blob read back from the kernel (vmlinux BTF is ~7 MiB).
pub const max_btf_bytes: usize = btf.max_blob_bytes;

/// The raw bytes of the BTF object behind `btf_fd` — what `bpftool btf dump
/// id N` reads. Two calls: the first (buffer 0) learns the size.
pub fn btfBlob(gpa: std.mem.Allocator, btf_fd: linux.fd_t) Error![]u8 {
    var info: BtfInfo = std.mem.zeroes(BtfInfo);
    try objInfo(btf_fd, std.mem.asBytes(&info));
    const n: usize = info.btf_size;
    if (n == 0 or n > max_btf_bytes) return error.InvalidArgument;
    const bytes = gpa.alloc(u8, n) catch return error.OutOfMemory;
    errdefer gpa.free(bytes);
    var again: BtfInfo = std.mem.zeroes(BtfInfo);
    again.btf = @intFromPtr(bytes.ptr);
    again.btf_size = @intCast(n);
    try objInfo(btf_fd, std.mem.asBytes(&again));
    // The object cannot change, but a lying kernel must not make us parse
    // beyond what we allocated.
    if (again.btf_size != n) return error.InvalidArgument;
    return bytes;
}

/// Read back and parse the BTF object `id`. Split BTF (a module's) needs its
/// `base`, as everywhere in this module. The `Btf` owns its bytes.
pub fn loadBtfById(gpa: std.mem.Allocator, id: u32, base: ?*const btf.Btf) (Error || btf.ParseError)!btf.Btf {
    const fd = try btfFdById(id);
    defer _ = linux.close(fd);
    const bytes = try btfBlob(gpa, fd);
    return btf.parse(gpa, bytes, .{ .base = base, .own_bytes = true }) catch |e| {
        gpa.free(bytes);
        return e;
    };
}

/// The id of the BTF object a loaded program carries (`bpf_prog_info.btf_id`;
/// 0 when it has none), as `bpftool prog show` prints it. Combine with
/// `loadBtfById`.
pub fn progBtfId(prog_fd: linux.fd_t) Error!u32 {
    var raw: [prog_info_btf_id_off + 4]u8 = @splat(0);
    try objInfo(prog_fd, &raw);
    return std.mem.readInt(u32, raw[prog_info_btf_id_off..][0..4], builtin.cpu.arch.endian());
}

/// The id of the BTF object a map carries (`bpf_map_info.btf_id`; 0: none).
pub fn mapBtfId(map_fd: linux.fd_t) Error!u32 {
    var raw: [map_info_btf_id_off + 4]u8 = @splat(0);
    try objInfo(map_fd, &raw);
    return std.mem.readInt(u32, raw[map_info_btf_id_off..][0..4], builtin.cpu.arch.endian());
}

/// Offsets of `btf_id` in `struct bpf_prog_info` / `struct bpf_map_info`.
pub const prog_info_btf_id_off: usize = 128;
pub const map_info_btf_id_off: usize = 64;

// ── BPF_PROG_QUERY ──────────────────────────────────────────────────────────

pub const QueryOptions = struct {
    /// `BPF_F_QUERY_EFFECTIVE` (1): the programs that actually run (a cgroup's
    /// own plus its ancestors'), not only the ones attached directly.
    effective: bool = false,
};

/// What `progQuery` learned.
pub const QueryResult = struct {
    /// How many programs are attached in total. `ids` holds the first
    /// `min(count, ids.len)` of them.
    count: u32,
    /// `attach_flags` of the attachment point (`BPF_F_ALLOW_MULTI`, ...).
    attach_flags: u32,
    /// The attachment point's revision (6.6+; 0 where the kernel has none), for
    /// an `expected_revision` compare-and-swap on the next attach.
    revision: u64,

    pub fn truncated(self: QueryResult, ids_len: usize) bool {
        return self.count > ids_len;
    }
};

/// Pure: the attr `BPF_PROG_QUERY` sends.
pub fn buildQueryAttr(target: u32, attach_type: BPF.AttachType, opts: QueryOptions, ids: []u32) QueryAttr {
    return .{
        .target_fd = target,
        .attach_type = @backingInt(attach_type),
        .query_flags = if (opts.effective) 1 else 0,
        .attach_flags = 0,
        .prog_ids = if (ids.len == 0) 0 else @intFromPtr(ids.ptr),
        .prog_cnt = @intCast(@min(ids.len, std.math.maxInt(u32))),
    };
}

/// `bpf(BPF_PROG_QUERY)`: which programs are attached to `target` for
/// `attach_type`. `target` is a cgroup directory fd, a netns fd, or (for
/// `tcx`/`netkit`/`xdp`-style hooks on kernels that support it) an ifindex.
/// A buffer too small is not an error: `count` says how many there are and
/// `truncated()` says the list is cut. Pass an empty `ids` to learn only the
/// count. Which attach types answer is the kernel's decision (`EINVAL` ->
/// `error.NotSupported`/`InvalidArgument`).
pub fn progQuery(target: u32, attach_type: BPF.AttachType, opts: QueryOptions, ids: []u32) Error!QueryResult {
    if (comptime builtin.os.tag != .linux) @compileError("ebpf.bpfsys is Linux-only (bpf() raw syscall)");
    var buf: AttrBuf = .{ .query = buildQueryAttr(target, attach_type, opts, ids) };
    const rc = linux.bpf(.prog_query, @ptrCast(&buf), @sizeOf(QueryAttr));
    switch (linux.errno(rc)) {
        // ENOSPC: the kernel still reports the true count and fills what fits.
        .SUCCESS, .NOSPC => return .{
            .count = buf.query.prog_cnt,
            .attach_flags = buf.query.attach_flags,
            .revision = buf.query.revision,
        },
        else => |e| return mapErrno(e),
    }
}

// ── tests ────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "layouts match <linux/bpf.h> (tools/uapi_layout.c)" {
    try testing.expectEqual(@as(usize, 0), @offsetOf(ObjAttr, "pathname"));
    try testing.expectEqual(@as(usize, 8), @offsetOf(ObjAttr, "bpf_fd"));
    try testing.expectEqual(@as(usize, 12), @offsetOf(ObjAttr, "file_flags"));
    try testing.expectEqual(@as(usize, 16), @offsetOf(ObjAttr, "path_fd"));
    try testing.expectEqual(@as(usize, 16), @offsetOf(QueryAttr, "prog_ids"));
    try testing.expectEqual(@as(usize, 24), @offsetOf(QueryAttr, "prog_cnt"));
    try testing.expectEqual(@as(usize, 32), @offsetOf(QueryAttr, "prog_attach_flags"));
    try testing.expectEqual(@as(usize, 40), @offsetOf(QueryAttr, "link_ids"));
    try testing.expectEqual(@as(usize, 48), @offsetOf(QueryAttr, "link_attach_flags"));
    try testing.expectEqual(@as(usize, 56), @offsetOf(QueryAttr, "revision"));
    try testing.expectEqual(@as(usize, 64), @sizeOf(QueryAttr));
    try testing.expectEqual(@as(usize, 32), @sizeOf(BtfInfo));
    try testing.expectEqual(@as(usize, 8), @offsetOf(BtfInfo, "btf_size"));
    try testing.expectEqual(@as(usize, 28), @offsetOf(BtfInfo, "kernel_btf"));
    // the attr union must be at least as large as the kernel's own
    try testing.expect(@sizeOf(AttrBuf) >= 64);
}

test "buildObjAttr and buildQueryAttr: the exact fields the kernel reads" {
    const a = buildObjAttr("/sys/fs/bpf/x", 7, 8);
    try testing.expectEqual(@as(i32, 7), a.bpf_fd);
    try testing.expectEqual(@as(u32, 8), a.file_flags);
    try testing.expectEqual(@as(i32, 0), a.path_fd);
    try testing.expect(a.pathname != 0);

    var ids: [3]u32 = undefined;
    const q = buildQueryAttr(9, .cgroup_inet_ingress, .{ .effective = true }, &ids);
    try testing.expectEqual(@as(u32, 9), q.target_fd);
    try testing.expectEqual(@as(u32, @backingInt(BPF.AttachType.cgroup_inet_ingress)), q.attach_type);
    try testing.expectEqual(@as(u32, 1), q.query_flags);
    try testing.expectEqual(@as(u32, 3), q.prog_cnt);
    try testing.expectEqual(@intFromPtr(&ids), q.prog_ids);
    const none = buildQueryAttr(9, .xdp, .{}, &.{});
    try testing.expectEqual(@as(u64, 0), none.prog_ids);
    try testing.expectEqual(@as(u32, 0), none.query_flags);
    try testing.expect((QueryResult{ .count = 4, .attach_flags = 0, .revision = 0 }).truncated(3));
    try testing.expect(!(QueryResult{ .count = 3, .attach_flags = 0, .revision = 0 }).truncated(3));
}

test "pin paths: empty, NUL-bearing and over-long paths are refused before any syscall" {
    try testing.expectError(error.PathTooLong, objPin(3, ""));
    try testing.expectError(error.InvalidArgument, objGet("/sys/fs/bpf/a\x00b", 0));
    var long: [4096]u8 = @splat('a');
    try testing.expectError(error.PathTooLong, objGet(&long, 0));
    try testing.expectError(error.PathTooLong, objUnpin(""));
}

test "unprivileged: every command answers with an error, never a crash" {
    // Without CAP_BPF these are EPERM; with it, ENOENT/EINVAL for the bogus
    // arguments. Either way the errno mapping must hold.
    const allowed = [_]anyerror{ error.PermissionDenied, error.NotFound, error.InvalidArgument, error.NotBpffs, error.NotSupported };
    const check = struct {
        fn ok(e: anyerror) bool {
            for (allowed) |a| if (a == e) return true;
            return false;
        }
    }.ok;
    if (objGet("/nonexistent-bpffs-pin", 0)) |fd| {
        _ = linux.close(fd);
        return error.TestUnexpectedResult;
    } else |e| try testing.expect(check(e));
    if (btfFdById(0xffff_fff0)) |fd| {
        _ = linux.close(fd);
        return error.TestUnexpectedResult;
    } else |e| try testing.expect(check(e));
    if (btfNextId(0xffff_fff0)) |_| {} else |e| try testing.expect(check(e));
    var ids: [4]u32 = undefined;
    if (progQuery(0xffff_ff00, .cgroup_inet_ingress, .{}, &ids)) |_| {
        return error.TestUnexpectedResult;
    } else |e| try testing.expect(check(e));
    try testing.expectError(error.NotFound, objUnpin("/nonexistent-bpffs-pin/x"));
}
