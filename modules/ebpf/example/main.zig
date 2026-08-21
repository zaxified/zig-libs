// SPDX-License-Identifier: MIT

//! What an observability-tooling consumer does with `ebpf`: create the
//! backing map, build the `kprobe-counter` program (the module's own
//! Fable-tier verifier-ready builder), load it into the kernel, attach it
//! to a live kernel function, and clean everything up in reverse order.
//!
//! Map creation itself is `std.os.linux.BPF.map_create` directly (this
//! module builds/loads/attaches *programs* — a hand-built program's map is
//! the caller's own std.os.linux.BPF business, the same division of labor
//! `object.zig`'s whole-ELF-object path uses internally).
//!
//! Every privileged step here can fail on a host without CAP_BPF (most CI
//! sandboxes, most non-root shells) — this example treats that as the
//! expected outcome on such a host, not a fatal error, and demonstrates the
//! exact named errors a caller must handle either way.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a
//! type/error needed to drive load/attach is not re-exported, this file
//! stops compiling.

const std = @import("std");
const linux = std.os.linux;
const ebpf = @import("ebpf");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // The counter map: BPF_MAP_TYPE_ARRAY, one u64 slot at key 0 (matches
    // kprobeCounter's documented key_size=4/value_size=8 contract).
    const map_fd = linux.BPF.map_create(.array, 4, 8, 1) catch |err| switch (err) {
        error.PermissionDenied => {
            std.debug.print("no CAP_BPF on this host -- skipping the live load/attach path\n", .{});
            return;
        },
        else => return err,
    };
    defer _ = linux.close(map_fd);

    // Build the verifier-ready instruction stream for this map.
    const insns = ebpf.kprobeCounter(map_fd);
    const prog: ebpf.Program = .{ .prog_type = .kprobe, .insns = insns };

    const prog_fd = ebpf.load(prog, "MIT") catch |err| switch (err) {
        // Named from outside: a program this builder produced failing the
        // verifier would be this module's own bug, but a caller still has
        // to be able to name the outcome rather than let it propagate as
        // an opaque anyerror.
        error.UnsafeProgram, error.InvalidProgram => {
            std.debug.print("verifier rejected the program: {s}\n", .{@errorName(err)});
            return err;
        },
        error.PermissionDenied => {
            std.debug.print("no CAP_BPF for BPF_PROG_LOAD -- skipping attach\n", .{});
            return;
        },
        else => return err,
    };
    defer _ = linux.close(prog_fd);

    // Attach to a function present in every mainline kernel build.
    var handle = ebpf.attachKprobe(gpa, "vfs_read", prog_fd) catch |err| switch (err) {
        error.SymbolNotFound => {
            std.debug.print("vfs_read not resolvable on this kernel -- nothing to attach to\n", .{});
            return;
        },
        error.PermissionDenied => {
            std.debug.print("no permission to open a kprobe perf event\n", .{});
            return;
        },
        else => return err,
    };
    defer handle.detach();

    std.debug.print("attached kprobe-counter to vfs_read via {s} path\n", .{@tagName(handle.path)});
}
