// SPDX-License-Identifier: MIT

//! diskusage — `statfs(2)`/`statfs64(2)` disk-space query plus
//! `/proc/self/mounts` and `/proc/self/mountinfo` parsers: "what is mounted
//! and how full is it", without spawning `df`/`mount`.
//!
//! Two independent pieces under one roof (see each submodule's doc comment
//! for the reasoning specific to it):
//!
//!   * `statfs.query(path)` — total/free/available bytes, inode counts,
//!     block size, filesystem type magic, for the filesystem containing
//!     `path`. Exposes both `f_bfree` (raw free) and `f_bavail` (available
//!     to an unprivileged caller, the number `df` actually reports).
//!   * `mounts.readMounts` / `mounts.parseMounts` — the `mtab`(5)-shaped
//!     four-column table (device, mount point, fs type, options).
//!   * `mountinfo.readMountinfo` / `mountinfo.parseMountinfo` — the richer
//!     `/proc/self/mountinfo` source (mount ID/parent ID/root/device
//!     numbers), what `findmnt`/`libmount` actually read.
//!
//! `platform = .linux`: `statfs.zig` is raw syscalls (no libc), and
//! `mounts.zig`/`mountinfo.zig` read Linux-specific `/proc` files — this is
//! the same conscious ceiling `procnet`/`rawsock`/`icmp` accept, not a bug.
//!
//! Basic usage:
//!
//! ```zig
//! const diskusage = @import("diskusage");
//!
//! const u = try diskusage.statfs.query("/var/log");
//! std.log.info("available: {d} MB", .{u.availableBytes() / (1024 * 1024)});
//!
//! const mnts = try diskusage.mounts.readMounts(gpa, io) orelse &.{};
//! defer diskusage.mounts.freeAll(gpa, mnts);
//! for (mnts) |m| std.log.info("{s} on {s} ({s})", .{ m.device, m.mount_point, m.fs_type });
//! ```

const std = @import("std");

pub const meta = .{
    .platform = .linux, // raw statfs(2)/statfs64(2) syscalls + /proc reads, no portable fallback
    .role = .util,
    .concurrency = .reentrant, // no shared state; every call is independent
    .model_after = "musl libc (src/stat/statvfs.c) for the statfs/statfs64 syscall-selection strategy; proc(5) + statfs(2) for the wire/text formats",
    .deps = .{},
};

pub const statfs = @import("statfs.zig");
pub const mounts = @import("mounts.zig");
pub const mountinfo = @import("mountinfo.zig");

// Re-exported at the top level for the common case (mirrors how consumers
// most often reach for this: "give me disk usage", not "give me the statfs
// submodule").
pub const query = statfs.query;
pub const Usage = statfs.Usage;

test {
    // Multi-file module: every submodule's tests must be pulled into the
    // aggregator explicitly, or they are silently never compiled/run
    // (CONVENTIONS.md §6 step 3, the dark-tests rule).
    _ = statfs;
    _ = mounts;
    _ = mountinfo;
}
