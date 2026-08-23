// SPDX-License-Identifier: MIT

//! diskusage — the `du(1)` question: how much space does a directory tree
//! occupy? Walks the tree, `lstat`s every entry, and accumulates real
//! allocation and apparent size, with the hard-link and filesystem-boundary
//! rules `du` itself applies.
//!
//! **Pairs with, and deliberately does not overlap, `diskfree`.** That
//! module answers the `df` question — whole-filesystem space, via
//! `statfs(2)` plus the mount table. It walks no directories and stats no
//! files. This one walks and stats and never calls `statfs`. A caller who
//! wants "how full is this filesystem" wants `diskfree`; a caller who wants
//! "what is taking up the space" wants this. Neither imports the other.
//!
//! Two pieces (see each submodule's doc comment for the reasoning):
//!
//!   * `stat` — the raw per-file metadata `std` does not expose portably:
//!     `st_blocks` (real allocation) and `st_dev` (filesystem identity),
//!     via `statx(2)` where the kernel has it and a raw
//!     `fstatat`/`fstatat64` with a per-architecture kernel-ABI struct
//!     where it does not.
//!   * `scan` — the traversal and accumulation: `du`'s hard-link
//!     de-duplication, its one-filesystem boundary, its post-order
//!     per-directory subtotals, and its skip-and-carry-on failure
//!     behaviour.
//!
//! `platform = .linux`: raw syscalls, no libc, no portable fallback — the
//! same conscious ceiling `diskfree`/`procnet`/`rawsock` accept.
//!
//! Basic usage:
//!
//! ```zig
//! const diskusage = @import("diskusage");
//!
//! var threaded: std.Io.Threaded = .init(gpa, .{});
//! defer threaded.deinit();
//!
//! const r = try diskusage.scanPath(gpa, threaded.io(), "/var/log", .{});
//! std.log.info("{d} bytes allocated, {d} apparent, {d} entries", .{
//!     r.total.allocated_bytes, r.total.apparent_bytes, r.total.entries,
//! });
//! ```

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "`du`-style tree walk over a raw `statx`/`fstatat` metadata wrapper — apparent size and real allocation in one pass, hard links counted once, one-filesystem boundary",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "**linux**",
    .targets = .{ .linux64, .linux32 },
    .platform = .linux, // raw statx(2)/fstatat(2) syscalls, no libc, no portable fallback
    .role = .util,
    // No shared state: the stat backend is chosen per scan and passed down,
    // never latched in a global, so two threads may scan two trees at once.
    .concurrency = .reentrant,
    .model_after = "GNU coreutils du (fts FTS_XDEV boundary + (dev,ino) hard-link set) for the traversal rules; statx(2) and the kernel UAPI stat structs for the wire format",
    .deps = .{},
};

pub const stat = @import("stat.zig");
pub const scan = @import("scan.zig");

// Re-exported at the top level for the common case: a consumer reaches for
// this module saying "how big is this tree", not "give me the scan
// submodule".
pub const scanAt = scan.scanAt;
pub const scanPath = scan.scanPath;
pub const Options = scan.Options;
pub const Report = scan.Report;
pub const Totals = scan.Totals;
pub const ErrorSink = scan.ErrorSink;
pub const DirSink = scan.DirSink;
pub const SinkError = scan.SinkError;
pub const ScanError = scan.ScanError;
pub const FileStat = stat.FileStat;
pub const Backend = stat.Backend;

test {
    // Multi-file module: every submodule's tests must be pulled into the
    // aggregator explicitly, or they are silently never compiled/run
    // (CONVENTIONS.md §6 step 3, the dark-tests rule).
    _ = stat;
    _ = scan;
}
