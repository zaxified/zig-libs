// SPDX-License-Identifier: MIT
//! Ad-hoc oracle: prints this host's `statfs` family/ABI, a live `query("/")`
//! result, the raw syscall bytes, and how the kernel's `do_statfs64` answers
//! a `query` with a deliberately wrong `sz` (the EINVAL-bounds-mistakes claim
//! `SPEC.md`'s "Self-checking property" and "x86 compat-layer assumption"
//! sections document).
//!
//! ⚠ **STALE as of 2026-09-10, moved verbatim rather than rebuilt.** This
//! references `statfs.family`, `statfs.audit_struct_size`,
//! `statfs.auditRawBytes` and `statfs.auditQueryWithSize` — none of which are
//! `pub` in today's `src/statfs.zig` (`family`/`familyFor`/`Family` are all
//! private, and the three `audit*` helpers do not exist at all under any
//! name). The audit that produced this file most likely ran it compiled
//! *inside* the module (same-file access to private symbols), then this copy
//! was extracted into the audit's evidence directory afterward, losing that
//! access — exactly the failure mode `CONVENTIONS.md` §9 warns an instrument
//! parked outside its module's gates suffers ("never built, never run,
//! rotting silently"). Per this A1 fixer campaign's brief (§3b), the
//! instruction was to relocate it into the module rather than rebuild it —
//! done here — but making it RUN again (exposing the needed surface as
//! `pub`, or moving this logic into `src/` as a `test` block) is a separate,
//! undone step: it touches `statfs.zig`'s public API shape, which is outside
//! the two findings (F7, F8) this campaign session actually fixed in
//! `diskfree`. Left as a TODO for whoever next needs this oracle.
//!
//! Intended usage once repaired: `zig run modules/diskfree/tools/arch.zig
//! --deps diskfree -Mdiskfree=modules/diskfree/src/root.zig`.
//!
//! Per `CONVENTIONS.md` §9, this belongs in the module's own tree rather than
//! an audit directory — moved here 2026-09-10 (A1 fixer campaign, `diskfree`)
//! from `20260901-zig-libs-audit/evidence/diskfree-oracle/`, where the
//! 2026-09-03 audit that used it had left it.

const std = @import("std");
const builtin = @import("builtin");
const diskfree = @import("diskfree");
const statfs = diskfree.statfs;

pub fn main() !void {
    const path = "/";
    std.debug.print("arch={s} abi={s} mode={s} family={s} sizeof={d}\n", .{
        @tagName(builtin.cpu.arch), @tagName(builtin.abi),    @tagName(builtin.mode),
        @tagName(statfs.family),    statfs.audit_struct_size,
    });
    const u = statfs.query(path) catch |e| {
        std.debug.print("  query ERR {}\n", .{e});
        return;
    };
    std.debug.print("  f_type=0x{x} bsize={d} frsize={d} blocks={d} bfree={d} bavail={d} files={d} ffree={d} namelen={d}\n", .{
        u.fs_type_magic,    u.block_size,   u.fragment_size, u.blocks_total, u.blocks_free,
        u.blocks_available, u.inodes_total, u.inodes_free,   u.name_max,
    });
    var raw: [256]u8 = undefined;
    const n = statfs.auditRawBytes(path, &raw) catch |e| {
        std.debug.print("  raw ERR {}\n", .{e});
        return;
    };
    std.debug.print("  raw[{d}]=", .{n});
    for (raw[0..n]) |b| std.debug.print("{x:0>2}", .{b});
    std.debug.print("\n", .{});
    // EINVAL claim: wrong sz values
    const sizes = [_]usize{ 84, 88, 96, 120, 0, 4096 };
    for (sizes) |sz| {
        const r = statfs.auditQueryWithSize(path, sz) catch |e| {
            std.debug.print("  sz={d}: caller err {}\n", .{ sz, e });
            continue;
        };
        std.debug.print("  sz={d}: errno={s} blocks={d}\n", .{ sz, @tagName(r.errno), r.u.blocks_total });
    }
}
