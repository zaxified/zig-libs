// SPDX-License-Identifier: MIT
//
// The runtime half of the cross-architecture layout oracle behind
// `src/stat.zig`'s nine `struct stat` families (finding O1, A1 audit,
// disposition 2026-09-17). `tools/stat-layout-probe.sh` (existing, kept
// under `CONVENTIONS.md` §9 as a data recipe) checks `@sizeOf`/`@offsetOf`
// STATICALLY, from ELF symbol sizes, with nothing executed. This program is
// the complementary EXECUTION oracle: cross-compiled and run for real under
// `qemu-user`, it calls this module's own `stat.lstatPath` — through the
// public API, not a copy of `stat.zig` — against real files on the host
// filesystem, for both backends. `qemu-user` translates the guest's syscall
// onto the real host kernel and filesystem, so a mismatch against the
// host's own `stat(1)` on the SAME file is a fact about this module's
// per-architecture struct decode, not about the file.
//
// WHAT IT NEEDS: the live module (`diskusage`), nothing else to build; a
// cross-compile target and (for anything but the host architecture) a
// `qemu-<arch>` user-mode emulator to run it. See
// `modules/diskusage/tools/README.md` for the build/run recipe.
//
// WHAT IT PRINTS: one line per `(path, backend)`, in the same field order
// `stat-layout-probe.sh`'s neighbour script `check-probes.sh` (A1 audit,
// pre-adoption) compared against `stat -c '%n mode=%f nlink=%h size=%s
// blocks=%b maj=%Hd min=%Ld ino=%i'` — deliberately the same shape so the
// two can be diffed with a script, not eyeballed:
//
//   <path> <backend> mode=<hex> nlink=<dec> size=<dec> blocks=<dec> maj=<dec> min=<dec> ino=<dec>
//   <path> <backend> ERR <error-name>
//
// Uses a raw `write(2)` rather than `std.debug.print`/`std.fs.File.Writer`:
// this binary is cross-compiled to targets `std`'s buffered-writer path is
// not routinely exercised on (musl mips/arm/riscv under qemu-user), and a
// direct syscall sidesteps any question of whether stdio buffering survived
// the cross-build. The A1 audit's own probe used the same technique across
// 17 architectures.
const std = @import("std");
const linux = std.os.linux;
const builtin = @import("builtin");
const diskusage = @import("diskusage");

fn emit(comptime fmt: []const u8, args: anytype) void {
    var buf: [1024]u8 = undefined;
    const s = std.fmt.bufPrint(&buf, fmt, args) catch return;
    _ = linux.write(1, s.ptr, s.len);
}

pub fn main(init: std.process.Init.Minimal) void {
    emit("# target={s}-{s} fstatat_available={}\n", .{
        @tagName(builtin.cpu.arch),
        @tagName(builtin.abi),
        diskusage.stat.fstatat_available,
    });
    var it = init.args.vector;
    for (it[1..]) |arg_z| {
        const p = std.mem.span(arg_z);
        inline for (.{ .statx, .fstatat }) |backend| {
            if (diskusage.stat.lstatPath(backend, p)) |st| {
                emit("{s} {s} mode={x} nlink={d} size={d} blocks={d} maj={d} min={d} ino={d}\n", .{
                    p, @tagName(backend), st.mode, st.nlink, st.size, st.blocks, st.dev_major, st.dev_minor, st.ino,
                });
            } else |e| {
                emit("{s} {s} ERR {s}\n", .{ p, @tagName(backend), @errorName(e) });
            }
        }
    }
}
