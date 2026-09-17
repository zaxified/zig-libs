# `diskusage` verification instruments

Two instruments, both run by hand and neither wired into `zig build`
(`CONVENTIONS.md` §9): the static one needs a cross-C-compiler and kernel
headers, the runtime one needs `qemu-user`. `zig build test-diskusage`
requires neither.

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for data the
tests pin, and oracles that drive a foreign implementation through the public API or
wire format. The audit's mutation runners, race-condition probes and per-finding
snapshots were deleted on 2026-09-17; what they found is pinned by tests in `src/`
or filed as open findings.

## Two independent checks on the same nine `struct stat` families

| tool | question it answers | executes anything? |
|---|---|---|
| [`stat-layout-probe.sh`](./stat-layout-probe.sh) | Does `src/stat.zig`'s `@sizeOf`/`@offsetOf` for each family match the real kernel UAPI header, compiled by that architecture's own C ABI? | No — reads ELF symbol sizes from an unlinked object file. |
| `arch_probe.zig` + [`qemu-runtime-oracle.sh`](./qemu-runtime-oracle.sh) | Cross-compiled and run for real under `qemu-user`, does this module's own `stat.lstatPath` (public API, both backends) agree with the HOST's `stat(1)` on the same real files? | Yes — `qemu-user` translates the guest syscall onto the real host kernel/filesystem, so a mismatch is a fact about the decode, not about the file. |

```bash
bash modules/diskusage/tools/qemu-runtime-oracle.sh
```

Builds `arch_probe.zig` for `x86_64` (native) plus `aarch64`, `arm`, `riscv64`,
`mips` (each under its `qemu-<arch>` user-mode emulator, skipped gracefully if
not installed), runs it against a small fixture (a plain file, a 4 MiB sparse
file, a symlink, a directory, `/dev/null`, `/etc/hostname`), and diffs
`mode`/`nlink`/`size`/`blocks`/`maj`/`min`/`ino` from BOTH the `statx` and
`fstatat` backends against `stat -c` on the host for every path.

**Measured 2026-09-17** (this machine, Zig 0.16, `qemu-aarch64`/`qemu-arm`/
`qemu-riscv64`/`qemu-mips` installed): **`OK=60 MISMATCH=0 SKIPPED-ARCH=0`** —
5 architectures × 2 backends × 6 fixture paths, all agreeing with the host's
own `stat(1)`. Covers three of the nine `Family` groups directly
(`x86_64`, `generic64` via aarch64/riscv64, `arm32`, `mips`); the A1 audit's
original run (pre-adoption, 17 architectures) additionally covered `s390x`,
`ppc64`/`ppc64le`, `x86_32`, and settled that sparc64's syscall 289 fills
`struct stat64` — re-running this script with more `qemu-<arch>` binaries
installed reaches the same families the same way.

SPEC.md grades this module *class B · oracle MIXED*; this is the "REDERIVED
... additionally live-verified" half for backends beyond the host's own
architecture, alongside the static `stat-layout-probe.sh` oracle.

No foreign licence to check: nothing beyond `zig`, `qemu-user`, and this
system's own `stat(1)`/kernel is involved.
