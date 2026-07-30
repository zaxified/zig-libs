# scripts/

Test driver for the module collection. `zig build test` runs all 210 modules;
this exists so you don't have to.

## Which do I run?

| When | Command | What it does |
|------|---------|--------------|
| **While working** | `scripts/test.sh` | Tests only what your change can affect |
| **Before committing** | `scripts/test.sh all` | Every module — the same gate CI runs |
| Reproducing a CI lane | `scripts/test.sh all -Dstrict-debug` / `-Doptimize=ReleaseFast` | Trailing args pass through to `zig build` |
| Investigating slowness | `scripts/test.sh time` | Serial per-module duration table |

## Environment gaps

Every runner starts with a capability check. It is **silent when this host can
run everything**; otherwise it names each gap, what coverage it costs, and the
exact command that closes it — permanently where that is possible (a sysctl
drop-in rather than `sysctl -w`, which reverts on reboot). The driver only
prints those commands; it never runs anything privileged or networked for you.

Two things the printed commands get right that a hand-written one usually does
not: an **absolute** `zig` path, because sudo's `secure_path` does not include a
toolchain under `~/.config` or `~/.local`, and **separate cache directories**,
because `zig build` as root otherwise leaves root-owned entries in the repo's
`.zig-cache` and breaks your next ordinary build.

One gap stays interactive on purpose. `tc`'s `RTM_NEWACTION` checks
`CAP_NET_ADMIN` against the *initial* user namespace, so neither `unshare -rn`
nor a rootless podman container can grant it — both run in a user namespace
(`uid_map` `0 1000 1`), which is exactly the wall. Only real root clears it, and
a `NOPASSWD` sudoers rule for `zig build` would not be a narrow grant: `zig
build` executes `build.zig`, i.e. arbitrary code, as root. One skipped test
group is the better trade.

## How `changed` decides what to run

Changed files come from the working tree, the index and untracked files — or
from a diff against `BASE_REF` if you pass one (`scripts/test.sh changed main`).

- `modules/<name>/**` → module `<name>`
- `build.zig`, `build.zig.zon`, `.github/**`, `scripts/**` → **all** modules,
  because the graph or the harness itself moved
- Root docs → no modules, but a `README.md` change still runs `check-catalog`

It then adds the **reverse-dependency closure**: every module that transitively
depends on a changed one. This is the part that makes the shortcut safe —
touching `rsa` selects 17 modules (`blindrsa`, `ssh`, `xmldsig`, `saml`, `jwe`,
`iec62351`, `opcua`, `netconf`, `fleetsim`, …), not one. The graph comes from
`zig build module-graph`, so `build.zig` stays its single source of truth.

## Network-namespace wrapping

Modules doing netlink writes are run under `unshare -rn` when it is available.
This is not just extra coverage: `zig build test-netlink` on a bare dev host
**fails outright**, because the host has enough ambient netlink access for the
write tests to attempt real changes that collide with host state. Inside a
namespace they are clean and green.

`icmp` and `traceroute` are deliberately **not** wrapped — a fresh namespace
starts with `lo` down, which turns their loopback tests from pass into failure.

## Reading the output

Skip reasons are silent by default, so **any stderr output means a real
problem**. Set `ZIG_LIBS_VERBOSE_SKIP=1` to see why something skipped; the skip
*count* is always in the summary either way.

## Memory cap

Every command `test.sh` runs goes inside a transient cgroup limited to
`ZIGLIBS_MEM_MAX` (default `12G`). A test that allocates without bound is then
killed by **its own** cgroup — one red step with exit 137 and an explicit
message — instead of by the kernel's global OOM killer, which picks its victim
by size and so takes down whatever is biggest on the machine. Under an IDE that
is the editor, because every build and test is a child of the editor's cgroup.
This is not a hypothetical: a `test` binary at 15.4 GB RSS killed the whole
session here, `constraint=CONSTRAINT_NONE, global_oom` in the kernel log.

The `12G` default is measured: a full `zig build test` across every module
peaks at **4.1 GiB** for the whole parallel build, and the largest individual
test binary is 115 MB. That leaves roughly 3x headroom over a legitimate full
run while still stopping a runaway an order of magnitude smaller than the one
that caused the crash.

    ZIGLIBS_MEM_MAX=24G scripts/test.sh all    # raise it
    ZIGLIBS_MEM_MAX=off scripts/test.sh        # disable the wrapper

For anything that bypasses the driver — a bare `zig build test-<module>` while
iterating — use the same cap through `scripts/capped`:

    scripts/capped zig build test-yaml --summary all

The cap needs cgroup v2 with the `memory` controller delegated to the user
manager (any modern systemd). It is probed for, not assumed, and degrades to a
plain exec on macOS, non-systemd Linux and containers without delegation.

## Optimization modes

Compute-heavy modules (pairings, hash-based signatures, FHE, scrypt, RSA) build
at ReleaseSafe when Debug is requested — same safety checks, a fraction of the
wall clock, since they are the suite's critical path. `-Dstrict-debug` forces
real Debug.

CI runs three lanes off this one command — default, `-Dstrict-debug` and
`-Doptimize=ReleaseFast` — as separate jobs, so the slow one does not gate the
fast one. The strict-debug lane is not optional bookkeeping: without it the
plain lane no longer proves anything about real Debug for the heavy modules,
and CONVENTIONS §6.4's "green in Debug and ReleaseFast" would quietly stop
meaning what it says.

## Privileged tests

`scripts/test.sh vm` (and `scripts/vm/run.sh <module> [platform]`) runs a
module inside a disposable VM, where tests gated on real root actually
execute instead of skipping. That is not a formality — the `tc` action-table
bug in `modules/tc` was invisible for as long as its test skipped. See
[vm/README.md](vm/README.md).
