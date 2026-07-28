# scripts/

Test driver for the module collection. `zig build test` runs all 210 modules;
this exists so you don't have to.

## Which do I run?

| When | Command | What it does |
|------|---------|--------------|
| **While working** | `scripts/test.sh` | Tests only what your change can affect |
| **Before committing** | `scripts/test.sh all` | Every module — the same gate CI runs |
| Investigating slowness | `scripts/test.sh time` | Serial per-module duration table |
| New machine / unexpected skips | `scripts/test.sh env` | What this host can and cannot do |
| Closing those gaps | `scripts/test.sh prepare [--yes]` | Dry-run unless `--yes` is passed |

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

## Optimization modes

Compute-heavy modules (pairings, hash-based signatures, FHE, scrypt, RSA) build
at ReleaseSafe when Debug is requested — same safety checks, a fraction of the
wall clock, since they are the suite's critical path. `-Dstrict-debug` forces
real Debug; that is what the CI matrix should use.
