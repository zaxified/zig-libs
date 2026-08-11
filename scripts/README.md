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
- `build.zig`, `build.zig.zon` → **ask the graph** (see below), not "all"
- `.github/**`, `scripts/test.sh`, `scripts/test-lib.sh`, `scripts/capped` → a
  **smoke set**, plus a loud note that this is not the gate. The harness is the
  very thing that decides a narrower set, so it cannot vouch for its own
  narrowing; instead it runs one plain and one netns-wrapped module — the two
  classes `run_modules` actually distinguishes — to prove the select → build →
  run → report path still works, and tells you to run `scripts/test.sh all`
  before committing
- `scripts/README.md`, `scripts/vm/**` → nothing; neither affects this lane
- Root docs → no modules, but a `README.md` change still runs `check-catalog`

### Touching `build.zig` does not mean running everything

Adding a module appends one row to `module_list` and cannot affect any existing
module, so escalating to the full ~8-minute gate for it is the driver being
wrong, not careful. The decision is made from the **module graph**, not from
which file was saved: the last verified graph is kept at
`.zig-cache/ziglibs-graph.tsv` and compared row by row.

| Graph delta | What runs |
|---|---|
| Rows only ADDED | just the new modules (adding `yaml`: ~2 s, not ~510 s) |
| A row altered (deps moved) | that module, plus its reverse-dep closure |
| A row removed (module deleted) | nothing extra — either the dependent's own row also changed (covered above), or it now names a module that does not exist and `zig build module-graph` aborts, so no run happens at all |
| Byte-identical | nothing extra |
| No snapshot yet | everything — there is nothing to compare against |

The snapshot is written only after a run **succeeds**, so a failed run never
promotes a graph to "known good". `build.zig` is still never parsed by this
script; `zig build module-graph` remains the only authority.

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

## Dark tests

A test that never runs has no symptom. Zig collects tests only from the files it
**analyses**, so a source reachable only through a `pub const conn =
@import("conn.zig");` re-export contributes nothing to the test binary — no
failure, no skip, no warning, and the suite total agrees with itself because it
is computed from what ran. `websocket` once shipped running **zero** of its 52
tests, one of which did not even compile; `ratelimit` reported `18/18 passed`,
exit 0, with `conn.zig`'s whole suite absent.

`scripts/dark-tests.sh` compares, per module, the number of `^test ` blocks in
`modules/<m>/src/**/*.zig` against the `(N total)` field of that module's
run-test line in `--summary all`, and requires them to be **equal**.

Two details are the whole check:

- **`(N total)`, not the pass count.** `run test 38 pass 3 skipped (41 total)` —
  the pass count is smaller than the declared count for any module with skips,
  so reading it makes every such module look short and hides a real dark file in
  that noise. `(N total)` is the number of test declarations the binary was
  built from, which is exactly what the disk count predicts.
- **Equality, not a ratio.** The earlier version only failed at zero and merely
  *reported* `ran < disk/2`. `ratelimit` had 21 on disk and 18 running — nowhere
  near half — so the shape that motivated the check would have passed it.

`^test ` is an **exact** count here, not an upper bound: Zig has no block
comments, a `//` comment cannot begin with `test` at column 0, every line of a
multi-line string starts with `\\`, test declarations are container-level and
`zig fmt` puts those at column 0, and the gate runs `zig fmt --check` over
`modules`. Verified across the tree: no indented `test "` / `test {` exists. The
count is **recursive** — `modules/protobuf/src/testdata/golden_bytes.zig` is
`@import`ed by `golden_test.zig` and is as much part of the compilation as any
top-level file. An aggregator `test { _ = conn; }` is itself a test: it is
counted on disk and it runs, so it appears on both sides and cancels.

A module that legitimately owns `.zig` sources its own compilation never
analyses gets an explicit row in the script's `DECLARED_EXEMPT`, with the count
and a written reason. That table is **empty**, and that is a measurement: as of
2026-08-11 all 224 modules satisfy declared == `(N total)` exactly.

### What it costs

Nothing in the gate. Zig does **not** cache test *run* steps — the same
multi-module `zig build … --summary all` takes the same 13.3 s twice in a row,
`compile test … cached` on both — so re-running the suites to count their tests
would roughly double `scripts/test.sh all`. Instead the driver passes
`--summary all` to the run it was already making, keeps that output, and hands
it to `scripts/dark-tests.sh --summary <file>`, which builds nothing.

    zig build check-dark-tests                     # standalone: builds+runs everything
    zig build check-dark-tests -Ddark-module=http  # …or just one module
    scripts/dark-tests.sh ratelimit                # same thing without the build step

The standalone forms pay for a full suite run, because they have no summary to
read. Use them outside the driver; inside it the check is already running.

`-Dtest-filter` compiles a subset on purpose, so the driver **skips** the check
(loudly) rather than reporting a phantom shortfall.

## Standards citations

`scripts/check-citations.py [module ...]` fetches the RFC/BIP/BOLT/W3C text
behind a quoted standards citation in `modules/**` and reports each one
VERIFIED, MISMATCH or UNFETCHABLE — a fabricated citation is worse than a
missing one, since nothing prompts a reader to doubt it. Needs network on
first run; caches into `${XDG_CACHE_HOME:-~/.cache}/zig-libs-citations`, never
into the repo.

It is a triage aid, not a gate. Extraction is regex-based, so a full-repo run
reports roughly half its claims as MISMATCH — mostly ordinary prose sitting
near a standards token, not wrong citations. Read the `file:line` before
believing one. UNFETCHABLE is never a pass: those claims are simply unchecked.
