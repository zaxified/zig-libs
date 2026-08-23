# scripts/

Test driver for the module collection, plus the tooling around it. `zig build
test` runs every module; this exists so you don't have to.

## What is in here

Most of this file explains the test driver. This table exists so the rest of the
directory is not mistaken for leftovers — several of these are single-purpose
tools that look disposable once the work that needed them landed, and are not.

| File | What it is |
|------|------------|
| `test.sh`, `test-lib.sh` | The test driver and its shared shell library. Everything below the next heading is about these. |
| `test-tag.sh` | Self-test for `tag.sh`. Runs inside the driver, because a release tool whose refusal path is untested refuses nothing. |
| `tag.sh` | Cuts a dated release tag, and re-runs every lane before it does. A tag asserts that every module passed every lane at that commit. |
| `hooks/` | The commit-time formatting hook and its own self-test. A hook that always exits 0 looks exactly like "nothing was ever unformatted". |
| `capped` | Memory-capped process wrapper. ⛔ Run fuzzing through it and nothing else — an uncapped sweep has taken this host down. |
| `fuzz-sweep.sh` | Repo-wide fuzz run over the harnesses `zig build check-fuzz` requires. |
| `ctgrind.sh`, `ctgrind-expected.tsv` | Constant-time verification and the per-module expectations it is judged against. Needs valgrind, so it is deliberately NOT in the gate. |
| `dark-tests.sh` | Finds modules that DECLARE tests the test binary never ran — the failure that reads as a pass. |
| `check-http-sizeprobe.sh` | Probes the `http` module's size-limit behaviour from outside, as a consumer would. Runs on every gate — it was in the driver but missing from this table until an audit compared the two. |
| `force-pubfn-reach.zig` | The second root `check-pubfn-reach` compiles over the module graph. Zig analyses a function body only when something references it, so a `pub fn` no test reaches is never type-checked at all; this file takes a reference to every one of them. |
| `portable-known-failures.tsv` | The `(module, target)` pairs a module DECLARES in `meta.targets` but that do not currently compile, each with the real compiler error. A declared-but-broken target is a tracked debt, not a silently dropped claim. |
| `check-apps.sh` | Builds every `example-apps/` project against THIS working tree, via `zig build --fork=../..`. The apps pin a released tag because that is what someone who downloads one needs; the fork overrides that pin without touching the file. It is the only check here that reaches the published API through the real package machinery, the way a consumer does. Also refuses a directory nobody declared and a declaration whose directory is gone. |
| `check-ci-cache-keys.sh` | Refuses a CI config where one lane's cache restore-key prefix can match another lane's entry. `restore-keys` matches by prefix, so distinct names are not enough — they must not be prefixes of each other. An amd64 lane restored an aarch64 tree this way and recompiled everything, green throughout. |
| `ci-environment.sh` | Installs the live peers a hosted runner lacks — wolfSSL, the open62541 container, five Python oracles. Run by BOTH CI jobs, because two copies of an install list drift and one script cannot. Not for a development machine: it uses `sudo` and pins system packages. |
| `check-citations.py` | Verifies the RFC/standard citations in module docs point at something real. **Manual, not a gate:** measured on `dns`, it pairs an `RFC NNNN` mention with any nearby quoted string, so a quoted SPEC.md heading reports as a mismatch. Useful with triage, not as a red/green. |
| `check-uapi-consts.py` | Diffs the kernel UAPI constants modules hardcode against the headers they came from. Driven by `zig build check-uapi`, which the gate runs; it SKIPS (never fails) on a host without python3 or kernel headers. Currently 689 matched / 0 mismatched across five modules, with 263 constants unresolved — it says so rather than counting them as passes. |
| `dissect.py` | Drives Wireshark's headless dissector (`sharkd`) as an external oracle for wire-format modules. |
| `pqxdh-kdf-check.py` | Second, independent implementation of PQXDH's key-derivation chain, written from `hmac`/`hashlib` alone. **Keep it.** Signal publishes no byte-exact PQXDH vectors, so this is the only thing standing between `signal`'s composition and a round trip that would agree with itself about a misplaced KEM secret. The values it emits are pinned in `modules/signal/src/interop_vectors.zig`, so the tests pass without it — which is exactly why it looks deletable. |
| `gen-bitcoin-core-vectors.py`, `gen-bitcointx-single-bug.py`, `gen-p256-wycheproof.py`, `gen-ocsp-byname.sh` | Regenerate committed test vectors from their upstream sources (Bitcoin Core, BIP-341, Wycheproof, OCSP). **Keep them.** The vectors are frozen in the tree and the tests do not need these to run — which is exactly why they look deletable. Without them the vectors cannot be re-derived or extended, only trusted. |
| `tz-gen/` | Regenerates `modules/tz/src/tz_data.zig` — the 598-zone UTC-offset table — from a compiled zoneinfo tree. Same reasoning as the row above: the table is frozen in the tree and `tz`'s tests pass without this, which is exactly why it looks deletable. It is the only place `std.Tz` is used, and without it the pinned tzdata release can never be bumped, only trusted. Writes the tzdata version into the generated header, so the committed file records its own pin. A Zig package rather than a script, hence the directory. **Run `tz-gen/fetch-and-build.sh`, not the tool directly** — see the row below. |
| `tz-gen/fetch-and-build.sh` | Fetches the PINNED tzdata release from IANA (SHA-256 in `tz-gen/checksums.txt`), compiles it with the system `zic -b fat`, and runs `tz-gen` against that tree. Without it the obvious input is `/usr/share/zoneinfo`, which is the distro's zic output at the DISTRO's release — this host is 2026c against a 2026a pin, so re-deriving there silently produces a different table. `--check` regenerates to a temp file and diffs, non-zero on any difference. Needs network and `zic`, so it is not a gate step; a missing `zic` is a hard failure, never a fall-back to the host tree. |
| `vm/` | Boots a qemu guest and runs a module's tests as real root. The only way the live BPF, netlink and 802.11 tests execute rather than skip. |

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
- `.github/**` and any script the gate itself executes — `test.sh`,
  `test-lib.sh`, `capped`, `dark-tests.sh`, `ci-environment.sh`, `test-tag.sh`,
  `check-ci-cache-keys.sh`, `hooks/**` → **locally, a smoke set** plus a loud
  note that this is not the
  gate. The harness is the very thing that decides a narrower set, so it cannot
  vouch for its own narrowing; instead it runs one plain and one netns-wrapped
  module — the two classes `run_modules` actually distinguishes — to prove the
  select → build → run → report path still works, and tells you to run
  `scripts/test.sh all` before committing.
  **On CI (`GITHUB_ACTIONS` set) it escalates to the full gate instead.** The
  advice above is something a person at a keyboard can act on; a runner cannot,
  and on 2026-08-15 a push that rewrote 191 lines of opcua's driver went green
  having never built the module. The membership rule is "the gate executes it",
  not "it lives in `scripts/`" — four of those entries were missing until then
- `scripts/README.md`, `scripts/vm/**`, the generators → nothing; none is a gate
  step
- Root docs → no modules, but a `README.md` change still runs `check-catalog`,
  and a root `CHANGELOG.md` change still runs `check-changelog` (that file is
  the index of the per-module changelogs, so editing it is exactly how it goes
  out of step with them)

### Touching `build.zig` does not mean running everything

Adding a module appends one row to `module_list` and cannot affect any existing
module, so escalating to the full gate for it is the driver being
wrong, not careful. The decision is made from the **module graph**, not from
which file was saved: the last verified graph is kept at
`.zig-cache/ziglibs-graph.tsv` and compared row by row.

| Graph delta | What runs |
|---|---|
| Rows only ADDED | just the new modules — adding `yaml` tests `yaml`, not everything |
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

`test.sh` re-execs itself inside **one** transient cgroup limited to
`ZIGLIBS_RUN_MEM_MAX` (default `20G`) and runs everything there. A run that
allocates without bound is then killed by **its own** cgroup — one red step with
exit 137 and an explicit message — instead of by the kernel's global OOM killer,
which picks its victim by `oom_score_adj` rather than by who filled memory.
Under an IDE that victim is the editor. Not hypothetical, twice over: a `test`
binary at 15.4 GB RSS killed the session here, and on 2026-08-22 an editor
window died with `global_oom` while the gate was mid-run.

**One cap for the run, not one per step, and the difference is the whole
point.** Each step used to get its own scope. That bounds a single runaway test
and cannot bound a run, for two reasons found the hard way:

- `--collect` destroys a step's scope when the step ends, and whatever it left
  in tmpfs is **reparented to the uncapped user slice**. Charges accumulate
  across steps while every individual step stays politely under its limit.
- `/tmp` is tmpfs on a desktop — RAM, evictable only to swap — and `step()`
  captures every command's stdout and stderr into `mktemp` files. A full run's
  logs are gigabytes of it. The 2026-08-22 crash was 15.7 GB of shmem against
  511 MB of swap, `all_unreclaimable? yes`, with the sum of every process's RSS
  only 9 GB. Nothing on the machine looked large; the memory was in files.

`test.sh` therefore also points `TMPDIR` at `.zig-cache/gate-tmp` (on disk) when
it would otherwise be `/tmp`, so step logs never occupy RAM at all. Set `TMPDIR`
yourself to override.

Verify the cap rather than trusting it: `ZIGLIBS_RUN_MEM_MAX` set absurdly low
must produce exit 137, and a *warm* cache is not a test — a fully cached
`zig build` allocates almost nothing and sails under a 150 MB cap. Force real
work (`--cache-dir` to a fresh directory) or you are measuring nothing.

The `12G` default is measured: a full `zig build test` across every module
peaks at **4.1 GiB** for the whole parallel build, and the largest individual
test binary is 115 MB. That leaves roughly 3x headroom over a legitimate full
run while still stopping a runaway an order of magnitude smaller than the one
that caused the crash.

    ZIGLIBS_RUN_MEM_MAX=28G scripts/test.sh all   # raise it
    ZIGLIBS_RUN_MEM_MAX=off scripts/test.sh       # disable the whole-run scope

`ZIGLIBS_MEM_MAX` (default `12G`) still exists and still wraps each command —
but only when the run is NOT already inside the whole-run scope, since a
transient scope cannot spawn another. It is what `scripts/capped` and
`scripts/tag.sh`'s per-lane wrapping use. Two names for two meanings, kept
separate so raising one cannot silently mean the other.

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
2026-08-11 every module in the collection satisfied declared == `(N total)`
exactly. Modules have been added since; the gate recomputes live, so a green run
is the current claim and that date is only when the table was last complete.

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

## Constant-time harnesses (ctgrind)

`scripts/ctgrind.sh [module ...]` runs every committed
`modules/<m>/src/ctgrind_harness.zig` under `valgrind --tool=memcheck` and
prints a control table. A harness marks a secret `MAKE_MEM_UNDEFINED`, drives
it through the code whose constant-time property that module's `SPEC.md`
claims, and formats the result through a deliberately non-constant-time
printer as a propagation witness.

    scripts/ctgrind.sh                    # every module with a harness
    scripts/ctgrind.sh ed448              # just this one
    scripts/ctgrind.sh --stacks ecvrf     # …and dump each row's memcheck log
    scripts/ctgrind.sh --pattern 'root[.]zig' ecvrf   # re-attribute the in-file column
    scripts/ctgrind.sh --check            # compare against scripts/ctgrind-expected.tsv

Needs `valgrind` on PATH. Not part of `zig build test`: a memcheck context
count is valgrind's own verdict, not something a Zig test can assert on.

**Every (mode, target) triple is three rows, never one.** The claim, an
UNTAINTED negative control, and a build without `-fvalgrind`. The last one is
not decoration: `std.valgrind.doClientRequest` opens with
`if (!builtin.valgrind_support) return default;`, and the release optimize
modes turn that flag off, so a ReleaseFast binary built **without the switch**
is a silent no-op under valgrind and reports a clean `0 errors` whatever the
code does. A ctgrind claim that does not state its **mode**, its **switch** and
its **context count** is therefore unfalsifiable — indistinguishable from a
measurement that never happened. Seven modules carry a harness today; five of
them carried exactly such a claim (one with a seven-row table) before these
harnesses existed, and `k256` + `montint` carried claims with **no** numbers at
all — only disassembly read once by hand.

The `--pattern` flag exists so that an attribution written in a `SPEC.md`
("these three contexts are all in `encodeToCurve`", "none are in `ct25519`'s
ladder") can be re-checked rather than believed.

**A green `--check` does not mean every constant-time claim holds.** It means
every recorded number still reads the way it read when it was taken. When a
measurement finds a real DEFECT, the convention is to record the defective count
here anyway, marked DEFECT in the comment above the row: the alternative is a
defect nothing tracks, and a row that goes red when the leak is *fixed* is how
the fix gets noticed. That is exactly how it went for `montint` at
`L < asm_min_limbs` — recorded at 7 and 5 on 2026-08-13, fixed the same day,
re-measured 0 and 0 (`modules/montint/SPEC.md`). No DEFECT rows are outstanding
today.

The montint fix is also the sharpest warning this file can give about reading
generated code instead of measuring it. The obvious structural repair — rewriting
the masked select into the sibling asm core's provably-clean two-pass form —
moved the counts by **exactly zero**, in both targets. Only an explicit
optimization barrier on the mask worked. A fix that looks right in the source is
not a fix until `--check` says so.

One trap when adding a harness or a positive control: an injected leak can make
the reported TOTAL go **down**, because memcheck resolves the branch and the
taint stops propagating to the downstream witness. "The count went up" is
therefore the wrong pass criterion; "a new context appeared at the mutated
location" is the right one. Both were observed while building the `k256`
harness.

### What keeps them from rotting

`zig build check-ctgrind` compiles every harness with `-fvalgrind`. It runs
**no** valgrind, so the gate never depends on that tool being installed and
never pays for a memcheck run. Semantic analysis only — the build system elides
the binary because nothing asks for it — so a warm run is ~0.1 s. It catches
the rot mode that actually happens: a harness that stops compiling because the
module's API moved, leaving the `SPEC.md` table it backs as an unfalsifiable
claim again. Verified by renaming a function the `ecvrf` harness calls: the
step failed, exit 1.

It is an **explicit `step` in all three of this driver's paths** (`all`,
`changed`, and the harness smoke set), not only a dependency of
`zig build test`. That distinction is the whole difference between a check and
a decoration: this driver never runs `zig build test` — it runs `test-<module>`
per module — so anything hung off the aggregate step alone would never execute
in the gate. `-fvalgrind` is forced on for the check even though it emits
nothing: the client-request bodies sit behind a comptime
`builtin.valgrind_support` branch, so a check built without the switch would
leave the taint calls unanalysed and would not notice a harness that had
stopped compiling against them.

`scripts/ctgrind.sh --check` catches the other direction — the code growing a
secret-dependent branch. It asserts what the claims actually rest on, not the
raw totals: every untainted control is 0, every no-`-fvalgrind` trap is 0, each
claim row's in-file count matches `scripts/ctgrind-expected.tsv`, and each
claim row's total is non-zero so a propagation witness demonstrably fired.
Totals are deliberately *not* diffed — they include the harness's own hex
formatter and std internals, so pinning them would go red on a compiler upgrade
for a reason that says nothing about the module, and a check that reds for the
wrong reason gets muted. Verified by re-introducing a variable-time
`if (nibble != 0)` table lookup in `ed448`'s `Point.mul`: `--check` reported
both affected rows and exited 1.

**What neither catches:** nothing compares a `SPEC.md` table against
`ctgrind-expected.tsv`, so prose and expectation can still drift apart if
someone edits one and not the other; and `--check` needs valgrind and a human
(or a lane that has it) to run it — it is not in the gate, by design.

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
