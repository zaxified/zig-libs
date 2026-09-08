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
| `fuzz-sweep.sh` | Repo-wide fuzz run over the harnesses `zig build check-fuzz` requires. ⛔ **This is the ONLY thing in the repo that actually fuzzes** — see below. |
| `ctgrind.sh`, `ctgrind-expected.tsv` | Constant-time verification and the per-module expectations it is judged against. Needs valgrind, so it is deliberately NOT in the gate. |
| `dark-tests.sh` | Finds modules that DECLARE tests the test binary never ran — the failure that reads as a pass. |
| `check-http-sizeprobe.sh` | Probes the `http` module's size-limit behaviour from outside, as a consumer would. Runs on every gate — it was in the driver but missing from this table until an audit compared the two. |
| `check-fp-freedom.sh` | Disassembles a ReleaseFast `falcon` and fails if a variable-latency FP instruction reached a non-test symbol. The `fpr` integer emulation is bit-identical to hardware FP, so **no value test can defend it** — the whole suite stays green with `fpr.div` replaced by `/`. Runs on every gate. |
| `check-skip-as-pass.py` | Refuses a test that announces a skip and then returns plainly — `zig test` counts a bare `return;` as a **PASS**, so the test prints "SKIPPED" and the summary reports full coverage. `testkit.skip` exists to replace exactly that shape and says so in its own doc comment; the first audit of `testkit` (2026-09-04) still found **11 instances in the tree**. Measured on one: `2/2 tests passed` before, `1 pass, 1 skip` after, and `nftables` as a whole went from 94 passing to `90 pass, 4 skip`. Catches two shapes — an announcement adjacent to a bare `return;` inside a test, and a *helper* that announces a skip and returns `null`, which is how three of them hid behind `liveSocket(…) orelse return;`. ⛔ Blind to a skip that never announces itself. Runs on every gate. |
| `check-fuzz-reach.py` | Refuses a fuzz harness that does not READ the input it is given. `zig build check-fuzz` proves a harness EXISTS; this proves it reads. `std.testing.Smith`'s ranged draws (`valueRange*`, `valueWeighted`, `index`, `bool*`, and `value` of a type narrower than 64 bits) read eight octets as a little-endian u64 and return the range MINIMUM unless that u64 already lies inside the range — **and return the minimum outright when fewer than eight octets remain** (`Smith.zig:445`). ⚠ The mechanism this row used to state — *"`bytes` consumed the whole input"* — is **false**: `Smith.zig:568` copies `@min(out.len, in.len)`. What actually happens is worse and sharper, and `modules/testkit/src/fuzz.zig` pins it in a test: with an 18-octet seed, `buf[0] == 'G'` and the length drawn right after it is **0**. **The harness fetches its input and then throws it away.** So the collapse is a function of seed LENGTH, which is why `--fuzz` (sizing its own inputs) can reproduce a crash while a hand-written corpus cannot. Three rules: **R1** the first draw must be faithful (`bytes*`/`slice*`, `value(T)` with T at least 64 bits, `[N]u8`); **R2** a collapsing binding must not govern the EXTENT of drawn bytes — as a slice of a filled buffer (any start, not just `buf[0..n]`), as the bound of a draw into one, or as the bound of the loop that feeds one; **R2(c)** a collapsing binding must not select WHICH path runs — a table index or a `switch` discriminant — unless the same table is iterated whole anyway. ⛔ **It measures one axis of two.** Outside `--fuzz` the lane replays the target's `corpus` and then one round of `in = ""`, so a target with no corpus executes exactly one input for ever. Driving this gate to zero moves targets from "collapsed" to "fixed and still fed one all-zero buffer". Use `fuzz-seed-candidates.py` and `modules/testkit/src/fuzz.zig` to close the other axis in the same edit. It also prints a worklist it deliberately does NOT count: **knobs drawn after a faithful byte draw**. `bytes` consumes `@min(buf.len, in.len)`, so a seed no longer than the buffer leaves nothing behind it and every later draw returns its minimum — `pir`'s three hostile-share harnesses meant party 1 had never run in the whole module, and an `nl80211` harness passed a pinned 0 MHz into the very function its security tests are about. ⚠ Whether those draws are dead is a property of the CORPUS, not the code: a seed longer than the buffer leaves a tail and they are faithful, which is one of the two blessed fixes and is already in use in finished modules. So it is a worklist to answer per target by reading the corpus, never a verdict, and it stays outside the ratchet. Runs `--ratchet` against `fuzz-reach-baseline.txt`; `--list` is the worklist grouped by module, `--module <name>` narrows it, `--update-baseline` locks a module's improvement in. A module states an exemption in its own SPEC.md/README.md as `**Fuzz-reach exemption:** STRUCTURED via fuzzA, fuzzB`. ⛔ Blind to whether the harness ASSERTS anything about what it decoded. Runs on every gate. |
| `fuzz-reach-baseline.txt` | The per-module ceiling `check-fuzz-reach.py --ratchet` enforces: a module may not exceed its number, and a module absent from the file must be at **zero**. Per module and not one total on purpose — a total lets one module regress while another improves and still reads green. `--update-baseline` rewrites it and **refuses to record a regression**: raising a ceiling is a decision, made by editing the file in a commit that says why. |
| `fuzz-seed-candidates.py` | Harvests candidate corpus seeds from a module's own tests — `./scripts/fuzz-seed-candidates.py modules/<m>/src/<file>.zig`. The expensive half of the fuzz burn-down is not the draw fix, it is finding real frames, and every module already has them in the value tests beside the harness. Prints every byte-array literal, `hex.bytes` vector and string literal as a `seed("…")` line with the line it came from, byte arrays first, and **warns when a candidate is longer than the harness's buffer** — a seed over the buffer reads back as the EMPTY one, which is silent everywhere else. ⚠ It is a shortlist to READ and choose from, not a corpus: a corpus nobody chose is worth nothing (`bacnet/service` once scored 19 of 19 "accepted" because decoding `""` is legal there). |
| `check-example-assert.py` | Refuses `std.debug.assert` under `modules/*/example/`. `build.zig` builds each example with the run's own `.optimize` and `run-examples` RUNS it in the lane's mode, so in `-Doptimize=ReleaseFast` every assertion is compiled out, the example prints its success lines and exits 0 having checked nothing. Measured 2026-09-05: **593 sites in 63 of the 230 examples**. Not merely lost coverage — `sealedbox`, `ripemd160` and `bip340` compared against an EXTERNAL oracle this way and PRINTED that the oracle agreed when no comparison ran; verified by breaking `sealedbox`'s PyNaCl constant, after which the old example still exited 0 and still claimed a byte-exact match, while the converted one names the failing line. Replacement is `must(<cond>, @src())` over `std.debug.panic`, which is live in every optimize mode, or `if (!cond) return error.X;`. ⛔ Blind to `unreachable`, to `std.debug.assert` inside `src/`, to a check that cannot fail, and to whether the example is run at all. Runs on every gate. |
| `check-changelog-entry.py` | Refuses a change-set that moves a module substantially without moving its `CHANGELOG.md`. `zig build check-changelog` is a PRESENCE gate — it reads the tree, never a diff, so a module can have its parser rewritten while its changelog last moved six weeks ago and stay green. **The rule, in one sentence:** a module owes a new dated bullet when, under `modules/<name>/src/`, the change-set touches a line beginning with `pub` **or** moves more than 25 lines of code — excluding blank lines, comments, whitespace-only differences, and everything inside a `test` block (tests live in `src/` here, so counting them would make a batch of regression tests look like a rewrite). Two triggers and not one, because a line threshold gets both ends backwards: widening a return type is one line every consumer must recompile against, and re-flowing a match is 200 lines nobody can observe. Base ref against the tree is authoritative and is what CI passes; `--staged` is what `hooks/pre-commit` asks of one commit; `--commit REV`/`A..B` replays history. **The escape is a real entry** — `- **YYYY-MM-DD** — **NO CONSUMER-VISIBLE CHANGE:** …` — deliberately not special-cased in code, for the same reason `FUZZ-EXEMPT.tsv` was retired, and the gate names every module that used it on every run. Replayed over the last 120 commits: 7 of 12 ten-commit windows red, 16 flags, all real. ⛔ Blind to a multi-line `pub fn` signature and to a field added inside a `pub const T = struct`; both need a Zig-side parse. Runs on every gate. |
| `force-pubfn-reach.zig` | The second root `check-pubfn-reach` compiles over the module graph. Zig analyses a function body only when something references it, so a `pub fn` no test reaches is never type-checked at all; this file takes a reference to every one of them. |
| `portable-known-failures.tsv` | The `(module, target)` pairs a module DECLARES in `meta.targets` but that do not currently compile, each with the real compiler error. A declared-but-broken target is a tracked debt, not a silently dropped claim. |
| `check-apps.sh` | Builds every `example-apps/` project against THIS working tree, via `zig build --fork=../..`. The apps pin a released tag because that is what someone who downloads one needs; the fork overrides that pin without touching the file. It is the only check here that reaches the published API through the real package machinery, the way a consumer does. `--pinned` builds from the manifest as written instead — fetch by URL and hash, compile the exported package — which is the downloader's own path and the only thing that exercises `.paths`; it is fail-closed and refuses unless every pinned tag resolves to `HEAD`, i.e. on a tag ref and nowhere else. `--run` then executes each app's own `smoke.sh`, which starts the program and asserts on what it does — the difference between "it compiles" and "it works", and what CI runs. It does that **twice per app, in `ReleaseSafe` and in `ReleaseFast`**, because a `std.debug.assert` guard is compiled out of the latter and a fail-open one is therefore invisible in safe modes. Also refuses a directory nobody declared, a declaration whose directory is gone, an app the collection README does not list, and an app with no executable `smoke.sh`. |
| `check-ci-cache-keys.sh` | Refuses a CI config where one lane's cache restore-key prefix can match another lane's entry. `restore-keys` matches by prefix, so distinct names are not enough — they must not be prefixes of each other. An amd64 lane restored an aarch64 tree this way and recompiled everything, green throughout. |
| `ci-environment.sh` | Installs the peers a hosted runner lacks. Run by BOTH CI jobs, because two copies of an install list drift and one script cannot. Not for a development machine: it uses `sudo` and pins system packages. **Takes a ROLE since 2026-09-06** — `tests` (default), `interop`, or `all` — and the split is the whole point of the file now. `tests` is what a lane that RUNS tests or examples needs: the userns and ping sysctls, the yaml-test-suite corpus, opcua's open62541 container and its asyncua venv, imap's pymap venv, and the pinned `websockets` the websocket EXAMPLE judges itself against. `interop` is what only `zig build interop-<m>` reaches: a C compiler + wolfSSL headers (dtls) and `jinja2==3.1.6`/sympy/brotli/protobuf plus a grpcio venv (the five Python-driven ones). ⛔ **The `interop` half is not deletable.** Those six modules replay committed transcripts and pass on a host with no compiler and no Python — but a transcript nobody can RE-TAKE is a frozen anchor, extendable and correctable by nobody. `dnssec` lost one exactly that way and `gen-dnssec-oracle.sh` had to be written from nothing to get it back. |
| `check-citations.py` | Verifies the RFC/standard citations in module docs point at something real. **Manual, not a gate:** measured on `dns`, it pairs an `RFC NNNN` mention with any nearby quoted string, so a quoted SPEC.md heading reports as a mismatch. Useful with triage, not as a red/green. 2026-09-06: 933 citations, 404 VERIFIED / 487 MISMATCH / 42 UNFETCHABLE — and two of the samples read by hand are genuinely wrong quotes, not extraction noise. See "Standards citations" below. |
| `check-uapi-consts.py` | Diffs the kernel UAPI constants modules hardcode against the headers they came from. Driven by `zig build check-uapi`, which the gate runs; it SKIPS (never fails) on a host without python3 or kernel headers. Currently 689 matched / 0 mismatched across five modules, with 263 constants unresolved — it says so rather than counting them as passes. |
| `gen-qr-decode-vectors.py` | External DECODE oracle for `qr`: **segno** (BSD-3, independently authored) produces the module grid and this module's decoder must read segno's own bytes back out. **Keep it.** `modules/qr/SPEC.md` named this gap in its own words — the committed golden set anchors the ENCODER, and only 10 of 40 versions, so the decoder (the untrusted-input half) had no external anchor at all until 2026-09-04. Emits all 960 vectors; 160 stratified ones are committed. Needs `segno`, so it is not a gate step. |
| `gen-dnssec-oracle.sh` | Re-takes `modules/dnssec`'s independent-oracle anchor: builds a zone, signs it once per implemented algorithm with **ldns** (not this repo), and has `ldns-verify-zone` check each result. **Keep it.** The committed `oracle_vectors.zig` credited two different scratchpad paths, neither of which is in the repo — the module's strongest anchor had no re-takeable recipe at all. It deliberately does NOT reproduce the committed vectors byte for byte (those keys are gone and DNSSEC signatures are not deterministic); it re-establishes the property they attest. Needs `ldns`, so it is not a gate step. |
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
| Before cutting a tag | `scripts/test.sh interop` | Re-takes the six interop anchors against REAL peers — see below. Needs `scripts/ci-environment.sh interop`; ~35 s warm |

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

## A module is standalone Zig — and where the foreign half lives

Owner's rule, 2026-09-06: a module is standalone Zig with no external dependency, and an
anchor against a foreign implementation is an EXTERNAL test that belongs in
`modules/<m>/tools/`, not inside the module. Six modules were separated from their interop
programs that day. Two things in this harness stand on that rule.

**`zig build check-module-purity`** (in the fast group, ~1.4 s, same order as
`check-copyleft` beside it) stops the shape coming back. It refuses a file under
`modules/<m>/src/` that starts a child process **and** either names a foreign toolchain
(`cc`, `python3`, `node`, `make`, …) or `@embedFile`s foreign SOURCE.

⭐ **The spawn is the condition, not the file extension**, and that is the entire design.
Three things in the tree today would be flagged by the obvious "fail any `.c`/`.js`/`.py`
under `src/`" rule and every one of them is innocent: `json5`'s six `.js` files, whose whole
content is `080` or `[\n ,null\n]` and whose extension IS the expected verdict ("valid
JavaScript, invalid JSON5"); `ebpf`'s seven `.bpf.c` files, the committed provenance that
makes its `.bpf.o` fixtures re-derivable, compiled by a human and never by the module; and
`qr`'s `reference.py`, a segno driver whose golden test's own title ends "no python
required". None of their modules spawns anything, so none of them trips the gate and none of
them needs an exemption entry. A module still on the wrong side states it in one line in its
own SPEC/README — `**Foreign toolchain:** MIGRATION-OWED via <path> — <argument>`, the
shape `**Fuzz exemption:**` uses — there is no spelling that approves one, and the line
expires by itself because the gate fails on a declaration whose file has stopped spawning.
`opcua` is the only module carrying it: `src/server_interop.zig` holds a ~190-line Python
`asyncua` driver as an inline `\\` literal and runs it with `python3 -c`.

**`scripts/test.sh interop`** is the other half, and it exists because nothing was running
one. `test-dtls` replays a wolfSSL transcript and passes 268/268 on a box with no compiler;
`test-grpc` went from 13 silent skips to 119/119 with no Python. What replay cannot do is
notice that something NEW we send provokes a different reaction, or that the peer moved —
only running the peer does. This command runs `check-interop` (compiles all six with no peer,
so a program that stopped building is reported as that) and then each `interop-<m>`. It
**verifies against the committed transcript rather than rewriting it**, so it leaves a clean
tree and goes red on divergence; re-blessing is a flag a human passes. Pre-release, not
per-commit: it is a lane of the CI matrix, which runs on tags and dispatch only.

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

`test.sh` therefore also points `TMPDIR` at `.zig-cache/gate-tmp` (on disk)
whenever `TMPDIR` is unset or names a **tmpfs/ramfs**, so step logs never occupy
RAM at all. The test is the filesystem, not the path: it once compared `TMPDIR`
to the literal `/tmp`, which misses `/tmp/<anything>/<session>` — the shape a
tool that gives each session its own scratch directory produces. Set `TMPDIR`
to a disk-backed directory to override.

A cap bounds the run; it cannot bound the machine. Measured 2026-08-23: a full
run peaked at 4.5 GB against a 20 GB cap and the kernel still fired a **global**
oom-kill, because other processes had filled RAM. `test.sh` warns before
starting when under a quarter of memory is available; `ZIGLIBS_MEM_QUIET=1`
silences it.

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

**⛔ Nothing measured under valgrind may be a Debug build — this is a repo-wide
rule, not a ctgrind detail.** Zig 0.16 compiles Debug with the self-hosted
x86_64 backend (Debug is the only optimize mode where that backend is the
default), and valgrind's DWARF reader cannot parse the `.debug_line` it emits.
Measured 2026-09-08 on a ten-line program with **no inline asm and no
`std.valgrind` call at all**: `-fno-llvm` 35 159 `Badly formed extended line op`
warnings, `-fllvm` **0**. It is a property of the backend and not of the mode —
forced with `-fno-llvm` the release modes break identically (ReleaseSafe 48 395,
ReleaseFast 37 369) and are clean only because LLVM is their default.

What it costs a measurement, same harness and target, frames carrying
`(file:line)`: `ReleaseFast` 36/36 · `ReleaseSafe` 2054/2054 · `Debug`
**904/2130 (42.4 %)** — and of the Debug frames that do resolve, **51 of 60
carry the wrong line number** (checked against `llvm-symbolizer`; the file is
right 60 of 60). So a Debug run under valgrind does not merely lose attribution,
it reports attribution that is wrong, and a context whose pattern-bearing frames
all lost their line info lands in `unattr` and fails a row for a reason that has
nothing to do with the code. `chachapoly` carried such a row from 2026-09-02
(recorded KNOWN RED) until 2026-09-08, when the same expectation passed on the
same tree; it is gone now, and `chachapoly`'s `ReleaseSafe` row makes the same
point.

⚠ **Do not diagnose this by counting warnings on a quiet run.** Valgrind reads
line information LAZILY — only when it first has to symbolize a frame — so a
binary that reports no errors never opens the table and prints **0 warnings
however broken it is**. Force symbolization first (`-lc` plus a deliberately
leaked `std.c.malloc` and `--leak-check=full`), or the zero means nothing. Two
other readers are no help here either: binutils `addr2line` and `eu-addr2line`
cannot read Zig's tables at all, and `llvm-dwarfdump --verify --debug-line`
reports **0 errors** on a binary valgrind cannot parse — the table is not
invalid, valgrind's DWARF2-era reader just does not handle what the self-hosted
backend emits. `llvm-symbolizer` is the oracle that works.

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

**Whole-repo run, 2026-09-06: 933 citations — 404 VERIFIED, 487 MISMATCH, 42
UNFETCHABLE, 4.3 s warm.** Before the same day it reported **12189** of them in
49.9 s, because the walk skipped `.git`, `.zig-cache` and `zig-out` but not
`zig-pkg` — and this collection's `example-apps/` depend on this collection, so
the tree holds twelve complete extra copies of `modules/` (a root `zig-pkg`
with seven package hashes, plus one per app). 6887 of those claims — 56% — were
the same source lines read again out of a checkout nobody edits, and each was
fetched against as well.

Hand-checked spot samples from that run, so the MISMATCH column is not read as
pure noise: `modules/mls/src/group.zig:3017` attributes "Verify that the group's
protocol version and cipher suite are ones this client supports" to RFC 9420
§12.4.3.1's *first joiner bullet* — that bullet begins "Identify an entry in the
secrets array", and the quoted sentence is in no part of the RFC (the substance
is real but lives in §7.3, which §12.4.3.1 reaches only by reference);
`:3034` does the same for a "third tree-integrity bullet". `modules/jwe/src/root.zig:740`
quotes RFC 7518 §4.8.1.1 as "A minimum salt length of 8 octets MUST be used",
where the clause says "A Salt Input value containing 8 or more octets MUST be
used" — and the PBKDF2 salt is `UTF8(Alg) || 0x00 || Salt Input`, so the two
sentences do not bound the same quantity. On the other side,
`modules/spake2plus/src/root.zig:286` is a FALSE positive: its quote is verbatim,
but the RFC wraps `little-`/`endian` across a line and `norm()` does not rejoin
a hyphen at a line break. Measured: rejoining them clears exactly 3 of the 487.

## ⛔ Fuzzing does not happen in the standing gate, and the numbers say how much

Measured 2026-09-03, during the `xmlenc` drift re-audit, which found its length
bounds deletable with the suite green and traced it here.

`std.testing.fuzz(ctx, f, opts)` behaves differently depending on how the test
binary was built. Outside `--fuzz` mode — which is every ordinary `zig build
test-<m>`, every `scripts/test.sh` run and every CI job — Zig's test runner
(`lib/compiler/test_runner.zig`) runs the harness on `opts.corpus` and then on
**one** empty-string smoke input:

```zig
// When the unit test executable is not built in fuzz mode, only run the
// provided corpus.
for (options.corpus) |input| { … }
// In case there is no provided corpus, also use an empty string as a smoke test.
var smith: testing.Smith = .{ .in = "" };
```

So a harness declared as `std.testing.fuzz({}, f, .{})` — an EMPTY corpus —
executes **exactly one input** in the lane that runs. It is a compile check, not
coverage, and its test name asserts a property nothing checked.

**203 of the repo's 226 harnesses are declared that way.** The 23 that are not
pass a `.corpus`, and those entries do get replayed as ordinary regression inputs
on every run — which is what a corpus is for and why it is worth adding.

Three things compound it, and none of them is a bug in isolation:

- `zig build check-fuzz` verifies a module **has** a harness. It cannot know
  whether the harness ever explores anything, and its message ("obligated,
  covered, exempt") reads as coverage.
- `scripts/test.sh` runs `check-fuzz` and never `fuzz-sweep.sh`.
- `.github/workflows/ci.yml` contains no fuzz step at all.
- ⚠ **`zig build --fuzz` compiles in the Release modes and NOT in Debug.**
  Measured on Zig 0.16.0, same module, one variable:

  ```
  $ zig build test-lnwire                --fuzz=20 ; echo $?    # Debug
  1
  $ zig build test-lnwire --release=safe --fuzz=20 ; echo $?
  0
  $ zig build test-lnwire --release=fast --fuzz=20 ; echo $?
  0
  ```

  The Debug failure is inside std's own runner and has nothing to do with the
  module:

  ```
  lib/compiler/test_runner.zig:566:55: error: expected type
      '*const debug.StackTrace', found '*builtin.StackTrace'
  ```

  So **coverage-guided fuzzing IS available — add `--release=safe`.** That
  matters, because it is the only way to answer "does this harness reach
  anything", which `fuzz-sweep.sh` cannot: it reports `clean` whether the
  harness explored the decoder or bounced off the first byte. Five harnesses
  found in three batches of the 2026-09 audit reached nothing at all.

  ⚠⚠ **The history of this bullet is itself the lesson.** It first said
  `--fuzz` "does not compile on this toolchain … identically for every module
  tried", with no pasted failure. On 2026-09-03 that was overturned as "not
  reproducible" — on the strength of one `--release=safe` run that worked and
  one Debug run that was *killed at 110 s and assumed to be fuzzing*. It was
  not; a Debug `--fuzz` build fails, and the 110 s was spent compiling. **The
  correction repeated the original error in the opposite direction: a claim
  about a failure, recorded without observing the failure.** The original note
  was right about the mode it must have been written in, and wrong only in
  saying "every module". Paste the failure, name the mode, or record neither.
- ⛔ `fuzz-sweep.sh` is still the routine sweep, and it is still manual.

**What to do about it.** Two routes, and the choice is about how the shapes are
reached, not about effort:

1. **An ordinary deterministic test** for each refusal, written by hand. Best
   when the shape is easy to state directly — a blob one byte under a length
   floor, a ciphertext that is not a whole number of blocks. This is what
   `xmlenc` got on 2026-09-03, and it is strictly clearer than a corpus, because
   the test says which guard it is about and fails with that guard's name.
2. **A committed `.corpus`** on the harness. Best when the interesting input is
   awkward to reach any other way, or when you already have crash inputs from a
   sweep and want them replayed forever. The runner loop above is what replays
   them, on every build, with no `--fuzz` anywhere.

⚠ Steering a corpus entry needs `std.testing.Smith`'s consumption model, which is
fully deterministic and worth knowing before you try: `bytes(out)` copies a
prefix of the input and ZERO-FILLS the remainder, while `valueRangeAtMost` reads
**8 little-endian bytes** and falls back to the range's LOWER BOUND both when
fewer than 8 remain and when the value read is out of range. So a short or
careless corpus entry silently selects the first branch of every switch — which
looks like coverage and is not.

Reserve `fuzz-sweep.sh` (through `scripts/capped` — an uncapped sweep has taken
this host down) for actual search.