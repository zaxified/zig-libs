#!/usr/bin/env bash
# Test driver for zig-libs. `zig build test` runs every module in the
# collection — fine for CI, absurd in a change/build/test loop where you
# touched one module and are waiting on the rest. `changed` (the
# default) works out which modules a change can actually affect, using
# `zig build module-graph` (the authoritative dependency graph — this
# script never parses build.zig) plus the reverse-dependency closure of
# that set, and tests only those.
#
# Touching build.zig does NOT by itself mean running everything: the graph is
# compared against the last verified one, and a purely additive change (a new
# module) tests only what was added. See the graph-snapshot block below.
#
# Usage:
#   scripts/test.sh                 — same as `changed` with no BASE_REF
#   scripts/test.sh changed [REF]   — test what changed (vs REF, or the
#                                     working tree/index/untracked files)
#   scripts/test.sh all [ZIG_ARGS…] — every module; the pre-commit/CI gate.
#                                     Trailing args go to `zig build`, e.g.
#                                     `all -Doptimize=ReleaseFast` or
#                                     `all -Dstrict-debug`.
#   scripts/test.sh time            — serial per-module timing table
#
# Every runner starts with a capability check: silent when the host can do
# everything, otherwise it names each gap and prints the exact least-privileged
# command that closes it. The driver only PRINTS those commands — it never runs
# anything privileged or networked for you.
#
# See scripts/README.md for the long version of each subcommand.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/test-lib.sh"

# ── one cgroup around the WHOLE run ────────────────────────────────────────
#
# `step()` already puts each command in its own transient scope with a memory
# cap, which bounds any single runaway test. That is not enough, and the gap
# cost a desktop on 2026-08-22.
#
# Two reasons the per-step cap does not bound a run:
#
#   1. `--collect` destroys each scope when its step ends, and anything the
#      step left in tmpfs is REPARENTED to the (uncapped) user slice. So the
#      charges accumulate across steps while every individual step stays
#      politely under the limit.
#   2. `/tmp` is tmpfs on a typical desktop -- RAM, evictable only to swap --
#      and `step()` captures every command's stdout and stderr into `mktemp`
#      files there. A full run's logs are gigabytes of it.
#
# What that looked like: 15.7 GB of shmem, 30 of 31 GB anonymous,
# `all_unreclaimable? yes` with 511 MB of swap, and the kernel's global OOM
# killer taking the editor -- which it picks by `oom_score_adj`, so the thing
# that dies is never the thing that filled memory.
#
# So the run re-execs itself inside ONE scope before doing anything. Inside it
# the per-step wrapper is skipped (a transient scope cannot spawn another),
# which is correct: one cap over the sum is what was missing, not a tighter one
# per part. `ZIGLIBS_RUN_MEM_MAX=off` opts out; the per-step limit keeps its own
# `ZIGLIBS_MEM_MAX`, deliberately a separate name because the two mean
# different things.
if [[ -z "${_ZL_IN_RUN_SCOPE:-}" ]]; then
    _zl_run_max="${ZIGLIBS_RUN_MEM_MAX:-20G}"
    if [[ $_ZL_CAP_OK -eq 1 && "$_zl_run_max" != "off" ]]; then
        export _ZL_IN_RUN_SCOPE=1
        exec systemd-run --user --scope -q --collect \
            -p "MemoryMax=$_zl_run_max" -p MemorySwapMax=0 -- "$0" "$@"
    fi
fi

# Step logs off tmpfs. `mktemp` follows TMPDIR, and on a desktop the default is
# RAM. This is the other half of the fix above: capping the run stops the
# machine dying, and moving the logs stops the run dying of its own output.
#
# The test is the FILESYSTEM, not the path. This used to compare `TMPDIR` to
# the literal `/tmp`, which misses every other way to point at RAM -- and the
# common one is not exotic: a tool that gives each session its own scratch
# directory under `/tmp` (`TMPDIR=/tmp/<tool>-1000/<session>`) is still on
# tmpfs and would have sailed past a string compare.
# `findmnt -T` resolves a path that is not itself a mount point; `df` is the
# fallback where util-linux is absent. NOT `df -P --output=fstype`: those two
# options are mutually exclusive, so that spelling prints an error and an empty
# answer -- a check that cannot fire, which is the failure mode this whole file
# exists to avoid. Verified in both directions below.
_zl_on_ram() {
    local fs
    fs="$(findmnt -no FSTYPE -T "$1" 2>/dev/null)"
    [[ -z "$fs" ]] && fs="$(df --output=fstype "$1" 2>/dev/null | tail -1)"
    [[ "$fs" == tmpfs || "$fs" == ramfs ]]
}
if [[ -z "${TMPDIR:-}" ]] || _zl_on_ram "$TMPDIR"; then
    _zl_disk_tmp="$REPO_ROOT/.zig-cache/gate-tmp"
    mkdir -p "$_zl_disk_tmp"
    export TMPDIR="$_zl_disk_tmp"
fi

# A cgroup cap bounds THIS run; it cannot bound the machine. Measured here on
# 2026-08-23: a full run peaked at 4.5 GB against its own 20 GB limit and was
# never close to it, yet the kernel still fired a GLOBAL oom-kill
# (`constraint=CONSTRAINT_NONE`) the moment `zig` asked for a page, because a
# browser was already holding 17.6 GB of 31 and 5.7 GB more sat in tmpfs. The
# victim is chosen by `oom_score_adj`, so it was not the gate that died.
#
# So: say so BEFORE the run, while the choice to wait or close something is
# still cheap. This warns and continues -- refusing to start would be worse,
# since the number is a snapshot and a full run is often exactly what someone
# wants on a loaded machine. `ZIGLIBS_MEM_QUIET=1` silences it.
_zl_warn_if_memory_tight() {
    [[ -n "${ZIGLIBS_MEM_QUIET:-}" ]] && return 0
    local avail_kb total_kb avail_g total_g
    avail_kb="$(awk '/^MemAvailable:/{print $2; exit}' /proc/meminfo 2>/dev/null)" || return 0
    total_kb="$(awk '/^MemTotal:/{print $2; exit}' /proc/meminfo 2>/dev/null)" || return 0
    [[ -z "$avail_kb" || -z "$total_kb" ]] && return 0
    avail_g=$((avail_kb / 1048576))
    total_g=$((total_kb / 1048576))
    # Under a quarter of RAM available is where today's kill happened.
    if (( avail_kb * 4 < total_kb )); then
        echo "  ! only ${avail_g} GB of ${total_g} GB available before this run starts." >&2
        echo "    The run is capped, but a cap cannot stop a GLOBAL oom-kill caused by" >&2
        echo "    what else is resident -- and the kernel picks its victim by" >&2
        echo "    oom_score_adj, so the process that dies will not be this one." >&2
        echo "    Check what is holding memory, or set ZIGLIBS_MEM_QUIET=1." >&2
    fi
}
_zl_warn_if_memory_tight

export ZIGLIBS_TEST_T0="$(_now)"

cd "$REPO_ROOT"

# NETNS_MODULES — the set of modules run under `unshare -rn` — is defined in
# test-lib.sh, because scripts/dark-tests.sh needs the identical split and a
# second copy would rot. Why each member is in it, and why `icmp`/`traceroute`
# are deliberately NOT:
#
# Verified empirically (2026-07-28), not just grepped:
#   - `zig build test-netlink` on a bare dev host FAILS outright (a
#     bridge/FDB/VLAN round-trip test, not a clean skip) because this host
#     has enough ambient netlink access to attempt real writes that then
#     collide with host state; wrapped in `unshare -rn` it is clean and
#     green — so wrapping isn't just "nice to have more coverage", it's
#     required for these modules to be reliably green at all outside CI.
#   - genetlink/nl80211/devlink's own gated tests are unprivileged reads or
#     hardware-presence checks (no wiphy / no devlink instance) — unshare
#     doesn't fabricate hardware, so it neither helps nor hurts them; kept
#     in the same bucket for uniformity since it's harmless.
#   - icmp and traceroute were tested too and deliberately EXCLUDED: a
#     fresh `unshare -rn` namespace starts with `lo` DOWN, which turns
#     their loopback ping/traceroute tests from PASS into a hard FAIL.
#     Wrapping them would make things worse, not better — rawsock brings
#     `lo` up itself (see rawsock/src/root.zig), these two do not.
#   - tc's RTM_NEWACTION checks CAP_NET_ADMIN against the *initial* user
#     namespace, so `unshare -rn` is not enough for that one path; tc's own
#     source documents this (grep `initial user namespace`). Nothing this
#     script can do about that short of real root; the capability check
#     prints the one-off `sudo unshare -n zig build test-tc` for it.

# ── module-graph plumbing ────────────────────────────────────────────────

G_NAMES=()
G_HEAVY=()
G_DEPS=()
G_GROUP=()
G_TSV=""

# Populates G_NAMES/G_HEAVY/G_DEPS from `zig build module-graph`. Never
# silently proceeds with an empty/partial graph — a build failure here
# would otherwise look identical to "nothing changed", the exact silent
# no-op class of bug this driver must not have.
graph_load() {
    G_NAMES=(); G_HEAVY=(); G_DEPS=(); G_GROUP=()
    local tsv
    if ! tsv="$(zig build module-graph 2>&1)"; then
        echo "test.sh: 'zig build module-graph' failed — refusing to guess the module set:" >&2
        echo "$tsv" >&2
        exit 1
    fi
    G_TSV="$tsv"
    local name heavy deps live ct group
    # ⚠ Split on `|`, not on the tab. A tab is IFS WHITESPACE to bash, so two in
    # a row -- the empty deps column of every module with no siblings -- collapse
    # into one and every later column shifts left: those modules read their
    # `live` marker as deps and their group as `ct`. Module names never contain
    # `|`, so the substitution is lossless.
    while IFS='|' read -r name heavy deps live ct group; do
        [[ -z "$name" ]] && continue
        G_NAMES+=("$name")
        G_HEAVY+=("$heavy")
        G_DEPS+=("$deps")
        G_GROUP+=("$group")
    done <<< "${tsv//$'\t'/|}"
    if [[ ${#G_NAMES[@]} -eq 0 ]]; then
        echo "test.sh: 'zig build module-graph' produced zero modules — refusing to pass vacuously" >&2
        exit 1
    fi
}

# The modules this lane covers: all of them, or -- when the lane passes
# `-Dgroup=<lib>` (repeatable; CI splits a lane across runners with it) --
# those whose primary lib is listed. build.zig narrows `zig build`,
# `check-pubfn-reach` and `check-examples` by the same option and the same
# rule (module-graph column 6), so the tests run here and the compile above
# them cover one set. An empty selection is refused: a lane that tests
# nothing must not pass.
lane_modules() {
    local -a want=() only=()
    local a
    for a in "${EXTRA_ZIG_ARGS[@]}"; do
        [[ "$a" == -Dgroup=* ]] && want+=("${a#-Dgroup=}")
        [[ "$a" == -Dmodule=* ]] && only+=("${a#-Dmodule=}")
    done
    local -a out=()
    local i
    for (( i = 0; i < ${#G_NAMES[@]}; i++ )); do
        if [[ ${#want[@]} -gt 0 ]]; then
            case " ${want[*]} " in *" ${G_GROUP[$i]} "*) ;; *) continue ;; esac
        fi
        if [[ ${#only[@]} -gt 0 ]]; then
            case " ${only[*]} " in *" ${G_NAMES[$i]} "*) ;; *) continue ;; esac
        fi
        out+=("${G_NAMES[$i]}")
    done
    if [[ ${#out[@]} -eq 0 ]]; then
        echo "test.sh: -Dgroup=${want[*]:-} -Dmodule=${only[*]:-} selects no module -- refusing to pass vacuously" >&2
        exit 1
    fi
    printf '%s' "${out[*]}"
}

# ── stamps ──────────────────────────────────────────────────────────────────
# A stamp says: this module, at this fingerprint, passed this lane. A module
# whose current fingerprint (`zig build module-fingerprints`, see build.zig for
# what goes into it) has a stamp for the lane being run is skipped -- it has
# already been proven, and nothing that could change the answer has moved.
#
#   <module> TAB <lane key> TAB <fingerprint> TAB <UTC time>
#
# The lane key is the command, its zig arguments minus the ones that only
# SELECT modules (-Dgroup, -Dmodule), and the machine architecture. The file is
# `.stamps.local.tsv` by default (gitignored, outside `.zig-cache`, which gets
# deleted by hand); CI points ZIGLIBS_STAMPS elsewhere and carries the file
# between runs as an artifact. Stamps are written only at the END of a command,
# which `step` reaches only when every step passed -- a red run writes none.
# ZIGLIBS_IGNORE_STAMPS=1 runs everything as if no stamp existed.
STAMPS_FILE="${ZIGLIBS_STAMPS:-.stamps.local.tsv}"
declare -A FP=()

fp_load() {
    [[ ${#FP[@]} -gt 0 ]] && return 0
    local tsv n f
    if ! tsv="$(zig build module-fingerprints 2>&1)"; then
        echo "test.sh: 'zig build module-fingerprints' failed -- refusing to guess what is proven:" >&2
        echo "$tsv" >&2
        exit 1
    fi
    while IFS=$'\t' read -r n f; do
        [[ -n "$n" && -n "$f" ]] && FP[$n]="$f"
    done <<< "$tsv"
    if [[ ${#FP[@]} -eq 0 ]]; then
        echo "test.sh: module-fingerprints produced nothing -- refusing to pass vacuously" >&2
        exit 1
    fi
}

stamps_lane_key() {
    local key="$1" a
    for a in "${EXTRA_ZIG_ARGS[@]}"; do
        case "$a" in -Dgroup=* | -Dmodule=*) ;; *) key="$key $a" ;; esac
    done
    printf '%s %s' "$key" "$(uname -m)"
}

# Prints the modules of $1 that have no stamp for lane $2 at their current
# fingerprint.
stamps_pending() {
    local mods="$1" lane="$2" m
    fp_load
    if [[ "${ZIGLIBS_IGNORE_STAMPS:-0}" == 1 || ! -f "$STAMPS_FILE" ]]; then
        printf '%s' "$mods"
        return 0
    fi
    declare -A have=()
    local sm sl sf _t
    while IFS=$'\t' read -r sm sl sf _t; do
        [[ "$sl" == "$lane" ]] && have[$sm]="$sf"
    done < "$STAMPS_FILE"
    local -a out=()
    for m in $mods; do
        [[ -n "${FP[$m]:-}" && "${have[$m]:-}" == "${FP[$m]}" ]] || out+=("$m")
    done
    printf '%s' "${out[*]}"
}

# Records a green stamp for every module of $1 in lane $2, replacing that
# module's previous stamp in the lane.
stamps_record() {
    local mods="$1" lane="$2" m now tmp
    [[ -z "${mods// /}" ]] && return 0
    fp_load
    now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    tmp="$(mktemp "${STAMPS_FILE}.XXXXXX")"
    declare -A drop=()
    for m in $mods; do drop[$m]=1; done
    if [[ -f "$STAMPS_FILE" ]]; then
        local sm sl rest
        while IFS=$'\t' read -r sm sl rest; do
            [[ "$sl" == "$lane" && -n "${drop[$sm]:-}" ]] && continue
            printf '%s\t%s\t%s\n' "$sm" "$sl" "$rest"
        done < "$STAMPS_FILE" > "$tmp"
    fi
    for m in $mods; do
        printf '%s\t%s\t%s\t%s\n' "$m" "$lane" "${FP[$m]}" "$now" >> "$tmp"
    done
    LC_ALL=C sort -o "$tmp" "$tmp"
    mv "$tmp" "$STAMPS_FILE"
    echo "stamps: $(wc -w <<< "$mods") module(s) recorded green for '$lane' in $STAMPS_FILE"
}

# The selecting arguments the lane was given (-Dgroup, -Dmodule) into SEL_ARGS,
# plus `-Dmodule=` for each module of $1 when it is a strict subset of the
# lane's modules $2 -- the whole lane needs no further narrowing.
SEL_ARGS=()
stamps_narrow() {
    SEL_ARGS=()
    local a m
    for a in "${EXTRA_ZIG_ARGS[@]}"; do
        case "$a" in -Dgroup=* | -Dmodule=*) SEL_ARGS+=("$a") ;; esac
    done
    [[ "$(wc -w <<< "$1")" -eq "$(wc -w <<< "$2")" ]] && return 0
    for m in $1; do SEL_ARGS+=("-Dmodule=$m"); done
}

# The harness itself changed (this script, test-lib.sh, capped, or a CI lane).
#
# There is no dependency edge to follow here: what changed is the mechanism that
# decides the narrow set, so it cannot vouch for its own narrowing. The honest
# answer is not to silently pick a smaller set and call it verified — it is to
# run what actually exercises the harness's own branches, and to say plainly
# that this is not the gate.
#
# `run_modules` distinguishes exactly two classes, plain and netns-wrapped, so
# one live module from each covers both paths end to end (select -> build ->
# run -> report) in seconds. Heavy modules are NOT included: "heavy" is a
# build.zig optimisation choice, invisible to this script, and one of them costs
# minutes. Picked from the graph rather than hardcoded, so the set cannot rot.
harness_smoke() {
    local plain="" netns="" n
    for n in "${G_NAMES[@]}"; do
        case " $NETNS_MODULES " in
            *" $n "*) [[ -z "$netns" ]] && netns="$n" ;;
            *) [[ -z "$plain" ]] && plain="$n" ;;
        esac
        [[ -n "$plain" && -n "$netns" ]] && break
    done

    echo "changed: the harness or a CI lane definition changed."
    echo "  The thing that narrows the module set is the thing that moved, so it cannot"
    echo "  narrow itself. Running a smoke set that exercises the driver's own branches"
    echo "  instead — this is NOT the gate:"
    echo "      scripts/test.sh all      <- run this before committing a harness change"
    step "fmt check" zig fmt --check build.zig build.zig.zon modules
    # The commit-time formatting hook is only as good as the last edit to it; a
    # hook that always exits 0 looks exactly like "nothing was ever unformatted".
    # ~0.2 s in a throwaway repo. See scripts/hooks/test-pre-commit.sh.
    step "hook self-test" ./scripts/hooks/test-pre-commit.sh
    step "tag.sh self-test" ./scripts/test-tag.sh
    step "check-ci-cache-keys" ./scripts/check-ci-cache-keys.sh
    step "check-scripts-doc" zig build check-scripts-doc
    step "check-package" zig build check-package
    step "check-catalog" zig build check-catalog

    # The root NOTICE stopped listing modules on 2026-09-06: a module's
    # third-party obligation is discharged in the module's own NOTICE, and the
    # root file answers one question only -- is the library as a whole still
    # plain MIT. This is what makes that answer checkable. It refuses a shipped
    # file that GRANTS ITSELF under a copyleft licence (an SPDX expression
    # naming GPL/AGPL/LGPL/EUPL/CeCILL/SSPL/OSL, or an FSF grant paragraph),
    # which is why `ebpf`'s `_license = "GPL"` -- a BPF verifier ABI value, not
    # a copyright notice -- does not trip it. Copyleft in shipped code is a
    # defect to be removed, not a paperwork item.
    step "check-copyleft" zig build check-copyleft

    # The teeth on the owner's rule of 2026-09-06 -- a module is standalone Zig
    # with no external dependency, and an anchor against a foreign
    # implementation is an EXTERNAL test that belongs in `modules/<m>/tools/`.
    # Six modules were separated from their interop programs that day; nothing
    # stopped the seventh being written the old way tomorrow. It refuses a file
    # under `modules/<m>/src/` that starts a child process AND either names a
    # foreign toolchain (`cc`, `python3`, `node`, `make`, ...) or `@embedFile`s
    # foreign SOURCE. The spawn is the condition, which is why json5's six `.js`
    # fixtures, ebpf's `.bpf.c` provenance and qr's `reference.py` -- none of
    # which anything in their own file can run -- do not trip it. ~1.4 s, the
    # same order as check-copyleft beside it.
    step "check-module-purity" zig build check-module-purity
    step "check-uapi" zig build check-uapi
    step "check-changelog" zig build check-changelog

    # `check-changelog` above proves the file EXISTS and is well formed; it reads
    # the tree, never a diff, so it cannot see that a module's parser was
    # rewritten while its changelog last moved six weeks ago. This one reads the
    # diff. Replayed over the last 120 commits it found public declarations that
    # reached no changelog at any later point either -- `http.setHeaderStatic`,
    # `cors.applyPreflight`, `ssh.max_packets_per_direction`. The `changed` lane
    # instance is the one CI reaches with a real base ref; the other two are
    # no-ops on a clean checkout.
    step "check-changelog-entry" ./scripts/check-changelog-entry.py ${base_ref:+"$base_ref"}
    step "check-testonly" zig build check-testonly
    step "check-ctgrind" zig build check-ctgrind
    step "check-fuzz" zig build check-fuzz
    step "check-global-alloc" zig build check-global-alloc
    step "check-portable" zig build check-portable
    step "check-portable-table" zig build check-portable-table
    step "check-libs-table" zig build check-libs-table
    step "check-catalog-table" zig build check-catalog-table
    # The class no other gate can see: Zig analyses a function body only when
    # something references it, so a `pub fn` no test reaches can be outright
    # non-compiling and still ship green. Measured 2026-08-21: 403 of 9626
    # public functions are unreachable from any test, across 106 modules, 90 of
    # them on a module's own published `root.zig` surface. Demonstrated by
    # mutation the same day -- a deliberate type error in an unreachable
    # `nftables` function compiled, linked and ran green under `test-nftables`,
    # and only this step went red on it.
    step "check-pubfn-reach" zig build check-pubfn-reach
    # The one class no test here can cover: is the PUBLISHED API sufficient to
    # do the job? Every test lives in the file it tests, so it reads private
    # declarations and its build carries `test_deps` a consumer never gets.
    # Proven on l2disco 2026-08-21: dropping `pub` from a type its API needs
    # left both `test-l2disco` and `check-pubfn-reach` green, and only this red.
    step "check-examples" zig build check-examples
    # ~30s when modules/http/src/Client.zig (or anything it pulls in) changed
    # content, near-instant otherwise (Zig's own cache). See the script's
    # header for what it checks and why one target, not two.
    step "check-http-sizeprobe" ./scripts/check-http-sizeprobe.sh
    # falcon's constant-time property is invisible to every value test (the
    # integer emulation is bit-identical to hardware FP), and falcon is not on
    # the ctgrind gate. This disassembly check is the only thing that fails when
    # the emulation is bypassed. See the script header.
    step "check-fp-freedom" ./scripts/check-fp-freedom.sh
    step "check-ct-compare" ./scripts/check-ct-compare.py
    step "check-skip-as-pass" ./scripts/check-skip-as-pass.py

    # `zig build check-fuzz` proves a harness EXISTS; this proves it READS its
    # input. A `Smith` ranged draw returns the range MINIMUM unless the eight
    # bytes it reads as a little-endian u64 already lie inside the range, so a
    # harness that opens with one -- or that slices its drawn bytes to a length
    # that came from one -- replays every corpus seed, and every crash `--fuzz`
    # minimises into a seed, as the same fixed input. 416 of 474 targets did at
    # landing. `--advisory` printed that burn-down without failing anything --
    # but a gate that never fails protects nothing, and the burn-down is being
    # done a module at a time over many sessions, so a module fixed in week one
    # could regress in week three with no signal at all. `--ratchet` compares
    # against `scripts/fuzz-reach-baseline.txt`, a ceiling PER MODULE: it fails
    # only where a module got worse, names the modules that have improved since
    # the file was written, and comes off entirely when the baseline is empty.
    # The ceiling is per module rather than one total on purpose -- a total lets
    # one module regress while another improves and still reads green.
    # It still FAILS on a malformed or stale exemption.
    step "check-fuzz-reach" ./scripts/check-fuzz-reach.py --ratchet

    # `run-examples` builds and runs each example in the LANE's optimize mode,
    # so in a ReleaseFast lane every `std.debug.assert` in one is compiled out
    # and the example prints its success lines having checked nothing. Three
    # examples compared against an external oracle that way and printed that it
    # agreed; breaking `sealedbox`'s PyNaCl constant left the old example
    # exiting 0 and still claiming a byte-exact match.
    step "check-example-assert" ./scripts/check-example-assert.py
    run_modules "$plain $netns"
    summary
}

_HAVE_UNSHARE=""
have_unshare() {
    if [[ -z "$_HAVE_UNSHARE" ]]; then
        if command -v unshare >/dev/null 2>&1 && unshare -rn true >/dev/null 2>&1; then
            _HAVE_UNSHARE=yes
        else
            _HAVE_UNSHARE=no
        fi
    fi
    [[ "$_HAVE_UNSHARE" == yes ]]
}

# Extra `zig build` arguments, taken from the subcommand's trailing CLI args
# (e.g. `scripts/test.sh all -Doptimize=ReleaseFast`, or `-Dstrict-debug` to
# force real Debug for the compute-heavy modules). An array, so an argument
# containing spaces stays one argument.
EXTRA_ZIG_ARGS=()

# run_modules "mod1 mod2 ..." — partitions the set into NETNS_MODULES vs the
# rest and invokes each partition as ONE `zig build test-a test-b ...`
# command (not a loop of 1-module invocations!) so zig's own step
# parallelism is preserved; only the netns partition is wrapped in
# `unshare -rn`, and only when it's actually available.
#
# `--summary all` is passed unconditionally and the output is kept, because the
# dark-test check below reads it. See `dark_check`.
# ⭐ PER-TEST DEADLINE. The one thing that turns a hang into a finding.
#
# On 2026-08-15 the tag matrix died at GitHub's six-hour job limit, and the
# cause was not the size of the collection: in EVERY lane a single module —
# `ssh` — was the only process still alive, for 23 to 64 minutes, while the
# other 214 finished in one to eight. Nothing in the run could say which TEST
# inside it was stuck, so the lane simply burned to the wall and was cancelled,
# taking every other lane's verdict with it. The same tests pass locally in 4 s.
#
# `zig build --test-timeout` is per-TEST, not per-module, and it names the
# culprit exactly — `error: 'root.test.<name>' timed out after …` — then lets
# the remaining tests in that binary run. A hang becomes a red test with an
# address instead of a wall-clock mystery.
#
# ⭐ THREE MINUTES IS A DESIGN RULE, NOT A SAFETY MARGIN. A single unit test
# that needs longer than this is not a test that deserves a bigger budget — it
# is a test that has to be restructured, and tripping the deadline is how that
# gets noticed. Owner's call, 2026-08-15. Do not raise it to make a red test
# green; that inverts what it is for.
#
# The margin is real all the same. Measured across the sixteen heaviest modules
# under `-Dstrict-debug`, the slowest lane, exactly four single tests exceed a
# minute and none reaches seventy seconds: dkg's end-to-end anchor, p256's
# differential-vs-std, its comb oracle, and group's differential. Nothing else
# in 1279 tests comes close. Nor is CI slower where it matters — the 2026-08-15
# strict-debug lane had `p256` at 119 s of module time where this host took
# 182 s — so the same headroom holds there.
#
# ⛔ NOT a substitute for a test that cannot hang. It is the backstop that makes
# the hang findable; the test still has to be fixed.
TEST_TIMEOUT="${TEST_TIMEOUT:-3m}"

# RUN the examples of the given modules, ONCE, in this lane's optimize mode.
# `check-examples` only compiles them, and compiling cannot see the class an
# example exists to catch -- a dangling slice, a leak, a wrong-tag union read;
# one sweep on 2026-08-23 found all three plus twelve examples that had never
# run at all.
run_examples_for() {
    local -a run_targets=()
    local m
    for m in $1; do
        [[ -f "modules/$m/example/main.zig" ]] && run_targets+=("run-example-$m")
    done
    [[ ${#run_targets[@]} -eq 0 ]] && return 0
    ZL_STEP_STDERR_IS_OUTPUT=1 step "run-examples (${#run_targets[@]} modules)" \
        zig build "${run_targets[@]}" "${EXTRA_ZIG_ARGS[@]}"
}

ZL_RUN_EXAMPLES=1

run_modules() {
    local mods="$1"
    [[ -z "${mods// /}" ]] && return 0

    local -a rest=() netns=() live=()
    local m
    for m in $mods; do
        case " $NETNS_MODULES " in
            *" $m "*) netns+=("$m"); continue ;;
        esac
        case " $(live_modules) " in
            *" $m "*) live+=("$m") ;;
            *) rest+=("$m") ;;
        esac
    done

    _ZL_KEEP_OUT="$(mktemp)"

    if [[ ${#rest[@]} -gt 0 ]]; then
        local -a targets=()
        for m in "${rest[@]}"; do targets+=("test-$m"); done
        step "build+test (${#rest[@]} modules)" zig build "${targets[@]}" --summary all --test-timeout "$TEST_TIMEOUT" "${EXTRA_ZIG_ARGS[@]}"
    fi

    if [[ ${#netns[@]} -gt 0 ]]; then
        local -a targets=()
        for m in "${netns[@]}"; do targets+=("test-$m"); done
        if have_unshare; then
            step "netns build+test (${#netns[@]} modules, unshare -rn)" unshare -rn zig build "${targets[@]}" --summary all --test-timeout "$TEST_TIMEOUT" "${EXTRA_ZIG_ARGS[@]}"
        else
            echo "note: unshare -rn unavailable — running netns-gated modules plainly; their privileged tests will SKIP" >&2
            step "netns build+test (${#netns[@]} modules, NO unshare)" zig build "${targets[@]}" --summary all --test-timeout "$TEST_TIMEOUT" "${EXTRA_ZIG_ARGS[@]}"
        fi
    fi

    # ⭐ LAST, AND GENUINELY ONE AT A TIME — one `zig build` per module. These
    # talk to a real peer with a clock on both ends; running them beside 215
    # other test binaries measures the scheduler rather than the interop. See
    # `live_modules` in test-lib.sh for the full reasoning, including what this
    # deliberately stops covering.
    #
    # ⚠⚠ `-j1` DID NOT DO THIS, and the step carried the word "serial" in its
    # own label while not delivering it. Measured 2026-08-15 by sampling argv[0]
    # during the step: `dtls` and `ssh` ran together at t=4 s, `imap` and `opcua`
    # at t=10 s — two live peers at once, every run. The CI heartbeat had been
    # printing `in flight: ssh test 3s, dtls test 3s` for weeks and it read as a
    # sampling artefact.
    #
    # Whatever `-j1` bounds, it is not concurrent RUN steps. Four separate build
    # invocations cost four build-runner startups, about a second each, and are
    # the only spelling that cannot quietly stop being true. That matters here
    # more than the second: the whole point of this step is a claim about what
    # is NOT running at the same time.
    if [[ ${#live[@]} -gt 0 ]]; then
        local m
        for m in "${live[@]}"; do
            # ⚠ ONE LANE IS ALLOWED TO OPT OUT OF ONE PEER, and it is named in
            # the lane table rather than decided here. The case it exists for:
            # open62541 publishes no arm64 image, so `opcua`'s container runs
            # EMULATED on the arm64 lane — 565.8 s there against 56.9 s on
            # amd64 on 2026-08-24, for a suite that skips 7 of its tests on
            # that host anyway. "Our client interoperates with open62541" is
            # not an architecture-dependent claim and amd64 makes it in a
            # minute. Skipping is LOUD: the line below is the only place that
            # says a live peer did not run, so it says it every time.
            case " ${ZIGLIBS_SKIP_LIVE:-} " in
                *" $m "*)
                    echo "  live interop: $m SKIPPED on this lane (ZIGLIBS_SKIP_LIVE) — its peer runs elsewhere"
                    continue
                    ;;
            esac
            step "live interop: $m" zig build "test-$m" --summary all --test-timeout "$TEST_TIMEOUT" "${EXTRA_ZIG_ARGS[@]}"
        done
    fi

    # RUN the examples, ONCE, in this lane's optimize mode. `check-examples`
    # only compiles them, and compiling cannot see the class an example exists
    # to catch -- a dangling slice, a leak, a wrong-tag union read; one sweep on
    # 2026-08-23 found all three plus twelve examples that had never run at all.
    #
    # ⭐ EVERY GROUP, and that is why this sits down here rather than beside the
    # `rest` build above. It used to run only `rest`, and `cmd_all`/`cmd_changed`
    # covered the remaining 14 -- ten netns modules and the four live ones --
    # with a separate aggregate `zig build run-examples`. That aggregate carried
    # no `EXTRA_ZIG_ARGS`, so in a release lane it was a SECOND compile of all
    # 230 in Debug, and in the default lane a second RUN of every binary: the
    # green ReleaseSafe lane of 2026-08-24 paid 157.8 s for it beside this
    # step's 1749.5 s, and every scoped push paid ~68 s. Building the target
    # list from all three groups makes one step cover what two used to.
    #
    # Concurrency is unchanged: the aggregate step ran all 230 example binaries
    # in one `zig build` too. The live modules' SERIAL rule is about their
    # tests, which hold a timed conversation with a real peer -- not about their
    # examples, which ran alongside everything else here before and still do.
    # ⚠ NOT IN THE `modules` LANE. CI runs modules and examples as separate
    # jobs (see ci.yml's lane table), because the two share no compilation:
    # a module is compiled once for its test binary and once for its example,
    # and Zig's unit of caching is the whole compilation. `changed` and `all`
    # leave this on, since a developer wants one command.
    (( ZL_RUN_EXAMPLES )) && run_examples_for "$mods"

    local log="$_ZL_KEEP_OUT"
    _ZL_KEEP_OUT=""
    dark_check "$mods" "$log"
    summary_digest "$log"
    rm -f "$log"
}

# ⭐ Dark-test gate. A test that never runs has NO symptom: Zig collects tests
# only from the files it analyses, so a source reachable only through a
# `pub const x = @import("x.zig");` re-export contributes nothing to the test
# binary — no failure, no skip, no warning. `websocket` once shipped running
# ZERO of its 52 tests, and `ratelimit` reported `18/18 passed`, exit 0, with an
# entire new suite absent. Nothing else in this driver can see that.
#
# scripts/dark-tests.sh compares each module's declared test count against the
# `(N total)` field of its run-test line and requires EQUALITY. It is handed the
# `--summary all` output the run above already produced, so it costs a few
# milliseconds of awk rather than a second full suite run — Zig does not cache
# test run steps, so building the summary again would roughly double this gate.
# ⭐ The `--summary all` output, which used to be read once and deleted.
#
# `step` prints a step's stdout only when it FAILS, so on a green lane the
# per-module summary — the one place that carries a time and a skip count for
# every module — went to a temp file, was parsed by `dark_check` for its test
# counts, and was removed. The numbers existed, were read, and were thrown away.
#
# That cost a day. On 2026-08-15 the per-module timings needed to size the CI
# work had to be reconstructed from the heartbeat's process sampling, which by
# construction sees only what is running at the instant it looks and is blind to
# every module that starts and finishes between two ticks.
#
# ⚠ THE SKIP LINE MATTERS MORE THAN THE TIMES. A green lane reporting "148
# skipped" and a green lane reporting none look identical in every other part of
# this log, and the difference is whole modules' worth of coverage. Naming which
# modules skipped is the only way that stays visible — see the `skip = pass`
# family of findings for why a silent skip is the expensive kind.
summary_digest() {
    local log="$1" text full prog
    [[ -s "$log" ]] || return 0
    # One program, rendered twice — see `skip_cap` in the END block for why.
    prog='
        # "12s" / "786ms" / "1m3s" -> milliseconds. `ms` must be tested before
        # `m`, or every millisecond figure reads as minutes.
        function ms(t,   n) {
            if (t ~ /^[0-9.]+ms$/)              { sub(/ms$/, "", t); return t + 0 }
            if (t ~ /^[0-9.]+m[0-9.]+s$/)       { n = t; sub(/m.*/, "", n); sub(/^[0-9.]+m/, "", t); sub(/s$/, "", t); return n * 60000 + t * 1000 }
            if (t ~ /^[0-9.]+s$/)               { sub(/s$/, "", t); return t * 1000 }
            if (t ~ /^[0-9.]+m$/)               { sub(/m$/, "", t); return t * 60000 }
            return 0
        }
        # ⚠⚠ PRINT ZIG-S OWN TOKEN, NEVER A RE-RENDERING OF IT. `ms()` exists to
        # RANK, and nothing more. Zig reports anything past a minute coarsely:
        # a module that ran 177 s prints as `2m`, which this parsed to 120000 ms
        # and then re-rendered as "120s" — a number that looks measured, is 32 %
        # low, and is IDENTICAL for every run between 2m and 3m.
        #
        # That cost real work on 2026-08-15. Four lanes across three optimize
        # modes and two architectures all reported `opcua 120s`, and a figure
        # that stable across such different machines reads as a fixed wait
        # rather than as computation — which is exactly how it was read, against
        # a `deadline_ms = 120_000` that turned out to have nothing to do with
        # it. `threshold_ecdsa 60s` and `k256/p256 180s` were the same illusion:
        # `1m` and `3m`.
        #
        # So the display keeps the source token. `opcua 2m` is less precise and
        # cannot mislead; the ordering stays exact because it still sorts on the
        # parsed value. If a real duration is wanted, time the module — Zig will
        # not give a finer one here.
        function human(v) { return (v >= 1000) ? sprintf("%.0fs", v / 1000) : sprintf("%dms", v) }
        /^Build Summary:/ { totals = totals (totals ? "; " : "") substr($0, 16) }
        # "+- run test <name> <n> pass[, <n> skip][, <n> fail] (<n> total) <time> MaxRSS:.."
        /\+- run test / {
            name = $4
            for (i = 1; i <= NF; i++) if ($i ~ /^MaxRSS:/) { t = ms($(i - 1)); raw = $(i - 1); break }
            if (t > run[name]) { run[name] = t; runtxt[name] = raw }
            for (i = 1; i <= NF; i++) if ($i ~ /^skip/) skipped[name] += $(i - 1) + 0
        }
        /\+- compile test / { name = $4; for (i = 1; i <= NF; i++) if ($i ~ /^MaxRSS:/) { t = ms($(i - 1)); raw = $(i - 1); break }
                              if (t > comp[name]) { comp[name] = t; comptxt[name] = raw } }
        function top(arr, txt, label,   k, best, bn, n, out, i) {
            out = ""
            for (n = 0; n < 8; n++) {
                best = -1; bn = ""
                for (k in arr) if (arr[k] > best) { best = arr[k]; bn = k }
                if (bn == "" || best <= 0) break
                out = out (out ? " · " : "") bn " " (bn in txt ? txt[bn] : human(best))
                delete arr[bn]
            }
            if (out != "") printf("  %-16s %s\n", label, out)
        }
        END {
            if (totals != "") printf("  %-16s %s\n", "totals:", totals)
            top(run, runtxt, "slowest run:")
            top(comp, comptxt, "slowest compile:")
            # The COUNT is the finding; the worst dozen names are enough to
            # act on. Forty-one modules on one line wraps into unreadability,
            # which is how a number stops being read at all.
            #
            # ⚠ …in a TERMINAL. `skip_cap` exists because the summary page of a run
            # is a different medium with different readers, and on 2026-08-15 the
            # cap truncated exactly the information the arm64 lane exists to
            # produce: it reported "150 in 48 modules" with "+36 more", and the
            # tail was where the architecture-specific skips lived. Same digest,
            # rendered twice — capped for the log, whole for the page.
            total_skips = 0; shown = 0; out = ""
            for (k in skipped) total_skips += skipped[k]
            for (n = 0; skip_cap <= 0 || n < skip_cap; n++) {
                best = -1; bn = ""
                for (k in skipped) if (skipped[k] > best) { best = skipped[k]; bn = k }
                if (bn == "" || best <= 0) break
                out = out (out ? " · " : "") bn " " best
                delete skipped[bn]; shown++
            }
            more = 0
            for (k in skipped) if (skipped[k] > 0) more++
            if (total_skips > 0)
                printf("  %-16s %d in %d module(s) — %s%s\n", "skipped:", total_skips, shown + more, out,
                       more > 0 ? sprintf(" · +%d more", more) : "")
        }
    '
    text=$(awk -v skip_cap=12 "$prog" "$log") || return 0
    full=$(awk -v skip_cap=0 "$prog" "$log") || full="$text"
    [[ -n "$text" ]] || return 0
    printf '%s\n' "$text"

    # ⭐ …and onto the run's own page, so comparing lanes does not mean
    # downloading four logs. That is not a hypothetical chore: it is exactly how
    # every question on 2026-08-15 was answered, one `gh api …/logs` at a time.
    #
    # ⚠ The only CI-aware line in this driver, and deliberately the mildest
    # shape available: a WRITE to a path the environment names, not GitHub
    # markup emitted on stdout. Off CI the variable is unset and this is inert,
    # so a local run reads exactly as before.
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        printf '### %s\n\n```\n%s\n```\n\n' "${ZIGLIBS_LANE:-gate}" "${full:-$text}" >> "$GITHUB_STEP_SUMMARY"
    fi
}

dark_check() {
    local mods="$1" log="$2"

    # An empty log is NOT "nothing to check". run_modules only gets here after
    # at least one `step` returned successfully, and a successful
    # `zig build … --summary all` always prints a summary — so an empty log
    # means the plumbing broke, and passing vacuously on it would recreate the
    # exact silent-hole class this check exists to close.
    if [[ ! -s "$log" ]]; then
        echo "test.sh: the build produced no --summary output, so the dark-test check has nothing to read." >&2
        echo "  This is a harness failure, not a pass. Check step()'s _ZL_KEEP_OUT handling." >&2
        exit 1
    fi

    # `-Dtest-filter` compiles only the tests whose name matches, so `(N total)`
    # is deliberately smaller than the declared count and equality is the wrong
    # question. Say so rather than reporting a phantom violation.
    local a
    for a in ${EXTRA_ZIG_ARGS[@]+"${EXTRA_ZIG_ARGS[@]}"}; do
        case "$a" in
            -Dtest-filter*)
                echo "  dark-tests ... SKIPPED (-Dtest-filter compiles a subset on purpose)"
                return 0
                ;;
        esac
    done

    step "dark-tests" "$SCRIPT_DIR/dark-tests.sh" --summary "$log" $mods
}

# ── file -> module mapping ───────────────────────────────────────────────

# ⚠ A BASE REF THAT DOES NOT RESOLVE MUST NOT LOOK LIKE "NOTHING CHANGED".
# `git diff` against a bad ref fails, `2>/dev/null` hid it, the file list came
# back empty and the caller printed "nothing to test" and exited 0 — a gate
# that tested nothing and said so in language nobody reads as a failure. That
# is reachable in CI: a force-push, a shallow clone with no merge base, or
# `github.event.before` being all-zeros on a branch's first push. Returns
# non-zero instead, and the caller escalates to the full run.
changed_files() {
    local base_ref="$1"
    if [[ -n "$base_ref" ]]; then
        git rev-parse --verify --quiet "${base_ref}^{commit}" >/dev/null || return 1
        { git diff --name-only "$base_ref" -- || return 1
          git ls-files --others --exclude-standard
        } 2>/dev/null
    else
        { git diff --name-only
          git diff --cached --name-only
          git ls-files --others --exclude-standard
        } 2>/dev/null
    fi
}

# Runs before every runner. Silent when the host can do everything — a clean
# host must not print noise. Otherwise names each gap, what it costs in
# coverage, and the EXACT command that closes it.
#
# Every command below is the least-privileged one that works, and the driver
# only ever PRINTS them — it never runs anything privileged or networked on
# your behalf. In particular there is deliberately no "give this user
# passwordless sudo" advice: the one gap that genuinely needs root is closed by
# running a single command under sudo interactively, not by widening sudoers.
_CAP_CHECKED=""
capability_check() {
    # `changed` can delegate to `all`; report once per invocation, not twice.
    [[ -n "$_CAP_CHECKED" ]] && return 0
    _CAP_CHECKED=1

    local -a gaps=()
    # Two lists, because two different things go wrong. A GAP costs coverage:
    # the test that needed the peer skips and the lane still goes green, which
    # is why every gap prints what it costs. A BLOCKER fails the lane outright —
    # examples do not skip, they run their external judge or return an error —
    # so printing it under "gap(s) reducing coverage" would be a lie about a
    # lane that is going to be red either way.
    local -a blockers=()

    # The userns knob differs by distro. `sysctl -w` only lasts until reboot,
    # so what we print is the persistent drop-in form plus a reload — one line,
    # survives reboots, and is a system policy toggle rather than a privilege
    # grant to this user.
    local userns_key=""
    if [[ -e /proc/sys/kernel/apparmor_restrict_unprivileged_userns ]]; then
        userns_key='kernel.apparmor_restrict_unprivileged_userns=0' # Ubuntu 24.04+
    elif [[ -e /proc/sys/kernel/unprivileged_userns_clone ]]; then
        userns_key='kernel.unprivileged_userns_clone=1' # Debian-family
    fi
    local userns_persist="echo '$userns_key' | sudo tee /etc/sysctl.d/60-zig-libs-userns.conf >/dev/null && sudo sysctl --system >/dev/null"

    if ! { command -v unshare >/dev/null 2>&1 && unshare -rn true >/dev/null 2>&1; }; then
        local fix
        if [[ -n "$userns_key" ]]; then
            fix="$userns_persist"
        else
            fix='sudo apt install util-linux   # or your distro'"'"'s equivalent'
        fi
        gaps+=("unshare -rn unavailable|netlink writes in $NETNS_MODULES run unsandboxed — their privileged tests SKIP, so those modules are reported green while covering less|$fix")
    elif [[ -n "$userns_key" ]] && ! grep -rqs "${userns_key%%=*}" /etc/sysctl.d /etc/sysctl.conf; then
        # Works now, but only because someone ran `sysctl -w` by hand — it
        # reverts on reboot and the netns modules start failing again.
        gaps+=("userns enabled at runtime only (reverts on reboot)|nothing today; after a reboot the $NETNS_MODULES gap returns|$userns_persist")
    fi

    if ! command -v podman >/dev/null 2>&1; then
        gaps+=("podman missing|opcua live server-interop tests skip|sudo apt install podman")
    else
        if ! podman image exists docker.io/open62541/open62541:latest 2>/dev/null; then
            gaps+=("open62541 image not pulled|opcua live server-interop tests skip|podman pull docker.io/open62541/open62541:latest")
        else
            # ⚠ THE PEER'S ARCHITECTURE IS PART OF WHAT THIS COSTS, and nothing
            # said so until the arm64 lane of tag 2026-08-15. open62541 publishes
            # no aarch64 image, so `podman pull` there fetched the amd64 one,
            # printed one warning line, and ran it under emulation: opcua took
            # 540 s of a 724 s lane — 4.5x its amd64 figure — and skipped 7 tests.
            #
            # Deliberately NOT an automatic downgrade to "skip the container
            # tests on arm64". An emulated peer is still a real third-party
            # implementation, and interop correctness does not depend on the
            # peer's ISA; what it costs is wall-clock. That trade is the owner's
            # call, so this states the fact and the price instead of deciding.
            local img_arch host_arch
            img_arch="$(podman image inspect --format '{{.Architecture}}' \
                docker.io/open62541/open62541:latest 2>/dev/null)"
            host_arch="$(uname -m)"
            case "$host_arch" in x86_64) host_arch=amd64 ;; aarch64) host_arch=arm64 ;; esac
            if [[ -n "$img_arch" && "$img_arch" != "$host_arch" ]]; then
                gaps+=("open62541 image is $img_arch on a $host_arch host|opcua's container tests run EMULATED — they still exercise a real peer, but at several times the wall-clock (540 s vs 120 s, tag 2026-08-15)|nothing to run: open62541 publishes no $host_arch image. Decide whether the coverage is worth the minutes")
            fi
        fi
        # Rootless podman needs a userspace network backend. Nothing today
        # depends on container networking, but without one any container that
        # does will fail at startup rather than skip.
        if [[ "$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null)" == true ]] \
            && ! { command -v pasta >/dev/null 2>&1 || command -v slirp4netns >/dev/null 2>&1; }; then
            gaps+=("rootless podman has no network backend|nothing today; any future networked container fails to start|sudo apt install passt")
        fi
    fi

    # dtls's interop PROGRAM compiles a small wolfSSL peer with cc. Both are
    # needed to re-take the transcript; neither is needed to check it. Since
    # 2026-09-06 `test-dtls` replays `src/testdata/wolfssl_transcript.txt` and
    # passes 268/268 with no compiler and no wolfSSL on the box -- it used to
    # skip 14 tests there, silently, which is why this gap is still reported
    # rather than deleted: without these, the transcript can never be RE-TAKEN,
    # and a frozen anchor that nobody can refresh is how this repo lost one
    # before. wolfSSL is the DTLS 1.3 peer because OpenSSL 3.5.5 and GnuTLS
    # 3.8.12 have no DTLS 1.3 at all.
    if ! command -v cc >/dev/null 2>&1; then
        gaps+=("no C compiler (cc)|'zig build interop-dtls' cannot re-take the wolfSSL transcript (test-dtls replays it hermetically)|sudo apt install build-essential")
    elif [[ ! -e /usr/include/wolfssl/ssl.h ]]; then
        gaps+=("wolfSSL headers missing|'zig build interop-dtls' cannot re-take the wolfSSL transcript (test-dtls replays it hermetically)|sudo apt install libwolfssl-dev")
    fi

    # ssh's live interop needs BOTH directions of a real OpenSSH: `sshd` for
    # the tests that drive our client against a real server, and the `ssh`
    # client for the ones that drive a real client against our server.
    # `ssh-keygen` mints the ephemeral host and client keys for both.
    #
    # ⚠ This probe was missing until 2026-08-15, and its absence is exactly the
    # shape the report exists to prevent: `ssh` carries 46 `SkipZigTest` paths,
    # so on a host without these the module reports a green module having
    # proved nothing against a real peer, and nothing anywhere said so.
    local ssh_missing=()
    [[ -x /usr/sbin/sshd ]] || ssh_missing+=("sshd")
    command -v ssh >/dev/null 2>&1 || ssh_missing+=("ssh")
    command -v ssh-keygen >/dev/null 2>&1 || ssh_missing+=("ssh-keygen")
    if [[ ${#ssh_missing[@]} -gt 0 ]]; then
        gaps+=("OpenSSH missing: ${ssh_missing[*]}|ssh live interop tests skip — the only ones that prove the transport against a real peer rather than against our own encoder|sudo apt install openssh-server openssh-client")
    fi

    # jinja's oracle is a real Python Jinja2, and its VERSION is part of the
    # claim rather than an implementation detail: the committed golden records
    # the version that produced it, and on 2026-08-15 a runner carrying a
    # different one turned two of 337 corpus cases red for `replace` and `trim`
    # with Markup arguments — our output matched the golden byte for byte in
    # both, so what had moved was the oracle. Report the version, not just its
    # presence, because "jinja2 is installed" is not the question.
    local golden_j2 live_j2
    golden_j2="$(sed -n 's/.*"jinja2"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        modules/jinja/src/testdata/golden.json 2>/dev/null | head -1)"
    live_j2="$(python3 -c 'import jinja2; print(jinja2.__version__)' 2>/dev/null)"
    if [[ -z "$live_j2" ]]; then
        gaps+=("python lacks jinja2|'zig build interop-jinja' cannot re-render the 351-case corpus against the real engine (test-jinja replays the transcript hermetically since 2026-09-06)|pip install 'jinja2==${golden_j2:-3.1.6}'")
    elif [[ -n "$golden_j2" && "$live_j2" != "$golden_j2" ]]; then
        gaps+=("jinja2 $live_j2 != golden's $golden_j2|the live oracle is not the one the committed golden was generated from, so a red jinja case may be drift rather than a defect|pip install 'jinja2==$golden_j2'")
    fi

    # opcua's asyncua interop drives a Python client; the interpreter needs
    # asyncua + cryptography. This is a separate gate from podman — the
    # container-backed tests pass without it.
    local opcua_py="${OPCUA_PYTHON:-python3}"
    if ! "$opcua_py" -c 'import asyncua, cryptography' >/dev/null 2>&1; then
        gaps+=("python lacks asyncua/cryptography|1 opcua live asyncua-interop test skips|python3 -m venv ~/.cache/zig-libs-opcua && ~/.cache/zig-libs-opcua/bin/pip -q install asyncua cryptography && echo 'export OPCUA_PYTHON=~/.cache/zig-libs-opcua/bin/python3' >> ~/.bashrc")
    fi

    # imap's live interop drives a real IMAP server (pymap -- an INDEPENDENT
    # implementation, not the one imap was ported from, which is the point).
    if [[ ! -x "${IMAP_PYMAP:-$HOME/.cache/zig-libs-imap/bin/pymap}" ]]; then
        gaps+=("no pymap IMAP server|1 imap live interop test skips (the only test that proves the client's SEQUENCING, not just its parsing)|python3 -m venv ~/.cache/zig-libs-imap && ~/.cache/zig-libs-imap/bin/pip -q install pymap")
    fi

    # ⭐ FOUR MORE PYTHON ORACLES, and they were invisible until 2026-08-15.
    #
    # Every module below is checked against an INDEPENDENT implementation of the
    # thing it implements — the highest-value tests in this collection, because
    # they are the only ones that can fail for a reason our own encoder does NOT
    # share. Each skips loudly in its own log line when its interpreter cannot import
    # the package, and every one of those lines lands in a per-module summary
    # this driver used to delete.
    #
    # The consequence, measured on the arm64 lane of tag 2026-08-15: the report
    # said "1 gap" while 22 of these tests skipped. A capability report that
    # names four of six oracles is not a report, it is a subset that reads like
    # one — and the modules it misses stay green. `capability_check` is where
    # this is fixed, NOT the individual tests: they already say what they need,
    # in the right words, to a reader who is looking at the right module.
    #
    # ⚠ A PROBE MUST USE THE INTERPRETER THE TEST USES, and the first draft of
    # this loop did not. Three of the four spawn a bare `python3`; `grpc` tries
    # `~/.cache/zig-libs-grpc/bin/python` first and falls back (see
    # `pythonInterpreter()` in `modules/grpc/tools/interop.zig` -- the file was
    # `src/reference_interop.zig` until 2026-09-06). Probing `python3` for all
    # four reported a grpcio gap on a host where grpc's tests were running fine
    # from its venv — a false gap, which spends the reader's trust in exactly
    # the report that most needs it.
    #
    # ⚠ ALL FOUR NOW COST AN `interop-<m>` RE-TAKE, NOT A TEST. Since the
    # 2026-09-06 split these four modules' own tests replay committed
    # transcripts and pass with no Python at all, so a lane that runs only
    # `test.sh modules` will report these four gaps and lose no coverage by
    # them. The lane that actually needs them is `test.sh interop`, and the
    # cost text below says so per module rather than leaving the reader to
    # infer it.
    #
    # ⚠ AND IT MUST IMPORT EVERYTHING THAT INTERPRETER WILL BE ASKED TO IMPORT.
    # `grpc` is one entry with two packages: both of its oracle scripts import
    # `google.protobuf` as well as `grpc`, and a venv sees no system
    # site-packages, so "grpcio is installed" is not the question. Probing only
    # `grpc` reported no gap on a runner whose venv had exactly that, and the
    # test then failed on the missing import rather than skipping.
    local oracle
    for oracle in \
        "grpc, google.protobuf|grpcio protobuf|zig-libs-grpc|'zig build interop-grpc' cannot re-take the wire recording against a real grpcio peer (test-grpc itself is hermetic since 2026-09-06 and does not need this)" \
        "sympy|sympy||'zig build interop-poseidon' cannot re-take the MDS subspace-trail transcript (test-poseidon replays it hermetically since 2026-09-06)" \
        "brotli|brotli||'zig build interop-brotli' cannot re-bless the reference streams against google/brotli (test-brotli replays them hermetically since 2026-09-06)" \
        "google.protobuf|protobuf||'zig build interop-protobuf' cannot re-capture against the upstream Python runtime (test-protobuf replays the capture hermetically since 2026-09-06)"
    do
        local mod="${oracle%%|*}" rest2="${oracle#*|}"
        local pkg="${rest2%%|*}"; rest2="${rest2#*|}"
        local venv="${rest2%%|*}" cost="${rest2#*|}"
        local py=python3 fix="pip install $pkg"
        if [[ -n "$venv" ]]; then
            [[ -x "$HOME/.cache/$venv/bin/python" ]] && py="$HOME/.cache/$venv/bin/python"
            fix="python3 -m venv ~/.cache/$venv && ~/.cache/$venv/bin/pip -q install $pkg"
        fi
        "$py" -c "import $mod" >/dev/null 2>&1 \
            || gaps+=("python lacks $pkg|$cost|$fix")
    done

    # ⭐ TWO MORE, FOUND BY READING THE UNCAPPED SKIP LIST. The digest's tail —
    # the part the terminal used to truncate — showed the runner skipping 114
    # tests in 43 modules against this host's 110 in 41, and the difference was
    # exactly `icmp 3` and `yaml 1`. Both had been skipping on every runner
    # since CI existed, under a report that said "1 gap".
    #
    # icmp: unprivileged ICMP sockets need a `net.ipv4.ping_group_range` that
    # contains one of our groups. The kernel default is the EMPTY range `1 0`
    # (start > end), so the tests get PermissionDenied and skip. Reading the
    # sysctl says so without needing to open a socket.
    if [[ -r /proc/sys/net/ipv4/ping_group_range ]]; then
        local pgr_lo pgr_hi
        read -r pgr_lo pgr_hi < /proc/sys/net/ipv4/ping_group_range
        if [[ -n "$pgr_hi" ]] && (( pgr_lo > pgr_hi )); then
            gaps+=("no unprivileged ICMP sockets (ping_group_range is $pgr_lo $pgr_hi, an empty range)|3 icmp live tests skip — the ones that send a real echo request rather than encode one|echo 'net.ipv4.ping_group_range=0 2147483647' | sudo tee /etc/sysctl.d/61-zig-libs-ping.conf >/dev/null && sudo sysctl --system >/dev/null")
        fi
    fi

    # yaml: the module is checked against yaml/yaml-test-suite, the LANGUAGE's
    # own conformance corpus — an oracle written by people who did not write
    # this parser, which makes it the most valuable single test the module has
    # and the easiest to lose, since the whole suite collapses to one skip.
    local yaml_suite="${ZIG_LIBS_YAML_SUITE:-$HOME/.cache/zig-libs-yaml/yaml-test-suite-data}"
    if [[ ! -d "$yaml_suite" ]]; then
        gaps+=("no yaml-test-suite checkout|the entire yaml conformance suite collapses into 1 skipped test — the module is then checked only against itself|git clone -b data --depth 1 https://github.com/yaml/yaml-test-suite ~/.cache/zig-libs-yaml/yaml-test-suite-data")
    fi

    # Always present: RTM_NEWACTION checks CAP_NET_ADMIN in the INITIAL user
    # namespace, so `unshare -rn` cannot grant it however userns is configured.
    #
    # Two things this command must get right, both learned the hard way:
    #   * an absolute zig path — sudo's secure_path does not include a
    #     toolchain under ~/.config or ~/.local, so a bare `zig` gives
    #     "unshare: failed to exec zig: No such file or directory";
    #   * separate cache directories — `zig build` as root would otherwise
    #     leave root-owned entries in the repo's .zig-cache and break the
    #     next ordinary build.
    #
    # This one stays interactive on purpose. A NOPASSWD sudoers rule for it
    # would be passwordless root, not a narrow grant: `zig build` executes
    # build.zig, i.e. arbitrary code, as root.
    local zig_abs; zig_abs="$(command -v zig 2>/dev/null || echo zig)"
    gaps+=("tc RTM_NEWACTION needs real root|tc action tests skip (the rest of tc runs)|sudo unshare -n $zig_abs build test-tc --cache-dir /tmp/zig-cache-root --global-cache-dir /tmp/zig-gcache-root")

    # ⭐ THE EXAMPLES' OWN PEERS, and they are a different class from everything
    # above. The gate RUNS each example (it only compiled them until
    # 2026-08-23), and an example whose external judge is missing returns an
    # error — `modules/websocket/example/main.zig` returns
    # `error.PythonPeerFailed`. That is deliberate: the judge is the point of
    # the file, and skipping it would leave an example that proves nothing.
    #
    # ⚠ WHICH MEANS THE REPORT ABOVE COULD NOT SEE IT. Its whole table probes
    # the peers of TESTS, and on 2026-08-24 it printed "1 gap" — real root for
    # tc — on a runner with no `websockets` at all, then spent eight minutes
    # reaching step 460 of 461 to say `ModuleNotFoundError` inside a traceback.
    # The host it was written on happened to have the package, so no local run
    # could have found this; only a host that did not.
    #
    # Everything else the examples spawn is stdlib (`sys`, `re`, `socket`) or a
    # coreutil, so this table has one row today. It is a table because the next
    # example with a third-party judge should cost one line, not a rediscovery.
    local peer
    for peer in \
        "websockets|websockets==15.0.1|the websocket example, and with it the gate's run-examples step and the whole lane"
    do
        local imp="${peer%%|*}" rest3="${peer#*|}"
        local spec="${rest3%%|*}" what_breaks="${rest3#*|}"
        python3 -c "import $imp" >/dev/null 2>&1 \
            || blockers+=("python lacks $imp|$what_breaks|pip install '$spec'")
    done

    if (( ${#blockers[@]} )); then
        echo "environment: ${#blockers[@]} MISSING PEER(S) THAT FAIL THE RUN — not a coverage gap:"
        local b
        for b in "${blockers[@]}"; do
            local b_what="${b%%|*}"; local b_rest="${b#*|}"
            local b_breaks="${b_rest%%|*}"; local b_fix="${b_rest#*|}"
            printf '  %s\n      breaks: %s\n      fix:    %s\n' "$b_what" "$b_breaks" "$b_fix"
        done
        echo
    fi

    [[ ${#gaps[@]} -eq 0 ]] && return 0

    echo "environment: ${#gaps[@]} gap(s) reducing coverage — run these to close them:"
    local g
    for g in "${gaps[@]}"; do
        local what="${g%%|*}"; local rest="${g#*|}"
        local cost="${rest%%|*}"; local fix="${rest#*|}"
        printf '  %s\n      cost: %s\n      fix:  %s\n' "$what" "$cost" "$fix"
    done
    echo
}

# ── subcommands ──────────────────────────────────────────────────────────

cmd_changed() {
    # ⛔ FLAGS AND THE BASE REF ARE SEPARATED BY SHAPE, not by position, and
    # until 2026-09-08 they were not separated at all. `base_ref` was `$1` and
    # nothing ever called `set_extra_args`, so this subcommand had two silent
    # failures, both measured with a probe test asserting `builtin.mode`:
    #
    #   test.sh changed <base> -Doptimize=ReleaseFast
    #       -> the flag lands in `${@:2}`, which only the unresolvable-base
    #          branch below ever passed on. EXTRA_ZIG_ARGS stayed empty and the
    #          run compiled DEBUG while the caller believed it had asked for
    #          ReleaseFast. `PROBE: mode=Debug`. A CI lane written this way
    #          would report green having measured the Debug lane twice.
    #
    #   test.sh changed -Doptimize=ReleaseFast
    #       -> the flag was taken as the BASE REF and forwarded as a positional
    #          argument to check-changelog-entry.py, which died on
    #          "unrecognized arguments".
    #
    # A `-`-prefixed argument is a flag wherever it appears; the first bare one
    # is the base ref. Audit finding R14 item 4.
    local base_ref=""
    local -a changed_extra=()
    local _a
    for _a in "$@"; do
        if [[ "$_a" == -* ]]; then
            changed_extra+=("$_a")
        elif [[ -z "$base_ref" ]]; then
            base_ref="$_a"
        else
            changed_extra+=("$_a")
        fi
    done
    set_extra_args ${changed_extra[@]+"${changed_extra[@]}"}
    local files
    if ! files="$(changed_files "$base_ref")"; then
        echo "changed: base ref '$base_ref' does not resolve here — cannot compute a narrower set," >&2
        echo "         so running everything rather than reporting nothing to do." >&2
        cmd_all ${changed_extra[@]+"${changed_extra[@]}"}
        return
    fi
    files="$(printf '%s\n' "$files" | sort -u)"

    # ⚠ An empty diff is NOT "nothing to test" any more: which MODULES run is
    # decided by the stamps below, and a module can be unproven with nothing
    # uncommitted -- committed untested, or red on the last run. The diff only
    # decides which repo-wide checks run.
    if [[ -z "$files" ]]; then
        echo "changed: no changed/staged/untracked files$( [[ -n "$base_ref" ]] && echo " vs $base_ref" ) — checking stamps only"
    fi

    capability_check

    local trigger_all=0 trigger_catalog=0 trigger_changelog=0
    local trigger_docs=0
    local seeds=" " docs_only=" " f name
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        case "$f" in
            # ── DOCUMENTATION-ONLY files inside a module ──────────────────────
            #
            # These cannot change what compiles or what a test does, so they do
            # NOT seed the reverse-dependency closure. Audit finding R27: eight
            # changed files, all NOTICE and CHANGELOG.md, seeded four modules,
            # pulled in fourteen more through `bls12_381` (which `bbs`, `ibe`,
            # `tlock`, `frost` and `voprf` all depend on) and paid 51 steps and
            # 1 425 tests to prove that prose still compiles the same way.
            #
            # ⛔ THE TRAP THIS AVOIDS, and it is the reason for `trigger_docs`
            # rather than a plain `continue`: the gates that actually READ these
            # files -- check-catalog, check-copyleft, check-changelog -- run
            # unconditionally BELOW, but only if execution reaches them. The
            # early exit further down ("no modules affected") would otherwise
            # fire on a NOTICE-only change and skip exactly the checks that
            # change was for. Cheaper is not the goal if it is cheaper by
            # skipping the answer.
            modules/*/*.md|modules/*/NOTICE|modules/*/LICENSE|modules/*/*/*.md)
                name="${f#modules/}"
                name="${name%%/*}"
                case "$docs_only" in *" $name "*) ;; *) docs_only="$docs_only$name " ;; esac
                trigger_docs=1
                ;;
            modules/*/*)
                name="${f#modules/}"
                name="${name%%/*}"
                case "$seeds" in *" $name "*) ;; *) seeds="$seeds$name " ;; esac
                ;;
            build.zig|build.zig.zon)
                # Nothing to decide here: build.zig is in every fingerprint
                # (its `module_list` entries per module, the rest as machinery),
                # so the stamps already say which modules this re-keyed.
                ;;
            .github/*|scripts/test.sh|scripts/test-lib.sh|scripts/capped|scripts/dark-tests.sh|scripts/ci-environment.sh|scripts/test-tag.sh|scripts/ci-stamps.sh|scripts/check-ci-cache-keys.sh|scripts/check-http-sizeprobe.sh|scripts/check-fp-freedom.sh|scripts/check-skip-as-pass.py|scripts/check-ct-compare.py|scripts/ct-compare-expected.tsv|scripts/check-fuzz-reach.py|scripts/check-example-assert.py|scripts/check-changelog-entry.py|scripts/hooks/*)
                # The harness or the CI lane definition itself: no narrower set
                # can be trusted, because what narrows it is the thing that
                # changed.
                #
                # ⚠ The membership rule is "the gate EXECUTES it", not "it lives
                # in scripts/". Four of these were missing until 2026-08-15 and
                # each was the same hole: `dark-tests.sh` decides which tests
                # count as dark, `ci-environment.sh` decides which live peers
                # exist on a runner, and `test-tag.sh` plus `hooks/*` are run as
                # gate steps in their own right. `check-http-sizeprobe.sh` was
                # added a day later (2026-08-18) and missed the same fix: it too
                # is a gate step (see the `check-http-sizeprobe` calls below),
                # so an edit weakening its TLS-symbol assertion would otherwise
                # seed nothing and self-certify. Editing any of them changes
                # what a green run means while leaving the narrowing untouched.
                #
                # Everything else under scripts/ is a tool the gate never calls
                # (generators, dissect.py, vm/**), so it stays below.
                trigger_all=1
                ;;
            scripts/*)
                ;; # scripts/README.md, scripts/vm/**, generators — not gate steps
            README.md)
                trigger_catalog=1
                ;;
            CHANGELOG.md)
                # NOT "a root doc with no module impact", which is what this
                # was classified as until `check-changelog` existed: the root
                # CHANGELOG is an INDEX of the per-module ones, and editing it
                # is precisely how that index goes out of step with them. A
                # modules/<m>/CHANGELOG.md edit needs no trigger of its own --
                # it seeds <m> above, so the unconditional step below runs.
                trigger_changelog=1
                ;;
            NOTICE|CONVENTIONS.md)
                ;; # root docs with no module impact
            *)
                ;; # unrecognized root-level file — no module impact
        esac
    done <<< "$files"

    [[ -n "$files" ]] && echo "changed: $(printf '%s\n' "$files" | wc -l) file(s) changed$( [[ -n "$base_ref" ]] && echo " vs $base_ref" )"

    # fmt on the CHANGED .zig files. `all` fmt-checks the whole tree, but the
    # change-aware path used to skip fmt entirely — so a commit verified only
    # this way could ship unformatted code, and one did (f76f360,
    # modules/decimal/src/root.zig). Per-file, so it costs milliseconds.
    #
    # Skipped when the harness moved, because both escalations below open with a
    # whole-tree `zig fmt --check` that strictly contains this one. Running it
    # anyway printed two fmt steps in one log, which reads as two different
    # checks rather than one done twice — and a step list that misrepresents
    # itself is the thing this driver spends the most comments guarding against.
    local zig_changed=""
    [[ $trigger_all -eq 1 ]] || zig_changed=$(printf '%s\n' "$files" | grep -E '\.zig$' || true)
    if [[ -n "$zig_changed" ]]; then
        local existing=()
        local f
        while IFS= read -r f; do [[ -f "$f" ]] && existing+=("$f"); done <<< "$zig_changed"
        if [[ ${#existing[@]} -gt 0 ]]; then
            step "fmt check (${#existing[@]} changed file(s))" zig fmt --check "${existing[@]}"
        fi
    fi

    graph_load

    if [[ $trigger_all -eq 1 ]]; then
        # ⭐ ON CI THE SMOKE SET IS NOT ENOUGH, and 2026-08-15 is why.
        #
        # `eef1e28` changed scripts/test.sh, test-lib.sh, dark-tests.sh, ci.yml
        # AND modules/opcua/src/server_interop.zig — 191 lines of the driver two
        # days of work had gone into. The harness had moved, so this branch ran
        # the smoke set: `netlink` and `testkit`. opcua was not built, let alone
        # tested. The job exited 0, the aggregate `gate` job read `success`, and
        # the push went green having tested none of what it changed.
        #
        # The message below is the right answer AT A KEYBOARD, where "run
        # scripts/test.sh all before committing" is advice a person can take.
        # In CI there is nobody to take it and a runner already standing idle,
        # so the honest thing is to spend the runner rather than print advice
        # into a log nobody reads on a green run.
        #
        # ⚠ Fail-closed, like every other escalation in this driver: unable to
        # narrow means run everything, never run less. The cost is that a push
        # touching the harness pays a full lane — which is exactly what a change
        # to the thing that decides coverage should cost.
        if [[ -n "${GITHUB_ACTIONS:-}" ]]; then
            echo "changed: the harness or a CI lane definition changed, and this is CI."
            echo "  What narrows the module set is what moved, so it cannot narrow itself."
            echo "  Escalating to the full gate rather than to a smoke set — see cmd_changed."
            # ⚠ The mode goes WITH the escalation. Without it a ReleaseFast lane
            # that escalates silently becomes a second Debug lane.
            cmd_all ${changed_extra[@]+"${changed_extra[@]}"}
            return
        fi
        harness_smoke
        return
    fi

    # ⭐ WHICH MODULES RUN IS DECIDED BY STAMPS (2026-09-18), not by the diff.
    # A module runs when it has no green stamp for this lane at its current
    # fingerprint. The fingerprint already folds in every dependency, so the
    # reverse-dependency closure and the graph-snapshot escalation this used
    # to compute are both implied; and unlike a diff against a base, a stamp
    # does not forget a module that went red two commits ago.
    local lane closure
    lane="$(stamps_lane_key changed)"
    closure="$(stamps_pending "${G_NAMES[*]}" "$lane")"
    local total_n
    total_n=$(wc -w <<< "$closure")
    echo "changed: $total_n of ${#G_NAMES[@]} modules have no green stamp for '$lane'"
    if [[ $total_n -gt 0 && $total_n -le 40 ]]; then
        echo "  to test: $closure"
    fi
    local dname docs_pure=" "
    for dname in $docs_only; do
        case " $closure " in *" $dname "*) ;; *) docs_pure="$docs_pure$dname " ;; esac
    done
    if [[ $trigger_docs -eq 1 && -n "${docs_pure// /}" ]]; then
        echo "  docs only:  ${docs_pure# } — not built or tested (they cannot change what compiles);"
        echo "              the gates that read them still run below."
    fi

    if [[ -z "$files" && -z "${closure// /}" ]]; then
        echo "changed: nothing to do"
        exit 0
    fi
    if [[ -z "${closure// /}" && $trigger_catalog -eq 0 && $trigger_changelog -eq 0 && $trigger_docs -eq 0 && -z "${seeds// /}" ]]; then
        echo "changed: no modules affected — nothing to test"
        exit 0
    fi

    # ⭐ THREE KINDS OF CHECK, gated three ways (2026-09-18). Every one of
    # these used to run on every invocation with a non-empty diff, ~52 s warm,
    # which a comment edit paid in full.
    #   repo    (`files`): read root docs and the diff -- run when anything moved;
    #   text    (`mt`):    scan module source and may read comments or NOTICE,
    #                      which no fingerprint sees -- run when a module file
    #                      moved or a module is unproven;
    #   content (`mc`):    compile or analyse module code, comment-blind -- run
    #                      only when some module is unproven (no stamp at its
    #                      current fingerprint), narrowed where the step allows.
    # A green run stamps the modules it ran, so a stamp implies these passed.
    local mc=0 mt=0
    [[ -n "${closure// /}" ]] && mc=1
    [[ $mc -eq 1 || -n "${seeds// /}" || -n "${docs_only// /}" ]] && mt=1
    closure_has() { case " $closure " in *" $1 "*) return 0 ;; esac; return 1; }
    stamps_narrow "$closure" "${G_NAMES[*]}"

    if [[ $trigger_catalog -eq 1 ]]; then
        step "check-catalog (README.md changed)" zig build check-catalog
    fi

    # Runs whenever anything moved (`files`), and reached by both paths that
    # get here: a changed module (its own CHANGELOG.md is
    # under modules/, so it seeded the module) and a changed root CHANGELOG.md
    # (`trigger_changelog`, which is what keeps the early exit above from
    # skipping this).
    [[ -n "$files" ]] && step "check-changelog" zig build check-changelog

    # `check-changelog` above proves the file EXISTS and is well formed; it reads
    # the tree, never a diff, so it cannot see that a module's parser was
    # rewritten while its changelog last moved six weeks ago. This one reads the
    # diff. Replayed over the last 120 commits it found public declarations that
    # reached no changelog at any later point either -- `http.setHeaderStatic`,
    # `cors.applyPreflight`, `ssh.max_packets_per_direction`. The `changed` lane
    # instance is the one CI reaches with a real base ref; the other two are
    # no-ops on a clean checkout.
    [[ -n "$files" ]] && step "check-changelog-entry" ./scripts/check-changelog-entry.py ${base_ref:+"$base_ref"}

    # A testkit leak into published code is introduced by editing a MODULE's
    # code, which re-keys it -- so an unproven module (`mc`) is the signal.
    (( mc )) && step "check-testonly" zig build check-testonly

    # Same reasoning as `check-testonly` above: ~0.1s warm, and the change
    # signal that would gate it (editing a harness, or editing the module it
    # measures) is exactly what a developer is doing when it matters.
    (( mc )) && step "check-ctgrind" zig build check-ctgrind

    # Gated on `mc` like the two above. It was absent from this driver until
    # 2026-08-14, which is why nobody noticed it had
    # been red for weeks on 21 modules: a gate that exists and is never invoked
    # makes the same claim a skipped test makes, which is that someone looked.
    (( mc )) && step "check-fuzz" zig build check-fuzz
    (( mt )) && step "check-copyleft" zig build check-copyleft

    # Same reasoning as check-copyleft above, and the same order of cost
    # (~1.4 s): a source scan that refuses a module whose own code runs a
    # foreign toolchain. See phase_checks_fast_tail for the rule in full.
    (( mt )) && step "check-module-purity" zig build check-module-purity
    (( mc )) && step "check-global-alloc" zig build check-global-alloc

    # 32-bit compile of every `platform = .any` module. ~6s cold for all 195,
    # near-free warm, and it is the only thing in this gate that can see a class
    # the whole CI matrix is blind to: every lane is 64-bit, arm64 included, so
    # `usize` is 64 bits everywhere the suite has ever run. `platform = .any`
    # covers wasm32 and arm32 too, and until this step existed nothing had ever
    # compiled for either.
    (( mc )) && step "check-portable" zig build check-portable
    [[ -n "$files" ]] && step "check-portable-table" zig build check-portable-table
    [[ -n "$files" ]] && step "check-libs-table" zig build check-libs-table
    [[ -n "$files" ]] && step "check-catalog-table" zig build check-catalog-table
    # The class no other gate can see: Zig analyses a function body only when
    # something references it, so a `pub fn` no test reaches can be outright
    # non-compiling and still ship green. Measured 2026-08-21: 403 of 9626
    # public functions are unreachable from any test, across 106 modules, 90 of
    # them on a module's own published `root.zig` surface. Demonstrated by
    # mutation the same day -- a deliberate type error in an unreachable
    # `nftables` function compiled, linked and ran green under `test-nftables`,
    # and only this step went red on it.
    (( mc )) && step "check-pubfn-reach" zig build check-pubfn-reach ${SEL_ARGS[@]+"${SEL_ARGS[@]}"}
    # The one class no test here can cover: is the PUBLISHED API sufficient to
    # do the job? Every test lives in the file it tests, so it reads private
    # declarations and its build carries `test_deps` a consumer never gets.
    # Proven on l2disco 2026-08-21: dropping `pub` from a type its API needs
    # left both `test-l2disco` and `check-pubfn-reach` green, and only this red.
    (( mc )) && step "check-examples" zig build check-examples "${EXTRA_ZIG_ARGS[@]}" ${SEL_ARGS[@]+"${SEL_ARGS[@]}"}
    # ⚠ `zig build run-examples` USED TO BE HERE, running all 230 examples on
    # every scoped push under a comment claiming "only the full lane pays it".
    # It did not: this step is unconditional, so the scoped lane paid ~68 s of
    # it per push and then `run_modules` ran the changed closure's examples
    # AGAIN. Running them is not in question -- compiling an example cannot see
    # what examples are for -- but the scoped lane runs the modules this change
    # can reach, and that is where its example runs belong too. See
    # `run_modules`, which now covers every group it tests.

    # `modules/http/sizeprobe/` proves requestPlain/requestStreamingPlain/
    # putFilePlain never pull in TLS (CONVENTIONS.md-adjacent doc on
    # `Client.zig`'s `dialPlain`), and it has its OWN standalone build.zig
    # that nothing else in the repo referenced -- an artefact whose check
    # never runs is worse than none (same lesson as the portability table
    # above). Builds both probes for x86_64-linux-musl only and asserts
    # zero TLS/certificate/curve/hash symbols in the plaintext one; see the
    # script for why one target is enough and why this is a symbol-presence
    # check rather than a byte-count one. ~30s when Client.zig's content
    # actually changed, near-instant otherwise.
    closure_has http && step "check-http-sizeprobe" ./scripts/check-http-sizeprobe.sh
    # falcon's constant-time property is invisible to every value test (the
    # integer emulation is bit-identical to hardware FP), and falcon is not on
    # the ctgrind gate. This disassembly check is the only thing that fails when
    # the emulation is bypassed. See the script header.
    closure_has falcon && step "check-fp-freedom" ./scripts/check-fp-freedom.sh
    # Strips comments before it scans, so a fingerprint change is its signal.
    (( mc )) && step "check-ct-compare" ./scripts/check-ct-compare.py
    (( mt )) && step "check-skip-as-pass" ./scripts/check-skip-as-pass.py

    # `zig build check-fuzz` proves a harness EXISTS; this proves it READS its
    # input. A `Smith` ranged draw returns the range MINIMUM unless the eight
    # bytes it reads as a little-endian u64 already lie inside the range, so a
    # harness that opens with one -- or that slices its drawn bytes to a length
    # that came from one -- replays every corpus seed, and every crash `--fuzz`
    # minimises into a seed, as the same fixed input. 416 of 474 targets did at
    # landing. `--advisory` printed that burn-down without failing anything --
    # but a gate that never fails protects nothing, and the burn-down is being
    # done a module at a time over many sessions, so a module fixed in week one
    # could regress in week three with no signal at all. `--ratchet` compares
    # against `scripts/fuzz-reach-baseline.txt`, a ceiling PER MODULE: it fails
    # only where a module got worse, names the modules that have improved since
    # the file was written, and comes off entirely when the baseline is empty.
    # The ceiling is per module rather than one total on purpose -- a total lets
    # one module regress while another improves and still reads green.
    # It still FAILS on a malformed or stale exemption.
    (( mt )) && step "check-fuzz-reach" ./scripts/check-fuzz-reach.py --ratchet

    # `run-examples` builds and runs each example in the LANE's optimize mode,
    # so in a ReleaseFast lane every `std.debug.assert` in one is compiled out
    # and the example prints its success lines having checked nothing. Three
    # examples compared against an external oracle that way and printed that it
    # agreed; breaking `sealedbox`'s PyNaCl constant left the old example
    # exiting 0 and still claiming a byte-exact match.
    (( mt )) && step "check-example-assert" ./scripts/check-example-assert.py

    if [[ -z "${closure// /}" ]]; then
        summary
        exit 0
    fi

    run_modules "$closure"
    stamps_record "$closure" "$lane"
    summary
}

# ⭐ COMPILE-ONLY GATE. Same gate as `all`, stopping after the compile.
#
# Nobody consumes this collection in Debug. It ships SOURCE (CONVENTIONS §7.1),
# and an integrator picks the optimize mode in their own build — small, safe or
# fast. So what a Debug lane is worth asking is whether the code COMPILES
# there, which is a real question: a downstream developer running their app in
# Debug compiles our modules in Debug, heavy ones included, and this is the only
# lane that ever does that (the default lane relaxes heavy modules to
# ReleaseSafe for wall-clock, see `heavy_optimize` in build.zig).
#
# What running the tests there is worth is nothing that can be pointed at, and
# that was measured on 2026-08-15 rather than assumed:
#
#   * Debug and ReleaseSafe arm the SAME safety checks. Debug's only difference
#     is that it does not optimise, which makes it WEAKER at exposing undefined
#     behaviour, not stronger — the one documented cross-mode catch went the
#     other way (ReleaseSafe found a use-after-scope in `http` that Debug
#     passed by luck, `f88a102`).
#   * tests in this repo that run ONLY in Debug: zero.
#   * tests that SKIP in Debug: fifteen, all in `threshold_ecdsa`, gated on
#     `builtin.mode == .Debug` because they are too slow there. Measured:
#     `-Dstrict-debug` gives 48/63 with 15 skipped where every other lane gives
#     63/63. The lane proved LESS than its siblings, not more.
#   * no finding in the audit corpus is attributed to this lane.
#
# ⚠ This is not a shortcut to make a slow lane fit. It is narrowing a lane to
# the claim it can actually support. If a Debug-only test ever exists, this
# stops being the right shape and the count above is how you would notice.
# ── the gate's phases, so CI can run them as separate jobs ────────────────
#
# ⭐ WHY THIS IS SPLIT AT ALL. The four lanes of the full matrix each ran the
# whole gate, and on 2026-08-24 the ReleaseFast lane passed its 90-minute cap
# by 23 SECONDS (5245.8 s of gate inside a 5400 s ceiling). The cap is not
# going up, so the work has to come apart — and it comes apart cleanly, because
# the halves share nothing: a module is compiled once for its test binary and
# once for its example, and Zig's unit of caching is the whole compilation, so
# there is no artifact for one to hand the other. Measured: examples cold
# 2.07 s, examples after the tests 1.80 s; tests cold 23.24 s, tests after the
# examples 23.44 s.
#
#   checks-fast   the sub-second ones, ~4 s. CI runs these BEFORE the lanes so
#                 a stray `zig fmt` cannot burn eight runners for an hour.
#   checks        the mode- and arch-independent rest, ~1-2 min, one job.
#   modules       per-arch `check-pubfn-reach`, compile every module, test it.
#   examples      compile every example in the lane's mode, run it.
#
# `all` still runs every phase in one process: that is what a local pre-commit
# gate should be, and nothing about the split belongs in a developer's hands.

# The first of the fast checks is `fmt`, and it stays spelled out at each call
# site: `af6a148` is why the fmt step is first and why the hook exists -- six
# files had drifted out of fmt, the gate stops on the first failure, and so NO
# module was being tested locally at all. The hook stops that landing in a
# commit -- but only while the hook itself works, which is what this checks.
phase_checks_fast() {
    step "fmt check" zig fmt --check build.zig build.zig.zon modules
    phase_checks_fast_tail
}

# Everything in here was measured at 0.0-1.3 s on 2026-08-24, twelve steps for
# about four seconds in total. That is the whole reason they are a group: they
# are cheap enough to run before anything expensive starts, which is what makes
# them a fail-fast gate rather than one more thing to wait for.
phase_checks_fast_tail() {
    step "hook self-test" ./scripts/hooks/test-pre-commit.sh
    step "tag.sh self-test" ./scripts/test-tag.sh
    step "check-ci-cache-keys" ./scripts/check-ci-cache-keys.sh
    step "check-scripts-doc" zig build check-scripts-doc
    step "check-package" zig build check-package
    step "check-catalog" zig build check-catalog

    # The root NOTICE stopped listing modules on 2026-09-06: a module's
    # third-party obligation is discharged in the module's own NOTICE, and the
    # root file answers one question only -- is the library as a whole still
    # plain MIT. This is what makes that answer checkable. It refuses a shipped
    # file that GRANTS ITSELF under a copyleft licence (an SPDX expression
    # naming GPL/AGPL/LGPL/EUPL/CeCILL/SSPL/OSL, or an FSF grant paragraph),
    # which is why `ebpf`'s `_license = "GPL"` -- a BPF verifier ABI value, not
    # a copyright notice -- does not trip it. Copyleft in shipped code is a
    # defect to be removed, not a paperwork item.
    step "check-copyleft" zig build check-copyleft

    # The teeth on the owner's rule of 2026-09-06 -- a module is standalone Zig
    # with no external dependency, and an anchor against a foreign
    # implementation is an EXTERNAL test that belongs in `modules/<m>/tools/`.
    # Six modules were separated from their interop programs that day; nothing
    # stopped the seventh being written the old way tomorrow. It refuses a file
    # under `modules/<m>/src/` that starts a child process AND either names a
    # foreign toolchain (`cc`, `python3`, `node`, `make`, ...) or `@embedFile`s
    # foreign SOURCE. The spawn is the condition, which is why json5's six `.js`
    # fixtures, ebpf's `.bpf.c` provenance and qr's `reference.py` -- none of
    # which anything in their own file can run -- do not trip it. ~1.4 s, the
    # same order as check-copyleft beside it.
    step "check-module-purity" zig build check-module-purity
    step "check-uapi" zig build check-uapi
    step "check-changelog" zig build check-changelog

    # `check-changelog` above proves the file EXISTS and is well formed; it reads
    # the tree, never a diff, so it cannot see that a module's parser was
    # rewritten while its changelog last moved six weeks ago. This one reads the
    # diff. Replayed over the last 120 commits it found public declarations that
    # reached no changelog at any later point either -- `http.setHeaderStatic`,
    # `cors.applyPreflight`, `ssh.max_packets_per_direction`. The `changed` lane
    # instance is the one CI reaches with a real base ref; the other two are
    # no-ops on a clean checkout.
    step "check-changelog-entry" ./scripts/check-changelog-entry.py ${base_ref:+"$base_ref"}
    step "check-portable-table" zig build check-portable-table
    step "check-libs-table" zig build check-libs-table
    step "check-catalog-table" zig build check-catalog-table
}

# The rest of the checks: 76 s on amd64, 104 s on arm64, and NOT arch-dependent
# in what they assert -- `check-portable` cross-compiles every `platform = .any`
# module for 32-bit and wasm32 targets from wherever it runs, and the ctgrind
# harnesses and the sizeprobe are compile-only. So one job runs them once for
# the whole matrix.
#
# ⚠ `check-pubfn-reach` is deliberately NOT here. It instantiates every `pub fn`
# for the target being built, which is exactly how the arm64 lane found x86
# inline asm in `montint` on 2026-08-24 -- run it once and that class goes
# unseen on three of four lanes. It lives in `modules`, per arch.
phase_checks() {
    step "check-testonly" zig build check-testonly
    step "check-fuzz" zig build check-fuzz
    step "check-global-alloc" zig build check-global-alloc
    step "check-portable" zig build check-portable
    step "check-http-sizeprobe" ./scripts/check-http-sizeprobe.sh
    # falcon's constant-time property is invisible to every value test (the
    # integer emulation is bit-identical to hardware FP), and falcon is not on
    # the ctgrind gate. This disassembly check is the only thing that fails when
    # the emulation is bypassed. See the script header.
    step "check-fp-freedom" ./scripts/check-fp-freedom.sh
    step "check-ct-compare" ./scripts/check-ct-compare.py
    step "check-skip-as-pass" ./scripts/check-skip-as-pass.py

    # `zig build check-fuzz` proves a harness EXISTS; this proves it READS its
    # input. A `Smith` ranged draw returns the range MINIMUM unless the eight
    # bytes it reads as a little-endian u64 already lie inside the range, so a
    # harness that opens with one -- or that slices its drawn bytes to a length
    # that came from one -- replays every corpus seed, and every crash `--fuzz`
    # minimises into a seed, as the same fixed input. 416 of 474 targets did at
    # landing. `--advisory` printed that burn-down without failing anything --
    # but a gate that never fails protects nothing, and the burn-down is being
    # done a module at a time over many sessions, so a module fixed in week one
    # could regress in week three with no signal at all. `--ratchet` compares
    # against `scripts/fuzz-reach-baseline.txt`, a ceiling PER MODULE: it fails
    # only where a module got worse, names the modules that have improved since
    # the file was written, and comes off entirely when the baseline is empty.
    # The ceiling is per module rather than one total on purpose -- a total lets
    # one module regress while another improves and still reads green.
    # It still FAILS on a malformed or stale exemption.
    step "check-fuzz-reach" ./scripts/check-fuzz-reach.py --ratchet

    # `run-examples` builds and runs each example in the LANE's optimize mode,
    # so in a ReleaseFast lane every `std.debug.assert` in one is compiled out
    # and the example prints its success lines having checked nothing. Three
    # examples compared against an external oracle that way and printed that it
    # agreed; breaking `sealedbox`'s PyNaCl constant left the old example
    # exiting 0 and still claiming a byte-exact match.
    step "check-example-assert" ./scripts/check-example-assert.py
    step "check-ctgrind" zig build check-ctgrind
}

cmd_checks_fast() {
    echo "checks-fast: the sub-second gates, before anything expensive starts"
    phase_checks_fast
    summary
}

cmd_checks() {
    echo "checks: the mode- and arch-independent gates, once for the whole matrix"
    phase_checks
    summary
}

# ⭐ THE `interop` LANE: RE-TAKE THE ANCHORS, which is the half of an interop
# test that a transcript cannot carry.
#
# On 2026-09-06 six modules were separated from their interop programs: the
# program moved to `modules/<m>/tools/interop.zig` and what it produced became a
# committed transcript the module's own tests replay hermetically. That was a
# clear win — `test-grpc` went from 13 silent skips on a host without Python to
# 119/119 passing anywhere — but it left a hole nobody was standing in. Replay
# proves our side still agrees with what the peer said LAST TIME. It cannot
# discover that something new we send provokes a different reaction, and it
# cannot notice that the peer changed. Only running the real thing does that.
#
# ⛔ AND NO LANE RAN IT. Between the migration and this command, `zig build
# interop-<m>` existed and nothing anywhere invoked it: CI installed five Python
# oracles and wolfSSL for lanes that no longer touched any of them, while the
# six programs that DID need them were run by nobody. A transcript nobody can
# re-take is a frozen anchor — `modules/dnssec` lost one exactly that way, and
# `scripts/gen-dnssec-oracle.sh` had to be written from nothing to get it back.
#
# PRE-RELEASE, NOT PER-COMMIT, and that is the migration's own stated intent.
# The full matrix runs on tags and dispatch only, so a lane here is exactly a
# pre-release check. Running it on every push would put six live peers —
# a container, a compiler, four pip installs — back on the path of every commit,
# which is the cost the migration removed.
#
# `check-interop` first, deliberately: it COMPILES all six with no peer present,
# so a program that stopped building is reported as that, not as a peer that
# would not start. Each program then gets its own step, because "interop failed"
# over six peers is not a diagnosis.
#
# ⚠ THIS VERIFIES, IT DOES NOT REWRITE. Each program compares what the peer
# says NOW against the committed transcript and reports mismatches; re-blessing
# is `zig build interop-<m> -- --capture`, which a human runs after reading the
# mismatch. So this leaves a clean tree and goes red on divergence -- a lane
# that silently rewrote its own anchor would be a lane that can never fail.
cmd_ctgrind() {
    # PRE-RELEASE ONLY. Runs the constant-time measurement itself -- the thing
    # `zig build check-ctgrind` deliberately does NOT do.
    #
    # ⛔ WHY THIS LANE EXISTS. Until 2026-09-08 nothing in any lane ran
    # `scripts/ctgrind.sh --check`. `check-ctgrind` in build.zig compiles the
    # harnesses as a rot guard and says so ("leaving the measurement itself out
    # of the critical path"), which is right for a gate that must pass on a host
    # with no valgrind -- but it left 20 pinned constant-time claims across 8
    # crypto modules verified by NOTHING. A compile is not a measurement: a
    # harness can build perfectly and report a leak, and for a week nobody would
    # know. Audit finding R14 item 1.
    #
    # Tag/dispatch only, like `interop`, for the same reason: it needs a peer
    # (valgrind) that `scripts/ci-environment.sh ctgrind` installs, and it costs
    # minutes rather than seconds -- measured 310 s warm for all 8 modules and
    # all 20 rows on an i7-7920HQ.
    #
    # ⚠ Missing valgrind FAILS here, it does not skip. `ctgrind.sh` exits 2 with
    # its own message; a lane whose only purpose is the measurement must not
    # report green for not having taken it.
    set_extra_args "$@"
    echo "ctgrind: taking the constant-time measurement for every module with a harness."
    echo "  ⚠ needs valgrind (scripts/ci-environment.sh ctgrind); this is NOT check-ctgrind,"
    echo "    which only compiles the harnesses and runs no measurement at all."
    # ⚠ `ZL_STEP_STDERR_IS_OUTPUT`: the control table is the point of the run and
    # `ctgrind.sh` narrates its builds on stderr, so the ordinary rule (exit 0
    # with anything on stderr is a failure) would reject a green measurement.
    # Exit status still decides -- and `--check` exits 1 on any failed row.
    ZL_STEP_STDERR_IS_OUTPUT=1 step "ctgrind" scripts/ctgrind.sh --check
    summary
}

cmd_interop() {
    set_extra_args "$@"
    capability_check
    local m progs=()
    for m in modules/*/tools/interop.zig; do
        [[ -e "$m" ]] || continue
        m="${m#modules/}"
        progs+=("${m%%/*}")
    done
    if (( ${#progs[@]} == 0 )); then
        echo "interop: no modules/*/tools/interop.zig in the tree — nothing to re-take" >&2
        exit 1
    fi
    echo "interop: re-taking the anchors of ${#progs[@]} module(s) against real peers: ${progs[*]}"
    echo "  ⚠ these need the peers scripts/ci-environment.sh installs under the \`interop\` role;"
    echo "    the transcripts they produce are what test-<m> replays hermetically."
    step "check-interop" zig build check-interop "${EXTRA_ZIG_ARGS[@]}"
    # ⚠ `ZL_STEP_STDERR_IS_OUTPUT` for the runs, NOT for `check-interop` above.
    # These steps run PROGRAMS whose narration is their point -- interop-brotli
    # prints "reference: python brotli 1.2.0 ..., 114 checks, 0 mismatches" --
    # and `std.debug.print` writes to stderr, so the ordinary rule (exit 0 with
    # anything on stderr is a failure) rejected a run that had just proved 114
    # checks. `check-interop` is a compile and stays under the strict rule,
    # because a compiler that succeeds while complaining is exactly what that
    # rule exists to catch. Exit status still decides either way.
    local m_rc=0
    for m in "${progs[@]}"; do
        ZL_STEP_STDERR_IS_OUTPUT=1 step "interop-$m" zig build "interop-$m" "${EXTRA_ZIG_ARGS[@]}" || m_rc=1
    done
    (( m_rc )) || true
    summary
}

# The `modules` lane: every module compiled and tested in ONE optimize mode.
# Examples are a separate lane; see the phase comment above for why that costs
# nothing.
cmd_modules() {
    set_extra_args "$@"
    capability_check
    graph_load
    local lane_mods todo lane
    lane_mods="$(lane_modules)"
    lane="$(stamps_lane_key modules)"
    todo="$(stamps_pending "$lane_mods" "$lane")"
    echo "modules: $(wc -w <<< "$todo") of $(wc -w <<< "$lane_mods") modules in this lane have no green stamp for '$lane' — compiling and testing those; examples run in their own lane"
    if [[ -z "${todo// /}" ]]; then
        echo "modules: nothing to do — every module here is stamped green at its current fingerprint"
        summary
        return 0
    fi
    stamps_narrow "$todo" "$lane_mods"
    step "check-pubfn-reach" zig build check-pubfn-reach ${SEL_ARGS[@]+"${SEL_ARGS[@]}"}
    step "build (all modules)" zig build "${EXTRA_ZIG_ARGS[@]}" ${SEL_ARGS[@]+"${SEL_ARGS[@]}"}
    ZL_RUN_EXAMPLES=0 run_modules "$todo"
    stamps_record "$todo" "$lane"
    summary
}

# The `examples` lane: every example compiled in THIS lane's mode and run.
# ⚠ It calls `capability_check` for a reason the modules lane does not share:
# the blocker probe there is about an EXAMPLE's external judge (the websocket
# example's Python peer), and this is the lane that would die without it.
cmd_examples() {
    set_extra_args "$@"
    capability_check
    graph_load
    local lane_mods todo lane
    lane_mods="$(lane_modules)"
    lane="$(stamps_lane_key examples)"
    todo="$(stamps_pending "$lane_mods" "$lane")"
    echo "examples: $(wc -w <<< "$todo") of $(wc -w <<< "$lane_mods") modules in this lane have no green stamp for '$lane' — compiling and running their examples"
    if [[ -z "${todo// /}" ]]; then
        echo "examples: nothing to do — every module here is stamped green at its current fingerprint"
        summary
        return 0
    fi
    stamps_narrow "$todo" "$lane_mods"
    step "check-examples" zig build check-examples "${EXTRA_ZIG_ARGS[@]}" ${SEL_ARGS[@]+"${SEL_ARGS[@]}"}
    run_examples_for "$todo"
    stamps_record "$todo" "$lane"
    summary
}

# `main` dispatches with "${rest[@]:-}", which expands an EMPTY array to one
# empty string, and `zig build ""` fails with `no step named ''`. Filtering
# here keeps every caller correct no matter how it quotes.
set_extra_args() {
    EXTRA_ZIG_ARGS=()
    local a
    for a in "$@"; do [[ -n "$a" ]] && EXTRA_ZIG_ARGS+=("$a"); done
    # ⚠ NOT DECORATION. The loop's last statement is an `&&` list, so with only
    # empty arguments the loop -- and therefore this function -- returns 1, and
    # under `set -e` the caller dies on the spot: `test.sh examples` printed the
    # memory warning and exited 1 with nothing else to show. Inline in cmd_all
    # this could not happen, because statements followed it.
    return 0
}

# The compile-only lane. It runs NOTHING: no test, no example, no check that
# belongs to another job. Its whole deliverable is "every module and every
# example compiles in this mode", which is why CI skips its peer install --
# and why `run-examples` sitting above the old build-only return was a defect
# rather than a nicety: on 2026-08-24 this lane died on error.PythonPeerFailed,
# having reached a Python peer it was configured never to have.
cmd_build() {
    GATE_BUILD_ONLY=1
    set_extra_args "$@"
    graph_load
    local lane_mods todo lane
    lane_mods="$(lane_modules)"
    lane="$(stamps_lane_key build)"
    todo="$(stamps_pending "$lane_mods" "$lane")"
    local n
    n=$(wc -w <<< "$todo")
    echo "build: COMPILING $n of $(wc -w <<< "$lane_mods") modules (no green stamp for '$lane') and their examples, running NOTHING"
    if [[ -z "${todo// /}" ]]; then
        echo "build: nothing to do — every module here is stamped green at its current fingerprint"
        summary
        return 0
    fi
    stamps_narrow "$todo" "$lane_mods"
    step "build (all modules)" zig build "${EXTRA_ZIG_ARGS[@]}" ${SEL_ARGS[@]+"${SEL_ARGS[@]}"}
    step "check-examples" zig build check-examples "${EXTRA_ZIG_ARGS[@]}" ${SEL_ARGS[@]+"${SEL_ARGS[@]}"}
    # This lane runs no test, so there is no `--summary all` to digest and
    # nothing would land on the run's page. A lane that contributes NOTHING
    # there reads as one that failed to report, not as one with nothing to
    # report, and on 2026-08-15 three of four lanes had a block and this one
    # did not. One line, saying what it did and what that is worth.
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        printf '### %s\n\n```\n  %-16s %d modules + %d examples compiled, 0 tests run (see cmd_build)\n```\n\n' \
            "${ZIGLIBS_LANE:-gate}" "compile only:" "$n" "$n" >> "$GITHUB_STEP_SUMMARY"
    fi
    # ⚠ The graph snapshot is NOT saved here. It is what `changed` uses to
    # decide it may run a narrow set, and a run that executed no test has no
    # business telling the next one that anything was covered. The stamp below
    # is keyed to the `build` lane, so it claims a compile and nothing more.
    stamps_record "$todo" "$lane"
    summary
}

GATE_BUILD_ONLY=0

cmd_all() {
    set_extra_args "$@"
    capability_check
    graph_load
    local all_mods="${G_NAMES[*]}"
    local n=${#G_NAMES[@]}
    echo "all: running every module ($n total, $(printf '%s\n' "${G_HEAVY[@]}" | grep -c heavy) heavy) — the pre-commit/CI gate"
    step "fmt check" zig fmt --check build.zig build.zig.zon modules
    # `af6a148` is why the fmt step is first and why the hook exists: six files
    # had drifted out of fmt, the gate stops on the first failure, and so NO
    # module was being tested locally at all. The hook stops that landing in a
    # commit -- but only while the hook itself works, which is what this checks.
    phase_checks_fast_tail
    phase_checks
    # The class no other gate can see: Zig analyses a function body only when
    # something references it, so a `pub fn` no test reaches can be outright
    # non-compiling and still ship green. Measured 2026-08-21: 403 of 9626
    # public functions are unreachable from any test, across 106 modules, 90 of
    # them on a module's own published `root.zig` surface. Demonstrated by
    # mutation the same day -- a deliberate type error in an unreachable
    # `nftables` function compiled, linked and ran green under `test-nftables`,
    # and only this step went red on it.
    step "check-pubfn-reach" zig build check-pubfn-reach
    # The one class no test here can cover: is the PUBLISHED API sufficient to
    # do the job? Every test lives in the file it tests, so it reads private
    # declarations and its build carries `test_deps` a consumer never gets.
    # Proven on l2disco 2026-08-21: dropping `pub` from a type its API needs
    # left both `test-l2disco` and `check-pubfn-reach` green, and only this red.
    # ⭐ WITH THE LANE'S FLAGS, because this is the step that COMPILES the
    # examples and a lane compiles in its own mode or it has not compiled them.
    # Without them a ReleaseSafe lane built all 230 in Debug here and the run
    # phase below then built them AGAIN in ReleaseSafe — the same omission that
    # made `run-examples` a second compile, one step over. It also matters most
    # in the lane that does nothing else: the compile-only lane's whole
    # deliverable is "the modules and the examples build in this mode".
    step "check-examples" zig build check-examples "${EXTRA_ZIG_ARGS[@]}"
    # ⚠ `run-examples` USED TO BE HERE, and being here made the compile-only
    # lane a liar. It announces "COMPILING every module and running NO tests"
    # and then executed 216 example binaries — which is also why CI skips that
    # lane's peer install (`if: matrix.peers` in ci.yml): a lane that
    # runs nothing needs no peers. On 2026-08-24 the strict-Debug lane of the
    # full matrix died on `error.PythonPeerFailed`, having reached a Python
    # peer it was configured never to need. It now sits below the build-only
    # return, where the things that RUN belong.
    # ⚠ `check-http-sizeprobe` and `check-ctgrind` were here; they are in
    # `phase_checks` now, which this function called above. They assert nothing
    # that depends on the optimize mode or the host arch, so the matrix runs
    # them once rather than four times.

    # ⭐ COMPILE EVERYTHING FIRST, then run. `zig build`'s default step depends
    # on every module's test Compile (see build.zig), so this is the whole
    # collection's compile and nothing else; `run_modules` below then finds
    # those artifacts cached and is close to pure test execution.
    #
    # The point is two numbers instead of one. On 2026-08-14 a tag's matrix was
    # killed by GitHub's 6h job cap after five hours, and nothing in the log
    # could say whether that was compiling 225 modules or running their tests —
    # the gate reported one `build+test` figure for both. Two steps, two
    # durations, and the next long run answers it without instrumentation.
    #
    # EXTRA_ZIG_ARGS matters here: the optimize flags have to match the run
    # phase exactly or the cache keys differ and this compiles a set nothing
    # below uses — a full extra build, silently.
    #
    # `changed` deliberately does NOT do this: the default step builds the whole
    # collection, and a scoped lane exists precisely to avoid that.
    step "build (all modules)" zig build "${EXTRA_ZIG_ARGS[@]}"
    # Below this line the gate RUNS things — examples included: `run_modules`
    # runs every module's example in this lane's optimize mode, which is what a
    # tag claims and what the aggregate `zig build run-examples` that used to
    # stand here could not say (it carried no EXTRA_ZIG_ARGS, so it ran Debug
    # binaries in a ReleaseSafe lane and compiled all 230 a second time to do
    # it). `all_mods` is every module, so nothing lost coverage in the move.
    run_modules "$all_mods"
    # `all` runs everything `changed` would, for every module, with the same
    # arguments -- so it proves the `changed` lane for all of them.
    stamps_record "$all_mods" "$(stamps_lane_key changed)"
    summary
}

cmd_time() {
    capability_check
    graph_load
    echo "time: running every module SERIALLY — measurement only. \`zig build test\`"
    echo "(and this driver's own 'changed'/'all') run steps in PARALLEL, so per-module"
    echo "times captured from a parallel run are meaningless; this is deliberately slow."
    echo

    local rows
    rows="$(mktemp)"
    local i name t0 t1 dur rc out
    out="$(mktemp)"
    for (( i = 0; i < ${#G_NAMES[@]}; i++ )); do
        name="${G_NAMES[$i]}"
        rc=0
        t0=$(_now)
        case " $NETNS_MODULES " in
            *" $name "*)
                if have_unshare; then
                    unshare -rn zig build "test-$name" >"$out" 2>&1 || rc=$?
                else
                    zig build "test-$name" >"$out" 2>&1 || rc=$?
                fi
                ;;
            *)
                zig build "test-$name" >"$out" 2>&1 || rc=$?
                ;;
        esac
        t1=$(_now)
        dur=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}')
        printf '%s\t%s\t%s\n' "$dur" "$name" "$rc" >> "$rows"
        if [[ $rc -ne 0 ]]; then
            echo "time: $name FAILED (rc=$rc):" >&2
            cat "$out" >&2
        fi
        : > "$out"
    done
    rm -f "$out"

    echo "Duration-sorted (slowest first):"
    sort -t $'\t' -k1 -rn "$rows" | awk -F'\t' '{ status = ($3=="0" ? "" : "  [FAILED]"); printf "  %-24s %8ss%s\n", $2, $1, status }'
    rm -f "$rows"
}



cmd_vm() {
    if [[ $# -eq 0 ]]; then
        echo "usage: scripts/test.sh vm <module> [openwrt|debian] [--test-filter PATTERN]" >&2
        exit 1
    fi
    exec "$SCRIPT_DIR/vm/run.sh" "$@"
}

usage() {
    cat <<'EOF'
Usage: scripts/test.sh [subcommand] [args]

  changed [BASE_REF]   (default) test only modules affected by the current
                        working-tree/staged/untracked changes — or, with
                        BASE_REF, changes since that ref — plus their
                        reverse-dependency closure.
  all                   test every module: fmt check + check-catalog +
                        check-changelog + the full suite + the dark-test
                        check. The pre-commit/CI gate.
                        The dark-test check requires each module's declared
                        `^test ` count to EQUAL the `(N total)` its test binary
                        reports, so a file whose tests were never compiled —
                        which has no other symptom at all — fails the gate.
                        It reads the `--summary all` output of the run above
                        rather than making its own. See scripts/dark-tests.sh.
                        `zig build check-fuzz` IS included, in both `changed`
                        and `all`, unconditionally — it is a static source
                        scan and costs about a second warm. It was kept out
                        while it was red on modules with no fuzz harness;
                        that debt was burned down on 2026-08-14 and it went
                        in the same day. This paragraph said the opposite for
                        the few hours in between.
                        `zig build check-portable` likewise: it compiles every
                        `platform = .any` module for wasm32-freestanding, ~6s
                        cold for all 195 and near-free warm. It is the only
                        check here that can see a 32-bit-only failure, because
                        every lane in the CI matrix is 64-bit, arm64 included.
                        `zig build check-global-alloc` likewise: a static
                        source scan for `std.heap.page_allocator` and its
                        siblings reaching outside a caller-supplied allocator
                        (CONVENTIONS.md §1.2), sub-second warm.
                        `scripts/check-http-sizeprobe.sh` likewise: rebuilds
                        modules/http/sizeprobe/ (its own standalone build.zig,
                        x86_64-linux-musl only) and asserts the plaintext
                        http.Client entry points link zero TLS/certificate/
                        curve/hash symbols. ~30s when Client.zig's content
                        changed, near-instant otherwise (Zig's own cache).
  build [FLAGS]         the same gate as `all`, stopping after the compile:
                        every static check, then every module compiled, and no
                        test run at all. For the Debug lane, whose whole claim
                        is that this collection COMPILES in a mode nobody ships
                        in — an integrator developing against it does build in
                        Debug, and heavy modules are compiled in real Debug
                        nowhere else. Running the tests there was measured to
                        prove nothing the ReleaseSafe lane does not; see the
                        comment on cmd_build for the numbers.
                        ⚠ Does NOT update the module-graph snapshot: a run that
                        executed no test must not tell `changed` that anything
                        was covered.
  interop               PRE-RELEASE ONLY — re-take the interop anchors. Runs
                        every `modules/<m>/tools/interop.zig` against a REAL
                        foreign peer (wolfSSL, grpcio, Jinja2, google/brotli,
                        the protobuf runtime, sympy) and compares what the
                        peer says NOW against the committed transcript the
                        module replays. It VERIFIES: it leaves a clean tree and
                        goes red on divergence. Re-blessing is a flag a human
                        passes (`zig build interop-<m> -- --capture`), never
                        this command. `test-<m>` never needs
                        any of that — it replays a committed transcript and
                        passes on a host with no compiler and no Python. This
                        is the half replay cannot carry: replay proves we still
                        agree with what the peer said LAST time, and only this
                        can find that something new we send provokes a
                        different reaction, or that the peer moved. Needs
                        `scripts/ci-environment.sh interop`.
  ctgrind               PRE-RELEASE ONLY — take the constant-time measurement.
                        Runs `scripts/ctgrind.sh --check`: every committed
                        `modules/<m>/src/ctgrind_harness.zig` under
                        `valgrind --tool=memcheck`, compared against the 20
                        pinned rows of scripts/ctgrind-expected.tsv. This is
                        NOT `zig build check-ctgrind`, which only COMPILES the
                        harnesses as a rot guard and takes no measurement — a
                        harness can build perfectly and report a leak. Until
                        2026-09-08 no lane ran this at all, so those 20 claims
                        were verified by nothing. Needs
                        `scripts/ci-environment.sh ctgrind` (valgrind), and
                        FAILS rather than skips without it. 310 s warm for all
                        8 modules.
  time                  run every module SERIALLY, print a duration-sorted
                        table. Slow; measurement only, never use this to
                        decide what to run.
  vm <module> [plat]    OPT-IN ONLY — never part of `changed`/`all`, which
                        exist to be fast. Boots a disposable QEMU VM (real
                        root, no host namespace tricks) and runs one
                        module's tests for real inside it — for the gaps
                        `unshare -rn` cannot close: tc's RTM_NEWACTION
                        (needs CAP_NET_ADMIN in the *initial* user
                        namespace) and any netlink/nftables/wireguard write
                        that would otherwise collide with host state.
                        `plat` is openwrt or debian; omit it to use the
                        routing table in scripts/vm/run.sh. First run:
                        `scripts/vm/fetch-images.sh`. See scripts/vm/README.md.
Every runner begins with a capability check. It is silent when this host can
run everything; otherwise it names each gap, what coverage it costs, and the
exact least-privileged command that closes it. Those commands are only ever
printed — the driver runs nothing privileged or networked for you.

Which do I run? While working: `changed` (fast, scoped). Before committing:
`all` (the full, authoritative gate). Closing a real-root gap that `changed`/
`all` can only skip and print a fix command for: `vm`.

`checks-fast`, `checks`, `modules` and `examples` are the four phases `all`
runs in one process, split so CI can put them in separate jobs — one lane per
(phase, optimize mode, arch). They are not a menu for people: running them by
hand in sequence is `all` with more typing and no graph snapshot in between.
The split exists because the halves share no compilation (a module is compiled
once for its test binary and once for its example, and Zig caches whole
compilations) and because the ReleaseFast lane cleared its 90-minute cap by 23
seconds on 2026-08-24.
EOF
}

main() {
    local cmd="${1:-changed}"
    local -a rest=()
    [[ $# -gt 0 ]] && rest=("${@:2}")
    case "$cmd" in
        changed) cmd_changed "${rest[@]:-}" ;;
        all) cmd_all "${rest[@]:-}" ;;
        build) cmd_build "${rest[@]:-}" ;;
        checks-fast) cmd_checks_fast ;;
        checks) cmd_checks ;;
        modules) cmd_modules "${rest[@]:-}" ;;
        examples) cmd_examples "${rest[@]:-}" ;;
        interop) cmd_interop "${rest[@]:-}" ;;
        ctgrind) cmd_ctgrind "${rest[@]:-}" ;;
        time) cmd_time "${rest[@]:-}" ;;
        vm) cmd_vm "${rest[@]:-}" ;;
        -h|--help|help) usage ;;
        *)
            echo "test.sh: unknown subcommand '$cmd'" >&2
            usage >&2
            exit 1
            ;;
    esac
}

main "$@"
