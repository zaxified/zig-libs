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
if [[ -z "${TMPDIR:-}" || "$TMPDIR" == "/tmp" ]]; then
    _zl_disk_tmp="$REPO_ROOT/.zig-cache/gate-tmp"
    mkdir -p "$_zl_disk_tmp"
    export TMPDIR="$_zl_disk_tmp"
fi

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
G_TSV=""
GRAPH_ADDED=""

# Populates G_NAMES/G_HEAVY/G_DEPS from `zig build module-graph`. Never
# silently proceeds with an empty/partial graph — a build failure here
# would otherwise look identical to "nothing changed", the exact silent
# no-op class of bug this driver must not have.
graph_load() {
    G_NAMES=(); G_HEAVY=(); G_DEPS=()
    local tsv
    if ! tsv="$(zig build module-graph 2>&1)"; then
        echo "test.sh: 'zig build module-graph' failed — refusing to guess the module set:" >&2
        echo "$tsv" >&2
        exit 1
    fi
    G_TSV="$tsv"
    local name heavy deps live ct
    while IFS=$'\t' read -r name heavy deps live ct; do
        [[ -z "$name" ]] && continue
        G_NAMES+=("$name")
        G_HEAVY+=("$heavy")
        G_DEPS+=("$deps")
    done <<< "$tsv"
    if [[ ${#G_NAMES[@]} -eq 0 ]]; then
        echo "test.sh: 'zig build module-graph' produced zero modules — refusing to pass vacuously" >&2
        exit 1
    fi
}

# ── graph snapshot ──────────────────────────────────────────────────────────
# Touching build.zig used to escalate straight to the full run, on the
# reasoning that the dependency graph might have changed. Usually it has not:
# ADDING a module appends one row to `module_list` and cannot affect any
# existing module. Paying the full gate for that is the driver being wrong, not
# careful — and a gate that expensive for a routine edit is one people learn to
# skip, which costs more than it saves.
#
# So the escalation is decided by the GRAPH, not by which file was saved. The
# last known-good graph is kept beside the build cache and compared row by row:
#
#   rows only in the new graph        -> modules were added; test just those
#   any row missing or altered       -> a module changed shape or vanished, and
#                                       the reverse-dep closure can no longer be
#                                       trusted -> full run
#   no snapshot yet                  -> nothing to compare against -> full run
#
# This keeps the driver's existing rule that `zig build module-graph` is the
# only authority on the module set; it still never parses build.zig.
GRAPH_SNAPSHOT=".zig-cache/ziglibs-graph.tsv"

graph_save() {
    [[ -n "$G_TSV" ]] || return 0
    mkdir -p "$(dirname "$GRAPH_SNAPSHOT")" 2>/dev/null || return 0
    printf '%s\n' "$G_TSV" > "$GRAPH_SNAPSHOT" 2>/dev/null || true
}

# Sets GRAPH_ADDED to the modules whose graph row was ADDED or ALTERED and
# returns 0. Returns 1 only when there is no snapshot to compare against.
#
# A module that gained or lost a dependency is a precisely answerable question,
# not a reason to run everything: the module itself changed shape, so retest it
# and — via the ordinary reverse-dependency closure, computed from the NEW graph
# — everything built on top of it. That is the same rule the rest of this driver
# already uses; there is nothing special about the edge having moved.
#
# ⭐ A REMOVED module needs no special case either, which is not obvious. The
# worry is that what used to depend on it is knowable only from the OLD graph.
# But a dependent cannot quietly survive its dependency's deletion:
#
#   * if the dependent's own row was updated to drop it, that row CHANGED, so
#     the dependent is seeded here and its closure covers everything above it;
#   * if it was not updated, it now declares a dependency on a module that does
#     not exist — and `zig build module-graph` ABORTS (verified: deleting
#     `protobuf` while `grpc` still names it terminates the build with SIGABRT).
#     graph_load then refuses to guess a module set and exits, so nothing runs
#     on a graph nobody can trust.
#
# So removals are simply ignored: either they are already covered, or there is
# no working graph to test against in the first place.
graph_added_only() {
    GRAPH_ADDED=""
    [[ -f "$GRAPH_SNAPSHOT" ]] || return 1
    # Rows present now but not in the snapshot: a module that was added, or one
    # whose row was edited (an edit shows up as a removal plus an addition, and
    # the addition is the one that matters — it carries the current shape).
    #
    # LC_ALL=C is load-bearing, not hygiene: `sort` collates by locale while
    # `comm` compares bytewise, so under cs_CZ comm reads its input as unsorted
    # and silently returns a WRONG answer — one that fails open, i.e. seeds too
    # little and under-tests. Its "file 1 is not in sorted order" warning goes
    # to stderr and is easy to miss because the result still looks plausible.
    GRAPH_ADDED="$(comm -13 <(LC_ALL=C sort "$GRAPH_SNAPSHOT") <(printf '%s\n' "$G_TSV" | LC_ALL=C sort) | cut -f1 | tr '\n' ' ')"
    return 0
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
    step "check-uapi" zig build check-uapi
    step "check-changelog" zig build check-changelog
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
    run_modules "$plain $netns"
    graph_save
    summary
}

module_exists() {
    local target="$1" n
    for n in "${G_NAMES[@]}"; do
        [[ "$n" == "$target" ]] && return 0
    done
    return 1
}

# Reverse-dependency closure: given a space-separated seed set of changed
# module names, returns the seeds plus every module that transitively
# depends ON one of them (NOT the modules a seed depends on — that's the
# opposite, wrong direction: if A depends on B and B changes, A must be
# retested, not the reverse). Correctness-critical; see the worked rsa
# example in scripts/README.md and the task report.
reverse_closure() {
    local seeds="$1"
    local result=" " s
    for s in $seeds; do
        case "$result" in *" $s "*) ;; *) result="$result$s " ;; esac
    done
    local frontier="$result"
    local changed=1
    while [[ $changed -eq 1 ]]; do
        changed=0
        local new_frontier=" "
        local i
        for (( i = 0; i < ${#G_NAMES[@]}; i++ )); do
            local name="${G_NAMES[$i]}"
            case "$result" in *" $name "*) continue ;; esac
            local deps="${G_DEPS[$i]}"
            [[ -z "$deps" ]] && continue
            local hit=0 d
            for d in ${deps//,/ }; do
                case "$frontier" in *" $d "*) hit=1; break ;; esac
            done
            if [[ $hit -eq 1 ]]; then
                result="$result$name "
                new_frontier="$new_frontier$name "
                changed=1
            fi
        done
        frontier="$new_frontier"
    done
    printf '%s' "$result"
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
            step "live interop: $m" zig build "test-$m" --summary all --test-timeout "$TEST_TIMEOUT" "${EXTRA_ZIG_ARGS[@]}"
        done
    fi

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

    # dtls's live third-party interop compiles a small wolfSSL peer with cc.
    # Both are needed: no compiler, or no wolfSSL headers/library, and the
    # tests skip. wolfSSL is the DTLS 1.3 peer here because OpenSSL 3.5.5 and
    # GnuTLS 3.8.12 have no DTLS 1.3 at all.
    if ! command -v cc >/dev/null 2>&1; then
        gaps+=("no C compiler (cc)|2 dtls live wolfSSL interop tests skip|sudo apt install build-essential")
    elif [[ ! -e /usr/include/wolfssl/ssl.h ]]; then
        gaps+=("wolfSSL headers missing|2 dtls live wolfSSL interop tests skip|sudo apt install libwolfssl-dev")
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
        gaps+=("python lacks jinja2|the whole jinja live-reference suite skips — 337 corpus cases stop being checked against the real engine|pip install 'jinja2==${golden_j2:-3.1.6}'")
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
    # `interpreter()` in its reference_interop.zig). Probing `python3` for all
    # four reported a grpcio gap on a host where grpc's tests were running fine
    # from its venv — a false gap, which spends the reader's trust in exactly
    # the report that most needs it.
    #
    # ⚠ AND IT MUST IMPORT EVERYTHING THAT INTERPRETER WILL BE ASKED TO IMPORT.
    # `grpc` is one entry with two packages: both of its oracle scripts import
    # `google.protobuf` as well as `grpc`, and a venv sees no system
    # site-packages, so "grpcio is installed" is not the question. Probing only
    # `grpc` reported no gap on a runner whose venv had exactly that, and the
    # test then failed on the missing import rather than skipping.
    local oracle
    for oracle in \
        "grpc, google.protobuf|grpcio protobuf|zig-libs-grpc|15 grpc reference-interop tests (the gRPC wire format against a real grpcio peer)" \
        "sympy|sympy||5 poseidon subspace-trail tests (the algebraic attack bound, recomputed rather than trusted)" \
        "brotli|brotli||4 brotli reference-interop tests (round-trips against google/brotli itself)" \
        "google.protobuf|protobuf||9 protobuf reference-interop tests (our encoding against the upstream Python runtime)"
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
            || gaps+=("python lacks $pkg|up to $cost skip|$fix")
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
    local base_ref="${1:-}"
    local files
    if ! files="$(changed_files "$base_ref")"; then
        echo "changed: base ref '$base_ref' does not resolve here — cannot compute a narrower set," >&2
        echo "         so running everything rather than reporting nothing to do." >&2
        cmd_all "${@:2}"
        return
    fi
    files="$(printf '%s\n' "$files" | sort -u)"

    if [[ -z "$files" ]]; then
        echo "changed: no changed/staged/untracked files$( [[ -n "$base_ref" ]] && echo " vs $base_ref" ) — nothing to test"
        exit 0
    fi

    capability_check

    local trigger_all=0 trigger_catalog=0 trigger_graph=0 trigger_changelog=0
    local seeds=" " f name
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        case "$f" in
            modules/*/*)
                name="${f#modules/}"
                name="${name%%/*}"
                case "$seeds" in *" $name "*) ;; *) seeds="$seeds$name " ;; esac
                ;;
            build.zig|build.zig.zon)
                # Might have changed the graph — ask the graph, do not assume.
                trigger_graph=1
                ;;
            .github/*|scripts/test.sh|scripts/test-lib.sh|scripts/capped|scripts/dark-tests.sh|scripts/ci-environment.sh|scripts/test-tag.sh|scripts/check-ci-cache-keys.sh|scripts/hooks/*)
                # The harness or the CI lane definition itself: no narrower set
                # can be trusted, because what narrows it is the thing that
                # changed.
                #
                # ⚠ The membership rule is "the gate EXECUTES it", not "it lives
                # in scripts/". Four of these were missing until 2026-08-15 and
                # each was the same hole: `dark-tests.sh` decides which tests
                # count as dark, `ci-environment.sh` decides which live peers
                # exist on a runner, and `test-tag.sh` plus `hooks/*` are run as
                # gate steps in their own right. Editing any of them changes
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

    echo "changed: $(printf '%s\n' "$files" | wc -l) file(s) changed$( [[ -n "$base_ref" ]] && echo " vs $base_ref" )"

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
            cmd_all
            return
        fi
        harness_smoke
        return
    fi

    if [[ $trigger_graph -eq 1 ]]; then
        if graph_added_only; then
            if [[ -n "${GRAPH_ADDED// /}" ]]; then
                echo "changed: build.zig touched -> graph rows added/altered: ${GRAPH_ADDED% } (seeded; the reverse-dep closure below covers the rest)"
                seeds="$seeds$GRAPH_ADDED"
            else
                # Also the "only removals" case: nothing gained or altered a
                # row, so there is nothing extra to seed (see graph_added_only
                # on why a removal needs no special handling).
                echo "changed: build.zig touched, but no module gained or altered a graph row -> nothing extra to seed"
            fi
        else
            echo "changed: no graph snapshot to compare against -> nothing to narrow with -> running ALL modules"
            cmd_all
            return
        fi
    fi

    local -a valid_seeds=()
    for name in $seeds; do
        # A module can be seeded twice -- once because its own files changed and
        # once because build.zig gained a graph row for it, which is exactly what
        # adding a module does. The closure below dedups, so a duplicate here
        # only corrupted the reported counts (a NEGATIVE reverse-dep count).
        case " ${valid_seeds[*]} " in *" $name "*) continue ;; esac
        if module_exists "$name"; then
            valid_seeds+=("$name")
        else
            echo "changed: warning: modules/$name/ changed but '$name' is not in the module graph — ignoring" >&2
        fi
    done

    if [[ ${#valid_seeds[@]} -eq 0 && $trigger_catalog -eq 0 && $trigger_changelog -eq 0 ]]; then
        echo "changed: no modules affected — nothing to test"
        graph_save
        exit 0
    fi

    local closure="" pulled_only=""
    if [[ ${#valid_seeds[@]} -gt 0 ]]; then
        closure="$(reverse_closure "${valid_seeds[*]}")"
        local m
        for m in $closure; do
            case " ${valid_seeds[*]} " in *" $m "*) ;; *) pulled_only="$pulled_only$m " ;; esac
        done
    fi

    local changed_n=${#valid_seeds[@]}
    local total_n
    total_n=$( [[ -n "$closure" ]] && echo $closure | wc -w || echo 0 )
    local pulled_n=$(( total_n - changed_n ))

    echo "changed: $changed_n module(s) directly changed, $pulled_n pulled in via reverse-dep closure -> $total_n to test"
    [[ ${#valid_seeds[@]} -gt 0 ]] && echo "  changed:    ${valid_seeds[*]}"
    [[ -n "$pulled_only" ]] && echo "  reverse-dep: $pulled_only"

    if [[ $trigger_catalog -eq 1 ]]; then
        step "check-catalog (README.md changed)" zig build check-catalog
    fi

    # Unconditional for the same reason as `check-testonly` below, and reached
    # by both paths that get here: a changed module (its own CHANGELOG.md is
    # under modules/, so it seeded the module) and a changed root CHANGELOG.md
    # (`trigger_changelog`, which is what keeps the early exit above from
    # skipping this).
    step "check-changelog" zig build check-changelog

    # Always: a testkit leak into published code is introduced by editing a
    # MODULE, not build.zig, so there is no change signal to gate this on --
    # and it is ~0.5s cold, ~0.15s warm, so gating would save nothing.
    step "check-testonly" zig build check-testonly

    # Same reasoning as `check-testonly` above: ~0.1s warm, and the change
    # signal that would gate it (editing a harness, or editing the module it
    # measures) is exactly what a developer is doing when it matters.
    step "check-ctgrind" zig build check-ctgrind

    # Unconditional for the same reason, and sub-second warm. It was absent
    # from this driver until 2026-08-14, which is why nobody noticed it had
    # been red for weeks on 21 modules: a gate that exists and is never invoked
    # makes the same claim a skipped test makes, which is that someone looked.
    step "check-fuzz" zig build check-fuzz
    step "check-global-alloc" zig build check-global-alloc

    # 32-bit compile of every `platform = .any` module. ~6s cold for all 195,
    # near-free warm, and it is the only thing in this gate that can see a class
    # the whole CI matrix is blind to: every lane is 64-bit, arm64 included, so
    # `usize` is 64 bits everywhere the suite has ever run. `platform = .any`
    # covers wasm32 and arm32 too, and until this step existed nothing had ever
    # compiled for either.
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
    step "check-http-sizeprobe" ./scripts/check-http-sizeprobe.sh

    if [[ -z "$closure" ]]; then
        graph_save
        summary
        exit 0
    fi

    run_modules "$closure"
    graph_save
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
cmd_build() {
    GATE_BUILD_ONLY=1
    cmd_all "$@"
}

GATE_BUILD_ONLY=0

cmd_all() {
    # Drop empty arguments rather than passing them on: main dispatches with
    # "${rest[@]:-}", which expands an EMPTY array to one empty string, and
    # `zig build ""` fails with `no step named ''`. Filtering here keeps this
    # correct no matter how the caller quotes.
    EXTRA_ZIG_ARGS=()
    local a
    for a in "$@"; do [[ -n "$a" ]] && EXTRA_ZIG_ARGS+=("$a"); done
    # ⚠ The capability report answers "which TESTS will silently cover less on
    # this host", so it has nothing to say about a run that executes none. In
    # build-only mode it listed six gaps against a lane that could not have used
    # any of them — noise shaped exactly like a coverage warning, which is the
    # one thing that report must never be.
    (( GATE_BUILD_ONLY )) || capability_check
    graph_load
    local all_mods="${G_NAMES[*]}"
    local n=${#G_NAMES[@]}
    if (( GATE_BUILD_ONLY )); then
        echo "build: COMPILING every module ($n total) and running NO tests — see cmd_build for why"
    else
        echo "all: running every module ($n total, $(printf '%s\n' "${G_HEAVY[@]}" | grep -c heavy) heavy) — the pre-commit/CI gate"
    fi
    step "fmt check" zig fmt --check build.zig build.zig.zon modules
    # `af6a148` is why the fmt step is first and why the hook exists: six files
    # had drifted out of fmt, the gate stops on the first failure, and so NO
    # module was being tested locally at all. The hook stops that landing in a
    # commit -- but only while the hook itself works, which is what this checks.
    step "hook self-test" ./scripts/hooks/test-pre-commit.sh
    step "tag.sh self-test" ./scripts/test-tag.sh
    step "check-ci-cache-keys" ./scripts/check-ci-cache-keys.sh
    step "check-scripts-doc" zig build check-scripts-doc
    step "check-package" zig build check-package
    step "check-catalog" zig build check-catalog
    step "check-uapi" zig build check-uapi
    step "check-changelog" zig build check-changelog
    step "check-testonly" zig build check-testonly
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
    # See cmd_changed's comment on this same step for what it checks.
    step "check-http-sizeprobe" ./scripts/check-http-sizeprobe.sh
    # The ctgrind harnesses (`modules/*/src/ctgrind_harness.zig`) are standalone
    # programs nothing else builds: they are not tests, and `scripts/ctgrind.sh`
    # -- which needs valgrind -- is deliberately NOT in this gate. Left alone
    # they would rot into unbuildable recipes the first time a module's API
    # moved, and the SPEC.md tables they back would silently become claims
    # nobody can re-take. This compiles them (semantic analysis only; the build
    # system emits no binary because nothing asks for one) and runs no valgrind:
    # ~0.1s warm. It is spelled out here rather than left to `zig build test`'s
    # dependency on it, because this driver never runs `zig build test` -- it
    # runs `test-<module>` per module, so anything hung off the aggregate step
    # alone would never execute in the gate.
    step "check-ctgrind" zig build check-ctgrind

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
    if (( GATE_BUILD_ONLY )); then
        # This lane runs no test, so there is no `--summary all` to digest and
        # nothing lands on the run's page. A lane that contributes NOTHING there
        # reads as one that failed to report, not as one with nothing to report,
        # and on 2026-08-15 three of four lanes had a block and this one did not.
        # One line, saying what it did and what that is worth.
        if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
            printf '### %s\n\n```\n  %-16s %d modules compiled, 0 tests run (see cmd_build)\n```\n\n' \
                "${ZIGLIBS_LANE:-gate}" "compile only:" "$n" >> "$GITHUB_STEP_SUMMARY"
        fi
        # ⚠ The graph snapshot is NOT saved here. It is what `changed` uses to
        # decide it may run a narrow set, and a run that executed no test has no
        # business telling the next one that anything was covered.
        summary
        return
    fi
    run_modules "$all_mods"
    graph_save
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
