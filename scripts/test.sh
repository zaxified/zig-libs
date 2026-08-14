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
    local name heavy deps
    while IFS=$'\t' read -r name heavy deps; do
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
    step "check-catalog" zig build check-catalog
    step "check-changelog" zig build check-changelog
    step "check-testonly" zig build check-testonly
    step "check-ctgrind" zig build check-ctgrind
    step "check-fuzz" zig build check-fuzz
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
run_modules() {
    local mods="$1"
    [[ -z "${mods// /}" ]] && return 0

    local -a rest=() netns=()
    local m
    for m in $mods; do
        case " $NETNS_MODULES " in
            *" $m "*) netns+=("$m") ;;
            *) rest+=("$m") ;;
        esac
    done

    _ZL_KEEP_OUT="$(mktemp)"

    if [[ ${#rest[@]} -gt 0 ]]; then
        local -a targets=()
        for m in "${rest[@]}"; do targets+=("test-$m"); done
        step "build+test (${#rest[@]} modules)" zig build "${targets[@]}" --summary all "${EXTRA_ZIG_ARGS[@]}"
    fi

    if [[ ${#netns[@]} -gt 0 ]]; then
        local -a targets=()
        for m in "${netns[@]}"; do targets+=("test-$m"); done
        if have_unshare; then
            step "netns build+test (${#netns[@]} modules, unshare -rn)" unshare -rn zig build "${targets[@]}" --summary all "${EXTRA_ZIG_ARGS[@]}"
        else
            echo "note: unshare -rn unavailable — running netns-gated modules plainly; their privileged tests will SKIP" >&2
            step "netns build+test (${#netns[@]} modules, NO unshare)" zig build "${targets[@]}" --summary all "${EXTRA_ZIG_ARGS[@]}"
        fi
    fi

    local log="$_ZL_KEEP_OUT"
    _ZL_KEEP_OUT=""
    dark_check "$mods" "$log"
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
            .github/*|scripts/test.sh|scripts/test-lib.sh|scripts/capped)
                # The harness or the CI lane definition itself: no narrower set
                # can be trusted, because what narrows it is the thing that
                # changed.
                trigger_all=1
                ;;
            scripts/*)
                ;; # scripts/README.md, scripts/vm/** — no effect on this lane
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
    local zig_changed
    zig_changed=$(printf '%s\n' "$files" | grep -E '\.zig$' || true)
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

    if [[ -z "$closure" ]]; then
        graph_save
        summary
        exit 0
    fi

    run_modules "$closure"
    graph_save
    summary
}

cmd_all() {
    # Drop empty arguments rather than passing them on: main dispatches with
    # "${rest[@]:-}", which expands an EMPTY array to one empty string, and
    # `zig build ""` fails with `no step named ''`. Filtering here keeps this
    # correct no matter how the caller quotes.
    EXTRA_ZIG_ARGS=()
    local a
    for a in "$@"; do [[ -n "$a" ]] && EXTRA_ZIG_ARGS+=("$a"); done
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
    step "hook self-test" ./scripts/hooks/test-pre-commit.sh
    step "tag.sh self-test" ./scripts/test-tag.sh
    step "check-catalog" zig build check-catalog
    step "check-changelog" zig build check-changelog
    step "check-testonly" zig build check-testonly
    step "check-fuzz" zig build check-fuzz
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
