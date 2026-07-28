#!/usr/bin/env bash
# Test driver for zig-libs. `zig build test` runs all 210 modules and takes
# ~5 minutes — fine for CI, absurd in a change/build/test loop where you
# touched one module and are waiting on 209 unrelated ones. `changed` (the
# default) works out which modules a change can actually affect, using
# `zig build module-graph` (the authoritative dependency graph — this
# script never parses build.zig) plus the reverse-dependency closure of
# that set, and tests only those.
#
# Usage:
#   scripts/test.sh                 — same as `changed` with no BASE_REF
#   scripts/test.sh changed [REF]   — test what changed (vs REF, or the
#                                     working tree/index/untracked files)
#   scripts/test.sh all             — every module; the pre-commit/CI gate
#   scripts/test.sh time             — serial per-module timing table
#   scripts/test.sh env              — read-only host capability report
#   scripts/test.sh prepare [--yes]  — close fixable environment gaps
#
# See scripts/README.md for the long version of each subcommand.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/test-lib.sh"
export ZIGLIBS_TEST_T0="$(_now)"

cd "$REPO_ROOT"

# Modules whose tests open AF_NETLINK/raw sockets gated on CAP_NET_ADMIN or
# CAP_NET_RAW *in the current network namespace* — `unshare -rn` (an
# unprivileged user+net namespace, mapped to root inside it) is enough to
# grant those and let the tests actually run instead of skipping.
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
#     script can do about that short of real root — see `env`/`prepare`.
NETNS_MODULES="netlink genetlink nl80211 ethtool devlink tc conntrack nftables wireguard rawsock"

# ── module-graph plumbing ────────────────────────────────────────────────

G_NAMES=()
G_HEAVY=()
G_DEPS=()

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

# run_modules "mod1 mod2 ..." — partitions the set into NETNS_MODULES vs the
# rest and invokes each partition as ONE `zig build test-a test-b ...`
# command (not a loop of 1-module invocations!) so zig's own step
# parallelism is preserved; only the netns partition is wrapped in
# `unshare -rn`, and only when it's actually available.
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

    if [[ ${#rest[@]} -gt 0 ]]; then
        local -a targets=()
        for m in "${rest[@]}"; do targets+=("test-$m"); done
        step "build+test (${#rest[@]} modules)" zig build "${targets[@]}"
    fi

    if [[ ${#netns[@]} -gt 0 ]]; then
        local -a targets=()
        for m in "${netns[@]}"; do targets+=("test-$m"); done
        if have_unshare; then
            step "netns build+test (${#netns[@]} modules, unshare -rn)" unshare -rn zig build "${targets[@]}"
        else
            echo "note: unshare -rn unavailable — running netns-gated modules plainly; their privileged tests will SKIP (see \`scripts/test.sh env\`)" >&2
            step "netns build+test (${#netns[@]} modules, NO unshare)" zig build "${targets[@]}"
        fi
    fi
}

# ── file -> module mapping ───────────────────────────────────────────────

changed_files() {
    local base_ref="$1"
    if [[ -n "$base_ref" ]]; then
        { git diff --name-only "$base_ref" --
          git ls-files --others --exclude-standard
        } 2>/dev/null
    else
        { git diff --name-only
          git diff --cached --name-only
          git ls-files --others --exclude-standard
        } 2>/dev/null
    fi
}

# ── subcommands ──────────────────────────────────────────────────────────

cmd_changed() {
    local base_ref="${1:-}"
    local files
    files="$(changed_files "$base_ref" | sort -u)"

    if [[ -z "$files" ]]; then
        echo "changed: no changed/staged/untracked files$( [[ -n "$base_ref" ]] && echo " vs $base_ref" ) — nothing to test"
        exit 0
    fi

    local trigger_all=0 trigger_catalog=0
    local seeds=" " f name
    while IFS= read -r f; do
        [[ -z "$f" ]] && continue
        case "$f" in
            modules/*/*)
                name="${f#modules/}"
                name="${name%%/*}"
                case "$seeds" in *" $name "*) ;; *) seeds="$seeds$name " ;; esac
                ;;
            build.zig|build.zig.zon|.github/*|scripts/*)
                trigger_all=1
                ;;
            README.md)
                trigger_catalog=1
                ;;
            CHANGELOG.md|NOTICE|CONVENTIONS.md)
                ;; # root docs with no module impact
            *)
                ;; # unrecognized root-level file — no module impact
        esac
    done <<< "$files"

    echo "changed: $(printf '%s\n' "$files" | wc -l) file(s) changed$( [[ -n "$base_ref" ]] && echo " vs $base_ref" )"

    if [[ $trigger_all -eq 1 ]]; then
        echo "changed: build.zig / build.zig.zon / .github / scripts touched -> the module graph or the harness itself may have changed -> running ALL modules"
        cmd_all
        return
    fi

    graph_load

    local -a valid_seeds=()
    for name in $seeds; do
        if module_exists "$name"; then
            valid_seeds+=("$name")
        else
            echo "changed: warning: modules/$name/ changed but '$name' is not in the module graph — ignoring" >&2
        fi
    done

    if [[ ${#valid_seeds[@]} -eq 0 && $trigger_catalog -eq 0 ]]; then
        echo "changed: no modules affected — nothing to test"
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

    if [[ -z "$closure" ]]; then
        summary
        exit 0
    fi

    run_modules "$closure"
    summary
}

cmd_all() {
    graph_load
    local all_mods="${G_NAMES[*]}"
    local n=${#G_NAMES[@]}
    echo "all: running every module ($n total, $(printf '%s\n' "${G_HEAVY[@]}" | grep -c heavy) heavy) — the pre-commit/CI gate"
    step "fmt check" zig fmt --check build.zig build.zig.zon modules
    step "check-catalog" zig build check-catalog
    run_modules "$all_mods"
    summary
}

cmd_time() {
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

cmd_env() {
    echo "Environment capability report (read-only — changes nothing):"
    echo

    local unshare_ok=no
    if command -v unshare >/dev/null 2>&1 && unshare -rn true >/dev/null 2>&1; then
        unshare_ok=yes
    fi

    local podman_ok=no
    command -v podman >/dev/null 2>&1 && podman_ok=yes

    local image_ok=no
    if [[ "$podman_ok" == yes ]] && podman image exists docker.io/open62541/open62541:latest 2>/dev/null; then
        image_ok=yes
    fi

    local sudo_ok=no
    sudo -n true >/dev/null 2>&1 && sudo_ok=yes

    printf '  %-32s %-4s  %s\n' "unshare -rn" "$unshare_ok" \
        "$( [[ $unshare_ok == yes ]] && echo "gates: $NETNS_MODULES" || echo "fix: install util-linux unshare + unprivileged userns clone" )"
    printf '  %-32s %-4s  %s\n' "podman" "$podman_ok" \
        "$( [[ $podman_ok == yes ]] && echo "gates: opcua LIVE server-interop" || echo "fix: install podman (podman.io/docs/installation)" )"
    printf '  %-32s %-4s  %s\n' "open62541 image pulled" "$image_ok" \
        "$( [[ $image_ok == yes ]] && echo "-" || echo "fix: podman pull docker.io/open62541/open62541:latest" )"
    printf '  %-32s %-4s  %s\n' "sudo -n (passwordless)" "$sudo_ok" \
        "$( [[ $sudo_ok == yes ]] && echo "-" || echo "fix: passwordless sudo for this user (visudo), or run gated commands interactively" )"

    echo
    echo "Modules whose tests stay (partly) skipped as a result of the gaps above:"
    if [[ "$unshare_ok" != yes ]]; then
        echo "  - $NETNS_MODULES"
        echo "      (no unshare -rn -> CAP_NET_ADMIN/CAP_NET_RAW-gated live tests SKIP)"
    fi
    if [[ "$podman_ok" != yes || "$image_ok" != yes ]]; then
        echo "  - opcua"
        echo "      (LIVE open62541 server-interop tests need podman + the pulled image)"
    fi
    echo "  - tc (partial, regardless of the above)"
    echo "      (RTM_NEWACTION checks CAP_NET_ADMIN in the *initial* user namespace;"
    echo "       unshare -rn is not enough for that one path — needs real root, e.g."
    echo "       \`sudo unshare -n\`. Not fixable by \`prepare\` — sudo would have to run"
    echo "       interactively, which this driver refuses to do.)"

    echo
    echo "Run \`scripts/test.sh prepare\` to see (and, with --yes, close) the fixable gaps."
}

cmd_prepare() {
    local do_it=0
    [[ "${1:-}" == "--yes" ]] && do_it=1

    local podman_ok=no
    command -v podman >/dev/null 2>&1 && podman_ok=yes
    local need_pull=0
    if [[ "$podman_ok" == yes ]] && ! podman image exists docker.io/open62541/open62541:latest 2>/dev/null; then
        need_pull=1
    fi

    echo "prepare: gaps this can close automatically:"
    if [[ $need_pull -eq 1 ]]; then
        echo "  - podman pull docker.io/open62541/open62541:latest  (network action, ~565 MB;"
        echo "    unlocks opcua's LIVE server-interop tests)"
    elif [[ "$podman_ok" != yes ]]; then
        echo "  - (podman itself is missing — install it first; see \`scripts/test.sh env\`)"
    else
        echo "  - (nothing — the open62541 image is already pulled)"
    fi

    echo
    echo "Gaps this will NEVER attempt (report only):"
    if ! sudo -n true >/dev/null 2>&1; then
        echo "  - sudo -n fails here — tc's initial-userns CAP_NET_ADMIN gap needs real root"
        echo "    and this driver will never prompt for a password interactively."
    fi
    if ! { command -v unshare >/dev/null 2>&1 && unshare -rn true >/dev/null 2>&1; }; then
        echo "  - unshare -rn is unavailable on this host — a kernel/policy property, not"
        echo "    something this script can install."
    fi

    echo
    if [[ $do_it -ne 1 ]]; then
        echo "Dry run only (pass --yes to actually pull). Nothing was changed."
        exit 0
    fi

    if [[ $need_pull -eq 1 ]]; then
        echo "Pulling docker.io/open62541/open62541:latest ..."
        podman pull docker.io/open62541/open62541:latest
    else
        echo "Nothing to do."
    fi
}

usage() {
    cat <<'EOF'
Usage: scripts/test.sh [subcommand] [args]

  changed [BASE_REF]   (default) test only modules affected by the current
                        working-tree/staged/untracked changes — or, with
                        BASE_REF, changes since that ref — plus their
                        reverse-dependency closure.
  all                   test every module: fmt check + check-catalog + the
                        full suite. The pre-commit/CI gate.
  time                  run every module SERIALLY, print a duration-sorted
                        table. Slow; measurement only, never use this to
                        decide what to run.
  env                   read-only report of what this host can/can't do for
                        the netns- and podman-gated tests.
  prepare [--yes]       close the fixable environment gaps (currently: pull
                        the open62541 image). Dry-run unless --yes is given;
                        never touches anything needing interactive sudo.

Which do I run? While working: `changed` (fast, scoped). Before committing:
`all` (the full, authoritative gate).
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
        env) cmd_env "${rest[@]:-}" ;;
        prepare) cmd_prepare "${rest[@]:-}" ;;
        -h|--help|help) usage ;;
        *)
            echo "test.sh: unknown subcommand '$cmd'" >&2
            usage >&2
            exit 1
            ;;
    esac
}

main "$@"
