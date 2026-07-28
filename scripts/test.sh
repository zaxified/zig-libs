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
#     script can do about that short of real root; the capability check
#     prints the one-off `sudo unshare -n zig build test-tc` for it.
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
            echo "note: unshare -rn unavailable — running netns-gated modules plainly; their privileged tests will SKIP" >&2
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
        gaps+=("unshare -rn unavailable|netlink writes in $NETNS_MODULES run unsandboxed (netlink then FAILS, it does not skip)|$fix")
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

    # opcua's asyncua interop drives a Python client; the interpreter needs
    # asyncua + cryptography. This is a separate gate from podman — the
    # container-backed tests pass without it.
    local opcua_py="${OPCUA_PYTHON:-python3}"
    if ! "$opcua_py" -c 'import asyncua, cryptography' >/dev/null 2>&1; then
        gaps+=("python lacks asyncua/cryptography|1 opcua live asyncua-interop test skips|python3 -m venv ~/.cache/zig-libs-opcua && ~/.cache/zig-libs-opcua/bin/pip -q install asyncua cryptography && echo 'export OPCUA_PYTHON=~/.cache/zig-libs-opcua/bin/python3' >> ~/.bashrc")
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
    files="$(changed_files "$base_ref" | sort -u)"

    if [[ -z "$files" ]]; then
        echo "changed: no changed/staged/untracked files$( [[ -n "$base_ref" ]] && echo " vs $base_ref" ) — nothing to test"
        exit 0
    fi

    capability_check

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
    capability_check
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
Every runner begins with a capability check. It is silent when this host can
run everything; otherwise it names each gap, what coverage it costs, and the
exact least-privileged command that closes it. Those commands are only ever
printed — the driver runs nothing privileged or networked for you.

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
        -h|--help|help) usage ;;
        *)
            echo "test.sh: unknown subcommand '$cmd'" >&2
            usage >&2
            exit 1
            ;;
    esac
}

main "$@"
