# Shared helpers for test.sh. Sourced; not executable on its own.
#
# Style note: no `declare -A` anywhere in these scripts, on purpose — macOS
# ships bash 3.2 (no associative arrays), where `declare -A` evaluates the
# key as arithmetic and errors out. "Sets" of module names are represented
# as space-padded strings (" a b c ") and tested with a `case " $s " in`
# glob, which works on any bash.

# ── the netns-wrapped module set ──────────────────────────────────────────
# Modules whose tests open AF_NETLINK/raw sockets gated on CAP_NET_ADMIN or
# CAP_NET_RAW *in the current network namespace* — `unshare -rn` (an
# unprivileged user+net namespace, mapped to root inside it) is enough to
# grant those and let the tests actually run instead of skipping. The long
# empirical justification, including why `icmp`/`traceroute`/`tc` are NOT in
# this list, is in test.sh at its only consumer of `run_modules`.
#
# It lives here, not in test.sh, because dark-tests.sh has to make the same
# split for the same reason (a module whose build FAILS prints no test count)
# and a second copy of this list would rot.
NETNS_MODULES="netlink genetlink nl80211 ethtool devlink tc conntrack nftables wireguard rawsock"

# ⭐ MODULES WHOSE TESTS HOLD A CONVERSATION WITH A REAL THIRD-PARTY PEER, and
# which therefore run SERIALLY, in their own step, after everything else.
#
# `opcua` drives an open62541 container and a Python asyncua client, `ssh` a
# real sshd and a real ssh client, `dtls` a wolfSSL responder, `imap` a pymap
# server. Each is a live protocol exchange with timeouts on BOTH ends, and none
# of them claims to hold those timings while 215 other test binaries saturate
# every core. That is not the property being tested — "our server interoperates
# with open62541" says nothing about eight-fold CPU oversubscription — so
# measuring it there measures the scheduler.
#
# Same reasoning as NETNS_MODULES above, which is split out because it needs a
# namespace; these need a machine that will schedule them.
#
# ⚠ WHAT THIS DOES NOT DO is make the harness robust under contention. Moving
# these out of the parallel bulk removes ACCIDENTAL stress coverage, and a green
# serial step is not evidence that anything was fixed.
#
# ⭐ AND THREE OF THESE FOUR HAVE NO EVIDENCE AGAINST THEM. This list was drawn
# by CATEGORY — "live peer with its own clock" — and on 2026-08-15 the category
# was finally tested instead of assumed: all four run CONCURRENTLY under seven
# of eight cores of load, three rounds.
#
#   opcua   failed 3 of 3 rounds (2, 3 and 2 failures of 176)
#   ssh     98/98,   every round
#   dtls    263/263, every round
#   imap    132/132, every round
#
# `ssh` is here because of the six-hour wall of 2026-08-14, whose cause turned
# out to be an OpenSSH version predating `mlkem768x25519-sha256` — diagnosed and
# closed, and nothing to do with contention. `dtls` and `imap` are here because
# they resemble `opcua`.
#
# That experiment also FOUND a defect the serial step had been hiding: the
# driver tore a finished connection down AFTER deciding whether to accept the
# next one, so a client that disconnects and reconnects — which open62541's
# `client` and `client_encryption` both do — got its reconnect closed. Fixed;
# the same reproduction now passes 4 of 4.
#
# ⛔ ALL FOUR STAY SERIAL ANYWAY (owner's decision, 2026-08-15), to be revisited
# once this has been quiet for a while. The serial step costs ~65 s and makes
# the gate's verdict a statement about our protocol rather than about the
# scheduler. What it does NOT do is reduce risk: it reduces DETECTION, and the
# defect above sat in the tree for a day because of it. The reproduction is one
# command — run the four `zig build test-*` targets together with `nproc - 1`
# busy loops — and it belongs in a session that is looking for this, not in
# every gate run.
#
# `jinja` is deliberately absent: its live peer is a Python script it runs to
# completion, not a network peer with a clock, and its one failure this week was
# a version drift in the oracle.
# DERIVED, not listed. The set itself is declared once, as `.live` on the
# module_list entry in build.zig, and published by `zig build module-graph`
# (column 4). It used to be spelled out here and consumed by three scripts, so
# a module that gained a live peer and was not added kept running in parallel
# -- the exact failure this variable exists to prevent, invisible until it went
# flaky. Queried once and cached; callers use `$(live_modules)`.
_ZL_LIVE_CACHE=""
live_modules() {
    if [[ -z "$_ZL_LIVE_CACHE" ]]; then
        _ZL_LIVE_CACHE="$(zig build module-graph 2>/dev/null | awk -F'\t' '$4=="live"{printf "%s ", $1}')"
        [[ -n "$_ZL_LIVE_CACHE" ]] || {
            echo "test-lib.sh: module-graph reported no live modules -- refusing to run the live set in parallel on a guess" >&2
            exit 1
        }
    fi
    printf '%s' "$_ZL_LIVE_CACHE"
}

# Sub-second timing via bash 5+ EPOCHREALTIME; fall back to whole seconds.
# EPOCHREALTIME honours the locale's decimal point (e.g. "1.234,56" in
# cs_CZ), which awk would parse as an integer — normalise comma -> period.
if [[ -n "${EPOCHREALTIME-}" ]]; then
    _now() { local v="$EPOCHREALTIME"; printf '%s\n' "${v//,/.}"; }
else
    _now() { date +%s; }
fi

: "${ZIGLIBS_TEST_T0:=}"

_ZL_LINE_W=70
_ZL_OK_COL=61   # column where the "O" of OK lands

# ── memory cap ────────────────────────────────────────────────────────────
# Every command `step` runs goes inside a transient cgroup with a hard memory
# limit, so a runaway test is killed by ITS OWN cgroup's OOM killer. Without
# this the kernel's global OOM killer chooses instead, and it picks by size —
# on a dev box that is the editor, not the 200-line test that caused it. This
# host has no swap, so there is no soft landing: the global killer fires within
# seconds of the limit being crossed.
#
# A test that exceeds the cap therefore shows up as one red step (SIGKILL,
# exit 137) rather than as a dead desktop. Set ZIGLIBS_MEM_MAX to another
# systemd size (e.g. 24G) to raise it, or to "off" to disable the wrapper.
#
# The 12G default is measured, not guessed: a full `zig build test` over every
# module peaks at 4.1 GiB for the WHOLE parallel build (largest single test
# binary: 115 MB MaxRSS). So the default leaves ~3x headroom over a legitimate
# full run while still catching the kind of runaway that motivated this — a
# test binary at 15.4 GB RSS. Re-measure before lowering it; the ReleaseFast
# lane compiles through LLVM and is heavier per process than the Debug lane
# this figure comes from.
#
# Requires cgroup v2 with the `memory` controller delegated to the user
# manager — true under any modern systemd, and probed for below rather than
# assumed, so this degrades to a plain exec on hosts (macOS, CI containers,
# non-systemd Linux) that cannot do it.
# Probed once (a systemd-run round trip is not free); the LIMIT is read per
# step, so ZIGLIBS_MEM_MAX can be changed after this file is sourced.
_ZL_CAP_OK=0
if command -v systemd-run >/dev/null 2>&1 &&
    systemd-run --user --scope -q --collect -- true >/dev/null 2>&1; then
    _ZL_CAP_OK=1
fi

# Populates _ZL_CAP with the wrapper argv for the current limit, or empties
# it. An array, not an echoed string, so nothing is ever word-split.
_ZL_CAP=()
_zl_cap_argv() {
    _ZL_CAP=()
    local max="${ZIGLIBS_MEM_MAX:-12G}"
    # Already inside test.sh's whole-run scope: a transient scope cannot spawn
    # another, so wrapping here would cost a failing D-Bus round trip per step
    # and cap nothing. The outer scope is the stronger guarantee anyway -- it
    # bounds the SUM, which is what the per-step cap could never do.
    [[ -z "${_ZL_IN_RUN_SCOPE:-}" ]] || return 0
    [[ $_ZL_CAP_OK -eq 1 && "$max" != "off" ]] || return 0
    _ZL_CAP=(systemd-run --user --scope -q --collect
        -p "MemoryMax=$max" -p MemorySwapMax=0 --)
}

# section "changed"  ->  "\nchanged ────────────────────────────────────"
section() {
    local title="$1"
    local head="$title "
    local pad=$(( _ZL_LINE_W - ${#head} ))
    (( pad < 3 )) && pad=3
    echo
    printf '%s' "$head"
    printf '─%.0s' $(seq 1 $pad)
    echo
}

# step "label" cmd args...
# Runs cmd, capturing stdout and stderr SEPARATELY. On success with empty
# stderr, prints "  <label> .... OK   X.Xs". Any stderr is treated as a real
# problem even when the command exits 0 — a module's tests are silent by
# default (ZIG_LIBS_VERBOSE_SKIP=0), so stderr output here means something
# unexpected printed (a stray debug print, a warning, a forgotten verbose
# skip) — the run is downgraded to FAIL and both streams are replayed.
# On a genuine nonzero exit, replays both streams and exits with that code.
#
# Set _ZL_KEEP_OUT to a path to have the captured stdout APPENDED there before
# it is discarded. That is how the dark-test check gets the `--summary all`
# output of the gate's own run instead of paying for a second one: Zig does not
# cache test RUN steps (measured — the same multi-module command takes the same
# 13.3 s twice in a row), so re-running the suites just to count their tests
# would roughly double the gate.
_ZL_KEEP_OUT=""

# A step prints nothing until it returns. On a terminal that is fine -- you can
# see the machine working. In CI it is not: `build+test` ran 95 minutes on a
# GitHub runner with the log frozen on the PREVIOUS step's line, which is
# indistinguishable from a hang, and the right reaction to a hung run is to kill
# it. A healthy run that reads as a dead one is a broken gate whatever it
# verifies.
#
# So each step announces itself and a heartbeat reports it is still alive while
# it runs. Nothing is streamed: the command's stdout and stderr are captured to
# files that the stderr-on-success rule and the failure replay are both built
# on, and piping them through `tee` at the same time races the reader of those
# files.
#
# ⚠ "is this alive" stopped being the whole question on 2026-08-14, when a tag's
# full matrix passed FIVE HOURS with every lane showing nothing but its own
# heartbeat. Alive was never in doubt; WHERE THE TIME WENT was, and a heartbeat
# renders a 95-minute step and a 5-hour step as the same line.
#
# The heartbeat therefore names what is IN FLIGHT, read from the process table.
# Three channels were measured on identical cold builds before settling there:
#
#     --summary all    294 B  end of run only          stderr
#     --verbose      1 411 B  live, names the module   stderr
#     ZIG_PROGRESS  31 685 B  live, structured         its own fd, stderr 0 B
#
# ⚠ ZIG_PROGRESS CARRIES THE WRONG SUBTREE. Re-measured with the build script
# already cached, so the only work left was a module's: 3120 B over 25 packets,
# EVERY node named `Compile Build Script`. A top-level `zig build` forwards its
# own tree; child compilations report over their own descriptors and it merges
# them only for TERMINAL drawing. `--verbose` does not enrich it either (still
# 3120 B, still only the build script). Do not spend the afternoon on it again.
#
# ⚠ AND `--verbose` ANSWERS THE WRONG QUESTION. It logs a command BEFORE running
# it and never reports completion, so its tail is a list of recent STARTS. After
# two hours the module you want is precisely the one that never came back, which
# is not in that list. It also costs an exception in the stderr rule below, for
# a fact the process table already holds exactly.
#
# Nor does a terminal help by itself: `std.Progress` has no text mode
# (`Progress.zig` offers `ansi_escape_codes`, `windows_api`, or `off`), a
# redirected gate gets `off`, and a PTY renders ~3.8 KB/s of cursor control that
# is 69 MB over a five-hour lane. This is also why the local run went silent
# after `check-ctgrind OK` — `step` redirects both streams, so zig saw no
# terminal there either.
#
_zl_tty() { [[ -t 1 ]]; }
# Off a terminal a heartbeat is a log line and 60 s is already chatty over
# hours; on one it is a redraw in place, where anything slower than a couple of
# seconds reads as frozen.
if [[ -z "${_ZL_HEARTBEAT_S:-}" ]]; then
    if _zl_tty; then _ZL_HEARTBEAT_S=2; else _ZL_HEARTBEAT_S=60; fi
fi

# Where this checkout lives, so the process scan cannot report a second worktree
# or a parallel gate as this run's progress. A plausible wrong name is worse
# than no name.
_ZL_REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

# ⚠ WHAT IS STILL RUNNING, not what started. `--verbose` logs a command BEFORE
# executing it and never says it finished, so after two hours its tail is a list
# of the most recent STARTS — and the one thing you want then is the module that
# never came back, which by definition is not among them. The processes that are
# still alive ARE the work still in flight, so that is what this reads, with
# each one's elapsed time, longest first. After two hours the top line is the
# module to blame.
#
# Both phases are nameable, which they were not before `.name = m.name` in
# build.zig: every test binary used to be called `test`, so a running one was
# `…/o/<hash>/test` and said nothing.
#
#     compile   `zig test … -Mroot=<repo>/modules/<name>/…`
#     run       `<cache>/o/<hash>/<name>`
#
# The snapshot is taken into a variable FIRST and matched afterwards: `ps | grep
# <pattern>` lists the grep, whose own argv contains the pattern, and matches
# itself — that shipped once and rendered as `compiling: [^`.
_zl_inflight_note() {
    local snap out
    snap=$(ps -eo etimes=,args= 2>/dev/null) || return 0
    out=$(awk -v repo="$_ZL_REPO_ROOT" '
        {
            et = $1 + 0
            if (match($0, / -Mroot=[^ ]*\/modules\/[^\/]+\//)) {
                s = substr($0, RSTART, RLENGTH)
                sub(/.*\/modules\//, "", s); sub(/\/$/, "", s)
                if (index($0, repo) > 0) print et "\t" s "\tcompile"
            } else if ($2 ~ /\/o\/[0-9a-f][0-9a-f]*\/[A-Za-z0-9_]+$/) {
                # ⚠ argv[0] ONLY ($2), not anywhere in the command line. A test
                # binary is EXECUTED as `<cache>/o/<hash>/<name> --listen=-`; a
                # compile of the same module merely NAMES that path further
                # along its own argv as an output. Matching the whole line
                # therefore labelled compiles as runs, and the 2026-08-15 arm64
                # log said `bacnet test` during a phase whose own Build Summary
                # (226 steps = 225 compiles + install) proves no test ran.
                s = $2
                sub(/.*\//, "", s)
                # `build` is the compiled build.zig runner, which lives in the
                # same cache and matches the same shape. It is present for the
                # whole run, so left in it would head the list forever and read
                # as the stuck one.
                if (s != "build") print et "\t" s "\ttest"
            }
        }' <<< "$snap" 2>/dev/null | sort -rn | head -4) || true
    [[ -z "$out" ]] && return 0

    local et name kind first=1
    printf ' in flight:'
    while IFS=$'\t' read -r et name kind; do
        [[ -z "$name" ]] && continue
        (( first )) || printf ','
        first=0
        printf ' %s %s %ss' "$name" "$kind" "$et"
    done <<< "$out"
}

step() {
    local label="$1"; shift
    local out err
    out=$(mktemp)
    err=$(mktemp)
    local t0 t1 dur rc=0 hb=""
    t0=$(_now)
    # Subshell in both branches, so killing it later cannot reach anything else.
    if ! _zl_tty; then
        printf '  > %s ... started %s\n' "$label" "$(date -u +%H:%M:%SZ)"
        ( local n=0
          while sleep "$_ZL_HEARTBEAT_S"; do
              n=$(( n + _ZL_HEARTBEAT_S ))
              printf '  . %s ... still running (%ss)%s\n' \
                     "$label" "$n" "$(_zl_inflight_note)"
          done ) &
        hb=$!
    else
        # In place, and erased below before the step's own aligned line.
        ( local n=0
          while sleep "$_ZL_HEARTBEAT_S"; do
              n=$(( n + _ZL_HEARTBEAT_S ))
              printf '\r\033[K  %s ... %ss%s' \
                     "$label" "$n" "$(_zl_inflight_note)"
          done ) &
        hb=$!
    fi
    # ${arr[@]+"${arr[@]}"} — expands to nothing when _ZL_CAP is empty, on
    # bash 3.2 too, where a bare "${arr[@]}" on an empty array is an error.
    _zl_cap_argv
    ${_ZL_CAP[@]+"${_ZL_CAP[@]}"} "$@" >"$out" 2>"$err" || rc=$?
    # `|| true` is load-bearing: `wait` on a killed child returns 143, that is
    # the status of the whole && list, and `set -e` then takes the script down
    # at the first step it ever runs. Off a TTY only, so a terminal run never
    # showed it.
    # `pkill -P` FIRST: killing the subshell leaves the `sleep` it is blocked
    # on running as a separate child, and GitHub lists one "Terminate orphan
    # process: (sleep)" per step at job cleanup. `|| true` on each, because
    # `wait` on a killed child returns 143 and `set -e` would take the script
    # down at the first step.
    if [[ -n "$hb" ]]; then
        pkill -P "$hb" 2>/dev/null || true
        kill "$hb" 2>/dev/null || true
        wait "$hb" 2>/dev/null || true
        # Clear the transient line so the aligned table below starts clean.
        if _zl_tty; then printf '\r\033[K'; fi
    fi
    t1=$(_now)
    dur=$(awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')

    # ⭐ `zig build --summary all` prints the build summary to STDERR, and the
    # rule above is that ANY stderr is a problem. The summary is the one
    # expected exception, and it is exactly identifiable: on a successful build
    # it is a contiguous block emitted LAST, beginning at the line
    # `Build Summary:` (progress goes to a TTY, never to a pipe, so nothing else
    # reaches stderr before it). So when a caller asked to keep the output, both
    # streams are copied out and only that trailing block is removed from the
    # stderr under judgement — a stray debug print, warning or forgotten verbose
    # skip still lands before it and still fails the step exactly as before.
    #
    # On a NONZERO exit nothing is filtered: the step is failing anyway and the
    # replay below must show everything, including the `error: the following
    # build command failed` line zig prints after the summary.
    if [[ -n "$_ZL_KEEP_OUT" ]]; then
        cat "$out" "$err" >> "$_ZL_KEEP_OUT"
        if [[ $rc -eq 0 ]]; then
            local trimmed
            trimmed=$(mktemp)
            sed '/^Build Summary:/,$d' "$err" > "$trimmed"
            mv "$trimmed" "$err"
        fi
    fi

    if [[ $rc -eq 0 && ! -s "$err" ]]; then
        local dots_n=$(( _ZL_OK_COL - 5 - ${#label} ))
        (( dots_n < 3 )) && dots_n=3
        local dots
        dots=$(printf '.%.0s' $(seq 1 $dots_n))
        printf '  %s %s OK %6ss\n' "$label" "$dots" "$dur"
        rm -f "$out" "$err"
        return 0
    fi

    if [[ $rc -eq 0 && -n "${ZL_STEP_STDERR_IS_OUTPUT:-}" ]]; then
        # This step runs PROGRAMS, not checkers, and their normal narration
        # goes to stderr -- `std.debug.print` writes there, which is what all
        # 230 examples use. The rule below exists to catch a checker that
        # reports success while complaining; a program that says what it
        # proved is not that. Its exit status still decides.
        #
        # ⚠ Set this ONLY where stderr is the step's ordinary output channel.
        # Four defects of the exit-0-and-complains shape are why the rule is
        # there, and `check-uapi` sat unwired for months because its summary
        # went to stderr and it therefore could not pass.
        local dots_n=$(( _ZL_OK_COL - 5 - ${#label} ))
        (( dots_n < 3 )) && dots_n=3
        local dots
        dots=$(printf '.%.0s' $(seq 1 $dots_n))
        printf '  %s %s OK %6ss\n' "$label" "$dots" "$dur"
        rm -f "$out" "$err"
        return 0
    fi

    if [[ $rc -eq 0 ]]; then
        # Exit 0 but stderr wrote something — treat as a failure so it can
        # never pass silently in CI or a work loop.
        rc=1
        echo "  $label ... OK-but-stderr -> treated as FAIL (${dur}s)"
    else
        echo "  $label ... FAIL (${dur}s)"
    fi
    if [[ $rc -eq 137 && $_ZL_CAP_OK -eq 1 ]]; then
        # 137 = SIGKILL. Inside the cap that is nearly always the cgroup OOM
        # killer, and the raw number tells you nothing on its own.
        if [[ -n "${_ZL_IN_RUN_SCOPE:-}" ]]; then
            echo "  -> SIGKILL: the run exceeded ZIGLIBS_RUN_MEM_MAX=${ZIGLIBS_RUN_MEM_MAX:-20G} (one cap for the WHOLE run, not this step alone)."
        else
            echo "  -> SIGKILL: almost certainly exceeded ZIGLIBS_MEM_MAX=${ZIGLIBS_MEM_MAX:-12G}."
        fi
        echo "     Shrink the test's footprint; raise the cap only if it is genuinely that large."
    fi
    echo
    if [[ -s "$out" ]]; then
        echo "--- stdout ---" >&2
        cat "$out" >&2
    fi
    if [[ -s "$err" ]]; then
        echo "--- stderr ---" >&2
        cat "$err" >&2
    fi
    rm -f "$out" "$err"
    exit "$rc"
}

# Bottom rule + total wall time. No-op if ZIGLIBS_TEST_T0 was never set.
summary() {
    [[ -z "$ZIGLIBS_TEST_T0" ]] && return 0
    local t1 total
    t1=$(_now)
    total=$(awk -v a="$ZIGLIBS_TEST_T0" -v b="$t1" 'BEGIN{printf "%.1f", b-a}')
    echo
    printf '─%.0s' $(seq 1 $_ZL_LINE_W)
    echo
    local left='  Total'
    local right="${total}s"
    local pad=$(( _ZL_LINE_W - ${#left} - ${#right} ))
    (( pad < 1 )) && pad=1
    printf '%s%*s%s\n' "$left" $pad '' "$right"
}
