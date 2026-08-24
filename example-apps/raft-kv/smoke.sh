#!/usr/bin/env bash
# Run the app and check that it did what it claims. Not a unit test: it starts
# a real 3-node cluster on loopback, then does to it exactly what the README
# promises it survives — kills the leader mid-flight, restarts the corpse,
# takes away the majority — and asserts on the answers, not on the logs.
#
#   ./smoke.sh            # after ./init.sh, or after `zig build`
#
# Exit 0 = elected, replicated, failed over, caught up, and REFUSED writes
# without a majority. Anything else prints every node's log, because a red
# run here is about timing and ordering.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

BIN="$PWD/zig-out/bin/raft-kv"
[ -x "$BIN" ] || { echo "smoke: $BIN is not built — run ./init.sh first" >&2; exit 2; }

WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in ${PIDS+"${PIDS[@]}"}; do kill -9 "$pid" 2>/dev/null || true; done
    rm -f "$WORK"/n*/raft.kv "$WORK"/*.log 2>/dev/null || true
    rmdir "$WORK"/n* "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
# A timeout must run cleanup, not just die: SIGKILL on $$ cannot be trapped
# and would orphan the child processes (still bound to the port) and $WORK.
# The watchdog sends SIGTERM instead; this handler prints and exits, so the
# EXIT trap above fires and kills the tracked PIDs.
trap 'echo "smoke: TIMED OUT" >&2; exit 124' TERM

# Everything here is bounded by client budgets, so anything long-running is a
# hang. 90s is ~3x a slow full run.
( sleep 90; kill -TERM $$ 2>/dev/null ) &
WATCHDOG=$!
PIDS+=("$WATCHDOG")

fail() {
    echo "smoke: FAILED — $1" >&2
    for f in "$WORK"/*.log; do
        [ -f "$f" ] || continue
        echo "───── $(basename "$f") ─────" >&2
        cat "$f" >&2
    done
    exit 1
}

BASE=$(( 20000 + RANDOM % 20000 ))
P="127.0.0.1:$BASE,127.0.0.1:$((BASE+1)),127.0.0.1:$((BASE+2))"
CL=(--cluster "$P")

start_node() { # id
    "$BIN" node --id "$1" --peers "$P" --data "$WORK/n$1" >> "$WORK/n$1.log" 2>&1 &
    eval "N$1_PID=\$!"
    PIDS+=("$!")
    disown "$!"  # keep bash quiet about the SIGKILLs this script hands out
}

for i in 0 1 2; do start_node "$i"; done

# ── 1. a leader emerges and a write replicates ──────────────────────────────
"$BIN" put "${CL[@]}" city Brno >/dev/null 2>&1 || fail "first put (no leader elected?)"
[ "$("$BIN" get "${CL[@]}" city 2>/dev/null)" = "Brno" ] || fail "get after put"

# ── 1b. status: one command sees the whole cluster, with exactly one leader ─
"$BIN" status "${CL[@]}" > "$WORK/status.out" 2>/dev/null || fail "status against a healthy cluster"
[ "$(wc -l < "$WORK/status.out")" = 3 ] || fail "status did not print one line per node:\n$(cat "$WORK/status.out")"
leaders=$(grep -c "  leader  " "$WORK/status.out" || true)
[ "$leaders" = 1 ] || fail "status shows $leaders leaders, Election Safety says exactly 1:\n$(cat "$WORK/status.out")"

# ── 2. kill the leader with SIGKILL; the survivors elect and keep serving ───
leader=""
for i in 0 1 2; do
    # No `… | head | grep -q` here: grep -q closing the pipe early makes the
    # producer exit 141 under pipefail ON A MATCH. Capture, then test.
    header="$("$BIN" dump --node "127.0.0.1:$((BASE+i))" 2>/dev/null || true)"
    case "$header" in role=leader*) leader=$i ;; esac
done
[ -n "$leader" ] || fail "no node reports role=leader"
eval "kill -9 \$N${leader}_PID"

"$BIN" put "${CL[@]}" k2 v2 >/dev/null 2>&1 || fail "put after killing the leader (no re-election?)"
[ "$("$BIN" get "${CL[@]}" city 2>/dev/null)" = "Brno" ] || fail "data lost with the leader"

# ── 3. the corpse restarts on the same port and catches up ──────────────────
start_node "$leader"
caught_up=0
for _ in $(seq 1 50); do
    if "$BIN" dump --node "127.0.0.1:$((BASE+leader))" 2>/dev/null | grep -q "^k2=v2"; then
        caught_up=1; break
    fi
    sleep 0.2
done
[ "$caught_up" = 1 ] || fail "restarted node never applied the entry committed while it was dead"

# ── 4. delete replicates too ────────────────────────────────────────────────
"$BIN" del "${CL[@]}" k2 >/dev/null 2>&1 || fail "del"
"$BIN" get "${CL[@]}" k2 >/dev/null 2>&1 && fail "get found a deleted key"
true  # (the && above is the assertion: not-found exits 2, found exits 0)

# ── 5. without a majority, writes REFUSE instead of lying ───────────────────
# Kill two nodes; the lone survivor must answer "no", not "ok".
for i in 0 1 2; do
    [ "$i" = "$leader" ] && continue
    eval "kill -9 \$N${i}_PID"
done
if "$BIN" put "${CL[@]}" k3 v3 --budget 4 >/dev/null 2>&1; then
    fail "a write SUCCEEDED with 1/3 nodes alive"
fi
"$BIN" get "${CL[@]}" k3 >/dev/null 2>&1 && fail "k3 visible after a refused write"

# ── 6. SIGTERM → clean exit, so the DebugAllocator leak check runs ──────────
eval "term_pid=\$N${leader}_PID"
kill -TERM "$term_pid" 2>/dev/null || fail "surviving node already dead?"
for _ in $(seq 1 50); do
    kill -0 "$term_pid" 2>/dev/null || break
    sleep 0.1
done
kill -0 "$term_pid" 2>/dev/null && fail "node did not exit on SIGTERM"
grep -q "stopped cleanly" "$WORK/n$leader.log" || fail "no clean-shutdown line (leak check unreachable)"

echo "smoke: OK — elected (status sees exactly one leader), replicated, failed over, caught up, refused without majority, stopped cleanly"
