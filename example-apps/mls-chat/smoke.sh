#!/usr/bin/env bash
# Run the app and check that it did what it claims. Not a unit test: it starts
# a relay and two clients as real processes on loopback and asserts on what
# they print.
#
#   ./smoke.sh            # after ./init.sh, or after `zig build`
#
# Exit 0 = the group formed and both directions decrypted. Anything else prints
# every process's output before failing, because a red run here is about timing
# and ordering, and a bare assertion number says nothing about either.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

BIN=./zig-out/bin/mls-chat
[ -x "$BIN" ] || { echo "smoke: $BIN is not built — run ./init.sh first" >&2; exit 2; }

WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in ${PIDS+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
    rm -f "$WORK"/*.in "$WORK"/*.out 2>/dev/null || true
    rmdir "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

# A watchdog, because every failure mode of a multi-process script that is not
# an assertion is a hang. 60s is ~20x the run.
( sleep 60; echo "smoke: TIMED OUT" >&2; kill -9 $$ 2>/dev/null ) &
WATCHDOG=$!
PIDS+=("$WATCHDOG")

fail() {
    echo "smoke: FAILED — $1" >&2
    for f in "$WORK"/*.out; do
        [ -f "$f" ] || continue
        echo "───── $(basename "$f") ─────" >&2
        cat "$f" >&2
    done
    exit 1
}

# An ephemeral-range port picked per run: a fixed one collides with a parallel
# run and, worse, with the TIME_WAIT of the previous one.
PORT=$(( 20000 + RANDOM % 20000 ))

# Wait for the relay to actually accept, rather than sleeping a guessed
# interval — a fixed sleep is either flaky or slow, and usually both.
wait_for_port() {
    for _ in $(seq 1 100); do
        if (exec 9<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then exec 9<&-; return 0; fi
        sleep 0.05
    done
    return 1
}

# Wait for a line to appear in a file, so each step starts when the previous
# one has actually happened.
wait_for_line() {
    local file="$1" pattern="$2"
    for _ in $(seq 1 200); do
        grep -q -- "$pattern" "$file" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

"$BIN" relay --port "$PORT" > "$WORK/relay.out" 2>&1 &
PIDS+=($!)
wait_for_port || fail "the relay never accepted a connection on port $PORT"

mkfifo "$WORK/alice.in" "$WORK/bob.in"

"$BIN" join --name alice --group smoke --create --port "$PORT" \
    < "$WORK/alice.in" > "$WORK/alice.out" 2>&1 &
PIDS+=($!)
exec 3> "$WORK/alice.in"

"$BIN" join --name bob --group smoke --port "$PORT" \
    < "$WORK/bob.in" > "$WORK/bob.out" 2>&1 &
PIDS+=($!)
exec 4> "$WORK/bob.in"

wait_for_line "$WORK/alice.out" "created 'smoke'" || fail "alice never created the group"
wait_for_line "$WORK/relay.out" "bob subscribed"  || fail "bob never subscribed to the group"

echo "/invite bob" >&3
wait_for_line "$WORK/bob.out" "joined 'smoke'" || fail "bob never received a usable Welcome"

echo "hello-from-alice" >&3
wait_for_line "$WORK/bob.out" "alice#0: hello-from-alice" \
    || fail "bob did not decrypt alice's message"

echo "hello-from-bob" >&4
wait_for_line "$WORK/alice.out" "bob#1: hello-from-bob" \
    || fail "alice did not decrypt bob's message"

# The membership half: a Remove must reach the removed member as such, and must
# advance the epoch for everyone else.
echo "/remove bob" >&3
wait_for_line "$WORK/bob.out" "you were removed" || fail "bob was not told he had been removed"
wait_for_line "$WORK/alice.out" "removed 'bob'"  || fail "alice's Remove commit did not land"

# And the delivery service must have stayed what it claims to be. A relay that
# ever decoded a message would have had to say something about it; this checks
# the only thing an outside observer can: it logged nothing but publications
# and subscriptions.
if grep -qiE "epoch|decrypt|welcome:|commit" "$WORK/relay.out"; then
    fail "the relay's log mentions MLS state — it is supposed to hold no key"
fi

echo "/quit" >&3
echo "/quit" >&4
exec 3>&-
exec 4>&-

echo "smoke: OK — group formed, both directions decrypted, Remove reached the removed member"
