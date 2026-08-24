#!/usr/bin/env bash
# Run the app and check that it did what it claims: this binary's SERVER mode
# against this binary's CLIENT mode, over a real socket, with a real host key
# and a real authorized_keys.
#
#   ./smoke.sh            # after ./init.sh, or after `zig build`
#
# The `ssh` module already tests our client against our server in-process, and
# against real OpenSSH in both directions. What none of that covers is the
# program: argument parsing, key files on disk, the known_hosts decision, and
# the exit status this binary reports. That is what fails when a demo rots.
#
# Needs `ssh-keygen` (openssh-client) to make the two keys.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

BIN=./zig-out/bin/ssh-demo
[ -x "$BIN" ] || { echo "smoke: $BIN is not built — run ./init.sh first" >&2; exit 2; }
command -v ssh-keygen >/dev/null || { echo "smoke: ssh-keygen not on PATH (openssh-client)" >&2; exit 2; }

WORK="$(mktemp -d)"
PIDS=()
cleanup() {
    for pid in ${PIDS+"${PIDS[@]}"}; do kill "$pid" 2>/dev/null || true; done
    rm -f "$WORK"/* 2>/dev/null || true
    rmdir "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

( sleep 60; echo "smoke: TIMED OUT" >&2; kill -9 $$ 2>/dev/null ) &
PIDS+=($!)

fail() {
    echo "smoke: FAILED — $1" >&2
    for f in "$WORK"/*.log; do
        [ -f "$f" ] || continue
        echo "───── $(basename "$f") ─────" >&2
        cat "$f" >&2
    done
    exit 1
}

ssh-keygen -q -t ed25519 -N "" -f "$WORK/host_ed25519" || fail "could not generate a host key"
ssh-keygen -q -t ed25519 -N "" -f "$WORK/user_ed25519" || fail "could not generate a user key"
cat "$WORK/user_ed25519.pub" > "$WORK/authorized_keys"
: > "$WORK/known_hosts"

USERNAME=smoke

# ⚠ Waits for the server's OWN log line, NOT by connecting to the port. A
# readiness probe that opens a TCP connection IS a client, and this server is
# `--once`: the probe consumed the one connection it had to give, the server
# exited, and the real client met ConnectionRefused. Found by running this.
wait_for_listening() {
    local log="$1" port="$2"
    for _ in $(seq 1 200); do
        grep -q "listening on 127.0.0.1 port $port" "$log" 2>/dev/null && return 0
        sleep 0.05
    done
    return 1
}

# One `--once` server per connection, by design: the flag means "serve one and
# exit", so each case below gets its own. An ephemeral-range port per case
# avoids both a parallel run and the previous case's TIME_WAIT.
run_case() {
    local label="$1" remote_cmd="$2" want_status="$3"
    local port=$(( 20000 + RANDOM % 20000 ))

    "$BIN" server \
        --port "$port" \
        --user "$USERNAME" \
        --host-key "$WORK/host_ed25519" \
        --authorized-keys "$WORK/authorized_keys" \
        --once > "$WORK/server-$label.log" 2>&1 &
    local server_pid=$!
    PIDS+=("$server_pid")
    wait_for_listening "$WORK/server-$label.log" "$port" || fail "the server never listened on port $port ($label)"

    set +e
    "$BIN" client \
        --port "$port" \
        --user "$USERNAME" \
        --identity "$WORK/user_ed25519" \
        --known-hosts "$WORK/known_hosts" \
        --accept-new \
        -- $remote_cmd < /dev/null > "$WORK/client-$label.log" 2>&1
    local rc=$?
    set -e

    [ "$rc" = "$want_status" ] || fail "$label: client exited $rc, expected $want_status"
    wait "$server_pid" 2>/dev/null || true
}

# 1. The ordinary path: publickey auth, one exec, output back.
run_case exec "echo hello-from-exec" 0
grep -q "hello-from-exec" "$WORK/client-exec.log" \
    || fail "the remote command's stdout did not reach the client"

# 2. `ssh(1)` propagates the remote exit status, and so does this. A demo that
#    always exits 0 looks identical to a working one until it matters.
run_case status "sh -c 'exit 7'" 7

# 3. TOFU wrote the host key down — under the right name. `known_hosts` is
#    keyed by host AND port, so the entry the first case accepted names that
#    case's port and no other. (Learned by writing this test the other way
#    round: a "second connection" on a fresh port is a FIRST connection as far
#    as known_hosts is concerned, and it correctly prompted.)
[ -s "$WORK/known_hosts" ] || fail "--accept-new did not record the host key in known_hosts"
grep -q "^\[127.0.0.1\]:" "$WORK/known_hosts" \
    || fail "the known_hosts entry does not name the host:port it was accepted for"

# 4. A host key already in known_hosts is trusted WITHOUT --accept-new, and
#    that path is what a real user is on from their second connection onward.
#    Seeded by hand rather than by reusing case 1's port: this server does not
#    set SO_REUSEADDR (deliberately — see its own comment), so rebinding the
#    port it just served on would fail rather than test anything.
port=$(( 20000 + RANDOM % 20000 ))
printf '[127.0.0.1]:%s %s\n' "$port" "$(cut -d' ' -f1,2 "$WORK/host_ed25519.pub")" >> "$WORK/known_hosts"
"$BIN" server \
    --port "$port" \
    --user "$USERNAME" \
    --host-key "$WORK/host_ed25519" \
    --authorized-keys "$WORK/authorized_keys" \
    --once > "$WORK/server-known.log" 2>&1 &
PIDS+=($!)
wait_for_listening "$WORK/server-known.log" "$port" || fail "the server never listened on port $port (known-host case)"
"$BIN" client \
    --port "$port" \
    --user "$USERNAME" \
    --identity "$WORK/user_ed25519" \
    --known-hosts "$WORK/known_hosts" \
    -- echo trusted-without-prompt < /dev/null > "$WORK/client-known.log" 2>&1 \
    || fail "a host already in known_hosts was not trusted without --accept-new"
grep -q "trusted-without-prompt" "$WORK/client-known.log" \
    || fail "the known-host connection produced no output"

# 5. And the refusal has to work, or none of the above means anything: a key
#    that is not in authorized_keys must not get a session.
: > "$WORK/authorized_keys_empty"
port=$(( 20000 + RANDOM % 20000 ))
"$BIN" server \
    --port "$port" \
    --user "$USERNAME" \
    --host-key "$WORK/host_ed25519" \
    --authorized-keys "$WORK/authorized_keys_empty" \
    --once > "$WORK/server-refuse.log" 2>&1 &
PIDS+=($!)
wait_for_listening "$WORK/server-refuse.log" "$port" || fail "the server never listened on port $port (refusal case)"
set +e
"$BIN" client \
    --port "$port" \
    --user "$USERNAME" \
    --identity "$WORK/user_ed25519" \
    --known-hosts "$WORK/known_hosts" \
    -- echo should-not-run < /dev/null > "$WORK/client-refuse.log" 2>&1
refuse_rc=$?
set -e
[ "$refuse_rc" != 0 ] || fail "a user key absent from authorized_keys was let in"
grep -q "should-not-run" "$WORK/client-refuse.log" \
    && fail "the refused connection still ran the command"

echo "smoke: OK — exec, exit-status propagation, known_hosts TOFU + trust, and an authorised-key refusal"
