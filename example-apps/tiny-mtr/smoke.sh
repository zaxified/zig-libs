#!/usr/bin/env bash
# Run the app and check that it did what it claims. Loopback only: one real hop
# over real sockets, every method, with no privilege (CI opens
# net.ipv4.ping_group_range; here a machine without it fails with the app's own
# explanation). The screen itself is driven through a pty by smoke_tty.py.
#
#   ./smoke.sh            # after ./init.sh, or after `zig build`
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

BIN="$PWD/zig-out/bin/tiny-mtr"
[ -x "$BIN" ] || { echo "smoke: $BIN is not built — run ./init.sh first" >&2; exit 2; }

WORK="$(mktemp -d)"
cleanup() {
    rm -f "$WORK"/* 2>/dev/null || true
    rmdir "$WORK" 2>/dev/null || true
}
trap cleanup EXIT

# Everything is bounded by round counts, so anything long-running is a hang.
( sleep 60
  echo "smoke: TIMED OUT" >&2
  for p in $(pgrep -P $$ 2>/dev/null); do [ "$p" = "$BASHPID" ] || kill -9 "$p" 2>/dev/null; done
  cleanup
  kill -9 $$ 2>/dev/null ) &
WATCHDOG=$!
# Its `sleep` too: an orphan holds this script's stdout, and whatever reads that
# would wait out the minute.
trap 'pkill -9 -P "$WATCHDOG" 2>/dev/null || true; kill -9 "$WATCHDOG" 2>/dev/null || true; cleanup' EXIT

fail() {
    echo "smoke: FAILED — $1" >&2
    [ -f "$WORK/out" ] && cat "$WORK/out" >&2
    [ -f "$WORK/err" ] && cat "$WORK/err" >&2
    exit 1
}

# One hop, answered every time, N rounds. Columns: host, loss, sent.
expect_report() { # address rounds args...
    local addr="$1" rounds="$2"; shift 2
    "$BIN" -r -n -i 0.1 -c "$rounds" "$@" "$addr" > "$WORK/out" 2> "$WORK/err" || fail "exit $? from: $* $addr"
    grep -q "^tiny-mtr to $addr .*, $rounds rounds$" "$WORK/out" || fail "no title for: $* $addr"
    [ "$(wc -l < "$WORK/out")" = 3 ] || fail "not exactly one hop for: $* $addr"
    awk -v a="$addr" -v n="$rounds" 'NR==3 && $2==a && $3=="0.0%" && $4==n {ok=1} END {exit !ok}' "$WORK/out" \
        || fail "wrong row for: $* $addr"
}

# ── the command line ────────────────────────────────────────────────────────
"$BIN" --help > "$WORK/out" || fail "--help"
grep -q "^usage: tiny-mtr" "$WORK/out" || fail "--help printed no usage"
set +e
"$BIN" > /dev/null 2>&1;                  [ $? = 2 ] || fail "no host must exit 2"
"$BIN" -i 0.01 127.0.0.1 > /dev/null 2>&1; [ $? = 2 ] || fail "a 10 ms interval must be refused"
"$BIN" -6 127.0.0.1 > /dev/null 2>&1;     [ $? = 1 ] || fail "-6 with a v4 address must be refused"
set -e

# ── every method, unprivileged ──────────────────────────────────────────────
expect_report 127.0.0.1 3
expect_report 127.0.0.1 3 -u
# Nothing listens on port 1: the RST is the answer.
expect_report 127.0.0.1 3 -T -P 1
if [ -s /proc/net/if_inet6 ] && grep -q '^0*1 ' /proc/net/if_inet6; then
    expect_report ::1 3
fi

# ── output that is not a terminal ───────────────────────────────────────────
# With no -r: a table, not escape sequences into a file.
"$BIN" -n -i 0.1 -c 2 127.0.0.1 < /dev/null > "$WORK/out" 2> "$WORK/err" || fail "piped run"
grep -q "2 rounds$" "$WORK/out" || fail "piped run did not count 2 rounds"
if grep -q $'\x1b' "$WORK/out"; then fail "escape sequences in a pipe"; fi
# A reader that goes away ends it, and nothing hangs.
# A failed write exits 1, which `pipefail` would make this script's own exit.
"$BIN" -n -i 0.1 -c 2 127.0.0.1 < /dev/null | true || true

# ── the screen ──────────────────────────────────────────────────────────────
python3 -I smoke_tty.py "$BIN" || fail "the screen (above)"

echo "smoke: OK — every method on loopback, reports, a pipe, and the screen through a pty"
