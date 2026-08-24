#!/usr/bin/env bash
# Run the app and check that it did what it claims: start the service, then
# drive it over real HTTP the way its README tells a reader to.
#
#   ./smoke.sh            # after ./init.sh, or after `zig build`
#
# The middleware modules all have their own tests. What none of them can test
# is this composition: whether the chain, in this order, actually refuses an
# unauthenticated request, accepts a signed webhook, and puts the headers on
# the way out. That is the thing a demo silently loses.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

BIN=./zig-out/bin/http-service
[ -x "$BIN" ] || { echo "smoke: $BIN is not built — run ./init.sh first" >&2; exit 2; }
command -v curl >/dev/null || { echo "smoke: curl is not on PATH" >&2; exit 2; }

# The webhook case needs an HMAC-SHA256 of the body. Either tool will do; a
# missing one is an explicit refusal to run, not a quietly skipped case.
if command -v openssl >/dev/null; then
    hmac() { printf '%s' "$2" | openssl dgst -sha256 -hmac "$1" -hex | sed 's/.*= *//'; }
elif command -v python3 >/dev/null; then
    hmac() { python3 -c 'import hmac,hashlib,sys; print(hmac.new(sys.argv[1].encode(), sys.argv[2].encode(), hashlib.sha256).hexdigest())' "$1" "$2"; }
else
    echo "smoke: neither openssl nor python3 is available to compute the webhook HMAC" >&2
    exit 2
fi

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
    echo "───── service.log ─────" >&2
    cat "$WORK/service.log" >&2 2>/dev/null || true
    exit 1
}

PORT=$(( 20000 + RANDOM % 20000 ))
KEY="smoke-api-key"
SECRET="smoke-webhook-secret"
BASE="http://127.0.0.1:$PORT"

"$BIN" --port "$PORT" --api-key "$KEY" --webhook-secret "$SECRET" \
    > "$WORK/service.log" 2>&1 &
SERVICE_PID=$!
PIDS+=("$SERVICE_PID")

# Wait on the service's own banner rather than on a fixed sleep, and rather
# than by opening a socket — a probe connection is a request as far as the
# accept loop and the rate limiter are concerned.
for _ in $(seq 1 200); do
    grep -q "listening on http://127.0.0.1:$PORT" "$WORK/service.log" 2>/dev/null && break
    sleep 0.05
done
grep -q "listening on http://127.0.0.1:$PORT" "$WORK/service.log" \
    || fail "the service never reported listening on port $PORT"

# `-o /dev/null -w %{http_code}` so a status check never depends on the body.
status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# 1. Liveness, unauthenticated on purpose.
[ "$(status "$BASE/healthz")" = 200 ] || fail "/healthz did not answer 200"

# 2. The gate. An /api/ request without a key must be refused — this is the
#    one assertion here whose failure would be a security bug rather than a
#    broken demo.
code=$(status -X POST -H 'Content-Type: application/json' -d '{"title":"no key"}' "$BASE/api/tasks")
case "$code" in
    401|403) ;;
    *) fail "an unauthenticated POST /api/tasks answered $code, not 401/403" ;;
esac

# 3. Create and read back with the key.
created=$(curl -s -H "X-Api-Key: $KEY" -H 'Content-Type: application/json' \
    -d '{"title":"smoke task"}' "$BASE/api/tasks")
echo "$created" > "$WORK/created.json"
grep -q '"smoke task"' "$WORK/created.json" || fail "POST /api/tasks did not echo the task back: $created"
id=$(sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p' "$WORK/created.json")
[ -n "$id" ] || fail "POST /api/tasks returned no id: $created"

got=$(curl -s -H "X-Api-Key: $KEY" "$BASE/api/tasks/$id")
echo "$got" | grep -q '"smoke task"' || fail "GET /api/tasks/$id did not return the task: $got"

# 4. Security headers are stamped on the way out, including on a response no
#    handler of ours wrote.
curl -s -D "$WORK/headers.txt" -o /dev/null "$BASE/healthz"
grep -qi '^content-security-policy:' "$WORK/headers.txt" \
    || fail "no Content-Security-Policy header on a plain response"

# 5. The webhook: a correct signature is accepted and a wrong one is refused.
#    Both halves matter — a verifier that accepts everything passes the first
#    on its own.
body="{\"id\":$id}"
sig=$(hmac "$SECRET" "$body")
code=$(status -X POST -H "X-Signature-256: sha256=$sig" \
    -H 'Content-Type: application/json' -d "$body" "$BASE/webhooks/tasks")
[ "$code" = 200 ] || [ "$code" = 204 ] || fail "a correctly signed webhook answered $code"

# ⚠ The refusal case corrupts the SIGNATURE, not the body. Corrupting the body
#    was the first attempt and it proved nothing: a mangled body is also
#    malformed JSON, so the handler answers 400 whether the signature was
#    checked or not — the test would have passed with verification disabled.
bad_sig="$(printf '%s' "$sig" | sed 's/^./0/; s/^0/1/')"
code=$(status -X POST -H "X-Signature-256: sha256=$bad_sig" \
    -H 'Content-Type: application/json' -d "$body" "$BASE/webhooks/tasks")
case "$code" in
    400|401|403) ;;
    *) fail "a webhook with a corrupted signature over a VALID body answered $code" ;;
esac

# 6. Idempotency: the same `Idempotency-Key` twice must replay the first
#    response, not create a second task. The README advertises this and
#    nothing asserted it until now.
first=$(curl -s -H "X-Api-Key: $KEY" -H "Idempotency-Key: smoke-key-1" \
    -H 'Content-Type: application/json' -d '{"title":"idempotent"}' "$BASE/api/tasks")
second=$(curl -s -H "X-Api-Key: $KEY" -H "Idempotency-Key: smoke-key-1" \
    -H 'Content-Type: application/json' -d '{"title":"idempotent"}' "$BASE/api/tasks")
[ "$first" = "$second" ] \
    || fail "a replayed Idempotency-Key produced a different response:\n  first:  $first\n  second: $second"
echo "$first" | grep -q '"idempotent"' || fail "the idempotent POST did not create the task: $first"

# 7. Rate limiting, LAST on purpose. The limiter is 5/s with a burst of 10,
#    and past that `abuseguard` stops answering this peer at the connection
#    level — measured: eight 200s, then 429s, then curl cannot connect at all.
#    So this case poisons the client address for everything after it, and
#    everything after it is nothing.
saw_429=0
codes=""
for _ in $(seq 1 30); do
    c=$(curl -s -m 2 -o /dev/null -w '%{http_code}' -H "X-Api-Key: $KEY" "$BASE/api/tasks" || echo 000)
    codes="$codes $c"
    [ "$c" = 429 ] && saw_429=1
done
[ "$saw_429" = 1 ] || fail "30 rapid requests never drew a 429 from a 5/s limiter — codes were:$codes"

# 8. And it has to STOP cleanly. This is not tidiness: `main` runs under a
#    `DebugAllocator` that panics on leak, and that check only ever executes on
#    a clean exit. A harness that kills the service instead makes the leak
#    detector unreachable — a guard that cannot fire, which reads exactly like
#    a guard that passed.
kill -TERM "$SERVICE_PID"
set +e
wait "$SERVICE_PID"
stop_rc=$?
set -e
[ "$stop_rc" = 0 ] || fail "SIGTERM did not stop the service cleanly (exit $stop_rc — a leak panic exits non-zero)"
grep -q "stopped cleanly" "$WORK/service.log" || fail "the service did not report a clean stop"

echo "smoke: OK — gate refuses, task round-trips, headers stamped, webhook signature accepts and refuses, replay is idempotent, burst is rate-limited, SIGTERM exits clean under the leak check"
