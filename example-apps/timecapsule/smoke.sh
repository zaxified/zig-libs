#!/usr/bin/env bash
# Run the app and check that it did what it claims — offline, against GENUINE
# quicknet beacon data (the same round-1000 documents the drand/tlock module
# KATs pin). The BLS verification of that signature against the real chain
# public key is a foreign implementation's output failing independently of us:
# nothing in this repo could fabricate a passing signature.
#
#   ./smoke.sh            # after ./init.sh, or after `zig build`
#
# Exit 0 = sealed, refused everything it must refuse, and opened byte-exactly.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

BIN="$PWD/zig-out/bin/timecapsule"
[ -x "$BIN" ] || { echo "smoke: $BIN is not built — run ./init.sh first" >&2; exit 2; }

WORK="$(mktemp -d)"
WAITER=""  # the `open --wait` background case, when running
cleanup() {
    [ -n "${WATCHDOG:-}" ] && kill "$WATCHDOG" 2>/dev/null || true
    [ -n "$WAITER" ] && kill "$WAITER" 2>/dev/null || true
    rm -f "$WORK"/* 2>/dev/null || true
    rmdir "$WORK" 2>/dev/null || true
}
trap cleanup EXIT
# A timeout must run cleanup, not just die: SIGKILL on $$ cannot be trapped and
# would orphan the `open --wait` child and $WORK. The watchdog sends SIGTERM;
# this handler exits so the EXIT trap fires.
trap 'echo "smoke: TIMED OUT" >&2; exit 124' TERM

# A watchdog: the app is offline here (every beacon document comes from a
# file), so anything long-running is a hang, not a download. 60s is ~20x.
( sleep 60; kill -TERM $$ 2>/dev/null ) &
WATCHDOG=$!
disown "$WATCHDOG"

fail() { echo "smoke: FAILED — $1" >&2; exit 1; }

# ── genuine quicknet documents ──────────────────────────────────────────────
# League of Entropy quicknet `/info` and `/public/1000`, exactly as served —
# the same bytes modules/drand's end-to-end KAT embeds. Public data.
cat > "$WORK/info.json" <<'EOF'
{
  "public_key": "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
  "period": 3,
  "genesis_time": 1692803367,
  "hash": "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
  "schemeID": "bls-unchained-g1-rfc9380",
  "metadata": { "beaconID": "quicknet" }
}
EOF
printf '%s' '{"round":1000,"randomness":"fe290beca10872ef2fb164d2aa4442de4566183ec51c56ff3cd603d930e54fdd","signature":"b44679b9a59af2ec876b1a6b1ad52ea9b1615fc3982b19576350f93447cb1125e342b73a8dd2bacbe47e4b6b63ed5e39"}' > "$WORK/round1000.json"

cd "$WORK"
OFFLINE=(--chain-info info.json)
printf 'the eagle lands at midnight\n' > msg.txt

# ── 1. keygen: both halves exist, the secret one is 0600 ────────────────────
"$BIN" keygen --out alice >/dev/null 2>&1 || fail "keygen"
[ -f alice.pk ] && [ -f alice.sk ] || fail "keygen wrote no keypair"
perms="$(stat -c %a alice.sk)"
[ "$perms" = 600 ] || fail "alice.sk has mode $perms, a secret key must be 600"

# ── 2. seal to a published round, open byte-exactly ─────────────────────────
"$BIN" seal --to alice.pk --at round:1000 --in msg.txt --out msg.tc "${OFFLINE[@]}" >/dev/null 2>&1 \
    || fail "seal to round 1000"
"$BIN" info --in msg.tc "${OFFLINE[@]}" > info.out 2>&1 || fail "info on a published round should exit 0"
grep -q "PUBLISHED" info.out || fail "info does not say the round is published"
"$BIN" open --key alice.sk --in msg.tc --out msg.out "${OFFLINE[@]}" --round-file round1000.json >/dev/null 2>&1 \
    || fail "open with the genuine signature"
cmp -s msg.txt msg.out || fail "plaintext is not byte-identical"

# ── 3. the four refusals, each for its own reason ───────────────────────────
# (a) tampered signature: not even a valid G1 point — refused at parse.
sed 's/b44679b9/b44679b8/' round1000.json > tampered.json
if "$BIN" open --key alice.sk --in msg.tc --out x "${OFFLINE[@]}" --round-file tampered.json >refuse.out 2>&1; then
    fail "a tampered signature was accepted"
fi

# (b) a VALID signature for the WRONG round: survives parsing, must die on the
# BLS pairing check against the chain public key — the foreign-anchor moment.
"$BIN" seal --to alice.pk --at round:2000 --in msg.txt --out r2000.tc "${OFFLINE[@]}" >/dev/null 2>&1
sed 's/"round":1000/"round":2000/' round1000.json > wronground.json
if "$BIN" open --key alice.sk --in r2000.tc --out x "${OFFLINE[@]}" --round-file wronground.json >bls.out 2>&1; then
    fail "round 1000's signature opened a round-2000 capsule"
fi
grep -q "REFUSED by BLS" bls.out || fail "wrong-round refusal did not come from BLS verification: $(cat bls.out)"

# (c) the right time, the wrong recipient: the PQ lock alone must hold.
"$BIN" keygen --out mallory >/dev/null 2>&1
if "$BIN" open --key mallory.sk --in msg.tc --out x "${OFFLINE[@]}" --round-file round1000.json >/dev/null 2>&1; then
    fail "a different recipient key opened the capsule"
fi

# (d) one flipped ciphertext byte.
cp msg.tc bad.tc
printf '\x00' | dd of=bad.tc bs=1 seek=100 conv=notrunc 2>/dev/null
if "$BIN" open --key alice.sk --in bad.tc --out x "${OFFLINE[@]}" --round-file round1000.json >/dev/null 2>&1; then
    fail "a tampered capsule was opened"
fi

# ── 4. a still-locked capsule says WHEN, and exits 3, not 1 ─────────────────
"$BIN" seal --to alice.pk --at +1h --in msg.txt --out future.tc "${OFFLINE[@]}" >/dev/null 2>&1 || fail "seal +1h"
set +e
"$BIN" info --in future.tc "${OFFLINE[@]}" > locked.out 2>&1
rc=$?
set -e
[ "$rc" = 3 ] || fail "info on a locked capsule exited $rc, the documented status is 3"
grep -q "still locked" locked.out || fail "locked capsule not reported as locked"
# And the signature for a DIFFERENT round must not open it (typed refusal).
if "$BIN" open --key alice.sk --in future.tc --out x "${OFFLINE[@]}" --round-file round1000.json >/dev/null 2>&1; then
    fail "a past round's signature opened a future capsule"
fi

# ── 5. --wait blocks while the source has nothing, opens when it appears ────
# The signature "publishes" by the round file appearing 2 s in — the same
# poll loop that watches the beacon watches the file, so this is the wait
# path minus the network, which CI does not get.
rm -f pending.json waited.out
( "$BIN" open --key alice.sk --in msg.tc --out waited.out "${OFFLINE[@]}" --round-file pending.json --wait \
      > wait.log 2>&1; echo "$?" > wait.rc ) &
WAITER=$!
sleep 2
cp round1000.json pending.json
wait "$WAITER"
[ "$(cat wait.rc)" = 0 ] || fail "open --wait exited $(cat wait.rc) (log: $(cat wait.log))"
grep -q "waiting — round 1000" wait.log || fail "open --wait never announced it was waiting — did it wait at all?"
cmp -s msg.txt waited.out || fail "--wait plaintext differs"

echo "smoke: OK"
