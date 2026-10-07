#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# The acme module's anchor against Pebble, Let's Encrypt's ACME test CA
# (a foreign server implementation; MPL-2.0, run as a black-box binary,
# never vendored). Starts pebble-challtestsrv (DNS: every name -> 127.0.0.1,
# DNS-01 TXT records set through its management API), Pebble in -strict mode
# against it, and tools/pebble_helper (a recording TLS proxy in front of
# Pebble + the TLS-ALPN-01 listener); then `zig build interop-acme` drives the
# acme client through every scenario and checks each issued chain against
# Pebble's root. The transcript becomes src/testdata/pebble_transcript.zig,
# which src/pebble_replay_test.zig replays with no Pebble.
#
#   modules/acme/tools/pebble.sh            # run, write the transcript
#   modules/acme/tools/pebble.sh --check    # run, do not write (live verdict only)
#
# Needs openssl, go, and the two binaries in $PEBBLE_BIN (default
# ~/.local/share/zig-libs/oracle-bin/pebble), installed once with
#   GOBIN=$PEBBLE_BIN go install github.com/letsencrypt/pebble/v2/cmd/{pebble,pebble-challtestsrv}@v2.10.1
# Loopback only; fixed ports 5001 5002 5003 8053 8055 14000 14001 15000.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
bin=${PEBBLE_BIN:-$HOME/.local/share/zig-libs/oracle-bin/pebble}
scr=$root/.zig-cache/interop-acme
check=0
[[ ${1:-} == --check ]] && check=1

mkdir -p "$scr"
cd "$scr"
for f in transcript.jsonl pebble.log challtestsrv.log helper.log; do rm -f "$f"; done

# A throwaway CA and the localhost certificate Pebble and the proxy serve.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=acme-interop-ca \
    -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -keyout localhost.key \
    -out localhost.csr 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in localhost.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile san.ext \
    -out localhost.pem 2>/dev/null

cat > pebble.json <<JSON
{"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
  "certificate": "$scr/localhost.pem", "privateKey": "$scr/localhost.key",
  "httpPort": 5002, "tlsPort": 5001, "ocspResponderURL": "", "externalAccountBindingRequired": false,
  "domainBlocklist": ["blocked.test"], "retryAfter": {"authz": 1, "order": 1}, "keyAlgorithm": "ecdsa",
  "profiles": {"default": {"description": "default", "validityPeriod": 7776000}}}}
JSON

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

"$bin/pebble-challtestsrv" -defaultIPv4 127.0.0.1 -defaultIPv6 "" -dnsserver 127.0.0.1:8053 -management 127.0.0.1:8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" > challtestsrv.log 2>&1 &
pids+=($!)
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=5 "$bin/pebble" -strict -config pebble.json -dnsserver 127.0.0.1:8053 \
    > pebble.log 2>&1 &
pids+=($!)
(cd "$here/pebble_helper" && go build -o "$scr/pebble_helper" .)
"$scr/pebble_helper" serve -scratch "$scr" > helper.log 2>&1 &
pids+=($!)

for _ in $(seq 100); do
    curl -s --cacert ca.pem https://localhost:14001/dir > /dev/null && break
    sleep 0.1
done
curl -sf --cacert ca.pem https://localhost:15000/roots/0 > pebble-root.pem

cd "$root"
zig build interop-acme -- --scratch "$scr"
cd "$scr"

if (( check == 0 )); then
    PEBBLE_VERSION=$(go version -m "$bin/pebble" | awk '$1 == "mod" { print $3 }') \
        "$scr/pebble_helper" gen transcript.jsonl "$root/modules/acme/src/testdata/pebble_transcript.zig"
    echo "pebble.sh: transcript -> modules/acme/src/testdata/pebble_transcript.zig"
fi
