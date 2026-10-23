#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# The acme module's `**Ahead:**` probe: x/crypto/acme/autocert v0.58.0 against
# Pebble (see main.go for the two scenarios). Pebble issues 24-hour
# certificates here (step-ca's default lifetime).
#
#   modules/acme/tools/autocert_lead/run.sh
#
# Needs go (the module cache must hold golang.org/x/crypto v0.58.0 and its
# x/net, x/text; GOPROXY=off below), openssl and the Pebble binaries of
# ../pebble.sh. Loopback only; ports 5001 5002 8053 8055 14000 15000.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
bin=${PEBBLE_BIN:-$HOME/.local/share/zig-libs/oracle-bin/pebble}
scr=$root/.zig-cache/autocert-lead

mkdir -p "$scr"
cd "$scr"
for f in pebble.log challtestsrv.log; do rm -f "$f"; done
for d in cache-fleet cache-renew; do
    if [[ -d $d ]]; then
        for f in "$d"/*; do [[ -e $f ]] && rm -f "$f"; done
        rmdir "$d"
    fi
done

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=autocert-lead-ca \
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
  "keyAlgorithm": "ecdsa",
  "profiles": {"default": {"description": "24 hours", "validityPeriod": 86400}}}}
JSON

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

"$bin/pebble-challtestsrv" -defaultIPv4 127.0.0.1 -defaultIPv6 "" -dnsserver 127.0.0.1:8053 -management 127.0.0.1:8055 \
    -http01 "" -https01 "" -tlsalpn01 "" -doh "" > challtestsrv.log 2>&1 &
pids+=($!)
PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 PEBBLE_AUTHZREUSE=0 "$bin/pebble" -config pebble.json \
    -dnsserver 127.0.0.1:8053 > pebble.log 2>&1 &
pids+=($!)

(cd "$here" && GOFLAGS=-mod=mod GOPROXY=off go build -o "$scr/autocert_lead" .)

for _ in $(seq 100); do
    curl -s --cacert ca.pem https://localhost:14000/dir > /dev/null && break
    sleep 0.1
done

mkdir -p cache-fleet cache-renew
"$scr/autocert_lead" -scenario fleet -ca ca.pem -scratch cache-fleet
"$scr/autocert_lead" -scenario renew -ca ca.pem -scratch cache-renew
