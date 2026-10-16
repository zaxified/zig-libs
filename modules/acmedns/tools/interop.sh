#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# acmedns against live peers: tools/peer.py (an authoritative DNS server with
# RFC 2136 + TSIG built on dnspython, an acme-dns API stand-in and an httpreq
# endpoint) and Pebble, Let's Encrypt's ACME test CA (MPL-2.0, run as a
# black-box binary, never vendored), whose validation authority resolves
# through that DNS server (-dnsserver). Then `zig build interop-acmedns`
# issues one certificate per publisher (see tools/interop.zig).
#
#   modules/acmedns/tools/interop.sh        # from anywhere; builds, so under `hw run`
#
# Needs python3 + dnspython, nsupdate (bind9-dnsutils), openssl, curl, and the
# Pebble binary in $PEBBLE_BIN (default ~/.local/share/zig-libs/oracle-bin/pebble),
# installed once with
#   GOBIN=$PEBBLE_BIN go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
# Loopback only; Pebble on its fixed ports 14000 (ACME) and 15000 (management),
# so it cannot run beside acme's tools/pebble.sh.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
bin=${PEBBLE_BIN:-$HOME/.local/share/zig-libs/oracle-bin/pebble}
scr=$root/.zig-cache/interop-acmedns
mkdir -p "$scr"
cd "$scr"
rm -f ports pebble.log peer.log

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 -subj /CN=acmedns-interop-ca \
    -keyout ca.key -out ca.pem 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=localhost -keyout localhost.key \
    -out localhost.csr 2>/dev/null
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\n' > san.ext
openssl x509 -req -in localhost.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 2 -extfile san.ext \
    -out localhost.pem 2>/dev/null

pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

python3 -I "$here/peer.py" "$scr/ports" > peer.log 2>&1 &
pids+=($!)
for _ in $(seq 100); do [[ -s ports ]] && break; sleep 0.1; done
read -r dns_port http_port < ports
echo "peer: DNS 127.0.0.1:$dns_port, HTTP 127.0.0.1:$http_port"

cat > pebble.json <<JSON
{"pebble": {"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
  "certificate": "$scr/localhost.pem", "privateKey": "$scr/localhost.key",
  "httpPort": 5002, "tlsPort": 5001, "ocspResponderURL": "", "externalAccountBindingRequired": false,
  "retryAfter": {"authz": 1, "order": 1}, "keyAlgorithm": "ecdsa"}}
JSON
PEBBLE_VA_NOSLEEP=1 "$bin/pebble" -strict -config pebble.json -dnsserver "127.0.0.1:$dns_port" > pebble.log 2>&1 &
pids+=($!)
for _ in $(seq 100); do
    curl -s --cacert ca.pem https://localhost:14000/dir > /dev/null && break
    sleep 0.1
done

export ACMEDNS_DNS_PORT=$dns_port
ACMEDNS_TSIG=$(printf %s hmac-sha256.key. | openssl dgst -sha256 -binary | base64)
export ACMEDNS_TSIG
cd "$root"
zig build interop-acmedns -- --scratch "$scr" --dns-port "$dns_port" --http-port "$http_port" \
    --exec "$here/exec_nsupdate.sh"
