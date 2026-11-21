#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# `AcmeDns`, its account `Store` and `Dns01Solver` against the REAL acme-dns
# server (joohoi/acme-dns, Go, MIT; run as a black-box binary, never vendored):
# its own DNS listener for auth.delegated.test and its HTTP API on loopback, a
# fresh database each run. Then `zig build interop-acmedns -- --real-api ...`
# (see `realAcmeDns` in tools/interop.zig). No Pebble, no Python peer.
#
#   modules/acmedns/tools/real_acmedns.sh     # from anywhere; builds, so under `hw run`
#
# Needs the acme-dns binary in $ACMEDNS_BIN (default
# ~/.local/share/zig-libs/oracle-bin/acme-dns/acme-dns), installed once with
#   GOBIN=~/.local/share/zig-libs/oracle-bin/acme-dns go install github.com/joohoi/acme-dns@master
# (a pure-Go SQLite: no cgo). The database runs with a memory journal: the
# default journal mode fails on this kernel's overlay ("disk I/O error").
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
bin=${ACMEDNS_BIN:-$HOME/.local/share/zig-libs/oracle-bin/acme-dns/acme-dns}
scr=$root/.zig-cache/real-acmedns
mkdir -p "$scr"
cd "$scr"
rm -f acme-dns.db run.log

read -r dns_port api_port < <(python3 -I -c '
import socket
a, b = socket.socket(), socket.socket()
a.bind(("127.0.0.1", 0)); b.bind(("127.0.0.1", 0))
print(a.getsockname()[1], b.getsockname()[1])')

cat > config.cfg <<CFG
[general]
listen = "127.0.0.1:$dns_port"
protocol = "both"
domain = "auth.delegated.test"
nsname = "auth.delegated.test"
nsadmin = "admin.delegated.test"
records = [
    "auth.delegated.test. A 127.0.0.1",
    "auth.delegated.test. NS auth.delegated.test.",
]
debug = false

[database]
engine = "sqlite"
connection = "file:acme-dns.db?_pragma=journal_mode(MEMORY)&_pragma=synchronous(OFF)"

[api]
ip = "127.0.0.1"
port = "$api_port"
tls = "none"
corsorigins = ["*"]
use_header = false
header_name = "X-Forwarded-For"
disable_registration = false

[logconfig]
loglevel = "info"
logtype = "stdout"
logformat = "text"
CFG

pid=
cleanup() { [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true; wait 2>/dev/null || true; }
trap cleanup EXIT
"$bin" -c config.cfg > run.log 2>&1 &
pid=$!
for _ in $(seq 100); do
    curl -s -m 1 -o /dev/null -X POST "http://127.0.0.1:$api_port/register" -d '{}' && break
    sleep 0.1
done
echo "acme-dns: DNS 127.0.0.1:$dns_port, API 127.0.0.1:$api_port"

cd "$root"
zig build interop-acmedns -- --real-api "http://127.0.0.1:$api_port" --real-dns "$dns_port" --scratch "$scr"
