#!/usr/bin/env bash
# Fetch Ubuntu's signed prometheus-blackbox-exporter package (no install, no
# root), run it on 127.0.0.1:19115 from .zig-cache, run probe.py.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
w="$repo/.zig-cache/blackbox-probe"
mkdir -p "$w/deb"
if [ ! -x "$w/root/usr/bin/prometheus-blackbox-exporter" ]; then
    (cd "$w/deb" && apt-get download prometheus-blackbox-exporter)
    dpkg-deb -x "$w"/deb/prometheus-blackbox-exporter_*.deb "$w/root"
fi
bin="$w/root/usr/bin/prometheus-blackbox-exporter"
"$bin" --version 2>&1 | head -1
"$bin" --config.file="$here/blackbox.yml" --web.listen-address=127.0.0.1:19115 >"$w/exporter.log" 2>&1 &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
for _ in $(seq 50); do
    curl -fsS -o /dev/null http://127.0.0.1:19115/ 2>/dev/null && break
    sleep 0.1
done
timeout 60 python3 -I "$here/probe.py" 127.0.0.1:19115
