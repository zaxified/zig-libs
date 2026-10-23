#!/usr/bin/env bash
# Fetch Ubuntu's signed nginx package (no install, no root), run it on
# 127.0.0.1:18431 from a scratch prefix under .zig-cache, run probe.py.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
w="$repo/.zig-cache/nginx-probe"
mkdir -p "$w/deb" "$w/logs" "$w/tmp" "$w/html"
if [ ! -x "$w/root/usr/sbin/nginx" ]; then
    (cd "$w/deb" && apt-get download nginx)
    dpkg-deb -x "$w"/deb/nginx_*.deb "$w/root"
fi
"$w/root/usr/sbin/nginx" -v
head -c 4000000 /dev/zero > "$w/html/big"
echo ok > "$w/html/index.html"
cp "$here/nginx.conf" "$w/nginx.conf"
"$w/root/usr/sbin/nginx" -p "$w" -c "$w/nginx.conf" &
pid=$!
trap 'kill $pid 2>/dev/null || true' EXIT
sleep 1
timeout 30 python3 -I "$here/probe.py" "${1:-20}"
