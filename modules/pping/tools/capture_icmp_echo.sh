#!/bin/sh
# SPDX-License-Identifier: MIT
#
# Recipe for the ICMP / ICMPv6 echo goldens in ../src/echo_kat.zig.
#
# Runs iputils `ping` against a second address on loopback inside a throwaway
# network namespace (`unshare --user --map-root-user --net`: CAP_NET_RAW exists
# only inside that disposable namespace, nothing on the host changes) and
# captures both directions with `tcpdump -i lo`. Writes, into OUTDIR:
#   v4.pcap   v4.ping.txt     ping -c 3 127.0.0.1 -> 127.0.0.2
#   v6.pcap   v6.ping.txt     ping -6 -c 3 fd00::1 -> fd00::2
#   wrap.pcap wrap.ping.txt   ping -f -c 65537 (sequence 65535 -> 0 wrap);
#                             the filter keeps only seq 65535 and 0
# then prints every frame as hex with nanosecond timestamps
# (`tcpdump -r X -tt --time-stamp-precision=nano -xx`). The goldens paste the
# frames' IP packets (the 14-byte DLT_EN10MB loopback header is dropped),
# the capture timestamps, and the `time=` values ping itself reported.
#
# Needs: iputils-ping, tcpdump, iproute2, util-linux `unshare`.
# Usage: tools/capture_icmp_echo.sh OUTDIR
set -eu
out=${1:?usage: $0 OUTDIR}
mkdir -p "$out"
out=$(cd "$out" && pwd)

unshare --user --map-root-user --net sh -eu -c '
out=$1
ip link set lo up
v6=no
if [ -e /proc/sys/net/ipv6 ]; then
    ip -6 addr add fd00::1/64 dev lo nodad
    ip -6 addr add fd00::2/64 dev lo nodad
    v6=yes
fi

cap() { # name filter cmd...
    name=$1; filter=$2; shift 2
    tcpdump -Z root -i lo -U -n --time-stamp-precision=nano -w "$out/$name.pcap" "$filter" 2>/dev/null &
    pid=$!
    sleep 1
    "$@" > "$out/$name.ping.txt"
    sleep 1
    kill -INT $pid; wait $pid || true
}
cap v4   "icmp" ping -n -c 3 -i 0.2 -I 127.0.0.1 127.0.0.2
[ $v6 = no ] || cap v6   "icmp6 and (ip6[40] = 128 or ip6[40] = 129)" ping -6 -n -c 3 -i 0.2 -I fd00::1 fd00::2
cap wrap "icmp and (icmp[6:2] = 65535 or icmp[6:2] = 0)" ping -n -q -f -c 65537 -I 127.0.0.1 127.0.0.2
' sh "$out"

for f in v4 v6 wrap; do
    [ -e "$out/$f.pcap" ] || { echo "== $f: skipped (kernel without IPv6)"; continue; }
    echo "== $f.ping.txt"; cat "$out/$f.ping.txt"
    echo "== $f.pcap";     tcpdump -r "$out/$f.pcap" -n -tt --time-stamp-precision=nano -xx 2>/dev/null
done
