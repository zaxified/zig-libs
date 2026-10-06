#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Re-derive the iproute2 oracle behind tcplan's "dual-stack circuit" golden
# (`src/root.zig`, test "oracle: dual-stack circuit with HTB knobs ...").
#
#     modules/tcplan/tools/capture_dualstack.sh
#
# Each line below is the `tc` command that realises one op of the plan tcplan
# compiles for that test's topology (one queue, a site, one subscriber with an
# IPv4 /32 + an IPv6 /56 and burst/cburst/prio/quantum set). Every command is
# run through the sibling tc module's capture recipe (`unshare -rn` + strace,
# nothing touches the host) and its `sendmsg` payload is printed as hex with
# `nlmsg_seq` (bytes 8..11) zeroed -- the test builds with seq 0.
#
# The kernel is free to REJECT these (lo has one TX queue, so `mq` fails, and a
# kernel without sch_cake/cls_flower refuses those): only the request bytes
# iproute2 puts on the wire are the oracle, not the kernel's answer.
#
# Provenance of the committed capture: iproute2-6.1.0, Linux 6.18, and
# /proc/net/psched = 000003e8 00000040 000f4240 3b9aca00 (the calibration
# `tc.ratespec.golden_psched` pins). A different iproute2 may legitimately
# differ; compare `tc -V` before believing a mismatch is a defect.
#
# Needs iproute2, strace, python3 and unprivileged user namespaces -- which is
# why this is in tools/ and not src/ (CONVENTIONS.md §9).
set -eu
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cap="$here/../../tc/tools/capture.sh"

cmds=(
  "tc qdisc add dev lo root handle 7fff: mq"
  "tc qdisc add dev lo parent 7fff:1 handle 1: htb"
  "tc class add dev lo parent 1: classid 1:1 htb rate 1gbit ceil 1gbit"
  "tc class add dev lo parent 1:1 classid 1:2 htb rate 100mbit ceil 200mbit burst 32k cburst 64k prio 2 quantum 3000"
  "tc qdisc add dev lo parent 1:2 handle 2: cake"
  "tc filter add dev lo parent 1: protocol ip prio 1 flower dst_ip 100.64.0.1/32 classid 1:2"
  "tc filter add dev lo parent 1: protocol ipv6 prio 2 flower dst_ip 2001:db8:1::/56 classid 1:2"
)

for c in "${cmds[@]}"; do
  echo "// $c"
  hex="$("$cap" "$c")"
  [ -n "$hex" ] || { echo "no sendmsg captured for: $c" >&2; exit 1; }
  # one datagram per command; zero nlmsg_seq
  echo "${hex:0:16}00000000${hex:24}"
done
