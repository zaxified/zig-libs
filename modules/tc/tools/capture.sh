#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Re-capture a golden from the real iproute2 binary and print the exact
# `sendmsg` payload as lowercase hex, so it can be compared with the constants
# in modules/tc/src/goldens.zig.
#
#     modules/tc/tools/capture.sh '<tc command>' ['<setup command>']
#
# Runs entirely inside an unprivileged `unshare -rn` network namespace, so
# nothing touches the host's network configuration -- that is what makes this
# safe to run on a developer machine rather than only in a throwaway VM.
#
# ⚠ Bytes 8..11 of each datagram are `nlmsg_seq`, which differ per run;
# `verify_goldens.py` zeroes them on both sides before comparing.
#
# ⚠ This needs a foreign toolchain -- iproute2, strace, and unprivileged user
# namespaces -- which is exactly why it lives in tools/ and not in src/:
# `zig build test-tc` must never require any of them (CONVENTIONS.md §9).
set -u
cmd="$1"
setup="${2:-true}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp "${TMPDIR:-/tmp}/tc-capture.XXXXXX")"
trap 'rm -f "$tmp"' EXIT

unshare -rn bash -c "
  ip link set lo up 2>/dev/null
  $setup >/dev/null 2>&1
  exec strace -f -e trace=sendmsg -e write=all -xx -s 65536 -e abbrev=none $cmd
" >/dev/null 2>"$tmp"

python3 "$here/parse_strace.py" "$tmp"
