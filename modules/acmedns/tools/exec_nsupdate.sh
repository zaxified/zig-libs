#!/bin/sh
# SPDX-License-Identifier: MIT
#
# The program `acmedns.Exec` runs in the interop (lego's exec protocol:
# $1 = present|cleanup, $2 = the record's absolute name, $3 = the TXT value),
# doing what such a hook usually does in the field: an RFC 2136 update with
# BIND's nsupdate. ACMEDNS_DNS_PORT and ACMEDNS_TSIG come from tools/interop.sh.
set -eu
case $1 in
present) line="update add $2 60 TXT \"$3\"" ;;
cleanup) line="update delete $2 TXT \"$3\"" ;;
*) echo "usage: $0 present|cleanup FQDN VALUE" >&2; exit 2 ;;
esac
nsupdate -y "hmac-sha256:hmac-sha256.key.:$ACMEDNS_TSIG" <<NSUPDATE
server 127.0.0.1 $ACMEDNS_DNS_PORT
$line
send
NSUPDATE
