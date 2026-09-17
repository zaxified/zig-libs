#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# WHY THIS EXISTS: three independent XML implementations over the same corpus.
# The module's own tests answer "does it do what we decided"; this answers
# "do libxml2 and expat agree", which is the only way an accept/reject
# divergence shows up at all. Audit F4 was found exactly here: four documents
# this parser took and both references refused.
#
# ⚠ THE DANGEROUS DIRECTION IS "WE ACCEPT, THEY REJECT". For a signature
# verifier, taking a document the other side throws away is worse than being
# strict -- so read the `zig-reject`/`zig-ignore` columns against the other two,
# not just for equality.
#
# WHAT IT NEEDS: `xmllint` (libxml2), python3 with `xml.etree.ElementTree`
# (expat), and the built `probe` binary. Measured present 2026-09-17:
# libxml 21502, expat via python3.
#
#   PROBE=<scratch>/probe modules/xml/tools/differ.sh <corpus-dir>
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
BASE="${BASE:-$REPO/.zig-cache/xml-corpus}"
PROBE="${PROBE:-$BASE/probe}"
DIR="${1:-$BASE/hostile}"

[ -d "$DIR" ] || { echo "no corpus at $DIR -- run gen_hostile.py first" >&2; exit 2; }
[ -x "$PROBE" ] || { echo "no probe binary at $PROBE -- see tools/README.md" >&2; exit 2; }
command -v xmllint >/dev/null || { echo "xmllint absent -- this is a statement about the machine, not the module" >&2; exit 2; }

printf "%-34s %-24s %-24s %-8s %-8s %s\n" FILE zig-reject zig-ignore xmllint python NOTE
for f in "$DIR"/*.xml; do
  z1=$("$PROBE" file "$f" 2>&1 | head -1)
  z2=$("$PROBE" file "$f" ignore 2>&1 | head -1)
  if xmllint --noout --nonet "$f" >/dev/null 2>&1; then xl=OK; else xl=ERR; fi
  py=$(python3 - "$f" <<'PY'
import sys, xml.etree.ElementTree as ET
try:
    ET.parse(sys.argv[1]); print("OK")
except Exception as e:
    print(type(e).__name__)
PY
)
  # ⚠ Flag the asymmetric case: this module accepts where BOTH references
  # refuse. That is the direction audit F4 lived in.
  note=""
  if { [ "$z1" = "OK" ] || [ "$z2" = "OK" ]; } && [ "$xl" = "ERR" ] && [ "$py" != "OK" ]; then
    note="<< we accept, both references reject"
  fi
  printf "%-34s %-24s %-24s %-8s %-8s %s\n" "$(basename "$f")" "$z1" "$z2" "$xl" "$py" "$note"
done
