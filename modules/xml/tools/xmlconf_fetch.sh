#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Fetches the W3C XML Conformance Test Suite (release 2008-08-27) into
# `modules/xml/tools/xmlconf-suite/`, a gitignored directory of its own. The
# suite is NEVER committed or redistributed by this repository: its files carry
# notices that grant no permission to copy them, so each developer downloads
# their own copy from W3C for local use. `xmlconf_run.zig` then runs it.
#
# The archive is pinned by sha256; a mismatch deletes the download and fails.
# Not in `.zig-cache`: that directory must stay droppable at any moment, and a
# download from an external service does not belong in it.
#
#   modules/xml/tools/xmlconf_fetch.sh            # idempotent
#   FORCE=1 modules/xml/tools/xmlconf_fetch.sh    # download again
#
# Needs: curl, sha256sum, unzip.
set -euo pipefail

URL="https://www.w3.org/XML/Test/xmlts20080827.zip"
SHA256="4e5bc821d521d68b0666f5cc7825cc6a61010d114086e963a21db7897b369d43"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$HERE/xmlconf-suite"
STAMP="$DEST/.fetched-$SHA256"

if [ -f "$STAMP" ] && [ -f "$DEST/xmlconf/xmlconf.xml" ] && [ "${FORCE:-0}" != 1 ]; then
  echo "xmlconf suite already present: $DEST/xmlconf"
  exit 0
fi

for tool in curl sha256sum unzip; do
  command -v "$tool" >/dev/null || { echo "$tool not found" >&2; exit 2; }
done

mkdir -p "$DEST"
ZIP="$DEST/xmlts.zip.part"
curl -sSfL --max-time 300 -o "$ZIP" "$URL"
got="$(sha256sum "$ZIP" | cut -d' ' -f1)"
if [ "$got" != "$SHA256" ]; then
  rm -f "$ZIP"
  echo "sha256 mismatch for $URL" >&2
  echo "  expected $SHA256" >&2
  echo "  got      $got" >&2
  exit 1
fi
unzip -q -o "$ZIP" -d "$DEST"
rm -f "$ZIP"
: > "$STAMP"
echo "xmlconf suite fetched and verified: $DEST/xmlconf"
