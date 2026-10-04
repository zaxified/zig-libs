#!/usr/bin/env bash
# Capture the staged-delta fixtures `src/testdata/delta_capture.txt` pins:
# each scenario runs real `uci` commands (no commit) against a scratch config
# and records the config, the delta file `uci` wrote to its save dir, and what
# `uci -X show` / `uci show` then report. The tests replay the delta with
# `applyDelta`/`Editor` and must print the same `show` text byte for byte.
#
# The real `uci` is built from OpenWrt's tree into a droppable cache and used
# as a black box through its command line only (no source is read, nothing
# copyleft is kept in this repository — same precedent as capture-grammar.sh).
#
#   modules/uci/tools/capture-delta.sh > modules/uci/src/testdata/delta_capture.txt
#
# Build step (once): BASE defaults to <repo>/.zig-cache/uci-delta.
set -euo pipefail
REPO=$(cd "$(dirname "$0")/../../.." && pwd)
BASE=${BASE:-$REPO/.zig-cache/uci-delta}
U=$BASE/out/uci
if [ ! -x "$U" ]; then
    mkdir -p "$BASE/ref" "$BASE/out"
    [ -d "$BASE/ref/uci" ] || git clone -q --depth 1 https://git.openwrt.org/project/uci.git "$BASE/ref/uci"
    ( cd "$BASE/ref/uci" && printf '/* black-box oracle build */\n' > uci_config.h &&
      gcc -O1 -std=gnu99 -I. -DUCI_PREFIX='"/nonexistent"' -o "$U" cli.c libuci.c file.c util.c delta.c parse.c )
fi

W=$(mktemp -d "$BASE/run.XXXXXX")
# Per-file delete, then the empty directories (no recursive rm).
trap 'find "$W" -type f -delete; find "$W" -depth -type d -empty -delete' EXIT

# scenario NAME PKG CONFIG-TEXT -- uci-args... ;; uci-args... ;; ...
scenario() {
    local name=$1 pkg=$2 cfg=$3
    shift 3
    local n=$((${N:-0} + 1)); N=$n
    local C="$W/c$n" S="$W/s$n"
    mkdir -p "$C" "$S"
    printf '%s' "$cfg" > "$C/$pkg"
    local args=()
    for a in "$@" ";;"; do
        if [ "$a" = ";;" ]; then
            [ ${#args[@]} -gt 0 ] && "$U" -c "$C" -t "$S" "${args[@]}" > /dev/null
            args=()
        else
            args+=("$a")
        fi
    done
    echo "### scenario $name $pkg"
    echo "--- config"; cat "$C/$pkg"
    echo "--- delta"; cat "$S/$pkg" 2>/dev/null || true
    echo "--- show -X"; "$U" -c "$C" -t "$S" -X show "$pkg"
    echo "--- show"; "$U" -c "$C" -t "$S" show "$pkg"
    echo "### end"
}

scenario every_op probe "config alpha 'alpha'
	option v 'A'
	list l 'x'
	list l 'y'

config beta
	option w '1'

config beta
	option w '2'
" set probe.alpha.v=Z ";;" set "probe.alpha.q=it's" ";;" add_list probe.alpha.l=z ";;" \
  del_list probe.alpha.l=x ";;" set "probe.@beta[1].w=9" ";;" delete "probe.@beta[0]" ";;" \
  add probe gamma ";;" set probe.new=delta ";;" rename probe.alpha.v=vv ";;" \
  rename probe.alpha=aa ";;" reorder probe.aa=2 ";;" delete probe.aa.q ";;" set probe.aa.l=single

scenario lists_and_types p "config a 'n1'
	option o 'single'
	list l 'x'
	list l 'y'
	list l 'x'
	option k 'K'

config b
	option w '1'
" set p.n1=newtype ";;" add_list p.n1.o=two ";;" del_list p.n1.l=x ";;" delete p.n1.l=0 ";;" \
  reorder p.n1=99 ";;" add p q ";;" rename "p.@b[0]=named" ";;" set p.named.w= ";;" \
  set "p.n1.m=line1
line2" ";;" set "p.n1.d=a\"b\\c'd" ";;" add_list p.n1.l=last ";;" delete p.n1.l=5

scenario counter p "config a 'n1'

config b
" set p.newsec=t ";;" add p t ";;" add p t ";;" delete "p.@t[0]" ";;" add p u
