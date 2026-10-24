#!/usr/bin/env bash
# Build the pagecache side and run both sides of the scan-resistance probe.
# Usage (from anywhere):  hw run --slots 1 --name pc-probe -- bash run.sh
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
m=$root/modules
out=$root/.zig-cache/pc-probe
mkdir -p "$out"
cd "$root"
zig build-exe -OReleaseSafe -femit-bin="$out/scan_probe" --cache-dir "$out/c" --global-cache-dir "$out/g" \
  --dep pagecache --dep kvtree -Mroot="$here/probe.zig" \
  --dep kvtree --dep ramcache -Mpagecache="$m/pagecache/src/root.zig" \
  --dep kv --dep crc32 -Mkvtree="$m/kvtree/src/root.zig" \
  -Mkv="$m/kv/src/root.zig" -Mcrc32="$m/crc32/src/root.zig" -Mramcache="$m/ramcache/src/root.zig"
"$out/scan_probe"
for cfg in "2000 200 100 10" "2000 200 100 2" "2000 200 180 10"; do
  echo "sqlite     N/C/H/passes = $cfg"
  strace -f -e trace=pread64,getppid -o "$out/st.out" python3 -I "$here/sqlite_side.py" $cfg "$out/t.db"
  python3 "$here/sqlite_side.py" --count "$out/st.out"
done
