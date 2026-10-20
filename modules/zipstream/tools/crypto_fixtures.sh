#!/usr/bin/env bash
# Re-takes the encrypted-archive fixtures in src/testdata/crypto/ and checks
# the writer's AES output against 7-Zip. Needs 7z (p7zip) and Info-ZIP zip.
#
#   modules/zipstream/tools/crypto_fixtures.sh      (from the repository root)
#
# 1. 7-Zip writes WinZip AES archives (AES-128/192/256, Deflate and Store)
#    and Info-ZIP writes ZipCrypto ones (Deflate and Store) of our own
#    content; src/crypto_test.zig decrypts every one.
# 2. tools/aes_golden.zig writes our AES archive (fixed salts); 7-Zip must
#    test and extract it to the same content; it becomes
#    src/testdata/crypto/ours_aes.zip, which the writer must reproduce.
set -euo pipefail
root=$(pwd)
mod=modules/zipstream
out=$mod/src/testdata/crypto
work=$root/.zig-cache/zipstream-crypto
mkdir -p "$work" "$out"
cd "$work"
for f in *; do [ -f "$f" ] && rm "$f"; done
for i in $(seq 0 299); do echo "line $i: Příliš žluťoučký kůň úpěl ďábelské ódy"; done > big.txt
printf 'tiny\n' > tiny.txt
touch -d @1700000000 big.txt tiny.txt
for s in 128 192 256; do
  7z a -tzip -psecret -mem=AES$s -mx5 "7z_aes${s}_deflate.zip" big.txt tiny.txt >/dev/null
  7z a -tzip -psecret -mem=AES$s -mx0 "7z_aes${s}_store.zip" big.txt tiny.txt >/dev/null
done
zip -q -P secret zc_deflate.zip big.txt tiny.txt
zip -q -0 -P secret zc_store.zip big.txt tiny.txt
for f in 7z_*.zip zc_*.zip; do cp "$f" "$root/$out/$f"; done
cd "$root"
zig run -fllvm --dep zipstream -Mroot=$mod/tools/aes_golden.zig \
  --dep zstd --dep aes192 -Mzipstream=$mod/src/root.zig \
  -Mzstd=modules/zstd/src/root.zig -Maes192=modules/aes192/src/root.zig \
  --cache-dir .zig-cache -- "$work/ours_aes.zip"
7z t -psecret "$work/ours_aes.zip"
rm -f "$work"/aes*.txt
(cd "$work" && 7z x -y -psecret ours_aes.zip >/dev/null)
for f in aes256_deflate.txt aes128_store.txt aes192_deflate_streamed.txt; do
  cmp "$work/$f" "$work/big.txt"
done
cp "$work/ours_aes.zip" "$out/ours_aes.zip"
echo "crypto fixtures re-taken; 7-Zip opened ours_aes.zip"
