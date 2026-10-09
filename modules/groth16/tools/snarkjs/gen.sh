#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# The snarkjs / circom oracle for groth16's file formats, prover and phase 2.
#
# snarkjs (GPL-3.0) and circom (GPL-3.0) are run as black boxes: built
# packages from npm, their source never read, only their OUTPUT kept. The
# format knowledge in src/snarkjs_bin.zig, zkey.zig, ptau.zig and circom.zig
# was established by comparing the bytes these tools write with the decimals
# their own `export json` commands print.
#
#     tools/snarkjs/gen.sh fixtures   # regenerate src/testdata/snarkjs (small circuit)
#     tools/snarkjs/gen.sh ours       # snarkjs judges OUR proof (ours_proof.json)
#     tools/snarkjs/gen.sh big        # 10 000-constraint circuit, both directions
#     tools/snarkjs/gen.sh json       # how ffjavascript itself writes/reads JSON points
#
# Work happens in <repo>/.zig-cache/g16 (droppable). Node is fetched there
# because snarkjs's worker pool crashes under Bun 1.3 (SIGILL), and setting
# `process.browser` to dodge that makes its file layer `fetch()` paths.
#
# ⚠ `fixtures` makes NEW random ceremony values: the decimal pins in
# snarkjs_files_test.zig and ours_proof.json then change, so run `ours` after
# it and update the test (the expected values are whatever snarkjs prints).
#
# What the runs of 2026-10-02 printed:
#   fixtures: groth16 verify -> OK!; zkey verify t.r1cs pot.ptau t1.zkey -> ZKey Ok!
#   ours:     our proof -> OK!; pi_a.x + 1 -> "Proof commitments are not valid."
#   json:     G1 zero -> ["0","1","0"]; G2 zero -> [["0","0"],["1","0"],["0","0"]];
#             G1 generator -> ["1","2","1"]; both our identity encodings parse
#             back as zero (pins in snarkjs_export.zig).
#   big:      our proof on snarkjs's key -> OK!; newzkey vs groth16 setup ->
#             64 differing bytes of 5 130 900 (the circuit hash, section 10);
#             our verify on b0/b1 -> ok; our contribution -> our verify ok, our
#             PoK checked, snarkjs prove + verify with it -> OK!;
#             snarkjs zkey verify on our keys -> "Circuit does not match" /
#             "INVALID(1): Inconsistent transcript" (expected: SPEC.md backlog).
#   timings (big, one core, ReleaseFast): load 201 ms, prove 1926 ms,
#             newzkey 1008 ms, verify 2013 ms, contribute 12087 ms;
#             snarkjs groth16 prove (all cores) 1.77 s.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
mod=$(cd "$here/../.." && pwd)
repo=$(cd "$mod/../.." && pwd)
work=$repo/.zig-cache/g16
mkdir -p "$work"
cd "$work"

NODE_V=v22.20.0
SNARKJS_V=0.7.6
CIRCOM2_V=0.2.23 # npm package; bundles circom 2.2.3

if [ ! -x node/bin/node ]; then
  curl -fsSL "https://nodejs.org/dist/$NODE_V/node-$NODE_V-linux-x64.tar.xz" -o node.tar.xz
  curl -fsSL "https://nodejs.org/dist/$NODE_V/SHASUMS256.txt" |
    grep " node-$NODE_V-linux-x64.tar.xz\$" | sed 's/node-.*/node.tar.xz/' | sha256sum -c
  tar xf node.tar.xz && mv "node-$NODE_V-linux-x64" node && rm node.tar.xz
fi
if [ ! -d node_modules/snarkjs ] || [ ! -d node_modules/circom2 ]; then
  printf '{ "name": "g16-oracle", "private": true, "dependencies": { "snarkjs": "%s", "circom2": "%s" } }\n' \
    "$SNARKJS_V" "$CIRCOM2_V" > package.json
  PATH=$work/node/bin:$PATH node/bin/npm install --no-audit --no-fund >/dev/null
fi
N=$work/node/bin/node
S="$N $work/node_modules/snarkjs/build/cli.cjs"
CIRCOM="$N $work/node_modules/circom2/cli.js"
last() { sed 's/\x1b\[[0-9;]*m//g' | grep -Ev '^\s+[0-9a-f]{8} ' | tail -1; }

build_g16() {
  local zig=${ZIG:-zig}
  (cd "$repo" && "$zig" build-exe -OReleaseFast -fllvm \
    --dep groth16 -Mroot=modules/groth16/tools/snarkjs/g16.zig \
    --dep bn254 -Mgroth16=modules/groth16/src/root.zig \
    --dep montint -Mbn254=modules/bn254/src/root.zig \
    -Mmontint=modules/montint/src/root.zig \
    --cache-dir .zig-cache -femit-bin=.zig-cache/g16/g16)
}

case "${1:-}" in
fixtures)
  td=$mod/src/testdata/snarkjs
  cp "$td/t.circom" "$td/input.json" .
  $CIRCOM t.circom --r1cs --wasm -o . >/dev/null
  $S powersoftau new bn128 4 pot0.ptau >/dev/null
  $S powersoftau contribute pot0.ptau pot1.ptau --name=one -e="fixed entropy one" >/dev/null
  $S powersoftau prepare phase2 pot1.ptau pot.ptau >/dev/null
  $S groth16 setup t.r1cs pot.ptau t0.zkey >/dev/null
  $S zkey contribute t0.zkey t1.zkey --name=c1 -e="fixed entropy two" >/dev/null
  $S zkey export verificationkey t1.zkey vk.json >/dev/null
  $N t_js/generate_witness.js t_js/t.wasm input.json t.wtns
  $S groth16 prove t1.zkey t.wtns proof.json public.json >/dev/null
  $S groth16 verify vk.json public.json proof.json 2>&1 | last
  $S zkey verify t.r1cs pot.ptau t1.zkey 2>&1 | last
  cp t.r1cs t.wtns t0.zkey t1.zkey pot.ptau vk.json proof.json public.json "$td/"
  ;;
ours)
  td=$mod/src/testdata/snarkjs
  $S groth16 verify "$td/vk.json" "$td/public.json" "$td/ours_proof.json" 2>&1 | last
  $N -e 'const d=require(process.argv[1]); d.pi_a[0]=(BigInt(d.pi_a[0])+1n).toString();
         require("fs").writeFileSync("ours_bad.json", JSON.stringify(d))' "$td/ours_proof.json"
  $S groth16 verify "$td/vk.json" "$td/public.json" ours_bad.json 2>&1 | last || true
  ;;
json)
  # The JSON point shape snarkjs_export.zig writes, asked of the library's
  # public curve API (run, not read): identity elements are the one case no
  # snarkjs output file in this recipe ever carries.
  $N -e '
    const S = (o) => JSON.stringify(o, (k, v) => typeof v === "bigint" ? v.toString() : v);
    require("ffjavascript").buildBn128(true).then(async (c) => {
      console.log("G1 zero ->", S(c.G1.toObject(c.G1.zero)));
      console.log("G2 zero ->", S(c.G2.toObject(c.G2.zero)));
      console.log("G1 generator ->", S(c.G1.toObject(c.G1.toAffine(c.G1.g))));
      console.log("our G1 identity parses as zero:", c.G1.isZero(c.G1.fromObject(["0", "1", "0"])));
      console.log("our G2 identity parses as zero:",
        c.G2.isZero(c.G2.fromObject([["0", "0"], ["1", "0"], ["0", "0"]])));
      await c.terminate();
    });'
  ;;
big)
  build_g16
  mkdir -p big && cd big
  if ! cmp -s "$here/big.circom" big.circom || [ ! -f big.wtns ]; then # ~4 min of snarkjs
    cp "$here/big.circom" .
    echo '{"x":"3","y":"5","k":"11"}' > input.json
    $CIRCOM big.circom --r1cs --wasm -o . >/dev/null
    $S powersoftau new bn128 14 p0.ptau >/dev/null
    $S powersoftau contribute p0.ptau p1.ptau --name=one -e="big entropy one" >/dev/null
    $S powersoftau prepare phase2 p1.ptau pot.ptau >/dev/null
    $S groth16 setup big.r1cs pot.ptau b0.zkey >/dev/null
    $S zkey contribute b0.zkey b1.zkey --name=c1 -e="big entropy two" >/dev/null
    $S zkey export verificationkey b1.zkey vk.json >/dev/null
    $N big_js/generate_witness.js big_js/big.wasm input.json big.wtns
  fi
  G=../g16
  echo "-- our proof, snarkjs's key"
  $G prove b1.zkey big.wtns oproof.json opublic.json
  $S groth16 verify vk.json opublic.json oproof.json 2>&1 | last
  echo "-- our newzkey vs snarkjs groth16 setup"
  $G newzkey big.r1cs pot.ptau o0.zkey
  { cmp -l b0.zkey o0.zkey || true; } | wc -l
  echo "-- our verify on snarkjs's keys"
  $G verify big.r1cs pot.ptau b0.zkey
  $G verify big.r1cs pot.ptau b1.zkey
  echo "-- our contribution; snarkjs proves with it"
  $G contribute b1.zkey o2.zkey zig
  $G verify big.r1cs pot.ptau o2.zkey
  $S zkey export verificationkey o2.zkey vk2.json >/dev/null
  $S groth16 prove o2.zkey big.wtns p2.json pub2.json >/dev/null
  $S groth16 verify vk2.json pub2.json p2.json 2>&1 | last
  echo "-- snarkjs zkey verify on our keys (expected to refuse; SPEC.md backlog)"
  $S zkey verify big.r1cs pot.ptau o0.zkey 2>&1 | last || true
  $S zkey verify big.r1cs pot.ptau o2.zkey 2>&1 | last || true
  ;;
*)
  sed -n '3,15p' "$here/$(basename "$0")"
  exit 2
  ;;
esac
