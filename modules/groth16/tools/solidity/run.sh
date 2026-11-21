#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# The EVM oracle for solidity.zig and snarkjs_export.writeSolidityCalldata.
# solc (MIT, npm `solc`) compiles the contract `g16 solidity` writes for the
# committed snarkjs verification key; @ethereumjs/evm (MPL-2.0) runs it on the
# calldata `g16 calldata` writes for snarkjs's proof, and on three tamperings.
# Both are run, not read. Uses gen.sh's Node in <repo>/.zig-cache/g16 (run
# `tools/snarkjs/gen.sh json` once first to fetch it); npm packages go to
# <repo>/.zig-cache/sol (droppable).
#
#     tools/solidity/run.sh
#
# What the run of 2026-11-21 printed (solc 0.8.30, @ethereumjs/evm 10.1.3):
#     as given: true (gas 209 281); a.x + 1: false (16 715); input[0] + 1: false
#     (201 781); input[0] + r: false (642). The contract text is pinned by its
#     SHA-256 in src/snarkjs_files_test.zig.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
mod=$(cd "$here/../.." && pwd)
repo=$(cd "$mod/../.." && pwd)
work=$repo/.zig-cache/sol
td=$mod/src/testdata/snarkjs
N=$repo/.zig-cache/g16/node/bin/node
mkdir -p "$work"
cd "$work"
if [ ! -d node_modules/@ethereumjs/evm ] || [ ! -d node_modules/solc ]; then
  printf '{ "name": "sol-oracle", "private": true, "dependencies": { "solc": "0.8.30", "@ethereumjs/evm": "10.1.3", "@ethereumjs/util": "10.1.3", "ethereum-cryptography": "3.2.0" } }\n' > package.json
  PATH=$(dirname "$N"):$PATH npm install --no-audit --no-fund >/dev/null
fi
# montint's build options (`zl_options`): any options.zig a `zig build` of this
# repo wrote; run `scripts/modtest groth16` once first.
opt=$repo/$(cd "$repo" && grep -l montint_asm_unroll .zig-cache/o/*/options.zig | head -1)
(cd "$repo" && "${ZIG:-zig}" build-exe -OReleaseFast -fllvm \
  --dep groth16 -Mroot=modules/groth16/tools/snarkjs/g16.zig \
  --dep bn254 -Mgroth16=modules/groth16/src/root.zig \
  --dep montint -Mbn254=modules/bn254/src/root.zig \
  --dep zl_options -Mmontint=modules/montint/src/root.zig \
  -Mzl_options="$opt" \
  --cache-dir .zig-cache -femit-bin=.zig-cache/sol/g16)
./g16 solidity "$td/vk.json" verifier.sol
./g16 calldata "$td/proof.json" "$td/public.json" > calldata.txt
NODE_PATH=$work/node_modules "$N" "$here/evm.cjs" verifier.sol calldata.txt
