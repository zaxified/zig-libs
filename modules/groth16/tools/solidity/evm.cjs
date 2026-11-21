// SPDX-License-Identifier: MIT
//
// Compile a verifier contract with solc and call its verifyProof in an EVM
// (@ethereumjs/evm, its JS BN254 precompiles). Both run as black boxes.
//
//   node evm.cjs <contract.sol> <calldata line file>
//
// Prints one verdict line per case: the calldata as given, then three
// tamperings the contract must refuse.
const fs = require("fs");
const solc = require("solc");
const { createEVM } = require("@ethereumjs/evm");
const { Account, createAddressFromString, hexToBytes, bytesToHex } = require("@ethereumjs/util");
const { keccak256 } = require("ethereum-cryptography/keccak.js");

const R = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

async function main() {
  const [solPath, cdPath] = process.argv.slice(2);
  const src = fs.readFileSync(solPath, "utf8");
  const out = JSON.parse(solc.compile(JSON.stringify({
    language: "Solidity",
    sources: { "v.sol": { content: src } },
    settings: { optimizer: { enabled: true, runs: 200 }, outputSelection: { "*": { "*": ["evm.deployedBytecode.object"] } } },
  })));
  for (const e of out.errors || []) if (e.severity === "error") { console.log("solc:", e.formattedMessage); process.exit(1); }
  const code = out.contracts["v.sol"].Groth16Verifier.evm.deployedBytecode.object;
  console.log(`solc ${solc.version()}: compiled, ${code.length / 2} bytes`);

  const [a, b, c, input] = JSON.parse("[" + fs.readFileSync(cdPath, "utf8").trim() + "]");
  const sig = `verifyProof(uint256[2],uint256[2][2],uint256[2],uint256[${input.length}])`;
  const sel = bytesToHex(keccak256(new TextEncoder().encode(sig))).slice(2, 10);

  const evm = await createEVM();
  const caller = createAddressFromString("0x00000000000000000000000000000000000000ee");
  const to = createAddressFromString("0x00000000000000000000000000000000000000c0");
  await evm.stateManager.putCode(to, hexToBytes("0x" + code));
  await evm.stateManager.putAccount(caller, new Account(0n, 10n ** 18n));

  const word = (v) => BigInt(v).toString(16).padStart(64, "0");
  async function call(label, a, b, c, input) {
    const words = [...a, ...b[0], ...b[1], ...c, ...input].map(word).join("");
    const res = await evm.runCall({ caller, to, gasLimit: 5_000_000n, data: hexToBytes("0x" + sel + words) });
    const ex = res.execResult;
    const verdict = ex.exceptionError ? `REVERT ${ex.exceptionError.error}` : (BigInt(bytesToHex(ex.returnValue)) === 1n ? "true" : "false");
    console.log(`${label}: ${verdict} (gas ${ex.executionGasUsed})`);
  }
  await call("as given", a, b, c, input);
  await call("a.x + 1", [(BigInt(a[0]) + 1n).toString(), a[1]], b, c, input);
  await call("input[0] + 1", a, b, c, [(BigInt(input[0]) + 1n).toString(), ...input.slice(1)]);
  await call("input[0] + r", a, b, c, [(BigInt(input[0]) + R).toString(), ...input.slice(1)]);
}
main().catch((e) => { console.error(e); process.exit(1); });
