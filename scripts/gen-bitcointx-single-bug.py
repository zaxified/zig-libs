# SPDX-License-Identifier: MIT
# Regenerates modules/bitcointx/src/single_bug_kat_vectors.zig.
#
#   python3 -m venv ~/.cache/zig-libs-bitcointx
#   ~/.cache/zig-libs-bitcointx/bin/pip install python-bitcoinlib
#   ~/.cache/zig-libs-bitcointx/bin/python scripts/gen-bitcointx-single-bug.py
#
# Emits only the array body; the file's header is written by hand. The output
# is frozen into the repo, so the test gate stays offline and dependency-free.
from bitcoin.core import CTransaction, CMutableTransaction, CMutableTxIn, CMutableTxOut, COutPoint, lx, b2x
from bitcoin.core.script import CScript, RawSignatureHash, SIGHASH_ALL, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_ANYONECANPAY

def mk(n_in, n_out):
    vin = [CMutableTxIn(COutPoint(lx('aa'*32 if i == 0 else 'bb'*32), i), CScript(b''), 0xffffffff)
           for i in range(n_in)]
    vout = [CMutableTxOut(1000 * (i + 1), CScript(bytes([0x51 + i]))) for i in range(n_out)]
    return CMutableTransaction(vin, vout, nLockTime=0, nVersion=1)

script = CScript(bytes.fromhex('76a914' + '11'*20 + '88ac'))  # P2PKH scriptCode

cases = [
    ("2-in 1-out, SINGLE at index 1: no corresponding output -> the bug", 2, 1, 1, SIGHASH_SINGLE),
    ("2-in 1-out, SINGLE at index 0: the output exists, normal path", 2, 1, 0, SIGHASH_SINGLE),
    ("2-in 2-out, SINGLE at index 1: last output, still normal", 2, 2, 1, SIGHASH_SINGLE),
    ("3-in 1-out, SINGLE at index 2: two indices past the end", 3, 1, 2, SIGHASH_SINGLE),
    ("2-in 1-out, SINGLE|ANYONECANPAY at index 1: the bug wins over ACP", 2, 1, 1, SIGHASH_SINGLE | SIGHASH_ANYONECANPAY),
    ("2-in 1-out, NONE at index 1: no bug, NONE has no corresponding output by design", 2, 1, 1, SIGHASH_NONE),
    ("2-in 1-out, ALL at index 1: no bug", 2, 1, 1, SIGHASH_ALL),
]
for desc, ni, no, idx, ht in cases:
    tx = mk(ni, no)
    h, err = RawSignatureHash(script, CTransaction.from_tx(tx), idx, ht)
    print("    .{")
    print('        .raw_tx_hex = "%s",' % b2x(CTransaction.from_tx(tx).serialize()))
    print('        .script_code_hex = "%s",' % b2x(bytes(script)))
    print('        .input_index = %d,' % idx)
    print('        .hash_type = 0x%02x,' % ht)
    print('        .expected_sighash_hex = "%s",' % b2x(h))
    print('        .comment = "%s",' % desc)
    print("    },")
