#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Regenerates modules/bitcointx/src/bip143_kat_vectors.zig and
bip341_kat_vectors.zig from the two BIPs' own published sources:

  * https://raw.githubusercontent.com/bitcoin/bips/master/bip-0143.mediawiki
    ("Example" section -- 4 worked examples, 12 signing cases total once
    every nHashType/OP_CODESEPARATOR/ANYONECANPAY sub-case is counted).
  * https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341/wallet-test-vectors.json
    (`keyPathSpending`'s 7 `inputSpending` cases -- every {DEFAULT, ALL,
    NONE, SINGLE} x {plain, ANYONECANPAY} combination that fits in BIP341's
    4-bit hashType space).

Fetches both fresh, then INDEPENDENTLY RECOMPUTES BIP143 and BIP341 from
their spec text (this script never imports or reads this module's Zig
source) and asserts the result matches what those two documents publish,
byte-exact, before emitting anything. A mismatch is a hard failure, not a
warning -- the whole point is that a wrong transcription (in either this
script or the Zig files it emits) cannot silently pass.

    python3 modules/bitcointx/tools/gen_vectors.py
    python3 modules/bitcointx/tools/gen_vectors.py --check   # exit 1 on diff, write nothing

Network access required (both URLs are small, public, unauthenticated GET
requests -- nothing is sent besides the request itself). Offline: pass
--bip143-file/--bip341-file pointing at local copies of the same two
documents.
"""

import argparse
import hashlib
import os
import re
import sys
import urllib.request

BIP143_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0143.mediawiki"
BIP341_VECTORS_URL = "https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341/wallet-test-vectors.json"

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(THIS_DIR, "..", "src")

# ── shared primitives ────────────────────────────────────────────────────


def dsha256(b):
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()


def sha256(b):
    return hashlib.sha256(b).digest()


def tagged_hash(tag, msg):
    th = sha256(tag.encode())
    return sha256(th + th + msg)


def compact_size(n):
    if n < 0xFD:
        return n.to_bytes(1, "little")
    elif n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    elif n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def read_compact_size(b, o):
    first = b[o]
    if first < 0xFD:
        return first, o + 1
    if first == 0xFD:
        return int.from_bytes(b[o + 1 : o + 3], "little"), o + 3
    if first == 0xFE:
        return int.from_bytes(b[o + 1 : o + 5], "little"), o + 5
    return int.from_bytes(b[o + 1 : o + 9], "little"), o + 9


def parse_tx(raw: bytes):
    """Legacy-form (no witness marker/flag -- every unsigned tx these BIPs
    publish is legacy-form) CompactSize transaction parse."""
    o = 0
    version = raw[0:4]
    o = 4
    vin_count, o = read_compact_size(raw, o)
    vins = []
    for _ in range(vin_count):
        txid = raw[o : o + 32]
        o += 32
        vout = raw[o : o + 4]
        o += 4
        slen, o = read_compact_size(raw, o)
        scriptsig = raw[o : o + slen]
        o += slen
        seq = raw[o : o + 4]
        o += 4
        vins.append((txid, vout, scriptsig, seq))
    vout_count, o = read_compact_size(raw, o)
    vouts = []
    for _ in range(vout_count):
        val = raw[o : o + 8]
        o += 8
        slen, o = read_compact_size(raw, o)
        spk = raw[o : o + slen]
        o += slen
        vouts.append((val, spk))
    locktime = raw[o : o + 4]
    o += 4
    assert o == len(raw), f"trailing bytes after transaction: {o} != {len(raw)}"
    return version, vins, vouts, locktime


def fetch(url):
    with urllib.request.urlopen(url, timeout=20) as r:
        return r.read()


def source(url, path_override):
    if path_override:
        with open(path_override, "rb") as f:
            return f.read()
    return fetch(url)


# ── BIP143 (bip-0143.mediawiki "Example" section) ───────────────────────


def bip143_preimage(version, vins, vouts, locktime, input_index, script_code, amount_sats, hash_type):
    """BIP143's "Specification" section, verbatim."""
    base = hash_type & 0x1F  # Core's `(nHashType & 0x1f)` classification
    acp = bool(hash_type & 0x80)

    if acp:
        hash_prevouts = b"\x00" * 32
    else:
        hash_prevouts = dsha256(b"".join(txid + vout for txid, vout, _, _ in vins))

    if acp or base in (2, 3):  # SIGHASH_NONE=2, SIGHASH_SINGLE=3
        hash_sequence = b"\x00" * 32
    else:
        hash_sequence = dsha256(b"".join(seq for _, _, _, seq in vins))

    if base not in (2, 3):  # "ALL-like": anything but NONE/SINGLE
        hash_outputs = dsha256(b"".join(val + compact_size(len(spk)) + spk for val, spk in vouts))
    elif base == 3:  # SINGLE
        if input_index >= len(vouts):
            hash_outputs = b"\x00" * 32  # the SIGHASH_SINGLE bug's domain
        else:
            val, spk = vouts[input_index]
            hash_outputs = dsha256(val + compact_size(len(spk)) + spk)
    else:  # NONE
        hash_outputs = b"\x00" * 32

    txid, vout, _, seq = vins[input_index]
    outpoint = txid + vout
    sc = compact_size(len(script_code)) + script_code
    amt = amount_sats.to_bytes(8, "little", signed=True)
    nhashtype = hash_type.to_bytes(4, "little")
    return version + hash_prevouts + hash_sequence + outpoint + sc + amt + seq + hash_outputs + locktime + nhashtype


BIP143_NAMES = [
    "native_p2wpkh",
    "p2sh_p2wpkh",
    "native_p2wsh_single_codesep_pending",
    "native_p2wsh_single_codesep_executed",
    "native_p2wsh_single_acp_input0",
    "native_p2wsh_single_acp_input1",
    "p2sh_p2wsh_all",
    "p2sh_p2wsh_none",
    "p2sh_p2wsh_single",
    "p2sh_p2wsh_all_acp",
    "p2sh_p2wsh_none_acp",
    "p2sh_p2wsh_single_acp",
]


def gen_bip143(path_override):
    text = source(BIP143_URL, path_override).decode("utf-8")

    # Only the "Example" section defines the canonical worked vectors;
    # "No FindAndDelete" (and anything after it) demonstrates an unrelated
    # malleability point with its own preimage/sigHash pairs, not part of
    # this module's vendored corpus.
    example_start = text.index("== Example ==")
    example_end = text.index("=== No FindAndDelete ===")
    example_text = text[example_start:example_end]

    section_re = re.compile(r"=== (.+?) ===")
    section_starts = [(m.start(), m.group(1)) for m in section_re.finditer(example_text)]

    def section_name_at(pos):
        name = section_starts[0][1]
        for s, n in section_starts:
            if s > pos:
                break
            name = n
        return name

    # One transaction "context" per "unsigned transaction:" occurrence --
    # NOT one per `=== ... ===` section: "Native P2WSH" carries TWO
    # unrelated worked examples (its own unsigned tx each) under one
    # section heading. Every preimage/sigHash pair belongs to the nearest
    # PRECEDING "unsigned transaction:" occurrence, section boundaries
    # aside.
    unsigned_tx_re = re.compile(r"unsigned transaction:\s*\n?\s*([0-9a-f]+)")
    preimage_re = re.compile(r"preimage[^:\n]*:\s*\n?\s*([0-9a-f]+)")
    sighash_re = re.compile(r"sigHash:\s*([0-9a-f]+)")

    tx_contexts = [(m.start(), m.group(1)) for m in unsigned_tx_re.finditer(example_text)]
    tx_contexts.append((len(example_text), None))

    cases = []
    for i in range(len(tx_contexts) - 1):
        start, raw_tx_hex = tx_contexts[i]
        end = tx_contexts[i + 1][0]
        chunk = example_text[start:end]
        section_name = section_name_at(start)
        raw_tx = bytes.fromhex(raw_tx_hex)
        version, vins, vouts, locktime = parse_tx(raw_tx)

        pos = 0
        while True:
            pm = preimage_re.search(chunk, pos)
            if not pm:
                break
            published_preimage_hex = pm.group(1)
            sm = sighash_re.search(chunk, pm.end())
            assert sm, f"{section_name}: preimage with no following sigHash at offset {pm.start()}"
            published_sighash_hex = sm.group(1)
            pos = sm.end()

            preimage = bytes.fromhex(published_preimage_hex)
            # Decompose the PUBLISHED preimage (fixed BIP143 layout) to
            # recover this case's own signing parameters.
            assert preimage[0:4] == version, f"{section_name}: preimage nVersion != tx nVersion"
            outpoint = preimage[68:104]
            txid, vout = outpoint[0:32], outpoint[32:36]
            matches = [i2 for i2, v in enumerate(vins) if v[0] == txid and v[1] == vout]
            assert len(matches) == 1, f"{section_name}: outpoint {outpoint.hex()} not uniquely in this tx's vins"
            input_index = matches[0]
            sc_len, sc_off = read_compact_size(preimage, 104)
            script_code = preimage[sc_off : sc_off + sc_len]
            after_sc = sc_off + sc_len
            amount_sats = int.from_bytes(preimage[after_sc : after_sc + 8], "little", signed=True)
            assert preimage[after_sc + 8 : after_sc + 12] == vins[input_index][3]
            assert preimage[len(preimage) - 8 : len(preimage) - 4] == locktime
            hash_type = int.from_bytes(preimage[len(preimage) - 4 :], "little")

            # The actual cross-check: recompute hashPrevouts/hashSequence/
            # hashOutputs (and hence the whole preimage) from the FULL
            # parsed unsigned tx -- not by re-emitting what was just
            # decomposed -- and require a byte-exact match against what
            # this BIP publishes for this case.
            recomputed_preimage = bip143_preimage(
                version, vins, vouts, locktime, input_index, script_code, amount_sats, hash_type
            )
            assert recomputed_preimage.hex() == published_preimage_hex, (
                f"{section_name}: recomputed preimage does not match published preimage\n"
                f"  published:  {published_preimage_hex}\n  recomputed: {recomputed_preimage.hex()}"
            )
            recomputed_sighash = dsha256(recomputed_preimage)
            assert recomputed_sighash.hex() == published_sighash_hex, (
                f"{section_name}: recomputed sigHash {recomputed_sighash.hex()} != "
                f"published {published_sighash_hex}"
            )

            cases.append(
                {
                    "unsigned_raw_tx_hex": raw_tx_hex,
                    "input_index": input_index,
                    "script_code_hex": script_code.hex(),
                    "amount_sats": amount_sats,
                    "hash_type": hash_type,
                    "sighash_hex": published_sighash_hex,
                }
            )

    assert len(cases) == len(BIP143_NAMES), f"expected {len(BIP143_NAMES)} cases, got {len(cases)}"
    for name, case in zip(BIP143_NAMES, cases):
        case["name"] = name
    return cases


BIP143_HEADER = '''// SPDX-License-Identifier: MIT
// Generated by modules/bitcointx/tools/gen_vectors.py from official public
// sources -- see doc comment below and in that script.
// Do not hand-edit hex payloads; regenerate instead.

//! BIP143's own published worked examples (bip-0143.mediawiki, "Example"
//! section), machine-transcribed from
//! https://raw.githubusercontent.com/bitcoin/bips/master/bip-0143.mediawiki.
//! Every field below (the intermediate hashPrevouts/hashSequence/
//! hashOutputs, the full preimage, and the final sighash) is independently
//! recomputed in Python (`gen_vectors.py`) directly from `unsigned_raw_tx_hex`
//! and asserted to match before this file is emitted -- a second,
//! independent cross-check of the transcription, separate from this
//! module's own Zig implementation under test.
//!
//! ALL FOUR of the BIP's worked examples are vendored, not two. The first
//! two ("Native P2WPKH", "P2SH-P2WPKH") are `hash_type = 0x01` only; the
//! `hash_type`-dependent branches of the algorithm -- the `hashSequence`
//! and `hashOutputs` zero-substitutions for `SIGHASH_NONE`/`SIGHASH_SINGLE`
//! and for `ANYONECANPAY` -- are covered by the other two:
//!
//!   * "Native P2WSH" -- `SIGHASH_SINGLE` (0x03) with `input_index = 1` and
//!     only one output, i.e. the *out-of-range SINGLE* case where BOTH
//!     `hashSequence` and `hashOutputs` are the all-zero substitution; plus
//!     `SINGLE|ANYONECANPAY` (0x83) on both inputs of a second transaction.
//!   * "P2SH-P2WSH" -- one transaction signed with all SIX hash types
//!     (ALL, NONE, SINGLE, and each with `ANYONECANPAY`), each with its own
//!     published hashPrevouts/hashSequence/hashOutputs, preimage and
//!     sigHash. This is the external oracle for the `hashSequence` gate:
//!     the NONE and SINGLE rows publish `hashSequence` = 32 zero bytes
//!     while the ALL row publishes the real
//!     `3bb13029ce7b1f559ef5e747fcac439f1455a2ec7c5f09b72290795e70665044`
//!     over the SAME transaction, so computing `hashSequence` for
//!     NONE/SINGLE (Bitcoin Core's *wrong* answer) cannot pass.
//!
//! Regenerate with (network access, or `--bip143-file`/`--bip341-file` for
//! an offline copy of the same two documents):
//!   python3 modules/bitcointx/tools/gen_vectors.py

pub const Example = struct {
    name: []const u8,
    /// The unsigned tx (empty scriptSigs) -- decodes as a plain legacy-form
    /// transaction (no witness marker/flag).
    unsigned_raw_tx_hex: []const u8,
    input_index: usize,
    script_code_hex: []const u8,
    amount_sats: i64,
    hash_type: u32,
    hash_prevouts_hex: []const u8,
    hash_sequence_hex: []const u8,
    hash_outputs_hex: []const u8,
    preimage_hex: []const u8,
    sighash_hex: []const u8,
};

pub const examples = [_]Example{
'''


def emit_bip143(cases):
    lines = [BIP143_HEADER]
    for c in cases:
        version, vins, vouts, locktime = parse_tx(bytes.fromhex(c["unsigned_raw_tx_hex"]))
        script_code = bytes.fromhex(c["script_code_hex"])
        preimage = bip143_preimage(
            version, vins, vouts, locktime, c["input_index"], script_code, c["amount_sats"], c["hash_type"]
        )
        # Same fixed-layout decomposition as the verifier, so the emitted
        # hash_prevouts_hex/hash_sequence_hex/hash_outputs_hex fields are
        # read out of the very preimage that was just independently
        # verified above, not recomputed a second, possibly-divergent way.
        hash_prevouts = preimage[4:36]
        hash_sequence = preimage[36:68]
        after_sc = 104 + 1 + len(script_code)  # all script_code lengths here are < 0xfd (1-byte prefix)
        hash_outputs = preimage[after_sc + 12 : after_sc + 44]
        lines.append("    .{\n")
        lines.append(f'        .name = "{c["name"]}",\n')
        lines.append(f'        .unsigned_raw_tx_hex = "{c["unsigned_raw_tx_hex"]}",\n')
        lines.append(f'        .input_index = {c["input_index"]},\n')
        lines.append(f'        .script_code_hex = "{c["script_code_hex"]}",\n')
        lines.append(f'        .amount_sats = {c["amount_sats"]},\n')
        lines.append(f'        .hash_type = 0x{c["hash_type"]:08x},\n')
        lines.append(f'        .hash_prevouts_hex = "{hash_prevouts.hex()}",\n')
        lines.append(f'        .hash_sequence_hex = "{hash_sequence.hex()}",\n')
        lines.append(f'        .hash_outputs_hex = "{hash_outputs.hex()}",\n')
        lines.append(f'        .preimage_hex = "{preimage.hex()}",\n')
        lines.append(f'        .sighash_hex = "{c["sighash_hex"]}",\n')
        lines.append("    },\n")
    lines.append("};\n")
    return "".join(lines)


# ── BIP341 (bip-0341/wallet-test-vectors.json keyPathSpending) ──────────


def bip341_sig_msg(version, vins, vouts, locktime, utxos, input_index, hash_type, ext_flag=0, annex=None):
    """BIP341 "Common Signature Message" (`SigMsg`), verbatim -- key-path
    spending only (`ext_flag = 0`), no annex (this vector set has none)."""
    acp = bool(hash_type & 0x80)
    out = bytes([0x00, hash_type]) + version + locktime  # epoch, hash_type, nVersion, nLockTime
    if not acp:
        sha_prevouts = sha256(b"".join(txid + vout for txid, vout, _, _ in vins))
        sha_amounts = sha256(b"".join(amt for amt, _ in utxos))
        sha_spks = sha256(b"".join(compact_size(len(spk)) + spk for _, spk in utxos))
        sha_sequences = sha256(b"".join(seq for _, _, _, seq in vins))
        out += sha_prevouts + sha_amounts + sha_spks + sha_sequences
    if (hash_type & 3) in (0, 1):  # SIGHASH_DEFAULT, SIGHASH_ALL
        sha_outputs = sha256(b"".join(val + compact_size(len(spk)) + spk for val, spk in vouts))
        out += sha_outputs
    spend_type = (ext_flag << 1) | (1 if annex is not None else 0)
    out += bytes([spend_type])
    if acp:
        txid, vout, _, seq = vins[input_index]
        amt, spk = utxos[input_index]
        out += txid + vout + amt + compact_size(len(spk)) + spk + seq
    else:
        out += input_index.to_bytes(4, "little")
    if annex is not None:
        out += sha256(compact_size(len(annex)) + annex)
    if (hash_type & 3) == 3:  # SIGHASH_SINGLE
        val, spk = vouts[input_index]
        out += sha256(val + compact_size(len(spk)) + spk)
    return out


def gen_bip341(path_override):
    import json

    d = json.loads(source(BIP341_VECTORS_URL, path_override))
    kp = d["keyPathSpending"][0]
    raw_tx_hex = kp["given"]["rawUnsignedTx"]
    version, vins, vouts, locktime = parse_tx(bytes.fromhex(raw_tx_hex))
    utxos_json = kp["given"]["utxosSpent"]
    utxos = [
        (u["amountSats"].to_bytes(8, "little", signed=True), bytes.fromhex(u["scriptPubKey"])) for u in utxos_json
    ]

    cases = []
    for ins in kp["inputSpending"]:
        input_index = ins["given"]["txinIndex"]
        hash_type = ins["given"]["hashType"]
        published_sig_msg_hex = ins["intermediary"]["sigMsg"]
        published_sighash_hex = ins["intermediary"]["sigHash"]

        sig_msg = bip341_sig_msg(version, vins, vouts, locktime, utxos, input_index, hash_type)
        assert sig_msg.hex() == published_sig_msg_hex, (
            f"input {input_index}: recomputed sigMsg does not match published sigMsg\n"
            f"  published:  {published_sig_msg_hex}\n  recomputed: {sig_msg.hex()}"
        )
        sighash = tagged_hash("TapSighash", sig_msg)
        assert sighash.hex() == published_sighash_hex, (
            f"input {input_index}: recomputed sigHash {sighash.hex()} != published {published_sighash_hex}"
        )

        cases.append(
            {
                "input_index": input_index,
                "hash_type": hash_type,
                "sig_msg_hex": sig_msg.hex(),
                "sighash_hex": sighash.hex(),
            }
        )
    return raw_tx_hex, utxos_json, cases


BIP341_HEADER = '''// SPDX-License-Identifier: MIT
// Generated by modules/bitcointx/tools/gen_vectors.py from official public
// sources -- see doc comment below and in that script.
// Do not hand-edit hex payloads; regenerate instead.

//! BIP341 key-path-spending SigMsg/sighash test vectors, machine-extracted
//! from the official
//! https://raw.githubusercontent.com/bitcoin/bips/master/bip-0341/wallet-test-vectors.json
//! `keyPathSpending` section (single shared transaction, 9 prevouts, 7
//! `inputSpending` sub-cases -- one per {SIGHASH_DEFAULT, ALL, NONE, SINGLE}
//! x {plain, ANYONECANPAY} combination that fits in 4-bit hashType space,
//! i.e. every value BIP341 accepts). Only the fields this module's sighash
//! function needs are kept (`internalPrivkey`/`tweak`/`merkleRoot`/`witness`
//! drive signing, not sighash computation, and are dropped).
//!
//! Both `sigMsg` and `sigHash` are independently recomputed in Python
//! (`gen_vectors.py`, BIP341's own `SigMsg`/`TapSighash` construction, not
//! this module's Zig implementation) and asserted to match the vector file
//! byte-exact before this file is emitted.
//!
//! Regenerate with: python3 modules/bitcointx/tools/gen_vectors.py

'''


def emit_bip341(raw_tx_hex, utxos_json, cases):
    lines = [BIP341_HEADER]
    lines.append(f'pub const raw_unsigned_tx_hex = "{raw_tx_hex}";\n\n')
    lines.append("pub const Utxo = struct {\n")
    lines.append("    script_pubkey_hex: []const u8,\n")
    lines.append("    amount_sats: i64,\n")
    lines.append("};\n\n")
    lines.append("pub const utxos_spent = [_]Utxo{\n")
    for u in utxos_json:
        lines.append(
            f'    .{{ .script_pubkey_hex = "{u["scriptPubKey"]}", .amount_sats = {u["amountSats"]} }},\n'
        )
    lines.append("};\n\n")
    lines.append("pub const InputCase = struct {\n")
    lines.append("    input_index: usize,\n")
    lines.append("    hash_type: u8,\n")
    lines.append("    /// The vector JSON's own `sigMsg` field -- despite the name, this is\n")
    lines.append("    /// `0x00 (epoch) || SigMsg(...)`, confirmed by field-by-field decoding\n")
    lines.append("    /// against `given`/`raw_unsigned_tx_hex` during generation (see\n")
    lines.append("    /// `sighash_bip341.zig`'s doc comment). Compare directly against this\n")
    lines.append("    /// module's `sigMsg(...)` return value (which also includes the epoch).\n")
    lines.append("    expected_sig_msg_hex: []const u8,\n")
    lines.append("    /// Internal/wire byte order (unlike `legacy_kat_vectors.zig`'s sighash\n")
    lines.append("    /// column, this one needs NO reversal -- confirmed the same way).\n")
    lines.append("    expected_sighash_hex: []const u8,\n")
    lines.append("};\n\n")
    lines.append("pub const input_cases = [_]InputCase{\n")
    for c in cases:
        lines.append("    .{\n")
        lines.append(f'        .input_index = {c["input_index"]},\n')
        lines.append(f'        .hash_type = 0x{c["hash_type"]:02x},\n')
        lines.append(f'        .expected_sig_msg_hex = "{c["sig_msg_hex"]}",\n')
        lines.append(f'        .expected_sighash_hex = "{c["sighash_hex"]}",\n')
        lines.append("    },\n")
    lines.append("};\n")
    return "".join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--bip143-file", help="local bip-0143.mediawiki instead of fetching it")
    p.add_argument("--bip341-file", help="local bip-0341/wallet-test-vectors.json instead of fetching it")
    p.add_argument("--check", action="store_true", help="exit 1 on diff from the vendored files, write nothing")
    args = p.parse_args()

    bip143_cases = gen_bip143(args.bip143_file)
    bip143_out = emit_bip143(bip143_cases)
    raw_tx_hex, utxos_json, bip341_cases = gen_bip341(args.bip341_file)
    bip341_out = emit_bip341(raw_tx_hex, utxos_json, bip341_cases)

    targets = {
        os.path.join(SRC_DIR, "bip143_kat_vectors.zig"): bip143_out,
        os.path.join(SRC_DIR, "bip341_kat_vectors.zig"): bip341_out,
    }

    if args.check:
        dirty = False
        for path, content in targets.items():
            existing = open(path, encoding="utf-8").read() if os.path.exists(path) else None
            if existing != content:
                print(f"DIFF: {path}", file=sys.stderr)
                dirty = True
        if dirty:
            sys.exit(1)
        print(f"OK: {len(bip143_cases)} BIP143 + {len(bip341_cases)} BIP341 cases match the vendored files")
        return

    for path, content in targets.items():
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"wrote {path}")


if __name__ == "__main__":
    main()
