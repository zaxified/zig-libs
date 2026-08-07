#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Transcribe subsets of Bitcoin Core's JSON test corpora into Zig vector files.

The repo has no build-time network access and no external dependencies, so the
corpora are vendored as generated `*_vectors.zig` files. This script is the
generator: point it at a checkout (or a downloaded copy) of Bitcoin Core's
`src/test/data/` and it re-emits those files, so the vendored subset stays
auditable against upstream instead of being hand-typed.

    scripts/gen-bitcoin-core-vectors.py --data-dir <dir> --which witness

Every selection predicate below is MECHANICAL (a property of the row), never a
hand-picked list, so re-running it on a newer upstream reproduces the file.
"""

import argparse
import json
import os
import sys

# Bitcoin Core `SCRIPT_ERR_*` name -> this repo's Zig error name.
#
# `WITNESS_PUBKEYTYPE` maps onto `Pubkeytype`, not a name of its own: this
# module deliberately folds Core's two pubkey-encoding errors into one (see
# `sigcheck.zig`'s `Pubkeytype` doc comment, which names both conditions). The
# vendored corpus therefore cannot tell those two apart -- stated here rather
# than papered over.
ERR = {
    "OK": None,
    "BAD_OPCODE": "BadOpcode",
    "CLEANSTACK": "CleanStack",
    "DISABLED_OPCODE": "DisabledOpcode",
    "DISCOURAGE_UPGRADABLE_NOPS": "DiscourageUpgradableNops",
    "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM": "DiscourageUpgradableWitnessProgram",
    "EQUALVERIFY": "Equalverify",
    "EVAL_FALSE": "EvalFalse",
    "INVALID_ALTSTACK_OPERATION": "InvalidAltstackOperation",
    "INVALID_STACK_OPERATION": "InvalidStackOperation",
    "MINIMALDATA": "MinimalData",
    "MINIMALIF": "MinimalIf",
    "NEGATIVE_LOCKTIME": "NegativeLocktime",
    "OP_COUNT": "OpCount",
    "OP_RETURN": "OpReturn",
    "PUBKEYTYPE": "Pubkeytype",
    "PUBKEY_COUNT": "PubkeyCount",
    "PUSH_SIZE": "PushSize",
    "SCRIPT_SIZE": "ScriptSize",
    "SIG_COUNT": "SigCount",
    "SIG_DER": "SigDer",
    "SIG_PUSHONLY": "SigPushonly",
    "STACK_SIZE": "StackSize",
    "UNBALANCED_CONDITIONAL": "UnbalancedConditional",
    "UNKNOWN_ERROR": "UnknownError",
    "UNSATISFIED_LOCKTIME": "UnsatisfiedLocktime",
    "VERIFY": "Verify",
    "WITNESS_MALLEATED": "WitnessMalleated",
    "WITNESS_MALLEATED_P2SH": "WitnessMalleatedP2SH",
    "WITNESS_PROGRAM_MISMATCH": "WitnessProgramMismatch",
    "WITNESS_PROGRAM_WITNESS_EMPTY": "WitnessProgramWitnessEmpty",
    "WITNESS_PROGRAM_WRONG_LENGTH": "WitnessProgramWrongLength",
    "WITNESS_PUBKEYTYPE": "Pubkeytype",
    "WITNESS_UNEXPECTED": "WitnessUnexpected",
}

# Core `SCRIPT_VERIFY_*` flag name -> this repo's `ScriptFlags` field.
FLAG = {
    "P2SH": "p2sh",
    "STRICTENC": "strictenc",
    "DERSIG": "dersig",
    "LOW_S": "low_s",
    "SIGPUSHONLY": "sigpushonly",
    "MINIMALDATA": "minimaldata",
    "NULLDUMMY": "nulldummy",
    "DISCOURAGE_UPGRADABLE_NOPS": "discourage_upgradable_nops",
    "CLEANSTACK": "cleanstack",
    "CHECKLOCKTIMEVERIFY": "checklocktimeverify",
    "CHECKSEQUENCEVERIFY": "checksequenceverify",
    "WITNESS": "witness",
    "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM": "discourage_upgradable_witness_program",
    "MINIMALIF": "minimalif",
    "NULLFAIL": "nullfail",
    "WITNESS_PUBKEYTYPE": "witness_pubkeytype",
    "CONST_SCRIPTCODE": "const_scriptcode",
    "TAPROOT": "taproot",
    "DISCOURAGE_UPGRADABLE_TAPROOT_VERSION": "discourage_upgradable_taproot_version",
    "DISCOURAGE_OP_SUCCESS": "discourage_op_success",
    "DISCOURAGE_UPGRADABLE_PUBKEYTYPE": "discourage_upgradable_pubkeytype",
    "NONE": None,
}

COIN = 100_000_000


def zq(s):
    """A Zig string literal for `s`."""
    out = ['"']
    for ch in s:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\n":
            out.append("\\n")
        elif 0x20 <= ord(ch) < 0x7F:
            out.append(ch)
        else:
            out.append("\\x%02x" % ord(ch))
    out.append('"')
    return "".join(out)


def flags_literal(field):
    names = [f for f in field.split(",") if f]
    fields = []
    for n in names:
        if n not in FLAG:
            raise SystemExit("unknown Core flag %r" % n)
        z = FLAG[n]
        if z is not None:
            fields.append(z)
    if not fields:
        return ".{}"
    return ".{ " + ", ".join(".%s = true" % f for f in sorted(set(fields))) + " }"


def _zig_list(items):
    """Body of a `&.{...}` literal, spaced the way `zig fmt` wants it."""
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    return " " + ", ".join(items) + " "


def data_rows(doc):
    return [r for r in doc if len(r) > 1]


def gen_witness(data_dir, out):
    doc = json.load(open(os.path.join(data_dir, "script_tests.json")))
    rows = data_rows(doc)
    # Selection predicate: exactly the rows whose FIRST field is the witness
    # array `[<stack item hex>..., <amount in BTC>]`. That is the whole of the
    # subset `script_tests_vectors.zig` drops, and nothing else.
    wit = [r for r in rows if isinstance(r[0], list)]
    out.write(HEADER_WITNESS % (len(rows), len(wit)))
    out.write("pub const vectors = [_]Vector{\n")
    for r in wit:
        stack, amount = r[0][:-1], r[0][-1]
        script_sig, script_pubkey, flags, expected = r[1], r[2], r[3], r[4]
        comment = r[5] if len(r) > 5 else ""
        if expected not in ERR:
            raise SystemExit("unknown Core script error %r" % expected)
        sats = int(round(float(amount) * COIN))
        items = ", ".join(zq(x) for x in stack)
        out.write("    .{\n")
        # `zig fmt` collapses the spaces for a single-element literal.
        inner = items if len(stack) <= 1 else " " + items + " "
        out.write("        .witness = &.{%s},\n" % inner)
        out.write("        .amount = %d,\n" % sats)
        out.write("        .script_sig = %s,\n" % zq(script_sig))
        out.write("        .script_pubkey = %s,\n" % zq(script_pubkey))
        out.write("        .flags = %s,\n" % flags_literal(flags))
        zerr = ERR[expected]
        out.write("        .expect = %s,\n" % ("null" if zerr is None else zq(zerr)))
        out.write("        .core_expect = %s,\n" % zq(expected))
        out.write("        .comment = %s,\n" % zq(comment))
        out.write("    },\n")
    out.write("};\n")
    return len(wit)


HEADER_WITNESS = """// SPDX-License-Identifier: MIT
// Generated by scripts/gen-bitcoin-core-vectors.py --which witness.
// Do not hand-edit; regenerate instead.

//! The **witness-bearing** rows of Bitcoin Core's `script_tests.json`
//! (`bitcoin/bitcoin` `src/test/data/script_tests.json`, tag `v29.0`), which
//! the sibling `script_tests_vectors.zig` excludes wholesale.
//!
//! Measured against that upstream file, not against our importer: it holds
//! **1258 array entries, 51 of them comment-only, so %d data rows**, and
//! **%d of those data rows carry a witness field** (a leading
//! `[<stack item hex>..., <amount in BTC>]` array). Zero of them set the
//! `TAPROOT` flag -- Core keeps the BIP342 corpus in a different file
//! (`script_assets_test.json`), so "no taproot rows here" is a property of
//! upstream, not of any filter of ours.
//!
//! This is the external oracle for segwit v0 that the module previously had
//! none of: P2WPKH/P2WSH dispatch, `WITNESS_MALLEATED` (a non-empty scriptSig
//! for a bare witness program), `WITNESS_MALLEATED_P2SH`, witness-program
//! length and version rules, `MINIMALIF` inside witness v0, `CLEANSTACK`
//! after a witness execution, and the compressed-pubkey rule. Before it, every
//! one of those paths was anchored only by round trips this repo wrote itself.
//!
//! Selection predicate (mechanical, applied to every data row): `isinstance(
//! row[0], list)`. No mnemonic filter is needed -- the only mnemonics these
//! rows use are `NOP`, `HASH160`, `EQUAL` and `CHECKSIG`, all of which this
//! module implements.
//!
//! `core_expect` keeps Core's own `SCRIPT_ERR_*` name beside the mapped Zig
//! error, because the mapping is not injective: Core's `WITNESS_PUBKEYTYPE`
//! and `PUBKEYTYPE` both land on this module's single `Pubkeytype` (see
//! `sigcheck.zig`), so the corpus cannot distinguish those two and says so
//! rather than implying a precision it does not have.

const ScriptFlags = @import("flags.zig").ScriptFlags;

pub const Vector = struct {
    /// Witness stack, bottom first, as hex (Core's JSON form).
    witness: []const []const u8,
    /// The spent output's value in satoshis (Core's row carries it in BTC).
    amount: i64,
    script_sig: []const u8,
    script_pubkey: []const u8,
    flags: ScriptFlags,
    /// null = expected OK; else this module's error name.
    expect: ?[]const u8,
    /// Core's own `SCRIPT_ERR_*` suffix for the same row.
    core_expect: []const u8,
    comment: []const u8,
};

"""


HEADER_LOCKTIME = """// SPDX-License-Identifier: MIT
// Generated by scripts/gen-bitcoin-core-vectors.py --which locktime.
// Do not hand-edit; regenerate instead.

//! The **BIP65 / BIP112 boundary** rows of Bitcoin Core's `tx_valid.json` and
//! `tx_invalid.json` (`bitcoin/bitcoin`, tag `v29.0`) -- REAL transactions
//! with real `nLockTime` and `nSequence` values, which is the only way to
//! exercise `OP_CHECKLOCKTIMEVERIFY` / `OP_CHECKSEQUENCEVERIFY` at all:
//! `script_tests.json`'s synthetic spend is fixed at `nLockTime = 0` and
//! `nSequence = SEQUENCE_FINAL`, so no row of it can distinguish the
//! comparison's `<=` from `>=`, and the sibling `script_tests_vectors.zig`
//! could not have anchored the boundary no matter how many rows it imported.
//!
//! Measured against upstream, not against our importer:
//!   `tx_valid.json`   -- 247 array entries, 127 comment-only, 120 data rows;
//!                        10 name CHECKLOCKTIMEVERIFY and 28 name
//!                        CHECKSEQUENCEVERIFY in a prevout script.
//!   `tx_invalid.json` -- 201 array entries, 108 comment-only, 93 data rows;
//!                        16 and 14 respectively.
//! Those %d rows are exactly what is vendored below.
//!
//! The rows straddle every boundary BIP65 and BIP112 define: 499999999 vs
//! 500000000 (the block-height / unix-time threshold), 4194303 vs 4194304
//! (BIP112's type flag), 2147483647 + 1 (the CScriptNum sign edge), negative
//! and 6-byte operands, and the `nSequence == SEQUENCE_FINAL` disable rule.
//!
//! Selection predicate (mechanical, applied to every data row of both files):
//! the row is not a `BADTX` row (those test `CheckTransaction`, not scripts)
//! and at least one prevout scriptPubKey names `CHECKLOCKTIMEVERIFY` or
//! `CHECKSEQUENCEVERIFY`.
//!
//! Flag-field semantics differ between the two files and are preserved
//! as-written (see `Vector.json_flags` in `tx_findanddelete_vectors.zig`,
//! whose `Prevout`/`FlagName`/`Vector` types this file reuses):
//! `tx_valid.json`'s field is the set to EXCLUDE (Core runs `~verify_flags`),
//! `tx_invalid.json`'s is the set to APPLY.

const shared = @import("tx_findanddelete_vectors.zig");
pub const Prevout = shared.Prevout;
pub const FlagName = shared.FlagName;
pub const Vector = shared.Vector;

"""


def gen_locktime(data_dir, out):
    picked = []
    for name, valid in (("tx_valid", True), ("tx_invalid", False)):
        doc = json.load(open(os.path.join(data_dir, name + ".json")))
        for r in data_rows(doc):
            prevouts, tx_hex, flags = r[0], r[1], r[2]
            if "BADTX" in flags:
                continue
            if not any(
                "CHECKLOCKTIMEVERIFY" in p[2] or "CHECKSEQUENCEVERIFY" in p[2]
                for p in prevouts
            ):
                continue
            picked.append((valid, prevouts, tx_hex, flags, r[3] if len(r) > 3 else ""))
    out.write(HEADER_LOCKTIME % len(picked))
    out.write("pub const vectors = [_]Vector{\n")
    for valid, prevouts, tx_hex, flags, comment in picked:
        out.write("    .{\n")
        out.write("        .valid = %s,\n" % ("true" if valid else "false"))
        out.write("        .prevouts = &.{\n")
        for p in prevouts:
            amount = int(round(float(p[3]) * COIN)) if len(p) > 3 else 0
            out.write(
                "            .{ .txid_hex = %s, .vout = %d, .script_asm = %s, .amount = %d },\n"
                % (zq(p[0]), p[1], zq(p[2]), amount)
            )
        out.write("        },\n")
        out.write("        .tx_hex = %s,\n" % zq(tx_hex))
        names = [FLAG[f] for f in flags.split(",") if f and FLAG.get(f)]
        for f in flags.split(","):
            if f and f not in FLAG:
                raise SystemExit("unknown Core flag %r" % f)
        out.write(
            "        .json_flags = &.{%s},\n"
            % _zig_list(["." + n for n in sorted(set(names))])
        )
        out.write("        .comment = %s,\n" % zq(comment))
        out.write("    },\n")
    out.write("};\n")
    return len(picked)


HEADER_TXWIRE = """// SPDX-License-Identifier: MIT
// Generated by scripts/gen-bitcoin-core-vectors.py --which txwire.
// Do not hand-edit; regenerate instead.

//! EVERY transaction in Bitcoin Core's `tx_valid.json` + `tx_invalid.json`
//! (`bitcoin/bitcoin`, tag `v29.0`), as a wire-format corpus for this module's
//! serializer/deserializer.
//!
//! Measured against upstream, not against our importer:
//!   `tx_valid.json`   -- 247 array entries, 127 comment-only, 120 data rows.
//!   `tx_invalid.json` -- 201 array entries, 108 comment-only, 93 data rows.
//! %d transactions in total, %d of them carrying the BIP144 segwit marker,
//! %d of them spending more than one prevout, %d of them `BADTX` rows (those
//! test Core's `CheckTransaction`, not scripts -- but they are still real
//! serializations and belong in a *wire*-format corpus, so unlike the
//! script-level importers this one keeps them).
//!
//! Before this file the module's entire external wire anchor was TWO
//! transactions (`tx_kat_vectors.zig`). Nothing external exercised the
//! decoder's rejection behaviour or its varint/marker edges at scale.
//!
//! ## The oracle is `prevouts`, not just the round trip
//!
//! A round trip proves our serializer and our deserializer share a
//! convention, not that the convention is Bitcoin's. What makes this corpus
//! an EXTERNAL oracle is the second field: Core's rows carry a hand-written
//! `[txid, vout, scriptPubKey]` table naming the outpoints each transaction
//! spends, derived from the transaction's meaning rather than from its bytes.
//! Every outpoint our decoder reports must appear in that table. A decoder
//! that miscounts a varint, swaps txid byte order, or reads `vout` at the
//! wrong offset round-trips perfectly and still fails this.
//!
//! Selection predicate: every data row of both files. No filter.
//!
//! `txid_hex` is Core's RPC display order (byte-reversed relative to the wire
//! order `TxIn.prevout.txid` holds), exactly as the JSON prints it.

pub const Outpoint = struct {
    txid_hex: []const u8,
    vout: u32,
};

pub const Vector = struct {
    /// `true` = from `tx_valid.json`, `false` = from `tx_invalid.json`.
    from_valid_file: bool,
    /// Core's serialized transaction, hex.
    tx_hex: []const u8,
    /// The outpoints Core's row says this transaction spends.
    prevouts: []const Outpoint,
    /// Core's `BADTX` rows test `CheckTransaction`, not script validity.
    badtx: bool,
    comment: []const u8,
};

"""


def gen_txwire(data_dir, out):
    picked = []
    for name, valid in (("tx_valid", True), ("tx_invalid", False)):
        doc = json.load(open(os.path.join(data_dir, name + ".json")))
        for r in data_rows(doc):
            picked.append(
                (valid, r[1], r[0], "BADTX" in r[2], r[3] if len(r) > 3 else "")
            )
    seg = sum(1 for p in picked if p[1][8:12] == "0001")
    multi = sum(1 for p in picked if len(p[2]) > 1)
    bad = sum(1 for p in picked if p[3])
    out.write(HEADER_TXWIRE % (len(picked), seg, multi, bad))
    out.write("pub const vectors = [_]Vector{\n")
    for valid, tx_hex, prevouts, badtx, comment in picked:
        out.write("    .{\n")
        out.write("        .from_valid_file = %s,\n" % ("true" if valid else "false"))
        out.write("        .tx_hex = %s,\n" % zq(tx_hex))
        out.write("        .prevouts = &.{\n")
        for p in prevouts:
            # Core stores the coinbase's null outpoint index as JSON -1;
            # on the wire it is 0xffffffff.
            vout = p[1] & 0xFFFFFFFF
            out.write(
                "            .{ .txid_hex = %s, .vout = %d },\n" % (zq(p[0]), vout)
            )
        out.write("        },\n")
        out.write("        .badtx = %s,\n" % ("true" if badtx else "false"))
        out.write("        .comment = %s,\n" % zq(comment))
        out.write("    },\n")
    out.write("};\n")
    return len(picked)


HEADER_SIGHASH = """// SPDX-License-Identifier: MIT
// Generated by scripts/gen-bitcoin-core-vectors.py --which sighash.
// Do not hand-edit hex payloads; regenerate instead.

//! Legacy sighash test vectors from Bitcoin Core's reference-oracle fixture
//! `src/test/data/sighash.json` (`bitcoin/bitcoin`, tag `v29.0`), columns
//! `raw_transaction, script, input_index, hashType, signature_hash`.
//!
//! Measured against upstream, not against our importer: the file holds **501
//! array entries, 1 of them the header comment, so 500 data rows**, and
//! **exactly %d of those carry a raw `0xab` (`OP_CODESEPARATOR`) byte in the
//! `script` column**.
//!
//! **All %d rows are vendored. There is no filter.** This file previously held
//! 290 of them: the %d `0xab` rows were excluded because `sighash_legacy.zig`
//! wrote `script_code` verbatim instead of running Core's
//! `SerializeScriptCode`, which omits `OP_CODESEPARATOR` opcodes. That step is
//! implemented now, so the exclusion is gone. Note that the `0xab` byte count
//! is an over-approximation of the rows that actually need the step -- a
//! `0xab` inside a push payload is data, not an opcode -- which is exactly why
//! the filter had to go rather than be narrowed: only a real Script walk can
//! tell those apart, and once you have the walk you no longer need the filter.
//!
//! `expected_sighash_hex` is stored in this module's internal/wire byte order
//! -- the reverse of `sighash.json`'s own `signature_hash` column, which is
//! the conventional *display* order (like a txid string). `hashType` is stored
//! in the JSON as a signed 32-bit integer and is masked to `u32` here.

pub const Vector = struct {
    raw_tx_hex: []const u8,
    script_code_hex: []const u8,
    input_index: usize,
    hash_type: u32,
    /// Internal/wire byte order (see doc comment above).
    expected_sighash_hex: []const u8,
    comment: []const u8,
};

"""


def gen_sighash(data_dir, out):
    doc = json.load(open(os.path.join(data_dir, "sighash.json")))
    rows = data_rows(doc)
    def has_ab(script_hex):
        return any(
            script_hex[i : i + 2].lower() == "ab" for i in range(0, len(script_hex), 2)
        )

    n_ab = sum(1 for r in rows if has_ab(r[1]))
    out.write(HEADER_SIGHASH % (n_ab, len(rows), n_ab))
    out.write("pub const vectors = [_]Vector{\n")
    for n, r in enumerate(rows, start=1):
        raw_tx, script, idx, hash_type, sig_hash = r[0], r[1], r[2], r[3], r[4]
        wire = bytes.fromhex(sig_hash)[::-1].hex()
        base = hash_type & 0x1F
        base_name = {1: "ALL", 2: "NONE", 3: "SINGLE"}.get(
            base, "unrecognized-low5(ALL-like)"
        )
        comment = "sighash.json row %d: base=%s anyone_can_pay=%s%s" % (
            n,
            base_name,
            bool(hash_type & 0x80),
            " codeseparator" if has_ab(script) else "",
        )
        out.write("    .{\n")
        out.write("        .raw_tx_hex = %s,\n" % zq(raw_tx))
        out.write("        .script_code_hex = %s,\n" % zq(script))
        out.write("        .input_index = %d,\n" % idx)
        out.write("        .hash_type = 0x%08x,\n" % (hash_type & 0xFFFFFFFF))
        out.write("        .expected_sighash_hex = %s,\n" % zq(wire))
        out.write("        .comment = %s,\n" % zq(comment))
        out.write("    },\n")
    out.write("};\n")
    return len(rows)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", required=True, help="Bitcoin Core src/test/data")
    ap.add_argument("--which", required=True, choices=["witness", "locktime", "txwire", "sighash"])
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    with open(a.out, "w") as f:
        n = {"witness": gen_witness, "locktime": gen_locktime, "txwire": gen_txwire, "sighash": gen_sighash}[a.which](a.data_dir, f)
    print("wrote %d vectors to %s" % (n, a.out), file=sys.stderr)


if __name__ == "__main__":
    main()
