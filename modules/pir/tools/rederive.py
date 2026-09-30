#!/usr/bin/env python3
"""Independent re-derivation oracle for the `pir` module (two-server DPF PIR).

Recipe (CONVENTIONS.md section 9), run by hand, never by a test:

    python3 modules/pir/tools/rederive.py > modules/pir/src/kat_vectors.zig
    python3 modules/pir/tools/rederive.py --self-check     # fss KATs only

Python 3, standard library only (hashlib).  Nothing from the Zig sources is
executed or ported; the two layers below are written from the specs.

What came from where
--------------------
From the SPECs (modules/fss/SPEC.md, modules/pir/SPEC.md, READMEs):
  * BGI16 Fig. 1 optimised-tree DPF: per-level correction words, the t-bit
    invariant, the (-1)^b sign, output group Z_{2^{8L}} (little-endian).
  * The SHA-256 PRG instantiation `Sha256Prg` (SPEC "PRG choice", and the PRG
    definition table in fss/src/prg.zig's header, which the SPEC points at):
    G(s) = SHA256(s||0x00), SHA256(s||0x01) -> seed = first 16 bytes,
    control bit = byte 16 & 1; Convert(s) = LE(SHA256(s||0x02)[0..L]).
  * PIR: answer_b[j] = sum_{x<N} Eval(b,k_b,x) * word_j(record[x]) mod 2^{8L},
    beta = 1, record cut into L-byte little-endian words, reconstruction is
    the word-wise ring SUM of the two answers.
From the Zig source, byte layouts only (the SPECs leave them unpinned):
  * serialised key = seed(16) || per level [s_cw(16) t_cw_l(1) t_cw_r(1)] ||
    cw_final (L bytes LE) -- `Key.toBytes` / `serializeCw` layout; the
    control-bit CWs are one whole byte valued 0/1.
  * the final partial word of a record is zero-padded on the high side
    (`wordAt`); the answer has ceil(record_len/L) words; the serialised answer
    is those words little-endian, back to back; reconstruction drops the
    padding of the last word.
  * seeds are the caller-supplied inputs of `query(index, s0, s1)`
    (deterministic entry point; no other keygen is used).
Nothing else was read from the Zig code.  The vectors below are NOT taken from
any Zig output: the PRG, tree walk and inner product are separate code.
"""

import hashlib
import os
import re
import sys


def sha(b):
    return hashlib.sha256(b).digest()


# ---------------------------------------------------------------------------
# PRG (SHA-256 instantiation) -- from the PRG definition in the SPEC/prg.zig
# ---------------------------------------------------------------------------

def prg_children(seed):
    """Return ((seed_left, t_left), (seed_right, t_right))."""
    kids = []
    for tweak in (0, 1):
        d = sha(seed + bytes([tweak]))
        kids.append((d[:16], d[16] & 1))
    return kids[0], kids[1]


def prg_convert(seed, L):
    return int.from_bytes(sha(seed + b"\x02")[:L], "little")


def xor16(a, b):
    return bytes(p ^ q for p, q in zip(a, b))


# ---------------------------------------------------------------------------
# BGI16 optimised-tree DPF (Fig. 1)
# ---------------------------------------------------------------------------

def dpf_gen(n, L, alpha, beta, root0, root1):
    """Return (cws, cw_final); cws = list of (s_cw, t_cw_l, t_cw_r)."""
    mod = 1 << (8 * L)
    path = [(alpha >> (n - 1 - i)) & 1 for i in range(n)]   # MSB first
    party = [(root0, 0), (root1, 1)]                         # (seed, t)
    cws = []
    for a in path:
        kids = [prg_children(s) for (s, _t) in party]
        # kids[b] = ((sL,tL),(sR,tR)); index 0 = left, 1 = right
        keep, lose = a, 1 - a
        s_cw = xor16(kids[0][lose][0], kids[1][lose][0])
        t_cw = [
            kids[0][0][1] ^ kids[1][0][1] ^ a ^ 1,           # left
            kids[0][1][1] ^ kids[1][1][1] ^ a,               # right
        ]
        cws.append((s_cw, t_cw[0], t_cw[1]))
        nxt = []
        for b in (0, 1):
            s_keep, t_keep = kids[b][keep]
            t_prev = party[b][1]
            if t_prev:
                s_keep = xor16(s_keep, s_cw)
                t_keep ^= t_cw[keep]
            nxt.append((s_keep, t_keep))
        party = nxt
    c0 = prg_convert(party[0][0], L)
    c1 = prg_convert(party[1][0], L)
    final = (beta - c0 + c1) % mod
    if party[1][1]:
        final = (-final) % mod
    return cws, final


def dpf_eval(n, L, b, root, cws, final, x):
    mod = 1 << (8 * L)
    s, t = root, b
    for i in range(n):
        bit = (x >> (n - 1 - i)) & 1
        s_cw, tl, tr = cws[i]
        (sl, tl_), (sr, tr_) = prg_children(s)
        s, tn = (sr, tr_) if bit else (sl, tl_)
        if t:
            s = xor16(s, s_cw)
            tn ^= tr if bit else tl
        t = tn
    v = prg_convert(s, L)
    if t:
        v = (v + final) % mod
    return (-v) % mod if b else v


def key_bytes(n, L, root, cws, final):
    out = bytearray(root)
    for s_cw, tl, tr in cws:
        out += s_cw + bytes([tl, tr])
    out += final.to_bytes(L, "little")
    return bytes(out)


def cw_bytes(n, L, cws, final):
    return key_bytes(n, L, b"", cws, final)


# ---------------------------------------------------------------------------
# Step (a): reproduce every fss KAT byte-exact
# ---------------------------------------------------------------------------

def parse_fss_kats(path):
    text = open(path).read()
    vecs = []
    for m in re.finditer(r"pub const (v\d+) = Vector\{(.*?)\n\};", text, re.S):
        name, body = m.group(1), m.group(2)

        def num(field):
            return int(re.search(r"\.%s = (\d+)," % field, body).group(1))

        def arr(field):
            mm = re.search(r"\.%s = &?\[_\]u8\{(.*?)\}" % field, body, re.S)
            return bytes(int(t, 16) for t in re.findall(r"0x[0-9a-f]{2}", mm.group(1)))

        def u64s(field):
            mm = re.search(r"\.%s = &(?:\[_\]u64)?\{(.*?)\}," % field, body, re.S)
            return [int(t) for t in re.findall(r"\d+", mm.group(1))] if mm else []

        spot = []
        mm = re.search(r"\.spot = &\[_\]\[3\]u64\{(.*)\},?$", body, re.M)
        if mm:
            for t in re.findall(r"\.\{ (\d+), (\d+), (\d+) \}", mm.group(1)):
                spot.append(tuple(int(z) for z in t))
        if not (u64s("eval0") or spot):
            raise SystemExit("self-check: %s has no eval points to check" % name)
        vecs.append(dict(
            name=name, n=num("n"), L=num("out_bytes"), alpha=num("alpha"),
            beta=num("beta"), s0=arr("seed0"), s1=arr("seed1"), cw=arr("cw"),
            eval0=u64s("eval0"), eval1=u64s("eval1"), spot=spot))
    return vecs


def self_check(verbose):
    here = os.path.dirname(os.path.abspath(__file__))
    path = os.path.join(here, "..", "..", "fss", "src", "kat_vectors.zig")
    vecs = parse_fss_kats(path)
    if len(vecs) != 4:
        raise SystemExit("self-check: expected 4 fss vectors, parsed %d" % len(vecs))
    for v in vecs:
        n, L = v["n"], v["L"]
        cws, final = dpf_gen(n, L, v["alpha"], v["beta"], v["s0"], v["s1"])
        if cw_bytes(n, L, cws, final) != v["cw"]:
            raise SystemExit("self-check FAILED: %s cw mismatch" % v["name"])
        checked = 0
        if v["eval0"]:
            pts = [(x, v["eval0"][x], v["eval1"][x]) for x in range(1 << n)]
        else:
            pts = v["spot"]
        for x, e0, e1 in pts:
            g0 = dpf_eval(n, L, 0, v["s0"], cws, final, x)
            g1 = dpf_eval(n, L, 1, v["s1"], cws, final, x)
            if (g0, g1) != (e0, e1):
                raise SystemExit("self-check FAILED: %s eval x=%d" % (v["name"], x))
            checked += 1
        if verbose:
            print("fss KAT %s (n=%d L=%d): cw %d bytes + %d eval points match"
                  % (v["name"], n, L, len(v["cw"]), checked))
    if verbose:
        print("self-check OK: every fss KAT vector reproduced byte-exact (%d vectors)" % len(vecs))


# ---------------------------------------------------------------------------
# Step (b): the PIR layer on top
# ---------------------------------------------------------------------------

def stream(tag, nbytes):
    out = b""
    ctr = 0
    while len(out) < nbytes:
        out += sha(tag + ctr.to_bytes(4, "little"))
        ctr += 1
    return out[:nbytes]


def word(rec, j, L):
    chunk = rec[j * L:(j + 1) * L]
    return int.from_bytes(chunk.ljust(L, b"\x00"), "little")


def pir_case(name, n, L, count, record_len, index):
    assert count <= (1 << n) and index < (1 << n)
    mod = 1 << (8 * L)
    tag = ("pir-kat/%s" % name).encode()
    seeds = stream(tag + b"/seeds", 32)
    s0, s1 = seeds[:16], seeds[16:]
    db = stream(tag + b"/db", count * record_len)
    recs = [db[x * record_len:(x + 1) * record_len] for x in range(count)]

    cws, final = dpf_gen(n, L, index, 1, s0, s1)      # beta = 1 (selector)
    k0 = key_bytes(n, L, s0, cws, final)
    k1 = key_bytes(n, L, s1, cws, final)
    n_words = -(-record_len // L)
    ans = []
    for b, root in ((0, s0), (1, s1)):
        acc = [0] * n_words
        for x in range(count):                          # x < N only
            sel = dpf_eval(n, L, b, root, cws, final, x)
            for j in range(n_words):
                acc[j] = (acc[j] + sel * word(recs[x], j, L)) % mod
        ans.append(b"".join(w.to_bytes(L, "little") for w in acc))
    # client: word-wise ring sum, then drop padding of the last word
    rec_out = bytearray()
    for j in range(n_words):
        w = (int.from_bytes(ans[0][j * L:(j + 1) * L], "little")
             + int.from_bytes(ans[1][j * L:(j + 1) * L], "little")) % mod
        rec_out += w.to_bytes(L, "little")
    rec_out = bytes(rec_out[:record_len])
    want = recs[index] if index < count else bytes(record_len)
    if rec_out != want:
        raise SystemExit("case %s: re-derived PIR does not reconstruct" % name)
    return dict(name=name, n=n, L=L, count=count, record_len=record_len,
                index=index, s0=s0, s1=s1, db=db, k0=k0, k1=k1,
                a0=ans[0], a1=ans[1], record=rec_out)


# (name, domain_bits, word_bytes, record count, record_len, index)
CASES = [
    ("min",        1,  1,   2,  1,  0),   # smallest domain, 1-byte words, index 0
    ("min_last",   1,  1,   2,  1,  1),   # ... and the last index
    ("single",     1,  4,   1,  3,  0),   # one record in a 2-point domain
    ("mid_word",   3,  4,   5, 13,  3),   # README shape family, ragged last word
    ("first",      4,  8,  11, 20,  0),   # index 0, record spans 3 words
    ("last",       4,  8,  11, 20, 10),   # last populated index
    ("full_domain", 5, 16, 32,  7, 31),   # count == 2^n, last index of domain
    ("wide_word",  6, 32,  20, 33, 19),   # 32-byte words (max), 2 words, ragged
    ("trunc_tail", 8,  4,  37,  9, 36),   # domain far larger than the database
    ("odd_word",   7,  3,  50, 10, 25),   # non-power-of-two word size
    ("unpopulated", 4, 4,   9,  6, 12),   # in-domain, past count: all zero
    ("deep",      10,  2, 100,  5, 99),   # 10-level tree, 2-byte words
]


def zig_bytes(b):
    if not b:
        return "&[_]u8{}"
    body = ", ".join("0x%02x" % c for c in b)
    # zig fmt writes a one-element list without the inner spaces
    return "&[_]u8{%s}" % body if len(b) == 1 else "&[_]u8{ %s }" % body


def emit():
    cases = [pir_case(*c) for c in CASES]
    o = []
    w = o.append
    w("// SPDX-License-Identifier: MIT")
    w("")
    w("//! kat_vectors -- GENERATED, do not edit.  Recipe:")
    w("//!")
    w("//!     python3 modules/pir/tools/rederive.py > modules/pir/src/kat_vectors.zig")
    w("//!")
    w("//! Each vector is the output of an INDEPENDENT Python re-derivation (stdlib")
    w("//! `hashlib` only) of the two-server DPF PIR: BGI16 Gen/Eval over the SHA-256")
    w("//! PRG, then the server inner product over Z_{2^{8L}} and the client's word-wise")
    w("//! sum.  The script first reproduces every `fss` KAT byte-exact, so the DPF")
    w("//! underneath is the anchored one.  `kat_test.zig` asserts `PirWith(Sha256Prg,")
    w("//! ...)` produces the shares and answers below byte-exact.  See SPEC.md")
    w("//! section \"Anchoring\" for what this does and does not establish.")
    w("")
    w("pub const Vector = struct {")
    w("    name: []const u8,")
    w("    domain_bits: usize,")
    w("    word_bytes: usize,")
    w("    count: usize,")
    w("    record_len: usize,")
    w("    index: usize,")
    w("    /// the caller-supplied root seeds handed to `query`")
    w("    seed0: [16]u8,")
    w("    seed1: [16]u8,")
    w("    /// the database, `count` records of `record_len` bytes, back to back")
    w("    db: []const u8,")
    w("    /// serialised query shares (`shareToBytes`): seed || CWs || cw_final")
    w("    share0: []const u8,")
    w("    share1: []const u8,")
    w("    /// serialised answers (`answerToBytes`): little-endian words")
    w("    answer0: []const u8,")
    w("    answer1: []const u8,")
    w("    /// the reconstructed record (zeros for an index at or past `count`)")
    w("    record: []const u8,")
    w("};")
    for c in cases:
        w("")
        w("/// domain_bits=%d, word_bytes=%d, count=%d, record_len=%d, index=%d"
          % (c["n"], c["L"], c["count"], c["record_len"], c["index"]))
        w("pub const %s = Vector{" % c["name"])
        w("    .name = \"%s\"," % c["name"])
        w("    .domain_bits = %d," % c["n"])
        w("    .word_bytes = %d," % c["L"])
        w("    .count = %d," % c["count"])
        w("    .record_len = %d," % c["record_len"])
        w("    .index = %d," % c["index"])
        w("    .seed0 = [_]u8{ %s }," % ", ".join("0x%02x" % x for x in c["s0"]))
        w("    .seed1 = [_]u8{ %s }," % ", ".join("0x%02x" % x for x in c["s1"]))
        for f, k in (("db", "db"), ("share0", "k0"), ("share1", "k1"),
                     ("answer0", "a0"), ("answer1", "a1"), ("record", "record")):
            w("    .%s = %s," % (f, zig_bytes(c[k])))
        w("};")
    w("")
    w("/// all recorded vectors, as a comptime tuple (each element carries its own")
    w("/// comptime geometry, so the harness `inline for`s and instantiates")
    w("/// `PirWith(Sha256Prg, v.domain_bits, v.word_bytes)` per vector).")
    w("pub const all = .{ " + ", ".join(c["name"] for c in cases) + " };")
    return "\n".join(o) + "\n"


def main():
    if "--self-check" in sys.argv[1:]:
        self_check(True)
        return
    self_check(False)          # never emit vectors from an unverified DPF
    sys.stdout.write(emit())


if __name__ == "__main__":
    main()
