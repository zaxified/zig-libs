#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""hqc mutation runner — one --cache-dir per variant, patch application verified.

WHY THIS EXISTS. A green suite proves the code passes its tests. It says nothing
about whether those tests COULD fail. This breaks the module on purpose, one
exact edit at a time, and records whether the suite noticed — which is the only
evidence that a passing run means anything.

WHAT IT NEEDS. A `zig` on PATH and nothing else; it is here rather than in
`src/` because it drives the compiler as a subprocess and writes working trees,
which a module's own test must never do.

    python3 mutate.py                    # every variant
    python3 mutate.py M7-compare-ignores-lsb   # one

Each variant: copy ../src -> <work>/<id>/src, apply an exact string replacement
(count asserted, else the variant is reported BROKEN, never PASS), then
`zig test root.zig -O ReleaseFast --cache-dir <work>/<id>/cache`.

⚠ ONE CACHE DIR PER VARIANT IS LOAD-BEARING. A shared cache handed back a stale
binary and produced 18 false PASSes in an earlier session.

A variant is SURVIVED (green suite) or KILLED (red suite). Positive controls
must be KILLED; if one SURVIVES the runner is broken, not the module.

WHAT IT PRODUCES. One line per variant as it finishes, a summary ordered as the
table below, and `<work>/results.json`. Work goes under `.zig-cache/`, which is
droppable by contract — nothing here is worth keeping after the run.
"""
import os, shutil, subprocess, sys, re, json, concurrent.futures as cf

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
SRC = os.path.join(HERE, "..", "src")
WORK = os.path.join(ROOT, ".zig-cache", "hqc-mutate")

# (id, kind, file, old, new, expected_count, hypothesis, note)
MUTATIONS = [
    # ---- positive controls: the suite MUST catch these ----
    ("PC1-vectcompare-always-equal", "control", "kem.zig",
     "    var r: u16 = 0x0100;\n            for (a, b) |x, y| r |= x ^ y;\n            return @intCast((r -% 1) >> 8);",
     "    var r: u16 = 0x0100;\n            for (a, b) |x, y| _ = x ^ y;\n            _ = &r;\n            return 0;",
     1, "KILLED", "FO compare always says 'equal' -> real ss returned for any ct"),
    ("PC2-gf256-mul-zero", "control", "gf256.zig", None, None, 0, "KILLED", "field multiply returns 0"),

    # ---- FO transform / implicit rejection ----
    ("M1-hashJ-domain", "probe", "prng.zig",
     "    st.update(h_ek);\n    st.update(sigma);\n    st.update(c_kem_bytes);\n    st.update(&.{params.domain.j});",
     "    st.update(h_ek);\n    st.update(sigma);\n    st.update(c_kem_bytes);\n    st.update(&.{params.domain.j +% 7});",
     1, "?", "J's domain separator changed -> different K_bar, still deterministic"),
    ("M2-hashJ-leaks-sigma", "probe", "prng.zig",
     "    var st = std.crypto.hash.sha3.Sha3_256.init(.{});\n    st.update(h_ek);\n    st.update(sigma);\n    st.update(c_kem_bytes);\n    st.update(&.{params.domain.j});\n    st.final(out);",
     "    _ = h_ek;\n    _ = c_kem_bytes;\n    @memcpy(out, sigma[0..32]);",
     1, "?", "K_bar := sigma verbatim -> every rejected ct returns the long-term secret"),
    ("M3-Kbar-over-ct-prime", "probe", "kem.zig",
     "prng.hashJ(&k_bar, &h_ek, &sigma, &ct);",
     "prng.hashJ(&k_bar, &h_ek, &sigma, &ct_prime);",
     1, "?", "K_bar hashed over the RE-ENCRYPTED ct' instead of the received ct (SPEC forbids)"),
    ("M4-compare-skips-salt", "probe", "kem.zig",
     "const result: u8 = vectCompare(&ct_prime, &ct) -% 1;",
     "const result: u8 = vectCompare(ct_prime[0 .. ct_bytes - params.salt_bytes], ct[0 .. ct_bytes - params.salt_bytes]) -% 1;",
     1, "?", "FO compare ignores the salt tail"),
    ("M5-compare-only-u", "probe", "kem.zig",
     "const result: u8 = vectCompare(&ct_prime, &ct) -% 1;",
     "const result: u8 = vectCompare(ct_prime[0..Ring.n_bytes], ct[0..Ring.n_bytes]) -% 1;",
     1, "?", "FO compare covers only u, not v/salt"),
    ("M6-compare-only-v-salt", "probe", "kem.zig",
     "const result: u8 = vectCompare(&ct_prime, &ct) -% 1;",
     "const result: u8 = vectCompare(ct_prime[Ring.n_bytes..], ct[Ring.n_bytes..]) -% 1;",
     1, "?", "FO compare covers only v/salt, not u"),
    ("M7-compare-ignores-lsb", "probe", "kem.zig",
     "for (a, b) |x, y| r |= x ^ y;",
     "for (a, b) |x, y| r |= (x ^ y) & 0xFE;",
     1, "?", "FO compare blind to bit 0 of every byte"),
    ("M8-compare-first-byte-only", "probe", "kem.zig",
     "const result: u8 = vectCompare(&ct_prime, &ct) -% 1;",
     "const result: u8 = vectCompare(ct_prime[0..1], ct[0..1]) -% 1;",
     1, "?", "FO compare degenerates to one byte"),
    ("M9-no-reencrypt-check", "probe", "kem.zig",
     "o.* = (kp & result) ^ (kb & ~result);",
     "o.* = kp;\n                _ = kb;\n                _ = result;",
     1, "?", "FO check dropped entirely: always return K'"),

    # ---- parsing / canonicality ----
    ("M10-fromBytes-no-masktop", "probe", "gf2x.zig",
     "            @memcpy(dst[0..n_bytes], bytes[0..n_bytes]);\n            maskTop(&out);\n            return out;",
     "            @memcpy(dst[0..n_bytes], bytes[0..n_bytes]);\n            return out;",
     1, "?", "non-canonical top bits of u survive parsing"),

    # ---- PRNG / sampler ----
    ("M11-xof-no-8byte-quirk", "probe", "prng.zig",
     "        const rem = out.len % 8;\n        const aligned = out.len - rem;\n        self.st.squeeze(out[0..aligned]);\n        if (rem != 0) {\n            var block: [8]u8 = undefined;\n            self.st.squeeze(&block);\n            @memcpy(out[aligned..], block[0..rem]);\n        }",
     "        self.st.squeeze(out);",
     1, "?", "the documented load-bearing 8-byte-rounding quirk removed"),
    ("M12-hashH-domain", "probe", "prng.zig",
     "    var st = std.crypto.hash.sha3.Sha3_256.init(.{});\n    st.update(ek_kem);\n    st.update(&.{params.domain.h});",
     "    var st = std.crypto.hash.sha3.Sha3_256.init(.{});\n    st.update(ek_kem);\n    st.update(&.{params.domain.h +% 9});",
     1, "?", "H's domain separator changed"),

    # ---- truncate / ring ----
    ("M13-truncate-off-by-one", "probe", "pke.zig",
     "            Ring.truncate(&t, p.n1n2());",
     "            Ring.truncate(&t, p.n1n2() + 1);",
     1, "?", "Truncate keeps one extra bit"),
]


def apply(mid, kind, fname, old, new, count, hyp, note):
    d = os.path.join(WORK, mid)
    sd = os.path.join(d, "src")
    if os.path.isdir(sd):
        for f in os.listdir(sd):
            os.remove(os.path.join(sd, f))
    os.makedirs(sd, exist_ok=True)
    for f in os.listdir(SRC):
        shutil.copy(os.path.join(SRC, f), sd)

    if mid == "PC2-gf256-mul-zero":
        p = os.path.join(sd, "gf256.zig")
        s = open(p).read()
        m = re.search(r"pub fn mul\(a: u8, b: u8\) u8 \{", s)
        if not m:
            return (mid, kind, "BROKEN", "anchor for gf256.mul not found", hyp, note)
        s = s[:m.end()] + "\n    _ = a; _ = b; return 0;\n    // @@\n" + s[m.end():]
        open(p, "w").write(s)
    else:
        p = os.path.join(sd, fname)
        s = open(p).read()
        n = s.count(old)
        if n != count:
            return (mid, kind, "BROKEN", f"pattern found {n}x, expected {count}x in {fname}", hyp, note)
        s = s.replace(old, new)
        open(p, "w").write(s)

    cache = os.path.join(d, "cache")
    r = subprocess.run(["zig", "test", "root.zig", "-O", "ReleaseFast", "--cache-dir", cache],
                       cwd=sd, capture_output=True, text=True, timeout=1800)
    out = r.stdout + r.stderr
    # ⚠ Match the COUNT, do not pin it. This read `"All 75 tests passed" in out`
    # until 2026-09-16; the day the suite gained a 76th test, every green run
    # would have fallen through to the KILLED branch below — reporting mutations
    # as caught when they had in fact survived, which flatters the suite in
    # exactly the direction this tool exists to distrust.
    if r.returncode == 0 and re.search(r"All (\d+) tests passed", out):
        n_passed = re.search(r"All (\d+) tests passed", out).group(1)
        return (mid, kind, "SURVIVED", f"{n_passed}/{n_passed} green", hyp, note)
    if "error:" in out and "tests passed" not in out and "FAIL" not in out:
        # may be a compile error -> that is not a test result
        first = [l for l in out.splitlines() if "error:" in l][:2]
        return (mid, kind, "COMPILE-ERROR", " | ".join(first), hyp, note)
    fails = re.findall(r"^(\d+/\d+ \S+)\.\.\.FAIL", out, re.M)
    m = re.search(r"(\d+) passed; (\d+) skipped; (\d+) failed", out)
    summ = m.group(0) if m else "red"
    return (mid, kind, "KILLED", f"{summ}; first failures: {'; '.join(f.split(' ',1)[-1] for f in fails[:3])}", hyp, note)


def main():
    os.makedirs(WORK, exist_ok=True)
    sel = sys.argv[1:] or None
    muts = [m for m in MUTATIONS if not sel or m[0] in sel]
    results = []
    with cf.ThreadPoolExecutor(max_workers=3) as ex:
        futs = {ex.submit(apply, *m): m[0] for m in muts}
        for f in cf.as_completed(futs):
            res = f.result()
            results.append(res)
            print(f"[{res[2]:<13}] {res[0]:<28} {res[3][:110]}", flush=True)
    print("\n=== SUMMARY ===")
    order = {m[0]: i for i, m in enumerate(MUTATIONS)}
    for r in sorted(results, key=lambda x: order[x[0]]):
        print(f"{r[2]:<13} {r[1]:<8} {r[0]:<28} :: {r[5]}")
    json.dump(results, open(os.path.join(WORK, "results.json"), "w"), indent=1)
    # A control that survived means the runner is broken; say so in the status.
    broken = [r for r in results if r[1] == "control" and r[2] != "KILLED"]
    if broken:
        print(f"\n⛔ {len(broken)} positive control(s) not KILLED — the runner is broken, "
              f"every other row above is meaningless")
    return 1 if broken else 0


if __name__ == "__main__":
    sys.exit(main())
