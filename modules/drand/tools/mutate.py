#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""drand mutation runner — 22 mutations over the verification path.

WHY THIS EXISTS. Every check this module makes — subgroup membership, the
identity guards, the randomness comparison, which message is signed — is a line
that could be deleted without a single test turning red, and a green suite says
nothing about that. This removes or weakens each one in turn and records whether
the suite noticed. `M00` is the POSITIVE CONTROL: a deliberately broken
verification equation the suite MUST catch. If M00 survives, the runner is
broken and every other row is meaningless.

⚠ EACH MUTATION GETS ITS OWN `--cache-dir`. A shared cache handed back a stale
binary and produced 18 false PASSes in an earlier session.

⚠ IT MUTATES A SEPARATE `git worktree`, NEVER THE TRACKED TREE (2026-09-16).
Every edit lands in a detached checkout under `.zig-cache/drand-mutate/wt`, so
a SIGKILL, an OOM kill or a power loss mid-run cannot leave a mutated file in
the tree you work in. Until that date this patched `modules/drand/src` in place
and relied on `git checkout --` in a `finally`, which is enough for a normal
exit and a Ctrl-C and not enough for anything else.

⚠ IT STILL RUNS `zig build test-drand`, AND THAT IS THE POINT. The module's
dependency closure is bls12_381 -> entropy and tlock -> bls12_381 + entropy,
plus testkit for tests; a hand-assembled `-M` module graph would have to
restate all of it and would silently rot when it changes. `whois`'s runner was
migrated with exactly one dep missing and every row read RED, no-op control
included, because nothing could build. Driving the real build system inside a
throwaway checkout keeps the deps correct by construction AND the tree safe.

The worktree is created on first use and left in place (72 MB, inside the
droppable cache). Remove it with:

    git worktree remove --force .zig-cache/drand-mutate/wt

WHAT IT NEEDS. A `zig` on PATH, and a repository `git worktree` can check out.

    python3 mutate.py            # all 22
    python3 mutate.py M09 M10    # only these

WHAT IT PRODUCES. One line per mutation as it finishes — CAUGHT, SURVIVED or
BUILD-ERROR — then a summary. A SURVIVED row on anything but a deliberate
control is a hole in the suite, not a pass.
"""
import os, subprocess, sys, shutil, time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
CACHE = os.path.join(ROOT, ".zig-cache/drand-mutate")
# The detached checkout everything happens in. `SRC` deliberately points INSIDE
# it: nothing in this file may name a path under the tracked tree.
WT = os.path.join(CACHE, "wt")
SRC = os.path.join(WT, "modules/drand/src")

# (id, file, kind, old, new, description)
MUTATIONS = [
    ("M00", "verify.zig", "positive-control",
     "const qid = ciphersuite.h1(ciphersuite.beaconId(round));",
     "const qid = ciphersuite.h1(ciphersuite.beaconId(round +% 1));",
     "POSITIVE CONTROL: sign-message uses round+1 (must break every KAT)"),

    ("M01", "chaininfo.zig", "remove",
     "        if (pt.infinity) return error.InvalidPoint;\n",
     "",
     "remove the identity-public-key KeyValidate guard"),

    ("M02", "chaininfo.zig", "remove",
     "        if (!g2.Jacobian.fromAffine(pt).subgroupCheck()) return error.PublicKeyNotInSubgroup;\n",
     "",
     "remove the G2 public-key subgroup check"),

    ("M03", "chaininfo.zig", "weaken",
     "if (!g2.Jacobian.fromAffine(pt).subgroupCheck()) return error.PublicKeyNotInSubgroup;",
     "if (!g2.Jacobian.fromAffine(pt).isOnCurve()) return error.PublicKeyNotInSubgroup;",
     "WEAKEN the G2 subgroup check to a curve-equation check"),

    ("M04", "round.zig", "remove",
     "        if (!g1.Jacobian.fromAffine(pt).subgroupCheck()) return error.SignatureNotInSubgroup;\n",
     "",
     "remove the G1 signature subgroup check at parse"),

    ("M05", "round.zig", "weaken",
     "if (!g1.Jacobian.fromAffine(pt).subgroupCheck()) return error.SignatureNotInSubgroup;",
     "if (!g1.Jacobian.fromAffine(pt).isOnCurve()) return error.SignatureNotInSubgroup;",
     "WEAKEN the parse-time G1 subgroup check to a curve check"),

    ("M06", "verify.zig", "remove",
     "    if (pubkey.infinity or sig.infinity) return false;\n",
     "",
     "remove the identity-operand guard in verifyRoundPoints"),

    ("M07", "verify.zig", "weaken",
     "if (pubkey.infinity or sig.infinity) return false;",
     "if (pubkey.infinity) return false;",
     "WEAKEN the identity guard to the public key only"),

    ("M08", "verify.zig", "weaken",
     "if (pubkey.infinity or sig.infinity) return false;",
     "if (sig.infinity) return false;",
     "WEAKEN the identity guard to the signature only"),

    ("M09", "verify.zig", "remove",
     "    if (!g1.Jacobian.fromAffine(sig).subgroupCheck()) return false;\n",
     "",
     "remove the G1 subgroup check inside verifyRoundPoints"),

    ("M10", "verify.zig", "remove",
     "        if (!std.mem.eql(u8, &digest, &claimed)) return error.RandomnessMismatch;\n",
     "",
     "remove the randomness == SHA-256(signature) check"),

    ("M11", "verify.zig", "weaken",
     "if (!std.mem.eql(u8, &digest, &claimed)) return error.RandomnessMismatch;",
     "if (!std.mem.eql(u8, digest[0..8], claimed[0..8])) return error.RandomnessMismatch;",
     "WEAKEN the randomness check to the first 8 of 32 bytes"),

    ("M12", "verify.zig", "weaken",
     "if (!std.mem.eql(u8, &digest, &claimed)) return error.RandomnessMismatch;",
     "if (!std.mem.eql(u8, digest[0..1], claimed[0..1])) return error.RandomnessMismatch;",
     "WEAKEN the randomness check to the first byte"),

    ("M13", "verify.zig", "remove",
     "    if (round.sig_len != g1.compressed_bytes) return error.SchemeGroupMismatch;\n",
     "",
     "remove the signature-group (48-byte) check"),

    ("M14", "verify.zig", "remove",
     "    if (!info.scheme.isVerifiable()) return error.UnsupportedScheme;\n",
     "",
     "remove the scheme dispatch guard"),

    ("M15", "verify.zig", "weaken",
     "const qid = ciphersuite.h1(ciphersuite.beaconId(round));",
     "const qid = ciphersuite.h1(ciphersuite.beaconId(round & 0xFFFF_FFFF));",
     "WEAKEN the signed message to the low 32 bits of the round number"),

    ("M16", "verify.zig", "weaken",
     "return (now_unix - info.genesis_time) / info.period_seconds + 1;",
     "return (now_unix - info.genesis_time) / info.period_seconds;",
     "drop the +1 in expectedRound (drand's CurrentRound formula)"),

    ("M17", "chaininfo.zig", "weaken",
     "pub const max_document_bytes: usize = 64 * 1024;",
     "pub const max_document_bytes: usize = 64 * 1024 * 1024;",
     "raise the /info document cap 1000x (64 KiB -> 64 MiB)"),

    ("M18", "round.zig", "weaken",
     "pub const max_document_bytes: usize = 64 * 1024;",
     "pub const max_document_bytes: usize = 64 * 1024 * 1024;",
     "raise the /public/<round> document cap 1000x"),

    ("M19", "chaininfo.zig", "weaken",
     "    const group_hash = try hexExact(32, raw.groupHash);",
     "    const group_hash = [_]u8{0} ** 32;\n    _ = raw.groupHash;",
     "ignore groupHash entirely and store zeros"),

    ("M20", "round.zig", "weaken",
     "        if (r.len != 64) return error.InvalidLength;",
     "        if (r.len > 64) return error.InvalidLength;",
     "WEAKEN the randomness length check from == 64 to <= 64"),

    ("M21", "chaininfo.zig", "weaken",
     "        if (pubkey_nbytes != g2.compressed_bytes) return error.InvalidLength;",
     "        if (pubkey_nbytes < g2.compressed_bytes) return error.InvalidLength;",
     "WEAKEN the quicknet key-length check from == 96 to >= 96"),

    ("M22", "chaininfo.zig", "weaken",
     "    if (hex.len != 2 * n) return error.InvalidLength;",
     "    if (hex.len < 2 * n) return error.InvalidLength;",
     "WEAKEN hexExact's length check from == to >="),
]


def run(mid, path, old, new, desc):
    full = os.path.join(SRC, path)
    orig = open(full).read()
    # A patch that did not land is a MISSING ROW, never a verdict: report it as
    # such rather than letting an unmutated build read as "SURVIVED".
    if old not in orig:
        return (mid, path, desc, "PATCH-MISS", "")
    if orig.count(old) != 1:
        return (mid, path, desc, f"AMBIGUOUS({orig.count(old)})", "")
    try:
        open(full, "w").write(orig.replace(old, new, 1))
        cd = os.path.join(CACHE, mid)
        t0 = time.time()
        p = subprocess.run(
            ["zig", "build", "test-drand", "-Doptimize=ReleaseFast",
             "--summary", "all", "--cache-dir", cd],
            cwd=WT, capture_output=True, text=True, timeout=1800)
        dt = time.time() - t0
        out = (p.stdout + p.stderr)
        # A mutation that fails to COMPILE is not a killed mutation -- see
        # mutate_m10.py for the case that taught this.
        if "error: " in out and "tests passed" not in out:
            verdict = "BUILD-ERROR"
        elif p.returncode == 0:
            verdict = "SURVIVED"
        else:
            verdict = "CAUGHT"
        summary = ""
        for line in out.splitlines():
            if "tests passed" in line or "test drand" in line and "pass" in line:
                summary = line.strip()
        first_err = ""
        for line in out.splitlines():
            if line.strip().startswith("error:") or "FAIL" in line:
                first_err = line.strip()[:150]
                break
        return (mid, path, desc, verdict, f"{summary} | {first_err} | {dt:.0f}s")
    finally:
        # Restore inside the WORKTREE. Even if this never runs, the tracked
        # tree is untouched -- that is the whole reason the worktree exists.
        subprocess.run(["git", "-C", WT, "checkout", "--",
                        "modules/drand/src/" + path])


def ensure_worktree():
    """A detached checkout of HEAD to mutate, created once and reused.

    Detached on purpose: a named branch here would show up in `git branch` and
    invite someone to commit to it.
    """
    os.makedirs(CACHE, exist_ok=True)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                          capture_output=True, text=True).stdout.strip()
    if not os.path.isdir(os.path.join(WT, ".git")) and not os.path.isfile(os.path.join(WT, ".git")):
        r = subprocess.run(["git", "worktree", "add", "--detach", WT, head],
                           cwd=ROOT, capture_output=True, text=True)
        if r.returncode != 0:
            print("REFUSING: could not create the worktree:\n" + r.stdout + r.stderr)
            sys.exit(1)
    # It must be pristine, for the same reason the tracked tree had to be
    # before: a leftover edit would be attributed to whichever row runs next.
    d = subprocess.run(["git", "-C", WT, "status", "--porcelain", "--", "modules/drand"],
                       capture_output=True, text=True).stdout.strip()
    if d:
        print("REFUSING: the worktree's modules/drand is not pristine:\n" + d)
        print(f"  restore it with: git -C {WT} checkout -- modules/drand")
        sys.exit(1)
    # ⚠ A REUSED WORKTREE GOES STALE, and that is the very defect this whole
    # migration exists to remove. `worktree add` runs once; without the move
    # below the checkout stays pinned at whatever HEAD was on the day it was
    # created, and every later run mutates a module one or more commits behind
    # the tree it claims to report on -- an instrument keeping its own copy,
    # which rots. Re-pointing it is cheap; being silently wrong is not.
    at = subprocess.run(["git", "-C", WT, "rev-parse", "HEAD"],
                        capture_output=True, text=True).stdout.strip()
    if at != head:
        r = subprocess.run(["git", "-C", WT, "checkout", "--detach", head],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"REFUSING: the worktree sits at {at[:8]} and could not be moved "
                  f"to {head[:8]}:\n" + r.stdout + r.stderr)
            sys.exit(1)
        print(f"worktree advanced {at[:8]} -> {head[:8]}")
    print(f"worktree: {WT}  (at {head[:8]})\n"
          f"  (the tracked tree is never written to; remove with "
          f"`git worktree remove --force {os.path.relpath(WT, ROOT)}`)\n")


def main():
    ensure_worktree()
    only = sys.argv[1:]
    rows = []
    for m in MUTATIONS:
        mid, path, kind, old, new, desc = m
        if only and mid not in only:
            continue
        r = run(mid, path, old, new, desc)
        rows.append((kind,) + r)
        print(f"{r[0]:4s} {kind:16s} {r[3]:12s} {r[1]:14s} {desc}", flush=True)
        print(f"       {r[4]}", flush=True)
    print("\n== SUMMARY ==")
    for kind, mid, path, desc, verdict, extra in rows:
        print(f"{mid} | {kind} | {verdict} | {path} | {desc}")
    # The control decides whether any of the above means anything.
    bad = [r for r in rows if r[0] == "positive-control" and r[4] != "CAUGHT"]
    if bad:
        print(f"\n⛔ the positive control was not CAUGHT ({bad[0][4]}) — the runner is "
              f"broken and every row above is meaningless")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
