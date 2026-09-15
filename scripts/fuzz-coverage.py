#!/usr/bin/env python3
"""Read Zig 0.16's fuzz coverage maps without trusting the build runner's report.

Used by `scripts/modtest <m> --fuzz`; not meant to be run by hand, but it can be:

    fuzz-coverage.py snapshot CACHE_DIR OUT.json
    fuzz-coverage.py report   CACHE_DIR BEFORE.json MODULE KV_OUT [REACH]

WHY THIS EXISTS. Under `zig build --fuzz=N` the process exit code says nothing
about crashes (see `scripts/fuzz-sweep.sh`), and the FUZZING REPORT prints one
block per test EXECUTABLE naming only `fuzz_tests.items[0]` -- so a module with
three harnesses in one binary looks like a module where one harness ran and two
were starved (`netconf` N13 read it exactly that way). The counters behind that
report live in a memory-mapped file the fuzzer updates while it runs:

    .zig-cache/v/<hex pc digest>   (std/Build/abi.zig, fuzz.SeenPcsHeader)
        u64 n_runs, u64 unique_runs, u64 pcs_len,
        ceil(pcs_len/64) u64 seen-bit words, pcs_len u64 unslid PC addresses

It is written by the fuzzed process itself, so it answers "how many iterations
really ran" even when the run was killed before any report was printed.

The PCs are the addresses of the instrumented executable's `__sancov_pcs1`
section as on disk (`fuzzer_unslide_address`), so resolving them with
`addr2line -i` against that executable says which SOURCE LINES the fuzzer
executed. That is what turns "the harness can select shape 4" into "shape 4's
decode was executed N times this run" -- the measurement the campaign kept
recording as impossible.
"""

import json
import os
import struct
import subprocess
import sys

HDR = struct.Struct("<QQQ")


def read_cov(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < HDR.size:
        return None
    runs, unique, pcs_len = HDR.unpack_from(data, 0)
    words = (pcs_len + 63) // 64
    need = HDR.size + 8 * words + 8 * pcs_len
    if pcs_len == 0 or len(data) != need:
        return None
    bits = data[HDR.size:HDR.size + 8 * words]
    pcs = struct.unpack_from("<%dQ" % pcs_len, data, HDR.size + 8 * words)
    return {"runs": runs, "unique": unique, "pcs_len": pcs_len, "bits": bits, "pcs": pcs}


def seen_set(bits, pcs_len):
    out = set()
    for w in range((pcs_len + 63) // 64):
        v = int.from_bytes(bits[8 * w:8 * w + 8], "little")
        while v:
            low = v & -v
            i = w * 64 + low.bit_length() - 1
            if i < pcs_len:
                out.add(i)
            v ^= low
    return out


def cov_files(cache_dir):
    vdir = os.path.join(cache_dir, "v")
    try:
        names = sorted(os.listdir(vdir))
    except FileNotFoundError:
        return []
    return [(n, os.path.join(vdir, n)) for n in names]


def cmd_snapshot(cache_dir, out):
    snap = {}
    for name, path in cov_files(cache_dir):
        c = read_cov(path)
        if c is None:
            continue
        snap[name] = {"runs": c["runs"], "unique": c["unique"], "bits": c["bits"].hex()}
    with open(out, "w") as f:
        json.dump(snap, f)


def elf_section(path, want):
    """Return the bytes of section `want` of a 64-bit LE ELF, or None."""
    try:
        with open(path, "rb") as f:
            ident = f.read(64)
            if len(ident) < 64 or ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
                return None
            shoff = struct.unpack_from("<Q", ident, 0x28)[0]
            shentsize, shnum, shstrndx = struct.unpack_from("<HHH", ident, 0x3A)
            if shoff == 0 or shentsize < 64 or shnum == 0:
                return None
            f.seek(shoff)
            table = f.read(shentsize * shnum)
            secs = []
            for i in range(shnum):
                off = i * shentsize
                name, typ = struct.unpack_from("<II", table, off)
                offset, size = struct.unpack_from("<QQ", table, off + 24)
                secs.append((name, typ, offset, size))
            _, _, stroff, strsize = secs[shstrndx]
            f.seek(stroff)
            strtab = f.read(strsize)
            for name, typ, offset, size in secs:
                end = strtab.find(b"\0", name)
                if strtab[name:end].decode(errors="replace") == want:
                    f.seek(offset)
                    return f.read(size) if typ != 8 else b"\0" * size
    except OSError:
        return None
    return None


def find_exe(cache_dir, module, cov):
    """The instrumented test executable whose __sancov_pcs1 IS this map's PC list.

    Matched by content, not by name or mtime: the build cache holds every
    earlier build of the same module, and a stale one of the same size would
    resolve the PCs to the wrong lines without complaint.
    """
    odir = os.path.join(cache_dir, "o")
    want = struct.pack("<%dQ" % cov["pcs_len"], *cov["pcs"])
    size_only = []
    try:
        hashes = os.listdir(odir)
    except FileNotFoundError:
        return None, "no .zig-cache/o"
    for h in hashes:
        p = os.path.join(odir, h, module)
        if not os.path.isfile(p):
            continue
        sec = elf_section(p, "__sancov_pcs1")
        if sec is None or len(sec) != len(want):
            continue
        if sec == want:
            return p, "matched by __sancov_pcs1 content"
        size_only.append(p)
    if len(size_only) == 1:
        return size_only[0], "matched by __sancov_pcs1 SIZE only (section not static) -- treat line data as approximate"
    return None, "no executable under .zig-cache/o/*/%s carries this PC list (%d size-only candidates)" % (module, len(size_only))


def resolve(exe, pcs):
    """PC index -> list of (function, path, line), inline frames included.

    `-f` output is two lines per frame (function, then file:line), after the
    `-a` address marker. Measured on protobuf 2026-09-15: a ReleaseSafe switch
    arm (`4 => try fuzzOne(ct.Presence, ...)`) has NO sancov PC of its own, so
    a line query for it is NO-PC even though the arm ran. Generic
    instantiations are only distinguishable by FUNCTION name, and Zig spells
    the type into it (`decode.Decoded(conformance.Presence).deinit`) -- hence
    the `fn:` reach form.
    """
    inp = "".join("0x%x\n" % pc for pc in pcs)
    r = subprocess.run(["addr2line", "-a", "-f", "-i", "-e", exe], input=inp,
                       capture_output=True, text=True, check=False)
    out = {}
    idx = -1
    func = None
    for line in r.stdout.splitlines():
        if line.startswith("0x") and func is None:
            idx += 1
            out[idx] = []
            continue
        if idx < 0:
            continue
        if func is None:
            func = line
            continue
        path, _, ln = line.rpartition(":")
        ln = ln.split(" ")[0]
        out[idx].append((func, path, int(ln) if ln.isdigit() else 0))
        func = None
    return out


def split_top(spec):
    """Split on commas that are not inside parentheses (function names have them)."""
    parts, depth, cur = [], 0, ""
    for ch in spec:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur)
            cur = ""
        else:
            cur += ch
    parts.append(cur)
    return [p.strip() for p in parts if p.strip()]


def parse_reach(spec):
    """`file.zig:LINE`, `file.zig:A-B`, or `fn:SUBSTRING` of a function name."""
    items = []
    for part in split_top(spec):
        if part.startswith("fn:"):
            items.append((part, "fn", part[3:], 0, 0))
            continue
        f, _, rng = part.rpartition(":")
        if not f or not rng:
            raise SystemExit("bad reach item %r (want file.zig:LINE, file.zig:A-B or fn:NAME)" % part)
        a, _, b = rng.partition("-")
        items.append((part, "line", f, int(a), int(b or a)))
    return items


def cmd_report(cache_dir, before_path, module, kv_out, reach_spec=""):
    with open(before_path) as f:
        before = json.load(f)
    reach = parse_reach(reach_spec) if reach_spec else []
    kv = {"runs_delta": 0, "maps": 0, "reach_items": len(reach), "reach_miss": 0}
    src_marker = "/modules/%s/src/" % module

    for name, path in cov_files(cache_dir):
        c = read_cov(path)
        if c is None:
            continue
        b = before.get(name)
        runs0 = b["runs"] if b else 0
        if c["runs"] == runs0:
            continue  # not touched by this run
        uniq0 = b["unique"] if b else 0
        seen_now = seen_set(c["bits"], c["pcs_len"])
        seen_then = seen_set(bytes.fromhex(b["bits"]), c["pcs_len"]) if b else set()
        kv["maps"] += 1
        kv["runs_delta"] += c["runs"] - runs0
        n = c["pcs_len"]
        print("fuzz map v/%s: runs %d -> %d (+%d), unique %d -> %d, coverage %d -> %d/%d PCs (%.2f%%)%s"
              % (name, runs0, c["runs"], c["runs"] - runs0, uniq0, c["unique"],
                 len(seen_then), len(seen_now), n, 100.0 * len(seen_now) / n,
                 "" if b else "  [fresh map: every number is this run's]"))

        exe, how = find_exe(cache_dir, module, c)
        print("  executable: %s (%s)" % (exe or "NOT FOUND", how))
        if exe is None:
            if reach:
                kv["reach_miss"] += len(reach)
                print("  ⛔ reach: cannot resolve PCs to lines, so no reach claim can be made")
            continue
        kv["exe"] = exe
        lines = resolve(exe, c["pcs"])

        per_file = {}
        for i in range(n):
            files = {p for _, p, _ in lines.get(i, []) if src_marker in p}
            for p in files:
                t = per_file.setdefault(p, [0, 0])
                t[0] += 1
                if i in seen_now:
                    t[1] += 1
        if per_file:
            print("  module source coverage (PCs whose inline chain touches the file; seen/total):")
            for p in sorted(per_file):
                tot, hit = per_file[p]
                print("    %-40s %6d/%-6d %6.2f%%" % (p.split(src_marker, 1)[1], hit, tot, 100.0 * hit / tot))
        else:
            print("  ⚠ no PC resolved into %s -- debug info missing or wrong executable" % src_marker)

        for label, kind, f, a, z in reach:
            if kind == "fn":
                pcs_here = [i for i in range(n) if any(f in fn for fn, _, _ in lines.get(i, []))]
            else:
                pcs_here = [i for i in range(n)
                            if any((p.endswith("/" + f) or p == f) and a <= ln <= z for _, p, ln in lines.get(i, []))]
            hit = [i for i in pcs_here if i in seen_now]
            new = [i for i in hit if i not in seen_then]
            if not pcs_here:
                verdict = "NO-PC (no instrumented PC maps to this line; the instrument cannot see it)"
                kv["reach_miss"] += 1
            elif not hit:
                verdict = "MISS"
                kv["reach_miss"] += 1
            else:
                verdict = "HIT"
            print("  reach %-28s %s  (%d/%d PCs seen, %d first seen this run)"
                  % (label, verdict, len(hit), len(pcs_here), len(new)))

    with open(kv_out, "w") as f:
        for k, v in kv.items():
            f.write("%s=%s\n" % (k, v))


def main(argv):
    if len(argv) >= 3 and argv[1] == "snapshot":
        return cmd_snapshot(argv[2], argv[3])
    if len(argv) >= 6 and argv[1] == "report":
        return cmd_report(argv[2], argv[3], argv[4], argv[5], argv[6] if len(argv) > 6 else "")
    sys.stderr.write(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv) or 0)
