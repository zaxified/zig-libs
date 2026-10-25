# SPDX-License-Identifier: MIT
"""Driver of the kv lead probe (backs the kv "Ahead" claims: P1 read-only
reader beside a live writer, P2 torn tail, P3 flipped byte in a sealed file).

usage: python3 -I drive.py WORKDIR p1|p2|p2z|p3|p3b|summary [config ...]

WORKDIR holds bin/<probe> (built by run.sh), work/ (scratch, emptied per trial)
and results/*.json. Every trial runs each store in its own OS process.
"""
import collections, glob, json, os, queue, random, re, shutil, subprocess, sys, threading
from concurrent.futures import ThreadPoolExecutor
ROOT = os.path.abspath(sys.argv[1])
WORK = os.path.join(ROOT, "work")
RES = os.path.join(ROOT, "results")
BIN = os.path.join(ROOT, "bin")
os.makedirs(WORK, exist_ok=True); os.makedirs(RES, exist_ok=True)
N = 1000

# config name -> argv prefix, env, active-file glob, files to remove, segment size for the sealed test
def cfgs():
    z = os.path.join(BIN, "kv")
    return {
     "kv-plain":  dict(cmd=[z, "plain"], env={}, act="kv.db", seg=16384, kind="kv"),
     "kv-mmap":   dict(cmd=[z, "mmap"],  env={}, act="kv.db", seg=16384, kind="kv"),
     "rosedb":    dict(cmd=[os.path.join(BIN, "rosedb")], env={}, act="*.SEG", seg=65536, kind="rosedb"),
     "bitcask":   dict(cmd=[os.path.join(BIN, "bitcask")], env={}, act="*.data", seg=16384, kind="bitcask"),
     "bitcask-noindex": dict(cmd=[os.path.join(BIN, "bitcask")], env={}, act="*.data", seg=16384, kind="bitcask", rm=["index", "ttl_index"]),
     "bitcask-autorecover": dict(cmd=[os.path.join(BIN, "bitcask")], env={"BC_RECOVER": "1"}, act="*.data", seg=16384, kind="bitcask"),
     "nutsdb":    dict(cmd=[os.path.join(BIN, "nutsdb")], env={}, act="*.dat", seg=16384, kind="nutsdb"),
    }
C = cfgs()

def run(c, args, timeout=60, stdin=None):
    env = dict(os.environ); env.update(C[c]["env"])
    try:
        p = subprocess.run(C[c]["cmd"] + args, capture_output=True, text=True, timeout=timeout, env=env, start_new_session=True, stdin=subprocess.DEVNULL)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired as e:
        return "TIMEOUT", (e.stdout or b"").decode() if isinstance(e.stdout, bytes) else (e.stdout or ""), "timeout"

def files_sorted(c, d):
    if C[c]["kind"] == "kv":
        extra = sorted(glob.glob(os.path.join(d, "kv.db.*.data")), key=lambda p: int(os.path.basename(p).split(".")[2]))
        return [os.path.join(d, "kv.db")] + extra
    return sorted(glob.glob(os.path.join(d, C[c]["act"])))

def logical_end(c, path):
    sz = os.path.getsize(path)
    if C[c]["kind"] != "nutsdb": return sz
    with open(path, "rb") as f: data = f.read()
    return len(data.rstrip(b"\0"))

def copytree(src, dst):
    if os.path.exists(dst): shutil.rmtree(dst)
    os.makedirs(dst)
    for n in os.listdir(src):
        subprocess.run(["cp", "--sparse=always", "-p", os.path.join(src, n), os.path.join(dst, n)], check=True)

def baseline(c, seg=0):
    d = os.path.join(WORK, c + ("-seg" if seg else "-base"))
    if os.path.exists(d): shutil.rmtree(d)
    os.makedirs(d)
    rc, o, e = run(c, ["write", d, str(N), str(seg)])
    return d, (rc, o, e)

def parse(o):
    r = {}
    m = re.search(r"open=(OK|ERR) ?(\".*\")?", o)
    r["open"] = (m.group(1) + (" " + m.group(2) if m.group(2) else "")) if m else "?"
    m = re.search(r"ok=(\d+) wrong=(\d+) missing=(\d+) err=(\d+) firsterr=(\".*\")", o)
    if m: r["ok"], r["wrong"], r["missing"], r["err"], r["firsterr"] = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4)), m.group(5)
    m = re.search(r"newkey=(\w+)", o)
    if m: r["newkey"] = m.group(1)
    m = re.search(r"put: (.*)", o)
    if m: r["put"] = m.group(1).strip()
    return r

def trial_p2(c, base, mode, k, seed, tag):
    d = os.path.join(WORK, f"{c}-{tag}")
    copytree(base, d)
    for n in C[c].get("rm", []):
        try: os.remove(os.path.join(d, n))
        except FileNotFoundError: pass
    f = files_sorted(c, d)[-1]
    le = logical_end(c, f)
    if mode == "trunc":
        with open(f, "r+b") as fh: fh.truncate(le - k)
    elif mode == "zero":
        with open(f, "r+b") as fh: fh.seek(le - k); fh.write(b"\0" * k)
    else:
        rnd = random.Random(seed)
        with open(f, "r+b") as fh:
            fh.seek(le); fh.write(rnd.randbytes(k))
    res = {}
    rc, o, e = run(c, ["check", d, str(N)])
    res["rc1"] = rc; res.update({"c1_" + a: b for a, b in parse(o).items()}); res["err1"] = e.strip().splitlines()[:2]
    rc, o, e = run(c, ["putnew", d]); p = parse(o); res["putnew_open"] = p["open"]; res["put"] = p.get("put"); res["rc2"] = rc; res["err2"] = e.strip().splitlines()[:2]
    rc, o, e = run(c, ["getnew", d]); p = parse(o); res["newkey"] = p.get("newkey", p["open"]); res["rc3"] = rc
    rc, o, e = run(c, ["check", d, str(N)]); res["rc4"] = rc; res.update({"c4_" + a: b for a, b in parse(o).items()}); res["err4"] = e.strip().splitlines()[:2]
    shutil.rmtree(d)
    return res

def p2(c):
    base, w = baseline(c)
    assert "close" in w[1], w
    f = files_sorted(c, base)[-1]
    rec = logical_end(c, f) // N
    ks = [1, 7, 13, 50, 101, rec // 2, rec]
    ks = sorted(set(ks))
    out = {"config": c, "rec": rec, "ks": ks, "trunc": {}, "garb": {}}
    jobs = []
    for k in ks:
        jobs.append(("trunc", k, 0))
        for s in range(20): jobs.append(("garb", k, s))
    def one(j):
        mode, k, s = j
        r = trial_p2(c, base, mode, k, s, f"{mode}{k}s{s}")
        print(f"P2 {c} {mode} k={k} seed={s} open={r['c1_open']} ok={r.get('c1_ok')} newkey={r['newkey']}", flush=True)
        return j, r
    with ThreadPoolExecutor(4) as ex:
        for (mode, k, s), r in ex.map(one, jobs):
            out[mode].setdefault(str(k), []).append(r)
    json.dump(out, open(os.path.join(RES, f"p2-{c}.json"), "w"), indent=1)

def p2z(c):
    base, w = baseline(c)
    f = files_sorted(c, base)[-1]; rec = logical_end(c, f) // N
    ks = sorted(set([1, 7, 13, 50, 101, rec // 2, rec])); out = {"config": c, "rec": rec, "ks": ks, "zero": {}}
    for k in ks:
        r = trial_p2(c, base, "zero", k, 0, f"zero{k}"); out["zero"][str(k)] = [r]
        print("P2z", c, k, r["c1_open"], r.get("c1_ok"), r["newkey"], flush=True)
    json.dump(out, open(os.path.join(RES, f"p2z-{c}.json"), "w"), indent=1)

def p3(c):
    base, w = baseline(c, C[c]["seg"])
    assert "close" in w[1], w
    fs = files_sorted(c, base)
    out = {"config": c, "files": [os.path.basename(x) for x in fs], "trials": []}
    sealed = fs[:-1]
    if not sealed: out["error"] = "no sealed files"; json.dump(out, open(os.path.join(RES, f"p3-{c}.json"), "w")); return
    blobs = {x: open(x, "rb").read() for x in sealed}
    def val(i): return bytes((i + j) % 251 for j in range(100))
    rnd = random.Random(7)
    ids = list(range(N)); rnd.shuffle(ids)
    targets = []
    for i in ids:
        for x, b in blobs.items():
            pos = b.find(val(i))
            if pos >= 0: targets.append((i, x, pos)); break
        if len(targets) == 20: break
    def one(t):
        i, x, pos = t
        d = os.path.join(WORK, f"{c}-p3-{i}")
        copytree(base, d)
        for n in C[c].get("rm", []):
            try: os.remove(os.path.join(d, n))
            except FileNotFoundError: pass
        f = os.path.join(d, os.path.basename(x))
        off = pos + rnd.randrange(100)  # race-free enough: rnd only picks offsets
        with open(f, "r+b") as fh:
            fh.seek(off); b = fh.read(1); fh.seek(off); fh.write(bytes([b[0] ^ 0x40]))
        rc, o, e = run(c, ["check", d, str(N)])
        r = parse(o); r["rc"] = rc; r["id"] = i; r["file"] = os.path.basename(x); r["stderr"] = e.strip().splitlines()[:2]
        print(f"P3 {c} id={i} {r}", flush=True)
        shutil.rmtree(d)
        return r
    out["trials"] = [one(t) for t in targets]
    json.dump(out, open(os.path.join(RES, f"p3-{c}.json"), "w"), indent=1)

def p3b(c):
    base, w = baseline(c, C[c]["seg"])
    fs = files_sorted(c, base); sealed = fs[:-1]
    blobs = {x: open(x, "rb").read() for x in sealed}
    def val(i): return bytes((i + j) % 251 for j in range(100))
    rnd = random.Random(11); ids = list(range(N)); rnd.shuffle(ids)
    targets = []
    for i in ids:
        for x, b in blobs.items():
            pos = b.find(val(i))
            if pos >= 0: targets.append((i, x, pos)); break
        if len(targets) == 10: break
    out = {"config": c, "trials": []}
    for (i, x, pos) in targets:
        d = os.path.join(WORK, f"{c}-p3b-{i}"); copytree(base, d)
        f = os.path.join(d, os.path.basename(x)); off = pos + rnd.randrange(100)
        r = Proc(c, ["reader", d]); r.until(lambda l: l == "READY" or (l or "").startswith("open=ERR"))
        r.send("check 0 1000"); pre = r.until(lambda l: (l or "").startswith("check"))[-1]
        with open(f, "r+b") as fh:
            fh.seek(off); b = fh.read(1); fh.seek(off); fh.write(bytes([b[0] ^ 0x40]))
        r.send("check 0 1000"); post = r.until(lambda l: (l or "").startswith("check"))[-1]
        ex = r.finish()
        t = {"id": i, "pre": pre, "post": post, "exit": ex}; out["trials"].append(t)
        print("P3b", c, i, post, ex, flush=True)
        shutil.rmtree(d)
    json.dump(out, open(os.path.join(RES, f"p3b-{c}.json"), "w"), indent=1)

class Proc:
    def __init__(self, c, args):
        env = dict(os.environ); env.update(C[c]["env"])
        self.p = subprocess.Popen(C[c]["cmd"] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, start_new_session=True)
        self.q = queue.Queue()
        threading.Thread(target=lambda: [self.q.put(l.rstrip("\n")) for l in self.p.stdout] or self.q.put(None), daemon=True).start()
    def line(self, t=20):
        try: return self.q.get(timeout=t)
        except queue.Empty: return "<<timeout>>"
    def until(self, pred, t=20):
        got = []
        while True:
            l = self.line(t); got.append(l)
            if l is None or l == "<<timeout>>" or pred(l): return got
    def send(self, s):
        try: self.p.stdin.write(s + "\n"); self.p.stdin.flush()
        except Exception as e: pass
    def finish(self):
        self.send("quit")
        try: self.p.wait(timeout=10)
        except Exception: self.p.kill()
        err = self.p.stderr.read()
        return self.p.returncode, err.strip().splitlines()[:3]

def p1(c, reader_rw=False):
    d = os.path.join(WORK, f"{c}-p1" + ("rw" if reader_rw else ""))
    if os.path.exists(d): shutil.rmtree(d)
    os.makedirs(d)
    log = {"config": c, "reader_role": "rw (plain second open)" if reader_rw else "ro (store's read-only option if any)"}
    h = Proc(c, ["holder", d, "100"])
    log["holder"] = h.until(lambda l: l == "READY")
    rargs = ["reader", d] + (["rw"] if reader_rw else [])
    r = Proc(c, rargs)
    first = r.until(lambda l: l == "READY" or (l or "").startswith("open=ERR"))
    log["reader_open"] = first
    if "READY" in first:
        r.send("check 0 100"); log["r_check_0_100"] = r.until(lambda l: (l or "").startswith("check"))[-1]
        h.send("more 100 110"); log["h_more"] = h.until(lambda l: l == "DONE")[-1]
        r.send("check 100 110"); log["r_check_before_refresh"] = r.until(lambda l: (l or "").startswith("check"))[-1]
        r.send("refresh"); log["r_refresh"] = r.until(lambda l: (l or "").startswith("refresh"))[-1]
        r.send("check 0 110"); log["r_check_after_refresh"] = r.until(lambda l: (l or "").startswith("check"))[-1]
        r.send("put"); log["r_put"] = r.until(lambda l: (l or "").startswith("put-on-reader"))[-1]
        log["reader_exit"] = r.finish()
    else:
        try: r.p.wait(timeout=5)
        except Exception: r.p.kill()
        log["reader_exit"] = (r.p.returncode, r.p.stderr.read().strip().splitlines()[:3])
    log["holder_exit"] = h.finish()
    rc, o, e = run(c, ["check", d, "110"]); log["after_all_check_110"] = (rc, o.strip(), e.strip().splitlines()[:2])
    shutil.rmtree(d)
    print("P1", c, json.dumps(log)[:300], flush=True)
    json.dump(log, open(os.path.join(RES, f"p1-{c}{'-rw' if reader_rw else ''}.json"), "w"), indent=1)

def rng(v):
    v = [x for x in v if x is not None]
    return "-" if not v else (str(min(v)) if min(v) == max(v) else f"{min(v)}..{max(v)}")

def summary():
    print("\n## P1 read-only reader beside a live writer")
    for f in sorted(glob.glob(os.path.join(RES, "p1-*.json"))):
        d = json.load(open(f))
        print(f"{os.path.basename(f)[3:-5]:22} reader_open={d['reader_open'][-1]!r} before_refresh={d.get('r_check_before_refresh', '-')[:40]!r}"
              f" after_refresh={d.get('r_check_after_refresh', '-')[:40]!r} put={d.get('r_put', '-')!r}")
    print("\n## P2 torn tail (trunc = truncate k bytes, garb = append k random bytes, 20 seeds)")
    for f in sorted(glob.glob(os.path.join(RES, "p2-*.json"))):
        d = json.load(open(f)); print(f"{d['config']} (record ~{d['rec']} B)")
        for mode in ("trunc", "garb"):
            for k in sorted(d[mode], key=int):
                ts = d[mode][k]
                opens = collections.Counter(t["c1_open"] for t in ts)
                crash = collections.Counter(str(t["rc1"]) for t in ts if t["rc1"] != 0)
                nk = collections.Counter(t["newkey"] for t in ts)
                print(f"  {mode} k={k:>4} n={len(ts)} open={dict(opens)} ok={rng([t.get('c1_ok') for t in ts])}"
                      f" wrong={rng([t.get('c1_wrong') for t in ts])} crash_rc={dict(crash)} newkey_after_reopen={dict(nk)}")
    print("\n## P3 flipped byte in a sealed file (reopen, read all)")
    for f in sorted(glob.glob(os.path.join(RES, "p3-*.json"))):
        d = json.load(open(f)); c = collections.Counter()
        for t in d["trials"]:
            if t["open"] != "OK": c["open:" + t["open"]] += 1
            else: c[f"open=OK ok={t['ok']} wrong={t['wrong']} missing={t['missing']} err={t['err']} {t.get('firsterr', '')}"] += 1
            if t["rc"] != 0: c[f"rc={t['rc']}"] += 1
        print(d["config"], "files", len(d["files"]), "trials", len(d["trials"]))
        for k, v in c.items(): print("   ", v, "x", k)
    print("\n## P3b flipped byte under an open store (read all again)")
    for f in sorted(glob.glob(os.path.join(RES, "p3b-*.json"))):
        d = json.load(open(f))
        c = collections.Counter(re.sub(r'(pos|key) \S+', r'\1 _', t["post"].replace("check [0,1000) ", "")) for t in d["trials"])
        print(os.path.basename(f)[4:-5], dict(c))

if __name__ == "__main__":
    what = sys.argv[2]; names = sys.argv[3:] or list(C)
    if what == "summary":
        summary(); sys.exit(0)
    for c in names:
        if what == "p1":
            p1(c)
            if C[c]["kind"] == "kv": p1(c, True)
        elif what == "p2": p2(c)
        elif what == "p3": p3(c)
        elif what == "p2z": p2z(c)
        elif what == "p3b": p3b(c)
