# SPDX-License-Identifier: MIT
"""Damaged-file driver for the kvtree / bbolt / LMDB probes (backs the kvtree
"never crashes on a damaged file" **Ahead:** claim).

usage: python3 -I run.py WORKDIR M [sides]

WORKDIR holds bin/<side> (the probe executables) and base/<side> (pristine
stores made by `<probe> build`). Trial i of mode m on side s is a pure
function of the seed "w9-<s>-<m>-<i>": copy the pristine file, flip 1..8
random bytes (mode "page": inside one random used page >= 2; mode "file":
anywhere), run `<probe> check` in a fresh process (5 s timeout, hang = PANIC)
and classify by exit code. Prints one table row per (side, mode).
"""
import json, os, random, shutil, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

W = os.path.abspath(sys.argv[1])
M = int(sys.argv[2])
sides = (sys.argv[3] if len(sys.argv) > 3 else 'kvtree,kvtree-mmap,bbolt,lmdb').split(',')
# kvtree-mmap: the same binary, store and damage as kvtree (seeds included),
# read through `FsStorage.initMmap`.
SIDES = {
    'kvtree': dict(f='t.db', lock=True),
    'kvtree-mmap': dict(f='t.db', lock=True, bin='kvtree', base='kvtree', check='check-mmap', seed='kvtree'),
    'bbolt': dict(f='t.db', lock=False),
    'lmdb': dict(f='t.mdb', lock=False),
}
PS = 4096
CLASSES = ('CLEAN', 'WRONG-value', 'WRONG-struct', 'ERROR', 'PANIC')


def used_pages(path):
    with open(path, 'rb') as fh:
        d = fh.read()
    return [p for p in range(2, len(d) // PS) if any(d[p * PS:(p + 1) * PS])], len(d)


def classify(rc, timed_out):
    if timed_out:
        return 'PANIC'
    return {0: 'CLEAN', 10: 'WRONG', 11: 'ERROR'}.get(rc, 'PANIC')


def trial(side, mode, i, base, used, size):
    cfg = SIDES[side]
    rng = random.Random(f'w9-{cfg.get("seed", side)}-{mode}-{i}')
    td = f'{W}/trials/{side}-{mode}-{i}'
    os.makedirs(td, exist_ok=True)
    try:
        shutil.copy(f'{base}/{cfg["f"]}', f'{td}/{cfg["f"]}')
        if cfg['lock']:
            open(f'{td}/t.db.lock', 'w').close()
        with open(f'{td}/{cfg["f"]}', 'rb') as fh:
            data = bytearray(fh.read())
        nflip = rng.randint(1, 8)
        if mode == 'page':
            lo = rng.choice(used) * PS
            hi = lo + PS
        else:
            lo, hi = 0, size
        for _ in range(nflip):
            p = rng.randrange(lo, hi)
            data[p] ^= rng.randint(1, 255)
        with open(f'{td}/{cfg["f"]}', 'wb') as fh:
            fh.write(data)
        pr = subprocess.Popen([f'{W}/bin/{cfg.get("bin", side)}', cfg.get('check', 'check'), td], stdout=subprocess.DEVNULL,
                              stderr=subprocess.PIPE, start_new_session=True)
        timed_out = False
        try:
            _, err = pr.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            timed_out = True
            try:
                os.killpg(pr.pid, 9)
            except OSError:
                pass
            _, err = pr.communicate()
        cls = classify(pr.returncode, timed_out)
        if cls == 'WRONG':
            cls = 'WRONG-value' if b'value-only' in err else 'WRONG-struct'
        return dict(side=side, mode=mode, seed=i, cls=cls, rc=pr.returncode, hang=timed_out)
    finally:
        for f in os.listdir(td):
            os.remove(os.path.join(td, f))
        os.rmdir(td)


def main():
    lock = threading.Lock()
    t0 = time.time()
    counts = {}
    with open(f'{W}/results.jsonl', 'w') as out:
        for side in sides:
            base = f'{W}/base/{SIDES[side].get("base", side)}'
            used, size = used_pages(f'{base}/{SIDES[side]["f"]}')
            print(f'{side}: file {size} bytes, {len(used)} used non-meta pages', flush=True)
            for mode in ('page', 'file'):
                c = counts[(side, mode)] = dict.fromkeys(CLASSES, 0)

                def job(i):
                    rec = trial(side, mode, i, base, used, size)
                    with lock:
                        out.write(json.dumps(rec) + '\n')
                        c[rec['cls']] += 1

                with ThreadPoolExecutor(4) as ex:
                    list(ex.map(job, range(M)))
                print(f'done {side}/{mode} t={int(time.time() - t0)}s', flush=True)
    print(f'\nM = {M} per cell')
    print('| store | mode | ' + ' | '.join(CLASSES) + ' |')
    print('|---|---|' + '---:|' * len(CLASSES))
    for (side, mode), c in counts.items():
        print(f'| {side} | {mode} | ' + ' | '.join(str(c[k]) for k in CLASSES) + ' |')
    for side in sides:
        n = sum(counts[(side, m)]['PANIC'] for m in ('page', 'file'))
        print(f'PANIC {side}: {n}/{2 * M}')


main()
