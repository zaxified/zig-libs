#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""argsafe foreign oracles: what real parsers say about the strings we may accept.

    oracle.py gen OUT.zig     build the corpus, take every foreign verdict, write the Zig vectors
    oracle.py kernel          (internal, runs inside `unshare -rn`) hex strings on stdin -> 0/1 each

Per corpus string the vectors carry five foreign verdicts (bit set = the foreign side
accepts / reads it as one plain word):

    SHELL   POSIX sh: Python shlex.split(posix) == [s]  AND  dash -c 'set -- S' sees one
            word equal to S, in a directory holding files named a Z 0 x (so a glob
            character would expand), PATH empty (only builtins can run). No namespace:
            cwd is a fresh temp directory and the corpus names no real path.
    WIN     CommandLineToArgvW / UCRT rules (backslash-before-quote, quote toggling,
            `""` inside quotes) transcribed from the Microsoft documentation, run on
            'prog ' + S: must give exactly ['prog', S]. A transcription, not a Windows run.
    GOHOST  go-playground/validator v10.30.5 `hostname_rfc1123`      (tools/go_oracle)
    GOPORT  go-playground/validator v10.30.5 `hostname_port` on ":" + S: its ParseInt 1..65535
    KERNEL  Linux dev_valid_name through the SIOCSIFNAME rename ioctl of a dummy link
            (a 16+ byte name cannot even be written into struct ifreq: refused)

src/oracle_vectors.zig is replayed by src/oracle_test.zig in the module's own lane; no
namespace, no Go, no shell is needed there. Needs python3, dash, ip, unshare, go 1.26 with
validator v10.30.5 in the module cache (GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off).
Nothing outside this directory and the output file is touched; the corpus is seeded.
"""
import fcntl
import os
import random
import shlex
import socket
import struct
import subprocess
import sys
import tempfile

SHELL, WIN, GOHOST, GOPORT, KERNEL = 1, 2, 4, 8, 16
HERE = os.path.dirname(os.path.abspath(__file__))

HOSTILE = [b' ', b'\t', b'\n', b'\r', b'"', b"'", b'`', b'\\', b'$', b';', b'&', b'|', b'*',
           b'?', b'[', b']', b'{', b'}', b'<', b'>', b'(', b')', b'~', b'#', b'!', b'%', b'^',
           b'=', b',', b':', b'/', b'@', b'+', b'-', b'.', b'_', b'\x7f', b'\x00', b'\x1b',
           b'\xc3\xa9', b'\xff', b'\x80', b'..', b'--', b'-x', b'0', b'a', b'Z']
ALNUM = b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'


def corpus():
    rnd = random.Random(0x41524753)  # "ARGS"
    out = set()

    def add(b):
        out.add(bytes(b))

    # every string of 0..2 hostile/short atoms
    for a in HOSTILE:
        add(a)
        for b in HOSTILE:
            add(a + b)
    add(b'')

    def label(n=None):
        n = n or rnd.choice([1, 1, 2, 3, 5, 8, 20, 62, 63, 64, 65])
        return bytes(rnd.choice(ALNUM + b'--') for _ in range(n))

    def mutate(b):
        b = bytearray(b)
        for _ in range(rnd.choice([0, 1, 1, 2])):
            h = rnd.choice(HOSTILE)
            p = rnd.randint(0, len(b))
            k = rnd.random()
            if k < 0.4:
                b[p:p] = h
            elif k < 0.8 and b:
                p = min(p, len(b) - 1)
                b[p:p + 1] = h
            elif b:
                del b[min(p, len(b) - 1)]
        return bytes(b)

    seeds = []
    for _ in range(500):  # host names, incl. length edges
        k = rnd.choice([1, 1, 2, 3, 4, 20])
        seeds.append(b'.'.join(label() for _ in range(k)))
    seeds.append(b'.'.join([b'a' * 63] * 3 + [b'b' * 61]))   # 253 bytes
    seeds.append(b'.'.join([b'a' * 63] * 3 + [b'b' * 62]))   # 254 bytes
    for v in (b'0', b'1', b'80', b'443', b'8080', b'65535', b'65536', b'00080', b'08', b'+80',
              b'-1', b'0x50', b'80 ', b' 80', b'1_000', b'99999', b'123456', b'18446744073709551615',
              b'18446744073709551616', b'99999999999999999999', b'\xef\xbc\x98\xef\xbc\x90'):
        seeds.append(v)
    for _ in range(150):
        seeds.append(str(rnd.choice([rnd.randint(0, 70000), rnd.randint(0, 99)])).encode())
    for _ in range(250):  # interface names
        n = rnd.choice([1, 2, 3, 6, 14, 15, 16, 17])
        seeds.append(bytes(rnd.choice(ALNUM + b'._-' * 2) for _ in range(n)))
    for v in (b'eth0', b'eth0.100', b'br-lan', b'wg0', b'lo', b'.', b'..', b'a..b', b'a/b', b'a:b',
              b'a b', b'a' * 15, b'a' * 16, b'-a', b'_a', b'a@b', b'1234567890abcde',
              b'1234567890abcdef'):
        seeds.append(v)
    for _ in range(120):  # identifiers, base64, cidr lists, kv, paths, urls
        seeds.append(bytes(rnd.choice(ALNUM + b'_-') for _ in range(rnd.randint(1, 20))))
        seeds.append(bytes(rnd.choice(ALNUM + b'+/=') for _ in range(rnd.randint(1, 20))))
        seeds.append(b','.join(bytes(rnd.choice(b'0123456789abcdef.:') for _ in range(rnd.randint(1, 8))) + b'/' +
                               str(rnd.randint(0, 128)).encode() for _ in range(rnd.randint(1, 3))))
        seeds.append(b'/' + b'/'.join(label(rnd.randint(1, 6)) for _ in range(rnd.randint(1, 3))))
        seeds.append(b'https://' + label(rnd.randint(1, 8)) + b'.example/' + label(rnd.randint(0, 5)))
        seeds.append(bytes(rnd.choice(ALNUM + b'.:/_- ') for _ in range(rnd.randint(1, 15))))
    for s in seeds:
        add(s)
        for _ in range(2):
            add(mutate(s))
    return sorted(out)


def win_one_arg(s):
    """True iff 'prog ' + s parses to exactly ['prog', s] under the UCRT rules."""
    if b'\x00' in s:
        return False
    line = b'prog ' + s
    args, i, n = [], 0, len(line)
    while i < n:
        while i < n and line[i] in b' \t':
            i += 1
        if i >= n:
            break
        cur, inq, started = bytearray(), False, True
        while i < n:
            c = line[i]
            if c == 0x5c:
                j = i
                while j < n and line[j] == 0x5c:
                    j += 1
                k = j - i
                if j < n and line[j] == 0x22:
                    cur += b'\\' * (k // 2)
                    if k % 2:
                        cur += b'"'
                        i = j + 1
                    else:
                        i = j  # the quote is handled below as a toggle
                else:
                    cur += b'\\' * k
                    i = j
                continue
            if c == 0x22:
                if inq and i + 1 < n and line[i + 1] == 0x22:
                    cur += b'"'
                    i += 2
                    continue
                inq = not inq
                i += 1
                continue
            if c in b' \t' and not inq:
                break
            cur.append(c)
            i += 1
        args.append(bytes(cur))
    return args == [b'prog', s]


def shell_word(s, shdir):
    if b'\x00' in s:
        return False
    try:
        if shlex.split(s.decode('latin-1'), posix=True) != [s.decode('latin-1')]:
            return False
    except ValueError:
        return False
    script = b'set -- ' + s + b'\n[ "$#" -eq 1 ] && printf %s "$1"'
    try:
        r = subprocess.run(['/usr/bin/dash', '-c', script], cwd=shdir, env={'PATH': ''},
                           capture_output=True, timeout=5)
    except subprocess.TimeoutExpired:
        return False
    return r.returncode == 0 and r.stdout == s


def go_verdicts(corp):
    env = dict(os.environ, GOFLAGS='-mod=mod', GOPROXY='off', GOSUMDB='off')
    inp = ''.join(c.hex() + '\n' for c in corp)
    r = subprocess.run(['go', 'run', '.'], cwd=os.path.join(HERE, 'go_oracle'), env=env,
                       input=inp, capture_output=True, text=True, check=True, timeout=600)
    lines = r.stdout.split('\n')[:-1]
    assert len(lines) == len(corp)
    return [tuple(int(x) for x in ln.split()) for ln in lines]


def kernel_inner():
    subprocess.run(['ip', 'link', 'add', 'x0', 'type', 'dummy'], check=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    cur = b'x0'
    out = []
    for ln in sys.stdin.read().split('\n')[:-1]:
        s = bytes.fromhex(ln)
        ok = 0
        if 0 < len(s) < 16 and b'\x00' not in s:
            req = struct.pack('16s16s', cur, s)
            try:
                fcntl.ioctl(sock, 0x8923, req)  # SIOCSIFNAME
                ok, cur = 1, s
            except OSError as e:
                # EEXIST: the name is valid but taken (lo, x0, an earlier rename)
                ok = 1 if e.errno == 17 else 0
        out.append(str(ok))
    print('\n'.join(out))


def kernel_verdicts(corp):
    inp = ''.join(c.hex() + '\n' for c in corp)
    r = subprocess.run(['unshare', '-rn', sys.executable, os.path.abspath(__file__), 'kernel'],
                       input=inp, capture_output=True, text=True, check=True, timeout=600)
    v = [int(x) for x in r.stdout.split()]
    assert len(v) == len(corp)
    return v


def shell_verdicts(corp):
    with tempfile.TemporaryDirectory(prefix='argsafe-sh') as d:
        for f in ('a', 'Z', '0', 'x'):
            open(os.path.join(d, f), 'w').close()
        # the whole batch inside a network-less user namespace is not needed for dash
        # itself (PATH is empty, cwd holds four empty files); keep it simple and local.
        return [shell_word(s, d) for s in corp]


def main():
    if sys.argv[1:2] == ['kernel']:
        return kernel_inner()
    if sys.argv[1:2] != ['gen'] or len(sys.argv) != 3:
        sys.exit(__doc__)
    corp = corpus()
    sh = shell_verdicts(corp)
    go = go_verdicts(corp)
    kn = kernel_verdicts(corp)
    rows = []
    for i, s in enumerate(corp):
        f = (SHELL if sh[i] else 0) | (WIN if win_one_arg(s) else 0) | (GOHOST if go[i][0] else 0) \
            | (GOPORT if go[i][1] else 0) | (KERNEL if kn[i] else 0)
        rows.append((s, f))
    with open(sys.argv[2], 'w') as o:
        o.write('// SPDX-License-Identifier: MIT\n'
                '// GENERATED by tools/oracle.py gen -- do not edit. Foreign verdicts per corpus string:\n'
                '// bit 1 SHELL, 2 WIN, 4 GOHOST, 8 GOPORT, 16 KERNEL (see the script header).\n'
                'pub const Vec = struct { h: []const u8, f: u8 };\n'
                'pub const vectors = [_]Vec{\n')
        for s, f in rows:
            o.write('    .{ .h = "%s", .f = %d },\n' % (s.hex(), f))
        o.write('};\n')
    print('%d vectors: shell %d win %d gohost %d goport %d kernel %d' % (
        len(rows), sum(1 for _, f in rows if f & SHELL), sum(1 for _, f in rows if f & WIN),
        sum(1 for _, f in rows if f & GOHOST), sum(1 for _, f in rows if f & GOPORT),
        sum(1 for _, f in rows if f & KERNEL)))


main()
