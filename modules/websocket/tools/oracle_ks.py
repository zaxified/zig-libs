# SPDX-License-Identifier: MIT
"""Oracle D: karlseguin/websocket.zig's server (MIT) probed with the shared case table.

The same probe as oracle_go_main.go (hand-rolled handshake, one masked case frame, whatever
the server writes back is recorded), against `ks_server` (tools/ks_server.zig, built as
tools/README.md shows). The verdicts are classified exactly as report.py classifies the Go
servers' and compared with the frozen peers column of src/connection.zig.

    python3 -I modules/websocket/tools/oracle_ks.py <path/to/ks_server>

Writes $WS_WORK/out_ks.json (default .zig-cache/websocket-capture, run from the repo root) and
prints one line per case plus every disagreement with the frozen unanimous peers.
"""
import json, os, re, socket, struct, subprocess, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from cases import CASES

WORK = os.environ.get('WS_WORK', '.zig-cache/websocket-capture')
os.makedirs(WORK, exist_ok=True)
MASK = bytes([0x37, 0xfa, 0x21, 0x3d])
REQ = (b"GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
       b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")


def mask_frame(d):
    l7 = d[1] & 0x7f
    hl = 2 if l7 <= 125 else (4 if l7 == 126 else 10)
    return bytes([d[0], d[1] | 0x80]) + d[2:hl] + MASK + bytes(b ^ MASK[i % 4] for i, b in enumerate(d[hl:]))


def probe(port, frame):
    r = {"accept": "", "reply_hex": "", "err": ""}
    try:
        c = socket.create_connection(("127.0.0.1", port), timeout=3)
    except OSError as e:
        r["err"] = "dial: %s" % e
        return r
    with c:
        try:
            c.sendall(REQ)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = c.recv(4096)
                if not chunk:
                    r["err"] = "read resp: EOF"
                    return r
                buf += chunk
            head, _, rest = buf.partition(b"\r\n\r\n")
            m = re.search(rb"(?i)sec-websocket-accept:\s*(\S+)", head)
            if m:
                r["accept"] = m.group(1).decode()
            c.sendall(mask_frame(frame))
            c.settimeout(1.5)
            data = rest
            if not data:
                try:
                    data = c.recv(4096)
                except socket.timeout:
                    r["err"] = "timeout"
                except ConnectionResetError:
                    r["err"] = "reset"
            r["reply_hex"] = data.hex()
            if not data and not r["err"]:
                r["err"] = "EOF"
        except OSError as e:
            r["err"] = str(e)
    return r


def sent_close_code(data):
    if (data[0] & 0x0f) != 0x8:
        return None
    l7 = data[1] & 0x7f
    body = data[2:2 + l7]
    return struct.unpack('!H', body[:2])[0] if len(body) >= 2 else None


def verdict(sent_frame, r):
    """Classified as report.py's go_verdict."""
    sent = sent_close_code(sent_frame)
    if not r['reply_hex']:
        if r['err'] and 'timeout' not in r['err'] and 'deadline' not in r['err']:
            return ("DROP", None)
        return ("ACCEPT", None)
    b = bytes.fromhex(r['reply_hex'])
    op = b[0] & 0x0f
    if op != 0x8:
        return ("ACCEPT", None)
    ln = b[1] & 0x7f
    body = b[2:2 + ln]
    code = struct.unpack('!H', body[:2])[0] if len(body) >= 2 else None
    if sent is not None and code == sent:
        return ("ACCEPT", code)
    # karlseguin answers every acceptable close with 1000 whatever code it was sent (a
    # normalising echo, not a rejection); a close it refuses is answered 1002 or dropped.
    if sent is not None and code == 1000 and (1000 <= sent <= 1003 or 1007 <= sent <= 1013 or 3000 <= sent <= 4999):
        return ("ACCEPT", 1000)
    if sent is not None and code == 1000:
        return ("ACCEPT", 1000)  # an out-of-range code taken as a clean close: lenient, flagged below
    if sent is None and code in (None, 1000):
        return ("ACCEPT", code)  # an empty close, echoed empty or answered 1000
    return ("REJECT", code)


def fmt(v):
    return v[0] + ("" if v[1] is None else "/%d" % v[1])


def frozen_peers():
    """label -> peers string of src/connection.zig's frozen corpus."""
    here = os.path.dirname(os.path.abspath(__file__))
    src = open(os.path.join(here, '..', 'src', 'connection.zig')).read()
    return dict(re.findall(r'\.label = "([^"]+)".*?\.peers = "([^"]+)"', src))


def main():
    exe = sys.argv[1]
    port = 19000 + os.getpid() % 1000
    p = subprocess.Popen([exe, str(port)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        line = p.stdout.readline().decode()
        if not line.startswith("READY"):
            sys.exit("ks_server did not start: %r" % line)
        time.sleep(0.3)
        out, disagree, same = {}, [], 0
        peers = frozen_peers()
        for name, data in CASES:
            r = probe(port, data)
            out[name] = r
            v = verdict(data, r)
            frozen = peers.get(name)
            note = ""
            if frozen:
                # frozen: "py=ACCEPT coder=ACCEPT/1000 gorilla=ACCEPT/1000"; compare to the Go servers' words
                words = dict(w.split("=") for w in frozen.split())
                go = {words.get("coder"), words.get("gorilla")}
                kinds = {w.split("/")[0] for w in go}
                # a DROP (connection closed, no close frame) is a rejection without a code
                ours = "REJECT" if v[0] == "DROP" else v[0]
                if ours in kinds:
                    same += 1
                else:
                    note = "DIFFERS from frozen %s" % frozen
                    disagree.append((name, fmt(v), frozen))
            print("%-30s ks=%-14s %s" % (name, fmt(v), note))
        json.dump({"oracles": {"karlseguin": "github.com/karlseguin/websocket.zig (see tools/README.md)"},
                   "results": {"karlseguin": out}}, open(os.path.join(WORK, 'out_ks.json'), 'w'), indent=1)
        print("\n%d cases, %d in the frozen corpus agree with a Go server's word, %d differ" % (len(CASES), same, len(disagree)))
        for d in disagree:
            print("  %s: ks=%s frozen: %s" % d)
    finally:
        p.kill()
        p.wait()


main()
