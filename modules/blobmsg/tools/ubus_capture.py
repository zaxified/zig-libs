#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Capture the wire of a REAL `ubusd` talking to the real `ubus` CLI (and to a small
scripted provider), and freeze it as `src/testdata/ubusd_capture.zig`.

The daemon and the CLI are the black-box binaries from the reviewed foreign build
(`ubus` is LGPL-2.1: its source is never read, behaviour comes only from running it;
see the module NOTICE). Everything runs on a private socket inside the droppable
`.zig-cache`, under a watchdog, and is torn down at the end. Run it through `hw`:

    hw run --mem 2G --name bm-capture -- python3 modules/blobmsg/tools/ubus_capture.py \\
        --out modules/blobmsg/src/testdata/ubusd_capture.zig

    UBUS_BIN=<dir with ubusd and ubus>   (default: ~/workspace/zig-libs/.zig-cache/foreign-build/out)
    --explore            print every captured frame decoded instead of writing the file
    unshare -r python3 ubus_capture.py --with-daemon -- CMD...
                         start a private ubusd, run CMD with BLOBMSG_UBUS_SOCKET=<its socket>
                         (the live integration tests of src/root.zig), tear the daemon down

Why `unshare -r`: an ordinary user is refused by ubusd for event registration and object
publishing (STATUS 6 / 2), the daemon only allows root without ACL files, and a router's ubus
clients are root. The user namespace maps us to uid 0 with no privilege on the host; the
refusals themselves are captured too (the `denied_*` captures run without it).

Every scenario starts its own fresh daemon, so ids are whatever that daemon chose;
the Zig tests never assert a daemon-chosen id, only frame shapes and the bytes
that are independent of it.
"""
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

ACL = bool(os.environ.get("ACL"))
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../../.."))
BIN = os.environ.get("UBUS_BIN", os.path.expanduser("~/workspace/zig-libs/.zig-cache/foreign-build/out"))
# Short names: a unix socket path holds 107 bytes and the worktree path is long.
WORK = os.path.join(ROOT, ".zig-cache", "bc")

MSG = {0: "HELLO", 1: "STATUS", 2: "DATA", 3: "PING", 4: "LOOKUP", 5: "INVOKE", 6: "ADD_OBJECT",
       7: "REMOVE_OBJECT", 8: "SUBSCRIBE", 9: "UNSUBSCRIBE", 10: "NOTIFY", 11: "MONITOR"}
ATTR = {1: "STATUS", 2: "OBJPATH", 3: "OBJID", 4: "METHOD", 5: "OBJTYPE", 6: "SIGNATURE", 7: "DATA",
        8: "TARGET", 9: "ACTIVE", 10: "NO_REPLY", 11: "SUBSCRIBERS", 12: "USER", 13: "GROUP",
        14: "SEQ"}
A = {v: k for k, v in ATTR.items()}
M = {v: k for k, v in MSG.items()}


# ---- blob helpers (our own, from the documented format) -------------------------------------

def pad4(n):
    return (n + 3) & ~3


def attr(aid, data, ext=False):
    n = 4 + len(data)
    head = struct.pack(">I", (0x80000000 if ext else 0) | (aid << 24) | n)
    return head + data + b"\0" * (pad4(n) - n)


def attr_u32(aid, v):
    return attr(aid, struct.pack(">I", v & 0xFFFFFFFF))


def attr_i32(aid, v):
    return attr(aid, struct.pack(">i", v))


def attr_str(aid, s):
    return attr(aid, s.encode() + b"\0")


def bm(btype, name, data):
    nb = name.encode()
    hdr = struct.pack(">H", len(nb)) + nb + b"\0"
    hdr += b"\0" * (pad4(len(hdr)) - len(hdr))  # the value starts 4-byte aligned
    return attr(btype, hdr + data, ext=True)


def bm_str(name, s):
    return bm(3, name, s.encode() + b"\0")


def bm_i32(name, v):
    return bm(5, name, struct.pack(">I", v & 0xFFFFFFFF))


def bm_table(name, children):
    return bm(2, name, b"".join(children))


def msg(mtype, seq, peer, children=b""):
    top = attr(0, children)
    return struct.pack(">BBHI", 0, mtype, seq, peer) + top


def walk(buf):
    out = []
    i = 0
    while i + 4 <= len(buf):
        v = struct.unpack(">I", buf[i:i + 4])[0]
        n = v & 0xFFFFFF
        if n < 4 or i + n > len(buf):
            out.append(("BAD", buf[i:].hex()))
            break
        out.append(((v >> 24) & 0x7F, bool(v >> 31), buf[i + 4:i + n]))
        i += pad4(n)
    return out


def describe(frame):
    ver, t, seq, peer = struct.unpack(">BBHI", frame[:8])
    ch = walk(frame[12:])
    parts = []
    for c in ch:
        if c[0] == "BAD":
            parts.append("BAD " + c[1])
            continue
        aid, ext, d = c
        nm = ATTR.get(aid, str(aid))
        if aid in (A["STATUS"], A["OBJID"], A["ACTIVE"], A["NO_REPLY"], A["SUBSCRIBERS"], A["TARGET"]) and len(d) == 4:
            parts.append("%s=%d" % (nm, struct.unpack(">I", d)[0]))
        elif aid in (A["OBJPATH"], A["METHOD"]):
            parts.append("%s=%r" % (nm, d.rstrip(b"\0").decode("latin1")))
        else:
            parts.append("%s[%dB]" % (nm, len(d)))
    return "%s seq=%d peer=0x%x { %s }" % (MSG.get(t, str(t)), seq, peer, ", ".join(parts))


class Framer:
    def __init__(self):
        self.buf = b""

    def feed(self, data):
        self.buf += data
        out = []
        while len(self.buf) >= 12:
            n = struct.unpack(">I", self.buf[8:12])[0] & 0xFFFFFF
            if len(self.buf) < 8 + n:
                break
            out.append(self.buf[:8 + n])
            self.buf = self.buf[8 + n:]
        return out


# ---- the daemon, the relay, the clients -------------------------------------------------------

ACL_ALL = """{
  "user": "*",
  "publish": ["*"],
  "subscribe": ["*"],
  "send": ["*"],
  "listen": ["*"],
  "access": { "*": { "methods": ["*"] } }
}
"""


def make_acl_dir(name):
    """A private ACL directory inside WORK (never a system one) that lets every user do everything."""
    d = os.path.join(WORK, "acl-" + name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "all.json"), "w") as f:
        f.write(ACL_ALL)
    return d


class Daemon:
    def __init__(self, name, acl=False):
        os.makedirs(WORK, exist_ok=True)
        self.sock = os.path.join(WORK, name + ".sock")
        if os.path.exists(self.sock):
            os.unlink(self.sock)
        extra = []
        if acl:
            extra = ["-A", make_acl_dir(name)]
        self.p = subprocess.Popen([os.path.join(BIN, "ubusd"), "-s", self.sock] + extra, start_new_session=True,
                                  stdout=subprocess.DEVNULL, stderr=open(os.path.join(WORK, name + ".log"), "w"))
        for _ in range(100):
            if os.path.exists(self.sock):
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("ubusd did not come up")

    def stop(self):
        try:
            os.killpg(self.p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.p.wait()
        if os.path.exists(self.sock):
            os.unlink(self.sock)


class Relay:
    """A byte relay in front of the daemon that records every chunk per connection."""

    def __init__(self, daemon):
        self.d = daemon
        self.path = daemon.sock + "x"
        if os.path.exists(self.path):
            os.unlink(self.path)
        self.ls = socket.socket(socket.AF_UNIX)
        self.ls.bind(self.path)
        self.ls.listen(16)
        self.log = []  # (t, conn, dir, bytes)
        self.lock = threading.Lock()
        self.nconn = 0
        self.stop = False
        self.threads = [threading.Thread(target=self.accept, daemon=True)]
        self.threads[0].start()

    def accept(self):
        while not self.stop:
            try:
                c, _ = self.ls.accept()
            except OSError:
                return
            u = socket.socket(socket.AF_UNIX)
            u.connect(self.d.sock)
            with self.lock:
                self.nconn += 1
                n = self.nconn
            for a, b, d in ((c, u, "c2d"), (u, c, "d2c")):
                t = threading.Thread(target=self.pump, args=(a, b, n, d), daemon=True)
                t.start()
                self.threads.append(t)

    def pump(self, a, b, n, d):
        while True:
            try:
                data = a.recv(65536)
            except OSError:
                data = b""
            if not data:
                try:
                    b.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return
            with self.lock:
                self.log.append((time.monotonic(), n, d, data))
            try:
                b.sendall(data)
            except OSError:
                return

    def frames(self):
        """[(conn, dir, frame)] in arrival order."""
        fr = {}
        out = []
        with self.lock:
            log = list(self.log)
        for _, n, d, data in log:
            f = fr.setdefault((n, d), Framer())
            for x in f.feed(data):
                out.append((n, d, x))
        return out

    def close(self):
        self.stop = True
        try:
            self.ls.close()
        except OSError:
            pass
        if os.path.exists(self.path):
            os.unlink(self.path)


def recv_frame(s, timeout=3.0):
    s.settimeout(timeout)
    hdr = b""
    while len(hdr) < 12:
        c = s.recv(12 - len(hdr))
        if not c:
            return None
        hdr += c
    n = struct.unpack(">I", hdr[8:12])[0] & 0xFFFFFF
    body = b""
    while len(body) < n - 4:
        c = s.recv(n - 4 - len(body))
        if not c:
            return None
        body += c
    return hdr + body


def children(frame):
    return walk(frame[12:])


def get(frame, aid):
    r = None
    for c in children(frame):
        if c[0] != "BAD" and c[0] == aid:
            r = c[2]
    return r


def connect(path):
    s = socket.socket(socket.AF_UNIX)
    s.connect(path)
    h = recv_frame(s)
    assert h and h[1] == 0, "no HELLO"
    return s, struct.unpack(">I", h[4:8])[0]


class Provider:
    """A tiny scripted object provider ("probe" with methods echo/fail) over a raw socket."""

    def __init__(self, path, name="probe"):
        self.s, self.cid = connect(path)
        sig = bm_table("echo", [bm_i32("msg", 3)]) + bm_table("fail", []) + bm_table("slow", []) + bm_table("notify", [])
        add = attr_str(A["OBJPATH"], name) + attr(A["SIGNATURE"], sig)
        self.s.sendall(msg(M["ADD_OBJECT"], 1, 0, add))
        self.replies = []
        self.oid = None
        while True:
            f = recv_frame(self.s)
            self.replies.append(f)
            o = get(f, A["OBJID"])
            if o:
                self.oid = struct.unpack(">I", o)[0]
            if f[1] == M["STATUS"]:
                break
        self.stop = False
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    def loop(self):
        while not self.stop:
            try:
                f = recv_frame(self.s, 0.2)
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                return
            if f is None:
                return
            self.replies.append(f)
            t = f[1]
            seq = struct.unpack(">H", f[2:4])[0]
            peer = struct.unpack(">I", f[4:8])[0]
            if t == M["INVOKE"]:
                meth = (get(f, A["METHOD"]) or b"").rstrip(b"\0").decode()
                data = get(f, A["DATA"]) or b""
                if meth == "echo":
                    self.s.sendall(msg(M["DATA"], seq, peer, attr_u32(A["OBJID"], self.oid) + attr(A["DATA"], data)))
                    self.s.sendall(msg(M["STATUS"], seq, peer, attr_i32(A["STATUS"], 0) + attr_u32(A["OBJID"], self.oid)))
                elif meth == "slow":
                    time.sleep(1.5)
                    self.s.sendall(msg(M["DATA"], seq, peer, attr_u32(A["OBJID"], self.oid) + attr(A["DATA"], data)))
                    self.s.sendall(msg(M["STATUS"], seq, peer, attr_i32(A["STATUS"], 0) + attr_u32(A["OBJID"], self.oid)))
                elif meth == "notify":
                    self.s.sendall(msg(M["STATUS"], seq, peer, attr_i32(A["STATUS"], 0) + attr_u32(A["OBJID"], self.oid)))
                    self.notify("tick", bm_i32("n", 5) + bm_str("s", "v"), seq=40)
                else:
                    self.s.sendall(msg(M["STATUS"], seq, peer, attr_i32(A["STATUS"], 9) + attr_u32(A["OBJID"], self.oid)))

    def notify(self, typ, data_children, seq=7):
        self.s.sendall(msg(M["NOTIFY"], seq, 0, attr_u32(A["OBJID"], self.oid) + attr_str(A["METHOD"], typ) +
                           attr(A["DATA"], data_children)))

    def close(self):
        self.stop = True
        self.s.close()


def run_cli(args, sock, timeout=4):
    """The real ubus CLI against `sock`; returns (rc, stdout, stderr)."""
    p = subprocess.Popen([os.path.join(BIN, "ubus"), "-s", sock] + args, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, start_new_session=True)
    try:
        o, e = p.communicate(timeout=timeout)
        return p.returncode, o.decode(errors="replace"), e.decode(errors="replace")
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        o, e = p.communicate()
        return "timeout", o.decode(errors="replace"), e.decode(errors="replace")


def spawn_cli(args, sock):
    return subprocess.Popen([os.path.join(BIN, "ubus"), "-s", sock] + args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, start_new_session=True)


def kill_cli(p):
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    o, e = p.communicate()
    return o.decode(errors="replace"), e.decode(errors="replace")


# ---- scenarios --------------------------------------------------------------------------------
# A scenario returns {name: {"cli": [rc, stdout, stderr] | None, "frames": [(conn, dir, bytes)]}}.

def snap(r, cli=None):
    return {"cli": list(cli) if cli else None, "frames": [(n, d, bytes(f)) for n, d, f in r.frames()]}


def inner_scenarios():
    """Everything that needs a privileged peer (see the module docstring on `unshare -r`)."""
    out = {}
    d = Daemon("a")
    r = Relay(d)
    try:
        prov = Provider(r.path)
        out["provider_add_object"] = {"cli": None, "frames": [(1, "d2c", bytes(f)) for f in prov.replies[:2]]}
        steps = (
            ("lookup_all", ["list"]),
            ("lookup_nomatch", ["list", "nosuch"]),
            ("lookup_match", ["-S", "list", "probe"]),
            ("call_echo", ["-S", "call", "probe", "echo", '{"msg":"hi"}']),
            ("call_fail", ["call", "probe", "fail"]),
            ("call_noobj", ["call", "nosuch", "x"]),
            ("call_t0_slow", ["-t", "0", "call", "probe", "slow", '{"msg":"s"}']),
            ("call_t1_slow", ["-t", "1", "call", "probe", "slow", '{"msg":"s"}']),
            ("subscribe_nosuch", ["-t", "1", "subscribe", "nosuch"]),
            ("wait_for", ["-t", "2", "wait_for", "probe"]),
            ("send_no_listener", ["send", "foo", '{"a":1}']),
        )
        for name, args in steps:
            r.log.clear()
            res = run_cli(args, r.path, timeout=6)
            out[name] = snap(r, res)
        prov.close()
    finally:
        r.close()
        d.stop()

    d = Daemon("b")
    r = Relay(d)
    try:
        lp = spawn_cli(["listen", "*"], r.path)
        time.sleep(0.6)
        out["listen_register"] = snap(r)
        r.log.clear()
        res = run_cli(["send", "foo", '{"a":1,"b":"x"}'], r.path)
        time.sleep(0.5)
        out["send_to_listener"] = snap(r, res)
        o, e = kill_cli(lp)
        out["send_to_listener"]["listen_stdout"] = o
    finally:
        r.close()
        d.stop()

    d = Daemon("c")
    r = Relay(d)
    try:
        prov = Provider(r.path)
        r.log.clear()
        sp = spawn_cli(["-t", "5", "subscribe", "probe"], r.path)
        time.sleep(0.8)
        out["subscribe_setup"] = snap(r)
        n_before = len(prov.replies)
        r.log.clear()
        prov.notify("tick", bm_i32("n", 5) + bm_str("s", "v"))
        time.sleep(0.5)
        out["subscribe_notify"] = snap(r)
        r.log.clear()
        prov.notify("tock", bm_str("k", "w"), seq=8)
        time.sleep(0.4)
        out["subscribe_notify2"] = snap(r)
        r.log.clear()
        prov.close()  # the target goes away while subscribed
        time.sleep(0.5)
        out["subscribe_target_gone"] = snap(r)
        o, e = kill_cli(sp)
        out["subscribe_target_gone"]["cli"] = [None, o, e]
    finally:
        r.close()
        d.stop()

    d = Daemon("d")
    r = Relay(d)
    try:
        prov = Provider(r.path)
        r.log.clear()
        mp = spawn_cli(["monitor"], r.path)
        time.sleep(0.6)
        run_cli(["call", "probe", "echo", '{"msg":"hi"}'], d.sock)
        run_cli(["list", "probe"], d.sock)
        time.sleep(0.5)
        out["monitor"] = snap(r)
        o, e = kill_cli(mp)
        out["monitor"]["cli"] = [None, o, e]
        prov.close()
    finally:
        r.close()
        d.stop()
    return out


def outer_scenarios():
    """The daemon and the CLI as an ordinary user: no root, no ACL files -> the daemon refuses."""
    out = {}
    d = Daemon("o")
    r = Relay(d)
    try:
        r.log.clear()
        out["denied_listen"] = snap(r, run_cli(["listen", "*"], r.path))
        r.log.clear()
        out["denied_send"] = snap(r, run_cli(["send", "foo", '{"a":1}'], r.path))
        s, _ = connect(r.path)
        r.log.clear()
        s.sendall(msg(M["ADD_OBJECT"], 1, 0, attr_str(A["OBJPATH"], "probe")))
        out["denied_add_named"] = {"cli": None, "frames": [(9, "d2c", recv_frame(s))]}
        s.close()
    finally:
        r.close()
        d.stop()
    return out


# ---- the Zig file -------------------------------------------------------------------------------

def zstr(s):
    out = '"'
    for b in s.encode():
        if b == 0x22:
            out += '\\"'
        elif b == 0x5C:
            out += "\\\\"
        elif b == 0x0A:
            out += "\\n"
        elif b == 0x09:
            out += "\\t"
        elif 0x20 <= b < 0x7F:
            out += chr(b)
        else:
            out += "\\x%02x" % b
    return out + '"'


def write_zig(allres, path):
    o = [
        "// SPDX-License-Identifier: MIT",
        "// Generated by modules/blobmsg/tools/ubus_capture.py from a REAL ubusd and the real `ubus` CLI",
        "// (black boxes, run never read), through a recording byte relay. Do not edit by hand.",
        "// Ids the daemon chose (client ids, object ids, type ids) differ per run: tests never assert them.",
        "",
        "pub const Dir = enum { c2d, d2c };",
        "pub const Frame = struct { conn: u8, dir: Dir, hex: []const u8 };",
        "pub const Capture = struct {",
        "    name: []const u8,",
        "    /// Exit code, stdout and stderr of the real `ubus` CLI run of this step (rc 0 and empty for none).",
        "    cli_stdout: []const u8,",
        "    cli_stderr: []const u8,",
        "    frames: []const Frame,",
        "};",
        "",
        "pub const captures = [_]Capture{",
    ]
    for name in sorted(allres):
        v = allres[name]
        cli = v.get("cli") or [None, "", ""]
        so = v.get("listen_stdout", cli[1])
        o.append("    .{")
        o.append("        .name = %s," % zstr(name))
        o.append("        .cli_stdout = %s," % zstr(so))
        o.append("        .cli_stderr = %s," % zstr(cli[2]))
        o.append("        .frames = &.{")
        for n, dr, f in v["frames"]:
            o.append("            .{ .conn = %d, .dir = .%s, .hex = \"%s\" }," % (n, dr, f.hex()))
        o.append("        },")
        o.append("    },")
    o.append("};")
    o.append("")
    with open(path, "w") as f:
        f.write("\n".join(o))


def to_json(res):
    import json
    return json.dumps({k: {"cli": v.get("cli"), "listen_stdout": v.get("listen_stdout"),
                           "frames": [[n, d, f.hex()] for n, d, f in v["frames"]]} for k, v in res.items()})


def from_json(s):
    import json
    res = {}
    for k, v in json.loads(s).items():
        e = {"cli": v["cli"], "frames": [(n, d, bytes.fromhex(f)) for n, d, f in v["frames"]]}
        if v.get("listen_stdout") is not None:
            e["listen_stdout"] = v["listen_stdout"]
        res[k] = e
    return res


def explore(res):
    for k, v in res.items():
        print("==", k, v.get("cli"), v.get("listen_stdout", ""))
        for n, d, f in v["frames"]:
            print("  c%d %s %s" % (n, d, describe(f)))


def main():
    args = sys.argv[1:]
    if "--with-daemon" in args:
        # Run under `unshare -r`: BLOBMSG_UBUS_SOCKET=<private socket> python3 ... --with-daemon -- CMD...
        cmd = args[args.index("--") + 1:]
        d = Daemon("live")
        prov = None
        try:
            prov = Provider(d.sock)  # an object "probe": echo / fail / slow / notify
            env = dict(os.environ, BLOBMSG_UBUS_SOCKET=d.sock)
            p = subprocess.Popen(cmd, env=env, start_new_session=True)
            try:
                rc = p.wait(timeout=int(os.environ.get("LIVE_TIMEOUT", "300")))
            except subprocess.TimeoutExpired:
                os.killpg(p.pid, signal.SIGKILL)
                p.wait()
                rc = 124
        finally:
            if prov:
                prov.close()
            d.stop()
        sys.exit(rc)
    if "--inner" in args:
        sys.stdout.write(to_json(inner_scenarios()))
        return
    res = outer_scenarios()
    # The privileged half runs in a user namespace that maps us to root: no host privilege, but
    # the daemon then lets us register events and objects like it does on a router.
    p = subprocess.run(["unshare", "-r", sys.executable, os.path.abspath(__file__), "--inner"],
                       capture_output=True, timeout=120)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode())
        sys.exit(1)
    res.update(from_json(p.stdout.decode()))
    if "--explore" in args:
        explore(res)
        return
    if "--out" in args:
        write_zig(res, args[args.index("--out") + 1])
        return
    print("use --explore, --out <file> or --serve <sock>", file=sys.stderr)
    sys.exit(2)


if __name__ == "__main__":
    main()
