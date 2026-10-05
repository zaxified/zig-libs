#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Topic-filter and topic-name oracle for `topic.zig`: a real Eclipse Mosquitto
2.x broker, driven over a raw MQTT 5.0 socket, as a black box.

Writes `src/topic_vectors.zig`, replayed by `src/topic_oracle_test.zig` with no
broker, no Python and no socket:

    python3 modules/mqtt/tools/topic_oracle.py > modules/mqtt/src/topic_vectors.zig

Needs podman and the image `tools/interop.zig` uses (`podman pull
docker.io/library/eclipse-mosquitto:2`). Raw packets, not a client library:
paho refuses some filters and names itself, and the point is the broker's
answer to every one.

What the broker answers:
  - a FILTER is valid when its SUBACK reason code is a granted QoS (< 0x80);
  - a NAME is valid when a QoS 1 PUBLISH to it is acknowledged (PUBACK < 0x80)
    on a connection the broker keeps;
  - for every valid filter and valid name, whether the filter MATCHES: each
    filter is subscribed with its own Subscription Identifier, every name is
    published once, and the identifiers each delivered message carries are
    collected (a sentinel publish marks the end).
Mosquitto is a black-box peer -- EPL-2.0 OR EDL-1.0, its source neither read
nor copied (root NOTICE §0).
"""
import socket
import struct
import subprocess
import time

IMAGE = "docker.io/library/eclipse-mosquitto:2"

FILTERS = [
    "#", "+", "+/+", "+/#", "/#", "/+", "a", "a/b", "a/b/c", "a/#", "a/+", "a/+/c", "a/+/#", "+/b", "+/b/#",
    "a//b", "a//#", "/", "//", "a/", "a/+/", "sport/#", "sport/tennis/+", "$foo/#", "$foo/+", "$foo", "+/foo",
    "#/a", "a/#/b", "a#", "a/b#", "+a", "a+/b", "a/++", "##", "a/#/", "", "é/#", "é/+/é",
    "a\u0000b", "A/B", "$share", "$sharex/a",
]

NAMES = [
    "a", "a/b", "a/b/c", "a/b/c/d", "/a", "a/", "/", "//", "a//b", "a/x/c", "sport", "sport/tennis",
    "sport/tennis/player1", "sports", "$foo", "$foo/a", "$foo/a/b", "foo", "x/foo", "A/B", "é/x",
    "é/y/é", "b", "x/b", "x/b/y", "a+b", "a/+", "a/#", "#", "+", "", "a\u0000b",
]


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Broker:
    def __init__(self):
        self.port = free_port()
        # The binary runs from a COPY: see tools/interop.zig (AppArmor attaches
        # a host profile to /usr/sbin/mosquitto by path).
        cmd = f"cp /usr/sbin/mosquitto /tmp/mosquitto && exec /tmp/mosquitto -p {self.port}"
        self.id = subprocess.run(["podman", "run", "-d", "--rm", "--network", "host", IMAGE, "sh", "-c", cmd],
                                 check=True, capture_output=True, text=True).stdout.strip()
        help_out = subprocess.run(["podman", "exec", self.id, "/tmp/mosquitto", "-h"], capture_output=True, text=True)
        self.version = (help_out.stdout or help_out.stderr).splitlines()[0] if (help_out.stdout or help_out.stderr) else "mosquitto ?"
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError("mosquitto not ready")

    def stop(self):
        subprocess.run(["podman", "rm", "-f", "-t", "0", self.id], capture_output=True)


def varint(n):
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def mstr(b):
    return struct.pack(">H", len(b)) + b


class Conn:
    """One MQTT 5.0 connection over a raw socket."""

    def __init__(self, port, cid):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=3)
        body = mstr(b"MQTT") + bytes([5, 0x02]) + struct.pack(">H", 60) + varint(0) + mstr(cid.encode())
        self.send(0x10, body)
        t, b = self.recv()
        assert t >> 4 == 2 and b[1] == 0, ("CONNACK", t, b)
        self.next_id = 1

    def send(self, first, body):
        self.s.sendall(bytes([first]) + varint(len(body)) + body)

    def recv(self):
        """(first byte, body), or None when the broker closed the connection."""
        try:
            h = self.s.recv(1)
            if not h:
                return None
            mul, n = 1, 0
            while True:
                b = self.s.recv(1)[0]
                n += (b & 0x7F) * mul
                mul *= 128
                if not b & 0x80:
                    break
            body = b""
            while len(body) < n:
                chunk = self.s.recv(n - len(body))
                if not chunk:
                    return None
                body += chunk
            return h[0], body
        except (socket.timeout, ConnectionResetError, IndexError):
            return None

    def pid(self):
        p = self.next_id
        self.next_id += 1
        return p

    def subscribe(self, flt, sub_id):
        """The SUBACK reason code, or None when the connection was dropped."""
        p = self.pid()
        props = b"\x0b" + varint(sub_id)
        self.send(0x82, struct.pack(">H", p) + varint(len(props)) + props + mstr(flt) + b"\x00")
        r = self.recv()
        if r is None or r[0] >> 4 != 9:
            return None
        body = r[1]
        plen_at = 2
        mul, plen, i = 1, 0, plen_at
        while True:
            b = body[i]
            i += 1
            plen += (b & 0x7F) * mul
            mul *= 128
            if not b & 0x80:
                break
        return body[i + plen]

    def publish(self, name):
        """The PUBACK reason code (0 when absent), or None when dropped."""
        p = self.pid()
        self.send(0x32, mstr(name) + struct.pack(">H", p) + varint(0) + b"x")
        while True:
            r = self.recv()
            if r is None:
                return None
            if r[0] >> 4 == 4:
                return r[1][2] if len(r[1]) > 2 else 0
            if r[0] >> 4 == 14:  # DISCONNECT
                return None

    def deliveries(self, until):
        """(topic, [subscription ids]) for every PUBLISH up to the one on `until`."""
        out = []
        while True:
            r = self.recv()
            assert r is not None, "connection lost while collecting"
            first, body = r
            if first >> 4 != 3:
                continue
            tlen = struct.unpack(">H", body[:2])[0]
            topic = body[2:2 + tlen]
            i = 2 + tlen + (2 if (first >> 1) & 3 else 0)
            mul, plen = 1, 0
            while True:
                b = body[i]
                i += 1
                plen += (b & 0x7F) * mul
                mul *= 128
                if not b & 0x80:
                    break
            props, ids, j = body[i:i + plen], [], 0
            while j < len(props):
                pid = props[j]
                j += 1
                if pid == 0x0B:
                    mul, v = 1, 0
                    while True:
                        b = props[j]
                        j += 1
                        v += (b & 0x7F) * mul
                        mul *= 128
                        if not b & 0x80:
                            break
                    ids.append(v)
                elif pid in (0x01,):
                    j += 1
                elif pid in (0x02,):
                    j += 4
                elif pid in (0x23,):
                    j += 2
                elif pid in (0x03, 0x08, 0x09):
                    j += 2 + struct.unpack(">H", props[j:j + 2])[0]
                elif pid == 0x26:
                    for _ in range(2):
                        j += 2 + struct.unpack(">H", props[j:j + 2])[0]
                else:
                    raise RuntimeError(f"unexpected PUBLISH property {pid:#x}")
            if topic == until:
                return out
            out.append((topic, ids))

    def close(self):
        try:
            self.send(0xE0, b"\x00\x00")
            self.s.close()
        except OSError:
            pass


def zig_str(s):
    out = []
    for b in (s if isinstance(s, bytes) else s.encode("utf-8")):
        c = chr(b)
        if c == '"':
            out.append('\\"')
        elif c == "\\":
            out.append("\\\\")
        elif 0x20 <= b < 0x7F:
            out.append(c)
        else:
            out.append(f"\\x{b:02x}")
    return '"' + "".join(out) + '"'


def main():
    broker = Broker()
    try:
        # Validity, each on a fresh connection: an invalid filter or name may
        # cost the connection.
        filter_ok, name_ok = {}, {}
        for i, f in enumerate(FILTERS):
            c = Conn(broker.port, f"f{i}")
            rc = c.subscribe(f.encode(), 1)
            filter_ok[f] = rc is not None and rc < 0x80
            c.close()
        for i, n in enumerate(NAMES):
            c = Conn(broker.port, f"n{i}")
            rc = c.publish(n.encode())
            name_ok[n] = rc is not None and rc < 0x80
            c.close()

        valid_filters = [f for f in FILTERS if filter_ok[f]]
        valid_names = [n for n in NAMES if name_ok[n]]
        sub = Conn(broker.port, "matcher")
        for i, f in enumerate(valid_filters):
            assert sub.subscribe(f.encode(), i + 1) is not None, f
        assert sub.subscribe(b"zz-sentinel", len(valid_filters) + 1) is not None
        pub = Conn(broker.port, "publisher")
        for n in valid_names:
            assert pub.publish(n.encode()) is not None, n
        assert pub.publish(b"zz-sentinel") is not None
        matched = {n: set() for n in valid_names}
        for t, ids in sub.deliveries(b"zz-sentinel"):
            matched[t.decode()].update(i for i in ids if i <= len(valid_filters))
        pub.close()
        sub.close()
    finally:
        broker.stop()

    print("// SPDX-License-Identifier: MIT")
    print(f"// GENERATED by modules/mqtt/tools/topic_oracle.py ({broker.version}) -- do not hand-edit.")
    print("//! Topic filter / name verdicts of a real Mosquitto broker, replayed by")
    print("//! `topic_oracle_test.zig`. Regenerate with the command in the script's docstring.")
    print()
    print("pub const Verdict = struct { s: []const u8, valid: bool };")
    print()
    print("/// SUBACK granted (< 0x80).")
    print("pub const filters = [_]Verdict{")
    for f in FILTERS:
        print(f"    .{{ .s = {zig_str(f)}, .valid = {'true' if filter_ok[f] else 'false'} }},")
    print("};")
    print()
    print("/// QoS 1 PUBLISH acknowledged on a connection the broker kept.")
    print("pub const names = [_]Verdict{")
    for n in NAMES:
        print(f"    .{{ .s = {zig_str(n)}, .valid = {'true' if name_ok[n] else 'false'} }},")
    print("};")
    print()
    print("/// For each valid name, the valid filters (indices into `filters`) whose")
    print("/// subscription received it; every other valid filter did not.")
    print("pub const Match = struct { name: []const u8, filters: []const u16 };")
    print("pub const matches = [_]Match{")
    for n in valid_names:
        idx = sorted(FILTERS.index(valid_filters[i - 1]) for i in matched[n])
        lst = "&.{}" if not idx else "&.{ " + ", ".join(str(i) for i in idx) + " }"
        print(f"    .{{ .name = {zig_str(n)}, .filters = {lst} }},")
    print("};")


main()
