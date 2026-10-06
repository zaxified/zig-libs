#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Broker-session oracle for `broker.zig`: a real Eclipse Mosquitto 2.x broker,
driven over raw MQTT 3.1.1 sockets, as a black box.

Writes `src/testdata/session_transcript.txt`, replayed by
`src/session_replay.zig` with no broker, no Python and no socket:

    python3 modules/mqtt/tools/session_oracle.py > modules/mqtt/src/testdata/session_transcript.txt

Needs podman and the image `tools/interop.zig` uses (`podman pull
docker.io/library/eclipse-mosquitto:2`). Raw packets, not a client library: the
scenarios ack late, drop sockets mid-flow and send what a library would refuse.

What it pins is the part of the broker the other anchors leave to self-tests:
session state across connections -- persistent sessions and their offline
queue, redelivery of unacknowledged QoS 1/2 messages (DUP, the same Packet
Identifier, PUBREL resent), QoS 2 duplicate suppression, retained messages and
their QoS, Wills on every way a connection ends, session take-over, the CONNECT
refusals, keep-alive, and which protocol violations close the connection.

Each scenario runs against a fresh broker. Every step is sent, then the driver
waits until no connection has received anything for `SETTLE` seconds, so the
order across connections is the broker's, settled. The transcript holds, per
step, the time and the client's bytes (or the client closing its socket, or a
pause), and, per connection, every byte the broker wrote and whether the broker
closed it. Mosquitto is a black-box peer -- EPL-2.0 OR EDL-1.0, its source
neither read nor copied (root NOTICE §0).
"""
import select
import socket
import struct
import subprocess
import sys
import time

IMAGE = "docker.io/library/eclipse-mosquitto:2"
SETTLE = 0.15


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class Broker:
    """Mosquitto, the anchor. `--peer` swaps in a tiebreaker for a divergence
    (`feedback`: a differential oracle needs a third implementation): NanoMQ
    (`podman pull docker.io/emqx/nanomq`) or amqtt (a venv with `pip install
    amqtt`, path in $AMQTT). Only Mosquitto's transcript is ever committed."""

    def __init__(self, peer="mosquitto"):
        self.port, self.peer, self.id, self.proc = free_port(), peer, None, None
        if peer == "mosquitto":
            # The binary runs from a COPY: see tools/interop.zig (AppArmor
            # attaches a host profile to /usr/sbin/mosquitto by path).
            cmd = f"cp /usr/sbin/mosquitto /tmp/mosquitto && exec /tmp/mosquitto -p {self.port}"
            self.id = self.podman(IMAGE, "sh", "-c", cmd)
        elif peer == "nanomq":
            self.id = self.podman("docker.io/emqx/nanomq", "nanomq", "start", "--url", f"nmq-tcp://127.0.0.1:{self.port}")
        elif peer == "amqtt":
            import os
            import tempfile
            cfg = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False)
            cfg.write(f"listeners:\n  default:\n    type: tcp\n    bind: 127.0.0.1:{self.port}\n"
                      "plugins:\n  amqtt.plugins.authentication.AnonymousAuthPlugin:\n    allow_anonymous: true\n")
            cfg.close()
            self.proc = subprocess.Popen([os.environ["AMQTT"], "-c", cfg.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            raise SystemExit(f"unknown peer {peer}")
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                time.sleep(0.2)
                return
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"{peer} not ready")

    @staticmethod
    def podman(*argv):
        return subprocess.run(["podman", "run", "-d", "--rm", "--network", "host", *argv],
                              check=True, capture_output=True, text=True).stdout.strip()

    def version(self):
        if self.peer != "mosquitto":
            return self.peer
        r = subprocess.run(["podman", "exec", self.id, "/tmp/mosquitto", "-h"], capture_output=True, text=True)
        out = r.stdout or r.stderr
        return out.splitlines()[0] if out else "mosquitto ?"

    def stop(self):
        if self.id:
            subprocess.run(["podman", "rm", "-f", "-t", "0", self.id], capture_output=True)
        if self.proc:
            self.proc.kill()
            self.proc.wait()


# ── MQTT 3.1.1 encoding ─────────────────────────────────────────────────────


def varint(n):
    out = bytearray()
    while True:
        b = n % 128
        n //= 128
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def mstr(b):
    if isinstance(b, str):
        b = b.encode()
    return struct.pack(">H", len(b)) + b


def pkt(first, body):
    return bytes([first]) + varint(len(body)) + body


def connect(cid, clean=True, keepalive=0, will=None, level=4, name=b"MQTT"):
    """will = (topic, payload, qos, retain)."""
    flags = 0x02 if clean else 0
    payload = mstr(cid)
    if will:
        topic, msg, qos, retain = will
        flags |= 0x04 | (qos << 3) | (0x20 if retain else 0)
        payload += mstr(topic) + mstr(msg)
    return pkt(0x10, mstr(name) + bytes([level, flags]) + struct.pack(">H", keepalive) + payload)


def connect5(cid, clean=True, session_expiry=None, will=None, will_delay=None):
    """MQTT 5.0 CONNECT; will = (topic, payload, qos, retain)."""
    flags = 0x02 if clean else 0
    props = b"" if session_expiry is None else b"\x11" + struct.pack(">I", session_expiry)
    payload = mstr(cid)
    if will:
        topic, msg, qos, retain = will
        flags |= 0x04 | (qos << 3) | (0x20 if retain else 0)
        wprops = b"" if will_delay is None else b"\x18" + struct.pack(">I", will_delay)
        payload += varint(len(wprops)) + wprops + mstr(topic) + mstr(msg)
    return pkt(0x10, mstr(b"MQTT") + bytes([5, flags]) + struct.pack(">H", 0) + varint(len(props)) + props + payload)


def publish(topic, payload, qos=0, retain=False, pid=None, dup=False):
    first = 0x30 | (qos << 1) | (0x01 if retain else 0) | (0x08 if dup else 0)
    body = mstr(topic) + (struct.pack(">H", pid) if qos else b"") + (payload.encode() if isinstance(payload, str) else payload)
    return pkt(first, body)


def subscribe(pid, subs, first=0x82, v5=False):
    props = b"\x00" if v5 else b""
    return pkt(first, struct.pack(">H", pid) + props + b"".join(mstr(f) + bytes([q]) for f, q in subs))


def unsubscribe(pid, filters):
    return pkt(0xA2, struct.pack(">H", pid) + b"".join(mstr(f) for f in filters))


def ack(kind, pid):
    first = {"puback": 0x40, "pubrec": 0x50, "pubrel": 0x62, "pubcomp": 0x70}[kind]
    return pkt(first, struct.pack(">H", pid))


DISCONNECT = b"\xe0\x00"
PINGREQ = b"\xc0\x00"


def split(stream):
    """The packets of a byte stream, as (first byte, body)."""
    out, off = [], 0
    while off < len(stream):
        first = stream[off]
        mul, n, i = 1, 0, off + 1
        while True:
            b = stream[i]
            i += 1
            n += (b & 0x7F) * mul
            mul *= 128
            if not b & 0x80:
                break
        out.append((first, stream[i:i + n]))
        off = i + n
    return out


# ── the driver ──────────────────────────────────────────────────────────────


class Run:
    def __init__(self, broker, name, out):
        self.broker, self.out = broker, out
        self.socks, self.rx, self.closed = {}, {}, {}
        self.dropped = set()  # conns the client closed (sockets closed in `finish`)
        self.acked = {}  # conn -> number of packets of rx already answered by `ackall`
        self.t0 = time.monotonic()
        out.append(f"scenario {name}")

    def now(self):
        return int((time.monotonic() - self.t0) * 1000)

    def settle(self, quiet=SETTLE):
        """Read every connection until none has received anything for `quiet` s."""
        deadline = time.monotonic() + quiet
        while True:
            live = [s for i, s in self.socks.items() if not self.closed[i] and i not in self.dropped]
            left = deadline - time.monotonic()
            if left <= 0 or not live:
                return
            r, _, _ = select.select(live, [], [], left)
            for s in r:
                i = next(k for k, v in self.socks.items() if v is s)
                try:
                    data = s.recv(65536)
                except ConnectionResetError:
                    data = b""
                if data:
                    self.rx[i] += data
                    deadline = time.monotonic() + quiet
                else:
                    self.closed[i] = True

    def send(self, i, data):
        if i not in self.socks:
            self.socks[i] = socket.create_connection(("127.0.0.1", self.broker.port))
            self.rx[i], self.closed[i], self.acked[i] = b"", False, 0
        if self.closed[i]:
            # Only a tiebreaker peer gets here; the replay ignores '#' lines.
            self.out.append(f"# conn {i}: already closed by the broker, step skipped")
            return
        if data[0] == 0x10 and data[2:9] == b"\x00\x04MQTT\x05":
            self.out.append(f"v5 {i}")
        self.out.append(f"at {self.now()} conn {i} c2s {data.hex()}")
        self.socks[i].sendall(data)
        self.settle()

    def drop(self, i):
        """The client closes its socket without a DISCONNECT."""
        self.out.append(f"at {self.now()} conn {i} close")
        self.socks[i].close()
        self.dropped.add(i)
        self.settle()

    def disconnect(self, i):
        self.send(i, DISCONNECT)
        self.drop(i)

    def pause(self, ms):
        """Nothing sent for `ms`: the broker's timers run. The replay ticks at the end."""
        end = time.monotonic() + ms / 1000
        while time.monotonic() < end:
            self.settle(min(SETTLE, max(0.0, end - time.monotonic())))
            time.sleep(0.01)
        self.out.append(f"at {self.now()} tick")
        self.settle()

    def ackall(self, i, upto=None):
        """Answer every QoS 1/2 PUBLISH and PUBREL received on conn `i` so far,
        as a well-behaved client would: PUBACK, PUBREC, PUBCOMP. `upto` stops
        a QoS 2 flow early ("pubrec": answer PUBLISH, not PUBREL)."""
        while True:
            pkts = split(self.rx[i])
            todo = pkts[self.acked[i]:]
            if not todo:
                return
            self.acked[i] = len(pkts)
            for first, body in todo:
                kind = first >> 4
                if kind == 3:
                    qos = (first >> 1) & 3
                    if qos:
                        tl = struct.unpack(">H", body[:2])[0]
                        pid = struct.unpack(">H", body[2 + tl:4 + tl])[0]
                        self.send(i, ack("puback" if qos == 1 else "pubrec", pid))
                elif kind == 6 and upto != "pubrec":
                    self.send(i, ack("pubcomp", struct.unpack(">H", body[:2])[0]))

    def finish(self):
        self.settle()
        for i in sorted(self.socks):
            self.out.append(f"out {i} {self.rx[i].hex()}")
            # Whether the BROKER closed it (end of stream before the client dropped it).
            self.out.append(f"closed {i} {1 if self.closed[i] else 0}")
        for s in self.socks.values():
            s.close()
        self.out.append("end")


# ── scenarios ───────────────────────────────────────────────────────────────


def persist_queue(r):
    # A persistent session queues QoS 1 and 2 while offline; QoS 0 is not
    # queued (Mosquitto's default `queue_qos0_messages false`).
    r.send(0, connect("s1", clean=False))
    r.send(0, subscribe(1, [("q/#", 2)]))
    r.disconnect(0)
    r.send(1, connect("p", clean=True))
    r.send(1, publish("q/0", "zero"))
    r.send(1, publish("q/1", "one", qos=1, pid=1))
    r.send(1, publish("q/2", "two", qos=2, pid=2))
    r.send(1, ack("pubrel", 2))
    r.disconnect(1)
    r.send(2, connect("s1", clean=False))
    r.ackall(2)
    r.disconnect(2)
    # Still there: the session survived a clean-state-free reconnect.
    r.send(3, connect("s1", clean=False))
    r.disconnect(3)


def clean_discards(r):
    r.send(0, connect("s1", clean=False))
    r.send(0, subscribe(1, [("q/#", 1)]))
    r.disconnect(0)
    r.send(1, connect("s1", clean=True))
    r.disconnect(1)
    r.send(2, connect("p"))
    r.send(2, publish("q/a", "lost", qos=1, pid=1))
    r.disconnect(2)
    r.send(3, connect("s1", clean=False))
    r.disconnect(3)


def redeliver_qos1(r):
    r.send(0, connect("s1", clean=False))
    r.send(0, subscribe(1, [("q", 1)]))
    r.send(1, connect("p"))
    r.send(1, publish("q", "m1", qos=1, pid=1))
    r.send(1, publish("q", "m2", qos=1, pid=2))
    r.drop(0)  # never acked
    r.send(1, publish("q", "m3", qos=1, pid=3))
    r.send(2, connect("s1", clean=False))
    r.ackall(2)
    r.disconnect(2)
    r.disconnect(1)


def qos2_pubrel_resend(r):
    r.send(0, connect("s1", clean=False))
    r.send(0, subscribe(1, [("q", 2)]))
    r.send(1, connect("p"))
    r.send(1, publish("q", "m", qos=2, pid=9))
    r.send(1, ack("pubrel", 9))
    r.ackall(0, upto="pubrec")  # PUBREC, then the PUBREL arrives: no PUBCOMP
    r.drop(0)
    r.send(2, connect("s1", clean=False))
    r.ackall(2)
    r.disconnect(2)
    r.disconnect(1)


def qos2_inbound_dup(r):
    r.send(0, connect("sub"))
    r.send(0, subscribe(1, [("q", 2)]))
    r.send(1, connect("p2", clean=False))
    r.send(1, publish("q", "once", qos=2, pid=7))
    r.drop(1)  # PUBREC received, no PUBREL sent
    r.send(2, connect("p2", clean=False))
    r.send(2, publish("q", "once", qos=2, pid=7, dup=True))
    r.send(2, ack("pubrel", 7))
    r.disconnect(2)
    r.ackall(0)
    r.disconnect(0)


def retained(r):
    r.send(0, connect("p"))
    r.send(0, publish("r/a", "v1", qos=1, retain=True, pid=1))
    r.send(0, publish("r/b", "b1", retain=True))
    r.send(1, connect("s1"))
    r.send(1, subscribe(1, [("r/#", 1)]))
    r.ackall(1)
    r.send(0, publish("r/a", "v2", qos=1, retain=True, pid=2))  # live: retain flag cleared
    r.ackall(1)
    r.send(2, connect("s2"))
    r.send(2, subscribe(1, [("r/a", 0)]))  # newest value, retain flag set
    r.send(0, publish("r/a", "", retain=True))  # clears it
    r.send(3, connect("s3"))
    r.send(3, subscribe(1, [("r/#", 0)]))  # only r/b left
    for i in (0, 1, 2, 3):
        r.disconnect(i)


def retained_qos(r):
    r.send(0, connect("p"))
    r.send(0, publish("r", "hi", qos=2, retain=True, pid=1))
    r.send(0, ack("pubrel", 1))
    r.send(1, connect("s0"))
    r.send(1, subscribe(1, [("r", 0)]))  # downgraded to QoS 0
    r.send(1, subscribe(2, [("r", 1)]))  # re-subscribe: SUBACK 1, retained again at QoS 1
    r.ackall(1)
    r.disconnect(0)
    r.disconnect(1)


def qos_downgrade(r):
    r.send(0, connect("s"))
    r.send(0, subscribe(1, [("d/0", 0), ("d/1", 1), ("d/2", 2)]))
    r.send(1, connect("p"))
    for n, t in enumerate(("d/0", "d/1", "d/2")):
        r.send(1, publish(t, "q2", qos=2, pid=10 + n))
        r.send(1, ack("pubrel", 10 + n))
    r.send(1, publish("d/2", "q1", qos=1, pid=20))
    r.send(1, publish("d/2", "q0"))
    r.ackall(0)
    r.disconnect(0)
    r.disconnect(1)


def overlapping(r):
    r.send(0, connect("s"))
    r.send(0, subscribe(1, [("o/#", 0), ("o/+", 1)]))
    r.send(0, publish("o/x", "self", qos=1, pid=1))  # its own message comes back too
    r.ackall(0)
    r.disconnect(0)


def unsubscribe_flow(r):
    r.send(0, connect("s"))
    r.send(0, subscribe(1, [("u/a", 0), ("u/b", 0)]))
    r.send(0, unsubscribe(2, ["u/a"]))
    r.send(0, unsubscribe(3, ["nothing/here"]))
    r.send(0, publish("u/a", "gone"))
    r.send(0, publish("u/b", "kept"))
    r.send(0, PINGREQ)
    r.disconnect(0)


def will_on_drop(r):
    r.send(0, connect("s"))
    r.send(0, subscribe(1, [("w/#", 1)]))
    r.send(1, connect("dies", will=("w/dies", "bye", 1, False)))
    r.drop(1)
    r.send(2, connect("polite", will=("w/polite", "never", 1, False)))
    r.disconnect(2)
    r.ackall(0)
    r.disconnect(0)


def will_retained(r):
    r.send(0, connect("dies", will=("w/r", "last", 0, True)))
    r.drop(0)
    r.send(1, connect("late"))
    r.send(1, subscribe(1, [("w/#", 0)]))
    r.disconnect(1)


def will_on_violation(r):
    r.send(0, connect("s"))
    r.send(0, subscribe(1, [("w/#", 0)]))
    r.send(1, connect("bad", will=("w/bad", "violated", 0, False)))
    r.send(1, publish("w/+", "wildcard topic name"))  # 3.3.2-2: the broker closes; the Will goes out
    r.disconnect(0)


def takeover(r):
    r.send(0, connect("s"))
    r.send(0, subscribe(1, [("w/#", 0)]))
    r.send(1, connect("dup", will=("w/dup", "old", 0, False)))
    r.send(2, connect("dup"))  # 3.1.4-2: the first connection is closed
    r.disconnect(2)
    r.disconnect(0)


def takeover_persistent(r):
    r.send(0, connect("dup", clean=False))
    r.send(0, subscribe(1, [("t", 1)]))
    r.send(1, connect("dup", clean=False))  # session present, subscription kept
    r.send(2, connect("p"))
    r.send(2, publish("t", "to the new one", qos=1, pid=1))
    r.ackall(1)
    r.disconnect(1)
    r.disconnect(2)


def offline_order(r):
    r.send(0, connect("s", clean=False))
    r.send(0, subscribe(1, [("o", 1)]))
    r.disconnect(0)
    r.send(1, connect("p"))
    for n in range(5):
        r.send(1, publish("o", f"m{n}", qos=1, pid=n + 1))
    r.disconnect(1)
    r.send(2, connect("s", clean=False))
    r.ackall(2)
    r.disconnect(2)


def inflight_window(r):
    # 25 QoS 1 messages to a subscriber that does not ack.
    r.send(0, connect("s"))
    r.send(0, subscribe(1, [("f", 1)]))
    r.send(1, connect("p"))
    for n in range(25):
        r.send(1, publish("f", f"m{n}", qos=1, pid=n + 1))
    r.ackall(0)
    r.disconnect(0)
    r.disconnect(1)


def connect_refusals(r):
    r.send(0, connect("lvl", level=6))  # refused: unacceptable protocol level, then close
    r.send(1, connect("", clean=False))  # 0x02 identifier rejected, then close
    r.send(2, connect("", clean=True))  # accepted with an assigned identifier
    r.disconnect(2)
    r.send(3, connect("lvl", level=3))  # "MQTT" at 3.1's level
    r.send(4, connect("lvl", level=255))


def violations(r):
    r.send(0, publish("a", "before connect"))  # first packet not CONNECT
    r.send(1, connect("c1"))
    r.send(1, connect("c1"))  # second CONNECT
    r.send(2, connect("c2"))
    r.send(2, subscribe(1, [("a", 3)]))  # QoS 3
    r.send(3, connect("c3"))
    r.send(3, subscribe(1, [("a", 0)], first=0x80))  # reserved flags wrong
    r.send(4, connect("c4"))
    r.send(4, subscribe(1, []))  # no topic filter (3.8.3-3)
    r.send(5, connect("c5"))
    r.send(5, publish("a", "x", qos=3, pid=1))  # QoS 3


def keepalive(r):
    r.send(0, connect("s"))
    r.send(0, subscribe(1, [("w/#", 0)]))
    r.send(1, connect("idle", keepalive=1, will=("w/idle", "timed out", 0, False)))
    r.pause(2600)  # 1.5 × 1 s passes with nothing from conn 1
    r.send(0, PINGREQ)
    r.disconnect(0)


# MQTT 5.0 timers. A connection whose CONNECT is 5.0 is marked `v5` in the
# transcript: the replay compares its CONNACK by flags and reason code only,
# since the CONNACK properties announce each broker's own limits.


def session_expiry5(r):
    r.send(0, connect5("e", clean=False, session_expiry=1))
    r.send(0, subscribe(1, [("x", 1)], v5=True))
    r.disconnect(0)
    r.send(1, connect5("e", clean=False, session_expiry=1))  # within 1 s: present
    r.disconnect(1)
    r.pause(2500)  # past it: gone
    r.send(2, connect5("e", clean=False, session_expiry=1))
    r.disconnect(2)


def will_delay5(r):
    r.send(0, connect("s"))
    r.send(0, subscribe(1, [("w/#", 0)]))
    r.send(1, connect5("d", clean=False, session_expiry=10, will=("w/d", "late", 0, False), will_delay=1))
    r.drop(1)
    r.pause(300)  # not yet
    r.pause(1700)  # now
    r.disconnect(0)


def will_delay_cancelled5(r):
    r.send(0, connect("s"))
    r.send(0, subscribe(1, [("w/#", 0)]))
    r.send(1, connect5("d", clean=False, session_expiry=10, will=("w/d", "never", 0, False), will_delay=2))
    r.drop(1)
    r.pause(300)
    r.send(2, connect5("d", clean=False, session_expiry=10))  # back in time: no Will
    r.pause(2500)
    r.disconnect(2)
    r.disconnect(0)


SCENARIOS = [
    persist_queue, clean_discards, redeliver_qos1, qos2_pubrel_resend, qos2_inbound_dup,
    retained, retained_qos, qos_downgrade, overlapping, unsubscribe_flow,
    will_on_drop, will_retained, will_on_violation, takeover, takeover_persistent,
    offline_order, inflight_window, connect_refusals, violations, keepalive,
    session_expiry5, will_delay5, will_delay_cancelled5,
]


def main():
    args = sys.argv[1:]
    peer = "mosquitto"
    if args[:1] == ["--peer"]:
        peer, args = args[1], args[2:]
    only = set(args)
    out = []
    version = None
    for sc in SCENARIOS:
        if only and sc.__name__ not in only:
            continue
        b = Broker(peer)
        try:
            version = version or b.version()
            r = Run(b, sc.__name__, out)
            sc(r)
            r.finish()
        finally:
            b.stop()
    head = [
        "# Generated by modules/mqtt/tools/session_oracle.py: MQTT 3.1.1 broker",
        "# sessions against a real Eclipse Mosquitto, replayed by src/session_replay.zig.",
        "# Do not edit by hand.",
        f"peer {version}",
    ]
    sys.stdout.write("\n".join(head + out) + "\n")


if __name__ == "__main__":
    main()
