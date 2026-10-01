# SPDX-License-Identifier: MIT
"""MQTT 5.0 scenario for `interop.zig`: real paho-mqtt clients against this
module's Broker.

Run by `zig build interop-mqtt` (never by hand in a gate): it connects to the
host/port given on the command line, plays every step below in order, waits
for each acknowledgement before the next — so the broker sees the steps
serialized and its transcript replays deterministically — and prints one JSON
object per observation on stdout. `interop.zig` checks them.

paho-mqtt is a black-box peer here (EPL-2.0 OR EDL-1.0, installed with pip);
none of its source was read or copied — root NOTICE section 0.
"""

import json
import queue
import sys
import time

import paho.mqtt.client as mqtt
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties
from paho.mqtt.subscribeoptions import SubscribeOptions

HOST = sys.argv[1]
PORT = int(sys.argv[2])
TIMEOUT = 5.0


def emit(**kv):
    print(json.dumps(kv), flush=True)


def props(kind, **kv):
    p = Properties(kind)
    for k, v in kv.items():
        setattr(p, k, v)
    return p


def plain(p):
    """The properties paho decoded, as JSON-able values."""
    if p is None:
        return {}
    out = {}
    for name in p.names.keys():
        compressed = name.replace(" ", "")
        if hasattr(p, compressed):
            v = getattr(p, compressed)
            if isinstance(v, bytes):
                v = v.hex()
            out[compressed] = v
    return out


class C:
    """One paho client whose callbacks land in queues."""

    def __init__(self, cid, **kw):
        self.events = queue.Queue()
        self.stash = []
        # No reconnect: a client told 0x8E (take-over) would come straight
        # back and take the session over in turn.
        self.c = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid, protocol=mqtt.MQTTv5,
                             reconnect_on_failure=False, **kw)
        self.c.on_connect = lambda c, u, f, rc, p: self.events.put(("connack", f.session_present, rc.value, plain(p)))
        self.c.on_subscribe = lambda c, u, mid, rcs, p: self.events.put(("suback", mid, [r.value for r in rcs]))
        self.c.on_unsubscribe = lambda c, u, mid, rcs, p: self.events.put(("unsuback", mid, [r.value for r in rcs]))
        self.c.on_publish = lambda c, u, mid, rc, p: self.events.put(("puback", mid, rc.value))
        self.c.on_message = lambda c, u, m: self.events.put(("message", m.topic, m.payload.decode(), m.qos, m.retain, plain(m.properties)))
        self.c.on_disconnect = lambda c, u, f, rc, p: self.events.put(("disconnect", rc.value))

    def expect(self, kind, timeout=TIMEOUT):
        """The next event of `kind`; others that arrive first are kept, in
        order, for a later `expect` (a QoS 1 echo may beat its PUBACK)."""
        for i, ev in enumerate(self.stash):
            if ev[0] == kind:
                return self.stash.pop(i)
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise SystemExit(f"timeout waiting for {kind}")
            try:
                ev = self.events.get(timeout=left)
            except queue.Empty:
                raise SystemExit(f"timeout waiting for {kind}")
            if ev[0] == kind:
                return ev
            self.stash.append(ev)

    def none(self, wait=0.3):
        """Nothing arrives within `wait` seconds (and nothing is kept)."""
        if self.stash:
            return self.stash[0]
        try:
            ev = self.events.get(timeout=wait)
        except queue.Empty:
            return None
        return ev

    def connect(self, clean=True, **cprops):
        p = props(PacketTypes.CONNECT, **cprops) if cprops else None
        self.c.connect(HOST, PORT, keepalive=60, clean_start=clean, properties=p)
        self.c.loop_start()
        return self.expect("connack")

    def sub(self, topics, **sprops):
        p = props(PacketTypes.SUBSCRIBE, **sprops) if sprops else None
        self.c.subscribe(topics, properties=p)
        return self.expect("suback")

    def pub(self, topic, payload, qos=0, retain=False, **pprops):
        """Publish and wait for paho's on_publish of THIS message (by mid):
        the ack for QoS 1/2, the send for QoS 0 — which fires too, and would
        otherwise answer a later publish's wait."""
        p = props(PacketTypes.PUBLISH, **pprops) if pprops else None
        info = self.c.publish(topic, payload, qos=qos, retain=retain, properties=p)
        while True:
            ev = self.expect("puback")
            if ev[1] == info.mid:
                return ev if qos > 0 else None
            raise SystemExit(f"on_publish for mid {ev[1]}, waiting for {info.mid}")

    def bye(self):
        self.c.disconnect()
        self.expect("disconnect")
        self.c.loop_stop()

    def drop(self):
        """End the TCP connection without a DISCONNECT."""
        self.c.loop_stop()
        self.c.socket().close()


# 1. CONNACK as paho sees it, an assigned client id.
p1 = C("")
ev = p1.connect(UserProperty=[("who", "paho")])
emit(step="connack", present=ev[1], reason=ev[2], props=ev[3])

# 2. Subscribe with a Subscription Identifier.
ev = p1.sub([("zp/#", SubscribeOptions(qos=2))], SubscriptionIdentifier=5)
emit(step="suback", codes=ev[2])

# 3. QoS 0/1/2 with properties; each comes back through the subscription.
for q in (0, 1, 2):
    ack = p1.pub(f"zp/q{q}", f"m{q}", qos=q, UserProperty=[("a", "1"), ("b", "2")], ResponseTopic="zp/reply",
                 CorrelationData=b"\x00\x2a", ContentType="text/plain", PayloadFormatIndicator=1,
                 MessageExpiryInterval=120)
    if ack:
        emit(step=f"ack-q{q}", reason=ack[2])
    m = p1.expect("message")
    emit(step=f"echo-q{q}", topic=m[1], payload=m[2], qos=m[3], props=m[5])

# 4. Nobody subscribed: 0x10.
ack = p1.pub("nosub/x", "z", qos=1)
emit(step="nosub", reason=ack[2])

# 5. A Topic Alias set, then used alone.
p1.pub("zp/alias", "first", TopicAlias=3)
m1 = p1.expect("message")
p1.pub("", "second", TopicAlias=3)
m2 = p1.expect("message")
emit(step="alias", topics=[m1[1], m2[1]], payloads=[m1[2], m2[2]])

# 6. A Shared Subscription across two clients: two messages each.
p2 = C("p2")
p2.connect()
p3 = C("p3")
p3.connect()
p2.sub([("$share/grp/zs/+", SubscribeOptions(qos=0))])
p3.sub([("$share/grp/zs/+", SubscribeOptions(qos=0))])
for i in range(4):
    p1.pub("zs/1", f"s{i}")
got2, got3 = [], []
for _ in range(2):
    got2.append(p2.expect("message")[2])
    got3.append(p3.expect("message")[2])
emit(step="shared", p2=got2, p3=got3, extra2=p2.none() is None, extra3=p3.none() is None)

# 7. No Local: the publisher's own message does not come back to it.
p1.sub([("zn", SubscribeOptions(qos=0, noLocal=True))])
p2.sub([("zn", SubscribeOptions(qos=0))])
p1.pub("zn", "local")
emit(step="nolocal", p2=p2.expect("message")[2], p1_quiet=p1.none() is None)

# 8. Retain As Published and Retain Handling.
p1.pub("zr", "kept", retain=True)
p2.sub([("zr", SubscribeOptions(qos=0, retainAsPublished=True))])
r = p2.expect("message")
p3.sub([("zr", SubscribeOptions(qos=0, retainHandling=2))])
emit(step="retain", retained=r[4], payload=r[2], rh2_quiet=p3.none() is None)
p1.pub("zr", "live", retain=True)
live = p2.expect("message")
emit(step="rap", retain=live[4])
p1.pub("zr", "", retain=True)  # clear it
p2.expect("message")

# 9. A Will with properties, after a connection that just ends.
p2.sub([("zw", SubscribeOptions(qos=0))])
p4 = C("p4")
p4.c.will_set("zw", "gone", qos=0, retain=False,
              properties=props(PacketTypes.WILLMESSAGE, ContentType="text/plain", UserProperty=[("why", "lost")]))
p4.connect()
p4.drop()
w = p2.expect("message")
emit(step="will", payload=w[2], props=w[5])

# 10. A session kept by its Session Expiry Interval, resumed with its queue.
p5 = C("p5")
p5.connect(clean=False, SessionExpiryInterval=60)
p5.sub([("zq", SubscribeOptions(qos=1))])
p5.bye()
p1.pub("zq", "q1", qos=1)
p1.pub("zq", "q2", qos=1)
p5 = C("p5")
ev = p5.connect(clean=False, SessionExpiryInterval=60)
q = [p5.expect("message")[2], p5.expect("message")[2]]
emit(step="resume", present=ev[1], queued=q)
p5.bye()

# 11. Take-over: the first connection is told, 0x8E.
p6 = C("dup")
p6.connect()
p7 = C("dup")
p7.connect()
emit(step="takeover", reason=p6.expect("disconnect")[1])
p6.c.loop_stop()
p7.bye()

# 12. UNSUBACK codes per filter.
p1.c.unsubscribe(["zn", "nothing"])
emit(step="unsuback", codes=p1.expect("unsuback")[2])

for c in (p1, p2, p3):
    c.bye()
emit(step="done")
