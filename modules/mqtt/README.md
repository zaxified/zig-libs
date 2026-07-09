# mqtt

Pure-Zig **MQTT 3.1.1 client + broker**: control-packet codec, a client state
machine and a server (broker). Pairs with `modbus` for the IoT / industrial
(SCADA-sim) work: a typed, allocation-free wire codec plus a
transport-agnostic client and a broker, all fully offline-testable.

- **Status:** gap — no mature pure-Zig MQTT library exists.
- **Platform:** any (codec + client are pure computation; only the optional
  `TcpTransport` adapter touches `std.Io.net`).
- **Model after:** MQTT 3.1.1 (OASIS) / mosquitto+paho behavior.
- **Scope:**
  - **Codec** (`packet`): encode + decode for all 14 control-packet types —
    CONNECT (clean session, keep-alive, will topic/message/QoS/retain,
    username/password), CONNACK (typed return codes 0 accepted / 1–5
    refused), PUBLISH (QoS 0/1/2, DUP, RETAIN, packet id for QoS > 0),
    PUBACK, PUBREC, PUBREL, PUBCOMP, SUBSCRIBE (per-filter requested QoS),
    SUBACK (granted QoS incl. 0x80 failure), UNSUBSCRIBE, UNSUBACK,
    PINGREQ, PINGRESP, DISCONNECT. Remaining-length varint (1–4 bytes,
    max 268 435 455) with malformed/overlong guards; 2-byte-length-prefixed
    UTF-8 strings validated (U+0000 and bad UTF-8 rejected). Decode is
    zero-copy and stream-friendly: `null` means "need more bytes";
    malformed/hostile bytes return typed errors, never a panic.
  - **Topics** (`topic`): `matches(filter, topic)` with the `+`
    single-level and trailing-`#` multi-level wildcard rules and the
    `$`-topic exclusion for leading wildcards; `validateName` /
    `validateFilter` per spec 4.7.
  - **Client** (`Client`): behind a caller-provided `Transport` write seam;
    incoming bytes via `feed`, `poll(now)` decodes server packets, advances
    the QoS state machines on both sides — QoS 1 PUBLISH→PUBACK, QoS 2
    PUBLISH→PUBREC→PUBREL→PUBCOMP with automatic acks and exactly-once
    dedup on receive — and surfaces typed events (connack, message, puback,
    pubcomp, suback, unsuback, pingresp). Bounded packet-id pool (wrap
    65535→1, in-use guard). Caller drives the clock (`now` in ms, no hidden
    time calls); `tick` sends keep-alive PINGREQ and reports ping timeouts.
    `publishDup` retransmits an unacked QoS > 0 publish with the DUP flag.
    Retained-session replay (buffering payloads) is deliberately the
    caller's job.
  - **Broker** (`Broker`): the server side, and the mirror image of `Client`
    — the broker owns the shared state (the connection set, the subscription
    registry and the retained store) and each `Connection` is a reversed
    per-connection state machine. Same caller-driven, socket-free seam,
    reversed: outgoing bytes to a client go through that connection's
    `Transport`; incoming bytes go to `Broker.feed`; `Broker.process(conn,
    now)` decodes buffered packets, drives the connection's state machine and
    fans PUBLISHes out to every matching subscription. `now` (ms) is passed in
    — no hidden clock — so the whole broker is drivable from in-memory buffers
    in tests. `broker.TcpServer` is an optional `std.Io.net` accept loop
    (thread-per-connection, one spinlock around the shared registry); tests
    never listen or dial.

    **First-cut broker scope (3.1.1):** CONNECT/CONNACK (protocol name+level
    validated, client-id assigned — empty → server-generated — or rejected,
    session take-over on a duplicate client-id, `session_present` always false
    / clean-session only, keep-alive deadline = 1.5 × the client's keep-alive
    checked against a caller-supplied last-packet timestamp); SUBSCRIBE/SUBACK
    and UNSUBSCRIBE/UNSUBACK over a flat verbatim-filter registry (exact-string
    UNSUBSCRIBE, `topic.matches` per PUBLISH — correct, no trie at this scale);
    PUBLISH fan-out at min(publisher QoS, granted QoS), one copy per connection
    at the highest granted QoS among overlapping filters; QoS 0 fire-and-forget
    and QoS 1 (inbound → immediate PUBACK; outbound → an id allocated in the
    *subscriber's* id space, tracked pending until its PUBACK); a retained
    store (empty payload clears; matching retained delivered right after a new
    SUBACK).

    **Deliberately deferred (documented, not built):** QoS 2
    (PUBREC/PUBREL/PUBCOMP — an inbound QoS 2 PUBLISH tears the connection
    down), persistent / offline sessions (clean-session only), DUP retransmit
    of an unacked outbound publish, Will / LWT, MQTT 5.0, and TLS (terminate in
    front and hand `TcpServer` plaintext, or drive the socket-free core over a
    TLS stream).

```zig
const mqtt = @import("mqtt");

var tt = try mqtt.TcpTransport.connect(io, address); // or any Transport impl
defer tt.close();
var rx: [4096]u8 = undefined;
var tx: [4096]u8 = undefined;
var client = mqtt.Client.init(tt.transport(), .{ .rx = &rx, .tx = &tx });

try client.connect(now(), .{ .client_id = "sensor-1", .keep_alive_s = 30 });
_ = try client.subscribe(now(), &.{.{ .filter = "plant/+/state" }});
_ = try client.publish(now(), "plant/1/cmd", "on", .{ .qos = .at_least_once });

// pump loop: read → feed → poll → tick
const n = try tt.readSome(&net_buf);
try client.feed(net_buf[0..n]);
while (try client.poll(now())) |event| switch (event) {
    .message => |m| handle(m.topic, m.payload),
    else => {},
};
try client.tick(now());
```

Tests are fully offline: golden-byte known-answer tests against the spec's
wire layout (CONNECT with will + credentials, CONNACK, QoS 1 PUBLISH
round-trip, SUBSCRIBE/SUBACK with mixed granted QoS incl. 0x80, all
remaining-length varint boundary values with overlong/5-byte rejection), a
scripted fake broker drives the full QoS 1 and QoS 2 handshakes, DUP
retransmission and dedup, keep-alive/ping timeout, packet-id wrap and pool
exhaustion, plus a topic-match truth table and 2×1000-iteration
garbage-byte no-panic sweeps (codec and client). The broker tests mirror the
same seam reversed — a scripted fake *client* hand-encodes raw
CONNECT/SUBSCRIBE/PUBLISH bytes against broker-side connection objects (no
socket): connect fan-in, subscribe→SUBACK→delivery, overlapping-filter
single-copy fan-out, retain-before-subscribe, QoS 1 PUBACK + broker-assigned
delivery id, exact-string unsubscribe, PINGRESP, DISCONNECT, keep-alive
teardown, session take-over, and a 1000-iteration hostile-byte no-panic sweep;
the `TcpServer` accept loop is compile-checked but gated behind
`error.SkipZigTest`.

Provenance: clean-room from the OASIS MQTT Version 3.1.1 specification
(open standard, royalty-free); mosquitto (EPL/EDL) and Eclipse Paho
referenced for behavior only, no source consulted or copied.
