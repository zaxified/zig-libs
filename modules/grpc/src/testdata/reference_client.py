# The reference gRPC *client* for this module's server interop tests: Python
# `grpcio`, the implementation gRPC itself ships, pointed at OUR server.
#
# This is the stronger direction. A client that frames wrongly can still be
# understood by a lenient peer; a server that frames wrongly fails visibly,
# because the peer has to find every message boundary, the trailer section and
# the status without any help from us.
#
# Schema-driven at run time out of `descriptor_pb2` (no `.proto`, no protoc)
# and driven through grpc's *generic* stub API (no generated `_pb2_grpc`),
# exactly like `reference_server.py` — and against the same `echo.Echo`
# contract, so only the producer of the bytes has swapped sides.
#
# Output contract: one `KEY\tVALUE` line per observation on stdout, then
# `DONE`. The Zig side parses those and asserts on them. Every call carries a
# deadline, because a framing bug against a real peer does not fail — it
# HANGS, and a hang has to surface as a timeout rather than as a stuck suite.
# The watchdog below is the backstop for that: whatever happens, this process
# exits and the Zig side sees EOF.

import os
import sys
import threading

import grpc
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

_watchdog = threading.Timer(90, lambda: os._exit(7))
_watchdog.daemon = True  # must not keep a finished process alive
_watchdog.start()

_STRING = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
_INT32 = descriptor_pb2.FieldDescriptorProto.TYPE_INT32
_BYTES = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES

_SCHEMA = {
    "EchoRequest": (("text", 1, _STRING), ("count", 2, _INT32), ("blob", 3, _BYTES)),
    "EchoReply": (("text", 1, _STRING), ("index", 2, _INT32), ("blob", 3, _BYTES)),
}

_fdp = descriptor_pb2.FileDescriptorProto()
_fdp.name = "echo.proto"
_fdp.package = "echo"
_fdp.syntax = "proto3"

for msg_name, fields in _SCHEMA.items():
    m = _fdp.message_type.add()
    m.name = msg_name
    for fname, fnum, ftype in fields:
        f = m.field.add()
        f.name, f.number, f.type = fname, fnum, ftype
        f.label = descriptor_pb2.FieldDescriptorProto.LABEL_OPTIONAL

_pool = descriptor_pool.DescriptorPool()
_pool.Add(_fdp)
EchoRequest = message_factory.GetMessageClass(_pool.FindMessageTypeByName("echo.EchoRequest"))
EchoReply = message_factory.GetMessageClass(_pool.FindMessageTypeByName("echo.EchoReply"))

T = 20  # per-call deadline, seconds


def ser(m):
    return m.SerializeToString()


def de(b):
    m = EchoReply()
    m.ParseFromString(b)
    return m


def out(key, value):
    sys.stdout.write("%s\t%s\n" % (key, value))
    sys.stdout.flush()


def md_get(pairs, name):
    for k, v in pairs or ():
        if k == name:
            return v
    return None


PROBE_BIN = bytes([0x00, 0x01, 0xFE, 0xFF, 0x0A, 0x25])


def main():
    port = int(sys.argv[1])
    ch = grpc.insecure_channel(
        "127.0.0.1:%d" % port,
        options=[
            ("grpc.max_send_message_length", 32 * 1024 * 1024),
            ("grpc.max_receive_message_length", 32 * 1024 * 1024),
        ],
    )

    def uu(p):
        return ch.unary_unary(p, request_serializer=ser, response_deserializer=de)

    def us(p):
        return ch.unary_stream(p, request_serializer=ser, response_deserializer=de)

    def su(p):
        return ch.stream_unary(p, request_serializer=ser, response_deserializer=de)

    def ss(p):
        return ch.stream_stream(p, request_serializer=ser, response_deserializer=de)

    # ── 1. unary ────────────────────────────────────────────────────────────
    rep, call = uu("/echo.Echo/Unary").with_call(
        EchoRequest(text="hello reference", count=7, blob=bytes([0x00, 0xFF, 0x10])),
        timeout=T,
    )
    out("unary.text", rep.text)
    out("unary.index", rep.index)
    out("unary.blob", rep.blob.hex())
    out("unary.code", call.code().name)

    # ── 2. server-streaming ─────────────────────────────────────────────────
    it = us("/echo.Echo/ServerStream")(EchoRequest(text="tick", count=5), timeout=T)
    texts = [r.text for r in it]
    out("serverstream.texts", ",".join(texts))
    out("serverstream.code", it.code().name)

    # ── 3. client-streaming ─────────────────────────────────────────────────
    reqs = iter([EchoRequest(text=t) for t in ("a", "bb", "ccc")])
    rep, call = su("/echo.Echo/ClientStream").with_call(reqs, timeout=T)
    out("clientstream.text", rep.text)
    out("clientstream.index", rep.index)
    out("clientstream.code", call.code().name)

    # ── 4. bidirectional, genuinely interleaved ─────────────────────────────
    # The generator does not yield request N+1 until reply N has been read, so
    # the request half is still open while the response half is producing.
    # A server that buffered the request to END_STREAM before dispatching
    # would DEADLOCK here rather than return a wrong answer — which is why
    # this call, like every other, has a deadline and a watchdog behind it.
    words = ["one", "two", "three"]
    replies = []
    answered = threading.Semaphore(0)

    def gen():
        for w in words:
            yield EchoRequest(text=w)
            if not answered.acquire(timeout=T):
                return

    stream = ss("/echo.Echo/Bidi")(gen(), timeout=T)
    for r in stream:
        replies.append(r.text)
        answered.release()
        if len(replies) == len(words):
            break
    out("bidi.texts", ",".join(replies))

    # ── 5. an error before any message: Trailers-Only ───────────────────────
    # The detail deliberately contains bytes the grpc-message ABNF forbids, so
    # the reference's percent-DEcoder is validating our ENcoder.
    detail = "boom\nline two ☃ 100% done"
    try:
        uu("/echo.Echo/Fail").with_call(
            EchoRequest(text=detail, count=grpc.StatusCode.PERMISSION_DENIED.value[0]),
            timeout=T,
        )
        out("fail.code", "NO_ERROR_RAISED")
    except grpc.RpcError as e:
        out("fail.code", e.code().name)
        out("fail.details_match", "1" if e.details() == detail else "0")
        out("fail.details_repr", repr(e.details()))
        # Metadata that rode in the SAME single field block as the status.
        seen = md_get(e.trailing_metadata(), "x-why") or md_get(e.initial_metadata(), "x-why")
        out("fail.x_why", seen or "-")

    # ── 6. messages, then a status in a real trailer section ────────────────
    n = 0
    try:
        it = us("/echo.Echo/StreamFail")(EchoRequest(count=3), timeout=T)
        for _ in it:
            n += 1
        out("streamfail.code", "NO_ERROR_RAISED")
    except grpc.RpcError as e:
        out("streamfail.code", e.code().name)
        out("streamfail.details", e.details())
    out("streamfail.count", n)

    # ── 7. an unknown method ────────────────────────────────────────────────
    try:
        uu("/echo.Echo/NoSuchMethod").with_call(EchoRequest(), timeout=T)
        out("unknown.code", "NO_ERROR_RAISED")
    except grpc.RpcError as e:
        out("unknown.code", e.code().name)
        out("unknown.details", e.details())

    # ── 8. metadata, both sections, ASCII and -bin ──────────────────────────
    rep, call = uu("/echo.Echo/Meta").with_call(
        EchoRequest(),
        timeout=T,
        metadata=(("x-probe", "probe-value"), ("x-probe-bin", PROBE_BIN)),
    )
    out("meta.body_text", rep.text)
    out("meta.body_blob", rep.blob.hex())
    out("meta.initial_ascii", md_get(call.initial_metadata(), "x-echo"))
    ib = md_get(call.initial_metadata(), "x-echo-bin")
    out("meta.initial_bin", ib.hex() if isinstance(ib, bytes) else "NOT_BYTES")
    out("meta.trailing_ascii", md_get(call.trailing_metadata(), "x-tail"))
    tb = md_get(call.trailing_metadata(), "x-tail-bin")
    out("meta.trailing_bin", tb.hex() if isinstance(tb, bytes) else "NOT_BYTES")
    # Decisive: a field the reference reports as TRAILING must not also have
    # been read as initial. If our server put the trailer fields in the head,
    # this flips.
    out("meta.tail_not_initial", "1" if md_get(call.initial_metadata(), "x-tail") is None else "0")

    # ── 9. grpc-timeout reaches the server ──────────────────────────────────
    # The server reports a band rather than a number, so the assertion is
    # exact against a real clock: 1 = "a deadline in (25 s, 30 s]", which only
    # happens if it parsed both our value AND our unit.
    rep, _ = uu("/echo.Echo/Deadline").with_call(EchoRequest(), timeout=30)
    out("deadline.band", rep.index)
    out("deadline.raw", rep.text)  # the reference's own grpc-timeout rendering
    rep, _ = uu("/echo.Echo/Deadline").with_call(EchoRequest())
    out("deadline.none", rep.index)

    # ── 10. a reply large enough to span many DATA frames ───────────────────
    rep, call = uu("/echo.Echo/Big").with_call(EchoRequest(count=48 * 1024), timeout=T)
    out("big.len", len(rep.blob))
    out("big.all_5a", "1" if set(rep.blob) == {0x5A} else "0")

    # ── 11. a REQUEST over the server's receive limit ───────────────────────
    try:
        uu("/echo.Echo/Unary").with_call(EchoRequest(blob=b"x" * (128 * 1024)), timeout=T)
        out("toolarge.code", "NO_ERROR_RAISED")
    except grpc.RpcError as e:
        out("toolarge.code", e.code().name)

    # ── 12. a successful call that produces no message ──────────────────────
    it = us("/echo.Echo/Empty")(EchoRequest(), timeout=T)
    out("empty.count", len(list(it)))
    out("empty.code", it.code().name)

    out("DONE", "1")
    ch.close()


main()
