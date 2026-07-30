# The reference gRPC server for this module's interop tests: Python `grpcio`,
# the implementation gRPC itself ships.
#
# It is deliberately schema-driven at run time — the `echo.EchoRequest` /
# `echo.EchoReply` descriptors are built here out of `descriptor_pb2`, so no
# `.proto` file and no `protoc` participate, exactly as in the `protobuf`
# module's reference driver. Handlers are registered through grpc's *generic*
# handler API for the same reason: no generated `_pb2_grpc` stubs.
#
# It binds 127.0.0.1 on an ephemeral port and prints `PORT <n>` on stdout,
# which is the whole handshake with the Zig side.
import sys
from concurrent import futures

import grpc
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory

_fdp = descriptor_pb2.FileDescriptorProto()
_fdp.name = "echo.proto"
_fdp.package = "echo"
_fdp.syntax = "proto3"

_STRING = descriptor_pb2.FieldDescriptorProto.TYPE_STRING
_INT32 = descriptor_pb2.FieldDescriptorProto.TYPE_INT32
_BYTES = descriptor_pb2.FieldDescriptorProto.TYPE_BYTES

# Field 2 is deliberately named differently in the two messages ("count" in
# the request, "index" in the reply) so a mixed-up schema shows up as an
# error rather than as a plausible value.
_SCHEMA = {
    "EchoRequest": (("text", 1, _STRING), ("count", 2, _INT32), ("blob", 3, _BYTES)),
    "EchoReply": (("text", 1, _STRING), ("index", 2, _INT32), ("blob", 3, _BYTES)),
}

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

_CODES = {c.value[0]: c for c in grpc.StatusCode}


def ser(m):
    return m.SerializeToString()


def de(b):
    m = EchoRequest()
    m.ParseFromString(b)
    return m


def unary(req, ctx):
    """text -> "echo:"+text, count -> index. Also mirrors blob back."""
    return EchoReply(text="echo:" + req.text, index=req.count, blob=req.blob)


def server_stream(req, ctx):
    for i in range(req.count):
        yield EchoReply(text="%s-%d" % (req.text, i), index=i)


def client_stream(reqs, ctx):
    parts, n = [], 0
    for r in reqs:
        parts.append(r.text)
        n += 1
    return EchoReply(text="|".join(parts), index=n)


def bidi(reqs, ctx):
    i = 0
    for r in reqs:
        yield EchoReply(text="re:" + r.text, index=i)
        i += 1


def fail(req, ctx):
    """Aborts before any initial metadata -> a Trailers-Only response."""
    ctx.abort(_CODES.get(req.count, grpc.StatusCode.UNKNOWN), req.text)


def stream_fail(req, ctx):
    """Sends `count` messages and THEN aborts -> HEADERS, DATA..., TRAILERS
    carrying a non-OK grpc-status. The other half of the error story."""
    for i in range(req.count):
        yield EchoReply(text="partial-%d" % i, index=i)
    ctx.abort(grpc.StatusCode.DATA_LOSS, "gave up after %d" % req.count)


def big(req, ctx):
    """A reply whose serialized size is driven by the caller — the message
    the receive limit exists for."""
    return EchoReply(text="big", index=req.count, blob=b"\x5a" * req.count)


def meta(req, ctx):
    """Echoes the request metadata back through both metadata sections."""
    md = dict(ctx.invocation_metadata())
    ascii_v = md.get("x-probe", "-")
    bin_v = md.get("x-probe-bin", b"")
    ctx.send_initial_metadata((("x-echo", ascii_v), ("x-echo-bin", bin_v)))
    ctx.set_trailing_metadata((("x-tail", ascii_v), ("x-tail-bin", bin_v)))
    return EchoReply(text=ascii_v, index=len(bin_v), blob=bin_v)


def deadline(req, ctx):
    """Reports the deadline the client asked for, in milliseconds remaining
    (rounded down to 100 ms so the value is stable)."""
    left = ctx.time_remaining()
    # With no deadline set, grpcio reports an effectively infinite remainder
    # rather than None, so anything absurd is reported as "no deadline".
    if left is None or left > 86400:
        return EchoReply(text="deadline", index=-1)
    return EchoReply(text="deadline", index=int(left * 1000) // 100 * 100)


HANDLERS = {
    "Unary": grpc.unary_unary_rpc_method_handler(unary, de, ser),
    "ServerStream": grpc.unary_stream_rpc_method_handler(server_stream, de, ser),
    "ClientStream": grpc.stream_unary_rpc_method_handler(client_stream, de, ser),
    "Bidi": grpc.stream_stream_rpc_method_handler(bidi, de, ser),
    "Fail": grpc.unary_unary_rpc_method_handler(fail, de, ser),
    "StreamFail": grpc.unary_stream_rpc_method_handler(stream_fail, de, ser),
    "Big": grpc.unary_unary_rpc_method_handler(big, de, ser),
    "Meta": grpc.unary_unary_rpc_method_handler(meta, de, ser),
    "Deadline": grpc.unary_unary_rpc_method_handler(deadline, de, ser),
}


def main():
    s = grpc.server(
        futures.ThreadPoolExecutor(max_workers=4),
        options=[
            ("grpc.max_send_message_length", 32 * 1024 * 1024),
            ("grpc.max_receive_message_length", 32 * 1024 * 1024),
        ],
    )
    s.add_generic_rpc_handlers((grpc.method_handlers_generic_handler("echo.Echo", HANDLERS),))
    port = s.add_insecure_port("127.0.0.1:0")
    s.start()
    sys.stdout.write("PORT %d\n" % port)
    sys.stdout.flush()
    s.wait_for_termination()


main()
