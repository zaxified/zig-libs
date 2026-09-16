#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""The reference side of the differential rig: Google's own protobuf, behind the
same line protocol `probe.zig` speaks.

WHY THIS EXISTS. The module's committed tests replay bytes that a reference run
froze once (`../src/testdata/`). That proves we still agree with a recording. It
cannot answer "what does the reference do with THIS input", and for a wire format
the interesting inputs are the ones no correct encoder emits — non-minimal
varints, wire type 7, a length claiming 4 GiB. This puts the reference behind a
pipe so any input at all can be put to both sides.

⚠ IT BUILDS DESCRIPTORS AT RUN TIME (`descriptor_pb2` + `descriptor_pool` +
`message_factory`), so there is no `.proto` file and no `protoc` — only
`pip install protobuf`. The schemas below must stay field-for-field identical to
`probe.zig`'s; if they drift, the rig keeps running and stops comparing what you
think it compares.

WHAT IT NEEDS. `pip install protobuf`.

    echo 'd Wide 08ff01' | python3 oracle.py
    python3 oracle.py --impl        # which implementation is installed (upb/python)

WHAT IT PRODUCES. One line per input line: `OK <dump>` or `ERR <reason>`, where
the dump is canonical and ordered by field number so it can be string-compared
with the Zig side's.
"""
import sys, struct
from google.protobuf import descriptor_pb2 as dp
from google.protobuf import descriptor_pool, message_factory

F = dp.FieldDescriptorProto
TYPE = {
    "int32": F.TYPE_INT32, "int64": F.TYPE_INT64,
    "uint32": F.TYPE_UINT32, "uint64": F.TYPE_UINT64,
    "sint32": F.TYPE_SINT32, "sint64": F.TYPE_SINT64,
    "bool": F.TYPE_BOOL, "enum": F.TYPE_ENUM,
    "fixed64": F.TYPE_FIXED64, "sfixed64": F.TYPE_SFIXED64, "double": F.TYPE_DOUBLE,
    "fixed32": F.TYPE_FIXED32, "sfixed32": F.TYPE_SFIXED32, "float": F.TYPE_FLOAT,
    "string": F.TYPE_STRING, "bytes": F.TYPE_BYTES, "message": F.TYPE_MESSAGE,
}

SCHEMAS = {
    "Inner": [("v", 1, "int32", "", None), ("note", 2, "string", "", None)],
    "Wide": [
        ("i32_", 1, "int32", "", None), ("i64_", 2, "int64", "", None),
        ("u32_", 3, "uint32", "", None), ("u64_", 4, "uint64", "", None),
        ("s32", 5, "sint32", "", None), ("s64", 6, "sint64", "", None),
        ("b", 7, "bool", "", None), ("color", 8, "enum", "", ".pb.Color"),
        ("f64_", 9, "fixed64", "", None), ("sf64", 10, "sfixed64", "", None),
        ("d", 11, "double", "", None), ("f32_", 12, "fixed32", "", None),
        ("sf32", 13, "sfixed32", "", None), ("f", 14, "float", "", None),
        ("s", 15, "string", "", None), ("raw", 16, "bytes", "", None),
        ("inner", 17, "message", "opt", ".pb.Inner"),
    ],
    "Repeated": [
        ("nums", 1, "int32", "rep", None), ("unpacked", 2, "int32", "rep", "unpacked"),
        ("zz", 3, "sint64", "rep", None), ("fixed", 4, "fixed32", "rep", None),
        ("flags", 5, "bool", "rep", None), ("colors", 6, "enum", "rep", ".pb.Color"),
        ("names", 7, "string", "rep", None), ("inners", 8, "message", "rep", ".pb.Inner"),
    ],
    "Presence": [
        ("implicit", 1, "int32", "", None), ("explicit", 2, "int32", "opt", None),
        ("implicit_str", 3, "string", "", None), ("explicit_str", 4, "string", "opt", None),
    ],
    "Chain": [("depth", 1, "int32", "", None), ("next", 2, "message", "opt", ".pb.Chain")],
}
ORDER = ["Inner", "Wide", "Repeated", "Presence", "Chain"]


def build_pool():
    fdp = dp.FileDescriptorProto()
    fdp.name = "audit_pb.proto"
    fdp.package = "pb"
    fdp.syntax = "proto3"
    e = fdp.enum_type.add()
    e.name = "Color"
    for n, v in (("COLOR_UNSPECIFIED", 0), ("COLOR_RED", 1), ("COLOR_GREEN", 2)):
        ev = e.value.add()
        ev.name, ev.number = n, v
    for msg_name in ORDER:
        m = fdp.message_type.add()
        m.name = msg_name
        synthetic = []
        for (name, number, ftype, card, extra) in SCHEMAS[msg_name]:
            f = m.field.add()
            f.name, f.number, f.type = name, number, TYPE[ftype]
            if extra and extra.startswith("."):
                f.type_name = extra
            if card == "rep":
                f.label = F.LABEL_REPEATED
                if extra == "unpacked":
                    f.options.packed = False
            else:
                f.label = F.LABEL_OPTIONAL
            if card == "opt" and ftype != "message":
                synthetic.append((f, name))
        for (f, name) in synthetic:
            f.proto3_optional = True
            f.oneof_index = len(m.oneof_decl)
            od = m.oneof_decl.add()
            od.name = "_" + name
    pool = descriptor_pool.DescriptorPool()
    pool.Add(fdp)
    return pool


POOL = build_pool()
_CLS = {}


def cls(name):
    if name not in _CLS:
        desc = POOL.FindMessageTypeByName("pb." + name)
        try:
            _CLS[name] = message_factory.GetMessageClass(desc)
        except AttributeError:
            _CLS[name] = message_factory.MessageFactory(POOL).GetPrototype(desc)
    return _CLS[name]


def fmt(fd, v):
    if fd.type == fd.TYPE_BOOL:
        return "1" if v else "0"
    if fd.type == fd.TYPE_FLOAT:
        return "f32:%08x" % struct.unpack("<I", struct.pack("<f", v))[0]
    if fd.type == fd.TYPE_DOUBLE:
        return "f64:%016x" % struct.unpack("<Q", struct.pack("<d", v))[0]
    if fd.type == fd.TYPE_BYTES:
        return "h" + v.hex()
    if fd.type == fd.TYPE_STRING:
        return "h" + v.encode("utf-8", "surrogatepass").hex()
    if fd.type == fd.TYPE_MESSAGE:
        return "{" + dump(v) + "}"
    return str(int(v))


def dump(msg):
    parts = []
    for fd in sorted(msg.DESCRIPTOR.fields, key=lambda f: f.number):
        v = getattr(msg, fd.name)
        if fd.label == fd.LABEL_REPEATED:
            parts.append("%s=[%s]" % (fd.name, ",".join(fmt(fd, x) for x in v)))
        elif fd.type == fd.TYPE_MESSAGE or fd.has_presence:
            parts.append("%s=%s" % (fd.name, fmt(fd, v) if msg.HasField(fd.name) else "<unset>"))
        else:
            parts.append("%s=%s" % (fd.name, fmt(fd, v)))
    return ";".join(parts)


def main():
    out = []
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        parts = line.split(" ")
        op, schema = parts[0], parts[1]
        hexs = parts[2] if len(parts) > 2 else ""
        try:
            data = bytes.fromhex(hexs)
        except ValueError:
            out.append("ERR BadHex")
            continue
        # ⚠ An unknown schema name is ANSWERED, never raised. The campaigns pair
        # the two sides BY POSITION, so a line that produces no answer here
        # shifts every later answer by one and the rig compares mismatched
        # rows from then on. `probe.zig` answers `ERR NoSuchSchema` for the same
        # input; until 2026-09-16 this side died with a descriptor_pool KeyError.
        try:
            m = cls(schema)()
        except Exception:
            out.append("ERR NoSuchSchema")
            continue
        try:
            n = m.ParseFromString(data)
            # ⚠ Trailing bytes are a REJECTION here. ParseFromString stops at the
            # end of what it understood and reports how far it got; without this
            # check a truncated-length input would compare as "accepted" against
            # a Zig side that refuses it, and the divergence would be ours.
            if n != len(data):
                raise ValueError("trailing bytes")
        except Exception as ex:
            out.append("ERR %s" % type(ex).__name__)
            continue
        if op == "d":
            out.append("OK " + dump(m))
        else:
            try:
                out.append("OK " + m.SerializeToString(deterministic=True).hex())
            except Exception as ex:
                out.append("ERR ser:%s" % type(ex).__name__)
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    from google.protobuf.internal import api_implementation
    # A successful query, not a silent success: --impl answers a question and
    # exits, which is why this exit(0) is correct where chainhash.py's was not.
    if "--impl" in sys.argv:
        print(api_implementation.Type())
        sys.exit(0)
    main()
