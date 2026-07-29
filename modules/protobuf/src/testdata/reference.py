# SPDX-License-Identifier: MIT
#
# Reference driver for the protobuf module's interop tests.
#
# Builds message descriptors AT RUNTIME with google.protobuf.descriptor_pb2 +
# descriptor_pool + message_factory, so no .proto file and no protoc are
# needed -- only `pip install protobuf`. The schemas below mirror the Zig
# fixtures in ../codec_test.zig field-for-field; the CASES table holds the
# same values the Zig tests build, keyed by name, so neither side has to
# marshal values across the process boundary.
#
# Usage (cwd = a scratch dir):
#   python3 reference.py ref_encode <case>   -> writes out.bin
#   python3 reference.py dump <case>         -> reads in.bin, writes out.txt
#   python3 reference.py selftest            -> sanity check, no files

import sys
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

# (name, number, type, cardinality, extra)
#   cardinality: "" singular implicit | "opt" explicit presence | "rep" repeated
#   extra: type name for message/enum, or "unpacked"
SCHEMAS = {
    "Inner": [
        ("v", 1, "int32", "", None),
        ("note", 2, "string", "", None),
    ],
    "Wide": [
        ("i32_", 1, "int32", "", None),
        ("i64_", 2, "int64", "", None),
        ("u32_", 3, "uint32", "", None),
        ("u64_", 4, "uint64", "", None),
        ("s32", 5, "sint32", "", None),
        ("s64", 6, "sint64", "", None),
        ("b", 7, "bool", "", None),
        ("color", 8, "enum", "", ".pb.Color"),
        ("f64_", 9, "fixed64", "", None),
        ("sf64", 10, "sfixed64", "", None),
        ("d", 11, "double", "", None),
        ("f32_", 12, "fixed32", "", None),
        ("sf32", 13, "sfixed32", "", None),
        ("f", 14, "float", "", None),
        ("s", 15, "string", "", None),
        ("raw", 16, "bytes", "", None),
        ("inner", 17, "message", "opt", ".pb.Inner"),
    ],
    "Repeated": [
        ("nums", 1, "int32", "rep", None),
        ("unpacked", 2, "int32", "rep", "unpacked"),
        ("zz", 3, "sint64", "rep", None),
        ("fixed", 4, "fixed32", "rep", None),
        ("flags", 5, "bool", "rep", None),
        ("colors", 6, "enum", "rep", ".pb.Color"),
        ("names", 7, "string", "rep", None),
        ("inners", 8, "message", "rep", ".pb.Inner"),
    ],
    "Presence": [
        ("implicit", 1, "int32", "", None),
        ("explicit", 2, "int32", "opt", None),
        ("implicit_str", 3, "string", "", None),
        ("explicit_str", 4, "string", "opt", None),
    ],
    "Chain": [
        ("depth", 1, "int32", "", None),
        ("next", 2, "message", "opt", ".pb.Chain"),
    ],
}

ORDER = ["Inner", "Wide", "Repeated", "Presence", "Chain"]


def build_pool():
    fdp = dp.FileDescriptorProto()
    fdp.name = "zig_libs_protobuf.proto"
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
            f.name = name
            f.number = number
            f.type = TYPE[ftype]
            if extra and extra.startswith("."):
                f.type_name = extra
            if card == "rep":
                f.label = F.LABEL_REPEATED
                if extra == "unpacked":
                    f.options.packed = False
            else:
                f.label = F.LABEL_OPTIONAL
            if card == "opt" and ftype != "message":
                # proto3 explicit presence == a synthetic one-field oneof.
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


def cls(name):
    desc = POOL.FindMessageTypeByName("pb." + name)
    try:
        return message_factory.GetMessageClass(desc)
    except AttributeError:  # protobuf < 4.22
        return message_factory.MessageFactory(POOL).GetPrototype(desc)


MIN32, MAX32 = -(2 ** 31), 2 ** 31 - 1
MIN64, MAX64 = -(2 ** 63), 2 ** 63 - 1
UMAX32, UMAX64 = 2 ** 32 - 1, 2 ** 64 - 1

# name -> (message type, {field: value}). Mirrors the Zig table exactly.
CASES = {
    "spec150":      ("Wide", {"i32_": 150}),
    "neg_int32":    ("Wide", {"i32_": -1}),
    "neg_int64":    ("Wide", {"i64_": -2}),
    "min_int32":    ("Wide", {"i32_": MIN32}),
    "min_int64":    ("Wide", {"i64_": MIN64}),
    "zigzag_neg":   ("Wide", {"s32": -1, "s64": -1}),
    "zigzag_pos":   ("Wide", {"s32": 1, "s64": 1}),
    "zigzag_min":   ("Wide", {"s32": MIN32, "s64": MIN64}),
    "zigzag_max":   ("Wide", {"s32": MAX32, "s64": MAX64}),
    "unsigned_max": ("Wide", {"u32_": UMAX32, "u64_": UMAX64}),
    "varint_edges": ("Wide", {"u64_": 127}),
    "varint_128":   ("Wide", {"u64_": 128}),
    "bool_enum":    ("Wide", {"b": True, "color": 2}),
    "enum_open":    ("Wide", {"color": 9999}),
    "fixed_all":    ("Wide", {"f64_": UMAX64, "sf64": MIN64, "f32_": UMAX32, "sf32": MIN32}),
    "floats":       ("Wide", {"d": -1.5e300, "f": 3.5}),
    "float_frac":   ("Wide", {"d": 0.1, "f": 0.1}),
    "strings":      ("Wide", {"s": "unicode: ěščřž \U0001f389",
                              "raw": bytes([0x00, 0xff, 0x7f, 0x80])}),
    "submessage":   ("Wide", {"inner": {"v": -9, "note": "n"}}),
    "empty":        ("Wide", {}),
    "packed":       ("Repeated", {"nums": [1, 2, 150]}),
    "packed_neg":   ("Repeated", {"nums": [-1, 0, 1, 150, MAX32]}),
    "unpacked":     ("Repeated", {"unpacked": [1, 2, 150]}),
    "rep_zigzag":   ("Repeated", {"zz": [-1, 1, MIN64]}),
    "rep_fixed":    ("Repeated", {"fixed": [0, 0xdeadbeef]}),
    "rep_bool":     ("Repeated", {"flags": [True, False, True]}),
    "rep_enum":     ("Repeated", {"colors": [1, 2, 77]}),
    "rep_string":   ("Repeated", {"names": ["", "a", "long-ish string"]}),
    "rep_message":  ("Repeated", {"inners": [{"v": 1}, {"v": 2, "note": "x"}]}),
    "rep_empty":    ("Repeated", {}),
    "pres_default": ("Presence", {"implicit": 0}),
    "pres_set":     ("Presence", {"implicit": 1}),
    "pres_expl_0":  ("Presence", {"explicit": 0}),
    "pres_expl_5":  ("Presence", {"explicit": 5}),
    "pres_str_0":   ("Presence", {"explicit_str": ""}),
    "chain3":       ("Chain", {"depth": 1, "next": {"depth": 2, "next": {"depth": 3}}}),
}


def populate(msg, values):
    for k, v in values.items():
        fd = msg.DESCRIPTOR.fields_by_name[k]
        if fd.label == fd.LABEL_REPEATED:
            if fd.type == fd.TYPE_MESSAGE:
                for item in v:
                    populate(getattr(msg, k).add(), item)
            else:
                getattr(msg, k).extend(v)
        elif fd.type == fd.TYPE_MESSAGE:
            populate(getattr(msg, k), v)
        else:
            setattr(msg, k, v)


def make(case):
    msg_name, values = CASES[case]
    msg = cls(msg_name)()
    populate(msg, values)
    return msg


def fmt(fd, v):
    if fd.type == fd.TYPE_BOOL:
        return "true" if v else "false"
    if fd.type in (fd.TYPE_DOUBLE, fd.TYPE_FLOAT):
        return float(v).hex()
    if fd.type == fd.TYPE_BYTES:
        return v.hex()
    if fd.type == fd.TYPE_STRING:
        return v
    if fd.type == fd.TYPE_MESSAGE:
        return "{" + dump(v).replace("\n", ";") + "}"
    return str(int(v))


def dump(msg):
    """Deterministic listing of EVERY field, defaults included, in field-number
    order -- so a value that decoded wrongly to a default is still visible."""
    lines = []
    for fd in sorted(msg.DESCRIPTOR.fields, key=lambda f: f.number):
        v = getattr(msg, fd.name)
        if fd.label == fd.LABEL_REPEATED:
            lines.append("%s=[%s]" % (fd.name, ",".join(fmt(fd, x) for x in v)))
        elif fd.type == fd.TYPE_MESSAGE:
            lines.append("%s=%s" % (fd.name, fmt(fd, v) if msg.HasField(fd.name) else "<unset>"))
        elif fd.has_presence:
            lines.append("%s=%s" % (fd.name, fmt(fd, v) if msg.HasField(fd.name) else "<unset>"))
        else:
            lines.append("%s=%s" % (fd.name, fmt(fd, v)))
    return "\n".join(lines)


def main(argv):
    op = argv[1]
    if op == "selftest":
        for name in CASES:
            msg = make(name)
            raw = msg.SerializeToString(deterministic=True)
            back = cls(CASES[name][0])()
            back.ParseFromString(raw)
            assert dump(back) == dump(msg), name
            print("%-14s %s" % (name, raw.hex()))
        return 0
    case = argv[2]
    msg_name = CASES[case][0]
    if op == "ref_encode":
        with open("out.bin", "wb") as fh:
            fh.write(make(case).SerializeToString(deterministic=True))
    elif op == "dump":
        msg = cls(msg_name)()
        # ParseFromString raises on malformed input -> non-zero exit, which
        # the Zig side reports as error.ReferenceRejected.
        msg.ParseFromString(open("in.bin", "rb").read())
        with open("out.txt", "w") as fh:
            fh.write(dump(msg))
    elif op == "expect_dump":
        with open("out.txt", "w") as fh:
            fh.write(dump(make(case)))
    else:
        raise SystemExit("unknown op " + op)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
