#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/testdata/core_vectors.zig`: the reference implementation
(Python `protobuf`, Google's own, BSD-3-Clause; checked with 4.21.12, pure-
Python backend) driven as a BLACK-BOX oracle through its public API only --
descriptors built at run time with `descriptor_pb2`, the well-known types
from the package's own `*_pb2` modules. No protobuf source was read.

Run:  python3 gen_core_vectors.py > ../src/testdata/core_vectors.zig
      zig fmt ../src/testdata/core_vectors.zig

Captured
  * `c_cases`  -- for schema `C` (maps, a oneof) below: an input and the
                  reference's verdict on it, re-serialized with
                  `SerializeToString()` (map entries in the reference's own
                  order: first insertion of each key, last value). The inputs
                  are the reference's own output for messages built here, plus
                  hand-made non-canonical shapes (duplicate keys, entries
                  missing key or value, oneof members switching and merging).
  * `enc_*`    -- three messages the Zig test builds field for field, and the
                  bytes the reference writes for them.
  * WKT        -- Timestamp/Duration/wrappers/FieldMask/Any/Struct bytes, and
                  the reference's FromNanoseconds split.

The Zig mirror of `C` is `core_test.zig`'s `C`; the two must stay field for
field identical (numbers, kinds), or the comparison silently stops meaning
what it says.
"""
import struct, sys, warnings
warnings.simplefilter("ignore")
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf import timestamp_pb2, duration_pb2, wrappers_pb2, field_mask_pb2, any_pb2, struct_pb2, empty_pb2

F = descriptor_pb2.FieldDescriptorProto
fdp = descriptor_pb2.FileDescriptorProto(name="core.proto", package="core", syntax="proto3")
sub = fdp.message_type.add(name="Sub")
sub.field.add(name="x", number=1, type=F.TYPE_INT32, label=F.LABEL_OPTIONAL)
sub.field.add(name="y", number=2, type=F.TYPE_INT32, label=F.LABEL_OPTIONAL)
c = fdp.message_type.add(name="C")
def map_field(name, number, kt, vt, vtype_name=None):
    e = c.nested_type.add(name=name[0].upper() + name[1:] + "Entry")
    e.options.map_entry = True
    e.field.add(name="key", number=1, type=kt, label=F.LABEL_OPTIONAL)
    v = e.field.add(name="value", number=2, type=vt, label=F.LABEL_OPTIONAL)
    if vtype_name: v.type_name = vtype_name
    c.field.add(name=name, number=number, type=F.TYPE_MESSAGE, label=F.LABEL_REPEATED, type_name=".core.C." + e.name)
map_field("labels", 1, F.TYPE_STRING, F.TYPE_INT32)
map_field("names", 2, F.TYPE_INT32, F.TYPE_STRING)
map_field("subs", 3, F.TYPE_SINT64, F.TYPE_MESSAGE, ".core.Sub")
map_field("flags", 4, F.TYPE_BOOL, F.TYPE_BYTES)
c.oneof_decl.add(name="choice")
c.field.add(name="a", number=5, type=F.TYPE_INT32, label=F.LABEL_OPTIONAL, oneof_index=0)
c.field.add(name="b", number=6, type=F.TYPE_STRING, label=F.LABEL_OPTIONAL, oneof_index=0)
c.field.add(name="c", number=7, type=F.TYPE_MESSAGE, label=F.LABEL_OPTIONAL, oneof_index=0, type_name=".core.Sub")
c.field.add(name="d", number=8, type=F.TYPE_BYTES, label=F.LABEL_OPTIONAL, oneof_index=0)
c.field.add(name="tail", number=9, type=F.TYPE_INT32, label=F.LABEL_OPTIONAL)
pool = descriptor_pool.DescriptorPool()
pool.Add(fdp)
fac = message_factory.MessageFactory(pool)
C = fac.GetPrototype(pool.FindMessageTypeByName("core.C"))

def zs(b):
    return '"' + b.hex() + '"'

def reparse(h):
    m = C()
    m.ParseFromString(bytes.fromhex(h))
    return m.SerializeToString()

built = []
m = C(); m.labels["b"] = 5; m.labels["a"] = 0; m.labels[""] = 7; built.append(("labels, default value and empty key", m))
m = C(); m.names[-1] = "minus"; m.names[0] = ""; m.names[300] = "ü"; built.append(("int32 keys incl. negative", m))
m = C(); m.subs[-2].x = 1; m.subs[5].CopyFrom(sub_msg := fac.GetPrototype(pool.FindMessageTypeByName("core.Sub"))()); built.append(("message values incl. empty", m))
m = C(); m.flags[True] = b"\x00\xff"; m.flags[False] = b""; built.append(("bool keys, bytes values", m))
m = C(); m.a = 0; built.append(("oneof int member set to 0", m))
m = C(); m.b = ""; m.tail = 3; built.append(("oneof string member set to empty", m))
m = C(); m.c.y = -1; built.append(("oneof message member", m))
m = C(); m.c.SetInParent(); built.append(("oneof empty message member", m))
m = C(); m.d = b"\x01"; m.labels["k"] = 1; built.append(("oneof bytes member and a map", m))

hand = [
    ("duplicate key: last value, first position", "0a050a016110010a050a016210020a050a01611003"),
    ("entry without key", "0a021005"),
    ("entry without value", "0a030a0178"),
    ("empty entry", "0a00"),
    ("entry with an unknown field", "0a080a0161100218ff01"),
    ("entry fields in reverse order", "0a0510070a0171"),
    ("entry key twice inside one entry", "0a080a01611001 0a0162".replace(" ", "")),
    ("message value merged inside one entry", "1a0a0802120208011202 1005".replace(" ", "")),
    ("duplicate message-valued key: no merge across entries", "1a0608021202080 11a0608021202 1005".replace(" ", "")),
    ("oneof: last member wins", "28071a00" .replace("1a00", "3201") + "78"),
    ("oneof: message member merges with itself", "3a0208013a021005"),
    ("oneof: another member in between restarts the message", "3a020801280 73a021005".replace(" ", "")),
    ("oneof: scalar after message", "3a0208012809"),
    ("oneof: message after scalar", "28093a021005"),
    ("oneof: bytes member twice", "42016142026263"),
    ("oneof member with the wrong wire type is unknown", "2d01000000"),
]

floats = [0, 1, -1, 999_999_999, 1_000_000_000, -1_000_000_001, 1_700_000_000_123_456_789, -62_135_596_800 * 10**9]

out = []
w = out.append
w("// SPDX-License-Identifier: MIT")
w("//! GENERATED by tools/gen_core_vectors.py (Python protobuf as a black-box oracle) -- do not edit.")
w("pub const Case = struct { what: []const u8, input: []const u8, canonical: []const u8 };")
w("pub const c_cases = [_]Case{")
for what, msg in built:
    b = msg.SerializeToString()
    w(f'    .{{ .what = "{what}", .input = {zs(b)}, .canonical = {zs(reparse(b.hex()))} }},')
for what, h in hand:
    w(f'    .{{ .what = "{what}", .input = "{h}", .canonical = {zs(reparse(h))} }},')
w("};")

# Mirrored by hand in core_test.zig ("encode: three messages built field for field").
m = C(); m.labels["zeta"] = 1; m.labels["alpha"] = 2; m.a = 7
w(f"pub const enc_map_and_oneof = {zs(m.SerializeToString())};")
m = C(); m.subs[3].x = 4; m.c.SetInParent(); m.tail = -1
w(f"pub const enc_message_values = {zs(m.SerializeToString())};")
m = C(); m.flags[False] = b""; m.names[0] = ""; m.b = "hi"
w(f"pub const enc_defaults_in_entries = {zs(m.SerializeToString())};")

w("pub const Ts = struct { seconds: i64, nanos: i32, hex: []const u8 };")
w("pub const timestamps = [_]Ts{")
for s_, n_ in [(0, 0), (1, 0), (0, 1), (-1, 999_999_999), (1_700_000_000, 123_456_789), (-62_135_596_800, 0), (253_402_300_799, 999_999_999)]:
    w(f"    .{{ .seconds = {s_}, .nanos = {n_}, .hex = {zs(timestamp_pb2.Timestamp(seconds=s_, nanos=n_).SerializeToString())} }},")
w("};")
w("pub const durations = [_]Ts{")
for s_, n_ in [(0, 0), (-1, -500_000_000), (315_576_000_000, 999_999_999), (-315_576_000_000, -999_999_999), (0, -1)]:
    w(f"    .{{ .seconds = {s_}, .nanos = {n_}, .hex = {zs(duration_pb2.Duration(seconds=s_, nanos=n_).SerializeToString())} }},")
w("};")
w("pub const Split = struct { ns: i128, seconds: i64, nanos: i32 };")
w("pub const timestamp_from_nanos = [_]Split{")
for ns in floats:
    t = timestamp_pb2.Timestamp(); t.FromNanoseconds(ns)
    w(f"    .{{ .ns = {ns}, .seconds = {t.seconds}, .nanos = {t.nanos} }},")
w("};")
w("pub const duration_from_nanos = [_]Split{")
for ns in floats[:7]:
    d = duration_pb2.Duration(); d.FromNanoseconds(ns)
    w(f"    .{{ .ns = {ns}, .seconds = {d.seconds}, .nanos = {d.nanos} }},")
w("};")
w(f"pub const wrap_double = {zs(wrappers_pb2.DoubleValue(value=-2.5).SerializeToString())};")
w(f"pub const wrap_float = {zs(wrappers_pb2.FloatValue(value=1.5).SerializeToString())};")
w(f"pub const wrap_int64 = {zs(wrappers_pb2.Int64Value(value=-3).SerializeToString())};")
w(f"pub const wrap_uint64 = {zs(wrappers_pb2.UInt64Value(value=2**64-1).SerializeToString())};")
w(f"pub const wrap_int32 = {zs(wrappers_pb2.Int32Value(value=-1).SerializeToString())};")
w(f"pub const wrap_uint32 = {zs(wrappers_pb2.UInt32Value(value=300).SerializeToString())};")
w(f"pub const wrap_bool = {zs(wrappers_pb2.BoolValue(value=True).SerializeToString())};")
w(f"pub const wrap_string = {zs(wrappers_pb2.StringValue(value='hé').SerializeToString())};")
w(f"pub const wrap_bytes = {zs(wrappers_pb2.BytesValue(value=b'\x00\x01').SerializeToString())};")
w(f"pub const wrap_zero = {zs(wrappers_pb2.Int32Value(value=0).SerializeToString())};")
w(f"pub const field_mask = {zs(field_mask_pb2.FieldMask(paths=['a.b', 'c']).SerializeToString())};")
w(f"pub const empty = {zs(empty_pb2.Empty().SerializeToString())};")
a = any_pb2.Any(); a.Pack(timestamp_pb2.Timestamp(seconds=5, nanos=6))
w(f'pub const any_type_url = "{a.type_url}";')
w(f"pub const any_timestamp = {zs(a.SerializeToString())};")
st = struct_pb2.Struct()
st.update({"name": "x", "n": 1.5, "ok": True, "nil": None, "list": [1, "two", [], {}], "obj": {"k": False}})
w(f"pub const struct_doc = {zs(st.SerializeToString())};")
lv = struct_pb2.ListValue(); lv.extend([None, 0, "", False])
w(f"pub const list_value = {zs(lv.SerializeToString())};")
print("\n".join(out))
