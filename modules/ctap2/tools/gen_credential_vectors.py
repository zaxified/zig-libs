#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/credential_vectors.zig`: authenticatorMakeCredential / authenticatorGetAssertion /
authenticatorGetNextAssertion request bytes captured from python-fido2 2.2.1 as a BLACK-BOX oracle (public API only),
with the scripted authenticator responses it parsed.

Run (from the repository root):
    python3 -m venv .zig-cache/fido2venv && .zig-cache/fido2venv/bin/pip install fido2==2.2.1
    .zig-cache/fido2venv/bin/python modules/ctap2/tools/gen_credential_vectors.py > modules/ctap2/src/credential_vectors.zig \
        && zig fmt modules/ctap2/src/credential_vectors.zig

A fake `fido2.ctap.CtapDevice` records every request (`command byte || CBOR`) `Ctap2.make_credential` /
`get_assertion` / `get_next_assertion` send and answers with fixed authenticator responses.
"""
import hashlib
import sys

from fido2 import cbor
from fido2.ctap import CtapDevice
from fido2.ctap2 import Ctap2

AAGUID = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
CRED_ID = bytes(range(32))
CRED_X = bytes.fromhex("b3b9febfa1a8d2c1339fd567fda125b604d2067cc2546ca5f492f34946e8d056")
CRED_Y = bytes.fromhex("ca76c93cf7d39516f5e60c6d562e9a2fd50b80f8a345a4c25bc2dc4457b33cdd")
RP_HASH = hashlib.sha256(b"example.com").digest()
CDH = hashlib.sha256(b"client data").digest()
CDH2 = hashlib.sha256(b"client data 2").digest()


def cose_es256():
    return cbor.encode({1: 2, 3: -7, -1: 1, -2: CRED_X, -3: CRED_Y})


def mc_auth_data(flags=0x45, count=7, ext=b""):
    return (RP_HASH + bytes([flags]) + count.to_bytes(4, "big") + AAGUID +
            len(CRED_ID).to_bytes(2, "big") + CRED_ID + cose_es256() + ext)


def ga_auth_data(flags=0x05, count=8):
    return RP_HASH + bytes([flags]) + count.to_bytes(4, "big")


SIG = bytes.fromhex("3045022100") + bytes(range(1, 33)) + bytes.fromhex("0220") + bytes(range(33, 65))
CERT = bytes([0x30, 0x82, 0x01, 0x00]) + bytes(256)

INFO = {1: ["FIDO_2_1", "FIDO_2_0"], 3: AAGUID, 4: {"rk": True, "clientPin": True}, 5: 1200, 6: [1, 2]}


def wire(r):
    return b"\x00" + cbor.encode(r) if isinstance(r, dict) else r


class FakeDevice(CtapDevice):
    def __init__(self, responses):
        self.responses = [wire(r) for r in responses]
        self.requests = []

    @property
    def capabilities(self):
        return 0x04

    @classmethod
    def list_devices(cls):
        return iter(())

    def close(self):
        pass

    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        assert cmd == 0x10, cmd
        if data[0] == 0x04:
            return b"\x00" + cbor.encode(INFO)
        self.requests.append(bytes(data))
        return self.responses.pop(0)


cases = []


def run(name, responses, fn):
    dev = FakeDevice(responses)
    fn(Ctap2(dev))
    assert not dev.responses, name
    cases.append((name, dev.requests, [wire(r) for r in responses]))


RP = {"id": "example.com", "name": "Example"}
USER = {"id": b"\x01\x02\x03\x04", "name": "alice", "displayName": "Alice A."}
KP = [{"type": "public-key", "alg": -7}]

MC_RESP = {1: "packed", 2: mc_auth_data(), 3: {"alg": -7, "sig": SIG, "x5c": [CERT]}}
MC_RESP_FULL = {1: "packed", 2: mc_auth_data(0xC5, 7, cbor.encode({"credProtect": 2, "hmac-secret": True})), 3: {"alg": -7, "sig": SIG}, 4: True, 5: bytes(range(32))}
GA_RESP = {1: {"id": CRED_ID, "type": "public-key"}, 2: ga_auth_data(), 3: SIG}
GA_RESP_MULTI = {1: {"id": CRED_ID, "type": "public-key"}, 2: ga_auth_data(0x05), 3: SIG,
                 4: {"id": b"\x01\x02\x03\x04", "name": "alice", "displayName": "Alice A."}, 5: 2, 7: bytes(range(32))}
GA_NEXT = {1: {"id": bytes(reversed(CRED_ID)), "type": "public-key"}, 2: ga_auth_data(0x05, 9), 3: SIG,
           4: {"id": b"\x09\x08"}}

run("mc_minimal", [MC_RESP], lambda c: c.make_credential(CDH, RP, USER, KP))
run("mc_full_protocol1", [MC_RESP_FULL], lambda c: c.make_credential(
    CDH, RP, USER, [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}, {"type": "public-key", "alg": -8}],
    exclude_list=[{"type": "public-key", "id": b"\xaa" * 16}, {"type": "public-key", "id": b"\xbb" * 20, "transports": ["usb", "nfc"]}],
    extensions={"credProtect": 2, "hmac-secret": True},
    options={"rk": True, "uv": False}, pin_uv_param=bytes(range(16)), pin_uv_protocol=1, enterprise_attestation=2))
run("mc_protocol2", [MC_RESP], lambda c: c.make_credential(
    CDH2, {"id": "example.com"}, {"id": b"\x07"}, KP, options={"rk": True}, pin_uv_param=bytes(range(32)), pin_uv_protocol=2))
run("ga_minimal", [GA_RESP], lambda c: c.get_assertion("example.com", CDH))
run("ga_full_protocol2", [GA_RESP_MULTI, GA_NEXT], lambda c: (
    c.get_assertion("example.com", CDH2,
                    allow_list=[{"type": "public-key", "id": CRED_ID}, {"type": "public-key", "id": b"\xcc" * 8, "transports": ["internal"]}],
                    extensions={"credBlob": True}, options={"up": False, "uv": True},
                    pin_uv_param=bytes(range(32)), pin_uv_protocol=2),
    c.get_next_assertion()))

out = ["// SPDX-License-Identifier: MIT\n",
       "//! GENERATED by tools/gen_credential_vectors.py -- do not edit. python-fido2 2.2.1 as a black-box oracle: the\n",
       "//! request bytes it sends for authenticatorMakeCredential / GetAssertion / GetNextAssertion and the scripted\n",
       "//! authenticator responses (status byte || CBOR) it was given.\n",
       "pub const Case = struct {\n    name: []const u8,\n    /// `command byte || CBOR`, in the order python-fido2 sent them.\n    requests: []const []const u8,\n    responses: []const []const u8,\n};\n\n",
       "const hex = @import(\"fido2_vectors.zig\").hex;\n\n",
       "pub const cred_id = \"%s\";\npub const cred_x = \"%s\";\npub const cred_y = \"%s\";\npub const aaguid = \"%s\";\npub const rp_id_hash = \"%s\";\npub const signature = \"%s\";\n\n" % (
           CRED_ID.hex(), CRED_X.hex(), CRED_Y.hex(), AAGUID.hex(), RP_HASH.hex(), SIG.hex()),
       "pub const cases = [_]Case{\n"]
for name, reqs, resps in cases:
    out.append("    .{\n        .name = \"%s\",\n        .requests = &.{\n" % name)
    for r in reqs:
        out.append("            &hex(\"%s\"),\n" % r.hex())
    out.append("        },\n        .responses = &.{\n")
    for r in resps:
        out.append("            &hex(\"%s\"),\n" % r.hex())
    out.append("        },\n    },\n")
out.append("};\n")
sys.stdout.write("".join(out))
