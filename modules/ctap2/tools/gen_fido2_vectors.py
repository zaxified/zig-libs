#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/fido2_vectors.zig`: request/response bytes captured from
python-fido2 2.2.1 used as a BLACK-BOX oracle (public API only; no source
consulted).

Run:  ~/workspace/zig-libs/.zig-cache/fido2venv/bin/python gen_fido2_vectors.py \
          > ../src/fido2_vectors.zig && zig fmt ../src/fido2_vectors.zig

How it works
  * A fake `fido2.ctap.CtapDevice` (public interface, `call(cmd, data, ...)`)
    plays the authenticator: a composed authenticatorGetInfo, a keyAgreement
    with a fixed authenticator key, and pinUvAuthTokens encrypted under the
    real shared secret. It RECORDS every request byte string python-fido2 sends.
  * `fido2.ctap2.Ctap2(device)` + `fido2.ctap2.pin.ClientPin(ctap2, protocol)`
    are driven through get_pin_retries / get_uv_retries / set_pin / change_pin /
    get_pin_token (legacy and with permissions) / get_uv_token, both protocols.
  * The platform "ephemeral" ECDH scalar is pinned by monkeypatching
    `cryptography...ec.generate_private_key` and the protocol-Two IVs by
    monkeypatching `os.urandom` (as ctap2pin's oracle vectors did for the scalar),
    so the capture is reproducible. Everything else runs unmodified.
"""
import hashlib, os, sys
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

PLATFORM_SCALAR = bytes.fromhex("47bbb56478be492dd1dab6a5ea00d37b178a078363652d0402797aaaa0df603f")
AUTH_SCALAR = bytes.fromhex("4f4d86a2e5423b2f3ff57529165ec6b6ce7544585be16e3242a675bfb1eb6855")
AAGUID = bytes.fromhex("000102030405060708090a0b0c0d0e0f")

# --- pin the platform ephemeral key and the IV source -----------------------
_orig_gen = ec.generate_private_key
def _pinned_gen(curve, backend=None):
    return ec.derive_private_key(int.from_bytes(PLATFORM_SCALAR, "big"), curve)
ec.generate_private_key = _pinned_gen

iv_log = []
_iv_counter = [0]
def _fake_urandom(n):
    _iv_counter[0] += 1
    out = hashlib.sha256(b"ctap2-oracle-iv" + bytes([_iv_counter[0]])).digest()[:n]
    iv_log.append(out)
    return out
os.urandom = _fake_urandom

from fido2 import cbor
from fido2.ctap import CtapDevice
from fido2.ctap2 import Ctap2
from fido2.ctap2.pin import ClientPin, PinProtocolV1, PinProtocolV2

for mod in (sys.modules.get("fido2.ctap2.pin"),):
    if mod is not None and hasattr(mod, "urandom"):
        mod.urandom = _fake_urandom

auth_key = ec.derive_private_key(int.from_bytes(AUTH_SCALAR, "big"), ec.SECP256R1())
auth_pub = auth_key.public_key().public_numbers()
AUTH_X = auth_pub.x.to_bytes(32, "big")
AUTH_Y = auth_pub.y.to_bytes(32, "big")

def cose_key(x, y):
    return {1: 2, 3: -25, -1: 1, -2: x, -3: y}

def shared_secret(protocol, platform_cose):
    peer = ec.EllipticCurvePublicNumbers(
        int.from_bytes(platform_cose[-2], "big"), int.from_bytes(platform_cose[-3], "big"),
        ec.SECP256R1()).public_key()
    z = auth_key.exchange(ec.ECDH(), peer)
    if protocol == 1:
        return hashlib.sha256(z).digest()
    h = HKDF(hashes.SHA256(), 32, b"\0" * 32, b"CTAP2 HMAC key").derive(z)
    a = HKDF(hashes.SHA256(), 32, b"\0" * 32, b"CTAP2 AES key").derive(z)
    return h + a

def enc(protocol, secret, data, iv):
    key = secret if protocol == 1 else secret[32:]
    iv_used = b"\0" * 16 if protocol == 1 else iv
    c = Cipher(algorithms.AES(key), modes.CBC(iv_used)).encryptor()
    ct = c.update(data) + c.finalize()
    return ct if protocol == 1 else iv + ct

class FakeDevice(CtapDevice):
    def __init__(self, protocol, info, token, retries=(8, False), uv_retries=3):
        self.protocol, self.info, self.token = protocol, info, token
        self.retries, self.uv_retries = retries, uv_retries
        self.requests, self.responses = [], []
    @property
    def capabilities(self): return 0x04
    @classmethod
    def list_devices(cls): return iter(())
    def close(self): pass
    def call(self, cmd, data=b"", event=None, on_keepalive=None):
        self.requests.append(bytes(data))
        assert cmd == 0x10, cmd
        ctap_cmd, body = data[0], data[1:]
        if ctap_cmd == 0x04:
            out = b"\x00" + cbor.encode(self.info)
        elif ctap_cmd == 0x06:
            req = cbor.decode(body)
            sub = req[2]
            if sub == 1:
                r = {3: self.retries[0]}
                if self.retries[1] is not None: r[4] = self.retries[1]
                out = b"\x00" + cbor.encode(r)
            elif sub == 7:
                out = b"\x00" + cbor.encode({5: self.uv_retries})
            elif sub == 2:
                out = b"\x00" + cbor.encode({1: cose_key(AUTH_X, AUTH_Y)})
            elif sub in (3, 4):
                out = b"\x00"
            elif sub in (5, 6, 9):
                secret = shared_secret(self.protocol, req[3])
                iv = hashlib.sha256(b"token-iv").digest()[:16]
                out = b"\x00" + cbor.encode({2: enc(self.protocol, secret, self.token, iv)})
            else:
                raise AssertionError(sub)
        else:
            raise AssertionError(ctap_cmd)
        self.responses.append(out)
        return out

def info_for(protocols, **opts):
    options = {"clientPin": True}
    options.update(opts)
    return {1: ["FIDO_2_1", "FIDO_2_0"], 3: AAGUID, 4: options, 5: 1200,
            6: protocols, 0x0D: 4}

TOKEN16 = bytes.fromhex("9b9fa85bad3af39ef391c1de54348d54")
TOKEN32 = bytes.fromhex("b09aa8ff4768554814c16bdef13dd14822d090d4663fd19f1138df09809603d8")

P = ClientPin.PERMISSION
cases = []
def run(name, protocol, info, token, fn):
    iv_log.clear(); _iv_counter[0] = 0
    dev = FakeDevice(protocol, info, token)
    ctap = Ctap2(dev)
    proto = PinProtocolV1() if protocol == 1 else PinProtocolV2()
    cp = ClientPin(ctap, proto)
    info_req, info_resp = dev.requests[0], dev.responses[0]
    dev.requests.clear(); dev.responses.clear()
    result = fn(cp)
    cases.append(dict(name=name, protocol=protocol, info_request=info_req,
                      info_response=info_resp, requests=list(dev.requests),
                      responses=list(dev.responses), ivs=list(iv_log),
                      result=result))

legacy = lambda p: info_for(p)
modern = lambda p: info_for(p, pinUvAuthToken=True, uv=True, credMgmt=True, largeBlobs=True)

for proto, toks in ((1, (TOKEN16, TOKEN32)), (2, (TOKEN32, TOKEN32))):
    pl = [proto]
    run(f"p{proto}_get_pin_retries", proto, modern(pl), toks[0],
        lambda cp: repr(cp.get_pin_retries()))
    run(f"p{proto}_get_uv_retries", proto, modern(pl), toks[0], lambda cp: repr(cp.get_uv_retries()))
    run(f"p{proto}_set_pin", proto, modern(pl), toks[0], lambda cp: cp.set_pin("1234"))
    run(f"p{proto}_set_pin_utf8", proto, modern(pl), toks[0], lambda cp: cp.set_pin("pässwörd€"))
    run(f"p{proto}_change_pin", proto, modern(pl), toks[0], lambda cp: cp.change_pin("1234", "secret-pin-9"))
    run(f"p{proto}_get_pin_token_legacy", proto, legacy(pl), toks[0],
        lambda cp: cp.get_pin_token("1234").hex())
    run(f"p{proto}_get_pin_token_mc_ga", proto, modern(pl), toks[1],
        lambda cp: cp.get_pin_token("1234", P.MAKE_CREDENTIAL | P.GET_ASSERTION, "example.com").hex())
    run(f"p{proto}_get_pin_token_cm_no_rpid", proto, modern(pl), toks[1],
        lambda cp: cp.get_pin_token("1234", P.CREDENTIAL_MGMT).hex())
    run(f"p{proto}_get_pin_token_lbw_acfg", proto, modern(pl), toks[1],
        lambda cp: cp.get_pin_token("1234", P.LARGE_BLOB_WRITE | P.AUTHENTICATOR_CFG | P.BIO_ENROLL).hex())
    run(f"p{proto}_get_uv_token", proto, modern(pl), toks[1],
        lambda cp: cp.get_uv_token(P.GET_ASSERTION, "example.com").hex())

def hx(b): return '"' + b.hex() + '"'
print("// SPDX-License-Identifier: MIT")
print("//! GENERATED by tools/gen_fido2_vectors.py -- do not edit. python-fido2 2.2.1 as a")
print("//! black-box oracle: the request bytes it sends and the scripted authenticator")
print("//! responses it was given, per PIN operation and protocol.")
print("const std = @import(\"std\");")
print()
print("/// Comptime hex decoder for the tables below.")
print("pub fn hex(comptime s: []const u8) [s.len / 2]u8 {")
print("    var out: [s.len / 2]u8 = undefined;")
print("    @setEvalBranchQuota(1_000_000);")
print("    _ = std.fmt.hexToBytes(&out, s) catch unreachable;")
print("    return out;")
print("}")
print()
print("pub const Case = struct {")
print("    name: []const u8,")
print("    protocol: u8,")
print("    /// Bytes python-fido2 sent via `CtapDevice.call` (ctap command byte || CBOR).")
print("    /// The authenticatorGetInfo exchange `Ctap2(device)` opened with.")
print("    info_request: []const u8,")
print("    info_response: []const u8,")
print("    requests: []const []const u8,")
print("    /// Scripted authenticator responses (status byte || CBOR), one per request.")
print("    responses: []const []const u8,")
print("    /// Values `os.urandom` produced (protocol-Two IVs), in draw order.")
print("    ivs: []const []const u8,")
print("    /// `repr`/hex of what python-fido2 returned (token hex, retries repr, or None).")
print("    result: []const u8,")
print("};")
print()
print(f'pub const platform_scalar = {hx(PLATFORM_SCALAR)};')
print(f'pub const auth_x = {hx(AUTH_X)};')
print(f'pub const auth_y = {hx(AUTH_Y)};')
print(f'pub const aaguid = {hx(AAGUID)};')
print()
print("pub const cases = [_]Case{")
for c in cases:
    print("    .{")
    print(f'        .name = "{c["name"]}", .protocol = {c["protocol"]},')
    print(f"        .info_request = &hex({hx(c['info_request'])}),")
    print(f"        .info_response = &hex({hx(c['info_response'])}),")
    for key in ("requests", "responses", "ivs"):
        print(f"        .{key} = &.{{")
        for r in c[key]: print(f"            &hex({hx(r)}),")
        print("        },")
    print(f'        .result = "{c["result"]}",')
    print("    },")
print("};")
