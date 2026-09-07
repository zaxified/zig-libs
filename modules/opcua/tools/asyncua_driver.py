# SPDX-License-Identifier: MIT
#
# Reference OPC UA *client* for the opcua module's interop program: Python
# `asyncua` (LGPL-3.0), driven as a black box against OUR server.
#
# FOREIGN CODE LIVES HERE, NOT IN THE MODULE. Until 2026-09-07 this file was a
# ~190-line `\\` string literal inside `modules/opcua/src/server_interop.zig`,
# run with `python3 -c`, which made `zig build test-opcua` reach for an
# interpreter and a third-party package the module has no business needing. It
# was the seventh instance of the shape six modules were separated from on
# 2026-09-06, and it was missed because a string constant is not a file anyone
# can `git mv`.
#
# Now only `tools/interop.zig` runs this, via `zig build interop-opcua`, and it
# is run FROM THIS PATH — never embedded, never inlined. What the exchange
# produces is frozen into `../src/testdata/asyncua_transcript.txt`, and that is
# what the module's own tests replay, hermetically, with no interpreter
# anywhere.
#
# WHY asyncua. It is the natural second opinion to open62541: a wholly
# independent stack, written in a different language, with its own reading of
# OPC 10000-6 §6.7. Neither its source nor open62541's is read, built or linked
# — only stdout is the assertion.
#
# NO KEY MATERIAL SHIPS. This script generates its own throwaway 2048-bit RSA
# key pair and self-signed certificate through `cryptography`, in a temp
# directory it makes and owns; the server's key pair is likewise generated
# in-process, from the seed the transcript records.
#
# OUTPUT CONTRACT. `ZIGLIBS-<MARKER> <values>` on stdout, one per observation,
# flushed as they happen, then `ZIGLIBS-ALL-DONE`. `tools/interop.zig` parses
# those and asserts on them; the first line reports the versions that go into
# the transcript header, because "which asyncua accepted these bytes" is the
# question a stale recording has to be able to answer.
#
# Usage: asyncua_driver.py [endpoint-url]

import asyncio
import datetime
import os
import platform
import sys
import tempfile

from asyncua import Client, ua
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa as crsa

URL = sys.argv[1] if len(sys.argv) > 1 else "opc.tcp://localhost:4841"
ANSWER = ua.NodeId("the.answer", 1)
METHOD = ua.NodeId(62541, 1)


def asyncua_version():
    try:
        import importlib.metadata as md

        return md.version("asyncua")
    except Exception:
        return "unknown"


def make_cert(d):
    key = crsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "asyncua interop client")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier("urn:zig-libs:opcua:asyncua-client")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True,
                                         key_encipherment=True, data_encipherment=True,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    cp = os.path.join(d, "client.der")
    kp = os.path.join(d, "client.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cp, kp


class Handler:
    def __init__(self):
        self.count = 0

    def datachange_notification(self, node, val, data):
        self.count += 1


async def secure_client(cp, kp, mode, user=None, password=None, timeout_ms=None):
    c = Client(url=URL)
    if timeout_ms is not None:
        c.secure_channel_timeout = timeout_ms
    await c.set_security_string("Basic256Sha256,%s,%s,%s" % (mode, cp, kp))
    if user is not None:
        c.set_user(user)
        c.set_password(password)
    return c


async def main():
    print("ZIGLIBS-VERSIONS asyncua=%s python=%s" % (asyncua_version(), platform.python_version()), flush=True)
    d = tempfile.mkdtemp(prefix="ziglibs-opcua-")
    cp, kp = make_cert(d)

    # ---- connection 1: endpoint discovery over SecurityPolicy#None
    eps = await Client(url=URL).connect_and_get_server_endpoints()
    modes = sorted({"%s|%s" % (e.SecurityPolicyUri.rsplit("#", 1)[-1], e.SecurityMode.name) for e in eps})
    print("ZIGLIBS-OK-ENDPOINTS", len(eps), ",".join(modes), flush=True)
    for e in eps:
        if e.SecurityMode != ua.MessageSecurityMode.None_:
            assert e.ServerCertificate, "secure endpoint without a ServerCertificate"

    # ---- connection 2: SignAndEncrypt, anonymous
    #      browse / read / write / call / subscribe
    c = await secure_client(cp, kp, "SignAndEncrypt")
    async with c:
        print("ZIGLIBS-OK-CONNECT SignAndEncrypt", flush=True)
        children = await c.nodes.objects.get_children()
        names = [(await ch.read_browse_name()).Name for ch in children]
        assert "the.answer" in names, names
        print("ZIGLIBS-OK-BROWSE", len(children), flush=True)

        node = c.get_node(ANSWER)
        v = await node.read_value()
        print("ZIGLIBS-OK-READ", v, flush=True)

        await node.write_value(ua.DataValue(ua.Variant(31337, ua.VariantType.Int32)))
        back = await node.read_value()
        assert back == 31337, back
        print("ZIGLIBS-OK-WRITE", back, flush=True)

        out = await c.nodes.objects.call_method(METHOD, ua.Variant("ping", ua.VariantType.String))
        print("ZIGLIBS-OK-CALL", out, flush=True)

        h = Handler()
        sub = await c.create_subscription(200, h)
        await sub.subscribe_data_change(node)
        await asyncio.sleep(2.0)
        await sub.delete()
        assert h.count >= 1, h.count
        print("ZIGLIBS-OK-SUBSCRIPTION", h.count, flush=True)

    # ---- connection 3: Sign only, with a Basic256Sha256-encrypted
    #      UserNameIdentityToken
    c = await secure_client(cp, kp, "Sign", user="user1", password="password")
    async with c:
        v = await c.get_node(ANSWER).read_value()
        print("ZIGLIBS-OK-SIGN-USERNAME", v, flush=True)

    # ---- connection 4: SecurityToken renewal. A 10 s channel lifetime held for
    #      ~30 s makes asyncua renew at least twice while requests keep flowing.
    #
    #      The margin is deliberately wide. It was a 4 s lifetime held for ~10 s
    #      until 2026-08-14, which is a real property proved on an idle machine
    #      and a coin flip on a busy one: inside a full 215-module lane the token
    #      expired before the renewal was served and the server answered
    #      BadSecureChannelTokenUnknown, while the same test passed on its own in
    #      every optimize mode. A live test that fails under load teaches people
    #      to re-run the gate, which costs more than the seconds this spends.
    c = await secure_client(cp, kp, "SignAndEncrypt", timeout_ms=10000)
    async with c:
        node = c.get_node(ANSWER)
        reads = 0
        for _ in range(30):
            await node.read_value()
            reads += 1
            await asyncio.sleep(1.0)
        print("ZIGLIBS-OK-RENEWAL", reads, flush=True)

    print("ZIGLIBS-ALL-DONE", flush=True)


asyncio.run(main())
