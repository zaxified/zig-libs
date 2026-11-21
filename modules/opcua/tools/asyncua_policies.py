# SPDX-License-Identifier: MIT
#
# Second phase of `zig build interop-opcua`: Python `asyncua` (LGPL-3.0, a
# black box) against OUR server at the newer security policies,
# Aes128_Sha256_RsaOaep and Aes256_Sha256_RsaPss (OPC 10000-7), each at Sign
# (with a username whose password asyncua encrypts with the policy's
# asymmetric algorithm) and at SignAndEncrypt (anonymous). Live only: nothing
# of this exchange is recorded into the transcript the module replays.
#
# Like asyncua_driver.py it makes its own throwaway RSA-2048 client
# certificate (the same shape; that script runs on import, so the helper is
# repeated here).
#
# OUTPUT CONTRACT. `ZIGLIBS-POLICY <policy> <mode> <read value>` per leg, then
# `ZIGLIBS-POLICIES-DONE`; a failing leg raises and the script exits non-zero.
#
# Usage: asyncua_policies.py [endpoint-url]

import asyncio
import datetime
import os
import sys
import tempfile

from asyncua import Client, ua
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa as crsa

URL = sys.argv[1] if len(sys.argv) > 1 else "opc.tcp://localhost:4841"
ANSWER = ua.NodeId("the.answer", 1)


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


async def leg(cp, kp, policy, mode, user=None, password=None):
    c = Client(url=URL)
    await c.set_security_string("%s,%s,%s,%s" % (policy, mode, cp, kp))
    if user is not None:
        c.set_user(user)
        c.set_password(password)
    async with c:
        node = c.get_node(ANSWER)
        value = await node.read_value()
        await node.write_value(ua.DataValue(ua.Variant(value + 1, ua.VariantType.Int32)))
        back = await node.read_value()
        assert back == value + 1, (value, back)
        print("ZIGLIBS-POLICY %s %s %d" % (policy, mode, back), flush=True)


async def main():
    d = tempfile.mkdtemp(prefix="ziglibs-opcua-policies-")
    cp, kp = make_cert(d)
    eps = await Client(url=URL).connect_and_get_server_endpoints()
    offered = sorted({"%s|%s" % (e.SecurityPolicyUri.rsplit("#", 1)[-1], e.SecurityMode.name) for e in eps})
    print("ZIGLIBS-POLICY-ENDPOINTS", ",".join(offered), flush=True)
    for policy in ("Aes128Sha256RsaOaep", "Aes256Sha256RsaPss"):
        await leg(cp, kp, policy, "Sign", "user1", "password")
        await leg(cp, kp, policy, "SignAndEncrypt")
    print("ZIGLIBS-POLICIES-DONE", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
