# SPDX-License-Identifier: MIT
#
# Third phase of `zig build interop-opcua`: Python `asyncua` (LGPL-3.0, a
# black box) as the SERVER, offering only Aes128_Sha256_RsaOaep and
# Aes256_Sha256_RsaPss at Sign and SignAndEncrypt (plus #None for
# discovery), for this module's CLIENT to connect to. Live only.
#
# It makes a throwaway RSA-2048 server certificate in a temp directory,
# prints `ZIGLIBS-SERVER-READY <certificate DER path>` once listening, and
# serves until its stdin closes (the interop program owns the process).
#
# Usage: asyncua_server.py <endpoint-url>

import asyncio
import datetime
import os
import sys
import tempfile

from asyncua import Server, ua
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa as crsa

URL = sys.argv[1] if len(sys.argv) > 1 else "opc.tcp://127.0.0.1:4842/"
APP_URI = "urn:zig-libs:opcua:asyncua-server"


def make_cert(d):
    key = crsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "asyncua interop server")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier(APP_URI), x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True,
                                         key_encipherment=True, data_encipherment=True,
                                         key_agreement=False, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    cp = os.path.join(d, "server.der")
    kp = os.path.join(d, "server.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.DER))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return cp, kp


async def main():
    d = tempfile.mkdtemp(prefix="ziglibs-opcua-server-")
    cp, kp = make_cert(d)
    server = Server()
    await server.init()
    server.set_endpoint(URL)
    await server.set_application_uri(APP_URI)
    await server.load_certificate(cp)
    await server.load_private_key(kp)
    server.set_security_policy([
        ua.SecurityPolicyType.NoSecurity,
        ua.SecurityPolicyType.Aes128Sha256RsaOaep_Sign,
        ua.SecurityPolicyType.Aes128Sha256RsaOaep_SignAndEncrypt,
        ua.SecurityPolicyType.Aes256Sha256RsaPss_Sign,
        ua.SecurityPolicyType.Aes256Sha256RsaPss_SignAndEncrypt,
    ])
    async with server:
        print("ZIGLIBS-SERVER-READY %s" % cp, flush=True)
        await asyncio.get_running_loop().run_in_executor(None, sys.stdin.read)


if __name__ == "__main__":
    asyncio.run(main())
