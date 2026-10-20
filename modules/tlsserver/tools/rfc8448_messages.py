#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/message_kat_vectors.zig`: the handshake messages of RFC 8448
sections 3 (simple 1-RTT), 4 (resumed 0-RTT: pre_shared_key with a binder,
early_data), 5 (HelloRetryRequest) and 6 (client authentication) that the
server reads or writes — the ClientHellos, and the server's ServerHello /
HelloRetryRequest, EncryptedExtensions, CertificateRequest, Certificate,
CertificateVerify and Finished; in section 6 also the client's Certificate,
CertificateVerify and Finished — plus, for
section 4, the length of the prefix the PSK binder is computed over and the
binder hash the RFC prints.

Checks before anything is written: section 4's printed "ClientHello prefix" is
the first octets of the sent ClientHello and SHA-256 of it is the printed
"binder hash"; every message's handshake header length matches its size.

Needs the RFC text (https://www.rfc-editor.org/rfc/rfc8448.txt):

    python3 -I tools/rfc8448_messages.py rfc8448.txt > src/message_kat_vectors.zig
"""

import hashlib
import re
import sys


def strip_page_breaks(text):
    """Drop the page footer / form feed / header sequence (as in
    rfc8448_records.py), which splits long hex blocks across pages."""
    return re.sub(r"\n*Thomson +Informational +\[Page \d+\]\n\f\nRFC 8448 +TLS 1\.3 Traces +January 2019\n\n*", "\n", text)


def hex_after(block, label):
    """The hex octets following `label` up to the first line that is not hex."""
    i = block.index(label) + len(label)
    out = []
    for n, line in enumerate(block[i:].split("\n")):
        s = line.strip()
        if n > 0 and not re.fullmatch(r"([0-9a-f]{2}\s*)+", s):
            break
        out += re.findall(r"\b[0-9a-f]{2}\b", s)
    return bytes.fromhex("".join(out))


def section(text, start, end):
    # rindex: the first occurrences are the table of contents.
    return text[text.rindex(start):text.rindex(end)]


def sent_client_hellos(sec):
    """The payload of every '{client}  send handshake record:' whose first
    octet is ClientHello (1)."""
    out = []
    for m in re.finditer(r"\{client\}  send handshake record:", sec):
        block = sec[m.end():m.end() + 6000]
        p = hex_after(block, re.search(r"payload \(\d+ octets\):", block).group(0))
        if p[0] == 1:
            out.append(p)
    return out


def server_message(sec, name, nth=0, side="server"):
    """The octets printed after '{server}  construct a(n) <name> handshake
    message:' (the nth such block in the section)."""
    starts = [m.end() for m in re.finditer(r"\{%s\}  construct an? %s handshake message:" % (side, re.escape(name)), sec)]
    block = sec[starts[nth]:starts[nth] + 6000]
    label = re.search(r"%s \(\d+ octets\):" % re.escape(name), block).group(0)
    return hex_after(block, label)


def check_len(msg):
    assert int.from_bytes(msg[1:4], "big") == len(msg) - 4, "handshake length"
    return msg


def zig(name, data):
    h = data.hex()
    lines = [h[i:i + 96] for i in range(0, len(h), 96)]
    # The layout `zig fmt` gives it.
    body = " ++\n    ".join('"%s"' % l for l in lines)
    return "pub const %s = hx(%d, %s);" % (name, len(data), body)


def main():
    text = strip_page_breaks(open(sys.argv[1]).read())
    s3 = section(text, "3.  Simple 1-RTT Handshake", "4.  Resumed 0-RTT Handshake")
    s4 = section(text, "4.  Resumed 0-RTT Handshake", "5.  HelloRetryRequest")
    s5 = section(text, "5.  HelloRetryRequest", "6.  Client Authentication")
    s6 = section(text, "6.  Client Authentication", "7.  Compatibility Mode")

    (ch3,) = sent_client_hellos(s3)
    (ch4,) = sent_client_hellos(s4)
    ch5_1, ch5_2 = sent_client_hellos(s5)
    (ch6,) = sent_client_hellos(s6)
    server = {
        "s3_server_hello": server_message(s3, "ServerHello"),
        "s3_encrypted_extensions": server_message(s3, "EncryptedExtensions"),
        "s3_certificate": server_message(s3, "Certificate"),
        "s3_certificate_verify": server_message(s3, "CertificateVerify"),
        "s3_server_finished": server_message(s3, "Finished"),
        "s4_server_hello": server_message(s4, "ServerHello"),
        "s4_encrypted_extensions": server_message(s4, "EncryptedExtensions"),
        "s5_hello_retry_request": server_message(s5, "ServerHello", 0),
        "s5_server_hello": server_message(s5, "ServerHello", 1),
        "s5_encrypted_extensions": server_message(s5, "EncryptedExtensions"),
        "s6_server_hello": server_message(s6, "ServerHello"),
        "s6_encrypted_extensions": server_message(s6, "EncryptedExtensions"),
        "s6_certificate_request": server_message(s6, "CertificateRequest"),
        "s6_certificate": server_message(s6, "Certificate"),
        "s6_certificate_verify": server_message(s6, "CertificateVerify"),
        "s6_server_finished": server_message(s6, "Finished"),
    }
    client = {
        "s6_client_certificate": server_message(s6, "Certificate", side="client"),
        "s6_client_certificate_verify": server_message(s6, "CertificateVerify", side="client"),
        "s6_client_finished": server_message(s6, "Finished", side="client"),
    }
    expect_type = {"server_hello": 2, "hello_retry_request": 2, "encrypted_extensions": 8,
                   "certificate": 11, "certificate_verify": 15, "server_finished": 20,
                   "certificate_request": 13, "client_certificate": 11,
                   "client_certificate_verify": 15, "client_finished": 20}
    for k, m in (*server.items(), *client.items()):
        assert m[0] == expect_type[k.split("_", 1)[1]], k
    for m in (ch3, ch4, ch5_1, ch5_2, ch6, *server.values(), *client.values()):
        check_len(m)
    # The HelloRetryRequest is the ServerHello with the special random.
    assert server["s5_hello_retry_request"][6:38] == bytes.fromhex(
        "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")

    i = s6.index('{server}  derive secret "tls13 c hs traffic":')
    c_hs = hex_after(s6[i:i + 2000], "expanded (32 octets):")
    assert len(c_hs) == 32

    i = s4.index("{client}  calculate PSK binder:")
    block = s4[i:i + 4000]
    prefix = hex_after(block, re.search(r"ClientHello prefix \(\d+ octets\):", block).group(0))
    binder_hash = hex_after(block, "binder hash (32 octets):")
    assert ch4[:len(prefix)] == prefix, "prefix is not the start of the sent ClientHello"
    assert hashlib.sha256(prefix).digest() == binder_hash, "binder hash"

    print("// SPDX-License-Identifier: MIT")
    print("")
    print("//! RFC 8448 handshake messages (sections 3 to 6) a server reads or")
    print("//! writes, generated by `tools/rfc8448_messages.py` from the RFC text. Do not")
    print("//! edit by hand.")
    print("")
    print("/// Section 3, simple 1-RTT handshake.")
    print(zig("rfc8448_s3", ch3))
    print("")
    print("/// Section 4, resumed 0-RTT handshake: early_data, psk_key_exchange_modes,")
    print("/// pre_shared_key (one identity, one binder) last.")
    print(zig("rfc8448_s4", ch4))
    print("/// The octets of `rfc8448_s4` the binder is computed over (RFC 8446")
    print("/// §4.2.11.2), and their SHA-256 (the RFC's \"binder hash\").")
    print("pub const rfc8448_s4_binder_prefix_len = %d;" % len(prefix))
    print(zig("rfc8448_s4_binder_hash", binder_hash))
    print("")
    print("/// Section 5: ClientHello1 (a key share for x25519 only; the server asks for")
    print("/// secp256r1) and ClientHello2 (the cookie and a secp256r1 key share).")
    print(zig("rfc8448_s5_ch1", ch5_1))
    print(zig("rfc8448_s5_ch2", ch5_2))
    print("")
    print("/// Section 6, client authentication (the client's key is RSA).")
    print(zig("rfc8448_s6", ch6))
    print("")
    print("/// The server's messages, each as the RFC prints it (header included).")
    for k, m in server.items():
        print(zig("rfc8448_" + k, m))
    print("")
    print("/// Section 6: the client's second flight.")
    for k, m in client.items():
        print(zig("rfc8448_" + k, m))
    print("/// Section 6: client_handshake_traffic_secret (\"tls13 c hs traffic\"), the")
    print("/// key of the client's Finished.")
    print(zig("rfc8448_s6_client_handshake_secret", c_hs))
    print("")
    print("fn hx(comptime n: usize, comptime hex: []const u8) [n]u8 {")
    print("    @setEvalBranchQuota(1_000_000);")
    print("    var out: [n]u8 = undefined;")
    print('    _ = @import("std").fmt.hexToBytes(&out, hex) catch unreachable;')
    print("    return out;")
    print("}")


if __name__ == "__main__":
    main()
