#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""An authoritative DNS server that takes RFC 2136 updates under TSIG, built on
dnspython -- the live peer for `dns.update` / `dns.tsig` and for acme's
RFC 2136 DNS-01 publisher.

    python3 -I modules/dns/tools/update_server.py check        # from the repo root
    python3 -I modules/dns/tools/update_server.py serve [PORT]  # just the server

`check` starts the server on a free loopback port and runs, against it:

  1. BIND's `nsupdate` (a control: the server must accept what the reference
     client sends, so a failure in step 2 is ours, not the server's);
  2. `zig build interop-dns -- --update-server PORT`, which drives every
     update operation, every TSIG algorithm and the failure paths through
     `dns.update.send` and reads the results back with the module's own
     resolver (RD clear, as a DNS-01 propagation check asks);
  3. BIND's `dig +norec`, reading back what step 2 left -- the server's view
     of our updates, by a second client.

Run it under `hw run` (it builds). Needs dnspython, nsupdate and dig -- foreign
toolchains `zig build test-dns` must never require (CONVENTIONS.md §9).

Zones: example.org and delegated.test, each with SOA + NS ns1.<zone> (A
127.0.0.1). Keys: one per algorithm, `<alg>.key.` (hmac-sha256.key., ...),
secret = SHA-256 of the key name's text -- the interop program derives the
same. Updates must be signed (REFUSED otherwise); a bad signature, an unknown
key or a stale time gets an unsigned NOTAUTH with the TSIG error set, the way
BIND answers (RFC 8945 §5.2).

The update semantics implemented here are RFC 2136 §3.2 (prerequisites) and
§3.4 (updates) for plain RRsets; SOA/NS at the apex are protected from
deletion, nothing else (no CNAME exclusivity, no serial arithmetic beyond +1).
"""

import base64
import hashlib
import socket
import socketserver
import struct
import subprocess
import sys
import threading

import dns.flags
import dns.message
import dns.name
import dns.opcode
import dns.rcode
import dns.rdata
import dns.rdataclass
import dns.rdataset
import dns.rdatatype
import dns.rrset
import dns.tsig
import dns.update

ZONES = ["example.org.", "delegated.test."]
ALGS = ["hmac-sha1", "hmac-sha224", "hmac-sha256", "hmac-sha384", "hmac-sha512"]


def key_secret(name):
    return hashlib.sha256(name.encode()).digest()


KEYRING = {
    dns.name.from_text(f"{a}.key."): dns.tsig.Key(f"{a}.key.", key_secret(f"{a}.key."), a)
    for a in ALGS
}

lock = threading.Lock()
# (name, rdtype) -> Rdataset
records = {}
serials = {}


def seed():
    for z in ZONES:
        zn = dns.name.from_text(z)
        serials[zn] = 1
        put(zn, "SOA", 3600, f"ns1.{z} hostmaster.{z} 1 3600 600 86400 60")
        put(zn, "NS", 3600, f"ns1.{z}")
        put(dns.name.from_text(f"ns1.{z}"), "A", 3600, "127.0.0.1")


def put(name, rdtype, ttl, text):
    rdtype = dns.rdatatype.from_text(rdtype) if isinstance(rdtype, str) else rdtype
    rd = dns.rdata.from_text(dns.rdataclass.IN, rdtype, text)
    rs = records.setdefault((name, rdtype), dns.rdataset.Rdataset(dns.rdataclass.IN, rdtype))
    rs.add(rd, ttl)


def zone_of(name):
    best = None
    for z in ZONES:
        zn = dns.name.from_text(z)
        if name.is_subdomain(zn) and (best is None or len(zn) > len(best)):
            best = zn
    return best


def name_exists(name):
    return any(n == name and len(rs) > 0 for (n, _), rs in records.items())


def bump_serial(zone):
    serials[zone] += 1
    soa = records[(zone, dns.rdatatype.SOA)]
    old = list(soa)[0]
    soa.clear()
    soa.add(old.replace(serial=serials[zone]), 3600)


def tsig_error_reply(wire, rcode_tsig):
    """NOTAUTH, unsigned, with a TSIG record carrying the error and no MAC
    (RFC 8945 §5.2: the way BIND answers a request it cannot verify)."""
    if len(wire) < 12:
        return None
    req_id = wire[0:2]
    flags = struct.unpack("!H", wire[2:4])[0]
    try:
        q = dns.message.from_wire(wire, ignore_trailing=True, keyring=False)
    except Exception:
        q = None
    out = bytearray()
    out += req_id
    out += struct.pack("!H", 0x8000 | (flags & 0x7800) | dns.rcode.NOTAUTH)
    zone = b""
    if q is not None and q.question:
        qq = q.question[0]
        zone = qq.name.to_wire() + struct.pack("!HH", qq.rdtype, qq.rdclass)
    keyname = q.keyname.to_wire() if q is not None and q.keyname is not None else b"\x00"
    alg = q.keyalgorithm.to_wire() if q is not None and q.keyalgorithm is not None else dns.tsig.HMAC_SHA256.to_wire()
    out += struct.pack("!HHHH", 1 if zone else 0, 0, 0, 1)
    out += zone
    import time

    rdata = alg + struct.pack("!HIH", 0, int(time.time()), 300) + struct.pack("!H", 0)
    rdata += req_id + struct.pack("!HH", rcode_tsig, 0)
    out += keyname + struct.pack("!HHIH", dns.rdatatype.TSIG, dns.rdataclass.ANY, 0, len(rdata)) + rdata
    return bytes(out)


def plain_reply(wire, rcode):
    if len(wire) < 12:
        return None
    flags = struct.unpack("!H", wire[2:4])[0]
    return wire[0:2] + struct.pack("!HHHHH", 0x8000 | (flags & 0x7800) | rcode, 0, 0, 0, 0)


def handle(wire):
    try:
        msg = dns.message.from_wire(wire, keyring=KEYRING)
    except (dns.message.UnknownTSIGKey, dns.tsig.BadAlgorithm):
        # RFC 8945 §5.2.1: an unknown key name OR algorithm is BADKEY.
        return tsig_error_reply(wire, dns.rcode.BADKEY)
    except dns.tsig.BadSignature:
        return tsig_error_reply(wire, dns.rcode.BADSIG)
    except dns.tsig.BadTime:
        return tsig_error_reply(wire, dns.rcode.BADTIME)
    except Exception:
        return plain_reply(wire, dns.rcode.FORMERR)
    with lock:
        if msg.opcode() == dns.opcode.UPDATE:
            return do_update(msg)
        return do_query(msg)


def do_query(msg):
    resp = dns.message.make_response(msg)
    resp.flags |= dns.flags.AA
    if len(msg.question) != 1:
        resp.set_rcode(dns.rcode.FORMERR)
        return resp
    q = msg.question[0]
    zone = zone_of(q.name)
    if zone is None:
        resp.flags &= ~dns.flags.AA
        resp.set_rcode(dns.rcode.REFUSED)
        return resp
    rs = records.get((q.name, q.rdtype))
    if rs is not None and len(rs) > 0:
        resp.answer.append(dns.rrset.from_rdata_list(q.name, rs.ttl, list(rs)))
        return resp
    cn = records.get((q.name, dns.rdatatype.CNAME))
    if cn is not None and len(cn) > 0 and q.rdtype != dns.rdatatype.CNAME:
        resp.answer.append(dns.rrset.from_rdata_list(q.name, cn.ttl, list(cn)))
        return resp
    soa = records[(zone, dns.rdatatype.SOA)]
    resp.authority.append(dns.rrset.from_rdata_list(zone, soa.ttl, list(soa)))
    if not name_exists(q.name):
        resp.set_rcode(dns.rcode.NXDOMAIN)
    return resp


def do_update(msg):
    resp = dns.message.make_response(msg)
    if not msg.had_tsig:
        resp.set_rcode(dns.rcode.REFUSED)
        return resp
    if len(msg.zone) != 1 or msg.zone[0].rdtype != dns.rdatatype.SOA:
        resp.set_rcode(dns.rcode.FORMERR)
        return resp
    zone = msg.zone[0].name
    if zone not in serials:
        resp.set_rcode(dns.rcode.NOTAUTH)
        return resp

    # §3.2 prerequisites.
    value_sets = {}
    for rrset in msg.prerequisite:
        if not rrset.name.is_subdomain(zone):
            resp.set_rcode(dns.rcode.NOTZONE)
            return resp
        if rrset.deleting == dns.rdataclass.ANY:
            if rrset.rdtype == dns.rdatatype.ANY:
                if not name_exists(rrset.name):
                    resp.set_rcode(dns.rcode.NXDOMAIN)
                    return resp
            else:
                rs = records.get((rrset.name, rrset.rdtype))
                if rs is None or len(rs) == 0:
                    resp.set_rcode(dns.rcode.NXRRSET)
                    return resp
        elif rrset.deleting == dns.rdataclass.NONE:
            if rrset.rdtype == dns.rdatatype.ANY:
                if name_exists(rrset.name):
                    resp.set_rcode(dns.rcode.YXDOMAIN)
                    return resp
            else:
                rs = records.get((rrset.name, rrset.rdtype))
                if rs is not None and len(rs) > 0:
                    resp.set_rcode(dns.rcode.YXRRSET)
                    return resp
        else:
            s = value_sets.setdefault((rrset.name, rrset.rdtype), set())
            for rd in rrset:
                s.add(rd)
    for (name, rdtype), want in value_sets.items():
        rs = records.get((name, rdtype))
        have = set(rs) if rs is not None else set()
        if have != want:
            resp.set_rcode(dns.rcode.NXRRSET)
            return resp

    # §3.4 updates (prescan, then apply).
    for rrset in msg.update:
        if not rrset.name.is_subdomain(zone):
            resp.set_rcode(dns.rcode.NOTZONE)
            return resp
    for rrset in msg.update:
        apex_protected = rrset.name == zone and rrset.rdtype in (dns.rdatatype.SOA, dns.rdatatype.NS)
        if rrset.deleting is None:
            rs = records.setdefault((rrset.name, rrset.rdtype), dns.rdataset.Rdataset(dns.rdataclass.IN, rrset.rdtype))
            for rd in rrset:
                rs.add(rd, rrset.ttl)
        elif rrset.deleting == dns.rdataclass.ANY:
            if rrset.rdtype == dns.rdatatype.ANY:
                for key in [k for k in records if k[0] == rrset.name]:
                    if not (rrset.name == zone and key[1] in (dns.rdatatype.SOA, dns.rdatatype.NS)):
                        del records[key]
            elif not apex_protected:
                records.pop((rrset.name, rrset.rdtype), None)
        elif rrset.deleting == dns.rdataclass.NONE and not apex_protected:
            rs = records.get((rrset.name, rrset.rdtype))
            if rs is not None:
                for rd in rrset:
                    rs.discard(rd)
                if len(rs) == 0:
                    del records[(rrset.name, rrset.rdtype)]
    bump_serial(zone)
    return resp


def render(resp, udp):
    if resp is None or isinstance(resp, bytes):
        return resp
    wire = resp.to_wire()
    if udp and len(wire) > 512:
        hdr = bytearray(wire[:12])
        hdr[2] |= 0x02  # TC
        hdr[4:12] = b"\x00" * 8
        return bytes(hdr)
    return wire


class Udp(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        out = render(handle(data), True)
        if out:
            sock.sendto(out, self.client_address)


class Tcp(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            hdr = self.request.recv(2, socket.MSG_WAITALL)
            if len(hdr) < 2:
                return
            (n,) = struct.unpack("!H", hdr)
            data = self.request.recv(n, socket.MSG_WAITALL)
            out = render(handle(data), False)
            if out:
                self.request.sendall(struct.pack("!H", len(out)) + out)


class ThreadedUdp(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


class ThreadedTcp(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start(port):
    seed()
    tcp = ThreadedTcp(("127.0.0.1", port), Tcp)
    port = tcp.server_address[1]
    udp = ThreadedUdp(("127.0.0.1", port), Udp)
    for s in (tcp, udp):
        threading.Thread(target=s.serve_forever, daemon=True).start()
    return port


def run(cmd, stdin=None):
    print("$ " + " ".join(cmd), flush=True)
    r = subprocess.run(cmd, input=stdin, text=True, capture_output=True)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r


def check():
    port = start(0)
    print(f"update server on 127.0.0.1:{port}", flush=True)
    failures = 0
    secret = base64.b64encode(key_secret("hmac-sha256.key.")).decode()

    # 1. The reference client: nsupdate adds a record the Zig side reads.
    r = run(
        ["nsupdate", "-y", f"hmac-sha256:hmac-sha256.key.:{secret}"],
        f"server 127.0.0.1 {port}\nzone example.org\n"
        'update add from-nsupdate.example.org. 60 TXT "nsupdate-was-here"\nsend\n',
    )
    if r.returncode != 0:
        print("FAIL: nsupdate was refused -- the server, not dns.update, is wrong")
        return 1

    # 2. Our client.
    r = run(["zig", "build", "interop-dns", "--", "--update-server", str(port)])
    if r.returncode != 0:
        failures += 1

    # 3. A second client reads back what ours left.
    for name, want in [
        ("from-zig.example.org.", '"zig-was-here"'),
        ("_acme-challenge.delegated.test.", '"via-tcp-yyyy'),
    ]:
        r = run(["dig", "+norec", "+short", "+tcp", "-p", str(port), "@127.0.0.1", name, "TXT"])
        if want not in r.stdout:
            print(f"FAIL: dig does not see {want[:30]}... at {name}")
            failures += 1
    print("PASS" if failures == 0 else f"FAIL ({failures})")
    return 1 if failures else 0


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "check":
        sys.exit(check())
    if len(sys.argv) >= 2 and sys.argv[1] == "serve":
        port = start(int(sys.argv[2]) if len(sys.argv) > 2 else 0)
        print(f"READY {port}", flush=True)
        threading.Event().wait()
    print(__doc__)
    sys.exit(2)


if __name__ == "__main__":
    main()
