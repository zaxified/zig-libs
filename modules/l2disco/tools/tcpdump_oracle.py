#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/testdata/tcpdump_facts.zig`: LLDP, CDP and DHCP frames that
reach every TLV / option shape this module decodes, and what tcpdump's own
dissectors read in them. Replayed by `src/tcpdump_oracle_test.zig`.

    python3 modules/l2disco/tools/tcpdump_oracle.py | zig fmt --stdin > modules/l2disco/src/testdata/tcpdump_facts.zig

The frames are built here from the standards (IEEE 802.1AB, 802.1Q / 802.3
annexes, ANSI/TIA-1057, Cisco's published CDP layout, RFC 2131/2132/3046/3397/
3442), independently of this module's `Builder`s. tcpdump 4.99 leaves DHCP
option 119 (domain search) undecoded, so those names come from dnspython's
`dns.name.from_wire` instead (needs `python3 -m pip install dnspython` where
the system Python lacks it). Each frame goes through `tcpdump -r - -vvv -nn` (a
black-box decoder, BSD-licensed, run as a program). The FACTS recorded per
frame are parsed out of tcpdump's text -- not copied from the intent -- and the
generator also asserts they equal the intent, so a wrong frame here cannot
become a wrong expectation silently. The replay renders the same facts from
this module's decoders and requires the same list.
"""
import re
import struct

import dns.name
import subprocess
import sys

SRC = bytes.fromhex("020000000001")


def tlv(t, v):
    return struct.pack(">H", (t << 9) | len(v)) + v


def org(oui, st, info):
    return tlv(127, bytes.fromhex(oui) + bytes([st]) + info)


def lldp(tlvs):
    return bytes.fromhex("0180c200000e") + SRC + b"\x88\xcc" + b"".join(tlvs) + tlv(0, b"")


def policy(app, u, t, vlan, prio, dscp):
    v = (u << 23) | (t << 22) | (vlan << 9) | (prio << 6) | dscp
    return bytes([app]) + v.to_bytes(3, "big")


def cdp_checksum(b):
    """RFC 1071 with standard zero padding. tcpdump does not verify CDP
    checksums ("unverified"), so this oracle says nothing about them."""
    if len(b) % 2:
        b += b"\x00"
    s = sum(struct.unpack(">%dH" % (len(b) // 2), b))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def cdp(tlvs, version=2, ttl=180):
    body = b"".join(struct.pack(">HH", t, 4 + len(v)) + v for t, v in tlvs)
    head = bytes([version, ttl]) + b"\x00\x00"
    pdu = head + body
    pdu = head[:2] + struct.pack(">H", cdp_checksum(pdu)) + body
    llc = b"\xaa\xaa\x03\x00\x00\x0c\x20\x00"
    payload = llc + pdu
    return bytes.fromhex("01000ccccccc") + SRC + struct.pack(">H", len(payload)) + payload


def cdp_addr_ipv4(addrs):
    out = struct.pack(">I", len(addrs))
    for a in addrs:
        out += b"\x01\x01\xcc" + struct.pack(">H", 4) + bytes(a)
    return out


# ── the frames, each with its intended facts ────────────────────────────────

FRAMES = []


def frame(name, raw, intent):
    FRAMES.append((name, raw, intent))


mac = SRC
frame("lldp_switch_port", lldp([
    tlv(1, b"\x04" + mac), tlv(2, b"\x05eth0"), tlv(3, b"\x00\x78"),
    tlv(4, b"uplink to core"), tlv(5, b"sw1.example"), tlv(6, b"Linux 6.8 x86_64"),
    tlv(7, struct.pack(">HH", 0x0014, 0x0004)),
    tlv(8, b"\x05\x01" + bytes([10, 0, 0, 1]) + b"\x02" + struct.pack(">I", 3) + b"\x00"),
    tlv(8, b"\x11\x02" + bytes.fromhex("20010db8000000000000000000000001") + b"\x03" + struct.pack(">I", 7) + b"\x00"),
    org("0080c2", 1, struct.pack(">H", 10)),
    org("0080c2", 2, b"\x06" + struct.pack(">H", 20)),
    org("0080c2", 3, struct.pack(">H", 30) + b"\x04mgmt"),
    org("00120f", 1, b"\x03" + struct.pack(">HH", 0x6C00, 0x0010)),
    org("00120f", 4, struct.pack(">H", 9216)),
]), [
    "chassis=4:02:00:00:00:00:01", "port=5:eth0", "ttl=120", "port_desc=uplink to core",
    "sys_name=sw1.example", "sys_desc=Linux 6.8 x86_64", "caps=0x0014/0x0004",
    "mgmt=10.0.0.1/2/3", "mgmt=2001:db8::1/3/7", "pvid=10", "ppvid=20/0x06", "vlan_name=30:mgmt",
    "mac_phy=0x03/0x6c00/16", "max_frame=9216",
])
frame("lldp_ids_and_shutdown", lldp([
    tlv(1, b"\x07router-17"), tlv(2, b"\x03" + bytes.fromhex("0a0b0c0d0e0f")), tlv(3, b"\x00\x00"),
    tlv(7, struct.pack(">HH", 0x00FF, 0x0011)),
]), ["chassis=7:router-17", "port=3:0a:0b:0c:0d:0e:0f", "ttl=0", "caps=0x00ff/0x0011"])
frame("lldp_network_address_ids", lldp([
    tlv(1, b"\x05\x01" + bytes([192, 0, 2, 9])), tlv(2, b"\x07Gi0/1"), tlv(3, b"\x00\x3c"),
]), ["chassis=5:192.0.2.9", "port=7:Gi0/1", "ttl=60"])
frame("lldp_component_ids", lldp([
    tlv(1, b"\x01chassis-A"), tlv(2, b"\x02alias-port"), tlv(3, b"\x00\x0a"),
]), ["chassis=1:chassis-A", "port=2:alias-port", "ttl=10"])
frame("lldp_med_phone", lldp([
    tlv(1, b"\x04" + mac), tlv(2, b"\x03" + mac), tlv(3, b"\x00\xb4"),
    org("0012bb", 1, struct.pack(">HB", 0x0033, 3)),
    org("0012bb", 2, policy(1, 0, 1, 100, 5, 46)),
    org("0012bb", 2, policy(2, 1, 0, 0, 0, 0)),
    org("0012bb", 4, bytes([(1 << 6) | (1 << 4) | 2]) + struct.pack(">H", 65)),
    org("0012bb", 5, b"1.2"), org("0012bb", 6, b"fw-3.4"), org("0012bb", 7, b"sw-5.6"),
    org("0012bb", 8, b"SN0042"), org("0012bb", 9, b"Acme"), org("0012bb", 10, b"Phone 9"),
    org("0012bb", 11, b"asset-7"),
]), [
    "chassis=4:02:00:00:00:00:01", "port=3:02:00:00:00:00:01", "ttl=180",
    "med_caps=0x0033/3", "policy=1/0/1/100/5/46", "policy=2/1/0/0/0/0", "ext_power=1/1/2/65",
    "inventory=5:1.2", "inventory=6:fw-3.4", "inventory=7:sw-5.6", "inventory=8:SN0042",
    "inventory=9:Acme", "inventory=10:Phone 9", "inventory=11:asset-7",
])
frame("lldp_power", lldp([
    tlv(1, b"\x04" + mac), tlv(2, b"\x05eth1"), tlv(3, b"\x00\x78"),
    org("00120f", 2, b"\x0f\x01\x04"),
]), ["chassis=4:02:00:00:00:00:01", "port=5:eth1", "ttl=120", "power=0x0f/1/4"])
frame("lldp_location_elin", lldp([
    tlv(1, b"\x04" + mac), tlv(2, b"\x05eth2"), tlv(3, b"\x00\x78"),
    org("0012bb", 3, b"\x03" + b"5551234567"),
]), ["chassis=4:02:00:00:00:00:01", "port=5:eth2", "ttl=120", "location=3"])
frame("cdp_v2_full", cdp([
    (0x0001, b"core-sw1"),
    (0x0002, cdp_addr_ipv4([[192, 0, 2, 1], [198, 51, 100, 7]])),
    (0x0003, b"GigabitEthernet0/1"),
    (0x0004, struct.pack(">I", 0x00000029)),
    (0x0005, b"Cisco IOS Software, Version 15.2(4)E"),
    (0x0006, b"cisco WS-C2960X-48TS-L"),
    (0x0009, b"lab"),
    (0x000A, struct.pack(">H", 42)),
    (0x000B, b"\x01"),
]), [
    "cdp_version=2", "cdp_ttl=180", "device_id=core-sw1", "address=192.0.2.1", "address=198.51.100.7",
    "port_id=GigabitEthernet0/1", "cdp_caps=0x00000029", "software=Cisco IOS Software, Version 15.2(4)E",
    "platform=cisco WS-C2960X-48TS-L", "vtp=lab", "native_vlan=42", "duplex=full",
])
frame("cdp_v1_odd_length", cdp([
    (0x0001, b"r1"), (0x0003, b"Fa0/1"), (0x000B, b"\x00"), (0x0006, b"odd"),
], version=1, ttl=60), [
    "cdp_version=1", "cdp_ttl=60", "device_id=r1", "port_id=Fa0/1", "duplex=half", "platform=odd",
])


def dopt(c, v):
    return bytes([c, len(v)]) + v


def bootp(op, xid, flags, ci, yi, si, gi, opts, hops=0, secs=0):
    h = struct.pack(">BBBBIHH", op, 1, 6, hops, xid, secs, flags) + bytes(ci) + bytes(yi) + bytes(si) + bytes(gi)
    h += SRC + b"\0" * 10 + b"\0" * 64 + b"\0" * 128
    return h + bytes.fromhex("63825363") + b"".join(opts) + b"\xff"


def udp_ip(payload, sport, dport, src, dst):
    """Ethernet + IPv4 (checksummed) + UDP (checksum 0 = none) around `payload`."""
    u = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(u), 1, 0, 64, 17, 0, bytes(src), bytes(dst))
    ip = ip[:10] + struct.pack(">H", cdp_checksum(ip)) + ip[12:]
    return bytes.fromhex("ffffffffffff") + SRC + b"\x08\x00" + ip + u


def dn(*labels):
    return b"".join(bytes([len(x)]) + x.encode() for x in labels) + b"\0"


ip4 = lambda s: bytes(int(x) for x in s.split("."))
frame("dhcp_offer", udp_ip(bootp(2, 0x1234ABCD, 0x8000, [0] * 4, ip4("192.168.1.10"), ip4("192.168.1.1"), ip4("10.0.0.1"), [
    dopt(53, b"\x02"), dopt(54, ip4("192.168.1.1")), dopt(51, struct.pack(">I", 3600)), dopt(1, ip4("255.255.255.0")),
    dopt(3, ip4("192.168.1.1")), dopt(6, ip4("1.1.1.1") + ip4("8.8.8.8")), dopt(15, b"example.com"), dopt(12, b"host1"),
    dopt(42, ip4("192.168.1.5")), dopt(66, b"tftp.example"), dopt(67, b"pxelinux.0"),
    dopt(121, bytes([8, 10]) + ip4("192.168.1.1") + bytes([24, 172, 16, 5]) + ip4("192.168.1.2") + b"\x00" + ip4("192.168.1.1")),
    # 119 with a compression pointer (RFC 3397): "corp" + pointer to offset 0.
    dopt(119, dn("example", "com") + b"\x04corp\xc0\x00"),
], secs=3), 67, 68, [192, 168, 1, 1], [255, 255, 255, 255]), [
    "dhcp_op=2", "xid=0x1234abcd", "secs=3", "flags=0x8000", "yiaddr=192.168.1.10", "siaddr=192.168.1.1",
    "giaddr=10.0.0.1", "chaddr=02:00:00:00:00:01", "msg_type=2", "server_id=192.168.1.1", "lease=3600",
    "subnet=255.255.255.0", "routers=192.168.1.1", "dns=1.1.1.1,8.8.8.8", "domain=example.com", "hostname=host1",
    "ntp=192.168.1.5", "tftp=tftp.example", "bootfile=pxelinux.0", "route=10.0.0.0/8:192.168.1.1",
    "route=172.16.5.0/24:192.168.1.2", "route=0.0.0.0/0:192.168.1.1", "search=example.com.", "search=corp.example.com.",
])
frame("dhcp_request", udp_ip(bootp(1, 0x0BADF00D, 0, [0] * 4, [0] * 4, [0] * 4, [0] * 4, [
    dopt(53, b"\x03"), dopt(50, ip4("192.168.1.10")), dopt(54, ip4("192.168.1.1")), dopt(12, b"laptop"),
    dopt(61, b"\x01" + SRC), dopt(55, bytes([1, 3, 6, 15, 119, 121])), dopt(60, b"MSFT 5.0"),
]), 68, 67, [0, 0, 0, 0], [255, 255, 255, 255]), [
    "dhcp_op=1", "xid=0x0badf00d", "flags=0x0000", "chaddr=02:00:00:00:00:01", "msg_type=3",
    "requested_ip=192.168.1.10", "server_id=192.168.1.1", "hostname=laptop", "client_id=1:02:00:00:00:00:01",
    "prl=1,3,6,15,119,121", "vendor_class=MSFT 5.0",
])
frame("dhcp_ack_renew", udp_ip(bootp(2, 0x00C0FFEE, 0, ip4("192.168.1.10"), ip4("192.168.1.10"), [0] * 4, [0] * 4, [
    dopt(53, b"\x05"), dopt(54, ip4("192.168.1.1")), dopt(51, struct.pack(">I", 86400)), dopt(1, ip4("255.255.0.0")),
    dopt(3, ip4("192.168.1.1") + ip4("192.168.1.254")), dopt(6, ip4("9.9.9.9") + ip4("1.0.0.1") + ip4("8.8.4.4")),
]), 67, 68, [192, 168, 1, 1], [192, 168, 1, 10]), [
    "dhcp_op=2", "xid=0x00c0ffee", "flags=0x0000", "ciaddr=192.168.1.10", "yiaddr=192.168.1.10",
    "chaddr=02:00:00:00:00:01", "msg_type=5", "server_id=192.168.1.1", "lease=86400", "subnet=255.255.0.0",
    "routers=192.168.1.1,192.168.1.254", "dns=9.9.9.9,1.0.0.1,8.8.4.4",
])
frame("dhcp_inform_search", udp_ip(bootp(1, 0x0D15EA5E, 0, ip4("192.168.1.10"), [0] * 4, [0] * 4, [0] * 4, [
    dopt(53, b"\x08"), dopt(55, bytes([6, 15, 119])), dopt(119, dn("example", "com") + dn("corp", "example", "com")),
]), 68, 67, [192, 168, 1, 10], [192, 168, 1, 1]), [
    "dhcp_op=1", "xid=0x0d15ea5e", "flags=0x0000", "ciaddr=192.168.1.10", "chaddr=02:00:00:00:00:01", "msg_type=8",
    "prl=6,15,119", "search=example.com.", "search=corp.example.com.",
])
frame("dhcp_relayed_discover", udp_ip(bootp(1, 0x55AA55AA, 0, [0] * 4, [0] * 4, [0] * 4, ip4("10.0.0.1"), [
    dopt(53, b"\x01"), dopt(82, dopt(1, b"ge-0/0/1.100") + dopt(2, b"sw-access-3")),
], hops=1), 67, 67, [10, 0, 0, 1], [192, 168, 1, 1]), [
    "dhcp_op=1", "xid=0x55aa55aa", "flags=0x0000", "giaddr=10.0.0.1", "chaddr=02:00:00:00:00:01", "msg_type=1",
    "relay=1:ge-0/0/1.100", "relay=2:sw-access-3",
])


# ── reading tcpdump's text back into facts ──────────────────────────────────

def pcap(frames):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for f in frames:
        out += struct.pack("<IIII", 0, 0, len(f), len(f)) + f
    return out


def tcpdump(frames):
    r = subprocess.run(["tcpdump", "-r", "-", "-vvv", "-nn", "-e"], input=pcap(frames),
                       capture_output=True, check=True)
    text = r.stdout.decode()
    blocks = re.split(r"\n(?=\d\d:\d\d:\d\d\.\d{6} )", text.strip())
    assert len(blocks) == len(frames), (len(blocks), len(frames))
    return blocks


# tcpdump's words for the flag and enum values, as its output prints them.
FLAG_WORDS = {"PSE": 0x01, "supported": 0x02, "enabled": 0x04, "can be controlled": 0x08}
EXT_TYPE = {"PSE device": 0, "PD device": 1}
EXT_SOURCE = {"PSE - primary power source": 1}
INVENTORY = {5: "Hardware revision", 6: "Firmware revision", 7: "Software revision", 8: "Serial number",
             9: "Manufacturer name", 10: "Model name", 11: "Asset ID"}
PAIR = {"signal": 1, "spare": 2}
CLASS = {f"class{i}": i + 1 for i in range(5)}


DHCP_TYPES = {"Discover": 1, "Offer": 2, "Request": 3, "Decline": 4, "ACK": 5, "NACK": 6, "Release": 7, "Inform": 8}
DHCP_QUOTED = {"Domain-Name (15)": "domain", "Hostname (12)": "hostname", "Vendor-Class (60)": "vendor_class",
               "TFTP (66)": "tftp", "BF (67)": "bootfile"}
DHCP_ADDRS = {"Server-ID (54)": "server_id", "Subnet-Mask (1)": "subnet", "Default-Gateway (3)": "routers",
              "Domain-Name-Server (6)": "dns", "NTP (42)": "ntp", "Requested-IP (50)": "requested_ip"}
DHCP_HEADER = {"Client-IP": "ciaddr", "Your-IP": "yiaddr", "Server-IP": "siaddr", "Gateway-IP": "giaddr",
               "Client-Ethernet-Address": "chaddr"}


def search_facts(raw):
    """Option 119 (RFC 3397), which tcpdump 4.99 leaves undecoded, decoded by
    dnspython: the option's names, compression pointers relative to its first
    byte."""
    if raw[12:14] != b"\x08\x00":
        return []
    b = raw[14 + 20 + 8 + 240:]
    data, i = b"", 0
    while i < len(b) and b[i] != 255:
        if b[i] == 0:
            i += 1
            continue
        if b[i] == 119:
            data += b[i + 2:i + 2 + b[i + 1]]
        i += 2 + b[i + 1]
    out, off = [], 0
    while off < len(data):
        name, used = dns.name.from_wire(data, off)
        out.append(f"search={name.to_text()}")
        off += used
    return out


def facts(block):
    """Facts from one frame's tcpdump text, in a fixed vocabulary."""
    out = []
    lines = [line.strip() for line in block.splitlines()]
    text = "\n".join(lines)
    for i, line in enumerate(lines):
        m = re.match(r"Subtype .*? \((\d)\): (.*)", line)
        if m and i and lines[i - 1].startswith(("Chassis ID TLV", "Port ID TLV")):
            key = "chassis" if lines[i - 1].startswith("Chassis") else "port"
            out.append(f"{key}={m[1]}:{re.sub(r'^AFI .*? \(\d+\): ', '', m[2])}")
        if m := re.match(r"Time to Live TLV \(3\), length 2: TTL (\d+)s", line):
            out.append(f"ttl={m[1]}")
        if m := re.match(r"Port Description TLV \(4\), length \d+: (.*)", line):
            out.append(f"port_desc={m[1]}")
        if m := re.match(r"System Name TLV \(5\), length \d+: (.*)", line):
            out.append(f"sys_name={m[1]}")
        if line.startswith("System Description TLV (6)"):
            out.append(f"sys_desc={lines[i + 1]}")
        if m := re.match(r"System  Capabilities \[.*\] \((0x[0-9a-f]+)\)", line):
            en = re.match(r"Enabled Capabilities \[.*\] \((0x[0-9a-f]+)\)", lines[i + 1])
            out.append(f"caps={m[1]}/{en[1]}")
        if m := re.match(r"Management Address length \d+, AFI .* \(\d\): (\S+)", line):
            n = re.match(r".* Interface Numbering \((\d)\): (\d+)", lines[i + 1])
            out.append(f"mgmt={m[1]}/{n[1]}/{n[2]}")
        if m := re.match(r"port vlan id \(PVID\): (\d+)", line):
            out.append(f"pvid={m[1]}")
        if m := re.match(r"port and protocol vlan id \(PPVID\): (\d+), flags \[.*\] \((0x[0-9a-f]+)\)", line):
            out.append(f"ppvid={m[1]}/{m[2]}")
        if m := re.match(r"vlan id \(VID\): (\d+)", line):
            out.append(f"vlan_name={m[1]}:{re.match(r'vlan name: (.*)', lines[i + 1])[1]}")
        if m := re.match(r"autonegotiation \[.*\] \((0x[0-9a-f]+)\)", line):
            pmd = re.search(r"\((0x[0-9a-f]+)\)", lines[i + 1])[1]
            mau = int(re.search(r"\((0x[0-9a-f]+)\)", lines[i + 2])[1], 16)
            out.append(f"mac_phy={m[1]}/{pmd}/{mau}")
        if m := re.match(r"MTU size (\d+)", line):
            out.append(f"max_frame={m[1]}")
        if m := re.match(r"MDI power support \[(.*)\], power pair (\w+), power class (\w+)", line):
            bits = sum(FLAG_WORDS[w.strip()] for w in m[1].split(",") if w.strip())
            out.append(f"power=0x{bits:02x}/{PAIR[m[2]]}/{CLASS[m[3]]}")
        if m := re.match(r"Media capabilities \[.*\] \((0x[0-9a-f]+)\)", line):
            dev = re.search(r"\((0x[0-9a-f]+)\)", lines[i + 1])[1]
            out.append(f"med_caps={m[1]}/{int(dev, 16)}")
        if m := re.match(r"Application type \[.*\] \((0x[0-9a-f]+)\), Flags \[(.*)\]", line):
            fl = m[2]
            v = re.match(r"Vlan id (\d+), L2 priority (\d+), DSCP value (\d+)", lines[i + 1])
            out.append(f"policy={int(m[1], 16)}/{int('Unknown' in fl)}/{int('Tagged' in fl)}/{v[1]}/{v[2]}/{v[3]}")
        if m := re.match(r"Power type \[(.*)\], Power source \[(.*)\]", line):
            p = re.match(r"Power priority \[.*\] \((0x[0-9a-f]+)\), Power ([0-9.]+) Watts", lines[i + 1])
            out.append(f"ext_power={EXT_TYPE[m[1]]}/{EXT_SOURCE[m[2]]}/{int(p[1], 16)}/{round(float(p[2]) * 10)}")
        if m := re.match(r"Location data format .* \((0x[0-9a-f]+)\)", line):
            out.append(f"location={int(m[1], 16)}")
        if m := re.match(r"Inventory - .* Subtype \((\d+)\)", line):
            label = INVENTORY[int(m[1])]
            assert lines[i + 1].startswith(label + " "), lines[i + 1]
            out.append(f"inventory={m[1]}:{lines[i + 1][len(label) + 1:]}")
        # CDP
        if m := re.search(r"CDPv(\d), ttl: (\d+)s, checksum: (0x[0-9a-f]+) \(unverified\), length \d+", line):
            out.append(f"cdp_version={m[1]}")
            out.append(f"cdp_ttl={m[2]}")
        if m := re.match(r"Device-ID \(0x01\), value length: \d+ bytes?: '(.*)'", line):
            out.append(f"device_id={m[1]}")
        if line.startswith("Address (0x02)"):
            out += [f"address={a}" for a in re.findall(r"IPv4 \(\d+\) (\S+)", line)]
        if m := re.match(r"Port-ID \(0x03\), value length: \d+ bytes?: '(.*)'", line):
            out.append(f"port_id={m[1]}")
        if m := re.match(r"Capability \(0x04\), value length: \d+ bytes?: \((0x[0-9a-f]+)\)", line):
            out.append(f"cdp_caps={m[1]}")
        if line.startswith("Version String (0x05)"):
            out.append(f"software={lines[i + 1]}")
        if m := re.match(r"Platform \(0x06\), value length: \d+ bytes?: '(.*)'", line):
            out.append(f"platform={m[1]}")
        if m := re.match(r"VTP Management Domain \(0x09\), value length: \d+ bytes?: '(.*)'", line):
            out.append(f"vtp={m[1]}")
        if m := re.match(r"Native VLAN ID \(0x0a\), value length: \d+ bytes?: (\d+)", line):
            out.append(f"native_vlan={m[1]}")
        if m := re.match(r"Duplex \(0x0b\), value length: \d+ bytes?: (\w+)", line):
            out.append(f"duplex={m[1]}")
        # DHCP
        if m := re.search(r"BOOTP/DHCP, (Request|Reply)", line):
            out.append(f"dhcp_op={1 if m[1] == 'Request' else 2}")
            out.append(f"xid=0x{int(re.search(r'xid (0x[0-9a-f]+)', line)[1], 16):08x}")
            if s := re.search(r"secs (\d+)", line):
                out.append(f"secs={s[1]}")
            out.append(f"flags={re.search(r'Flags \[.*\] \((0x[0-9a-f]+)\)', line)[1]}")
        if m := re.match(r"(Client-IP|Your-IP|Server-IP|Gateway-IP|Client-Ethernet-Address) (\S+)$", line):
            out.append(f"{DHCP_HEADER[m[1]]}={m[2]}")
        if m := re.match(r"DHCP-Message \(53\), length 1: (\w+)", line):
            out.append(f"msg_type={DHCP_TYPES[m[1]]}")
        if m := re.match(r"(.+ \(\d+\)), length \d+: (.*)", line):
            if m[1] in DHCP_ADDRS:
                out.append(f"{DHCP_ADDRS[m[1]]}={m[2]}")
            if m[1] in DHCP_QUOTED:
                out.append(f"{DHCP_QUOTED[m[1]]}={m[2][1:-1]}")
            if m[1] == "Lease-Time (51)":
                out.append(f"lease={m[2]}")
            if m[1] == "Client-ID (61)" and m[2].startswith("ether "):
                out.append(f"client_id=1:{m[2][6:]}")
            if m[1] == "Classless-Static-Route (121)":
                for dst, gw in re.findall(r"\(([^:]+):([^)]+)\)", m[2]):
                    out.append(f"route={'0.0.0.0/0' if dst == 'default' else dst}:{gw}")
        if m := re.match(r"\S+ SubOption (\d+), length \d+: (.*)", line):
            out.append(f"relay={m[1]}:{m[2]}")
        if line.startswith("Parameter-Request (55)"):
            codes, j = [], i + 1
            while j < len(lines) and not re.match(r".+ \(\d+\), length \d+", lines[j]):
                codes += re.findall(r"\((\d+)\)", lines[j])
                j += 1
            out.append("prl=" + ",".join(codes))
    return out, text


def main():
    blocks = tcpdump([raw for _, raw, _ in FRAMES])
    if "--show" in sys.argv:
        for (name, _, _), b in zip(FRAMES, blocks):
            print("==", name)
            print(b)
        return
    o = [
        "// SPDX-License-Identifier: MIT",
        "// Generated by modules/l2disco/tools/tcpdump_oracle.py: frames built from the standards, and",
        "// the facts tcpdump read in them"
        f" ({subprocess.run(['tcpdump', '--version'], capture_output=True, text=True).stdout.splitlines()[0]}).",
        "// Replayed by src/tcpdump_oracle_test.zig. Do not edit by hand.",
        "",
        "pub const Frame = struct { name: []const u8, bytes: []const u8, facts: []const []const u8 };",
        "",
        "pub const frames = [_]Frame{",
    ]
    for (name, raw, intent), block in zip(FRAMES, blocks):
        got, text = facts(block)
        got += search_facts(raw)
        if sorted(got) != sorted(intent):
            sys.exit(f"{name}: tcpdump read\n  {sorted(got)}\nintent\n  {sorted(intent)}\n{text}")
        fs = ", ".join('"' + f.replace("\\", "\\\\").replace('"', '\\"') + '"' for f in got)
        o.append(f'    .{{ .name = "{name}", .bytes = "{raw.hex()}", .facts = &.{{{fs}}} }},')
    o.append("};")
    sys.stdout.write("\n".join(o) + "\n")


if __name__ == "__main__":
    main()
