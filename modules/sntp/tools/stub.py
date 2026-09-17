#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Hostile SNTP stub server, written from RFC 4330 §4 packet layout only.

WHY THIS EXISTS, in two parts:

 1. It is the PEER that makes `query`'s anti-spoof guards testable offline.
    Audit finding F1 was that both guards (peer address/port, origin echo) sat
    in `query`'s receive loop where no test reached them -- and the reason the
    finding could be closed at all is that this stub plus `client.zig` drives
    the real `query` over loopback on an ephemeral port, touching no public NTP
    server (proven with `strace`). The guards now also have direct unit tests,
    but those drive `processReply`/`validateReply`; only this exercises the
    socket path end to end.

 2. `decode-golden` is an INDEPENDENT DECODER for the module's frozen golden
    reply. The golden test in `src/root.zig` asserts offset/delay values; this
    recomputes them from the same 48 bytes using a decoder written from the RFC,
    not from the module.

⚠ Its independence is MEDIUM, not high, and saying so matters: it is a second
implementation written from the same spec by the same author, not a third-party
stack. `ntplib`, `chronyc`, `ntpdate` and `sntp` are not installed here
(checked). What is genuinely foreign is the INPUT -- 48 bytes a Google server
actually sent -- not the decoder.

WHAT IT NEEDS: Python 3 stdlib only. No network beyond 127.0.0.1.

    modules/sntp/tools/stub.py <scenario> [port]   # serve one exchange
    modules/sntp/tools/stub.py decode-golden       # independent golden decode

Prints the bound port on stdout (line 1), diagnostics on stderr.
"""
import socket
import struct
import sys
import time

NTP_UNIX_OFFSET = 2208988800


def pack(li=0, vn=4, mode=4, stratum=2, poll=4, precision=-20,
         root_delay=0, root_disp=0, ref_id=b"GPS\0",
         ref=(0, 0), org=(0, 0), rec=(0, 0), xmt=(0, 0)):
    b0 = (li << 6) | (vn << 3) | mode
    return struct.pack(
        "!BBbbII4sIIIIIIII",
        b0, stratum, poll, precision, root_delay, root_disp, ref_id,
        ref[0], ref[1], org[0], org[1], rec[0], rec[1], xmt[0], xmt[1],
    )


def unpack(data):
    b0, stratum, poll, precision, rd, rdisp, rid, rs, rf, os_, of, rcs, rcf, xs, xf = \
        struct.unpack("!BBbbII4sIIIIIIII", data[:48])
    return dict(li=b0 >> 6, vn=(b0 >> 3) & 7, mode=b0 & 7, stratum=stratum,
                poll=poll, precision=precision, root_delay=rd, root_disp=rdisp,
                ref_id=rid, ref=(rs, rf), org=(os_, of), rec=(rcs, rcf),
                xmt=(xs, xf))


def now_ntp():
    t = time.time() + NTP_UNIX_OFFSET
    s = int(t)
    f = int((t - s) * (1 << 32)) & 0xFFFFFFFF
    return (s, f)


def serve(scenario, port):
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", port))
    real_port = srv.getsockname()[1]
    print(real_port, flush=True)

    if scenario == "silent":
        # Accept the request and never answer: does the client's timeout bound
        # the whole RUN, or only one receive step?
        srv.settimeout(60)
        try:
            srv.recvfrom(2048)
        except socket.timeout:
            pass
        time.sleep(30)
        return

    srv.settimeout(30)
    try:
        data, peer = srv.recvfrom(2048)
    except socket.timeout:
        print("stub: no request arrived", file=sys.stderr)
        return
    req = unpack(data)
    print("stub: request len=%d mode=%d vn=%d T1=%08x.%08x" %
          (len(data), req["mode"], req["vn"], req["xmt"][0], req["xmt"][1]),
          file=sys.stderr)
    # ⚠ T1 here is the WIRE NONCE, not the client's clock reading. Audit F4
    # split the two: the nonce carries 32 CSPRNG bits and is what must be
    # echoed, while the offset math uses the real clock T1. Echoing this value
    # is what an honest server does.
    t1 = req["xmt"]
    t2 = now_ntp()
    t3 = (t2[0], t2[1] + 1000)

    if scenario == "correct":
        pkt = pack(org=t1, rec=t2, xmt=t3)
    elif scenario == "zero_origin":
        pkt = pack(org=(0, 0), rec=t2, xmt=t3)
    elif scenario == "foreign_origin":
        pkt = pack(org=(0xDEADBEEF, 0x12345678), rec=t2, xmt=t3)
    elif scenario == "origin_hi_only":
        # correct seconds, wrong fraction -- probes a half-width comparison
        pkt = pack(org=(t1[0], t1[1] ^ 0xFFFFFFFF), rec=t2, xmt=t3)
    elif scenario == "origin_lo_only":
        pkt = pack(org=(t1[0] ^ 0xFFFFFFFF, t1[1]), rec=t2, xmt=t3)
    elif scenario == "mode3":
        pkt = pack(mode=3, org=t1, rec=t2, xmt=t3)
    elif scenario == "kod":
        pkt = pack(li=3, stratum=0, ref_id=b"DENY", org=t1, rec=t2, xmt=t3)
    elif scenario == "stratum16":
        pkt = pack(stratum=16, org=t1, rec=t2, xmt=t3)
    elif scenario == "li3":
        # LI = 3 "alarm condition, clock not synchronized". Accepted when the
        # audit ran; refused since F7 added `UnsynchronizedLeap`.
        pkt = pack(li=3, stratum=1, org=t1, rec=t2, xmt=t3)
    elif scenario == "far_future":
        far = (0xFFFFFFF0, 0)
        pkt = pack(org=t1, rec=far, xmt=far)
    elif scenario == "zero_t2":
        # Accepted when the audit ran (offset ≈ -63 years); refused since F3
        # added `ReceiveTimestampUnset`.
        pkt = pack(org=t1, rec=(0, 0), xmt=t3)
    elif scenario == "mac68":
        # NTPv4 symmetric-key authenticated reply: 48 + 4-byte key id + 16-byte MD5.
        # Accepted when the audit ran (the MAC was silently dropped); refused
        # since F2 made the truncation flag mean `InvalidLength`.
        pkt = pack(org=t1, rec=t2, xmt=t3) + struct.pack("!I", 1) + b"\xAA" * 16
    elif scenario == "long1024":
        pkt = pack(org=t1, rec=t2, xmt=t3) + b"\xBB" * 976
    elif scenario == "short40":
        pkt = pack(org=t1, rec=t2, xmt=t3)[:40]
    elif scenario == "wrongport":
        # Same source IP, a different source port -- must be ignored, and the
        # run must still end at the deadline rather than early.
        alt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        alt.bind(("127.0.0.1", 0))
        alt.sendto(pack(org=t1, rec=t2, xmt=t3), peer)
        print("stub: sent from alt port %d" % alt.getsockname()[1], file=sys.stderr)
        time.sleep(8)
        return
    elif scenario == "flood_then_correct":
        # 2000 datagrams from foreign ports, then the genuine one: the receive
        # loop must skip the flood without resetting its deadline.
        alt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        alt.bind(("127.0.0.1", 0))
        bogus = pack(org=(0xDEADBEEF, 0), rec=t2, xmt=t3)
        for _ in range(2000):
            alt.sendto(bogus, peer)
        srv.sendto(pack(org=t1, rec=t2, xmt=t3), peer)
        print("stub: 2000 foreign-port datagrams then the genuine reply",
              file=sys.stderr)
        time.sleep(3)
        return
    else:
        raise SystemExit("unknown scenario " + scenario)

    srv.sendto(pkt, peer)
    print("stub: replied %d bytes" % len(pkt), file=sys.stderr)
    time.sleep(3)


def decode_golden():
    golden = bytes.fromhex(
        "2401 00ec 0000 0000 0000 0007 474f 4f47"
        "ee18 7a1c f698 9f83 ee18 7a1c ef6b 2800"
        "ee18 7a1c f698 9f84 ee18 7a1c f698 9f86".replace(" ", ""))
    d = unpack(golden)
    for k, v in d.items():
        print("%-10s %s" % (k, v))
    # T4 from the module's own golden test.
    t4 = (3994581532, 0xF9AC1000)

    def ns(ts):
        return ts[0] * 10**9 + (ts[1] * 10**9 >> 32)

    a = ns(d["rec"]) - ns(d["org"]) + ns(d["xmt"]) - ns(t4)
    # ⚠ Python's // FLOORS; NTP and the module TRUNCATE toward zero. Audit F10
    # exists because that difference is invisible whenever the sum is even --
    # every value in the golden is. Do not "simplify" this back to `a // 2`.
    off = int(a / 2) if a < 0 else a // 2
    delay = (ns(t4) - ns(d["org"])) - (ns(d["xmt"]) - ns(d["rec"]))
    print("offset_ns  %d" % off)
    print("delay_ns   %d" % delay)
    print("unix_time  %.6f" % (d["xmt"][0] + d["xmt"][1] / 2**32 - NTP_UNIX_OFFSET))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    if sys.argv[1] == "decode-golden":
        decode_golden()
        raise SystemExit(0)
    serve(sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 0)
