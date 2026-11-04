# SPDX-License-Identifier: MIT
"""Probe: does the Linux kernel accept libpcap's `ip6 protochain N` program?

libpcap compiles `protochain` to a loop over the extension headers: a `ja` that
jumps BACKWARDS. The kernel refuses that at attach time (its check wants every
jump target past the instruction); libpcap's own USERSPACE interpreter
(`bpf_filter.c`) does run it, so `pcap_offline_filter` filters a savefile with it.
This asks the kernel: the program `tcpdump -dd EXPR` is attached through
SO_ATTACH_FILTER on an AF_PACKET socket on lo. A control (a known-good program) is
attached first in the same namespace, so a refusal means the program, not the
sandbox. Exit status: 0 only when the control attaches and every protochain
program is refused with EINVAL; 1 otherwise (including a missing tcpdump, a
program with no backward `ja`, or a protochain program that attaches).

    unshare -rn sh -c "ip link set lo up && python3 -I modules/rawsock/tools/protochain_probe.py"

Needs tcpdump (libpcap 1.10.x) for `-d`/`-dd`. Result of the run behind the SPEC
verdict (Linux 7.0): control accepted; the three programs: errno 22.
"""
import ctypes, errno, re, socket, struct, subprocess, sys

SO_ATTACH_FILTER = 26


class SockFprog(ctypes.Structure):  # struct sock_fprog, the host's own layout
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def attach(prog):
    """None if the kernel accepted the program, else the errno."""
    rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    try:
        rx.bind(('lo', 0))
        arr = ctypes.create_string_buffer(prog, len(prog))
        fp = SockFprog(len(prog) // 8, ctypes.cast(arr, ctypes.c_void_p))
        rx.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, bytes(fp))
        return None
    except OSError as e:
        return e.errno
    finally:
        rx.close()


def insns(text):
    b = b''
    for l in text.splitlines():
        m = re.match(r'\{ (0x[0-9a-f]+), (\d+), (\d+), (0x[0-9a-f]+) \}', l.strip())
        if m:
            b += struct.pack('<HBBI', int(m.group(1), 16), int(m.group(2)), int(m.group(3)), int(m.group(4), 16))
    return b


bad = False
control = attach(struct.pack('<HBBI', 0x06, 0, 0, 0))  # ret #0
print('control (ret #0): %s' % ('accepted' if control is None else 'REFUSED errno %d' % control))
if control is not None:
    sys.exit(1)
for expr in ('ip6 protochain 6', 'ip6 protochain 44', 'ip protochain 6'):
    r = subprocess.run(['tcpdump', '-Z', 'root', '-dd', expr], capture_output=True, text=True)
    d = subprocess.run(['tcpdump', '-Z', 'root', '-d', expr], capture_output=True, text=True)
    prog = insns(r.stdout)
    if r.returncode != 0 or not prog:
        print('%-22s tcpdump failed: %s' % (expr, r.stderr.strip()[-60:]))
        bad = True
        continue
    back = []
    for l in d.stdout.splitlines():
        m = re.match(r'\((\d+)\)\s+ja\s+(\d+)', l.strip())
        if m and int(m.group(2)) <= int(m.group(1)):
            back.append(l.strip())
    err = attach(prog)
    ok = bool(back) and err == errno.EINVAL
    print('%-22s %3d insns, backward ja: %s -> kernel: %s%s' % (expr, len(prog) // 8, back, 'accepted' if err is None else 'errno %d' % err, '' if ok else '   UNEXPECTED'))
    bad = bad or not ok
sys.exit(1 if bad else 0)
