# SPDX-License-Identifier: MIT
"""Probe: does the Linux kernel accept libpcap's `ip6 protochain N` program?

libpcap compiles `ip6 protochain 6` to a loop over the extension headers
(a `ja` BACK to the loop head). A classic-BPF program may not jump backwards
(`ja` takes an unsigned offset and the kernel's check refuses a target past the
end; a backward jump is not expressible). This asks the kernel: the program
`tcpdump -dd 'ip6 protochain 6'` is attached through SO_ATTACH_FILTER on an
AF_PACKET socket on lo and the errno is printed. Run in a user+net namespace:

    unshare -rn sh -c "ip link set lo up && python3 -I modules/rawsock/tools/protochain_probe.py"

Needs tcpdump (libpcap 1.10.x) for `-dd`; the result of the run that decided the
SPEC verdict is pinned in the SPEC (Linux 7.0).
"""
import ctypes, re, socket, struct, subprocess, sys

SO_ATTACH_FILTER = 26


def attach(prog):
    rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    rx.bind(('lo', 0))
    arr = ctypes.create_string_buffer(prog, len(prog))
    fp = struct.pack('H6xQ', len(prog) // 8, ctypes.addressof(arr))
    try:
        rx.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fp)
        return 'accepted'
    except OSError as e:
        return 'refused errno %d (%s)' % (e.errno, e.strerror)
    finally:
        rx.close()


for expr in ('ip6 protochain 6', 'ip6 protochain 44', 'ip protochain 6'):
    r = subprocess.run(['tcpdump', '-Z', 'root', '-dd', expr], capture_output=True, text=True)
    if r.returncode != 0:
        print('%-22s tcpdump: %s' % (expr, r.stderr.strip()[-60:]))
        continue
    prog = b''
    for l in r.stdout.splitlines():
        m = re.match(r'\{ (0x[0-9a-f]+), (\d+), (\d+), (0x[0-9a-f]+) \}', l.strip())
        if m:
            prog += struct.pack('<HBBI', int(m.group(1), 16), int(m.group(2)), int(m.group(3)), int(m.group(4), 16))
    dis = subprocess.run(['tcpdump', '-Z', 'root', '-d', expr], capture_output=True, text=True).stdout
    back = [l for l in dis.splitlines() if re.search(r'\bja\b', l)]
    print('%-22s %3d insns, ja lines: %s -> kernel: %s' % (expr, len(prog) // 8, [l.strip() for l in back], attach(prog)))
