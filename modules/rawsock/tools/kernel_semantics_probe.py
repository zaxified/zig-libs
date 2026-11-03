# SPDX-License-Identifier: MIT
"""Probe: what the Linux kernel does with classic-BPF corner cases, through
SO_ATTACH_FILTER on an AF_PACKET socket on lo. Run inside a user+net
namespace: `unshare -rn sh -c "ip link set lo up && python3 -I tools/kernel_semantics_probe.py"`.
The results (Linux 7.0) are pinned in src/filter.zig, test "run: the semantics
the kernel showed". True = the frame passed, ERRn = attach refused with errno n."""
import socket, struct, sys, time

ETH_P_ALL = 3
SO_ATTACH_FILTER = 26


def ins(code, k, jt=0, jf=0):
    return struct.pack('HBBI', code, jt, jf, k & 0xffffffff)

LD_ABS_W, LD_ABS_H, LD_ABS_B = 0x20, 0x28, 0x30
LD_IND_W = 0x40
LD_IMM, LDX_IMM = 0x00, 0x01
LD_LEN, LDX_LEN = 0x80, 0x81
LD_MEM, LDX_MEM = 0x60, 0x61
ST, STX = 0x02, 0x03
ALU = {'add': 0x04, 'sub': 0x14, 'mul': 0x24, 'div': 0x34, 'or': 0x44, 'and': 0x54, 'lsh': 0x64, 'rsh': 0x74, 'neg': 0x84, 'mod': 0x94, 'xor': 0xa4}
X = 0x08
JEQ = 0x15
RET_K, RET_A = 0x06, 0x16
TAX, TXA = 0x07, 0x87

frame = bytes(range(12)) + b'\x08\x00' + bytes(range(14, 60))


def accepted(prog):
    """True if the kernel delivers `frame` through prog; 'EINVAL' if attach is refused."""
    rx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    rx.bind(('lo', 0))
    buf = b''.join(prog)
    fprog = struct.pack('HL', len(prog), 0)  # placeholder, replaced below
    import ctypes
    arr = ctypes.create_string_buffer(buf, len(buf))
    # struct sock_fprog { u16 len; struct sock_filter *filter; } with padding
    fp = struct.pack('H6xQ', len(prog), ctypes.addressof(arr))
    try:
        rx.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, fp)
    except OSError as e:
        rx.close()
        return 'ERR%d' % e.errno
    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, 0)
    tx.bind(('lo', 0))
    # drain
    rx.settimeout(0.2)
    tx.send(frame)
    ok = False
    try:
        while True:
            d = rx.recv(2048)
            if d == frame:
                ok = True
                break
    except socket.timeout:
        pass
    rx.close(); tx.close()
    return ok


def check(name, setup, expect_a):
    prog = list(setup) + [ins(JEQ, expect_a, 0, 1), ins(RET_K, 65535), ins(RET_K, 0)]
    print('%-46s -> %s' % (name, accepted(prog)))

check('baseline: ld [4] == 0x04050607', [ins(LD_ABS_W, 4)], 0x04050607)
check('ldx #0xffffffff; ld [x+2] == [1..5] (wrap?)', [ins(LDX_IMM, 0xffffffff), ins(LD_IND_W, 2)], 0x01020304)
check('ldx #0xfffffff0; ld [x+0x20] == [0x10..] (wrap?)', [ins(LDX_IMM, 0xfffffff0), ins(LD_IND_W, 0x20)], 0x10111213)
check('ld #1; ldx #32; lsh x == 1 (masked &31?)', [ins(LD_IMM, 1), ins(LDX_IMM, 32), ins(ALU['lsh'] | X, 0)], 1)
check('ld #1; ldx #33; lsh x == 2', [ins(LD_IMM, 1), ins(LDX_IMM, 33), ins(ALU['lsh'] | X, 0)], 2)
check('ld #1; ldx #32; lsh x == 0', [ins(LD_IMM, 1), ins(LDX_IMM, 32), ins(ALU['lsh'] | X, 0)], 0)
check('ld #0x80000000; ldx #32; rsh x == 0x80000000', [ins(LD_IMM, 0x80000000), ins(LDX_IMM, 32), ins(ALU['rsh'] | X, 0)], 0x80000000)
check('ld #0x80000000; ldx #63; rsh x == 1', [ins(LD_IMM, 0x80000000), ins(LDX_IMM, 63), ins(ALU['rsh'] | X, 0)], 1)
check('ld #1; lsh #32 (constant)', [ins(LD_IMM, 1), ins(ALU['lsh'], 32)], 0)
check('ld [-0x1000] (SKF_AD_PROTOCOL) == 0x0000', [ins(LD_ABS_W, 0xfffff000)], 0)
check('ld [-0x1000] proto accepted as nonzero? (== 0 expect False)', [ins(LD_ABS_W, 0xfffff000)], 0x00010203)
check('ld [0xfffffffe] (neg offset, skb_header_pointer?)', [ins(LD_ABS_W, 0xfffffffe)], 0)
check('ldx #0; ld #5; div x (div by zero -> drop)', [ins(LDX_IMM, 0), ins(LD_IMM, 5), ins(ALU['div'] | X, 0)], 0)
check('ld #5; mod x (x=0) -> drop', [ins(LDX_IMM, 0), ins(LD_IMM, 5), ins(ALU['mod'] | X, 0)], 0)
check('ld #5; neg == 0xfffffffb', [ins(LD_IMM, 5), ins(ALU['neg'], 0)], 0xfffffffb)
check('ld #0xffffffff; add #2 == 1', [ins(LD_IMM, 0xffffffff), ins(ALU['add'], 2)], 1)
check('ld mem unset (M[3]) == 0', [ins(LD_MEM, 3)], 0)
check('ldx #len == 60', [ins(LDX_LEN, 0), ins(TXA, 0)], 60)
check('st/ld M[15]', [ins(LD_IMM, 7), ins(ST, 15), ins(LD_IMM, 0), ins(LD_MEM, 15)], 7)
check('ld [x+k] x=100 beyond len -> drop', [ins(LDX_IMM, 100), ins(LD_IND_W, 0)], 0)
print('ret 1 only', accepted([ins(RET_K, 65535)]))
print('ret 0 only', accepted([ins(RET_K, 0)]))
