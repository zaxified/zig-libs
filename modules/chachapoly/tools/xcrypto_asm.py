#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Recipe for `src/xcrypto_amd64.s`: golang.org/x/crypto's amd64 ChaCha20-Poly1305
(`chacha20poly1305/chacha20poly1305_amd64.s`, avo-generated, BSD-3-Clause, see
`../NOTICE`) translated from Go's Plan 9 assembly to GNU AT&T syntax, with:

* a System V entry per function (`zl_chachapoly_xc_open`/`_seal`): it saves the
  callee-saved registers (Go's ABI0 has none), builds the frame the Go body expects
  (288 bytes of locals, the argument block above it where `name+N(FP)` points) and
  calls the body; the argument block is the Go one, `[]byte` = ptr/len/cap, plus a
  tag pointer at offset 104;
* the tag read (open) and written (seal) through that tag pointer instead of
  "at the end of the message": our API keeps `c` and `tag` apart;
* the two tails that touched up to 15 bytes past the message made exact: open's
  last partial block is gathered byte by byte into the frame (Go loads 16 bytes,
  "padded with the MAC"), seal's last partial block is stored byte by byte (Go
  stores 16 and lets the tag overwrite the excess).

usage: xcrypto_asm.py <x/crypto chacha20poly1305_amd64.s> <out .s>
"""
import re
import sys

REG64 = {"AX": "rax", "BX": "rbx", "CX": "rcx", "DX": "rdx", "SI": "rsi", "DI": "rdi",
         "BP": "rbp", "SP": "rsp", **{f"R{i}": f"r{i}" for i in range(8, 16)}}
REG8 = {"AX": "al", "BX": "bl", "CX": "cl", "DX": "dl", "SI": "sil", "DI": "dil",
        "BP": "bpl", "SP": "spl", **{f"R{i}": f"r{i}b" for i in range(8, 16)}}
MNEM = {"MOVOU": "movdqu", "MOVO": "movdqa", "CMOVQCS": "cmovbq", "CMOVQEQ": "cmoveq",
        "CMOVQGT": "cmovgq", "JLT": "jl", "JGT": "jg", "JG": "jg", "JGE": "jge"}
ARGS_AT = 328  # the argument block's offset from the body's %rsp (see the entry)
PREFIX = "zl_chachapoly_xc_"

# (anchor lines, replacement lines): exact-text patches on the Go source, each must
# match exactly once.
PATCHES = [
    # open: the final tag compare reads the tag through the tag pointer.
    (["\tXORQ    AX, AX", "\tMOVQ    $0x00000001, DX", "\tXORQ    (SI), R10", "\tXORQ    8(SI), R11"],
     ["\tXORQ    AX, AX", "\tMOVQ    $0x00000001, DX", "\tMOVQ    tag+104(FP), SI",
      "\tXORQ    (SI), R10", "\tXORQ    8(SI), R11"]),
    # open: the last partial block gathered byte by byte (no read past the message).
    (["\tLEAQ  ·andMask<>+0(SB), R13", "\tMOVOU (SI), X12", "\tADDQ  BX, SI"],
     ["\tLEAQ  ·andMask<>+0(SB), R13",
      "\tMOVQ  $0x00000000, 64(BP)", "\tMOVQ  $0x00000000, 72(BP)", "\tXORQ  CX, CX",
      "openTailGather:", "\tMOVB  (SI)(CX*1), AX", "\tMOVB  AX, 64(BP)(CX*1)", "\tINCQ  CX",
      "\tCMPQ  CX, BX", "\tJB    openTailGather",
      "\tMOVOU 64(BP), X12", "\tADDQ  BX, SI"]),
    # seal: the last partial block stored byte by byte (no write past the message).
    (["\tPXOR   64(BP), X1", "\tMOVOU  X1, (DI)"],
     ["\tPXOR   64(BP), X1", "\tMOVOU  X1, 64(BP)", "\tXORQ   CX, CX",
      "sealTailScatter:", "\tMOVB   64(BP)(CX*1), AX", "\tMOVB   AX, (DI)(CX*1)", "\tINCQ   CX",
      "\tCMPQ   CX, BX", "\tJB     sealTailScatter"]),
    # seal: the tag written through the tag pointer.
    (["\t// Finally store the tag at the end of the message", "\tMOVQ R10, (DI)", "\tMOVQ R11, 8(DI)"],
     ["\t// The tag, through the tag pointer", "\tMOVQ tag+104(FP), DI", "\tMOVQ R10, (DI)",
      "\tMOVQ R11, 8(DI)"]),
]


def patch(lines):
    for anchor, repl in PATCHES:
        hits = [i for i in range(len(lines) - len(anchor) + 1) if lines[i:i + len(anchor)] == anchor]
        if len(hits) != 1:
            sys.exit(f"patch anchor {anchor[1]!r}: {len(hits)} matches, want 1")
        i = hits[0]
        lines[i:i + len(anchor)] = repl
    return lines


def reg(name, byte=False):
    if name in REG64:
        return "%" + (REG8 if byte else REG64)[name]
    m = re.fullmatch(r"([XY])(\d+)", name)
    if m:
        return f"%{'xmm' if m[1] == 'X' else 'ymm'}{m[2]}"
    sys.exit(f"unknown register {name}")


def sym(name):
    return PREFIX + name.lstrip("·").replace("<>", "")


def operand(op, byte=False):
    op = op.strip()
    if op.startswith("$"):
        return op
    m = re.fullmatch(r"[a-z_]+\+(\d+)\(FP\)", op)
    if m:
        return f"{ARGS_AT + int(m[1])}(%rsp)"
    m = re.fullmatch(r"(·?\w+<>)\+(-?\d+)\(SB\)", op)
    if m:
        return f"{sym(m[1])}+{m[2]}(%rip)"
    m = re.fullmatch(r"(-?\d*)\((\w+)\)(?:\((\w+)\*(\d)\))?", op)
    if m:
        base = reg(m[2])
        idx = f",{reg(m[3])},{m[4]}" if m[3] else ""
        return f"{m[1]}({base}{idx})"
    return reg(op, byte)


def translate(src):
    out = []
    data = {}   # symbol -> bytearray
    sizes = {}
    func = None
    labels = set()
    for raw in src:
        line = raw.rstrip()
        s = line.strip()
        if not s or s.startswith("#include") or s.startswith("//go:build"):
            continue
        if s.startswith("//"):
            out.append("\t#" + s[2:])
            continue
        m = re.match(r"TEXT\s+(·?\w+<>|·\w+)\(SB\)", s)
        if m:
            func = m[1].lstrip("·").replace("<>", "")
            out.append("")
            out.append(f"{PREFIX}{func}_body:" if "<>" not in m[1] else f"{PREFIX}{func}:")
            continue
        m = re.fullmatch(r"(\w+):", s)
        if m:
            labels.add(m[1])
            out.append(f".L{func}_{m[1]}:")
            continue
        m = re.fullmatch(r"DATA\s+(·?\w+<>)\+(\d+)\(SB\)/(\d),\s*\$(\S+)", s)
        if m:
            b = data.setdefault(m[1], bytearray())
            off, n, v = int(m[2]), int(m[3]), int(m[4], 0)
            if len(b) < off + n:
                b.extend(b"\0" * (off + n - len(b)))
            b[off:off + n] = (v & ((1 << (8 * n)) - 1)).to_bytes(n, "little")
            continue
        m = re.fullmatch(r"GLOBL\s+(·?\w+<>)\(SB\),\s*\S+,\s*\$(\d+)", s)
        if m:
            sizes[m[1]] = int(m[2])
            continue
        parts = s.split(None, 1)
        mn = parts[0]
        ops = [o for o in re.split(r",\s*", parts[1].split("//")[0].strip())] if len(parts) > 1 else []
        if mn in ("JMP", "JE", "JNE", "JB", "JBE", "JLT", "JGT", "JG", "JGE", "CALL"):
            tgt = ops[0]
            if tgt.endswith("(SB)"):
                out.append(f"\t{MNEM.get(mn, mn.lower())} {sym(tgt[:-4])}")
            else:
                out.append(f"\t{MNEM.get(mn, mn.lower())} .L{func}_{tgt}")
            continue
        if mn == "RET":
            out.append("\tret")
            continue
        byte = mn == "MOVB"
        tops = [operand(o, byte) for o in ops]
        if mn.startswith("CMP"):
            tops = tops[::-1]  # Plan 9 CMP is in Intel order
        if mn in ("SHLQ", "SHRQ") and len(ops) == 3:
            mn = "SHLDQ" if mn == "SHLQ" else "SHRDQ"
        out.append(f"\t{MNEM.get(mn, mn.lower())} " + ", ".join(tops) if tops else f"\t{MNEM.get(mn, mn.lower())}")
    # read-only data, 32-byte aligned (VMOVDQA reads it)
    ro = ["", "\t.pushsection .rodata", "\t.balign 32"]
    for name, b in data.items():
        size = sizes.get(name, len(b))
        b = b + b"\0" * (size - len(b))
        ro.append("\t.balign 32")
        ro.append(f"{sym(name)}:")
        for i in range(0, len(b), 16):
            ro.append("\t.byte " + ",".join(f"0x{x:02x}" for x in b[i:i + 16]))
    ro.append("\t.popsection")
    return out, ro


ENTRY = """
	# System V entry: %rdi = the argument block (Go's layout + tag pointer at 104).
	.globl {p}{f}
	.hidden {p}{f}
	.type {p}{f},@function
{p}{f}:
	pushq %rbp
	pushq %rbx
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	subq $440, %rsp
	movdqu 0(%rdi), %xmm0
	movdqu %xmm0, 320(%rsp)
	movdqu 16(%rdi), %xmm0
	movdqu %xmm0, 336(%rsp)
	movdqu 32(%rdi), %xmm0
	movdqu %xmm0, 352(%rsp)
	movdqu 48(%rdi), %xmm0
	movdqu %xmm0, 368(%rsp)
	movdqu 64(%rdi), %xmm0
	movdqu %xmm0, 384(%rsp)
	movdqu 80(%rdi), %xmm0
	movdqu %xmm0, 400(%rsp)
	movdqu 96(%rdi), %xmm0
	movdqu %xmm0, 416(%rsp)
	call {p}{f}_body
	movzbl 416(%rsp), %eax
	vzeroupper
	addq $440, %rsp
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %rbx
	popq %rbp
	ret
	.size {p}{f}, .-{p}{f}
"""


def main():
    src = open(sys.argv[1]).read().split("\n")
    lines = patch(src)
    body, ro = translate(lines)
    hdr = [
        "# GENERATED by modules/chachapoly/tools/xcrypto_asm.py from golang.org/x/crypto",
        "# v0.58.0 chacha20poly1305/chacha20poly1305_amd64.s (BSD-3-Clause, Copyright The Go",
        "# Authors; see ../NOTICE). Do not edit; re-run the recipe.",
        "# A Zig inline-asm template (every register is written %%reg): the body of the",
        "# exported naked function `zl_chachapoly_xc_blob` in root.zig. Function-level",
        "# inline asm keeps its AT&T dialect when Zig emits Intel-syntax assembly",
        "# (-femit-asm, -Djcc-safe); module-level asm did not.",
        "\t.p2align 5",
    ]
    entries = [ENTRY.format(p=PREFIX, f=f) for f in ("chacha20Poly1305Open", "chacha20Poly1305Seal")]
    # The arguments live at ARGS_AT(%rsp) inside the body: the entry's 440-byte frame
    # holds 320 bytes of body locals below the argument block, and the call pushes 8.
    assert ARGS_AT == 320 + 8
    text = "\n".join(entries + body + ro).replace("%", "%%")
    open(sys.argv[2], "w").write("\n".join(hdr) + "\n" + text + "\n")


main()
