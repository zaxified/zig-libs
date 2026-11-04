// SPDX-License-Identifier: MIT
//! A tcpdump-style filter expression → classic BPF, plus a classic-BPF
//! interpreter to run any program over a frame in userspace.
//!
//! `compile("tcp dst port 22 and not ip src net 10.0.0.0/8")` returns a program
//! for `Socket.setFilter`/`Options.filter`, so a capture drops unwanted frames
//! in the kernel instead of in a `recv` loop (see `Options.recv_timeout_ms` for
//! why that matters). `run(prog, frame)` executes a program the way the kernel
//! does — out-of-bounds loads drop the frame — which is how this file tests the
//! compiler without a socket.
//!
//! ## The language (a subset of pcap-filter(7), same meaning)
//!
//! ```text
//! expr      := factor { ("and" | "&&" | "or" | "||") factor }   (equal precedence, left to right)
//! factor    := ("not" | "!") factor | "(" expr ")" | primitive
//! primitive := "ip" | "ip6" | "arp" | "icmp" | "tcp" | "udp" | "sctp"
//!            | "ether" ("src" | "dst" | "host") MAC     | "ether" "proto" NUM
//!            | "ip" "proto" NUM
//!            | "ip" ["src" | "dst"] "host" A.B.C.D      | "ip" ["src" | "dst"] "net" A.B.C.D/LEN
//!            | ["tcp" | "udp" | "sctp"] ["src" | "dst"] "port" NUM
//! ```
//!
//! Each primitive means what libpcap 1.10 makes it mean — read off
//! `tcpdump -d` (black-box; libpcap's source was read only for specific questions, nothing ported) and pinned by a
//! differential test against `tcpdump -r` over a corpus of frames:
//!
//! * `tcp`/`udp`/`sctp` match IPv4 by protocol, and IPv6 by the fixed header's
//!   next-header field or a fragment header (44) whose next header is the
//!   protocol. `icmp` is IPv4 only.
//! * A port test on IPv4 also requires a non-fragmented datagram (fragment
//!   offset 0 — only the first fragment carries the ports) and finds the
//!   transport header through the IHL (`ldxb 4*([14]&0xf)`); on IPv6 it reads
//!   the ports right after the 40-byte header, with no extension-header walk.
//!   `port N` alone is tcp, udp or sctp.
//! * `ether host` is source or destination.
//!
//! * Bare `host`/`net` (no `ip`/`ip6`) is libpcap's reading: an IPv4 literal
//!   matches IP, ARP and RARP (sender/target protocol address), an IPv6 literal
//!   matches IPv6. `net A/LEN`, `net 10` (/8), `net 10.1` (/16), `net A mask M`
//!   (contiguous); host bits outside the prefix are refused, as libpcap does.
//! * `host a or b`, `port 80 or 443`, `ether host x or y`: a bare value after
//!   `and`/`or` repeats the previous primitive's qualifiers.
//! * `and` and `or` have EQUAL precedence, left to right (pcap-filter(7));
//!   only `not` binds tighter. `tcp or udp and port 53` is `(tcp or udp) and port 53`.
//! * `portrange A-B` (swapped when A > B), `less N` (len <= N), `greater N`
//!   (len >= N), `len RELOP N`, `broadcast` / `multicast` (Ethernet), `icmp6`,
//!   `proto N`, `ip|ip6 proto N` (a number, or `\tcp`-style names: libpcap needs
//!   the backslash too), `ether proto \ip`, and offset expressions
//!   `ether|ip|ip6|arp|rarp|tcp|udp|icmp|sctp[OFF[:SIZE]] [& MASK] RELOP N` with
//!   a literal offset (SIZE 1, 2 or 4; spaces inside the brackets are fine),
//!   `tcpflags` / `icmptype` / `icmpcode` as the offset, and named values
//!   (`tcp-syn` ... `tcp-cwr`, `icmp-echo` ...) or `(a|b)` of them as MASK or N.
//!   Transport offsets are IPv4-only, as libpcap's. Numbers are libpcap's:
//!   decimal, `0x` hex, leading-0 octal; no sign, no `_`.
//! * `vlan` and `vlan N`: the tag in the packet (offline form, what `tcpdump -r`
//!   means). Like libpcap, every primitive written AFTER a `vlan` looks inside
//!   the tag (offsets +4; MAC addresses, `multicast` and `ether[..]` are not
//!   moved), so `vlan and ip` tests the inner EtherType and `vlan and vlan 5`
//!   the second tag. `Options.vlan_ancillary` is the form for a live socket
//!   (the kernel strips the tag there): the first `vlan` asks the kernel's
//!   `SKF_AD_VLAN_TAG_PRESENT` / `SKF_AD_VLAN_TAG` words, and when the tag is
//!   still in the frame sets the run-time shift in M[0] to 4; the primitives
//!   written after it load through `ldx M[0]` (libpcap's `ldx M[1]` form). It
//!   works alone and combined (`vlan and ip`, `vlan 5 and tcp port 80`) and
//!   is kernel-only: `run` drops negative-offset loads, `runLive` answers them
//!   from the `Frame.vlan_tci` metadata (see `usesAncillary`).
//! * `Options.link`: `.ethernet` (default), `.linux_sll` (a `tcpdump -i any`
//!   savefile: offsets +2), `.linux_sll2` (cooked v2, +6, the protocol field
//!   first: what tcpdump 4.99 captures `-i any` as), `.raw` (no link header:
//!   the IP version nibble replaces the EtherType; `arp` is refused, as in
//!   libpcap) and `.bsd_null` / `.bsd_loop` (a 4-byte address-family word:
//!   NULL in the capturing host's byte order, LOOP in network order; `ip` is
//!   AF 2, `ip6` the savefile numbers 24, 28 and 30; `arp` is refused).
//!
//! * `inbound`, `outbound`, `ifindex N`: the kernel's packet type and interface index
//!   (`SKF_AD_PKTTYPE`, `SKF_AD_IFINDEX`); live only, `runLiveMeta` answers them from the metadata.
//!   `mpls [N]` and `pppoes [N]` work alone only.
//! * Compile nesting is bounded (`Parser.max_depth` 16 parentheses / `not`), left-deep
//!   chains are walked by a loop: the deepest accepted input compiles in a 64 KiB stack.
//!
//! Not supported (`error.UnsupportedExpression`): host and network *names*
//! and `gateway` (the resolver, /etc/ethers), `ip broadcast` / `ip multicast`
//! (the interface netmask), service names for ports, computed offsets
//! (`ip[ip[0] & 0xf]`), `protochain` (libpcap's program jumps backwards: the
//! kernel refuses it with EINVAL, `tools/protochain_probe.py`), MPLS and the
//! link types beyond the six above (802.11, PPP...). The generated code is not
//! optimised: longer than libpcap's, with the same verdicts on every row of the tcpdump oracle (known deviations: offline `ip and vlan` without an id, which libpcap refuses; live `ip and vlan 5`, where libpcap's own program accepts nothing; and libpcap's quirk that a failed live `vlan` test leaves the shift at 4, so `vlan or ip` misses plain IPv4, repeated here). A program
//! may use `ja` stubs for jumps over 255 instructions (as libpcap does) and
//! is refused past `max_insns` (4096).

const std = @import("std");
const root = @import("root.zig");
const netaddr = @import("netaddr");
const BpfInsn = root.BpfInsn;

// ── opcodes (<linux/bpf_common.h>, <linux/filter.h>) ─────────────────────────

pub const op = struct {
    // classes
    pub const ld: u16 = 0x00;
    pub const ldx: u16 = 0x01;
    pub const alu: u16 = 0x04;
    pub const jmp: u16 = 0x05;
    pub const ret: u16 = 0x06;
    pub const misc: u16 = 0x07;
    // sizes
    pub const w: u16 = 0x00;
    pub const h: u16 = 0x08;
    pub const b: u16 = 0x10;
    // modes
    pub const imm: u16 = 0x00;
    pub const abs: u16 = 0x20;
    pub const ind: u16 = 0x40;
    pub const len: u16 = 0x80;
    pub const msh: u16 = 0xa0;
    // alu / jmp operations
    pub const add: u16 = 0x00;
    pub const sub: u16 = 0x10;
    pub const @"and": u16 = 0x50;
    pub const @"or": u16 = 0x40;
    pub const lsh: u16 = 0x60;
    pub const rsh: u16 = 0x70;
    pub const ja: u16 = 0x00;
    pub const jeq: u16 = 0x10;
    pub const jgt: u16 = 0x20;
    pub const jge: u16 = 0x30;
    pub const jset: u16 = 0x40;
    // sources
    pub const k: u16 = 0x00;
    pub const x: u16 = 0x08;
    pub const a: u16 = 0x10; // ret A
    // misc
    pub const tax: u16 = 0x00;
    pub const txa: u16 = 0x80;
    // scratch memory
    pub const st: u16 = 0x02;
    pub const mem: u16 = 0x60;
};

/// The snapshot length an accepting program returns — libpcap's default
/// (`ret #262144`), i.e. "the whole frame".
pub const accept_len: u32 = 262144;

/// `BPF_MAXINSNS` — the kernel refuses longer classic programs.
pub const max_insns = 4096;

// ── interpreter ─────────────────────────────────────────────────────────────

/// Run a classic-BPF program over `frame` and return what it returns: the
/// number of bytes to keep, 0 = drop. Kernel semantics: a load past the end of
/// the frame drops it (returns 0); division by zero drops it; running off the
/// end of the program or a jump past it drops it. Supports the whole classic
/// instruction set (loads, ALU, jumps, scratch memory, `len`, `tax`/`txa`);
/// an opcode the kernel would refuse at attach time drops the frame.
pub fn run(prog: []const BpfInsn, frame: []const u8) u32 {
    return exec(false, prog, frame, .{});
}

/// `run` for a program that reads the kernel's packet metadata (`usesAncillary`):
/// `vlan_tci` is what a live AF_PACKET socket reports for the frame
/// (`Frame.vlan_tci`, the tag the kernel stripped), null when the frame still
/// carries its tag or has none. The `SKF_AD_VLAN_TAG_PRESENT` and
/// `SKF_AD_VLAN_TAG` words answer from it; any other ancillary or negative
/// offset drops the frame, as in `run`. So a program from `compileOpts` with
/// `vlan_ancillary` gets its userspace verdict here.
pub fn runLive(prog: []const BpfInsn, frame: []const u8, vlan_tci: ?u16) u32 {
    return exec(true, prog, frame, .{ .vlan_tci = vlan_tci });
}

/// The packet metadata a live socket has besides the frame.
pub const LiveMeta = struct {
    /// The tag the kernel stripped (`Frame.vlan_tci`), null when none.
    vlan_tci: ?u16 = null,
    /// `sockaddr_ll.sll_pkttype` (`Frame.pkttype`): 0 host, 1 broadcast, 2 multicast, 3 otherhost, 4 outgoing.
    pkttype: u8 = 0,
    /// The interface index the frame arrived on or leaves from.
    ifindex: u32 = 0,
};

/// `runLive` with the whole metadata: `inbound`, `outbound`, `ifindex N` and `vlan` programs.
pub fn runLiveMeta(prog: []const BpfInsn, frame: []const u8, meta: LiveMeta) u32 {
    return exec(true, prog, frame, meta);
}

inline fn ancWord(k: u32, m: LiveMeta) ?u32 {
    return switch (k - ancillary_base) {
        4 => m.pkttype,
        8 => m.ifindex,
        44 => m.vlan_tci orelse 0,
        48 => @intFromBool(m.vlan_tci != null),
        else => null,
    };
}

fn exec(comptime anc: bool, prog: []const BpfInsn, frame: []const u8, tci: LiveMeta) u32 {
    var A: u32 = 0;
    var X: u32 = 0;
    // Scratch memory M[0..15]: a slot nothing stored to reads as 0 (the kernel
    // refuses programs that read before writing; this one reads zero), which
    // `mem_set` tracks so the call does not zero 64 bytes first.
    var mem: [16]u32 = undefined;
    var mem_set: u16 = 0;
    var pc: usize = 0;
    // Terminates: every instruction advances `pc` by at least one and no
    // classic-BPF jump goes backwards (offsets are unsigned), so the loop runs
    // at most `prog.len` times.
    while (pc < prog.len) {
        const i = prog[pc];
        pc += 1;
        // One switch over the whole opcode (class | size | mode, or class |
        // op | source): the kernel's own validity list, nothing else runs.
        switch (i.code) {
            op.ld | op.w | op.imm => A = i.k,
            op.ldx | op.w | op.imm => X = i.k,
            op.ld | op.w | op.len => A = @truncate(frame.len),
            op.ldx | op.w | op.len => X = @truncate(frame.len),
            op.ld | op.w | 0x60 => { // ld M[k]
                if (i.k >= mem.len) return 0;
                A = if (mem_set >> @intCast(i.k) & 1 != 0) mem[i.k] else 0;
            },
            op.ldx | op.w | 0x60 => {
                if (i.k >= mem.len) return 0;
                X = if (mem_set >> @intCast(i.k) & 1 != 0) mem[i.k] else 0;
            },
            op.ld | op.w | op.abs => A = (if (anc and i.k >= ancillary_base) ancWord(i.k, tci) else load32(frame, i.k)) orelse return 0,
            op.ld | op.h | op.abs => A = (if (anc and i.k >= ancillary_base) ancWord(i.k, tci) else load16(frame, i.k)) orelse return 0,
            op.ld | op.b | op.abs => A = (if (anc and i.k >= ancillary_base) ancWord(i.k, tci) else load8(frame, i.k)) orelse return 0,
            op.ld | op.w | op.ind => A = load32(frame, X +% i.k) orelse return 0,
            op.ld | op.h | op.ind => A = load16(frame, X +% i.k) orelse return 0,
            op.ld | op.b | op.ind => A = load8(frame, X +% i.k) orelse return 0,
            op.ldx | op.b | op.msh => X = ((load8(frame, i.k) orelse return 0) & 0x0f) * 4,
            0x02 => { // st
                if (i.k >= mem.len) return 0;
                mem[i.k] = A;
                mem_set |= @as(u16, 1) << @intCast(i.k);
            },
            0x03 => { // stx
                if (i.k >= mem.len) return 0;
                mem[i.k] = X;
                mem_set |= @as(u16, 1) << @intCast(i.k);
            },
            inline op.alu | op.add | op.k,
            op.alu | op.add | op.x,
            op.alu | op.sub | op.k,
            op.alu | op.sub | op.x,
            op.alu | 0x20 | op.k, // mul
            op.alu | 0x20 | op.x,
            op.alu | op.@"or" | op.k,
            op.alu | op.@"or" | op.x,
            op.alu | op.@"and" | op.k,
            op.alu | op.@"and" | op.x,
            op.alu | 0xa0 | op.k, // xor
            op.alu | 0xa0 | op.x,
            op.alu | op.lsh | op.k,
            op.alu | op.lsh | op.x,
            op.alu | op.rsh | op.k,
            op.alu | op.rsh | op.x,
            => |c| {
                const src = if (comptime c & op.x != 0) X else i.k;
                switch (comptime c & 0xf0) {
                    op.add => A +%= src,
                    op.sub => A -%= src,
                    0x20 => A *%= src,
                    op.@"or" => A |= src,
                    op.@"and" => A &= src,
                    0xa0 => A ^= src,
                    // The kernel masks a register shift count to five bits
                    // (probed on Linux 7.0: 1 << 32 is 1) and refuses a
                    // constant of 32 or more at attach time (`validate`).
                    op.lsh => A = if (comptime c & op.x != 0) A << @intCast(src & 31) else if (src >= 32) return 0 else A << @intCast(src),
                    op.rsh => A = if (comptime c & op.x != 0) A >> @intCast(src & 31) else if (src >= 32) return 0 else A >> @intCast(src),
                    else => comptime unreachable,
                }
            },
            op.alu | 0x30 | op.k, op.alu | 0x30 | op.x, op.alu | 0x90 | op.k, op.alu | 0x90 | op.x => { // div, mod
                const src = if (i.code & op.x != 0) X else i.k;
                if (src == 0) return 0;
                A = if (i.code & 0xf0 == 0x30) A / src else A % src;
            },
            op.alu | 0x80 => A = 0 -% A, // neg
            op.jmp | op.ja => pc = advance(usize, pc, i.k),
            inline op.jmp | op.jeq | op.k,
            op.jmp | op.jeq | op.x,
            op.jmp | op.jgt | op.k,
            op.jmp | op.jgt | op.x,
            op.jmp | op.jge | op.k,
            op.jmp | op.jge | op.x,
            op.jmp | op.jset | op.k,
            op.jmp | op.jset | op.x,
            => |c| {
                const src = if (comptime c & op.x != 0) X else i.k;
                const taken = switch (comptime c & 0xf0) {
                    op.jeq => A == src,
                    op.jgt => A > src,
                    op.jge => A >= src,
                    op.jset => A & src != 0,
                    else => comptime unreachable,
                };
                pc += if (taken) i.jt else i.jf;
            },
            op.ret | op.k => return i.k,
            op.ret | op.a => return A,
            op.misc | op.tax => X = A,
            op.misc | op.txa => A = X,
            else => return 0,
        }
    }
    return 0;
}

/// What the kernel refuses when a classic program is attached
/// (`bpf_check_classic`, probed on Linux 7.0 through `SO_ATTACH_FILTER`):
/// `Length` 0 or over `max_insns`; `Opcode` not a classic-BPF opcode; `Jump`
/// past the end; `Scratch` an `M[k]` with k >= 16; `Shift` a constant shift
/// of 32 or more; `DivZero` a division or modulus by the constant 0;
/// `Uninitialised` an `M[k]` read on some path that never stored to it;
/// `Ancillary` a negative load offset in the ancillary window that is not an
/// `SKF_AD_*` word; `NoReturn` a last instruction that is not a `ret`.
pub const ValidateError = error{ Length, Opcode, Jump, Scratch, Shift, DivZero, Uninitialised, Ancillary, NoReturn };

/// `SKF_AD_*` indices (`<linux/filter.h>`): PROTOCOL, PKTTYPE, IFINDEX, NLATTR,
/// NLATTR_NEST, MARK, QUEUE, HATYPE, RXHASH, CPU, ALU_XOR_X, VLAN_TAG,
/// VLAN_TAG_PRESENT, PAY_OFFSET, RANDOM, VLAN_TPID.
fn ancillaryIndex(k: u32) bool {
    if (k < ancillary_base or k - ancillary_base > 60) return false;
    return (k - ancillary_base) % 4 == 0;
}

fn isAncillaryLoad(i: BpfInsn) bool {
    const abs = i.code == (op.ld | op.w | op.abs) or i.code == (op.ld | op.h | op.abs) or i.code == (op.ld | op.b | op.abs);
    return abs and i.k >= 0x80000000; // a negative offset
}

/// Does `prog` have an absolute load at a NEGATIVE offset: the ancillary words
/// (`SKF_AD_*`, e.g. `vlan` compiled with `Options.vlan_ancillary`) or the
/// header-relative `SKF_NET_OFF` / `SKF_LL_OFF` loads? Such a program works in
/// the kernel only: `run` has a frame and no packet metadata, so those loads
/// drop the frame there (it never reads, never panics). Use this to refuse
/// them where a userspace verdict is wanted.
pub fn usesAncillary(prog: []const BpfInsn) bool {
    for (prog) |i| if (isAncillaryLoad(i)) return true;
    return false;
}

/// The kernel's attach-time checks, so a program that `validate`s is one
/// `Socket.setFilter` accepts. Allocation-free: the scratch-initialisation
/// pass keeps one `u16` mask per instruction on the stack (8 KiB at most).
pub fn validate(prog: []const BpfInsn) ValidateError!void {
    if (prog.len == 0 or prog.len > max_insns) return error.Length;
    var init: [max_insns]u16 = undefined; // scratch slots stored on EVERY path reaching pc
    @memset(init[0..prog.len], 0xffff);
    var memvalid: u16 = 0; // the kernel's running mask (bpf_check_classic): carried through a ret, reset to all-valid after a jump
    for (prog, 0..) |i, pc| {
        memvalid &= init[pc];
        switch (i.code) {
            op.ld | op.w | op.imm,
            op.ldx | op.w | op.imm,
            op.ld | op.w | op.len,
            op.ldx | op.w | op.len,
            op.ld | op.w | op.ind,
            op.ld | op.h | op.ind,
            op.ld | op.b | op.ind,
            op.ldx | op.b | op.msh,
            op.misc | op.tax,
            op.misc | op.txa,
            op.alu | op.add | op.k,
            op.alu | op.add | op.x,
            op.alu | op.sub | op.k,
            op.alu | op.sub | op.x,
            op.alu | 0x20 | op.k,
            op.alu | 0x20 | op.x,
            op.alu | op.@"or" | op.k,
            op.alu | op.@"or" | op.x,
            op.alu | op.@"and" | op.k,
            op.alu | op.@"and" | op.x,
            op.alu | 0xa0 | op.k,
            op.alu | 0xa0 | op.x,
            op.alu | 0x30 | op.x,
            op.alu | 0x90 | op.x,
            op.alu | 0x80,
            => {},
            op.ld | op.w | op.abs, op.ld | op.h | op.abs, op.ld | op.b | op.abs => {
                // Negative offsets: SKF_AD_OFF and up are the ancillary words,
                // anything from there to 0 that is not one is refused.
                if (i.k >= 0xfffff000 and !ancillaryIndex(i.k)) return error.Ancillary;
            },
            op.alu | 0x30 | op.k, op.alu | 0x90 | op.k => if (i.k == 0) return error.DivZero,
            op.alu | op.lsh | op.k, op.alu | op.rsh | op.k => if (i.k >= 32) return error.Shift,
            op.alu | op.lsh | op.x, op.alu | op.rsh | op.x => {},
            op.ld | op.w | 0x60, op.ldx | op.w | 0x60 => {
                if (i.k >= 16) return error.Scratch;
                if (memvalid >> @intCast(i.k) & 1 == 0) return error.Uninitialised;
            },
            0x02, 0x03 => {
                if (i.k >= 16) return error.Scratch;
                memvalid |= @as(u16, 1) << @intCast(i.k);
            },
            op.jmp | op.ja => {
                if (i.k >= prog.len - pc - 1) return error.Jump;
                init[pc + 1 + i.k] &= memvalid;
                memvalid = 0xffff;
                continue;
            },
            op.jmp | op.jeq | op.k,
            op.jmp | op.jeq | op.x,
            op.jmp | op.jgt | op.k,
            op.jmp | op.jgt | op.x,
            op.jmp | op.jge | op.k,
            op.jmp | op.jge | op.x,
            op.jmp | op.jset | op.k,
            op.jmp | op.jset | op.x,
            => {
                if (pc + 1 + i.jt >= prog.len or pc + 1 + i.jf >= prog.len) return error.Jump;
                init[pc + 1 + i.jt] &= memvalid;
                init[pc + 1 + i.jf] &= memvalid;
                memvalid = 0xffff;
                continue;
            },
            op.ret | op.k, op.ret | op.a => continue,
            else => return error.Opcode,
        }
    }
    const last = prog[prog.len - 1].code;
    if (last != (op.ret | op.k) and last != (op.ret | op.a)) return error.NoReturn;
}

inline fn load8(frame: []const u8, at: u64) ?u32 {
    if (at >= frame.len) return null;
    return frame[@intCast(at)];
}

inline fn load16(frame: []const u8, at: u64) ?u32 {
    if (at > frame.len or frame.len - at < 2) return null;
    return std.mem.readInt(u16, frame[@intCast(at)..][0..2], .big);
}

inline fn load32(frame: []const u8, at: u64) ?u32 {
    if (at > frame.len or frame.len - at < 4) return null;
    return std.mem.readInt(u32, frame[@intCast(at)..][0..4], .big);
}

/// `pc + k` that cannot overflow: on a 32-bit target `usize` is 32 bits and a
/// `ja` offset is a full `u32`. Saturating lands past the program, which
/// drops the frame, exactly what any too-large jump does. See sweep RS2.
fn advance(comptime U: type, pc: U, k: u32) U {
    return pc +| k;
}

// ── compiler ────────────────────────────────────────────────────────────────

pub const CompileError = std.mem.Allocator.Error || error{
    /// Not a well-formed expression (unbalanced parentheses, a missing
    /// operand, a malformed address or number).
    Syntax,
    /// Well-formed pcap-filter syntax this compiler does not implement (see
    /// the file header).
    UnsupportedExpression,
    /// The program would need a jump longer than 255 instructions or more
    /// than `max_insns` instructions.
    FilterTooComplex,
};

const Size = enum(u16) { w = op.w, h = op.h, b = op.b };

/// One comparison: load (optionally through the IPv4 header length), an
/// optional mask, then `jeq`/`jset`.
const Test = struct {
    size: Size,
    off: u32,
    /// Offset is relative to the IPv4 header length (`ldxb 4*([14]&0xf)`).
    ind: bool = false,
    mask: ?u32 = null,
    kind: enum { eq, set, ge, gt } = .eq,
    /// Load the frame length (`ld #pktlen`) instead of frame bytes.
    len: bool = false,
    /// Not moved by the link-layer shift (a MAC address, `ether[..]`, the
    /// multicast bit, an ancillary word).
    fixed: bool = false,
    /// The IPv4 header-length load of an indirect test (`ldxb 4*([msh]&0xf)`).
    msh: u32 = 14,
    /// Loads go through the run-time vlan shift in M[0] (`ldx M[0]; ld [x+off]`,
    /// the live ancillary form after a `vlan`).
    dyn: bool = false,
    k: u32,
};

const Node = union(enum) {
    /// The first `vlan [N]` of a live (ancillary) program: is the tag present
    /// as metadata or still in the frame, and set M[0] to the shift.
    vlan_live: ?u16,
    @"and": [2]*const Node,
    @"or": [2]*const Node,
    not: *const Node,
    t: Test,
};

/// Compile `expr` into a classic-BPF program. Caller frees the slice.
pub fn compile(gpa: std.mem.Allocator, expr: []const u8) CompileError![]BpfInsn {
    return compileOpts(gpa, expr, .{});
}

pub const Options = struct {
    /// `vlan` / `vlan N` for a LIVE AF_PACKET socket: the kernel strips the
    /// 802.1Q tag before the filter runs, so libpcap (live) also reads the
    /// ancillary `SKF_AD_VLAN_TAG_PRESENT` / `SKF_AD_VLAN_TAG` words. Off (the
    /// default) is the offline form, an in-packet tag at offset 12, which is
    /// what `tcpdump -r` and `run` over a savefile mean. A program with the
    /// ancillary loads works in the kernel only: `run` drops those loads (see
    /// `usesAncillary`).
    vlan_ancillary: bool = false,
    /// The link layer the frames carry: `.ethernet` (AF_PACKET `SOCK_RAW` on an
    /// Ethernet device, what `Socket` delivers), `.linux_sll` (the 16-byte
    /// cooked header of a `tcpdump -i any` savefile, DLT_LINUX_SLL) or `.raw`
    /// (no link header, DLT_RAW: a tun device or an IP savefile). MAC, `vlan`,
    /// multicast and `ether[..]` primitives are Ethernet-only
    /// (`UnsupportedExpression`, as libpcap refuses them); on `.raw` the
    /// EtherType tests become the IP version nibble and `arp`/`rarp` are
    /// refused.
    link: Link = .ethernet,
    /// Byte order of a `.bsd_null` savefile's family word: the order of the host
    /// that CAPTURED it (libpcap decides by the file, not by the machine that
    /// compiles). Default: this host's. Set it from the savefile when it may come
    /// from the other kind of host: `pcap.Reader.byteOrder()` or `pcapng.Reader.order`
    /// is the file's order.
    /// Ignored by every other link (LOOP is always network order).
    null_byte_order: std.builtin.Endian = @import("builtin").cpu.arch.endian(),
};

/// Link layers `Options.link` compiles for (the libpcap DLT in brackets, also
/// `Link.dlt`): `ethernet` [EN10MB 1], `linux_sll` [LINUX_SLL 113, `-i any`
/// in libpcap's default], `linux_sll2` [LINUX_SLL2 276, what tcpdump 4.99 picks
/// for `-i any`], `raw` [RAW 101], `bsd_null` [NULL 0: a 4-byte address-family
/// word in the byte order of the capturing host] and `bsd_loop` [LOOP 108: the
/// same word in network order].
pub const Link = enum {
    ethernet,
    linux_sll,
    raw,
    linux_sll2,
    bsd_null,
    bsd_loop,

    /// The `pcap` savefile link-type number (`pcap.Header.linktype`).
    pub fn dlt(l: Link) u32 {
        return switch (l) {
            .ethernet => 1,
            .linux_sll => 113,
            .raw => 101,
            .linux_sll2 => 276,
            .bsd_null => 0,
            .bsd_loop => 108,
        };
    }

    /// The link a savefile's link-type number names, or null for one this
    /// compiler has no layout for.
    pub fn fromDlt(n: u32) ?Link {
        for (std.enums.values(Link)) |l| if (l.dlt() == n) return l;
        return null;
    }

    /// Bytes before the network header: the offset every Ethernet-relative
    /// network-layer offset (14 + n) is moved by is `header_len - 14`.
    fn headerLen(l: Link) u32 {
        return switch (l) {
            .ethernet => 14,
            .linux_sll => 16,
            .raw => 0,
            .linux_sll2 => 20,
            .bsd_null, .bsd_loop => 4,
        };
    }
};

/// The address-family word of a NULL/LOOP header as `ld [0]` reads it.
fn familyWord(link: Link, order: std.builtin.Endian, af: u32) u32 {
    // NULL stores the word in the capturing host's byte order (the savefile's, `Options.null_byte_order`); `ld` reads big endian.
    return if (link == .bsd_null and order == .little) @byteSwap(af) else af;
}

/// AF_INET (the same everywhere) and the AF_INET6 numbers a BSD-family savefile
/// holds: NetBSD/OpenBSD/BSD-OS 24, FreeBSD 28, macOS 30. libpcap compiles
/// `ip6` for a savefile as the OR of the three.
const af_inet: u32 = 2;
const af_inet6 = [_]u32{ 24, 28, 30 };

/// A compile's working memory: a typical filter fits here and touches no allocator
/// but for its result. On 0.17 `ArenaAllocator` is lock-free, measured 40 % of a
/// compile's user cycles, and an arena per call is the shape that grows
/// `std.heap.smp_allocator` without bound (2 M compiles, 3.6 GB, nothing leaked).
const scratch_bytes = 8192;

/// Bump inside the buffer, the arena past it. Nothing is freed one by one.
const Scratch = struct {
    fba: std.heap.FixedBufferAllocator,
    next: std.mem.Allocator,

    fn allocator(s: *Scratch) std.mem.Allocator {
        return .{ .ptr = s, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
        const s: *Scratch = @ptrCast(@alignCast(ctx));
        return s.fba.allocator().rawAlloc(len, al, ra) orelse s.next.rawAlloc(len, al, ra);
    }
    fn resize(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) bool {
        const s: *Scratch = @ptrCast(@alignCast(ctx));
        return if (s.fba.ownsSlice(m)) s.fba.allocator().rawResize(m, al, n, ra) else s.next.rawResize(m, al, n, ra);
    }
    fn remap(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, n: usize, ra: usize) ?[*]u8 {
        const s: *Scratch = @ptrCast(@alignCast(ctx));
        return if (s.fba.ownsSlice(m)) s.fba.allocator().rawRemap(m, al, n, ra) else s.next.rawRemap(m, al, n, ra);
    }
    fn free(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, ra: usize) void {
        const s: *Scratch = @ptrCast(@alignCast(ctx));
        if (!s.fba.ownsSlice(m)) s.next.rawFree(m, al, ra);
    }
};

/// `compile` with options (see `Options`).
pub fn compileOpts(gpa: std.mem.Allocator, expr: []const u8, opts: Options) CompileError![]BpfInsn {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var scratch_buf: [scratch_bytes]u8 = undefined;
    var scratch: Scratch = .{ .fba = .init(&scratch_buf), .next = arena.allocator() };
    const scratch_a = scratch.allocator();
    var p: Parser = .{ .a = scratch_a, .lex = .{ .src = expr }, .opts = opts, .shift = @as(i32, @intCast(opts.link.headerLen())) - 14 };
    var ast = try p.parseExpr();
    if (try p.lex.peek() != null) return error.Syntax;
    // The ancillary form tells the kernel's metadata from the packet's tag, and
    // libpcap then shifts the later primitives' offsets by a run-time amount
    // (`ldx M[1]`): alone it is the plain form above, combined with other
    // primitives the whole expression is parsed again in the run-time form.
    if (p.alone_only and p.leaves != p.alone_leaves) return error.UnsupportedExpression;
    var live = false;
    if (p.saw_vlan and opts.vlan_ancillary) {
        arena.deinit();
        arena = std.heap.ArenaAllocator.init(gpa);
        scratch.fba.reset();
        scratch.next = arena.allocator();
        p = .{ .a = scratch_a, .lex = .{ .src = expr }, .opts = opts, .shift = 0, .live = true };
        ast = try p.parseExpr();
        if (try p.lex.peek() != null) return error.Syntax;
        live = p.dyn_used;
    }

    var g: Gen = .{ .a = scratch_a, .store_shift = live };
    // Past the growth steps of a typical filter in one allocation each.
    try g.code.ensureTotalCapacity(g.a, 32);
    try g.labels.ensureTotalCapacity(g.a, 32);
    if (live) {
        // M[0] is the run-time shift (0 when the kernel stripped the first
        // tag, 4 when it is still in the frame), initialised on every path so
        // the kernel's check accepts the reads.
        try g.emit(.{ .insn = .{ .code = op.ld | op.w | op.imm, .jt = 0, .jf = 0, .k = 0 } });
        try g.emit(.{ .insn = .{ .code = op.st, .jt = 0, .jf = 0, .k = 0 } });
    }
    const t_label = try g.newLabel();
    const f_label = try g.newLabel();
    try g.gen(ast, t_label, f_label, 0);
    try g.place(t_label);
    try g.emit(.{ .insn = .{ .code = op.ret | op.k, .jt = 0, .jf = 0, .k = accept_len } });
    try g.place(f_label);
    try g.emit(.{ .insn = .{ .code = op.ret | op.k, .jt = 0, .jf = 0, .k = 0 } });
    return g.finish(gpa);
}

const Gen = struct {
    a: std.mem.Allocator,
    code: std.ArrayList(Pending) = .empty,
    labels: std.ArrayList(?usize) = .empty,
    /// The live `vlan` records its run-time shift in M[0] (something reads it).
    store_shift: bool = false,

    const Pending = struct { insn: BpfInsn, jt: ?usize = null, jf: ?usize = null };

    fn newLabel(g: *Gen) !usize {
        try g.labels.append(g.a, null);
        return g.labels.items.len - 1;
    }

    fn place(g: *Gen, l: usize) !void {
        g.labels.items[l] = g.code.items.len;
    }

    fn emit(g: *Gen, p: Pending) !void {
        if (g.code.items.len >= max_insns) return error.FilterTooComplex;
        try g.code.append(g.a, p);
    }

    /// Native recursion bound for `gen`. Left-deep chains no longer recurse
    /// (`genChain`); what is left is `not` and parentheses, which the parser caps
    /// at `Parser.max_depth`. Sized so that `compile` fits in a 64 KiB stack (test
    /// "compile: the deepest accepted inputs fit in a 64 KiB stack"). Measured on
    /// those inputs 2026-11-04: LLVM Debug needs over 40 KiB, ReleaseSafe over 16 KiB.
    const max_gen_depth = 200;

    fn ins(g: *Gen, code: u16, k: u32) !void {
        try g.emit(.{ .insn = .{ .code = code, .jt = 0, .jf = 0, .k = k } });
    }

    fn jump(g: *Gen, code: u16, k: u32, t: usize, f: usize) !void {
        try g.emit(.{ .insn = .{ .code = code, .jt = 0, .jf = 0, .k = k }, .jt = t, .jf = f });
    }

    /// The first `vlan [N]` of a live program, the shape libpcap emits: the
    /// kernel's PRESENT word; when set the tag is metadata and the shift stays
    /// 0, otherwise the shift becomes 4 and the frame must carry an 802.1Q,
    /// 802.1ad or QinQ EtherType at offset 12. `N` is then the id from
    /// `SKF_AD_VLAN_TAG` or from the frame.
    fn vlanLive(g: *Gen, id: ?u16, t: usize, f: usize) !void {
        const in_frame = try g.newLabel();
        const present = if (id != null) try g.newLabel() else t;
        const tpid_ok = if (id != null) try g.newLabel() else t;
        const n1 = try g.newLabel();
        const n2 = try g.newLabel();
        try g.ins(op.ld | op.b | op.abs, ancillary_base + 48);
        try g.jump(op.jmp | op.jeq | op.k, 1, present, in_frame);
        if (id) |v| {
            try g.place(present);
            try g.ins(op.ld | op.h | op.abs, ancillary_base + 44);
            try g.ins(op.alu | op.@"and" | op.k, 0xfff);
            try g.jump(op.jmp | op.jeq | op.k, v, t, f);
        }
        try g.place(in_frame);
        if (g.store_shift) {
            try g.ins(op.ld | op.w | op.imm, 4);
            try g.ins(op.st, 0);
        }
        try g.ins(op.ld | op.h | op.abs, 12);
        try g.jump(op.jmp | op.jeq | op.k, 0x8100, tpid_ok, n1);
        try g.place(n1);
        try g.jump(op.jmp | op.jeq | op.k, 0x88a8, tpid_ok, n2);
        try g.place(n2);
        try g.jump(op.jmp | op.jeq | op.k, 0x9100, tpid_ok, f);
        if (id) |v| {
            try g.place(tpid_ok);
            try g.ins(op.ld | op.h | op.abs, 14);
            try g.ins(op.alu | op.@"and" | op.k, 0xfff);
            try g.jump(op.jmp | op.jeq | op.k, v, t, f);
        }
    }

    /// A left-deep `and`/`or` chain (the parser builds `a and b and c ...` that way, with no
    /// depth of its own) walked WITHOUT native recursion down its left spine: the labels
    /// are worked out from the outside in, the code is emitted from the inside out, as
    /// the recursive form did. Native recursion is left to `not` and parentheses, which
    /// the parser bounds (`Parser.max_depth`).
    fn genChain(g: *Gen, n: *const Node, t: usize, f: usize, depth: usize) CompileError!void {
        const Link2 = struct { node: *const Node, mid: usize, t: usize, f: usize };
        // Length first: a short chain stays on the stack (allocation is the largest
        // single cost of a compile, measured), a long one takes one allocation, not a
        // growing list. Stack use is bounded by `Parser.max_depth` nestings of this.
        var len: usize = 0;
        var walk = n;
        while (true) {
            const ab = switch (walk.*) {
                .@"and", .@"or" => |x| x,
                else => break,
            };
            len += 1;
            walk = ab[0];
        }
        var small: [8]Link2 = undefined;
        const spine: []Link2 = if (len <= small.len) small[0..len] else try g.a.alloc(Link2, len);
        var cur = n;
        var ct = t;
        var cf = f;
        for (spine) |*l| {
            const ab = switch (cur.*) {
                .@"and", .@"or" => |x| x,
                else => unreachable,
            };
            const mid = try g.newLabel();
            l.* = .{ .node = cur, .mid = mid, .t = ct, .f = cf };
            if (cur.* == .@"and") ct = mid else cf = mid;
            cur = ab[0];
        }
        try g.gen(cur, ct, cf, depth + 1);
        var i = spine.len;
        while (i > 0) {
            i -= 1;
            const l = spine[i];
            try g.place(l.mid);
            const right = switch (l.node.*) {
                .@"and", .@"or" => |x| x[1],
                else => unreachable,
            };
            try g.gen(right, l.t, l.f, depth + 1);
        }
    }

    fn gen(g: *Gen, n: *const Node, t: usize, f: usize, depth: usize) CompileError!void {
        if (depth > max_gen_depth) return error.FilterTooComplex;
        switch (n.*) {
            .vlan_live => |id| try g.vlanLive(id, t, f),
            .@"and", .@"or" => try g.genChain(n, t, f, depth),
            .not => |inner| try g.gen(inner, f, t, depth + 1),
            .t => |c| {
                if (c.len) {
                    try g.emit(.{ .insn = .{ .code = op.ld | op.w | op.len, .jt = 0, .jf = 0, .k = 0 } });
                } else if (c.dyn) {
                    // libpcap's `ldx M[0]; ld [x + off]`; an indirect test adds the
                    // IPv4 header length to the shift first.
                    try g.emit(.{ .insn = .{ .code = op.ldx | op.w | op.mem, .jt = 0, .jf = 0, .k = 0 } });
                    if (c.ind) {
                        try g.emit(.{ .insn = .{ .code = op.ld | op.b | op.ind, .jt = 0, .jf = 0, .k = c.msh } });
                        try g.emit(.{ .insn = .{ .code = op.alu | op.@"and" | op.k, .jt = 0, .jf = 0, .k = 0xf } });
                        try g.emit(.{ .insn = .{ .code = op.alu | op.lsh | op.k, .jt = 0, .jf = 0, .k = 2 } });
                        try g.emit(.{ .insn = .{ .code = op.alu | op.add | op.x, .jt = 0, .jf = 0, .k = 0 } });
                        try g.emit(.{ .insn = .{ .code = op.misc | op.tax, .jt = 0, .jf = 0, .k = 0 } });
                    }
                    try g.emit(.{ .insn = .{ .code = op.ld | @backingInt(c.size) | op.ind, .jt = 0, .jf = 0, .k = c.off } });
                } else {
                    if (c.ind) try g.emit(.{ .insn = .{ .code = op.ldx | op.b | op.msh, .jt = 0, .jf = 0, .k = c.msh } });
                    try g.emit(.{ .insn = .{
                        .code = op.ld | @backingInt(c.size) | (if (c.ind) op.ind else op.abs),
                        .jt = 0,
                        .jf = 0,
                        .k = c.off,
                    } });
                }
                if (c.mask) |m| try g.emit(.{ .insn = .{ .code = op.alu | op.@"and" | op.k, .jt = 0, .jf = 0, .k = m } });
                try g.emit(.{
                    .insn = .{ .code = op.jmp | (switch (c.kind) {
                        .eq => op.jeq,
                        .set => op.jset,
                        .ge => op.jge,
                        .gt => op.jgt,
                    }) | op.k, .jt = 0, .jf = 0, .k = c.k },
                    .jt = t,
                    .jf = f,
                });
            },
        }
    }

    /// Lay the program out, widening every conditional jump whose target is
    /// more than 255 instructions away: the long side goes through a `ja`
    /// (32-bit offset) placed right after the conditional, as libpcap does.
    /// `[cond jt=0 jf=1][ja T][ja F]` when both sides are long. Widening one
    /// jump moves others, so layout repeats until no new jump needs it (flags
    /// only ever turn on, so it ends).
    fn finish(g: *Gen, gpa: std.mem.Allocator) CompileError![]BpfInsn {
        const n = g.code.items.len;
        const long_t = try g.a.alloc(bool, n);
        const long_f = try g.a.alloc(bool, n);
        @memset(long_t, false);
        @memset(long_f, false);
        const pos = try g.a.alloc(usize, n + 1);
        while (true) {
            var at: usize = 0;
            for (0..n) |i| {
                pos[i] = at;
                at += 1 + @as(usize, @intFromBool(long_t[i])) + @intFromBool(long_f[i]);
            }
            pos[n] = at;
            var changed = false;
            for (g.code.items, 0..) |p, i| {
                if (p.jt) |l| if (!long_t[i] and pos[g.labels.items[l].?] - (pos[i] + 1) > 255) {
                    long_t[i] = true;
                    changed = true;
                };
                if (p.jf) |l| if (!long_f[i] and pos[g.labels.items[l].?] - (pos[i] + 1) > 255) {
                    long_f[i] = true;
                    changed = true;
                };
            }
            if (!changed) break;
        }
        if (pos[n] > max_insns) return error.FilterTooComplex;
        const out = try gpa.alloc(BpfInsn, pos[n]);
        errdefer gpa.free(out);
        for (g.code.items, 0..) |p, i| {
            const at = pos[i];
            out[at] = p.insn;
            var stub = at + 1;
            if (p.jt) |l| {
                const target = pos[g.labels.items[l].?];
                if (long_t[i]) {
                    out[at].jt = 0;
                    out[stub] = .{ .code = op.jmp | op.ja, .jt = 0, .jf = 0, .k = @intCast(target - (stub + 1)) };
                    stub += 1;
                } else out[at].jt = @intCast(target - (at + 1));
            }
            if (p.jf) |l| {
                const target = pos[g.labels.items[l].?];
                if (long_f[i]) {
                    out[at].jf = if (long_t[i]) 1 else 0;
                    out[stub] = .{ .code = op.jmp | op.ja, .jt = 0, .jf = 0, .k = @intCast(target - (stub + 1)) };
                } else out[at].jf = @intCast(target - (at + 1));
            }
        }
        return out;
    }
};

const Lexer = struct {
    src: []const u8,
    pos: usize = 0,
    peeked: ?[]const u8 = null,
    /// Tokens pushed back (a stack: the last one is read first), for the
    /// `host a or b` shorthand that repeats the previous qualifiers.
    pending: [8][]const u8 = undefined,
    n_pending: usize = 0,
    /// Tokens read since the last reset, so a primitive's qualifiers can be
    /// remembered.
    log: [8][]const u8 = undefined,
    n_log: usize = 0,

    fn peek(l: *Lexer) CompileError!?[]const u8 {
        if (l.peeked == null) {
            if (l.n_pending > 0) {
                l.n_pending -= 1;
                l.peeked = l.pending[l.n_pending];
            } else l.peeked = l.scan();
        }
        return l.peeked;
    }

    fn next(l: *Lexer) CompileError!?[]const u8 {
        const t = try l.peek();
        l.peeked = null;
        if (t) |tok| if (l.n_log < l.log.len) {
            l.log[l.n_log] = tok;
            l.n_log += 1;
        };
        return t;
    }

    fn push(l: *Lexer, tok: []const u8) void {
        if (l.n_pending < l.pending.len) {
            l.pending[l.n_pending] = tok;
            l.n_pending += 1;
        }
    }

    fn scan(l: *Lexer) ?[]const u8 {
        while (l.pos < l.src.len and std.ascii.isWhitespace(l.src[l.pos])) l.pos += 1;
        if (l.pos == l.src.len) return null;
        const start = l.pos;
        const c = l.src[l.pos];
        if (c == '(' or c == ')') {
            l.pos += 1;
            return l.src[start..l.pos];
        }
        if ((c == '&' or c == '|') and l.pos + 1 < l.src.len and l.src[l.pos + 1] == c) {
            l.pos += 2;
            return l.src[start..l.pos];
        }
        // Comparison operators: `=` `==` `!=` `<` `<=` `>` `>=`.
        if (c == '=' or c == '<' or c == '>' or c == '!') {
            l.pos += 1;
            if (l.pos < l.src.len and l.src[l.pos] == '=') l.pos += 1;
            return l.src[start..l.pos];
        }
        while (l.pos < l.src.len) : (l.pos += 1) {
            const d = l.src[l.pos];
            if (std.ascii.isWhitespace(d) or d == '(' or d == ')' or d == '!' or d == '&' or d == '|' or d == '=' or d == '<' or d == '>') break;
        }
        if (l.pos == start) {
            // A lone '&' or '|' (the mask operator of an offset expression).
            l.pos += 1;
            return l.src[start..l.pos];
        }
        // `ip[ 6 : 2 ]`: a bracket opened without its close takes spaces up to the `]`.
        const word = l.src[start..l.pos];
        if (std.mem.findScalar(u8, word, '[') != null and std.mem.findScalar(u8, word, ']') == null) {
            if (std.mem.findScalarPos(u8, l.src, l.pos, ']')) |close| l.pos = close + 1;
        }
        return l.src[start..l.pos];
    }
};

/// A bare value that continues the previous primitive: a number, a dotted
/// address or an IPv6/MAC literal (libpcap: `host a or b`, `port 80 or 443`).
fn looksLikeValue(tok: []const u8) bool {
    return tok.len > 0 and (std.ascii.isDigit(tok[0]) or std.mem.findScalar(u8, tok, ':') != null);
}

/// libpcap's integer syntax (`strtol` base 0): decimal, `0x` hex, leading-0
/// octal; no sign, no `_` (Zig's own `parseInt` base 0 accepts both).
fn parseNum(comptime T: type, w: []const u8) ?T {
    if (w.len == 0) return null;
    for (w) |c| if (!std.ascii.isAlphanumeric(c)) return null;
    if (w.len > 1 and w[0] == '0') {
        if (w[1] == 'x' or w[1] == 'X') return if (w.len > 2) std.fmt.parseInt(T, w[2..], 16) catch null else null;
        return std.fmt.parseInt(T, w[1..], 8) catch null;
    }
    return std.fmt.parseInt(T, w, 10) catch null;
}

const NamedValue = struct { []const u8, u32 };

/// `SKF_AD_OFF`: a load at this offset plus an index is an ancillary load
/// (packet metadata) in the kernel, not a byte of the frame.
pub const ancillary_base: u32 = 0xfffff000;

fn etherProtoName(w: []const u8) ?u16 {
    const table = [_]NamedValue{ .{ "ip", 0x0800 }, .{ "ip6", 0x86dd }, .{ "arp", 0x0806 }, .{ "rarp", 0x8035 }, .{ "lldp", 0x88cc } };
    return if (named(&table, w)) |v| @intCast(v) else null;
}

const tcp_flag_names = [_]NamedValue{
    .{ "tcp-fin", 0x01 }, .{ "tcp-syn", 0x02 }, .{ "tcp-rst", 0x04 }, .{ "tcp-push", 0x08 },
    .{ "tcp-ack", 0x10 }, .{ "tcp-urg", 0x20 }, .{ "tcp-ece", 0x40 }, .{ "tcp-cwr", 0x80 },
};

const icmp_type_names = [_]NamedValue{
    .{ "icmp-echoreply", 0 },  .{ "icmp-unreach", 3 },      .{ "icmp-sourcequench", 4 },   .{ "icmp-redirect", 5 },
    .{ "icmp-echo", 8 },       .{ "icmp-routeradvert", 9 }, .{ "icmp-routersolicit", 10 }, .{ "icmp-timxceed", 11 },
    .{ "icmp-paramprob", 12 }, .{ "icmp-tstamp", 13 },      .{ "icmp-tstampreply", 14 },   .{ "icmp-ireq", 15 },
    .{ "icmp-ireqreply", 16 }, .{ "icmp-maskreq", 17 },     .{ "icmp-maskreply", 18 },
};

const proto_names = [_]NamedValue{
    .{ "icmp", 1 },   .{ "igmp", 2 },  .{ "tcp", 6 },    .{ "udp", 17 },   .{ "gre", 47 },  .{ "esp", 50 }, .{ "ah", 51 },
    .{ "icmp6", 58 }, .{ "pim", 103 }, .{ "vrrp", 112 }, .{ "sctp", 132 }, .{ "ospf", 89 },
};

fn named(table: []const NamedValue, w: []const u8) ?u32 {
    for (table) |e| if (std.mem.eql(u8, e[0], w)) return e[1];
    return null;
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const Parser = struct {
    a: std.mem.Allocator,
    lex: Lexer,
    depth: usize = 0,
    /// Comparisons built so far. Each one becomes at least one instruction of
    /// the program, so more than `max_insns` of them can never compile; the
    /// bound stops `a and a and a ...` from growing the tree without limit.
    /// See sweep RS1.
    leaves: usize = 0,
    opts: Options = .{},
    /// A `vlan` primitive was seen, and how many leaves it made.
    saw_vlan: bool = false,
    /// Added to every link-relative offset: 4 per `vlan` seen so far (libpcap
    /// shifts the primitives that FOLLOW it), 2 for SLL, -14 for raw IP.
    shift: i32 = 0,
    /// A non-contiguous `net A mask M` mask, for the one primitive being built.
    mask_override: ?u32 = null,
    vlan_leaves: usize = 0,
    /// Run-time form of the ancillary `vlan` (see `compileOpts`): the first
    /// `vlan` is a `.vlan_live` node and the primitives after it load through
    /// the shift in M[0].
    live: bool = false,
    live_x: bool = false,
    /// `mpls` / `pppoes` were seen and how many leaves they made (alone only).
    alone_only: bool = false,
    alone_leaves: usize = 0,
    /// Some primitive loads through the run-time shift (so M[0] is needed).
    dyn_used: bool = false,
    /// The qualifier tokens of the last `host`/`net`/`port`/`portrange`
    /// primitive: `tcp dst port 80 or 443` repeats `tcp dst port`.
    last: [6][]const u8 = undefined,
    n_last: usize = 0,

    /// Parenthesis/`not` nesting bound: recursion is per token, so a hostile
    /// expression cannot exhaust the stack.
    const max_depth = 16;

    fn node(p: *Parser, n: Node) !*const Node {
        const ptr = try p.a.create(Node);
        ptr.* = n;
        return ptr;
    }

    fn both(p: *Parser, kind: enum { @"and", @"or" }, l: *const Node, r: *const Node) !*const Node {
        return p.node(if (kind == .@"and") .{ .@"and" = .{ l, r } } else .{ .@"or" = .{ l, r } });
    }

    fn t(p: *Parser, c0: Test) !*const Node {
        p.leaves += 1;
        if (p.leaves > max_insns) return error.FilterTooComplex;
        var c = c0;
        if (p.live_x and !c.fixed and !c.len and c.off < ancillary_base) {
            c.dyn = true;
            p.dyn_used = true;
        }
        if (!c.fixed and !c.len and c.off < ancillary_base) {
            c.off = std.math.cast(u32, @as(i64, c.off) + p.shift) orelse return error.UnsupportedExpression;
            if (c.ind) c.msh = std.math.cast(u32, @as(i64, c.msh) + p.shift) orelse return error.UnsupportedExpression;
        }
        return p.node(.{ .t = c });
    }

    fn ethernetOnly(p: *Parser) CompileError!void {
        if (p.opts.link != .ethernet) return error.UnsupportedExpression;
    }

    /// `and` and `or` have EQUAL precedence and associate left to right
    /// (pcap-filter(7): "Negation has the highest precedence. Alternation and
    /// concatenation have equal precedence and associate left to right"):
    /// `tcp or udp and port 53` is `(tcp or udp) and port 53`.
    fn parseExpr(p: *Parser) CompileError!*const Node {
        var left = try p.parseFactor();
        while (try p.lex.peek()) |tok| {
            const is_or = eql(tok, "or") or eql(tok, "||");
            if (!is_or and !eql(tok, "and") and !eql(tok, "&&")) break;
            _ = try p.lex.next();
            left = try p.both(if (is_or) .@"or" else .@"and", left, try p.parseFactor());
        }
        return left;
    }

    fn parseFactor(p: *Parser) CompileError!*const Node {
        const tok = (try p.lex.next()) orelse return error.Syntax;
        if (eql(tok, "not") or eql(tok, "!") or eql(tok, "(")) {
            p.depth += 1;
            defer p.depth -= 1;
            if (p.depth > max_depth) return error.FilterTooComplex;
            if (eql(tok, "(")) {
                const inner = try p.parseExpr();
                const close = (try p.lex.next()) orelse return error.Syntax;
                if (!eql(close, ")")) return error.Syntax;
                return inner;
            }
            return p.node(.{ .not = try p.parseFactor() });
        }
        if (p.n_last > 0 and looksLikeValue(tok)) {
            // `host a or b`: the value repeats the previous primitive's qualifiers.
            p.lex.push(tok);
            var i = p.n_last;
            while (i > 1) : (i -= 1) p.lex.push(p.last[i - 1]);
            return p.primitive(p.last[0]);
        }
        p.lex.n_log = 1;
        p.lex.log[0] = tok;
        const n = try p.primitive(tok);
        // Remember `... host|net|port|portrange VALUE` (the last two tokens read).
        const lg = p.lex.n_log;
        p.n_last = 0;
        if (lg >= 2 and lg - 1 <= p.last.len) {
            const kw = p.lex.log[lg - 2];
            if (eql(kw, "host") or eql(kw, "net") or eql(kw, "port") or eql(kw, "portrange")) {
                @memcpy(p.last[0 .. lg - 1], p.lex.log[0 .. lg - 1]);
                p.n_last = lg - 1;
            }
        }
        return n;
    }

    fn expectWord(p: *Parser) CompileError![]const u8 {
        return (try p.lex.next()) orelse error.Syntax;
    }

    fn primitive(p: *Parser, first: []const u8) CompileError!*const Node {
        if (std.mem.findScalar(u8, first, '[')) |_| return p.offsetExpr(first);
        if (eql(first, "ether")) {
            const what = try p.expectWord();
            if (eql(what, "proto")) {
                const w = try p.expectWord();
                const ty = if (w.len > 0 and w[0] == '\\') etherProtoName(w[1..]) orelse return error.Syntax else parseNum(u16, w) orelse return error.Syntax;
                return p.etherType(ty);
            }
            if (eql(what, "broadcast")) return p.etherAddr(.dst, @splat(0xff));
            if (eql(what, "multicast")) return p.multicast();
            const dir: Dir = if (eql(what, "src")) .src else if (eql(what, "dst")) .dst else if (eql(what, "host")) .either else return error.UnsupportedExpression;
            const mac = root.parseHwaddr(try p.expectWord()) orelse return error.Syntax;
            return p.etherAddr(dir, mac);
        }
        if (eql(first, "broadcast")) return p.etherAddr(.dst, @splat(0xff));
        if (eql(first, "multicast")) return p.multicast();
        if (eql(first, "less") or eql(first, "greater")) {
            // libpcap: `less N` is len <= N, `greater N` is len >= N.
            const n = try p.number(u32);
            if (eql(first, "less")) return p.node(.{ .not = try p.t(.{ .size = .w, .off = 0, .len = true, .kind = .gt, .k = n }) });
            return p.t(.{ .size = .w, .off = 0, .len = true, .kind = .ge, .k = n });
        }
        if (eql(first, "len")) return p.relation(.{ .size = .w, .off = 0, .len = true, .k = 0 }, null);
        if (eql(first, "arp") or eql(first, "rarp")) return p.arpOnly(if (eql(first, "arp")) 0x0806 else 0x8035);
        if (eql(first, "ip6")) {
            const nxt = (try p.lex.peek()) orelse return p.etherType(0x86dd);
            if (eql(nxt, "proto")) {
                _ = try p.lex.next();
                return p.ip6Proto(try p.protoNumber());
            }
            var dir: Dir = .either;
            if (eql(nxt, "src") or eql(nxt, "dst")) {
                _ = try p.lex.next();
                dir = if (eql(nxt, "src")) .src else .dst;
            } else if (eql(nxt, "multicast") or eql(nxt, "broadcast") or eql(nxt, "protochain")) {
                return error.UnsupportedExpression; // netmask / header-chain walk
            } else if (!eql(nxt, "host") and !eql(nxt, "net")) return p.etherType(0x86dd);
            return p.hostNet(dir, .ip6);
        }
        if (eql(first, "icmp")) return p.ipProto(1);
        if (eql(first, "icmp6")) return p.ip6Proto(58);
        if (eql(first, "proto")) {
            const n = try p.protoNumber();
            return p.both(.@"or", try p.ipProto(n), try p.ip6Proto(n));
        }
        if (eql(first, "vlan")) return p.vlan();
        if (eql(first, "inbound") or eql(first, "outbound")) {
            // The kernel's packet type (SKF_AD_PKTTYPE): 4 is PACKET_OUTGOING; live only.
            const out = try p.t(.{ .size = .h, .off = ancillary_base + 4, .fixed = true, .k = 4 });
            return if (eql(first, "outbound")) out else p.node(.{ .not = out });
        }
        if (eql(first, "ifindex")) {
            const n = try p.number(u32);
            return p.t(.{ .size = .w, .off = ancillary_base + 8, .fixed = true, .k = n }); // SKF_AD_IFINDEX
        }
        if (eql(first, "pppoed")) {
            try p.ethernetOnly();
            return p.etherType(0x8863); // PPPoE discovery
        }
        if (eql(first, "mpls") or eql(first, "pppoes")) {
            // Alone only: in libpcap everything written after them moves (the label
            // stack / the PPPoE header), which this compiler has no form for.
            try p.ethernetOnly();
            const mpls = eql(first, "mpls");
            const before = p.leaves;
            var id: ?u32 = null;
            if (try p.lex.peek()) |nxt| if (parseNum(u32, nxt) != null) {
                _ = try p.lex.next();
                id = parseNum(u32, nxt).?;
                if (id.? > (if (mpls) @as(u32, 0xfffff) else 0xffff)) return error.Syntax;
            };
            var n = try p.etherType(if (mpls) 0x8847 else 0x8864);
            if (id) |v| n = try p.both(.@"and", n, try p.t(.{ .size = .w, .off = 14, .fixed = true, .mask = if (mpls) 0xfffff000 else 0xffff, .k = if (mpls) v << 12 else v }));
            p.alone_only = true;
            p.alone_leaves += p.leaves - before;
            return n;
        }
        if (eql(first, "ifname") or eql(first, "rnr") or eql(first, "ruleset") or eql(first, "reason") or eql(first, "action") or eql(first, "srnr") or eql(first, "subrulenum")) return error.UnsupportedExpression; // OpenBSD pflog only (libpcap: "supported only on PF linktype")
        if (eql(first, "geneve")) return error.UnsupportedExpression; // see SPEC: a computed-offset option walk, not built
        if (eql(first, "ip")) {
            const nxt = (try p.lex.peek()) orelse return p.etherType(0x0800);
            if (eql(nxt, "proto")) {
                _ = try p.lex.next();
                return p.ipProto(try p.protoNumber());
            }
            var dir: Dir = .either;
            if (eql(nxt, "src") or eql(nxt, "dst")) {
                _ = try p.lex.next();
                dir = if (eql(nxt, "src")) .src else .dst;
            } else if (eql(nxt, "multicast") or eql(nxt, "broadcast") or eql(nxt, "protochain")) {
                return error.UnsupportedExpression; // netmask / header-chain walk
            } else if (!eql(nxt, "host") and !eql(nxt, "net")) return p.etherType(0x0800);
            return p.hostNet(dir, .ip4);
        }
        var proto: ?u8 = null;
        var tok = first;
        if (eql(tok, "tcp") or eql(tok, "udp") or eql(tok, "sctp")) {
            proto = if (eql(tok, "tcp")) 6 else if (eql(tok, "udp")) 17 else 132;
            const nxt = (try p.lex.peek()) orelse return p.transport(proto.?);
            if (!eql(nxt, "src") and !eql(nxt, "dst") and !eql(nxt, "port") and !eql(nxt, "portrange")) return p.transport(proto.?);
            tok = (try p.lex.next()).?;
        }
        var dir: Dir = .either;
        if (eql(tok, "src") or eql(tok, "dst")) {
            dir = if (eql(tok, "src")) .src else .dst;
            tok = try p.expectWord();
        }
        if (proto == null and (eql(tok, "host") or eql(tok, "net"))) {
            // Bare host/net: libpcap's "any address family" reading.
            // (The keyword is read again by `hostNet`: drop its first reading from the log.)
            if (p.lex.n_log > 0) p.lex.n_log -= 1;
            p.lex.peeked = tok;
            return p.hostNet(dir, .any);
        }
        if (eql(tok, "port") or eql(tok, "portrange")) {
            var lo: u16 = undefined;
            var hi: u16 = undefined;
            if (eql(tok, "port")) {
                lo = try p.number(u16);
                hi = lo;
            } else {
                const w = try p.expectWord();
                const dash = std.mem.findScalar(u8, w, '-') orelse return error.Syntax;
                lo = parseNum(u16, w[0..dash]) orelse return error.Syntax;
                hi = parseNum(u16, w[dash + 1 ..]) orelse return error.Syntax;
                if (lo > hi) std.mem.swap(u16, &lo, &hi); // libpcap swaps too
            }
            if (proto) |pr| return p.port(pr, dir, lo, hi);
            return p.both(.@"or", try p.port(6, dir, lo, hi), try p.both(.@"or", try p.port(17, dir, lo, hi), try p.port(132, dir, lo, hi)));
        }
        return error.UnsupportedExpression;
    }

    /// A protocol number or a name (`\tcp`; libpcap needs the backslash, a bare
    /// `tcp` after `proto` is a syntax error there too).
    fn protoNumber(p: *Parser) CompileError!u8 {
        const w = try p.expectWord();
        if (w.len > 1 and w[0] == '\\') {
            const v = named(&proto_names, w[1..]) orelse return error.Syntax;
            return @intCast(v);
        }
        return parseNum(u8, w) orelse error.Syntax;
    }

    /// `vlan` and `vlan N` as the WHOLE expression (see `compileOpts`).
    fn vlan(p: *Parser) CompileError!*const Node {
        try p.ethernetOnly();
        const before = p.leaves;
        var id: ?u16 = null;
        if (try p.lex.peek()) |nxt| if (parseNum(u16, nxt) != null) {
            _ = try p.lex.next();
            id = parseNum(u16, nxt).?;
            if (id.? > 0xfff) return error.Syntax;
        };
        if (p.live and !p.live_x) {
            // The first tag of a live program: kernel metadata or still in the frame
            // (run-time shift in M[0]); the primitives after it load through X.
            p.leaves += 1;
            if (p.leaves > max_insns) return error.FilterTooComplex;
            p.saw_vlan = true;
            p.live_x = true;
            return p.node(.{ .vlan_live = id });
        }
        // In the packet: an 802.1Q / 802.1ad / QinQ ethertype, then the id.
        const t8100 = try p.etherType(0x8100);
        const t88a8 = try p.etherType(0x88a8);
        const t9100 = try p.etherType(0x9100);
        var inpkt = try p.both(.@"or", t8100, try p.both(.@"or", t88a8, t9100));
        if (id) |v| inpkt = try p.both(.@"and", inpkt, try p.t(.{ .size = .h, .off = 14, .mask = 0xfff, .k = v }));
        p.saw_vlan = true;
        p.vlan_leaves += p.leaves - before;
        // libpcap shifts the primitives that follow by the tag's four bytes.
        p.shift += 4;
        return inpkt;
    }

    fn number(p: *Parser, comptime T: type) CompileError!T {
        const w = try p.expectWord();
        // libpcap's named constants are plain numbers wherever a number goes
        // (`port tcp-syn`, `icmp[0] = tcp-syn`).
        if (parseNum(T, w)) |v| return v;
        const nv = named(&tcp_flag_names, w) orelse named(&icmp_type_names, w) orelse return error.Syntax;
        return std.math.cast(T, nv) orelse error.Syntax;
    }

    const Dir = enum { src, dst, either };
    const Family = enum { ip4, ip6, any };

    /// `host ADDR` or `net ADDR/LEN` (the keyword is the next token). `.any`
    /// is libpcap's bare form: an IPv4 literal matches IP, ARP and RARP, an
    /// IPv6 one matches IPv6.
    fn hostNet(p: *Parser, dir: Dir, fam: Family) CompileError!*const Node {
        defer p.mask_override = null;
        const kind = try p.expectWord();
        const is_net = eql(kind, "net");
        if (!is_net and !eql(kind, "host")) return error.UnsupportedExpression;
        const w = try p.expectWord();
        var text = w;
        var plen: ?u8 = null;
        if (std.mem.findScalar(u8, w, '/')) |slash| {
            if (!is_net) return error.Syntax;
            text = w[0..slash];
            plen = std.fmt.parseInt(u8, w[slash + 1 ..], 10) catch return error.Syntax;
        }
        // Anything that is not numeric is a host or network NAME: resolving it
        // is not this module's job (the caller passes numbers).
        for (text) |c| if (!std.ascii.isHex(c) and c != ':' and c != '.') return error.UnsupportedExpression;
        if (std.mem.findScalar(u8, text, ':') != null) {
            if (fam == .ip4) return error.Syntax;
            if (is_net and plen == null) return error.Syntax;
            const addr6 = netaddr.parseIp6(text) orelse return error.Syntax;
            const pl6 = plen orelse 128;
            if (pl6 > 128) return error.Syntax;
            return p.ip6Addr(dir, addr6, pl6);
        }
        if (fam == .ip6) return error.Syntax;
        var addr: [4]u8 = undefined;
        var pl: u8 = 32;
        if (is_net and plen == null) {
            // `net 10` is 10.0.0.0/8, `net 10.1` /16, `net 10.1.2` /24
            // (libpcap takes the prefix from the octets given); a net may then
            // carry `mask M`.
            var octets: usize = 0;
            addr = @splat(0);
            var it = std.mem.splitScalar(u8, text, '.');
            while (it.next()) |part| : (octets += 1) {
                if (octets == 4 or part.len == 0 or part.len > 3) return error.Syntax;
                addr[octets] = std.fmt.parseInt(u8, part, 10) catch return error.Syntax;
            }
            // Four octets name one host (`net 10.0.0.0` is /32); fewer are a prefix.
            pl = if (octets == 4) 32 else @intCast(8 * octets);
            if (try p.lex.peek()) |nx| if (eql(nx, "mask")) {
                _ = try p.lex.next();
                if (octets == 1) return error.Syntax; // libpcap: `net 10 mask M` is a syntax error
                const m = parseIpv4(try p.expectWord()) orelse return error.Syntax;
                const mv = std.mem.readInt(u32, &m, .big);
                pl = @intCast(@popCount(mv));
                // libpcap takes any mask (`and #mask; jeq`), contiguous or not.
                if (maskOf(pl) != mv) p.mask_override = mv;
            };
        } else {
            addr = parseIpv4(text) orelse return error.Syntax;
            pl = plen orelse 32;
        }
        if (pl > 32) return error.Syntax;
        // libpcap refuses host bits outside the mask ("non-network bits set
        // in"); so does this.
        if (std.mem.readInt(u32, &addr, .big) & ~(p.mask_override orelse maskOf(pl)) != 0) return error.Syntax;
        if (fam == .ip4) return p.ipAddr(dir, addr, pl);
        if (p.opts.link == .raw or p.opts.link == .bsd_null or p.opts.link == .bsd_loop) return p.ipAddr(dir, addr, pl); // no ARP there
        const arp_or_rarp = try p.both(.@"or", try p.arpAddr(0x0806, dir, addr, pl), try p.arpAddr(0x8035, dir, addr, pl));
        return p.both(.@"or", try p.ipAddr(dir, addr, pl), arp_or_rarp);
    }

    /// `arp` / `rarp` alone, or `arp [src|dst] host A.B.C.D`.
    fn arpOnly(p: *Parser, ty: u16) CompileError!*const Node {
        const nxt = (try p.lex.peek()) orelse return p.etherType(ty);
        var dir: Dir = .either;
        if (eql(nxt, "src") or eql(nxt, "dst")) {
            _ = try p.lex.next();
            dir = if (eql(nxt, "src")) .src else .dst;
        } else if (!eql(nxt, "host")) return p.etherType(ty);
        const kind = try p.expectWord();
        if (!eql(kind, "host")) return error.UnsupportedExpression;
        const addr = parseIpv4(try p.expectWord()) orelse return error.Syntax;
        return p.arpAddr(ty, dir, addr, 32);
    }

    fn arpAddr(p: *Parser, ty: u16, dir: Dir, addr: [4]u8, plen: u8) CompileError!*const Node {
        if (dir == .either) return p.both(.@"or", try p.arpAddr(ty, .src, addr, plen), try p.arpAddr(ty, .dst, addr, plen));
        const m = p.mask_override orelse maskOf(plen);
        const cmp = try p.t(.{
            .size = .w,
            .off = if (dir == .src) 28 else 38, // sender / target protocol address
            .mask = if (m == 0xffffffff) null else m,
            .k = std.mem.readInt(u32, &addr, .big) & m,
        });
        return p.both(.@"and", try p.etherType(ty), cmp);
    }

    fn multicast(p: *Parser) CompileError!*const Node {
        try p.ethernetOnly();
        return p.t(.{ .size = .b, .off = 0, .kind = .set, .fixed = true, .k = 1 });
    }

    /// A number, a named constant (`tcp-syn`, `icmp-echo`) or a parenthesised
    /// `a | b | ...` of them.
    fn value(p: *Parser) CompileError!u32 {
        const w = try p.expectWord();
        if (!eql(w, "(")) return p.atom(w);
        var v = try p.atom(try p.expectWord());
        while (true) {
            const sep = try p.expectWord();
            if (eql(sep, ")")) return v;
            if (!eql(sep, "|")) return error.Syntax;
            v |= try p.atom(try p.expectWord());
        }
    }

    fn atom(p: *Parser, w: []const u8) CompileError!u32 {
        _ = p;
        return parseNum(u32, w) orelse named(&tcp_flag_names, w) orelse named(&icmp_type_names, w) orelse error.Syntax;
    }

    /// `[& MASK] RELOP NUM` after the load `base` (its `k` is filled in here).
    /// `<` and `<=` are the negations of `>=` and `>`.
    fn relation(p: *Parser, base: Test, cond: ?*const Node) CompileError!*const Node {
        var tst = base;
        var tok = try p.expectWord();
        if (eql(tok, "&")) {
            tst.mask = try p.value();
            tok = try p.expectWord();
        }
        var negate = false;
        if (eql(tok, "=") or eql(tok, "==")) {
            tst.kind = .eq;
        } else if (eql(tok, "!=")) {
            tst.kind = .eq;
            negate = true;
        } else if (eql(tok, ">")) {
            tst.kind = .gt;
        } else if (eql(tok, ">=")) {
            tst.kind = .ge;
        } else if (eql(tok, "<")) {
            tst.kind = .ge;
            negate = true;
        } else if (eql(tok, "<=")) {
            tst.kind = .gt;
            negate = true;
        } else return error.Syntax;
        tst.k = try p.value();
        var n = try p.t(tst);
        if (negate) n = try p.node(.{ .not = n });
        if (cond) |c| return p.both(.@"and", c, n);
        return n;
    }

    /// `proto[off]` / `proto[off:size]` (size 1, 2 or 4) compared to a number,
    /// as libpcap's `ip[6:2] & 0x1fff = 0`. The offset is a literal.
    fn offsetExpr(p: *Parser, tok: []const u8) CompileError!*const Node {
        const open = std.mem.findScalar(u8, tok, '[').?;
        if (tok[tok.len - 1] != ']') return error.Syntax;
        const name = tok[0..open];
        var ibuf: [64]u8 = undefined;
        var n_in: usize = 0;
        for (tok[open + 1 .. tok.len - 1]) |c| {
            if (std.ascii.isWhitespace(c)) continue;
            if (n_in == ibuf.len) return error.Syntax;
            ibuf[n_in] = c;
            n_in += 1;
        }
        const inner = ibuf[0..n_in];
        var off_text = inner;
        var size: Size = .b;
        if (std.mem.findScalar(u8, inner, ':')) |colon| {
            off_text = inner[0..colon];
            size = switch (std.fmt.parseInt(u8, inner[colon + 1 ..], 10) catch return error.Syntax) {
                1 => .b,
                2 => .h,
                4 => .w,
                else => return error.Syntax,
            };
        }
        const off: u32 = if (eql(off_text, "tcpflags") and eql(name, "tcp")) 13 else if (eql(off_text, "icmptype") and eql(name, "icmp")) 0 else if (eql(off_text, "icmpcode") and eql(name, "icmp")) 1 else parseNum(u32, off_text) orelse return error.Syntax;
        if (off > 65535) return error.Syntax;
        if (eql(name, "ether")) {
            // libpcap reads `ether[N]` as link-header byte N on NULL, LOOP and
            // cooked v2 as well (`tcpdump -y NULL -d 'ether[0] = 1'` is `ldb [0]`).
            if (p.opts.link != .bsd_null and p.opts.link != .bsd_loop and p.opts.link != .linux_sll2) try p.ethernetOnly();
            return p.relation(.{ .size = size, .off = off, .fixed = true, .k = 0 }, null);
        }
        if (eql(name, "ip") or eql(name, "ip6") or eql(name, "arp") or eql(name, "rarp")) {
            const ty: u16 = if (eql(name, "ip")) 0x0800 else if (eql(name, "ip6")) 0x86dd else if (eql(name, "arp")) 0x0806 else 0x8035;
            return p.relation(.{ .size = size, .off = 14 + off, .k = 0 }, try p.etherType(ty));
        }
        const pr: u8 = if (eql(name, "tcp")) 6 else if (eql(name, "udp")) 17 else if (eql(name, "icmp")) 1 else if (eql(name, "sctp")) 132 else return error.UnsupportedExpression;
        // Transport offsets are IPv4 only, as libpcap's: protocol, first
        // fragment, then relative to the IP header length.
        const not_frag = try p.node(.{ .not = try p.t(.{ .size = .h, .off = 20, .kind = .set, .k = 0x1fff }) });
        const cond = try p.both(.@"and", try p.ipProto(pr), not_frag);
        return p.relation(.{ .size = size, .off = 14 + off, .ind = true, .k = 0 }, cond);
    }

    fn etherType(p: *Parser, ty: u16) !*const Node {
        switch (p.opts.link) {
            .raw => {
                // No EtherType: the IP version nibble. Anything else never matches
                // in libpcap's eyes ("expression rejects all packets").
                return switch (ty) {
                    0x0800 => p.t(.{ .size = .b, .off = 0, .mask = 0xf0, .fixed = true, .k = 0x40 }),
                    0x86dd => p.t(.{ .size = .b, .off = 0, .mask = 0xf0, .fixed = true, .k = 0x60 }),
                    else => error.UnsupportedExpression,
                };
            },
            .bsd_null, .bsd_loop => {
                // The address-family word; libpcap compares IP and IPv6 only. In a
                // savefile AF_INET6 is the capturing OS's number: 24, 28 or 30
                // (gencode.c, `rfile != NULL`); Linux's own 10 is not among them.
                return switch (ty) {
                    0x0800 => p.t(.{ .size = .w, .off = 0, .fixed = true, .k = familyWord(p.opts.link, p.opts.null_byte_order, af_inet) }),
                    0x86dd => blk: {
                        var acc = try p.t(.{ .size = .w, .off = 0, .fixed = true, .k = familyWord(p.opts.link, p.opts.null_byte_order, af_inet6[0]) });
                        for (af_inet6[1..]) |af| acc = try p.both(.@"or", acc, try p.t(.{ .size = .w, .off = 0, .fixed = true, .k = familyWord(p.opts.link, p.opts.null_byte_order, af) }));
                        break :blk acc;
                    },
                    else => error.UnsupportedExpression,
                };
            },
            // The protocol is the first field of the cooked-v2 header.
            .linux_sll2 => return p.t(.{ .size = .h, .off = 0, .fixed = true, .k = ty }),
            .ethernet, .linux_sll => return p.t(.{ .size = .h, .off = 12, .k = ty }),
        }
    }

    fn etherAddr(p: *Parser, dir: Dir, mac: [6]u8) CompileError!*const Node {
        try p.ethernetOnly();
        if (dir == .either) return p.both(.@"or", try p.etherAddr(.src, mac), try p.etherAddr(.dst, mac));
        const base: u32 = if (dir == .src) 6 else 0;
        return p.both(
            .@"and",
            try p.t(.{ .size = .w, .off = base + 2, .fixed = true, .k = std.mem.readInt(u32, mac[2..6], .big) }),
            try p.t(.{ .size = .h, .off = base, .fixed = true, .k = std.mem.readInt(u16, mac[0..2], .big) }),
        );
    }

    fn ipProto(p: *Parser, pr: u8) CompileError!*const Node {
        return p.both(.@"and", try p.etherType(0x0800), try p.t(.{ .size = .b, .off = 23, .k = pr }));
    }

    fn ip6Proto(p: *Parser, pr: u8) CompileError!*const Node {
        // Fixed header next-header, or a fragment header (44) carrying it.
        const direct = try p.t(.{ .size = .b, .off = 20, .k = pr });
        const frag = try p.both(.@"and", try p.t(.{ .size = .b, .off = 20, .k = 44 }), try p.t(.{ .size = .b, .off = 54, .k = pr }));
        return p.both(.@"and", try p.etherType(0x86dd), try p.both(.@"or", direct, frag));
    }

    fn transport(p: *Parser, pr: u8) CompileError!*const Node {
        return p.both(.@"or", try p.ipProto(pr), try p.ip6Proto(pr));
    }

    fn port(p: *Parser, pr: u8, dir: Dir, lo: u16, hi: u16) CompileError!*const Node {
        // IPv6: ports straight after the 40-byte header, next header = pr.
        const v6 = try p.both(.@"and", try p.both(.@"and", try p.etherType(0x86dd), try p.t(.{ .size = .b, .off = 20, .k = pr })), try p.ports(dir, lo, hi, false));
        // IPv4: protocol, first fragment only, ports after IHL.
        const not_frag = try p.node(.{ .not = try p.t(.{ .size = .h, .off = 20, .kind = .set, .k = 0x1fff }) });
        const v4 = try p.both(.@"and", try p.both(.@"and", try p.ipProto(pr), not_frag), try p.ports(dir, lo, hi, true));
        return p.both(.@"or", v6, v4);
    }

    /// One 16-bit port compared to `lo..hi` (equality when they match).
    fn portIn(p: *Parser, off: u32, ind: bool, lo: u16, hi: u16) CompileError!*const Node {
        if (lo == hi) return p.t(.{ .size = .h, .off = off, .ind = ind, .k = lo });
        const ge = try p.t(.{ .size = .h, .off = off, .ind = ind, .kind = .ge, .k = lo });
        const gt = try p.t(.{ .size = .h, .off = off, .ind = ind, .kind = .gt, .k = hi });
        return p.both(.@"and", ge, try p.node(.{ .not = gt }));
    }

    fn ports(p: *Parser, dir: Dir, lo: u16, hi: u16, v4: bool) CompileError!*const Node {
        // v4: [x + 14] / [x + 16]; v6: [54] / [56].
        const base: u32 = if (v4) 14 else 54;
        return switch (dir) {
            .src => p.portIn(base, v4, lo, hi),
            .dst => p.portIn(base + 2, v4, lo, hi),
            .either => p.both(.@"or", try p.portIn(base, v4, lo, hi), try p.portIn(base + 2, v4, lo, hi)),
        };
    }

    /// An IPv6 `host`/`net`: the EtherType, then one 32-bit compare per word
    /// the prefix touches (a partial word is masked), as libpcap emits.
    fn ip6Addr(p: *Parser, dir: Dir, addr: [16]u8, plen: u8) CompileError!*const Node {
        if (dir == .either) return p.both(.@"or", try p.ip6Addr(.src, addr, plen), try p.ip6Addr(.dst, addr, plen));
        const base: u32 = if (dir == .src) 22 else 38;
        var acc = try p.etherType(0x86dd);
        var i: u32 = 0;
        while (i < 4) : (i += 1) {
            const done = i * 32;
            if (plen <= done) break;
            const bits: u8 = @intCast(@min(32, plen - done));
            const m = maskOf(bits);
            const word = std.mem.readInt(u32, addr[i * 4 ..][0..4], .big);
            // Host bits beyond the prefix: libpcap refuses ("non-network bits set").
            if (word & ~m != 0) return error.Syntax;
            const cmp = try p.t(.{ .size = .w, .off = base + i * 4, .mask = if (bits == 32) null else m, .k = word });
            acc = try p.both(.@"and", acc, cmp);
        }
        return acc;
    }

    fn ipAddr(p: *Parser, dir: Dir, addr: [4]u8, plen: u8) CompileError!*const Node {
        if (dir == .either) return p.both(.@"or", try p.ipAddr(.src, addr, plen), try p.ipAddr(.dst, addr, plen));
        const m = p.mask_override orelse maskOf(plen);
        const cmp = try p.t(.{
            .size = .w,
            .off = if (dir == .src) 26 else 30,
            .mask = if (m == 0xffffffff) null else m,
            .k = std.mem.readInt(u32, &addr, .big),
        });
        return p.both(.@"and", try p.etherType(0x0800), cmp);
    }
};

fn maskOf(plen: u8) u32 {
    return if (plen == 0) 0 else ~@as(u32, 0) << @intCast(32 - @as(u32, plen));
}

fn parseIpv4(s: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        // An empty part fails parseInt; more than 3 digits is not dotted-quad.
        if (i == 4 or part.len > 3) return null;
        out[i] = std.fmt.parseInt(u8, part, 10) catch return null;
    }
    if (i != 4) return null;
    return out;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;
const pcap = @import("pcap.zig");

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(100000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

// A 20-frame corpus (a pcap file, generated for this test, frame i stamped
// at second 1000+i): ARP; IPv4 TCP both directions; UDP with and without IP
// options; a non-first and a first fragment; ICMP; SCTP; IPv6 TCP, UDP, a
// fragment header carrying TCP, ICMPv6; a 13-byte runt; an IPv4 frame cut
// right after its IP header; a 10.200/16 source; an 802.1Q-tagged frame; an
// unknown EtherType; TCP with a 60-byte IP header; an IPv6 header whose
// next-header is 1 (ICMP's IPv4 number — `icmp` must not match it). The oracle is libpcap
// 1.10.6 itself: `tcpdump -r` decided every verdict below.
const corpus_pcap = hex(
    "d4c3b2a10200040000000000000000000000040001000000e8030000000000002a0000002a000000ffffffffffff00112233" ++
        "4455080600010800060400010011223344550a0000010000000000000a000002e9030000000000002c0000002c0000000200" ++
        "0000000900112233445508004500001e00010000400600000a000001c000020504d20050000000007878ea03000000000000" ++
        "2c0000002c00000000112233445502000000000908004500001e0001000040060000c00002050a000001005004d200000000" ++
        "7878eb030000000000002c0000002c00000002000000000902000000000908004500001e00010000401100000a0102030a00" ++
        "0001003514e9000000007878ec03000000000000300000003000000002000000000902000000000908004600002200010000" ++
        "401100000a0102030a0000090101010113880035000000007878ed030000000000002c0000002c0000000200000000090200" ++
        "0000000908004500001e00010010401100000a0102030a00000900350035000000007878ee030000000000002c0000002c00" ++
        "000002000000000902000000000908004500001e00012000401100000a0102030a00000900350035000000007878ef030000" ++
        "000000002a0000002a00000002000000000902000000000908004500001c00010000400100000a0000010808080808000000" ++
        "00000000f0030000000000002c0000002c00000002000000000902000000000908004500001e00010000408400000a000007" ++
        "0a0000080035270f000000007878f103000000000000400000004000000002000000000902000000000986dd60000000000a" ++
        "064020010db800000000000000000000000120010db800000000000000000000000200169c40000000007878f20300000000" ++
        "0000400000004000000002000000000902000000000986dd60000000000a114020010db80000000000000000000000012001" ++
        "0db80000000000000000000000029c400035000000007878f303000000000000480000004800000002000000000902000000" ++
        "000986dd6000000000122c4020010db800000000000000000000000120010db8000000000000000000000002060000000000" ++
        "000104570050000000007878f4030000000000003e0000003e00000002000000000902000000000986dd6000000000083a40" ++
        "20010db800000000000000000000000120010db80000000000000000000000028000000000000000f5030000000000000d00" ++
        "00000d00000000000000000000000000000000f6030000000000002200000022000000020000000009020000000009080045" ++
        "00001e00010000401100000a0000010a000002f7030000000000002c0000002c000000001122334455020000000009080045" ++
        "00001e00010000400600000ac80304c0000201115c01bb000000007878f80300000000000030000000300000000200000000" ++
        "090200000000098100000508004500001e00010000401100000a0000010a00000200350035000000007878f9030000000000" ++
        "00200000002000000002000000000900112233445588b56c6f63616c206578706572696d656e74616cfa0300000000000054" ++
        "0000005400000002000000000902000000000908004f00004600010000400600000a0000050a000001010101010101010101" ++
        "0101010101010101010101010101010101010101010101010101010101010100500050000000007878fb030000000000003e" ++
        "0000003e00000002000000000902000000000986dd600000000008014020010db800000000000000000000000120010db800" ++
        "00000000000000000000020800000000000000fc030000000000002a0000002a000000ffffffffffff001122334455080600" ++
        "010800060400010011223344550a0000010000000000000a000009fd030000000000002a0000002a00000002000000090200" ++
        "112233445580350001080006040003001122334455c00002050200000009020a010101fe030000000000003e0000003e0000" ++
        "0033330000000100112233445586dd600000000008114020010db8000100000000000000000005ff02000000000000000000" ++
        "000000000114e914e900080000ff030000000000004000000040000000020000000902001122334455080045000032000100" ++
        "00400600000a0000010a00000203e800160000000000000000500203e8000000000000000000000000000000040000000000" ++
        "00c8000000c80000000200000009020011223344550800450000ba00010000400600000a0000020a000001001603e8000000" ++
        "0000000000501203e80000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000104000000000000720000007200000001005e0000fb00112233445508004500006400010000401100" ++
        "00c0000209e00000fb001909c400500000000000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000204000000000000320000" ++
        "003200000002000000090200112233445508004500002400010000400100000a0000010a0000020800000000010001000000" ++
        "00000000000304000000000000320000003200000002000000090200112233445508004500002400010000010100000a0000" ++
        "020a0000010000000000010001000000000000000004040000000000004a0000004a00000002000000090200112233445586" ++
        "dd600000000014064020010db8ffff0000000000000000000720010db8000000000000000000000002001900500000000000" ++
        "000000501003e80000000005040000000000002a0000002a00000002000000090200112233445508004500001c0001200040" ++
        "1100000a0000010a000002003513880008000006040000000000003200000032000000020000000902001122334455810000" ++
        "078100000508004500001c00010000401100000a0000010a000002003513880008000007040000000000003a0000003a0000" ++
        "000200000009020011223344558100000508004500002800010000400600000a000001c000020903e8005000000000000000" ++
        "00500203e8000000000804000000000000460000004600000002000000090200112233445586dd6000000000102c4020010d" ++
        "b800000000000000000000000120010db8000000000000000000000002110000000000000700351388000800000904000000" ++
        "000000460000004600000002000000090200112233445586dd6000000000102c4020010db800000000000000000000000120" ++
        "010db80000000000000000000000023a000000000000078000000000000000",
);

/// What `tcpdump -n -tt -r corpus.pcap EXPR` printed: frame i has timestamp 1000+i.
const oracle = [_]struct { []const u8, []const usize }{
    .{ "ip", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 27, 29 } },
    .{ "ip6", &.{ 9, 10, 11, 12, 19, 22, 28, 32, 33 } },
    .{ "arp", &.{ 0, 20 } },
    .{ "icmp", &.{ 7, 26, 27 } },
    .{ "tcp", &.{ 1, 2, 9, 11, 15, 18, 23, 24, 28 } },
    .{ "udp", &.{ 3, 4, 5, 6, 10, 14, 22, 25, 29, 32 } },
    .{ "sctp", &.{8} },
    .{ "port 53", &.{ 3, 4, 6, 8, 10, 29 } },
    .{ "udp port 53", &.{ 3, 4, 6, 10, 29 } },
    .{ "tcp dst port 80", &.{ 1, 18, 28 } },
    .{ "tcp src port 80", &.{ 2, 18 } },
    .{ "udp src port 53", &.{ 3, 6, 29 } },
    .{ "src port 53", &.{ 3, 6, 8, 29 } },
    .{ "dst port 80", &.{ 1, 18, 28 } },
    .{ "ip src host 10.0.0.1", &.{ 1, 7, 14, 23, 26, 29 } },
    .{ "ip dst host 10.0.0.1", &.{ 2, 3, 18, 24, 27 } },
    .{ "ip host 10.0.0.1", &.{ 1, 2, 3, 7, 14, 18, 23, 24, 26, 27, 29 } },
    .{ "ip net 10.0.0.0/8", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 23, 24, 26, 27, 29 } },
    .{ "ip src net 10.200.0.0/16", &.{15} },
    .{ "ip dst net 192.0.2.0/24", &.{ 1, 15 } },
    .{ "ether host 00:11:22:33:44:55", &.{ 0, 1, 2, 15, 17, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 } },
    .{ "ether src 00:11:22:33:44:55", &.{ 0, 1, 17, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 } },
    .{ "ether dst ff:ff:ff:ff:ff:ff", &.{ 0, 20 } },
    .{ "ether proto 0x86dd", &.{ 9, 10, 11, 12, 19, 22, 28, 32, 33 } },
    .{ "ether proto 34997", &.{17} },
    .{ "ip proto 132", &.{8} },
    .{ "not ip", &.{ 0, 9, 10, 11, 12, 16, 17, 19, 20, 21, 22, 28, 30, 31, 32, 33 } },
    .{ "arp or icmp", &.{ 0, 7, 20, 26, 27 } },
    .{ "tcp and not port 80", &.{ 9, 11, 15, 23, 24 } },
    .{ "(udp or tcp) and ip6", &.{ 9, 10, 11, 22, 28, 32 } },
    .{ "!tcp && !udp", &.{ 0, 7, 8, 12, 16, 17, 19, 20, 21, 26, 27, 30, 31, 33 } },
    .{ "ip and not ip src net 10.0.0.0/8 or arp", &.{ 0, 2, 20, 25 } },
    .{ "not (ip or ip6 or arp)", &.{ 16, 17, 21, 30, 31 } },
    .{ "sctp port 53", &.{8} },
    .{ "udp and ip6 and dst port 53", &.{10} },
    .{ "ip6 host 2001:db8::1", &.{ 9, 10, 11, 12, 19, 32, 33 } },
    .{ "ip6 src host 2001:db8::2", &.{} },
    .{ "ip6 dst host 2001:db8::2", &.{ 9, 10, 11, 12, 19, 28, 32, 33 } },
    .{ "ip6 dst net 2001:db8::/32", &.{ 9, 10, 11, 12, 19, 28, 32, 33 } },
    .{ "ip6 net 2001:db8:1::/48", &.{22} },
    .{ "ip6 src net 2001:db8:ffff::/48", &.{28} },
    .{ "ip6 host ff02::1", &.{22} },
    .{ "ip6 net ::/0", &.{ 9, 10, 11, 12, 19, 22, 28, 32, 33 } },
    .{ "host 10.0.0.1", &.{ 0, 1, 2, 3, 7, 14, 18, 20, 23, 24, 26, 27, 29 } },
    .{ "src host 10.0.0.1", &.{ 0, 1, 7, 14, 20, 23, 26, 29 } },
    .{ "dst host 10.0.0.9", &.{ 4, 5, 6, 20 } },
    .{ "net 10.0.0.0/8", &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 20, 21, 23, 24, 26, 27, 29 } },
    .{ "src net 192.0.2.0/24", &.{ 2, 21, 25 } },
    .{ "host 2001:db8::1", &.{ 9, 10, 11, 12, 19, 32, 33 } },
    .{ "ip6 proto 17", &.{ 10, 22, 32 } },
    .{ "arp host 10.0.0.9", &.{20} },
    .{ "arp src host 10.0.0.1", &.{ 0, 20 } },
    .{ "arp dst host 10.0.0.9", &.{20} },
    .{ "rarp", &.{21} },
    .{ "rarp host 10.1.1.1", &.{21} },
    .{ "portrange 20-30", &.{ 9, 23, 24, 25, 28 } },
    .{ "tcp portrange 20-30", &.{ 9, 23, 24, 28 } },
    .{ "udp src portrange 5000-5400", &.{ 4, 22 } },
    .{ "dst portrange 80-20", &.{ 1, 4, 6, 10, 18, 23, 28 } },
    .{ "tcp dst portrange 22-22", &.{23} },
    .{ "less 60", &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16, 17, 20, 21, 26, 27, 29, 30, 31 } },
    .{ "less 42", &.{ 0, 7, 13, 14, 17, 20, 21, 29 } },
    .{ "greater 100", &.{ 24, 25 } },
    .{ "greater 64", &.{ 9, 10, 11, 18, 23, 24, 25, 28, 32, 33 } },
    .{ "len <= 60", &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 13, 14, 15, 16, 17, 20, 21, 26, 27, 29, 30, 31 } },
    .{ "len > 100", &.{ 24, 25 } },
    .{ "len = 42", &.{ 0, 7, 20, 21, 29 } },
    .{ "len >= 200", &.{24} },
    .{ "len != 62", &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 } },
    .{ "ip[6:2] & 0x1fff = 0", &.{ 1, 2, 3, 4, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 27, 29 } },
    .{ "ip[6:2] & 0x1fff != 0", &.{5} },
    .{ "ip[8] <= 64", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 27, 29 } },
    .{ "ip[8] < 2", &.{27} },
    .{ "ip[8] > 1", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 29 } },
    .{ "ip[9] = 6", &.{ 1, 2, 15, 18, 23, 24 } },
    .{ "ip[0] & 0xf > 5", &.{ 4, 18 } },
    .{ "tcp[13] & 2 != 0", &.{ 23, 24 } },
    .{ "tcp[13] = 0x12", &.{24} },
    .{ "tcp[0:2] = 22", &.{24} },
    .{ "udp[0:2] = 53", &.{ 3, 6, 29 } },
    .{ "udp[2:2] >= 2500", &.{ 3, 25, 29 } },
    .{ "icmp[0] = 8", &.{ 7, 26 } },
    .{ "icmp[0] != 8", &.{27} },
    .{ "ether[0] & 1 = 1", &.{ 0, 20, 22, 25 } },
    .{ "ether[12:2] = 0x0806", &.{ 0, 20 } },
    .{ "ether[0:4] = 0xffffffff", &.{ 0, 20 } },
    .{ "ip6[6] = 17", &.{ 10, 22 } },
    .{ "ip6[6:1] = 6", &.{ 9, 28 } },
    .{ "arp[6:2] = 1", &.{ 0, 20 } },
    .{ "arp[6:2] = 3", &.{} },
    .{ "rarp[6:2] = 3", &.{21} },
    .{ "broadcast", &.{ 0, 20 } },
    .{ "multicast", &.{ 0, 20, 22, 25 } },
    .{ "ether broadcast", &.{ 0, 20 } },
    .{ "ether multicast", &.{ 0, 20, 22, 25 } },
    .{ "ip proto 6", &.{ 1, 2, 15, 18, 23, 24 } },
    .{ "not host 10.0.0.1 and tcp", &.{ 9, 11, 15, 28 } },
    .{ "ip[6:2]&0x1fff=0", &.{ 1, 2, 3, 4, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 27, 29 } },
    .{ "tcp[13]&2!=0", &.{ 23, 24 } },
    .{ "(tcp[13] & 2 != 0) or udp portrange 25-53", &.{ 3, 4, 6, 10, 23, 24, 25, 29 } },
    .{ "tcp or udp and port 53", &.{ 3, 4, 6, 10, 29 } },
    .{ "tcp and port 80 or udp", &.{ 1, 2, 3, 4, 5, 6, 10, 14, 18, 22, 25, 28, 29, 32 } },
    .{ "udp or tcp and not port 53", &.{ 1, 2, 5, 9, 11, 15, 18, 22, 23, 24, 25, 28, 32 } },
    .{ "arp or ip and host 10.0.0.1", &.{ 0, 1, 2, 3, 7, 14, 18, 20, 23, 24, 26, 27, 29 } },
    .{ "ip and host 10.0.0.1 or arp", &.{ 0, 1, 2, 3, 7, 14, 18, 20, 23, 24, 26, 27, 29 } },
    .{ "not tcp or udp and port 53", &.{ 3, 4, 6, 8, 10, 29 } },
    .{ "port 53 or port 80 and tcp", &.{ 1, 2, 18, 28 } },
    .{ "(tcp or udp) and port 53", &.{ 3, 4, 6, 10, 29 } },
    .{ "tcp or (udp and port 53)", &.{ 1, 2, 3, 4, 6, 9, 10, 11, 15, 18, 23, 24, 28, 29 } },
    .{ "ip6 or arp and multicast", &.{ 0, 20, 22 } },
    .{ "host 10.0.0.1 and tcp or udp or icmp", &.{ 1, 2, 3, 4, 5, 6, 7, 10, 14, 18, 22, 23, 24, 25, 26, 27, 29, 32 } },
    .{ "icmp6", &.{ 12, 33 } },
    .{ "ip proto \\tcp", &.{ 1, 2, 15, 18, 23, 24 } },
    .{ "proto 6", &.{ 1, 2, 9, 11, 15, 18, 23, 24, 28 } },
    .{ "proto 17", &.{ 3, 4, 5, 6, 10, 14, 22, 25, 29, 32 } },
    .{ "ip6 proto \\udp", &.{ 10, 22, 32 } },
    .{ "ether proto \\ip", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 27, 29 } },
    .{ "ether proto \\arp", &.{ 0, 20 } },
    .{ "net 10", &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 20, 21, 23, 24, 26, 27, 29 } },
    .{ "net 10.200", &.{15} },
    .{ "net 192.0.2", &.{ 1, 2, 15, 21, 25 } },
    .{ "net 10.0.0.0 mask 255.0.0.0", &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 20, 21, 23, 24, 26, 27, 29 } },
    .{ "net 10.1 mask 255.255.0.0", &.{ 3, 4, 5, 6, 21 } },
    .{ "net 10.0.0.0", &.{} },
    .{ "src net 10", &.{ 0, 1, 3, 4, 5, 6, 7, 8, 14, 15, 18, 20, 23, 24, 26, 27, 29 } },
    .{ "dst net 192.0.2", &.{ 1, 15 } },
    .{ "tcp[tcpflags] & tcp-syn != 0", &.{ 23, 24 } },
    .{ "tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn", &.{23} },
    .{ "tcp[13] & (tcp-syn|tcp-ack) != 0", &.{ 23, 24 } },
    .{ "icmp[icmptype] = icmp-echo", &.{ 7, 26 } },
    .{ "icmp[icmptype] != icmp-echo", &.{27} },
    .{ "icmp[icmpcode] = 0", &.{ 7, 26, 27 } },
    .{ "ip[ 6 : 2 ] & 0x1fff = 0", &.{ 1, 2, 3, 4, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 27, 29 } },
    .{ "ip[ 8 ] <= 64", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 27, 29 } },
    .{ "host 10.0.0.1 or 10.0.0.2", &.{ 0, 1, 2, 3, 7, 14, 18, 20, 23, 24, 26, 27, 29 } },
    .{ "port 53 or 80", &.{ 1, 2, 3, 4, 6, 8, 10, 18, 28, 29 } },
    .{ "tcp dst port 22 or 80 or 443", &.{ 1, 15, 18, 23, 28 } },
    .{ "ip host 10.0.0.1 or 192.0.2.9", &.{ 1, 2, 3, 7, 14, 18, 23, 24, 25, 26, 27, 29 } },
    .{ "ether host 00:11:22:33:44:55 or 02:00:00:00:09:02", &.{ 0, 1, 2, 15, 17, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 } },
    .{ "src host 10.0.0.1 or 10.0.0.2", &.{ 0, 1, 7, 14, 20, 23, 24, 26, 27, 29 } },
    .{ "portrange 20-30 or 5000-5400", &.{ 3, 4, 9, 22, 23, 24, 25, 28, 29 } },
    .{ "port 053", &.{} },
    .{ "port 0x35", &.{ 3, 4, 6, 8, 10, 29 } },
    .{ "ip proto 0x6", &.{ 1, 2, 15, 18, 23, 24 } },
    .{ "vlan", &.{ 16, 30, 31 } },
    .{ "vlan 5", &.{ 16, 31 } },
    .{ "vlan 6", &.{} },
    .{ "host 10.0.0.0 or host 10.0.1.1 or host 10.0.2.2 or host 10.0.3.3 or host 10.0.4.4 or host 10.0.5.5 or host 10.0.6.6 or host 10.0.7.0 or host 10.0.8.1 or host 10.0.9.2 or host 10.0.10.3 or host 10.0.11.4 or host 10.0.12.5 or host 10.0.13.6 or host 10.0.14.0 or host 10.0.15.1 or host 10.0.16.2 or host 10.0.17.3 or host 10.0.18.4 or host 10.0.19.5 or host 10.0.20.6 or host 10.0.21.0 or host 10.0.22.1 or host 10.0.23.2 or host 10.0.24.3 or host 10.0.25.4 or host 10.0.26.5 or host 10.0.27.6 or host 10.0.28.0 or host 10.0.29.1 or host 10.0.30.2 or host 10.0.31.3 or host 10.0.32.4 or host 10.0.33.5 or host 10.0.34.6 or host 10.0.35.0 or host 10.0.36.1 or host 10.0.37.2 or host 10.0.38.3 or host 10.0.39.4 or host 10.0.0.1", &.{ 0, 1, 2, 3, 7, 14, 18, 20, 23, 24, 26, 27, 29 } },
    .{ "not host 10.9.0.1 and not host 10.9.1.2 and not host 10.9.2.3 and not host 10.9.3.4 and not host 10.9.4.5 and not host 10.9.5.6 and not host 10.9.6.7 and not host 10.9.7.8 and not host 10.9.8.9 and not host 10.9.9.10 and not host 10.9.10.11 and not host 10.9.11.12 and not host 10.9.12.13 and not host 10.9.13.14 and not host 10.9.14.15 and not host 10.9.15.16 and not host 10.9.16.17 and not host 10.9.17.18 and not host 10.9.18.19 and not host 10.9.19.20 and not host 10.9.20.21 and not host 10.9.21.22 and not host 10.9.22.23 and not host 10.9.23.24 and not host 10.9.24.25 and tcp", &.{ 1, 2, 9, 11, 15, 18, 23, 24, 28 } },
    .{ "portrange 1000-1005 or portrange 1010-1015 or portrange 1020-1025 or portrange 1030-1035 or portrange 1040-1045 or portrange 1050-1055 or portrange 1060-1065 or portrange 1070-1075 or portrange 1080-1085 or portrange 1090-1095 or portrange 1100-1105 or portrange 1110-1115 or portrange 1120-1125 or portrange 1130-1135 or portrange 1140-1145 or portrange 1150-1155 or portrange 1160-1165 or portrange 1170-1175 or portrange 1180-1185 or portrange 1190-1195 or portrange 1200-1205 or portrange 1210-1215 or portrange 1220-1225 or portrange 1230-1235 or portrange 1240-1245 or portrange 1250-1255 or portrange 1260-1265 or portrange 1270-1275 or portrange 1280-1285 or portrange 1290-1295 or port 53", &.{ 1, 2, 3, 4, 6, 8, 10, 23, 24, 29 } },
    .{ "ether host 02:00:00:00:00:00 or ether host 02:00:00:00:01:01 or ether host 02:00:00:00:02:02 or ether host 02:00:00:00:03:03 or ether host 02:00:00:00:04:04 or ether host 02:00:00:00:05:05 or ether host 02:00:00:00:06:06 or ether host 02:00:00:00:07:07 or ether host 02:00:00:00:08:08 or ether host 02:00:00:00:09:09 or ether host 02:00:00:00:0a:0a or ether host 02:00:00:00:0b:0b or ether host 02:00:00:00:0c:0c or ether host 02:00:00:00:0d:0d or ether host 02:00:00:00:0e:0e or ether host 02:00:00:00:0f:0f or ether host 02:00:00:00:10:10 or ether host 02:00:00:00:11:11 or ether host 02:00:00:00:12:12 or ether host 02:00:00:00:13:13 or ether host 02:00:00:00:14:14 or ether host 02:00:00:00:15:15 or ether host 02:00:00:00:16:16 or ether host 02:00:00:00:17:17 or ether host 02:00:00:00:18:18 or ether host 00:11:22:33:44:55", &.{ 0, 1, 2, 15, 17, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 } },
    .{ "vlan and ip", &.{ 16, 31 } },
    .{ "vlan 5 and tcp port 80", &.{31} },
    .{ "vlan and ether host 00:11:22:33:44:55", &.{ 30, 31 } },
    .{ "vlan and multicast", &.{} },
    .{ "vlan and ether proto 0x800", &.{ 16, 31 } },
    .{ "vlan and ether[12:2] = 0x800", &.{} },
    .{ "vlan and arp host 10.0.0.1", &.{} },
    .{ "vlan and ip[8] = 64", &.{ 16, 31 } },
    .{ "vlan and tcp[13] & 2 != 0", &.{31} },
    .{ "vlan and vlan 5", &.{30} },
    .{ "vlan and vlan", &.{30} },
    .{ "not vlan and ip", &.{ 0, 20, 21 } },
    .{ "vlan or ip", &.{ 0, 16, 20, 21, 30, 31 } },
    .{ "vlan and less 60", &.{ 16, 30, 31 } },
    .{ "vlan and host 10.0.0.1", &.{ 16, 31 } },
    .{ "vlan and ip6 host 2001:db8::1", &.{} },
    .{ "vlan 7 and vlan 5 and udp", &.{30} },
    .{ "vlan and net 10", &.{ 16, 31 } },
    .{ "ip6 proto 6", &.{ 9, 11, 28 } },
    .{ "ip6 proto 17", &.{ 10, 22, 32 } },
    .{ "ip6 proto 58", &.{ 12, 33 } },
    .{ "ip6 proto \\tcp", &.{ 9, 11, 28 } },
    .{ "ip6 proto \\udp", &.{ 10, 22, 32 } },
    .{ "udp", &.{ 3, 4, 5, 6, 10, 14, 22, 25, 29, 32 } },
    .{ "tcp", &.{ 1, 2, 9, 11, 15, 18, 23, 24, 28 } },
    .{ "icmp6", &.{ 12, 33 } },
    .{ "proto 17", &.{ 3, 4, 5, 6, 10, 14, 22, 25, 29, 32 } },
    .{ "proto 58", &.{ 12, 33 } },
    .{ "udp port 53", &.{ 3, 4, 6, 10, 29 } },
    .{ "ip6 and not icmp6", &.{ 9, 10, 11, 19, 22, 28, 32 } },
    .{ "net 10.0.0.0 mask 255.0.255.0", &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 18, 20, 23, 24, 26, 27, 29 } },
    .{ "net 10.0.0.0 mask 255.255.255.255", &.{} },
    .{ "src net 10.0.0.0 mask 255.0.0.255", &.{} },
    .{ "icmp[icmptype] = tcp-syn", &.{} },
    .{ "ip[0] = tcp-syn", &.{} },
    .{ "port tcp-syn", &.{} },
    .{ "port icmp-echo", &.{} },
    .{ "len > icmp-echo", &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33 } },
    .{ "tcp[tcpflags] & icmp-echo != 0", &.{} },
};

// BEGIN link corpora (tools/gen_filter_oracle.py)
const corpus_sll_pcap = hex(
    "d4c3b2a10200040000000000000000000000040071000000e8030000000000002c0000002c00000000000001000600112233" ++
        "44550000080600010800060400010011223344550a0000010000000000000a000002e9030000000000002e0000002e000000" ++
        "000000010006001122334455000008004500001e00010000400600000a000001c000020504d20050000000007878ea030000" ++
        "000000002e0000002e000000000000010006020000000009000008004500001e0001000040060000c00002050a0000010050" ++
        "04d2000000007878eb030000000000002e0000002e000000000000010006020000000009000008004500001e000100004011" ++
        "00000a0102030a000001003514e9000000007878ec0300000000000032000000320000000000000100060200000000090000" ++
        "08004600002200010000401100000a0102030a0000090101010113880035000000007878ed030000000000002e0000002e00" ++
        "0000000000010006020000000009000008004500001e00010010401100000a0102030a00000900350035000000007878ee03" ++
        "0000000000002e0000002e000000000000010006020000000009000008004500001e00012000401100000a0102030a000009" ++
        "00350035000000007878ef030000000000002c0000002c000000000000010006020000000009000008004500001c00010000" ++
        "400100000a000001080808080800000000000000f0030000000000002e0000002e0000000000000100060200000000090000" ++
        "08004500001e00010000408400000a0000070a0000080035270f000000007878f10300000000000042000000420000000000" ++
        "00010006020000000009000086dd60000000000a064020010db800000000000000000000000120010db80000000000000000" ++
        "0000000200169c40000000007878f2030000000000004200000042000000000000010006020000000009000086dd60000000" ++
        "000a114020010db800000000000000000000000120010db80000000000000000000000029c400035000000007878f3030000" ++
        "000000004a0000004a000000000000010006020000000009000086dd6000000000122c4020010db800000000000000000000" ++
        "000120010db8000000000000000000000002060000000000000104570050000000007878f403000000000000400000004000" ++
        "0000000000010006020000000009000086dd6000000000083a4020010db800000000000000000000000120010db800000000" ++
        "00000000000000028000000000000000f6030000000000002400000024000000000000010006020000000009000008004500" ++
        "001e00010000401100000a0000010a000002f7030000000000002e0000002e00000000000001000602000000000900000800" ++
        "4500001e00010000400600000ac80304c0000201115c01bb000000007878f803000000000000320000003200000000000001" ++
        "000602000000000900008100000508004500001e00010000401100000a0000010a00000200350035000000007878f9030000" ++
        "000000002200000022000000000000010006001122334455000088b56c6f63616c206578706572696d656e74616cfa030000" ++
        "000000005600000056000000000000010006020000000009000008004f00004600010000400600000a0000050a0000010101" ++
        "010101010101010101010101010101010101010101010101010101010101010101010101010100500050000000007878fb03" ++
        "0000000000004000000040000000000000010006020000000009000086dd600000000008014020010db80000000000000000" ++
        "0000000120010db80000000000000000000000020800000000000000fc030000000000002c0000002c000000000000010006" ++
        "0011223344550000080600010800060400010011223344550a0000010000000000000a000009fd030000000000002c000000" ++
        "2c000000000000010006001122334455000080350001080006040003001122334455c00002050200000009020a010101fe03" ++
        "0000000000004000000040000000000000010006001122334455000086dd600000000008114020010db80001000000000000" ++
        "00000005ff02000000000000000000000000000114e914e900080000ff030000000000004200000042000000000000010006" ++
        "001122334455000008004500003200010000400600000a0000010a00000203e800160000000000000000500203e800000000" ++
        "000000000000000000000004000000000000ca000000ca00000000000001000600112233445500000800450000ba00010000" ++
        "400600000a0000020a000001001603e80000000000000000501203e800000000000000000000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000001040000000000007400000074000000000000010006" ++
        "00112233445500000800450000640001000040110000c0000209e00000fb001909c400500000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000002040000000000003400000034000000000000010006001122334455000008004500002400010000" ++
        "400100000a0000010a0000020800000000010001000000000000000003040000000000003400000034000000000000010006" ++
        "001122334455000008004500002400010000010100000a0000020a0000010000000000010001000000000000000004040000" ++
        "000000004c0000004c000000000000010006001122334455000086dd600000000014064020010db8ffff0000000000000000" ++
        "000720010db8000000000000000000000002001900500000000000000000501003e80000000005040000000000002c000000" ++
        "2c000000000000010006001122334455000008004500001c00012000401100000a0000010a00000200351388000800000604" ++
        "00000000000034000000340000000000000100060011223344550000810000078100000508004500001c0001000040110000" ++
        "0a0000010a000002003513880008000007040000000000003c0000003c000000000000010006001122334455000081000005" ++
        "08004500002800010000400600000a000001c000020903e800500000000000000000500203e8000000000804000000000000" ++
        "4800000048000000000000010006001122334455000086dd6000000000102c4020010db80000000000000000000000012001" ++
        "0db8000000000000000000000002110000000000000700351388000800000904000000000000480000004800000000000001" ++
        "0006001122334455000086dd6000000000102c4020010db800000000000000000000000120010db800000000000000000000" ++
        "00023a000000000000078000000000000000",
);

const oracle_sll = [_]struct { []const u8, []const usize }{
    .{ "ip", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 27, 29 } },
    .{ "ip6", &.{ 9, 10, 11, 12, 19, 22, 28, 32, 33 } },
    .{ "arp", &.{ 0, 20 } },
    .{ "tcp port 80", &.{ 1, 2, 18, 28 } },
    .{ "udp port 53", &.{ 3, 4, 6, 10, 29 } },
    .{ "host 10.0.0.1", &.{ 0, 1, 2, 3, 7, 14, 18, 20, 23, 24, 26, 27, 29 } },
    .{ "src host 10.0.0.1", &.{ 0, 1, 7, 14, 20, 23, 26, 29 } },
    .{ "net 10", &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 20, 21, 23, 24, 26, 27, 29 } },
    .{ "ip[8] = 64", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 29 } },
    .{ "tcp[13] & 2 != 0", &.{ 23, 24 } },
    .{ "ip6 net 2001:db8::/32", &.{ 9, 10, 11, 12, 19, 22, 28, 32, 33 } },
    .{ "icmp", &.{ 7, 26, 27 } },
    .{ "icmp6", &.{ 12, 33 } },
    .{ "proto 6", &.{ 1, 2, 9, 11, 15, 18, 23, 24, 28 } },
    .{ "portrange 20-30", &.{ 9, 23, 24, 25, 28 } },
    .{ "less 60", &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 16, 17, 20, 21, 26, 27, 29, 30, 31 } },
    .{ "tcp or udp and port 53", &.{ 3, 4, 6, 10, 29 } },
    .{ "ip6 host 2001:db8::1", &.{ 9, 10, 11, 12, 19, 32, 33 } },
    .{ "greater 100", &.{ 24, 25 } },
    .{ "ip and host 10.0.0.1 or ip6", &.{ 1, 2, 3, 7, 9, 10, 11, 12, 14, 18, 19, 22, 23, 24, 26, 27, 28, 29, 32, 33 } },
};

const corpus_raw_pcap = hex(
    "d4c3b2a10200040000000000000000000000040065000000e9030000000000001e0000001e0000004500001e000100004006" ++
        "00000a000001c000020504d20050000000007878ea030000000000001e0000001e0000004500001e0001000040060000c000" ++
        "02050a000001005004d2000000007878eb030000000000001e0000001e0000004500001e00010000401100000a0102030a00" ++
        "0001003514e9000000007878ec0300000000000022000000220000004600002200010000401100000a0102030a0000090101" ++
        "010113880035000000007878ed030000000000001e0000001e0000004500001e00010010401100000a0102030a0000090035" ++
        "0035000000007878ee030000000000001e0000001e0000004500001e00012000401100000a0102030a000009003500350000" ++
        "00007878ef030000000000001c0000001c0000004500001c00010000400100000a000001080808080800000000000000f003" ++
        "0000000000001e0000001e0000004500001e00010000408400000a0000070a0000080035270f000000007878f10300000000" ++
        "0000320000003200000060000000000a064020010db800000000000000000000000120010db8000000000000000000000002" ++
        "00169c40000000007878f203000000000000320000003200000060000000000a114020010db8000000000000000000000001" ++
        "20010db80000000000000000000000029c400035000000007878f3030000000000003a0000003a0000006000000000122c40" ++
        "20010db800000000000000000000000120010db8000000000000000000000002060000000000000104570050000000007878" ++
        "f40300000000000030000000300000006000000000083a4020010db800000000000000000000000120010db8000000000000" ++
        "0000000000028000000000000000f60300000000000014000000140000004500001e00010000401100000a0000010a000002" ++
        "f7030000000000001e0000001e0000004500001e00010000400600000ac80304c0000201115c01bb000000007878fa030000" ++
        "0000000046000000460000004f00004600010000400600000a0000050a000001010101010101010101010101010101010101" ++
        "0101010101010101010101010101010101010101010100500050000000007878fb0300000000000030000000300000006000" ++
        "00000008014020010db800000000000000000000000120010db80000000000000000000000020800000000000000fe030000" ++
        "000000003000000030000000600000000008114020010db8000100000000000000000005ff02000000000000000000000000" ++
        "000114e914e900080000ff0300000000000032000000320000004500003200010000400600000a0000010a00000203e80016" ++
        "0000000000000000500203e800000000000000000000000000000004000000000000ba000000ba000000450000ba00010000" ++
        "400600000a0000020a000001001603e80000000000000000501203e800000000000000000000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000001040000000000006400000064000000450000640001" ++
        "000040110000c0000209e00000fb001909c40050000000000000000000000000000000000000000000000000000000000000" ++
        "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020400000000" ++
        "000024000000240000004500002400010000400100000a0000010a0000020800000000010001000000000000000003040000" ++
        "0000000024000000240000004500002400010000010100000a0000020a000001000000000001000100000000000000000404" ++
        "0000000000003c0000003c000000600000000014064020010db8ffff0000000000000000000720010db80000000000000000" ++
        "00000002001900500000000000000000501003e80000000005040000000000001c0000001c0000004500001c000120004011" ++
        "00000a0000010a0000020035138800080000080400000000000038000000380000006000000000102c4020010db800000000" ++
        "000000000000000120010db80000000000000000000000021100000000000007003513880008000009040000000000003800" ++
        "0000380000006000000000102c4020010db800000000000000000000000120010db80000000000000000000000023a000000" ++
        "000000078000000000000000",
);

const oracle_raw = [_]struct { []const u8, []const usize }{
    .{ "ip", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 27, 29 } },
    .{ "ip6", &.{ 9, 10, 11, 12, 19, 22, 28, 32, 33 } },
    .{ "tcp port 80", &.{ 1, 2, 18, 28 } },
    .{ "udp port 53", &.{ 3, 4, 6, 10, 29 } },
    .{ "host 10.0.0.1", &.{ 1, 2, 3, 7, 14, 18, 23, 24, 26, 27, 29 } },
    .{ "src host 10.0.0.1", &.{ 1, 7, 14, 23, 26, 29 } },
    .{ "net 10", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 23, 24, 26, 27, 29 } },
    .{ "ip[8] = 64", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18, 23, 24, 25, 26, 29 } },
    .{ "tcp[13] & 2 != 0", &.{ 23, 24 } },
    .{ "ip6 net 2001:db8::/32", &.{ 9, 10, 11, 12, 19, 22, 28, 32, 33 } },
    .{ "icmp", &.{ 7, 26, 27 } },
    .{ "icmp6", &.{ 12, 33 } },
    .{ "proto 6", &.{ 1, 2, 9, 11, 15, 18, 23, 24, 28 } },
    .{ "portrange 20-30", &.{ 9, 23, 24, 25, 28 } },
    .{ "less 60", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 14, 15, 19, 22, 23, 26, 27, 28, 29, 32, 33 } },
    .{ "tcp or udp and port 53", &.{ 3, 4, 6, 10, 29 } },
    .{ "ip6 host 2001:db8::1", &.{ 9, 10, 11, 12, 19, 32, 33 } },
    .{ "greater 100", &.{ 24, 25 } },
    .{ "ip and host 10.0.0.1 or ip6", &.{ 1, 2, 3, 7, 9, 10, 11, 12, 14, 18, 19, 22, 23, 24, 26, 27, 28, 29, 32, 33 } },
};

// END link corpora

/// `tcpdump -dd -y EN10MB EXPR` — libpcap 1.10.6's own programs, to check `run` against them.
const libpcap_programs = [_]struct { []const u8, []const BpfInsn }{
    .{ "tcp dst port 80", &.{
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x0000000c },
        .{ .code = 0x15, .jt = 0, .jf = 4, .k = 0x000086dd },
        .{ .code = 0x30, .jt = 0, .jf = 0, .k = 0x00000014 },
        .{ .code = 0x15, .jt = 0, .jf = 11, .k = 0x00000006 },
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x00000038 },
        .{ .code = 0x15, .jt = 8, .jf = 9, .k = 0x00000050 },
        .{ .code = 0x15, .jt = 0, .jf = 8, .k = 0x00000800 },
        .{ .code = 0x30, .jt = 0, .jf = 0, .k = 0x00000017 },
        .{ .code = 0x15, .jt = 0, .jf = 6, .k = 0x00000006 },
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x00000014 },
        .{ .code = 0x45, .jt = 4, .jf = 0, .k = 0x00001fff },
        .{ .code = 0xb1, .jt = 0, .jf = 0, .k = 0x0000000e },
        .{ .code = 0x48, .jt = 0, .jf = 0, .k = 0x00000010 },
        .{ .code = 0x15, .jt = 0, .jf = 1, .k = 0x00000050 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00040000 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00000000 },
    } },
    .{ "port 53", &.{
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x0000000c },
        .{ .code = 0x15, .jt = 0, .jf = 8, .k = 0x000086dd },
        .{ .code = 0x30, .jt = 0, .jf = 0, .k = 0x00000014 },
        .{ .code = 0x15, .jt = 2, .jf = 0, .k = 0x00000084 },
        .{ .code = 0x15, .jt = 1, .jf = 0, .k = 0x00000006 },
        .{ .code = 0x15, .jt = 0, .jf = 17, .k = 0x00000011 },
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x00000036 },
        .{ .code = 0x15, .jt = 14, .jf = 0, .k = 0x00000035 },
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x00000038 },
        .{ .code = 0x15, .jt = 12, .jf = 13, .k = 0x00000035 },
        .{ .code = 0x15, .jt = 0, .jf = 12, .k = 0x00000800 },
        .{ .code = 0x30, .jt = 0, .jf = 0, .k = 0x00000017 },
        .{ .code = 0x15, .jt = 2, .jf = 0, .k = 0x00000084 },
        .{ .code = 0x15, .jt = 1, .jf = 0, .k = 0x00000006 },
        .{ .code = 0x15, .jt = 0, .jf = 8, .k = 0x00000011 },
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x00000014 },
        .{ .code = 0x45, .jt = 6, .jf = 0, .k = 0x00001fff },
        .{ .code = 0xb1, .jt = 0, .jf = 0, .k = 0x0000000e },
        .{ .code = 0x48, .jt = 0, .jf = 0, .k = 0x0000000e },
        .{ .code = 0x15, .jt = 2, .jf = 0, .k = 0x00000035 },
        .{ .code = 0x48, .jt = 0, .jf = 0, .k = 0x00000010 },
        .{ .code = 0x15, .jt = 0, .jf = 1, .k = 0x00000035 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00040000 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00000000 },
    } },
    .{ "ip net 10.0.0.0/8", &.{
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x0000000c },
        .{ .code = 0x15, .jt = 0, .jf = 7, .k = 0x00000800 },
        .{ .code = 0x20, .jt = 0, .jf = 0, .k = 0x0000001a },
        .{ .code = 0x54, .jt = 0, .jf = 0, .k = 0xff000000 },
        .{ .code = 0x15, .jt = 3, .jf = 0, .k = 0x0a000000 },
        .{ .code = 0x20, .jt = 0, .jf = 0, .k = 0x0000001e },
        .{ .code = 0x54, .jt = 0, .jf = 0, .k = 0xff000000 },
        .{ .code = 0x15, .jt = 0, .jf = 1, .k = 0x0a000000 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00040000 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00000000 },
    } },
    .{ "not ip", &.{
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x0000000c },
        .{ .code = 0x15, .jt = 0, .jf = 1, .k = 0x00000800 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00000000 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00040000 },
    } },
    .{ "ether host 00:11:22:33:44:55", &.{
        .{ .code = 0x20, .jt = 0, .jf = 0, .k = 0x00000008 },
        .{ .code = 0x15, .jt = 0, .jf = 2, .k = 0x22334455 },
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x00000006 },
        .{ .code = 0x15, .jt = 4, .jf = 0, .k = 0x00000011 },
        .{ .code = 0x20, .jt = 0, .jf = 0, .k = 0x00000002 },
        .{ .code = 0x15, .jt = 0, .jf = 3, .k = 0x22334455 },
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x00000000 },
        .{ .code = 0x15, .jt = 0, .jf = 1, .k = 0x00000011 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00040000 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00000000 },
    } },
    .{ "tcp and not port 80", &.{
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x0000000c },
        .{ .code = 0x15, .jt = 0, .jf = 9, .k = 0x00000800 },
        .{ .code = 0x30, .jt = 0, .jf = 0, .k = 0x00000017 },
        .{ .code = 0x15, .jt = 0, .jf = 18, .k = 0x00000006 },
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x00000014 },
        .{ .code = 0x45, .jt = 15, .jf = 0, .k = 0x00001fff },
        .{ .code = 0xb1, .jt = 0, .jf = 0, .k = 0x0000000e },
        .{ .code = 0x48, .jt = 0, .jf = 0, .k = 0x0000000e },
        .{ .code = 0x15, .jt = 13, .jf = 0, .k = 0x00000050 },
        .{ .code = 0x48, .jt = 0, .jf = 0, .k = 0x00000010 },
        .{ .code = 0x15, .jt = 11, .jf = 10, .k = 0x00000050 },
        .{ .code = 0x15, .jt = 0, .jf = 10, .k = 0x000086dd },
        .{ .code = 0x30, .jt = 0, .jf = 0, .k = 0x00000014 },
        .{ .code = 0x15, .jt = 0, .jf = 4, .k = 0x00000006 },
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x00000036 },
        .{ .code = 0x15, .jt = 6, .jf = 0, .k = 0x00000050 },
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x00000038 },
        .{ .code = 0x15, .jt = 4, .jf = 3, .k = 0x00000050 },
        .{ .code = 0x15, .jt = 0, .jf = 3, .k = 0x0000002c },
        .{ .code = 0x30, .jt = 0, .jf = 0, .k = 0x00000036 },
        .{ .code = 0x15, .jt = 0, .jf = 1, .k = 0x00000006 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00040000 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00000000 },
    } },
    .{ "!tcp && !udp", &.{
        .{ .code = 0x28, .jt = 0, .jf = 0, .k = 0x0000000c },
        .{ .code = 0x15, .jt = 0, .jf = 2, .k = 0x00000800 },
        .{ .code = 0x30, .jt = 0, .jf = 0, .k = 0x00000017 },
        .{ .code = 0x15, .jt = 7, .jf = 6, .k = 0x00000006 },
        .{ .code = 0x15, .jt = 0, .jf = 7, .k = 0x000086dd },
        .{ .code = 0x30, .jt = 0, .jf = 0, .k = 0x00000014 },
        .{ .code = 0x15, .jt = 4, .jf = 0, .k = 0x00000006 },
        .{ .code = 0x15, .jt = 0, .jf = 2, .k = 0x0000002c },
        .{ .code = 0x30, .jt = 0, .jf = 0, .k = 0x00000036 },
        .{ .code = 0x15, .jt = 1, .jf = 0, .k = 0x00000006 },
        .{ .code = 0x15, .jt = 0, .jf = 1, .k = 0x00000011 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00000000 },
        .{ .code = 0x6, .jt = 0, .jf = 0, .k = 0x00040000 },
    } },
};

/// The corpus frame numbers (record time minus 1000 s) a program accepts.
fn verdictsOf(prog: []const BpfInsn, corpus: []const u8, out: *std.ArrayList(usize)) !void {
    out.clearRetainingCapacity();
    var r = try pcap.Reader.init(corpus);
    while (try r.next()) |rec| {
        if (run(prog, rec.data) != 0) try out.append(testing.allocator, @intCast(rec.ts_ns / std.time.ns_per_s - 1000));
    }
}

test "compile: SLL and raw-IP savefiles select the frames tcpdump -y selects" {
    var got: std.ArrayList(usize) = .empty;
    defer got.deinit(testing.allocator);
    inline for (.{ .{ Link.linux_sll, &oracle_sll, &corpus_sll_pcap }, .{ Link.raw, &oracle_raw, &corpus_raw_pcap } }) |c| {
        for (c[1]) |o| {
            const prog = compileOpts(testing.allocator, o[0], .{ .link = c[0] }) catch |e| {
                std.debug.print("link {t} expression: {s}\n", .{ c[0], o[0] });
                return e;
            };
            defer testing.allocator.free(prog);
            try validate(prog);
            try verdictsOf(prog, c[2], &got);
            testing.expectEqualSlices(usize, o[1], got.items) catch |e| {
                std.debug.print("link {t} expression: {s}\n", .{ c[0], o[0] });
                return e;
            };
        }
    }
    // What libpcap refuses on these links is `UnsupportedExpression` here.
    for ([_][]const u8{ "ether host 00:11:22:33:44:55", "multicast", "vlan", "ether[0] = 1" }) |e| {
        try testing.expectError(error.UnsupportedExpression, compileOpts(testing.allocator, e, .{ .link = .linux_sll }));
        try testing.expectError(error.UnsupportedExpression, compileOpts(testing.allocator, e, .{ .link = .raw }));
    }
    try testing.expectError(error.UnsupportedExpression, compileOpts(testing.allocator, "arp", .{ .link = .raw }));
}

const link_oracle = @import("testdata/link_oracle.zig");
const vlan_live = @import("testdata/vlan_live.zig");

/// A NULL savefile holds the byte order of the host that captured it; the
/// committed corpus came from a little-endian host. Turn the family words
/// around for a big-endian test host (what libpcap compiles for there).
fn swapNullWords(buf: []u8) void {
    var pos: usize = 24;
    while (pos + 16 <= buf.len) {
        const cl = std.mem.readInt(u32, buf[pos + 8 ..][0..4], .little);
        std.mem.reverse(u8, buf[pos + 16 ..][0..4]);
        pos += 16 + cl;
    }
}

test "compile: a NULL savefile is read in the byte order of its capturing host, whatever the compiling host is" {
    var le = hex(link_oracle.corpus_null); // captured on a little-endian host
    var be = le;
    swapNullWords(&be); // the same capture as a big-endian host wrote it
    var got: std.ArrayList(usize) = .empty;
    defer got.deinit(testing.allocator);
    var want: std.ArrayList(usize) = .empty;
    defer want.deinit(testing.allocator);
    for ([_][]const u8{ "ip", "ip6", "ether proto 0x86dd", "host 10.0.0.1 or ip6" }) |e| {
        const p_le = try compileOpts(testing.allocator, e, .{ .link = .bsd_null, .null_byte_order = .little });
        defer testing.allocator.free(p_le);
        const p_be = try compileOpts(testing.allocator, e, .{ .link = .bsd_null, .null_byte_order = .big });
        defer testing.allocator.free(p_be);
        try verdictsOf(p_le, &le, &want);
        try verdictsOf(p_be, &be, &got);
        try testing.expectEqualSlices(usize, want.items, got.items);
        // The wrong order matches nothing for the family primitives.
        try verdictsOf(p_be, &le, &got);
        try testing.expect(got.items.len < want.items.len);
        try testing.expect(want.items.len > 0);
    }
}

test "compile: NULL, LOOP and cooked-v2 savefiles select the frames tcpdump -y selects" {
    var got: std.ArrayList(usize) = .empty;
    defer got.deinit(testing.allocator);
    inline for (.{
        .{ Link.bsd_null, &link_oracle.oracle_null, link_oracle.corpus_null, &link_oracle.refused_null },
        .{ Link.bsd_loop, &link_oracle.oracle_loop, link_oracle.corpus_loop, &link_oracle.refused_loop },
        .{ Link.linux_sll2, &link_oracle.oracle_sll2, link_oracle.corpus_sll2, &link_oracle.refused_sll2 },
    }) |c| {
        var corpus = hex(c[2]);
        const rd = try pcap.Reader.init(&corpus);
        try testing.expectEqual(c[0].dlt(), rd.header.linktype);
        try testing.expectEqual(@as(?Link, c[0]), Link.fromDlt(c[0].dlt()));
        for (c[1]) |o| {
            // The file's own byte order decides (the committed corpus is a little-endian
            // capture; the bytes are NOT rewritten for the host running the test).
            const prog = compileOpts(testing.allocator, o[0], .{ .link = c[0], .null_byte_order = rd.byteOrder() }) catch |e| {
                std.debug.print("link {t} expression: {s}\n", .{ c[0], o[0] });
                return e;
            };
            defer testing.allocator.free(prog);
            try validate(prog);
            try verdictsOf(prog, &corpus, &got);
            testing.expectEqualSlices(usize, o[1], got.items) catch |e| {
                std.debug.print("link {t} expression: {s}\n", .{ c[0], o[0] });
                return e;
            };
            // Non-vacuous: some expressions select nothing, most select something.
        }
        for (c[3]) |e| {
            testing.expectError(error.UnsupportedExpression, compileOpts(testing.allocator, e, .{ .link = c[0] })) catch |er| {
                std.debug.print("link {t} refused expression: {s}\n", .{ c[0], e });
                return er;
            };
        }
    }
    try testing.expectEqual(@as(?Link, null), Link.fromDlt(12345));
    try testing.expectEqual(@as(u32, 276), Link.linux_sll2.dlt());
}

/// The frame `f` with an 802.1Q tag `tci` after the MACs.
fn withTag(out: []u8, f: []const u8, tpid: u16, tci: u16) []u8 {
    @memcpy(out[0..12], f[0..12]);
    std.mem.writeInt(u16, out[12..14], tpid, .big);
    std.mem.writeInt(u16, out[14..16], tci, .big);
    @memcpy(out[16 .. f.len + 4], f[12..]);
    return out[0 .. f.len + 4];
}

test "compile: the live vlan form combined with other primitives agrees with libpcap's live program" {
    const corpus = corpus_pcap;
    var progs: [4096]BpfInsn = undefined;
    const rd0 = try pcap.Reader.init(&corpus);
    var n_cmp: usize = 0;
    var n_accept: usize = 0;
    var n_bad: usize = 0;
    var n_defect_accept: usize = 0;
    for (vlan_live.rows) |row| {
        var lp_bytes: [4096 * 8]u8 = undefined;
        const lp_len = (try std.fmt.hexToBytes(&lp_bytes, row[1])).len / 8;
        for (progs[0..lp_len], 0..) |*ins, k| { // little-endian fields, whatever the host is
            const w = lp_bytes[k * 8 ..][0..8];
            ins.* = .{ .code = std.mem.readInt(u16, w[0..2], .little), .jt = w[2], .jf = w[3], .k = std.mem.readInt(u32, w[4..8], .little) };
        }
        const lp = progs[0..lp_len];
        try validate(lp);
        const ours = compileOpts(testing.allocator, row[0], .{ .vlan_ancillary = true }) catch |e| {
            std.debug.print("live vlan expression: {s}\n", .{row[0]});
            return e;
        };
        defer testing.allocator.free(ours);
        try validate(ours);
        var rd = rd0;
        var row_bad = false;
        const defect = std.mem.eql(u8, row[0], "ip and vlan 5");
        while (try rd.next()) |rec| {
            const f = rec.data;
            if (f.len < 14 or f.len > 1500) continue;
            var b1: [1600]u8 = undefined;
            var b2: [1600]u8 = undefined;
            const ety = std.mem.readInt(u16, f[12..14], .big);
            const tagged = (ety == 0x8100 or ety == 0x88a8 or ety == 0x9100) and f.len >= 18;
            var b3: [1600]u8 = undefined;
            var b4: [1600]u8 = undefined;
            var cases: [8]struct { []const u8, ?u16 } = undefined;
            var nc: usize = 0;
            cases[nc] = .{ f, null }; // as captured: any tag stays in the frame
            nc += 1;
            if (tagged) { // the kernel stripped the outer tag into metadata
                @memcpy(b1[0..12], f[0..12]);
                @memcpy(b1[12 .. f.len - 4], f[16..]);
                cases[nc] = .{ b1[0 .. f.len - 4], std.mem.readInt(u16, f[14..16], .big) };
                nc += 1;
            } else {
                cases[nc] = .{ withTag(&b1, f, 0x8100, 5), null }; // in the frame
                nc += 1;
                cases[nc] = .{ f, 5 }; // metadata
                nc += 1;
                cases[nc] = .{ f, 0x6007 }; // metadata, priority bits
                nc += 1;
                cases[nc] = .{ f, 0 }; // metadata, id 0 (present is not "id != 0")
                nc += 1;
                const t1 = withTag(&b1, f, 0x8100, 5);
                cases[nc] = .{ withTag(&b2, t1, 0x88a8, 7), null }; // two tags in the frame
                nc += 1;
                // An MPLS frame (label 5, bottom of stack) and a PPPoE session 7 frame carrying the same payload.
                @memcpy(b3[0..12], f[0..12]);
                std.mem.writeInt(u16, b3[12..14], 0x8847, .big);
                std.mem.writeInt(u32, b3[14..18], 5 << 12 | 1 << 8 | 64, .big);
                @memcpy(b3[18 .. f.len + 4], f[14..]);
                cases[nc] = .{ b3[0 .. f.len + 4], null };
                nc += 1;
                @memcpy(b4[0..12], f[0..12]);
                std.mem.writeInt(u16, b4[12..14], 0x8864, .big);
                @memcpy(b4[14..22], &[_]u8{ 0x11, 0, 0, 7, 0, 40, 0, 0x21 });
                @memcpy(b4[22 .. f.len + 8], f[14..]);
                cases[nc] = .{ b4[0 .. f.len + 8], null };
                nc += 1;
            }
            for (cases[0..nc]) |cs| {
                for ([_]LiveMeta{
                    .{ .vlan_tci = cs[1], .pkttype = 0, .ifindex = 1 },
                    .{ .vlan_tci = cs[1], .pkttype = 4, .ifindex = 2 },
                    .{ .vlan_tci = cs[1], .pkttype = 3, .ifindex = 1 },
                }) |meta| {
                    const a = runLiveMeta(ours, cs[0], meta) != 0;
                    const l = runLiveMeta(lp, cs[0], meta) != 0;
                    if (defect) {
                        // libpcap's own live program for `ip and vlan 5` accepts nothing (it jumps over the
                        // `ldh [vlan_tci]` it needs, so the id test sees the PRESENT flag): not reproduced.
                        try testing.expect(!l);
                        if (a) n_defect_accept += 1;
                    } else if (l != a) {
                        if (!row_bad) std.debug.print("live vlan expression differs: {s}, frame len {d}, meta {?d}, libpcap {}\n", .{ row[0], cs[0].len, cs[1], l });
                        row_bad = true;
                        n_bad += 1;
                    }
                    n_cmp += 1;
                    if (l) n_accept += 1;
                }
            }
        }
    }
    try testing.expectEqual(@as(usize, 0), n_bad);
    try testing.expect(n_defect_accept > 0);
    // Non-vacuous: thousands of verdict pairs, a good share accepting.
    try testing.expect(n_cmp > 15000);
    try testing.expect(n_accept > 1500);
}

fn smallStackCompile(expr: []const u8, ok: *bool) void {
    const gpa = std.heap.page_allocator; // global-alloc-ok: runs in a 64 KiB-stack thread with its own allocator
    if (compileOpts(gpa, expr, .{})) |prog| {
        gpa.free(prog);
    } else |_| {}
    ok.* = true;
}

test "compile: a typical filter allocates only its result, a large one still works" {
    const Counting = struct {
        child: std.mem.Allocator,
        calls: usize = 0,
        fn a(c: *@This()) std.mem.Allocator {
            return .{ .ptr = c, .vtable = &.{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free } };
        }
        fn alloc(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            c.calls += 1;
            return c.child.rawAlloc(len, al, ra);
        }
        fn free(ctx: *anyopaque, m: []u8, al: std.mem.Alignment, ra: usize) void {
            const c: *@This() = @ptrCast(@alignCast(ctx));
            c.child.rawFree(m, al, ra);
        }
    };
    var c: Counting = .{ .child = testing.allocator };
    const p = try compile(c.a(), "tcp dst port 22 and not ip src net 10.0.0.0/8");
    defer testing.allocator.free(p);
    try testing.expectEqual(@as(usize, 1), c.calls);
    // Past the buffer: the arena takes over, nothing leaks (testing.allocator checks).
    var b: std.ArrayList(u8) = .empty;
    defer b.deinit(testing.allocator);
    for (0..400) |i| {
        if (i != 0) try b.appendSlice(testing.allocator, " or ");
        try b.appendSlice(testing.allocator, "host 10.1.2.3");
    }
    const big = compile(testing.allocator, b.items) catch |e| switch (e) {
        error.FilterTooComplex => return,
        else => return e,
    };
    testing.allocator.free(big);
}

test "compile: the deepest accepted inputs fit in a 64 KiB stack" {
    // A consumer's worker thread may have a small stack: nothing a hostile string can build
    // may recurse deeper than that (the left-deep chain is walked by a loop, parentheses and
    // `not` are capped by the parser).
    const a = testing.allocator;
    var inputs: std.ArrayList([]u8) = .empty;
    defer {
        for (inputs.items) |i| a.free(i);
        inputs.deinit(a);
    }
    // 1: the longest left-deep chain the leaf cap allows, and: or
    for ([_][]const u8{ " and ", " or " }) |sep| {
        var b: std.ArrayList(u8) = .empty;
        for (0..max_insns) |i| {
            if (i != 0) try b.appendSlice(a, sep);
            try b.appendSlice(a, "ip");
        }
        try inputs.append(a, try b.toOwnedSlice(a));
    }
    // 2: the deepest parenthesis nesting accepted, plain and with `not`, each level also a chain
    for ([_][]const u8{ "(", "not (", "(ip and ", "not (ip or " }) |open| {
        for ([_]usize{ Parser.max_depth - 1, Parser.max_depth, Parser.max_depth + 1, 1000 }) |depth| {
            var b: std.ArrayList(u8) = .empty;
            for (0..depth) |_| try b.appendSlice(a, open);
            try b.appendSlice(a, "tcp port 80");
            for (0..depth) |_| try b.appendSlice(a, ")");
            try inputs.append(a, try b.toOwnedSlice(a));
        }
    }
    // 3: `not not not ...` at and past the bound
    for ([_]usize{ Parser.max_depth - 1, Parser.max_depth, Parser.max_depth + 1, 5000 }) |depth| {
        var b: std.ArrayList(u8) = .empty;
        for (0..depth) |_| try b.appendSlice(a, "not ");
        try b.appendSlice(a, "ip");
        try inputs.append(a, try b.toOwnedSlice(a));
    }
    for (inputs.items) |expr| {
        var done = false;
        const th = try std.Thread.spawn(.{ .stack_size = 64 * 1024 }, smallStackCompile, .{ expr, &done });
        th.join();
        try testing.expect(done);
    }
}

test "runLiveMeta answers the kernel's ancillary words from the metadata, and mpls / pppoes stay alone" {
    const a = ancillary_base;
    const words = [_]struct { size: u16, off: u32 }{ .{ .size = op.h, .off = a + 4 }, .{ .size = op.w, .off = a + 8 }, .{ .size = op.b, .off = a + 48 }, .{ .size = op.h, .off = a + 44 } };
    const meta: LiveMeta = .{ .vlan_tci = 0x6007, .pkttype = 4, .ifindex = 77 };
    const want = [_]u32{ 4, 77, 1, 0x6007 };
    for (words, want) |w, v| {
        const prog = [_]BpfInsn{ .{ .code = op.ld | w.size | op.abs, .jt = 0, .jf = 0, .k = w.off }, .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 } };
        try testing.expectEqual(v, runLiveMeta(&prog, "", meta));
        try testing.expectEqual(@as(u32, 0), runLiveMeta(&prog, "", .{})); // no tag, host packet, interface 0
        try testing.expectEqual(@as(u32, 0), run(&prog, "")); // run has no metadata: the load drops the frame
    }
    // mpls / pppoes: the label / session id limits, and only alone.
    for ([_][]const u8{ "mpls 1048576", "pppoes 65536", "mpls 4294967296" }) |e| try testing.expectError(error.Syntax, compile(testing.allocator, e));
    for ([_][]const u8{ "mpls 1048575", "mpls", "pppoes 65535", "pppoes", "pppoed" }) |e| testing.allocator.free(try compile(testing.allocator, e));
    for ([_][]const u8{ "mpls and ip", "ip and mpls", "pppoes and ip", "pppoes 7 or tcp", "not mpls and ip" }) |e| {
        try testing.expectError(error.UnsupportedExpression, compile(testing.allocator, e));
    }
    for ([_][]const u8{ "geneve", "ifname x", "rnr 1", "decnet", "lane" }) |e| try testing.expectError(error.UnsupportedExpression, compile(testing.allocator, e));
}

test "compile: protocol and EtherType names mean their numbers (each table entry used)" {
    const pairs = [_][2][]const u8{
        .{ "ether proto \\ip", "ether proto 0x800" },
        .{ "pppoed", "ether proto 0x8863" },
        .{ "pppoes", "ether proto 0x8864" },
        .{ "mpls", "ether proto 0x8847" },
        .{ "ether proto \\ip6", "ether proto 0x86dd" },
        .{ "ether proto \\arp", "ether proto 0x806" },
        .{ "ether proto \\rarp", "ether proto 0x8035" },
        .{ "ether proto \\lldp", "ether proto 0x88cc" },
        .{ "ip proto \\icmp", "ip proto 1" },
        .{ "ip proto \\tcp", "ip proto 6" },
        .{ "ip proto \\udp", "ip proto 17" },
        .{ "ip proto \\sctp", "ip proto 132" },
        .{ "ip6 proto \\icmp6", "ip6 proto 58" },
        .{ "ip6 proto \\igmp", "ip6 proto 2" },
        .{ "proto \\gre", "proto 47" },
        .{ "ip proto \\esp", "ip proto 50" },
        .{ "ip proto \\ah", "ip proto 51" },
        .{ "ip proto \\pim", "ip proto 103" },
        .{ "ip proto \\vrrp", "ip proto 112" },
        .{ "ip proto \\ospf", "ip proto 89" },
        .{ "tcp[tcpflags] & tcp-fin != 0", "tcp[13] & 1 != 0" },
        .{ "tcp[tcpflags] & tcp-syn != 0", "tcp[13] & 2 != 0" },
        .{ "tcp[tcpflags] & tcp-rst != 0", "tcp[13] & 4 != 0" },
        .{ "tcp[tcpflags] & tcp-push != 0", "tcp[13] & 8 != 0" },
        .{ "tcp[tcpflags] & tcp-ack != 0", "tcp[13] & 16 != 0" },
        .{ "tcp[tcpflags] & tcp-urg != 0", "tcp[13] & 32 != 0" },
        .{ "tcp[tcpflags] & tcp-ece != 0", "tcp[13] & 64 != 0" },
        .{ "tcp[tcpflags] & tcp-cwr != 0", "tcp[13] & 128 != 0" },
        .{ "icmp[icmptype] = icmp-echoreply", "icmp[0] = 0" },
        .{ "icmp[icmptype] = icmp-unreach", "icmp[0] = 3" },
        .{ "icmp[icmptype] = icmp-sourcequench", "icmp[0] = 4" },
        .{ "icmp[icmptype] = icmp-redirect", "icmp[0] = 5" },
        .{ "icmp[icmptype] = icmp-echo", "icmp[0] = 8" },
        .{ "icmp[icmptype] = icmp-routeradvert", "icmp[0] = 9" },
        .{ "icmp[icmptype] = icmp-routersolicit", "icmp[0] = 10" },
        .{ "icmp[icmptype] = icmp-timxceed", "icmp[0] = 11" },
        .{ "icmp[icmptype] = icmp-paramprob", "icmp[0] = 12" },
        .{ "icmp[icmptype] = icmp-tstamp", "icmp[0] = 13" },
        .{ "icmp[icmptype] = icmp-tstampreply", "icmp[0] = 14" },
        .{ "icmp[icmptype] = icmp-ireq", "icmp[0] = 15" },
        .{ "icmp[icmptype] = icmp-ireqreply", "icmp[0] = 16" },
        .{ "icmp[icmptype] = icmp-maskreq", "icmp[0] = 17" },
        .{ "icmp[icmptype] = icmp-maskreply", "icmp[0] = 18" },
        .{ "port 010", "port 8" }, // leading zero: octal
        .{ "port 0x10", "port 16" },
        .{ "port 10 or 11", "port 10 or port 11" }, // a bare value repeats the qualifiers
        .{ "tcp dst port 10 or 11 or 12", "tcp dst port 10 or tcp dst port 11 or tcp dst port 12" },
        .{ "host 10.0.0.1 or 10.0.0.2", "host 10.0.0.1 or host 10.0.0.2" },
        .{ "portrange 30-20", "portrange 20-30" },
    };
    for (pairs) |pr| {
        const a = compile(testing.allocator, pr[0]) catch |e| {
            std.debug.print("name pair: {s}\n", .{pr[0]});
            return e;
        };
        defer testing.allocator.free(a);
        const b = try compile(testing.allocator, pr[1]);
        defer testing.allocator.free(b);
        testing.expectEqualSlices(BpfInsn, b, a) catch |e| {
            std.debug.print("name pair: {s} vs {s}\n", .{ pr[0], pr[1] });
            return e;
        };
    }
}

fn verdicts(prog: []const BpfInsn, out: *std.ArrayList(usize)) !void {
    out.clearRetainingCapacity();
    var r = try pcap.Reader.init(&corpus_pcap);
    var i: usize = 0;
    while (try r.next()) |rec| : (i += 1) {
        if (run(prog, rec.data) != 0) try out.append(testing.allocator, i);
    }
    try testing.expectEqual(@as(usize, 34), i);
}

test "compile: every expression selects exactly the frames tcpdump selects" {
    var got: std.ArrayList(usize) = .empty;
    defer got.deinit(testing.allocator);
    for (oracle) |o| {
        const prog = compile(testing.allocator, o[0]) catch |e| {
            std.debug.print("expression: {s}\n", .{o[0]});
            return e;
        };
        defer testing.allocator.free(prog);
        try verdicts(prog, &got);
        testing.expectEqualSlices(usize, o[1], got.items) catch |e| {
            std.debug.print("expression: {s}\n", .{o[0]});
            return e;
        };
        // An accepting program keeps the whole frame, as libpcap's does.
        try testing.expectEqual(accept_len, prog[prog.len - 2].k);
    }
}

test "run: libpcap's own programs give tcpdump's verdicts too" {
    // The interpreter is what the compiler test above leans on, so it is
    // checked against code the compiler did not write.
    var got: std.ArrayList(usize) = .empty;
    defer got.deinit(testing.allocator);
    for (libpcap_programs) |lp| {
        try verdicts(lp[1], &got);
        const want = for (oracle) |o| {
            if (eql(o[0], lp[0])) break o[1];
        } else unreachable;
        testing.expectEqualSlices(usize, want, got.items) catch |e| {
            std.debug.print("libpcap program: {s}\n", .{lp[0]});
            return e;
        };
    }
}

test "run: kernel semantics at the edges" {
    const ret_a = [_]BpfInsn{
        .{ .code = op.ld | op.len, .jt = 0, .jf = 0, .k = 0 },
        .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 },
    };
    try testing.expectEqual(@as(u32, 5), run(&ret_a, "hello"));
    // A load whose last byte is the frame's last byte succeeds; one byte
    // further drops.
    const at = [_]BpfInsn{
        .{ .code = op.ld | op.h | op.abs, .jt = 0, .jf = 0, .k = 3 },
        .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 },
    };
    try testing.expectEqual(@as(u32, 0x6c6f), run(&at, "hello"));
    try testing.expectEqual(@as(u32, 0), run(&at, "hell"));
    // Division by zero drops; falling off the end drops; an unknown opcode drops.
    const div0 = [_]BpfInsn{
        .{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 7 },
        .{ .code = op.alu | 0x30 | op.k, .jt = 0, .jf = 0, .k = 0 },
        .{ .code = op.ret | op.k, .jt = 0, .jf = 0, .k = 1 },
    };
    try testing.expectEqual(@as(u32, 0), run(&div0, "x"));
    const no_ret = [_]BpfInsn{.{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 1 }};
    try testing.expectEqual(@as(u32, 0), run(&no_ret, "x"));
    const bad = [_]BpfInsn{.{ .code = 0xff, .jt = 0, .jf = 0, .k = 0 }};
    try testing.expectEqual(@as(u32, 0), run(&bad, "x"));
    // A jump past the end drops; scratch memory round-trips; ind + X.
    const far = [_]BpfInsn{
        .{ .code = op.jmp | op.ja, .jt = 0, .jf = 0, .k = 10 },
        .{ .code = op.ret | op.k, .jt = 0, .jf = 0, .k = 1 },
    };
    try testing.expectEqual(@as(u32, 0), run(&far, "x"));
    const mem = [_]BpfInsn{
        .{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 2 },
        .{ .code = 0x02, .jt = 0, .jf = 0, .k = 15 }, // st M[15]
        .{ .code = op.ldx | 0x60, .jt = 0, .jf = 0, .k = 15 }, // ldx M[15]
        .{ .code = op.ld | op.b | op.ind, .jt = 0, .jf = 0, .k = 1 }, // A = P[X+1]
        .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 },
    };
    try testing.expectEqual(@as(u32, 'l'), run(&mem, "hello"));
    const mem16 = [_]BpfInsn{
        .{ .code = 0x02, .jt = 0, .jf = 0, .k = 16 },
        .{ .code = op.ret | op.k, .jt = 0, .jf = 0, .k = 1 },
    };
    try testing.expectEqual(@as(u32, 0), run(&mem16, "x"));
    // ldxb 4*([k]&0xf): the IPv4 header-length idiom.
    const msh = [_]BpfInsn{
        .{ .code = op.ldx | op.b | op.msh, .jt = 0, .jf = 0, .k = 0 },
        .{ .code = op.misc | op.txa, .jt = 0, .jf = 0, .k = 0 },
        .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 },
    };
    try testing.expectEqual(@as(u32, 20), run(&msh, &.{0x45}));
    // jgt is strict, jge is not (A == k is the boundary).
    for ([_]struct { u16, u32, u32 }{ .{ op.jgt, 5, 0 }, .{ op.jgt, 4, 1 }, .{ op.jge, 5, 1 }, .{ op.jge, 6, 0 } }) |c| {
        const cmp = [_]BpfInsn{
            .{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 5 },
            .{ .code = op.jmp | c[0] | op.k, .jt = 0, .jf = 1, .k = c[1] },
            .{ .code = op.ret | op.k, .jt = 0, .jf = 0, .k = 1 },
            .{ .code = op.ret | op.k, .jt = 0, .jf = 0, .k = 0 },
        };
        try testing.expectEqual(c[2], run(&cmp, "x"));
    }
    // ALU with the X register as source (BPF_X): 5 + 3, then 5 - X.
    const alu_x = [_]BpfInsn{
        .{ .code = op.ldx | op.imm, .jt = 0, .jf = 0, .k = 3 },
        .{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 5 },
        .{ .code = op.alu | op.add | op.x, .jt = 0, .jf = 0, .k = 100 },
        .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 },
    };
    try testing.expectEqual(@as(u32, 8), run(&alu_x, "x"));
    try testing.expectEqual(@as(u32, 60), run(&msh, &.{0x4f}));
}

test "run: every ALU and jump opcode, both sources, against hand-worked values" {
    // A = 12 (0b1100), operand 10 (0b1010), each op's result returned.
    const alu = [_]struct { u16, u32 }{
        .{ op.add, 22 },       .{ op.sub, 2 },    .{ 0x20, 120 },    .{ 0x30, 1 },
        .{ 0x90, 2 },          .{ op.@"or", 14 }, .{ op.@"and", 8 }, .{ 0xa0, 6 },
        .{ op.lsh, 12 << 10 }, .{ op.rsh, 0 },
    };
    for (alu) |c| {
        for ([_]u16{ op.k, op.x }) |src| {
            const prog = [_]BpfInsn{
                .{ .code = op.ldx | op.imm, .jt = 0, .jf = 0, .k = 10 },
                .{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 12 },
                .{ .code = op.alu | c[0] | src, .jt = 0, .jf = 0, .k = 10 },
                .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 },
            };
            try testing.expectEqual(c[1], run(&prog, "x"));
        }
    }
    // neg, tax/txa, and a shift by 32 or more (zero, never UB).
    const neg = [_]BpfInsn{
        .{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 1 },
        .{ .code = op.alu | 0x80, .jt = 0, .jf = 0, .k = 0 },
        .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 },
    };
    try testing.expectEqual(@as(u32, 0xffff_ffff), run(&neg, "x"));
    const tax = [_]BpfInsn{
        .{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 7 },
        .{ .code = op.misc | op.tax, .jt = 0, .jf = 0, .k = 0 },
        .{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 0 },
        .{ .code = op.misc | op.txa, .jt = 0, .jf = 0, .k = 0 },
        .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 },
    };
    try testing.expectEqual(@as(u32, 7), run(&tax, "x"));
    for ([_]u16{ op.lsh, op.rsh }) |sh| {
        for ([_]u32{ 32, 40, 0xffff_ffff }) |by| {
            const wide = [_]BpfInsn{
                .{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 7 },
                .{ .code = op.alu | sh | op.k, .jt = 0, .jf = 0, .k = by },
                .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 },
            };
            try testing.expectEqual(@as(u32, 0), run(&wide, "x"));
        }
    }
    // Every conditional jump, both sources, taken and not taken: A = 5.
    const jumps = [_]struct { u16, u32, bool }{
        .{ op.jeq, 5, true }, .{ op.jeq, 6, false }, .{ op.jgt, 4, true },  .{ op.jgt, 5, false },
        .{ op.jge, 5, true }, .{ op.jge, 6, false }, .{ op.jset, 4, true }, .{ op.jset, 2, false },
    };
    for (jumps) |c| {
        for ([_]u16{ op.k, op.x }) |src| {
            const prog = [_]BpfInsn{
                .{ .code = op.ldx | op.imm, .jt = 0, .jf = 0, .k = c[1] },
                .{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 5 },
                .{ .code = op.jmp | c[0] | src, .jt = 0, .jf = 1, .k = c[1] },
                .{ .code = op.ret | op.k, .jt = 0, .jf = 0, .k = 1 },
                .{ .code = op.ret | op.k, .jt = 0, .jf = 0, .k = 0 },
            };
            try testing.expectEqual(@as(u32, if (c[2]) 1 else 0), run(&prog, "x"));
        }
    }
    // What the kernel refuses at attach time drops the frame: ret with the X
    // source bit, a mode the class has no use for, ldx from the packet.
    for ([_]u16{ op.ret | op.x, op.ldx | op.abs, op.ld | op.h | op.imm, op.alu | 0x40 | 0x08 | 0x100 }) |bad| {
        const prog = [_]BpfInsn{
            .{ .code = bad, .jt = 0, .jf = 0, .k = 1 },
            .{ .code = op.ret | op.k, .jt = 0, .jf = 0, .k = 1 },
        };
        try testing.expectEqual(@as(u32, 0), run(&prog, "xxxx"));
    }
    // A scratch slot nothing stored to reads as zero.
    const unset = [_]BpfInsn{
        .{ .code = op.ld | op.imm, .jt = 0, .jf = 0, .k = 9 },
        .{ .code = op.ld | 0x60, .jt = 0, .jf = 0, .k = 3 },
        .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 },
    };
    try testing.expectEqual(@as(u32, 0), run(&unset, "x"));
}

test "compile: malformed and unsupported expressions are refused, never mis-compiled" {
    const cases = .{
        .{ "", error.Syntax },
        .{ "tcp and", error.Syntax },
        .{ "(tcp", error.Syntax },
        .{ "tcp)", error.Syntax },
        .{ "port", error.Syntax },
        .{ "port 70000", error.Syntax },
        .{ "ip host 10.0.0", error.Syntax },
        .{ "ip host 10.0.0.256", error.Syntax },
        .{ "ip net 10.0.0.1/8", error.Syntax }, // host bits set (libpcap refuses too)
        .{ "ip net 10.0.0.0/33", error.Syntax },
        .{ "ether host 00:11:22", error.Syntax },
        .{ "host foo.example", error.UnsupportedExpression }, // no name resolution
        .{ "net foo", error.UnsupportedExpression },
        .{ "net 10.0.0.0/8 mask 255.0.0.0", error.Syntax },
        .{ "net 10.1.2.3.4", error.Syntax },
        .{ "port 1_000", error.Syntax }, // libpcap rejects it; Zig's parseInt would not
        .{ "port +80", error.Syntax },
        .{ "ip[+5] = 1", error.Syntax },
        .{ "ip proto tcp", error.Syntax }, // libpcap needs `\\tcp`
        .{ "ip6 protochain 6", error.UnsupportedExpression },
        .{ "vlan 5000", error.Syntax },
        .{ "ip6 net 2001:db8::/16", error.Syntax }, // host bits set (libpcap refuses too)
        .{ "ip6 host 2001:db8::/32", error.Syntax },
        .{ "ip6 net 2001:db8::/129", error.Syntax },
        .{ "ip host 2001:db8::1", error.Syntax },
        .{ "ip6 host 10.0.0.1", error.Syntax },
        .{ "ip[1:3] = 1", error.Syntax },
        .{ "ip[1:2 = 1", error.Syntax },
        .{ "ip[70000] = 1", error.Syntax },
        .{ "ip[1] ~ 1", error.Syntax },
        .{ "ip[1] =", error.Syntax },
        .{ "ip[1] & = 1", error.Syntax },
        .{ "len", error.Syntax },
        .{ "less", error.Syntax },
        .{ "portrange 1", error.Syntax },
        .{ "portrange 1-70000", error.Syntax },
        .{ "gateway 10.0.0.1", error.UnsupportedExpression },
        .{ "foo[1] = 1", error.UnsupportedExpression },
        .{ "ip src 10.0.0.1", error.UnsupportedExpression },
        .{ "ether foo 1", error.UnsupportedExpression },
        .{ "tcp tcp", error.Syntax },
    };
    inline for (cases) |c| {
        testing.expectError(c[1], compile(testing.allocator, c[0])) catch |e| {
            std.debug.print("expression: '{s}'\n", .{c[0]});
            return e;
        };
    }
}

test "compile: nesting and size are bounded" {
    // Parser.max_depth + 1 nested `not`s exceed the parser's depth bound…
    try testing.expectError(error.FilterTooComplex, compile(testing.allocator, strRepeat("not ", Parser.max_depth + 1) ++ "ip"));
    // …Parser.max_depth do not.
    const ok = try compile(testing.allocator, strRepeat("not ", Parser.max_depth) ++ "ip");
    testing.allocator.free(ok);
    // A long disjunction needs jumps past 255 instructions: widened through
    // `ja`, as libpcap does, up to the kernel's 4096 instructions.
    const long = try compile(testing.allocator, "port 1" ++ strRepeat(" or port 1", 20));
    testing.allocator.free(long);
    // Past 4096 instructions it is refused, never truncated.
    try testing.expectError(error.FilterTooComplex, compile(testing.allocator, "port 1" ++ strRepeat(" or port 1", 200)));
    // The accepting/dropping tail is ret #262144 / ret #0, as libpcap's.
    const p = try compile(testing.allocator, "arp");
    defer testing.allocator.free(p);
    try testing.expectEqual(@as(usize, 4), p.len);
    try testing.expectEqual(@as(u32, 0), p[3].k);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}

fn advanceBody() void {
    if (advance(u32, 1, std.math.maxInt(u32)) != std.math.maxInt(u32)) @panic("not saturated");
    if (advance(u32, 7, 3) != 10) @panic("plain add changed");
    if (advance(usize, 5, 2) != 7) @panic("plain add changed");
}

test "advance: a jump offset cannot overflow the program counter, even a 32-bit one (sweep RS2)" {
    try @import("sweep_test.zig").expectSurvives(advanceBody);
}

test "gen: a 1000-term chain is cut off by the depth bound before any code is emitted (sweep REV-RS-1)" {
    // 1000 x `arp` = 2000 instructions: under max_insns, so only the depth
    // bound (or the later jump-distance check in `finish`) can refuse it. The
    // seam: drive Parser + Gen by hand; the bound fires on the way DOWN the
    // left spine, so nothing has been emitted, while `finish`'s refusal would
    // come after all 2000 instructions.
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const unit = " and arp";
    const src = try a.alloc(u8, 3 + unit.len * 999);
    @memcpy(src[0..3], "arp");
    for (0..999) |i| @memcpy(src[3 + i * unit.len ..][0..unit.len], unit);
    // Since 2026-11-03 jumps past 255 instructions are widened through `ja`,
    // so this chain compiles (it was FilterTooComplex before) and still
    // decides correctly.
    const prog = try compile(testing.allocator, src);
    defer testing.allocator.free(prog);
    try testing.expect(prog.len > 2000);
    var arp_frame: [14]u8 = @splat(0);
    arp_frame[12] = 0x08;
    arp_frame[13] = 0x06;
    try testing.expectEqual(accept_len, run(prog, &arp_frame));
    arp_frame[13] = 0x00;
    try testing.expectEqual(@as(u32, 0), run(prog, &arp_frame));
}

test "gen: the depth cap sits exactly at max_gen_depth on every edge kind (sweep audit GS-A1)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var p: Parser = .{ .a = a, .lex = .{ .src = "arp" } };
    const leaf = try p.parseExpr();
    // and[0], and[1], or[0], or[1], not: a chain of n wrappers puts the leaf at depth n.
    // Only the `not` chain adds no leaves per level, so only it reaches the
    // depth cap before the 4096-instruction cap (the others hit that first).
    inline for (.{4}) |kind| {
        for ([_]usize{ Gen.max_gen_depth, Gen.max_gen_depth + 1 }) |n| {
            var cur = leaf;
            for (0..n) |_| {
                const nd = try a.create(Node);
                nd.* = switch (kind) {
                    0 => .{ .@"and" = .{ cur, leaf } },
                    1 => .{ .@"and" = .{ leaf, cur } },
                    2 => .{ .@"or" = .{ cur, leaf } },
                    3 => .{ .@"or" = .{ leaf, cur } },
                    else => .{ .not = cur },
                };
                cur = nd;
            }
            var g: Gen = .{ .a = a };
            const t_label = try g.newLabel();
            const f_label = try g.newLabel();
            if (n == Gen.max_gen_depth) {
                try g.gen(cur, t_label, f_label, 0);
            } else {
                try testing.expectError(error.FilterTooComplex, g.gen(cur, t_label, f_label, 0));
            }
        }
    }
}

test "Parser: the leaf cap sits exactly at max_insns terms (sweep audit GS-A2)" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    inline for (.{ max_insns, max_insns + 1 }) |n| {
        const src = try a.alloc(u8, 2 + 7 * (n - 1));
        @memcpy(src[0..2], "ip");
        for (0..n - 1) |i| @memcpy(src[2 + i * 7 ..][0..7], " and ip");
        var p: Parser = .{ .a = a, .lex = .{ .src = src } };
        if (n == max_insns) {
            _ = try p.parseExpr();
        } else {
            try testing.expectError(error.FilterTooComplex, p.parseExpr());
        }
    }
}

fn mk(code: u16, k: u32) BpfInsn {
    return .{ .code = code, .jt = 0, .jf = 0, .k = k };
}

test "run: the semantics the kernel showed (SO_ATTACH_FILTER on Linux 7.0, ldx/lsh/ld ind probes)" {
    const frame = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d";
    // X + k wraps in 32 bits (X = 0xffffffff, k = 2 loads from offset 1), and so does X + k past the end.
    const wrap = [_]BpfInsn{
        mk(op.ldx | op.imm, 0xffffffff),
        mk(op.ld | op.w | op.ind, 2),
        mk(op.ret | op.a, 0),
    };
    try testing.expectEqual(@as(u32, 0x01020304), run(&wrap, frame));
    // A register shift count is masked to five bits: 1 << 32 is 1, 1 << 33 is 2, 0x80000000 >> 63 is 1.
    for ([_]struct { u16, u32, u32, u32 }{
        .{ op.lsh, 1, 32, 1 },
        .{ op.lsh, 1, 33, 2 },
        .{ op.lsh, 1, 16, 1 << 16 }, // bit 4 of the count matters: masked to 5 bits, not 4
        .{ op.lsh, 1, 48, 1 << 16 },
        .{ op.rsh, 0x80000000, 32, 0x80000000 },
        .{ op.rsh, 0x80000000, 63, 1 },
    }) |c| {
        const prog = [_]BpfInsn{
            mk(op.ld | op.imm, c[1]),
            mk(op.ldx | op.imm, c[2]),
            mk(op.alu | c[0] | op.x, 0),
            mk(op.ret | op.a, 0),
        };
        try testing.expectEqual(c[3], run(&prog, frame));
    }
    // A constant shift of 32 or more is refused at attach time; `run` drops.
    const kshift = [_]BpfInsn{ mk(op.ld | op.imm, 1), mk(op.alu | op.lsh | op.k, 32), mk(op.ret | op.a, 0) };
    try testing.expectEqual(@as(u32, 0), run(&kshift, frame));
    try testing.expectError(error.Shift, validate(&kshift));
    // A negative load offset (ancillary, header-relative) is the kernel's; `run` drops it.
    const anc = [_]BpfInsn{ mk(op.ld | op.w | op.abs, ancillary_base), mk(op.ret | op.k, 1) };
    try testing.expectEqual(@as(u32, 0), run(&anc, frame));
    try validate(&anc);
    try testing.expect(usesAncillary(&anc));
    try testing.expect(!usesAncillary(&kshift));
}

test "validate: what the kernel refuses at attach time, and nothing else" {
    const ok = [_]BpfInsn{ mk(op.ld | op.imm, 7), mk(0x02, 15), mk(op.ld | 0x60, 15), mk(op.ret | op.a, 0) };
    try validate(&ok);
    try testing.expectError(error.Length, validate(&.{}));
    try testing.expectError(error.NoReturn, validate(&.{mk(op.ld | op.imm, 1)}));
    try testing.expectError(error.Opcode, validate(&.{ mk(0xff, 0), mk(op.ret | op.k, 0) }));
    try testing.expectError(error.Opcode, validate(&.{ mk(op.ret | op.x, 0), mk(op.ret | op.k, 0) }));
    try testing.expectError(error.Scratch, validate(&.{ mk(0x02, 16), mk(op.ret | op.k, 0) }));
    try testing.expectError(error.DivZero, validate(&.{ mk(op.alu | 0x30 | op.k, 0), mk(op.ret | op.k, 0) }));
    try validate(&.{ mk(op.alu | 0x30 | op.x, 0), mk(op.ret | op.k, 0) }); // by X is a runtime drop, not a refusal
    try testing.expectError(error.Uninitialised, validate(&.{ mk(op.ld | 0x60, 3), mk(op.ret | op.k, 0) }));
    // Stored on one path only: refused (the kernel intersects the paths).
    const one_path = [_]BpfInsn{
        .{ .code = op.jmp | op.jeq | op.k, .jt = 0, .jf = 1, .k = 1 },
        mk(0x02, 3),
        mk(op.ld | 0x60, 3),
        mk(op.ret | op.k, 0),
    };
    try testing.expectError(error.Uninitialised, validate(&one_path));
    try testing.expectError(error.Jump, validate(&.{ .{ .code = op.jmp | op.jeq | op.k, .jt = 5, .jf = 0, .k = 0 }, mk(op.ret | op.k, 0) }));
    try testing.expectError(error.Jump, validate(&.{ mk(op.jmp | op.ja, 1), mk(op.ret | op.k, 0) }));
    // Ancillary: SKF_AD_PROTOCOL is fine; one past the window's words is not.
    try validate(&.{ mk(op.ld | op.w | op.abs, ancillary_base), mk(op.ret | op.k, 0) });
    try testing.expectError(error.Ancillary, validate(&.{ mk(op.ld | op.w | op.abs, 0xfffffffe), mk(op.ret | op.k, 0) }));
    try testing.expectError(error.Ancillary, validate(&.{ mk(op.ld | op.w | op.abs, ancillary_base + 2), mk(op.ret | op.k, 0) }));
    // A load below the window (SKF_NET_OFF) is valid.
    try validate(&.{ mk(op.ld | op.w | op.abs, 0xfff00000), mk(op.ret | op.k, 0) });
    // 4097 instructions.
    var big: [max_insns + 1]BpfInsn = @splat(mk(op.ld | op.imm, 0));
    big[max_insns] = mk(op.ret | op.k, 0);
    try testing.expectError(error.Length, validate(&big));
    try validate(big[1..]);
}

test "compile: every program it emits passes the kernel's attach-time checks" {
    for (oracle) |o| {
        const prog = compile(testing.allocator, o[0]) catch |e| {
            std.debug.print("expression: {s}\n", .{o[0]});
            return e;
        };
        defer testing.allocator.free(prog);
        validate(prog) catch |e| {
            std.debug.print("expression: {s}\n", .{o[0]});
            return e;
        };
    }
}

test "compile: vlan is the in-packet tag by default, plus the kernel's ancillary words on request" {
    const plain = try compile(testing.allocator, "vlan 5");
    defer testing.allocator.free(plain);
    try testing.expect(!usesAncillary(plain));
    const live = try compileOpts(testing.allocator, "vlan 5", .{ .vlan_ancillary = true });
    defer testing.allocator.free(live);
    try testing.expect(usesAncillary(live));
    try validate(live);
    // In a savefile the in-packet form decides; the live form also does when the tag is still in the frame.
    var tagged: [20]u8 = @splat(0);
    tagged[12] = 0x81;
    tagged[14] = 0x00;
    tagged[15] = 0x05;
    try testing.expect(run(plain, &tagged) != 0);
    tagged[15] = 0x06;
    try testing.expectEqual(@as(u32, 0), run(plain, &tagged));
    // Combined, the run-time form: the program validates, reads the kernel's words and keeps M[0].
    const comb = try compileOpts(testing.allocator, "vlan and ip", .{ .vlan_ancillary = true });
    defer testing.allocator.free(comb);
    try validate(comb);
    try testing.expect(usesAncillary(comb));
    // `vlan and ip` looks inside the tag: the offline form shifts what follows by four bytes.
    const inner = try compile(testing.allocator, "vlan and ip");
    defer testing.allocator.free(inner);
    var q: [40]u8 = @splat(0);
    q[12] = 0x81;
    q[16] = 0x08; // ethertype 0x0800 after the tag
    try testing.expect(run(inner, &q) != 0);
    q[16] = 0x86;
    q[17] = 0xdd;
    try testing.expectEqual(@as(u32, 0), run(inner, &q));
}

test "compile: || and && are or and and" {
    const a = try compile(testing.allocator, "tcp || udp && port 53");
    defer testing.allocator.free(a);
    const b = try compile(testing.allocator, "tcp or udp and port 53");
    defer testing.allocator.free(b);
    try testing.expectEqualSlices(u8, std.mem.sliceAsBytes(b), std.mem.sliceAsBytes(a));
}

test "compile: and/or share one precedence level, left to right (pcap-filter(7))" {
    var udp53: [64]u8 = @splat(0);
    udp53[12] = 0x08; // IPv4 UDP port 53
    udp53[14] = 0x45;
    udp53[23] = 17;
    udp53[35] = 53;
    var tcp22: [64]u8 = @splat(0);
    tcp22[12] = 0x08;
    tcp22[14] = 0x45;
    tcp22[23] = 6;
    tcp22[37] = 22;
    // `tcp or udp and port 53` is `(tcp or udp) and port 53`: the tcp frame on port 22 does not pass.
    const p = try compile(testing.allocator, "tcp or udp and port 53");
    defer testing.allocator.free(p);
    try testing.expect(run(p, &udp53) != 0);
    try testing.expectEqual(@as(u32, 0), run(p, &tcp22));
    const q = try compile(testing.allocator, "tcp or (udp and port 53)");
    defer testing.allocator.free(q);
    try testing.expect(run(q, &tcp22) != 0);
}

const run_diff = @import("testdata/run_diff.zig");

fn decodeProg(hex_prog: []const u8, out: []BpfInsn) ![]BpfInsn {
    var bytes: [8 * 64]u8 = undefined;
    const n = hex_prog.len / 2;
    _ = try std.fmt.hexToBytes(bytes[0..n], hex_prog);
    for (0..n / 8) |i| {
        const b = bytes[i * 8 ..][0..8];
        out[i] = .{
            .code = std.mem.readInt(u16, b[0..2], .little),
            .jt = b[2],
            .jf = b[3],
            .k = std.mem.readInt(u32, b[4..8], .little),
        };
    }
    return out[0 .. n / 8];
}

test "run: random kernel-valid programs return what libpcap's interpreter returns (tools/gen_run_diff.py)" {
    var frames: [run_diff.frames.len][]u8 = undefined;
    var storage: [run_diff.frames.len][128]u8 = undefined;
    for (run_diff.frames, 0..) |h, i| frames[i] = try std.fmt.hexToBytes(&storage[i], h);
    var nonzero: usize = 0;
    var distinct: [64]u32 = undefined;
    var n_distinct: usize = 0;
    for (run_diff.cases, 0..) |c, ci| {
        if (!c.libpcap_valid) continue;
        var buf: [64]BpfInsn = undefined;
        const prog = try decodeProg(c.prog, &buf);
        // The generator's programs are kernel-valid: `validate` must agree.
        validate(prog) catch |e| {
            std.debug.print("case {d}: validate said {t}\n", .{ ci, e });
            return e;
        };
        for (frames, c.verdicts) |f, want| {
            const got = run(prog, f);
            testing.expectEqual(want, got) catch |e| {
                std.debug.print("case {d}\n", .{ci});
                return e;
            };
            if (want != 0) nonzero += 1;
            if (n_distinct < distinct.len and std.mem.indexOfScalar(u32, distinct[0..n_distinct], want) == null) {
                distinct[n_distinct] = want;
                n_distinct += 1;
            }
        }
    }
    // The table must exercise the interpreter, not agree on all-zero verdicts.
    try testing.expect(nonzero >= 100);
    try testing.expect(n_distinct >= 20);
}

const validate_kernel = @import("testdata/validate_kernel.zig");

test "validate agrees with the Linux kernel's attach verdict on 210 programs (tools/gen_validate_kernel.py)" {
    for (validate_kernel.cases) |c| {
        var buf: [64]BpfInsn = undefined;
        const prog = try decodeProg(c.prog, &buf);
        const ok = if (validate(prog)) true else |_| false;
        testing.expectEqual(c.kernel_ok, ok) catch |e| {
            std.debug.print("program: {s} ({s})\n", .{ c.name, c.prog });
            return e;
        };
    }
}

// ── fuzz: `validate` and `run` on arbitrary bytes read as a program ──────────

const garbage_seeds = [_][]const u8{
    testkit.fuzz.seed("\x20\x00\x00\x00\x0c\x00\x00\x00\x15\x00\x00\x01\x00\x08\x00\x00\x06\x00\x00\x00\xff\xff\x00\x00\x06\x00\x00\x00\x00\x00\x00\x00"),
    testkit.fuzz.seed("\x20\x00\x00\x00\x00\xf0\xff\xff\x06\x00\x00\x00\x01\x00\x00\x00"),
    testkit.fuzz.seed("\x02\x00\x00\x00\x03\x00\x00\x00\x60\x00\x00\x00\x03\x00\x00\x00\x16\x00\x00\x00\x00\x00\x00\x00"),
    testkit.fuzz.seed(""),
};
const GarbageMark = fz.Marker(enum { rejected, valid, ancillary });

test "fuzz: validate and run never panic on arbitrary bytes as a program" {
    try testing.fuzz({}, fuzzGarbageSmith, .{ .corpus = &garbage_seeds });
}

test "fuzz driver: RAWSOCK_FUZZ (validate)" {
    try fz.fuzz_driver.run(fuzzGarbage, .{ .prefix = "RAWSOCK_FUZZ", .name = "rawsock-validate" });
}

test "fuzz harness: validate, 300 seeds, reaches every outcome" {
    try GarbageMark.reach(fuzzGarbage, "rawsock-validate", 300);
}

fn fuzzGarbageSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzGarbage, smith, script[0..n]);
}

fn fuzzGarbage(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [8 * 40]u8 = undefined;
    const len: usize = fz.drawInput(S, smith, &buf, &garbage_seeds);
    var prog: [40]BpfInsn = undefined;
    const n = len / 8;
    for (0..n) |i| {
        const b = buf[i * 8 ..][0..8];
        prog[i] = .{ .code = std.mem.readInt(u16, b[0..2], .little), .jt = b[2], .jf = b[3], .k = std.mem.readInt(u32, b[4..8], .little) };
    }
    const p = prog[0..n];
    if (validate(p)) {
        // A program the kernel would accept terminates and returns without a panic on any frame.
        const frame = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20 };
        _ = run(p, &frame);
        _ = run(p, frame[0..3]);
        GarbageMark.mark(.valid);
        if (usesAncillary(p)) GarbageMark.mark(.ancillary);
    } else |_| {
        // Never-validated garbage is still safe to run: it drops or returns, it does not panic.
        _ = run(p, "garbage frame bytes");
        GarbageMark.mark(.rejected);
    }
}

// ── fuzz: `run` against a second, independent model ─────────────────────────
//
// Random programs, valid by construction (no scratch memory, shifts below 32,
// constant divisors nonzero, jumps forward and inside, a final ret), over a
// random frame: `validate` must accept them, `run` must terminate, and it
// must agree with `refRun`, a plain kernel-semantics reading written here
// separately (u64 offsets, explicit case per opcode).

fn refRun(prog: []const BpfInsn, frame: []const u8) u32 {
    var a: u32 = 0;
    var x: u32 = 0;
    var pc: usize = 0;
    while (pc < prog.len) {
        const i = prog[pc];
        pc += 1;
        const code = i.code;
        const cls = code & 7;
        if (cls == 0 or cls == 1) { // ld / ldx
            var v: u32 = 0;
            const mode = code & 0xe0;
            const size: usize = switch (code & 0x18) {
                0x00 => 4,
                0x08 => 2,
                else => 1,
            };
            if (mode == 0x00) {
                v = i.k;
            } else if (mode == 0x80) {
                v = @intCast(frame.len);
            } else if (mode == 0xa0) {
                if (i.k >= frame.len) return 0;
                v = (frame[i.k] & 0xf) * 4;
            } else {
                const off: u64 = if (mode == 0x40) @as(u64, x +% i.k) else i.k;
                if (off + size > frame.len) return 0;
                var acc: u32 = 0;
                for (0..size) |j| acc = acc << 8 | frame[@intCast(off + j)];
                v = acc;
            }
            if (cls == 0) a = v else x = v;
        } else if (cls == 4) { // alu
            const src = if (code & 8 != 0) x else i.k;
            switch (code & 0xf0) {
                0x00 => a +%= src,
                0x10 => a -%= src,
                0x20 => a *%= src,
                0x30 => {
                    if (src == 0) return 0;
                    a /= src;
                },
                0x40 => a |= src,
                0x50 => a &= src,
                0x60 => a <<= @intCast(src & 31),
                0x70 => a >>= @intCast(src & 31),
                0x80 => a = 0 -% a,
                0x90 => {
                    if (src == 0) return 0;
                    a %= src;
                },
                0xa0 => a ^= src,
                else => return 0,
            }
        } else if (cls == 5) { // jmp
            if (code & 0xf0 == 0) {
                pc += i.k;
                continue;
            }
            const src = if (code & 8 != 0) x else i.k;
            const t = switch (code & 0xf0) {
                0x10 => a == src,
                0x20 => a > src,
                0x30 => a >= src,
                else => a & src != 0,
            };
            pc += if (t) i.jt else i.jf;
        } else if (cls == 6) {
            return if (code & 0x18 == 0x10) a else i.k;
        } else if (cls == 7) {
            if (code & 0x80 != 0) a = x else x = a;
        }
    }
    return 0;
}

const run_codes = [_]u16{
    op.ld | op.w | op.abs,     op.ld | op.h | op.abs,     op.ld | op.b | op.abs,   op.ld | op.w | op.ind,    op.ld | op.h | op.ind,
    op.ld | op.b | op.ind,     op.ld | op.w | op.imm,     op.ldx | op.w | op.imm,  op.ld | op.w | op.len,    op.ldx | op.w | op.len,
    op.ldx | op.b | op.msh,    op.misc | op.tax,          op.misc | op.txa,        op.alu | op.add | op.k,   op.alu | op.add | op.x,
    op.alu | op.sub | op.k,    op.alu | op.sub | op.x,    op.alu | 0x20 | op.k,    op.alu | 0x20 | op.x,     op.alu | 0x30 | op.k,
    op.alu | 0x30 | op.x,      op.alu | 0x90 | op.k,      op.alu | 0x90 | op.x,    op.alu | op.@"or" | op.k, op.alu | op.@"or" | op.x,
    op.alu | op.@"and" | op.k, op.alu | op.@"and" | op.x, op.alu | 0xa0 | op.k,    op.alu | 0xa0 | op.x,     op.alu | op.lsh | op.k,
    op.alu | op.lsh | op.x,    op.alu | op.rsh | op.k,    op.alu | op.rsh | op.x,  op.alu | 0x80,            op.jmp | op.ja,
    op.jmp | op.jeq | op.k,    op.jmp | op.jeq | op.x,    op.jmp | op.jgt | op.k,  op.jmp | op.jgt | op.x,   op.jmp | op.jge | op.k,
    op.jmp | op.jge | op.x,    op.jmp | op.jset | op.k,   op.jmp | op.jset | op.x,
};

const run_seeds = [_][]const u8{
    testkit.fuzz.seed("\x00\x01\x02\x03\x06\x04\x05\x06\x0e\x00\x00\x04\x27\x00\x10\x00\x21\x00\x00\x01\x28\x00\x00\x00\x45\x00\x00\x00\x08\x00\x45\x00\x00\x1e\x00\x01\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x01\x0a\x00\x00\x02"),
    testkit.fuzz.seed("\x0a\x00\x00\x03\x1c\x00\x00\x00\x0b\x00\x01\x00\x20\x20\x20\x20\xff\xff\xff\xff\xff\xff\xff\xff"),
    testkit.fuzz.seed(""),
};

const RunMark = fz.Marker(enum { dropped, accepted, jumped });

test "fuzz: run agrees with a separate model on random valid programs, validate accepts them" {
    try testing.fuzz({}, fuzzRunSmith, .{ .corpus = &run_seeds });
}

test "fuzz driver: RAWSOCK_FUZZ (run)" {
    try fz.fuzz_driver.run(fuzzRun, .{ .prefix = "RAWSOCK_FUZZ", .name = "rawsock-run" });
}

test "fuzz harness: run, 300 seeds, reaches every outcome" {
    try RunMark.reach(fuzzRun, "rawsock-run", 300);
}

fn fuzzRunSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzRun, smith, script[0..n]);
}

fn fuzzRun(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    _ = gpa;
    var buf: [256]u8 = undefined;
    const len: usize = fz.drawInput(S, smith, &buf, &run_seeds);
    var prog: [33]BpfInsn = undefined;
    const n_ins: usize = @min(len / 4, 32);
    for (0..n_ins) |i| {
        const b = buf[i * 4 ..][0..4];
        const code = run_codes[b[0] % run_codes.len];
        var k: u32 = b[1];
        if (b[2] & 3 == 0) k = k << 24 | 0xffffff; // large and negative-looking offsets too
        var jt: u8 = 0;
        var jf: u8 = 0;
        const room: u32 = @intCast(n_ins - 1 - i); // instructions after this one, before the final ret: all are targets
        if (code & 7 == op.jmp) {
            if (code == op.jmp | op.ja) {
                k = b[1] % (room + 1);
            } else {
                jt = @intCast(b[2] % (room + 1));
                jf = @intCast(b[3] % (room + 1));
            }
        }
        // The kernel refuses a negative absolute offset in the ancillary window that is not an SKF_AD_* word.
        if (code & 7 == op.ld and code & 0xe0 == op.abs and k >= ancillary_base and !ancillaryIndex(k)) k = 0xfff00000;
        if ((code == op.alu | 0x30 | op.k or code == op.alu | 0x90 | op.k) and k == 0) k = 1;
        if (code == op.alu | op.lsh | op.k or code == op.alu | op.rsh | op.k) k %= 32;
        prog[i] = .{ .code = code, .jt = jt, .jf = jf, .k = k };
    }
    prog[n_ins] = .{ .code = op.ret | op.a, .jt = 0, .jf = 0, .k = 0 };
    const p = prog[0 .. n_ins + 1];
    try validate(p);
    const frame = buf[@min(len, n_ins * 4)..len];
    const got = run(p, frame);
    try testing.expectEqual(refRun(p, frame), got);
    if (got == 0) RunMark.mark(.dropped) else RunMark.mark(.accepted);
    for (p) |ins_| if (ins_.code == op.jmp | op.ja) {
        RunMark.mark(.jumped);
        break;
    };
}

// ── fuzz: the expression compiler and the interpreter ────────────────────────
//
// `compile` takes operator text. The property that needs no oracle: a program
// that compiled is well-formed (ends in two `ret`s, every jump lands inside it),
// `run` terminates on it for any frame, and it composes — `E` and `E and E`
// and `E or E` give one verdict, and `not (E)` never accepts a frame `E`
// accepts (an out-of-range load drops under BOTH, which is why this is not
// "the opposite verdict").

const testkit = @import("testkit");
const fz = @import("fuzz_test.zig");
const FilterMark = fz.Marker(enum { syntax, unsupported, too_complex, accepted, dropped, composed, live_form, new_link });

const filter_seeds = [_][]const u8{
    testkit.fuzz.seed("tcp dst port 22 and not ip src net 10.0.0.0/8"),
    testkit.fuzz.seed("host 10.0.0.1 or ip6 net 2001:db8::/32"),
    testkit.fuzz.seed("udp portrange 5000-5400 and greater 60"),
    testkit.fuzz.seed("ip[6:2] & 0x1fff = 0 and tcp[13] & 2 != 0"),
    testkit.fuzz.seed("(arp or rarp) and ether[0] & 1 = 1"),
    testkit.fuzz.seed("len <= 100 and not multicast and src host 192.0.2.7"),
    testkit.fuzz.seed("less 64 or ether dst ff:ff:ff:ff:ff:ff"),
    testkit.fuzz.seed("port 1 or port 1 or port 1 or port 1 or port 1 or port 1 or port 1 or port 1 or port 1 or port 1 or port 1 or port 1"), // long jumps
    testkit.fuzz.seed("not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not not ip"), // past the nesting bound
    testkit.fuzz.seed("vlan"),
    testkit.fuzz.seed("vlan 5 and tcp port 80 or ip6 and vlan"), // the live form needs a vlan AND other primitives
    testkit.fuzz.seed("ip and vlan and vlan 7 and udp[2:2] = 53"),
    testkit.fuzz.seed("ip6 proto 17 or arp host 10.0.0.1 or ether proto 0x800"), // link-specific refusals
    testkit.fuzz.seed("inbound and ifindex 2 or mpls 5 or pppoes 7 or outbound"), // kernel metadata and the alone-only shifters
    testkit.fuzz.seed(""),
};

/// Three frames the harness runs every program over: an ARP request, an IPv4
/// TCP SYN, an IPv6 UDP datagram.
fn fuzzFrames(out: *[5][80]u8, lens: *[5]usize) void {
    out.* = @splat(@splat(0));
    const arp_req = root.arp.buildRequest(.{ 2, 0, 0, 0, 0, 1 }, .{ 10, 0, 0, 1 }, .{ 10, 0, 0, 9 });
    @memset(out[0][0..6], 0xff);
    @memcpy(out[0][6..12], &[_]u8{ 2, 0, 0, 0, 0, 1 });
    @memcpy(out[0][12..42], arp_req[12..42]);
    lens[0] = 42;
    @memcpy(out[1][0..12], &[_]u8{ 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1 });
    @memcpy(out[1][12..34], &[_]u8{ 0x08, 0x00, 0x45, 0, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2 });
    @memcpy(out[1][34..54], &[_]u8{ 0x04, 0xd2, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0 });
    lens[1] = 54;
    @memcpy(out[2][0..12], &[_]u8{ 0x33, 0x33, 0, 0, 0, 1, 2, 0, 0, 0, 0, 1 });
    @memcpy(out[2][12..22], &[_]u8{ 0x86, 0xdd, 0x60, 0, 0, 0, 0, 8, 17, 64 });
    @memcpy(out[2][22..38], &[_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5 });
    @memcpy(out[2][38..54], &[_]u8{ 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
    @memcpy(out[2][54..62], &[_]u8{ 0x14, 0xe9, 0x14, 0xe9, 0, 8, 0, 0 });
    lens[2] = 62;
    // An 802.1Q-tagged TCP SYN (vlan 5) and a QinQ (7 over 5) UDP datagram.
    @memcpy(out[3][0..12], &[_]u8{ 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1 });
    @memcpy(out[3][12..18], &[_]u8{ 0x81, 0x00, 0x00, 0x05, 0x08, 0x00 });
    @memcpy(out[3][18..38], &[_]u8{ 0x45, 0, 0, 40, 0, 1, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2 });
    @memcpy(out[3][38..58], &[_]u8{ 0x04, 0xd2, 0, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0 });
    lens[3] = 58;
    @memcpy(out[4][0..12], &[_]u8{ 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1 });
    @memcpy(out[4][12..22], &[_]u8{ 0x81, 0x00, 0x00, 0x07, 0x81, 0x00, 0x00, 0x05, 0x08, 0x00 });
    @memcpy(out[4][22..42], &[_]u8{ 0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2 });
    @memcpy(out[4][42..50], &[_]u8{ 0x00, 0x35, 0x13, 0x88, 0, 8, 0, 0 });
    lens[4] = 50;
}

fn wellFormed(prog: []const BpfInsn) !void {
    try testing.expect(prog.len >= 2 and prog.len <= max_insns);
    try testing.expectEqual(op.ret | op.k, prog[prog.len - 2].code);
    try testing.expectEqual(op.ret | op.k, prog[prog.len - 1].code);
    // The kernel's own attach-time checks: every jump lands inside, scratch is stored before it is read.
    try validate(prog);
}

test "fuzz: filter.compile never panics, and what it compiles is well-formed and composes" {
    try testing.fuzz({}, fuzzFilterSmith, .{ .corpus = &filter_seeds });
}

test "fuzz driver: RAWSOCK_FUZZ (filter)" {
    try fz.fuzz_driver.run(fuzzFilter, .{ .prefix = "RAWSOCK_FUZZ", .name = "rawsock-filter" });
}

test "fuzz harness: filter, 600 seeds, reaches every outcome" {
    try FilterMark.reach(fuzzFilter, "rawsock-filter", 600);
}

fn fuzzFilterSmith(_: void, smith: *std.testing.Smith) !void {
    var script: [fz.script_cap]u8 = undefined;
    const n = smith.slice(&script);
    try fz.runFrom(fuzzFilter, smith, script[0..n]);
}

fn fuzzFilter(comptime S: type, smith: *S, gpa: std.mem.Allocator) anyerror!void {
    var buf: [512]u8 = undefined;
    const len: usize = fz.drawInput(S, smith, &buf, &filter_seeds);
    const expr = buf[0..len];
    // Every link type and both vlan forms: one byte picks the options.
    const sel = smith.valueRangeAtMost(u8, 0, 11);
    // `vlan` is Ethernet-only: an expression naming it gets the Ethernet link and the
    // live form half of the time (so the run-time form is reached by more than chance).
    const has_vlan = std.mem.find(u8, expr, "vlan") != null;
    const opts: Options = if (has_vlan) .{ .link = .ethernet, .vlan_ancillary = sel % 2 == 0 } else .{ .link = switch (sel % 6) {
        0 => .ethernet,
        1 => .linux_sll,
        2 => .raw,
        3 => .linux_sll2,
        4 => .bsd_null,
        else => .bsd_loop,
    }, .vlan_ancillary = sel >= 6 };
    const prog = compileOpts(gpa, expr, opts) catch |e| switch (e) {
        error.Syntax => return FilterMark.mark(.syntax),
        error.UnsupportedExpression => return FilterMark.mark(.unsupported),
        error.FilterTooComplex => return FilterMark.mark(.too_complex),
        error.OutOfMemory => return e,
    };
    defer gpa.free(prog);
    try wellFormed(prog);
    if (opts.link == .linux_sll2 or opts.link == .bsd_null or opts.link == .bsd_loop) FilterMark.mark(.new_link);
    if (opts.vlan_ancillary) for (prog) |i| if (i.code == (op.ldx | op.w | op.mem)) {
        FilterMark.mark(.live_form);
        break;
    };

    var frames: [5][80]u8 = undefined;
    var lens: [5]usize = undefined;
    fuzzFrames(&frames, &lens);

    // `E and E` is not `E` when E contains `vlan`: every primitive after a vlan
    // is shifted by four bytes, and the second copy comes after the first. The
    // composition properties are skipped for those (substring `vlan`).
    const sticky = std.mem.find(u8, expr, "vlan") != null;

    // E and E, E or E, and not (E).
    var and_buf: [2 * 512 + 16]u8 = undefined;
    var or_buf: [2 * 512 + 16]u8 = undefined;
    const variants = [_][]const u8{
        std.fmt.bufPrint(&and_buf, "({s}) and ({s})", .{ expr, expr }) catch "",
        std.fmt.bufPrint(&or_buf, "({s}) or ({s})", .{ expr, expr }) catch "",
    };
    var neg_buf: [512 + 16]u8 = undefined;
    const neg_text = std.fmt.bufPrint(&neg_buf, "not ({s})", .{expr}) catch "";
    var composed = false;
    for (variants) |v| {
        if (v.len == 0) continue;
        if (sticky) break;
        const p2 = compileOpts(gpa, v, opts) catch continue;
        defer gpa.free(p2);
        try wellFormed(p2);
        composed = true;
        for (frames, lens) |f, l| try testing.expectEqual(run(prog, f[0..l]) != 0, run(p2, f[0..l]) != 0);
    }
    if (neg_text.len != 0 and !sticky) if (compileOpts(gpa, neg_text, opts)) |pn| {
        defer gpa.free(pn);
        try wellFormed(pn);
        composed = true;
        for (frames, lens) |f, l| try testing.expect(!(run(prog, f[0..l]) != 0 and run(pn, f[0..l]) != 0));
    } else |_| {};
    if (composed) FilterMark.mark(.composed);

    var any = false;
    for (frames, lens) |f, l| {
        // Truncated copies drop or accept without a read past the end.
        for ([_]usize{ l, l / 2, 0 }) |cut| any = (run(prog, f[0..cut]) != 0) or any;
    }
    if (any) FilterMark.mark(.accepted) else FilterMark.mark(.dropped);
}

// ── delta audit 2026-11-04: tests for the mutants the suite did not kill ─────

test "Scratch: bump inside the buffer, the arena past it; resize, remap and free follow the owner" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var buf: [64]u8 = undefined;
    var s: Scratch = .{ .fba = .init(&buf), .next = arena.allocator() };
    const a = s.allocator();
    // Exactly the buffer fits; one byte more spills to the arena.
    const exact = try a.alloc(u8, 64);
    try testing.expect(s.fba.ownsSlice(exact));
    const spill = try a.alloc(u8, 1);
    try testing.expect(!s.fba.ownsSlice(spill));
    a.free(exact);
    a.free(spill);
    s.fba.reset();
    // The buffer's last allocation grows in place, by resize and by remap.
    const small = try a.alloc(u8, 16);
    try testing.expect(s.fba.ownsSlice(small));
    try testing.expect(a.resize(small, 32));
    const grown = small.ptr[0..32];
    const moved = a.remap(grown, 48) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@intFromPtr(small.ptr), @intFromPtr(moved.ptr));
    try testing.expect(s.fba.ownsSlice(moved));
    // An arena allocation is the arena's: the buffer is never asked about it.
    const big = try a.alloc(u8, 200);
    try testing.expect(!s.fba.ownsSlice(big));
    // Asking for more of a slice the buffer does not own goes to the arena, never to the buffer's
    // assert; the arena may decline.
    if (a.resize(big, 220)) a.free(big.ptr[0..220]) else a.free(big);
    const big2 = try a.alloc(u8, 200);
    if (a.remap(big2, 100)) |m| a.free(m) else a.free(big2);
}

test "compile: the vlan re-parse frees the first pass's arena after a compile that spilled past the scratch buffer" {
    // 400 terms put the tree far past the 8 KiB buffer, so the arena (testing.allocator,
    // which reports a leak) holds the first pass when the live form re-parses.
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    try text.appendSlice(testing.allocator, "vlan");
    for (0..400) |_| try text.appendSlice(testing.allocator, " and ip");
    const prog = try compileOpts(testing.allocator, text.items, .{ .vlan_ancillary = true });
    defer testing.allocator.free(prog);
    try validate(prog);
    try testing.expect(prog.len > 1000);
}

test "compile: the live form stores the run-time shift only when something reads it" {
    for ([_][]const u8{ "vlan", "vlan 5" }) |e| {
        const p = try compileOpts(testing.allocator, e, .{ .vlan_ancillary = true });
        defer testing.allocator.free(p);
        for (p) |i| try testing.expect(i.code != op.st);
    }
    const p = try compileOpts(testing.allocator, "vlan and ip", .{ .vlan_ancillary = true });
    defer testing.allocator.free(p);
    var stores: usize = 0;
    for (p) |i| stores += @intFromBool(i.code == op.st);
    try testing.expect(stores >= 1);
}

test "genChain: a spine of every length around the on-stack buffer compiles and decides" {
    var arp: [14]u8 = @splat(0);
    arp[12] = 0x08;
    arp[13] = 0x06;
    var other = arp;
    other[13] = 0x00;
    for ([_][]const u8{ " or ", " and " }) |sep| {
        for (1..21) |n| {
            var text: std.ArrayList(u8) = .empty;
            defer text.deinit(testing.allocator);
            try text.appendSlice(testing.allocator, "arp");
            for (0..n) |_| {
                try text.appendSlice(testing.allocator, sep);
                try text.appendSlice(testing.allocator, "arp");
            }
            const p = try compile(testing.allocator, text.items);
            defer testing.allocator.free(p);
            try validate(p);
            try testing.expectEqual(accept_len, run(p, &arp));
            try testing.expectEqual(@as(u32, 0), run(p, &other));
        }
    }
}

test "finish: a jump of 255 stays short, of 256 is widened, on the true side and on the false side; 4096 instructions fit" {
    var arp: [14]u8 = @splat(0);
    arp[12] = 0x08;
    arp[13] = 0x06;
    arp[0] = 0xff; // ether[0] & 1 = 1 holds too
    var other = arp;
    other[13] = 0x00;
    other[0] = 0x00;
    var saw255_t = false;
    var saw255_f = false;
    var saw_4096 = false;
    // Leaves of 2 instructions ("arp") and a last one of 2 or 3 shift the parity of every distance.
    for ([_][]const u8{ " or ", " and " }) |sep| {
        for ([_][]const u8{ "arp", "ether[0] & 1 = 1" }) |last| {
            var k: usize = 1;
            while (k < 1500) : (k += if (k < 300) 1 else 37) {
                var text: std.ArrayList(u8) = .empty;
                defer text.deinit(testing.allocator);
                for (0..k) |_| {
                    try text.appendSlice(testing.allocator, "arp");
                    try text.appendSlice(testing.allocator, sep);
                }
                try text.appendSlice(testing.allocator, last);
                const p = compile(testing.allocator, text.items) catch |e| {
                    try testing.expectEqual(error.FilterTooComplex, e);
                    continue;
                };
                defer testing.allocator.free(p);
                try validate(p);
                if (k < 300) {
                    try testing.expectEqual(accept_len, run(p, &arp));
                    try testing.expectEqual(@as(u32, 0), run(p, &other));
                }
                for (p) |i| {
                    if (i.code & 7 != 5 or i.code == (op.jmp | op.ja)) continue;
                    if (i.jt == 255) saw255_t = true;
                    if (i.jf == 255) saw255_f = true;
                }
                if (p.len == max_insns) saw_4096 = true;
            }
        }
    }
    try testing.expect(saw255_t and saw255_f);
    // The sweep is coarse above 300 leaves: search the neighbourhood of the cap one leaf at a time.
    var k: usize = 1300;
    while (k < 1420 and !saw_4096) : (k += 1) {
        for ([_][]const u8{ "arp", "ether[0] & 1 = 1" }) |last| {
            var text: std.ArrayList(u8) = .empty;
            defer text.deinit(testing.allocator);
            for (0..k) |_| try text.appendSlice(testing.allocator, "arp or ");
            try text.appendSlice(testing.allocator, last);
            const p = compile(testing.allocator, text.items) catch continue;
            defer testing.allocator.free(p);
            if (p.len == max_insns) saw_4096 = true;
        }
    }
    try testing.expect(saw_4096);
}

test "compile: offsets, addresses and masks at their limits" {
    const a = testing.allocator;
    for ([_][]const u8{ "ether[65535] = 1", "ether[65535:1] = 1" }) |e| a.free(try compile(a, e));
    try testing.expectError(error.Syntax, compile(a, "ether[65536] = 1"));
    // Five octets are not an address, and `net 10 mask M` is not libpcap syntax.
    try testing.expectError(error.Syntax, compile(a, "host 1.2.3.4.5"));
    try testing.expectError(error.Syntax, compile(a, "ip host 1.2.3.4.5"));
    try testing.expectError(error.Syntax, compile(a, "net 10 mask 255.0.0.0"));
    a.free(try compile(a, "net 10.0 mask 255.255.0.0"));
    // The prefix limits: /32 and /0 are fine, /33 is not (v6: /128, /129).
    a.free(try compile(a, "net 1.2.3.4/32"));
    a.free(try compile(a, "net 0.0.0.0/0"));
    try testing.expectError(error.Syntax, compile(a, "net 1.2.3.4/33"));
    a.free(try compile(a, "ip6 net ::/128"));
    try testing.expectError(error.Syntax, compile(a, "ip6 net ::/129"));
}

test "validate and usesAncillary: the ancillary window and its edges" {
    const base = ancillary_base;
    // SKF_AD_OFF + 60 is the last ancillary word; +64 (SKF_AD_MAX) and a misaligned index are refused.
    try validate(&.{ mk(op.ld | op.w | op.abs, base + 60), mk(op.ret | op.k, 0) });
    try testing.expectError(error.Ancillary, validate(&.{ mk(op.ld | op.w | op.abs, base + 64), mk(op.ret | op.k, 0) }));
    try testing.expectError(error.Ancillary, validate(&.{ mk(op.ld | op.w | op.abs, base + 2), mk(op.ret | op.k, 0) }));
    // The lowest negative offset is a negative offset.
    try testing.expect(usesAncillary(&.{mk(op.ld | op.b | op.abs, 0x80000000)}));
    try testing.expect(!usesAncillary(&.{mk(op.ld | op.b | op.abs, 0x7fffffff)}));
}

test "validate: after a jump every scratch slot counts as stored again (the kernel's mask is reset), a ret keeps the mask" {
    // jeq with both targets past the next instruction: that instruction is dead and reads M[3].
    var dead = [_]BpfInsn{ mk(op.jmp | op.jeq | op.k, 0), mk(op.ld | 0x60, 3), mk(op.ret | op.k, 0), mk(op.ret | op.k, 0) };
    dead[0].jt = 1;
    dead[0].jf = 1;
    try validate(&dead);
    // The same read straight after a ret (no jump in between) is on a path that never stored.
    try testing.expectError(error.Uninitialised, validate(&.{ mk(op.ret | op.k, 0), mk(op.ld | 0x60, 3), mk(op.ret | op.k, 0) }));
}

test "run: scratch slots 16 and up drop the frame, stx stores, a load at the last bytes drops, msh takes the low nibble" {
    const frame = "\x55\x01\x02\x03\x04\x05\x06\x07";
    for ([_]u32{ 16, 17, 0xffffffff }) |k| {
        for ([_]u16{ op.ld | 0x60, op.ldx | 0x60, 0x02, 0x03 }) |code| {
            const prog = [_]BpfInsn{ mk(code, k), mk(op.ret | op.k, 7) };
            try testing.expectEqual(@as(u32, 0), run(&prog, frame));
        }
    }
    const stx = [_]BpfInsn{ mk(op.ldx | op.imm, 77), mk(0x03, 2), mk(op.ld | 0x60, 2), mk(op.ret | op.a, 0) };
    try testing.expectEqual(@as(u32, 77), run(&stx, frame));
    try validate(&stx);
    // Frame of 8 bytes: a word at 4 is the last, at 5 is three bytes (drop); a half at 7 is one byte (drop).
    try testing.expectEqual(@as(u32, 0x04050607), run(&.{ mk(op.ld | op.w | op.abs, 4), mk(op.ret | op.a, 0) }, frame));
    try testing.expectEqual(@as(u32, 0), run(&.{ mk(op.ld | op.w | op.abs, 5), mk(op.ret | op.k, 1) }, frame));
    try testing.expectEqual(@as(u32, 0), run(&.{ mk(op.ld | op.h | op.abs, 7), mk(op.ret | op.k, 1) }, frame));
    try testing.expectEqual(@as(u32, 0), run(&.{ mk(op.ld | op.b | op.abs, 8), mk(op.ret | op.k, 1) }, frame));
    try testing.expectEqual(@as(u32, 7), run(&.{ mk(op.ld | op.b | op.abs, 7), mk(op.ret | op.a, 0) }, frame));
    // 0x55: (0x55 & 0x0f) * 4 = 20; a wider mask would give 84.
    try testing.expectEqual(@as(u32, 20), run(&.{ mk(op.ldx | op.b | op.msh, 0), mk(op.misc | op.txa, 0), mk(op.ret | op.a, 0) }, frame));
}
