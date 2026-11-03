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
//! `tcpdump -d` (black-box; no libpcap source read) and pinned by a
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
//!   the second tag. `Options.vlan_ancillary` adds the kernel's
//!   `SKF_AD_VLAN_TAG*` words for a live socket (the kernel strips the tag
//!   there); that form is alone-only (libpcap shifts later offsets by a
//!   run-time amount, `ldx M[1]`, which this compiler has no form for) and is
//!   kernel-only: `run` drops negative-offset loads (see `usesAncillary`).
//! * `Options.link`: `.ethernet` (default), `.linux_sll` (a `tcpdump -i any`
//!   savefile: offsets +2) and `.raw` (no link header: the IP version nibble
//!   replaces the EtherType; `arp` is refused, as in libpcap).
//!
//! Not supported (`error.UnsupportedExpression`): host and network *names*
//! and `gateway` (the resolver, /etc/ethers), `ip broadcast` / `ip multicast`
//! (the interface netmask), service names for ports, computed offsets
//! (`ip[ip[0] & 0xf]`), `protochain`, MPLS, link types beyond Ethernet, Linux
//! SLL and raw IP (DLT_NULL, 802.11, PPP...). The generated code is not
//! optimised: longer than libpcap's, never different in meaning. A program
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
            op.ld | op.w | op.abs => A = load32(frame, i.k) orelse return 0,
            op.ld | op.h | op.abs => A = load16(frame, i.k) orelse return 0,
            op.ld | op.b | op.abs => A = load8(frame, i.k) orelse return 0,
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
    k: u32,
};

const Node = union(enum) {
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
};

pub const Link = enum { ethernet, linux_sll, raw };

/// `compile` with options (see `Options`).
pub fn compileOpts(gpa: std.mem.Allocator, expr: []const u8, opts: Options) CompileError![]BpfInsn {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var p: Parser = .{ .a = arena.allocator(), .lex = .{ .src = expr }, .opts = opts, .shift = switch (opts.link) {
        .ethernet => 0,
        .linux_sll => 2,
        .raw => -14,
    } };
    const ast = try p.parseExpr();
    if (try p.lex.peek() != null) return error.Syntax;
    // `vlan` shifts every later offset in libpcap (`vlan and ip` looks inside
    // the tag); this compiler does not, so `vlan` is only the whole expression.
    // The ancillary form tells the kernel's metadata from the packet's tag, and
    // libpcap then shifts later offsets by a run-time amount (`ldx M[1]`) that
    // this compiler has no X-relative form for: alone only.
    if (p.saw_vlan and opts.vlan_ancillary and p.leaves != p.vlan_leaves) return error.UnsupportedExpression;

    var g: Gen = .{ .a = arena.allocator() };
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

    /// Recursion bound for `gen`: the parser builds `a and b and c ...` as a
    /// left-deep chain without touching its own depth counter, and a program
    /// whose chain is this long cannot compile anyway (the first false-jump
    /// must reach the end within 255 instructions). See sweep REV-RS-1.
    const max_gen_depth = max_insns;

    fn gen(g: *Gen, n: *const Node, t: usize, f: usize, depth: usize) CompileError!void {
        if (depth > max_gen_depth) return error.FilterTooComplex;
        switch (n.*) {
            .@"and" => |ab| {
                const mid = try g.newLabel();
                try g.gen(ab[0], mid, f, depth + 1);
                try g.place(mid);
                try g.gen(ab[1], t, f, depth + 1);
            },
            .@"or" => |ab| {
                const mid = try g.newLabel();
                try g.gen(ab[0], t, mid, depth + 1);
                try g.place(mid);
                try g.gen(ab[1], t, f, depth + 1);
            },
            .not => |inner| try g.gen(inner, f, t, depth + 1),
            .t => |c| {
                if (c.len) {
                    try g.emit(.{ .insn = .{ .code = op.ld | op.w | op.len, .jt = 0, .jf = 0, .k = 0 } });
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
    /// bound stops `a and a and a ...` (a left-deep chain `gen` recurses down)
    /// from growing the tree without limit. See sweep RS1.
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
    /// The qualifier tokens of the last `host`/`net`/`port`/`portrange`
    /// primitive: `tcp dst port 80 or 443` repeats `tcp dst port`.
    last: [6][]const u8 = undefined,
    n_last: usize = 0,

    /// Parenthesis/`not` nesting bound: recursion is per token, so a hostile
    /// expression cannot exhaust the stack.
    const max_depth = 64;

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
        // In the packet: an 802.1Q / 802.1ad / QinQ ethertype, then the id.
        const t8100 = try p.etherType(0x8100);
        const t88a8 = try p.etherType(0x88a8);
        const t9100 = try p.etherType(0x9100);
        var inpkt = try p.both(.@"or", t8100, try p.both(.@"or", t88a8, t9100));
        if (id) |v| inpkt = try p.both(.@"and", inpkt, try p.t(.{ .size = .h, .off = 14, .mask = 0xfff, .k = v }));
        var res = inpkt;
        if (p.opts.vlan_ancillary) {
            // The kernel stripped it: SKF_AD_VLAN_TAG_PRESENT, then SKF_AD_VLAN_TAG.
            var anc = try p.t(.{ .size = .b, .off = ancillary_base + 48, .k = 1 });
            if (id) |v| anc = try p.both(.@"and", anc, try p.t(.{ .size = .h, .off = ancillary_base + 44, .mask = 0xfff, .k = v }));
            res = try p.both(.@"or", anc, inpkt);
        }
        p.saw_vlan = true;
        p.vlan_leaves += p.leaves - before;
        // libpcap shifts the primitives that follow by the tag's four bytes.
        p.shift += 4;
        return res;
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
        if (p.opts.link == .raw) return p.ipAddr(dir, addr, pl); // no ARP on a raw-IP link
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
            try p.ethernetOnly();
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
        if (p.opts.link == .raw) {
            // No EtherType: the IP version nibble. Anything else never matches
            // in libpcap's eyes ("expression rejects all packets").
            return switch (ty) {
                0x0800 => p.t(.{ .size = .b, .off = 0, .mask = 0xf0, .fixed = true, .k = 0x40 }),
                0x86dd => p.t(.{ .size = .b, .off = 0, .mask = 0xf0, .fixed = true, .k = 0x60 }),
                else => error.UnsupportedExpression,
            };
        }
        return p.t(.{ .size = .h, .off = 12, .k = ty });
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
    // 65 nested `not`s exceed the parser's depth bound…
    try testing.expectError(error.FilterTooComplex, compile(testing.allocator, strRepeat("not ", 65) ++ "ip"));
    // …64 do not.
    const ok = try compile(testing.allocator, strRepeat("not ", 64) ++ "ip");
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
    // The ancillary form cannot be combined (libpcap shifts by a run-time amount there).
    try testing.expectError(error.UnsupportedExpression, compileOpts(testing.allocator, "vlan and ip", .{ .vlan_ancillary = true }));
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
const FilterMark = fz.Marker(enum { syntax, unsupported, too_complex, accepted, dropped, composed });

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
    const sel = smith.valueRangeAtMost(u8, 0, 5);
    const opts: Options = .{ .link = switch (sel % 3) {
        0 => .ethernet,
        1 => .linux_sll,
        else => .raw,
    }, .vlan_ancillary = sel >= 3 };
    const prog = compileOpts(gpa, expr, opts) catch |e| switch (e) {
        error.Syntax => return FilterMark.mark(.syntax),
        error.UnsupportedExpression => return FilterMark.mark(.unsupported),
        error.FilterTooComplex => return FilterMark.mark(.too_complex),
        error.OutOfMemory => return e,
    };
    defer gpa.free(prog);
    try wellFormed(prog);

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
