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
//! expr      := term  { ("or" | "||") term }
//! term      := factor { ("and" | "&&") factor }
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
//! Not supported (`error.UnsupportedExpression`): bare `host`/`net` (libpcap
//! also matches ARP/RARP addresses there), IPv6 addresses, `vlan` (on Linux the
//! kernel strips the tag before the filter runs; libpcap uses ancillary loads),
//! `portrange`, `len`, byte-offset expressions (`ip[6:2] & 0x1fff`), `gateway`,
//! `broadcast`/`multicast`. The generated code is not optimised — it is longer
//! than libpcap's, never different in meaning.

const std = @import("std");
const root = @import("root.zig");
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
/// end of the program or a jump past it drops it. Supports the instruction set
/// `compile` and `etherTypeFilter` emit plus the rest of classic BPF's ALU,
/// jumps, scratch memory and `len`; anything else drops.
pub fn run(prog: []const BpfInsn, frame: []const u8) u32 {
    var A: u32 = 0;
    var X: u32 = 0;
    var mem: [16]u32 = @splat(0);
    var pc: usize = 0;
    // Terminates: every instruction advances `pc` by at least one and no
    // classic-BPF jump goes backwards (offsets are unsigned), so the loop runs
    // at most `prog.len` times.
    while (pc < prog.len) {
        const i = prog[pc];
        pc += 1;
        const class = i.code & 0x07;
        switch (class) {
            op.ld, op.ldx => {
                const size = i.code & 0x18;
                const mode = i.code & 0xe0;
                var v: u32 = undefined;
                switch (mode) {
                    op.imm => v = i.k,
                    op.len => v = @intCast(@min(frame.len, std.math.maxInt(u32))),
                    0x60 => { // mem
                        if (i.k >= mem.len) return 0;
                        v = mem[i.k];
                    },
                    op.abs, op.ind => {
                        const base: u64 = if (mode == op.ind) X else 0;
                        v = load(frame, base + i.k, size) orelse return 0;
                    },
                    op.msh => {
                        if (class != op.ldx) return 0;
                        const byte = load(frame, i.k, op.b) orelse return 0;
                        v = (byte & 0x0f) * 4;
                    },
                    else => return 0,
                }
                if (class == op.ld) A = v else X = v;
            },
            0x02 => { // st
                if (i.k >= mem.len) return 0;
                mem[i.k] = A;
            },
            0x03 => { // stx
                if (i.k >= mem.len) return 0;
                mem[i.k] = X;
            },
            op.alu => {
                const src = if (i.code & op.x != 0) X else i.k;
                switch (i.code & 0xf0) {
                    op.add => A +%= src,
                    op.sub => A -%= src,
                    0x20 => A *%= src,
                    0x30 => {
                        if (src == 0) return 0;
                        A /= src;
                    },
                    0x90 => {
                        if (src == 0) return 0;
                        A %= src;
                    },
                    op.@"or" => A |= src,
                    op.@"and" => A &= src,
                    0xa0 => A ^= src,
                    op.lsh => A = if (src >= 32) 0 else A << @intCast(src),
                    op.rsh => A = if (src >= 32) 0 else A >> @intCast(src),
                    0x80 => A = 0 -% A,
                    else => return 0,
                }
            },
            op.jmp => {
                const jop = i.code & 0xf0;
                if (jop == op.ja) {
                    pc += i.k;
                    continue;
                }
                const src = if (i.code & op.x != 0) X else i.k;
                const taken = switch (jop) {
                    op.jeq => A == src,
                    op.jgt => A > src,
                    op.jge => A >= src,
                    op.jset => A & src != 0,
                    else => return 0,
                };
                pc += if (taken) i.jt else i.jf;
            },
            op.ret => return if (i.code & 0x18 == op.a) A else i.k,
            op.misc => {
                if (i.code & 0xf8 == op.txa) A = X else X = A;
            },
            else => return 0,
        }
    }
    return 0;
}

fn load(frame: []const u8, at: u64, size: u16) ?u32 {
    const n: u64 = switch (size) {
        op.w => 4,
        op.h => 2,
        op.b => 1,
        else => return null,
    };
    if (at > frame.len or frame.len - at < n) return null;
    const p = frame[@intCast(at)..];
    return switch (size) {
        op.w => std.mem.readInt(u32, p[0..4], .big),
        op.h => std.mem.readInt(u16, p[0..2], .big),
        else => p[0],
    };
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
    kind: enum { eq, set } = .eq,
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
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var p: Parser = .{ .a = arena.allocator(), .lex = .{ .src = expr } };
    const ast = try p.parseExpr();
    if (try p.lex.peek() != null) return error.Syntax;

    var g: Gen = .{ .a = arena.allocator() };
    const t_label = try g.newLabel();
    const f_label = try g.newLabel();
    try g.gen(ast, t_label, f_label);
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

    fn gen(g: *Gen, n: *const Node, t: usize, f: usize) CompileError!void {
        switch (n.*) {
            .@"and" => |ab| {
                const mid = try g.newLabel();
                try g.gen(ab[0], mid, f);
                try g.place(mid);
                try g.gen(ab[1], t, f);
            },
            .@"or" => |ab| {
                const mid = try g.newLabel();
                try g.gen(ab[0], t, mid);
                try g.place(mid);
                try g.gen(ab[1], t, f);
            },
            .not => |inner| try g.gen(inner, f, t),
            .t => |c| {
                if (c.ind) try g.emit(.{ .insn = .{ .code = op.ldx | op.b | op.msh, .jt = 0, .jf = 0, .k = 14 } });
                try g.emit(.{ .insn = .{
                    .code = op.ld | @intFromEnum(c.size) | (if (c.ind) op.ind else op.abs),
                    .jt = 0,
                    .jf = 0,
                    .k = c.off,
                } });
                if (c.mask) |m| try g.emit(.{ .insn = .{ .code = op.alu | op.@"and" | op.k, .jt = 0, .jf = 0, .k = m } });
                try g.emit(.{
                    .insn = .{ .code = op.jmp | (if (c.kind == .eq) op.jeq else op.jset) | op.k, .jt = 0, .jf = 0, .k = c.k },
                    .jt = t,
                    .jf = f,
                });
            },
        }
    }

    fn finish(g: *Gen, gpa: std.mem.Allocator) CompileError![]BpfInsn {
        const out = try gpa.alloc(BpfInsn, g.code.items.len);
        errdefer gpa.free(out);
        for (g.code.items, 0..) |p, pc| {
            out[pc] = p.insn;
            if (p.jt) |l| out[pc].jt = try rel(g.labels.items[l].?, pc);
            if (p.jf) |l| out[pc].jf = try rel(g.labels.items[l].?, pc);
        }
        return out;
    }

    fn rel(target: usize, pc: usize) CompileError!u8 {
        // Labels are only ever placed after the jumps that use them.
        std.debug.assert(target > pc);
        const d = target - pc - 1;
        if (d > 255) return error.FilterTooComplex;
        return @intCast(d);
    }
};

const Lexer = struct {
    src: []const u8,
    pos: usize = 0,
    peeked: ?[]const u8 = null,

    fn peek(l: *Lexer) CompileError!?[]const u8 {
        if (l.peeked == null) l.peeked = l.scan();
        return l.peeked;
    }

    fn next(l: *Lexer) CompileError!?[]const u8 {
        const t = try l.peek();
        l.peeked = null;
        return t;
    }

    fn scan(l: *Lexer) ?[]const u8 {
        while (l.pos < l.src.len and std.ascii.isWhitespace(l.src[l.pos])) l.pos += 1;
        if (l.pos == l.src.len) return null;
        const start = l.pos;
        const c = l.src[l.pos];
        if (c == '(' or c == ')' or (c == '!' and !(l.pos + 1 < l.src.len and l.src[l.pos + 1] == '='))) {
            l.pos += 1;
            return l.src[start..l.pos];
        }
        if ((c == '&' or c == '|') and l.pos + 1 < l.src.len and l.src[l.pos + 1] == c) {
            l.pos += 2;
            return l.src[start..l.pos];
        }
        while (l.pos < l.src.len) : (l.pos += 1) {
            const d = l.src[l.pos];
            if (std.ascii.isWhitespace(d) or d == '(' or d == ')' or d == '!' or d == '&' or d == '|') break;
        }
        if (l.pos == start) {
            // A lone '&' or '|' (or "!=" which this subset has no use for).
            l.pos += 1;
            return l.src[start..l.pos];
        }
        return l.src[start..l.pos];
    }
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const Parser = struct {
    a: std.mem.Allocator,
    lex: Lexer,
    depth: usize = 0,

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

    fn t(p: *Parser, c: Test) !*const Node {
        return p.node(.{ .t = c });
    }

    fn parseExpr(p: *Parser) CompileError!*const Node {
        var left = try p.parseTerm();
        while (try p.lex.peek()) |tok| {
            if (!eql(tok, "or") and !eql(tok, "||")) break;
            _ = try p.lex.next();
            left = try p.both(.@"or", left, try p.parseTerm());
        }
        return left;
    }

    fn parseTerm(p: *Parser) CompileError!*const Node {
        var left = try p.parseFactor();
        while (try p.lex.peek()) |tok| {
            if (!eql(tok, "and") and !eql(tok, "&&")) break;
            _ = try p.lex.next();
            left = try p.both(.@"and", left, try p.parseFactor());
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
        return p.primitive(tok);
    }

    fn expectWord(p: *Parser) CompileError![]const u8 {
        return (try p.lex.next()) orelse error.Syntax;
    }

    fn primitive(p: *Parser, first: []const u8) CompileError!*const Node {
        if (eql(first, "ether")) {
            const what = try p.expectWord();
            if (eql(what, "proto")) return p.etherType(try p.number(u16));
            const dir: Dir = if (eql(what, "src")) .src else if (eql(what, "dst")) .dst else if (eql(what, "host")) .either else return error.UnsupportedExpression;
            const mac = root.parseHwaddr(try p.expectWord()) orelse return error.Syntax;
            return p.etherAddr(dir, mac);
        }
        if (eql(first, "arp")) return p.etherType(0x0806);
        if (eql(first, "ip6")) return p.etherType(0x86dd);
        if (eql(first, "icmp")) return p.ipProto(1);
        if (eql(first, "ip")) {
            const nxt = (try p.lex.peek()) orelse return p.etherType(0x0800);
            if (eql(nxt, "proto")) {
                _ = try p.lex.next();
                return p.ipProto(try p.number(u8));
            }
            var dir: Dir = .either;
            if (eql(nxt, "src") or eql(nxt, "dst")) {
                _ = try p.lex.next();
                dir = if (eql(nxt, "src")) .src else .dst;
            }
            const kind = (try p.lex.peek()) orelse return error.Syntax;
            if (eql(kind, "host")) {
                _ = try p.lex.next();
                const addr = parseIpv4(try p.expectWord()) orelse return error.Syntax;
                return p.ipAddr(dir, addr, 32);
            }
            if (eql(kind, "net")) {
                _ = try p.lex.next();
                const w = try p.expectWord();
                const slash = std.mem.indexOfScalar(u8, w, '/') orelse return error.Syntax;
                const addr = parseIpv4(w[0..slash]) orelse return error.Syntax;
                const plen = std.fmt.parseInt(u8, w[slash + 1 ..], 10) catch return error.Syntax;
                if (plen > 32) return error.Syntax;
                // libpcap refuses host bits outside the mask ("non-network
                // bits set in"); so does this.
                const m = maskOf(plen);
                if (std.mem.readInt(u32, &addr, .big) & ~m != 0) return error.Syntax;
                return p.ipAddr(dir, addr, plen);
            }
            if (dir != .either) return error.UnsupportedExpression;
            return p.etherType(0x0800);
        }
        var proto: ?u8 = null;
        var tok = first;
        if (eql(tok, "tcp") or eql(tok, "udp") or eql(tok, "sctp")) {
            proto = if (eql(tok, "tcp")) 6 else if (eql(tok, "udp")) 17 else 132;
            const nxt = (try p.lex.peek()) orelse return p.transport(proto.?);
            if (!eql(nxt, "src") and !eql(nxt, "dst") and !eql(nxt, "port")) return p.transport(proto.?);
            tok = (try p.lex.next()).?;
        }
        var dir: Dir = .either;
        if (eql(tok, "src") or eql(tok, "dst")) {
            dir = if (eql(tok, "src")) .src else .dst;
            tok = try p.expectWord();
        }
        if (eql(tok, "port")) {
            const n = try p.number(u16);
            if (proto) |pr| return p.port(pr, dir, n);
            return p.both(.@"or", try p.port(6, dir, n), try p.both(.@"or", try p.port(17, dir, n), try p.port(132, dir, n)));
        }
        return error.UnsupportedExpression;
    }

    fn number(p: *Parser, comptime T: type) CompileError!T {
        const w = try p.expectWord();
        return std.fmt.parseInt(T, w, 0) catch error.Syntax;
    }

    const Dir = enum { src, dst, either };

    fn etherType(p: *Parser, ty: u16) !*const Node {
        return p.t(.{ .size = .h, .off = 12, .k = ty });
    }

    fn etherAddr(p: *Parser, dir: Dir, mac: [6]u8) CompileError!*const Node {
        if (dir == .either) return p.both(.@"or", try p.etherAddr(.src, mac), try p.etherAddr(.dst, mac));
        const base: u32 = if (dir == .src) 6 else 0;
        return p.both(
            .@"and",
            try p.t(.{ .size = .w, .off = base + 2, .k = std.mem.readInt(u32, mac[2..6], .big) }),
            try p.t(.{ .size = .h, .off = base, .k = std.mem.readInt(u16, mac[0..2], .big) }),
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

    fn port(p: *Parser, pr: u8, dir: Dir, n: u16) CompileError!*const Node {
        // IPv6: ports straight after the 40-byte header, next header = pr.
        const v6 = try p.both(.@"and", try p.both(.@"and", try p.etherType(0x86dd), try p.t(.{ .size = .b, .off = 20, .k = pr })), try p.ports(dir, n, false));
        // IPv4: protocol, first fragment only, ports after IHL.
        const not_frag = try p.node(.{ .not = try p.t(.{ .size = .h, .off = 20, .kind = .set, .k = 0x1fff }) });
        const v4 = try p.both(.@"and", try p.both(.@"and", try p.ipProto(pr), not_frag), try p.ports(dir, n, true));
        return p.both(.@"or", v6, v4);
    }

    fn ports(p: *Parser, dir: Dir, n: u16, v4: bool) CompileError!*const Node {
        // v4: [x + 14] / [x + 16]; v6: [54] / [56].
        const base: u32 = if (v4) 14 else 54;
        const src = try p.t(.{ .size = .h, .off = base, .ind = v4, .k = n });
        const dst = try p.t(.{ .size = .h, .off = base + 2, .ind = v4, .k = n });
        return switch (dir) {
            .src => src,
            .dst => dst,
            .either => p.both(.@"or", src, dst),
        };
    }

    fn ipAddr(p: *Parser, dir: Dir, addr: [4]u8, plen: u8) CompileError!*const Node {
        if (dir == .either) return p.both(.@"or", try p.ipAddr(.src, addr, plen), try p.ipAddr(.dst, addr, plen));
        const m = maskOf(plen);
        const cmp = try p.t(.{
            .size = .w,
            .off = if (dir == .src) 26 else 30,
            .mask = if (plen == 32) null else m,
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
    "d4c3b2a10200040000000000000000000000040001000000e8030000000000002a0000002a000000ffffffffffff0011" ++
        "22334455080600010800060400010011223344550a0000010000000000000a000002e9030000000000002c0000002c00" ++
        "000002000000000900112233445508004500001e00010000400600000a000001c000020504d20050000000007878ea03" ++
        "0000000000002c0000002c00000000112233445502000000000908004500001e0001000040060000c00002050a000001" ++
        "005004d2000000007878eb030000000000002c0000002c00000002000000000902000000000908004500001e00010000" ++
        "401100000a0102030a000001003514e9000000007878ec03000000000000300000003000000002000000000902000000" ++
        "000908004600002200010000401100000a0102030a0000090101010113880035000000007878ed030000000000002c00" ++
        "00002c00000002000000000902000000000908004500001e00010010401100000a0102030a0000090035003500000000" ++
        "7878ee030000000000002c0000002c00000002000000000902000000000908004500001e00012000401100000a010203" ++
        "0a00000900350035000000007878ef030000000000002a0000002a00000002000000000902000000000908004500001c" ++
        "00010000400100000a000001080808080800000000000000f0030000000000002c0000002c0000000200000000090200" ++
        "0000000908004500001e00010000408400000a0000070a0000080035270f000000007878f10300000000000040000000" ++
        "4000000002000000000902000000000986dd60000000000a064020010db800000000000000000000000120010db80000" ++
        "0000000000000000000200169c40000000007878f2030000000000004000000040000000020000000009020000000009" ++
        "86dd60000000000a114020010db800000000000000000000000120010db80000000000000000000000029c4000350000" ++
        "00007878f303000000000000480000004800000002000000000902000000000986dd6000000000122c4020010db80000" ++
        "0000000000000000000120010db8000000000000000000000002060000000000000104570050000000007878f4030000" ++
        "000000003e0000003e00000002000000000902000000000986dd6000000000083a4020010db800000000000000000000" ++
        "000120010db80000000000000000000000028000000000000000f5030000000000000d0000000d000000000000000000" ++
        "00000000000000f603000000000000220000002200000002000000000902000000000908004500001e00010000401100" ++
        "000a0000010a000002f7030000000000002c0000002c00000000112233445502000000000908004500001e0001000040" ++
        "0600000ac80304c0000201115c01bb000000007878f80300000000000030000000300000000200000000090200000000" ++
        "098100000508004500001e00010000401100000a0000010a00000200350035000000007878f903000000000000200000" ++
        "002000000002000000000900112233445588b56c6f63616c206578706572696d656e74616cfa03000000000000540000" ++
        "005400000002000000000902000000000908004f00004600010000400600000a0000050a000001010101010101010101" ++
        "0101010101010101010101010101010101010101010101010101010101010100500050000000007878fb030000000000" ++
        "003e0000003e00000002000000000902000000000986dd600000000008014020010db800000000000000000000000120" ++
        "010db80000000000000000000000020800000000000000",
);

/// What `tcpdump -n -tt -r corpus.pcap EXPR` printed: frame i has timestamp 1000+i.
const oracle = [_]struct { []const u8, []const usize }{
    .{ "ip", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18 } },
    .{ "ip6", &.{ 9, 10, 11, 12, 19 } },
    .{ "arp", &.{0} },
    .{ "icmp", &.{7} },
    .{ "tcp", &.{ 1, 2, 9, 11, 15, 18 } },
    .{ "udp", &.{ 3, 4, 5, 6, 10, 14 } },
    .{ "sctp", &.{8} },
    .{ "port 53", &.{ 3, 4, 6, 8, 10 } },
    .{ "udp port 53", &.{ 3, 4, 6, 10 } },
    .{ "tcp dst port 80", &.{ 1, 18 } },
    .{ "tcp src port 80", &.{ 2, 18 } },
    .{ "udp src port 53", &.{ 3, 6 } },
    .{ "src port 53", &.{ 3, 6, 8 } },
    .{ "dst port 80", &.{ 1, 18 } },
    .{ "ip src host 10.0.0.1", &.{ 1, 7, 14 } },
    .{ "ip dst host 10.0.0.1", &.{ 2, 3, 18 } },
    .{ "ip host 10.0.0.1", &.{ 1, 2, 3, 7, 14, 18 } },
    .{ "ip net 10.0.0.0/8", &.{ 1, 2, 3, 4, 5, 6, 7, 8, 14, 15, 18 } },
    .{ "ip src net 10.200.0.0/16", &.{15} },
    .{ "ip dst net 192.0.2.0/24", &.{ 1, 15 } },
    .{ "ether host 00:11:22:33:44:55", &.{ 0, 1, 2, 15, 17 } },
    .{ "ether src 00:11:22:33:44:55", &.{ 0, 1, 17 } },
    .{ "ether dst ff:ff:ff:ff:ff:ff", &.{0} },
    .{ "ether proto 0x86dd", &.{ 9, 10, 11, 12, 19 } },
    .{ "ether proto 34997", &.{17} },
    .{ "ip proto 132", &.{8} },
    .{ "not ip", &.{ 0, 9, 10, 11, 12, 16, 17, 19 } },
    .{ "arp or icmp", &.{ 0, 7 } },
    .{ "tcp and not port 80", &.{ 9, 11, 15 } },
    .{ "(udp or tcp) and ip6", &.{ 9, 10, 11 } },
    .{ "!tcp && !udp", &.{ 0, 7, 8, 12, 16, 17, 19 } },
    .{ "ip and not ip src net 10.0.0.0/8 or arp", &.{ 0, 2 } },
    .{ "not (ip or ip6 or arp)", &.{ 16, 17 } },
    .{ "sctp port 53", &.{8} },
    .{ "udp and ip6 and dst port 53", &.{10} },
};

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

fn verdicts(prog: []const BpfInsn, out: *std.ArrayList(usize)) !void {
    out.clearRetainingCapacity();
    var r = try pcap.Reader.init(&corpus_pcap);
    var i: usize = 0;
    while (try r.next()) |rec| : (i += 1) {
        if (run(prog, rec.data) != 0) try out.append(testing.allocator, i);
    }
    try testing.expectEqual(@as(usize, 20), i);
}

test "compile: every expression selects exactly the frames tcpdump selects" {
    var got: std.ArrayList(usize) = .empty;
    defer got.deinit(testing.allocator);
    for (oracle) |o| {
        const prog = try compile(testing.allocator, o[0]);
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
        .{ "host 10.0.0.1", error.UnsupportedExpression },
        .{ "vlan", error.UnsupportedExpression },
        .{ "ip src 10.0.0.1", error.UnsupportedExpression },
        .{ "ether foo 1", error.UnsupportedExpression },
        .{ "portrange 1-2", error.UnsupportedExpression },
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
    try testing.expectError(error.FilterTooComplex, compile(testing.allocator, "not " ** 65 ++ "ip"));
    // …64 do not.
    const ok = try compile(testing.allocator, "not " ** 64 ++ "ip");
    testing.allocator.free(ok);
    // A long disjunction needs a jump past 255 instructions to reach the
    // accept: refused rather than silently truncated.
    try testing.expectError(error.FilterTooComplex, compile(testing.allocator, "port 1" ++ " or port 1" ** 20));
    // The accepting/dropping tail is ret #262144 / ret #0, as libpcap's.
    const p = try compile(testing.allocator, "arp");
    defer testing.allocator.free(p);
    try testing.expectEqual(@as(usize, 4), p.len);
    try testing.expectEqual(@as(u32, 0), p[3].k);
}
