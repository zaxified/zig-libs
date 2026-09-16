// SPDX-License-Identifier: MIT

//! Canonical one-line rendering of what `dns.message.decode` made of each
//! packet, so a second implementation can be asked the same question.
//!
//! Reads hex packets (one per line) from a file, writes one line per packet.
//! It is the Zig half of the dnspython differential; `oracle_dnspython.py`
//! parses this exact format, so **the format is an interface** -- changing a
//! field means changing the parser in the same commit.
//!
//! Build and run it (from the repository root):
//!
//!     scripts/capped zig build-exe --cache-dir .zig-cache \
//!       -femit-bin=.zig-cache/dns-oracle/probe_dump \
//!       --dep msg -Mroot=modules/dns/tools/probe_dump.zig \
//!       --dep testkit -Mmsg=modules/dns/src/message.zig \
//!       -Mtestkit=modules/testkit/src/root.zig
//!     .zig-cache/dns-oracle/probe_dump corpus.hex out.txt
//!
//! ⚠ `msg` is the LIVE `modules/dns/src/message.zig`, never a copy beside this
//! file. The audit version imported a `msg.zig` snapshot that had rotted 181
//! lines behind the module it claimed to describe (CONVENTIONS.md §9).
//!
//! ⚠ `--dep testkit` is not optional even though nothing here fuzzes:
//! `message.zig` imports `testkit` at file scope for its fuzz corpus, and
//! `goldens.zig` resolves relative to it -- which is why the module path must
//! point into `src/` rather than into a scratch directory.
const std = @import("std");
const msg = @import("msg");

pub fn main(init: std.process.Init.Minimal) !u8 {
    var gpa_inst: std.heap.DebugAllocator(.{}) = .init;
    const gpa = gpa_inst.allocator();
    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var it = init.args.iterate();
    _ = it.next();
    const in_path = it.next() orelse {
        std.debug.print("usage: probe_dump <corpus.hex> <out.txt>\n", .{});
        return 2;
    };
    const out_path = it.next() orelse {
        std.debug.print("usage: probe_dump <corpus.hex> <out.txt>\n", .{});
        return 2;
    };
    const text = try std.Io.Dir.cwd().readFileAlloc(io, in_path, gpa, .limited(1 << 28));
    defer gpa.free(text);
    var aw: std.Io.Writer.Allocating = .init(gpa);
    defer aw.deinit();
    const w = &aw.writer;
    const line_buf = try gpa.alloc(u8, 1 << 18);
    defer gpa.free(line_buf);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const n = line.len / 2;
        var k: usize = 0;
        while (k < n) : (k += 1) {
            line_buf[k] = (std.fmt.charToDigit(line[2 * k], 16) catch 0) * 16 +
                (std.fmt.charToDigit(line[2 * k + 1], 16) catch 0);
        }
        const bytes = line_buf[0..n];
        if (msg.decode(gpa, bytes)) |m| {
            var mm = m;
            defer mm.deinit();
            try w.print("OK id={d} rc={d} qd={d} an={d} ns={d} ar={d}", .{
                mm.header.id,   @intFromEnum(mm.rcode()), mm.questions.len,
                mm.answers.len, mm.authorities.len,       mm.additionals.len,
            });
            for (mm.questions) |q| try w.print(" |Q<{x}>{d}/{d}", .{ q.name, @intFromEnum(q.ty), @intFromEnum(q.class) });
            for ([_][]const msg.Record{ mm.answers, mm.authorities, mm.additionals }) |sec| {
                for (sec) |r| {
                    try w.print(" |R<{x}>{d}/{d}/{d}", .{ r.name, @intFromEnum(r.ty), @intFromEnum(r.class), r.ttl });
                    switch (r.data) {
                        .a => |b| try w.print("=A{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] }),
                        .aaaa => |b| try w.print("=AAAA{x}", .{b}),
                        .cname => |s2| try w.print("=CNAME<{x}>", .{s2}),
                        .ns => |s2| try w.print("=NS<{x}>", .{s2}),
                        .ptr => |s2| try w.print("=PTR<{x}>", .{s2}),
                        .mx => |m2| try w.print("=MX{d}<{x}>", .{ m2.preference, m2.exchange }),
                        .txt => |ts| {
                            try w.print("=TXT{d}", .{ts.len});
                            for (ts) |t| try w.print("<{x}>", .{t});
                        },
                        .soa => |s2| try w.print("=SOA<{x}><{x}>{d},{d},{d},{d},{d}", .{ s2.mname, s2.rname, s2.serial, s2.refresh, s2.retry, s2.expire, s2.minimum }),
                        .srv => |s2| try w.print("=SRV{d},{d},{d}<{x}>", .{ s2.priority, s2.weight, s2.port, s2.target }),
                        .caa => |c| try w.print("=CAA{d}<{x}><{x}>", .{ c.flags, c.tag, c.value }),
                        .opt => |o| try w.print("=OPT{d},{d},{d},{}", .{ o.udp_payload_size, o.extended_rcode, o.version, o.dnssec_ok }),
                        .unknown => |u| try w.print("=RAW<{x}>", .{u}),
                    }
                }
            }
            try w.writeByte('\n');
        } else |e| try w.print("ERR {t}\n", .{e});
    }
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = aw.written() });
    return 0;
}
