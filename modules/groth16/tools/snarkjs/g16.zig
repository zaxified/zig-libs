// SPDX-License-Identifier: MIT
//! `g16` — this module's file-level operations as a command line, so the
//! snarkjs oracle in `gen.sh` can drive them on circuits too big to commit:
//!
//!     g16 prove      <circuit.zkey> <witness.wtns> <proof.json> <public.json>
//!     g16 newzkey    <circuit.r1cs> <ceremony.ptau> <out.zkey>
//!     g16 contribute <in.zkey> <out.zkey> <name>
//!     g16 verify     <circuit.r1cs> <ceremony.ptau> <circuit.zkey>
//!
//! Each prints the wall time of its phases on stderr. The proof's r, s come
//! from `Fr.random(io)` (the `Io`'s CSPRNG); a contribution's secret, which
//! must be unpredictable even to a process whose memory leaked, from
//! `io.randomSecure`.
//!
//! Built by `gen.sh` with `zig build-exe -OReleaseFast` against the module's
//! sources; it is a test instrument, not part of the published module.

const std = @import("std");
const groth16 = @import("groth16");

const Fr = groth16.Fr;

fn usage() noreturn {
    std.debug.print(
        \\usage: g16 prove <zkey> <wtns> <proof.json> <public.json>
        \\       g16 newzkey <r1cs> <ptau> <out.zkey>
        \\       g16 contribute <in.zkey> <out.zkey> <name>
        \\       g16 verify <r1cs> <ptau> <zkey>
        \\
    , .{});
    std.process.exit(2);
}

const max_file = 16 << 30;

/// A scalar from 64 bytes of `randomSecure` reduced mod r (bias < 2⁻²⁵⁰).
fn secureFr(io: std.Io) !Fr {
    var buf: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    try io.randomSecure(&buf);
    return Fr.reduceWide(&buf);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args = try init.minimal.args.iterateAllocator(gpa);
    defer args.deinit();
    _ = args.next();
    const cmd = args.next() orelse usage();
    var a: [4][]const u8 = undefined;
    var n: usize = 0;
    while (args.next()) |s| : (n += 1) {
        if (n == a.len) usage();
        a[n] = s;
    }
    const cwd = std.Io.Dir.cwd();

    if (std.mem.eql(u8, cmd, "prove")) {
        if (n != 4) usage();
        var t = std.Io.Timestamp.now(io, .awake);
        const zbytes = try cwd.readFileAlloc(io, a[0], gpa, .limited(max_file));
        var z = try groth16.zkey.parse(gpa, zbytes);
        gpa.free(zbytes);
        defer z.deinit(gpa);
        const wbytes = try cwd.readFileAlloc(io, a[1], gpa, .limited(max_file));
        const w = try groth16.circom.parseWitness(gpa, wbytes);
        std.crypto.secureZero(u8, wbytes);
        gpa.free(wbytes);
        defer groth16.circom.freeWitness(gpa, w);
        std.debug.print("load {d} ms (n_vars {d}, domain {d})\n", .{ t.untilNow(io, .awake).toMilliseconds(), z.n_vars, z.domain_size });
        t = std.Io.Timestamp.now(io, .awake);
        var rand: groth16.Randomizers = .{ .r = Fr.random(io), .s = Fr.random(io) };
        defer std.crypto.secureZero(u8, std.mem.asBytes(&rand));
        const proof = try groth16.zkprove.prove(gpa, z, w, &rand);
        std.debug.print("prove {d} ms\n", .{t.untilNow(io, .awake).toMilliseconds()});
        const pj = try groth16.snarkjs_export.proofJson(gpa, proof);
        defer gpa.free(pj);
        try cwd.writeFile(io, .{ .sub_path = a[2], .data = pj });
        const pubj = try groth16.snarkjs_export.publicJson(gpa, w[1 .. z.n_public + 1]);
        defer gpa.free(pubj);
        try cwd.writeFile(io, .{ .sub_path = a[3], .data = pubj });
    } else if (std.mem.eql(u8, cmd, "newzkey")) {
        if (n != 3) usage();
        const rbytes = try cwd.readFileAlloc(io, a[0], gpa, .limited(max_file));
        defer gpa.free(rbytes);
        var r = try groth16.circom.parseR1cs(gpa, rbytes);
        defer r.deinit(gpa);
        const pbytes = try cwd.readFileAlloc(io, a[1], gpa, .limited(max_file));
        defer gpa.free(pbytes);
        const p = try groth16.ptau.Ptau.parse(pbytes);
        const t = std.Io.Timestamp.now(io, .awake);
        var z = try groth16.phase2.newZkey(gpa, r, p);
        defer z.deinit(gpa);
        std.debug.print("newzkey {d} ms\n", .{t.untilNow(io, .awake).toMilliseconds()});
        const out = try groth16.zkey.toBytes(gpa, z);
        defer gpa.free(out);
        try cwd.writeFile(io, .{ .sub_path = a[2], .data = out });
    } else if (std.mem.eql(u8, cmd, "contribute")) {
        if (n != 3) usage();
        const zbytes = try cwd.readFileAlloc(io, a[0], gpa, .limited(max_file));
        var z = try groth16.zkey.parse(gpa, zbytes);
        gpa.free(zbytes);
        defer z.deinit(gpa);
        var x = try secureFr(io);
        var s = try secureFr(io);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&x));
        defer std.crypto.secureZero(u8, std.mem.asBytes(&s));
        const t = std.Io.Timestamp.now(io, .awake);
        try groth16.phase2.contribute(gpa, &z, &x, &s, a[2]);
        std.debug.print("contribute {d} ms\n", .{t.untilNow(io, .awake).toMilliseconds()});
        const out = try groth16.zkey.toBytes(gpa, z);
        defer gpa.free(out);
        try cwd.writeFile(io, .{ .sub_path = a[1], .data = out });
    } else if (std.mem.eql(u8, cmd, "verify")) {
        if (n != 3) usage();
        const rbytes = try cwd.readFileAlloc(io, a[0], gpa, .limited(max_file));
        defer gpa.free(rbytes);
        var r = try groth16.circom.parseR1cs(gpa, rbytes);
        defer r.deinit(gpa);
        const pbytes = try cwd.readFileAlloc(io, a[1], gpa, .limited(max_file));
        defer gpa.free(pbytes);
        const p = try groth16.ptau.Ptau.parse(pbytes);
        const zbytes = try cwd.readFileAlloc(io, a[2], gpa, .limited(max_file));
        var z = try groth16.zkey.parse(gpa, zbytes);
        gpa.free(zbytes);
        defer z.deinit(gpa);
        const t = std.Io.Timestamp.now(io, .awake);
        const verdict = try groth16.phase2.verify(gpa, io, r, p, z);
        std.debug.print("verify {d} ms\n", .{t.untilNow(io, .awake).toMilliseconds()});
        var ours: usize = 0;
        for (0..z.contributions.len) |k| {
            if (groth16.phase2.verifyContribution(z, k)) ours += 1;
        }
        std.debug.print("{s} (contributions {d}, proofs checked here {d})\n", .{ @tagName(verdict), z.contributions.len, ours });
        if (verdict != .ok) std.process.exit(1);
    } else usage();
}
