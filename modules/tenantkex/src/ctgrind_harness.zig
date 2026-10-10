// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh tenantkex`, which
//! builds every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-tenantkex`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `ik` — a full per-tenant Noise_IK exchange (`Initiator.writeMessage1`,
//!    `Responder.readMessage1`, `writeMessage2`, `Initiator.readMessage2`)
//!    with both PEs' static PRIVATE keys and every ephemeral seed (drawn from
//!    a `std.Random` whose fill marks its output undefined) tainted. Static
//!    public keys, the fabric context (I-SID, PE ids) and lengths are public.
//!    Both sides' `SessionKeys` are printed.
//!
//! This module is a driver over `noise` (whose own rows measure the
//! handshake engine); the in-file pattern is this module's own files plus
//! `root.zig` of the siblings it calls (noise's and chachapoly's root.zig
//! share the name).
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const tk = @import("root.zig");

const Target = enum { ik };
const Taint = enum { yes, no };

var taint_on = false;

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

const TaintRng = struct {
    prng: std.Random.DefaultPrng,
    fn fill(self: *TaintRng, buf: []u8) void {
        self.prng.random().bytes(buf);
        if (taint_on) std.valgrind.memcheck.makeMemUndefined(buf);
    }
    fn random(self: *TaintRng) std.Random {
        return std.Random.init(self, fill);
    }
};

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });
    taint_on = taint == .yes;

    switch (target) {
        .ik => {
            var pe_a = try tk.KeyPair.generateDeterministic(secretBytes(32, "ctgrind-tenantkex-pe-a-v1"));
            var pe_b = try tk.KeyPair.generateDeterministic(secretBytes(32, "ctgrind-tenantkex-pe-b-v1"));
            if (taint_on) {
                std.valgrind.memcheck.makeMemUndefined(&pe_a.secret_key);
                std.valgrind.memcheck.makeMemUndefined(&pe_b.secret_key);
            }
            const ctx: tk.FabricContext = .{ .isid = 0x123456, .initiator_pe = 7, .responder_pe = 9 };
            var trng: TaintRng = .{ .prng = .init(0x7e4a47) };
            const rng = trng.random();

            var ini: tk.Initiator = undefined;
            ini.init(&pe_a, pe_b.public_key, ctx);
            var rsp: tk.Responder = undefined;
            rsp.init(&pe_b, pe_a.public_key, ctx);

            var m1: [256]u8 = undefined;
            var m2: [256]u8 = undefined;
            var pl: [64]u8 = undefined;
            const n1 = try ini.writeMessage1(rng, "tenant hello", &m1);
            _ = try rsp.readMessage1(m1[0..n1], &pl);
            var rkeys: tk.SessionKeys = undefined;
            const n2 = try rsp.writeMessage2(rng, "tenant ack", &m2, &rkeys);
            var ikeys: tk.SessionKeys = undefined;
            _ = try ini.readMessage2(m2[0..n2], &pl, &ikeys);
            std.debug.print("ctgrind_result={x}\n", .{ikeys.send_key ++ ikeys.recv_key ++ ikeys.transcript_hash});
            std.debug.print("ctgrind_result={x}\n", .{rkeys.send_key ++ rkeys.recv_key});
        },
    }
}
