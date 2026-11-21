// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh hashdigest`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-hashdigest`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//!  * `keyed` — the 32-byte key of `blake3Keyed` tainted, over data of 0, 63,
//!    64 and 1,500 bytes and output lengths of 16, 32 and 100 bytes (one chunk,
//!    several chunks, an extended output).
//!  * `derive` — the key material of `blake3DeriveKey` tainted (the context is
//!    public), over lengths of 0, 32 and 2,000 bytes.
//!  * `blake2b` — the key of `blake2b` (`Blake2bParams.key`, 1..64 bytes) tainted.
//!
//! Digests, XOFs and `verifyEntry` handle public data; only keys and key
//! material are secrets here.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const hd = @import("root.zig");

const Target = enum { keyed, derive, blake2b };
const Taint = enum { yes, no };

fn taintBytes(taint: Taint, bytes: []u8) void {
    if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });
    var data: [1500]u8 = undefined;
    std.crypto.hash.Blake3.hash("ctgrind-hashdigest-data-v1", &data, .{});
    var out: [100]u8 = undefined;
    switch (target) {
        .keyed => {
            var key: [32]u8 = undefined;
            std.crypto.hash.Blake3.hash("ctgrind-hashdigest-key-v1", &key, .{});
            taintBytes(taint, &key);
            for ([_]usize{ 0, 63, 64, 1500 }) |n| {
                for ([_]usize{ 16, 32, 100 }) |o| {
                    hd.blake3Keyed(&key, data[0..n], out[0..o]);
                    std.debug.print("ctgrind_result={x}\n", .{out[0..o]});
                }
            }
        },
        .derive => {
            var material: [2000]u8 = undefined;
            std.crypto.hash.Blake3.hash("ctgrind-hashdigest-material-v1", &material, .{});
            taintBytes(taint, &material);
            for ([_]usize{ 0, 32, 2000 }) |n| {
                hd.blake3DeriveKey("hashdigest ctgrind 2026-11-21 derive", material[0..n], out[0..32]);
                std.debug.print("ctgrind_result={x}\n", .{out[0..32]});
            }
        },
        .blake2b => {
            var key: [64]u8 = undefined;
            std.crypto.hash.Blake3.hash("ctgrind-hashdigest-b2key-v1", &key, .{});
            taintBytes(taint, &key);
            for ([_]usize{ 1, 32, 64 }) |kl| {
                try hd.blake2bVar(out[0..32], data[0..200], .{ .key = key[0..kl] });
                std.debug.print("ctgrind_result={x}\n", .{out[0..32]});
            }
        },
    }
}
