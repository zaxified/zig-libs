// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh opcua`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-opcua`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures (Basic256Sha256 secure channel, symmetric half)
//!
//!  * `kdf` — `security.deriveKeys` (P_SHA256) with both channel nonces
//!    tainted: they travel RSA-OAEP-encrypted in the OpenSecureChannel
//!    exchange and are the root of every channel key.
//!  * `chunk` — the channel keys and the message body tainted through
//!    `symmetricSignAndEncrypt` and `symmetricDecryptAndVerify` (AES-256-CBC +
//!    HMAC-SHA256, modes Sign and SignAndEncrypt), plus a chunk opened with
//!    the wrong direction's keys (rejected). The chunk on the wire is public
//!    and is marked defined before it is opened.
//!
//! The asymmetric (RSA) half is the `rsa` module's and has its own rows.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const opcua = @import("root.zig");

const sec = opcua.security;
const Target = enum { kdf, chunk };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var cn = secretBytes(32, "ctgrind-opcua-client-nonce-v1");
    var sn = secretBytes(32, "ctgrind-opcua-server-nonce-v1");

    switch (target) {
        .kdf => {
            if (taint == .yes) {
                std.valgrind.memcheck.makeMemUndefined(&cn);
                std.valgrind.memcheck.makeMemUndefined(&sn);
            }
            const keys = sec.deriveKeys(&cn, &sn, .basic256sha256);
            std.debug.print("ctgrind_result={x}\n", .{std.mem.asBytes(&keys).*});
        },
        .chunk => {
            var heap: [1 << 16]u8 = undefined;
            var fba = std.heap.FixedBufferAllocator.init(&heap);
            const gpa = fba.allocator();
            var keys = sec.deriveKeys(&cn, &sn, .basic256sha256);
            var body = secretBytes(32, "ctgrind-opcua-body-v1") ++ secretBytes(29, "ctgrind-opcua-body-2-v1");
            if (taint == .yes) {
                std.valgrind.memcheck.makeMemUndefined(std.mem.asBytes(&keys));
                std.valgrind.memcheck.makeMemUndefined(&body);
            }
            for ([_]sec.SecurityMode{ .sign, .sign_and_encrypt }) |mode| {
                const wire = try sec.symmetricSignAndEncrypt(gpa, "MSG", &body, mode, &keys, .client_to_server);
                std.debug.print("ctgrind_result={x}\n", .{wire});
                std.valgrind.memcheck.makeMemDefined(wire);
                const got = try sec.symmetricDecryptAndVerify(gpa, wire[0..8], wire[8..], mode, &keys, .client_to_server);
                std.debug.print("ctgrind_result={x}\n", .{got});
                // The body length comes out of the (post-MAC) padding byte, so
                // it is tainted, and so is the harness allocator's bump index
                // it moved; both are public (the message's length). Left
                // tainted, every later allocation's ADDRESS is tainted.
                std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&fba.end_index));
                const rejected = if (sec.symmetricDecryptAndVerify(gpa, wire[0..8], wire[8..], mode, &keys, .server_to_client)) |_| false else |_| true;
                std.debug.print("ctgrind_result={x}\n", .{[1]u8{@intFromBool(rejected)}});
                std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&fba.end_index));
            }
        },
    }
}
