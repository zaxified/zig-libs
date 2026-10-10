// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh mls`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-mls`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures (suite 0x0001, X25519/AES-128-GCM/SHA-256/Ed25519)
//!
//!  * `ks` — `keyschedule.deriveEpoch` with the previous init secret, the
//!    commit secret and the PSK secret tainted (RFC 9420 §8: joiner, member,
//!    welcome, epoch secret and every secret derived from it).
//!  * `tree` — the secret tree (§9) under a tainted encryption secret:
//!    `nodeSecret` for every node, `ratchetBaseSecret`, `Ratchet`
//!    `current`/`advance` and `Window.get` out of order.
//!  * `priv` — a PrivateMessage (§6.3): `protectPrivate` with the content
//!    key/nonce, the sender-data secret and the Ed25519 signing key tainted,
//!    then the receiver's `senderDataKeys`, `decryptSenderData` and
//!    `decryptContent`. The wire bytes `protectPrivate` returns are public and
//!    are marked defined before the receiver parses them.
//!
//! Not measured here: TreeKEM path secrets and HPKE (`treekem`, `welcome`)
//! — their KEM is the `hpke` module's, which carries its own rows.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const mls = @import("root.zig");

const S = mls.suite.default;
const KN = mls.secrettree.KeyNonce(S);
const Target = enum { ks, tree, priv };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

fn taintBytes(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var heap: [1 << 16]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&heap);
    const gpa = fba.allocator();

    switch (target) {
        .ks => {
            var init_prev = secretBytes(32, "ctgrind-mls-init-secret-v1");
            var commit = secretBytes(32, "ctgrind-mls-commit-secret-v1");
            var psk = secretBytes(32, "ctgrind-mls-psk-secret-v1");
            taintBytes(taint, &init_prev);
            taintBytes(taint, &commit);
            taintBytes(taint, &psk);
            var es: mls.keyschedule.EpochSecrets(S) = undefined;
            try mls.keyschedule.deriveEpoch(S, gpa, &init_prev, &commit, &psk, "ctgrind group context bytes", &es);
            std.debug.print("ctgrind_result={x}\n", .{std.mem.asBytes(&es).*});
        },
        .tree => {
            var enc = secretBytes(32, "ctgrind-mls-encryption-secret-v1");
            taintBytes(taint, &enc);
            var ns: [32]u8 = undefined;
            for (0..7) |ni| {
                try mls.secrettree.nodeSecret(S, &enc, 4, ni, &ns);
                std.debug.print("ctgrind_result={x}\n", .{ns});
            }
            var base: [32]u8 = undefined;
            try mls.secrettree.ratchetBaseSecret(S, &enc, 4, 2, .application, &base);
            var rt: mls.secrettree.Ratchet(S) = undefined;
            mls.secrettree.Ratchet(S).init(&base, &rt);
            var kn: KN = undefined;
            for (0..3) |_| {
                try rt.current(&kn);
                std.debug.print("ctgrind_result={x}\n", .{std.mem.asBytes(&kn).*});
                try rt.advance();
            }
            var win: mls.secrettree.Window(S, 4) = undefined;
            mls.secrettree.Window(S, 4).init(&base, &win);
            for ([_]u32{ 2, 0, 3, 1 }) |g| {
                try win.get(g, &kn);
                std.debug.print("ctgrind_result={x}\n", .{std.mem.asBytes(&kn).*});
            }
        },
        .priv => {
            var sig = try S.Sig.KeyPair.generateDeterministic(secretBytes(32, "ctgrind-mls-sig-v1"));
            var sd_secret = secretBytes(32, "ctgrind-mls-sender-data-v1");
            const base = secretBytes(32, "ctgrind-mls-ratchet-base-v1");
            var rt: mls.secrettree.Ratchet(S) = undefined;
            mls.secrettree.Ratchet(S).init(&base, &rt);
            var kn: KN = undefined;
            try rt.current(&kn);
            taintBytes(taint, std.mem.asBytes(&sig.secret_key));
            taintBytes(taint, &sd_secret);
            taintBytes(taint, std.mem.asBytes(&kn));
            const guard: [4]u8 = .{ 1, 2, 3, 4 };
            const fc: mls.framing.FramedContent = .{
                .group_id = "ctgrind-group",
                .epoch = 1,
                .sender = .{ .member = 0 },
                .authenticated_data = "aad",
                .body = .{ .application = "mls application data under tainted keys" },
            };
            const wire = try mls.framing.protectPrivate(S, gpa, .{
                .signature_key_pair = &sig,
                .group_context = "ctgrind group context bytes",
                .content = fc,
                .key_nonce = &kn,
                .generation = 0,
                .reuse_guard = guard,
                .sender_data_secret = &sd_secret,
            });
            // On the wire: public.
            std.valgrind.memcheck.makeMemDefined(wire);
            var rd = mls.codec.Reader.init(wire);
            const pm = try mls.framing.PrivateMessage.decode(&rd);
            const sd = try mls.framing.decryptSenderData(S, gpa, pm, &sd_secret);
            const pt = try mls.framing.decryptContent(S, gpa, pm, &kn, guard);
            std.debug.print("ctgrind_result={x}\n", .{std.mem.asBytes(&sd).*});
            std.debug.print("ctgrind_result={x}\n", .{pt});
        },
    }
}
