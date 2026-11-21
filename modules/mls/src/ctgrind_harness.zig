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
//!  * `group` — the group-level application path (§6.3 through
//!    `Group.protectApplication` / `Group.unprotectApplication`): alice
//!    creates a group and adds bob (Commit + Welcome, untainted, from a
//!    deterministic `Io`), bob joins; then alice's `EpochSecrets` and her
//!    Ed25519 signing key are tainted. Alice protects two messages
//!    (generations 0 and 1, so the ratchet advances under taint; her secret
//!    tree is built from the tainted encryption secret on first use) and bob,
//!    untainted, opens them as the check that the measured bytes are right.
//!    The wire bytes are public and marked defined before bob reads them. The
//!    receive side under a tainted key is `priv`'s: a group-level receiver
//!    under taint also counts the processing of its decrypted sender data and
//!    content (ratchet selection by leaf index and generation, parsing,
//!    signature verification), which is data, not key — measured 2026-11-21
//!    at 159 in-file contexts, every one downstream of the two AES-GCM tag
//!    verdicts.
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
const Target = enum { ks, tree, priv, group };
const G = mls.group.Group(S);
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

fn taintBytes(t: Taint, bytes: []u8) void {
    if (t == .yes) std.valgrind.memcheck.makeMemUndefined(bytes);
}

// A deterministic `Io.randomSecure` for the `group` target, so the printed
// wire bytes (and so `out_sha`) are the same on every run.
var det_counter: u64 = 0;
fn detSecure(_: ?*anyopaque, buf: []u8) std.Io.RandomSecureError!void {
    var o: usize = 0;
    while (o < buf.len) {
        var h: [32]u8 = undefined;
        var s = std.crypto.hash.sha2.Sha256.init(.{});
        s.update("ctgrind-mls-group-draw");
        s.update(std.mem.asBytes(&det_counter));
        s.final(&h);
        det_counter += 1;
        const k = @min(h.len, buf.len - o);
        @memcpy(buf[o..][0..k], h[0..k]);
        o += k;
    }
}

const Member = struct {
    sig: S.Sig.KeyPair,
    init_kp: S.Kem.KeyPair,
    enc_kp: S.Kem.KeyPair,
    kp_msg: []u8,
    kp: mls.keypackage.KeyPackage,

    fn init(arena: std.mem.Allocator, name: []const u8, seed: u8) !Member {
        const sig = try S.Sig.KeyPair.generateDeterministic(@splat(seed));
        const init_kp = S.Kem.KeyPair.generateDeterministic(@splat(seed +% 64));
        const enc_kp = S.Kem.KeyPair.generateDeterministic(@splat(seed +% 128));
        const kp = try mls.keypackage.create(S, arena, .{
            .signature_key_pair = &sig,
            .init_key = init_kp.public_key,
            .encryption_key = enc_kp.public_key,
            .credential = .{ .basic = name },
            .capabilities = .{
                .versions = &.{1},
                .cipher_suites = &.{1},
                .extensions = &.{},
                .proposals = &.{},
                .credentials = &.{1},
            },
            .lifetime = .{ .not_before = 0, .not_after = std.math.maxInt(u64) },
        });
        const msg: mls.framing.MLSMessage = .{ .key_package = kp };
        return .{ .sig = sig, .init_kp = init_kp, .enc_kp = enc_kp, .kp_msg = try msg.encodeAlloc(arena), .kp = kp };
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
        .group => {
            const pa = std.heap.page_allocator; // global-alloc-ok: one-shot ctgrind diagnostic binary, the group state outgrows the 64 KiB buffer
            var threaded = std.Io.Threaded.init(pa, .{});
            defer threaded.deinit();
            const base_io = threaded.io();
            var vt = base_io.vtable.*;
            vt.randomSecure = detSecure;
            const io: std.Io = .{ .userdata = base_io.userdata, .vtable = &vt };

            var arena_state = std.heap.ArenaAllocator.init(pa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            var alice = try Member.init(arena, "alice", 1);
            const bob = try Member.init(arena, "bob", 2);

            var a: G = undefined;
            try G.create(pa, .{
                .io = io,
                .group_id = "ctgrind-mls-group",
                .key_package_msg = alice.kp_msg,
                .encryption_priv = &alice.enc_kp.secret_key,
            }, &a);
            defer a.deinit();
            const props = [_]G.CommitSource{.{ .by_value = .{ .add = bob.kp } }};
            const c = try a.createCommit(arena, .{
                .io = io,
                .signature_key_pair = &alice.sig,
                .proposals = &props,
            });
            var b: G = undefined;
            try G.fromWelcome(pa, .{
                .welcome_msg = c.welcome.?,
                .key_package_msg = bob.kp_msg,
                .init_priv = &bob.init_kp.secret_key,
                .encryption_priv = &bob.enc_kp.secret_key,
            }, &b);
            defer b.deinit();

            // Only the SENDER is tainted: bob's copy of the same epoch stays
            // defined, so his open checks the measured bytes without counting
            // the processing of decrypted sender data and content (the leaf
            // index and generation select a ratchet, the content is parsed and
            // its signature verified), which follows from the plaintext being
            // derived from a tainted key, not from a branch on the key.
            taintBytes(taint, std.mem.asBytes(&a.secrets));
            taintBytes(taint, std.mem.asBytes(&alice.sig.secret_key));

            for ([_][]const u8{ "group application data under tainted keys", "second message, ratchet advanced" }) |data| {
                const wire = try a.protectApplication(arena, .{
                    .io = io,
                    .signature_key_pair = &alice.sig,
                    .data = data,
                    .authenticated_data = "aad",
                });
                // Printed while still tainted (the propagation witness: the
                // ciphertext and signature come from the tainted keys), then
                // marked defined: on the wire it is public.
                std.debug.print("ctgrind_result={x}\n", .{wire});
                std.valgrind.memcheck.makeMemDefined(wire);
                const got = try b.unprotectApplication(arena, wire);
                if (got.sender != 0 or !std.mem.eql(u8, got.authenticated_data, "aad")) return error.WrongMessage;
                std.debug.print("ctgrind_result={x}\n", .{got.data});
            }
        },
    }
}
