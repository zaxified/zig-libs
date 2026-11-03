// SPDX-License-Identifier: MIT

//! ctgrind_harness: what `wireguard` does with its secrets, measured in the binary.
//! Run it through `../../../scripts/checks/ctgrind.sh wireguard`.
//!
//! Targets, and what is tainted in each:
//!   keyb64     the key text through `keyFromBase64Into`, the key through `keyToBase64`
//!   keyhex     the same through `uapi.keyFromHex` / `uapi.keyToHex`
//!   handshake  both static private keys, both ephemerals and the PSK through a whole
//!              Noise_IKpsk2 exchange, down to the transport keys
//!   transport  the session key through `seal` and `open`
//!   cookie     the cookie secret `Rm` through `cookieFor`, `createReplyWithNonce`
//!              and `checkMac2`
//!   tunnel     the static private key and the PSK through `Tunnel`: a handshake,
//!              data one way (random ephemerals, so only the plaintext is printed)
//!
//! What goes on the wire is public, and what an attacker is told by a refusal is the
//! refusal. So messages and public keys are declassified where they leave the
//! function that made them: without that, the receiver's perfectly public checks on
//! them are counted as leaks. The counts left are verdicts, documented in the
//! expected table. The text parsers (`conf.parse`, `uapi.GetParser`) are not targets:
//! they look for newlines and `=` in every line, a key's too, and for valid key
//! text each of those comparisons comes out the same whatever the key.

const std = @import("std");
const builtin = @import("builtin");
const root = @import("root.zig");
const hs = root.handshake;
const transport = root.transport;
const uapi = root.uapi;
const tunnel = root.tunnel;
const Tunnel = root.Tunnel;

fn secret(comptime label: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("ctgrind-wireguard-" ++ label, &out, .{});
    return out;
}

fn taint(enabled: bool, bytes: []u8) void {
    if (enabled) std.valgrind.memcheck.makeMemUndefined(bytes);
}

fn public(bytes: []const u8) void {
    std.valgrind.memcheck.makeMemDefined(bytes);
}

fn keypairOf(priv: *const [32]u8) !hs.Keypair {
    var kp: hs.Keypair = undefined;
    try hs.Keypair.fromPrivateKey(priv, &kp);
    public(&kp.public);
    return kp;
}

const Target = enum { keyb64, keyhex, handshake, transport, cookie, tunnel };

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse return error.UnknownTarget;
    const tainted = std.mem.eql(u8, it.next() orelse return error.MissingTaint, "yes");
    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    var threaded: std.Io.Threaded = .init(std.heap.page_allocator, .{ .environ = init.environ });
    defer threaded.deinit();
    const io = threaded.io();

    switch (target) {
        .keyb64 => {
            var key = secret("b64");
            var text = root.keyToBase64(key);
            taint(tainted, &key);
            const enc = root.keyToBase64(key);
            taint(tainted, &text);
            var back: root.Key = undefined;
            root.keyFromBase64Into(&text, &back) catch return error.Refused;
            std.debug.print("ctgrind_result={x}\n", .{enc});
            std.debug.print("ctgrind_result[1]={x}\n", .{back});
        },
        .keyhex => {
            var key = secret("hex");
            var text: [64]u8 = undefined;
            uapi.keyToHex(&key, &text);
            taint(tainted, &key);
            var enc: [64]u8 = undefined;
            uapi.keyToHex(&key, &enc);
            taint(tainted, &text);
            var back: root.Key = undefined;
            uapi.keyFromHex(&text, &back) catch return error.Refused;
            std.debug.print("ctgrind_result={x}\n", .{enc});
            std.debug.print("ctgrind_result[1]={x}\n", .{back});
        },
        .handshake => {
            var si = secret("si");
            var sr = secret("sr");
            var ei = secret("ei");
            var er = secret("er");
            var psk = secret("psk");
            for ([_][]u8{ &si, &sr, &ei, &er, &psk }) |s| taint(tainted, s);
            const ks_i = try keypairOf(&si);
            const ks_r = try keypairOf(&sr);
            var ini: hs.Handshake = .{
                .static_keypair = ks_i,
                .remote_static_public = ks_r.public,
                .preshared_key = psk,
                .local_ephemeral = try keypairOf(&ei),
                .local_index = 1,
            };
            var rsp: hs.Handshake = .{
                .static_keypair = ks_r,
                .remote_static_public = ks_i.public,
                .preshared_key = psk,
                .local_ephemeral = try keypairOf(&er),
                .local_index = 2,
            };
            var m1 = try ini.createInitiation(io, tunnel.tai64n(1, 0));
            public(std.mem.asBytes(&m1));
            try rsp.consumeInitiation(m1);
            var m2 = try rsp.createResponse(io);
            public(std.mem.asBytes(&m2));
            try ini.consumeResponse(m2);
            var ki: transport.TransportKeys = undefined;
            var kr: transport.TransportKeys = undefined;
            ini.deriveTransportKeys(true, &ki);
            rsp.deriveTransportKeys(false, &kr);
            std.debug.print("ctgrind_result={x}\n", .{ki.send});
            std.debug.print("ctgrind_result[1]={x}\n", .{kr.send});
        },
        .transport => {
            var key = secret("session");
            taint(tainted, &key);
            var pkt: [1420]u8 = @splat(0x42);
            var s: transport.SendSession = undefined;
            s.init(&key, 7, 0);
            var r: transport.RecvSession = undefined;
            r.init(&key, 7, 0);
            var wire: [transport.sealedLen(pkt.len)]u8 = undefined;
            const n = (try s.seal(&wire, &pkt, 0)).len;
            std.debug.print("ctgrind_result={x}\n", .{wire[wire.len - 16 ..]});
            public(wire[0..n]);
            var plain: [pkt.len + 16]u8 = undefined;
            _ = try r.open(&plain, wire[0..n], 0);
            std.debug.print("ctgrind_result[1]={x}\n", .{plain[0..16]});
        },
        .cookie => {
            var rm = secret("rm");
            taint(tainted, &rm);
            const peer: [32]u8 = @splat(9);
            var c: hs.CookieChecker = undefined;
            hs.CookieChecker.initWithSecret(peer, &rm, 100, &c);
            var cookie: [16]u8 = undefined;
            c.cookieFor(io, 100, "source", &cookie);
            var msg: hs.MessageInitiation = std.mem.zeroes(hs.MessageInitiation);
            msg.type = 1;
            msg.mac1 = hs.Handshake.computeMac1(&.{ .static_keypair = undefined, .remote_static_public = peer }, std.mem.asBytes(&msg)[0..@offsetOf(hs.MessageInitiation, "mac1")]);
            const f = try hs.macFields(std.mem.asBytes(&msg));
            const ok = c.checkMac2(io, 100, f, "source");
            var reply = c.createReplyWithNonce(io, 100, f, "source", @splat(3));
            public(std.mem.asBytes(&reply));
            std.debug.print("ctgrind_result={x}\n", .{cookie});
            std.debug.print("ctgrind_result[1]={x} {}\n", .{ reply.encrypted_cookie, ok });
        },
        .tunnel => {
            var pa = secret("a");
            var pb = secret("b");
            var psk = secret("psk");
            for ([_][]u8{ &pa, &pb, &psk }) |s| taint(tainted, s);
            var ka = try keypairOf(&pa);
            var kb = try keypairOf(&pb);
            const clk: tunnel.Clock = .{ .mono_ms = 1000, .tai64n = tunnel.tai64n(100, 0) };
            var a: Tunnel = undefined;
            var b: Tunnel = undefined;
            try Tunnel.init(&a, &.{ .allowed_ips = null, .static_private = &pa, .remote_static = kb.public, .preshared_key = &psk }, io, clk);
            try Tunnel.init(&b, &.{ .allowed_ips = null, .static_private = &pb, .remote_static = ka.public, .preshared_key = &psk }, io, clk);
            public(&a.static_keypair.public);
            public(&b.static_keypair.public);
            std.crypto.secureZero(u8, &ka.private);
            std.crypto.secureZero(u8, &kb.private);
            var buf: [2048]u8 = undefined;
            var buf2: [2048]u8 = undefined;
            const m1 = (try a.initiateHandshake(io, clk, &buf)).network;
            public(m1);
            const m2 = (try b.decapsulate(io, clk, m1, &buf2)).output.network;
            public(m2);
            const k = (try a.decapsulate(io, clk, m2, &buf)).output.network;
            public(k);
            _ = try b.decapsulate(io, clk, k, &buf2);
            var pkt: [64]u8 = @splat(0x33);
            pkt[0] = 0x45;
            pkt[2] = 0;
            pkt[3] = 64;
            const w = (try a.encapsulate(io, clk, &pkt, &buf)).network;
            public(w);
            const got = (try b.decapsulate(io, clk, w, &buf2)).output.tunnel;
            std.debug.print("ctgrind_result={x}\n", .{got[20..28]});
        },
    }
}
