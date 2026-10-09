// SPDX-License-Identifier: MIT

//! Test-only value-shaped wrappers over the pointer/`out` API, so a KAT can
//! write `tu.keyPair(seed)` instead of three lines of `var`/`&`/`try`. The
//! tests keep these secrets in their own frames on purpose; the dead-stack
//! guarantee is about the library entry points, probed in
//! `stackprobe_test.zig` / `stackprobe2_test.zig`. Imported from tests only.

const dh = @import("dh.zig");
const handshake = @import("handshake.zig");
const transport = @import("transport.zig");

pub fn tryKeyPair(seed: [32]u8) dh.SecretKeyError!dh.KeyPair {
    var kp: dh.KeyPair = undefined;
    try dh.KeyPair.generateDeterministic(&kp, &seed);
    return kp;
}

pub fn keyPair(seed: [32]u8) dh.KeyPair {
    return tryKeyPair(seed) catch unreachable;
}

pub fn initiator(ls: *const dh.KeyPair, rs_pub: [33]u8) handshake.Initiator {
    var i: handshake.Initiator = undefined;
    handshake.Initiator.init(&i, ls, rs_pub);
    return i;
}

pub fn responder(ls: *const dh.KeyPair) handshake.Responder {
    var r: handshake.Responder = undefined;
    handshake.Responder.init(&r, ls);
    return r;
}

pub fn transportOf(result: handshake.HandshakeResult) transport.Transport {
    var t: transport.Transport = undefined;
    transport.Transport.init(&t, &result);
    return t;
}
