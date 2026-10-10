// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh quic-crypto`, which
//! builds every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-quic-crypto`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! The secrets are a 1-RTT traffic secret and everything derived from it.
//! Initial secrets are NOT: they derive from the client's Destination
//! Connection ID, which is on the wire (RFC 9001 §5.2), and the Retry
//! integrity key is a published constant (§5.8).
//!
//!  * `aes` — the traffic secret tainted, then `derivePacketKeys` (key, iv,
//!    hp), `advanceKeys` (key update), `Protection(Aes128Gcm).seal`, header
//!    protection `computeMaskAes` + `apply`, and the receiver's
//!    `computeMaskAes` + `remove` + `open` on the protected packet.
//!  * `chacha` — the same with ChaCha20-Poly1305 and `computeMaskChaCha20`.
//!
//! Header protection hides the packet-number length and the packet number
//! from observers, but `remove` must read the unmasked length to know how
//! many bytes to unmask: on a tainted mask that read is a context by
//! construction, a public value to the endpoint. The harness then marks the
//! unmasked header defined before `open`, for the same reason.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const q = @import("root.zig");

const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
const Target = enum { aes, chacha };
const Taint = enum { yes, no };

fn secretBytes(comptime n: usize, label: []const u8) [n]u8 {
    var full: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &full, .{});
    return full[0..n].*;
}

fn reloadVolatile(comptime n: usize, src: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

fn run(comptime key_len: usize, comptime Aead: type, comptime mask: anytype, secret: *const [32]u8) !void {
    const P = q.protection.Protection(Aead);
    var keys: q.PacketKeys(key_len) = undefined;
    q.derivePacketKeys(Hkdf, key_len, &keys, secret);
    var ku: q.KeyUpdate(Hkdf, key_len) = undefined;
    q.advanceKeys(Hkdf, key_len, &ku, secret);

    // A short-header packet: flags, 8-byte DCID, 2-byte packet number.
    const pn: u64 = 0x1234;
    var pkt: [128]u8 = undefined;
    pkt[0] = 0x41; // short header, pn_len = 2
    @memset(pkt[1..9], 0xab);
    std.mem.writeInt(u16, pkt[9..11], @truncate(pn), .big);
    const hdr_len = 11;
    const payload = "QUIC 1-RTT payload under a tainted key, padded to sample";
    const n = try P.seal(&keys.key, keys.iv, pn, pkt[0..hdr_len], payload, pkt[hdr_len..]);
    const total = hdr_len + n;
    // Sample starts 4 bytes after the packet-number offset (RFC 9001 §5.4.2).
    const pn_off = 9;
    try q.headerprot.apply(pkt[0..total], .short, pn_off, 2, mask(&keys.hp, pkt[pn_off + 4 ..][0..16].*));

    // Receiver.
    var rm = try q.headerprot.remove(pkt[0..total], .short, pn_off, mask(&keys.hp, pkt[pn_off + 4 ..][0..16].*));
    // Unmasked, the first byte, the packet-number length and the packet
    // number are the endpoint's public header (hidden from observers only).
    // Left tainted, every length the AEAD derives from them is an artefact.
    std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&rm));
    std.valgrind.memcheck.makeMemDefined(pkt[0 .. pn_off + 4]);
    var plain: [payload.len]u8 = undefined;
    const hl = pn_off + rm.pn_len;
    _ = try P.open(&keys.key, keys.iv, pn, pkt[0..hl], pkt[hl..total], &plain);

    std.debug.print("ctgrind_result={x}\n", .{pkt[0..total]});
    std.debug.print("ctgrind_result={x}\n", .{plain});
    std.debug.print("ctgrind_result={x}\n", .{ku.next_secret ++ ku.key ++ ku.iv});
}

fn maskAes(hp: *const [16]u8, sample: [16]u8) q.headerprot.Mask {
    return q.headerprot.computeMaskAes(hp, sample);
}

fn maskChaCha(hp: *const [32]u8, sample: [16]u8) q.headerprot.Mask {
    return q.headerprot.computeMaskChaCha20(hp, sample);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var raw = secretBytes(32, "ctgrind-quic-traffic-secret-v1");
    if (taint == .yes) std.valgrind.memcheck.makeMemUndefined(&raw);
    const secret = reloadVolatile(32, &raw);
    switch (target) {
        .aes => try run(16, std.crypto.aead.aes_gcm.Aes128Gcm, maskAes, &secret),
        .chacha => try run(32, std.crypto.aead.chacha_poly.ChaCha20Poly1305, maskChaCha, &secret),
    }
}
