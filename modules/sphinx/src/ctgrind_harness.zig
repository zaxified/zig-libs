// SPDX-License-Identifier: MIT

//! ctgrind_harness — constant-time evidence for `SPEC.md`'s "Constant-time
//! scope" paragraph, as an actual committed program rather than a claim
//! backed only by reading the code once. Not wired into `zig build
//! test-sphinx` — memcheck's context count is valgrind's own verdict, not
//! something a Zig test can assert on.
//!
//! Suggested `scripts/ctgrind.sh` config (NOT added here — the shared script
//! is coordinator-owned while other harnesses are in flight; see the
//! per-module block below for the exact lines):
//!
//!   TARGETS[sphinx]="construct process"
//!   MODES[sphinx]="ReleaseFast"
//!   PATTERN[sphinx/construct]='core[.]zig|keyderive[.]zig|hopframe[.]zig|bigsize[.]zig|group[.]zig|field[.]zig|scalar[.]zig|common[.]zig'
//!   PATTERN[sphinx/process]='core[.]zig|keyderive[.]zig|hopframe[.]zig|bigsize[.]zig|group[.]zig|field[.]zig|common[.]zig'
//!   LABEL[sphinx/construct]='sphinx construct (session_key fwd chain)+k256'
//!   LABEL[sphinx/process]='sphinx process (relay privkey unwrap)+k256'
//!
//! ## The two targets, and which claim each pins
//!
//! Sphinx has exactly two places a real secret enters the module's public
//! API (SPEC.md "Constant-time scope"):
//!
//! * `construct` — the SENDER's per-packet ephemeral `session_key`, entering
//!   `core.construct`. It seeds `deriveHopSecrets`'s forward chain (ECDH via
//!   `k256`'s `Secp256k1.mul`/`.combMulBase`, the `SHA256`-derived blinding
//!   factor, `Secp256k1.scalar.mul` for the next ephemeral scalar) and then
//!   drives `construct`'s reverse-order wrap loop (`keyderive.generateKey`/
//!   `.generateCipherStream`, `hopframe.rightShift`/`.writeHopFrame`,
//!   `HmacSha256`). Every per-hop shared secret is a pure function of this
//!   one input plus the (untainted, public) route pubkeys, so tainting only
//!   `session_key` exercises the whole forward chain without a separate
//!   target for "the shared secrets" — they have no other source.
//! * `process` — a RELAY's `node_privkey`, entering `core.process` against
//!   the real, published BOLT#4 onion packet (`kat_vectors.onion`, hop 0 of
//!   5 — NOT the final hop, so the "forward vs. this-is-mine" branch below
//!   is actually exercised with a real, non-degenerate `next_hmac`). This is
//!   the interesting side per the audit brief: it covers the receiver-
//!   direction ECDH, the constant-time HMAC gate
//!   (`std.crypto.timing_safe.eql`, `core.zig:437`), the ChaCha20
//!   deobfuscation, `hopframe.readHopFrame`'s bigsize/length parse, the
//!   `std.mem.allEqual` all-zero check that decides "this is the final
//!   destination" vs. "forward onward" (`core.zig:472`), and the re-blinding
//!   point-multiply for the outgoing packet.
//!
//! Both targets use the REAL, published KAT fixture (`kat_vectors.zig`) for
//! every value that is not the one being tainted — the route pubkeys,
//! payloads and associated_data for `construct`; the onion packet and
//! associated_data for `process`. Nothing here fabricates curve points or
//! ciphertexts by hand: the only hex-decoding in this file is turning the
//! KAT's own hex strings into bytes, exactly as `kat_test.zig` already does.
//!
//! ## What this does NOT taint, on purpose
//!
//! `construct`'s hop pubkeys and payloads, and `process`'s packet bytes, are
//! all PUBLIC (an adversary who relays the packet sees every byte of it).
//! Tainting them would manufacture branches that say nothing about a secret
//! leak — the brief's own instruction. The one exception `process` makes is
//! implicit, not explicit: `pkt.hop_payloads`/`pkt.hmac` are public going
//! IN, but everything `process` derives from them via the tainted
//! `node_privkey` (the shared secret, the deobfuscated plaintext, the
//! outgoing `next_hmac`) inherits the taint through data flow — which is
//! exactly why the "final hop?" check and the frame parse are reachable from
//! this harness without tainting the packet itself.
//!
//! ## The two traps (see `ct25519`'s harness for the fuller writeup)
//!
//! 1. Without `-fvalgrind`, `std.valgrind.doClientRequest` is a no-op outside
//!    Debug, so a build without it reads 0 for every row regardless of what
//!    the code does. Build both ways; the no-`-fvalgrind` row is the trap.
//! 2. `reloadVolatile` forces one real load from freshly-tainted memory
//!    immediately before the call under test, so the optimizer cannot feed
//!    the ladder/HMAC/ChaCha20 a defined copy left over from before
//!    `makeMemUndefined` ran.
//!
//! ## The propagation witness
//!
//! Both targets format their result through `std.debug.print`, which is not
//! constant-time by design — a tainted byte reaching it is the propagation
//! proof that makes an in-file zero mean "no branch found" rather than "the
//! taint never arrived".

const std = @import("std");
const builtin = @import("builtin");
const sphinx = @import("root.zig");
const v = @import("kat_vectors.zig");

/// Decode a fixed-length hex string (the KAT fixture's own encoding) into
/// exactly `n` bytes. Plain test-fixture plumbing, not a stand-in for any
/// crypto primitive.
fn hexN(comptime n: usize, hex_str: []const u8) [n]u8 {
    var out: [n]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, hex_str) catch unreachable;
    return out;
}

/// Decode a variable-length hex string into `buf`, returning the written
/// subslice — mirrors `kat_test.zig`'s `hexInto`.
fn hexInto(buf: []u8, hex_str: []const u8) []u8 {
    const n = hex_str.len / 2;
    _ = std.fmt.hexToBytes(buf[0..n], hex_str) catch unreachable;
    return buf[0..n];
}

fn taintIf(cond: bool, bytes: []u8) void {
    if (cond) std.valgrind.memcheck.makeMemUndefined(bytes);
}

/// Forces one real load from `s` through a volatile pointer, byte at a time,
/// so the code under test cannot be fed a copy that predates
/// `makeMemUndefined` (trap 2 above).
fn reloadVolatile(comptime n: usize, s: *const [n]u8) [n]u8 {
    var out: [n]u8 = undefined;
    for (&out, s) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

const Target = enum { construct, process };
const Taint = enum { yes, no };

fn parseTarget(s: []const u8) !Target {
    if (std.mem.eql(u8, s, "construct")) return .construct;
    if (std.mem.eql(u8, s, "process")) return .process;
    return error.UnknownTarget;
}

fn parseTaint(s: []const u8) !Taint {
    if (std.mem.eql(u8, s, "yes")) return .yes;
    if (std.mem.eql(u8, s, "no")) return .no;
    return error.UnknownTaint;
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = try parseTarget(it.next() orelse return error.MissingTarget);
    const tainted = (try parseTaint(it.next() orelse return error.MissingTaint)) == .yes;

    std.debug.print("valgrind_support={}\n", .{builtin.valgrind_support});

    switch (target) {
        .construct => {
            // The SENDER's per-packet ephemeral secret. Everything else fed
            // to `construct` below (route pubkeys, TLV payloads, associated
            // data) is the real published KAT fixture and stays untainted —
            // it is public route information the sender chose, not secret
            // material.
            var sk = hexN(32, v.session_key);
            taintIf(tainted, &sk);
            const session_key = reloadVolatile(32, &sk);

            var pk_storage: [5][sphinx.pubkey_len]u8 = undefined;
            inline for (v.pubkeys, 0..) |hex, i| pk_storage[i] = hexN(sphinx.pubkey_len, hex);

            // Strip each payload's own bigsize length prefix -- `construct`
            // takes the raw TLV content and re-adds it via
            // `hopframe.writeHopFrame` (see kat_test.zig's `katPayloadTlvs`,
            // duplicated here rather than imported since it is private to
            // that file).
            var pl_storage: [5][300]u8 = undefined;
            var tlvs: [5][]const u8 = undefined;
            inline for (v.payloads, 0..) |hex, i| {
                const bytes = hexInto(&pl_storage[i], hex);
                const len_field = sphinx.bigsize.read(bytes) catch unreachable;
                tlvs[i] = bytes[len_field.len..];
            }

            const associated_data = hexN(32, v.associated_data);

            const pkt = try sphinx.construct(session_key, &pk_storage, &tlvs, &associated_data);

            // Propagation witness: both fields are downstream of the whole
            // forward chain + reverse wrap loop.
            std.debug.print("pubkey={x}\nhmac={x}\n", .{ pkt.public_key, pkt.hmac });
        },
        .process => {
            // The RELAY's node private key -- the other of the two real
            // secrets this module ever handles. `pkt`/`associated_data` are
            // the real published onion packet: public bytes an adversary on
            // the wire already sees.
            var pv = hexN(32, v.node_privkeys[0]);
            taintIf(tainted, &pv);
            const node_privkey = reloadVolatile(32, &pv);

            const pkt = try sphinx.OnionPacket.fromBytes(hexN(sphinx.packet_len, v.onion));
            const associated_data = hexN(32, v.associated_data);

            // Hop 0 of 5: NOT the final hop, so `result.next_packet` is
            // non-null and the "final hop?" all-zero check inside `process`
            // (core.zig's `std.mem.allEqual(u8, &frame.hmac, 0)`) actually
            // runs its "false" path against a real, non-degenerate
            // `next_hmac` -- the exact branch the audit brief flagged as the
            // interesting one (it decides "deliver here" vs. "forward").
            const result = try sphinx.process(node_privkey, pkt, &associated_data);

            std.debug.print("payload_len={d} has_next={}\n", .{
                result.payload_len,
                result.next_packet != null,
            });
        },
    }
}
