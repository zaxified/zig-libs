// SPDX-License-Identifier: MIT

//! What a provider edge (PE) does with `tenantkex`: run a Noise_IK
//! handshake with a peer PE for one tenant's I-SID, get back the two
//! directional transport keys, and confirm they line up (initiator's
//! send key is the responder's recv key, and vice versa) — the exact
//! orientation `aeadframe`'s Sealer/Opener would be fed on each side.
//! Then show tenant isolation working: a responder configured for a
//! DIFFERENT I-SID fails the handshake by name rather than completing
//! it against the wrong tenant.
//!
//! Built by `zig build check-examples` against the PUBLISHED module — no
//! access to anything `tenantkex` (or its declared dep `noise`) does not
//! export.

const std = @import("std");
const tenantkex = @import("tenantkex");

pub fn main() !void {
    // Fixed seeds keep this example reproducible; a real PE draws its
    // long-term static key once at provisioning time from a CSPRNG.
    const pe1_static = try tenantkex.KeyPair.generateDeterministic([_]u8{0x31} ** 32);
    const pe2_static = try tenantkex.KeyPair.generateDeterministic([_]u8{0x42} ** 32);

    const ctx: tenantkex.FabricContext = .{ .isid = 0x00_10_20, .initiator_pe = 1, .responder_pe = 2 };

    var initiator = tenantkex.Initiator.init(pe1_static, pe2_static.public_key, ctx);
    defer initiator.wipe();
    var responder = tenantkex.Responder.init(pe2_static, ctx);
    defer responder.wipe();

    var rng_i = std.Random.DefaultPrng.init(0xC0FFEE);
    var rng_r = std.Random.DefaultPrng.init(0xDECAFBAD);

    var msg1: [tenantkex.message1Len(0)]u8 = undefined;
    var msg2: [tenantkex.message2Len(0)]u8 = undefined;
    var payload_out: [16]u8 = undefined;

    const n1 = try initiator.writeMessage1(rng_i.random(), "", &msg1);
    _ = try responder.readMessage1(msg1[0..n1], &payload_out);

    const fin_r = try responder.writeMessage2(rng_r.random(), "", &msg2);
    var fin_r_keys = fin_r.keys;
    defer fin_r_keys.wipe();
    const fin_i = try initiator.readMessage2(msg2[0..fin_r.len], &payload_out);
    var fin_i_keys = fin_i.keys;
    defer fin_i_keys.wipe();

    std.debug.print("session established, {d}-byte + {d}-byte handshake\n", .{ n1, fin_r.len });
    std.debug.print("initiator.send == responder.recv: {}\n", .{
        std.mem.eql(u8, &fin_i_keys.send_key, &fin_r_keys.recv_key),
    });
    std.debug.print("initiator.recv == responder.send: {}\n", .{
        std.mem.eql(u8, &fin_i_keys.recv_key, &fin_r_keys.send_key),
    });
    std.debug.print("transcript hash matches on both sides: {}\n", .{
        std.mem.eql(u8, &fin_i_keys.transcript_hash, &fin_r_keys.transcript_hash),
    });

    // Tenant isolation: a responder provisioned for a DIFFERENT I-SID must
    // reject the same initiator's msg1 — the prologue mismatch breaks the
    // encrypted static-key token's AEAD tag, which is exactly what scopes
    // a completed session to one tenant.
    const wrong_ctx: tenantkex.FabricContext = .{ .isid = 0x00_99_99, .initiator_pe = 1, .responder_pe = 2 };
    var stray_initiator = tenantkex.Initiator.init(pe1_static, pe2_static.public_key, ctx);
    defer stray_initiator.wipe();
    var mismatched_responder = tenantkex.Responder.init(pe2_static, wrong_ctx);
    defer mismatched_responder.wipe();

    var rng2 = std.Random.DefaultPrng.init(0xABCDEF01);
    var stray_msg1: [tenantkex.message1Len(0)]u8 = undefined;
    const sn1 = try stray_initiator.writeMessage1(rng2.random(), "", &stray_msg1);
    if (mismatched_responder.readMessage1(stray_msg1[0..sn1], &payload_out)) |_| {
        std.debug.print("unexpectedly accepted a cross-tenant handshake\n", .{});
    } else |err| switch (err) {
        error.DecryptionFailed => std.debug.print(
            "cross-tenant handshake correctly rejected (DecryptionFailed)\n",
            .{},
        ),
        else => return err,
    }
}
