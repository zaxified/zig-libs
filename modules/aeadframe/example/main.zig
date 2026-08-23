// SPDX-License-Identifier: MIT

//! What a per-tenant L2VPN gateway does with `aeadframe`: one `Sealer`/
//! `Opener` pair per I-SID, sealing frames bound to that tenant's context
//! string so a cross-tenant open fails even under the same wire, then
//! demonstrating the two events a receiver must survive without crashing:
//! a replayed frame and an epoch rollover after rekey.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.

const std = @import("std");
const af = @import("aeadframe");

fn key(seed: u8) [32]u8 {
    var k: [32]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = seed +% @as(u8, @intCast(i));
    return k;
}

pub fn main() !void {
    const tenant_a = "isid:0x1A2B3C";
    const shared_key = key(0x42);

    var sealer = af.ChaChaChannel.Sealer.init(shared_key, 0);
    var opener = af.ChaChaChannel.Opener.init(shared_key, 0);
    defer sealer.wipe();
    defer opener.wipe();

    const msg = "l2 frame payload for tenant A";
    var rec: [af.ChaChaChannel.Sealer.sealedLen(msg.len)]u8 = undefined;
    const n = try sealer.seal(&rec, msg, tenant_a);
    std.debug.print("sealed {d} bytes for {s}\n", .{ n, tenant_a });

    var pt: [msg.len]u8 = undefined;
    const m = try opener.open(&pt, rec[0..n], tenant_a);
    std.debug.print("opened: \"{s}\"\n", .{pt[0..m]});

    // A record cannot cross a tenant boundary: wrong aad must be nameable
    // from outside, not just observable as "some error". This must be a
    // FRESH record (an unconsumed sequence number) — `open`'s doc comment
    // spells out its check order as parse -> epoch -> replay pre-check ->
    // AEAD verify -> commit, so the replay window is consulted BEFORE
    // authentication (deliberately: a known-replayed record is rejected
    // without paying for a decrypt). Reusing the already-opened `rec` here
    // would hit `error.Replayed` before the AAD mismatch is ever checked.
    var rec_x: [af.ChaChaChannel.Sealer.sealedLen(msg.len)]u8 = undefined;
    const nx = try sealer.seal(&rec_x, msg, tenant_a);
    if (opener.open(&pt, rec_x[0..nx], "isid:0xFFFFFF")) |_| {
        return error.CrossTenantOpenUnexpectedlySucceeded;
    } else |err| switch (err) {
        error.AuthenticationFailed => std.debug.print("cross-tenant open correctly rejected\n", .{}),
        else => return err,
    }

    // A duplicate delivery of the same record (network retransmit, replayed
    // attacker capture) must be rejected by the sliding-window filter.
    if (opener.open(&pt, rec[0..n], tenant_a)) |_| {
        return error.ReplayedOpenUnexpectedlySucceeded;
    } else |err| switch (err) {
        error.Replayed => std.debug.print("replayed frame correctly rejected\n", .{}),
        else => return err,
    }

    // Epoch rollover: same key, both sides bump together, sequence space
    // resets, and the old epoch's records are no longer accepted.
    try sealer.bumpEpoch();
    try opener.bumpEpoch();
    var rec2: [af.ChaChaChannel.Sealer.sealedLen(msg.len)]u8 = undefined;
    const n2 = try sealer.seal(&rec2, msg, tenant_a);
    const m2 = try opener.open(&pt, rec2[0..n2], tenant_a);
    std.debug.print("post-rekey epoch {d}: opened {d} bytes\n", .{ opener.epoch, m2 });

    // The pre-rollover record is now stale under the new epoch.
    if (opener.open(&pt, rec[0..n], tenant_a)) |_| {
        return error.StaleEpochOpenUnexpectedlySucceeded;
    } else |err| switch (err) {
        error.EpochMismatch => std.debug.print("stale-epoch frame correctly rejected\n", .{}),
        else => return err,
    }
}
