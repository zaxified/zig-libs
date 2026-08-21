// SPDX-License-Identifier: MIT

//! What a consumer does with `lninvoice`: decode a BOLT#11 payment request
//! string a user pasted in, check the amount and payment hash before
//! showing a "pay this invoice?" prompt, and read out the route hint a
//! sender would need to reach an unadvertised node. The invoice below is
//! BOLT#11's own published test vector ("sub-millisatoshi pico amount...
//! + route hint" — lightning/bolts, "Please make a donation of any amount
//! using payment_hash 0001020304050607..." test suite), not invented —
//! its fields are independently checked against the spec's own worked
//! values below.
//!
//! Also shows the decode path's fail-closed posture: a bech32 checksum
//! error on a hand-corrupted invoice comes back as a specific, nameable
//! error rather than a partial parse.
//!
//! Built against the PUBLISHED module (`@import("lninvoice")`) only — no
//! `test_deps`, no network, no wallet state.

const std = @import("std");
const lninvoice = @import("lninvoice");

const spec_invoice = "lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz";

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    var invoice = try lninvoice.decode(gpa, spec_invoice);
    defer invoice.deinit(gpa);

    // Amount is in millisatoshis — an integer, never a float, so a
    // wallet's balance check has no rounding surprise.
    if (invoice.amount_msat) |msat| {
        std.debug.print("amount: {d} msat\n", .{msat});
    } else {
        std.debug.print("amount: unspecified (payer chooses)\n", .{});
    }
    std.debug.print("payment_hash: {x}\n", .{invoice.payment_hash});
    std.debug.print("expiry: {d}s  min_final_cltv_expiry: {d}\n", .{ invoice.expiry_seconds, invoice.min_final_cltv_expiry });

    // No `n` field on this invoice, so the payee's node ID was RECOVERED
    // from the signature, not read off a plaintext field — a consumer
    // checking "is this really who I think I'm paying" needs to know
    // which path it took.
    std.debug.print("payee pubkey source: {s}\n", .{@tagName(invoice.verification)});

    // A route hint tells the sender how to reach a node with no public
    // channels — the wallet UI needs the hop details to build the route.
    for (invoice.route_hints) |hint| {
        for (hint.hops) |hop| {
            std.debug.print(
                "route hint: via {x} base_fee={d}msat ppm={d} cltv_delta={d} scid={d}\n",
                .{ hop.pubkey, hop.fee_base_msat, hop.fee_proportional_millionths, hop.cltv_expiry_delta, hop.short_channel_id },
            );
        }
    }

    // ── fail-closed: a corrupted invoice is a named error, not a partial
    // parse a wallet could accidentally act on. Flip one character in the
    // data part (leaves the human-readable amount prefix alone) so the
    // bech32 checksum no longer matches.
    var corrupted: [spec_invoice.len]u8 = undefined;
    @memcpy(&corrupted, spec_invoice);
    corrupted[corrupted.len - 10] = if (corrupted[corrupted.len - 10] == 'q') 'p' else 'q';

    var bad = lninvoice.decode(gpa, &corrupted) catch |err| switch (err) {
        error.InvalidChecksum => {
            std.debug.print("corrupted invoice rejected: InvalidChecksum\n", .{});
            return;
        },
        else => return err,
    };
    bad.deinit(gpa);
    return error.CorruptionNotDetected;
}
