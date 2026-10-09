// SPDX-License-Identifier: MIT

//! Dead-stack probe on the shared engine (`testkit.stackprobe`) for BOLT#11
//! `encode` with a raw private key (the entry point burned in the 2026-10-09
//! sweep). The older `stackprobe_test.zig` keeps the needle-based probe of the
//! whole signing path. ReleaseFast only (`skipUnlessOptimized`).

const std = @import("std");
const bolt11 = @import("bolt11.zig");
const sp = @import("testkit").stackprobe;

// Window above the deepest burn (16 KiB, one-shot per invoice).
const P = sp.Probe(.{ .window = 64 * 1024 });

var heap_buf: [64 * 1024]u8 = undefined;
var fba: std.heap.FixedBufferAllocator = undefined;
var key: [32]u8 = undefined;

const fields = [_]bolt11.TaggedFieldOut{
    .{ .payment_hash = [_]u8{0x01} ** 32 },
    .{ .payment_secret = [_]u8{0x11} ** 32 },
    .{ .description = "lninvoice dead-stack probe" },
};

test "STACKPROBE: bolt11.encode with a raw private key leaves no key in any frame" {
    try sp.skipUnlessOptimized();
    std.crypto.hash.sha2.Sha256.hash("lninvoice probe key", &key, .{});
    fba = .init(&heap_buf);
    const params: bolt11.EncodeParams = .{ .network = .testnet, .amount_msat = 1_234_000, .timestamp = 1_700_000_000, .fields = &fields };
    _ = try P.run("encode(.private_key)", bolt11.encode, .{ fba.allocator(), params, bolt11.SignInput{ .private_key = &key } }, &[_][]const u8{&key}, .{});
}
