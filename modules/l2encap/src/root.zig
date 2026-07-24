//! l2encap — tenant-tagged L2-over-tunnel encapsulation for a multi-tenant
//! L2VPN fabric: wrap a customer Ethernet frame with a lean, versioned header
//! carrying a 24-bit I-SID (tenant service identifier), a TTL, and BUM /
//! split-horizon control bits, for transport over an encrypted backbone
//! (WireGuard). Bounds-checked decode of untrusted tunnel payloads. Composes
//! with `ethfrag` (fragment the encapsulated payload) and feeds `wireguard`.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "802.1ah PBB I-TAG (I-SID) / VXLAN-Geneve VNI, lean over-WG variant",
    .deps = .{},
};

test "smoke" {
    try std.testing.expect(true);
}
