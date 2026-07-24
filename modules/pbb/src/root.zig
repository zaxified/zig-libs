//! pbb — IEEE 802.1ah Provider Backbone Bridge (MAC-in-MAC) encapsulation codec:
//! wrap a customer Ethernet frame in a backbone header (B-DA, B-SA, optional
//! B-Tag / B-VID) + the I-TAG carrying the 24-bit I-SID service instance, and
//! decode it back. The real-Ethernet SPB (802.1aq) data-plane encapsulation —
//! distinct from the sibling `l2encap`, which is the lean L2-over-WireGuard
//! variant that drops the backbone MACs. Pure, bounds-checked decode of
//! untrusted link bytes.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "IEEE 802.1ah PBB (MAC-in-MAC) I-TAG frame format",
    .deps = .{},
};

test "smoke" {
    try std.testing.expect(true);
}
