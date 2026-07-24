//! isis-flood — the IS-IS flooding transmit scheduler: drain the `isis-lsdb`
//! per-interface SRM (send LSP) and SSN (send PSNP ack) flag sets into the
//! ordered list of PDUs to send, pacing LSP (re)transmissions by
//! minimumLSPTransmissionInterval and emitting periodic CSNPs for database
//! sync. Pure and time-injected — no threads, no owned timers, no sockets: the
//! caller supplies `now` + the set of interfaces with an Up adjacency and
//! performs the actual sends; this module decides WHAT to send WHEN and updates
//! the LSDB flags accordingly. P2P first (LAN DIS-driven CSNP is a later step).
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §7.3.15 flooding + §7.3.16.3/.4 transmission pacing",
    .deps = .{ "isis", "isis-lsdb" },
};

test "smoke" {
    try std.testing.expect(true);
}
