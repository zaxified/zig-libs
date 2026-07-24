//! isis-lsdb — the IS-IS link-state database: store LSPs keyed by LSP-ID, apply
//! the ISO/IEC 10589 §7.3.15/§7.3.16 newer-LSP comparison (sequence number →
//! zero-lifetime-wins → checksum), age remaining-lifetime on a time-injected
//! tick and purge at MaxAge, and maintain the per-interface SRM (flood) / SSN
//! (acknowledge) flag sets a flooding layer consumes. Pure: no threads, no
//! owned timers, no sockets — the caller supplies `now` and drives I/O. Builds
//! on the `isis` codec; the flooding transmit loop + SPF are later consumers.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §7.3 link-state database (update process, SRM/SSN)",
    .deps = .{"isis"},
};

test "smoke" {
    try std.testing.expect(true);
}
