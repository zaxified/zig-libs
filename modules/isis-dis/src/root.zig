//! isis-dis — IS-IS LAN Designated-IS (DIS) election (ISO/IEC 10589 §7.2.6 /
//! §8.4.5): a pure, time-injected function/FSM that, from the set of routers
//! seen on a LAN circuit (each with its priority + SNPA/MAC, from LAN Hellos),
//! elects the DIS — highest priority, SNPA as the tie-break, with immediate
//! preemption (no hold-down: IS-IS DIS has no backoff, unlike OSPF DR) — reports
//! whether THIS system is the DIS, and derives the pseudonode LSP-ID the DIS
//! originates. No threads, no owned timers, no sockets — the caller supplies the
//! neighbour view + `now` and acts on the emitted DIS-change effect. Pairs with
//! the P2P `isis-adj`/`isis-lsdb`/`isis-flood`/`isis-spf` stack to add LAN.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §8.4.5 LAN DIS election (priority + SNPA, preemptive)",
    .deps = .{"isis"},
};

test "smoke" {
    try std.testing.expect(true);
}
