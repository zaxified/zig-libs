//! isis-adj — the IS-IS point-to-point adjacency state machine (ISO/IEC 10589
//! §8.2 + RFC 5303 three-way handshake): a pure, time-injected FSM that drives
//! one P2P neighbour Down → Initializing → Up from received IIH PDUs (decoded
//! by the sibling `isis` codec) and hold-timer expiry. No threads, no owned
//! timers, no sockets — the caller supplies `now` and the received PDUs and
//! acts on the emitted transitions/effects. LAN adjacency + DIS election are a
//! later increment (E-Line/P2P is the current fabric phase).
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .util,
    .concurrency = .single_owner,
    .model_after = "ISO/IEC 10589 §8.2 P2P adjacency + RFC 5303 three-way handshake",
    .deps = .{"isis"},
};

test "smoke" {
    try std.testing.expect(true);
}
