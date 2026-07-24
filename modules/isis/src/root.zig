//! isis — IS-IS (ISO/IEC 10589) PDU codec: the common header + the TLV
//! framework + the IIH (Hello) and LSP PDUs + the SPB (802.1aq) TLVs, with a
//! raw/unknown-TLV escape hatch. Pure, bounds-checked encode/decode of
//! untrusted link bytes — the wire foundation the SPB control plane (adjacency
//! FSM, LSP DB, flooding) builds on. No state machine here; codec only.
//!
//! Placeholder: pre-wired by the coordinator; core implementation pending.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "ISO/IEC 10589 IS-IS + IEEE 802.1aq (SPB) TLVs; frrouting isisd wire",
    .deps = .{},
};

test "smoke" {
    try std.testing.expect(true);
}
