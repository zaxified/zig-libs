// SPDX-License-Identifier: MIT

//! What an IS-IS LAN adjacency manager does with `isis-dis`: track the set
//! of routers with an Up LAN adjacency, drive the DIS election on every
//! membership change, and react to the emitted `became_dis`/`resigned_dis`
//! effects — the trigger to start or stop originating this LAN's
//! pseudonode LSP.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling. The module's own tests cannot notice
//! either, because they live inside it.
//!
//! Note: `isis-dis`'s public surface (`elect`, `Election.recompute`,
//! `Result.pseudonodeLspId`) is entirely infallible — pure functions over
//! caller-owned data, no allocation, no I/O — so there is no error to name
//! from outside; this example exercises the state machine's effects
//! instead.

const std = @import("std");
const isis_dis = @import("isis-dis");

fn snpa(last: u8) isis_dis.Snpa {
    return .{ 0x00, 0x00, 0x00, 0x00, 0x00, last };
}

/// This router, configured with pseudonode id 1 for this circuit.
const local: isis_dis.Candidate = .{
    .system_id = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A },
    .priority = 64,
    .snpa = snpa(0xAA),
    .pseudonode_id = 1,
};

fn reportEffect(label: []const u8, eff: isis_dis.Effect) void {
    const dis_hex = std.fmt.bytesToHex(eff.result.dis_system_id, .lower);
    std.debug.print("{s}: dis={s} local_dis={}", .{
        label,
        &dis_hex,
        eff.result.is_local_dis,
    });
    if (eff.change) |c| {
        std.debug.print(" [change: became_dis={} resigned_dis={} at={d}]", .{ c.became_dis, c.resigned_dis, c.at });
    }
    std.debug.print("\n", .{});
}

pub fn main() !void {
    var election = isis_dis.Election.init(local);

    // t=1: local is alone on the LAN → local becomes DIS.
    const s0 = election.recompute(&.{}, 1);
    reportEffect("t=1 (alone)", s0);
    std.debug.assert(s0.result.is_local_dis);
    std.debug.assert(s0.change.?.became_dis);

    // t=2: a neighbour with equal priority but a lower SNPA joins — local
    // still wins the tie-break, no change.
    const weaker: isis_dis.Candidate = .{
        .system_id = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x0B },
        .priority = 64,
        .snpa = snpa(0x10),
    };
    const s1 = election.recompute(&.{weaker}, 2);
    reportEffect("t=2 (weaker neighbour)", s1);
    std.debug.assert(s1.change == null);

    // t=3: a higher-priority router appears → immediate preemption, no
    // hold-down (unlike OSPF's DR) — local must resign right away.
    const king: isis_dis.Candidate = .{
        .system_id = .{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D },
        .priority = 127,
        .snpa = snpa(0x01),
        .pseudonode_id = 9,
    };
    const s2 = election.recompute(&.{ weaker, king }, 3);
    reportEffect("t=3 (king arrives)", s2);
    std.debug.assert(!s2.result.is_local_dis);
    std.debug.assert(s2.change.?.resigned_dis);

    // The new DIS's pseudonode LSP-ID — what a real listener would purge
    // its OWN pseudonode LSP against, and what it would start tracking for
    // the new DIS's LSPs.
    const lsp_id = s2.result.pseudonodeLspId();
    const lsp_hex = std.fmt.bytesToHex(lsp_id, .lower);
    std.debug.print("new DIS pseudonode LSP-ID: {s}\n", .{&lsp_hex});

    // t=4: the king leaves → local resumes DIS immediately.
    const s3 = election.recompute(&.{weaker}, 4);
    reportEffect("t=4 (king departs)", s3);
    std.debug.assert(s3.result.is_local_dis);
    std.debug.assert(s3.change.?.became_dis);
}
