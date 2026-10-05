// SPDX-License-Identifier: MIT

//! OFFLINE replay of the kernel oracle (`tools/interop.zig` +
//! `tools/kernel_oracle.py`, frozen in `kernel_oracle_vectors.zig`). Real
//! kernels in a client -> router -> server namespace topology answered every
//! attempt below -- forwarding, refusing locally (`EMSGSIZE`), sending ICMP
//! Fragmentation Needed / Packet Too Big, or saying nothing because the
//! router's firewall ate its own error. `searchWith` must ask the very same
//! sizes in the very same order and arrive at the smallest configured link
//! MTU, flagging a black hole exactly where the router was made one. No
//! namespaces at test time: the replay requires the kernels' own answers.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const vectors = @import("kernel_oracle_vectors.zig");

/// Answers each size with what the kernel answered, in order; any departure
/// from the recorded sequence is a failure, not a guess.
const TranscriptProber = struct {
    attempts: []const vectors.Attempt,
    next: usize = 0,
    diverged: bool = false,

    fn prober(self: *TranscriptProber) root.Prober {
        return .{ .ctx = self, .probeFn = probeFn };
    }

    fn probeFn(ctx: *anyopaque, wire_size: u16) root.ProbeOutcome {
        const self: *TranscriptProber = @ptrCast(@alignCast(ctx));
        if (self.next >= self.attempts.len or self.attempts[self.next].size != wire_size) {
            self.diverged = true;
            return .send_failed;
        }
        defer self.next += 1;
        return self.attempts[self.next].outcome;
    }
};

test "kernel oracle: searchWith replays every real transcript to the configured link MTU" {
    try testing.expect(vectors.scenarios.len >= 20);
    var blackholes: usize = 0;
    for (vectors.scenarios) |sc| {
        // `probe` searches from the protocol floor to the interface MTU.
        const floor: u16 = if (sc.v6) root.min_mtu_v6 else root.min_mtu_v4;
        try testing.expectEqual(floor, sc.attempts[0].size);
        try testing.expectEqual(sc.client_mtu, sc.attempts[1].size);

        var tp: TranscriptProber = .{ .attempts = sc.attempts };
        const r = try root.searchWith(tp.prober(), floor, sc.client_mtu, sc.client_mtu);
        if (tp.diverged or tp.next != sc.attempts.len)
            std.debug.print("{s}: replay left the transcript at attempt {d} of {d}\n", .{ sc.name, tp.next, sc.attempts.len });
        try testing.expect(!tp.diverged);
        try testing.expectEqual(sc.attempts.len, tp.next);
        try testing.expectEqual(@as(u32, sc.truth), r.mtu);
        try testing.expectEqual(sc.blackhole, r.blackhole);
        try testing.expectEqual(sc.mtu, r.mtu);
        try testing.expectEqual(sc.flagged, r.blackhole);
        if (sc.blackhole) {
            blackholes += 1;
            // The blind spot this module exists for, on a real kernel: the
            // cache and iputils tracepath both still read the interface MTU.
            try testing.expectEqual(@as(u32, sc.client_mtu), sc.query_after);
        } else {
            try testing.expectEqual(@as(u32, sc.truth), sc.query_after);
            try testing.expectEqual(@as(?u32, sc.truth), sc.tracepath);
        }
    }
    try testing.expect(blackholes >= 4);
}
