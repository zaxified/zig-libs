// SPDX-License-Identifier: MIT

//! OFFLINE replay of the NTP oracle (`tools/interop.zig` +
//! `tools/ntp_oracle.py` + `tools/go_oracle`, frozen in
//! `ntp_oracle_vectors.zig`). A real chronyd 4.8 sent every reply below --
//! synchronized at stratum 3 and 10 to requests of versions 1-4, its
//! unsynchronized answer, the replies and Kiss-o'-Death RATE packets of its
//! rate limiter -- with the T1 this module stamped and the T4 it read; each
//! verdict was judged against the server's configuration, against
//! beevik/ntp's on the same server and, for offset and delay, against
//! ntplib on the very same bytes. `decodeResponse` and `Sample` must reach
//! the very same verdicts. No server at test time.

const std = @import("std");
const testing = std.testing;
const root = @import("root.zig");
const vectors = @import("ntp_oracle_vectors.zig");

test "ntp oracle: every recorded chronyd reply decodes to the verdict the oracle judged" {
    var ok: usize = 0;
    var kisses: usize = 0;
    var unsynced: usize = 0;
    for (vectors.exchanges) |x| {
        var kod: root.KissOfDeath = undefined;
        if (root.decodeResponse(x.reply, &kod)) |r| {
            const want = x.verdict.ok;
            try root.verifyOriginate(r, x.t1);
            const sample: root.Sample = .{ .originate = x.t1, .receive = r.receive, .transmit = r.transmit, .destination = x.t4 };
            try testing.expectEqual(want.stratum, r.stratum);
            try testing.expectEqual(want.offset_ns, sample.offsetNanos());
            try testing.expectEqual(want.roundtrip_ns, sample.roundtripDelayNanos());
            ok += 1;
        } else |e| switch (x.verdict) {
            .ok => return e,
            .kiss => |code| {
                try testing.expectEqual(error.KissOfDeath, e);
                try testing.expectEqual(code, kod.code);
                kisses += 1;
            },
            .err => |want| {
                try testing.expectEqual(want, e);
                if (e == error.UnsynchronizedLeap) unsynced += 1;
            },
        }
    }
    try testing.expect(ok >= 15);
    try testing.expect(kisses >= 1);
    try testing.expect(unsynced >= 1);
}
