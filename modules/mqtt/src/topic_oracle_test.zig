// SPDX-License-Identifier: MIT

//! OFFLINE anchor for `topic.zig`: what a real Eclipse Mosquitto broker
//! (2.1.2) answered over a raw MQTT 5.0 socket -- which filters it grants,
//! which names it accepts a QoS 1 PUBLISH to, and for every valid pair
//! whether the filter's subscription received the name (each filter carried
//! its own Subscription Identifier). Taken by `tools/topic_oracle.py` into
//! `topic_vectors.zig`; replayed here with no broker and no socket.
//!
//! Mosquitto is an oracle, not an authority: a deliberate difference is
//! listed with the judgement, an unlisted one fails.

const std = @import("std");
const testing = std.testing;
const topic = @import("topic.zig");
const vectors = @import("topic_vectors.zig");

const Divergence = struct { s: []const u8, why: []const u8 };

/// Filters/names where `validateFilter`/`validateName` deliberately answer
/// differently from the broker.
const validity_divergences = [_]Divergence{
    .{ .s = "$share", .why = "a Shared Subscription is `$share/{ShareName}/{filter}` (MQTT 5.0 4.8.2); `$share` alone is an ordinary filter by 4.7 and this module (topic.zig and Broker) grants it. Mosquitto refuses any filter that starts with `$share` and is not a well-formed shared one; it grants `$sharex/a`" },
};

fn listed(s: []const u8) bool {
    for (validity_divergences) |d| if (std.mem.eql(u8, d.s, s)) return true;
    return false;
}

test "topic oracle: validateFilter grants what Mosquitto grants" {
    var failed: usize = 0;
    for (vectors.filters) |f| {
        const ours = if (topic.validateFilter(f.s)) |_| true else |_| false;
        if ((ours != f.valid) != listed(f.s)) {
            std.debug.print("topic oracle: filter \"{f}\": ours {}, mosquitto {}{s}\n", .{ std.zig.fmtString(f.s), ours, f.valid, if (listed(f.s)) " (listed, agrees now)" else "" });
            failed += 1;
        }
    }
    if (failed != 0) return error.TopicOracleDisagrees;
}

test "topic oracle: validateName accepts what Mosquitto accepts" {
    var failed: usize = 0;
    for (vectors.names) |n| {
        const ours = if (topic.validateName(n.s)) |_| true else |_| false;
        if ((ours != n.valid) != listed(n.s)) {
            std.debug.print("topic oracle: name \"{f}\": ours {}, mosquitto {}{s}\n", .{ std.zig.fmtString(n.s), ours, n.valid, if (listed(n.s)) " (listed, agrees now)" else "" });
            failed += 1;
        }
    }
    if (failed != 0) return error.TopicOracleDisagrees;
}

test "topic oracle: matches agrees with Mosquitto's delivery on every valid pair" {
    var failed: usize = 0;
    var pairs: usize = 0;
    for (vectors.matches) |m| {
        for (vectors.filters, 0..) |f, i| {
            if (!f.valid) continue;
            pairs += 1;
            const delivered = std.mem.indexOfScalar(u16, m.filters, @intCast(i)) != null;
            if (topic.matches(f.s, m.name) != delivered) {
                std.debug.print("topic oracle: \"{f}\" on \"{f}\": ours {}, mosquitto delivered {}\n", .{ std.zig.fmtString(f.s), std.zig.fmtString(m.name), !delivered, delivered });
                failed += 1;
            }
        }
    }
    try testing.expect(pairs > 500);
    if (failed != 0) return error.TopicOracleDisagrees;
}
