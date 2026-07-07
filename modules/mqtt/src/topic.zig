// SPDX-License-Identifier: MIT

//! MQTT 3.1.1 topic names and topic filters (spec section 4.7).
//!
//! - `matches(filter, topic)` — the wildcard rules: `+` matches exactly one
//!   level, `#` matches any number of trailing levels (including the parent
//!   level itself), and a filter whose *first* level is a wildcard never
//!   matches a `$`-prefixed topic (`$SYS/...`).
//! - `validateName` / `validateFilter` — syntactic validity per the spec:
//!   1–65 535 bytes of well-formed UTF-8, no U+0000; names carry no
//!   wildcards; in filters `#` may only be the whole last level and `+`
//!   must occupy a whole level.
//!
//! Provenance: clean-room from the OASIS MQTT Version 3.1.1 specification.

const std = @import("std");
const packet = @import("packet.zig");

/// Topic names and filters share the UTF-8 string limit (spec 4.7.3).
pub const max_topic_len: usize = packet.max_string_len;

pub const NameError = error{InvalidTopicName};
pub const FilterError = error{InvalidTopicFilter};

fn wellFormed(s: []const u8) bool {
    if (s.len == 0 or s.len > max_topic_len) return false;
    return packet.wellFormedString(s);
}

/// Validate a topic *name* (as used in PUBLISH): non-empty, well-formed
/// UTF-8, no U+0000, and no `+` / `#` wildcard characters (spec 4.7.1-1).
pub fn validateName(name: []const u8) NameError!void {
    if (!wellFormed(name)) return error.InvalidTopicName;
    if (std.mem.indexOfAny(u8, name, "+#") != null) return error.InvalidTopicName;
}

/// Validate a topic *filter* (as used in SUBSCRIBE / UNSUBSCRIBE):
/// non-empty, well-formed UTF-8, no U+0000; `#` only as the entire last
/// level (spec 4.7.1-2); `+` only as an entire level (spec 4.7.1-3).
pub fn validateFilter(filter: []const u8) FilterError!void {
    if (!wellFormed(filter)) return error.InvalidTopicFilter;
    var levels = std.mem.splitScalar(u8, filter, '/');
    var saw_hash = false;
    while (levels.next()) |level| {
        if (saw_hash) return error.InvalidTopicFilter; // '#' was not last
        if (std.mem.eql(u8, level, "#")) {
            saw_hash = true;
            continue;
        }
        if (std.mem.eql(u8, level, "+")) continue;
        if (std.mem.indexOfAny(u8, level, "+#") != null) return error.InvalidTopicFilter;
    }
}

/// Does `filter` match `topic` under the MQTT wildcard rules (spec 4.7)?
///
/// Matching is level-by-level on `/`-separated segments; comparison is
/// byte-exact (no case folding, no normalization — spec 4.7.3). Both inputs
/// are assumed syntactically valid (see `validateFilter` / `validateName`);
/// invalid inputs still never cause a panic, only an unspecified boolean.
pub fn matches(filter: []const u8, topic: []const u8) bool {
    // A filter starting with a wildcard never matches a $-topic (4.7.2-1).
    if (topic.len > 0 and topic[0] == '$' and
        filter.len > 0 and (filter[0] == '#' or filter[0] == '+'))
    {
        return false;
    }
    var f = std.mem.splitScalar(u8, filter, '/');
    var t = std.mem.splitScalar(u8, topic, '/');
    while (true) {
        const fl = f.next() orelse return t.next() == null;
        // "sport/#" also matches "sport" — check '#' before consuming a
        // topic level (spec 4.7.1-2 example).
        if (std.mem.eql(u8, fl, "#")) return true;
        const tl = t.next() orelse return false;
        if (std.mem.eql(u8, fl, "+")) continue;
        if (!std.mem.eql(u8, fl, tl)) return false;
    }
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "matches: multi-level wildcard '#'" {
    try testing.expect(matches("sport/tennis/player1/#", "sport/tennis/player1"));
    try testing.expect(matches("sport/tennis/player1/#", "sport/tennis/player1/ranking"));
    try testing.expect(matches("sport/tennis/player1/#", "sport/tennis/player1/score/wimbledon"));
    try testing.expect(matches("sport/#", "sport"));
    try testing.expect(matches("sport/#", "sport/tennis"));
    try testing.expect(matches("sport/#", "sport/tennis/player1/score"));
    try testing.expect(matches("#", "sport"));
    try testing.expect(matches("#", "sport/tennis/player1"));
    try testing.expect(matches("#", "/"));
    try testing.expect(!matches("sport/#", "sports"));
    try testing.expect(!matches("sport/tennis/#", "sport"));
}

test "matches: single-level wildcard '+'" {
    try testing.expect(matches("sport/+", "sport/tennis"));
    try testing.expect(!matches("sport/+", "sport/tennis/x"));
    try testing.expect(!matches("sport/+", "sport"));
    try testing.expect(matches("sport/+", "sport/")); // empty level is a level
    try testing.expect(matches("+", "sport"));
    try testing.expect(!matches("+", "sport/tennis"));
    try testing.expect(matches("sport/tennis/+", "sport/tennis/player1"));
    try testing.expect(!matches("sport/tennis/+", "sport/tennis/player1/ranking"));
    try testing.expect(matches("+/tennis/#", "sport/tennis/player1/score"));
    try testing.expect(!matches("+/tennis/#", "sport/badminton/player1"));
    try testing.expect(matches("+/+", "/finance"));
    try testing.expect(matches("/+", "/finance"));
    try testing.expect(!matches("+", "/finance"));
}

test "matches: '$'-prefixed topics are excluded from leading wildcards" {
    try testing.expect(!matches("#", "$SYS/broker/clients"));
    try testing.expect(!matches("+/monitor/Clients", "$SYS/monitor/Clients"));
    try testing.expect(matches("$SYS/#", "$SYS/broker/clients"));
    try testing.expect(matches("$SYS/monitor/+", "$SYS/monitor/Clients"));
    // Only a *leading* '$' is special.
    try testing.expect(matches("sport/+", "sport/$odd"));
}

test "matches: exact and near-miss literals" {
    try testing.expect(matches("sport/tennis", "sport/tennis"));
    try testing.expect(!matches("sport/tennis", "sport/Tennis")); // case-sensitive
    try testing.expect(!matches("sport/tennis", "sport/tennis/x"));
    try testing.expect(!matches("sport/tennis/x", "sport/tennis"));
    try testing.expect(matches("/", "/"));
}

test "validateName" {
    try validateName("sport/tennis/player1");
    try validateName("/");
    try validateName("$SYS/broker");
    try testing.expectError(error.InvalidTopicName, validateName(""));
    try testing.expectError(error.InvalidTopicName, validateName("sport/+"));
    try testing.expectError(error.InvalidTopicName, validateName("sport/#"));
    try testing.expectError(error.InvalidTopicName, validateName("a#b"));
    try testing.expectError(error.InvalidTopicName, validateName("a\x00b"));
    try testing.expectError(error.InvalidTopicName, validateName("\xFF\xFE"));
}

test "validateFilter" {
    try validateFilter("#");
    try validateFilter("+");
    try validateFilter("sport/#");
    try validateFilter("sport/+/player1");
    try validateFilter("+/+");
    try validateFilter("/");
    try validateFilter("$SYS/#");
    try testing.expectError(error.InvalidTopicFilter, validateFilter(""));
    try testing.expectError(error.InvalidTopicFilter, validateFilter("sport+"));
    try testing.expectError(error.InvalidTopicFilter, validateFilter("sport/+ball"));
    try testing.expectError(error.InvalidTopicFilter, validateFilter("sport/tennis#"));
    try testing.expectError(error.InvalidTopicFilter, validateFilter("sport/#/ranking"));
    try testing.expectError(error.InvalidTopicFilter, validateFilter("#/x"));
    try testing.expectError(error.InvalidTopicFilter, validateFilter("a\x00b"));
    try testing.expectError(error.InvalidTopicFilter, validateFilter("\xFF\xFE"));
}
