// SPDX-License-Identifier: MIT

//! Shared plumbing for saml's deterministic fuzz driver (added 2026-10-09),
//! and the one harness that needs nothing private: `consumeResponseXml` over
//! the genuinely signed fixture.
//!
//! The two older harnesses (`fields`, `idp`) stay in `root.zig`, beside the
//! seeds and alphabets they use; every harness is generic over its source of
//! choices, `fn(comptime S, *S, gpa)`, and `testing.fuzz` hands it a
//! `std.testing.Smith` (all are byte-first: the first draw is one `slice`, so
//! corpus seeds replay as before). This file holds what they share: the
//! reach counters with the N-seed in-suite check, and the input draw.
//!
//! Driver: `SAML_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver; `_ONLY`
//! selects a harness by name -- `fields`, `idp`, `consume` --, `_MS`,
//! `_SEEDFILE`, `_INPUT` as documented there).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
pub const fuzz_driver = testkit.fuzz.driver;
const saml = @import("root.zig");
const fx = @import("fixtures.zig");

/// One harness input into `buf`; returns its length. Under `Smith` (`--fuzz`,
/// `_INPUT` replay) it is exactly `src.slice`. Under the driver's `Rng` half
/// the draws are instead a corpus entry (frames carry a little-endian u32
/// length header; the octets after the frame, if any, are dropped) with 0-3
/// octets damaged and maybe truncated: random bytes alone never pass the
/// first grammar check of these parsers.
pub fn drawInput(comptime S: type, src: *S, buf: []u8, corpus: []const []const u8) usize {
    if (S != fuzz_driver.Rng) return src.slice(buf);
    if (corpus.len == 0 or !src.value(bool)) return src.slice(buf);
    const entry = corpus[src.index(corpus.len)];
    const flen = std.mem.readInt(u32, entry[0..4], .little);
    const frame = entry[4..][0..@min(flen, entry.len - 4)];
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness's labels. `mark` also feeds the driver's
/// `REACH` report; `reach` runs `seeds` seeds in the ordinary test binary and
/// fails with `error.HarnessDoesNotReach` if a label never fired.
pub fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".fields.len]usize = @splat(0);

        pub fn mark(comptime l: Label) void {
            counts[@intFromEnum(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        pub fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @enumFromInt(i)), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

// ── consume: a genuinely signed Response, accepted; a damaged one, refused ───

const ConsumeMark = Marker(enum { genuine_accepted, flipped_refused, truncated });

/// Whether `res` is the identity the genuine fixture carries. A damaged
/// document that is still accepted (a flip in an unsigned, unchecked octet of
/// the envelope) is only benign if it yields exactly this.
fn isGenuineIdentity(res: *const saml.AuthnResult) bool {
    if (!std.mem.eql(u8, res.name_id, "alice@example.org")) return false;
    if (!std.mem.eql(u8, res.assertion_id, fx.assertion_id)) return false;
    const si = res.session_index orelse return false;
    if (!std.mem.eql(u8, si, "sess-abc-123")) return false;
    if (res.attributes.len != 2) return false;
    if (!std.mem.eql(u8, res.attributes[0].name, "email") or res.attributes[0].values.len != 1) return false;
    if (!std.mem.eql(u8, res.attributes[0].values[0], "alice@example.org")) return false;
    if (!std.mem.eql(u8, res.attributes[1].name, "groups") or res.attributes[1].values.len != 2) return false;
    return std.mem.eql(u8, res.attributes[1].values[0], "admins") and std.mem.eql(u8, res.attributes[1].values[1], "staff");
}

/// `consumeResponseXml` over the signed fixture: untouched, it MUST be
/// accepted with the genuine identity; with 1-3 octets flipped (anywhere, or
/// inside the signed assertion) or the tail cut, it must be refused -- or, if
/// the damage fell on an octet nothing signed or checked, accepted with
/// EXACTLY the genuine identity, never another.
pub fn consumeHarness(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    // One byte-first draw: the script every choice below reads from.
    var script_buf: [64]u8 = undefined;
    const script_len: usize = src.slice(&script_buf);
    var script: testkit.fuzz.Cursor = .{ .bytes = script_buf[0..script_len] };

    const genuine = fx.signed_response;
    var buf: [genuine.len]u8 = undefined;
    @memcpy(&buf, genuine);
    var n: usize = genuine.len;

    const mode = script.ranged(0, 3);
    const assertion_at = std.mem.indexOf(u8, genuine, "<saml:Assertion").?;
    switch (mode) {
        0 => {},
        1, 2 => {
            const lo: usize = if (mode == 2) assertion_at else 0;
            for (0..script.ranged(1, 3)) |_| {
                const at = lo + @as(usize, script.word()) % (genuine.len - lo);
                buf[at] ^= @intCast(script.ranged(1, 255));
            }
        },
        else => n = @as(usize, script.word()) % genuine.len,
    }
    const changed = !std.mem.eql(u8, buf[0..n], genuine);

    var res = saml.consumeResponseXml(gpa, buf[0..n], .{
        .idp_entity_id = fx.idp_entity_id,
        .idp_key = fx.idpKey(),
        .sp_entity_id = fx.sp_entity_id,
        .acs_url = fx.acs_url,
        .now_unix = fx.t_valid,
        .expected_in_response_to = fx.request_id,
    }) catch {
        if (!changed) return error.GenuineResponseRefused;
        if (mode == 3) ConsumeMark.mark(.truncated) else ConsumeMark.mark(.flipped_refused);
        return;
    };
    defer res.deinit();
    if (!isGenuineIdentity(&res)) return error.AlteredIdentityAccepted;
    // A damaged document still accepted with the genuine identity is rare (an
    // octet nothing signed or checked): counted for the report, not required.
    if (changed) fuzz_driver.hit("flipped_benign") else ConsumeMark.mark(.genuine_accepted);
}

test "fuzz driver: SAML_FUZZ (consume: genuine accepted, flipped refused)" {
    try fuzz_driver.run(consumeHarness, .{ .prefix = "SAML_FUZZ", .name = "consume" });
}

test "fuzz harness: 300 seeds of consumeResponseXml in every test run, genuine accepted and damaged refused" {
    try ConsumeMark.reach(consumeHarness, "saml-consume", 300);
}

fn consumeSmith(_: void, smith: *std.testing.Smith) !void {
    try consumeHarness(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: consumeResponseXml on the signed fixture, damaged by a script (coverage-guided exploration)" {
    // Scripts: the first octet picks the mode (0 genuine, 1 flips, 2 flips in
    // the assertion, 3 truncation), the rest are offsets and masks.
    try testing.fuzz({}, consumeSmith, .{ .corpus = &.{
        testkit.fuzz.seedHex("00"),
        testkit.fuzz.seedHex("01" ++ "00" ++ "0010" ++ "01"),
        testkit.fuzz.seedHex("02" ++ "02" ++ "0300" ++ "20" ++ "0400" ++ "ff"),
        testkit.fuzz.seedHex("03" ++ "0100"),
    } });
}

test "drawInput: Rng takes damaged corpus entries, Smith the plain slice" {
    const seeds = [_][]const u8{testkit.fuzz.seed("0123456789abcdef")};
    var prng = std.Random.DefaultPrng.init(1);
    var rng: fuzz_driver.Rng = .{ .r = prng.random() };
    var buf: [64]u8 = undefined;
    var from_corpus = false;
    for (0..64) |_| {
        const n = drawInput(fuzz_driver.Rng, &rng, &buf, &seeds);
        if (n >= 8 and std.mem.startsWith(u8, buf[0..n], "01234")) from_corpus = true;
    }
    try testing.expect(from_corpus);

    var smith: std.testing.Smith = .{ .in = seeds[0] };
    try testing.expectEqual(@as(usize, 16), drawInput(std.testing.Smith, &smith, &buf, &seeds));
    try testing.expectEqualStrings("01234", buf[0..5]);
}
