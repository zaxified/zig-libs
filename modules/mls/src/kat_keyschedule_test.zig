// SPDX-License-Identifier: MIT
//! mls.kat_keyschedule_test — the official RFC 9420 key-schedule interop
//! vectors (`mlswg/mls-implementations` `test-vectors/key-schedule.json`
//! and `test-vectors/psk_secret.json`), embedded verbatim and driven
//! end-to-end against `keyschedule.zig`. See `NOTICE` for the exact source
//! commits and fetch date.
//!
//! **This is the only thing that can tell a correct key schedule from a
//! plausible one.** Every value RFC 9420 §8 derives is an
//! indistinguishable-looking 32 bytes; an inverted `KDF.Extract` salt/IKM
//! pair, a `GroupContext` field written in the wrong order, or
//! `welcome_secret` hung off `epoch_secret` instead of the member secret
//! all produce output that passes every self-consistency check anyone could
//! write and matches no other implementation on earth. So this harness
//! checks each STAGE separately against the vector rather than only the end
//! of the chain — when something is wrong, the first failing stage names
//! the bug.
//!
//! Parsed as generic `std.json.Value`, matching `kat_test.zig`'s reasoning:
//! the file is a direct transcription of "what the JSON says", not a schema
//! fight.
//!
//! One field type is easy to get wrong and worth stating: the upstream
//! vector spec declares `epochs[i].exporter.label` as `/* string */` while
//! every sibling field is `/* hex-encoded binary data */`. The generator
//! happens to emit hex-looking ASCII for it, so hex-decoding it "works" all
//! the way to a wrong answer. It is used here as the literal UTF-8 bytes.

const std = @import("std");
const suite = @import("suite.zig");
const crypto = @import("crypto.zig");
const keyschedule = @import("keyschedule.zig");
const tree = @import("tree.zig");
const codec = @import("codec.zig");

const key_schedule_json = @embedFile("data/key-schedule.json");
const psk_secret_json = @embedFile("data/psk_secret.json");

const testing = std.testing;
const S = suite.default;

fn hexDecode(allocator: std.mem.Allocator, hex: []const u8) ![]u8 {
    const out = try allocator.alloc(u8, hex.len / 2);
    _ = try std.fmt.hexToBytes(out, hex);
    return out;
}

/// A vector field that must be exactly one KDF output wide.
fn hexSecret(hex: []const u8) ![S.Nh]u8 {
    var out: [S.Nh]u8 = undefined;
    const decoded = try std.fmt.hexToBytes(&out, hex);
    try testing.expectEqual(@as(usize, S.Nh), decoded.len);
    return out;
}

fn asI64(v: std.json.Value) i64 {
    return switch (v) {
        .integer => |i| i,
        else => unreachable,
    };
}

/// `expectEqualSlices` with the stage's name attached — a bare byte diff in
/// a chain of twelve 32-byte values does not say which link broke.
fn expectStage(name: []const u8, want: []const u8, got: []const u8) !void {
    testing.expectEqualSlices(u8, want, got) catch |err| {
        std.debug.print("key-schedule KAT: stage '{s}' diverged\n", .{name});
        return err;
    };
}

test "key-schedule.json: RFC 9420 §8's full epoch chain for cipher suite 0x0001, byte-exact" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, key_schedule_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();

    var found_suite_1 = false;
    var skipped_other_suites: usize = 0;
    var checked_epochs: usize = 0;

    for (parsed.value.array.items) |entry| {
        const cs = asI64(entry.object.get("cipher_suite").?);
        if (cs != @as(i64, @intFromEnum(S.id))) {
            skipped_other_suites += 1;
            continue; // this module only wires suite 0x0001 — see suite.zig
        }
        found_suite_1 = true;

        const group_id = try hexDecode(arena, entry.object.get("group_id").?.string);

        // The chain's seed. Every later epoch's `init_secret` comes out of
        // the epoch before it, so a single wrong step poisons the rest —
        // which is exactly the property that makes this vector worth
        // driving as a CHAIN rather than as five independent cases.
        var init_secret_prev = try hexSecret(entry.object.get("initial_init_secret").?.string);

        for (entry.object.get("epochs").?.array.items, 0..) |epoch_v, epoch_index| {
            const ep = epoch_v.object;

            // ── inputs the generator chose ──
            const tree_hash = try hexDecode(arena, ep.get("tree_hash").?.string);
            const cth = try hexDecode(arena, ep.get("confirmed_transcript_hash").?.string);
            const commit_secret = try hexSecret(ep.get("commit_secret").?.string);
            const psk_secret = try hexSecret(ep.get("psk_secret").?.string);

            // ── §8.1: GroupContext serialization ──
            const gc: keyschedule.GroupContext = .{
                .cipher_suite = S.id,
                .group_id = group_id,
                .epoch = @intCast(epoch_index),
                .tree_hash = tree_hash,
                .confirmed_transcript_hash = cth,
                .extensions = &.{},
            };
            const encoded_gc = try gc.encodeAlloc(arena);
            const want_gc = try hexDecode(arena, ep.get("group_context").?.string);
            try expectStage("group_context", want_gc, encoded_gc);

            // ...and the decoder agrees with the encoder on the vector's
            // own bytes, so `GroupContext` is pinned in both directions.
            {
                var r = codec.Reader.init(want_gc);
                const back = try keyschedule.GroupContext.decode(arena, &r);
                try testing.expect(r.atEnd());
                try testing.expectEqual(@as(u64, @intCast(epoch_index)), back.epoch);
                try testing.expectEqual(S.id, back.cipher_suite);
                try testing.expectEqual(keyschedule.ProtocolVersion.mls10, back.version);
                try testing.expectEqualSlices(u8, group_id, back.group_id);
                try testing.expectEqualSlices(u8, tree_hash, back.tree_hash);
                try testing.expectEqualSlices(u8, cth, back.confirmed_transcript_hash);
                try testing.expectEqual(@as(usize, 0), back.extensions.len);
            }

            // ── §8: the chain, stage by stage ──
            // Driven through the granular entry points FIRST so a
            // divergence names the exact link, then re-checked through the
            // one-call `deriveEpoch` so the convenience path cannot drift
            // from the pieces.
            const joiner = try keyschedule.joinerSecret(S, arena, init_secret_prev, commit_secret, encoded_gc);
            try expectStage("joiner_secret", try hexDecode(arena, ep.get("joiner_secret").?.string), &joiner);

            const welcome = try keyschedule.welcomeSecret(S, joiner, psk_secret);
            try expectStage("welcome_secret", try hexDecode(arena, ep.get("welcome_secret").?.string), &welcome);

            const epoch_secret = try keyschedule.epochSecret(S, arena, joiner, psk_secret, encoded_gc);

            var secrets = try keyschedule.deriveEpoch(S, arena, init_secret_prev, commit_secret, psk_secret, encoded_gc);
            try expectStage("deriveEpoch/joiner_secret", &joiner, &secrets.joiner_secret);
            try expectStage("deriveEpoch/welcome_secret", &welcome, &secrets.welcome_secret);
            try expectStage("deriveEpoch/epoch_secret", &epoch_secret, &secrets.epoch_secret);

            // ── §8 Table 4's fan-out ──
            const table4 = [_]struct { name: []const u8, field: [S.Nh]u8 }{
                .{ .name = "sender_data_secret", .field = secrets.sender_data_secret },
                .{ .name = "encryption_secret", .field = secrets.encryption_secret },
                .{ .name = "exporter_secret", .field = secrets.exporter_secret },
                .{ .name = "external_secret", .field = secrets.external_secret },
                .{ .name = "confirmation_key", .field = secrets.confirmation_key },
                .{ .name = "membership_key", .field = secrets.membership_key },
                .{ .name = "resumption_psk", .field = secrets.resumption_psk },
                .{ .name = "epoch_authenticator", .field = secrets.epoch_authenticator },
                .{ .name = "init_secret", .field = secrets.init_secret },
            };
            for (table4) |row| {
                try expectStage(row.name, try hexDecode(arena, ep.get(row.name).?.string), &row.field);
            }

            // ── §8: external_pub = KEM.DeriveKeyPair(external_secret) ──
            const external_kp = keyschedule.externalKeyPair(S, secrets.external_secret);
            try expectStage(
                "external_pub",
                try hexDecode(arena, ep.get("external_pub").?.string),
                &external_kp.public_key,
            );

            // ── §8.5: MLS-Exporter ──
            {
                const exp = ep.get("exporter").?.object;
                const label = exp.get("label").?.string; // a STRING, not hex — see this file's doc comment
                const context = try hexDecode(arena, exp.get("context").?.string);
                const length: usize = @intCast(asI64(exp.get("length").?));
                const out = try arena.alloc(u8, length);
                try keyschedule.mlsExporter(S, secrets.exporter_secret, label, context, out);
                try expectStage("exporter", try hexDecode(arena, exp.get("secret").?.string), out);
            }

            init_secret_prev = secrets.init_secret;
            checked_epochs += 1;
        }
    }

    try testing.expect(found_suite_1);
    try testing.expect(checked_epochs >= 5);
    // Suites 0x0002-0x0007 are present in the file and intentionally
    // skipped — this module only wires the mandatory suite.
    try testing.expectEqual(@as(usize, 6), skipped_other_suites);
}

test "psk_secret.json: RFC 9420 §8.4's psk_secret chain for 0..10 PSKs, byte-exact" {
    var parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, psk_secret_json, .{});
    defer parsed.deinit();
    const arena = parsed.arena.allocator();

    var found_suite_1 = false;
    var checked_cases: usize = 0;
    var max_psks: usize = 0;
    var saw_empty = false;

    for (parsed.value.array.items) |entry| {
        const cs = asI64(entry.object.get("cipher_suite").?);
        if (cs != @as(i64, @intFromEnum(S.id))) continue;
        found_suite_1 = true;

        const psks_json = entry.object.get("psks").?.array.items;
        const psks = try arena.alloc(keyschedule.PreSharedKey(S), psks_json.len);
        for (psks_json, 0..) |p, i| {
            // The vector spec: "compute PreSharedKeyID with external
            // PSKType and with provided psk_id and psk_nonce".
            psks[i] = .{
                .id = .{
                    .id = .{ .external = try hexDecode(arena, p.object.get("psk_id").?.string) },
                    .psk_nonce = try hexDecode(arena, p.object.get("psk_nonce").?.string),
                },
                // §8.4 feeds the PSK to `KDF.Extract` as IKM, so it is NOT
                // width-constrained — see `keyschedule.PreSharedKey.secret`.
                .secret = try hexDecode(arena, p.object.get("psk").?.string),
            };
        }

        const got = try keyschedule.pskSecret(S, arena, psks);
        try expectStage("psk_secret", try hexDecode(arena, entry.object.get("psk_secret").?.string), &got);

        if (psks.len == 0) saw_empty = true;
        max_psks = @max(max_psks, psks.len);
        checked_cases += 1;
    }

    try testing.expect(found_suite_1);
    // The empty case pins §8.4's "the resulting psk_secret is
    // psk_secret_[0], the all-zero vector", and a double-digit chain pins
    // that PSKLabel.index/count really do advance per element.
    try testing.expect(saw_empty);
    try testing.expect(max_psks >= 10);
    try testing.expect(checked_cases >= 11);
}
