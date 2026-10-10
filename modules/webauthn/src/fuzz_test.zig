// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for webauthn (added 2026-10-10).
//!
//! The existing script-driven harnesses (`parseClientData`,
//! `parseAuthenticatorData`, `verifyAttestation`, registration binding) keep
//! their `--fuzz` corpora; this file adds the crypto oracles over the six
//! W3C section 16 ceremonies, both generic over their source of choices.
//! `WEBAUTHN_FUZZ=<runs>[,<first seed>]` runs them (testkit's fuzz driver;
//! `_ONLY` selects one by name, `_MS`, `_SEEDFILE`, `_INPUT` as documented
//! there):
//! - `webauthn-assertion`: `verifyAssertion` over a genuine vector ACCEPTS;
//!   damage (0-3 octets, truncation) to the authenticatorData, the
//!   clientDataJSON, the signature or the credential public key is REFUSED
//!   with a typed error.
//! - `webauthn-registration`: `verifyRegistration` over a genuine vector
//!   ACCEPTS; damage to the clientDataJSON is refused wherever the statement
//!   signs its hash (every format but `none`, which binds nothing: a changed
//!   `extraData` member is the same ceremony); damage to the
//!   attestationObject is refused wherever the attestation statement signs
//!   the authData with the credential's own key (self attestation). `none`
//!   carries no signature and a full `x5c` statement does not chain the
//!   certificate (SPEC "Deferred"): there an altered object may verify, and
//!   it is only required not to crash.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const webauthn = @import("root.zig");
const cbor = @import("cbor");
const vectors = @import("vectors.zig");
pub const fuzz_driver = testkit.fuzz.driver;

/// `frame` into `buf` with 0-3 octets damaged and maybe truncated. The
/// driver's `Rng` only.
pub fn damage(src: anytype, buf: []u8, frame: []const u8) usize {
    var n = @min(frame.len, buf.len);
    @memcpy(buf[0..n], frame[0..n]);
    for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
        if (n == 0) break;
        buf[src.index(n)] = src.value(u8);
    }
    if (src.valueRangeAtMost(u8, 0, 3) == 0) n = src.index(n + 1);
    return n;
}

/// Reach counters for one harness file's labels (see jwt's fuzz_test.zig).
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

const Ceremony = struct {
    registration_client_data_json: []const u8,
    attestation_object: []const u8,
    registration_challenge: []const u8,
    authenticator_data: []const u8,
    assertion_client_data_json: []const u8,
    signature: []const u8,
    assertion_challenge: []const u8,
    credential_public_key: []const u8,
    /// The attestation statement is a signature over authData || clientDataHash
    /// by the credential's own key (self) or an attestation key (x5c).
    signs_auth_data: bool,
    /// ... and no certificate is carried, so EVERY octet of the object counts.
    self_attested: bool,
    /// The statement signs the clientDataJSON hash (every format but `none`).
    signs_client_data: bool,
};

fn ceremony(comptime V: type, comptime signs_auth_data: bool, comptime self_attested: bool, comptime signs_client_data: bool) Ceremony {
    return .{
        .registration_client_data_json = &V.registration_client_data_json,
        .attestation_object = &V.attestation_object,
        .registration_challenge = &V.registration_challenge,
        .authenticator_data = &V.authenticator_data,
        .assertion_client_data_json = &V.assertion_client_data_json,
        .signature = &V.signature,
        .assertion_challenge = &V.assertion_challenge,
        .credential_public_key = &V.credential_public_key,
        .signs_auth_data = signs_auth_data,
        .self_attested = self_attested,
        .signs_client_data = signs_client_data,
    };
}

const ceremonies = [_]Ceremony{
    ceremony(vectors.none_es256, false, false, false),
    ceremony(vectors.packed_self_es256, true, true, true),
    ceremony(vectors.packed_es256_full, true, false, true),
    ceremony(vectors.packed_rs256, true, false, true),
    ceremony(vectors.packed_eddsa, true, false, true),
    // fido-u2f signs rpIdHash, clientDataHash, credentialId and the key, not the flags,
    // counter or AAGUID.
    ceremony(vectors.fido_u2f_es256, false, false, true),
};

// ── webauthn-assertion ──────────────────────────────────────────────────────

const AssertMark = Marker(enum {
    genuine_accepted,
    auth_data_refused,
    client_data_refused,
    signature_refused,
    key_refused,
    key_unparsable,
});

const Part = enum { none, auth_data, client_data, signature, key };

pub fn fuzzAssertion(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = ceremonies;
    const c = cs[src.index(cs.len)];
    var part: Part = .none;
    if (S == fuzz_driver.Rng) {
        part = switch (src.valueRangeAtMost(u8, 0, 11)) {
            0, 1 => .none,
            2, 3, 4 => .auth_data,
            5, 6, 7 => .client_data,
            8, 9 => .signature,
            else => .key,
        };
    } else part = @enumFromInt(src.index(5));

    var ad: [1024]u8 = undefined;
    var cd: [1024]u8 = undefined;
    var sg: [1024]u8 = undefined;
    var ky: [1024]u8 = undefined;
    var auth_data: []const u8 = c.authenticator_data;
    var client_data: []const u8 = c.assertion_client_data_json;
    var signature: []const u8 = c.signature;
    var key_bytes: []const u8 = c.credential_public_key;
    var changed = false;
    switch (part) {
        .none => {},
        .auth_data => {
            const n = damage(src, &ad, auth_data);
            changed = n != auth_data.len or !std.mem.eql(u8, ad[0..n], auth_data);
            auth_data = ad[0..n];
        },
        .client_data => {
            const n = damage(src, &cd, client_data);
            changed = n != client_data.len or !std.mem.eql(u8, cd[0..n], client_data);
            client_data = cd[0..n];
        },
        .signature => {
            const n = damage(src, &sg, signature);
            changed = n != signature.len or !std.mem.eql(u8, sg[0..n], signature);
            signature = sg[0..n];
        },
        .key => {
            const n = damage(src, &ky, key_bytes);
            changed = n != key_bytes.len or !std.mem.eql(u8, ky[0..n], key_bytes);
            key_bytes = ky[0..n];
        },
    }

    const decoded = cbor.decode(a, key_bytes, .{}) catch {
        if (!changed) return error.GenuineKeyUnparsable;
        AssertMark.mark(.key_unparsable);
        return;
    };
    const key = webauthn.parseCredentialKey(decoded) catch {
        if (!changed) return error.GenuineKeyUnparsable;
        AssertMark.mark(.key_unparsable);
        return;
    };
    const result = webauthn.verifyAssertion(a, auth_data, client_data, signature, key, .{
        .rp_id = vectors.rp_id,
        .expected_challenge = c.assertion_challenge,
        .expected_origin = vectors.origin,
    });
    if (result) |_| {
        if (changed) {
            std.debug.print("webauthn-assertion: a damaged {t} was ACCEPTED\n", .{part});
            return error.DamagedAssertionAccepted;
        }
        AssertMark.mark(.genuine_accepted);
    } else |err| {
        if (!changed) {
            std.debug.print("webauthn-assertion: the genuine ceremony was refused: {t}\n", .{err});
            return error.GenuineAssertionRefused;
        }
        switch (part) {
            .auth_data => AssertMark.mark(.auth_data_refused),
            .client_data => AssertMark.mark(.client_data_refused),
            .signature => AssertMark.mark(.signature_refused),
            .key => AssertMark.mark(.key_refused),
            .none => {},
        }
    }
}

fn fuzzAssertionSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzAssertion(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: a genuine assertion is accepted, a damaged one refused" {
    try testing.fuzz({}, fuzzAssertionSmith, .{});
}

test "fuzz driver: WEBAUTHN_FUZZ (assertion)" {
    try fuzz_driver.run(fuzzAssertion, .{ .prefix = "WEBAUTHN_FUZZ", .name = "webauthn-assertion" });
}

test "fuzz harness: assertion, 400 seeds, reaches every outcome" {
    try AssertMark.reach(fuzzAssertion, "webauthn-assertion", 400);
}

// ── webauthn-registration ───────────────────────────────────────────────────

const RegMark = Marker(enum {
    genuine_accepted,
    client_data_refused,
    attestation_refused,
    lenient_accepted,
    lenient_refused,
});

pub fn fuzzRegistration(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const a = arena.allocator();
    const cs = ceremonies;
    const c = cs[src.index(cs.len)];
    const Which = enum { none, client_data, attestation };
    var which: Which = .none;
    if (S == fuzz_driver.Rng) {
        which = switch (src.valueRangeAtMost(u8, 0, 9)) {
            0, 1 => .none,
            2, 3, 4 => .client_data,
            else => .attestation,
        };
    } else which = @enumFromInt(src.index(3));

    var cdb: [1024]u8 = undefined;
    var aob: [2048]u8 = undefined;
    var client_data: []const u8 = c.registration_client_data_json;
    var att: []const u8 = c.attestation_object;
    var changed = false;
    switch (which) {
        .none => {},
        .client_data => {
            const n = damage(src, &cdb, client_data);
            changed = n != client_data.len or !std.mem.eql(u8, cdb[0..n], client_data);
            client_data = cdb[0..n];
        },
        .attestation => {
            const n = damage(src, &aob, att);
            changed = n != att.len or !std.mem.eql(u8, aob[0..n], att);
            att = aob[0..n];
        },
    }
    // Where the damage starts (a truncation counts from the cut), and where
    // authData begins in the genuine object: a damage confined to authData
    // is under the attestation signature on every `packed` vector; the
    // certificate in an `x5c` statement is not chained (SPEC "Deferred").
    var first: usize = att.len;
    if (which == .attestation) {
        const orig = c.attestation_object;
        if (att.len < orig.len) first = att.len;
        for (att[0..@min(att.len, orig.len)], orig[0..@min(att.len, orig.len)], 0..) |x, y, i| if (x != y) {
            first = @min(first, i);
            break;
        };
    }
    const auth_start = std.mem.lastIndexOf(u8, c.attestation_object, "authData").? + "authData".len;
    const strict = which == .attestation and c.signs_auth_data and (c.self_attested or first > auth_start);
    const result = webauthn.verifyRegistration(a, att, client_data, .{
        .rp_id = vectors.rp_id,
        .expected_challenge = c.registration_challenge,
        .expected_origin = vectors.origin,
    });
    if (result) |_| {
        if (!changed) {
            RegMark.mark(.genuine_accepted);
            return;
        }
        if ((which == .client_data and c.signs_client_data) or strict) {
            std.debug.print("webauthn-registration: a damaged {t} was ACCEPTED (vector signs authData: {})\n", .{ which, c.signs_auth_data });
            return error.DamagedRegistrationAccepted;
        }
        RegMark.mark(.lenient_accepted);
    } else |err| {
        if (!changed) {
            std.debug.print("webauthn-registration: the genuine ceremony was refused: {t}\n", .{err});
            return error.GenuineRegistrationRefused;
        }
        if (which == .client_data) RegMark.mark(.client_data_refused) else if (strict) RegMark.mark(.attestation_refused) else RegMark.mark(.lenient_refused);
    }
}

fn fuzzRegistrationSmith(_: void, smith: *std.testing.Smith) !void {
    try fuzzRegistration(std.testing.Smith, smith, testing.allocator);
}

test "fuzz: a genuine registration is accepted, a damaged one refused" {
    try testing.fuzz({}, fuzzRegistrationSmith, .{});
}

test "fuzz driver: WEBAUTHN_FUZZ (registration)" {
    try fuzz_driver.run(fuzzRegistration, .{ .prefix = "WEBAUTHN_FUZZ", .name = "webauthn-registration" });
}

test "fuzz harness: registration, 400 seeds, reaches every outcome" {
    try RegMark.reach(fuzzRegistration, "webauthn-registration", 400);
}
