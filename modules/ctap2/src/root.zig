// SPDX-License-Identifier: MIT
//! ctap2 — the CTAP 2.1 client side of `authenticatorClientPIN` over a
//! caller-supplied transport (FIDO Alliance CTAP 2.1, §6.4, §6.5.5, §8.2).
//!
//! `ctap2pin` (the sibling module) is the `pinUvAuthProtocol` crypto only:
//! encapsulate, encrypt, decrypt, authenticate. This module is the command layer
//! above it, so an application gets PIN handling in one call:
//!
//!   1. **Framing** (`framing`): request = command byte || CBOR map, response =
//!      status byte || optional CBOR, over a `Transport` (a ctx pointer and one
//!      `transact` function). No device I/O lives in this module.
//!   2. **Status codes** (`status`): every CTAP 2.1 §8.2 status as a named Zig
//!      error (`error.PinInvalid`, `error.PinBlocked`, `error.PinAuthBlocked`, ...).
//!   3. **`authenticatorGetInfo`** (`getinfo`): the response subset needed to
//!      drive PIN (versions, aaguid, PIN-relevant options, pinUvAuthProtocols,
//!      maxMsgSize, minPINLength, forcePINChange).
//!   4. **`authenticatorClientPIN`** (`clientpin`): getPINRetries, getKeyAgreement,
//!      setPIN, changePIN, getPinToken (legacy), getPinUvAuthTokenUsingPin- and
//!      -UvWithPermissions, getUVRetries; both PIN/UV protocols; the spec's PIN
//!      rules; secrets wiped.
//!   5. **CTAPHID packets** (`ctaphid`): the 64-byte init/continuation report
//!      codec (pure encode/decode, no device I/O).
//!
//! All cryptography is `ctap2pin`'s and all CBOR is `cbor`'s; nothing is
//! re-implemented here. Randomness (the ECDH scalar, protocol-Two IVs) comes
//! from a caller-supplied `std.Random`.
//!
//! Validation: for every subcommand and both protocols the request bytes are
//! asserted equal, byte for byte, to what python-fido2 2.2.1 sends when driven
//! as a black-box oracle (see `NOTICE`, `tools/gen_fido2_vectors.py`).
//!
//! Clean-room from the public CTAP 2.1 specification; no other implementation's
//! source was consulted.

const std = @import("std");
/// Test-only (`build.zig`'s `test_deps`): fuzz corpus framing.
const testkit = @import("testkit");

pub const meta = .{
    // The module catalog's one-line entry; README.md's table is rendered from
    // it by `zig build gen-catalog`.
    .doc = "CTAP2 (FIDO2) `authenticatorClientPIN` command layer over a caller-supplied transport: GetInfo, PIN retries/set/change/token-with-permissions, both PIN protocols, CTAPHID packet codec.",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec, // wire framing + command encoding; the transport is the caller's
    .concurrency = .reentrant, // no globals; a `Client` holds only caller-supplied state
    .model_after = "FIDO Alliance CTAP 2.1 (6.4, 6.5.5, 8.2, 11.2); python-fido2 used as a black-box oracle",
    .deps = .{ "cbor", "ctap2pin" },
};

/// The sibling modules this one is built on, re-exported so a program that
/// implements a `Transport` needs no second import (the example's in-process
/// authenticator uses them).
pub const cbor = @import("cbor");
pub const ctap2pin = @import("ctap2pin");

pub const status = @import("status.zig");
pub const framing = @import("framing.zig");
pub const getinfo = @import("getinfo.zig");
pub const clientpin = @import("clientpin.zig");
pub const ctaphid = @import("ctaphid.zig");

pub const StatusError = status.StatusError;
pub const Transport = framing.Transport;
pub const TransportError = framing.TransportError;
pub const Info = getinfo.Info;
pub const Client = clientpin.Client;
pub const Permissions = clientpin.Permissions;
pub const Token = clientpin.Token;
pub const PinRetries = clientpin.PinRetries;
pub const ClientPinError = clientpin.ClientPinError;

test {
    _ = status;
    _ = framing;
    _ = getinfo;
    _ = clientpin;
    _ = ctaphid;
    _ = @import("fido2_vectors.zig");
    _ = @import("oracle_test.zig");
    _ = @import("client_test.zig");
}

// ── fuzz: every parser of authenticator bytes, and the client on top ────────

const fido2_vectors = @import("fido2_vectors.zig");
const testutil = @import("testutil.zig");

const fuzz_platform_scalar: [32]u8 = .{ 0x47, 0xbb, 0xb5, 0x64, 0x78, 0xbe, 0x49, 0x2d, 0xd1, 0xda, 0xb6, 0xa5, 0xea, 0x00, 0xd3, 0x7b, 0x17, 0x8a, 0x07, 0x83, 0x63, 0x65, 0x2d, 0x04, 0x02, 0x79, 0x7a, 0xaa, 0xa0, 0xdf, 0x60, 0x3f };

/// Script layout (`smith.slice`): [0] selector, [1..] the bytes handed to the
/// selected parser (selector 5 hands over the whole script minus the selector
/// as a complete response message including its status byte).
/// Bit 7 of the selector byte picks protocol Two for selector 6.
///   0 getinfo.parse           1 parseKeyAgreementResponse
///   2 parsePinRetriesResponse 3 parseUvRetriesResponse
///   4 token response + decrypt under a fixed secret (both protocols)
///   5 framing.splitResponse   6 Client.getPinToken against a valid key
///     agreement followed by these bytes as the token response
fn fuzzResponses(_: void, smith: *std.testing.Smith) !void {
    var script: [2048]u8 = undefined;
    const n: usize = smith.slice(&script);
    if (n == 0) return;
    const sel = (script[0] & 0x7f) % 7;
    const body = script[1..n];
    const a = std.testing.allocator;

    switch (sel) {
        0 => _ = getinfo.parse(a, body) catch {},
        1, 2, 3, 4 => {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const al = arena.allocator();
            switch (sel) {
                1 => _ = clientpin.parseKeyAgreementResponse(al, body) catch {},
                2 => _ = clientpin.parsePinRetriesResponse(al, body) catch {},
                3 => _ = clientpin.parseUvRetriesResponse(al, body) catch {},
                else => {
                    const ct = clientpin.parseTokenResponse(al, body) catch return;
                    for ([_]ctap2pin.Protocol{ .one, .two }) |p| {
                        var s: clientpin.SharedSecret = .{ .protocol = p, .platform_key = undefined };
                        @memset(&s.bytes, 0x42);
                        if (s.decryptToken(ct)) |tok| {
                            var t = tok;
                            t.deinit();
                        } else |_| {}
                    }
                },
            }
        },
        5 => _ = framing.splitResponse(body) catch {},
        else => {
            const auth_pub = try ctap2pin.publicKeyFromScalar(&[32]u8{ 0x4f, 0x4d, 0x86, 0xa2, 0xe5, 0x42, 0x3b, 0x2f, 0x3f, 0xf5, 0x75, 0x29, 0x16, 0x5e, 0xc6, 0xb6, 0xce, 0x75, 0x44, 0x58, 0x5b, 0xe1, 0x6e, 0x32, 0x42, 0xa6, 0x75, 0xbf, 0xb1, 0xeb, 0x68, 0x55 });
            const cose = [_]cbor.MapEntry{
                .{ .key = cbor.Value.fromI64(1), .value = cbor.Value.fromI64(2) },
                .{ .key = cbor.Value.fromI64(3), .value = cbor.Value.fromI64(-25) },
                .{ .key = cbor.Value.fromI64(-1), .value = cbor.Value.fromI64(1) },
                .{ .key = cbor.Value.fromI64(-2), .value = .{ .bytes = &auth_pub.x } },
                .{ .key = cbor.Value.fromI64(-3), .value = .{ .bytes = &auth_pub.y } },
            };
            const outer = [_]cbor.MapEntry{.{ .key = .{ .uint = 1 }, .value = .{ .map = &cose } }};
            const enc_body = try cbor.encode(a, .{ .map = &outer }, .{ .canonical = true });
            defer a.free(enc_body);
            var key_resp: [256]u8 = undefined;
            key_resp[0] = 0;
            @memcpy(key_resp[1..][0..enc_body.len], enc_body);
            var tr = testutil.ScriptTransport.init(a, &.{ key_resp[0 .. 1 + enc_body.len], body });
            defer tr.deinit();
            const scalars = fuzz_platform_scalar ++ [_]u8{1} ** 16;
            var rnd: testutil.ScriptRandom = .{ .bytes = &scalars };
            const protocol: ctap2pin.Protocol = if (script[0] & 0x80 != 0) .two else .one;
            const c = clientpin.Client.init(a, tr.transport(), rnd.random(), protocol);
            var t = c.getPinToken("1234") catch return;
            t.deinit();
        },
    }
}

const fuzz_seeds = [_][]const u8{
    testkit.fuzz.seed(&[_]u8{0} ++ fido2_vectors.cases[0].info_response[1..]), // GetInfo (status byte dropped)
    testkit.fuzz.seed(&[_]u8{1} ++ fido2_vectors.cases[2].responses[0][1..]), // key agreement
    testkit.fuzz.seed(&[_]u8{2} ++ fido2_vectors.cases[0].responses[0][1..]), // PIN retries
    testkit.fuzz.seed(&[_]u8{3} ++ fido2_vectors.cases[1].responses[0][1..]), // UV retries
    testkit.fuzz.seed(&[_]u8{4} ++ fido2_vectors.cases[5].responses[1][1..]), // token response
    testkit.fuzz.seed(&[_]u8{5} ++ fido2_vectors.cases[5].responses[1]), // whole message
    testkit.fuzz.seed(&[_]u8{6} ++ fido2_vectors.cases[5].responses[1][1..]), // client, protocol One
    testkit.fuzz.seed(&[_]u8{0x86} ++ fido2_vectors.cases[15].responses[1][1..]), // client, protocol Two
};

test "fuzz: authenticator responses never panic or leak" {
    try std.testing.fuzz({}, fuzzResponses, .{ .corpus = &fuzz_seeds });
}

test "corpus: each fuzz seed reaches its selector's accept path" {
    // Selectors 0-4 and 6 accept the genuine python-fido2 responses they are seeded with.
    const a = std.testing.allocator;
    for (fuzz_seeds[0..5], 0..) |sd, i| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [2048]u8 = undefined;
        const n: usize = smith.slice(&script);
        try std.testing.expectEqual(@as(u8, @intCast(i)), script[0]);
        const body = script[1..n];
        switch (i) {
            0 => _ = try getinfo.parse(a, body),
            else => {
                var arena = std.heap.ArenaAllocator.init(a);
                defer arena.deinit();
                switch (i) {
                    1 => _ = try clientpin.parseKeyAgreementResponse(arena.allocator(), body),
                    2 => _ = try clientpin.parsePinRetriesResponse(arena.allocator(), body),
                    3 => _ = try clientpin.parseUvRetriesResponse(arena.allocator(), body),
                    else => try std.testing.expectEqual(@as(usize, 16), (try clientpin.parseTokenResponse(arena.allocator(), body)).len),
                }
            },
        }
    }
}
