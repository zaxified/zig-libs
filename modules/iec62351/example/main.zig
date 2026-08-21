// SPDX-License-Identifier: MIT

//! What a GOOSE publisher/subscriber pair does with `iec62351`: wrap an
//! already-encoded GOOSE APDU (this module never parses 61850 itself — see
//! its module doc comment, "security is a wrapper over a wire format, not
//! a fork of it") in an IEC 62351-6:2020 HMAC-SHA256-128 authentication
//! extension, then verify it on the subscriber side. Also shows the
//! fail-closed check on a tampered frame — the whole point of authenticating
//! a trip/close command on a substation bus.
//!
//! Built against the PUBLISHED module (`@import("iec62351")`) only — the
//! HMAC profile needs neither of the module's declared deps (`x509`/`rsa`
//! back the 2007 RSASSA-PSS signature profile instead), but `goose.zig`
//! imports `rsa` unconditionally so the full transitive graph is still
//! required to compile this file, same as any other consumer of this
//! module. No socket, no network — a caller wires this over its own
//! Ethernet raw socket / capture pipeline.

const std = @import("std");
const iec62351 = @import("iec62351");

// A stand-in for an already-encoded goosePdu (this module never inspects
// its contents — see module doc comment). A real caller gets these bytes
// from `iec61850`'s GOOSE encoder.
const sample_apdu = [_]u8{ 0x61, 0x1a, 0x80, 0x01, 0x00 } ++ "trip-breaker-1" ++ [_]u8{0};

// The group key every IED on this GOOSE control block holds (IEC 62351-9
// key distribution, out of this module's scope — see `IvCounter`'s doc
// comment on why a *shared* key makes IV/nonce uniqueness this module's
// sharpest edge; HMAC needs no IV at all, which is why this example
// sidesteps that edge rather than demonstrating it).
const group_key = [_]u8{0x5a} ** 32;

pub fn main() !void {
    var out: [256]u8 = undefined;
    const sealer: iec62351.goose.Sealer = .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &group_key } };

    const frame_bytes = try iec62351.buildAuthenticatedFrame(&out, .{
        .appid = 0x1000,
        .apdu = sample_apdu,
    }, sealer);
    std.debug.print("built authenticated GOOSE frame: {d} bytes ({d} APDU + {d} extension)\n", .{
        frame_bytes.len, sample_apdu.len, frame_bytes.len - iec62351.goose.apdu_offset - sample_apdu.len,
    });

    // ── subscriber side ─────────────────────────────────────────────────
    const verifier: iec62351.goose.Verifier = .{ .mac = .{ .algorithm = .hmac_sha256_128, .key = &group_key } };
    const result = try iec62351.verifyFrame(frame_bytes, .ed2020, verifier);
    std.debug.print("verified: apdu={d} bytes tag={d} bytes key_id={d}\n", .{
        result.frame.apdu.len, result.tag.len, result.unauthenticated.key_id,
    });
    if (!std.mem.eql(u8, result.frame.apdu, sample_apdu)) return error.ApduMismatch;

    // ── fail-closed: a bit flipped anywhere in the covered range must be
    // rejected, not silently accepted — this is the entire security value
    // of authenticating a GOOSE trip command.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..frame_bytes.len], frame_bytes);
    tampered[iec62351.goose.apdu_offset] ^= 0x01; // flip a byte inside the APDU

    _ = iec62351.verifyFrame(tampered[0..frame_bytes.len], .ed2020, verifier) catch |err| switch (err) {
        // Named, not `anyerror`: a subscriber drops the frame and logs the
        // specific reason rather than crashing on an unhandled error.
        error.AuthenticationFailed => {
            std.debug.print("tampered frame rejected: AuthenticationFailed\n", .{});
            return;
        },
        else => return err,
    };
    return error.TamperNotDetected;
}
