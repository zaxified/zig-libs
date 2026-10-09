// SPDX-License-Identifier: MIT

//! ctgrind_harness — the constant-time evidence for `SPEC.md`'s Hardening line.
//! Run it through `../../../scripts/checks/ctgrind.sh mqtt`, which builds
//! every mode/taint combination and prints the control table.
//!
//! Not wired into `zig build test-mqtt`: memcheck's context count is
//! valgrind's own output. `zig build check-ctgrind` only compiles it.
//!
//! ## What this measures
//!
//! The module's secrets are the CONNECT password (3.1.3.5, opaque binary) and
//! the 5.0 Authentication Data property (CONNECT and AUTH). The codec only
//! moves them — length-prefixed copy on encode, a slice on decode — and this
//! harness is what says that is all it does:
//!
//!  * `encode` — password and auth data tainted, then `encodePacket` of a
//!    3.1.1 CONNECT, a 5.0 CONNECT with method + data, and a 5.0 AUTH.
//!  * `decode` — those packets encoded from untainted credentials, then ONLY
//!    the credential bytes inside the wire image tainted (lengths, flags and
//!    every other field stay defined: they are public) and decoded back with
//!    `decodePacket`.
//!
//! ## The propagation witness
//!
//! Every result is printed as `ctgrind_result={x}` over its bytes; the hex
//! formatter is not constant-time, so the total is non-zero while the in-file
//! count is zero.

const std = @import("std");
const builtin = @import("builtin");
const packet = @import("packet.zig");

const Target = enum { encode, decode };
const Taint = enum { yes, no };

const cred_len = 32;

/// A runtime (not comptime-foldable) stand-in for a secret.
fn secretBytes(label: []const u8) [cred_len]u8 {
    var out: [cred_len]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &out, .{});
    return out;
}

fn reloadVolatile(src: *const [cred_len]u8) [cred_len]u8 {
    var out: [cred_len]u8 = undefined;
    for (&out, src) |*o, *b| {
        const vb: *const volatile u8 = b;
        o.* = vb.*;
    }
    return out;
}

fn packets(password: []const u8, auth_data: []const u8) [3]struct { packet.Version, packet.Packet } {
    return .{
        .{ .v3_1_1, .{ .connect = .{ .client_id = "ct-client", .username = "ct-user", .password = password } } },
        .{ .v5, .{ .connect = .{
            .client_id = "ct-client",
            .username = "ct-user",
            .password = password,
            .version = .v5,
            .properties = .{ .authentication_method = "SCRAM-SHA-256", .authentication_data = auth_data },
        } } },
        .{ .v5, .{ .auth = .{
            .reason_code = .continue_authentication,
            .properties = .{ .authentication_method = "SCRAM-SHA-256", .authentication_data = auth_data },
        } } },
    };
}

/// Mark `secret`'s bytes inside `wire` undefined. The position is found
/// before tainting, from the untainted wire image: where a credential sits is
/// public (it follows from public lengths).
fn taintWithin(wire: []u8, secret: []const u8) void {
    const at = std.mem.indexOf(u8, wire, secret) orelse @panic("credential not in wire image");
    std.valgrind.memcheck.makeMemUndefined(wire[at..][0..secret.len]);
}

pub fn main(init: std.process.Init.Minimal) !void {
    var it = init.args.iterate();
    _ = it.next(); // argv[0]
    const target = std.meta.stringToEnum(Target, it.next() orelse return error.MissingTarget) orelse
        return error.UnknownTarget;
    const taint = std.meta.stringToEnum(Taint, it.next() orelse return error.MissingTaint) orelse
        return error.UnknownTaint;

    std.debug.print("valgrind_support={} target={t}\n", .{ builtin.valgrind_support, target });

    var pw_raw = secretBytes("ctgrind-mqtt-password-v1");
    var ad_raw = secretBytes("ctgrind-mqtt-auth-data-v1");

    switch (target) {
        .encode => {
            if (taint == .yes) {
                std.valgrind.memcheck.makeMemUndefined(&pw_raw);
                std.valgrind.memcheck.makeMemUndefined(&ad_raw);
            }
            const pw = reloadVolatile(&pw_raw);
            const ad = reloadVolatile(&ad_raw);
            for (packets(&pw, &ad)) |vp| {
                var buf: [256]u8 = undefined;
                const wire = try packet.encodePacket(&buf, vp[0], vp[1]);
                std.debug.print("ctgrind_result={x}\n", .{wire});
            }
        },
        .decode => {
            for (packets(&pw_raw, &ad_raw)) |vp| {
                var buf: [256]u8 = undefined;
                const wire = buf[0..(try packet.encodePacket(&buf, vp[0], vp[1])).len];
                if (taint == .yes) {
                    if (vp[1] == .connect) taintWithin(wire, &pw_raw);
                    if (vp[0] == .v5) taintWithin(wire, &ad_raw);
                }
                const d = (try packet.decodePacket(wire, vp[0])) orelse return error.Incomplete;
                const props = switch (d.packet) {
                    .connect => |c| c.properties,
                    .auth => |a| a.properties,
                    else => return error.UnexpectedPacket,
                };
                var res: [2 * cred_len]u8 = @splat(0);
                if (d.packet == .connect) @memcpy(res[0..cred_len], d.packet.connect.password.?);
                if (props.authentication_data) |ad| @memcpy(res[cred_len..], ad);
                std.debug.print("ctgrind_result={x}\n", .{res});
            }
        },
    }
}
