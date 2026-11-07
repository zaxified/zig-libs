// SPDX-License-Identifier: MIT

//! Dead-stack probe for the proxy credentials (`testkit.stackprobe`):
//! `client_proxy.Endpoint.parse` decodes `user:password` into a 512-byte stack
//! scratch to validate it, and `Endpoint.writeAuthorization` decodes the same
//! credentials into a stack buffer to build the `Proxy-Authorization` line.
//! Both end in `std.crypto.secureZero`; no test saw a missing wipe in an
//! optimized build (whole-module mutation run, burn calls 10908/10909).
//! ReleaseFast only (`skipUnlessOptimized`, a runtime skip, so the body is
//! type-checked in every mode).
//!
//! `residue = false`: the frames below each burn belong to callees
//! (`decodeCredentials`, the base64 encoder) and hold public data or the
//! encoded form, not the decoded text; the needle check (the decoded
//! `user:password`, and for `writeAuthorization` its base64 form, in any
//! 16-byte window) is what pins the wipe, and the burn must exist (`burn =
//! true`: a zero run of the scratch's size).

const std = @import("std");
const sp = @import("testkit").stackprobe;
const client_proxy = @import("client_proxy.zig");

const P = sp.Probe(.{ .window = 32 * 1024 });

// The userinfo is percent-encoded on purpose (`%65` is `e`, `%40` is `@`): the
// decoded form only ever exists in the decode scratch, so a needle of the
// decoded text can come from nowhere else. 24 bytes, many distinct.
const raw: []const u8 = "http://alice:s3cr%65t-pa%40ss%21w0rd@proxy.example:3128";
const decoded: []const u8 = "alice:s3cret-pa@ss!w0rd";
/// `decoded` in base64 -- password-equivalent, the form `writeAuthorization`
/// puts on the wire; its stack copy must be wiped as well.
const encoded: []const u8 = "YWxpY2U6czNjcmV0LXBhQHNzIXcwcmQ=";

var out_buf: [256]u8 = undefined;
var out_w: std.Io.Writer = .fixed(&out_buf);

fn authorize(ep: client_proxy.Endpoint) anyerror!void {
    out_w = .fixed(&out_buf);
    try ep.writeAuthorization(&out_w);
}

test "STACKPROBE: no proxy credential residue after Endpoint.parse" {
    try sp.skipUnlessOptimized();
    const secrets = [_][]const u8{decoded};
    _ = try P.run("Endpoint.parse", client_proxy.Endpoint.parse, .{raw}, &secrets, .{ .residue = false });
}

test "STACKPROBE: no proxy credential residue after Endpoint.writeAuthorization" {
    try sp.skipUnlessOptimized();
    const ep = try client_proxy.Endpoint.parse(raw);
    const secrets = [_][]const u8{ decoded, encoded };
    _ = try P.run("Endpoint.writeAuthorization", authorize, .{ep}, &secrets, .{ .residue = false });
    // The call really produced the line (so the burn is not trivially "nothing ran").
    try std.testing.expect(std.mem.startsWith(u8, out_w.buffered(), "Proxy-Authorization: Basic "));
}
