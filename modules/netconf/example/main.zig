// SPDX-License-Identifier: MIT

//! What a consumer does with `netconf` without opening an SSH session: build
//! a `<get-config>` request, negotiate the framing dialect from two `<hello>`
//! documents, and parse both a successful and a failing `<rpc-reply>`. This
//! is the module's own advertised seam — `buildRpc`/`parseReply`/
//! `parseHello`/`negotiate` are exported "without a session" precisely so
//! the request/reply grammar can be exercised without a live device.
//!
//! Built against the PUBLISHED module (`@import("netconf")`) only.

const std = @import("std");
const netconf = @import("netconf");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── build a request ─────────────────────────────────────────────────
    const request = try netconf.buildRpc(gpa, 1, .{ .get_config = .{
        .source = .running,
        .filter = .{ .subtree = "<interfaces xmlns=\"urn:example:if\"/>" },
    } });
    defer gpa.free(request);
    std.debug.print("request ({d} bytes):\n{s}\n", .{ request.len, request });

    // ── negotiate the framing dialect from both sides' <hello> ─────────
    var ours = try netconf.Capabilities.fromSlice(gpa, &netconf.capabilities.default_client_capabilities);
    defer ours.deinit();

    const server_hello =
        \\<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <capabilities>
        \\    <capability>urn:ietf:params:netconf:base:1.0</capability>
        \\    <capability>urn:ietf:params:netconf:base:1.1</capability>
        \\  </capabilities>
        \\  <session-id>4</session-id>
        \\</hello>
    ;
    var server = try netconf.parseHello(gpa, server_hello, .server);
    defer server.deinit();

    const dialect = try netconf.capabilities.negotiate(&ours, &server.capabilities);
    std.debug.print("negotiated dialect: {s}, session-id={d}\n", .{ @tagName(dialect), server.session_id.? });

    // ── a successful reply ───────────────────────────────────────────────
    const ok_reply =
        \\<rpc-reply message-id="1" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <data><interfaces xmlns="urn:example:if"><eth0/></interfaces></data>
        \\</rpc-reply>
    ;
    var reply = try netconf.parseReply(gpa, ok_reply);
    defer reply.deinit();
    try reply.expectMessageId(1);
    const data = try reply.expectData();
    std.debug.print("reply data: {s}\n", .{data});

    // ── a failing reply, handled by name ────────────────────────────────
    const err_reply =
        \\<rpc-reply message-id="2" xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
        \\  <rpc-error>
        \\    <error-type>application</error-type>
        \\    <error-tag>invalid-value</error-tag>
        \\    <error-severity>error</error-severity>
        \\    <error-message>no such interface</error-message>
        \\  </rpc-error>
        \\</rpc-reply>
    ;
    var failed = try netconf.parseReply(gpa, err_reply);
    defer failed.deinit();
    if (failed.expectData()) |_| {
        return error.ExpectedRpcError;
    } else |err| switch (err) {
        error.RpcError => {
            const e = failed.firstError().?;
            std.debug.print("rpc-error: tag={s} message={s}\n", .{ @tagName(e.tag), e.message.? });
        },
        else => return err,
    }
}
