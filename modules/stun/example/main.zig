// SPDX-License-Identifier: MIT

//! What a NAT-traversal consumer does with `stun`: build a Binding request
//! carrying a short-term credential, hand the wire bytes to a transport of
//! its own choosing (here, simulated in-process rather than real UDP — the
//! module's own `query` helper already covers the batteries-included path),
//! decode the server's response, verify its integrity, and read back the
//! public address the server observed.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to build/verify a message is not public, or an error cannot be
//! named from outside, this file stops compiling.

const std = @import("std");
const stun = @import("stun");
const netaddr = @import("netaddr");

const credential = "s3cr3t-short-term-password";

pub fn main() !void {
    const txid: stun.TransactionId = .{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 };

    // Build a Binding request: SOFTWARE, then MESSAGE-INTEGRITY and
    // FINGERPRINT last (in that order, per RFC 8489 -- each covers every
    // byte written before it).
    var req_buf: [128]u8 = undefined;
    var b = try stun.Builder.init(&req_buf, .request, .binding, txid);
    try b.addSoftware("zig-libs stun example");
    try b.addMessageIntegrity(credential);
    try b.addFingerprint();
    const request = b.finish();

    const parsed_req = try stun.decode(request);
    std.debug.print("built request: class={s} method={s} {d} bytes\n", .{
        @tagName(parsed_req.class), @tagName(parsed_req.method), request.len,
    });

    // A no-op fingerprint check against a truncated buffer, to exercise a
    // named error from DecodeError before we move on to the happy path.
    const truncated = request[0 .. stun.header_len - 1];
    _ = stun.decode(truncated) catch |err| switch (err) {
        error.Truncated => std.debug.print("decode correctly rejected a header-less buffer\n", .{}),
        else => return err,
    };

    // Simulate the server's success response: it echoes our transaction id
    // and reflects back our (fictional) public address as XOR-MAPPED-ADDRESS,
    // signed with the same short-term credential.
    const public_ip = netaddr.parseIp("203.0.113.42").?;
    var resp_buf: [128]u8 = undefined;
    var rb = try stun.Builder.init(&resp_buf, .success_response, .binding, txid);
    try rb.addMappedAddress(public_ip, 51820, true); // XOR-MAPPED-ADDRESS
    try rb.addMessageIntegrity(credential);
    try rb.addFingerprint();
    const response = rb.finish();

    // A real client would receive this over UDP and hand the bytes here.
    const msg = try stun.decode(response);
    if (!std.mem.eql(u8, &msg.transaction_id, &txid)) @panic("transaction id mismatch");
    if (!msg.verifyFingerprint()) @panic("FINGERPRINT did not verify");
    if (!msg.verifyMessageIntegrity(credential)) @panic("MESSAGE-INTEGRITY did not verify");

    const addr = (try msg.mappedAddress()) orelse @panic("response carried no mapped address");
    var ip_buf: [netaddr.max_ip_text_len]u8 = undefined;
    std.debug.print("reflexive address: {s}:{d}\n", .{ netaddr.formatIp(addr.ip, &ip_buf), addr.port });

    // A response signed with the wrong credential must fail verification --
    // the whole point of MESSAGE-INTEGRITY.
    if (msg.verifyMessageIntegrity("wrong-password")) @panic("verification must not accept a wrong credential");
    std.debug.print("wrong-credential check correctly failed\n", .{});
}
