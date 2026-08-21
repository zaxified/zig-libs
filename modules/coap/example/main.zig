// SPDX-License-Identifier: MIT

//! What a consumer does with `coap`: build a request with `client.Client`,
//! correlate a piggybacked response with `Exchange.match`, and read the
//! response body through the typed `options` accessors — all in memory, the
//! way the module's own doc comment sketches it. `coap.parse`/`serialize`
//! are transport-agnostic on purpose (RFC 7252 says nothing about the
//! socket), so a UDP endpoint is exactly this plus a real `std.Io.net.Udp`
//! underneath; nothing here needs one to prove the API holds together.
//!
//! Built against the PUBLISHED module (`@import("coap")`) only.

const std = @import("std");
const coap = @import("coap");

pub fn main() !void {
    var client = coap.client.Client.init(0x1000, 0x40);
    var opts_buf: [16]coap.Option = undefined;
    var scratch: [128]u8 = undefined;
    var out: [256]u8 = undefined;

    // GET coap://sensor.local/temp, asking for a JSON reply.
    const req = try client.buildRequest(.get, "coap://sensor.local/temp", .{
        .accept = coap.options.content_format.json,
    }, &opts_buf, &scratch, &out);
    std.debug.print("request: {d} bytes, token len {d}\n", .{ req.datagram.len, req.exchange.token().len });

    // A confirmable request needs retransmission until it is ACKed; the
    // reliability layer owns that timer, independent of the client layer.
    var rt = coap.reliability.Retransmit.init(.{}, 0, 0);
    std.debug.print("initial retransmit timeout: {d} ms\n", .{rt.timeout_ms});

    // The sensor answers with a piggybacked 2.05 Content, same message id
    // and token as the request — build that reply by hand the way a UDP
    // recv would hand it over.
    var reply_opts: [4]coap.Option = undefined;
    const cf_bytes = [_]u8{coap.options.content_format.json};
    const reply_msg: coap.Message = .{
        .type = .ack,
        .code = .content,
        .message_id = req.exchange.message_id,
        .token = req.exchange.token(),
        .options = &.{.{ .number = coap.options.number.content_format, .value = &cf_bytes }},
        .payload = "{\"celsius\":21.5}",
    };
    var reply_buf: [128]u8 = undefined;
    const reply_len = try coap.serialize(reply_msg, &reply_buf);

    const parsed_reply = try coap.parse(reply_buf[0..reply_len], &reply_opts);
    switch (req.exchange.match(parsed_reply)) {
        .piggybacked => {
            rt.ack();
            const cf = (try coap.options.contentFormat(parsed_reply)) orelse return error.NoContentFormat;
            std.debug.print(
                "response: {d}.{d:0>2} content-format={d} body={s}\n",
                .{ parsed_reply.code.class(), parsed_reply.code.detail(), cf, parsed_reply.payload },
            );
        },
        // A real endpoint handles every branch; a consumer that only cares
        // about the happy path still has to name what it's declining.
        .empty_ack, .separate, .reset, .unrelated => return error.UnexpectedMatch,
    }

    // A malformed reply (cut off mid-token) never panics — it is the first
    // thing done with attacker-controlled UDP bytes.
    const truncated = reply_buf[0..6]; // 4-byte header + only 2 of the 4 token bytes
    var trunc_opts: [4]coap.Option = undefined;
    if (coap.parse(truncated, &trunc_opts)) |_| {
        return error.TruncatedDatagramShouldHaveFailed;
    } else |err| switch (err) {
        error.Truncated => std.debug.print("truncated reply rejected: {s}\n", .{@errorName(err)}),
        else => return err,
    }
}
