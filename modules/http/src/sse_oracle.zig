// SPDX-License-Identifier: MIT

//! OFFLINE anchor for `sse`, taken by `zig build interop-http -- --phase sse`
//! (`tools/oracles.zig`): our server streamed the events and comments in
//! `sse_oracle_vectors.zig`, curl fetched the stream, and sseclient-py and
//! httpx-sse dispatched exactly what the WHATWG §9.2.6 parsing rules make of
//! what was meant (type, data with CR/CRLF as LF, last event ID, retry);
//! httpx-sse's dispatch of comment-only blocks is listed there as its own
//! departure. Teeth, at capture: the stream with one event terminator removed
//! fails. Here `writeEvent`/`writeComment` must still produce that stream byte
//! for byte.

const std = @import("std");
const testing = std.testing;
const sse = @import("sse.zig");
const vectors = @import("sse_oracle_vectors.zig");

test "sse oracle: the stream both Python clients read correctly is what the writer still writes" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    for (vectors.events) |ev| try sse.writeEvent(&out.writer, ev);
    for (vectors.comments) |c| try sse.writeComment(&out.writer, c);
    try testing.expectEqualStrings(vectors.stream, out.written());
}
