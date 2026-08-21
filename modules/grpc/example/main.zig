// SPDX-License-Identifier: MIT

//! What a consumer does with `grpc`'s framing and status layers on their
//! own — the module's own doc comment calls this out explicitly:
//! `frame.Deframer` is "useful for gRPC-Web, or for anything else that must
//! read the same envelope" without the full `Channel`/`Call` machinery, and
//! the length-prefix framing does not care what codec produced the message
//! bytes. Everything here stays in memory: frame a message with the 5-byte
//! length prefix, feed the wire bytes through the deframer in two
//! chopped-up pushes the way a real stream would arrive, and map an
//! HTTP-level failure onto a gRPC status and a named Zig error.
//!
//! Built against the PUBLISHED module (`@import("grpc")`) only: no
//! `test_deps`, no `http` session, no socket.

const std = @import("std");
const grpc = @import("grpc");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    // ── frame ────────────────────────────────────────────────────────────
    const message_bytes = "hi";
    const framed = try grpc.frame.encodeAlloc(gpa, message_bytes);
    defer gpa.free(framed);
    std.debug.print("framed {d} message byte(s) into {d} wire byte(s)\n", .{
        message_bytes.len,
        framed.len,
    });

    // ── deframe ──────────────────────────────────────────────────────────
    // A real stream does not hand the 5-byte header and the payload over in
    // one read; split the frame mid-header to prove the deframer buffers a
    // partial prefix rather than needing a whole frame per `push`.
    var deframer: grpc.Deframer = .{};
    defer deframer.deinit(gpa);

    const split = 3; // inside the 5-byte header
    try deframer.push(gpa, framed[0..split]);
    if (try deframer.next()) |_| return error.UnexpectedEarlyMessage;

    try deframer.push(gpa, framed[split..]);
    const recovered = (try deframer.next()) orelse return error.MissingMessage;
    std.debug.print("recovered message: \"{s}\"\n", .{recovered});

    try deframer.endOfStream(); // no bytes left dangling mid-message

    // ── status ───────────────────────────────────────────────────────────
    // An intermediary that has never heard of gRPC answers with a plain HTTP
    // failure instead of a `grpc-status` trailer; `statusFromHttpStatus` is
    // the spec's fallback table for turning that into the same `Status` a
    // real trailer would have carried.
    const status = grpc.statusFromHttpStatus(503);
    std.debug.print("http 503 -> grpc status {s}\n", .{status.name()});

    // The normal path is a real trailer pair. Both halves have to be public
    // for a consumer reading this envelope from anywhere else -- gRPC-Web, a
    // proxy, a capture -- which is what `frame.Deframer`'s own doc invites.
    // (They were not, until this example went looking for them.)
    const trailer = grpc.statusParse("14") orelse return error.BadTrailer;
    var msg_buf: [64]u8 = undefined;
    const detail = grpc.statusDecodeMessage("upstream%20closed", &msg_buf);
    std.debug.print("trailer grpc-status={s} grpc-message=\"{s}\"\n", .{ trailer.name(), detail });

    // Strictness is the point: a value a lenient parser would wave through as
    // `.ok` must come back null, not zero.
    if (grpc.statusParse(" 0") != null) return error.LenientStatusParse;

    reportRpc(status) catch |err| switch (err) {
        // Handled by name: a caller that wants to retry unavailable calls
        // and surface everything else does exactly this.
        error.Unavailable => std.debug.print("transient failure, would retry\n", .{}),
        else => return err,
    };
}

fn reportRpc(status: grpc.Status) grpc.StatusError!void {
    if (status == .ok) return;
    return grpc.statusToError(status);
}
