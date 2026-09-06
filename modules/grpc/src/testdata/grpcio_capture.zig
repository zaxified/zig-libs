// SPDX-License-Identifier: MIT

//! GENERATED — do not hand-edit. Rewritten by
//! `zig build interop-grpc -- --capture` (see `../../tools/interop.zig`).
//!
//! ## What this is
//!
//! A byte-for-byte recording of a conversation with the **reference** gRPC
//! implementation, Python `grpcio` (the stack the gRPC project ships).
//! `../reference_replay.zig` replays it with no child process, no socket
//! and no foreign source, so the anchor's evidence runs on every machine —
//! including one with no `python3` and no `go` anywhere.
//!
//! ## What each recording contains
//!
//! `forward` entries are the bytes the reference **server** put on the wire,
//! taped at the socket by this module's own h2 client. One entry per case,
//! each from its own fresh connection.
//!
//! `reverse_client` is the bytes the reference **client** put on the wire
//! against our server, taped the same way; `reverse_report` is the
//! `KEY\tVALUE` report that same client printed after reading our replies.
//! A server reference and a client reference test opposite directions and
//! both are here.
//!
//! ## What is pinned, and how replay is made deterministic
//!
//! gRPC over HTTP/2 carries several things that differ run to run. None of
//! them is reached by comparing less:
//!
//!   * **Stream ids** — every forward case records its OWN connection, so
//!     ids restart at 1 and the client that replays them opens streams in
//!     the identical order. A shared connection would have made each case
//!     depend on which others ran first.
//!   * **HPACK dynamic-table state** — self-contained in each recording for
//!     the same reason: the field blocks are replayed from the byte the
//!     table was empty at, so every indexed reference resolves.
//!   * **Flow control** — the recording holds the peer's whole side up
//!     front. Our own WINDOW_UPDATEs still go out during replay (into a
//!     discarded writer); the peer's accounting was settled at capture.
//!   * **`grpc-timeout`** — the value grpcio renders is chosen from the
//!     wall-clock gap between "deadline set" and "request framed", so the
//!     same 30 s call is `30100m` on one run and `30S` on another. The
//!     recording pins ONE such rendering and the replay asserts the band it
//!     produced, exactly as the live run does — the literal itself is
//!     grpcio's timing artifact, not this module's behaviour.
//!   * **Timestamps** — gRPC responses carry no `date` header (grpcio does
//!     not send one, and our server's `now` hook is left null), so nothing
//!     in these bytes moves with the clock.
//!
//! ## What replay CANNOT carry, and where that still runs
//!
//! In the forward direction the replay is complete: the reference produced
//! those bytes and our client parses them, which is the whole test.
//!
//! In the reverse direction the replay covers the half that is recordable —
//! grpcio's requests, decoded by our server. Whether grpcio can READ our
//! server's replies cannot be replayed at all (it needs grpcio). What
//! bridges the gap is `reverse_report`: the replay asserts our server's
//! decoded output against the values the reference itself read off the
//! wire, so those expectations keep grpcio as their provenance rather than
//! becoming numbers someone typed. A NEW divergence there is still only
//! findable by `zig build interop-grpc`.

pub const Case = struct {
    name: []const u8,
    /// The peer's side of one conversation, from byte zero.
    bytes: []const u8,
};

/// Look one up by name; `null` if the fixture was regenerated without it,
/// which the replay turns into a failing test rather than a silent skip.
pub fn find(name: []const u8) ?Case {
    for (forward) |c| {
        if (@import("std").mem.eql(u8, c.name, name)) return c;
    }
    return null;
}

/// The reference implementation this fixture was taken from.
pub const reference = "Python grpcio 1.83.0 / protobuf 7.35.1";

/// The day it was taken.
pub const captured_on = "2026-09-06";

/// The exact command that produced it, run from the repository root.
pub const command = "zig build interop-grpc -- --capture";

/// The service the reverse direction was recorded against. Changing
/// the method set on one side without the other is what this records.
pub const reverse_service = "echo.Echo: Unary ServerStream ClientStream Bidi Fail StreamFail Empty Big Meta Deadline";

/// The reference SERVER's side, one entry per case.
pub const forward = [_]Case{
    .{ .name = "unary", .bytes = @embedFile("grpcio/unary.bin") },
    .{ .name = "server_stream", .bytes = @embedFile("grpcio/server_stream.bin") },
    .{ .name = "client_stream", .bytes = @embedFile("grpcio/client_stream.bin") },
    .{ .name = "bidi", .bytes = @embedFile("grpcio/bidi.bin") },
    .{ .name = "fail", .bytes = @embedFile("grpcio/fail.bin") },
    .{ .name = "trailers_only", .bytes = @embedFile("grpcio/trailers_only.bin") },
    .{ .name = "stream_fail", .bytes = @embedFile("grpcio/stream_fail.bin") },
    .{ .name = "big", .bytes = @embedFile("grpcio/big.bin") },
    .{ .name = "metadata", .bytes = @embedFile("grpcio/metadata.bin") },
    .{ .name = "deadline_none", .bytes = @embedFile("grpcio/deadline_none.bin") },
    .{ .name = "deadline_seconds", .bytes = @embedFile("grpcio/deadline_seconds.bin") },
    .{ .name = "deadline_millis", .bytes = @embedFile("grpcio/deadline_millis.bin") },
    .{ .name = "multiplex", .bytes = @embedFile("grpcio/multiplex.bin") },
};

/// The reference CLIENT's side, driving our server: one connection
/// carrying all twelve of its calls.
pub const reverse_client: []const u8 = @embedFile("grpcio/reverse_client.bin");

/// What that same client printed after reading our server's replies —
/// `KEY\tVALUE` per observation. The replay checks our server's decoded
/// output against these, so the expectations are the reference's
/// readings and not hand-typed constants.
pub const reverse_report: []const u8 = @embedFile("grpcio/reverse_report.txt");
