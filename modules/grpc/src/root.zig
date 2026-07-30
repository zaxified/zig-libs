// SPDX-License-Identifier: MIT
//! grpc — a **gRPC client and server** over HTTP/2, per the
//! `grpc-over-http2` protocol specification.
//!
//! It is the third piece of a stack whose other two already exist here: the
//! multiplexing HTTP/2 client and server in `http` carry the bytes,
//! `protobuf` codes the messages, and this module is the thin, exacting
//! layer between them — the five-byte length prefix, the header/trailer
//! contract, and the status.
//!
//! ```zig
//! // client
//! var hs = try client.connectH2c("127.0.0.1", port, .{});
//! defer hs.close();
//! var ch = grpc.Channel.overH2Session(hs, .{});
//!
//! var reply = try grpc.unary(EchoRequest, EchoReply, &ch,
//!     "/echo.Echo/Unary", .{ .text = "hi" }, .{});
//! defer reply.deinit();
//! std.debug.print("{s}\n", .{reply.value.text});
//! ```
//!
//! ```zig
//! // server
//! const M = grpc.Methods(EchoRequest, EchoReply);
//! var router: grpc.Router = .{ .gpa = gpa, .services = &.{.{
//!     .name = "echo.Echo",
//!     .methods = &.{ M.unary("Unary", myUnary), M.bidiStreaming("Bidi", myBidi) },
//! }} };
//! var srv = http.Server.init(io, gpa, router.httpOptions(.{
//!     .handler = grpc.handleHttp, .port = 50051,
//! }));
//! try srv.listen();
//! ```
//!
//! All four call shapes are supported on both sides and are the *same*
//! engine used differently (`call.zig` and `server.zig` explain why):
//! `unary` and `Stream` on the client, `Methods(Req, Rep)` on the server.
//!
//! ## The security-critical part
//!
//! A message's length is read from the wire before its bytes exist. See
//! `frame.zig`: the declared length never sizes an allocation, and
//! `Options.max_recv_message_size` (4 MiB, gRPC's own default) is enforced
//! the instant the 5-byte header completes — a 5-byte frame claiming 4 GiB
//! fails the call with `RESOURCE_EXHAUSTED` and buffers nothing. That is one
//! `Deframer` and therefore one property, on both sides: the server enforces
//! it against request messages exactly as the client does against replies.
//!
//! Provenance: clean-room from the published `grpc-over-http2` protocol
//! specification and `doc/compression.md` (public specifications —
//! CONVENTIONS.md §5); no gRPC implementation source was ported or studied.
//! The Python `grpcio` package is run as a black-box test oracle only, in
//! both directions — as the server our client calls, and as the client
//! calling our server. No NOTICE entry needed.

const std = @import("std");
const protobuf = @import("protobuf");

pub const meta = .{
    .platform = .any,
    .role = .both,
    .concurrency = .single_owner, // one task drives a Channel's session
    .model_after = "the grpc-over-http2 protocol specification; verified live against Python grpcio (the reference implementation), in both directions",
    .deps = .{ "http", "protobuf" },
};

const call_mod = @import("call.zig");
const frame_mod = @import("frame.zig");
const status_mod = @import("status.zig");
const metadata_mod = @import("metadata.zig");
const server_mod = @import("server.zig");

// ── status ──────────────────────────────────────────────────────────────────

/// The canonical status codes 0–16 (non-exhaustive: the wire may carry a
/// code from a newer spec revision).
pub const Status = status_mod.Status;
/// One Zig error per non-OK status.
pub const StatusError = status_mod.StatusError;
pub const statusToError = status_mod.toError;
pub const statusFromError = status_mod.fromError;
/// The status a non-200 HTTP response maps to.
pub const statusFromHttpStatus = status_mod.fromHttpStatus;

// ── framing ─────────────────────────────────────────────────────────────────

/// Length-Prefixed-Message framing on its own — useful for gRPC-Web, or for
/// anything else that must read the same envelope.
pub const frame = frame_mod;
pub const Deframer = frame_mod.Deframer;
pub const default_max_recv_message_size = frame_mod.default_max_recv_message_size;

// ── metadata ────────────────────────────────────────────────────────────────

pub const metadata = metadata_mod;
/// One metadata pair; `-bin` keys carry raw bytes and are base64-coded for
/// you in both directions.
pub const Entry = metadata_mod.Entry;

// ── calls ───────────────────────────────────────────────────────────────────

pub const Error = call_mod.Error;
pub const Options = call_mod.Options;
pub const CallOptions = call_mod.CallOptions;
pub const Failure = call_mod.Failure;
pub const Timeout = call_mod.Timeout;
pub const Channel = call_mod.Channel;
/// The untyped call: messages are opaque byte slices. Use it for a codec
/// other than protobuf, or when the schema is not known at compile time.
pub const Call = call_mod.Call;
/// Build `/{Service}/{Method}`.
pub const methodPath = call_mod.methodPath;

// ── typed surface ───────────────────────────────────────────────────────────

/// A typed RPC over `Call`: `Req` and `Rep` are ordinary Zig structs with a
/// `pb_fields` descriptor (see the `protobuf` module), encoded and decoded
/// with the schema derived at compile time.
///
/// One type covers server-streaming, client-streaming and bidirectional
/// calls, because the wire does not distinguish them:
///
/// ```zig
/// // server-streaming: one request, many replies
/// var s = try grpc.Stream(Req, Rep).start(&ch, "/svc/M", .{});
/// defer s.deinit();
/// try s.sendEnd(.{ .text = "go" });
/// while (try s.receive()) |*r| { defer r.deinit(); use(r.value); }
/// try s.finish();
///
/// // client-streaming: many requests, one reply — send, then closeSend
/// // bidirectional: interleave send and receive freely on the one stream
/// ```
pub fn Stream(comptime Req: type, comptime Rep: type) type {
    return struct {
        const Self = @This();

        call: Call,
        /// Decode options for received messages (nesting cap, unknown-field
        /// policy). The default already refuses a hostile nesting depth.
        decode_options: protobuf.DecodeOptions = .{},

        /// Open the stream and send the request head.
        pub fn start(ch: *Channel, path: []const u8, opts: CallOptions) Error!Self {
            return .{ .call = try ch.start(path, opts) };
        }

        pub fn deinit(s: *Self) void {
            s.call.deinit();
        }

        /// Encode and send one request message; the request side stays open.
        pub fn send(s: *Self, value: Req) (Error || protobuf.EncodeError)!void {
            return s.sendInner(value, false);
        }

        /// Encode and send the last request message, closing the request side
        /// with it (one frame, not two).
        pub fn sendEnd(s: *Self, value: Req) (Error || protobuf.EncodeError)!void {
            return s.sendInner(value, true);
        }

        /// Close the request side with no further message.
        pub fn closeSend(s: *Self) Error!void {
            return s.call.closeSend();
        }

        /// Block for the response head (status line + initial metadata)
        /// without waiting for a message. Optional — `receive` does it.
        pub fn readHead(s: *Self) Error!void {
            return s.call.readHead();
        }

        /// The next reply, or null when the response is complete. The result
        /// owns an arena; `deinit` it.
        pub fn receive(s: *Self) (Error || protobuf.DecodeError)!?protobuf.Decoded(Rep) {
            const bytes = try s.call.receive() orelse return null;
            return try protobuf.decode(Rep, s.call.ch.gpa, bytes, s.decode_options);
        }

        /// Drain to the end of the response and raise a non-OK status as an
        /// error.
        pub fn finish(s: *Self) Error!void {
            return s.call.finish();
        }

        fn sendInner(s: *Self, value: Req, end: bool) (Error || protobuf.EncodeError)!void {
            const gpa = s.call.ch.gpa;
            const bytes = try protobuf.encodeAlloc(gpa, value, .{});
            defer gpa.free(bytes);
            return s.call.sendMessage(bytes, end);
        }
    };
}

/// A unary RPC: send one message, receive exactly one, check the status.
/// "Exactly one" is enforced — a server that sends none (`MissingMessage`) or
/// two (`UnexpectedMessage`) has broken the unary contract, and quietly
/// taking the first is how a caller ends up acting on the wrong reply.
pub fn unary(
    comptime Req: type,
    comptime Rep: type,
    ch: *Channel,
    path: []const u8,
    request: Req,
    opts: CallOptions,
) (Error || protobuf.EncodeError || protobuf.DecodeError)!protobuf.Decoded(Rep) {
    var s = try Stream(Req, Rep).start(ch, path, opts);
    defer s.deinit();
    try s.sendEnd(request);
    var reply = try s.receive() orelse {
        // No message at all. Almost always because the call failed — a
        // Trailers-Only error response has no body by construction — so the
        // status has to be consulted before complaining about the absence,
        // or every server-side error would surface as `MissingMessage`.
        try s.finish();
        return error.MissingMessage;
    };
    errdefer reply.deinit();
    if (try s.receive()) |second| {
        var extra = second;
        extra.deinit();
        return error.UnexpectedMessage;
    }
    try s.finish();
    return reply;
}

// ── server ──────────────────────────────────────────────────────────────────

/// Everything server-side, one namespace deep, for callers who prefer
/// `grpc.server.Router` to the flat re-exports below.
pub const server = server_mod;

/// The routing table plus policy: hand it services and wire it into
/// `http.Server` with `Router.httpOptions` (or `h2_server` via
/// `Router.h2ServerOptions`). See `server.zig` for why registration is a
/// data table rather than comptime reflection over a struct's decls.
pub const Router = server_mod.Router;
/// One service: the `{Service}` half of `/{Service}/{Method}`.
pub const Service = server_mod.Service;
/// One method. Build these with `Methods(Req, Rep)`, or `Method.raw` for a
/// codec other than protobuf.
pub const Method = server_mod.Method;
/// The typed method constructors — one per call shape, so the shape is a
/// written decision rather than something inferred from a signature.
pub const Methods = server_mod.Methods;
/// One server-side RPC: `receive`, `send`, `fail`, plus the metadata and
/// deadline surfaces.
pub const ServerCall = server_mod.Call;
pub const ServerOptions = server_mod.Options;
pub const ServerError = server_mod.CallError;
/// Injected monotonic clock for `grpc-timeout` enforcement.
pub const Clock = server_mod.Clock;
/// `http.Server.Handler` for a `Router` — installed by `Router.httpOptions`.
pub const handleHttp = server_mod.handleHttp;

test {
    // Every submodule's tests, explicitly — a `pub const` re-export does not
    // pull them in (CONVENTIONS.md §6.3, the dark-tests rule).
    _ = status_mod;
    _ = frame_mod;
    _ = metadata_mod;
    _ = call_mod;
    _ = @import("call_test.zig");
    _ = @import("adversarial.zig");
    _ = server_mod;
    _ = @import("reference_interop.zig");
}
