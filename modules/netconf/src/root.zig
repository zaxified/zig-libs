// SPDX-License-Identifier: MIT

//! netconf — a NETCONF client (RFC 6241) over the sibling `ssh` module.
//!
//! Four layers, each usable on its own:
//!
//! * `framing` (RFC 6242) — both framing dialects as one pure state machine:
//!   the legacy `]]>]]>` end-of-message mechanism (§4.3) and the chunked
//!   mechanism (§4.2). The dialect switch is an explicit, guarded transition
//!   that can only happen at a message boundary — which is exactly where RFC
//!   6242 §4.1 puts it, right after the hello exchange.
//! * `capabilities` (RFC 6241 §8.1) — `<hello>` parsing/serialisation, the
//!   capability set (standard ones resolved, YANG module capabilities kept
//!   verbatim), the `<session-id>` rules, and `negotiate`, the one place the
//!   dialect is decided.
//! * `rpc` (RFC 6241 §7/§8, RFC 5277 §2.1.1) — request builders for every
//!   standard operation plus a `raw` escape hatch, as pure serialisation.
//! * `reply` (RFC 6241 §4.2–§4.3, RFC 5277 §2.2.1) — `<rpc-reply>` with
//!   `<ok>`/`<data>`/`<rpc-error>` and `<notification>`, parsed with the
//!   sibling `xml` module (no second XML parser lives here).
//!
//! `client` ties them into a session: hello exchange, monotonic `message-id`
//! allocation, reply correlation, notification queueing, and `SshTransport`,
//! the adapter onto `ssh.connection.Session` after `subsystem("netconf")`.
//!
//! **Blocking policy:** this module owns none. Exactly one call blocks —
//! `Client.pumpOnce`, one read on a caller-supplied `Transport` — and the
//! framer underneath is a pure `feed`/`next` state machine. A caller that
//! wants a read timeout implements it inside its own `Transport.read`; there
//! is no timer thread here. See README.md.
//!
//! Verified against a live third-party NETCONF server (see SPEC.md) in both
//! framing dialects, plus byte-exact goldens taken verbatim from RFC 6242
//! §4.2/§4.3, RFC 6241 §7–§8 and RFC 5277.
//!
//! Provenance: clean-room from RFC 6241 / RFC 6242 / RFC 5277; XML parsing
//! from this repo's `xml` module, SSH transport from its `ssh` module. No
//! third-party source consulted — see `SPEC.md`.

const std = @import("std");

pub const framing = @import("framing.zig");
pub const capabilities = @import("capabilities.zig");
pub const rpc = @import("rpc.zig");
pub const reply = @import("reply.zig");
pub const client = @import("client.zig");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "NETCONF client (RFC 6241) over SSH — RFC 6242 framing, hello/capability exchange, get/get-config/edit-config/commit RPCs with typed replies",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .client,
    // One Client owns one session's framer, message-id counter and buffers;
    // nothing shared or global. Concurrency (and any read timeout) belongs to
    // the caller's Transport implementation.
    .concurrency = .single_owner,
    .model_after = "RFC 6241 (NETCONF) + RFC 6242 (NETCONF over SSH) + RFC 5277 (notifications); framing/dialect behaviour cross-checked against a live third-party NETCONF server",
    .deps = .{ "ssh", "xml" },
};

// ── top-level names (the ones a consumer actually types) ───────────────────

/// A NETCONF session over any byte stream. See `client.zig`.
pub const Client = client.Client;
/// The byte-stream seam: one blocking `read`, one `write`.
pub const Transport = client.Transport;
pub const TransportError = client.TransportError;
pub const SessionError = client.SessionError;
pub const Options = client.Options;
pub const State = client.State;

/// Adapter onto an `ssh.connection.Session` that has requested the `netconf`
/// subsystem (RFC 6242 §2).
pub const SshTransport = client.SshTransport;

/// RFC 6242 framing, both dialects, as a pure state machine.
pub const Framer = framing.Framer;
pub const Dialect = framing.Dialect;
pub const Limits = framing.Limits;

/// Request model (RFC 6241 §7/§8).
pub const Rpc = rpc.Rpc;
pub const Datastore = rpc.Datastore;
pub const ConfigSource = rpc.ConfigSource;
pub const Filter = rpc.Filter;
pub const EditConfig = rpc.EditConfig;
pub const EditPayload = rpc.EditPayload;
pub const CopyConfig = rpc.CopyConfig;
pub const Commit = rpc.Commit;
pub const CreateSubscription = rpc.CreateSubscription;
pub const Operation = rpc.Operation;
pub const DefaultOperation = rpc.DefaultOperation;
pub const TestOption = rpc.TestOption;
pub const ErrorOption = rpc.ErrorOption;

/// Reply model (RFC 6241 §4.2–§4.3).
pub const Reply = reply.Reply;
pub const RpcError = reply.RpcError;
pub const ErrorTag = reply.ErrorTag;
pub const ErrorType = reply.ErrorType;
pub const ErrorSeverity = reply.ErrorSeverity;
pub const Notification = reply.Notification;

/// Capability model (RFC 6241 §8.1).
pub const Capabilities = capabilities.Capabilities;
pub const Hello = capabilities.Hello;
/// The NETCONF base XML namespace (stays `:base:1.0` even in a 1.1 session).
pub const base_ns = capabilities.base_ns;

/// Build one `<rpc>` document into an allocated buffer, without a session.
pub const buildRpc = rpc.buildRpc;
/// Parse one `<rpc-reply>` document, without a session.
pub const parseReply = reply.parseReply;
/// Parse one `<hello>` document, without a session.
pub const parseHello = capabilities.parseHello;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ───────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s tests
// into the test binary on its own — every submodule must be named here too.
test {
    _ = framing;
    _ = capabilities;
    _ = rpc;
    _ = reply;
    _ = client;
}

test "meta.deps names the modules this one is built on" {
    try std.testing.expectEqualStrings("ssh", meta.deps[0]);
    try std.testing.expectEqualStrings("xml", meta.deps[1]);
}
