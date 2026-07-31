// SPDX-License-Identifier: MIT

//! imap — an IMAP4rev2 (RFC 9051) client, in pure Zig.
//!
//! **Status: part 1 of 2 — the wire layer.** What is here is the encoding
//! that mailbox names travel in; the response decoder, the command encoder and
//! the session (`CAPABILITY` / `LOGIN` / `SELECT`) land next, then `FETCH` /
//! `BODYSTRUCTURE` / `SEARCH` / `IDLE`.
//!
//! Like `smtp` and `dtls`, this module **owns no socket and speaks no TLS**.
//! It works on caller-supplied bytes and `std.Io` streams, so it drops onto
//! plain TCP, `std.crypto.tls.Client`, or a test buffer unchanged. That seam
//! is why `emersion/go-imap` was chosen as the port source over the Rust and
//! Python candidates: its client takes an already-connected socket and runs
//! every protocol path over reader/writer interfaces, which is the shape this
//! repo already uses.
//!
//! IMAP4rev2 is a superset of IMAP4rev1 (RFC 3501) for everything this client
//! sends, so a rev1-only server is a supported peer.

const std = @import("std");

pub const meta = .{
    .platform = .any,
    .role = .client,
    .concurrency = .single_owner,
    .model_after = "emersion/go-imap v2 (MIT) — ported, not merely referenced; see modules/imap/NOTICE",
    .deps = .{},
};

/// Modified UTF-7 (RFC 3501 §5.1.3), the encoding IMAP mailbox names use.
pub const utf7 = @import("utf7.zig");

/// The wire grammar (RFC 9051 §9), decode side.
pub const wire = @import("wire.zig");

/// Server responses (RFC 9051 §7): continuation, tagged, untagged data.
pub const response = @import("response.zig");

/// Commands (RFC 9051 §6), encode side.
pub const command = @import("command.zig");

/// `FETCH` (RFC 9051 §6.4.5, §7.5.2): envelopes, body structures, sections.
pub const fetch = @import("fetch.zig");

/// `SEARCH` (RFC 9051 §6.4.4), both reply shapes.
pub const search = @import("search.zig");

/// The client session (RFC 9051 §3): state, tag matching, literal handshake.
pub const client = @import("client.zig");
pub const Client = client.Client;

test {
    // A `pub const x = @import(...)` re-export does NOT pull x's tests into
    // the test binary (CONVENTIONS §6.3 — this is what hid 52 never-run tests
    // in `websocket`). Every submodule must be named here.
    _ = utf7;
    _ = wire;
    _ = response;
    _ = command;
    _ = fetch;
    _ = search;
    _ = client;
    // LIVE interop; skips loudly when the peer is not installed.
    _ = @import("live_test.zig");
}

test "meta is well-formed" {
    try std.testing.expect(meta.deps.len == 0);
    try std.testing.expectEqualStrings("client", @tagName(meta.role));
}
