// SPDX-License-Identifier: MIT

//! smtp — an SMTP client (RFC 5321) with MIME message composition, in pure Zig.
//!
//! Seven layers, each usable on its own and none of them owning a socket:
//!
//! * `reply` (RFC 5321 §4.2, RFC 3463) — the multi-line reply as an incremental
//!   `feed`/`next` state machine, with the permanent (5yz) / transient (4yz)
//!   distinction as typed errors.
//! * `capabilities` (RFC 5321 §4.1.1.1, RFC 1869) — the ESMTP keyword set from
//!   the EHLO reply: STARTTLS, AUTH, PIPELINING, SIZE, 8BITMIME, SMTPUTF8,
//!   ENHANCEDSTATUSCODES; unknown keywords kept, never rejected.
//! * `command` (RFC 5321 §4.1) — command serialisation into a caller buffer,
//!   with the §4.5.3.1 length ceilings and a hard refusal of CR/LF/NUL in any
//!   argument (SMTP command injection).
//! * `data` (RFC 5321 §4.5.2) — dot-stuffing and un-stuffing, and the
//!   `CRLF.CRLF` terminator, strict about the bare-LF ambiguity that "SMTP
//!   smuggling" turns into message injection.
//! * `auth` (RFC 4954, RFC 4616) — SASL PLAIN and LOGIN.
//! * `mime` (RFC 5322, RFC 2045/2047) — header folding, encoded words,
//!   quoted-printable, base64, RFC 5322 dates.
//! * `message` — the composer: address headers, `multipart/mixed` and
//!   `multipart/alternative`, attachments with `Content-Disposition`, and
//!   boundary generation that **checks** the boundary does not occur in any
//!   part rather than assuming it.
//!
//! `session` is a pure state machine over all of that — greeting, EHLO with
//! HELO fallback, STARTTLS, AUTH, the MAIL/RCPT/DATA transaction with optional
//! PIPELINING grouping, QUIT — driven by `next()`/`feedReply()` with no I/O
//! whatsoever, so a whole conversation is testable without a socket. `client`
//! is the thin loop that runs a `session` over a caller-supplied `Transport`.
//!
//! **Blocking policy:** this module owns none. Exactly one call blocks —
//! `Client.pumpOnce`, one read on the caller's `Transport` — and everything
//! under it is pure. A caller that wants a read timeout implements it inside
//! its own `Transport.read`; there is no timer thread here.
//!
//! **TLS is a seam, not an implementation** (CONVENTIONS.md §2). `STARTTLS` is
//! negotiated here; the caller performs the handshake and hands back an
//! upgraded `Transport`. The pre-TLS capability set is discarded and EHLO is
//! re-issued, because a capability list learned in the clear is attacker
//! controlled (RFC 3207 §4.2).
//!
//! Verified against a live third-party SMTP server (`aiosmtpd`) and
//! cross-checked by re-parsing our own output with Python's `email` module —
//! see SPEC.md.
//!
//! Provenance: clean-room from the RFCs listed above. No third-party source was
//! ported or studied; `aiosmtpd` and Python's `email` are black-box oracles.

const std = @import("std");

pub const reply = @import("reply.zig");
pub const capabilities = @import("capabilities.zig");
pub const command = @import("command.zig");
pub const data = @import("data.zig");
pub const auth = @import("auth.zig");
pub const mime = @import("mime.zig");
pub const message = @import("message.zig");
pub const session = @import("session.zig");
pub const client = @import("client.zig");
/// Byte-exact transcript captured from the live interop session, replayed as a
/// test. Not part of the API surface a consumer uses.
pub const live_golden = @import("live_golden.zig");

pub const meta = .{
    .targets = .{.linux64},
    .platform = .any,
    .role = .client,
    // One Session/Client owns one conversation's parser, capability set and
    // buffers; nothing shared or global. Concurrency (and any read timeout)
    // belongs to the caller's Transport implementation.
    .concurrency = .single_owner,
    .model_after = "RFC 5321 (SMTP) + RFC 1869/2920/3207/4954/1870/6152/6531 (ESMTP) + RFC 5322/2045/2046/2047 (message format); behaviour cross-checked against a live aiosmtpd server and Python's email parser",
    .deps = .{"netaddr"},
};

// ── top-level names (the ones a consumer actually types) ───────────────────

/// An SMTP conversation over any byte stream. See `client.zig`.
pub const Client = client.Client;
/// The byte-stream seam: one blocking `read`, one `write`.
pub const Transport = client.Transport;
pub const TransportError = client.TransportError;
pub const ClientError = client.ClientError;
pub const ClientOptions = client.Options;

/// The pure conversation state machine. See `session.zig`.
pub const Session = session.Session;
pub const Step = session.Step;
pub const State = session.State;
pub const Options = session.Options;
pub const SessionError = session.SessionError;
pub const Envelope = session.Envelope;
pub const RecipientStatus = session.RecipientStatus;
pub const TlsPolicy = session.TlsPolicy;
pub const Credentials = session.Credentials;

/// Replies (RFC 5321 §4.2 + RFC 3463).
pub const Reply = reply.Reply;
pub const ReplyParser = reply.Parser;
pub const ReplyError = reply.ReplyError;
pub const Enhanced = reply.Enhanced;
pub const Class = reply.Class;

/// ESMTP capabilities (RFC 5321 §4.1.1.1).
pub const Capabilities = capabilities.Capabilities;
pub const Mechanism = capabilities.Mechanism;
pub const AuthSet = capabilities.AuthSet;

/// DATA transparency (RFC 5321 §4.5.2).
pub const Stuffer = data.Stuffer;
pub const Unstuffer = data.Unstuffer;
pub const writeData = data.writeData;
pub const stuffAlloc = data.stuffAlloc;
pub const unstuffAlloc = data.unstuffAlloc;

/// Message composition (RFC 5322 + RFC 2045/2046/2047).
pub const Message = message.Message;
pub const Part = message.Part;
pub const Text = message.Text;
pub const Attachment = message.Attachment;
pub const Multipart = message.Multipart;
pub const Disposition = message.Disposition;
pub const Encoding = message.Encoding;
pub const Header = message.Header;
pub const RenderOptions = message.RenderOptions;
pub const RenderError = message.RenderError;
/// Render a `Message` into a freshly allocated RFC 5322 document.
pub const render = message.render;
/// An `Address` — used both in headers and (as `.addr`) in the envelope.
pub const Address = mime.Address;
pub const DateTime = mime.DateTime;
pub const formatDate = mime.formatDate;

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ───────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s tests
// into the test binary — every submodule must be named here too.
test {
    _ = reply;
    _ = capabilities;
    _ = command;
    _ = data;
    _ = auth;
    _ = mime;
    _ = message;
    _ = session;
    _ = client;
    _ = live_golden;
}

test "meta.deps names the module this one is built on" {
    try std.testing.expectEqualStrings("netaddr", meta.deps[0]);
}
