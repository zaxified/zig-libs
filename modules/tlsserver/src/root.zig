// SPDX-License-Identifier: MIT

//! tlsserver — a TLS 1.3 server (RFC 8446), buffer-driven (sans-I/O) with a
//! blocking wrapper on top, built on the collection's `tls13` handshake
//! building blocks and its `aesgcm` / `chachapoly` AEADs. Under construction
//! (plan: milestones M1–M4, `SPEC.md`); today it has the record layer:
//! the 5-byte header, per-direction in-place record protection for
//! TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 and
//! TLS_CHACHA20_POLY1305_SHA256, the receive side (records → handshake
//! messages, alerts, application data), alerts, the ClientHello decoder and
//! the encoders of the server's handshake messages.
//!
//! No TLS 1.2, no 0-RTT in v1 (`SPEC.md`, *What is deliberately not done*).

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "TLS 1.3 server (RFC 8446), sans-I/O core with a blocking wrapper — under construction: today the record layer (in-place record protection for the AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305 suites, the receive side joining handshake messages, alerts, the ClientHello decoder, the server's message encoders)",
    // Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any (pure computation; the planned blocking wrapper uses std.Io)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .server,
    // One record-protection state per direction per connection; nothing
    // shared or global.
    .concurrency = .single_owner,
    .model_after = "RFC 8446; rustls `ServerConnection` (buffer-driven core) for scope and API split",
    .deps = .{ "tls13", "aesgcm", "chachapoly", "netaddr" }, // tls13: key schedule; aesgcm/chachapoly: record AEADs (std AES-GCM is 2.6x slower on Zig 0.17, #36256); netaddr: an IP literal in SNI
};

/// The TLS 1.3 record layer: header, `Protection` (seal / open in place).
pub const record = @import("record.zig");

/// Alerts: the message, what a received one means, error → alert.
pub const alert = @import("alert.zig");

/// The receive side: records → handshake messages, alerts, application data.
pub const inbound = @import("inbound.zig");

/// The ClientHello, decoded into slices with every extension checked.
pub const hello = @import("hello.zig");

/// The handshake messages the server writes (ServerHello … Finished).
pub const messages = @import("messages.zig");

test {
    _ = record;
    _ = alert;
    _ = inbound;
    _ = hello;
    _ = messages;
    _ = @import("stackprobe_test.zig");
    _ = @import("fuzz_test.zig");
}

test "meta.deps is {tls13, aesgcm, chachapoly, netaddr}" {
    try std.testing.expectEqual(@as(usize, 4), meta.deps.len);
    try std.testing.expectEqualStrings("tls13", meta.deps[0]);
    try std.testing.expectEqualStrings("aesgcm", meta.deps[1]);
    try std.testing.expectEqualStrings("chachapoly", meta.deps[2]);
    try std.testing.expectEqualStrings("netaddr", meta.deps[3]);
}
