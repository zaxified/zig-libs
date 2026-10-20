// SPDX-License-Identifier: MIT

//! tls13 — the TLS 1.3 handshake building blocks shared by the collection's
//! TLS-family engines: today the RFC 8446 §7.1 key schedule, instantiated for
//! TLS 1.3 (`"tls13 "` labels) and DTLS 1.3 (`"dtls13"`, RFC 9147 §5.9).
//! Pure functions over caller bytes: no I/O, no allocation, no key storage.
//!
//! It is the shared core of `dtls` (which re-exports its `keyschedule` under
//! the old names) and of the planned `tlsserver`; more pieces move here as
//! that module needs them (SPEC.md, *Backlog / deferred*). Not an engine:
//! nothing here sends, parses or decides anything about a handshake.

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "TLS 1.3 handshake building blocks shared by the TLS-family engines: the RFC 8446 §7.1 key schedule for TLS 1.3 and DTLS 1.3 labels (resumption, exporter and KeyUpdate steps included)",
    // Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any (pure computation)",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "RFC 8446 §7 / RFC 9147 §5.9 (rustls `tls13::key_schedule` for the API split)",
    .deps = .{},
};

/// The RFC 8446 §7.1 key schedule: `keyschedule.tls13` and
/// `keyschedule.dtls13` (one `Schedule(prefix)` per protocol).
pub const keyschedule = @import("keyschedule.zig");

test {
    _ = keyschedule;
}
