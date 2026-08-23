// SPDX-License-Identifier: MIT

//! iec62351 — IEC 62351 power-systems communication security, over
//! caller-supplied PDU bytes.
//!
//! Four files, each securing a protocol that is defined somewhere else:
//!
//! - **`goose` — IEC 62351-6, layer-2 GOOSE/SV authentication.** Builds and
//!   verifies the security `Extension` appended to an IEC 61850-8-1 GOOSE or
//!   IEC 61850-9-2 Sampled Value frame: HMAC-SHA256 (80/128/256-bit tags) and
//!   AES-GMAC (64/128-bit) per the 2020 edition, plus the 2007 edition's
//!   RSASSA-PSS signature profile and ECDSA P-256, over an explicit, tested
//!   covered range.
//! - **`replay` — IEC 62351-6 clause 6.2, replay protection.** The
//!   `stNum`/`sqNum`/`t` state machine for GOOSE and the `smpCnt` window for
//!   Sampled Values, as pure time-injected components: no threads, no clock,
//!   no allocation.
//! - **`acse` — IEC 62351-4, MMS/application authentication.** Finds, builds
//!   and splices the ACSE `sender-acse-requirements` / `mechanism-name` /
//!   `calling-authentication-value` fields inside a caller-owned AARQ or
//!   AARE, including a signed, time-stamped token.
//! - **`tlsprofile` — IEC 62351-3, the TLS profile.** The standard's cipher
//!   suite, version, certificate and session rules as a **checkable policy
//!   object**: given a certificate and a description of a negotiated session,
//!   it returns the specific rules that were violated.
//!
//! ## The seam: this module never parses a protocol PDU
//!
//! Every entry point takes bytes the caller already has — an encoded GOOSE
//! APDU, an AARQ, a certificate — and authenticates or checks them. There is
//! **no dependency on `iec61850`**, by design: security is a wrapper over a
//! wire format, not a fork of it, and the wrapper is useful to anything that
//! can produce the bytes (a live stack, a capture, a test harness). README.md
//! shows how an `iec61850` caller wires the two together.
//!
//! ## Relationship to `dnp3`
//!
//! IEC 62351-**5** (DNP3 Secure Authentication, = IEEE 1815-2012 §7) is
//! already implemented inside `modules/dnp3` as `dnp3.sa`, where it belongs:
//! SA is not a wrapper over DNP3, it is object group 120 *inside* DNP3's own
//! application layer, with a challenge/reply flow bound to DNP3 ASDUs.
//! Nothing is moved or duplicated here. See `SPEC.md`.
//!
//! ## Honesty about the source material
//!
//! IEC 62351 is paywalled and publishes no test vectors. `SPEC.md` separates,
//! field by field, what is grounded in publicly available material from what
//! is this module's model, and every modelled decision is either a parameter
//! or has a documented `raw` escape hatch. Test vectors are labelled
//! `standard`-derived (RFC 4231, the AES-GCM test cases) or `self`-derived,
//! and the self-derived ones are anchored to the standard ones rather than to
//! themselves.

const std = @import("std");

pub const ber = @import("ber.zig");
pub const goose = @import("goose.zig");
pub const replay = @import("replay.zig");
pub const acse = @import("acse.zig");
pub const tlsprofile = @import("tlsprofile.zig");

// ── the most-used entry points, re-exported ─────────────────────────────────

/// IEC 62351-6: build an authenticated GOOSE/SV frame around a caller's APDU.
pub const buildAuthenticatedFrame = goose.build;
/// IEC 62351-6: parse and authenticate a GOOSE/SV frame.
pub const verifyFrame = goose.verify;
/// The per-publisher GMAC IV counter every `.aes_gmac_*` sealer needs
/// (NIST SP 800-38D §8.2.1). Re-exported because a caller who does not find it
/// invents a constant, which voids the authentication entirely.
pub const GmacIvCounter = goose.IvCounter;
/// IEC 62351-6 §6.2 replay guards.
pub const GooseReplayGuard = replay.GooseGuard;
pub const SvReplayGuard = replay.SvGuard;
/// IEC 62351-3 TLS conformance policy.
pub const TlsProfile = tlsprofile.Profile;

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "IEC 62351 power-systems security — GOOSE/SV authentication (62351-6) over caller-supplied PDU bytes, MMS application authentication (62351-4), checkable TLS policy",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util, // pure verification/policy logic over caller-supplied bytes; no I/O, no wire framing of its own
    .concurrency = .reentrant, // no globals; the replay guards are plain values owned by the caller
    .model_after = "IEC 62351-3/-4/-6 (paywalled — modelled from public descriptions, see SPEC.md); RFC 4231 + NIST SP 800-38D for the primitives",
    .deps = .{ "x509", "rsa" }, // certificate extensions for the -3 policy; RSASSA-PSS for the -6/-4 signature profiles
};

// ── dark-tests aggregator (CONVENTIONS.md §6 step 3) ────────────────────────
//
// A bare `pub const x = @import("x.zig")` re-export does NOT pull `x`'s tests
// into the test binary — every submodule must be named here too.
test {
    _ = ber;
    _ = goose;
    _ = replay;
    _ = acse;
    _ = tlsprofile;
    _ = @import("test_keys.zig");
    _ = @import("vectors_test.zig");
    _ = @import("goose_capture_test.zig");
}
