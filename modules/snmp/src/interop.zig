// SPDX-License-Identifier: MIT

//! Interop evidence for the SNMPv3 stack: **byte-exact goldens captured from a
//! real net-snmp exchange**, replayed offline, plus an optional live test
//! against a running agent.
//!
//! ## Where the goldens come from
//! A stock net-snmp 5.9.4 `snmpd` was run unprivileged on `127.0.0.1:11161`
//! with a pinned, synthetic engine ID and a set of USM users created from the
//! RFC 3414 example password:
//!
//! ```
//! engineID   rfc3414-example          # → 80 00 1F 88 04 "rfc3414-example"
//! createUser md5User    MD5     "maplesyrup"
//! createUser shaDesUser SHA     "maplesyrup" DES "maplesyrup"
//! createUser shaAesUser SHA     "maplesyrup" AES "maplesyrup"
//! createUser sha256User SHA-256 "maplesyrup" AES "maplesyrup"
//! createUser sha512User SHA-512 "maplesyrup" AES "maplesyrup"
//! sysName    zig-libs-snmp-test
//! ```
//!
//! and net-snmp's own `snmpget -d -v3 …` printed every datagram it sent and
//! received. Those hex dumps are the arrays below, verbatim. Nothing here comes
//! from a real device: the engine ID is a literal text label, the password is
//! the one printed in RFC 3414 Appendix A.3, and the only "secret" involved is
//! that same public example string.
//!
//! ## What the replays prove
//! For every captured datagram the tests below:
//!   1. decode the RFC 3412 envelope and the **nested** `msgSecurityParameters`
//!      (a BER SEQUENCE serialised inside an OCTET STRING) and check every
//!      field against what net-snmp put there;
//!   2. re-encode those parsed fields and require the result to be
//!      **byte-identical** to the captured blob — a wire-level golden for the
//!      nested encoding in both directions;
//!   3. derive the localized key from the password and **verify net-snmp's own
//!      HMAC** over the untouched datagram — an independent implementation's
//!      digest, over its own bytes, with our key. This pins password→Ku→Kul,
//!      the zero-fill rule, and the per-protocol truncation length all at once;
//!   4. zero the auth field, re-`sign` it with our code, and require the whole
//!      datagram to come back **bit-identical** to net-snmp's — i.e. we produce
//!      the exact bytes net-snmp does;
//!   5. for authPriv, decrypt the ScopedPDU and check the PDU inside.
//!
//! ## Live test
//! `snmpTestAgent()` reads `SNMP_TEST_AGENT=host:port`; without it (or without
//! a reachable agent) the live test prints `SKIPPED:` and passes, like the live
//! tests in `netconf` and `tc`.

const std = @import("std");
const builtin = @import("builtin");

// Skip diagnostics are opt-in: `zig build test` must be silent on
// success (any stderr triggers the build runner's `failed command:`
// line even when the step succeeded), while the skip *count* still
// shows up in the summary regardless. Set ZIG_LIBS_VERBOSE_SKIP to any
// non-empty value to see the reasons. (std.posix.getenv doesn't exist
// in 0.16 — std.testing.environ + Environ.getPosix is the repo's
// existing env-read pattern for tests, see netconf's `envVar`.)
const testkit = @import("testkit");
const verboseSkip = testkit.verboseSkip;

const ber = @import("ber.zig");
const oid_mod = @import("oid.zig");
const message = @import("message.zig");
const v3 = @import("v3.zig");
const usm = @import("usm.zig");
const priv = @import("priv.zig");
const report_mod = @import("report.zig");
const client_mod = @import("client.zig");
const v3client = @import("v3client.zig");

const Oid = oid_mod.Oid;
const testing = std.testing;

/// The `snmpd` engine ID the goldens were captured against:
/// `80 00 1F 88 04` (RFC 3411 enterprise 8072, text format) + "rfc3414-example".
pub const engine_id = usm.netsnmp_engine_id;

/// The RFC 3414 Appendix A.3 example password, used for every user.
pub const password = "maplesyrup";

/// `sysName.0` on the captured agent.
pub const sys_name = "zig-libs-snmp-test";

// ── captured datagrams ──────────────────────────────────────────────────────

/// noAuthNoPriv discovery probe: empty engineID/user, no varbinds (64 bytes).
pub const discovery_probe = [_]u8{
    0x30, 0x3e, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x7c, 0xfe, 0x80,
    0xa8, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x04, 0x02, 0x01, 0x03,
    0x04, 0x10, 0x30, 0x0e, 0x04, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00,
    0x04, 0x00, 0x04, 0x00, 0x04, 0x00, 0x30, 0x14, 0x04, 0x00, 0x04, 0x00,
    0xa0, 0x0e, 0x02, 0x04, 0x31, 0x8a, 0xd4, 0x51, 0x02, 0x01, 0x00, 0x02,
    0x01, 0x00, 0x30, 0x00,
};

/// the engine's Report: usmStatsUnknownEngineIDs.0 + its real engineID/boots/time (121 bytes).
pub const discovery_report = [_]u8{
    0x30, 0x77, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x7c, 0xfe, 0x80,
    0xa8, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x00, 0x02, 0x01, 0x03,
    0x04, 0x24, 0x30, 0x22, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04, 0x72,
    0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0f, 0x04, 0x00, 0x04, 0x00,
    0x04, 0x00, 0x30, 0x39, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04, 0x72,
    0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x04, 0x00, 0xa8, 0x1f, 0x02, 0x04, 0x31, 0x8a, 0xd4, 0x51,
    0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x0a,
    0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x04, 0x00, 0x41, 0x01,
    0x01,
};

/// authNoPriv HMAC-MD5-96 GetRequest sysName.0 (138 bytes).
pub const md5_authnopriv_request = [_]u8{
    0x30, 0x81, 0x87, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x7c, 0xfe,
    0x80, 0xa7, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x05, 0x02, 0x01,
    0x03, 0x04, 0x37, 0x30, 0x35, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04,
    0x72, 0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0f, 0x04, 0x07, 0x6d,
    0x64, 0x35, 0x55, 0x73, 0x65, 0x72, 0x04, 0x0c, 0xc5, 0x86, 0x6e, 0x7f,
    0x1a, 0x57, 0xbd, 0x1f, 0x08, 0x32, 0x60, 0x81, 0x04, 0x00, 0x30, 0x36,
    0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04, 0x72, 0x66, 0x63, 0x33, 0x34,
    0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x04, 0x00,
    0xa0, 0x1c, 0x02, 0x04, 0x31, 0x8a, 0xd4, 0x50, 0x02, 0x01, 0x00, 0x02,
    0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02,
    0x01, 0x01, 0x05, 0x00, 0x05, 0x00,
};

/// authNoPriv HMAC-MD5-96 Response sysName.0 (156 bytes).
pub const md5_authnopriv_response = [_]u8{
    0x30, 0x81, 0x99, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x7c, 0xfe,
    0x80, 0xa7, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x01, 0x02, 0x01,
    0x03, 0x04, 0x37, 0x30, 0x35, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04,
    0x72, 0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0f, 0x04, 0x07, 0x6d,
    0x64, 0x35, 0x55, 0x73, 0x65, 0x72, 0x04, 0x0c, 0x5c, 0x3c, 0xde, 0x3e,
    0x34, 0x91, 0xd4, 0x70, 0x5e, 0x70, 0xc7, 0xed, 0x04, 0x00, 0x30, 0x48,
    0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04, 0x72, 0x66, 0x63, 0x33, 0x34,
    0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x04, 0x00,
    0xa2, 0x2e, 0x02, 0x04, 0x31, 0x8a, 0xd4, 0x50, 0x02, 0x01, 0x00, 0x02,
    0x01, 0x00, 0x30, 0x20, 0x30, 0x1e, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02,
    0x01, 0x01, 0x05, 0x00, 0x04, 0x12, 0x7a, 0x69, 0x67, 0x2d, 0x6c, 0x69,
    0x62, 0x73, 0x2d, 0x73, 0x6e, 0x6d, 0x70, 0x2d, 0x74, 0x65, 0x73, 0x74,
};

/// authPriv HMAC-SHA-1-96 + DES-CBC GetRequest (151 bytes).
pub const sha1_des_authpriv_request = [_]u8{
    0x30, 0x81, 0x94, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x33, 0xf2,
    0x2c, 0xe2, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x07, 0x02, 0x01,
    0x03, 0x04, 0x42, 0x30, 0x40, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04,
    0x72, 0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0f, 0x04, 0x0a, 0x73,
    0x68, 0x61, 0x44, 0x65, 0x73, 0x55, 0x73, 0x65, 0x72, 0x04, 0x0c, 0x4e,
    0x5b, 0xf5, 0xe1, 0xd5, 0x46, 0xac, 0x4a, 0xd1, 0xb6, 0x55, 0x1a, 0x04,
    0x08, 0x00, 0x00, 0x00, 0x01, 0x9c, 0x45, 0x17, 0x2b, 0x04, 0x38, 0x53,
    0xb9, 0x79, 0xfd, 0xa9, 0x5e, 0xc0, 0x61, 0xba, 0x85, 0x26, 0x17, 0xef,
    0x31, 0x30, 0xbe, 0xdb, 0x2c, 0xc9, 0x27, 0x94, 0x89, 0xc5, 0x0f, 0x55,
    0xaa, 0xca, 0xf9, 0xb0, 0xec, 0x37, 0x58, 0x1a, 0x8d, 0x30, 0xd0, 0x88,
    0x09, 0x9a, 0xc3, 0xa1, 0x64, 0xaa, 0x2f, 0xff, 0x33, 0x86, 0xfd, 0xed,
    0x57, 0x2d, 0x00, 0xde, 0x3b, 0x58, 0x21,
};

/// authPriv HMAC-SHA-1-96 + DES-CBC Response (175 bytes).
pub const sha1_des_authpriv_response = [_]u8{
    0x30, 0x81, 0xac, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x33, 0xf2,
    0x2c, 0xe2, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x03, 0x02, 0x01,
    0x03, 0x04, 0x42, 0x30, 0x40, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04,
    0x72, 0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0f, 0x04, 0x0a, 0x73,
    0x68, 0x61, 0x44, 0x65, 0x73, 0x55, 0x73, 0x65, 0x72, 0x04, 0x0c, 0x3a,
    0x24, 0xd4, 0x8d, 0x64, 0xaf, 0x05, 0x39, 0x3a, 0x1e, 0xb9, 0x2d, 0x04,
    0x08, 0x00, 0x00, 0x00, 0x01, 0x95, 0x51, 0x04, 0xbc, 0x04, 0x50, 0xe4,
    0xb2, 0x50, 0x16, 0x38, 0x47, 0x81, 0xbb, 0xb6, 0x07, 0x07, 0x46, 0xd5,
    0x87, 0x0d, 0xfe, 0x22, 0xcc, 0xf4, 0x39, 0xe7, 0x6f, 0x1e, 0x02, 0xd2,
    0x7f, 0x3c, 0x6c, 0x88, 0x35, 0xb4, 0xcc, 0xba, 0x70, 0xb5, 0xc0, 0xef,
    0x24, 0x40, 0x5c, 0x8b, 0x49, 0xcc, 0x71, 0x65, 0xc3, 0xf7, 0xb5, 0x4f,
    0xfe, 0x63, 0xfc, 0x6e, 0xa2, 0xa9, 0x8a, 0xd7, 0x8a, 0x22, 0x95, 0x33,
    0x49, 0x2f, 0x02, 0x5b, 0x13, 0x8e, 0xa6, 0x10, 0xd9, 0x35, 0xb5, 0x12,
    0x50, 0x2c, 0xad, 0x4c, 0xdc, 0xfe, 0xbf,
};

/// authPriv HMAC-SHA-1-96 + AES-128-CFB GetRequest (151 bytes).
pub const sha1_aes_authpriv_request = [_]u8{
    0x30, 0x81, 0x94, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x6f, 0x2a,
    0x1a, 0x2d, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x07, 0x02, 0x01,
    0x03, 0x04, 0x42, 0x30, 0x40, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04,
    0x72, 0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0f, 0x04, 0x0a, 0x73,
    0x68, 0x61, 0x41, 0x65, 0x73, 0x55, 0x73, 0x65, 0x72, 0x04, 0x0c, 0x14,
    0x4c, 0xfa, 0xb6, 0xb8, 0xb0, 0xc9, 0x8b, 0x1a, 0x7f, 0x17, 0x09, 0x04,
    0x08, 0xa2, 0x67, 0x69, 0x7f, 0x82, 0xb4, 0x48, 0xe1, 0x04, 0x38, 0xe3,
    0xc8, 0x27, 0xdb, 0xc1, 0xf9, 0xdc, 0x66, 0xc1, 0xcd, 0xd7, 0xf6, 0xe0,
    0x21, 0x7d, 0xe8, 0xca, 0xe0, 0xf5, 0xb3, 0xae, 0x5e, 0xa2, 0xd9, 0x9c,
    0x30, 0x0d, 0x07, 0xd2, 0x61, 0xa1, 0x22, 0xa2, 0xd8, 0x15, 0xaf, 0xe4,
    0x28, 0x24, 0x32, 0xe9, 0x85, 0x03, 0x19, 0x36, 0x76, 0xb0, 0x2e, 0x9b,
    0x84, 0xb0, 0x15, 0x8c, 0xf4, 0x4c, 0xa4,
};

/// authPriv HMAC-SHA-1-96 + AES-128-CFB Response (169 bytes).
pub const sha1_aes_authpriv_response = [_]u8{
    0x30, 0x81, 0xa6, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x6f, 0x2a,
    0x1a, 0x2d, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x03, 0x02, 0x01,
    0x03, 0x04, 0x42, 0x30, 0x40, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04,
    0x72, 0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0f, 0x04, 0x0a, 0x73,
    0x68, 0x61, 0x41, 0x65, 0x73, 0x55, 0x73, 0x65, 0x72, 0x04, 0x0c, 0x18,
    0x2d, 0x5a, 0x17, 0xb9, 0x8d, 0xd8, 0x69, 0x94, 0x1f, 0x28, 0x42, 0x04,
    0x08, 0x26, 0x04, 0x81, 0x96, 0xf1, 0xbf, 0x6b, 0x6f, 0x04, 0x4a, 0xef,
    0xe3, 0x4f, 0x43, 0x5b, 0x7e, 0xb1, 0x7c, 0x00, 0x2c, 0x4c, 0xb3, 0x45,
    0x9e, 0xea, 0x33, 0xfd, 0xb2, 0xf8, 0x8c, 0xf7, 0x63, 0x01, 0x36, 0x84,
    0x3a, 0xe3, 0x8c, 0x4c, 0xe6, 0x60, 0xfd, 0xf3, 0xcd, 0x03, 0x1c, 0x3f,
    0x1a, 0xf5, 0x03, 0x76, 0x87, 0x5f, 0xff, 0xcd, 0x8b, 0x86, 0x88, 0x2f,
    0xe0, 0xe2, 0xa1, 0x39, 0x39, 0x7d, 0x5b, 0xf7, 0x80, 0x23, 0x39, 0x0d,
    0xed, 0xc3, 0xb1, 0x73, 0xdf, 0xd5, 0xcf, 0xf2, 0x02, 0x25, 0xe5, 0x8f,
    0xce,
};

/// authPriv RFC 7860 HMAC-192-SHA-256 + AES-128-CFB GetRequest (24-byte digest) (163 bytes).
pub const sha256_aes_authpriv_request = [_]u8{
    0x30, 0x81, 0xa0, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x61, 0x06,
    0x67, 0x18, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x07, 0x02, 0x01,
    0x03, 0x04, 0x4e, 0x30, 0x4c, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04,
    0x72, 0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0f, 0x04, 0x0a, 0x73,
    0x68, 0x61, 0x32, 0x35, 0x36, 0x55, 0x73, 0x65, 0x72, 0x04, 0x18, 0x6a,
    0xda, 0x57, 0x8c, 0x45, 0x3a, 0xd2, 0x09, 0xe2, 0xcf, 0x4e, 0x50, 0x89,
    0x67, 0xf7, 0x7f, 0x00, 0xf6, 0x87, 0xc2, 0xb6, 0x04, 0x06, 0xe6, 0x04,
    0x08, 0xba, 0x3c, 0x16, 0x23, 0xd6, 0xa4, 0x8e, 0x06, 0x04, 0x38, 0xbb,
    0xf3, 0x1a, 0x13, 0xb1, 0x41, 0xf2, 0x03, 0xa8, 0x12, 0xce, 0xfa, 0xaa,
    0x90, 0x36, 0x46, 0xdb, 0x1f, 0x8e, 0x18, 0xf4, 0xcc, 0x9d, 0x62, 0x76,
    0xa2, 0x51, 0x77, 0x9a, 0x82, 0x29, 0x20, 0x90, 0x84, 0xfb, 0xee, 0xc2,
    0x20, 0xa0, 0xa7, 0xd0, 0x47, 0x80, 0x03, 0x70, 0x03, 0xd6, 0x2e, 0xe1,
    0xf2, 0xa8, 0x46, 0x74, 0xf0, 0xa6, 0x50,
};

/// authPriv RFC 7860 HMAC-192-SHA-256 + AES-128-CFB Response (181 bytes).
pub const sha256_aes_authpriv_response = [_]u8{
    0x30, 0x81, 0xb2, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x61, 0x06,
    0x67, 0x18, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x03, 0x02, 0x01,
    0x03, 0x04, 0x4e, 0x30, 0x4c, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04,
    0x72, 0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0f, 0x04, 0x0a, 0x73,
    0x68, 0x61, 0x32, 0x35, 0x36, 0x55, 0x73, 0x65, 0x72, 0x04, 0x18, 0xab,
    0x05, 0xe0, 0xe8, 0x19, 0x25, 0xfe, 0x79, 0x2b, 0x14, 0x7d, 0x12, 0xb2,
    0x5f, 0x4b, 0x8b, 0x30, 0xb6, 0xef, 0x6b, 0xde, 0x82, 0x90, 0x34, 0x04,
    0x08, 0x26, 0x04, 0x81, 0x96, 0xf1, 0xbf, 0x6b, 0x70, 0x04, 0x4a, 0x66,
    0x3b, 0xdb, 0xe2, 0x1d, 0xab, 0xbb, 0x36, 0x1d, 0xd7, 0x24, 0x8d, 0xaa,
    0x95, 0x83, 0x78, 0xa4, 0x7b, 0xbd, 0x3f, 0xcb, 0xb5, 0x26, 0x3a, 0x0a,
    0xe6, 0x00, 0xa3, 0x79, 0xa6, 0x49, 0xc3, 0x05, 0x91, 0x6d, 0xf4, 0x8c,
    0x02, 0x98, 0x9b, 0xcd, 0x86, 0xd7, 0x36, 0x4b, 0x7d, 0x93, 0xe7, 0xd0,
    0x2e, 0xe0, 0xf2, 0x70, 0xc7, 0x00, 0xad, 0xc5, 0x15, 0x3e, 0xb5, 0x17,
    0xf6, 0x0d, 0xf1, 0x07, 0xc5, 0x5e, 0x07, 0xaa, 0xdc, 0x98, 0xf0, 0xf3,
    0xa2,
};

/// authPriv RFC 7860 HMAC-384-SHA-512 + AES-128-CFB GetRequest (48-byte digest) (187 bytes).
pub const sha512_aes_authpriv_request = [_]u8{
    0x30, 0x81, 0xb8, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x08, 0x33,
    0x5c, 0x40, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x07, 0x02, 0x01,
    0x03, 0x04, 0x66, 0x30, 0x64, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04,
    0x72, 0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0f, 0x04, 0x0a, 0x73,
    0x68, 0x61, 0x35, 0x31, 0x32, 0x55, 0x73, 0x65, 0x72, 0x04, 0x30, 0x83,
    0x94, 0x77, 0x8e, 0xba, 0x59, 0xa6, 0x59, 0x95, 0x4d, 0x42, 0x69, 0x3b,
    0x27, 0xa4, 0xed, 0xf7, 0x0f, 0x91, 0xbf, 0xc5, 0x34, 0xf1, 0x1b, 0xf6,
    0x1c, 0x81, 0xca, 0xd7, 0x4b, 0x0f, 0xe1, 0xb0, 0xaf, 0xc2, 0xbd, 0x75,
    0x7d, 0xd4, 0x2c, 0x60, 0xe3, 0xa0, 0x0b, 0xa4, 0x32, 0x97, 0xe0, 0x04,
    0x08, 0x59, 0x67, 0x51, 0x07, 0x1b, 0x96, 0xcd, 0xe7, 0x04, 0x38, 0x77,
    0xca, 0xcb, 0xc4, 0xf1, 0x5b, 0x5d, 0xa0, 0xa5, 0x67, 0x1e, 0x56, 0x1c,
    0xd8, 0x6f, 0x88, 0xa5, 0xff, 0xb9, 0xd4, 0x95, 0x1f, 0x8e, 0x96, 0xae,
    0x77, 0xe4, 0x83, 0x68, 0xea, 0xcc, 0xc4, 0x21, 0x3a, 0x96, 0x4e, 0x2f,
    0x77, 0x59, 0xe6, 0x9c, 0xd8, 0xaf, 0xd1, 0x55, 0xf6, 0xe4, 0x12, 0xe0,
    0x62, 0xfa, 0xf7, 0xd9, 0x8e, 0x67, 0xdf,
};

/// authPriv RFC 7860 HMAC-384-SHA-512 + AES-128-CFB Response (205 bytes).
pub const sha512_aes_authpriv_response = [_]u8{
    0x30, 0x81, 0xca, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x08, 0x33,
    0x5c, 0x40, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x03, 0x02, 0x01,
    0x03, 0x04, 0x66, 0x30, 0x64, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04,
    0x72, 0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x0f, 0x04, 0x0a, 0x73,
    0x68, 0x61, 0x35, 0x31, 0x32, 0x55, 0x73, 0x65, 0x72, 0x04, 0x30, 0x2b,
    0x44, 0x36, 0x80, 0xda, 0x3e, 0x28, 0xe2, 0x1c, 0xb6, 0xe3, 0x2e, 0xaf,
    0x91, 0xe1, 0x80, 0x97, 0xf7, 0xe7, 0x14, 0x38, 0x11, 0x6c, 0xcd, 0x26,
    0xe7, 0xf6, 0xb0, 0x9d, 0x87, 0xf9, 0x2c, 0x44, 0xda, 0xb9, 0x73, 0x7f,
    0x51, 0x6a, 0x8d, 0x10, 0x4f, 0xd7, 0x5d, 0xce, 0x30, 0x91, 0x05, 0x04,
    0x08, 0x26, 0x04, 0x81, 0x96, 0xf1, 0xbf, 0x6b, 0x71, 0x04, 0x4a, 0x3b,
    0x7a, 0x05, 0xc3, 0x64, 0x03, 0x6b, 0xd7, 0x60, 0x65, 0x0f, 0x1e, 0x81,
    0x11, 0xf4, 0x49, 0x5e, 0x6a, 0x9f, 0xfe, 0x90, 0x97, 0xf4, 0xcc, 0x45,
    0xd1, 0x91, 0x77, 0x44, 0x55, 0x41, 0xe4, 0x3c, 0x3d, 0x34, 0x36, 0xeb,
    0x1d, 0xdb, 0xcb, 0x38, 0xdb, 0x64, 0x64, 0x3e, 0x2c, 0x58, 0x75, 0x06,
    0x58, 0xb3, 0x87, 0x77, 0x9e, 0xaa, 0xb4, 0xb1, 0x2b, 0x5d, 0x03, 0xbc,
    0x03, 0x88, 0x8d, 0x27, 0x32, 0xc3, 0x82, 0x58, 0xdc, 0x6a, 0x70, 0x8e,
    0xd9,
};

/// usmStatsWrongDigests.0 (wrong auth password) (128 bytes).
pub const report_wrong_digest = [_]u8{
    0x30, 0x7e, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x73, 0x0b, 0xe7,
    0x9c, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x00, 0x02, 0x01, 0x03,
    0x04, 0x2b, 0x30, 0x29, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04, 0x72,
    0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x39, 0x04, 0x07, 0x6d, 0x64,
    0x35, 0x55, 0x73, 0x65, 0x72, 0x04, 0x00, 0x04, 0x00, 0x30, 0x39, 0x04,
    0x14, 0x80, 0x00, 0x1f, 0x88, 0x04, 0x72, 0x66, 0x63, 0x33, 0x34, 0x31,
    0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x04, 0x00, 0xa8,
    0x1f, 0x02, 0x04, 0x41, 0xda, 0x2d, 0x26, 0x02, 0x01, 0x00, 0x02, 0x01,
    0x00, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03,
    0x0f, 0x01, 0x01, 0x05, 0x00, 0x41, 0x01, 0x01,
};

/// usmStatsUnknownUserNames.0 (132 bytes).
pub const report_unknown_user = [_]u8{
    0x30, 0x81, 0x81, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x07, 0xa7,
    0x36, 0x6a, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x00, 0x02, 0x01,
    0x03, 0x04, 0x2e, 0x30, 0x2c, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04,
    0x72, 0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d,
    0x70, 0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x39, 0x04, 0x0a, 0x6e,
    0x6f, 0x73, 0x75, 0x63, 0x68, 0x55, 0x73, 0x65, 0x72, 0x04, 0x00, 0x04,
    0x00, 0x30, 0x39, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04, 0x72, 0x66,
    0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c,
    0x65, 0x04, 0x00, 0xa8, 0x1f, 0x02, 0x04, 0x69, 0xca, 0x7e, 0xee, 0x02,
    0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x0a, 0x2b,
    0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01, 0x03, 0x00, 0x41, 0x01, 0x01,
};

/// usmStatsUnsupportedSecLevels.0 (authPriv asked of an auth-only user) (125 bytes).
pub const report_unsupported_sec_level = [_]u8{
    0x30, 0x7b, 0x02, 0x01, 0x03, 0x30, 0x11, 0x02, 0x04, 0x65, 0xc2, 0x96,
    0xf9, 0x02, 0x03, 0x00, 0xff, 0xe3, 0x04, 0x01, 0x00, 0x02, 0x01, 0x03,
    0x04, 0x2b, 0x30, 0x29, 0x04, 0x14, 0x80, 0x00, 0x1f, 0x88, 0x04, 0x72,
    0x66, 0x63, 0x33, 0x34, 0x31, 0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70,
    0x6c, 0x65, 0x02, 0x01, 0x01, 0x02, 0x01, 0x39, 0x04, 0x07, 0x6d, 0x64,
    0x35, 0x55, 0x73, 0x65, 0x72, 0x04, 0x00, 0x04, 0x00, 0x30, 0x36, 0x04,
    0x14, 0x80, 0x00, 0x1f, 0x88, 0x04, 0x72, 0x66, 0x63, 0x33, 0x34, 0x31,
    0x34, 0x2d, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x04, 0x00, 0xa8,
    0x1c, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x11,
    0x30, 0x0f, 0x06, 0x0a, 0x2b, 0x06, 0x01, 0x06, 0x03, 0x0f, 0x01, 0x01,
    0x01, 0x00, 0x41, 0x01, 0x01,
};

// ── replay tests ────────────────────────────────────────────────────────────

test "golden: the discovery probe is exactly what RFC 3414 §4 prescribes" {
    const m = try v3.decode(&discovery_probe);
    try testing.expectEqual(v3.security_model_usm, m.header.security_model);
    // Reportable only — no auth, no priv (nothing is known yet).
    try testing.expect(!m.header.flags.auth);
    try testing.expect(!m.header.flags.priv);
    try testing.expect(m.header.flags.reportable);

    const sp = try usm.parse(m.security_parameters);
    try testing.expectEqual(@as(usize, 0), sp.engine_id.len);
    try testing.expectEqual(@as(u32, 0), sp.engine_boots);
    try testing.expectEqual(@as(u32, 0), sp.engine_time);
    try testing.expectEqual(@as(usize, 0), sp.user_name.len);
    try testing.expectEqual(@as(usize, 0), sp.auth_params.len);
    try testing.expectEqual(@as(usize, 0), sp.priv_params.len);

    const scoped = m.data.plaintext;
    try testing.expectEqual(@as(usize, 0), scoped.context_engine_id.len);
    try testing.expectEqual(@as(usize, 0), scoped.context_name.len);
    // A GetRequest with an EMPTY varbind list.
    try testing.expectEqual(@as(usize, 0), try scoped.pdu.get_request.varbinds.count());
}

test "golden: the discovery Report yields engineID/boots/time and usmStatsUnknownEngineIDs" {
    const m = try v3.decode(&discovery_report);
    try testing.expect(!m.header.flags.auth and !m.header.flags.priv);
    const sp = try usm.parse(m.security_parameters);
    try testing.expectEqualSlices(u8, &engine_id, sp.engine_id);
    try testing.expectEqual(@as(u32, 1), sp.engine_boots);
    try testing.expectEqual(@as(u32, 15), sp.engine_time);

    const info = try report_mod.classify(m.data.plaintext);
    try testing.expectEqual(report_mod.Reason.unknown_engine_ids, info.reason);
    try testing.expect(info.reason.isRecoverable());
    try testing.expectEqual(report_mod.ReportError.UnknownEngineId, report_mod.toError(info.reason));
    // The msgID of probe and report match — the client's reply matching works.
    const probe = try v3.decode(&discovery_probe);
    try testing.expectEqual(probe.header.msg_id, m.header.msg_id);
}

test "golden: msgSecurityParameters re-encodes byte-identically (nested encoding)" {
    // Every captured datagram: parse the nested USM SEQUENCE out of the opaque
    // OCTET STRING, re-encode it from the parsed fields, and require the bytes
    // to be identical. This pins the nested layering in both directions.
    const all = [_][]const u8{
        &discovery_probe,              &discovery_report,
        &md5_authnopriv_request,       &md5_authnopriv_response,
        &sha1_des_authpriv_request,    &sha1_des_authpriv_response,
        &sha1_aes_authpriv_request,    &sha1_aes_authpriv_response,
        &sha256_aes_authpriv_request,  &sha256_aes_authpriv_response,
        &sha512_aes_authpriv_request,  &sha512_aes_authpriv_response,
        &report_wrong_digest,          &report_unknown_user,
        &report_unsupported_sec_level,
    };
    for (all) |dg| {
        const m = try v3.decode(dg);
        const sp = try usm.parse(m.security_parameters);
        var buf: [256]u8 = undefined;
        const again = try usm.encode(&buf, sp);
        try testing.expectEqualSlices(u8, m.security_parameters, again);
    }
}

/// Verify net-snmp's own digest over a captured datagram with a key we derive
/// from the password, then prove we reproduce those exact bytes: zero the auth
/// field, re-sign with our code, and compare the WHOLE datagram.
fn expectDigestInterop(proto: usm.AuthProtocol, golden: []const u8, want_user: []const u8) !void {
    var key_buf: [usm.max_key_len]u8 = undefined;
    const key = try usm.passwordToKey(proto, password, &engine_id, &key_buf);

    // Work on a mutable copy so auth_params points into the buffer we verify.
    var buf: [512]u8 = undefined;
    @memcpy(buf[0..golden.len], golden);
    const dg = buf[0..golden.len];

    const m = try v3.decode(dg);
    try testing.expect(m.header.flags.auth);
    const sp = try usm.parse(m.security_parameters);
    try testing.expectEqualStrings(want_user, sp.user_name);
    try testing.expectEqualSlices(u8, &engine_id, sp.engine_id);
    // The truncation length net-snmp used must be the one RFC 7860 specifies.
    try testing.expectEqual(proto.digestLen(), sp.auth_params.len);

    // (1) net-snmp's digest verifies under our key, over its own bytes.
    try usm.verify(proto, key, dg, sp);

    // (2) we regenerate it bit-for-bit.
    const off = usm.authOffsetFor(proto, dg, sp).?;
    @memset(dg[off..][0..proto.digestLen()], 0);
    usm.sign(proto, key, dg, off);
    try testing.expectEqualSlices(u8, golden, dg);

    // (3) a single flipped bit anywhere outside the digest breaks it.
    dg[dg.len - 1] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, usm.verify(proto, key, dg, sp));
}

test "golden interop: HMAC-MD5-96 digest (RFC 3414 §6) matches net-snmp exactly" {
    try expectDigestInterop(.hmac_md5, &md5_authnopriv_request, "md5User");
    try expectDigestInterop(.hmac_md5, &md5_authnopriv_response, "md5User");
}

test "golden interop: HMAC-SHA-1-96 digest (RFC 3414 §7) matches net-snmp exactly" {
    try expectDigestInterop(.hmac_sha1, &sha1_des_authpriv_request, "shaDesUser");
    try expectDigestInterop(.hmac_sha1, &sha1_des_authpriv_response, "shaDesUser");
    try expectDigestInterop(.hmac_sha1, &sha1_aes_authpriv_request, "shaAesUser");
    try expectDigestInterop(.hmac_sha1, &sha1_aes_authpriv_response, "shaAesUser");
}

test "golden interop: RFC 7860 SHA-256 (24-byte) digest matches net-snmp exactly" {
    try expectDigestInterop(.hmac_sha256, &sha256_aes_authpriv_request, "sha256User");
    try expectDigestInterop(.hmac_sha256, &sha256_aes_authpriv_response, "sha256User");
}

test "golden interop: RFC 7860 SHA-512 (48-byte) digest matches net-snmp exactly" {
    try expectDigestInterop(.hmac_sha512, &sha512_aes_authpriv_request, "sha512User");
    try expectDigestInterop(.hmac_sha512, &sha512_aes_authpriv_response, "sha512User");
}

test "golden interop: using the WRONG auth protocol on a real datagram fails cleanly" {
    // The SHA-256 request has a 24-byte auth field; MD5/SHA-1 want 12, and
    // SHA-512 wants 48 — all must be BadAuthParams, never a silent compare.
    var key_buf: [usm.max_key_len]u8 = undefined;
    const m = try v3.decode(&sha256_aes_authpriv_request);
    const sp = try usm.parse(m.security_parameters);
    for ([_]usm.AuthProtocol{ .hmac_md5, .hmac_sha1, .hmac_sha224, .hmac_sha384, .hmac_sha512 }) |p| {
        const key = try usm.passwordToKey(p, password, &engine_id, &key_buf);
        try testing.expectError(
            error.BadAuthParams,
            usm.verify(p, key, &sha256_aes_authpriv_request, sp),
        );
    }
    // Right length (SHA-1 vs MD5 both truncate to 12) but wrong hash → the
    // digest simply does not match. Use the MD5 golden with a SHA-1 key.
    const m2 = try v3.decode(&md5_authnopriv_request);
    const sp2 = try usm.parse(m2.security_parameters);
    const sha1_key = try usm.passwordToKey(.hmac_sha1, password, &engine_id, &key_buf);
    try testing.expectError(
        error.AuthenticationFailed,
        usm.verify(.hmac_sha1, sha1_key, &md5_authnopriv_request, sp2),
    );
}

/// Decrypt a captured authPriv datagram and hand back its ScopedPDU.
fn decryptGolden(
    auth: usm.AuthProtocol,
    p: priv.PrivProtocol,
    golden: []const u8,
    out: []u8,
) !v3.ScopedPdu {
    var key_buf: [usm.max_key_len]u8 = undefined;
    // RFC 3414 §2.6: the privacy password is localized with the AUTH hash.
    const pkey = try usm.passwordToKey(auth, password, &engine_id, &key_buf);
    const m = try v3.decode(golden);
    try testing.expect(m.header.flags.priv);
    const sp = try usm.parse(m.security_parameters);
    try testing.expectEqual(@as(usize, 8), sp.priv_params.len);
    return priv.decryptScopedPdu(
        p,
        pkey,
        sp.engine_boots,
        sp.engine_time,
        sp.priv_params,
        m.data.encrypted,
        out,
    );
}

test "golden interop: decrypting net-snmp's authPriv ScopedPDUs (DES + AES, SHA-1/256/512)" {
    const sys_name_oid = try Oid.parse("1.3.6.1.2.1.1.5.0");
    const cases = [_]struct { usm.AuthProtocol, priv.PrivProtocol, []const u8, []const u8 }{
        .{ .hmac_sha1, .des_cbc, &sha1_des_authpriv_request, &sha1_des_authpriv_response },
        .{ .hmac_sha1, .aes128_cfb, &sha1_aes_authpriv_request, &sha1_aes_authpriv_response },
        .{ .hmac_sha256, .aes128_cfb, &sha256_aes_authpriv_request, &sha256_aes_authpriv_response },
        .{ .hmac_sha512, .aes128_cfb, &sha512_aes_authpriv_request, &sha512_aes_authpriv_response },
    };
    for (cases) |c| {
        var out: [512]u8 = undefined;

        // The request: GetRequest sysName.0 with a NULL value.
        const req = try decryptGolden(c[0], c[1], c[2], &out);
        try testing.expectEqualSlices(u8, &engine_id, req.context_engine_id);
        try testing.expectEqualStrings("", req.context_name);
        var rit = req.pdu.get_request.varbinds.iterator();
        const asked = (try rit.next()).?;
        try testing.expect(asked.name.eql(&sys_name_oid));
        try testing.expect(asked.value == .null);

        // The response: sysName.0 = the agent's configured name.
        var out2: [512]u8 = undefined;
        const rsp = try decryptGolden(c[0], c[1], c[3], &out2);
        var it = rsp.pdu.response.varbinds.iterator();
        const vb = (try it.next()).?;
        try testing.expect(vb.name.eql(&sys_name_oid));
        try testing.expectEqualStrings(sys_name, vb.value.octet_string);
        try testing.expectEqual(message.ErrorStatus.no_error, rsp.pdu.response.error_status);
    }
}

test "golden interop: the plaintext authNoPriv response carries sysName.0" {
    const m = try v3.decode(&md5_authnopriv_response);
    try testing.expect(m.header.flags.auth and !m.header.flags.priv);
    const scoped = m.data.plaintext;
    var it = scoped.pdu.response.varbinds.iterator();
    const vb = (try it.next()).?;
    const want = try Oid.parse("1.3.6.1.2.1.1.5.0");
    try testing.expect(vb.name.eql(&want));
    try testing.expectEqualStrings(sys_name, vb.value.octet_string);
}

test "golden interop: every captured error Report classifies to the right typed error" {
    const cases = [_]struct { []const u8, report_mod.Reason, anyerror }{
        .{ &report_wrong_digest, .wrong_digests, error.WrongDigest },
        .{ &report_unknown_user, .unknown_user_names, error.UnknownUserName },
        .{ &report_unsupported_sec_level, .unsupported_sec_levels, error.UnsupportedSecLevel },
    };
    for (cases) |c| {
        const m = try v3.decode(c[0]);
        const info = try report_mod.classify(m.data.plaintext);
        try testing.expectEqual(c[1], info.reason);
        try testing.expectEqual(c[2], report_mod.toError(info.reason));
        try testing.expect(!info.reason.isRecoverable()); // all terminal
    }
}

test "golden interop: a truncated or corrupted capture is a typed error, never a panic" {
    // Each capture is paired with the protocol that actually signed it, so the
    // corruption sweep below can verify under the REAL key. Verifying under an
    // all-zero key would pass even against an accept-anything `verify`.
    const all = [_]struct { dg: []const u8, auth: ?usm.AuthProtocol }{
        .{ .dg = &discovery_report, .auth = null }, // noAuthNoPriv: nothing to verify
        .{ .dg = &md5_authnopriv_response, .auth = .hmac_md5 },
        .{ .dg = &sha1_aes_authpriv_response, .auth = .hmac_sha1 },
        .{ .dg = &sha512_aes_authpriv_response, .auth = .hmac_sha512 },
    };
    for (all) |case| {
        const dg = case.dg;
        // Every truncation.
        for (0..dg.len) |n| {
            if (v3.decode(dg[0..n])) |m| {
                _ = usm.parse(m.security_parameters) catch {};
                switch (m.data) {
                    .plaintext => |s| {
                        var it = switch (s.pdu) {
                            inline else => |p| p.varbinds.iterator(),
                        };
                        while (it.next() catch null) |_| {}
                    },
                    .encrypted => {},
                }
            } else |_| {}
        }
        // Every single-byte 0xff flip.
        var mut: [512]u8 = undefined;
        for (0..dg.len) |i| {
            @memcpy(mut[0..dg.len], dg);
            mut[i] ^= 0xff;
            if (v3.decode(mut[0..dg.len])) |m| {
                if (usm.parse(m.security_parameters)) |sp| {
                    if (case.auth) |proto| {
                        var key_buf: [usm.max_key_len]u8 = undefined;
                        const key = try usm.passwordToKey(proto, password, &engine_id, &key_buf);
                        // Negative control: the whole message is authenticated,
                        // so NO single-byte corruption may ever authenticate.
                        // Rejection may be AuthenticationFailed or a typed parse
                        // error — either way it must not be accepted.
                        try testing.expect(std.meta.isError(
                            usm.verify(proto, key, mut[0..dg.len], sp),
                        ));
                    }
                } else |_| {}
            } else |_| {}
        }
    }
}

test "golden interop: security parameters with hostile lengths stay typed" {
    // A msgSecurityParameters OCTET STRING that is not a valid USM SEQUENCE.
    const hostile = [_][]const u8{
        &.{}, // empty
        &.{0x30}, // tag, no length
        &.{ 0x30, 0x82, 0xff, 0xff }, // length far beyond the buffer
        &.{ 0x30, 0x02, 0x04, 0x00 }, // SEQUENCE with only one field
    };
    for (hostile) |h| {
        var buf: [256]u8 = undefined;
        const dg = try v3.encode(&buf, .{
            .msg_id = 1,
            .flags = .{ .auth = true },
            .security_parameters = h,
            .context_engine_id = &engine_id,
            .pdu = .{ .type = .response, .request_id = 1 },
        });
        const m = try v3.decode(dg);
        try testing.expect(std.meta.isError(usm.parse(m.security_parameters)));
    }
}

test "golden interop: an auth field of the wrong length inside a real envelope" {
    // Rebuild the MD5 request with an 11-byte auth field: BadAuthParams, and
    // crucially NOT a digest comparison against a short buffer.
    var sp_buf: [128]u8 = undefined;
    const sp_wire = try usm.encode(&sp_buf, .{
        .engine_id = &engine_id,
        .engine_boots = 1,
        .engine_time = 15,
        .user_name = "md5User",
        .auth_params = &[_]u8{0} ** 11,
        .priv_params = &.{},
    });
    var buf: [512]u8 = undefined;
    const dg = try v3.encode(&buf, .{
        .msg_id = 1,
        .flags = .{ .auth = true },
        .security_parameters = sp_wire,
        .context_engine_id = &engine_id,
        .pdu = .{ .type = .response, .request_id = 1 },
    });
    const m = try v3.decode(dg);
    const sp = try usm.parse(m.security_parameters);
    var key_buf: [usm.max_key_len]u8 = undefined;
    const key = try usm.passwordToKey(.hmac_md5, password, &engine_id, &key_buf);
    try testing.expectError(error.BadAuthParams, usm.verify(.hmac_md5, key, dg, sp));
}

test "golden interop: a ScopedPDU that fails to decrypt is a typed error" {
    var key_buf: [usm.max_key_len]u8 = undefined;
    const key = try usm.passwordToKey(.hmac_sha1, password, &engine_id, &key_buf);
    const m = try v3.decode(&sha1_des_authpriv_response);
    const sp = try usm.parse(m.security_parameters);

    // Wrong salt → wrong IV → garbage plaintext → BER failure (or, at worst, a
    // structure that does not match the real one). Never a panic.
    var out: [512]u8 = undefined;
    const bad_salt = [_]u8{0xff} ** 8;
    if (priv.decryptScopedPdu(.des_cbc, key, sp.engine_boots, sp.engine_time, &bad_salt, m.data.encrypted, &out)) |scoped| {
        try testing.expect(!std.mem.eql(u8, scoped.context_engine_id, &engine_id));
    } else |_| {}

    // A ciphertext whose length is not a multiple of 8 is rejected outright.
    try testing.expectError(error.InvalidLength, priv.decryptScopedPdu(
        .des_cbc,
        key,
        sp.engine_boots,
        sp.engine_time,
        sp.priv_params,
        m.data.encrypted[0 .. m.data.encrypted.len - 1],
        &out,
    ));

    // A salt of the wrong length is BadSalt, both ways.
    try testing.expectError(error.BadSalt, priv.decryptScopedPdu(
        .aes128_cfb,
        key,
        sp.engine_boots,
        sp.engine_time,
        sp.priv_params[0..4],
        m.data.encrypted,
        &out,
    ));
}

test "golden replay through V3Client: the captured discovery Report drives the handshake" {
    // A transport that answers the client's first request with net-snmp's real
    // captured Report, re-stamped with the client's msgID.
    const Replay = struct {
        out: [512]u8 = undefined,

        fn exchangeFn(ctx: *anyopaque, req: []const u8, reply_buf: []u8) client_mod.TransportError!usize {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            const asked = v3.decode(req) catch return error.TransportFailed;
            // Rebuild the captured Report under the caller's msgID/request-id.
            const captured = v3.decode(&discovery_report) catch return error.TransportFailed;
            const sp = usm.parse(captured.security_parameters) catch return error.TransportFailed;
            var sp_buf: [128]u8 = undefined;
            const sp_wire = usm.encode(&sp_buf, sp) catch return error.TransportFailed;
            const vbs = [_]message.VarBind{.{
                .name = Oid.parse("1.3.6.1.6.3.15.1.1.4.0") catch return error.TransportFailed,
                .value = .{ .counter32 = 1 },
            }};
            const wire = v3.encode(&s.out, .{
                .msg_id = asked.header.msg_id,
                .security_parameters = sp_wire,
                .context_engine_id = sp.engine_id,
                .pdu = .{ .type = .report, .request_id = 0, .varbinds = &vbs },
            }) catch return error.TransportFailed;
            std.mem.copyForwards(u8, reply_buf[0..wire.len], wire);
            return wire.len;
        }
    };
    var r: Replay = .{};
    var c = v3client.V3Client.init(
        .{ .ctx = &r, .exchangeFn = Replay.exchangeFn },
        .{
            .name = "sha256User",
            .level = .auth_priv,
            .auth_protocol = .hmac_sha256,
            .auth_password = password,
            .priv_protocol = .aes128_cfb,
            .priv_password = password,
        },
        .{},
    );
    try c.discover();
    try testing.expectEqualSlices(u8, &engine_id, c.engine.id());
    try testing.expectEqual(@as(u32, 1), c.engine.clock.engine_boots);
    try testing.expectEqual(@as(u32, 15), c.engine.clock.engine_time);
    // And the keys the handshake produced are the ones net-snmp stores.
    try testing.expectEqual(@as(usize, 32), c.engine.authKey().len);
    var want: [usm.max_key_len]u8 = undefined;
    const expect_key = try usm.passwordToKey(.hmac_sha256, password, &engine_id, &want);
    try testing.expectEqualSlices(u8, expect_key, c.engine.authKey());
}

// ── live interop against a running agent (gated, skips cleanly) ─────────────
//
// Set SNMP_TEST_AGENT=host:port to run the real thing against a live SNMPv3
// agent — e.g. an unprivileged net-snmp on a high port:
//
//   snmpd -f -Lo -C -c snmpd.conf -r --persistentDir=<dir>
//
// with the snmpd.conf shown at the top of this file. Optional overrides:
// SNMP_TEST_USER (default "shaAesUser"), SNMP_TEST_AUTH_PASSWORD and
// SNMP_TEST_PRIV_PASSWORD (default "maplesyrup"), SNMP_TEST_AUTH_PROTO
// (md5 | sha1 | sha224 | sha256 | sha384 | sha512, default sha1) and
// SNMP_TEST_PRIV_PROTO (des | aes, default aes) and SNMP_TEST_LEVEL
// (noAuthNoPriv | authNoPriv | authPriv, default authPriv). Without
// SNMP_TEST_AGENT, or if the agent does not answer, the test prints SKIPPED and
// passes.

fn envVar(name: []const u8) ?[]const u8 {
    return std.process.Environ.getPosix(std.testing.environ, name);
}

fn authProtoFromEnv() ?usm.AuthProtocol {
    const name = envVar("SNMP_TEST_AUTH_PROTO") orelse return .hmac_sha1;
    const table = [_]struct { []const u8, usm.AuthProtocol }{
        .{ "md5", .hmac_md5 },       .{ "sha1", .hmac_sha1 },
        .{ "sha224", .hmac_sha224 }, .{ "sha256", .hmac_sha256 },
        .{ "sha384", .hmac_sha384 }, .{ "sha512", .hmac_sha512 },
    };
    for (table) |row| if (std.mem.eql(u8, name, row[0])) return row[1];
    return null;
}

fn privProtoFromEnv() ?priv.PrivProtocol {
    const name = envVar("SNMP_TEST_PRIV_PROTO") orelse return .aes128_cfb;
    if (std.mem.eql(u8, name, "des")) return .des_cbc;
    if (std.mem.eql(u8, name, "aes")) return .aes128_cfb;
    return null;
}

fn levelFromEnv() ?v3client.SecurityLevel {
    const name = envVar("SNMP_TEST_LEVEL") orelse return .auth_priv;
    if (std.mem.eql(u8, name, "noAuthNoPriv")) return .no_auth_no_priv;
    if (std.mem.eql(u8, name, "authNoPriv")) return .auth_no_priv;
    if (std.mem.eql(u8, name, "authPriv")) return .auth_priv;
    return null;
}

test "live: SNMPv3 GET + walk against a real agent" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const endpoint = envVar("SNMP_TEST_AGENT") orelse {
        if (verboseSkip()) std.debug.print(
            "SKIPPED: live SNMPv3 interop (set SNMP_TEST_AGENT=host:port," ++
                " optionally SNMP_TEST_USER / SNMP_TEST_AUTH_PASSWORD /" ++
                " SNMP_TEST_PRIV_PASSWORD)\n",
            .{},
        );
        return error.SkipZigTest;
    };
    const user_name = envVar("SNMP_TEST_USER") orelse "shaAesUser";
    const auth_pw = envVar("SNMP_TEST_AUTH_PASSWORD") orelse password;
    const priv_pw = envVar("SNMP_TEST_PRIV_PASSWORD") orelse password;
    const auth_proto = authProtoFromEnv() orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live SNMPv3 interop (unknown SNMP_TEST_AUTH_PROTO)\n", .{});
        return error.SkipZigTest;
    };
    const priv_proto = privProtoFromEnv() orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live SNMPv3 interop (unknown SNMP_TEST_PRIV_PROTO)\n", .{});
        return error.SkipZigTest;
    };
    const level = levelFromEnv() orelse {
        if (verboseSkip()) std.debug.print("SKIPPED: live SNMPv3 interop (unknown SNMP_TEST_LEVEL)\n", .{});
        return error.SkipZigTest;
    };

    const colon = std.mem.lastIndexOfScalar(u8, endpoint, ':') orelse return error.SkipZigTest;
    const host = endpoint[0..colon];
    const port = std.fmt.parseInt(u16, endpoint[colon + 1 ..], 10) catch return error.SkipZigTest;

    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = std.Io.net.IpAddress.parse(host, port) catch return error.SkipZigTest;
    var udp = client_mod.UdpTransport.open(io, addr, .{
        .timeout = .{ .duration = .{ .raw = .fromMilliseconds(3000), .clock = .awake } },
    }) catch {
        if (verboseSkip()) std.debug.print("SKIPPED: live SNMPv3 interop (cannot open a socket to {s})\n", .{endpoint});
        return error.SkipZigTest;
    };
    defer udp.close();

    var c = v3client.V3Client.init(udp.transport(), .{
        .name = user_name,
        .level = level,
        .auth_protocol = auth_proto,
        .auth_password = auth_pw,
        .priv_protocol = priv_proto,
        .priv_password = priv_pw,
    }, .{});

    c.discover() catch |err| {
        if (verboseSkip()) std.debug.print(
            "SKIPPED: live SNMPv3 interop (no answer from {s}: {t})\n",
            .{ endpoint, err },
        );
        return error.SkipZigTest;
    };
    try testing.expect(c.engine.discovered);
    try testing.expect(c.engine.id().len >= 5);

    const resp = try c.get(&.{try Oid.parse("1.3.6.1.2.1.1.5.0")}); // sysName.0
    std.debug.print(
        "live SNMPv3 OK: {s} user={s} level={t} auth={t} priv={t} status={t}" ++
            " (engineID {d} bytes, boots {d}, time {d})\n",
        .{
            endpoint,
            user_name,
            level,
            auth_proto,
            priv_proto,
            resp.error_status,
            c.engine.id().len,
            c.engine.clock.engine_boots,
            c.engine.clock.engine_time,
        },
    );

    // The USM exchange itself is what this test proves: discovery, key
    // localization, digest, encryption and reply matching all worked well
    // enough for the agent to answer with a Response. Whether that Response
    // carries data or `authorizationError` is a VACM (access-control) decision
    // on the agent — a `rwuser` granted only at authNoPriv legitimately refuses
    // a noAuthNoPriv request — so it is reported, not asserted away.
    if (resp.error_status == .authorization_error) {
        std.debug.print(
            "  (agent returned authorizationError — VACM denies this security level; " ++
                "the v3 exchange itself succeeded)\n",
            .{},
        );
        return;
    }
    try testing.expectEqual(message.ErrorStatus.no_error, resp.error_status);
    var it = resp.varbinds.iterator();
    const vb = (try it.next()) orelse return error.TestUnexpectedResult;
    try testing.expect(vb.value == .octet_string);
    std.debug.print("  sysName.0 = \"{s}\"\n", .{vb.value.octet_string});

    // A walk exercises the repeated request path over the same session.
    var w = c.walker(try Oid.parse("1.3.6.1.2.1.1"));
    var seen: usize = 0;
    while (try w.next()) |_| {
        seen += 1;
        if (seen > 16) break;
    }
    try testing.expect(seen > 0);
}
