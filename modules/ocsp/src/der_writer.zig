// SPDX-License-Identifier: MIT
//! Minimal arena-backed DER *encoder* used by `buildRequest` (the only
//! DER this module ever emits) and by the test fixtures (which hand-build
//! signed certificates + OCSP responses). Every method returns a freshly
//! allocated `[]const u8` holding one complete TLV (tag + length + content);
//! callers compose them by nesting (`seq(&.{a, b})`). All allocation is on the
//! caller-supplied arena, so nothing needs individual freeing — the arena is
//! reset/destroyed at the operation boundary.
//!
//! This is an ENCODER only. All *decoding* of attacker-influenced bytes goes
//! through the bounds-safe reader in `root.zig` (built on x509's
//! `extensions.parseElement`); nothing here parses untrusted input.

const std = @import("std");

pub const Error = std.mem.Allocator.Error;

pub const Builder = struct {
    a: std.mem.Allocator,

    /// Encode a length in DER definite form (short form < 128, else long form).
    fn lenBytes(a: std.mem.Allocator, len: usize) Error![]u8 {
        if (len < 0x80) {
            const out = try a.alloc(u8, 1);
            out[0] = @intCast(len);
            return out;
        }
        // Long form: 0x80 | n, followed by n big-endian length octets.
        var tmp: [8]u8 = undefined;
        var n: usize = 0;
        var v = len;
        while (v != 0) : (v >>= 8) {
            tmp[n] = @truncate(v);
            n += 1;
        }
        const out = try a.alloc(u8, n + 1);
        out[0] = @intCast(0x80 | n);
        for (0..n) |i| out[1 + i] = tmp[n - 1 - i];
        return out;
    }

    /// One TLV with an explicit identifier octet and already-built content.
    pub fn tlv(b: Builder, tag: u8, content: []const u8) Error![]const u8 {
        const len = try lenBytes(b.a, content.len);
        var out = try b.a.alloc(u8, 1 + len.len + content.len);
        out[0] = tag;
        @memcpy(out[1 .. 1 + len.len], len);
        @memcpy(out[1 + len.len ..], content);
        return out;
    }

    pub fn seq(b: Builder, parts: []const []const u8) Error![]const u8 {
        return b.tlv(0x30, try std.mem.concat(b.a, u8, parts));
    }

    /// SEQUENCE with the `sequence_of` bit is identical on the wire to 0x30 for
    /// our purposes; DER encodes SEQUENCE OF with tag 0x30.
    pub fn seqOf(b: Builder, parts: []const []const u8) Error![]const u8 {
        return b.seq(parts);
    }

    pub fn setOf(b: Builder, parts: []const []const u8) Error![]const u8 {
        return b.tlv(0x31, try std.mem.concat(b.a, u8, parts));
    }

    /// OBJECT IDENTIFIER from its already-encoded content octets.
    pub fn oid(b: Builder, encoded: []const u8) Error![]const u8 {
        return b.tlv(0x06, encoded);
    }

    pub fn octet(b: Builder, content: []const u8) Error![]const u8 {
        return b.tlv(0x04, content);
    }

    /// BIT STRING with zero unused bits (the only form this module emits).
    pub fn bitString(b: Builder, content: []const u8) Error![]const u8 {
        const body = try b.a.alloc(u8, content.len + 1);
        body[0] = 0; // unused-bits count
        @memcpy(body[1..], content);
        return b.tlv(0x03, body);
    }

    pub fn @"null"(b: Builder) Error![]const u8 {
        return b.tlv(0x05, &.{});
    }

    /// INTEGER from raw big-endian magnitude bytes already in DER-canonical
    /// form (this is used to re-emit a certificate's serialNumber verbatim, so
    /// no re-normalization is applied — the bytes came from a valid cert).
    pub fn integerRaw(b: Builder, content: []const u8) Error![]const u8 {
        return b.tlv(0x02, content);
    }

    pub fn integerU8(b: Builder, v: u8) Error![]const u8 {
        return b.tlv(0x02, try b.a.dupe(u8, &.{v}));
    }

    pub fn enumerated(b: Builder, v: u8) Error![]const u8 {
        return b.tlv(0x0a, try b.a.dupe(u8, &.{v}));
    }

    pub fn utf8String(b: Builder, s: []const u8) Error![]const u8 {
        return b.tlv(0x0c, s);
    }

    pub fn generalizedTime(b: Builder, s: []const u8) Error![]const u8 {
        return b.tlv(0x18, s);
    }

    /// Context-specific constructed `[n] EXPLICIT` wrapper (tag 0xA0 | n).
    pub fn explicit(b: Builder, n: u3, content: []const u8) Error![]const u8 {
        return b.tlv(0xa0 | @as(u8, n), content);
    }

    /// Context-specific primitive `[n] IMPLICIT` leaf (tag 0x80 | n), e.g.
    /// `good [0] IMPLICIT NULL` (empty content) or an IMPLICIT OCTET STRING.
    pub fn implicitPrimitive(b: Builder, n: u3, content: []const u8) Error![]const u8 {
        return b.tlv(0x80 | @as(u8, n), content);
    }

    /// Context-specific constructed `[n] IMPLICIT` for a SEQUENCE-shaped body
    /// (tag 0xA0 | n, same octet as EXPLICIT — used for `revoked [1] IMPLICIT
    /// RevokedInfo`, where the underlying type is a SEQUENCE).
    pub fn implicitConstructed(b: Builder, n: u3, content: []const u8) Error![]const u8 {
        return b.tlv(0xa0 | @as(u8, n), content);
    }
};
