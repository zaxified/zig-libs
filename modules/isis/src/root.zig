// SPDX-License-Identifier: MIT
//! isis — IS-IS (ISO/IEC 10589) PDU codec: the common header + the TLV
//! framework + the IIH (Hello) and LSP PDUs + CSNP/PSNP + the SPB (802.1aq /
//! RFC 6329) TLVs, with a raw/unknown-TLV escape hatch. Pure, bounds-checked
//! encode/decode of untrusted link bytes — the wire foundation the SPB control
//! plane (adjacency FSM, LSP DB, flooding) builds on. No state machine here;
//! codec only.
//!
//! ## Layers
//! - `header` — the 8-byte common PDU header + the `PduType` enum.
//! - `tlv` — the bounds-checked TLV walker (`TlvIterator`), the raw escape
//!   hatch (`RawTlv`), and the caller-buffer `Builder`. The core: one
//!   length-check implementation serves both top-level and sub-TLVs.
//! - `tlvs` — typed views of the common TLVs (Area Addresses #1, IS
//!   Neighbours #2/#6, Extended IS Reachability #22 with sub-TLVs, Protocols
//!   Supported #129, Dynamic Hostname #137, LSP Entries #9).
//! - `pdu` — the IIH (LAN + P2P), LSP, CSNP, and PSNP bodies + builders.
//! - `spb` — the SPB MT-Capability (#144) / MT-Port-Capability (#143) container
//!   and the SPB Instance (sub-TLV 1) + SPBM-SI (sub-TLV 3) sub-TLVs.
//! - `checksum` — the ISO 8473 Fletcher checksum (RFC 905 Annex B), and with it
//!   `pdu.{computeLspChecksum, checkLspChecksum, stampLspChecksum}` for ISO
//!   10589 §7.3.11. The codec still *carries* the field verbatim on decode; the
//!   §7.3.14.2 receive policy is the update process's (`isis-lsdb`).
//!
//! ## Conventions (see SPEC.md for the rationale)
//! - System ids are 6 octets (the default, MAC-sized id SPB uses); the typed
//!   PDU bodies decode only that id length (raw TLV walking is id-length-free).
//! - All multi-byte integer fields are big-endian (network byte order).
//! - Decode is zero-copy and zero-allocation: every value is a subslice of the
//!   input; a TLV length that lies about the buffer is a typed error, never an
//!   over-read (the untrusted-decode guarantee).
//!
//! Provenance: clean-room from ISO/IEC 10589, RFC 1195/5301/5305, and RFC
//! 6329/6165 (SPB); no third-party dissector source consulted. See /NOTICE
//! (no entry required — public specs).

const std = @import("std");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "IS-IS (ISO/IEC 10589) PDU codec — common header + TLV framework + IIH/LSP PDUs + SPB (802.1aq) TLVs; pure bounds-checked encode/decode, wire foundation for an SPB control plane",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "ISO/IEC 10589 IS-IS + IEEE 802.1aq/RFC 6329 (SPB) TLVs",
    .deps = .{}, // std only
};

pub const header = @import("header.zig");
pub const tlv = @import("tlv.zig");
pub const tlvs = @import("tlvs.zig");
pub const pdu = @import("pdu.zig");
pub const spb = @import("spb.zig");
pub const checksum = @import("checksum.zig");

// Convenience re-exports of the most-used surface.
pub const PduType = header.PduType;
pub const CommonHeader = header.CommonHeader;
pub const RawTlv = tlv.RawTlv;
pub const TlvIterator = tlv.TlvIterator;
pub const Builder = tlv.Builder;
pub const LanHello = pdu.LanHello;
pub const P2pHello = pdu.P2pHello;
pub const Lsp = pdu.Lsp;
pub const Csnp = pdu.Csnp;
pub const Psnp = pdu.Psnp;

/// A decoded PDU, tagged by type. Unknown/unmodeled PDU types keep the parsed
/// common header and the raw remaining bytes so nothing panics on an
/// unexpected type.
pub const Pdu = union(enum) {
    lan_hello: LanHello,
    p2p_hello: P2pHello,
    lsp: Lsp,
    csnp: Csnp,
    psnp: Psnp,
    /// A well-formed common header whose PDU type this codec does not model a
    /// body for; `bytes` is the whole input.
    other: struct { header: CommonHeader, bytes: []const u8 },
};

/// Dispatches on the common header's PDU type and decodes the matching body.
/// A malformed header or body surfaces as a typed `pdu.DecodeError`; an
/// unmodeled-but-well-formed PDU type returns `.other` rather than an error.
pub fn decode(bytes: []const u8) pdu.DecodeError!Pdu {
    const h = try header.decode(bytes);
    return switch (h.pdu_type) {
        .l1_lan_iih, .l2_lan_iih => .{ .lan_hello = try LanHello.decode(bytes) },
        .p2p_iih => .{ .p2p_hello = try P2pHello.decode(bytes) },
        .l1_lsp, .l2_lsp => .{ .lsp = try Lsp.decode(bytes) },
        .l1_csnp, .l2_csnp => .{ .csnp = try Csnp.decode(bytes) },
        .l1_psnp, .l2_psnp => .{ .psnp = try Psnp.decode(bytes) },
        else => .{ .other = .{ .header = h, .bytes = bytes } },
    };
}

test {
    _ = @import("header.zig");
    _ = @import("tlv.zig");
    _ = @import("tlvs.zig");
    _ = @import("pdu.zig");
    _ = @import("spb.zig");
    _ = @import("checksum.zig");
    _ = @import("goldens.zig");
}

test "meta is well-formed" {
    try std.testing.expectEqual(.any, meta.platform);
    try std.testing.expectEqual(.codec, meta.role);
    try std.testing.expectEqual(.reentrant, meta.concurrency);
}

test "top-level decode dispatches by PDU type" {
    var buf: [64]u8 = undefined;
    var b = try pdu.P2pHelloBuilder.init(&buf, .{ .source_id = .{ 0, 0, 0, 0, 0, 1 }, .holding_time = 30 });
    try tlvs.addProtocolsSupported(&b.tlvs, &.{tlvs.nlpid_ipv4});
    const wire = b.finish();
    switch (try decode(wire)) {
        .p2p_hello => |p| try std.testing.expectEqual(@as(u16, 30), p.holding_time),
        else => return error.WrongVariant,
    }
}

// ── fuzz target: the mandatory bounds-safety core ────────────────────────────

test "fuzz: PDU/TLV decode never panics/OOBs/over-allocates on hostile bytes" {
    // Fuzzing is built into the toolchain (`zig build test --fuzz`); under a
    // plain `zig build test` this runs once as a smoke test (same convention as
    // l2encap / icmp). The decoder reads straight off an untrusted link, so this
    // drives arbitrary bytes and asserts only: never panics, every walk
    // terminates, and any value slice lies strictly within the input.
    try std.testing.fuzz({}, fuzzDecode, .{});
}

/// `sub` must lie entirely inside `input`. Checked as an offset and a length,
/// never as a raw pointer comparison — a wrapped length is the failure mode
/// being looked for, and `ptr + len` would wrap along with it.
fn within(sub: []const u8, input: []const u8) void {
    std.debug.assert(@intFromPtr(sub.ptr) >= @intFromPtr(input.ptr));
    const off = @intFromPtr(sub.ptr) - @intFromPtr(input.ptr);
    std.debug.assert(off <= input.len);
    std.debug.assert(sub.len <= input.len - off);
}

/// W2 A3 recorded that this harness reached `tlv.TlvIterator` and nothing else:
/// `walkTlvs` built one raw walker and stopped, so `spb.{MtCapability,
/// SpbInstance, SpbmServiceId}.decode` and the five `tlvs.*Iterator`s — every
/// **fixed-offset** reader in the module, which is the shape that over-reads —
/// were never handed a hostile byte. Dispatching on the TLV code would not have
/// been enough on its own: a 128-octet random buffer almost never spells `144`
/// in a length-consistent position, so the typed decoders would still have been
/// entered on a vanishing fraction of iterations. Every typed decoder is
/// therefore run on **every** value, code or no code — each one is a total
/// function on bytes, and the only question is whether it stays in bounds.
fn driveTyped(value: []const u8, input: []const u8) void {
    var guard: usize = 0;

    var areas = tlvs.AreaAddressIterator.init(value);
    while (true) {
        const a = (areas.next() catch break) orelse break;
        within(a, input);
        guard += 1;
        std.debug.assert(guard <= input.len + 1);
    }

    var snpas = tlvs.SnpaIterator.init(value);
    guard = 0;
    while (true) {
        _ = (snpas.next() catch break) orelse break;
        guard += 1;
        std.debug.assert(guard <= input.len + 1);
    }

    if (tlvs.IsReachIterator.init(value)) |init_ok| {
        var reach = init_ok;
        _ = reach.virtualFlag();
        guard = 0;
        while (true) {
            _ = (reach.next() catch break) orelse break;
            guard += 1;
            std.debug.assert(guard <= input.len + 1);
        }
    } else |_| {}

    var ext = tlvs.ExtIsReachIterator.init(value);
    guard = 0;
    while (true) {
        const e = (ext.next() catch break) orelse break;
        within(e.sub_tlvs, input);
        var esub = e.subTlvIterator();
        while (true) {
            const s = (esub.next() catch break) orelse break;
            within(s.value, input);
        }
        guard += 1;
        std.debug.assert(guard <= input.len + 1);
    }

    var entries = tlvs.LspEntryIterator.init(value);
    guard = 0;
    while (true) {
        _ = (entries.next() catch break) orelse break;
        guard += 1;
        std.debug.assert(guard <= input.len + 1);
    }

    // The SPB container and its two fixed-layout sub-TLVs.
    if (spb.MtCapability.decode(value)) |mt| {
        within(mt.sub_tlvs, input);
        var msub = mt.subTlvIterator();
        guard = 0;
        while (true) {
            const s = (msub.next() catch break) orelse break;
            within(s.value, input);
            driveSpb(s.value, input);
            guard += 1;
            std.debug.assert(guard <= input.len + 1);
        }
    } else |_| {}
    // Also unconditionally, so the sub-TLV readers do not depend on the
    // container preamble having been synthesised first.
    driveSpb(value, input);
}

fn driveSpb(value: []const u8, input: []const u8) void {
    var guard: usize = 0;
    if (spb.SpbInstance.decode(value)) |inst| {
        within(inst.tuple_bytes, input);
        std.debug.assert(inst.tuple_bytes.len == @as(usize, inst.num_trees) * 8);
        var tuples = inst.tupleIterator();
        while (true) {
            _ = (tuples.next() catch break) orelse break;
            guard += 1;
            std.debug.assert(guard <= input.len + 1);
        }
    } else |_| {}
    if (spb.SpbmServiceId.decode(value)) |si| {
        within(si.isid_bytes, input);
        std.debug.assert(si.isid_bytes.len % 4 == 0);
        var isids = si.isidIterator();
        guard = 0;
        while (true) {
            _ = (isids.next() catch break) orelse break;
            guard += 1;
            std.debug.assert(guard <= input.len + 1);
        }
    } else |_| {}
}

fn walkTlvs(bytes: []const u8, input: []const u8) void {
    var it = tlv.TlvIterator.init(bytes);
    var guard: usize = 0;
    while (it.next() catch return) |t| {
        // Every yielded value must be a subslice of the original input.
        within(t.value, input);
        // One level of sub-TLV walking (extended-reach / SPB shape).
        var sub = tlv.TlvIterator.init(t.value);
        while (true) {
            const s = (sub.next() catch break) orelse break;
            within(s.value, input);
            driveTyped(s.value, input);
        }
        // …and the typed views of this value, which is where the fixed-offset
        // reads live.
        driveTyped(t.value, input);
        guard += 1;
        std.debug.assert(guard <= input.len); // the walk must terminate
    }
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    smith.bytes(&buf);
    const len: usize = smith.valueRangeAtMost(u8, 0, @intCast(buf.len));
    const input = buf[0..len];

    // Bias toward valid-looking headers so deeper paths are exercised, not just
    // the discriminator bail-out.
    if (len >= 8 and smith.value(bool)) {
        buf[0] = header.discriminator;
        buf[2] = header.version;
        buf[5] = header.version;
    }

    // The raw TLV walk over the whole buffer must always be safe.
    walkTlvs(input, input);

    // The dispatch decoder must never panic; on success, the body's TLV region
    // is walked (already bounded) and its sub-TLVs, all within the input.
    const p = decode(input) catch return;
    const region: []const u8 = switch (p) {
        .lan_hello => |x| x.tlv_bytes,
        .p2p_hello => |x| x.tlv_bytes,
        .lsp => |x| x.tlv_bytes,
        .csnp => |x| x.tlv_bytes,
        .psnp => |x| x.tlv_bytes,
        .other => return,
    };
    walkTlvs(region, input);
}
