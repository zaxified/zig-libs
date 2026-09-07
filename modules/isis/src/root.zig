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

/// `testkit.fuzz`: `seedHex` for the corpus below and `Cursor` for the bias's
/// own two choices. A corpus entry is not the PDU — `Smith.slice` reads a
/// little-endian u32 length first, so a raw frame would arrive minus its own
/// discriminator and common header.
const testkit = @import("testkit");
const seed = testkit.fuzz.seedHex;

test "fuzz: PDU/TLV decode never panics/OOBs/over-allocates on hostile bytes" {
    // Fuzzing is built into the toolchain (`zig build test --fuzz`); under a
    // plain `zig build test` this runs once as a smoke test (same convention as
    // l2encap / icmp). The decoder reads straight off an untrusted link, so this
    // drives arbitrary bytes and asserts only: never panics, every walk
    // terminates, and any value slice lies strictly within the input.
    try std.testing.fuzz({}, fuzzDecode, .{ .corpus = &decode_seeds });
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

/// The five PDU shapes `decode` models, with the fixed header length the
/// Length Indicator must equal and the offset of the PDU-Length field.
/// Kept beside the harness rather than in `pdu.zig` because it exists to make
/// a fuzzer's random draw land on a decodable header, which is a testing
/// concern and not part of the codec's contract.
const modeled_shapes = [_]struct { type_byte: u8, fixed_len: u8, len_off: usize }{
    .{ .type_byte = 15, .fixed_len = 27, .len_off = 17 }, // L1 LAN IIH
    .{ .type_byte = 17, .fixed_len = 20, .len_off = 17 }, // P2P IIH
    .{ .type_byte = 18, .fixed_len = 27, .len_off = 8 }, // L1 LSP
    .{ .type_byte = 24, .fixed_len = 33, .len_off = 8 }, // L1 CSNP
    .{ .type_byte = 26, .fixed_len = 17, .len_off = 8 }, // L1 PSNP
};

/// Rewrites the front of `buf` into a header that `decode` will accept, so the
/// fuzzer spends its draws on the body and the TLV region instead of on the
/// header's equality checks. Everything past the fixed header — including the
/// TLVs — stays whatever the fuzzer drew.
///
/// ⚠ Driven by a `testkit.fuzz.Cursor` over the drawn bytes, not by further
/// `Smith` draws. Both of the draws this used to make came AFTER
/// `smith.bytes(&buf)` had eaten the input, so both returned their range
/// minimum: the shape was always `modeled_shapes[0]` and the PDU Length was
/// always `fixed_len` — an empty TLV region, in the harness whose whole purpose
/// is walking the TLV region. Reading them out of the seed instead makes the
/// choice reproducible from the seed, and under `--fuzz` the fuzzer still drives
/// it because it drives the slice.
fn biasToModeledPdu(buf: []u8, len: usize, cur: *testkit.fuzz.Cursor) bool {
    const s = modeled_shapes[cur.ranged(0, modeled_shapes.len - 1)];
    if (len < s.fixed_len) return false;
    buf[0] = header.discriminator;
    buf[1] = s.fixed_len; // Length Indicator — an equality, not a bound
    buf[2] = header.version;
    buf[3] = 6; // ID Length
    buf[4] = s.type_byte; // top 3 bits clear, so no ReservedBitSet
    buf[5] = header.version;
    // PDU Length must land in [fixed_len, len]; a random u16 essentially never
    // does, which is the single load-bearing field the old bias omitted.
    const pdu_len: u16 = @intCast(cur.ranged(s.fixed_len, @intCast(len)));
    std.mem.writeInt(u16, buf[s.len_off..][0..2], pdu_len, .big);
    return true;
}

/// Real IS-IS PDUs, in the format `Smith.slice` reads.
///
/// Every one is a capture-shaped frame from `goldens.zig` — the module's own
/// reference PDUs — plus the refusals `decode` names. The largest is 66 octets,
/// comfortably inside the 512-octet buffer (checked: a seed over the buffer
/// reads back EMPTY, not truncated).
///
/// Uniform random octets have to spell `0x83` in byte 0, a Length Indicator
/// that EQUALS the shape's fixed length in byte 1, and a PDU Length inside
/// `[fixed_len, len]` — the module's own TEETH test records that two million
/// coverage-guided runs crossed that never, which is why the goldens are here
/// rather than left to the search.
const decode_seeds = [_][]const u8{
    seed("831401061101000303000000000001001E0025018101CC0104034900010606001B213C9DF8"), // L1 LAN IIH
    seed("831B010612010003003C04B00000000000010000000000010000010104034900018101CC89046E6F646590100000030C0000001122330010C0000064"), // L1 LSP with SPB MT-Capability sub-TLVs
    seed("831B01060F01000303000000000001001B002C40000000000001020104034900018101CC0606001B213C9DF8"), // P2P IIH
    seed("83210106180100030033000000000001000000000000000000FFFFFFFFFFFFFFFF091004AE0000000000010000000000051234"), // L1 CSNP with an LSP-entry TLV
    seed("831101061A010003002300000000000100091004AE0000000000010000000000051234"), // L1 PSNP
    seed("831B010612010003004204B0000000000002000000000001000001010403490001020C000A8080800000000000030016110000000000030000000A06FA040A000001"), // LSP with extended IS reachability + sub-TLVs
    seed("831B010612010003003C04B0000000000003000000000001000001901F0000011B80000000000000010000000080000010ABCD01C000000001010020"), // LSP with an SPB Instance / SPBM Service ID
    seed("83210106190100030033000000000001000000000000000000FFFFFFFFFFFFFFFF091004AE0000000000010000000000051234"), // L2 CSNP
    seed("831101061B010003002300000000000100091004AE0000000000010000000000051234"), // L2 PSNP
    seed("DEADBEEF99"), // not an IS-IS PDU at all: the discriminator bail-out
    seed("83"), // one octet: shorter than the common header
    seed("831401061101000303000000000001001E0025"), // an IIH header with the TLV region cut off
    seed(""), // the empty buffer
};

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM —
    // so `len` was 0 on every input a seed can carry, and `walkTlvs` and
    // `decode` were both handed an empty slice. Everything the TEETH test below
    // proves about `biasToModeledPdu` was true and unreachable at the same time:
    // the `smith.value(bool)` guarding it was drawn AFTER the exhausted input,
    // so it was false and the bias never ran once outside `--fuzz`.
    const len: usize = smith.slice(&buf);
    driveInput(buf[0..len]);

    // The bias, as a second arm rather than a coin flip: a copy of the same
    // bytes with a modeled header stamped over the front, so the corpus
    // exercises the body decoders and the raw seed exercises the refusals.
    var biased: [512]u8 = undefined;
    @memcpy(biased[0..len], buf[0..len]);
    var cur: testkit.fuzz.Cursor = .{ .bytes = buf[0..len] };
    if (len >= 8) _ = biasToModeledPdu(biased[0..len], len, &cur);
    driveInput(biased[0..len]);
}

/// Everything the harness asserts about one buffer of untrusted octets.
fn driveInput(input: []const u8) void {
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
    // The LSP checksum surface reads the SAME untrusted bytes, and
    // `isis-lsdb` calls `checkLspChecksum` on them straight off the wire.
    // It was never driven from here: 210 lines added on the untrusted path
    // with no fuzz coverage at all.
    if (p == .lsp) {
        _ = pdu.computeLspChecksum(input) catch {};
        _ = pdu.checkLspChecksum(input) catch {};
    }
    walkTlvs(region, input);
}

test "corpus: every seed reaches the decoder, and the counts are pinned" {
    // Four numbers. `nonempty` is the reach claim. `decoded` says the corpus is
    // not refusals only. `tlv_bytes` is the one an empty input cannot produce
    // and neither can a header-only PDU: `decode` accepts a PDU whose TLV region
    // is empty, so counting acceptances alone would report health over a corpus
    // that never entered `walkTlvs` on a body — which is the entire harness.
    // `biased_stamped` is the fourth: how many seeds the bias arm actually
    // stamps a modeled header over. It was **0** for the whole life of this
    // harness — the `smith.value(bool)` gating the bias was drawn after the
    // input had been consumed, so it was false every time.
    var nonempty: usize = 0;
    var decoded: usize = 0;
    var tlv_bytes: usize = 0;
    var biased_stamped: usize = 0;
    for (decode_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [512]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (decode(buf[0..len])) |p| {
            if (p != .other) {
                decoded += 1;
                tlv_bytes += switch (p) {
                    .lan_hello => |x| x.tlv_bytes.len,
                    .p2p_hello => |x| x.tlv_bytes.len,
                    .lsp => |x| x.tlv_bytes.len,
                    .csnp => |x| x.tlv_bytes.len,
                    .psnp => |x| x.tlv_bytes.len,
                    .other => 0,
                };
            }
        } else |_| {}

        var biased: [512]u8 = undefined;
        @memcpy(biased[0..len], buf[0..len]);
        var cur: testkit.fuzz.Cursor = .{ .bytes = buf[0..len] };
        if (len >= 8 and biasToModeledPdu(biased[0..len], len, &cur)) {
            biased_stamped += 1;
            // A stamped header is a header `decode` accepts, by construction.
            _ = try decode(biased[0..len]);
        }
    }
    try std.testing.expectEqual(decode_seeds.len - 1, nonempty); // the empty seed is deliberate
    try std.testing.expectEqual(@as(usize, 9), decoded);
    try std.testing.expectEqual(@as(usize, 211), tlv_bytes);
    try std.testing.expectEqual(@as(usize, 9), biased_stamped);
}

test "TEETH: the fuzz bias actually reaches a decoded PDU body" {
    // The harness's bias block is the only thing standing between the fuzzer
    // and the body decoders, and for the whole life of this module it reached
    // a body ZERO times — a fact no gate could report, because `check-fuzz`
    // asks whether a harness EXISTS. This test asks the question `check-fuzz`
    // cannot: it draws from the harness's own bias and asserts that at least
    // one draw decodes into a modeled PDU.
    //
    // Deterministic: a fixed seed through `std.testing.Smith`, so this is a
    // reachability assertion and not a flaky sampling test.
    // ⚠ The draws here do NOT go through `Smith` the way `fuzzDecode` does,
    // and that is deliberate: `Smith.bytes(out)` consumes the whole supplied
    // input, so every later `valueRangeAtMost` falls back to its range's LOWER
    // bound. Written the obvious way — one `Smith` per round, `bytes` then
    // `valueRangeAtMost` — this test draws `len = 0` every single round, skips
    // every iteration, and would report whatever the final `expect` says with
    // nothing behind it. What is asserted instead is the thing that was
    // broken: that `biasToModeledPdu` turns a random buffer into a header the
    // dispatcher accepts.
    var prng = std.Random.DefaultPrng.init(0x1515);
    const rand = prng.random();
    var seen: usize = 0;
    var round: u8 = 0;
    while (round < 64) : (round += 1) {
        var buf: [128]u8 = undefined;
        rand.bytes(&buf);
        const len: usize = rand.intRangeAtMost(usize, 8, buf.len);
        // Fresh, generously sized script for the bias's own two choices only.
        var script: [64]u8 = undefined;
        rand.bytes(&script);
        var cur: testkit.fuzz.Cursor = .{ .bytes = &script };
        _ = biasToModeledPdu(&buf, len, &cur);
        const p = decode(buf[0..len]) catch continue;
        if (p != .other) seen += 1;
    }
    // Before the fix this was 0 for any number of rounds.
    try std.testing.expect(seen > 0);
}
