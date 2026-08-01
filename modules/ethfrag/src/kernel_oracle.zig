// SPDX-License-Identifier: MIT

//! **External anchor: the real Linux kernel's own IPv4/IPv6 fragment
//! reassembly, used as a black-box RFC-policy oracle.**
//!
//! Before this file, every test in `root.zig` was self-consistent: build
//! fragments with THIS module's own `fragment()`, feed them to THIS
//! module's own `Reassembler`, assert round-trip equality (plus one seeded
//! property test over the same pair). No external judgement ever entered —
//! a bug wrong the same way on both sides of that pair is invisible to it.
//!
//! ## What is, and isn't, oracle-able here
//! `ethfrag` is a **standalone overlay codec**: its 8-byte `frag_id`/
//! `offset`/`length`/`flags` header (see `root.zig`'s module doc comment)
//! is a wire format this module invented, not IPv4 or IPv6. The kernel has
//! no idea what these bytes mean, so literally replaying `ethfrag`'s own
//! wire bytes at a kernel socket tests nothing — the kernel would just see
//! opaque application payload. What CAN be oracled is the thing this module
//! explicitly claims to model (`root.zig`: `model_after = "IP
//! fragmentation/reassembly (RFC 791 §3.2) + RFC 5722 §3 overlap rejection,
//! hardened"`): build REAL IPv4/IPv6 fragments by hand, let the real
//! kernel reassemble (or refuse to reassemble) them, and compare the
//! kernel's accept/drop/deliver decision against what THIS module's
//! `Reassembler` decides for a fragment set with the IDENTICAL shape
//! (same offsets, same order, same overlap/duplicate pattern) re-encoded
//! into `ethfrag`'s own wire format. This is a policy-level comparison,
//! not a byte-format one — exactly the level at which "model_after" is a
//! testable claim.
//!
//! `scapy` is not installed and may not be installed. Every fragment below
//! was built by hand in Python (raw `AF_INET`/`AF_INET6` `SOCK_RAW` sockets
//! with `IP_HDRINCL`/`IPV6_HDRINCL`, manual header packing, manual Internet
//! checksums) inside an unprivileged `unshare --user --map-root-user --net`
//! namespace, so nothing touched host state. A plain `SOCK_DGRAM` UDP
//! listener in the same namespace is the receiver: `recvfrom()` returning
//! the reassembled datagram is "DELIVERED"; a 1.5s `socket.timeout` with
//! nothing received is "TIMEOUT" (a bounded proxy for "kernel never
//! reassembled this", not a claim about the kernel's actual multi-second
//! reassembly-queue expiry).
//!
//! ## Capture recipe (six scenarios × {IPv4, IPv6} = 12 captures)
//! A 32-byte UDP payload (`8 + 32 = 40`-byte UDP datagram, split into three
//! chunks at offsets 0/16/32 -- all multiples of 8, satisfying IPv4's
//! 8-byte fragment-offset granularity and IPv6's identical Fragment
//! extension-header granularity) was fragmented by hand for:
//!   - `in_order`: the three chunks sent offset-ascending.
//!   - `out_of_order`: the three chunks sent last-chunk-first.
//!   - `missing_middle`: only the first and last chunks sent (the middle
//!     third of the datagram is never supplied).
//!   - `duplicate`: the first chunk sent TWICE, byte-for-byte identical
//!     (same offset, same length, same content), then the rest in order.
//!   - `overlap`: an extra 16-byte fragment at offset 8 whose CONTENT
//!     conflicts with what the real datagram has there (`0xEE` filler),
//!     straddling the first/second chunk boundary — the RFC 5722 §3 case.
//!   - `overlap_same_content`: the identical shape as `overlap` (offset 8,
//!     16 bytes, straddling the chunk boundary) but with content that
//!     AGREES with the real datagram in the overlapped region — distinct
//!     from `duplicate` because it is not a resend of any whole fragment
//!     actually sent (it's a different offset/length slicing of the same
//!     bytes), isolating "does the kernel tolerate exact fragment
//!     retransmission" from "does the kernel tolerate any content-
//!     consistent overlap".
//!
//! ```sh
//! unshare --user --map-root-user --net -- bash -c '
//!   ip link set lo up
//!   python3 capture.py   # hand-rolled raw-socket sender + UDP listener
//! '
//! ```
//! (`capture.py` is not part of this repository -- a throwaway harness,
//! not shipped code; the bytes and verdicts it produced are frozen below.)
//!
//! ## A methodology bug this capture surfaced in ITSELF (worth recording)
//! The first capture pass reused one fragment id across every scenario run
//! back-to-back inside one namespace. The kernel's IP reassembly queue is
//! keyed by `(src, dst, protocol, identification)` -- NOT by socket or by
//! which Python process sent it. `missing_middle` deliberately leaves an
//! incomplete queue entry that only expires after the kernel's own
//! multi-second reassembly timeout; a LATER scenario reusing the same id
//! before that expiry silently merges with the leftover fragments,
//! producing "DELIVERED" verdicts that had nothing to do with the
//! scenario under test. This was caught because `overlap_same_content`
//! gave two different verdicts across two capture runs with different
//! scenario orderings for what should have been a pure function of the
//! scenario. The fix: a globally-unique `ident` (and a scenario-specific
//! payload, so `matches_expected` is meaningful too) per (scenario,
//! address-family) capture. Every capture below used a distinct id;
//! re-running the whole 12-capture sweep twice after the fix reproduced
//! identical verdicts both times.
//!
//! ## Results (see `captures` below for the frozen bytes)
//! IPv4 and IPv6 agreed with each other on every scenario on this kernel:
//!   - `in_order`, `out_of_order`: DELIVERED, byte-exact.
//!   - `missing_middle`: never delivered.
//!   - `overlap`, `overlap_same_content`: never delivered (dropped).
//!   - `duplicate`: DELIVERED -- the kernel tolerates a byte-for-byte,
//!     offset-for-offset EXACT resend of an already-accepted fragment as a
//!     harmless retransmission, distinct from `overlap_same_content`'s
//!     content-consistent-but-differently-sliced fragment, which it drops
//!     exactly like a conflicting overlap.
//!
//! **This module intentionally diverges from the kernel on `duplicate`**:
//! `Reassembler.insert` drops the whole datagram on ANY overlap, including
//! an exact duplicate (`root.zig`'s doc comment already named this design
//! choice explicitly, before this file existed: "there is deliberately no
//! separate 'identical bytes, so merge it' fast path, because that
//! distinction is exactly what overlap-based IDS-evasion attacks rely
//! on"). This capture is the first EXTERNAL confirmation that a real,
//! widely-deployed stack (this host's Linux kernel) does implement exactly
//! that fast path for both IPv4 and IPv6 -- i.e. this module is
//! deliberately, verifiably stricter than the reference implementation it
//! is modeled after, not accidentally out of sync with it. Per the task
//! mandate: this divergence is reported, not "fixed" by loosening our
//! policy to match the kernel, because RFC 5722 §3's IPv6 text ("MUST be
//! discarded", no carve-out for duplicates) sides with the stricter
//! behavior, not the kernel's tolerant one.
//!
//! ## Not oracle-able (written reason, per the task's item 4)
//! This module's own resource-bound policies -- `max_inflight`,
//! `max_fragments_per_datagram`, `timeout_ns` -- are invented knobs of
//! THIS codec with no IPv4/IPv6 kernel equivalent to compare against (the
//! kernel has its own, differently-shaped global thresholds --
//! `ipfrag_high_thresh` and friends -- which bound kernel-wide memory, not
//! one caller-owned `Reassembler` instance). Likewise `InvalidHeader`/
//! `LengthMismatch`/`TableFull`/`ProtocolViolation` are rejections of THIS
//! module's own wire format, which the kernel never parses at all. Both
//! classes are already covered by the self-contained adversarial tests in
//! `root.zig` (that file's "Verification" section in `SPEC.md` lists them
//! one-for-one); this file adds no test for them, by design, not oversight
//! -- see the count canary at the bottom.
//!
//! ## Attribution
//! Exercising the kernel's own IPv4/IPv6 reassembly purely as a black-box
//! RFC-policy oracle (never consulting or copying kernel source) needs no
//! `NOTICE` entry -- root `NOTICE` §0 exempts this explicitly, the same
//! pattern already used for `icmp`/`genetlink` (the kernel itself as
//! oracle) and now `wireguard` (kernel + `wg`-tool netlink capture).

const std = @import("std");
const testing = std.testing;
const ethfrag = @import("root.zig");

const Capture = struct {
    name: []const u8,
    v6: bool,
    ident: u32,
    /// Raw wire bytes of each real IPv4/IPv6 fragment, in SEND order, hex.
    packets_hex: []const []const u8,
    /// Did the kernel's UDP listener actually receive a reassembled
    /// datagram (true), or did it time out with nothing delivered (false)?
    verdict_delivered: bool,
    /// The expected reassembled bytes (the on-wire UDP datagram: 8-byte
    /// UDP header + 32-byte payload) when `verdict_delivered` is true.
    full_dgram_hex: []const u8,
};

const captures = [_]Capture{
    .{
        .name = "in_order",
        .v6 = false,
        .ident = 0x1001,
        .packets_hex = &.{
            "450000241001200040114cc67f0000017f000001ca42ca4100280000040b121920272e35",
            "450000241001200240114cc47f0000017f0000013c434a51585f666d747b828990979ea5",
            "4500001c1001000440116cca7f0000017f000001acb3bac1c8cfd6dd",
        },
        .verdict_delivered = true,
        .full_dgram_hex = "ca42ca4100280000040b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dd",
    },
    .{
        .name = "out_of_order",
        .v6 = false,
        .ident = 0x1002,
        .packets_hex = &.{
            "4500001c1002000440116cc97f0000017f000001adb4bbc2c9d0d7de",
            "450000241002200040114cc57f0000017f000001ca42ca4100280000050c131a21282f36",
            "450000241002200240114cc37f0000017f0000013d444b525960676e757c838a91989fa6",
        },
        .verdict_delivered = true,
        .full_dgram_hex = "ca42ca4100280000050c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7de",
    },
    .{
        .name = "missing_middle",
        .v6 = false,
        .ident = 0x1003,
        .packets_hex = &.{
            "450000241003200040114cc47f0000017f000001ca42ca4100280000060d141b22293037",
            "4500001c1003000440116cc87f0000017f000001aeb5bcc3cad1d8df",
        },
        .verdict_delivered = false,
        .full_dgram_hex = "ca42ca4100280000060d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8df",
    },
    .{
        .name = "duplicate",
        .v6 = false,
        .ident = 0x1004,
        .packets_hex = &.{
            "450000241004200040114cc37f0000017f000001ca42ca4100280000070e151c232a3138",
            "450000241004200040114cc37f0000017f000001ca42ca4100280000070e151c232a3138",
            "450000241004200240114cc17f0000017f0000013f464d545b626970777e858c939aa1a8",
            "4500001c1004000440116cc77f0000017f000001afb6bdc4cbd2d9e0",
        },
        .verdict_delivered = true,
        .full_dgram_hex = "ca42ca4100280000070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0",
    },
    .{
        .name = "overlap",
        .v6 = false,
        .ident = 0x1005,
        .packets_hex = &.{
            "450000241005200040114cc27f0000017f000001ca42ca4100280000080f161d242b3239",
            "450000241005200140114cc17f0000017f000001eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "450000241005200240114cc07f0000017f00000140474e555c636a71787f868d949ba2a9",
            "4500001c1005000440116cc67f0000017f000001b0b7bec5ccd3dae1",
        },
        .verdict_delivered = false,
        .full_dgram_hex = "ca42ca4100280000080f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1",
    },
    .{
        .name = "overlap_same_content",
        .v6 = false,
        .ident = 0x1006,
        .packets_hex = &.{
            "450000241006200040114cc17f0000017f000001ca42ca41002800000910171e252c333a",
            "450000241006200140114cc07f0000017f0000010910171e252c333a41484f565d646b72",
            "450000241006200240114cbf7f0000017f00000141484f565d646b727980878e959ca3aa",
            "4500001c1006000440116cc57f0000017f000001b1b8bfc6cdd4dbe2",
        },
        .verdict_delivered = false,
        .full_dgram_hex = "ca42ca41002800000910171e252c333a41484f565d646b727980878e959ca3aab1b8bfc6cdd4dbe2",
    },
    .{
        .name = "in_order",
        .v6 = true,
        .ident = 0x10000007,
        .packets_hex = &.{
            "6000000000182c4000000000000000000000000000000001000000000000000000000000000000011100000110000007ca42ca41002833710a11181f262d343b",
            "6000000000182c4000000000000000000000000000000001000000000000000000000000000000011100001110000007424950575e656c737a81888f969da4ab",
            "6000000000102c4000000000000000000000000000000001000000000000000000000000000000011100002010000007b2b9c0c7ced5dce3",
        },
        .verdict_delivered = true,
        .full_dgram_hex = "ca42ca41002833710a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3",
    },
    .{
        .name = "out_of_order",
        .v6 = true,
        .ident = 0x10000008,
        .packets_hex = &.{
            "6000000000102c4000000000000000000000000000000001000000000000000000000000000000011100002010000008b3bac1c8cfd6dde4",
            "6000000000182c4000000000000000000000000000000001000000000000000000000000000000011100000110000008ca42ca41002823610b121920272e353c",
            "6000000000182c4000000000000000000000000000000001000000000000000000000000000000011100001110000008434a51585f666d747b828990979ea5ac",
        },
        .verdict_delivered = true,
        .full_dgram_hex = "ca42ca41002823610b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4",
    },
    .{
        .name = "missing_middle",
        .v6 = true,
        .ident = 0x10000009,
        .packets_hex = &.{
            "6000000000182c4000000000000000000000000000000001000000000000000000000000000000011100000110000009ca42ca41002813510c131a21282f363d",
            "6000000000102c4000000000000000000000000000000001000000000000000000000000000000011100002010000009b4bbc2c9d0d7dee5",
        },
        .verdict_delivered = false,
        .full_dgram_hex = "ca42ca41002813510c131a21282f363d444b525960676e757c838a91989fa6adb4bbc2c9d0d7dee5",
    },
    .{
        .name = "duplicate",
        .v6 = true,
        .ident = 0x1000000a,
        .packets_hex = &.{
            "6000000000182c400000000000000000000000000000000100000000000000000000000000000001110000011000000aca42ca41002803410d141b222930373e",
            "6000000000182c400000000000000000000000000000000100000000000000000000000000000001110000011000000aca42ca41002803410d141b222930373e",
            "6000000000182c400000000000000000000000000000000100000000000000000000000000000001110000111000000a454c535a61686f767d848b9299a0a7ae",
            "6000000000102c400000000000000000000000000000000100000000000000000000000000000001110000201000000ab5bcc3cad1d8dfe6",
        },
        .verdict_delivered = true,
        .full_dgram_hex = "ca42ca41002803410d141b222930373e454c535a61686f767d848b9299a0a7aeb5bcc3cad1d8dfe6",
    },
    .{
        .name = "overlap",
        .v6 = true,
        .ident = 0x1000000b,
        .packets_hex = &.{
            "6000000000182c400000000000000000000000000000000100000000000000000000000000000001110000011000000bca42ca410028f3300e151c232a31383f",
            "6000000000182c400000000000000000000000000000000100000000000000000000000000000001110000091000000beeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "6000000000182c400000000000000000000000000000000100000000000000000000000000000001110000111000000b464d545b626970777e858c939aa1a8af",
            "6000000000102c400000000000000000000000000000000100000000000000000000000000000001110000201000000bb6bdc4cbd2d9e0e7",
        },
        .verdict_delivered = false,
        .full_dgram_hex = "ca42ca410028f3300e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7",
    },
    .{
        .name = "overlap_same_content",
        .v6 = true,
        .ident = 0x1000000c,
        .packets_hex = &.{
            "6000000000182c400000000000000000000000000000000100000000000000000000000000000001110000011000000cca42ca410028e3200f161d242b323940",
            "6000000000182c400000000000000000000000000000000100000000000000000000000000000001110000091000000c0f161d242b323940474e555c636a7178",
            "6000000000182c400000000000000000000000000000000100000000000000000000000000000001110000111000000c474e555c636a71787f868d949ba2a9b0",
            "6000000000102c400000000000000000000000000000000100000000000000000000000000000001110000201000000cb7bec5ccd3dae1e8",
        },
        .verdict_delivered = false,
        .full_dgram_hex = "ca42ca410028e3200f161d242b323940474e555c636a71787f868d949ba2a9b0b7bec5ccd3dae1e8",
    },
};

// ── replay: real IP-level fragment shapes, re-encoded into OUR wire format ──

const FragView = struct { more: bool, offset: u16, payload: []const u8 };

/// `bytes` is one complete, real IPv4 datagram (20-byte header, no options
/// -- every capture above used a bare 5-word IHL) exactly as sent on the
/// wire. Extracts the fragment-relevant fields the same way the kernel's
/// own `ip_defrag` does: MF is bit 13 of the 16-bit flags/fragoffset word
/// (0x2000), the low 13 bits are the offset in 8-byte units.
fn parseV4(bytes: []const u8) FragView {
    std.debug.assert(bytes[0] & 0xF0 == 0x40); // IPv4
    const ihl: usize = @as(usize, bytes[0] & 0x0F) * 4;
    const flags_frag = std.mem.readInt(u16, bytes[6..8], .big);
    return .{
        .more = (flags_frag & 0x2000) != 0,
        .offset = (flags_frag & 0x1FFF) * 8,
        .payload = bytes[ihl..],
    };
}

/// `bytes` is one complete, real IPv6 datagram: a fixed 40-byte base
/// header (every capture's Next Header = 44, Fragment) immediately
/// followed by an 8-byte Fragment extension header (next-header, reserved,
/// 13-bit offset + 2 reserved bits + M flag, 32-bit identification).
fn parseV6(bytes: []const u8) FragView {
    std.debug.assert(bytes[0] & 0xF0 == 0x60); // IPv6
    std.debug.assert(bytes[6] == 44); // Next Header = Fragment
    const off_res_m = std.mem.readInt(u16, bytes[42..44], .big);
    return .{
        .more = (off_res_m & 1) != 0,
        .offset = (off_res_m >> 3) * 8,
        .payload = bytes[48..],
    };
}

/// Re-encodes one parsed real-IP fragment view into `ethfrag`'s own
/// 8-byte-header wire format (see `root.zig`'s module doc comment) so it
/// can be fed to the production `Reassembler.insert`. `buf` must be at
/// least `ethfrag.header_len + f.payload.len` bytes.
fn toOurWire(buf: []u8, frag_id: u16, f: FragView) []u8 {
    std.debug.assert(buf.len >= ethfrag.header_len + f.payload.len);
    std.mem.writeInt(u16, buf[0..2], frag_id, .big);
    std.mem.writeInt(u16, buf[2..4], f.offset, .big);
    std.mem.writeInt(u16, buf[4..6], @intCast(f.payload.len), .big);
    buf[6] = if (f.more) 1 else 0;
    buf[7] = 0;
    @memcpy(buf[ethfrag.header_len..][0..f.payload.len], f.payload);
    return buf[0 .. ethfrag.header_len + f.payload.len];
}

const OurVerdict = union(enum) {
    complete: []u8, // caller frees (same allocator as passed to replay)
    incomplete,
    rejected: anyerror,
};

/// Replays one capture's real IP-fragment shapes through a FRESH
/// `Reassembler`, re-encoded into this module's own wire format. A fresh
/// instance per capture means the constant `frag_id` used below needs no
/// relation to the real capture's IPv4/IPv6 identification field --
/// it only needs to be consistent WITHIN one capture's fragments, which it
/// is.
fn replayCapture(gpa: std.mem.Allocator, cap: Capture) !OurVerdict {
    var r = ethfrag.Reassembler.init(gpa, .{
        .max_inflight = 4,
        .timeout_ns = std.math.maxInt(u64), // never time out mid-replay
    });
    defer r.deinit();

    var raw_buf: [128]u8 = undefined;
    var wire_buf: [ethfrag.header_len + 64]u8 = undefined;
    var now: u64 = 0;
    for (cap.packets_hex) |hex| {
        const raw = (try std.fmt.hexToBytes(raw_buf[0 .. hex.len / 2], hex));
        const view = if (cap.v6) parseV6(raw) else parseV4(raw);
        const wire = toOurWire(&wire_buf, 0, view);
        const res = r.insert(wire, now) catch |err| return .{ .rejected = err };
        switch (res) {
            .incomplete => {},
            .complete => |bytes| return .{ .complete = bytes },
        }
        now += 1;
    }
    return .incomplete;
}

fn expectHexEqual(hex: []const u8, actual: []const u8) !void {
    var buf: [64]u8 = undefined;
    const expected = try std.fmt.hexToBytes(buf[0 .. hex.len / 2], hex);
    try testing.expectEqualSlices(u8, expected, actual);
}

test "kernel oracle: our Reassembler's verdict vs the real Linux kernel's IPv4/IPv6 fragment reassembly" {
    const gpa = testing.allocator;
    var divergences_seen: usize = 0;
    var matches_seen: usize = 0;
    for (captures) |cap| {
        const verdict = try replayCapture(gpa, cap);
        defer if (verdict == .complete) gpa.free(verdict.complete);

        if (std.mem.eql(u8, cap.name, "duplicate")) {
            // THE documented divergence: the kernel tolerates an exact
            // duplicate fragment (verdict_delivered == true) but this
            // module's strict RFC-5722-style policy drops the whole
            // datagram on ANY overlap, including an exact one. Assert
            // exactly that shape, not merely "not equal".
            try testing.expect(cap.verdict_delivered);
            try testing.expectEqual(OurVerdict{ .rejected = error.OverlappingFragment }, verdict);
            divergences_seen += 1;
            continue;
        }

        // Every other scenario: our verdict must MATCH the kernel's.
        matches_seen += 1;
        if (cap.verdict_delivered) {
            switch (verdict) {
                .complete => |bytes| try expectHexEqual(cap.full_dgram_hex, bytes),
                else => return error.TestUnexpectedResult, // kernel delivered, we didn't
            }
        } else {
            switch (verdict) {
                .complete => return error.TestUnexpectedResult, // kernel dropped, we delivered
                .incomplete => {}, // missing_middle: neither side ever completes
                .rejected => |err| try testing.expectEqual(error.OverlappingFragment, err), // overlap*: both reject
            }
        }
    }
    // 6 scenarios × {IPv4, IPv6} = 12 kernel-oracle-anchored comparisons: 10
    // matches (in_order, out_of_order, missing_middle, overlap,
    // overlap_same_content -- ×2 families) + 2 documented divergences
    // (duplicate ×2 families). This module's own resource-bound policies
    // (max_inflight/max_fragments_per_datagram/timeout_ns) and wire-format-
    // specific rejections (InvalidHeader/LengthMismatch/TableFull/
    // ProtocolViolation) have no kernel equivalent and are intentionally
    // NOT covered here (see this file's module doc comment) -- they are
    // covered by root.zig's self-contained adversarial tests instead.
    try testing.expectEqual(@as(usize, 2), divergences_seen);
    try testing.expectEqual(@as(usize, 10), matches_seen);
}

test "count canary: kernel-oracle-anchored captures on file" {
    try testing.expectEqual(@as(usize, 12), captures.len);
}
