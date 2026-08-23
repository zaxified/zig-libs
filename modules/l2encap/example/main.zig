// SPDX-License-Identifier: MIT

//! What a PE (provider edge) on an L2-over-WireGuard fabric does with
//! `l2encap`: encapsulate a real Ethernet II frame (802.1Q-tagged, the way a
//! customer VLAN trunk actually looks on the wire) as both a unicast and a
//! broadcast (BUM) tenant frame, relay the BUM frame across three hops the
//! way a real core does — decrementing TTL and re-checking split-horizon at
//! every hop — and confirm the one case the split-horizon predicate DOES
//! catch (a reflection back to its own originator) fires while the TTL
//! backstop still bounds an unbounded relay. Then feed `decode` every
//! malformed-header shape an untrusted or buggy tunnel peer can hand it:
//! truncated below the 8-byte header, wrong version, a dirty reserved flag
//! bit, and an over-cap frame.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export).

const std = @import("std");
const l2encap = @import("l2encap");

/// A real Ethernet II frame, 802.1Q-tagged: dst MAC, src MAC, an 0x8100 TPID
/// + VLAN tag (PCP=0, DEI=0, VID=100), the real ethertype (IPv4, 0x0800)
/// behind the tag, then a stand-in IPv4 payload. `l2encap` never looks inside
/// this — it is carried as opaque bytes — but a realistic customer frame is
/// what actually rides a fabric, not an arbitrary byte string.
const customer_frame_v4 = [_]u8{
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC: broadcast
    0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // src MAC
    0x81, 0x00, // 802.1Q TPID
    0x00, 0x64, // PCP=0 DEI=0 VID=100
    0x08, 0x00, // ethertype: IPv4
    0x45, 0x00, 0x00, 0x14, // stand-in IPv4 header bytes
} ++ ("customer payload".*);

pub fn main() !void {
    // A DebugAllocator that panics on leak makes this example a leak
    // detector for `encodeAlloc`'s ownership contract (CONVENTIONS.md §7.2).
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── encode a real tagged Ethernet frame as a BUM (broadcast) tenant frame ──
    const pe_a: u16 = 1; // ingress PE: originates this BUM frame
    const pe_b: u16 = 2; // core hop 1
    const pe_c: u16 = 3; // core hop 2

    std.debug.assert(l2encap.looksLikeEthernet(&customer_frame_v4));

    const bum_fields: l2encap.Fields = .{
        .isid = 0x00_10_20, // tenant 0x1020
        .ttl = l2encap.default_ttl,
        .bum = true,
        .ingress_pe = pe_a,
    };
    const wire = try l2encap.encodeAlloc(gpa, bum_fields, &customer_frame_v4);
    defer gpa.free(wire);
    std.debug.assert(wire.len == l2encap.encodedLen(customer_frame_v4.len));

    var dec = try l2encap.decode(wire);
    std.debug.assert(dec.fields.isid == 0x00_10_20);
    std.debug.assert(dec.fields.bum);
    std.debug.assert(std.mem.eql(u8, dec.payload, &customer_frame_v4));
    std.debug.assert(l2encap.looksLikeEthernet(dec.payload));
    std.debug.print("encapsulated a real 802.1Q Ethernet frame as a BUM tenant frame, decoded intact\n", .{});

    // ── relay the BUM frame across three PE hops, the way a real core does ──
    // At each hop: split-horizon is checked first (a real PE would drop and
    // stop here), then TTL is decremented before the frame goes onward.
    std.debug.assert(!l2encap.droppedBySplitHorizon(dec.fields, pe_b));
    dec.fields = try l2encap.decrementTtl(dec.fields);
    std.debug.assert(dec.fields.ttl == l2encap.default_ttl - 1);
    std.debug.assert(dec.fields.ingress_pe == pe_a); // originator preserved, not the relayer

    std.debug.assert(!l2encap.droppedBySplitHorizon(dec.fields, pe_c));
    dec.fields = try l2encap.decrementTtl(dec.fields);
    std.debug.assert(dec.fields.ttl == l2encap.default_ttl - 2);

    // The one case split-horizon DOES own: the frame reflected back to its
    // own originator, however many hops it took to get there.
    std.debug.assert(l2encap.droppedBySplitHorizon(dec.fields, pe_a));
    std.debug.print("relayed across 2 core hops: split-horizon silent en route, fires on reflection to origin PE {d}\n", .{pe_a});

    // ── TTL backstop: drive it all the way to expiry, under pressure ───────
    var f: l2encap.Fields = .{ .isid = 1, .ttl = 3, .bum = false, .ingress_pe = 7 };
    var hops: usize = 0;
    while (l2encap.decrementTtl(f)) |next| {
        f = next;
        hops += 1;
    } else |err| switch (err) {
        error.TtlExpired => std.debug.print("TTL backstop: dropped after {d} hops (expected)\n", .{hops}),
    }
    std.debug.assert(hops == 3);

    // ── the unicast twin, through the caller-buffer (non-allocating) form ──
    {
        var buf: [l2encap.header_len + customer_frame_v4.len]u8 = undefined;
        const uni_fields: l2encap.Fields = .{ .isid = 0x00_10_20, .ttl = 32, .bum = false, .ingress_pe = pe_a };
        const out = try l2encap.encode(uni_fields, &customer_frame_v4, &buf);
        const udec = try l2encap.decode(out);
        std.debug.assert(!udec.fields.bum);
        std.debug.assert(!l2encap.droppedBySplitHorizon(udec.fields, pe_a)); // unicast: never split-horizon-dropped
        std.debug.print("unicast twin: caller-buffer encode round-trips, split-horizon never touches it\n", .{});
    }

    // ── malformed headers: every shape an untrusted tunnel peer can hand us ──

    // Truncated below the 8-byte header — a peer that died mid-write, or a
    // torn read off a lossy transport.
    {
        const short = wire[0 .. l2encap.header_len - 1];
        if (l2encap.decode(short)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.Truncated => std.debug.print("7-byte header: Truncated (expected)\n", .{}),
            else => return err,
        }
    }

    // Wrong version — a future/foreign encapsulation this build must not
    // best-effort-parse under the wrong layout.
    {
        var bad = wire[0..l2encap.header_len].*;
        bad[0] = 0x02;
        if (l2encap.decode(&bad)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.UnsupportedVersion => std.debug.print("version 2 (unknown): UnsupportedVersion (expected)\n", .{}),
            else => return err,
        }
    }

    // A dirty reserved flag bit — rejected, never silently masked (closes a
    // covert channel).
    {
        var bad = wire[0..l2encap.header_len].*;
        bad[1] |= 0b0100_0000; // set a reserved bit alongside the real bum bit
        if (l2encap.decode(&bad)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.InvalidHeader => std.debug.print("reserved flag bit set: InvalidHeader (expected)\n", .{}),
            else => return err,
        }
    }

    // Over the frame cap — decode rejects before touching a single field.
    {
        const huge = try gpa.alloc(u8, l2encap.max_frame_len + 1);
        defer gpa.free(huge);
        @memset(huge, 0);
        huge[0] = l2encap.version_current; // otherwise-valid header; only the length is the fault
        if (l2encap.decode(huge)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.FrameTooLarge => std.debug.print("{d}-byte frame (cap {d}): FrameTooLarge (expected)\n", .{ huge.len, l2encap.max_frame_len }),
            else => return err,
        }
    }

    // Encode side: the caller's buffer is too small — must reject, and must
    // never partially write into it.
    {
        var too_small: [4]u8 = @splat(0xAA);
        const f2: l2encap.Fields = .{ .isid = 1, .ttl = 1, .bum = false, .ingress_pe = 1 };
        if (l2encap.encode(f2, "xy", &too_small)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.BufferTooSmall => {
                std.debug.assert(std.mem.allEqual(u8, &too_small, 0xAA)); // nothing written
                std.debug.print("4-byte output buffer for an 8+2-byte frame: BufferTooSmall, untouched (expected)\n", .{});
            },
            else => return err,
        }
    }
}
