// SPDX-License-Identifier: MIT

//! What a real-Ethernet SPB edge bridge does with `pbb`: encapsulate a real
//! customer Ethernet frame (its own 802.1Q C-VLAN tag + an IPv4 payload)
//! under a B-Tagged backbone header, send it, decode it back on the far
//! side and recover every field including the customer bytes, do it again
//! for a second, differently-shaped frame (untagged backbone, a different
//! I-SID tenant), and reject a truncated / wrong-EtherType / over-long
//! frame by NAMED error rather than a blanket catch.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). `pbb`
//! declares no deps at all (std only).
//!
//! **Allocation note.** `pbb.decode` allocates nothing by construction (the
//! customer bytes come back as a subslice of the input). The only allocating
//! function is `encodeAlloc`, and its one error (`FrameTooLarge`) is checked
//! *before* the allocation happens — encoding a doomed frame must not first
//! spend an allocation on it. So there is no "allocates, then fails" path
//! anywhere in this module's public surface; the failure-path checks below
//! (`Truncated`, `UnexpectedEtherType`, `BufferTooSmall`, `FrameTooLarge`)
//! are all zero-allocation by design, and that is worth stating explicitly
//! rather than leaving the omission looking like an oversight.

const std = @import("std");
const pbb = @import("pbb");

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    // ── run 1: a B-Tagged backbone frame carrying a tagged customer frame ────
    {
        const fields: pbb.Fields = .{
            .b_da = .{ 0x00, 0x1b, 0x21, 0x00, 0x00, 0x01 },
            .b_sa = .{ 0x00, 0x1b, 0x21, 0x00, 0x00, 0x02 },
            .b_tag = .{ .pcp = 2, .dei = false, .vid = 200 },
            .i_pcp = 4,
            .i_dei = false,
            .uca = true,
            .i_sid = 0x00_1000, // tenant 4096
            .c_da = .{ 0x00, 0x50, 0x56, 0x00, 0x00, 0x01 },
            .c_sa = .{ 0x00, 0x50, 0x56, 0x00, 0x00, 0x02 },
        };
        // The customer frame's OWN 802.1Q C-VLAN tag (VID=10) + IPv4 ethertype,
        // then a few opaque payload bytes — everything after the customer's own
        // DA/SA, which `pbb` relocates into the I-TAG (see the module doc).
        const customer_data = [_]u8{
            0x81, 0x00, 0x00, 0x0a, 0x08, 0x00, // C-VLAN(10) + IPv4 ethertype
            0x41, 0x42, 0x43, 0x44, // opaque payload
        };

        const wire = try pbb.encodeAlloc(gpa, fields, &customer_data);
        defer gpa.free(wire);
        std.debug.assert(wire.len == pbb.headerLen(true) + customer_data.len);

        const dec = try pbb.decode(wire);
        std.debug.assert(std.meta.eql(fields, dec.fields));
        std.debug.assert(std.mem.eql(u8, &customer_data, dec.customer_data));
        std.debug.assert(dec.fields.bvid().? == 200);
        std.debug.assert(dec.fields.hasBTag());
        std.debug.print("run 1 (B-Tagged, I-SID 0x1000): encode/decode round-trips every field\n", .{});
    }

    // ── run 2: a second, differently-shaped frame — untagged backbone, a
    // different tenant, no customer payload. A distinct topology/dataset from
    // run 1 in the same process, so any state pbb held between calls (it
    // holds none, by design) would show up as a leak or stale field here. ────
    {
        const fields: pbb.Fields = .{
            .b_da = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 },
            .b_sa = .{ 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 },
            .b_tag = null, // untagged on the B-VLAN this time
            .i_pcp = 0,
            .i_dei = false,
            .uca = false,
            .i_sid = 0x00_ABCD, // a different tenant
            .c_da = .{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
            .c_sa = .{ 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F },
        };
        const wire = try pbb.encodeAlloc(gpa, fields, "");
        defer gpa.free(wire);
        std.debug.assert(wire.len == pbb.min_frame_len);

        const dec = try pbb.decode(wire);
        std.debug.assert(std.meta.eql(fields, dec.fields));
        std.debug.assert(dec.customer_data.len == 0);
        std.debug.assert(dec.fields.bvid() == null);
        std.debug.assert(!dec.fields.hasBTag());
        std.debug.assert(dec.fields.i_sid != 0x00_1000); // distinct from run 1's tenant
        std.debug.print("run 2 (untagged, I-SID 0xABCD): encode/decode round-trips every field\n", .{});
    }

    // ── negative: a truncated frame is rejected by name, not a panic ─────────
    // (A truncated frame must still carry a valid tag-region EtherType at the
    // point the cut lands after, or the wrong-EtherType check fires first —
    // so this truncates a REAL encoded frame, not arbitrary bytes.)
    {
        const fields: pbb.Fields = .{
            .b_da = @splat(0x11),
            .b_sa = @splat(0x22),
            .b_tag = null,
            .i_pcp = 0,
            .i_dei = false,
            .uca = false,
            .i_sid = 0x12_3456,
            .c_da = @splat(0x33),
            .c_sa = @splat(0x44),
        };
        var buf: [pbb.min_frame_len]u8 = undefined;
        const full = try pbb.encode(fields, "", &buf);
        const wire = full[0 .. full.len - 1]; // one byte short
        if (pbb.decode(wire)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.Truncated => std.debug.print("truncated frame: Truncated (expected)\n", .{}),
            else => return err,
        }
    }

    // ── negative: a tag-region EtherType that is neither B-Tag nor I-TAG ─────
    {
        var wire: [pbb.min_frame_len]u8 = @splat(0);
        std.mem.writeInt(u16, wire[pbb.b_mac_len..][0..2], 0x0800, .big); // plain IPv4 ethertype
        if (pbb.decode(&wire)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.UnexpectedEtherType => std.debug.print("wrong tag-region EtherType: UnexpectedEtherType (expected)\n", .{}),
            else => return err,
        }
    }

    // ── negative: a B-Tag not followed by the I-TAG EtherType ────────────────
    {
        var wire: [pbb.min_frame_len + pbb.b_tag_len]u8 = @splat(0);
        std.mem.writeInt(u16, wire[pbb.b_mac_len..][0..2], pbb.b_tpid, .big); // B-Tag TPID
        // Whatever follows the B-Tag here is left zero — not the I-TAG ethertype.
        if (pbb.decode(&wire)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.MissingITag => std.debug.print("B-Tag without I-TAG: MissingITag (expected)\n", .{}),
            else => return err,
        }
    }

    // ── negative: caller's output buffer is smaller than the encoded frame ───
    {
        const fields: pbb.Fields = .{
            .b_da = @splat(0xAA),
            .b_sa = @splat(0xBB),
            .b_tag = null,
            .i_pcp = 0,
            .i_dei = false,
            .uca = false,
            .i_sid = 1,
            .c_da = @splat(0),
            .c_sa = @splat(0),
        };
        var too_small: [pbb.min_frame_len - 1]u8 = undefined;
        if (pbb.encode(fields, "", &too_small)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.BufferTooSmall => std.debug.print("undersized output buffer: BufferTooSmall (expected)\n", .{}),
            else => return err,
        }
    }

    // ── negative: an over-long header — a frame past max_frame_len is rejected
    // by name, zero-allocation (the check runs before any write/alloc) ───────
    {
        const fields: pbb.Fields = .{
            .b_da = @splat(0x11),
            .b_sa = @splat(0x22),
            .b_tag = null,
            .i_pcp = 0,
            .i_dei = false,
            .uca = false,
            .i_sid = 1,
            .c_da = @splat(0x33),
            .c_sa = @splat(0x44),
        };
        // headerLen(false) + this exceeds max_frame_len (65535) by one byte.
        var oversized_data: [pbb.max_frame_len - pbb.headerLen(false) + 1]u8 = undefined;
        var out: [16]u8 = undefined; // deliberately far too small — FrameTooLarge
        // must fire before BufferTooSmall would even be checked.
        if (pbb.encode(fields, &oversized_data, &out)) |_| {
            unreachable;
        } else |err| switch (err) {
            error.FrameTooLarge => std.debug.print("over-long header: FrameTooLarge (expected)\n", .{}),
            else => return err,
        }
    }
}
