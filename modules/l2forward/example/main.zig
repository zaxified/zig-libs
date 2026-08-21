// SPDX-License-Identifier: MIT

//! What a provider-edge (PE) forwarding loop does with `l2forward`: provision
//! a tenant, learn a customer MAC off an access-circuit frame, forward a
//! known unicast, forward a BUM frame from the core (must stay local — the
//! full-mesh split-horizon rule), and react to a MAC move that trips
//! duplicate-MAC detection.
//!
//! This is an example in the gate sense — it is built by
//! `zig build check-examples` against the PUBLISHED module (`deps` only, no
//! `test_deps`, no access to anything the module does not export). If a type
//! needed to call the API is not public, or an error cannot be named from
//! outside, this file stops compiling.

const std = @import("std");
const l2forward = @import("l2forward");

fn mac(last: u8) l2forward.Mac {
    return .{ 0x02, 0, 0, 0, 0, last }; // locally-administered, unicast (I/G=0)
}

pub fn main() !void {
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var table = l2forward.Table.init(gpa, .{
        .max_macs_per_isid = 8,
        .aging_ticks = 100,
        .max_mac_moves = 2,
        .mac_move_window = 50,
    });
    defer table.deinit();

    const isid: l2forward.Isid = 42; // one tenant's I-SID
    try table.addIsid(isid); // control-plane provisioning, before any traffic
    try table.addMember(isid, 2);
    try table.addMember(isid, 5);

    const station = mac(0xAA);
    var out: [16]l2forward.PeId = undefined;

    // A data-plane frame for an I-SID nobody configured is refused by name,
    // not allocated — a received frame can never spend the tenant budget.
    _ = table.learn(999, station, 2, 0) catch |err| switch (err) {
        error.UnknownIsid => std.debug.print("refused frame for unconfigured I-SID 999\n", .{}),
        else => return err,
    };

    // Learn the station off an access frame, then forward a known unicast.
    const outcome = try table.learn(isid, station, 2, 0);
    std.debug.print("learn outcome: {s}\n", .{@tagName(outcome)});
    const d1 = try table.forward(isid, station, .access, 0, &out);
    std.debug.print("known unicast -> {any}\n", .{d1});

    // An unknown MAC from an access circuit floods every member, ascending.
    const d2 = try table.forward(isid, mac(0xBB), .access, 0, &out);
    std.debug.print("unknown unicast -> {any}\n", .{d2});

    // A BUM frame arriving from the core must never re-enter the fabric.
    const d3 = try table.forward(isid, l2forward.broadcast, .{ .core = 5 }, 0, &out);
    std.debug.print("core BUM -> {any} (split horizon: nothing re-enters the fabric)\n", .{d3});

    // A hostile flap: the station's MAC moves twice inside the window, which
    // trips RFC 7432 duplicate-MAC detection and quarantines it — the caller
    // hears about this by name, not as a silent rebind.
    _ = try table.learn(isid, station, 5, 5); // move 1: PE 2 -> PE 5
    const flap = try table.learn(isid, station, 2, 10); // move 2: PE 5 -> PE 2
    switch (flap) {
        .duplicate_detected => std.debug.print("MAC {x} quarantined after {d} moves\n", .{ station, table.moveCount(isid, station) }),
        else => std.debug.print("learn outcome: {s}\n", .{@tagName(flap)}),
    }
    std.debug.print("quarantined: {}\n", .{table.isQuarantined(isid, station)});

    // A quarantined MAC floods rather than being unicast to whoever won the
    // last race — the module's own answer to "who do I trust now?".
    const d4 = try table.forward(isid, station, .access, 10, &out);
    std.debug.print("quarantined MAC forwards as -> {any}\n", .{d4});
}
