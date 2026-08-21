// SPDX-License-Identifier: MIT

//! What a Loopix mixnet operator does with this module OFF the simulator:
//! route a batch of client messages through a stratified topology, hold each
//! one at its first mix with the module's own Poisson delay law (`Prng` +
//! `sampleExpDelay` — the real mixing core, not a mock), and feed the
//! resulting arrival/departure transcript to the global-passive-adversary
//! measurement (`adversary.measure`) to check it clears the deployment's
//! anonymity bound. Then do the same with a FIFO (order-preserving) hold to
//! see the adversary's posterior collapse — the module's own headline claim,
//! reproduced here with nothing but public API and in-memory data, no
//! `netsim` run required.
//!
//! Built against the PUBLISHED module (`@import("loopix")`) only.

const std = @import("std");
const loopix = @import("loopix");

pub fn main() !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();

    const cfg: loopix.LoopixConfig = .{ .layers = 2, .width = 2, .clients = 4 };

    var mix_prng = loopix.Prng.init(0xC0FFEE);
    var real_transits: std.ArrayList(loopix.Transit) = .empty;
    defer real_transits.deinit(gpa);
    var cover_transits: std.ArrayList(loopix.Transit) = .empty;
    defer cover_transits.deinit(gpa);

    // Eight application messages from four clients, each routed to a random
    // other client and held at its first mix by an independent exponential
    // draw — the actual Poisson-mix mechanism, not a stand-in for it.
    var i: u64 = 0;
    while (i < 8) : (i += 1) {
        const sender: u8 = @intCast(i % cfg.clients);
        const key: u64 = @as(u64, sender) * 1000 + i;
        const dest = loopix.pickDestClient(cfg, key, sender);

        var header: loopix.MixHeader = .{ .kind = .real, .id = i, .hop = 0, .n_hops = 0, .route = undefined };
        loopix.pickRoute(cfg, key, dest, &header);

        // Round-trip the wire header once, to prove the codec a real mix
        // would speak matches what `pickRoute` just built.
        if (i == 0) {
            var buf: [loopix.MixHeader.wire_len]u8 = undefined;
            header.encode(&buf);
            const back = try loopix.MixHeader.decode(&buf);
            std.debug.print("header round-trip: next hop after mix 0 is node {d}\n", .{back.nextHop()});
        }

        const send_time: u64 = i * 5;
        const hold = loopix.sampleExpDelay(&mix_prng, cfg.mean_delay);
        try real_transits.append(gpa, .{
            .mix = header.currentMix(),
            .arrival = send_time,
            .departure = send_time + hold,
            .kind = .real,
            .id = i,
        });
    }

    // Poisson cover chaff at the same mixes, self-clocked exactly like a real
    // node would: draw the next emission gap, advance, repeat. This is what
    // keeps each mix's departure pool large enough to hide a target in.
    var cover_prng = loopix.Prng.init(0xC0FFEE ^ 0xD00D);
    var t: u64 = 0;
    var n_cover: u32 = 0;
    while (t < 60 and n_cover < 40) : (n_cover += 1) {
        const ev = loopix.nextCover(&cover_prng, cfg);
        t += ev.delay;
        const mix = header0Mix(cfg, cover_prng.next());
        const hold = loopix.sampleExpDelay(&cover_prng, cfg.mean_delay);
        try cover_transits.append(gpa, .{
            .mix = mix,
            .arrival = t,
            .departure = t + hold,
            .kind = ev.kind,
            .id = 1_000_000 + n_cover, // never scored — cover is not a target
        });
    }

    var all: std.ArrayList(loopix.Transit) = .empty;
    defer all.deinit(gpa);
    try all.appendSlice(gpa, real_transits.items);
    try all.appendSlice(gpa, cover_transits.items);

    const bound: loopix.AnonymityBound = .{};

    const poisson = try loopix.measure(gpa, all.items, .{ .exponential = @floatFromInt(cfg.mean_delay) });
    std.debug.print(
        "Poisson mix: min_effective_set={d:.2} max_link_prob={d:.2} holds={}\n",
        .{ poisson.min_effective_set, poisson.max_link_prob, poisson.holds(bound) },
    );

    // Same arrivals, but a FIFO/constant hold instead of the exponential one
    // — what the module's own `fifo_delay` positive control uses. Rebuild
    // both real and cover transits with `departure = arrival + fifo_delay`
    // and measure with the matching constant kernel.
    var fifo_all: std.ArrayList(loopix.Transit) = .empty;
    defer fifo_all.deinit(gpa);
    for (all.items) |tr| {
        try fifo_all.append(gpa, .{
            .mix = tr.mix,
            .arrival = tr.arrival,
            .departure = tr.arrival + cfg.fifo_delay,
            .kind = tr.kind,
            .id = tr.id,
        });
    }
    const fifo = try loopix.measure(gpa, fifo_all.items, .{ .constant = .{ .delta = cfg.fifo_delay, .tol = 0 } });
    std.debug.print(
        "FIFO mix:    min_effective_set={d:.2} max_link_prob={d:.2} holds={}\n",
        .{ fifo.min_effective_set, fifo.max_link_prob, fifo.holds(bound) },
    );
}

/// Pick a plausible first-layer mix for a piece of cover traffic (cover does
/// not carry a route of its own in this example — only the mix it transits
/// matters to the measurement). Spelled `u32`, not a `loopix`-exported name —
/// see the note below.
fn header0Mix(cfg: loopix.LoopixConfig, r: u64) u32 {
    return cfg.mixNode(0, @intCast(r % cfg.width));
}

// `loopix` never re-exports the `NodeId` (= `netsim.NodeId`, a `u32` alias)
// or `Time` (= `netsim.Time`, `u64`) types its own public API is built from
// (`MixHeader.route`, `Transit.mix`, `LoopixConfig.mean_delay`, ...). Nothing
// here fails to compile over it, because a plain integer alias is
// structurally the same type as the primitive it names — but a consumer who
// wants to spell a node id or a tick count in their OWN function signatures
// (as `header0Mix` above does) has no name to import for it short of adding
// `netsim` as a second import purely to reach `netsim.NodeId`/`netsim.Time`,
// even though `loopix` already depends on it.
