// SPDX-License-Identifier: MIT

//! `procnet-demo` — an `ss(8)`-shaped socket lister built on the `procnet`
//! module, plus the two smaller tables (`-r` routes, `-N` neighbours) and the
//! device snapshot (`-s`), because those columns would otherwise ship
//! unrendered.
//!
//! **Why this is the example.** `ss -tuln` is a command every Linux user has
//! typed, so the reader has an oracle in their own terminal: run this, run
//! `ss`, compare. Everything it prints comes from `procnet` — the module owns
//! the parse, this file owns the rendering, the filtering and the CLI, which
//! is exactly the split SPEC.md describes.
//!
//! **The process column is the interesting one.** `ss -p` does not read a
//! "who owns this socket" table, because the kernel exposes none: it takes
//! each socket's inode from `/proc/net/{tcp,udp}` and hunts for a
//! `/proc/<pid>/fd/*` symlink pointing at `socket:[<inode>]`. This demo does
//! the same through `procnet.indexSocketOwners`, and the two properties worth
//! watching for are both visible in a plain unprivileged run:
//!
//!   * **The answer is partial, and that is correct.** `/proc/<pid>/fd` is
//!     `0500`, so a non-root scan sees its own processes and is refused every
//!     other user's. `ss -p` behaves identically — it leaves the process
//!     column blank for another user's socket rather than failing. `-p` here
//!     prints a footer saying how many processes were refused, so a blank
//!     column is never mistaken for "nothing owns this".
//!   * **It costs real work.** The scan is one `readlink` per open descriptor
//!     of every visible process. The index is therefore built ONCE, before
//!     the socket loop, and every socket joins against it — building it per
//!     socket would multiply the whole sweep by the number of sockets. `-p`
//!     prints what the sweep cost so the price is visible rather than
//!     asserted.
//!
//! **What it does not do**, deliberately: no `sock_diag` netlink. Real `ss`
//! asks the kernel over `NETLINK_SOCK_DIAG` first and only falls back to
//! these text files, which is why `ss` can show a few things this cannot —
//! `IPV6_V6ONLY` (the `*:port` vs `[::]:port` distinction in `ss`'s own
//! output), cgroup paths, the `sk` cookie, TCP internals from `ss -i`. None
//! of that is in `/proc/net/*` to be parsed. `procnet` is the text-file view
//! and this demo shows exactly it.
//!
//! ⚠ The one difference a reader will notice immediately when diffing this
//! against `ss -tuln`: for a LISTENING socket, `ss` prints the configured
//! backlog in Send-Q and this prints `0`. That is not a bug here — measured
//! against a `listen(3)` socket holding two un-accepted connections, `ss`
//! said `Recv-Q 2  Send-Q 3` while `/proc/net/tcp` printed
//! `00000000:00000002`: rx 2 (which this matches exactly) and tx 0. The
//! backlog is simply not in the text file; `ss` reads it over netlink.
//!
//! Built against the PUBLISHED module (`@import("procnet")`) only.

const std = @import("std");
const procnet = @import("procnet");
const netaddr = procnet.netaddr;

const Allocator = std.mem.Allocator;

const usage_text =
    \\procnet-demo -- an ss(8)-shaped view of Linux /proc, built on the `procnet` module.
    \\
    \\usage:
    \\  procnet-demo [-t] [-u] [-4] [-6] [-l | -a] [-p] [-e]   list sockets
    \\  procnet-demo -r                                        routing table (route -n)
    \\  procnet-demo -N                                        neighbour table (arp -n)
    \\  procnet-demo -s                                        device snapshot
    \\
    \\  -t            TCP only        -4  IPv4 only     -l  listening/unconnected only
    \\  -u            UDP only        -6  IPv6 only     -a  every state (default: connected)
    \\  -p            show the owning process (scans /proc/<pid>/fd; see the footer)
    \\  -e            show uid and socket inode
    \\  -h, --help    this text
    \\
    \\Addresses are always numeric: `procnet` returns typed addresses and does no
    \\name resolution, so there is no `-n` to pass and no `-r` (resolve) to avoid.
    \\
;

pub fn main(init: std.process.Init.Minimal) !u8 {
    // A `DebugAllocator` that panics on leak makes the example a leak
    // detector for the module's ownership contract (CONVENTIONS.md §7.2).
    var da: std.heap.DebugAllocator(.{}) = .init;
    defer if (da.deinit() == .leak) @panic("leak");
    const gpa = da.allocator();

    var threaded: std.Io.Threaded = .init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var args = init.args.iterate();
    _ = args.next(); // argv[0]

    const opts = parseArgs(&args) catch {
        try printOut(io, "{s}", .{usage_text});
        return 1;
    };

    return switch (opts.mode) {
        .help => blk: {
            try printOut(io, "{s}", .{usage_text});
            break :blk 0;
        },
        .sockets => runSockets(gpa, io, opts),
        .routes => runRoutes(gpa, io),
        .neighbours => runNeighbours(gpa, io),
        .snapshot => runSnapshot(gpa, io),
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// arguments
// ─────────────────────────────────────────────────────────────────────────────

const Mode = enum { help, sockets, routes, neighbours, snapshot };

/// Which states to show. Mirrors `ss`: with neither `-l` nor `-a`, `ss` shows
/// only connected sockets, which is why a bare `ss -t` on a quiet machine
/// looks empty even though the machine is listening on plenty of ports.
const StateFilter = enum { connected, unconnected, all };

const Options = struct {
    mode: Mode = .sockets,
    tcp: bool = true,
    udp: bool = true,
    v4: bool = true,
    v6: bool = true,
    states: StateFilter = .connected,
    show_process: bool = false,
    show_extended: bool = false,
};

/// Short flags cluster the way `ss`'s do — `-tuln` is one argument, and
/// typing it is the whole point of an `ss`-shaped demo, so it has to work.
/// `-n` is accepted and ignored: every address this module returns is
/// already numeric, and rejecting the flag a reader will inevitably copy
/// from their `ss` habit would be gratuitous.
fn parseArgs(args: *std.process.Args.Iterator) !Options {
    var o: Options = .{};
    var saw_proto = false;
    var saw_family = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help")) {
            o.mode = .help;
            continue;
        } else if (std.mem.eql(u8, arg, "--route")) {
            o.mode = .routes;
            continue;
        } else if (std.mem.eql(u8, arg, "--neigh")) {
            o.mode = .neighbours;
            continue;
        } else if (std.mem.eql(u8, arg, "--snapshot")) {
            o.mode = .snapshot;
            continue;
        }
        if (arg.len < 2 or arg[0] != '-') return error.BadUsage;

        for (arg[1..]) |c| switch (c) {
            'h' => o.mode = .help,
            'r' => o.mode = .routes,
            'N' => o.mode = .neighbours,
            's' => o.mode = .snapshot,
            't', 'u' => {
                if (!saw_proto) {
                    o.tcp = false;
                    o.udp = false;
                    saw_proto = true;
                }
                if (c == 't') o.tcp = true else o.udp = true;
            },
            '4', '6' => {
                if (!saw_family) {
                    o.v4 = false;
                    o.v6 = false;
                    saw_family = true;
                }
                if (c == '4') o.v4 = true else o.v6 = true;
            },
            'l' => o.states = .unconnected,
            'a' => o.states = .all,
            'p' => o.show_process = true,
            'e' => o.show_extended = true,
            'n' => {}, // always numeric; accepted for muscle memory
            else => return error.BadUsage,
        };
    }
    return o;
}

// ─────────────────────────────────────────────────────────────────────────────
// sockets — the `ss -tuln` view
// ─────────────────────────────────────────────────────────────────────────────

fn runSockets(gpa: Allocator, io: std.Io, opts: Options) !u8 {
    const socks = try procnet.readSockets(gpa, io);
    defer gpa.free(socks);

    // ⚠ Build the owner index ONCE, outside the loop. It is an O(processes ×
    // descriptors) sweep of /proc; doing it per socket would make the whole
    // listing quadratic in the size of the machine.
    var owners: ?procnet.SocketOwnerIndex = null;
    var sweep_ns: u64 = 0;
    if (opts.show_process) {
        const t0 = now();
        owners = try procnet.indexSocketOwners(gpa, io, .{});
        sweep_ns = now() -| t0;
    }
    defer if (owners) |idx| idx.deinit(gpa);

    var buf: [8192]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;

    try out.print("{s:<5} {s:<7} {s:>6} {s:>6} {s:>34} {s:<22}", .{
        "Netid", "State", "Recv-Q", "Send-Q", "Local Address:Port", "Peer Address:Port",
    });
    if (opts.show_extended) try out.print(" {s:<20}", .{"uid/inode"});
    if (opts.show_process) try out.print(" {s}", .{"Process"});
    try out.writeAll("\n");

    var shown: usize = 0;
    for (socks) |s| {
        if (!wanted(s, opts)) continue;
        shown += 1;

        var local_buf: [64]u8 = undefined;
        var peer_buf: [64]u8 = undefined;

        try out.print("{s:<5} {s:<7} {d:>6} {d:>6} {s:>34} {s:<22}", .{
            switch (s.proto) {
                .tcp => "tcp",
                .udp => "udp",
            },
            stateName(s.state),
            s.rx_queue,
            s.tx_queue,
            formatEndpoint(&local_buf, s.local, s.local_port, false),
            formatEndpoint(&peer_buf, s.remote, s.remote_port, true),
        });

        if (opts.show_extended) {
            var ex_buf: [40]u8 = undefined;
            const ex = std.fmt.bufPrint(&ex_buf, "uid:{d} ino:{d}", .{ s.uid, s.inode }) catch "uid:? ino:?";
            try out.print(" {s:<20}", .{ex});
        }

        if (owners) |idx| {
            const holders = idx.findAll(s.inode);
            if (holders.len == 0) {
                // Blank, exactly as `ss -p` leaves it: either nothing holds
                // this socket (inode 0 — an orphan) or its holder belongs to
                // another uid. The footer says how many of the latter there
                // were.
                try out.writeAll(" ");
            } else {
                try out.writeAll(" users:(");
                for (holders, 0..) |h, i| {
                    if (i > 0) try out.writeAll(",");
                    try out.print("(\"{s}\",pid={d},fd={d})", .{ h.name(), h.pid, h.fd });
                }
                try out.writeAll(")");
            }
        }
        try out.writeAll("\n");
    }

    if (owners) |idx| {
        try out.print(
            \\
            \\-- process join: {d} sockets shown; scanned {d} processes ({d} descriptors matched a socket) in {d} ms.
            \\   {d} processes refused: /proc/<pid>/fd is 0500, so an unprivileged scan cannot see another user's
            \\   descriptors. Their sockets are still LISTED above (the kernel's socket table is world-readable) --
            \\   only the Process column is blank for them. `ss -p` does exactly the same, silently.
            \\
        , .{ shown, idx.scanned, idx.owners.len, sweep_ns / std.time.ns_per_ms, idx.denied });
        if (idx.vanished > 0)
            try out.print("   {d} processes exited mid-scan (/proc races by construction; not an error).\n", .{idx.vanished});
        if (idx.truncated)
            try out.writeAll("   ⚠ the sweep hit its own cap and is INCOMPLETE.\n");
    }

    try out.flush();
    return 0;
}

fn wanted(s: procnet.SocketEntry, opts: Options) bool {
    switch (s.proto) {
        .tcp => if (!opts.tcp) return false,
        .udp => if (!opts.udp) return false,
    }
    switch (s.local) {
        .v4 => if (!opts.v4) return false,
        .v6 => if (!opts.v6) return false,
    }
    // `.close` is the kernel's TCP_CLOSE, which UDP reuses for
    // "bound but not connected" — `ss` calls both UNCONN.
    const connected = s.state != .listen and s.state != .close;
    return switch (opts.states) {
        .all => true,
        .connected => connected,
        .unconnected => !connected,
    };
}

/// `ss`'s own state words, from its manual page's STATE-FILTER list and its
/// output (`ESTAB`, not `ESTABLISHED`; `UNCONN` for both TCP_CLOSE and a
/// bound UDP socket). An unrecognized code prints its raw hex rather than
/// being dropped, matching `SockState` being a non-exhaustive enum.
fn stateName(st: procnet.SockState) []const u8 {
    return switch (st) {
        .established => "ESTAB",
        .syn_sent => "SYN-SENT",
        .syn_recv => "SYN-RECV",
        .fin_wait1 => "FIN-WAIT-1",
        .fin_wait2 => "FIN-WAIT-2",
        .time_wait => "TIME-WAIT",
        .close => "UNCONN",
        .close_wait => "CLOSE-WAIT",
        .last_ack => "LAST-ACK",
        .listen => "LISTEN",
        .closing => "CLOSING",
        .new_syn_recv => "NEW-SYN-RECV",
        _ => "UNKNOWN",
    };
}

/// `address:port`, `ss`-style: IPv6 bracketed, and a zero port rendered `*`.
///
/// `wildcard_port` is set for the peer column only. `ss` prints a listening
/// socket's peer as `0.0.0.0:*` / `[::]:*` — the address as the kernel gave
/// it, the port as a star — and the star is genuinely a rendering choice, not
/// data: the kernel prints a peer port of `0000` and that IS the value.
fn formatEndpoint(buf: []u8, ip: netaddr.Ip, port: u16, wildcard_port: bool) []const u8 {
    var ip_buf: [netaddr.max_ip_text_len]u8 = undefined;
    const ip_text = netaddr.formatIp(ip, &ip_buf);
    const bracket = ip == .v6;

    const open = if (bracket) "[" else "";
    const close = if (bracket) "]" else "";
    if (wildcard_port and port == 0) {
        return std.fmt.bufPrint(buf, "{s}{s}{s}:*", .{ open, ip_text, close }) catch "?";
    }
    return std.fmt.bufPrint(buf, "{s}{s}{s}:{d}", .{ open, ip_text, close, port }) catch "?";
}

// ─────────────────────────────────────────────────────────────────────────────
// the smaller tables
// ─────────────────────────────────────────────────────────────────────────────

fn runRoutes(gpa: Allocator, io: std.Io) !u8 {
    const routes = try procnet.readRoutes(gpa, io);
    defer gpa.free(routes);

    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;

    try out.print("{s:<20} {s:<16} {s:<8} {s:>6} {s}\n", .{ "Destination", "Gateway", "Flags", "Metric", "Iface" });
    for (routes) |r| {
        var dest_buf: [netaddr.max_prefix_text_len]u8 = undefined;
        var gw_buf: [netaddr.max_ip_text_len]u8 = undefined;
        var flag_buf: [8]u8 = undefined;

        try out.print("{s:<20} {s:<16} {s:<8} {d:>6} {s}\n", .{
            netaddr.formatPrefix(r.dest, &dest_buf),
            if (r.gateway) |g| netaddr.formatIp(g, &gw_buf) else "-",
            routeFlags(&flag_buf, r.flags),
            r.metric,
            r.iface(),
        });
    }
    try out.flush();
    return 0;
}

/// `route -n`'s Flags letters, from `route(8)`: `U` up, `G` gateway, `H`
/// host, `D` dynamic, `M` modified. This is the whole reason `RouteEntry`
/// carries the raw `RTF_*` word — the letters are a rendering of it, and a
/// caller that wanted to act on `RTF_UP` needs the bits, not the letters.
fn routeFlags(buf: []u8, flags: u16) []const u8 {
    var n: usize = 0;
    if (flags & 0x0001 != 0) {
        buf[n] = 'U';
        n += 1;
    }
    if (flags & 0x0002 != 0) {
        buf[n] = 'G';
        n += 1;
    }
    if (flags & 0x0004 != 0) {
        buf[n] = 'H';
        n += 1;
    }
    if (flags & 0x0010 != 0) {
        buf[n] = 'D';
        n += 1;
    }
    if (flags & 0x0020 != 0) {
        buf[n] = 'M';
        n += 1;
    }
    if (n == 0) {
        buf[n] = '-';
        n += 1;
    }
    return buf[0..n];
}

fn runNeighbours(gpa: Allocator, io: std.Io) !u8 {
    const neighbours = try procnet.readArp(gpa, io);
    defer gpa.free(neighbours);

    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;

    try out.print("{s:<18} {s:<10} {s:<20} {s}\n", .{ "Address", "HWtype", "HWaddress", "Iface" });
    for (neighbours) |n| {
        var ip_buf: [netaddr.max_ip_text_len]u8 = undefined;
        try out.print("{s:<18} {s:<10} {x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2} {s:<3} {s}\n", .{
            netaddr.formatIp(n.ip, &ip_buf),
            // `arp -n` prints the hardware type as a name; 0x1 is the only
            // one whose addresses fit `ArpEntry.mac`, so anything else is
            // shown raw rather than guessed at.
            if (n.hw_type == 0x1) "ether" else "other",
            n.mac[0],
            n.mac[1],
            n.mac[2],
            n.mac[3],
            n.mac[4],
            n.mac[5],
            // ATF_COM (0x2) is the kernel's "this entry is complete"; an
            // incomplete entry prints an all-zero MAC that means "unknown",
            // not "00:00:00:00:00:00".
            if (n.flags & 0x2 != 0) "C" else "I",
            n.device(),
        });
    }
    try out.flush();
    return 0;
}

fn runSnapshot(gpa: Allocator, io: std.Io) !u8 {
    var snap = try procnet.snapshot(gpa, io);
    defer snap.deinit(gpa);

    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;

    try out.print("uptime   {d} s\n", .{snap.uptime_s});
    try out.print("load     {d:.2} {d:.2} {d:.2}\n", .{ snap.load[0], snap.load[1], snap.load[2] });
    try out.print("memory   {d} kB total, {d} kB free, {d} kB available\n", .{
        snap.mem_total_kb, snap.mem_free_kb, snap.mem_available_kb,
    });
    if (snap.thermal_c) |t| {
        try out.print("thermal  {d:.1} C hottest of {d} zone(s)\n", .{ t, snap.thermal_zones.len });
        for (snap.thermal_zones) |z| try out.print("         {s:<16} {s:<16} {d:.1} C\n", .{ z.zone(), z.kind(), z.temp_c });
    } else {
        try out.writeAll("thermal  (no zones exposed)\n");
    }
    if (snap.conntrack) |c| {
        try out.print("conntrack {d} of {d}\n", .{ c.count, c.max });
    } else {
        try out.writeAll("conntrack (module not loaded)\n");
    }
    try out.flush();
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// small helpers
// ─────────────────────────────────────────────────────────────────────────────

fn printOut(io: std.Io, comptime fmt: []const u8, args: anytype) !void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    try w.interface.print(fmt, args);
    try w.interface.flush();
}

/// A monotonic nanosecond reading, used only to price the `/proc/<pid>/fd`
/// sweep. `CLOCK_MONOTONIC` because the number is a duration, not a date.
fn now() u64 {
    var ts: std.os.linux.timespec = undefined;
    if (std.os.linux.clock_gettime(.MONOTONIC, &ts) != 0) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}
