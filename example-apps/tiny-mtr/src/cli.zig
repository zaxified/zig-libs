//! The command line, mtr's letters where it has them.
const std = @import("std");
const traceroute = @import("traceroute");

pub const usage =
    \\tiny-mtr: a continuous traceroute, on zig-libs
    \\
    \\usage: tiny-mtr [options] HOST
    \\
    \\  -r, --report        no screen: run the rounds, print the table, exit
    \\  -c, --count N       stop after N rounds (a report's default is 10)
    \\  -i, --interval SEC  time between rounds, at least 0.1 (default 1)
    \\  -w, --timeout SEC   how long a round waits for answers, up to 10 (default 1)
    \\  -m, --max-hops N    highest TTL, up to 255 (default 30)
    \\  -n, --no-dns        show addresses, send no PTR queries
    \\  -u, --udp           UDP probes on one flow (Paris traceroute)
    \\  -T, --tcp           TCP connection attempts as probes
    \\  -P, --port N        port of -T (default 80) or -u (default 33434)
    \\  -4, -6              ask DNS for this address family only
    \\  -h, --help          this text
    \\
    \\On the screen: q quit, r reset, n names on or off, p pause or go on.
    \\
;

pub const Config = struct {
    target: []const u8 = "",
    report: bool = false,
    count: ?u64 = null,
    names: bool = true,
    family: Family = .any,
    mtr: traceroute.MtrOptions = .{},

    pub const Family = enum { any, v4, v6 };
};

pub const Parsed = union(enum) {
    run: Config,
    help,
    /// What to tell the user, then exit 2.
    bad: []const u8,
};

fn seconds(text: []const u8, min_ms: u32, max_ms: u32) ?u32 {
    const s = std.fmt.parseFloat(f64, text) catch return null;
    // Written so that NaN fails too.
    if (!(s * 1000 >= @as(f64, @floatFromInt(min_ms)) and s * 1000 <= @as(f64, @floatFromInt(max_ms)))) return null;
    return @intFromFloat(s * 1000);
}

/// `args` without the program name. Short flags bundle, as in `-rn`, and a
/// value may follow its letter directly, as in `-c5`.
pub fn parse(args: []const []const u8) Parsed {
    var c: Config = .{};
    var port: ?u16 = null;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.startsWith(u8, a, "--")) {
            const letter = longToShort(a) orelse return .{ .bad = "unknown option" };
            var value: ?[]const u8 = null;
            if (takesValue(letter)) {
                i += 1;
                if (i == args.len) return .{ .bad = "an option needs a value" };
                value = args[i];
            }
            if (apply(&c, &port, letter, value)) |why| return why;
        } else if (a.len > 1 and a[0] == '-') {
            var j: usize = 1;
            while (j < a.len) : (j += 1) {
                const letter = a[j];
                var value: ?[]const u8 = null;
                if (takesValue(letter)) {
                    if (j + 1 < a.len) {
                        value = a[j + 1 ..];
                    } else {
                        i += 1;
                        if (i == args.len) return .{ .bad = "an option needs a value" };
                        value = args[i];
                    }
                    j = a.len;
                }
                if (apply(&c, &port, letter, value)) |why| return why;
            }
        } else {
            if (c.target.len != 0) return .{ .bad = "more than one host" };
            if (a.len == 0) return .{ .bad = "empty host" };
            c.target = a;
        }
    }
    if (c.target.len == 0 and c.count == null and !c.report and args.len == 1 and isHelp(args[0])) return .help;
    if (c.target.len == 0) return .{ .bad = "no host given" };
    switch (c.mtr.method) {
        .icmp => if (port != null) return .{ .bad = "-P goes with -u or -T" },
        .udp => {
            c.mtr.flow_stable = true;
            if (port) |p| c.mtr.udp_port_base = p;
        },
        .tcp => if (port) |p| {
            c.mtr.dst_port = p;
        },
    }
    if (c.report and c.count == null) c.count = 10;
    c.mtr.validate() catch return .{ .bad = "these options do not work together" };
    return .{ .run = c };
}

fn isHelp(a: []const u8) bool {
    return std.mem.eql(u8, a, "-h") or std.mem.eql(u8, a, "--help");
}

fn takesValue(letter: u8) bool {
    return switch (letter) {
        'c', 'i', 'w', 'm', 'P' => true,
        else => false,
    };
}

fn longToShort(a: []const u8) ?u8 {
    const table = [_]struct { []const u8, u8 }{
        .{ "--report", 'r' },  .{ "--count", 'c' },    .{ "--interval", 'i' },
        .{ "--timeout", 'w' }, .{ "--max-hops", 'm' }, .{ "--no-dns", 'n' },
        .{ "--udp", 'u' },     .{ "--tcp", 'T' },      .{ "--port", 'P' },
        .{ "--help", 'h' },
    };
    for (table) |t| {
        if (std.mem.eql(u8, a, t[0])) return t[1];
    }
    return null;
}

fn apply(c: *Config, port: *?u16, letter: u8, value: ?[]const u8) ?Parsed {
    switch (letter) {
        'r' => c.report = true,
        'n' => c.names = false,
        'u' => c.mtr.method = .udp,
        'T' => c.mtr.method = .tcp,
        '4' => c.family = .v4,
        '6' => c.family = .v6,
        'h' => return .help,
        'c' => {
            const n = std.fmt.parseInt(u64, value.?, 10) catch return .{ .bad = "-c wants a whole number" };
            if (n == 0) return .{ .bad = "-c wants at least 1" };
            c.count = n;
        },
        'i' => c.mtr.interval_ms = seconds(value.?, traceroute.min_mtr_interval_ms, 3_600_000) orelse
            return .{ .bad = "-i wants seconds, from 0.1 to 3600" },
        'w' => c.mtr.timeout_ms = seconds(value.?, 1, traceroute.max_mtr_timeout_ms) orelse
            return .{ .bad = "-w wants seconds, from 0.001 to 10" },
        'm' => c.mtr.max_hops = std.fmt.parseInt(u8, value.?, 10) catch return .{ .bad = "-m wants 1 to 255" },
        'P' => port.* = std.fmt.parseInt(u16, value.?, 10) catch return .{ .bad = "-P wants 1 to 65535" },
        else => return .{ .bad = "unknown option" },
    }
    return null;
}

const testing = std.testing;

fn run(args: []const []const u8) !Config {
    return switch (parse(args)) {
        .run => |c| c,
        else => error.NotRun,
    };
}

test "defaults, bundled flags, attached values" {
    const d = try run(&.{"example.net"});
    try testing.expectEqualStrings("example.net", d.target);
    try testing.expect(!d.report and d.names and d.count == null);
    try testing.expectEqual(traceroute.Method.icmp, d.mtr.method);

    const b = try run(&.{ "-rnc5", "-i0.5", "--max-hops", "12", "example.net" });
    try testing.expect(b.report and !b.names);
    try testing.expectEqual(@as(?u64, 5), b.count);
    try testing.expectEqual(@as(u32, 500), b.mtr.interval_ms);
    try testing.expectEqual(@as(u8, 12), b.mtr.max_hops);

    try testing.expectEqual(@as(?u64, 10), (try run(&.{ "-r", "h" })).count);
}

test "methods take their ports; UDP keeps one flow" {
    const u = try run(&.{ "-u", "-P", "4000", "h" });
    try testing.expect(u.mtr.flow_stable);
    try testing.expectEqual(@as(u16, 4000), u.mtr.udp_port_base);
    const t = try run(&.{ "--tcp", "--port", "443", "h" });
    try testing.expectEqual(traceroute.Method.tcp, t.mtr.method);
    try testing.expectEqual(@as(u16, 443), t.mtr.dst_port);
    try testing.expect(parse(&.{ "-P", "443", "h" }) == .bad);
}

test "what is refused says so, rather than running" {
    const bad = [_][]const []const u8{
        &.{},
        &.{"-r"},
        &.{ "a", "b" },
        &.{ "-x", "h" },
        &.{ "--nope", "h" },
        &.{ "h", "-c" },
        &.{ "-c", "0", "h" },
        &.{ "-c", "-1", "h" },
        &.{ "-i", "0.01", "h" },
        &.{ "-i", "nan", "h" },
        &.{ "-i", "inf", "h" },
        &.{ "-w", "11", "h" },
        &.{ "-m", "0", "h" },
        &.{ "-m", "256", "h" },
        &.{ "-T", "-P", "70000", "h" },
    };
    for (bad) |args| try testing.expect(parse(args) == .bad);
    try testing.expect(parse(&.{"-h"}) == .help);
    try testing.expect(parse(&.{ "--help", "h" }) == .help);
}
