// SPDX-License-Identifier: MIT

//! `dns-demo` — a `dig(1)`-shaped query tool built on the `dns` module's
//! `Resolver.query` (the primitive that bypasses the search list and the
//! hosts file and hands back the raw decoded message — already `dig`-shaped,
//! so this file is the CLI and the output formatting, not new resolver
//! logic).
//!
//! **What this demonstrates, and why each piece is here:**
//!
//! - **The decoded type set.** A/NS/CNAME/SOA/PTR/MX/TXT/AAAA/SRV/CAA plus
//!   OPT are printed from their typed `Record.Data` fields. The `Type` enum
//!   is non-exhaustive (message.zig), so any other code — NAPTR, RRSIG,
//!   DNSKEY, ... — decodes as `.unknown` and is printed here as RFC 3597
//!   generic rdata (`TYPE<n> \# <len> <hex>`, the same convention `dig`
//!   itself falls back to). It never crashes; it is honestly hex.
//!
//! - **TC → TCP is invisible from `Resolver.query` on purpose** (the module
//!   handles it transparently, see Resolver.zig `query`). To make it
//!   *visible*, `--probe-tc` does one extra, manual UDP round trip with no
//!   EDNS(0) OPT record — using only `dns.encodeQuery`/`dns.decode` (public
//!   codec) and `std.Io.net` directly, exactly the shape `Resolver` itself
//!   uses internally — and reports the TC bit on the raw 512-byte-capped
//!   response before making the real (transparently-retried) query. This is
//!   an outside consumer reusing the published wire codec, not a reach into
//!   `Resolver` internals.
//!
//! - **EDNS(0) / the DO bit.** On by default (`--bufsize`, default 1232;
//!   `--no-edns` to turn it off). `Record.Data.Opt.dnssec_ok` is parsed and
//!   printed when a response carries it — but `message.QueryOptions` has no
//!   field to *set* the DO bit on an outgoing query, so this tool can ask a
//!   validating resolver a question and see whether *it* validated (SERVFAIL
//!   on a broken zone happens resolver-side regardless of the client's DO
//!   bit), but it cannot itself request the accompanying RRSIG the way real
//!   `dig +dnssec` does. That is a module gap, not a CLI choice — see
//!   SPEC.md "not a validating resolver" and the coordinator report.
//!
//! - **DoH** (`--doh <url>`, RFC 8484 POST/GET, plus `--doh-json` for the
//!   common non-standard JSON flavour) rides the sibling `http` module
//!   including its TLS. **DoT is not implemented by this module** — there is
//!   no flag for it here, and none should be invented; the module's SPEC.md
//!   says nothing about DoT being a deliberate omission, so this tool treats
//!   it as simply absent.
//!
//! - **Search list / `ndots`.** `Resolver.query` (the default path here)
//!   does not consult them; `--search` switches to `Resolver.resolve`, which
//!   does (Go `nameList` semantics, from `/etc/resolv.conf`). The same short
//!   name can resolve differently between the two — that's the point of the
//!   flag, not a bug in either path.
//!
//! **Deliberately simplified vs. real `dig`**: `WHEN` prints a raw
//! CLOCK_REALTIME epoch (no calendar/locale formatting in scope here); `MSG
//! SIZE rcvd` is omitted because `Resolver.query` returns a decoded
//! `Message`, not the raw wire bytes, so this tool has no honest number to
//! print for it. Both are noted inline rather than faked.
//!
//! Built against the PUBLISHED module (`@import("dns")`) only.

const std = @import("std");
const dns = @import("dns");
const netaddr = @import("netaddr");
const net = std.Io.net;

const Allocator = std.mem.Allocator;
const Resolver = dns.Resolver;
const message = dns.message;

const usage_text =
    \\dns-demo -- a dig(1)-shaped query tool for the `dns` module.
    \\
    \\usage:
    \\  dns-demo [@server] name [type] [options]
    \\  dns-demo [@server] -x <addr> [options]        reverse (PTR) lookup
    \\
    \\  @server           DNS server IP (default: /etc/resolv.conf, like dig)
    \\  name              domain to query
    \\  type              A NS CNAME SOA PTR MX TXT AAAA SRV CAA OPT (default A)
    \\                    plus any other name/number this module does NOT decode
    \\                    (NAPTR DS RRSIG NSEC DNSKEY TLSA SSHFP CDS CDNSKEY SPF
    \\                    HINFO DNAME URI ANY, or raw TYPE<n>/<n>) -- printed as
    \\                    RFC 3597 generic rdata to prove the non-exhaustive
    \\                    decode never crashes.
    \\
    \\  -x <addr>         reverse-lookup an IPv4/IPv6 address (PTR); ignores name/type
    \\  -p, --port <n>    server port (default 53)
    \\  --tcp             force TCP transport (Resolver.Transport.tcp)
    \\  --no-edns         send no OPT record (plain RFC 1035, hard 512-byte UDP cap)
    \\  --bufsize <n>     EDNS(0) advertised UDP payload size (default 1232)
    \\  --search          use Resolver.resolve (search list / ndots from resolv.conf)
    \\                    instead of the default Resolver.query (exact name, no list)
    \\  --resolv-conf <f> read the search list / ndots / servers from this file instead
    \\                    of /etc/resolv.conf (only used together with --search, or when
    \\                    @server is omitted)
    \\  --doh <url>       query over DoH (RFC 8484) instead of UDP/TCP; @server/-p/--tcp
    \\                    are ignored. DoT (DNS-over-TLS) is NOT implemented by this
    \\                    module -- there is no flag for it here.
    \\  --doh-get         use RFC 8484 GET instead of the default POST (with --doh)
    \\  --doh-json        use the application/dns-json flavour instead (with --doh)
    \\  --probe-tc        before the real query, do one manual no-EDNS UDP round trip
    \\                    and report whether the server set the TC bit (see the module
    \\                    doc comment). Try it against "amazon.com TXT" -- a name with
    \\                    enough TXT records that the no-EDNS 512-byte reply reliably
    \\                    truncates against public resolvers.
    \\  --timeout <ms>    per-attempt timeout (default 5000)
    \\  -h, --help        this text
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

    if (opts.mode == .help) {
        try printOut(io, "{s}", .{usage_text});
        return 0;
    }

    return run(gpa, io, opts) catch |err| {
        std.debug.print("dns-demo: {t}\n", .{err});
        return 1;
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// arguments
// ─────────────────────────────────────────────────────────────────────────────

const Mode = enum { help, query };

const Options = struct {
    mode: Mode = .query,
    server: ?netaddr.Ip = null,
    port: u16 = 53,
    name: []const u8 = "",
    ty: message.Type = .a,
    reverse_ip: ?netaddr.Ip = null,
    force_tcp: bool = false,
    no_edns: bool = false,
    bufsize: u16 = 1232,
    use_search: bool = false,
    resolv_conf_path: []const u8 = "/etc/resolv.conf",
    doh_url: ?[]const u8 = null,
    doh_method: Resolver.DohMethod = .post,
    doh_json: bool = false,
    probe_tc: bool = false,
    timeout_ms: u32 = 5000,
};

fn parseArgs(args: *std.process.Args.Iterator) !Options {
    var o: Options = .{};
    var have_name = false;
    var have_type = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            o.mode = .help;
            return o;
        } else if (std.mem.eql(u8, arg, "-x")) {
            const v = args.next() orelse return error.BadUsage;
            o.reverse_ip = netaddr.parseIp(v) orelse return error.BadUsage;
        } else if (std.mem.eql(u8, arg, "-p") or std.mem.eql(u8, arg, "--port")) {
            const v = args.next() orelse return error.BadUsage;
            o.port = std.fmt.parseInt(u16, v, 10) catch return error.BadUsage;
        } else if (std.mem.eql(u8, arg, "--tcp")) {
            o.force_tcp = true;
        } else if (std.mem.eql(u8, arg, "--no-edns")) {
            o.no_edns = true;
        } else if (std.mem.eql(u8, arg, "--bufsize")) {
            const v = args.next() orelse return error.BadUsage;
            o.bufsize = std.fmt.parseInt(u16, v, 10) catch return error.BadUsage;
        } else if (std.mem.eql(u8, arg, "--search")) {
            o.use_search = true;
        } else if (std.mem.eql(u8, arg, "--resolv-conf")) {
            o.resolv_conf_path = args.next() orelse return error.BadUsage;
        } else if (std.mem.eql(u8, arg, "--doh")) {
            o.doh_url = args.next() orelse return error.BadUsage;
        } else if (std.mem.eql(u8, arg, "--doh-get")) {
            o.doh_method = .get;
        } else if (std.mem.eql(u8, arg, "--doh-json")) {
            o.doh_json = true;
        } else if (std.mem.eql(u8, arg, "--probe-tc")) {
            o.probe_tc = true;
        } else if (std.mem.eql(u8, arg, "--timeout")) {
            const v = args.next() orelse return error.BadUsage;
            o.timeout_ms = std.fmt.parseInt(u32, v, 10) catch return error.BadUsage;
        } else if (arg.len > 1 and arg[0] == '@') {
            o.server = netaddr.parseIp(arg[1..]) orelse return error.BadUsage;
        } else if (!have_name) {
            o.name = arg;
            have_name = true;
        } else if (!have_type) {
            o.ty = parseType(arg) orelse return error.BadUsage;
            have_type = true;
        } else {
            return error.BadUsage;
        }
    }

    if (o.reverse_ip == null and o.name.len == 0) return error.BadUsage;
    return o;
}

/// dig-style type names, plus the well-known codes this module does NOT
/// decode (they fall through `message.zig`'s switch to `.unknown` -- that is
/// the point of exercising them here) and the RFC 3597 `TYPE<n>` / bare
/// numeric escape hatch for anything else.
fn parseType(text: []const u8) ?message.Type {
    const Named = struct { name: []const u8, code: u16 };
    const table = [_]Named{
        // Decoded by this module (message.zig switch).
        .{ .name = "A", .code = 1 },
        .{ .name = "NS", .code = 2 },
        .{ .name = "CNAME", .code = 5 },
        .{ .name = "SOA", .code = 6 },
        .{ .name = "PTR", .code = 12 },
        .{ .name = "MX", .code = 15 },
        .{ .name = "TXT", .code = 16 },
        .{ .name = "AAAA", .code = 28 },
        .{ .name = "SRV", .code = 33 },
        .{ .name = "OPT", .code = 41 },
        .{ .name = "CAA", .code = 257 },
        // NOT decoded -- printed as raw rdata (RFC 3597) by this tool.
        .{ .name = "HINFO", .code = 13 },
        .{ .name = "NAPTR", .code = 35 },
        .{ .name = "DNAME", .code = 39 },
        .{ .name = "DS", .code = 43 },
        .{ .name = "SSHFP", .code = 44 },
        .{ .name = "RRSIG", .code = 46 },
        .{ .name = "NSEC", .code = 47 },
        .{ .name = "DNSKEY", .code = 48 },
        .{ .name = "NSEC3", .code = 50 },
        .{ .name = "NSEC3PARAM", .code = 51 },
        .{ .name = "SMIMEA", .code = 53 },
        .{ .name = "TLSA", .code = 52 },
        .{ .name = "CDS", .code = 59 },
        .{ .name = "CDNSKEY", .code = 60 },
        .{ .name = "OPENPGPKEY", .code = 61 },
        .{ .name = "SPF", .code = 99 },
        .{ .name = "URI", .code = 256 },
        .{ .name = "ANY", .code = 255 },
    };
    for (table) |t| {
        if (std.ascii.eqlIgnoreCase(text, t.name)) return @enumFromInt(t.code);
    }
    if (text.len > 4 and std.ascii.startsWithIgnoreCase(text, "TYPE")) {
        const n = std.fmt.parseInt(u16, text[4..], 10) catch return null;
        return @enumFromInt(n);
    }
    if (std.fmt.parseInt(u16, text, 10) catch null) |n| return @enumFromInt(n);
    return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// running the query
// ─────────────────────────────────────────────────────────────────────────────

fn run(gpa: Allocator, io: std.Io, opts: Options) !u8 {
    var buf: [8192]u8 = undefined;
    var w = std.Io.File.stdout().writer(io, &buf);
    const out = &w.interface;
    defer out.flush() catch {};

    var name_buf: [dns.max_reverse_name_len]u8 = undefined;
    // name_buf is sized to exactly max_reverse_name_len: reverseName cannot
    // fail here.
    const name = if (opts.reverse_ip) |ip| dns.reverseName(ip, &name_buf) catch unreachable else opts.name;
    const ty: message.Type = if (opts.reverse_ip != null) .ptr else opts.ty;

    if (opts.probe_tc and opts.doh_url == null) {
        try probeTruncation(gpa, io, out, opts, name, ty);
    }

    var banner_tbuf: [16]u8 = undefined;
    try out.print("; <<>> dns-demo (zig-libs `dns`) <<>> {s} {s}{s}\n", .{
        name, typeTagBuf(&banner_tbuf, ty), if (opts.reverse_ip != null) " (via -x)" else "",
    });

    if (opts.doh_json) {
        if (opts.doh_url == null) {
            try out.writeAll(";; --doh-json needs --doh <url>\n");
            return 1;
        }
        return runDohJson(gpa, io, out, opts, name, ty);
    }

    var resolver: Resolver = .init(io, gpa, .{
        .servers = if (opts.server) |s| (&[1]netaddr.Ip{s})[0..] else &.{},
        .port = opts.port,
        .doh_url = opts.doh_url,
        .doh_method = opts.doh_method,
        .transport = if (opts.force_tcp) .tcp else .auto,
        .timeout_ms = opts.timeout_ms,
        .use_search = opts.use_search,
        .resolv_conf_path = opts.resolv_conf_path,
        .edns_udp_size = if (opts.no_edns) null else opts.bufsize,
    });
    defer resolver.deinit();

    const t0 = now();
    var msg = (if (opts.use_search)
        resolver.resolve(name, ty)
    else
        resolver.query(name, ty)) catch |err| {
        try out.print(";; query failed: {t}\n", .{err});
        try printFailureHint(out, err, opts);
        return 1;
    };
    defer msg.deinit();
    const elapsed_ms = (now() -| t0) / std.time.ns_per_ms;

    try printMessage(out, &msg);
    try printFooter(out, opts, elapsed_ms);
    return 0;
}

fn printFailureHint(out: *std.Io.Writer, err: anyerror, opts: Options) !void {
    switch (err) {
        error.Timeout, error.NetworkFailed => try out.writeAll(
            ";; (no network reachable, or the server is unresponsive -- this is the " ++
                "'handle no network access gracefully' case)\n",
        ),
        error.NoDohEndpoint => try out.writeAll(";; --doh <url> is required for this mode\n"),
        error.DohFailed => try out.writeAll(";; DoH transport/HTTP failure -- see the http module's own diagnostics\n"),
        else => {},
    }
    _ = opts;
}

fn runDohJson(gpa: Allocator, io: std.Io, out: *std.Io.Writer, opts: Options, name: []const u8, ty: message.Type) !u8 {
    var resolver: Resolver = .init(io, gpa, .{
        .doh_url = opts.doh_url,
        .timeout_ms = opts.timeout_ms,
    });
    defer resolver.deinit();

    const t0 = now();
    const parsed = resolver.queryJson(name, ty) catch |err| {
        try out.print(";; DoH-JSON query failed: {t}\n", .{err});
        return 1;
    };
    defer parsed.deinit();
    const elapsed_ms = (now() -| t0) / std.time.ns_per_ms;

    try out.print(";; DoH-JSON (application/dns-json) via {s}\n", .{opts.doh_url.?});
    try out.print(";; status: {d} (raw RCODE integer -- this schema has no name table)\n", .{parsed.value.Status});
    try out.print(";; TC (server-reported, informational only over HTTPS): {}\n", .{parsed.value.TC});
    try out.writeAll(";; ANSWER SECTION:\n");
    for (parsed.value.Answer) |rec| {
        try out.print(";{s}\t{d}\tIN\tTYPE{d}\t{s}\n", .{ rec.name, rec.TTL, rec.type, rec.data });
    }
    try out.print(";; Query time: {d} msec\n", .{elapsed_ms});
    try out.writeAll(
        ";; NOTE: DoH-JSON is text throughout (RDATA arrives as a string, not wire\n" ++
            ";; bytes), so unlike the binary path there is nothing to render as raw hex here.\n",
    );
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// the TC-bit / TCP-retry probe
// ─────────────────────────────────────────────────────────────────────────────

/// One manual, no-EDNS UDP round trip using only the published codec
/// (`dns.encodeQuery`/`dns.decode`) and `std.Io.net` directly -- the same
/// shape `Resolver.query` uses internally (see Resolver.zig `udpExchange`),
/// reproduced here because `Resolver.query` retries over TCP transparently
/// and never reports that it did. Requires `@server`: without an explicit
/// resolver this tool has no public way to read `/etc/resolv.conf`'s server
/// list itself (that parsing lives behind `Resolver`, not `dns.config`'s
/// public surface for a bare address list).
fn probeTruncation(gpa: Allocator, io: std.Io, out: *std.Io.Writer, opts: Options, name: []const u8, ty: message.Type) !void {
    var ttag_buf: [16]u8 = undefined;
    const ttag = typeTagBuf(&ttag_buf, ty);

    const server = opts.server orelse {
        try out.writeAll(";; --probe-tc needs an explicit @server (e.g. @8.8.8.8); skipping the probe\n");
        return;
    };

    var qbuf: [message.max_query_len]u8 = undefined;
    var id_bytes: [2]u8 = undefined;
    io.random(&id_bytes);
    const id = std.mem.readInt(u16, &id_bytes, .big);
    // No OPT record at all: RFC 1035's original 512-byte UDP limit applies,
    // which is what makes truncation easy to provoke on purpose.
    const packet = message.encodeQuery(&qbuf, name, ty, .{ .id = id, .edns_udp_size = null }) catch |err| {
        try out.print(";; --probe-tc: cannot encode {s}/{s}: {t}\n", .{ name, ttag, err });
        return;
    };

    const dest: net.IpAddress = switch (server) {
        .v4 => |b| .{ .ip4 = .{ .bytes = b, .port = opts.port } },
        .v6 => |b| .{ .ip6 = .{ .bytes = b, .port = opts.port } },
    };
    const bind_addr: net.IpAddress = switch (server) {
        .v4 => .{ .ip4 = .unspecified(0) },
        .v6 => .{ .ip6 = .unspecified(0) },
    };
    const sock = bind_addr.bind(io, .{ .mode = .dgram }) catch |err| {
        try out.print(";; --probe-tc: bind failed: {t} (no network access?)\n", .{err});
        return;
    };
    defer sock.close(io);
    sock.send(io, &dest, packet) catch |err| {
        try out.print(";; --probe-tc: send failed: {t}\n", .{err});
        return;
    };

    const deadline_t: std.Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(opts.timeout_ms), .clock = .awake } };
    const deadline = deadline_t.toDeadline(io);
    // 512 bytes: what a client that never advertised EDNS(0) can rely on.
    var rbuf: [512]u8 = undefined;
    const incoming = sock.receiveTimeout(io, &rbuf, deadline) catch |err| {
        try out.print(";; --probe-tc: no reply within {d}ms ({t}) -- can't tell; the real query below may still succeed via a different path\n", .{ opts.timeout_ms, err });
        return;
    };

    if (incoming.data.len < message.header_len) {
        try out.writeAll(";; --probe-tc: reply shorter than a DNS header; skipping\n");
        return;
    }
    const tc = incoming.data[2] & 0x02 != 0; // same bit test Resolver.query itself makes
    if (tc) {
        try out.print(
            ";; --probe-tc: TC bit SET on the raw {d}-byte no-EDNS UDP reply for {s}/{s} -- " ++
                "a client that stopped here would have an incomplete answer. Resolver.query " ++
                "retries this exact query over TCP transparently; see the full answer below.\n",
            .{ incoming.data.len, name, ttag },
        );
    } else {
        try out.print(
            ";; --probe-tc: TC bit NOT set on the raw {d}-byte no-EDNS UDP reply for {s}/{s} " ++
                "-- this answer fit under 512 bytes, so there is nothing for Resolver to retry. " ++
                "Try a domain with many TXT/DNSKEY records (e.g. `amazon.com TXT`), whose answer " ++
                "reliably exceeds it.\n",
            .{ incoming.data.len, name, ttag },
        );
    }

    // Independently confirm against the decoded header field too (same
    // TC bit, decoded through the public codec rather than hand-indexed).
    var probe_msg = message.decode(gpa, incoming.data) catch return;
    defer probe_msg.deinit();
    std.debug.assert(probe_msg.header.truncated == tc);
}

// ─────────────────────────────────────────────────────────────────────────────
// output formatting (dig-shaped, for side-by-side diffing)
// ─────────────────────────────────────────────────────────────────────────────

fn printMessage(out: *std.Io.Writer, msg: *const message.Message) !void {
    var obuf: [16]u8 = undefined;
    var rbuf: [16]u8 = undefined;
    try out.print(
        ";; Got answer:\n;; ->>HEADER<<- opcode: {s}, status: {s}, id: {d}\n" ++
            ";; flags:{s}{s}{s}{s}{s} ; QUERY: {d}, ANSWER: {d}, AUTHORITY: {d}, ADDITIONAL: {d}\n\n",
        .{
            opcodeTag(&obuf, msg.header.opcode),
            rcodeTag(&rbuf, msg.rcode()),
            msg.header.id,
            if (msg.header.response) " qr" else "",
            if (msg.header.authoritative) " aa" else "",
            if (msg.header.truncated) " tc" else "",
            if (msg.header.recursion_desired) " rd" else "",
            if (msg.header.recursion_available) " ra" else "",
            msg.questions.len,
            msg.answers.len,
            msg.authorities.len,
            msg.additionals.len,
        },
    );

    for (msg.additionals) |r| {
        if (r.data != .opt) continue;
        const opt = r.data.opt;
        try out.print(
            ";; OPT PSEUDOSECTION:\n; EDNS: version: {d}, flags:{s}; udp: {d}\n" ++
                "; (dnssec_ok is PARSED here, not validated -- this module is not a\n" ++
                ";  validating resolver; see SPEC.md)\n\n",
            .{ opt.version, if (opt.dnssec_ok) " do" else "", opt.udp_payload_size },
        );
    }

    if (msg.questions.len > 0) {
        try out.writeAll(";; QUESTION SECTION:\n");
        for (msg.questions) |q| {
            var tbuf: [16]u8 = undefined;
            try out.print(";{s}\t\tIN\t{s}\n", .{ q.name, typeTagBuf(&tbuf, q.ty) });
        }
        try out.writeAll("\n");
    }
    try printSection(out, "ANSWER", msg.answers);
    try printSection(out, "AUTHORITY", msg.authorities);
    try printNonOptSection(out, "ADDITIONAL", msg.additionals);
}

fn printSection(out: *std.Io.Writer, title: []const u8, records: []const message.Record) !void {
    if (records.len == 0) return;
    try out.print(";; {s} SECTION:\n", .{title});
    for (records) |r| try printRecord(out, r);
    try out.writeAll("\n");
}

/// Same as `printSection` but skips OPT (already shown in its own
/// pseudosection above) -- matches real `dig`'s ADDITIONAL SECTION, which
/// also never lists OPT there.
fn printNonOptSection(out: *std.Io.Writer, title: []const u8, records: []const message.Record) !void {
    var any = false;
    for (records) |r| {
        if (r.data == .opt) continue;
        if (!any) {
            try out.print(";; {s} SECTION:\n", .{title});
            any = true;
        }
        try printRecord(out, r);
    }
    if (any) try out.writeAll("\n");
}

fn printRecord(out: *std.Io.Writer, r: message.Record) !void {
    var tbuf: [16]u8 = undefined;
    try out.print("{s}\t{d}\t{s}\t{s}\t", .{ r.name, r.ttl, classTag(r.class), typeTagBuf(&tbuf, r.ty) });
    switch (r.data) {
        .a => |b| try out.print("{d}.{d}.{d}.{d}\n", .{ b[0], b[1], b[2], b[3] }),
        .aaaa => |b| {
            var ip_buf: [netaddr.max_ip_text_len]u8 = undefined;
            try out.print("{s}\n", .{netaddr.formatIp(.{ .v6 = b }, &ip_buf)});
        },
        .cname => |n| try out.print("{s}\n", .{n}),
        .ns => |n| try out.print("{s}\n", .{n}),
        .ptr => |n| try out.print("{s}\n", .{n}),
        .mx => |mx| try out.print("{d} {s}\n", .{ mx.preference, mx.exchange }),
        .txt => |strings| {
            for (strings, 0..) |s, i| {
                if (i > 0) try out.writeAll(" ");
                try out.print("\"{s}\"", .{s});
            }
            try out.writeAll("\n");
        },
        .soa => |s| try out.print("{s} {s} {d} {d} {d} {d} {d}\n", .{
            s.mname, s.rname, s.serial, s.refresh, s.retry, s.expire, s.minimum,
        }),
        .srv => |s| try out.print("{d} {d} {d} {s}\n", .{ s.priority, s.weight, s.port, s.target }),
        .caa => |c| try out.print("{d} {s} \"{s}\"\n", .{ c.flags, c.tag, c.value }),
        .opt => try out.writeAll("(EDNS OPT -- see the pseudosection above)\n"),
        .unknown => |raw| {
            // RFC 3597 "unknown RR" generic presentation format -- the same
            // fallback real `dig`/`named` use for a type they were not built
            // to decode. Proves the non-exhaustive Type enum never crashes,
            // shows exactly the bytes instead of pretending to understand them.
            try out.print("\\# {d} ", .{raw.len});
            for (raw) |byte| try out.print("{x:0>2}", .{byte});
            try out.writeAll("\n");
        },
    }
}

fn typeTag(ty: message.Type) []const u8 {
    return switch (ty) {
        .a => "A",
        .ns => "NS",
        .cname => "CNAME",
        .soa => "SOA",
        .ptr => "PTR",
        .mx => "MX",
        .txt => "TXT",
        .aaaa => "AAAA",
        .srv => "SRV",
        .opt => "OPT",
        .caa => "CAA",
        else => "TYPE?", // see typeTagBuf for the numbered form used in records
    };
}

/// Like `typeTag`, but for an unrecognized code prints `TYPE<n>` (RFC 3597)
/// into `buf` instead of the placeholder `typeTag` returns. Record printing
/// always goes through this one so an undecoded type still names itself.
fn typeTagBuf(buf: []u8, ty: message.Type) []const u8 {
    const known = typeTag(ty);
    if (!std.mem.eql(u8, known, "TYPE?")) return known;
    return std.fmt.bufPrint(buf, "TYPE{d}", .{@intFromEnum(ty)}) catch "TYPE?";
}

/// `message.Header.opcode` is a non-exhaustive `enum(u4)`; `@tagName`
/// (and so `{t}`) is unsafe on an unnamed value, and a real server response
/// can legitimately carry one, so this never reaches for `{t}`.
fn opcodeTag(buf: []u8, op: message.Opcode) []const u8 {
    return switch (op) {
        .query => "QUERY",
        .iquery => "IQUERY",
        .status => "STATUS",
        else => std.fmt.bufPrint(buf, "OPCODE{d}", .{@intFromEnum(op)}) catch "OPCODE?",
    };
}

/// Same reasoning as `opcodeTag`: `Rcode` is non-exhaustive (EDNS(0)
/// extends it to 12 bits, RFC 6891 §3), and only a handful of values are
/// named.
fn rcodeTag(buf: []u8, rc: message.Rcode) []const u8 {
    return switch (rc) {
        .no_error => "NOERROR",
        .form_err => "FORMERR",
        .serv_fail => "SERVFAIL",
        .nx_domain => "NXDOMAIN",
        .not_imp => "NOTIMP",
        .refused => "REFUSED",
        .yx_domain => "YXDOMAIN",
        .yx_rrset => "YXRRSET",
        .nx_rrset => "NXRRSET",
        .not_auth => "NOTAUTH",
        .not_zone => "NOTZONE",
        .bad_vers => "BADVERS",
        else => std.fmt.bufPrint(buf, "RCODE{d}", .{@intFromEnum(rc)}) catch "RCODE?",
    };
}

fn classTag(class: message.Class) []const u8 {
    return switch (class) {
        .in => "IN",
        .ch => "CH",
        .hs => "HS",
        .any => "ANY",
        else => "CLASS?",
    };
}

fn printFooter(out: *std.Io.Writer, opts: Options, elapsed_ms: u64) !void {
    var server_buf: [netaddr.max_ip_text_len]u8 = undefined;
    const server_text = if (opts.server) |s| netaddr.formatIp(s, &server_buf) else "resolv.conf";
    try out.print(";; Query time: {d} msec\n", .{elapsed_ms});
    if (opts.doh_url) |url| {
        try out.print(";; SERVER: {s} (DoH, {s})\n", .{ url, if (opts.doh_method == .get) "GET" else "POST" });
    } else {
        try out.print(";; SERVER: {s}#{d}\n", .{ server_text, opts.port });
    }
    try out.print(";; WHEN: {d} (CLOCK_REALTIME epoch seconds -- no calendar formatting in scope)\n", .{timestampSec()});
    try out.writeAll(
        ";; MSG SIZE  rcvd: n/a -- Resolver.query returns a decoded Message, not the\n" ++
            ";; raw wire bytes, so this tool has no honest byte count to print here.\n",
    );
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

fn now() u64 {
    var ts: std.os.linux.timespec = undefined;
    if (std.os.linux.clock_gettime(.MONOTONIC, &ts) != 0) return 0;
    return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
}

fn timestampSec() i64 {
    var ts: std.os.linux.timespec = undefined;
    if (std.os.linux.clock_gettime(.REALTIME, &ts) != 0) return 0;
    return @intCast(ts.sec);
}
