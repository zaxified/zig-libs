// SPDX-License-Identifier: MIT

//! Live oracle for `tlsclient`: Go's crypto/tls (the scope reference, through
//! its public API in `tools/go_oracle`) serves every case, Go's own client
//! judges it first, and this module's client then runs the same case against
//! the same server; the two are compared.
//!
//! THIS IS A PROGRAM, NOT A TEST. `zig build interop-tlsclient` runs it and
//! `zig build check-interop` compiles it. Needs `go` on PATH (stdlib only, no
//! module downloads; GOPROXY=off) and loopback networking. Run from the
//! repository root.
//!
//!   zig build interop-tlsclient              # judge and compare; exit 1 on any surprise
//!   zig build interop-tlsclient -- chain     # only the cases whose id contains "chain"
//!
//! The Go side builds the PKI and the cases (versions, every TLS 1.2 AEAD
//! suite, every group with and without HelloRetryRequest, every server key
//! type, chain validation rules, ALPN, client certificates of four key types,
//! TLS 1.3 resumption, OCSP/SCT stapling, 1 MiB of application data), and the
//! server tells each client, in its first line, what IT saw: version, suite,
//! group, HelloRetryRequest, ALPN, resumption, verified client certificates,
//! SNI and 32 octets of exporter output (see `go_oracle/main.go`). A client's
//! verdict is "ok" when its handshake succeeds and that line arrives.
//!
//! For each case this program checks:
//!
//! - the verdict against Go's client's, per the row's expectation: `agree`
//!   (the same verdict, and on "ok" the same server line but for the exporter
//!   value, which is per connection), `stricter` (Go accepts, this module
//!   refuses -- the rule is in the row's `why`; these are the card's
//!   `**Ahead:**` rows), `gap` (a listed deficit in SPEC's Backlog: Go's client
//!   gets something this one does not; when they start to agree the gap is
//!   closed and the row is a surprise until the SPEC says so);
//! - on "ok", that this client's own view (`ConnectionInfo`, the exporter)
//!   matches the server's line, the stapled OCSP response and SCTs arrived as
//!   sent, and the application data arrived intact up to close_notify.
//!
//! Every verdict goes to `.zig-cache/interop-tlsclient/verdicts.tsv`; stdout
//! gets the surprises and a summary per family.

const std = @import("std");
const tlsclient = @import("tlsclient");
const Client = tlsclient.Client;
const tls = std.crypto.tls;

const work_dir = ".zig-cache/interop-tlsclient";
const go_dir = "modules/tlsclient/tools/go_oracle";
const ekm_label = "EXPERIMENTAL-zl-interop";
const pattern = 31;

const Expect = enum { agree, stricter, gap };

const Case = struct {
    id: []const u8,
    family: []const u8,
    expect: Expect,
    port: u16,
    host: []const u8,
    min: u16,
    max: u16,
    groups: []const tls.NamedGroup,
    alpn: []const []const u8,
    ccert: ?[]const u8,
    root: []const u8,
    twice: bool,
    bulk: usize,
    staple: ?[]const u8,
    scts: []const []const u8,
    go_ok: bool,
    go_line: []const u8,
    why: []const u8,
};

const Outcome = struct {
    ok: bool,
    /// The server's line on "ok", else the error.
    text: []const u8,
    /// A disagreement between this client's own view and the server's line
    /// (or the stapled data, or the bulk octets); null when consistent.
    inconsistent: ?[]const u8 = null,
};

fn split(arena: std.mem.Allocator, s: []const u8, sep: u8) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (std.mem.eql(u8, s, "-")) return out.items;
    var it = std.mem.splitScalar(u8, s, sep);
    while (it.next()) |p| try out.append(arena, p);
    return out.items;
}

fn parseCases(arena: std.mem.Allocator, text: []const u8) ![]Case {
    var out: std.ArrayList(Case) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    _ = lines.next(); // header
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const f = try split(arena, line, '\t');
        if (f.len != 19) return error.BadCaseRow;
        var groups: std.ArrayList(tls.NamedGroup) = .empty;
        for (try split(arena, f[7], ',')) |g| try groups.append(arena, @fromBackingInt(try std.fmt.parseInt(u16, g, 16)));
        try out.append(arena, .{
            .id = f[0],
            .family = f[1],
            .expect = std.meta.stringToEnum(Expect, f[2]) orelse return error.BadExpect,
            .port = try std.fmt.parseInt(u16, f[3], 10),
            .host = f[4],
            .min = try std.fmt.parseInt(u16, f[5], 16),
            .max = try std.fmt.parseInt(u16, f[6], 16),
            .groups = groups.items,
            .alpn = try split(arena, f[9], ','),
            .ccert = if (std.mem.eql(u8, f[10], "-")) null else f[10],
            .root = f[11],
            .twice = std.mem.eql(u8, f[12], "1"),
            .bulk = try std.fmt.parseInt(usize, f[13], 10),
            .staple = if (std.mem.eql(u8, f[14], "-")) null else f[14],
            .scts = try split(arena, f[15], ','),
            .go_ok = std.mem.eql(u8, f[16], "ok"),
            .go_line = f[17],
            .why = f[18],
        });
    }
    return out.items;
}

/// The server line without its `ekm=` field (the exporter differs per connection).
fn withoutEkm(line: []const u8) []const u8 {
    return if (std.mem.find(u8, line, " ekm=")) |at| line[0..at] else line;
}

fn field(line: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, line, ' ');
    while (it.next()) |kv| {
        if (kv.len > name.len and std.mem.startsWith(u8, kv, name) and kv[name.len] == '=') return kv[name.len + 1 ..];
    }
    return null;
}

const Env = struct {
    io: std.Io,
    arena: std.mem.Allocator,
    dir: std.Io.Dir,
    lock: std.Io.RwLock = .init,
};

fn loadKey(env: *Env, kind: []const u8, key: *Client.ClientAuth.PrivateKey, rsa_kp: *Client.rsa.KeyPair) !void {
    const raw = try env.dir.readFileAlloc(env.io, try env.arena.print("client_{s}.key", .{kind}), env.arena, .limited(8192));
    if (std.mem.eql(u8, kind, "p256")) {
        key.* = .{ .ecdsa_secp256r1_sha256 = raw[0..32].* };
    } else if (std.mem.eql(u8, kind, "p384")) {
        key.* = .{ .ecdsa_secp384r1_sha384 = raw[0..48].* };
    } else if (std.mem.eql(u8, kind, "ed25519")) {
        key.* = .{ .ed25519 = raw[0..32].* };
    } else if (std.mem.eql(u8, kind, "rsa2048")) {
        try rsa_kp.secret_key.fromDer(raw);
        key.* = .{ .rsa = rsa_kp };
    } else return error.UnknownClientKey;
}

/// One connection of `c`; `ok` = handshake done and the server's line read.
fn connectOnce(env: *Env, c: *const Case, bundle: *std.crypto.Certificate.Bundle, cache: *Client.SessionCache, auth: ?Client.ClientAuth) Outcome {
    return connectOnceInner(env, c, bundle, cache, auth) catch |e| .{ .ok = false, .text = @errorName(e) };
}

fn connectOnceInner(env: *Env, c: *const Case, bundle: *std.crypto.Certificate.Bundle, cache: *Client.SessionCache, auth: ?Client.ClientAuth) !Outcome {
    const io = env.io;
    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", c.port);
    const stream = try addr.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var net_in: [Client.min_buffer_len]u8 = undefined;
    var net_out: [Client.min_buffer_len]u8 = undefined;
    var tls_in: [Client.min_buffer_len]u8 = undefined;
    var tls_out: [Client.min_buffer_len]u8 = undefined;
    var sr = stream.reader(io, &net_in);
    var sw = stream.writer(io, &net_out);
    var entropy: [Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    var storage: [16 * 1024]u8 = undefined;
    var info: Client.ConnectionInfo = .init(&storage);

    var client: Client = undefined;
    try Client.initInto(&client, &sr.interface, &sw.interface, .{
        .host = .{ .explicit = c.host },
        .ca = .{ .bundle = .{ .gpa = env.arena, .io = io, .lock = &env.lock, .bundle = bundle } },
        .read_buffer = &tls_in,
        .write_buffer = &tls_out,
        .entropy = &entropy,
        .realtime_now = std.Io.Clock.real.now(io),
        .min_version = @fromBackingInt(c.min),
        .max_version = @fromBackingInt(c.max),
        .groups = if (c.groups.len > 0) c.groups else &Client.default_groups,
        .key_share_groups = if (c.groups.len > 0) c.groups else &Client.default_key_share_groups,
        .alpn_protocols = c.alpn,
        .client_auth = auth,
        .connection_info = &info,
        .session_cache = if (c.twice) cache else null,
    });
    const raw_line = try client.reader.takeDelimiterExclusive('\n');
    const line = try env.arena.dupe(u8, raw_line);
    client.reader.toss(1);

    // This client's view against the server's.
    var km: [32]u8 = undefined;
    try client.exportKeyingMaterial(ekm_label, null, &km);
    const mine = try env.arena.print("v={x:0>4} cs={x:0>4} g={x:0>4} hrr={d} alpn={s} res={d} ekm={x}", .{
        @backingInt(info.version),
        @backingInt(info.cipher_suite),
        if (info.negotiated_group) |g| @backingInt(g) else 0,
        @intFromBool(info.hello_retry_request),
        info.alpn_protocol orelse "-",
        @intFromBool(info.did_resume),
        &km,
    });
    const names = [_][]const u8{ "v", "cs", "g", "hrr", "alpn", "res", "ekm" };
    for (names) |n| {
        const theirs = field(line, n) orelse return .{ .ok = true, .text = line, .inconsistent = "server line lacks a field" };
        if (!std.mem.eql(u8, theirs, field(mine, n).?))
            return .{ .ok = true, .text = line, .inconsistent = try env.arena.print("{s}: ours {s}, the server's {s}", .{ n, field(mine, n).?, theirs }) };
    }
    if (c.staple) |want| if (!std.mem.eql(u8, info.ocsp_response, want))
        return .{ .ok = true, .text = line, .inconsistent = try env.arena.print("OCSP response {d} octets, sent {d}", .{ info.ocsp_response.len, want.len }) };
    const scts = info.signedCertificateTimestamps();
    if (c.scts.len > 0) {
        if (scts.len != c.scts.len) return .{ .ok = true, .text = line, .inconsistent = "SCT count" };
        for (scts, c.scts) |got, want| if (!std.mem.eql(u8, got, want)) return .{ .ok = true, .text = line, .inconsistent = "SCT bytes" };
    }
    if (c.bulk > 0) {
        var i: usize = 0;
        while (i < c.bulk) {
            const chunk = try client.reader.peekGreedy(1);
            const n = @min(chunk.len, c.bulk - i);
            for (chunk[0..n], i..) |b, j| if (b != @as(u8, @truncate(j *% pattern +% 7)))
                return .{ .ok = true, .text = line, .inconsistent = try env.arena.print("bulk octet {d} differs", .{j}) };
            client.reader.toss(n);
            i += n;
        }
    }
    // Then close_notify: a clean end of the stream.
    if (client.reader.peekByte()) |_| {
        return .{ .ok = true, .text = line, .inconsistent = "data after the expected end" };
    } else |e| if (e != error.EndOfStream) return .{ .ok = true, .text = line, .inconsistent = try env.arena.print("end of stream: {t}", .{e}) };
    return .{ .ok = true, .text = line };
}

fn runCase(env: *Env, c: *const Case) !Outcome {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    try bundle.addCertsFromFilePath(env.arena, env.io, std.Io.Clock.real.now(env.io), env.dir, try env.arena.print("{s}.pem", .{c.root}));
    var entries: [4]Client.ClientSession = undefined;
    var cache: Client.SessionCache = .init(&entries, null);
    var key: Client.ClientAuth.PrivateKey = undefined;
    var rsa_kp: Client.rsa.KeyPair = undefined;
    var chain: [1][]const u8 = undefined;
    var auth: ?Client.ClientAuth = null;
    if (c.ccert) |kind| {
        try loadKey(env, kind, &key, &rsa_kp);
        chain[0] = try env.dir.readFileAlloc(env.io, try env.arena.print("client_{s}.der", .{kind}), env.arena, .limited(16384));
        auth = .{ .certificate_chain = &chain, .key = &key };
    }
    const first = connectOnce(env, c, &bundle, &cache, auth);
    if (!c.twice or !first.ok or first.inconsistent != null) return first;
    return connectOnce(env, c, &bundle, &cache, auth);
}

pub fn main(init: std.process.Init) !u8 {
    const io = init.io;
    const arena = init.arena.allocator();
    const cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, work_dir);
    var dir = try cwd.openDir(io, work_dir, .{});
    defer dir.close(io);
    const abs = try cwd.realPathFileAlloc(io, work_dir, arena);
    const args = try init.minimal.args.toSlice(arena);
    const filters = if (args.len > 1) args[1..] else &[_][:0]const u8{};

    var env_map = try init.environ_map.clone(arena);
    try env_map.put("GOTOOLCHAIN", "local");
    try env_map.put("GOPROXY", "off");
    try env_map.put("GOFLAGS", "-mod=readonly");
    const exe = try arena.print("{s}/go_oracle", .{abs});
    const build = std.process.run(arena, io, .{
        .argv = &.{ "go", "build", "-o", exe, "." },
        .environ_map = &env_map,
        .cwd = .{ .path = go_dir },
    }) catch |e| {
        std.debug.print("interop-tlsclient: could not run go ({t}) -- the oracle needs it\n", .{e});
        return 1;
    };
    if (build.term != .exited or build.term.exited != 0) {
        std.debug.print("interop-tlsclient: go build failed:\n{s}\n", .{build.stderr});
        return 1;
    }

    var server = try std.process.spawn(io, .{
        .argv = &.{ exe, abs },
        .environ_map = &env_map,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .inherit,
    });
    defer server.kill(io);
    var go_version: []const u8 = "?";
    {
        var buf: [256]u8 = undefined;
        var r = server.stdout.?.reader(io, &buf);
        const line = (try r.interface.takeDelimiter('\n')) orelse {
            std.debug.print("interop-tlsclient: the Go oracle exited before it was ready\n", .{});
            return 1;
        };
        var it = std.mem.tokenizeScalar(u8, line, ' ');
        if (!std.mem.eql(u8, it.next() orelse "", "READY")) return error.BadOracleBanner;
        go_version = try arena.dupe(u8, it.next() orelse "?");
    }

    const text = try dir.readFileAlloc(io, "cases.tsv", arena, .limited(1 << 22));
    const cases = try parseCases(arena, text);

    var env: Env = .{ .io = io, .arena = arena, .dir = dir };
    var out_buf: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &out_buf);
    const w = &stdout.interface;
    var tsv: std.Io.Writer.Allocating = .init(arena);
    try tsv.writer.writeAll("id\tfamily\texpect\tgo\tours\tverdict\tdetail\n");

    const Tally = struct { cases: usize = 0, surprises: usize = 0, stricter: usize = 0, gap: usize = 0 };
    var families: std.StringArrayHashMapUnmanaged(Tally) = .empty;
    var total: Tally = .{};
    for (cases) |*c| {
        if (filters.len > 0) {
            var hit = false;
            for (filters) |f| hit = hit or std.mem.find(u8, c.id, f) != null;
            if (!hit) continue;
        }
        const o = try runCase(&env, c);
        // The verdict per the row's expectation.
        const surprise: ?[]const u8 = blk: {
            if (o.inconsistent) |why| break :blk try arena.print("client view vs server: {s}", .{why});
            switch (c.expect) {
                .agree => {
                    if (o.ok != c.go_ok) break :blk try arena.print("Go {s}, ours {s}", .{ if (c.go_ok) "ok" else "err", if (o.ok) "ok" else "err" });
                    if (o.ok and !std.mem.eql(u8, withoutEkm(o.text), withoutEkm(c.go_line)))
                        break :blk try arena.print("server saw Go: {s} | ours: {s}", .{ withoutEkm(c.go_line), withoutEkm(o.text) });
                    break :blk null;
                },
                .stricter => {
                    if (!c.go_ok) break :blk "Go refuses it now: the lead is gone";
                    if (o.ok) break :blk "ours accepts it: the lead is gone";
                    break :blk null;
                },
                .gap => {
                    if (!c.go_ok) break :blk "Go fails it now";
                    if (o.ok and std.mem.eql(u8, withoutEkm(o.text), withoutEkm(c.go_line))) break :blk "ours does what Go does: the gap is closed (update SPEC)";
                    break :blk null;
                },
            }
        };
        const fam = try families.getOrPut(arena, c.family);
        if (!fam.found_existing) fam.value_ptr.* = .{};
        inline for (.{ fam.value_ptr, &total }) |t| {
            t.cases += 1;
            if (surprise != null) t.surprises += 1;
            if (surprise == null and c.expect == .stricter) t.stricter += 1;
            if (surprise == null and c.expect == .gap) t.gap += 1;
        }
        try tsv.writer.print("{s}\t{s}\t{t}\t{s}\t{s}\t{s}\t{s}\n", .{
            c.id, c.family, c.expect, if (c.go_ok) "ok" else "err", if (o.ok) "ok" else o.text, if (surprise == null) "as expected" else "SURPRISE", surprise orelse c.why,
        });
        if (surprise) |s| try w.print("SURPRISE {s} ({t}): {s}\n", .{ c.id, c.expect, s });
    }
    try dir.writeFile(io, .{ .sub_path = "verdicts.tsv", .data = tsv.written() });

    try w.print("\nGo {s} crypto/tls, {d} cases\n", .{ go_version, total.cases });
    try w.print("{s:<12} {s:>6} {s:>9} {s:>9} {s:>5}\n", .{ "family", "cases", "surprises", "stricter", "gap" });
    for (families.keys(), families.values()) |k, v| try w.print("{s:<12} {d:>6} {d:>9} {d:>9} {d:>5}\n", .{ k, v.cases, v.surprises, v.stricter, v.gap });
    try w.print("{s:<12} {d:>6} {d:>9} {d:>9} {d:>5}\n", .{ "total", total.cases, total.surprises, total.stricter, total.gap });
    try w.print("verdicts: {s}/verdicts.tsv\n", .{work_dir});
    try w.flush();
    return if (total.surprises == 0) 0 else 1;
}
