// SPDX-License-Identifier: MIT

//! Model-based fuzzing for `aaa-gate` (2026-10-17): each harness drives the
//! real gate and a deliberately naive reference model with the same script
//! and compares every observable after every step.
//!
//! - `aaa-gate-verify` — `Gate.verify` / `verifyApiKey` / `verifyBasic` under
//!   rotation (`add`/`remove` of tokens, API keys, Basic users), with or without a
//!   dynamic verifier callback, with `allow_when_unconfigured` either way.
//!   Credentials come from a small alphabet (so adds, removes and presents
//!   collide) plus arbitrary bytes. The model keeps the credentials
//!   themselves in plain lists (the gate keeps SHA-256 digests) and states
//!   the SPEC's decision table directly. Compared: every verdict and both
//!   counts.
//! - `aaa-gate-throttle` — the denied-request audit throttle, end to end
//!   through the middleware on the wire: a virtual clock, client keys from a
//!   header (`Options.throttle_key`), a random window and key cap. The model
//!   keeps its entries in an array with a recency counter (the gate uses a
//!   hash map plus an intrusive LRU list) and follows the documented rule:
//!   coalesce inside the window, fold the count into the next admitted
//!   entry, sweep idle keys before tracking a new one, evict the least
//!   recently seen at the cap. Compared: every response status, whether the
//!   hook ran, its `suppressed` value, and the tracked-key count.
//!
//! Driver: `AAA_GATE_FUZZ=<runs>[,<first seed>]` (testkit's fuzz driver;
//! `AAA_GATE_FUZZ_ONLY` picks a harness by name).

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const router = @import("router");
const http = @import("http");
const gate_mod = @import("root.zig");
const fuzz_driver = testkit.fuzz.driver;
const Rng = fuzz_driver.Rng;

const Gate = gate_mod.Gate;
const Verdict = Gate.Verdict;

/// Reach counters for one harness's labels.
fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

        fn mark(l: Label) void {
            counts[@backingInt(l)] += 1;
            switch (l) {
                inline else => |c| fuzz_driver.hit(@tagName(c)),
            }
        }

        fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: Rng = .{ .r = prng.random() };
                harness(Rng, &rng, testing.allocator) catch |err| {
                    std.debug.print(name ++ " seed {d}: {t}\n", .{ seed, err });
                    return err;
                };
            }
            for (counts, 0..) |n, i| if (n == 0) {
                std.debug.print("reach: " ++ name ++ " label {t} never hit in {d} seeds\n", .{ @as(Label, @fromBackingInt(@intCast(i))), seeds });
                return error.HarnessDoesNotReach;
            };
        }
    };
}

/// A draw in `lo..hi` as `usize` (Smith has no `usize` ranges).
/// Every draw reduces a full `u64` (`check-fuzz-reach` option 2): a `Smith`
/// ranged draw returns the range minimum unless the input word already lies
/// in range, so under `zig build --fuzz` the script would collapse to op 0.
fn pick(comptime S: type, src: *S, lo: usize, hi: usize) usize {
    return lo + @as(usize, @intCast(src.value(u64) % (hi - lo + 1)));
}

// ── harness 1: the decision table under rotation ───────────────────────────

const alphabet = [_][]const u8{ "alpha", "beta", "gamma", "delta", "a", "alpha " };

const VerifyLabel = enum { ok_bearer, ok_api_key, ok_basic, ok_open, denied, via_callback, rotated_to_empty };
const VerifyMark = Marker(VerifyLabel);

/// A verifier callback that accepts exactly the credentials in `accept`.
const Callback = struct {
    accept: []const []const u8,
    fn check(ctx: ?*anyopaque, presented: []const u8) bool {
        const self: *const Callback = @ptrCast(@alignCast(ctx.?));
        for (self.accept) |a| if (std.mem.eql(u8, a, presented)) return true;
        return false;
    }
};

const Model = struct {
    items: std.ArrayList([]const u8) = .empty,

    fn has(m: *const Model, s: []const u8) bool {
        for (m.items.items) |x| if (std.mem.eql(u8, x, s)) return true;
        return false;
    }
    fn add(m: *Model, gpa: std.mem.Allocator, s: []const u8) !void {
        if (!m.has(s)) try m.items.append(gpa, s);
    }
    fn remove(m: *Model, s: []const u8) void {
        var i: usize = 0;
        while (i < m.items.items.len) {
            if (std.mem.eql(u8, m.items.items[i], s)) _ = m.items.orderedRemove(i) else i += 1;
        }
    }
};

/// The SPEC's decision for one scheme, stated directly.
fn expectedVerdict(set: *const Model, callback: ?*const Callback, allow_open: bool, presented: ?[]const u8, ok: Verdict) Verdict {
    if (set.items.items.len == 0 and callback == null) return if (allow_open) .ok_open else .denied;
    const p = presented orelse return .denied;
    if (set.has(p)) return ok;
    if (callback) |cb| if (Callback.check(@constCast(cb), p)) return ok;
    return .denied;
}

fn pickCredential(comptime S: type, src: *S, buf: *[24]u8) []const u8 {
    if (pick(S, src, 0, 4) != 0) return alphabet[pick(S, src, 0, alphabet.len - 1)];
    const n = src.slice(buf);
    if (n == 0) return alphabet[0]; // a credential is never empty
    return buf[0..n];
}

fn fuzzVerify(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const allow_open = (pick(S, src, 0, 1) == 1);
    var tok_cb: Callback = .{ .accept = &.{ "beta", "zeta" } };
    var key_cb: Callback = .{ .accept = &.{"gamma"} };
    const use_tok_cb = pick(S, src, 0, 3) == 0;
    const use_key_cb = pick(S, src, 0, 3) == 0;

    var tokens: Model = .{};
    defer tokens.items.deinit(gpa);
    var keys: Model = .{};
    defer keys.items.deinit(gpa);
    // Basic users as "user:password" (a user never contains ':').
    var basics: Model = .{};
    defer basics.items.deinit(gpa);
    // Owned copies of arbitrary credentials (the model keeps the strings).
    var owned: std.ArrayList([]u8) = .empty;
    defer {
        for (owned.items) |o| gpa.free(o);
        owned.deinit(gpa);
    }

    var initial_tokens: [3][]const u8 = undefined;
    const n_init_tok = pick(S, src, 0, 3);
    for (initial_tokens[0..n_init_tok]) |*t| t.* = alphabet[pick(S, src, 0, alphabet.len - 1)];
    var initial_keys: [2][]const u8 = undefined;
    const n_init_key = pick(S, src, 0, 2);
    for (initial_keys[0..n_init_key]) |*k| k.* = alphabet[pick(S, src, 0, alphabet.len - 1)];
    for (initial_tokens[0..n_init_tok]) |t| try tokens.add(gpa, t);
    for (initial_keys[0..n_init_key]) |k| try keys.add(gpa, k);

    var g = try Gate.init(gpa, .{
        .extra_tokens = initial_tokens[0..n_init_tok],
        .extra_api_keys = initial_keys[0..n_init_key],
        .allow_when_unconfigured = allow_open,
        .token_verify = if (use_tok_cb) Callback.check else null,
        .token_verify_ctx = &tok_cb,
        .api_key_verify = if (use_key_cb) Callback.check else null,
        .api_key_verify_ctx = &key_cb,
    });
    defer g.deinit();

    const steps = pick(S, src, 1, 40);
    for (0..steps) |_| {
        var buf: [24]u8 = undefined;
        const cred = pickCredential(S, src, &buf);
        const op = pick(S, src, 0, 8);
        switch (op) {
            0, 1 => {
                const stored = try gpa.dupe(u8, cred);
                try owned.append(gpa, stored);
                if (op == 0) {
                    try g.addToken(stored);
                    try tokens.add(gpa, stored);
                } else {
                    try g.addApiKey(stored);
                    try keys.add(gpa, stored);
                }
            },
            2 => {
                g.removeToken(cred);
                tokens.remove(cred);
                if (tokens.items.items.len == 0) VerifyMark.mark(.rotated_to_empty);
            },
            3 => {
                g.removeApiKey(cred);
                keys.remove(cred);
            },
            4, 5 => {
                const presented: ?[]const u8 = if (pick(S, src, 0, 5) == 0) null else cred;
                const bearer = op == 4;
                const got = if (bearer) g.verify(presented) else g.verifyApiKey(presented);
                const want = if (bearer)
                    expectedVerdict(&tokens, if (use_tok_cb) &tok_cb else null, allow_open, presented, .ok_bearer)
                else
                    expectedVerdict(&keys, if (use_key_cb) &key_cb else null, allow_open, presented, .ok_api_key);
                if (got != want) {
                    std.debug.print("verify mismatch: bearer={} presented={?s} got {t} want {t}\n", .{ bearer, presented, got, want });
                    return error.ModelMismatch;
                }
                VerifyMark.mark(switch (got) {
                    .ok_bearer => .ok_bearer,
                    .ok_api_key => .ok_api_key,
                    .ok_open => .ok_open,
                    .denied => .denied,
                    .ok_basic => return error.ModelMismatch, // not from verify/verifyApiKey
                });
                if (got != .denied and got != .ok_open) {
                    const set = if (bearer) &tokens else &keys;
                    if (!set.has(presented.?)) VerifyMark.mark(.via_callback);
                }
            },
            6, 7, 8 => {
                const user = alphabet[pick(S, src, 0, alphabet.len - 1)];
                const joined = try gpa.print("{s}:{s}", .{ user, cred });
                try owned.append(gpa, joined);
                const pw = joined[user.len + 1 ..];
                if (op == 6) {
                    try g.addBasicUser(user, pw);
                    try basics.add(gpa, joined);
                } else if (op == 7) {
                    g.removeBasicUser(user, pw);
                    basics.remove(joined);
                } else {
                    const presented: ?http.BasicCredentials = if (pick(S, src, 0, 5) == 0) null else .{ .user = user, .password = pw };
                    const got = g.verifyBasic(presented);
                    const want: Verdict = if (basics.items.items.len == 0)
                        (if (allow_open) .ok_open else .denied)
                    else if (presented != null and basics.has(joined)) .ok_basic else .denied;
                    if (got != want) {
                        std.debug.print("basic mismatch: {s} got {t} want {t}\n", .{ joined, got, want });
                        return error.ModelMismatch;
                    }
                    if (got == .ok_basic) VerifyMark.mark(.ok_basic);
                }
            },
            else => unreachable,
        }
        try testing.expectEqual(tokens.items.items.len, g.tokenCount());
        try testing.expectEqual(basics.items.items.len, g.basicCount());
        try testing.expectEqual(keys.items.items.len, g.apiKeyCount());
    }
}

fn verifySmith(_: void, s: *testing.Smith) !void {
    return fuzzVerify(testing.Smith, s, testing.allocator);
}
test "fuzz: verify/verifyApiKey agree with the decision table under rotation" {
    try testing.fuzz({}, verifySmith, .{});
}
test "fuzz driver: AAA_GATE_FUZZ (model verify)" {
    try fuzz_driver.run(fuzzVerify, .{ .prefix = "AAA_GATE_FUZZ", .name = "aaa-gate-verify" });
}
test "fuzz harness: verify, 400 seeds, reaches every outcome" {
    try VerifyMark.reach(fuzzVerify, "aaa-gate-verify", 400);
}

// ── harness 2: the denied-request throttle, through the middleware ─────────

const ThrottleLabel = enum { admitted_fresh, coalesced, folded_count, evicted_pending, swept_idle };
const ThrottleMark = Marker(ThrottleLabel);

const VClock = struct {
    ns: u64 = 1_000_000_000,
    fn now(ctx: ?*anyopaque) u64 {
        return @as(*VClock, @ptrCast(@alignCast(ctx.?))).ns;
    }
};

const Hook = struct {
    calls: usize = 0,
    last_suppressed: u64 = 0,
    last_authed: bool = true,
    fn record(ctx: ?*anyopaque, e: gate_mod.AuditEntry) void {
        const h: *Hook = @ptrCast(@alignCast(ctx.?));
        h.calls += 1;
        h.last_suppressed = e.suppressed;
        h.last_authed = e.authed;
    }
};

fn keyFromHeader(_: ?*anyopaque, c: *router.Ctx, _: *[gate_mod.client_key_len_max]u8) []const u8 {
    return c.req.header("x-k") orelse "none";
}

const ThrottleModel = struct {
    const Entry = struct { key: u8, last: u64, suppressed: u64, seen: u64 };
    entries: [8]Entry = undefined,
    len: usize = 0,
    seq: u64 = 0,

    fn find(m: *ThrottleModel, key: u8) ?usize {
        for (m.entries[0..m.len], 0..) |e, i| if (e.key == key) return i;
        return null;
    }
    fn lru(m: *ThrottleModel) ?usize {
        if (m.len == 0) return null;
        var best: usize = 0;
        for (m.entries[1..m.len], 1..) |e, i| if (e.seen < m.entries[best].seen) {
            best = i;
        };
        return best;
    }
    fn drop(m: *ThrottleModel, i: usize) void {
        m.entries[i] = m.entries[m.len - 1];
        m.len -= 1;
    }

    /// null = coalesced (no hook call), else the suppressed count folded
    /// into the admitted entry.
    fn decide(m: *ThrottleModel, key: u8, now: u64, window: u64, max_keys: usize) ?u64 {
        m.seq += 1;
        if (m.find(key)) |i| {
            const e = &m.entries[i];
            e.seen = m.seq;
            if (window != 0 and now -| e.last < window) {
                e.suppressed += 1;
                ThrottleMark.mark(.coalesced);
                return null;
            }
            const folded = e.suppressed;
            if (folded != 0) ThrottleMark.mark(.folded_count);
            e.suppressed = 0;
            e.last = now;
            return folded;
        }
        // A new key: drop the least recently seen keys while they are idle
        // (past the window, nothing pending), then make room at the cap.
        while (m.lru()) |i| {
            const e = m.entries[i];
            if (e.suppressed != 0 or now -| e.last < window) break;
            ThrottleMark.mark(.swept_idle);
            m.drop(i);
        }
        if (m.len >= max_keys) if (m.lru()) |i| {
            if (m.entries[i].suppressed != 0) ThrottleMark.mark(.evicted_pending);
            m.drop(i);
        };
        m.entries[m.len] = .{ .key = key, .last = now, .suppressed = 0, .seen = m.seq };
        m.len += 1;
        ThrottleMark.mark(.admitted_fresh);
        return 0;
    }
};

fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: std.Io.Reader = .fixed(bytes);
    var out: std.Io.Writer = .fixed(out_buf);
    var head_buf: [1024]u8 = undefined;
    var request_body_buf: [64]u8 = undefined;
    var response_body_buf: [256]u8 = undefined;
    var chunk_buf: [64]u8 = undefined;
    http.Server.serveStream(.{ .handler = r.handler(), .context = r, .server_name = null }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn okHandler(ctx: *router.Ctx) anyerror!void {
    try ctx.res.writeAll("ok");
}

fn fuzzThrottle(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const windows = [_]u64{ 0, 10 * std.time.ns_per_ms, 100 * std.time.ns_per_ms };
    const window_ns = windows[pick(S, src, 0, windows.len - 1)];
    const max_keys = pick(S, src, 1, 4);
    var clock: VClock = .{};
    var hook: Hook = .{};
    var g = try Gate.init(gpa, .{
        .token = "good",
        .on_audit = Hook.record,
        .on_audit_ctx = &hook,
        .throttle_window_ms = window_ns / std.time.ns_per_ms,
        .throttle_max_keys = max_keys,
        .clock = .{ .ctx = &clock, .nowFn = VClock.now },
        .throttle_key = .{ .keyFor = keyFromHeader },
    });
    defer g.deinit();
    var r = router.Router.init(gpa);
    defer r.deinit();
    try r.use(g.middleware());
    try r.get("/x", okHandler);

    var model: ThrottleModel = .{};
    const steps = pick(S, src, 1, 60);
    for (0..steps) |_| {
        clock.ns += switch (pick(S, src, 0, 3)) {
            0 => 0,
            1 => @as(u64, pick(S, src, 0, 12)) * std.time.ns_per_ms,
            2 => @as(u64, pick(S, src, 0, 150)) * std.time.ns_per_ms,
            else => std.time.ns_per_s,
        };
        const key: u8 = 'a' + @as(u8, @intCast(pick(S, src, 0, 5)));
        const authed = pick(S, src, 0, 5) == 0;
        var req_buf: [160]u8 = undefined;
        const req = try std.mem.print(&req_buf, "GET /x HTTP/1.1\r\nHost: t\r\nX-K: {c}\r\n{s}Connection: close\r\n\r\n", .{
            key, if (authed) "Authorization: Bearer good\r\n" else "",
        });
        const calls_before = hook.calls;
        var out_buf: [1024]u8 = undefined;
        const got = runWire(&r, req, &out_buf);
        if (authed) {
            // A GET passing the gate is not audited; the throttle is not touched.
            try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200 "));
            try testing.expectEqual(calls_before, hook.calls);
            continue;
        }
        try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 401 "));
        const want = model.decide(key, clock.ns, window_ns, max_keys);
        if (want) |folded| {
            if (hook.calls != calls_before + 1 or hook.last_authed or hook.last_suppressed != folded) {
                std.debug.print("throttle mismatch: key {c} want admitted({d}) got calls {d}->{d} suppressed {d}\n", .{ key, folded, calls_before, hook.calls, hook.last_suppressed });
                return error.ModelMismatch;
            }
        } else if (hook.calls != calls_before) {
            std.debug.print("throttle mismatch: key {c} want coalesced, hook ran\n", .{key});
            return error.ModelMismatch;
        }
        try testing.expectEqual(model.len, g.throttleKeyCount());
    }
}

fn throttleSmith(_: void, s: *testing.Smith) !void {
    return fuzzThrottle(testing.Smith, s, testing.allocator);
}
test "fuzz: the denied-request throttle agrees with its documented rule, on the wire" {
    try testing.fuzz({}, throttleSmith, .{});
}
test "fuzz driver: AAA_GATE_FUZZ (model throttle)" {
    try fuzz_driver.run(fuzzThrottle, .{ .prefix = "AAA_GATE_FUZZ", .name = "aaa-gate-throttle", .scale = 8 });
}
test "fuzz harness: throttle, 400 seeds, reaches every outcome" {
    try ThrottleMark.reach(fuzzThrottle, "aaa-gate-throttle", 400);
}
