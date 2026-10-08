// SPDX-License-Identifier: MIT
//! `VerifiedCache` — remember a token that verified, until its `exp`, so the
//! next request carrying the same bytes skips the signature check.
//!
//! Verifying a JWS is the expensive part of serving a Bearer request: ES256
//! runs at a few thousand verifications per second per core, RS256 through
//! std's bignum is slower still, and a client presents the same access token
//! on every request until it expires. The cache turns the repeat into a hash
//! and a table probe.
//!
//! **It answers exactly what verifying again would answer** — that is the
//! contract, and SPEC.md § "Verified-token cache" argues each point:
//!
//! * The key is a SipHash-2-4-128 MAC, under a random key drawn for each
//!   cache (`io.randomSecure`), over the claim policy (`Options` minus
//!   `now_s`), the cache's `Config.context` and the EXACT compact token bytes.
//!   Without the key nobody can aim a different byte string at a stored
//!   entry: a false hit is a 2^-128 guess per request. So a hit means these
//!   very bytes verified before under this very policy. (Why not an unkeyed
//!   hash: SPEC.md, measured — it was most of the hit path.)
//! * Every entry is bound to the `JwkSet.id` it verified under. A replaced set
//!   has a new id (ids are never reused), so a JWKS refresh or rotation
//!   invalidates everything verified under the old one at once: "a key the set
//!   drops stops verifying at the next fetch" still holds.
//! * A hit re-runs the time checks — the SAME `checkTimes` `validateClaims`
//!   runs — against the caller's `now_s`. An expired entry is evicted and
//!   reported as `error.Expired`, which is what a fresh verify returns for it.
//! * Only a success is stored. A failure is never cached: that would let an
//!   attacker pin a refusal on a token, or fill the table with junk.
//!
//! What is stored is not the token but a caller-chosen `Value` derived from
//! the verified token (a principal id and scope bits, say): plain data, no
//! pointers (checked at compile time), copied out on a hit. That is what makes
//! the hit path allocation-free, and it bounds an entry's size — a token whose
//! claims do not fit the caller's `Value` simply is not cached (its `derive`
//! returns null).
//!
//! Concurrency: one spin lock per 4-way bucket, held for a probe and a copy
//! only — the MAC is computed before it is taken and the signature is
//! verified after it is released. Eviction is CLOCK (second chance) within a
//! bucket, after free, stale-set and expired slots.

const std = @import("std");
const root = @import("root.zig");

/// The entry key: a 128-bit PRF under a per-cache secret (see SPEC.md for
/// the measurement against SHA-256 and BLAKE3).
const Mac = std.crypto.auth.siphash.SipHash128(2, 4);
const digest_len = Mac.mac_length;

/// Entries per bucket (the table is 4-way set-associative).
pub const ways = 4;

/// Longest `Config.context` accepted.
pub const max_context_len = 64;

pub const Config = struct {
    /// Most tokens held at once. Rounded up so the bucket count is a power
    /// of two (`VerifiedCache.capacity` reports the result). Must be > 0.
    capacity: usize,
    /// Bytes folded into every key besides the claim policy: name the
    /// configuration of the caller's derive step (which claim is the
    /// principal id, which scope names map to which bits), so two callers
    /// deriving different `Value`s from one token never share an entry.
    /// Copied; at most `max_context_len` bytes.
    context: []const u8 = "",
};

/// The time-based claims a hit re-checks.
pub const TimeClaims = struct {
    exp: ?i64 = null,
    nbf: ?i64 = null,
    iat: ?i64 = null,
};

/// The time half of `validateClaims` (RFC 7519 §4.1.4/.5/.6), in its order:
/// `exp`, then `nbf`, then (opt-in) `iat`. Shared by `validateClaims` and a
/// cache hit, so the two cannot disagree.
pub fn checkTimes(t: TimeClaims, opts: root.Options) root.ValidateError!void {
    const leeway: i64 = opts.leeway_s;
    if (t.exp) |exp| {
        if (exp +| leeway < opts.now_s) return error.Expired;
    } else if (opts.require_exp) {
        return error.MissingExp;
    }
    if (t.nbf) |nbf| {
        if (nbf -| leeway > opts.now_s) return error.NotYetValid;
    }
    if (opts.reject_future_iat) {
        if (t.iat) |iat| {
            if (iat -| leeway > opts.now_s) return error.IssuedInFuture;
        }
    }
}

/// A cache of verified tokens whose entries carry a `Value` the caller
/// derived from each one. `Value` must be plain data: no pointer or slice
/// anywhere in it (it outlives the parsed token it came from).
pub fn VerifiedCache(comptime Value: type) type {
    comptime assertPlainData(Value, @typeName(Value));
    return struct {
        const Self = @This();

        gpa: std.mem.Allocator,
        buckets: []Bucket,
        /// The MAC key: secret, drawn at `init`, wiped at `deinit`.
        mac_key: [Mac.key_length]u8,
        context_buf: [max_context_len]u8 = @splat(0),
        context_len: usize = 0,

        const Entry = struct {
            digest: [digest_len]u8 = @splat(0),
            /// `JwkSet.id` verified under; 0 = free slot.
            set_id: u64 = 0,
            times: TimeClaims = .{},
            /// `exp + leeway` of the policy it was stored under (or
            /// `maxInt` without `exp`): past it the entry is dead weight and
            /// the first choice of victim.
            dead_after: i64 = 0,
            /// CLOCK's second-chance bit.
            referenced: bool = false,
            value: Value = undefined,
        };

        const Bucket = struct {
            /// Held for a probe or a write, never across anything slow.
            /// Cache-line aligned so two buckets' locks never share a line.
            lock: std.atomic.Mutex align(std.atomic.cache_line) = .unlocked,
            hand: u8 = 0,
            entries: [ways]Entry = @splat(.{}),

            fn acquire(b: *Bucket) void {
                while (!b.lock.tryLock()) std.atomic.spinLoopHint();
            }
        };

        pub const InitError = error{ OutOfMemory, InvalidCapacity, ContextTooLong } || std.Io.RandomSecureError;

        /// Allocate the table (`capacity` entries, rounded up) and draw the
        /// MAC key from `io.randomSecure` — fail-closed: no entropy, no cache.
        pub fn init(gpa: std.mem.Allocator, io: std.Io, config: Config) InitError!Self {
            if (config.capacity == 0) return error.InvalidCapacity;
            if (config.context.len > max_context_len) return error.ContextTooLong;
            const wanted = std.math.divCeil(usize, config.capacity, ways) catch unreachable;
            const n = std.math.ceilPowerOfTwo(usize, wanted) catch return error.InvalidCapacity;
            var mac_key: [Mac.key_length]u8 = undefined;
            defer std.crypto.secureZero(u8, &mac_key);
            try io.randomSecure(&mac_key);
            const buckets = try gpa.alloc(Bucket, n);
            @memset(buckets, .{});
            var self: Self = .{ .gpa = gpa, .buckets = buckets, .mac_key = mac_key };
            @memcpy(self.context_buf[0..config.context.len], config.context);
            self.context_len = config.context.len;
            return self;
        }

        /// Free the table. The derived values are wiped first (they may name
        /// a principal, and the freed block goes back to the allocator), and
        /// so is the MAC key.
        pub fn deinit(self: *Self) void {
            std.crypto.secureZero(u8, &self.mac_key);
            std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.buckets));
            self.gpa.free(self.buckets);
            self.buckets = &.{};
        }

        /// Entries the table holds at most (`Config.capacity` rounded up).
        pub fn capacity(self: *const Self) usize {
            return self.buckets.len * ways;
        }

        /// Drop every entry (e.g. after changing what `derive` produces).
        pub fn clear(self: *Self) void {
            for (self.buckets) |*b| {
                b.acquire();
                defer b.lock.unlock();
                for (&b.entries) |*e| wipe(e);
            }
        }

        /// The cached value for `token` verified under `set` and `opts`'s
        /// policy, with the time claims re-checked at `opts.now_s`:
        /// * null — not cached (never seen, evicted, other set, other policy);
        /// * an error — cached, but the time checks fail now: exactly the
        ///   error `parseVerifyJwks` would return (its signature and
        ///   `iss`/`aud` checks passed for these bytes under this set and
        ///   policy, and the time checks come first). An `Expired` entry is
        ///   evicted.
        ///
        /// No allocation, no I/O; the bucket lock is held for the probe.
        pub fn lookup(self: *Self, token: []const u8, set: *const root.JwkSet, opts: root.Options) root.ValidateError!?Value {
            if (set.id == 0) return null;
            return self.lookupDigest(self.digestOf(token, opts), set.id, opts);
        }

        /// Store `value` for `token`, which the caller verified under `set`
        /// and `opts` — signature included (`parseVerifyJwks` accepted it).
        /// `parsed` must be `token`'s own parse. As a guard against misuse,
        /// nothing is stored when `parsed` is not a parse of `token`, when
        /// its claims do not pass `validateClaims(opts)` now, or when `set`
        /// has no identity (`id == 0`). The signature itself cannot be
        /// re-checked cheaply: that part of the precondition is the caller's.
        pub fn insert(
            self: *Self,
            token: []const u8,
            parsed: *const root.ParsedToken,
            set: *const root.JwkSet,
            opts: root.Options,
            value: Value,
        ) void {
            self.insertDigest(self.digestOf(token, opts), token, parsed, set, opts, value);
        }

        /// `parseVerifyJwks` with the cache in front of it: a hit returns the
        /// stored value; a miss parses and verifies `token` in `scratch`,
        /// derives the value with `deriver`'s `pub fn derive(*const ParsedToken) ?Value`
        /// and stores it. `derive` returning null (the token verified but the
        /// value cannot be made, e.g. no principal claim) is
        /// `error.NotDerived`, and nothing is stored.
        ///
        /// `derive` must be a pure function of the token: whatever else it
        /// reads belongs in `Config.context`. The whole call returns what
        /// `parseVerifyJwks` + `derive` would return without the cache.
        pub fn verifyJwks(
            self: *Self,
            scratch: std.mem.Allocator,
            token: []const u8,
            set: *const root.JwkSet,
            opts: root.Options,
            deriver: anytype,
        ) (root.ParseAndVerifyError || error{NotDerived})!Value {
            const digest = self.digestOf(token, opts);
            if (set.id != 0) {
                if (try self.lookupDigest(digest, set.id, opts)) |v| return v;
            }
            var parsed = try root.parseVerifyJwks(scratch, token, set.*, opts);
            defer parsed.deinit();
            const value = deriver.derive(&parsed) orelse return error.NotDerived;
            self.insertDigest(digest, token, &parsed, set, opts, value);
            return value;
        }

        /// Free a slot, wiping the value it held (it may name a principal).
        /// All-zero is a free entry: `set_id == 0`.
        fn wipe(e: *Entry) void {
            std.crypto.secureZero(u8, std.mem.asBytes(e));
        }

        fn bucketOf(self: *Self, digest: *const [digest_len]u8) *Bucket {
            const h = std.mem.readInt(u64, digest[0..8], .little);
            return &self.buckets[@intCast(h & (self.buckets.len - 1))];
        }

        fn lookupDigest(self: *Self, digest: [digest_len]u8, set_id: u64, opts: root.Options) root.ValidateError!?Value {
            const b = self.bucketOf(&digest);
            b.acquire();
            defer b.lock.unlock();
            for (&b.entries) |*e| {
                if (e.set_id != set_id) continue;
                if (!std.crypto.timing_safe.eql([digest_len]u8, e.digest, digest)) continue;
                checkTimes(e.times, opts) catch |err| {
                    // Past `exp` the entry is dead for good at this clock;
                    // anything else (a clock stepped back before `nbf`) may
                    // pass again later, so it stays.
                    if (err == error.Expired) wipe(e);
                    return err;
                };
                e.referenced = true;
                return e.value;
            }
            return null;
        }

        fn insertDigest(
            self: *Self,
            digest: [digest_len]u8,
            token: []const u8,
            parsed: *const root.ParsedToken,
            set: *const root.JwkSet,
            opts: root.Options,
            value: Value,
        ) void {
            if (set.id == 0) return;
            // `parsed` must be this token's parse: its signing input is the
            // token up to the second dot.
            const si = parsed.signing_input;
            if (token.len <= si.len or token[si.len] != '.' or !std.mem.eql(u8, token[0..si.len], si)) return;
            root.validateClaims(parsed.claims, opts) catch return;

            const times: TimeClaims = .{ .exp = parsed.claims.exp, .nbf = parsed.claims.nbf, .iat = parsed.claims.iat };
            const dead_after = if (times.exp) |exp| exp +| @as(i64, opts.leeway_s) else std.math.maxInt(i64);
            const b = self.bucketOf(&digest);
            b.acquire();
            defer b.lock.unlock();
            const slot = pickSlot(b, digest, opts.now_s);
            b.entries[slot] = .{
                .digest = digest,
                .set_id = set.id,
                .times = times,
                .dead_after = dead_after,
                .referenced = false,
                .value = value,
            };
        }

        /// Called with the bucket locked. The same token's slot (another set
        /// or a racing insert), else a free one, else one past its `exp`,
        /// else CLOCK: the first from the hand without its second chance.
        fn pickSlot(b: *Bucket, digest: [digest_len]u8, now_s: i64) usize {
            for (&b.entries, 0..) |*e, i| {
                if (e.set_id != 0 and std.mem.eql(u8, &e.digest, &digest)) return i;
            }
            for (&b.entries, 0..) |*e, i| if (e.set_id == 0) return i;
            for (&b.entries, 0..) |*e, i| if (e.dead_after < now_s) return i;
            var i: usize = b.hand;
            while (true) : (i = (i + 1) % ways) {
                const e = &b.entries[i];
                if (e.referenced) {
                    e.referenced = false;
                    continue;
                }
                b.hand = @intCast((i + 1) % ways);
                return i;
            }
        }

        fn digestOf(self: *const Self, token: []const u8, opts: root.Options) [digest_len]u8 {
            return keyDigest(&self.mac_key, self.context_buf[0..self.context_len], token, opts);
        }
    };
}

/// SipHash-2-4-128 under `mac_key` over a domain tag, the claim policy (every
/// `Options` field except `now_s`), the context and the token. Everything
/// before the token is length-delimited and the token comes last, so no two
/// distinct inputs encode alike.
fn keyDigest(mac_key: *const [Mac.key_length]u8, context: []const u8, token: []const u8, opts: root.Options) [digest_len]u8 {
    // A field added to `Options` must be decided here — folded into the key,
    // or excluded like `now_s` — before this compiles again.
    comptime {
        const known = [_][]const u8{ "now_s", "leeway_s", "issuer", "audience", "require_exp", "reject_future_iat" };
        for (@typeInfo(root.Options).@"struct".fields) |f| {
            for (known) |k| {
                if (std.mem.eql(u8, f.name, k)) break;
            } else @compileError("jwt.VerifiedCache: fold Options." ++ f.name ++ " into keyDigest");
        }
    }
    var h: Mac = .init(mac_key);
    h.update("zig-libs jwt.VerifiedCache v1\x00");
    var fixed: [6]u8 = undefined;
    std.mem.writeInt(u32, fixed[0..4], opts.leeway_s, .little);
    fixed[4] = @intFromBool(opts.require_exp);
    fixed[5] = @intFromBool(opts.reject_future_iat);
    h.update(&fixed);
    switch (opts.issuer) {
        .any => h.update(&.{0}),
        .required => |s| updatePrefixed(&h, 1, s),
    }
    switch (opts.audience) {
        .any => h.update(&.{0}),
        .required => |s| updatePrefixed(&h, 1, s),
    }
    updatePrefixed(&h, 2, context);
    h.update(token);
    return h.finalResult();
}

fn updatePrefixed(h: *Mac, tag: u8, bytes: []const u8) void {
    var head: [9]u8 = undefined;
    head[0] = tag;
    std.mem.writeInt(u64, head[1..9], bytes.len, .little);
    h.update(&head);
    h.update(bytes);
}

fn assertPlainData(comptime T: type, comptime what: []const u8) void {
    switch (@typeInfo(T)) {
        .int, .float, .bool, .@"enum", .void => {},
        .array => |a| assertPlainData(a.child, what),
        .vector => |v| assertPlainData(v.child, what),
        .optional => |o| assertPlainData(o.child, what),
        .@"struct" => |s| for (s.fields) |f| assertPlainData(f.type, what),
        .@"union" => |u| for (u.fields) |f| assertPlainData(f.type, what),
        else => @compileError("jwt.VerifiedCache: Value " ++ what ++ " must be plain data (no " ++ @typeName(T) ++ ")"),
    }
}

// ── tests ──────────────────────────────────────────────────────────────────

const testing = std.testing;

/// What a resource server derives: an id and scope bits (qap's shape).
const TestValue = struct {
    id_buf: [32]u8 = @splat(0),
    id_len: u8 = 0,
    scopes: u64 = 0,

    fn id(v: *const TestValue) []const u8 {
        return v.id_buf[0..v.id_len];
    }
};

/// Counts its calls, so a test can tell a hit (no derive) from a miss.
const Deriver = struct {
    calls: usize = 0,

    fn derive(d: *Deriver, parsed: *const root.ParsedToken) ?TestValue {
        d.calls += 1;
        const sub = parsed.claims.claimStr("sub") orelse return null;
        if (sub.len > 32) return null;
        var v: TestValue = .{ .id_len = @intCast(sub.len) };
        @memcpy(v.id_buf[0..sub.len], sub);
        if (parsed.claims.claimStr("scope")) |s| {
            if (std.mem.indexOf(u8, s, "read") != null) v.scopes |= 1;
        }
        return v;
    }
};

const Cache = VerifiedCache(TestValue);

const secret_a = [_]u8{0x11} ** 32;
const secret_b = [_]u8{0x22} ** 32;
// base64url of 32 × 0x11 and 32 × 0x22.
const jwks_a =
    \\{"keys":[{"kty":"oct","kid":"a","k":"ERERERERERERERERERERERERERERERERERERERERERE"}]}
;
const jwks_b =
    \\{"keys":[{"kty":"oct","kid":"b","k":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI"}]}
;

const issuer = "https://issuer.test";

fn policy(now_s: i64) root.Options {
    return .{ .now_s = now_s, .issuer = .{ .required = issuer }, .audience = .{ .required = "api://a" } };
}

fn mint(claims_json: []const u8) ![]u8 {
    return root.encodeJson(testing.allocator, claims_json, .{ .hs256 = &secret_a }, .{ .kid = "a" });
}

fn mintSub(buf: []u8, i: usize, exp: i64) ![]u8 {
    const json = try std.fmt.bufPrint(buf, "{{\"iss\":\"{s}\",\"aud\":\"api://a\",\"sub\":\"user-{d}\",\"exp\":{d}}}", .{ issuer, i, exp });
    return mint(json);
}

test "VerifiedCache: a miss verifies and stores, the repeat is a hit that never derives" {
    var set = try root.parseJwks(testing.allocator, jwks_a);
    defer set.deinit();
    var cache: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 64 });
    defer cache.deinit();
    const token = try mint(
        \\{"iss":"https://issuer.test","aud":"api://a","sub":"alice","scope":"read write","exp":2000}
    );
    defer testing.allocator.free(token);

    var d: Deriver = .{};
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(token, &set, policy(1000)));
    const first = try cache.verifyJwks(testing.allocator, token, &set, policy(1000), &d);
    try testing.expectEqualStrings("alice", first.id());
    try testing.expectEqual(@as(u64, 1), first.scopes);
    try testing.expectEqual(@as(usize, 1), d.calls);

    for (0..3) |_| {
        const again = try cache.verifyJwks(testing.allocator, token, &set, policy(1500), &d);
        try testing.expectEqualStrings("alice", again.id());
        try testing.expectEqual(@as(u64, 1), again.scopes);
    }
    try testing.expectEqual(@as(usize, 1), d.calls); // hits: no parse, no derive
    const hit = (try cache.lookup(token, &set, policy(1500))).?;
    try testing.expectEqualStrings("alice", hit.id());
}

test "VerifiedCache: exp crossing while cached -- the hit refuses exactly as a fresh verify does, and evicts" {
    var set = try root.parseJwks(testing.allocator, jwks_a);
    defer set.deinit();
    var cache: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 64 });
    defer cache.deinit();
    const token = try mint(
        \\{"iss":"https://issuer.test","aud":"api://a","sub":"alice","exp":1000}
    );
    defer testing.allocator.free(token);
    var d: Deriver = .{};
    _ = try cache.verifyJwks(testing.allocator, token, &set, policy(900), &d);

    // Leeway 60: 1060 is the last second a fresh verify accepts.
    try testing.expect((try cache.lookup(token, &set, policy(1060))) != null);
    try testing.expectError(error.Expired, root.parseVerifyJwks(testing.allocator, token, set, policy(1061)));
    try testing.expectError(error.Expired, cache.lookup(token, &set, policy(1061)));
    // Evicted: even a clock stepped back finds nothing now.
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(token, &set, policy(900)));
    // Through the one-call path the refusal is the same, and nothing is stored.
    try testing.expectError(error.Expired, cache.verifyJwks(testing.allocator, token, &set, policy(1061), &d));
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(token, &set, policy(900)));
}

test "VerifiedCache: nbf and iat are re-checked on a hit, in validateClaims' order" {
    var set = try root.parseJwks(testing.allocator, jwks_a);
    defer set.deinit();
    var cache: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 64 });
    defer cache.deinit();
    const token = try mint(
        \\{"iss":"https://issuer.test","aud":"api://a","sub":"alice","nbf":500,"iat":500,"exp":5000}
    );
    defer testing.allocator.free(token);
    var d: Deriver = .{};
    _ = try cache.verifyJwks(testing.allocator, token, &set, policy(500), &d);

    // The clock steps back past nbf - leeway: refused, as a fresh verify is.
    try testing.expectError(error.NotYetValid, root.parseVerifyJwks(testing.allocator, token, set, policy(439)));
    try testing.expectError(error.NotYetValid, cache.lookup(token, &set, policy(439)));
    // Not evicted: once the clock is past nbf again the entry answers.
    try testing.expect((try cache.lookup(token, &set, policy(441))) != null);
    try testing.expectEqual(@as(usize, 1), d.calls);

    // `reject_future_iat` is part of the policy: a separate entry, and its
    // own check on the hit.
    var strict = policy(500);
    strict.reject_future_iat = true;
    _ = try cache.verifyJwks(testing.allocator, token, &set, strict, &d);
    try testing.expectEqual(@as(usize, 2), d.calls);
    strict.now_s = 439;
    try testing.expectError(error.NotYetValid, cache.lookup(token, &set, strict)); // nbf first
}

test "VerifiedCache: a replaced key set invalidates every entry; a dropped key stops verifying" {
    var set1 = try root.parseJwks(testing.allocator, jwks_a);
    defer set1.deinit();
    var cache: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 64 });
    defer cache.deinit();
    const token = try mint(
        \\{"iss":"https://issuer.test","aud":"api://a","sub":"alice","exp":5000}
    );
    defer testing.allocator.free(token);
    var d: Deriver = .{};
    _ = try cache.verifyJwks(testing.allocator, token, &set1, policy(1000), &d);
    try testing.expect((try cache.lookup(token, &set1, policy(1000))) != null);

    // A refresh that returns the SAME keys is still a new set: miss, verify again.
    var set2 = try root.parseJwks(testing.allocator, jwks_a);
    defer set2.deinit();
    try testing.expect(set2.id != set1.id and set1.id != 0 and set2.id != 0);
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(token, &set2, policy(1000)));
    _ = try cache.verifyJwks(testing.allocator, token, &set2, policy(1000), &d);
    try testing.expectEqual(@as(usize, 2), d.calls);

    // A rotation that drops key `a`: the cached token is refused at once.
    var set3 = try root.parseJwks(testing.allocator, jwks_b);
    defer set3.deinit();
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(token, &set3, policy(1000)));
    try testing.expectError(error.NoMatchingKey, cache.verifyJwks(testing.allocator, token, &set3, policy(1000), &d));
}

test "VerifiedCache: another audience, issuer, leeway or context never shares an entry" {
    var set = try root.parseJwks(testing.allocator, jwks_a);
    defer set.deinit();
    var cache: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 64 });
    defer cache.deinit();
    const token = try mint(
        \\{"iss":"https://issuer.test","aud":["api://a","api://b"],"sub":"alice","exp":5000}
    );
    defer testing.allocator.free(token);
    var d: Deriver = .{};
    _ = try cache.verifyJwks(testing.allocator, token, &set, policy(1000), &d);

    var other = policy(1000);
    other.audience = .{ .required = "api://b" };
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(token, &set, other));
    other.audience = .{ .required = "api://c" };
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(token, &set, other));
    try testing.expectError(error.AudienceMismatch, cache.verifyJwks(testing.allocator, token, &set, other, &d));
    other.audience = .any;
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(token, &set, other));

    var wrong_iss = policy(1000);
    wrong_iss.issuer = .{ .required = "https://evil.test" };
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(token, &set, wrong_iss));
    try testing.expectError(error.IssuerMismatch, cache.verifyJwks(testing.allocator, token, &set, wrong_iss, &d));

    var leeway = policy(1000);
    leeway.leeway_s = 0;
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(token, &set, leeway));

    // Same policy, another cache context: its own entries.
    var cache2: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 64, .context = "id=email" });
    defer cache2.deinit();
    const mk: [Mac.key_length]u8 = @splat(9);
    const k1 = keyDigest(&mk, "", token, policy(1000));
    const k2 = keyDigest(&mk, "id=email", token, policy(1000));
    try testing.expect(!std.mem.eql(u8, &k1, &k2));
    try testing.expectEqual(@as(?TestValue, null), try cache2.lookup(token, &set, policy(1000)));
    // now_s is NOT part of the key; the MAC key is.
    const k3 = keyDigest(&mk, "", token, policy(4999));
    try testing.expectEqualSlices(u8, &k1, &k3);
    const other_key: [Mac.key_length]u8 = @splat(10);
    const k4 = keyDigest(&other_key, "", token, policy(1000));
    try testing.expect(!std.mem.eql(u8, &k1, &k4));
    // Two caches draw different keys.
    try testing.expect(!std.mem.eql(u8, &cache.mac_key, &cache2.mac_key));
}

test "VerifiedCache: a token differing in one byte never hits" {
    var set = try root.parseJwks(testing.allocator, jwks_a);
    defer set.deinit();
    var cache: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 64 });
    defer cache.deinit();
    const token = try mint(
        \\{"iss":"https://issuer.test","aud":"api://a","sub":"alice","exp":5000}
    );
    defer testing.allocator.free(token);
    var d: Deriver = .{};
    _ = try cache.verifyJwks(testing.allocator, token, &set, policy(1000), &d);

    const copy = try testing.allocator.dupe(u8, token);
    defer testing.allocator.free(copy);
    for (0..copy.len) |i| {
        const saved = copy[i];
        for ([_]u8{ 0x01, 0x20, 0x80 }) |flip| {
            copy[i] = saved ^ flip;
            try testing.expectEqual(@as(?TestValue, null), try cache.lookup(copy, &set, policy(1000)));
        }
        copy[i] = saved;
    }
    // Truncated and extended: no hit either.
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(token[0 .. token.len - 1], &set, policy(1000)));
    const longer = try std.mem.concat(testing.allocator, u8, &.{ token, "A" });
    defer testing.allocator.free(longer);
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(longer, &set, policy(1000)));
    try testing.expect((try cache.lookup(copy, &set, policy(1000))) != null); // restored: hits
}

test "VerifiedCache: failures are never cached" {
    var set = try root.parseJwks(testing.allocator, jwks_a);
    defer set.deinit();
    var cache: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 64 });
    defer cache.deinit();
    var d: Deriver = .{};

    // Bad signature: the last signature character altered.
    const good = try mint(
        \\{"iss":"https://issuer.test","aud":"api://a","sub":"alice","exp":5000}
    );
    defer testing.allocator.free(good);
    const bad = try testing.allocator.dupe(u8, good);
    defer testing.allocator.free(bad);
    bad[bad.len - 2] = if (bad[bad.len - 2] == 'A') 'B' else 'A';
    for (0..2) |_| {
        try testing.expectError(error.BadSignature, cache.verifyJwks(testing.allocator, bad, &set, policy(1000), &d));
        try testing.expectEqual(@as(?TestValue, null), try cache.lookup(bad, &set, policy(1000)));
    }

    // Expired at verification: refused, not stored as a refusal either.
    const old = try mint(
        \\{"iss":"https://issuer.test","aud":"api://a","sub":"alice","exp":100}
    );
    defer testing.allocator.free(old);
    try testing.expectError(error.Expired, cache.verifyJwks(testing.allocator, old, &set, policy(1000), &d));
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(old, &set, policy(50)));

    // Verified, but the value cannot be derived (no `sub`): not stored.
    const nosub = try mint(
        \\{"iss":"https://issuer.test","aud":"api://a","exp":5000}
    );
    defer testing.allocator.free(nosub);
    try testing.expectError(error.NotDerived, cache.verifyJwks(testing.allocator, nosub, &set, policy(1000), &d));
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(nosub, &set, policy(1000)));
    try testing.expectEqual(@as(usize, 1), d.calls); // only the no-sub token reached derive

    // `insert` refuses a parse of another token and claims that fail now.
    var parsed_good = try root.parse(testing.allocator, good);
    defer parsed_good.deinit();
    cache.insert(nosub, &parsed_good, &set, policy(1000), .{});
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(nosub, &set, policy(1000)));
    cache.insert(good, &parsed_good, &set, policy(6000), .{}); // expired at 6000
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(good, &set, policy(1000)));
    // A set without identity is never cached.
    var anon = set;
    anon.id = 0;
    cache.insert(good, &parsed_good, &anon, policy(1000), .{});
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(good, &anon, policy(1000)));
    _ = try cache.verifyJwks(testing.allocator, good, &anon, policy(1000), &d);
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(good, &anon, policy(1000)));
}

test "VerifiedCache: capacity rounds up; eviction prefers free, then expired, then CLOCK's unreferenced" {
    var set = try root.parseJwks(testing.allocator, jwks_a);
    defer set.deinit();
    try testing.expectError(error.InvalidCapacity, Cache.init(testing.allocator, testing.io, .{ .capacity = 0 }));
    try testing.expectError(error.ContextTooLong, Cache.init(testing.allocator, testing.io, .{ .capacity = 1, .context = &([_]u8{'x'} ** 65) }));
    var big: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 9 });
    try testing.expectEqual(@as(usize, 16), big.capacity()); // 3 buckets -> 4
    big.deinit();

    // One bucket of four: every token lands in it.
    var cache: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 4 });
    defer cache.deinit();
    try testing.expectEqual(@as(usize, 4), cache.capacity());
    var d: Deriver = .{};
    var bufs: [6][160]u8 = undefined;
    var tokens: [6][]u8 = undefined;
    for (&tokens, 0..) |*t, i| t.* = try mintSub(&bufs[i], i, if (i == 1) 1100 else 5000);
    defer for (tokens) |t| testing.allocator.free(t);

    for (tokens[0..4]) |t| _ = try cache.verifyJwks(testing.allocator, t, &set, policy(1000), &d);
    for (tokens[0..4]) |t| try testing.expect((try cache.lookup(t, &set, policy(1000))) != null);

    // Token 1 is past exp + leeway at 2000: it is the victim, even though referenced.
    _ = try cache.verifyJwks(testing.allocator, tokens[4], &set, policy(2000), &d);
    try testing.expectEqual(@as(?TestValue, null), try cache.lookup(tokens[1], &set, policy(1000)));
    for ([_]usize{ 0, 2, 3, 4 }) |i| try testing.expect((try cache.lookup(tokens[i], &set, policy(2000))) != null);

    // All four referenced: CLOCK clears the bits in one sweep and takes the
    // first slot from the hand; re-referencing all but one before the next
    // insert makes that one the victim.
    _ = try cache.verifyJwks(testing.allocator, tokens[5], &set, policy(2000), &d);
    var present: usize = 0;
    for (tokens) |t| {
        if ((try cache.lookup(t, &set, policy(2000))) != null) present += 1;
    }
    try testing.expectEqual(@as(usize, 4), present);
    try testing.expect((try cache.lookup(tokens[5], &set, policy(2000))) != null);
    try testing.expectEqual(@as(usize, 6), d.calls);

    cache.clear();
    for (tokens) |t| try testing.expectEqual(@as(?TestValue, null), try cache.lookup(t, &set, policy(2000)));
}

test "VerifiedCache: CLOCK gives a referenced entry its second chance" {
    var set = try root.parseJwks(testing.allocator, jwks_a);
    defer set.deinit();
    var cache: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 4 });
    defer cache.deinit();
    var d: Deriver = .{};
    var bufs: [8][160]u8 = undefined;
    var tokens: [8][]u8 = undefined;
    for (&tokens, 0..) |*t, i| t.* = try mintSub(&bufs[i], i, 5000);
    defer for (tokens) |t| testing.allocator.free(t);

    for (tokens[0..4]) |t| _ = try cache.verifyJwks(testing.allocator, t, &set, policy(1000), &d);
    // Only token 0 is used again; the next four inserts must never evict it
    // while an unreferenced entry is available.
    for (tokens[4..8]) |t| {
        try testing.expect((try cache.lookup(tokens[0], &set, policy(1000))) != null);
        _ = try cache.verifyJwks(testing.allocator, t, &set, policy(1000), &d);
    }
    try testing.expect((try cache.lookup(tokens[0], &set, policy(1000))) != null);
    try testing.expect((try cache.lookup(tokens[7], &set, policy(1000))) != null);
}

test "VerifiedCache: several threads hammering one small table never see a torn entry" {
    var set = try root.parseJwks(testing.allocator, jwks_a);
    defer set.deinit();
    // A wide value, so a torn copy would show as mixed bytes.
    const Wide = struct { bytes: [200]u8 };
    const WideCache = VerifiedCache(Wide);
    var cache: WideCache = try .init(testing.allocator, testing.io, .{ .capacity = 8 });
    defer cache.deinit();

    const n_tokens = 24;
    var bufs: [n_tokens][160]u8 = undefined;
    var tokens: [n_tokens][]u8 = undefined;
    var parsed: [n_tokens]root.ParsedToken = undefined;
    for (0..n_tokens) |i| {
        tokens[i] = try mintSub(&bufs[i], i, 5000);
        parsed[i] = try root.parse(testing.allocator, tokens[i]);
    }
    defer for (0..n_tokens) |i| {
        parsed[i].deinit();
        testing.allocator.free(tokens[i]);
    };

    const Worker = struct {
        fn run(c: *WideCache, s: *const root.JwkSet, toks: *const [n_tokens][]u8, ps: *const [n_tokens]root.ParsedToken, seed: u64, bad: *std.atomic.Value(usize), hits: *std.atomic.Value(usize)) void {
            var prng: std.Random.DefaultPrng = .init(seed);
            const r = prng.random();
            for (0..20_000) |_| {
                const i = r.uintLessThan(usize, n_tokens);
                const got = c.lookup(toks[i], s, policy(1000)) catch {
                    _ = bad.fetchAdd(1, .monotonic);
                    continue;
                };
                if (got) |v| {
                    _ = hits.fetchAdd(1, .monotonic);
                    for (v.bytes) |b| {
                        if (b != @as(u8, @intCast(i))) {
                            _ = bad.fetchAdd(1, .monotonic);
                            break;
                        }
                    }
                } else {
                    c.insert(toks[i], &ps[i], s, policy(1000), .{ .bytes = @splat(@intCast(i)) });
                }
            }
        }
    };
    var bad: std.atomic.Value(usize) = .init(0);
    var hits: std.atomic.Value(usize) = .init(0);
    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*t, k| t.* = try std.Thread.spawn(.{}, Worker.run, .{ &cache, &set, &tokens, &parsed, k + 1, &bad, &hits });
    for (threads) |t| t.join();
    try testing.expectEqual(@as(usize, 0), bad.load(.monotonic));
    try testing.expect(hits.load(.monotonic) > 0);
}

test "VerifiedCache: ES256 end to end -- the hit returns what the verify derived" {
    const kp = try root.EcdsaP256Sha256.KeyPair.generateDeterministic([_]u8{0x42} ** root.EcdsaP256Sha256.KeyPair.seed_length);
    const sec1 = kp.public_key.toUncompressedSec1();
    const enc = std.base64.url_safe_no_pad.Encoder;
    var x: [43]u8 = undefined;
    var y: [43]u8 = undefined;
    _ = enc.encode(&x, sec1[1..33]);
    _ = enc.encode(&y, sec1[33..65]);
    var json_buf: [256]u8 = undefined;
    const json = try std.fmt.bufPrint(&json_buf, "{{\"keys\":[{{\"kty\":\"EC\",\"crv\":\"P-256\",\"kid\":\"e\",\"x\":\"{s}\",\"y\":\"{s}\"}}]}}", .{ &x, &y });
    var set = try root.parseJwksSource(testing.allocator, json, .network);
    defer set.deinit();
    const token = try root.encodeJson(testing.allocator,
        \\{"iss":"https://issuer.test","aud":"api://a","sub":"bob","scope":"read","exp":5000}
    , .{ .es256 = &kp }, .{ .kid = "e" });
    defer testing.allocator.free(token);

    var cache: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 16 });
    defer cache.deinit();
    var d: Deriver = .{};
    const a = try cache.verifyJwks(testing.allocator, token, &set, policy(1000), &d);
    const b = try cache.verifyJwks(testing.allocator, token, &set, policy(1000), &d);
    try testing.expectEqualStrings("bob", b.id());
    try testing.expectEqual(a.scopes, b.scopes);
    try testing.expectEqual(@as(usize, 1), d.calls);
}

test "JwkSet ids: every parsed set gets a fresh, nonzero id" {
    var a = try root.parseJwks(testing.allocator, jwks_a);
    defer a.deinit();
    var b = try root.parseJwks(testing.allocator, jwks_a);
    defer b.deinit();
    try testing.expect(a.id != 0 and b.id != 0 and a.id != b.id);
}

test "VerifiedCache: deinit wipes the MAC key" {
    var cache: Cache = try .init(testing.allocator, testing.io, .{ .capacity = 4 });
    const zero: [Mac.key_length]u8 = @splat(0);
    try testing.expect(!std.mem.eql(u8, &cache.mac_key, &zero)); // drawn, not left zero
    cache.deinit();
    try testing.expectEqualSlices(u8, &zero, &cache.mac_key);
}
