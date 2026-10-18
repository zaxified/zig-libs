// SPDX-License-Identifier: MIT

//! Ready-made authorization for the broker's hooks: an `Acl` (topic access
//! rules, `Config.authorizeFn`) and a `Passwords` table (`Config.authenticateFn`).
//!
//! Both are plain data over caller-provided storage; the check paths do not
//! allocate. Plug in:
//!
//! ```zig
//! var acl = try acl_mod.Acl.parse(acl_text, &rule_buf);
//! var pw = try acl_mod.Passwords.parse(password_text, &entry_buf);
//! var b = Broker.init(gpa, .{
//!     .authorizeFn = acl_mod.authorize, .acl_ctx = &acl,
//!     .authenticateFn = acl_mod.authenticate, .auth_ctx = &pw,
//! });
//! ```
//!
//! The ACL text format and its semantics follow the documented behaviour of
//! Mosquitto's `acl_file` (mosquitto.conf(5)); the password format is the
//! `$7$` form of Mosquitto's `password_file`. Written from the documentation
//! only, no Mosquitto source consulted.
//!
//! ACL file: one directive per line, `#` starts a comment line, blank lines
//! are ignored.
//!
//! ```text
//! topic [read|write|readwrite|deny] <topic>
//! user <name>
//! pattern [read|write|readwrite|deny] <topic>
//! ```
//!
//! - `topic` lines before the first `user` line apply to anonymous clients
//!   (no username); after `user X` they apply to the client with username X.
//! - `pattern` lines apply to every client, with `%u` replaced by its
//!   username and `%c` by its client id.
//! - The access word defaults to `readwrite`. `read` is what a SUBSCRIBE
//!   needs, `write` what a PUBLISH (and a Will) needs. If the word is
//!   followed by nothing (`topic read`) it is the topic, not an access word.
//! - The topic is a filter: `+` and `#` in a rule cover what they would
//!   match as a subscription. A SUBSCRIBE is allowed only if the rule covers
//!   the whole requested filter (`a/#` covers `a/b/+`; `a/b` does not cover
//!   `a/#`). As for subscriptions, a rule whose first level is a wildcard
//!   does not cover `$`-topics.
//! - Deny wins: if any applicable rule that matches says `deny`, the answer
//!   is no. For a SUBSCRIBE a deny rule "matches" when its topic merely
//!   overlaps the requested filter (some topic name could match both):
//!   `deny private/+` refuses `private/#`, `#` and `+/x`, not `public/#`.
//!   Conservative on purpose. To be exact a broker must ALSO check read
//!   access for every delivered message, as Mosquitto does; that is the
//!   broker's job, not this helper's. Otherwise yes if some matching rule
//!   grants the needed access; with no matching rule the answer is no.
//!
//! `%u` / `%c` safety (a known pitfall of substitution ACLs): a username or
//! client id that contains `/`, `+` or `#` (or is empty) never matches a
//! pattern that uses it. Substituted text could otherwise add topic levels
//! or wildcards of its own and widen `sensors/%u/#` to a wider subtree. A
//! client without a username never matches a `%u` pattern.

const std = @import("std");
const burn = @import("burn.zig");
const b64ct = @import("b64ct");
const broker = @import("broker.zig");
const topic_rules = @import("topic.zig");

// ── Acl ─────────────────────────────────────────────────────────────────────

pub const Access = enum { read, write, readwrite, deny };

pub const Scope = enum {
    /// A `topic` line before any `user` line: clients without a username.
    anonymous,
    /// A `topic` line under `user <name>`.
    user,
    /// A `pattern` line: every client, `%u` / `%c` substituted.
    pattern,
};

pub const Rule = struct {
    scope: Scope,
    /// The username of a `.user` rule.
    user: []const u8 = "",
    access: Access,
    /// A topic filter; for `.pattern` it may hold `%u` and `%c`.
    topic: []const u8,
};

pub const ParseError = error{
    /// A line starting with something other than topic / user / pattern.
    UnknownDirective,
    /// `user` / `topic` / `pattern` without its argument.
    MissingArgument,
    /// The topic is not a valid topic filter.
    InvalidTopic,
    /// More rules than the caller's buffer holds.
    TooManyRules,
};

pub const Acl = struct {
    rules: []const Rule,

    pub fn init(rules: []const Rule) Acl {
        return .{ .rules = rules };
    }

    /// Parse acl_file text into `rules_buf`. The rules point into `text`,
    /// which must outlive the `Acl`.
    pub fn parse(text: []const u8, rules_buf: []Rule) ParseError!Acl {
        var line: usize = 0;
        return parseWithLine(text, rules_buf, &line);
    }

    /// `parse`, also reporting the 1-based number of the offending line in
    /// `line_out` when it fails.
    pub fn parseWithLine(text: []const u8, rules_buf: []Rule, line_out: *usize) ParseError!Acl {
        var n: usize = 0;
        var current_user: ?[]const u8 = null;
        var lines = std.mem.splitScalar(u8, text, '\n');
        var lineno: usize = 0;
        while (lines.next()) |raw| {
            lineno += 1;
            line_out.* = lineno;
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            const kw_end = std.mem.indexOfAny(u8, line, " \t") orelse line.len;
            const kw = line[0..kw_end];
            const rest = std.mem.trim(u8, line[kw_end..], " \t");
            if (std.mem.eql(u8, kw, "user")) {
                if (rest.len == 0) return error.MissingArgument;
                current_user = rest;
            } else if (std.mem.eql(u8, kw, "topic") or std.mem.eql(u8, kw, "pattern")) {
                if (rest.len == 0) return error.MissingArgument;
                var access: Access = .readwrite;
                var topic = rest;
                const w_end = std.mem.indexOfAny(u8, rest, " \t") orelse rest.len;
                if (w_end < rest.len) if (std.meta.stringToEnum(Access, rest[0..w_end])) |a| {
                    access = a;
                    topic = std.mem.trim(u8, rest[w_end..], " \t");
                };
                topic_rules.validateFilter(topic) catch return error.InvalidTopic;
                if (n >= rules_buf.len) return error.TooManyRules;
                const is_pattern = kw[1] == 'a';
                rules_buf[n] = .{
                    .scope = if (is_pattern) .pattern else if (current_user != null) .user else .anonymous,
                    .user = if (!is_pattern) current_user orelse "" else "",
                    .access = access,
                    .topic = topic,
                };
                n += 1;
            } else return error.UnknownDirective;
        }
        return .{ .rules = rules_buf[0..n] };
    }

    /// May this PUBLISH (write) or SUBSCRIBE (read) go ahead? See the module
    /// comment for the rules.
    pub fn check(a: Acl, req: broker.AclRequest) bool {
        var allowed = false;
        for (a.rules) |r| {
            switch (r.scope) {
                .anonymous => if (req.username != null) continue,
                .user => if (req.username == null or !std.mem.eql(u8, req.username.?, r.user)) continue,
                .pattern => {},
            }
            // Fail closed: a deny pattern whose `%u` / `%c` value cannot be
            // substituted safely (it holds `/ + #`) would otherwise stop
            // applying to exactly the identity that tries to dodge it.
            if (r.scope == .pattern and r.access == .deny and patternRefused(r, req)) return false;
            // A deny rule that merely overlaps a requested filter denies it
            // (conservative); every other check needs full coverage.
            if (!ruleMatches(r, req, r.access == .deny and req.operation == .subscribe)) continue;
            switch (r.access) {
                .deny => return false,
                .readwrite => allowed = true,
                .read => if (req.operation == .subscribe) {
                    allowed = true;
                },
                .write => if (req.operation == .publish) {
                    allowed = true;
                },
            }
        }
        return allowed;
    }
};

/// `Config.authorizeFn`-shaped: `ctx` is a `*const Acl`. A null ctx denies.
pub fn authorize(ctx: ?*anyopaque, req: broker.AclRequest) bool {
    const a: *const Acl = @ptrCast(@alignCast(ctx orelse return false));
    return a.check(req);
}

fn plainName(s: []const u8) bool {
    return s.len > 0 and std.mem.indexOfAny(u8, s, "/+#") == null;
}

/// Does this pattern use a substitution whose value (present, but empty or
/// holding `/ + #`) cannot be put into a topic safely?
fn patternRefused(r: Rule, req: broker.AclRequest) bool {
    if (std.mem.indexOf(u8, r.topic, "%u") != null) {
        if (req.username) |u| if (!plainName(u)) return true;
    }
    if (std.mem.indexOf(u8, r.topic, "%c") != null and !plainName(req.client_id)) return true;
    return false;
}

fn ruleMatches(r: Rule, req: broker.AclRequest, overlap: bool) bool {
    if (r.scope != .pattern) return if (overlap) overlaps(r.topic, req.topic, null) else covers(r.topic, req.topic, null);
    var subst = Subst{ .username = "", .client_id = "" };
    if (std.mem.indexOf(u8, r.topic, "%u") != null) {
        const u = req.username orelse return false;
        if (!plainName(u)) return false;
        subst.username = u;
    }
    if (std.mem.indexOf(u8, r.topic, "%c") != null) {
        if (!plainName(req.client_id)) return false;
        subst.client_id = req.client_id;
    }
    return if (overlap) overlaps(r.topic, req.topic, subst) else covers(r.topic, req.topic, subst);
}

const Subst = struct { username: []const u8, client_id: []const u8 };

/// Does the rule filter cover everything `target` (a topic name, or a
/// subscription filter) names? Level by level, like `topic.matches`, but the
/// target's own wildcards count as literals the rule must cover.
fn covers(rule: []const u8, target: []const u8, subst: ?Subst) bool {
    var ri = std.mem.splitScalar(u8, rule, '/');
    var ti = std.mem.splitScalar(u8, target, '/');
    var first = true;
    while (true) {
        const rl = ri.next() orelse return ti.next() == null;
        if (std.mem.eql(u8, rl, "#")) return !(first and target.len > 0 and target[0] == '$');
        const tl = ti.next() orelse return false;
        if (std.mem.eql(u8, rl, "+")) {
            if (std.mem.eql(u8, tl, "#")) return false;
            if (first and tl.len > 0 and tl[0] == '$') return false;
        } else if (!levelEq(rl, tl, subst)) return false;
        first = false;
    }
}

/// Could some topic name match both the rule filter and `target` (a
/// subscription filter)? `+` / `#` on either side count as wildcards.
fn overlaps(rule: []const u8, target: []const u8, subst: ?Subst) bool {
    var ri = std.mem.splitScalar(u8, rule, '/');
    var ti = std.mem.splitScalar(u8, target, '/');
    var first = true;
    while (true) {
        const rl = ri.next();
        const tl = ti.next();
        if (rl == null and tl == null) return true;
        if (rl == null) return std.mem.eql(u8, tl.?, "#"); // "a/#" also matches "a"
        if (tl == null) return std.mem.eql(u8, rl.?, "#");
        const r_hash = std.mem.eql(u8, rl.?, "#");
        const t_hash = std.mem.eql(u8, tl.?, "#");
        const r_wild = r_hash or std.mem.eql(u8, rl.?, "+");
        const t_wild = t_hash or std.mem.eql(u8, tl.?, "+");
        // a first-level wildcard never matches a `$` topic
        if (first and ((r_wild and !t_wild and tl.?.len > 0 and tl.?[0] == '$') or
            (t_wild and !r_wild and rl.?.len > 0 and rl.?[0] == '$'))) return false;
        if (r_hash or t_hash) return true;
        if (!r_wild and !t_wild and !levelEq(rl.?, tl.?, subst)) return false;
        first = false;
    }
}

/// Compare a rule level with a target level, substituting `%u` / `%c` in the
/// rule level when `subst` is given.
fn levelEq(rl: []const u8, tl: []const u8, subst: ?Subst) bool {
    const s = subst orelse return std.mem.eql(u8, rl, tl);
    var pos: usize = 0;
    var i: usize = 0;
    while (i < rl.len) {
        if (rl[i] == '%' and i + 1 < rl.len and (rl[i + 1] == 'u' or rl[i + 1] == 'c')) {
            const v = if (rl[i + 1] == 'u') s.username else s.client_id;
            if (!std.mem.startsWith(u8, tl[pos..], v)) return false;
            pos += v.len;
            i += 2;
        } else {
            if (pos >= tl.len or tl[pos] != rl[i]) return false;
            pos += 1;
            i += 1;
        }
    }
    return pos == tl.len;
}

// ── Passwords ───────────────────────────────────────────────────────────────

/// One account: the username and its stored hash in `$7$<iterations>$<salt>$<hash>`
/// form (base64 salt and 64-byte PBKDF2-HMAC-SHA512 hash, standard alphabet
/// with padding), as in Mosquitto's `password_file` (`user:$7$1000$<salt>$<hash>`; the tool writes a 64-byte salt).
pub const Entry = struct {
    username: []const u8,
    hash: []const u8,
};

pub const PasswordParseError = error{
    /// A line without `user:hash`, or a hash that is not valid `$7$`.
    InvalidEntry,
    TooManyEntries,
};

/// The most PBKDF2 iterations a stored hash may ask for (bounds the cost of
/// one login attempt against a hostile file).
pub const max_iterations = 10_000_000;
pub const hash_len = 64;
pub const max_salt_len = 64;
/// The iteration count `mosquitto_passwd` 2.1 writes (the stored field is
/// read from each line, so other counts verify too).
pub const default_iterations = 1000;

const Parsed = struct {
    iterations: u32,
    salt: [max_salt_len]u8,
    salt_len: usize,
    hash: [hash_len]u8,
};

fn parseHash(text: []const u8) ?Parsed {
    if (!std.mem.startsWith(u8, text, "$7$")) return null;
    var it = std.mem.splitScalar(u8, text[3..], '$');
    const iter_s = it.next() orelse return null;
    const salt_s = it.next() orelse return null;
    const hash_s = it.next() orelse return null;
    if (it.next() != null) return null;
    if (iter_s.len == 0 or !std.ascii.isDigit(iter_s[0])) return null; // no sign
    const iterations = std.fmt.parseInt(u32, iter_s, 10) catch return null;
    if (iterations == 0 or iterations > max_iterations) return null;
    // Constant-time decode (b64ct): the stored verifier is compared against
    // a derived key, so its characters must not index a table.
    const dec = b64ct.standard;
    var p: Parsed = .{ .iterations = iterations, .salt = undefined, .salt_len = 0, .hash = undefined };
    p.salt_len = dec.decodedLen(salt_s) catch return null;
    if (p.salt_len == 0 or p.salt_len > max_salt_len) return null;
    _ = dec.decode(p.salt[0..p.salt_len], salt_s) catch return null;
    if ((dec.decodedLen(hash_s) catch return null) != hash_len) return null;
    _ = dec.decode(&p.hash, hash_s) catch return null;
    return p;
}

fn derive(out: *[hash_len]u8, password: []const u8, salt: []const u8, iterations: u32) bool {
    std.crypto.pwhash.pbkdf2(out, password, salt, iterations, std.crypto.auth.hmac.sha2.HmacSha512) catch return false;
    return true;
}

/// Write a `$7$` hash of `password` with `salt` (any 1..64 bytes; Mosquitto
/// uses 12 random ones) into `out`; returns the used part. Use it to build a
/// password file. `error.NoSpaceLeft` when `out` is too small (~ 130 bytes
/// are enough for a 12-byte salt).
pub fn formatHash(out: []u8, password: []const u8, salt: []const u8, iterations: u32) error{ NoSpaceLeft, InvalidParameters }![]u8 {
    return burn.run(burn.cred_burn, error{ NoSpaceLeft, InvalidParameters }![]u8, formatHashBody, .{ out, password, salt, iterations });
}

fn formatHashBody(out: []u8, password: []const u8, salt: []const u8, iterations: u32) error{ NoSpaceLeft, InvalidParameters }![]u8 {
    if (salt.len == 0 or salt.len > max_salt_len or iterations == 0 or iterations > max_iterations) return error.InvalidParameters;
    var dk: [hash_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &dk);
    if (!derive(&dk, password, salt, iterations)) return error.InvalidParameters;
    var salt_b64: [b64ct.standard.encodedLen(max_salt_len)]u8 = undefined;
    var hash_b64: [b64ct.standard.encodedLen(hash_len)]u8 = undefined;
    const s = b64ct.standard.encode(&salt_b64, salt);
    const h = b64ct.standard.encode(&hash_b64, &dk);
    return std.fmt.bufPrint(out, "$7${d}${s}${s}", .{ iterations, s, h });
}

pub const Passwords = struct {
    entries: []const Entry,
    /// Accept a CONNECT without a username. A CONNECT WITH a username is
    /// always checked against the table, whatever this says.
    allow_anonymous: bool = false,

    pub fn init(entries: []const Entry, allow_anonymous: bool) Passwords {
        return .{ .entries = entries, .allow_anonymous = allow_anonymous };
    }

    /// Parse password_file text (`user:$7$...` per line, blank lines
    /// skipped) into `buf`. The entries point into `text`. Every hash is
    /// validated now, so a bad file fails at load, not at the first login.
    pub fn parse(text: []const u8, buf: []Entry) PasswordParseError!Passwords {
        var n: usize = 0;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0) continue;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidEntry;
            if (colon == 0) return error.InvalidEntry;
            const hash = line[colon + 1 ..];
            if (parseHash(hash) == null) return error.InvalidEntry;
            if (n >= buf.len) return error.TooManyEntries;
            buf[n] = .{ .username = line[0..colon], .hash = hash };
            n += 1;
        }
        return .{ .entries = buf[0..n] };
    }

    /// Check one login. The comparison of the derived hash is constant time,
    /// and an unknown user costs the same PBKDF2 run as a known one, so
    /// timing does not reveal which usernames exist.
    ///
    /// Runs one frame down under a dead-stack burn (`burn.cred_burn`): PBKDF2
    /// keeps HMAC states keyed with the password on the stack.
    pub fn verify(p: Passwords, username: []const u8, password: []const u8) bool {
        return burn.run(burn.cred_burn, bool, verifyBody, .{ &p, username, password });
    }

    fn verifyBody(p: *const Passwords, username: []const u8, password: []const u8) bool {
        var found: ?Parsed = null;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&found)); // holds the stored hash
        for (p.entries) |e| {
            if (std.mem.eql(u8, e.username, username)) {
                found = parseHash(e.hash);
                break;
            }
        }
        const dummy_salt = [_]u8{0} ** 12;
        const salt = if (found) |f| f.salt[0..f.salt_len] else &dummy_salt;
        const iterations = if (found) |f| f.iterations else p.dummyIterations();
        var dk: [hash_len]u8 = undefined;
        defer std.crypto.secureZero(u8, &dk);
        if (!derive(&dk, password, salt, iterations)) return false;
        const f = found orelse return false;
        return std.crypto.timing_safe.eql([hash_len]u8, dk, f.hash);
    }

    /// The PBKDF2 cost an unknown user is charged: the highest iteration
    /// count in the table, so a login attempt costs the same whether the name
    /// exists or not (when every account has the same count; a table with
    /// mixed counts leaks through the difference, as any choice would).
    pub fn dummyIterations(p: Passwords) u32 {
        var m: u32 = 0;
        for (p.entries) |e| if (parseHash(e.hash)) |h| {
            m = @max(m, h.iterations);
        };
        return if (m == 0) default_iterations else m;
    }
};

/// `Config.authenticateFn`-shaped: `ctx` is a `*const Passwords`. A null ctx
/// refuses everything.
pub fn authenticate(ctx: ?*anyopaque, req: broker.AuthRequest) broker.AuthDecision {
    const p: *const Passwords = @ptrCast(@alignCast(ctx orelse return .deny_not_authorized));
    const user = req.username orelse
        return if (p.allow_anonymous) .allow else .deny_not_authorized;
    const pw = req.password orelse {
        // Still pay for the PBKDF2 run, as for a wrong password.
        _ = p.verify(user, "");
        return .deny_bad_credentials;
    };
    return if (p.verify(user, pw)) .allow else .deny_bad_credentials;
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

fn rq(op: broker.Operation, topic: []const u8, user: ?[]const u8, cid: []const u8) broker.AclRequest {
    return .{ .client_id = cid, .username = user, .topic = topic, .operation = op };
}

test "acl: read / write / readwrite, default access, and the unlisted default of no" {
    var buf: [8]Rule = undefined;
    const a = try Acl.parse(
        \\# comment
        \\user alice
        \\topic read sensors/#
        \\topic write cmd/alice
        \\topic data/alice
        \\
    , &buf);
    try testing.expectEqual(@as(usize, 3), a.rules.len);
    try testing.expect(a.check(rq(.subscribe, "sensors/a/b", "alice", "c")));
    try testing.expect(!a.check(rq(.publish, "sensors/a/b", "alice", "c")));
    try testing.expect(a.check(rq(.publish, "cmd/alice", "alice", "c")));
    try testing.expect(!a.check(rq(.subscribe, "cmd/alice", "alice", "c")));
    try testing.expect(a.check(rq(.publish, "data/alice", "alice", "c")));
    try testing.expect(a.check(rq(.subscribe, "data/alice", "alice", "c")));
    try testing.expect(!a.check(rq(.publish, "other", "alice", "c")));
    // rules of alice are not bob's, and not an anonymous client's
    try testing.expect(!a.check(rq(.subscribe, "sensors/a", "bob", "c")));
    try testing.expect(!a.check(rq(.subscribe, "sensors/a", null, "c")));
}

test "acl: anonymous rules before the first user line; user rules; patterns for all" {
    var buf: [8]Rule = undefined;
    const a = try Acl.parse(
        \\topic read public/#
        \\user bob
        \\topic write bob/out
        \\pattern readwrite own/%u/#
        \\
    , &buf);
    try testing.expect(a.check(rq(.subscribe, "public/x", null, "c")));
    try testing.expect(!a.check(rq(.subscribe, "public/x", "bob", "c"))); // anonymous-only
    try testing.expect(a.check(rq(.publish, "bob/out", "bob", "c")));
    try testing.expect(!a.check(rq(.publish, "bob/out", null, "c")));
    try testing.expect(a.check(rq(.publish, "own/bob/x/y", "bob", "c")));
    try testing.expect(a.check(rq(.publish, "own/carol/x", "carol", "c")));
    try testing.expect(!a.check(rq(.publish, "own/bob/x", "carol", "c")));
    try testing.expect(!a.check(rq(.publish, "own/anon/x", null, "c"))); // no username, no %u
}

test "acl: deny wins over any grant, whatever the order or scope" {
    var buf: [8]Rule = undefined;
    const a = try Acl.parse(
        \\pattern deny secret/#
        \\user alice
        \\topic readwrite #
        \\topic deny private/+
        \\
    , &buf);
    try testing.expect(a.check(rq(.publish, "any/topic", "alice", "c")));
    try testing.expect(!a.check(rq(.publish, "private/x", "alice", "c")));
    try testing.expect(!a.check(rq(.subscribe, "private/x", "alice", "c")));
    try testing.expect(a.check(rq(.publish, "private/x/y", "alice", "c"))); // + is one level
    try testing.expect(!a.check(rq(.publish, "secret/x", "alice", "c"))); // the pattern deny
    try testing.expect(!a.check(rq(.subscribe, "secret/#", "alice", "c")));
}

test "acl: wildcard rules cover subscriptions only when they cover the whole filter" {
    var buf: [8]Rule = undefined;
    const a = try Acl.parse(
        \\topic read a/#
        \\topic read b/+/c
        \\topic read d/e
        \\
    , &buf);
    try testing.expect(a.check(rq(.subscribe, "a/#", null, "c")));
    try testing.expect(a.check(rq(.subscribe, "a/b/+", null, "c")));
    try testing.expect(a.check(rq(.subscribe, "a", null, "c"))); // # covers the parent level
    try testing.expect(a.check(rq(.subscribe, "b/+/c", null, "c")));
    try testing.expect(a.check(rq(.subscribe, "b/x/c", null, "c")));
    try testing.expect(!a.check(rq(.subscribe, "b/#", null, "c")));
    try testing.expect(!a.check(rq(.subscribe, "b/+/+", null, "c")));
    try testing.expect(!a.check(rq(.subscribe, "d/#", null, "c")));
    try testing.expect(!a.check(rq(.subscribe, "d/+", null, "c")));
    try testing.expect(!a.check(rq(.subscribe, "#", null, "c")));
    try testing.expect(a.check(rq(.subscribe, "d/e", null, "c")));
}

test "acl: a wildcard first level does not cover $-topics" {
    var buf: [4]Rule = undefined;
    const a = try Acl.parse("topic read #\ntopic read $SYS/#\n", &buf);
    try testing.expect(a.check(rq(.subscribe, "x/y", null, "c")));
    try testing.expect(a.check(rq(.subscribe, "$SYS/broker", null, "c"))); // the explicit rule
    var b2: [4]Rule = undefined;
    const only_hash = try Acl.parse("topic read #\n", &b2);
    try testing.expect(!only_hash.check(rq(.subscribe, "$SYS/broker", null, "c")));
}

test "acl: %u and %c substitute; a name with / + # never matches" {
    var buf: [4]Rule = undefined;
    const a = try Acl.parse(
        \\pattern readwrite users/%u/#
        \\pattern readwrite dev/%c/state
        \\pattern read mix/%u-%c
        \\
    , &buf);
    try testing.expect(a.check(rq(.publish, "users/alice/x", "alice", "c1")));
    try testing.expect(!a.check(rq(.publish, "users/bob/x", "alice", "c1")));
    try testing.expect(a.check(rq(.publish, "dev/c1/state", "alice", "c1")));
    try testing.expect(!a.check(rq(.publish, "dev/c2/state", "alice", "c1")));
    try testing.expect(a.check(rq(.subscribe, "mix/alice-c1", "alice", "c1")));
    try testing.expect(!a.check(rq(.subscribe, "mix/alice-c2", "alice", "c1")));
    // the pitfall: a name that would widen the pattern
    try testing.expect(!a.check(rq(.subscribe, "users/+/x", "+", "c1")));
    try testing.expect(!a.check(rq(.subscribe, "users/#", "#", "c1")));
    try testing.expect(!a.check(rq(.publish, "users/a/b/x", "a/b", "c1")));
    try testing.expect(!a.check(rq(.publish, "users/a/b/x", "a/b", "c1")));
    try testing.expect(!a.check(rq(.subscribe, "dev/+/state", "u", "+")));
    try testing.expect(!a.check(rq(.publish, "dev/x/y/state", "u", "x/y")));
    try testing.expect(!a.check(rq(.publish, "users//x", "", "c1"))); // empty name
    // and a client's wildcard filter is not covered by its own name
    try testing.expect(!a.check(rq(.subscribe, "users/+/x", "alice", "c1")));
}

test "acl: parse errors name the line" {
    var buf: [2]Rule = undefined;
    var line: usize = 0;
    try testing.expectError(error.UnknownDirective, Acl.parseWithLine("topic a\nfrobnicate x\n", &buf, &line));
    try testing.expectEqual(@as(usize, 2), line);
    try testing.expectError(error.MissingArgument, Acl.parseWithLine("user\n", &buf, &line));
    try testing.expectError(error.MissingArgument, Acl.parseWithLine("topic\n", &buf, &line));
    try testing.expectError(error.MissingArgument, Acl.parseWithLine("# c\n\ntopic   \n", &buf, &line));
    try testing.expectEqual(@as(usize, 3), line);
    try testing.expectError(error.InvalidTopic, Acl.parse("topic read a/#/b\n", &buf));
}

test "acl: an access word alone is a topic name; too many rules; CRLF" {
    var buf: [2]Rule = undefined;
    const a = try Acl.parse("topic read\r\ntopic write w\r\n", &buf);
    try testing.expectEqualStrings("read", a.rules[0].topic);
    try testing.expectEqual(Access.readwrite, a.rules[0].access);
    try testing.expectEqual(Access.write, a.rules[1].access);
    try testing.expectError(error.TooManyRules, Acl.parse("topic a\ntopic b\ntopic c\n", &buf));
}

// ── passwords ───────────────────────────────────────────────────────────────

fn makeLine(out: []u8, user: []const u8, password: []const u8, salt: []const u8, iterations: u32) ![]u8 {
    var h: [200]u8 = undefined;
    const hash = try formatHash(&h, password, salt, iterations);
    return std.fmt.bufPrint(out, "{s}:{s}\n", .{ user, hash });
}

test "passwords: ok, wrong, unknown user, no password, anonymous" {
    var text_buf: [512]u8 = undefined;
    var n: usize = 0;
    n += (try makeLine(text_buf[n..], "alice", "s3cret", "0123456789ab", 101)).len;
    n += (try makeLine(text_buf[n..], "bob", "hunter2", "ba9876543210", 7)).len;
    var entries: [4]Entry = undefined;
    var pw = try Passwords.parse(text_buf[0..n], &entries);
    try testing.expectEqual(@as(usize, 2), pw.entries.len);
    const ctx: ?*anyopaque = &pw;
    const A = broker.AuthRequest;
    try testing.expectEqual(broker.AuthDecision.allow, authenticate(ctx, A{ .client_id = "c", .username = "alice", .password = "s3cret" }));
    try testing.expectEqual(broker.AuthDecision.allow, authenticate(ctx, A{ .client_id = "c", .username = "bob", .password = "hunter2" }));
    try testing.expectEqual(broker.AuthDecision.deny_bad_credentials, authenticate(ctx, A{ .client_id = "c", .username = "alice", .password = "S3cret" }));
    try testing.expectEqual(broker.AuthDecision.deny_bad_credentials, authenticate(ctx, A{ .client_id = "c", .username = "alice", .password = "hunter2" }));
    try testing.expectEqual(broker.AuthDecision.deny_bad_credentials, authenticate(ctx, A{ .client_id = "c", .username = "mallory", .password = "s3cret" }));
    try testing.expectEqual(broker.AuthDecision.deny_bad_credentials, authenticate(ctx, A{ .client_id = "c", .username = "alice", .password = null }));
    try testing.expectEqual(broker.AuthDecision.deny_bad_credentials, authenticate(ctx, A{ .client_id = "c", .username = "alice", .password = "" }));
    try testing.expectEqual(broker.AuthDecision.deny_not_authorized, authenticate(ctx, A{ .client_id = "c", .username = null, .password = null }));
    pw.allow_anonymous = true;
    try testing.expectEqual(broker.AuthDecision.allow, authenticate(ctx, A{ .client_id = "c", .username = null, .password = null }));
    // anonymous allowed does not let a wrong login through
    try testing.expectEqual(broker.AuthDecision.deny_bad_credentials, authenticate(ctx, A{ .client_id = "c", .username = "alice", .password = "nope" }));
    try testing.expectEqual(broker.AuthDecision.deny_not_authorized, authenticate(null, A{ .client_id = "c", .username = null, .password = null }));
}

test "acl: a deny rule refuses every SUBSCRIBE it overlaps" {
    var buf: [4]Rule = undefined;
    const a = try Acl.parse("topic readwrite #\ntopic deny private/+\n", &buf);
    try testing.expect(!a.check(rq(.subscribe, "private/#", null, "c")));
    try testing.expect(!a.check(rq(.subscribe, "#", null, "c")));
    try testing.expect(!a.check(rq(.subscribe, "+/x", null, "c")));
    try testing.expect(!a.check(rq(.subscribe, "private/x", null, "c")));
    try testing.expect(a.check(rq(.subscribe, "public/#", null, "c")));
    try testing.expect(a.check(rq(.subscribe, "private/x/y", null, "c"))); // deeper than `+`
    try testing.expect(a.check(rq(.subscribe, "+/x/y", null, "c")));
    try testing.expect(a.check(rq(.publish, "private/x/y", null, "c")));
    // overlap with `#` rules, the parent level, and a pattern deny
    var b2: [4]Rule = undefined;
    const d = try Acl.parse("pattern deny own/%u/x\nuser u\ntopic readwrite #\ntopic deny a/b/#\n", &b2);
    try testing.expect(!d.check(rq(.subscribe, "a/b", "u", "c")));
    try testing.expect(!d.check(rq(.subscribe, "a/+/c", "u", "c")));
    try testing.expect(d.check(rq(.subscribe, "a/c/#", "u", "c")));
    try testing.expect(!d.check(rq(.subscribe, "own/+/x", "u", "c")));
    try testing.expect(!d.check(rq(.subscribe, "own/u/#", "u", "c")));
    try testing.expect(d.check(rq(.subscribe, "own/v/#", "u", "c")));
}

// Lines written by the official mosquitto_passwd 2.1.2 (1000 iterations,
// 64-byte salt), 2026-10-17.
const golden_alice = "alice:$7$1000$aVdP5TwRZIFzLGb8rViI1k6ir2ldLZamfpOm9Av4n0QzEQsO7s6qVsXb9qy8LAy3V0kIG7dqu9T+yxdsCwTcRw==$hdd22TxC7KfyRQBDDQMmcoWz3nwFxlhMdwh45yQsryyMx/ffsn+AqUhLle2+HQeBiA1SWT+DFrDiBqV9xRya0Q==";
const golden_bob_salt = "AdPRuou8DmEDG7SizhAjrmHJk94sE28EL96MplcRW3GWofUi9cyHDpl20p0STCFvX+XDgUwKS0IuX5vaMU3Ckg==";
const golden_bob = "bob:$7$1000$" ++ golden_bob_salt ++ "$jn0M3dNRPYhYpWOfsFHQVZJZc0XulVhPZD5Do8iAGJ0qH7G6wdWRd9rFb1WUbIfAD395dO/0HWm3L189aObziw==";

test "passwords: lines made by the real mosquitto_passwd verify" {
    var e: [4]Entry = undefined;
    const pw = try Passwords.parse(golden_alice ++ "\n" ++ golden_bob ++ "\n", &e);
    try testing.expectEqual(@as(usize, 2), pw.entries.len);
    try testing.expect(pw.verify("alice", "s3cret pass"));
    try testing.expect(!pw.verify("alice", "s3cret pas"));
    try testing.expect(!pw.verify("alice", "hunter2"));
    try testing.expect(pw.verify("bob", "hunter2"));
    try testing.expect(!pw.verify("bob", "Hunter2"));
    try testing.expect(!pw.verify("carol", "hunter2"));
    // and our formatter reproduces the tool's hash byte for byte
    var salt_bytes: [64]u8 = undefined;
    try std.base64.standard.Decoder.decode(&salt_bytes, golden_bob_salt);
    var out: [256]u8 = undefined;
    const mine = try formatHash(&out, "hunter2", &salt_bytes, default_iterations);
    try testing.expectEqualStrings(golden_bob["bob:".len..], mine);
}

test "passwords: a malformed salt or hash is refused (b64ct decode)" {
    const good_hash = "jn0M3dNRPYhYpWOfsFHQVZJZc0XulVhPZD5Do8iAGJ0qH7G6wdWRd9rFb1WUbIfAD395dO/0HWm3L189aObziw==";
    try testing.expect(parseHash("$7$1000$" ++ golden_bob_salt ++ "$" ++ good_hash) != null);
    // character outside the alphabet in the salt / in the hash
    try testing.expect(parseHash("$7$1000$MDEyMzQ1Njc4OWF*$" ++ good_hash) == null);
    try testing.expect(parseHash("$7$1000$MDEyMzQ1Njc4OWFi$" ++ "jn0M3dNRPYhYpWOfsFHQVZJZc0XulVhPZD5Do8iAGJ0qH7G6wdWRd9rFb1WUbIfAD395dO_0HWm3L189aObziw==") == null);
    // missing padding, wrong length, stray low bits, empty salt
    try testing.expect(parseHash("$7$1000$MDEyMzQ1Njc4OWFi$" ++ good_hash[0 .. good_hash.len - 2]) == null);
    try testing.expect(parseHash("$7$1000$MDEyMzQ1Njc4OWFi$" ++ good_hash[0 .. good_hash.len - 4] ++ "==") == null);
    try testing.expect(parseHash("$7$1000$MDEyMzQ1Njc4OWFi$" ++ good_hash[0 .. good_hash.len - 3] ++ "B==") == null);
    try testing.expect(parseHash("$7$1000$MDEyMzQ1Njc4OWFi$" ++ good_hash[0 .. good_hash.len - 3] ++ "A==") != null);
    try testing.expect(parseHash("$7$1000$MDEyMzQ1Njc4OWF$" ++ good_hash) == null);
    try testing.expect(parseHash("$7$1000$$" ++ good_hash) == null);
}

test "passwords: the stored format and file errors" {
    var h: [200]u8 = undefined;
    const hash = try formatHash(&h, "pw", "0123456789ab", 101);
    try testing.expect(std.mem.startsWith(u8, hash, "$7$101$MDEyMzQ1Njc4OWFi$"));
    // 12-byte salt -> 16 base64 chars; 64-byte hash -> 88 chars with padding
    try testing.expectEqual(@as(usize, "$7$101$".len + 16 + 1 + 88), hash.len);
    // PBKDF2-HMAC-SHA512 against an independent known answer (RFC 6070 style,
    // "password"/"salt", 1 iteration, from the widely published SHA-512 set)
    var dk: [hash_len]u8 = undefined;
    try testing.expect(derive(&dk, "password", "salt", 1));
    const want = "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce";
    var hex: [128]u8 = undefined;
    _ = std.fmt.bufPrint(&hex, "{x}", .{&dk}) catch unreachable;
    try testing.expectEqualStrings(want, &hex);

    var e: [2]Entry = undefined;
    try testing.expectError(error.InvalidEntry, Passwords.parse("alice\n", &e));
    try testing.expectError(error.InvalidEntry, Passwords.parse(":$7$101$MDEyMzQ1Njc4OWFi$x\n", &e));
    try testing.expectError(error.InvalidEntry, Passwords.parse("alice:plaintext\n", &e));
    try testing.expectError(error.InvalidEntry, Passwords.parse("alice:$7$0$MDEyMzQ1Njc4OWFi$x\n", &e));
    try testing.expectError(error.InvalidEntry, Passwords.parse("alice:$7$99999999$MDEyMzQ1Njc4OWFi$x\n", &e));
    var line: [512]u8 = undefined;
    const ok = try std.fmt.bufPrint(&line, "a:{s}\nb:{s}\nc:{s}\n", .{ hash, hash, hash });
    try testing.expectError(error.TooManyEntries, Passwords.parse(ok, &e));
    try testing.expectError(error.InvalidParameters, formatHash(&h, "pw", "", 101));
}

// ── the broker, with both plugged in ────────────────────────────────────────

const Sink = struct {
    buf: [2048]u8 = undefined,
    len: usize = 0,
    read: usize = 0,

    fn transport(s: *Sink) broker.Transport {
        return .{ .ctx = s, .writeFn = writeFn };
    }

    fn writeFn(ctx: *anyopaque, bytes: []const u8) broker.TransportError!void {
        const s: *Sink = @ptrCast(@alignCast(ctx));
        @memcpy(s.buf[s.len..][0..bytes.len], bytes);
        s.len += bytes.len;
    }

    fn next(s: *Sink) !?@import("packet.zig").Packet {
        const packet = @import("packet.zig");
        if (s.read >= s.len) return null;
        const dec = (try packet.decode(s.buf[s.read..s.len])) orelse return null;
        s.read += dec.consumed;
        return dec.packet;
    }
};

fn send(b: *broker.Broker, conn: *broker.Connection, bytes: []const u8) !broker.Disposition {
    try b.feed(conn, bytes);
    return b.process(conn, 1);
}

test "broker: the ACL and the password table plugged into Config deny a publish and a subscribe" {
    const packet = @import("packet.zig");
    var text_buf: [512]u8 = undefined;
    var n: usize = 0;
    n += (try makeLine(text_buf[n..], "alice", "apw", "0123456789ab", 5)).len;
    n += (try makeLine(text_buf[n..], "watch", "wpw", "ba9876543210", 5)).len;
    var entries: [4]Entry = undefined;
    const pw = try Passwords.parse(text_buf[0..n], &entries);
    var rules: [8]Rule = undefined;
    const acl = try Acl.parse(
        \\user alice
        \\topic write room/alice/#
        \\topic deny room/alice/secret
        \\user watch
        \\topic read room/#
        \\
    , &rules);

    var b = broker.Broker.init(testing.allocator, .{
        .authenticateFn = authenticate,
        .auth_ctx = @constCast(&pw),
        .authorizeFn = authorize,
        .acl_ctx = @constCast(&acl),
    });
    defer b.deinit();
    var buf: [256]u8 = undefined;

    // wrong password: refused with bad_username_or_password
    var bad_sink = Sink{};
    const bad = try b.accept(bad_sink.transport());
    _ = try send(&b, bad, try packet.encodeConnect(&buf, .{ .client_id = "x", .username = "alice", .password = "wrong" }));
    const refused = (try bad_sink.next()).?;
    try testing.expectEqual(packet.ConnectReturnCode.bad_username_or_password, refused.connack.return_code);
    // anonymous: refused too (allow_anonymous is false)
    var anon_sink = Sink{};
    const anon = try b.accept(anon_sink.transport());
    _ = try send(&b, anon, try packet.encodeConnect(&buf, .{ .client_id = "y" }));
    try testing.expectEqual(packet.ConnectReturnCode.not_authorized, (try anon_sink.next()).?.connack.return_code);

    // the watcher may subscribe to room/#, and to nothing outside
    var w_sink = Sink{};
    const w = try b.accept(w_sink.transport());
    _ = try send(&b, w, try packet.encodeConnect(&buf, .{ .client_id = "w", .username = "watch", .password = "wpw" }));
    try testing.expectEqual(packet.ConnectReturnCode.accepted, (try w_sink.next()).?.connack.return_code);
    _ = try send(&b, w, try packet.encodeSubscribe(&buf, 1, &.{ .{ .filter = "room/#" }, .{ .filter = "other/#" } }));
    const suback = (try w_sink.next()).?.suback;
    try testing.expectEqual(@as(u8, 0), suback.codes[0]);
    try testing.expectEqual(@as(u8, 0x80), suback.codes[1]);

    // alice may publish under room/alice/ but not to room/alice/secret
    var a_sink = Sink{};
    const al = try b.accept(a_sink.transport());
    _ = try send(&b, al, try packet.encodeConnect(&buf, .{ .client_id = "a", .username = "alice", .password = "apw" }));
    try testing.expectEqual(packet.ConnectReturnCode.accepted, (try a_sink.next()).?.connack.return_code);
    _ = try send(&b, al, try packet.encodePublish(&buf, .{ .topic = "room/alice/secret", .payload = "no" }));
    try testing.expect((try w_sink.next()) == null); // denied: dropped
    _ = try send(&b, al, try packet.encodePublish(&buf, .{ .topic = "room/alice/temp", .payload = "21" }));
    const got = (try w_sink.next()).?.publish;
    try testing.expectEqualStrings("room/alice/temp", got.topic);
    try testing.expectEqualStrings("21", got.payload);
    // alice has no read right: her subscription is refused
    _ = try send(&b, al, try packet.encodeSubscribe(&buf, 2, &.{.{ .filter = "room/alice/temp" }}));
    try testing.expectEqual(@as(u8, 0x80), (try a_sink.next()).?.suback.codes[0]);
}

// ── review fixes ────────────────────────────────────────────────────────────

test "review M3: a deny pattern fails closed for a name it cannot substitute; allow patterns stay refused" {
    var buf: [8]Rule = undefined;
    const a = try Acl.parse(
        \\pattern deny %c/admin
        \\pattern deny private/%u
        \\pattern readwrite open/%u/#
        \\topic readwrite #
        \\
    , &buf);
    // an honest identity: the deny applies as written
    try testing.expect(!a.check(rq(.publish, "c1/admin", null, "c1")));
    try testing.expect(a.check(rq(.publish, "c1/other", null, "c1")));
    // a client id / username built to dodge the substitution: denied, not "no rule matched"
    try testing.expect(!a.check(rq(.publish, "a/b/admin", null, "a/b")));
    try testing.expect(!a.check(rq(.publish, "anything", null, "+")));
    try testing.expect(!a.check(rq(.subscribe, "anything", "x", "#")));
    try testing.expect(!a.check(rq(.publish, "private/x/y", "x/y", "c1")));
    // the allow pattern is still just refused (the grant by `topic readwrite #` is anonymous-only)
    var b2: [4]Rule = undefined;
    const g = try Acl.parse("pattern readwrite open/%u/#\n", &b2);
    try testing.expect(g.check(rq(.publish, "open/bob/x", "bob", "c")));
    try testing.expect(!g.check(rq(.publish, "open/a/b/x", "a/b", "c")));
}

test "review M4: an unknown user is charged the table's iteration count; a signed count is no count" {
    var h: [200]u8 = undefined;
    const slow = try formatHash(&h, "pw", "0123456789ab", 7);
    var text: [300]u8 = undefined;
    const line = try std.fmt.bufPrint(&text, "u:{s}\n", .{slow});
    var e: [2]Entry = undefined;
    const pw = try Passwords.parse(line, &e);
    try testing.expectEqual(@as(u32, 7), pw.dummyIterations());
    try testing.expectEqual(@as(u32, default_iterations), (Passwords{ .entries = &.{} }).dummyIterations());
    try testing.expect(pw.verify("u", "pw"));
    try testing.expect(!pw.verify("nobody", "pw"));
    // "+7" parsed as 7 before
    var signed_buf: [300]u8 = undefined;
    const signed = try std.fmt.bufPrint(&signed_buf, "u:$7$+7${s}\n", .{slow["$7$7$".len..]});
    try testing.expectError(error.InvalidEntry, Passwords.parse(signed, &e));
}
