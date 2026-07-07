// SPDX-License-Identifier: MIT

//! nftables — typed builder for the libnftables JSON ruleset format.
//!
//! Construct tables/chains/rules/sets with a typed Zig API and serialize them
//! to the documented JSON representation accepted by `nft -j -f -` (check
//! first with `nft -c -j -f -`). This lets a program manage the Linux
//! firewall natively instead of assembling `nft` command strings by hand.
//!
//! Scope: the ruleset-building subset of the schema — `add`/`create`/
//! `delete`/`flush` commands over table/chain/rule/set (+ `flush ruleset`),
//! and the common expression/statement vocabulary (payload & meta & ct
//! matches, prefixes, ranges, anonymous and named sets, verdicts, NAT,
//! counter/log/limit). The JSON produced here is portable data; *applying*
//! it requires the Linux `nft` binary.
//!
//! Provenance: clean-room from the documented libnftables JSON schema
//! (libnftables-json(5) man page / nftables wiki "JSON representation");
//! no libnftables source consulted or copied — we emit the documented
//! `nft -j` interchange format only.

const std = @import("std");
const builtin = @import("builtin");

pub const meta = .{
    .status = .gap, // no pure-Zig nftables library exists
    .platform = .any, // the JSON is portable; applying it is Linux/nft
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "libnftables JSON (nft -j) schema",
    .deps = .{}, // std only
};

const JsonError = error{WriteFailed};

// ── vocabulary enums ────────────────────────────────────────────────────────
// For every enum below whose tag names equal the schema tokens verbatim, the
// default std.json enum serialization (`@tagName`) is exactly right; the few
// whose tokens are not Zig identifiers ("==", "fully-random", "tcp reset")
// carry a custom `jsonStringify`.

/// Address family of a table.
pub const Family = enum { ip, ip6, inet, arp, bridge, netdev };

/// Base chain type.
pub const ChainType = enum { filter, nat, route };

/// Base chain hook point.
pub const Hook = enum { prerouting, input, forward, output, postrouting, ingress, egress };

/// Base chain default policy.
pub const Policy = enum { accept, drop };

/// Comparison operator of a `match` statement. `in` performs a lookup
/// (bits-contained / set membership).
pub const Op = enum {
    eq,
    ne,
    lt,
    gt,
    le,
    ge,
    in,

    pub fn token(self: Op) []const u8 {
        return switch (self) {
            .eq => "==",
            .ne => "!=",
            .lt => "<",
            .gt => ">",
            .le => "<=",
            .ge => ">=",
            .in => "in",
        };
    }

    pub fn jsonStringify(self: Op, jw: anytype) JsonError!void {
        try jw.write(self.token());
    }
};

/// Packet metadata keys (`meta` expression).
pub const MetaKey = enum {
    length,
    protocol,
    priority,
    random,
    mark,
    iif,
    iifname,
    iiftype,
    oif,
    oifname,
    oiftype,
    skuid,
    skgid,
    nftrace,
    rtclassid,
    ibriport,
    obriport,
    ibridgename,
    obridgename,
    pkttype,
    cpu,
    iifgroup,
    oifgroup,
    cgroup,
    nfproto,
    l4proto,
    secpath,
};

/// Named packet headers usable in a `payload` expression.
pub const PayloadProto = enum {
    ether,
    vlan,
    arp,
    ip,
    icmp,
    igmp,
    ip6,
    icmpv6,
    tcp,
    udp,
    udplite,
    sctp,
    dccp,
    ah,
    esp,
    comp,
    th,
};

/// Reference point of a raw `payload` expression.
pub const PayloadBase = enum { ll, nh, th };

/// Conntrack direction for `ct` expressions.
pub const CtDir = enum { original, reply };

/// NAT statement flags.
pub const NatFlag = enum {
    random,
    fully_random,
    persistent,

    pub fn token(self: NatFlag) []const u8 {
        return switch (self) {
            .random => "random",
            .fully_random => "fully-random",
            .persistent => "persistent",
        };
    }

    pub fn jsonStringify(self: NatFlag, jw: anytype) JsonError!void {
        try jw.write(self.token());
    }
};

/// Reject statement variants.
pub const RejectType = enum {
    tcp_reset,
    icmpx,
    icmp,
    icmpv6,

    pub fn token(self: RejectType) []const u8 {
        return switch (self) {
            .tcp_reset => "tcp reset",
            .icmpx => "icmpx",
            .icmp => "icmp",
            .icmpv6 => "icmpv6",
        };
    }

    pub fn jsonStringify(self: RejectType, jw: anytype) JsonError!void {
        try jw.write(self.token());
    }
};

/// Log statement severity.
pub const LogLevel = enum { emerg, alert, crit, err, warn, notice, info, debug, audit };

/// Denominator of a limit rate.
pub const LimitPer = enum { second, minute, hour, day, week };

/// Unit of a limit rate.
pub const LimitUnit = enum { packets, bytes, kbytes, mbytes };

/// Named set flags.
pub const SetFlag = enum { constant, interval, timeout };

/// Named set element datatype.
pub const SetDataType = enum {
    ipv4_addr,
    ipv6_addr,
    ether_addr,
    inet_proto,
    inet_service,
    mark,
    ifname,
};

// ── expressions ─────────────────────────────────────────────────────────────

/// A scalar value — the leaves of `range` bounds.
pub const Val = union(enum) {
    str: []const u8,
    num: i64,

    pub fn jsonStringify(self: Val, jw: anytype) JsonError!void {
        switch (self) {
            .str => |s| try jw.write(s),
            .num => |n| try jw.write(n),
        }
    }
};

/// Named packet header field, e.g. `{"payload":{"protocol":"tcp","field":"dport"}}`.
pub const Payload = struct {
    protocol: PayloadProto,
    field: []const u8,
};

/// Raw payload reference: `len` bits at `offset` from `base`.
pub const PayloadRaw = struct {
    base: PayloadBase,
    offset: u32,
    len: u32,
};

/// Conntrack data reference, e.g. `{"ct":{"key":"state"}}`.
pub const Ct = struct {
    key: []const u8,
    family: ?Family = null,
    dir: ?CtDir = null,

    pub fn jsonStringify(self: Ct, jw: anytype) JsonError!void {
        try jw.beginObject();
        try jw.objectField("key");
        try jw.write(self.key);
        if (self.family) |f| {
            try jw.objectField("family");
            try jw.write(f);
        }
        if (self.dir) |d| {
            try jw.objectField("dir");
            try jw.write(d);
        }
        try jw.endObject();
    }
};

/// CIDR prefix, e.g. `{"prefix":{"addr":"10.0.0.0","len":8}}`.
pub const Prefix = struct {
    addr: []const u8,
    len: u8,
};

/// Inclusive range, e.g. `{"range":[1024,65535]}`.
pub const Range = struct {
    lo: Val,
    hi: Val,
};

/// An nftables expression — the building block of match statements, set
/// elements and NAT arguments.
pub const Expr = union(enum) {
    /// Immediate string ("eth0", "established", "192.0.2.1", ...).
    str: []const u8,
    /// Immediate number (port, mark, ICMP code, ...).
    num: i64,
    /// Immediate boolean (e.g. header-existence checks).
    boolean: bool,
    /// Reference to a named set: serialized as `"@name"`.
    set_ref: []const u8,
    /// Named header field.
    payload: Payload,
    /// Raw payload bits.
    payload_raw: PayloadRaw,
    /// Packet metadata.
    meta: MetaKey,
    /// Conntrack data.
    ct: Ct,
    /// CIDR prefix.
    prefix: Prefix,
    /// Inclusive range.
    range: Range,
    /// Anonymous set `{"set":[...]}`.
    set: []const Expr,
    /// Plain list `[...]` (e.g. the RHS of a `ct state` lookup).
    list: []const Expr,
    /// Concatenation `{"concat":[...]}`.
    concat: []const Expr,

    pub fn jsonStringify(self: Expr, jw: anytype) JsonError!void {
        switch (self) {
            .str => |s| try jw.write(s),
            .num => |n| try jw.write(n),
            .boolean => |b| try jw.write(b),
            .set_ref => |name| {
                // "@" ++ name as one properly escaped JSON string.
                try jw.beginWriteRaw();
                try jw.writer.writeAll("\"@");
                try std.json.Stringify.encodeJsonStringChars(name, jw.options, jw.writer);
                try jw.writer.writeByte('"');
                jw.endWriteRaw();
            },
            .payload => |p| try writeWrapped(jw, "payload", p),
            .payload_raw => |p| try writeWrapped(jw, "payload", p),
            .meta => |k| {
                try jw.beginObject();
                try jw.objectField("meta");
                try jw.beginObject();
                try jw.objectField("key");
                try jw.write(k);
                try jw.endObject();
                try jw.endObject();
            },
            .ct => |c| try writeWrapped(jw, "ct", c),
            .prefix => |p| try writeWrapped(jw, "prefix", p),
            .range => |r| {
                try jw.beginObject();
                try jw.objectField("range");
                try jw.beginArray();
                try jw.write(r.lo);
                try jw.write(r.hi);
                try jw.endArray();
                try jw.endObject();
            },
            .set => |elems| try writeWrapped(jw, "set", elems),
            .list => |elems| try jw.write(elems),
            .concat => |elems| try writeWrapped(jw, "concat", elems),
        }
    }
};

/// Serialize `{"<key>": <value>}`.
fn writeWrapped(jw: anytype, key: []const u8, value: anytype) JsonError!void {
    try jw.beginObject();
    try jw.objectField(key);
    try jw.write(value);
    try jw.endObject();
}

// ── expression helpers ──────────────────────────────────────────────────────

/// Immediate number expression.
pub fn num(n: i64) Expr {
    return .{ .num = n };
}

/// Immediate string expression.
pub fn str(s: []const u8) Expr {
    return .{ .str = s };
}

/// Reference to the named set `name` (serialized as `"@name"`).
pub fn setRef(name: []const u8) Expr {
    return .{ .set_ref = name };
}

/// CIDR prefix expression, e.g. `cidr("10.0.0.0", 8)`.
pub fn cidr(addr: []const u8, len: u8) Expr {
    return .{ .prefix = .{ .addr = addr, .len = len } };
}

/// Inclusive port range expression, e.g. `portRange(8000, 8100)`.
pub fn portRange(lo: u16, hi: u16) Expr {
    return .{ .range = .{ .lo = .{ .num = lo }, .hi = .{ .num = hi } } };
}

/// Anonymous set expression `{ ... }` over the given elements.
pub fn anonSet(elems: []const Expr) Expr {
    return .{ .set = elems };
}

/// Named header field expression, e.g. `payloadField(.tcp, "dport")`.
pub fn payloadField(protocol: PayloadProto, field: []const u8) Expr {
    return .{ .payload = .{ .protocol = protocol, .field = field } };
}

// ── statements ──────────────────────────────────────────────────────────────

/// Relational match: `{"match":{"op":..,"left":..,"right":..}}`.
pub const Match = struct {
    op: Op = .eq,
    left: Expr,
    right: Expr,

    pub fn jsonStringify(self: Match, jw: anytype) JsonError!void {
        try jw.beginObject();
        try jw.objectField("op");
        try jw.write(self.op);
        try jw.objectField("left");
        try jw.write(self.left);
        try jw.objectField("right");
        try jw.write(self.right);
        try jw.endObject();
    }
};

/// Reject statement options. Default (both null) serializes as
/// `{"reject":null}`.
pub const Reject = struct {
    type: ?RejectType = null,
    /// ICMP code to reject with.
    expr: ?Expr = null,
};

/// Log statement options. Default (all null) serializes as `{"log":null}`.
pub const Log = struct {
    prefix: ?[]const u8 = null,
    group: ?u32 = null,
    snaplen: ?u32 = null,
    /// Serialized as `"queue-threshold"`.
    queue_threshold: ?u32 = null,
    level: ?LogLevel = null,
};

/// Anonymous limit statement.
pub const Limit = struct {
    rate: u64,
    per: LimitPer = .second,
    burst: ?u64 = null,
    rate_unit: ?LimitUnit = null,
    /// If true, match when the limit is exceeded.
    inv: bool = false,
};

/// snat/dnat statement arguments.
pub const Nat = struct {
    /// Address to translate to (immediate string).
    addr: ?[]const u8 = null,
    /// Family of `addr`; required in the inet table family.
    family: ?Family = null,
    /// Port to translate to.
    port: ?u16 = null,
    flags: []const NatFlag = &.{},
};

/// An nftables statement — one entry of a rule's `expr` array.
pub const Stmt = union(enum) {
    match: Match,
    accept,
    drop,
    @"return",
    @"continue",
    /// Jump to target chain.
    jump: []const u8,
    /// Goto target chain.
    goto: []const u8,
    reject: Reject,
    /// Anonymous counter: `{"counter":null}`.
    counter,
    /// Reference to a named counter object: `{"counter":"name"}`.
    counter_ref: []const u8,
    log: Log,
    limit: Limit,
    masquerade,
    /// Redirect, optionally to a port.
    redirect: ?u16,
    snat: Nat,
    dnat: Nat,

    pub fn jsonStringify(self: Stmt, jw: anytype) JsonError!void {
        try jw.beginObject();
        switch (self) {
            .accept, .drop, .@"return", .@"continue", .counter, .masquerade => {
                try jw.objectField(@tagName(self));
                try jw.write(null);
            },
            .match => |m| {
                try jw.objectField("match");
                try jw.write(m);
            },
            .jump, .goto => |target| {
                try jw.objectField(@tagName(self));
                try jw.beginObject();
                try jw.objectField("target");
                try jw.write(target);
                try jw.endObject();
            },
            .reject => |r| {
                try jw.objectField("reject");
                if (r.type == null and r.expr == null) {
                    try jw.write(null);
                } else {
                    try jw.beginObject();
                    if (r.type) |t| {
                        try jw.objectField("type");
                        try jw.write(t);
                    }
                    if (r.expr) |e| {
                        try jw.objectField("expr");
                        try jw.write(e);
                    }
                    try jw.endObject();
                }
            },
            .counter_ref => |name| {
                try jw.objectField("counter");
                try jw.write(name);
            },
            .log => |l| {
                try jw.objectField("log");
                if (l.prefix == null and l.group == null and l.snaplen == null and
                    l.queue_threshold == null and l.level == null)
                {
                    try jw.write(null);
                } else {
                    try jw.beginObject();
                    if (l.prefix) |p| {
                        try jw.objectField("prefix");
                        try jw.write(p);
                    }
                    if (l.group) |g| {
                        try jw.objectField("group");
                        try jw.write(g);
                    }
                    if (l.snaplen) |s| {
                        try jw.objectField("snaplen");
                        try jw.write(s);
                    }
                    if (l.queue_threshold) |q| {
                        try jw.objectField("queue-threshold");
                        try jw.write(q);
                    }
                    if (l.level) |lv| {
                        try jw.objectField("level");
                        try jw.write(lv);
                    }
                    try jw.endObject();
                }
            },
            .limit => |l| {
                try jw.objectField("limit");
                try jw.beginObject();
                try jw.objectField("rate");
                try jw.write(l.rate);
                try jw.objectField("per");
                try jw.write(l.per);
                if (l.burst) |b| {
                    try jw.objectField("burst");
                    try jw.write(b);
                }
                if (l.rate_unit) |u| {
                    try jw.objectField("rate_unit");
                    try jw.write(u);
                }
                if (l.inv) {
                    try jw.objectField("inv");
                    try jw.write(true);
                }
                try jw.endObject();
            },
            .redirect => |port| {
                try jw.objectField("redirect");
                if (port) |p| {
                    try jw.beginObject();
                    try jw.objectField("port");
                    try jw.write(p);
                    try jw.endObject();
                } else {
                    try jw.write(null);
                }
            },
            .snat, .dnat => |n| {
                try jw.objectField(@tagName(self));
                try jw.beginObject();
                if (n.addr) |a| {
                    try jw.objectField("addr");
                    try jw.write(a);
                }
                if (n.family) |f| {
                    try jw.objectField("family");
                    try jw.write(f);
                }
                if (n.port) |p| {
                    try jw.objectField("port");
                    try jw.write(p);
                }
                if (n.flags.len > 0) {
                    try jw.objectField("flags");
                    try jw.write(n.flags);
                }
                try jw.endObject();
            },
        }
        try jw.endObject();
    }
};

// ── ruleset objects ─────────────────────────────────────────────────────────

/// A table: the top-level container of chains and sets.
pub const Table = struct {
    family: Family,
    name: []const u8,
};

/// A chain. Base chains (attached to a netfilter hook) carry `chain_type`,
/// `hook`, `prio` and usually `policy`; regular chains leave them null.
/// Use the `base` / `regular` constructors.
pub const Chain = struct {
    family: Family,
    table: []const u8,
    name: []const u8,
    chain_type: ?ChainType = null,
    hook: ?Hook = null,
    prio: ?i32 = null,
    /// Bound interface (netdev family base chains).
    dev: ?[]const u8 = null,
    policy: ?Policy = null,

    /// A base chain attached to a netfilter hook.
    pub fn base(
        family: Family,
        table: []const u8,
        name: []const u8,
        chain_type: ChainType,
        hook: Hook,
        prio: i32,
        policy: Policy,
    ) Chain {
        return .{
            .family = family,
            .table = table,
            .name = name,
            .chain_type = chain_type,
            .hook = hook,
            .prio = prio,
            .policy = policy,
        };
    }

    /// A regular (non-base) chain, reached via jump/goto.
    pub fn regular(family: Family, table: []const u8, name: []const u8) Chain {
        return .{ .family = family, .table = table, .name = name };
    }

    pub fn jsonStringify(self: Chain, jw: anytype) JsonError!void {
        try jw.beginObject();
        try jw.objectField("family");
        try jw.write(self.family);
        try jw.objectField("table");
        try jw.write(self.table);
        try jw.objectField("name");
        try jw.write(self.name);
        if (self.chain_type) |t| {
            try jw.objectField("type");
            try jw.write(t);
        }
        if (self.hook) |h| {
            try jw.objectField("hook");
            try jw.write(h);
        }
        if (self.prio) |p| {
            try jw.objectField("prio");
            try jw.write(p);
        }
        if (self.dev) |d| {
            try jw.objectField("dev");
            try jw.write(d);
        }
        if (self.policy) |p| {
            try jw.objectField("policy");
            try jw.write(p);
        }
        try jw.endObject();
    }
};

/// A rule: an `expr` array of statements in a chain. `handle` identifies an
/// existing rule (delete); `comment` is a free-form annotation.
pub const Rule = struct {
    family: Family,
    table: []const u8,
    chain: []const u8,
    expr: []const Stmt = &.{},
    handle: ?u64 = null,
    comment: ?[]const u8 = null,

    pub fn jsonStringify(self: Rule, jw: anytype) JsonError!void {
        try jw.beginObject();
        try jw.objectField("family");
        try jw.write(self.family);
        try jw.objectField("table");
        try jw.write(self.table);
        try jw.objectField("chain");
        try jw.write(self.chain);
        if (self.expr.len > 0) {
            try jw.objectField("expr");
            try jw.write(self.expr);
        }
        if (self.handle) |h| {
            try jw.objectField("handle");
            try jw.write(h);
        }
        if (self.comment) |c| {
            try jw.objectField("comment");
            try jw.write(c);
        }
        try jw.endObject();
    }
};

/// A named set.
pub const Set = struct {
    family: Family,
    table: []const u8,
    name: []const u8,
    /// Element datatype; serialized as `"type"`.
    elem_type: SetDataType,
    flags: []const SetFlag = &.{},
    /// Initial elements.
    elem: []const Expr = &.{},
    /// Element timeout in seconds.
    timeout: ?u64 = null,
    /// Maximum number of elements.
    size: ?u64 = null,
    /// Merge adjacent/overlapping interval elements; serialized as
    /// `"auto-merge"`.
    auto_merge: ?bool = null,

    pub fn jsonStringify(self: Set, jw: anytype) JsonError!void {
        try jw.beginObject();
        try jw.objectField("family");
        try jw.write(self.family);
        try jw.objectField("table");
        try jw.write(self.table);
        try jw.objectField("name");
        try jw.write(self.name);
        try jw.objectField("type");
        try jw.write(self.elem_type);
        if (self.flags.len > 0) {
            try jw.objectField("flags");
            try jw.write(self.flags);
        }
        if (self.elem.len > 0) {
            try jw.objectField("elem");
            try jw.write(self.elem);
        }
        if (self.timeout) |t| {
            try jw.objectField("timeout");
            try jw.write(t);
        }
        if (self.size) |s| {
            try jw.objectField("size");
            try jw.write(s);
        }
        if (self.auto_merge) |a| {
            try jw.objectField("auto-merge");
            try jw.write(a);
        }
        try jw.endObject();
    }
};

/// A ruleset element a command operates on.
pub const Object = union(enum) {
    table: Table,
    chain: Chain,
    rule: Rule,
    set: Set,
    /// The whole ruleset (`flush ruleset`).
    ruleset,

    pub fn jsonStringify(self: Object, jw: anytype) JsonError!void {
        try jw.beginObject();
        try jw.objectField(@tagName(self));
        switch (self) {
            .ruleset => try jw.write(null),
            inline .table, .chain, .rule, .set => |obj| try jw.write(obj),
        }
        try jw.endObject();
    }
};

/// A top-level command: one entry of the `"nftables"` array.
pub const Cmd = union(enum) {
    add: Object,
    create: Object,
    delete: Object,
    flush: Object,

    pub fn jsonStringify(self: Cmd, jw: anytype) JsonError!void {
        try jw.beginObject();
        try jw.objectField(@tagName(self));
        switch (self) {
            inline else => |obj| try jw.write(obj),
        }
        try jw.endObject();
    }
};

// ── ruleset builder ─────────────────────────────────────────────────────────

/// Ordered list of commands, serializable to `{"nftables":[...]}`.
///
/// All strings and expression slices are *borrowed* — they must outlive the
/// Ruleset. Statement arrays passed to `addRule` (and those accumulated by
/// `RuleBuilder`) are copied into an internal arena, so rule statements may
/// be built in temporary storage. Feed the serialized bytes to
/// `nft -c -j -f -` (check) or `nft -j -f -` (apply).
pub const Ruleset = struct {
    arena: std.heap.ArenaAllocator,
    cmds: std.ArrayList(Cmd),

    pub fn init(gpa: std.mem.Allocator) Ruleset {
        return .{
            .arena = std.heap.ArenaAllocator.init(gpa),
            .cmds = .empty,
        };
    }

    pub fn deinit(rs: *Ruleset) void {
        rs.arena.deinit();
        rs.* = undefined;
    }

    /// Append an arbitrary command.
    pub fn push(rs: *Ruleset, cmd: Cmd) error{OutOfMemory}!void {
        try rs.cmds.append(rs.arena.allocator(), cmd);
    }

    /// `{"add": ...}`.
    pub fn add(rs: *Ruleset, obj: Object) error{OutOfMemory}!void {
        try rs.push(.{ .add = obj });
    }

    /// `{"create": ...}` — like add, but errors if the object exists.
    pub fn create(rs: *Ruleset, obj: Object) error{OutOfMemory}!void {
        try rs.push(.{ .create = obj });
    }

    /// `{"delete": ...}`.
    pub fn delete(rs: *Ruleset, obj: Object) error{OutOfMemory}!void {
        try rs.push(.{ .delete = obj });
    }

    /// `{"flush": ...}` — empty the given object's contents.
    pub fn flush(rs: *Ruleset, obj: Object) error{OutOfMemory}!void {
        try rs.push(.{ .flush = obj });
    }

    /// `flush ruleset` — wipe everything.
    pub fn flushRuleset(rs: *Ruleset) error{OutOfMemory}!void {
        try rs.flush(.ruleset);
    }

    pub fn addTable(rs: *Ruleset, family: Family, name: []const u8) error{OutOfMemory}!void {
        try rs.add(.{ .table = .{ .family = family, .name = name } });
    }

    pub fn addChain(rs: *Ruleset, chain: Chain) error{OutOfMemory}!void {
        try rs.add(.{ .chain = chain });
    }

    pub fn addSet(rs: *Ruleset, set: Set) error{OutOfMemory}!void {
        try rs.add(.{ .set = set });
    }

    /// Append `add rule` with a copy of `stmts` (the copy lives in the
    /// arena; nested expression slices are still borrowed).
    pub fn addRule(
        rs: *Ruleset,
        family: Family,
        table: []const u8,
        chain: []const u8,
        stmts: []const Stmt,
    ) error{OutOfMemory}!void {
        const owned = try rs.arena.allocator().dupe(Stmt, stmts);
        try rs.add(.{ .rule = .{
            .family = family,
            .table = table,
            .chain = chain,
            .expr = owned,
        } });
    }

    /// Start a fluent rule builder; finish with `apply()`.
    pub fn rule(rs: *Ruleset, family: Family, table: []const u8, chain: []const u8) RuleBuilder {
        return .{ .rs = rs, .family = family, .table = table, .chain = chain };
    }

    /// Serialize as minified JSON to a writer.
    pub fn writeJson(rs: *const Ruleset, w: *std.Io.Writer) JsonError!void {
        var jw: std.json.Stringify = .{ .writer = w, .options = .{} };
        try jw.beginObject();
        try jw.objectField("nftables");
        try jw.write(rs.cmds.items);
        try jw.endObject();
    }

    /// Serialize as minified JSON; caller owns the returned bytes.
    pub fn toJson(rs: *const Ruleset, gpa: std.mem.Allocator) error{OutOfMemory}![]u8 {
        var aw: std.Io.Writer.Allocating = .init(gpa);
        defer aw.deinit();
        rs.writeJson(&aw.writer) catch return error.OutOfMemory;
        return aw.toOwnedSlice();
    }
};

/// Fluent builder for one rule's statement list. Obtained from
/// `Ruleset.rule()`; every method returns the builder so calls chain.
/// Allocation failures are latched and reported by `apply()`.
pub const RuleBuilder = struct {
    rs: *Ruleset,
    family: Family,
    table: []const u8,
    chain: []const u8,
    stmts: std.ArrayList(Stmt) = .empty,
    comment: ?[]const u8 = null,
    oom: bool = false,

    /// Append the finished rule to the ruleset as `add rule`.
    pub fn apply(b: *RuleBuilder) error{OutOfMemory}!void {
        if (b.oom) return error.OutOfMemory;
        try b.rs.add(.{ .rule = .{
            .family = b.family,
            .table = b.table,
            .chain = b.chain,
            .expr = b.stmts.items,
            .comment = b.comment,
        } });
    }

    pub fn push(b: *RuleBuilder, s: Stmt) *RuleBuilder {
        b.stmts.append(b.rs.arena.allocator(), s) catch {
            b.oom = true;
        };
        return b;
    }

    /// Generic relational match.
    pub fn match(b: *RuleBuilder, left: Expr, op: Op, right: Expr) *RuleBuilder {
        return b.push(.{ .match = .{ .op = op, .left = left, .right = right } });
    }

    /// `<proto> <field> == right`, e.g. `payloadEq(.tcp, "flags", ...)`.
    pub fn payloadEq(b: *RuleBuilder, protocol: PayloadProto, field: []const u8, right: Expr) *RuleBuilder {
        return b.match(payloadField(protocol, field), .eq, right);
    }

    /// `tcp dport <right>` — right may be a number, range, anonymous set or
    /// `setRef`.
    pub fn tcpDport(b: *RuleBuilder, right: Expr) *RuleBuilder {
        return b.payloadEq(.tcp, "dport", right);
    }

    /// `udp dport <right>`.
    pub fn udpDport(b: *RuleBuilder, right: Expr) *RuleBuilder {
        return b.payloadEq(.udp, "dport", right);
    }

    /// `ip saddr <right>` — right may be a string address, `cidr`, range or set.
    pub fn ipSaddr(b: *RuleBuilder, right: Expr) *RuleBuilder {
        return b.payloadEq(.ip, "saddr", right);
    }

    /// `ip daddr <right>`.
    pub fn ipDaddr(b: *RuleBuilder, right: Expr) *RuleBuilder {
        return b.payloadEq(.ip, "daddr", right);
    }

    /// `ct state <states>`, e.g. `ctState(&.{ "established", "related" })`.
    pub fn ctState(b: *RuleBuilder, states: []const []const u8) *RuleBuilder {
        const list = b.rs.arena.allocator().alloc(Expr, states.len) catch {
            b.oom = true;
            return b;
        };
        for (states, list) |s, *e| e.* = .{ .str = s };
        return b.match(.{ .ct = .{ .key = "state" } }, .in, .{ .list = list });
    }

    /// `meta <key> == right`, e.g. `metaEq(.mark, num(1))`.
    pub fn metaEq(b: *RuleBuilder, key: MetaKey, right: Expr) *RuleBuilder {
        return b.match(.{ .meta = key }, .eq, right);
    }

    /// `iifname "<name>"`.
    pub fn iifname(b: *RuleBuilder, name: []const u8) *RuleBuilder {
        return b.metaEq(.iifname, str(name));
    }

    /// `oifname "<name>"`.
    pub fn oifname(b: *RuleBuilder, name: []const u8) *RuleBuilder {
        return b.metaEq(.oifname, str(name));
    }

    /// `meta l4proto <proto>`, e.g. `l4proto("icmp")`.
    pub fn l4proto(b: *RuleBuilder, protocol: []const u8) *RuleBuilder {
        return b.metaEq(.l4proto, str(protocol));
    }

    pub fn accept(b: *RuleBuilder) *RuleBuilder {
        return b.push(.accept);
    }

    pub fn drop(b: *RuleBuilder) *RuleBuilder {
        return b.push(.drop);
    }

    pub fn reject(b: *RuleBuilder) *RuleBuilder {
        return b.push(.{ .reject = .{} });
    }

    pub fn rejectWith(b: *RuleBuilder, r: Reject) *RuleBuilder {
        return b.push(.{ .reject = r });
    }

    pub fn ret(b: *RuleBuilder) *RuleBuilder {
        return b.push(.@"return");
    }

    pub fn jump(b: *RuleBuilder, target: []const u8) *RuleBuilder {
        return b.push(.{ .jump = target });
    }

    pub fn goto(b: *RuleBuilder, target: []const u8) *RuleBuilder {
        return b.push(.{ .goto = target });
    }

    pub fn counter(b: *RuleBuilder) *RuleBuilder {
        return b.push(.counter);
    }

    pub fn log(b: *RuleBuilder, prefix: []const u8) *RuleBuilder {
        return b.push(.{ .log = .{ .prefix = prefix } });
    }

    pub fn logWith(b: *RuleBuilder, l: Log) *RuleBuilder {
        return b.push(.{ .log = l });
    }

    pub fn limit(b: *RuleBuilder, l: Limit) *RuleBuilder {
        return b.push(.{ .limit = l });
    }

    pub fn masquerade(b: *RuleBuilder) *RuleBuilder {
        return b.push(.masquerade);
    }

    pub fn snat(b: *RuleBuilder, n: Nat) *RuleBuilder {
        return b.push(.{ .snat = n });
    }

    pub fn dnat(b: *RuleBuilder, n: Nat) *RuleBuilder {
        return b.push(.{ .dnat = n });
    }

    pub fn withComment(b: *RuleBuilder, c: []const u8) *RuleBuilder {
        b.comment = c;
        return b;
    }
};

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Assert `v` serializes to exactly `expected` (minified std.json).
fn expectJson(expected: []const u8, v: anytype) !void {
    const got = try std.json.Stringify.valueAlloc(testing.allocator, v, .{});
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(expected, got);
}

/// Parse `json` back with std.json to prove it is well-formed.
fn expectWellFormed(json: []const u8) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, json, .{});
    defer parsed.deinit();
    try testing.expect(parsed.value == .object);
    try testing.expect(parsed.value.object.get("nftables").? == .array);
}

test "golden: inet filter table with default-drop input chain" {
    var rs = Ruleset.init(testing.allocator);
    defer rs.deinit();

    try rs.flushRuleset();
    try rs.addTable(.inet, "filter");
    try rs.addChain(Chain.base(.inet, "filter", "input", .filter, .input, 0, .drop));

    var r1 = rs.rule(.inet, "filter", "input");
    try r1.ctState(&.{ "established", "related" }).accept().apply();

    var r2 = rs.rule(.inet, "filter", "input");
    try r2.tcpDport(num(22)).accept().apply();

    var r3 = rs.rule(.inet, "filter", "input");
    try r3.l4proto("icmp").accept().apply();

    const json = try rs.toJson(testing.allocator);
    defer testing.allocator.free(json);

    const expected =
        "{\"nftables\":[" ++
        "{\"flush\":{\"ruleset\":null}}," ++
        "{\"add\":{\"table\":{\"family\":\"inet\",\"name\":\"filter\"}}}," ++
        "{\"add\":{\"chain\":{\"family\":\"inet\",\"table\":\"filter\",\"name\":\"input\"," ++
        "\"type\":\"filter\",\"hook\":\"input\",\"prio\":0,\"policy\":\"drop\"}}}," ++
        "{\"add\":{\"rule\":{\"family\":\"inet\",\"table\":\"filter\",\"chain\":\"input\"," ++
        "\"expr\":[{\"match\":{\"op\":\"in\",\"left\":{\"ct\":{\"key\":\"state\"}}," ++
        "\"right\":[\"established\",\"related\"]}},{\"accept\":null}]}}}," ++
        "{\"add\":{\"rule\":{\"family\":\"inet\",\"table\":\"filter\",\"chain\":\"input\"," ++
        "\"expr\":[{\"match\":{\"op\":\"==\",\"left\":{\"payload\":{\"protocol\":\"tcp\"," ++
        "\"field\":\"dport\"}},\"right\":22}},{\"accept\":null}]}}}," ++
        "{\"add\":{\"rule\":{\"family\":\"inet\",\"table\":\"filter\",\"chain\":\"input\"," ++
        "\"expr\":[{\"match\":{\"op\":\"==\",\"left\":{\"meta\":{\"key\":\"l4proto\"}}," ++
        "\"right\":\"icmp\"}},{\"accept\":null}]}}}" ++
        "]}";
    try testing.expectEqualStrings(expected, json);
    try expectWellFormed(json);
}

test "golden: ip nat table with masquerade postrouting" {
    var rs = Ruleset.init(testing.allocator);
    defer rs.deinit();

    try rs.addTable(.ip, "nat");
    try rs.addChain(Chain.base(.ip, "nat", "postrouting", .nat, .postrouting, 100, .accept));

    var r = rs.rule(.ip, "nat", "postrouting");
    try r.oifname("eth0").masquerade().apply();

    const json = try rs.toJson(testing.allocator);
    defer testing.allocator.free(json);

    const expected =
        "{\"nftables\":[" ++
        "{\"add\":{\"table\":{\"family\":\"ip\",\"name\":\"nat\"}}}," ++
        "{\"add\":{\"chain\":{\"family\":\"ip\",\"table\":\"nat\",\"name\":\"postrouting\"," ++
        "\"type\":\"nat\",\"hook\":\"postrouting\",\"prio\":100,\"policy\":\"accept\"}}}," ++
        "{\"add\":{\"rule\":{\"family\":\"ip\",\"table\":\"nat\",\"chain\":\"postrouting\"," ++
        "\"expr\":[{\"match\":{\"op\":\"==\",\"left\":{\"meta\":{\"key\":\"oifname\"}}," ++
        "\"right\":\"eth0\"}},{\"masquerade\":null}]}}}" ++
        "]}";
    try testing.expectEqualStrings(expected, json);
    try expectWellFormed(json);
}

test "golden: named port set used in a rule" {
    var rs = Ruleset.init(testing.allocator);
    defer rs.deinit();

    try rs.addTable(.inet, "filter");
    try rs.addChain(Chain.regular(.inet, "filter", "input"));
    try rs.addSet(.{
        .family = .inet,
        .table = "filter",
        .name = "allowed_ports",
        .elem_type = .inet_service,
        .flags = &.{.interval},
        .elem = &.{ num(22), num(80), portRange(8000, 8100) },
    });

    var r = rs.rule(.inet, "filter", "input");
    try r.tcpDport(setRef("allowed_ports")).accept().apply();

    const json = try rs.toJson(testing.allocator);
    defer testing.allocator.free(json);

    const expected =
        "{\"nftables\":[" ++
        "{\"add\":{\"table\":{\"family\":\"inet\",\"name\":\"filter\"}}}," ++
        "{\"add\":{\"chain\":{\"family\":\"inet\",\"table\":\"filter\",\"name\":\"input\"}}}," ++
        "{\"add\":{\"set\":{\"family\":\"inet\",\"table\":\"filter\",\"name\":\"allowed_ports\"," ++
        "\"type\":\"inet_service\",\"flags\":[\"interval\"]," ++
        "\"elem\":[22,80,{\"range\":[8000,8100]}]}}}," ++
        "{\"add\":{\"rule\":{\"family\":\"inet\",\"table\":\"filter\",\"chain\":\"input\"," ++
        "\"expr\":[{\"match\":{\"op\":\"==\",\"left\":{\"payload\":{\"protocol\":\"tcp\"," ++
        "\"field\":\"dport\"}},\"right\":\"@allowed_ports\"}},{\"accept\":null}]}}}" ++
        "]}";
    try testing.expectEqualStrings(expected, json);
    try expectWellFormed(json);
}

test "enum tokens: match operators" {
    try expectJson("\"==\"", Op.eq);
    try expectJson("\"!=\"", Op.ne);
    try expectJson("\"<\"", Op.lt);
    try expectJson("\">\"", Op.gt);
    try expectJson("\"<=\"", Op.le);
    try expectJson("\">=\"", Op.ge);
    try expectJson("\"in\"", Op.in);
}

test "enum tokens: families, hooks, chain types, policies, special flags" {
    try expectJson("\"ip\"", Family.ip);
    try expectJson("\"ip6\"", Family.ip6);
    try expectJson("\"inet\"", Family.inet);
    try expectJson("\"arp\"", Family.arp);
    try expectJson("\"bridge\"", Family.bridge);
    try expectJson("\"netdev\"", Family.netdev);
    try expectJson("\"prerouting\"", Hook.prerouting);
    try expectJson("\"postrouting\"", Hook.postrouting);
    try expectJson("\"filter\"", ChainType.filter);
    try expectJson("\"nat\"", ChainType.nat);
    try expectJson("\"route\"", ChainType.route);
    try expectJson("\"accept\"", Policy.accept);
    try expectJson("\"drop\"", Policy.drop);
    try expectJson("\"iifname\"", MetaKey.iifname);
    try expectJson("\"l4proto\"", MetaKey.l4proto);
    // Tokens that are not Zig identifiers:
    try expectJson("\"fully-random\"", NatFlag.fully_random);
    try expectJson("\"tcp reset\"", RejectType.tcp_reset);
}

test "expression shapes" {
    try expectJson("\"eth0\"", str("eth0"));
    try expectJson("443", num(443));
    try expectJson("true", Expr{ .boolean = true });
    try expectJson("\"@myset\"", setRef("myset"));
    try expectJson(
        "{\"prefix\":{\"addr\":\"10.0.0.0\",\"len\":8}}",
        cidr("10.0.0.0", 8),
    );
    try expectJson("{\"range\":[1024,65535]}", portRange(1024, 65535));
    try expectJson(
        "{\"range\":[\"10.0.0.1\",\"10.0.0.9\"]}",
        Expr{ .range = .{ .lo = .{ .str = "10.0.0.1" }, .hi = .{ .str = "10.0.0.9" } } },
    );
    try expectJson("{\"set\":[22,80]}", anonSet(&.{ num(22), num(80) }));
    try expectJson("[\"established\",\"related\"]", Expr{ .list = &.{ str("established"), str("related") } });
    try expectJson(
        "{\"concat\":[{\"payload\":{\"protocol\":\"ip\",\"field\":\"saddr\"}},{\"payload\":{\"protocol\":\"tcp\",\"field\":\"dport\"}}]}",
        Expr{ .concat = &.{ payloadField(.ip, "saddr"), payloadField(.tcp, "dport") } },
    );
    try expectJson(
        "{\"payload\":{\"base\":\"nh\",\"offset\":64,\"len\":32}}",
        Expr{ .payload_raw = .{ .base = .nh, .offset = 64, .len = 32 } },
    );
    try expectJson(
        "{\"ct\":{\"key\":\"saddr\",\"family\":\"ip\",\"dir\":\"original\"}}",
        Expr{ .ct = .{ .key = "saddr", .family = .ip, .dir = .original } },
    );
}

test "statement shapes: verdicts, counter, jump/goto" {
    try expectJson("{\"accept\":null}", @as(Stmt, .accept));
    try expectJson("{\"drop\":null}", @as(Stmt, .drop));
    try expectJson("{\"return\":null}", @as(Stmt, .@"return"));
    try expectJson("{\"continue\":null}", @as(Stmt, .@"continue"));
    try expectJson("{\"counter\":null}", @as(Stmt, .counter));
    try expectJson("{\"counter\":\"http_hits\"}", Stmt{ .counter_ref = "http_hits" });
    try expectJson("{\"jump\":{\"target\":\"my_chain\"}}", Stmt{ .jump = "my_chain" });
    try expectJson("{\"goto\":{\"target\":\"my_chain\"}}", Stmt{ .goto = "my_chain" });
    try expectJson("{\"masquerade\":null}", @as(Stmt, .masquerade));
    try expectJson("{\"redirect\":null}", Stmt{ .redirect = null });
    try expectJson("{\"redirect\":{\"port\":8080}}", Stmt{ .redirect = 8080 });
}

test "statement shapes: reject, log, limit, nat" {
    try expectJson("{\"reject\":null}", Stmt{ .reject = .{} });
    try expectJson(
        "{\"reject\":{\"type\":\"tcp reset\"}}",
        Stmt{ .reject = .{ .type = .tcp_reset } },
    );
    try expectJson(
        "{\"reject\":{\"type\":\"icmpx\",\"expr\":\"admin-prohibited\"}}",
        Stmt{ .reject = .{ .type = .icmpx, .expr = str("admin-prohibited") } },
    );
    try expectJson("{\"log\":null}", Stmt{ .log = .{} });
    try expectJson(
        "{\"log\":{\"prefix\":\"ssh: \",\"queue-threshold\":10,\"level\":\"info\"}}",
        Stmt{ .log = .{ .prefix = "ssh: ", .queue_threshold = 10, .level = .info } },
    );
    try expectJson(
        "{\"limit\":{\"rate\":10,\"per\":\"second\"}}",
        Stmt{ .limit = .{ .rate = 10 } },
    );
    try expectJson(
        "{\"limit\":{\"rate\":1,\"per\":\"minute\",\"burst\":5,\"rate_unit\":\"kbytes\",\"inv\":true}}",
        Stmt{ .limit = .{ .rate = 1, .per = .minute, .burst = 5, .rate_unit = .kbytes, .inv = true } },
    );
    try expectJson(
        "{\"snat\":{\"addr\":\"192.0.2.1\",\"flags\":[\"random\",\"persistent\"]}}",
        Stmt{ .snat = .{ .addr = "192.0.2.1", .flags = &.{ .random, .persistent } } },
    );
    try expectJson(
        "{\"dnat\":{\"addr\":\"10.0.0.5\",\"family\":\"ip\",\"port\":8080}}",
        Stmt{ .dnat = .{ .addr = "10.0.0.5", .family = .ip, .port = 8080 } },
    );
}

test "command shapes: delete and flush" {
    var rs = Ruleset.init(testing.allocator);
    defer rs.deinit();

    try rs.delete(.{ .table = .{ .family = .inet, .name = "filter" } });
    try rs.delete(.{ .chain = Chain.regular(.inet, "filter", "input") });
    try rs.delete(.{ .set = .{
        .family = .inet,
        .table = "filter",
        .name = "allowed_ports",
        .elem_type = .inet_service,
    } });
    try rs.delete(.{ .rule = .{ .family = .inet, .table = "filter", .chain = "input", .handle = 42 } });
    try rs.flush(.{ .chain = Chain.regular(.inet, "filter", "input") });
    try rs.flush(.{ .table = .{ .family = .inet, .name = "filter" } });
    try rs.create(.{ .table = .{ .family = .ip, .name = "t" } });

    const json = try rs.toJson(testing.allocator);
    defer testing.allocator.free(json);

    const expected =
        "{\"nftables\":[" ++
        "{\"delete\":{\"table\":{\"family\":\"inet\",\"name\":\"filter\"}}}," ++
        "{\"delete\":{\"chain\":{\"family\":\"inet\",\"table\":\"filter\",\"name\":\"input\"}}}," ++
        "{\"delete\":{\"set\":{\"family\":\"inet\",\"table\":\"filter\",\"name\":\"allowed_ports\",\"type\":\"inet_service\"}}}," ++
        "{\"delete\":{\"rule\":{\"family\":\"inet\",\"table\":\"filter\",\"chain\":\"input\",\"handle\":42}}}," ++
        "{\"flush\":{\"chain\":{\"family\":\"inet\",\"table\":\"filter\",\"name\":\"input\"}}}," ++
        "{\"flush\":{\"table\":{\"family\":\"inet\",\"name\":\"filter\"}}}," ++
        "{\"create\":{\"table\":{\"family\":\"ip\",\"name\":\"t\"}}}" ++
        "]}";
    try testing.expectEqualStrings(expected, json);
    try expectWellFormed(json);
}

test "rule comment and handle emission" {
    try expectJson(
        "{\"rule\":{\"family\":\"inet\",\"table\":\"t\",\"chain\":\"c\"," ++
            "\"expr\":[{\"accept\":null}],\"handle\":7,\"comment\":\"allow all\"}}",
        Object{ .rule = .{
            .family = .inet,
            .table = "t",
            .chain = "c",
            .expr = &.{.accept},
            .handle = 7,
            .comment = "allow all",
        } },
    );
}

test "set optional properties emission" {
    try expectJson(
        "{\"set\":{\"family\":\"ip\",\"table\":\"t\",\"name\":\"s\",\"type\":\"ipv4_addr\"," ++
            "\"flags\":[\"interval\",\"timeout\"],\"elem\":[{\"prefix\":{\"addr\":\"10.0.0.0\",\"len\":8}}]," ++
            "\"timeout\":600,\"size\":1024,\"auto-merge\":true}}",
        Object{ .set = .{
            .family = .ip,
            .table = "t",
            .name = "s",
            .elem_type = .ipv4_addr,
            .flags = &.{ .interval, .timeout },
            .elem = &.{cidr("10.0.0.0", 8)},
            .timeout = 600,
            .size = 1024,
            .auto_merge = true,
        } },
    );
}

test "set reference name is JSON-escaped" {
    try expectJson("\"@we\\\"ird\"", setRef("we\"ird"));
}

test "builder and manual statement slice produce identical JSON" {
    var rs1 = Ruleset.init(testing.allocator);
    defer rs1.deinit();
    var b = rs1.rule(.inet, "filter", "input");
    try b.ipSaddr(cidr("192.168.0.0", 16)).tcpDport(anonSet(&.{ num(80), num(443) }))
        .counter().log("web: ").accept().apply();

    var rs2 = Ruleset.init(testing.allocator);
    defer rs2.deinit();
    try rs2.addRule(.inet, "filter", "input", &.{
        .{ .match = .{
            .op = .eq,
            .left = payloadField(.ip, "saddr"),
            .right = cidr("192.168.0.0", 16),
        } },
        .{ .match = .{
            .op = .eq,
            .left = payloadField(.tcp, "dport"),
            .right = anonSet(&.{ num(80), num(443) }),
        } },
        .counter,
        .{ .log = .{ .prefix = "web: " } },
        .accept,
    });

    const j1 = try rs1.toJson(testing.allocator);
    defer testing.allocator.free(j1);
    const j2 = try rs2.toJson(testing.allocator);
    defer testing.allocator.free(j2);
    try testing.expectEqualStrings(j1, j2);
    try expectWellFormed(j1);
}

// ── optional live check against the nft binary ──────────────────────────────
// `nft -c -j -f -` parses and validates without applying anything. JSON
// parse/schema errors are reported before the netlink stage, so even without
// CAP_NET_ADMIN (where cache initialization fails with EPERM) we can verify
// that nft's parser accepts our output. Never applies rules.

const NftCheck = struct {
    exit_code: ?u8, // null = terminated by signal etc.
    stderr: []u8,

    fn deinit(self: NftCheck, gpa: std.mem.Allocator) void {
        gpa.free(self.stderr);
    }
};

/// Pipe `json` to `nft -c -j -f -`; error.SkipZigTest if nft is unavailable.
fn runNftCheck(gpa: std.mem.Allocator, json: []const u8) !NftCheck {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // nft usually lives in sbin, which spawn's PATH lookup may not cover.
    const candidates = [_][]const u8{ "nft", "/usr/sbin/nft", "/sbin/nft" };
    var child: std.process.Child = for (candidates) |argv0| {
        break std.process.spawn(io, .{
            .argv = &.{ argv0, "-c", "-j", "-f", "-" },
            .stdin = .pipe,
            .stdout = .ignore,
            .stderr = .pipe,
        }) catch continue;
    } else return error.SkipZigTest;

    var wbuf: [512]u8 = undefined;
    var stdin_writer = child.stdin.?.writer(io, &wbuf);
    stdin_writer.interface.writeAll(json) catch return error.SkipZigTest;
    stdin_writer.interface.flush() catch return error.SkipZigTest;
    child.stdin.?.close(io);
    child.stdin = null;

    var rbuf: [4096]u8 = undefined;
    var stderr_reader = child.stderr.?.reader(io, &rbuf);
    const stderr = try stderr_reader.interface.allocRemaining(gpa, .unlimited);
    errdefer gpa.free(stderr);

    const term = child.wait(io) catch return error.SkipZigTest;
    return .{
        .exit_code = switch (term) {
            .exited => |code| code,
            else => null,
        },
        .stderr = stderr,
    };
}

fn netlinkPermissionDenied(stderr: []const u8) bool {
    return std.mem.indexOf(u8, stderr, "Operation not permitted") != null;
}

test "nft -c accepts a generated ruleset (skipped when nft is unavailable)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    var rs = Ruleset.init(gpa);
    defer rs.deinit();
    try rs.addTable(.inet, "zig_nftables_check");
    try rs.addChain(Chain.base(.inet, "zig_nftables_check", "input", .filter, .input, 0, .drop));
    try rs.addSet(.{
        .family = .inet,
        .table = "zig_nftables_check",
        .name = "ok_ports",
        .elem_type = .inet_service,
        .flags = &.{.interval},
        .elem = &.{ num(22), portRange(8000, 8100) },
    });
    var r1 = rs.rule(.inet, "zig_nftables_check", "input");
    try r1.ctState(&.{ "established", "related" }).accept().apply();
    var r2 = rs.rule(.inet, "zig_nftables_check", "input");
    try r2.ipSaddr(cidr("10.0.0.0", 8)).tcpDport(setRef("ok_ports")).counter()
        .log("ok: ").accept().apply();
    var r3 = rs.rule(.inet, "zig_nftables_check", "input");
    try r3.limit(.{ .rate = 10, .burst = 5 }).rejectWith(.{ .type = .tcp_reset }).apply();

    const json = try rs.toJson(gpa);
    defer gpa.free(json);

    const res = try runNftCheck(gpa, json);
    defer res.deinit(gpa);

    if (res.exit_code == null) return error.SkipZigTest;
    if (res.exit_code.? == 0) return; // fully validated (CAP_NET_ADMIN available)
    // Unprivileged: the parser accepted the JSON iff the only failure is the
    // netlink cache EPERM. A parse/schema rejection prints its own error and
    // never reaches netlink.
    if (netlinkPermissionDenied(res.stderr)) return;
    std.debug.print("nft -c rejected generated JSON:\n{s}\n", .{res.stderr});
    return error.TestUnexpectedResult;
}

test "nft -c rejects a deliberately bad ruleset (skipped when nft is unavailable)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;

    // Schema-invalid: unknown family. Must fail in the parser, i.e. before
    // any netlink access, whatever the privileges.
    const bad = "{\"nftables\":[{\"add\":{\"table\":{\"family\":\"bogus\",\"name\":\"t\"}}}]}";
    const res = try runNftCheck(gpa, bad);
    defer res.deinit(gpa);

    if (res.exit_code == null) return error.SkipZigTest;
    try testing.expect(res.exit_code.? != 0);
    try testing.expect(!netlinkPermissionDenied(res.stderr));
}
