// SPDX-License-Identifier: MIT

//! rdap — RDAP (Registration Data Access Protocol) client: the JSON-over-HTTPS
//! successor to whois (RFC 7480–7484; queries/responses renumbered as RFC
//! 9082/9083, bootstrap as RFC 9224). Pairs with the `whois` module.
//!
//! Four layers, each usable alone:
//!
//! - **Query URLs** (RFC 9082/7482): `buildPath` / `buildUrl` produce the
//!   `domain/<name>`, `ip/<addr-or-cidr>`, `autnum/<asn>`, `nameserver/<host>`,
//!   `entity/<handle>` paths with correct percent-encoding, plus the
//!   `application/rdap+json` Accept header (RFC 7480 §4.2).
//! - **Response model** (RFC 9083/7483): `parseResponse` maps the RDAP JSON
//!   into a typed `Object` (class, handle, names, status, events, entities
//!   with roles + best-effort jCard fn/org/email + their own nested entities
//!   (RFC 9083 §5.1, e.g. registrar → abuse contact, bounded by
//!   `max_entity_depth`), nameservers with glue addresses, links,
//!   notices/remarks, publicIds, GDPR `redacted` disclosures (RFC 9537),
//!   ip-network and autnum ranges) or a typed `RdapError` (RFC 7480 §5.3).
//!   Servers vary wildly — missing, extra and wrong-typed fields are
//!   tolerated everywhere; only malformed JSON errors out.
//! - **Bootstrap** (RFC 9224/7484): `parseBootstrap` reads an IANA bootstrap
//!   registry file; `Bootstrap.lookupDomain` / `.lookupIp` / `.lookupAsn`
//!   resolve the authoritative RDAP base URL (longest-match semantics),
//!   `bootstrapLookup` is the exact-key primitive.
//! - **Client**: `query` = build URL → fetch → parse, optionally following one
//!   `rel:"related"` link (registry → registrar). I/O goes through the
//!   `Fetcher` seam ("GET this URL, give me status + body"), so everything is
//!   offline-testable; `HttpFetcher` adapts our `http.Client` for real use.
//!
//! Provenance: clean-room from RFCs 7480/7482/7483/7484/9224 (plus their
//! 9082/9083 renumberings). No third-party RDAP implementation was consulted
//! or copied.

const std = @import("std");
const http = @import("http");
const netaddr = @import("netaddr");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "RDAP client (RFC 7480–7484) — JSON-over-HTTPS whois successor: query URLs, typed response model, IANA bootstrap, fetch seam",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any, // pure logic over the Fetcher seam; HttpFetcher uses `http`
    .role = .client,
    .concurrency = .reentrant, // no shared state anywhere
    .model_after = "RFC 7480-7484 RDAP; ARIN/RIPE RDAP behavior",
    .deps = .{ "http", "netaddr" },
};

// ── constants ───────────────────────────────────────────────────────────────

/// The RDAP media type (RFC 7480 §4.2).
pub const media_type = "application/rdap+json";

/// Ready-made Accept header for RDAP requests.
pub const accept_header: http.Header = .{ .name = "Accept", .value = media_type };

/// Upper bound for a built query URL (base + path).
pub const max_url_len = 2048;

// ── query URL construction (RFC 9082/7482) ──────────────────────────────────

/// The five RDAP lookup path segments (RFC 9082 §3.1).
pub const QueryType = enum {
    domain,
    ip,
    autnum,
    nameserver,
    entity,

    /// The URL path segment, e.g. `.domain` → "domain".
    pub fn segment(t: QueryType) []const u8 {
        return @tagName(t);
    }
};

pub const PathError = error{ PathTooLong, EmptyQuery };
pub const UrlError = error{ UrlTooLong, EmptyQuery, BadBase };

/// Build the query path `<segment>/<percent-encoded value>` into `buf`.
/// Unreserved characters (RFC 3986 §2.3) and `:` (IPv6 literals) pass
/// through; everything else — including the `/` of a CIDR — is
/// percent-encoded.
pub fn buildPath(buf: []u8, query_type: QueryType, value: []const u8) PathError![]const u8 {
    if (value.len == 0) return error.EmptyQuery;
    var w: std.Io.Writer = .fixed(buf);
    w.print("{s}/", .{query_type.segment()}) catch return error.PathTooLong;
    writeEncoded(&w, value) catch return error.PathTooLong;
    return w.buffered();
}

/// Build the full query URL: `base` (with or without a trailing `/`) joined
/// with `buildPath`'s output.
pub fn buildUrl(
    buf: []u8,
    base: []const u8,
    query_type: QueryType,
    value: []const u8,
) UrlError![]const u8 {
    if (base.len == 0) return error.BadBase;
    if (value.len == 0) return error.EmptyQuery;
    var w: std.Io.Writer = .fixed(buf);
    w.writeAll(base) catch return error.UrlTooLong;
    if (base[base.len - 1] != '/') w.writeByte('/') catch return error.UrlTooLong;
    w.print("{s}/", .{query_type.segment()}) catch return error.UrlTooLong;
    writeEncoded(&w, value) catch return error.UrlTooLong;
    return w.buffered();
}

fn writeEncoded(w: *std.Io.Writer, value: []const u8) error{WriteFailed}!void {
    for (value) |c| {
        if (std.ascii.isAlphanumeric(c) or switch (c) {
            '-', '.', '_', '~', ':' => true,
            else => false,
        }) {
            try w.writeByte(c);
        } else {
            try w.print("%{X:0>2}", .{c});
        }
    }
}

// ── response model (RFC 9083/7483) ──────────────────────────────────────────

/// `objectClassName` mapped to a tag; unrecognized classes are `.other`
/// (the raw name stays in `Object.object_class_name`).
pub const ObjectClass = enum { domain, ip_network, autnum, nameserver, entity, other };

fn classFromName(name: []const u8) ObjectClass {
    const map = [_]struct { n: []const u8, c: ObjectClass }{
        .{ .n = "domain", .c = .domain },
        .{ .n = "ip network", .c = .ip_network },
        .{ .n = "autnum", .c = .autnum },
        .{ .n = "nameserver", .c = .nameserver },
        .{ .n = "entity", .c = .entity },
    };
    for (map) |m| if (std.ascii.eqlIgnoreCase(m.n, name)) return m.c;
    return .other;
}

/// One `events[]` member (RFC 9083 §4.5). Dates stay as the RFC 3339 text
/// the server sent.
pub const Event = struct {
    action: []const u8 = "", // "registration", "expiration", "last changed", …
    date: []const u8 = "",
    actor: ?[]const u8 = null,
};

/// Cap on how many `entities[].entities[]…` levels `mapEntities` will
/// recurse into. RDAP nests entities to carry role-specific sub-contacts
/// (registrar → abuse, RFC 9083 §5.1) — the real captured golden in
/// `goldens.zig` nests exactly one level. Nothing on the wire bounds how
/// deep a hostile or broken server could go, so this caps the *mapping*
/// recursion `parseResponse` adds on top of `std.json`'s own tree. Matches
/// this module's tolerant-parsing policy (see the module doc comment):
/// entities nested past this depth are silently dropped rather than
/// rejecting the whole response. 8 is generous for anything a real registry
/// emits — matches the bound `devlink` uses for its own JSON-shaped nesting.
pub const max_entity_depth: u32 = 8;

/// One `entities[]` member (RFC 9083 §5.1) — handle + roles, plus a
/// best-effort extraction of fn/org/email from the jCard `vcardArray`.
pub const Entity = struct {
    handle: ?[]const u8 = null,
    roles: []const []const u8 = &.{},
    full_name: ?[]const u8 = null, // jCard "fn"
    org: ?[]const u8 = null, // jCard "org"
    email: ?[]const u8 = null, // jCard "email"
    /// This entity's own `links[]` (RFC 9083 §4.2) — e.g. a "self" link to
    /// its RDAP record, or "about" pointing at a sub-registrar's own RDAP API.
    links: []const Link = &.{},
    /// `publicIds[]` (RFC 9083 §4.8) — third-party identifiers, e.g. an
    /// IANA Registrar ID.
    public_ids: []const PublicId = &.{},
    /// This entity's own nested `entities[]` — RDAP's shape for
    /// role-specific sub-contacts (registrar → abuse, RFC 9083 §5.1).
    /// Bounded to `max_entity_depth` levels; see its doc comment.
    entities: []const Entity = &.{},

    pub fn hasRole(e: *const Entity, role: []const u8) bool {
        for (e.roles) |r| if (std.ascii.eqlIgnoreCase(r, role)) return true;
        return false;
    }

    /// First entity directly nested under `e` (one level — `e.entities`,
    /// not deeper) carrying `role`. Chain calls to go further, e.g.
    /// `o.entityWithRole("registrar").?.entityWithRole("abuse")`.
    pub fn entityWithRole(e: *const Entity, role: []const u8) ?*const Entity {
        for (e.entities) |*sub| if (sub.hasRole(role)) return sub;
        return null;
    }
};

/// One `nameservers[]` member (RFC 9083 §5.2), names + optional glue
/// addresses.
pub const Nameserver = struct {
    /// A nameserver is itself an RDAP object (RFC 9083 §5.2) and carries its
    /// own `handle` — distinct from the containing domain's `handle`.
    handle: ?[]const u8 = null,
    ldh_name: ?[]const u8 = null,
    unicode_name: ?[]const u8 = null,
    /// `ipAddresses.v4` — glue A records, when the server includes them.
    ipv4_addresses: []const []const u8 = &.{},
    /// `ipAddresses.v6` — glue AAAA records.
    ipv6_addresses: []const []const u8 = &.{},
    status: []const []const u8 = &.{},
};

/// One `publicIds[]` member (RFC 9083 §4.8) — a third-party identifier for
/// the object, e.g. an IANA Registrar ID on an entity.
pub const PublicId = struct {
    /// The JSON "type" member — named `id_type` because `type` is reserved
    /// in Zig.
    id_type: []const u8 = "",
    identifier: []const u8 = "",
};

/// One `redacted[]` member (RFC 9537) — which field(s) a privacy policy
/// (typically GDPR) removed or altered, and how.
pub const Redacted = struct {
    /// `name.type` when present (a registry-defined label, e.g. "Registry
    /// Domain ID"), else `name.description` (free text) — RFC 9537 §3
    /// requires exactly one of the two on `name`.
    name: ?[]const u8 = null,
    pre_path: ?[]const u8 = null, // JSONPath of the affected field(s)
    post_path: ?[]const u8 = null,
    replacement_path: ?[]const u8 = null,
    path_lang: ?[]const u8 = null, // default "jsonpath" when absent
    method: ?[]const u8 = null, // "removal" / "emptyValue" / "partialValue" / "referenceRemoval"
};

/// One `links[]` member (RFC 9083 §4.2). Entries without an `href` are
/// dropped during mapping.
pub const Link = struct {
    href: []const u8 = "",
    rel: ?[]const u8 = null, // "self", "related", …
    media_type: ?[]const u8 = null, // the JSON "type" member
    value: ?[]const u8 = null,
    title: ?[]const u8 = null,
};

/// One `notices[]` / `remarks[]` member (RFC 9083 §4.3).
pub const Notice = struct {
    title: ?[]const u8 = null,
    description: []const []const u8 = &.{},
};

/// An RDAP error response body (RFC 7480 §5.3).
pub const RdapError = struct {
    error_code: i64 = 0,
    title: ?[]const u8 = null,
    description: []const []const u8 = &.{},
};

/// The typed RDAP object — a superset of the common members across the five
/// object classes; unused members stay at their defaults. All slices are
/// owned by the surrounding `Parsed` arena.
pub const Object = struct {
    /// `rdapConformance[]` (RFC 9083 §4.1) — extension tags the server
    /// claims support for, e.g. `"redacted"` when `redacted` below is used.
    rdap_conformance: []const []const u8 = &.{},
    object_class: ObjectClass = .other,
    object_class_name: []const u8 = "",
    handle: ?[]const u8 = null,

    // domain / nameserver
    ldh_name: ?[]const u8 = null,
    unicode_name: ?[]const u8 = null,

    // ip network / autnum
    start_address: ?[]const u8 = null,
    end_address: ?[]const u8 = null,
    ip_version: ?[]const u8 = null, // "v4" / "v6"
    start_autnum: ?i64 = null,
    end_autnum: ?i64 = null,
    name: ?[]const u8 = null,
    country: ?[]const u8 = null,

    status: []const []const u8 = &.{},
    events: []const Event = &.{},
    entities: []const Entity = &.{},
    nameservers: []const Nameserver = &.{},
    links: []const Link = &.{},
    notices: []const Notice = &.{},
    remarks: []const Notice = &.{},
    port43: ?[]const u8 = null,
    /// `publicIds[]` (RFC 9083 §4.8) — third-party identifiers for this
    /// object.
    public_ids: []const PublicId = &.{},
    /// `redacted[]` (RFC 9537) — GDPR/privacy redaction disclosures.
    redacted: []const Redacted = &.{},

    /// `eventDate` of the first event with this action
    /// (ASCII case-insensitive), e.g. "registration", "expiration".
    pub fn eventDate(o: *const Object, action: []const u8) ?[]const u8 {
        for (o.events) |e| if (std.ascii.eqlIgnoreCase(e.action, action)) return e.date;
        return null;
    }

    /// First entity carrying `role` (e.g. "registrar", "registrant").
    pub fn entityWithRole(o: *const Object, role: []const u8) ?*const Entity {
        for (o.entities) |*e| if (e.hasRole(role)) return e;
        return null;
    }

    /// `href` of the first link with this `rel` (e.g. "self", "related").
    pub fn linkHref(o: *const Object, rel: []const u8) ?[]const u8 {
        for (o.links) |l| {
            const r = l.rel orelse continue;
            if (std.ascii.eqlIgnoreCase(r, rel)) return l.href;
        }
        return null;
    }
};

/// A parsed RDAP response body: either an object or a typed error.
pub const Document = union(enum) {
    object: Object,
    rdap_error: RdapError,
};

/// Owns everything `Document` points at. Call `deinit` when done.
pub const Parsed = struct {
    arena: *std.heap.ArenaAllocator,
    document: Document,

    pub fn deinit(p: *Parsed) void {
        const gpa = p.arena.child_allocator;
        p.arena.deinit();
        gpa.destroy(p.arena);
        p.* = undefined;
    }
};

pub const ParseError = error{
    /// Not well-formed JSON (includes truncation).
    InvalidJson,
    /// Well-formed JSON, but the top level is not an object.
    InvalidRdap,
    OutOfMemory,
};

/// Parse an RDAP response body into a typed `Document`. A top-level
/// `errorCode` member selects the `rdap_error` arm (RFC 7480 §5.3); anything
/// else maps to `Object`, tolerating missing, extra and wrong-typed members —
/// sparse or surprising (but well-formed) JSON never fails. All strings are
/// copied into the result's arena; `json_text` may be reused afterwards.
pub fn parseResponse(gpa: std.mem.Allocator, json_text: []const u8) ParseError!Parsed {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();

    const root = std.json.parseFromSliceLeaky(std.json.Value, a, json_text, .{}) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidJson,
        };
    const obj = switch (root) {
        .object => |o| o,
        else => return error.InvalidRdap,
    };

    const document: Document = if (obj.get("errorCode") != null)
        .{ .rdap_error = try mapError(a, obj) }
    else
        .{ .object = try mapObject(a, obj) };
    return .{ .arena = arena, .document = document };
}

// ── JSON → model mapping (tolerant: wrong types degrade to defaults) ────────

fn getStr(obj: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .string => |s| s,
        else => null,
    };
}

fn getObj(obj: std.json.ObjectMap, key: []const u8) ?std.json.ObjectMap {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .object => |o| o,
        else => null,
    };
}

fn dupField(
    a: std.mem.Allocator,
    obj: std.json.ObjectMap,
    key: []const u8,
) error{OutOfMemory}!?[]const u8 {
    const s = getStr(obj, key) orelse return null;
    return try a.dupe(u8, s);
}

fn intField(obj: std.json.ObjectMap, key: []const u8) ?i64 {
    const v = obj.get(key) orelse return null;
    return switch (v) {
        .integer => |i| i,
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

fn arrayOf(v_opt: ?std.json.Value) ?std.json.Array {
    const v = v_opt orelse return null;
    return switch (v) {
        .array => |x| x,
        else => null,
    };
}

fn strListField(
    a: std.mem.Allocator,
    obj: std.json.ObjectMap,
    key: []const u8,
) error{OutOfMemory}![]const []const u8 {
    const arr = arrayOf(obj.get(key)) orelse return &.{};
    var list: std.ArrayList([]const u8) = .empty;
    for (arr.items) |item| switch (item) {
        .string => |s| try list.append(a, try a.dupe(u8, s)),
        else => {},
    };
    return try list.toOwnedSlice(a);
}

fn mapError(a: std.mem.Allocator, obj: std.json.ObjectMap) error{OutOfMemory}!RdapError {
    return .{
        .error_code = intField(obj, "errorCode") orelse 0,
        .title = try dupField(a, obj, "title"),
        .description = try strListField(a, obj, "description"),
    };
}

fn mapObject(a: std.mem.Allocator, obj: std.json.ObjectMap) error{OutOfMemory}!Object {
    var o: Object = .{};
    o.rdap_conformance = try strListField(a, obj, "rdapConformance");
    if (getStr(obj, "objectClassName")) |s| {
        o.object_class_name = try a.dupe(u8, s);
        o.object_class = classFromName(s);
    }
    o.handle = try dupField(a, obj, "handle");
    o.ldh_name = try dupField(a, obj, "ldhName");
    o.unicode_name = try dupField(a, obj, "unicodeName");
    o.start_address = try dupField(a, obj, "startAddress");
    o.end_address = try dupField(a, obj, "endAddress");
    o.ip_version = try dupField(a, obj, "ipVersion");
    o.start_autnum = intField(obj, "startAutnum");
    o.end_autnum = intField(obj, "endAutnum");
    o.name = try dupField(a, obj, "name");
    o.country = try dupField(a, obj, "country");
    o.port43 = try dupField(a, obj, "port43");
    o.status = try strListField(a, obj, "status");
    o.events = try mapEvents(a, obj.get("events"));
    o.entities = try mapEntities(a, obj.get("entities"), 0);
    o.nameservers = try mapNameservers(a, obj.get("nameservers"));
    o.links = try mapLinks(a, obj.get("links"));
    o.notices = try mapNotices(a, obj.get("notices"));
    o.remarks = try mapNotices(a, obj.get("remarks"));
    o.public_ids = try mapPublicIds(a, obj.get("publicIds"));
    o.redacted = try mapRedacted(a, obj.get("redacted"));
    return o;
}

fn mapEvents(a: std.mem.Allocator, v_opt: ?std.json.Value) error{OutOfMemory}![]const Event {
    const arr = arrayOf(v_opt) orelse return &.{};
    var list: std.ArrayList(Event) = .empty;
    for (arr.items) |item| {
        const eo = switch (item) {
            .object => |x| x,
            else => continue,
        };
        try list.append(a, .{
            .action = if (getStr(eo, "eventAction")) |s| try a.dupe(u8, s) else "",
            .date = if (getStr(eo, "eventDate")) |s| try a.dupe(u8, s) else "",
            .actor = try dupField(a, eo, "eventActor"),
        });
    }
    return try list.toOwnedSlice(a);
}

/// `depth` is the number of `entities[].entities[]…` hops already taken to
/// reach this call (0 at the top level); recursion stops silently past
/// `max_entity_depth` — see its doc comment for why that is a drop, not an
/// error.
fn mapEntities(
    a: std.mem.Allocator,
    v_opt: ?std.json.Value,
    depth: u32,
) error{OutOfMemory}![]const Entity {
    const arr = arrayOf(v_opt) orelse return &.{};
    var list: std.ArrayList(Entity) = .empty;
    for (arr.items) |item| {
        const eo = switch (item) {
            .object => |x| x,
            else => continue,
        };
        var ent: Entity = .{
            .handle = try dupField(a, eo, "handle"),
            .roles = try strListField(a, eo, "roles"),
            .links = try mapLinks(a, eo.get("links")),
            .public_ids = try mapPublicIds(a, eo.get("publicIds")),
        };
        if (eo.get("vcardArray")) |vc| try extractVcard(a, vc, &ent);
        if (depth < max_entity_depth) {
            ent.entities = try mapEntities(a, eo.get("entities"), depth + 1);
        }
        try list.append(a, ent);
    }
    return try list.toOwnedSlice(a);
}

/// Shared by `Object.public_ids` and `Entity.public_ids`.
fn mapPublicIds(a: std.mem.Allocator, v_opt: ?std.json.Value) error{OutOfMemory}![]const PublicId {
    const arr = arrayOf(v_opt) orelse return &.{};
    var list: std.ArrayList(PublicId) = .empty;
    for (arr.items) |item| {
        const po = switch (item) {
            .object => |x| x,
            else => continue,
        };
        try list.append(a, .{
            .id_type = if (getStr(po, "type")) |s| try a.dupe(u8, s) else "",
            .identifier = if (getStr(po, "identifier")) |s| try a.dupe(u8, s) else "",
        });
    }
    return try list.toOwnedSlice(a);
}

fn mapRedacted(a: std.mem.Allocator, v_opt: ?std.json.Value) error{OutOfMemory}![]const Redacted {
    const arr = arrayOf(v_opt) orelse return &.{};
    var list: std.ArrayList(Redacted) = .empty;
    for (arr.items) |item| {
        const ro = switch (item) {
            .object => |x| x,
            else => continue,
        };
        var name: ?[]const u8 = null;
        if (getObj(ro, "name")) |n| {
            name = try dupField(a, n, "type");
            if (name == null) name = try dupField(a, n, "description");
        }
        try list.append(a, .{
            .name = name,
            .pre_path = try dupField(a, ro, "prePath"),
            .post_path = try dupField(a, ro, "postPath"),
            .replacement_path = try dupField(a, ro, "replacementPath"),
            .path_lang = try dupField(a, ro, "pathLang"),
            .method = try dupField(a, ro, "method"),
        });
    }
    return try list.toOwnedSlice(a);
}

/// Best-effort jCard (RFC 7095) extraction: the first fn / org / email
/// property text. Anything structurally unexpected is skipped silently.
fn extractVcard(a: std.mem.Allocator, v: std.json.Value, ent: *Entity) error{OutOfMemory}!void {
    const outer = switch (v) {
        .array => |x| x,
        else => return,
    };
    if (outer.items.len < 2) return;
    const props = switch (outer.items[1]) {
        .array => |x| x,
        else => return,
    };
    for (props.items) |prop_v| {
        const prop = switch (prop_v) {
            .array => |x| x,
            else => continue,
        };
        if (prop.items.len < 4) continue;
        const pname = switch (prop.items[0]) {
            .string => |s| s,
            else => continue,
        };
        // jCard value: usually a text string; structured values ("org" may be
        // an array of components) degrade to their first text component.
        const pval: ?[]const u8 = switch (prop.items[3]) {
            .string => |s| s,
            .array => |va| blk: {
                for (va.items) |e| switch (e) {
                    .string => |s| if (s.len > 0) break :blk s,
                    else => {},
                };
                break :blk null;
            },
            else => null,
        };
        const value = pval orelse continue;
        if (std.ascii.eqlIgnoreCase(pname, "fn")) {
            if (ent.full_name == null) ent.full_name = try a.dupe(u8, value);
        } else if (std.ascii.eqlIgnoreCase(pname, "org")) {
            if (ent.org == null) ent.org = try a.dupe(u8, value);
        } else if (std.ascii.eqlIgnoreCase(pname, "email")) {
            if (ent.email == null) ent.email = try a.dupe(u8, value);
        }
    }
}

fn mapNameservers(
    a: std.mem.Allocator,
    v_opt: ?std.json.Value,
) error{OutOfMemory}![]const Nameserver {
    const arr = arrayOf(v_opt) orelse return &.{};
    var list: std.ArrayList(Nameserver) = .empty;
    for (arr.items) |item| {
        const no = switch (item) {
            .object => |x| x,
            else => continue,
        };
        const ip_obj = getObj(no, "ipAddresses");
        try list.append(a, .{
            .handle = try dupField(a, no, "handle"),
            .ldh_name = try dupField(a, no, "ldhName"),
            .unicode_name = try dupField(a, no, "unicodeName"),
            .status = try strListField(a, no, "status"),
            .ipv4_addresses = if (ip_obj) |io| try strListField(a, io, "v4") else &.{},
            .ipv6_addresses = if (ip_obj) |io| try strListField(a, io, "v6") else &.{},
        });
    }
    return try list.toOwnedSlice(a);
}

fn mapLinks(a: std.mem.Allocator, v_opt: ?std.json.Value) error{OutOfMemory}![]const Link {
    const arr = arrayOf(v_opt) orelse return &.{};
    var list: std.ArrayList(Link) = .empty;
    for (arr.items) |item| {
        const lo = switch (item) {
            .object => |x| x,
            else => continue,
        };
        const href = getStr(lo, "href") orelse continue; // a link without href is useless
        try list.append(a, .{
            .href = try a.dupe(u8, href),
            .rel = try dupField(a, lo, "rel"),
            .media_type = try dupField(a, lo, "type"),
            .value = try dupField(a, lo, "value"),
            .title = try dupField(a, lo, "title"),
        });
    }
    return try list.toOwnedSlice(a);
}

fn mapNotices(a: std.mem.Allocator, v_opt: ?std.json.Value) error{OutOfMemory}![]const Notice {
    const arr = arrayOf(v_opt) orelse return &.{};
    var list: std.ArrayList(Notice) = .empty;
    for (arr.items) |item| {
        const no = switch (item) {
            .object => |x| x,
            else => continue,
        };
        try list.append(a, .{
            .title = try dupField(a, no, "title"),
            .description = try strListField(a, no, "description"),
        });
    }
    return try list.toOwnedSlice(a);
}

// ── bootstrap (RFC 9224/7484) ───────────────────────────────────────────────

/// A parsed IANA bootstrap registry file
/// (`{"services": [[["net","com"], ["https://rdap.example/"]], …]}`).
pub const Bootstrap = struct {
    arena: *std.heap.ArenaAllocator,
    services: []const Service,

    pub const Service = struct {
        keys: []const []const u8,
        urls: []const []const u8,
    };

    pub fn deinit(b: *Bootstrap) void {
        const gpa = b.arena.child_allocator;
        b.arena.deinit();
        gpa.destroy(b.arena);
        b.* = undefined;
    }

    /// Exact key match (ASCII case-insensitive) → the service URL list.
    pub fn lookup(b: *const Bootstrap, key: []const u8) ?[]const []const u8 {
        for (b.services) |s| for (s.keys) |k| {
            if (std.ascii.eqlIgnoreCase(k, key)) return s.urls;
        };
        return null;
    }

    /// DNS bootstrap: resolve a domain name against the TLD keys (longest
    /// matching label suffix wins, per RFC 9224 §4; a trailing root dot is
    /// ignored).
    pub fn lookupDomain(b: *const Bootstrap, domain: []const u8) ?[]const []const u8 {
        var d = domain;
        if (d.len > 0 and d[d.len - 1] == '.') d = d[0 .. d.len - 1];
        var best: ?[]const []const u8 = null;
        var best_len: usize = 0;
        for (b.services) |s| for (s.keys) |k| {
            if (k.len + 1 <= best_len or !domainSuffixMatch(d, k)) continue;
            best_len = k.len + 1;
            best = s.urls;
        };
        return best;
    }

    /// IPv4/IPv6 bootstrap: longest-prefix CIDR match. `addr_text` may be a
    /// bare address or a CIDR (its network address is matched).
    pub fn lookupIp(b: *const Bootstrap, addr_text: []const u8) ?[]const []const u8 {
        const bare = if (std.mem.indexOfScalar(u8, addr_text, '/')) |i|
            addr_text[0..i]
        else
            addr_text;
        const ip = netaddr.parseIp(bare) orelse return null;
        var best: ?[]const []const u8 = null;
        var best_bits: i16 = -1;
        for (b.services) |s| for (s.keys) |k| {
            const bits = cidrMatch(ip, k) orelse continue;
            if (bits > best_bits) {
                best_bits = bits;
                best = s.urls;
            }
        };
        return best;
    }

    /// ASN bootstrap: keys are `start-end` ranges (or single numbers).
    pub fn lookupAsn(b: *const Bootstrap, asn: u32) ?[]const []const u8 {
        for (b.services) |s| for (s.keys) |k| {
            var lo_text = k;
            var hi_text = k;
            if (std.mem.indexOfScalar(u8, k, '-')) |i| {
                lo_text = k[0..i];
                hi_text = k[i + 1 ..];
            }
            const lo = std.fmt.parseInt(u32, lo_text, 10) catch continue;
            const hi = std.fmt.parseInt(u32, hi_text, 10) catch continue;
            if (asn >= lo and asn <= hi) return s.urls;
        };
        return null;
    }
};

/// Free-function form of the exact-key lookup (RFC 9224 §5 match primitive).
pub fn bootstrapLookup(registry: *const Bootstrap, key: []const u8) ?[]const []const u8 {
    return registry.lookup(key);
}

/// Parse an IANA bootstrap registry file. Service entries take the **last
/// two** arrays as `[keys, urls]`, which also accepts the three-element
/// object-tag form (RFC 8521 prepends a contact array); malformed entries
/// are skipped.
pub fn parseBootstrap(gpa: std.mem.Allocator, json_text: []const u8) ParseError!Bootstrap {
    const arena = try gpa.create(std.heap.ArenaAllocator);
    arena.* = std.heap.ArenaAllocator.init(gpa);
    errdefer {
        arena.deinit();
        gpa.destroy(arena);
    }
    const a = arena.allocator();

    const root = std.json.parseFromSliceLeaky(std.json.Value, a, json_text, .{}) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.InvalidJson,
        };
    const obj = switch (root) {
        .object => |o| o,
        else => return error.InvalidRdap,
    };
    const services_arr = arrayOf(obj.get("services")) orelse return error.InvalidRdap;

    var list: std.ArrayList(Bootstrap.Service) = .empty;
    for (services_arr.items) |entry_v| {
        const entry = switch (entry_v) {
            .array => |x| x,
            else => continue,
        };
        if (entry.items.len < 2) continue;
        const keys = try dupStrArray(a, entry.items[entry.items.len - 2]);
        const urls = try dupStrArray(a, entry.items[entry.items.len - 1]);
        if (keys.len == 0 or urls.len == 0) continue;
        try list.append(a, .{ .keys = keys, .urls = urls });
    }
    return .{ .arena = arena, .services = try list.toOwnedSlice(a) };
}

fn dupStrArray(a: std.mem.Allocator, v: std.json.Value) error{OutOfMemory}![]const []const u8 {
    const arr = switch (v) {
        .array => |x| x,
        else => return &.{},
    };
    var list: std.ArrayList([]const u8) = .empty;
    for (arr.items) |item| switch (item) {
        .string => |s| try list.append(a, try a.dupe(u8, s)),
        else => {},
    };
    return try list.toOwnedSlice(a);
}

/// True when `domain` equals `key` or ends with `"." ++ key`
/// (ASCII case-insensitive).
fn domainSuffixMatch(domain: []const u8, key: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(domain, key)) return true;
    if (domain.len < key.len + 2) return false;
    return domain[domain.len - key.len - 1] == '.' and
        std.ascii.eqlIgnoreCase(domain[domain.len - key.len ..], key);
}

/// If `ip` falls inside CIDR `cidr` ("192.0.0.0/8", "2001:4200::/23"),
/// return the prefix length; null on mismatch (including family mismatch)
/// or a malformed CIDR.
fn cidrMatch(ip: netaddr.Ip, cidr: []const u8) ?i16 {
    const slash = std.mem.indexOfScalar(u8, cidr, '/') orelse return null;
    const net_ip = netaddr.parseIp(cidr[0..slash]) orelse return null;
    const plen = std.fmt.parseInt(u8, cidr[slash + 1 ..], 10) catch return null;
    switch (net_ip) {
        .v4 => |nb| {
            const ab = switch (ip) {
                .v4 => |x| x,
                .v6 => return null,
            };
            if (plen > 32) return null;
            if (!bitsEqual(&ab, &nb, plen)) return null;
        },
        .v6 => |nb| {
            const ab = switch (ip) {
                .v6 => |x| x,
                .v4 => return null,
            };
            if (plen > 128) return null;
            if (!bitsEqual(&ab, &nb, plen)) return null;
        },
    }
    return plen;
}

fn bitsEqual(a: []const u8, b: []const u8, bits: u8) bool {
    const full: usize = bits / 8;
    const rem: u3 = @intCast(bits % 8);
    if (!std.mem.eql(u8, a[0..full], b[0..full])) return false;
    if (rem == 0) return true;
    const mask = ~(@as(u8, 0xff) >> rem);
    return (a[full] & mask) == (b[full] & mask);
}

// ── fetch seam + client ─────────────────────────────────────────────────────

pub const FetchError = error{
    /// Connect / TLS / send / receive failed.
    FetchFailed,
    /// The body did not fit the caller's buffer (byte cap).
    ResponseTooLarge,
    /// The blocked wait was canceled through the `std.Io` cancellation
    /// protocol (`Future.cancel`). Surfaced instead of `FetchFailed` so a
    /// caller can tell a canceled wait from a real transport failure.
    Canceled,
};

/// The one I/O operation RDAP needs: GET `url` (with the RDAP Accept
/// header), return the HTTP status and the body bytes in `body_buf`.
/// Implementations MUST return `error.ResponseTooLarge` instead of
/// truncating silently.
pub const Fetcher = struct {
    ctx: *anyopaque,
    fetchFn: *const fn (ctx: *anyopaque, url: []const u8, body_buf: []u8) FetchError!Result,

    pub const Result = struct { status: u16, body_len: usize };
    pub const Response = struct { status: u16, body: []const u8 };

    pub fn fetch(f: Fetcher, url: []const u8, body_buf: []u8) FetchError!Response {
        const r = try f.fetchFn(f.ctx, url, body_buf);
        if (r.body_len > body_buf.len) return error.FetchFailed;
        return .{ .status = r.status, .body = body_buf[0..r.body_len] };
    }
};

/// RDAP query driver over a `Fetcher` seam.
pub const Client = struct {
    fetcher: Fetcher,
    gpa: std.mem.Allocator,
    /// Where this client may dial. See `DestinationPolicy` — both terms
    /// default to deny, and they apply to the primary query as well as the
    /// related hop. The primary URL is not automatically trustworthy: the
    /// documented way to obtain one is `Bootstrap.lookupDomain`, which returns
    /// service URLs parsed straight out of an untrusted registry file.
    destinations: DestinationPolicy = .{},

    pub const QueryError = FetchError || ParseError || UrlError || DestinationError ||
        error{
            /// HTTP 404 — the queried object does not exist (RFC 7480 §5.3).
            NotFound,
            /// Non-2xx status without a parseable RDAP error body. `query`'s
            /// `status_out` parameter carries the actual status code, since
            /// this error itself cannot.
            HttpStatus,
        };

    pub const QueryOptions = struct {
        /// After a successful lookup, follow one `rel:"related"` RDAP link
        /// (registry → registrar redirection, RFC 7480 §5.2) and return that
        /// document instead — falling back to the first document when the
        /// follow-up fetch or parse fails.
        follow_related: bool = false,
    };

    /// Build the query URL, fetch it, and parse the response. `body_buf` is
    /// the per-response byte cap (reused for the optional related-link hop —
    /// safe, because `Parsed` owns arena copies of everything). Returns a
    /// `Parsed` the caller must `deinit`.
    ///
    /// `status_out`, if non-null, is filled with the HTTP status of the
    /// *primary* fetch when (and only when) `query` returns
    /// `error.HttpStatus` — a non-2xx response without a parseable RDAP
    /// error body, e.g. a bare 429 or 500 from a proxy in front of the
    /// registry. Without it a caller cannot tell a rate limit from a server
    /// error and so cannot implement backoff. The (rare, best-effort)
    /// related-link hop never writes to it: a failed hop already falls back
    /// to the first document silently, and reporting that hop's status
    /// through the same out-pointer would misattribute it to the query the
    /// caller actually asked about.
    pub fn query(
        c: *Client,
        base_url: []const u8,
        query_type: QueryType,
        value: []const u8,
        options: QueryOptions,
        body_buf: []u8,
        status_out: ?*u16,
    ) QueryError!Parsed {
        var url_buf: [max_url_len]u8 = undefined;
        const url = try buildUrl(&url_buf, base_url, query_type, value);
        var parsed = try c.fetchAndParse(url, body_buf, status_out);
        if (!options.follow_related) return parsed;

        const related_opt: ?[]const u8 = switch (parsed.document) {
            .object => |o| o.linkHref("related"),
            .rdap_error => null,
        };
        const related = related_opt orelse return parsed;
        // Same gate as the primary — including the https requirement, so a
        // `related` href cannot walk the exchange off TLS. A refused hop falls
        // back to the document we already have, as a failed one always did.
        const followed = c.fetchAndParse(related, body_buf, null) catch return parsed;
        parsed.deinit();
        return followed;
    }

    fn fetchAndParse(c: *Client, url: []const u8, body_buf: []u8, status_out: ?*u16) QueryError!Parsed {
        try checkDestination(url, c.destinations);
        const res = try c.fetcher.fetch(url, body_buf);
        if (res.status == 404) return error.NotFound;
        const failure = res.status < 200 or res.status >= 300;
        var parsed = parseResponse(c.gpa, res.body) catch |err| {
            if (err != error.OutOfMemory and failure) {
                if (status_out) |so| so.* = res.status;
                return error.HttpStatus;
            }
            return err;
        };
        if (failure and parsed.document != .rdap_error) {
            // A failure status must carry an RDAP error body to be typed.
            parsed.deinit();
            if (status_out) |so| so.* = res.status;
            return error.HttpStatus;
        }
        return parsed;
    }
};

fn isHttpUrl(s: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(s, "https://") or
        std.ascii.startsWithIgnoreCase(s, "http://");
}

// ── related-link destination policy (SSRF hardening) ────────────────────────
// RDAP's whole point is cross-registry redirection, so a hostile or
// compromised registry can name anything in a `rel:"related"` href. Without a
// destination check, `follow_related` would fetch whatever host the response
// names (SSRF). Default-deny special-use address space before ever fetching
// a related link.

/// True when `host` (as returned by `http.Url.parse`) names special-use /
/// non-routable address space: the conventional `localhost` name, or an IP
/// literal in loopback (`127.0.0.0/8`, `::1`), RFC 1918 private (`10/8`,
/// `172.16/12`, `192.168/16`), link-local (`169.254.0.0/16`, `fe80::/10`),
/// IPv6 unique-local (`fc00::/7`), unspecified (`0.0.0.0`, `::`), multicast,
/// or documentation space (RFC 5737 TEST-NET-1/2/3, RFC 3849 `2001:db8::/32`).
/// A host that is a hostname other than `localhost` is not classified
/// here — it is left to the caller's `Fetcher`/`http.Client`'s own resolver;
/// this check catches the literal-IP and `localhost` cases the audit found
/// directly exploitable.
fn isSpecialUseHost(raw_host: []const u8) bool {
    // A trailing root dot is the ABSOLUTE spelling of the same name: every
    // resolver treats `localhost.` as `localhost` (verified on this host —
    // `getent hosts localhost.` answers `::1`). Comparing the unnormalised
    // string missed it, `netaddr.parseIp` rejected it, and the function
    // returned false — so the one hostname this guard exists to deny was
    // reachable in one hop by writing it with a dot on the end.
    const host = std.mem.trimEnd(u8, raw_host, ".");
    if (host.len == 0) return true; // "." / "" is not a destination
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
    if (std.ascii.endsWithIgnoreCase(host, ".localhost")) return true;
    const ip = netaddr.parseIp(host) orelse return false;
    return isSpecialUseIp(ip);
}

/// What this module will dial. Applied to **every** URL it fetches — the
/// primary query, the `rel:"related"` hop, and each redirect `Location` —
/// because the address that matters is the one finally connected to, and a
/// check on the first of those bounds nothing.
///
/// Both defaults are deny. RDAP is an https protocol (every IANA bootstrap
/// entry is https) and its trust rests entirely on TLS to the server, so a
/// plaintext destination is a downgrade whoever named it. Point a client at a
/// loopback or plaintext server on purpose by relaxing these.
pub const DestinationPolicy = struct {
    /// Refuse special-use / non-routable address space (see `isSpecialUseHost`).
    deny_special_use: bool = true,
    /// Refuse `http://`; only `https://` may be dialed.
    require_https: bool = true,
};

pub const DestinationError = error{
    /// The URL is not http(s), or is not parseable as one.
    BadDestination,
    /// The destination is refused by the active `DestinationPolicy`.
    BlockedDestination,
};

/// The single gate every dial in this module passes through.
pub fn checkDestination(url: []const u8, policy: DestinationPolicy) DestinationError!void {
    if (!isHttpUrl(url)) return error.BadDestination;
    if (policy.require_https and !std.ascii.startsWithIgnoreCase(url, "https://")) {
        return error.BlockedDestination;
    }
    const parsed = http.Url.parse(url) catch return error.BadDestination;
    if (policy.deny_special_use and isSpecialUseHost(parsed.host)) return error.BlockedDestination;
}

/// The policy: which address space this module refuses to follow a related
/// link into. Every term is a `netaddr` predicate — the RFC 1918 check used to
/// be open-coded here, which is how a filter drifts from the addressing rules
/// it is supposed to implement. What stays local is the *choice* of terms,
/// because that is the threat model, not addressing.
fn isSpecialUseIp(ip: netaddr.Ip) bool {
    return ip.isUnspecified() or ip.isLoopback() or ip.isLinkLocalUnicast() or
        ip.isMulticast() or ip.isUniqueLocal() or ip.isPrivate() or
        isDocumentationIp(ip);
}

/// IANA special-purpose documentation space: RFC 5737's TEST-NET-1
/// (`192.0.2.0/24`), TEST-NET-2 (`198.51.100.0/24`), TEST-NET-3
/// (`203.0.113.0/24`) and RFC 3849's `2001:db8::/32`. Not routable on the
/// public internet, so a `related` href naming one is never a real registry —
/// but on a lab network where TEST-NET is routed internally, following it is
/// the same internal-connect this guard exists to refuse. Kept byte-for-byte
/// in step with `whois.isDocumentationIp`; `netaddr` deliberately does not
/// carry this predicate (it is threat model, not addressing — audit
/// `netaddr` F3 scoped the fix to the two consumers, not to `netaddr`).
fn isDocumentationIp(ip: netaddr.Ip) bool {
    return switch (ip.unmap()) {
        .v4 => |q| (q[0] == 192 and q[1] == 0 and q[2] == 2) or
            (q[0] == 198 and q[1] == 51 and q[2] == 100) or
            (q[0] == 203 and q[1] == 0 and q[2] == 113),
        .v6 => |o| o[0] == 0x20 and o[1] == 0x01 and o[2] == 0x0d and o[3] == 0xb8,
    };
}

// ── default fetcher over our http client ────────────────────────────────────
// Convenience only — nothing in the logic or tests needs it, and no test
// below ever touches the network.

/// `Fetcher` implementation over `http.Client` (GET + RDAP Accept header;
/// the http client follows HTTP redirects itself, RFC 7480 §5.2).
pub const HttpFetcher = struct {
    client: *http.Client,
    /// Applied to every redirect `Location` before it is dialed. Keep it the
    /// same as the `Client`'s: this fetcher is where the destinations that
    /// `Client` never sees are chosen.
    destinations: DestinationPolicy = .{},
    /// How many `Location` hops to follow. `http.Client` would follow up to
    /// ten of them **itself**, accepting an absolute cross-origin `Location`
    /// verbatim — so the module's destination check applied to the address it
    /// asked for and never to the one it reached, and any server able to send
    /// one response could bounce the client anywhere. Following them here is
    /// what puts each hop through `checkDestination`.
    max_redirects: u8 = 5,

    pub fn fetcher(f: *HttpFetcher) Fetcher {
        return .{ .ctx = f, .fetchFn = fetchFn };
    }

    fn fetchFn(ctx: *anyopaque, url: []const u8, body_buf: []u8) FetchError!Fetcher.Result {
        const f: *HttpFetcher = @ptrCast(@alignCast(ctx));
        var url_buf: [max_url_len]u8 = undefined;
        var current = url;
        var hops: u8 = 0;
        while (true) {
            var res = f.client.request(.get, current, .{
                .headers = &.{accept_header},
                .follow_redirects = false,
            }) catch |err| return mapFetchError(err);
            if (!isRedirectStatus(res.status)) return readBody(&res, body_buf);
            const location = res.header("location") orelse return readBody(&res, body_buf);
            if (hops >= f.max_redirects) {
                res.deinit();
                return error.FetchFailed;
            }
            const base = http.Url.parse(current) catch {
                res.deinit();
                return error.FetchFailed;
            };
            // Resolve into a buffer that is NOT the response's, then drop the
            // response: `location` points into `res`.
            var next_buf: [max_url_len]u8 = undefined;
            const resolved = http.resolveLocation(base, location, &next_buf) catch {
                res.deinit();
                return error.FetchFailed;
            };
            const len = resolved.len;
            @memcpy(url_buf[0..len], resolved);
            res.deinit();
            const next = url_buf[0..len];
            checkDestination(next, f.destinations) catch return error.FetchFailed;
            current = next;
            hops += 1;
        }
    }

    fn isRedirectStatus(status: u16) bool {
        return switch (status) {
            301, 302, 303, 307, 308 => true,
            else => false,
        };
    }

    fn readBody(res: *http.Client.Response, body_buf: []u8) FetchError!Fetcher.Result {
        defer res.deinit();

        const n = res.reader().readSliceShort(body_buf) catch |err| switch (err) {
            error.ReadFailed => return mapFetchError(res.readFailure()),
        };
        if (n == body_buf.len) {
            // Buffer exactly full — distinguish "fit exactly" from "more coming".
            var extra: [1]u8 = undefined;
            const m = res.reader().readSliceShort(&extra) catch |err| switch (err) {
                error.ReadFailed => return mapFetchError(res.readFailure()),
            };
            if (m != 0) return error.ResponseTooLarge;
        }
        return .{ .status = res.status, .body_len = n };
    }
};

/// Widen an `http.Client.Error` to `FetchError`, the one place this module
/// touches the network. `error.Canceled` is the only variant worth telling
/// apart from a plain transport failure — everything else already collapsed
/// into `FetchFailed` before cancelation recovery existed, and stays that
/// way. Covers both `client.request()` itself (the connect/send phase,
/// which `http.Client.Error` already carries `Canceled` for) and
/// `Response.readFailure()` (the blocked-body-read phase, recovered from the
/// concrete reader's out-of-band `err` field — see CONVENTIONS.md §2).
fn mapFetchError(err: http.Client.Error) FetchError {
    return switch (err) {
        error.Canceled => error.Canceled,
        else => error.FetchFailed,
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test "buildPath KATs (RFC 9082 §3.1): all query types + percent-encoding" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "domain/example.com",
        try buildPath(&buf, .domain, "example.com"),
    );
    // The CIDR '/' must be percent-encoded inside the path segment.
    try testing.expectEqualStrings(
        "ip/192.0.2.0%2F24",
        try buildPath(&buf, .ip, "192.0.2.0/24"),
    );
    try testing.expectEqualStrings(
        "autnum/65536",
        try buildPath(&buf, .autnum, "65536"),
    );
    // IPv6: ':' is a legal pchar and stays literal.
    try testing.expectEqualStrings(
        "ip/2001:db8::1",
        try buildPath(&buf, .ip, "2001:db8::1"),
    );
    try testing.expectEqualStrings(
        "nameserver/ns1.example.com",
        try buildPath(&buf, .nameserver, "ns1.example.com"),
    );
    // Reserved characters in entity handles are escaped (uppercase hex).
    try testing.expectEqualStrings(
        "entity/ABC%20123%2FX",
        try buildPath(&buf, .entity, "ABC 123/X"),
    );

    try testing.expectError(error.EmptyQuery, buildPath(&buf, .domain, ""));
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.PathTooLong, buildPath(&tiny, .domain, "example.com"));
}

test "Accept header carries the RDAP media type (RFC 7480 §4.2)" {
    try testing.expectEqualStrings("application/rdap+json", media_type);
    try testing.expectEqualStrings("Accept", accept_header.name);
    try testing.expectEqualStrings(media_type, accept_header.value);
}

test "buildUrl joins base with and without trailing slash" {
    var buf: [256]u8 = undefined;
    try testing.expectEqualStrings(
        "https://rdap.example/domain/example.com",
        try buildUrl(&buf, "https://rdap.example/", .domain, "example.com"),
    );
    try testing.expectEqualStrings(
        "https://rdap.verisign.com/com/v1/domain/example.com",
        try buildUrl(&buf, "https://rdap.verisign.com/com/v1", .domain, "example.com"),
    );
    try testing.expectEqualStrings(
        "https://rdap.arin.net/registry/ip/192.0.2.0%2F24",
        try buildUrl(&buf, "https://rdap.arin.net/registry/", .ip, "192.0.2.0/24"),
    );
    try testing.expectError(error.BadBase, buildUrl(&buf, "", .domain, "x"));
    try testing.expectError(error.EmptyQuery, buildUrl(&buf, "https://r.example/", .domain, ""));
    var tiny: [16]u8 = undefined;
    try testing.expectError(
        error.UrlTooLong,
        buildUrl(&tiny, "https://rdap.example/", .domain, "example.com"),
    );
}

// Canned domain response modeled on the RFC 9083 §5.3 example (abridged).
const domain_json =
    \\{
    \\  "rdapConformance": ["rdap_level_0"],
    \\  "objectClassName": "domain",
    \\  "handle": "2336799_DOMAIN_COM-VRSN",
    \\  "ldhName": "example.com",
    \\  "unicodeName": "example.com",
    \\  "status": ["active", "client transfer prohibited"],
    \\  "events": [
    \\    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
    \\    {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
    \\    {"eventAction": "last changed", "eventDate": "2025-08-14T07:01:44Z",
    \\     "eventActor": "joe"}
    \\  ],
    \\  "entities": [
    \\    {
    \\      "objectClassName": "entity",
    \\      "handle": "376",
    \\      "roles": ["registrar"],
    \\      "vcardArray": ["vcard", [
    \\        ["version", {}, "text", "4.0"],
    \\        ["fn", {}, "text", "Example Registrar Inc."],
    \\        ["org", {}, "text", "Example Registrar"],
    \\        ["email", {}, "text", "registrar@example.net"]
    \\      ]]
    \\    }
    \\  ],
    \\  "nameservers": [
    \\    {"objectClassName": "nameserver", "ldhName": "a.iana-servers.net"},
    \\    {"objectClassName": "nameserver", "ldhName": "b.iana-servers.net"}
    \\  ],
    \\  "links": [
    \\    {"rel": "self", "type": "application/rdap+json",
    \\     "href": "https://rdap.verisign.com/com/v1/domain/example.com"},
    \\    {"rel": "related", "type": "application/rdap+json",
    \\     "href": "https://rdap.markmonitor.com/rdap/domain/example.com"}
    \\  ],
    \\  "notices": [
    \\    {"title": "Terms of Use", "description": ["Service subject to Terms of Use."]}
    \\  ],
    \\  "remarks": [
    \\    {"title": "data policy", "description": ["some data withheld"]}
    \\  ],
    \\  "port43": "whois.example.net",
    \\  "secureDNS": {"delegationSigned": true}
    \\}
;

test "parse: domain response KAT (RFC 9083 §5.3 shape)" {
    var parsed = try parseResponse(testing.allocator, domain_json);
    defer parsed.deinit();
    const o = &parsed.document.object;

    try testing.expectEqual(ObjectClass.domain, o.object_class);
    try testing.expectEqualStrings("domain", o.object_class_name);
    try testing.expectEqualStrings("2336799_DOMAIN_COM-VRSN", o.handle.?);
    try testing.expectEqualStrings("example.com", o.ldh_name.?);
    try testing.expectEqualStrings("example.com", o.unicode_name.?);

    try testing.expectEqual(@as(usize, 2), o.status.len);
    try testing.expectEqualStrings("active", o.status[0]);
    try testing.expectEqualStrings("client transfer prohibited", o.status[1]);

    try testing.expectEqual(@as(usize, 3), o.events.len);
    try testing.expectEqualStrings("1995-08-14T04:00:00Z", o.eventDate("registration").?);
    try testing.expectEqualStrings("2026-08-13T04:00:00Z", o.eventDate("expiration").?);
    try testing.expectEqualStrings("2025-08-14T07:01:44Z", o.eventDate("Last Changed").?);
    try testing.expectEqualStrings("joe", o.events[2].actor.?);
    try testing.expect(o.eventDate("transfer") == null);

    const registrar = o.entityWithRole("registrar").?;
    try testing.expectEqualStrings("376", registrar.handle.?);
    try testing.expectEqualStrings("Example Registrar Inc.", registrar.full_name.?);
    try testing.expectEqualStrings("Example Registrar", registrar.org.?);
    try testing.expectEqualStrings("registrar@example.net", registrar.email.?);
    try testing.expect(o.entityWithRole("registrant") == null);

    try testing.expectEqual(@as(usize, 2), o.nameservers.len);
    try testing.expectEqualStrings("a.iana-servers.net", o.nameservers[0].ldh_name.?);
    try testing.expectEqualStrings("b.iana-servers.net", o.nameservers[1].ldh_name.?);

    try testing.expectEqualStrings(
        "https://rdap.verisign.com/com/v1/domain/example.com",
        o.linkHref("self").?,
    );
    try testing.expectEqualStrings(
        "https://rdap.markmonitor.com/rdap/domain/example.com",
        o.linkHref("related").?,
    );
    try testing.expectEqualStrings("application/rdap+json", o.links[0].media_type.?);

    try testing.expectEqual(@as(usize, 1), o.notices.len);
    try testing.expectEqualStrings("Terms of Use", o.notices[0].title.?);
    try testing.expectEqualStrings("Service subject to Terms of Use.", o.notices[0].description[0]);
    try testing.expectEqual(@as(usize, 1), o.remarks.len);
    try testing.expectEqualStrings("some data withheld", o.remarks[0].description[0]);
    try testing.expectEqualStrings("whois.example.net", o.port43.?);
}

test "parse: ip network response KAT (RFC 9083 §5.4 shape)" {
    const json =
        \\{
        \\  "objectClassName": "ip network",
        \\  "handle": "XXXX-RIR",
        \\  "startAddress": "192.0.2.0",
        \\  "endAddress": "192.0.2.255",
        \\  "ipVersion": "v4",
        \\  "name": "NET-RTR-1",
        \\  "type": "DIRECT ALLOCATION",
        \\  "country": "AU",
        \\  "status": ["active"]
        \\}
    ;
    var parsed = try parseResponse(testing.allocator, json);
    defer parsed.deinit();
    const o = &parsed.document.object;
    try testing.expectEqual(ObjectClass.ip_network, o.object_class);
    try testing.expectEqualStrings("XXXX-RIR", o.handle.?);
    try testing.expectEqualStrings("192.0.2.0", o.start_address.?);
    try testing.expectEqualStrings("192.0.2.255", o.end_address.?);
    try testing.expectEqualStrings("v4", o.ip_version.?);
    try testing.expectEqualStrings("NET-RTR-1", o.name.?);
    try testing.expectEqualStrings("AU", o.country.?);
    // The parsed addresses are valid literals netaddr can consume.
    try testing.expect(netaddr.parseIp(o.start_address.?) != null);
}

test "parse: autnum response KAT (RFC 9083 §5.5 shape)" {
    const json =
        \\{
        \\  "objectClassName": "autnum",
        \\  "handle": "XXXX-RIR",
        \\  "startAutnum": 65536,
        \\  "endAutnum": 65541,
        \\  "name": "AS-RTR-1",
        \\  "status": ["active"]
        \\}
    ;
    var parsed = try parseResponse(testing.allocator, json);
    defer parsed.deinit();
    const o = &parsed.document.object;
    try testing.expectEqual(ObjectClass.autnum, o.object_class);
    try testing.expectEqual(@as(?i64, 65536), o.start_autnum);
    try testing.expectEqual(@as(?i64, 65541), o.end_autnum);
    try testing.expectEqualStrings("AS-RTR-1", o.name.?);
}

test "parse: RDAP error object → typed error document (RFC 7480 §5.3)" {
    const json =
        \\{
        \\  "errorCode": 418,
        \\  "title": "Your Beverage Choice is Not Available",
        \\  "description": ["I know coffee", "Try a different beverage"]
        \\}
    ;
    var parsed = try parseResponse(testing.allocator, json);
    defer parsed.deinit();
    const e = &parsed.document.rdap_error;
    try testing.expectEqual(@as(i64, 418), e.error_code);
    try testing.expectEqualStrings("Your Beverage Choice is Not Available", e.title.?);
    try testing.expectEqual(@as(usize, 2), e.description.len);
    try testing.expectEqualStrings("Try a different beverage", e.description[1]);
}

test "parse: jCard structured value (org as array of components) uses first text" {
    const json =
        \\{
        \\  "objectClassName": "domain",
        \\  "handle": "STRUCT-1",
        \\  "entities": [
        \\    {
        \\      "objectClassName": "entity",
        \\      "handle": "E-1",
        \\      "roles": ["registrant"],
        \\      "vcardArray": ["vcard", [
        \\        ["org", {}, "text", ["", "Example Registrar", "Suite 100"]]
        \\      ]]
        \\    }
        \\  ]
        \\}
    ;
    var parsed = try parseResponse(testing.allocator, json);
    defer parsed.deinit();
    const o = &parsed.document.object;
    try testing.expectEqualStrings("Example Registrar", o.entities[0].org.?);
}

test "parse: sparse response (objectClassName + handle only)" {
    var parsed = try parseResponse(testing.allocator,
        \\{"objectClassName": "entity", "handle": "SPARSE-1"}
    );
    defer parsed.deinit();
    const o = &parsed.document.object;
    try testing.expectEqual(ObjectClass.entity, o.object_class);
    try testing.expectEqualStrings("SPARSE-1", o.handle.?);
    try testing.expect(o.ldh_name == null);
    try testing.expectEqual(@as(usize, 0), o.status.len);
    try testing.expectEqual(@as(usize, 0), o.events.len);
    try testing.expect(o.eventDate("registration") == null);
    try testing.expect(o.entityWithRole("registrar") == null);
    try testing.expect(o.linkHref("self") == null);
}

test "parse: malformed/truncated JSON → clean error, wrong top level rejected" {
    try testing.expectError(error.InvalidJson, parseResponse(testing.allocator, ""));
    try testing.expectError(error.InvalidJson, parseResponse(testing.allocator, "{\"a\": "));
    try testing.expectError(error.InvalidJson, parseResponse(testing.allocator, "\x00\xff junk"));
    try testing.expectError(
        error.InvalidJson,
        parseResponse(testing.allocator, domain_json[0 .. domain_json.len / 2]),
    );
    try testing.expectError(error.InvalidRdap, parseResponse(testing.allocator, "[1,2,3]"));
    try testing.expectError(error.InvalidRdap, parseResponse(testing.allocator, "\"just text\""));
    try testing.expectError(error.InvalidRdap, parseResponse(testing.allocator, "42"));
}

test "parse: wrong-typed members degrade to defaults (never panic)" {
    const json =
        \\{
        \\  "objectClassName": "domain",
        \\  "ldhName": 7,
        \\  "status": 42,
        \\  "events": "nope",
        \\  "rdapConformance": "nope",
        \\  "publicIds": "nope",
        \\  "redacted": [{"name": "not-an-object"}, "junk", {"prePath": 5}],
        \\  "entities": [7, {
        \\    "roles": {"a": 1}, "vcardArray": ["vcard", "oops"],
        \\    "entities": "not-an-array", "links": "nope", "publicIds": "nope"
        \\  }],
        \\  "nameservers": [null, {"objectClassName": "nameserver", "ipAddresses": "oops"}],
        \\  "links": [{"rel": "self"}, "junk"],
        \\  "notices": [{"description": "not-an-array"}],
        \\  "startAutnum": "12x",
        \\  "port43": true
        \\}
    ;
    var parsed = try parseResponse(testing.allocator, json);
    defer parsed.deinit();
    const o = &parsed.document.object;
    try testing.expectEqual(ObjectClass.domain, o.object_class);
    try testing.expect(o.ldh_name == null);
    try testing.expectEqual(@as(usize, 0), o.status.len);
    try testing.expectEqual(@as(usize, 0), o.events.len);
    try testing.expectEqual(@as(usize, 0), o.rdap_conformance.len);
    try testing.expectEqual(@as(usize, 0), o.public_ids.len);
    // A non-object entry and a wrong-typed "name" are dropped; an object
    // with an unusable "name" (wrong type on both type/description) still
    // survives as a redacted entry with name == null.
    try testing.expectEqual(@as(usize, 2), o.redacted.len);
    try testing.expect(o.redacted[0].name == null);
    try testing.expect(o.redacted[1].pre_path == null); // prePath: 5 is not a string
    try testing.expectEqual(@as(usize, 1), o.entities.len); // the object survives
    try testing.expectEqual(@as(usize, 0), o.entities[0].roles.len);
    try testing.expect(o.entities[0].email == null);
    try testing.expectEqual(@as(usize, 0), o.entities[0].entities.len); // "not-an-array" → empty, not a panic
    try testing.expectEqual(@as(usize, 0), o.entities[0].links.len);
    try testing.expectEqual(@as(usize, 0), o.entities[0].public_ids.len);
    try testing.expectEqual(@as(usize, 1), o.nameservers.len); // null entry dropped, object entry survives
    try testing.expectEqual(@as(usize, 0), o.nameservers[0].ipv4_addresses.len); // "ipAddresses": "oops" → empty
    try testing.expectEqual(@as(usize, 0), o.nameservers[0].ipv6_addresses.len);
    try testing.expectEqual(@as(usize, 0), o.links.len); // no href → dropped
    try testing.expectEqual(@as(usize, 1), o.notices.len);
    try testing.expectEqual(@as(usize, 0), o.notices[0].description.len);
    try testing.expect(o.start_autnum == null);
    try testing.expect(o.port43 == null);
}

test "parse: nested entities (RFC 9083 §5.1 registrar → abuse contact)" {
    const json =
        \\{
        \\  "objectClassName": "domain",
        \\  "entities": [
        \\    {
        \\      "objectClassName": "entity",
        \\      "handle": "REGISTRAR-1",
        \\      "roles": ["registrar"],
        \\      "links": [
        \\        {"rel": "self", "href": "https://rdap.example/entity/REGISTRAR-1"}
        \\      ],
        \\      "entities": [
        \\        {
        \\          "objectClassName": "entity",
        \\          "roles": ["abuse"],
        \\          "vcardArray": ["vcard", [
        \\            ["email", {}, "text", "abuse@registrar.example"]
        \\          ]]
        \\        },
        \\        {
        \\          "objectClassName": "entity",
        \\          "roles": ["technical"]
        \\        }
        \\      ]
        \\    }
        \\  ]
        \\}
    ;
    var parsed = try parseResponse(testing.allocator, json);
    defer parsed.deinit();
    const o = &parsed.document.object;

    const registrar = o.entityWithRole("registrar").?;
    try testing.expectEqual(@as(usize, 1), registrar.links.len);
    try testing.expectEqualStrings(
        "https://rdap.example/entity/REGISTRAR-1",
        registrar.links[0].href,
    );
    try testing.expectEqual(@as(usize, 2), registrar.entities.len);
    const abuse = registrar.entityWithRole("abuse").?;
    try testing.expectEqualStrings("abuse@registrar.example", abuse.email.?);
    try testing.expectEqual(@as(usize, 0), abuse.entities.len);
    try testing.expect(registrar.entityWithRole("technical") != null);
    try testing.expect(registrar.entityWithRole("billing") == null);
    // Object.entityWithRole only searches the top level — it does not reach
    // through nested entities on its own; chaining is the caller's job.
    try testing.expect(o.entityWithRole("abuse") == null);
}

test "parse: entities nested past max_entity_depth are dropped, not an error (tolerant policy)" {
    // hop-h entities are wrapped one level deeper than hop-(h-1); a sentinel
    // "BOTTOM" object several hops past max_entity_depth checks that the
    // parser simply stops descending there rather than rejecting the whole
    // response (this module's tolerant-parsing policy — see the module doc
    // comment).
    const levels = max_entity_depth + 3;
    var buf: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try w.writeAll("{\"objectClassName\":\"domain\",\"entities\":[");
    for (0..levels) |i| {
        try w.print("{{\"objectClassName\":\"entity\",\"handle\":\"L{d}\",\"entities\":[", .{i});
    }
    try w.writeAll("{\"objectClassName\":\"entity\",\"handle\":\"BOTTOM\"}");
    for (0..levels) |_| try w.writeAll("]}");
    try w.writeAll("]}");

    var parsed = try parseResponse(testing.allocator, w.buffered());
    defer parsed.deinit();
    const o = &parsed.document.object;

    var cur: *const Entity = &o.entities[0];
    try testing.expectEqualStrings("L0", cur.handle.?);
    var hops: usize = 0;
    while (cur.entities.len > 0) {
        cur = &cur.entities[0];
        hops += 1;
    }
    try testing.expectEqual(@as(usize, max_entity_depth), hops);
    var name_buf: [8]u8 = undefined;
    const expected = try std.fmt.bufPrint(&name_buf, "L{d}", .{max_entity_depth});
    try testing.expectEqualStrings(expected, cur.handle.?);
}

test "parse: rdapConformance[] (RFC 9083 §4.1), publicIds[] (§4.8), redacted[] (RFC 9537)" {
    const json =
        \\{
        \\  "rdapConformance": ["rdap_level_0", "redacted"],
        \\  "objectClassName": "domain",
        \\  "publicIds": [{"type": "Some Registry ID", "identifier": "XYZ-1"}],
        \\  "redacted": [
        \\    {
        \\      "name": {"type": "Registrant Name"},
        \\      "prePath": "$.entities[?(@.roles[0]=='registrant')]",
        \\      "method": "removal"
        \\    },
        \\    {
        \\      "name": {"description": "custom label"},
        \\      "postPath": "$.foo",
        \\      "pathLang": "jsonpath",
        \\      "method": "emptyValue"
        \\    }
        \\  ]
        \\}
    ;
    var parsed = try parseResponse(testing.allocator, json);
    defer parsed.deinit();
    const o = &parsed.document.object;

    try testing.expectEqual(@as(usize, 2), o.rdap_conformance.len);
    try testing.expectEqualStrings("redacted", o.rdap_conformance[1]);

    try testing.expectEqual(@as(usize, 1), o.public_ids.len);
    try testing.expectEqualStrings("Some Registry ID", o.public_ids[0].id_type);
    try testing.expectEqualStrings("XYZ-1", o.public_ids[0].identifier);

    try testing.expectEqual(@as(usize, 2), o.redacted.len);
    try testing.expectEqualStrings("Registrant Name", o.redacted[0].name.?);
    try testing.expectEqualStrings("removal", o.redacted[0].method.?);
    // "name.description" is the fallback when "name.type" is absent.
    try testing.expectEqualStrings("custom label", o.redacted[1].name.?);
    try testing.expectEqualStrings("$.foo", o.redacted[1].post_path.?);
    try testing.expectEqualStrings("emptyValue", o.redacted[1].method.?);
}

test "parse: nameserver ipAddresses.v4/v6 (RFC 9083 §5.2 glue addresses)" {
    const json =
        \\{
        \\  "objectClassName": "domain",
        \\  "nameservers": [
        \\    {
        \\      "objectClassName": "nameserver",
        \\      "ldhName": "ns1.example.com",
        \\      "ipAddresses": {"v4": ["192.0.2.1"], "v6": ["2001:db8::1", "2001:db8::2"]}
        \\    },
        \\    {"objectClassName": "nameserver", "ldhName": "ns2.example.com"}
        \\  ]
        \\}
    ;
    var parsed = try parseResponse(testing.allocator, json);
    defer parsed.deinit();
    const o = &parsed.document.object;

    try testing.expectEqual(@as(usize, 1), o.nameservers[0].ipv4_addresses.len);
    try testing.expectEqualStrings("192.0.2.1", o.nameservers[0].ipv4_addresses[0]);
    try testing.expectEqual(@as(usize, 2), o.nameservers[0].ipv6_addresses.len);
    try testing.expectEqualStrings("2001:db8::2", o.nameservers[0].ipv6_addresses[1]);
    try testing.expectEqual(@as(usize, 0), o.nameservers[1].ipv4_addresses.len);
    try testing.expectEqual(@as(usize, 0), o.nameservers[1].ipv6_addresses.len);
}

test "bootstrap: DNS registry KAT (RFC 9224 shape)" {
    const json =
        \\{
        \\  "version": "1.0",
        \\  "publication": "2026-07-01T00:00:00Z",
        \\  "description": "RDAP bootstrap file for Domain Name System registrations",
        \\  "services": [
        \\    [["net", "com"], ["https://rdap.verisign.com/com/v1/"]],
        \\    [["cz"], ["https://rdap.nic.cz/"]],
        \\    [["org"], ["https://rdap.org.example/", "http://rdap.org.example/"]]
        \\  ]
        \\}
    ;
    var b = try parseBootstrap(testing.allocator, json);
    defer b.deinit();
    try testing.expectEqual(@as(usize, 3), b.services.len);

    // Domain resolution: label-suffix TLD match, case-insensitive.
    try testing.expectEqualStrings(
        "https://rdap.verisign.com/com/v1/",
        b.lookupDomain("example.com").?[0],
    );
    try testing.expectEqualStrings("https://rdap.nic.cz/", b.lookupDomain("EXAMPLE.CZ").?[0]);
    try testing.expectEqualStrings("https://rdap.nic.cz/", b.lookupDomain("a.b.example.cz.").?[0]);
    try testing.expectEqual(@as(usize, 2), b.lookupDomain("example.org").?.len);
    try testing.expect(b.lookupDomain("example.test") == null); // unknown TLD
    try testing.expect(b.lookupDomain("com.invalid") == null); // TLD is a suffix, not a label
    try testing.expect(b.lookupDomain("") == null);

    // The exact-key primitive.
    try testing.expectEqualStrings(
        "https://rdap.verisign.com/com/v1/",
        bootstrapLookup(&b, "net").?[0],
    );
    try testing.expectEqualStrings("https://rdap.nic.cz/", bootstrapLookup(&b, "CZ").?[0]);
    try testing.expect(bootstrapLookup(&b, "example.com") == null);
}

test "bootstrap: IPv4/IPv6 longest-prefix match" {
    const json =
        \\{
        \\  "version": "1.0",
        \\  "services": [
        \\    [["192.0.0.0/8"], ["https://rdap.coarse.example/"]],
        \\    [["192.0.2.0/24"], ["https://rdap.fine.example/"]],
        \\    [["2001:4200::/23"], ["https://rdap.afrinic.example/"]],
        \\    [["2c00::/12"], ["https://rdap.other6.example/"]]
        \\  ]
        \\}
    ;
    var b = try parseBootstrap(testing.allocator, json);
    defer b.deinit();

    // Longest prefix wins over the /8.
    try testing.expectEqualStrings("https://rdap.fine.example/", b.lookupIp("192.0.2.7").?[0]);
    try testing.expectEqualStrings("https://rdap.coarse.example/", b.lookupIp("192.1.1.1").?[0]);
    // CIDR query form matches by its network address.
    try testing.expectEqualStrings("https://rdap.fine.example/", b.lookupIp("192.0.2.0/24").?[0]);
    // IPv6, non-byte-aligned /23.
    try testing.expectEqualStrings(
        "https://rdap.afrinic.example/",
        b.lookupIp("2001:4300::1").?[0],
    );
    try testing.expect(b.lookupIp("2001:4400::1") == null); // outside the /23
    try testing.expectEqualStrings("https://rdap.other6.example/", b.lookupIp("2c0f:f00::1").?[0]);
    try testing.expect(b.lookupIp("10.0.0.1") == null);
    try testing.expect(b.lookupIp("not an ip") == null);
}

test "bootstrap: ASN ranges" {
    const json =
        \\{
        \\  "version": "1.0",
        \\  "services": [
        \\    [["64496-64511", "65536-65551"], ["https://rdap.a.example/"]],
        \\    [["65552"], ["https://rdap.b.example/"]]
        \\  ]
        \\}
    ;
    var b = try parseBootstrap(testing.allocator, json);
    defer b.deinit();
    try testing.expectEqualStrings("https://rdap.a.example/", b.lookupAsn(64496).?[0]);
    try testing.expectEqualStrings("https://rdap.a.example/", b.lookupAsn(65540).?[0]);
    try testing.expectEqualStrings("https://rdap.a.example/", b.lookupAsn(65551).?[0]);
    try testing.expectEqualStrings("https://rdap.b.example/", b.lookupAsn(65552).?[0]);
    try testing.expect(b.lookupAsn(65535) == null);
    try testing.expect(b.lookupAsn(1) == null);
}

test "bootstrap: malformed input rejected, odd entries tolerated" {
    try testing.expectError(error.InvalidJson, parseBootstrap(testing.allocator, "{"));
    try testing.expectError(error.InvalidRdap, parseBootstrap(testing.allocator, "[]"));
    try testing.expectError(
        error.InvalidRdap,
        parseBootstrap(testing.allocator, "{\"version\": \"1.0\"}"),
    );

    // Non-array entries, short entries and the 3-element object-tag form
    // (contact prepended, RFC 8521) are all handled.
    const json =
        \\{
        \\  "services": [
        \\    "junk",
        \\    [["only-keys"]],
        \\    [["contact@example.com"], ["YYYY"], ["https://example.com/rdap/"]],
        \\    [["ok"], ["https://rdap.ok.example/"]]
        \\  ]
        \\}
    ;
    var b = try parseBootstrap(testing.allocator, json);
    defer b.deinit();
    try testing.expectEqual(@as(usize, 2), b.services.len);
    try testing.expectEqualStrings("https://example.com/rdap/", b.lookup("YYYY").?[0]);
    try testing.expectEqualStrings("https://rdap.ok.example/", b.lookup("ok").?[0]);
}

// Scripted fetcher: canned url→(status, body) map plus a call log, so every
// client test runs offline.
const StubFetcher = struct {
    entries: []const Entry,
    urls: [4][max_url_len]u8 = undefined,
    url_lens: [4]usize = @splat(0),
    call_count: usize = 0,

    const Entry = struct { url: []const u8, status: u16 = 200, body: []const u8 };

    fn calledUrl(s: *const StubFetcher, i: usize) []const u8 {
        return s.urls[i][0..s.url_lens[i]];
    }

    fn fetcher(s: *StubFetcher) Fetcher {
        return .{ .ctx = s, .fetchFn = fetchFn };
    }

    fn fetchFn(ctx: *anyopaque, url: []const u8, body_buf: []u8) FetchError!Fetcher.Result {
        const s: *StubFetcher = @ptrCast(@alignCast(ctx));
        if (s.call_count < s.urls.len and url.len <= max_url_len) {
            @memcpy(s.urls[s.call_count][0..url.len], url);
            s.url_lens[s.call_count] = url.len;
            s.call_count += 1;
        }
        for (s.entries) |e| {
            if (!std.mem.eql(u8, e.url, url)) continue;
            if (e.body.len > body_buf.len) return error.ResponseTooLarge;
            @memcpy(body_buf[0..e.body.len], e.body);
            return .{ .status = e.status, .body_len = e.body.len };
        }
        return error.FetchFailed;
    }
};

test "client: end-to-end domain query via canned fetch" {
    var stub: StubFetcher = .{ .entries = &.{
        .{
            .url = "https://rdap.verisign.com/com/v1/domain/example.com",
            .body = domain_json,
        },
    } };
    var client: Client = .{ .fetcher = stub.fetcher(), .gpa = testing.allocator };
    var buf: [8192]u8 = undefined;

    var parsed = try client.query(
        "https://rdap.verisign.com/com/v1",
        .domain,
        "example.com",
        .{},
        &buf,
        null,
    );
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), stub.call_count);
    try testing.expectEqualStrings(
        "https://rdap.verisign.com/com/v1/domain/example.com",
        stub.calledUrl(0),
    );
    const o = &parsed.document.object;
    try testing.expectEqualStrings("example.com", o.ldh_name.?);
    try testing.expectEqualStrings(
        "registrar@example.net",
        o.entityWithRole("registrar").?.email.?,
    );
}

test "client: 404 → NotFound; other failures typed or HttpStatus" {
    const err_body =
        \\{"errorCode": 400, "title": "Bad Request", "description": ["malformed query"]}
    ;
    var stub: StubFetcher = .{ .entries = &.{
        .{ .url = "https://r.example/domain/gone.example", .status = 404, .body = "" },
        .{ .url = "https://r.example/domain/bad.example", .status = 400, .body = err_body },
        .{ .url = "https://r.example/domain/broken.example", .status = 500, .body = "<html>oops" },
        .{ .url = "https://r.example/domain/weird.example", .status = 403, .body = "{}" },
        .{ .url = "https://r.example/domain/limited.example", .status = 429, .body = "{}" },
    } };
    var client: Client = .{ .fetcher = stub.fetcher(), .gpa = testing.allocator };
    var buf: [1024]u8 = undefined;

    try testing.expectError(
        error.NotFound,
        client.query("https://r.example", .domain, "gone.example", .{}, &buf, null),
    );

    // Failure status + RDAP error body → typed rdap_error document.
    var parsed = try client.query("https://r.example", .domain, "bad.example", .{}, &buf, null);
    defer parsed.deinit();
    try testing.expectEqual(@as(i64, 400), parsed.document.rdap_error.error_code);
    try testing.expectEqualStrings("Bad Request", parsed.document.rdap_error.title.?);

    // Failure status + unparseable body → HttpStatus, and status_out carries the
    // real HTTP status (500) — the signal a caller needs to tell a server error
    // from a rate limit, which the bare error variant cannot carry.
    var status: u16 = 0;
    try testing.expectError(
        error.HttpStatus,
        client.query("https://r.example", .domain, "broken.example", .{}, &buf, &status),
    );
    try testing.expectEqual(@as(u16, 500), status);

    // Failure status + JSON that is not an RDAP error → HttpStatus (no leak),
    // status_out still carries the real code (403, distinct from the 500 above).
    status = 0;
    try testing.expectError(
        error.HttpStatus,
        client.query("https://r.example", .domain, "weird.example", .{}, &buf, &status),
    );
    try testing.expectEqual(@as(u16, 403), status);

    // The motivating case: 429 (rate limit) is distinguishable from 500
    // (server error) purely from status_out — this is the signal a caller
    // needs to implement backoff, which this module otherwise has no
    // client-side rate limiting of its own to provide.
    status = 0;
    try testing.expectError(
        error.HttpStatus,
        client.query("https://r.example", .domain, "limited.example", .{}, &buf, &status),
    );
    try testing.expectEqual(@as(u16, 429), status);

    // Unknown URL → transport failure.
    try testing.expectError(
        error.FetchFailed,
        client.query("https://other.example", .domain, "x.example", .{}, &buf, null),
    );
}

test "client: follows one related link (registry → registrar)" {
    const registrar_json =
        \\{
        \\  "objectClassName": "domain",
        \\  "handle": "REGR-1",
        \\  "ldhName": "example.com",
        \\  "status": ["client transfer prohibited"]
        \\}
    ;
    var stub: StubFetcher = .{ .entries = &.{
        .{ .url = "https://rdap.verisign.com/com/v1/domain/example.com", .body = domain_json },
        .{ .url = "https://rdap.markmonitor.com/rdap/domain/example.com", .body = registrar_json },
    } };
    var client: Client = .{ .fetcher = stub.fetcher(), .gpa = testing.allocator };
    var buf: [8192]u8 = undefined;

    var parsed = try client.query(
        "https://rdap.verisign.com/com/v1",
        .domain,
        "example.com",
        .{ .follow_related = true },
        &buf,
        null,
    );
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 2), stub.call_count);
    try testing.expectEqualStrings(
        "https://rdap.markmonitor.com/rdap/domain/example.com",
        stub.calledUrl(1),
    );
    try testing.expectEqualStrings("REGR-1", parsed.document.object.handle.?);
}

test "client: failed related hop falls back to the first document" {
    // The related URL answers with garbage — the follow-up parse fails and
    // the registry document must survive, even though the fetch overwrote
    // the shared body buffer (the model is arena-owned).
    var stub: StubFetcher = .{ .entries = &.{
        .{ .url = "https://rdap.verisign.com/com/v1/domain/example.com", .body = domain_json },
        .{ .url = "https://rdap.markmonitor.com/rdap/domain/example.com", .body = "{ truncated" },
    } };
    var client: Client = .{ .fetcher = stub.fetcher(), .gpa = testing.allocator };
    var buf: [8192]u8 = undefined;

    var parsed = try client.query(
        "https://rdap.verisign.com/com/v1",
        .domain,
        "example.com",
        .{ .follow_related = true },
        &buf,
        null,
    );
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 2), stub.call_count);
    const o = &parsed.document.object;
    try testing.expectEqualStrings("2336799_DOMAIN_COM-VRSN", o.handle.?);
    try testing.expectEqualStrings("1995-08-14T04:00:00Z", o.eventDate("registration").?);
}

test "isSpecialUseHost: classifies loopback/private/link-local/localhost, passes public" {
    try testing.expect(isSpecialUseHost("127.0.0.1"));
    try testing.expect(isSpecialUseHost("10.0.0.5"));
    try testing.expect(isSpecialUseHost("172.16.0.1"));
    try testing.expect(!isSpecialUseHost("172.32.0.1")); // just outside 172.16/12
    try testing.expect(isSpecialUseHost("192.168.1.1"));
    try testing.expect(isSpecialUseHost("169.254.169.254")); // cloud metadata
    try testing.expect(isSpecialUseHost("::1"));
    try testing.expect(isSpecialUseHost("fe80::1"));
    try testing.expect(isSpecialUseHost("224.0.0.1")); // IPv4 multicast
    try testing.expect(isSpecialUseHost("ff02::1")); // IPv6 multicast
    try testing.expect(isSpecialUseHost("fc00::1")); // IPv6 unique-local
    try testing.expect(isSpecialUseHost("localhost"));
    try testing.expect(!isSpecialUseHost("rdap.markmonitor.com"));
    // RFC 5737 / RFC 3849 documentation space — refused (audit `netaddr` F3).
    try testing.expect(isSpecialUseHost("192.0.2.1")); // TEST-NET-1
    try testing.expect(isSpecialUseHost("198.51.100.7")); // TEST-NET-2
    try testing.expect(isSpecialUseHost("203.0.113.9")); // TEST-NET-3
    try testing.expect(isSpecialUseHost("2001:db8::1")); // RFC 3849
    try testing.expect(isSpecialUseHost("::ffff:203.0.113.9")); // v4-mapped TEST-NET-3
    // …and not over-wide: the neighbouring prefixes stay public.
    try testing.expect(!isSpecialUseHost("192.0.3.1"));
    try testing.expect(!isSpecialUseHost("198.51.101.1"));
    try testing.expect(!isSpecialUseHost("203.0.114.1"));
    try testing.expect(!isSpecialUseHost("2001:db9::1"));
}

test "isSpecialUseHost: the ABSOLUTE spelling is the same name (re-audit F1)" {
    // `localhost.` is `localhost` to every resolver on earth — verified on
    // this host: `getent hosts localhost.` answers `::1`. The guard compared
    // the raw string and `netaddr.parseIp` rejected the dotted form, so this
    // returned false and the hop was dialed.
    for ([_][]const u8{
        "localhost.",       "LOCALHOST.",     "LocalHost.", "localhost..",
        "x.localhost.",     "a.b.localhost.", "127.0.0.1.", "10.0.0.1.",
        "169.254.169.254.", "0.0.0.0.",       ".",          "",
    }) |h| {
        if (!isSpecialUseHost(h)) {
            std.debug.print("host not classified special-use: '{s}'\n", .{h});
            return error.TestUnexpectedResult;
        }
    }
    // Unchanged: a public name is still not special-use, and a name that
    // merely CONTAINS one is not either.
    for ([_][]const u8{
        "rdap.verisign.com",        "rdap.verisign.com.",
        "localhost.evil.example",   "notlocalhost",
        "203.0.113.9.evil.example",
    }) |h| {
        if (isSpecialUseHost(h)) {
            std.debug.print("public host classified special-use: '{s}'\n", .{h});
            return error.TestUnexpectedResult;
        }
    }
}

test "checkDestination: the policy is scheme AND address, and both default to deny (re-audit F1/F3)" {
    const strict: DestinationPolicy = .{};
    // Plaintext is a downgrade whoever named it: this module's trust rests
    // entirely on TLS to the RDAP server.
    try testing.expectError(error.BlockedDestination, checkDestination("http://rdap.verisign.com/x", strict));
    try testing.expectError(error.BlockedDestination, checkDestination("https://localhost./x", strict));
    try testing.expectError(error.BlockedDestination, checkDestination("https://127.0.0.1./x", strict));
    try testing.expectError(error.BlockedDestination, checkDestination("https://169.254.169.254/x", strict));
    try testing.expectError(error.BadDestination, checkDestination("file:///etc/passwd", strict));
    try testing.expectError(error.BadDestination, checkDestination("ftp://rdap.example/x", strict));
    try checkDestination("https://rdap.verisign.com/com/v1/domain/example.com", strict);

    // A caller that really does point at a local server says so.
    const lax: DestinationPolicy = .{ .deny_special_use = false, .require_https = false };
    try checkDestination("http://127.0.0.1:8080/rdap/domain/x", lax);
    // ...and relaxing one term does not relax the other.
    try testing.expectError(error.BlockedDestination, checkDestination(
        "http://127.0.0.1:8080/x",
        .{ .deny_special_use = true, .require_https = false },
    ));
    try testing.expectError(error.BlockedDestination, checkDestination(
        "http://rdap.verisign.com/x",
        .{ .deny_special_use = false, .require_https = true },
    ));
}

test "client: a related link cannot walk the exchange off TLS (re-audit F3)" {
    // The 2026-07-19 audit's F1 named the scheme downgrade in the same
    // sentence as the address SSRF; the fix that closed it added the address
    // guard only, so this half stayed open and was recorded nowhere.
    const downgrade_json =
        \\{
        \\  "objectClassName": "domain",
        \\  "handle": "REGISTRY",
        \\  "links": [
        \\    {"rel": "related", "type": "application/rdap+json",
        \\     "href": "http://rdap.registrar.example/domain/example.com"}
        \\  ]
        \\}
    ;
    var stub: StubFetcher = .{
        .entries = &.{
            .{ .url = "https://rdap.verisign.com/com/v1/domain/example.com", .body = downgrade_json },
            // Reachable only if the downgrade is followed. It must not be.
            .{ .url = "http://rdap.registrar.example/domain/example.com", .body = domain_json },
        },
    };
    var client: Client = .{ .fetcher = stub.fetcher(), .gpa = testing.allocator };
    var buf: [8192]u8 = undefined;
    var parsed = try client.query(
        "https://rdap.verisign.com/com/v1",
        .domain,
        "example.com",
        .{ .follow_related = true },
        &buf,
        null,
    );
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 1), stub.call_count); // never dialed
    try testing.expectEqualStrings("REGISTRY", parsed.document.object.handle.?);
}

test "client: a related link at the ABSOLUTE loopback name is refused (re-audit F1)" {
    const dotted_json =
        \\{
        \\  "objectClassName": "domain",
        \\  "handle": "REGISTRY",
        \\  "links": [
        \\    {"rel": "related", "type": "application/rdap+json",
        \\     "href": "https://localhost.:6379/rdap/domain/example.com"}
        \\  ]
        \\}
    ;
    var stub: StubFetcher = .{
        .entries = &.{
            .{ .url = "https://rdap.verisign.com/com/v1/domain/example.com", .body = dotted_json },
            .{ .url = "https://localhost.:6379/rdap/domain/example.com", .body = domain_json },
        },
    };
    var client: Client = .{ .fetcher = stub.fetcher(), .gpa = testing.allocator };
    var buf: [8192]u8 = undefined;
    var parsed = try client.query(
        "https://rdap.verisign.com/com/v1",
        .domain,
        "example.com",
        .{ .follow_related = true },
        &buf,
        null,
    );
    defer parsed.deinit();
    try testing.expectEqual(@as(usize, 1), stub.call_count);
    try testing.expectEqualStrings("REGISTRY", parsed.document.object.handle.?);
}

test "client: the PRIMARY url is gated too — a bootstrap entry is untrusted input (re-audit F4)" {
    // `Bootstrap.lookupDomain` returns service URLs parsed out of a registry
    // file this module does not author, and `example/main.zig` feeds `urls[0]`
    // straight to `query`. That path had no destination check at all: a
    // bootstrap naming `http://169.254.169.254/` sent every query there.
    var stub: StubFetcher = .{ .entries = &.{
        .{ .url = "http://169.254.169.254/domain/example.com", .body = domain_json },
        .{ .url = "https://localhost./domain/example.com", .body = domain_json },
    } };
    var client: Client = .{ .fetcher = stub.fetcher(), .gpa = testing.allocator };
    var buf: [8192]u8 = undefined;
    try testing.expectError(error.BlockedDestination, client.query(
        "http://169.254.169.254",
        .domain,
        "example.com",
        .{},
        &buf,
        null,
    ));
    try testing.expectError(error.BlockedDestination, client.query(
        "https://localhost.",
        .domain,
        "example.com",
        .{},
        &buf,
        null,
    ));
    // Refused BEFORE the fetcher was touched, not after.
    try testing.expectEqual(@as(usize, 0), stub.call_count);
}

test "client: related link at a loopback host is refused, falls back to the first document" {
    const ssrf_related_json =
        \\{
        \\  "objectClassName": "domain",
        \\  "handle": "REG-1",
        \\  "links": [
        \\    {"rel": "related", "type": "application/rdap+json",
        \\     "href": "http://127.0.0.1:6379/rdap/domain/example.com"}
        \\  ]
        \\}
    ;
    var stub: StubFetcher = .{
        .entries = &.{
            .{ .url = "https://rdap.verisign.com/com/v1/domain/example.com", .body = ssrf_related_json },
            // If the guard failed, this would be reachable — it must never be dialed.
            .{ .url = "http://127.0.0.1:6379/rdap/domain/example.com", .body = domain_json },
        },
    };
    var client: Client = .{ .fetcher = stub.fetcher(), .gpa = testing.allocator };
    var buf: [8192]u8 = undefined;

    var parsed = try client.query(
        "https://rdap.verisign.com/com/v1",
        .domain,
        "example.com",
        .{ .follow_related = true },
        &buf,
        null,
    );
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), stub.call_count); // the loopback hop was never fetched
    try testing.expectEqualStrings("REG-1", parsed.document.object.handle.?);
}

test "client: related link at a private (RFC 1918) host is refused" {
    const ssrf_related_json =
        \\{
        \\  "objectClassName": "domain",
        \\  "handle": "REG-2",
        \\  "links": [
        \\    {"rel": "related", "type": "application/rdap+json",
        \\     "href": "https://10.0.0.5/internal/domain/example.com"}
        \\  ]
        \\}
    ;
    var stub: StubFetcher = .{ .entries = &.{
        .{ .url = "https://rdap.verisign.com/com/v1/domain/example.com", .body = ssrf_related_json },
        .{ .url = "https://10.0.0.5/internal/domain/example.com", .body = domain_json },
    } };
    var client: Client = .{ .fetcher = stub.fetcher(), .gpa = testing.allocator };
    var buf: [8192]u8 = undefined;

    var parsed = try client.query(
        "https://rdap.verisign.com/com/v1",
        .domain,
        "example.com",
        .{ .follow_related = true },
        &buf,
        null,
    );
    defer parsed.deinit();

    try testing.expectEqual(@as(usize, 1), stub.call_count);
    try testing.expectEqualStrings("REG-2", parsed.document.object.handle.?);
}

test "HttpFetcher compiles (never dialed in tests)" {
    // Reference the optional real fetcher so it is semantically checked
    // without any network activity.
    _ = HttpFetcher.fetchFn;
    _ = HttpFetcher.fetcher;
}

// ── tests (cancellation, loopback) ──────────────────────────────────────────
//
// `HttpFetcher.fetchFn` drives `res.reader()` directly rather than
// `readAllAlloc`, which is exactly the shape `http.Client.Response
// .readFailure()` (2c03d99) exists to unblock — `*std.Io.Reader`'s error set
// cannot carry `Canceled`, and `Conn` is private, so this module has no
// concrete reader of its own to consult. Proven here rather than assumed:
// the fake peer answers a `Content-Length: 5` head and sends none of the
// body, so the read is genuinely parked in the kernel when the test cancels
// it.

const FetchCancelPeer = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    stop: std.atomic.Value(u32) = .init(0),
    /// Set once `accept` returned; `release` only has to wake a peer before that.
    accepted: std.atomic.Value(u32) = .init(0),

    fn run(p: *FetchCancelPeer) void {
        const s = p.listener.accept(p.io) catch return;
        defer s.close(p.io);
        p.accepted.store(1, .release);
        if (p.stop.load(.acquire) != 0) return; // woken by `release`
        var wbuf: [256]u8 = undefined;
        var sw = s.writer(p.io, &wbuf);
        sw.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n") catch {};
        sw.interface.flush() catch {};
        while (p.stop.load(.acquire) == 0)
            p.io.sleep(.fromMilliseconds(5), .awake) catch return;
    }

    /// Wake the peer if it is still parked in `accept`. After a client that
    /// never connected nothing else would, and `join` would wait forever.
    /// Closing the listener does not wake it under `std.Io.Threaded`.
    fn release(p: *@This(), port: u16) void {
        p.stop.store(1, .release);
        if (p.accepted.load(.acquire) != 0) return;
        const addr = std.Io.net.IpAddress.parse("127.0.0.1", port) catch return;
        const s = addr.connect(p.io, .{ .mode = .stream }) catch return;
        s.close(p.io);
    }
};

/// A real `std.Io` whose only changed slot counts `netRead` entries. A cancel
/// test uses it to cancel once the client is INSIDE a given socket read, not
/// after a sleep. The peer writes its whole head in one flush, so on loopback
/// the head (or reply) is read #1 and the body read #2. With a sleep, a loaded
/// machine could cancel an earlier step, which passes by the wrong route. It
/// could also cancel before the connect: the peer then waits in `accept`
/// forever, and so does `join`. That is the http full-gate hang of
/// 2026-09-17, and the same shape as this module's peer.
const ReadCueIo = struct {
    vtable: std.Io.VTable,
    userdata: ?*anyopaque,

    var inner_vtable: *const std.Io.VTable = undefined;
    var reads: std.atomic.Value(u32) = .init(0);

    fn init(inner: std.Io) ReadCueIo {
        inner_vtable = inner.vtable;
        reads.store(0, .release);
        var vt = inner.vtable.*;
        vt.netRead = netRead;
        return .{ .vtable = vt, .userdata = inner.userdata };
    }

    fn io(self: *const ReadCueIo) std.Io {
        return .{ .userdata = self.userdata, .vtable = &self.vtable };
    }

    fn netRead(userdata: ?*anyopaque, src: std.Io.net.Socket.Handle, data: [][]u8) std.Io.net.Stream.Reader.Error!usize {
        _ = reads.fetchAdd(1, .monotonic);
        return inner_vtable.netRead(userdata, src, data);
    }

    /// Wait until the client has entered its `n`-th socket read. The deadline
    /// is a watchdog only: a client that never gets there is a red, not a hang
    /// (the gate's per-test limit is 3 minutes).
    fn awaitReads(real_io: std.Io, n: u32) bool {
        const start = std.Io.Clock.Timestamp.now(real_io, .awake);
        while (reads.load(.acquire) < n) {
            const waited = start.durationTo(std.Io.Clock.Timestamp.now(real_io, .awake)).raw.nanoseconds;
            if (waited > 60 * std.time.ns_per_s) return false;
            real_io.sleep(.fromMilliseconds(1), .awake) catch return reads.load(.acquire) >= n;
        }
        return true;
    }
};

fn fetchOnce(f: Fetcher, url: []const u8, body_buf: []u8) FetchError!Fetcher.Response {
    return f.fetch(url, body_buf);
}

test "HttpFetcher.fetchFn: a canceled body read surfaces error.Canceled, not error.FetchFailed" {
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var listener = addr.listen(io, .{}) catch |err| {
        std.debug.print("rdap fetch cancel test listen failed ({s}), skipping\n", .{@errorName(err)});
        return error.SkipZigTest;
    };
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();

    var peer: FetchCancelPeer = .{ .io = io, .listener = &listener };
    const peer_thread = try std.Thread.spawn(.{}, FetchCancelPeer.run, .{&peer});
    defer peer_thread.join();
    defer peer.release(port);

    var cue: ReadCueIo = .init(io);
    var http_client = http.Client.init(cue.io(), testing.allocator, .{ .pool = .{ .enabled = false } });
    defer http_client.deinit();
    var hf: HttpFetcher = .{ .client = &http_client };

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/", .{port});
    var body_buf: [256]u8 = undefined;

    var fut = try io.concurrent(fetchOnce, .{ hf.fetcher(), url, &body_buf });
    // Cancel once the client is inside read #2, the body read (`ReadCueIo`).
    const reached = ReadCueIo.awaitReads(io, 2);
    const result = fut.cancel(io);
    try testing.expect(reached);
    try testing.expectError(error.Canceled, result);
}

/// A listener that answers up to `max_serve` requests with the same canned
/// bytes, counting how many it actually served. Closing the listener from the
/// main thread is what releases it when it is parked in `accept`.
const CannedPeer = struct {
    io: std.Io,
    listener: *std.Io.net.Server,
    response: []const u8,
    hits: std.atomic.Value(u32) = .init(0),
    stop: std.atomic.Value(u32) = .init(0),

    fn run(p: *CannedPeer) void {
        while (true) {
            const s = p.listener.accept(p.io) catch return;
            defer s.close(p.io);
            // Closing the listener does NOT wake a peer parked in `accept`
            // under `std.Io.Threaded`, so the test wakes it with one throwaway
            // connection after setting this. (Learned the hard way: the first
            // shape of this test hung the whole suite.)
            if (p.stop.load(.acquire) != 0) return;
            _ = p.hits.fetchAdd(1, .monotonic);
            var rbuf: [1024]u8 = undefined;
            var sr = s.reader(p.io, &rbuf);
            _ = sr.interface.takeDelimiterExclusive('\n') catch {};
            var wbuf: [512]u8 = undefined;
            var sw = s.writer(p.io, &wbuf);
            sw.interface.writeAll(p.response) catch {};
            sw.interface.flush() catch {};
        }
    }
};

test "HttpFetcher: every redirect Location is gated, and the chain is bounded (re-audit F2)" {
    // `http.Client` follows up to ten `Location` hops ITSELF, accepting an
    // absolute cross-origin one verbatim — so this module's destination check
    // applied to the address it ASKED for and never to the one it REACHED.
    // Any server able to send one response could bounce the client anywhere,
    // which made the whole SSRF deny-list decorative. Following the hops here
    // is what puts each one through `checkDestination`.
    var threaded = std.Io.Threaded.init(testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const addr = try std.Io.net.IpAddress.parse("127.0.0.1", 0);
    var server = addr.listen(io, .{}) catch return error.SkipZigTest;
    var open = true;
    defer if (open) server.deinit(io);
    const port = server.socket.address.getPort();

    // The server points every request straight back at itself: a redirect
    // graph with no exit, which is exactly what a bound has to survive.
    var loc_buf: [160]u8 = undefined;
    const response = try std.fmt.bufPrint(
        &loc_buf,
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{d}/next\r\nContent-Length: 0\r\n\r\n",
        .{port},
    );
    var peer: CannedPeer = .{ .io = io, .listener = &server, .response = response };
    const pt = try std.Thread.spawn(.{}, CannedPeer.run, .{&peer});

    var http_client = http.Client.init(io, testing.allocator, .{ .pool = .{ .enabled = false } });
    defer http_client.deinit();

    var url_buf: [64]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/rdap/domain/x", .{port});
    var body_buf: [512]u8 = undefined;

    // (a) The policy a caller uses to reach a plaintext loopback server on
    // purpose still denies special-use ADDRESSES — and the Location names
    // one, so the hop is refused after exactly one request.
    var gated: HttpFetcher = .{
        .client = &http_client,
        .destinations = .{ .require_https = false, .deny_special_use = true },
    };
    const gated_result = gated.fetcher().fetch(url, &body_buf);
    const after_gated = peer.hits.load(.monotonic);

    // (b) With the address term relaxed the hops ARE followed — and stop at
    // `max_redirects`, rather than running as long as the server likes.
    var bounded: HttpFetcher = .{
        .client = &http_client,
        .destinations = .{ .require_https = false, .deny_special_use = false },
        .max_redirects = 2,
    };
    const bounded_result = bounded.fetcher().fetch(url, &body_buf);
    const after_bounded = peer.hits.load(.monotonic);

    // Release the peer, then tear the listener down.
    peer.stop.store(1, .release);
    if (server.socket.address.connect(io, .{ .mode = .stream })) |wake| {
        var w = wake;
        w.close(io);
    } else |_| {}
    pt.join();
    server.deinit(io);
    open = false;

    try testing.expectError(error.FetchFailed, gated_result);
    try testing.expectEqual(@as(u32, 1), after_gated);
    try testing.expectError(error.FetchFailed, bounded_result);
    // The first request plus `max_redirects` follow-ups, and not one more.
    try testing.expectEqual(@as(u32, 1 + 2), after_bounded - after_gated);
}

// ── fuzz: RDAP response + IANA bootstrap JSON parse, never panics ──────────
//
// `parseResponse` runs on the HTTP response body from whatever RDAP server
// a query was routed to (a registry/registrar an attacker may control or
// spoof); `parseBootstrap` runs on the IANA bootstrap registry file the
// client fetches to find that server in the first place — both are JSON
// this process did not produce.

/// `testkit.fuzz` — see that module for why a corpus entry is not the frame.
const tkfuzz = @import("testkit").fuzz;
const seed = tkfuzz.seed;

/// The harness buffers, raised from 512 on 2026-09-07.
///
/// ⛔ `domain_json` — this module's own reference RDAP document, the one
/// `assertMapperReached` parses — is **1549 octets**. A seed longer than the
/// harness buffer does not arrive truncated, it reads back EMPTY
/// (`Smith.slice` falls back to the range minimum), so at 512 the document the
/// module is built around could never have passed through the module's own
/// harness. Raise the buffer, never shrink the seed.
const rdap_fuzz_buf_len = 2048;

/// RDAP documents in the format `Smith.slice` reads (see `testkit.fuzz`).
///
/// 512 uniform random bytes never form JSON, so without these the target
/// reached `std.json`'s first token and stopped — the tolerant mapper, which
/// is the actual untrusted-input surface, was never entered from the fuzzer's
/// own bytes at all.
const response_seeds = [_][]const u8{
    seed(domain_json), // the RFC 9083 §5.3 reference document, 1549 octets
    seed("{\"objectClassName\":\"domain\",\"handle\":\"H\"}"), // the minimum that maps
    seed("{\"objectClassName\":\"entity\",\"vcardArray\":[\"vcard\",[[\"fn\",{},\"text\",\"A\"]]]}"), // extractVcard
    seed("{\"objectClassName\":\"domain\",\"entities\":[{\"objectClassName\":\"entity\",\"handle\":\"E\"}]}"), // mapEntities
    seed("{\"objectClassName\":\"domain\",\"redacted\":[{\"name\":{\"type\":\"Registrant\"}}]}"), // mapRedacted
    seed("{\"objectClassName\":\"domain\",\"status\":\"active\"}"), // a string where an array belongs
    seed("{\"objectClassName\":\"domain\",\"events\":[1,2,3]}"), // an array of the wrong element type
    seed("{\"errorCode\":404,\"title\":\"Not Found\"}"), // the RFC 9083 §6 error response
    seed("[]"), // valid JSON, not an RDAP object
    seed("{"), // InvalidJson: truncated
    seed("null"),
    seed(""), // InvalidJson — and the ONE input the collapsed harness ran
};

test "fuzz: parseResponse never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParseResponse, .{ .corpus = &response_seeds });
}

/// The tolerant mapper — `mapObject`/`mapEntities`/`extractVcard`/
/// `mapRedacted` — is the actual untrusted-input surface, and 512 uniform
/// random bytes never form JSON, so before this the harness reached
/// `std.json` and stopped there. Worse, `catch return` turned every outcome
/// into a pass. Three things fix the aim: an assertion that the mapper really
/// ran (independent of the fuzzer, so it fails the moment the harness drifts
/// off target again), an error switch instead of `catch return`, and a second
/// pass that puts the fuzzer's bytes INSIDE a well-formed RDAP document.
fn assertMapperReached() !void {
    var parsed = try parseResponse(testing.allocator, domain_json);
    defer parsed.deinit();
    const o = parsed.document.object;
    try testing.expectEqualStrings("2336799_DOMAIN_COM-VRSN", o.handle.?);
    try testing.expectEqual(@as(usize, 1), o.entities.len); // mapEntities
    try testing.expectEqualStrings("Example Registrar Inc.", o.entities[0].full_name.?); // extractVcard
    try testing.expect(o.events.len >= 3);
    try testing.expect(o.links.len >= 2);
}

fn tolerate(result: ParseError!Parsed) !void {
    var parsed = result catch |err| switch (err) {
        // The declared set, and nothing else. Anything outside it is a
        // failure, which `catch return` could never report.
        error.InvalidJson, error.InvalidRdap, error.OutOfMemory => return,
    };
    parsed.deinit();
}

/// Wrap the fuzzer's bytes in a real RDAP skeleton at a fuzzer-chosen member,
/// as a fuzzer-chosen JSON shape. This is what actually drives the mapper's
/// type switches: a member that is a string where an array is expected, an
/// array of the wrong element type, a deeply nested value, an absent member.
/// ⚠ The knobs are read out of `payload` with a `testkit.fuzz.Cursor`, NOT
/// drawn from `smith` after it. A knob drawn after the byte draw is dead on a
/// corpus replay — `Smith` discards the rest of its input on the first short
/// read, so `smith.index` returned 0 every time and this generator produced
/// `"handle"` as a JSON string, one shape out of six, on every single seed.
/// Reading them from the payload keeps them alive on a replay (a different
/// document picks a different member), keeps the seeds pure RDAP JSON, and
/// still lets `--fuzz` drive every choice, because `--fuzz` drives the bytes.
fn buildFuzzedResponse(w: *std.Io.Writer, payload: []const u8) !void {
    const members = [_][]const u8{
        "handle",      "ldhName",   "status",    "events",  "entities",
        "nameservers", "links",     "notices",   "remarks", "vcardArray",
        "redacted",    "publicIds", "secureDNS",
    };
    var knobs: tkfuzz.Cursor = .{ .bytes = payload };
    const member = members[knobs.ranged(0, members.len - 1)];
    try w.writeAll("{\"objectClassName\":\"domain\",\"handle\":\"H\",\"");
    try w.writeAll(member);
    try w.writeAll("\":");
    switch (knobs.ranged(0, 5)) {
        0 => try std.json.Stringify.encodeJsonString(payload, .{}, w),
        1 => try w.print("{d}", .{payload.len}),
        2 => {
            try w.writeAll("[");
            try std.json.Stringify.encodeJsonString(payload, .{}, w);
            try w.writeAll("]");
        },
        3 => {
            try w.writeAll("[{\"");
            try w.writeAll(member);
            try w.writeAll("\":");
            try std.json.Stringify.encodeJsonString(payload, .{}, w);
            try w.writeAll("}]");
        },
        4 => try w.writeAll("null"),
        else => {
            // Nesting, bounded by the fuzzer's own byte budget.
            const depth = knobs.ranged(0, 32);
            var i: u32 = 0;
            while (i < depth) : (i += 1) try w.writeAll("[");
            try std.json.Stringify.encodeJsonString(payload, .{}, w);
            i = 0;
            while (i < depth) : (i += 1) try w.writeAll("]");
        },
    }
    try w.writeAll("}");
}

fn fuzzParseResponse(_: void, smith: *std.testing.Smith) !void {
    try assertMapperReached();

    var buf: [rdap_fuzz_buf_len]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length. `bytes` takes `@min(buf.len, in.len)` octets and the ranged draw
    // then finds fewer than the eight it needs and returns the range MINIMUM —
    // so `len` was 0 for every input and both passes below ran on "", with the
    // document sitting unread in `buf`. `assertMapperReached` above kept the
    // target honest about the mapper being *reachable*, but nothing the fuzzer
    // produced ever got there. Measured 2026-09-07 over the corpus above:
    // **0 of 12 seeds non-empty and 0 documents mapped before, 11 of 12
    // non-empty (one seed IS the empty document) and 8 mapped after; and the
    // wrapper generator went from 1 distinct document across the corpus to 5.**
    const len: usize = smith.slice(&buf);
    const payload = buf[0..len];

    // (a) the raw bytes, as before: they must never panic.
    try tolerate(parseResponse(testing.allocator, payload));

    // (b) the same bytes inside a document the mapper will actually walk.
    var doc: std.Io.Writer.Allocating = .init(testing.allocator);
    defer doc.deinit();
    buildFuzzedResponse(&doc.writer, payload) catch return;
    try tolerate(parseResponse(testing.allocator, doc.written()));
}

test "corpus: every response seed reaches the mapper, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment — and the
    // only thing that would notice `domain_json` outgrowing the harness buffer
    // again, because such a seed reads back EMPTY, not truncated.
    //
    // `handles` and `entities` are pinned beside `mapped`: `parseResponse("")`
    // fails, so `mapped` is already a real signal, but the two structural
    // counts are what say the tolerant mapper walked something — they cannot
    // move for an empty document, and they notice a seed being shortened.
    //
    // `shapes` is the third: the number of DISTINCT wrapper documents
    // `buildFuzzedResponse` produced across the corpus. With the knobs drawn
    // after the byte draw it was 1 — one member, one shape, every seed.
    var nonempty: usize = 0;
    var mapped: usize = 0;
    var handles: usize = 0;
    var entities: usize = 0;
    var errors: usize = 0;
    var shapes: usize = 0;
    var seen: [response_seeds.len][]const u8 = undefined;
    var docs: [response_seeds.len]std.Io.Writer.Allocating = undefined;
    defer for (docs[0..shapes]) |*d| d.deinit();
    for (response_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [rdap_fuzz_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (parseResponse(testing.allocator, buf[0..len])) |p| {
            var parsed = p;
            defer parsed.deinit();
            mapped += 1;
            switch (parsed.document) {
                .object => |o| {
                    if (o.handle != null) handles += 1;
                    entities += o.entities.len;
                },
                .rdap_error => errors += 1,
            }
        } else |_| {}

        docs[shapes] = .init(testing.allocator);
        buildFuzzedResponse(&docs[shapes].writer, buf[0..len]) catch {
            docs[shapes].deinit();
            continue;
        };
        const wrapper = docs[shapes].written();
        var already = false;
        for (seen[0..shapes]) |s| {
            if (std.mem.eql(u8, s, wrapper)) already = true;
        }
        if (already) {
            docs[shapes].deinit();
        } else {
            seen[shapes] = wrapper;
            shapes += 1;
        }
    }
    // One seed IS the empty document, a legal member of a refusal corpus.
    try testing.expectEqual(response_seeds.len - 1, nonempty);
    // Measured 2026-09-07: with the collapsing draw, 0 non-empty, 0 mapped, 0
    // handles, 0 entities — and exactly 1 distinct wrapper document, because
    // the generator's knobs were dead too. After:
    try testing.expectEqual(@as(usize, 8), mapped);
    try testing.expectEqual(@as(usize, 2), handles);
    try testing.expectEqual(@as(usize, 2), entities);
    try testing.expectEqual(@as(usize, 1), errors);
    try testing.expectEqual(@as(usize, 5), shapes);
}

/// IANA bootstrap registry files in the format `Smith.slice` reads.
const bootstrap_seeds = [_][]const u8{
    // The RFC 9224 §4 shape: two services, four TLDs. Accepted.
    seed("{\"version\":\"1.0\",\"services\":[[[\"com\",\"net\"],[\"https://rdap.verisign.com/com/v1/\"]],[[\"org\"],[\"https://rdap.publicinterestregistry.org/rdap/\"]]]}"),
    seed("{\"version\":\"1.0\",\"publication\":\"2026-01-01T00:00:00Z\",\"services\":[[[\"example\"],[\"https://rdap.example/\"]]]}"),
    seed("{\"version\":\"1.0\",\"services\":[]}"), // legal and empty: zero services
    seed("{\"version\":\"1.0\",\"services\":[[[\"a\"],[]]]}"), // an entry with no URL
    seed("{\"version\":\"1.0\",\"services\":[[[\"a\"],[\"http://plaintext.example/\"]]]}"), // a non-TLS URL
    seed("{\"version\":\"1.0\"}"), // no services member at all
    seed("{\"services\":[[[\"com\"],[\"https://x/\"]]]}"), // no version member
    seed("{\"version\":\"1.0\",\"services\":\"not-an-array\"}"), // wrong type
    seed("{\"version\":\"1.0\",\"services\":[[\"com\",\"https://x/\"]]}"), // entry not a pair of arrays
    seed("[]"), // valid JSON, not a bootstrap file
    seed("{"), // InvalidJson
    seed(""), // InvalidJson — and the ONE input the collapsed harness ran
};

test "fuzz: parseBootstrap never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzParseBootstrap, .{ .corpus = &bootstrap_seeds });
}

fn fuzzParseBootstrap(_: void, smith: *std.testing.Smith) !void {
    var buf: [rdap_fuzz_buf_len]u8 = undefined;
    // ⚠ One `smith.slice` call, never `smith.bytes` followed by a ranged
    // length — see `fuzzParseResponse` for the measurement. `len` was 0 for
    // every input, so both `parseBootstrap` calls below ran on "" (once
    // directly, once wrapped as a service entry of two empty strings), with
    // the registry file sitting unread in `buf`. Measured 2026-09-07 over the
    // corpus above: **0 of 12 seeds non-empty and 0 registries parsed before,
    // 11 of 12 non-empty (one seed IS the empty file), 7 parsed and 5 services
    // walked after.**
    const len: usize = smith.slice(&buf);
    const payload = buf[0..len];

    // Aim canary: the bootstrap mapper must be reachable, and this says so
    // without depending on the fuzzer (see `assertMapperReached`).
    {
        const canary =
            \\{
            \\  "version": "1.0",
            \\  "services": [
            \\    [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
            \\    [["org"], ["https://rdap.publicinterestregistry.org/rdap/"]]
            \\  ]
            \\}
        ;
        var bs = try parseBootstrap(testing.allocator, canary);
        defer bs.deinit();
        try testing.expectEqual(@as(usize, 2), bs.services.len);
        try testing.expect(bs.lookupDomain("example.com") != null);
    }

    if (parseBootstrap(testing.allocator, payload)) |bs| {
        var b = bs;
        b.deinit();
    } else |err| switch (err) {
        error.InvalidJson, error.InvalidRdap, error.OutOfMemory => {},
    }

    // The fuzzer's bytes as a service entry, so the shape the mapper walks is
    // a bootstrap file and not a random blob.
    var doc: std.Io.Writer.Allocating = .init(testing.allocator);
    defer doc.deinit();
    doc.writer.writeAll("{\"version\":\"1.0\",\"services\":[[[") catch return;
    std.json.Stringify.encodeJsonString(payload, .{}, &doc.writer) catch return;
    doc.writer.writeAll("],[") catch return;
    std.json.Stringify.encodeJsonString(payload, .{}, &doc.writer) catch return;
    doc.writer.writeAll("]]]}") catch return;
    if (parseBootstrap(testing.allocator, doc.written())) |bs| {
        var b = bs;
        b.deinit();
    } else |err| switch (err) {
        error.InvalidJson, error.InvalidRdap, error.OutOfMemory => {},
    }
}

test "corpus: every bootstrap seed reaches parseBootstrap, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment.
    //
    // ⚠ `parsed` on its own would be the exact trap tranche 2 paid for: a
    // bootstrap file with an EMPTY services array is legal, so a lenient
    // count reads high while nothing is walked. `services` is the number the
    // empty input — and the empty registry — cannot produce.
    var nonempty: usize = 0;
    var parsed: usize = 0;
    var services: usize = 0;
    var resolvable: usize = 0;
    for (bootstrap_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var buf: [rdap_fuzz_buf_len]u8 = undefined;
        const len: usize = smith.slice(&buf);
        if (len != 0) nonempty += 1;
        if (parseBootstrap(testing.allocator, buf[0..len])) |b| {
            var bs = b;
            defer bs.deinit();
            parsed += 1;
            services += bs.services.len;
            if (bs.lookupDomain("example.com") != null) resolvable += 1;
        } else |_| {}
    }
    // One seed IS the empty file, a legal member of a refusal corpus.
    try testing.expectEqual(bootstrap_seeds.len - 1, nonempty);
    // Measured 2026-09-07: with the collapsing draw, 0 non-empty, 0 parsed, 0
    // services and 0 resolvable — one empty string twelve times. After:
    try testing.expectEqual(@as(usize, 7), parsed);
    try testing.expectEqual(@as(usize, 5), services);
    try testing.expectEqual(@as(usize, 2), resolvable);
}

test {
    _ = @import("goldens.zig");
}
