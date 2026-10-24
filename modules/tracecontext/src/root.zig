// SPDX-License-Identifier: MIT

//! tracecontext — W3C Trace Context propagation as a `router` middleware.
//!
//! Implements W3C Trace Context Level 1: parsing, generating and forwarding
//! the `traceparent` header, and parsing, carrying and amending the
//! `tracestate` list, so a request keeps a single distributed-trace identity
//! as it crosses services.
//!
//! A `traceparent` value is `version-traceid-parentid-flags`, e.g.
//! `00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01`:
//!
//! - `version`   two lowercase hex. `00` (Level 1) is what we emit; a higher
//!               version is read forward-compatibly as its Level 1 prefix
//!               (W3C §3.2.2.3), and `ff` is reserved as invalid.
//! - `trace-id`  16 bytes / 32 lowercase hex — the whole-trace identity, kept
//!               end to end. The all-zero value is invalid.
//! - `parent-id` (a.k.a. span-id) 8 bytes / 16 lowercase hex — the caller's
//!               span. The all-zero value is invalid.
//! - `flags`     one byte / 2 lowercase hex — bit 0 (`01`) = sampled.
//!
//! The middleware, per request:
//!
//! 1. Parses the incoming `traceparent`. If valid (and `trust_incoming`),
//!    **keeps its trace-id and flags** and mints a **fresh span-id** for this
//!    hop — the child context of the incoming one.
//! 2. If absent or malformed, **starts a new trace** (fresh trace-id + span-id,
//!    flags from `sampled`).
//! 3. When (and only when) a trusted `traceparent` was continued in step 1,
//!    carries the `tracestate` list along: header instances combined per
//!    RFC 9110 §5.3, parsed by the W3C member grammar (`TraceState`), a list
//!    that fails it dropped whole, optional whitespace and empty members
//!    dropped, a key's later duplicates dropped. A `tracestate` arriving
//!    without a valid incoming `traceparent` is dropped outright — per spec,
//!    a vendor that fails to parse `traceparent` MUST NOT attempt to parse
//!    `tracestate`. With `Options.state_entry` this service's own member is
//!    put in front (replacing its old one), on a new trace too.
//! 4. Exposes the current hop's context via `tracecontext.current()` (a
//!    thread-local, like `requestid.current()`) and, when `echo` is set, writes
//!    the outgoing `traceparent`/`tracestate` back on the response.
//!
//! Register it **first** (outermost) so every response carries the context.
//!
//! ## Generated IDs
//!
//! trace-ids and span-ids come from one process-wide atomic sequence, offset
//! by a per-process prefix and scattered by a 64-bit bijection — unique
//! within the process across all threads, no allocation and no OS entropy
//! call. They are **correlation** identifiers, NOT unpredictable security
//! tokens: do not rely on them being unguessable. W3C Level 1 does not
//! require randomness of trace-ids, only uniqueness; if you need CSPRNG ids,
//! mint them yourself and set `traceparent`.
//!
//! ## Memory / concurrency
//!
//! The current context is a value in thread-local storage owned by the
//! connection task (the server is task-per-connection: one request at a time
//! per thread). The outgoing `tracestate` is formatted into a thread-local
//! buffer, valid until the next request on the thread. `current()` is meaningful only from
//! the connection thread handling the request the middleware ran on.

const std = @import("std");
const builtin = @import("builtin");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "W3C Trace Context — `traceparent`/`tracestate` parse + generate + propagation middleware (child span per hop) for distributed tracing",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .util,
    // Per-request state lives in thread-local storage owned by the connection
    // task; the immutable config is only read.
    .concurrency = .threadsafe,
    .model_after = "W3C Trace Context Level 1 (traceparent/tracestate)",
    .deps = .{ "router", "http" },
};

/// Default header names (case-insensitive on read; emitted lowercase per spec).
pub const default_traceparent_header = "traceparent";
pub const default_tracestate_header = "tracestate";

/// traceparent flag: the trace is sampled (recorded).
pub const flag_sampled: u8 = 0x01;

/// Longest combined incoming `tracestate` accepted (a longer one is dropped
/// whole) and longest outgoing one (whole members are left out to fit, see
/// `TraceState.write`). W3C: vendors SHOULD propagate at least 512 characters
/// and document their maximum — this is it.
pub const max_state_len = 512;

/// A parsed / mintable `traceparent` (version `00`). `trace_id` and
/// `parent_id` are raw bytes; `write` renders them back to the header string.
pub const TraceParent = struct {
    trace_id: [16]u8,
    parent_id: [8]u8,
    flags: u8,

    /// Length of a rendered `00` traceparent: `00` `-` 32 `-` 16 `-` 2 = 55.
    pub const header_len = 2 + 1 + 32 + 1 + 16 + 1 + 2;

    pub const ParseError = error{
        BadLength,
        BadVersion,
        BadFormat,
        BadHex,
        ZeroTraceId,
        ZeroParentId,
    };

    /// Parse a traceparent. Rejects a wrong length, misplaced delimiters, any
    /// non-lowercase-hex digit and the all-zero trace-id / parent-id (both
    /// invalid per spec).
    ///
    /// Future versions are parsed forward-compatibly, as W3C §3.2.2.3
    /// requires: every version keeps the Level 1 `version-traceid-parentid-
    /// flags` prefix and may append `-<extra>`, so a header we do not know is
    /// read as its Level 1 prefix and the remainder is ignored rather than
    /// restarting the trace. Version `ff` is reserved as invalid, and `00`
    /// itself is exactly `header_len` — trailing bytes there are malformed,
    /// not an extension.
    pub fn parse(v: []const u8) ParseError!TraceParent {
        if (v.len < header_len) return error.BadLength;
        var version_byte: [1]u8 = undefined;
        if (!decodeHex(&version_byte, v[0..2])) return error.BadVersion;
        if (version_byte[0] == 0xff) return error.BadVersion;
        if (version_byte[0] == 0x00) {
            if (v.len != header_len) return error.BadLength;
        } else if (v.len > header_len and v[header_len] != '-') {
            return error.BadFormat;
        }
        if (v[2] != '-' or v[35] != '-' or v[52] != '-') return error.BadFormat;

        var tp: TraceParent = undefined;
        var flags_byte: [1]u8 = undefined;
        if (!decodeHex(&tp.trace_id, v[3..35])) return error.BadHex;
        if (!decodeHex(&tp.parent_id, v[36..52])) return error.BadHex;
        if (!decodeHex(&flags_byte, v[53..55])) return error.BadHex;
        tp.flags = flags_byte[0];

        if (isZero(&tp.trace_id)) return error.ZeroTraceId;
        if (isZero(&tp.parent_id)) return error.ZeroParentId;
        return tp;
    }

    /// Render this context into `buf` (exactly `header_len` bytes) and return
    /// the slice. Always version `00`, lowercase hex.
    pub fn write(tp: TraceParent, buf: *[header_len]u8) []const u8 {
        buf[0] = '0';
        buf[1] = '0';
        buf[2] = '-';
        encodeHex(buf[3..35], &tp.trace_id);
        buf[35] = '-';
        encodeHex(buf[36..52], &tp.parent_id);
        buf[52] = '-';
        encodeHex(buf[53..55], &[_]u8{tp.flags});
        return buf[0..];
    }

    /// True when the sampled flag (bit 0) is set.
    pub fn sampled(tp: TraceParent) bool {
        return tp.flags & flag_sampled != 0;
    }
};

/// The child of `parent` for this hop: same trace-id, a fresh span-id
/// (`parent_id`) identifying the current span, and the parent's `sampled`
/// flag. Every other flag bit is cleared: Level 1 defines only `sampled`,
/// and "Vendors MUST set all unparsed / unknown trace-flags to 0 on outgoing
/// requests" (W3C Trace Context §3.2.2.5 / processing model). An incoming
/// `...-ff` is still accepted (the spec forbids rejecting it), it just goes
/// out as `...-01`. Until 2026-10-05 every bit was copied through (found by
/// the OpenTelemetry Go oracle, `otel_oracle_test.zig`).
pub fn childOf(parent: TraceParent, span_id: [8]u8) TraceParent {
    return .{ .trace_id = parent.trace_id, .parent_id = span_id, .flags = parent.flags & flag_sampled };
}

/// A brand-new root context (fresh trace-id + span-id).
pub fn newTrace(flags: u8) TraceParent {
    return .{ .trace_id = newTraceId(), .parent_id = newSpanId(), .flags = flags };
}

/// Most list-members a `tracestate` may hold (W3C Trace Context §3.3.1.3).
pub const max_members = 32;
/// Longest key and longest value of one list-member.
pub const max_key_len = 256;
pub const max_value_len = 256;

/// A key per the W3C grammar: `(lcalpha / DIGIT) 0*255(keychar)`, keychar =
/// lcalpha / DIGIT / `_` / `-` / `*` / `/` / `@` (the text of the pinned
/// spec revision; Level 1's tenant`@`system split is a subset of it).
pub fn isValidKey(k: []const u8) bool {
    if (k.len == 0 or k.len > max_key_len) return false;
    switch (k[0]) {
        'a'...'z', '0'...'9' => {},
        else => return false,
    }
    for (k[1..]) |c| switch (c) {
        'a'...'z', '0'...'9', '_', '-', '*', '/', '@' => {},
        else => return false,
    };
    return true;
}

/// A value per the W3C grammar: 1–256 printable ASCII (0x20–0x7E) except
/// `,` and `=`, not ending in a space. Leading spaces are part of the value.
pub fn isValidValue(v: []const u8) bool {
    if (v.len == 0 or v.len > max_value_len or v[v.len - 1] == ' ') return false;
    for (v) |c| switch (c) {
        0x20...0x2B, 0x2D...0x3C, 0x3E...0x7E => {},
        else => return false,
    };
    return true;
}

/// A parsed `tracestate` list (W3C Trace Context §3.3): up to
/// `max_members` key/value members, left = most recent. Members borrow the
/// parsed input and the values handed to `put`; nothing is allocated.
pub const TraceState = struct {
    members_buf: [max_members]Member = undefined,
    len: u8 = 0,

    pub const Member = struct { key: []const u8, value: []const u8 };

    pub const ParseError = error{
        /// A member is not `key=value`, or its key or value breaks the grammar.
        BadMember,
        /// More than `max_members` non-empty members.
        TooManyMembers,
    };

    /// Parse a combined header value. Optional whitespace around members is
    /// ignored and empty members are skipped (both legal: they appear when
    /// several header fields are combined). A later duplicate of a key is
    /// dropped — the left one is the most recent (the conformance suite
    /// accepts keeping one; the spec lets a vendor discard duplicates). Any
    /// invalid member makes the whole value invalid, as the conformance
    /// suite requires: a vendor that cannot parse `tracestate` drops it.
    pub fn parse(v: []const u8) ParseError!TraceState {
        var ts: TraceState = .{};
        var it = std.mem.splitScalar(u8, v, ',');
        var seen: usize = 0;
        while (it.next()) |raw| {
            const m = std.mem.trim(u8, raw, " \t");
            if (m.len == 0) continue;
            const eq = std.mem.findScalar(u8, m, '=') orelse return error.BadMember;
            const key = m[0..eq];
            const value = m[eq + 1 ..];
            if (!isValidKey(key) or !isValidValue(value)) return error.BadMember;
            seen += 1;
            if (seen > max_members) return error.TooManyMembers;
            if (ts.get(key) != null) continue;
            ts.members_buf[ts.len] = .{ .key = key, .value = value };
            ts.len += 1;
        }
        return ts;
    }

    pub fn members(ts: *const TraceState) []const Member {
        return ts.members_buf[0..ts.len];
    }

    /// The value for `key`, or null.
    pub fn get(ts: *const TraceState, key: []const u8) ?[]const u8 {
        for (ts.members()) |m| if (std.mem.eql(u8, m.key, key)) return m.value;
        return null;
    }

    /// Add or update `key` and move it to the front (W3C "Mutating the
    /// tracestate Field": a modified key moves left, a key appears once).
    /// A full list loses its right-most member. Both slices are borrowed.
    pub fn put(ts: *TraceState, key: []const u8, value: []const u8) error{BadMember}!void {
        if (!isValidKey(key) or !isValidValue(value)) return error.BadMember;
        _ = ts.delete(key);
        const keep: usize = @min(ts.len, max_members - 1); // usize: @min would narrow to u5
        std.mem.copyBackwards(Member, ts.members_buf[1 .. keep + 1], ts.members_buf[0..keep]);
        ts.members_buf[0] = .{ .key = key, .value = value };
        ts.len = @intCast(keep + 1);
    }

    /// Remove `key`; false when it was not there.
    pub fn delete(ts: *TraceState, key: []const u8) bool {
        for (ts.members(), 0..) |m, i| if (std.mem.eql(u8, m.key, key)) {
            std.mem.copyForwards(Member, ts.members_buf[i .. ts.len - 1], ts.members_buf[i + 1 .. ts.len]);
            ts.len -= 1;
            return true;
        };
        return false;
    }

    /// Render `key=value,…` into `buf`. When it does not fit, whole members
    /// are left out the way the spec orders it: members over 128 characters
    /// first, then from the right. The result may be empty (no member fits,
    /// or the list is empty) — send no header then.
    pub fn write(ts: *const TraceState, buf: []u8) []const u8 {
        var keep: [max_members]bool = @splat(true);
        var total: usize = 0;
        for (ts.members(), 0..) |m, i| total += memberLen(m) + @intFromBool(i != 0);
        // Long members first, right to left, then any from the right.
        for ([_]bool{ true, false }) |long_only| {
            var i: usize = ts.len;
            while (total > buf.len and i > 0) {
                i -= 1;
                if (!keep[i] or (long_only and memberLen(ts.members_buf[i]) <= 128)) continue;
                keep[i] = false;
                total -|= memberLen(ts.members_buf[i]) + 1; // its comma (or the next one's); 0 once none is left
            }
        }
        var w: std.Io.Writer = .fixed(buf);
        var first = true;
        for (ts.members(), keep[0..ts.len]) |m, k| {
            if (!k) continue;
            if (!first) w.writeByte(',') catch unreachable;
            w.print("{s}={s}", .{ m.key, m.value }) catch unreachable;
            first = false;
        }
        return w.buffered();
    }

    fn memberLen(m: Member) usize {
        return m.key.len + 1 + m.value.len;
    }
};

/// This service's own `tracestate` entry, written on every outgoing context
/// (W3C: "The new key/value pair SHOULD be added to the beginning of the
/// list"; an existing entry under the same key is replaced and moved left).
pub const StateEntry = struct {
    /// Our vendor key; must pass `isValidKey` or the entry is never added.
    key: []const u8,
    /// Passed back to `value` verbatim.
    context: ?*anyopaque = null,
    /// The value for this hop (`hop` is the outgoing context), written into
    /// `buf` or any slice that outlives the request; null adds nothing this
    /// time. A value failing `isValidValue` is not added.
    value: *const fn (context: ?*anyopaque, hop: TraceParent, buf: *[max_value_len]u8) ?[]const u8,
};

pub const Options = struct {
    /// Header carrying the trace-id chain. Default `traceparent`.
    traceparent_header: []const u8 = default_traceparent_header,
    /// Vendor state header carried along. Default `tracestate`.
    tracestate_header: []const u8 = default_tracestate_header,
    /// Continue a valid incoming trace instead of always starting a new one.
    trust_incoming: bool = true,
    /// Sampled flag for a newly *started* trace (ignored when continuing).
    sampled: bool = true,
    /// Echo the outgoing `traceparent` (and `tracestate`) on the response.
    /// Off ⇒ the context is only exposed via `current()`/`currentState()`.
    echo: bool = true,
    /// This service's own `tracestate` member, added in front of the
    /// carried list (or as the only member of a new trace). Null: the list
    /// is carried as received (normalized: OWS and empty members dropped,
    /// a key's later duplicates dropped).
    state_entry: ?StateEntry = null,
};

/// Config + the middleware over it. Immutable; share one across threads.
pub const TraceContext = struct {
    options: Options = .{},

    pub fn middleware(tc: *const TraceContext) router.Middleware {
        return .{ .state = @constCast(tc), .run = middlewareRun };
    }
};

// Per-connection-thread request-scoped storage (see the module doc).
threadlocal var current_ctx: ?TraceParent = null;
threadlocal var current_state: ?[]const u8 = null;
// Scratch for combining multiple `tracestate` header instances (RFC 9110
// §5.3 field order — see `combinedHeader`) before validation. Sized to
// `max_state_len` since anything that would overflow it is dropped anyway
// under the existing coarse length gate.
threadlocal var state_buf: [max_state_len]u8 = undefined;
// The outgoing (normalized) `tracestate`, and our own entry's value.
threadlocal var state_out_buf: [max_state_len]u8 = undefined;
threadlocal var entry_value_buf: [max_value_len]u8 = undefined;

/// The current hop's trace context, or null if no `TraceContext` middleware has
/// run on this thread yet. Call it from the connection thread during the
/// request. The trace-id is the whole-trace identity; the parent-id is this
/// hop's span-id.
pub fn current() ?TraceParent {
    return current_ctx;
}

/// The outgoing `tracestate` of this request (normalized, with our
/// `state_entry` in front), if any.
pub fn currentState() ?[]const u8 {
    return current_state;
}

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const tc: *const TraceContext = @ptrCast(@alignCast(state.?));
    const opt = tc.options;

    const incoming: ?TraceParent = blk: {
        if (!opt.trust_incoming) break :blk null;
        // A duplicated traceparent is ambiguous (which of the two is the real
        // parent?), so it is discarded exactly like an absent/malformed one —
        // per the W3C conformance suite's `test_traceparent_duplicated`, NOT a
        // normative sentence in the spec's traceparent section itself.
        const raw = singleHeader(ctx.req, opt.traceparent_header) orelse break :blk null;
        break :blk TraceParent.parse(raw) catch null;
    };

    const hop: TraceParent = if (incoming) |p|
        childOf(p, newSpanId())
    else
        newTrace(if (opt.sampled) flag_sampled else 0);
    current_ctx = hop;

    // tracestate: the spec is explicit — "If the vendor failed to parse
    // traceparent, it MUST NOT attempt to parse tracestate" (spec
    // `20-http_request_header_format.md`, "Tracestate Header"; the W3C
    // conformance suite's `test_tracestate_included_traceparent_missing`
    // exercises exactly this). So without a trusted, successfully-parsed
    // incoming traceparent, the incoming tracestate is dropped outright —
    // there is no parent to correlate it with — regardless of how
    // well-formed it looks. Otherwise: RFC 9110 §5.3 requires multiple
    // same-name header instances to be combined (comma-joined, in wire
    // order) before use — the spec's own "tracestate MAY be split into
    // multiple header fields" text depends on this. A combined value that
    // fails the member grammar is dropped whole.
    var list: TraceState = .{};
    if (incoming != null) {
        if (combinedHeader(ctx.req, opt.tracestate_header, &state_buf)) |raw| {
            list = TraceState.parse(raw) catch .{};
        }
    }
    if (opt.state_entry) |e| {
        if (e.value(e.context, hop, &entry_value_buf)) |v| list.put(e.key, v) catch {};
    }
    current_state = blk: {
        const out = list.write(&state_out_buf);
        break :blk if (out.len == 0) null else out;
    };

    if (opt.echo) {
        // Plain local: `setHeader` copies the bytes (`ResponseWriter.header_buf`),
        // so this buffer only has to outlive the call, not the response. It was
        // a `threadlocal` until 2026-08-12 for the latter reason.
        var out_buf: [TraceParent.header_len]u8 = undefined;
        try ctx.res.setHeader(opt.traceparent_header, hop.write(&out_buf));
        if (current_state) |ts| try ctx.res.setHeader(opt.tracestate_header, ts);
    }
    return next.run(ctx);
}

/// The value of header `name` only when it occurs EXACTLY once; null if
/// absent OR duplicated. A single-valued header (`traceparent`) sent twice is
/// ambiguous — neither occurrence can be trusted over the other — so it is
/// treated the same as absent/malformed (see `middlewareRun`).
fn singleHeader(req: *const http.Server.Request, name: []const u8) ?[]const u8 {
    var it = req.iterateHeaders();
    var found: ?[]const u8 = null;
    while (it.next()) |entry| {
        if (!std.ascii.eqlIgnoreCase(entry.name, name)) continue;
        if (found != null) return null; // duplicate — ambiguous, discard both
        found = entry.value;
    }
    return found;
}

/// Every occurrence of header `name`, comma-joined in wire order into `buf`
/// (RFC 9110 §5.3 field-order combining — `tracestate` MAY legally arrive as
/// several header instances that must be combined before use). Returns null
/// when absent, or when combining would overflow `buf` (the existing coarse
/// `max_state_len` gate then drops it entirely, same as an over-long single
/// header already did).
fn combinedHeader(req: *const http.Server.Request, name: []const u8, buf: []u8) ?[]const u8 {
    var it = req.iterateHeaders();
    var len: usize = 0;
    var any = false;
    while (it.next()) |entry| {
        if (!std.ascii.eqlIgnoreCase(entry.name, name)) continue;
        const piece = entry.value;
        const sep_len: usize = if (any) 1 else 0;
        if (len + sep_len + piece.len > buf.len) return null;
        if (any) {
            buf[len] = ',';
            len += 1;
        }
        @memcpy(buf[len..][0..piece.len], piece);
        len += piece.len;
        any = true;
    }
    return if (any) buf[0..len] else null;
}

// ── id generation (portable, no OS entropy — see module doc) ─────────────────

/// A fresh 8-byte span-id (never all-zero).
pub fn newSpanId() [8]u8 {
    var id: [8]u8 = undefined;
    fillId(&id);
    return id;
}

/// A fresh 16-byte trace-id (never all-zero).
pub fn newTraceId() [16]u8 {
    var id: [16]u8 = undefined;
    fillId(&id);
    return id;
}

/// Fill `dst` (8 or 16 bytes) with an id unique within the process. Each
/// call takes a number from one process-wide atomic sequence and passes it,
/// offset by a per-process prefix, through a 64-bit bijection (the
/// SplitMix64 finalizer) — distinct numbers give distinct, well-scattered
/// ids. A 16-byte trace-id puts the prefix itself in front, so trace-ids of
/// two processes differ unless their prefixes do. Never the all-zero
/// (invalid) id. Not a CSPRNG — a correlation id, not a secret.
///
/// Until 2026-10-11 the input was the monotonic clock, a thread-address
/// nonce and a per-thread counter, which could repeat across connection
/// threads (TLS blocks sit at a fixed stride; every thread's counter started
/// at 1; see requestid's same fix).
fn fillId(dst: []u8) void {
    const prefix = processPrefix();
    var x = mix64(next_seq.fetchAdd(1, .monotonic) +% prefix);
    if (x == 0) x = 1; // the one sequence value mapping to 0
    switch (dst.len) {
        8 => std.mem.writeInt(u64, dst[0..8], x, .big),
        16 => {
            std.mem.writeInt(u64, dst[0..8], prefix, .big);
            std.mem.writeInt(u64, dst[8..16], x, .big);
        },
        else => unreachable,
    }
}

var next_seq: std.atomic.Value(u64) = .init(0);
var prefix_cache: std.atomic.Value(u64) = .init(0);

/// SplitMix64's output function: a bijection on u64.
fn mix64(v: u64) u64 {
    var z = v;
    z = (z ^ (z >> 30)) *% 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) *% 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

/// Per-process value computed on first use from the wall and monotonic
/// clocks, the PID (Linux) and a static's address (ASLR); never 0 (the
/// "not yet" sentinel). Racing first callers: the first store wins.
fn processPrefix() u64 {
    const cached = prefix_cache.load(.monotonic);
    if (cached != 0) return cached;
    var h = std.hash.Wyhash.init(0x7472_6163_6563_7478);
    std.hash.autoHash(&h, wallNs());
    std.hash.autoHash(&h, monoNs());
    std.hash.autoHash(&h, @intFromPtr(&prefix_cache));
    if (builtin.os.tag == .linux) std.hash.autoHash(&h, std.os.linux.getpid());
    const fresh = @max(h.final(), 1);
    return prefix_cache.cmpxchgStrong(0, fresh, .monotonic, .monotonic) orelse fresh;
}

fn wallNs() u64 {
    if (builtin.os.tag == .windows) return 0; // the monotonic reading and ASLR still vary
    var ts: std.posix.timespec = undefined;
    if (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts)) != .SUCCESS) return 0;
    return @as(u64, @bitCast(@as(i64, ts.sec))) *% std.time.ns_per_s +% @as(u64, @intCast(ts.nsec));
}

fn monoNs() u64 {
    switch (builtin.os.tag) {
        .windows => {
            var qpf: std.os.windows.LARGE_INTEGER = undefined;
            var qpc: std.os.windows.LARGE_INTEGER = undefined;
            if (!std.os.windows.ntdll.RtlQueryPerformanceFrequency(&qpf).toBool()) return 0;
            if (!std.os.windows.ntdll.RtlQueryPerformanceCounter(&qpc).toBool()) return 0;
            const freq: u64 = @bitCast(qpf);
            const count: u64 = @bitCast(qpc);
            return @intCast(@as(u128, count) * std.time.ns_per_s / freq);
        },
        else => {
            var ts: std.posix.timespec = undefined;
            if (std.posix.errno(std.posix.system.clock_gettime(.MONOTONIC, &ts)) != .SUCCESS) return 0;
            return @as(u64, @intCast(ts.sec)) * std.time.ns_per_s + @as(u64, @intCast(ts.nsec));
        },
    }
}

// ── hex helpers (lowercase only, per spec) ───────────────────────────────────

const hex_digits = "0123456789abcdef";

fn encodeHex(dst: []u8, src: []const u8) void {
    for (src, 0..) |byte, i| {
        dst[i * 2] = hex_digits[byte >> 4];
        dst[i * 2 + 1] = hex_digits[byte & 0x0f];
    }
}

/// Decode `src` (lowercase hex, `dst.len * 2` chars) into `dst`; false on any
/// non-lowercase-hex digit. Uppercase is rejected — the spec mandates lowercase.
fn decodeHex(dst: []u8, src: []const u8) bool {
    for (dst, 0..) |*d, i| {
        const hi = hexNibble(src[i * 2]) orelse return false;
        const lo = hexNibble(src[i * 2 + 1]) orelse return false;
        d.* = (@as(u8, hi) << 4) | lo;
    }
    return true;
}

fn hexNibble(c: u8) ?u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        else => null,
    };
}

fn isZero(s: []const u8) bool {
    for (s) |b| {
        if (b != 0) return false;
    }
    return true;
}

// ── tests (offline — through http.Server.serveStream) ───────────────────────

const testing = std.testing;
const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

// A canonical W3C example traceparent (from the spec).
const sample = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const sample_trace = "4bf92f3577b34da6a3ce929d0e0e4736";
const sample_span = "00f067aa0ba902b7";

// `runWire`/`headerValue` are `pub` (not just file-local) so the vendored
// W3C-corpus runner (`w3c_conformance_test.zig`) can drive the same offline
// wire harness instead of duplicating it.
pub fn runWire(r: *router.Router, bytes: []const u8, out_buf_wire: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf_wire);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [256]u8 = undefined;
    var response_body_buf: [512]u8 = undefined;
    var chunk_buf: [128]u8 = undefined;
    http.Server.serveStream(.{
        .handler = r.handler(),
        .context = r,
        .server_name = null,
    }, &in, &out, .{
        .head = &head_buf,
        .request_body = &request_body_buf,
        .response_body = &response_body_buf,
        .chunk = &chunk_buf,
    });
    return out.buffered();
}

fn bodyOf(got: []const u8) []const u8 {
    const i = std.mem.find(u8, got, "\r\n\r\n") orelse return "";
    return got[i + 4 ..];
}

pub fn headerValue(got: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, got, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, line[0..colon], " "), name))
            return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

/// Handler that renders `current()` into the body so tests can assert it
/// matches the outgoing response header.
fn hEchoCurrent(ctx: *router.Ctx) anyerror!void {
    if (current()) |tp| {
        var b: [TraceParent.header_len]u8 = undefined;
        try ctx.res.writeAll(tp.write(&b));
    } else try ctx.res.writeAll("<none>");
}

test "valid incoming traceparent: trace-id carried, fresh span-id, current() matches" {
    var tc = TraceContext{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "traceparent: " ++ sample ++ "\r\nConnection: close\r\n\r\n", &buf);

    const hdr = headerValue(got, "traceparent").?;
    try testing.expectEqual(@as(usize, TraceParent.header_len), hdr.len);
    // Trace-id and flags carried from the incoming header …
    try testing.expectEqualStrings("00", hdr[0..2]);
    try testing.expectEqualStrings(sample_trace, hdr[3..35]);
    try testing.expectEqualStrings("01", hdr[53..55]);
    // … but a fresh span-id was minted for this hop.
    try testing.expect(!std.mem.eql(u8, sample_span, hdr[36..52]));
    // The outgoing header re-parses and is sampled.
    const parsed = try TraceParent.parse(hdr);
    try testing.expect(parsed.sampled());
    // Handler saw the same context via current().
    try testing.expectEqualStrings(hdr, bodyOf(got));
}

test "absent traceparent starts a fresh valid trace" {
    var tc = TraceContext{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    const hdr = headerValue(got, "traceparent").?;
    const parsed = try TraceParent.parse(hdr); // valid, non-zero ids
    try testing.expect(parsed.sampled()); // default sampled=true
}

test "malformed incoming traceparent starts a fresh trace" {
    var tc = TraceContext{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "traceparent: not-a-valid-traceparent\r\nConnection: close\r\n\r\n", &buf);
    const hdr = headerValue(got, "traceparent").?;
    _ = try TraceParent.parse(hdr); // still emits a valid fresh context
}

test "echo=false omits the header but keeps current()" {
    var tc = TraceContext{ .options = .{ .echo = false } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "traceparent"));
    try testing.expectEqual(@as(usize, TraceParent.header_len), bodyOf(got).len); // current() set
}

test "trust_incoming=false always starts a fresh trace, even with a valid incoming traceparent" {
    var tc = TraceContext{ .options = .{ .trust_incoming = false } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "traceparent: " ++ sample ++ "\r\nConnection: close\r\n\r\n", &buf);

    const hdr = headerValue(got, "traceparent").?;
    const parsed = try TraceParent.parse(hdr); // still a valid fresh context
    // The incoming trace-id must NOT have been kept: a fresh trace-id was minted.
    try testing.expect(!std.mem.eql(u8, sample_trace, hdr[3..35]));
    _ = parsed;
}

test "tracestate is carried through unchanged" {
    var tc = TraceContext{};
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "traceparent: " ++ sample ++ "\r\ntracestate: rojo=00f067aa0ba902b7,congo=t61rcWkgMzE\r\n" ++
        "Connection: close\r\n\r\n", &buf);
    try testing.expectEqualStrings(
        "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
        headerValue(got, "tracestate").?,
    );
}

test "traceparent: every field delimiter is checked; a fresh trace honours Options.sampled; DEL in tracestate is dropped" {
    // W3C Trace Context §3.2.2: `version "-" trace-id "-" parent-id "-"
    // trace-flags` -- a non-dash at byte 35 or 52 is no traceparent.
    // Mutation 2026-10-04: dropping either delimiter check survived (the
    // vectors only break the first one).
    const tid = "4bf92f3577b34da6a3ce929d0e0e4736";
    const pid = "00f067aa0ba902b7";
    try testing.expectError(error.BadFormat, TraceParent.parse("00-" ++ tid ++ "x" ++ pid ++ "-01"));
    try testing.expectError(error.BadFormat, TraceParent.parse("00-" ++ tid ++ "-" ++ pid ++ "x01"));

    // `Options.sampled`: "Sampled flag for a newly *started* trace" -- false
    // starts an unsampled trace (flags 00). Mutation: ignoring it survived.
    {
        var tc = TraceContext{ .options = .{ .sampled = false } };
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(tc.middleware());
        try r.get("/", hEchoCurrent);
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n", &buf);
        const tp = try TraceParent.parse(headerValue(got, "traceparent").?);
        try testing.expect(!tp.sampled());
    }

    // `isValidValue`: printable ASCII only; DEL (0x7f) is a control
    // character. Mutation 2026-10-04 (on the old whole-value guard):
    // admitting 0x7f survived (only 0x01 was tested). Checked on the
    // grammar itself: `http.Server` already refuses a header value carrying
    // DEL, so over the wire it never gets this far -- the grammar is what
    // holds for any other server feeding this middleware.
    try testing.expect(!isValidValue("\x7fbad"));
    try testing.expectError(error.BadMember, TraceState.parse("rojo=\x7fbad"));
    const ok = try TraceState.parse("rojo=00f067aa0ba902b7,\tcongo=t61rcWkgMzE");
    try testing.expectEqual(@as(usize, 2), ok.members().len);
}

test "tracestate: invalid values (empty, too long, control char) are dropped, not passed through" {
    // Empty value: dropped.
    {
        var tc = TraceContext{};
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(tc.middleware());
        try r.get("/", hEchoCurrent);
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "traceparent: " ++ sample ++ "\r\ntracestate: \r\n" ++
            "Connection: close\r\n\r\n", &buf);
        try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "tracestate"));
    }
    // Longer than max_state_len (512): dropped, at the exact boundary + 1.
    {
        var tc = TraceContext{};
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(tc.middleware());
        try r.get("/", hEchoCurrent);

        var req_buf: [4096]u8 = undefined;
        const too_long = "k1=" ++ strRepeat("a", 254) ++ ",k2=" ++ strRepeat("b", 252); // 513
        comptime std.debug.assert(too_long.len == max_state_len + 1);
        const req = try std.mem.print(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "traceparent: " ++ sample ++ "\r\ntracestate: {s}\r\n" ++
            "Connection: close\r\n\r\n", .{too_long});
        var buf: [2048]u8 = undefined;
        const got = runWire(&r, req, &buf);
        try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "tracestate"));
    }
    // A control character (below 0x20): dropped.
    {
        var tc = TraceContext{};
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(tc.middleware());
        try r.get("/", hEchoCurrent);
        var buf: [1024]u8 = undefined;
        const got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "traceparent: " ++ sample ++ "\r\ntracestate: rojo=\x01bad\r\n" ++
            "Connection: close\r\n\r\n", &buf);
        try testing.expectEqual(@as(?[]const u8, null), headerValue(got, "tracestate"));
    }
    // Exactly at the boundary (max_state_len): kept. Two members of 256
    // and 255 characters plus their comma = 512.
    {
        var tc = TraceContext{};
        var r = router.Router.init(testing.allocator);
        defer r.deinit();
        try r.use(tc.middleware());
        try r.get("/", hEchoCurrent);

        var req_buf: [4096]u8 = undefined;
        const at_boundary = "k1=" ++ strRepeat("a", 253) ++ ",k2=" ++ strRepeat("b", 252);
        comptime std.debug.assert(at_boundary.len == max_state_len);
        const req = try std.mem.print(&req_buf, "GET / HTTP/1.1\r\nHost: t\r\n" ++
            "traceparent: " ++ sample ++ "\r\ntracestate: {s}\r\n" ++
            "Connection: close\r\n\r\n", .{at_boundary});
        var buf: [2048]u8 = undefined;
        const got = runWire(&r, req, &buf);
        try testing.expectEqualStrings(at_boundary, headerValue(got, "tracestate").?);
    }
}

test "parse / write round-trip" {
    const tp = try TraceParent.parse(sample);
    try testing.expect(tp.sampled());
    var b: [TraceParent.header_len]u8 = undefined;
    try testing.expectEqualStrings(sample, tp.write(&b));
}

test "a future traceparent version is parsed as its Level 1 prefix" {
    // W3C §3.2.2.3: an unknown *higher* version keeps the version-traceid-
    // parentid-flags prefix and may append `-<extra>`. Rejecting it would
    // restart the trace and break the very forward compatibility the field
    // exists for. We re-emit as `00` because that is all we understand.
    const future = "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
    const tp = try TraceParent.parse(future);
    try testing.expect(tp.sampled());
    var b: [TraceParent.header_len]u8 = undefined;
    try testing.expectEqualStrings(sample, tp.write(&b));

    // Same, with a future field appended after the Level 1 prefix.
    const extended = future ++ "-somethingnew";
    const tp2 = try TraceParent.parse(extended);
    try testing.expectEqualStrings(sample, tp2.write(&b));

    // The Level 1 validity rules still apply to the prefix of a future version.
    try testing.expectError(
        TraceParent.ParseError.ZeroTraceId,
        TraceParent.parse("cc-00000000000000000000000000000000-00f067aa0ba902b7-01"),
    );
}

test "invalid traceparents are rejected" {
    const E = TraceParent.ParseError;
    // Wrong length.
    try testing.expectError(E.BadLength, TraceParent.parse("00-abcd"));
    // Version `ff` is reserved as invalid (W3C §3.2.2.3).
    try testing.expectError(
        E.BadVersion,
        TraceParent.parse("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    // A version that is not lowercase hex at all.
    try testing.expectError(
        E.BadVersion,
        TraceParent.parse("0X-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    // Version `00` is exactly 55 chars: trailing bytes are malformed, not an
    // extension — only a *higher* version may carry one.
    try testing.expectError(
        E.BadLength,
        TraceParent.parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-xyz"),
    );
    // A future version whose 56th char is not `-` cannot be trusted to keep
    // the Level 1 prefix.
    try testing.expectError(
        E.BadFormat,
        TraceParent.parse("01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01x"),
    );
    // Misplaced delimiter.
    try testing.expectError(
        E.BadFormat,
        TraceParent.parse("00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"),
    );
    // Uppercase hex (spec mandates lowercase).
    try testing.expectError(
        E.BadHex,
        TraceParent.parse("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"),
    );
    // All-zero trace-id.
    try testing.expectError(
        E.ZeroTraceId,
        TraceParent.parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01"),
    );
    // All-zero parent-id.
    try testing.expectError(
        E.ZeroParentId,
        TraceParent.parse("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"),
    );
}

test "TraceState: normalizes, dedupes, put moves left, delete, 32-member cap" {
    var ts = try TraceState.parse(" \tcongo=t61, ,rojo=00f0 \t,congo=old,, ");
    try testing.expectEqual(@as(usize, 2), ts.members().len);
    try testing.expectEqualStrings("t61", ts.get("congo").?); // left one kept
    var buf: [max_state_len]u8 = undefined;
    try testing.expectEqualStrings("congo=t61,rojo=00f0", ts.write(&buf));

    // Update an existing key: it moves to the front.
    try ts.put("rojo", "new");
    try testing.expectEqualStrings("rojo=new,congo=t61", ts.write(&buf));
    try testing.expect(ts.delete("congo"));
    try testing.expect(!ts.delete("congo"));
    try testing.expectEqualStrings("rojo=new", ts.write(&buf));
    try testing.expectError(error.BadMember, ts.put("Bad", "v"));
    try testing.expectError(error.BadMember, ts.put("ok", "trailing "));

    // A full list loses its right-most member when a new key arrives.
    var full: TraceState = .{};
    var keys: [max_members][4]u8 = undefined;
    for (&keys, 0..) |*k, i| {
        _ = std.mem.print(k, "k{d:0>3}", .{i}) catch unreachable;
        try full.put(k, "v");
    }
    try testing.expectEqual(@as(usize, max_members), full.members().len);
    try testing.expectEqualStrings("k000", full.members()[max_members - 1].key);
    try full.put("ours", "1");
    try testing.expectEqual(@as(usize, max_members), full.members().len);
    try testing.expectEqualStrings("ours", full.members()[0].key);
    try testing.expectEqualStrings("k001", full.members()[max_members - 1].key); // k000 dropped

    // 33 members in the input: the whole list is invalid.
    var many: [33 * 6]u8 = undefined;
    var w: std.Io.Writer = .fixed(&many);
    for (0..33) |i| w.print("{s}m{d:0>2}=1", .{ if (i == 0) "" else ",", i }) catch unreachable;
    try testing.expectError(error.TooManyMembers, TraceState.parse(w.buffered()));
    // Grammar: digit-first key and '@' anywhere after the first char are
    // keys; '@'-first, uppercase, '.', empty value, '=' in value are not.
    _ = try TraceState.parse("1a=1,a@b@c=2,v= leading");
    for ([_][]const u8{ "@a=1", "A=1", "a.b=1", "a=", "a=b=c", "a", "=1" }) |bad|
        try testing.expectError(error.BadMember, TraceState.parse(bad));
    try testing.expectEqualStrings(" leading", (try TraceState.parse("v= leading ")).get("v").?);
}

test "TraceState.write truncates whole members: over 128 characters first, then from the right" {
    // Negative control 2026-10-11: dropping the long-members-first pass
    // (right-most first only) failed the first expectation (it keeps the
    // 150-character member and drops `c`, `b`).
    var ts: TraceState = .{};
    const long = strRepeat("x", 150);
    try ts.put("c", "3");
    try ts.put("long", long);
    try ts.put("b", "2");
    try ts.put("a", "1"); // a=1,b=2,long=…,c=3
    var small: [16]u8 = undefined;
    try testing.expectEqualStrings("a=1,b=2,c=3", ts.write(&small));
    var tiny: [7]u8 = undefined;
    try testing.expectEqualStrings("a=1,b=2", ts.write(&tiny));
    var none: [2]u8 = undefined;
    try testing.expectEqualStrings("", ts.write(&none));
}

/// Test `StateEntry`: "<span-id hex>" so the test can see the hop it got.
fn spanValue(_: ?*anyopaque, hop: TraceParent, buf: *[max_value_len]u8) ?[]const u8 {
    return std.mem.print(buf, "{x}", .{&hop.parent_id}) catch unreachable;
}
fn badValue(_: ?*anyopaque, _: TraceParent, _: *[max_value_len]u8) ?[]const u8 {
    return "bad,value";
}

test "state_entry: our member goes first, replaces our old one, starts a new trace's list" {
    var tc = TraceContext{ .options = .{ .state_entry = .{ .key = "zl", .value = spanValue } } };
    var r = router.Router.init(testing.allocator);
    defer r.deinit();
    try r.use(tc.middleware());
    try r.get("/", hEchoCurrent);

    var buf: [1024]u8 = undefined;
    var got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "traceparent: " ++ sample ++ "\r\ntracestate: rojo=1,zl=stale,congo=2\r\n" ++
        "Connection: close\r\n\r\n", &buf);
    const tp = try TraceParent.parse(headerValue(got, "traceparent").?);
    var want: [64]u8 = undefined;
    try testing.expectEqualStrings(
        try std.mem.print(&want, "zl={x},rojo=1,congo=2", .{&tp.parent_id}),
        headerValue(got, "tracestate").?,
    );

    // A new trace (no incoming traceparent) carries only our member; an
    // incoming tracestate without a traceparent is still ignored.
    got = runWire(&r, "GET / HTTP/1.1\r\nHost: t\r\ntracestate: rojo=1\r\nConnection: close\r\n\r\n", &buf);
    const tp2 = try TraceParent.parse(headerValue(got, "traceparent").?);
    try testing.expectEqualStrings(
        try std.mem.print(&want, "zl={x}", .{&tp2.parent_id}),
        headerValue(got, "tracestate").?,
    );

    // A value breaking the grammar is not added; the carried list stays.
    var tc_bad = TraceContext{ .options = .{ .state_entry = .{ .key = "zl", .value = badValue } } };
    var r2 = router.Router.init(testing.allocator);
    defer r2.deinit();
    try r2.use(tc_bad.middleware());
    try r2.get("/", hEchoCurrent);
    got = runWire(&r2, "GET / HTTP/1.1\r\nHost: t\r\n" ++
        "traceparent: " ++ sample ++ "\r\ntracestate: rojo=1\r\nConnection: close\r\n\r\n", &buf);
    try testing.expectEqualStrings("rojo=1", headerValue(got, "tracestate").?);
}

test "generated ids: no duplicate trace-id or span-id across many threads at once" {
    // Negative control 2026-10-11: a threadlocal sequence instead of the
    // process-wide one failed this (every thread minted the same ids).
    const n_threads = 32;
    const per_thread = 200;
    const T = struct {
        fn run(go: *std.atomic.Value(bool), out: *[per_thread][16]u8, spans: *[per_thread][8]u8) void {
            while (!go.load(.acquire)) std.atomic.spinLoopHint();
            for (out, spans) |*t, *s| {
                t.* = newTraceId();
                s.* = newSpanId();
            }
        }
    };
    const traces = try testing.allocator.alloc([per_thread][16]u8, n_threads);
    defer testing.allocator.free(traces);
    const spans = try testing.allocator.alloc([per_thread][8]u8, n_threads);
    defer testing.allocator.free(spans);
    var go: std.atomic.Value(bool) = .init(false);
    var threads: [n_threads]std.Thread = undefined;
    for (&threads, traces, spans) |*th, *t, *s| th.* = try std.Thread.spawn(.{}, T.run, .{ &go, t, s });
    go.store(true, .release);
    for (threads) |th| th.join();

    var seen_t: std.AutoHashMapUnmanaged([16]u8, void) = .empty;
    defer seen_t.deinit(testing.allocator);
    var seen_s: std.AutoHashMapUnmanaged([8]u8, void) = .empty;
    defer seen_s.deinit(testing.allocator);
    for (traces, spans) |*tt, *ss| for (tt, ss) |t, s| {
        try testing.expect(!isZero(&t) and !isZero(&s));
        if ((try seen_t.getOrPut(testing.allocator, t)).found_existing) return error.DuplicateTraceId;
        if ((try seen_s.getOrPut(testing.allocator, s)).found_existing) return error.DuplicateSpanId;
    };
}

// ── model-fuzz: TraceState.parse/write vs a naive restatement of the grammar ──
//
// The model reads the W3C text with its own logic (explicit character
// strings, no call into `isValidKey`/`isValidValue`).

const model_key_first = "abcdefghijklmnopqrstuvwxyz0123456789";
const model_key_rest = model_key_first ++ "_-*/@";

fn modelKeyOk(k: []const u8) bool {
    if (k.len < 1 or k.len > 256) return false;
    if (std.mem.findScalar(u8, model_key_first, k[0]) == null) return false;
    for (k) |c| if (std.mem.findScalar(u8, model_key_rest, c) == null) return false;
    return true;
}

fn modelValueOk(v: []const u8) bool {
    if (v.len < 1 or v.len > 256) return false;
    if (v[v.len - 1] == ' ') return false;
    for (v) |c| if (c < 0x20 or c > 0x7e or c == ',' or c == '=') return false;
    return true;
}

test "model-fuzz: TraceState.parse matches the grammar model; write/parse round-trips" {
    const seed: u64 = 0x7472616365737431;
    var prng = std.Random.DefaultPrng.init(seed);
    const rnd = prng.random();
    const pieces = [_][]const u8{ "a", "z9", "k_-*/", "t@s", "1x", "@x", "A", "a.b", "", "foo", strRepeat("x", 255), strRepeat("y", 256) };
    const vals = [_][]const u8{ "1", " lead", "v ", "", "a=b", "a,b", "~!#", "\x7f", "\t", strRepeat("z", 256), strRepeat("w", 257) };
    var reach_ok: usize = 0;
    var reach_bad: usize = 0;
    var reach_dup: usize = 0;
    var reach_many: usize = 0;
    var reach_empty_member: usize = 0;
    var buf: [16384]u8 = undefined;
    var step: usize = 0;
    while (step < 3000) : (step += 1) {
        // A list of 0..34 members, OWS and empty members sprinkled in; mostly
        // valid parts so the valid path gets real lists.
        var w: std.Io.Writer = .fixed(&buf);
        const n = rnd.uintLessThan(usize, if (rnd.uintLessThan(u8, 8) == 0) 36 else 8);
        var want_valid = true;
        var want_count: usize = 0;
        var keys_seen: [40][]const u8 = undefined;
        var key_store: [40][300]u8 = undefined;
        var n_keys: usize = 0;
        var dup = false;
        for (0..n) |i| {
            if (i != 0) w.writeAll(if (rnd.boolean()) "," else " \t,\t") catch unreachable;
            if (rnd.uintLessThan(u8, 10) == 0) { // empty member
                reach_empty_member += 1;
                continue;
            }
            const clean = rnd.uintLessThan(u8, 6) != 0;
            const k = if (clean) pieces[rnd.uintLessThan(usize, 5)] else pieces[rnd.uintLessThan(usize, pieces.len)];
            const v = if (clean) vals[rnd.uintLessThan(usize, 3)] else vals[rnd.uintLessThan(usize, vals.len)];
            // Make clean keys distinct most of the time. Each member gets
            // its own key storage: `keys_seen` keeps slices of it.
            const kb = &key_store[i];
            const key = if (clean and rnd.uintLessThan(u8, 5) != 0)
                std.mem.print(kb, "{s}{d}", .{ k, i }) catch unreachable
            else
                k;
            w.print("{s}={s}", .{ key, v }) catch unreachable;
            // OWS trimming makes a trailing space of the LAST piece of a
            // member optional whitespace, not part of the value.
            const v_eff = std.mem.trimEnd(u8, v, " \t");
            if (!modelKeyOk(key) or !modelValueOk(v_eff)) want_valid = false;
            want_count += 1;
            var is_dup = false;
            for (keys_seen[0..n_keys]) |s| if (std.mem.eql(u8, s, key)) {
                is_dup = true;
            };
            if (is_dup) dup = true else if (n_keys < keys_seen.len) {
                keys_seen[n_keys] = key;
                n_keys += 1;
            }
        }
        if (want_count > 32) want_valid = false;
        const input = w.buffered();
        errdefer std.debug.print("tracestate model-fuzz mismatch: seed=0x{x} step={d} input={f}\n", .{ seed, step, std.zig.fmtString(input) });
        if (TraceState.parse(input)) |ts| {
            try testing.expect(want_valid);
            try testing.expectEqual(n_keys, ts.members().len);
            // Round trip: what we write parses back to the same members.
            var out: [16384]u8 = undefined;
            const again = try TraceState.parse(ts.write(&out));
            try testing.expectEqual(ts.members().len, again.members().len);
            for (ts.members(), again.members()) |a, b| {
                try testing.expectEqualStrings(a.key, b.key);
                try testing.expectEqualStrings(a.value, b.value);
            }
            reach_ok += 1;
            if (dup) reach_dup += 1;
        } else |_| {
            try testing.expect(!want_valid);
            reach_bad += 1;
            if (want_count > 32) reach_many += 1;
        }
    }
    try testing.expect(reach_ok > 0 and reach_bad > 0 and reach_dup > 0 and reach_many > 0 and reach_empty_member > 0);
}

test "childOf keeps the trace and generated ids are unique / non-zero" {
    const parent = try TraceParent.parse(sample);
    const span = newSpanId();
    const child = childOf(parent, span);
    try testing.expectEqualSlices(u8, &parent.trace_id, &child.trace_id);
    try testing.expectEqualSlices(u8, &span, &child.parent_id);
    try testing.expectEqual(parent.flags, child.flags);
    // Unknown flag bits are accepted on the way in, zeroed on the way out.
    const odd = try TraceParent.parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-ff");
    try testing.expectEqual(@as(u8, 0xff), odd.flags);
    try testing.expectEqual(flag_sampled, childOf(odd, span).flags);
    const unsampled = try TraceParent.parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-fe");
    try testing.expectEqual(@as(u8, 0), childOf(unsampled, span).flags);

    // Successive generated ids differ and are never the invalid all-zero id.
    const a = newTraceId();
    const b = newTraceId();
    try testing.expect(!std.mem.eql(u8, &a, &b));
    try testing.expect(!isZero(&a));
    try testing.expect(!isZero(&newSpanId()));
}

/// The handler half of the dead-frame test below: format the outgoing
/// traceparent into a buffer that dies with THIS frame — exactly what
/// `middlewareRun`'s echo block does — and hand it to `setHeader`. Mirrors
/// `http`'s and `cookies`' own `setFromDeadFrame`.
///
/// A separate `noinline` function, not a block inside the test: Zig gives
/// each local its own slot for the enclosing function's entire body in
/// Debug, so a block scope frees nothing and the bug this guards would stay
/// invisible. Only a returned frame is really reusable.
noinline fn setFromDeadFrame(res: *http.Server.ResponseWriter) !void {
    var out_buf: [TraceParent.header_len]u8 = undefined;
    const tp = try TraceParent.parse(sample);
    try res.setHeader(default_traceparent_header, tp.write(&out_buf));
}

/// Reuse the frame `setFromDeadFrame` just left, the way the next call down
/// the stack would have. `noinline` + `doNotOptimizeAway` so neither the
/// call nor the stores can be optimized out.
noinline fn clobberDeadFrame() void {
    var scratch: [2048]u8 = undefined;
    @memset(&scratch, '#');
    std.mem.doNotOptimizeAway(&scratch);
}

test "TraceContext echo: traceparent header survives the caller's dead frame" {
    // What this pins: `middlewareRun`'s echo block formats the outgoing
    // traceparent into `out_buf`, a plain local that dies once
    // `middlewareRun` returns -- well before `end()` runs (`writeHead` runs
    // inside `end()`, which both servers call only after the whole handler
    // chain has returned). `out_buf` was `threadlocal` until 2026-08-12
    // specifically so it would outlive the response regardless of copying;
    // now that it is a plain local (see the module doc's "Memory /
    // concurrency" section), this module leans entirely on `http`'s
    // `ResponseWriter.dupe` copying header bytes into its own storage rather
    // than borrowing the caller's.
    //
    // Nothing else in this module's suite pins that on purpose -- `runWire`
    // drives `middlewareRun` through the full router/server dispatch with no
    // seam between the echo block returning and `end()` running in which to
    // clobber the stack deliberately (a mutation removing the copy can
    // *happen* to corrupt the header there today by accident, depending on
    // what the dispatch path's own stack traffic leaves behind, but that is
    // not a reliable anchor). So the writer is built and driven by hand
    // here, mirroring `http`'s and `cookies`' own dead-frame tests.
    var out_buf: [512]u8 = undefined;
    var out: Writer = .fixed(&out_buf);
    var body_buf: [64]u8 = undefined;
    var chunk_buf: [32]u8 = undefined;
    var rw: http.Server.ResponseWriter = .init(&out, &body_buf, &chunk_buf, .{});

    try setFromDeadFrame(&rw);
    clobberDeadFrame();

    try rw.writeAll("ok");
    try rw.end();
    const wire = out.buffered();

    // The traceparent header, read back off the wire after every byte of its
    // source was overwritten.
    try testing.expect(std.mem.find(u8, wire, "traceparent: " ++ sample ++ "\r\n") != null);
    // …and not one byte of the clobber pattern anywhere on it.
    try testing.expect(std.mem.find(u8, wire, "#") == null);
}

// See w3c_conformance_test.zig / w3c_vectors.zig / NOTICE.
test {
    _ = @import("fuzz_test.zig");
    _ = @import("w3c_vectors.zig");
    _ = @import("w3c_conformance_test.zig");
    _ = @import("otel_oracle_test.zig");
}

// ── fuzz: TraceParent.parse never panics on arbitrary or shaped bytes ──────
//
// `TraceParent.parse` is the decode entry point for a `traceparent` header —
// attacker-controlled bytes off the wire. It is allocation-free (the result
// is a fixed-size value), so there is no leak oracle to run here; the
// property under test is "never panics or reads out of bounds" across pure
// garbage, plus input shaped like `version-traceid-parentid-flags` with each
// field's length, hex-ness and delimiter independently perturbed — arbitrary
// bytes essentially never land on `header_len` (55) with dashes in the right
// three places, so without shaping this harness would only ever exercise the
// very first length check.
const fuzzseed = @import("testkit").fuzz;

/// ⛔ The corpus this replaces held five real `traceparent` header strings as
/// RAW text, and not one of them reached `TraceParent.parse`.
/// `buildTraceparent` opened with `smith.valueRangeAtMost(u8, 0, 7)`, which
/// reads EIGHT octets as a little-endian `u64` and returns the range MINIMUM
/// unless that whole word already lies in 0..7 — `"00-4bf92"` is nowhere near,
/// so every seed took the "pure arbitrary bytes" branch, `smith.bytes(&raw)`
/// ate the rest of the header, and the ranged length after it found nothing
/// left and returned 0. **All five headers arrived at the parser as the empty
/// string.** Measured 2026-09-07: 0 of 5 seeds carried an octet and 0 parsed.
///
/// The seeds are now scripts. Octet 0 selects: `0x00` means "the rest of this
/// seed IS the header, verbatim" — which is what lets a real W3C example be a
/// seed at all — and anything else means "the rest is a script that assembles
/// `version-traceid-parentid-flags` field by field".
const traceparent_corpus = [_][]const u8{
    fuzzseed.seed("\x00" ++ sample), // ⭐ the W3C example header
    fuzzseed.seed("\x00" ++ "00-00000000000000000000000000000000-00f067aa0ba902b7-01"), // all-zero trace-id
    fuzzseed.seed("\x00" ++ "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"), // all-zero parent-id
    fuzzseed.seed("\x00" ++ "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"), // the reserved version
    fuzzseed.seed("\x00" ++ "cc-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-somethingnew"), // a future version's extension
    fuzzseed.seed("\x00" ++ "00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01"), // ⭐ UPPERCASE hex, which the spec forbids
    fuzzseed.seed("\x00" ++ "00_4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"), // an underscore where the first dash belongs
    fuzzseed.seed("\x00" ++ "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-0"), // one octet short of `header_len`
    fuzzseed.seed("\x00" ++ "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-011"), // one octet over
    fuzzseed.seed("\x00"), // the empty header
    fuzzseed.seed("\x00" ++ "\xff\x00\x7f-\r\n"), // bytes no header could contain
    // Script seeds (fuzz_test.zig `buildTraceparent`; a short script CYCLES):
    // per field one fault octet (mod 16: 0 short, 1 long, 2 uppercase, 3
    // arbitrary octet, else clean), a position octet, then one octet per digit.
    fuzzseed.seed("\x01" ++ "\x04"), // script: every field clean, `-` delimiters, version "44" (accepted)
    fuzzseed.seed("\x01" ++ "\x00"), // script: every field one octet SHORT, `_` delimiters
    fuzzseed.seed("\x01" ++ "\x01"), // script: every field one octet LONG, plus an extension
    fuzzseed.seed("\x01" ++ "\x02\x00\x0b"), // script: an uppercase digit in a field
    fuzzseed.seed("\x01" ++ "\x03\x00\xff"), // script: an arbitrary octet in a field
};

test "fuzz: TraceParent.parse never panics, arbitrary or traceparent-shaped bytes" {
    try std.testing.fuzz({}, fuzzParseNeverPanics, .{ .corpus = &traceparent_corpus });
}

/// The header buffer, plus one octet of mode. `header_len` is 55 and the
/// longest seed here is the extension one at 68, so 128 is not tight.
const traceparent_buf_len = 128;

fn fuzzParseNeverPanics(_: void, smith: *std.testing.Smith) !void {
    var raw: [1 + traceparent_buf_len]u8 = undefined;
    // ⚠ ONE byte-first draw. See `traceparent_corpus` for what the ranged
    // draws did to a corpus of real headers.
    const n: usize = smith.slice(&raw);
    var src: fz.ScriptSource = .{ .cur = .{ .bytes = raw[0..n] } };
    try fz.parseHarness(fz.ScriptSource, &src, testing.allocator);
}

const fz = @import("fuzz_test.zig");

const buildTraceparent = fz.buildTraceparent;

test "corpus: every traceparent seed reaches the parser, and what it accepts is pinned" {
    // ⭐ Pinning the accepted count alone would be a weak guard on a decoder
    // whose refusals are most of its behaviour, so the second number is the
    // total octets HANDED to the parser: a corpus that stops assembling
    // headers — which is exactly what the ranged draws did to the old one —
    // shows up there long before it shows up in the accepted count.
    var nonempty: usize = 0;
    var octets: usize = 0;
    var accepted: usize = 0;
    var sampled: usize = 0;
    for (traceparent_corpus) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var raw: [1 + traceparent_buf_len]u8 = undefined;
        const n: usize = smith.slice(&raw);
        var buf: [traceparent_buf_len]u8 = undefined;
        const input = buildTraceparent(raw[0..n], &buf);
        if (input.len != 0) nonempty += 1;
        octets += input.len;
        const tp = TraceParent.parse(input) catch continue;
        accepted += 1;
        if (tp.sampled()) sampled += 1;
    }
    // One seed is deliberately the empty header.
    try testing.expectEqual(traceparent_corpus.len - 1, nonempty);
    // Measured 2026-09-07. The corpus this replaces handed the parser 0
    // octets and got 0 headers parsed, from five real W3C header strings.
    try testing.expectEqual(@as(usize, 791), octets);
    try testing.expectEqual(@as(usize, 3), accepted);
    try testing.expectEqual(@as(usize, 2), sampled);
}

/// Comptime string repetition; replaces the `**` operator removed in Zig 0.17.
inline fn strRepeat(comptime s: []const u8, comptime n: usize) *const [s.len * n:0]u8 {
    // One @splat + @bitCast, not a loop: a comptime loop writing into an
    // array var costs O(n^2) in Sema (40 000 bytes: 8.7 s; http's test
    // binary spent ~5 min in Sema on these, 2026-10-24).
    const rep_result = comptime blk: {
        const unit: [s.len]u8 = s[0..s.len].*;
        const grid: [n][s.len]u8 = @splat(unit);
        const flat: [s.len * n]u8 = @bitCast(grid);
        break :blk (flat ++ [_:0]u8{})[0 .. s.len * n :0].*;
    };
    return &rep_result;
}
