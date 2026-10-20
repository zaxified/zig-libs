// SPDX-License-Identifier: MIT

//! Deterministic fuzz driver for tlsserver (added 2026-10-20):
//! `TLSSERVER_FUZZ=<runs>[,<first seed>]` (testkit's driver), harnesses
//! `tlsserver-record` and `tlsserver-inbound` (the latter is described at
//! its section below). `tlsserver-record`: for a random suite and traffic secret, a sealed record
//! (random content length, inner type and padding) opens back to the same
//! content and type; the same record damaged — a flipped bit anywhere, the
//! header's length or type octets aimed at, truncation, extension, random
//! bytes in place of the ciphertext — or opened under another sequence number
//! is refused, never accepted unless identical, never a panic; a refused
//! record never advances the sequence number.
//! `tlsserver-keys` (`keys.CertKeyPair.fromPem`), `tlsserver-server`
//! (`Server` on recorded real clients) and `tlsserver-keyupdate` (KeyUpdate
//! against a model client) are described at their sections.

const std = @import("std");
const testing = std.testing;
const testkit = @import("testkit");
const fuzz_driver = testkit.fuzz.driver;
const ScriptSource = testkit.fuzz.ScriptSource;

const record = @import("record.zig");

/// Reach counters for one harness's labels (copied from `tls13`'s
/// fuzz_test). `mark` also feeds the driver's `REACH` report; `reach` runs
/// `seeds` seeds in the ordinary test binary and fails with
/// `error.HarnessDoesNotReach` if a label never fired.
fn Marker(comptime Label: type) type {
    return struct {
        var counts: [@typeInfo(Label).@"enum".field_names.len]usize = @splat(0);

        fn mark(comptime l: Label) void {
            counts[@backingInt(l)] += 1;
            fuzz_driver.hit(@tagName(l));
        }

        fn reach(comptime harness: anytype, comptime name: []const u8, seeds: usize) !void {
            counts = @splat(0);
            for (0..seeds) |seed| {
                var prng = std.Random.DefaultPrng.init(seed);
                var rng: fuzz_driver.Rng = .{ .r = prng.random() };
                harness(fuzz_driver.Rng, &rng, testing.allocator) catch |err| {
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

const Mark = Marker(enum {
    aes128,
    aes256,
    chacha,
    genuine,
    padded,
    empty_content,
    flipped_refused,
    header_refused,
    resized_refused,
    garbage_refused,
    wrong_seq_refused,
});

const max_content = 1200; // keeps runs fast; the 2^14 bound is a unit test

fn fuzzRecord(comptime S: type, src: *S, _: std.mem.Allocator) anyerror!void {
    const suites = [_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 };
    const suite = suites[src.index(suites.len)];
    switch (suite) {
        .aes_128_gcm_sha256 => Mark.mark(.aes128),
        .aes_256_gcm_sha384 => Mark.mark(.aes256),
        else => Mark.mark(.chacha),
    }
    var secret: [48]u8 = undefined;
    src.bytes(&secret);
    const secret_len = suite.hashLen().?;

    var tx: record.Protection = undefined;
    try tx.init(suite, secret[0..secret_len]);
    tx.seq = src.value(u8); // a few distinct nonces per key
    const seq0 = tx.seq;

    // One run in eight at the short edge (0..3 octets: an empty record is
    // legal and has the least to authenticate).
    const content_len = if (src.valueRangeAtMost(u8, 0, 7) == 0) src.valueRangeAtMost(u16, 0, 3) else src.valueRangeAtMost(u16, 0, max_content);
    const pad = if (src.valueRangeAtMost(u8, 0, 3) == 0) src.valueRangeAtMost(u16, 1, 300) else 0;
    const types = [_]record.ContentType{ .handshake, .application_data, .alert };
    const ctype = types[src.index(types.len)];
    var content: [max_content]u8 = undefined;
    src.bytes(content[0..content_len]);

    var buf: [record.header_len + max_content + 1 + 300 + record.tag_len + 16]u8 = undefined;
    @memcpy(buf[record.header_len..][0..content_len], content[0..content_len]);
    const rec_len = (try tx.seal(&buf, content_len, ctype, pad)).len;
    var genuine: [buf.len]u8 = undefined;
    @memcpy(genuine[0..rec_len], buf[0..rec_len]);

    // Genuine: opens to the same content and type.
    {
        var rx: record.Protection = undefined;
        try rx.init(suite, secret[0..secret_len]);
        rx.seq = seq0;
        var in = genuine;
        const o = try rx.open(in[0..rec_len]);
        if (o.content_type != ctype) return error.WrongContentType;
        if (!std.mem.eql(u8, o.content, content[0..content_len])) return error.WrongContent;
        if (rx.seq != seq0 + 1) return error.SequenceNotAdvanced;
        Mark.mark(.genuine);
        if (pad != 0) Mark.mark(.padded);
        if (content_len == 0) Mark.mark(.empty_content);
    }

    // Damaged copies: refused unless the damage left the bytes identical.
    var in: [buf.len + 8]u8 = undefined;
    var n: usize = rec_len;
    @memcpy(in[0..rec_len], genuine[0..rec_len]);
    const kind = src.valueRangeAtMost(u8, 0, 4);
    switch (kind) {
        0 => in[src.index(rec_len)] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7)),
        1 => {
            // The header: type, version or length octets.
            in[src.index(record.header_len)] = src.value(u8);
        },
        2 => {
            const new_n = src.valueRangeAtMost(u16, 0, @intCast(rec_len + 8));
            if (new_n > n) src.bytes(in[n..new_n]);
            n = new_n;
        },
        3 => src.bytes(in[record.header_len..rec_len]),
        else => {}, // sequence number below
    }
    var rx: record.Protection = undefined;
    try rx.init(suite, secret[0..secret_len]);
    rx.seq = if (kind == 4) seq0 +% (1 + @as(u64, src.value(u8))) else seq0;
    const seq_before = rx.seq;
    // Decided before `open`, which decrypts `in` in place.
    const identical = kind != 4 and n == rec_len and std.mem.eql(u8, in[0..n], genuine[0..rec_len]);
    if (rx.open(in[0..n])) |_| {
        // Damage that rewrote a byte with its own value is no damage.
        if (!identical) return error.DamagedRecordAccepted;
    } else |_| {
        if (rx.seq != seq_before) return error.SequenceAdvancedOnFailure;
        switch (kind) {
            0 => Mark.mark(.flipped_refused),
            1 => Mark.mark(.header_refused),
            2 => Mark.mark(.resized_refused),
            3 => Mark.mark(.garbage_refused),
            else => Mark.mark(.wrong_seq_refused),
        }
    }
}

fn fuzzRecordSmith(_: void, smith: *std.testing.Smith) anyerror!void {
    var script: [2048]u8 = undefined;
    var src: ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzRecord(ScriptSource, &src, testing.allocator);
}

test "fuzz: tlsserver record, genuine opens / damaged refused" {
    try testing.fuzz({}, fuzzRecordSmith, .{});
}
test "fuzz driver: TLSSERVER_FUZZ (record)" {
    try fuzz_driver.run(fuzzRecord, .{ .prefix = "TLSSERVER_FUZZ", .name = "tlsserver-record" });
}
test "fuzz harness: record, 300 seeds, reaches every outcome" {
    try Mark.reach(fuzzRecord, "tlsserver-record", 300);
}

// ── tlsserver-inbound ────────────────────────────────────────────────────
//
// A stream of 1..4 handshake messages (bodies up to 20,000 octets, so some
// span records) cut into records at random points — plaintext, or protected
// under a random suite with application data and a close_notify after the
// handshake data — with compatibility CCS records at message boundaries,
// fed to `Inbound.next` in random chunk sizes. The events must give back
// exactly the messages and the application data, whatever the cut and the
// chunking. The same stream damaged (a flipped bit, a header octet
// rewritten, truncated, random octets spliced in) never panics, and a
// damaged protected stream is never accepted with the genuine output.

const inbound = @import("inbound.zig");

const InMark = Marker(enum {
    plaintext,
    protected,
    multi_record_message,
    multi_message_record,
    full_record,
    compat_ccs,
    app_data,
    closed,
    genuine,
    damaged_refused,
    damaged_plain_accepted,
});

const max_body = 20_000;
const max_msgs = 4;

const Output = struct {
    msgs: [max_msgs]struct { t: u8, body: []u8 } = undefined,
    n_msgs: usize = 0,
    app: std.ArrayList(u8) = .empty,
    closed: bool = false,

    fn deinit(o: *Output, gpa: std.mem.Allocator) void {
        for (o.msgs[0..o.n_msgs]) |m| gpa.free(m.body);
        o.app.deinit(gpa);
    }

    fn eql(a: *const Output, b: *const Output) bool {
        if (a.n_msgs != b.n_msgs or a.closed != b.closed) return false;
        for (a.msgs[0..a.n_msgs], b.msgs[0..b.n_msgs]) |x, y| {
            if (x.t != y.t or !std.mem.eql(u8, x.body, y.body)) return false;
        }
        return std.mem.eql(u8, a.app.items, b.app.items);
    }
};

/// Feed `stream` in chunks drawn from `src`; collect what comes out. An
/// `Inbound` error ends the feed and is returned.
fn feed(comptime S: type, src: *S, gpa: std.mem.Allocator, in: *inbound.Inbound, stream: []u8, out: *Output) !void {
    var off: usize = 0;
    var fed: usize = 0;
    var guard: usize = 0;
    while (true) : (guard += 1) {
        if (guard > 1_000_000) return error.FeedDoesNotProgress;
        const r = try in.next(stream[off..fed]);
        if (r.consumed > fed - off) return error.ConsumedTooMuch;
        switch (r.event) {
            .need_more => {
                off += r.consumed;
                if (fed == stream.len) return;
                const step: usize = if (src.valueRangeAtMost(u8, 0, 3) == 0) src.valueRangeAtMost(u16, 1, 8) else src.valueRangeAtMost(u16, 1, 20_000);
                fed = @min(stream.len, fed + step);
            },
            .handshake => |m| {
                if (out.n_msgs == max_msgs) return error.TooManyMessages;
                out.msgs[out.n_msgs] = .{ .t = m.msg_type, .body = try gpa.dupe(u8, m.body) };
                out.n_msgs += 1;
                off += r.consumed;
            },
            .app_data => |d| {
                try out.app.appendSlice(gpa, d);
                off += r.consumed;
            },
            .peer_closed => {
                out.closed = true;
                return;
            },
        }
    }
}

fn fuzzInbound(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const protected = src.valueRangeAtMost(u8, 0, 1) == 1;
    const suites = [_]record.CipherSuite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256 };
    const suite = suites[src.index(suites.len)];
    var secret: [48]u8 = undefined;
    src.bytes(&secret);
    const secret_len = suite.hashLen().?;
    if (protected) InMark.mark(.protected) else InMark.mark(.plaintext);

    // The expected output and the handshake octets.
    var want: Output = .{};
    defer want.deinit(gpa);
    var hs: std.ArrayList(u8) = .empty;
    defer hs.deinit(gpa);
    var boundaries: [max_msgs]usize = undefined;
    const n_msgs = src.valueRangeAtMost(u8, 1, max_msgs);
    for (0..n_msgs) |i| {
        const len: usize = switch (src.valueRangeAtMost(u8, 0, 7)) {
            0 => src.valueRangeAtMost(u16, 0, 3),
            1 => src.valueRangeAtMost(u16, 16_000, max_body),
            else => src.valueRangeAtMost(u16, 0, 600),
        };
        const t = src.value(u8);
        const body = try gpa.alloc(u8, len);
        src.bytes(body);
        want.msgs[i] = .{ .t = t, .body = body };
        want.n_msgs += 1;
        var h: [4]u8 = .{ t, 0, 0, 0 };
        std.mem.writeInt(u24, h[1..4], @intCast(len), .big);
        try hs.appendSlice(gpa, &h);
        try hs.appendSlice(gpa, body);
        boundaries[i] = hs.items.len;
    }

    // With application data the engine has seen the client's Finished: no
    // compatibility CCS any more.
    const app_ok = protected and src.valueRangeAtMost(u8, 0, 1) == 1;

    // Cut into records; a CCS may follow a cut that is a message boundary.
    var tx: record.Protection = undefined;
    if (protected) try tx.init(suite, secret[0..secret_len]);
    defer if (protected) tx.wipe();
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(gpa);
    // [start, end) of every protected record: damage elsewhere (a plaintext
    // CCS, octets after the last record) may legitimately go unnoticed.
    var sealed: std.ArrayList(struct { start: usize, end: usize, output: bool }) = .empty;
    defer sealed.deinit(gpa);
    // The end of the last protected record whose loss changes the output
    // (an empty application data record does not).
    var last_output_end: usize = 0;
    var scratch: [record.max_record_len]u8 = undefined;
    var at: usize = 0;
    var ccs_sent: usize = 0;
    var records_for_msg: usize = 0;
    var msgs_in_record = false;
    while (at < hs.items.len) {
        const left = hs.items.len - at;
        const cap = @min(left, record.max_plaintext_len);
        // Short cuts, whole records (the 2^14 edge: a protected one is then
        // longer than any plaintext record may be), or anything between.
        const n: usize = switch (src.valueRangeAtMost(u8, 0, 7)) {
            0, 1 => src.valueRangeAtMost(u16, 1, @intCast(@min(cap, 16))),
            2 => cap,
            else => src.valueRangeAtMost(u16, 1, @intCast(cap)),
        };
        if (n == record.max_plaintext_len) InMark.mark(.full_record);
        const frag = hs.items[at..][0..n];
        var crossed: usize = 0;
        for (boundaries[0..n_msgs]) |b| {
            if (b > at and b < at + n) crossed += 1;
        }
        if (crossed > 0) msgs_in_record = true;
        records_for_msg += 1;
        if (records_for_msg > 1) InMark.mark(.multi_record_message);
        if (protected) {
            @memcpy(scratch[record.header_len..][0..n], frag);
            const r0 = stream.items.len;
            try stream.appendSlice(gpa, try tx.seal(&scratch, n, .handshake, 0));
            try sealed.append(gpa, .{ .start = r0, .end = stream.items.len, .output = true });
            last_output_end = stream.items.len;
        } else {
            var h: [record.header_len]u8 = undefined;
            record.writeHeader(&h, .handshake, @intCast(n));
            try stream.appendSlice(gpa, &h);
            try stream.appendSlice(gpa, frag);
        }
        at += n;
        if (std.mem.indexOfScalar(usize, boundaries[0..n_msgs], at) != null) {
            records_for_msg = 0;
            if (!app_ok and ccs_sent < inbound.max_compat_ccs and src.valueRangeAtMost(u8, 0, 3) == 0) {
                try stream.appendSlice(gpa, &.{ 20, 3, 3, 0, 1, 1 });
                ccs_sent += 1;
                InMark.mark(.compat_ccs);
            }
        }
    }
    if (msgs_in_record) InMark.mark(.multi_message_record);

    // After the handshake data: application data and close_notify.
    if (app_ok) {
        for (0..src.valueRangeAtMost(u8, 0, 3)) |_| {
            const n = src.valueRangeAtMost(u16, 0, 300);
            src.bytes(scratch[record.header_len..][0..n]);
            try want.app.appendSlice(gpa, scratch[record.header_len..][0..n]);
            const r0 = stream.items.len;
            try stream.appendSlice(gpa, try tx.seal(&scratch, n, .application_data, src.valueRangeAtMost(u8, 0, 2)));
            try sealed.append(gpa, .{ .start = r0, .end = stream.items.len, .output = n > 0 });
            if (n > 0) last_output_end = stream.items.len;
            InMark.mark(.app_data);
        }
        if (src.valueRangeAtMost(u8, 0, 1) == 1) {
            @memcpy(scratch[record.header_len..][0..2], &[_]u8{ 1, 0 });
            const r0 = stream.items.len;
            try stream.appendSlice(gpa, try tx.seal(&scratch, 2, .alert, 0));
            try sealed.append(gpa, .{ .start = r0, .end = stream.items.len, .output = true });
            last_output_end = stream.items.len;
            want.closed = true;
            InMark.mark(.closed);
        }
    }

    const joiner_buf = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer gpa.free(joiner_buf);
    const fresh = struct {
        fn make(jb: []u8, p: bool, s: record.CipherSuite, sec: []const u8, ok: bool) !inbound.Inbound {
            var in: inbound.Inbound = .init(jb);
            // The first message plays the ClientHello for CCS purposes.
            in.handshake_seen = true;
            in.app_data_ok = ok;
            // The harness sends up to two (the budget once HRR exists).
            in.ccs_left = inbound.max_compat_ccs;
            if (p) try in.installRx(s, sec);
            return in;
        }
    }.make;

    // Genuine: exactly what was sent.
    {
        const copy = try gpa.dupe(u8, stream.items);
        defer gpa.free(copy);
        var in = try fresh(joiner_buf, protected, suite, secret[0..secret_len], app_ok);
        defer in.wipe();
        var got: Output = .{};
        defer got.deinit(gpa);
        try feed(S, src, gpa, &in, copy, &got);
        if (!got.eql(&want)) return error.GenuineStreamMisread;
        InMark.mark(.genuine);
    }

    // Damaged: never a panic; protected, never the genuine output.
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    try bad.appendSlice(gpa, stream.items);
    switch (src.valueRangeAtMost(u8, 0, 3)) {
        0, 1 => |kind| {
            // A flipped bit anywhere, or a rewritten octet in some record's
            // header (the first, or a protected record's).
            const pos = if (kind == 0 or sealed.items.len == 0)
                src.index(bad.items.len)
            else
                sealed.items[src.index(sealed.items.len)].start + src.index(record.header_len);
            if (kind == 0) bad.items[pos] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7)) else bad.items[pos] = src.value(u8);
        },
        2 => bad.shrinkRetainingCapacity(src.index(bad.items.len)),
        else => {
            var junk: [64]u8 = undefined;
            const jn = src.valueRangeAtMost(u8, 1, 64);
            src.bytes(junk[0..jn]);
            try bad.insertSlice(gpa, src.index(bad.items.len + 1), junk[0..jn]);
        },
    }
    // Where the damage really starts (an inserted octet may equal the one it
    // displaces). It must show if it lands in a protected record that
    // carries output, or shifts the stream ahead of one; damage confined to
    // an empty application data record, a plaintext CCS or the octets after
    // the last output may go unnoticed.
    const first_diff = std.mem.indexOfDiff(u8, bad.items, stream.items) orelse bad.items.len;
    var hits_sealed = bad.items.len != stream.items.len and first_diff < last_output_end;
    for (sealed.items) |sp| hits_sealed = hits_sealed or (sp.output and first_diff >= sp.start and first_diff < sp.end);
    const identical = std.mem.eql(u8, bad.items, stream.items);
    var in = try fresh(joiner_buf, protected, suite, secret[0..secret_len], app_ok);
    defer in.wipe();
    var got: Output = .{};
    defer got.deinit(gpa);
    if (feed(S, src, gpa, &in, bad.items, &got)) |_| {
        if (hits_sealed and !identical and got.eql(&want)) {
            std.debug.print("damage from octet {d} of {d} (now {d}) accepted\n", .{ first_diff, stream.items.len, bad.items.len });
            return error.DamagedProtectedStreamAccepted;
        }
        if (!protected) InMark.mark(.damaged_plain_accepted);
    } else |err| switch (err) {
        error.OutOfMemory, error.FeedDoesNotProgress, error.ConsumedTooMuch => return err,
        else => {
            if (identical) return error.GenuineStreamRefused;
            InMark.mark(.damaged_refused);
        },
    }
}

fn fuzzInboundSmith(_: void, smith: *std.testing.Smith) anyerror!void {
    var script: [4096]u8 = undefined;
    var src: ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzInbound(ScriptSource, &src, testing.allocator);
}

test "fuzz: tlsserver inbound, records → messages whatever the cut" {
    try testing.fuzz({}, fuzzInboundSmith, .{});
}
test "fuzz driver: TLSSERVER_FUZZ (inbound)" {
    try fuzz_driver.run(fuzzInbound, .{ .prefix = "TLSSERVER_FUZZ", .name = "tlsserver-inbound" });
}
test "fuzz harness: inbound, 300 seeds, reaches every outcome" {
    try InMark.reach(fuzzInbound, "tlsserver-inbound", 300);
}

// ── tlsserver-hello ──────────────────────────────────────────────────────
//
// A ClientHello built from a model — the fixed fields, and a random subset
// of the extensions the decoder knows (each with a random well-formed body)
// plus unknown ones, in random order, pre_shared_key last when present —
// decodes to exactly the model: every list walked by its iterator, the SNI
// classification, the binder offset. Planted faults give their error: a
// repeated extension or pre_shared_key not last is IllegalParameter, a
// 33-octet session id DecodeError. The same message damaged (a flipped
// bit, a rewritten octet, truncation, spliced octets) never panics, and
// whatever it decodes to can be walked to the end by every iterator.

const hello = @import("hello.zig");

const HelloMark = Marker(enum {
    sni_dns,
    sni_ip,
    alpn,
    key_shares,
    empty_key_shares,
    psk,
    cookie,
    ocsp,
    unknown_ext,
    no_ext_block,
    duplicate_refused,
    psk_not_last_refused,
    long_session_id_refused,
    damaged_refused,
    damaged_decoded,
});

const Writer = struct {
    buf: []u8,
    n: usize = 0,

    fn bytes(w: *Writer, b: []const u8) void {
        @memcpy(w.buf[w.n..][0..b.len], b);
        w.n += b.len;
    }
    fn int(w: *Writer, comptime T: type, v: T) void {
        std.mem.writeInt(T, w.buf[w.n..][0..@sizeOf(T)], v, .big);
        w.n += @sizeOf(T);
    }
    /// Reserve a length prefix; `close` fills it in.
    fn open(w: *Writer, comptime L: type) usize {
        w.n += @sizeOf(L);
        return w.n;
    }
    fn close(w: *Writer, comptime L: type, at: usize) void {
        std.mem.writeInt(L, w.buf[at - @sizeOf(L) ..][0..@sizeOf(L)], @intCast(w.n - at), .big);
    }
};

/// Random u16 list `<2..>` with a `L` length prefix; returns the elements.
fn randU16List(comptime S: type, src: *S, w: *Writer, comptime L: type, max: u8, out: []u16) []u16 {
    const n = src.valueRangeAtMost(u8, 1, max);
    const at = w.open(L);
    for (out[0..n]) |*v| {
        v.* = src.value(u16);
        w.int(u16, v.*);
    }
    w.close(L, at);
    return out[0..n];
}

fn expectU16s(it: ?hello.U16Iter, want: []const u16) !void {
    var i = it orelse return error.ListMissing;
    for (want) |v| if (i.next() != v) return error.ListDiffers;
    if (i.next() != null) return error.ListDiffers;
}

fn walkAll(ch: *const hello.ClientHello) void {
    var cs = ch.cipherSuites();
    while (cs.next()) |_| {}
    inline for (.{ "supportedGroups", "signatureAlgorithms", "signatureAlgorithmsCert", "supportedVersions", "compressCertificate" }) |f| {
        if (@field(hello.ClientHello, f)(ch)) |it0| {
            var it = it0;
            while (it.next()) |_| {}
        }
    }
    if (ch.keyShares()) |it0| {
        var it = it0;
        while (it.next()) |e| std.mem.doNotOptimizeAway(e.key_exchange.len);
    }
    if (ch.alpn()) |it0| {
        var it = it0;
        while (it.next()) |p| std.mem.doNotOptimizeAway(p.len);
    }
    if (ch.pre_shared_key) |p| {
        var ids = p.identities();
        while (ids.next()) |id| std.mem.doNotOptimizeAway(id.identity.len);
        var bs = p.binders();
        while (bs.next()) |b| std.mem.doNotOptimizeAway(b.len);
    }
}

fn fuzzHello(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const buf = try gpa.alloc(u8, 32 * 1024);
    defer gpa.free(buf);
    var w: Writer = .{ .buf = buf };

    const long_sid = src.valueRangeAtMost(u8, 0, 15) == 0;
    w.int(u16, 0x0303);
    var random: [32]u8 = undefined;
    src.bytes(&random);
    w.bytes(&random);
    const sid_len: u8 = if (long_sid) 33 else src.valueRangeAtMost(u8, 0, 32);
    w.int(u8, sid_len);
    var sid: [33]u8 = undefined;
    src.bytes(sid[0..sid_len]);
    w.bytes(sid[0..sid_len]);
    var suites_buf: [40]u16 = undefined;
    const suites = randU16List(S, src, &w, u16, 40, &suites_buf);
    w.int(u8, 1);
    w.int(u8, 0);

    // Model of the extensions.
    var groups_buf: [20]u16 = undefined;
    var groups: ?[]u16 = null;
    var sigs_buf: [20]u16 = undefined;
    var sigs: ?[]u16 = null;
    var versions_buf: [8]u16 = undefined;
    var versions: ?[]u16 = null;
    var sni: ?std.meta.Tag(hello.ServerName) = null;
    var sni_name: [64]u8 = undefined;
    var sni_len: usize = 0;
    var alpn_names: [4][16]u8 = undefined;
    var alpn_lens: [4]u8 = undefined;
    var alpn_n: ?usize = null;
    var shares: [3]struct { g: u16, len: u16, first: u8 } = undefined;
    var shares_n: ?usize = null;
    var cookie_len: ?u16 = null;
    var ocsp = false;
    var early = false;
    var psk_ids: ?usize = null;
    var binders_offset: usize = 0;

    const no_ext_block = src.valueRangeAtMost(u8, 0, 15) == 0;
    const fault = src.valueRangeAtMost(u8, 0, 7); // 0: duplicate, 1: psk not last
    var duplicate_planted = false;
    var psk_misplaced = false;
    if (no_ext_block) {
        HelloMark.mark(.no_ext_block);
    } else {
        const ext_at = w.open(u16);
        // Order: a random permutation of the 12 kinds below, each present
        // with probability 1/2; pre_shared_key goes last on its own.
        var order: [12]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
        var i: usize = order.len;
        while (i > 1) : (i -= 1) std.mem.swap(u8, &order[i - 1], &order[src.index(i)]);
        var unknown_used: [3]u16 = undefined;
        var unknown_n: usize = 0;
        var first_type: ?u16 = null;
        for (order) |kind| {
            if (src.valueRangeAtMost(u8, 0, 1) == 0) continue;
            const t: u16 = switch (kind) {
                0 => 0,
                1 => 10,
                2 => 13,
                3 => 43,
                4 => 16,
                5 => 51,
                6 => 44,
                7 => 5,
                8 => 42,
                9, 10, 11 => blk: {
                    // An unknown type (GREASE-like), distinct from the others.
                    var u: u16 = 0x0a0a + 0x1010 * @as(u16, src.valueRangeAtMost(u8, 0, 14));
                    while (std.mem.indexOfScalar(u16, unknown_used[0..unknown_n], u) != null) u +%= 0x1010;
                    unknown_used[unknown_n] = u;
                    unknown_n += 1;
                    HelloMark.mark(.unknown_ext);
                    break :blk u;
                },
                else => unreachable,
            };
            if (first_type == null) first_type = t;
            w.int(u16, t);
            const at = w.open(u16);
            switch (kind) {
                0 => {
                    const name_at = w.open(u16);
                    w.int(u8, 0);
                    const host_at = w.open(u16);
                    if (src.valueRangeAtMost(u8, 0, 3) == 0) {
                        const ip = std.fmt.bufPrint(&sni_name, "{d}.{d}.{d}.{d}", .{ src.value(u8), src.value(u8), src.value(u8), src.value(u8) }) catch unreachable;
                        sni_len = ip.len;
                        sni = .ip_address;
                        HelloMark.mark(.sni_ip);
                    } else {
                        // Letters and dots, never a leading/trailing/double dot.
                        sni_len = src.valueRangeAtMost(u8, 1, 60);
                        for (sni_name[0..sni_len], 0..) |*c, k| {
                            const dot = k > 0 and k + 1 < sni_len and sni_name[k - 1] != '.' and src.valueRangeAtMost(u8, 0, 7) == 0;
                            c.* = if (dot) '.' else 'a' + src.valueRangeAtMost(u8, 0, 25);
                        }
                        sni = .dns_name;
                        HelloMark.mark(.sni_dns);
                    }
                    w.bytes(sni_name[0..sni_len]);
                    w.close(u16, host_at);
                    w.close(u16, name_at);
                },
                1 => groups = randU16List(S, src, &w, u16, 20, &groups_buf),
                2 => sigs = randU16List(S, src, &w, u16, 20, &sigs_buf),
                3 => versions = randU16List(S, src, &w, u8, 8, &versions_buf),
                4 => {
                    const list_at = w.open(u16);
                    alpn_n = src.valueRangeAtMost(u8, 1, 4);
                    for (0..alpn_n.?) |k| {
                        alpn_lens[k] = src.valueRangeAtMost(u8, 1, 16);
                        src.bytes(alpn_names[k][0..alpn_lens[k]]);
                        w.int(u8, alpn_lens[k]);
                        w.bytes(alpn_names[k][0..alpn_lens[k]]);
                    }
                    w.close(u16, list_at);
                    HelloMark.mark(.alpn);
                },
                5 => {
                    const list_at = w.open(u16);
                    shares_n = src.valueRangeAtMost(u8, 0, 3);
                    if (shares_n.? == 0) HelloMark.mark(.empty_key_shares) else HelloMark.mark(.key_shares);
                    for (shares[0..shares_n.?]) |*sh| {
                        sh.g = src.value(u16);
                        sh.len = src.valueRangeAtMost(u16, 0, 1300);
                        sh.first = src.value(u8);
                        w.int(u16, sh.g);
                        w.int(u16, sh.len);
                        const kat = w.n;
                        src.bytes(w.buf[kat..][0..sh.len]);
                        if (sh.len > 0) w.buf[kat] = sh.first;
                        w.n += sh.len;
                    }
                    w.close(u16, list_at);
                },
                6 => {
                    cookie_len = src.valueRangeAtMost(u16, 1, 300);
                    w.int(u16, cookie_len.?);
                    src.bytes(w.buf[w.n..][0..cookie_len.?]);
                    w.n += cookie_len.?;
                    HelloMark.mark(.cookie);
                },
                7 => {
                    w.int(u8, 1);
                    w.int(u16, 0);
                    w.int(u16, 0);
                    ocsp = true;
                    HelloMark.mark(.ocsp);
                },
                8 => early = true,
                else => {
                    const n = src.valueRangeAtMost(u8, 0, 20);
                    src.bytes(w.buf[w.n..][0..n]);
                    w.n += n;
                },
            }
            w.close(u16, at);
        }
        if (fault == 0) if (first_type) |t| {
            // Repeat the first extension, empty-bodied: refused for the
            // repeat before its body is looked at.
            w.int(u16, t);
            w.int(u16, 0);
            duplicate_planted = true;
        };
        if (src.valueRangeAtMost(u8, 0, 2) == 0) {
            w.int(u16, 41);
            const at = w.open(u16);
            const ids_at = w.open(u16);
            const n_ids = src.valueRangeAtMost(u8, 1, 3);
            for (0..n_ids) |_| {
                const l = src.valueRangeAtMost(u16, 1, 200);
                w.int(u16, l);
                src.bytes(w.buf[w.n..][0..l]);
                w.n += l;
                w.int(u32, src.value(u32));
            }
            w.close(u16, ids_at);
            binders_offset = w.n;
            const bs_at = w.open(u16);
            for (0..n_ids) |_| {
                w.int(u8, 32);
                src.bytes(w.buf[w.n..][0..32]);
                w.n += 32;
            }
            w.close(u16, bs_at);
            w.close(u16, at);
            psk_ids = n_ids;
            if (fault == 1) {
                w.int(u16, 0x7a7a);
                w.int(u16, 0);
                psk_misplaced = true;
            }
        }
        w.close(u16, ext_at);
    }
    const body = buf[0..w.n];

    // Genuine (or with a planted fault).
    if (hello.parseClientHello(body)) |ch| {
        if (long_sid or duplicate_planted or psk_misplaced) return error.FaultAccepted;
        if (!std.mem.eql(u8, ch.random, &random)) return error.RandomDiffers;
        if (!std.mem.eql(u8, ch.legacy_session_id, sid[0..sid_len])) return error.SessionIdDiffers;
        try expectU16s(ch.cipherSuites(), suites);
        if (groups) |g| try expectU16s(ch.supportedGroups(), g) else if (ch.supported_groups_raw != null) return error.Phantom;
        if (sigs) |g| try expectU16s(ch.signatureAlgorithms(), g) else if (ch.signature_algorithms_raw != null) return error.Phantom;
        if (versions) |g| try expectU16s(ch.supportedVersions(), g) else if (ch.supported_versions_raw != null) return error.Phantom;
        if (sni) |t| {
            const got = ch.server_name orelse return error.SniMissing;
            if (std.meta.activeTag(got) != t) return error.SniClassDiffers;
            if (t == .dns_name and !std.mem.eql(u8, got.dns_name, sni_name[0..sni_len])) return error.SniDiffers;
        } else if (ch.server_name != null) return error.Phantom;
        if (alpn_n) |n| {
            var it = ch.alpn() orelse return error.AlpnMissing;
            for (0..n) |k| if (!std.mem.eql(u8, it.next() orelse return error.AlpnDiffers, alpn_names[k][0..alpn_lens[k]])) return error.AlpnDiffers;
            if (it.next() != null) return error.AlpnDiffers;
        } else if (ch.alpn_raw != null) return error.Phantom;
        if (shares_n) |n| {
            var it = ch.keyShares() orelse return error.SharesMissing;
            for (shares[0..n]) |sh| {
                const e = it.next() orelse return error.SharesDiffer;
                if (e.group != sh.g or e.key_exchange.len != sh.len) return error.SharesDiffer;
                if (sh.len > 0 and e.key_exchange[0] != sh.first) return error.SharesDiffer;
            }
            if (it.next() != null) return error.SharesDiffer;
        } else if (ch.key_shares_raw != null) return error.Phantom;
        if ((ch.cookie == null) != (cookie_len == null)) return error.CookieDiffers;
        if (cookie_len) |l| if (ch.cookie.?.len != l) return error.CookieDiffers;
        if (ch.ocsp_requested != ocsp or ch.early_data != early) return error.FlagDiffers;
        if (psk_ids) |n| {
            const p = ch.pre_shared_key orelse return error.PskMissing;
            if (p.binders_offset != binders_offset) return error.BindersOffsetDiffers;
            var ids = p.identities();
            var k: usize = 0;
            while (ids.next()) |_| k += 1;
            if (k != n) return error.PskDiffers;
            HelloMark.mark(.psk);
        } else if (ch.pre_shared_key != null) return error.Phantom;
    } else |err| {
        if (long_sid and err == error.DecodeError) {
            HelloMark.mark(.long_session_id_refused);
        } else if (duplicate_planted and err == error.IllegalParameter) {
            HelloMark.mark(.duplicate_refused);
        } else if (psk_misplaced and err == error.IllegalParameter) {
            HelloMark.mark(.psk_not_last_refused);
        } else return err;
    }

    // Damaged: never a panic; whatever decodes can be walked.
    const bad = try gpa.alloc(u8, body.len + 64);
    defer gpa.free(bad);
    @memcpy(bad[0..body.len], body);
    var n = body.len;
    switch (src.valueRangeAtMost(u8, 0, 3)) {
        0 => bad[src.index(n)] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7)),
        1 => bad[src.index(n)] = src.value(u8),
        2 => n = src.index(n),
        else => {
            const at = src.index(n + 1);
            const k = src.valueRangeAtMost(u8, 1, 64);
            std.mem.copyBackwards(u8, bad[at + k .. n + k], bad[at..n]);
            src.bytes(bad[at..][0..k]);
            n += k;
        },
    }
    if (hello.parseClientHello(bad[0..n])) |ch| {
        walkAll(&ch);
        HelloMark.mark(.damaged_decoded);
    } else |_| HelloMark.mark(.damaged_refused);
}

fn fuzzHelloSmith(_: void, smith: *std.testing.Smith) anyerror!void {
    var script: [4096]u8 = undefined;
    var src: ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzHello(ScriptSource, &src, testing.allocator);
}

test "fuzz: tlsserver hello, model → wire → decode" {
    try testing.fuzz({}, fuzzHelloSmith, .{});
}
test "fuzz driver: TLSSERVER_FUZZ (hello)" {
    try fuzz_driver.run(fuzzHello, .{ .prefix = "TLSSERVER_FUZZ", .name = "tlsserver-hello" });
}
test "fuzz harness: hello, 300 seeds, reaches every outcome" {
    try HelloMark.reach(fuzzHello, "tlsserver-hello", 300);
}

// ── tlsserver-keys ───────────────────────────────────────────────────────
//
// `keys.CertKeyPair.fromPem` on the openssl-written key vectors, damaged:
// the key's DER with 1..3 octets rewritten (a tag, a length octet or any
// octet), truncated or extended and re-armoured under its own or another
// key label; or rebuilt from a model of its fields (version, the scalar or
// seed at a length around the curve's, the curve OIDs, the optional [0] and
// [1], the PKCS#8 wrapper or not), the way the hello harness builds a
// ClientHello; or the PEM text itself with octets rewritten or cut. Every
// outcome is a typed error or a key of the case's kind that matches the
// certificate; never a panic, never a leak (the driver's allocator checks).

const keys = @import("keys.zig");
const key_vectors = @import("key_vectors.zig");

const KeyMark = Marker(enum {
    genuine,
    der_damaged_refused,
    der_damaged_loaded,
    relabelled_refused,
    model_loaded,
    model_refused,
    text_damaged_refused,
    malformed,
    invalid_pem,
    unsupported,
    mismatch,
    missing,
});

const key_label_names = [_][]const u8{ "EC PRIVATE KEY", "PRIVATE KEY", "RSA PRIVATE KEY", "ENCRYPTED PRIVATE KEY" };

/// The last block of `pem` (a key file's key block): its label and body.
fn lastBlock(pem: []const u8) struct { []const u8, []const u8 } {
    const bi = std.mem.lastIndexOf(u8, pem, "-----BEGIN ").?;
    const label_end = std.mem.indexOfPos(u8, pem, bi + 11, "-----").?;
    const body_start = std.mem.indexOfScalarPos(u8, pem, label_end, '\n').? + 1;
    const body_end = std.mem.indexOfPos(u8, pem, body_start, "-----END").?;
    return .{ pem[bi + 11 .. label_end], pem[body_start..body_end] };
}

fn armour(w: *std.Io.Writer, label: []const u8, der: []const u8) !void {
    var b64: [8192]u8 = undefined;
    const text = std.base64.standard.Encoder.encode(&b64, der);
    try w.print("-----BEGIN {s}-----\n", .{label});
    var rest = text;
    while (rest.len > 64) : (rest = rest[64..]) try w.print("{s}\n", .{rest[0..64]});
    try w.print("{s}\n-----END {s}-----\n", .{ rest, label });
}

fn sameKey(a: *const keys.PrivateKey, b: *const keys.PrivateKey) bool {
    return switch (a.*) {
        .ecdsa_p256 => |k| std.mem.eql(u8, &k.toBytes(), &b.ecdsa_p256.toBytes()),
        .ecdsa_p384 => |k| std.mem.eql(u8, &k.toBytes(), &b.ecdsa_p384.toBytes()),
        .ed25519 => |k| std.mem.eql(u8, &k.toBytes(), &b.ed25519.toBytes()),
        .rsa => |k| k.publicKey().equal(&b.rsa.publicKey()),
    };
}

/// A DER builder over a fixed buffer, back to front: `tlv` wraps everything
/// written since `mark` in one element.
const DerOut = struct {
    buf: [1024]u8 = undefined,
    len: usize = 0,

    fn put(o: *DerOut, bytes: []const u8) void {
        @memcpy(o.buf[o.len..][0..bytes.len], bytes);
        o.len += bytes.len;
    }
    fn mark(o: *const DerOut) usize {
        return o.len;
    }
    /// `[tag][len][content written since start]`, shifting the content.
    fn wrap(o: *DerOut, start: usize, tag: u8) void {
        const n = o.len - start;
        var hdr: [4]u8 = undefined;
        var h: usize = 0;
        hdr[0] = tag;
        if (n < 0x80) {
            hdr[1] = @intCast(n);
            h = 2;
        } else if (n < 0x100) {
            hdr[1] = 0x81;
            hdr[2] = @intCast(n);
            h = 3;
        } else {
            hdr[1] = 0x82;
            hdr[2] = @intCast(n >> 8);
            hdr[3] = @intCast(n & 0xff);
            h = 4;
        }
        std.mem.copyBackwards(u8, o.buf[start + h ..][0..n], o.buf[start..][0..n]);
        @memcpy(o.buf[start..][0..h], hdr[0..h]);
        o.len += h;
    }
    fn tlv(o: *DerOut, tag: u8, content: []const u8) void {
        const m = o.mark();
        o.put(content);
        o.wrap(m, tag);
    }
};

const oid_ec = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
const oid_p256 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
const oid_p384 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
const oid_ed = [_]u8{ 0x2b, 0x65, 0x70 };

/// The key's secret field at a length around `n`: the genuine bytes,
/// left-padded or cut, or random.
fn secretField(comptime S: type, src: *S, genuine: []const u8, out: []u8) []u8 {
    const n = genuine.len;
    const len: usize = switch (src.valueRangeAtMost(u8, 0, 5)) {
        0, 1, 2 => n,
        3 => n - 1 - src.index(3),
        4 => n + 1 + src.index(3),
        else => src.index(70),
    };
    if (src.valueRangeAtMost(u8, 0, 7) == 0) {
        src.bytes(out[0..len]);
    } else if (len >= n) {
        @memset(out[0 .. len - n], 0);
        @memcpy(out[len - n ..][0..n], genuine);
    } else @memcpy(out[0..len], genuine[n - len ..]);
    return out[0..len];
}

/// A key DER from a model of its fields; the label it goes under.
fn modelKey(comptime S: type, src: *S, genuine: *const keys.PrivateKey, o: *DerOut) []const u8 {
    var field_buf: [80]u8 = undefined;
    const pkcs8 = src.valueRangeAtMost(u8, 0, 1) == 0;
    const top = o.mark();
    switch (genuine.*) {
        .ecdsa_p256, .ecdsa_p384 => {
            const is384 = genuine.* == .ecdsa_p384;
            var sk: [48]u8 = undefined;
            const n: usize = if (is384) 48 else 32;
            if (is384) sk[0..48].* = genuine.ecdsa_p384.toBytes() else sk[0..32].* = genuine.ecdsa_p256.toBytes();
            const own: []const u8 = if (is384) &oid_p384 else &oid_p256;
            const other: []const u8 = if (is384) &oid_p256 else &oid_p384;
            const curve_oid = if (src.valueRangeAtMost(u8, 0, 5) == 0) other else own;
            if (pkcs8) {
                o.tlv(0x02, &.{if (src.valueRangeAtMost(u8, 0, 7) == 0) src.value(u8) else 0});
                const alg = o.mark();
                o.tlv(0x06, if (src.valueRangeAtMost(u8, 0, 9) == 0) &oid_ed else &oid_ec);
                o.tlv(0x06, curve_oid);
                o.wrap(alg, 0x30);
            }
            const inner = o.mark();
            o.tlv(0x02, &.{if (src.valueRangeAtMost(u8, 0, 7) == 0) src.value(u8) else 1});
            o.tlv(0x04, secretField(S, src, sk[0..n], &field_buf));
            if (!pkcs8 or src.valueRangeAtMost(u8, 0, 2) == 0) { // [0] curve
                const p = o.mark();
                o.tlv(0x06, if (src.valueRangeAtMost(u8, 0, 5) == 0) other else own);
                o.wrap(p, 0xa0);
            }
            if (src.valueRangeAtMost(u8, 0, 1) == 0) { // [1] some public key
                var pk: [98]u8 = undefined;
                pk[0] = 0;
                src.bytes(pk[1..]);
                const p = o.mark();
                o.tlv(0x03, pk[0 .. 2 + src.index(96)]);
                o.wrap(p, 0xa1);
            }
            o.wrap(inner, 0x30);
            if (pkcs8) {
                o.wrap(inner, 0x04);
                o.wrap(top, 0x30);
                return "PRIVATE KEY";
            }
            return "EC PRIVATE KEY";
        },
        .ed25519 => |k| {
            o.tlv(0x02, &.{if (src.valueRangeAtMost(u8, 0, 7) == 0) src.value(u8) else src.valueRangeAtMost(u8, 0, 1)});
            const alg = o.mark();
            o.tlv(0x06, &oid_ed);
            if (src.valueRangeAtMost(u8, 0, 7) == 0) o.tlv(0x05, ""); // parameters, which RFC 8410 forbids
            o.wrap(alg, 0x30);
            const priv = o.mark();
            o.tlv(0x04, secretField(S, src, &k.seed(), &field_buf));
            o.wrap(priv, 0x04);
            o.wrap(top, 0x30);
            return "PRIVATE KEY";
        },
        .rsa => unreachable,
    }
}

fn fuzzKeys(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const c = key_vectors.cases[src.index(key_vectors.cases.len)];
    var text_buf: [8192]u8 = undefined;
    var w: std.Io.Writer = .fixed(&text_buf);
    var mode = src.valueRangeAtMost(u8, 0, 11);
    if (mode >= 7 and mode <= 8 and c.kind == .rsa) mode = 1; // no RSA model
    var damaged = true;
    var relabel = false;
    if (mode == 0) {
        try w.writeAll(c.key_pem);
        damaged = false;
    } else if (mode <= 6) {
        // The DER, damaged and re-armoured.
        const label, const body = lastBlock(c.key_pem);
        var der_buf: [4096]u8 = undefined;
        const dec = std.base64.standard.decoderWithIgnore(" \t\r\n");
        var n = try dec.decode(&der_buf, body);
        var orig_buf: [4096]u8 = undefined;
        const orig = orig_buf[0..n];
        @memcpy(orig, der_buf[0..n]);
        switch (src.valueRangeAtMost(u8, 0, 3)) {
            0 => n = src.valueRangeAtMost(u16, 0, @intCast(n)), // truncated
            1 => { // extended
                const m = src.valueRangeAtMost(u16, 1, 16);
                src.bytes(der_buf[n..][0..m]);
                n += m;
            },
            2 => { // a header octet near the front (tags and lengths live there)
                if (n > 0) der_buf[src.index(@min(n, 40))] = src.value(u8);
            },
            else => if (n > 0) for (0..src.valueRangeAtMost(u8, 1, 3)) |_| {
                der_buf[src.index(n)] = src.value(u8);
            },
        }
        const out_label = if (src.valueRangeAtMost(u8, 0, 3) == 0) key_label_names[src.index(key_label_names.len)] else label;
        relabel = !std.mem.eql(u8, out_label, label);
        // A rewrite can leave the octets as they were: then only a label
        // change counts as damage.
        damaged = relabel or !std.mem.eql(u8, der_buf[0..n], orig);
        try armour(&w, out_label, der_buf[0..n]);
    } else if (mode <= 8) {
        // Rebuilt from the model.
        var genuine: keys.CertKeyPair = undefined;
        try keys.CertKeyPair.fromPem(&genuine, gpa, c.cert_pem, c.key_pem);
        defer genuine.deinit(gpa);
        var o: DerOut = .{};
        const label = modelKey(S, src, &genuine.key, &o);
        try armour(&w, label, o.buf[0..o.len]);
    } else {
        // The PEM text itself.
        try w.writeAll(c.key_pem);
        const t = w.buffered();
        if (src.valueRangeAtMost(u8, 0, 1) == 0) {
            for (0..src.valueRangeAtMost(u8, 1, 3)) |_| t[src.index(t.len)] = src.value(u8);
        } else {
            w.end = src.index(t.len);
        }
    }

    var pair: keys.CertKeyPair = undefined;
    if (keys.CertKeyPair.fromPem(&pair, gpa, c.cert_pem, w.buffered())) |_| {
        defer pair.deinit(gpa);
        if (!std.mem.eql(u8, @tagName(c.kind), @tagName(std.meta.activeTag(pair.key)))) return error.WrongKeyKind;
        // Whatever loads is the genuine key, not merely one of its kind.
        var genuine: keys.CertKeyPair = undefined;
        try keys.CertKeyPair.fromPem(&genuine, gpa, c.cert_pem, c.key_pem);
        defer genuine.deinit(gpa);
        if (!sameKey(&pair.key, &genuine.key)) return error.DifferentKeyLoaded;
        if (!damaged) KeyMark.mark(.genuine) else if (mode <= 6) KeyMark.mark(.der_damaged_loaded) else if (mode <= 8) KeyMark.mark(.model_loaded);
    } else |err| {
        if (!damaged) return err;
        switch (err) {
            error.MalformedKey => KeyMark.mark(.malformed),
            error.InvalidPem => KeyMark.mark(.invalid_pem),
            error.UnsupportedKey => KeyMark.mark(.unsupported),
            error.KeyMismatch => KeyMark.mark(.mismatch),
            error.MissingPrivateKey => KeyMark.mark(.missing),
            error.OutOfMemory, error.MissingCertificate, error.MalformedCertificate => return err,
        }
        if (mode > 8) KeyMark.mark(.text_damaged_refused) else if (mode > 6) KeyMark.mark(.model_refused) else if (relabel) KeyMark.mark(.relabelled_refused) else KeyMark.mark(.der_damaged_refused);
    }
}

fn fuzzKeysSmith(_: void, smith: *std.testing.Smith) anyerror!void {
    var script: [1024]u8 = undefined;
    var src: ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzKeys(ScriptSource, &src, testing.allocator);
}

test "fuzz: tlsserver keys, damaged key PEM is a typed error" {
    try testing.fuzz({}, fuzzKeysSmith, .{});
}
test "fuzz driver: TLSSERVER_FUZZ (keys)" {
    try fuzz_driver.run(fuzzKeys, .{ .prefix = "TLSSERVER_FUZZ", .name = "tlsserver-keys" });
}
test "fuzz harness: keys, 400 seeds, reaches every outcome" {
    try KeyMark.reach(fuzzKeys, "tlsserver-keys", 400);
}

// ── tlsserver-server ─────────────────────────────────────────────────────
//
// `Server` as a whole, fed real clients: the OpenSSL and Go sessions in
// `interop_vectors.zig`. A server with the recorded seed is a function of
// what it receives, so the genuine stream — cut into random chunks, down to
// one octet at a time — must produce the recorded output byte for byte.
// Damaged streams:
//
// - a flipped bit in a record's body (the plaintext ClientHello is in the
//   transcript, everything after it is sealed) never ends like the genuine
//   session, and when it hits a record up to the client's Finished the
//   handshake never completes;
// - a flipped bit in a record header may be refused, stall or (for octets
//   no one reads) pass — but passing means the recorded output;
// - (white box: the harness takes the client's handshake traffic secret
//   from the server, which only it can, as no change to the ClientHello
//   leaves the client's keys valid) the client's Finished opened and
//   resealed: damaged — a flipped verify_data bit, one octet short, another
//   message type — it is refused and the handshake never completes; intact
//   with random padding, the session ends as recorded;
// - a truncated stream never errs and its output is a prefix of the
//   recording;
// - random octets spliced in at a record boundary;
// - (the `resumed` cases) a flipped bit in the offered ticket: the server
//   does not resume, never checks the binder, sends a full flight — and the
//   client's Finished, keyed for the resumption, fails; a flipped bit in the
//   binder: decrypt_error before anything else is sent (RFC 8446 §4.2.11);
//
// and over all of them: a failure leaves `feed` returning `Closed`; a
// failure before the server wrote anything leaves exactly the plaintext
// fatal alert `alertFor` names, after its flight one sealed alert record;
// application data never precedes `handshake_done`; `write` before it is
// `NotConnected`.

const server_mod = @import("server.zig");
const interop = @import("interop_vectors.zig");
const certs = @import("test_certs.zig");
const rsa = @import("rsa");
const tlsresume = @import("tlsresume");

/// The recordings' ticket key and clock (`interop_vectors.zig`).
const InteropTickets = struct {
    ring: tlsresume.stek.DefaultRing,
    stek: server_mod.StekTicketer(tlsresume.stek.DefaultRing),
    tickets: server_mod.Tickets,

    fn init(t: *InteropTickets) void {
        t.ring = .init();
        t.ring.rotate(1, &interop.stek_key, @divFloor(interop.clock_ms, 1000));
        t.stek = .{ .ring = &t.ring };
        t.tickets = .{ .ticketer = t.stek.ticketer(), .clock = .{ .now_ms = clock } };
    }

    fn clock(_: ?*anyopaque) i64 {
        return interop.clock_ms;
    }
};

const SrvMark = Marker(enum {
    openssl_case,
    go_case,
    retry_case,
    key_update_case,
    resumed_case,
    ticket_flip_full_handshake,
    binder_flip_refused,
    genuine_chunked,
    genuine_bytewise,
    truncated_waits,
    body_flip_refused,
    body_flip_before_finished,
    header_flip_refused,
    header_flip_passed,
    header_flip_stalled,
    splice_refused,
    finished_forged_refused,
    finished_repadded,
    plain_alert,
    plain_alert_after_retry,
    sealed_alert,
    closed_after_error,
});

const FuzzKeys = struct {
    p256: std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey,
    p384: std.crypto.sign.ecdsa.EcdsaP384Sha384.SecretKey,
    ed25519: std.crypto.sign.Ed25519.SecretKey,
    rsa2048: rsa.SecretKey,
    chains: [4][1][]const u8,
    cks: [4]server_mod.CertifiedKey,
};
var fuzz_keys: ?*FuzzKeys = null;

/// Built once per process (RSA's parse dominates a run otherwise); never
/// freed — test-only, and the driver's leak check sees only `gpa`.
fn fuzzKeys_() !*FuzzKeys {
    if (fuzz_keys) |k| return k;
    const k = try std.heap.page_allocator.create(FuzzKeys); // global-alloc-ok: process-lifetime fuzz/test fixture cached across driver runs, outlives testing.allocator's per-test teardown
    k.p256 = try .fromBytes(certs.p256_scalar);
    k.p384 = try .fromBytes(certs.p384_scalar);
    k.ed25519 = try .fromBytes(certs.ed25519_secret);
    try rsa.SecretKey.fromDer(&k.rsa2048, &certs.rsa2048_pkcs1);
    k.chains = .{ .{&certs.p256_cert}, .{&certs.p384_cert}, .{&certs.ed25519_cert}, .{&certs.rsa2048_cert} };
    k.cks = .{
        .{ .chain = &k.chains[0], .key = .{ .ecdsa_p256 = &k.p256 } },
        .{ .chain = &k.chains[1], .key = .{ .ecdsa_p384 = &k.p384 } },
        .{ .chain = &k.chains[2], .key = .{ .ed25519 = &k.ed25519 } },
        .{ .chain = &k.chains[3], .key = .{ .rsa = &k.rsa2048 } },
    };
    fuzz_keys = k;
    return k;
}

const SrvRun = struct {
    out: std.ArrayList(u8) = .empty,
    app: std.ArrayList(u8) = .empty,
    handshake_done: bool = false,
    peer_closed: bool = false,
    answered: bool = false,
    /// The recording's server asked for a KeyUpdate before "pong\n".
    key_update: bool = false,
    failure: ?server_mod.Error = null,

    fn deinit(r: *SrvRun, gpa: std.mem.Allocator) void {
        r.out.deinit(gpa);
        r.app.deinit(gpa);
    }
};

/// Drain the server's output into `run.out`.
fn drainOut(server: *server_mod.Server, run: *SrvRun, gpa: std.mem.Allocator) !void {
    const p = server.pendingOutput();
    try run.out.appendSlice(gpa, p);
    server.discardOutput(p.len);
}

/// Feed `stream` in chunks the source chooses (`bytewise`: one octet at a
/// time), running the interop application protocol (answer "ping\n" with
/// "pong\n" and close_notify), checking the invariants on the way.
fn driveServer(comptime S: type, src: *S, gpa: std.mem.Allocator, server: *server_mod.Server, stream: []const u8, bytewise: bool, run: *SrvRun) !void {
    const in = try gpa.alloc(u8, 2 * record.max_record_len);
    defer gpa.free(in);
    var have: usize = 0;
    var at: usize = 0;
    if (server.write("early") catch |e| e != error.NotConnected) return error.WriteBeforeHandshake;
    while (at < stream.len or have != 0) {
        if (at < stream.len) {
            const n = if (bytewise) 1 else src.valueRangeAtMost(u16, 1, @intCast(@min(stream.len - at, 4096)));
            if (have + n > in.len) return error.HarnessBufferFull;
            @memcpy(in[have..][0..n], stream[at..][0..n]);
            have += n;
            at += n;
        }
        while (true) {
            const out_before = run.out.items.len;
            const closed_before = server.write_closed;
            const r = server.feed(in[0..have]) catch |err| {
                run.failure = err;
                try drainOut(server, run, gpa);
                try checkFailure(server, run, err, out_before, closed_before);
                return;
            };
            if (r.consumed > have) return error.ConsumedTooMuch;
            switch (r.event) {
                .need_more => {},
                .handshake_done => {
                    if (run.handshake_done) return error.HandshakeDoneTwice;
                    run.handshake_done = true;
                },
                .app_data => |d| {
                    if (!run.handshake_done) return error.AppDataBeforeHandshake;
                    try run.app.appendSlice(gpa, d);
                    if (!run.answered and std.mem.endsWith(u8, run.app.items, "ping\n")) {
                        if (run.key_update) try server.keyUpdate(.update_requested);
                        _ = try server.write("pong\n");
                        try server.close();
                        run.answered = true;
                    }
                },
                .peer_closed => run.peer_closed = true,
            }
            std.mem.copyForwards(u8, in[0 .. have - r.consumed], in[r.consumed..have]);
            have -= r.consumed;
            try drainOut(server, run, gpa);
            if (run.peer_closed) return;
            if (r.event == .need_more) break;
        }
        if (at == stream.len) return; // stalled: the rest is an incomplete record
    }
}

fn checkFailure(server: *server_mod.Server, run: *SrvRun, err: server_mod.Error, out_before: usize, closed_before: bool) !void {
    if (server.feed(@constCast("")) catch |e| e != error.Closed) return error.FeedAfterFailure;
    SrvMark.mark(.closed_after_error);
    const added = run.out.items[out_before..];
    // After its own close_notify the server sends nothing more; an error
    // that names no alert sends none.
    const d = (if (closed_before) null else server_mod.alertFor(err)) orelse {
        if (added.len != 0) return error.AlertAfterClose;
        return;
    };
    // The alert is the last record out: in plaintext while the server has
    // sent nothing protected (nothing at all, or a HelloRetryRequest and
    // its CCS), else sealed (2 octets + inner type + tag) after the flight
    // — which may have gone out in this same `feed`.
    const all = run.out.items;
    var starts_buf: [64]usize = undefined;
    const starts = recordStarts(all, &starts_buf);
    const any_sealed = for (starts) |s| {
        if (all[s] == 23) break true;
    } else false;
    if (!any_sealed) {
        const level: u8 = if (d == .close_notify) 1 else 2;
        const want = [7]u8{ 21, 3, 3, 0, 2, level, @backingInt(d) };
        if (all.len < 7 or !std.mem.eql(u8, all[all.len - 7 ..], &want)) return error.WrongPlainAlert;
        // Before the alert: nothing, or exactly HelloRetryRequest + CCS.
        if (all.len != 7) {
            if (starts.len != 3 or all[0] != 22 or all[starts[1]] != 20) return error.WrongPlainAlert;
            SrvMark.mark(.plain_alert_after_retry);
        }
        SrvMark.mark(.plain_alert);
        return;
    }
    if (added.len < 24 or all.len == 24 or !std.mem.eql(u8, all[all.len - 24 ..][0..5], &.{ 23, 3, 3, 0, 19 })) {
        std.debug.print("{t}: {d} octets out before, added {x}\n", .{ err, out_before, added });
        return error.MissingAlert;
    }
    SrvMark.mark(.sealed_alert);
}

/// The record boundaries of a recording: `starts[i]` is record i's header.
fn recordStarts(stream: []const u8, starts: []usize) []usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i + 5 <= stream.len and n < starts.len) {
        starts[n] = i;
        n += 1;
        i += 5 + std.mem.readInt(u16, stream[i + 3 ..][0..2], .big);
    }
    return starts[0..n];
}

fn fuzzServer(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const fk = try fuzzKeys_();
    // RSA signing dominates a run: one run in ten picks among all cases.
    var v: interop.Case = undefined;
    while (true) {
        v = interop.cases[src.index(interop.cases.len)];
        if (v.cert != .rsa2048 or src.valueRangeAtMost(u8, 0, 9) == 0) break;
    }
    if (std.mem.startsWith(u8, v.name, "go-")) SrvMark.mark(.go_case) else SrvMark.mark(.openssl_case);
    if (std.mem.indexOf(u8, v.name, "hrr") != null) SrvMark.mark(.retry_case);
    const ck = &fk.cks[@backingInt(v.cert)];
    var suites: [8]record.CipherSuite = undefined;
    for (v.suites, 0..) |s, i| suites[i] = @fromBackingInt(s);
    var csprng = std.Random.DefaultCsprng.init(@splat(v.seed));
    var it: InteropTickets = undefined;
    it.init();
    const cfg: server_mod.Config = .{
        .certificate = .{ .fixed = ck },
        .cipher_suites = suites[0..v.suites.len],
        .groups = v.groups,
        .alpn_protocols = v.alpn,
        .random = csprng.random(),
        .tickets = if (v.tickets) &it.tickets else null,
    };
    const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer gpa.free(joiner);
    const outb = try gpa.alloc(u8, server_mod.minOutputLen(ck) + 4096);
    defer gpa.free(outb);
    var server: server_mod.Server = .init(&cfg, joiner, outb);
    defer server.deinit();

    const stream = try gpa.dupe(u8, v.client);
    defer gpa.free(stream);
    var starts_buf: [64]usize = undefined;
    const starts = recordStarts(v.client, &starts_buf);
    // The client's Finished: its first sealed record.
    const finished_rec = for (starts, 0..) |s, i| {
        if (v.client[s] == 23) break i;
    } else return error.NoFinishedInRecording;

    var run: SrvRun = .{ .key_update = v.key_update };
    defer run.deinit(gpa);
    if (v.key_update) SrvMark.mark(.key_update_case);
    if (v.resumed) SrvMark.mark(.resumed_case);
    const mode = src.valueRangeAtMost(u8, 0, 13);
    const genuine_end = struct {
        fn f(r: *const SrvRun, want: []const u8) bool {
            // s_client's KeyUpdate rides with "again\n" (tools/interop.zig).
            const app_ok = std.mem.eql(u8, r.app.items, "ping\n") or (r.key_update and std.mem.eql(u8, r.app.items, "ping\nagain\n"));
            return r.failure == null and r.peer_closed and std.mem.eql(u8, r.out.items, want) and app_ok;
        }
    }.f;
    switch (mode) {
        0, 1 => {
            const bytewise = mode == 1;
            try driveServer(S, src, gpa, &server, stream, bytewise, &run);
            if (run.failure) |f| {
                std.debug.print("genuine {s}: {t}\n", .{ v.name, f });
                return error.GenuineRefused;
            }
            if (!genuine_end(&run, v.server)) return error.GenuineDiffers;
            if (server.isResumed() != v.resumed) return error.ResumptionDiffers;
            if (bytewise) SrvMark.mark(.genuine_bytewise) else SrvMark.mark(.genuine_chunked);
        },
        2 => {
            const cut = src.index(stream.len);
            try driveServer(S, src, gpa, &server, stream[0..cut], false, &run);
            if (run.failure) |f| {
                std.debug.print("truncated {s} at {d}: {t}\n", .{ v.name, cut, f });
                return error.TruncatedRefused;
            }
            if (!std.mem.startsWith(u8, v.server, run.out.items)) return error.TruncatedOutputNotPrefix;
            SrvMark.mark(.truncated_waits);
        },
        3, 4, 5, 6 => {
            // A body octet: not inside any record header.
            const ri = src.index(starts.len);
            const body_start = starts[ri] + 5;
            const body_end = if (ri + 1 < starts.len) starts[ri + 1] else stream.len;
            if (body_end <= body_start) return;
            const pos = body_start + src.index(body_end - body_start);
            stream[pos] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7));
            try driveServer(S, src, gpa, &server, stream, false, &run);
            if (genuine_end(&run, v.server)) return error.BodyFlipAccepted;
            if (ri <= finished_rec) {
                if (run.handshake_done) return error.HandshakeWithDamagedRecord;
                SrvMark.mark(.body_flip_before_finished);
            }
            if (run.failure != null) SrvMark.mark(.body_flip_refused);
        },
        7, 8 => {
            const ri = src.index(starts.len);
            const pos = starts[ri] + src.index(5);
            stream[pos] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7));
            try driveServer(S, src, gpa, &server, stream, false, &run);
            if (run.failure != null) {
                SrvMark.mark(.header_flip_refused);
            } else if (run.peer_closed) {
                // Passing: the server saw the same handshake.
                if (!genuine_end(&run, v.server)) return error.HeaderFlipPassedDifferently;
                SrvMark.mark(.header_flip_passed);
            } else {
                if (!std.mem.startsWith(u8, v.server, run.out.items)) return error.HeaderFlipStalledDifferently;
                SrvMark.mark(.header_flip_stalled);
            }
        },
        10, 11 => {
            // Up to the client's Finished, then that record resealed.
            const fs = starts[finished_rec];
            const fe = if (finished_rec + 1 < starts.len) starts[finished_rec + 1] else stream.len;
            try driveServer(S, src, gpa, &server, stream[0..fs], false, &run);
            if (run.failure != null or server.state != .client_finished) return error.PrefixDidNotReachFinished;
            const suite = server.cipherSuite().?;
            var rx: record.Protection = undefined;
            try rx.init(suite, server.client_handshake_secret[0..suite.hashLen().?]);
            defer rx.wipe();
            const sealed = try gpa.dupe(u8, stream[fs..fe]);
            defer gpa.free(sealed);
            const opened = try rx.open(sealed);
            if (opened.content_type != .handshake or opened.content.len < 5 or opened.content.len > 4 + 48) return error.RecordingFinishedShape;
            var msg_buf: [4 + 48]u8 = undefined;
            var msg: []u8 = msg_buf[0..opened.content.len];
            @memcpy(msg, opened.content);
            const forged = mode == 10;
            if (forged) switch (src.valueRangeAtMost(u8, 0, 2)) {
                0 => msg[4 + src.index(msg.len - 4)] ^= @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7)),
                1 => {
                    msg = msg[0 .. msg.len - 1];
                    std.mem.writeInt(u24, msg[1..4], @intCast(msg.len - 4), .big);
                },
                else => msg[0] = if (src.value(bool)) 15 else 24, // certificate_verify, key_update
            };
            const pad: usize = src.valueRangeAtMost(u16, 0, 300);
            var tx: record.Protection = undefined;
            try tx.init(suite, server.client_handshake_secret[0..suite.hashLen().?]);
            defer tx.wipe();
            const rebuilt = try gpa.alloc(u8, record.header_len + msg.len + 1 + pad + record.tag_len + (stream.len - fe));
            defer gpa.free(rebuilt);
            @memcpy(rebuilt[record.header_len..][0..msg.len], msg);
            const rec = try tx.seal(rebuilt, msg.len, .handshake, pad);
            @memcpy(rebuilt[rec.len..][0 .. stream.len - fe], stream[fe..]);
            try driveServer(S, src, gpa, &server, rebuilt[0 .. rec.len + stream.len - fe], false, &run);
            if (forged) {
                if (run.handshake_done or run.failure == null) return error.ForgedFinishedAccepted;
                SrvMark.mark(.finished_forged_refused);
            } else {
                if (!genuine_end(&run, v.server)) return error.RepaddedFinishedDiffers;
                SrvMark.mark(.finished_repadded);
            }
        },
        12, 13 => {
            if (!v.resumed) return;
            // The ClientHello the server resumes on: the last plaintext
            // handshake record before the Finished (the second one after a
            // retry), one whole message.
            const ri = for (0..finished_rec) |k| {
                const i = finished_rec - 1 - k;
                if (stream[starts[i]] == 22) break i;
            } else return error.NoClientHello;
            const body = stream[starts[ri] + 5 + 4 .. if (ri + 1 < starts.len) starts[ri + 1] else stream.len];
            const ch = hello.parseClientHello(body) catch return error.RecordedHelloRefused;
            const offer = ch.pre_shared_key orelse return error.RecordedHelloWithoutPsk;
            const bit = @as(u8, 1) << @intCast(src.valueRangeAtMost(u8, 0, 7));
            const ticket_flip = mode == 12;
            if (ticket_flip) {
                var ids = offer.identities();
                const t = ids.next().?.identity;
                const off = @intFromPtr(t.ptr) - @intFromPtr(stream.ptr);
                stream[off + src.index(t.len)] ^= bit;
            } else {
                // A binder's octets (after its length octet).
                const b = offer.binders_raw;
                const off = @intFromPtr(b.ptr) - @intFromPtr(stream.ptr);
                stream[off + 1 + src.index(b[0])] ^= bit;
            }
            try driveServer(S, src, gpa, &server, stream, false, &run);
            if (run.handshake_done) return error.DamagedOfferCompleted;
            const f = run.failure orelse return error.DamagedOfferNotRefused;
            if (ticket_flip) {
                if (server.isResumed() or f == error.DecryptError) return error.ForeignTicketResumedOrChecked;
                SrvMark.mark(.ticket_flip_full_handshake);
            } else {
                if (f != error.DecryptError) return error.BadBinderNotDecryptError;
                SrvMark.mark(.binder_flip_refused);
            }
        },
        else => {
            // Splice random octets in at a record boundary.
            const ri = src.index(starts.len);
            const n = src.valueRangeAtMost(u16, 1, 64);
            var junk: [64]u8 = undefined;
            src.bytes(junk[0..n]);
            const spliced = try gpa.alloc(u8, stream.len + n);
            defer gpa.free(spliced);
            @memcpy(spliced[0..starts[ri]], stream[0..starts[ri]]);
            @memcpy(spliced[starts[ri]..][0..n], junk[0..n]);
            @memcpy(spliced[starts[ri] + n ..], stream[starts[ri]..]);
            try driveServer(S, src, gpa, &server, spliced, false, &run);
            if (run.failure != null) SrvMark.mark(.splice_refused);
        },
    }
}

fn fuzzServerSmith(_: void, smith: *std.testing.Smith) anyerror!void {
    var script: [4096]u8 = undefined;
    var src: ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzServer(ScriptSource, &src, testing.allocator);
}

test "fuzz: tlsserver server, recorded clients whole, cut and damaged" {
    try testing.fuzz({}, fuzzServerSmith, .{});
}
test "fuzz driver: TLSSERVER_FUZZ (server)" {
    try fuzz_driver.run(fuzzServer, .{ .prefix = "TLSSERVER_FUZZ", .name = "tlsserver-server" });
}
test "fuzz harness: server, 400 seeds, reaches every outcome" {
    try SrvMark.reach(fuzzServer, "tlsserver-server", 400);
}

// ── tlsserver-keyupdate ──────────────────────────────────────────────────
//
// `Server` after a recorded handshake (an interop case fed through the
// client's Finished), then a script of post-handshake steps against a model
// client that follows every KeyUpdate: client KeyUpdates of either request,
// whole or split across two records; client application data, empty
// records too; server writes, an output left full, server-initiated
// KeyUpdates, the send key at `max_records_per_key`, close_notify; and one
// closing refusal — an invalid request octet, a wrong length, a KeyUpdate
// sharing its record with the next message, more than `max_key_updates` in
// a row, a record under the client's previous key.
//
// Invariants: everything the server sends opens under the model's keys, in
// order; data arrives intact both ways; a KeyUpdate the client requested is
// out before the server's next application data, and the number of server
// KeyUpdates (and of those requesting one back) is exactly what the
// requests, the `keyUpdate` calls and the key limit account for —
// coalesced while one is still due, dropped after close_notify; a refusal
// is the predicted error, its alert the last record (sealed under the key
// in force), and the server takes nothing more.

const tls13 = @import("tls13");
const ks13 = tls13.keyschedule.tls13;
const alert_mod = @import("alert.zig");

const KuMark = Marker(enum {
    sha384_suite,
    ku_not_requested,
    ku_requested_answered,
    tickets_after_finished,
    reply_deferred,
    reply_coalesced,
    own_update_requested,
    own_update_not_requested,
    limit_rekey,
    split_message,
    empty_app_record,
    output_full,
    after_close,
    refused_illegal_parameter,
    refused_decode_error,
    refused_misaligned,
    refused_too_many,
    refused_stale_key,
});

fn nextSecret(suite: record.CipherSuite, secret: *[48]u8) []const u8 {
    if (suite == .aes_256_gcm_sha384) {
        ks13.nextApplicationTrafficSecret(std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.sha2.HmacSha384), secret, secret);
        return secret;
    }
    ks13.nextApplicationTrafficSecret(std.crypto.kdf.hkdf.HkdfSha256, secret[0..32], secret[0..32]);
    return secret[0..32];
}

const KuClient = struct {
    server: *server_mod.Server,
    suite: record.CipherSuite,
    gpa: std.mem.Allocator,
    in: []u8,
    tx: record.Protection = undefined,
    rx: record.Protection = undefined,
    tx_secret: [48]u8 = @splat(0),
    rx_secret: [48]u8 = @splat(0),
    /// The client's previous send key (secret, next sequence number).
    prev_secret: ?[48]u8 = null,
    prev_seq: u64 = 0,
    /// Octets of server output the model has opened.
    out_total: usize = 0,
    /// Output offsets from which a requested KeyUpdate is due, oldest first.
    due: [64]usize = undefined,
    n_due: usize = 0,
    allowed: usize = 0,
    allowed_requested: usize = 0,
    seen: usize = 0,
    seen_requested: usize = 0,
    /// The server asked for a KeyUpdate: the client's next record is one.
    owes: bool = false,
    in_a_row: usize = 0,
    closed: bool = false,
    /// The server's close_notify has been opened: nothing may follow it.
    closed_seen: bool = false,
    /// Server → client: what `write` took, what opened.
    want: std.ArrayList(u8) = .empty,
    got: std.ArrayList(u8) = .empty,

    fn deinit(c: *KuClient) void {
        c.want.deinit(c.gpa);
        c.got.deinit(c.gpa);
        c.gpa.free(c.in);
    }

    /// A fatal alert's octets (close_notify is `closed_seen`).
    const Opened = struct { alert: ?[2]u8 = null };

    /// Open everything the server queued.
    fn drain(c: *KuClient) !Opened {
        var res: Opened = .{};
        const p = c.server.pendingOutput();
        const buf = try c.gpa.dupe(u8, p);
        defer c.gpa.free(buf);
        c.server.discardOutput(p.len);
        var at: usize = 0;
        while (at < buf.len) {
            if (buf.len - at < 5) return error.PartialRecordOut;
            const h = record.parseHeader(buf[at..][0..5]);
            if (h.content_type != .application_data) return error.PlaintextAfterHandshake;
            const start = c.out_total + at;
            const o = c.rx.open(buf[at..][0 .. 5 + h.length]) catch return error.ServerRecordDoesNotOpen;
            at += 5 + h.length;
            if (res.alert != null or c.closed_seen) return error.RecordAfterAlert;
            switch (o.content_type) {
                .handshake => {
                    if (o.content.len != 5 or !std.mem.eql(u8, o.content[0..4], &.{ 24, 0, 0, 1 })) return error.UnexpectedServerMessage;
                    if (o.content[4] > 1) return error.BadServerRequest;
                    c.seen += 1;
                    if (o.content[4] == 1) {
                        c.seen_requested += 1;
                        c.owes = true;
                    }
                    if (c.seen > c.allowed or c.seen_requested > c.allowed_requested) return error.UnaskedKeyUpdate;
                    if (c.n_due != 0) {
                        std.mem.copyForwards(usize, c.due[0 .. c.n_due - 1], c.due[1..c.n_due]);
                        c.n_due -= 1;
                    }
                    try c.rx.init(c.suite, nextSecret(c.suite, &c.rx_secret));
                },
                .application_data => {
                    if (c.n_due != 0 and start >= c.due[0]) return error.DataBeforeRequestedKeyUpdate;
                    try c.got.appendSlice(c.gpa, o.content);
                },
                .alert => {
                    if (o.content.len != 2) return error.BadAlertOut;
                    if (std.mem.eql(u8, o.content, &alert_mod.Alert.close_notify.encode())) {
                        if (!c.closed) return error.UnaskedCloseNotify;
                        c.closed_seen = true;
                    } else res.alert = o.content[0..2].*;
                },
                else => return error.UnexpectedServerRecord,
            }
        }
        c.out_total += buf.len;
        if (!std.mem.startsWith(u8, c.want.items, c.got.items)) return error.ServerDataDiffers;
        return res;
    }

    /// Feed `n` octets of `in` (whole records); the application data that
    /// arrives goes to `app`.
    fn feed(c: *KuClient, n: usize, app: *std.ArrayList(u8)) !?server_mod.Error {
        var at: usize = 0;
        while (true) {
            const r = c.server.feed(c.in[at..n]) catch |err| {
                const refused: ?server_mod.Error = err;
                return refused;
            };
            at += r.consumed;
            switch (r.event) {
                .need_more => {
                    if (at != n) return error.WholeRecordsLeftOver;
                    return null;
                },
                .app_data => |d| try app.appendSlice(c.gpa, d),
                .handshake_done, .peer_closed => return error.UnexpectedEvent,
            }
        }
    }

    /// Seal one record into `in` at `at`; returns the new end.
    fn seal(c: *KuClient, at: usize, ct: record.ContentType, content: []const u8) usize {
        @memcpy(c.in[at + 5 ..][0..content.len], content);
        return at + (c.tx.seal(c.in[at..], content.len, ct, 0) catch unreachable).len;
    }

    fn rotateTx(c: *KuClient) void {
        c.prev_secret = c.tx_secret;
        c.prev_seq = c.tx.seq;
        c.tx.init(c.suite, nextSecret(c.suite, &c.tx_secret)) catch unreachable;
    }

    /// The bookkeeping of a KeyUpdate request the server is about to see.
    fn requestArrives(c: *KuClient) void {
        if (c.closed) {
            KuMark.mark(.after_close);
            return;
        }
        // `feed` first sends a KeyUpdate still due, if it fits now; only one
        // that stays queued answers this request too.
        const ku_record = 5 + 4 + 1 + 1 + record.tag_len;
        const fits = c.server.out.buf.len - c.server.out.len >= @import("outbound.zig").alert_reserve + ku_record;
        if (c.server.tx_update != null and !fits) {
            KuMark.mark(.reply_coalesced);
            return;
        }
        c.allowed += 1;
        c.due[c.n_due] = c.out_total + c.server.pendingOutput().len;
        c.n_due += 1;
    }

    /// Settle what the client owes before its next record (true: done; false:
    /// the owed KeyUpdate was the refused one).
    fn payDebt(c: *KuClient) !bool {
        if (!c.owes) return true;
        c.owes = false;
        return c.clientKeyUpdate(0, false);
    }

    /// One KeyUpdate from the client, whole or split over two records.
    /// False: refused as predicted (too many).
    fn clientKeyUpdate(c: *KuClient, request: u8, split: bool) !bool {
        if (c.in_a_row == server_mod.max_key_updates) {
            const end = c.seal(0, .handshake, &.{ 24, 0, 0, 1, request });
            try c.expectRefusal(end, error.TooManyKeyUpdates);
            KuMark.mark(.refused_too_many);
            return false;
        }
        var app: std.ArrayList(u8) = .empty;
        defer app.deinit(c.gpa);
        const msg = [_]u8{ 24, 0, 0, 1, request };
        const end = if (split) blk: {
            const e1 = c.seal(0, .handshake, msg[0..2]);
            break :blk c.seal(e1, .handshake, msg[2..]);
        } else c.seal(0, .handshake, &msg);
        if (request == 1) c.requestArrives();
        c.in_a_row += 1;
        if (try c.feed(end, &app)) |err| {
            std.debug.print("client KeyUpdate({d}) refused: {t}\n", .{ request, err });
            return error.KeyUpdateRefused;
        }
        if (app.items.len != 0) return error.DataFromNowhere;
        if (request == 1 and !c.closed and c.server.tx_update != null) KuMark.mark(.reply_deferred);
        c.rotateTx();
        if (split) KuMark.mark(.split_message);
        if (request == 1) KuMark.mark(.ku_requested_answered) else KuMark.mark(.ku_not_requested);
        return true;
    }

    /// Feed the `n` octets of `in`; the server must fail with `want`, send
    /// that error's alert last (sealed under the key in force) and refuse
    /// everything after.
    fn expectRefusal(c: *KuClient, n: usize, want: server_mod.Error) !void {
        var app: std.ArrayList(u8) = .empty;
        defer app.deinit(c.gpa);
        const got = (try c.feed(n, &app)) orelse return error.RefusalAccepted;
        if (got != want) {
            std.debug.print("want {t}, got {t}\n", .{ want, got });
            return error.WrongRefusal;
        }
        const o = try c.drain();
        if (c.closed) {
            if (o.alert != null) return error.AlertAfterClose;
        } else {
            const d = server_mod.alertFor(want).?;
            const a = o.alert orelse return error.MissingAlert;
            if (!std.mem.eql(u8, &a, &alert_mod.Alert.fatal(d).encode())) return error.WrongAlert;
        }
        var empty: [0]u8 = .{};
        if (c.server.feed(&empty)) |_| return error.FeedAfterFailure else |e| if (e != error.Closed) return error.FeedAfterFailure;
    }
};

fn fuzzKeyUpdate(comptime S: type, src: *S, gpa: std.mem.Allocator) anyerror!void {
    const fk = try fuzzKeys_();
    var v: interop.Case = undefined;
    while (true) {
        v = interop.cases[src.index(interop.cases.len)];
        if (v.cert != .rsa2048) break;
    }
    const ck = &fk.cks[@backingInt(v.cert)];
    var suites: [8]record.CipherSuite = undefined;
    for (v.suites, 0..) |s, i| suites[i] = @fromBackingInt(s);
    var csprng = std.Random.DefaultCsprng.init(@splat(v.seed));
    var it: InteropTickets = undefined;
    it.init();
    const cfg: server_mod.Config = .{
        .certificate = .{ .fixed = ck },
        .cipher_suites = suites[0..v.suites.len],
        .groups = v.groups,
        .alpn_protocols = v.alpn,
        .random = csprng.random(),
        .tickets = if (v.tickets) &it.tickets else null,
    };
    const joiner = try gpa.alloc(u8, inbound.Joiner.bufferLen(inbound.default_max_message));
    defer gpa.free(joiner);
    const outb = try gpa.alloc(u8, server_mod.minOutputLen(ck) + 4096);
    defer gpa.free(outb);
    var server: server_mod.Server = .init(&cfg, joiner, outb);
    defer server.deinit();

    // The recording through the client's Finished.
    var starts_buf: [64]usize = undefined;
    const starts = recordStarts(v.client, &starts_buf);
    const fin = for (starts, 0..) |s, i| {
        if (v.client[s] == 23) break i;
    } else return error.NoFinishedInRecording;
    const fin_end = if (fin + 1 < starts.len) starts[fin + 1] else v.client.len;
    var c: KuClient = .{ .server = &server, .suite = undefined, .gpa = gpa, .in = try gpa.alloc(u8, 4 * record.max_record_len) };
    defer c.deinit();
    {
        @memcpy(c.in[0..fin_end], v.client[0..fin_end]);
        var at: usize = 0;
        var end = starts[fin];
        while (true) {
            const r = try server.feed(c.in[at..end]);
            at += r.consumed;
            if (r.event == .handshake_done) break;
            if (r.event != .need_more) return error.HandshakeDidNotComplete;
            if (at != end or end == fin_end) return error.HandshakeDidNotComplete;
            // The first flight went out under the handshake keys; the
            // client's Finished goes in alone.
            server.discardOutput(server.pendingOutput().len);
            end = fin_end;
        }
        if (at != fin_end) return error.HandshakeLeftOctets;
    }
    c.suite = server.cipherSuite().?;
    if (c.suite == .aes_256_gcm_sha384) KuMark.mark(.sha384_suite);
    const L = c.suite.hashLen().?;
    @memcpy(c.tx_secret[0..L], server.client_application_secret[0..L]);
    @memcpy(c.rx_secret[0..L], server.server_application_secret[0..L]);
    try c.tx.init(c.suite, c.tx_secret[0..L]);
    try c.rx.init(c.suite, c.rx_secret[0..L]);
    // What the client's Finished brought: the NewSessionTickets, in one
    // record, under the application key.
    {
        const p = try gpa.dupe(u8, server.pendingOutput());
        defer gpa.free(p);
        server.discardOutput(p.len);
        var n_tickets: usize = 0;
        var at: usize = 0;
        while (at < p.len) {
            const h = record.parseHeader(p[at..][0..5]);
            const o = c.rx.open(p[at..][0 .. 5 + h.length]) catch return error.TicketRecordDoesNotOpen;
            at += 5 + h.length;
            if (o.content_type != .handshake) return error.UnexpectedServerRecord;
            var m: usize = 0;
            while (m < o.content.len) : (n_tickets += 1) {
                if (o.content[m] != 4) return error.UnexpectedServerMessage;
                m += 4 + std.mem.readInt(u24, o.content[m + 1 ..][0..3], .big);
            }
        }
        if (n_tickets != (if (v.tickets) @as(usize, 2) else 0)) return error.WrongTicketCount;
        if (n_tickets != 0) KuMark.mark(.tickets_after_finished);
    }

    const steps = src.valueRangeAtMost(u8, 1, 24);
    var data: [256]u8 = undefined;
    for (0..steps) |_| {
        switch (src.valueRangeAtMost(u8, 0, 13)) {
            0, 1 => if (!try c.payDebt() or !try c.clientKeyUpdate(0, false)) return,
            2, 3 => if (!try c.payDebt() or !try c.clientKeyUpdate(1, false)) return,
            4 => if (!try c.payDebt() or !try c.clientKeyUpdate(src.valueRangeAtMost(u8, 0, 1), true)) return,
            5 => {
                if (!try c.payDebt()) return;
                const n = src.valueRangeAtMost(u16, 0, 64);
                src.bytes(data[0..n]);
                const end = c.seal(0, .application_data, data[0..n]);
                var app: std.ArrayList(u8) = .empty;
                defer app.deinit(gpa);
                if (try c.feed(end, &app)) |err| {
                    std.debug.print("client data refused: {t}\n", .{err});
                    return error.DataRefused;
                }
                if (!std.mem.eql(u8, app.items, data[0..n])) return error.ClientDataDiffers;
                if (n == 0) KuMark.mark(.empty_app_record);
                c.in_a_row = 0;
            },
            6, 7 => {
                const n = src.valueRangeAtMost(u16, 1, 200);
                src.bytes(data[0..n]);
                if (server.out.tx.seq >= server_mod.max_records_per_key and server.tx_update == null and !c.closed) {
                    c.allowed += 1;
                    c.allowed_requested += 1;
                    KuMark.mark(.limit_rekey);
                }
                if (server.write(data[0..n])) |k| {
                    if (c.closed) return error.WriteAfterClose;
                    try c.want.appendSlice(gpa, data[0..k]);
                } else |err| switch (err) {
                    error.OutputFull => KuMark.mark(.output_full),
                    error.Closed => if (!c.closed) return error.UnexpectedClosed,
                    else => return err,
                }
            },
            8 => {
                const req: server_mod.KeyUpdateRequest = if (src.value(bool)) .update_requested else .update_not_requested;
                const before = server.tx_update;
                if (server.keyUpdate(req)) {
                    if (c.closed) return error.KeyUpdateAfterClose;
                    if (before == null) {
                        c.allowed += 1;
                        if (req == .update_requested) c.allowed_requested += 1;
                    } else if (before.? == .update_not_requested and req == .update_requested) {
                        // The queued one becomes a request.
                        c.allowed_requested += 1;
                    }
                    if (req == .update_requested) KuMark.mark(.own_update_requested) else KuMark.mark(.own_update_not_requested);
                } else |err| if (err != error.Closed or !c.closed) return err;
            },
            9 => _ = try c.drain(),
            10 => {
                // Leave the output full.
                for (0..400) |_| {
                    if (c.closed) break;
                    if (server.out.tx.seq >= server_mod.max_records_per_key and server.tx_update == null) {
                        c.allowed += 1;
                        c.allowed_requested += 1;
                        KuMark.mark(.limit_rekey);
                    }
                    const filler: [200]u8 = @splat('f');
                    const k = server.write(&filler) catch |err| switch (err) {
                        error.OutputFull => break,
                        else => return err,
                    };
                    try c.want.appendSlice(gpa, filler[0..k]);
                }
                KuMark.mark(.output_full);
            },
            11 => {
                // The send key just short of its limit (model in step).
                if ((try c.drain()).alert != null) return error.UnexpectedAlert;
                const k = src.valueRangeAtMost(u8, 0, 2);
                server.out.tx.seq = server_mod.max_records_per_key - k;
                c.rx.seq = server.out.tx.seq;
            },
            12 => if (!c.closed) {
                // An undelivered KeyUpdate is dropped with close_notify.
                if (server.tx_update != null) {
                    c.allowed -= 1;
                    if (server.tx_update.? == .update_requested) c.allowed_requested -= 1;
                }
                try server.close();
                c.closed = true;
                c.n_due = 0;
            },
            else => {
                if (!try c.payDebt()) return;
                switch (src.valueRangeAtMost(u8, 0, 4)) {
                    0 => {
                        const r = src.valueRangeAtMost(u8, 2, 255);
                        const end = c.seal(0, .handshake, &.{ 24, 0, 0, 1, r });
                        if (c.in_a_row == server_mod.max_key_updates) {
                            try c.expectRefusal(end, error.TooManyKeyUpdates);
                            KuMark.mark(.refused_too_many);
                        } else {
                            try c.expectRefusal(end, error.IllegalParameter);
                            KuMark.mark(.refused_illegal_parameter);
                        }
                    },
                    1 => {
                        const end = if (src.value(bool)) c.seal(0, .handshake, &.{ 24, 0, 0, 0 }) else c.seal(0, .handshake, &.{ 24, 0, 0, 2, 0, 0 });
                        try c.expectRefusal(end, error.DecodeError);
                        KuMark.mark(.refused_decode_error);
                    },
                    2 => {
                        // The next message starts in the KeyUpdate's record.
                        const tail = src.valueRangeAtMost(u8, 1, 5);
                        const msg = [_]u8{ 24, 0, 0, 1, 0, 24, 0, 0, 1, 0 };
                        const end = c.seal(0, .handshake, msg[0 .. 5 + tail]);
                        if (c.in_a_row == server_mod.max_key_updates) {
                            try c.expectRefusal(end, error.TooManyKeyUpdates);
                            KuMark.mark(.refused_too_many);
                        } else {
                            try c.expectRefusal(end, error.UnexpectedMessage);
                            KuMark.mark(.refused_misaligned);
                        }
                    },
                    3 => {
                        while (try c.clientKeyUpdate(0, false)) {}
                    },
                    else => {
                        const prev = c.prev_secret orelse return;
                        var old: record.Protection = undefined;
                        var ps = prev;
                        try old.init(c.suite, ps[0..L]);
                        old.seq = c.prev_seq;
                        @memcpy(c.in[5..][0..3], "old");
                        const end = (try old.seal(c.in, 3, .application_data, 0)).len;
                        try c.expectRefusal(end, error.BadRecordMac);
                        KuMark.mark(.refused_stale_key);
                    },
                }
                return;
            },
        }
    }
    // Everything settles: the output drained, a due KeyUpdate goes out.
    _ = try c.drain();
    var empty: [0]u8 = .{};
    _ = try server.feed(&empty);
    _ = try c.drain();
    if (c.n_due != 0) return error.RequestedKeyUpdateNeverSent;
    if (c.seen != c.allowed or c.seen_requested != c.allowed_requested) {
        std.debug.print("KeyUpdates seen {d} ({d} requesting), allowed {d} ({d})\n", .{ c.seen, c.seen_requested, c.allowed, c.allowed_requested });
        return error.KeyUpdateCountDiffers;
    }
    if (!std.mem.eql(u8, c.want.items, c.got.items)) return error.ServerDataDiffers;
}

fn fuzzKeyUpdateSmith(_: void, smith: *std.testing.Smith) anyerror!void {
    var script: [4096]u8 = undefined;
    var src: ScriptSource = .init(script[0..smith.slice(&script)]);
    try fuzzKeyUpdate(ScriptSource, &src, testing.allocator);
}

test "fuzz: tlsserver KeyUpdate, scripted against a model client" {
    try testing.fuzz({}, fuzzKeyUpdateSmith, .{});
}
test "fuzz driver: TLSSERVER_FUZZ (keyupdate)" {
    try fuzz_driver.run(fuzzKeyUpdate, .{ .prefix = "TLSSERVER_FUZZ", .name = "tlsserver-keyupdate" });
}
test "fuzz harness: keyupdate, 400 seeds, reaches every outcome" {
    try KuMark.reach(fuzzKeyUpdate, "tlsserver-keyupdate", 400);
}
