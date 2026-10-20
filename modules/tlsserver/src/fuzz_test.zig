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
