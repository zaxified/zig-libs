// SPDX-License-Identifier: MIT
//! Allocator-owned, length-uncapped bech32 codec — BOLT#11 explicitly waives
//! BIP173's 90-character total-length ceiling ("A writer: ... MAY exceed the
//! 90-character limit specified in BIP-0173" / "A reader: MUST parse the
//! address as Bech32, as specified in BIP-0173 (also without the character
//! limit)"), so the `bech32` module's `encode`/`decode` — which enforce that
//! ceiling via fixed ~90-byte stack buffers — cannot be reused for invoices.
//! This file reimplements BIP173's BCH checksum + charset mapping (the same
//! public algorithm `bech32`'s own `bech32.zig` implements, just over
//! allocator-owned buffers instead of a capped stack buffer) so an invoice of
//! arbitrary length can be decoded/encoded; `bech32.charset` itself (the
//! 32-symbol alphabet, already `pub`) is reused rather than redeclared.
//!
//! Also provides a **checksum-less** variant (`decodeNoChecksum`/
//! `encodeNoChecksum`) for BOLT#12: offers/invoice_requests/invoices are
//! bech32-*style* strings with the trailing 6-character checksum omitted
//! entirely — BOLT#12 "Encoding": "There is no checksum, unlike bech32m" —
//! plus the `+`-continuation stripping BOLT#12 "Requirements" mandates
//! ("if it encounters a `+` followed by zero or more whitespace characters
//! between two bech32 characters: MUST remove the `+` and whitespace").

const std = @import("std");
const Allocator = std.mem.Allocator;
const bech32 = @import("bech32");

/// The 32-symbol bech32 charset (BIP173), re-exported from `bech32` so it is
/// declared in exactly one place in the repo.
pub const charset = bech32.charset;

const gen = [5]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
/// BOLT#11 invoices always checksum as plain bech32 (BIP173 constant `1`),
/// never bech32m — there is no witness-version-style variant selection here.
const bech32_const: u32 = 1;

fn polymod(values: []const u5) u32 {
    var chk: u32 = 1;
    for (values) |v| {
        const b: u32 = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ @as(u32, v);
        if (b & 1 != 0) chk ^= gen[0];
        if (b & 2 != 0) chk ^= gen[1];
        if (b & 4 != 0) chk ^= gen[2];
        if (b & 8 != 0) chk ^= gen[3];
        if (b & 16 != 0) chk ^= gen[4];
    }
    return chk;
}

const charset_rev: [256]i8 = blk: {
    var t: [256]i8 = [_]i8{-1} ** 256;
    for (charset, 0..) |c, i| t[c] = @intCast(i);
    break :blk t;
};

fn charValue(c: u8) ?u5 {
    const v = charset_rev[c];
    if (v < 0) return null;
    return @intCast(v);
}

fn toLower(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

/// True iff `c` is a member of the 32-symbol bech32 charset, case-folded (the
/// format allows an all-upper OR all-lower string, never mixed, so a single
/// stray uppercase neighbour must still count as "a bech32 character" here —
/// `splitHrp`/`charValue` reject a genuinely mixed-case string downstream;
/// this helper only asks "is this byte bech32-shaped at all").
fn isBech32Char(c: u8) bool {
    return charValue(toLower(c)) != null;
}

fn hrpExpand(allocator: Allocator, hrp: []const u8) Allocator.Error![]u5 {
    const out = try allocator.alloc(u5, 2 * hrp.len + 1);
    for (hrp, 0..) |c, i| out[i] = @intCast(c >> 5);
    out[hrp.len] = 0;
    for (hrp, 0..) |c, i| out[hrp.len + 1 + i] = @intCast(c & 31);
    return out;
}

pub const SplitError = error{ MixedCase, NoSeparator, EmptyHrp, HrpCharOutOfRange };

const Split = struct { hrp: []const u8, data: []const u8 };

/// BIP173's HRP/data split + the case/range checks common to both the
/// checksummed and checksum-less variants (BOLT#12 requires the same
/// all-lowercase-or-all-UPPERCASE rule bech32/BIP173 does).
fn splitHrp(s: []const u8) SplitError!Split {
    var saw_lower = false;
    var saw_upper = false;
    for (s) |c| {
        if (c >= 'a' and c <= 'z') saw_lower = true;
        if (c >= 'A' and c <= 'Z') saw_upper = true;
    }
    if (saw_lower and saw_upper) return error.MixedCase;

    // The separator is the LAST '1' (data-part charset never contains '1').
    const sep = std.mem.lastIndexOfScalar(u8, s, '1') orelse return error.NoSeparator;
    if (sep == 0) return error.EmptyHrp;
    for (s[0..sep]) |c| {
        if (c < 33 or c > 126) return error.HrpCharOutOfRange;
    }
    return .{ .hrp = s[0..sep], .data = s[sep + 1 ..] };
}

// ── checksummed (BOLT#11) ───────────────────────────────────────────────

pub const DecodeError = SplitError || error{ DataTooShort, InvalidDataChar, InvalidChecksum };

pub const Decoded = struct {
    hrp: []u8,
    /// Checksum already verified and stripped.
    data: []u5,

    pub fn deinit(self: *Decoded, allocator: Allocator) void {
        allocator.free(self.hrp);
        allocator.free(self.data);
        self.* = undefined;
    }
};

/// Decode + checksum-verify a bech32 string with no length cap. Fail-closed:
/// mixed case, out-of-charset characters, and a bad checksum are all
/// rejected with a specific typed error before any tagged-field parsing.
pub fn decode(allocator: Allocator, s: []const u8) (DecodeError || Allocator.Error)!Decoded {
    const split = try splitHrp(s);
    if (split.data.len < 6) return error.DataTooShort;

    const hrp = try allocator.alloc(u8, split.hrp.len);
    errdefer allocator.free(hrp);
    for (split.hrp, 0..) |c, i| hrp[i] = toLower(c);

    const full = try allocator.alloc(u5, split.data.len);
    defer allocator.free(full);
    for (split.data, 0..) |c, i| full[i] = charValue(toLower(c)) orelse return error.InvalidDataChar;

    const expanded = try hrpExpand(allocator, hrp);
    defer allocator.free(expanded);
    const combined = try allocator.alloc(u5, expanded.len + full.len);
    defer allocator.free(combined);
    @memcpy(combined[0..expanded.len], expanded);
    @memcpy(combined[expanded.len..], full);
    if (polymod(combined) != bech32_const) return error.InvalidChecksum;

    const data = try allocator.alloc(u5, full.len - 6);
    errdefer allocator.free(data);
    @memcpy(data, full[0 .. full.len - 6]);
    return .{ .hrp = hrp, .data = data };
}

pub const EncodeError = error{ EmptyHrp, HrpCharOutOfRange };

/// Encode `hrp` + `data` with a freshly computed bech32 checksum. No length
/// cap (the caller's `data` may exceed BIP173's payload ceiling).
pub fn encode(allocator: Allocator, hrp: []const u8, data: []const u5) (EncodeError || Allocator.Error)![]u8 {
    if (hrp.len == 0) return error.EmptyHrp;
    for (hrp) |c| {
        if (c < 33 or c > 126) return error.HrpCharOutOfRange;
    }

    const lowered = try allocator.alloc(u8, hrp.len);
    defer allocator.free(lowered);
    for (hrp, 0..) |c, i| lowered[i] = toLower(c);

    const expanded = try hrpExpand(allocator, lowered);
    defer allocator.free(expanded);
    const combined = try allocator.alloc(u5, expanded.len + data.len + 6);
    defer allocator.free(combined);
    @memcpy(combined[0..expanded.len], expanded);
    @memcpy(combined[expanded.len..][0..data.len], data);
    @memset(combined[expanded.len + data.len ..], 0);
    const pm = polymod(combined) ^ bech32_const;

    const out = try allocator.alloc(u8, lowered.len + 1 + data.len + 6);
    errdefer allocator.free(out);
    var n: usize = 0;
    @memcpy(out[n..][0..lowered.len], lowered);
    n += lowered.len;
    out[n] = '1';
    n += 1;
    for (data) |d| {
        out[n] = charset[d];
        n += 1;
    }
    for (0..6) |i| {
        const shift: u5 = @intCast(5 * (5 - i));
        out[n] = charset[@as(u5, @intCast((pm >> shift) & 31))];
        n += 1;
    }
    return out;
}

// ── checksum-less (BOLT#12) ─────────────────────────────────────────────

/// Strips `+` continuation markers and any whitespace immediately following
/// each one (BOLT#12 "Requirements": readers MUST remove a `+` and any
/// following whitespace — used to split a long offer/invoice across
/// limited-length text fields like a tweet).
///
/// **Corrected 2026-08-02 (external anchor: BOLT#12
/// `bolt12/format-string-test.json`, five "+ must be surrounded by bech32
/// characters" rows).** The spec's rule is conditional, not unconditional:
/// "if it encounters a `+` ... BETWEEN TWO bech32 characters: MUST remove
/// the `+` and whitespace" — a `+` at the very start/end of the string,
/// immediately adjacent to another `+`, or followed by nothing but
/// whitespace-then-end-of-string, does NOT sit between two characters and
/// must NOT be removed. The previous implementation stripped every `+`
/// unconditionally, which wrongly ACCEPTED strings the vectors require
/// rejected — e.g. a leading `+` ("+lno1...") was silently deleted,
/// recovering the exact valid offer underneath instead of leaving the `+`
/// in place to fail as `error.InvalidDataChar` (or, if it lands in the HRP
/// portion, `error.UnknownPrefix`) the way an unstripped `+` naturally does.
/// Left un-stripped, a disqualified `+` simply flows through to
/// `charValue`/`splitHrp` and is rejected there — no new error variant
/// needed.
///
/// **Neighbour test (W2 `lninvoice` F6, tightened):** the spec's "bech32
/// characters" means charset membership, not merely "anything that is not
/// `+`/whitespace". The prior check (`s[i-1] != '+' and !isWhitespace(...)`)
/// qualified any other byte at all, so a `+` preceded by e.g. a control
/// character or punctuation the spec would NOT call a bech32 character was
/// still treated as sitting "between two bech32 characters" and stripped.
/// `isBech32Char` (charset membership, case-folded) is the literal reading.
pub fn stripContinuation(allocator: Allocator, s: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == '+') {
            const has_before = i > 0 and isBech32Char(s[i - 1]);
            var j = i + 1;
            while (j < s.len and std.ascii.isWhitespace(s[j])) : (j += 1) {}
            const has_after = j < s.len and isBech32Char(s[j]);
            if (has_before and has_after) {
                i = j;
                continue;
            }
        }
        try out.append(allocator, s[i]);
        i += 1;
    }
    return out.toOwnedSlice(allocator);
}

pub const NoChecksumDecoded = struct {
    hrp: []u8,
    data: []u5,

    pub fn deinit(self: *NoChecksumDecoded, allocator: Allocator) void {
        allocator.free(self.hrp);
        allocator.free(self.data);
        self.* = undefined;
    }
};

/// Decode a checksum-less bech32-style string (BOLT#12). Caller is
/// responsible for `stripContinuation` first if the input may contain `+`.
pub fn decodeNoChecksum(allocator: Allocator, s: []const u8) (SplitError || error{InvalidDataChar} || Allocator.Error)!NoChecksumDecoded {
    const split = try splitHrp(s);

    const hrp = try allocator.alloc(u8, split.hrp.len);
    errdefer allocator.free(hrp);
    for (split.hrp, 0..) |c, i| hrp[i] = toLower(c);

    const data = try allocator.alloc(u5, split.data.len);
    errdefer allocator.free(data);
    for (split.data, 0..) |c, i| data[i] = charValue(toLower(c)) orelse return error.InvalidDataChar;

    return .{ .hrp = hrp, .data = data };
}

/// Encode a checksum-less bech32-style string (BOLT#12): `hrp` + `1` +
/// `data`, no checksum appended.
pub fn encodeNoChecksum(allocator: Allocator, hrp: []const u8, data: []const u5) (EncodeError || Allocator.Error)![]u8 {
    if (hrp.len == 0) return error.EmptyHrp;
    for (hrp) |c| {
        if (c < 33 or c > 126) return error.HrpCharOutOfRange;
    }
    const out = try allocator.alloc(u8, hrp.len + 1 + data.len);
    errdefer allocator.free(out);
    var n: usize = 0;
    for (hrp) |c| {
        out[n] = toLower(c);
        n += 1;
    }
    out[n] = '1';
    n += 1;
    for (data) |d| {
        out[n] = charset[d];
        n += 1;
    }
    return out;
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;
const testkit = @import("testkit");

test "encode then decode round-trips, no length cap" {
    const allocator = testing.allocator;
    var data_buf: [200]u5 = undefined;
    for (&data_buf, 0..) |*d, i| d.* = @intCast(i % 32);

    const enc = try encode(allocator, "lnbc", &data_buf);
    defer allocator.free(enc);
    try testing.expect(enc.len > 90); // exceeds BIP173's cap -- the whole point

    var dec = try decode(allocator, enc);
    defer dec.deinit(allocator);
    try testing.expectEqualStrings("lnbc", dec.hrp);
    try testing.expectEqualSlices(u5, &data_buf, dec.data);
}

test "TEETH: a data part too short to hold a checksum is refused, not underflowed" {
    // `split.data.len < 6` is the first thing an untrusted invoice string
    // touches, and it is what keeps `full.len - 6` below from wrapping around
    // on a `usize`. No test reached it: `error.DataTooShort` appeared in no
    // test body in the module, replacing the body with `unreachable` kept the
    // suite green, and so did weakening the bound to `< 1`.
    const allocator = testing.allocator;
    // 0..5 data characters — every length below the checksum's own width.
    const cases = [_][]const u8{ "lnbc1", "lnbc1q", "lnbc1qq", "lnbc1qqq", "lnbc1qqqq", "lnbc1qqqqq" };
    for (cases) |c| {
        try testing.expectError(error.DataTooShort, decode(allocator, c));
    }
    // Six characters is the boundary and is long enough to reach the checksum,
    // which then rejects it for its own reason — so the bound above is exactly
    // where it claims to be, not one either side.
    try testing.expectError(error.InvalidChecksum, decode(allocator, "lnbc1qqqqqq"));
}

test "decode: mixed case rejected" {
    const allocator = testing.allocator;
    try testing.expectError(error.MixedCase, decode(allocator, "Lnbc1qqqqqqqq"));
}

test "decode: no separator rejected" {
    const allocator = testing.allocator;
    try testing.expectError(error.NoSeparator, decode(allocator, "qqqqqqqq"));
}

test "decode: bit-flipped checksum rejected (positive control)" {
    const allocator = testing.allocator;
    var data_buf: [10]u5 = undefined;
    for (&data_buf, 0..) |*d, i| d.* = @intCast(i);
    const enc = try encode(allocator, "lnbc", &data_buf);
    defer allocator.free(enc);
    const tampered = try allocator.dupe(u8, enc);
    defer allocator.free(tampered);
    tampered[tampered.len - 1] = if (tampered[tampered.len - 1] == 'q') 'p' else 'q';
    try testing.expectError(error.InvalidChecksum, decode(allocator, tampered));
}

test "checksum-less: encode/decode round-trips, no checksum bytes appended" {
    const allocator = testing.allocator;
    var data_buf: [40]u5 = undefined;
    for (&data_buf, 0..) |*d, i| d.* = @intCast(i % 32);

    const enc = try encodeNoChecksum(allocator, "lno", &data_buf);
    defer allocator.free(enc);
    try testing.expectEqual(@as(usize, 3 + 1 + 40), enc.len); // hrp + '1' + data, NOTHING else

    var dec = try decodeNoChecksum(allocator, enc);
    defer dec.deinit(allocator);
    try testing.expectEqualStrings("lno", dec.hrp);
    try testing.expectEqualSlices(u5, &data_buf, dec.data);
}

test "stripContinuation: removes '+' and following whitespace (BOLT#12 QR-split)" {
    const allocator = testing.allocator;
    const stripped = try stripContinuation(allocator, "lno1xxxxxxxx+\n\nyyyyyyyyyyyy+ zzzzz");
    defer allocator.free(stripped);
    try testing.expectEqualStrings("lno1xxxxxxxxyyyyyyyyyyyyzzzzz", stripped);
}

// Regression (audit W2 `lninvoice` F6): the neighbour test is "a bech32
// charset member", not "anything other than '+'/whitespace". Before the fix,
// a `+` preceded by a non-bech32, non-whitespace byte (e.g. `.` or `_`,
// neither of which the 32-symbol charset contains) was still stripped,
// because the old test only excluded `+` and whitespace explicitly. The
// disqualifying byte is itself rejected downstream by `charValue`/`splitHrp`
// today (so this was latent looseness, not a live accept per the audit's own
// note), but the neighbour test itself must match the spec's literal words.
test "stripContinuation: a '+' next to a NON-bech32 byte is left in place, not stripped" {
    const allocator = testing.allocator;
    // '.' and '_' are not in the 32-symbol bech32 charset.
    const cases = [_][]const u8{
        "lno1xx.+ yyyy", // disqualifying byte BEFORE the '+'
        "lno1xx+ .yyyy", // disqualifying byte AFTER the '+' (past the whitespace)
        "lno1xx_+yyyy",
        "lno1xx+_yyyy",
    };
    for (cases) |c| {
        const stripped = try stripContinuation(allocator, c);
        defer allocator.free(stripped);
        // Unchanged: the '+' (and any whitespace after it) survives verbatim
        // because at least one neighbour is not bech32-charset-shaped.
        try testing.expectEqualStrings(c, stripped);
    }
}

test "stripContinuation: a '+' between two genuine bech32 characters is still stripped" {
    const allocator = testing.allocator;
    // Sanity: the tightened check does not regress the ordinary case — every
    // byte on both sides is a real bech32-charset member.
    const stripped = try stripContinuation(allocator, "lno1xxq+yyyy");
    defer allocator.free(stripped);
    try testing.expectEqualStrings("lno1xxqyyyy", stripped);
}

// ── fuzz: decode never panics on an arbitrary raw string ─────────────────
//
// This is a from-scratch reimplementation of BIP173's HRP/checksum state
// machine (see the module doc comment for why -- the sibling `bech32`
// module's own fuzzed `decode` enforces a 90-char cap BOLT#11 explicitly
// waives, so it can't be reused here), so it needs its own harness rather
// than inheriting `bech32`'s coverage. Unlike `bolt11.zig`'s fuzz harness
// (which always routes through this module's own `encode` to reach a
// checksum-valid string), this one mutates the wire text MORE directly --
// biased toward the bech32 charset/separator/case rules most of the time,
// with fully-random byte splices the rest, so the HRP-range/mixed-case/
// out-of-charset paths get exercised on their own, not only via a
// well-formed encoder round-trip.
/// `testkit.fuzz.Cursor` over one corpus seed, which is what drives
/// `fuzzDecode`.
///
/// ⚠ Every choice here used to come from a scalar `Smith` draw, the FIRST of
/// them `valueRangeAtMost(u8, 0, buf.len)` — `check-fuzz-reach` classifies
/// that R1, and correctly: a scalar draw reads eight octets as a little-endian
/// u64 and returns the range MINIMUM unless the whole word falls inside the
/// range, so on the one input an ordinary `zig build test-*` run gets, `len`
/// was **0** and `decode` was called with `""`. The character bias, the
/// case-flip, all of it ran zero times. Reading the choices out of ONE
/// `smith.slice` fixes both halves: the draw is byte-first, and a seed becomes
/// the invoice string it represents rather than a list of u64 words.
const Script = @import("testkit").fuzz.Cursor;

/// The body of `fuzzDecode`, factored out so the harness and the corpus guard
/// build the SAME string from the same octets. Returns the built string in
/// `out`.
///
/// The layout the cursor reads is `length`, then per character `form` and the
/// character itself (`form` odd = a bech32 charset symbol or the separator,
/// even = the octet raw), then `flipCase` and a position. A short script
/// cycles.
fn buildString(script: []const u8, out: *[128]u8) []u8 {
    var s = Script{ .bytes = script };
    const len: usize = s.ranged(0, out.len);
    for (out[0..len]) |*c| {
        if (s.byte() & 1 != 0) {
            // Bias toward the 32-symbol bech32 charset plus the '1'
            // separator -- what a real (possibly-corrupted) invoice
            // string is actually made of.
            const alphabet = charset ++ "1";
            c.* = alphabet[s.ranged(0, alphabet.len - 1)];
        } else {
            c.* = s.byte();
        }
    }
    // Occasionally flip ASCII-letter case on a byte, to reach MixedCase.
    if (len > 0 and s.byte() & 1 != 0) {
        const i: usize = s.ranged(0, @intCast(len - 1));
        if (std.ascii.isAlphabetic(out[i])) out[i] = if (std.ascii.isUpper(out[i])) std.ascii.toLower(out[i]) else std.ascii.toUpper(out[i]);
    }
    return out[0..len];
}

/// Scripts for `buildString`, in the format `Smith.slice` reads.
///
/// ⭐ Built at run time, and the reason is the whole point of this corpus: a
/// bech32 string ends in a 6-symbol checksum over everything before it, so a
/// script whose character choices are picked by hand produces a string that
/// `decode` refuses at the checksum, always. The first draft of this corpus
/// was eight such scripts and scored **0 accepted** — which the guard caught,
/// and which is a finding rather than a result. `spell` therefore takes a
/// string this module's own `encode` produced and emits the script that
/// reproduces it character for character, so the harness reaches the payload
/// behind the checksum rather than only the refusal in front of it.
const StringCorpus = struct {
    store: [16 * 1024]u8 = undefined,
    used: usize = 0,
    /// ⚠ The strings are COPIED here rather than borrowed: the encoder's
    /// output is freed before `build` returns, and `texts` pointing at it is a
    /// use-after-free that reads back as a segfault in the guard's `eql`.
    text_store: [4 * 1024]u8 = undefined,
    text_used: usize = 0,
    entries: [10][]const u8 = undefined,
    texts: [10][]const u8 = undefined,
    n: usize = 0,

    /// Emit the script that makes `buildString` reproduce `text`, optionally
    /// with the case flip armed at `flip_at`.
    fn spell(self: *StringCorpus, text: []const u8, flip_at: ?u8) void {
        var script: [1 + 2 * 128 + 2]u8 = undefined;
        var k: usize = 0;
        script[k] = @intCast(text.len);
        k += 1;
        for (text) |c| {
            const alphabet = charset ++ "1";
            if (std.mem.indexOfScalar(u8, alphabet, c)) |idx| {
                script[k] = 0x01; // form: draw from the charset
                script[k + 1] = @intCast(idx);
            } else {
                script[k] = 0x00; // form: the octet, raw
                script[k + 1] = c;
            }
            k += 2;
        }
        if (flip_at) |at| {
            script[k] = 0x01;
            script[k + 1] = at;
            k += 2;
        } else {
            script[k] = 0x00;
            k += 1;
        }
        const head = testkit.fuzz.seedInto(self.store[self.used..], script[0..k]);
        self.entries[self.n] = head;
        @memcpy(self.text_store[self.text_used..][0..text.len], text);
        self.texts[self.n] = self.text_store[self.text_used..][0..text.len];
        self.text_used += text.len;
        self.used += head.len;
        self.n += 1;
    }

    fn build(self: *StringCorpus, allocator: Allocator) ![]const []const u8 {
        // Two real, checksum-valid strings out of this module's own encoder:
        // a short data part and a 100-quintet one.
        const short = try encode(allocator, "lnbc", &[_]u5{ 1, 2, 3, 4, 5, 6, 7, 8 });
        defer allocator.free(short);
        self.spell(short, null);
        // The same string with one letter's case flipped: `MixedCase`.
        self.spell(short, 5);

        var quintets: [100]u5 = undefined;
        for (&quintets, 0..) |*q, i| q.* = @intCast(i % 32);
        const long = try encode(allocator, "lntb", &quintets);
        defer allocator.free(long);
        self.spell(long, null);

        // An empty data part is still six checksum symbols.
        const bare = try encode(allocator, "ln", &.{});
        defer allocator.free(bare);
        self.spell(bare, null);

        // ── strings the decoder must refuse ────────────────────────────────
        // One data symbol corrupted: the checksum no longer holds.
        {
            var bent: [128]u8 = undefined;
            @memcpy(bent[0..short.len], short);
            bent[short.len - 1] = if (bent[short.len - 1] == 'q') 'p' else 'q';
            self.spell(bent[0..short.len], null);
        }
        self.spell("", null); // the empty string — what the collapsed draw produced
        self.spell("q", null); // one character: no separator, no checksum
        self.spell("lnbc1", null); // a separator with nothing behind it
        self.spell("1111111111", null); // nothing but separators
        self.spell("lnbc1qqqqqq\x80\xff", null); // out-of-charset octets
        return self.entries[0..self.n];
    }
};

test "fuzz: decode never panics on arbitrary bytes" {
    var corpus: StringCorpus = .{};
    try testing.fuzz({}, fuzzDecode, .{ .corpus = try corpus.build(testing.allocator) });
}

fn fuzzDecode(_: void, smith: *std.testing.Smith) !void {
    const allocator = testing.allocator;
    // ⚠ One `smith.slice`, then the octets say what happens — see `Script`.
    // Measured 2026-09-07 over the corpus below: **one input, the EMPTY
    // string, before; 10 scripts, 206 characters and 3 strings decoded after.**
    var script: [512]u8 = undefined;
    const n: usize = smith.slice(&script);
    var buf: [128]u8 = undefined;
    const text = buildString(script[0..n], &buf);

    var dec = decode(allocator, text) catch return;
    defer dec.deinit(allocator);
}

test "corpus: every string script builds a string, and what decode made of it is pinned" {
    // ⭐ The measurement, executable rather than written in a comment, over the
    // SAME corpus the harness gets and through the SAME `buildString`.
    //
    // `chars` is the reach claim in the form that fits a harness whose seed is
    // a SCRIPT rather than the string: "non-empty seed" would only say the
    // script arrived, and the thing the collapse destroyed was the LENGTH.
    // `hrp_octets` is the second number, and it is what the empty string
    // cannot produce — a decode that succeeds still says nothing about whether
    // a human-readable part was ever read.
    var corpus: StringCorpus = .{};
    const entries = try corpus.build(testing.allocator);
    var spelled: usize = 0;
    var chars: usize = 0;
    var decoded: usize = 0;
    var hrp_octets: usize = 0;
    for (entries, corpus.texts[0..corpus.n]) |sd, want| {
        var smith: std.testing.Smith = .{ .in = sd };
        var script: [512]u8 = undefined;
        const n: usize = smith.slice(&script);
        var buf: [128]u8 = undefined;
        const text = buildString(script[0..n], &buf);
        // The script reproduced the string it was written from, character for
        // character. Without this the corpus could be spelling anything.
        if (std.mem.eql(u8, text, want)) spelled += 1;
        chars += text.len;
        var dec = decode(testing.allocator, text) catch continue;
        defer dec.deinit(testing.allocator);
        decoded += 1;
        hrp_octets += dec.hrp.len;
    }
    // One short: the case-flipped seed deliberately does not reproduce its
    // source string.
    try testing.expectEqual(entries.len - 1, spelled);
    try testing.expectEqual(@as(usize, 206), chars);
    try testing.expectEqual(@as(usize, 3), decoded);
    // 4 + 4 + 2: the two `lnbc`/`lntb` strings and the bare `ln` one. The
    // case-flipped seed is `MixedCase` and contributes none.
    try testing.expectEqual(@as(usize, 10), hrp_octets);

    // The "before" measurement, executable: the empty script is exactly what
    // the collapsed harness ran, and it builds the empty string.
    var zero: [128]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), buildString(&.{}, &zero).len);
}
