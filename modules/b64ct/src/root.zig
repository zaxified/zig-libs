// SPDX-License-Identifier: MIT

//! b64ct — constant-time base64 (RFC 4648 §4 and §5, padded and unpadded),
//! for the secrets a program writes or reads as base64: private keys in PEM,
//! shared secrets in config files, credentials in `AUTH PLAIN`, exported
//! session keys.
//!
//! `std.base64` encodes through a 64-entry table indexed by each secret
//! sextet and decodes through a 256-entry table indexed by each secret
//! character — secret-dependent load addresses, which a cache-timing attacker
//! can read (memcheck flagged every one: `ctgrind.sh acme`/`smtp`/`megolm`,
//! 2026-10-10/13). Here every character is computed arithmetically: each range
//! decision is a borrow turned into a mask, never a branch or an index.
//! Validity is accumulated over the whole input and branched on once, at the
//! end. The construction is libsodium's (`sodium_bin2base64` /
//! `sodium_base642bin`), and so is the decoder's contract: the same four
//! variants, the same strictness (padding exactly as the length requires,
//! unused low bits zero), an `ignore` set, and a prefix mode that stops at the
//! first character outside the encoding (`decodePrefix`, libsodium's
//! `b64_end`).
//!
//! What is public, and why (`SPEC.md` § Constant-time contract): the input and
//! output LENGTHS, the number of `=` (it follows from the output length), the
//! positions of ignored characters (the text's layout — line breaks — never a
//! key character), where `decodePrefix` stops, and the accept/reject verdict.
//! Each is turned into a branch at exactly one place, through `public`, which
//! tells memcheck the value is defined — so ctgrind reads zero branches on the
//! secret for every accepted input.

const std = @import("std");

pub const meta = .{
    .doc = "Constant-time base64 (RFC 4648 standard and URL alphabets, padded and unpadded) for secrets: no secret-indexed table or branch; libsodium's strictness, ignore set, prefix decode, PEM line wrapping.",
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .codec,
    .concurrency = .reentrant,
    .model_after = "libsodium sodium_bin2base64/sodium_base642bin (C); RustCrypto base64ct (Rust)",
    .deps = .{},
};

/// `std.base64.Error`, so a caller switching from std keeps its error set:
/// `InvalidCharacter` (a character outside the alphabet, or `=` where no
/// padding may be), `InvalidPadding` (a length the variant cannot have, the
/// wrong number of `=`, or nonzero unused bits in the final character),
/// `NoSpaceLeft` (the output buffer is too short).
pub const Error = std.base64.Error;

pub const Alphabet = enum {
    /// `A–Z a–z 0–9 + /` (RFC 4648 §4).
    standard,
    /// `A–Z a–z 0–9 - _` (RFC 4648 §5).
    url_safe,
};

pub const LineEnding = enum {
    lf,
    crlf,

    pub fn bytes(self: LineEnding) []const u8 {
        return switch (self) {
            .lf => "\n",
            .crlf => "\r\n",
        };
    }
};

/// The characters a PEM body may carry between base64 characters (RFC 7468
/// §3 allows any whitespace; this is the set real files use).
pub const pem_whitespace = " \t\r\n";

/// Padded standard base64 (RFC 4648 §4) — `std.base64.standard`, libsodium
/// `sodium_base64_VARIANT_ORIGINAL`, PEM.
pub const standard = Codec(.standard, true);
/// Unpadded standard base64 — `std.base64.standard_no_pad`, libsodium
/// `ORIGINAL_NO_PADDING`.
pub const standard_no_pad = Codec(.standard, false);
/// Padded URL-safe base64 (RFC 4648 §5) — libsodium `URLSAFE`.
pub const url_safe = Codec(.url_safe, true);
/// Unpadded URL-safe base64 — libsodium `URLSAFE_NO_PADDING`, JOSE.
pub const url_safe_no_pad = Codec(.url_safe, false);

/// Where `decodePrefix` stopped: `data` is the decoded front of `out`,
/// `consumed` the number of input characters that encoded it (padding and
/// trailing ignored characters included).
pub const Prefix = struct {
    data: []u8,
    consumed: usize,
};

/// A value computed from secret input that the contract makes public (a
/// length, a layout position, the verdict). Without `-fvalgrind` this is the
/// identity; with it, memcheck is told the value is defined, so the one
/// branch taken on it is not reported. Every call site is a declassification
/// — `SPEC.md` lists them.
inline fn public(comptime T: type, v: T) T {
    var x = v;
    std.valgrind.memcheck.makeMemDefined(std.mem.asBytes(&x));
    return x;
}

/// 0xff when `a >= b`, else 0 — from the borrow of `b-1 - a`.
inline fn ge(a: u8, comptime b: u8) u8 {
    return @truncate((@as(u16, b) -% 1 -% a) >> 8);
}

/// 0xff when lo <= c <= hi, else 0.
inline fn inRange(c: u8, comptime lo: u8, comptime hi: u8) u8 {
    const v = (@as(u16, c) -% lo) | (@as(u16, hi) -% c);
    return ~@as(u8, @truncate(v >> 8));
}

/// 0xff when c == x (runtime x), else 0.
inline fn eqMask(c: u8, x: u8) u8 {
    const d: u16 = c ^ x;
    return @truncate((d -% 1) >> 8);
}

// ── 16 characters at a time ─────────────────────────────────────────────────
//
// The same arithmetic as the scalar path, lane-wise: compares and selects
// compile to vector compares and masks (pcmpgtb/pminub/pand on x86-64, cmhi/
// and on aarch64), never to a branch or a table. Little-endian only: `pack16`
// reads each quantum's four sextets as one u32 lane.

const builtin = @import("builtin");
const simd = builtin.cpu.arch.endian() == .little;
const V8 = @Vector(16, u8);

inline fn splat(x: u8) V8 {
    return @splat(x);
}

inline fn mask16(b: @Vector(16, bool)) V8 {
    return @select(u8, b, splat(0xff), splat(0));
}

/// Four quanta of sextets (a, b, c, d per u32 lane) to their 12 octets.
inline fn pack16(out: *[12]u8, sx: V8) void {
    const w: @Vector(4, u32) = @bitCast(sx);
    const m: @Vector(4, u32) = @splat(0xff);
    const S = @Vector(4, u5);
    const v = ((w & m) << @as(S, @splat(18))) |
        (((w >> @as(S, @splat(8))) & m) << @as(S, @splat(12))) |
        (((w >> @as(S, @splat(16))) & m) << @as(S, @splat(6))) |
        (w >> @as(S, @splat(24)));
    const bytes: V8 = @bitCast(v);
    out.* = @shuffle(u8, bytes, undefined, [12]i32{ 2, 1, 0, 6, 5, 4, 10, 9, 8, 14, 13, 12 });
}

pub fn Codec(comptime alphabet: Alphabet, comptime padding: bool) type {
    return struct {
        const c62: u8 = switch (alphabet) {
            .standard => '+',
            .url_safe => '-',
        };
        const c63: u8 = switch (alphabet) {
            .standard => '/',
            .url_safe => '_',
        };
        // After the first three ranges a sextet v ≥ 62 sits at v - 4.
        const delta62: u8 = c62 -% (62 - 4);
        const delta63: u8 = c63 -% c62 -% 1;

        pub const alphabet_kind = alphabet;
        pub const pads = padding;

        /// One sextet (0..63) to its character, branch- and table-free.
        inline fn sextet(v: u8) u8 {
            var c: u8 = v +% 'A';
            c +%= ge(v, 26) & 6; // 'a' - 'A' - 26
            c +%= ge(v, 52) & @as(u8, @bitCast(@as(i8, -75))); // '0' - 'a' - 26
            c +%= ge(v, 62) & delta62;
            c +%= ge(v, 63) & delta63;
            return c;
        }

        /// One character to its sextet; `valid` gets 0xff ANDed out when it
        /// is not in the alphabet (the sextet is then 0).
        inline fn value(c: u8, valid: *u8) u8 {
            const up = inRange(c, 'A', 'Z');
            const lo = inRange(c, 'a', 'z');
            const dg = inRange(c, '0', '9');
            const s62 = inRange(c, c62, c62);
            const s63 = inRange(c, c63, c63);
            valid.* &= up | lo | dg | s62 | s63;
            return (up & (c -% 'A')) | (lo & (c -% 71)) | (dg & (c +% 4)) | (s62 & 62) | (s63 & 63);
        }

        /// 0xff when `c` is a character of this alphabet.
        inline fn isAlphabet(c: u8) u8 {
            var v: u8 = 0xff;
            _ = value(c, &v);
            return v;
        }

        // ── encoding ────────────────────────────────────────────────────────

        /// Length of the encoding of `n` octets. (It exceeds `usize` only
        /// for an `n` above 3/4 of the address space — no slice that long
        /// exists.)
        pub fn encodedLen(n: usize) usize {
            if (padding) return n / 3 * 4 + @as(usize, if (n % 3 != 0) 4 else 0);
            return n / 3 * 4 + (n % 3 * 4 + 2) / 3;
        }

        /// Encodes `src` into the front of `out` and returns the written
        /// slice. Panics, in every build mode, when `out.len <
        /// encodedLen(src.len)` — std only asserts, which ReleaseFast drops.
        pub fn encode(out: []u8, src: []const u8) []const u8 {
            const len = encodedLen(src.len);
            if (out.len < len) @panic("b64ct.encode: output buffer shorter than encodedLen");
            var o: usize = 0;
            var i: usize = 0;
            while (i + 3 <= src.len) : (i += 3) {
                const a = src[i];
                const b = src[i + 1];
                const c = src[i + 2];
                out[o] = sextet(a >> 2);
                out[o + 1] = sextet(((a & 3) << 4) | (b >> 4));
                out[o + 2] = sextet(((b & 15) << 2) | (c >> 6));
                out[o + 3] = sextet(c & 63);
                o += 4;
            }
            switch (src.len - i) {
                0 => {},
                1 => {
                    const a = src[i];
                    out[o] = sextet(a >> 2);
                    out[o + 1] = sextet((a & 3) << 4);
                    if (padding) {
                        out[o + 2] = '=';
                        out[o + 3] = '=';
                    }
                },
                2 => {
                    const a = src[i];
                    const b = src[i + 1];
                    out[o] = sextet(a >> 2);
                    out[o + 1] = sextet(((a & 3) << 4) | (b >> 4));
                    out[o + 2] = sextet((b & 15) << 2);
                    if (padding) out[o + 3] = '=';
                },
                else => unreachable,
            }
            return out[0..len];
        }

        /// Length of `encodeWrapped`'s output: the encoding plus one line
        /// ending after every line, the last one included; 0 for no input.
        pub fn encodedWrappedLen(n: usize, comptime line_len: usize, eol: LineEnding) usize {
            checkLineLen(line_len);
            const e = encodedLen(n);
            if (e == 0) return 0;
            return e + (e + line_len - 1) / line_len * eol.bytes().len;
        }

        fn checkLineLen(comptime line_len: usize) void {
            if (line_len == 0 or line_len % 4 != 0)
                @compileError("b64ct: line_len must be a positive multiple of 4");
        }

        /// Encodes `src` in lines of `line_len` characters (a positive
        /// multiple of 4, checked at compile time: PEM's 64, MIME's 76), each
        /// one terminated by `eol`. Panics, in every build mode, when
        /// `out.len < encodedWrappedLen(...)`. The line layout depends only
        /// on `src.len`.
        pub fn encodeWrapped(out: []u8, src: []const u8, comptime line_len: usize, eol: LineEnding) []const u8 {
            const total = encodedWrappedLen(src.len, line_len, eol);
            if (out.len < total) @panic("b64ct.encodeWrapped: output buffer shorter than encodedWrappedLen");
            const per_line = line_len / 4 * 3;
            const e = eol.bytes();
            var o: usize = 0;
            var i: usize = 0;
            while (i < src.len) {
                const take = @min(per_line, src.len - i);
                o += encode(out[o..], src[i..][0..take]).len;
                @memcpy(out[o..][0..e.len], e);
                o += e.len;
                i += take;
            }
            std.debug.assert(o == total);
            return out[0..total];
        }

        /// `encode` into a new allocation of exactly `encodedLen(src.len)`.
        pub fn encodeAlloc(gpa: std.mem.Allocator, src: []const u8) std.mem.Allocator.Error![]u8 {
            const out = try gpa.alloc(u8, encodedLen(src.len));
            _ = encode(out, src);
            return out;
        }

        // ── decoding ────────────────────────────────────────────────────────

        /// An upper bound on what `n` input characters decode to, for any
        /// decoder here (ignored characters included in `n`).
        pub fn maxDecodedLen(n: usize) usize {
            return n / 4 * 3 + (n % 4 * 3) / 4;
        }

        /// Number of `=` among the last two characters `c d`, as std's
        /// `calcSizeForSlice` counts them: in a valid text only `==` and `x=`
        /// occur, and in `=x` the `=` stays in the data, where it is an invalid
        /// character whatever the count says. Computed with masks; the count
        /// is public — it follows from the decoded length.
        inline fn padCount(c: u8, d: u8) usize {
            return public(u8, (inRange(d, '=', '=') & 1) + (inRange(c, '=', '=') & 1));
        }

        /// Exact decoded length of `src` for `decode` (no ignored
        /// characters), or `InvalidPadding` for a length the variant cannot
        /// have: not a multiple of 4 when padded, ≡ 1 (mod 4) when not. Reads
        /// only the length and, when padded, whether the last two
        /// characters are `=`.
        pub fn decodedLen(src: []const u8) Error!usize {
            const n = src.len;
            if (padding) {
                if (n % 4 != 0) return error.InvalidPadding;
                if (n == 0) return 0;
                return n / 4 * 3 - padCount(src[n - 2], src[n - 1]);
            }
            if (n % 4 == 1) return error.InvalidPadding;
            return n / 4 * 3 + (n % 4 * 3) / 4;
        }

        /// Decodes the four characters of a full data quantum into 3 octets.
        inline fn quad(out: *[3]u8, q: [4]u8, valid: *u8) void {
            const a = value(q[0], valid);
            const b = value(q[1], valid);
            const c = value(q[2], valid);
            const d = value(q[3], valid);
            out[0] = (a << 2) | (b >> 4);
            out[1] = (b << 4) | (c >> 2);
            out[2] = (c << 6) | d;
        }

        /// Decodes a final partial quantum of 2 or 3 data characters; returns
        /// the unused low bits of its last character (must be zero).
        inline fn tail(out: []u8, t: []const u8, valid: *u8) u8 {
            const a = value(t[0], valid);
            const b = value(t[1], valid);
            out[0] = (a << 2) | (b >> 4);
            if (t.len == 2) return b & 15;
            const c = value(t[2], valid);
            out[1] = (b << 4) | (c >> 2);
            return c & 3;
        }

        /// The verdict, once: invalid character first, then stray bits.
        inline fn verdict(valid: u8, stray: u8) Error!void {
            // 0: ok · 1: stray bits · 2,3: bad character.
            const bad: u8 = (~valid & 2) | (~eqMask(stray, 0) & 1);
            switch (public(u8, bad)) {
                0 => {},
                1 => return error.InvalidPadding,
                else => return error.InvalidCharacter,
            }
        }

        /// 16 characters to their sextets; `valid` gets 0x00 ANDed into the
        /// lane of every character outside the alphabet. `value`, lane-wise.
        inline fn values16(c: V8, valid: *V8) V8 {
            const up = mask16(c -% splat('A') <= splat(25));
            const lo = mask16(c -% splat('a') <= splat(25));
            const dg = mask16(c -% splat('0') <= splat(9));
            const s62 = mask16(c == splat(c62));
            const s63 = mask16(c == splat(c63));
            valid.* &= up | lo | dg | s62 | s63;
            return (up & (c -% splat('A'))) | (lo & (c -% splat(71))) | (dg & (c +% splat(4))) |
                (s62 & splat(62)) | (s63 & splat(63));
        }

        /// Decodes the unpadded data characters `body` into `out[0..n]`
        /// (n = maxDecodedLen(body.len), body.len % 4 != 1).
        fn decodeBody(out: []u8, body: []const u8) Error!void {
            var valid: u8 = 0xff;
            var o: usize = 0;
            var i: usize = 0;
            if (simd) {
                var vvalid: V8 = @splat(0xff);
                while (i + 16 <= body.len) : ({
                    i += 16;
                    o += 12;
                }) pack16(out[o..][0..12], values16(body[i..][0..16].*, &vvalid));
                valid = @reduce(.And, vvalid);
            }
            while (i + 4 <= body.len) : (i += 4) {
                quad(out[o..][0..3], body[i..][0..4].*, &valid);
                o += 3;
            }
            var stray: u8 = 0;
            if (body.len - i >= 2) stray = tail(out[o..], body[i..], &valid);
            try verdict(valid, stray);
        }

        /// Decodes `src` (no whitespace or other characters between) into the
        /// front of `out` and returns the written slice. Accepts exactly the
        /// canonical encodings of this variant, as libsodium and
        /// `std.base64` do. `NoSpaceLeft` when `out.len < decodedLen(src)`.
        /// On any error, nothing derived from `src` is left in `out`.
        pub fn decode(out: []u8, src: []const u8) Error![]u8 {
            const len = try decodedLen(src);
            if (out.len < len) return error.NoSpaceLeft;
            const body_len = if (padding) src.len - (src.len / 4 * 3 - len) else src.len;
            decodeBody(out[0..len], src[0..body_len]) catch |e| {
                std.crypto.secureZero(u8, out[0..len]);
                return e;
            };
            return out[0..len];
        }

        /// `decode` over `buf` itself (RustCrypto base64ct's
        /// `decode_in_place`): the decoded octets end up at its front. Every
        /// decoder here writes behind what it has read, so `out` may be `src`
        /// for `decodeIgnoring` and `decodePrefix` too.
        pub fn decodeInPlace(buf: []u8) Error![]u8 {
            return decode(buf, buf);
        }

        /// `decode` into a new allocation of exactly the decoded length.
        pub fn decodeAlloc(gpa: std.mem.Allocator, src: []const u8) (Error || std.mem.Allocator.Error)![]u8 {
            const out = try gpa.alloc(u8, try decodedLen(src));
            errdefer gpa.free(out);
            _ = try decode(out, src);
            return out;
        }

        /// 0xff when `c` is one of `ignore`.
        inline fn inSet(c: u8, ignore: []const u8) u8 {
            var m: u8 = 0;
            for (ignore) |x| m |= eqMask(c, x);
            return m;
        }

        /// What one pass over `src` under libsodium's rules found and wrote:
        /// the data (alphabet characters, the non-alphabet characters of
        /// `ignore` skipped), then — padded variants — the `=` the data's
        /// length requires, any `ignore` character allowed between them, then
        /// any `ignore` characters after.
        ///
        /// Every branch here is on a public decision: a character in the
        /// data is an alphabet character whatever its value, so being told so
        /// says nothing about the key; where the data stops, where the `=`
        /// are and which characters are skipped is the text's layout.
        const Run = struct {
            /// Octets written to `out`.
            len: usize,
            /// Alphabet characters in the data.
            data: usize,
            /// After the padding and the trailing ignored characters.
            end: usize,
            /// End of the data (alphabet + skipped characters).
            data_end: usize,
            /// The padding the data's length requires is all there.
            pad_ok: bool,
            /// `out` was too short; nothing past what fitted was written.
            overflow: bool,
            /// The unused low bits of the last data character.
            stray: u8,
        };

        fn run(out: []u8, src: []const u8, ignore: []const u8) Run {
            var q: [4]u8 = undefined;
            defer std.crypto.secureZero(u8, &q);
            var n: usize = 0;
            var o: usize = 0;
            var data: usize = 0;
            var overflow = false;
            var unused: u8 = 0xff; // every data character is alphabet: checked, public
            var i: usize = 0;
            while (i < src.len) {
                // 16 alphabet characters at a quantum boundary — every line
                // of a wrapped body but its last — in one step.
                if (simd and n == 0 and src.len - i >= 16) {
                    var vvalid: V8 = @splat(0xff);
                    const sx = values16(src[i..][0..16].*, &vvalid);
                    if (public(u8, @reduce(.And, vvalid)) == 0xff) {
                        if (!overflow and out.len - o >= 12) {
                            pack16(out[o..][0..12], sx);
                            o += 12;
                        } else overflow = true;
                        data += 16;
                        i += 16;
                        continue;
                    }
                }
                const c = src[i];
                if (public(u8, isAlphabet(c)) != 0) {
                    q[n] = c;
                    n += 1;
                    data += 1;
                    if (n == 4) {
                        if (!overflow and out.len - o >= 3) {
                            quad(out[o..][0..3], q, &unused);
                            o += 3;
                        } else overflow = true;
                        n = 0;
                    }
                } else if (public(u8, inSet(c, ignore)) == 0) break;
                i += 1;
            }
            var r: Run = .{ .len = o, .data = data, .end = i, .data_end = i, .pad_ok = true, .overflow = overflow, .stray = 0 };
            if (n >= 2) {
                if (!overflow and out.len - o >= n - 1) {
                    r.stray = tail(out[o..], q[0..n], &unused);
                    r.len += n - 1;
                } else r.overflow = true;
            }
            if (padding) {
                // libsodium's `_sodium_base642bin_skip_padding` (a data
                // length ≡ 1 mod 4 is refused whatever this finds).
                var need = (4 - data % 4) % 4;
                while (need > 0) : (i += 1) {
                    if (i == src.len) {
                        r.pad_ok = false;
                        break;
                    }
                    if (public(u8, inRange(src[i], '=', '=')) != 0) {
                        need -= 1;
                    } else if (public(u8, inSet(src[i], ignore)) == 0) {
                        r.pad_ok = false;
                        break;
                    }
                }
                // ⚠ libsodium skips ANY `ignore` character here, an
                // alphabet one included (after the padding no data follows).
                if (r.pad_ok) while (i < src.len and public(u8, inSet(src[i], ignore)) != 0) {
                    i += 1;
                };
                r.end = i;
            }
            return r;
        }

        /// The verdict on a `run` whose input ends where the caller wants it
        /// to; wipes what the run wrote on any error.
        fn finish(out: []u8, r: Run) Error![]u8 {
            errdefer std.crypto.secureZero(u8, out[0..r.len]);
            if (r.data % 4 == 1 or !r.pad_ok) return error.InvalidPadding;
            if (r.overflow) return error.NoSpaceLeft;
            try verdict(0xff, r.stray);
            return out[0..r.len];
        }

        /// `decode`, skipping the characters of `ignore` (`pem_whitespace`
        /// for a PEM body or a wrapped config value), under libsodium's rules
        /// (`sodium_base642bin` with `b64_end` NULL): inside the data only
        /// characters outside the alphabet are skipped, between and after the
        /// `=` every one of `ignore` is. With `pem_whitespace` that is
        /// `decode` of the text with its whitespace removed.
        ///
        /// Public, beyond `decode`'s: which characters are skipped, and — on
        /// a rejected input — where the first character that is neither
        /// alphabet nor ignored stands (the scan stops there, as libsodium's
        /// does). `NoSpaceLeft` when `out` cannot hold the decoded data
        /// (`maxDecodedLen(src.len)` always can); on any error nothing derived
        /// from `src` is left in `out` (decoding in place, the undecoded text
        /// is the caller's input and stays). Unpadded variants return std's
        /// error for the text with the ignored characters removed, for an
        /// `ignore` holding no alphabet character.
        pub fn decodeIgnoring(out: []u8, src: []const u8, ignore: []const u8) Error![]u8 {
            const r = run(out, src, ignore);
            if (r.end != src.len) {
                std.crypto.secureZero(u8, out[0..r.len]);
                if (!padding) {
                    // std checks the length before any character.
                    var m = r.data;
                    for (src[r.data_end..]) |c| {
                        if (public(u8, isAlphabet(c) | ~inSet(c, ignore)) != 0) m += 1;
                    }
                    if (m % 4 == 1) return error.InvalidPadding;
                    return error.InvalidCharacter;
                }
                if (r.data % 4 == 1 or !r.pad_ok) return error.InvalidPadding;
                return error.InvalidCharacter;
            }
            return finish(out, r);
        }

        /// libsodium's `sodium_base642bin` with `b64_end`: decodes the
        /// longest prefix of `src` made of alphabet characters and skipped
        /// `ignore` characters, then — padded variants — exactly the `=` its
        /// length requires (`ignore` characters allowed between them), then
        /// any `ignore` characters after; whatever follows is left for the
        /// caller. Where it stops is public. `InvalidPadding` when the data
        /// has an impossible length or lacks its padding.
        pub fn decodePrefix(out: []u8, src: []const u8, ignore: []const u8) Error!Prefix {
            const r = run(out, src, ignore);
            return .{ .data = try finish(out, r), .consumed = r.end };
        }
    };
}

// ── tests ───────────────────────────────────────────────────────────────────

const testing = std.testing;

test {
    _ = @import("fuzz.zig");
}

/// (ours, std's) codec pairs, in libsodium's variant order.
const pairs = .{
    .{ standard, std.base64.standard },
    .{ standard_no_pad, std.base64.standard_no_pad },
    .{ url_safe, std.base64.url_safe },
    .{ url_safe_no_pad, std.base64.url_safe_no_pad },
};

test "RFC 4648 §10 test vectors, every variant" {
    const vectors = [_][2][]const u8{
        .{ "", "" },
        .{ "f", "Zg==" },
        .{ "fo", "Zm8=" },
        .{ "foo", "Zm9v" },
        .{ "foob", "Zm9vYg==" },
        .{ "fooba", "Zm9vYmE=" },
        .{ "foobar", "Zm9vYmFy" },
    };
    inline for (.{ standard, url_safe }) |C| for (vectors) |v| {
        var buf: [16]u8 = undefined;
        try testing.expectEqualStrings(v[1], C.encode(&buf, v[0]));
        var dec: [16]u8 = undefined;
        try testing.expectEqualStrings(v[0], try C.decode(&dec, v[1]));
    };
    inline for (.{ standard_no_pad, url_safe_no_pad }) |C| for (vectors) |v| {
        const want = std.mem.trimEnd(u8, v[1], "=");
        var buf: [16]u8 = undefined;
        try testing.expectEqualStrings(want, C.encode(&buf, v[0]));
        var dec: [16]u8 = undefined;
        try testing.expectEqualStrings(v[0], try C.decode(&dec, want));
    };
}

test "sextets 62 and 63 differ between the alphabets (RFC 4648 §4 vs §5)" {
    var buf: [8]u8 = undefined;
    try testing.expectEqualStrings("+/8=", standard.encode(&buf, "\xfb\xff"));
    try testing.expectEqualStrings("-_8=", url_safe.encode(&buf, "\xfb\xff"));
    try testing.expectEqualStrings("-_8", url_safe_no_pad.encode(&buf, "\xfb\xff"));
    var out: [4]u8 = undefined;
    try testing.expectError(error.InvalidCharacter, standard.decode(&out, "-_8="));
    try testing.expectError(error.InvalidCharacter, url_safe.decode(&out, "+/8="));
    try testing.expectEqualSlices(u8, "\xfb\xff", try url_safe.decode(&out, "-_8="));
}

test "encode is byte-identical to std for every variant, length 0..300 and byte value" {
    var src: [300]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i *% 157 +% 11);
    var all: [256]u8 = undefined;
    for (&all, 0..) |*b, i| b.* = @intCast(i);
    inline for (pairs) |p| {
        const C = p[0];
        const S = p[1];
        for ([_][]const u8{ &src, &all }) |s| {
            for (0..s.len + 1) |n| {
                var ours: [400]u8 = undefined;
                var theirs: [400]u8 = undefined;
                try testing.expectEqual(S.Encoder.calcSize(n), C.encodedLen(n));
                try testing.expectEqualStrings(S.Encoder.encode(&theirs, s[0..n]), C.encode(&ours, s[0..n]));
                var dec: [300]u8 = undefined;
                try testing.expectEqual(n, try C.decodedLen(ours[0..C.encodedLen(n)]));
                try testing.expectEqualSlices(u8, s[0..n], try C.decode(&dec, ours[0..C.encodedLen(n)]));
            }
        }
    }
}

/// std's verdict on `s`: the decoded bytes, or its error.
fn stdDecode(comptime S: anytype, buf: []u8, s: []const u8) Error![]const u8 {
    const n = try S.Decoder.calcSizeForSlice(s);
    if (n > buf.len) return error.NoSpaceLeft;
    try S.Decoder.decode(buf[0..n], s);
    return buf[0..n];
}

test "decode accepts exactly what std accepts, with the same bytes (and, unpadded, the same error)" {
    // Every character value in every position of every final-quantum shape
    // after one full quantum — `=` included, so every padding shape is hit.
    // std's padded decoder names the FIRST fault by position (and compares
    // the character after a `=` with 0xff where it means its table entry),
    // which a decoder that does not branch per character cannot reproduce;
    // for padded variants only the verdict and the bytes are std's.
    inline for (pairs) |p| {
        const C = p[0];
        const S = p[1];
        const tails = if (C.pads)
            [_][]const u8{ "QUJD", "QUI=", "QQ==" }
        else
            [_][]const u8{ "QUJD", "QUI", "QQ" };
        for (tails) |t| for (0..t.len) |pos| for (0..256) |cv| {
            var s: [8]u8 = undefined;
            @memcpy(s[0..4], "QUJD");
            @memcpy(s[4..][0..t.len], t);
            s[4 + pos] = @intCast(cv);
            const src = s[0 .. 4 + t.len];
            var ours: [6]u8 = undefined;
            var theirs: [6]u8 = undefined;
            const r_theirs = stdDecode(S, &theirs, src);
            const r_ours = C.decode(&ours, src);
            if (r_theirs) |want| {
                try testing.expectEqualSlices(u8, want, try r_ours);
            } else |e| if (C.pads)
                try testing.expect(std.meta.isError(r_ours))
            else
                try testing.expectError(e, r_ours);
        };
    }
}

test "decode rejects every malformed padding std rejects" {
    const cases = [_][]const u8{ "Q", "QU", "QUJ", "Q===", "QU=D", "=QUJ", "====", "QUJDQ===", "QQ==QUJD", "QQ=", "QUI==" };
    for (cases) |s| {
        var ours: [12]u8 = undefined;
        var theirs: [12]u8 = undefined;
        const r_theirs = stdDecode(std.base64.standard, &theirs, s);
        const r_ours = standard.decode(&ours, s);
        if (r_theirs) |_| return error.TestUnexpectedResult else |_| try testing.expect(std.meta.isError(r_ours));
    }
}

test "decode: NoSpaceLeft below the exact length, and nothing secret left in out on error" {
    var out: [6]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, standard.decode(out[0..2], "QUJD"));
    try testing.expectEqualSlices(u8, "ABC", try standard.decode(out[0..3], "QUJD"));
    try testing.expectEqualSlices(u8, "AB", try standard.decode(out[0..2], "QUI="));
    // A bad character in the second quantum: the first quantum was decoded
    // into `out` before the verdict, and must be gone.
    @memset(&out, 0xaa);
    try testing.expectError(error.InvalidCharacter, standard.decode(&out, "QUJDQU!D"));
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0 }, &out);
    // decodeIgnoring rejects a bad character before it writes anything; a
    // stray bit ('J' = 9 leaves 1 in the unused low bits) only after.
    @memset(&out, 0xaa);
    try testing.expectError(error.InvalidPadding, standard.decodeIgnoring(&out, "QUJD\nQUJ=", pem_whitespace));
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0 }, out[0..5]);
}

test "decoding in place: out aliasing src, every variant and length 0..120" {
    var src: [120]u8 = undefined;
    for (&src, 0..) |*x, i| x.* = @truncate(i *% 113 +% 5);
    inline for (pairs) |p| {
        const C = p[0];
        for (0..src.len + 1) |n| {
            var buf: [200]u8 = undefined;
            const e = C.encode(&buf, src[0..n]);
            try testing.expectEqualSlices(u8, src[0..n], try C.decodeInPlace(buf[0..e.len]));
            // Wrapped at 16 (the vector step) and decoded over itself.
            var w: [240]u8 = undefined;
            const wrapped = C.encodeWrapped(&w, src[0..n], 16, .crlf);
            try testing.expectEqualSlices(u8, src[0..n], try C.decodeIgnoring(w[0..wrapped.len], wrapped, pem_whitespace));
        }
    }
}

test "the 16-lane path: every byte value in every lane, against std" {
    // 20 characters, so `decode` takes one vector step and `decodeIgnoring`
    // one block before the scalar tail; the varied character sits in the block.
    const base = "QUJDQUJDQUJDQUJDQUJD"; // "ABC" × 5
    inline for (pairs) |p| {
        const C = p[0];
        const S = p[1];
        for (0..16) |pos| for (0..256) |cv| {
            var s: [20]u8 = base.*;
            s[pos] = @intCast(cv);
            var ours: [15]u8 = undefined;
            var theirs: [15]u8 = undefined;
            const want = stdDecode(S, &theirs, &s);
            const r_dec = C.decode(&ours, &s);
            if (want) |w| {
                try testing.expectEqualSlices(u8, w, try r_dec);
                try testing.expectEqualSlices(u8, w, try C.decodeIgnoring(&ours, &s, ""));
            } else |_| {
                try testing.expect(std.meta.isError(r_dec));
                try testing.expect(std.meta.isError(C.decodeIgnoring(&ours, &s, "")));
            }
        };
    }
}

test "decodeIgnoring: one ignored character anywhere in a long text, quantum boundary or not" {
    var src: [90]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i *% 37 +% 1);
    inline for (pairs) |p| {
        const C = p[0];
        var enc: [128]u8 = undefined;
        const e = C.encode(&enc, &src);
        for (0..e.len + 1) |at| {
            var t: [129]u8 = undefined;
            @memcpy(t[0..at], e[0..at]);
            t[at] = '\n';
            @memcpy(t[at + 1 ..][0 .. e.len - at], e[at..]);
            var dec: [90]u8 = undefined;
            try testing.expectEqualSlices(u8, &src, try C.decodeIgnoring(&dec, t[0 .. e.len + 1], "\n"));
            const r = try C.decodePrefix(&dec, t[0 .. e.len + 1], "\n");
            try testing.expectEqualSlices(u8, &src, r.data);
            try testing.expectEqual(e.len + 1, r.consumed);
        }
    }
}

test "decodeIgnoring: rejected after octets were written, and they are gone" {
    var out: [12]u8 = undefined;
    @memset(&out, 0xaa);
    // Two quanta decoded, then a character neither alphabet nor ignored.
    try testing.expectError(error.InvalidCharacter, standard.decodeIgnoring(&out, "QUJDQUJD!", ""));
    try testing.expectEqualSlices(u8, &@as([6]u8, @splat(0)), out[0..6]);
    @memset(&out, 0xaa);
    try testing.expectError(error.InvalidCharacter, standard_no_pad.decodeIgnoring(&out, "QUJDQUJD!QUI", ""));
    try testing.expectEqualSlices(u8, &@as([6]u8, @splat(0)), out[0..6]);
}

test "every decoder wipes what it wrote on every error path" {
    var out: [12]u8 = undefined;
    // decodePrefix, stray bits after two decoded quanta.
    @memset(&out, 0xaa);
    try testing.expectError(error.InvalidPadding, standard.decodePrefix(&out, "QUJDQUJ=;", ""));
    try testing.expectEqualSlices(u8, &@as([5]u8, @splat(0)), out[0..5]);
    // decodePrefix, missing padding after decoded data.
    @memset(&out, 0xaa);
    try testing.expectError(error.InvalidPadding, standard.decodePrefix(&out, "QUJDQUI;", ""));
    try testing.expectEqualSlices(u8, &@as([5]u8, @splat(0)), out[0..5]);
    // NoSpaceLeft after the part that fitted was written.
    @memset(&out, 0xaa);
    try testing.expectError(error.NoSpaceLeft, standard.decodeIgnoring(out[0..4], "QUJDQUJD", ""));
    try testing.expectEqualSlices(u8, &@as([3]u8, @splat(0)), out[0..3]);
    try testing.expectEqual(@as(u8, 0xaa), out[3]); // never written
}

test "maxDecodedLen is the exact length of an unpadded text and bounds every other" {
    const want = [_]usize{ 0, 0, 1, 2, 3, 3, 4, 5, 6 };
    for (want, 0..) |w, n| try testing.expectEqual(w, standard.maxDecodedLen(n));
    for (0..100) |k| {
        try testing.expectEqual(k, standard_no_pad.maxDecodedLen(standard_no_pad.encodedLen(k)));
        try testing.expect(standard.maxDecodedLen(standard.encodedLen(k)) >= k);
    }
}

test "decodedLen counts padding as std's calcSizeForSlice does" {
    for ([_][]const u8{ "", "QUJD", "QUI=", "QQ==", "QU=D", "Q===", "====", "QUJDQQ==" }) |s|
        try testing.expectEqual(try std.base64.standard.Decoder.calcSizeForSlice(s), try standard.decodedLen(s));
    try testing.expectError(error.InvalidPadding, standard.decodedLen("QUJ"));
}

test "decodeAlloc / encodeAlloc allocate exactly" {
    const gpa = testing.allocator;
    const e = try url_safe_no_pad.encodeAlloc(gpa, "\xfb\xff\x00");
    defer gpa.free(e);
    try testing.expectEqualStrings("-_8A", e);
    const d = try url_safe_no_pad.decodeAlloc(gpa, e);
    defer gpa.free(d);
    try testing.expectEqualSlices(u8, "\xfb\xff\x00", d);
    try testing.expectError(error.InvalidCharacter, standard.decodeAlloc(gpa, "QU!D"));
    try testing.expectError(error.InvalidPadding, standard.decodeAlloc(gpa, "QUJ"));
}

test "encodeWrapped: PEM and MIME layouts, every length 0..200" {
    var src: [200]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    inline for (.{ 4, 64, 76 }) |ll| for ([_]LineEnding{ .lf, .crlf }) |eol| for (0..src.len + 1) |n| {
        var w: [512]u8 = undefined;
        const wrapped = standard.encodeWrapped(&w, src[0..n], ll, eol);
        try testing.expectEqual(standard.encodedWrappedLen(n, ll, eol), wrapped.len);
        // Joining the lines gives `encode`; every line but the last is full.
        var flat: [300]u8 = undefined;
        const want = standard.encode(&flat, src[0..n]);
        var joined: [300]u8 = undefined;
        var j: usize = 0;
        var lines = std.mem.splitSequence(u8, wrapped, eol.bytes());
        var count: usize = 0;
        while (lines.next()) |line| {
            if (line.len == 0) break;
            count += 1;
            try testing.expect(line.len <= ll);
            if (j + line.len < want.len) try testing.expectEqual(ll, line.len);
            @memcpy(joined[j..][0..line.len], line);
            j += line.len;
        }
        try testing.expectEqualStrings(want, joined[0..j]);
        try testing.expectEqual((want.len + ll - 1) / ll, count);
        if (n > 0) try testing.expect(std.mem.endsWith(u8, wrapped, eol.bytes()));
        var dec: [200]u8 = undefined;
        try testing.expectEqualSlices(u8, src[0..n], try standard.decodeIgnoring(&dec, wrapped, pem_whitespace));
    };
}

test "decodeIgnoring equals decode of the text with the ignored characters removed" {
    var src: [40]u8 = undefined;
    for (&src, 0..) |*b, i| b.* = @truncate(i *% 89 +% 3);
    inline for (pairs) |p| {
        const C = p[0];
        for (0..src.len + 1) |n| {
            var enc: [64]u8 = undefined;
            const e = C.encode(&enc, src[0..n]);
            // A space before every character position in turn, and one
            // newline after every third — padding included.
            for (0..e.len + 1) |at| {
                var t: [128]u8 = undefined;
                var k: usize = 0;
                for (e, 0..) |c, idx| {
                    if (idx == at) {
                        t[k] = ' ';
                        k += 1;
                    }
                    t[k] = c;
                    k += 1;
                    if (idx % 3 == 2) {
                        t[k] = '\n';
                        k += 1;
                    }
                }
                if (at == e.len) {
                    t[k] = '\t';
                    k += 1;
                }
                var dec: [40]u8 = undefined;
                try testing.expectEqualSlices(u8, src[0..n], try C.decodeIgnoring(&dec, t[0..k], pem_whitespace));
                // Only newlines ignored: the space or tab is a bad character, or
                // makes the length impossible — either way, rejected.
                try testing.expect(std.meta.isError(C.decodeIgnoring(&dec, t[0..k], "\n")));
            }
        }
    }
}

test "decodeIgnoring: alphabet characters and = in the ignore set, as libsodium reads them" {
    var out: [8]u8 = undefined;
    // Inside the data an alphabet character is data even when it is in the
    // set: "QUJD" + "A" → length ≡ 1 (mod 4).
    try testing.expectError(error.InvalidPadding, standard.decodeIgnoring(&out, "QUJDA", "A"));
    try testing.expectEqualSlices(u8, "ABC", try standard.decodeIgnoring(&out, "QUJD", "A"));
    // After the padding every character of the set is skipped, alphabet ones too.
    try testing.expectEqualSlices(u8, "A", try standard.decodeIgnoring(&out, "QQ==A", "A"));
    // '=' in a padded variant's set is skipped inside the data, so the
    // padding the data then needs is missing — or not needed at all.
    try testing.expectError(error.InvalidPadding, standard.decodeIgnoring(&out, "QUI=", "="));
    try testing.expectEqualSlices(u8, "ABC", try standard.decodeIgnoring(&out, "QU=JD===", "="));
    // Unpadded variants: '=' is not part of the encoding and may be ignored.
    try testing.expectEqualSlices(u8, "AB", try standard_no_pad.decodeIgnoring(&out, "QUI=", "="));
    try testing.expectError(error.InvalidCharacter, standard_no_pad.decodeIgnoring(&out, "QUI=", ""));
}

test "decodeIgnoring: NoSpaceLeft, and a short output is never written past" {
    var out: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, standard.decodeIgnoring(out[0..5], "QUJD\nQUJD\n", "\n"));
    try testing.expectEqualSlices(u8, "ABCAB", try standard.decodeIgnoring(out[0..5], "QUJD\nQUI=\n", "\n"));
    try testing.expectError(error.NoSpaceLeft, standard_no_pad.decodeIgnoring(out[0..4], "QUJDQUI", ""));
    try testing.expectEqualSlices(u8, "ABCAB", try standard_no_pad.decodeIgnoring(out[0..5], "QUJDQUI", ""));
}

test "decodePrefix: stops where libsodium's b64_end does" {
    var out: [16]u8 = undefined;
    {
        const r = try standard.decodePrefix(&out, "QUJD\nQUI=\n-----END", "\n");
        try testing.expectEqualSlices(u8, "ABCAB", r.data);
        try testing.expectEqual(@as(usize, 10), r.consumed);
    }
    {
        // Ignored characters between the padding characters.
        const r = try standard.decodePrefix(&out, "QQ= =;rest", " ");
        try testing.expectEqualSlices(u8, "A", r.data);
        try testing.expectEqual(@as(usize, 5), r.consumed);
    }
    {
        const r = try standard_no_pad.decodePrefix(&out, "QUI.QUJD", "");
        try testing.expectEqualSlices(u8, "AB", r.data);
        try testing.expectEqual(@as(usize, 3), r.consumed);
    }
    {
        // Nothing decodable at all: an empty prefix.
        const r = try url_safe.decodePrefix(&out, "!x", "");
        try testing.expectEqual(@as(usize, 0), r.data.len);
        try testing.expectEqual(@as(usize, 0), r.consumed);
    }
    try testing.expectError(error.InvalidPadding, standard.decodePrefix(&out, "QUI;", ""));
    try testing.expectError(error.InvalidPadding, standard.decodePrefix(&out, "QUIDQ=", ""));
    try testing.expectError(error.InvalidPadding, standard.decodePrefix(&out, "QQ=", ""));
    try testing.expectError(error.InvalidPadding, url_safe_no_pad.decodePrefix(&out, "Q!", ""));
}
