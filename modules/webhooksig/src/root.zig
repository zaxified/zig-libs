// SPDX-License-Identifier: MIT

//! webhooksig — webhook signature signing and verification, plus a
//! `router` middleware that gates inbound webhooks on a valid signature.
//!
//! Four schemes:
//!   - **prefixed** (GitHub `X-Hub-Signature-256: sha256=<hex>`, legacy
//!     `sha1=`, Shopify-style base64): one `<prefix><mac>` value, MAC over
//!     the body; digest SHA-1/SHA-256/SHA-512, hex or base64 (`Format`).
//!   - **Standard Webhooks** (`standard`, the Svix scheme): `webhook-id`,
//!     `webhook-timestamp`, `webhook-signature`; MAC over
//!     `id.timestamp.body`, `v1,<base64>` (HMAC-SHA256, `whsec_` secrets)
//!     and `v1a,<base64>` (Ed25519, `whpk_`/`whsk_` keys).
//!   - **Stripe** (`stripe`): `Stripe-Signature: t=<ts>,v1=<hex>`, MAC over
//!     `ts.body`.
//!   - **Slack** (`slack`): `X-Slack-Signature: v0=<hex>` over
//!     `v0:ts:body`, with `X-Slack-Request-Timestamp`.
//!
//! The timestamped schemes refuse a timestamp more than `tolerance_s`
//! (default 300 s, as every reference does) away from a caller-supplied
//! `now` in either direction — the module has no clock of its own (`Clock`
//! carries one into the middleware).
//!
//! The sender computes `HMAC-SHA256(secret, raw_body)` and presents it in
//! a header, e.g. `X-Signature-256: sha256=<hex-lowercase>` (GitHub) — the
//! header name and the `sha256=` prefix are configurable. The receiver
//! recomputes the MAC over the exact bytes it received and compares in
//! **constant time** (`std.crypto.timing_safe.eql` over the fixed-size raw
//! MAC — never `std.mem.eql` on the signature, which would leak a
//! byte-at-a-time timing oracle an attacker can walk to forge a
//! signature). A small **secret set** is supported for zero-downtime
//! rotation: every configured secret is tried, OR-accumulated without
//! early exit, so neither which secret matched nor whether any did leaks
//! through timing.
//!
//! ## What it provides
//!
//! - `sign` / `signWithPrefix` — produce the `sha256=<hex>` header value
//!   for an outbound webhook (or a test), into a caller buffer.
//! - `verify` / `verifyWithPrefix` — constant-time check of a presented
//!   header value against a single secret.
//! - `computeHex` — the raw lowercase-hex MAC (no prefix), the building
//!   block both of the above share.
//! - `Verifier` + `Verifier.middleware()` — a `router.Middleware` that
//!   reads the request body, verifies the signature against the (possibly
//!   rotated) secret set and short-circuits **401** on a
//!   missing/mismatched signature, else attaches the read body to
//!   `ctx.data` and continues.
//!
//! ## Reading the body consumes the stream
//!
//! The middleware must read the **entire raw body** to compute the MAC —
//! `ctx.req.reader().allocRemaining(gpa, .limited(max))`. That drains the
//! request stream, so a downstream handler **cannot re-read it** from
//! `ctx.req.reader()`. To make the already-read bytes available, the
//! middleware stashes them on `ctx.data` for the duration of the inner
//! chain; the handler retrieves them with `bodyOf(ctx)`. The buffer is
//! freed when the middleware returns — copy anything kept past the
//! handler.
//!
//! ## Secrets in memory
//!
//! Unlike a bearer-token gate (which can store only a digest and compare
//! digests), an HMAC verifier needs the **raw secret** to recompute the
//! MAC over each body, so `Verifier` retains gpa-owned copies of the
//! secrets for its lifetime. Keep the `Verifier` itself out of any
//! serialized/loggable surface.
//!
//! ## Thread-safety
//!
//! `Verifier` is immutable after `init` (no runtime mutation, no shared
//! counters) — safe to share by `*const`/`*` across all of
//! `http.Server`'s connection threads at once (`.threadsafe`). The
//! free functions are pure.

const std = @import("std");
const router = @import("router");
const http = @import("http");

pub const meta = .{
    // The module catalog's one-line entry. This IS the source of truth:
    // README.md's table is rendered from it by `zig build gen-catalog`.
    .doc = "Webhook signatures: Standard Webhooks (v1 HMAC + v1a Ed25519), Stripe, Slack, GitHub-style `<prefix><hex|base64>` (SHA-1/256/512) — constant-time sign/verify, replay tolerance, key rotation, gating middleware",
    // The catalog's Platform cell. Prose, because it carries nuance the
    // `platform` enum below cannot -- "any (packer: linux)", "amd64 asm +
    // portable fallback". Rendered by `gen-catalog` alongside `doc`.
    .platform_note = "any",
    .targets = .{.linux64},
    .platform = .any,
    .role = .server,
    // Immutable after init (secret set + config fixed); no shared mutable
    // state, so sharing a single Verifier across all connection threads is
    // safe without locking.
    .concurrency = .threadsafe,
    .model_after = "Standard Webhooks (svix); GitHub/Stripe/Slack webhook signatures; RFC 2104 HMAC",
    .deps = .{ "router", "http" },
};

const Allocator = std.mem.Allocator;

/// The MAC primitive: HMAC-SHA256 (RFC 2104 + FIPS 180-4).
pub const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

/// Raw MAC length in bytes (32 for HMAC-SHA256).
pub const mac_length = Hmac.mac_length;

/// Length of the lowercase-hex MAC, without any prefix (64).
pub const signature_hex_len = mac_length * 2;

/// Default header carrying the signature (GitHub's `X-Signature-256`).
pub const default_header = "X-Signature-256";

/// Default value prefix (GitHub's `sha256=`); the hex MAC follows it.
pub const default_prefix = "sha256=";

/// `WWW-Authenticate`-style challenge scheme emitted on rejection. HMAC
/// webhooks have no registered auth scheme; `Signature` names the
/// mechanism for symmetry with the AAA layer's `Bearer` challenge.
pub const default_challenge = "Signature";

// ── pure sign / verify ──────────────────────────────────────────────────────

/// The raw lowercase-hex HMAC-SHA256 of `body` under `secret` (no prefix).
/// This is the value that follows `sha256=` in the header.
pub fn computeHex(secret: []const u8, body: []const u8) [signature_hex_len]u8 {
    var mac: [mac_length]u8 = undefined;
    Hmac.create(&mac, body, secret);
    return std.fmt.bytesToHex(mac, .lower);
}

/// Buffer length `signWithPrefix` needs for a given prefix
/// (`prefix.len + signature_hex_len`).
pub fn signatureBufLen(prefix: []const u8) usize {
    return prefix.len + signature_hex_len;
}

pub const SignError = error{
    /// `out_buf.len < signatureBufLen(prefix)`. Returned rather than
    /// asserted: `out_buf` is a caller-supplied buffer, and ReleaseFast
    /// compiles the assert (and the bounds check on the two `@memcpy`s
    /// below) out together, turning an undersized buffer into a silent
    /// out-of-bounds write in the build that ships.
    OutputTooSmall,
};

/// Write `<prefix><hex-lowercase-mac>` into `out_buf` and return the
/// written slice. `out_buf` must be at least `signatureBufLen(prefix)`
/// bytes, else `error.OutputTooSmall`. For outbound webhooks and tests.
pub fn signWithPrefix(prefix: []const u8, secret: []const u8, body: []const u8, out_buf: []u8) SignError![]const u8 {
    return signFormat(.{ .prefix = prefix }, secret, body, out_buf);
}

/// `signWithPrefix` with the default `sha256=` prefix (GitHub style).
pub fn sign(secret: []const u8, body: []const u8, out_buf: []u8) SignError![]const u8 {
    return signWithPrefix(default_prefix, secret, body, out_buf);
}

/// Decode the raw MAC out of a presented header value: strip `prefix`
/// (surrounding SP/TAB tolerated; the prefix compare is a plain byte
/// compare — the prefix is not secret), then hex-decode the remaining
/// `signature_hex_len` chars (case-insensitive). Returns null when the
/// prefix is absent, the length is wrong, or the hex is malformed — none
/// of which involves the secret, so an early return here leaks nothing
/// about it.
fn presentedMac(prefix: []const u8, presented: []const u8) ?[max_mac_length]u8 {
    return presentedMacFormat(.{ .prefix = prefix }, presented);
}

fn presentedMacFormat(f: Format, presented: []const u8) ?[max_mac_length]u8 {
    const v = std.mem.trim(u8, presented, " \t");
    if (v.len != f.signatureLen()) return null;
    if (!std.mem.eql(u8, v[0..f.prefix.len], f.prefix)) return null;
    return decodeMac(f.digest, f.encoding, v[f.prefix.len..]);
}

/// Constant-time check that `presented` is a valid `<prefix><hex>`
/// signature of `body` under `secret`. The recomputed MAC and the decoded
/// presented MAC are compared with `std.crypto.timing_safe.eql` over the
/// fixed-size raw MAC — never `std.mem.eql` on the signature. A
/// malformed/absent-prefix/wrong-length presented value is simply false.
pub fn verifyWithPrefix(prefix: []const u8, secret: []const u8, body: []const u8, presented: []const u8) bool {
    return verifyFormat(.{ .prefix = prefix }, secret, body, presented);
}

/// `verifyWithPrefix` with the default `sha256=` prefix (GitHub style).
pub fn verify(secret: []const u8, body: []const u8, presented: []const u8) bool {
    return verifyWithPrefix(default_prefix, secret, body, presented);
}

// ── digests, encodings, the prefixed scheme in general ──────────────────────

/// The HMAC hash. SHA-1 exists for legacy senders only (GitHub's
/// `X-Hub-Signature: sha1=…`); HMAC-SHA-1 is still unforgeable without the
/// key, but prefer SHA-256.
pub const Digest = enum {
    sha1,
    sha256,
    sha512,

    pub fn macLength(d: Digest) usize {
        return switch (d) {
            .sha1 => 20,
            .sha256 => 32,
            .sha512 => 64,
        };
    }
};

/// How the MAC is spelled in the header.
pub const Encoding = enum {
    /// Lower-case on output; either case accepted on input.
    hex,
    /// RFC 4648 standard alphabet, padded (Standard Webhooks, Shopify).
    base64,

    pub fn encodedLen(e: Encoding, mac_len: usize) usize {
        return switch (e) {
            .hex => 2 * mac_len,
            .base64 => std.base64.standard.Encoder.calcSize(mac_len),
        };
    }
};

/// The longest MAC (HMAC-SHA-512).
pub const max_mac_length = 64;

/// A `<prefix><mac>` header value: what the GitHub-style functions above
/// fix at `sha256=` + SHA-256 + hex.
pub const Format = struct {
    prefix: []const u8 = default_prefix,
    digest: Digest = .sha256,
    encoding: Encoding = .hex,

    /// Length of a signature value in this format, prefix included.
    pub fn signatureLen(f: Format) usize {
        return f.prefix.len + f.encoding.encodedLen(f.digest.macLength());
    }
};

/// HMAC of the concatenation of `parts` under `key`, zero-padded to
/// `max_mac_length` so MACs of any digest compare as one fixed-size array.
fn macParts(d: Digest, key: []const u8, parts: []const []const u8) [max_mac_length]u8 {
    var out: [max_mac_length]u8 = @splat(0);
    switch (d) {
        inline else => |tag| {
            const H = switch (tag) {
                .sha1 => std.crypto.auth.hmac.HmacSha1,
                .sha256 => std.crypto.auth.hmac.sha2.HmacSha256,
                .sha512 => std.crypto.auth.hmac.sha2.HmacSha512,
            };
            var h = H.init(key);
            for (parts) |p| h.update(p);
            h.final(out[0..H.mac_length]);
        },
    }
    return out;
}

/// Decode an encoded MAC of exactly the digest's length, zero-padded; null
/// on any malformation. Works on the presented value only — nothing here
/// depends on a secret, so an early return leaks nothing.
fn decodeMac(d: Digest, e: Encoding, text: []const u8) ?[max_mac_length]u8 {
    var out: [max_mac_length]u8 = @splat(0);
    const n = d.macLength();
    if (text.len != e.encodedLen(n)) return null;
    switch (e) {
        .hex => _ = std.fmt.hexToBytes(out[0..n], text) catch return null,
        .base64 => std.base64.standard.Decoder.decode(out[0..n], text) catch return null,
    }
    return out;
}

fn encodeMac(d: Digest, e: Encoding, mac: *const [max_mac_length]u8, out: []u8) []const u8 {
    const n = d.macLength();
    switch (e) {
        .hex => {
            const hex = "0123456789abcdef";
            for (mac[0..n], 0..) |b, i| {
                out[2 * i] = hex[b >> 4];
                out[2 * i + 1] = hex[b & 15];
            }
            return out[0 .. 2 * n];
        },
        .base64 => return std.base64.standard.Encoder.encode(out, mac[0..n]),
    }
}

/// Constant-time compare of two zero-padded MACs.
fn macEql(a: [max_mac_length]u8, b: [max_mac_length]u8) bool {
    return std.crypto.timing_safe.eql([max_mac_length]u8, a, b);
}

/// Write `<prefix><mac>` for `body` under `secret` in format `f` into
/// `out_buf` (at least `f.signatureLen()` bytes, else `OutputTooSmall`).
pub fn signFormat(f: Format, secret: []const u8, body: []const u8, out_buf: []u8) SignError![]const u8 {
    const n = f.signatureLen();
    if (out_buf.len < n) return error.OutputTooSmall;
    @memcpy(out_buf[0..f.prefix.len], f.prefix);
    const mac = macParts(f.digest, secret, &.{body});
    _ = encodeMac(f.digest, f.encoding, &mac, out_buf[f.prefix.len..n]);
    return out_buf[0..n];
}

/// Constant-time check of a `<prefix><mac>` value in format `f`. SP/TAB
/// around the value are tolerated; anything malformed is false.
pub fn verifyFormat(f: Format, secret: []const u8, body: []const u8, presented: []const u8) bool {
    const got = presentedMacFormat(f, presented) orelse return false;
    return macEql(macParts(f.digest, secret, &.{body}), got);
}

// ── timestamps ──────────────────────────────────────────────────────────────

/// The replay window every reference uses (Standard Webhooks' libraries,
/// Stripe's SDKs, Slack's docs): five minutes.
pub const default_tolerance_s: u32 = 300;

/// Why a timestamped signature was refused.
pub const VerifyError = error{
    /// A required header is absent or not in the scheme's shape.
    InvalidHeader,
    /// The timestamp is not 1..19 ASCII digits (no sign, no fraction).
    InvalidTimestamp,
    /// More than `tolerance_s` before `now`: a replay, or a delayed delivery.
    TimestampTooOld,
    /// More than `tolerance_s` after `now`.
    TimestampTooNew,
    /// No presented signature matched any key.
    NoMatchingSignature,
};

/// Parse `text` as unix seconds and check it against `now` ± `tolerance_s`.
/// The boundary is inclusive: exactly `tolerance_s` away passes, as in the
/// Standard Webhooks reference (`now - ts > tolerance` fails).
pub fn checkTimestamp(text: []const u8, now: i64, tolerance_s: u32) VerifyError!u64 {
    const t = std.mem.trim(u8, text, " \t");
    if (t.len == 0 or t.len > 19) return error.InvalidTimestamp;
    // 19 digits are at most 9 999 999 999 999 999 999 < 2^64: no overflow.
    var v: u64 = 0;
    for (t) |c| {
        if (c < '0' or c > '9') return error.InvalidTimestamp;
        v = v * 10 + (c - '0');
    }
    const age: i128 = @as(i128, now) - @as(i128, v);
    if (age > tolerance_s) return error.TimestampTooOld;
    if (-age > tolerance_s) return error.TimestampTooNew;
    return v;
}

/// Unix seconds for the middleware's tolerance check. The module reads no
/// clock of its own; `fromIo` adapts `std.Io`'s real-time clock, a test
/// passes a fixed one.
pub const Clock = struct {
    context: ?*anyopaque = null,
    nowFn: *const fn (context: ?*anyopaque) i64,

    pub fn now(c: Clock) i64 {
        return c.nowFn(c.context);
    }

    /// `std.Io.Clock.real` through `io`, which must outlive the Clock.
    pub fn fromIo(io: *const std.Io) Clock {
        return .{ .context = @ptrCast(@constCast(io)), .nowFn = ioNow };
    }

    fn ioNow(context: ?*anyopaque) i64 {
        const io: *const std.Io = @ptrCast(@alignCast(context.?));
        return std.Io.Clock.real.now(io.*).toSeconds();
    }
};

/// At most this many signatures of one header are looked at (rotation
/// lists are two or three long). Every HMAC is computed once per key, not
/// per presented signature, but each Ed25519 check hashes the body again,
/// so an unbounded list would let one request buy unbounded work.
pub const max_signatures = 16;

/// Of those, at most this many `v1a` (Ed25519) ones: each is checked
/// against every public key and each check hashes the body, so this times
/// the key count bounds the body passes one request can cost.
pub const max_ed25519_signatures = 4;

fn writeDecimal(buf: *[20]u8, v: u64) []const u8 {
    return std.fmt.bufPrint(buf, "{d}", .{v}) catch unreachable;
}

// ── Standard Webhooks ───────────────────────────────────────────────────────

/// The Standard Webhooks scheme (standard-webhooks/spec, as Svix sends it).
/// Signed content: `<webhook-id>.<webhook-timestamp>.<body>`, the timestamp
/// re-spelled as plain decimal (as the reference libraries do).
pub const standard = struct {
    pub const header_id = "webhook-id";
    pub const header_timestamp = "webhook-timestamp";
    pub const header_signature = "webhook-signature";
    pub const secret_prefix = "whsec_";
    pub const public_key_prefix = "whpk_";
    pub const signing_key_prefix = "whsk_";
    /// The spec's symmetric secret range, 24..64 bytes.
    pub const min_secret_len = 24;
    pub const max_secret_len = 64;
    /// `v1,` + base64 of 32 bytes.
    pub const v1_len = 3 + 44;
    /// `v1a,` + base64 of a 64-byte Ed25519 signature.
    pub const v1a_len = 4 + 88;

    const Ed25519 = std.crypto.sign.Ed25519;

    pub const KeyError = error{InvalidKey};

    /// The raw HMAC key of a `whsec_<base64>` secret (the prefix is
    /// optional, padding too). Refused unless it decodes to 24..64 bytes.
    pub fn decodeSecret(out: *[max_secret_len]u8, text: []const u8) KeyError![]const u8 {
        const n = try decodeB64(out, stripPrefix(text, secret_prefix));
        if (n < min_secret_len) return error.InvalidKey;
        return out[0..n];
    }

    /// `whsec_<base64>` for a raw key of 24..64 bytes, into `out`.
    pub fn encodeSecret(out: []u8, key: []const u8) (KeyError || SignError)![]const u8 {
        if (key.len < min_secret_len or key.len > max_secret_len) return error.InvalidKey;
        const n = secret_prefix.len + std.base64.standard.Encoder.calcSize(key.len);
        if (out.len < n) return error.OutputTooSmall;
        @memcpy(out[0..secret_prefix.len], secret_prefix);
        _ = std.base64.standard.Encoder.encode(out[secret_prefix.len..n], key);
        return out[0..n];
    }

    /// The Ed25519 public key of a `whpk_<base64 of 32 bytes>` value.
    pub fn decodePublicKey(text: []const u8) KeyError!Ed25519.PublicKey {
        var buf: [64]u8 = undefined;
        const n = try decodeB64(&buf, stripPrefix(text, public_key_prefix));
        if (n != 32) return error.InvalidKey;
        return Ed25519.PublicKey.fromBytes(buf[0..32].*) catch error.InvalidKey;
    }

    /// The Ed25519 key pair of a `whsk_<base64>` value. The spec does not
    /// fix the layout, so both are accepted: the 32-byte seed, and the
    /// 64-byte seed‖public key (libsodium / `std` `SecretKey`), whose public
    /// half must then match the seed.
    pub fn decodeSigningKey(text: []const u8) KeyError!Ed25519.KeyPair {
        var buf: [64]u8 = undefined;
        const n = try decodeB64(&buf, stripPrefix(text, signing_key_prefix));
        return switch (n) {
            32 => Ed25519.KeyPair.generateDeterministic(buf[0..32].*) catch error.InvalidKey,
            64 => blk: {
                // NOT `Ed25519.KeyPair.fromSecretKey`: `std` checks the
                // embedded public half against the seed only under
                // `std.debug.runtime_safety`, so in ReleaseFast a mismatched
                // half was taken as is (and signing one message under two
                // public keys gives away the secret scalar). Derive from the
                // seed and compare, in every mode.
                const kp = Ed25519.KeyPair.generateDeterministic(buf[0..32].*) catch break :blk error.InvalidKey;
                if (!std.crypto.timing_safe.eql([32]u8, kp.public_key.toBytes(), buf[32..64].*)) break :blk error.InvalidKey;
                break :blk kp;
            },
            else => error.InvalidKey,
        };
    }

    /// `v1,<base64 HMAC-SHA256>` of `id.timestamp.payload` under the raw
    /// `key` (see `decodeSecret`), into `out` (at least `v1_len`).
    pub fn sign(out: []u8, key: []const u8, msg_id: []const u8, timestamp: u64, payload: []const u8) SignError![]const u8 {
        if (out.len < v1_len) return error.OutputTooSmall;
        var tb: [20]u8 = undefined;
        const mac = macParts(.sha256, key, &.{ msg_id, ".", writeDecimal(&tb, timestamp), ".", payload });
        @memcpy(out[0..3], "v1,");
        _ = encodeMac(.sha256, .base64, &mac, out[3..v1_len]);
        return out[0..v1_len];
    }

    /// `v1a,<base64 Ed25519 signature>` of `id.timestamp.payload`, into
    /// `out` (at least `v1a_len`). Deterministic (RFC 8032, no noise), which
    /// hashes the message twice — so the signed content is assembled in
    /// `scratch` (at least `msg_id.len + 22 + payload.len` bytes, else
    /// `OutputTooSmall`); `std`'s streaming signer is randomized.
    pub fn signEd25519(out: []u8, scratch: []u8, key_pair: Ed25519.KeyPair, msg_id: []const u8, timestamp: u64, payload: []const u8) (SignError || error{SigningFailed})![]const u8 {
        if (out.len < v1a_len) return error.OutputTooSmall;
        var tb: [20]u8 = undefined;
        const content = std.fmt.bufPrint(scratch, "{s}.{s}.{s}", .{ msg_id, writeDecimal(&tb, timestamp), payload }) catch return error.OutputTooSmall;
        const sig = (key_pair.sign(content, null) catch return error.SigningFailed).toBytes();
        @memcpy(out[0..4], "v1a,");
        _ = std.base64.standard.Encoder.encode(out[4..v1a_len], &sig);
        return out[0..v1a_len];
    }

    /// The keys a receiver accepts: raw HMAC secrets (rotation set) and
    /// Ed25519 public keys. Either may be empty.
    pub const Keys = struct {
        secrets: []const []const u8 = &.{},
        public_keys: []const Ed25519.PublicKey = &.{},
    };

    /// Verify a Standard Webhooks delivery: the timestamp within
    /// `tolerance_s` of `now`, then any `v1` signature of the space-separated
    /// `webhook-signature` list matching any secret, or any `v1a` one
    /// verifying under any public key. Unknown versions are skipped; more
    /// than `max_signatures` entries, or more than `max_ed25519_signatures`
    /// `v1a` ones, is `InvalidHeader`. HMACs are compared
    /// in constant time and every one is checked (no early exit).
    /// Replay inside the window is the caller's to stop (remember
    /// `webhook-id`s for `tolerance_s`).
    pub fn verify(keys: Keys, msg_id: []const u8, timestamp: []const u8, signatures: []const u8, payload: []const u8, now: i64, tolerance_s: u32) VerifyError!void {
        const ts = try checkTimestamp(timestamp, now, tolerance_s);
        if (msg_id.len == 0) return error.InvalidHeader;
        var tb: [20]u8 = undefined;
        const parts = [_][]const u8{ msg_id, ".", writeDecimal(&tb, ts), ".", payload };
        var wants: [max_keys][max_mac_length]u8 = undefined;
        const nk = @min(keys.secrets.len, max_keys);
        for (keys.secrets[0..nk], 0..) |k, i| wants[i] = macParts(.sha256, k, &parts);

        var ok = false;
        var seen: usize = 0;
        var seen_v1a: usize = 0;
        var it = std.mem.tokenizeAny(u8, signatures, " \t");
        while (it.next()) |entry| {
            seen += 1;
            if (seen > max_signatures) return error.InvalidHeader;
            const comma = std.mem.indexOfScalar(u8, entry, ',') orelse continue;
            const version = entry[0..comma];
            const value = entry[comma + 1 ..];
            if (std.mem.eql(u8, version, "v1")) {
                const got = decodeMac(.sha256, .base64, value) orelse continue;
                for (wants[0..nk]) |w| ok = macEql(w, got) or ok;
            } else if (std.mem.eql(u8, version, "v1a")) {
                seen_v1a += 1;
                if (seen_v1a > max_ed25519_signatures) return error.InvalidHeader;
                if (value.len != 88) continue;
                var sb: [64]u8 = undefined;
                std.base64.standard.Decoder.decode(&sb, value) catch continue;
                const sig = Ed25519.Signature.fromBytes(sb);
                for (keys.public_keys) |pk| {
                    var v = sig.verifier(pk) catch continue;
                    for (parts) |p| v.update(p);
                    if (v.verify()) |_| {
                        ok = true;
                    } else |_| {}
                }
            }
        }
        if (!ok) return error.NoMatchingSignature;
    }

    fn stripPrefix(text: []const u8, prefix: []const u8) []const u8 {
        const t = std.mem.trim(u8, text, " \t");
        return if (std.mem.startsWith(u8, t, prefix)) t[prefix.len..] else t;
    }

    /// Standard-alphabet base64, padded or not, into `out`; the length.
    fn decodeB64(out: *[64]u8, text: []const u8) KeyError!usize {
        const d = if (std.mem.endsWith(u8, text, "=")) std.base64.standard.Decoder else std.base64.standard_no_pad.Decoder;
        const n = d.calcSizeForSlice(text) catch return error.InvalidKey;
        if (n == 0 or n > out.len) return error.InvalidKey;
        d.decode(out[0..n], text) catch return error.InvalidKey;
        return n;
    }
};

/// Most keys one verification tries (the rotation set). A verifier with
/// more is a configuration error; the extras are ignored by the free
/// functions and refused by `Verifier.init` (asserted).
pub const max_keys = 8;

// ── Stripe ──────────────────────────────────────────────────────────────────

/// Stripe's `Stripe-Signature: t=<ts>,v1=<hex>[,v1=…][,v0=…]`, HMAC-SHA256
/// over `<ts>.<body>`. The endpoint secret (`whsec_…`) is the HMAC key AS
/// TEXT — Stripe does not base64-decode it (unlike Standard Webhooks).
pub const stripe = struct {
    pub const header = "Stripe-Signature";

    /// `t=<timestamp>,v1=<hex>` into `out` (at least 2 + 20 + 4 + 64 bytes
    /// suffices for any timestamp).
    pub fn sign(out: []u8, secret: []const u8, timestamp: u64, payload: []const u8) SignError![]const u8 {
        var tb: [20]u8 = undefined;
        const ts = writeDecimal(&tb, timestamp);
        const n = 2 + ts.len + 4 + 64;
        if (out.len < n) return error.OutputTooSmall;
        const mac = macParts(.sha256, secret, &.{ ts, ".", payload });
        @memcpy(out[0..2], "t=");
        @memcpy(out[2..][0..ts.len], ts);
        @memcpy(out[2 + ts.len ..][0..4], ",v1=");
        _ = encodeMac(.sha256, .hex, &mac, out[2 + ts.len + 4 .. n]);
        return out[0..n];
    }

    /// Verify a `Stripe-Signature` value: one `t=` (the first wins), the
    /// timestamp within `tolerance_s` of `now` in either direction (Stripe's
    /// SDKs check only the past; a future timestamp is no less suspect), and
    /// any `v1=` matching any secret. `v0=` and unknown schemes are ignored.
    pub fn verify(secrets: []const []const u8, header_value: []const u8, payload: []const u8, now: i64, tolerance_s: u32) VerifyError!void {
        var t_text: ?[]const u8 = null;
        var seen: usize = 0;
        var it = std.mem.tokenizeScalar(u8, header_value, ',');
        while (it.next()) |raw| {
            const item = std.mem.trim(u8, raw, " \t");
            if (std.mem.startsWith(u8, item, "t=") and t_text == null) t_text = item[2..];
        }
        const ts = try checkTimestamp(t_text orelse return error.InvalidHeader, now, tolerance_s);
        var tb: [20]u8 = undefined;
        const parts = [_][]const u8{ writeDecimal(&tb, ts), ".", payload };
        var wants: [max_keys][max_mac_length]u8 = undefined;
        const nk = @min(secrets.len, max_keys);
        for (secrets[0..nk], 0..) |k, i| wants[i] = macParts(.sha256, k, &parts);
        var ok = false;
        it.reset();
        while (it.next()) |raw| {
            const item = std.mem.trim(u8, raw, " \t");
            if (!std.mem.startsWith(u8, item, "v1=")) continue;
            seen += 1;
            if (seen > max_signatures) return error.InvalidHeader;
            const got = decodeMac(.sha256, .hex, item[3..]) orelse continue;
            for (wants[0..nk]) |w| ok = macEql(w, got) or ok;
        }
        if (!ok) return error.NoMatchingSignature;
    }
};

// ── Slack ───────────────────────────────────────────────────────────────────

/// Slack's request signing: `X-Slack-Signature: v0=<hex>` over
/// `v0:<X-Slack-Request-Timestamp>:<body>`, HMAC-SHA256 under the signing
/// secret as text.
pub const slack = struct {
    pub const header_signature = "X-Slack-Signature";
    pub const header_timestamp = "X-Slack-Request-Timestamp";
    /// `v0=` + 64 hex.
    pub const signature_len = 3 + 64;

    pub fn sign(out: []u8, secret: []const u8, timestamp: u64, body: []const u8) SignError![]const u8 {
        if (out.len < signature_len) return error.OutputTooSmall;
        var tb: [20]u8 = undefined;
        const mac = macParts(.sha256, secret, &.{ "v0:", writeDecimal(&tb, timestamp), ":", body });
        @memcpy(out[0..3], "v0=");
        _ = encodeMac(.sha256, .hex, &mac, out[3..signature_len]);
        return out[0..signature_len];
    }

    /// The timestamp within `tolerance_s` of `now`, then the `v0=` value
    /// matching any secret (constant time, every secret tried).
    pub fn verify(secrets: []const []const u8, timestamp: []const u8, signature: []const u8, body: []const u8, now: i64, tolerance_s: u32) VerifyError!void {
        const ts = try checkTimestamp(timestamp, now, tolerance_s);
        const got = presentedMacFormat(.{ .prefix = "v0=" }, signature) orelse return error.NoMatchingSignature;
        var tb: [20]u8 = undefined;
        const parts = [_][]const u8{ "v0:", writeDecimal(&tb, ts), ":", body };
        var ok = false;
        for (secrets[0..@min(secrets.len, max_keys)]) |k| ok = macEql(macParts(.sha256, k, &parts), got) or ok;
        if (!ok) return error.NoMatchingSignature;
    }
};

// ── the middleware verifier ─────────────────────────────────────────────────

/// Which signature scheme a `Verifier` checks.
pub const Scheme = enum {
    /// One `<prefix><mac>` header over the body (GitHub, Shopify, …):
    /// `header`, `prefix`, `digest`, `encoding`.
    prefixed,
    /// `standard`'s three headers; secrets are RAW keys (decode `whsec_…`
    /// with `standard.decodeSecret`), `public_keys` take `v1a`.
    standard_webhooks,
    /// `stripe.header`; secrets as text.
    stripe,
    /// `slack`'s two headers; secrets as text.
    slack,
};

pub const Options = struct {
    /// The primary signing secret (raw bytes; retained). No secret at all
    /// (and, for `.standard_webhooks`, no public key) is a misconfiguration
    /// (asserted) — a gate with no key can verify nothing. At most
    /// `max_keys` secrets (asserted).
    secret: ?[]const u8 = null,
    /// Additional valid secrets (rotation set): a body signed with **any**
    /// configured secret passes. Add the new secret, migrate senders, then
    /// drop the old one. Retained (raw bytes).
    extra_secrets: []const []const u8 = &.{},
    /// Header carrying the signature (case-insensitive lookup). Copied into
    /// the Verifier. Default `X-Signature-256`.
    header: []const u8 = default_header,
    /// Value prefix before the hex MAC. Copied into the Verifier. Default
    /// `sha256=`. Use `""` for a bare-hex header.
    prefix: []const u8 = default_prefix,
    /// Maximum request body read; a body larger than this is rejected
    /// **413** (before any verification). Bounds memory per request.
    max_body_bytes: usize = 1 << 20, // 1 MiB
    /// `WWW-Authenticate` challenge value on rejection. Copied. Default
    /// `Signature`.
    challenge: []const u8 = default_challenge,
    /// The scheme. Default: the GitHub-style prefixed value.
    scheme: Scheme = .prefixed,
    /// `.prefixed` only: the HMAC digest and the MAC's spelling.
    digest: Digest = .sha256,
    encoding: Encoding = .hex,
    /// `.standard_webhooks` only: Ed25519 keys accepting `v1a` signatures
    /// (decode `whpk_…` with `standard.decodePublicKey`). Copied.
    public_keys: []const std.crypto.sign.Ed25519.PublicKey = &.{},
    /// Required (asserted) by the timestamped schemes: unix seconds now.
    clock: ?Clock = null,
    /// Timestamped schemes: the replay window, either direction.
    tolerance_s: u32 = default_tolerance_s,
};

/// The signature you attached to `ctx.data` on the success path — the raw
/// body the middleware already read (so the handler need not, and cannot,
/// re-read the consumed stream). Valid only for the duration of the inner
/// chain; `ctx.data` is restored and the buffer freed afterwards.
pub const Attached = struct {
    /// The verified raw request body.
    body: []const u8,
};

/// The verified body the middleware attached to this request, or null when
/// no verifier ran / the slot was not set by this module. Only meaningful
/// below a `Verifier.middleware()` in the chain.
pub fn bodyOf(ctx: *const router.Ctx) ?[]const u8 {
    const p = ctx.data orelse return null;
    const a: *Attached = @ptrCast(@alignCast(p));
    return a.body;
}

pub const Verifier = struct {
    gpa: Allocator,
    /// gpa-owned copies of the raw secrets (rotation set).
    secrets: std.ArrayList([]u8) = .empty,
    /// gpa-owned copies.
    header: []const u8,
    prefix: []const u8,
    challenge: []const u8,
    max_body_bytes: usize,
    scheme: Scheme = .prefixed,
    digest: Digest = .sha256,
    encoding: Encoding = .hex,
    /// gpa-owned copy.
    public_keys: []const std.crypto.sign.Ed25519.PublicKey = &.{},
    clock: ?Clock = null,
    tolerance_s: u32 = default_tolerance_s,

    /// Build a verifier. Secret/header/prefix slices are copied, so the
    /// caller's buffers need not outlive this call (the secrets *are*
    /// retained, as owned copies). Requires at least one secret.
    pub fn init(gpa: Allocator, options: Options) error{OutOfMemory}!Verifier {
        var secrets: std.ArrayList([]u8) = .empty;
        errdefer {
            for (secrets.items) |s| gpa.free(s);
            secrets.deinit(gpa);
        }
        if (options.secret) |s| {
            std.debug.assert(s.len != 0);
            try secrets.append(gpa, try gpa.dupe(u8, s));
        }
        for (options.extra_secrets) |s| {
            std.debug.assert(s.len != 0);
            try secrets.append(gpa, try gpa.dupe(u8, s));
        }
        // A gate needs a key; `max_keys` bounds the per-request work.
        std.debug.assert(secrets.items.len + options.public_keys.len != 0);
        std.debug.assert(options.scheme == .standard_webhooks or secrets.items.len != 0);
        std.debug.assert(secrets.items.len <= max_keys and options.public_keys.len <= max_keys);
        if (options.scheme != .prefixed) std.debug.assert(options.clock != null);
        // A `whsec_…` string is not the key: decode it first.
        if (options.scheme == .standard_webhooks) for (secrets.items) |s|
            std.debug.assert(!std.mem.startsWith(u8, s, standard.secret_prefix));

        std.debug.assert(options.header.len != 0);
        const header = try gpa.dupe(u8, options.header);
        errdefer gpa.free(header);
        const prefix = try gpa.dupe(u8, options.prefix);
        errdefer gpa.free(prefix);
        const challenge = try gpa.dupe(u8, options.challenge);
        errdefer gpa.free(challenge);
        const public_keys = try gpa.dupe(std.crypto.sign.Ed25519.PublicKey, options.public_keys);
        errdefer gpa.free(public_keys);

        return .{
            .gpa = gpa,
            .secrets = secrets,
            .header = header,
            .prefix = prefix,
            .challenge = challenge,
            .max_body_bytes = options.max_body_bytes,
            .scheme = options.scheme,
            .digest = options.digest,
            .encoding = options.encoding,
            .public_keys = public_keys,
            .clock = options.clock,
            .tolerance_s = options.tolerance_s,
        };
    }

    pub fn deinit(v: *Verifier) void {
        for (v.secrets.items) |s| v.gpa.free(s);
        v.secrets.deinit(v.gpa);
        v.gpa.free(v.header);
        v.gpa.free(v.prefix);
        v.gpa.free(v.challenge);
        v.gpa.free(v.public_keys);
        v.* = undefined;
    }

    /// Number of configured secrets (diagnostics / tests).
    pub fn secretCount(v: *const Verifier) usize {
        return v.secrets.items.len;
    }

    /// Constant-time verification of `presented` against the whole secret
    /// set: every secret is tried and the results OR-accumulated **without
    /// early exit**, so neither which secret matched nor whether any did
    /// leaks through timing. A malformed/absent presented value is false.
    ///
    /// `.prefixed` scheme only (the header value is the whole signature);
    /// the timestamped schemes go through `verifyRequest`.
    pub fn verifyBody(v: *const Verifier, body: []const u8, presented: []const u8) bool {
        const f: Format = .{ .prefix = v.prefix, .digest = v.digest, .encoding = v.encoding };
        const got = presentedMacFormat(f, presented) orelse return false;
        var ok = false;
        for (v.secrets.items) |secret| {
            ok = macEql(macParts(v.digest, secret, &.{body}), got) or ok;
        }
        return ok;
    }

    /// The request's signature headers for this verifier's scheme, read
    /// through `get` (`ctx.req.header` in the middleware).
    pub const Headers = struct {
        /// `.prefixed`: the signature; `.standard_webhooks`:
        /// `webhook-signature`; `.stripe`: `Stripe-Signature`; `.slack`:
        /// `X-Slack-Signature`.
        signature: ?[]const u8 = null,
        /// `.standard_webhooks`: `webhook-timestamp`; `.slack`:
        /// `X-Slack-Request-Timestamp`.
        timestamp: ?[]const u8 = null,
        /// `.standard_webhooks`: `webhook-id`.
        id: ?[]const u8 = null,
    };

    /// Check one request of any scheme against the whole key set, with
    /// `now` for the timestamped ones. The timestamp half needs no body —
    /// `checkFreshness` runs it alone so the middleware can refuse a stale
    /// delivery before reading anything.
    pub fn verifyRequest(v: *const Verifier, h: Headers, body: []const u8, now: i64) VerifyError!void {
        const sig = h.signature orelse return error.InvalidHeader;
        const secrets: []const []const u8 = @ptrCast(v.secrets.items);
        switch (v.scheme) {
            .prefixed => if (!v.verifyBody(body, sig)) return error.NoMatchingSignature,
            .standard_webhooks => try standard.verify(
                .{ .secrets = secrets, .public_keys = v.public_keys },
                h.id orelse return error.InvalidHeader,
                h.timestamp orelse return error.InvalidHeader,
                sig,
                body,
                now,
                v.tolerance_s,
            ),
            .stripe => try stripe.verify(secrets, sig, body, now, v.tolerance_s),
            .slack => try slack.verify(secrets, h.timestamp orelse return error.InvalidHeader, sig, body, now, v.tolerance_s),
        }
    }

    /// The timestamp check of `verifyRequest` alone (no-op for `.prefixed`).
    pub fn checkFreshness(v: *const Verifier, h: Headers, now: i64) VerifyError!void {
        switch (v.scheme) {
            .prefixed => {},
            .standard_webhooks, .slack => _ = try checkTimestamp(h.timestamp orelse return error.InvalidHeader, now, v.tolerance_s),
            .stripe => {
                const sig = h.signature orelse return error.InvalidHeader;
                var it = std.mem.tokenizeScalar(u8, sig, ',');
                while (it.next()) |raw| {
                    const item = std.mem.trim(u8, raw, " \t");
                    if (std.mem.startsWith(u8, item, "t=")) {
                        _ = try checkTimestamp(item[2..], now, v.tolerance_s);
                        return;
                    }
                }
                return error.InvalidHeader;
            },
        }
    }

    fn headersOf(v: *const Verifier, ctx: *router.Ctx) Headers {
        return switch (v.scheme) {
            .prefixed => .{ .signature = ctx.req.header(v.header) },
            .standard_webhooks => .{
                .signature = ctx.req.header(standard.header_signature),
                .timestamp = ctx.req.header(standard.header_timestamp),
                .id = ctx.req.header(standard.header_id),
            },
            .stripe => .{ .signature = ctx.req.header(stripe.header) },
            .slack => .{
                .signature = ctx.req.header(slack.header_signature),
                .timestamp = ctx.req.header(slack.header_timestamp),
            },
        };
    }

    /// A `router.Middleware` gating requests on a valid signature. `state`
    /// is the Verifier — register it before the protected routes; the
    /// Verifier must outlive the Router at a stable address.
    pub fn middleware(v: *Verifier) router.Middleware {
        return .{ .state = v, .run = middlewareRun };
    }

    fn reject(v: *const Verifier, ctx: *router.Ctx) anyerror!void {
        ctx.res.setStatus(401);
        try ctx.res.setHeader("WWW-Authenticate", v.challenge);
        try ctx.res.setHeader("Content-Type", "text/plain");
        try ctx.res.writeAll("Invalid signature\n");
    }
};

fn middlewareRun(state: ?*anyopaque, ctx: *router.Ctx, next: router.Next) anyerror!void {
    const v: *Verifier = @ptrCast(@alignCast(state.?));

    // Absent signature header, or a stale/future timestamp → 401 without
    // touching the body.
    const h = v.headersOf(ctx);
    if (h.signature == null) return v.reject(ctx);
    const now: i64 = if (v.clock) |c| c.now() else 0;
    v.checkFreshness(h, now) catch return v.reject(ctx);

    // Read the exact raw bytes to compute the MAC over. This consumes the
    // request stream — the handler retrieves the bytes via bodyOf(ctx).
    const body = ctx.req.reader().allocRemaining(v.gpa, .limited(v.max_body_bytes)) catch |err| switch (err) {
        error.StreamTooLong => {
            ctx.res.setStatus(413);
            try ctx.res.setHeader("Content-Type", "text/plain");
            try ctx.res.writeAll("Payload too large\n");
            return;
        },
        error.OutOfMemory => return error.OutOfMemory,
        else => return err, // ReadFailed → server answers 500
    };
    defer v.gpa.free(body);

    v.verifyRequest(h, body, now) catch return v.reject(ctx);

    // Verified: hand the already-read body to the inner chain via ctx.data.
    var attached: Attached = .{ .body = body };
    const saved = ctx.data;
    ctx.data = &attached;
    defer ctx.data = saved;
    return next.run(ctx);
}

// ── tests: pure sign / verify ───────────────────────────────────────────────

const testing = std.testing;

test "sign → verify round-trip (default sha256= prefix)" {
    const secret = "topsecret";
    const body = "{\"hello\":\"world\"}";
    var buf: [signatureBufLen(default_prefix)]u8 = undefined;
    const value = try sign(secret, body, &buf);

    try testing.expect(std.mem.startsWith(u8, value, "sha256="));
    try testing.expectEqual(@as(usize, default_prefix.len + signature_hex_len), value.len);
    try testing.expect(verify(secret, body, value)); // the round-trip
}

// signWithPrefix used to guard out_buf.len with std.debug.assert before two
// @memcpy calls. ReleaseFast compiles the assert (and the bounds check on
// those memcpys) out together, so an out_buf undersized relative to
// signatureBufLen(prefix) was a silent out-of-bounds write in the build that
// ships. Written in terms of signatureBufLen rather than a literal so it
// keeps measuring the mechanism if the buffer math ever changes.
test "signWithPrefix: an out_buf one byte short of signatureBufLen is an error, not an assert" {
    const secret = "topsecret";
    const body = "payload";
    const n = signatureBufLen(default_prefix);
    var buf: [signatureBufLen(default_prefix)]u8 = undefined;

    try testing.expectError(error.OutputTooSmall, signWithPrefix(default_prefix, secret, body, buf[0 .. n - 1]));
    _ = try signWithPrefix(default_prefix, secret, body, buf[0..n]);
}

test "verify: tampered body / wrong secret / malformed all rejected (constant-time compare)" {
    const secret = "topsecret";
    const body = "payload-bytes";
    var buf: [64 + 8]u8 = undefined;
    const value = try sign(secret, body, &buf);

    try testing.expect(verify(secret, body, value)); // baseline pass
    try testing.expect(!verify(secret, "payload-byteS", value)); // one body byte flipped
    try testing.expect(!verify("wrongsecret", body, value)); // wrong secret
    try testing.expect(!verify(secret, body, "sha256=deadbeef")); // wrong length
    try testing.expect(!verify(secret, body, "sha1=" ++ ("0" ** 64))); // wrong prefix
    try testing.expect(!verify(secret, body, value[7..])); // prefix stripped by caller
    try testing.expect(!verify(secret, body, "")); // empty
    // Same-length, single hex nibble flipped → must still be denied (proves
    // it is a full MAC compare, not a prefix/length check).
    var tampered = buf;
    tampered[10] = if (tampered[10] == 'a') 'b' else 'a';
    try testing.expect(!verify(secret, body, tampered[0..value.len]));
}

// ── fuzz: verify (presentedMac decode) never panics on arbitrary input ────
//
// `verify`/`verifyWithPrefix` run on the `X-Signature-256` request header —
// an attacker fully controls `presented` (and, for the request-signing use
// case, `body` too). `presentedMac` is the byte-parser underneath: strip a
// prefix, then hex-decode a fixed-width tail. Structured half: builds a
// value shaped like `sha256=<64 hex chars>` (the exact length gate
// `presentedMac` requires to reach `hexToBytes`) with random hex/non-hex
// characters and surrounding whitespace, so the hex-decode path — not just
// the length/prefix check — actually runs.

/// `testkit.fuzz` — see that module for why a corpus entry is not the frame.
const tkfuzz = @import("testkit").fuzz;
const seed = tkfuzz.seed;

/// The credential the harness verifies against: the same key/body pair as
/// `computeHex is lowercase hex and matches a well-known HMAC-SHA256 demo
/// vector`, so the corpus can carry a signature that is genuinely CORRECT.
const anchor_secret = "key";
const anchor_body = "The quick brown fox jumps over the lazy dog";
const anchor_hex = "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8";

/// Presented header values in the format `Smith.slice` reads.
///
/// ⚠ `presentedMac` gates on an exact length before it looks at anything else
/// (`prefix.len + 64`), so a value that is not exactly 71 octets after
/// trimming never reaches the prefix compare, let alone `hexToBytes`. The
/// interesting inputs are therefore all the same length, and that length has
/// to be spelled out rather than drawn.
const presented_seeds = [_][]const u8{
    seed("sha256=" ++ anchor_hex), // the CORRECT signature: verify → true
    seed("sha256=" ++ anchor_hex[0..63] ++ "9"), // one hex digit off: decodes, compare fails
    seed("  sha256=" ++ anchor_hex ++ " \t"), // the SP/TAB trim path, still true
    seed("sha256=F7BC83F430538424B13298E6AA6FB143EF4D59A14946175997479DBC2D1A3CD8"), // uppercase: hexToBytes is case-insensitive
    seed("sha256=" ++ anchor_hex[0..63] ++ "g"), // a non-hex digit: hexToBytes refuses
    seed("sha255=" ++ anchor_hex), // right length, wrong prefix
    seed(anchor_hex), // no prefix: wrong length for `verify`, RIGHT length for the empty-prefix call
    seed("sha256="), // prefix only: the length gate
    seed("sha256=" ++ anchor_hex ++ "0"), // one octet too long
    seed("a" ** 128), // the full harness buffer
    seed(""), // the ONE input the collapsed harness ever ran
};

test "fuzz: verify never panics on arbitrary secret/body/presented" {
    try testing.fuzz({}, fuzzVerify, .{ .corpus = &presented_seeds });
}

fn fuzzVerify(_: void, smith: *std.testing.Smith) !void {
    var presented_buf: [128]u8 = undefined;
    // ⚠ One `smith.slice` call, and it is the FIRST draw. This harness used to
    // open with `smith.bytes(&secret_buf)` + a ranged length, then the same for
    // the body, then `smith.value(bool)` to pick between a raw and a structured
    // `presented`. Every one of those collapses outside `--fuzz`: a ranged
    // `Smith` draw reads eight octets as a little-endian u64 and returns the
    // range MINIMUM when fewer remain, `bool` is a 1-bit range, and `Smith`
    // discards the rest of its input after the first short read. So the target
    // ran exactly one input for its whole existence — secret `"\x00"`, body
    // `""`, and a presented value of seven NUL octets followed by sixty-four
    // `'0'`s, because `smith.index` was 0 for every character. Measured
    // 2026-09-07 over the corpus above: **0 of 11 seeds non-empty, 0 MACs
    // decoded and 0 signatures accepted before; 10 of 11 non-empty (one seed IS
    // the empty header), 5 decoded and 4 accepted after.**
    const presented_len: usize = smith.slice(&presented_buf);
    const presented = presented_buf[0..presented_len];

    // (a) Against the module's own anchor credential, so the TRUE branch of the
    // constant-time compare is reachable at all — no random secret can ever
    // produce a matching MAC, so before this the success path of `verify` was
    // unreachable from the fuzzer by construction.
    _ = verify(anchor_secret, anchor_body, presented);
    // ⚠ …with a DIFFERENT prefix. The second call here used to be
    // `verifyWithPrefix("sha256=", …)`, which is literally what `verify`
    // expands to — the same call twice. The empty prefix is the case that
    // actually differs: a bare 64-character hex value.
    _ = verifyWithPrefix("", anchor_secret, anchor_body, presented);

    // (b) Against a secret and body derived from the presented bytes.
    // ⚠ With a `Cursor` over the drawn slice, NOT draws after it: a knob drawn
    // after the byte draw is dead on a corpus replay, which is how the secret
    // was one NUL octet and the body empty on every run.
    var knobs: tkfuzz.Cursor = .{ .bytes = presented };
    var secret_buf: [32]u8 = undefined;
    const secret_len: usize = knobs.ranged(1, secret_buf.len); // Verifier requires nonempty
    for (secret_buf[0..secret_len]) |*b| b.* = knobs.byte();
    var body_buf: [64]u8 = undefined;
    const body_len: usize = knobs.ranged(0, body_buf.len);
    for (body_buf[0..body_len]) |*b| b.* = knobs.byte();
    _ = verify(secret_buf[0..secret_len], body_buf[0..body_len], presented);
}

test "corpus: every presented value reaches presentedMac, and the counts are pinned" {
    // ⭐ The measurement, executable rather than written in a comment. A seed
    // longer than the harness's buffer reads back EMPTY (`Smith.slice` falls
    // back to the range minimum) and nothing else would notice.
    //
    // Two numbers past `nonempty`, and both are ones the collapsed harness
    // could not produce: `decoded` counts the values that got past the length
    // and prefix gates into `hexToBytes` under EITHER prefix, and `accepted`
    // counts the ones that actually verified against the anchor credential —
    // a branch no randomly-drawn secret can reach.
    var nonempty: usize = 0;
    var decoded: usize = 0;
    var accepted: usize = 0;
    var distinct_secrets: usize = 0;
    var seen: [presented_seeds.len][32]u8 = undefined;
    var seen_len: [presented_seeds.len]usize = undefined;
    for (presented_seeds) |sd| {
        var smith: std.testing.Smith = .{ .in = sd };
        var presented_buf: [128]u8 = undefined;
        const presented_len: usize = smith.slice(&presented_buf);
        if (presented_len != 0) nonempty += 1;
        const presented = presented_buf[0..presented_len];

        if (presentedMac("sha256=", presented) != null or presentedMac("", presented) != null) decoded += 1;
        if (verify(anchor_secret, anchor_body, presented)) accepted += 1;
        if (verifyWithPrefix("", anchor_secret, anchor_body, presented)) accepted += 1;

        // The Cursor-derived secret must actually vary with the seed —
        // otherwise the knob is as dead as the draw it replaced.
        var knobs: tkfuzz.Cursor = .{ .bytes = presented };
        var secret_buf: [32]u8 = undefined;
        const secret_len: usize = knobs.ranged(1, secret_buf.len);
        for (secret_buf[0..secret_len]) |*b| b.* = knobs.byte();
        var already = false;
        for (seen[0..distinct_secrets], seen_len[0..distinct_secrets]) |s, l| {
            if (l == secret_len and std.mem.eql(u8, s[0..l], secret_buf[0..secret_len])) already = true;
        }
        if (!already) {
            seen[distinct_secrets] = secret_buf;
            seen_len[distinct_secrets] = secret_len;
            distinct_secrets += 1;
        }
    }
    // One seed IS the empty header value, a legal member of a refusal corpus.
    try testing.expectEqual(presented_seeds.len - 1, nonempty);
    // Measured 2026-09-07: with the collapsing draws, 0 non-empty, 0 decoded,
    // 0 accepted and exactly 1 distinct secret (a single NUL octet) across the
    // whole corpus. After:
    try testing.expectEqual(@as(usize, 5), decoded);
    try testing.expectEqual(@as(usize, 4), accepted);
    try testing.expectEqual(@as(usize, 8), distinct_secrets);
}

test "computeHex is lowercase hex and matches a well-known HMAC-SHA256 demo vector" {
    // NOT an RFC 4231 vector (RFC 4231's HMAC-SHA256 keys/data are the
    // 0x0b*20/"Jefe"/0xaa*20/... test cases) — this key="key" /
    // "The quick brown fox jumps over the lazy dog" pairing is a widely
    // circulated illustrative HMAC-SHA256 example (previously mislabeled
    // here as "RFC-style"); numerically re-verified against `openssl dgst
    // -sha256 -hmac`. See the RFC 4231 / GitHub-docs anchor discussion below
    // for what this module's own external anchor actually is.
    const hex = computeHex("key", "The quick brown fox jumps over the lazy dog");
    try testing.expectEqualStrings(
        "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
        &hex,
    );
}

// ── external anchor: RFC 4231 refuted, GitHub's own published vector adopted ─
//
// RFC 4231 (HMAC-SHA-224/256/384/512 test vectors) anchors the bare HMAC-
// SHA256 PRIMITIVE — but this module's `Hmac` is `std.crypto.auth.hmac.
// sha2.HmacSha256` used directly (see the type alias above); the primitive
// is already anchored upstream, in Zig std's own test suite. Feeding RFC
// 4231's key/data pairs through `computeHex` would just re-verify
// std.crypto's HMAC through a one-line pass-through, i.e. testing someone
// else's code, not this module's contribution — so those vectors are
// deliberately NOT adopted here.
//
// This module's own contribution is the `sha256=<hex>` GitHub-style webhook
// FRAMING on top (computeHex's hex formatting + sign/verify's prefix
// handling) — RFC 4231 says nothing about that framing. A real external
// anchor for it does exist: GitHub's own webhook-validation docs
// (https://docs.github.com/en/webhooks/using-webhooks/validating-webhook-deliveries)
// publish a canonical secret/payload/signature triple specifically so a
// third-party implementation can self-check against it. Independently
// reproduced here with `openssl dgst -sha256 -hmac "It's a Secret to
// Everybody"` over the literal bytes "Hello, World!", which reproduces
// GitHub's published "sha256=757107ea0eb2..." value exactly — this is the
// module's real framing-level anchor, not RFC 4231.
test "GitHub docs' published canonical webhook signature (framing anchor, not RFC 4231)" {
    const secret = "It's a Secret to Everybody";
    const body = "Hello, World!";
    const want = "sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17";

    var buf: [signatureBufLen(default_prefix)]u8 = undefined;
    try testing.expectEqualStrings(want, try sign(secret, body, &buf));
    try testing.expect(verify(secret, body, want));
}

test "custom prefix (empty / non-default) signs and verifies" {
    const secret = "s";
    const body = "b";
    var buf: [signature_hex_len]u8 = undefined;
    const bare = try signWithPrefix("", secret, body, &buf);
    try testing.expectEqual(@as(usize, signature_hex_len), bare.len);
    try testing.expect(verifyWithPrefix("", secret, body, bare));
    // The bare-hex value must not verify under the default prefix.
    try testing.expect(!verify(secret, body, bare));
}

// ── tests: Verifier (secret set) ────────────────────────────────────────────

test "Verifier.verifyBody: rotation — old and new secret both accepted, without early exit" {
    var v = try Verifier.init(testing.allocator, .{
        .secret = "new-secret",
        .extra_secrets = &.{"old-secret"},
    });
    defer v.deinit();
    try testing.expectEqual(@as(usize, 2), v.secretCount());

    const body = "event=push";
    var nbuf: [64 + 8]u8 = undefined;
    var obuf: [64 + 8]u8 = undefined;
    const new_sig = try sign("new-secret", body, &nbuf);
    const old_sig = try sign("old-secret", body, &obuf);

    try testing.expect(v.verifyBody(body, new_sig)); // current secret
    try testing.expect(v.verifyBody(body, old_sig)); // rotated-out secret still valid
    // `sign` returns a slice INTO its out_buf: signing into `nbuf` here would
    // clobber `new_sig` and silently defang the tampered-body control below.
    var gbuf: [64 + 8]u8 = undefined;
    try testing.expect(!v.verifyBody(body, try sign("gone-secret", body, &gbuf))); // never configured
    // Negative control: a signature valid for `body` must NOT verify against a
    // different body — proves the MAC covers the body, not just the secret set.
    try testing.expect(!v.verifyBody("event=pull", new_sig)); // tampered body
}

// ── tests: middleware over the socket-free server codec ──────────────────────

const Reader = std.Io.Reader;
const Writer = std.Io.Writer;

/// Drive a router through `http.Server.serveStream` with canned wire bytes
/// (same harness as router/aaa-gate); returns the full response bytes.
fn runWire(r: *router.Router, bytes: []const u8, out_buf: []u8) []const u8 {
    var in: Reader = .fixed(bytes);
    var out: Writer = .fixed(out_buf);
    var head_buf: [2048]u8 = undefined;
    var request_body_buf: [1024]u8 = undefined;
    var response_body_buf: [1024]u8 = undefined;
    var chunk_buf: [256]u8 = undefined;
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

/// Build `POST /hook` wire bytes with an optional signature header and a body.
fn buildReq(buf: []u8, sig_header: ?[]const u8, sig_value: ?[]const u8, body: []const u8) []const u8 {
    var w: Writer = .fixed(buf);
    w.writeAll("POST /hook HTTP/1.1\r\nHost: t\r\n") catch unreachable;
    if (sig_value) |val| {
        const name = sig_header orelse default_header;
        w.print("{s}: {s}\r\n", .{ name, val }) catch unreachable;
    }
    w.print("Connection: close\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body }) catch unreachable;
    return w.buffered();
}

fn expectStatus(got: []const u8, comptime status: []const u8) !void {
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 " ++ status));
}

fn bodyOfResp(got: []const u8) []const u8 {
    return got[std.mem.indexOf(u8, got, "\r\n\r\n").? + 4 ..];
}

/// Handler that echoes the verified body it received via `bodyOf` — a
/// missing attachment errors → 500, so a 200 with the echoed body proves
/// both that verification passed and that the body survived the read.
fn hEcho(ctx: *router.Ctx) anyerror!void {
    const body = bodyOf(ctx) orelse return error.NoBody;
    try ctx.res.writeAll(body);
}

fn gatedRouter(v: *Verifier) !router.Router {
    var r = router.Router.init(testing.allocator);
    errdefer r.deinit();
    try r.use(v.middleware());
    try r.post("/hook", hEcho);
    return r;
}

test "middleware: correctly-signed body passes 200 and the handler sees it" {
    var v = try Verifier.init(testing.allocator, .{ .secret = "whsec" });
    defer v.deinit();
    var r = try gatedRouter(&v);
    defer r.deinit();

    const body = "{\"action\":\"opened\"}";
    var sbuf: [64 + 8]u8 = undefined;
    const sig = try sign("whsec", body, &sbuf);

    var reqbuf: [512]u8 = undefined;
    var respbuf: [1024]u8 = undefined;
    const got = runWire(&r, buildReq(&reqbuf, null, sig, body), &respbuf);
    try expectStatus(got, "200");
    try testing.expectEqualStrings(body, bodyOfResp(got)); // handler re-read the stashed body
}

test "middleware: missing header, tampered body and wrong secret each → 401" {
    var v = try Verifier.init(testing.allocator, .{ .secret = "whsec" });
    defer v.deinit();
    var r = try gatedRouter(&v);
    defer r.deinit();

    const body = "hello-webhook";
    var sbuf: [64 + 8]u8 = undefined;
    const good = try sign("whsec", body, &sbuf);

    var reqbuf: [512]u8 = undefined;
    var respbuf: [1024]u8 = undefined;

    // Missing signature header.
    const miss = runWire(&r, buildReq(&reqbuf, null, null, body), &respbuf);
    try expectStatus(miss, "401");
    try testing.expect(std.mem.indexOf(u8, miss, "\r\nWWW-Authenticate: Signature\r\n") != null);

    // Correct signature but the delivered body was altered in flight.
    var rb2: [512]u8 = undefined;
    const tampered = runWire(&r, buildReq(&rb2, null, good, "hello-webhook!"), &respbuf);
    try expectStatus(tampered, "401");

    // A signature made with a different secret.
    var wbuf: [64 + 8]u8 = undefined;
    const wrong = try sign("attacker", body, &wbuf);
    var rb3: [512]u8 = undefined;
    try expectStatus(runWire(&r, buildReq(&rb3, null, wrong, body), &respbuf), "401");

    // The good one still passes (sanity).
    var rb4: [512]u8 = undefined;
    try expectStatus(runWire(&r, buildReq(&rb4, null, good, body), &respbuf), "200");
}

test "middleware: custom header name and rotation both accepted over the wire" {
    var v = try Verifier.init(testing.allocator, .{
        .secret = "new",
        .extra_secrets = &.{"old"},
        .header = "X-Hub-Signature-256",
    });
    defer v.deinit();
    var r = try gatedRouter(&v);
    defer r.deinit();

    const body = "rotate-me";
    var nbuf: [64 + 8]u8 = undefined;
    var obuf: [64 + 8]u8 = undefined;
    const new_sig = try sign("new", body, &nbuf);
    const old_sig = try sign("old", body, &obuf);

    var reqbuf: [512]u8 = undefined;
    var respbuf: [1024]u8 = undefined;

    // The default header name is now wrong → 401 (verifier reads X-Hub-…).
    try expectStatus(runWire(&r, buildReq(&reqbuf, default_header, new_sig, body), &respbuf), "401");

    // Correct custom header, current secret → 200.
    var rb2: [512]u8 = undefined;
    try expectStatus(runWire(&r, buildReq(&rb2, "X-Hub-Signature-256", new_sig, body), &respbuf), "200");

    // Correct custom header, rotated-out secret → still 200.
    var rb3: [512]u8 = undefined;
    try expectStatus(runWire(&r, buildReq(&rb3, "X-Hub-Signature-256", old_sig, body), &respbuf), "200");
}

// ── core (2026-10-04): schemes, digests, encodings, timestamps ──────────────
//
// Expected values come from outside this module: the Standard Webhooks
// reference libraries' own sign test (standard-webhooks/standard-webhooks
// libraries/go/webhook_test.go `TestWebhookSign`, read 2026-10-04), Slack's
// documented worked example (docs.slack.dev, "Verifying requests from
// Slack"), and — where no provider publishes a vector (Stripe, SHA-1/512,
// base64, Ed25519 `v1a`) — Python's `hmac` and `openssl pkeyutl -sign` run
// as black boxes over the same inputs. RFC 8032 §7.1 TEST 1's key pair is the
// Ed25519 key (a published test key, not a secret).

const sw_secret = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw";
const sw_id = "msg_p5jXN8AQM9LWM0D4loKWxJek";
const sw_ts: u64 = 1614265330;
const sw_payload = "{\"test\": 2432232314}";
const sw_v1 = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=";
// `openssl pkeyutl -sign -rawin` with RFC 8032 TEST 1's key over
// `sw_id ++ "." ++ "1614265330" ++ "." ++ sw_payload`.
const sw_v1a = "v1a,fldxM4gAKugP6nnt1hdz3sgGfZ6d99nzrMFnZOELIxbzEHoVmAb2ADpkJK7zgPePmPsle0zV9jSeGlHFG2NVAw==";
const sw_whsk = "whsk_nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A=";
const sw_whpk = "whpk_11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=";

test "Standard Webhooks: the reference library's sign vector" {
    var kb: [standard.max_secret_len]u8 = undefined;
    const key = try standard.decodeSecret(&kb, sw_secret);
    try testing.expectEqual(@as(usize, 24), key.len);
    var out: [standard.v1_len]u8 = undefined;
    try testing.expectEqualStrings(sw_v1, try standard.sign(&out, key, sw_id, sw_ts, sw_payload));
    // The prefix is optional on decode (the reference strips it if present).
    var kb2: [standard.max_secret_len]u8 = undefined;
    try testing.expectEqualSlices(u8, key, try standard.decodeSecret(&kb2, sw_secret[6..]));
    // Surrounding SP/TAB (a secret pasted from a config file) is trimmed.
    try testing.expectEqualSlices(u8, key, try standard.decodeSecret(&kb2, " \t" ++ sw_secret ++ " "));
    var eb: [128]u8 = undefined;
    try testing.expectEqualStrings(sw_secret, try standard.encodeSecret(&eb, key));
}

test "Standard Webhooks: verify, multi-signature list, and the tolerance boundary" {
    var kb: [standard.max_secret_len]u8 = undefined;
    const key = try standard.decodeSecret(&kb, sw_secret);
    const keys: standard.Keys = .{ .secrets = &.{key} };
    const now: i64 = @intCast(sw_ts);
    try standard.verify(keys, sw_id, "1614265330", sw_v1, sw_payload, now, 300);
    // The Go reference's "valid multi sig is valid" list: two wrong v1/v2
    // entries before the right one, one after.
    const multi = "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc= v2,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc= " ++
        sw_v1 ++ " v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=";
    try standard.verify(keys, sw_id, "1614265330", multi, sw_payload, now, 300);
    // …and the reference's refusals.
    try testing.expectError(error.NoMatchingSignature, standard.verify(keys, sw_id, "1614265330", "v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=", sw_payload, now, 300));
    try testing.expectError(error.NoMatchingSignature, standard.verify(keys, sw_id, "1614265330", "v1,", sw_payload, now, 300));
    try testing.expectError(error.NoMatchingSignature, standard.verify(keys, sw_id, "1614265330", sw_v1, sw_payload ++ " ", now, 300));
    try testing.expectError(error.NoMatchingSignature, standard.verify(keys, "msg_other", "1614265330", sw_v1, sw_payload, now, 300));
    // The timestamp is part of the signed content, not only a freshness gate.
    try testing.expectError(error.NoMatchingSignature, standard.verify(keys, sw_id, "1614265331", sw_v1, sw_payload, now, 300));
    // Inclusive at exactly 300 s, refused one second past it, both sides.
    try standard.verify(keys, sw_id, "1614265330", sw_v1, sw_payload, now + 300, 300);
    try standard.verify(keys, sw_id, "1614265330", sw_v1, sw_payload, now - 300, 300);
    try testing.expectError(error.TimestampTooOld, standard.verify(keys, sw_id, "1614265330", sw_v1, sw_payload, now + 301, 300));
    try testing.expectError(error.TimestampTooNew, standard.verify(keys, sw_id, "1614265330", sw_v1, sw_payload, now - 301, 300));
    // Leading zeros re-spell to the same decimal the sender signed.
    try standard.verify(keys, sw_id, "01614265330", sw_v1, sw_payload, now, 300);
    try testing.expectError(error.InvalidHeader, standard.verify(keys, "", "1614265330", sw_v1, sw_payload, now, 300));
    // Rotation: a wrong key next to the right one still verifies, in either
    // order (a match is never overwritten by a later miss).
    const rot: standard.Keys = .{ .secrets = &.{ "a-different-key-of-24-bytes!", key } };
    try standard.verify(rot, sw_id, "1614265330", sw_v1, sw_payload, now, 300);
    const rot2: standard.Keys = .{ .secrets = &.{ key, "a-different-key-of-24-bytes!" } };
    try standard.verify(rot2, sw_id, "1614265330", sw_v1, sw_payload, now, 300);
    // …and a matching signature followed by a non-matching one still wins.
    try standard.verify(keys, sw_id, "1614265330", sw_v1 ++ " v1,Ceo5qEr07ixe2NLpvHk3FH9bwy/WavXrAFQ/9tdO6mc=", sw_payload, now, 300);
}

test "Standard Webhooks: more than max_signatures entries is refused" {
    var kb: [standard.max_secret_len]u8 = undefined;
    const key = try standard.decodeSecret(&kb, sw_secret);
    const junk = "v9,x " ** max_signatures;
    try testing.expectError(error.InvalidHeader, standard.verify(.{ .secrets = &.{key} }, sw_id, "1614265330", junk ++ sw_v1, sw_payload, @intCast(sw_ts), 300));
    // Exactly max_signatures entries, the good one last, is fine.
    const ok_list = "v9,x " ** (max_signatures - 1);
    try standard.verify(.{ .secrets = &.{key} }, sw_id, "1614265330", ok_list ++ sw_v1, sw_payload, @intCast(sw_ts), 300);
}

test "Standard Webhooks v1a: Ed25519 against openssl, both whsk_ layouts" {
    const kp = try standard.decodeSigningKey(sw_whsk);
    const pk = try standard.decodePublicKey(sw_whpk);
    try testing.expectEqualSlices(u8, &pk.toBytes(), &kp.public_key.toBytes());
    var out: [standard.v1a_len]u8 = undefined;
    var scratch: [128]u8 = undefined;
    try testing.expectEqualStrings(sw_v1a, try standard.signEd25519(&out, &scratch, kp, sw_id, sw_ts, sw_payload));
    try testing.expectError(error.OutputTooSmall, standard.signEd25519(&out, scratch[0..20], kp, sw_id, sw_ts, sw_payload));
    const keys: standard.Keys = .{ .public_keys = &.{pk} };
    try standard.verify(keys, sw_id, "1614265330", sw_v1a, sw_payload, @intCast(sw_ts), 300);
    try standard.verify(keys, sw_id, "1614265330", "v1,AAAA " ++ sw_v1a, sw_payload, @intCast(sw_ts), 300);
    try testing.expectError(error.NoMatchingSignature, standard.verify(keys, sw_id, "1614265330", sw_v1a, "{}", @intCast(sw_ts), 300));
    // A v1a value is never taken as v1 and vice versa.
    try testing.expectError(error.NoMatchingSignature, standard.verify(keys, sw_id, "1614265330", sw_v1, sw_payload, @intCast(sw_ts), 300));
    // The 64-byte seed‖public layout decodes to the same pair; a public half
    // that does not belong to the seed is refused.
    const kp64 = try standard.decodeSigningKey("whsk_nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2DXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGg==");
    try testing.expectEqualSlices(u8, &kp.public_key.toBytes(), &kp64.public_key.toBytes());
    try testing.expectError(error.InvalidKey, standard.decodeSigningKey("whsk_nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="));
    try testing.expectError(error.InvalidKey, standard.decodePublicKey("whpk_AAAA"));
    // The v1a cap: max_ed25519_signatures junk entries before the good one
    // are one too many.
    const junk = "v1a,x " ** max_ed25519_signatures;
    try testing.expectError(error.InvalidHeader, standard.verify(keys, sw_id, "1614265330", junk ++ sw_v1a, sw_payload, @intCast(sw_ts), 300));
    const fits = "v1a,x " ** (max_ed25519_signatures - 1);
    try standard.verify(keys, sw_id, "1614265330", fits ++ sw_v1a, sw_payload, @intCast(sw_ts), 300);
}

test "Standard Webhooks: secret decoding refusals" {
    var kb: [standard.max_secret_len]u8 = undefined;
    // 23 bytes: one short of the spec's 24-byte minimum.
    try testing.expectError(error.InvalidKey, standard.decodeSecret(&kb, "whsec_eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg="));
    try testing.expectError(error.InvalidKey, standard.decodeSecret(&kb, "whsec_"));
    try testing.expectError(error.InvalidKey, standard.decodeSecret(&kb, "whsec_not*base64!"));
    // 65 bytes: one past the 64-byte maximum.
    try testing.expectError(error.InvalidKey, standard.decodeSecret(&kb, "whsec_" ++ "A" ** 88));
    var eb: [128]u8 = undefined;
    try testing.expectError(error.InvalidKey, standard.encodeSecret(&eb, "short"));
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, standard.encodeSecret(&tiny, "x" ** 24));
}

// Slack's documented example, transcribed from docs.slack.dev and
// re-verified with Python's `hmac` before adoption.
const slack_secret = "8f742231b10e8888abcd99yyyzzz85a5";
const slack_body = "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";
const slack_sig = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";

test "Slack: the documented example signs and verifies" {
    var out: [slack.signature_len]u8 = undefined;
    try testing.expectEqualStrings(slack_sig, try slack.sign(&out, slack_secret, 1531420618, slack_body));
    try slack.verify(&.{slack_secret}, "1531420618", slack_sig, slack_body, 1531420618, 300);
    try slack.verify(&.{ "old", slack_secret }, "1531420618", slack_sig, slack_body, 1531420618 + 300, 300);
    try slack.verify(&.{ slack_secret, "old" }, "1531420618", slack_sig, slack_body, 1531420618 - 300, 300);
    try testing.expectError(error.TimestampTooOld, slack.verify(&.{slack_secret}, "1531420618", slack_sig, slack_body, 1531420618 + 301, 300));
    try testing.expectError(error.NoMatchingSignature, slack.verify(&.{slack_secret}, "1531420619", slack_sig, slack_body, 1531420618, 300));
    try testing.expectError(error.NoMatchingSignature, slack.verify(&.{slack_secret}, "1531420618", "v1=" ++ slack_sig[3..], slack_body, 1531420618, 300));
    try testing.expectError(error.InvalidTimestamp, slack.verify(&.{slack_secret}, "", slack_sig, slack_body, 1531420618, 300));
}

test "Stripe: sign and verify (Python hmac as the oracle)" {
    const secret = "whsec_test_secret";
    const payload = "{\"id\":\"evt_test\",\"object\":\"event\"}";
    const want = "t=1492774577,v1=691252e266ce41cb94d709c84e9580d4172b117a510bbc81723f657d2cd5d215";
    var out: [128]u8 = undefined;
    try testing.expectEqualStrings(want, try stripe.sign(&out, secret, 1492774577, payload));
    try stripe.verify(&.{secret}, want, payload, 1492774577, 300);
    // Stripe sends extra schemes and several v1 values; spaces tolerated.
    try stripe.verify(&.{secret}, "t=1492774577, v1=" ++ "00" ** 32 ++ ", v1=" ++ want[16..] ++ ",v0=abc", payload, 1492774577, 300);
    try stripe.verify(&.{ "whsec_old", secret }, want, payload, 1492774577, 300);
    try stripe.verify(&.{ secret, "whsec_old" }, want, payload, 1492774577, 300);
    try testing.expectError(error.InvalidHeader, stripe.verify(&.{secret}, want[13..], payload, 1492774577, 300)); // no t=
    try testing.expectError(error.NoMatchingSignature, stripe.verify(&.{secret}, "t=1492774577,v0=" ++ want[16..], payload, 1492774577, 300));
    try testing.expectError(error.NoMatchingSignature, stripe.verify(&.{secret}, want, payload ++ "x", 1492774577, 300));
    try testing.expectError(error.TimestampTooOld, stripe.verify(&.{secret}, want, payload, 1492774577 + 301, 300));
    try testing.expectError(error.TimestampTooNew, stripe.verify(&.{secret}, want, payload, 1492774577 - 301, 300));
    // The first t= wins; a second one cannot move the window.
    try testing.expectError(error.NoMatchingSignature, stripe.verify(&.{secret}, "t=1492774578," ++ want, payload, 1492774577, 300));
    var tiny: [16]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, stripe.sign(&tiny, secret, 1492774577, payload));
}

test "Format: SHA-1 / SHA-512 and base64 against Python hmac on GitHub's triple" {
    const secret = "It's a Secret to Everybody";
    const body = "Hello, World!";
    const cases = [_]struct { f: Format, want: []const u8 }{
        .{ .f = .{ .prefix = "sha1=", .digest = .sha1 }, .want = "sha1=01dc10d0c83e72ed246219cdd91669667fe2ca59" },
        .{ .f = .{ .prefix = "", .encoding = .base64 }, .want = "dXEH6g6yUJ/CESIczphLijdXC211hsIsRvQ3nIsEPhc=" },
        .{ .f = .{ .prefix = "sha512=", .digest = .sha512, .encoding = .base64 }, .want = "sha512=Ee01WmF+mBNOhCASp5RMz1nBAlbLGCNXvX46QgE/8Hw3b4wUz1zBkj2iC1HWQlay+4678QCqZ6YTJvYf6oERvA==" },
        .{ .f = .{ .prefix = "sha512=", .digest = .sha512 }, .want = "sha512=11ed355a617e98134e842012a7944ccf59c10256cb182357bd7e3a42013ff07c376f8c14cf5cc1923da20b51d64256b2fb8ebbf100aa67a61326f61fea8111bc" },
    };
    for (cases) |c| {
        var out: [256]u8 = undefined;
        try testing.expectEqualStrings(c.want, try signFormat(c.f, secret, body, &out));
        try testing.expectEqual(c.want.len, c.f.signatureLen());
        try testing.expect(verifyFormat(c.f, secret, body, c.want));
        try testing.expect(!verifyFormat(c.f, secret, "Hello, World?", c.want));
        try testing.expect(!verifyFormat(c.f, secret, body, c.want[0 .. c.want.len - 1]));
        try testing.expectError(error.OutputTooSmall, signFormat(c.f, secret, body, out[0 .. c.want.len - 1]));
    }
    // Upper-case hex verifies; a SHA-1 MAC under the SHA-256 format does not.
    try testing.expect(verifyFormat(.{ .prefix = "sha1=", .digest = .sha1 }, secret, body, "sha1=01DC10D0C83E72ED246219CDD91669667FE2CA59"));
    try testing.expect(!verifyFormat(.{ .prefix = "sha1=" }, secret, body, "sha1=01dc10d0c83e72ed246219cdd91669667fe2ca59"));
}

test "checkTimestamp: shape and range" {
    try testing.expectEqual(@as(u64, 100), try checkTimestamp(" 100\t", 100, 0));
    for ([_][]const u8{ "", " ", "-1", "+1", "1.5", "1e3", "0x10", "12a", "18446744073709551616", "99999999999999999999" }) |t|
        try testing.expectError(error.InvalidTimestamp, checkTimestamp(t, 0, 300));
    // 19 digits fit a u64; far in the future of any real clock.
    try testing.expectError(error.TimestampTooNew, checkTimestamp("9999999999999999999", std.math.maxInt(i64), 300));
    // `now` at the i64 extremes does not overflow the age.
    try testing.expectError(error.TimestampTooNew, checkTimestamp("1", std.math.minInt(i64), 300));
    try testing.expectError(error.TimestampTooOld, checkTimestamp("0", std.math.maxInt(i64), 300));
}

test "Clock.fromIo reads a plausible real time" {
    const c = Clock.fromIo(&testing.io);
    try testing.expect(c.now() > 1_600_000_000);
}

// ── middleware over the wire, each scheme ───────────────────────────────────

var fixed_now: i64 = 0;
fn fixedNow(_: ?*anyopaque) i64 {
    return fixed_now;
}
const fixed_clock: Clock = .{ .nowFn = fixedNow };

fn buildReqHeaders(buf: []u8, headers: []const [2][]const u8, body: []const u8) []const u8 {
    var w: Writer = .fixed(buf);
    w.writeAll("POST /hook HTTP/1.1\r\nHost: t\r\n") catch unreachable;
    for (headers) |h| w.print("{s}: {s}\r\n", .{ h[0], h[1] }) catch unreachable;
    w.print("Connection: close\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body }) catch unreachable;
    return w.buffered();
}

test "middleware: Standard Webhooks — v1, v1a, stale, missing id" {
    var kb: [standard.max_secret_len]u8 = undefined;
    const key = try standard.decodeSecret(&kb, sw_secret);
    var v = try Verifier.init(testing.allocator, .{
        .secret = key,
        .scheme = .standard_webhooks,
        .public_keys = &.{try standard.decodePublicKey(sw_whpk)},
        .clock = fixed_clock,
    });
    defer v.deinit();
    var r = try gatedRouter(&v);
    defer r.deinit();
    var reqbuf: [1024]u8 = undefined;
    var respbuf: [1024]u8 = undefined;
    fixed_now = @intCast(sw_ts + 10);
    const good = runWire(&r, buildReqHeaders(&reqbuf, &.{ .{ "webhook-id", sw_id }, .{ "webhook-timestamp", "1614265330" }, .{ "webhook-signature", sw_v1 } }, sw_payload), &respbuf);
    try expectStatus(good, "200");
    try testing.expectEqualStrings(sw_payload, bodyOfResp(good));
    try expectStatus(runWire(&r, buildReqHeaders(&reqbuf, &.{ .{ "Webhook-Id", sw_id }, .{ "Webhook-Timestamp", "1614265330" }, .{ "Webhook-Signature", sw_v1a } }, sw_payload), &respbuf), "200");
    try expectStatus(runWire(&r, buildReqHeaders(&reqbuf, &.{ .{ "webhook-timestamp", "1614265330" }, .{ "webhook-signature", sw_v1 } }, sw_payload), &respbuf), "401");
    try expectStatus(runWire(&r, buildReqHeaders(&reqbuf, &.{ .{ "webhook-id", sw_id }, .{ "webhook-signature", sw_v1 } }, sw_payload), &respbuf), "401");
    fixed_now = @intCast(sw_ts + 301);
    try expectStatus(runWire(&r, buildReqHeaders(&reqbuf, &.{ .{ "webhook-id", sw_id }, .{ "webhook-timestamp", "1614265330" }, .{ "webhook-signature", sw_v1 } }, sw_payload), &respbuf), "401");
}

test "middleware: a stale delivery is refused before its body is read" {
    // The freshness check runs on the headers alone: a stale request with a
    // body over `max_body_bytes` gets 401 (refused unread), not the 413 that
    // reading it would produce — for Stripe, whose timestamp sits inside
    // the signature header, and for Slack.
    fixed_now = 1492774577 + 301;
    var vt = try Verifier.init(testing.allocator, .{ .secret = "k", .scheme = .stripe, .clock = fixed_clock, .max_body_bytes = 4 });
    defer vt.deinit();
    var rt = try gatedRouter(&vt);
    defer rt.deinit();
    var reqbuf: [1024]u8 = undefined;
    var respbuf: [1024]u8 = undefined;
    try expectStatus(runWire(&rt, buildReqHeaders(&reqbuf, &.{.{ "Stripe-Signature", "t=1492774577,v1=00" }}, "longer than four"), &respbuf), "401");
    // Fresh, same body: now the size limit answers.
    fixed_now = 1492774577;
    try expectStatus(runWire(&rt, buildReqHeaders(&reqbuf, &.{.{ "Stripe-Signature", "t=1492774577,v1=00" }}, "longer than four"), &respbuf), "413");
    var vs = try Verifier.init(testing.allocator, .{ .secret = "k", .scheme = .slack, .clock = fixed_clock, .max_body_bytes = 4 });
    defer vs.deinit();
    var rs = try gatedRouter(&vs);
    defer rs.deinit();
    try expectStatus(runWire(&rs, buildReqHeaders(&reqbuf, &.{ .{ "X-Slack-Request-Timestamp", "1" }, .{ "X-Slack-Signature", "v0=00" } }, "longer than four"), &respbuf), "401");
}

test "middleware: Stripe and Slack schemes" {
    fixed_now = 1531420618;
    var vs = try Verifier.init(testing.allocator, .{ .secret = slack_secret, .scheme = .slack, .clock = fixed_clock });
    defer vs.deinit();
    var rs = try gatedRouter(&vs);
    defer rs.deinit();
    var reqbuf: [1024]u8 = undefined;
    var respbuf: [1024]u8 = undefined;
    try expectStatus(runWire(&rs, buildReqHeaders(&reqbuf, &.{ .{ "X-Slack-Request-Timestamp", "1531420618" }, .{ "X-Slack-Signature", slack_sig } }, slack_body), &respbuf), "200");
    try expectStatus(runWire(&rs, buildReqHeaders(&reqbuf, &.{.{ "X-Slack-Signature", slack_sig }}, slack_body), &respbuf), "401");

    fixed_now = 1492774577;
    var vt = try Verifier.init(testing.allocator, .{ .secret = "whsec_test_secret", .scheme = .stripe, .clock = fixed_clock });
    defer vt.deinit();
    var rt = try gatedRouter(&vt);
    defer rt.deinit();
    const payload = "{\"id\":\"evt_test\",\"object\":\"event\"}";
    const sig = "t=1492774577,v1=691252e266ce41cb94d709c84e9580d4172b117a510bbc81723f657d2cd5d215";
    try expectStatus(runWire(&rt, buildReqHeaders(&reqbuf, &.{.{ "Stripe-Signature", sig }}, payload), &respbuf), "200");
    try expectStatus(runWire(&rt, buildReqHeaders(&reqbuf, &.{.{ "Stripe-Signature", sig }}, payload ++ " "), &respbuf), "401");
    try expectStatus(runWire(&rt, buildReqHeaders(&reqbuf, &.{.{ "Stripe-Signature", sig[13..] }}, payload), &respbuf), "401");
}

test "middleware: prefixed scheme with SHA-512 base64" {
    var v = try Verifier.init(testing.allocator, .{
        .secret = "It's a Secret to Everybody",
        .header = "X-Hmac",
        .prefix = "",
        .digest = .sha512,
        .encoding = .base64,
    });
    defer v.deinit();
    var r = try gatedRouter(&v);
    defer r.deinit();
    var reqbuf: [1024]u8 = undefined;
    var respbuf: [1024]u8 = undefined;
    const sig = "Ee01WmF+mBNOhCASp5RMz1nBAlbLGCNXvX46QgE/8Hw3b4wUz1zBkj2iC1HWQlay+4678QCqZ6YTJvYf6oERvA==";
    try expectStatus(runWire(&r, buildReqHeaders(&reqbuf, &.{.{ "X-Hmac", sig }}, "Hello, World!"), &respbuf), "200");
    try expectStatus(runWire(&r, buildReqHeaders(&reqbuf, &.{.{ "X-Hmac", sig }}, "Hello, World?"), &respbuf), "401");
}

// ── seeded sweep: hostile headers never panic; signatures are exact ─────────
//
// Two halves, both deterministic. (1) Headers built from scheme fragments and
// damaged at random go through every verifier and parser: no panic, and a
// damaged signature is never accepted unless it is byte-identical to a valid
// one. (2) Oracle: random keys, ids, timestamps and payloads sign → verify
// under every scheme, and one flipped byte of id, timestamp, payload or
// signature is refused.

const SweepReach = struct {
    parsed_ok: usize = 0,
    too_old: usize = 0,
    too_new: usize = 0,
    bad_ts: usize = 0,
    bad_header: usize = 0,
    no_match: usize = 0,
    roundtrips: usize = 0,
    flips_refused: usize = 0,
};

fn genText(r: std.Random, buf: []u8) []u8 {
    const frags = [_][]const u8{ "v1,", "v1a,", "v2,", " ", ",", "t=", "v1=", "v0=", "1614265330", "1492774577", "=", "==", "AAAA", "g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE=", "00", "ff", "-", "9999999999999999999" };
    var n: usize = 0;
    const want = r.uintAtMost(usize, buf.len);
    while (n < want) {
        if (r.uintLessThan(u8, 6) == 0) {
            buf[n] = r.int(u8);
            n += 1;
            continue;
        }
        const f = frags[r.uintLessThan(usize, frags.len)];
        if (n + f.len > buf.len) break;
        @memcpy(buf[n..][0..f.len], f);
        n += f.len;
    }
    return buf[0..n];
}

fn tally(reach: *SweepReach, res: VerifyError!void) void {
    if (res) |_| reach.parsed_ok += 1 else |e| switch (e) {
        error.TimestampTooOld => reach.too_old += 1,
        error.TimestampTooNew => reach.too_new += 1,
        error.InvalidTimestamp => reach.bad_ts += 1,
        error.InvalidHeader => reach.bad_header += 1,
        error.NoMatchingSignature => reach.no_match += 1,
    }
}

test "sweep: hostile headers never panic; sign/verify is exact under every scheme" {
    var reach: SweepReach = .{};
    var kb: [standard.max_secret_len]u8 = undefined;
    const key = try standard.decodeSecret(&kb, sw_secret);
    const pk = try standard.decodePublicKey(sw_whpk);
    var k: u64 = 0;
    while (k < 6000) : (k += 1) {
        var prng = std.Random.DefaultPrng.init(k);
        const r = prng.random();
        var b1: [200]u8 = undefined;
        var b2: [40]u8 = undefined;
        // Half the inputs carry a fresh timestamp, so the damage reaches the
        // signature parsers instead of stopping at the clock check.
        const fresh = r.boolean();
        if (fresh) @memcpy(b1[0..13], "t=1614265330,");
        const sigs = if (fresh) b1[0 .. 13 + genText(r, b1[13..]).len] else genText(r, &b1);
        const ts = if (fresh) "1614265330" else genText(r, &b2);
        const now: i64 = if (fresh or r.boolean()) @intCast(sw_ts) else r.int(i64);
        const sw = standard.verify(.{ .secrets = &.{key}, .public_keys = &.{pk} }, sw_id, ts, sigs, sw_payload, now, 300);
        // The fragment list carries the one genuine v1 signature; an accepted
        // header must contain it whole.
        if (sw) |_| {
            if (std.mem.indexOf(u8, sigs, sw_v1) == null) return error.ForgedAccepted;
        } else |_| {}
        tally(&reach, sw);
        const st = stripe.verify(&.{"s"}, sigs, sw_payload, now, 300);
        const sl = slack.verify(&.{"s"}, ts, sigs, sw_payload, now, 300);
        if (st) |_| return error.ForgedAccepted else |_| {}
        if (sl) |_| return error.ForgedAccepted else |_| {}
        tally(&reach, st);
        tally(&reach, sl);
        for ([_]Format{ .{}, .{ .prefix = "", .digest = .sha512, .encoding = .base64 }, .{ .prefix = "v1,", .digest = .sha1 } }) |f|
            if (verifyFormat(f, "s", sw_payload, sigs)) return error.ForgedAccepted;
    }
    k = 0;
    while (k < 1500) : (k += 1) {
        var prng = std.Random.DefaultPrng.init(k ^ 0xabcdef);
        const r = prng.random();
        var keyb: [32]u8 = undefined;
        r.bytes(&keyb);
        var idb: [12]u8 = undefined;
        for (&idb) |*c| c.* = 'a' + r.uintLessThan(u8, 26);
        var pb: [48]u8 = undefined;
        const plen = r.uintAtMost(usize, pb.len);
        r.bytes(pb[0..plen]);
        const payload = pb[0..plen];
        const ts = r.uintAtMost(u64, 4_000_000_000);
        var tsb: [20]u8 = undefined;
        const ts_text = writeDecimal(&tsb, ts);
        const now: i64 = @intCast(ts);

        var s1: [standard.v1_len]u8 = undefined;
        const v1 = try standard.sign(&s1, &keyb, &idb, ts, payload);
        try standard.verify(.{ .secrets = &.{&keyb} }, &idb, ts_text, v1, payload, now, 0);
        var s2: [128]u8 = undefined;
        const st = try stripe.sign(&s2, &keyb, ts, payload);
        try stripe.verify(&.{&keyb}, st, payload, now, 0);
        var s3: [slack.signature_len]u8 = undefined;
        const sl = try slack.sign(&s3, &keyb, ts, payload);
        try slack.verify(&.{&keyb}, ts_text, sl, payload, now, 0);
        reach.roundtrips += 3;

        // One flipped byte anywhere must be refused.
        var m1 = s1;
        const at = 3 + r.uintLessThan(usize, 43); // inside the base64 MAC, before the pad
        m1[at] = if (m1[at] == 'A') 'B' else 'A';
        if (standard.verify(.{ .secrets = &.{&keyb} }, &idb, ts_text, &m1, payload, now, 0)) |_| return error.FlipAccepted else |_| reach.flips_refused += 1;
        var id2 = idb;
        id2[r.uintLessThan(usize, id2.len)] ^= 1;
        if (standard.verify(.{ .secrets = &.{&keyb} }, &id2, ts_text, v1, payload, now, 5)) |_| return error.FlipAccepted else |_| reach.flips_refused += 1;
        if (plen > 0) {
            var p2 = pb;
            p2[r.uintLessThan(usize, plen)] ^= 0x80;
            if (stripe.verify(&.{&keyb}, st, p2[0..plen], now, 0)) |_| return error.FlipAccepted else |_| reach.flips_refused += 1;
            if (slack.verify(&.{&keyb}, ts_text, sl, p2[0..plen], now, 0)) |_| return error.FlipAccepted else |_| reach.flips_refused += 1;
        }
    }
    // Reach floors (measured 2026-10-04, see SPEC.md § Verification).
    // Measured: genuine v1 found 5, too old 92, too new 187, bad timestamp
    // 6174, bad header 2379, no match 9163, flips refused 5940.
    try testing.expect(reach.parsed_ok > 0);
    try testing.expect(reach.too_old > 50);
    try testing.expect(reach.too_new > 100);
    try testing.expect(reach.bad_ts > 4000);
    try testing.expect(reach.bad_header > 1500);
    try testing.expect(reach.no_match > 7000);
    try testing.expectEqual(@as(usize, 4500), reach.roundtrips);
    try testing.expect(reach.flips_refused > 5000);
}

// ── tests added for mutation survivors (2026-10-04) ─────────────────────────

test "a signature one byte short is refused even when the missing byte is zero" {
    // HMAC-SHA256("whsec_test_secret", `1492774577.{"n":53}`) ends in 0x00
    // (found and computed with Python's `hmac`). Without the exact-length
    // check, the 62-hex-digit value would decode into a zero-padded buffer
    // and compare EQUAL — a truncated signature accepted.
    const full = "d71d17d21368b52c26af081e5762aaab576d215be834de1858b027c72011d400";
    try stripe.verify(&.{"whsec_test_secret"}, "t=1492774577,v1=" ++ full, "{\"n\":53}", 1492774577, 0);
    try testing.expectError(error.NoMatchingSignature, stripe.verify(&.{"whsec_test_secret"}, "t=1492774577,v1=" ++ full[0..62], "{\"n\":53}", 1492774577, 0));
}

test "Standard Webhooks key encodings: sizes outside the spec are refused" {
    var eb: [256]u8 = undefined;
    // 64 bytes is the spec's maximum and encodes; 65 does not.
    _ = try standard.encodeSecret(&eb, "k" ** 64);
    try testing.expectError(error.InvalidKey, standard.encodeSecret(&eb, "k" ** 65));
    // Unpadded base64 is accepted (the reference libraries append "==" before
    // decoding): 25 bytes of 'x', padded and unpadded (Python's base64).
    var kb: [standard.max_secret_len]u8 = undefined;
    try testing.expectEqualStrings("x" ** 25, try standard.decodeSecret(&kb, "whsec_eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA=="));
    try testing.expectEqualStrings("x" ** 25, try standard.decodeSecret(&kb, "whsec_eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eA"));
    // A public key is exactly 32 bytes: the 64-byte signing-key value is not one.
    try testing.expectError(error.InvalidKey, standard.decodePublicKey("whpk_nWGxne/9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2DXWpgBgrEKt9VL/tPJZAc6DuFy89qmIyWvAhpo9wdRGg=="));
}
