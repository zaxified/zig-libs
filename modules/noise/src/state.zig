// SPDX-License-Identifier: MIT
//! Noise Protocol Framework cryptographic state objects (spec rev 34 §5):
//! `CipherState` (§5.1), `SymmetricState` (§5.2), `HandshakeState` (§5.3).
//!
//! Clean-room implementation from the spec text (noiseprotocol.org, revision
//! 34). Pure `std.crypto`, zero dependencies. Verified byte-exact against the
//! official Noise test vectors (rweather/noise-c `tests/vector/
//! noise-c-basic.txt`, the "cacophony" JSON vector format) — see the KAT
//! tests at the bottom of this file.

const std = @import("std");
const chachapoly = @import("chachapoly");
const patterns = @import("patterns.zig");
const Token = @import("token.zig").Token;

// ── protocol-name fragments (spec §8) ────────────────────────────────────

fn dhName(comptime T: type) []const u8 {
    if (T == std.crypto.dh.X25519) return "25519";
    @compileError("noise: no spec §8 protocol name for DH type " ++ @typeName(T));
}

/// Spec §8's `ChaChaPoly`/`AESGCM` cipher-name fragment. BOTH
/// ChaCha20-Poly1305 implementations map to the SAME name: the `chachapoly`
/// sibling is byte-exact to `std.crypto.aead.chacha_poly.ChaCha20Poly1305`
/// (differentially anchored in that module over every block-boundary edge
/// length), so which one a suite is bound with is an implementation choice
/// that must NOT reach the wire. The protocol name is hashed into the
/// initial chaining key, so returning two different strings here would fork
/// the handshake transcript and silently break interop.
fn cipherName(comptime T: type) []const u8 {
    if (T == chachapoly.ChaCha20Poly1305) return "ChaChaPoly";
    if (T == std.crypto.aead.chacha_poly.ChaCha20Poly1305) return "ChaChaPoly";
    if (T == std.crypto.aead.aes_gcm.Aes256Gcm) return "AESGCM";
    @compileError("noise: no spec §8 protocol name for AEAD type " ++ @typeName(T));
}

fn hashName(comptime T: type) []const u8 {
    if (T == std.crypto.hash.sha2.Sha256) return "SHA256";
    if (T == std.crypto.hash.sha2.Sha512) return "SHA512";
    if (T == std.crypto.hash.blake2.Blake2s256) return "BLAKE2s";
    if (T == std.crypto.hash.blake2.Blake2b512) return "BLAKE2b";
    @compileError("noise: no spec §8 protocol name for hash type " ++ @typeName(T));
}

/// Bind a Noise cipher suite: `DH` (spec §4.1, e.g. `std.crypto.dh.X25519`),
/// `Cipher` (spec §4.2 AEAD, e.g.
/// `std.crypto.aead.chacha_poly.ChaCha20Poly1305` or
/// `std.crypto.aead.aes_gcm.Aes256Gcm`), `Hash` (spec §4.3, e.g.
/// `std.crypto.hash.sha2.Sha256`, `.Sha512`, `std.crypto.hash.blake2.
/// Blake2s256`, `.Blake2b512`). Returns a namespace holding `CipherState`/
/// `SymmetricState`/`HandshakeState` (spec §5) parameterized on that
/// choice, plus the suite's DH/hash byte widths.
pub fn Suite(comptime DH: type, comptime Cipher: type, comptime Hash: type) type {
    return struct {
        /// The DH function type this suite was bound with (spec §4.1).
        pub const Dh = DH;
        /// The AEAD cipher type this suite was bound with (spec §4.2).
        pub const AeadCipher = Cipher;
        /// The hash function type this suite was bound with (spec §4.3).
        pub const HashFn = Hash;

        /// DH public-key / output length in bytes (spec §4.1's `DHLEN`).
        pub const DHLEN = DH.public_length;
        /// Hash digest / chaining-key / transcript-hash width in bytes
        /// (spec §4.3's `HASHLEN`).
        pub const HASHLEN = Hash.digest_length;
        /// AEAD authentication-tag length (16 for every spec-named AEAD).
        pub const TAGLEN = Cipher.tag_length;
        /// A DH keypair (spec §4.1's abstract `GENERATE_KEYPAIR()` result).
        pub const KeyPair = DH.KeyPair;

        comptime {
            // Spec §4.2: every named AEAD takes a 32-byte key, a 96-bit
            // nonce and produces a 16-byte tag; §4.3 names only 32/64-byte
            // hashes. §5.2's MixKey truncates HKDF output to 32 bytes.
            std.debug.assert(Cipher.key_length == 32);
            std.debug.assert(Cipher.nonce_length == 12);
            std.debug.assert(Cipher.tag_length == 16);
            std.debug.assert(HASHLEN == 32 or HASHLEN == 64);
            std.debug.assert(Hmac.mac_length == HASHLEN);
        }

        const Hmac = std.crypto.auth.hmac.Hmac(Hash);
        const max_nonce: u64 = std.math.maxInt(u64);

        /// Spec §5.1 nonce encoding into the AEAD's 96-bit nonce: 4 zero
        /// bytes then the 64-bit counter — little-endian for ChaChaPoly,
        /// big-endian for AESGCM (spec §12.3/§12.4).
        fn nonceBytes(n: u64) [Cipher.nonce_length]u8 {
            const big = Cipher == std.crypto.aead.aes_gcm.Aes256Gcm;
            var npub = [_]u8{0} ** Cipher.nonce_length;
            std.mem.writeInt(u64, npub[4..12], n, if (big) .big else .little);
            return npub;
        }

        /// Noise `HKDF(chaining_key, input_key_material, num_outputs)`
        /// (spec §4.3): `temp_key = HMAC(ck, ikm)`, then
        /// `output_i = HMAC(temp_key, output_{i-1} || i)`.
        fn noiseHkdf(
            comptime num_outputs: usize,
            chaining_key: *const [HASHLEN]u8,
            input_key_material: []const u8,
        ) [num_outputs][HASHLEN]u8 {
            comptime std.debug.assert(num_outputs >= 1 and num_outputs <= 3);
            var temp_key: [HASHLEN]u8 = undefined;
            Hmac.create(&temp_key, input_key_material, chaining_key);
            defer std.crypto.secureZero(u8, &temp_key);

            var out: [num_outputs][HASHLEN]u8 = undefined;
            Hmac.create(&out[0], &[_]u8{1}, &temp_key);
            comptime var i: usize = 1;
            inline while (i < num_outputs) : (i += 1) {
                var msg: [HASHLEN + 1]u8 = undefined;
                @memcpy(msg[0..HASHLEN], &out[i - 1]);
                msg[HASHLEN] = @intCast(i + 1);
                Hmac.create(&out[i], &msg, &temp_key);
                std.crypto.secureZero(u8, &msg);
            }
            return out;
        }

        /// Spec §5.1: an AEAD key `k` (or "empty") plus an 8-byte nonce
        /// counter `n`. `k` is all-zero while conceptually "empty" —
        /// callers must consult `hasKey()` rather than inspecting `k`
        /// directly, matching the spec's explicit empty/non-empty state.
        pub const CipherState = struct {
            k: [32]u8 = [_]u8{0} ** 32,
            n: u64 = 0,
            has_key: bool = false,

            /// §5.1 `InitializeKey(key)`: sets `k = key`, `n = 0`.
            pub fn initializeKey(self: *CipherState, key: [32]u8) void {
                self.k = key;
                self.n = 0;
                self.has_key = true;
            }

            /// §5.1 `HasKey()`: true unless `k` is still "empty".
            pub fn hasKey(self: *const CipherState) bool {
                return self.has_key;
            }

            /// §5.1 `SetNonce(n)`: an implementation-defined extension
            /// point (spec explicitly permits this for retry/rekey flows).
            pub fn setNonce(self: *CipherState, n: u64) void {
                self.n = n;
            }

            /// The ciphertext expansion the next `encryptWithAd` will add:
            /// `TAGLEN` once a key is present, 0 while "empty".
            pub fn overhead(self: *const CipherState) usize {
                return if (self.has_key) TAGLEN else 0;
            }

            /// §5.1 `EncryptWithAd(ad, plaintext)`: AEAD-encrypts under key
            /// `k` and nonce `n` (then increments `n`), writing
            /// `plaintext.len + overhead()` bytes into `out`. Per the spec,
            /// if `k` is "empty" this returns the plaintext unmodified (and
            /// leaves `n` untouched). Fails with `error.NonceExhausted`
            /// once `n` reaches 2^64-1 (that value is reserved for
            /// `rekey`). `out` must not partially overlap `plaintext`.
            pub fn encryptWithAd(
                self: *CipherState,
                ad: []const u8,
                plaintext: []const u8,
                out: []u8,
            ) error{ NonceExhausted, BufferTooSmall }!void {
                if (!self.has_key) {
                    if (out.len < plaintext.len) return error.BufferTooSmall;
                    @memcpy(out[0..plaintext.len], plaintext);
                    return;
                }
                if (self.n == max_nonce) return error.NonceExhausted;
                if (out.len < plaintext.len + TAGLEN) return error.BufferTooSmall;
                Cipher.encrypt(
                    out[0..plaintext.len],
                    out[plaintext.len..][0..TAGLEN],
                    plaintext,
                    ad,
                    nonceBytes(self.n),
                    self.k,
                );
                self.n += 1;
            }

            /// §5.1 `DecryptWithAd(ad, ciphertext)`: AEAD-decrypts under
            /// key `k` and nonce `n` (then increments `n`), writing
            /// `ciphertext.len - overhead()` bytes into `out`. Per the
            /// spec, if `k` is "empty" this returns the ciphertext
            /// unmodified. Returns `error.DecryptionFailed` on an
            /// authentication failure, in which case `n` is NOT
            /// incremented — never panics on attacker-controlled input.
            pub fn decryptWithAd(
                self: *CipherState,
                ad: []const u8,
                ciphertext: []const u8,
                out: []u8,
            ) error{ DecryptionFailed, NonceExhausted, BufferTooSmall }!void {
                if (!self.has_key) {
                    if (out.len < ciphertext.len) return error.BufferTooSmall;
                    @memcpy(out[0..ciphertext.len], ciphertext);
                    return;
                }
                if (ciphertext.len < TAGLEN) return error.DecryptionFailed;
                if (self.n == max_nonce) return error.NonceExhausted;
                const msg_len = ciphertext.len - TAGLEN;
                if (out.len < msg_len) return error.BufferTooSmall;
                Cipher.decrypt(
                    out[0..msg_len],
                    ciphertext[0..msg_len],
                    ciphertext[msg_len..][0..TAGLEN].*,
                    ad,
                    nonceBytes(self.n),
                    self.k,
                ) catch return error.DecryptionFailed;
                self.n += 1;
            }

            /// §5.1 `Rekey()`: `k = ENCRYPT(k, 2^64-1, zerolen, zeros[32])`
            /// truncated to 32 bytes — the optional key-update procedure.
            pub fn rekey(self: *CipherState) void {
                std.debug.assert(self.has_key);
                var ct: [32 + TAGLEN]u8 = undefined;
                Cipher.encrypt(
                    ct[0..32],
                    ct[32..][0..TAGLEN],
                    &([_]u8{0} ** 32),
                    "",
                    nonceBytes(max_nonce),
                    self.k,
                );
                self.k = ct[0..32].*;
                std.crypto.secureZero(u8, &ct);
            }
        };

        /// Spec §5.2: a chaining key `ck`, a running transcript hash `h`,
        /// and an embedded `CipherState` used to en/decrypt handshake
        /// payloads once a key has been mixed in.
        pub const SymmetricState = struct {
            ck: [HASHLEN]u8 = [_]u8{0} ** HASHLEN,
            h: [HASHLEN]u8 = [_]u8{0} ** HASHLEN,
            cipher_state: CipherState = .{},

            /// §5.2 `InitializeSymmetric(protocol_name)`: sets
            /// `h = protocol_name` zero-padded if it fits in `HASHLEN`,
            /// else `h = HASH(protocol_name)`; then `ck = h` and clears
            /// the embedded `CipherState`.
            pub fn initializeSymmetric(self: *SymmetricState, protocol_name: []const u8) void {
                if (protocol_name.len <= HASHLEN) {
                    self.h = [_]u8{0} ** HASHLEN;
                    @memcpy(self.h[0..protocol_name.len], protocol_name);
                } else {
                    Hash.hash(protocol_name, &self.h, .{});
                }
                self.ck = self.h;
                self.cipher_state = .{};
            }

            /// §5.2 `MixKey(input_key_material)`: `HKDF(ck, ikm, 2)` →
            /// new `ck` plus `temp_k`; re-initializes the embedded
            /// `CipherState` with `temp_k` truncated to 32 bytes.
            pub fn mixKey(self: *SymmetricState, input_key_material: []const u8) void {
                var out = noiseHkdf(2, &self.ck, input_key_material);
                self.ck = out[0];
                self.cipher_state.initializeKey(out[1][0..32].*);
                std.crypto.secureZero(u8, std.mem.asBytes(&out));
            }

            /// §5.2 `MixHash(data)`: extends the transcript hash,
            /// `h := HASH(h || data)`.
            pub fn mixHash(self: *SymmetricState, data: []const u8) void {
                var hasher = Hash.init(.{});
                hasher.update(&self.h);
                hasher.update(data);
                hasher.final(&self.h);
            }

            /// §5.2 `MixKeyAndHash(input_key_material)`: the three-output
            /// `HKDF(ck, ikm, 3)` used only by PSK handshakes — ratchets
            /// `ck`, mixes the middle output into `h`, and re-initializes
            /// the `CipherState` key from the third output (truncated to
            /// 32 bytes).
            pub fn mixKeyAndHash(self: *SymmetricState, input_key_material: []const u8) void {
                var out = noiseHkdf(3, &self.ck, input_key_material);
                self.ck = out[0];
                self.mixHash(&out[1]);
                self.cipher_state.initializeKey(out[2][0..32].*);
                std.crypto.secureZero(u8, std.mem.asBytes(&out));
            }

            /// §5.2 `GetHandshakeHash()`: returns `h`, the final
            /// channel-binding value once the handshake completes.
            pub fn getHandshakeHash(self: *const SymmetricState) [HASHLEN]u8 {
                return self.h;
            }

            /// §5.2 `EncryptAndHash(plaintext)`: `EncryptWithAd(h,
            /// plaintext)` on the embedded `CipherState`, then `MixHash` of
            /// the resulting ciphertext. `out.len` must be exactly
            /// `plaintext.len + cipher_state.overhead()`.
            pub fn encryptAndHash(
                self: *SymmetricState,
                plaintext: []const u8,
                out: []u8,
            ) error{ NonceExhausted, BufferTooSmall }!void {
                if (out.len != plaintext.len + self.cipher_state.overhead())
                    return error.BufferTooSmall;
                try self.cipher_state.encryptWithAd(&self.h, plaintext, out);
                self.mixHash(out);
            }

            /// §5.2 `DecryptAndHash(ciphertext)`: `DecryptWithAd(h,
            /// ciphertext)` on the embedded `CipherState`, then `MixHash`
            /// of the (still-encrypted) input. `out.len` must be exactly
            /// `ciphertext.len - cipher_state.overhead()`. On an
            /// authentication failure neither `h` nor `n` advances.
            pub fn decryptAndHash(
                self: *SymmetricState,
                ciphertext: []const u8,
                out: []u8,
            ) error{ DecryptionFailed, NonceExhausted, BufferTooSmall }!void {
                if (ciphertext.len < self.cipher_state.overhead())
                    return error.BufferTooSmall;
                if (out.len != ciphertext.len - self.cipher_state.overhead())
                    return error.BufferTooSmall;
                try self.cipher_state.decryptWithAd(&self.h, ciphertext, out);
                self.mixHash(ciphertext);
            }

            /// §5.2 `Split()`: derives the pair of transport `CipherState`s
            /// (`[0]` = initiator-to-responder, `[1]` = the reverse) via
            /// `HKDF(ck, zerolen, 2)`, ending the handshake phase.
            pub fn split(self: *SymmetricState) [2]CipherState {
                var out = noiseHkdf(2, &self.ck, "");
                var pair = [2]CipherState{ .{}, .{} };
                pair[0].initializeKey(out[0][0..32].*);
                pair[1].initializeKey(out[1][0..32].*);
                std.crypto.secureZero(u8, std.mem.asBytes(&out));
                return pair;
            }
        };

        /// Spec §5.3: the full handshake driver — static/ephemeral/remote
        /// keypairs, the embedded `SymmetricState`, the negotiated
        /// `HandshakePattern` plus a cursor into its `message_patterns`,
        /// and (for PSK patterns) the pre-shared keys to mix in.
        pub const HandshakeState = struct {
            /// This party's static keypair, if the pattern uses one.
            s: ?KeyPair = null,
            /// This party's ephemeral keypair. Normally left `null` and
            /// generated by `writeMessage`'s `e` token from its `random`
            /// argument; pre-setting it (via `initialize`'s `e` parameter,
            /// the spec's own testing hook) makes `writeMessage` emit the
            /// injected ephemeral instead — used by the KAT vectors.
            e: ?KeyPair = null,
            /// The remote party's static public key, once known.
            rs: ?[DHLEN]u8 = null,
            /// The remote party's ephemeral public key, once known.
            re: ?[DHLEN]u8 = null,
            /// The embedded `SymmetricState` (spec §5.2).
            symmetric_state: SymmetricState = .{},
            /// `true` if this `HandshakeState` is the pattern's initiator.
            initiator: bool = false,
            /// The negotiated handshake pattern (spec §7/§9).
            pattern: patterns.HandshakePattern = patterns.NN,
            /// Index into `pattern.message_patterns` for the next
            /// `writeMessage`/`readMessage` call.
            message_index: usize = 0,
            /// Pre-shared symmetric keys for PSK-modified patterns (spec
            /// §9), consumed in order as `psk` tokens are processed.
            psks: []const [32]u8 = &.{},
            /// Next index into `psks` (advanced per `psk` token).
            psk_index: usize = 0,
            /// Whether `pattern` contains any `psk` token (spec §9.1: such
            /// patterns additionally `MixKey` every `e` public key).
            has_psk: bool = false,

            /// Errors `writeMessage` can produce.
            pub const WriteError = error{
                /// The handshake already returned its transport states.
                HandshakeComplete,
                /// `out` cannot hold this handshake message.
                BufferTooSmall,
                /// A DH produced an all-zero/identity output (spec §4.1
                /// allows rejecting these).
                DhFailed,
                /// A `CipherState` nonce counter hit 2^64-1.
                NonceExhausted,
            };

            /// Errors `readMessage` can produce.
            pub const ReadError = error{
                HandshakeComplete,
                /// `message` is shorter than the pattern requires.
                MessageTooShort,
                /// `out` cannot hold the decrypted payload.
                BufferTooSmall,
                DhFailed,
                NonceExhausted,
                /// AEAD authentication failed (tampered/corrupt message).
                DecryptionFailed,
            };

            /// Result of one `writeMessage`/`readMessage` step: how many
            /// bytes were produced in `out`, plus — once the final message
            /// pattern has been processed — `Split()`'s two transport
            /// `CipherState`s (`[0]` = initiator→responder, `[1]` = the
            /// reverse; both parties receive the same pair and pick their
            /// sending direction by role). `transport` is `null` while
            /// more handshake messages remain.
            pub const Step = struct {
                len: usize,
                transport: ?[2]CipherState,
            };

            /// §5.3 `Initialize(handshake_pattern, initiator, prologue,
            /// s, e, rs, re)`: derives the protocol name (spec §8,
            /// `"Noise_" ++ pattern.name ++ "_25519_ChaChaPoly_SHA256"`
            /// etc.) into `SymmetricState.initializeSymmetric`, mixes in
            /// `prologue`, records the known keys, and processes the
            /// pattern's pre-message tokens (mixing the already-known
            /// public keys into the transcript hash, initiator's first).
            /// `e` is normally `null` (see the `e` field doc); `psks` must
            /// hold one 32-byte key per `psk` token in the pattern.
            pub fn initialize(
                self: *HandshakeState,
                pattern: patterns.HandshakePattern,
                initiator: bool,
                prologue: []const u8,
                s: ?KeyPair,
                e: ?KeyPair,
                rs: ?[DHLEN]u8,
                re: ?[DHLEN]u8,
                psks: []const [32]u8,
            ) void {
                self.* = .{
                    .s = s,
                    .e = e,
                    .rs = rs,
                    .re = re,
                    .initiator = initiator,
                    .pattern = pattern,
                    .psks = psks,
                };
                outer: for (pattern.message_patterns) |mp| for (mp) |t| {
                    if (t == .psk) {
                        self.has_psk = true;
                        break :outer;
                    }
                };

                const suffix = comptime "_" ++ dhName(DH) ++ "_" ++
                    cipherName(Cipher) ++ "_" ++ hashName(Hash);
                var name_buf: [128]u8 = undefined;
                std.debug.assert(pattern.name.len + 6 + suffix.len <= name_buf.len);
                const protocol_name = std.fmt.bufPrint(
                    &name_buf,
                    "Noise_{s}" ++ suffix,
                    .{pattern.name},
                ) catch unreachable;
                self.symmetric_state.initializeSymmetric(protocol_name);
                self.symmetric_state.mixHash(prologue);

                // Pre-messages (§7.2): initiator's key(s) first, then the
                // responder's, each seen from this party's perspective.
                for (pattern.pre_message_initiator) |t| {
                    const pk: [DHLEN]u8 = switch (t) {
                        .e => if (initiator) self.e.?.public_key else self.re.?,
                        .s => if (initiator) self.s.?.public_key else self.rs.?,
                        else => unreachable,
                    };
                    self.symmetric_state.mixHash(&pk);
                }
                for (pattern.pre_message_responder) |t| {
                    const pk: [DHLEN]u8 = switch (t) {
                        .e => if (initiator) self.re.? else self.e.?.public_key,
                        .s => if (initiator) self.rs.? else self.s.?.public_key,
                        else => unreachable,
                    };
                    self.symmetric_state.mixHash(&pk);
                }
            }

            /// §5.3's DH tokens with the role asymmetry made explicit:
            /// `es` is always DH(initiator ephemeral, responder static)
            /// and `se` always DH(initiator static, responder ephemeral),
            /// so which *local* key participates depends on `initiator`.
            /// Identical for writing and reading.
            fn mixDh(self: *HandshakeState, token: Token) error{DhFailed}!void {
                const local: KeyPair, const remote_pub: [DHLEN]u8 = switch (token) {
                    .ee => .{ self.e.?, self.re.? },
                    .ss => .{ self.s.?, self.rs.? },
                    .es => if (self.initiator)
                        .{ self.e.?, self.rs.? }
                    else
                        .{ self.s.?, self.re.? },
                    .se => if (self.initiator)
                        .{ self.s.?, self.re.? }
                    else
                        .{ self.e.?, self.rs.? },
                    else => unreachable,
                };
                var shared = DH.scalarmult(local.secret_key, remote_pub) catch
                    return error.DhFailed;
                self.symmetric_state.mixKey(&shared);
                std.crypto.secureZero(u8, &shared);
            }

            /// Wipe key material once the handshake has produced its
            /// transport states (the transcript hash `h` stays available
            /// for `getHandshakeHash`).
            fn wipe(self: *HandshakeState) void {
                if (self.e != null) std.crypto.secureZero(u8, &self.e.?.secret_key);
                std.crypto.secureZero(u8, &self.symmetric_state.ck);
                std.crypto.secureZero(u8, &self.symmetric_state.cipher_state.k);
                self.symmetric_state.cipher_state.has_key = false;
            }

            /// §5.3 `WriteMessage(payload)`: processes the next message
            /// pattern's tokens — `e` generates (from `random`; 32 bytes
            /// per attempt) or reuses a pre-set ephemeral, appends it and
            /// mixes it into the transcript (also into the chaining key
            /// for PSK patterns); `s` appends the encrypted static key;
            /// `ee`/`es`/`se`/`ss` mix the corresponding DH output; `psk`
            /// mixes the next pre-shared key — then appends
            /// `EncryptAndHash(payload)`. Returns the message length and,
            /// once the final message pattern has been processed,
            /// `Split()`'s transport pair. `random` must be
            /// cryptographically secure in production (e.g.
            /// `std.Random.IoSource`); it is only drawn from when an `e`
            /// token fires with no pre-set ephemeral.
            pub fn writeMessage(
                self: *HandshakeState,
                random: std.Random,
                payload: []const u8,
                out: []u8,
            ) WriteError!Step {
                if (self.message_index >= self.pattern.message_patterns.len)
                    return error.HandshakeComplete;
                var w: usize = 0;
                for (self.pattern.message_patterns[self.message_index]) |token| {
                    switch (token) {
                        .e => {
                            if (self.e == null) {
                                var seed: [DH.seed_length]u8 = undefined;
                                defer std.crypto.secureZero(u8, &seed);
                                self.e = while (true) {
                                    random.bytes(&seed);
                                    break KeyPair.generateDeterministic(seed) catch continue;
                                };
                            }
                            const pk = self.e.?.public_key;
                            if (out.len < w + DHLEN) return error.BufferTooSmall;
                            @memcpy(out[w..][0..DHLEN], &pk);
                            w += DHLEN;
                            self.symmetric_state.mixHash(&pk);
                            if (self.has_psk) self.symmetric_state.mixKey(&pk);
                        },
                        .s => {
                            const n = DHLEN + self.symmetric_state.cipher_state.overhead();
                            if (out.len < w + n) return error.BufferTooSmall;
                            try self.symmetric_state.encryptAndHash(
                                &self.s.?.public_key,
                                out[w..][0..n],
                            );
                            w += n;
                        },
                        .ee, .es, .se, .ss => try self.mixDh(token),
                        .psk => {
                            self.symmetric_state.mixKeyAndHash(&self.psks[self.psk_index]);
                            self.psk_index += 1;
                        },
                    }
                }
                const n = payload.len + self.symmetric_state.cipher_state.overhead();
                if (out.len < w + n) return error.BufferTooSmall;
                try self.symmetric_state.encryptAndHash(payload, out[w..][0..n]);
                w += n;

                self.message_index += 1;
                if (self.message_index == self.pattern.message_patterns.len) {
                    const pair = self.symmetric_state.split();
                    self.wipe();
                    return .{ .len = w, .transport = pair };
                }
                return .{ .len = w, .transport = null };
            }

            /// §5.3 `ReadMessage(message)`: the mirror of `writeMessage` —
            /// consumes the next message pattern's tokens from `message`
            /// (`e`/`s` from the wire, DH/psk tokens from state) and
            /// decrypts the trailing payload into `out` (the whole
            /// `message` slice is one handshake message; the payload is
            /// whatever follows the tokens). Returns the payload length
            /// and, once the final message pattern has been processed,
            /// `Split()`'s transport pair. On any error the message must
            /// be discarded and the handshake aborted.
            pub fn readMessage(
                self: *HandshakeState,
                message: []const u8,
                out: []u8,
            ) ReadError!Step {
                if (self.message_index >= self.pattern.message_patterns.len)
                    return error.HandshakeComplete;
                var r: usize = 0;
                for (self.pattern.message_patterns[self.message_index]) |token| {
                    switch (token) {
                        .e => {
                            if (message.len < r + DHLEN) return error.MessageTooShort;
                            const pk: [DHLEN]u8 = message[r..][0..DHLEN].*;
                            r += DHLEN;
                            self.re = pk;
                            self.symmetric_state.mixHash(&pk);
                            if (self.has_psk) self.symmetric_state.mixKey(&pk);
                        },
                        .s => {
                            const n = DHLEN + self.symmetric_state.cipher_state.overhead();
                            if (message.len < r + n) return error.MessageTooShort;
                            var pk: [DHLEN]u8 = undefined;
                            try self.symmetric_state.decryptAndHash(message[r..][0..n], &pk);
                            r += n;
                            self.rs = pk;
                        },
                        .ee, .es, .se, .ss => try self.mixDh(token),
                        .psk => {
                            self.symmetric_state.mixKeyAndHash(&self.psks[self.psk_index]);
                            self.psk_index += 1;
                        },
                    }
                }
                const rest = message[r..];
                if (rest.len < self.symmetric_state.cipher_state.overhead())
                    return error.MessageTooShort;
                const payload_len = rest.len - self.symmetric_state.cipher_state.overhead();
                if (out.len < payload_len) return error.BufferTooSmall;
                try self.symmetric_state.decryptAndHash(rest, out[0..payload_len]);

                self.message_index += 1;
                if (self.message_index == self.pattern.message_patterns.len) {
                    const pair = self.symmetric_state.split();
                    self.wipe();
                    return .{ .len = payload_len, .transport = pair };
                }
                return .{ .len = payload_len, .transport = null };
            }
        };
    };
}

// ── tests ────────────────────────────────────────────────────────────────

const testing = std.testing;

/// The default binding: the `chachapoly` sibling's AEAD. Several tests below
/// recompute their expectation with `std.crypto.aead.chacha_poly.
/// ChaCha20Poly1305` directly, which makes them differential — the suite runs
/// `chachapoly`, the oracle is std, and the bytes must match.
const TestSuite = Suite(
    std.crypto.dh.X25519,
    chachapoly.ChaCha20Poly1305,
    std.crypto.hash.sha2.Sha256,
);

/// Both byte-exact ChaCha20-Poly1305 implementations. Every official-vector
/// KAT below is run under BOTH: the vectors are the wire format, so a suite
/// bound with `chachapoly` and one bound with std must produce identical
/// bytes at every step. Ordered `chachapoly` first so the default is the one
/// a failure names first.
const chacha_aeads = [_]type{
    chachapoly.ChaCha20Poly1305,
    std.crypto.aead.chacha_poly.ChaCha20Poly1305,
};

test "Suite(X25519, ChaCha20Poly1305, SHA256): DHLEN/HASHLEN + zero-value defaults" {
    const S = TestSuite;
    try testing.expectEqual(@as(usize, 32), S.DHLEN);
    try testing.expectEqual(@as(usize, 32), S.HASHLEN);

    const cs: S.CipherState = .{};
    try testing.expectEqual(@as(u64, 0), cs.n);
    try testing.expectEqual([_]u8{0} ** 32, cs.k);
    try testing.expectEqual(false, cs.hasKey());

    const ss: S.SymmetricState = .{};
    try testing.expectEqual([_]u8{0} ** 32, ss.ck);
    try testing.expectEqual([_]u8{0} ** 32, ss.h);

    const hs: S.HandshakeState = .{};
    try testing.expectEqual(false, hs.initiator);
    try testing.expectEqual(@as(usize, 0), hs.message_index);
    try testing.expectEqual(@as(usize, 0), hs.psks.len);
    try testing.expectEqual(@as(?S.KeyPair, null), hs.s);
}

test "Suite: HASHLEN tracks the bound Hash, not a fixed constant" {
    const S256 = Suite(std.crypto.dh.X25519, std.crypto.aead.chacha_poly.ChaCha20Poly1305, std.crypto.hash.sha2.Sha256);
    const S512 = Suite(std.crypto.dh.X25519, std.crypto.aead.chacha_poly.ChaCha20Poly1305, std.crypto.hash.sha2.Sha512);
    const SBlake2s = Suite(std.crypto.dh.X25519, std.crypto.aead.chacha_poly.ChaCha20Poly1305, std.crypto.hash.blake2.Blake2s256);
    const SBlake2b = Suite(std.crypto.dh.X25519, std.crypto.aead.chacha_poly.ChaCha20Poly1305, std.crypto.hash.blake2.Blake2b512);
    try testing.expectEqual(@as(usize, 32), S256.HASHLEN);
    try testing.expectEqual(@as(usize, 64), S512.HASHLEN);
    try testing.expectEqual(@as(usize, 32), SBlake2s.HASHLEN);
    try testing.expectEqual(@as(usize, 64), SBlake2b.HASHLEN);
}

test "Suite: alternate AEAD (Aes256Gcm) reserved and selectable" {
    const S = Suite(std.crypto.dh.X25519, std.crypto.aead.aes_gcm.Aes256Gcm, std.crypto.hash.sha2.Sha256);
    try testing.expectEqual(std.crypto.aead.aes_gcm.Aes256Gcm, S.AeadCipher);
    const cs: S.CipherState = .{};
    try testing.expectEqual(@as(u64, 0), cs.n);
}

test "Suite: HandshakeState defaults to the NN pattern until initialize() is called" {
    const S = Suite(std.crypto.dh.X25519, std.crypto.aead.chacha_poly.ChaCha20Poly1305, std.crypto.hash.sha2.Sha256);
    const hs: S.HandshakeState = .{};
    try testing.expectEqualStrings("NN", hs.pattern.name);
}

// ── CipherState unit tests ───────────────────────────────────────────────

test "CipherState: no key = identity passthrough, n untouched" {
    var cs: TestSuite.CipherState = .{};
    var out: [5]u8 = undefined;
    try cs.encryptWithAd("ad", "hello", &out);
    try testing.expectEqualStrings("hello", &out);
    try testing.expectEqual(@as(u64, 0), cs.n);
    try cs.decryptWithAd("ad", "hello", &out);
    try testing.expectEqualStrings("hello", &out);
    try testing.expectEqual(@as(u64, 0), cs.n);
}

test "CipherState: nonce = 4 zero bytes || LE64(n) for ChaChaPoly; n increments" {
    const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const key = [_]u8{0xab} ** 32;
    var cs: TestSuite.CipherState = .{};
    cs.initializeKey(key);
    cs.setNonce(7);

    var got: [9 + 16]u8 = undefined;
    try cs.encryptWithAd("assoc", "plaintext", &got);
    try testing.expectEqual(@as(u64, 8), cs.n);

    var npub = [_]u8{0} ** 12;
    std.mem.writeInt(u64, npub[4..12], 7, .little);
    var want: [9 + 16]u8 = undefined;
    Aead.encrypt(want[0..9], want[9..25], "plaintext", "assoc", npub, key);
    try testing.expectEqualSlices(u8, &want, &got);

    var back: [9]u8 = undefined;
    cs.setNonce(7);
    try cs.decryptWithAd("assoc", &got, &back);
    try testing.expectEqualStrings("plaintext", &back);
    try testing.expectEqual(@as(u64, 8), cs.n);
}

test "CipherState: auth failure leaves n unchanged; nonce 2^64-1 exhausts" {
    var cs: TestSuite.CipherState = .{};
    cs.initializeKey([_]u8{1} ** 32);
    var ct: [3 + 16]u8 = undefined;
    try cs.encryptWithAd("", "abc", &ct);
    ct[0] ^= 1;
    var pt: [3]u8 = undefined;
    cs.setNonce(0);
    try testing.expectError(error.DecryptionFailed, cs.decryptWithAd("", &ct, &pt));
    try testing.expectEqual(@as(u64, 0), cs.n);
    try testing.expectError(error.DecryptionFailed, cs.decryptWithAd("", ct[0..8], &pt));

    cs.setNonce(std.math.maxInt(u64));
    try testing.expectError(error.NonceExhausted, cs.encryptWithAd("", "abc", &ct));
    try testing.expectError(error.NonceExhausted, cs.decryptWithAd("", &ct, &pt));
}

test "CipherState: rekey matches spec formula and keeps both directions in sync" {
    const Aead = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const key = [_]u8{0x42} ** 32;
    var a: TestSuite.CipherState = .{};
    var b: TestSuite.CipherState = .{};
    a.initializeKey(key);
    b.initializeKey(key);

    a.rekey();
    // Spec §4.2: REKEY(k) = ENCRYPT(k, 2^64-1, zerolen, zeros[32])[0..32].
    var npub = [_]u8{0} ** 12;
    std.mem.writeInt(u64, npub[4..12], std.math.maxInt(u64), .little);
    var want: [48]u8 = undefined;
    Aead.encrypt(want[0..32], want[32..48], &([_]u8{0} ** 32), "", npub, key);
    try testing.expectEqualSlices(u8, want[0..32], &a.k);
    try testing.expect(!std.mem.eql(u8, &a.k, &key));

    b.rekey();
    var ct: [4 + 16]u8 = undefined;
    var pt: [4]u8 = undefined;
    try a.encryptWithAd("", "ping", &ct);
    try b.decryptWithAd("", &ct, &pt);
    try testing.expectEqualStrings("ping", &pt);
}

// ── SymmetricState unit tests ────────────────────────────────────────────

test "SymmetricState: initializeSymmetric pads short names, hashes long ones" {
    var ss: TestSuite.SymmetricState = .{};
    const name = "Noise_XX_25519_ChaChaPoly_SHA256"; // exactly 32 bytes
    ss.initializeSymmetric(name);
    try testing.expectEqualSlices(u8, name, &ss.h);
    try testing.expectEqual(ss.h, ss.ck);
    try testing.expect(!ss.cipher_state.hasKey());

    const long = "Noise_XXfallback_25519_ChaChaPoly_SHA256"; // 40 bytes > HASHLEN
    ss.initializeSymmetric(long);
    var want: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(long, &want, .{});
    try testing.expectEqual(want, ss.h);

    const short = "Noise_NN_25519";
    ss.initializeSymmetric(short);
    try testing.expectEqualSlices(u8, short, ss.h[0..short.len]);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** (32 - short.len)), ss.h[short.len..]);
}

test "SymmetricState: Noise HKDF == RFC 5869 HKDF with empty info (mixKey/mixKeyAndHash/split)" {
    // Noise's HMAC chain (temp = HMAC(ck, ikm); o1 = HMAC(temp, 0x01);
    // o2 = HMAC(temp, o1||0x02); o3 = HMAC(temp, o2||0x03)) is exactly
    // HKDF-Extract(salt=ck, ikm) + HKDF-Expand(prk, info="", 96) — use
    // std's independent implementation as the oracle.
    const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;
    const ck = [_]u8{0x11} ** 32;
    const ikm = [_]u8{0x22} ** 32;
    const prk = Hkdf.extract(&ck, &ikm);
    var okm: [96]u8 = undefined;
    Hkdf.expand(&okm, "", prk);

    var ss: TestSuite.SymmetricState = .{};
    ss.ck = ck;
    ss.mixKey(&ikm);
    try testing.expectEqualSlices(u8, okm[0..32], &ss.ck);
    try testing.expectEqualSlices(u8, okm[32..64], &ss.cipher_state.k);
    try testing.expectEqual(@as(u64, 0), ss.cipher_state.n);
    try testing.expect(ss.cipher_state.hasKey());

    ss = .{};
    ss.ck = ck;
    const h_before = ss.h;
    ss.mixKeyAndHash(&ikm);
    try testing.expectEqualSlices(u8, okm[0..32], &ss.ck);
    try testing.expectEqualSlices(u8, okm[64..96], &ss.cipher_state.k);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(&h_before);
    hasher.update(okm[32..64]);
    var want_h: [32]u8 = undefined;
    hasher.final(&want_h);
    try testing.expectEqual(want_h, ss.h);

    ss = .{};
    ss.ck = ck;
    const prk2 = Hkdf.extract(&ck, "");
    var okm2: [64]u8 = undefined;
    Hkdf.expand(&okm2, "", prk2);
    const pair = ss.split();
    try testing.expectEqualSlices(u8, okm2[0..32], &pair[0].k);
    try testing.expectEqualSlices(u8, okm2[32..64], &pair[1].k);
    try testing.expectEqual(@as(u64, 0), pair[0].n);
    try testing.expectEqual(@as(u64, 0), pair[1].n);
}

test "SymmetricState: encryptAndHash/decryptAndHash roundtrip and transcript advance" {
    var a: TestSuite.SymmetricState = .{};
    var b: TestSuite.SymmetricState = .{};
    a.initializeSymmetric("Noise_NN_25519_ChaChaPoly_SHA256");
    b.initializeSymmetric("Noise_NN_25519_ChaChaPoly_SHA256");

    // Keyless phase: ciphertext == plaintext, but h still advances.
    var out0: [5]u8 = undefined;
    try a.encryptAndHash("hello", &out0);
    try testing.expectEqualStrings("hello", &out0);
    var pt0: [5]u8 = undefined;
    try b.decryptAndHash(&out0, &pt0);
    try testing.expectEqual(a.h, b.h);

    const ikm = [_]u8{0x77} ** 32;
    a.mixKey(&ikm);
    b.mixKey(&ikm);
    var out1: [5 + 16]u8 = undefined;
    try a.encryptAndHash("world", &out1);
    var pt1: [5]u8 = undefined;
    try b.decryptAndHash(&out1, &pt1);
    try testing.expectEqualStrings("world", &pt1);
    try testing.expectEqual(a.h, b.h);
    try testing.expectEqual(a.getHandshakeHash(), a.h);

    // Tampered ciphertext: DecryptionFailed and h does not advance.
    var out2: [3 + 16]u8 = undefined;
    try a.encryptAndHash("abc", &out2);
    out2[1] ^= 0x80;
    const h_before = b.h;
    var pt2: [3]u8 = undefined;
    try testing.expectError(error.DecryptionFailed, b.decryptAndHash(&out2, &pt2));
    try testing.expectEqual(h_before, b.h);
}

// ── HandshakeState: official KAT vectors ─────────────────────────────────
//
// Source: the official Noise test vectors from rweather/noise-c,
// `tests/vector/noise-c-basic.txt` (cacophony JSON vector format). Each
// vector fixes the prologue, both parties' static/ephemeral private keys
// and lists every handshake + transport message byte-exactly. The fixed
// ephemerals are injected through `initialize`'s `e` parameter (the spec's
// own testing hook); `no_random` panics if `writeMessage` ever tries to
// draw randomness during a KAT.

fn hx(comptime s: []const u8) *const [s.len / 2]u8 {
    comptime {
        @setEvalBranchQuota(1 << 20);
        var out: [s.len / 2]u8 = undefined;
        _ = std.fmt.hexToBytes(&out, s) catch unreachable;
        const frozen = out;
        return &frozen;
    }
}

fn noRandomFill(_: *anyopaque, _: []u8) void {
    @panic("KAT handshake must not draw randomness (ephemeral injected)");
}
const no_random = std.Random{ .ptr = undefined, .fillFn = noRandomFill };

const KatMsg = struct { payload: []const u8, ciphertext: []const u8 };

const Kat = struct {
    pattern: patterns.HandshakePattern,
    prologue: []const u8,
    init_static: ?[]const u8 = null,
    init_ephemeral: []const u8,
    init_remote_static: ?[]const u8 = null,
    resp_static: ?[]const u8 = null,
    resp_ephemeral: []const u8,
    msgs: []const KatMsg,
    handshake_hash: []const u8,
};

fn katKeyPair(comptime S: type, priv: ?[]const u8) ?S.KeyPair {
    const p = priv orelse return null;
    return S.KeyPair.generateDeterministic(p[0..32].*) catch unreachable;
}

fn katPub(comptime S: type, pubkey: ?[]const u8) ?[S.DHLEN]u8 {
    const p = pubkey orelse return null;
    return p[0..S.DHLEN].*;
}

/// Run one official ChaChaPoly vector under BOTH byte-exact ChaCha20-Poly1305
/// implementations (`chachapoly` sibling and std). The vectors ARE the wire
/// format, so this is the differential that keeps the AEAD swap inert: if the
/// two disagree anywhere — ciphertext, tag, or the final handshake hash — one
/// of the two runs goes red against the SAME published bytes.
fn runKatBothChaChaAeads(comptime Hash: type, comptime v: Kat) !void {
    inline for (chacha_aeads) |Aead| {
        try runKat(Suite(std.crypto.dh.X25519, Aead, Hash), v);
    }
}

fn runKat(comptime S: type, comptime v: Kat) !void {
    var ini: S.HandshakeState = .{};
    var rsp: S.HandshakeState = .{};
    ini.initialize(
        v.pattern,
        true,
        v.prologue,
        katKeyPair(S, v.init_static),
        katKeyPair(S, v.init_ephemeral),
        katPub(S, v.init_remote_static),
        null,
        &.{},
    );
    rsp.initialize(
        v.pattern,
        false,
        v.prologue,
        katKeyPair(S, v.resp_static),
        katKeyPair(S, v.resp_ephemeral),
        null,
        null,
        &.{},
    );

    const n_hs = v.pattern.message_patterns.len;
    var t_ini: [2]S.CipherState = undefined;
    var t_rsp: [2]S.CipherState = undefined;

    for (v.msgs, 0..) |m, i| {
        // Even message index = initiator sends (handshake and transport
        // alike — the cacophony vector convention).
        const from_initiator = (i % 2 == 0);
        if (i < n_hs) {
            const writer = if (from_initiator) &ini else &rsp;
            const reader = if (from_initiator) &rsp else &ini;
            var wire: [512]u8 = undefined;
            var plain: [512]u8 = undefined;
            const wr = try writer.writeMessage(no_random, m.payload, &wire);
            try testing.expectEqualSlices(u8, m.ciphertext, wire[0..wr.len]);
            const rr = try reader.readMessage(m.ciphertext, &plain);
            try testing.expectEqualSlices(u8, m.payload, plain[0..rr.len]);
            if (i == n_hs - 1) {
                const wt = wr.transport orelse return error.TestExpectedTransport;
                const rt = rr.transport orelse return error.TestExpectedTransport;
                try testing.expectEqualSlices(u8, &wt[0].k, &rt[0].k);
                try testing.expectEqualSlices(u8, &wt[1].k, &rt[1].k);
                t_ini = if (from_initiator) wt else rt;
                t_rsp = if (from_initiator) rt else wt;
            } else {
                try testing.expectEqual(@as(?[2]S.CipherState, null), wr.transport);
                try testing.expectEqual(@as(?[2]S.CipherState, null), rr.transport);
            }
        } else {
            // Transport phase: [0] carries initiator→responder.
            const send_cs = if (from_initiator) &t_ini[0] else &t_rsp[1];
            const recv_cs = if (from_initiator) &t_rsp[0] else &t_ini[1];
            var wire: [512]u8 = undefined;
            var plain: [512]u8 = undefined;
            try send_cs.encryptWithAd("", m.payload, wire[0..m.ciphertext.len]);
            try testing.expectEqualSlices(u8, m.ciphertext, wire[0..m.ciphertext.len]);
            try recv_cs.decryptWithAd("", m.ciphertext, plain[0..m.payload.len]);
            try testing.expectEqualSlices(u8, m.payload, plain[0..m.payload.len]);
        }
    }

    try testing.expectEqualSlices(
        u8,
        v.handshake_hash,
        &ini.symmetric_state.getHandshakeHash(),
    );
    try testing.expectEqualSlices(
        u8,
        v.handshake_hash,
        &rsp.symmetric_state.getHandshakeHash(),
    );
}

// Shared fixtures across the noise-c basic vectors.
const kat_prologue = hx("50726f6c6f677565313233"); // "Prologue123"
const kat_init_static = hx("e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1");
const kat_init_ephemeral = hx("893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a");
const kat_resp_static = hx("4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893");
const kat_resp_ephemeral = hx("bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b");
const kat_resp_static_pub = hx("31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62");
const kat_p0 = hx("4c756477696720766f6e204d69736573"); // "Ludwig von Mises"
const kat_p1 = hx("4d757272617920526f746862617264"); // "Murray Rothbard"
const kat_p2 = hx("462e20412e20486179656b"); // "F. A. Hayek"
const kat_p3 = hx("4361726c204d656e676572"); // "Carl Menger"
const kat_p4 = hx("4a65616e2d426170746973746520536179"); // "Jean-Baptiste Say"
const kat_p5 = hx("457567656e2042f6686d20766f6e2042617765726b"); // "Eugen Böhm von Bawerk"

test "KAT: Noise_NN_25519_ChaChaPoly_SHA256 (official noise-c vector)" {
    try runKatBothChaChaAeads(std.crypto.hash.sha2.Sha256, .{
        .pattern = patterns.NN,
        .prologue = kat_prologue,
        .init_ephemeral = kat_init_ephemeral,
        .resp_ephemeral = kat_resp_ephemeral,
        .msgs = &.{
            .{ .payload = kat_p0, .ciphertext = hx("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573") },
            .{ .payload = kat_p1, .ciphertext = hx("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843a0ff96bdf86b579ef7dbf94e812a7481d8f4c68907c4aa441057a30cebc1b0") },
            .{ .payload = kat_p2, .ciphertext = hx("eb1a3e3d80c1792b1bb9cb0e1382f8d8322bfb1ca7c4c8517bb686") },
            .{ .payload = kat_p3, .ciphertext = hx("c781b198d2a974eb1da2c7d518c000cf6396de87ca540963c03713") },
            .{ .payload = kat_p4, .ciphertext = hx("c77048eb6919fdfe8fe45842bfc5b8d1ff50d1e20c717453ccdfe6176d805b996d") },
            .{ .payload = kat_p5, .ciphertext = hx("61834d7069dcfb7a1adf8d5ac910f83fa04c73a67789895c6f5f995c5db2ce88e49b124178") },
        },
        .handshake_hash = hx("ac2ae5a7e8ea36ee502bf8647fda092657082519fdae56dd8014684cfca9fe96"),
    });
}

test "KAT: Noise_NK_25519_ChaChaPoly_SHA256 (official noise-c vector)" {
    try runKatBothChaChaAeads(std.crypto.hash.sha2.Sha256, .{
        .pattern = patterns.NK,
        .prologue = kat_prologue,
        .init_ephemeral = kat_init_ephemeral,
        .init_remote_static = kat_resp_static_pub,
        .resp_static = kat_resp_static,
        .resp_ephemeral = kat_resp_ephemeral,
        .msgs = &.{
            .{ .payload = kat_p0, .ciphertext = hx("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79448134d00711fdb390a0d178fa008f6d47f49a76e297aa164052a3d842aa8ff7d8") },
            .{ .payload = kat_p1, .ciphertext = hx("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088438ea16e3701bc0d77744f117bee22451628b075da65d4114bd343e2d93006c4") },
            .{ .payload = kat_p2, .ciphertext = hx("a62de29ce27cb80245d440d986ed816c156e9d757d7008df2198b0") },
            .{ .payload = kat_p3, .ciphertext = hx("174a35f11c689f4530d7208618e0564ae12f2f50ba8eb4df5382ff") },
            .{ .payload = kat_p4, .ciphertext = hx("337e475ebb8eae60f91974c4e455a5af38d1d8628d1803b160d60442874b0a1777") },
            .{ .payload = kat_p5, .ciphertext = hx("047e80e060b7bb08b53c5a23dfe9920cae135b9d1dc6302fc475003062723700366346ac9d") },
        },
        .handshake_hash = hx("d5c4ce9ffe8bcd940aa50f842a5d4d90d3f7163f4b3916deb87a5d747712d718"),
    });
}

test "KAT: Noise_XX_25519_ChaChaPoly_SHA256 (official noise-c vector; covers es+se both roles)" {
    try runKatBothChaChaAeads(std.crypto.hash.sha2.Sha256, .{
        .pattern = patterns.XX,
        .prologue = kat_prologue,
        .init_static = kat_init_static,
        .init_ephemeral = kat_init_ephemeral,
        .resp_static = kat_resp_static,
        .resp_ephemeral = kat_resp_ephemeral,
        .msgs = &.{
            .{ .payload = kat_p0, .ciphertext = hx("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573") },
            .{ .payload = kat_p1, .ciphertext = hx("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f14480884381cbad1f276e038c48378ffce2b65285e08d6b68aaa3629a5a8639392490e5b94a6d8798832d5372f220f161d9c2df035528f8982ffe09be9b5c412f8a0db5d21351f20af1370d0bf8ef1a8c59a30e") },
            .{ .payload = kat_p2, .ciphertext = hx("c7195ffacac1307ff99046f219750fc47693e23c3cb08b89c2af808b444850a8589981dfbd651e6ff4724a781cc2aa6158c9fea0d4ec82a286427484c5b8c8123a7a6002b1de9f9775fc97") },
            .{ .payload = kat_p3, .ciphertext = hx("96763ed773f8e47bb3712f0e29b3060ffc956ffc146cee53d5e1df") },
            .{ .payload = kat_p4, .ciphertext = hx("3e40f15f6f3a46ae446b253bf8b1d9ffb6ed9b174d272328ff91a7e2e5c79c07f5") },
            .{ .payload = kat_p5, .ciphertext = hx("eb3f3515110702e047a6c9da4478b6ead94873c11c0f2d710ddb3f09fce024b3a58502ae3f") },
        },
        .handshake_hash = hx("852a28d2146785c54bd8334f4e460c80d7fe4fd0cc5bc0abef2a24a3c4d44d5f"),
    });
}

test "KAT: Noise_IK_25519_ChaChaPoly_SHA256 (official noise-c vector; covers es+ss+se)" {
    try runKatBothChaChaAeads(std.crypto.hash.sha2.Sha256, .{
        .pattern = patterns.IK,
        .prologue = kat_prologue,
        .init_static = kat_init_static,
        .init_ephemeral = kat_init_ephemeral,
        .init_remote_static = kat_resp_static_pub,
        .resp_static = kat_resp_static,
        .resp_ephemeral = kat_resp_ephemeral,
        .msgs = &.{
            .{ .payload = kat_p0, .ciphertext = hx("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944718da798efbcd91528520204f904b9bd6c7413dccdc214d951e15253e39987f1508bfd10ad143e921328082a3c3b9e50c289f0294b29960a72f48e0b7bba2e89f20d17ed0e4dcf718749c95a941a620e") },
            .{ .payload = kat_p1, .ciphertext = hx("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435361e70b2ed446e6c9ec387d1d6b3b3380e00f0055bd7b310e12947fbab8e7") },
            .{ .payload = kat_p2, .ciphertext = hx("050e9f3c8fac16b68dbce8f8c4bfbf6617c897f9ada4aa29aa19c8") },
            .{ .payload = kat_p3, .ciphertext = hx("344233a6cabb7141d80f3da2fedc311d9646bbb0f505afe403a667") },
            .{ .payload = kat_p4, .ciphertext = hx("62cdeeb172ad7ade7aa7d9e069da5790f12331bfa00177787a1d0810c67dc3b2b4") },
            .{ .payload = kat_p5, .ciphertext = hx("029bead1b40992327044d409d9a1f3ad8f36c3c452775d557e18bbeb2e8dfcead32d514024") },
        },
        .handshake_hash = hx("3d8748e8f966293aeab5cd9a2e42ad0e8d0ebd83fa78957c4664bc6718613eeb"),
    });
}

test "KAT: Noise_XX_25519_ChaChaPoly_BLAKE2s (official noise-c vector; second hash)" {
    try runKatBothChaChaAeads(std.crypto.hash.blake2.Blake2s256, .{
        .pattern = patterns.XX,
        .prologue = kat_prologue,
        .init_static = kat_init_static,
        .init_ephemeral = kat_init_ephemeral,
        .resp_static = kat_resp_static,
        .resp_ephemeral = kat_resp_ephemeral,
        .msgs = &.{
            .{ .payload = kat_p0, .ciphertext = hx("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79444c756477696720766f6e204d69736573") },
            .{ .payload = kat_p1, .ciphertext = hx("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088437c365eb362a1c991b0557fe8a7fb187d99346765d93ec63db6c1b01504ebeec5a11745edbea05ef4097ca82afe861d8aa196a6cead1e11b2bb13e336fa13614136f53e3d34be699da5983876f700ff") },
            .{ .payload = kat_p2, .ciphertext = hx("46c3307de83b014258717d97781c1f50936d8b7d50c0722a1739654d10392d4176a11f5a0f70968037b0e0bedf68d18d802efa4220cff733e7b566970e749fef06ea55e598cdb819d0a33e") },
            .{ .payload = kat_p3, .ciphertext = hx("d5e83adfaac5dc324a68f1862df54549e56d209fba707205f328b2") },
            .{ .payload = kat_p4, .ciphertext = hx("d102c9029b1f55c788f561ba7737afbccef9c9f1bf2f238167fd40ba9c1c134867") },
            .{ .payload = kat_p5, .ciphertext = hx("cb1ce80960382c6d5d5e740ffb724d1432f0310b200fb6f8424120f506092744baa415e155") },
        },
        .handshake_hash = hx("ff2542ab6833ab2243a6a19599fde5e2b2ac5a6dc4f34a9be3046233fd790d41"),
    });
}

test "KAT: Noise_IK_25519_ChaChaPoly_SHA512 (official noise-c vector; HASHLEN=64 truncation)" {
    try runKatBothChaChaAeads(std.crypto.hash.sha2.Sha512, .{
        .pattern = patterns.IK,
        .prologue = kat_prologue,
        .init_static = kat_init_static,
        .init_ephemeral = kat_init_ephemeral,
        .init_remote_static = kat_resp_static_pub,
        .resp_static = kat_resp_static,
        .resp_ephemeral = kat_resp_ephemeral,
        .msgs = &.{
            .{ .payload = kat_p0, .ciphertext = hx("ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79447a2281c0f1aee0c48c41333a1abbb349ee4bf12e09f8c4fd66635aabbb7dad345826d359e4bd6ebee659f5c6cb3d2d4ed12f7c7ffc9fe5513818d9cf9b8778d1502f90649c42ab4a1e3df7199a3d6a13") },
            .{ .payload = kat_p1, .ciphertext = hx("95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843f58050451a0edd2a40bb8b0f6b51ea63e1f1f429f1afd583e5d6e53f44da1e") },
            .{ .payload = kat_p2, .ciphertext = hx("cae0b6af5460d026e80e22c27572a92048176872538f91a056a8df") },
            .{ .payload = kat_p3, .ciphertext = hx("ab1440d2b5892c638a11a7fa6412beaea5cee62342147f02d75a68") },
            .{ .payload = kat_p4, .ciphertext = hx("0263ed778a193155c9947202e0b9d35eb46581a902449d091e1b6575a9a59fbeff") },
            .{ .payload = kat_p5, .ciphertext = hx("95aedd9192351379cb063c8d5827d5529c7f2c8929552dd64c57029734737ea2a405255dcf") },
        },
        .handshake_hash = hx("48d8b650f042c4767cf1f3c26b22ccdd4bc8cff341166603109954eab8a9bd20915d284b6b618a325e93a8e949a23f4b62ba3094aad0b640c14cbd4f14ccd1e1"),
    });
}

// ── HandshakeState: self-consistency with generated ephemerals ──────────

fn selfConsistency(
    comptime pat: patterns.HandshakePattern,
    comptime init_has_s: bool,
    comptime resp_has_s: bool,
    comptime init_knows_rs: bool,
    random: std.Random,
) !void {
    const S = TestSuite;
    var seed: [32]u8 = undefined;

    random.bytes(&seed);
    const init_s = try S.KeyPair.generateDeterministic(seed);
    random.bytes(&seed);
    const resp_s = try S.KeyPair.generateDeterministic(seed);

    var ini: S.HandshakeState = .{};
    var rsp: S.HandshakeState = .{};
    ini.initialize(
        pat,
        true,
        "prologue",
        if (init_has_s) init_s else null,
        null,
        if (init_knows_rs) resp_s.public_key else null,
        null,
        &.{},
    );
    rsp.initialize(
        pat,
        false,
        "prologue",
        if (resp_has_s) resp_s else null,
        null,
        null,
        null,
        &.{},
    );

    var transport: ?[2]S.CipherState = null;
    inline for (0..pat.message_patterns.len) |i| {
        const writer = if (i % 2 == 0) &ini else &rsp;
        const reader = if (i % 2 == 0) &rsp else &ini;
        var wire: [512]u8 = undefined;
        var plain: [64]u8 = undefined;
        const payload = "handshake payload";
        const wr = try writer.writeMessage(random, payload, &wire);
        const rr = try reader.readMessage(wire[0..wr.len], &plain);
        try testing.expectEqualSlices(u8, payload, plain[0..rr.len]);
        if (i == pat.message_patterns.len - 1) {
            const wt = wr.transport orelse return error.TestExpectedTransport;
            const rt = rr.transport orelse return error.TestExpectedTransport;
            try testing.expectEqualSlices(u8, &wt[0].k, &rt[0].k);
            try testing.expectEqualSlices(u8, &wt[1].k, &rt[1].k);
            transport = wt;
        }
    }
    try testing.expectEqual(
        ini.symmetric_state.getHandshakeHash(),
        rsp.symmetric_state.getHandshakeHash(),
    );

    // Transport both ways off the split pair (each side owns a copy; the
    // keys are identical, so one pair suffices for the roundtrip check).
    var pair = transport.?;
    var wire: [64 + 16]u8 = undefined;
    var plain: [64]u8 = undefined;
    try pair[0].encryptWithAd("", "initiator->responder", wire[0..36]);
    pair[0].setNonce(0);
    try pair[0].decryptWithAd("", wire[0..36], plain[0..20]);
    try testing.expectEqualStrings("initiator->responder", plain[0..20]);
    try pair[1].encryptWithAd("", "responder->initiator", wire[0..36]);
    pair[1].setNonce(0);
    try pair[1].decryptWithAd("", wire[0..36], plain[0..20]);
    try testing.expectEqualStrings("responder->initiator", plain[0..20]);
}

test "self-consistency: NN/NK/XX/IK full handshakes with generated ephemerals" {
    var prng = std.Random.DefaultPrng.init(0x6e6f697365);
    const random = prng.random();
    try selfConsistency(patterns.NN, false, false, false, random);
    try selfConsistency(patterns.NK, false, true, true, random);
    try selfConsistency(patterns.XX, true, true, false, random);
    try selfConsistency(patterns.IK, true, true, true, random);
}

test "self-consistency: tampered handshake message fails authentication" {
    const S = TestSuite;
    var prng = std.Random.DefaultPrng.init(0xbadc0de);
    const random = prng.random();

    var ini: S.HandshakeState = .{};
    var rsp: S.HandshakeState = .{};
    ini.initialize(patterns.NN, true, "", null, null, null, null, &.{});
    rsp.initialize(patterns.NN, false, "", null, null, null, null, &.{});

    var m0: [64]u8 = undefined;
    var m1: [64]u8 = undefined;
    var plain: [64]u8 = undefined;
    const w0 = try ini.writeMessage(random, "", &m0);
    _ = try rsp.readMessage(m0[0..w0.len], &plain);
    const w1 = try rsp.writeMessage(random, "hello", &m1);

    // Message 2 of NN carries an AEAD-protected payload — flip one bit.
    m1[w1.len - 1] ^= 0x01;
    try testing.expectError(
        error.DecryptionFailed,
        ini.readMessage(m1[0..w1.len], &plain),
    );
}

test "HandshakeState: reading a truncated message fails cleanly" {
    const S = TestSuite;
    var rsp: S.HandshakeState = .{};
    rsp.initialize(patterns.NN, false, "", null, null, null, null, &.{});
    var plain: [64]u8 = undefined;
    // First NN message needs at least DHLEN bytes for the `e` token.
    try testing.expectError(error.MessageTooShort, rsp.readMessage(&[_]u8{1} ** 16, &plain));
}

test "HandshakeState: identity-point remote static key is rejected (invalid-point DH)" {
    // Spec §4.1 explicitly allows rejecting DH outputs that are the
    // all-zero identity element — the classic small-subgroup attack
    // where an attacker plants a low-order public key so every party's
    // DH computation collapses to the same known value regardless of
    // its own secret. Nothing else in this suite ever hands mixDh() an
    // invalid remote key, so this reject path (error.DhFailed) had no
    // test at all before this one.
    const S = TestSuite;
    var prng = std.Random.DefaultPrng.init(0x1d1d1d);
    const random = prng.random();
    var ini: S.HandshakeState = .{};
    const zero_rs: [S.DHLEN]u8 = [_]u8{0} ** S.DHLEN;
    // NK's pre-message gives the initiator the responder's static key
    // out of band; plant the identity element there so message 1's
    // `es` token (DH(e, rs)) computes against it.
    ini.initialize(patterns.NK, true, "", null, null, zero_rs, null, &.{});
    var m: [64]u8 = undefined;
    try testing.expectError(error.DhFailed, ini.writeMessage(random, "", &m));
}

fn fuzzReadMessage(_: void, smith: *std.testing.Smith) !void {
    var msg: [256]u8 = undefined;
    smith.bytes(&msg);
    const len: usize = smith.valueRangeAtMost(u16, 0, msg.len);
    const S = TestSuite;
    var rsp: S.HandshakeState = .{};
    rsp.initialize(patterns.NN, false, "", null, null, null, null, &.{});
    var out: [256]u8 = undefined;
    // The wire-facing decoder for an in-progress handshake: arbitrary bytes
    // must only ever yield a typed error (short message / bad auth tag /
    // handshake already complete), never a panic or OOB write into `out`.
    _ = rsp.readMessage(msg[0..len], &out) catch return;
}

test "fuzz: HandshakeState.readMessage never panics on arbitrary bytes" {
    try testing.fuzz({}, fuzzReadMessage, .{});
}
