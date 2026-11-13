// SPDX-License-Identifier: MIT
//! RFC 9807 OPAQUE-3DH, generic over the configuration (RFC 9807 §7):
//! `Opaque(C)` with `C.Oprf` a `voprf` suite instance and `C.Hash`/`C.Hmac`/
//! `C.Hkdf` the matching std SHA-2 family. The AKE group is the OPRF group
//! (§6.4.1.1 ristretto255, §6.4.1.2 P-256: `DiffieHellman` = the group's
//! constant-time multiply, output through the OPRF group's SerializeElement).
//! `root.zig` instantiates it and re-exports the ristretto255-SHA512 instance
//! at top level; see `root.zig`'s module doc comment for the design notes.
//! Every declaration is `pub` so `root.zig`'s tests reach the internals; the
//! public API is what `root.zig` re-exports.

const std = @import("std");
const timing_safe = std.crypto.timing_safe;
const burn = @import("burn.zig");
const voprf = @import("voprf"); // error sets only; the suite is `C.Oprf`

pub fn Opaque(comptime C: type) type {
    return struct {
        // ── configuration constants (RFC 9807 §2 / §7, ristretto255-SHA-512) ─────

        /// `Nn` (§2): nonce length (envelope, masking, client/server nonces).
        pub const Nn: usize = 32;

        /// `Nseed` (§2): seed length (keyshare seeds, the envelope PrivateKey seed).
        pub const Nseed: usize = 32;

        /// `Nh` (§2.3): Hash output length (SHA-512).
        pub const Nh: usize = C.Hash.digest_length;

        /// `Npk` (§7): encoded AKE public key length (ristretto255 element).
        pub const Npk: usize = C.Oprf.Ne;

        /// `Nsk` (§7): encoded AKE private key length (ristretto255 scalar).
        pub const Nsk: usize = C.Oprf.Ns;

        /// `Nm` (§2.2): MAC output length (HMAC-SHA-512).
        pub const Nm: usize = Nh;

        /// `Nx` (§2.2): KDF Extract output length (HKDF-SHA-512).
        pub const Nx: usize = Nh;

        /// `Nok` (§2.1): OPRF private key length (ristretto255 scalar).
        pub const Nok: usize = C.Oprf.Ns;

        /// `Noe` (§2.1): serialized OPRF group element length.
        pub const Noe: usize = C.Oprf.Ne;

        /// `Ns` (RFC 9497 §4.1): OPRF blind scalar length. Blinds are produced
        /// by the caller's CSPRNG via `scalarFromWideBytes` (re-exported below).
        pub const Ns: usize = C.Oprf.Ns;

        /// The `masked_response` length: `Npk + Nn + Nm` (§6.3.1) — the XOR
        /// masking of `server_public_key || Envelope`.
        pub const masked_response_length: usize = Npk + Nn + Nm;

        /// Re-exported from `voprf` (RFC 9497 §4.7.2): reduce 64 uniformly
        /// random bytes to a canonical scalar — the intended way for callers
        /// with their own CSPRNG to produce the `blind` inputs below.
        pub const scalarFromWideBytes = C.Oprf.scalarFromWideBytes;

        // ── typed errors (RFC 9807 §9.3) ─────────────────────────────────────────

        /// §4.1.3 `EnvelopeRecoveryError`: the envelope auth_tag check failed —
        /// on the client this is what a WRONG PASSWORD (or a tampered
        /// credential response) looks like.
        pub const EnvelopeRecoveryError = error{EnvelopeRecovery};

        /// §6.4.3 `ServerAuthenticationError`: KE2's `server_mac` did not
        /// verify — the server could not prove knowledge of the record.
        pub const ServerAuthenticationError = error{ServerAuthentication};

        /// §6.4.4 `ClientAuthenticationError`: KE3's `client_mac` did not
        /// verify — the client could not prove knowledge of the password.
        pub const ClientAuthenticationError = error{ClientAuthentication};

        // ── wire structures (§4.1.1, §5.1, §6.1, §6.3.1) ─────────────────────────

        /// §4.1.1 `Envelope`: nonce + auth_tag ONLY (internal keying mode — the
        /// client private key is re-derived, never stored or encrypted).
        pub const Envelope = struct {
            nonce: [Nn]u8,
            auth_tag: [Nm]u8,

            pub const encoded_length = Nn + Nm; // 96

            pub fn toBytes(e: Envelope) [encoded_length]u8 {
                return e.nonce ++ e.auth_tag;
            }

            pub fn fromBytes(bytes: [encoded_length]u8) Envelope {
                return .{ .nonce = bytes[0..Nn].*, .auth_tag = bytes[Nn..].* };
            }
        };

        /// §5.1 `RegistrationRequest`: the client's blinded password element.
        pub const RegistrationRequest = struct {
            blinded_message: [Noe]u8,

            pub const encoded_length = Noe;

            pub fn toBytes(r: RegistrationRequest) [encoded_length]u8 {
                return r.blinded_message;
            }

            pub fn fromBytes(bytes: [encoded_length]u8) RegistrationRequest {
                return .{ .blinded_message = bytes };
            }
        };

        /// §5.1 `RegistrationResponse`: the evaluated element + the server's
        /// long-term AKE public key.
        pub const RegistrationResponse = struct {
            evaluated_message: [Noe]u8,
            server_public_key: [Npk]u8,

            pub const encoded_length = Noe + Npk;

            pub fn toBytes(r: RegistrationResponse) [encoded_length]u8 {
                return r.evaluated_message ++ r.server_public_key;
            }

            pub fn fromBytes(bytes: [encoded_length]u8) RegistrationResponse {
                return .{
                    .evaluated_message = bytes[0..Noe].*,
                    .server_public_key = bytes[Noe..].*,
                };
            }
        };

        /// §5.1 `RegistrationRecord` (the RFC's wire name is
        /// `registration_upload`): what the server stores per client.
        pub const RegistrationRecord = struct {
            client_public_key: [Npk]u8,
            masking_key: [Nh]u8,
            envelope: Envelope,

            pub const encoded_length = Npk + Nh + Envelope.encoded_length; // 192

            pub fn toBytes(r: RegistrationRecord) [encoded_length]u8 {
                return r.client_public_key ++ r.masking_key ++ r.envelope.toBytes();
            }

            pub fn fromBytes(bytes: [encoded_length]u8) RegistrationRecord {
                return .{
                    .client_public_key = bytes[0..Npk].*,
                    .masking_key = bytes[Npk .. Npk + Nh].*,
                    .envelope = Envelope.fromBytes(bytes[Npk + Nh ..].*),
                };
            }

            /// A1/opaque.md L1: `fromBytes` is pure slicing — a server that stores
            /// whatever bytes a registering client uploaded, unchecked, only
            /// discovers a malformed `client_public_key` at the first login
            /// attempt, as `generateKE2`'s `error.InvalidPublicKey` (via the
            /// `diffieHellman` DH step). RFC 9807 §5.2.3 does not require the
            /// server to validate on upload, so this is optional hardening, not a
            /// conformance requirement — but validating at storage time turns a
            /// permanently unusable account into an upload-time rejection the
            /// client can retry from, instead of a login-time failure that looks
            /// like a wrong password. Checks exactly what `diffieHellman` would
            /// have checked anyway: canonical ristretto255 encoding.
            pub fn validate(r: RegistrationRecord) error{InvalidPublicKey}!void {
                _ = C.Oprf.Element.fromBytes(r.client_public_key) catch return error.InvalidPublicKey;
            }
        };

        /// §6.3.1 `CredentialRequest` (same shape as `RegistrationRequest`).
        pub const CredentialRequest = struct {
            blinded_message: [Noe]u8,
        };

        /// §6.3.1 `CredentialResponse`: evaluated element + masking nonce + the
        /// XOR-masked `server_public_key || Envelope`.
        pub const CredentialResponse = struct {
            evaluated_message: [Noe]u8,
            masking_nonce: [Nn]u8,
            masked_response: [masked_response_length]u8,

            pub const encoded_length = Noe + Nn + masked_response_length; // 192

            pub fn toBytes(r: CredentialResponse) [encoded_length]u8 {
                return r.evaluated_message ++ r.masking_nonce ++ r.masked_response;
            }

            pub fn fromBytes(bytes: [encoded_length]u8) CredentialResponse {
                return .{
                    .evaluated_message = bytes[0..Noe].*,
                    .masking_nonce = bytes[Noe .. Noe + Nn].*,
                    .masked_response = bytes[Noe + Nn ..].*,
                };
            }
        };

        /// §6.1 `AuthRequest`: client nonce + client ephemeral public keyshare.
        pub const AuthRequest = struct {
            client_nonce: [Nn]u8,
            client_public_keyshare: [Npk]u8,
        };

        /// §6.1 `KE1` = CredentialRequest || AuthRequest.
        pub const KE1 = struct {
            credential_request: CredentialRequest,
            auth_request: AuthRequest,

            pub const encoded_length = Noe + Nn + Npk; // 96

            pub fn toBytes(m: KE1) [encoded_length]u8 {
                return m.credential_request.blinded_message ++
                    m.auth_request.client_nonce ++
                    m.auth_request.client_public_keyshare;
            }

            pub fn fromBytes(bytes: [encoded_length]u8) KE1 {
                return .{
                    .credential_request = .{ .blinded_message = bytes[0..Noe].* },
                    .auth_request = .{
                        .client_nonce = bytes[Noe .. Noe + Nn].*,
                        .client_public_keyshare = bytes[Noe + Nn ..].*,
                    },
                };
            }
        };

        /// §6.1 `AuthResponse`: server nonce + server ephemeral public
        /// keyshare + the server's transcript MAC.
        pub const AuthResponse = struct {
            server_nonce: [Nn]u8,
            server_public_keyshare: [Npk]u8,
            server_mac: [Nm]u8,
        };

        /// §6.1 `KE2` = CredentialResponse || AuthResponse.
        pub const KE2 = struct {
            credential_response: CredentialResponse,
            auth_response: AuthResponse,

            pub const encoded_length = CredentialResponse.encoded_length + Nn + Npk + Nm; // 320

            pub fn toBytes(m: KE2) [encoded_length]u8 {
                return m.credential_response.toBytes() ++
                    m.auth_response.server_nonce ++
                    m.auth_response.server_public_keyshare ++
                    m.auth_response.server_mac;
            }

            pub fn fromBytes(bytes: [encoded_length]u8) KE2 {
                const cr = CredentialResponse.encoded_length;
                return .{
                    .credential_response = CredentialResponse.fromBytes(bytes[0..cr].*),
                    .auth_response = .{
                        .server_nonce = bytes[cr .. cr + Nn].*,
                        .server_public_keyshare = bytes[cr + Nn .. cr + Nn + Npk].*,
                        .server_mac = bytes[cr + Nn + Npk ..].*,
                    },
                };
            }
        };

        /// §6.1 `KE3`: the client's transcript MAC.
        pub const KE3 = struct {
            client_mac: [Nm]u8,

            pub const encoded_length = Nm;

            pub fn toBytes(m: KE3) [encoded_length]u8 {
                return m.client_mac;
            }

            pub fn fromBytes(bytes: [encoded_length]u8) KE3 {
                return .{ .client_mac = bytes };
            }
        };

        /// §4 optional application identities. When a field is `null` it
        /// defaults to the corresponding public key (§4
        /// `CreateCleartextCredentials`) — both sides must agree on the same
        /// choice, and it must match what registration used.
        pub const Identities = struct {
            client: ?[]const u8 = null,
            server: ?[]const u8 = null,
        };

        /// An AKE key pair as produced by §6.4.1.1
        /// `DeriveDiffieHellmanKeyPair` (see `deriveAkeKeyPair`).
        pub const AkeKeyPair = struct {
            private_key: [Nsk]u8,
            public_key: [Npk]u8,
        };

        // ── KDF helpers ──────────────────────────────────────────────────────────

        /// RFC 5869 HKDF-Expand (HMAC-SHA-512) with a multi-part `info` and
        /// `L <= 2 * Nx` — every `Expand` RFC 9807 performs composes `info` by
        /// concatenation, and the longest output is the `Npk + Nn + Nm = 128`
        /// byte `credential_response_pad`, so two HMAC blocks suffice:
        /// `T(1) = HMAC(prk, info || 0x01)`, `T(2) = HMAC(prk, T(1) || info ||
        /// 0x02)`. Pinned against `std.crypto.kdf.hkdf.C.Hkdf.expand` by
        /// the `"expandMulti agrees with std"` test below (and transitively by
        /// every KAT).
        pub fn expandMulti(out: []u8, prk: *const [Nx]u8, info_parts: []const []const u8) void {
            std.debug.assert(out.len >= 1 and out.len <= 255 * Nx);
            var t: [Nx]u8 = undefined;
            var off: usize = 0;
            var i: u8 = 1;
            while (off < out.len) : (i += 1) {
                var mac = C.Hmac.init(prk);
                if (i > 1) mac.update(&t);
                for (info_parts) |part| mac.update(part);
                mac.update(&[1]u8{i});
                mac.final(&t);
                const n = @min(Nx, out.len - off);
                @memcpy(out[off..][0..n], t[0..n]);
                off += n;
            }
            std.crypto.secureZero(u8, &t);
        }

        /// `I2OSP(len, 2)` (§1.2) — the 2-byte big-endian length prefix used
        /// throughout the envelope MAC and the AKE preamble. Callers MUST check
        /// `len <= 0xffff` first (`checkI2ospLen`/`checkIdentities`) — an
        /// application-supplied identity or context past that bound reaches here
        /// only in ReleaseFast, where the assert below compiles out and the
        /// length silently wraps mod 65536 (A1/opaque.md M2).
        pub fn i2osp2(len: usize) [2]u8 {
            std.debug.assert(len <= 0xffff);
            var out: [2]u8 = undefined;
            std.mem.writeInt(u16, &out, @intCast(len), .big);
            return out;
        }

        /// A1/opaque.md M2: `identities.client`/`.server` and `context` are
        /// application-controlled byte strings with no documented or enforced
        /// bound, fed to `i2osp2` wherever the envelope MAC or the AKE transcript
        /// binds them (`envelopeAuthTag`, `runKeySchedule`). Past `0xffff` bytes,
        /// `i2osp2`'s length prefix is no longer injective: `debug.assert`
        /// panics in Debug/ReleaseSafe, and in ReleaseFast the length silently
        /// wraps mod 65536, so two DIFFERENT (identity, context) pairs can
        /// serialize to the IDENTICAL preamble and collide on the tag/transcript
        /// they are meant to bind apart. Checked once, at every public entry
        /// point that accepts these values, before anything derived from them is
        /// computed — 0 consumers in this repo, so a new rejection of input that
        /// used to panic or silently misbehave is P1 hardening, not a decision.
        pub fn checkIdentities(identities: Identities, context: []const u8) error{IdentityTooLong}!void {
            if (identities.client) |s| if (s.len > 0xffff) return error.IdentityTooLong;
            if (identities.server) |s| if (s.len > 0xffff) return error.IdentityTooLong;
            if (context.len > 0xffff) return error.IdentityTooLong;
        }

        // ── key derivation (§4.1.1, §6.4.1.1) ────────────────────────────────────

        /// §6.4.1.1 `DeriveDiffieHellmanKeyPair(seed)` = RFC 9497 §3.2.1
        /// `DeriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")` in the
        /// base-OPRF-mode context — via `C.Oprf.deriveKeyPair`. Public because
        /// servers use it to create their long-term AKE key pair at setup.
        ///
        /// `seed` by pointer and the key pair through `out` (written only on
        /// success); the derivation's stack is burned before the call returns.
        pub fn deriveAkeKeyPair(seed: *const [Nseed]u8, out: *AkeKeyPair) error{DeriveKeyPairFailed}!void {
            return burn.run(burn.small_burn, error{DeriveKeyPairFailed}!void, deriveAkeKeyPairBody, .{ seed, out });
        }

        pub fn deriveAkeKeyPairBody(seed: *const [Nseed]u8, out: *AkeKeyPair) error{DeriveKeyPairFailed}!void {
            out.* = try akeKeyPair(seed);
        }

        /// The by-value form for callers that already run inside a burned frame.
        pub fn akeKeyPair(seed: *const [Nseed]u8) error{DeriveKeyPairFailed}!AkeKeyPair {
            var kp: C.Oprf.KeyPair = undefined;
            // The info string is a constant, so voprf's `InputTooLong` cannot occur.
            C.Oprf.deriveKeyPair(.oprf, seed, "OPAQUE-DeriveDiffieHellmanKeyPair", &kp) catch return error.DeriveKeyPairFailed;
            return .{ .private_key = kp.sk, .public_key = kp.pk.toBytes() };
        }

        /// §5.2.2/§6.3.2.2's per-client OPRF key: `seed = Expand(oprf_seed,
        /// credential_identifier || "OprfKey", Nok)`, then RFC 9497
        /// `DeriveKeyPair(seed, "OPAQUE-DeriveKeyPair")` via `voprf`.
        pub fn deriveOprfKey(oprf_seed: [Nh]u8, credential_identifier: []const u8) error{DeriveKeyPairFailed}![Nok]u8 {
            var seed: [Nok]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            expandMulti(&seed, &oprf_seed, &.{ credential_identifier, "OprfKey" });
            var kp: C.Oprf.KeyPair = undefined;
            // Constant info: voprf's `InputTooLong` cannot occur.
            C.Oprf.deriveKeyPair(.oprf, &seed, "OPAQUE-DeriveKeyPair", &kp) catch return error.DeriveKeyPairFailed;
            return kp.sk;
        }

        /// §6.4.1.1 `DiffieHellman(k, B)`: RFC 9496 Decode (with §10.7 input
        /// validation: canonical + non-identity, via `C.Oprf.Element.fromBytes`)
        /// then a scalar multiplication that is constant-time in `k` AND does not
        /// branch on its own result — `ct25519.mulRistretto`, not
        /// `Ristretto255.mul`. Output is the 32-byte encoded element.
        ///
        /// **How §6.4.1.1's "the shared secret MUST NOT be the identity element"
        /// is satisfied.** It used to be satisfied by `catch`ing the rejection
        /// std's `mul` performs on its own output — i.e. by branching on a value
        /// derived from the SECRET `private_key`. It is now satisfied
        /// structurally, which is stronger: ristretto255 is a group of PRIME
        /// order `L` (that is the entire point of the ristretto abstraction — no
        /// cofactor, no small subgroup), and `fromBytes` has already rejected the
        /// identity, so `B` generates the whole group and `k*B` is the identity
        /// **iff `k == 0 (mod L)`**. A peer therefore cannot induce it at all,
        /// with any element it can encode. `k` is either a `C.Oprf.deriveKeyPair`
        /// output (the RFC 9497 §3.2.1 loop rejects zero) or a caller-supplied
        /// long-term server key held to the same rule. There is nothing left for
        /// a runtime check to catch that a branch on `k` would not simply leak.
        pub fn diffieHellman(private_key: [Nsk]u8, public_key: [Npk]u8) error{InvalidPublicKey}![Npk]u8 {
            const point = C.Oprf.Element.fromBytes(public_key) catch return error.InvalidPublicKey;
            return C.Oprf.Group.encode(C.Oprf.Group.mulSecret(point.p, &private_key));
        }

        /// A pluggable Key Stretching Function (RFC 9807 §7 `KSF`). RFC 9807
        /// leaves the concrete algorithm to "the application" — this module
        /// never picks one for you (see module doc comment for why: no
        /// `Allocator`/`Io` dependency anywhere in this module, and a real KSF
        /// like Argon2id needs both) and has no default: every caller of
        /// `finalizeRegistrationRequest`/`generateKE3` must pass one
        /// explicitly. `ctx` lets a real implementation close over whatever it
        /// needs (allocator, `Io`, parameters) without this module knowing its
        /// shape.
        pub const Ksf = struct {
            ctx: ?*anyopaque = null,
            /// `in` is `oprf_output` (`Nh` bytes); must write exactly `Nh`
            /// stretched bytes to `out`. A real KSF can fail (allocation
            /// failure, misconfigured parameters, ...): `error.KsfFailed` is
            /// the only variant this module's public error sets add for it —
            /// distinguish specific causes on the caller's side of `ctx`.
            stretchFn: *const fn (ctx: ?*anyopaque, in: [Nh]u8, out: *[Nh]u8) error{KsfFailed}!void,

            /// `Stretch(msg) = msg` — what RFC 9807 Appendix C's own test
            /// vectors use, and ONLY what they use: reproducing those KATs (or
            /// a test built the same way) is the one legitimate reason to pass
            /// this. RFC 9807 §7 never recommends it for a deployment — its
            /// three configurations RECOMMENDED absent an application-specific
            /// profile all use a real KSF (two Argon2id, one scrypt), because
            /// skipping stretching entirely means an offline dictionary attack
            /// on a leaked `RegistrationRecord` costs one OPRF evaluation per
            /// guess. There being no default on `finalizeRegistrationRequest`/
            /// `generateKE3` is deliberate: passing `.identity` outside a test
            /// must be a decision the caller's source visibly makes, not
            /// something that happens by omission.
            pub const identity: Ksf = .{ .stretchFn = identityStretch };
            fn identityStretch(_: ?*anyopaque, in: [Nh]u8, out: *[Nh]u8) error{KsfFailed}!void {
                out.* = in;
            }

            fn stretch(self: Ksf, in: [Nh]u8) error{KsfFailed}![Nh]u8 {
                var out: [Nh]u8 = undefined;
                try self.stretchFn(self.ctx, in, &out);
                return out;
            }
        };

        /// §5.2.3/§6.3.2.3's `randomized_password` = `Extract("",
        /// oprf_output || Stretch(oprf_output))`, `Stretch` = `ksf`.
        pub fn randomizedPassword(
            password: []const u8,
            blind: [Ns]u8,
            evaluated_message: [Noe]u8,
            ksf: Ksf,
        ) (error{ InvalidMessage, InvalidBlind, InputTooLong } || error{KsfFailed})![Nx]u8 {
            const evaluated = C.Oprf.Element.fromBytes(evaluated_message) catch return error.InvalidMessage;
            var oprf_output: [Nh]u8 = undefined;
            try C.Oprf.finalize(password, &blind, evaluated, &oprf_output);
            defer std.crypto.secureZero(u8, &oprf_output);
            var stretched = try ksf.stretch(oprf_output);
            defer std.crypto.secureZero(u8, &stretched);
            var extract = C.Hkdf.extractInit("");
            extract.update(&oprf_output);
            extract.update(&stretched);
            var prk: [Nx]u8 = undefined;
            extract.final(&prk);
            return prk;
        }

        // ── envelope (§4.1) ──────────────────────────────────────────────────────

        /// The §4.1.2/§4.1.3 auth_tag: `MAC(auth_key, envelope_nonce ||
        /// CleartextCredentials)` where the §4 `CleartextCredentials`
        /// serialization is `server_public_key || I2OSP(len(server_identity),
        /// 2) || server_identity || I2OSP(len(client_identity), 2) ||
        /// client_identity` (identities already defaulted by the caller).
        pub fn envelopeAuthTag(
            auth_key: *const [Nh]u8,
            envelope_nonce: [Nn]u8,
            server_public_key: [Npk]u8,
            server_identity: []const u8,
            client_identity: []const u8,
        ) [Nm]u8 {
            var mac = C.Hmac.init(auth_key);
            mac.update(&envelope_nonce);
            mac.update(&server_public_key);
            mac.update(&i2osp2(server_identity.len));
            mac.update(server_identity);
            mac.update(&i2osp2(client_identity.len));
            mac.update(client_identity);
            var tag: [Nm]u8 = undefined;
            mac.final(&tag);
            return tag;
        }

        pub const StoreResult = struct {
            envelope: Envelope,
            client_public_key: [Npk]u8,
            masking_key: [Nh]u8,
            export_key: [Nh]u8,
        };

        /// §4.1.2 `Store`: derive `masking_key`/`auth_key`/`export_key`/the
        /// private-key seed from `randomized_password`, derive the client AKE
        /// key pair (internal keying), and MAC the cleartext credentials. On
        /// the (negligible) `DeriveKeyPairFailed`, re-run registration with a
        /// fresh `envelope_nonce` per §4.1.2.
        pub fn store(
            randomized_password: *const [Nx]u8,
            server_public_key: [Npk]u8,
            identities: Identities,
            envelope_nonce: [Nn]u8,
        ) error{DeriveKeyPairFailed}!StoreResult {
            var masking_key: [Nh]u8 = undefined;
            expandMulti(&masking_key, randomized_password, &.{"MaskingKey"});
            var auth_key: [Nh]u8 = undefined;
            defer std.crypto.secureZero(u8, &auth_key);
            expandMulti(&auth_key, randomized_password, &.{ &envelope_nonce, "AuthKey" });
            var export_key: [Nh]u8 = undefined;
            expandMulti(&export_key, randomized_password, &.{ &envelope_nonce, "ExportKey" });
            var seed: [Nseed]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            expandMulti(&seed, randomized_password, &.{ &envelope_nonce, "PrivateKey" });
            // A1/opaque.md H2: `kp.private_key` is the client's long-term AKE
            // private key, deterministic in (password, user) — whoever recovers it
            // once owns the account forever, even across server key rotation. It
            // never leaves this function (only `kp.public_key` is returned), so
            // zeroing it here is free and closes exactly the stack residue the
            // audit's `stackscan` probe measured.
            var kp = try akeKeyPair(&seed);
            defer std.crypto.secureZero(u8, &kp.private_key);

            const server_identity = identities.server orelse &server_public_key;
            const client_identity = identities.client orelse &kp.public_key;
            const tag = envelopeAuthTag(&auth_key, envelope_nonce, server_public_key, server_identity, client_identity);

            return .{
                .envelope = .{ .nonce = envelope_nonce, .auth_tag = tag },
                .client_public_key = kp.public_key,
                .masking_key = masking_key,
                .export_key = export_key,
            };
        }

        pub const RecoverResult = struct {
            client_private_key: [Nsk]u8,
            client_public_key: [Npk]u8,
            export_key: [Nh]u8,
        };

        /// §4.1.3 `Recover`: re-derive the keys from `randomized_password` and
        /// the envelope nonce, re-derive the client key pair, recompute the
        /// auth_tag over the cleartext credentials, and compare timing-safe.
        /// Fails CLOSED (`error.EnvelopeRecovery`) on any mismatch — including
        /// the negligible key-derivation failure — releasing nothing.
        pub fn recover(
            randomized_password: *const [Nx]u8,
            server_public_key: [Npk]u8,
            envelope: Envelope,
            identities: Identities,
        ) EnvelopeRecoveryError!RecoverResult {
            var auth_key: [Nh]u8 = undefined;
            defer std.crypto.secureZero(u8, &auth_key);
            expandMulti(&auth_key, randomized_password, &.{ &envelope.nonce, "AuthKey" });
            var export_key: [Nh]u8 = undefined;
            expandMulti(&export_key, randomized_password, &.{ &envelope.nonce, "ExportKey" });
            var seed: [Nseed]u8 = undefined;
            defer std.crypto.secureZero(u8, &seed);
            expandMulti(&seed, randomized_password, &.{ &envelope.nonce, "PrivateKey" });
            const kp = akeKeyPair(&seed) catch return error.EnvelopeRecovery;

            const server_identity = identities.server orelse &server_public_key;
            const client_identity = identities.client orelse &kp.public_key;
            const expected_tag = envelopeAuthTag(&auth_key, envelope.nonce, server_public_key, server_identity, client_identity);
            if (!timing_safe.eql([Nm]u8, envelope.auth_tag, expected_tag))
                return error.EnvelopeRecovery;

            return .{
                .client_private_key = kp.private_key,
                .client_public_key = kp.public_key,
                .export_key = export_key,
            };
        }

        // ── registration (§5.2) ──────────────────────────────────────────────────

        /// §5.2.1 `CreateRegistrationRequest(password)` with a caller-supplied
        /// `blind` (the RFC's `Blind` samples it internally; here it MUST be a
        /// fresh uniformly random scalar from the caller's CSPRNG — see
        /// `scalarFromWideBytes`). The caller keeps `blind` secret for
        /// `finalizeRegistrationRequest`.
        pub fn createRegistrationRequest(
            password: []const u8,
            blind: *const [Ns]u8,
        ) voprf.BlindError!RegistrationRequest {
            return burn.run(burn.mul_burn, voprf.BlindError!RegistrationRequest, createRegistrationRequestBody, .{ password, blind });
        }

        pub fn createRegistrationRequestBody(password: []const u8, blind: *const [Ns]u8) voprf.BlindError!RegistrationRequest {
            const blinded = try C.Oprf.blind(.oprf, password, blind);
            return .{ .blinded_message = blinded.toBytes() };
        }

        /// No `InvalidSecretKey`: `C.Oprf.blindEvaluate` returns no error (A1/opaque.md L2).
        pub const CreateRegistrationResponseError = error{ InvalidMessage, DeriveKeyPairFailed };

        /// §5.2.2 `CreateRegistrationResponse`: derive the per-client OPRF key
        /// from `oprf_seed` + `credential_identifier` and evaluate the blinded
        /// element (both via `voprf`). On the negligible `DeriveKeyPairFailed`,
        /// choose a new `credential_identifier` per §5.2.2.
        pub fn createRegistrationResponse(
            request: RegistrationRequest,
            server_public_key: [Npk]u8,
            credential_identifier: []const u8,
            oprf_seed: *const [Nh]u8,
        ) CreateRegistrationResponseError!RegistrationResponse {
            return burn.run(burn.mul_burn, CreateRegistrationResponseError!RegistrationResponse, createRegistrationResponseBody, .{ request, server_public_key, credential_identifier, oprf_seed });
        }

        pub fn createRegistrationResponseBody(
            request: RegistrationRequest,
            server_public_key: [Npk]u8,
            credential_identifier: []const u8,
            oprf_seed: *const [Nh]u8,
        ) CreateRegistrationResponseError!RegistrationResponse {
            // A1/opaque.md H2: per-client OPRF key, never returned to the caller.
            var oprf_key = try deriveOprfKey(oprf_seed.*, credential_identifier);
            defer std.crypto.secureZero(u8, &oprf_key);
            const blinded = C.Oprf.Element.fromBytes(request.blinded_message) catch return error.InvalidMessage;
            const evaluated = C.Oprf.blindEvaluate(&oprf_key, blinded);
            return .{
                .evaluated_message = evaluated.toBytes(),
                .server_public_key = server_public_key,
            };
        }

        /// `InputTooLong`: a password longer than RFC 9497's `2^16 - 1`-byte OPRF input bound.
        pub const FinalizeRegistrationError = error{ InvalidMessage, InvalidBlind, DeriveKeyPairFailed, IdentityTooLong, KsfFailed, InputTooLong };

        pub const FinalizeRegistrationResult = struct {
            /// The `RegistrationRecord` to send to the server (§5.1
            /// `registration_upload`).
            record: RegistrationRecord,
            /// The client-only export key (§10.4) — same value re-derived at
            /// every successful login.
            export_key: [Nh]u8,
        };

        /// §5.2.3 `FinalizeRegistrationRequest`: unblind + finalize the OPRF
        /// (via `C.Oprf.finalize`), stretch (`ksf` — see `Ksf`'s doc comment;
        /// pass `Ksf.identity` ONLY to reproduce an RFC 9807 Appendix C KAT,
        /// never for a real registration) and extract `randomized_password`,
        /// then §4.1.2 `Store` with the caller-supplied `envelope_nonce` (the
        /// RFC samples it inside `Store`; fresh random per registration).
        /// `identities` must match what logins will use.
        ///
        /// `blind` by pointer; the record and the `export_key` go through `out`
        /// (written only on success). Stack burned before return.
        pub fn finalizeRegistrationRequest(
            password: []const u8,
            blind: *const [Ns]u8,
            response: RegistrationResponse,
            identities: Identities,
            envelope_nonce: [Nn]u8,
            ksf: Ksf,
            out: *FinalizeRegistrationResult,
        ) FinalizeRegistrationError!void {
            return burn.run(burn.reg_burn, FinalizeRegistrationError!void, finalizeRegistrationRequestBody, .{ password, blind, response, identities, envelope_nonce, ksf, out });
        }

        pub fn finalizeRegistrationRequestBody(
            password: []const u8,
            blind: *const [Ns]u8,
            response: RegistrationResponse,
            identities: Identities,
            envelope_nonce: [Nn]u8,
            ksf: Ksf,
            out: *FinalizeRegistrationResult,
        ) FinalizeRegistrationError!void {
            try checkIdentities(identities, "");
            var rp = try randomizedPassword(password, blind.*, response.evaluated_message, ksf);
            defer std.crypto.secureZero(u8, &rp);
            const stored = try store(&rp, response.server_public_key, identities, envelope_nonce);
            out.* = .{
                .record = .{
                    .client_public_key = stored.client_public_key,
                    .masking_key = stored.masking_key,
                    .envelope = stored.envelope,
                },
                .export_key = stored.export_key,
            };
        }

        // ── online AKE (§6) ──────────────────────────────────────────────────────

        /// §6's `ClientState`: everything the client must hold between
        /// `generateKE1` and `generateKE3`. `password` is borrowed (the caller
        /// keeps it alive and secret); the rest are secrets to erase after the
        /// login completes (§6: "ephemeral and should be erased").
        pub const ClientLoginState = struct {
            password: []const u8,
            blind: [Ns]u8,
            /// The client's ephemeral AKE private keyshare (`client_secret`).
            client_secret: [Nsk]u8,
            ke1: KE1,
        };

        /// §6.4's `ServerAkeState`: held between `generateKE2` and
        /// `serverFinish`; ephemeral, erase after the login completes.
        pub const ServerLoginState = struct {
            expected_client_mac: [Nm]u8,
            session_key: [Nx]u8,
        };

        /// No `InvalidBlind`: `C.Oprf.blind` only returns `InvalidInput`; the blind is
        /// first used, and can first fail, in `generateKE3` (A1/opaque.md L2).
        /// `InputTooLong`: a password longer than RFC 9497's `2^16 - 1`-byte OPRF input bound.
        pub const GenerateKE1Error = error{ InvalidInput, DeriveKeyPairFailed, InputTooLong };

        pub const GenerateKE1Result = struct {
            ke1: KE1,
            state: ClientLoginState,
        };

        /// §6.2.1 `GenerateKE1` (= `CreateCredentialRequest` +
        /// `AuthClientStart`) with caller-supplied randomness: `blind` (fresh
        /// random scalar), `client_nonce` (fresh Nn bytes), and
        /// `client_keyshare_seed` (fresh Nseed bytes; the ephemeral keyshare
        /// is derived from it per §6.4.1.1).
        ///
        /// `blind` and the keyshare seed by pointer; the result (whose `state` holds
        /// the blind and the ephemeral key by design) through `out`, written only on
        /// success. Stack burned before return.
        pub fn generateKE1(
            password: []const u8,
            blind: *const [Ns]u8,
            client_nonce: [Nn]u8,
            client_keyshare_seed: *const [Nseed]u8,
            out: *GenerateKE1Result,
        ) GenerateKE1Error!void {
            return burn.run(burn.mul_burn, GenerateKE1Error!void, generateKE1Body, .{ password, blind, client_nonce, client_keyshare_seed, out });
        }

        pub fn generateKE1Body(
            password: []const u8,
            blind: *const [Ns]u8,
            client_nonce: [Nn]u8,
            client_keyshare_seed: *const [Nseed]u8,
            out: *GenerateKE1Result,
        ) GenerateKE1Error!void {
            const blinded = try C.Oprf.blind(.oprf, password, blind);
            var keyshare = try akeKeyPair(client_keyshare_seed);
            defer std.crypto.secureZero(u8, &keyshare.private_key);
            const ke1 = KE1{
                .credential_request = .{ .blinded_message = blinded.toBytes() },
                .auth_request = .{
                    .client_nonce = client_nonce,
                    .client_public_keyshare = keyshare.public_key,
                },
            };
            out.* = .{ .ke1 = ke1, .state = .{
                .password = password,
                .blind = blind.*,
                .client_secret = keyshare.private_key,
                .ke1 = ke1,
            } };
        }

        /// No `InvalidSecretKey`: `C.Oprf.blindEvaluate` returns no error (A1/opaque.md L2).
        pub const GenerateKE2Error = error{ InvalidMessage, InvalidPublicKey, DeriveKeyPairFailed, IdentityTooLong };

        pub const GenerateKE2Result = struct {
            ke2: KE2,
            state: ServerLoginState,
        };

        /// §6.2.2 `GenerateKE2` (= `CreateCredentialResponse` +
        /// `AuthServerRespond`) with caller-supplied randomness
        /// (`masking_nonce`, `server_nonce`, `server_keyshare_seed` — all
        /// fresh random per login). `context` is the application-configured
        /// shared context string (§7; both sides must agree; may be empty).
        /// For an UNREGISTERED user, pass the server's one persistent fake
        /// record (§6.3.2.2) — see the module doc comment.
        ///
        /// The server key, `oprf_seed` and the keyshare seed by pointer; the result
        /// (whose `state` holds the expected client MAC and the session key by design)
        /// through `out`, written only on success. Stack burned before return.
        pub fn generateKE2(
            server_private_key: *const [Nsk]u8,
            server_public_key: [Npk]u8,
            record: RegistrationRecord,
            credential_identifier: []const u8,
            oprf_seed: *const [Nh]u8,
            ke1: KE1,
            identities: Identities,
            context: []const u8,
            masking_nonce: [Nn]u8,
            server_nonce: [Nn]u8,
            server_keyshare_seed: *const [Nseed]u8,
            out: *GenerateKE2Result,
        ) GenerateKE2Error!void {
            return burn.run(burn.reg_burn, GenerateKE2Error!void, generateKE2Body, .{ server_private_key, server_public_key, record, credential_identifier, oprf_seed, ke1, identities, context, masking_nonce, server_nonce, server_keyshare_seed, out });
        }

        pub fn generateKE2Body(
            server_private_key: *const [Nsk]u8,
            server_public_key: [Npk]u8,
            record: RegistrationRecord,
            credential_identifier: []const u8,
            oprf_seed: *const [Nh]u8,
            ke1: KE1,
            identities: Identities,
            context: []const u8,
            masking_nonce: [Nn]u8,
            server_nonce: [Nn]u8,
            server_keyshare_seed: *const [Nseed]u8,
            out: *GenerateKE2Result,
        ) GenerateKE2Error!void {
            try checkIdentities(identities, context);
            // §6.3.2.2 CreateCredentialResponse.
            // A1/opaque.md H2: per-client OPRF key, never returned to the caller.
            var oprf_key = try deriveOprfKey(oprf_seed.*, credential_identifier);
            defer std.crypto.secureZero(u8, &oprf_key);
            const blinded = C.Oprf.Element.fromBytes(ke1.credential_request.blinded_message) catch
                return error.InvalidMessage;
            const evaluated = C.Oprf.blindEvaluate(&oprf_key, blinded);

            var masked = credentialResponsePad(&record.masking_key, masking_nonce);
            const plaintext = server_public_key ++ record.envelope.toBytes();
            for (&masked, plaintext) |*b, p| b.* ^= p;

            const credential_response = CredentialResponse{
                .evaluated_message = evaluated.toBytes(),
                .masking_nonce = masking_nonce,
                .masked_response = masked,
            };

            // §6.4.4 AuthServerRespond.
            // A1/opaque.md H2: the server's ephemeral keyshare private key; only
            // `keyshare.public_key` (below) and the DH outputs it feeds (already
            // zeroed via `ikm`) leave this function.
            var keyshare = try akeKeyPair(server_keyshare_seed);
            defer std.crypto.secureZero(u8, &keyshare.private_key);
            const dh1 = try diffieHellman(keyshare.private_key, ke1.auth_request.client_public_keyshare);
            const dh2 = try diffieHellman(server_private_key.*, ke1.auth_request.client_public_keyshare);
            const dh3 = try diffieHellman(keyshare.private_key, record.client_public_key);
            var ikm = dh1 ++ dh2 ++ dh3;
            defer std.crypto.secureZero(u8, &ikm);

            const server_identity = identities.server orelse &server_public_key;
            const client_identity = identities.client orelse &record.client_public_key;
            const schedule = runKeySchedule(
                &ikm,
                context,
                client_identity,
                server_identity,
                ke1,
                credential_response,
                server_nonce,
                keyshare.public_key,
            );

            out.* = .{
                .ke2 = .{
                    .credential_response = credential_response,
                    .auth_response = .{
                        .server_nonce = server_nonce,
                        .server_public_keyshare = keyshare.public_key,
                        .server_mac = schedule.server_mac,
                    },
                },
                .state = .{
                    .expected_client_mac = schedule.client_mac,
                    .session_key = schedule.session_key,
                },
            };
        }

        pub const GenerateKE3Error = error{
            /// A password longer than RFC 9497's `2^16 - 1`-byte OPRF input bound.
            InputTooLong,
            InvalidMessage,
            InvalidBlind,
            InvalidPublicKey,
            EnvelopeRecovery,
            ServerAuthentication,
            IdentityTooLong,
            KsfFailed,
        };

        pub const GenerateKE3Result = struct {
            ke3: KE3,
            /// The shared session secret — MUST NOT be used unless this call
            /// succeeded (server authentication verified).
            session_key: [Nx]u8,
            /// The client-only export key (§10.4), identical to the one from
            /// registration. Only released after the server_mac verified.
            export_key: [Nh]u8,
        };

        /// §6.2.3 `GenerateKE3` (= `RecoverCredentials` +
        /// `AuthClientFinalize`): unmask the credential response, recover the
        /// envelope (wrong password ⇒ `error.EnvelopeRecovery`, fail closed),
        /// run the client side of 3DH, verify the server's transcript MAC
        /// timing-safe (mismatch ⇒ `error.ServerAuthentication`, fail closed),
        /// and only then produce KE3 + `session_key` + `export_key`. Must use
        /// the same `ksf` as the `finalizeRegistrationRequest` call that
        /// created this account (a mismatched KSF fails closed via
        /// `EnvelopeRecovery`, same as a wrong password —
        /// `randomized_password` differs either way).
        /// `identities` and `context` must match the server's.
        ///
        /// `state` by pointer (no by-value copy of the blind and the ephemeral key in
        /// the callee's frame); the session key and export key go through `out`,
        /// written only after the server MAC verified. Stack burned before return.
        pub fn generateKE3(
            state: *const ClientLoginState,
            identities: Identities,
            context: []const u8,
            ke2: KE2,
            ksf: Ksf,
            out: *GenerateKE3Result,
        ) GenerateKE3Error!void {
            return burn.run(burn.ke3_burn, GenerateKE3Error!void, generateKE3Body, .{ state, identities, context, ke2, ksf, out });
        }

        pub fn generateKE3Body(
            state: *const ClientLoginState,
            identities: Identities,
            context: []const u8,
            ke2: KE2,
            ksf: Ksf,
            out: *GenerateKE3Result,
        ) GenerateKE3Error!void {
            try checkIdentities(identities, context);
            // §6.3.2.3 RecoverCredentials.
            var rp = try randomizedPassword(state.password, state.blind, ke2.credential_response.evaluated_message, ksf);
            defer std.crypto.secureZero(u8, &rp);
            var masking_key: [Nh]u8 = undefined;
            defer std.crypto.secureZero(u8, &masking_key);
            expandMulti(&masking_key, &rp, &.{"MaskingKey"});

            var plaintext = credentialResponsePad(&masking_key, ke2.credential_response.masking_nonce);
            for (&plaintext, ke2.credential_response.masked_response) |*b, m| b.* ^= m;
            const server_public_key: [Npk]u8 = plaintext[0..Npk].*;
            const envelope = Envelope.fromBytes(plaintext[Npk..].*);

            // A1/opaque.md H2: the client's long-term AKE private key, statically
            // derived from (password, user) — see the identical note in `store`.
            var credentials = try recover(&rp, server_public_key, envelope, identities);
            defer std.crypto.secureZero(u8, &credentials.client_private_key);

            // §6.4.3 AuthClientFinalize.
            // A1/opaque.md H2: `state` is a by-value parameter, so this is already
            // a local copy distinct from whatever the caller holds — zeroing it
            // here is scoped to this function's own stack frame, the same scope
            // the audit's `stackscan` probe measured.
            var client_secret = state.client_secret;
            defer std.crypto.secureZero(u8, &client_secret);
            const dh1 = try diffieHellman(client_secret, ke2.auth_response.server_public_keyshare);
            const dh2 = try diffieHellman(client_secret, server_public_key);
            const dh3 = try diffieHellman(credentials.client_private_key, ke2.auth_response.server_public_keyshare);
            var ikm = dh1 ++ dh2 ++ dh3;
            defer std.crypto.secureZero(u8, &ikm);

            const server_identity = identities.server orelse &server_public_key;
            const client_identity = identities.client orelse &credentials.client_public_key;
            const schedule = runKeySchedule(
                &ikm,
                context,
                client_identity,
                server_identity,
                state.ke1,
                ke2.credential_response,
                ke2.auth_response.server_nonce,
                ke2.auth_response.server_public_keyshare,
            );

            if (!timing_safe.eql([Nm]u8, ke2.auth_response.server_mac, schedule.server_mac))
                return error.ServerAuthentication;

            out.* = .{
                .ke3 = .{ .client_mac = schedule.client_mac },
                .session_key = schedule.session_key,
                .export_key = credentials.export_key,
            };
        }

        /// §6.2.4 `ServerFinish` (= `AuthServerFinalize`): verify the client's
        /// transcript MAC timing-safe and release `session_key` if and only if
        /// it matches (`error.ClientAuthentication` otherwise, fail closed —
        /// this check is what gives full forward secrecy against active
        /// attackers, §6.2.4).
        /// `state` by pointer; the session key goes through `out` (written only on
        /// success).
        pub fn serverFinish(state: *const ServerLoginState, ke3: KE3, out: *[Nx]u8) ClientAuthenticationError!void {
            return burn.run(burn.small_burn, ClientAuthenticationError!void, serverFinishBody, .{ state, ke3, out });
        }

        pub fn serverFinishBody(state: *const ServerLoginState, ke3: KE3, out: *[Nx]u8) ClientAuthenticationError!void {
            if (!timing_safe.eql([Nm]u8, ke3.client_mac, state.expected_client_mac))
                return error.ClientAuthentication;
            out.* = state.session_key;
        }

        // ── credential masking (§6.3.2.2/§6.3.2.3) ───────────────────────────────

        /// `credential_response_pad = Expand(masking_key, masking_nonce ||
        /// "CredentialResponsePad", Npk + Nn + Nm)` — the XOR pad over
        /// `server_public_key || Envelope` in both directions.
        pub fn credentialResponsePad(masking_key: *const [Nh]u8, masking_nonce: [Nn]u8) [masked_response_length]u8 {
            var pad: [masked_response_length]u8 = undefined;
            expandMulti(&pad, masking_key, &.{ &masking_nonce, "CredentialResponsePad" });
            return pad;
        }

        // ── 3DH key schedule (§6.4.2) ────────────────────────────────────────────

        /// §6.4.2.1 `Derive-Secret(Secret, Label, Transcript-Hash)` =
        /// `Expand(Secret, CustomLabel, Nx)` with the TLS 1.3-style
        /// `CustomLabel = I2OSP(Nx, 2) || I2OSP(len("OPAQUE-" || Label), 1) ||
        /// "OPAQUE-" || Label || I2OSP(len(Context), 1) || Context`.
        pub fn deriveSecret(secret: *const [Nx]u8, comptime label: []const u8, transcript: []const u8) [Nx]u8 {
            const full_label = "OPAQUE-" ++ label;
            comptime std.debug.assert(full_label.len >= 8 and full_label.len <= 255);
            std.debug.assert(transcript.len <= 255);
            var out: [Nx]u8 = undefined;
            expandMulti(&out, secret, &.{
                &[2]u8{ 0, Nx },
                &[1]u8{full_label.len},
                full_label,
                &[1]u8{@intCast(transcript.len)},
                transcript,
            });
            return out;
        }

        pub const KeySchedule = struct {
            server_mac: [Nm]u8,
            client_mac: [Nm]u8,
            session_key: [Nx]u8,
        };

        /// The shared §6.4.2 core both sides run identically: stream the
        /// §6.4.2.1 `Preamble` into SHA-512 (`"OPAQUEv1-" || I2OSP(len(
        /// context), 2) || context || I2OSP(len(client_identity), 2) ||
        /// client_identity || KE1 || I2OSP(len(server_identity), 2) ||
        /// server_identity || credential_response || server_nonce ||
        /// server_public_keyshare`), then §6.4.2.2 `DeriveKeys(ikm,
        /// preamble)`: `prk = Extract("", ikm)`, `handshake_secret` /
        /// `session_key` via `Derive-Secret(..., Hash(preamble))`, `Km2`/`Km3`
        /// from `handshake_secret`, `server_mac = MAC(Km2, Hash(preamble))`,
        /// and `client_mac = MAC(Km3, Hash(preamble || server_mac))`.
        pub fn runKeySchedule(
            ikm: *const [3 * Npk]u8,
            context: []const u8,
            client_identity: []const u8,
            server_identity: []const u8,
            ke1: KE1,
            credential_response: CredentialResponse,
            server_nonce: [Nn]u8,
            server_public_keyshare: [Npk]u8,
        ) KeySchedule {
            var transcript = C.Hash.init(.{});
            transcript.update("OPAQUEv1-");
            transcript.update(&i2osp2(context.len));
            transcript.update(context);
            transcript.update(&i2osp2(client_identity.len));
            transcript.update(client_identity);
            transcript.update(&ke1.toBytes());
            transcript.update(&i2osp2(server_identity.len));
            transcript.update(server_identity);
            transcript.update(&credential_response.toBytes());
            transcript.update(&server_nonce);
            transcript.update(&server_public_keyshare);

            var preamble_hash: [Nh]u8 = undefined;
            var preamble_only = transcript; // value copy: Hash(preamble)
            preamble_only.final(&preamble_hash);

            var prk = C.Hkdf.extract("", ikm);
            defer std.crypto.secureZero(u8, &prk);
            var handshake_secret = deriveSecret(&prk, "HandshakeSecret", &preamble_hash);
            defer std.crypto.secureZero(u8, &handshake_secret);
            const session_key = deriveSecret(&prk, "SessionKey", &preamble_hash);
            var km2 = deriveSecret(&handshake_secret, "ServerMAC", "");
            defer std.crypto.secureZero(u8, &km2);
            var km3 = deriveSecret(&handshake_secret, "ClientMAC", "");
            defer std.crypto.secureZero(u8, &km3);

            var server_mac: [Nm]u8 = undefined;
            C.Hmac.create(&server_mac, &preamble_hash, &km2);

            // client_mac covers Hash(preamble || server_mac).
            transcript.update(&server_mac);
            var full_transcript_hash: [Nh]u8 = undefined;
            transcript.final(&full_transcript_hash);
            var client_mac: [Nm]u8 = undefined;
            C.Hmac.create(&client_mac, &full_transcript_hash, &km3);

            return .{
                .server_mac = server_mac,
                .client_mac = client_mac,
                .session_key = session_key,
            };
        }

        // ── tests ────────────────────────────────────────────────────────────────

    };
}
