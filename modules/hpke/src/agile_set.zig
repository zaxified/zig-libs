// SPDX-License-Identifier: MIT
//! `hpke.agile.Agile(opts)`: the runtime-agile API over a subset of KEMs,
//! KDFs and AEADs (`agile.zig` holds the shared types and the full-set
//! instance). A separate file so the instance's `Context`/`Setup` do not
//! collide with `agile.zig`'s full-set aliases of the same name.

const std = @import("std");
const ag = @import("agile.zig");
const suite = @import("suite.zig");
const schedule = @import("schedule.zig");
const burn = @import("burn.zig");

const Suite = ag.Suite;
const KemId = ag.KemId;
const KdfId = ag.KdfId;
const AeadId = ag.AeadId;
const Mode = ag.Mode;
const PublicKey = ag.PublicKey;
const KeyPair = ag.KeyPair;
const Msg = ag.Msg;
const EphSource = ag.EphSource;
const KemOf = ag.KemOf;
const KdfOf = ag.KdfOf;
const AeadOf = ag.AeadOf;
const isPq = ag.isPq;
const known = ag.known;
const checkMode = ag.checkMode;
const max_nsecret = ag.max_nsecret;
const max_nh = ag.max_nh;
const max_enc_len = ag.max_enc_len;
const SuiteError = ag.SuiteError;
const KeyError = ag.KeyError;
const SetupSError = ag.SetupSError;
const SetupRError = ag.SetupRError;
const SealError = ag.SealError;
const OpenError = ag.OpenError;
const SealOnceError = ag.SealOnceError;
const OpenOnceError = ag.OpenOnceError;
const Options = ag.Options;

/// The runtime-agile API over the subset `opts`: only the listed KEMs, KDFs
/// and AEADs are compiled in, every other id is `error.UnsupportedSuite`.
pub fn Agile(comptime opts: Options) type {
    return struct {
        pub const options = opts;

        /// `suite` restricted to this instance.
        pub fn supports(s: Suite) bool {
            return known(KemId, opts.kems, s.kem) and known(KdfId, opts.kdfs, s.kdf) and known(AeadId, opts.aeads, s.aead);
        }

        /// `DeserializePublicKey` (Go `KEM.NewPublicKey`): a length other
        /// than the KEM's `Npk` is `InvalidLength`; the NIST DHKEM points are
        /// validated now (`DeserializeError`); X25519, X448 and the ML-KEM keys
        /// are checked by `encap`, as in the comptime API.
        pub fn publicKeyFromBytes(kem: KemId, b: []const u8) KeyError!PublicKey {
            inline for (opts.kems) |k| if (kem == k) {
                const K = KemOf(k);
                if (b.len != K.Npk) return error.InvalidLength;
                if (@hasDecl(K, "validatePublicKey")) try K.validatePublicKey(b[0..K.Npk]);
                var out: PublicKey = .{ .kem = kem, .len = b.len, .bytes = undefined };
                @memcpy(out.bytes[0..b.len], b);
                return out;
            };
            return error.UnsupportedSuite;
        }

        /// `GenerateKeyPair()` (Go `KEM.GenerateKey`).
        pub fn generateKeyPair(out: *KeyPair, kem: KemId, io: std.Io) SuiteError!void {
            inline for (opts.kems) |k| if (kem == k) {
                out.* = @unionInit(KeyPair, @tagName(k), undefined);
                KemOf(k).generateKeyPair(&@field(out.*, @tagName(k)), io);
                return;
            };
            return error.UnsupportedSuite;
        }

        /// `DeriveKeyPair(ikm)` (Go `KEM.DeriveKeyPair`).
        // secret-api-ok: a dispatch to the static KEM's deriveKeyPair, which burns (DHKEM: kem_burn; ML-KEM/hybrid: fromSeed's burn covers deriveSeed's sibling frames, needle probe in stackprobe2_test.zig).
        pub fn deriveKeyPair(out: *KeyPair, kem: KemId, ikm: []const u8) SuiteError!void {
            inline for (opts.kems) |k| if (kem == k) {
                out.* = @unionInit(KeyPair, @tagName(k), undefined);
                KemOf(k).deriveKeyPair(&@field(out.*, @tagName(k)), ikm);
                return;
            };
            return error.UnsupportedSuite;
        }

        /// `DeserializePrivateKey` (Go `KEM.NewPrivateKey`): the DHKEM scalar
        /// (`keyPairFromSecret`, `DeserializeError` outside `[1, n-1]`) or the
        /// ML-KEM / hybrid seed (`fromSeed`). A length other than the KEM's
        /// `Nsk` is `InvalidLength`. `out` is zeroed on error.
        pub fn keyPairFromSecret(out: *KeyPair, kem: KemId, sk: []const u8) KeyError!void {
            inline for (opts.kems) |k| if (kem == k) {
                const K = KemOf(k);
                if (sk.len != K.Nsk) return error.InvalidLength;
                out.* = @unionInit(KeyPair, @tagName(k), undefined);
                const p = &@field(out.*, @tagName(k));
                if (comptime isPq(K)) {
                    K.fromSeed(p, sk[0..K.Nsk]);
                } else K.keyPairFromSecret(p, sk[0..K.Nsk]) catch |e| {
                    std.crypto.secureZero(u8, std.mem.asBytes(out));
                    return e;
                };
                return;
            };
            return error.UnsupportedSuite;
        }

        const MsgTag = std.meta.Tag(Msg);

        /// RFC 9180 §5.2/§5.3 encryption context of a run-time suite (Go
        /// `Sender`/`Recipient`). Holds the AEAD key and the exporter
        /// secret: wipe it when done.
        pub const Context = struct {
            suite: Suite,
            msg: Msg,
            exporter_secret: [max_nh]u8,

            /// RFC 9180 §5.2 `Context.Seal`: `out.len == pt.len +
            /// suite.tagLength()`.
            // secret-api-ok: a dispatch to the static Context.seal, which runs under msg_burn.
            pub fn seal(self: *Context, aad: []const u8, pt: []const u8, out: []u8) SealError!void {
                inline for (opts.aeads) |a| if (a != .export_only and std.meta.activeTag(self.msg) == @field(MsgTag, @tagName(a)))
                    return @field(self.msg, @tagName(a)).seal(aad, pt, out);
                return error.ExportOnly;
            }

            /// RFC 9180 §5.2 `Context.Open`: `out.len == ct.len -
            /// suite.tagLength()`.
            // secret-api-ok: a dispatch to the static Context.open, which runs under msg_burn.
            pub fn open(self: *Context, aad: []const u8, ct: []const u8, out: []u8) OpenError!void {
                inline for (opts.aeads) |a| if (a != .export_only and std.meta.activeTag(self.msg) == @field(MsgTag, @tagName(a)))
                    return @field(self.msg, @tagName(a)).open(aad, ct, out);
                return error.ExportOnly;
            }

            /// The sequence number of the next `seal`/`open` (0 for
            /// export-only).
            pub fn seq(self: *const Context) u64 {
                return switch (self.msg) {
                    .export_only => 0,
                    inline else => |*c| c.seq,
                };
            }

            /// RFC 9180 §5.3 `Context.Export(exporter_context, L)`, `L =
            /// out.len`.
            pub fn exportSecret(self: *const Context, exporter_context: []const u8, out: []u8) suite.LabeledExpandError!void {
                const sid = self.suite.id();
                inline for (opts.kdfs) |k| if (self.suite.kdf == k) {
                    const Kdf = KdfOf(k);
                    var c: schedule.Context(schedule.ExportOnly, Kdf) = .{ .key = .{}, .base_nonce = .{}, .exporter_secret = self.exporter_secret[0..Kdf.Nh].* };
                    defer std.crypto.secureZero(u8, std.mem.asBytes(&c));
                    return c.exportSecret(&sid, exporter_context, out);
                };
                unreachable; // a Context exists only for a supported suite
            }
        };

        /// `setupS`'s result: `enc` (first `enc_len` bytes) and the sender's
        /// `Context`.
        pub const Setup = struct {
            enc: [max_enc_len]u8,
            enc_len: usize,
            context: Context,

            pub fn encSlice(self: *const Setup) []const u8 {
                return self.enc[0..self.enc_len];
            }
        };

        /// `KeySchedule` for the suite's (KDF, AEAD) into `out`.
        fn keyScheduleInto(
            out: *Context,
            s: Suite,
            mode: Mode,
            shared_secret: []const u8,
            info: []const u8,
            psk: []const u8,
            psk_id: []const u8,
        ) (schedule.KeyScheduleError || suite.LabeledExpandError)!void {
            const sid = s.id();
            inline for (opts.kdfs) |k| if (s.kdf == k) {
                inline for (opts.aeads) |a| if (s.aead == a) {
                    const Kdf = KdfOf(k);
                    const Aead = AeadOf(a);
                    var tmp: schedule.Context(Aead, Kdf) = undefined;
                    defer std.crypto.secureZero(u8, std.mem.asBytes(&tmp));
                    try schedule.keySchedule(Aead, Kdf, &tmp, mode, &sid, shared_secret, info, psk, psk_id);
                    out.suite = s;
                    out.exporter_secret = @splat(0);
                    out.exporter_secret[0..Kdf.Nh].* = tmp.exporter_secret;
                    if (Aead == schedule.ExportOnly) {
                        out.msg = .export_only;
                    } else {
                        out.msg = @unionInit(Msg, @tagName(a), undefined);
                        @field(out.msg, @tagName(a)) = .{ .key = tmp.key, .base_nonce = tmp.base_nonce, .exporter_secret = @splat(0) };
                    }
                    return;
                };
            };
            unreachable; // checked by `supports` first
        }

        fn setupSBody(
            out: *Setup,
            s: *const Suite,
            mode: Mode,
            pkR: *const PublicKey,
            skS: ?*const KeyPair,
            eph_src: *const EphSource,
            info: []const u8,
            psk: []const u8,
            psk_id: []const u8,
        ) SetupSError!void {
            errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
            if (!supports(s.*)) return error.UnsupportedSuite;
            if (pkR.kem != s.kem) return error.KemMismatch;
            if (skS) |k| if (k.kemId() != s.kem) return error.KemMismatch;
            var ss: [max_nsecret]u8 = undefined;
            defer std.crypto.secureZero(u8, &ss);
            var ss_len: usize = 0;
            inline for (opts.kems) |kid| if (s.kem == kid) {
                const K = KemOf(kid);
                try checkMode(K, mode, skS != null);
                var eph: schedule.Ephemeral(K) = undefined;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&eph));
                switch (eph_src.*) {
                    .io => |io| if (comptime isPq(K)) K.generateEphemeral(&eph, io) else K.generateKeyPair(&eph, io),
                    .ikm => |ikm| if (comptime isPq(K)) {
                        if (ikm.len != @sizeOf(K.Ephemeral)) return error.InvalidLength;
                        @memcpy(std.mem.asBytes(&eph), ikm);
                    } else K.deriveKeyPair(&eph, ikm),
                }
                var e: K.Encapped = undefined;
                defer std.crypto.secureZero(u8, std.mem.asBytes(&e));
                if (comptime isPq(K)) {
                    try K.encapDeterministic(&e, pkR.typed(K), &eph);
                } else if (skS) |k| {
                    try K.authEncapDeterministic(&e, pkR.typed(K), &@field(k.*, @tagName(kid)), &eph);
                } else try K.encapDeterministic(&e, pkR.typed(K), &eph);
                out.enc_len = e.enc.len;
                @memcpy(out.enc[0..e.enc.len], &e.enc);
                ss[0..K.Nsecret].* = e.shared_secret;
                ss_len = K.Nsecret;
            };
            try keyScheduleInto(&out.context, s.*, mode, ss[0..ss_len], info, psk, psk_id);
        }

        fn setupRBody(
            out: *Context,
            s: *const Suite,
            mode: Mode,
            enc: []const u8,
            skR: *const KeyPair,
            pkS: ?*const PublicKey,
            info: []const u8,
            psk: []const u8,
            psk_id: []const u8,
        ) SetupRError!void {
            errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
            if (!supports(s.*)) return error.UnsupportedSuite;
            if (skR.kemId() != s.kem) return error.KemMismatch;
            if (pkS) |k| if (k.kem != s.kem) return error.KemMismatch;
            var ss: [max_nsecret]u8 = undefined;
            defer std.crypto.secureZero(u8, &ss);
            var ss_len: usize = 0;
            inline for (opts.kems) |kid| if (s.kem == kid) {
                const K = KemOf(kid);
                try checkMode(K, mode, pkS != null);
                const n = @sizeOf(K.EncappedKey);
                if (enc.len != n) return error.InvalidLength;
                const sk = &@field(skR.*, @tagName(kid));
                if (comptime isPq(K)) {
                    try K.decap(ss[0..K.Nsecret], enc[0..n].*, sk);
                } else if (pkS) |k| {
                    try K.authDecap(ss[0..K.Nsecret], enc[0..n].*, sk, k.typed(K));
                } else try K.decap(ss[0..K.Nsecret], enc[0..n].*, sk);
                ss_len = K.Nsecret;
            };
            try keyScheduleInto(out, s.*, mode, ss[0..ss_len], info, psk, psk_id);
        }

        /// RFC 9180 §5.1 `Setup<Mode>S` for a run-time suite (Go
        /// `NewSender` for base mode). `skS` is the sender's key pair for
        /// `auth`/`auth_psk` and `null` otherwise; `psk`/`psk_id` are empty
        /// unless the mode takes them. `out` is zeroed on error.
        pub fn setupS(
            out: *Setup,
            s: Suite,
            mode: Mode,
            pkR: *const PublicKey,
            skS: ?*const KeyPair,
            io: std.Io,
            info: []const u8,
            psk: []const u8,
            psk_id: []const u8,
        ) SetupSError!void {
            const src: EphSource = .{ .io = io };
            return burn.run(burn.kem_burn, SetupSError!void, setupSBody, .{ out, &s, mode, pkR, skS, &src, info, psk, psk_id });
        }

        /// `setupS` with the ephemeral from `ikmE` (a DHKEM's
        /// `DeriveKeyPair(ikmE)`, a pq KEM's encapsulation randomness, which
        /// must be `Ephemeral`-long) — the test-vector seam, as
        /// `schedule.setupBaseSDeterministic`. Reusing `ikmE` voids HPKE's
        /// security.
        pub fn setupSDeterministic(
            out: *Setup,
            s: Suite,
            mode: Mode,
            pkR: *const PublicKey,
            skS: ?*const KeyPair,
            ikmE: []const u8,
            info: []const u8,
            psk: []const u8,
            psk_id: []const u8,
        ) SetupSError!void {
            const src: EphSource = .{ .ikm = ikmE };
            return burn.run(burn.kem_burn, SetupSError!void, setupSBody, .{ out, &s, mode, pkR, skS, &src, info, psk, psk_id });
        }

        /// RFC 9180 §5.1 `Setup<Mode>R` for a run-time suite (Go
        /// `NewRecipient`). `pkS` is the sender's public key for
        /// `auth`/`auth_psk`, else `null`. `out` is zeroed on error.
        pub fn setupR(
            out: *Context,
            s: Suite,
            mode: Mode,
            enc: []const u8,
            skR: *const KeyPair,
            pkS: ?*const PublicKey,
            info: []const u8,
            psk: []const u8,
            psk_id: []const u8,
        ) SetupRError!void {
            return burn.run(burn.kem_burn, SetupRError!void, setupRBody, .{ out, &s, mode, enc, skR, pkS, info, psk, psk_id });
        }

        /// RFC 9180 §6.1 single-shot base-mode `Seal` (Go `hpke.Seal`, which
        /// also returns `enc ‖ ct`): writes `enc ‖ ct` into `out`, `out.len ==
        /// s.encLength() + pt.len + s.tagLength()`.
        pub fn sealBase(s: Suite, pkR: *const PublicKey, io: std.Io, info: []const u8, aad: []const u8, pt: []const u8, out: []u8) SealOnceError!void {
            const n = s.encLength();
            if (out.len < n) return error.InvalidLength;
            var st: Setup = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&st));
            try setupS(&st, s, .base, pkR, null, io, info, "", "");
            try st.context.seal(aad, pt, out[n..]);
            @memcpy(out[0..n], st.encSlice());
        }

        /// The mirror of `sealBase` (Go `hpke.Open`): `sealed = enc ‖ ct`,
        /// `out.len == sealed.len - s.encLength() - s.tagLength()`.
        pub fn openBase(s: Suite, skR: *const KeyPair, info: []const u8, aad: []const u8, sealed: []const u8, out: []u8) OpenOnceError!void {
            const n = s.encLength();
            if (sealed.len < n) return error.InvalidLength;
            var c: Context = undefined;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&c));
            try setupR(&c, s, .base, sealed[0..n], skR, null, info, "", "");
            try c.open(aad, sealed[n..], out);
        }
    };
}
