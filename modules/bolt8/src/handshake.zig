// SPDX-License-Identifier: MIT

//! The `Noise_XK` handshake DRIVER: `Initiator`/`Responder` state machines
//! that walk BOLT#8's three acts (`act.zig` supplies the wire framing this
//! drives; `dh.zig` supplies the secp256k1 ECDH primitive).
//!
//! **Noise-reuse decision (see ../SPEC.md for the full investigation):**
//! this module is built on `noise.Suite(dh, ChaChaPoly, SHA256)
//! .SymmetricState` (mixKey/mixHash/encryptAndHash/decryptAndHash/split) —
//! NOT on `noise.HandshakeState`. `noise`'s `HandshakeState.initialize`
//! derives the Noise protocol-name string via a `dhName(DH)` lookup
//! (`noise/src/state.zig`) that only recognizes `std.crypto.dh.X25519` and
//! `@compileError`s for any other `DH` type — so instantiating
//! `HandshakeState` with this module's secp256k1 `dh` adapter would fail to
//! compile the moment `.initialize` is called (it never is, here).
//! `SymmetricState`, by contrast, never references the `DH` type at all —
//! it operates purely on opaque `[]const u8` key material — so it is fully
//! reusable, DH-agnostic infrastructure. XK is not in `noise/src/
//! patterns.zig` (only NN/NK/XX/IK) — moot for this module either way,
//! since we never reach the code path that would consult a
//! `HandshakePattern`.
//!
//! `init()` below (BOLT#8 "Handshake State Initialization") is REAL: it is
//! pure protocol-name-hash + prologue + pre-message mixHash, structurally
//! identical to what `noise.HandshakeState.initialize` already does for
//! real (proven by the `noise` module's own KATs) — no new crypto decision
//! is made here, just `SymmetricState.initializeSymmetric`/`.mixHash`
//! calls.
//!
//! Every act step past `init` (`genAct1`/`readAct2`/`genAct3` on
//! `Initiator`; `readAct1`/`genAct2`/`readAct3` on `Responder`) is a
//! crypto core: each performs one ECDH (via `dh.dh`) mixed into the
//! running key via `SymmetricState.mixKey`, then one
//! `encryptAndHash`/`decryptAndHash` — per its own doc comment's exact
//! BOLT#8 step list. All six are IMPLEMENTED and KAT-verified byte-exact
//! against BOLT#8 Appendix A (`kat_test.zig`: the full act1->act2->act3
//! walk, all five crypto-level negative vectors, and a post-handshake
//! transport round-trip).

const std = @import("std");
const builtin = @import("builtin");
const noise = @import("noise");
const dh = @import("dh.zig");
const act = @import("act.zig");

/// `noise.Suite` bound to this module's secp256k1 DH adapter. `dh.zig`
/// itself supplies the `public_length`/`KeyPair`/`scalarmult` decls
/// `Suite(DH,...)` expects off its `DH` type parameter — see that file's
/// "noise.Suite(DH, ...) adapter surface" section.
/// The AEAD is `noise.ChaCha20Poly1305` — the `chachapoly` sibling, reached
/// through `noise`'s re-export so this module needs no `chachapoly` dep of
/// its own. It is byte-exact to `std.crypto.aead.chacha_poly.
/// ChaCha20Poly1305`, and `kat_test.zig` runs the BOLT#8 Appendix A vectors
/// under both to keep that claim honest here rather than by reference.
pub const Suite = noise.Suite(
    dh,
    noise.ChaCha20Poly1305,
    std.crypto.hash.sha2.Sha256,
);

/// The same suite bound to `std`'s ChaCha20-Poly1305 instead. Not used on any
/// production path — it exists so `kat_test.zig` can drive the published
/// BOLT#8 vectors through the OTHER AEAD implementation and assert the two
/// produce identical wire bytes (the differential that proves the swap inert).
pub const StdAeadSuite = noise.Suite(
    dh,
    std.crypto.aead.chacha_poly.ChaCha20Poly1305,
    std.crypto.hash.sha2.Sha256,
);

/// BOLT#8 "Noise Protocol Instantiation": "The official protocol name for
/// the Lightning variant of Noise is `Noise_XK_secp256k1_ChaChaPoly_
/// SHA256`."
pub const protocol_name = "Noise_XK_secp256k1_ChaChaPoly_SHA256";
/// BOLT#8 "Handshake State Initialization" step 3: the ASCII string
/// `"lightning"`.
pub const prologue = "lightning";

pub const HandshakeError = act.ParseError || dh.DhError || error{
    /// An AEAD tag failed to verify — BOLT#8: "the connection is to be
    /// immediately terminated" (no further messages sent).
    DecryptionFailed,
    NonceExhausted,
    BufferTooSmall,
    /// An act was driven out of order on this handshake object — the second
    /// `genAct1` on one `Initiator`, a `readAct2` before Act One was sent,
    /// and so on. Noise_XK is a strictly linear three-act exchange and each
    /// ephemeral share belongs to exactly one run; re-entering an act would
    /// otherwise silently reuse the previous ephemeral (see `Ephemeral`).
    /// Start a fresh `Initiator`/`Responder` for a retry.
    WrongState,
};

/// Where an act's ephemeral keypair comes from.
///
/// **Why this is a type and not a `std.Random` parameter.** BOLT#8 Act One's
/// `e` is the initiator's ONLY per-session secret input: `es = ECDH(e.priv,
/// rs)` and the Act-One wire bytes are pure functions of it. `std.Random` is a
/// vtable — `DefaultPrng.init(0).random()` and a real CSPRNG are
/// indistinguishable at the call site — so a bare `random: std.Random`
/// parameter offers no way to *ask for* the weak path, and no way to see that
/// it was taken. A named arm is the asking.
///
/// This mirrors `dtls`'s `Connection.Entropy` (same two arms, same private
/// `source()` accessor). Like that module, this one is a sans-I/O state
/// machine — no socket, no clock, no allocator — so the `io: std.Io` arm the
/// `coconut`/`bbs` siblings use is deliberately absent: `std.Io` is the
/// authority to open sockets and files, which is precisely what a protocol
/// engine should not hold. A tagged union is a VALUE and costs that invariant
/// nothing.
pub const Ephemeral = union(enum) {
    /// PRODUCTION. A generator the caller asserts is cryptographically
    /// secure — `std.Random.DefaultCsprng` seeded from `getrandom(2)`, or an
    /// equivalent. std 0.16 removed `std.crypto.random`, so this module has
    /// no hidden RNG of its own and cannot verify the assertion: naming this
    /// arm IS the assertion.
    csprng: std.Random,

    /// **TEST ONLY.** A caller-seeded generator, so a handshake can be
    /// replayed byte-for-byte.
    ///
    /// What choosing this in production costs, concretely: the bytes drawn
    /// from it ARE the secp256k1 ephemeral private key. Every Act One this
    /// node sends then carries the same `e_pub`, so every connection it opens
    /// is trivially linkable and byte-identical on the wire; `es = ECDH(e,
    /// rs)` becomes a constant, so anyone who recovers the seed recovers `es`
    /// for every past and future session to that peer. Initiator-side forward
    /// secrecy is gone.
    seeded_for_test: std.Random,

    /// The arm-erased generator, for the two act steps that actually draw.
    /// Deliberately NOT `pub`: the point of the type is that the choice is
    /// visible at the call site, and a public accessor would hand callers
    /// back the flat `std.Random` this replaced.
    fn source(self: Ephemeral) std.Random {
        return switch (self) {
            .csprng => |r| r,
            .seeded_for_test => |r| r,
        };
    }
};

/// The compile-time guard on the two `…WithEphemeral` KAT entry points.
/// BOLT#8 Appendix A fixes `e.priv` on both sides ("note: this is a violation
/// of the spec, which requires randomness"), so the vectors are unreachable
/// without a hook that pins the ephemeral exactly — and there is no legitimate
/// production use for one: Noise_XK has no session resumption and no
/// pre-agreed share, every run draws a fresh `e`. So the hook exists, and it
/// does not exist outside a test build.
fn assertTestOnly(comptime who: []const u8) void {
    comptime if (!builtin.is_test) @compileError(
        "bolt8: " ++ who ++ " pins the act's ephemeral keypair and is reachable only from a test " ++
            "build (BOLT#8 Appendix A's fixed-`e.priv` vectors). Production must call " ++
            "genAct1/genAct2 with an `Ephemeral` — `.csprng` draws a fresh share, which is the " ++
            "only shape Noise_XK's forward secrecy is defined for.",
    );
}

/// The result of a completed Act Three: the transport send/receive keys
/// (`sk`/`rk` in the spec) plus the value that becomes BOTH `sck` AND
/// `rck` (spec Act Three: "8. `rck = sck = ck`") for `transport.zig`'s
/// key-rotation ratchet, and the final handshake hash (channel-binding
/// value; not otherwise consumed by this module).
pub const HandshakeResult = struct {
    sk: [32]u8,
    rk: [32]u8,
    ck: [32]u8,
    handshake_hash: [32]u8,
};

/// The initiator's side of `Noise_XK(s, rs)`. BOLT#8 requires the
/// initiator to know the responder's static public key `rs` in advance
/// (the whole point of `XK`: the responder's key is never sent over the
/// wire during the handshake).
pub const Initiator = struct {
    ls: dh.KeyPair,
    rs_pub: [33]u8,
    /// **OUTPUT of `genAct1`, never an input.** `genAct1` derives the
    /// ephemeral from its `Ephemeral` argument and overwrites this field, so
    /// assigning to it beforehand has no effect — Zig has no field privacy,
    /// but there is no read of this field that a caller can steer. It is kept
    /// because `readAct2` needs `e.priv` for `ee`, and readable because the
    /// KAT asserts on it. (It was named `e` and WAS an input until the B6 RNG
    /// seam audit: `self.e orelse dh.KeyPair.generate(random)` made the
    /// generator argument silently dead for anyone who set the field.)
    ephemeral: ?dh.KeyPair = null,
    ss: Suite.SymmetricState = .{},
    /// The responder's ephemeral public key, learned from Act Two.
    re_pub: ?[33]u8 = null,
    /// Act ordering. Noise_XK is strictly linear and the Act-One ephemeral
    /// belongs to exactly one run, so re-entering an act is `error.WrongState`
    /// rather than a silent share reuse.
    state: State = .start,

    pub const State = enum { start, awaiting_act2, ready_act3, done };

    /// BOLT#8 "Handshake State Initialization" — REAL, no DH/AEAD:
    ///
    /// 1. `h = SHA256(protocolName)`, `ck = h`
    ///    (`SymmetricState.initializeSymmetric(protocol_name)`).
    /// 2. `h = SHA256(h || prologue)` (`.mixHash(prologue)`).
    /// 3. The initiator mixes in the RESPONDER's known static public key:
    ///    `h = SHA256(h || rs.pub.serializeCompressed())`
    ///    (`.mixHash(&rs_pub)`).
    pub fn init(ls: dh.KeyPair, rs_pub: [33]u8) Initiator {
        var self = Initiator{ .ls = ls, .rs_pub = rs_pub };
        self.ss.initializeSymmetric(protocol_name);
        self.ss.mixHash(prologue);
        self.ss.mixHash(&rs_pub);
        return self;
    }

    /// BOLT#8 Act One, **Sender Actions** (`-> e, es`):
    ///
    /// 1. `e = generateKey()` — ALWAYS a fresh draw from `ephemeral`'s
    ///    generator (`Ephemeral.csprng` in production). The KAT hook is the
    ///    separate, test-build-only `genAct1WithEphemeral`.
    /// 2. `h = SHA256(h || e.pub)` (`ss.mixHash(&e.public_key)`).
    /// 3. `es = ECDH(e.priv, rs)` (`dh.dh(e.secret_key, self.rs_pub)`).
    /// 4. `ck, temp_k1 = HKDF(ck, es)` (`ss.mixKey(&es)` — re-seeds the
    ///    embedded `CipherState` with `temp_k1` and resets its nonce to 0).
    /// 5. `c = encryptWithAD(temp_k1, 0, h, <empty>)`
    ///    (`ss.encryptAndHash(&.{}, &tag_out)` — the embedded
    ///    `CipherState`'s nonce is 0 here since `mixKey` just reset it).
    /// 6. `h = SHA256(h || c)` — done automatically inside
    ///    `encryptAndHash`'s own trailing `mixHash(out)` call.
    /// 7. Return `act.Act1{ .e_pub = e.pub, .tag = c }` for the caller to
    ///    send as `0 || e.pub || c` (`Act1.toBytes`).
    pub fn genAct1(self: *Initiator, ephemeral: Ephemeral) HandshakeError!act.Act1 {
        return self.act1(dh.KeyPair.generate(ephemeral.source()));
    }

    /// **TEST ONLY** (`@compileError` outside a test build — see
    /// `assertTestOnly`): run Act One over exactly `e` instead of a drawn
    /// share, which is how BOLT#8 Appendix A's fixed-`e.priv` vectors are
    /// reproduced byte-exact.
    pub fn genAct1WithEphemeral(self: *Initiator, e: dh.KeyPair) HandshakeError!act.Act1 {
        assertTestOnly("Initiator.genAct1WithEphemeral");
        return self.act1(e);
    }

    fn act1(self: *Initiator, e: dh.KeyPair) HandshakeError!act.Act1 {
        if (self.state != .start) return error.WrongState;
        self.ephemeral = e;
        self.ss.mixHash(&e.public_key);
        const es = try dh.dh(e.secret_key, self.rs_pub);
        self.ss.mixKey(&es);
        var tag: [16]u8 = undefined;
        try self.ss.encryptAndHash("", &tag);
        self.state = .awaiting_act2;
        return .{ .e_pub = e.public_key, .tag = tag };
    }

    /// BOLT#8 Act Two, **Receiver Actions** (`<- e, ee`):
    ///
    /// 1. Parse `msg` (already done by the caller via `act.Act2.fromBytes`
    ///    — version/length checks live there, not here).
    /// 2. `h = SHA256(h || re)` (`ss.mixHash(&msg.e_pub)`); store
    ///    `self.re_pub = msg.e_pub`.
    /// 3. `ee = ECDH(e.priv, re)` (`dh.dh(self.e.?.secret_key,
    ///    msg.e_pub)`, using the ephemeral `genAct1` generated).
    /// 4. `ck, temp_k2 = HKDF(ck, ee)` (`ss.mixKey(&ee)`).
    /// 5. `p = decryptWithAD(temp_k2, 0, h, c)`
    ///    (`ss.decryptAndHash(&msg.tag, &.{})` — zero-length plaintext, so
    ///    `out` is empty; a tag mismatch surfaces as
    ///    `error.DecryptionFailed` and the spec requires terminating the
    ///    connection with no further messages).
    /// 6. `h = SHA256(h || c)` — automatic, inside `decryptAndHash`.
    pub fn readAct2(self: *Initiator, msg: act.Act2) HandshakeError!void {
        if (self.state != .awaiting_act2) return error.WrongState;
        self.ss.mixHash(&msg.e_pub);
        const ee = try dh.dh(self.ephemeral.?.secret_key, msg.e_pub);
        self.ss.mixKey(&ee);
        var empty: [0]u8 = undefined;
        try self.ss.decryptAndHash(&msg.tag, &empty);
        self.re_pub = msg.e_pub;
        self.state = .ready_act3;
    }

    /// BOLT#8 Act Three, **Sender Actions** (`-> s, se`) — also derives
    /// the transport keys (steps 6-8 fold into this, since nothing further
    /// happens after Act Three):
    ///
    /// 1. `c = encryptWithAD(temp_k2, 1, h, ls.pub)`
    ///    (`ss.encryptAndHash(&self.ls.public_key, &c_out)` — note the
    ///    nonce is 1, NOT 0: `ss`'s embedded `CipherState` is STILL keyed
    ///    with `temp_k2` from `readAct2` step 4 and has already encrypted
    ///    one message at nonce 0 there — continuing to use the SAME
    ///    `SymmetricState` instance across acts makes this fall out for
    ///    free via its auto-incrementing nonce counter; do NOT
    ///    re-`mixKey`/re-initialize between Act Two and this step, or the
    ///    nonce silently resets to 0 and every downstream ciphertext byte
    ///    changes).
    /// 2. `h = SHA256(h || c)` — automatic.
    /// 3. `se = ECDH(ls.priv, re)` (`dh.dh(self.ls.secret_key,
    ///    self.re_pub.?)`).
    /// 4. `ck, temp_k3 = HKDF(ck, se)` (`ss.mixKey(&se)` — resets the
    ///    nonce to 0 again, ready for step 5).
    /// 5. `t = encryptWithAD(temp_k3, 0, h, <empty>)`
    ///    (`ss.encryptAndHash(&.{}, &t_out)`).
    /// 6. `sk, rk = HKDF(ck, <empty>)`: this is `SymmetricState.split()`
    ///    — NOT `mixKeyAndHash` (there is no further `h` mixing here) —
    ///    called with a zero-length `ikm` implicitly (`split()` takes
    ///    none). Crucially, `split()` (see `noise/src/state.zig`) reads
    ///    `self.ck` but does NOT overwrite it, so `ss.ck` immediately
    ///    after this call IS exactly the spec's post-split `ck` — feed it
    ///    into `HandshakeResult.ck` for step 8 below with no extra work.
    /// 7. `rn = sn = 0` — true by construction: `split()`'s two
    ///    `CipherState`s both start at `n = 0`.
    /// 8. `rck = sck = ck` — `HandshakeResult.ck = ss.ck` (see step 6).
    pub fn genAct3(self: *Initiator) HandshakeError!struct { msg: act.Act3, result: HandshakeResult } {
        if (self.state != .ready_act3) return error.WrongState;
        // Step 1: encrypt the local static key at nonce 1 — `ss` is STILL
        // keyed with temp_k2 from readAct2 (no mixKey between the acts;
        // see the doc comment's nonce-continuity warning).
        var c: [49]u8 = undefined;
        try self.ss.encryptAndHash(&self.ls.public_key, &c);
        const se = try dh.dh(self.ls.secret_key, self.re_pub.?);
        self.ss.mixKey(&se);
        var t: [16]u8 = undefined;
        try self.ss.encryptAndHash("", &t);
        // split() = HKDF(ck, zerolen): pair[0] is initiator->responder,
        // pair[1] the reverse — for THIS (initiator) side, sk = pair[0].
        // split() does not mutate ss.ck, so ss.ck here IS the spec's
        // `rck = sck = ck` value (doc comment steps 6-8).
        const pair = self.ss.split();
        self.state = .done;
        return .{
            .msg = .{ .c = c, .t = t },
            .result = .{
                .sk = pair[0].k,
                .rk = pair[1].k,
                .ck = self.ss.ck,
                .handshake_hash = self.ss.getHandshakeHash(),
            },
        };
    }
};

/// The responder's side of `Noise_XK(s, rs)`.
pub const Responder = struct {
    ls: dh.KeyPair,
    /// **OUTPUT of `genAct2`, never an input** — see `Initiator.ephemeral`
    /// for the full note (this field was `e` and was an input until the B6
    /// RNG seam audit).
    ephemeral: ?dh.KeyPair = null,
    ss: Suite.SymmetricState = .{},
    /// The initiator's ephemeral public key, learned from Act One.
    re_pub: ?[33]u8 = null,
    /// The initiator's static public key, recovered from Act Three.
    rs_pub: ?[33]u8 = null,
    /// Act ordering — see `Initiator.state`.
    state: State = .start,

    pub const State = enum { start, ready_act2, awaiting_act3, done };

    /// BOLT#8 "Handshake State Initialization" — REAL, mirrors
    /// `Initiator.init` exactly except the final mixHash: the responder
    /// mixes in ITS OWN static public key (spec: "The responding node
    /// mixes in their local static public key... `h = SHA256(h ||
    /// ls.pub.serializeCompressed())`") rather than a remote one — both
    /// sides end up mixing in the SAME bytes (the responder's static
    /// key), just from their own local/remote perspective.
    pub fn init(ls: dh.KeyPair) Responder {
        var self = Responder{ .ls = ls };
        self.ss.initializeSymmetric(protocol_name);
        self.ss.mixHash(prologue);
        self.ss.mixHash(&ls.public_key);
        return self;
    }

    /// BOLT#8 Act One, **Receiver Actions**:
    ///
    /// 1-2. Parse `msg` (done by the caller via `act.Act1.fromBytes`).
    /// 3. `h = SHA256(h || re)` (`ss.mixHash(&msg.e_pub)`); store
    ///    `self.re_pub = msg.e_pub`.
    /// 4. `es = ECDH(s.priv, re)` (`dh.dh(self.ls.secret_key,
    ///    msg.e_pub)` — the RESPONDER's static key this time, not an
    ///    ephemeral; this is the asymmetry `es` always denotes in Noise
    ///    notation, "ephemeral times static", with the ephemeral supplied
    ///    by whichever side sent it).
    /// 5. `ck, temp_k1 = HKDF(ck, es)` (`ss.mixKey(&es)`).
    /// 6. `p = decryptWithAD(temp_k1, 0, h, c)`
    ///    (`ss.decryptAndHash(&msg.tag, &.{})` — a tag failure here means
    ///    "the initiator does _not_ know the responder's static public
    ///    key"; spec: MUST terminate with no further messages).
    /// 7. `h = SHA256(h || c)` — automatic.
    pub fn readAct1(self: *Responder, msg: act.Act1) HandshakeError!void {
        if (self.state != .start) return error.WrongState;
        self.ss.mixHash(&msg.e_pub);
        const es = try dh.dh(self.ls.secret_key, msg.e_pub);
        self.ss.mixKey(&es);
        var empty: [0]u8 = undefined;
        try self.ss.decryptAndHash(&msg.tag, &empty);
        self.re_pub = msg.e_pub;
        self.state = .ready_act2;
    }

    /// BOLT#8 Act Two, **Sender Actions**:
    ///
    /// 1. `e = generateKey()` — ALWAYS a fresh draw from `ephemeral`'s
    ///    generator; store into `self.ephemeral` (Act Three's receiver step
    ///    needs it for `se`). The KAT hook is the separate, test-build-only
    ///    `genAct2WithEphemeral`.
    /// 2. `h = SHA256(h || e.pub)` (`ss.mixHash(&e.public_key)`).
    /// 3. `ee = ECDH(e.priv, re)` (`dh.dh(e.secret_key,
    ///    self.re_pub.?)` — `re` here is the INITIATOR's ephemeral from
    ///    Act One).
    /// 4. `ck, temp_k2 = HKDF(ck, ee)` (`ss.mixKey(&ee)`).
    /// 5. `c = encryptWithAD(temp_k2, 0, h, <empty>)`
    ///    (`ss.encryptAndHash(&.{}, &c_out)`).
    /// 6. `h = SHA256(h || c)` — automatic.
    pub fn genAct2(self: *Responder, ephemeral: Ephemeral) HandshakeError!act.Act2 {
        return self.act2(dh.KeyPair.generate(ephemeral.source()));
    }

    /// **TEST ONLY** (`@compileError` outside a test build — see
    /// `assertTestOnly`): the Appendix A responder-side KAT hook, mirroring
    /// `Initiator.genAct1WithEphemeral`.
    pub fn genAct2WithEphemeral(self: *Responder, e: dh.KeyPair) HandshakeError!act.Act2 {
        assertTestOnly("Responder.genAct2WithEphemeral");
        return self.act2(e);
    }

    fn act2(self: *Responder, e: dh.KeyPair) HandshakeError!act.Act2 {
        if (self.state != .ready_act2) return error.WrongState;
        self.ephemeral = e;
        self.ss.mixHash(&e.public_key);
        const ee = try dh.dh(e.secret_key, self.re_pub.?);
        self.ss.mixKey(&ee);
        var tag: [16]u8 = undefined;
        try self.ss.encryptAndHash("", &tag);
        self.state = .awaiting_act3;
        return .{ .e_pub = e.public_key, .tag = tag };
    }

    /// BOLT#8 Act Three, **Receiver Actions** — also derives the
    /// transport keys (mirrors `Initiator.genAct3`'s steps 6-8, with
    /// `rk`/`sk` swapped since this is the other side of the same
    /// channel):
    ///
    /// 1-2. Parse `msg` (done by the caller via `act.Act3.fromBytes`).
    /// 3. `rs = decryptWithAD(temp_k2, 1, h, c)`
    ///    (`ss.decryptAndHash(&msg.c, &rs_out)` — SAME nonce-continuity
    ///    note as `Initiator.genAct3` step 1 applies here in reverse: `ss`
    ///    is still keyed with `temp_k2` from `genAct2` step 4/5, and this
    ///    is its SECOND use, landing at nonce 1 automatically). Store the
    ///    recovered 33-byte key into `self.rs_pub` — but see `dh.zig`'s
    ///    "act3 bad rs test" note: a successfully-decrypted `rs` can still
    ///    fail to parse as a valid SEC1 point (`error.InvalidPublicKey`
    ///    from a later `dh.dh` call, or an explicit `Secp256k1.fromSec1`
    ///    check here) — that failure must also abort the connection.
    /// 4. `h = SHA256(h || c)` — automatic.
    /// 5. `se = ECDH(e.priv, rs)` (`dh.dh(self.e.?.secret_key,
    ///    self.rs_pub.?)` — the RESPONDER's ephemeral this time, mirroring
    ///    the initiator's `se = ECDH(s.priv, re)`: same DH pair, computed
    ///    from the other side).
    /// 6. `ck, temp_k3 = HKDF(ck, se)` (`ss.mixKey(&se)`).
    /// 7. `p = decryptWithAD(temp_k3, 0, h, t)`
    ///    (`ss.decryptAndHash(&msg.t, &.{})`).
    /// 8. `rk, sk = HKDF(ck, <empty>)` — `ss.split()`; NOTE the
    ///    responder's naming is swapped from the initiator's (`rk` first,
    ///    then `sk` — spec Act Three receiver step 9) but `split()`
    ///    itself returns `[2]CipherState` as `{initiator->responder,
    ///    responder->initiator}` regardless of which side calls it, so
    ///    THIS side's `HandshakeResult.rk`/`.sk` must be assigned from
    ///    `pair[0]`/`pair[1]` in the OPPOSITE order `Initiator.genAct3`
    ///    uses (`Initiator.result.sk == Responder.result.rk` and
    ///    vice versa — verify this against the published KAT, which gives
    ///    both sides' `sk`/`rk` explicitly).
    /// 9. `rn = sn = 0` — true by construction (`split()`'s output).
    /// 10. `rck = sck = ck` — `HandshakeResult.ck = ss.ck` (same
    ///     post-`split()`-is-unmutated property as `Initiator.genAct3`
    ///     step 6 relies on).
    pub fn readAct3(self: *Responder, msg: act.Act3) HandshakeError!HandshakeResult {
        if (self.state != .awaiting_act3) return error.WrongState;
        // Step 3: decrypt the initiator's static key at nonce 1 — `ss` is
        // STILL keyed with temp_k2 from genAct2 (nonce-continuity, see the
        // doc comment).
        var rs: [33]u8 = undefined;
        try self.ss.decryptAndHash(&msg.c, &rs);
        // A successfully-decrypted `rs` can still fail to parse as a valid
        // SEC1 point — `dh.dh`'s `Secp256k1.fromSec1` rejects it with
        // `error.InvalidPublicKey` before any scalar multiply runs (BOLT#8
        // "act3 bad rs test"); only a VALIDATED key is stored.
        const se = try dh.dh(self.ephemeral.?.secret_key, rs);
        self.rs_pub = rs;
        self.ss.mixKey(&se);
        var empty: [0]u8 = undefined;
        try self.ss.decryptAndHash(&msg.t, &empty);
        // split(): pair[0] is initiator->responder, pair[1] the reverse —
        // for THIS (responder) side, rk = pair[0] and sk = pair[1], the
        // OPPOSITE assignment order Initiator.genAct3 uses (doc comment
        // step 8).
        const pair = self.ss.split();
        self.state = .done;
        return .{
            .sk = pair[1].k,
            .rk = pair[0].k,
            .ck = self.ss.ck,
            .handshake_hash = self.ss.getHandshakeHash(),
        };
    }
};

// ── tests ─────────────────────────────────────────────────────────────

const testing = std.testing;

test "Suite(dh, ChaChaPoly, SHA256) type-checks and its SymmetricState is DH-agnostic (see module doc comment)" {
    try testing.expectEqual(@as(usize, 32), Suite.HASHLEN);
    try testing.expectEqual(@as(usize, 16), Suite.TAGLEN);
    var ss: Suite.SymmetricState = .{};
    ss.initializeSymmetric(protocol_name);
    ss.mixHash(prologue);
    try testing.expect(!ss.cipher_state.hasKey());
    // Deliberately NOT tested: Suite.HandshakeState.initialize(...) — see
    // the module doc comment, this would fail to COMPILE (dhName's
    // X25519-only @compileError), which is exactly why this module drives
    // the handshake itself instead of reusing noise.HandshakeState.
}

const kv = @import("kat_vectors.zig");
// The pre-Act-One transcript hash is not itself a `kat_vectors.zig` entry
// (it's an independently-computed cross-check specific to this test, not
// a value BOLT#8 publishes) — kept as its own top-level const (rather than
// called inline inside the test body) because `kat_vectors.hx`'s internal
// `comptime` block requires a comptime-forced call site.
const h_before_act1 = kv.hx("8401b3fdcaaa710b5405400536a3d5fd7792fe8e7fe29cd8b687216fe323ecbd");

test "Initiator.init / Responder.init: BOLT#8 'Handshake State Initialization' matches an INDEPENDENT oracle (Python hashlib, not Zig re-run)" {
    // Fixed identities from BOLT#8 Appendix A (see dh.zig's KAT constants
    // for provenance); re-derived here via public API so this test does
    // not reach into dh.zig's private test-only decls.
    const init_ls = try dh.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const resp_ls = try dh.KeyPair.generateDeterministic([_]u8{0x21} ** 32);

    const initiator = Initiator.init(init_ls, resp_ls.public_key);
    const responder = Responder.init(resp_ls);

    // Both sides mix in the SAME bytes (the responder's static key) as
    // their final pre-message step, so their running `h`/`ck` must match
    // before Act One even begins.
    try testing.expectEqual(initiator.ss.h, responder.ss.h);
    try testing.expectEqual(initiator.ss.ck, responder.ss.ck);
    try testing.expect(!initiator.ss.cipher_state.hasKey());

    // `ck` right after `initializeSymmetric("Noise_XK_secp256k1_ChaChaPoly_
    // SHA256")` — unaffected by the two subsequent `mixHash` calls (mixHash
    // never touches `ck`) — is independently confirmed by BOLT#8's own
    // Appendix A: the "HKDF(0x2640f52e...,...)" comment inside Act One's
    // worked trace passes exactly this value as `ck` into the FIRST
    // `mixKey` call, i.e. it IS the post-"Handshake State Initialization"
    // `ck`. Recomputed independently here via Python hashlib (see this
    // module's own investigation notes) as a from-scratch cross-check of
    // the spec's own published intermediate, not merely a second run of
    // this same Zig code.
    try testing.expectEqualSlices(u8, kv.ck_after_init, &initiator.ss.ck);

    // The final pre-Act-One transcript hash `h` (after prologue + the
    // responder's static-key mixHash) is NOT itself published by BOLT#8
    // (Appendix A's first `h=` comment already reflects Act One step 2's
    // `e.pub` mixHash on top of it) — independently computed here via
    // Python hashlib from the spec's own formulas as a from-scratch
    // cross-check.
    try testing.expectEqual(h_before_act1.*, initiator.ss.h);
}

// ── B6 RNG-seam pins (2026-08-12) ─────────────────────────────────────
//
// R1 was: `e` was a PUBLIC INPUT field and `genAct1` did `self.e orelse
// dh.KeyPair.generate(random)`, so a consumer who assigned it got a constant
// ephemeral public key in every Act One — total cross-session linkability and
// a constant `es` — while the `random` argument became silently dead code.
// Nobody had to SELECT the weak path; it was reachable by assignment. These
// three tests pin the shape that replaced it.

test "Ephemeral: exactly two arms, production and test are distinct, and nothing else is admitted" {
    // `genAct1`/`genAct2` take an `Ephemeral`, not a `std.Random`. The whole
    // point is that the two generators are DIFFERENT TYPES at the call site,
    // so this pins the arm count and both names: adding a third arm, or
    // renaming `csprng` to something that reads as neutral, breaks it.
    const info = @typeInfo(Ephemeral).@"union";
    try testing.expectEqual(@as(usize, 2), info.fields.len);
    try testing.expectEqualStrings("csprng", info.fields[0].name);
    try testing.expectEqualStrings("seeded_for_test", info.fields[1].name);

    var csprng = std.Random.DefaultCsprng.init([_]u8{0x5a} ** 32);
    const production: Ephemeral = .{ .csprng = csprng.random() };
    const for_test: Ephemeral = .{ .seeded_for_test = csprng.random() };
    try testing.expect(std.meta.activeTag(production) != std.meta.activeTag(for_test));
}

test "genAct1/genAct2 ALWAYS draw: the stored ephemeral is an output, and pre-setting it cannot steer Act One (B6 R1)" {
    const ls = try dh.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const rs = try dh.KeyPair.generateDeterministic([_]u8{0x21} ** 32);

    // The exact attack the audit described: a consumer pins a constant
    // ephemeral of their own choosing and expects it to be used.
    const attacker_fixed = try dh.KeyPair.generateDeterministic([_]u8{0x42} ** 32);

    var prng = std.Random.DefaultPrng.init(0xb01783);
    var initiator = Initiator.init(ls, rs.public_key);
    initiator.ephemeral = attacker_fixed; // inert since B6: never read as input
    const a1 = try initiator.genAct1(.{ .seeded_for_test = prng.random() });

    // Act One does NOT carry the assigned key...
    try testing.expect(!std.mem.eql(u8, &attacker_fixed.public_key, &a1.e_pub));
    try testing.expect(!std.mem.eql(u8, &attacker_fixed.secret_key, &initiator.ephemeral.?.secret_key));
    // ...it carries the drawn one, and the field records that draw.
    try testing.expectEqual(initiator.ephemeral.?.public_key, a1.e_pub);

    // And the draw genuinely comes from the supplied generator: the same
    // seed reproduces it, a different seed does not. (Without this half the
    // test would also pass against a hardcoded key.)
    var same = std.Random.DefaultPrng.init(0xb01783);
    var i_same = Initiator.init(ls, rs.public_key);
    const a1_same = try i_same.genAct1(.{ .seeded_for_test = same.random() });
    try testing.expectEqual(a1.e_pub, a1_same.e_pub);

    var other = std.Random.DefaultPrng.init(0xb01784);
    var i_other = Initiator.init(ls, rs.public_key);
    const a1_other = try i_other.genAct1(.{ .seeded_for_test = other.random() });
    try testing.expect(!std.mem.eql(u8, &a1.e_pub, &a1_other.e_pub));

    // Same three properties on the responder side.
    var responder = Responder.init(rs);
    try responder.readAct1(a1);
    responder.ephemeral = attacker_fixed;
    var rprng = std.Random.DefaultPrng.init(0xdeadbeef);
    const a2 = try responder.genAct2(.{ .seeded_for_test = rprng.random() });
    try testing.expect(!std.mem.eql(u8, &attacker_fixed.public_key, &a2.e_pub));
    try testing.expectEqual(responder.ephemeral.?.public_key, a2.e_pub);
}

test "act ordering is enforced: no second genAct1/genAct2 can silently reuse the ephemeral (B6 R2)" {
    const ls = try dh.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const rs = try dh.KeyPair.generateDeterministic([_]u8{0x21} ** 32);
    var prng = std.Random.DefaultPrng.init(0x60177);
    const rnd: Ephemeral = .{ .seeded_for_test = prng.random() };

    var initiator = Initiator.init(ls, rs.public_key);
    // Out of order the other way: Act Two / Act Three before Act One.
    try testing.expectError(error.WrongState, initiator.readAct2(.{ .e_pub = rs.public_key, .tag = @splat(0) }));
    try testing.expectError(error.WrongState, initiator.genAct3());

    const a1 = try initiator.genAct1(rnd);
    // The R2 case: a retry that forgets to rebuild the handshake. Before the
    // guard this returned a SECOND Act One over the SAME cached ephemeral.
    try testing.expectError(error.WrongState, initiator.genAct1(rnd));
    try testing.expectError(error.WrongState, initiator.genAct1WithEphemeral(ls));

    var responder = Responder.init(rs);
    try testing.expectError(error.WrongState, responder.genAct2(rnd));
    try responder.readAct1(a1);
    try testing.expectError(error.WrongState, responder.readAct1(a1));
    const a2 = try responder.genAct2(rnd);
    try testing.expectError(error.WrongState, responder.genAct2(rnd));

    // The happy path still walks all three acts, with DRAWN ephemerals on
    // both sides (the KAT suite only ever exercises pinned ones) — and the
    // two sides agree on the transport keys, which is the end-to-end proof
    // that `genAct1`/`genAct2`'s rewrite kept the protocol intact.
    try initiator.readAct2(a2);
    const fin = try initiator.genAct3();
    const rres = try responder.readAct3(fin.msg);
    try testing.expectEqual(fin.result.sk, rres.rk);
    try testing.expectEqual(fin.result.rk, rres.sk);
    try testing.expectEqual(fin.result.ck, rres.ck);
    try testing.expectEqual(fin.result.handshake_hash, rres.handshake_hash);
    try testing.expectEqual(Initiator.State.done, initiator.state);
    try testing.expectEqual(Responder.State.done, responder.state);
    try testing.expectError(error.WrongState, responder.readAct3(fin.msg));
}
