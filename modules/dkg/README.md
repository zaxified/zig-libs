# dkg

Secure **Distributed Key Generation** for [`threshold_ecdsa`](../threshold_ecdsa)
over secp256k1 — the **GJKR** construction (Gennaro, Jarecki, Krawczyk, Rabin,
*"Secure Distributed Key Generation for Discrete-Log Based Cryptosystems"*,
J. Cryptology 2007), which removes the **trusted-dealer** assumption: `n` parties
jointly generate an ECDSA secret sharing with no party ever holding the whole
key and no dealer to trust.

GJKR is the *bias-resistant* DKG. Naive Pedersen-DKG lets a rushing adversary,
who waits to see honest parties' contributions before choosing its own, bias the
resulting public key. GJKR fixes this by a two-phase commit: parties first
commit to their sharings with **Pedersen** commitments and fix the qualified set
**QUAL** from complaints alone; only *after* QUAL is frozen do they reveal
**Feldman** commitments and extract the public key `Q = Σ_{i∈QUAL} g^{a_i0}`.

> **Status — mvp.** Two ways to run the protocol: `Participant` — each party its own
> sans-I/O state machine, frames in, frames out, usable over a real network — and
> `Dkg.run`, the in-process lockstep driver kept as the test oracle (both give
> byte-identical outputs for the same randomness). `ReshareDealer`/`ReshareReceiver`
> move a finished key to a new committee (or refresh the same one) keeping the public key.
> Known gap: a QUAL dealer failing the Feldman check aborts the run (GJKR's public
> reconstruction is not implemented). See `SPEC.md`.

## The end-to-end anchor

There is no external byte-exact KAT for a randomized DKG, so correctness is
pinned a stronger way: the DKG-produced shares feed the REAL
`threshold_ecdsa.signWithShares`, and the resulting signature is verified under
the DKG's public key `Q` with **`std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`**.
A DKG that produces a valid, std-verifiable ECDSA signature produced a correct,
usable key — this defeats "self-consistent but nonstandard" without any external
vector. See the `END-TO-END ANCHOR` test in `src/root.zig`.

## Scope

The secret-key DKG plus resharing. Output (`DkgShareOutput`) is the ECDSA key material —
this party's Shamir share `x_j`, the group key `Q = x·G`, and its verifying share
`X_j = x_j·G` — directly consumable by `threshold_ecdsa` signing via `assembleKeyShares`
(which attaches each party's independently-generated Paillier keypair + ring-Pedersen aux
params). Out of scope: CGGMP21 signing-phase **identifiable abort** and distributed
**aux-parameter** generation. See `SPEC.md`.

## One party over a real network

```zig
const dkg = @import("dkg");

// Party `me` of a 2-of-3 run. `random` must be a CSPRNG-backed std.Random.
var p = try dkg.Participant.init(allocator, .{ .t = 2, .n = 3 }, me, random);
defer p.deinit(); // wipes every secret

try p.start(); // round 1: Pedersen broadcast + one share per peer
// Then, per round: send what is queued, deliver what arrives, close the round.
while (p.phase() != .done) {
    const out = try p.takeOutgoing();
    defer dkg.freeOutgoing(allocator, out);
    for (out) |m| switch (m.to) {
        .broadcast => transport.broadcast(m.bytes), // reliable broadcast, same bytes to all
        .party => |j| transport.sendConfidential(j, m.bytes), // shares are secret
    };
    while (transport.next()) |frame| { // frame.from is the AUTHENTICATED sender
        p.handle(frame.from, frame.bytes) catch |e| switch (e) {
            error.WrongRound => transport.holdBack(frame), // early frame: redeliver later
            error.OutOfMemory => return e,
            else => log.warn("refused frame from {d}: {t}", .{ frame.from, e }),
        };
    }
    try p.advance(); // all expected frames in, or the round's deadline passed
}
var mine = p.output().?; // DkgShareOutput
defer mine.deinit();
```

Run rounds until `p.phase()` is `.done`: five when every dealer behaves, six when a dealer
had to be reconstructed. A QUAL dealer whose Feldman commitments fail some party's share, or
never arrive, does not stop the run: the complaint opens the share so every party checks it,
everybody reveals its share of that dealer, and its polynomial is rebuilt in public (GJKR
Fig. 2 step 4) — so it can neither split the honest parties nor veto a `Q` it dislikes.
`advance` errors name what went wrong (`ReconstructionFailed`: `p.culprit()` is the dealer
id); any error leaves the party `.aborted`. A refused frame never changes state, so a garbage
frame cannot derail a run — but a peer that stays silent is treated as absent (round 1).
`Participant.init` and `Dkg.run` refuse `n < 2t − 1` (`NoHonestMajority`): GJKR's
guarantees need the `t − 1` parties it tolerates to be a minority.

Resharing to a new committee (or the same one, as a proactive refresh):

```zig
// Public inputs every party of the resharing agrees on: old and new (n, t), which old
// parties deal (at least the old t), the group key, and the old verifying shares X_i.
const rc: dkg.ReshareConfig = .{ .old = .{ .t = 2, .n = 3 }, .new = .{ .t = 3, .n = 5 },
    .dealers = &.{ 1, 3 }, .group_public_key = q, .old_verifying_shares = xs };

// An old party deals its share ...
var dealer = try dkg.ReshareDealer.init(allocator, my_old_output, rc.new, random);
try dealer.start(); // broadcast -> every new party; party(j) -> new party j
// ... a new party collects (from = OLD id, except for complaints: from = NEW id).
var recv = try dkg.ReshareReceiver.init(allocator, rc, my_new_id);
// rounds: recv.advance() [complaints out] -> dealer.advance() [defenses out] -> recv.advance()
// recv.output() is the new DkgShareOutput; group_public_key is unchanged.
```

Old shares are not revoked by resharing: `t` old shares still reconstruct the key among
themselves, so old holders must erase them (`DkgShareOutput.deinit`). What you get is the
proactive guarantee — shares stolen before a refresh are useless after it.

## Lockstep driver

```zig
const dkg = @import("dkg");

// Run the dealer-free DKG (2-of-3), all parties honest, all in this process.
const outs = try dkg.Dkg.run(allocator, .{ .t = 2, .n = 3 }, .{}, random);
defer allocator.free(outs);

// Every honest party agrees on Q, and any t shares reconstruct x with x·G == Q.
std.debug.assert(dkg.checks.allSameQ(outs));
std.debug.assert(try dkg.checks.reconstructsToQ(allocator, outs[0..2]));

// Bridge to threshold signing: attach Paillier + aux, then sign.
const key_shares = try dkg.assembleKeyShares(allocator, outs, 2, paillier_keys, aux_params);
```

## Independent check

`tools/gjkr_oracle.py` recomputes every public value of a recorded transcript (5 parties,
`t = 3`, and a resharing to `n' = 3`, `t' = 2`, all secret coefficients revealed) with plain
integers over secp256k1, written from the GJKR paper. `python3 tools/gjkr_oracle.py --check`
verifies the committed `src/transcript_vectors.zig`; two Zig tests replay it through the
state machines. It is a re-derivation, not a foreign implementation (none exists for GJKR
over secp256k1).

Provenance: clean-room implementation of GJKR (J. Cryptology 2007) over
`std.crypto.ecc.Secp256k1`, reusing this repo's `threshold_ecdsa` key format /
Shamir+Feldman shape and `paillier`. No third-party code. The detail lives in
[`NOTICE`](NOTICE) beside this file — a provenance note, carrying no condition.
