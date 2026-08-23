# spake2plus

SPAKE2+, an AUGMENTED (asymmetric) Password-Authenticated Key Exchange,
per RFC 9383 — **P-256/SHA-256/HKDF-SHA256/HMAC-SHA256 ciphersuite**
(the one Matter/Thread device commissioning uses). Unlike a balanced PAKE
(RFC 9382's plain SPAKE2), the two sides here are asymmetric BY DESIGN:
the Prover (client) holds a password-derived `w0` AND `w1`; the Verifier
(server) holds `w0` AND a registration record `L = w1*P`, NEVER `w1`
itself — so a Verifier-database compromise does not directly hand an
attacker the password.

**Status: complete.** Ciphersuite constants, wire encoders
(`m_compressed_sec1`/`n_compressed_sec1`, `mPoint`/`nPoint`,
`computeTranscript`, the `hash`/`mac`/`kdf` primitive wrappers), and the
seven crypto cores (`computeW0W1`, `computeL`, `proverStart`,
`verifierStart`, `deriveKeys`, `proverFinish`, `verifierFinish`) are all
implemented and KAT-validated — no `@panic`/TODO stub remains in
`root.zig`. An eighth function, `verifierConfirm`, lets the Verifier emit
its `confirmV` message before it has seen the Prover's `confirmP` — see
"Protocol flow" below and [SPEC.md](SPEC.md) for why that split is
necessary, and the `V`-computation asymmetry this scheme's security
hinges on.

| File | Contents |
|---|---|
| `root.zig` | `M`/`N` ciphersuite constants + `mPoint`/`nPoint`, `computeTranscript`, `hash`/`mac`/`kdf` wrappers, the 7 crypto cores (`computeW0W1`, `computeL`, `proverStart`, `verifierStart`, `deriveKeys`, `proverFinish`, `verifierFinish`), and `verifierConfirm` (the Verifier's confirmV-emission half, split out of `verifierFinish` so a blind two-party run is drivable) — all REAL |
| `kat_vectors.zig` | RFC 9383 Appendix C's 1 official P-256/SHA-256 test vector, byte-exact |
| `kat_test.zig` | "REAL TODAY" tests (`computeTranscript`/`mac`, pass now) + byte-exact KAT assertions + a genuinely-blind end-to-end Prover<->Verifier run (no foreknowledge of either confirmation value) + tamper-rejection tests |

## Import

```zig
const spake2plus = @import("spake2plus");
```

## Protocol flow (RFC 9383 §3.1 / Appendix A.5)

This is the REAL message order — RFC 9383 Appendix A.5's Verifier
transmits `confirmV` before it has ever seen a `confirmP`, so the
Verifier's own confirmation is computed by `verifierConfirm`, NOT
`verifierFinish` (which requires `received_confirm_p` and is the final,
gated step — see below). Every value below is genuinely produced by the
call before it; nothing is known in advance:

```zig
// Offline registration (once, out of band): derive w0/w1 from the
// password (computeW0W1 — RFC 9383 §3.2), then compute L for the
// Verifier's database.
const w0w1 = try spake2plus.computeW0W1(pbkdf_output); // 80-byte PBKDF output
const l = try spake2plus.computeL(w0w1.w1); // Verifier stores w0 + l; NEVER w1

// Round 1: shares — neither side needs anything from the other yet.
const share_p = try spake2plus.proverStart(x, w0w1.w0);   // Prover   -> Verifier: share_p
const share_v = try spake2plus.verifierStart(y, w0w1.w0); // Verifier -> Prover:   share_v

// Round 2a: the Verifier goes FIRST — it emits confirmV with no Prover
// confirmation in existence yet (RFC 9383 Appendix A.5).
const verifier_confirm = try spake2plus.verifierConfirm(
    allocator, context, id_prover, id_verifier,
    w0w1.w0, l, y, share_p, share_v,
);
defer allocator.free(verifier_confirm.tt);
// verifier_confirm.confirm_v -> Verifier -> Prover: confirmV
// (no k_shared here by design — see verifierConfirm's doc comment)

// Round 2b: the Prover validates the confirmV it just received, and only
// on success computes its own confirmP and the shared secret.
const prover_result = try spake2plus.proverFinish(
    allocator, context, id_prover, id_verifier,
    w0w1.w0, w0w1.w1, x, share_p, share_v, verifier_confirm.confirm_v,
);
defer allocator.free(prover_result.tt);
// prover_result.confirm_p -> Prover -> Verifier: confirmP
// prover_result.k_shared  -> the authenticated shared secret

// Round 2c: the Verifier validates the confirmP it just received, and
// only on success obtains the matching shared secret.
const verifier_result = try spake2plus.verifierFinish(
    allocator, context, id_prover, id_verifier,
    w0w1.w0, l, y, share_p, share_v, prover_result.confirm_p,
);
defer allocator.free(verifier_result.tt);
// verifier_result.k_shared == prover_result.k_shared
```

`x`/`y` (the ephemeral per-session scalars) and the peer's
key-confirmation MAC arguments (`verifier_confirm.confirm_v` fed into
`proverFinish`, `prover_result.confirm_p` fed into `verifierFinish`) are
always CALLER-supplied — this module never generates randomness or
drives a transport itself; see `SPEC.md`'s threat-model section for the
CSPRNG and constant-time-comparison requirements this places on
callers/the crypto-core implementation. `K_shared` is returned ONLY by
`proverFinish`/`verifierFinish`, and only after each has independently,
constant-time-validated the peer's confirmation — `verifierConfirm`
cannot hand back `K_shared` at all (RFC 9383 §3.3: neither party may
consider the protocol complete before that validation).

## Import graph

```
spake2plus → std.crypto.ecc.P256 / std.crypto.hash.sha2.Sha256 /
             std.crypto.auth.hmac.sha2.HmacSha256 / std.crypto.kdf.hkdf.HkdfSha256
```

## Verify

```
zig build test-spake2plus                     # Debug — green
zig build test-spake2plus -Doptimize=ReleaseFast
zig fmt --check modules/spake2plus/
```

`kat_test.zig` asserts byte-exact `computeL`/`proverStart`/
`verifierStart`/`deriveKeys`/`proverFinish`/`verifierFinish`/
`verifierConfirm` output against RFC 9383 Appendix C's official
P-256/SHA-256 vector, plus a genuinely blind end-to-end property test
(Prover<->Verifier agreement on `K_shared`, driven only through the
public API in the real RFC 9383 Appendix A.5 message order — neither
party is fed a confirmation value it did not itself just receive) and
tamper rejection (corrupted confirmation MAC, corrupted share).
`computeW0W1` has no official byte-exact oracle — see `SPEC.md`'s note.

Provenance: see [NOTICE](NOTICE).
