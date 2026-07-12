# spake2plus

SPAKE2+, an AUGMENTED (asymmetric) Password-Authenticated Key Exchange,
per RFC 9383 — **P-256/SHA-256/HKDF-SHA256/HMAC-SHA256 ciphersuite**
(the one Matter/Thread device commissioning uses). Unlike a balanced PAKE
(RFC 9382's plain SPAKE2), the two sides here are asymmetric BY DESIGN:
the Prover (client) holds a password-derived `w0` AND `w1`; the Verifier
(server) holds `w0` AND a registration record `L = w1*P`, NEVER `w1`
itself — so a Verifier-database compromise does not directly hand an
attacker the password.

**Status: scaffold.** Ciphersuite constants and wire encoders
(`m_compressed_sec1`/`n_compressed_sec1`, `mPoint`/`nPoint`,
`computeTranscript`, the `hash`/`mac`/`kdf` primitive wrappers) are
implemented and tested. The seven crypto cores (`computeW0W1`,
`computeL`, `proverStart`, `verifierStart`, `deriveKeys`, `proverFinish`,
`verifierFinish`) are stubbed (`@panic("TODO(fable): ...")`) with their
final signatures fixed and the exact construction fully documented in
`root.zig`'s doc comments — see [SPEC.md](SPEC.md) for the design, the
`V`-computation asymmetry this scheme's security hinges on, and the TODO
list.

| File | Contents |
|---|---|
| `root.zig` | `M`/`N` ciphersuite constants + `mPoint`/`nPoint` (REAL), `computeTranscript` (REAL), `hash`/`mac`/`kdf` wrappers (REAL) — plus the 7 stubbed crypto cores (`computeW0W1`, `computeL`, `proverStart`, `verifierStart`, `deriveKeys`, `proverFinish`, `verifierFinish`) |
| `kat_vectors.zig` | RFC 9383 Appendix C's 1 official P-256/SHA-256 test vector, byte-exact |
| `kat_test.zig` | "REAL TODAY" tests (`computeTranscript`/`mac`, pass now) + byte-exact KAT assertions + an end-to-end Prover<->Verifier property harness + tamper-rejection tests |

## Import

```zig
const spake2plus = @import("spake2plus");
```

## Protocol flow (RFC 9383 §3.1 / Appendix A.5)

```zig
// Offline registration (once, out of band): derive w0/w1 from the
// password (computeW0W1 — RFC 9383 §3.2), then compute L for the
// Verifier's database.
const w0w1 = try spake2plus.computeW0W1(pbkdf_output); // 80-byte PBKDF output
const l = try spake2plus.computeL(w0w1.w1); // Verifier stores w0 + l; NEVER w1

// Round 1.
const share_p = try spake2plus.proverStart(x, w0w1.w0);       // Prover  -> Verifier
const share_v = try spake2plus.verifierStart(y, w0);           // Verifier -> Prover

// Round 2 + key confirmation (Prover side).
const prover_result = try spake2plus.proverFinish(
    allocator, context, id_prover, id_verifier,
    w0, w1, x, share_p, share_v, received_confirm_v,
);
defer allocator.free(prover_result.tt);
// prover_result.confirm_p  -> transmit to Verifier
// prover_result.k_shared   -> the authenticated shared secret

// Round 2 + key confirmation (Verifier side).
const verifier_result = try spake2plus.verifierFinish(
    allocator, context, id_prover, id_verifier,
    w0, l, y, share_p, share_v, received_confirm_p,
);
defer allocator.free(verifier_result.tt);
// verifier_result.confirm_v -> transmit to Prover
// verifier_result.k_shared  -> the authenticated shared secret (== prover's)
```

`x`/`y` (the ephemeral per-session scalars) and `received_confirm_v`/
`received_confirm_p` (the peer's key-confirmation MAC) are always
CALLER-supplied — this module never generates randomness or drives a
transport itself; see `SPEC.md`'s threat-model section for the CSPRNG and
constant-time-comparison requirements this places on callers/the
crypto-core implementation.

## Import graph

```
spake2plus → std.crypto.ecc.P256 / std.crypto.hash.sha2.Sha256 /
             std.crypto.auth.hmac.sha2.HmacSha256 / std.crypto.kdf.hkdf.HkdfSha256
```

## Verify

```
zig build test-spake2plus                    # Debug — "REAL TODAY" tests pass; panics at the first crypto-core call (expected; see SPEC.md)
zig fmt --check modules/spake2plus/
```

Once the seven crypto cores are implemented, `kat_test.zig` asserts
byte-exact `computeL`/`proverStart`/`verifierStart`/`deriveKeys`/
`proverFinish`/`verifierFinish` output against RFC 9383 Appendix C's
official P-256/SHA-256 vector, plus an end-to-end property test
(Prover<->Verifier agreement on `K_shared`, driven only through the
public API) and tamper rejection (corrupted confirmation MAC, corrupted
share). `computeW0W1` has no official byte-exact oracle — see
`SPEC.md`'s note.

Provenance: see [NOTICE](NOTICE).
