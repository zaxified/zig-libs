# drand

Client core for the **drand randomness beacon**: parse a chain-info
(`/info`) document, decode a beacon round (`/public/<round>`), and
BLS-verify a round's threshold signature against the chain public key.
The cryptography is entirely `bls12_381`'s (the pairing + RFC-9380
hash-to-curve), and the quicknet message-hashing (`beaconId`/`h1`) is
REUSED verbatim from `tlock.ciphersuite` so `drand` and `tlock` can
never drift on the scheme. Models drand's own Go client and its
`crypto.Scheme.VerifyBeacon`, targeting the League of Entropy's
**quicknet** beacon (`bls-unchained-g1-rfc9380` — signatures in `G1`,
master key in `G2`).

**Transport-agnostic — by design.** This module never opens a socket or
speaks TLS. The caller fetches the `/info` and `/public/<round>`
response bytes with their own HTTPS client and hands them here to be
parsed + verified — exactly the way `tlock` consumes a round signature
without fetching it (`CONVENTIONS.md` §2's bring-your-own-transport
posture). `round.roundPath`/`round.latestPath` build the request path as
a convenience; performing the request is the caller's job.

**Status: REAL — KAT-verified against genuine quicknet data.**
`verifyRound` is validated against the live-fetched quicknet round-1000
signature + chain public key (the same genuine bytes `tlock`'s KAT
harness pins), and a permanent positive-control test proves the
big-endian round encoding is load-bearing (little-endian hashing makes
the genuine KAT fail). Signatures on G1, master key on G2 — the MIRROR
of `bls12_381.bls_sig`'s min-pubkey ciphersuite, so verification is a
direct pairing check, not `bls_sig.verify` (see [SPEC.md](SPEC.md)).

| File | Contents |
|---|---|
| `root.zig` | Module doc, `meta`, flattened re-exports, dark-tests aggregator, end-to-end KAT |
| `chaininfo.zig` | `parseInfo` → `ChainInfo` (typed plain value; decodes + `KeyValidate`s the `G2` chain key for quicknet), `Scheme` enum |
| `round.zig` | `parseRound` → `Round` (decodes **and `KeyValidate`s** the `G1` signature — the pairing equation cannot see a cofactor-torsion addend, so a non-subgroup signature is rejected here; retains `randomness`/`previous_signature`); `roundPath`/`latestPath` request-path helpers |
| `verify.zig` | `verifyRound(info, round)` — the drand `VerifyBeacon` pairing equation on `bls12_381.pairing` + the `randomness == SHA-256(signature)` check; the fuzz harness |

## Schemes covered

| `schemeID` | Signatures | Key | Message | This module |
|---|---|---|---|---|
| `bls-unchained-g1-rfc9380` (quicknet) | `G1` (48 B) | `G2` (96 B) | `H1(SHA-256(round_be))`, RFC-9380 `_NUL_` DST | **parse + verify** |
| `pedersen-bls-chained` (legacy default) | `G2` (96 B) | `G1` (48 B) | `H(round ‖ prev_sig)` | parse only → `error.UnsupportedScheme` |
| `bls-unchained-on-g1` (deprecated) | `G1` | `G2` | non-conformant DST reuse | parse only → `error.UnsupportedScheme` |

## Import

```zig
const drand = @import("drand");
```

## API

```zig
// 1. Parse the chain-info the caller fetched from `<host>/<chainhash>/info`
//    (or `/v2/beacons/<id>/info`). Returns a plain value — no deinit.
const info = try drand.parseInfo(gpa, info_bytes);

// 2. (Optional) build the round request path; YOU perform the HTTPS GET.
var buf: [128]u8 = undefined;
const path = try drand.roundPath(&buf, "52db9ba7...e971", 1000); // "/52db9ba7.../public/1000"

// 3. Parse the round document the caller fetched from that path.
const round = try drand.parseRound(gpa, round_bytes);

// 4. Verify: BLS-verify the signature against info's chain key AND
//    (when present) that randomness == SHA-256(signature).
try drand.verifyRound(&info, &round);
// error.InvalidSignature / RandomnessMismatch / UnsupportedScheme / … on any failure —
// never a panic, never a silent false-accept.
```

`gpa` is used only transiently inside the parsers (an internal arena,
freed before return); every returned value (`ChainInfo`, `Round`) owns no
heap memory. All parsing is bounds-checked: malformed / truncated /
oversized JSON or hex yields a typed error (`ParseError` /
`RoundParseError`), never a panic, OOB read, hang, or amplified
allocation (documents over 64 KiB are rejected up front).

`verifyRoundPoints(pubkey, round, sig)` exposes the raw pairing equation
for a caller that already holds decoded `bls12_381` points (e.g. from
`tlock`).

## Import graph

```
drand → bls12_381  (G1/G2 arithmetic, the pairing, RFC 9380 hash-to-curve)
      → tlock       (ciphersuite.beaconId / h1 — the quicknet message hashing, reused so the two can't drift)
```

`meta.deps = .{ "bls12_381", "tlock" }`. The `tlock` dependency is load-bearing:
it supplies the byte-identical `beaconId`/`h1` construction, guaranteeing this
verifier and `tlock`'s timelock encryption agree on quicknet's scheme.

## Verify

```
zig build test-drand --summary all                     # Debug
zig build test-drand -Doptimize=ReleaseFast --summary all
zig fmt --check modules/drand/
```

All **31** tests PASS in both Debug and ReleaseFast: the chain-info and
round parsers (round-trip + every malformed variant), the genuine
quicknet round-1000 verification KAT, the negative tests (flipped
signature, wrong round, wrong chain key, tampered randomness,
unsupported scheme), the little-endian positive-control, and the fuzz
harness over both parsers + the verify path.

Provenance: spec/RFC-only — see [SPEC.md](SPEC.md)'s Provenance section
(no third-party source ported; the genuine quicknet KAT bytes are the
same live-fetched public data `tlock` pins).
