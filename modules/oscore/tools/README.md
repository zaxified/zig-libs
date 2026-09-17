# `oscore` verification instruments

One instrument, run by hand. Not wired into `zig build`: it needs a
**foreign toolchain** (Python's `cryptography`). `zig build test-oscore` must
require none of it (`CONVENTIONS.md` §9).

Only two kinds of instrument are kept here (`CONVENTIONS.md` §9): recipes for
data the tests pin, and oracles that drive a foreign implementation through
the public API or wire format. The audit's mutation runners, probes, and
benchmarks (nonce truncation, dead-stack scans, message-size ceiling, decode
fuzzing, ctgrind) were deleted on 2026-09-17; what they found is pinned by
tests in `src/` or filed as open findings (`rfc_provenance.py`, the other
audit script that once lived beside this one, belongs to a separate, rejected
shared KAT-provenance verifier — not adopted here).

Figures below were measured on 2026-09-17 against the tree as it stands.

## A third-party crypto stack agrees with the committed vectors

| tool | question it answers |
|---|---|
| `independent_oracle.py` | Recomputes RFC 8613 Appendix C's key derivation and protected-message construction from scratch on python `cryptography` (a different HKDF, a different AES-CCM, a different CBOR encoder, a different language) and checks every field of `src/kat_vectors.zig` against it. |

```bash
python3 modules/oscore/tools/independent_oracle.py modules/oscore/src/kat_vectors.zig
```

**Measured 2026-09-17: 73/73 agreements, 0 mismatches** — all 6 key-derivation
vectors (C.1-C.3: `info` CBOR, Sender/Recipient Key, Common IV, both
Partial-IV-0 nonces) and all 5 message vectors (C.4-C.8: nonce, `aad_array`,
full `Enc_structure`, AES-CCM-16-64-128 seal, and its own decrypt back to
plaintext). `kat_vectors.zig`'s values are not merely "copied from the RFC" —
an independent implementation, in a different language against a different
crypto library, derives the same bytes from the same inputs.

**Licence, checked at the source:** python `cryptography` 50.0.0 is
Apache-2.0 OR BSD-3-Clause (`License-Expression: Apache-2.0 OR BSD-3-Clause`
in its installed dist-info `METADATA`). Not copyleft; fetched/installed only,
never vendored into this tree.
