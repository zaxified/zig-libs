# ctap2 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-10** — **Fixed (constant time): `validateNewPin` no longer branches on the PIN bytes.** It counted code points with `std.unicode.utf8CountCodepoints`, which takes an ASCII fast path and then decodes sequence by sequence, so its timing showed whether a PIN is ASCII and, for a non-ASCII PIN, its code-point structure. The new private `utf8CountCt` classifies lead bytes by arithmetic ranges, carries the expected-continuation count and the narrowed second-byte range (E0/ED/F0/F4) in masks, counts code points as the bytes that are not `10xxxxxx`, and returns one validity bit for a single verdict after the loop. There is no branch and no table indexed by a PIN byte. Accept set and errors are unchanged: overlongs, surrogates, >U+10FFFF and truncated sequences are refused exactly as std refuses them. Cross-checked against std on every 1-, 2- and 3-byte string and 200,000 random strings of up to 63 bytes (valid, damaged and raw), comparing validity and count. ctgrind `ctap2/pin` went from 1 to 0 in-file contexts. No API change.
- **2026-10-10** — Constant time: new `src/ctgrind_harness.zig` (targets `pin`, `token`, ReleaseFast). The PIN and the ECDH shared secret are tainted through `validateNewPin`, `padPin`, `pinHash` and `SharedSecret.encrypt`/`authenticate`; `token` taints the shared secret through `decryptToken` and `Token.authenticate`, protocols One and Two. `token`: 0 in-file contexts. `pin`: 1 at first, from `validateNewPin`'s use of `std.unicode.utf8CountCodepoints`; fixed the same day (see the entry above).
- **2026-10-08** — **Migrated to ctap2pin's pointer / out-param API** (secrets on the dead stack,
  see ctap2pin's changelog): `openSession`, `SharedSecret.encrypt`/`decryptToken`, tests and the
  example. No behaviour change.

- **2026-10-03** — Audit (review + mutation, 87 mutants). Fix: `ctaphid.Channel.open`
  now refuses a device that allocates CID 0 or the broadcast CID (`TransportFailed`), and
  skips an INIT response carrying another client's nonce instead of failing (§11.2.3).
  20 new tests pin the guards the first mutation pass left unchecked; see SPEC.md
  § Audit 2026-10-03.
- **2026-09-30** — New module: the CTAP 2.1 `authenticatorClientPIN` command layer
  over a caller-supplied `Transport`, on top of `ctap2pin` (crypto) and `cbor`.
  Message framing (command byte || CBOR, status byte || CBOR), every CTAP 2.1 §8.2
  status code as a named error, `authenticatorGetInfo` parsing (the PIN-relevant
  subset), and all `authenticatorClientPIN` subcommands — getPINRetries,
  getKeyAgreement, setPIN, changePIN, getPinToken, get-token-with-permissions via
  PIN and via UV, getUVRetries — for both PIN/UV protocols, with the spec's PIN
  rules enforced before any I/O. Also a CTAPHID packet codec and a `Channel` for
  one `CTAPHID_CBOR` transaction over caller-supplied reports. Request bytes are
  asserted equal to python-fido2 2.2.1's for all 10 operations x 2 protocols.
  Maturity task B5.
