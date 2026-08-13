# megolm — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-13** — `OutboundSession.init`'s Ed25519 signing keypair now draws its seed from
  `entropy.fill` (`std.Io.randomSecure`) instead of `io.random`, matching
  what `Ratchet.generate` already did for R₀. **Not breaking:** no
  signature changed and no new dep (`entropy` was already one).

  The ratchet half of a session was fail-closed and the signing half was
  not, which is the wrong place to draw that line: this key signs every
  session-sharing blob and every message frame, so a weak draw lets an
  attacker forge into the group no matter how good R₀ was. The generator
  is std's `Ed25519.KeyPair.generate` verbatim — retry loop included —
  with one substitution in where its 32 seed bytes come from.

- **2026-08-12** — `Ratchet.generate` draws R₀ through the new `entropy` module
  (`entropy.fill`, i.e. `std.Io.randomSecure`) instead of `io.random`. Not
  breaking: `fill` returns `void`, so no signature changed and `generate`
  still returns a plain `Ratchet`. `std.Io.random` is a CSPRNG whose
  contract permits a silent fallback to a weaker seed (`std/Io.zig:2462`)
  and the default `Io.Threaded` takes it, seeding from pid + wall clock +
  an ASLR pointer. Those 128 bytes *are* the session key — every message
  key the group will ever use is a hash of them and they are shared out
  verbatim in the session-sharing format — so the draw now aborts rather
  than mint a group history from a degraded seed. The old doc comment
  justified `io.random` by pointing at `signal` and `std`'s Ed25519
  keygen; that comparison is gone with it.
- **2026-07-29** — New module: Matrix's Megolm group ratchet, the third real-world
  group-messaging construction here alongside `signal` (pairwise Double
  Ratchet) and `mls` (RFC 9420). A one-way four-part HMAC-SHA-256 hash
  ratchet that fast-forwards to any future index but never rewinds, plus
  Ed25519 signatures over the message frame; `OutboundSession` /
  `InboundGroupSession` and the exact session-sharing, session-export and
  message wire formats. The cipher is not a choice: the spec mandates
  AES-256-CBC/PKCS#7 + HMAC-SHA-256 truncated to 8 bytes, taken from the
  sibling `aescbc`. `decrypt` separates four failure causes into distinct
  typed errors (`InvalidSignature`, `MessageIndexTooOld`, `InvalidMac`,
  `InvalidPadding`) and verifies signature → MAC → padding in that order,
  so the padding check is unreachable without a valid MAC. Byte-exact
  against libolm's own `test_megolm.cpp` ratchet vectors — including the
  2^24/2^16/2^8 boundary crossings and the 32-bit counter wraparound —
  and a real libolm-produced session-key + message pair from
  `test_group_session.cpp`, independently re-derived end to end with a
  separate Python toolchain (PyNaCl + `cryptography` + stdlib `hmac`) as
  a non-libolm cross-check. The ratchet advance is a cascade, not a
  per-part rehash: crossing a boundary rehashes the crossed part and
  everything to its right **from the same pre-update value** —
  implementing it as an independent per-part rehash still round-trips,
  and is caught only by a boundary-crossing vector. Olm, the Matrix
  event-JSON layer and key backup are out of scope.
