# ctap2 — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
