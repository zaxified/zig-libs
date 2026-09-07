# tlsresume — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz reach: both fuzz targets ran one input, and it was the same one
  every time. Each opened `smith.value(bool)` to pick between an unstructured and a
  structured half; a `Smith` scalar draw reads eight octets as a little-endian `u64` and
  returns the range minimum when fewer remain, and neither target carried a corpus, so
  outside `--fuzz` the single input was empty, the bool was always false, and the
  unstructured half **never ran once**. Worse, inside the structured half every field draw
  collapsed too: `fuzzSessionStateParse` serialized a record with an empty nonce and
  all-zero timestamps and parsed it back, with the second `smith.value(bool)` guarding the
  nonce-length mutation ALSO false — so the `bytes.len < r + nonce_len + 8 + 4` bounds
  check the harness's own comment says the structured half exists for was never evaluated
  against a disagreeing length. `fuzzTicketDecode` built a 13-octet all-zero ticket
  (lifetime 0, age_add 0, nonce_len 0, ticket_len 0, ext_total_len 0, no trailing garbage)
  and decoded it successfully; the per-field bounds checks and the extension-nest loop
  were never entered. Measured 2026-09-07: 1 round each, 0 nonce octets, 0 extensions.
  Both branches and both generators are gone: each target draws its byte slice with one
  `smith.slice` over a corpus built from this module's own `serialize`/`encode` plus the
  length lies no encoder produces (nonce_len 255 with nothing behind it, ticket_len
  0xFFFF, nine extensions against an `[8]Extension` buffer, a trailing octet past a
  well-formed ticket). ⚠ Both guards pin a second number the collapsed input cannot make,
  because both collapsed inputs were ACCEPTED: 3 accepted / 6 refused / 8 nonce octets,
  and 3 accepted / 7 refused / 26 body octets / 10 extensions parsed.

- **2026-07-18** — Security audit: zero findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against RFC 8448 §4's
  published test vectors.
- **2026-07-11** — New module: Server-side TLS 1.3 session-ticket resumption (RFC 8446
  §4.2.11/§4.6.1/§7.1/§8).
