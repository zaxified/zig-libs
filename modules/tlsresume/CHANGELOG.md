# tlsresume — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-09** — **BREAKING:** `StekRing.activeKey()` and `findKey(id)` return `?*const Stek` (a
  pointer into the ring, valid until the next `rotate`) instead of a copy: every call copied the STEK —
  the ticket-encryption key — into the caller's frame. `ring.activeKey().?.key` and `== null` read as
  before.
- **2026-10-09** — **BREAKING (dead-stack rule, CONVENTIONS §2.1.1):** secrets in by `*const`, secret results
  out through an `out` pointer (first parameter after the comptime types), every entry point's body under a
  burn (new `src/burn.zig`). `psk.derivePsk(Hkdf, len, out, rms, nonce)`, `psk.earlySecret(Hkdf, out, psk)`,
  `psk.binderKey(Hkdf, out, early, hash)`, `psk.computeBinder(Hkdf, Hmac, out, binder_key, hash)`,
  `psk.verifyBinder(.., binder_key: *const .., ..)`; `earlydata.clientEarlyTrafficSecret` /
  `earlyExporterMasterSecret` (`out` first), `earlyTrafficKeyIv(Hkdf, key_len, out: *TrafficKeyIv, secret)`,
  `EarlyDataContext.derive(out: *Ctx, psk, hash)` (was: returned the context); `stek.StekRing.rotate(id, key:
  *const [32]u8, now_s)`; `select.selectPsk(Hkdf, Hmac, Ring, out: *Selection, ring, ...) SelectError!void`
  (was: returned the `Selection` with the PSK and session secret; `out` is zeroed on error). Burns: 8 KiB
  one-shot KDF steps, 4 KiB per-ticket `StekRing.seal/open`, 16 KiB `selectPsk`. Not covered (open):
  `StekRing.activeKey/findKey` still return the `Stek` (key included) by value. New probe `src/stackprobe_test.zig`
  (testkit engine) over every entry point; `check-secret-api` is at 0. Example and README migrated.

- **2026-10-04** — Tests: mutation schemata run (37 mutants, all killed). Four new tests:
  NewSessionTicket length prefixes that overrun what follows, `maxEarlyDataSize`'s type/length
  rule, the strike register's inclusive window / re-arm / eviction boundary, and `selectPsk`
  rejecting a future-dated ticket and an allocation-failing strike register. No behaviour change.
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
