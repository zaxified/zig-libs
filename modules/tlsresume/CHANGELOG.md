# tlsresume — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-26** — Audit (review + mutation) fixes. `select.selectPsk`: with a strike register the
  freshness window applied is at most half the register's window (`strikeFreshnessCap`), also when
  none was passed — before, a ClientHello replayed after the register forgot it passed a freshness
  window as long as the register's, or none (F1); `identities.len != binders.len` is
  `error.BinderMismatch` instead of a panic on client-chosen counts (F2); a ticket opened and not
  selected is wiped from `open_scratch`, the selected one is the caller's to wipe (documented) (F3).
  **BREAKING:** `ticket.NewSessionTicket.encode` returns the new `error.InvalidField` for a
  `ticket_lifetime` over 7 days (`ticket.max_ticket_lifetime_s`), a nonce over 255 bytes, an empty or
  over-long ticket, an over-long extension or block, or an extension type twice; `decode` refuses an
  extension type twice (RFC 8446 §4.2) (F4, F10). `StekRing`: depth over 256 is a compile error (u8
  key ids), `findKey` returns the newest key with an id, new `wipe()` (F5, F7). Documented: one ring per
  purpose / hash (F6), GCM nonce budget, strike-register scan cost, cache id entropy.
- **2026-10-26** — Live oracle `tools/interop.zig` (`zig build interop-tlsresume`, `tlsserver` as the
  engine through the new `interop_deps`): OpenSSL 3.5 `s_client` and Go 1.26's crypto/tls
  (`tools/go_peer`) resume, take 0-RTT, get refused on replay, age skew, an expired STEK and a spent
  stateful ticket; Go's TLS 1.2 client against OpenSSL's and Go's TLS 1.2 servers through `ticket12`.
  Captures (`src/interop_vectors.zig`) replayed by `interop_replay_test.zig`. Bench: aws-lc-rs 1.18.0
  side (`tools/rust_fast_bench`, the fastest in the field).

- **2026-10-20** — **BREAKING:** `select.selectPsk` gains a `filter: ?select.Filter` parameter
  (the engine's own checks on its fields behind the `SessionState` prefix — suite, SNI, its
  lifetime — run before the binder), `freshness_window_ms` becomes `?u32` (null: the reported
  ticket age is not checked, as rustls/BoringSSL/Go outside early data), and a binder that does
  not verify on the identity that would be taken is now `error.BinderMismatch` instead of a skip
  to the next identity (RFC 8446 §4.2.11: the server MUST abort; rustls `IncorrectBinder`). The
  derived PSK, early secret and binder key are wiped per identity. First consumer: `tlsserver`.
- **2026-10-20** — **BREAKING:** `select.selectPsk` takes a `stek.RotationPolicy` and opens tickets with `openAt` (a retired STEK key still in the ring no longer opens tickets), and skips sessions older than 7 days (RFC 8446 §4.6.1) (audit 2026-10-19 O4).
- **2026-10-19** — The STEK ticket AEAD (`stek.Aead`, AES-256-GCM) and the early-data test vectors moved from `std.crypto.aead.aes_gcm` to the zig-libs `aesgcm` module (new dep; Zig 0.17 #36256). `stek.Aead` is now `aesgcm.Aes256Gcm` (same `key_length`/`nonce_length`/`tag_length`, same bytes on the wire).
- **2026-10-13** — `ticket12`: a zero-length ticket is legal (RFC 5077 §3.3, the server withdrawing an announced ticket) — `encode`/`decode` accept it, `isWithdrawal` names it; `stek.depthFor(policy)` gives the ring depth that holds every key a policy accepts (8 for the Go defaults; `DefaultRing` holds ~2 periods). ctgrind harness (`stek`, `psk`, `early`); card Scope core → parity.
- **2026-10-13** — `stek.RotationPolicy` + `StekRing.needsRotation`/`maybeRotate`/`expire`/`openAt` (scheduled rotation with a grace period, Go/rustls defaults); `rotate` now wipes the evicted key.
- **2026-10-13** — new `ticket12.zig`: TLS 1.2 session tickets (RFC 5077 NewSessionTicket body + SessionTicket extension classifier).
- **2026-10-13** — new `cache.zig`: `SessionCache(max_id_len, max_state_len)` stateful session cache (timeout, oldest eviction, single-use `take`).

- **2026-10-10** — Comparative benchmark `tools/bench.zig` (`zig build bench-tlsresume`, kept instrument kind 3): card Performance 0.90–1.08× the same recipe on OpenSSL EVP (OpenSSL has no standalone resumption API), measured on a quiet host. Tooling only, no code change.

- **2026-10-09** — tests: deterministic fuzz driver `TLSRESUME_FUZZ` over the existing harnesses (plus a generated-record overlay: serialize/encode then parse/decode must round-trip, every truncation and a trailing octet must be refused).
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
