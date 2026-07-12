# tlsresume — spec

Design + fill-in notes for the next (crypto-implementing) agent. Usage: see
`./README.md`. Attribution/provenance: see `./NOTICE` (module-local for now —
mirrors `dtls`'s placement note; fold into the root `NOTICE` before this
module ships — see that file).

## What this is, in one paragraph

Server-side TLS 1.3 session-ticket resumption (RFC 8446), engine-agnostic:
the TLS engine (this repo's `dtls` targets DTLS 1.3 PSK mode and explicitly
declares resumption out of scope; the vendored `ianic/tls.zig` implements
only the CLIENT side of resumption) passes in transcript-hash bytes and
already-negotiated secrets, and this module returns derived PSKs,
binder-verify decisions, ticket wire bytes, and STEK-sealed ticket blobs. It
never parses a ClientHello, never owns a handshake state machine, never
touches a socket.

## RFC 8446 sections covered, one line each

| Section | What / why |
|---|---|
| §4.2.11 | `pre_shared_key` extension shape: a list of `PskIdentity` (opaque identity + `obfuscated_ticket_age`) and a separate, positionally-aligned list of binders — `select.zig`'s `OfferedIdentity`/`selectPsk` model this split directly. |
| §4.2.11.1 | Obfuscated ticket age: `obfuscated_ticket_age = (age_ms + ticket_age_add) mod 2^32`; the server recomputes and freshness-checks it — `replay.zig`'s `obfuscateAge`/`deobfuscateAge`/`withinFreshnessWindow` (all REAL, no crypto). |
| §4.2.11.2 | The PSK binder: `HMAC(finished_key, Transcript-Hash(Truncate(ClientHello)))`, `finished_key` derived from `binder_key` — `psk.zig`'s `computeBinder`/`verifyBinder` (REAL; the single highest-severity item in this module). |
| §4.6.1 | `NewSessionTicket` wire shape (`ticket_lifetime`/`ticket_age_add`/`ticket_nonce`/`ticket`/`extensions`, incl. `early_data`) — `ticket.zig` (REAL, KAT-validated against the actual RFC 8448 §3 wire bytes). |
| §4.2.10 | `early_data`: the `max_early_data_size` advertisement lives in `ticket.zig` (`maxEarlyDataSize`/`earlyDataExtension`); the 0-RTT key derivation the advertisement enables is `earlydata.zig` (REAL, see the 0-RTT section below). |
| §7.1 | The key-schedule labels this module needs: `PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)`, `Early Secret = HKDF-Extract(0, PSK)`, `binder_key = Derive-Secret(early_secret, "res binder", "")` — `psk.zig`'s `derivePsk`/`earlySecret`/`binderKey` (all REAL) — plus the early branch `Derive-Secret(early_secret, "c e traffic"/"e exp master", ClientHello)` — `earlydata.zig` (REAL). |
| §7.3 | Traffic-key calculation for early-data records: `key = HKDF-Expand-Label(secret, "key", "", key_len)`, `iv = …("iv", "", 12)` — `earlydata.zig`'s `earlyTrafficKeyIv` (REAL). |
| §8 / §8.1 / §8.2 | Anti-replay for single-use PSKs / 0-RTT: single-use tickets (chosen shape here), ClientHello recording, freshness-only — `replay.zig`'s `StrikeRegister` (REAL, bounded fail-closed eviction). |

## Design & invariants

**Layered like `dtls`/`noise` (this repo's other TLS-family scaffolds):**
codec/bookkeeping is real and allocation-light; the AEAD/HKDF/HMAC crypto
core is deferred. See `root.zig`'s module doc table for the exact
real-vs-stub split per file. This is a deliberate split, not laziness: the
codec (`ticket.zig`) and bookkeeping (`stek.zig`'s ring rotation,
`select.zig`'s `SessionState` packing) have ONE correct byte layout each,
provably matched against a real wire trace; the crypto core involves
security-critical judgment calls (nonce-reuse policy, constant-time
compares, replay-window sizing) that deserve a dedicated, carefully
KAT-verified pass rather than a first guess baked into a scaffold.

**Engine-agnostic, no owned state machine.** Every function takes
already-computed bytes (transcript hashes, secrets, wall-clock readings) as
parameters; nothing here calls a clock, generates randomness, or reads a
socket. This mirrors `dtls.keyschedule`/`dtls.aead` (pure functions over
caller-supplied bytes) rather than `dtls.Connection` — there is no
`tlsresume.Connection` because this module is not a transport, it is the
resumption *policy + crypto* seam a transport-owning engine calls into.

**STEK ticket-blob layout is `tlsresume`'s own choice, not RFC-mandated.**
RFC 8446 §4.6.1 explicitly leaves `ticket`'s contents to the server
("entirely up to the server"). This module picks:

```
ticket blob  := key_id(1) || nonce(12) || ciphertext(N) || tag(16)    (stek.zig)
plaintext    := resumption_master_secret(32|48) || nonce_len(1) || ticket_nonce
             || issued_at_ms(8, BE i64) || ticket_age_add(4, BE u32)  (select.zig's SessionState)
```

`stek.zig` itself is agnostic to what it seals (any `[]const u8`);
`select.zig`'s `SessionState(rms_len)` defines the canonical minimal
plaintext this module's own `selectPsk` expects, documented as a REQUIRED
PREFIX so an engine can append its own extra fields (ALPN, negotiated
group, early-data limits, ...) after it without breaking `parse`.

## Threat model

- **Binder forgery (highest severity).** `psk.computeBinder`/`verifyBinder`
  (RFC 8446 §4.2.11.2) is the one check that proves the client actually
  possesses the PSK derived from a specific prior connection's
  `resumption_master_secret` — skip it, or compare it with a variable-time
  `std.mem.eql`, and an attacker who merely observed a ticket on the wire
  (tickets are NOT confidential in transit — they are bearer tokens
  protected only by the STEK seal) can splice it into their own connection.
  `verifyBinder` compares with `std.crypto.timing_safe.eql`, and the
  `computeBinder` HMAC math is KAT-validated byte-exact against RFC 8448 §4
  — the constant-time-compare invariant is locked in at the type-signature
  level, not left to callers to remember.
- **Ticket replay.** A captured ticket + its (also captured, or freshly
  computed by the attacker if they also have the PSK) binder is fully
  reusable unless the server enforces something from RFC 8446 §8 — this
  module's chosen shape is `replay.StrikeRegister`'s single-use strike
  register (§8.1), implemented with a bounded fail-closed eviction policy
  (see `replay.zig`'s module doc); a server that
  skips this by policy (accepting resumption PSKs multiple times, common
  for the NON-0-RTT case — RFC 8446 only mandates single-use enforcement
  for 0-RTT/early-data acceptance, §8) is not "wrong" per se, but the type
  exists so a server that does want it has a real seam to call.
- **STEK compromise / rotation.** `stek.StekRing`'s bounded `depth` limits
  the blast radius of one leaked key (only tickets sealed under that one
  rotation slot are affected) and enables forward-secrecy-by-rotation (an
  operator that rotates keys and discards old ones makes tickets sealed
  under the discarded key permanently unopenable, i.e. a coarse-grained
  ticket lifetime ceiling independent of `ticket_lifetime`). `rotate`'s
  caller supplies the key material — this module never generates key bytes
  itself, so it carries no CSPRNG-quality risk of its own; that
  responsibility sits with the engine, consistent with this repo's
  no-hidden-globals rule (CONVENTIONS.md §2).
- **Const-time compare, generally.** Every crypto-critical value compare in
  this module's eventual implementation (binder, and — if the fill-in pass
  adds it — the AEAD tag inside `stek.open`, though `std.crypto.aead.*`
  already compares tags in constant time internally) MUST use
  `std.crypto.timing_safe.eql`, never `std.mem.eql`. `psk.verifyBinder`
  already does; `stek.open`'s crypto-implementation pass must preserve this
  for anything it adds beyond the AEAD library call itself.
- **Ticket-age spoofing.** `replay.withinFreshnessWindow` bounds how far a
  client's claimed `obfuscated_ticket_age` may diverge from the server's own
  elapsed-time measurement (RFC 8446 §4.2.11.1) — this is a DoS/early-data
  replay mitigant, not a confidentiality boundary (a client can always claim
  ANY age within the window; the point is bounding how large a replay
  window an attacker gets, not proving a specific age).

## Crypto-implementation pass — DONE (all 7 items landed)

The formerly-stubbed function bodies are all implemented and their
previously skip-guarded tests un-guarded and passing. What each turned out
to be, in the original implementation order:

1. `psk.zig: earlySecret` — RFC 8446 §7.1 `HKDF-Extract(salt = 0^Hash.length,
   IKM = PSK)` via `Hkdf.extract`. KAT: RFC 8448 §4 early_secret.
2. `psk.zig: derivePsk` — RFC 8446 §7.1/§4.6.1
   `HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce,
   Hash.length)` via `std.crypto.tls.hkdfExpandLabel` (its hardcoded
   `"tls13 "` prefix is exactly right here). KAT: RFC 8448 §4 PSK.
3. `psk.zig: binderKey` — RFC 8446 §7.1 `Derive-Secret(early_secret, "res
   binder", "")` — the label is `"res binder"`, NOT `"ext binder"`
   (external-PSK case, which this module does not implement — see
   `dtls.keyschedule.binderKey` for that sibling case). KAT: RFC 8448 §4
   binder_key.
4. `psk.zig: computeBinder` — RFC 8446 §4.2.11.2: `finished_key =
   HKDF-Expand-Label(binder_key, "finished", "", Hash.length)`, then
   `HMAC(finished_key, transcript_hash)`. **Highest-severity function in
   the module** — see the threat model above. KAT: RFC 8448 §4
   finished_key + binder, byte-exact.
5. `stek.zig: StekRing(depth).seal` / `.open` — AES-256-GCM over the blob
   layout above, with the 1-byte key id authenticated as the AEAD
   associated data (a blob cannot be re-pointed at a different ring slot).
   Fresh nonce per seal is caller-supplied (no-owned-RNG design); any tag
   mismatch is the typed `error.DecryptionFailed`, never a panic on
   attacker-controlled bytes.
6. `replay.zig: StrikeRegister.checkAndMark` — RFC 8446 §8/§8.1 single-use
   anti-replay: an identifier repeats within `window_ms` -> reject;
   capacity-bounded with expired-entry eviction; a register full of live
   entries fail-closes on new identifiers (rejecting resumption only forces
   a full handshake — never evicts a live entry, which would re-open its
   replay window). See `replay.zig`'s module doc for the full policy.
7. `select.zig: selectPsk` — composes all of the above (unseal → parse →
   freshness → derive PSK → verify binder → strike register → first match
   wins). The binder is verified BEFORE the strike register is marked, so a
   forged binder can never consume a real ticket's single-use slot (no
   attacker-driven DoS of the legitimate client's resumption).

## 0-RTT early-data key derivation — implemented (`earlydata.zig`)

A follow-up pass on top of the crypto core above: the early-data branch of
the RFC 8446 §7.1 key schedule, so a resuming client's 0-RTT records can be
protected/opened before the handshake completes.

- `clientEarlyTrafficSecret` = `Derive-Secret(early_secret, "c e traffic",
  ClientHello)`; `earlyExporterMasterSecret` = `Derive-Secret(early_secret,
  "e exp master", ClientHello)`. Both take the transcript hash of the
  **complete** ClientHello (binders included) — deliberately distinct from
  `psk.computeBinder`'s **truncated**-ClientHello hash; the doc comments and
  KATs pin this distinction because it is the one wrong input a caller can
  plausibly pass.
- `earlyTrafficKeyIv` = the §7.3 record-protection pair (`"key"`/`"iv"`
  labels, 12-byte IV; key_len 16 or 32 per the §B.4 suites; SHA-256 and
  SHA-384 via the comptime `Hkdf` parameter, as everywhere in this module).
- `EarlyDataContext(Hkdf, key_len).derive(psk, ch_hash)` — one-call
  convenience: PSK → `early_secret` (REUSES `psk.earlySecret`) →
  `client_early_traffic_secret` → key/iv.
- What it does NOT own (cross-referenced, not reimplemented): the
  `max_early_data_size` advertisement is `ticket.zig`'s (§4.2.10), and the
  anti-replay defense 0-RTT REQUIRES (§8, §2.3 — early data is replayable
  without it) is `replay.StrikeRegister` + `withinFreshnessWindow`. Deriving
  early keys without wiring those is a replay vulnerability, not a working
  configuration.

**KAT sourcing for 0-RTT — official, not self-consistency:** RFC 8448 §4
("Resumed 0-RTT Handshake") is itself a full 0-RTT trace and carries
byte-exact vectors for the entire early branch: the `"tls13 c e traffic"`
and `"tls13 e exp master"` derivations (complete-ClientHello hash
`08ad0f…`), the early write key/iv, and even the client's actual encrypted
early-data record (payload `"ABCDEF"`). `earlydata.zig`'s tests assert all
of these byte-exact — including AEAD-opening the trace's real record with
the derived key/iv and a seal/open round-trip in the other direction. The
one thing RFC 8448 does NOT carry is a SHA-384 0-RTT vector (its trace is
TLS_AES_128_GCM_SHA256 only), so the SHA-384/key_len-32 test asserts
internal consistency (manual chain == convenience type, AES-256-GCM
seal/open round-trip) rather than an external byte-exact target — the same
honest split `psk.zig`'s SHA-384 test already makes.

## KAT sourcing (RFC 8448, fetched fresh for this module)

`psk.zig`'s, `earlydata.zig`'s, and `replay.zig`'s KAT constants were
extracted directly from <https://www.rfc-editor.org/rfc/rfc8448> §3
("Simple 1-RTT Handshake", whose NewSessionTicket trace `ticket.zig`
decodes byte-for-byte) and §4 ("Resumed 0-RTT Handshake", whose
PSK/binder-key/finished-key/binder chain `psk.zig` targets and whose
early-traffic-secret/early-key-iv/encrypted-early-record trace
`earlydata.zig` targets). This is the SAME source `dtls.keyschedule.zig` already
uses for its own (external-PSK, `"ext binder"`) binder KAT — the
resumption-PSK chain here diverges from that one exactly at the `"res
binder"` vs `"ext binder"` label, per RFC 8446 §7.1's two separate PSK
binder-key derivations.

## Verification status

1. **KAT (done):** the formerly skip-guarded tests in
   `psk.zig`/`replay.zig`/`stek.zig`/`select.zig` are un-guarded and pass
   against their byte-exact RFC 8448 targets (Debug and ReleaseFast).
2. **Live interop, most realistic given PSK/resumption needs no certificate
   infrastructure:** stand up `openssl s_server -tls1_3 ...`, complete a
   full handshake, capture the real `NewSessionTicket` it sends, and open
   it as a black box (bytes only, obviously not this server's own STEK
   format) through `ticket.NewSessionTicket.decode` as a second, independent
   wire-format cross-check beyond the RFC 8448 trace. For the SERVER side
   specifically (this module's actual target), the natural oracle is an
   OpenSSL or BoringSSL TLS 1.3 CLIENT resuming against a minimal engine
   built on top of `tlsresume` + `dtls`'s sibling TLS 1.3 handshake pieces
   (or any other RFC-8446-compliant client) — not yet stood up in this pass.
3. **Self-consistency (mirrors `dtls.Connection`'s pattern):** issue a
   ticket, seal it, "resume" against the SAME process's `selectPsk`, and
   assert the round-tripped PSK matches what a hypothetical peer would have
   derived independently from the same `resumption_master_secret` +
   `ticket_nonce`.
