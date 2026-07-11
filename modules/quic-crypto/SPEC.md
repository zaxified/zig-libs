# quic-crypto — spec

Design + fill-in notes for the next (crypto-implementing) agent. Usage: see
`./README.md`. Attribution/provenance: see `./NOTICE` (module-local for now —
see that file's placement note). Meta tags live in `src/root.zig`'s
`pub const meta` (CONVENTIONS.md §5) and are not restated here.

## What this module is (and is deliberately not)

The RFC 9001 packet-protection **crypto seam**, standalone: it derives keys
and protects/unprotects packet bytes, and owns NO QUIC transport state. No
streams, no loss recovery, no ACK/congestion logic, no handshake flight, no
packet-number reconstruction (the caller passes the already-reconstructed
62-bit packet number). This mirrors `dtls`, which ships `keyschedule.zig` +
`aead.zig` as a pure crypto core with the flight engine deferred — except
QUIC's transport engine is large enough that it is not scaffolded here at all
(there is no `Connection` type). A future `quic` transport module would depend
ON this seam, not the reverse.

## RFC 9001 sections covered — what / why

| § | File | What / why |
|---|---|---|
| §5.1 Packet Protection Keys | `keyschedule.zig` | `key`/`iv`/`hp = HKDF-Expand-Label(secret, "quic key"/"quic iv"/"quic hp", "", len)`. QUIC reuses TLS 1.3 HKDF-Expand-Label UNCHANGED; only the labels differ. |
| §5.2 Initial Secrets | `initial.zig` | The one level whose secret is not TLS-derived: `HKDF-Extract(initial_salt_v1, client_dcid)` then `"client in"`/`"server in"` expand. Lets an on-path element derive Initial keys trivially (Initial packets are not confidential — by design). |
| §5.3 AEAD Usage | `protection.zig` | Seal/open with `nonce = iv XOR left-pad(packet_number, 12)`, AAD = unprotected header. `open` = typed `DecryptionFailed`, never panic. |
| §5.4 Header Protection | `headerprot.zig` | Sample 16 ciphertext bytes at `pn_offset+4`; `mask = AES-ECB(hp, sample)` (AES suites) or `ChaCha20(hp, sample[0..4] LE counter, sample[4..16] nonce, 5 zero bytes)` (ChaCha); XOR `mask[0]`'s low 4 (long) / 5 (short) bits into byte 0, `mask[1..1+pn_len]` into the PN. |
| §6 Key Update | `keyschedule.zig` | `next_secret = HKDF-Expand-Label(secret, "quic ku", "", Hash.length)`; new key+iv from it; **hp unchanged** (§6.1) so header protection keeps covering the Key Phase bit. |

## Recon vs. Zig 0.16 `std.crypto` (single source of truth = root.zig)

Recorded in `src/root.zig`'s module doc. Summary of the exact std paths:

- **THE KEY FINDING:** `std.crypto.tls.hkdfExpandLabel` hardcodes the
  `"tls13 "` label prefix and RFC 9001 §5.1/§5.2 requires it UNCHANGED — so
  this module calls it directly (the `tlsresume.psk` pattern), unlike `dtls`
  which forks the prefix to `"dtls13"` (RFC 9147 §5.9) and therefore
  re-implements `HkdfLabel`. Forking the prefix here would silently produce
  keys no QUIC peer accepts.
- `std.crypto.kdf.hkdf.HkdfSha256` — `.extract` (§5.2), `.prk_length` = 32.
- `std.crypto.aead.aes_gcm.Aes128Gcm` / `Aes256Gcm`,
  `std.crypto.aead.chacha_poly.ChaCha20Poly1305` — the three QUIC v1 AEADs
  (12-byte nonce, 16-byte tag); `TLS_AES_128_CCM_8_SHA256` is excluded from
  QUIC by §5.3, so there is no 12-vs-13-byte-nonce CCM problem here (contrast
  `dtls`'s CCM caveat).
- `std.crypto.core.aes.Aes128` / `Aes256` `.initEnc(key).encrypt(block,
  sample)` — the §5.4.3 AES-ECB header mask.
- `std.crypto.stream.chacha.ChaCha20IETF` `.stream(out, counter, key, nonce)`
  — the §5.4.4 raw-ChaCha20 header mask.

## The dtls constructions mirrored (and how QUIC differs)

No `dtls` code is imported or copied (`deps = .{}`, std-only). The two shared
CONSTRUCTIONS, re-expressed QUIC-shaped:

1. **AEAD nonce** — `dtls.aead.Protection.nonce` (RFC 9147 §4.2.2,
   `static_iv XOR right-aligned seq64`) ≡ `protection.Protection.nonce`
   (RFC 9001 §5.3, `iv XOR left-pad(packet_number, 12)`). Byte-identical
   construction; QUIC calls the input a 62-bit packet number, DTLS a 64-bit
   sequence number. DTLS additionally has an `epoch` param it deliberately
   ignores; QUIC has none.
2. **Header/sequence mask** — `dtls.aead.encryptSequenceNumberAes`
   (`AES-ECB(key, sample)`) and `encryptSequenceNumberChaCha20`
   (`ChaCha20(key, counter=sample[0..4] LE, nonce=sample[4..16])` of zero
   bytes) are the SAME two primitives as `headerprot.computeMaskAes` /
   `computeMaskChaCha20`. **The QUIC difference is the XOR step:** DTLS §4.2.3
   masks only the 1–2 on-wire sequence-number bytes; QUIC §5.4 ALSO masks the
   low 4 (long header) / 5 (short header) bits of the packet's FIRST byte, and
   the PN is a VARIABLE 1–4 bytes. DTLS keeps 2 mask bytes; QUIC keeps 5.

## Threat model

- **Nonce reuse under GCM.** `iv XOR left-pad(pn)` must be unique per
  (key, packet-number). Reusing a packet number under one key is a
  catastrophic AES-GCM nonce reuse (forgery + confidentiality loss). The
  packet-number-uniqueness invariant lives in the (out-of-scope) transport
  engine; this seam must at minimum never truncate or mis-pad the PN into the
  nonce. The `sanity` nonce test pins the byte placement against App. A.
- **Header-protection sample/mask correctness.** The sample is taken at a
  FIXED `pn_offset + 4` (§5.4.2: the PN is assumed 4 bytes for sampling), from
  the ciphertext AFTER packet protection. A wrong offset or a mask computed
  over plaintext leaks or corrupts the PN. Both mask primitives are pinned
  byte-exact against App. A.2/A.3/A.5.
- **PN-length ordering hazard (§5.4.1).** On receive, the 2 bits that encode
  the PN length are themselves masked, so `remove` MUST unmask the first byte
  before it can know how many PN bytes to unmask. Implementing `remove` as
  "unmask a fixed 4 bytes" or reading pn_len before unmasking byte 0 is wrong.
  The `remove` API returns the discovered `pn_len` precisely so the caller
  cannot skip this.
- **Key-update epoch handling (§6).** `advanceKeys` derives the next epoch's
  key/iv but NOT a new hp (§6.1). The transport engine must retain old +
  current (+ next) key sets (§6.3) so packets that straddle a Key-Phase toggle
  still decrypt; discarding old keys too early drops delayed packets. This
  seam only supplies the derivation; the epoch bookkeeping is the caller's.
- **Constant-time AEAD verify.** `Protection.open` must return the typed
  `error.DecryptionFailed` on any tag mismatch — never a panic (attacker
  ciphertext must not reach a panic path) and via std AEAD's constant-time tag
  compare (no timing distinction between failure modes).

## Crypto-implementation pass — DONE (all 9 items landed)

The formerly-stubbed function bodies are all implemented and every
previously skip-guarded test un-guarded and passing byte-exact against
RFC 9001 Appendix A. What each turned out to be, in the original
dependency order:

1. **`keyschedule.derivePacketKeys`** (§5.1) — three
   `std.crypto.tls.hkdfExpandLabel` calls (`"quic key"`/`"quic iv"`/
   `"quic hp"`), prefix unforked. KAT: App. A.1 client + server key/iv/hp
   (AES-128-GCM) + A.5 32-byte chacha set.
2. **`initial.deriveInitialSecrets`** (§5.2) —
   `HkdfSha256.extract(&initial_salt_v1, client_dcid)` then the
   `"client in"`/`"server in"` expands. KAT: App. A.1 initial-secret chain.
3. **`protection.Protection.nonce`** (§5.3) — packet number written
   big-endian into the rightmost 8 of 12 zero bytes, XORed into `iv`
   (mirrors `dtls.aead.Protection.nonce`). KAT: App. A.2 + A.5 nonces.
4. **`protection.Protection.seal` / `.open`** (§5.3) — AEAD
   encrypt/decrypt with the header as AAD, tag appended/split;
   `open` returns typed `error.DecryptionFailed` on any tag mismatch
   (constant-time compare inside std), `error.PacketTooShort` for
   sub-tag-length input — never a panic. KAT: App. A.3 server Initial
   byte-exact seal + round-trip + tamper matrix, A.5 chacha seal.
5. **`headerprot.computeMaskAes`** (§5.4.3) — single-block AES-ECB of the
   sample, Aes128/Aes256 dispatched on `hp_key.len`, first 5 bytes kept.
   KAT: App. A.2 client + A.3 server masks.
6. **`headerprot.computeMaskChaCha20`** (§5.4.4) — ChaCha20 keystream with
   counter = `sample[0..4]` LE, nonce = `sample[4..16]`, over 5 zero
   bytes. KAT: App. A.5 mask.
7. **`headerprot.apply`** (§5.4.1 send) — `packet[0] ^= mask[0] & 0x0f`
   (long) / `0x1f` (short), then `mask[1..1+pn_len]` into the PN bytes;
   bounds-checked before any mutation. KAT: App. A.2 (long, 4-byte PN),
   A.3 (long, 2-byte PN), A.5 (short, 3-byte PN) protected headers.
8. **`headerprot.remove`** (§5.4.1 receive — the ordering hazard) —
   (1) unmask `packet[0]` first, (2) THEN read
   `pn_len = (packet[0] & 0x03) + 1` from the now-cleartext low bits,
   (3) THEN unmask exactly `pn_len` PN bytes; returns the discovered
   `pn_len`. A failed PN bounds check restores byte 0 (atomic failure).
   KAT: App. A.5 recovers pn_len 3 + plaintext header, A.2 recovers
   pn_len 4; round-trips with `apply`.
9. **`keyschedule.advanceKeys`** (§6.1) — `"quic ku"` expand to
   `next_secret`, then `"quic key"`/`"quic iv"` from it; `hp` deliberately
   absent from the result type (§6.1: header protection key unchanged).
   KAT: App. A.5 `"quic ku"` secret; key/iv checked against the sanity
   derivation of that secret.

## Verification

The `sanity` tests prove the constants + std constructions inside the test
binary (independent oracle), and the API tests route the public surface
through the SAME expected values — both green in Debug and ReleaseFast.
Beyond the App. A KATs, a live wire-interop test (against ngtcp2 / quiche /
msquic Initial packets) belongs to the eventual `quic` transport consumer,
not to this crypto seam — this module has no socket and no packet framing to
drive such a test on its own.
