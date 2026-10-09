# quic-crypto

The **RFC 9001 (Using TLS to Secure QUIC) crypto seam** — Initial-secret
derivation, per-secret key/iv/hp derivation, AEAD packet protection, header
protection, key update, the Retry Integrity Tag (§5.8) and QUIC v2 (RFC 9369). **Engine-agnostic and standalone:** it owns no
QUIC transport state machine (no streams, no loss detection, no ACK logic, no
handshake flight, no packet-number reconstruction) — it transforms
caller-supplied bytes into key material / protected-or-opened bytes and back.
This is the same split the sibling `dtls` module ships (`dtls.keyschedule` +
`dtls.aead` as a pure crypto core with the flight engine left out); QUIC's
transport engine is a much larger separate concern, so here there is no
connection type at all.

**Status: implemented — all crypto bodies are real and KAT-validated against
RFC 9001 Appendix A.** Each submodule keeps a std-only `sanity` test proving
the published vectors chain correctly through `std.crypto` directly
(independent oracle), and the per-function tests drive the SAME vectors
through the public API byte-exact. See `SPEC.md` for the implementation
record and the threat model.

## What it covers (all RFC 9001)

- **`src/initial.zig` — §5.2 Initial secrets.** `initial_salt_v1` (the fixed
  20-byte QUIC v1 salt) + `deriveInitialSecrets(out, client_dcid)` →
  `client_initial_secret` / `server_initial_secret` from the client's chosen
  Destination Connection ID.
- **`src/keyschedule.zig` — §5.1 key/iv/hp + §6 key update.**
  `derivePacketKeys(Hkdf, key_len, out, secret)` → `{ key, iv, hp }`;
  `advanceKeys(Hkdf, key_len, out, secret)` → `{ next_secret, key, iv }` (hp is
  NOT re-derived — §6.1). Supports AES-128-GCM (key_len 16) and, structurally,
  AES-256-GCM + ChaCha20-Poly1305 (key_len 32).
- **`src/protection.zig` — §5.3 packet protection.** `Protection(Aead)` with
  `nonce`/`seal`/`open` — AEAD with `nonce = iv XOR left-pad(packet_number,
  12)` and the unprotected header as additional data. `open` returns a typed
  `error.DecryptionFailed`, never a panic.
- **`src/headerprot.zig` — §5.4 header protection.** `computeMaskAes` /
  `computeMaskChaCha20` (16-byte sample → 5-byte mask) + `apply` (send) and
  `remove` (receive). `remove` models the §5.4.1 ordering hazard: unmask the
  first byte, read the PN length from its low 2 bits, THEN unmask that many
  packet-number bytes.

- **`src/retry.zig` — §5.8 Retry integrity tag.** `computeRetryTag(ver, odcid,
  retry_no_tag)` (server) and `verifyRetryTag(ver, odcid, retry_packet)`
  (client; typed `error.IntegrityFailed`, no allocator).
- **`src/version.zig` — QUIC v1 / v2 (RFC 9369).** `Version` (`.v1`, `.v2`) with
  the per-version Initial salt, HKDF labels, Retry key/nonce and long-header
  packet-type codes. `deriveInitialSecretsFor`, `derivePacketKeysFor`,
  `advanceKeysFor` take a `Version`; the unsuffixed functions stay v1.

## Import

```zig
const quic = @import("quic-crypto");
```

## API surface

```zig
// §5.2 Initial secrets from the client's Destination Connection ID.
var secrets: quic.InitialSecrets = undefined;
quic.deriveInitialSecrets(&secrets, client_dcid); // => .{ client_initial_secret, server_initial_secret }

// §5.1 key/iv/hp from any traffic secret (Initial or TLS-derived).
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
var k: quic.PacketKeys(16) = undefined;
quic.derivePacketKeys(HkdfSha256, 16, &k, &secrets.client_initial_secret); // k = .{ key, iv, hp }

// §5.3 AEAD packet protection (AES-128-GCM shown).
const P = quic.Protection(std.crypto.aead.aes_gcm.Aes128Gcm);
var out: [2048]u8 = undefined;
const n = try P.seal(&k.key, k.iv, packet_number, header_bytes, payload, &out);
// receiver: const m = try P.open(&k.key, k.iv, pn, header_bytes, ciphertext, &buf);

// §5.4 header protection.
const mask = quic.headerprot.computeMaskAes(&k.hp, sample);
try quic.headerprot.apply(packet, .long, pn_offset, pn_len, mask);          // send
const r = try quic.headerprot.remove(packet, .long, pn_offset, mask);        // receive => r.pn_len
```

```zig
// QUIC v2 (RFC 9369): the same calls with a Version; v1 is the default.
var s2: quic.InitialSecrets = undefined;
quic.deriveInitialSecretsFor(.v2, &s2, client_dcid);
var k2: quic.PacketKeys(16) = undefined;
quic.derivePacketKeysFor(.v2, HkdfSha256, 16, &k2, &s2.client_initial_secret);

// §5.8 Retry integrity: server appends the tag, client verifies it.
const tag = try quic.computeRetryTag(.v1, odcid, retry_without_tag);
try quic.verifyRetryTag(.v1, odcid, retry_packet_with_tag); // error.IntegrityFailed on mismatch
```

Choosing the version (RFC 9368 negotiation, Retry uses the original version)
and parsing the version-specific long-header type bits
(`Version.longPacketTypeBits`) are the transport's job.

## Verify

```sh
zig build test-quic-crypto
```

## Provenance

Clean-room from RFC 9001 (Using TLS to Secure QUIC) — an open IETF
specification (not a copyrightable work; see `../../CONVENTIONS.md` §5). This
module reuses TLS 1.3's HKDF-Expand-Label UNCHANGED via
`std.crypto.tls.hkdfExpandLabel` (RFC 9001 §5.1 requires the `"tls13 "`
prefix as-is — the defining contrast with `dtls`, which forks it to
`"dtls13"`). The AEAD-nonce and header-mask constructions are shared in shape
with this repo's `dtls` module and are cited there as a design reference; no
`dtls` code is imported or copied (`deps = .{}`, std-only). RFC 9001 Appendix
A known-answer vectors were cross-checked against a from-scratch Python
`hmac`/`hashlib` HKDF and the `cryptography` package before commit. See
`NOTICE`.
