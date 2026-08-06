# aeadframe

A per-key AEAD **record/frame layer**: once two peers share a 32-byte key,
every message is sealed/opened with guaranteed nonce uniqueness, anti-replay,
and epoch rekeying — the IPsec ESP / DTLS 1.3 record layer distilled to a
reusable primitive. It is **generic over the AEAD**: a comptime
`Channel(Aead)` instantiated for **ChaCha20-Poly1305** (via the `chachapoly`
sibling) and **AES-256-GCM** (via std), exposed as `ChaChaChannel` and
`AesGcmChannel`. Both are 32-byte key / 12-byte nonce / 16-byte tag, so the
seam is clean.

This module **composes** existing AEADs — it implements no cipher or MAC. The
12-byte nonce is derived deterministically from the record's `(epoch, seq)`, so
it is never reused under one key; the sequence counter is monotonic and refuses
to wrap; the receiver runs a sliding-window replay filter; and the
caller-supplied `aad` cryptographically pins each record to its context (tenant
/ I-SID / channel), the isolation binding for the S1b per-tenant L2VPN case.

**Key establishment is out of scope.** The 32-byte key is an input — a
Noise/HPKE/X25519 handshake (a caller or future module) produces it. See
[SPEC.md](SPEC.md).

**Status:** complete — round-trip, tamper, nonce-uniqueness, anti-replay,
epoch/rekey, a byte-anchored framing KAT, and an untrusted-decode fuzz harness,
all green against **both** instantiations in Debug + ReleaseFast.

| File | Contents |
|---|---|
| `channel.zig` | `Channel(Aead)` → `Sealer` (seal + `bumpEpoch`/`rekey`) and `Opener` (open + replay window + `bumpEpoch`/`rekey`); the `ChaChaChannel`/`AesGcmChannel` instantiations; the framing KAT, positive-control sentinels, and the `open` fuzz harness |
| `record.zig` | Wire format (`Header`, `parse`, `encode`) and the `(epoch, seq) → nonce` derivation |
| `replay.zig` | `ReplayWindow` — the bounded sliding-window anti-replay filter |

## Import

```zig
const af = @import("aeadframe");
```

## Use

```zig
// Both ends share `key` (from a handshake — not this module's job) and start
// at epoch 0. Pick ChaChaChannel or AesGcmChannel; the API is identical.
var s = af.ChaChaChannel.Sealer.init(key, 0);
var o = af.ChaChaChannel.Opener.init(key, 0);

// Seal: aad binds the record to a context (here, a tenant id). Zero allocation.
var rec: [af.ChaChaChannel.Sealer.sealedLen(msg.len)]u8 = undefined;
const n = try s.seal(&rec, msg, "tenant-A");

// Open: the identical aad is required; a replay, wrong epoch, tamper, or
// truncation returns a typed error and never yields garbage plaintext.
var pt: [msg.len]u8 = undefined;
const m = try o.open(&pt, rec[0..n], "tenant-A");
// pt[0..m] == msg
```

Contracts (full detail in [SPEC.md](SPEC.md)):

- **Nonce uniqueness.** `nonce = epoch(4B, big-endian) ‖ seq(8B, big-endian)`.
  The map is injective in `(epoch, seq)`; `seq` is strictly monotonic per epoch
  and `seal` returns `error.SequenceExhausted` rather than wrapping. No two
  distinct records under one key ever share a nonce.
- **Anti-replay.** The opener holds a sliding window (default 64) over sequence
  numbers: a duplicate or too-old `seq` returns `error.Replayed`;
  reordered-but-fresh is accepted. The window is committed **only after** the
  AEAD tag verifies, so a forged record cannot burn a legitimate slot.
- **Rekey / epoch.** `bumpEpoch` keeps the key and advances the epoch (reset
  `seq`, fresh window) — nonce-safe because the epoch is *in* the nonce and
  strictly increases. `rekey(new_key, epoch)` installs a caller-supplied fresh
  key (adds forward secrecy) and refuses with `error.NonceSpaceReuse` if asked
  to re-install the *current* key at an epoch that does not advance — that
  would reset `seq` inside a spent nonce space (see SPEC.md §4 for the one
  residual case it cannot see). An old-epoch record is rejected
  (`error.EpochMismatch`); a new-epoch record may reuse an old `seq` because it
  maps to a fresh nonce.
- **AAD binding.** The `aad` is authenticated into the tag; a record sealed
  under tenant A does not open under tenant B (`error.AuthenticationFailed`).

## Import graph

```
aeadframe → chachapoly (ChaCha20-Poly1305)
          → std.crypto.aead.aes_gcm.Aes256Gcm
```

## Verify

```
zig build test-aeadframe                       # Debug
zig build test-aeadframe -Doptimize=ReleaseFast
zig fmt --check modules/aeadframe
```

Provenance: clean-room from the public IPsec ESP (RFC 4303) and DTLS 1.3
(RFC 9147 §5) record-layer designs and the anti-replay window of RFC 6479 —
no third-party source ported or studied. The AEADs are composed, not
reimplemented (`chachapoly` and std carry their own KATs). Design rationale
and the byte-exact wire format are in [SPEC.md](SPEC.md); no `NOTICE` entry
(clean-room from public specs).
