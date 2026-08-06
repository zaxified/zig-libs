# megolm

Matrix's **Megolm group ratchet**
(gitlab.matrix.org/matrix-org/olm, [megolm.md][spec]): a one-way hash
ratchet for many-recipient group messaging, plus Ed25519 signatures for
authenticity. The third real-world group-messaging construction in this
collection, alongside `signal` (pairwise Double Ratchet) and `mls`
(RFC 9420) — Megolm's niche is "one sender, many receivers, no
peer-to-peer fan-out": a sending `OutboundSession` encrypts a message once
and every recipient holding a copy of the ratchet at-or-before that
message's index can decrypt it, without replaying anything key-by-key.

**Status: complete** for everything in scope (see "Scope" below).
`ratchet.zig`'s hash ratchet, `cipher.zig`'s HKDF+AES-CBC+HMAC layer,
`message.zig`/`session_key.zig`'s wire codecs, and `session.zig`'s
`OutboundSession`/`InboundGroupSession` are implemented and tested,
including byte-exact anchors from libolm's own test suite. See
[SPEC.md](SPEC.md) for the anchoring grade of each area and the threat
model.

## Scope

In scope: an outbound session (create, advance, export the session key at
the current index, encrypt+sign a message), an inbound session (import a
session key, fast-forward to a given index, decrypt+verify), the spec's
wire/export formats (including the base64 encodings and the session-export
format), and Ed25519 signing/verification of the message frame.

Out of scope: Olm (the pairwise partner protocol — see `signal` for a
different pairwise ratchet with the same shape of problem), the Matrix
event-JSON layer (`m.room_key`/`m.room.encrypted` content shapes — this
module hands back/accepts raw bytes and base64 strings, never JSON), key
backup (the separate, PBKDF2-encrypted "session export file" format some
Matrix clients use for off-device backup — not part of the Megolm spec
itself), and anything requiring a server.

## Import

```zig
const megolm = @import("megolm");
```

## Walkthrough

```zig
// Sender:
var out = megolm.OutboundSession.init(io);
defer out.deinit();

// Share this with the group over a secure (e.g. Olm-encrypted) channel:
const session_key = try out.sessionKey();
const session_key_b64 = try session_key.toBase64(allocator);
defer allocator.free(session_key_b64);

var msg = try out.encrypt(allocator, "hello group");
defer msg.deinit(allocator);
const wire = try msg.toBase64(allocator); // send this + out.sessionId()

// Recipient, after receiving `session_key_b64` over the secure channel:
const key = try megolm.SessionKey.fromBase64(allocator, session_key_b64); // self-verifies its signature
var in = try megolm.InboundGroupSession.fromSessionKey(key);
defer in.deinit();

var incoming = try megolm.Message.fromBase64(allocator, wire);
defer incoming.deinit(allocator);
var decrypted = try in.decrypt(allocator, &incoming);
defer decrypted.deinit(allocator);
// decrypted.plaintext == "hello group"
```

Sharing your ability to decrypt history with someone else from a point
forward, without handing over earlier messages, is `InboundGroupSession.
exportAt(index)` → `ExportedSessionKey` (megolm.md's "session export
format" — identical to the session-sharing format minus the signature,
since re-signing a ratcheted-forward copy isn't possible without the
original private key).

## Layout

| File | Contents |
|---|---|
| `src/root.zig` | `meta`, flat re-exports, dark-tests aggregator |
| `src/ratchet.zig` | The 128-byte four-part hash ratchet: `advanceStep` (one message), `advanceToUnchecked` (unconditional fast-forward incl. 32-bit wraparound), guarded `advanceTo` (`error.CannotRatchetBackward`) |
| `src/cipher.zig` | HKDF-SHA-256 key derivation (`AES_KEY‖HMAC_KEY‖AES_IV`, info `"MEGOLM_KEYS"`) + AES-256-CBC/PKCS#7 (over the sibling `aescbc` module) + truncated HMAC-SHA-256 |
| `src/message.zig` | The wire message codec (version + LEB128-tagged payload + MAC + signature byte ranges) — no keys, no crypto. A decoded `Message` retains the **received** signed span, so verification authenticates the bytes that arrived rather than a canonical re-encoding (`decode` → `encode` is byte-identical) |
| `src/session_key.zig` | The signed session-sharing format (`SessionKey`, self-verifying) and unsigned session-export format (`ExportedSessionKey`) |
| `src/session.zig` | `OutboundSession` (encrypt+sign+advance) and `InboundGroupSession` (verify signature → locate ratchet → verify MAC → decrypt) |
| `src/kat_test.zig` | External anchors (libolm ratchet vectors + a real libolm session-key+message pair) and the reject-teeth battery |

## Import graph

```
megolm → aescbc → std.crypto.core.aes
       → std.crypto.kdf.hkdf.HkdfSha256 / std.crypto.auth.hmac.sha2.HmacSha256 /
         std.crypto.sign.Ed25519 / std.base64
```

## Verify

```
zig build test-megolm
zig fmt --check modules/megolm/
```

Provenance: see [NOTICE](NOTICE).

[spec]: https://gitlab.matrix.org/matrix-org/olm/-/blob/master/docs/megolm.md
