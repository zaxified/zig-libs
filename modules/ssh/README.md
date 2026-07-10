# ssh

SSH-2.0 client. **Part 1 (this scaffold): the RFC 4253 transport layer** —
version exchange, KEXINIT algorithm negotiation, curve25519-sha256 (RFC 8731)
key exchange, the RFC 4253 §6 Binary Packet Protocol, and cipher/MAC state.
Userauth (RFC 4252, part 2) and connection-protocol channels (RFC 4254, part
3) are reserved top-level placeholders — see `src/root.zig`.

**Status: SKELETON / NOT IMPLEMENTED — reserved API surface only, awaiting
crypto-implementation pass.** Every function that touches crypto or protocol
logic (KEXINIT encode/decode, version exchange, KEX, key derivation, Binary
Packet Protocol read/write, the client handshake) is a real, fully-typed
`@panic("TODO(agent): ...")` stub — the types and signatures are final, the
bodies are not implemented. `zig build test-ssh` passes today because tests
only construct values and never call a stub. The only real, working code in
this module is the pure RFC 4251 §5 wire-format codec in `src/messages.zig`
(`writeString`/`readString`, `writeMpint`/`readMpint`,
`writeNameList`/`readNameList`) — not crypto, just byte-string/integer/list
framing — which has passing round-trip unit tests.

- **Model after:** RFC 4253 (Transport Layer Protocol) / RFC 4251 (Protocol
  Architecture — wire types) / RFC 4252 (Authentication Protocol, not yet
  implemented) / RFC 4254 (Connection Protocol, not yet implemented) / RFC
  8731 (curve25519-sha256 key exchange). Design reference:
  ringtailsoftware/misshod (MIT) for architecture *shape* only — no source
  copied.
- **Platform:** any. **Role:** client. **Concurrency:** single_owner — one
  `Transport` instance owns one connection's sequence-number/cipher state; no
  shared/global state.
- **Deps:** `rsa` (this repo's own module) — for `rsa-sha2-256`/
  `rsa-sha2-512` (RFC 8332) host-key signature verification during KEX.
- **Crypto (once implemented):** Zig `std.crypto` — X25519 (KEX),
  Ed25519/P-256 (host-key signature verification), ChaCha20-Poly1305 /
  AES-256-CTR (ciphers), SHA-2 / HMAC-SHA2-256 (hash/MAC).

## Provenance

Clean-room implementation from RFC 4253/4251/4252/4254 + RFC 8731
(curve25519-sha256). The `chacha20-poly1305@openssh.com` cipher framing
(and, when implemented, `aes-gcm`-family framing) follows the OpenSSH
`PROTOCOL`/`PROTOCOL.chacha20poly1305` notes and RFC 5647 — public
documentation of OpenSSH's own wire-format extensions, not OpenSSH source.
Design reference: ringtailsoftware/misshod (MIT) — architecture shape only
(the version-exchange → KEXINIT → KEX → NEWKEYS → Binary-Packet-Protocol
layering), no source consulted or copied. No GPL/LGPL dependency anywhere in
this module. See `NOTICE` for the canonical design-reference entry.

## API

```zig
const ssh = @import("ssh");

// Wire-format helpers (messages.zig) — implemented for real:
var w: std.Io.Writer = ...;
try ssh.messages.writeString(&w, "hello");
try ssh.messages.writeMpint(&w, big_endian_magnitude_bytes);
try ssh.messages.writeNameList(&w, &.{ "curve25519-sha256", "curve25519-sha256@libssh.org" });

var r: std.Io.Reader = ...;
const s = try ssh.messages.readString(gpa, &r); // caller frees
const m = try ssh.messages.readMpint(gpa, &r); // caller frees
var list = try ssh.messages.readNameList(gpa, &r);
defer list.deinit();

// Transport (transport.zig) — types/signatures final, bodies are stubs:
var t = ssh.transport.Transport.init(reader, writer);
try t.clientHandshake(gpa, verifyHostKeyFn); // @panic until implemented
try t.sendPacket(payload); // @panic until implemented
const pkt = try t.recvPacket(&buf); // @panic until implemented

// Reserved for later parts (also stubs):
ssh.userauth(); // RFC 4252, part 2 — @panic
ssh.openSession(); // RFC 4254, part 3 — @panic
ssh.exec(); // RFC 4254, part 3 — @panic
```

See `src/transport.zig` for the full reserved API surface (algorithm
name-list constants, `KexInit`, `IdentificationString`/`exchangeVersions`,
`Packet`/`CipherState`/`readPacket`/`writePacket`, `HostKeyVerifier`,
`curve25519Kex`/`deriveKeys`, `Transport`) with each stub's RFC section
reference in its doc comment, and `SPEC.md` for the design/threat notes and
implementation backlog.

## Tests

`zig build test-ssh` — passes today: `messages.zig`'s wire-format round-trip
tests (string/mpint incl. the high-bit zero-pad rule/name-list, plus an
oversize-length rejection test) and `transport.zig`'s/`root.zig`'s
construction-only smoke tests (algorithm lists are non-empty, `CipherState`/
`Packet`/`Transport` are constructible, `meta.deps` names `rsa`) — no stub
body is ever invoked by the test suite.
