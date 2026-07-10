# ssh

SSH-2.0 transport layer, **client and server**. **Part 1 (this pass): the RFC
4253 transport layer** — version exchange, KEXINIT algorithm negotiation,
curve25519-sha256 (RFC 8731) key exchange, the RFC 4253 §6 Binary Packet
Protocol, and cipher/MAC state — is **fully implemented for both roles** and
validated against live OpenSSH. Userauth (RFC 4252, part 2) and
connection-protocol channels (RFC 4254, part 3) are reserved top-level
placeholders — see `src/root.zig`.

**Status: transport layer IMPLEMENTED (client + server).** `clientHandshake`
(`transport.zig`) performs version exchange, KEXINIT negotiation,
curve25519-sha256 KEX, the Binary Packet Protocol, `chacha20-poly1305@openssh.com`
and `aes256-ctr`/`hmac-sha2-256` ciphers, and host-key *verification*
(ssh-ed25519 / ecdsa-sha2-nistp256 / rsa-sha2-256/512 via the `rsa` module),
establishing an encrypted, host-authenticated `Transport`. `serverHandshake`/
`accept` (`server.zig`) is the responder-role mirror — host-key *signing*
(`HostKey` loaded from an openssh-key-v1 file: ed25519 + rsa; `publicBlob`;
`sign`) plus `curve25519KexServer` — reusing (not duplicating) the client's
packet codec, `KexInit`, `deriveKeys`, and `Transport` struct. Validated with
**live interop against real OpenSSH 10.2p1 both directions**: our client ↔
real `sshd`, and real OpenSSH `ssh` ↔ our server (4 host-key×cipher
combinations), plus KAT/self-consistency tests — 35 tests total, Debug and
ReleaseFast, 0 skipped.

Userauth (RFC 4252) and connection-protocol channels (RFC 4254 —
`openSession`/`exec`) are **still genuine reserved stubs** (`@panic`) — not
implemented yet; see the Backlog in `SPEC.md`.

- **Model after:** RFC 4253 (Transport Layer Protocol) / RFC 4251 (Protocol
  Architecture — wire types) / RFC 4252 (Authentication Protocol, not yet
  implemented) / RFC 4254 (Connection Protocol, not yet implemented) / RFC
  8731 (curve25519-sha256 key exchange). Design reference:
  ringtailsoftware/misshod (MIT) for architecture *shape* only — no source
  copied.
- **Platform:** any. **Role:** both (client + server). **Concurrency:**
  single_owner — one `Transport` instance owns one connection's
  sequence-number/cipher state; no shared/global state.
- **Deps:** `rsa` (this repo's own module) — for `rsa-sha2-256`/
  `rsa-sha2-512` (RFC 8332) host-key signature verify (client) / sign
  (server).
- **Crypto:** Zig `std.crypto` — X25519 (KEX), Ed25519/P-256 (host-key
  signature verify/sign), ChaCha20-Poly1305 / AES-256-CTR (ciphers), SHA-2 /
  HMAC-SHA2-256 (hash/MAC).

## Provenance

Clean-room implementation from RFC 4253/4251/4252/4254 + RFC 8731
(curve25519-sha256). The `chacha20-poly1305@openssh.com` cipher framing
follows the OpenSSH `PROTOCOL`/`PROTOCOL.chacha20poly1305` notes and RFC
5647 — public documentation of OpenSSH's own wire-format extensions, not
OpenSSH source. Design reference: ringtailsoftware/misshod (MIT) —
architecture shape only (the version-exchange → KEXINIT → KEX → NEWKEYS →
Binary-Packet-Protocol layering), no source consulted or copied. No
GPL/LGPL dependency anywhere in this module. See `NOTICE` for the canonical
design-reference entry.

## API

```zig
const ssh = @import("ssh");

// Wire-format helpers (messages.zig):
var w: std.Io.Writer = ...;
try ssh.messages.writeString(&w, "hello");
try ssh.messages.writeMpint(&w, big_endian_magnitude_bytes);
try ssh.messages.writeNameList(&w, &.{ "curve25519-sha256", "curve25519-sha256@libssh.org" });

var r: std.Io.Reader = ...;
const s = try ssh.messages.readString(gpa, &r); // caller frees
const m = try ssh.messages.readMpint(gpa, &r); // caller frees
var list = try ssh.messages.readNameList(gpa, &r);
defer list.deinit();

// Client (transport.zig) — connect + handshake against an already-connected
// reader/writer pair (this module never opens a socket itself):
fn verifyHostKey(key_type: []const u8, key_blob: []const u8) bool {
    // caller's own known_hosts/TOFU/pinning policy — return true to trust.
    _ = key_type;
    _ = key_blob;
    return true;
}

var t = try ssh.transport.connect(&reader, &writer, gpa, verifyHostKey);
// ...or step-by-step:
// var t = ssh.transport.Transport.init(&reader, &writer);
// try t.clientHandshake(gpa, verifyHostKey);

try t.sendPacket(payload);
var buf: [35000]u8 = undefined;
const pkt = try t.recvPacket(&buf);
try t.requestService("ssh-userauth", &buf); // proves the encrypted channel end-to-end

// Server (server.zig) — load a host key and accept a connection:
const host_key = try ssh.server.HostKey.fromOpenSSH(openssh_key_v1_text, null); // ed25519 or rsa
var st = try ssh.server.accept(&reader, &writer, gpa, .{ .host_keys = &.{host_key} });
// ...or step-by-step:
// var st = ssh.transport.Transport.init(&reader, &writer);
// try ssh.server.serverHandshake(&st, gpa, .{ .host_keys = &.{host_key} });

// Reserved for later parts (still stubs):
ssh.userauth(); // RFC 4252, part 2 — @panic
ssh.openSession(); // RFC 4254, part 3 — @panic
ssh.exec(); // RFC 4254, part 3 — @panic
```

See `src/transport.zig` for the full client API (algorithm name-list
constants, `KexInit`, `IdentificationString`/`exchangeVersions`,
`Packet`/`CipherState`/`readPacket`/`writePacket`, `HostKeyVerifier`,
`curve25519Kex`/`deriveKeys`, `Transport`/`connect`) and `src/server.zig` for
the server API (`HostKey`, `ServerConfig`, `curve25519KexServer`,
`serverHandshake`/`accept`), and `SPEC.md` for the design/threat notes and
the userauth/channels backlog.

## Server side (`src/server.zig`) — implemented

The SSH **server** (responder) role is implemented in `src/server.zig`:
`HostKey` (host private-key load from openssh-key-v1 text — ed25519 and rsa
— plus `publicBlob`/`sign`/`algorithmName`), `ServerConfig`, and
`serverHandshake`/`accept` (the responder-role mirror of
`Transport.clientHandshake`/`connect`). It reuses (does not duplicate)
`transport.zig`'s packet codec, `KexInit`, `deriveKeys`, and the `Transport`
struct itself; the responder-role KEX exchange (`curve25519KexServer`) and
host-key *signing* (as opposed to the client's host-key signature
*verification*) are the new, server-only pieces. Live-interop-verified
against a real OpenSSH `ssh` client across ed25519/rsa-sha2-256/rsa-sha2-512
host keys × chacha20-poly1305/aes256-ctr ciphers. See `src/server.zig`'s doc
comments for the full reuse-vs-new breakdown.

## Tests

`zig build test-ssh` — 35 tests, all passing (Debug and ReleaseFast): the
wire-format round-trip tests in `messages.zig` (string/mpint incl. the
high-bit zero-pad rule/name-list, plus an oversize-length rejection test),
KAT/self-consistency tests for KEXINIT encode/decode, curve25519 KEX, key
derivation, and the Binary Packet Protocol ciphers, `HostKey.fromOpenSSH`
fixture tests (ed25519 + rsa, `K_S` checked against `ssh-keygen`'s `.pub`
blob), and **live interop tests against real OpenSSH 10.2p1** (gated:
skipped if `sshd`/`ssh-keygen`/`ssh` aren't on `PATH`) — our client against a
locally spawned real `sshd` (chacha20-poly1305 and aes256-ctr), and a real
`ssh` client against our server (4 host-key×cipher combinations). No stub
`@panic` body is ever invoked by the test suite.
