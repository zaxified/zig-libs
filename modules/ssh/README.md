# ssh

A complete pure-Zig **SSH-2.0 client and server**: transport (RFC 4253), user
authentication (RFC 4252) and the connection protocol (RFC 4254) — i.e.
everything needed to **run a remote command over SSH**, both as the client and
as the server. No `@panic` stubs remain in this module.

**Status: parts 1-3 IMPLEMENTED (client + server).**

- **Part 1 — transport** (`transport.zig` client, `server.zig` server): version
  exchange, KEXINIT negotiation, `mlkem768x25519-sha256` / `curve25519-sha256`
  (RFC 8731) / `diffie-hellman-group14-sha256` / `-group16-sha512` key
  exchange, the RFC 4253 §6 Binary Packet Protocol,
  `chacha20-poly1305@openssh.com` / `aes256-ctr`+`hmac-sha2-256` /
  `aes{128,256}-gcm@openssh.com` ciphers, and host-key *verification* (client)
  / *signing* (server) for ssh-ed25519, rsa-sha2-256/512 (via the `rsa` module)
  and ecdsa-sha2-nistp256. Once a handshake completes, `Transport.negotiated`
  reports the negotiated KEX/host-key/cipher/MAC wire names (both roles) —
  diagnostics parity with `ssh -v`'s negotiation banner.
- **Part 2 — userauth** (`userauth.zig`): the `publickey` method (RFC 4252 §7)
  including the two-phase query → `SSH_MSG_USERAUTH_PK_OK` → signed-request
  flow, and the `password` method (§8), plus `_FAILURE`/`_SUCCESS`/`_BANNER` —
  both roles. The signature is bound to the transport's session id (see
  SPEC.md §2: that binding is the security property).
- **Part 3 — connection protocol** (`connection.zig`): `"session"` channels
  with real RFC 4254 §5.2 window/flow control, `CHANNEL_DATA` /
  `_EXTENDED_DATA` (stderr) / `_EOF` / `_CLOSE`, and the `"exec"` /
  `"subsystem"` requests plus §6.10 `exit-status` — both roles.

Validated with **live interop against real OpenSSH 10.2p1 in both
directions, including authentication and command execution**: our client
authenticates to a spawned real `sshd` with a public key and runs a command
(asserting stdout, stderr and exit status), and a real `ssh` client
authenticates to our server and runs one. Green in Debug and ReleaseFast,
no skips.

- **Model after:** RFC 4253 (Transport) / RFC 4251 (Architecture — wire types)
  / RFC 4252 (Authentication) / RFC 4254 (Connection) / RFC 8731
  (curve25519-sha256) / RFC 8332, 8709, 5656 (host+user key algorithms).
  Design reference: ringtailsoftware/misshod (MIT) for architecture *shape*
  only — no source copied.
- **Platform:** linux — the transport's `fillRandom` is a raw `getrandom(2)`
  loop on the Binary-Packet-Protocol write path, so a non-Linux target fails to
  compile, it does not silently degrade. **Role:** both (client + server). **Concurrency:**
  single_owner — one `Transport` instance owns one connection's
  sequence-number/cipher state; no shared/global state.
- **Deps:** `rsa` (this repo's own module) — for `rsa-sha2-256`/`rsa-sha2-512`
  (RFC 8332) signature verify/sign, as host keys and as user keys.
- **Crypto:** Zig `std.crypto` — X25519 + ML-KEM-768 (KEX), Ed25519/P-256
  (signatures), ChaCha20-Poly1305 / AES-CTR / AES-GCM (ciphers), SHA-2 /
  HMAC-SHA2-256.

## Provenance

Clean-room implementation from RFC 4253 (SSH Transport Layer Protocol),
RFC 4251 (SSH Protocol Architecture — the mpint/string/name-list wire types),
RFC 4252 (Authentication Protocol), RFC 4254 (Connection Protocol) and RFC 8731
(curve25519-sha256 key exchange). The `chacha20-poly1305@openssh.com` cipher
framing and (when implemented) `aes-gcm`-family framing follow the OpenSSH
`PROTOCOL`/`PROTOCOL.chacha20poly1305` notes and RFC 5647 — public
documentation of OpenSSH's own protocol extensions, not OpenSSH source.
Design reference: ringtailsoftware/misshod (MIT) — architecture SHAPE only,
no source copied. Crypto primitives come from Zig `std.crypto` (X25519,
Ed25519, ChaCha20-Poly1305, P-256, SHA-2, HMAC) plus this repo's own `rsa`
module for rsa-sha2 (RFC 8332) host-key verification. No GPL/LGPL source
consulted or copied anywhere in this module.
## API

```zig
const ssh = @import("ssh");

// ── client: connect → authenticate → run a command ────────────────────────
fn verifyHostKey(key_type: []const u8, key_blob: []const u8) bool {
    // caller's own known_hosts/TOFU/pinning policy — return true to trust.
    _ = key_type;
    _ = key_blob;
    return true;
}

var t = try ssh.transport.connect(&reader, &writer, gpa, verifyHostKey);

// RFC 4252 publickey (requests the ssh-userauth service, then authenticates;
// the signature is bound to t.session_id).
const key = try ssh.userauth.AuthKey.fromOpenSSH(id_ed25519_text, null);
try ssh.authenticate(&t, gpa, "alice", key);
// ...or step-by-step / other methods:
// try t.requestService("ssh-userauth", &buf);
// try ssh.userauth.authenticatePublickey(&t, gpa, "alice", key, .{});
// try ssh.userauth.authenticatePassword(&t, gpa, "alice", secret);

// RFC 4254 exec: one call, stdout + stderr + exit status.
var r = try ssh.exec(&t, gpa, "uname -a", .{});
defer r.deinit(gpa);
std.debug.print("{s} (exit {?d})\n", .{ r.stdout, r.exit_status });

// ...or drive the channel yourself (streaming; this is what a NETCONF /
// RFC 6242 caller wants):
var s = try ssh.openSession(&t, gpa, .{});
defer s.deinit();
try s.subsystem("netconf");
try s.writeData(hello_xml);
while (...) {
    _ = try s.pumpOnce(); // fills s.stdout / s.stderr, keeps the window open
}
try s.close();

// ── server: accept → authenticate → serve one session channel ─────────────
fn authorizedKey(user: []const u8, algorithm: []const u8, key_blob: []const u8) bool {
    // caller's own authorized_keys policy.
    _ = algorithm;
    return std.mem.eql(u8, user, "alice") and std.mem.eql(u8, key_blob, alice_blob);
}

fn runCommand(
    a: std.mem.Allocator,
    user: []const u8,
    command: []const u8,
    stdin: []const u8,
    stdout: *std.ArrayList(u8),
    stderr: *std.ArrayList(u8),
) ssh.connection.CommandError!u32 {
    _ = stdin;
    try stdout.print(a, "hello {s}, you asked for {s}\n", .{ user, command });
    _ = stderr;
    return 0; // exit status
}

const host_key = try ssh.server.HostKey.fromOpenSSH(openssh_key_v1_text, null);
var st = try ssh.server.accept(&reader, &writer, gpa, .{ .host_keys = &.{host_key} });

const auth = try ssh.userauth.serveUserauth(&st, gpa, .{ .authorized_key = authorizedKey });
try ssh.connection.serveSession(&st, gpa, .{ .user = auth.user(), .exec = runCommand });
```

Top-level shortcuts: `ssh.authenticate` (client publickey auth),
`ssh.openSession` (= `ssh.connection.Session.open`), `ssh.exec`
(= `ssh.connection.exec`). Namespaces: `ssh.transport`, `ssh.server`,
`ssh.userauth`, `ssh.connection`, `ssh.messages`.

See `src/transport.zig` for the full client transport API (algorithm
name-list constants, `KexInit`, `exchangeVersions`, `Packet`/`CipherState`/
`readPacket`/`writePacket`, `HostKeyVerifier`, `NegotiatedAlgorithms`,
`Transport`/`connect`),
`src/server.zig` for the server transport API (`HostKey`, `ServerConfig`,
`serverHandshake`/`accept`), `src/userauth.zig` and `src/connection.zig` for
parts 2 and 3, and `SPEC.md` for the design/threat notes and what is
deferred.

## What is deliberately not implemented

`keyboard-interactive` and `hostbased` authentication, the password-*change*
sub-protocol, agent forwarding, OpenSSH certificate key types; `pty-req` /
`shell` / `env` / `signal` / `exit-signal` / `window-change` channel requests,
X11 and TCP/IP port forwarding; more than one channel per connection;
rekeying; compression. Requests for any of them are answered
`SSH_MSG_CHANNEL_FAILURE` / `SSH_MSG_CHANNEL_OPEN_FAILURE` rather than
mishandled. See SPEC.md → Backlog.

## Tests

`zig build test-ssh` — **all passing, Debug and ReleaseFast, no skips** with
OpenSSH installed:

- wire-codec round-trips and `Cursor` bounds tests (oversize/off-by-one/
  truncated lengths are typed errors, never panics);
- transport KAT/self-consistency (KEXINIT, KDF, every cipher, tamper
  detection, RFC 3526 primes, degenerate DH values);
- `HostKey.fromOpenSSH` fixtures checked against `ssh-keygen`'s `.pub` blob;
- userauth unit tests (`signedBlob` field order, session-id sensitivity, the
  algorithm↔key-blob-type pairing, crafted-wire oversize rejection);
- **full-stack loopback self-interop** — our client ↔ our server over a real
  socket: KEX → publickey userauth → channel open → exec → stdout/stderr/
  exit-status → close, incl. 100 KB of output through a 16 KB window so the
  flow control really blocks;
- **reject-teeth with positive controls** — wrong session id, unauthorized
  key, channel-open before auth, request after close, window overrun, unknown
  channel type;
- **live interop against real OpenSSH 10.2p1 both directions, incl. publickey
  auth and `exec`** (skipped if `sshd`/`ssh`/`ssh-keygen` are absent).
