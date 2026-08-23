# Security Policy

## Supported versions

zig-libs is pre-1.0; only the `main` branch is supported. Fixes land on
`main` — there are no backported release branches yet. For a stable point, pin
a dated release **tag**, not a bare commit: a tag asserts that every module
cleared every lane at that commit, and a bare commit asserts nothing. See
README's *Versioning & stability*, which this page used to contradict.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use GitHub's private
vulnerability reporting:

1. Go to the repository's **Security** tab → **Report a vulnerability**.
2. Describe the issue, the affected module(s), and a reproduction (a failing
   test or minimal input is ideal).

You'll get an acknowledgement, and a fix or an explanation of why it is out of
scope. Please allow a reasonable window to address the report before any public
disclosure.

## What's in scope

This is a library, so severity depends on how a consumer wires a module. The
highest-value reports concern:

- **Cryptographic / auth modules** — `jwt` (JWS/JWT verification, OIDC
  discovery, JWKS), `sealedbox`, `webhooksig`, `aaa-gate`, `acme`,
  `wireguard`. Signature-verification bypasses, algorithm-confusion,
  constant-time violations, nonce/key misuse.
- **Parsers on untrusted input** — `http` (h1/h2), `dns`, `snmp`, `mqtt`,
  `coap`, `netlink`, `tar`, `blobmsg`, `json5`. Memory-safety issues
  (out-of-bounds, use-after-free), panics/DoS on crafted input, decoder
  desync.
- **Injection surfaces** — `cookies`, `security-headers`, `cors`,
  `csvsafe`, `argsafe`, `validate`. Header/attribute injection, formula
  injection, sanitizer bypasses.

Undefined behavior that only manifests under `ReleaseFast` (where safety
checks are off) is in scope — Zig's Debug safety checks do not run in
released binaries.

## What's out of scope

- Vulnerabilities in a consuming application's own wiring (e.g. supplying a
  buffer with the wrong lifetime, disabling a documented validation).
- Issues requiring a compromised build toolchain or a malicious `build.zig`.
- Missing hardening that is explicitly documented as a consumer
  responsibility in a module's `SPEC.md` (e.g. stream TLS termination — no
  module terminates TLS on a stream transport by design; `http`/`h2` and
  friends take an already-terminated stream through a BYO-TLS/ALPN seam, so
  the TLS handshake and certificate policy are the consumer's proxy or
  `std.crypto.tls`, not ours — see CONVENTIONS.md §2).

**Not out of scope, despite the above:** `dtls` implements a real RFC 9147
DTLS 1.3 endpoint in *both* roles, server included (`Connection.serverInit`).
Its handshake, key schedule, cookie/anti-amplification and certificate
verification are ours and are fully in scope for a report. The stream rule
does not reach it: there is no datagram equivalent of a TLS-terminating proxy
to delegate to, and `std` ships no DTLS.
