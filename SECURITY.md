# Security Policy

## Supported versions

zig-libs is pre-1.0; only the `main` branch is supported. Fixes land on
`main` — there are no backported release branches yet. Pin a commit if you
need a stable point.

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
  responsibility in a module's `SPEC.md` (e.g. TLS termination — no module
  ships a TLS server by design).
