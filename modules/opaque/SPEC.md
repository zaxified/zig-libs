# opaque — module spec

RFC 9807 OPAQUE aPAKE, **ristretto255-SHA-512 configuration with the
3DH key exchange only** (OPRF: ristretto255-SHA512 / RFC 9497
modeOPRF via the sibling `voprf` module, KDF: HKDF-SHA-512, MAC:
HMAC-SHA-512, Hash: SHA-512, KSF: Identity, Group: ristretto255).
Status: **complete** — registration + login/AKE implemented and
KAT-validated byte-exact against RFC 9807 Appendix C.1.1 and C.1.2
(see `src/kat_test.zig`).

## What an aPAKE is (and why OPAQUE)

A password-authenticated key exchange where the server stores only a
one-way, per-user-salted transform of the password (never the password
itself — not even at registration), and each login derives a mutually
authenticated `session_key` with forward secrecy. OPAQUE's OPRF salt
is *secret* (the per-client OPRF key), so an attacker who steals the
credential file cannot run a precomputed dictionary attack — every
guess costs an OPRF evaluation *after* the compromise. The client
additionally gets an `export_key` the server never sees (e.g., to
encrypt vault material stored server-side).

## Threat model

- **Server compromise** (credential file + `oprf_seed` +
  `server_private_key` leak): no precomputation attack (the OPRF key
  is the secret salt, §10.11); the attacker must run an *offline*
  dictionary attack per user after the leak, and even then cannot
  impersonate the client to the server without cracking the password
  (3DH's KCI resistance, §10.2).
- **Network attacker (active)**: sees only blinded OPRF elements,
  nonces, ephemeral public keyshares, a masked credential response,
  and MACs. Forward secrecy holds against active attackers because
  the server releases nothing until KE3's `client_mac` verifies
  (§6.2.4) and the client releases nothing until KE2's `server_mac`
  verifies.
- **Client enumeration** (§10.9): the credential response is XOR-
  masked under the per-user `masking_key`, so a response for a
  registered user is indistinguishable from a fake one. The fake-record
  *policy* (respond to unknown users with one persistent fake record,
  §6.3.2.2) is the server application's job; `generateKE2` works
  unchanged with a fake record.
- **Out of scope for this module**: rate limiting online guesses
  (§9.2), the confidential channel registration requires (§3.2 —
  registration MUST run over server-authenticated TLS or equivalent),
  and secure erasure of the caller-held password/state.

## Registration (§5) — one confidential round trip

```
client: createRegistrationRequest(password, blind)      → request
server: createRegistrationResponse(request, server_pk,
                                   credential_identifier, oprf_seed)
                                                         → response
client: finalizeRegistrationRequest(password, blind, response,
                                    identities, envelope_nonce)
                                                         → {record, export_key}
```

The server persists `record` (`client_public_key || masking_key ||
envelope`, 192 bytes) under `credential_identifier`, alongside its
long-term `server_private_key`/`server_public_key` and the global
`oprf_seed`.

## The internal-keying Envelope decision (§4.1)

The envelope is just `nonce[32] || auth_tag[64]` — it stores **no
encrypted private key**. Instead the client's AKE private key is
*re-derived on every login* from the password's OPRF output:

```
randomized_password = Extract("", oprf_output || Stretch(oprf_output))
seed     = Expand(randomized_password, nonce || "PrivateKey", 32)
(sk, pk) = DeriveKeyPair(seed, "OPAQUE-DeriveDiffieHellmanKeyPair")
auth_tag = MAC(auth_key, nonce || server_pk ||
               len(server_identity) || server_identity ||
               len(client_identity) || client_identity)
```

This removes the need for an equivocable/key-robust *encryption*
scheme entirely (only the MAC needs random-key robustness — HMAC over
a collision-resistant hash qualifies, §10.6) and shrinks the record.
A wrong password produces a different `auth_key`/keypair, so the
timing-safe `auth_tag` check fails closed as `error.EnvelopeRecovery`.

## KSF = Identity — deliberate, and where the seam is

`Stretch(msg) = msg`, the configuration RFC 9807's own Appendix C test
vectors use — chosen so the KATs are reproducible. The RFC's
RECOMMENDED production configuration uses Argon2id here (§7); that is
a client-side cost knob against offline attacks after server
compromise (§10.8), not a protocol change. The single seam is
`randomizedPassword` in `root.zig` (the second `extract.update` is the
stretched copy); swapping in a real KSF changes no wire format but
invalidates existing registrations (users must re-register, §8).

## Login: 3DH AKE (§6.4)

Fixed-size messages: `KE1` 96 B, `KE2` 320 B, `KE3` 64 B.

```
IKM (client) = DH(eskC, epkS) || DH(eskC, pkS) || DH(skC, epkS)
IKM (server) = DH(eskS, epkC) || DH(pkS_sk, epkC) || DH(eskS, pkC)

preamble = "OPAQUEv1-" || len(context) || context ||
           len(client_identity) || client_identity || KE1 ||
           len(server_identity) || server_identity ||
           credential_response || server_nonce || epkS

prk               = Extract("", IKM)
handshake_secret  = Derive-Secret(prk, "HandshakeSecret", Hash(preamble))
session_key       = Derive-Secret(prk, "SessionKey",      Hash(preamble))
Km2               = Derive-Secret(handshake_secret, "ServerMAC", "")
Km3               = Derive-Secret(handshake_secret, "ClientMAC", "")
server_mac        = MAC(Km2, Hash(preamble))
client_mac        = MAC(Km3, Hash(preamble || server_mac))
```

`Derive-Secret` is the TLS 1.3-style `Expand-Label` (`I2OSP(64,2) ||
len1("OPAQUE-"+Label) || "OPAQUE-"+Label || len1(Context) || Context`).
All ephemeral keyshares are derived from caller-supplied seeds via
`DeriveDiffieHellmanKeyPair` (§6.4.1.1) — same derivation as the
envelope's internal keypair, different seeds.

Order of checks on the client (§6.3.2.3/§6.4.3): unmask → recover
envelope (`EnvelopeRecovery` = wrong password) → 3DH → verify
`server_mac` (`ServerAuthentication`) → only then release
`ke3`/`session_key`/`export_key`. On the server (§6.4.4): verify
`client_mac` (`ClientAuthentication`) before releasing `session_key`.
Both MAC checks are `std.crypto.timing_safe.eql` and fail closed.

## API discipline

- **No internal RNG** (house rule, same as `voprf`): every blind,
  nonce, and keyshare seed is a caller-supplied parameter, which is
  also what makes the RFC KATs runnable against the public API.
  Callers MUST supply fresh CSPRNG output for each of them in
  production (blinds via `scalarFromWideBytes`).
- **No allocation, no I/O**; all state is in caller-held value types
  (`ClientLoginState` borrows only the password slice).
- Public-key/OPRF-element inputs are validated on deserialization
  (canonical ristretto255 + identity rejection via `voprf.Element`,
  §10.7). §6.4.1.1's "the DH shared secret MUST NOT be the identity"
  is **no longer** discharged by the rejection inside
  `Ristretto255.mul`, as this line used to claim: that rejection is a
  branch on a value derived from the SECRET private key, and `catch`ing
  it made `diffieHellman` branch on it a second time. The multiply now
  runs on the sibling `ct25519` (std's ladder without the trailing
  `rejectIdentity`) and the requirement is met structurally: ristretto255
  has PRIME order and the peer element is already validated non-identity,
  so `k*B` is the identity iff `k == 0 (mod L)` — a broken LOCAL key,
  unreachable for any element a peer can encode, and excluded by
  `voprf.deriveKeyPair`'s own §3.2.1 zero-rejection loop.

## Out of scope (deliberate)

- **Other groups/suites** (C.1.3-C.1.6: curve25519, P-256): no
  consumer here needs them; P-256 would drag in a different OPRF
  ciphersuite `voprf` does not build.
- **Non-Identity KSFs** (Argon2id/scrypt): parameter policy belongs to
  the consumer; seam documented above. std has Argon2id when wanted.
- **The "Fake" credential flow KATs** (C.2): the fake-record response
  is a server policy using the same `generateKE2` code path; nothing
  new to pin.
- **HMQV / SIGMA-I instantiations** (Appendix B): sketches only in the
  RFC, no vectors, no consumer.
- **`randomized_password` backup login** (§10.13): storage-side
  feature for clients with persistent secret state; adds API surface
  without a consumer.

## Consumers

`aaa-gate` / `sessions` (password-backed authentication where the
server must never see a password; `export_key` for client-side vault
encryption). The wire structs all have fixed-size `toBytes`/
`fromBytes`, so any transport (HTTP body, MCP, raw TCP) can carry
them.
