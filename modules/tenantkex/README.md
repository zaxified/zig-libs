# tenantkex

Per-tenant key exchange for the L2VPN fabric: run a Noise_IK handshake (via the
`noise` module) between two provider edges, binding the tenant's I-SID into the
handshake prologue so a session is cryptographically scoped to one tenant, and
derive the two directional channel keys that feed `aeadframe`. Pure driver over
`noise`'s HandshakeState — the caller carries the two messages over the WG
backbone; this module produces {send_key, recv_key, transcript_hash}.

**Status:** gap (placeholder — implementation pending).
