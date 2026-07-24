# aeadframe

A per-key AEAD record/frame layer: seal/open messages under one key with a
monotonic counter nonce (never reused), epoch-based rekey, a sliding-window
anti-replay filter, and AAD binding. Generic over the AEAD — ChaCha20-Poly1305
(via `chachapoly`) and AES-256-GCM (std). The S1b consumer is per-tenant L2VPN
confidentiality: one channel per I-SID over the shared encrypted backbone.

**Status:** gap (placeholder — implementation pending).
