# timelock_envelope

Hybrid sealed envelope: the plaintext unlocks only when BOTH a drand timelock
round has published (time gate, via `tlock`) AND the recipient holds the
post-quantum KEM secret key (long-term confidentiality, via `hqc`). Content is
AEAD-sealed under a key bound to both locks. Crypto core of the S5
dead-man-switch.

**Status:** gap (placeholder — implementation pending).
