# `tls13` — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-20** — New module: the TLS 1.3 handshake building blocks shared by the TLS-family
  engines — first the RFC 8446 §7.1 key schedule, moved from `dtls` (earlier history: `modules/dtls/src/keyschedule.zig`; git does not follow the
  split) and split into one `Schedule(prefix)` per protocol (`tls13`, `dtls13`), plus the steps
  a TLS server needs that DTLS's PSK path did not: `resumptionBinderKey`,
  `deriveExporterMasterSecret`, `deriveResumptionMasterSecret`, `deriveResumptionPsk`,
  `nextApplicationTrafficSecret`. Anchored on RFC 8448 §3/§4 (every step of the `tls13`
  instance, including the new ones), an independent Python oracle for `dtls13`, and std's
  `hkdfExpandLabel` as a differential oracle for `tls13`. First step (M0) of the `tlsserver`
  plan.
