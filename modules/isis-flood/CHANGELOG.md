# isis-flood — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: with more than 256 LSPs in the database, the flooding
  scheduler's CSNP series claimed to cover the entire LSP-ID space while listing only
  256 entries, understating what a peer had actually seen; fixed, along with one further
  finding.
- **2026-07-24** — New module: IS-IS flooding transmit scheduler — drain `isis-lsdb`
  per-interface SRM/SSN flags into the ordered PDUs to send, pace LSP (re)transmission +
  emit periodic CSNPs; pure time-injected.
