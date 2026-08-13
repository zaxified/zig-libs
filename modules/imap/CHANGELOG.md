# imap — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-11** — Security audit: the write path had no CR/LF discipline, so a
  caller-supplied argument containing a CRLF could inject a second IMAP command into an
  authenticated session; fixed, along with missing STARTTLS handling and five further
  findings.
- **2026-07-31** — New module: IMAP4rev2 (RFC 9051) client — complete: the
  modified-UTF-7 mailbox-name codec (RFC 3501 §5.1.3, canonical in both directions) and
  the §9 wire grammar decode side.
