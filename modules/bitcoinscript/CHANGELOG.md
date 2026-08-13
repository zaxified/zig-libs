# bitcoinscript — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-08-06** — Security audit: the interpreter appeared to omit Bitcoin Core's
  legacy `FindAndDelete` sighash step for a class of legacy scripts, which looked like
  it could yield a different validity verdict than Core; investigation found the
  mechanism could not actually diverge in practice, but the code was still changed to
  mirror Core's exact behaviour, and 9 further findings were fixed.
- **2026-07-21** — New module: Bitcoin Script consensus interpreter (VM).
