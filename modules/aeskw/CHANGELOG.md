# aeskw — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Fuzz: the no-partial-key-leak oracle had never executed.
  `fuzzUnwrapNoLeak` opened with `smith.value(bool)` and then a ranged `ct_len`,
  both of which return the range minimum when fewer than eight input octets
  remain — so with no corpus the target ran one input for ever: a 32-octet zero
  KEK over an empty ciphertext, which `unwrap` refuses as `InvalidLength`, and
  the `err != error.Unauthentic` guard returned before the assertion. Sibling
  `fuzzWrapUnwrapRoundTrip`, whose name claims "at every legal size", ran the
  single case n = 2 with a zero KEK. Both now draw bytes first
  (`smith.slice`), run BOTH KEK lengths on every input (a KEK drawn either side
  of the byte draw is dead on a corpus replay), and carry corpora: RFC 3394
  §4.1/4.3/4.5/4.6 ciphertexts plus two one-octet perturbations for unwrap, and
  a set of lengths for the round trip. Pinned by corpus guards: 4 accepted, 88
  octets of key material recovered, 8 refusals that reached the integrity check
  (the oracle's actual firing count); round trip 928 octets over 8 seeds.

- **2026-08-06** — Security audit: two findings fixed, two documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against RFC 3394 §4.1's
  published test vectors.
- **2026-07-22** — New module: RFC 3394 AES Key Wrap (AES-128/256 KEK) — constant-time
  integrity check + scratch zeroization, byte-exact vs RFC 3394 §4.
