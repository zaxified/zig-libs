# bitcointx — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-07** — Test-only, no production change: neither fuzz target had ever decoded
  a transaction. `fuzzSighash` carried four hand-written 512-octet seeds, but the helper
  that built them wrote `(bits >> w) & 0x03` into every trailing `u64` word — including
  the word `len = smith.valueRangeAtMost(u16, 0, 256)` read — so the longest transaction
  the harness ever saw was **3 octets**, shorter than the four-octet `version` field, and
  `script` was the same shape and always empty. `fuzzDeserializePartial` had no corpus at
  all, so outside `--fuzz` its one input was `""`. Both now draw with a single
  `smith.slice(&buf)`. Separately, both buffers were **256 octets** against a module whose
  own smaller reference transaction is 275 and whose largest `tx_wire_vectors` row (Bitcoin
  Core `tx_valid.json`/`tx_invalid.json`) is 1911 — and a seed over the buffer reads back
  EMPTY rather than truncated — so no real Bitcoin transaction this module owns could have
  passed through either harness even with a working length draw; raised to 2048
  (`tx.fuzz_tx_buf_len`). Seeds are the two `tx_kat_vectors` transactions plus targeted
  refusals, each carrying a `u64` tail so the knobs after the byte draw are alive on a
  corpus replay rather than pinned at their range minimum. Measured by the two new
  `corpus:` guards — `deserializePartial`: 7 non-empty seeds, 2 accepted, 3 inputs walked,
  1 witness-carrying, 3 of the 4 bias branches exercised; `fuzzSighash`: 6 non-empty, 4
  decoded, 6 inputs, 75 script octets, and **3 legacy / 3 BIP143 / 3 BIP341 digests
  actually computed, against 0 for every input this target had ever run**.

- **2026-08-11** — Security audit: ten findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit. Byte-exact against BIP341's published
  test vectors.
- **2026-07-21** — New module: Bitcoin transaction (de)serialization + signature
  hashing.
