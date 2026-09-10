# dnssec — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-10** — **BEHAVIOURAL, not breaking:** `validate` now rejects an
  RRset whose `rrsig.signer_name` is not the owner name's zone or an
  ancestor of it (RFC 4035 §5.3.1, audit A1 F1) and whose `rrsig.labels`
  exceeds the owner's own label count (F6); `chain.validateDnskeySet`
  applies the equivalent type_covered/signer_name/labels guards (F5);
  `nsec3.proveDenial` now refuses a set of more than `max_nsec3_records`
  (1200, new public constant) NSEC3 records instead of scanning it (F2,
  also ~20x faster at the audit's measured shape via a decode-once pass);
  `rdata.TypeBitMap.contains` bounds-checks every window instead of only
  the one being probed (F4). All four narrow what previously validated or
  ran without crashing; no consumer exists yet (0 in-repo, confirmed against
  `example-apps/` too) so nothing downstream to update.
- **2026-09-07** — **All four fuzz harnesses were replaying an EMPTY input, three of
  them also had a dead knob, and two had buffers smaller than this module's own
  vectors.**

  `fuzzDecodePublicKey`, `fuzzProveDenial`, `fuzzRdata` and
  `fuzzDecodeUncompressedName` opened with `smith.bytes(&buf)` followed by
  `smith.valueRangeAtMost(u16, 0, buf.len)`. `bytes` consumes `min(buf.len, in.len)`
  octets and a ranged draw then reads eight *more* as a little-endian u64, returning
  the range minimum when fewer remain — so the drawn length was 0 for every input a
  seed can carry. All four now take their bytes in one `smith.slice(&buf)` draw and
  carry a corpus with a guard test in the ordinary lane.

  ⛔ **`fuzzDecodePublicKey` had never decoded a key.** Its `algorithm` came from
  `smith.value(u8)` *after* the byte draw, so it read an exhausted input and returned
  the weight minimum — 0, which is not an IANA DNSSEC algorithm number. Every
  iteration it ever ran was `decodePublicKey(0, "")`, taking the `else` arm before
  touching a byte: the RSA, ECDSA-P256, ECDSA-P384 and Ed25519 decoders this file
  exists for had never been reached. The algorithm is now the seed's first octet.
  Measured after: 20 seeds, 5 accepted, **all 4 key families** reached.

  ⛔ **`fuzzProveDenial`'s alphabet fold had never run.** `smith.boolWeighted(1, 3)`
  sat after the byte draw and returned false every time — and its own comment says it
  exists "to actually reach `decode`". So a zero-length label went in and the
  base32hex decoder the harness is named after was never entered. Every seed is now
  run both verbatim and folded: 17 seeds, 6 hashes decoded verbatim, **10 folded**.

  ⛔ **`fuzzDecodeUncompressedName`'s `start` was always 0**, while its doc comment
  says the point is "an attacker-influenced starting offset … not necessarily 0". The
  offset is now swept from 0 to `len` inclusive: 15 seeds, 245 decodes, 26 238 text
  octets, and a longest decode of exactly 253 — `max_name_text_len`, the boundary the
  `NameTooLong` check defends.

  ⛔ **Two buffers were smaller than the module's own vectors.** `fuzzRdata` held 256
  octets against a 264-octet DNSKEY RDATA and a 283-octet RRSIG RDATA, and
  `fuzzDecodePublicKey` held 256 against a 260-octet RSA public-key field. A seed over
  the buffer does not arrive truncated — `Smith.slice` falls back to the range minimum
  and it arrives *empty* — so the largest real records this module owns could not have
  passed through their own harnesses even with the length draw fixed. Both are 512 now.

  The RDATA guard counts per parser rather than in total, because `parseTypeBitMap("")`
  succeeds (an empty bit map is a legal empty type set) and would have carried a
  non-zero "accepted" on its own. Measured: 23 seeds; DNSKEY 20, RRSIG 4, DS 20, bit
  map 2, NSEC 1, NSEC3 1, NSEC3PARAM 1. `parseNsec` read **0** until a genuine NSEC
  RDATA was taken from the oracle vectors — no hand-written refusal is a well-formed
  one, and NSEC is also the only record type that drives
  `wire.decodeUncompressedName` from this file.

- **2026-09-03** — Drift re-audit. **The oracle's reproduction recipe is back in
  the repo.** `src/oracle_vectors.zig` — the module's strongest anchor, signed
  with `ldns-signzone` and independently accepted by `ldns-verify-zone` — was
  credited to `scratchpad/dnssec-oracle/`, which SPEC and README both named and
  README called "ephemeral". Accurately: a scratchpad does not survive a
  reboot, so the anchor had no re-takeable recipe at all, which makes it an
  assertion rather than a measurement (same shape as the drift-ranking script
  this campaign had to move out of a session scratchpad).
  `scripts/gen-dnssec-oracle.sh` restores the provenance chain: it builds a
  zone, signs it once per algorithm this module implements a verifier for
  (RSASHA256, ECDSAP256SHA256, Ed25519) plus an NSEC3 pass, and has ldns verify
  each — run and confirmed on this host, not written from memory. ⚠ It does
  NOT reproduce the committed vectors byte for byte (those keys are gone, and
  DNSSEC signatures are not deterministic across fresh keys), and the extractor
  that turned wire rdata into the `Vec` literals was only ever in the
  scratchpad and is not reconstructed. Both limits are stated in the script's
  own header and in SPEC rather than left for the next reader to discover.


- **2026-07-19** — Security audit: fixed a memory-safety finding rated CRIT/HIGH (part of
  the collection-wide audit; the root changelog records no further detail
  than this).
