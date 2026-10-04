# l2encap — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-10-04** — Tests: first mutation run (34 mutants, 34 killed); added a test that rejects each reserved `flags` bit 1..7 individually.

- **2026-09-30** — Anchor grade corrected from class A · oracle SELF to **class D · oracle n/a**: the
  8-byte header is this module's own format (no third party implements it), so there is no outside
  truth to anchor on. Documentation only; grade 4 → 2 follows from the honest class, not new evidence.

- **2026-09-07** — **`fuzzDecode` handed `decode` an EMPTY frame on every input,
  and the version-byte bias that would have rescued it never ran either.**

  It opened with `smith.bytes(buf[0..fuzz_drawn])` and then drew a size class with
  `smith.valueRangeAtMost`. `bytes` consumes `min(out.len, in.len)` octets and every
  ranged draw after it reads eight *more* as a little-endian u64, returning the range
  minimum when fewer remain — so the size class was always 0, the length inside it
  was always 0, and the `smith.value(bool)` that forces `version_current` into byte 0
  was always false. The harness's own comment says the jumbo and MTU size classes
  exist because a `u8` draw "never leaves" the 72-octet region; in fact no draw ever
  left zero.

  One `smith.slice` draw, the size class and the split-horizon id read from a
  `testkit.fuzz.Cursor` over the seed's own octets, and an eight-entry hex corpus:
  a unicast frame, a BUM frame at max I-SID and max ingress-PE, a TTL-0 frame,
  and the four refusals (`InvalidHeader` on a reserved flag bit,
  `UnsupportedVersion`, the all-zero buffer, and a six-octet truncation).

  Measured 2026-09-07, before → after: **0 of 8 seeds non-empty → 7 of 8**, 0 decoded
  → 3, and **0 BUM frames → 1**. The BUM count is the discriminating one: the
  all-zero buffer the collapsed harness produced is rejected as version 0, so nothing
  downstream of the version check — not the reserved-bit rejection, not the I-SID,
  not `droppedBySplitHorizon` — had ever been reached at all.

- **2026-08-06** — Security audit: four findings fixed, one documented as accepted (not
  defects) — part of the collection-wide audit.
- **2026-07-24** — New module: Tenant-tagged (24-bit I-SID) L2-over-tunnel encapsulation
  for a multi-tenant L2VPN fabric.
