# isis — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

- **2026-09-14** — **BREAKING (error set, enum) + BEHAVIOURAL:** audit F2/F3, round-2 decision Q5
  (the newer norm wins; ISO/IEC 10589:2002, no switch). Two reserved-field rules the codec had
  backwards, against the norm and against RFC 1142's identical wording:
  - **F2, accepts more:** `header.decode` rejected a set reserved PDU-type bit (bits 6-8 of octet
    4) with `error.ReservedBitSet`. They are "transmitted as 0 and ignored on receipt": now masked,
    and `ReservedBitSet` is gone from `header.DecodeError` (no caller named it).
  - **F3, refuses more:** `LanHello.decode`/`P2pHello.decode` accepted Circuit Type 0 as
    `.reserved0`. The norm: "if specified the entire PDU shall be ignored". Now
    `error.ReservedCircuitType`, and `CircuitType` loses `.reserved0`, so a builder cannot emit
    one either. The six high bits of that octet stay ignored.
  Consumers `isis-adj`, `isis-dis`, `isis-flood`, `isis-lsdb`, `isis-sim`, `isis-spf` never named
  either; no source change. Two fuzz seeds added (a reserved PDU-type bit, Circuit Type 0).

- **2026-09-10** — The `lsp_checksum_base` citation of ISO/IEC 10589 §7.3.11
  quoted the opening paragraph and then jumped straight to the closing NOTE,
  silently skipping the middle paragraph — a real normative requirement (an
  "additional precaution against hardware failure": generation should resume
  checksum computation from a persisted, systemID-anchored prefix state
  rather than always starting at zero). Quoted in full now, with a note
  explaining why this codec does not implement it: it is a redundancy check
  against a corrupted in-memory systemID, requires state a pure/stateless
  codec does not hold, and does not change the computed checksum value
  (resuming from a cached prefix that matches the actual prefix bytes is
  arithmetically identical to one continuous pass). Also documented (in its
  own words) in SPEC.md's "Deliberately deferred" section. `grep -rln
  "additional precaution" modules/isis/`: empty before this entry, `pdu.zig`
  after.
- **2026-09-07** — **`fuzzDecode` walked an EMPTY buffer, and the header bias its
  own TEETH test defends had never executed outside `--fuzz`.**

  Two defects, one cause. The harness opened with `smith.bytes(&buf)` followed by
  `smith.valueRangeAtMost(u8, 0, buf.len)`: `bytes` consumes `min(buf.len, in.len)`
  octets and a ranged draw then reads eight *more* as a little-endian u64, returning
  the range minimum when fewer remain — so `len` was 0 for every input a seed can
  carry, and both `walkTlvs` and `decode` were handed an empty slice.

  ⭐ The second is the one the earlier audit could not have seen. `biasToModeledPdu`
  was gated on `smith.value(bool)` **drawn after** that byte draw, and both of the
  bias's own draws came after it too. With the input exhausted every one of them
  returns its range minimum: the gate was `false`, so the bias never ran at all in
  the ordinary lane; and had it run, the shape would always have been
  `modeled_shapes[0]` and the PDU Length always `fixed_len` — an empty TLV region, in
  the harness whose entire purpose is walking the TLV region. The module's own TEETH
  test proves the bias works, and it was right; the harness simply never called it.

  Now: one `smith.slice(&buf)` draw, the buffer raised 128 → 512 (the largest golden
  PDU is 66 octets, so nothing was being silently emptied, but a real LSP is not
  128), the bias driven by a `testkit.fuzz.Cursor` over the seed's own bytes instead
  of by exhausted `Smith` draws, and run as a second arm rather than a coin flip —
  the raw seed exercises the refusals, the stamped copy exercises the bodies. A
  13-entry corpus of the module's own golden capture frames plus the refusals.

  Measured 2026-09-07, before → after: **0 of 13 seeds non-empty → 12 of 13** (the
  empty buffer is a seed on purpose), 0 PDUs decoded → 9, **0 octets of TLV region
  walked → 211**, and **0 bias stamps → 9**. The TLV-region column is the
  discriminating one: `decode` accepts a PDU whose TLV region is empty, so counting
  acceptances would have reported health over a corpus that never entered `walkTlvs`
  on a body.

- **2026-09-03** — Drift re-audit (714 lines since the last one). ⚠ **BREAKING:**
  `checksum.compute` now returns `error{ChecksumFieldOutOfRange}!u16` instead of
  `u16`, and `pdu.DecodeError` gained `ChecksumFieldOutOfRange`. Its only
  precondition guard was a `std.debug.assert`, i.e. nothing in ReleaseFast: the
  `bytes.len - csum_off - 1` below it underflows a `usize` and `accumulate`
  reads off the end. Measured on identical source and input — Debug and
  ReleaseSafe panic, **ReleaseFast SIGSEGVs**; undefined behaviour, so the class
  is "unchecked out-of-range read" rather than either symptom. Not reachable
  from inside the module today, which is not the guarantee an exported function
  makes.
- **2026-09-03** — The `std.testing.fuzz` harness reached a decoded PDU **body**
  exactly never. Its bias set bytes 0/2/5 and left the Length Indicator, ID
  Length, PDU-type octet and the entire PDU-Length field random, so
  `checkCommon` refused every draw: two million coverage-guided runs, zero
  bodies, while `check-fuzz` reported the module covered. Every fixed-offset
  body read, `tlvRegion` and the whole `checksum.zig` surface were unfuzzed. The
  bias now writes a complete modeled header plus a consistent PDU-Length, the
  LSP checksum entry points are driven from the harness, and a non-fuzz test
  asserts the bias reaches a body.
- **2026-09-03** — `example/main.zig`'s untrusted-input demonstration could not
  fail: `_ = decode(x) catch |err| switch (err)` asserted nothing if `decode`
  SUCCEEDED, so `run-example-isis` stayed green with the bounds guard removed.
  Now fail-closed (verified red under that mutation).
- **2026-09-03** — Docs: `LspFields.checksum`'s doc claimed `0` means
  "checksumming not in use"; `ChecksumStatus.not_present` fifty lines below said
  the opposite and cited RFC 3719 §7 correctly. An LSP built from the default and
  closed with `finish()` is one `isis-lsdb` must discard. SPEC.md's Verification
  section still carried the "no live capture was available" sentence that was
  deleted from `goldens.zig` as stale, contradicting the Anchoring section of the
  same file; it also named 2 goldens (there are 9) and never mentioned the
  Wireshark-graded checksum KAT.
- **2026-08-06** — Security audit: five findings fixed (part of the collection-wide
  audit; the root changelog records no further detail than this). ⚠ The trailing
  "Verified: — and re-verified first-hand, not trusted." was a dangling template
  substitution and is removed. This entry also recorded none of the 714 lines that
  followed it: `src/checksum.zig`, `LspBuilder.finishStamped`, the seven
  `pdu.*` LSP-checksum entry points, `buildableTlvRegion`'s 65535 cap, and
  `DecodeError.LengthIndicatorMismatch` — the last of which is a public error-set
  addition AND a tightening that rejects PDUs previously accepted.
- **2026-07-24** — New module: IS-IS (ISO/IEC 10589) PDU codec — common header + TLV
  framework + IIH/LSP PDUs + SPB (802.1aq) TLVs + raw-TLV escape hatch; pure
  bounds-checked encode/decode of untrusted link bytes, the wire.
