# isis — changelog

Newest first. See the root [`CHANGELOG.md`](../../CHANGELOG.md) for which
release tag each entry shipped in, and `CONVENTIONS.md` §8 for the policy.

## Unreleased

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
