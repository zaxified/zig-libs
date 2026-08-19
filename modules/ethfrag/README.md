# ethfrag

Inner-frame **fragmentation and reassembly** for an overlay encapsulation:
splits an inner Ethernet frame across fixed-MTU carrier packets and puts it back
together, treating every fragment as adversarial input. The IP-fragmentation CVE
playbook — teardrop, overlapping fragments, tiny-fragment floods,
incomplete-reassembly memory exhaustion — is the **threat model**, not a list of
corner cases. Standalone codec: no sockets, no wall-clock read.

- **Status:** complete. **Platform:** any — pure transforms over caller-owned
  slices; the only allocation is the caller's `Allocator`.
- **Deps:** none (std only).
- **Model after:** IP fragmentation/reassembly (RFC 791 §3.2) with RFC 5722 §3
  overlap rejection, hardened.

Consumer: an L2-over-WireGuard data plane. See
[`SPEC.md`](SPEC.md) for the full threat model and the wire format.

## Wire format

An 8-byte big-endian header (`frag_id`, `offset`, `length`, `flags`,
`reserved`) followed by the payload slice. `flags` bit 0 is `more`; **every
other flag bit and the whole `reserved` byte must be zero** — `Header.decode`
rejects a nonzero reserved bit rather than ignoring it, which closes a
reserved-field covert channel for free. `offset`/`length` are `u16`, so a
reassembled frame is capped at 65535 bytes (`max_frame_len`) — a ceiling tied
to the header width rather than an arbitrary constant, with headroom over both
standard (1500) and jumbo (~9216) MTUs.

`frag_id` groups one inner frame's fragments. Like IPv4's identification field,
assigning distinct ids to concurrently in-flight frames — and not reusing one
before its reassembly window has elapsed — is the **sender's** responsibility,
which is exactly why `fragment()` takes it as a parameter.

## Use

```zig
const ethfrag = @import("ethfrag");

const frags = try ethfrag.fragment(gpa, inner_frame, frag_id, carrier_mtu, header_overhead);
defer ethfrag.freeFragments(gpa, frags);

var r = ethfrag.Reassembler.init(gpa, .{ .max_inflight = 64, .timeout_ns = 2 * std.time.ns_per_s });
defer r.deinit();
switch (try r.insert(wire_bytes, now_ns)) {
    .incomplete => {},
    .complete => |frame| { /* allocator-owned; the caller frees it */ },
}
```

`now_ns` is caller-supplied on every call — the idle timeout that reclaims
abandoned datagrams never reads a clock itself, so a test can drive it (and
`expireOlderThan` sweeps explicitly when no fragment arrives to trigger it).

## Verify

```
zig build test-ethfrag                          # Debug       — 26 pass
zig build test-ethfrag -Doptimize=ReleaseFast   # ReleaseFast — 26 pass
```

Round-trip smoke, a 300-iteration seeded property test (fragment → shuffle →
reassemble → byte-identical, across random frame lengths / MTUs / overheads),
**one targeted adversarial test per threat-model bullet**: overlap,
duplicate, teardrop overrun, contradictory `more=false`, tiny-fragment flood,
concurrent-datagram cap, and timeout reclamation, and an **external anchor**
(`kernel_oracle.zig`) comparing this module's accept/drop/deliver decision
against the real Linux kernel's own IPv4/IPv6 fragment reassembly for
structurally equivalent fragment sets — see that file's doc comment for the
capture recipe and the one confirmed, deliberate divergence (this module
rejects an exact-duplicate fragment; the kernel tolerates it as a harmless
retransmission). A frame is returned only once every byte is accounted for by
non-overlapping fragments; there is no code path that returns a partial frame.

Provenance: clean-room from RFC 791 §3.2 and RFC 5722 §3 — both public specs,
no third-party source ported or studied, so no `NOTICE` entry is required (root
[`NOTICE`](../../NOTICE) §0). Exercising the kernel's own reassembly as a
black-box RFC-policy oracle (`kernel_oracle.zig`) is likewise exempt under
`NOTICE` §0 — no kernel source consulted or copied, only its observable
accept/drop behavior against fragments built by hand.
