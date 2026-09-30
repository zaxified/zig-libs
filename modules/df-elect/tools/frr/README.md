# FRR EVPN-MH DF-election oracle lab

A reproducible FRRouting lab in **rootless podman** that shows how FRR elects
the Designated Forwarder (DF) of an EVPN Ethernet Segment, so `df-elect` can be
compared against it.

**FRR is run as a black box; no FRR source was read.** Only its CLI output
(`vtysh` help and `show` commands) and behaviour were observed.

## Lab

- Image: `quay.io/frrouting/frr:10.7.1` pinned as
  `@sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2`
  (the tag's manifest list, as reported by the quay.io API on 2026-09-30).
- 3 PEs `dfe-pe1..3`, network `dfe-net` (10.77.0.0/24), 256 MB each, caps
  `NET_ADMIN,SYS_ADMIN,NET_RAW`. No root needed (bridge/vxlan/bond/veth all work
  in the container's user-owned netns).
- Loopback = VTEP = originator IP: `10.0.0.1`, `10.0.0.2`, `10.0.0.3`
  (reachable via static routes). iBGP full mesh (AS 65000) on the loopbacks,
  address family l2vpn evpn, `advertise-all-vni`.
- Data plane per PE: VLAN-aware `br0`, VLANs/VNIs 1000 and 1001 (`vx1000`,
  `vx1001`), and one ES access port `bond1` (802.3ad bond, member veth `es0`
  whose peer `ce0` is just left up). `ip link set ce0 down` = ES access link down.
- ES config on `bond1`: `evpn mh es-id 1`, `evpn mh es-sys-mac 00:00:00:aa:00:01`,
  `evpn mh es-df-pref <P>` (ESI `03:00:00:00:aa:00:01:00:00:01`).
- `lab.sh` sets `evpn mh startup-delay 10` (env `DFE_STARTUP_DELAY`, empty = FRR
  default) so restarts are quick; see the `startup-delay` scenario for the default.
- Observation: an in-container poller runs `vtysh -c "show evpn es detail json"`
  every 100 ms per PE (microsecond stamps, one host clock); `collect.py` merges
  the logs with the scenario's action events and emits one JSON line per *change*.

## Run

```sh
./lab.sh up
for s in steady-equal-pref steady-pref df-link-down df-pe-crash startup-delay; do ./lab.sh scenario $s; done
./lab.sh down            # removes dfe-pe*, network dfe-net, .work/pe*
./lab.sh vtysh 2 -c 'show evpn es detail'    # poke around
```

Each scenario writes `observed/<scenario>.jsonl` (override the directory with
`DFE_OUT`) and prints it. `startup-delay` takes ~5 minutes, the others 15 s to
2 minutes. Requires `podman`, `bash`, `python3`, and network access for the
first image pull.

Line kinds: `{"pe","es","df","df_pref","flags","peers":{vtep:pref}}` (state change
of a PE), `{"kind":"action|note","event"}` (what the lab did / a CLI snapshot),
`{"summary":"df_change","after","df_before","df_after","first_change_ms","settled_ms"}`.
The PEs are polled ~60 ms apart, so a hand-over can show a short "two DFs"/"no DF"
set; `first_change_ms` is the first differing DF set after the action,
`settled_ms` the last change before the next action.

## Scenarios

| name | what it does |
|---|---|
| `steady-equal-pref` | prefs 100/100/100; who is DF; per-VNI carving? (es-evi snapshot) |
| `steady-pref` | prefs 100/200/300; then raise pe1 to 400, lower it to 50, unset pe3's pref |
| `df-link-down` | DF's `ce0` down then up, with distinct prefs and again with equal prefs |
| `df-pe-crash` | `podman stop -t0` on the DF, then start again; distinct and equal prefs |
| `startup-delay` | restart pe3 with FRR's default `startup-delay`, sample its timer |

## Observed results (FRR 10.7.1; final run, `observed/`)

| aspect | observation |
|---|---|
| Algorithm | Type-4 route carries `DF: (alg: 2, pref: N)`; `show evpn es detail` prints `df_alg: preference`. Preference-based election (draft-ietf-bess-evpn-pref-df style); no modulo/HRW election was seen |
| Granularity | One election **per ES**, not per VLAN/VNI: `DF status` is a single value in `show evpn es detail`; `show evpn es-evi` has no DF field; both VNIs 1000/1001 follow the ES |
| Ordering | Highest `es-df-pref` wins. Equal pref: **numerically lowest originator IP** wins (10.0.0.1 with 100/100/100; after the DF leaves, 10.0.0.2 takes over; 10.0.0.1 takes it back when it returns) |
| Default pref | With no `es-df-pref` configured FRR uses **32767** (pe3 unset vs 200 and 50 elsewhere: pe3 stays DF) |
| Pref change at runtime | Takes effect within ~100 to 230 ms (pe1 100 to 400: pe1 DF; 400 to 50: pe3 DF again). Setting 100/100/100 while pe3 (300) is DF moves the DF to pe1 in ~0.5 to 0.7 s |
| Preemption | **Always preempts.** The higher-preference / lower-IP PE takes the DF role back when it returns (link up: original DF is DF again in ~0.2 to 0.3 s, with distinct and with equal prefs). `evpn mh` offers only `mac-holdtime, neigh-holdtime, redirect-off, startup-delay`, the interface level only `bypass, es-df-pref, es-id, es-sys-mac, uplink`: **no don't-preempt / non-revertive knob exists** in `vtysh` help |
| DF link down | DF's ES link down: next-best PE is DF after ~50 to 240 ms, settled within ~0.13 to 0.24 s; the PE with the down link loses `operUp` and is not DF |
| DF link up | Old DF is DF again ~0.2 to 0.3 s after link up (preempt); no DF-wait delay was visible |
| DF PE crash (`stop -t0`) | Next-best PE becomes DF after ~50 to 130 ms (the BGP hold time was not the limiting factor). An earlier exploratory run without `timers connect` measured 2.8 s and 5.0 s; not reproduced in either of the two final passes |
| DF PE restart | The restarted PE, with no BGP peers yet, declares itself DF after ~3.6 s (alone) while the stand-in DF still holds the role: a **dual-DF window** until the EVPN sessions re-establish (~20 to 30 s here, dominated by BGP reconnect, not by the election); the stand-in then yields at once |
| Timers | `evpn mh startup-delay` default **180 s** (`show evpn`: `startup-delay: 180s`; `startupDelayTimer` counts down 00:02:49 ... 00:00:05, then `--:--:--`); `mac-holdtime` / `neigh-holdtime` default **1080 s**. Without `evpn mh uplink` configured, the startup delay did **not** delay ES readiness or DF election (pe3 was `readyForBgp` and not DF 3 s after start with the 180 s timer running) |

Per-scenario summaries: `rg summary observed/`. Timings vary by ~100 ms between
runs (two full passes agreed on every DF outcome).

## Not verified / caveats

- Only 3 PEs, one ES, one ES member per PE, all-active; `vtysh` has no DF-wait
  timer setting, so none was tuned.
- Modulo/HRW (RFC 7432 default, RFC 8584) was not observed: FRR offers no way to
  pick an algorithm, and mixed-algorithm peers were not tested.
- `evpn mh uplink` (which `startup-delay` gates) was not used.
- Latencies include the 100 ms polling grain and ~60 ms inter-PE skew; the
  restart-return numbers include BGP re-establishment.
- The 10 s startup-delay in `lab.sh` is a lab choice, not FRR's default.

## Cleanup

`./lab.sh down` removes containers `dfe-pe1..3`, network `dfe-net` and `.work/pe*`.
Check: `podman ps -a --filter name=dfe-` and `podman network ls`.
The pulled image stays in the local store: `podman rmi quay.io/frrouting/frr:10.7.1`.
