#!/usr/bin/env bash
# FRR EVPN-MH designated-forwarder lab (rootless podman).  FRR is run as a
# black box: only its CLI output is observed.  See README.md.
#
#   lab.sh up | scenario <name> | down | status | vtysh <pe#> <cmd...>
#
# Env: DFE_STARTUP_DELAY  seconds for `evpn mh startup-delay` (default here: 10; empty = FRR default)
set -euo pipefail

IMAGE_TAG=10.7.1
IMAGE_DIGEST=sha256:e995beaa50fdc9edb35eadcfefa29b7f062cc06f2b812613789b68fa541554d2
IMAGE="quay.io/frrouting/frr:${IMAGE_TAG}@${IMAGE_DIGEST}"
NET=dfe-net
SUBNET=10.77.0.0/24
NPE=3
ASN=65000
ES_MAC=00:00:00:aa:00:01
VLANS="1000 1001"                     # VLAN id == VNI
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$HERE/.work"
OUT="${DFE_OUT:-$HERE/observed}"
mkdir -p "$WORK"

cname() { echo "dfe-pe$1"; }
cip()   { echo "10.77.0.1$1"; }       # underlay address
lo()    { echo "10.0.0.$1"; }         # loopback / VTEP / originator IP
now_ns(){ date +%s%N; }
log()   { echo "[lab] $*" >&2; }
vt()    { local n=$1; shift; podman exec "$(cname "$n")" vtysh "$@"; }

# ---- config ---------------------------------------------------------------
write_conf() {                        # write_conf <n> <pref>
  local n=$1 pref=$2 m d="$WORK/pe$1"
  mkdir -p "$d"; rm -f "$d/frr.conf" "$d/frr.conf.sav"   # frr may have rewritten it (owned by a sub-uid)
  cat > "$d/daemons" <<E
bgpd=yes
ospfd=no
ospf6d=no
ripd=no
ripngd=no
isisd=no
pimd=no
pim6d=no
ldpd=no
nhrpd=no
eigrpd=no
babeld=no
sharpd=no
pbrd=no
bfdd=no
fabricd=no
vrrpd=no
pathd=no
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
mgmtd_options="  -A 127.0.0.1"
bgpd_options="   -A 127.0.0.1"
staticd_options="-A 127.0.0.1"
E
  : > "$d/vtysh.conf"
  {
    echo "frr defaults traditional"
    echo "hostname pe$n"
    echo "log stdout informational"
    [ -z "${DFE_STARTUP_DELAY-10}" ] || echo "evpn mh startup-delay ${DFE_STARTUP_DELAY-10}"
    echo "router bgp $ASN"
    echo " bgp router-id $(lo "$n")"
    echo " no bgp default ipv4-unicast"
    for m in $(seq 1 $NPE); do
      [ "$m" = "$n" ] && continue
      echo " neighbor $(lo "$m") remote-as $ASN"
      echo " neighbor $(lo "$m") update-source lo"
      echo " neighbor $(lo "$m") timers connect 2"   # fast re-connect after a PE restart
    done
    echo " address-family l2vpn evpn"
    for m in $(seq 1 $NPE); do
      [ "$m" = "$n" ] || echo "  neighbor $(lo "$m") activate"
    done
    echo "  advertise-all-vni"
    echo " exit-address-family"
    echo "exit"
    echo "interface bond1"
    echo " evpn mh es-id 1"
    echo " evpn mh es-sys-mac $ES_MAC"
    [ "$pref" = none ] || echo " evpn mh es-df-pref $pref"
    echo "exit"
  } > "$d/frr.conf"
  chmod 644 "$d/daemons" "$d/vtysh.conf" "$d/frr.conf"
}

# ---- kernel data plane inside one PE ----------------------------------------
setup_net() {                         # setup_net <n>   (idempotent per fresh netns)
  local n=$1 m v
  {
    echo "set -e"
    echo "ip addr add $(lo "$n")/32 dev lo; ip link set lo up"
    for m in $(seq 1 $NPE); do
      [ "$m" = "$n" ] || echo "ip route add $(lo "$m")/32 via $(cip "$m")"
    done
    echo "ip link add br0 type bridge vlan_filtering 1 vlan_default_pvid 0; ip link set br0 addrgenmode none up"
    for v in $VLANS; do
      echo "ip link add vx$v type vxlan id $v dstport 4789 local $(lo "$n") nolearning"
      echo "ip link set vx$v addrgenmode none master br0 up"
      echo "bridge vlan add dev vx$v vid $v pvid untagged"
      echo "bridge link set dev vx$v neigh_suppress on learning off"
    done
    # access side: bond with one veth member; the veth peer (ce0) is just left up
    echo "ip link add bond1 type bond mode 802.3ad"
    echo "ip link set bond1 address $ES_MAC"
    echo "ip link add es0 type veth peer name ce0"
    echo "ip link set es0 master bond1"
    echo "ip link set ce0 up; ip link set es0 up"
    echo "ip link set bond1 master br0 up"
    for v in $VLANS; do echo "bridge vlan add dev bond1 vid $v"; done
  } | podman exec -i "$(cname "$n")" sh
}

# ---- up / down --------------------------------------------------------------
up() {
  local n prefs=(100 100 100)
  podman image exists "$IMAGE" || podman pull -q "$IMAGE" >/dev/null
  podman network exists $NET || podman network create --subnet $SUBNET $NET >/dev/null
  for n in $(seq 1 $NPE); do
    write_conf "$n" "${prefs[$((n-1))]}"
    podman rm -f "$(cname "$n")" >/dev/null 2>&1 || true
    podman run -d --name "$(cname "$n")" --hostname "pe$n" --network $NET --ip "$(cip "$n")" \
      --memory 256m --cap-add NET_ADMIN,SYS_ADMIN,NET_RAW -v "$WORK/pe$n:/etc/frr" "$IMAGE" >/dev/null
  done
  for n in $(seq 1 $NPE); do
    timeout 30 bash -c "until podman exec $(cname "$n") vtysh -c 'show version' >/dev/null 2>&1; do sleep 0.5; done"
    setup_net "$n"
  done
  log "up; waiting for BGP EVPN sessions"
  wait_bgp
}

wait_bgp() {
  local n
  for n in $(seq 1 $NPE); do
    timeout 90 bash -c "until [ \"\$(podman exec $(cname "$n") vtysh -c 'show bgp l2vpn evpn summary json' 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print(sum(1 for p in d.get(\"default\",d).get(\"peers\",{}).values() if p[\"state\"]==\"Established\"))' 2>/dev/null)\" = $((NPE-1)) ]; do sleep 1; done" \
      || { log "BGP not established on pe$n"; return 1; }
  done
}

down() {
  local n
  for n in $(seq 1 $NPE); do podman rm -f -t0 "$(cname "$n")" >/dev/null 2>&1 || true; done
  podman network exists $NET && podman network rm -f $NET >/dev/null 2>&1 || true
  # work dir is bind-mounted with container-root ownership mapping to the user: plain rm works
  rm -f "$WORK"/pe*/* 2>/dev/null || true
  rmdir "$WORK"/pe* "$WORK" 2>/dev/null || true
  log "down"
}

# ---- observation helpers -----------------------------------------------------
poll_start() {                        # in-container 100 ms poller, output on the bind mount
  local n
  for n in "$@"; do
    podman exec -d "$(cname "$n")" bash -c \
      'while :; do echo "@@ ${EPOCHREALTIME/./}"; vtysh -c "show evpn es detail json" 2>&1; sleep 0.1; done >> /etc/frr/poll.log 2>&1' >/dev/null
  done
}
poll_stop() {
  local n
  for n in "$@"; do
    podman exec "$(cname "$n")" pkill -f 'EPOCHREALTIME' 2>/dev/null || true
    podman exec "$(cname "$n")" pkill -f 'show evpn es detail' 2>/dev/null || true
  done
}
EVENTS=""
mark() {                              # mark action|note <text>: an event line at the current time
  EVENTS+="$(now_ns) $*"$'\n'
}

emit() {                              # emit <scenario> <t0_ns>: merge polls + marks into JSON lines
  local scen=$1 t0=$2 n args=()
  for n in $(seq 1 $NPE); do args+=("$n:$(lo "$n"):$WORK/pe$n/poll.log"); done
  printf '%s' "$EVENTS" | python3 "$HERE/collect.py" "$scen" "$t0" "${args[@]}"
}

LIVE="1 2 3"                          # PEs whose containers are running
wait_stable() {                       # wait_stable <secs>: exactly one live PE is DF, unchanged for <secs>
  local secs=${1:-3} deadline=$((SECONDS+${DFE_WAIT:-400})) prev="" cur since=$SECONDS n
  while [ $SECONDS -lt $deadline ]; do
    cur=""
    for n in $LIVE; do cur+="$(df_state "$n");"; done
    if [ "$cur" = "$prev" ] && [ "$(grep -o 'YES' <<<"$cur" | wc -l)" = 1 ] && [ $((SECONDS-since)) -ge "$secs" ]; then return 0; fi
    [ "$cur" = "$prev" ] || since=$SECONDS
    prev=$cur; sleep 1
  done
  log "not stable: $prev"; return 1
}
df_state() {                          # YES (is DF) | no | none  for the ES of PE n
  podman exec "$(cname "$1")" vtysh -c 'show evpn es detail json' 2>/dev/null | python3 -c '
import sys,json
try: d=json.load(sys.stdin)
except Exception: print("none"); sys.exit()
print("YES" if d and "df" in d[0].get("flags",[]) else "no" if d else "none")'
}
df_pe() {                             # index of the (single) live DF PE
  local n; for n in $LIVE; do [ "$(df_state "$n")" = YES ] && { echo "$n"; return; }; done; return 1
}
set_pref() {                          # set_pref <n> <pref|none>
  if [ "$2" = none ]; then vt "$1" -c 'conf t' -c 'interface bond1' -c 'no evpn mh es-df-pref' >/dev/null
  else vt "$1" -c 'conf t' -c 'interface bond1' -c "evpn mh es-df-pref $2" >/dev/null; fi
  vt "$1" -c 'write memory' >/dev/null 2>&1 || true
}
ce() { podman exec "$(cname "$1")" ip link set ce0 "$2"; }   # ce <n> up|down : the ES access link

# ---- scenarios ---------------------------------------------------------------
set_prefs() { local n=1 p; for p in "$@"; do set_pref "$n" "$p"; n=$((n+1)); done; }
begin() {                             # begin <scenario> <pref1> <pref2> <pref3>
  SCEN=$1; shift
  LIVE="1 2 3"; EVENTS=""
  set_prefs "$@"
  wait_stable 5
  local n; for n in $LIVE; do : > "$WORK/pe$n/poll.log"; done
  T0=$(now_ns); poll_start $LIVE
  mark note "prefs $*"
  sleep 2
}
finish() {
  sleep 1; poll_stop 1 2 3
  emit "$SCEN" "$T0" | tee "$OUT/$SCEN.jsonl"
}
note_snapshot() {                     # note_snapshot <pe#> <label> <vtysh cmd>: one-line cmd output as a note
  mark note "$2: $(vt "$1" -c "$3" 2>&1 | tr '\n\t"' '; ' | tr -s ' ')"
}

sc_steady_equal_pref() {
  begin steady-equal-pref 100 100 100
  note_snapshot 1 "pe1 es-evi (per-VNI carving?)" 'show evpn es-evi detail json'
  note_snapshot 1 "pe1 es detail" 'show evpn es detail'
  note_snapshot 2 "pe2 es detail" 'show evpn es detail'
  note_snapshot 1 "pe1 type-4 routes" 'show bgp l2vpn evpn route type 4'
  sleep 5; finish
}
sc_steady_pref() {
  begin steady-pref 100 200 300
  sleep 3
  note_snapshot 1 "pe1 type-4 routes" 'show bgp l2vpn evpn route type 4'
  mark note "knobs: $(podman exec "$(cname 1)" vtysh -c 'conf t' -c 'interface bond1' -c 'evpn mh ?' 2>&1 | tr '\n' ';' | tr -s ' ')"
  mark action "set_pref 10.0.0.1 400"; set_pref 1 400
  wait_stable 5; sleep 2
  mark action "set_pref 10.0.0.1 50"; set_pref 1 50
  wait_stable 5; sleep 2
  mark action "no_pref 10.0.0.3"; set_pref 3 none
  wait_stable 5; sleep 2
  finish
}
link_phase() {                        # link_phase <label> : take the current DF's ES link down and up
  local df; df=$(df_pe); mark note "phase $1: DF is 10.0.0.$df"
  mark action "link_down 10.0.0.$df"; ce "$df" down
  wait_stable 5; sleep 2
  mark action "link_up 10.0.0.$df"; ce "$df" up
  wait_stable 10; sleep 3
}
sc_df_link_down() {
  begin df-link-down 100 200 300
  link_phase distinct-prefs-100-200-300
  mark action "set_prefs 100 100 100"; set_prefs 100 100 100; wait_stable 5; sleep 2
  link_phase equal-prefs
  finish
}
pe_crash() {                          # pe_crash <n> : stop container, wait, start it again
  local n=$1
  mark action "pe_down 10.0.0.$n"; podman stop -t0 "$(cname "$n")" >/dev/null
  LIVE=$(for m in 1 2 3; do [ "$m" = "$n" ] || printf '%s ' "$m"; done)
  wait_stable 5; sleep 2
  mark action "pe_up 10.0.0.$n"; podman start "$(cname "$n")" >/dev/null
  timeout 30 bash -c "until podman exec $(cname "$n") vtysh -c 'show version' >/dev/null 2>&1; do sleep 0.3; done"
  setup_net "$n"; poll_start "$n"
  LIVE="1 2 3"
  wait_stable 10; sleep 3
}
sc_df_pe_crash() {
  begin df-pe-crash 100 200 300
  local df; df=$(df_pe); mark note "phase distinct-prefs: DF is 10.0.0.$df"; pe_crash "$df"
  mark action "set_prefs 100 100 100"; set_prefs 100 100 100; wait_stable 5; sleep 2
  df=$(df_pe); mark note "phase equal-prefs: DF is 10.0.0.$df"; pe_crash "$df"
  finish
}
sc_startup_delay() {                  # cold start of pe3 with FRR's default startup delay
  begin startup-delay 100 100 100
  DFE_STARTUP_DELAY= write_conf 3 100
  mark action "pe_restart 10.0.0.3 (default startup-delay)"
  podman restart -t0 "$(cname 3)" >/dev/null
  timeout 30 bash -c "until podman exec $(cname 3) vtysh -c 'show version' >/dev/null 2>&1; do sleep 0.3; done"
  setup_net 3; poll_start 3
  mark note "zebra: $(vt 3 -c 'show evpn json' | tr -d ' \n"')"
  local i
  for i in $(seq 1 26); do sleep 10; mark note "t+$((i*10))s: $(vt 3 -c 'show evpn json' 2>/dev/null | python3 -c 'import sys,json; d=json.load(sys.stdin); print("startupDelayTimer="+d["startupDelayTimer"]+" uplinkActive="+str(d["uplinkActiveCount"]))') es=$(df_state 3)"; done
  wait_stable 5
  write_conf 3 100
  finish
}

scenario() {
  case "$1" in
    steady-equal-pref) sc_steady_equal_pref ;;
    steady-pref)       sc_steady_pref ;;
    df-link-down)      sc_df_link_down ;;
    df-pe-crash)       sc_df_pe_crash ;;
    startup-delay)     sc_startup_delay ;;
    *) echo "unknown scenario $1" >&2; exit 2 ;;
  esac
}

case "${1:-}" in
  up) up ;;
  scenario) scenario "$2" ;;
  down) down ;;
  status) for n in $(seq 1 $NPE); do echo "pe$n: $(df_state "$n")"; done ;;
  vtysh) n=$2; shift 2; vt "$n" "$@" ;;
  *) echo "usage: $0 up|scenario <name>|down|status|vtysh <pe#> <cmd..>" >&2; exit 2 ;;
esac
