#!/usr/bin/env bash
# Runs one module's test binary for real, inside a disposable QEMU VM, as
# real root — for the tests that `scripts/test.sh`'s `unshare -rn` wrapping
# cannot reach: tc's RTM_NEWACTION (CAP_NET_ADMIN in the *initial* user
# namespace — no namespace trick grants that) and anything else that would
# otherwise pollute or collide with host netlink/nftables/wireguard state.
#
# Usage:
#   scripts/vm/run.sh <module> [platform] [--test-filter PATTERN]
#
#   <module>      any name from `zig build module-graph`
#   [platform]    openwrt | debian — defaults to this module's entry in the
#                 routing table below, or debian (the verified superset) if
#                 the module isn't listed
#   --test-filter forwarded to `zig test --test-filter` to run one test.
#                 REPEATABLE, and a union: zig skips tests matching no filter,
#                 so two of them run both. Some modules have a DEFAULT filter
#                 list (guest_default_filter below) because running their whole
#                 suite in here would be wrong; passing any explicitly replaces
#                 the whole default list.
#
# What it does, in order:
#   1. resolve <module>'s forward dependency closure from `zig build
#      module-graph` (the same authoritative graph scripts/test.sh reads —
#      this script never parses build.zig either)
#   2. cross-compile ONLY that closure's test binary for the guest's libc
#      with `zig test --test-no-exec`, never running it on the host
#   3. boot the target image with -snapshot (disk changes discarded on
#      exit — see README "Is -snapshot enough?")
#   4. get the binary into the guest (tftp first — qemu's usermode netdev
#      serves it with no host-side server process; falls back to a one-off
#      `python3 -m http.server` when the guest has no tftp client, which is
#      the case for both images here)
#   5. run it as real root, capture stdout+exit code
#   6. propagate that exit code as THIS script's exit code — a VM run that
#      always reports success would be worse than no VM lane at all
#
# See scripts/vm/README.md for the routing table's rationale and the
# one-liner to fetch images on a fresh clone.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
source "$SCRIPT_DIR/manifest.sh"
source "$SCRIPT_DIR/recipe.sh"

cd "$REPO_ROOT" || exit 1

MODULE="${1:-}"
if [[ -z "$MODULE" ]]; then
    echo "usage: scripts/vm/run.sh <module> [openwrt|debian] [--test-filter PATTERN]" >&2
    exit 1
fi
shift

PLATFORM=""
# Repeatable: `zig test --test-filter` is documented as "skip tests that do not
# match ANY filter", so several of them are a union, not an intersection. That
# is what lets one guest boot drive several protocols' live tests in sequence.
TEST_FILTERS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        openwrt|debian) PLATFORM="$1"; shift ;;
        --test-filter) TEST_FILTERS+=("$2"); shift 2 ;;
        *) echo "run.sh: unrecognized argument '$1'" >&2; exit 1 ;;
    esac
done

# ── routing table ────────────────────────────────────────────────────────
# Verified empirically (2026-07-28), not assumed:
#   tc       -> debian. OpenWRT's *stock* x86-64 build has NO tc qdisc/action
#               kernel modules at all — `modprobe sch_netem`/`act_gact`/
#               `cls_u32`/`cls_flower` all fail "not found", and there is no
#               `tc` userspace binary either. This is a real kernel gap, not
#               a privilege gap: Debian's generic cloud kernel loads every
#               one of those modules cleanly and ships tc/iproute2 6.15.
#               The PROVISIONED OpenWRT image (scripts/vm/provision.sh) does
#               have all of them and runs this suite fine — `scripts/vm/
#               run.sh tc openwrt` is execution-verified. The default stays
#               debian only because it needs no provisioning step; pick
#               openwrt explicitly to test the musl/OpenWRT kernel side.
#   nftables -> openwrt. Execution-verified: `zig build test-nftables`'s live
#               round-trip/atomicity/JSON-consistency suite (73 tests) all
#               pass for real, incl. an actual create/list/delete round-trip
#               and a batch-rollback-on-failure case.
#   conntrack-> openwrt. Execution-verified: 28 tests pass for real.
# Everything else (genetlink/nl80211/ethtool/devlink/wireguard/rawsock/
# ebpf/xdp-classifier and any future netns module): debian by default. Most
# of these don't actually need this VM lane in the first place — per
# scripts/test.sh's own NETNS_MODULES comment, `unshare -rn` already grants
# them what they need; this lane exists for the ones that namespace can't
# (tc's action table) or shouldn't (real writes that would collide with host
# state). wireguard/ebpf kernel support was NOT verified on either image —
# treat a route here as a starting guess, not a claim.
route_platform() {
    case "$1" in
        # tc runs on either now that the provisioned OpenWRT image carries
        # tc-full and the sched kmods; Debian stays the default for it
        # because its stock kernel already had them.
        tc) echo debian ;;
        nftables) echo openwrt ;;
        conntrack) echo openwrt ;;
        # ebpf needs CAP_BPF + CAP_PERFMON and a kernel with full BPF: six
        # live attach tests (kprobe, uprobe, tracepoint, raw tracepoint,
        # cgroup link) skip on any normal host. Debian only — OpenWRT's
        # kernel has no BPF tooling.
        ebpf) echo debian ;;
        *) echo debian ;;
    esac
}

[[ -z "$PLATFORM" ]] && PLATFORM="$(route_platform "$MODULE")"

# ── guest-side setup ─────────────────────────────────────────────────────
# A few modules' live tests need a device that only exists once a kernel
# module has been loaded as real root — which is the whole reason this lane
# exists. Kept as a table here, beside the routing table, rather than as an
# env var, so `run.sh <module>` stays reproducible from the module name alone.
#
#   nl80211 -> mac80211_hwsim, the kernel's fully simulated 802.11 radio.
#              Verified present in Debian's stock cloud kernel (see
#              manifest.sh). Two radios, so an AP and a STA can coexist on
#              the one simulated medium. Without this the module's eight live
#              tests skip on a headless guest exactly as they do on a host
#              with no wireless card.
#
#              The interfaces are brought UP as part of the setup, and that
#              is not cosmetic: hwsim registers them down, and TRIGGER_SCAN
#              on a down interface fails with ENETDOWN, so leaving them down
#              buys a skip where the point of this lane is to actually run
#              the privileged path. (That ENETDOWN is how the unmapped-errno
#              defect in client.errnoToError was found in the first place.)
#
# NOT here, deliberately: devlink/netdevsim. netdevsim.ko is shipped by no
# Debian and no OpenWRT package — see manifest.sh's "what this image CANNOT
# provide" note rather than re-deriving it.
#   fleetsim -> five real third-party SCADA masters. Its live tests are the
#              only external anchor the module has, and every one of them
#              needs a counterpart process that cannot be installed on the dev
#              host (pip-only libraries, and the owner's standing rule is that
#              a venv is one-shot). Inside a disposable guest that constraint
#              does not apply: pymodbus 3.14.0, pycomm3 1.2.16, bacpypes3
#              0.0.106, python-snap7 3.1.0 and asyncua 2.0.1 are baked into
#              the provisioned image by the recipe (manifest.sh's
#              VM_DEBIAN_PIP), and guests/fleetsim-<protocol>-master.py drives
#              each simulated device through a byte tap so the sessions can
#              also be frozen into the offline suite. Every master retries its
#              connect for the whole run budget, so neither the start race nor
#              the sequential test order matters.
#
#              Each master also GRADES: it writes what it decoded back into
#              the device through that protocol's own write service, and the
#              Zig test asserts on those marks. See the `*_verdict` blocks in
#              modules/fleetsim/src/root.zig, and guest_require below for why
#              the shell gate deliberately does not.
#
# guest_setup runs BEFORE the test binary, so it may only set up and launch;
# anything that has to read a result afterwards belongs in guest_after.
guest_setup() {
    case "$1" in
        nl80211)
            printf '%s' \
                'modprobe mac80211_hwsim radios=2 && ip link set wlan0 up && ' \
                'ip link set wlan1 up && echo SETUP_OK || echo SETUP_FAIL; '
            ;;
        fleetsim)
            # No quotes anywhere in here: the whole command line is passed to
            # expect as one argv element and read back with `lindex`, and
            # keeping it quote-free keeps that round-trip boring.
            #
            # Every master is launched at once, before the test binary starts,
            # and every one of them retries its connect for the whole run
            # budget. That is deliberate: the binary runs its live tests
            # SEQUENTIALLY, each holding its socket for the full 60 s
            # `live_run_ms`, so the last master in the order does not see its
            # device until ~4 minutes in. A short wait here would look exactly
            # like a broken lane.
            local m setup=''
            for m in $(fleetsim_masters); do
                setup+="export $(fleetsim_master_env "$m")=127.0.0.1:$(fleetsim_master_port "$m"); "
            done
            setup+='export FLEETSIM_EXPECT_LIVE=1; '
            for m in $(fleetsim_masters); do
                setup+="curl -fsS http://10.0.2.2:$HTTP_PORT/fleetsim-$m-master.py -o /tmp/fm-$m.py && "
            done
            setup+='python3 -m pip show pymodbus > /dev/null && echo SETUP_OK || echo SETUP_FAIL; '
            for m in $(fleetsim_masters); do
                setup+="nohup python3 /tmp/fm-$m.py 127.0.0.1 $(fleetsim_master_port "$m") $FLEETSIM_MASTER_WAIT > /tmp/fm-$m.log 2>&1 & "
            done
            printf '%s' "$setup"
            ;;
        *) printf '' ;;
    esac
}

# ── fleetsim's master table ──────────────────────────────────────────────
# One row per third-party master the guest image can serve. Adding a master
# means: a pip pin in manifest.sh's VM_DEBIAN_PIP, a driver script in
# scripts/vm/guests/, a verdict channel in the module's live test, and a row
# here. All four together or none — a half-wired lane that fails by default is
# how this audit collected eleven lying stamps.
#
# `FLEETSIM_MASTERS` narrows the set for a single run (e.g. while iterating on
# one driver). It is a development affordance, not a supported mode: the
# default is every master, and that is what the lane is judged on.
fleetsim_masters() {
    printf '%s\n' "${FLEETSIM_MASTERS:-modbus enip bacnet s7 opcua}"
}

fleetsim_master_env() {
    case "$1" in
        modbus) echo FLEETSIM_TEST_LISTEN ;;
        enip)   echo FLEETSIM_ENIP_LISTEN ;;
        bacnet) echo FLEETSIM_BACNET_LISTEN ;;
        s7)     echo FLEETSIM_S7_LISTEN ;;
        opcua)  echo FLEETSIM_OPCUA_LISTEN ;;
    esac
}

fleetsim_master_port() {
    case "$1" in
        modbus) echo 15020 ;;
        enip)   echo 15021 ;;
        bacnet) echo 15022 ;;
        s7)     echo 15024 ;;
        opcua)  echo 15025 ;;
    esac
}

fleetsim_master_marker() {
    case "$1" in
        modbus) echo MODBUS_MASTER_DONE ;;
        enip)   echo ENIP_MASTER_DONE ;;
        bacnet) echo BACNET_MASTER_DONE ;;
        s7)     echo S7_MASTER_DONE ;;
        opcua)  echo OPCUA_MASTER_DONE ;;
    esac
}

# The `--test-filter` that selects exactly this master's live test.
fleetsim_master_filter() {
    case "$1" in
        modbus) echo 'live: a real Modbus master' ;;
        enip)   echo 'live: a real EtherNet/IP master' ;;
        bacnet) echo 'live: a real BACnet client' ;;
        s7)     echo 'live: a real S7 client' ;;
        opcua)  echo 'live: a real OPC UA client' ;;
    esac
}

# How long each master waits for its device, in seconds. Sized from the run
# itself: N live tests x `live_run_ms` (60 s each, sequential) plus boot and
# the binary's own startup. Deliberately generous — the cost of overshooting
# is a process sleeping in a VM that is about to be discarded.
FLEETSIM_MASTER_WAIT=420

# Runs AFTER the test binary, before GUEST_EXIT is reported. Its own exit code
# is deliberately discarded — the binary's is what this lane propagates.
guest_after() {
    case "$1" in
        fleetsim)
            # `wait` for every master, then print each transcript in turn. The
            # logs are what gets frozen into src/master_goldens.zig, so they
            # have to reach the host even when the suite already failed.
            local m after='wait; '
            for m in $(fleetsim_masters); do
                after+="echo ===MASTER-$m===; cat /tmp/fm-$m.log; "
            done
            printf '%s' "$after"
            ;;
        *) printf '' ;;
    esac
}

# Extra files to serve alongside the test binary, repo-relative. Fetched by
# guest_setup over the same one-off http server.
guest_files() {
    case "$1" in
        fleetsim)
            local m
            for m in $(fleetsim_masters); do
                printf '%s\n' "scripts/vm/guests/fleetsim-$m-master.py"
            done
            ;;
        *) printf '' ;;
    esac
}

# Markers the guest MUST print, beyond the binary's own exit code. This is the
# same defence as the SETUP_OK check: a live test that silently did not run
# leaves an all-green suite behind it, so the counterpart has to say for
# itself that it was there.
#
# PRESENCE ONLY — deliberately. fleetsim's marker used to be
# MODBUS_MASTER_OK, i.e. the master's own *grade*, and that turned out to be
# the only thing carrying the anchor: with the device's register encoder
# byte-swapped the Zig live test still passed (it asserted frame counts and
# nothing else) and the run went red purely because this gate missed the OK.
# A grade enforced by a shell `grep` is not a test suite. The masters now write
# what they decoded back into the device (a "verdict block"), the live tests
# assert on it, and this gate is left with the one job it is actually good at:
# proving the counterpart was there at all. _DONE means "ran to the end",
# never "was satisfied".
guest_require() {
    case "$1" in
        fleetsim)
            local m
            for m in $(fleetsim_masters); do
                fleetsim_master_marker "$m"
            done
            ;;
        *) printf '' ;;
    esac
}

# Guest RAM, MB. 512 is enough for a netlink suite; a simulation harness that
# stands up a thousand in-process devices is not that.
guest_mem() {
    case "$1" in
        fleetsim) echo 1536 ;;
        *) echo 512 ;;
    esac
}

# Seconds boot-debian.exp will wait for the command batch. The default 90 is
# sized for a suite that runs in seconds; fleetsim's live tests each hold a
# socket open for a 60s budget by design.
guest_cmd_timeout() {
    case "$1" in
        # Five live tests, each holding its socket for the full 60 s
        # `live_run_ms`, run one after another — plus boot, plus the rest of
        # the filtered suite. 900 leaves headroom over the ~340 s that costs.
        fleetsim) echo 900 ;;
        *) echo 90 ;;
    esac
}

# A default --test-filter, when running the WHOLE suite in the VM would be
# wrong. fleetsim: the guest carries five masters, and FLEETSIM_EXPECT_LIVE=1
# turns "did not run" into a failure for every live test — so without a filter
# the live tests whose master is NOT installed (DNP3's opendnp3, IEC 104's
# c104, and the two-masters case) would fail for the wrong reason. Filtering to
# the tests the guest can actually serve keeps the failure signal honest. The
# master table above is the single place all of this is listed, so adding a
# master widens the pip list, the filter, the marker gate and the launcher
# together — never separately.
guest_default_filter() {
    case "$1" in
        fleetsim)
            local m
            for m in $(fleetsim_masters); do
                fleetsim_master_filter "$m"
            done
            ;;
        *) printf '' ;;
    esac
}

if [[ ${#TEST_FILTERS[@]} -eq 0 ]]; then
    while IFS= read -r _f; do
        [[ -z "$_f" ]] && continue
        TEST_FILTERS+=("$_f")
        echo "vm: default --test-filter for $MODULE: '$_f'"
    done < <(guest_default_filter "$MODULE")
fi

case "$PLATFORM" in
    openwrt) TARGET_TRIPLE="x86_64-linux-musl" ;;
    debian) TARGET_TRIPLE="x86_64-linux-gnu" ;;
    *) echo "run.sh: unknown platform '$PLATFORM' (openwrt|debian)" >&2; exit 1 ;;
esac

IMAGES_DIR="$SCRIPT_DIR/images"
WORK_DIR="$SCRIPT_DIR/work"
mkdir -p "$WORK_DIR"

# ── image selection: provisioned first, stock as a loud fallback ─────────
# The provisioned image's filename embeds its recipe hash (scripts/vm/
# recipe.sh), so a package-list change makes the current recipe resolve to a
# name that does not exist yet — a guaranteed miss. A stale image built from
# an older list is never reachable, because nothing ever asks for its name.
# That matters: "provisioned image is out of date" and "the package didn't
# install" produce identical test failures, and only one of them is a bug in
# the code under test.
case "$PLATFORM" in
    openwrt) STOCK_IMG="$IMAGES_DIR/$VM_OPENWRT_FILE" ;;
    debian) STOCK_IMG="$IMAGES_DIR/$VM_DEBIAN_FILE" ;;
esac
PROV_IMG="$(provisioned_image "$PLATFORM")"
IMAGE_KIND="provisioned"
IMG="$PROV_IMG"
if ! provisioned_ok "$PLATFORM"; then
    IMAGE_KIND="STOCK (unprovisioned)"
    IMG="$STOCK_IMG"
    echo "run.sh: no provisioned $PLATFORM image for recipe $(recipe_hash "$PLATFORM" | cut -c1-12)" >&2
    stale="$(list_stale_provisioned "$PLATFORM")"
    if [[ -n "$stale" ]]; then
        echo "        (provisioned images DO exist for other recipes — the package list changed:" >&2
        echo "$stale" | sed 's/^/          /' >&2
        echo "         they are NOT used; a stale guest would silently look like a code bug)" >&2
    fi
    echo "        falling back to the STOCK image — run: scripts/vm/provision.sh $PLATFORM" >&2
fi
if [[ ! -f "$IMG" ]]; then
    echo "run.sh: image missing: $IMG" >&2
    echo "        run: scripts/vm/fetch-images.sh $PLATFORM && scripts/vm/provision.sh $PLATFORM" >&2
    exit 1
fi

echo "vm: module=$MODULE platform=$PLATFORM target=$TARGET_TRIPLE image=$(basename "$IMG") [$IMAGE_KIND]"

# ── 1. dependency closure (forward: what MODULE depends on) ────────────
declare -a G_NAMES=() G_DEPS=()
tsv="$(zig build module-graph 2>&1)"
if [[ $? -ne 0 ]]; then
    echo "run.sh: 'zig build module-graph' failed:" >&2
    echo "$tsv" >&2
    exit 1
fi
while IFS=$'\t' read -r name _heavy deps; do
    [[ -z "$name" ]] && continue
    G_NAMES+=("$name")
    G_DEPS+=("$deps")
done <<< "$tsv"

deps_of() {
    local target="$1" i
    for (( i = 0; i < ${#G_NAMES[@]}; i++ )); do
        if [[ "${G_NAMES[$i]}" == "$target" ]]; then
            printf '%s' "${G_DEPS[$i]}"
            return 0
        fi
    done
    return 1
}

if ! deps_of "$MODULE" >/dev/null; then
    echo "run.sh: '$MODULE' is not in the module graph" >&2
    exit 1
fi

# BFS over the "depends on" edge (opposite direction from test.sh's
# reverse-dependency closure, which is "depends on ME").
declare -a CLOSURE=("$MODULE")
declare -a FRONTIER=("$MODULE")
seen=" $MODULE "
while [[ ${#FRONTIER[@]} -gt 0 ]]; do
    declare -a NEXT=()
    for m in "${FRONTIER[@]}"; do
        d="$(deps_of "$m")"
        for dep in ${d//,/ }; do
            [[ -z "$dep" ]] && continue
            case "$seen" in *" $dep "*) continue ;; esac
            seen="$seen$dep "
            CLOSURE+=("$dep")
            NEXT+=("$dep")
        done
    done
    FRONTIER=("${NEXT[@]}")
done
echo "vm: dependency closure: ${CLOSURE[*]}"

# ── 2. cross-compile the test binary, WITHOUT running it on the host ────
# `zig test --test-no-exec -femit-bin=…` compiles and stops — this is the
# mechanism, not `zig build test-<module> -Dtarget=…`, because the build.zig
# per-module step always chains an addRunArtifact and would try to execute
# the cross binary on the host the moment its OS/arch matched (a static
# musl binary runs fine on a glibc host — same kernel, no dynamic linking —
# so that isn't even a hard failure, just the wrong thing to do).
#
# Each module in CLOSURE gets its own `--dep`s (from the SAME graph) before
# its own `-M`; Zig resolves `--dep` names against every `-M` on the command
# line regardless of order, so the closure can be emitted in any order (only
# the FIRST `-M` must be the module under test — that's what "the main
# module" means to `zig test`). Verified on a 2-level chain (wireguard ->
# genetlink -> netlink) before relying on it here.
ZIG_ARGS=()
for m in "${CLOSURE[@]}"; do
    d="$(deps_of "$m")"
    for dep in ${d//,/ }; do
        [[ -z "$dep" ]] && continue
        ZIG_ARGS+=(--dep "$dep")
    done
    ZIG_ARGS+=("-M${m}=modules/${m}/src/root.zig")
done

BIN="$WORK_DIR/${MODULE}-${PLATFORM}-test"
rm -f "$BIN"
ZIG_CMD=(zig test "${ZIG_ARGS[@]}" -target "$TARGET_TRIPLE" --test-no-exec -femit-bin="$BIN")
# Guarded: `"${arr[@]}"` on an empty array trips `set -u` on bash before 4.4,
# and this script is expected to run on whatever bash the host ships.
if [[ ${#TEST_FILTERS[@]} -gt 0 ]]; then
    for _f in "${TEST_FILTERS[@]}"; do ZIG_CMD+=(--test-filter "$_f"); done
fi

echo "vm: compiling for $TARGET_TRIPLE (host never executes this binary)..."
if ! "${ZIG_CMD[@]}"; then
    echo "run.sh: cross-compile failed" >&2
    exit 1
fi
if [[ ! -x "$BIN" ]]; then
    echo "run.sh: expected binary not produced: $BIN" >&2
    exit 1
fi
echo "vm: built $(du -h "$BIN" | cut -f1) $BIN"

# ── 3. serve it (tftp built into qemu's usermode netdev; http fallback) ──
SERVE_DIR="$WORK_DIR/serve"
mkdir -p "$SERVE_DIR"
BIN_NAME="runme"
cp "$BIN" "$SERVE_DIR/$BIN_NAME"

# Anything guest_setup will curl. Served from the same directory as the test
# binary so there is exactly one transfer mechanism to reason about.
while IFS= read -r f; do
    [[ -z "$f" ]] && continue
    if [[ ! -f "$REPO_ROOT/$f" ]]; then
        echo "run.sh: guest file missing: $f" >&2
        exit 1
    fi
    cp "$REPO_ROOT/$f" "$SERVE_DIR/$(basename "$f")"
    echo "vm: serving guest file $(basename "$f")"
done < <(guest_files "$MODULE")

HTTP_PID=""
cleanup() {
    [[ -n "$HTTP_PID" ]] && kill "$HTTP_PID" >/dev/null 2>&1
}
trap cleanup EXIT

# A random port (not the obvious 8000) so a stale server left over from an
# earlier interrupted run — or a second concurrent `run.sh` — can't silently
# bind-fail and have curl/wget quietly hit the WRONG server's 404 instead of
# ours. Verified locally (not just "port opened") before booting anything.
HTTP_PORT=$(( 20000 + (RANDOM % 20000) ))
( cd "$SERVE_DIR" && exec python3 -m http.server "$HTTP_PORT" ) >"$WORK_DIR/http.log" 2>&1 &
HTTP_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -fsS "http://127.0.0.1:$HTTP_PORT/$BIN_NAME" -o /dev/null 2>/dev/null && break
    sleep 0.3
done
if ! curl -fsS "http://127.0.0.1:$HTTP_PORT/$BIN_NAME" -o /dev/null 2>/dev/null; then
    echo "run.sh: local http server on :$HTTP_PORT never served $BIN_NAME — see $WORK_DIR/http.log" >&2
    exit 1
fi

# Now that the port is known, the setup line can reference it.
SETUP="$(guest_setup "$MODULE")"
AFTER="$(guest_after "$MODULE")"
[[ -n "$SETUP" ]] && echo "vm: guest setup: ${SETUP%; }"

VMLOG="$WORK_DIR/${MODULE}-${PLATFORM}-vm.log"

# ── 4/5. boot + fetch + run ──────────────────────────────────────────────
t0=$(date +%s)
case "$PLATFORM" in
    openwrt)
        RUNCMD="$SETUP(tftp -g -r $BIN_NAME -l /tmp/$BIN_NAME 10.0.2.2 && echo TFTP_OK) || echo TFTP_FAIL; if \[ ! -s /tmp/$BIN_NAME \]; then wget http://10.0.2.2:$HTTP_PORT/$BIN_NAME -O /tmp/$BIN_NAME >/dev/null 2>&1 && echo WGET_OK || echo WGET_FAIL; fi; chmod +x /tmp/$BIN_NAME; /tmp/$BIN_NAME; RC=\$?; ${AFTER}echo GUEST_EXIT=\$RC"
        expect "$SCRIPT_DIR/boot-openwrt.exp" "$IMG" 256 "$RUNCMD" >"$VMLOG" 2>&1
        ;;
    debian)
        HASH='$6$ziglibsvm$2WcZuPUB4TEmGwA.07rEyxkoXl.TTGBAGJBnUjWbJhfpEFQiFc08SdtJACCJGetmUIy5MIbNfFN/Zy.euXHIC1'  # throwaway VM-only password "zigvm" — ephemeral -snapshot guest, no host port exposed
        RUNCMD="${SETUP}curl -fsS http://10.0.2.2:$HTTP_PORT/$BIN_NAME -o /tmp/$BIN_NAME && echo FETCH_OK || echo FETCH_FAIL; chmod +x /tmp/$BIN_NAME; /tmp/$BIN_NAME; RC=\$?; ${AFTER}echo GUEST_EXIT=\$RC"
        expect "$SCRIPT_DIR/boot-debian.exp" "$IMG" "$HASH" "$(guest_mem "$MODULE")" "$RUNCMD" "$(guest_cmd_timeout "$MODULE")" >"$VMLOG" 2>&1
        ;;
esac
t1=$(date +%s)

# ── 6. slice out the guest's own output, propagate its exit code ────────
GUEST_OUT="$(awk '/===VM_CMD_BEGIN===/{f=1;next}/===VM_CMD_END===/{f=0}f' "$VMLOG")"
echo "$GUEST_OUT"
echo
echo "vm: wall time $((t1 - t0))s (full log: $VMLOG)"

# Herestrings, not `echo … | grep -q`, in every gate below. Under `set -o
# pipefail` — which this script sets — `grep -q` exits the moment it matches,
# `echo` then dies of SIGPIPE (141), and the PIPELINE reports 141 even though
# the pattern WAS found. That is invisible while the guest prints a few lines
# and fires the moment it prints a lot: a five-master fleetsim run whose every
# marker was present, whose suite passed and whose GUEST_EXIT was 0 came back
# as "binary transfer into the guest never succeeded". A herestring has no
# pipeline and no early-exit hazard.
if ! grep -q "FETCH_OK\|TFTP_OK\|WGET_OK" <<< "$GUEST_OUT"; then
    echo "run.sh: FAIL — binary transfer into the guest never succeeded" >&2
    exit 1
fi

# A failed setup must not be allowed to look like a pass. Without the device
# the module's live tests skip, and a suite that skips everything still exits
# 0 — the exact "silent skip reads as success" failure this lane exists to
# avoid.
if [[ -n "$SETUP" ]] && ! grep -q "SETUP_OK" <<< "$GUEST_OUT"; then
    echo "run.sh: FAIL — guest setup for '$MODULE' did not report SETUP_OK" >&2
    echo "        (the live tests would have skipped and the run would have looked green)" >&2
    exit 1
fi

# Same defence one level up: a counterpart process that never reached the
# device leaves the suite green (the live test just skips), so anything the
# guest was supposed to prove has to be asserted by name.
while IFS= read -r marker; do
    [[ -z "$marker" ]] && continue
    if ! grep -q "$marker" <<< "$GUEST_OUT"; then
        echo "run.sh: FAIL — guest never printed '$marker'" >&2
        echo "        (the live counterpart did not complete; the suite alone would have looked green)" >&2
        exit 1
    fi
done < <(guest_require "$MODULE")

EXIT_LINE="$(grep -o 'GUEST_EXIT=[0-9]*' <<< "$GUEST_OUT" | tail -1)"
if [[ -z "$EXIT_LINE" ]]; then
    echo "run.sh: FAIL — never saw a GUEST_EXIT= marker (VM likely hung or crashed — see $VMLOG)" >&2
    exit 1
fi
GUEST_EXIT="${EXIT_LINE#GUEST_EXIT=}"
exit "$GUEST_EXIT"
