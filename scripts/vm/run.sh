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
#   --test-filter forwarded to `zig test --test-filter` to run one test
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
TEST_FILTER=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        openwrt|debian) PLATFORM="$1"; shift ;;
        --test-filter) TEST_FILTER="$2"; shift 2 ;;
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
guest_setup() {
    case "$1" in
        nl80211)
            printf '%s' \
                'modprobe mac80211_hwsim radios=2 && ip link set wlan0 up && ' \
                'ip link set wlan1 up && echo SETUP_OK || echo SETUP_FAIL; '
            ;;
        *) printf '' ;;
    esac
}
SETUP="$(guest_setup "$MODULE")"
[[ -n "$SETUP" ]] && echo "vm: guest setup: ${SETUP%; }"

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
[[ -n "$TEST_FILTER" ]] && ZIG_CMD+=(--test-filter "$TEST_FILTER")

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

VMLOG="$WORK_DIR/${MODULE}-${PLATFORM}-vm.log"

# ── 4/5. boot + fetch + run ──────────────────────────────────────────────
t0=$(date +%s)
case "$PLATFORM" in
    openwrt)
        RUNCMD="$SETUP(tftp -g -r $BIN_NAME -l /tmp/$BIN_NAME 10.0.2.2 && echo TFTP_OK) || echo TFTP_FAIL; if \[ ! -s /tmp/$BIN_NAME \]; then wget http://10.0.2.2:$HTTP_PORT/$BIN_NAME -O /tmp/$BIN_NAME >/dev/null 2>&1 && echo WGET_OK || echo WGET_FAIL; fi; chmod +x /tmp/$BIN_NAME; /tmp/$BIN_NAME; echo GUEST_EXIT=\$?"
        expect "$SCRIPT_DIR/boot-openwrt.exp" "$IMG" 256 "$RUNCMD" >"$VMLOG" 2>&1
        ;;
    debian)
        HASH='$6$ziglibsvm$2WcZuPUB4TEmGwA.07rEyxkoXl.TTGBAGJBnUjWbJhfpEFQiFc08SdtJACCJGetmUIy5MIbNfFN/Zy.euXHIC1'  # throwaway VM-only password "zigvm" — ephemeral -snapshot guest, no host port exposed
        RUNCMD="${SETUP}curl -fsS http://10.0.2.2:$HTTP_PORT/$BIN_NAME -o /tmp/$BIN_NAME && echo FETCH_OK || echo FETCH_FAIL; chmod +x /tmp/$BIN_NAME; /tmp/$BIN_NAME; echo GUEST_EXIT=\$?"
        expect "$SCRIPT_DIR/boot-debian.exp" "$IMG" "$HASH" 512 "$RUNCMD" >"$VMLOG" 2>&1
        ;;
esac
t1=$(date +%s)

# ── 6. slice out the guest's own output, propagate its exit code ────────
GUEST_OUT="$(awk '/===VM_CMD_BEGIN===/{f=1;next}/===VM_CMD_END===/{f=0}f' "$VMLOG")"
echo "$GUEST_OUT"
echo
echo "vm: wall time $((t1 - t0))s (full log: $VMLOG)"

if ! echo "$GUEST_OUT" | grep -q "FETCH_OK\|TFTP_OK\|WGET_OK"; then
    echo "run.sh: FAIL — binary transfer into the guest never succeeded" >&2
    exit 1
fi

# A failed setup must not be allowed to look like a pass. Without the device
# the module's live tests skip, and a suite that skips everything still exits
# 0 — the exact "silent skip reads as success" failure this lane exists to
# avoid.
if [[ -n "$SETUP" ]] && ! echo "$GUEST_OUT" | grep -q "SETUP_OK"; then
    echo "run.sh: FAIL — guest setup for '$MODULE' did not report SETUP_OK" >&2
    echo "        (the live tests would have skipped and the run would have looked green)" >&2
    exit 1
fi

EXIT_LINE="$(echo "$GUEST_OUT" | grep -o 'GUEST_EXIT=[0-9]*' | tail -1)"
if [[ -z "$EXIT_LINE" ]]; then
    echo "run.sh: FAIL — never saw a GUEST_EXIT= marker (VM likely hung or crashed — see $VMLOG)" >&2
    exit 1
fi
GUEST_EXIT="${EXIT_LINE#GUEST_EXIT=}"
exit "$GUEST_EXIT"
