#!/usr/bin/env bash
# seglog on a real filesystem, crashed at every flush and every FUA write: dm-log-writes.
#
#   zig build seglog-crash -Doptimize=ReleaseSafe        # as yourself, first
#   sudo seglog/tools/crash-dm/run.sh [records] [fs]     # records 300, fs ext4
#
# What it does. A 64 MiB filesystem is made on a dm-log-writes device, which
# records every write, flush and FUA in order onto a log device. The workload
# (`seglog-crash write`) appends `records` records with fsync each, rotating
# and compressing, once without and once with preallocation. Then replay-log
# (xfstests) replays that log onto a fresh device and, after every flush —
# every point a power cut could have left the disk in — the checker copies
# the device, mounts the copy (the filesystem's own journal recovery runs),
# and runs `seglog-crash check`: the log must open, hold 1, 2, 3 … with the
# right bytes and no gap, and `verify` clean. Across the points the count may
# only grow, and at the end it must be every record the workload saw acked.
#
# Needs root for loop devices, device-mapper and mount; everything else is in
# egw-hub/.zig-cache/crash-dm (on disk, not tmpfs), and the trap undoes the
# devices and mounts whatever happens. replay-log is GPL-2 test tooling from
# xfstests: downloaded and built here, never committed or shipped.
set -euo pipefail

N=${1:-300}
FS=${2:-ext4}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
HUB=$(cd "$HERE/../../.." && pwd)
BIN=$HUB/zig-out/bin/seglog-crash
W=$HUB/.zig-cache/crash-dm
DM=seglog-lw
OWNER=${SUDO_USER:-$(id -un)}

[ "$(id -u)" = 0 ] || { echo "run.sh: needs root (sudo)" >&2; exit 2; }
[ -x "$BIN" ] || { echo "run.sh: build $BIN first: zig build seglog-crash -Doptimize=ReleaseSafe" >&2; exit 2; }
command -v "mkfs.$FS" >/dev/null || { echo "run.sh: no mkfs.$FS" >&2; exit 2; }
mkdir -p "$W/mnt" "$W/snapmnt"

RL=$W/xfstests/replay-log
if [ ! -x "$RL" ]; then
    mkdir -p "$W/xfstests"
    for f in replay-log.c log-writes.c log-writes.h; do
        curl -fsSL -o "$W/xfstests/$f" \
            "https://git.kernel.org/pub/scm/fs/xfs/xfstests-dev.git/plain/src/log-writes/$f"
    done
    gcc -O2 -o "$RL" "$W/xfstests/replay-log.c" "$W/xfstests/log-writes.c"
fi
modprobe dm-log-writes

LOOPS=()
cleanup() {
    set +e
    mountpoint -q "$W/snapmnt" && umount "$W/snapmnt"
    mountpoint -q "$W/mnt" && umount "$W/mnt"
    dmsetup info "$DM" >/dev/null 2>&1 && dmsetup remove "$DM"
    for l in "${LOOPS[@]}"; do losetup -d "$l"; done
    rm -f "$W/data.img" "$W/log.img" "$W/replay.img" "$W/snap-0.img" "$W/snap-1.img"
    chown -R "$OWNER": "$W"
}
trap cleanup EXIT

# `attach VAR file`: not `VAR=$(attach file)` — a command substitution is a
# subshell, and the device it added to LOOPS never reached the cleanup (six
# loop devices were left attached that way).
attach() { local d; d=$(losetup -f --show "$2"); LOOPS+=("$d"); printf -v "$1" '%s' "$d"; }

# Devices a killed earlier run left attached to this directory's images.
losetup -a | awk -F: -v w="$W/" 'index($0, w) { print $1 }' | while read -r stale; do
    losetup -d "$stale" && echo "run.sh: detached stale $stale"
done

# The checker replay-log runs after every flush entry: on a COPY of the replay
# device, since mounting runs journal recovery, which writes. The copy gets a
# loop device attached and detached here: `mount -o loop` frees its device
# lazily, and a check mounting the same file while the last one's device was
# still attached failed as "already mounted" (after 569 good checks). Two
# copies alternate, so a device still going away never holds the next one.
cat > "$W/check.sh" <<EOF
#!/usr/bin/env bash
set -u
points=\$(wc -l < "\$COUNTS")
snap="$W/snap-\$(( points % 2 )).img"
dd if="\$REPLAY_DEV" of="\$snap" bs=1M status=none
dev=\$(losetup -f --show "\$snap") || { echo "CHECK: losetup failed after \$points points" >&2; exit 1; }
if ! mount -t $FS "\$dev" "$W/snapmnt"; then
    losetup -d "\$dev"; echo "CHECK: mount failed after \$points points" >&2; exit 1
fi
out=\$("$BIN" check "$W/snapmnt/log" 2>&1); rc=\$?
umount "$W/snapmnt"
for i in 1 2 3 4 5 6 7 8 9 10; do losetup -d "\$dev" 2>/dev/null && break; sleep 0.1; done
[ \$rc = 0 ] || { echo "CHECK FAILED at point \$points: \$out" >&2; exit 1; }
n=\${out#records }
prev=\$(tail -1 "\$COUNTS" 2>/dev/null || echo 0)
[ "\$n" -ge "\${prev:-0}" ] || { echo "CHECK FAILED at point \$points: \$n records after \$prev at an earlier point" >&2; exit 1; }
echo "\$n" >> "\$COUNTS"
EOF
chmod +x "$W/check.sh"

verdict=0
for PA in 0 65536; do
    echo "── $FS, $N records, preallocate=$PA"
    for f in data log replay; do rm -f "$W/$f.img"; truncate -s 64M "$W/$f.img"; done
    truncate -s 512M "$W/log.img" # every write, with its data
    attach DATA "$W/data.img"; attach LOGD "$W/log.img"; attach REPL "$W/replay.img"
    dmsetup create "$DM" --table "0 $(blockdev --getsz "$DATA") log-writes $DATA $LOGD"
    "mkfs.$FS" -q "/dev/mapper/$DM" >/dev/null
    dmsetup message "$DM" 0 mark mkfs
    mount "/dev/mapper/$DM" "$W/mnt"
    "$BIN" write "$W/mnt/log" "$N" "$PA" > "$W/acked.txt"
    acked=$(grep -c '^acked' "$W/acked.txt")
    umount "$W/mnt"
    dmsetup remove "$DM"

    # Crash points of two kinds, one replay each: every flush, and every FUA
    # write. Neither alone sees every state. With preallocation an fdatasync
    # into written reserved blocks is a bare flush (FUA-only saw 34 of 301
    # states); one into a fresh unwritten block converts it in the journal,
    # so the record is readable only after the commit's FUA write (flush-only
    # missed exactly those 14, one per 4 KiB block).
    t0=$(date +%s)
    ok=1
    for MODE in flush fua; do
        COUNTS=$W/counts-$PA-$MODE; : > "$COUNTS"; export COUNTS
        dd if=/dev/zero of="$REPL" bs=1M status=none 2>/dev/null || true
        # mkfs first, unchecked (a half-made filesystem does not mount).
        "$RL" --log "$LOGD" --replay "$REPL" --end-mark mkfs > "$W/replay-$MODE.out" 2>&1
        if REPLAY_DEV=$REPL "$RL" --log "$LOGD" --replay "$REPL" --start-mark mkfs --check "$MODE" --fsck "$W/check.sh" >> "$W/replay-$MODE.out" 2>&1; then
            # And the end of the log: everything acked is there.
            REPLAY_DEV=$REPL "$W/check.sh" 2>>"$W/replay-$MODE.out"
            last=$(tail -1 "$COUNTS")
            if [ "$last" != "$acked" ]; then
                echo "   FAILED ($MODE): $acked acked, $last at the end"; ok=0
            fi
        else
            echo "   FAILED ($MODE): $(grep -m1 'CHECK' "$W/replay-$MODE.out" || tail -3 "$W/replay-$MODE.out") ($(wc -l < "$COUNTS") points passed before it)"; ok=0
        fi
    done
    if [ $ok = 1 ]; then
        points=$(cat "$W/counts-$PA-flush" "$W/counts-$PA-fua" | wc -l)
        states=$(sort -un "$W/counts-$PA-flush" "$W/counts-$PA-fua" | wc -l)
        echo "   OK: $points crash points (flush + FUA), $states of $((acked + 1)) states seen, the count never went back, all $acked acked records at the end ($(( $(date +%s) - t0 ))s)"
        [ "$states" = "$((acked + 1))" ] || { echo "   ⚠ not every state was a crash point"; verdict=1; }
    else
        verdict=1
    fi
    for l in "${LOOPS[@]}"; do losetup -d "$l"; done
    LOOPS=()
done
exit $verdict
