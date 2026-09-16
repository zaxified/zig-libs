#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Mutation runner for `netsim`: weaken one guard at a time in a FRESH copy of
# ../src, verify the edit actually landed, and run the module's own suite over
# the copy.
#
#   RED   = the suite caught it — the guard is covered
#   GREEN = the suite still passes with the guard gone — a coverage gap
#
# WHY THIS EXISTS. netsim is a fault injector: its whole job is to drop, delay,
# duplicate and partition. A bug that makes a fault silently NOT happen produces
# a green suite and a simulation that tests nothing — the worst failure this
# module can have, and the one its own tests are least able to see. So most of
# the mutations below disarm a fault rather than break one, and the interesting
# verdict is GREEN.
#
# ⚠ TWO ANCHORS ARE STALE against the current sources and report SKIPPED:
# "severed ignores partitions" and "max_events_cap backstop removed" (both
# sim.zig). SKIPPED is deliberate — a mutation that did not apply is a MISSING
# ROW, never a result. Fixing them means re-reading those functions and
# re-deriving the edit, not loosening the match.
#
# ⚠ IT COPIES FROM ../src AT RUN TIME. The audit kept a `base/` snapshot; by
# 2026-09-16 that snapshot was 748 lines away from sim.zig and 285 from
# root.zig, so it mutated code that no longer existed. The tracked tree is never
# touched: everything happens under .zig-cache/, which is droppable by contract.
#
# WHAT IT NEEDS. A `zig` on PATH; `scripts/capped` bounds each build's memory.
#
#     ./mutate.sh
#
# WHAT IT PRODUCES. A verdict line per mutation, flagged when it differs from
# the expectation recorded beside it, and a non-zero exit if a POSITIVE CONTROL
# did not go RED — in which case the runner is broken and no other row means
# anything.
set -u

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../.." && pwd)"
SRC="$HERE/../src"
MUT="$REPO/.zig-cache/netsim-mutate"
CAPPED="$REPO/scripts/capped"

mkdir -p "$MUT"
control_failures=0

apply() { # $1 file  $2 old  $3 new
  python3 - "$MUT/$1" "$2" "$3" <<'PY'
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
n = s.count(old)
if n != 1:
    print(f"MUTATION-NOT-APPLIED: pattern occurs {n} times in {p}", file=sys.stderr)
    sys.exit(3)
open(p, 'w').write(s.replace(old, new))
PY
}

run_one() { # $1 label  $2 expect(RED|GREEN)  $3 file  $4 old  $5 new
  local label="$1" expect="$2" file="$3" old="$4" new="$5"
  rm -f "$MUT"/*.zig
  cp "$SRC"/*.zig "$MUT"/
  if ! apply "$file" "$old" "$new"; then
    printf '  %-58s %s\n' "$label" "SKIPPED (pattern did not match — NOT a result)"
    # A CONTROL that cannot even be applied is a broken runner, not a skip: the
    # run has lost the one row that says whether any other row is evidence.
    [ "$IN_CONTROLS" = 1 ] && control_failures=$((control_failures + 1))
    return
  fi
  # diff-verify: the copy must now differ from the source in exactly this file
  local changed
  changed=$(diff -q "$SRC/$file" "$MUT/$file" >/dev/null 2>&1 && echo no || echo yes)
  if [ "$changed" != yes ]; then
    printf '  %-58s %s\n' "$label" "SKIPPED (diff shows no change — NOT a result)"
    return
  fi
  local out rc
  out=$("$CAPPED" zig test "$MUT/root.zig" 2>&1)
  rc=$?
  local verdict
  if [ $rc -eq 0 ]; then verdict=GREEN; else verdict=RED; fi
  local flag=""
  [ "$verdict" != "$expect" ] && flag="   <== differs from expectation ($expect)"
  local detail=""
  [ "$verdict" = RED ] && detail=" [$(echo "$out" | grep -oE '[0-9]+ passed|[0-9]+ failed' | tr '\n' ' ')]"
  printf '  %-58s %-5s%s%s\n' "$label" "$verdict" "$detail" "$flag"
  if [ "$IN_CONTROLS" = 1 ] && [ "$verdict" != RED ]; then
    control_failures=$((control_failures + 1))
  fi
}

echo "baseline (unmutated copy of ../src):"
rm -f "$MUT"/*.zig; cp "$SRC"/*.zig "$MUT"/
"$CAPPED" zig test "$MUT/root.zig" 2>&1 | tail -1

IN_CONTROLS=1
echo
echo "POSITIVE CONTROLS (a suite with teeth must go RED here):"
run_one "checkInvariant neutered (never reports a violation)" RED sim.zig \
  '        const f = self.protocol.checkFn orelse return;' \
  '        if (true) return;
        const f = self.protocol.checkFn orelse return;'
run_one "Prng.below always returns 0" RED prng.zig \
  '        if (n == 0) return 0;
        return @intCast(p.next() % @as(u64, n));' \
  '        if (n == 0) return 0;
        _ = p.next();
        return 0;'
run_one "neighbors truncates instead of failing closed" RED sim.zig \
  '        if (adj.len > out.len) return error.TooManyNeighbors;' \
  '        if (adj.len > out.len) { for (adj[0..out.len], 0..) |idx, n| out[n] = self.links.items[idx].b; return out.len; }'
run_one "severed ignores partitions" RED sim.zig \
  '        for (self.partitions.items) |p| {
            const in_a = std.mem.indexOfScalar(NodeId, p.cut, a) != null;
            const in_b = std.mem.indexOfScalar(NodeId, p.cut, b) != null;
            if (in_a != in_b) return true;
        }' \
  '        for (self.partitions.items) |p| { _ = p; }'
run_one "ddmin returns the input unshrunk" RED shrink.zig \
  '    var granularity: usize = 2;' \
  '    if (true) return current;
    var granularity: usize = 2;'
IN_CONTROLS=0

echo
echo "GUARDS THE SUITE MIGHT NOT COVER:"
run_one "drop_once never arms (the fault does nothing)" RED sim.zig \
  '                if (self.findLink(l.a, l.b)) |link| link.drop_pending += 1;' \
  '                if (self.findLink(l.a, l.b)) |link| { _ = link; }'
run_one "dup_once never arms" RED sim.zig \
  '                if (self.findLink(l.a, l.b)) |link| link.dup_pending += 1;' \
  '                if (self.findLink(l.a, l.b)) |link| { _ = link; }'
run_one "delay_once never arms" RED sim.zig \
  '                if (self.findLink(d.a, d.b)) |link| link.delay_pending += d.extra;' \
  '                if (self.findLink(d.a, d.b)) |link| { _ = link; }'
run_one "link_down never severs" RED sim.zig \
  '                if (self.findLink(l.a, l.b)) |link| link.up = false;' \
  '                if (self.findLink(l.a, l.b)) |link| { _ = link; }'
run_one "crash_node never crashes" RED sim.zig \
  '                self.nodes.items[c.node].crashed = true;' \
  '                self.nodes.items[c.node].crashed = false;'
run_one "clock_jump never shifts a clock" RED sim.zig \
  '                self.nodes.items[j.node].clock_offset += j.delta;' \
  '                self.nodes.items[j.node].clock_offset += 0;'
run_one "restart_node never revives" RED sim.zig \
  '                self.nodes.items[r.node].crashed = false;
                self.append(.{ .tag = .restart, .a = r.node });' \
  '                self.append(.{ .tag = .restart, .a = r.node });'
run_one "per-link loss_permille ignored (never lose a message)" RED sim.zig \
  '        if (self.prng.permille(link.cfg.loss_permille)) {' \
  '        if (self.prng.permille(link.cfg.loss_permille) and false) {'
run_one "per-link dup_permille ignored" RED sim.zig \
  '        const dup_cfg = self.prng.permille(link.cfg.dup_permille);' \
  '        const dup_cfg = self.prng.permille(link.cfg.dup_permille) and false;'
run_one "jitter ignored (latency becomes exact)" RED sim.zig \
  '        if (link.cfg.jitter > 0) delay += self.prng.belowWide(link.cfg.jitter + 1);' \
  '        if (link.cfg.jitter > 0) { _ = self.prng.belowWide(link.cfg.jitter + 1); }'
run_one "reorder_extra ignored" RED sim.zig \
  '        if (link.cfg.reorder_extra > 0 and self.prng.permille(link.cfg.reorder_permille))
            delay += self.prng.belowWide(link.cfg.reorder_extra + 1);' \
  '        if (link.cfg.reorder_extra > 0 and self.prng.permille(link.cfg.reorder_permille)) {
            _ = self.prng.belowWide(link.cfg.reorder_extra + 1);
        }'
run_one "bandwidth serialization delay ignored" RED sim.zig \
  '            if (bw > 0) delay += payload.len / bw;' \
  '            if (bw > 0) delay += 0;'
run_one "max_events_cap backstop removed" RED sim.zig \
  '            if (self.events_processed >= self.max_events_cap) break;' \
  ''
run_one "until-bound removed (run to queue exhaustion)" RED sim.zig \
  '            if (t > self.until) break;' \
  '            if (t > self.until * 1000) break;'
run_one "event heap loses its (time,seq) FIFO tie-break" RED sim.zig \
  '    if (x.time != y.time) return x.time < y.time;
    return x.seq < y.seq;' \
  '    if (x.time != y.time) return x.time < y.time;
    return x.seq > y.seq;'
run_one "send does not copy the payload (aliases caller memory)" RED sim.zig \
  '        const buf = try self.arena.allocator().dupe(u8, payload);' \
  '        const buf = payload;'
run_one "fault schedule: repair half never emitted" RED fault.zig \
  '    /// Probability (in 1000ths) a repairable disruption also gets a later repair.
    repair_permille: u16 = 750,' \
  '    /// Probability (in 1000ths) a repairable disruption also gets a later repair.
    repair_permille: u16 = 0,'
run_one "fault schedule: max_events default drops to 1" RED fault.zig \
  '    max_events: usize = 20,' \
  '    max_events: usize = 1,'

echo
if [ "$control_failures" -gt 0 ]; then
  echo "⛔ $control_failures positive control(s) did not go RED — the runner is broken"
  echo "   and every row above is meaningless."
  exit 1
fi
exit 0
