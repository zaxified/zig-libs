#!/usr/bin/env bash
# Coverage-guided fuzz sweep over zig-libs.
#
# ⭐ THE BUDGET IS ITERATIONS PER HARNESS, NOT SECONDS PER MODULE. The first
# argument used to be a per-module wall-clock window; it is now a per-fuzz-test
# iteration count handed to `zig build --fuzz=<N>`. Read the two blocks marked
# WHY ITERATIONS below before changing it back — the old shape had three
# defects that this one does not, and all three were measured, not theorised.
#
#   ./scripts/fuzz-sweep.sh                 # every module with a harness
#   ./scripts/fuzz-sweep.sh 200000          # a bigger per-harness budget
#   ./scripts/fuzz-sweep.sh 50000 http dns  # only these
#
# Verdicts written to $OUT/summary.tsv:
#
#   clean          every harness completed its full iteration budget, no crash
#   FINDING        a crash; the log and the crashing input are kept, and the
#                  module is then re-run ONE HARNESS AT A TIME (see RE-RUN)
#   HANG           the bounded run did not finish within 6x its own measured
#                  rate — the thing that used to be indistinguishable from clean
#   NEVER-FUZZED   the process exited without the fuzzer performing a single run
#   OOM-KILLED     the cgroup killed it: an allocation sized from unbounded input
#   INCOMPLETE     no crash was recognised, but the run performed far fewer
#                  iterations than the budget it asked for, so it stopped early
#                  for a reason this script could not name. NOT clean — see
#                  WHY THE EXIT CODE CANNOT BE TRUSTED.
#
# ⭐⭐ WHY THE EXIT CODE CANNOT BE TRUSTED UNDER `--fuzz`. `zig build --fuzz=N`
# EXITS 0 EVEN WHEN A FUZZ TEST CRASHES. This is not a guess; it is visible in
# the 0.16.0 build runner. `compiler/build_runner.zig` totals `failure_count`
# from the step states in a loop that runs BEFORE `if (fuzz) |mode|` starts the
# fuzzer, and the process exit code is computed from that already-frozen total:
#
#     for (step_stack.keys()) |s| { ... .failure => failure_count += 1 ... }
#     if (fuzz) |mode| { ... f.start(); try f.waitAndPrintReport(); }
#     const code: u8 = code: { if (failure_count == 0) break :code 0; ... };
#
# A crash found by the fuzzer marks its step `.failure` only afterwards, and
# `std/Build/Fuzz.zig:fuzzWorkerRun` swallows the `error.MakeFailed` it gets
# back — it prints the message and `return`s. So the failure is REPORTED and
# never COUNTED. Reproduced at fd39a3e:
#
#     zig build test-bacnet --release=safe \
#         -Dtest-filter="every canonically decoded header re-encodes" --fuzz=20000
#     -> "error: test '...' exited with code 1; input saved to '.zig-cache/f/crash'"
#     -> $? == 0
#
# The consequence for this script is that `rc` says nothing about crashes, and
# the old log grep only matched the SIGNAL/panic spellings — so a harness that
# fails by RETURNING AN ERROR (the ordinary shape of a round-trip oracle:
# `try expectEqualSlices` -> `error.TestExpectedEqual`) printed `exited with
# code 1` and was filed as `clean`, with an empty findings.txt. That happened to
# `bacnet` on 2026-08-06. Under-reporting is worse than no gate at all, so the
# verdict now rests on THREE independent observations, any one of which is
# enough to deny `clean`:
#
#   1. the log (see CRASH_RE) — the authoritative line is Run.zig's
#      `error: test '<name>' <term>; input saved to '<path>'`, which is emitted
#      for every terminating shape: exit code, signal, stop;
#   2. the `.zig-cache/f/crash` artifact — stamped before and after each run, so
#      a crash the text patterns miss still shows up as a new artifact;
#   3. the iteration budget — a completed run performs at least one full
#      budget per harness (see BUDGET FLOOR); a run that stopped early is
#      INCOMPLETE, which is the fail-closed answer to "I cannot tell".
#
# Everything runs through scripts/capped, so a runaway allocation is killed by
# its own cgroup instead of the machine. NEVER run the fuzz command without it:
# outside a scope the kernel's GLOBAL oom-killer picks its victim by size, and
# under an IDE that victim is the editor. That is not hypothetical — it killed
# VS Code on 2026-07-31 during exactly this script's follow-up diagnosis.
set -u
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$(cd "$SCRIPT_DIR/.." && pwd)"

ITERS="${1:-50000}"
CAL_ITERS="${CAL_ITERS:-1000}"   # calibration budget, per harness
CAL_WALL="${CAL_WALL:-300}"      # hard ceiling on the calibration run, seconds
HANG_FACTOR="${HANG_FACTOR:-6}"  # main run may take this x its calibrated rate
OUT="${FUZZ_OUT:-${TMPDIR:-/tmp}/zig-libs-fuzz}"
mkdir -p "$OUT"
: > "$OUT/summary.tsv"
: > "$OUT/findings.txt"

# Modules that actually have a fuzz harness. Derived, never hardcoded, so
# the sweep cannot silently stop covering a module that grows one.
#
# ⚠ Derivation only answers "which modules HAVE a harness". It cannot answer
# "which modules SHOULD" — a module with no harness is simply absent here and
# looks covered from outside. That is what `zig build check-fuzz` is for; it is
# a separate gate precisely because this script cannot be one.
mapfile -t ALL_MODS < <(grep -rl 'testing\.fuzz(' modules/*/src/*.zig 2>/dev/null |
    sed 's|modules/||; s|/src/.*||' | sort -u)
shift || true
if [[ $# -gt 0 ]]; then
    MODS=()
    for want in "$@"; do
        found=0
        for have in "${ALL_MODS[@]}"; do
            [[ "$have" == "$want" ]] && { MODS+=("$want"); found=1; break; }
        done
        (( found )) || echo "  skipping '$want': no testing.fuzz( harness in modules/$want/src/"
    done
    (( ${#MODS[@]} )) || { echo "no named module has a fuzz harness"; exit 2; }
else
    MODS=("${ALL_MODS[@]}")
fi
total=${#MODS[@]}

# ⭐ A CGROUP OOM-KILL REPORTS 15, NOT 137. `scripts/capped` runs the command
# under `systemd-run --user --scope`, and when the scope hits MemoryMax systemd
# terminates it and reports SIGTERM's 15 — so the obvious `137) OOM-KILLED`
# branch could never fire, and every runaway was filed as a generic EXIT-15.
# `dataset` sat in the results as an unexplained EXIT-15 until the kernel log
# was read; the script never said "out of memory" at all.
#
# 15 alone is not proof (a plain SIGTERM is also 15), so ask the kernel rather
# than infer: an OOM inside a scope logs `oom-kill:` with
# `constraint=CONSTRAINT_MEMCG` and a `run-p<pid>` memcg. When journalctl is
# unavailable the answer is "unknown", never a false "clean".
oomKilled() { # $1 = epoch seconds the run started
    journalctl --since "@$1" --no-pager -k 2>/dev/null |
        grep -qE 'oom-kill:.*CONSTRAINT_MEMCG.*run-p[0-9]+'
}

# ⭐ A TIMED-OUT FUZZ RUN LEAVES AN ORPHAN THAT WEDGES THE NEXT ONE. `timeout`
# signals the `zig` it spawned, but the build RUNNER it forked lives on inside
# the systemd scope `scripts/capped` created — still spinning on the input that
# caused the timeout, still holding `.zig-cache/f/`. The next invocation for
# that module then blocks forever with no output. Cost me three dead sweeps
# while testing the HANG branch: the sweep printed "warming ..." and never
# returned, and the culprit was a build runner from two attempts earlier.
#
# So reap after any timeout, matched narrowly on this module's own command line.
reapOrphans() { # $1 = module
    pkill -9 -f "test-$1 --release=safe" 2>/dev/null
    sleep 1
    return 0
}

# The fuzzer's own end-of-run report carries `Runs: <before> -> <after>`, where
# both numbers are cumulative across runs that share the cache. The DELTA is the
# only trustworthy answer to "did this actually fuzz?" — far better than the old
# `grep -q 'Build Summary'` heuristic, which could only tell that the build had
# got as far as printing a summary.
runsDelta() { # $1 = log path
    awk -F'[ >-]+' '/^Runs: /{ d += $3 - $2 } END { print d+0 }' "$1"
}

# ⭐ EVERY SPELLING OF "A FUZZ TEST DIED", not just the ones with a signal in
# them. The load-bearing member is `input saved to`/`error: test '`, which is
# `std/Build/Step/Run.zig`'s single `step.fail("test '{s}' {f}; input saved to
# '{f}{s}'")` — one call site, reached for `exited with code N`, `terminated
# with signal N` and `stopped` alike. `run test failure` is the build runner's
# own tree line for the same event and survives if that message is ever
# reworded. The old ` [0-9]+ crash` was aimed at the Build Summary's
# `N crashed`, which under `--fuzz` is BOTH counted before the fuzzer runs and
# suppressed by the default `--summary failures` when failure_count is 0 — it
# could never fire. Kept anyway; it costs nothing and covers non-fuzz callers.
CRASH_RE="error: test '| [0-9]+ crash|terminated with signal|thread [0-9]+ panic|input saved to|run test failure"

crashSeen() { # $1 = log path
    [[ -f "$1" ]] && grep -qE "$CRASH_RE" "$1"
}

# ⭐ THE CRASHING INPUT IS EVIDENCE THAT DOES NOT DEPEND ON WORDING. The fuzzer
# writes `.zig-cache/f/crash` when, and only when, a fuzz test terminated
# abnormally. Stamping it either side of a run detects a crash even if every
# text pattern above misses, and mtime+size beats an `-newermt` window because
# it has no one-second granularity hole.
crashStamp() {
    stat -c '%Y:%s' .zig-cache/f/crash 2>/dev/null || echo none
}

# Every `testing.fuzz(` call site, as `<file>\t<test name>`. The name is the one
# the compiler will match `-Dtest-filter` against, taken from the nearest
# preceding `test "..."` header. Used for the per-harness re-run and to report
# WHICH FILES a module's harnesses actually live in — a module can be listed in
# every sweep on the strength of one file's harness while a second decoder in
# the same module has none (`lninvoice`: bech32_raw + bolt11 fuzzed, bolt12.zig
# not). The sweep cannot refuse to run in that state, but it can stop hiding it.
harnessesOf() { # $1 = module
    awk -v mod="$1" '
        FNR == 1 { name = "" }
        /^[[:space:]]*test "/ {
            line = $0
            sub(/^[^"]*"/, "", line)
            sub(/".*$/, "", line)
            name = line
        }
        /testing\.fuzz\(/ && name != "" { print FILENAME "\t" name }
    ' modules/"$1"/src/*.zig 2>/dev/null
}

# ⭐ WHY ITERATIONS (1/2) — WARMING IS STILL NEEDED, BUT NO LONGER LOAD-BEARING.
# Under the old seconds-per-module budget a cold ReleaseSafe compile ate the
# window and the module reported "clean" for a sweep that barely ran (measured
# on `imap`: a planted 1-byte trigger was NOT found in 45s cold and WAS found
# within 60s warm). A budget counted in ITERATIONS cannot be eaten by a compile
# — the run performs its N iterations per harness whether the build took 1s or
# 90s. Warming now only keeps the calibration timing honest, so a slow compile
# is not mistaken for a slow target.
#
# ⚠ Warm with `--fuzz=1`, not a plain build. `--fuzz` rebuilds the module in
# FUZZ MODE — a different, instrumented binary with its own cache entry — so
# warming without it warms the wrong artifact. Caught here: `linkheader`
# calibrated at 17s instead of ~0s after a "warm" plain build, and its hang
# ceiling came out ten times too generous as a result.
#
# ⚠ The warm run is TIMED OUT like every other fuzz invocation. `--fuzz=1` still
# replays the persisted corpus first, so a module with a nonterminating path
# already reachable from its corpus hangs HERE, before calibration — observed
# while testing the HANG branch, where the warm pass sat forever and the sweep
# never reached the module. An unbounded command in a sweep whose whole point is
# bounding things is a bug.
# ⭐ REFUSE TO START ON TOP OF ANOTHER FUZZ RUN. Two fuzzers sharing a module's
# corpus collide, and the collision surfaces as a Zig panic reading
# `corpus … in use by another fuzzer` — an artifact that has been mistaken for a
# finding. It also just wedges: a leftover build runner (see reapOrphans) holds
# the corpus and the new run blocks in the warm pass with no output at all,
# which is how three sweeps died during this script's own testing. So look
# first, name what is running, and stop rather than produce a bad answer.
mapfile -t RUNNING < <(pgrep -af -- '--fuzz' 2>/dev/null | grep -v fuzz-sweep || true)
if (( ${#RUNNING[@]} )); then
    echo "REFUSING TO START — a fuzz run is already in flight:"
    printf '  %s\n' "${RUNNING[@]}"
    echo "Wait for it, or reap it (a timed-out run leaves the build runner alive)."
    exit 3
fi

echo "warming $total instrumented builds so calibration times the target, not the compiler..."
warm_start=$(date +%s)
for m in "${MODS[@]}"; do
    timeout "$CAL_WALL" ./scripts/capped zig build "test-$m" --release=safe --fuzz=1 > /dev/null 2>&1 || {
        echo "  warm FAILED or timed out: $m (calibration will re-time it and can report HANG)"
        reapOrphans "$m"
    }
done
echo "warmed in $(( $(date +%s) - warm_start ))s"
echo

# ⭐ WHY ITERATIONS (2/2) — A MODULE'S BUDGET USED TO BE SHARED BY EVERY HARNESS
# IN IT, so adding one starved the others and coverage regressed silently while
# the sweep still said `clean`. Measured during the class-B burn-down: with all
# three `webauthn` harnesses live, 120s did NOT reach a live CRIT; with only the
# attestation harness live, 180s did.
#
# `--fuzz=<N>` gives EACH fuzz test its own limit of N (lib/fuzzer.zig keeps a
# per-`Test` `limit` and `select()` returns null only once every test has used
# its own up). Verified here: `btcp2p`, 11 harnesses, `--fuzz=5000` performed
# 55,208 runs = 11 x 5000. So a module that grows a twelfth harness gets a
# twelfth full budget instead of eleven thinner ones.
#
# It also makes the run TERMINATE, which is what lets `clean` and `hang` finally
# be different answers — see the HANG branch.
i=0
for m in "${MODS[@]}"; do
    i=$((i + 1))
    log="$OUT/$m.log"
    mapfile -t HARNESS < <(harnessesOf "$m")
    nh=${#HARNESS[@]}

    # Calibrate on a small budget to learn this module's own throughput, so the
    # hang ceiling below is derived from the target rather than guessed. A
    # target that cannot even finish CAL_ITERS inside CAL_WALL is already the
    # answer.
    cal_start=$(date +%s)
    stamp_before=$(crashStamp)
    timeout "$CAL_WALL" ./scripts/capped zig build "test-$m" --release=safe \
        --fuzz="$CAL_ITERS" > "$log.cal" 2>&1
    cal_rc=$?
    cal_dur=$(( $(date +%s) - cal_start ))
    cal_delta=$(runsDelta "$log.cal")

    # ⭐ THE CALIBRATION RUN IS A FUZZ RUN AND CAN CRASH TOO. It was previously
    # judged by `cal_rc` alone, which under `--fuzz` is 0 whatever happens, so a
    # module that crashed in the first CAL_ITERS iterations went on to a main
    # run timed by a truncated `cal_dur` and could come back `clean`. Remember
    # it; the verdict below refuses `clean` for a module that crashed here even
    # if the main run happened not to reach the same input again.
    cal_crashed=0
    if crashSeen "$log.cal" || [[ "$(crashStamp)" != "$stamp_before" ]]; then
        cal_crashed=1
    fi

    if [[ $cal_rc -eq 124 ]]; then
        reapOrphans "$m"
        printf '%s\t%s\t%s\t%s\t%s\n' "$m" 124 "$cal_dur" "HANG" \
            "did not finish ${CAL_ITERS} iters/harness in ${CAL_WALL}s (calibration)" >> "$OUT/summary.tsv"
        { echo "=== $m (HANG at calibration, ${cal_dur}s) ==="; tail -40 "$log.cal"; echo; } >> "$OUT/findings.txt"
        echo "[$i/$total] $m -> HANG (calibration, ${cal_dur}s)"
        continue
    fi

    # Scale the calibrated time to the real budget, then allow HANG_FACTOR x
    # that. A slow-but-terminating target stays clean; one that stops making
    # progress blows through its own measured rate and is named.
    wall=$(( (cal_dur * ITERS / CAL_ITERS + 15) * HANG_FACTOR ))
    (( wall < 60 )) && wall=60

    start=$(date +%s)
    stamp_before=$(crashStamp)
    timeout "$wall" ./scripts/capped zig build "test-$m" --release=safe \
        --fuzz="$ITERS" > "$log" 2>&1
    rc=$?
    dur=$(( $(date +%s) - start ))
    [[ $rc -eq 124 ]] && reapOrphans "$m"
    delta=$(runsDelta "$log")
    new_crash_artifact=0
    [[ "$(crashStamp)" != "$stamp_before" ]] && new_crash_artifact=1

    # ⭐ BUDGET FLOOR — the observation that does not read a single word of the
    # log. A run that ran to completion performs at least ITERS iterations per
    # fuzz test, so `delta` has a floor, and a run that stopped early falls
    # under it no matter WHY it stopped or how the reason was spelled.
    #
    # Two independent estimators of that floor, because each can be wrong on its
    # own and they are wrong in opposite directions:
    #
    #   nh * ITERS          — exact when `harnessesOf` counted right, but it
    #                         counts `testing.fuzz(` call sites, so two calls in
    #                         one test (or one in a helper) OVER-counts.
    #   cal_delta * ITERS/CAL_ITERS
    #                       — measured from this module's own completed
    #                         calibration, immune to miscounting, but noisy:
    #                         the fuzzer overshoots its limit in batches, and at
    #                         CAL_ITERS the relative overshoot is largest, so it
    #                         OVER-estimates.
    #
    # Take the smaller, then keep 10% back for the batching overshoot. Measured
    # at fd39a3e, --fuzz=3000: netaddr 3 harnesses -> 9080 (floor 9000),
    # json5 2 -> 6722 (6000), cbor 1 -> 3149 (3000). Never once undershot.
    # bacnet's misreported crash: floor 14x20000 = 280000, delta 80712 = 29%.
    floor=$(( nh * ITERS ))
    if (( cal_crashed == 0 && cal_delta > 0 )); then
        cal_floor=$(( cal_delta * ITERS / CAL_ITERS ))
        (( cal_floor < floor )) && floor=$cal_floor
    fi

    # ⭐ THE LADDER IS ORDERED BY WHAT IT CAN PROVE, and `clean` is the only rung
    # that requires proof rather than the absence of evidence. `rc` is checked
    # LAST among the failure shapes for exactly the reason in the header: under
    # `--fuzz` it is 0 even for a crash, so it can only ever add verdicts, never
    # withhold one.
    if crashSeen "$log" || (( new_crash_artifact )) || (( cal_crashed )); then
        verdict="FINDING"
    else
        case $rc in
            124) verdict="HANG" ;;
            137) verdict="OOM-KILLED" ;;
            15)  if oomKilled "$start"; then verdict="OOM-KILLED"; else verdict="EXIT-15-SIGTERM"; fi ;;
            0)   if [[ "$delta" -le 0 ]]; then
                     verdict="NEVER-FUZZED"
                 elif ! grep -q '^Runs: ' "$log"; then
                     # No FUZZING REPORT at all: nothing to measure against, so
                     # say so instead of guessing.
                     verdict="INCOMPLETE"
                 elif (( floor > 0 && delta * 100 < floor * 90 )); then
                     verdict="INCOMPLETE"
                 else
                     verdict="clean"
                 fi ;;
            *)   verdict="EXIT-$rc" ;;
        esac
    fi

    # An OOM is a finding about the module, not a flaw in the run: something
    # sized an allocation from input it had not bounded. Say so where it will
    # be read, next to the trace, instead of leaving a bare exit code.
    if [[ "$verdict" == "OOM-KILLED" ]]; then
        echo "  OOM: killed by its cgroup after ${dur}s — an allocation was sized from unbounded input" >> "$log"
    fi
    if [[ "$verdict" == "HANG" ]]; then
        echo "  HANG: killed after ${dur}s, having asked for ${ITERS} iterations per harness and been" >> "$log"
        echo "  given ${wall}s = ${HANG_FACTOR}x its own calibrated rate. A bounded fuzz run that does" >> "$log"
        echo "  not terminate means some input reached a path that does not." >> "$log"
    fi
    if [[ "$verdict" == "INCOMPLETE" ]]; then
        echo "  INCOMPLETE: performed $delta runs where a completed run of ${nh} harness(es) at" >> "$log"
        echo "  ${ITERS} iterations each has a floor of ${floor}. Something stopped this run early and" >> "$log"
        echo "  none of the crash signals named it. Re-run it alone before believing anything." >> "$log"
    fi

    # ⭐ PRESERVE THE CRASHING INPUT, not just the trace. The Zig fuzzer writes
    # it to .zig-cache/f/crash, and the NEXT module's run overwrites it — so a
    # sweep that kept only the log left a finding that could not be reproduced
    # except by fuzzing until it happened again. Worse, the traces are built in
    # ReleaseSafe and their line attribution is inlined-away: `json5`'s pointed
    # at a guarded expression and at a COMMENT line, so the input is the only
    # reliable evidence of what actually failed.
    if [[ "$verdict" == "FINDING" && -f .zig-cache/f/crash ]]; then
        cp .zig-cache/f/crash "$OUT/$m.crash-input"
        echo "  saved crashing input -> $OUT/$m.crash-input"
    fi

    printf '%s\t%s\t%s\t%s\t%s\n' "$m" "$rc" "$dur" "$verdict" \
        "harnesses=$nh runs=$delta budget=${ITERS}/harness wall=${wall}s" >> "$OUT/summary.tsv"
    if [[ "$verdict" != "clean" ]]; then
        { echo "=== $m (exit $rc, ${dur}s, $verdict) ==="; tail -40 "$log"; echo; } >> "$OUT/findings.txt"
    fi
    echo "[$i/$total] $m -> $verdict (${dur}s, $nh harness(es), $delta runs)"

    # ⭐ RE-RUN: ONE CRASH USED TO SILENCE EVERY LATER HARNESS IN THE MODULE.
    # All of a module's fuzz tests share one process, so the first to crash
    # takes the rest down with it and they were reported as if they had run
    # their budget. There is no way to keep them alive in that process, so give
    # each survivor a process of its own via `-Dtest-filter` and report it
    # separately. This costs one compile per harness, which is why it happens
    # only for a module that actually crashed.
    if [[ "$verdict" == "FINDING" && $nh -gt 1 ]]; then
        echo "  crash in a shared process starved the other $((nh - 1)) harness(es) — re-running each alone"
        for h in "${HARNESS[@]}"; do
            hfile="${h%%$'\t'*}"; hname="${h#*$'\t'}"
            hlog="$OUT/$m.$(echo "$hname" | tr -c 'A-Za-z0-9' '_').log"
            hstart=$(date +%s)
            hstamp=$(crashStamp)
            timeout "$wall" ./scripts/capped zig build "test-$m" --release=safe \
                -Dtest-filter="$hname" --fuzz="$ITERS" > "$hlog" 2>&1
            hrc=$?
            [[ $hrc -eq 124 ]] && reapOrphans "$m"
            hdelta=$(runsDelta "$hlog")
            # Same three signals as the main ladder. This loop exists to say
            # which harnesses are innocent, so it is the LAST place that may
            # answer `clean` from the absence of a message.
            if crashSeen "$hlog" || [[ "$(crashStamp)" != "$hstamp" ]]; then
                hv="FINDING"
            elif [[ $hrc -eq 124 ]]; then hv="HANG"
            elif [[ $hrc -ne 0 ]]; then hv="EXIT-$hrc"
            elif [[ "$hdelta" -le 0 ]]; then hv="NEVER-FUZZED"
            elif (( hdelta * 100 < ITERS * 90 )); then hv="INCOMPLETE"
            else hv="clean"; fi
            # Each isolated re-run overwrites .zig-cache/f/crash in turn, so a
            # second crashing harness used to lose its input to the third one's.
            # Found the moment the verdict fix let the re-run happen at all:
            # bacnet's re-run turned up a SECOND crash (sc.zig option walking,
            # integer overflow) that the mislabelled `clean` had hidden.
            if [[ "$hv" == "FINDING" && -f .zig-cache/f/crash ]]; then
                cp .zig-cache/f/crash "${hlog%.log}.crash-input"
            fi
            printf '%s\t%s\t%s\t%s\t%s\n' "$m/$hname" "$hrc" "$(( $(date +%s) - hstart ))" "$hv" \
                "isolated re-run, $hfile, runs=$hdelta" >> "$OUT/summary.tsv"
            echo "    $hfile :: $hname -> $hv ($hdelta runs)"
        done
    fi
done

echo
echo "=== SWEEP DONE ==="
awk -F'\t' '{c[$4]++} END {for (v in c) printf "%-16s %d\n", v, c[v]}' "$OUT/summary.tsv"
echo
echo "Modules that SHOULD have a harness and do not are invisible here by"
echo "construction — run \`zig build check-fuzz\` for that half of the picture."
