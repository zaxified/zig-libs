#!/usr/bin/env bash
# Coverage-guided fuzz sweep over zig-libs.
#
# ⭐ THE BUDGET IS ITERATIONS PER HARNESS, NOT SECONDS PER MODULE. The first
# argument used to be a per-module wall-clock window; it is now a per-fuzz-test
# iteration count handed to `zig build --fuzz=<N>`. Read the two blocks marked
# WHY ITERATIONS below before changing it back — the old shape had three
# defects that this one does not, and all three were measured, not theorised.
#
#   ./scripts/fuzz-sweep.sh http dns        # only these
#   ./scripts/fuzz-sweep.sh 50000 http dns  # ... with an explicit budget
#   ./scripts/fuzz-sweep.sh all             # every module with a harness
#   ./scripts/fuzz-sweep.sh 200000 all      # ... with a bigger per-harness budget
#
# ⭐ THE TARGET IS MANDATORY. A bare `./scripts/fuzz-sweep.sh` used to start a
# sweep of the WHOLE REPO — hours of ReleaseSafe fuzzing — which is not a thing
# anyone types on purpose, and it was triggered by accident on 2026-08-07 while
# someone was listing harnesses. Whole-repo now costs the word `all`. The first
# argument is the budget only when it is all digits, so a bare module name works
# too (`fuzz-sweep.sh cbor` used to be read as `--fuzz=cbor`).
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
#   TOO-SLOW       the module's measured rate is so low that not even MIN_ITERS
#                  iterations per harness fit in MODULE_WALL. Named rather than
#                  swept badly — see THE SLOW LANE.
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

CAL_ITERS="${CAL_ITERS:-1000}"   # calibration budget, per harness (starting point)
CAL_WALL="${CAL_WALL:-300}"      # hard ceiling on ONE calibration attempt, seconds
HANG_FACTOR="${HANG_FACTOR:-6}"  # main run may take this x its calibrated rate
MODULE_WALL="${MODULE_WALL:-600}" # target wall-clock for one module's main run
MIN_ITERS="${MIN_ITERS:-200}"    # below this a reduced budget is not worth calling clean

usage() {
    cat >&2 <<'EOF'
usage: fuzz-sweep.sh [ITERS] <module>...
       fuzz-sweep.sh [ITERS] all

  ITERS      per-harness iteration budget handed to `zig build --fuzz=N`
             (default 50000). Recognised only if it is all digits.
  <module>   one or more module names, e.g. `cbor http dns`
  all        every module in the repo that has a `testing.fuzz(` harness.
             Required spelling: a whole-repo sweep is hours of work and is
             never what a bare invocation meant to ask for.
EOF
    exit 2
}

ITERS=50000
if [[ ${1:-} =~ ^[0-9]+$ ]]; then
    ITERS="$1"
    shift
fi
(( $# )) || usage
(( ITERS > 0 )) || usage
for a in "$@"; do
    [[ "$a" == "all" && $# -ne 1 ]] && { echo "'all' must be the only target" >&2; usage; }
    [[ "$a" == -* ]] && { echo "unknown option: $a" >&2; usage; }
done


# Modules that actually have a fuzz harness. Derived, never hardcoded, so
# the sweep cannot silently stop covering a module that grows one.
#
# ⚠ Derivation only answers "which modules HAVE a harness". It cannot answer
# "which modules SHOULD" — a module with no harness is simply absent here and
# looks covered from outside. That is what `zig build check-fuzz` is for; it is
# a separate gate precisely because this script cannot be one.
mapfile -t ALL_MODS < <(grep -rl 'testing\.fuzz(' modules/*/src/*.zig 2>/dev/null |
    sed 's|modules/||; s|/src/.*||' | sort -u)
if [[ "$1" == "all" ]]; then
    MODS=("${ALL_MODS[@]}")
    # Same guard the named branch has: a discovery that finds no fuzz harness
    # must FAIL, not sweep zero modules and print "SWEEP DONE" over nothing.
    # (ctgrind.sh and dark-tests.sh both guard their all-branch; this one did
    # not.) It is dormant today — many call sites exist — but a refactor that
    # renamed `testing.fuzz(` would silently empty the sweep.
    (( ${#MODS[@]} )) || { echo "no module has a testing.fuzz( harness — nothing to sweep"; exit 2; }
else
    MODS=()
    for want in "$@"; do
        found=0
        for have in "${ALL_MODS[@]}"; do
            [[ "$have" == "$want" ]] && { MODS+=("$want"); found=1; break; }
        done
        (( found )) || echo "  skipping '$want': no testing.fuzz( harness in modules/$want/src/"
    done
    (( ${#MODS[@]} )) || { echo "no named module has a fuzz harness"; exit 2; }
fi
total=${#MODS[@]}

# ⭐ ONE RUN MUST NOT ERASE ANOTHER'S EVIDENCE. Every sweep used to write
# summary.tsv and findings.txt into one shared directory AND TRUNCATE BOTH ON
# START, so the second of two sequential sweeps destroyed the first's verdicts —
# with two agents working the same tree that is the permanent condition, and it
# already cost this campaign a verdict that had to be re-run. Each run now owns
# a directory keyed by start time and pid; nothing is ever truncated except this
# run's own files, which are new. $BASE/latest is a convenience pointer for the
# common case ("where did my sweep go"), and $BASE/runs.tsv is an append-only
# index so a run whose pointer was overtaken is still findable.
# Default OFF tmpfs: fuzz corpora and instrumented builds are big, and /tmp is
# RAM here (a 4.5 GB cache parked there OOM-killed the editor once). `.zig-cache`
# is the repo's own scratch. `FUZZ_OUT` still overrides for a deliberate choice.
BASE="${FUZZ_OUT:-.zig-cache/zig-libs-fuzz}"
RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
OUT="$BASE/run-$RUN_ID"
mkdir -p "$OUT"
: > "$OUT/summary.tsv"
: > "$OUT/findings.txt"
ln -sfn "$OUT" "$BASE/latest"
printf '%s\t%s\t%s\t%s\n' "$RUN_ID" "started" "iters=$ITERS" "targets=$*" >> "$BASE/runs.tsv"
echo "run $RUN_ID -> $OUT   (also reachable as $BASE/latest)"

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
#
# ⭐ A `testing.fuzz(` INSIDE A COMMENT IS NOT A HARNESS. This file was matching
# the literal text anywhere on a line, and this repo writes long provenance
# comments that quote it — `brotli/src/root.zig:298` and
# `lninvoice/src/bolt12.zig:1606` both say the words `testing.fuzz(` in prose
# about the sweep itself. The count feeds the BUDGET FLOOR below, so brotli came
# back as 3 harnesses when it has 1, its floor was set three times too high, and
# the module was filed INCOMPLETE twice in a row on a run that had in fact done
# its full budget. lninvoice the same, 4 counted against 3 real. Strip anything
# from `//` onwards before matching, on the test header too, so a commented-out
# test cannot supply a name either.
#
# The module-level `grep -rl` above has the same shape and is left alone: it
# only answers yes/no per module, and it was checked to select the same 132
# modules with and without comment stripping.
harnessesOf() { # $1 = module
    awk '
        FNR == 1 { name = "" }
        { code = $0; sub(/\/\/.*/, "", code) }
        code ~ /^[[:space:]]*test "/ {
            line = code
            sub(/^[^"]*"/, "", line)
            sub(/".*$/, "", line)
            name = line
        }
        code ~ /testing\.fuzz\(/ && name != "" { print FILENAME "\t" name }
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
    # hang ceiling below is derived from the target rather than guessed.
    #
    # ⭐⭐ A FIXED CALIBRATION BUDGET CALLS A SLOW MODULE A HANG. The budget used
    # to be exactly CAL_ITERS and the ceiling exactly CAL_WALL, so a module whose
    # harnesses are individually expensive could not calibrate at all and was
    # filed `HANG (calibration)` — a verdict about the instrument, not the code.
    # `iec62351` is the case that found this: its `tlsprofile` harness builds a
    # fresh RSA-2048 certificate per iteration, measured at 0.33 s/run, so 1000
    # iterations of that ONE harness need ~330 s and the module could never
    # finish 1000 x 8 inside 300 s. Twice reproduced on an idle machine.
    #
    # Raising the constant is not a fix — it just moves the cliff, and there is
    # always a module past it. The rule instead:
    #
    #   BACK THE CALIBRATION BUDGET OFF UNTIL IT COMPLETES, and only call it a
    #   hang when even `--fuzz=1` cannot finish inside CAL_WALL.
    #
    # That threshold is meaningful rather than arbitrary: at `--fuzz=1` the work
    # left is one iteration per harness plus a replay of the persisted corpus,
    # i.e. a FIXED amount of work. A target that does not get through a fixed
    # amount of work in five minutes is not slow, it is not terminating — which
    # is exactly what HANG is supposed to mean. Everything above that threshold
    # gets a measured rate, and a measured rate is all the ceiling below needs.
    #
    # Note the backoff costs nothing for a module that calibrates today: the
    # first attempt is still CAL_ITERS and still the only one.
    cal_budget=$CAL_ITERS
    cal_crashed=0
    cal_timedout=0
    while :; do
        cal_start=$(date +%s)
        stamp_before=$(crashStamp)
        timeout "$CAL_WALL" ./scripts/capped zig build "test-$m" --release=safe \
            --fuzz="$cal_budget" > "$log.cal" 2>&1
        cal_rc=$?
        cal_dur=$(( $(date +%s) - cal_start ))
        cal_delta=$(runsDelta "$log.cal")

        # ⭐ THE CALIBRATION RUN IS A FUZZ RUN AND CAN CRASH TOO. It was
        # previously judged by `cal_rc` alone, which under `--fuzz` is 0 whatever
        # happens, so a module that crashed in the first iterations went on to a
        # main run timed by a truncated `cal_dur` and could come back `clean`.
        # Remember it; the verdict below refuses `clean` for a module that
        # crashed here even if the main run happened not to reach the same input
        # again. A crash also ends the backoff — the answer is already known.
        if crashSeen "$log.cal" || [[ "$(crashStamp)" != "$stamp_before" ]]; then
            cal_crashed=1
            break
        fi
        [[ $cal_rc -ne 124 ]] && break
        reapOrphans "$m"
        if (( cal_budget <= 1 )); then cal_timedout=1; break; fi
        cal_budget=$(( cal_budget / 10 ))
        (( cal_budget < 1 )) && cal_budget=1
        cp "$log.cal" "$log.cal.timedout-above-$cal_budget"
        echo "  $m: calibration did not finish in ${CAL_WALL}s — retrying at ${cal_budget} iters/harness"
    done

    if (( cal_timedout )); then
        printf '%s\t%s\t%s\t%s\t%s\n' "$m" 124 "$cal_dur" "HANG" \
            "did not finish 1 iter/harness + corpus replay in ${CAL_WALL}s (calibration floor)" >> "$OUT/summary.tsv"
        { echo "=== $m (HANG at calibration floor, ${cal_dur}s) ==="; tail -40 "$log.cal"; echo; } >> "$OUT/findings.txt"
        echo "[$i/$total] $m -> HANG (calibration floor, ${cal_dur}s)"
        continue
    fi

    # ⭐ THE SLOW LANE. The budget is per harness and in iterations, so a module
    # whose iterations cost 1000x the median asks for 1000x the wall clock. With
    # the calibration fixed, `iec62351` at the default 50000/harness projects to
    # ~6 hours — technically a verdict, practically a sweep nobody runs, which is
    # the same blindness as the false HANG it replaced.
    #
    # So the ITERATION budget is the request and MODULE_WALL is the allowance: a
    # module too slow for the request is run at the largest budget that fits its
    # own measured rate, and the reduction is REPORTED next to the verdict. This
    # keeps `clean` meaning exactly what it meant — "every harness completed the
    # budget it was given" — while making the budget it was given visible, so a
    # thin clean can never be mistaken for a full one.
    #
    # Below MIN_ITERS there is no honest verdict left to give, and the module is
    # named TOO-SLOW rather than swept badly. That is a finding about the module
    # (a harness doing keygen per iteration is a harness design problem), not a
    # verdict about its code.
    budget=$ITERS
    reduced=""
    if (( cal_dur > 0 && cal_budget > 0 )); then
        proj=$(( cal_dur * ITERS / cal_budget ))
        if (( proj > MODULE_WALL )); then
            budget=$(( MODULE_WALL * cal_budget / cal_dur ))
            (( budget > ITERS )) && budget=$ITERS
            if (( budget < MIN_ITERS )); then
                printf '%s\t%s\t%s\t%s\t%s\n' "$m" 0 "$cal_dur" "TOO-SLOW" \
                    "measured ${cal_delta} runs in ${cal_dur}s at ${cal_budget}/harness; ${ITERS}/harness projects to ${proj}s and even ${MIN_ITERS}/harness does not fit MODULE_WALL=${MODULE_WALL}s" >> "$OUT/summary.tsv"
                { echo "=== $m (TOO-SLOW: ${cal_delta} runs in ${cal_dur}s) ==="
                  echo "A harness in this module is too expensive per iteration to fuzz at any"
                  echo "budget worth calling clean. Fix the harness (per-iteration keygen or"
                  echo "signature work belongs outside the loop), or raise MODULE_WALL knowingly."
                  echo; } >> "$OUT/findings.txt"
                echo "[$i/$total] $m -> TOO-SLOW (${cal_delta} runs in ${cal_dur}s)"
                continue
            fi
            reduced=" REDUCED-BUDGET from ${ITERS} (full budget projects to ${proj}s > MODULE_WALL=${MODULE_WALL}s)"
            echo "  $m: slow lane — budget reduced ${ITERS} -> ${budget} iters/harness"
        fi
    fi

    # Scale the calibrated time to the real budget, then allow HANG_FACTOR x
    # that. A slow-but-terminating target stays clean; one that stops making
    # progress blows through its own measured rate and is named.
    wall=$(( (cal_dur * budget / cal_budget + 15) * HANG_FACTOR ))
    (( wall < 60 )) && wall=60

    start=$(date +%s)
    stamp_before=$(crashStamp)
    timeout "$wall" ./scripts/capped zig build "test-$m" --release=safe \
        --fuzz="$budget" > "$log" 2>&1
    rc=$?
    dur=$(( $(date +%s) - start ))
    [[ $rc -eq 124 ]] && reapOrphans "$m"
    delta=$(runsDelta "$log")
    new_crash_artifact=0
    [[ "$(crashStamp)" != "$stamp_before" ]] && new_crash_artifact=1

    # ⭐ BUDGET FLOOR — the observation that does not read a single word of the
    # log. A run that ran to completion performs at least `budget` iterations per
    # fuzz test, so `delta` has a floor, and a run that stopped early falls
    # under it no matter WHY it stopped or how the reason was spelled.
    #
    # Two independent estimators of that floor, because each can be wrong on its
    # own and they are wrong in opposite directions:
    #
    #   nh * budget         — exact when `harnessesOf` counted right, but it
    #                         counts `testing.fuzz(` call sites, so two calls in
    #                         one test (or one in a helper) OVER-counts.
    #   cal_delta * budget/cal_budget
    #                       — measured from this module's own completed
    #                         calibration, immune to miscounting, but noisy:
    #                         the fuzzer overshoots its limit in batches, and at
    #                         cal_budget the relative overshoot is largest, so it
    #                         OVER-estimates.
    #
    # Take the smaller, then keep 10% back for the batching overshoot. Measured
    # at fd39a3e, --fuzz=3000: netaddr 3 harnesses -> 9080 (floor 9000),
    # json5 2 -> 6722 (6000), cbor 1 -> 3149 (3000). Never once undershot.
    # bacnet's misreported crash: floor 14x20000 = 280000, delta 80712 = 29%.
    floor=$(( nh * budget ))
    if (( cal_crashed == 0 && cal_delta > 0 )); then
        cal_floor=$(( cal_delta * budget / cal_budget ))
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
        echo "  HANG: killed after ${dur}s, having asked for ${budget} iterations per harness and been" >> "$log"
        echo "  given ${wall}s = ${HANG_FACTOR}x its own calibrated rate. A bounded fuzz run that does" >> "$log"
        echo "  not terminate means some input reached a path that does not." >> "$log"
    fi
    if [[ "$verdict" == "INCOMPLETE" ]]; then
        echo "  INCOMPLETE: performed $delta runs where a completed run of ${nh} harness(es) at" >> "$log"
        echo "  ${budget} iterations each has a floor of ${floor}. Something stopped this run early and" >> "$log"
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
        "harnesses=$nh runs=$delta budget=${budget}/harness wall=${wall}s${reduced}" >> "$OUT/summary.tsv"
    if [[ "$verdict" != "clean" ]]; then
        { echo "=== $m (exit $rc, ${dur}s, $verdict) ==="; tail -40 "$log"; echo; } >> "$OUT/findings.txt"
    fi
    echo "[$i/$total] $m -> $verdict (${dur}s, $nh harness(es), $delta runs, ${budget}/harness)"

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
                -Dtest-filter="$hname" --fuzz="$budget" > "$hlog" 2>&1
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
            elif (( hdelta * 100 < budget * 90 )); then hv="INCOMPLETE"
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

# A `clean` won at a reduced budget is not the same evidence as a `clean` at the
# budget that was asked for. Say so at the end, where the counts are read.
if grep -q 'REDUCED-BUDGET' "$OUT/summary.tsv"; then
    echo
    echo "SLOW LANE — these ran at less than the ${ITERS}/harness you asked for:"
    awk -F'\t' '/REDUCED-BUDGET/ { print "  " $1 "\t" $4 "\t" $5 }' "$OUT/summary.tsv"
fi
echo
echo "evidence: $OUT   (latest -> $BASE/latest, index: $BASE/runs.tsv)"
printf '%s\t%s\t%s\t%s\n' "$RUN_ID" "finished" \
    "$(awk -F'\t' '{c[$4]++} END {for (v in c) printf "%s=%d ", v, c[v]}' "$OUT/summary.tsv")" \
    "$OUT" >> "$BASE/runs.tsv"
echo
echo "Modules that SHOULD have a harness and do not are invisible here by"
echo "construction — run \`zig build check-fuzz\` for that half of the picture."
