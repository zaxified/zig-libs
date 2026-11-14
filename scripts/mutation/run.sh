#!/usr/bin/env bash
# run.sh -- run a mutant-schemata test binary once per mutant, strict verdicts
# (CONVENTIONS.md §9, "the mutation kit"; recipe in scripts/mutation/README.md).
#
#   run.sh <test-binary> <ENV_NAME> <last-id>        # mutants 0..last-id
#   ONLY="0 5 9" run.sh <test-binary> <ENV_NAME> -   # just these
#
# Environment knobs: MUT_TIMEOUT (s per mutant, default 20), MUT_ULIMIT_KB
# (virtual memory per mutant, default 3000000), MUT_LOGDIR (default: beside the
# binary, out-<id>.log per mutant).
#
# One line per mutant on stdout, TSV:  <id> <verdict> <seconds> <reason>
#   PASS       id 0 only; anything else for 0 stops the run (exit 2)
#   KILLED     rc != 0 with a failing test, a panic or a signal in the log
#   HANG       killed at MUT_TIMEOUT (counts as killed, reported apart)
#   SURVIVED   rc 0
#   UNCLEAR    rc != 0 with none of the above -- e.g. a build/link problem or an
#              allocator ulimit refusal; never counted as a kill (strict verdict)
#
# Why each piece (all met in practice):
#   - ulimit -v BEFORE the loop: a mutant that drops a size bound allocates
#     without limit and the OOM killer took the whole batch (2026-11-05).
#   - setsid -w: without -w setsid forks and returns 0 at once, so every mutant
#     "survived" (2026-09-27); its own session keeps a hung child killable.
#   - M0 first, under the same command: a mutant can only be judged against a
#     baseline that passes exactly this way.
#   - a printed line per mutant: `hw run --quiet` kills a silent job.
set -u
BIN="${1:?usage: run.sh <test-binary> <ENV_NAME> <last-id|->}"
ENV_NAME="${2:?usage: run.sh <test-binary> <ENV_NAME> <last-id|->}"
LAST="${3:?usage: run.sh <test-binary> <ENV_NAME> <last-id|->}"
TIMEOUT="${MUT_TIMEOUT:-20}"
LOGDIR="${MUT_LOGDIR:-$(dirname "$BIN")}"
[[ -x "$BIN" ]] || { echo "run.sh: $BIN is not an executable" >&2; exit 2; }
mkdir -p "$LOGDIR"
ulimit -v "${MUT_ULIMIT_KB:-3000000}" || { echo "run.sh: ulimit -v failed" >&2; exit 2; }

if [[ -n "${ONLY:-}" ]]; then ids="$ONLY"
else ids="$(seq 0 "$LAST")"; fi
ids="$(echo $ids)"  # one line, single spaces
ids="0 $(tr ' ' '\n' <<< "$ids" | grep -vx 0 | tr '\n' ' ')"  # the baseline first, once

declare -A tally=()
for i in $ids; do
    log="$LOGDIR/out-$i.log"
    t0=$(date +%s)
    # The group's 2>/dev/null only silences bash's own "Killed" notice.
    { env "$ENV_NAME=$i" setsid -w timeout -s KILL "$TIMEOUT" "$BIN" > "$log" 2>&1; } 2>/dev/null
    rc=$?
    dt=$(( $(date +%s) - t0 ))
    reason=""
    if (( rc == 0 )); then
        if [[ "$i" == 0 ]]; then v=PASS; else v=SURVIVED; fi
    elif (( rc == 124 || rc == 137 )); then
        v=HANG; reason="killed at ${TIMEOUT}s"
    # A test binary run directly reports `<n>/<m> <name>...FAIL (<Err>)` and
    # `<k> failed.`; a panic or a safety check names itself.
    elif grep -qE "FAIL \(|[0-9]+ failed\.|panic|Segmentation fault|reached unreachable|integer overflow|index out of bounds" "$log"; then
        v=KILLED; reason="$(grep -m1 -oE "FAIL \([A-Za-z0-9_]+\)|[0-9]+ failed\.|panic.{0,60}|Segmentation fault|reached unreachable|integer overflow|index out of bounds" "$log")"
    elif (( rc > 128 )); then
        v=KILLED; reason="signal $(( rc - 128 ))"
    else
        v=UNCLEAR; reason="rc $rc, no failing test in $log"
    fi
    printf '%s\t%s\t%s\t%s\n' "$i" "$v" "$dt" "$reason"
    tally[$v]=$(( ${tally[$v]:-0} + 1 ))
    if [[ "$i" == 0 && "$v" != PASS ]]; then
        echo "run.sh: the baseline (0) did not pass under this exact command -- nothing can be judged" >&2
        exit 2
    fi
done
summary=""
for k in PASS KILLED HANG SURVIVED UNCLEAR; do summary="$summary $k=${tally[$k]:-0}"; done
echo "run.sh:$summary"
