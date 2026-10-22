#!/usr/bin/env bash
# Gate for legacy/tools/coldproof/prune_builds.sh.
#
# The pruner DELETES 33 GB. A test that only checked "it returned 0" would pass
# on a script that deletes everything, which is the failure mode that matters
# here. So every claim below is made against a FIXTURE tree, and each one is
# proved by construction: the fixture is built, the pruner is run against it,
# and the artefact is then CHECKED ON DISK. A pruner that reported a refusal and
# deleted the directory anyway fails this test.
#
# Fixture root is a fresh mktemp -d. Nothing here touches the real
# out/c-bootstrap/builds/.
set -uo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
PRUNER="$HERE/prune_builds.sh"
DOC="$HERE/BUILDS-RETENTION.md"

fail=0
checks=0
check() { # check <condition-result> <description>
    checks=$((checks+1))
    if [ "$1" = 0 ]; then printf '  ok   %s\n' "$2"
    else printf '  FAIL %s\n' "$2"; fail=$((fail+1)); fi
}

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/ng-prune-gate-XXXXXX") || {
    echo "BUILDS_PRUNE_GATE fail=1 reason=cannot_create_fixture_root"; exit 1; }
trap 'rm -rf "$ROOT"' EXIT

# A repository-shaped root, so the pruner finds out/c-bootstrap/builds where it
# expects it and its repo containment check has something real to check.
FAKE_REPO="$ROOT/repo"
BUILDS="$FAKE_REPO/out/c-bootstrap/builds"
mkdir -p "$BUILDS"

AGE_FAR=$(( $(date +%s) - 86400 ))   # comfortably past LIVE_MIN_AGE_S (1800 s)

mk_run() { # mk_run <name> <epoch> <pid>
    mkdir -p "$BUILDS/$1"
    printf 'artefact\n' >"$BUILDS/$1/payload.o"
    # mtime is set AFTER the payload is written: writing the payload stamps a
    # fresh mtime on the directory, which the AGE signal would then correctly
    # and uselessly treat as live.
    touch -d "@$2" "$BUILDS/$1" "$BUILDS/$1/payload.o"
}
# The timestamp is zero-padded to SIX digits by printf, not built by string
# concatenation. `ngbuild-10000$i` yields SEVEN digits at i=10; those two
# directories stop matching the run-name grammar and are then correctly
# REFUSED -- which silently moved the population from 12 to 10 and made the
# retention arithmetic wrong by two. A fixture whose shape depends on an
# integer's width is a fixture that lies to whoever reads its verdict.
ts() { printf '%06d' "$1"; }


# A pid that is DEAD BY CONSTRUCTION, so the retention arithmetic is not a race
# against this host's process table. A pid invented as `9000$i` is a guess, and
# on a busy Windows host it can be a live process -- which is how the first run
# of this gate reported `to prune 5` where the fixture arithmetic says 6.
DEAD_PID=$( (sleep 0.2 & echo $!) )
while ps -p "$DEAD_PID" >/dev/null 2>&1; do sleep 0.05; done
if ps -p "$DEAD_PID" >/dev/null 2>&1; then
    echo "BUILDS_PRUNE_GATE fail=1 reason=could_not_obtain_a_dead_pid"; exit 1
fi

# ---- the fixture population -------------------------------------------------
# Twelve stale runs with a dead pid, plus ONE live-by-pid run (below).
# 12 stale - KEEP 5 = 7 to prune.
i=0
while [ $i -lt 12 ]; do
    mk_run "ngbuild-$(ts "$i")-$DEAD_PID" $(( AGE_FAR - i * 60 )) "$DEAD_PID"
    i=$((i+1))
done

# ---- the four shapes the pruner must REFUSE, each with its own reason -------
mkdir -p "$BUILDS/w26reg2/neg/CLASS/tools/coldproof"
printf 'x\n' >"$BUILDS/w26reg2/neg/CLASS/tools/coldproof/ngbuild.sh"   # CITED, unrecognised name
touch -d "@$AGE_FAR" "$BUILDS/w26reg2"
mk_run "frame-final" "$AGE_FAR" "$DEAD_PID"                            # unrecognised name
ln -s "$BUILDS/ngbuild-000000-$DEAD_PID" "$BUILDS/ngbuild-120000-90009" 2>/dev/null
SYMLINK_MADE=$?
printf 'a stray log, not a directory\n' >"$BUILDS/W27Census.rail.log"  # not a directory
touch -d "@$AGE_FAR" "$BUILDS/W27Census.rail.log"
# A run directory that is FRESH (mtime = now) with a DEAD pid, so the AGE signal
# has something to fire on that the PID signal cannot account for. Without it
# the AGE branch is never taken in this gate, and a guard that has never
# executed is not a guard.
mkdir -p "$BUILDS/ngbuild-105000-$DEAD_PID"
printf 'fresh\n' >"$BUILDS/ngbuild-105000-$DEAD_PID/recent.o"

# ---- the LIVE negative control ---------------------------------------------
# A real process, whose PID goes into a run directory's NAME. If the liveness
# predicate is ever weakened to recency alone, this directory is deleted and the
# test goes red. A liveness guard that has never been shown REFUSING is an
# assumption, not a guard.
sleep 300 &
LIVE_PID=$!
mkdir -p "$BUILDS/ngbuild-105959-$LIVE_PID"
printf 'live\n' >"$BUILDS/ngbuild-105959-$LIVE_PID/inflight.o"
# STALE mtime on purpose: recency must NOT be what saves it, the PID must.
touch -d "@$AGE_FAR" "$BUILDS/ngbuild-105959-$LIVE_PID"

run_prune() { NG_REPO="$FAKE_REPO" NG_PRUNE_LIVE_MIN_AGE_S=1800 bash "$PRUNER" "$@" 2>&1; }

echo "BUILDS_PRUNE_GATE fixture=$ROOT dead_pid=$DEAD_PID live_pid=$LIVE_PID"

echo "-- pass 1: DRY RUN must change nothing on disk -------------------------"
D1=$(run_prune --check-policy); rc1=$?
check "$([ $rc1 = 0 ] && echo 0 || echo 1)" "dry run exits 0 (rc=$rc1)"
check "$(printf '%s' "$D1" | grep -qa 'DRY-RUN (nothing was deleted)' && echo 0 || echo 1)" \
      "dry run announces DRY-RUN and deleted nothing"
check "$(printf '%s' "$D1" | grep -qa 'PRUNE_BUILD_DONE pruned=0 dry_run=1' && echo 0 || echo 1)" \
      "dry run reports pruned=0"
check "$([ -d "$BUILDS/ngbuild-000000-$DEAD_PID" ] && echo 0 || echo 1)" \
      "dry run left a recognised run directory on disk"
check "$(printf '%s' "$D1" | grep -qa 'accounting            OK' && echo 0 || echo 1)" \
      "kept + to_prune + refused == entries_before"

echo "-- refusals -------------------------------------------------------------"
check "$(printf '%s' "$D1" | grep -qa 'w26reg2|REFUSED reason=unrecognised_name' && echo 0 || echo 1)" \
      "REFUSED unrecognised_name: w26reg2 (the CITED directory)"
check "$(printf '%s' "$D1" | grep -qa 'frame-final|REFUSED reason=unrecognised_name' && echo 0 || echo 1)" \
      "REFUSED unrecognised_name: frame-final"
check "$(printf '%s' "$D1" | grep -qa 'W27Census.rail.log|REFUSED reason=not_a_directory' && echo 0 || echo 1)" \
      "REFUSED not_a_directory: W27Census.rail.log"
if [ $SYMLINK_MADE = 0 ]; then
    check "$(printf '%s' "$D1" | grep -qa 'ngbuild-120000-90009|REFUSED reason=symlink' && echo 0 || echo 1)" \
          "REFUSED symlink: ngbuild-120000-90009"
else
    printf '  skip symlink fixture: ln -s unsupported here (not a red: the shape is\n'
    printf '       covered by the not_a_directory and unrecognised refusals above)\n'
fi
check "$([ -f "$BUILDS/w26reg2/neg/CLASS/tools/coldproof/ngbuild.sh" ] && echo 0 || echo 1)" \
      "the CITED file tests_ntasm_registry.c:6593 depends on is STILL ON DISK"

echo "-- liveness -------------------------------------------------------------"
check "$(printf '%s' "$D1" | grep -qa "LIVE pid=$LIVE_PID" && echo 0 || echo 1)" \
      "LIVE detected by PID for a run directory whose PID is a real process"
check "$(printf '%s' "$D1" | grep -q 'written within 1800s' && echo 0 || echo 1)" \
      "the AGE signal also fires on a freshly-written directory"

echo "-- retention arithmetic -------------------------------------------------"
# Assert the PRUNABLE set, which is a retention question. The live-by-pid entry
# is excluded before ranking, so it is not one of the 12 stale runs.
to_prune=$(printf '%s' "$D1" | grep -oaE 'to prune +[0-9]+' | head -1 | grep -oaE '[0-9]+')
check "$([ "${to_prune:-x}" = 7 ] && echo 0 || echo 1)" \
      "to prune == 7 (12 stale recognised runs minus KEEP=5); got '${to_prune:-none}'"

# The population is asserted CLOSED before the arithmetic is asserted. Two
# fixture directories stopped matching the run-name grammar and were refused,
# which moved the population from 12 to 10 and made every count below wrong by
# two -- while the pruner was RIGHT and the test was wrong. A gate that only
# checks the arithmetic cannot tell those two cases apart; a gate that checks
# the denominator first can.
# The line reads `recognised runs  <stale> stale + <live> live = <total>`. The
# assertion wants the TOTAL, so it reads the field AFTER the `=`. Taking the
# first number on the line reads the stale count instead, which is a number that
# looks exactly like the one wanted and is not it -- AGENTS.md:21, measured.
RECOGNISED=$(printf '%s' "$D1" | grep -oaE 'recognised runs +[0-9]+ stale \+ [0-9]+ live = [0-9]+' \
    | head -1 | grep -oaE '[0-9]+$')
STALE_N=$(printf '%s' "$D1" | grep -oaE 'recognised runs +[0-9]+' | head -1 | grep -oaE '[0-9]+')
LIVE_N=$(printf '%s' "$D1" | grep -oaE 'stale \+ [0-9]+ live' | head -1 | grep -oaE '[0-9]+')
check "$([ "${RECOGNISED:-x}" = 14 ] && echo 0 || echo 1)" \
      "14 recognised runs total on the fixture; got '${RECOGNISED:-none}'"
# Two separate conditions, not `A && B` inside one `[ ]`: `echo "${LIVE_N}" = 2`
# is a STRING, so it is non-empty and therefore TRUE, and the old form could
# only ever report the first comparison. The gate was structurally incapable
# of failing on the second half of its own assertion.
STALE_LIVE_OK=0
[ "${STALE_N:-x}" = 12 ] || STALE_LIVE_OK=1
[ "${LIVE_N:-x}" = 2 ] || STALE_LIVE_OK=1
check "$STALE_LIVE_OK" "12 stale + 2 live; got '${STALE_N:-none}' stale + '${LIVE_N:-none}' live"
REFUSED_N=$(printf '%s' "$D1" | grep -oaE 'refused +[0-9]+' | head -1 | grep -oaE '[0-9]+')
check "$([ "${REFUSED_N:-x}" = 4 ] && echo 0 || echo 1)" \
      "4 refusals (w26reg2, frame-final, W27Census.rail.log, symlink); got '${REFUSED_N:-none}'"

echo "-- policy cross-check ---------------------------------------------------"
check "$(printf '%s' "$D1" | grep -qa 'policy cross-check    OK' && echo 0 || echo 1)" \
      "N in BUILDS-RETENTION.md agrees with KEEP= in prune_builds.sh"
DOC_KEEP=$(grep -oE '^N *= *[0-9]+' "$DOC" 2>/dev/null | head -1 | grep -oaE '[0-9]+')
check "$([ "${DOC_KEEP:-x}" = 5 ] && echo 0 || echo 1)" \
      "the document states N=5; got '${DOC_KEEP:-none}'"

echo "-- pass 2: --apply -------------------------------------------------------"
A=$(run_prune --apply --check-policy); rc2=$?
check "$([ $rc2 = 0 ] && echo 0 || echo 1)" "apply exits 0, no PRUNE_FAILED (rc=$rc2)"
# i=11 is the OLDEST: the loop sets mtime to AGE_FAR - i*60, so the larger the
# index the older the directory. Asserting on the oldest rather than on "some
# directory" is what makes this a retention test instead of a delete test.
check "$(printf '%s' "$A" | grep -qa "PRUNED  *ngbuild-000011-$DEAD_PID" && echo 0 || echo 1)" \
      "the OLDEST stale run (i=11) was pruned"
check "$([ ! -e "$BUILDS/ngbuild-000011-$DEAD_PID" ] && echo 0 || echo 1)" \
      "and it is GONE FROM DISK -- the report is not the only proof"
check "$([ -d "$BUILDS/ngbuild-000000-$DEAD_PID" ] && echo 0 || echo 1)" \
      "the NEWEST stale run (i=0) was KEPT -- retention keeps the most recent"
check "$([ -d "$BUILDS/w26reg2" ] && echo 0 || echo 1)" "apply did NOT touch the cited w26reg2"
check "$([ -f "$BUILDS/W27Census.rail.log" ] && echo 0 || echo 1)" "apply did NOT delete the stray file"
check "$(printf '%s' "$A" | grep -qaE 'bytes before +[0-9]+' && echo 0 || echo 1)" "apply prints bytes before"
check "$(printf '%s' "$A" | grep -qaE 'bytes after +[0-9]+' && echo 0 || echo 1)" "apply prints bytes after"
BEF=$(printf '%s' "$A" | grep -oaE 'bytes before +[0-9]+' | grep -oaE '[0-9]+')
AFT=$(printf '%s' "$A" | grep -oaE 'bytes after +[0-9]+' | grep -oaE '[0-9]+')
check "$([ -n "$BEF" ] && [ -n "$AFT" ] && [ "$AFT" -lt "$BEF" ] && echo 0 || echo 1)" \
      "bytes after < bytes before (${BEF:-?} -> ${AFT:-?})"
check "$(printf '%s' "$A" | grep -qaE '^PRUNE_BUILD_DONE pruned=7 failed=0' && echo 0 || echo 1)" \
      "PRUNE_BUILD_DONE reports pruned=7 failed=0"
# After the apply the recognised run dirs on disk are: 5 kept by retention,
# plus the one kept by the AGE signal, plus the one kept by the PID signal.
STALE_LEFT=$(find "$BUILDS" -mindepth 1 -maxdepth 1 -type d -name 'ngbuild-*' | wc -l)
check "$([ "$STALE_LEFT" = 7 ] && echo 0 || echo 1)" \
      "7 run dirs remain (5 by retention + 1 live-by-age + 1 live-by-pid); got $STALE_LEFT"
check "$([ -d "$BUILDS/ngbuild-105000-$DEAD_PID" ] && echo 0 || echo 1)" \
      "the FRESH directory survived --apply on the AGE signal, with a dead pid"

echo "-- pass 3: the LIVE directory survives the real apply ------------------"
check "$([ -d "$BUILDS/ngbuild-105959-$LIVE_PID" ] && echo 0 || echo 1)" \
      "the LIVE run's directory SURVIVED --apply, with a STALE mtime, on PID alone"
check "$([ -f "$BUILDS/ngbuild-105959-$LIVE_PID/inflight.o" ] && echo 0 || echo 1)" \
      "its contents survived too"
kill "$LIVE_PID" 2>/dev/null
wait "$LIVE_PID" 2>/dev/null

echo "-- pass 4: idempotence and the absent-target refusal --------------------"
I=$(run_prune --apply); rcI=$?
check "$([ $rcI = 0 ] && echo 0 || echo 1)" "second apply exits 0 (idempotent, nothing left to prune)"
rm -rf "$FAKE_REPO"
OUT=$(NG_REPO="$FAKE_REPO" bash "$PRUNER" --apply 2>&1); rc4=$?
check "$([ $rc4 = 2 ] && echo 0 || echo 1)" "refuses when builds/ does not exist (rc=2, got $rc4)"
check "$(printf '%s' "$OUT" | grep -qa 'reason=no_builds_dir' && echo 0 || echo 1)" \
      "and says why: reason=no_builds_dir"

printf 'BUILDS_PRUNE_GATE checks=%d failures=%d\n' "$checks" "$fail"
exit $(( fail > 0 ? 1 : 0 ))
