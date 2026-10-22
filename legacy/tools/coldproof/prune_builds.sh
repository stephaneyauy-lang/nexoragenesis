#!/usr/bin/env bash
# Prune out/c-bootstrap/builds/ down to a retention window.
#
# WHY THIS EXISTS (measured 30 September 2026): every ngbuild.sh run creates
# out/c-bootstrap/builds/ngbuild-<HHMMSS>-<pid>/ and no code path ever removed an
# old one. Measured: 397 entries, 33 405 MB, and two whole-tree censuses timed
# out at 250 s and 280 s because out/ holds ~132 411 of the tree's ~136 820
# files. A scan that cannot finish is a scan that cannot report.
#
# WHAT IT MAY DELETE: nothing, without --apply. The default is a DRY RUN that
# prints the identical before/after/kept/pruned/refused report and changes
# nothing on disk. An unattended `rm -rf` of 33 GB reached by a shared driver
# nine agents run is not a default worth having.
#
# THE POLICY IS IN legacy/tools/coldproof/BUILDS-RETENTION.md. This file is the
# mechanism; that document is the contract, and the two must not disagree.
set -uo pipefail

REPO=${NG_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)}
BUILDS="$REPO/out/c-bootstrap/builds"

# KEEP is the retention number, N. It is duplicated in
# legacy/tools/coldproof/BUILDS-RETENTION.md and the two are asserted against each
# other by --check-policy. A number that lives only in code is a number a
# reader has to run something to learn.
KEEP=5

# LIVE_MIN_AGE_S: an entry younger than this is NEVER a prune candidate,
# whatever its rank. A run in flight writes to its directory seconds ago, and
# "written recently" is byte-for-byte what a killed run's leftovers look like
# from the filesystem. Measured full suite: ~508 s. 1800 s is 3.5x that, so a
# live run cannot be mistaken for a corpse even if its PID is invisible here.
LIVE_MIN_AGE_S=${NG_PRUNE_LIVE_MIN_AGE_S:-1800}

APPLY=0
CHECK_POLICY=0
QUIET=0
while [ $# -gt 0 ]; do
    case "$1" in
        --apply) APPLY=1 ;;
        --check-policy) CHECK_POLICY=1 ;;
        --quiet) QUIET=1 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "PRUNE_BUILD_USAGE unknown argument '$1'" >&2; exit 2 ;;
    esac
    shift
done

say() { [ "$QUIET" = 1 ] || printf '%s\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. Refuse to do anything at all unless builds/ is where it must be.
#
# A pruner that resolves its own target can be pointed at a tree it does not
# understand. The path is checked against the repository root AND each entry's
# realpath must resolve back inside it, so a link or a junction out of the tree
# is a refusal, never a deletion.
# ---------------------------------------------------------------------------
if [ ! -d "$BUILDS" ]; then
    echo "PRUNE_BUILD_REFUSED reason=no_builds_dir path=$BUILDS" >&2
    exit 2
fi
BUILDS_REAL=$(cd "$BUILDS" && pwd -P) || {
    echo "PRUNE_BUILD_REFUSED reason=builds_dir_unresolvable path=$BUILDS" >&2; exit 2; }
case "$BUILDS_REAL" in
    "$REPO"/out/c-bootstrap/builds) ;;
    *) echo "PRUNE_BUILD_REFUSED reason=builds_dir_outside_repo resolved=$BUILDS_REAL" >&2
       exit 2 ;;
esac

NOW=$(date +%s)

# ---------------------------------------------------------------------------
# 2. LIVENESS. Two INDEPENDENT signals, and an entry is live if EITHER fires.
#
#    (a) PID: the run directory is NAMED ngbuild-<HHMMSS>-<pid> by ngbuild.sh:198,
#        so the pid is IN THE NAME. If a process with that pid exists, something
#        may still be writing here.
#    (b) AGE: the newest mtime is younger than LIVE_MIN_AGE_S.
#
#    Why (b) exists at all, given (a): on this host the runs observed writing
#    into builds/ are WSL-hosted, launched as C:\windows\system32\bash.exe, so the
#    $$ baked into the directory name is a LINUX pid and is NOT in the PID
#    namespace this script can see. Signal (a) is therefore a FALSE NEGATIVE
#    for exactly the runs that matter. (b) covers them. ANDing the two guards is
#    strictly safer than either alone: a directory is pruned only when its pid is
#    dead AND it has been quiet for half an hour.
#
#    PIDs RECYCLE, so (a) errs toward KEEPING, which is the safe direction: a
#    recycled pid can only cost bytes, never a sibling's run.
# ---------------------------------------------------------------------------
pid_alive() {
    local p=$1
    [ -n "$p" ] || return 1
    if ps -p "$p" >/dev/null 2>&1; then return 0; fi
    if tasklist //FI "PID eq $p" 2>/dev/null | grep -qa "^$p"; then return 0; fi
    return 1
}

PID_SIGNAL="ps+tasklist"
say "PRUNE_BUILD pid_signal=$PID_SIGNAL keep=$KEEP live_min_age_s=$LIVE_MIN_AGE_S mode=$([ $APPLY = 1 ] && echo APPLY || echo DRY-RUN)"

# ---------------------------------------------------------------------------
# 3. CLASSIFY. An entry is a prune candidate only if it is POSITIVELY recognised
#    as a per-run build directory. Everything else is refused WITH A REASON.
#
#    The name grammar is the driver's own, from ngbuild.sh:198. Nothing that
#    does not match it is a run directory this tool can prove it created, so
#    nothing that does not match it is deleted -- including the entries that are
#    cited: tests_ntasm_registry.c:6593-6596 names four files under
#    out/c-bootstrap/builds/w26reg2/, and that directory does not match, so it is
#    refused and stays.
# ---------------------------------------------------------------------------
NAME_RE='^ngbuild-[0-9]{6}-[0-9]+$'

bytes_of() { du -sb "$1" 2>/dev/null | cut -f1; }

# --- the census, before anything is touched ---------------------------------
BEFORE_BYTES=$(du -sb "$BUILDS" 2>/dev/null | cut -f1)
BEFORE_BYTES=${BEFORE_BYTES:-0}
BEFORE_ENTRIES=$(find "$BUILDS" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)

kept_names=(); prune_names=(); refuse_lines=()
refused=0; live_kept=0; candidates=0

while IFS= read -r -d '' entry; do
    name=$(basename "$entry")

    # (3a) shape refusals, cheapest and most common first
    if [ -L "$entry" ]; then
        refuse_lines+=("$name|REFUSED reason=symlink"); refused=$((refused+1)); continue
    fi
    if [ ! -d "$entry" ]; then
        refuse_lines+=("$name|REFUSED reason=not_a_directory"); refused=$((refused+1)); continue
    fi
    real=$(cd "$entry" 2>/dev/null && pwd -P)
    if [ -z "$real" ] || [ "${real#"$BUILDS_REAL"/}" = "$real" ]; then
        refuse_lines+=("$name|REFUSED reason=resolves_outside_builds"); refused=$((refused+1)); continue
    fi
    if ! printf '%s' "$name" | grep -qE "$NAME_RE"; then
        refuse_lines+=("$name|REFUSED reason=unrecognised_name"); refused=$((refused+1)); continue
    fi

    # NOTE: this array is `kept_names`, and it is `kept_names` in the report too.
    # It was `keep_names` in these two branches and `kept_names` in the report,
    # so the first dry run printed `kept 5` on a tree where 23 entries were
    # live-kept. A counter that cannot be false proves nothing.
    # (3b) it IS a per-run build directory. Now: is it alive?
    pid=${name##*-}
    mtime=$(stat -c %Y "$entry" 2>/dev/null) || mtime=0
    age=$(( NOW - ${mtime:-0} ))
    if pid_alive "$pid"; then
        kept_names+=("$name"); live_kept=$((live_kept+1))
        say "  LIVE pid=$pid  $name  (pid alive; not a prune candidate)"
        continue
    fi
    if [ "$age" -lt "$LIVE_MIN_AGE_S" ]; then
        kept_names+=("$name"); live_kept=$((live_kept+1))
        say "  LIVE age=${age}s  $name  (written within ${LIVE_MIN_AGE_S}s; not a prune candidate)"
        continue
    fi
    prune_names+=("$name|$mtime"); candidates=$((candidates+1))
done < <(find "$BUILDS" -mindepth 1 -maxdepth 1 -print0 2>/dev/null)

# Newest first: mtime descending, name as the tie-break so two runs cannot
# produce different answers about the same bytes.
if [ "${#prune_names[@]}" -gt 0 ]; then
    mapfile -t prune_sorted < <(printf '%s\n' "${prune_names[@]}" \
        | sort -t'|' -k2,2nr -k1,1)
else
    prune_sorted=()
fi

# Retention keeps the NEWEST KEEP. `prune_sorted` is newest-first, so the
# retained window is the HEAD of the array and the doomed tail is everything
# after it. This was the reverse for one run -- doomed took the head -- so the
# pruner deleted the most RECENT directories and kept the five oldest. The
# fixture assertion "the newest stale run was KEPT" is what caught it; an
# instrument that only counts deletions would have reported a clean run.
total=${#prune_sorted[@]}
if [ "$total" -gt "$KEEP" ]; then
    retained=("${prune_sorted[@]:0:$KEEP}")
    doomed=("${prune_sorted[@]:$KEEP}")
else
    doomed=()
    retained=("${prune_sorted[@]}")
fi
retained_names=(); for r in "${retained[@]:-}"; do [ -n "$r" ] && retained_names+=("${r%%|*}"); done
doomed_names=();     for d in "${doomed[@]:-}";     do [ -n "$d" ] && doomed_names+=("${d%%|*}");   done

kept=$(( ${#kept_names[@]} + ${#retained_names[@]} ))
pruned=0; pruned_bytes=0; failed=0

say ""
say "PRUNE_BUILD_REPORT repo=$REPO"
say "  builds_dir            $BUILDS"
say "  mode                  $([ $APPLY = 1 ] && echo APPLY || echo 'DRY-RUN (nothing was deleted)')"
say "  entries before        $BEFORE_ENTRIES"
say "  bytes before          $BEFORE_BYTES"
say "  recognised runs       $candidates stale + $live_kept live = $((candidates+live_kept))"
say "  kept                  $kept  (= $live_kept live-by-signal + ${#retained_names[@]} kept-by-retention)"
say "  to prune              ${#doomed_names[@]}"
say "  refused               $refused"
for line in "${refuse_lines[@]:-}"; do
    [ -n "$line" ] && say "    ${line}"
done

# The sum is checked AND printed. A total that cannot be reconciled against its
# own parts is the shape AGENTS.md:114 warns about: an instrument that prints a
# value the world does not contain, and nothing goes red.
if [ $(( kept + ${#doomed_names[@]} + refused )) -ne "$BEFORE_ENTRIES" ]; then
    say "  ACCOUNTING            MISMATCH kept=$kept + to_prune=${#doomed_names[@]} + refused=$refused != entries_before=$BEFORE_ENTRIES"
else
    say "  accounting            OK  kept=$kept + to_prune=${#doomed_names[@]} + refused=$refused = entries_before=$BEFORE_ENTRIES"
fi

if [ "$CHECK_POLICY" = 1 ]; then
    # The policy document is resolved NEXT TO THIS SCRIPT, not under $REPO.
    # $REPO is the prune TARGET and a test fixture points it at a tree that has
    # no policy document at all, so resolving the doc through the target made
    # --check-policy fail for the right reason on the wrong path. The policy
    # travels with the mechanism; the target is data.
    doc="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/BUILDS-RETENTION.md"
    doc_keep=$(grep -oE '^N *= *[0-9]+' "$doc" 2>/dev/null | head -1 | grep -oE '[0-9]+')
    if [ "${doc_keep:-}" = "$KEEP" ]; then
        say "  policy cross-check    OK  N=$KEEP matches $doc"
    else
        echo "PRUNE_BUILD_POLICY_MISMATCH code=$KEEP doc=${doc_keep:-ABSENT} doc=$doc" >&2
        exit 3
    fi
fi

if [ "$APPLY" != 1 ]; then
    say ""
    say "  bytes after           $BEFORE_BYTES (unchanged: this was a DRY RUN)"
    say "PRUNE_BUILD_DONE pruned=0 dry_run=1 kept=$kept refused=$refused"
    exit 0
fi

# ---------------------------------------------------------------------------
# 4. DELETE. Re-verify every entry's identity IMMEDIATELY before removing it:
#    the census above happened seconds ago and nine agents share this tree.
# ---------------------------------------------------------------------------
say ""
for name in "${doomed_names[@]:-}"; do
    [ -n "$name" ] || continue
    path="$BUILDS/$name"
    if [ -L "$path" ] || [ ! -d "$path" ]; then
        say "  PRUNE_SKIPPED $name reason=changed_shape_since_census"; failed=$((failed+1)); continue
    fi
    if ! printf '%s' "$name" | grep -qE "$NAME_RE"; then
        say "  PRUNE_SKIPPED $name reason=name_no_longer_matches"; failed=$((failed+1)); continue
    fi
    b=$(bytes_of "$path"); b=${b:-0}
    rm -rf -- "$path"
    if [ -e "$path" ]; then
        # `rm -rf` on this filesystem has been observed NOT to take effect
        # (coldsuite.sh:9). A delete that reports success without the directory
        # being gone is the failure this branch exists to catch.
        say "  PRUNE_FAILED  $name reason=still_present_after_rm bytes=$b"; failed=$((failed+1)); continue
    fi
    pruned=$((pruned+1)); pruned_bytes=$((pruned_bytes+b))
    say "  PRUNED        $name  $b bytes"
done

AFTER_BYTES=$(du -sb "$BUILDS" 2>/dev/null | cut -f1); AFTER_BYTES=${AFTER_BYTES:-0}
AFTER_ENTRIES=$(find "$BUILDS" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)

say ""
say "  entries after         $AFTER_ENTRIES"
say "  bytes after           $AFTER_BYTES"
say "  bytes reclaimed       $((BEFORE_BYTES-AFTER_BYTES)) (sum of per-dir removals: $pruned_bytes)"
say "  kept                  $((kept - failed))"
say "  pruned                $pruned"
say "  refused               $refused"
say "PRUNE_BUILD_DONE pruned=$pruned failed=$failed kept=$((kept-failed)) refused=$refused" \
    "bytes_before=$BEFORE_BYTES bytes_after=$AFTER_BYTES"
[ "$failed" = 0 ]
