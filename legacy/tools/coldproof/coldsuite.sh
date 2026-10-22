#!/usr/bin/env bash
# Cold-build wrapper for a FULL suite run, with proof.
#
# Why this exists, and why plain "rm -rf && build" is not enough:
#
#  * ngbuild.sh's own stale_obj skips a compile when an object sits in a later
#    second than its source, so a directory that "still has its objects" can
#    answer for a revision of the source that no longer exists.
#  * `rm -rf` on this filesystem has been observed NOT to take effect.
#  * An unrelated process has been observed DELETING build directories and
#    their contents mid-run. Two directories were lost that way tonight, and a
#    directory that disappears between the run and the report is not evidence.
#
# So: create a name that has never existed, stamp a sentinel, build, then
# REFUSE to call the run green unless every gate binary and every run log in
# the directory is strictly newer than the sentinel AND the directory is still
# there at the end. A run that cannot prove coldness is a sample, not a
# measurement, whatever the banners said.
#
# usage: coldsuite.sh <builddir> [gate ...]      # no gate = the full 92
set -uo pipefail
NG=${NG:-/mnt/d/Projets/Racine-C/NexoraGenesis/tools/coldproof/ngbuild.sh}
BUILD="$1"; shift

# A build directory that is not the one you asked for is not evidence about the
# one you asked for. Given `/mnt/d/Projets/Racine-C/NexoraGenesis` this script
# once received `D:ProjetsRacine-CNexoraGenesis` with every slash eaten, built
# happily in a real but DIFFERENT empty directory where the sentinel and the
# artefacts agreed, and printed COLD_PROOF ok. The proof was true of a place
# nobody named. Refuse a path that is not absolute, and refuse one that does not
# resolve to itself.
case "$BUILD" in
  /*) ;;
  *) echo "COLD_ABORT the build directory must be ABSOLUTE; got '$BUILD'."
     echo "  A relative path can be resolved against the wrong root, and then"
     echo "  COLD_PROOF would be true of a directory nobody named."
     exit 2 ;;
esac
case "$BUILD" in
  *[!a-zA-Z0-9._/-]*)
    echo "COLD_ABORT the build directory contains a character that may not"
    echo "  survive path translation: '$BUILD'"
    echo "  (a Windows-style path arriving here has every slash eaten)"
    exit 2 ;;
esac
if [ -e "$BUILD" ]; then echo "COLD_ABORT $BUILD already exists; pick a name that has never existed"; exit 2; fi
mkdir -p "$BUILD" || exit 2
# Resolve what we actually created and require it to be the path we were given.
MADE=$(cd "$BUILD" 2>/dev/null && pwd -P) || { echo "COLD_ABORT $BUILD is not a directory"; exit 2; }
if [ "$MADE" != "$BUILD" ]; then
  echo "COLD_ABORT asked for '$BUILD' and created '$MADE'."
  echo "  COLD_PROOF about the second is not evidence about the first."
  exit 2
fi
sleep 1.1
touch "$BUILD/.COLD_SENTINEL" || exit 2
NG_BUILD="$BUILD" bash "$NG" "$@" >"$BUILD/.run.log" 2>&1
rc=$?
grep -aE '^(NTASM_|COVERAGE |REFERENCES|REGISTRY |DRIFT|MUTANT|RAIL_SELFTEST|LIBS_OK|GATES_DONE|CC_FAIL|RUN_FAIL|STALE_OBJECTS|SOURCES-MOVED|UNREGISTERED)' "$BUILD/.run.log" || true

cold=1
if [ ! -e "$BUILD/.COLD_SENTINEL" ]; then
  echo "COLD_PROOF FAILED: sentinel vanished — the directory was not fresh"; cold=0
fi
if [ ! -d "$BUILD" ]; then
  echo "COLD_PROOF FAILED: the build directory was deleted mid-run"; cold=0
fi
# Every gate binary AND every run log must postdate the sentinel. With no gate
# named this is the whole suite, which is the case the run-log loop below
# cannot enumerate from "$@".
n=0
for a in "$BUILD"/*; do
  case "$(basename "$a")" in
    .COLD_SENTINEL|.run.log|.gates|.harnesses) continue ;;
  esac
  [ -f "$a" ] || continue
  case "$a" in
    *.o|*.log) continue ;;
  esac
  n=$((n+1))
  if [ "$BUILD/.COLD_SENTINEL" -nt "$a" ]; then
    echo "COLD_PROOF FAILED: $a predates the sentinel"; cold=0
  fi
done

# A cold proof over ZERO artefacts is a green that checked nothing. `ngbuild.sh
# libsonly` exits before the object loop, so `coldsuite.sh <dir> libsonly` used
# to print RAIL_SELFTEST ok and COLD_PROOF ok over an empty directory — the
# exact failure this project exists to remove, in the instrument that enforces
# the rule. Refuse it.
if [ "$n" -eq 0 ]; then
  echo "COLD_PROOF FAILED: zero gate binaries were produced, so nothing was proven."
  echo "  (ngbuild.sh 'libsonly' exits before the object loop and compiles"
  echo "   nothing — name at least one real gate.)"
  cold=0
fi
echo "  (checked $n gate binaries)"
if [ "$cold" = 1 ]; then
  echo "COLD_PROOF ok: $BUILD created empty, all artefacts newer than its sentinel, directory intact"
else
  echo "COLD_PROOF: SAMPLES ONLY — do not quote any number from this run"
fi
exit $rc
