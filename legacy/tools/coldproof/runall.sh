#!/usr/bin/env bash
# Full 92-gate run, cold-proven. $1 is an optional label for the log.
set -uo pipefail
REPO=/mnt/d/Projets/Racine-C/NexoraGenesis
cd "$REPO"
B=/mnt/d/Projets/Racine-C/ngf-$(date +%H%M%S)-$$
LOG=out/c-bootstrap/nova/evidence/wave17-integration.log
mkdir -p "$(dirname "$LOG")"
bash /mnt/d/Projets/Racine-C/NexoraGenesis/tools/coldproof/coldsuite.sh "$B" >"$LOG" 2>&1
rc=$?
echo "build dir: $B"
echo "log:        $LOG"
echo "---"
grep -aE "GATES_DONE|COLD_PROOF|RUN_FAIL|CC_FAIL|UNREGISTERED|STALE_OBJECTS|SOURCES-MOVED" "$LOG"
echo "--- every FAIL, if any ---"
grep -aE "^FAIL" "$LOG" | cut -c1-140 | head -20
echo "--- key banners ---"
grep -aE "REFERENCES |REFERENCES-PER-DOC|REGISTRY |COVERAGE|MACRO_EXPAND|SPLICE|DRIFT-ORACLE|DRIFT-ASSEMBLY" "$LOG" | head -10
exit $rc
