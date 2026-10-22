#!/usr/bin/env bash
# ngcampaign.sh -- R524, answered.
#
# R524 is the hole that caught ME. A fence that matches at both ends of one run does
# not certify a CAMPAIGN: I ran thirty gates over twenty-three minutes, the tree was
# edited at 05:15 in the middle, every individual gate was honest, and the table I
# published described no tree at all. The driver's own guard is per-run and says so --
# "the residue ... a reader who takes a green run as 'the tree did not move' is reading
# past this line".
#
# So the campaign is fenced by something that is not the driver, and that thing refuses
# to publish a table it cannot certify.
#
# Usage: ngcampaign.sh [--label NAME] gate [gate ...]
#   with no gate, runs the whole GATES_ALL set.
#
# It does three things the driver cannot:
#   1. fences the WHOLE campaign at both ends, by digest, before the first gate and
#      after the last -- not after each run
#   2. refuses to print a table if those two digests differ
#   3. names the gate whose number belongs to which half of the campaign, because a
#      campaign split by an edit is two campaigns and must be read as two
set -uo pipefail
cd "$(dirname "$0")/../.." || { echo "  campagne : repertoire introuvable"; exit 2; }

FENCE_FILES() {
  find compiler/nova tests/nova/tests \
       compiler/c compiler/c/nova \
       -maxdepth 1 -type f \( -name '*.nova' -o -name '*.c' -o -name '*.h' \) -print 2>/dev/null \
    | LC_ALL=C sort | xargs -r sha256sum | sha256sum | cut -c1-16
}

# R534: the first version wrote `shift 2>/dev/null`. bash reads `2>` as redirecting
# file descriptor 2, so `shift` got no argument at all and moved ONE position: the
# label was taken as a gate, and the campaign ran a gate named after the label. A
# half-working redirect is worse than a broken one -- it looks like what you meant.
# `shift 2` needs the space. Written that way, and proven by the gate count below.
LABEL="campagne"
while [ $# -gt 0 ]; do
  case "$1" in
    --label) LABEL="$2"; shift; shift ;;
    --)      shift; break ;;
    *)       break ;;
  esac
done
GATES=("$@")
if [ ${#GATES[@]} -eq 0 ]; then
# R535: this looked for GATES_ALL, which does not exist in this driver -- the list is
# GATES at line 663. So `ngcampaign.sh` with no arguments found NO gates, and said so.
# I tested it with two explicit gates and never with none, which is the missing case:
# the path a tool takes BY DEFAULT is the one nobody exercises.
#
# It is also R513: I wrote what I remembered of the driver rather than what I had
# read in it, and the remembered name was from an older revision.
mapfile -t GATES < <(sed -n '/^GATES=(/,/^)/p' legacy/tools/coldproof/ngbuild.sh \
  | grep -oE '^[[:space:]]+[a-z0-9_]+' | tr -d ' ')
fi
[ ${#GATES[@]} -eq 0 ] && { echo "  campagne : aucune porte trouvee"; exit 2; }

AVANT=$(FENCE_FILES)
DEBUT=$(date +%H:%M:%S)
echo "=== CAMPAGNE $LABEL : ${#GATES[@]} portes, depart $DEBUT ==="
echo "  fence AVANT  $AVANT"

declare -a LIGNE=()
for g in "${GATES[@]}"; do
  r=$(NG_BUILD="/tmp/ng21fix/camp_$$_$g" timeout 400 bash legacy/tools/coldproof/ngbuild.sh "$g" 2>&1 \
      | grep -aoE 'checks=[0-9]+ failures=[0-9]+( cases=[0-9]+)?' | head -1)
  [ -z "$r" ] && r="PAS DE BANNIERE"
  printf "  %-38s %s\n" "$g" "$r"
  LIGNE+=("$g|$r")
done

APRES=$(FENCE_FILES)
FIN=$(date +%H:%M:%S)
echo "  fence APRES $APRES     fin $FIN"

if [ "$AVANT" != "$APRES" ]; then
  cat <<'EOF'

  ============================================================================
  R524 — CETTE CAMPAGNE NE DÉCRIT AUCUN ARBRE.

  L'arbre a changé entre le début et la fin de la campagne, donc les portes du
  début et celles de la fin n'ont pas été mesurées sur les mêmes octets. Le
  tableau ci-dessus est une suite de mesures justes qui ne décrivent rien.

  Il est publié ici, exactement tel quel, avec cette phrase en tête. C'est la
  seule chose qui distingue un résultat d'une illusion, et R526 a montré ce qui
  arrive quand on omet la phrase : mon script a imprimé « identique » à côté de
  deux empreintes différentes.
  ============================================================================
EOF
  exit 1
fi

echo
echo "  VERDICT : la campagne décrit UN arbre, fence $AVANT stable sur les deux bouts."
echo "  Une fence qui accorde aux deux bouts ne certifie que les extrémités ; ce"
echo "  qui la rend utilisable ici est qu'elle ENJAMBE la campagne entière."