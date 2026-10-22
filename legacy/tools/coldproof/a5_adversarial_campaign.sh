#!/usr/bin/env bash
# A5_CAMPAIGN_ADVERSARIAL -- driver.
#
# Criterion A5 of docs/status/ntasm-completion.md: "Hygiène, provenance, absence d'I/O
# et bornes imposées, avec tests adverses".
#
# WHY A SCRIPT AND NOT A GATE HARNESS.  ngbuild.sh turns any tests_ntasm_*.c
# absent from its GATES list into UNREGISTERED_HARNESS and a suite-wide red
# (ngbuild.sh:1009-1012), and that scan reads exactly one directory,
# compiler/c/nova.  This campaign adds no inventory and edits no
# shared line.  The precedent is legacy/tools/coldproof/a5_bounds_campaign.{c,sh}.
#
# WHAT IT IS FOR, and what it is NOT.  tests_ntasm_a5_inventory.c is the
# instrument for the §12/§13 cross-tabulation and it runs green at
# checks=109 failures=0 cases=20.  A cross-tabulation reads a TABLE; this
# campaign EXECUTES inputs.  The inventory says whether a requirement is
# declared and exercised.  This says whether the product refuses, whether the
# refusal NAMES THE RULE THAT FIRED, and whether each refusal has a control
# that answers differently -- because a refusal that cannot be told apart from
# an unrelated one proves nothing, and this project has paid for that three
# times (a green banner read as coverage, a case count read as a requirement
# count, and a sweep whose strongest verdict had nothing to fire on).
#
# THE FINDING THIS RUNS ONTO, and it is the one the A5 row has carried as
# unmeasured for weeks: "le NV2_BOUNDS(4) à 32 704 items dont le site de levée
# n'est pas identifié — il n'est pas deviné".  It is identified here, by
# sweeping the CALLER's buffer one word at a time rather than by reading the
# runtime: the boundary is at exactly 8388609 words, one word past 64 MiB, and
# the refusal is on the caller's borrow while the expander's own verdict stays
# 0.  So the bound bites, and it is a boundary of the HARNESS.
#
# THE COLDNESS BAR, from a5_bounds_campaign.sh and for the same reason: given a
# relative path this tree once built happily in a real but DIFFERENT empty
# directory where the sentinel and the artefacts agreed and printed COLD_PROOF
# ok.  The build directory must be ABSOLUTE, must resolve to itself, and must
# hold ZERO FILES before the run -- not merely exist, because a directory can
# exist and be empty and `test -d` passes either way.
#
# THE RED PROOFS.  A green probe is evidence about the probe.  With --mutate,
# four perturbations are applied to a SCRATCH COPY carrying its own
# compiler/nova, and the repository is only ever read.  Each must turn
# the campaign RED:
#   M1  the __ntm$ mark word          -> the hygiene arm must fail
#   M2  the three folding writers     -> the I/O arm must fall back to 374/1
#   M3  the 381 span raises           -> the provenance arm must fail
#   M4  the probe's own perturbation  -> the determinism CONTROL must fail
# M4 perturbs the INSTRUMENT on purpose: it is the only way to show the
# determinism control can fail, and a control that cannot fail is a posture.
#
# usage: a5_adversarial_campaign.sh <absolute-builddir> [--mutate]
set -uo pipefail

REPO=${NG_REPO:-/mnt/d/Projets/Racine-C/NexoraGenesis}
BUILD="${1:-}"
MUTATE=0
[ "${2:-}" = "--mutate" ] && MUTATE=1

case "$BUILD" in
  /*) ;;
  *) echo "A5_ADV_ABORT the build directory must be ABSOLUTE; got '$BUILD'."
     exit 2 ;;
esac
case "$BUILD" in
  *[!a-zA-Z0-9._/-]*)
    echo "A5_ADV_ABORT the build directory has a character a path translation can"
    echo "  eat, so COLD_PROOF would be true of a place nobody named."
    exit 2 ;;
esac

root="$REPO/compiler/c"
mkdir -p "$BUILD" || exit 2
resolved=$(cd "$BUILD" && pwd -P) || exit 2
if [ "$resolved" != "$BUILD" ]; then
  echo "A5_ADV_ABORT '$BUILD' resolves to '$resolved'; refusing to build in a"
  echo "  directory nobody named."
  exit 2
fi
files_before=$(find "$BUILD" -type f | wc -l)
if [ "$files_before" != "0" ]; then
  echo "A5_ADV_ABORT $BUILD already holds $files_before files; a cold directory is"
  echo "  one that has never held a build."
  exit 2
fi
sentinel="$BUILD/.sentinel-$$"
: >"$sentinel" || exit 2
mkdir -p "$BUILD/objects" "$BUILD/campaign" || exit 2

# The project's own recipe, from ngbuild.sh:610 (libraries) and :747 (gates):
# -Wall -Wextra -Werror -O1 -g -fsanitize=address,undefined
LIBS=(
  "$root"/nova.c "$root"/ntasm.c "$root"/frontend.c "$root"/codegen.c
  "$root"/x64.c "$root"/pe.c "$root"/object.c "$root"/object_build.c
  "$root"/object_link.c "$root"/object_materialize.c "$root"/conformance.c
  "$root"/nova/run_host.c "$root"/nova/runtime_v2.c "$root"/nova/pe_oracle.c
)
OBJ=()
for lib in "${LIBS[@]}"; do
  [ -f "$lib" ] || { echo "A5_ADV_ABORT missing library $lib"; exit 2; }
  obj="$BUILD/objects/$(basename "${lib%.c}").o"
  if ! gcc -std=c11 -Wall -Wextra -Werror -O1 -g \
      -fsanitize=address,undefined -fno-omit-frame-pointer \
      -I"$root" -c "$lib" -o "$obj" 2>"$obj.cc.log"; then
    echo "A5_ADV_CC_FAIL $(basename "$lib")"
    sed -n '1,25p' "$obj.cc.log"
    exit 1
  fi
  OBJ+=("$obj")
done
echo "LIBS_OK ${#OBJ[@]}"

PROBE="$REPO/legacy/tools/coldproof/a5_adversarial_campaign.c"
if ! gcc -std=c11 -Wall -Wextra -Werror -O1 -g \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$root" "${OBJ[@]}" "$PROBE" \
    -o "$BUILD/campaign/a5_adversarial" 2>"$BUILD/campaign/cc.log"; then
  echo "A5_ADV_CC_FAIL campaign"
  sed -n '1,40p' "$BUILD/campaign/cc.log"
  exit 1
fi

# The revision the run answers for.  A campaign that does not name it is a
# number about an unbounded set.
SRCDIR="$REPO/compiler/nova"
NOVA=(
  "$SRCDIR/tests/macro-expand-entry.nova" "$SRCDIR/macro_expand.nova"
  "$SRCDIR/constant_eval.nova" "$SRCDIR/parser.nova" "$SRCDIR/ast.nova"
  "$SRCDIR/lexer.nova"
)
echo "A5_ADV_SOURCE_REVISION dir=$SRCDIR"
sha256sum "${NOVA[@]}"

run_probe() {   # run_probe <tree-root> ; prints the whole record
  ( cd "$1" && ASAN_OPTIONS=detect_leaks=0 "$BUILD/campaign/a5_adversarial" 2>&1 )
}

banner=$(basename "$SRCDIR")
if [ ! -f "$BUILD/$banner" ]; then :; fi

echo
echo "=================== BASELINE (shipped tree) ==================="
run_probe "$REPO" | tee "$BUILD/campaign/baseline.log"
base_rc=${PIPESTATUS[0]}
tail -1 "$BUILD/campaign/baseline.log"

# ---- the coldness control: the sentinel is still the only thing we made ----
echo
echo "COLD_PROOF dir=$BUILD sentinel=$sentinel"
if [ ! -f "$sentinel" ]; then
  echo "A5_ADV_ABORT the sentinel is gone; the run was not in the directory named."
  exit 2
fi

if [ "$MUTATE" != "1" ]; then
  echo "COLD_PROOF ok"
  exit "$base_rc"
fi

# ------------------------------- the red proofs ---------------------------
SCRATCH="$BUILD/scratch"
prep() {
  rm -rf "$SCRATCH"
  mkdir -p "$SCRATCH/toolchain" "$SCRATCH/compiler/c/nova"
  cp -r "$SRCDIR" "$SCRATCH/compiler/nova"
  cp "$root/nova/tests_ntasm_macro_expand.c" \
     "$SCRATCH/compiler/c/nova/"
}
mut() {   # mut <name> <python-or-sed body applied to the scratch tree>
  prep
  ( cd "$SCRATCH" && eval "$2" )
  echo
  echo "########## $1 ##########"
  run_probe "$SCRATCH" | tee "$BUILD/campaign/$3.log" \
    | grep -E "^FAIL|A5_ADVERSARIAL conjuncts|^[A-Z_]+ (HYGIENE|IO_CASE|IO_CTL|PROV_SPAN|DET |BND located)" \
    | head -12
  # A mutation that leaves the campaign green is a finding, not a pass.
  if grep -q "failures=0" "$BUILD/campaign/$3.log"; then
    echo "MUTATION_SURVIVED $1 -- the arm does not discriminate; this is a"
    echo "  finding about the campaign and is reported, not hidden."
  else
    echo "MUTATION_BIT $1"
  fi
}

mut "M1 the __ntm\$ mark word" \
    "sed -i 's/0x0000246d746e5f5f/0x0000246d746e5e5f/' compiler/nova/macros/macro_expand.nova" \
    m1
mut "M2 the three env.folding=true writers" \
    "sed -i 's/env.folding=true;/env.folding=false;/g' compiler/nova/macros/macro_expand.nova" \
    m2
mut "M3 the 381 span raises report a constant position" \
    "sed -i 's/return fail(env,381,1,nline(env,name),ncolumn(env,name));/return fail(env,381,1,1,1);/g' compiler/nova/macros/macro_expand.nova" \
    m3

# M4 perturbs the PROBE, not the product: the determinism control has to be
# shown capable of failing, and the only way to show that is to neuter it once.
echo
echo "########## M4 the determinism control, neutered in the PROBE ##########"
echo "     (this perturbs the instrument on purpose: a control that cannot"
echo "      fail is a posture, and this is what shows it can)"
sed "s/hit\[strlen(\"return \$v+\") - 1\] = '2';/hit = NULL;/" \
    "$PROBE" >"$BUILD/campaign/m4_probe.c"
if gcc -std=c11 -Wall -Wextra -Werror -O1 -g \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$root" "${OBJ[@]}" "$BUILD/campaign/m4_probe.c" \
    -o "$BUILD/campaign/a5_m4" 2>"$BUILD/campaign/m4.cc.log"; then
  prep
  ( cd "$SCRATCH" && ASAN_OPTIONS=detect_leaks=0 \
      "$BUILD/campaign/a5_m4" 2>&1 ) | tee "$BUILD/campaign/m4.log" \
    | grep -E "^FAIL|A5_ADVERSARIAL conjuncts|^DET " | head -8
  if grep -q "failures=0" "$BUILD/campaign/m4.log"; then
    echo "MUTATION_SURVIVED M4 -- the determinism control cannot fail"
  else
    echo "MUTATION_BIT M4"
  fi
else
  echo "M4 probe did not compile; the sed did not match. Not a survival."
  sed -n '1,20p' "$BUILD/campaign/m4.cc.log"
fi

echo
echo "RESTORE: the scratch tree is discarded; the repository was only READ."
rm -rf "$SCRATCH"
echo "COLD_PROOF ok"
exit "$base_rc"