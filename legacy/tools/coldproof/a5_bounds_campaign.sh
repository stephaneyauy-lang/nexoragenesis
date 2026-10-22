#!/usr/bin/env bash
# A5_CAMPAIGN_BOUNDS -- driver for the seven compilation bounds and the
# diagnostic-text gap.  Criterion A5, wave 21.
#
# WHY A SCRIPT AND NOT A GATE HARNESS.  ngbuild.sh turns any tests_ntasm_*.c
# absent from the GATES list at ngbuild.sh:210 into UNREGISTERED_HARNESS and a
# red for the whole suite, and that list is a shared line range several lots in
# this wave are already near.  This script adds no inventory and edits no
# shared line: it compiles its own probe in its OWN build directory.
#
# THE COLDNESS BAR.  coldsuite.sh's argument is not decorative: given a
# relative path this tree once built happily in a real but DIFFERENT empty
# directory where the sentinel and the artefacts agreed and printed COLD_PROOF
# ok.  So the build directory must be ABSOLUTE and must resolve to itself, and
# it must hold ZERO FILES before the run -- not merely exist, because a
# directory can exist and be empty, and `test -d` passes either way.  The
# assertion is about the artefact and never about the place the artefact would
# be.
#
# TWO CONTROLS, AND THEY ANSWER TWO SEPARATE QUESTIONS.  A void run and a wrong
# mutation look identical from the outside: both produce a number.
#
#   1. WAS THE PERTURBATION THE ONE I MEANT?  Established by controls that must
#      PASS: the copy differs from the tree by exactly one term, and the
#      mutated run's arena accounting DIFFERS from the baseline's taken in this
#      same build directory.  A copy that was never compiled in produces a log
#      identical to the baseline's, and identical is what this catches.
#   2. WAS THE RUN DOING WHAT I ASKED?  Established by a control that must
#      FAIL: a Nova syntax error in a copy, which must make the run refuse to
#      build an image and exit non-zero.  It is a check of the RIG, not of the
#      product.  If it comes back green, the run measured the shipped tree and
#      every number in it is void -- declared void by this script, not diagnosed
#      by the reader, because the reader is the part that is primed.
#
# THE PERTURBED COPY.  The mutation runs against a COPY in this build
# directory.  The tree is not modified, so there is no restore that can lie and
# no sibling can be holding a baseline that just moved.
#
# usage: a5_bounds_campaign.sh <builddir> [--mutate]
set -uo pipefail

REPO=${NG_REPO:-/mnt/d/Projets/Racine-C/NexoraGenesis}
BUILD="${1:-}"
MUTATE=0
[ "${2:-}" = "--mutate" ] && MUTATE=1

case "$BUILD" in
  /*) ;;
  *) echo "A5_ABORT the build directory must be ABSOLUTE; got '$BUILD'."
     exit 2 ;;
esac
case "$BUILD" in
  *[!a-zA-Z0-9._/-]*)
    echo "A5_ABORT the build directory has a character a path translation can"
    echo "  eat, so COLD_PROOF would be true of a place nobody named."
    exit 2 ;;
esac

root="$REPO/compiler/c"
mkdir -p "$BUILD" || exit 2
resolved=$(cd "$BUILD" && pwd -P) || exit 2
if [ "$resolved" != "$BUILD" ]; then
  echo "A5_ABORT '$BUILD' resolves to '$resolved'; refusing to build in a"
  echo "  directory nobody named."
  exit 2
fi
# THE COUNT, not the container.  A directory can exist and hold nothing, and
# `test -d` would call that cold.
files_before=$(find "$BUILD" -type f | wc -l)
if [ "$files_before" != "0" ]; then
  echo "A5_ABORT $BUILD already holds $files_before files; a cold directory is"
  echo "  one that has never held a build."
  exit 2
fi
sentinel="$BUILD/.sentinel-$$"
: >"$sentinel" || exit 2
mkdir -p "$BUILD/objects" "$BUILD/campaign" || exit 2

LIBS=(
  "$root"/nova.c "$root"/ntasm.c "$root"/frontend.c "$root"/codegen.c
  "$root"/x64.c "$root"/pe.c "$root"/object.c "$root"/object_build.c
  "$root"/object_link.c "$root"/object_materialize.c "$root"/conformance.c
  "$root"/nova/run_host.c "$root"/nova/runtime_v2.c "$root"/nova/pe_oracle.c
)
OBJ=()
for lib in "${LIBS[@]}"; do
  [ -f "$lib" ] || { echo "A5_ABORT missing library $lib"; exit 2; }
  obj="$BUILD/objects/$(basename "${lib%.c}").o"
  if ! gcc -std=c11 -Wall -Wextra -Werror -O1 -g \
      -fsanitize=address,undefined -fno-omit-frame-pointer \
      -I"$root" -c "$lib" -o "$obj" 2>"$obj.cc.log"; then
    echo "A5_CC_FAIL $(basename "$lib")"
    sed -n '1,25p' "$obj.cc.log"
    exit 1
  fi
  OBJ+=("$obj")
done

if ! gcc -std=c11 -Wall -Wextra -Werror -O1 -g \
    -fsanitize=address,undefined -fno-omit-frame-pointer \
    -I"$root" "${OBJ[@]}" "$REPO/legacy/tools/coldproof/a5_bounds_campaign.c" \
    -o "$BUILD/campaign/a5_bounds" 2>"$BUILD/campaign/cc.log"; then
  echo "A5_CC_FAIL campaign"
  sed -n '1,40p' "$BUILD/campaign/cc.log"
  exit 1
fi

SRCDIR="$REPO/compiler/nova"
NOVA=(
  "$SRCDIR/tests/macro-expand-entry.nova" "$SRCDIR/macro_expand.nova"
  "$SRCDIR/constant_eval.nova" "$SRCDIR/parser.nova" "$SRCDIR/ast.nova"
  "$SRCDIR/lexer.nova"
)
# The revision the run answers for.  A campaign that does not name it is a
# number about an unbounded set.
echo "A5_SOURCE_REVISION dir=$SRCDIR"
sha256sum "${NOVA[@]}"

run_probe() {   # run_probe <logfile> [dir]
  local log="$1"; shift
  ( cd "$REPO" && ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
      UBSAN_OPTIONS=halt_on_error=1 "$BUILD/campaign/a5_bounds" "$@" ) \
      >"$log" 2>&1
}

copy_six() {     # copy_six <dir>
  mkdir -p "$1/tests" || exit 2
  cp "$SRCDIR/tests/macro-expand-entry.nova" "$1/tests/" || exit 2
  local f
  for f in macro_expand.nova constant_eval.nova parser.nova ast.nova lexer.nova; do
    cp "$SRCDIR/$f" "$1/$f" || exit 2
  done
}

# --------------------------------------------------------------------------
# THE BASELINE, FIRST AND IN THIS BUILD DIRECTORY, because the mutation arm's
# must-PASS control compares against it and a baseline taken elsewhere would be
# a comparison across machines.
# --------------------------------------------------------------------------
LOG="$BUILD/campaign/baseline.log"
# NO argument: the probe then reads the six paths the macro_expand gate reads,
# relative to the repository root.  "The baseline" is the tree as the product
# reads it, and passing a directory would be a different set of paths for the
# same sources.
run_probe "$LOG"
status=$?

if [ "$MUTATE" = 1 ]; then
  # --------------------------------------------------------------------------
  # THE MUTATION.  A probe that returned green is recorded, not buried.
  #
  # max_arena() is the budget that shadows hard_node_cap and ast_nodes.  Raise
  # it and the arena stops answering, so the node cap becomes reachable and any
  # campaign that believes the arena binds first MUST react.  The A5 row keeps
  # the same shape one level down: relaxing only the arena term of an assertion
  # left the live-node term and it stayed green.
  # --------------------------------------------------------------------------
  COPY="$BUILD/nova-mutated"
  copy_six "$COPY"
  sed -i 's/^fn max_arena()->u64 { return 16777216; }$/fn max_arena()->u64 { return 167772160; }/' \
    "$COPY/macro_expand.nova" || exit 2
  changed=$(diff "$SRCDIR/macro_expand.nova" "$COPY/macro_expand.nova" \
            | grep -c '^[<>]' || true)
  echo "A5_MUTATION max_arena 16777216 -> 167772160 changed_lines=$changed"

  # ---- CONTROL 1a, must PASS: the perturbation is the one that was meant.
  if [ "$changed" != "2" ]; then
    echo "A5_ABORT the mutation changed $changed lines, not the 2 of a one-term"
    echo "  replacement. A void run and a wrong mutation look identical from"
    echo "  the outside, so the two questions are answered separately."
    exit 2
  fi
  echo "A5_CONTROL_1a_PASSES the copy differs from the tree by exactly one term"

  MLOG="$BUILD/campaign/mutated.log"
  run_probe "$MLOG" "$COPY"
  m1=$?
  echo "A5_MUTATION_RESULT M1=max_arena_raised status=$m1"

  # ---- WHAT M1 ACTUALLY SHOWS, stated rather than assumed.
  #
  # M1 is the mutation the A5 row already records one level down: relax ONLY
  # the arena term and see whether the probe notices.  It does not, and the
  # reason is a property of the PROBE and not of the product: every body this
  # campaign composes pins arena_bytes=16777216 through a comptime block, and
  # a comptime block may only LOWER a budget, so the declared maximum is
  # never consulted at all.  Raising max_arena cannot move a number the probe
  # does not read.
  #
  # A green mutant here is NOT a finding about the product -- it is a
  # finding about the campaign, and that is the whole reason it is run and
  # the whole reason it is reported.  So the run is NOT declared void: it is
  # declared to have SURVIVED, and a second mutation is run that the probe
  # can see.
  if diff -q \
      <(grep -aE '^(ARENA_NODE|ARENA_CEILING|ARITHMETIC_SUMMARY)' "$MLOG") \
      <(grep -aE '^(ARENA_NODE|ARENA_CEILING|ARITHMETIC_SUMMARY)' \
               "$BUILD/campaign/baseline.log") >/dev/null 2>&1; then
    echo "A5_MUTATION_SURVIVED M1 status=$m1 the_arena_accounting_is_"
    echo "  BYTE_IDENTICAL_to_the_baseline"
    echo "  why=every_body_this_campaign_composes_pins_arena_bytes_through_a_"
    echo "  comptime_block_and_a_comptime_block_may_only_LOWER_a_budget_so_the_"
    echo "  declared_maximum_is_never_consulted"
    echo "  this_is_a_finding_about_THE_CAMPAIGN_not_about_the_product"
    M1_SURVIVED=yes
  else
    echo "A5_MUTATION_BIT M1 status=$m1 the_arena_accounting_MOVED:"
    diff <(grep -aE '^(ARENA_NODE|ARENA_CEILING|ARITHMETIC_SUMMARY)' \
             "$BUILD/campaign/baseline.log") \
         <(grep -aE '^(ARENA_NODE|ARENA_CEILING|ARITHMETIC_SUMMARY)' "$MLOG") \
      | sed 's/^/  /' | head -20
    M1_SURVIVED=no
  fi

  # ---- M2, THE MUTATION THE PROBE CAN SEE.  node_bytes is the constant every
  # arena figure in this campaign is derived from, so relaxing it moves the
  # arithmetic the assertions are about.  It is the same shape as M1 -- one
  # term, nothing else -- with the difference that this one is REACHABLE from
  # the product's own declaration rather than shadowed by the caller's
  # comptime block, and that difference is the campaign's own blind spot
  # measured from the inside.
  COPY2="$BUILD/nova-mutated-2"
  copy_six "$COPY2"
  sed -i 's/^fn node_bytes()->u64 { return 96; }$/fn node_bytes()->u64 { return 48; }/' \
    "$COPY2/macro_expand.nova" || exit 2
  changed2=$(diff "$SRCDIR/macro_expand.nova" "$COPY2/macro_expand.nova" \
             | grep -c '^[<>]' || true)
  echo "A5_MUTATION M2=node_bytes 96 -> 48 changed_lines=$changed2"
  if [ "$changed2" != "2" ]; then
    echo "A5_ABORT the second mutation changed $changed2 lines, not the 2 of a"
    echo "  one-term replacement."
    exit 2
  fi
  MLOG2="$BUILD/campaign/mutated-2.log"
  run_probe "$MLOG2" "$COPY2"
  status=$?
  LOG="$MLOG2"
  if diff -q \
      <(grep -aE '^(ARENA_NODE|ARENA_CEILING|ARITHMETIC_SUMMARY)' "$LOG") \
      <(grep -aE '^(ARENA_NODE|ARENA_CEILING|ARITHMETIC_SUMMARY)' \
               "$BUILD/campaign/baseline.log") >/dev/null 2>&1; then
    echo "A5_ABORT M2's arena lines are IDENTICAL to the baseline's. M2 was not"
    echo "  compiled in either, so BOTH mutations are void and this campaign"
    echo "  measures the shipped tree."
    exit 2
  fi
  echo "A5_CONTROL_1b_PASSES M2 is visible in the results, so the rig compiles"
  echo "  the directory it is given"
  echo "A5_MUTATION_RESULT M2=node_bytes_halved status=$status BIT=yes"
  echo "A5_MUTATION_DIFF M2, baseline against mutation:"
  diff <(grep -aE '^(ARENA_NODE|ARENA_CEILING|ARITHMETIC_SUMMARY)' \
           "$BUILD/campaign/baseline.log") \
       <(grep -aE '^(ARENA_NODE|ARENA_CEILING|ARITHMETIC_SUMMARY)' "$LOG") \
    | sed 's/^/  /' | head -20
  echo "A5_MUTATION_SUMMARY M1_max_arena_raised=$M1_SURVIVED M2_node_bytes_"
  echo "  halved=bit  the_campaign_is_blind_to_a_budget_the_caller_pins_and_"
  echo "  sensitive_to_one_the_caller_does_not"

  # ---- CONTROL 2, must FAIL: the run did what it was asked.
  BROKEN="$BUILD/nova-must-fail"
  copy_six "$BROKEN"
  sed -i 's/^fn node_bytes()->u64 { return 96; }$/fn node_bytes()->u64 { return 96;/' \
    "$BROKEN/macro_expand.nova" || exit 2
  BRCLOG="$BUILD/campaign/must-fail.log"
  run_probe "$BRCLOG" "$BROKEN"
  brc=$?
  echo "A5_CONTROL_2_MUST_FAIL a_nova_syntax_error_status=$brc"
  if [ "$brc" = 0 ]; then
    echo "A5_ABORT the control that must fail returned GREEN, which is impossible."
    echo "  This run did not compile the directory it was pointed at; the"
    echo "  mutation's result above is about the shipped tree and is VOID."
    exit 2
  fi
  echo "A5_CONTROL_2_PASSES the rig compiles the directory it is given"
fi

echo "A5_RUN status=$status log=$LOG"
grep -aE '^(BOUND|BOUND_DECL|BOUND_ARITHMETIC|ARITHMETIC_|ARENA_|NAME_|A5_TEXT|A5_DIAGNOSTIC|A5_CAMPAIGN|FAIL)' \
  "$LOG" || true

# Coldness, proved rather than asserted: the directory is still here and every
# artefact postdates the sentinel.  Anything else is a sample, not a
# measurement, whatever the banner says.
cold=ok
for art in "$BUILD/campaign/a5_bounds" "$LOG"; do
  [ -f "$art" ] || cold=bad
  [ "$art" -nt "$sentinel" ] || cold=bad
done
[ -d "$BUILD" ] || cold=bad
files_after=$(find "$BUILD" -type f | wc -l)
echo "COLD_PROOF $cold dir=$BUILD files_before=$files_before files_after=$files_after"
echo "A5_DONE status=$status cold=$cold mutate=$MUTATE"
exit $status
