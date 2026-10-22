#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# ASSEMBLED, NOT THE ORIGINAL. Read this before trusting a number from it.
#
# The 748-line driver that stood at 10:41 today was destroyed by a
# symlink-following write, and a second destruction followed from a job still
# running a deleted harness. Neither is recoverable by re-running anything.
#
# Assembled from three real sources, each verified:
#   BASE     ng23u2build/ngbuild-rootgate.sh  520L, 2026-09-30 05:17 -- five
#            functions, the gate loop, STALE_OBJECTS, ROOT_LIBS, NOVA_LIBS
#   ARRAYS   W26DriverRecovery/ARRAYS-124.txt  95 + 1 + 28 = 124, machine-checked
#   BLOCKS   the two census comment blocks, two readers compared byte for byte
#
# It is SHORT of the original. What the original held that this does not, every
# element tagged, is specified at
#   out/c-bootstrap/nova/evidence/W26Restore/SPECIFICATION.md
# and the incident record, including what is ABSENT and NOT reconstructed, is at
#   out/c-bootstrap/nova/evidence/W26Restore/INCIDENT-concurrent-writes.md
#
# It RUNS. It is not a refusal, and it is not the original.
# ---------------------------------------------------------------------------

# --------------------------------------------------------------------------
# ================================ WHAT THESE GATES CAN AND CANNOT PROVE.
#
# A census of the 124 gates below (95 GATES + 1 NOVA_GATES + 28 ROOT_GATES)
# classified each one by the SHAPE of its evidence:
#   A  no byte evidence .............. 72    evidence terminates in status words
#   C1 NOVA vs C, pipeline ........... 9
#   C2 NOVA vs C, object/PE ......... 12
#   C3 NOVA vs C, encoder .......... 24
#   C4 bytes, no independent side ... 6    <-- READ THIS ONE, see below
#   C5 NOVA vs compiled oracle ...... 1
# A gate whose evidence terminates in a status word cannot demonstrate an
# end-to-end property, whatever its check count says.
#
# 52 IS TRUE AND WRONG IN THE SAME BREATH, which is the most dangerous shape
# a number has. 52 gates do touch bytes -- but only 46 of them (C1+C2+C3+C5)
# compare those bytes against an INDEPENDENT other side. The other 6 are C4:
# they have bytes and no independent second producer, so a reader who reads
# 52 as "52 gates compare bytes against a reference" is wrong about six of
# them. Quote 46, or quote C1..C5, never the sum.
#
# THE BINDING, and it is to the CLASSIFICATION, not to the bytes:
#   class digest b1302e448844072f  over (name + " " + class letter) of all 124
# Re-derive it with a second party, no arguments needed:
#   python3 out/c-bootstrap/nova/W26Exposure/derive_population.py
# That script prints the class digest, compares it against the value above,
# and also prints the tally, so a reader never has to take this comment's word
# for any number in it. It is the address of the re-deriver; a digest with no
# address is a rumour.
#
# THE CLASS DIGEST REPRODUCED EXACTLY, FIRST TRY, FROM THE PROSE
# SERIALISATION, WITH NO PERTURBATION. The instrument that answers "which CLAIM
# are you making" is current; the one that answers "which BYTES did you read"
# is not. The source digest this block used to cite (6fdb102703f969d9) now
# computes to b8f5ae127606fe7d over the same 124 -- a gate was edited after
# the census. A stale BOUND digest is a loud failure silenced by the binding
# itself: the reader is handed a hex string to trust and no way to check it,
# so it is strictly worse than the unbound count it replaced.
#
# WHY BIND TO CLASSES AND NOT TO BYTES, which is the point and not a
# convenience. A gate can be repaired without changing any classification, so a
# source digest moves on edits IRRELEVANT to this claim -- and a reader
# checking one would be checking the wrong thing, then doubting a claim that
# never moved.
#
# WHAT THE CLASS DIGEST DOES NOT ESTABLISH, stated as its own defect: it CANNOT
# DETECT A GATE BEING REPAIRED. Every byte of a gate may change and the digest
# will not move, because what it binds is the claim, not the text. That is a
# deliberate trade -- a binding that tracks the claim survives the ordinary
# edit, which is the edit this census is about -- and it is a trade, not an
# oversight. A reader who needs to know whether the BYTES moved must run the
# script and read its SOURCE digest line, which is reported, not asserted here.
#
# SEEN DIRECTLY, twice, on 30 September 2026, minutes apart, with the tree
# being edited underneath: the SOURCE digest moved twice (6fdb102703f969d9,
# then b8f5ae127606fe7d, then 101935c0aa3e22f3) while the CLASS digest did
# not move at all. Three different byte-states, one claim, unchanged. That is
# the whole argument for this binding, and it was not predicted -- it was
# observed by running the command twice.
#
# THE EXTRACTION RULE IS PART OF THE DIGEST, and the termination rule is where
# a re-deriver will go wrong. An array is read as `^NAME=\((.*?)\)` over the
# driver text, non-greedy, so it ends at the FIRST ')' CHARACTER -- on a line
# of its own (GATES), at the end of the opening line (NOVA_GATES), or at the
# end of a token line (ROOT_GATES). A rule that instead looks for a line
# BEGINNING with ')' bleeds past the two latter arrays into the *_NOT_A_GATE
# blocks and returns a DIFFERENT POPULATION -- which is a different claim, not
# a different spelling of this one. A rule that is not written down is not a
# rule; it is one implementer's memory, and the next implementer will produce
# a different digest that looks exactly as authoritative as this one.
#
# WHAT THE CLASSES MEAN.
#   byte-evidenced  -- 46 gates, classes C1 C2 C3 C5: the gate compares
#                      produced bytes against an INDEPENDENT reference, so a
#                      wrong entry is attributable to the producers alone.
#   status-word     -- the gate asserts that a rule is implemented. It
#                      answers "is the rule implemented?" correctly and
#                      cannot answer "does it survive a whole program?".
#   Three comparison ROLES, which are not a ranking:
#     producer-vs-reference  a WITNESS. Two independent producers; a
#                            disagreement is attributable to them.
#     same-side, two routes  a ROUTE CHECK. Both sides come from the same
#                            producer, so a wrong entry that breaks both
#                            routes the same way survives it.
#     bytes, no second side   the 6 C4 gates. Bytes are compared, but the
#                            other side is not an independent producer, so
#                            the comparison is not yet a witness. Inside the
#                            52, correctly outside the 46.
#     encoder-vs-encoder     BETWEEN the two: two encoders compared, no
#                            third reference. Whether that is a witness is
#                            UNESTABLISHED, not assumed here.
#
# THIS IS NOT A DEFECT LIST AND NOT A COVERAGE NUMBER. A status-word gate
# is not a worse gate; it is a gate answering a different question, and
# deleting one because it lacks byte evidence removes a real check. Read
# "72 of 124" as a statement about gate SHAPE, never as "58% of the project
# is untested" -- that reading is wrong, and this block exists to stop it.
# A comparison is a witness only if (a) no producer on one side can observe
# the other, (b) the result is attributable to the two producers alone
# (never paraphrased as "nobody introduced the disagreement" -- a RED
# witness IS a disagreement nobody introduced), and (c) the stated scope is
# a region a NAMED wrong entry cannot produce.
#
# TWO DISCRIMINATORS WERE TRIED AND REJECTED. A future lot will otherwise
# retry them; they are the most reusable result of the census. Both were run
# over the population bound above, and their NUMBERS ARE NOT RESULTS about
# this tree -- they are outputs of instruments known to be wrong, quoted so
# that nobody re-derives them and mistakes a rejected number for a finding.
#   D1 "which APIs does the gate call" -- gave 67 byte-observing gates.
#      Refuted by reading nxo_link_pe by hand: it DOES compare Nova PE bytes
#      against a C-oracle PE, and the regex missed the idiom. D1 measures
#      vocabulary, not evidence.
#   D2 "memcmp is present" -- gave 56 P / 68 S. Refuted by `registry`, which
#      has 23 memcmps and is a DOCUMENT gate, every one a string compare over
#      a markdown file. A memcmp over text is not evidence about emitted
#      bytes.
# The accepted discriminator parses each gate's `typedef struct{...}Run;`
# for a uint8_t/NtBuffer member instead of guessing at container spellings,
# then asks whether the OTHER side of the byte comparison is an independent
# producer. Two instruments keyed on the wrong signal is the standing risk
# here: an exit code is not self-validating, and neither is an API name.

# --------------------------------------------------------------------------
# THE SIZE, measured before anything was written, and BOUND TO A DIGEST that
# a second party can recompute. A bare count here is worse than no count: this
# block's whole argument is that a file nobody ever ran is a finding, and a
# number that has quietly stopped describing the directory is a finding too.
# Re-derive both digests from the repo root with:
#   ls -1 compiler/c/*.c | LC_ALL=C sort | md5sum
#   ( cd compiler/c && for f in $(ls -1 *.c | LC_ALL=C sort); do
#       printf '%s %s\n' "$(md5sum "$f" | cut -d' ' -f1)" "$f"; done | md5sum )
#   name-list 33bb5779c27d1a05908127862f8169b5
#   name+md5  182d4eb7aa799b5c6a1407703791b5db
# REGION VERIFIED, and only this region: the direct *.c children of $root.
# A subdirectory (nova/, stubs/, uefi-test/, bench/) is NOT in this census.
#
# AS WRITTEN IT SAID 52 .c files and 39 with a main. Re-measured 30 September
# 2026, the same region gives 51 .c files (name-list digest above) and 38 whose
# text matches a bare `main(` at a token boundary. So the 52 and the 39 are
# STALE, by one file and one main, and they were unbound, which is why nothing
# said so. The class breakdown below (28 self-contained gates, 6 argument-taking
# drivers, 4 compile-then-fail-to-link, 1 scratch) is NOT re-derived here and
# should be read as measured-then; the 28 is the ROOT_GATES array below, which
# is a declaration this script checks in both directions and does not rest on.
# An OPEN QUESTION, not a result: whether the 38 still split 28/6/4/1, or
# 27/6/4/1, depends on which file left and must be settled by running the
# files, which is the rule the not_a_gate reasons below already record.
#
# HISTORIC FORM, kept so the drift is visible rather than silently overwritten:
# 52 .c files sat directly under $root, 39 defining a C main. Of those 39: 28
# were self-contained gates that build and pass, 6 were drivers whose main takes
# a source-file argument, 4 compiled and then failed to link, 1 was another
# lot's scratch file. NOT ONE of the 39 was named by a compiler-invoking line
# anywhere in the tree -- there were four such lines outside out/ and
# evidence/, and none named a file at this level. The three occurrences of
# tests.c in scripts/ntbuild.sh are refusal FIXTURES (`check
# tests/c/ntasm/tests.c` expecting the ungranted-quarantine-source
# refusal), which is the opposite of a build.
# Nexora Genesis - build + run Nova NTASM gates (WSL gcc, ASan+UBSan).
# Run from anywhere; gates themselves must be launched with cwd = repo root.
set -euo pipefail

# A RUN THAT DIED MUST SAY SO. `GATES_DONE` is printed only on the normal path, so a
# driver killed mid-loop leaves a log whose last lines are green banners and no verdict
# — and a reader who greps the tail concludes the suite passed. That is what happened
# tonight: reported as `line 885: one: command not found`, `guest_exit=127`, and a tail
# that looked green. Four later runs were clean, so the cause was intermittent and the
# symptom was constant: absent verdict read as success.
#
# The marker is unconditional and names the line, so it is falsifiable against the file.
# `_NG_TERMINATED` is set on the normal path immediately before `exit $fail`, so a
# deliberate non-zero exit (gates red) is NOT reported as a death — only a path that
# never reached its own ending is. `set -e` aborts anywhere; this is what says where.
_NG_TERMINATED=0
trap '_rc=$?; if [ "${_NG_TERMINATED:-0}" = 0 ]; then printf "%s\n" "GATES_DID_NOT_TERMINATE rc=$_rc -- no verdict was printed, so this run is NOT a pass" >&2; fi' EXIT
REPO=${NG_REPO:-/mnt/d/Projets/Racine-C/NexoraGenesis}
# Durable by default, and that is the point: every claim in this project
# rests on a run log, and /tmp is reclaimed. A lot had to re-derive a
# baseline from lines it had captured by hand, while the prose
# summarising that log survived -- the claim kept, the thing that would
# let a reader check it discarded. An explicit NG_BUILD still wins.
#
# UNIQUE PER RUN, and that second half matters as much as the first: a
# fixed durable path is durable AND shared, and two lots writing into it
# interleave their logs -- a sibling reported two contradictory registry
# banners in one file and had to say which was hers. The complaint was
# that /tmp RECLAIMS; a path that is merely SHARED has the same failure
# with a longer life. Durable and unique, or neither.
BUILD=${NG_BUILD:-$REPO/out/c-bootstrap/builds/ngbuild-$(date +%H%M%S)-$$}
root="$REPO/compiler/c"
mkdir -p "$BUILD"

# THE RED REGISTER -- a count and a list, not a boolean.
#
# `fail=1` was set at every site below and INCREMENTED at none of them, so the
# terminator could say only THAT something was red. Measured on this tree before
# this block: `GATES_DONE fail=1` with `RUN_FAIL registry`, `RUN_FAIL corpus_e2e`
# and `MODULES_EDITED_DURING_RUN` in the same log, and the line said nothing
# about which, or how many. Lot 53 recorded the names by hand for exactly that
# reason. A zero without a denominator is an instrument failure, and `fail=1`
# is the same shape: a boolean standing where a quantity is read.
#
# THREE CLASSES, and the third is the point. A run's GUARD precedes its
# symptoms by construction: STALE_OBJECTS and MODULES_EDITED_DURING_RUN do not
# assert that a gate is broken, they assert that a file moved under a run that
# was reading it, which authorises exactly one conclusion -- "nothing moved
# during the read" -- and forbids every other one. Counting a guard as a gate
# failure would report a timing event as a defect, and dropping it would report
# an untrustworthy run as trustworthy, so it is counted, named, and labelled.
#
#   GATE   a gate, or a declaration about one, is red
#   RAIL   a non-gate instrument refused, or is absent (census, terminator
#          census, delivery verdicts, the S0 fixed point, the build rails)
#   GUARD  a run-race guard fired
#   INTERRUPTED  a gate exited non-zero and printed NO banner, so it never
#          reached its summary line. Not a red check: a gate that did not
#          finish. See run_harness for the measurement that separates it.
#
# A FILE, not a variable, because several of the sites below sit inside `while
# read` loops fed by process substitution and inside functions, and a counter
# incremented in one of those does not always reach the caller. $BUILD is
# unique per run (see above), so this list cannot be shared with a sibling lot.
RED_LIST="$BUILD/.red_gates"
: >"$RED_LIST"
red() { # $1 = class (GATE|RAIL|GUARD|INTERRUPTED), $2 = the name that is red
  printf '%s\t%s\n' "$1" "$2" >>"$RED_LIST"
  fail=1
}

LIBS=(
  "$root"/nova.c "$root"/ntasm.c "$root"/frontend.c "$root"/codegen.c
  "$root"/x64.c "$root"/pe.c "$root"/object.c "$root"/object_build.c
  "$root"/object_link.c "$root"/object_materialize.c "$root"/conformance.c
  "$root"/nova/run_host.c "$root"/nova/runtime_v2.c "$root"/nova/pe_oracle.c "$root"/nova/machine_driver.c
)


# ================================ the other half of the run-race guard.
#
# LIBS above is the set of files whose OBJECTS are rebuilt here. It is not the
# set of files a gate READS. A gate is a program that links the objects and then
# opens text by RELATIVE PATH from the repository root: measured on 30 September
# 2026, 156 `.nova` modules under compiler/nova/ are opened that way, by
# 80-odd harnesses, and none of them is in LIBS. So the run-race guard below --
# which is the only thing standing between a run's answers and a tree that
# moved underneath it -- was watching fourteen `.c` paths and nothing else.
#
# THAT WAS NOT A THEORETICAL HOLE. It was watched failing:
# compiler/nova/backend/x64/x64_lower_nxo.nova went 3f67cbe1 -> be94a832 across the
# boundary of one run (13:25:26 -> 13:25:50) and STALE_OBJECTS stayed silent,
# because the file it would have had to watch is not one it watched. A run's
# answers are PROVEN by verify_identity to come from the bytes this process
# LOADED; they were only ASSUMED to come from bytes that were stable for the
# whole run. The assumption failed inside one run, and it failed to be reported.
#
# THE DECLARATION IS TWO DIRECTORIES AND NOT 156 LINES, which is a departure
# from the form asked for and is deliberate. An enumerated list of 156 paths is
# a THIRD convention that can drift: a new module lands, nothing is red, and
# the guard has silently shrunk. A directory is a statement about a whole tree
# and cannot go stale the same way. This is not a new idea in this file: the
# declaration rails for nova/*.c and $root/*.c already invert the
# responsibility the same way, for the same reason, and the reasoning is written
# out at "WHAT THIS DOES INSTEAD -- invert the responsibility" above.
# RUNTIME_MODULES_SNAPSHOT then turns the declaration into an exact file list at
# the START of the run, so what was watched is printed in the log rather than
# inferred.
#
# REASON, one line, and it is the same line for both entries because there is
# only one reason: "loaded by a gate at run time, by relative path, so an edit
# during the run changes the answer without changing any object." It is written
# once here rather than twice-per-file because 156 copies of one sentence is a
# comment that will drift out of step with the sentence it repeats.
#
# NOT WATCHED, and this is the part that is worth more than the mechanism: the
# published residue is at the end of this file under RUN_RACE_GUARD_LIMITS,
# which names what a reader may NOT conclude from a green run. An instrument
# that says only what it does is less useful than one that says what it does
# not, because the second is the only one a reader can reason with.
RUNTIME_MODULES=(
  "$REPO/compiler/nova"          # the .nova modules the gates load at run time; ntir_inspect.nova took this to 59
  "$REPO/tests/nova/tests"    # the 98 -entry.nova modules they load the same way
  "$REPO/compiler/c"        # R522: 55 files a gate COMPILES were not named here at all
  "$REPO/compiler/c/nova"   # the harnesses themselves -- tests_ntasm_*.c, and they move
)

# R522, measured on this tree: the guard watched 172 files and 55 files that go INTO
# the answer were outside it. A harness .c moved at 04:14:44, four checks appeared
# (822 -> 826), and both runs' MODULES_EDITED_DURING_RUN guards stayed CLEAN --
# because a .c is not a .nova and this line only ever named .nova.
#
# The two are different causes and the guard now says so where it reports: a .nova is
# OPENED BY PATH at run time and nothing is rebuilt for it; a .c is COMPILED into the
# binary that answers. Same detection, different reason, and the reason is what tells
# a reader whether to look for a stale object or a stale source.
#
# What is STILL not watched, and named so a reader does not have to guess: the .sh
# files other than this one, every ROOT_GATES/NOVA_GATES list, every reference .bin
# and fixture a gate reads as data, and every .nova outside the four directories above.
runtime_module_list() { # prints one absolute path per line
  local d
  for d in "${RUNTIME_MODULES[@]}"; do
    [ -d "$d" ] || continue
    find "$d" -maxdepth 1 -type f \( -name '*.nova' -o -name '*.c' -o -name '*.h' \) -print
  done | LC_ALL=C sort
}

# Hash every runtime module into $1. Content, not mtime: a sibling lot that
# saves a module twice inside one wall-clock second is invisible to the mtime
# comparison stale_scan uses, and this guard exists because an assumption
# failed, not because a timestamp was coarse.
runtime_module_snapshot() {
  local list=$1
  [ -f "$list" ] || return 1
  xargs -a "$list" -r sha256sum 2>/dev/null || return 1
}

# The MODULES_EDITED_DURING_RUN predicate, as a function for the same reason
# stale_scan is one: the self-test must put a constructed before/after pair in
# front of the REAL comparison, not in front of a copy of it, or editing this
# function is undetectable. One function, two callers, no second copy.
#
# $1 = the snapshot file (sha256sum lines), rest = the module paths.
# Prints " name" per module whose bytes are not what the snapshot recorded,
# including a module that has since been DELETED -- a deletion during the run
# changes the answer just as an edit does, and a scan that only compares live
# files answers nothing about it.
module_scan() { # $1 = snapshot file, rest = module paths
  local snap=$1 m now moved=""
  shift
  [ -f "$snap" ] || { printf 'NO_SNAPSHOT'; return; }
  for m in "$@"; do
    # THE DELETED MODULE, and this function covers that state three times over,
    # which was MEASURED rather than assumed and is written down because a reader
    # would otherwise take the arm below for the load-bearing one. Three layers:
    # this `[ -n "$now" ]` arm; `sha256sum` of a missing file yielding an empty
    # digest; and `grep -Fxq ""` matching no snapshot line, which makes the
    # comparison itself name the module. Deleting any ONE of the three left
    # rails_selftest at 14 cases 0 failed; only removing all three turned "a
    # module deleted during the run is named" red. Four mutations, measured.
    #
    # So the honest reading of that self-test case is: it pins the BEHAVIOUR "a
    # deleted module is named", and it does not pin this line. Stated here rather
    # than left for a reader to assume the strongest of the three. The arm is
    # kept because it is the only layer a reader can see and the only one that
    # survives a future change to the comparison; the redundancy is disclosed
    # rather than removed, because removing the other two would trade a correct
    # predicate for a fragile one for no measured gain.
    # `set -euo pipefail` is in force at :184, and a command substitution whose command
    # FAILS aborts the script THERE -- so the `[ -n "$now" ]` guard on the next line,
    # which exists precisely to name a module that has just been deleted, was
    # UNREACHABLE. `2>/dev/null` hid the message and left the status standing.
    # This is the same defect the census rail already fixed at :1291 with `|| rc=$?`,
    # in the same file, and it was still live here. Symptom: on a tree being written
    # under the run, the driver dies mid-loop, prints no GATES_DONE, and the green tail
    # reads as a pass. `one: command not found` was reported at :885, which is the
    # blank line after this loop's caller -- bash attributes there, not here.
    now=$(sha256sum "$m" 2>/dev/null) || now=""
    [ -n "$now" ] || { moved="$moved $(basename "$m")"; continue; }
    grep -Fxq -- "$now" "$snap" || moved="$moved $(basename "$m")"
  done
  printf '%s' "$moved"
}


# Rebuild unless the object is strictly in a LATER wall-clock second than its
# source. `[ a -nt b ]` compares whole seconds, so a source saved in the same
# second the object was written looks older-or-equal and is silently NOT
# recompiled -- the object then answers for a revision of the source that no
# longer exists. Rebuilding in the same-second case costs one compile and
# removes the case entirely; the object being genuinely newer is the only skip.
stale_obj() { [ ! -f "$2" ] || [ "$(( $(stat -c %Y "$1") - $(stat -c %Y "$2") ))" -ge 0 ]; }


# ================================ the two rails, and a self-test that can fail.
#
# STALE_OBJECTS below and stale_obj above are the two instruments wave 10 added
# after the warm-directory finding. Both were verified once, by hand, by their
# author: one by starting a slow gate and touching a source during the gate
# loop, the other by constructing the same-second case directly with `touch
# -d`. That is real evidence, done once, in a scratch directory, and it is not
# in the suite -- so it will rot silently, which is the defect class this whole
# project exists to remove.
#
# WHY A PREDICATE SELF-TEST AND NOT A FULL BUILD, which is the honest form
# rather than the convenient one. A test that shells out to this script with a
# concurrent writer would be slow, would race the eight lots currently editing
# this tree, and its red would be about a MOVING TREE rather than about the
# code -- the run-race guard would fire on the test that exists to test it, and
# the reader could not tell the two apart. A full build also cannot produce the
# state STALE_OBJECTS exists to detect without deliberately corrupting a build
# directory mid-run, which is a destructive command against a shared artefact.
# Both predicates are pure functions of two paths, so the questions they exist
# to answer can be put to them directly, on files this script creates, in a
# directory this script removes.
#
# WHAT MAKES IT A TEST RATHER THAN A RESTATEMENT. It calls the same two
# functions the build calls -- `stale_obj` and `stale_scan`, by name, with the
# same arguments -- and it asserts a truth table over constructed mtimes, not
# that the source contains certain words. A copy of the predicate in the test
# would prove nothing and is deliberately not written: the mutation that this
# test is here to catch is someone editing `stale_obj` itself, and only a call
# to the real function can catch that.
#
# WHY IT RUNS ON EVERY INVOCATION. An instrument exercised in one state has not
# been tested against the state it exists to detect, and a self-test behind a
# flag is an instrument exercised in exactly one state. It costs a handful of
# `touch` and `stat` calls in a private temp directory -- no gcc, no repository
# access, no network -- so it runs unconditionally, including under `libsonly`,
# and it cannot be skipped by anyone who forgets the flag.
#
# THE DETERMINISM. Every mtime below is set with `touch -d` to an absolute
# time, never relative to now, so the truth table does not depend on when the
# run happened or on how fast the machine is. There is no sleep and no
# wall-clock comparison anywhere in this function, which is what makes it
# impossible for it to be flaky.

RAIL_CASES=0
RAIL_FAILED=0

# One assertion against one named case. `want` and `got` are "0" or "1" and are
# compared as strings so a case can never be satisfied by a non-boolean.
rail_case() {
  RAIL_CASES=$((RAIL_CASES + 1))
  if [ "$2" != "$3" ]; then
    RAIL_FAILED=$((RAIL_FAILED + 1))
    echo "RAIL_SELFTEST_FAIL $1: expected $2 and the predicate returned $3"
  fi
}

# The STALE_OBJECTS predicate, as a function so that the self-test can put the
# state it exists to detect in front of it without a concurrent writer. The
# build path below calls this with the real library list and the real build
# directory; the self-test calls it with a synthetic list in a temp directory.
# One function, two callers -- there is no second copy of the comparison to
# drift out of step with the first.
stale_scan() { # $1 = build dir, rest = source paths; prints " name" per stale
  local bd=$1 src o stale=""
  shift
  for src in "$@"; do
    o="$bd/$(basename "$src" .c).o"
    if [ -f "$o" ] && [ "$src" -nt "$o" ]; then
      stale="$stale $(basename "$src")"
    fi
  done
  printf '%s' "$stale"
}

rails_selftest() {
  local d rc=0
  d="$(mktemp -d "${TMPDIR:-/tmp}/ng-rails-XXXXXX")" || {
    echo "RAIL_SELFTEST_FAIL: cannot create a work directory, so the rails are UNTESTED"
    return 1
  }

  # ---- the truth table of stale_obj: does it rebuild when it must?
  # The same-second case is the one the whole function exists for. `[ -nt ]`
  # cannot see it, so the case asserts BOTH halves: that the naive comparison
  # says "no rebuild" and that stale_obj says "rebuild". If someone ever
  # "simplifies" stale_obj back to `[ "$1" -nt "$2" ]`, the first half still
  # passes and the second goes red, which is the mutation this pins.
  : >"$d/a.c"; touch -d '2026-02-03 04:05:06.100000000' "$d/a.c"
  : >"$d/a.o"; touch -d '2026-02-03 04:05:06.900000000' "$d/a.o"
  if [ "$d/a.c" -nt "$d/a.o" ]; then rail_case "same-second naive -nt sees the edit" 0 1
  else                            rail_case "same-second naive -nt sees the edit" 0 0; fi
  if stale_obj "$d/a.c" "$d/a.o"; then rail_case "same-second source is rebuilt" 0 0
  else                                 rail_case "same-second source is rebuilt" 0 1; fi

  # The object genuinely in a LATER second: the one and only case in which the
  # compile is skipped. A rail that rebuilt unconditionally would pass every
  # case above and be wrong here, which is why this case is in the table.
  : >"$d/b.c"; touch -d '2026-02-03 04:05:06.000000000' "$d/b.c"
  : >"$d/b.o"; touch -d '2026-02-03 04:05:07.000000000' "$d/b.o"
  if stale_obj "$d/b.c" "$d/b.o"; then rail_case "a later object is skipped" 1 0
  else                                 rail_case "a later object is skipped" 1 1; fi

  # Object older by a whole second: the ordinary edit, which `[ -nt ]` does see.
  : >"$d/c.c"; touch -d '2026-02-03 04:05:07.000000000' "$d/c.c"
  : >"$d/c.o"; touch -d '2026-02-03 04:05:06.000000000' "$d/c.o"
  if stale_obj "$d/c.c" "$d/c.o"; then rail_case "a whole second older is rebuilt" 0 0
  else                               rail_case "a whole second older is rebuilt" 0 1; fi

  # No object at all: a cold directory must always compile.
  : >"$d/e.c"
  if stale_obj "$d/e.c" "$d/e.o"; then rail_case "a missing object is built" 0 0
  else                               rail_case "a missing object is built" 0 1; fi

  # ---- the truth table of stale_scan: can STALE_OBJECTS fire, and can it stay
  # quiet? Both directions are asserted. A scan that cannot fire is a rail that
  # was never armed; a scan that fires on a still tree is a rail that gets
  # switched off, and both are the same defect.
  mkdir -p "$d/bd"
  : >"$d/quiet.c"; touch -d '2026-02-03 04:05:06.000000000' "$d/quiet.c"
  : >"$d/bd/quiet.o"; touch -d '2026-02-03 04:05:07.000000000' "$d/bd/quiet.o"
  : >"$d/edited.c"; touch -d '2026-02-03 04:05:07.000000000' "$d/edited.c"
  : >"$d/bd/edited.o"; touch -d '2026-02-03 04:05:06.000000000' "$d/bd/edited.o"
  : >"$d/none.c"; touch -d '2026-02-03 04:05:07.000000000' "$d/none.c"

  # The fire case. The expected string carries the LEADING SPACE on purpose:
  # the build path pastes it straight after "sources-edited-during-run:", so
  # the exact bytes are part of the line a reader sees, and a self-test that
  # trimmed them would pass while the log said "…run:nova.c".
  rail_case "an object older than its source is named" " edited.c" \
    "$(stale_scan "$d/bd" "$d/quiet.c" "$d/edited.c")"
  # The quiet cases: a source nobody touched, and a source with no object at
  # all. `[ -f "$o" ]` is what makes the second one quiet, and it is asserted
  # because a scan that reported a missing object would fire on every cold
  # build and be ignored within a day.
  rail_case "a still tree names nothing" "" \
    "$(stale_scan "$d/bd" "$d/quiet.c")"
  rail_case "a missing object names nothing" "" \
    "$(stale_scan "$d/bd" "$d/none.c")"
  # The count, not just the membership: a scan that names everything on a tree
  # where one file moved passes both cases above.
  rail_case "one moved file is named once" " edited.c" \
    "$(stale_scan "$d/bd" "$d/quiet.c" "$d/edited.c" "$d/none.c")"

  # ---- the truth table of module_scan: the guard that was MISSING. Both
  # directions are asserted, for the same reason the stale_scan cases above
  # assert both: a scan that cannot fire is a rail that was never armed, and a
  # scan that fires on a still tree is a rail that gets switched off within a
  # day. Same form as the stale_scan cases, same truth table, no second
  # harness, and no full build: a full build cannot produce a mid-run module
  # edit without deliberately corrupting a shared tree, which is the reason
  # this whole function is a predicate self-test (see the header above).
  mkdir -p "$d/mods"
  printf 'x64_lower_nxo v1\n' >"$d/mods/moved.nova"
  printf 'parser v1\n'      >"$d/mods/quiet.nova"
  printf 'gone v1\n'        >"$d/mods/vanished.nova"
  : >"$d/mods.snap"
  find "$d/mods" -maxdepth 1 -type f -name '*.nova' -print | LC_ALL=C sort >"$d/mods.list"
  if runtime_module_snapshot "$d/mods.list" >"$d/mods.snap"; then :; else
    rail_case "the module snapshot can be taken" 0 1
  fi
  # An EDIT, forced back into the SAME wall-clock second as the snapshot. This
  # is the case that motivated content hashing rather than mtime: an mtime
  # comparison here would be silent, and the guard's whole reason for existing
  # is that an assumption about bytes failed silently once already.
  printf 'x64_lower_nxo v2\n' >"$d/mods/moved.nova"
  touch -r "$d/mods/quiet.nova" "$d/mods/moved.nova"
  rail_case "a module edited during the run is named" " moved.nova" \
    "$(module_scan "$d/mods.snap" "$d/mods/quiet.nova" "$d/mods/moved.nova")"
  # The quiet case: a module nobody touched must not be named, or this rail
  # reports the whole corpus on every run and is ignored the same afternoon.
  rail_case "a still module names nothing" "" \
    "$(module_scan "$d/mods.snap" "$d/mods/quiet.nova")"
  # A module DELETED mid-run: the bytes a gate would have loaded are gone, and
  # a scan that only compares live files cannot see that at all.
  rm -f "$d/mods/vanished.nova"
  rail_case "a module deleted during the run is named" " vanished.nova" \
    "$(module_scan "$d/mods.snap" "$d/mods/vanished.nova")"
  # The COUNT, not just the membership: a scan that names every module passes
  # both quiet cases above, and a rail that names every module is a rail that
  # has been switched off.
  rail_case "one edited module is named once" " moved.nova" \
    "$(module_scan "$d/mods.snap" "$d/mods/quiet.nova" "$d/mods/moved.nova")"
  # A snapshot that was never taken must say so rather than reporting a clean
  # tree. Silence here would be indistinguishable from "nothing moved", which
  # is the one answer this instrument is not allowed to invent.
  rail_case "a missing snapshot says so" "NO_SNAPSHOT" \
    "$(module_scan "$d/nosuchsnap" "$d/mods/quiet.nova")"

  rm -rf "$d"

  if [ "$RAIL_FAILED" -ne 0 ]; then
    rc=1
    echo "RAIL_SELFTEST $RAIL_CASES cases, $RAIL_FAILED FAILED -- the build rails above are NOT trustworthy"
  else
    echo "RAIL_SELFTEST $RAIL_CASES cases, 0 failed"
  fi
  return $rc
}
# WHERE THIS RUNS, and the position was wrong once. A check behind a flag is a
# check that runs in exactly one state, so it runs on every invocation -- and it
# runs BEFORE the library build, not after it. The first version sat between the
# build and the libsonly exit, which meant `libsonly` compiled fourteen objects
# with a predicate that had not yet been shown to work and only then reported
# the verdict: the one mode whose entire job is to produce objects was the mode
# that got the least protection. A self-test that runs after the thing it is
# testing has already used is a post-mortem.
rail_fail=0
rails_selftest || { red RAIL RAIL_SELFTEST_FAILED; rail_fail=1; }

# WHERE THE MODULE SNAPSHOT IS TAKEN: here, after the predicate has been shown
# to work and BEFORE the first object is compiled and long before the first gate
# runs. A snapshot taken after the build would compare the tree with itself and
# report a clean run, which is the exact failure this guard exists to stop.
#
# A DECLARED DIRECTORY THAT IS MISSING OR EMPTY is red, here, for the same
# reason the three declared-gate arrays below are checked in both directions: a
# watch over nothing is not a watch, and it is indistinguishable from a watch
# that found nothing. Measured population on this tree: 156 modules.
MOD_SNAP="$BUILD/.modules.snap"
MOD_LIST="$BUILD/.modules.list"
# R512: $MOD_SNAP is PRIVATE TO ONE RUN, which is the whole of the hole. This path
# is NOT under $BUILD, so it survives into the next run, and the block at the end of
# the guard writes it. $REPO, not $REPO_ROOT -- under `set -u` an unknown variable
# aborts the driver, which is what happened the first time this patch was tried.
LAST_RUN_SNAP="$REPO/out/c-bootstrap/.last-modules.snap"
# R534: how old a cross-run snapshot may be before it is refused rather than compared.
# One day. The gap it certifies is "the tree did not move between two runs"; past a day
# that is not a claim about the tree, it is a claim about when some earlier run happened.
MAX_SNAP_AGE=${NG_MAX_SNAP_AGE:-86400}
runtime_module_list >"$MOD_LIST"
runtime_module_snapshot "$MOD_LIST" >"$MOD_SNAP" || {
  echo "MODULE_SNAPSHOT_UNDECLARED the runtime module list could not be hashed; the"
  echo "  run-race guard would report a clean tree for files it never read. declared:"
  printf '  %s\n' "${RUNTIME_MODULES[@]}"
  red RAIL MODULE_SNAPSHOT_UNDECLARED
  rail_fail=1
}
mod_declared=0
for g in $(cat "$MOD_LIST"); do mod_declared=$((mod_declared + 1)); done
for d in "${RUNTIME_MODULES[@]}"; do
  # R545: R522 widened RUNTIME_MODULES with the two directories that hold the COMPILED
  # sources, and widened runtime_module_list with them -- but NOT this check, which still
  # asked for a .nova. So both new directories were declared VOID while the guard was
  # watching 197 .c and .h in them. The rail was MY defect, firing on every run since
  # H2, and I read it twice as a gate being red before I looked at what it measures.
  #
  # A check that validates a set must use the SAME set as the thing that consumes it.
  # Widening one and not the other is not a half-finished change; it is a change that
  # asserts the opposite of what the guard is doing, in a rail, on every run.
  if [ ! -d "$d" ] || [ -z "$(find "$d" -maxdepth 1 -type f \
        \( -name '*.nova' -o -name '*.c' -o -name '*.h' \) -print -quit 2>/dev/null)" ]; then
    echo "MODULE_DIR_VOID $d is absent or holds no .nova, .c or .h, so the guard would"
    echo "  watch nothing there and say nothing about it"
    red RAIL "MODULE_DIR_VOID:$d"
    rail_fail=1
  fi
done
mod_declared="$(grep -c '' "$MOD_LIST" || true)"
[ -n "$mod_declared" ] || mod_declared=0
echo "MODULES_WATCHED n=$mod_declared from=${#RUNTIME_MODULES[@]} declared-dirs list=$MOD_LIST"

if [ "${1:-}" = "libsonly" ]; then exit "$rail_fail"; fi

OBJ=()
if [ "${1:-}" != "libsonly" ]; then
  for src in "${LIBS[@]}"; do
    o="$BUILD/$(basename "$src" .c).o"
    if stale_obj "$src" "$o"; then
      gcc -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
        -I"$root" -c "$src" -o "$o"
    fi
    OBJ+=("$o")
  done
  echo "LIBS_OK ${#OBJ[@]}"
fi


# gate name -> harness file, without the tests_ntasm_ prefix / .c suffix
custom=0
if [ "$#" -ge 1 ]; then GATES=("$@"); custom=1; else
# R545: inscribed after measuring it, not after wanting it. 246 checks, 14 cases,
# 0 failures -- and among those 246 is the refusal path of the sentinelle, which
# states that node() answers 0 when the tree is full and that 0 is REFUSED BY THE
# CALLER, never read as a node. That rule was written, tested, and DARK: a rule
# that is not exercised cannot catch the mistake it exists to catch.
#
# HERE and not in NOVA_GATES: resolve_gate() tries NOVA_GATES FIRST and returns
# $root/nova/<name>.c, and this gate carries the tests_ntasm_ prefix. Declaring it
# in NOVA_GATES sent the resolver to a file that does not exist and the gate
# answered UNRESOLVED -- a gate I had just made unreachable BY NAME.
GATES=(
    validate x64_lower_nxo x64_lower_nxo_data x64_lower_nxo_combined x64_lower_nxo_import x64_lower_nxo_local
    x64_lower_nxo_local_pe x64_lower_nxo_local_data x64_lower_nxo_local_data_pe x64_lower_nxo_local_multi x64_lower_nxo_local_multi_pe x64_lower_nxo_local_multi_data
    x64_lower_nxo_local_multi_data_pe x64_lower_nxo_pe x64_lower_unified nxo nxo_merge nxo_link_pe
    nxo_pe nxo_inspect_text nxo_reloc nxo_symbol parser lexer ast c_conversion
    pe_relocation nxo_inspect macro_io_provenance_unbound
    object_pe_join
    semantics decls refs calls callable_names parameters
    locals bindings register_bindings register_widths symbol_names clobbers
    abi effects contracts call_effects call_contracts call_clobbers
    invalid_positions interrupt_syscall
    body_effects body_intrinsics body_clobbers control_flow pointer_spaces features
    call_fold nested_call
    feature_requirements targets versions types return_types call_types
    literal_initializers condition_types constant_types initializer_types x64_fixed x64_rr
    x64_binary x64_a2_parity output_goldens ntir_schema machine_schema pe_oracle_provenance pe_exec
    x64_ri x64_memory x64_setcc x64_control x64_jcc x64_stack
    x64_unary_shift x64_lower_fixed x64_lower_basic x64_lower_address x64_lower_memory x64_lower_sib
    x64_labels pe_inspect macro_expand nxo_merge_list x64_lower_nxo_function_bodies x64_lower_nxo_frames
    x64_lea x64_shift_cl x64_two_reg x64_lower_lea x64_lower_shift_cl x64_shift_mem
    x64_high8 x64_lower_two_reg stub_table diagnostics nxo_link_pe_list registry
    ntir ntir_inspect cli machine_ir splice ir_image
    placeholder form_matrix comptime comptime_purity directions bounds_ceiling
    reg_width_binding corpus_e2e bool_fold
    a5_inventory artifact_ownership machine_x64 nova_language_lex machine_pipeline machine_producer_exec machine_corpus machine_macro_calls machine_missing validate_expanded
    nova_language_parse
)
fi

# ---------------------------------------------------------------------------
# form_matrix, AND WHY ITS REGISTRATION WAS A PACKAGE.  Read this before touching
# either half.
#
# It was NOT registered for a long time, on purpose: derive_population.py had no
# cell for it, and census_rail.py:133 makes coverage a CONDITION of closure, so
# adding the stem ALONE would RELOCATE UNREGISTERED_HARNESS into
# POPULATION_NOT_CLOSED -- the same suite, the same fail=1, and a red that
# misnames itself.  Two lots measured that before I did and both refused it; I
# registered it anyway, found the cell absent, and withdrew it.  The cell is now
# written (class A, with the operands that stop it being derived), so both halves
# are in place and the stem is live.
#
# The argv it needs is at run_harness above.  It matters: WITHOUT it the gate
# writes the matrix from the very call that derived it, and checks=154 failures=0
# is true BY CONSTRUCTION -- a green that proves nothing about itself.  WITH
# --verify it checks the COMMITTED file, so a hand-edited row is a red row.
#
# AND THIS NOTE IS HERE, BELOW THE ARRAY'S CLOSING PARENTHESIS, FOR A MEASURED
# REASON: derive_population.py reads its population out of this file.  The first
# version of this note sat INSIDE GATES=( ... ) and inflated the census from 128
# entries to 225, with duplicates=['#', 'is', 'NOT', 'registered,', 'on',
# 'purpose'].  A positional reader has no way to tell a name from a sentence
# about a name.  Do not put prose in this array.

# ---------------------------------------------------------------------------
# The gates the tests_ntasm_ NAME FILTER cannot see.
#
# WHY A SECOND LIST, AND WHY THIS IS NOT THE SAME LIST. A gate is a harness
# with a main(); this script finds them by the filename convention
# tests_ntasm_<stem>.c, and the convention is a NAME test, so a harness that
# does not follow it is invisible to the loop above AND to the closure rail
# below: neither can see it, so neither can report it missing. One harness in
# this directory did not follow the convention -- nova_corpus_convergence.c,
# the only gate that proves the Nova producer converges byte for byte against
# the C reference over the seven pinned corpus members. It was therefore
# compiled by nothing and run by nobody, and the suite was green over a gate
# that did not run. That is the whole of the defect: not a missing gate but a
# missing MEASUREMENT, invisible precisely because the instrument was not
# registered.
#
# WHY NOT WIDEN THE FILTER. Dropping `-name 'tests_ntasm_*'` matches run_host.c,
# runtime_v2.c, pe_oracle.c, cli.c and the rest of the infrastructure and
# demands a GATES entry for each; the rail then goes red on ordinary library
# files, and a rail that cries wolf on the infrastructure is switched off within
# a day, which leaves the hole open AND the rail discredited. Raising
# -maxdepth buys nothing at all: this directory is the rail's own find root and
# the file sits at depth 1. Both were measured; see out/c-bootstrap/ng21outfam.
#
# WHAT THIS DOES INSTEAD -- invert the responsibility. The owner DECLARES every
# .c file in this directory, and the rail checks the declaration against the
# directory in BOTH directions, which is the same closure property the
# tests_ntasm_ rail already has, applied to the case the name filter excluded.
# A new file cannot slip through silently, because an undeclared file is red.
# A file declared NOT_A_GATE is a visible, greppable, dated decision in one
# place instead of silence, which is the difference between a decision and an
# oversight. It is not a guarantee against a dishonest declaration, and no
# rail of this kind is; it is a guarantee against the accidental one.
#
# gate        built and run below; the file must exist, and it must not also
#             carry a name the tests_ntasm_ filter owns -- both asserted
# lib         linked into every gate above; appearing in LIBS is asserted
# not_a_gate  present, declared here, NOT built by this script, with the reason
NOVA_GATES=(
    nova_corpus_convergence
)
NOVA_LIBS=(
    pe_oracle.c run_host.c runtime_v2.c machine_driver.c
)
NOVA_NOT_A_GATE=(
  "cli.c|has its own main; the command that builds it is written down in this
directory's BOOTSTRAP_CHECKLIST.md and in READINESS.md, not here"
  "runtime.c|the v1 runtime, superseded by runtime_v2.c which is the one LIBS
links; measured 30 September 2026: no build in the tree compiles it"
  "uefi_platform.c|no build in the tree compiles it; measured 30 September 2026"
  "uefi_probe.c|efi_main, built by an EFI toolchain that is not in this tree;
measured 30 September 2026: the string uefi_probe occurs in no .sh and no .md
outside out/"
)

fail=$rail_fail

# ONE build path for every harness, named gates and declared ones alike. A
# second copy of this loop would be a second convention that can drift, which is
# the defect the refactor would have been introduced to remove.
run_harness() { # $1 harness path, $2 label, $3 log/binary stem
  local h=$1 g=$2
  # ARGUMENT-TAKING GATES.  A harness whose main() reads argv returns its usage
  # exit before its first check when given none, so it is a PLACEMENT problem and
  # not a defect.  The list is EMPTY for every gate that needs nothing, which is
  # every gate that was working before this.  Add an entry only for a harness whose
  # own usage line names what it wants; do not invent arguments for it.
  local -a gate_argv=()
  case "$g" in
    form_matrix)
      # WITHOUT this the gate writes the matrix from the very call that derived it
      # and asserts nothing -- checks=154 failures=0 by construction.  WITH it the
      # gate checks the COMMITTED file, so a hand-edited row is a red row.
      gate_argv=(--verify "$REPO/out/c-bootstrap/nova/form-matrix.tsv") ;;
  esac
  [ -f "$h" ] || { echo "MISSING_HARNESS $g"; red GATE "$g:MISSING_HARNESS"; return; }
  if ! gcc -std=c11 -Wall -Wextra -Werror -O1 -g \
      -fsanitize=address,undefined -fno-omit-frame-pointer \
      -I"$root" "${OBJ[@]}" "$h" -o "$BUILD/$3" 2>"$BUILD/$3.cc.log"; then
    echo "CC_FAIL $g"; tail -25 "$BUILD/$3.cc.log"; red GATE "$g:CC_FAIL"; return
  fi
  # BOTH streams go to the log. Writing only stderr put the banner -- which is
  # stdout -- and the diagnostics a reader greps for on two different streams,
  # and this is how a counted failure was hunted for across three runs and not
  # found: the count was on the terminal, the FAIL lines were in the log, and
  # the two were never in the same place. The reader was in the right log
  # looking at the wrong quantity, which is a different mistake from silence
  # and no-less expensive. The log is the record; the banner is re-emitted
  # below so a watching reader still sees it.
  #
  # `tail -25`, NOT `sed -n '1,25p'`, and the reason is measured on this tree:
  # tests_ntasm_registry.c writes NTASM_NOVA_REGISTRY at the END of its run log.
  # Measured: the banner sits at line 2247 of a 2247-line registry.run.log, and
  # the first 25 lines of that log contain ZERO lines matching `checks=`. So the
  # old `sed` printed a red gate's failure context and NOT the one number that
  # says how bad it is -- `checks=3451 failures=8 cases=676` was in the file and
  # not on the screen. A counter that exists, counts, and is not printed when it
  # counts is a counter that lies by omission, which is the same defect as
  # `fail=1` without a count, one level down: the terminator now names WHICH
  # gate is red, and a reader who then asks "by how much" was still sent to a
  # window of the log that cannot contain the answer.
  #
  # A RED GATE AND AN INTERRUPTED ONE ARE DIFFERENT, and the banner is what
  # tells them apart. A gate that ran its checks and reported a failures>0
  # count is red: it finished and its answer is the answer. A gate whose log
  # holds no banner at all died before it could speak -- an ASan abort, a
  # missing input, a crash in setup -- and its non-zero exit says only that it
  # did not finish, not that anything failed. Counting those as red reports a
  # crash as a verdict, and dropping them reports a dead gate as a green one.
  # The register distinguishes them below, which is the only reason to look.
  gate_banner() { # $1 = gate label; re-emit this gate's banner lines
    grep -aE '^[A-Z][A-Z0-9_.-]+ +[a-z_]+=' "$1" || true
  }
  if ! ( cd "$REPO" && ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
         UBSAN_OPTIONS=halt_on_error=1 "$BUILD/$3" ${gate_argv[@]+"${gate_argv[@]}"} ) >"$BUILD/$3.run.log" 2>&1; then
    # The banner comes FIRST, before RUN_FAIL and before the tail, and that is
    # the second half of a rule this driver already follows in its first half:
    # the banner is re-emitted on the RUN_FAIL path as well as the green one,
    # because the one case where a reader most needs the count was the one case
    # that never printed it. Order is the same requirement: a reader that meets
    # the gate's FAIL lines before the gate's counters cannot attribute them, and
    # every downstream instrument has to guess. Measured on this tree, the
    # whole failure block of `validate` — 12 lines — landed ahead of the first
    # banner in the log, and checkset.py reported named_failing_checks=0 on a
    # log that contains 18 such lines. Emitting the counters first makes the
    # positional reading correct instead of merely possible.
    gate_banner "$BUILD/$3.run.log" || true
    # The FAILING LINES, not the last 25 lines. `tail -25` is a diagnostic for a
    # crash, and a gate that RUNS and fails seventeen checks produces more than 25
    # lines of output — so every one of its failures was truncated away and the
    # log said `failures=17` while naming none. Measured on splice: run directly
    # it prints 17 `FAIL` lines, all `ret=940 want=0 runtime=0`; run through this
    # path it printed zero. The banner now comes first (see above), and this
    # completes it: a reader can finally attribute every announced failure.
    echo "RUN_FAIL $g"
    # Each gate's FAIL lines are emitted ONCE. The driver runs some gates more
    # than once, and a gate that is re-run re-reports the same failures — so an
    # eight-failure gate reached the log as sixteen named lines and every
    # consumer then compared sixteen names against an announced eight. The
    # duplicate is a property of the driver, not of the gate, so it is removed
    # here rather than divided out downstream.
    if [ -z "${_ng_fail_reported:-}" ] || ! printf '%s\n' "${_ng_fail_reported}" | grep -qxF "$g"; then
      _ng_fail_reported="${_ng_fail_reported:-}${_ng_fail_reported:+
}$g"
      grep -a '^FAIL ' "$BUILD/$3.run.log" \
        || echo "FAIL_LINES_ABSENT $(grep -ac '' "$BUILD/$3.run.log") lines in the gate log, none named"
    fi
    # The tail publishes CONTEXT, not failures. `tail -25` on a log shorter than the
    # window returns the whole log, so on a nine-line gate it republished every FAIL
    # line the grep above had already emitted — and validate and initializer_types
    # reached the log as sixteen and twelve named lines against eight and six
    # announced. The duplicate is a property of the DRIVER, not of the gate, so it is
    # removed here rather than divided out downstream. `grep -a` keeps it binary-safe;
    # `|| true` because filtering may legitimately leave nothing to print.
    tail -25 "$BUILD/$3.run.log" | grep -av '^FAIL ' || true
    if [ -n "$(grep -aE '^[A-Z][A-Z0-9_.-]+ +[a-z_]+=' "$BUILD/$3.run.log" || true)" ]; then
      red GATE "$g:RUN_FAIL"
    else
      # No banner: the gate did not finish, so nothing here is a measurement of
      # the tree. INTERRUPTED is its own class for exactly that reason.
      red INTERRUPTED "$g:NO_BANNER"
    fi
    return
  fi
  gate_banner "$BUILD/$3.run.log" || true
}

# A failing rail self-test sets the run red here, before the first gate is even
# compiled. The alternative -- carrying it in a variable nobody reads until the
# end -- is a warning that leaves fail=0, which is the exact shape this project
# spent wave 10 removing.
fail=$rail_fail

# HOW A NAME ON THE COMMAND LINE BECOMES A FILE. The single-gate path used to
# resolve every name as tests_ntasm_<name>.c, which meant a gate that does not
# carry that prefix -- nova_corpus_convergence, the one member of NOVA_GATES --
# was unreachable BY NAME even though the full suite builds and runs it. That is
# a gate that is green in the suite and cannot be run by a reader, and a
# document (MEM.md) had already recorded such a gate as « not run by the suite »,
# which was false of today's bytes and wrong in the direction that HIDES
# evidence: a reader who believes it does not go looking for 264 passing checks.
#
# The residue of a record is visible in the PORTABILITY of a name, not in the
# presence of the gate, and the two look alike in an inventory. So the resolver
# asks the two declared classes in a fixed order and says WHICH class it used.
resolve_gate() { # $1 = gate name; echoes the harness path, or nothing + a reason
  local g=$1 d n
  for d in "${NOVA_GATES[@]}"; do
    if [ "$d" = "$g" ]; then
      if [ -f "$root/nova/$g.c" ]; then printf '%s' "$root/nova/$g.c"; return 0; fi
      # The name IS registered; the FILE is gone. Reporting MISSING_HARNESS here
      # would name a class the caller never asked for and send the next reader to
      # a tests_ntasm_ prefix that has nothing to do with it. The cause is the
      # declaration, so the message names the declaration.
      echo "DECLARED_GATE_FILE_ABSENT $g is a member of NOVA_GATES and $root/nova/$g.c does not exist"
      return 1
    fi
  done
  if [ -f "$root/nova/tests_ntasm_${g}.c" ]; then
    printf '%s' "$root/nova/tests_ntasm_${g}.c"; return 0
  fi
  # MISSING_HARNESS, but with the two classes it looked in NAMED, because the old
  # message implied the only way to register a gate was the tests_ntasm_ prefix
  # and that is not what this file does.
  echo "MISSING_HARNESS $g: no $root/nova/tests_ntasm_$g.c and no NOVA_GATES member of that"
  echo "  name; a gate is reachable by name only if it is in GATES under that stem or is"
  echo "  declared in NOVA_GATES. Add it to one of the two, do not just create the file."
  return 1
}

for g in "${GATES[@]}"; do
  if h="$(resolve_gate "$g")"; then run_harness "$h" "$g" "$g"
  else printf '%s\n' "$h"; red GATE "$g:UNRESOLVED"; fi
done

# The declared gates. `custom` means "run exactly the gates named on the command
# line and nothing else", which is what every caller of `ngbuild.sh <gate>` means,
# so the declared gates do not run in that mode -- exactly as the closure rail
# below does not fire in that mode. They are declared unconditionally, so a
# deletion is visible in the file rather than at the moment someone runs it.
if [ "$custom" = 0 ]; then
  for g in "${NOVA_GATES[@]}"; do
    run_harness "$root/nova/$g.c" "$g" "$g"
  done
fi


# ---------------------------------------------------------------------------
# W23U2. THE SECOND BLIND DIRECTORY, and this one is bigger.
#
# Both rails above are rooted at $root/nova: the name filter and the
# declaration rail. $root ITSELF is searched by neither, so nothing directly
# under compiler/c can be reported missing by anything. Measured on
# 30 September 2026: 52 .c files sit at that level, 39 of them define main(),
# and no compiler line anywhere in the tree names one of those 39. They are not
# unregistered; they are invisible. A rail cannot report what it does not
# search, so "the inventory is complete" was a claim nothing held.
#
# The declaration is widened to this directory in the same three classes the
# nova rail already uses, and it is checked in BOTH directions.
ROOT_GATES=(
    tests.c tests_a5.c tests_codegen.c tests_conformance.c
    tests_conformance_cfg.c tests_conformance_efi.c tests_conformance_frontend.c
    tests_conformance_permissions.c tests_conformance_provenance.c
    tests_frontend.c tests_indirect_call.c tests_nova.c tests_nova_aggregates.c
    tests_nova_boundary.c tests_nova_capacity.c tests_nova_integers.c
    tests_nova_limits.c tests_nova_memory.c tests_nova_modules.c tests_nova_v2.c
    tests_object.c tests_object_build.c tests_object_errors.c tests_object_link.c
    tests_object_separate.c tests_pe_relocations.c tests_static_pointer.c
    tests_x64.c
)
ROOT_LIBS=(
    nova.c ntasm.c frontend.c codegen.c x64.c pe.c
    object.c object_build.c object_link.c object_materialize.c conformance.c
)
#
# A GATE is a file that run_harness can compile, link and run to green on its
# own, with the arguments it supplies.  run_harness now supplies an ARGUMENT
# LIST PER GATE, empty for every gate that needs none -- see the case above --
# so a harness whose main() reads argv can still be a gate, provided its own
# usage line names what it wants.  The six below remain declared NOT_A_GATE
# because giving each of them its own arguments is a separate decision, not a
# change this one makes for them. A harness whose
# main() reads argv is not a gate here, and a harness whose symbols come from a
# translation unit outside ROOT_LIBS is not a gate here either. Both are still
# real files with real coverage, so they are DECLARED rather than dropped, and
# the reason says which of the two it is and what the missing thing is.
#
# The nine below were added to this directory after the vintage this driver was
# assembled from, and were declared ROOT_GATES in one block on the reasoning
# that a file under $root is a gate. Measured 30 September 2026, each one is
# refused by the rail for a reason of its own, and the two causes are distinct:
#
#   SIX TAKE ARGUMENTS. run_harness execs the binary with no argv, so each
#   returns its usage exit before the first check. Two of the six are proven
#   green the moment they are handed what their own usage line names, which is
#   what makes this a PLACEMENT error and not a defect:
#     tests_nova_component.c    NOVA_COMPONENT_TESTS    checks=5104 failures=0
#     tests_nova_component_v2.c NOVA_COMPONENT_V2_TESTS checks=8922 failures=0
#   Both were compiled and run by hand against
#   examples/nova-bootstrap/decimal-u64.nova. The other four are drivers over a
#   built artifact and want their own inputs:
#     build_witness.c       argc==5: source plus three output paths
#     tests_nova_pe.c       argc in 3..5: source, output, optional --large
#     tests_nova_pe_reloc.c argc==3: source plus output
#     tests_pe.c            argc==2, and argv[1] must be a COMPILED PE to
#                          inspect, not a .nova source to compile
#
#   THREE COMPILE AND FAIL TO LINK. These are the tests OF a library that this
#   script does not link into gates, so declaring them gates asserts a link
#   that does not exist:
#     tests_cli.c               needs nt_cli, defined in cli.c
#     tests_nova_runtime.c      needs nova_runtime_init/nova_runtime_destroy
#     tests_nova_runtime_host.c the same two
#   cli.c is NOT_A_GATE below and so cannot also be a ROOT_LIBS entry -- the
#   rail would raise ROOT_DECLARED_TWICE on it, which is the rail being right.
#   nova/runtime.c is the interesting one: NOVA_NOT_A_GATE above calls it
#   'superseded by runtime_v2.c ... no build in the tree compiles it', and that
#   reason is now FALSIFIED -- these two harnesses reference its entry points.
#   The falsification is recorded here rather than by editing that reason,
#   because runtime.c is a nova/ file and its reason is not this declaration's
#   to revise. The build that would revive it links nova/runtime.c; nothing in
#   this tree does.
ROOT_NOT_A_GATE=(
  "build_witness.c|an argument-taking driver, not a gate: its main() requires
argc==5 (source, output.nxo, output.efi, output-rva.bin) and returns 2 without
them, so run_harness, which supplies no argv, never reaches its first check"
  "tests_cli.c|a test OF the CLI library that this script does not link: it
compiles, then fails to link on an undefined reference to nt_cli, which is
defined in cli.c -- a file declared NOT_A_GATE below and so not in ROOT_LIBS.
The build that runs it is the one that links cli.c"
  "tests_nova_close_fault.c|an LD_PRELOAD fault injector with no main of its
own; it is linked into tests_nova_runtime.c, not run as a gate"
  "tests_nova_component.c|an argument-taking driver, not a gate: its main()
requires a .nova source path and returns 2 without one. Handed the corpus file
it is green -- measured 30 September 2026, NOVA_COMPONENT_TESTS checks=5104
failures=0 -- so this is a placement error, not a defect"
  "tests_nova_component_v2.c|the same shape, and green the same way: measured
30 September 2026, NOVA_COMPONENT_V2_TESTS checks=8922 failures=0"
  "tests_nova_pe.c|an argument-taking driver, not a gate: main() accepts 3 to 5
arguments -- a .nova source and an output path, optionally --large -- and
returns 2 otherwise"
  "tests_nova_pe_reloc.c|an argument-taking driver, not a gate: main() requires
exactly 3 arguments, a .nova source and an output path"
  "tests_nova_runtime.c|compiles, then fails to link on undefined references to
nova_runtime_init and nova_runtime_destroy, defined in nova/runtime.c, which
NOVA_NOT_A_GATE above records as superseded and compiled by nothing; the two
statements cannot both stand, and the link is the one that is missing"
  "tests_nova_runtime_host.c|the same two undefined references, and the same
missing nova/runtime.c"
  "tests_pe.c|an argument-taking driver, not a gate: main() requires exactly 2
arguments and opens argv[1] as a binary PE to inspect, so it consumes a built
artifact rather than producing one"
  "cli.c|the CLI library; main.c is its entry point and is listed here too"
  "main.c|the CLI entry point, built by scripts/ntbuild.sh, not by this script"
)

if [ "$custom" = 0 ]; then
  for g in "${ROOT_GATES[@]}"; do
    run_harness "$root/$g" "${g%.c}" "${g%.c}"
  done

  find "$root" -maxdepth 1 -name '*.c' -printf '%f\n' \
    | LC_ALL=C sort -u >"$BUILD/.root_c"
  {
    for g in "${ROOT_GATES[@]}";     do printf '%s\n' "$g"; done
    for l in "${ROOT_LIBS[@]}";       do printf '%s\n' "$l"; done
    for d in "${ROOT_NOT_A_GATE[@]}"; do printf '%s\n' "${d%%|*}"; done
  } | LC_ALL=C sort >"$BUILD/.root_declared_raw"
  LC_ALL=C sort -u "$BUILD/.root_declared_raw" >"$BUILD/.root_declared"
  for g in "${ROOT_GATES[@]}"; do
    [ -f "$root/$g" ] || { echo "MISSING_ROOT_GATE $g"; red GATE "$g:MISSING_ROOT_GATE"; }
  done
  dup="$(LC_ALL=C uniq -d "$BUILD/.root_declared_raw" || true)"
  if [ -n "$dup" ]; then
    while read -r b; do
      [ -n "$b" ] && { echo "ROOT_DECLARED_TWICE $b"; red GATE "$b:ROOT_DECLARED_TWICE"; }
    done <<<"$dup"
  fi
  while read -r b; do
    [ -n "$b" ] && { echo "UNDECLARED_ROOT_C_FILE $b"; red GATE "$b:UNDECLARED_ROOT_C_FILE"; }
  done < <(comm -23 "$BUILD/.root_c" "$BUILD/.root_declared")
  while read -r b; do
    [ -n "$b" ] && { echo "STALE_ROOT_DECLARATION $b"; red GATE "$b:STALE_ROOT_DECLARATION"; }
  done < <(comm -13 "$BUILD/.root_c" "$BUILD/.root_declared")
fi

# Inventory closure: a harness present in the tree but absent from GATES is a
# silent coverage hole, so it fails the run instead of being ignored.
if [ "$custom" = 0 ]; then
  printf '%s\n' "${GATES[@]}" | LC_ALL=C sort -u >"$BUILD/.gates"
  find "$root/nova" -maxdepth 1 -name 'tests_ntasm_*.c' -printf '%f\n' \
    | sed 's/^tests_ntasm_//; s/\.c$//' | LC_ALL=C sort -u >"$BUILD/.harnesses"
  unreg="$(comm -13 "$BUILD/.gates" "$BUILD/.harnesses" || true)"
  if [ -n "$unreg" ]; then
    while read -r b; do
      if [ -n "$b" ]; then echo "UNREGISTERED_HARNESS $b"; red GATE "$b:UNREGISTERED_HARNESS"; fi
    done <<<"$unreg"
  fi

  # ---- the same closure property, for the files the NAME filter excluded.
  #
  # Four clauses, and each one is a direction rather than a restatement:
  #   (a) every declared gate file EXISTS      -- catches a rename or a deletion
  #   (b) every declared lib is in LIBS        -- catches a declaration that has
  #       stopped being true, which is the failure mode of every static table
  #   (c) no declared gate file is ALSO a tests_ntasm_ file, and no declared
  #       not_a_gate stem is in GATES -- the two declarations cannot be
  #       satisfied by the same file at once, in either direction
  #   (d) every .c the first rail does NOT own is declared -- THE CLAUSE THAT
  #       CLOSES THE HOLE, and it is checked in BOTH directions so a
  #       declaration that names nothing is itself red
  # tests_ntasm_*.c is EXCLUDED here on purpose: those belong to the rail above,
  # and clause (d) as first written matched them too and fired UNDECLARED_C_FILE
  # ninety-odd times on a clean tree. That was measured, not predicted. A rail
  # that reports the whole corpus on every run is a rail whose one real line
  # nobody reads, and this block exists to ADD the names the first rail cannot
  # see, not to restate the ones it already sees.
  # An unregistered harness therefore still fails the run exactly as before:
  # this block was ADDED to the existing check, and every clause below is
  # asserted against a COPY of this script, never against the tree.
  find "$root/nova" -maxdepth 1 -name '*.c' ! -name 'tests_ntasm_*.c' -printf '%f\n' \
    | LC_ALL=C sort -u >"$BUILD/.nova_c"
  # The RAW list is kept as well as the deduplicated one, because clause (c)
  # needs the duplicates that `sort -u` throws away. Checking a `-u`ed list for
  # duplicates checks an empty question and answers nothing.
  {
    for g in "${NOVA_GATES[@]}"; do printf '%s.c\n' "$g"; done
    for l in "${NOVA_LIBS[@]}";   do printf '%s\n' "$l"; done
    for d in "${NOVA_NOT_A_GATE[@]}"; do printf '%s\n' "${d%%|*}"; done
  } | LC_ALL=C sort >"$BUILD/.declared_raw"
  LC_ALL=C sort -u "$BUILD/.declared_raw" >"$BUILD/.declared"

  # (a) a declared gate file EXISTS, and does not ALSO carry a name the first
  # rail owns. A file that is both nova_corpus_convergence.c and
  # tests_ntasm_nova_corpus_convergence.c would be built TWICE under two
  # registrations, and the count a reader takes from the banner would be a
  # count over a set with a duplicate in it.
  #
  # An earlier version of this clause asserted the declared gate's stem was in
  # GATES, and it fired on a CLEAN tree, because being in GATES is exactly what
  # a declared gate is NOT: the GATES array is the name-filter's list, and a
  # stem in it makes the loop above look for tests_ntasm_<stem>.c and report
  # MISSING_HARNESS. Measured, not predicted: UNDECLARED_IN_GATES fired on the
  # clean tree and the run went red over a clause that was asking for the
  # opposite of what it meant. Registration for these files IS the NOVA_GATES
  # entry, so the clause asks about the collision instead.
  for g in "${NOVA_GATES[@]}"; do
    [ -f "$root/nova/$g.c" ] || { echo "MISSING_DECLARED_GATE $g"; red GATE "$g:MISSING_DECLARED_GATE"; }
    [ -f "$root/nova/tests_ntasm_$g.c" ] \
      && { echo "DECLARED_GATE_OWNED_BY_NAME_FILTER $g"; red GATE "$g:DECLARED_GATE_OWNED_BY_NAME_FILTER"; }
  done
  # (b)
  for l in "${NOVA_LIBS[@]}"; do
    found=0
    for src in "${LIBS[@]}"; do
      [ "$(basename "$src")" = "$l" ] && found=1
    done
    [ "$found" = 1 ] || { echo "DECLARED_LIB_NOT_LINKED $l"; red GATE "$l:DECLARED_LIB_NOT_LINKED"; }
  done
  # (c), the other direction: one FILE, one class. A name in two of the three
  # declarations would be built, or linked, under two rules at once, and which
  # one won would be a property of array order rather than of a decision.
  #
  # Two earlier versions of this clause were wrong in ways only a run found.
  # The first compared a not_a_gate file's STEM against GATES and fired on the
  # clean tree, because cli.c without its extension is `cli` and GATES holds an
  # unrelated gate named `cli`. The second asked whether tests_ntasm_<stem>.c
  # exists and fired on the clean tree for the same file: nova/cli.c and
  # tests_ntasm_cli.c are DIFFERENT files that legitimately share a stem, and a
  # stem is not a registration. Both were measured, both are recorded here, and
  # the check that survives is the one about the file itself.
  dup="$(LC_ALL=C uniq -d "$BUILD/.declared_raw" || true)"
  if [ -n "$dup" ]; then
    while read -r b; do
      [ -n "$b" ] && { echo "DECLARED_TWICE $b"; red GATE "$b:DECLARED_TWICE"; }
    done <<<"$dup"
  fi
  # (d), both directions
  if [ ! -s "$BUILD/.nova_c" ]; then
    echo "DECLARATION_RAIL_VOID find matched no .c file under $root/nova"
    red RAIL DECLARATION_RAIL_VOID
  fi
  while read -r b; do
    [ -n "$b" ] && { echo "UNDECLARED_C_FILE $b"; red GATE "$b:UNDECLARED_C_FILE"; }
  done < <(comm -23 "$BUILD/.nova_c" "$BUILD/.declared")
  while read -r b; do
    [ -n "$b" ] && { echo "STALE_DECLARATION $b"; red GATE "$b:STALE_DECLARATION"; }
  done < <(comm -13 "$BUILD/.nova_c" "$BUILD/.declared")
fi

# ================================ the run-race guard, and WHAT IT DOES NOT COVER.
#
# The original sentence here was « A source edited by a sibling lot DURING the
# run ». That reads as universal and never was: the scan below is called with
# "${LIBS[@]}", which is fourteen `.c` paths, while the gates that run above
# open 156 `.nova` modules by relative path at run time. A sentence that
# overstates an instrument's scope is worse than no sentence, because it is
# the sentence a reader quotes. So the scope is stated here, in the block, in
# the form this project already uses for GATE_SHAPE-LIMITS: an `asserted=` list
# and a `not_asserted=` list, printed on every run.
#
# STALE_OBJECTS -- object-side. The objects above were rebuilt if their source
# was newer at the START of this run. A source edited by a sibling lot DURING
# the run leaves an object older than its source, and any gate that reads that
# source as text while probing the linked object then compares two different
# revisions of one file. The result is a false red that names the gate rather
# than the cause, which is the expensive kind. Re-check at the end and say so
# loudly.
stale="$(stale_scan "$BUILD" "${LIBS[@]}")"
if [ -n "$stale" ]; then
  echo "STALE_OBJECTS sources-edited-during-run:$stale"
  echo "  these objects predate their sources; every gate above that reads one of"
  echo "  them as text compared two revisions of the same file. Re-run."
  red GUARD STALE_OBJECTS
fi

# MODULES_EDITED_DURING_RUN -- input-side, and this is the half that was
# missing. No object is rebuilt when a `.nova` module moves, because a module is
# not compiled into anything: it is opened, by path, by a process that is
# already running. So a module edited mid-run changes the answer of a run whose
# objects are all up to date and whose STALE_OBJECTS is silent. That is not a
# hypothesis in this file; it was measured in this tree (x64_lower_nxo.nova,
# 3f67cbe1 -> be94a832, across the boundary of one run, guard silent) and it is
# the reason this block exists.
#
# verify_identity() in tests_ntasm_x64_lower_nxo_pe.c proves the first half of
# the sentence -- a run's answers are for the bytes this process LOADED. It says
# nothing about the second half -- that those bytes were the bytes on disk for
# the whole run -- and that second half was assumed until now. The two halves
# together are what "this run is trustworthy" means, and only one of them was
# being checked.
mod_paths=()
while IFS= read -r _mp; do [ -n "$_mp" ] && mod_paths+=("$_mp"); done <"$MOD_LIST"
mods="$(module_scan "$MOD_SNAP" "${mod_paths[@]}")"
if [ -n "$mods" ]; then
  echo "MODULES_EDITED_DURING_RUN modules-changed-during-run:$mods"
  echo "  a .nova is opened BY PATH at run time, so nothing was rebuilt for it and"
  echo "  STALE_OBJECTS cannot see it. A .c is COMPILED into the binary that answers,"
  echo "  so an edit under this run means the objects above were built from different"
  echo "  sources than the log beside them names. Either way: gates above may have"
  echo "  read one revision and answered from another. Re-run; nothing here is fixed."
  red GUARD MODULES_EDITED_DURING_RUN
fi

# R512, the cross-run half. The guard above compares two moments INSIDE one run, and
# is therefore silent on a tree that moved BETWEEN two runs -- measured, twelve
# seconds wide, by W218EntryName. This compares the current tree against where the
# LAST COMPLETED run left it, the only moment the driver actually owns.
#
# Its own token, NOT folded into MODULES_EDITED_DURING_RUN: DURING says a run loaded
# two revisions, BETWEEN says no run was in flight at all. Same cause, different
# answer, and conflating them makes the second look like a re-run of the first.
if [ -f "$LAST_RUN_SNAP" ]; then
  between="$(module_scan "$LAST_RUN_SNAP" "${mod_paths[@]}")"
  if [ -n "$between" ] && [ "$between" != "NO_SNAPSHOT" ]; then
    echo "MODULES_EDITED_BETWEEN_RUNS modules-changed-between-runs:$between"
    echo "  no run was in flight: the tree moved in the gap between the previous run's"
    echo "  guard and this one's snapshot. The previous banners were certified on"
    echo "  different bytes than the ones above were. Re-run to restate them."
    red GUARD MODULES_EDITED_BETWEEN_RUNS
  fi
  # R534: the snapshot says WHAT it saw and never WHEN. It survives between sessions
  # because it must -- that is the whole point of the cross-run half -- and a file
  # that survives between sessions without carrying its own age cannot tell a
  # gap of twelve seconds from a gap of two days. Both are "the tree moved", and a
  # reader who cannot tell them apart cannot tell whether the previous banners are
  # one re-run away or a fortnight away.
  #
  # So it carries its own age, and a snapshot older than MAX_AGE says so instead of
  # being silently compared. A stale-but-matching snapshot is the worst case: it
  # produces a CLEAN answer about a comparison that has no business being made.
  snap_age=$(( $(date +%s) - $(date -r "$LAST_RUN_SNAP" +%s) ))
  if [ "$snap_age" -gt "$MAX_SNAP_AGE" ]; then
    echo "LAST_RUN_SNAPSHOT_OLD last-run-modules-snap:$LAST_RUN_SNAP age_seconds:$snap_age"
    echo "  the cross-run comparison above was made against a snapshot $snap_age s old."
    echo "  That is not a measurement of the gap -- it is a measurement of how long ago"
    echo "  some earlier run happened. Treat the guard above as NOT RUN, not as clean."
    red RAIL LAST_RUN_SNAPSHOT_OLD
    rail_fail=1
  fi
fi

# Carry the state forward, AFTER the guards and unconditionally: a run that failed its
# guards still tells the next run what the tree looked like when it stopped, and a tree
# that keeps moving shows up on every later run instead of being absorbed.
runtime_module_snapshot "$MOD_LIST" >"$LAST_RUN_SNAP" 2>/dev/null || {
  echo "LAST_RUN_SNAPSHOT_UNWRITABLE last-run-modules-snap:$LAST_RUN_SNAP"
  red RAIL LAST_RUN_SNAPSHOT_UNWRITABLE
  rail_fail=1
}

# RUN_RACE_GUARD_LIMITS. The residue, named rather than left implicit: after
# this change the guard covers exactly two sets -- the 14 LIBS paths and the
# modules listed in $MOD_LIST -- and NOTHING ELSE. A reader who takes a green
# run as "the tree did not move" is reading past this line, and the residue is
# large enough to matter: it is every harness `.c`, every ROOT_GATES/NOVA_GATES
# file, every `.sh`, every reference `.bin` and fixture a gate reads as data,
# and every `.nova` OUTSIDE the two declared directories. Measured examples of
# that last class on this tree, none of them watched: the bare-name .nova
# fixtures the harnesses carry as strings, and
# tests/c/nova/tests/validate-macro-decl-entry.nova, which no
# harness in $root/nova loads today but which one could name at any time
# without any line of this file changing.
#
# The second `not_asserted` is the one that is easy to overclaim: this guard
# compares DIGESTS, so it cannot tell an edit from a repair, and it cannot tell
# a module that was read from one that was merely present. A red here is a true
# statement about bytes and a silent run says nothing about whether those bytes
# are the RIGHT bytes. Only a gate's own check can say that, which is why the
# wording above says "Re-run" and not "revert".
echo "RUN_RACE_GUARD_LIMITS asserted=that_no_path_in_LIBS_14_moved_under_an_object_this_run_built_"
echo "  (STALE_OBJECTS, by_mtime, both_directions);that_no_.nova_module_in_the_two_declared_"
echo "  RUNTIME_MODULES_directories_n=${mod_declared}_changed_bytes_under_this_run_"
echo "  (MODULES_EDITED_DURING_RUN, by_sha256, including_deletions);that_neither_declared_"
echo "  directory_is_missing_or_empty;that_both_predicates_pass_their_own_truth_tables_in_"
echo "  rails_selftest_on_every_invocation. "
echo "  not_asserted=that_the_tree_did_not_move_it_moved_in_every_file_that_is_not_in_LIBS_"
echo "  and_not_in_RUNTIME_MODULES:_the_harness_.c_files_themselves_the_ROOT_GATES_and_"
echo "  NOVA_GATES_sources_every_.sh_every_reference_.bin_and_data_fixture_a_gate_reads_"
echo "  and_every_.nova_outside_toolchain/ntasm-nova_and_its_tests_subdirectory_including_"
echo "  compiler/c/nova/tests/validate-macro-decl-entry.nova_which_no_harness_"
echo "  loads_today;that_a_change_was_a_repair_rather_than_a_regression_this_guard_compares_"
echo "  digests_and_a_digest_cannot_tell_those_two_apart_only_a_gates_own_check_can;that_"
echo "  a_module_was_actually_loaded_rather_than_simply_present_a_clean_run_is_silence_not_"
echo "  a_receipt;that_libsonly_is_guarded_at_all_it_exits_before_the_end_of_run_comparison_"
echo "  because_it_runs_no_gate_and_loads_no_module. A guard that published only what it "
echo "  covers would read as universal, and this one is not universal. Green means: of the "
echo "  files listed above, none moved. It does not mean the tree stood still."

# The census rail, run every time, printing its queue and NEVER failing on it.
#
# WHY IT IS HERE AND NOT AS A GATE. The rail's specification refuses five things
# and the first is THE CLASS OF A GATE. A gate that reported a queue as a failure
# would be making the judgement the rail refuses to make, and every reader would
# then treat a queue as a verdict. So it prints, and its verdict on its own queue
# is deliberately not consulted: the output is a QUEUE.
#
# WHY IT IS HERE AT ALL. Without this line the rail is a script nobody runs,
# which is the same defect this driver already had with nova_corpus_convergence
# -- evidence produced and never read. The rail exists to make the hand-entered
# census cells REVIEWABLE, and a cell nobody can see is not reviewable.
#
# WHY IT CANNOT BE A MEMBER OF NOVA_GATES, and this is a MEASUREMENT rather
# than a preference, because the obvious fix is to register it and that fix is
# WRONG. NOVA_GATES is not a list of things the driver runs; it is a list of
# C HARNESSES the tests_ntasm_ NAME FILTER cannot see, and it carries a PATH
# RULE with it. Measured 30 September 2026: a NOVA_GATES member resolves to
# $root/nova/<name>.c, so `census_rail` would resolve to
# compiler/c/nova/census_rail.c, which does not exist -- the rail is
# a PYTHON FILE at legacy/tools/coldproof/census_rail.py, not a harness under $root.
# Registering it there would therefore not register it; it would make the run
# red on a MISSING_DECLARED_GATE for a file that is present and working, and
# clause (c) would raise DECLARED_GATE_OWNED_BY_NAME_FILTER besides, because
# tests_ntasm_census_rail.c does not exist either. The census instrument cannot
# be registered in the form the C gates use, so the registration is done in
# the form the rail's own contract allows: it is DECLARED, its presence is
# ASSERTED, and its refusal sets fail. What it asserts is untouched.
#
# WHAT IT DOES NOT DO. It never sums DISAGREE and SINGLE, and it never repairs a
# cell. Both are refusals in its own specification and both are load bearing:
# adding the two is what made the census's own tally read as a finding.
# ABSENCE IS RED, and the path is anchored to $REPO. Both halves are one fix
# for one measured defect. This block guarded itself with a RELATIVE path
# (`legacy/tools/coldproof/census_rail.py`) inside `if [ -f ... ]`, and this script
# says at :183 that it may be RUN FROM ANYWHERE -- so from any working
# directory but the repository root the test was FALSE, the whole census block
# was SKIPPED, and the run ended GATES_DONE fail=0 having never once looked at
# the census. Measured 30 September 2026: `cd /tmp && NG_REPO=<repo> ngbuild.sh
# registry` printed ZERO lines matching POPULATION|census rail, and the silent
# skip is indistinguishable from a rail that found nothing -- which is the one
# answer this instrument is not allowed to invent, and the same reason
# MODULE_DIR_VOID above is red. Anchoring to $REPO fixes the resolution, and
# making a missing rail RED fixes the class: a census that stops covering the
# population must not be able to report itself as a census that was fine.
#
# Not a widened refusal: the rail still never fails on its own QUEUE, which is
# the one judgement its specification refuses. What is red here is the rail
# being ABSENT, which is a different event and was previously silent.
CENSUS_RAIL="$REPO/legacy/tools/coldproof/census_rail.py"
if [ -f "$CENSUS_RAIL" ]; then
    # `set -euo pipefail` is in force at :184, and a command substitution whose
    # command FAILS aborts the script THERE -- `census_rc=$?` on the next line is
    # never reached. Measured: the rail refuses on an unclosed population, the
    # driver died silently before printing GATES_DONE, and the run looked like a
    # truncated capture rather than a refusal. So the exit status is taken in the
    # GUARDED position, which is the form that does not abort.
    census_rc=0
    census_out=$(python3 "$CENSUS_RAIL" --queue=4 2>&1) || census_rc=$?
    # The per-cell BLOCKS are the deliverable, not the counts. R24 §5.3 makes a cell
    # reviewable by printing, for that cell alone, its evidence -- the verdicts,
    # the per-gate digest, the edit state -- and this filter was DROPPING THEM:
    # it passed through the five count lines and nothing beginning `gate=`, so the
    # reader saw the tally the specification explicitly refuses to rely on and
    # none of the evidence that would let them disagree with a cell.
    #
    # The five refusals are why each token is printed on its own line: a cell's
    # evidence can contain `|`, so piping the blocks through anything that
    # reformats them would silently corrupt them.
    printf '%s\n' "$census_out" | grep -aE '^(POPULATION|TALLY_FROM_TABLE|EDIT_STATE|QUEUE_|SUM |RAIL_LIMITS|gate=)' || true
    if [ "$census_rc" != 0 ]; then
        echo "CENSUS_RAIL_ERROR rc=$census_rc -- the rail REFUSED rather than reporting an"
        echo "  unclosed denominator, which is one of its five refusals working. The queue"
        echo "  above is therefore incomplete and the cells are NOT reviewable right now."
        red RAIL CENSUS_RAIL_ERROR
    else
        echo "  census rail: printed, not consulted. A queue is not a verdict, and a rail"
        echo "  that failed on its own queue would be making the judgement it refuses."
    fi
else
    echo "CENSUS_RAIL_ABSENT $CENSUS_RAIL does not exist, so the census was NOT"
    echo "  consulted on this run. This is red rather than skipped on purpose: a"
    echo "  census that cannot be run is not a census that found nothing, and"
    echo "  reporting it as silence is the gap this line exists to close."
    red RAIL CENSUS_RAIL_ABSENT
fi
# --------------------------------------------------------------------------
# THE S0 FIXED POINT, RE-ATTESTED OR NOT -- AND THE BANNER SAYS WHICH ONE.
#
# WHAT WAS MISSING, and it was measured before this block was written:
# `grep -c 'fixed-point\|FIXED_POINT' legacy/tools/coldproof/ngbuild.sh` returned 0.
# A PUBLISHED BOUND -- two PE, a byte count and a sha256, deposited in the tree
# so that a reader could check them -- was named by NOTHING here. Nothing re-read
# those bytes, so an edit to them, or to the document that publishes them,
# moves the claim without moving a single count in this file. That is the
# failure this driver has been closing all night, in its most literal form: an
# artefact nothing checks drifts silently, because silence is what it reads as.
#
# WHY IT IS NOT A NOVA_GATES MEMBER, which repeats the census rail's
# MEASUREMENT instead of borrowing its conclusion. A NOVA_GATES member resolves
# to $root/nova/<name>.c (resolve_gate, above), so registering this would look
# for compiler/c/nova/<name>.c -- a C harness in the quarantine this
# project does not write to, for a claim that contains no C at all -- and would
# make the run red on DECLARED_GATE_FILE_ABSENT for a check that is present and
# working. So it lives HERE, beside the census rail: DECLARED, ASSERTED, run on
# every invocation, path-anchored to $REPO exactly like CENSUS_RAIL, because
# this script may be RUN FROM ANYWHERE (:183) and a relative path would make
# the whole block vanish silently from any other working directory.
#
# THREE STATES, because a gate that silently skips is worse than one that is
# red, and because a reader who cannot tell "re-attested" from "not
# re-attested" has been handed the same sentence either way.
#   ATTESTED        the recipe RAN here. The toolchain was present, the
#                   producer booted, ::/NTASM1.EFI came back out of the image
#                   it wrote, and that file's sha256 and byte count are the
#                   published pair. Only the recipe can reach this state.
#   ARTEFACTS_ONLY  the recipe COULD NOT run -- the EFI toolchain is absent --
#                   so NOTHING was re-attested, and the banner says so in
#                   words rather than by omission. What IS asserted here, and
#                   is worth asserting: both PE are present, their digests and
#                   byte counts are the ones REPLAY.md and README.md publish,
#                   the two documents agree with each other and with the files,
#                   and the recipe still carries the commands that produce the
#                   expected value. Green in this state is a TRUE AND NARROW
#                   statement -- the published bound is INTACT, not reproduced.
#   BROKEN          something checkable on any host is wrong: an artefact
#                   missing, a digest or a byte count that does not match what
#                   is published, two documents that disagree, a recipe that no
#                   longer carries the step that produces the expected value, or
#                   a toolchain that IS present and a replay that fails.
# BROKEN is the ONLY state that sets fail.
#
# The published pair is read off the DISK, never off this comment, and the two
# documents are checked against each other as well as against the bytes: a
# single source of truth that nothing compares to anything else is exactly the
# shape of the defect this block exists to close.
FP_DIR=${NG_FIXED_POINT_DIR:-$REPO/legacy/ntasm-s0/fixed-point}
FP_HOST="$FP_DIR/compiler-host.NTASM1.EFI"
FP_CORE="$FP_DIR/compiler-core.NTASM1.EFI"
FP_REPLAY="$FP_DIR/REPLAY.md"
FP_README="$FP_DIR/README.md"
# NG_FIXED_POINT_DIR exists so the two negative controls can be run against a
# COPY, which is what makes them honest: a control that had to damage the
# published artefact to prove the gate bites would be a control that risks the
# thing it measures. The default IS the tree, so a run with no environment set
# is a run over the real artefact.
fp_bad=""
fp_note() { fp_bad="${fp_bad}$1 "; }

# THE TOOLCHAIN, named item by item. An EMPTY list here is the only thing that
# makes the ATTESTED branch reachable, so a missing tool can never be confused
# with a passing replay -- it is a different state with its own banner.
fp_missing=""
for fp_t in mkfs.vfat mmd mcopy qemu-system-x86_64 python3 truncate cmp; do
  command -v "$fp_t" >/dev/null 2>&1 || fp_missing="${fp_missing}$fp_t "
done
fp_ovmf_code=${NG_OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
fp_ovmf_vars=${NG_OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
[ -f "$fp_ovmf_code" ] || fp_missing="${fp_missing}$(basename "$fp_ovmf_code") "
[ -f "$fp_ovmf_vars" ] || fp_missing="${fp_missing}$(basename "$fp_ovmf_vars") "

for fp_f in "$FP_HOST" "$FP_CORE" "$FP_REPLAY" "$FP_README" \
           "$REPO/legacy/ntasm-s0/compiler-host.ntasm" \
           "$REPO/legacy/ntasm-s0/modules/compiler-core.ntasm"; do
  [ -f "$fp_f" ] || fp_note "input_absent:${fp_f#"$REPO"/}"
done

fp_host_sha=""; fp_host_bytes=""; fp_core_sha=""; fp_core_bytes=""
fp_pub_produced_sha=""; fp_pub_produced_bytes=""
fp_pub_tree_sha=""; fp_pub_boot_bytes=""; fp_pub_core_bytes=""
fp_readme_host_sha=""; fp_readme_host_bytes=""
fp_readme_core_sha=""; fp_readme_core_bytes=""

# Parsed with awk, and NOT with a regex over the drive-spec colons, which is a
# MEASUREMENT and not a taste. Two instruments in this project's reach disagree
# about the very bytes this gate attests: the `read` tool renders REPLAY.md's
# mtools drive spec as `:::/EFI/BOOT/BOOTX64.EFI` -- three colons -- while the
# bytes on disk carry two. Measured 30 September 2026:
#   sed -n 49p legacy/ntasm-s0/fixed-point/REPLAY.md | tr -cd ':' | wc -c  -> 2
# A parser written from the RENDERED text matches nothing at all, and a gate
# whose parser cannot see the published bytes reports a state that looks like an
# answer. So every row below is matched on the file name and on the numeric
# field, never on the spelling of the drive spec, and every value it publishes
# is printed so a reader can re-derive it by hand.
if [ -z "$fp_bad" ]; then
  fp_host_sha=$(sha256sum "$FP_HOST" 2>/dev/null | cut -d' ' -f1) || fp_note "unreadable:$FP_HOST "
  fp_core_sha=$(sha256sum "$FP_CORE" 2>/dev/null | cut -d' ' -f1) || fp_note "unreadable:$FP_CORE "
  fp_host_bytes=$(wc -c <"$FP_HOST" | tr -d ' ') || fp_note "unreadable:$FP_HOST "
  fp_core_bytes=$(wc -c <"$FP_CORE" | tr -d ' ') || fp_note "unreadable:$FP_CORE "

  while IFS='=' read -r fp_k fp_v; do
    case "$fp_k" in
      produced_bytes) fp_pub_produced_bytes=$fp_v ;;
      produced_sha)   fp_pub_produced_sha=$fp_v ;;
      intree_sha)     fp_pub_tree_sha=$fp_v ;;
      boot_bytes)     fp_pub_boot_bytes=$fp_v ;;
      ntcore_bytes)   fp_pub_core_bytes=$fp_v ;;
      *) : ;;
    esac
  done <<EOF
$(awk '
  /^produced / { for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) { print "produced_bytes=" $i; break } }
  $1 == "sha256" && NR < 20 { print "produced_sha=" $2 }
  /^in-tree/ { print "intree_sha=" $4 }
  /^::.*BOOTX64\.EFI/ { for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) { print "boot_bytes=" $i; break } }
  /^::.*NTCORE\.EFI/ { for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) { print "ntcore_bytes=" $i; break } }
' "$FP_REPLAY")
EOF
  while IFS='=' read -r fp_k fp_v; do
    case "$fp_k" in
      readme_host_bytes) fp_readme_host_bytes=$fp_v ;;
      readme_host_sha)   fp_readme_host_sha=$fp_v ;;
      readme_core_bytes) fp_readme_core_bytes=$fp_v ;;
      readme_core_sha)   fp_readme_core_sha=$fp_v ;;
      *) : ;;
    esac
  done <<EOF
$(awk -F'|' '
  /^\| .compiler-host\.NTASM1\.EFI. \|/ && !seen_host { b = $3; s = $4; gsub(/[^0-9]/, "", b); gsub(/[^0-9a-f]/, "", s); print "readme_host_bytes=" b; print "readme_host_sha=" s; seen_host = 1 }
  /^\| .compiler-core\.NTASM1\.EFI. \|/ && !seen_core { b = $3; s = $4; gsub(/[^0-9]/, "", b); gsub(/[^0-9a-f]/, "", s); print "readme_core_bytes=" b; print "readme_core_sha=" s; seen_core = 1 }
' "$FP_README")
EOF

  for fp_v in "$fp_host_sha" "$fp_core_sha" "$fp_pub_produced_sha" "$fp_pub_tree_sha" \
             "$fp_readme_host_sha" "$fp_readme_core_sha"; do
    case "$fp_v" in *[!0-9a-f]*|"") fp_note "published_digest_is_not_a_digest:$fp_v " ;; esac
    [ "${#fp_v}" = 64 ] || fp_note "published_digest_is_not_64_chars:${#fp_v}:$fp_v "
  done

  # Every one of these compares TWO things that could have been written by two
  # different hands on two different dates. A rule that could only fail by
  # deleting a file would never have caught the drift this is for.
  [ "$fp_pub_produced_bytes" = "$fp_host_bytes" ] || fp_note "replay_published_bytes_vs_the_file:$fp_pub_produced_bytes!=$fp_host_bytes "
  [ "$fp_pub_produced_bytes" = "$fp_pub_boot_bytes" ] || fp_note "replay_internal_bytes_disagree:produced=$fp_pub_produced_bytes bootx64=$fp_pub_boot_bytes "
  [ "$fp_pub_produced_sha" = "$fp_pub_tree_sha" ] || fp_note "replay_internal_digests_disagree:produced=$fp_pub_produced_sha in_tree=$fp_pub_tree_sha "
  [ "$fp_pub_produced_sha" = "$fp_host_sha" ] || fp_note "host_digest_is_not_the_published_one:$fp_host_sha!=$fp_pub_produced_sha "
  [ "$fp_readme_host_sha" = "$fp_pub_produced_sha" ] || fp_note "readme_vs_replay_host_digest:$fp_readme_host_sha!=$fp_pub_produced_sha "
  [ "$fp_readme_host_bytes" = "$fp_pub_produced_bytes" ] || fp_note "readme_vs_replay_host_bytes:$fp_readme_host_bytes!=$fp_pub_produced_bytes "
  [ "$fp_readme_core_bytes" = "$fp_pub_core_bytes" ] || fp_note "core_bytes_readme_vs_replay_mdir:$fp_readme_core_bytes!=$fp_pub_core_bytes "
  [ "$fp_readme_core_bytes" = "$fp_core_bytes" ] || fp_note "core_bytes_doc_vs_file:$fp_readme_core_bytes!=$fp_core_bytes "
  [ "$fp_readme_core_sha" = "$fp_core_sha" ] || fp_note "core_digest_is_not_the_published_one:$fp_core_sha!=$fp_readme_core_sha "
  [ "$fp_host_sha" != "$fp_core_sha" ] || fp_note "the_two_artefacts_are_byte_identical "

  # THE RECIPE STILL DESCRIBES A RECIPE. Each of these is a command whose
  # absence means the documented path to the expected value is broken: without
  # the extraction step there is nothing to compare, and without the comparison
  # there is no fixed point at all.
  for fp_need in "mkfs.vfat -F 16" "mmd -i esp.img ::/EFI/BOOT" \
                 "mcopy -i esp.img ::/NTASM1.EFI produced.EFI" \
                 "cmp produced.EFI" "qemu-system-x86_64" "NG_NTASM_NATIVE_SCAN_OK"; do
    awk -v n="$fp_need" 'index($0, n) { found = 1; exit } END { exit found ? 0 : 1 }' "$FP_REPLAY" \
      || fp_note "recipe_step_absent:$fp_need "
  done
fi

# THE REPLAY, which is the only path to ATTESTED. It is the recipe of REPLAY.md
# step for step -- ESP, payload, the read-the-payload-back control, the boot,
# the MARKER as the exit condition, HMP quit, and the extraction of the produced
# file. It runs under $BUILD, which is inside out/, because AGENTS.md forbids a
# persistent runner outside out/ and a recipe executed by the driver is not one.
fp_port=$(( 54961 + $$ % 997 ))
fp_replay() {
  fp_run_rc=0; fp_run_sha=""; fp_run_bytes=""
  mkdir -p "$1"
  (
    set -e
    cd "$1"
    truncate -s 32M esp.img
    mkfs.vfat -F 16 -n EFX esp.img
    mmd -i esp.img ::/EFI
    mmd -i esp.img ::/EFI/BOOT
    mcopy -i esp.img "$FP_HOST" ::/EFI/BOOT/BOOTX64.EFI
    mcopy -i esp.img "$FP_CORE" ::/NTCORE.EFI
    mcopy -i esp.img "$REPO/legacy/ntasm-s0/compiler-host.ntasm" ::/NTASM1.NTASM
    mcopy -i esp.img ::/EFI/BOOT/BOOTX64.EFI check-host.efi
    cmp check-host.efi "$FP_HOST"
    cp "$fp_ovmf_vars" vars.fd
    qemu-system-x86_64 -machine q35,accel=tcg -cpu max -m 256M \
      -drive if=pflash,format=raw,unit=0,readonly=on,file="$fp_ovmf_code" \
      -drive if=pflash,format=raw,unit=1,file=vars.fd \
      -drive if=virtio,format=raw,file=esp.img \
      -boot order=c,menu=off -nic none -display none \
      -monitor tcp:127.0.0.1:"$fp_port",server=on,wait=off \
      -serial file:serial.log -d guest_errors -D qemu.log \
      -no-reboot -no-shutdown &
    # Ce QEMU survivait à tout échec (marqueur absent en 240 s, quit refusé par le port moniteur) : 46 instances
    # comptées le 4 octobre 2026. Il est tué à la sortie du sous-shell, sur tous les chemins.
    fp_qemu=$!
    trap 'kill "$fp_qemu" 2>/dev/null; wait "$fp_qemu" 2>/dev/null' EXIT
    fp_i=0
    while [ "$fp_i" -lt 240 ]; do
      grep -q NG_NTASM_NATIVE_SCAN_OK serial.log 2>/dev/null && break
      fp_i=$((fp_i + 1)); sleep 1
    done
    grep -q NG_NTASM_NATIVE_SCAN_OK serial.log || { echo "no-marker-in-serial-log"; exit 3; }
    python3 -c "import socket
s = socket.create_connection(('127.0.0.1', $fp_port), timeout=8); s.settimeout(5)
try: s.recv(65536)
except Exception: pass
s.sendall(b'quit\n')
try: s.recv(65536)
except Exception: pass
s.close()" || true
    mcopy -i esp.img ::/NTASM1.EFI produced.EFI
  ) >"$1/replay.log" 2>&1 || fp_run_rc=$?
  if [ "$fp_run_rc" = 0 ] && [ -f "$1/produced.EFI" ]; then
    fp_run_sha=$(sha256sum "$1/produced.EFI" | cut -d' ' -f1)
    fp_run_bytes=$(wc -c <"$1/produced.EFI" | tr -d ' ')
  fi
}

fp_state=BROKEN
if [ -n "$fp_bad" ]; then
  fp_state=BROKEN
elif [ -n "$fp_missing" ]; then
  fp_state=ARTEFACTS_ONLY
else
  fp_run_dir="$BUILD/fixed-point-$$"
  fp_replay "$fp_run_dir"
  if [ "$fp_run_rc" != 0 ]; then
    fp_state=BROKEN
    fp_note "the_recipe_ran_and_failed:rc=$fp_run_rc,log=$fp_run_dir/replay.log "
  elif [ "$fp_run_sha" != "$fp_pub_produced_sha" ]; then
    fp_state=BROKEN
    fp_note "reproduced_digest_is_not_the_published_one:$fp_run_sha!=$fp_pub_produced_sha "
  elif [ "$fp_run_bytes" != "$fp_pub_produced_bytes" ]; then
    fp_state=BROKEN
    fp_note "reproduced_bytes_are_not_the_published_count:$fp_run_bytes!=$fp_pub_produced_bytes "
  else
    fp_state=ATTESTED
  fi
fi

case "$fp_state" in
  ATTESTED)
    echo "S0_FIXED_POINT ATTESTED  recipe_ran=YES  re_attested=YES  toolchain_absent=none"
    ;;
  ARTEFACTS_ONLY)
    echo "S0_FIXED_POINT ARTEFACTS_ONLY  recipe_ran=NO  re_attested=NO  -- NOT RE-ATTESTED"
    echo "  The producer was NOT run on this host, so nothing here re-attests the"
    echo "  bound; the EFI toolchain the recipe needs is absent:${fp_missing}"
    echo "  What IS asserted, and is the whole of this state: both PE are present,"
    echo "  their digests and byte counts are the published ones, REPLAY.md and"
    echo "  README.md agree with each other and with the files, and the recipe"
    echo "  still carries the commands that produce the expected value."
    ;;
  BROKEN)
    echo "S0_FIXED_POINT BROKEN  recipe_ran=NO  re_attested=NO  fail=1"
    ;;
esac
echo "  fixed_point_dir=$FP_DIR"
echo "  measured compiler-host.NTASM1.EFI bytes=$fp_host_bytes sha256=$fp_host_sha"
echo "  measured compiler-core.NTASM1.EFI bytes=$fp_core_bytes sha256=$fp_core_sha"
echo "  published REPLAY.md produced_bytes=$fp_pub_produced_bytes produced_sha256=$fp_pub_produced_sha in_tree_sha256=$fp_pub_tree_sha"
echo "  published REPLAY.md esp_bootx64_bytes=$fp_pub_boot_bytes esp_ntcore_bytes=$fp_pub_core_bytes"
echo "  published README.md host_bytes=$fp_readme_host_bytes host_sha256=$fp_readme_host_sha core_bytes=$fp_readme_core_bytes core_sha256=$fp_readme_core_sha"
if [ -n "$fp_bad" ]; then
  for fp_r in $fp_bad; do echo "  BROKEN reason: $fp_r"; done
  red RAIL S0_FIXED_POINT_BROKEN
fi
if [ "$fp_state" = ATTESTED ]; then
  echo "  replayed bytes=$fp_run_bytes sha256=$fp_run_sha == published; dir=$fp_run_dir"
fi
echo "  not_asserted=that_the_recipe_ran_on_this_host;that_the_published_digest_is_the_right_one_REPLAY.md_is_the_result_and_not_an_independent_input_so_this_is_determinism_not_the_correctness_of_the_launcher;that_any_component_other_than_these_two_PE_is_covered(module-host_native-lexer_native-source_are_out_of_scope_by_REPLAY.md's_own_words)."
# --------------------------------------------------------------------------
# THE LINE-TERMINATOR CENSUS -- THE PROJECT FORBIDS MIXED TERMINATORS, AND
# NOTHING HERE MEASURED THEM.
#
# THE CITATION, checked against the file instead of against the brief. The brief
# said "AGENTS.md:13 forbids mixed line terminators"; `sed -n 13p AGENTS.md` is
# "de « conserver l'état courant, le dernier gate vert et la prochaine étape", a
# fragment of the ZÉRO QUESTION rule with nothing about terminators in it. The
# real anchors are AGENTS.md:33-47 and AGENTS.md:154-164. A citation into the
# wrong line is AGENTS.md:21-31 in another hat -- a number read in the wrong
# field, which still LOOKS like a number, so it has to be re-read before it is
# shipped, exactly like any other one.
#
# WHAT WAS MISSING, and it was measured before this block was written: on the
# night of 30 September 2026 six files drifted to MIXED terminators -- one of
# them MEM.md, which went from uniform LF to 6465 CRLF against 141 bare LF --
# and the only reason any of it was found is that a human compared what he
# believed he had written against what he had actually written. Every one of
# those files still compiled and every gate still passed. AGENTS.md:33-47 records
# the same hazard from the other side: `edit` NORMALISED all 684 terminators of
# parser.nova without saying so and reported SUCCESS. So a hazard with no
# instrument is a hazard waiting, in both directions at once.
#
# WHY IT IS NOT A NOVA_GATES MEMBER, which repeats the census rail's
# MEASUREMENT rather than borrowing its conclusion. A NOVA_GATES member resolves
# to $root/nova/<name>.c (resolve_gate, above), so registering this would look
# for compiler/c/nova/eol_rail.c -- a C harness in the quarantine this
# project does not write to, for an instrument that is PYTHON -- and would make
# the run red on DECLARED_GATE_FILE_ABSENT for a check that is present and
# working. It lives HERE, beside the census rail and the S0 block: DECLARED,
# ASSERTED, path-anchored to $REPO exactly like CENSUS_RAIL, because this script
# may be RUN FROM ANYWHERE (:183) and a relative path would make the whole block
# vanish silently from any other working directory.
#
# ABSENCE IS RED, for the reason the census block's is: a terminator census that
# cannot be run is not a census that found nothing, and reporting it as silence is
# the gap this line exists to close.
#
# THREE STATES, named in the rail's own banner and reprinted here, and only one
# of which sets fail:
#   UNIFORM_LF          the norm.
#   NO_FINAL_NEWLINE    uniform LF but the last line is unterminated. REPORTED,
#                       NOT RED: AGENTS.md:33-47 forbids MIXED, not a missing final
#                       newline -- and this state is NOT EMPTY on this host.
#                       compiler/nova/inspectors/nxo_inspect.nova carries it, so red
#                       here would be a gate permanently red, which is a defect
#                       rather than a measurement.
#   OFF_NORM            CRLF / bare CR / a MIXTURE in live source with no fixture
#                       evidence. THE ONLY RED STATE.
# Two further strata are REPORTED and never red: FIXTURE_EVIDENCED (off-norm but
# cited as a fixture from outside itself -- normalising those deletes the test,
# and the citing path is printed so the exemption is never silent) and SNAPSHOT
# (verifieur/, 2841 files read and censused on every run, dated evidence left as
# found).
#
# WHAT IT ADDS TO THE RUN, measured: walk_s=3.3 read_s=2.4, elapsed_s=4.2 to 6.6
# against a ~508 s suite. It says plainly which stratum it did NOT walk: out/ is
# 133 598 files, 97% of the tree, PRUNED AT THE WALK LEVEL and never opened. The
# file count it prints is STAMPED and carries count_age_s, because a count of out/
# costs 95 s to 223 s to obtain and an undated cached number in a banner reads as
# a measurement of this run when it is not one.
EOL_RAIL="$REPO/legacy/tools/coldproof/eol_rail.py"
if [ -f "$EOL_RAIL" ]; then
    eol_rc=0
    eol_out=$(python3 "$EOL_RAIL" 2>&1) || eol_rc=$?
    # The filter passes EVERY line the rail prints: its own `EOL_` banners and
    # every indented line under them. My first filter enumerated the indented
    # keys by name and SILENTLY DROPPED eight of the most load-bearing lines --
    # the seven `state <shape> <n>` tallies and the snapshot shape breakdown.
    # Those tallies ARE the population split; a banner that counts the files and
    # hides how they divide is the "uniform distribution" shape AGENTS.md:135
    # warns looks like a perfect measurement. Enumerating keys in a filter is
    # the same stale-list mistake as enumerating fixtures by hand: a new key is
    # dropped without anything saying so.
    printf '%s\n' "$eol_out" | grep -aE '^(EOL_|[[:space:]])' || true
    if [ "$eol_rc" = 1 ]; then
        echo "EOL_OFF_NORM_IN_LIVE_SOURCE fail=1 -- the terminator census refused."
        red RAIL EOL_OFF_NORM_IN_LIVE_SOURCE
    elif [ "$eol_rc" != 0 ]; then
        echo "EOL_RAIL_ERROR rc=$eol_rc -- the census REFUSED rather than reporting"
        echo "  a population it could not close, which is never reported as a pass."
        red RAIL EOL_RAIL_ERROR
    else
        echo "  terminator census: printed, and green. A green here means no live"
        echo "  source file carries mixed CRLF/LF/CR terminators; it says nothing"
        echo "  about the out/ stratum, which was not walked, and nothing about"
        echo "  whether the snapshot stratum is uniform, which is reported."
    fi
else
    echo "EOL_RAIL_ABSENT $EOL_RAIL does not exist, so the terminator census was NOT"
    echo "  run on this invocation. This is red rather than skipped on purpose: a"
    echo "  census that cannot be run is not a census that found nothing."
    red RAIL EOL_RAIL_ABSENT
fi
#
# THE DELIVERY-VERDICT FALSIFIER, and what it is worth. This block exists
# because of a measurement, not a preference. `docs/status/ntasm-completion.md` is the
# document that decides whether B2.1 is delivered, and since the tables were
# rewritten it carries EXACTLY ONE verdict per requirement, in a four-word
# closed vocabulary. Measured on the 30th of September 2026, the repository's
# own coherence check reads not one of those words:
# `grep -cE 'livré|partiel|bloqué|non commencé' compiler/c/nova/
# tests_ntasm_registry.c` returns 0, and check_doc_structure reads geometry,
# section anchors, links and citations. So before this block, a delivery verdict
# was a COMMENT: nothing in the tree could falsify the words that decide the
# delivery, and the run ended GATES_DONE fail=0 while saying nothing about them.
#
# WHY IT IS NOT A NOVA_GATES MEMBER, which repeats the census rail's and the
# terminator rail's MEASUREMENT rather than borrowing their conclusion. A
# NOVA_GATES member resolves to $root/nova/<name>.c (resolve_gate, above), so
# registering this would look for compiler/c/nova/verdict_check.c --
# a C harness in the quarantine this project does not write to, for an
# instrument that is PYTHON -- and would make the run red on
# DECLARED_GATE_FILE_ABSENT for a check that is present and working. It lives
# HERE, beside the census rail, the S0 block and the terminator rail: DECLARED,
# path-anchored to $REPO exactly like CENSUS_RAIL and EOL_RAIL, because this
# script may be RUN FROM ANYWHERE and a relative path would make the whole block
# vanish silently from any other working directory.
#
# WHAT IT ADDS, and it is small: a PYTHON process and one file read, against a
# ~508 s suite. Its eight rules (R1 vocabulary, R2 one word per row, R3 BACKED,
# R4 LIVRE-CONTRADICTED, R5 NON-COMMENCE-CONTRADICTED, R6 BLOQUE-NO-MISSING,
# R7 entry/row agreement, R8 row-set closure) each cite the line of the document
# they are read from, in the check's own banner. Its ONE red state is a FINDING;
# its QUEUE lines are printed and never red, and its two refused strata (R9
# `partiel` with no resolving artefact, R10 a dated scope) are named in its
# header with the reason they are not enforced -- an instrument that hides the
# stratum it refuses to walk is one stratum smaller than its author believes.
#
# ABSENCE IS RED, for the census block's reason: a falsifier that cannot be run
# is not a falsifier that found nothing.
#
# THE FILTER prints the whole output, which is short and fixed-width: the matrix,
# the SCOPE lines, the QUEUE lines and the FINDING lines. Enumerating the keys by
# name, which is what the terminator rail's first filter did and silently dropped
# eight of its most load-bearing lines, is the stale-list mistake this project has
# already paid for once.
VERDICT_CHECK_RAIL="$REPO/legacy/tools/coldproof/verdict_check.py"
if [ -f "$VERDICT_CHECK_RAIL" ]; then
    verdict_rc=0
    verdict_out=$(python3 "$VERDICT_CHECK_RAIL" 2>&1) || verdict_rc=$?
    printf '%s\n' "$verdict_out" || true
    if [ "$verdict_rc" = 1 ]; then
        echo "VERDICT_CHECK_FINDING fail=1 -- the delivery verdicts of"
        echo "  docs/status/ntasm-completion.md contradict the document's own rules. Each"
        echo "  FINDING line above names its rule and its row."
        red RAIL VERDICT_CHECK_FINDING
    elif [ "$verdict_rc" != 0 ]; then
        echo "VERDICT_CHECK_REFUSED rc=$verdict_rc -- the falsifier REFUSED rather"
        echo "  than reporting a document it could not read, which is never a pass."
        red RAIL VERDICT_CHECK_REFUSED
    else
        echo "  delivery verdicts: read, and consistent with their own evidence."
        echo "  A green here means every row's verdict agrees with its evidence entry"
        echo "  and every entry names a command or an artefact; it says nothing about"
        echo "  the two refused strata, which are named in the check's header, nor"
        echo "  about the Historique section, which was deliberately not read."
    fi
else
    echo "VERDICT_CHECK_ABSENT $VERDICT_CHECK_RAIL does not exist, so the delivery"
    echo "  verdicts were NOT falsified on this invocation. This is red rather than"
    echo "  skipped on purpose: a falsifier that cannot run is not one that passed."
    red RAIL VERDICT_CHECK_ABSENT
fi

# THE TERMINATOR -- A COUNT AND A LIST, AND THE `fail=` TOKEN LEFT ALONE.
#
# `GATES_DONE fail=$fail` is unchanged and stays on its own line, for readers
# that already exist and were found before this was written: AGENTS.md:77
# (`grep -a '^GATES_DONE' log`), coldsuite.sh:59 and runall.sh:14 (both grep the
# literal token), and the prose in MEM.md and docs/ which quotes `fail=0` and
# `fail=1` as the whole of the verdict. The line is a BOOLEAN and every one of
# those readers is reading a boolean off it. So the token keeps its exact shape
# and the quantity arrives on lines of its own, where a boolean reader never
# looks and a reader who wants to know WHICH is not left to reconstruct it.
#
# The three classes are printed under separate headings on purpose. A run-race
# GUARD and a red GATE both set fail=1, and they are not the same statement: the
# guard says a file moved while this run was reading it, which makes the run's
# answers untrustworthy WITHOUT saying any gate is broken, while a red gate says
# a check failed. Counting them together is the defect this block exists to
# close -- a reader who sees `fail=1` and two gate names and one guard name in an
# undifferentiated list cannot tell whether the tree is broken or merely moving.
#
# ORDER. A run's guard precedes its symptoms by construction, so the GUARD
# section is printed FIRST: the reader learns whether the run may be believed
# before learning what it says.
#
# FOURTH CLASS: INTERRUPTED. A gate that exited non-zero WITH a banner is red --
# it finished, and its count is its answer. A gate that exited non-zero with NO
# banner never reached its first summary line: it crashed, or setup killed it.
# Its exit status says it did not finish, not that anything failed, so calling
# it red would report a crash as a verdict. Calling it silent would report a
# dead gate as a green one. It is its own class, and the owner asked for exactly
# this: RÉUSSI / ÉCHOUÉ / INTERROMPU / NON EXÉCUTÉ. A gate that reaches its
# banner with failures=0 is RÉUSSI and appears nowhere in this list, which is
# why the green count is stated rather than inferred from the total.
#
# NOT EXECUTED is not a register entry and cannot be: a gate that never ran
# leaves no line here. It is bounded instead, by the declared population
# printed above, and GATES_RED_NOT_RUN below says how many of the declared
# gates the register never heard from. A red register and a complete
# declaration are different claims, and only the second one is a coverage claim.
red_gates=0; red_rails=0; red_guards=0; red_interrupted=0
red_seen=0
while IFS=$'\t' read -r rc_name rc_item; do
  red_seen=$((red_seen + 1))
  case "$rc_name" in
    GATE)  red_gates=$((red_gates + 1)) ;;
    RAIL)  red_rails=$((red_rails + 1)) ;;
    GUARD) red_guards=$((red_guards + 1)) ;;
    INTERRUPTED) red_interrupted=$((red_interrupted + 1)) ;;
  esac
done <"$RED_LIST"
red_total=$((red_gates + red_rails + red_guards + red_interrupted))

echo "GATES_RED total=$red_total gates=$red_gates rails=$red_rails guards=$red_guards interrupted=$red_interrupted"
if [ "$red_interrupted" -gt 0 ]; then
  echo "GATES_RED_INTERRUPTED count=$red_interrupted -- a gate exited non-zero with NO"
  echo "  banner, so it never reached its summary line. It is NOT a red check: it is"
  echo "  a gate that did not finish, and its exit status says only that. Fix or"
  echo "  restore it before reading anything else as a measurement of the tree."
  while IFS=$'\t' read -r rc_name rc_item; do
    [ "$rc_name" = INTERRUPTED ] && echo "GATES_RED_ITEM INTERRUPTED $rc_item"
  done <"$RED_LIST"
fi
if [ "$red_guards" -gt 0 ]; then
  echo "GATES_RED_GUARD count=$red_guards -- a file moved under this run. These do NOT"
  echo "  say a gate is broken; they say this run's answers are for a tree that was"
  echo "  moving while it read them. Re-run before believing anything below."
  while IFS=$'\t' read -r rc_name rc_item; do
    [ "$rc_name" = GUARD ] && echo "GATES_RED_ITEM GUARD $rc_item"
  done <"$RED_LIST"
fi
if [ "$red_gates" -gt 0 ]; then
  echo "GATES_RED_GATE count=$red_gates"
  while IFS=$'\t' read -r rc_name rc_item; do
    [ "$rc_name" = GATE ] && echo "GATES_RED_ITEM GATE $rc_item"
  done <"$RED_LIST"
fi
if [ "$red_rails" -gt 0 ]; then
  echo "GATES_RED_RAIL count=$red_rails -- instruments, not gates. A rail that refused"
  echo "  or is absent says the CHECK did not complete; it does not say a gate failed."
  while IFS=$'\t' read -r rc_name rc_item; do
    [ "$rc_name" = RAIL ] && echo "GATES_RED_ITEM RAIL $rc_item"
  done <"$RED_LIST"
fi
if [ "$red_total" -eq 0 ]; then
  echo "GATES_RED_ITEM none"
  echo "  Zero is a COUNT here, not a boolean: zero red gates out of the population"
  echo "  declared above, zero red rails, zero guards fired, zero interrupted. The"
  echo "  guards' silence is what it says, and RUN_RACE_GUARD_LIMITS above says how"
  echo "  far that silence reaches. A guard that watched nothing is not a guard that"
  echo "  found nothing."
fi
_NG_TERMINATED=1
echo "GATES_DONE fail=$fail"
exit $fail
