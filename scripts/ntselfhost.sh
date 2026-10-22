#!/usr/bin/env bash
# Nexora Genesis - the fixed point of the final producer, checked.
#
# It writes nothing outside out/. It is invoked, never resident: no daemon, no
# scheduled task, no state kept in the source tree. It is called by the build
# (scripts/ntbuild.sh, command `build`), so the check is not something a person
# has to remember, and it can be run alone with `ntbuild.sh selfhost`.
#
# ---------------------------------------------------------------------------
# What "a fixed point" means here, because the phrase is not a test
# ---------------------------------------------------------------------------
# Let S be the source of a producer P, and C a fixed corpus: a finite set of
# programs, each of which is a set of compilation units given to one assemble.
#
#   R1  reproducibility    for any two clean runs, P(C) is byte-identical.
#   R2  producer           P_a(C) == P_b(C) bytewise for two DISTINCT producer
#       independence       binaries P_a != P_b. The product bytes are a function
#                          of the source text, not of the build that made the
#                          producer.
#   F   fixed point        P_1 = P_0(S) and P_2 = P_1(S), and P_2 == P_1
#                          bytewise. The producer, rebuilt by itself out of its
#                          own source, reproduces itself exactly.
#
# F is what A8(4) asks for. It is strictly stronger than R1+R2, and this script
# does not prove it - but it no longer ASSERTS that it does not. The block
# below used to write `fixed_point_proven=no` in a literal, outside every
# condition: a constant that is right on every run and has therefore never been
# tested once. It is now a verdict read from a record the BUILD wrote - which
# compiler produced each generation, by path and by digest - and re-digested
# here from the file that record names. It can answer no, UNKNOWN or yes, and
# the two are different claims: `no` is a measurement and `UNKNOWN` is this
# run declining to have one. See "THE BOUNDARY, MEASURED" below.
#
# ---------------------------------------------------------------------------
# The producer
# ---------------------------------------------------------------------------
# A8 says "le producteur final". AGENTS.md names it: NASM is "un producteur
# temporaire quarantaine, ... jamais le producteur final". The final producer
# of this project is NTASM itself - the assembler that emits our binaries.
# Nova is a separate compiler, not the assembler, so `nova.c` is not this
# producer; the brief's alternative reading is rejected on that ground.
#
# ---------------------------------------------------------------------------
# The shape of the gap - and this paragraph is NOT the evidence
# ---------------------------------------------------------------------------
# Read this for why the gap is shaped the way it is. Do not cite it as proof
# that the gap is there: it was the only thing behind the verdict for as long
# as the verdict was a literal, and a paragraph cannot be perturbed, so a
# paragraph cannot be wrong in a way a run would catch. What the run now
# reports is "who built the generations", read from the build's own record -
# see "THE BOUNDARY, MEASURED" below, which can answer `no` and can answer
# `UNKNOWN`, and the difference between those two is the whole point.
#
# F needs the producer's source in a language the producer consumes. Today the
# producer is the C bootstrap, built from 16 C translation units by gcc, and it
# consumes .ntasm in the v0 dialect. It cannot consume C.
#
# This is measured, not assumed. Assembling the NTASM S0 sources - the only
# NTASM-language producer sources in the tree - with the v0 producer gives:
#
#   legacy/ntasm-s0/compiler-host.ntasm:1:1: E200: expected 'module'
#
# so the v0 producer and the S0 producer do not even share a dialect. There is
# no common corpus on which the C producer and an NTASM producer could be shown
# to agree, because there is no program both will accept. F becomes reachable
# only when the producer's source is written in NTASM (or in Nova, once NTASM
# can itself be built by Nova - the port AGENTS.md already mandates).
#
# The historical S0 fixed point IS a property of this tree's bytes. An earlier
# version of this comment said otherwise, on the grounds that
# out/ntasm/native-selfhost-checkpoint.md records compiler-host.ntasm at
# 36073 bytes / 7254902a... while the file on disk is 43793 / 1d72d975....
# The premise was right and the conclusion was wrong: that 12:02 checkpoint is
# SUPERSEDED, not invalidated, and the same fixed point was re-established at
# 14:38-14:39 the same day over the bytes that are still in the tree:
#
#   out/ntasm/agent-release-integration/audit/token-provenance.csv
#     stage2/stage3 compiler-host  43793 1d72d975... -> 17408 82826f45...
#     stage2/stage3 compiler-core  54798 fc1c5d5a... -> 20992 a02425be...
#
# Both generations produce byte-identical binaries, and the chain is genuinely
# self-referential rather than a restatement:
#   out/ntasm/token-limit-stage2/environment.json candidate_path ->
#     recovery-intraline-stage3/.../produced-NTASM1.EFI
#   out/ntasm/token-limit-stage3/environment.json candidate_path ->
#     token-limit-stage2/.../produced-NTASM1.EFI
# so P_0 = P_1(S) = P_2(S) = 82826f45... / a02425be....
#
# What is still unproven is a replay TODAY: the S0 producer is a quarantined
# NASM build that this project correctly refuses to build (ntbuild.sh:85 and
# :764-765, the selftest case "producer is NASM"), so reproducing it needs QEMU
# + OVMF out of band. "Not re-run
# today" is not the same claim as "cannot be repeated", and only the first is
# true. A frozen replayable package is at
# out/ntasm/agent-release-integration/package/ with the replay command in
# out/ntasm/agent-release-integration/checkpoint.md.
#
# ---------------------------------------------------------------------------
# What this script therefore proves
# ---------------------------------------------------------------------------
# R1 and R2 on the accessible producer, against a pinned corpus:
#   - RUN A: clean, build at -O2. Assemble the corpus. Digest each output.
#   - RUN B: clean, build at -O0. Assemble the corpus. Digest each output.
#   - the two producers are REQUIRED to differ, or the convergence is vacuous;
#   - A[i] == B[i] for every i, bytewise: producer independence;
#   - A[i] == pin[i] for every i: the bytes are also the recorded ones, so a
#     producer that is deterministically wrong fails rather than agreeing with
#     itself;
#   - the producer is rebuilt a third time at the caller's level and must
#     reproduce the caller's digest, or the build fails.
#
# ---------------------------------------------------------------------------
# What the source list changed, and what it did not
# ---------------------------------------------------------------------------
# Until 28 September 2026 a corpus member was one FILE by construction: the
# build synthesised `examples/ntasm-v0/c-bootstrap/$name.ntasm` and this script
# passed that single path to a single `assemble`. The strongest artefact A9
# holds - app.ntasm + math.ntasm, a module importing another, which boots and
# returns 42 - therefore could not be pinned at all, and was re-checked by hand.
#
# A member is now a SET of compilation units, '+'-joined in the corpus row and
# handed to one `assemble` in the order written. `multi-app-math` is the first
# member whose path is a list, and that is what changes the shape of the check.
#
# IT NOW PROVES, which it did not before: that a two-module program - a
# cross-module import, a function resolved from another unit - is assembled to
# the same bytes by two producers that are required to differ, and that those
# bytes are the recorded ones. Cross-module resolution and import contracts are
# inside the fixed-point comparison instead of outside it.
#
# IT NO LONGER PROVES: the corpus is no longer a corpus of single files, so
# `member count` is not `source count` and no claim of the form "every member
# is a one-file program" is available from it. Nothing was traded for that: the
# seven single-source rows produce the identical command line and the identical
# digests they produced before, and compared=7 converged=7 pinned=7 was
# re-measured over those same seven rows after this change.
#
# IT STILL DOES NOT PROVE, and did not before either:
#   - the object+link form. The multi-source member is pinned on the one-shot
#     form only; object-then-link gives 352 differing bytes at the same size,
#     and nothing in either script executes that path.
#   - that anything must NOT assemble. This corpus records successes only. Two
#     sources of examples/ntasm-v0/c-bootstrap-multi/ refuse by design - the
#     data-import pair on E200, because the grammar that reads `import x as
#     y: u64` as something other than a function signature does not exist - and
#     a format with nowhere to put an expectation of failure cannot hold them.
#
#   ntselfhost.sh [--build PATH] [--expect-producer SHA256] [--summary]
set -euo pipefail

SELF=$(realpath -m "${BASH_SOURCE[0]}")
REPO=${NG_REPO:-$(dirname "$(dirname "$SELF")")}
REPO=$(realpath -m "$REPO")
BUILD=${NG_BUILD_SCRIPT:-$REPO/scripts/ntbuild.sh}
PRODUCT_DIR="$REPO/out/c-bootstrap/ntasm"
PRODUCT="$PRODUCT_DIR/ntasm"
# Evidence lives outside out/c-bootstrap/ntasm because `ntbuild.sh clean` owns
# that directory and the check calls it three times.
EVIDENCE=${NG_SELFHOST_EVIDENCE:-$REPO/out/c-bootstrap/selfhost}
WORK="$EVIDENCE/work"

OPT_A=${NG_SELFHOST_OPT_A:--O2}
OPT_B=${NG_SELFHOST_OPT_B:--O0}
RESTORE_OPT=${NG_OPT:--O2}
EXPECT_PRODUCER=""
SUMMARY_ONLY=0
SELFTEST=0
PERTURB_PIN=""
PERTURB_LAYOUT=0

while [ $# -gt 0 ]; do
  case "$1" in
    --build) BUILD=${2:?--build needs a path}; shift 2 ;;
    --build=*) BUILD=${1#*=}; shift ;;
    --expect-producer) EXPECT_PRODUCER=${2:?--expect-producer needs a digest}; shift 2 ;;
    --expect-producer=*) EXPECT_PRODUCER=${1#*=}; shift ;;
    --restore-opt) RESTORE_OPT=${2:?--restore-opt needs a level}; shift 2 ;;
    --restore-opt=*) RESTORE_OPT=${1#*=}; shift ;;
    --selftest) SELFTEST=1; shift ;;
    --perturb-pin) PERTURB_PIN=${2:?--perturb-pin needs a member name}; shift 2 ;;
    --perturb-pin=*) PERTURB_PIN=${1#*=}; shift ;;
    --perturb-layout) PERTURB_LAYOUT=1; shift ;;
    -h|--help) sed -n '2,80p' "$SELF" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "ntselfhost.sh: unknown argument '$1'" >&2; exit 2 ;;
  esac
done

digest() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

fail=0

# A silent death under `set -e` is the failure mode this project has already
# paid for twice: a helper that absorbs its own precondition surfaces four
# lines away as a mystery. Dying without having said why is said here - and
# only here, because a failure that already explained itself must not have a
# second, vaguer diagnosis stacked on top of the right one.
DIAGNOSED=0
trap 'rc=$?; [ "$rc" -eq 0 ] || [ "$DIAGNOSED" -eq 1 ] || echo "ntselfhost: aborted (exit $rc) with no diagnosis" >&2' ERR
note() { DIAGNOSED=1; echo "ntselfhost: $*" >&2; }

# The verdict for one corpus member, in one place at top level, so that the
# selftest below drives the same code the real run drives. A selftest of a COPY
# of the comparison is a selftest of the copy.
#
#   $1 name   $2 digest from run a   $3 digest from run b   $4 the pin
# Echoes "agree pinok" on stdout; the diagnosis goes to stderr. Returns 0 when
# the member holds and 1 when it does not.
verdict_member() {
  local n=$1 shaA_i=$2 shaB_i=$3 p=$4 agree=yes pinok=yes bad=0
  if [ -z "$shaA_i" ] || [ -z "$shaB_i" ]; then
    note "no digest recorded for $n in one of the two generations, so this" \
         "run compared nothing for that member and cannot be called a pass."
    echo "no no"
    return 1
  fi
  if [ "$shaA_i" != "$shaB_i" ]; then
    bad=1; agree=no
    note "PRODUCERS DISAGREE on $n"
    note "  run a ($OPT_A): $shaA_i"
    note "  run b ($OPT_B): $shaB_i"
  fi
  if [ "$shaA_i" != "$p" ]; then
    bad=1; pinok=no
    note "BYTES DIFFER FROM THE PIN on $n"
    note "  produced: $shaA_i"
    note "  pinned:   $p"
  fi
  echo "$agree $pinok"
  return "$bad"
}

# ---------------------------------------------------------------------------
# THE BOUNDARY, MEASURED: who built the producer
# ---------------------------------------------------------------------------
# F - the header's fixed point - asks whether the producer, rebuilt by itself
# out of its own source, reproduces itself. Nothing above can answer that,
# because the run records WHAT the two generations emit and never WHO built
# them. So the boundary was prose, and then a literal, and neither is a
# measurement: a line that reads `fixed_point_proven=no` outside every
# condition is a constant, and a constant is right every run and has therefore
# never been tested once.

# THE RECORD THAT ANSWERS IT IS NOT WRITTEN HERE. scripts/ntbuild.sh resolves
# the compiler it is about to exec, digests the binary it resolved, and prints
# both into the build log of every generation it builds:

#   producer_sha256=<sha256 of that compiler file> producer_path=<its path>

# That is the chain of custody, and it is worth one sentence of scepticism: the
# path is `realpath -m` of a program, the digest is sha256 over the bytes at
# that path, and neither can be stated without the other being re-measurable
# from the same file. So this guard RE-DIGESTS the named file and compares it
# with the recorded digest before it believes the record. A record that does
# not re-digest is not evidence, and printing it does not make it one.
#
# WHAT IS DELIBERATELY NOT READ: the `provenance=BOOTSTRAP_EXTERNAL_C` line in
# the same log, and the identical string inside the binary. Both are a literal
# in compiler/c/ntasm/cli/cli.c, so one token moved there makes the tree say
# anything it likes about itself, and a guard that read that field would be
# moved by exactly the edit that should not move it. It is printed below,
# labelled as self-declared, and nothing in the verdict reads it.
#
# THE THREE VERDICTS, which are three different facts and not one fact with
# three decorations:
#   no       the producer that built every generation is a program OUTSIDE
#            this tree, named and digested and re-digested here. The tree did
#            not act on itself, and that is now a reading rather than a claim.
#   UNKNOWN  this run cannot tell: the record is absent, or it does not
#            re-digest, or the producer IS a tree artefact and the chain has
#            one hop where F needs two. Not a failure, not a proof.
#   yes      a generation built a later one, and the corpus and the restore
#            agree. NOT YET REACHABLE, and the reason is below rather than
#            hidden: the anti-vacuity guard above REQUIRES the two producers to
#            differ, and a fixed point is the case where they do not. A lot
#            that makes the chain self-referential has to change that guard
#            first, and until it does, this branch is a definition and not a
#            result.

# The producer line of one build log: "<recorded digest> <path>". Empty and
# non-zero when the log carries none, which is a state and not a parse error.
producer_record() { # producer_record <build-log>
  local line d p
  line=$(grep -m1 '^producer_sha256=' "$1" 2>/dev/null || true)
  [ -n "$line" ] || return 1
  d=${line#producer_sha256=}; d=${d%% *}
  p=${line#* producer_path=}
  [ -n "$d" ] && [ -n "$p" ] || return 1
  printf '%s %s\n' "$d" "$p"
}

# Echoes one line: VERDICT BASIS HOPS digest_a path_a digest_b path_b.
# The verdict is the only thing this decides; the report below words it.
#   $1 build log A  $2 build log B
#   $3 digest of the producer generation A built  $4 ... generation B
#   $5 every corpus member agreed across both generations (yes|no)
#   $6 the restore build reproduced the caller's digest (yes|no|skipped)
boundary_verdict() {
  local logA=$1 logB=$2 shaGenA=$3 shaGenB=$4 agree=$5 restore=$6
  local recA recB dA pA dB pB rA rB lbl d p live gen hops verdict basis
  verdict=UNKNOWN; hops=0

  if ! recA=$(producer_record "$logA") || ! recB=$(producer_record "$logB"); then
    basis=no_producer_record
    echo "$verdict $basis $hops - - - -"
    return 0
  fi
  read -r dA pA <<<"$recA"
  read -r dB pB <<<"$recB"

  # CORROBORATION, for both generations, before the record is believed. The
  # digest in the log is a claim about a file; the file is the fact.
  for lbl in a b; do
    if [ "$lbl" = a ]; then d=$dA; p=$pA; else d=$dB; p=$pB; fi
    if [ ! -f "$p" ]; then
      basis=producer_file_absent
      echo "$verdict $basis $hops - $pA - $pB"
      return 0
    fi
    live=$(digest "$p" 2>/dev/null || true)
    if [ "$live" != "$d" ]; then
      basis=record_not_corroborated
      echo "$verdict $basis $hops - $pA - $pB"
      return 0
    fi
  done

  rA=$(realpath -m -- "$pA" 2>/dev/null || printf '%s' "$pA")
  rB=$(realpath -m -- "$pB" 2>/dev/null || printf '%s' "$pB")

  # A producer inside this tree is a producer this tree made. That is the whole
  # difference between an external compiler and a self-hosted one, and it is
  # read off the path the build resolved - not off a string either side
  # declares about itself.
  local selfref=no
  case "$rA" in "$REPO"/*) selfref=yes ;; esac
  case "$rB" in "$REPO"/*) selfref=yes ;; esac
  if [ "$selfref" = no ]; then
    echo "no producer_provenance $hops $dA $rA $dB $rB"
    return 0
  fi

  # Self-referential. F is TWO hops: P1 = P0(S) and P2 = P1(S). A chain of one
  # hop - a tree artefact built the product and this run used it again - has
  # measured neither the second hop nor its absence, so it is reported as what
  # it is: a state this run cannot decide.
  for gen in "$shaGenA" "$shaGenB"; do
    [ -n "$gen" ] || continue
    case "$dA" in "$gen") hops=2 ;; esac
    case "$dB" in "$gen") hops=2 ;; esac
  done
  if [ "$hops" -lt 2 ]; then
    verdict=UNKNOWN; basis=one_hop_short
  elif [ "$agree" = yes ] && [ "$restore" = yes ]; then
    verdict=yes; basis=two_generations
  else
    verdict=no; basis=self_referential_unproved
  fi
  echo "$verdict $basis $hops $dA $rA $dB $rB"
}

# The two other instruments a reader will point at, and why neither is this
# line. Printed by the report, not by a document, because a boundary that only
# lives in a document has drifted by the time it is needed.
boundary_context() {
  cat <<'EOF'
  the other two instruments a reader comes here for, and why neither is this
  line - named so that the verdict above is read as what it measured:
    A8(2) CONVERGENCE C/NOVA, compiler/c/nova/nova_corpus_convergence.c.
    It compiles 17 .nova modules through nova_compile_many_v2, maps the host
    image, and compares what the Nova producer emits against the C reference
    object-by-object and PE-by-PE, with a negative instrument that shows the
    comparison can go red. That is a real measurement of a real property and it
    is in the tree. It is not evidence for A8(4): the harness is C, so the
    compiler that built those 17 modules is the C one in every run. Nothing in
    its output - NTASM_NOVA_X64_LOWER_NXO_CORPUS checks= failures= cases=
    converged= of known_gaps=, BOUNDARY_SUMMARY rows= converged=
    pinned_refusals= widened=, BOUNDARY_ROW <name> expect= observed=,
    NEGATIVE_PROOF stable/sensitive/flipped_byte - names a producer, a
    language, or a chain. The evidence that would tell a tree-produced
    compiler from an external one does not exist in it, and this line does not
    count it.
    THE S0 FIXED POINT, legacy/ntasm-s0/fixed-point/. It IS
    self-referential over bytes in this tree, and it is the producer of
    compiler-host.ntasm, not the final producer A8(4) names; its replay needs
    QEMU and OVMF out of band, so no run of this script measures it either.
EOF
}

# The block itself. It prints the verdict, the record it came from, and what
# was deliberately not read. The selftest below drives THIS function, so the
# text a case is judged on is the text the run prints.
boundary_report() { # same six arguments as boundary_verdict
  local line verdict basis hops dA pA dB pB selfdecl
  line=$(boundary_verdict "$@")
  read -r verdict basis hops dA pA dB pB <<<"$line"
  selfdecl=$(grep -m1 '^provenance=' "$1" 2>/dev/null || true)
  selfdecl=${selfdecl#provenance=}
  echo "NTSELFHOST_BOUNDARY fixed_point_proven=$verdict basis=$basis hops=$hops"
  echo "  chain_of_custody=scripts/ntbuild.sh resolves the compiler it execs and"
  echo "    prints sha256+path into each generation's build.log; this guard"
  echo "    RE-DIGESTS that file and compares. A record that does not re-digest"
  echo "    is not evidence, so a verdict that cannot read one is UNKNOWN, not no."
  echo "  producer_a sha256=$dA path=$pA"
  echo "  producer_b sha256=$dB path=$pB"
  echo "  self_declared_provenance=${selfdecl:-none} read=no"
  echo "    it is a literal at compiler/c/ntasm/cli/cli.c; a guard that read it"
  echo "    would be moved by editing that one string, which is the defect this"
  echo "    block replaced"
  boundary_context
}


# Build the producer from clean at one optimisation level, then assemble the
# corpus with it. Echoes nothing; leaves digests in the caller's arrays.
# $1 tag, $2 optimisation level, $3 destination directory.
run_generation() {
  local tag=$1 opt=$2 dest=$3
  rm -rf "$dest"
  mkdir -p "$dest"
  if ! NG_SELFHOST_DEPTH=$(( ${NG_SELFHOST_DEPTH:-0} + 1 )) NG_OPT="$opt" \
       bash "$BUILD" build >"$dest/build.log" 2>&1; then
    note "generation $tag failed to build at $opt"
    sed -n '1,25p' "$dest/build.log" >&2
    return 1
  fi
  [ -x "$PRODUCT" ] || { note "generation $tag produced no product binary"; return 1; }
  cp "$PRODUCT" "$dest/producer"
  # One row is one member, and a member may name SEVERAL sources: ntbuild.sh
  # sends them '+'-joined and all of them go to ONE assemble call, in the order
  # written. Before this, one member was one file by construction, which is why
  # a two-module program could not be pinned at all. The three-line split below
  # is the same one ntbuild.sh carries; those two are the only places the list
  # is turned back into arguments, and neither of them reads a corpus row.
  local line name rel pin p
  local -a args sources
  while IFS='|' read -r name rel pin; do
    [ -n "$name" ] || continue
    IFS=+ read -r -a sources <<<"$rel"
    args=()
    for p in "${sources[@]}"; do args+=("$REPO/$p"); done
    # A member that names no source produces no image and no digest, and would
    # be compared as "nothing" - the same hole as an empty corpus, refused in
    # the same words, because it is the same defect.
    if [ "${#args[@]}" -eq 0 ]; then
      note "corpus member $name names no source, so it assembles nothing and"
      note "compares nothing; a check over nothing always passes."
      return 1
    fi
    if ! "$dest/producer" assemble "${args[@]}" -o "$dest/$name.efi" \
         >"$dest/$name.log" 2>&1; then
      note "generation $tag could not assemble $name from ${#args[@]} source(s)"
      sed -n '1,8p' "$dest/$name.log" >&2
      return 1
    fi
    line="$name|$rel|$pin|$(digest "$dest/$name.efi")|$(wc -c <"$dest/$name.efi" | tr -d ' ')"
    printf '%s\n' "$line" >>"$dest/results.csv"
  done < <(bash "$BUILD" corpus)
  return 0
}

# ---------------------------------------------------------------------------
# LAYOUT: the second reading, and it is load-bearing
# ---------------------------------------------------------------------------
# The digest comparison above is a PRODUCER claim: it witnesses that the bytes
# do not depend on how the producer was compiled. A10's clause also names
# "layout/relocations deterministes", and the layout is upstream of the bytes:
# section placement, symbol geometry, symbol and relocation ORDER, the entry
# symbol, and the per-symbol typed contract.
#
# THE HONEST LIMIT, and it belongs here because this is where the next person
# reads before trusting a green:
#   This layout check HAS been shown to bite - on a defect the PE digest
#   provably cannot see, namely a typed contract naming an ABI profile this
#   tree does not implement. Materialize copies section payloads and applies
#   relocation values (object_materialize.c:42-76); it never reads a contract,
#   so the linked image is byte-identical with the contract right or wrong.
#   It has NEVER been shown to bite on a defect the PRODUCER ITSELF emits,
#   because none is known and none was found. That sentence is the difference
#   between an instrument and a demonstration, and it is why this step reports
#   what it covered rather than only that it was green.
#
# BOTH READINGS ARE REQUIRED. The point is not that the digest check is weak.
# It is that it answers a question this step answers differently, and running
# only one of them destroys the demonstration: a layout pass alone loses the
# pair (determinism green while layout red), and a digest pass alone cannot
# see the defect at all. The pair IS the argument.
#
# The producers are the two generations already built above, so this costs no
# extra build. And BOTH are used, with an explicit refusal if they are the
# same bytes - see layout_audit.

LAYOUT_TOOL="$REPO/tools/inspection/ntlayout.py"

python_for_layout() {
  if [ -n "${NG_PYTHON:-}" ]; then echo "$NG_PYTHON"; return 0; fi
  local c
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1; then echo "$c"; return 0; fi
  done
  return 1
}

# How many compilation units the corpus actually names. The object form emits
# ONE OBJECT PER SOURCE, and a corpus row is '+'-joined (ntselfhost.sh:100-123).
# So the expected unit count is derived from the corpus itself and compared
# against what was emitted. A sweep that enumerated its own list - the way the
# first version of this step's harness did, guessing the C sources and missing
# conformance.c and the three nova/ units - disagrees with this count, and the
# disagreement is the failure. Nothing here is hardcoded.
corpus_units() { # corpus_units <corpus-file>
  local total=0 name rel n
  while IFS='|' read -r name rel _; do
    [ -n "$name" ] || continue
    n=1
    case "$rel" in
      *+*) n=$(printf '%s' "$rel" | tr '+' '\n' | grep -c .) ;;
    esac
    total=$((total + n))
  done <"$1"
  echo "$total"
}

# Emit every corpus unit through the object form with ONE producer, then audit.
# $1 producer  $2 destination  $3 corpus file
layout_emit_and_audit() {
  local producer=$1 dest=$2 corpus=$3
  local py
  if ! py=$(python_for_layout); then
    note "no python3 on PATH, so the layout reading cannot run."
    note "This is NOT a pass. A reading that cannot run must never be"
    note "indistinguishable from one that passed, because a void run renders"
    note "the real numbers and they look like a success."
    return 1
  fi
  [ -f "$LAYOUT_TOOL" ] || { note "no layout tool at $LAYOUT_TOOL"; return 1; }
  rm -rf "$dest"; mkdir -p "$dest"
  local name rel src unit emitted=0
  local -a args
  while IFS='|' read -r name rel _; do
    [ -n "$name" ] || continue
    IFS=+ read -r -a args <<<"$rel"
    local j=0
    for src in "${args[@]}"; do
      j=$((j + 1))
      local out="$dest/$name.$j.nxo"
      # The producer REFUSES to overwrite an existing output (E700), so a
      # stale object left by an earlier run would be audited as if this run had
      # emitted it. Remove first.
      rm -f "$out"
      if ! "$producer" object "$REPO/$src" -o "$out" \
           >"$dest/$name.$j.log" 2>&1; then
        note "$producer could not emit the object for $name unit $j ($src)"
        sed -n '1,5p' "$dest/$name.$j.log" >&2
        return 1
      fi
      emitted=$((emitted + 1))
      # The load-bearing proof, and the hook that makes it repeatable. One
      # emitted object is corrupted AFTER emission and BEFORE the audit, so
      # the whole real path runs unchanged and the only difference is a
      # defective layout. If the run still reports PASS, the layout step is
      # decorative and this flag is what exposed it.
      if [ "$PERTURB_LAYOUT" -eq 1 ] && [ "$emitted" -eq 1 ]; then
        local bad="$out.perturbed"
        if "$py" "$LAYOUT_TOOL" --perturb-abi "$out" "$bad" \
             >"$dest/perturb.log" 2>&1; then
          mv "$bad" "$out"
          echo "NTSELFHOST_LAYOUT_PERTURBED object=$name.$j field=abi"
        else
          note "the layout perturbation could not be applied to $out"
          sed -n '1,5p' "$dest/perturb.log" >&2
          return 1
        fi
      fi
    done
  done <"$corpus"

  local expected
  expected=$(corpus_units "$corpus")
  if [ "$emitted" -eq 0 ]; then
    note "the layout step emitted no objects, so auditing them would pass over"
    note "an empty set. This is a broken step, not a pass."
    return 1
  fi
  if [ "$emitted" -ne "$expected" ]; then
    note "the layout step emitted $emitted objects but the corpus names"
    note "$expected compilation units. The enumeration is wrong."
    return 1
  fi

  # The full per-object dump goes to the evidence file; the summary and any
  # failures go to the log, so a build log stays readable while the evidence
  # keeps the examples the instrument printed before its count.
  local rc=0
  "$py" "$LAYOUT_TOOL" "$dest"/*.nxo >"$dest/audit.txt" 2>&1 || rc=$?
  grep -E '^LAYOUT_(SUMMARY|UNREADABLE|FAILURE)' "$dest/audit.txt" >&2 || true
  if [ "$rc" -ne 0 ]; then
    note "the layout of the objects emitted by $producer is not well formed"
    return 1
  fi
  echo "LAYOUT objects=$emitted expected_units=$expected producer=$producer rc=0"
  return 0
}

# Run the layout reading for BOTH generations, and refuse if the two producers
# are the same bytes.
#
# THE ELEVENTH TRAP, and this function is the guard against it. A verification
# pass that measures ONE thing four times and reports four agreements is
# indistinguishable from a pass that varied something. The first version of
# this step's harness did exactly that: it linked every case with one
# top-level binary and called the agreement producer independence. So the two
# producers are checked for distinctness HERE, in the step that varies them,
# and the selftest below drives the refusal.
layout_audit() { # layout_audit <producer-a> <producer-b> <corpus-file> <out>
  local pa=$1 pb=$2 corpus=$3 out=$4
  local sa sb
  sa=$(digest "$pa"); sb=$(digest "$pb")
  if [ "$sa" = "$sb" ]; then
    note "the two producers are the same bytes ($sa), so running the layout"
    note "reading twice would measure one thing twice and call it two"
    note "readings. Choose two levels that build differently."
    return 1
  fi
  local a b
  a=0; b=0
  layout_emit_and_audit "$pa" "$out/a" "$corpus" || a=1
  layout_emit_and_audit "$pb" "$out/b" "$corpus" || b=1
  if [ "$a" -ne 0 ] || [ "$b" -ne 0 ]; then
    note "the layout reading failed for at least one producer"
    return 1
  fi
  echo "NTSELFHOST_LAYOUT producers=a:$sa,b:$sb distinct=yes readings=2"
  return 0
}


# Write a corpus whose unit count is known by hand and check corpus_units
# agrees. $1 path  $2 expected total. Exits non-zero on any disagreement, so
# it can be driven by st_case like any other case.
units_from_synthetic_corpus() { # units_from_synthetic_corpus <path> <want>
  local path=$1 want=$2
  {
    printf 'one|examples/a.ntasm|deadbeef\n'
    printf 'two|examples/b.ntasm|deadbeef\n'
    printf 'three|examples/c.ntasm+examples/d.ntasm|deadbeef\n'
  } >"$path"
  local got
  got=$(corpus_units "$path")
  if [ "$got" != "$want" ]; then
    echo "corpus_units said $got, the synthetic corpus names $want sources" >&2
    return 1
  fi
  # And the negative: a corpus that names nothing must count zero, so an empty
  # corpus cannot be made to look like a populated one.
  : >"$path.empty"
  local none
  none=$(corpus_units "$path.empty")
  if [ "$none" != 0 ]; then
    echo "an empty corpus counted $none units" >&2
    return 1
  fi
  return 0
}

main() {
  if [ ! -x "$BUILD" ] && [ ! -f "$BUILD" ]; then
    note "no build script at $BUILD"
    return 1
  fi
  rm -rf "$EVIDENCE"
  mkdir -p "$EVIDENCE" "$WORK"

  # The corpus pins, read once from the build that owns them. ntbuild.sh holds
  # the only copy; this script holds none, so the two cannot drift apart.
  local corpus_file="$EVIDENCE/corpus.csv"
  bash "$BUILD" corpus >"$corpus_file"
  # The perturbation hook, used only by the selftest. It corrupts ONE pin in
  # the corpus this run will compare against, so the whole real path - build,
  # assemble, digest, compare - runs unchanged and the only difference is a
  # wrong expectation. A check that has never been shown to go red is a check
  # that might be unable to.
  if [ -n "$PERTURB_PIN" ]; then
    local tmp="$corpus_file.tmp" n2 r2 p2 hit=0
    while IFS='|' read -r n2 r2 p2; do
      if [ "$n2" = "$PERTURB_PIN" ]; then
        p2="0000000000000000000000000000000000000000000000000000000000000000"
        hit=1
      fi
      printf '%s|%s|%s\n' "$n2" "$r2" "$p2"
    done <"$corpus_file" >"$tmp"
    mv "$tmp" "$corpus_file"
    if [ "$hit" -eq 0 ]; then
      note "no corpus member named $PERTURB_PIN, so the perturbation changed" \
           "nothing and the run below would prove nothing."
      return 1
    fi
    echo "NTSELFHOST_PERTURBED member=$PERTURB_PIN pin=all-zeroes"
  fi
  local members
  members=$(wc -l <"$corpus_file" | tr -d ' ')
  if [ "$members" -eq 0 ]; then
    note "the corpus is empty; a check over nothing always passes"
    return 1
  fi

  echo "NTSELFHOST_BEGIN policy=$("$BUILD" policy | head -1)"
  echo "NTSELFHOST_CORPUS members=$members from=ntbuild.sh-corpus"

  local genA="$WORK/run-a" genB="$WORK/run-b"
  run_generation a "$OPT_A" "$genA" || return 1
  run_generation b "$OPT_B" "$genB" || return 1

  local shaA shaB
  shaA=$(digest "$genA/producer")
  shaB=$(digest "$genB/producer")

  # The anti-vacuity guard. Two runs of the SAME binary prove determinism and
  # nothing about the product being independent of the build. If the two
  # producers are the same bytes, the convergence below is a tautology, and a
  # tautology that reports "ok" is worse than no check at all.
  if [ "$shaA" = "$shaB" ]; then
    note "producers at $OPT_A and $OPT_B are the same bytes ($shaA)."
    note "Comparing a producer with itself would pass whatever it emits, so"
    note "this run proves nothing. Choose two levels that build differently."
    return 1
  fi
  echo "NTSELFHOST_PRODUCERS a=$OPT_A sha256=$shaA b=$OPT_B sha256=$shaB distinct=yes"

  local name rel pin shaA_i shaB_i compared=0 converged=0 pinned=0 agree pinok v
  while IFS='|' read -r n r p; do
    [ -n "$n" ] || continue
    compared=$((compared + 1))
    shaA_i=$(grep "^$n|" "$genA/results.csv" | cut -d'|' -f4 || true)
    shaB_i=$(grep "^$n|" "$genB/results.csv" | cut -d'|' -f4 || true)
    # The verdict is captured, not run twice: the function's diagnosis goes to
    # stderr and its verdict to stdout, so one call is read once, here.
    if v=$(verdict_member "$n" "$shaA_i" "$shaB_i" "$p"); then
      converged=$((converged + 1))
    else
      fail=$((fail + 1))
    fi
    read -r agree pinok <<<"$v"
    if [ "$pinok" = yes ]; then pinned=$((pinned + 1)); fi
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$n" "$r" "$shaA_i" "$shaB_i" "$p" "$agree" "$pinok" "$compared" \
      >>"$EVIDENCE/fixedpoint.csv"
  done <"$corpus_file"

  echo "NTSELFHOST_COMPARE compared=$compared converged=$converged pinned=$pinned"

  # The second reading, run on the two generations already built, so it costs
  # no extra build. It is part of the check, not a report beside it: a layout
  # failure increments `fail` and fails the build.
  #
  # The corpus is re-read here rather than reused from run_generation, because
  # run_generation assembles a whole member in ONE call and the object form
  # needs one call PER SOURCE. The member count is unchanged; what changes is
  # that the layout reading is taken over the same sources the digests were.
  if ! layout_audit "$genA/producer" "$genB/producer" "$corpus_file" \
       "$WORK/layout"; then
    fail=$((fail + 1))
    note "the layout reading did not pass; see $WORK/layout"
  else
    echo "NTSELFHOST_LAYOUT result=PASS objects_per_producer=$( \
      corpus_units "$corpus_file")"
    echo "  limit=shown to bite on a contract defect the PE digest cannot see;"
    echo "  never yet shown to bite on a defect the producer itself emits,"
    echo "  because none is known. Coverage is the corpus, not layout at large."
  fi

  # The third build: the producer the caller linked, rebuilt from clean at the
  # caller's own level. If that does not reproduce the caller's digest, then
  # "the same source built twice" is false and the build must not be called
  # reproducible. `restore_state` is kept because the boundary verdict below is
  # a function of what the restore measured, not of whether it was asked for.
  local restore_state=skipped
  if [ -n "$EXPECT_PRODUCER" ]; then
    local restore="$WORK/restore"
    if ! run_generation restore "$RESTORE_OPT" "$restore"; then
      fail=$((fail + 1))
      restore_state=no
      note "the restore build failed"
    else
      local shaR
      shaR=$(digest "$restore/producer")
      if [ "$shaR" = "$EXPECT_PRODUCER" ]; then
        restore_state=yes
        echo "NTSELFHOST_RESTORE sha256=$shaR reproduced=yes"
      else
        fail=$((fail + 1))
        restore_state=no
        note "THE PRODUCER DOES NOT REBUILD TO THE SAME BYTES"
        note "  the build linked: $EXPECT_PRODUCER"
        note "  rebuilt from clean: $shaR"
      fi
    fi
  else
    echo "NTSELFHOST_RESTORE skipped=no-expectation"
  fi

  # A8(4), reported from a record this run did not write. The previous line
  # here was `fixed_point_proven=no` in a literal, outside every condition: a
  # constant that is right every run and has therefore never been tested. What
  # replaces it reads WHO built the two generations out of the build logs the
  # build wrote, re-digests the compiler each one names, and can return three
  # different answers - including UNKNOWN, which is the state the old constant
  # could not represent and the one a reader most needs to see.
  local agree=no
  if [ "$compared" -gt 0 ] && [ "$converged" -eq "$compared" ] && \
     [ "$pinned" -eq "$compared" ]; then
    agree=yes
  fi
  bfields=$(boundary_verdict "$genA/build.log" "$genB/build.log" "$shaA" \
    "$shaB" "$agree" "$restore_state")
  local bout
  bout=$(boundary_report "$genA/build.log" "$genB/build.log" "$shaA" "$shaB" \
    "$agree" "$restore_state")
  printf '%s\n' "$bout"

  {
    echo "NTSELFHOST result=$([ "$fail" -eq 0 ] && echo PASS || echo FAIL) failures=$fail"
    echo "  generations=2 from clean, levels $OPT_A and $OPT_B, producers distinct"
    echo "  compared=$compared converged=$converged pinned=$pinned"
    echo "  producer_a=$shaA"
    echo "  producer_b=$shaB"
    echo "  layout=audited over the object form, one object per corpus source,"
    echo "    with BOTH producers; a layout failure fails the build"
    echo "  layout_limit=shown to bite on a typed-contract defect the PE digest"
    echo "    cannot see; never yet shown to bite on a defect the producer"
    echo "    itself emits, because none is known and none was found"
    echo "  fixed_point=$bfields"
    echo "  fixed_point_of_the_C_bootstrap=MEASURED, not asserted; the verdict is"
    echo "    read from the producer record the build wrote and re-digested here,"
    echo "    and UNKNOWN is a value it can take. The block itself, verbatim:"
    printf '%s\n' "$bout" | sed 's/^/    /'
  } >"$EVIDENCE/report.txt"

  trap - ERR
  if [ "$SUMMARY_ONLY" -eq 1 ]; then
    grep -h '^NTSELFHOST_COMPARE\|^NTSELFHOST_RESTORE\|^    NTSELFHOST_BOUNDARY\|^  compared\|^  fixed_point=' \
      "$EVIDENCE/report.txt" 2>/dev/null || true
    echo "selfhost=passed compared=$compared failures=$fail"
    return "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
  fi
  echo "NTSELFHOST_DONE compared=$compared failures=$fail evidence=${EVIDENCE#"$REPO"/}"
  return "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
}

# ---------------------------------------------------------------------------
# The selftest: prove the comparison can fail.
#
# The shape of the defect this guards against is not hypothetical in this
# project. A gate once shipped green through 2197 and then 2207 checks while
# the control inside it had never executed once, because the guard that
# reached it depended on the value it was verifying. A check nobody has ever
# seen go red is the same shape waiting to happen.
#
# Cases B, C and D drive verdict_member - the SAME function the real run calls,
# not a copy - and say so in their output. Case E is the expensive one and the
# only fully end-to-end: it perturbs a real pin and runs the whole check, so
# the build, the assembly, the digests and the comparison all execute and only
# the expectation is wrong.
# ---------------------------------------------------------------------------
st_pass=0
st_fail=0
st_ran=0
ST_CASES=19
ST_FILTER=${NG_SELFHOST_ST_CASES:-}
ST_PARTIAL=no
if [ -n "$ST_FILTER" ]; then
  ST_PARTIAL=yes
fi

# The case filter, and the line that has to be impossible to miss. Running a
# subset is a legitimate need - the expensive cases E and I each build the
# project three times - but a subset that printed "ok" and exited 0 is
# indistinguishable from a full green to whatever reads it, which is the same
# class of defect as the count check below. So a filtered run says PARTIAL
# before any case output, and the DONE line carries it. Unset, which is what
# the build does, the full run is unchanged and the count check is in force.
st_wanted() { # st_wanted <label>; the filter names case IDs (J, G2, ...)
  [ "$ST_PARTIAL" = no ] && return 0
  local id=${1%% *}
  case " $ST_FILTER " in *" $id "*) return 0 ;; esac
  return 1
}

st_verdict() { # st_verdict <label> <want "VERDICT BASIS"> <command...>
  st_wanted "$1" || return 0
  st_ran=$((st_ran + 1))
  local label=$1 want=$2
  shift 2
  local out got
  set +e
  out=$("$@" 2>&1)
  set -e
  got=$(printf '%s\n' "$out" \
        | sed -n 's/^NTSELFHOST_BOUNDARY fixed_point_proven=\([^ ]*\) basis=\([^ ]*\).*/\1 \2/p' \
        | head -1)
  if [ "$got" = "$want" ]; then
    st_pass=$((st_pass + 1))
    printf '  ok    %-46s %s\n' "$label" "$got"
  else
    st_fail=$((st_fail + 1))
    printf '  FAIL  %-46s got [%s] wanted [%s]\n' "$label" "${got:-nothing}" "$want"
    printf '%s\n' "$out" | sed -n '1,4p' | sed 's/^/          /'
  fi
}
st_case() { # st_case <label> <want-exit> <command...>
  st_wanted "$1" || return 0
  st_ran=$((st_ran + 1))
  local label=$1 want=$2
  shift 2
  local out rc
  set +e
  out=$("$@" 2>&1)
  rc=$?
  set -e
  if [ "$rc" = "$want" ]; then
    st_pass=$((st_pass + 1))
    printf '  ok    %-46s exit=%s\n' "$label" "$rc"
  else
    st_fail=$((st_fail + 1))
    printf '  FAIL  %-46s exit=%s wanted %s\n' "$label" "$rc" "$want"
    printf '%s\n' "$out" | sed -n '1,6p' | sed 's/^/          /'
  fi
}

GOOD=1111111111111111111111111111111111111111111111111111111111111111
OTHER=2222222222222222222222222222222222222222222222222222222222222222

selftest() {
  echo "NTSELFHOST_SELFTEST unit-cases drive verdict_member, the function the"
  echo "  real run calls; case E is the full check with one pin perturbed;"
  echo "  cases F-H drive the LAYOUT step, including the two controls that had"
  echo "  to be corrected once: one producer measured twice and called it two"
  echo "  readings, and an enumerated list instead of the corpus's own;"
  echo "  cases J-O drive the BOUNDARY verdict, which replaced a literal, and"
  echo "  they are the cases that can say whether it measures anything: a"
  echo "  perturbation that must move it, one that must NOT, and a control."
  if [ "$ST_PARTIAL" = yes ]; then
    echo "NTSELFHOST_SELFTEST_PARTIAL running only: $ST_FILTER"
    echo "  THIS IS NOT A FULL SELFTEST. $ST_CASES cases are declared and the"
    echo "  pass count below is a number about the ones that ran."
  fi

  # A: the member holds. If this failed, the check would be red on a good
  # producer and nothing else would mean anything.
  st_case "A member holds (equal digests, equal pin)" 0 \
    verdict_member m "$GOOD" "$GOOD" "$GOOD"
  # B: the producers disagree - the convergence branch, observed red.
  st_case "B producers disagree" 1 \
    verdict_member m "$GOOD" "$OTHER" "$GOOD"
  # C: the bytes differ from the pin - the correctness branch, observed red.
  st_case "C bytes differ from the pin" 1 \
    verdict_member m "$GOOD" "$GOOD" "$OTHER"
  # D: a digest is missing. "Compared nothing" must not read as "compared and
  # agreed", which is how an empty scan looks identical to a clean one.
  st_case "D a digest is missing" 1 \
    verdict_member m "" "$GOOD" "$GOOD"

  # E: end to end. One pin wrong, everything else real.
  #
  # The first member is read through a process substitution, not through a
  # pipe into head: head closes the pipe, the producer takes SIGPIPE, and
  # under `set -o pipefail` that 141 becomes a real failure of the
  # assignment. A selftest that dies of its own plumbing proves nothing about
  # the thing it is testing - which is this wave's defect, not a new one.
  local name _ignored
  IFS='|' read -r name _ignored < <(bash "$BUILD" corpus)
  if [ -z "$name" ]; then
    st_fail=$((st_fail + 1))
    echo "  FAIL  the corpus is empty, so no member could be perturbed"
  else
    st_case "E one pin perturbed, whole check must go red" 1 \
      "$SELF" --build "$BUILD" --perturb-pin "$name"
  fi

  # F, G, H: the layout step, and the two controls this project had to learn
  # the hard way. They live HERE, in the tool, because a verification pass
  # that measures one thing twice and reports two agreements is
  # indistinguishable from a pass that varied something - and the first
  # version of this step's harness did exactly that, linking every case with
  # one top-level binary and calling it producer independence.

  # F: the two producers must be REFUSED when they are the same bytes. This
  # drives layout_audit's own guard, not a copy of it.
  st_case "F layout step refuses two identical producers" 1 \
    layout_audit "$BUILD" "$BUILD" /dev/null "$WORK/st-f"

  # G: the layout instrument must go RED on a defect the digest cannot see.
  # The object is perturbed with the tool's own --perturb-abi, so there is one
  # implementation of the perturbation, and the clean object is audited first
  # so a control that cannot run cannot read as a pass.
  local py lyt
  if py=$(python_for_layout) && [ -f "$LAYOUT_TOOL" ]; then
    local gdir="$WORK/st-g"
    rm -rf "$gdir"; mkdir -p "$gdir"
    local gunit
    # Read the first corpus row through a process substitution, NOT through a
    # pipe into head: head closes the pipe, `ntbuild.sh corpus` takes SIGPIPE,
    # and under `set -o pipefail` that 141 kills the assignment - and with it
    # the whole selftest. The first version of this case did exactly that and
    # the selftest died at 141 with cases G, H and I never reached, which looks
    # exactly like those three cases passing quietly and not running at all.
    IFS='|' read -r _gname gunit _gpin < <(bash "$BUILD" corpus)
    if [ -z "$gunit" ]; then
      st_fail=$((st_fail + 1))
      echo "  FAIL  G the corpus named no source to perturb"
      gunit=""
    fi
    local gout="$gdir/one.nxo"
    rm -f "$gout"
    if [ -n "$gunit" ] && [ -x "$WORK/run-a/producer" ] && \
       "$WORK/run-a/producer" object "$REPO/$gunit" -o "$gout" \
         >"$gdir/emit.log" 2>&1; then
      st_case "G layout audit green on an unperturbed object" 0 \
        "$py" "$LAYOUT_TOOL" "$gout"
      st_case "G2 the perturbation changes the object" 0 \
        "$py" "$LAYOUT_TOOL" --perturb-abi "$gout" "$gdir/two.nxo"
      st_case "G3 layout audit RED on the perturbed object" 1 \
        "$py" "$LAYOUT_TOOL" "$gdir/two.nxo"
    else
      st_fail=$((st_fail + 1))
      echo "  FAIL  G could not emit an object to perturb"
      # The emit.log does not exist on this path: the &&-chain above short-
      # circuits before the redirect that would have created it whenever the
      # corpus named no unit or there is no producer. `sed` on a missing file
      # exits 2, and under `set -e -o pipefail` that 2 fails the pipeline and
      # kills the WHOLE selftest - so cases H, I and the boundary cases J-O
      # never run, while every case before this one printed "ok". That is the
      # SIGPIPE defect documented at the corpus read above, reached from the
      # other side, and it is the same shape: a diagnostic that can abort the
      # harness hides the rest of the harness. `|| true` keeps the lines and
      # gives up the status, which is the status of a diagnostic, not of the
      # check - the FAIL above is what this path asserts.
      if [ -f "$gdir/emit.log" ]; then
        sed -n '1,5p' "$gdir/emit.log" | sed 's/^/          /' || true
      else
        echo "          (no emit.log: the producer was never invoked, so it"
        echo "           printed nothing - the corpus or the producer is absent)"
      fi
    fi
  else
    st_fail=$((st_fail + 1))
    echo "  FAIL  G skipped: no python3 or no layout tool. A case that cannot"
    echo "        run is not a pass, so it is recorded as a failure."
  fi

  # H: the unit count must be DERIVED from the corpus, so that a sweep which
  # enumerates its own list disagrees with it and is caught. Driven on a
  # synthetic corpus whose answer is known by hand: two single-source rows and
  # one two-source row are FOUR compilation units, not three and not two.
  st_case "H corpus_units derives the unit count from the corpus" 0 \
    units_from_synthetic_corpus "$WORK/st-h.csv" 4

  # I: THE LOAD-BEARING CASE, and the second expensive one. Case G proves the
  # instrument bites; this proves the STEP decides the run. One emitted object
  # is perturbed after emission and before the audit, so the whole real path
  # executes and only the layout is wrong. If this stays green, the layout
  # step is a report printed beside the check rather than part of it - which is
  # the exact shape of a gate nobody runs.
  st_case "I one layout perturbed, whole check must go red" 1 \
    "$SELF" --build "$BUILD" --perturb-layout

  # J-O: THE BOUNDARY VERDICT, and the reason these seven exist at all.
  #
  # The line they exercise used to read `fixed_point_proven=no` in a literal,
  # outside every condition. A guard with one possible answer is a constant
  # wearing a guard's clothes: it is right every run, so it is never wrong, so
  # it has never been tested. What is asked here is therefore not "does it
  # pass" but two questions, and they pull in opposite directions:
  #   - can it MOVE? A perturbation of the RECORD must change the answer, or it
  #     is a constant with a new name.
  #   - can it be moved by something that is not a change to the guard? An
  #     unrelated edit - and above all the self-declared provenance string,
  #     which is the one field a one-token edit in cli.c can rewrite - must
  #     leave it alone. A guard that goes green when anything moves is the same
  # defect pointing the other way.
  #
  # EVERY CASE IS THE SAME RECORD WITH ONE FIELD CHANGED, and case J is the
  # control: the record exactly as the build writes it, taken from the last
  # real run when one is on disk. The "external producer" is a real file
  # outside this tree - the shell that is running the test - so its digest is
  # recomputed from bytes rather than typed in as a plausible string, and the
  # "tree artefact" is a real file under $REPO, because that is what the
  # self-referential branch keys on.
  local bdir="$WORK/st-boundary"
  mkdir -p "$bdir"
  local ext extd treefile treed
  ext=$(realpath -m -- "$(command -v bash)")
  extd=$(digest "$ext")
  # Under $REPO and not under $EVIDENCE: EVIDENCE is relocatable, the tree is
  # not, and "did this tree make the producer" is a question about the tree.
  treefile="$REPO/out/c-bootstrap/selfhost/.st-boundary-tree-producer"
  mkdir -p "$(dirname "$treefile")"
  printf 'a stand-in for a compiler this tree built; its digest is real\n' \
    >"$treefile"
  treed=$(digest "$treefile")

  # The control record. Two possible sources, and it says which: the last real
  # run's build log when the run left one, otherwise a record in the same
  # shape. A control that is constructed is still a control, but a reader has
  # to be able to tell which one they are looking at.
  local recA recB
  recA="$bdir/control-a.log"; recB="$bdir/control-b.log"
  if [ -f "$WORK/run-a/build.log" ] && [ -f "$WORK/run-b/build.log" ]; then
    cp "$WORK/run-a/build.log" "$recA"; cp "$WORK/run-b/build.log" "$recB"
    echo "  (boundary cases run on the LAST REAL RUN's build logs)"
  else
    # A record in the format scripts/ntbuild.sh prints, so a case with no real
    # run behind it still perturbs the real format rather than a fixture
    # invented to suit the test. The digest is of the file named beside it.
    local f
    for f in "$recA" "$recB"; do
      cat >"$f" <<EOF
NTBUILD_OK policy=NTBUILD-POLICY/1
producer=gcc flags=-std=c11 -O2
binary=out/c-bootstrap/ntasm/ntasm
bytes=377632
sha256=5ba4c3e356581945d409b8c0b5cf9c3c98ce2400a59249ecd3123de27f5f41a9
provenance=BOOTSTRAP_EXTERNAL_C
version=ntasm 0.0.1-c-bootstrap provenance=BOOTSTRAP_EXTERNAL_C B2.1=not-delivered
producer_sha256=$extd producer_path=$ext
selfhost=skipped depth=1
input_units=16 input_headers=18
EOF
    done
    echo "  (boundary cases run on a record in the build's own format: there is"
    echo "   no real run on disk, so this control is constructed, not measured)"
  fi

  # J: THE CONTROL. Unchanged record, and the answer must be the derived one.
  st_verdict "J control, an external producer is read as no" "no producer_provenance" \
    boundary_report "$recA" "$recB" "$GOOD" "$OTHER" yes skipped

  # K: MUST MOVE. The recorded digest no longer matches the file. This is the
  # one-token attack aimed at the guard instead of at the tree: edit the
  # number, not the code, and a guard that trusted the number would go green.
  sed -e "s|^producer_sha256=.*|producer_sha256=$OTHER producer_path=$ext|" \
    "$recA" >"$bdir/k.log"
  cp "$recB" "$bdir/k-b.log"
  st_verdict "K a digest that does not re-digest is UNKNOWN" "UNKNOWN record_not_corroborated" \
    boundary_report "$bdir/k.log" "$bdir/k-b.log" "$GOOD" "$OTHER" yes skipped

  # L: MUST MOVE. The producer is a file INSIDE this tree, with a digest that
  # really is its digest. The chain is self-referential and one hop long, and
  # F needs two, so the honest answer is that this run cannot tell - which the
  # old constant had no way to say.
  sed -e "s|^producer_sha256=.*|producer_sha256=$treed producer_path=$treefile|" \
    "$recA" >"$bdir/l.log"
  cp "$recB" "$bdir/l-b.log"
  st_verdict "L a tree artefact with one hop is UNKNOWN" "UNKNOWN one_hop_short" \
    boundary_report "$bdir/l.log" "$bdir/l-b.log" "$GOOD" "$OTHER" yes skipped

  # M: MUST MOVE. The record is gone. A guard with no input has no opinion, and
  # the state it must report is "cannot tell", not the answer it would have
  # given if it had had an input.
  grep -v '^producer_sha256=' "$recA" >"$bdir/m.log"
  cp "$recB" "$bdir/m-b.log"
  st_verdict "M no producer record is UNKNOWN" "UNKNOWN no_producer_record" \
    boundary_report "$bdir/m.log" "$bdir/m-b.log" "$GOOD" "$OTHER" yes skipped

  # P: MUST MOVE, and the branch that would otherwise be the one nobody has
  # ever seen return anything. A record naming a file that is not there is not
  # a record of an external producer; it is a record of nothing, and the
  # difference is the whole subject of this lot.
  sed -e "s|^producer_sha256=.*|producer_sha256=$extd producer_path=$bdir/no-such-compiler|" \
    "$recA" >"$bdir/p.log"
  cp "$recB" "$bdir/p-b.log"
  st_verdict "P a producer file that is not there is UNKNOWN" "UNKNOWN producer_file_absent" \
    boundary_report "$bdir/p.log" "$bdir/p-b.log" "$GOOD" "$OTHER" yes skipped

  # N: MUST NOT MOVE. Every other field in the record is rewritten, including
  # the provenance string - the field a single token in cli.c controls - and
  # the product's own digest. The verdict keys on the producer the build
  # resolved and this guard re-digested, so none of that is an input to it. If
  # this case goes red the guard is reading the tree's self-description, and
  # the whole construction is a different constant.
  sed -e "s|^provenance=.*|provenance=A_TREE_THAT_CLAIMS_WHATEVER_IT_LIKES|" \
      -e "s|^version=.*|version=ntasm 9.9.9 provenance=A_TREE_THAT_CLAIMS_WHATEVER_IT_LIKES|" \
      -e "s|^sha256=.*|sha256=$GOOD|" \
      -e "s|^bytes=.*|bytes=1|" \
      -e "s|^producer=.*|producer=rustc flags=whatever|" \
    "$recA" >"$bdir/n.log"
  sed -e "s|^provenance=.*|provenance=A_TREE_THAT_CLAIMS_WHATEVER_IT_LIKES|" \
      -e "s|^version=.*|version=ntasm 9.9.9 provenance=A_TREE_THAT_CLAIMS_WHATEVER_IT_LIKES|" \
      -e "s|^sha256=.*|sha256=$OTHER|" \
    "$recB" >"$bdir/n-b.log"
  st_verdict "N rewriting the self-declared fields must NOT move it" "no producer_provenance" \
    boundary_report "$bdir/n.log" "$bdir/n-b.log" "$GOOD" "$OTHER" yes skipped

  # O: the state A8(4) asks for, driven on a record that reaches it - a
  # generation's own bytes are the producer that built the next one, and the
  # corpus and the restore agree. Unreachable by a real run today, because the
  # anti-vacuity guard above REFUSES two producers with the same bytes and a
  # fixed point is that case; so it is exercised here, on a record, rather than
  # left as a branch nobody has ever seen return anything.
  st_verdict "O a generation built the next one is a fixed point" "yes two_generations" \
    boundary_report "$bdir/l.log" "$bdir/l-b.log" "$treed" "$OTHER" yes yes
  # The same chain with the restore not reproducing: self-referential and
  # still not proven, which is a fourth answer rather than a green.
  st_verdict "O2 the same chain, restore did not reproduce" "no self_referential_unproved" \
    boundary_report "$bdir/l.log" "$bdir/l-b.log" "$treed" "$OTHER" yes no


  # A selftest that reports its cases must also report HOW MANY IT EXECUTED.
  #
  # A pass count is a number about the cases that ran. A harness that dies
  # before its remaining cases are reached reports a pass count that is a
  # number about the ones it SKIPPED, and the partial output looks exactly
  # like a clean run. This file did that to itself once: case G read the
  # corpus through `| head -1`, head closed the pipe, `ntbuild.sh corpus` took
  # SIGPIPE, and under `set -o pipefail` the 141 killed the whole selftest -
  # so G, H and I never ran, while every case before them printed "ok". The
  # only reason it was caught is that the run's EXIT STATUS was read instead
  # of the verdicts alone. So the count is checked here, where the next
  # person meets it, and the declared number is a literal that has to be
  # updated when a case is added - which is the point: adding a case without
  # raising it fails the selftest.
  if [ "$ST_PARTIAL" = yes ]; then
    # A filtered run has not executed the declared set and must not borrow the
    # full run's guarantee. It says so here, where the DONE line carries it, and
    # it says so BEFORE any case output too, where a reader meets it first.
    echo "NTSELFHOST_SELFTEST_PARTIAL selected=$ST_FILTER executed=$st_ran of $ST_CASES"
    echo "  this run executed a SUBSET and does not claim a full selftest"
  elif [ "$st_ran" -ne "$ST_CASES" ]; then
    st_fail=$((st_fail + 1))
    echo "  FAIL  executed $st_ran of $ST_CASES declared cases; a selftest"
    echo "        that did not run every case cannot report a pass"
  fi
  echo "NTSELFHOST_SELFTEST_DONE pass=$st_pass fail=$st_fail executed=$st_ran declared=$ST_CASES partial=$ST_PARTIAL"
  [ "$st_fail" -eq 0 ]
}

if [ "$SELFTEST" -eq 1 ]; then
  trap - ERR
  selftest
  exit $?
fi

main "$@"
