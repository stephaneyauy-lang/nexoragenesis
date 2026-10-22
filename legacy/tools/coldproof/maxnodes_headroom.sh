#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# MAX_NODES HEADROOM. A MEASUREMENT, not a change to nova.c.
#
# The question this answers, and the one it is NOT allowed to answer by
# editing the file: how much room is left under the MAX_NODES the trust root
# carries TODAY, and what that number decides about a 20-module compile. The
# value is READ from nova.c at run time and never written in this file, so it
# cannot go stale the way the transcribed literal did.
#
# WHAT IT NEVER DOES. It writes nothing under compiler/c/. Every
# instrumented compiler is a COPY under $BUILD, and before each measurement the
# script prints the diff against the trust root so a reader sees that the only
# differences are (a) one fprintf in dispose() and, for the uncapped run, (b)
# one integer on the MAX_NODES line. The trust-root digests are printed at the
# top and re-checked at the bottom; if any byte moved, this script fails.
#
# WHY A COPY AT ALL, which is the only interesting design decision here. The
# counter this lot needs -- c->p.expression_count at the moment of refusal --
# is a field of a Compiler that compile_profile() disposes before it returns,
# and the refusal path longjmp()s past every observation point. There is no
# way to read it from outside the translation unit, and the two obvious ways to
# get it -- an added fprintf, or a raise of the cap so the run completes --
# are both edits to the trust root. A copy carries the measurement with zero
# bytes changed in nova.c, and the printed diff is what makes the copy
# auditable rather than merely asserted.
#
# WHAT IS MEASURED AND WHERE EVERY NUMBER COMES FROM:
#   expr    c->p.expression_count, read at dispose() -- for a success that is
#           the final count, for a refusal it is the count AT the refusal,
#           because the setjmp path reaches dispose() directly.
#   stmt    c->p.statement_count, same moment (shares MAX_NODES).
#   vars    c->p.variable_count, against MAX_LOCALS.
#   toks    c->token_count, against MAX_TOKENS.
#   funcs   c->p.function_count, against MAX_FUNCS.
#   The counts are read on BOTH paths, so a refusal is a measurement too and
#   not an inference from a passing run.
#
# The check-only entry point (nova_check_many_v2) is NOT used for the reported
# numbers: it returns before public_entry_v2(), and MEASURED on the 18-module
# set it reports 979745 against the full path's 980263, a 518-expression
# difference. Every number below is from the full compile path.
#
# Run:  bash legacy/tools/coldproof/maxnodes_headroom.sh
# From the repo root or anywhere; REPO is anchored like ngbuild.sh's.
# ---------------------------------------------------------------------------
#
# THE CAP IS RAISED BY A GUARDED RAISE, NOT BY A TRANSCRIBED sed. The first
# version of this script substituted a literal:
#     sed 's/^  MAX_NODES = 1081344,/  MAX_NODES = 4325376,/' nova_probe.c
# When the constant moved, the anchor stopped matching, sed copied the file
# through unchanged, and the "uncapped" binary WAS the capped one. Nothing
# failed. The script went on to print HEADROOM as if a raised cap had been
# measured, and a reader had no way to tell. The fix is not the new literal --
# any literal is stale the next time the constant moves -- it is that the two
# builds are compared and the script REFUSES to print a headroom figure when
# they are the same bytes. See raise_cap() and the --selftest-cap-guard run
# that demonstrates the refusal on a deliberately stale anchor.
set -uo pipefail
REPO=${NG_REPO:-/mnt/d/Projets/Racine-C/NexoraGenesis}
root="$REPO/compiler/c"
BUILD=${NG_BUILD:-$REPO/out/c-bootstrap/maxnodes/measure-$(date +%H%M%S)-$$}
mkdir -p "$BUILD"
cd "$REPO" || exit 2

echo "MAXNODES_WATCH where=$REPO"
echo "BUILD $BUILD"

# ---- THE TRUST-ROOT DIGESTS, taken before anything is built. Re-checked at
# the end; a mismatch is this script's own failure, not a finding about Nova.
NOVA_C="$root/nova.c"
before_nova=$(sha256sum "$NOVA_C" | cut -d' ' -f1)
echo "TRUST_ROOT_BEFORE file=compiler/c/nova/frontend/nova.c sha256=$before_nova"

# ---- THE CAP IS READ FROM THE TRUST ROOT HERE, once, before anything is
# built, because two later places need it and neither may transcribe it.
#
# CAPLINE is the whole matched line, leading spaces and trailing comma
# included, so the substitution below anchors on exactly the text that was
# found rather than on a number typed here. Exactly one match is required:
# zero means the shape of the declaration moved, two means the substitution
# would be ambiguous, and in both cases the honest move is to stop.
CAPLINE=$(sed -n 's/^\(  MAX_NODES = [0-9]*,\)$/\1/p' "$NOVA_C")
CAPN=$(printf '%s' "$CAPLINE" | sed -n 's/^  MAX_NODES = \([0-9]*\),\?$/\1/p')
CAPMATCHES=$(sed -n 's/^  MAX_NODES = [0-9]*,$/x/p' "$NOVA_C" | wc -l | tr -d ' ')
if [ "$CAPMATCHES" != 1 ] || [ -z "$CAPN" ]; then
  echo "HEADROOM_REFUSED reason=CAP_NOT_UNIQUELY_READABLE matches=$CAPMATCHES value='$CAPN'" >&2
  echo "HEADROOM_REFUSED no headroom figure is reported by this run." >&2
  exit 3
fi
echo "CAP_READ_FROM_NOVA_C line='$CAPLINE' value=$CAPN matches=$CAPMATCHES"

# ---- raise_cap SRC DST. Copy SRC to DST with the MAX_NODES line replaced by
# RAISEN, and PROVE the replacement happened.
#
# The proof is the whole point. The defect this replaces was a sed whose
# anchor had stopped matching: the command succeeded, the output file was
# created, the script continued, and the "uncapped" build was the capped one.
# A raise that cannot report that it failed is not a raise. So this function
# returns non-zero, LOUDLY, whenever the two files come out identical -- and
# the caller aborts before any headroom number is printed.
#
# The comparison is on the SOURCE COPIES, before a compiler can paper over a
# difference, and it is byte-for-byte via cmp rather than a diff whose empty
# output a reader has to notice.
RAISEN=0
# raise_target CAP -- 4x the cap, rounded UP to a whole 32 Ki step, the step
# size nova.c's own budget comment uses. Computed in ONE place so the
# self-test and the real run cannot raise to different numbers.
raise_target() { python3 -c "import sys; v=4*int(sys.argv[1]); s=32768; print(-(-v//s)*s)" "$1"; }
raise_cap() { # $1 = src, $2 = dst
  sed "s/^  MAX_NODES = $CAPN,$/  MAX_NODES = $RAISEN,/" "$1" >"$2"
  if [ ! -s "$2" ]; then
    echo "HEADROOM_REFUSED reason=RAISE_PRODUCED_NO_FILE src=$1 dst=$2" >&2
    return 1
  fi
  if cmp -s "$1" "$2"; then
    echo "HEADROOM_REFUSED reason=BUILDS_BYTE_IDENTICAL src=$1 dst=$2" >&2
    echo "HEADROOM_REFUSED the 'uncapped' copy is byte-for-byte the capped one, so" >&2
    echo "HEADROOM_REFUSED every count below would come from the CAPPED compiler." >&2
    echo "HEADROOM_REFUSED No headroom figure is reported by this run." >&2
    echo "HEADROOM_REFUSED the anchor did not match; the MAX_NODES declaration is:" >&2
    grep -n 'MAX_NODES' "$1" | sed 's/^/HEADROOM_REFUSED   /' >&2
    return 1
  fi
  # Not just different: different in the ONE place it is supposed to differ.
  # A two-line diff that also touched something else would be a different
  # instrument, and this script's whole credibility is that the only change
  # is the cap.
  local changed
  changed=$(diff "$1" "$2" | grep -c '^[<>]' || true)
  if [ "$changed" != 2 ]; then
    echo "HEADROOM_REFUSED reason=RAISE_CHANGED_TOO_MUCH changed_lines=$changed (MUST be 2)" >&2
    diff "$1" "$2" | sed 's/^/HEADROOM_REFUSED   /' >&2
    return 1
  fi
  echo "CAP_RAISE_VERIFIED src=$(basename "$1") dst=$(basename "$2") from=$CAPN to=$RAISEN changed_lines=$changed"
  return 0
}

# ---- THE SELF-TEST, which is how the guard is shown rather than asserted.
#   bash legacy/tools/coldproof/maxnodes_headroom.sh --selftest-cap-guard
#
# A guard nobody has watched fire is a comment. This mode feeds raise_cap the
# exact failure the script is built against -- an anchor naming a value the
# file no longer carries -- using the REAL nova.c bytes, and requires the
# function to REFUSE. Then it runs the positive control, the same call with
# the value the file actually carries, and requires the function to ACCEPT.
# A guard that cannot tell those two apart is not a guard, and this mode is
# how that is checked on every run of the self-test rather than on my word.
if [ "${1:-}" = "--selftest-cap-guard" ]; then
  ST="$BUILD/selftest"
  mkdir -p "$ST"
  cp "$NOVA_C" "$ST/trust_root_copy.c"
  selftest_fail=0

  echo "--- ARM 1, the historical failure: anchor names 1081344, the file says $CAPN"
  ( CAPN=1081344; RAISEN=4325376; raise_cap "$ST/trust_root_copy.c" "$ST/stale.c" )
  rc=$?
  if [ "$rc" != 0 ]; then
    echo "SELFTEST ARM=stale_anchor EXPECTED=refuse GOT=refuse rc=$rc verdict=PASS"
  else
    echo "SELFTEST ARM=stale_anchor EXPECTED=refuse GOT=accept rc=$rc verdict=FAIL"
    selftest_fail=1
  fi
  if cmp -s "$ST/trust_root_copy.c" "$ST/stale.c"; then
    echo "SELFTEST_ARM1 detail=the refused output IS byte-identical to its input, which is the lie this script used to tell"
  fi

  echo "--- ARM 2, the positive control: anchor names the value the file carries"
  RAISEN=$(raise_target "$CAPN")
  raise_cap "$ST/trust_root_copy.c" "$ST/fresh.c"
  rc=$?
  if [ "$rc" = 0 ]; then
    echo "SELFTEST ARM=current_anchor EXPECTED=accept GOT=accept rc=$rc verdict=PASS"
  else
    echo "SELFTEST ARM=current_anchor EXPECTED=accept GOT=refuse rc=$rc verdict=FAIL"
    selftest_fail=1
  fi

  if [ "$selftest_fail" = 0 ]; then
    echo "CAP_GUARD_SELFTEST verdict=PASS the guard refuses a stale anchor and accepts the current one"
    exit 0
  fi
  echo "CAP_GUARD_SELFTEST verdict=FAIL" >&2
  exit 6
fi

# ---- THE MODULE SETS. The 18 is the effective set of the two gates that
# report E201 (tests_ntasm_x64_lower_nxo_pe.c and ..._local_pe.c). NOTE a
# count that the source does not state: that harness's paths[] holds NINE
# initialisers for an EIGHTEEN-slot array (19 "ntasm-nova" lines against the
# array sized 18), the last two being constant_eval.nova twice, so the
# duplicate is dropped at compile time and the run sees 18 distinct sources.
# Reading the list as 19 inputs reproduces a DIFFERENT failure -- E300
# "duplicate record type" -- which is not the E201 under investigation.
G18=(
  tests/nova/tests/x64-lower-nxo-pe-entry.nova
  compiler/nova/backend/x64/x64_lower_nxo_pe.nova
  compiler/nova/backend/x64/x64_lower_nxo.nova
  compiler/nova/backend/x64/x64_lower_control.nova
  compiler/nova/backend/x64/x64_lower_fixed.nova
  compiler/nova/backend/x64/x64_fixed.nova
  compiler/nova/analysis/types/register_widths.nova
  compiler/nova/formats/nxo/nxo_link_pe.nova
  compiler/nova/formats/nxo/nxo_merge.nova
  compiler/nova/formats/nxo/nxo_pe.nova
  compiler/nova/formats/nxo/nxo.nova
  compiler/nova/formats/pe/pe.nova
  compiler/nova/frontend/parser.nova
  compiler/nova/frontend/ast.nova
  compiler/nova/frontend/lexer.nova
  compiler/nova/macros/macro_splice.nova
  compiler/nova/macros/macro_expand.nova
  compiler/nova/macros/constant_eval.nova
)
NTIR=compiler/nova/formats/ntir/ntir.nova
MIR=compiler/nova/ir/machine_ir.nova

# ---- BUILD. The libs are the same set ngbuild.sh compiles, so the numbers
# come from the same code the suite runs. No sanitizers here: ASan is the
# right default for a gate and the wrong one for a lot whose deliverable is a
# count, because its shadow memory roughly doubles the peak on an 18-module
# program.
LIBS=(
  "$root"/nova.c "$root"/ntasm.c "$root"/frontend.c "$root"/codegen.c
  "$root"/x64.c "$root"/pe.c "$root"/object.c "$root"/object_build.c
  "$root"/object_link.c "$root"/object_materialize.c "$root"/conformance.c
  "$root"/nova/run_host.c "$root"/nova/runtime_v2.c "$root"/nova/pe_oracle.c
)
OBJ=()
for src in "${LIBS[@]}"; do
  o="$BUILD/$(basename "$src" .c).o"
  gcc -std=c11 -O1 -g -I"$root" -c "$src" -o "$o" || { echo "CC_FAIL $src"; exit 1; }
  OBJ+=("$o")
done
# nova.o is the pristine object; the probes link the probe objects instead.
pristine_nova="$BUILD/nova.o"

echo "LIBS_OK ${#OBJ[@]}"

# ---- THE PROBE. It takes module paths and reports the verdict; the counts
# come from the instrumented copy's own fprintf, so the probe and the count
# are two reads of the same run rather than two runs.
cat >"$BUILD/probe.c" <<'EOF'
#include "nova.h"
#include <stdio.h>
#include <stdlib.h>
static char *loadf(const char *p, size_t *n) {
  FILE *f = fopen(p, "rb");
  if (!f) { fprintf(stderr, "PROBE_MISSING %s\n", p); return NULL; }
  fseek(f, 0, SEEK_END); long L = ftell(f); fseek(f, 0, SEEK_SET);
  char *b = malloc((size_t)L + 1);
  if (!b || fread(b, 1, (size_t)L, f) != (size_t)L) { fclose(f); free(b); return NULL; }
  fclose(f); b[L] = 0; *n = (size_t)L; return b;
}
int main(int argc, char **argv) {
  size_t count = (size_t)argc - 1;
  if (count < 1 || count > 64) { fprintf(stderr, "PROBE_USAGE 1..64 paths\n"); return 2; }
  char *src[64]; size_t len[64]; NtFInput in[64];
  for (size_t i = 0; i < count; i++) {
    src[i] = loadf(argv[i + 1], &len[i]);
    if (!src[i]) return 3;
    in[i] = (NtFInput){argv[i + 1], src[i], len[i]};
  }
  NtArtifact a = {0};
  int ok = nova_compile_many_v2(in, count, &a);
  printf("PROBE modules=%zu ok=%d code=%u at=%zu:%zu msg=%s\n",
         count, ok, a.error.code, a.error.line, a.error.column, a.error.message);
  nt_artifact_free(&a);
  return ok ? 0 : 1;
}
EOF

link_probe() { # $1 = object replacing nova.o, $2 = output
  local others=()
  local o
  for o in "${OBJ[@]}"; do
    [ "$o" = "$pristine_nova" ] || others+=("$o")
  done
  gcc -std=c11 -O1 -g -I"$root" "$1" "${others[@]}" "$BUILD/probe.c" -o "$2" || exit 1
}

# ---- COPY 1: the instrumented compiler, cap UNTOUCHED. Pure addition -- the
# diff is asserted to contain no '<' line, so a reader can see that the
# refusal this reports is the refusal of the real constant.
python3 - "$NOVA_C" "$BUILD/nova_probe.c" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src, newline="").read()
anchor = "static void dispose(Compiler *c) {\n  if (!c)\n    return;\n"
if s.count(anchor) != 1:
    raise SystemExit("ANCHOR_MISSING dispose(): the copy would not be a copy")
probe = anchor + (
  '  fprintf(stderr,\n'
  '              "NGPROBE where=dispose expr=%zu stmt=%zu vars=%zu toks=%zu funcs=%zu lowering=%zu\\n",\n'
  '              c->p.expression_count, c->p.statement_count, c->p.variable_count,\n'
  '              c->token_count, c->p.function_count, c->lowering_budget);\n')
open(dst, "w", newline="").write(s.replace(anchor, probe))
PY
removed=$(diff "$NOVA_C" "$BUILD/nova_probe.c" | grep -c '^<' || true)
added=$(diff "$NOVA_C" "$BUILD/nova_probe.c" | grep -c '^>' || true)
echo "PROBE_COPY diff_vs_trust_root removed=$removed added=$added (removed MUST be 0)"
[ "$removed" = 0 ] || { echo "COPY_NOT_A_COPY -- a line of the trust root is missing"; exit 1; }
gcc -std=c11 -O1 -g -I"$root" -c "$BUILD/nova_probe.c" -o "$BUILD/nova_probe.o" || exit 1
link_probe "$BUILD/nova_probe.o" "$BUILD/probe_capped"

# ---- COPY 2: the same instrument, with the cap raised ONLY so the 20-module
# program can complete and be COUNTED. This is the measurement of what the
# program actually needs; it is not a proposal, and the raised number is never
# written into nova.c.
#
# The raise is 4x the CURRENT cap, computed, not 4325376. The old literal was
# 4x of a constant that has since moved, and when the anchor stopped matching
# sed emitted a byte-identical copy, the diff below printed EMPTY, and the run
# continued to report headroom from a capped compiler. raise_cap refuses that
# outcome; this line refuses to build anything at all if the refusal fires.
RAISEN=$(raise_target "$CAPN")
raise_cap "$BUILD/nova_probe.c" "$BUILD/nova_cap.c" || {
  echo "MAXNODES_ABORT the 'uncapped' build could not be shown to differ from the" >&2
  echo "MAXNODES_ABORT capped one, so no count below would be an uncapped count." >&2
  echo "MAXNODES_ABORT Stopping BEFORE section 1. No headroom figure is reported." >&2
  exit 4
}
capdiff=$(diff "$BUILD/nova_probe.c" "$BUILD/nova_cap.c" | grep -E '^[<>]' | tr '\n' ' ')
echo "UNCAPPED_COPY diff_vs_capped_copy: $capdiff"
gcc -std=c11 -O1 -g -I"$root" -c "$BUILD/nova_cap.c" -o "$BUILD/nova_cap.o" || exit 1
link_probe "$BUILD/nova_cap.o" "$BUILD/probe_uncapped"
# Second, independent proof, on the LINKED BINARIES. The source copies could
# differ and still compile to one object if the difference were, say, a
# comment; these carry the constant the compiler actually compares against, so
# identical binaries mean the measurement is capped no matter what the source
# said. Checked before any run, and refused the same way.
if cmp -s "$BUILD/probe_capped" "$BUILD/probe_uncapped"; then
  echo "HEADROOM_REFUSED reason=PROBE_BINARIES_IDENTICAL" >&2
  echo "HEADROOM_REFUSED probe_capped and probe_uncapped are byte-for-byte equal," >&2
  echo "HEADROOM_REFUSED so the compiler measured at the capped constant under both" >&2
  echo "HEADROOM_REFUSED names. No headroom figure is reported by this run." >&2
  exit 5
fi
echo "UNCAPPED_BINARY_VERIFIED probe_capped != probe_uncapped sha=$(sha256sum "$BUILD/probe_uncapped" | cut -c1-16) vs $(sha256sum "$BUILD/probe_capped" | cut -c1-16)"
# The PRISTINE probe, linked against the unmodified nova.o. It is here so the
# refusal is witnessed on the bytes the suite builds and not only on a copy
# that differs from them: this binary carries no probe at all, so the E201 it
# prints is the one a reader gets by running the gate.
link_probe "$pristine_nova" "$BUILD/probe_pristine"

run() { # $1 = binary, rest = modules. prints the NGPROBE line's expr= and the verdict
  "$1" "${@:2}" 2>&1
}
expr_of() { run "$@" | grep -o 'expr=[0-9]*' | head -1 | cut -d= -f2; }
verdict_of() { run "$@" | grep -o 'PROBE .*' | head -1; }

echo
echo "================ 1. REPRODUCTION, at the REAL cap ================"
echo "--- 18 modules, the set the two gates compile today:"
run "$BUILD/probe_capped" "${G18[@]}"
echo "--- 20 modules, the set the blocked splice asks for (18 + ntir + machine_ir):"
run "$BUILD/probe_capped" "${G18[@]}" "$NTIR" "$MIR"
echo "--- the same 20 on the PRISTINE objects, for the record:"
"$BUILD/probe_pristine" "${G18[@]}" "$NTIR" "$MIR"

echo
echo "================ 2. WHAT THE PROGRAM ACTUALLY NEEDS (cap raised on a copy) ================"
e18=$(expr_of "$BUILD/probe_uncapped" "${G18[@]}")
e19=$(expr_of "$BUILD/probe_uncapped" "${G18[@]}" "$NTIR")
e20=$(expr_of "$BUILD/probe_uncapped" "${G18[@]}" "$NTIR" "$MIR")
echo "MEASURED expr modules=18 $e18"
echo "MEASURED expr modules=19 $e19"
echo "MEASURED expr modules=20 $e20"
run "$BUILD/probe_uncapped" "${G18[@]}" "$NTIR" "$MIR" | tail -1

echo
echo "================ 3. SHAPE: linear in module count, or a cliff? ================"
# Synthetic import-free modules of a known, tiny cost. If the growth were
# super-linear there would be a cross-module term and the marginal cost of a
# filler would RISE with the number of modules already present.
mkdir -p "$BUILD/fill"
i=0
while [ $i -lt 64 ]; do
  i=$((i+1))
  printf 'module fill%03d;\nfn f%03d()->u64{let a:u64=7;return a+1;}\n' "$i" "$i" \
    >"$BUILD/fill/fill$(printf %03d $i).nova"
done
base=$e18
echo "SHAPE base_expr_at_18_modules=$base"
for n in 5 10 20 30 40 46; do
  F=()
  k=0
  while [ $k -lt $n ]; do
    k=$((k+1)); F+=("$BUILD/fill/fill$(printf %03d $k).nova")
  done
  e=$(expr_of "$BUILD/probe_uncapped" "${G18[@]}" "${F[@]}")
  echo "SHAPE total_modules=$((18+n)) expr=$e added_over_base=$((e-base)) marginal_per_module=$(python3 -c "print(f'{($e-$base)/$n:.2f}')")"
done

echo
echo "================ 4. HEADROOM, AND WHICH CAP BINDS FIRST ================"
# Re-read rather than reuse, so the headroom below is against what nova.c says
# NOW and not against a value captured before the builds -- and checked to be
# the same, because a file that moved mid-run would make every number on this
# screen a cross-run average.
MAXN=$(sed -n 's/^  MAX_NODES = \([0-9]*\),$/\1/p' "$NOVA_C")
MAXL=$(sed -n 's/^  MAX_LOCALS = \([0-9]*\),$/\1/p' "$NOVA_C")
MAXT=$(sed -n 's/^  MAX_TOKENS = \([0-9]*\),$/\1/p' "$NOVA_C")
MAXF=$(sed -n 's/^  MAX_FUNCS = \([0-9]*\),$/\1/p' "$NOVA_C")
if [ "$MAXN" != "$CAPN" ]; then
  echo "HEADROOM_REFUSED reason=CAP_MOVED_MID_RUN before=$CAPN now=$MAXN" >&2
  echo "HEADROOM_REFUSED nova.c changed between the two builds. No headroom figure" >&2
  echo "HEADROOM_REFUSED is reported by this run." >&2
  exit 7
fi
for v in "$MAXN" "$MAXL" "$MAXT" "$MAXF"; do
  case "$v" in
    ''|*[!0-9]*)
      echo "HEADROOM_REFUSED reason=A_CAP_WAS_NOT_READ value='$v'" >&2
      echo "HEADROOM_REFUSED No headroom figure is reported by this run." >&2
      exit 7 ;;
  esac
done
echo "CAPS_READ_FROM_NOVA_C MAX_NODES=$MAXN MAX_LOCALS=$MAXL MAX_TOKENS=$MAXT MAX_FUNCS=$MAXF"
read -r s20 v20 t20 f20 <<<"$(run "$BUILD/probe_uncapped" "${G18[@]}" "$NTIR" "$MIR" \
  | grep -o 'stmt=[0-9]* vars=[0-9]* toks=[0-9]* funcs=[0-9]*' | head -1 \
  | sed 's/[a-z]*=//g')"
python3 - "$MAXN" "$MAXL" "$MAXT" "$MAXF" "$e18" "$e19" "$e20" "$s20" "$v20" "$t20" "$f20" <<'PY'
import sys
maxn, maxl, maxt, maxf = (int(x) for x in sys.argv[1:5])
e18, e19, e20, s20, v20, t20, f20 = (int(x) for x in sys.argv[5:12])
print("%-34s%9s%11s%8s" % ("set", "expr", "headroom", "used%"))
for name, e in (("18 modules (green today)", e18), ("19 modules (+ntir)", e19),
                ("20 modules (+ntir+machine_ir)", e20)):
    hr = maxn - e
    print("%-34s%9d%11d%7.1f%%" % (name, e, hr, 100.0 * e / maxn))
print()
print("HEADROOM_AT_18 modules=18 headroom=%d used_pct=%.1f  (%.3f of the measured need)"
      % (maxn - e18, 100.0 * e18 / maxn, (maxn - e18) / e18))
print("SHORTFALL_AT_20 modules=20 need=%d have=%d short_by=%d (%.2f%%)"
      % (e20, maxn, e20 - maxn, 100.0 * (e20 - maxn) / maxn))
print()
print("CAP_BINDING_AT_20:")
for nm, val, cap in (("expressions", e20, maxn), ("statements", s20, maxn),
                     ("variables/locals", v20, maxl), ("tokens", t20, maxt),
                     ("functions", f20, maxf)):
    print("  %-18s%9d / %-9d headroom=%-8d (%.1f%% used)"
          % (nm, val, cap, cap - val, 100.0 * val / cap))
print()
print("RAISE_ARITHMETIC, printed and NOT applied:")
import math
print("  minimum that FITS 20 modules      = %d" % e20)
print("  1.25x policy over that need       = %.0f" % (1.25 * e20))
step = 32768
s = step * math.ceil(1.25 * e20 / step)
print("  smallest 32 Ki step at or above   = %d (%d x 32768), ratio %.4fx"
      % (s, s // step, s / e20))
PY

echo
echo "================ 5. THE TRUST ROOT IS UNTOUCHED ================"
after_nova=$(sha256sum "$NOVA_C" | cut -d' ' -f1)
echo "TRUST_ROOT_AFTER  file=compiler/c/nova/frontend/nova.c sha256=$after_nova"
if [ "$before_nova" = "$after_nova" ]; then
  echo "NOVA_C_UNMODIFIED yes before=$before_nova"
else
  echo "NOVA_C_UNMODIFIED NO before=$before_nova after=$after_nova"
  exit 1
fi
# The whole region, not one file: a lot that wrote a header would be caught by
# this and not by a check on nova.c alone.
echo "QUARANTINE_C_DIGESTS (every *.c and *.h directly under the quarantine root):"
find "$root" -maxdepth 1 -type f \( -name '*.c' -o -name '*.h' \) -print0 \
  | LC_ALL=C sort -z | xargs -0 sha256sum | sed "s|$REPO/||"
echo "MAXNODES_DONE"
