#!/usr/bin/env bash
# Nexora Genesis - citation audit for a document range.
#
# WHAT IT IS FOR. A citation written as `file:line` is a claim about an EDITION,
# not about a file: nine of them in spec/ntasm/ntasm.md went stale in one night
# because four cited files were edited by the wave that was running, and nobody
# noticed, because a line number LOOKS checked. This prints the TARGET LINE of
# every citation in a range, so the number is checked against bytes rather than
# by arithmetic.
#
#   audit_citations.sh <first-line> <last-line> [document]
#   audit_citations.sh 1308 1700                 # spec/ntasm/ntasm.md by default
#   audit_citations.sh 1 60 docs/guides/ntasm-build.md
#   audit_citations.sh --self-test                # the two controls, below
#
# WHAT IT DOES NOT DO, and the omission is deliberate. It resolves every path
# and every line number, and prints the line the number lands on. It does NOT
# decide whether that line is what the citation CLAIMS -- a number can be in
# range and still name the wrong statement. Reading the printed column is the
# second half of the check and it is the half that catches the interesting
# case. What it does catch mechanically: a citation to a file that does not
# exist, a line number past the end of a file that does, a bare `:NNN` whose
# paragraph names no file, and a bare name that two roots both answer to.
#
# WHY IT PRINTS INSTEAD OF COUNTING. A count tells a reader that something is
# wrong without telling it what, and a reader who cannot act on a count stops
# acting on it. This prints one line per citation: the spec line, the citation,
# and the target. That is three times the output of a counter and it is the
# difference between a signal and a report.
#
# THE SHORTHAND, which the first version of this file could not see. A document
# that writes `x64_lower_nxo_pe.nova:130` and then, three clauses later, `:118`,
# has made TWO citations and shown the reader one. Those are the citations that
# drifted twice in spec/ntasm.md. This version resolves the bare `:NNN` against
# the most recently named file in scope and prints the line it lands on, marked
# with a leading `~` so the reader can see that a resolution HAPPENED and can
# disagree with the choice of anchor:
#
#   ntasm.md:1770  ~x64_lower_nxo_pe.nova:194 | ...
#
# SCOPE, and it is a rule and not a heuristic. The anchor is the last file
# token that appears TEXTUALLY BEFORE the shorthand, inside the same paragraph
# (a run of non-blank lines). A blank line, a heading and a block quote each
# end the scope. There is no backward search, no nearest-file guess and no
# cross-paragraph carry: `:46` in a paragraph that names no file is NOT
# resolved against whatever the paragraph before it happened to name, because
# that is a guess wearing a citation's clothes.
#
# WHEN THERE IS NO ANCHOR, IT SAYS SO. A bare `:NNN` whose paragraph names no
# file is printed as UNRESOLVED-SHORTHAND and its number is never resolved.
# A silent guess would be worse than the old blind spot: the blind spot left a
# citation unchecked, and a guess converts "unchecked" into "checked and
# wrong", which is a false negative a reader cannot detect.
#
# IT CAN BE WRONG IN A NEW WAY, and that is stated rather than hidden. The
# anchor is the most recent file token, but a paragraph that names five files
# and abbreviates after the first is genuinely ambiguous to a human reader too.
# So every shorthand row PRINTS the file it was resolved against. A reader who
# thinks the anchor is the wrong file sees that immediately; a reader who
# cannot see the anchor has no way to notice. That is why the anchor is a
# column and not a private decision.
#
# SELF-TEST. `--self-test` builds a throwaway document in a private temporary
# directory and runs this script against it in BOTH directions:
#   positive control - a paragraph that names a file and then abbreviates must
#                      print the real target line, with the anchor visible;
#   negative control - a paragraph with a bare `:NNN` and NO named file must
#                      print UNRESOLVED-SHORTHAND and resolve nothing.
# An instrument nobody has seen fail is not an instrument. The test exits
# non-zero if either control misbehaves; a self-test that cannot fail is
# decoration.
#
# NOT A PRODUCER. It reads the tree and writes nothing outside stdout, except
# under `--self-test`, where it creates and removes one directory under
# $TMPDIR and nothing else. Like the rest of legacy/tools/coldproof, it is
# orchestration, not a source, not a build input.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="${NG_AUDIT_ROOT:-$(cd "$HERE/../.." && pwd)}"
# The blind spot this file used to declare, kept as a record of what changed.
# It was true of version 1 (sha256 794b194ccd938bd616f88c16c2b3081d1c777319b
# 1f9329244a3908f631d09d09d6) and is false of this one. It is not deleted: a
# tool that hides the hole it used to have is a tool you cannot calibrate.
#
#   "This parser looks for `file.ext:NNN`. It does NOT resolve the
#    colon-shorthand `:NNN` that a paragraph uses once it has named its file in
#    the same sentence ... this tool will not see one of them. Read the
#    shorthand by hand; do not read a clean run as a clean document."
#
# It is resolved above. What is NOT resolved, and cannot be, is the other half
# of that sentence: the tool now SEES every shorthand citation in a range, and
# seeing is not judging. A clean run of this script means every number landed
# on a line that exists. It does not mean the document is clean.

# A file token: a path, bare or qualified, ending in a known source extension,
# optionally carrying its own line or line range. The extension set is the
# first version's set; adding one is how a new kind of file gets audited.
FILE_EXT='c|h|nova|md|sh|py'

# A file token, and a bare line reference. Bare references are matched with a
# leading delimiter so that `x64.c:942` is always read as the file form and
# never as a `c:942` shorthand.
TOKEN_RE="[A-Za-z0-9_/.-]+\.($FILE_EXT)(:[0-9]+(-[0-9]+)?)?|[^A-Za-z0-9_/.-]:[0-9]+(-[0-9]+)?"

# A file token may be written bare (`x64.c:942`) or with a path
# (`compiler/nova/analysis/control_flow.nova:309`). Resolve a bare token against
# the roots a source of this project actually lives under, in the order that
# makes a bare token unambiguous. The CWD-relative candidate of the first
# version is gone: an audit whose answer depends on the directory it was
# launched from is not an audit of the tree.
resolve() {
  local f="$1" p
  for p in "$ROOT/$f" \
           "$ROOT/compiler/c/$f" \
           "$ROOT/compiler/c/nova/$f" \
           "$ROOT/compiler/nova/$f" \
           "$ROOT/scripts/$f" "$ROOT/legacy/tools/coldproof/$f" \
           "$ROOT/docs/$f" "$ROOT/spec/$f"; do
    if [ -f "$p" ]; then printf '%s' "$p"; return 0; fi
  done
  return 1
}

# Every candidate that exists, one per line. Used to say AMBIGUOUS rather than
# to pick quietly: two files with the same bare name in two roots is a real
# condition in this tree and the reader is entitled to see it.
candidates() {
  local f="$1" p
  for p in "$ROOT/$f" \
           "$ROOT/compiler/c/$f" \
           "$ROOT/compiler/c/nova/$f" \
           "$ROOT/compiler/nova/$f" \
           "$ROOT/scripts/$f" "$ROOT/legacy/tools/coldproof/$f" \
           "$ROOT/docs/$f" "$ROOT/spec/$f"; do
    [ -f "$p" ] && printf '%s\n' "$p"
  done
  return 0
}

# Print the text of line N of file P, truncated, or the closing line of a
# range. A range citation names a span; the span's two ends are what a reader
# needs, and printing only the first end is how a range that has drifted at its
# far end keeps looking checked.
target() {
  local p="$1" a="$2" b="${3:-}" out
  if [ -n "$b" ] && [ "$b" != "$a" ]; then
    out="$(sed -n "${a}p" "$p" | cut -c1-90) <-> $(sed -n "${b}p" "$p" | cut -c1-90)"
  else
    out="$(sed -n "${a}p" "$p" | cut -c1-100)"
  fi
  printf '%s' "$out"
}

# ---------------------------------------------------------------------------
# The two controls. A negative result needs a positive control, and an
# instrument that has only ever returned green is decoration.
# ---------------------------------------------------------------------------
self_test() {
  local d rc=0 out
  d="$(mktemp -d "${TMPDIR:-/tmp}/ng-audit-selftest.XXXXXX")" || return 3
  trap 'rm -rf "$d"' RETURN

  # The fixture: a real file, and a document that cites it both ways. The
  # paragraphs are separated by blank lines on purpose — that separation IS
  # the scope rule, and a fixture that did not exercise it would be testing
  # a rule the document does not have.
  printf 'alpha one\nalpha two\nalpha three\n' >"$d/subject.c"
  cat >"$d/fixture.md" <<'FIXTURE'
first line, nothing cited here

`subject.c:2` is a full citation and must print alpha two

`subject.c:2`, then `:3`, both in one paragraph

`:3` alone with no file named in this paragraph
FIXTURE

  # The inner run's own exit status is captured IMMEDIATELY and by
  # assignment, never by `$?` after a pipe: a status read after a pipeline is
  # the last stage's status, and a green run whose instrument died would
  # otherwise be indistinguishable from a green run that worked.
  out="$(NG_AUDIT_ROOT="$d" "$0" 1 8 "$d/fixture.md" 2>"$d/err")"; inner=$?
  err="$(cat "$d/err")"
  if [ "$inner" -ne 0 ]; then
    echo "FAIL run: the instrument exited $inner on its own fixture"
    rc=1
  fi

  # POSITIVE CONTROL: the shorthand must resolve to the real line, and must
  # show which file it was resolved against.
  if printf '%s\n' "$out" | grep -q '~subject\.c:3 *\| *alpha three'; then
    echo "PASS positive-control: bare \`:3\` resolved to subject.c:3 -> 'alpha three'"
  else
    echo "FAIL positive-control: bare \`:3\` did not resolve to subject.c:3"
    printf '%s\n' "$out" | sed 's/^/    got: /'
    rc=1
  fi

  # NEGATIVE CONTROL: with no file named in its paragraph, the shorthand must
  # be reported, and nothing may be resolved for it.
  if printf '%s\n' "$out" | grep -q '^UNRESOLVED-SHORTHAND  fixture\.md:7  :3'; then
    echo "PASS negative-control: bare \`:3\` with no named file reported, not guessed"
  else
    echo "FAIL negative-control: bare \`:3\` with no named file was not reported"
    printf '%s\n' "$out" | sed 's/^/    got: /'
    rc=1
  fi
  # ...and the negative control must not have produced a target line.
  if printf '%s\n' "$out" | grep -q 'fixture\.md:7 .*subject\.c'; then
    echo "FAIL negative-control: line 7 was RESOLVED against a file it never named"
    rc=1
  fi

  # The full form must still work, or the extension broke the original.
  if printf '%s\n' "$out" | grep -q 'fixture\.md:3  *subject\.c:2 *\| *alpha two'; then
    echo "PASS regression: full \`file:NNN\` citations still resolve"
  else
    echo "FAIL regression: full \`file:NNN\` citations stopped resolving"
    printf '%s\n' "$out" | sed 's/^/    got: /'
    rc=1
  fi

  # Anything the tool said on stderr DURING its own controls, beyond the
  # three-line footer it always prints, is itself a failure. A self-test that
  # swallows its own errors is the instrument this whole file is about.
  noise="$(printf '%s\n' "$err" | grep -v -e '^A range was audited,' \
             -e '^still has to be read against' -e '^the file it was resolved' \
             -e '^$')"
  if [ -n "$noise" ]; then
    echo "FAIL noise: the controls wrote to stderr:"
    printf '%s\n' "$noise" | sed 's/^/    got: /'
    rc=1
  fi

  [ $rc -eq 0 ] && echo "self-test: both directions observed"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then
  self_test
  exit $?
fi

if [ $# -lt 2 ]; then
  echo "usage: audit_citations.sh <first-line> <last-line> [document]" >&2
  echo "       audit_citations.sh --self-test" >&2
  echo "  default document: spec/ntasm/ntasm.md" >&2
  exit 2
fi
A=$1; B=$2
DOC=${3:-"$ROOT/spec/ntasm/ntasm.md"}

if [ ! -f "$DOC" ]; then
  echo "NO-SUCH-DOCUMENT $DOC" >&2
  exit 2
fi
case "$A:$B" in *[!0-9:]*) echo "lines must be numbers" >&2; exit 2;; esac
[ "$A" -le "$B" ] || { echo "first line must not be past last line" >&2; exit 2; }

DNAME="$(basename "$DOC")"

# One pass over the document. Paragraph boundaries are tracked even before
# $A, so that the anchor in force at line $A is the one the reader would have
# found by reading, not one reset by the range.
anchor=""        # bare file token last named, in scope
anchor_at=0      # spec line where it was named
sl=0
# Associative, NOT indexed: the keys are paths, and bash would
# arithmetic-evaluate an indexed subscript and fail on the slashes.
declare -A amb=()
declare -A seen_this_line=()

while IFS= read -r line || [ -n "$line" ]; do
  sl=$((sl + 1))

  # A blank line, a heading, or a block quote that opens a new block ends the
  # scope. Headings end it because a section is a scope in every reading of
  # this document, including the reader's.
  if [ -z "${line// /}" ] || [ "${line:0:1}" = "#" ] || [ "${line:0:1}" = ">" ]; then
    anchor=""; anchor_at=0
    continue
  fi

  [ "$sl" -lt "$A" ] && continue
  [ "$sl" -gt "$B" ] && break

  seen_this_line=()
  while IFS= read -r tok; do
    [ -n "$tok" ] || continue
    # Drop the delimiter a bare reference was matched with.
    case "$tok" in
      [A-Za-z0-9_/.-]*) : ;;
      *) tok="${tok#?}" ;;
    esac
    [ -n "$tok" ] || continue
    key="$tok"
    [ -n "${seen_this_line[$key]:-}" ] && continue
    seen_this_line[$key]=1

    if [ "${tok:0:1}" = ":" ]; then
      # THE SHORTHAND. Resolved against the anchor, or refused.
      if [ -z "$anchor" ]; then
        printf 'UNRESOLVED-SHORTHAND  %s:%s  %s  (no file named earlier in this paragraph)\n' \
          "$DNAME" "$sl" "$tok"
        continue
      fi
      f="$anchor"
      n="${tok#:}"; b=""
      case "$n" in *-*) b="${n#*-}"; n="${n%%-*}";; esac
      p="$(resolve "$f")" || {
        printf 'MISSING-FILE  %s:%s  %s  (shorthand, anchored on %s named at line %s)\n' \
          "$DNAME" "$sl" "$tok" "$f" "$anchor_at"
        continue; }
      lines=$(wc -l <"$p")
      b2=""; [ -n "$b" ] && b2="$b"
      if [ "$b2" != "" ] && [ "$b2" -gt "$lines" ]; then
        printf 'OUT-OF-RANGE  %s:%s  %s  (%s has %s lines)\n' \
          "$DNAME" "$sl" "$f$tok" "$(basename "$p")" "$lines"
      elif [ "$n" -gt "$lines" ]; then
        printf 'OUT-OF-RANGE  %s:%s  %s  (%s has %s lines)\n' \
          "$DNAME" "$sl" "$f$tok" "$(basename "$p")" "$lines"
      else
        printf '%-14s %-42s | %s\n' "$DNAME:$sl" "~$f$tok" "$(target "$p" "$n" "$b2")"
      fi
    else
      f="${tok%%:*}"
      n=""
      case "$tok" in *:*) n="${tok#*:}";; esac
      # Naming a file re-aims the shorthand, line-numbered or not.
      anchor="$f"; anchor_at="$sl"
      # Ambiguity can only happen for a BARE name: a qualified path is
      # explicit, and a relative link with `..` is a link, not a name. The
      # first version of this file counted candidates for every token and
      # fired on `../docs/x.md` because two roots both answer to it once the
      # `scripts/` root is prepended to a `..` path.
      namb=0
      case "$f" in */*) ;; *) namb=$(candidates "$f" | wc -l);; esac
      if [ "$namb" -gt 1 ] && [ -z "${amb[$f]:-}" ]; then
        amb[$f]=1
        printf 'AMBIGUOUS-NAME  %s:%s  %s  (%s files of that name; first is %s)\n' \
          "$DNAME" "$sl" "$f" "$namb" "$(resolve "$f" | sed "s|$ROOT/||")"
      fi
      [ -n "$n" ] || continue
      b=""; case "$n" in *-*) b="${n#*-}"; n="${n%%-*}";; esac
      p="$(resolve "$f")" || {
        printf 'MISSING-FILE  %s:%s  %s\n' "$DNAME" "$sl" "$f:$n"; continue; }
      lines=$(wc -l <"$p")
      if [ "$n" -gt "$lines" ] || { [ -n "$b" ] && [ "$b" -gt "$lines" ]; }; then
        printf 'OUT-OF-RANGE  %s:%s  %s  (%s has %s lines)\n' \
          "$DNAME" "$sl" "$f:$n" "$(basename "$p")" "$lines"
      else
        printf '%-14s %-42s | %s\n' "$DNAME:$sl" "$f:$n" "$(target "$p" "$n" "$b")"
      fi
    fi
  done < <(printf '%s' "$line" | grep -oE "$TOKEN_RE")
done <"$DOC"

echo
echo "A range was audited, not a document judged. Every number printed above" >&2
echo "still has to be read against the line it names, and every ~ row against" >&2
echo "the file it was resolved against: the anchor is a rule, not a fact." >&2
