#!/usr/bin/env python3
"""checkset.py -- what a gate emitted, and what it did not. Lot 161.

THE DEFECT THIS INSTRUMENT EXISTS FOR

    2026-09-27 13:57   out/c-bootstrap/nova/w5-lot4-full-suite.log
                       89 gates    0 failures    19 012 cases
    2026-10-03        tonight
                       94 gates   41 failures    21 826 cases

Two readings fit those counters equally well -- coverage grew and found latent
defects, or the tree regressed. A counter says HOW MANY failed and never WHICH.
Three before/after comparisons were written into the register tonight off those
counters alone; all three were narrative rather than measurement.

THE MEASUREMENT THAT DECIDES, AND WHY IT IS NOT AVAILABLE YET

Separating the two readings needs ONE quantity: the identity of the check that
fails. Concretely, for a failing check named C, three cases:

    C failed on the 27th and fails tonight   -> not new; already known red
    C passed on the 27th and fails tonight   -> REGRESSION on an existing check
    C did not exist on the 27th              -> NEW COVERAGE, latent defect found

Case 2 and case 3 are the whole question, and they are told apart by ONE datum:
did the 27th log NAME check C as existing? "Passed" is not the same as "was
there", and only the name settles it.

    THE 27TH LOG NAMES NO CHECKS AT ALL.
    w5-lot4-full-suite.log carries 89 banners, 0 failures, and 0 FAIL lines.
    Its 228 named forms are diagnostics (ABSENT bswap oracle=ok(3)
    encoder=401), not check identities. A run with 0 failures prints 0 FAIL
    lines, so a clean log is structurally incapable of naming what passed.

So cases 2 and 3 are INDISTINGUISHABLE from these two logs. That is the
finding, and it is not repaired by any amount of reading them.

WHAT THIS TOOL EMITS, therefore, and the honest label on each line

    CHECKFAIL <GATE> <identity>
        One failing check, NAMED. Tonight: 41 of these, not 21 826. This is the
        quantity that did not exist before and is the whole deliverable of the
        next run onward.

    FAILSET <GATE> n=<count> id=<digest>
        Digest over the SORTED SET of the gate's NAMED FAILING checks. Sorted
        and deduplicated, so a reordering or a re-run does not move it -- a
        digest over a multiset would flag every scheduling change as a set
        change, which is a false positive shaped exactly like a coverage change.
        The word is FAILSET and not CHECKSET on purpose: this is a digest over
        the checks that FAILED, never over the checks that ran. A reader who
        mistakes one for the other will conclude a green gate ran zero checks.

    CHECKSET_ABSENT <GATE> checks=<n> failures=<f>
        The gate ran and named NOTHING. This is emitted for every green gate in
        every log, tonight and on the 27th. It is explicitly not n=0: an absent
        datum is not a zero, and conflating them is the failure this file was
        written against -- four instruments tonight each defaulted an absence to
        a value.

    CHECKSET_REFUSED <GATE> reason=<why>
        The gate emitted something internally inconsistent. No digest, no count.

WHAT IT REFUSES
    * `checks < failures` -- an impossible counter pair. Refused before
      anything else is derived from those two fields.
    * a TRUNCATED log -- `ngbuild.sh` prints `tail -25` on a compile failure,
      so truncation is broken WITHOUT tripping checks<failures and must be
      caught on its own signature, or a cut-short log reads as a short clean one.
    * `failures=N` with N named lines missing -- the counter and the names
      disagree, so the failing set is not a trustworthy identity set and is not
      digested over. This is the REGISTRY case tonight: 2 failures, 0 names.

RECIPE. Every number here is read from a log the project's own driver wrote --
legacy/tools/coldproof/ngbuild.sh -- which builds every harness with
    gcc -std=c11 -Wall -Wextra -Werror -O1 -g \
        -fsanitize=address,undefined -fno-omit-frame-pointer
This tool never compiles and never runs a gate, so the recipe is not its own to
choose; it only prints the sha256 of each log it reads, because two instants on
a moving tree are not comparable and the fence must be visible in the output.

Run:  checkset.py <log> [<log>...]            the failing identities, per gate
      checkset.py --selftest
"""

import collections
import hashlib
import os
import re
import sys
import tempfile

# The banner the harnesses print (compiler/c/nova/tests_ntasm_*.c):
#   printf("NTASM_NOVA_<GATE> checks=%u failures=%u cases=%u\n", ...)
# Trailing per-gate keys (oracle_divergences=, profiles_agreed=, fence_moved=)
# vary, so the parse stops after cases= and the rest is not read.
BANNER = re.compile(
    r"^(NTASM_NOVA_[A-Z0-9_]+)\s+checks=(\d+)\s+failures=(\d+)\s+cases=(\d+)")

# A failing check's identity. Harnesses print `FAIL <identity>...` to stderr and
# ngbuild.sh folds stderr into the log, so a FAIL line belongs to the banner
# above it.
#
# THE IDENTITY IS THE WHOLE MESSAGE, not its first word. The harnesses write a
# prose identity followed by trailing key=value measurements:
#     FAIL never call terminal ret=940 runtime=0 out=7,1,940,23
#     FAIL operand agreement A let local in a nested block: the product refuses ...
# Taking the first whitespace token collapses `never call terminal`, `boolean
# and-or precedence` and `parity in bound macro` onto their first words, and a
# prefix is not an identity: prefixes collide. VALIDATE's 12 failures became 8
# distinct names that way, and a digest over a set that has silently merged
# four distinct failures will report two runs as identical when they are not --
# the exact false negative this instrument exists to rule out.
#
# So the identity is the message with its trailing key=value measurements
# stripped. What remains is what the harness CALLS the check. The stripped tail
# -- ret, runtime, out, want, nodes, code -- is a measured RESULT, not a name,
# and results legitimately change between runs while the check does not.
FAIL = re.compile(r"^FAIL\s+(.+?)\s*$")

# One trailing measurement field: `ret=940`, `out=7,1,940,23`, `want=0`.
MEASURE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# THE ONE-LINE EMISSION A GATE WOULD ADD. Not implemented in any gate tonight --
# that is the user's call, not this lot's -- but parsed here and exercised by the
# selftest, so the day it lands the instrument already consumes it:
#
#     CHECKSET NTASM_NOVA_VALIDATE n=480 id=<16 hex>
#
# emitted by the gate over the SORTED SET of every check identity it ran, failing
# or not. That is what makes the question answerable: a gate that names only its
# failures cannot distinguish a check that passed from one that never existed,
# because a passing check emits no line. Naming all of them is the whole fix,
# and it is one line in one macro per harness.
NATIVE = re.compile(
    r"^CHECKSET\s+(NTASM_NOVA_[A-Z0-9_]+)\s+n=(\d+)\s+id=([0-9a-f]{16,})\s*$")

def identity_of(message):
    """The check's name: the FAIL message minus its trailing measurements.

    Stripped from the RIGHT, one field at a time, and stopped at the first field
    that is not a measurement. Stripping from the left would eat the identity,
    because an identity legitimately contains `=` (`parity in unbound
    macro=940` names a macro, and `macro=` there is part of the name's tail, not
    a result field).
    """
    parts = message.split()
    while parts and MEASURE.match(parts[-1]):
        parts.pop()
    return " ".join(parts)


# The terminal marker. A log without one of these was cut short.
DONE = ("GATES_DONE", "GATES_DONE_RC")


def failset_digest(identities):
    """Digest over the sorted SET of named failing identities."""
    uniq = sorted(set(identities))
    return len(uniq), hashlib.sha256("\n".join(uniq).encode("utf-8")).hexdigest()[:16]


class Gate:
    __slots__ = ("name", "checks", "failures", "cases", "failing", "line", "native")

    def __init__(self, name, checks, failures, cases, line):
        self.name = name
        self.checks = checks
        self.failures = failures
        self.cases = cases
        self.failing = []
        self.line = line
        # (n, id) when the gate emitted its OWN full check-identity digest, which
        # is the emission no gate makes tonight and the one that would settle the
        # question. None until one does.
        self.native = None

    @property
    def bare(self):
        return self.name.replace("NTASM_NOVA_", "")


def read_log(path):
    """Parse one log into ordered gate records.

    Returns (gates, truncated, last_line, sha256). A line it cannot parse is not
    evidence of anything and is never turned into a count.
    """
    with open(path, "rb") as fh:
        raw = fh.read()
    sha = hashlib.sha256(raw).hexdigest()
    lines = raw.decode("utf-8", errors="replace").split("\n")

    gates = []
    cur = None
    saw_done = False
    orphans = []

    for lineno, line in enumerate(lines, 1):
        last = lineno
        if not line.strip():
            continue
        if line.startswith(DONE):
            saw_done = True
            continue
        m = BANNER.match(line)
        if m:
            cur = Gate(m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4)), lineno)
            gates.append(cur)
            continue
        f = FAIL.match(line)
        if f:
            if cur is None:
                # A FAIL line with no banner above it cannot be attributed, and
                # DROPPING IT SILENTLY made this instrument report
                # named_failing_checks=0 on a log that contains 18 such lines.
                # The repository driver's log emits 12 of its 18 FAIL lines
                # before the first banner, so the positional assumption in this
                # function is false there. A line that cannot be attributed is
                # still a line that exists, and it is counted, not discarded.
                orphans.append((lineno, f.group(1)))
            else:
                cur.failing.append(identity_of(f.group(1)))
            continue
        # A gate's own full check-identity digest, if it ever emits one. Parsed
        # here so the day that emission lands the instrument already consumes it,
        # and attached to the gate it NAMES rather than to whichever banner
        # happened to precede it -- a gate printing its digest before its banner
        # must not be credited to the gate above it.
        nat = NATIVE.match(line)
        if nat:
            target = next((g for g in reversed(gates) if g.name == nat.group(1)), None)
            if target is None:
                target = Gate(nat.group(1), 0, 0, 0, lineno)
                gates.append(target)
            target.native = (int(nat.group(2)), nat.group(3))
    return gates, not saw_done, last, sha, orphans




def emit(path, out):
    gates, truncated, last, sha, orphans = read_log(path)
    out.append("LOG %s sha256=%s lines=%d gate_banners=%d terminal=%s"
               % (path, sha[:16], last, len(gates), "ABSENT" if truncated else "GATES_DONE"))

    if orphans:
        out.append("FAIL_UNATTRIBUTABLE n=%d first_line=line%d last_line=line%d "
                   "reason=NO_BANNER_ABOVE_THIS_FAIL_LINE"
                   % (len(orphans), orphans[0][0], orphans[-1][0]))
        for lineno, msg in orphans:
            out.append("FAIL_ORPHAN line=%d %s" % (lineno, identity_of(msg)))

    if truncated:
        out.append("CHECKSET_REFUSED log reason=TRUNCATED_NO_TERMINAL_MARKER last=line%d" % last)
        out.append("CHECKSET_NONE emitted=0 reason=truncated_log")
        return gates, truncated

    # The repository driver runs some gates more than once, so the same name can
    # appear twice: once carrying its FAIL lines and once as a bare re-announce.
    # Reporting both produced a FAILSET and eight CHECKFAILs for VALIDATE and
    # then a CHECKSET_REFUSED for the same VALIDATE claiming zero names -- two
    # contradictory lines about one gate, which is the shape this instrument
    # exists to refuse. Fold the repeats and say how many there were.
    folded, runs = collections.OrderedDict(), collections.Counter()
    for g in gates:
        runs[g.bare] += 1
        prev = folded.get(g.bare)
        if prev is None or len(g.failing) > len(prev.failing):
            folded[g.bare] = g
    for bare, n in runs.items():
        if n > 1:
            out.append("GATE_REPEATED %s runs=%d folded=yes" % (bare, n))
    # Prefer the occurrence whose NAME COUNT MATCHES the announced failure count.
    # The driver runs a gate more than once and the RUN_FAIL branch now prints the
    # FAIL lines on both, so the same failure is named twice per run — and taking
    # the LARGEST name list turns an eight-failure gate into a sixteen-name one
    # and then refuses it. A gate whose names never match its count is reported,
    # not silently resolved.
    folded = collections.OrderedDict()
    for g in gates:
        prev = folded.get(g.bare)
        if prev is None:
            folded[g.bare] = g
        elif len(g.failing) == g.failures and len(prev.failing) != prev.failures:
            folded[g.bare] = g
    gates = list(folded.values())
    n_named = 0
    for g in gates:
        # Impossible counters are refused first: everything below is derived
        # from these two fields.
        if g.failures > g.checks:
            out.append("CHECKSET_REFUSED %s reason=IMPOSSIBLE_COUNTERS_checks_LT_failures "
                       "checks=%d failures=%d" % (g.bare, g.checks, g.failures))
            continue

        # A gate that digested its OWN full check set. This is the one line that
        # settles the question, and it is the emission no gate makes tonight.
        #
        # It is checked FIRST and it EXCLUDES the branches below rather than
        # preceding them: a gate that emitted a full-set digest has emitted
        # identity, so also calling it CHECKSET_ABSENT in the next breath would
        # assert both that it spoke and that it said nothing. Two contradictory
        # lines about one gate is worse than either alone -- a reader cannot
        # tell which to believe, and a digest that also says "absent" is not a
        # digest anyone will trust.
        if g.native is not None:
            nn, dig = g.native
            if nn != g.checks:
                out.append("CHECKSET_REFUSED %s reason=NATIVE_SET_SIZE_%d_NE_checks_%d"
                           % (g.bare, nn, g.checks))
                continue
            out.append("CHECKSET %s n=%d id=%s scope=FULL_SET" % (g.bare, nn, dig))
            continue

        # A gate that counted failures but named a different number of them is
        # inconsistent, and the disagreement is checked BEFORE the absence
        # branch: `failures=2` with zero names is NOT a gate that named nothing,
        # it is a gate whose red is unattributable. Collapsing the two would
        # report tonight's REGISTRY as a gate with nothing to say.
        if len(g.failing) != g.failures:
            out.append("CHECKSET_REFUSED %s reason=FAIL_NAMES_%d_NE_Failures_%d "
                       "checks=%d failures=%d" % (g.bare, len(g.failing), g.failures,
                                                  g.checks, g.failures))
            continue

        if not g.failing:
            # Ran, counted, named nothing -- a green gate. Never n=0: a green
            # gate runs checks, it just named none of them.
            out.append("CHECKSET_ABSENT %s checks=%d failures=%d named=0" % (g.bare, g.checks, g.failures))
            continue

        n, dig = failset_digest(g.failing)
        out.append("FAILSET %s n=%d id=%s scope=FAILING_ONLY" % (g.bare, n, dig))
        for ident in g.failing:
            out.append("CHECKFAIL %s %s" % (g.bare, ident))
            n_named += 1

    if orphans:
        # The total is computed over the ATTRIBUTED lines only. Saying
        # named_failing_checks=0 beside an unattributable count reads as a
        # measurement; it is a partial one, and the difference is the whole
        # point of an instrument that exists to catch fail-silents.
        out.append("LOG_TOTAL %s named_failing_checks=%d gates_with_names=%d gates_total=%d "
                   "PARTIAL unattributable_fail_lines=%d"
                   % (os.path.basename(path), n_named,
                      sum(1 for l in out if l.startswith("FAILSET ")), len(gates),
                      len(orphans)))
    else:
        out.append("LOG_TOTAL %s named_failing_checks=%d gates_with_names=%d gates_total=%d"
                   % (os.path.basename(path), n_named,
                      sum(1 for l in out if l.startswith("FAILSET ")), len(gates)))
    return gates, truncated


def _write_tmp(text):
    fd, p = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)
    return p


def selftest():
    """Seven behaviours. Four of them are the degradations that decide whether
    this instrument is honest, driven from synthetic logs so that a refusal no
    real log happens to provoke is still exercised."""
    fails = []

    def t(name, ok, detail=""):
        print("  %-58s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            fails.append(name)
            if detail:
                print("      " + detail.replace("\n", "\n      "))

    def run(text):
        p = _write_tmp(text)
        buf = []
        emit(p, buf)
        os.unlink(p)
        return buf

    print("checkset.py -- selftest")

    # 1. A red gate: failing checks named, and digested as a SET.
    out = run("NTASM_NOVA_A checks=3 failures=2 cases=2\n"
              "FAIL alpha\nFAIL beta\nGATES_DONE fail=1\n")
    t("a red gate names each failing check",
      "CHECKFAIL A alpha" in out and "CHECKFAIL A beta" in out, "\n".join(out))
    t("the digest is labelled FAILING_ONLY, never as the check set",
      any(l.startswith("FAILSET A n=2 id=") and l.endswith("scope=FAILING_ONLY") for l in out),
      "\n".join(out))

    # 2. THE ABSENCE IS NOT A ZERO. A green gate names nothing; it must say so
    #    and must NOT be handed n=0, which reads as "this gate ran no checks".
    out = run("NTASM_NOVA_B checks=480 failures=0 cases=9\nGATES_DONE fail=0\n")
    t("a green gate says CHECKSET_ABSENT, never n=0",
      any(l.startswith("CHECKSET_ABSENT B checks=480 failures=0 named=0") for l in out)
      and not any(l.startswith("FAILSET B n=0") for l in out), "\n".join(out))

    # 3. THE IMPOSSIBLE COUNTERS. checks < failures refuses outright, and no
    #    digest and no named check comes out of it.
    out = run("NTASM_NOVA_C checks=2 failures=7 cases=1\nFAIL x\nGATES_DONE fail=1\n")
    t("checks<failures refuses and emits no digest",
      any("REFUSED C reason=IMPOSSIBLE_COUNTERS" in l for l in out)
      and not any(l.startswith("FAILSET C ") for l in out)
      and not any(l.startswith("CHECKFAIL C ") for l in out), "\n".join(out))

    # 4. THE TRUNCATED LOG -- broken WITHOUT tripping checks<failures.
    out = run("NTASM_NOVA_D checks=100 failures=0 cases=5\n")
    t("a truncated log refuses whole and names no gate as digested",
      any("TRUNCATED_NO_TERMINAL_MARKER" in l for l in out)
      and any(l == "CHECKSET_NONE emitted=0 reason=truncated_log" for l in out)
      and not any(l.startswith("FAILSET D ") for l in out), "\n".join(out))

    # 5. Counter vs named lines disagree -> the failing set is not trustworthy,
    #    so it is not digested and not named. This is the REGISTRY shape.
    out = run("NTASM_NOVA_E checks=3524 failures=2 cases=685\n"
              "RUN_FAIL E\nGATES_DONE fail=1\n")
    t("2 counted failures with 0 names refuses (tonight's REGISTRY)",
      any("REFUSED E reason=FAIL_NAMES_0_NE_Failures_2" in l for l in out), "\n".join(out))

    # 6. The digest is over the SET: reordering does not move it.
    a = run("NTASM_NOVA_F checks=4 failures=2 cases=1\nFAIL alpha\nFAIL beta\nGATES_DONE fail=1\n")
    b = run("NTASM_NOVA_F checks=4 failures=2 cases=1\nFAIL beta\nFAIL alpha\nGATES_DONE fail=1\n")
    da = [l for l in a if l.startswith("FAILSET F ")]
    db = [l for l in b if l.startswith("FAILSET F ")]
    t("the digest is order-insensitive (a SET, not a schedule)",
      bool(da) and bool(db) and da[0].split("id=")[1] == db[0].split("id=")[1],
      "%s vs %s" % (da, db))

    # 7. A repeated identity does not inflate the set.
    c = run("NTASM_NOVA_G checks=4 failures=2 cases=1\nFAIL alpha\nFAIL alpha\nGATES_DONE fail=1\n")
    t("a repeated identity does not inflate the set digest",
      any(l.startswith("FAILSET G n=1 id=") for l in c), "\n".join(c))

    # 8. THE IDENTITY IS THE MESSAGE, NOT ITS FIRST WORD. Pinned on verbatim
    #    lines from tonight's log, because taking the first token is wrong in a
    #    way that is invisible in the output: 12 distinct failures collapse onto
    #    8 names, the set still digests, and the digest is confidently wrong.
    out = run("NTASM_NOVA_H checks=5 failures=3 cases=1\n"
              "FAIL never call terminal ret=940 runtime=0 out=7,1,940,23\n"
              "FAIL boolean and-or precedence ret=941 runtime=0 out=12,14,941,49\n"
              "FAIL parity in bound macro=940 clear=0 want=0\n"
              "GATES_DONE fail=1\n")
    named = [l.split(" ", 2)[2] for l in out if l.startswith("CHECKFAIL H ")]
    t("the identity is the message, not its first word",
      "never call terminal" in named and "boolean and-or precedence" in named
      and "parity in bound" in named, "named=%r" % (named,))
    # `macro=940` IS a measurement here: tests_ntasm_validate.c:75 prints it as
    # a.returned, alongside clear= and want=. So it is stripped with the rest
    # and the check is called `parity in bound`. Stripping left-to-right would
    # instead cut the name to `parity`, losing which parity case this is.
    t("trailing key=value measurements are stripped, and that is the identity",
      any(l.startswith("FAILSET H n=3 id=") for l in out), "\n".join(out))

    # 9. The same check failing with DIFFERENT measurements is still the same
    #    check, so the digest does not move. A digest taken over the raw message
    #    would report a new failure every time a return code changed.
    a = run("NTASM_NOVA_I checks=1 failures=1 cases=1\nFAIL never call terminal ret=940 runtime=0\nGATES_DONE fail=1\n")
    b = run("NTASM_NOVA_I checks=1 failures=1 cases=1\nFAIL never call terminal ret=819 runtime=3\nGATES_DONE fail=1\n")
    da = [l for l in a if l.startswith("FAILSET I ")]
    db = [l for l in b if l.startswith("FAILSET I ")]
    t("a changed measurement does not change the check's identity",
      bool(da) and bool(db) and da[0].split("id=")[1] == db[0].split("id=")[1],
      "%s vs %s" % (da, db))

    # 10. THE EMISSION NO GATE MAKES TONIGHT. A gate that digests its own full
    #     check set is parsed and re-emitted with scope=FULL_SET, and a green
    #     gate carrying one is NOT called absent. This is the path that answers
    #     the question from the next run onward, exercised now so that the day
    #     the emission lands is not also the day this parser is written.
    out = run("NTASM_NOVA_J checks=4 failures=0 cases=1\n"
              "CHECKSET NTASM_NOVA_J n=4 id=0123456789abcdef\nGATES_DONE fail=0\n")
    t("a gate's own full-set digest is parsed and emitted scope=FULL_SET",
      any(l == "CHECKSET J n=4 id=0123456789abcdef scope=FULL_SET" for l in out),
      "\n".join(out))
    t("a green gate carrying its own digest is NOT reported absent",
      not any(l.startswith("CHECKSET_ABSENT J ") for l in out), "\n".join(out))

    # 11. A digest whose size contradicts the banner is refused: a gate that
    #     digests 4 checks while reporting checks=5 has disagreed with itself,
    #     and that disagreement is caught rather than digested through.
    out = run("NTASM_NOVA_K checks=5 failures=0 cases=1\n"
              "CHECKSET NTASM_NOVA_K n=4 id=0123456789abcdef\nGATES_DONE fail=0\n")
    t("a native digest contradicting checks= is refused",
      any("REFUSED K reason=NATIVE_SET_SIZE_4_NE_checks_5" in l for l in out), "\n".join(out))

    print("  -- %d/%d" % (13 - len(fails), 13))
    return 1 if fails else 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 2
    out = []
    for p in args:
        emit(p, out)
        out.append("")
    for line in out:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())