#!/usr/bin/env python3
"""checkset_cmp.py -- two logs, and the honest answer to "coverage grew or the
tree regressed?". Lot 161.

THE QUESTION, AND WHY A COUNTER CANNOT ANSWER IT

    2026-09-27 13:57   out/c-bootstrap/nova/w5-lot4-full-suite.log
                       89 gates    0 failures    19 012 cases
    2026-10-03        tonight
                       94 gates   41 failures    21 826 cases

    VALIDATE             381/0  ->  480/12      +99 checks
    INITIALIZER_TYPES    135/0  ->  679/9      +544
    REGISTRY             136/0  -> 3524/2     +3388
    X64_LOWER_NXO_PE    2384/0  -> 2631/1      +247

Two readings fit those counters equally well. Telling them apart needs, for each
failing check named tonight, one fact about the 27th:

    it was failing on the 27th              -> not new
    it PASSED on the 27th                   -> REGRESSION on an existing check
    it DID NOT EXIST on the 27th            -> NEW COVERAGE, latent defect found

The middle and the bottom are the whole question, and they are separated by
exactly one datum: did the 27th log name that check as existing?

"Passed" is not "was there". Only a name settles it.

    AND THE 27TH LOG NAMES NO CHECKS.
    w5-lot4-full-suite.log has 89 banners, 0 failures and 0 FAIL lines. A clean
    run emits no FAIL line by construction, so a green log is structurally
    incapable of recording which checks passed. Tonight's log names 39 of its
    41; the 27th names none of its 0. Diffing against it is diffing against a
    set that was never measured, and every one of tonight's 39 would come out
    "added" -- a manufactured answer, not a measurement.

SO THIS TOOL REPORTS, PER GATE

    CMP <GATE> added=.. removed=.. newly_failing=.. newly_passing=..
        Over the NAMED sets on both sides, when both sides named some.
    CMP_UNCOMPARABLE <GATE> reason=<..> old_named=.. new_named=..
        One or both sides named nothing, so no set comparison exists. The gate is
        reported with its counters and marked uncomparable. It is NEVER counted
        as "no difference" -- that would read as agreement between two logs that
        were never compared.
    CMP_OLD_ONLY / CMP_NEW_ONLY <GATE>
        The gate ran on one side only.
    CMP_ABSENT_BOTH <GATE>
        A gate named on neither side, reported rather than dropped.

and then, at the bottom, a VERDICT whose scope is printed with it. The verdict
is computed ONLY over gates whose identity sets exist on both sides. A gate
outside that scope is listed in VERDICT_EXCLUDED. There are exactly two possible
outcomes on these two logs and the tool distinguishes them rather than guessing:

    answer=NOT_ANSWERABLE
        No gate named an identity on both sides. This is tonight's outcome, and
        it is a finding, not a failure of the tool.
    answer=REGRESSION / NEW_COVERAGE / MIXED
        Reachable only once both sides name.

WHAT IT REFUSES
    * a truncated log on either side -- `ngbuild.sh` prints `tail -25` on a
      compile failure, so truncation is broken WITHOUT tripping checks<failures.
    * `checks < failures`, and `failures=N` with N names absent: the same
      refusals checkset.py makes, imported rather than reinvented.

RECIPE. Both logs are read as the project's own driver wrote them --
legacy/tools/coldproof/ngbuild.sh, which builds every harness with
    gcc -std=c11 -Wall -Wextra -Werror -O1 -g \
        -fsanitize=address,undefined -fno-omit-frame-pointer
This tool compiles nothing and runs no gate. It prints the sha256 of BOTH logs
it read, because a comparison across two instants on a moving tree is not a
measurement and the fence must be visible in the output rather than assumed.

Run:  checkset_cmp.py <old.log> <new.log>
      checkset_cmp.py --selftest
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from checkset import Gate, read_log  # noqa: E402


def collect(path):
    """One side: per gate, the named FAILING identity set, or None.

    A gate name recurring twice in one log is folded to its LAST banner, and
    the fold is reported -- six gates recur in tonight's log, which holds 100
    banner lines for 94 gates. Silently folding them would hide that.
    """
    gates, truncated, last, sha = read_log(path)
    if truncated:
        return None, truncated, last, sha, None

    folded = []
    latest = {}
    for g in gates:
        if g.name in latest:
            folded.append(g.name)
        latest[g.name] = g

    table = {}
    for name, g in latest.items():
        rec = dict(checks=g.checks, failures=g.failures, cases=g.cases, ref=None)
        if g.failures > g.checks:
            rec["ref"] = "IMPOSSIBLE_COUNTERS_checks_LT_failures"
        elif len(g.failing) != g.failures:
            # 0 names against 2 counted failures is the REGISTRY shape: the red
            # is real and unattributable, which is not the same as no red.
            rec["ref"] = "FAIL_NAMES_%d_NE_Failures_%d" % (len(g.failing), g.failures)
        # None means THE GATE EMITTED NO IDENTITY. It is NOT an empty set.
        #
        # This distinction is the whole tool. A green run prints no FAIL line
        # by construction, so a gate with failures=0 and no names has told us
        # NOTHING about which checks exist -- and reading it as "the gate named
        # an empty set" would make every failing check tonight come out ADDED
        # against it. That is how a silent log manufactures a verdict: real
        # failing checks diffed against a set nobody measured. An absent datum
        # is not a zero, and an unmeasured set is not an empty one.
        #
        # Note also what a RED gate's named set is: the checks that FAILED,
        # never the checks that ran. It settles `already_failing_on_old` and
        # bounds `added` from below; it cannot alone separate a check that
        # passed before from one that did not exist, because a check that
        # passed emits no line either.
        rec["named"] = None if (rec["ref"] or not g.failing) else set(g.failing)
        table[name] = rec

    # A gate that emitted its own full check-identity digest is decidable even if
    # it named no failure: the digest says the set EXISTS, and its equality with
    # the other side's is exactly the "did the check set move" comparison. The
    # identities themselves are not printed -- only compared by digest -- which
    # is what keeps the answer to 21 826 checks one line per gate.
    native = {name: g.native for name, g in latest.items() if g.native is not None}
    for name, (nn, dig) in native.items():
        rec = table.setdefault(name, dict(checks=0, failures=0, cases=0, ref=None, named=None))
        rec["checks"] = max(rec["checks"], nn)
        rec["native"] = (nn, dig)
        table[name] = rec

    return table, truncated, last, sha, sorted(set(folded))


def compare(old_path, new_path):
    out = []
    old, o_trunc, o_last, o_sha, o_fold = collect(old_path)
    new, n_trunc, n_last, n_sha, n_fold = collect(new_path)

    out.append("CMP_LOG old=%s sha256=%s lines=%d terminal=%s named_gates=%s"
               % (old_path, o_sha[:16], o_last, "ABSENT" if o_trunc else "GATES_DONE",
                  "ABSENT" if o_trunc else sum(1 for v in old.values() if v["named"] is not None)))
    out.append("CMP_LOG new=%s sha256=%s lines=%d terminal=%s named_gates=%s"
               % (new_path, n_sha[:16], n_last, "ABSENT" if n_trunc else "GATES_DONE",
                  "ABSENT" if n_trunc else sum(1 for v in new.values() if v["named"] is not None)))
    for lbl, fold in (("old", o_fold), ("new", n_fold)):
        if fold:
            out.append("CMP_NOTE %s_log_repeated_gate_banners=%d folded_to_last=%s"
                       % (lbl, len(fold),
                          ",".join(x.replace("NTASM_NOVA_", "") for x in fold)))

    # Refuse rather than produce a number from half a log.
    if o_trunc:
        out.append("CMP_REFUSED old_log reason=TRUNCATED_NO_TERMINAL_MARKER last=line%d" % o_last)
        return out, None
    if n_trunc:
        out.append("CMP_REFUSED new_log reason=TRUNCATED_NO_TERMINAL_MARKER last=line%d" % n_last)
        return out, None

    o_names, n_names = set(old), set(new)
    common = sorted(o_names & n_names)
    changed = []
    uncomparable = []

    for name in common:
        o, n = old[name], new[name]
        bare = name.replace("NTASM_NOVA_", "")
        if o["ref"] or n["ref"]:
            out.append("CMP_UNCOMPARABLE %s reason=%s old=%d/%d new=%d/%d"
                       % (bare, o["ref"] or n["ref"], o["checks"], o["failures"],
                          n["checks"], n["failures"]))
            uncomparable.append(name)
            continue
        if o["named"] is None or n["named"] is None:
            side = "OLD" if o["named"] is None else "NEW"
            out.append("CMP_UNCOMPARABLE %s reason=IDENTITY_ABSENT_ON_%s old=%d/%d new=%d/%d"
                       % (bare, side, o["checks"], o["failures"], n["checks"], n["failures"]))
            uncomparable.append(name)
            continue

        added = n["named"] - o["named"]
        removed = o["named"] - n["named"]
        nf = n["named"] - o["named"]
        np_ = o["named"] - n["named"]
        if not (added or removed or nf or np_):
            continue
        changed.append((bare, added, removed, nf, np_))
        out.append("CMP %s added=%d removed=%d newly_failing=%d newly_passing=%d"
                   % (bare, len(added), len(removed), len(nf), len(np_)))
        for i in sorted(nf):
            out.append("  NEWLY_FAILING %s" % i)
        for i in sorted(np_):
            out.append("  NEWLY_PASSING %s" % i)
        for i in sorted(added):
            out.append("  ADDED %s" % i)
        for i in sorted(removed):
            out.append("  REMOVED %s" % i)

    for name in sorted(o_names - n_names):
        out.append("CMP_OLD_ONLY %s old=%d/%d new=ABSENT"
                   % (name.replace("NTASM_NOVA_", ""), old[name]["checks"], old[name]["failures"]))
    for name in sorted(n_names - o_names):
        out.append("CMP_NEW_ONLY %s old=ABSENT new=%d/%d"
                   % (name.replace("NTASM_NOVA_", ""), new[name]["checks"], new[name]["failures"]))

    # ---- THE VERDICT -------------------------------------------------------
    # Only gates named on BOTH sides can decide the question. Everything else is
    # excluded AND NAMED: a verdict whose denominator is not printed is a verdict
    # nobody can audit, and the register has been burned by unprinted scope once
    # already tonight.
    decidable, excluded = [], []
    for name in sorted(o_names & n_names):
        (decidable if (old[name]["named"] is not None and new[name]["named"] is not None)
         else excluded).append(name)

    on_new = sorted({i for name in decidable for i in new[name]["named"]})
    # A named failure tonight that the old log ALSO named was already failing.
    # A named failure the old log did not name is either an old passing check
    # that broke, or a check that did not exist -- and which of those two is
    # exactly what the old log's silence makes undecidable.
    already_red = sorted(i for i in on_new
                         if i in {x for name in decidable for x in old[name]["named"]})
    undecided = sorted(i for i in on_new
                       if i not in {x for name in decidable for x in old[name]["named"]})

    # A gate that did not exist at all on the old side IS decidable, and in one
    # direction only: every check in it is new by definition, so a red in it is
    # new coverage and cannot be a regression. This case is real tonight --
    # SPLICE ran 609 checks and 17 of them failed, and the old log has no
    # SPLICE banner at all. Calling that undecidable would be as wrong as
    # calling it a regression: the gate's absence settles it.
    new_only_named, new_only_unnamed = [], []
    for name in sorted(n_names - o_names):
        (new_only_named if new[name]["named"] is not None
         else new_only_unnamed).append(name)
    on_new_only = sorted({i for name in new_only_named for i in new[name]["named"]})

    # THE COMPARISON THAT ANSWERS IT, once both sides digest their own set. The
    # digests are compared for EQUALITY, which is the "did the check set move"
    # question in one comparison per gate, without printing a single identity
    # when the answer is "no". Equal digests on a red gate mean the reds are the
    # SAME reds on checks that already existed: a regression. Differing digests
    # mean the set moved, and the named failures are then new checks: coverage
    # that grew. This is the only branch that can settle the question, and it is
    # unreachable tonight because no gate emits a digest.
    native_moved, native_same = [], []
    for name in sorted(o_names & n_names):
        o_nat, n_nat = old[name].get("native"), new[name].get("native")
        if not o_nat or not n_nat:
            continue
        bare = name.replace("NTASM_NOVA_", "")
        if o_nat[1] == n_nat[1]:
            native_same.append(bare)
            if new[name]["failures"] > 0:
                out.append("CMP_SET %s old_n=%d new_n=%d SET_IDENTICAL "
                           "failures_old=%d failures_new=%d verdict=REGRESSION_ON_EXISTING_CHECKS"
                           % (bare, o_nat[0], n_nat[0], old[name]["failures"],
                              new[name]["failures"]))
        else:
            native_moved.append(bare)
            out.append("CMP_SET %s old_n=%d new_n=%d SET_MOVED delta=%+d "
                       "failures_old=%d failures_new=%d verdict=NEW_COVERAGE"
                       % (bare, o_nat[0], n_nat[0], n_nat[0] - o_nat[0],
                          old[name]["failures"], new[name]["failures"]))
            if new[name]["named"]:
                for i in sorted(new[name]["named"]):
                    out.append("  NEWLY_NAMED_FAILURE %s" % i)

    # Counted reds on gates whose identity is absent on either side. These are
    # REAL failures that no identity comparison can classify, and they are
    # reported as a count so the verdict's own denominator is visible.
    unclassified = sorted(
        name.replace("NTASM_NOVA_", "")
        for name in sorted(n_names)
        if new[name]["failures"] > 0 and name not in decidable and name not in new_only_named)
    unclassified_fails = sum(new[name]["failures"] for name in n_names
                             if name.replace("NTASM_NOVA_", "") in unclassified)

    out.append("")
    out.append("VERDICT_SCOPE gates_decidable=%d gates_new_only_named=%d "
               "gates_excluded=%d gates_old_only=%d gates_new_only_unnamed=%d "
               "gates_native_set_compared=%d"
               % (len(decidable), len(new_only_named), len(excluded),
                  len(o_names - n_names), len(new_only_unnamed),
                  len(native_same) + len(native_moved)))
    if excluded:
        out.append("VERDICT_EXCLUDED %s" % ",".join(
            x.replace("NTASM_NOVA_", "") for x in excluded))
    if unclassified:
        out.append("VERDICT_UNCLASSIFIED gates=%s failures=%d reason=IDENTITY_ABSENT_OR_INCONSISTENT"
                   % (",".join(unclassified), unclassified_fails))
    out.append("VERDICT named_failures_decidable=%d already_failing_on_old=%d "
               "new_gate_failures=%d undecidable_without_old_identities=%d"
               % (len(on_new) + len(on_new_only), len(already_red),
                  len(on_new_only), len(undecided)))

    # A gate whose set digest is IDENTICAL on both sides and which is red tonight
    # is a regression on checks that demonstrably already existed -- the one
    # verdict that cannot be argued with. It outranks everything below, because
    # it rests on a comparison that was actually made rather than on one that
    # was merely possible.
    # `native_same` and `native_moved` hold BARE gate names, for printing, so the
    # table is indexed by the full banner name here. Getting these two name forms
    # confused raises a KeyError, which is at least a loud failure -- but the fix
    # is written down so nobody "simplifies" one form into the other.
    regressed = [g for g in native_same if new["NTASM_NOVA_" + g]["failures"] > 0]
    if regressed:
        out.append("VERDICT answer=REGRESSION gates=%s -- identical check-set digest on both "
                   "sides and red tonight, so these reds sit on checks that existed"
                   % ",".join(regressed))
        answer = "REGRESSION"
    elif native_moved:
        out.append("VERDICT answer=NEW_COVERAGE gates=%s -- the check-set digest moved on these "
                   "gates, so tonight's reds sit on checks the old log did not have"
                   % ",".join(native_moved))
        answer = "NEW_COVERAGE"
    elif not decidable and not new_only_named:
        out.append("VERDICT answer=NOT_ANSWERABLE reason=no_gate_named_an_identity_on_both_sides")
        answer = "NOT_ANSWERABLE"
    elif not decidable:
        out.append("VERDICT answer=NEW_COVERAGE_ONLY decidable_gates=none; the %d named "
                   "failures that CAN be classified all sit in %s, which had no banner on "
                   "the old side at all -- new coverage, not a regression"
                   % (len(on_new_only),
                      ",".join(x.replace("NTASM_NOVA_", "") for x in new_only_named)))
        answer = "NEW_COVERAGE_ONLY"
    elif undecided and not already_red and not on_new_only:
        out.append("VERDICT answer=NEW_COVERAGE all %d named failures are absent from the old "
                   "log's named set" % len(undecided))
        answer = "NEW_COVERAGE"
    elif already_red and not undecided and not on_new_only:
        out.append("VERDICT answer=REGRESSION all %d named failures were already named on the "
                   "old side" % len(already_red))
        answer = "REGRESSION"
    else:
        bits = []
        if already_red:
            bits.append("%d already failing on the old side" % len(already_red))
        if on_new_only:
            bits.append("%d in gates absent from the old side" % len(on_new_only))
        if undecided:
            bits.append("%d undecidable without the old identities" % len(undecided))
        out.append("VERDICT answer=MIXED %s" % ", ".join(bits))
        answer = "MIXED"
    return out, dict(answer=answer, decidable=decidable, excluded=excluded,
                     new_only_named=new_only_named, on_new=on_new,
                     on_new_only=on_new_only, already_red=already_red,
                     undecided=undecided, unclassified=unclassified,
                     unclassified_fails=unclassified_fails)


def _tmp(text):
    import tempfile
    fd, p = tempfile.mkstemp(suffix=".log")
    os.close(fd)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(text)
    return p


def selftest():
    """Seven behaviours. The third is the one that decides whether this tool can
    lie: a log that named nothing must NOT be diffed against an empty set."""
    fails = []

    def t(name, ok, detail=""):
        print("  %-58s %s" % (name, "ok" if ok else "FAIL"))
        if not ok:
            fails.append(name)
            if detail:
                print("      " + detail.replace("\n", "\n      "))

    def pair(o, n):
        po, pn = _tmp(o), _tmp(n)
        out, v = compare(po, pn)
        os.unlink(po); os.unlink(pn)
        return out, v

    print("checkset_cmp.py -- selftest")

    # 1. A check already failing on the old side stays red: not new.
    out, v = pair("NTASM_NOVA_G checks=3 failures=1 cases=2\nFAIL alpha\nGATES_DONE fail=1\n",
                  "NTASM_NOVA_G checks=3 failures=2 cases=2\nFAIL alpha\nFAIL beta\nGATES_DONE fail=1\n")
    t("a check already red on the old side is not counted new",
      v and v["already_red"] == ["alpha"] and v["undecided"] == ["beta"]
      and any("CMP G added=1 removed=0 newly_failing=1 newly_passing=0" in l for l in out),
      "\n".join(out))

    # 2. The symmetric difference, with the four quantities disjoint.
    out, v = pair("NTASM_NOVA_H checks=3 failures=2 cases=1\nFAIL alpha\nFAIL beta\nGATES_DONE fail=1\n",
                  "NTASM_NOVA_H checks=3 failures=2 cases=1\nFAIL beta\nFAIL gamma\nGATES_DONE fail=1\n")
    t("newly_failing + newly_passing == the symmetric difference of the red sets",
      any("CMP H added=1 removed=1 newly_failing=1 newly_passing=1" in l for l in out),
      "\n".join(out))

    # 3. THE EMPTY-SET TRAP. The old side named NOTHING -- tonight's real
    #    situation. Every new failure would look "added" against an empty set.
    out, v = pair("NTASM_NOVA_I checks=300 failures=0 cases=9\nGATES_DONE fail=0\n",
                  "NTASM_NOVA_I checks=300 failures=2 cases=9\nFAIL x\nFAIL y\nGATES_DONE fail=1\n")
    t("a log that named nothing is UNCOMPARABLE, never diffed vs empty",
      any("CMP_UNCOMPARABLE I reason=IDENTITY_ABSENT_ON_OLD" in l for l in out)
      and not any(l.startswith("CMP I ") for l in out)
      and any("answer=NOT_ANSWERABLE" in l for l in out), "\n".join(out))

    # 4. No gate named on both sides -> NOT_ANSWERABLE, with the scope printed.
    out, v = pair("NTASM_NOVA_J checks=9 failures=0 cases=1\nGATES_DONE fail=0\n"
                  "NTASM_NOVA_K checks=9 failures=0 cases=1\nGATES_DONE fail=0\n",
                  "NTASM_NOVA_J checks=9 failures=1 cases=1\nFAIL j1\nGATES_DONE fail=1\n"
                  "NTASM_NOVA_K checks=9 failures=1 cases=1\nFAIL k1\nGATES_DONE fail=1\n")
    t("an identity-absent old side gives NOT_ANSWERABLE and prints the scope",
      v and v["answer"] == "NOT_ANSWERABLE" and v["decidable"] == []
      and any("VERDICT_SCOPE gates_decidable=0" in l and "gates_excluded=2" in l for l in out),
      "\n".join(out))
    t("reds on unclassified gates are counted, not dropped from the denominator",
      v and v["unclassified"] == ["J", "K"] and v["unclassified_fails"] == 2
      and any("VERDICT_UNCLASSIFIED gates=J,K failures=2" in l for l in out),
      "\n".join(out))

    # 5. Truncated side refuses the whole comparison, not one gate.
    out, v = pair("NTASM_NOVA_L checks=1 failures=0 cases=0\nGATES_DONE fail=0\n",
                  "NTASM_NOVA_L checks=1 failures=1 cases=0\nFAIL z\n")
    t("a truncated new log refuses the comparison outright",
      v is None and any("CMP_REFUSED new_log reason=TRUNCATED" in l for l in out),
      "\n".join(out))

    # 6. A gate on one side only is named, never silently dropped.
    out, v = pair("NTASM_NOVA_M checks=1 failures=0 cases=0\nGATES_DONE fail=0\n",
                  "NTASM_NOVA_M checks=1 failures=0 cases=0\n"
                  "NTASM_NOVA_N checks=9 failures=3 cases=1\nFAIL q\nGATES_DONE fail=1\n")
    t("a gate absent from the old side is reported as NEW_ONLY",
      any("CMP_NEW_ONLY N" in l for l in out), "\n".join(out))

    # 7. 2 counted failures with 0 names is a REFUSAL, not an empty set --
    #    tonight's REGISTRY. It must not silently become "named nothing".
    out, v = pair("NTASM_NOVA_P checks=136 failures=0 cases=10\nGATES_DONE fail=0\n",
                  "NTASM_NOVA_P checks=3524 failures=2 cases=685\nRUN_FAIL P\nGATES_DONE fail=1\n")
    t("counted failures with no names are refused, not read as an empty set",
      any("CMP_UNCOMPARABLE P reason=FAIL_NAMES_0_NE_Failures_2" in l for l in out),
      "\n".join(out))

    # 8. A gate ABSENT from the old side is decidable in one direction: every
    #    check in it is new, so its reds are new coverage, never a regression.
    #    Tonight's SPLICE is this shape -- 609 checks, 17 red, no old banner.
    #    Reporting it as undecidable would be as wrong as calling it a
    #    regression, so the verdict has to name it as decidable.
    out, v = pair("NTASM_NOVA_Q checks=5 failures=0 cases=1\nGATES_DONE fail=0\n",
                  "NTASM_NOVA_Q checks=5 failures=0 cases=1\n"
                  "NTASM_NOVA_SPLICE checks=609 failures=2 cases=50\n"
                  "FAIL pipeline twice data\nFAIL pipeline makes fn\nGATES_DONE fail=1\n")
    t("a gate absent from the old side is NEW_COVERAGE_ONLY, decidable",
      v and v["answer"] == "NEW_COVERAGE_ONLY"
      and v["on_new_only"] == ["pipeline makes fn", "pipeline twice data"]
      and any("gates_decidable=0 gates_new_only_named=1" in l for l in out),
      "\n".join(out))

    # 9. A mixed case: a red in a gate that existed, plus a red in a gate that
    #    did not. Both are reported, and neither is allowed to absorb the other.
    out, v = pair("NTASM_NOVA_R checks=3 failures=1 cases=1\nFAIL alpha\nGATES_DONE fail=1\n",
                  "NTASM_NOVA_R checks=3 failures=2 cases=1\nFAIL alpha\nFAIL beta\n"
                  "NTASM_NOVA_S checks=3 failures=1 cases=1\nFAIL gamma\nGATES_DONE fail=1\n")
    t("a red in an old gate and a red in a new gate report as MIXED, neither absorbed",
      v and v["answer"] == "MIXED" and v["already_red"] == ["alpha"]
      and v["undecided"] == ["beta"] and v["on_new_only"] == ["gamma"],
      "\n".join(out))

    # 10. THE ANSWER, ONCE THE EMISSION EXISTS. An identical check-set digest on
    #     both sides plus red tonight means the reds sit on checks that already
    #     existed -- a regression, and the one verdict that cannot be argued
    #     with, because it rests on a comparison that was actually made rather
    #     than on one that was merely possible.
    out, v = pair("NTASM_NOVA_S1 checks=381 failures=0 cases=9\n"
                  "CHECKSET NTASM_NOVA_S1 n=381 id=aaaa0000aaaa0000\nGATES_DONE fail=0\n",
                  "NTASM_NOVA_S1 checks=381 failures=2 cases=9\n"
                  "FAIL never call terminal\nFAIL parity in bound\n"
                  "CHECKSET NTASM_NOVA_S1 n=381 id=aaaa0000aaaa0000\nGATES_DONE fail=1\n")
    t("an identical set digest with red tonight reads REGRESSION",
      v and v["answer"] == "REGRESSION"
      and any("CMP_SET S1 old_n=381 new_n=381 SET_IDENTICAL" in l for l in out)
      and any("verdict=REGRESSION_ON_EXISTING_CHECKS" in l for l in out), "\n".join(out))

    # 11. The other half of the same comparison: the digest moved, so the reds
    #     are on checks the old run never had. Same gate, same format -- decided
    #     entirely by the digest and not by any count.
    out, v = pair("NTASM_NOVA_S2 checks=381 failures=0 cases=9\n"
                  "CHECKSET NTASM_NOVA_S2 n=381 id=aaaa0000aaaa0000\nGATES_DONE fail=0\n",
                  "NTASM_NOVA_S2 checks=480 failures=1 cases=9\n"
                  "FAIL never call terminal\n"
                  "CHECKSET NTASM_NOVA_S2 n=480 id=bbbb1111bbbb1111\nGATES_DONE fail=1\n")
    t("a moved set digest reads NEW_COVERAGE, and names the new failures",
      v and v["answer"] == "NEW_COVERAGE"
      and any("CMP_SET S2 old_n=381 new_n=480 SET_MOVED delta=+99" in l for l in out)
      and any("NEWLY_NAMED_FAILURE never call terminal" in l for l in out), "\n".join(out))

    print("  -- %d/%d" % (11 - len(fails), 11))
    return 1 if fails else 0


def main():
    if "--selftest" in sys.argv:
        return selftest()
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if len(args) != 2:
        print(__doc__)
        return 2
    out, _ = compare(args[0], args[1])
    for line in out:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())