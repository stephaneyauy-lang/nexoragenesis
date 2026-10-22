#!/usr/bin/env python3
"""claim_selftest.py — the five arms, on a scratch tree, touching nothing else.

Every arm runs against a temporary directory built here, with `--root` pointed
at it. No file of the real tree is read for judgement and none is written.

Each arm prints the VERDICT it expected, the VERDICT it got, and a
before/after count, because the two failure shapes this project has actually
produced both hide in a bare "ok":

  * an instrument that is green because it exercised nothing, and
  * a perturbation too weak to remove what the rule was carrying.

So arm 4 ships a CONTROL GROUP. The same lot, the same file set, the same
release — once with nothing moved, once with a file moved that was never
claimed. If the two releases agree, the detector is not carrying the rule and
the arm reports `PROOF_INVALID` instead of a pass. The count line is printed
before the verdict for the same reason.

Exit 0 all arms behaved as declared. Exit 1 an arm did not.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLAIM = os.path.join(HERE, "claim.py")

CLEAN, FINDING, UNUSABLE, USAGE = 0, 1, 2, 3
HOUR = 3600.0
T0 = 1780000000.0  # a fixed instant, so --now is deterministic across runs

SURFACE_DIR = "compiler/nova"
SURFACE_FILES = ("a.nova", "b.nova", "c.nova")

failures: list[str] = []


def say(line: str) -> None:
    print(line)


def run(root: str, *args: str, now: float | None = None) -> tuple[int, str]:
    cmd = [sys.executable, CLAIM, *args, "--root", root]
    if now is not None:
        cmd += ["--now", repr(now)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def expect(name: str, cond: bool, detail: str) -> None:
    if cond:
        say(f"  ARM-OK   {name}")
    else:
        say(f"  ARM-FAIL {name} :: {detail}")
        failures.append(f"{name} :: {detail}")


def make_root() -> str:
    root = tempfile.mkdtemp(prefix="ng-claim-selftest-")
    d = os.path.join(root, SURFACE_DIR)
    os.makedirs(d)
    for i, f in enumerate(SURFACE_FILES):
        with open(os.path.join(d, f), "w", encoding="utf-8") as fh:
            fh.write(f"module m{i};\n" + "x" * 64 + "\n")
    with open(os.path.join(root, "MEM.md"), "w", encoding="utf-8") as fh:
        fh.write("# scratch\n")
    return root


def touch(path: str, marker: str) -> int:
    """A real write, then a real mtime advance. Returns the observed delta in ns.

    The utime call is what a text editor does on save, and it is there so the
    test does not depend on the filesystem's mtime granularity. The DELTA is
    returned so the caller can print it: if a platform gave back 0 ns, the arm
    would be asserting a detection it never exercised, which is the whole class
    of defect this project keeps re-learning.
    """
    before = os.stat(path).st_mtime_ns
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"; {marker}\n")
    after = os.stat(path).st_mtime_ns
    if after <= before:  # a save inside the same timestamp tick
        os.utime(path, ns=(after + 2_000_000_000, after + 2_000_000_000))
        after = os.stat(path).st_mtime_ns
    return after - before


# ----------------------------------------------------------------------- arm 1


def arm1(root: str) -> None:
    say("ARM 1  two lots claim the same file -> the SECOND is refused, naming the holder")
    rc1, out1 = run(root, "claim", "--lot", "lot-110", f"{SURFACE_DIR}/a.nova", now=T0)
    expect("arm1.first-claim-accepted", rc1 == CLEAN, f"rc={rc1}\n{out1}")
    rc2, out2 = run(root, "claim", "--lot", "lot-111", f"{SURFACE_DIR}/a.nova", now=T0 + 60)
    expect("arm1.second-refused", rc2 == FINDING, f"rc={rc2}\n{out2}")
    expect("arm1.names-holder", "holder=lot-110" in out2, f"no holder named:\n{out2}")
    expect("arm1.names-when",
           f"holder_claimed_at={int(T0)}" in out2, f"no claim time:\n{out2}")
    expect("arm1.says-conflict-not-generic", "CLAIM-REFUSED" in out2, out2)
    say(f"    REFUSAL LINE: {out2.strip()}")
    # And the refused claim left no record: a refusal that still wrote a
    # holder would block the third lot with a lie.
    rc3, out3 = run(root, "claim", "--lot", "lot-112", f"{SURFACE_DIR}/a.nova", now=T0 + 120)
    expect("arm1.refusal-wrote-nothing", rc3 == FINDING and "holder=lot-110" in out3,
           f"third lot saw:\n{out3}")


# ----------------------------------------------------------------------- arm 2


def arm2(root: str) -> None:
    say("ARM 2  two lots claim different files -> both proceed")
    rc1, out1 = run(root, "claim", "--lot", "lot-113", f"{SURFACE_DIR}/b.nova", now=T0)
    expect("arm2.first-proceeds", rc1 == CLEAN, f"rc={rc1}\n{out1}")
    rc2, out2 = run(root, "claim", "--lot", "lot-114", f"{SURFACE_DIR}/c.nova", now=T0)
    expect("arm2.second-proceeds", rc2 == CLEAN, f"rc={rc2}\n{out2}")
    expect("arm2.no-false-refusal", "CLAIM-REFUSED" not in out2, out2)
    # Release both without moving anything: a clean run must be CLEAN, or the
    # mechanism is a constant-red and arms 1/3/4 prove nothing.
    r1, o1 = run(root, "release", "--lot", "lot-113", now=T0 + 30)
    expect("arm2.release-clean", r1 == CLEAN, f"rc={r1}\n{o1}")
    r2, o2 = run(root, "release", "--lot", "lot-114", now=T0 + 31)
    expect("arm2.release-clean-2", r2 == CLEAN, f"rc={r2}\n{o2}")
    expect("arm2.control-group-green", "moved=0" in o1 and "RELEASE-NOTHING-MOVED" in o1,
           f"control did not exercise the counter:\n{o1}")


# ----------------------------------------------------------------------- arm 3


def arm3(root: str) -> None:
    say("ARM 3  a lot claims, then never claims again -> does the claim expire?")
    rc, out = run(root, "claim", "--lot", "lot-115", f"{SURFACE_DIR}/a.nova", now=T0)
    expect("arm3.claimed", rc == CLEAN, f"rc={rc}\n{out}")
    later = T0 + 6 * HOUR + 1

    # While the lease is live the claim still refuses.
    rc_mid, out_mid = run(root, "claim", "--lot", "lot-116", f"{SURFACE_DIR}/a.nova",
                          now=T0 + 6 * HOUR - 60)
    expect("arm3.live-lease-still-refuses", rc_mid == FINDING and "holder=lot-115" in out_mid,
           f"rc={rc_mid}\n{out_mid}")

    # After the lease, the claim no longer blocks.
    rc_after, out_after = run(root, "claim", "--lot", "lot-117", f"{SURFACE_DIR}/a.nova",
                              now=later)
    expect("arm3.expired-claim-does-not-block", rc_after == CLEAN, f"rc={rc_after}\n{out_after}")
    say(f"    POST-EXPIRY CLAIM: {out_after.strip().splitlines()[0]}")

    # WHO NOTICES. The global report names the dead holder. This is the whole
    # answer to "and who notices": not the next lot by accident — the report,
    # which is the one verb that requires nothing of anybody.
    rc_rep, out_rep = run(root, "report", now=later)
    expect("arm3.report-names-expiry", "CLAIM-EXPIRED lot=lot-115" in out_rep, out_rep)
    expect("arm3.report-states-retained", "retained=yes" in out_rep, out_rep)
    expect("arm3.report-shows-overdue", "overdue_s=1" in out_rep, out_rep)

    # The record is RETAINED, not deleted. A claim that vanishes is a claim
    # that can be covered up, and the report is the witness.
    state = os.path.join(root, "out", "coldproof", "claims")
    retained = os.path.isfile(os.path.join(state, "lot-115.json"))
    expect("arm3.expired-record-retained-on-disk", retained,
           "lot-115.json was deleted on expiry")

    # The cost of a stale claim, measured rather than asserted: a move to the
    # dead holder's file is reported UNCLAIMED, i.e. the LOUD label. Expiry
    # must fail toward noise.
    delta = touch(os.path.join(root, SURFACE_DIR, "a.nova"), "arm3 stale")
    rc_mv, out_mv = run(root, "report", now=later)
    expect("arm3.stale-edit-is-loud-not-silent",
           "held-by=NONE" in out_mv and "REPORT-UNCLAIMED" in out_mv, out_mv)
    say(f"    STALE-CLAIM COST: an edit under an expired claim reads "
        f"held-by=NONE (mtime delta observed {delta} ns) — loud, not silent")

    # lot-115 CANNOT re-claim a.nova here, and must not: lot-117 took it
    # legally sixty seconds ago and its lease is live. The first version of
    # this arm asserted that lot-115's re-claim succeeded, and it failed —
    # correctly. The tool was enforcing a real conflict and the test was
    # asserting the wrong thing about it. It is kept as an assertion now,
    # because "the expired lot cannot simply take its file back" is a
    # property worth pinning.
    rc_re, out_re = run(root, "claim", "--lot", "lot-115", f"{SURFACE_DIR}/a.nova",
                        now=later + 60)
    expect("arm3.expiry-does-not-resurrect-the-old-claim",
           rc_re == FINDING and "holder=lot-117" in out_re, f"rc={rc_re}\n{out_re}")

    # Re-claiming refreshes the lease, and this is measured rather than
    # assumed: the SAME file, free of other holders, claimed twice, and the
    # lease_until read off both lines. A refresh that silently kept the old
    # expiry would pass an assertion that only checked the exit code.
    rc_a, out_a = run(root, "claim", "--lot", "lot-160", f"{SURFACE_DIR}/b.nova", now=T0)
    expect("arm3.refresh-first-claim", rc_a == CLEAN, f"rc={rc_a}\n{out_a}")
    rc_b, out_b = run(root, "claim", "--lot", "lot-160", f"{SURFACE_DIR}/b.nova",
                      now=T0 + 2 * HOUR)
    expect("arm3.re-claim-refreshes", rc_b == CLEAN, f"rc={rc_b}\n{out_b}")

    def lease_of(text: str) -> float:
        for line in text.splitlines():
            if line.startswith("CLAIMED lot="):
                for tok in line.split():
                    if tok.startswith("lease_until="):
                        return float(tok.split("=", 1)[1])
        return -1.0

    l1, l2 = lease_of(out_a), lease_of(out_b)
    say(f"    LEASE REFRESH: lease_until {l1:.0f} -> {l2:.0f} "
        f"(claimed_at advanced too, so this is a renewal and not a re-read)")
    expect("arm3.lease-actually-advanced", l2 > l1, f"lease_until {l1} -> {l2}")
    expect("arm3.renewal-is-a-full-new-lease", l2 == T0 + 2 * HOUR + 6 * HOUR,
           f"lease_until={l2}, wanted {T0 + 8 * HOUR:.0f} — a refresh that kept "
           f"the ORIGINAL expiry would leave a long lot unprotected")


# ----------------------------------------------------------------------- arm 4


def arm4(root: str) -> None:
    say("ARM 4  a lot claims a file, then EDITS a file it did NOT claim")
    say("       <- the case that produced twenty-nine false reds")

    # CONTROL: claim b.nova, move nothing, release -> CLEAN. Without this, a
    # release that is always red would satisfy every assertion below.
    rc_c, out_c = run(root, "claim", "--lot", "lot-120", f"{SURFACE_DIR}/b.nova", now=T0)
    expect("arm4.control-claim", rc_c == CLEAN, f"rc={rc_c}\n{out_c}")
    r_clean, o_clean = run(root, "release", "--lot", "lot-120", now=T0 + 10)
    say(f"    CONTROL RELEASE: {o_clean.strip()}")
    expect("arm4.control-is-clean", r_clean == CLEAN, f"rc={r_clean}\n{o_clean}")

    # The perturbation: a lot claims c.nova and edits a.nova, which it never
    # claimed. The declaration is present and CORRECT as far as it goes; the
    # edit is outside it. This is the arm a declared-files-only design misses.
    rc_t, out_t = run(root, "claim", "--lot", "lot-121", f"{SURFACE_DIR}/c.nova", now=T0)
    expect("arm4.claim-taken", rc_t == CLEAN, f"rc={rc_t}\n{out_t}")
    delta = touch(os.path.join(root, SURFACE_DIR, "a.nova"), "arm4 undeclared")
    say(f"    UNDECLARED EDIT: wrote a.nova while claiming only c.nova "
        f"(mtime delta observed {delta} ns)")
    expect("arm4.perturbation-actually-moved", delta > 0, "the edit did not move the file")

    r_dirty, o_dirty = run(root, "release", "--lot", "lot-121", now=T0 + 20)
    say(f"    DIRTY RELEASE:\n" + "\n".join("      " + l for l in o_dirty.strip().splitlines()))
    expect("arm4.undeclared-edit-caught", r_dirty == FINDING, f"rc={r_dirty}\n{o_dirty}")
    expect("arm4.names-the-file", f"path={SURFACE_DIR}/a.nova" in o_dirty, o_dirty)
    expect("arm4.says-held-by-none", "held-by=NONE" in o_dirty, o_dirty)
    expect("arm4.does-not-blame-the-claimed-file",
           f"path={SURFACE_DIR}/c.nova" not in o_dirty.split("MOVED-UNCLAIMED")[1].split("SUMMARY")[0]
           if "MOVED-UNCLAIMED" in o_dirty else True,
           o_dirty)

    # THE PERTURBATION MUST CHANGE THE COUNT. If the two releases agree, the
    # instrument is not carrying the rule, and saying PASS here would be the
    # exact defect AGENTS.md names: an instrument that cannot refute itself by
    # being turned.
    def moved_count(text: str) -> int:
        for line in text.splitlines():
            if line.startswith("RELEASE lot="):
                for tok in line.split():
                    if tok.startswith("moved="):
                        return int(tok.split("=", 1)[1])
        return -1

    m_clean, m_dirty = moved_count(o_clean), moved_count(o_dirty)
    say(f"    PERTURBATION STRENGTH: moved count {m_clean} -> {m_dirty}")
    if m_dirty == m_clean:
        say("  PROOF_INVALID the undeclared edit did not change the movement "
            "count, so the rule was never exercised and this arm proves nothing")
        failures.append("arm4.proof-invalid")
    expect("arm4.movement-count-rose", m_dirty > m_clean,
           f"control moved={m_clean} dirty moved={m_dirty}")

    # And the global report catches the same edit with no lot cooperating.
    rc_g, out_g = run(root, "report", "--since", repr(T0), now=T0 + 40)
    expect("arm4.report-also-catches",
           f"path={SURFACE_DIR}/a.nova" in out_g and "held-by=NONE" in out_g, out_g)

    # THE LOAD-BEARING CASE, and the one the whole design is justified by: a
    # lot that ignores the mechanism ENTIRELY. It never claims, never releases,
    # edits two files and walks away. The obligation — if this is one — is
    # ignored completely, and the consequence must still be loud, specific and
    # non-zero. This is measured on a tree with no claim state at all, because
    # a lot that never claims leaves no state, and a report that required state
    # would be blind to exactly this lot. It was, until it was measured here.
    ignore = os.path.join(root, "ignores-everything")
    os.makedirs(os.path.join(ignore, SURFACE_DIR))
    # All three are dated 30 h back — OUTSIDE the 24 h window — and only two
    # are then brought inside it. Dating only the two was the first version,
    # and the report duly listed all three: the third was genuinely inside the
    # window, having just been created. The count is now exact, and asserted
    # exact, so a report that started naming files at random could not pass.
    for i, f in enumerate(SURFACE_FILES):
        p = os.path.join(ignore, SURFACE_DIR, f)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(f"module g{i};\n")
        os.utime(p, (T0 - 30 * HOUR, T0 - 30 * HOUR))  # outside the window
    for f in ("a.nova", "b.nova"):
        p = os.path.join(ignore, SURFACE_DIR, f)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write("; edited by a lot that never claimed anything\n")
        os.utime(p, (T0 - 30, T0 - 30))  # inside the 24 h window
    rc_i, out_i = run(ignore, "report", now=T0)
    say(f"    IGNORING LOT: no claim, no release, two files touched, walked away")
    say(f"      report rc={rc_i} (want {FINDING})")
    for line in out_i.splitlines():
        if line.startswith(("REPORT-NO-CLAIM-STATE", "REPORT-UNCLAIMED ",
                            "REPORT-MOVED path")):
            say(f"      {line[:150]}")
    expect("arm4.ignoring-lot-is-not-silent", rc_i == FINDING,
           f"rc={rc_i} (want {FINDING}) — an ignoring lot produced a non-finding:\n{out_i}")
    expect("arm4.ignoring-lot-both-files-named",
           f"path={SURFACE_DIR}/a.nova" in out_i and f"path={SURFACE_DIR}/b.nova" in out_i,
           out_i)
    expect("arm4.ignoring-lot-unattributed",
           "held-by=NONE" in out_i and "REPORT-UNCLAIMED" in out_i, out_i)
    # EXACT, not merely non-empty: a report that named every file on the tree
    # would satisfy "names-the-mover" while being useless, and a tool that
    # cries wolf on a 413-file surface gets ignored within a night.
    expect("arm4.ignoring-lot-count-is-exact",
           "REPORT-UNCLAIMED count=2" in out_i and "REPORT-MOVED count=2" in out_i
           and f"path={SURFACE_DIR}/c.nova" not in out_i, out_i)


# ----------------------------------------------------------------------- arm 5


def arm5(root: str) -> None:
    say("ARM 5  the mechanism's own state is stale or corrupted -> it REFUSES")
    state = os.path.join(root, "out", "coldproof", "claims")
    os.makedirs(state, exist_ok=True)
    good = os.path.join(state, "lot-130.json")

    cases: list[tuple[str, str]] = [
        ("not-json", "{ this is not json at all"),
        ("truncated", '{"schema": "ng-coldproof-claim/1", "lot": "lot-130"'),
        ("unknown-schema", '{"schema": "something/else", "lot": "lot-130",'
                           ' "state": "live", "claimed_at": 1.0, "lease_until": 2.0,'
                           ' "files": [], "snapshot": {}}'),
        ("missing-field", '{"schema": "ng-coldproof-claim/1", "lot": "lot-130",'
                          ' "state": "live", "claimed_at": 1.0, "files": [],'
                          ' "snapshot": {}}'),
        ("wrong-type", '{"schema": "ng-coldproof-claim/1", "lot": 130,'
                       ' "state": "live", "claimed_at": 1.0, "lease_until": 2.0,'
                       ' "files": [], "snapshot": {}}'),
        ("bad-snapshot-stamp", '{"schema": "ng-coldproof-claim/1", "lot": "lot-130",'
                               ' "state": "live", "claimed_at": 1.0, "lease_until": 2.0,'
                               ' "files": [], "snapshot": {"a.nova": [1, 2]}}'),
        ("bad-state-word", '{"schema": "ng-coldproof-claim/1", "lot": "lot-130",'
                           ' "state": "maybe", "claimed_at": 1.0, "lease_until": 2.0,'
                           ' "files": [], "snapshot": {}}'),
    ]
    for name, body in cases:
        with open(good, "w", encoding="utf-8") as fh:
            fh.write(body)
        for verb, verb_args in (("report", ()), ("claim", ("--lot", "lot-131", f"{SURFACE_DIR}/b.nova")),
                                ("release", ("--lot", "lot-131",))):
            rc, out = run(root, verb, *verb_args, now=T0)
            ok = rc == UNUSABLE and "CLAIM-STATE-UNUSABLE" in out
            silent = any(s in out for s in
                         ("no conflicts", "REPORT-CLEAN", "CLAIMED lot=", "RELEASED lot="))
            expect(f"arm5.{name}.{verb}-refuses", ok and not silent,
                   f"rc={rc} (want {UNUSABLE}) and not a clean report:\n{out}")
        say(f"    {name}: {out.strip().splitlines()[0]}")

    # A claim file that cannot even be read (a directory wearing the name).
    os.remove(good)
    os.makedirs(good)
    rc, out = run(root, "report", now=T0)
    expect("arm5.unreadable-refuses", rc == UNUSABLE and "CLAIM-STATE-UNUSABLE" in out,
           f"rc={rc}\n{out}")
    os.rmdir(good)

    # A state directory that does not exist is NOT corruption — it is a tree
    # where nobody has ever claimed. The first version of this arm asserted
    # that a report REFUSES there, and it passed, and that was the bug: a lot
    # that ignores the mechanism completely leaves no state behind, so a
    # report that needs state is blind to precisely the ignoring lot — and it
    # answered « I could not look » where the truth was « two files moved ».
    # The report must RUN here, and name what moved. A wrong --root cannot
    # masquerade as this case, because a wrong root has no surface and the
    # emptiness check below refuses that separately.
    missing_root = os.path.join(root, "no-such-tree")
    d = os.path.join(missing_root, "compiler/nova")
    os.makedirs(d)
    quiet = os.path.join(d, "quiet.nova")
    moved_f = os.path.join(d, "moved.nova")
    # quiet.nova sits 30 h back — OUTSIDE the 24 h default window — and
    # moved.nova 60 s back, inside it. The first version of this fixture put
    # quiet.nova 10 h back, still inside 24 h, and the arm failed: a file that
    # moved ten hours ago HAS moved inside the window, and the tool was right
    # to report it. The assertion was correct and the fixture was wrong, which
    # is the opposite of the usual direction and is why the ages are computed
    # rather than eyeballed.
    for p, age in ((quiet, 30 * HOUR), (moved_f, 60.0)):
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("module q;\n")
        os.utime(p, (T0 - age, T0 - age))
    rc, out = run(missing_root, "report", now=T0)
    expect("arm5.never-claimed-tree-is-scanned-not-refused", rc == FINDING,
           f"rc={rc} (want {FINDING}: a file moved and nobody is claiming)\n{out}")
    expect("arm5.never-claimed-names-the-mover",
           "path=compiler/nova/moved.nova" in out and "held-by=NONE" in out, out)
    expect("arm5.never-claimed-excludes-the-quiet-file", "quiet.nova" not in out, out)
    expect("arm5.never-claimed-says-why",
           "REPORT-NO-CLAIM-STATE" in out and "NOT a clean bill of health" in out, out)
    say(f"    never-claimed tree: {out.strip().splitlines()[0][:130]}")

    # An empty surface is a green of nothing, and must refuse too — and it is
    # a DIFFERENT refusal from the one above, which is the point of writing
    # both. « nobody has ever claimed here, and here is what moved » is a
    # FINDING. « there is nothing to look at » is being unable to look. The
    # state directory is created first so that the second is reached on its own
    # terms rather than as a side effect of the first.
    bare = tempfile.mkdtemp(prefix="ng-claim-bare-")
    try:
        os.makedirs(os.path.join(bare, "out", "coldproof", "claims"))
        rc, out = run(bare, "report", now=T0)
        expect("arm5.empty-surface-refuses", rc == UNUSABLE and "SURFACE-EMPTY" in out,
               f"rc={rc}\n{out}")
        say(f"    empty surface: {out.strip().splitlines()[0]}")
        rc, out = run(bare, "claim", "--lot", "lot-140", now=T0)
        expect("arm5.claim-on-empty-surface-refuses", rc == UNUSABLE, f"rc={rc}\n{out}")
    finally:
        shutil.rmtree(bare, ignore_errors=True)


# ---------------------------------------------------------------------- extra


def refusals(root: str) -> None:
    say("EXTRA  the refusals that keep a claim from being a promise")
    rc, out = run(root, "claim", "--lot", "lot-150", f"{SURFACE_DIR}/nope.nova", now=T0)
    expect("extra.claim-on-missing-file-refused", rc == FINDING and "does not exist" in out,
           f"rc={rc}\n{out}")
    rc, out = run(root, "claim", "--lot", "lot-151", "verifieur/whatever/x.md", now=T0)
    expect("extra.claim-outside-surface-refused", rc == FINDING and "OUTSIDE" in out,
           f"rc={rc}\n{out}")
    rc, out = run(root, "claim", "--lot", "bad lot/name", f"{SURFACE_DIR}/b.nova", now=T0)
    expect("extra.bad-lot-id-refused", rc == UNUSABLE and "CLAIM-STATE-UNUSABLE" in out,
           f"rc={rc}\n{out}")
    rc, out = run(root, "release", "--lot", "lot-never-claimed", now=T0)
    expect("extra.release-without-claim-refused", rc == FINDING and "NO-CLAIM" in out,
           f"rc={rc}\n{out}")
    rc, out = run(root, "claim", "--lot", "lot-152", f"{SURFACE_DIR}/b.nova",
                  f"{SURFACE_DIR}/b.nova", now=T0)
    expect("extra.duplicate-path-refused", rc == USAGE and "CLAIM-DUPLICATE" in out,
           f"rc={rc}\n{out}")
    # Claiming NOTHING is legal, and that is deliberate: a lot must be able to
    # be running and detectable before it has decided what it will touch.
    rc, out = run(root, "claim", "--lot", "lot-153", now=T0)
    expect("extra.claim-of-nothing-is-legal", rc == CLEAN and "files=0" in out,
           f"rc={rc}\n{out}")


def main() -> int:
    say("=" * 78)
    say("claim.py self-test — five arms on a scratch tree, nothing else touched")
    say(f"tool   {CLAIM}")
    say(f"python {sys.version.split()[0]}")
    say("=" * 78)
    for arm in (arm1, arm2, arm3, arm4, arm5, refusals):
        root = make_root()
        try:
            arm(root)
        finally:
            shutil.rmtree(root, ignore_errors=True)
        say("")
    say("=" * 78)
    if failures:
        say(f"RESULT FAIL arms_failing={len(failures)}")
        for f in failures:
            say(f"  - {f}")
        return 1
    say("RESULT PASS arms_failing=0")
    return 0


if __name__ == "__main__":
    sys.exit(main())
