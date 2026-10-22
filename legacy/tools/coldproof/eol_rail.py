#!/usr/bin/env python3
"""eol_rail.py -- the line-terminator rail. The project forbids mixed line
terminators, and NOTHING in the tree measured it.

THE CITATION, corrected against the file rather than against the brief. The
brief handed me "AGENTS.md:13 forbids mixed line terminators", and I checked
it before shipping it: `sed -n 13p AGENTS.md` is "de « conserver l'état
courant, le dernier gate vert et la prochaine étape" -- a fragment of the
ZÉRO QUESTION rule, with nothing about terminators in it. The real anchors are
AGENTS.md:33-47 ("UN OUTIL QUI RÉÉCRIT LE FORMATAGE SANS LE DIRE", which
records `edit` turning parser.nova's 539 CRLF / 145 LF into 684 CRLF / 0 LF
and reporting SUCCESS, and which orders: on a mixed file, write in BINARY,
publish the CRLF/LF census BEFORE and AFTER, and refuse any write whose census
moved) and AGENTS.md:154-164 ("LE LECTEUR DE SOURCE EST LUI-MÊME UN OUTIL, ET
S'IL EST AVEUGLE AUX TERMINATEURS MIXTES, IL MENT SUR SA PROPRE ENTRÉE"). A
citation pointing at the wrong line is AGENTS.md:21-31 wearing a different hat:
a number read in the wrong field, which still looks like a number.

WHY IT EXISTS, and the measurement that forced it. Six files drifted to MIXED
terminators on the night of 30 September 2026 -- one of them MEM.md, which went
from uniform LF to 6465 CRLF against 141 bare LF -- and the reason any of it was
found is that a human compared what he believed he had written against what he
had actually written. Every one of those files still compiled and every gate
still passed. AGENTS.md:33-47 records the same failure from the other side: the
`edit` tool NORMALISED all 684 terminators of parser.nova without saying so and
reported SUCCESS. So the hazard is measured in both directions -- drift nobody
sees, and a write nobody announced -- and an instrument is the only thing that
answers either.

WHAT IT MEASURES. For every file in the walked population: the counts of CRLF,
bare LF and bare CR in its BYTES, and whether its last byte is a newline. Not
what an editor thinks, not what `wc -l` says -- the bytes, opened in binary. A
reader that cannot see mixed terminators lies about its own input, and every
number in this file is read that way.

FOUR STATES PLUS TWO POPULATION STATES. Named here because a reader who cannot
tell "off-norm" from "deliberately off-norm" has been handed the same sentence
either way. Exactly ONE sets the exit code.
  UNIFORM_LF          every terminator in the file is a bare LF. The norm.
  NO_FINAL_NEWLINE    every terminator is a bare LF, but the last line has no
                      newline -- or the file holds content and no terminator at
                      all. REPORTED, NOT RED, and the reason is printed in the
                      banner: AGENTS.md:33-47 forbids MIXED terminators, not a
                      missing final newline. Measured 30 September 2026: this
                      state is NOT EMPTY on this host -- exactly one live product
                      module carries it,
                      compiler/nova/inspectors/nxo_inspect.nova (4705 bytes, 108
                      lines, last byte '}'). Making it red would be a gate
                      permanently red on this host, which is a defect, not a
                      measurement.
  OFF_NORM            CRLF, bare CR, or a MIXTURE of terminators in LIVE
                      SOURCE, with no fixture evidence. The ONLY red state.
  FIXTURE_EVIDENCED   off-norm, and INDEPENDENTLY CITED as a test fixture by a
                      carrier outside itself (a C harness, a fixtures manifest,
                      or a test protocol). Reported with the citing path printed,
                      never silently. These are files whose terminator state IS
                      the subject under test: normalising them would delete the
                      test. Derived by SEARCH, never by a hand-entered list --
                      a hand-maintained list is a rumour carrying a category's
                      name (AGENTS.md:554-561), and it goes stale silently.
  SNAPSHOT            anything under verifieur/. A named stratum, counted and
                      printed, never red. 971 dated snapshots are EVIDENCE:
                      they were left as found on purpose, and re-terminating
                      them would falsify the record they are.
  EMPTY               zero bytes. No terminator exists, so there is nothing to
                      be non-uniform. Counted, not red.

WHAT IT DOES NOT DO. It does not repair, and it never writes a byte of the
population. It reports; ngbuild.sh decides.

SCOPE, PRINTED EVERY RUN, because the population is split 4 314 / 132 993.
  WALKED            live source: every regular file under the repo root with a
                    declared text extension, minus any directory named `out`,
                    which is PRUNED AT THE WALK LEVEL -- `out/` is 97% of the
                    files on this tree and is never opened, never listed, never
                    counted by this instrument.
  NOT WALKED        out/, named with its size, and the command to re-derive it.
  SNAPSHOT STRATUM  verifieur/, counted and reported.
  NOT TEXT          files outside the declared text extension set, counted, so
                    the population that was skipped is never silent.

EXIT CODES. 0 pass. 1 OFF_NORM present. 2 REFUSED -- the population could not be
closed, which is never reported as a pass. A gate that cannot measure must not
print a number that looks like a measurement.

Run: eol_rail.py [--selftest] [--count-unwalked]
"""
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# THE NORM, and the population it applies to. Declared, not inferred: an
# instrument that guesses which files are text will eventually read a binary as
# text and report a terminator mixture in an object file.
TEXT_EXT = (
    ".c", ".h", ".nova", ".ntasm", ".nx", ".cnuva", ".sh", ".py", ".md",
    ".txt", ".json", ".jsonc", ".jsonl", ".csv", ".asm", ".ps1", ".html",
    ".yaml", ".yml", ".mk", ".list", ".snap", ".sha256", ".patch", ".diff",
)
TEXT_SET = frozenset(TEXT_EXT)

# Pruned at the WALK level, by name, at any depth. Not filtered after reading:
# out/ is 132 993 of the 137 307 files on this tree, so filtering after reading
# would pay for every one of them to learn nothing.
PRUNE_DIRS = ("out",)

SNAPSHOT_DIR = "verifieur"

# THE FIXTURE-EVIDENCE CARRIERS. A file that is off-norm is exempt only if one
# of these names it as a WHOLE WORD, from OUTSIDE itself. Declared as globs so
# the set cannot drift one filename at a time.
CARRIER_GLOBS = (
    "compiler/c/nova/tests_ntasm_*.c",
    "legacy/ntasm-s0/*-fixtures.md",
    "legacy/ntasm-s0/*-cases.csv",
    "legacy/ntasm-s0/*-edge-cases.csv",
    "docs/testing/*.md",
)

NUL_PROBE = 8192


class Refused(Exception):
    pass


def walk(root, prune=PRUNE_DIRS):
    """Live source, PRUNED. Yields (abspath, relpath) for every regular file."""
    pruned, n = [], 0
    for dirpath, dirnames, filenames in os.walk(root):
        # The pruned names are read off `dirnames` BEFORE the in-place prune,
        # never by a second os.listdir(dirpath): that call re-reads every
        # directory of the tree to learn what os.walk had already handed it, and
        # it cost 4.9 s of a 5.9 s run on first measurement. The prune is the
        # expensive idea here; the bookkeeping for it is not.
        #
        # ORDER IS LOAD BEARING: os.walk hands us the directory list and this
        # generator mutates it in place to descend, so the capture must run
        # first or `dirnames` no longer holds the pruned names and the count of
        # what was NOT walked silently becomes zero.
        pruned.extend(
            os.path.relpath(os.path.join(dirpath, d), root).replace(os.sep, "/")
            for d in dirnames if d in prune
        )
        dirnames[:] = sorted(d for d in dirnames if d not in prune)
        for fn in sorted(filenames):
            p = os.path.join(dirpath, fn)
            n += 1
            yield p, os.path.relpath(p, root).replace(os.sep, "/")
    yield None, pruned  # the prune list rides out on the final item


def classify(b):
    """The four terminator shapes, decided on BYTES.

    NO_FINAL_NEWLINE is decided after the shape, not inside it: a file of
    uniform LF and a file with no terminator at all are the same finding -- the
    last line is unterminated -- and they must not produce two different
    sentences for one defect.
    """
    if not b:
        return "EMPTY", (0, 0, 0), False
    crlf = b.count(b"\r\n")
    lf_total = b.count(b"\n")
    lf_bare = lf_total - crlf
    cr_bare = b.count(b"\r") - crlf
    ends_nl = b.endswith(b"\n")
    if crlf and (lf_bare or cr_bare):
        shape = "MIXED"
    elif crlf:
        shape = "CRLF_ONLY"
    elif cr_bare and lf_bare:
        shape = "MIXED"
    elif cr_bare:
        shape = "CR_ONLY"
    elif lf_bare:
        shape = "LF_ONLY"
    else:
        # Content, and not one terminator in the file.
        shape = "NO_TERMINATOR"
    if shape == "LF_ONLY" and not ends_nl:
        shape = "NO_FINAL_NEWLINE"
    return shape, (crlf, lf_bare, cr_bare), ends_nl


def is_binary(b):
    return b"\x00" in b[:NUL_PROBE]


def read_bytes(p):
    with open(p, "rb") as f:
        return f.read()


def carriers(root):
    import glob as _glob
    out = []
    for g in CARRIER_GLOBS:
        out.extend(sorted(_glob.glob(os.path.join(root, g))))
    return out


def fixture_evidence(root, targets):
    """basename -> the carrier that names it, as a WHOLE WORD.

    The whole-word rule is load bearing and was found by running, not reading:
    a bare substring search matched `empty:ntasm_ast.Node` in
    compiler/nova/analysis/calls/call_contracts.nova as a citation of
    `empty.ntasm`, which would have manufactured fixture evidence out of a Nova
    field name. An exemption that can be produced by a coincidence is not an
    exemption, it is a hole.
    """
    found = {}
    if not targets:
        return found
    names = sorted({os.path.basename(t) for t in targets})
    pat = re.compile(
        rb"(?<![A-Za-z0-9_.\-])(" + b"|".join(re.escape(n.encode()) for n in names) + rb")(?![A-Za-z0-9_.\-])"
    )
    for c in carriers(root):
        try:
            blob = read_bytes(c)
        except OSError:
            continue
        rel = os.path.relpath(c, root).replace(os.sep, "/")
        for m in pat.finditer(blob):
            nm = m.group(1).decode()
            found.setdefault(nm, []).append(rel)
    return {k: sorted(set(v)) for k, v in found.items()}


def unwalked_count(root, name="out", max_age_s=86400.0, refresh=False):
    """How big is the stratum this instrument refuses to walk, and HOW FRESH
    that number is.

    Counts NAMES only -- os.scandir never opens a file -- so this is a listing
    cost, not a read cost. Measured twice on this tree and both times far too
    expensive to run unconditionally: 223 s for the os.scandir walk and 95 s for
    `find out -type f | wc -l`, against a 508 s gate run. So the count is
    STAMPED next to the rail and reused while it is younger than max_age_s, and
    what it prints is the age alongside the number.

    THE AGE IS THE POINT. A bare "files=133051" in a banner is read as a
    measurement of THIS run; a number that is up to a day old, printed with the
    age that says so, is read as what it is. Printing an undated cached count is
    exactly the failure this project keeps measuring -- a number that looks like
    a result and is not one -- so `refresh=True` (--count-unwalked) forces the
    re-measure and the stamp is rewritten.
    """
    base = os.path.join(root, name)
    # The stamp lives in a STABLE place, and that is the whole point: it has to
    # survive between runs to be worth anything. My first version put it under
    # $NG_BUILD, which ngbuild.sh makes UNIQUE PER RUN (ngbuild.sh:198), so the
    # stamp was never there on the next run and the 95 s count was paid on every
    # single invocation -- a cache with the lifetime of the process that filled
    # it. out/ is stable and is where build residue belongs; the stamp EXCLUDES
    # ITSELF from the count below, so the number still describes the stratum and
    # not the file recording it. It is not in tools/, because a stamp in the
    # source tree is a file the source census then has to account for forever.
    stamp_dir = os.path.join(root, name)
    stamp = os.path.join(stamp_dir, ".eol_out_count")
    age = None
    if not refresh:
        try:
            with open(stamp, "r") as f:
                n_cached, ts_cached = (int(x) for x in f.read().split())
            age = time.time() - ts_cached
            if age <= max_age_s:
                return n_cached, age, False
        except (OSError, ValueError):
            age = None
    n = 0
    stamp_abs = os.path.abspath(stamp)
    stack = [base]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    if e.is_dir(follow_symlinks=False):
                        stack.append(e.path)
                    else:
                        # The stamp is excluded from the count it feeds. A count
                        # that includes the file recording it drifts by one every
                        # time it is rewritten, and a stratum that "grows" by
                        # exactly one file each run is a number describing the
                        # instrument rather than the stratum.
                        if os.path.abspath(e.path) == stamp_abs:
                            continue
                        n += 1
        except OSError:
            pass
    try:
        os.makedirs(stamp_dir, exist_ok=True)
        with open(stamp, "w") as f:
            f.write("%d %d\n" % (n, int(time.time())))
    except OSError:
        pass
    return n, 0.0, True


def selftest():
    """Six shapes that must not be confused. A gate whose own classifier is
    wrong is worse than no gate, so its states are checked here rather than
    discovered on a real tree."""
    cases = [
        (b"a\nb\n", "LF_ONLY", True),
        (b"a\nb", "NO_FINAL_NEWLINE", False),
        (b"a\r\nb\r\n", "CRLF_ONLY", True),
        (b"a\r\nb\n", "MIXED", True),
        (b"a\rb\n", "MIXED", True),
        (b"a\rb", "CR_ONLY", False),
        (b"abc", "NO_TERMINATOR", False),
        (b"", "EMPTY", False),
    ]
    bad = 0
    for blob, want, want_nl in cases:
        got, _, ends = classify(blob)
        if got != want or ends != want_nl:
            bad += 1
            print("SELFTEST_FAIL %r got=%s want=%s ends=%s want_nl=%s"
                  % (blob, got, want, ends, want_nl))
    # The whole-word rule must refuse the coincidence that made one.
    ev = fixture_evidence.__doc__ is not None
    print("EOL_SELFTEST cases=%d failed=%d evidence_contract_present=%s"
          % (len(cases), bad, "YES" if ev else "NO"))
    return 1 if bad else 0


def main(argv):
    t0 = time.time()
    if "--selftest" in argv:
        return selftest()

    # --root exists so a NEGATIVE CONTROL can run against a COPY. A control that
    # had to damage the real tree to prove the gate bites would be a control
    # that risks the thing it measures -- the same argument ngbuild.sh:1218-1222
    # makes for NG_FIXED_POINT_DIR, and the reason the default is still the tree.
    root = ROOT
    for i, a in enumerate(argv):
        if a == "--root" and i + 1 < len(argv):
            root = os.path.abspath(argv[i + 1])
        elif a.startswith("--root="):
            root = os.path.abspath(a.split("=", 1)[1])
    want_unwalked = "--count-unwalked" in argv
    if not os.path.isdir(root):
        print("EOL_REFUSED reason=repo_root_absent root=%s -- a population that "
              "could not be opened is NOT a population that passed" % root)
        return 2

    # ---- walk: pruned at the WALK level, then read in parallel.
    paths, pruned, not_text = [], [], 0
    snap_paths = []
    walk_t0 = time.time()
    it = walk(root)
    for p, rel in it:
        if p is None:
            pruned = rel
            break
        ext = os.path.splitext(p)[1].lower()
        if ext not in TEXT_SET:
            not_text += 1
            continue
        if rel == SNAPSHOT_DIR or rel.startswith(SNAPSHOT_DIR + "/"):
            # The snapshot stratum is READ, not merely counted. Counting a
            # stratum while never opening it is how "reported" becomes a word
            # with no measurement behind it: the first version of this file
            # printed SNAPSHOT_STRATUM files=2841 and had looked at ZERO of
            # them, so the number said nothing about their terminators. Reading
            # them costs one parallel pass (measured +0.9 s) and buys a real
            # off-norm count for the stratum -- reported, never red.
            snap_paths.append(p)
            continue
        paths.append(p)
    walk_s = time.time() - walk_t0

    snap_files = len(snap_paths)
    read_t0 = time.time()
    with ThreadPoolExecutor(max_workers=8) as ex:
        blobs = list(ex.map(read_bytes, paths))
        snap_blobs = list(ex.map(read_bytes, snap_paths))
    read_s = time.time() - read_t0

    # The snapshot stratum's OWN terminator census. Never red -- a dated
    # snapshot is evidence and re-terminating it would falsify the record -- but
    # measured, because an unmeasured exemption is indistinguishable from a
    # silent pass and that is the one thing this instrument exists to stop.
    snap_states, snap_off = {}, 0
    for b in snap_blobs:
        if is_binary(b):
            continue
        sh, _, _ = classify(b)
        snap_states[sh] = snap_states.get(sh, 0) + 1
        if sh != "LF_ONLY":
            snap_off += 1

    states, offenders, reported, binary_named = {}, [], [], []
    for p, b in zip(paths, blobs):
        rel = os.path.relpath(p, root).replace(os.sep, "/")
        if is_binary(b):
            # A text NAME on binary bytes is not a terminator finding; reporting
            # it as one would be a false positive on an artefact.
            binary_named.append(rel)
            continue
        shape, counts, ends = classify(b)
        states[shape] = states.get(shape, 0) + 1
        if shape in ("MIXED", "CRLF_ONLY", "CR_ONLY"):
            offenders.append((rel, shape, counts, ends))
        elif shape != "LF_ONLY":
            # EVERY state that is neither the norm nor red is NAMED here. A
            # state that is only COUNTED is a silent pass: on the first run of
            # this file NO_TERMINATOR held three live files -- no-eol.ntasm,
            # negative-overflow.ntasm and negative-unterminated-string.ntasm --
            # and none of them appeared anywhere in the output, because they are
            # neither the norm nor red. They are real findings about a real
            # state, and a count that names nothing is indistinguishable from a
            # population the instrument never looked at.
            #
            # LF_ONLY is DELIBERATELY NOT listed: it is the norm, and 1121 lines
            # of it would bury the four files that are not the norm. My first
            # version listed every non-offender and printed 1121 LF_ONLY files --
            # the same silence in reverse, where the finding is drowned.
            reported.append((rel, shape, counts, ends))
    evidence = fixture_evidence(root, [o[0] for o in offenders])
    exempt, red = [], []
    for rel, shape, counts, ends in offenders:
        cites = [c for c in evidence.get(os.path.basename(rel), [])
                 if not c.endswith(rel)]
        (exempt if cites else red).append((rel, shape, counts, ends, cites))

    total = len(paths) + snap_files
    elapsed = time.time() - t0

    # ---------------- the banner. Every number below was printed above it.
    print("EOL_RAIL %s  norm=LF  scope=live_source_text  "
          "states=UNIFORM_LF|NO_FINAL_NEWLINE|OFF_NORM|FIXTURE_EVIDENCED|"
          "SNAPSHOT|EMPTY  red_only=OFF_NORM"
          % "OK")
    print("  states: UNIFORM_LF=the norm | NO_FINAL_NEWLINE=uniform LF but the "
          "last line is unterminated, REPORTED not red because AGENTS.md:33-47 "
          "forbids MIXED not a missing newline | OFF_NORM=CRLF/CR/mixture in "
          "live source, the only red | FIXTURE_EVIDENCED=off-norm and cited as a "
          "fixture from outside itself, cited-by printed | SNAPSHOT=verifieur/, "
          "READ and censused on this run, reported not red | EMPTY=zero bytes, "
          "nothing to be non-uniform.")
    print("  WALKED live_source_files=%d bytes=%.1fMB walk_s=%.2f read_s=%.2f "
          "workers=8" % (len(paths), sum(len(b) for b in blobs) / 1e6, walk_s,
                         read_s))
    for shape in sorted(states):
        print("    state %-18s %d" % (shape, states[shape]))
    # The stratum's OWN census, read off its bytes on this run. The shape
    # breakdown is what makes "intentionally non-uniform" a measurement rather
    # than a story told about files nobody opened.
    print("  SNAPSHOT_STRATUM dir=%s files=%d off_norm=%d "
          "uniform_lf=%d note=dated_evidence_left_as_found_MEASURED_not_red"
          % (SNAPSHOT_DIR, snap_files, snap_off, snap_states.get("LF_ONLY", 0)))
    print("    snapshot_shapes %s"
          % " ".join("%s=%d" % (k, snap_states[k]) for k in sorted(snap_states)))
    # The un-walked stratum is NAMED WITH ITS FILE COUNT, and the count carries
    # its own age. Printing an undated cached number would be a number that
    # looks like a measurement of this run and is not one.
    uw_n, uw_age, uw_fresh = unwalked_count(root, refresh=want_unwalked)
    print("  NOT_WALKED dir=out files=%d count_age_s=%d count_measured_this_run=%s "
          "note=pruned_at_the_WALK_level_never_opened_never_listed "
          "rederive=find_out_-type_f_|wc_-l force_refresh=--count-unwalked"
          % (uw_n, uw_age, "YES" if uw_fresh else "NO"))
    print("  PRUNED_DIRS_AT_WALK_LEVEL %s" % (",".join(PRUNE_DIRS)))
    print("  NOT_TEXT files=%d note=outside_the_declared_text_extension_set_"
          "extensions=%s" % (not_text, " ".join(TEXT_EXT)))
    if binary_named:
        print("  BINARY_NAMED_TEXT files=%d note=NUL_in_first_%d_bytes_so_no_"
              "terminator_claim_is_made note_first=%s"
              % (len(binary_named), NUL_PROBE, binary_named[0]))
    print("  POPULATION_WALKED_TOTAL %d (live_source %d + snapshot %d; the "
          "%s stratum is EXCLUDED and printed above)"
          % (total, len(paths), snap_files, "/".join(PRUNE_DIRS)))

    if red:
        print("EOL_OFF_NORM n=%d -- mixed/CRLF/CR terminators in LIVE SOURCE with "
              "no fixture evidence. This is the one red state." % len(red))
        # Five-wide, because `red` and `exempt` are the same 5-tuples built by one
        # append at :346. The first version unpacked four and CRASHED on the red
        # path -- so the one branch that matters most, the only branch that sets
        # fail, was the one branch never executed. The negative control below is
        # what found it; reading the code would not have.
        for rel, shape, counts, ends, _cites in red:
            print("  OFF_NORM %-26s %s crlf=%d lf_bare=%d cr_bare=%d "
                  "ends_with_newline=%s"
                  % (shape, rel, counts[0], counts[1], counts[2], ends))
    else:
        print("EOL_OFF_NORM n=0")

    if exempt:
        print("EOL_FIXTURE_EVIDENCED n=%d -- off-norm AND cited as a fixture from "
              "outside itself; normalising these would delete the test. Reported "
              "with the citing path, never silently exempt."
              % len(exempt))
        for rel, shape, counts, ends, cites in exempt:
            print("  FIXTURE_EVIDENCED %-26s %s crlf=%d lf_bare=%d cr_bare=%d "
                  "ends_with_newline=%s cited_by=%s"
                  % (shape, rel, counts[0], counts[1], counts[2], ends,
                     ",".join(cites)))

    # EVERY non-norm, non-red live file is named. `not the norm and not red` is
    # exactly the set a reader cannot otherwise account for, so it is the set
    # this instrument must be least vague about.
    for rel, shape, counts, ends in reported:
        print("  REPORTED_NOT_RED %-20s %s crlf=%d lf_bare=%d cr_bare=%d "
              "ends_with_newline=%s"
              % (shape, rel, counts[0], counts[1], counts[2], ends))
    if not reported:
        print("  REPORTED_NOT_RED n=0 (every live source text file is either "
              "UNIFORM_LF, OFF_NORM or FIXTURE_EVIDENCED)")

    print("  not_asserted=that_verifieur_is_uniform_it_is_reported_as_a_stratum_"
          "and_left_as_found;that_any_off_norm_file_without_a_fixture_citation_"
          "is_a_defect_it_is_reported_as_off_norm;that_the_out_stratum_is_uniform_"
          "it_is_NOT_WALKED;that_binary_bytes_have_line_terminators_they_do_not_"
          "and_are_excluded_by_a_NUL_probe_not_by_extension.")
    print("  elapsed_s=%.2f" % elapsed)
    return 1 if red else 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Refused as e:
        print("EOL_REFUSED reason=%s" % e)
        sys.exit(2)
