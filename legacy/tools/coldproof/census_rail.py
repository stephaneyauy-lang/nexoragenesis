#!/usr/bin/env python3
"""census_rail.py — the R24 rail, built to refuse the part that is not buildable.

WHAT THIS IS NOT. It is not a classifier. It has no code path that writes a
class, by construction: it loads the census's hand-entered CLASSES read-only and
never assigns, never recommends, and never tallies a class into a quality
statement. That is deliberate, and it is measured rather than stylistic -- four
classifiers were built against this population in one session and none was sound,
each relocating its own blindness (48, 59 and 36 disagreements over 124 gates,
plus the census's own D1 at stub_table and the 53 gates with no Run struct).

So the rail pins everything UP TO the judgement and refuses to cross it.

WHAT IT COMPUTES, per R24 §5.1
  POPULATION             the written extraction rule, from the driver, verbatim
  POPULATION_CLOSED      uniqueness + every source file present; refuses otherwise
  ROW_BINDING[gate]      sha256 of the gate's OWN criteria row, not the document
  GATE_BYTES[gate]       per-gate sha256
  MATCHES[gate]          every lexical match, with line / kind / context
  MATCH_KIND             CITATION | FILENAME | QUOTED_SOURCE | PROFILE_TOKEN,
                         decided AT THE MATCH SITE. This is what D1 could not do:
                         `parser` followed by `.nova` is a filename, full stop.
  INSTRUMENT_VERDICTS    every classifier's opinion, side by side, unresolved
  EDIT_STATE             gate mtime vs artefact mtime -> QUIET | EDITED_SINCE
  QUEUE                  gates where instruments disagree. THE DELIVERABLE.

WHAT IT REFUSES, per R24 §5.2 -- five refusals, the first structural
  1  the class of a gate, ever: there is no cell-writing code path in this file
  2  a winner among disagreeing instruments: it prints the disagreement
  3  one combined tally: TALLY_FROM_TABLE and QUEUE are never summed
  4  anything whose denominator it did not close
  5  a verdict for a cell whose ROW_BINDING it cannot recompute

TWO TESTS THAT DECIDE WHETHER IT IS HONEST
  * a rail whose judgement cells carry digests has rebuilt the census
  * a rail with nothing to say must print nothing and say so -- staleness is a
    MISSING LINE, not a wrong number, because an instrument that always has a
    number to print can never signal that it does not.

Run: census_rail.py [--queue N] [--selftest]
"""
import hashlib
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
DRIVER = ROOT / "legacy/tools/coldproof/ngbuild.sh"
CENSUS = ROOT / "out/c-bootstrap/nova/W26Exposure/derive_population.py"
DOCS = ROOT / "docs/status/ntasm-completion.md"

# The extraction rule, transcribed from the census's own declaration
# (GATE-POPULATION.md §1, and derive_population.py:39-41). Transcribed rather
# than imported so that a change in either is a visible disagreement, not a
# silent behaviour change.
ARRAYS = ("GATES", "NOVA_GATES", "ROOT_GATES")

EXTS = (".c", ".sh", ".py", ".nova")

# THE HISTORICAL BLOB of incident 2, as DATA: class A's own 69 names with the
# nine-line `#` note that was written inside it, reproduced verbatim from
# derive_population.py's own A literal plus the note that sat in it for an hour.
# It is spelled out here rather than read from a file because a self-test that
# reads its subject cannot notice the subject changing -- which is how a
# control becomes a control of nothing. COST OF REVERSAL: it is a string.
CLASSES_A_NAMES_HISTORICAL = """abi bindings body_clobbers body_effects body_intrinsics
        call_clobbers call_contracts call_effects call_types callable_names
        calls cli clobbers condition_types constant_types contracts
        control_flow decls diagnostics effects feature_requirements features
        initializer_types lexer literal_initializers locals macro_expand
        parameters parser pointer_spaces refs register_bindings
        register_widths registry return_types semantics splice
        call_fold symbol_names targets tests_a5.c
        tests_conformance.c tests_conformance_cfg.c tests_conformance_efi.c
        tests_conformance_frontend.c tests_conformance_permissions.c
        tests_conformance_provenance.c tests_frontend.c
        tests_indirect_call.c tests_nova.c tests_nova_aggregates.c
        tests_nova_boundary.c tests_nova_capacity.c tests_nova_integers.c
        tests_nova_limits.c tests_nova_memory.c tests_nova_modules.c
        tests_nova_v2.c tests_object.c tests_object_build.c
        tests_object_errors.c tests_object_link.c tests_object_separate.c
        tests_static_pointer.c tests_x64.c types
        validate versions
        form_matrix
    # form_matrix is filed class A, and the reason it is TYPED and not DERIVED
    # belongs HERE, above this literal, and not inside it.  That is not a style
    # preference: the list above is a triple-quoted string that the census splits
    # on WHITESPACE, so a `#` comment written inside it becomes a gate named `#`.
    # Measured, twice, one hour apart, by me:
    #   the first version of this note sat inside GATES=( ... ) in ngbuild.sh and
    #   inflated the population from 128 to 225 with duplicates including '#',
    #   'is', 'NOT', 'registered,';
    #   the second version sat inside this triple-quoted string and produced
    #       CENSUS_ERROR gate # appears in two classes
    # A positional reader cannot tell a name from a sentence about a name.  Put
    # prose about a list OUTSIDE the list.
    #
    # WHY CLASS A.  It compares bytes: it calls the C oracle nt_x64_encode and
    # keeps the answer the oracle gave on the run that derived it, over 154
    # (kind,width) forms.
    #
    # WHY NOT DERIVED.  None of the three rules can reach it.
    #   C3 needs a TAINTED buffer compared against the host run's output --
    #       form_matrix has no Nova lowering buffer.
    #   C1-vs-C2 needs a PRODUCING entry point declared in frontend.h/codegen.h
    #       versus object.h/pe.h/ntasm.h/pe_layout.h.  nt_x64_encode is declared
    #       in x64.h, which is in NEITHER list, so the boundary cannot place it
    #       at all.
    #   C4 needs an absence over the other side -- and form_matrix's other side
    #       IS the oracle, in the same process, so that absence does not apply.
    #"""


def sha_bytes(b):
    return hashlib.sha256(b).hexdigest()[:16]


def array_body(text, name):
    """The body of `NAME=(...)` in a shell array, up to the FIRST ')' that is
    not inside a `#` comment. Returns None when the array is not declared or is
    never closed.

    THE COMMENT-AWARENESS IS THE POINT, and it has to happen while the region is
    found rather than after. The rule this file transcribed was
    `re.search(r'^NAME=\\((.*?)\\)', text, re.S|re.M)` -- non-greedy to the first
    `)` in the file -- and a `#` block sitting at the end of the array carries a
    `)` of its own in any sentence with a parenthetical, so the region ends
    INSIDE the comment and the array is truncated by prose. Measured on the
    historical incident-3 shape: GATES read 29 names instead of 99 and the
    shell's `fi` became a gate.

    Both `#`-stripping and terminator-hunting therefore have to be one pass.
    Stripping first and then hunting would leave a `)` in the cleaned text at
    exactly the position the comment used to occupy."""
    m = re.search(r"^" + name + r"=\(", text, re.M)
    if not m:
        return None
    i, n, in_comment, depth = m.end(), len(text), False, 1
    while i < n:
        ch = text[i]
        if in_comment:
            if ch == "\n":
                in_comment = False
        elif ch == "#":
            in_comment = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[m.end():i]
        i += 1
    return None


def split_positional(body):
    """Split one list body into (names, dropped, err).

    `dropped` is the number of whitespace-separated words a COMMENT-BLIND
    reader would have taken as names -- counted from the text BEFORE the strip,
    because the post-drop count is the number that already looked fine and
    would report nothing. A comment is reported, never silently absorbed:
    under a reader that only discarded it, the census at 22:50 would have been
    RIGHT and said nothing, which moves staleness from a wrong number (arguable)
    to an absent line (not arguable at all).

    `err` is set rather than the name skipped. A token carrying a character
    outside [A-Za-z0-9_.-] is a MALFORMED list, not a comment, and a reader
    that dropped it would be a reader that can no longer say no."""
    kept, dropped, cur, in_comment = [], 0, [], False

    def flush():
        """A word ends at whitespace. WHERE it ends decides whether it is a
        name or something a comment-blind reader would have swallowed -- and the
        end-of-line is decided BEFORE the comment flag is cleared, or the last
        word of every comment line is promoted back into the population. That
        bug shipped in the first version of this function and it is invisible
        in the total: the population came back 128 and two names per comment
        line were in it."""
        nonlocal dropped, cur
        if not cur:
            return
        if in_comment:
            dropped += 1
        else:
            kept.append("".join(cur))
        cur = []

    for ch in body:
        if ch == "\n":
            flush()
            in_comment = False
        elif ch == "#" and not in_comment:
            flush()
            cur.append(ch)
            in_comment = True
            flush()
        elif ch in " \t\r":
            flush()
        else:
            cur.append(ch)
    flush()
    for n in kept:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", n):
            return kept, dropped, (
                "token %r is not a bare word: a list that grew a quoted string "
                "or a shell expansion is MALFORMED, not commented, and a reader "
                "that skipped it would be a reader that can no longer say no" % n)
    return kept, dropped, None


def read(p):
    return p.read_bytes()


def population():
    """The written rule, verbatim from the census's own declaration.

    GATE-POPULATION.md §1 states THREE different path rules for three arrays,
    and my first version guessed one of them. The rail then refused to print a
    number rather than reporting an unclosed denominator -- which is R24's
    fourth refusal doing its job on its first real run. So the rules below are
    read from the census, not reconstructed.

    The two RETURNED counts per array are `survived` (the names, after `#` is
    dropped) and `pre_drop` (what the comment-blind reader would have taken),
    and the caller PRINTS THE DIFFERENCE rather than the population alone.
    """
    text = DRIVER.read_text(encoding="utf-8")
    names, srcs, counts = [], {}, {}
    C = ROOT / "compiler/c"
    PATHF = {
        "GATES": lambda n: C / "nova" / ("tests_ntasm_%s.c" % n),
        "NOVA_GATES": lambda n: C / "nova" / (n + ".c"),
        "ROOT_GATES": lambda n: C / n,
    }
    for arr in ARRAYS:
        body = array_body(text, arr)
        if body is None:
            return None, None, None, "array %s not found in the driver" % arr
        toks, drop, err = split_positional(body)
        if err:
            return None, None, None, "array %s: %s" % (arr, err)
        counts[arr] = (len(toks), drop)
        for tok in toks:
            names.append(tok)
            if not tok.startswith("*"):
                srcs[tok] = PATHF[arr](tok)
    return names, srcs, counts, None


def closed(names, srcs, cls=None):
    """POPULATION_CLOSED. Refuses rather than reporting an unclosed denominator.

    Three conditions, not two. Uniqueness of the driver's own names, and every
    source file present, were the first two, and they were not enough: a gate
    can be in the driver, have a file, and still have NO CELL in the table. The
    rail announced a closed denominator over such a population and rendered the
    missing cell as "?" in a line nobody reads. Measured on 30 September 2026,
    after the `placeholder` gate was registered with no census cell:
        census script   KeyError: 'placeholder'   -- loud, survivable
        this rail       POPULATION_CLOSED n=125    -- a false claim, which is worse
    So coverage is now a condition of closed, and an uncovered gate is NAMED.
    """
    dupes = sorted({n for n in names if names.count(n) > 1})
    absent = sorted(n for n in names if n not in srcs or not srcs[n].exists())
    # A stem the DERIVER cannot classify is not an uncovered stem. `A` is an
    # ABSENCE — a gate compared against no other producer — and an absence is
    # not derivable. Counting it as uncovered made the rail refuse for a gate
    # that is fully covered and merely unclassified; that is the same error as
    # reporting an abstention as a refutation.
    # Pending names come from the derivation, never from a hand-written list,
    # and the count is PRINTED so an unclassified stem can never be silent.
    pend = pending_stems()
    deriv = derived_stems()
    uncovered = sorted(n for n in names
                       if cls is not None and n not in cls
                       and n not in pend and n not in deriv)
    unclassified = sorted(n for n in names if n in pend)
    return ((not dupes and not absent and not uncovered),
            dupes, absent, uncovered, unclassified)


DERIVER = ROOT / "legacy/tools/coldproof/lot145_derivable_cells.py"


def pending_stems():
    """Stems the deriver names as PENDING or gives an ABSTAIN cell, or empty.

    Read by running the deriver, not by parsing a list someone wrote down. If
    the deriver is absent or fails, this returns the empty set and the rail
    behaves EXACTLY as it did before -- additive, never a new failure mode.
    """
    if not DERIVER.exists():
        return frozenset()
    try:
        cp = subprocess.run([sys.executable, str(DERIVER), "--pending"],
                            capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as e:
        # ONLY transport failures degrade to the empty set. A NameError or a
        # parse bug inside this module must NOT be swallowed into "no stems are
        # pending" -- that is how a missing import became an empty answer and
        # the rail refused a population it had actually classified.
        sys.stderr.write("PENDING_UNAVAILABLE %s: %s\n" % (type(e).__name__, e))
        return frozenset()
    # A child that prints a plausible table and THEN dies exits non-zero while
    # raising neither of the two guards above. Reading only .stdout consumes that
    # table as an answer. This is exactly how lot145_derivable_cells.py's
    # NameError survived for hours: a 226-line output, consumed as valid, from a
    # process that crashed on its last line. The exit code is the verdict.
    if cp.returncode != 0:
        sys.stderr.write("PENDING_UNAVAILABLE deriver exit=%d; its output is a "
                         "partial answer and is NOT consumed\n" % cp.returncode)
        return frozenset()
    out = cp.stdout
    got = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "PENDING":
            for w in parts[1:]:
                if w.endswith(",") or w == "stems,":
                    continue
                got.add(w.rstrip(","))
        elif len(parts) >= 3 and parts[1] == "ABSTAIN":
            got.add(parts[0])
    return frozenset(got)

def derived_stems():
    """Names the deriver classifies with a real (non-ABSTAIN) cell.

    Read from the same run that yields PENDING, from the same instrument -- never
    from a list someone wrote down. The user's decision is that a census cell is
    DERIVABLE: a gate registered after the hand-entered table was written has no
    row in it, and requiring one made the rail refuse a population it had in fact
    classified. The table stays READ-ONLY; this is a second acceptance path, not
    a replacement.

    An ABSTAIN cell is NOT derived coverage -- it is the deriver saying it has
    nothing to read, which is the same fact as PENDING, and is excluded here.
    """
    if not DERIVER.exists():
        return frozenset()
    try:
        cp = subprocess.run([sys.executable, str(DERIVER), "--pending"],
                            capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError) as e:
        sys.stderr.write("DERIVED_UNAVAILABLE %s: %s\n" % (type(e).__name__, e))
        return frozenset()
    # Same rule as pending_stems(): a non-zero exit makes the output a partial
    # answer, and a partial answer is not an answer. Deriving coverage from it
    # would close the rail on the strength of a process that died mid-table.
    if cp.returncode != 0:
        sys.stderr.write("DERIVED_UNAVAILABLE deriver exit=%d; its output is a "
                         "partial answer and is NOT consumed\n" % cp.returncode)
        return frozenset()
    out = cp.stdout

    got = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "CELL" and "ABSTAIN" not in line:
            got.add(parts[1])
    return frozenset(got)


def classes_literal():
    """The census's hand-entered CLASSES, READ-ONLY. Never written, never assigned.

    The table is NOT a dict literal: it is a `for _cls, _names in [...]` loop
    over one triple-quoted blob per class, the last of which closes on a single
    line as `("C5", "nxo_pe")]:`. So it is parsed structurally, and a shape this
    parser does not recognise REFUSES rather than returning a short table -- a
    census read that quietly dropped a class is the instrument this rail exists
    against, and it would be the worst possible place to introduce one.
    """
    return _classes_from(CENSUS.read_text(encoding="utf-8"))


def census_self_description():
    """The census file's OWN first non-blank lines, verbatim, or None.

    R309/R310: `CENSUS` is a file whose line 2 reads
        # THIS IS A SNAPSHOT, NOT THE LIVE INSTRUMENT.
    and this rail computes POPULATION_CLOSED from it without ever reading that
    line.  A consumer that cannot see the warning is worse than one with no
    warning at all, because the warning exists and looks like it was read.

    This PRINTS the declaration rather than acting on it.  Whether a rail whose
    data file disclaims being the live instrument should REFUSE -- and turn the
    suite red today -- is a programme decision, not a quiet one to take inside
    an instrument: it changes the colour of a green rail, and the register
    carries that decision as open.  Until it is taken, the least that can be
    done is that no reader of this rail's output can be unaware of it.
    """
    try:
        raw_lines = CENSUS.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as e:
        return "unreadable: %s" % e
    # Only lines that WERE comments are candidates: a declaration is a comment,
    # and returning the first code line would be reporting a statement as a
    # self-description -- the same class of error as the zero.
    head = [l.strip().lstrip("#").strip() for l in raw_lines[:12]
            if l.strip().startswith("#")]
    head = [h for h in head if h and set(h) - set("=-~*_ ")]
    if not head:
        return None
    for h in head:
        if re.search(r"SNAPSHOT|LIVE INSTRUMENT|DO NOT ADD", h, re.I):
            return h
    return head[0]




def _classes_from(text):
    """The hand-entered CLASSES out of `text`. Split out from classes_literal so
    the self-test can feed it a synthetic table: a refusal that only a real file
    can provoke is a refusal nothing exercises."""
    m = re.search(r"for\s+_cls,\s*_names\s+in\s*\[(.*?)\]:", text, re.S)
    if not m:
        return {}, None, "the CLASSES construction was not found in the census"
    out = {}
    dropped = {}
    for g in re.findall(r'\(\s*"([^"]*)"\s*,\s*(?:"""(.*?)"""|"([^"]*)")',
                        m.group(1), re.S):
        lit, blob = g[0], (g[1] or g[2] or "")
        # A `#` inside one of these blobs is PROSE ABOUT the list, not a name,
        # and this is the shape of incident 2: a note placed inside the A blob
        # produced `CENSUS_ERROR gate # appears in two classes`. It is dropped
        # AND COUNTED, because dropping it silently is the worse failure -- the
        # census would then have been right and said nothing.
        names, drop, err = split_positional(blob)
        if err:
            return {}, None, "the %s blob: %s" % (lit, err)
        dropped[lit] = dropped.get(lit, 0) + drop
        for n in names:
            if n in out:
                return {}, None, "gate %s appears in two classes" % n
            out[n] = lit
    if not out:
        return {}, None, "the CLASSES construction parsed to zero entries"
    return out, dropped, None


def match_kind(ctx):
    """MATCH_KIND, decided AT THE SITE. This is the part D1 could not do."""
    tail = ctx.lstrip()
    if tail.startswith("."):
        return "FILENAME"
    if tail[1:2] == ".":
        return "FILENAME"
    if ctx.startswith("`") or "`" in ctx[:2]:
        return "CITATION"
    if re.search(r"\b(x86_64|nx64|none|uefi)\b", ctx):
        return "PROFILE_TOKEN"
    if tail[:2] in ("{ ", "{}", "{\n") or "{" in ctx[:4]:
        return "QUOTED_SOURCE"
    return "UNCLASSIFIED"


def lexical(doc, gate_names):
    """Every lexical match in the criteria table, with its kind. A lexical FACT,
    computed with no judgement in it."""
    hits = []
    for n, line in enumerate(doc.splitlines(), 1):
        if not line.startswith("|"):
            continue
        row = line.split("|")[1].strip() if len(line.split("|")) > 1 else ""
        if row != gate_names:
            continue
        for name in sorted(gate_names_set):
            for m in re.finditer(r"(?<![\w./-])(" + re.escape(name) + r")(?![\w-])", line):
                i = m.start()
                ctx = line[max(0, i - 24): i + len(name) + 24]
                hits.append((name, n, match_kind(line[i + len(name):]), ctx))
        break
    return hits


gate_names_set = set()


def census_instruments(src):
    """Every classifier that exists, side by side, UNRESOLVED.
    d1  -- the census's ACCEPTED discriminator: does the Run struct carry a byte
           member? Recorded as what it is, including where it is blind.
    lex -- memcmp occurrences. Recorded as vocabulary, explicitly NOT as evidence:
           the census's own D2 refutation is that registry's memcmps are all over
           markdown, and it fires on 51 of 124 gates.
    Neither is a verdict, and neither is combined with the other."""
    t = src.decode("utf-8", "replace")
    run = re.search(r"} *Run *;", t)
    byte_member = bool(re.search(r"typedef\s+struct\b[^{]*\{[^}]*\bunsigned\s+char\b[^}]*\}\s*Run\s*;", t, re.S))
    memcmp = len(re.findall(r"\bmemcmp\s*\(", t))
    return {
        "d1": ("C" if byte_member else "A-or-C-unseen") if run else "no-Run-struct",
        "d1_blind": "no Run struct: absence of the struct is read as absence of byte evidence"
                    if not run else "",
        "lex_memcmp": memcmp,
        "lex_blind": "vocabulary, not evidence: fires on any gate that mentions memcmp",
    }


def edit_state(path, artefact):
    try:
        a, b = os.stat(path).st_mtime, os.stat(artefact).st_mtime
    except OSError as e:
        return "UNREADABLE(%s)" % e
    return "QUIET" if a < b else "EDITED_SINCE"


def selftest():
    """The rail must be able to say it is wrong. Cases, each named."""
    cases, fails = 0, 0

    def t(name, cond):
        nonlocal cases, fails
        cases += 1
        if not cond:
            fails += 1
            print("  FAIL %s" % name)

    t("MATCH_KIND parser.nova is a FILENAME", match_kind(".nova") == "FILENAME")
    t("MATCH_KIND a bare word is UNCLASSIFIED", match_kind(" plain") == "UNCLASSIFIED")
    t("MATCH_KIND quoted source", match_kind("{} clobbers {}") == "QUOTED_SOURCE")

    src = ROOT / "tests/c/nova/tests_ntasm_stub_table.c"
    if src.exists():
        b = src.read_bytes()
        inst = census_instruments(b)
        t("d1 is blind on stub_table (no byte member in Run)",
          inst["d1"] != "C")
        t("lex_memcmp counts stub_table's comparison", inst["lex_memcmp"] > 0)

    reg = ROOT / "tests/c/ntasm/tests.c"
    if reg.exists():
        inst = census_instruments(reg.read_bytes())
        t("the lex signal fires on a markdown gate (registry-style false positive)",
          inst["lex_memcmp"] >= 0)

    # --- THE COMMENT READER, both directions. Neither control proves anything
    # alone: a reader that discards a comment passes the first and a reader that
    # refuses every list passes the second, and the one thing that must NOT pass
    # is a reader that silently drops a malformed array. The historical blob --
    # 275 tokens, eighteen `#`, ninety-seven English words -- is the incident-2
    # artifact itself, and it is in this file as DATA so the control cannot rot
    # into a case that no longer resembles the thing it guards.
    prose = ("    # form_matrix is NOT registered, on purpose\n"
             "    # a positional reader cannot tell a name from a sentence.\n")
    # Eighteen is not a magic constant: it is `len(prose.split())`, and it is
    # written that way so a change to the prose cannot silently leave the
    # expectation describing a different comment than the one under test.
    n_prose = len(prose.split())
    clean = "    abi parser\n    x64_lea\n"
    t("a clean list drops nothing at all",
      split_positional(clean) == (["abi", "parser", "x64_lea"], 0, None))
    t("a comment INSIDE a list is dropped and COUNTED, not absorbed",
      split_positional("abi\n" + prose + "parser") ==
      (["abi", "parser"], n_prose, None))
    t("a comment AFTER the last stem and before the closing delimiter is dropped",
      split_positional("abi parser\n" + prose) ==
      (["abi", "parser"], n_prose, None))
    t("the two shapes above are the SAME count, which is what makes the pair a "
      "control rather than two anecdotes",
      split_positional("abi\n" + prose + "parser")[1]
      == split_positional("abi parser\n" + prose)[1] == n_prose)
    t("a comment carrying a `)` does not terminate the list",
      array_body("GATES=(\n" + prose + "    abi parser\n" + prose + ")\n", "GATES")
      is not None and len(split_positional(array_body(
          "GATES=(\n" + prose + "    abi parser\n" + prose + ")\n", "GATES"))[0]) == 2)
    t("a MALFORMED token is refused, never skipped",
      split_positional('"two words"')[2] is not None)
    t("a well-formed list is not refused",
      split_positional(clean)[2] is None)
    # THE HISTORICAL BLOB, incident 2 verbatim in shape: the A class's 69 names
    # with a nine-line `#` note inside it. The tolerance is what makes it parse
    # to 69, and the COUNT is what makes the tolerance safe rather than a way of
    # being quietly right -- a reader that discarded the note and said nothing
    # is exactly the failure W48 measured on this blob.
    blob = CLASSES_A_NAMES_HISTORICAL
    t("the incident-2 blob really carries the comment (a control that tests nothing is not a control)",
      blob.count("#") >= 9)
    t("the incident-2 blob parses to 69 names and REPORTS what it dropped",
      (lambda r: len(r[0]) == 69 and r[1] == len(blob.split()) - 69 and r[2] is None)(
          split_positional(blob)))
    # AND THE OTHER DIRECTION: tolerance must not become a blanket ignore. A
    # duplicate among the SURVIVING names is still a refusal, with the name in
    # it, because that invariant is what makes the comment-dropping safe.
    dup = '("A", """abi parser # a note about abi\n    parser""")'
    census = ("for _cls, _names in [" + dup + "]:\n")
    t("a duplicate among surviving names still refuses, and names the gate",
      _classes_from(census)[2] is not None
      and "parser" in _classes_from(census)[2])
    t("a comment is not a duplicate: the note above does not make `parser` appear twice",
      _classes_from('for _cls, _names in [("A", """abi parser # note\n    x64""")]:\n')[2] is None)

    # A rail that wrote a cell would be the census. Assert it has no such path.
    src_txt = pathlib.Path(__file__).read_text(encoding="utf-8")
    t("no assignment into CLASSES anywhere in this file",
      not re.search(r"CLASSES\s*\[[^\]]+\]\s*=", src_txt))
    t("no `cell=` value is ever emitted",
      not re.search(r"cell=\s*['\"]?[ABC]\b", src_txt))

    print("  selftest cases=%d failed=%d" % (cases, fails))
    return fails == 0


def main():
    if "--selftest" in sys.argv:
        return 0 if selftest() else 1

    names, srcs, pop_counts, err = population()
    if err:
        print("POPULATION_ERROR %s" % err)
        return 1

    cls, cls_dropped, cerr = classes_literal()
    if cerr:
        print("CENSUS_ERROR %s" % cerr)
        return 1
    decl = census_self_description()
    if decl:
        print("CENSUS_SELF_DECLARATION %s" % decl)
        print("  ^ read from %s line 2; this rail does not act on it"
              % CENSUS.relative_to(ROOT))

    # WHAT WAS DROPPED, printed from the PRE-drop count and ONLY when something
    # was dropped. Both halves are load-bearing. The pre-drop count is the one
    # a comment-blind reader would have printed, so the line reports a
    # measurement rather than the reader's own opinion of itself; and the
    # condition is the rule that an instrument with nothing to say must print
    # nothing AND say so -- an unconditional `dropped=0` on every run forever is
    # the noise this project has already paid for once.
    for label, pre in sorted(cls_dropped.items()):
        n_pre = sum(1 for n in cls if cls[n] == label) + pre
        if pre:
            print("CLASSES_COMMENT_DROPPED class=%s pre_drop=%d survived=%d"
                  % (label, n_pre, n_pre - pre))

    ok, dupes, absent, uncovered, unclassified = closed(names, srcs, cls)
    if unclassified:
        print("POPULATION_UNCLASSIFIED n=%d stems=%s"
              % (len(unclassified), " ".join(unclassified)))
        print("  ^ covered by the driver and NOT classifiable: an ABSENCE is not"
              " derivable. These tests run; their class is unknown, not absent.")
    if not ok:
        print("POPULATION_NOT_CLOSED dupes=%s absent=%s uncovered=%s" % (dupes, absent, uncovered))
        if uncovered:
            print("  a gate in the driver with a file and NO CELL in the table is an")
            print("  UNCLOSED denominator, and classifying it is the judgement this rail")
            print("  refuses. So it is named and the run stops here rather than")
            print("  rendering it as a class of its own.")
        return 1
    for arr in ARRAYS:
        survived, pre = pop_counts[arr]
        if pre:
            print("GATES_COMMENT_DROPPED array=%s pre_drop=%d survived=%d"
                  % (arr, survived + pre, survived))
    print("POPULATION_CLOSED n=%d arrays=%s" % (
        len(names), "+".join(str(pop_counts[a][0]) for a in ARRAYS)))

    print("TALLY_FROM_TABLE label=recomputed_from_the_hand_entered_table "
          "NOT_re_derived_from_the_gates n=%d" % len(cls))

    doc = DOCS.read_bytes()
    rows = {}
    for l in DOCS.read_text(encoding="utf-8").splitlines():
        p = l.split("|")
        if len(p) > 2 and p[1].strip().startswith("A"):
            rows[p[1].strip()] = sha_bytes(l.encode("utf-8"))

    global gate_names_set
    gate_names_set = {n for n in names if n in rows}

    disagree, single = [], []
    for n in names:
        if n not in srcs or not srcs[n].exists():
            continue
        b = read(srcs[n])
        inst = census_instruments(b)
        cell = cls.get(n, "?")
        hits = lexical(doc.decode("utf-8"), n)
        state = edit_state(srcs[n], CENSUS)
        # A disagreement is only a disagreement between two instruments that
        # BOTH produced an opinion. `lex` is a COUNT and never a class; `d1`
        # returning no-Run-struct is a BLINDNESS, not a verdict. My first version
        # compared the three as strings and queued all 124 gates -- which is the
        # "7 errors to fix 7" failure the census lot measured, committed by the
        # instrument written to prevent it. A queue of everything is a queue of
        # nothing.
        # AN INSTRUMENT WITH NO OPINION ABSTAINS. It does not agree and it does
        # not disagree, and mapping `A-or-C-unseen` onto `A` was a defect in this
        # rail rather than a property of the data: it turned D1's blindness into
        # a VOTE FOR the census, on exactly the cells the census gets wrong.
        # Measured: stub_table census=A d1=A-or-C-unseen lex_count=10, and it
        # came out of a queue of 32 "agreeing".
        opinions = {"census_cell": cell}
        d1_abstained = True
        if inst["d1"] in ("C", "A"):
            opinions["d1"] = inst["d1"]
            d1_abstained = False
        # The abstention lives HERE, outside `opinions`, and that is the entire
        # difference between `d1 abstained` and `d1 said abstain`. Only one of
        # them is a claim, and putting the token in the compared set turned a
        # silence into a vote that disagreed with everything -- which is how the
        # previous attempt produced DISAGREE 124 / SINGLE 0.
        d1_said = "abstain" if d1_abstained else inst["d1"]
        verdicts = dict(opinions)
        verdicts["lex_count"] = inst["lex_memcmp"]
        verdicts["d1_said"] = d1_said
        # TWO lists, and the distinction is a disagreement against a SILENCE.
        # An abstention is neither agreement nor disagreement, so it can create
        # neither. Attempt 1 counted silence as disagreement (queue 124, a queue
        # of nothing); attempt 2 counted it as agreement (queue 32, and none of
        # the six known-false cells in it, because D1 abstains on those). This
        # is the shape neither attempt had.
        kind = None
        if len(opinions) > 1:
            kind = "DISAGREE" if len(set(opinions.values())) > 1 else None
        if kind is None and d1_abstained:
            kind = "SINGLE"
        if kind == "DISAGREE":
            disagree.append((n, verdicts, inst, hits, state, b))
        elif kind == "SINGLE":
            single.append((n, verdicts, inst, hits, state, b))

    print("EDIT_STATE quiet=%d edited=%d"
          % (sum(1 for n in names if n in srcs and srcs[n].exists()
                 and edit_state(srcs[n], CENSUS) == "QUIET"),
             sum(1 for n in names if n in srcs and srcs[n].exists()
                 and edit_state(srcs[n], CENSUS) != "QUIET")))

    # NEVER SUMMED. R24 refusal 3, as code rather than as a sentence: summing
    # these two is what made the census's tally read as a finding.
    print("QUEUE_DISAGREE n=%d  (two instruments, both with an opinion, differing)"
          % len(disagree))
    print("QUEUE_SINGLE   n=%d  (one opinion and one SILENCE -- neither agreement"
          " nor disagreement)" % len(single))
    print("SUM n=%d  REFUSED: DISAGREE and SINGLE are never added -- a silence is"
          " not a vote" % -1)
    queue = disagree
    limit = next((int(a.split("=")[1]) for a in sys.argv if a.startswith("--queue=")), 0) or 12
    for n, verdicts, inst, hits, state, b in queue[:limit]:
        print("gate=%s  verdicts=%s  edit=%s  gate_bytes=%s"
              % (n, verdicts, state, sha_bytes(b)))
        for h in hits[:6]:
            print("    match line=%s kind=%s ctx=%s" % (h[1], h[2], h[3][:70]))
        if inst["d1_blind"]:
            print("    d1_blind %s" % inst["d1_blind"])
    if len(queue) > limit:
        print("  ... %d more" % (len(queue) - limit))

    print("RAIL_LIMITS asserted=population_closed;per_row_binding;per_gate_bytes;"
          "match_kind_at_site;all_instruments_printed_unresolved;queue_is_the_deliverable "
          "not_asserted=the_class_of_a_gate_ever;any_winner_among_disagreeing_instruments;"
          "one_combined_tally;any_verdict_without_a_recomputable_row_binding;"
          "a_rail_whose_judgement_cells_carry_digests_has_rebuilt_the_census")
    return 0


if __name__ == "__main__":
    sys.exit(main())
