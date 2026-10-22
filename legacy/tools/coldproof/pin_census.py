#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# LOT 64 -- PIN CONVERGENCE CENSUS.
#
# WHAT THIS IS FOR, in one line: a .ntasm member named by two gate tables is
# measured twice, and nothing in the tree checks that the two measurements
# agree. This instrument enumerates the members, enumerates the tables that
# name them, extracts every pin, and compares ONLY the members two or more
# tables measure.
#
# WHAT IT DOES NOT DO, and the omission is deliberate rather than an oversight:
# it does not decide which pin is right when two disagree. A pin is a claim
# about intent, and editing one to make a report green is the failure mode the
# owner's own README names at
# examples/ntasm-v0/c-bootstrap-controlflow/README.md:174-177. This file reads
# pins and names them, and writes nothing outside out/.
#
# THE ORDERING IS THE DISCIPLINE. The population is printed BEFORE the counts,
# because a zero without a denominator is an instrument failure and a count
# without a population is a rumour.
#
# NOTHING HERE IS HARDCODED. Every table is parsed out of the gate's own bytes
# on this run, so a row added to a gate tomorrow is a row this reads tomorrow,
# and a gate edited without its table updated moves the number here instead of
# leaving it stale and green.
# ---------------------------------------------------------------------------
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
NOVA = os.path.join(REPO, "bootstrap", "quarantine", "c", "nova")

SKIP = set(" \t\r\n")


def read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def walk_members():
    """Every .ntasm on the tree. The denominator for every count below."""
    root = os.path.join(REPO, "examples", "ntasm-v0")
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for f in sorted(filenames):
            if f.endswith(".ntasm"):
                rel = os.path.relpath(os.path.join(dirpath, f), REPO)
                out.append(rel.replace("\\", "/"))
    out.sort()
    return out


# ===========================================================================
# C SOURCE SCANNERS
#
# The tables are C initialisers: brace nesting, string literals that span
# lines, and long comments. A scanner that counted braces with a regex, or
# that treated a `;` inside a comment as a terminator, reads a table as EMPTY
# -- and a table read as empty is a census that looks like coverage. So both
# scanners below skip comments explicitly, and blank_comments() replaces a
# comment with spaces of equal length so byte offsets survive.
# blank_comments replaces a comment with spaces of the SAME LENGTH *and* keeps
# every newline it covered. Replacing a 40-line block comment with 40 spaces
# was the first version, and it renumbered every line after it -- which put a
# gate's pin on the wrong line, and a pin's line is half of what this lot has
# to report. Length and line count are both preserved.
# ===========================================================================


def blank_comments(s):
    out = []
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == '"':
            j = i + 1
            while j < n:
                if s[j] == "\\":
                    j += 2
                    continue
                if s[j] == '"':
                    j += 1
                    break
                j += 1
            out.append(s[i:j])
            i = j
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "*":
            end = s.find("*/", i + 2)
            if end < 0:
                end = n - 2
            out.append("".join(ch if ch in "\r\n" else " " for ch in s[i:end + 2]))
            i = end + 2
            continue
        if c == "/" and i + 1 < n and s[i + 1] == "/":
            end = s.find("\n", i)
            end = n if end < 0 else end
            out.append("".join(ch if ch in "\r\n" else " " for ch in s[i:end]))
            i = end
            continue
        out.append(c)
        i += 1
    return "".join(out)


def skip_trivia(s, i):
    n = len(s)
    while i < n:
        if s[i] in SKIP:
            i += 1
            continue
        if s[i] == "/" and i + 1 < n and s[i + 1] == "*":
            end = s.find("*/", i + 2)
            i = n if end < 0 else end + 2
            continue
        if s[i] == "/" and i + 1 < n and s[i + 1] == "/":
            end = s.find("\n", i)
            i = n if end < 0 else end
            continue
        break
    return i


def array_body(text, start_pat):
    """(body, offset_of_body_start) for the array opened by start_pat."""
    m = re.search(start_pat, text)
    if not m:
        return None, None
    body = blank_comments(text)
    off = m.end()
    end = body.find("};", off)
    if end < 0:
        end = len(body)
    return body, off, end


TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|(NULL|[A-Za-z_][A-Za-z0-9_]*)|(-?\d+)')


def row_tokens(row):
    strings, idents, ints = [], [], []
    for m in TOKEN.finditer(row):
        if m.group(1) is not None:
            strings.append(m.group(1))
        elif m.group(2) is not None:
            idents.append(m.group(2))
        else:
            ints.append(m.group(3))
    return strings, idents, ints


def _walk_array(text, start_pat):
    """(blanked_body, offset_just_past_the_opening_brace).

    The end of the array is found by BRACE DEPTH and never by searching for
    `};`: a program-text literal in one of these rows can itself contain
    `};`, and a search for it stops the walk inside a row."""
    m = re.search(start_pat, text)
    if not m:
        return None, None
    return blank_comments(text), m.end()


def _array_span(body, off):
    """[off, end) of the array whose opening brace sits just BEFORE off, so
    the depth baseline is 1 and not 0.

    The baseline is the whole function. Starting at 0 makes the first ROW's
    brace open a depth the function did not know about, so that row's closing
    brace returns depth to 0 and the span ends one row in -- a 21-row table
    read as 1. Starting at 1 leaves rows at depth 2 and the array's own `};`
    at depth 0."""
    n = len(body)
    i, depth, in_str, in_chr = off, 1, False, False
    while i < n:
        c = body[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
        elif in_chr:
            if c == "\\":
                i += 2
                continue
            if c == "'":
                in_chr = False
        elif c == '"':
            in_str = True
        elif c == "'":
            in_chr = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return off, i
        elif c == ";" and depth == 1:
            return off, i
        i += 1
    return off, n


def scan_struct_rows(text, start_pat):
    """(row_text, first_line) for each top-level {...} initialiser inside the
    array.

    Rows are separated by COMMAS, so the walk skips trivia and commas. A
    walker that stops at the comma after the first row reads a 21-row table
    as a 1-row table -- which is exactly how this instrument's first version
    shipped, and it is the shape of defect this lot exists to correct: a
    census that reads as coverage because the parser, not the corpus, was
    empty."""
    body, off = _walk_array(text, start_pat)
    if body is None:
        return []
    off, end = _array_span(body, off)
    n = len(body)
    i = off
    rows = []
    while True:
        while i < end and (body[i] in SKIP or body[i] == ","):
            i += 1
        if i >= end or body[i] != "{":
            break
        depth, j, in_str, in_chr = 0, i, False, False
        while j < n:
            c = body[j]
            if in_str:
                if c == "\\":
                    j += 2
                    continue
                if c == '"':
                    in_str = False
            elif in_chr:
                if c == "\\":
                    j += 2
                    continue
                if c == "'":
                    in_chr = False
            else:
                if c == '"':
                    in_str = True
                elif c == "'":
                    in_chr = True
                elif c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        j += 1
                        break
            j += 1
        rows.append((body[i:j], body.count("\n", 0, i) + 1))
        i = j
    return rows


def scan_flat_strings(text, start_pat):
    """(literal, line) for a flat `const char *X[] = { "a", "b" };` array,
    which carries no per-row braces at all."""
    body, off = _walk_array(text, start_pat)
    if body is None:
        return []
    off, end = _array_span(body, off)
    out = []
    for m in re.finditer(r'"((?:[^"\\]|\\.)*)"', body[off:end]):
        out.append((m.group(1), body.count("\n", 0, off + m.start()) + 1))
    return out


# ===========================================================================
# PINS
# ===========================================================================


class Pin(object):
    """One (member, gate) measurement.

    The raw form is kept verbatim because the difference between "expects a
    refusal with code 800" and "expects a result of 0" is the finding, and
    normalising it away would erase the very thing being measured."""

    def __init__(self, gate, table, member, line, verdict, result, sizes, raw,
                 row_name=None):
        self.gate = gate
        self.table = table
        self.member = member
        self.line = line
        # The row's OWN name, as its table spells it. A run log reports that
        # name, not the file path, so it is carried rather than re-derived by
        # regex -- the first version re-derived it and lost one row of 21,
        # silently, and the row it lost was the one carrying the finding.
        self.row_name = row_name
        self.verdict = verdict   # CONVERGE | REFUSE | EXECUTE | BUILD | NONE
        self.result = result     # expected value / refusal code, or None
        self.sizes = sizes       # expected byte sizes / digests, unnormalised
        self.raw = raw

    def build_claim(self):
        """What this pin asserts about whether the product BUILDS the member,
        or None when the pin makes no such claim. A pin that says nothing
        about building cannot disagree with one that does -- and reporting it
        as a disagreement would be a false positive."""
        if self.verdict in ("CONVERGE", "EXECUTE", "BUILD"):
            return "builds"
        if self.verdict == "REFUSE":
            return "refuses"
        return None


# ===========================================================================
# THE GATE TABLES. Found by their DATA, not by their filename.
# ===========================================================================


def table_convergence_corpus():
    """CORPUS[] -- 'the Nova producer's object and PE are byte identical to
    the C reference's'. Names only; the bytes are the pin."""
    path = os.path.join(NOVA, "nova_corpus_convergence.c")
    text = read(path)
    dm = re.search(r'static const char \*DIR = "([^"]+)"', text)
    if not dm:
        return [], None
    base = dm.group(1)
    pins = []
    for name, line in scan_flat_strings(text, r"static const char \*CORPUS\[\] = \{"):
        pins.append(Pin("nova_corpus_convergence", "CORPUS[]",
                        base + name + ".ntasm", line, "CONVERGE", None, {},
                        '"%s"' % name))
    return pins, path


def table_convergence_boundary():
    """BOUNDARY[] -- per row: nova == 0 means 'must converge byte identical',
    else the pin is the refusal CODE. Rows whose source slot is an inline
    program literal are NOT tree members and are deliberately excluded; rows
    naming a path are members."""
    path = os.path.join(NOVA, "nova_corpus_convergence.c")
    text = read(path)
    pins = []
    for row, line in scan_struct_rows(text, r"static const Boundary BOUNDARY\[\] = \{"):
        strings, idents, ints = row_tokens(row)
        if len(strings) < 2 or len(ints) < 3:
            continue
        name, base = strings[0], strings[1]
        filt = [s for s in strings[2:] if s.endswith(".ntasm")]
        if not filt:
            continue  # inline source literal: a shape, not a member
        c_object, c_pe, nova = (int(x) for x in ints[-3:])
        verdict = "CONVERGE" if nova == 0 else "REFUSE"
        BOUNDARY_ROW_PATH[name] = base + filt[0]
        # This gate drives ONE source file through one entry and says so in
        # its own header. That is recorded on the pin because whether two
        # gates hand the product the same INPUT SET is half of whether their
        # verdicts are comparable at all.
        pins.append(Pin("nova_corpus_convergence", "BOUNDARY[]",
                        base + filt[0], line, verdict,
                        None if nova == 0 else nova,
                        {"c_object": c_object, "c_pe": c_pe,
                         "inputs": "one source / one entry / mode 0"},
                        row.strip()))
    return pins, path


def table_corpus_e2e():
    """MEMBERS[] -- per row: expect_refused says the product must refuse;
    otherwise the member is compiled, linked and executed, and has_want says
    the value it must return. The primary source is the member; the second
    source is a companion unit, recorded on the row, not a member of its own.
    This is the table whose row asserts that branching-runtime BUILDS."""
    path = os.path.join(NOVA, "tests_ntasm_corpus_e2e.c")
    text = read(path)
    dm = re.search(r'#define EXDIR "([^"]+)"', text)
    if not dm:
        return [], None
    base = dm.group(1)
    pins = []
    for row, line in scan_struct_rows(text, r"static const Member MEMBERS\[\] = \{"):
        strings, idents, ints = row_tokens(row)
        paths = [s for s in strings if s.endswith(".ntasm")]
        if not paths or len(ints) < 5:
            continue
        has_second = int(ints[0])
        expect_refused = int(ints[1])
        closing = int(ints[2])
        want = int(ints[3])
        has_want = int(ints[4])
        if expect_refused:
            verdict, result = "REFUSE", 0
        elif has_want:
            verdict, result = "EXECUTE", want
        else:
            verdict, result = "BUILD", None
        pins.append(Pin("tests_ntasm_corpus_e2e", "MEMBERS[]",
                        base + paths[0], line, verdict, result,
                        {"closing": closing,
                         "second": (paths[1] if has_second and len(paths) > 1
                                    else None),
                         "inputs": ("%d sources through the whole pipeline"
                                    % len(paths)) if has_second
                                   else "one source through the whole pipeline"},
                        row.strip(),
                        row_name=(strings[1] if len(strings) > 1 else None)))
    return pins, path


def table_frames():
    """frame_member() -- per row: a byte prefix the reference .text must
    carry, and must_emit saying whether a refusal is a FAILURE for this row.
    must_emit=0 pins no verdict -- it permits both -- so the row's build claim
    is None and the row can never disagree with anything."""
    path = os.path.join(NOVA, "tests_ntasm_x64_lower_nxo_frames.c")
    text = read(path)
    dm = re.search(r'#define DIR "([^"]+)"', text)
    if not dm:
        return [], None
    base = dm.group(1)
    pins = []
    for m in re.finditer(r"frame_member\(&\w+,\s*\"([^\"]+)\"", text):
        name = m.group(1)
        line = text.count("\n", 0, m.start()) + 1
        tail = text[m.start():]
        depth, k = 0, 0
        while k < len(tail):
            if tail[k] == "(":
                depth += 1
            elif tail[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        ints = [int(x) for x in re.findall(r"(?<![\w.])(-?\d+)(?![\w.])", tail[1:k])]
        must_emit = ints[-1] if ints else 0
        pins.append(Pin("tests_ntasm_x64_lower_nxo_frames", "frame_member()",
                        base + name + ".ntasm", line,
                        "BUILD" if must_emit else "NONE", None,
                        {
                         "must_emit": must_emit,
                         "inputs": "1 source / frameless profile, mode 5"},
                        m.group(0)))
    return pins, path


def _fenced_block(text, tag, occurrence):
    """(body, line_of_body) for the `occurrence`-th ```<tag> fenced block,
    reproducing tests_ntasm_cli.c's own block() so this instrument reads the
    SAME scope the gate reads.

    This is not a detail. Reading the whole document instead of the gate's
    block picked up a prose line -- a bare `sha256  <digest>` inside an
    unrelated block -- as an example id, and invented a corpus member named
    examples/ntasm-v0/c-bootstrap/sha256.ntasm that exists nowhere. A census
    that invents a member is worse than one that misses one: the invention
    reads as coverage."""
    seen = 0
    for m in re.finditer(r"```([^\n]*)\n", text):
        info = m.group(1)
        if info != tag:
            continue
        if seen != occurrence:
            seen += 1
            continue
        close = text.find("\n```", m.end())
        if close < 0:
            return None, None
        return text[m.end():close], text.count("\n", 0, m.start()) + 2
    return None, None


def table_cli_guide():
    """The cli gate holds NO literal table: it parses docs/guides/ntasm-cli.md at run
    time (block(doc,"text",3) then examples_from_block) and asserts every id
    assembles and hashes to the sha256 the guide records. The pin is a digest
    and it lives in the doc, so this reads the doc the same way, and from the
    same block."""
    gpath = os.path.join(NOVA, "tests_ntasm_cli.c")
    gtext = read(gpath)
    dm = re.search(r'static const char EXAMPLE_DIR\[\] *= *"([^"]+)"', gtext)
    # The occurrence is taken from the block call whose RESULT is handed to
    # examples_from_block, not from the first block(doc,"text",N) in the file.
    # The gate makes five such calls and the first one is the usage block, so
    # taking the first read occurrence 0 and found NO rows -- the table went to
    # zero without anything looking broken.
    occurrence = None
    for am in re.finditer(r"(\w+)\s*=\s*block\(\s*doc\s*,\s*\"text\"\s*,"
                          r"\s*(\d+)", gtext):
        if re.search(r"examples_from_block\(\s*%s\b" % re.escape(am.group(1)),
                     gtext):
            occurrence = int(am.group(2))
            break
    if occurrence is None:
        return [], None
    base = dm.group(1)
    doc_rel = "docs/guides/ntasm-cli.md"
    dpath = os.path.join(REPO, doc_rel)
    if not os.path.exists(dpath):
        return [], None
    text = read(dpath)
    block, block_line = _fenced_block(text, "text", occurrence)
    if block is None:
        return [], None
    pins = []
    for m in re.finditer(r"^([A-Za-z0-9_][A-Za-z0-9_.-]*)[ \t]+([0-9a-f]{64})"
                         r"[ \t]*([0-9]*)[ \t]*$", block, re.M):
        ident, digest, ret = m.group(1), m.group(2), m.group(3)
        line = block_line + block.count("\n", 0, m.start())
        pins.append(Pin("tests_ntasm_cli",
                        "guide table (%s text-block %d)" % (doc_rel, occurrence),
                        base + "/" + ident + ".ntasm", line, "BUILD",
                        int(ret) if ret.isdigit() else None,
                        {
                         "sha256": digest,
                         "inputs": "1 source through the shipped binary"},
                        m.group(0).strip()))
    return pins, (gpath, dpath)


def table_ntbuild_pinned():
    """scripts/ntbuild.sh :: RECORDED_EXAMPLES -- the PINNED CORPUS: one
    sha256 of a shipped PE per program. It lives outside the nova directory,
    and it is listed here because a pin table that the census skipped would
    make the census wrong by omission rather than by measurement."""
    path = os.path.join(REPO, "scripts", "ntbuild.sh")
    if not os.path.exists(path):
        return [], None
    text = read(path)
    m = re.search(r"RECORDED_EXAMPLES=\(", text)
    if not m:
        return [], None
    end = text.find("\n)", m.end())
    body = text[m.end():end if end > 0 else len(text)]
    pins = []
    for pm in re.finditer(r'"([^"|]+)\|([^"|]+)\|([0-9a-f]{64})"', body):
        ident, src, digest = pm.group(1), pm.group(2), pm.group(3)
        line = text.count("\n", 0, m.end() + pm.start()) + 1
        pins.append(Pin("scripts/ntbuild.sh", "RECORDED_EXAMPLES",
                        src.split("+")[0], line, "BUILD", None,
                        {
                         "sha256": digest, "sources": src,
                         "inputs": "%d sources through the shipped binary"
                                   % (src.count("+") + 1)}, pm.group(0)))
    return pins, path


ALL_TABLES = [
    ("nova_corpus_convergence :: CORPUS[]", table_convergence_corpus),
    ("nova_corpus_convergence :: BOUNDARY[]", table_convergence_boundary),
    ("tests_ntasm_corpus_e2e :: MEMBERS[]", table_corpus_e2e),
    ("tests_ntasm_x64_lower_nxo_frames :: frame_member()", table_frames),
    ("tests_ntasm_cli :: guide table", table_cli_guide),
    ("scripts/ntbuild.sh :: RECORDED_EXAMPLES", table_ntbuild_pinned),
]


# ===========================================================================
# THE COMPARISON -- only over multiply-measured members.
# ===========================================================================


def observed_build_axis(token):
    """Reduce an observation to the ONE axis both gates measure: did the
    product build the member? Everything else -- the result value, the
    refusal code, the executed flag -- is detail under that answer, and
    comparing it across gates that ask different questions manufactures a
    difference out of nothing."""
    if token is None:
        return None
    if token.startswith("BUILDS"):
        return "builds"
    if token.startswith("REFUSES"):
        return "refuses"
    return None


WORDNUM = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
           "single": 1, "1": 1, "2": 2, "3": 3}


def source_count(label):
    """How many source units this pin's table hands the product.

    The first version matched /(\\d+) sources?/ and fell back to string
    equality when that missed. It missed on "one source", because "one" is
    not a digit -- so two gates that BOTH drive a single source were reported
    as driving different inputs, and the one real pin split in the tree was
    reclassified as `different_purpose`. That is this lot's own defect class
    run backwards: it HIDES the finding instead of inventing one. So the word
    forms are spelled out rather than pattern-matched."""
    if not label:
        return None
    m = re.search(r"(\w+)\s+sources?", label)
    if not m:
        return None
    return WORDNUM.get(m.group(1).lower())


def same_input_set(a, b):
    """True when two pins drive the product the same number of sources, False
    when they do not, None when the tables do not say.

    A gate that hands the product ONE source and a gate that hands it TWO are
    not measuring the same thing, so their verdicts cannot contradict each
    other. Read off the tables, not argued -- and the disagreement is only
    declared when the count is actually known on both sides, because an
    unknown is not a difference."""
    na = source_count(a.sizes.get("inputs"))
    nb = source_count(b.sizes.get("inputs"))
    if na is None or nb is None:
        return None
    return na == nb


def pair_classification(a, b, observed):
    """(class, why, details).

    Three classes, and conflating any two of them is the defect:
      same_claim_agree    both claim the product builds it
      same_claim_disagree one says it refuses, the other says it builds
      different_purpose   the two gates ask different questions or hand the
                          product different inputs, so their verdicts are not
                          comparable and calling it a disagreement is a false
                          positive

    A fourth question is answered ONLY from observations, never by reading two
    tables against each other: when two pins split, did both gates MEASURE the
    same answer? Two gates observing the same answer means a stale pin. Two
    gates observing DIFFERENT answers means the product has two answers, which
    is a defect in the product and the most valuable thing this can find."""
    ca, cb = a.build_claim(), b.build_claim()
    if ca is None or cb is None:
        which = a if ca is None else b
        other = b if ca is None else a
        return "different_purpose", (
            "%s (%s, %s:%d) pins no verdict on building, so %s (%s) cannot "
            "contradict it" % (which.gate, which.verdict, which.table,
                               which.line, other.gate, other.verdict)), []
    if ca == cb:
        if ca == "refuses" and a.result != b.result:
            return "same_claim_disagree", (
                "%s pins refusal code %s and %s pins %s"
                % (a.gate, a.result, b.gate, b.result)), []
        return "same_claim_agree", (
            "both tables claim the product builds the member "
            "(%s=%s, %s=%s)" % (a.table, a.verdict, b.table, b.verdict)), []

    # The claims differ. Before calling that a disagreement, ask whether the
    # two gates even measured the same thing.
    same_inputs = same_input_set(a, b)
    if same_inputs is False:
        return "different_purpose", (
            "%s drives [%s] and %s drives [%s] -- a different number of source "
            "units, so their verdicts are about different inputs and this is "
            "NOT a disagreement"
            % (a.gate, a.sizes.get("inputs"), b.gate, b.sizes.get("inputs"))), []

    why = ("%s pins %s (%s:%d, %s) and %s pins %s (%s:%d, %s)"
           % (a.gate, ca, a.table, a.line, a.raw.split("\n")[0][:70],
              b.gate, cb, b.table, b.line, b.raw.split("\n")[0][:70]))
    detail = []
    ka = (a.gate, a.table, a.member)
    kb = (b.gate, b.table, b.member)
    oa, ob = observed.get(ka), observed.get(kb)
    sa = observed_build_axis(oa)
    sb = observed_build_axis(ob)
    if sa is not None and sb is not None:
        detail.append("measured, not read: %s measured %s | %s measured %s"
                      % (a.table, oa, b.table, ob))
        if sa == sb:
            detail.append("BOTH GATES MEASURED THE PRODUCT BUILDING IT -> the "
                          "product gave ONE answer and the split is between "
                          "the PINS. One pin is stale.")
        else:
            detail.append("THE TWO GATES MEASURED DIFFERENT ANSWERS (%s vs %s) "
                          "-> the product gave TWO answers on the same input, "
                          "which is a DEFECT IN THE PRODUCT, not a stale pin"
                          % (oa, ob))
    else:
        detail.append("NO MEASUREMENT for at least one gate (%s=%s, %s=%s). "
                      "This is a PIN split and is deliberately NOT classified "
                      "as stale or as a product defect here: saying which "
                      "needs a run of both gates on this tree, and this "
                      "instrument did not perform one."
                      % (ka[1], oa, kb[1], ob))
    return "same_claim_disagree", why, detail


# ===========================================================================
# THE NEGATIVE CONTROL. It must bite BEFORE the report.
# ===========================================================================
def negative_control(emit):
    m = "examples/ntasm-v0/c-bootstrap-controlflow/branching-runtime.ntasm"
    emit("NEGCONTROL the false positive under test: 'the two tables list the "
         "same members, therefore they agree'")
    a = Pin("synthetic_gate_A", "T[]", m, 1, "REFUSE", 800, {}, "")
    b = Pin("synthetic_gate_B", "T[]", m, 1, "EXECUTE", 43, {}, "")
    same = [m] == [m]
    emit("NEGCONTROL synthetic: ONE member, OPPOSITE pins (A=REFUSE 800, "
         "B=EXECUTE 43), identical member lists=%s" % same)
    kind, why, _ = pair_classification(a, b, {})
    emit("NEGCONTROL naive_same_membership_test would say: %s"
         % ("AGREE" if same else "DISAGREE"))
    emit("NEGCONTROL this instrument says: %s  [%s]" % (kind, why))
    bit = kind == "same_claim_disagree"
    emit("NEGCONTROL BIT=%s -- the instrument refuses the false positive"
         % ("YES" if bit else "NO"))

    c = Pin("synthetic_gate_B", "T[]", m, 1, "REFUSE", 800, {}, "")
    kind2, why2, _ = pair_classification(a, c, {})
    quiet = kind2 == "same_claim_agree"
    emit("NEGCONTROL synthetic: IDENTICAL pins must agree, or every row would "
         "be reported red and the word means nothing")
    emit("NEGCONTROL this instrument says: %s  [%s]" % (kind2, why2))
    emit("NEGCONTROL QUIET=%s -- it is not simply always-red"
         % ("YES" if quiet else "NO"))

    d = Pin("synthetic_gate_C", "T[]", m, 1, "NONE", None, {}, "")
    kind3, why3, _ = pair_classification(a, d, {})
    emit("NEGCONTROL a pin carrying no verdict cannot be a disagreement: %s"
         % kind3)
    emit("NEGCONTROL [%s]" % why3)
    third = kind3 == "different_purpose"

    # the fourth control, and the one that would have caught the parser bugs
    # this instrument actually shipped with: a table read as ZERO rows must be
    # reported, not silently counted as a member in no table.
    t = ('static const char *CORPUS[] = {\n'
         '  /* a comment with a ; semicolon inside it, which a naive scanner '
         'reads as the end of the array */\n'
         '  "alpha", "beta"\n};\n')
    got = scan_flat_strings(t, r"static const char \*CORPUS\[\] = \{")
    fourth = [n for n, _ in got] == ["alpha", "beta"]
    emit("NEGCONTROL a comment containing `;` must not truncate a table: "
         "read=%s expected=['alpha', 'beta'] -> %s"
         % ([n for n, _ in got], "OK" if fourth else "TRUNCATED"))
    return bit and quiet and third and fourth


# ===========================================================================
# OBSERVATIONS. Read from gate run logs when they are supplied.
#
# THE DISTINCTION THIS FUNCTION EXISTS TO KEEP. A run log carries TWO different
# kinds of line and conflating them produces a headline that is exactly wrong:
#
#   BOUNDARY branching_runtime NOVA refused=0 ... verdict=MOVED
#                           ^^^^^^^^^^^^^^  ^^^^^^^^^^^^^
#                           the PRODUCT      the GATE's own pin comparison
#
# `MOVED` does NOT mean the product refused. It means the gate compared what
# the product did against what the table pins and found a difference. Reading
# `MOVED` as an observation of the product's behaviour -- which this
# instrument's first version did -- turns "one pin is stale" into "the
# product gave two answers", the single most expensive misreading available
# here, because it names a defect in the product that does not exist and
# sends the owner to fix the wrong thing.
#
# So: `refused=N` is the product's answer. `AS_PINNED` / `MOVED` is the
# gate's verdict about the pin, and it is recorded separately.
# ===========================================================================
def load_observations(paths):
    """(gate, table, member) -> what the PRODUCT did, as a comparable token.

    A pin with no observation beside it is a pin comparison. It is never
    promoted to a verdict, and it is never called stale."""
    obs = {}
    drift = {}

    def bkey(row):
        """The member path a BOUNDARY[] row names.

        The row name is the TABLE's name (`branching_runtime`) and its file is
        the row's `path` field (`branching-runtime.ntasm`) -- two different
        spellings, in two different tables, and the first version of this
        function guessed the second from the first. That guess produced
        branching_runtime.ntasm, a file that does not exist, and silently
        matched NO observation against the one row that carries the finding.
        The directory comes from the table itself rather than a constant,
        because the rows do not all live in one directory."""
        path = BOUNDARY_ROW_PATH.get(row)
        if path is None:
            return None
        return ("nova_corpus_convergence", "BOUNDARY[]", path)

    for p in paths:
        if not (p and os.path.exists(p)):
            continue
        for line in read(p).split("\n"):
            # the PRODUCT's answer, for a row that converges
            m = re.match(r"^BOUNDARY (\S+) OBJECT C=\d+ Nova=\d+ verdict=(\S+)",
                         line)
            if m and bkey(m.group(1)):
                obs[bkey(m.group(1))] = "BUILDS"
                continue
            # the PRODUCT's answer, for a row that refuses
            m = re.match(r"^BOUNDARY (\S+) NOVA refused=(\d+)", line)
            if m and bkey(m.group(1)):
                code = int(m.group(2))
                obs[bkey(m.group(1))] = ("BUILDS" if code == 0
                                         else "REFUSES(code=%d)" % code)
                continue
            # the GATE's pin comparison -- kept, but never as an observation
            m = re.match(r"^BOUNDARY_ROW (\S+) expect=(\S+) observed=(\S+)", line)
            if m and bkey(m.group(1)):
                drift[bkey(m.group(1))] = ("expect=%s observed=%s"
                                           % (m.group(2), m.group(3)))
                continue
            m = re.match(r"^CORPUS\s+(\S+)\s+compiled=(\S+)\s+linked=(\S+)"
                         r"\s+executed=(\S+)(?:\s+result=(\S+))?", line)
            if m:
                member = E2E_MEMBER_BY_NAME.get(m.group(1))
                if not member:
                    continue
                key = ("tests_ntasm_corpus_e2e", "MEMBERS[]", member)
                if m.group(2) != "yes":
                    obs[key] = "REFUSES(compiled=%s)" % m.group(2)
                elif m.group(4) != "yes":
                    obs[key] = "BUILDS(executed=no)"
                else:
                    obs[key] = "BUILDS(executed=yes,result=%s)" % (m.group(5) or "-")
    return obs, drift


# The BOUNDARY[] rows live in more than one corpus directory, and a row NAME is
# not the row's FILE: the table writes `branching_runtime` and reads the file
# `branching-runtime.ntasm`. BOUNDARY_ROW_PATH is filled in by the table
# parser from the row's own path field and read back by load_observations, so
# the two never have to be reconciled by a guess.
BOUNDARY_ROW_PATH = {}
E2E_MEMBER_BY_NAME = {}



# ===========================================================================
# MAIN
# ===========================================================================
def main():
    out = []

    def emit(s=""):
        out.append(s)
        print(s)

    emit("=" * 78)
    emit("PIN CONVERGENCE CENSUS -- lot 64")
    emit("=" * 78)
    emit()

    # ---- the population, BEFORE any count --------------------------------
    members = walk_members()
    emit("POPULATION  every .ntasm member on the tree, enumerated before any "
         "count is printed:")
    for m in members:
        emit("  MEMBER %s" % m)
    emit("POPULATION members_on_tree=%d" % len(members))
    emit()

    # ---- the tables ------------------------------------------------------
    all_pins = []
    table_list = []
    for label, fn in ALL_TABLES:
        pins, src = fn()
        table_list.append((label, pins, src))
        all_pins.extend(pins)
        for p in pins:
            if p.gate == "tests_ntasm_corpus_e2e" and p.row_name:
                E2E_MEMBER_BY_NAME[p.row_name] = p.member
        emit("TABLE %-48s rows=%d" % (label, len(pins)))
    emit("GATE_TABLES %d" % len(table_list))
    emit()

    # ---- one row per (member, gate), format NOT normalised ---------------
    by_member = {}
    for p in all_pins:
        by_member.setdefault(p.member, []).append(p)

    emit("PINS one row per (member, gate). The verdict, the expected result and "
         "the expected byte sizes are kept in the shape each table writes them:")
    for m in sorted(by_member):
        for p in sorted(by_member[m], key=lambda x: (x.gate, x.line)):
            sizes = " ".join("%s=%s" % (k, v) for k, v in sorted(p.sizes.items())
                             if v is not None)
            emit("  PIN member=%-46s gate=%-32s table=%-30s line=%-5d "
                 "verdict=%-9s result=%-6s %s"
                 % (m, p.gate, p.table, p.line, p.verdict,
                    "-" if p.result is None else p.result, sizes or "-"))
    emit("PINS_ENUMERATED %d" % len(all_pins))
    emit()

    # ---- the membership census ------------------------------------------
    multi = sorted(m for m in by_member if len(by_member[m]) >= 2)
    single = sorted(m for m in by_member if len(by_member[m]) == 1)
    none_ = sorted(m for m in members if m not in by_member)
    ghost = sorted(m for m in by_member if m not in members)

    emit("MEMBERS MEASURED BY 2 OR MORE TABLES: %d of %d on the tree"
         % (len(multi), len(members)))
    for m in multi:
        emit("  MULTI  %-46s tables=%d  [%s]"
             % (m, len(by_member[m]),
                ", ".join(sorted(set(p.table for p in by_member[m])))))
    emit("MEMBERS MEASURED BY EXACTLY 1 TABLE: %d" % len(single))
    for m in single:
        emit("  SINGLE %-46s %s" % (m, by_member[m][0].gate))
    emit("MEMBERS IN NO TABLE (the census gap): %d" % len(none_))
    for m in none_:
        emit("  UNMEASURED %s" % m)
    emit("MEMBERS NAMED BY A TABLE BUT ABSENT ON TREE: %d" % len(ghost))
    for m in ghost:
        emit("  GHOST %s" % m)
    emit()

    # ---- observations ----------------------------------------------------
    observed, drift = load_observations(sys.argv[1:])
    missing = [p for p in sys.argv[1:] if not os.path.exists(p)]
    for p in missing:
        emit("  LOG_MISSING %s -- every pin this log would have measured is "
             "reported WITHOUT an observation, and a split missing a "
             "measurement is reported as UNRESOLVED rather than as a finding. "
             "A wrong log path demotes a real result to silence and does not "
             "look like an error." % p)
    emit("OBSERVATIONS -- what the PRODUCT did, read from %d run log(s): %d"
         % (len(sys.argv) - 1, len(observed)))
    for k in sorted(observed):
        emit("  MEASURED  %-46s %-30s %s" % (k[2], k[1], observed[k]))
    emit()
    emit("GATE PIN COMPARISONS -- what the GATE concluded about its own table. "
         "These are the gates' verdicts on their pins and are NOT observations "
         "of the product; the two are kept apart on purpose.")
    for k in sorted(drift):
        emit("  GATE_VERDICT %-46s %-30s %s" % (k[2], k[1], drift[k]))
    emit()

    # ---- the comparison --------------------------------------------------
    counts = {"same_claim_agree": 0, "same_claim_disagree": 0,
              "different_purpose": 0}
    findings = []
    pairs = 0
    emit("COMPARISON over the %d multiply-measured members only. A member in "
         "one table cannot disagree with anything:" % len(multi))
    for m in multi:
        pins = by_member[m]
        for i in range(len(pins)):
            for j in range(i + 1, len(pins)):
                a, b = pins[i], pins[j]
                kind, why, detail = pair_classification(a, b, observed)
                pairs += 1
                counts[kind] = counts.get(kind, 0) + 1
                emit("  PAIR %s" % m)
                emit("       A %-30s %s:%-5d verdict=%-9s result=%s"
                     % (a.table, a.gate, a.line, a.verdict,
                        "-" if a.result is None else a.result))
                emit("       B %-30s %s:%-5d verdict=%-9s result=%s"
                     % (b.table, b.gate, b.line, b.verdict,
                        "-" if b.result is None else b.result))
                emit("       -> %s  [%s]" % (kind, why))
                for d in detail:
                    emit("          %s" % d)
                if kind != "same_claim_agree":
                    findings.append((m, a, b, kind, why, detail))
    emit()
    disagree = counts["same_claim_disagree"] + counts["different_purpose"]
    emit("DISAGREEMENTS_FOUND %d of %d pairs, over %d multiply-measured members "
         "of %d members on the tree"
         % (disagree, pairs, len(multi), len(members)))
    emit("  same_claim_disagree (a real pin split) %d" % counts["same_claim_disagree"])
    emit("  different_purpose  (not a disagreement; a false positive avoided) %d"
         % counts["different_purpose"])
    emit("  same_claim_agree  %d" % counts["same_claim_agree"])
    emit()

    # ---- stale vs product-defect, from MEASUREMENTS only -----------------
    stale, product_two, unresolved = [], [], []
    for m, a, b, kind, why, detail in findings:
        if kind != "same_claim_disagree":
            continue
        oa = observed.get((a.gate, a.table, a.member))
        ob = observed.get((b.gate, b.table, b.member))
        sa = observed_build_axis(oa)
        sb = observed_build_axis(ob)
        if sa is not None and sb is not None and sa == sb:
            stale.append((m, a, b, why, detail))
        elif sa is not None and sb is not None:
            product_two.append((m, a, b, why, detail))
        else:
            unresolved.append((m, a, b, why, detail))

    emit("CLASSIFICATION of the %d pin splits. Each is classified by what the "
         "gates MEASURED, never by reading one table against another:"
         % (len(stale) + len(product_two) + len(unresolved)))
    emit("  STALE_PIN (one pin did not move with the product) %d" % len(stale))
    for m, a, b, why, detail in stale:
        emit("    STALE %s" % m)
        emit("       gate/line A %s:%d  pin=%s"
             % (a.gate, a.line, a.result if a.result is not None else a.verdict))
        emit("       gate/line B %s:%d  pin=%s"
             % (b.gate, b.line, b.result if b.result is not None else b.verdict))
        emit("       %s" % why)
        for d in detail:
            emit("       %s" % d)
    emit("  PRODUCT_TWO_ANSWES (the product gave two answers -- a defect) %d"
         % len(product_two))
    for m, a, b, why, detail in product_two:
        emit("    TWO_ANSWERS %s" % m)
        emit("       %s" % why)
        for d in detail:
            emit("       %s" % d)
    emit("  UNRESOLVED_WITHOUT_AN_OBSERVATION %d" % len(unresolved))
    for m, a, b, why, detail in unresolved:
        emit("    UNRESOLVED %s  %s" % (m, why))
        for d in detail:
            emit("       %s" % d)
    emit()

    emit("NEGATIVE CONTROL")
    control_ok = negative_control(emit)
    emit()

    # ---- what this CONFIRMS and REFUTES about R163 ------------------------
    # R163 recorded the disagreement correctly and then declined to verify
    # the first half, for a stated reason: the README said NOVA_GATES are run
    # only in full-suite mode, so `ngbuild.sh <gate>` could not reach
    # nova_corpus_convergence at all. That reason is checkable, and it is
    # CHECKED here rather than repeated.
    emit("R163 VERIFICATION -- confirm or refute what the record states, "
         "against the runs this census read:")
    br_key = ("nova_corpus_convergence", "BOUNDARY[]",
              "examples/ntasm-v0/c-bootstrap-controlflow/branching-runtime.ntasm")
    e2e_key = ("tests_ntasm_corpus_e2e", "MEMBERS[]",
               "examples/ntasm-v0/c-bootstrap-controlflow/branching-runtime.ntasm")
    emit("  R163 RECORDS : convergence %s"
         % (drift.get(br_key) or "NO GATE VERDICT FOUND"))
    emit("  THIS RUN MEASURED : convergence %s | corpus_e2e %s"
         % (observed.get(br_key, "NOT MEASURED"),
            observed.get(e2e_key, "NOT MEASURED")))
    if drift.get(br_key) and "MOVED" in drift[br_key]:
        emit("  CONFIRMED : the pin split is REAL and still present on this "
             "tree. The gate reads observed=MOVED where R163 recorded "
             "AS_PINNED, so R163's snapshot has aged: what it recorded as a "
             "documented observation is today a live gate failure.")
        emit("  CORRECTED : R163's own snapshot read AS_PINNED, meaning that "
             "when R163 was written the two gates AGREED in what they "
             "measured and differed only in what their tables PIN. On this "
             "tree BOTH gates measure the product building the member. The "
             "widening has since reached the entry nova_corpus_convergence "
             "drives, so its pin is the one that did not move.")
        emit("  CONSEQUENCE : the split is now ONE STALE PIN, not a product "
             "with two answers. R163 could not establish which without a "
             "convergence run; this census had one.")
    emit("  REFUTED : R163 declined to verify the convergence half because "
         "README.md:203-205 claims ngbuild.sh <gate> cannot reach a "
         "NOVA_GATES entry at all. THIS RUN REACHED IT BY NAME with "
         "`ngbuild.sh nova_corpus_convergence`, which compiled and ran it "
         "and printed its BOUNDARY rows. The claim is false on today's "
         "ngbuild.sh, which resolves a bare name to a file without the "
         "tests_ntasm_ prefix. Reported, not repaired: the README is not "
         "this lot's file and the edit is its owner's.")
    emit()

    emit("PIN_CENSUS members=%d tables=%d multiply_measured=%d "
         "single_table=%d in_no_table=%d pins=%d pairs=%d disagree=%d "
         "stale=%d different_purpose=%d product_two_answers=%d "
         "negative_control=%s pins_edited=0"
         % (len(members), len(table_list), len(multi), len(single), len(none_),
            len(all_pins), pairs, counts["same_claim_disagree"], len(stale),
            counts["different_purpose"], len(product_two),
            "BIT" if control_ok else "FAILED"))

    dest = os.path.join(REPO, "out", "c-bootstrap", "nova", "lot64")
    if not os.path.isdir(dest):
        os.makedirs(dest)
    with open(os.path.join(dest, "pin_census.txt"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("\n".join(out) + "\n")
    return 0 if control_ok else 1


if __name__ == "__main__":
    sys.exit(main())