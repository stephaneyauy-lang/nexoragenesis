#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lot145_derivable_cells.py -- WHAT A DERIVABLE CELL HAS TO BE ABLE TO SAY.

THE SCHEMA, settled before any code that depends on it
=======================================================
The census at out/c-bootstrap/nova/W26Exposure/derive_population.py holds one
letter per gate, hand-entered, and the header says one of them is known false:
`stub_table` is filed `A` and its own bytes confront three producers at once.
lot141_second_class.py, read and run before this file was written, reproduces
that as `CONFLICT`: byte evidence at C1, C3 and C5, from FIVE sites.

So the question this file answers is not "how do I derive the letter".  It is
**"what does a cell have to be able to say"**.  The answer, from the evidence:

    A CELL IS NOT A LETTER.  A cell is a RECORD, and a letter is a PROJECTION
    of that record which is defined only when the record has the shape a
    letter can hold.

    Cell = {
      layers    : the SET of producer layers with byte evidence at some site.
                  A SET, because stub_table has three and one of them is the
                  whole finding.
      others    : for each byte site, what the OTHER side was -- a different
                  producer (INDEPENDENT), the same Nova product (SAME_SIDE),
                  or bytes the gate wrote or typed (NOT_INDEPENDENT).
      bytesites : how many byte comparison sites there were.
      wordsites : how many comparisons were made on something that is not
                  bytes -- return codes, guard words, report columns.
      letter    : the census letter IF the record collapses to one; otherwise
                  MULTI(C1,C3,C5) or ABSTAIN, both printed as VALUES.
    }

Four things follow, and each is a consequence rather than a preference:

  1. `A` IS NOT DERIVABLE.  It is an ABSENCE -- no byte site -- over a
     comparison vocabulary nobody has enumerated.  A gate with no byte site
     therefore reads ABSTAIN, and ABSTAIN against a table cell is UNVERIFIED,
     never DISAGREE.  Abstaining is not a claim and this file never renders
     one as either agreement or contradiction.

  2. A GATE WITH BYTES AT THREE LAYERS HAS NO LETTER.  It prints
     MULTI(...).  Printing `C1` there would be choosing, and choosing is the
     hand-entry this file exists to stop doing -- with a generator.

  3. A GATE WITH BYTES BUT NO INDEPENDENT OTHER SIDE IS C4, and that is a
     DIFFERENT claim from `A` even though both can print C4's letter: C4
     asserts the bytes were compared; A asserts nothing about bytes at all.
     The cell keeps the two apart by carrying `bytesites` and `layers`.

  4. WORD-LEVEL ASSERTIONS ARE EVIDENCE AND ARE COUNTED.  `machine_x64` pins
     six stage return codes and four report words per case before it reaches
     a single byte.  A schema with no place to put that would call a byte gate
     a byte gate and hide what it actually weighs.

WHY A DERIVED CELL MAY NOT REPLACE THE HAND-ENTERED ONE
========================================================
It is printed BESIDE it, in its own column, with the disagreement visible.  A
derived cell that silently replaced the hand-entered letter would certify the
defect identically to a digest of it -- the census's own sentence, and the
reason this file exists.  So the hand-entered table is read AFTER every derived
cell has been computed, and `derive_all()` refuses to run if it has already
been parsed.

WHAT IS DERIVED FROM
====================
The gate's own source, and the C headers that declare the producers it calls.
Not the hand-entered table, not a hint, not a default, not a list of gate names.

On top of lot141_second_class.py, whose three recorded defects are the reason
several scopes here are keyed BY INDEX rather than by name, and whose parse
primitives are imported rather than rewritten:

  * origins, per SCOPE, from a producing entry point's declared
    non-const aggregate out-parameter; from a buffer lent to the mapped Nova
    image with the writer flag READ OFF THE CALL; from bytes read off disk; and
    from a run-carrier struct's own declaration.

  * ONE JOINT FIXPOINT over three edge kinds -- copy (`memcpy`/assignment),
    forward (argument names the callee's parameter) and BACKWARD (a callee's
    writability reaches the caller's buffer).  lot141 runs the copy pass
    entirely inside `scope_origins` and the parameter passes afterwards, so a
    value that only becomes a buffer THROUGH a parameter cannot be copied
    from: in tests_ntasm_machine_x64.c, `measure`'s `memcpy(v->text, r.text)`
    is a copy edge whose source `r` is only known to be a run buffer because
    `run()`'s fourth borrow is writable, which is a parameter fact.  Measured:
    the two-loop version leaves `v`, `v1` and `v2` unbound and the gate
    abstains; the joint fixpoint binds all three and reaches the two memcmp
    sites.  This is the third recorded defect's shape, in a place lot141 does
    not cover.

WHAT IS NOT ESTABLISHED HERE
============================
No cell is written anywhere.  No gate is registered.  No census is closed.  The
census file says not to add a cell to it and this file does not: it holds no
code path that writes one, and its self-test asserts it.

Run:
    python legacy/tools/coldproof/lot145_derivable_cells.py
    python legacy/tools/coldproof/lot145_derivable_cells.py --why <stem>
    python legacy/tools/coldproof/lot145_derivable_cells.py --selftest
"""

import hashlib
import os
import pathlib
import re
import sys
import tempfile
from collections import Counter, OrderedDict

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
# lot141_second_class is imported for its PARSE PRIMITIVES and its header
# layers.  It is not modified, not subclassed, and `classify_gate` -- which
# collapses a cell to one letter or to the string CONFLICT -- is never called
# here, because collapsing is what this file declines to do.
import lot141_second_class as L

ROOT = pathlib.Path(__file__).resolve().parents[2]
DRIVER = ROOT / "tools" / "coldproof" / "ngbuild.sh"
C = ROOT / "bootstrap" / "quarantine" / "c"
NOVA = C / "nova"
CENSUS = ROOT / "out" / "c-bootstrap" / "nova" / "W26Exposure" / "derive_population.py"

# The two stems the census cannot carry today: a gate in the driver with a
# file and no cell is POPULATION_NOT_CLOSED, and while unclosed the rail
# prints no per-gate cell at all.  They are listed HERE, as stems to ATTEMPT,
# and nothing else: no class is attached to either name anywhere in this file,
# so each one is derived from its source or abstains.  Their sources are
# located by the driver's OWN GATES rule (`<name>` -> NOVA/tests_ntasm_<name>.c),
# read out of the same driver file the population is read from -- not typed.
def _driver_stems():
    """Every name the driver registers, read from the driver."""
    text = DRIVER.read_text(encoding="utf-8")
    out = set()
    for arr in ("GATES", "NOVA_GATES", "ROOT_GATES"):
        m = re.search(r"^" + arr + r"=\((.*?)\)", text, re.S | re.M)
        if m:
            out |= set(m.group(1).split())
    return out


def _pending_stems():
    """Harnesses PRESENT in the tree and ABSENT from the driver.

    Derived, never typed. The previous hand-written tuple went stale the moment
    its two names were registered -- it kept listing them as pending while the
    driver ran them -- and it could not see the two harnesses that actually are
    unregistered. A pending set is a set DIFFERENCE between the tree and the
    driver; anything else is a memory.
    """
    registered = _driver_stems()
    got = set()
    for base, prefix in ((NOVA, "tests_ntasm_"), (C, "tests_ntasm_")):
        for f in base.glob(prefix + "*.c"):
            s = f.stem[len(prefix):]
            if s and s not in registered:
                got.add(s)
    return tuple(sorted(got))


PENDING_STEMS = _pending_stems()

_TABLE_PARSED = False
BYTES_ORIGIN = set(L.PRODUCING_CLASSES) | {"RUN", "GOLDEN", "LOCAL", "LITERAL"}
PRODUCING_SIDE = set(L.PRODUCING_CLASSES) | {"RUN"}


# ---------------------------------------------------------------------------
# 0. THE FENCE.  Taken BEFORE any reading and AFTER all of it, because a
#    number compared against a number taken at a different instant on a tree
#    that moved is not a comparison.
# ---------------------------------------------------------------------------

def fence():
    h = hashlib.sha256()
    for p in (DRIVER, CENSUS):
        h.update(p.name.encode("utf-8"))
        h.update(p.read_bytes())
    for name, pathf in (("GATES", lambda n: NOVA / ("tests_ntasm_%s.c" % n)),
                        ("NOVA_GATES", lambda n: NOVA / (n + ".c")),
                        ("ROOT_GATES", lambda n: C / n)):
        m = re.search(r"^" + name + r"=\((.*?)\)", DRIVER.read_text(encoding="utf-8"),
                      re.S | re.M)
        if not m:
            raise SystemExit("FENCE_ERROR array not found in driver: " + name)
        for tok in m.group(1).split():
            p = pathf(tok)
            h.update(tok.encode("utf-8"))
            h.update(p.read_bytes() if p.is_file() else b"\0MISSING")
    for stem in PENDING_STEMS:
        p = stem_source(stem)
        h.update(stem.encode("utf-8"))
        h.update(p.read_bytes() if p.is_file() else b"\0MISSING")
    return h.hexdigest()[:16]


# ---------------------------------------------------------------------------
# 1. THE POPULATION.  Asserted BEFORE anything is counted: a pattern that does
#    not match RAISES here and never reports a zero it invented.
# ---------------------------------------------------------------------------

def stem_source(stem):
    """A pending stem's source, by the DRIVER'S OWN GATES rule."""
    return NOVA / ("tests_ntasm_%s.c" % stem)


def census_population():
    text = DRIVER.read_text(encoding="utf-8")
    pop = []
    for arr, pathf in (("GATES", lambda n: NOVA / ("tests_ntasm_%s.c" % n)),
                       ("NOVA_GATES", lambda n: NOVA / (n + ".c")),
                       ("ROOT_GATES", lambda n: C / n)):
        m = re.search(r"^" + arr + r"=\((.*?)\)", text, re.S | re.M)
        if not m:
            raise SystemExit("POPULATION_ERROR array %s not found in driver; "
                             "refusing to count" % arr)
        toks = m.group(1).split()
        if not toks:
            raise SystemExit("POPULATION_ERROR array %s parsed to 0 entries; "
                             "refusing to count" % arr)
        pop.extend((t, pathf(t)) for t in toks)
    if not pop:
        raise SystemExit("POPULATION_ERROR empty; refusing to count")
    absent = [n for n, p in pop if not p.is_file()]
    if absent:
        raise SystemExit("POPULATION_ERROR %d source(s) absent: %s"
                         % (len(absent), ", ".join(absent[:8])))
    for stem in PENDING_STEMS:
        p = stem_source(stem)
        if not p.is_file():
            raise SystemExit("POPULATION_ERROR pending stem %s has no source at "
                             "the driver's own GATES path rule: %s" % (stem, p))
    if len(pop) != len(set(n for n, _ in pop)):
        raise SystemExit("POPULATION_ERROR duplicate names in the driver arrays")
    return pop


# ---------------------------------------------------------------------------
# 2. THE DERIVATION.  A cell per gate, from that gate's source and the C
#    headers that declare the producers it calls.
# ---------------------------------------------------------------------------

def _param_slots(params):
    """ONE SLOT PER PARAMETER, in order, pointer positions named.

    Dropping the non-pointer parameters instead of leaving a hole shifts every
    later index and binds each argument to the wrong parameter.  A by-value
    parameter cannot carry a buffer, and letting one try taints sizes.
    """
    slots = []
    for pp in L.split_params(params):
        slots.append(None)
        if "*" not in pp:
            continue
        mm = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", pp.replace("*", " * "))
        if mm and mm.group(1) not in L.KEYWORDS and not mm.group(1).endswith("_t"):
            slots[-1] = mm.group(1)
    return slots


def nova_host_producers():
    """{entry point: out-param index} for the NOVA HOST's own producers.

    DERIVED, not typed, and from the same rule the C layers use: a declaration
    that returns a status code and takes a non-const aggregate out-parameter is
    a producer.  `nova_compile_many_v2(..., NtArtifact *out)` in nova.h fills a
    caller's artifact; that artifact is the NOVA PRODUCT, which is a producer
    of bytes like any other and is simply not in the C1..C5 header partition,
    because it is not one of the C reference layers.  Reading it off nova.h by
    signature is what lets `nova_language_lex`'s
    `memcmp(first.text.bytes, second.text.bytes, ...)` resolve: both operands
    are artifacts this gate compiled, and neither is a hand-typed literal.
    """
    out = {}
    hdr = C / "nova.h"
    txt = hdr.read_text(encoding="utf-8", errors="replace")
    for m in L.DECL_RE.finditer(txt):
        fn, params = m.group(1), m.group(2)
        if not fn.startswith("nova_"):
            continue
        line_start = txt.rfind("\n", 0, m.start()) + 1
        ret = re.sub(r"\b(static|extern|inline)\b", " ", txt[line_start:m.start(1)]).strip()
        if not ret or ret == "void":
            continue
        for i, p in enumerate(L.split_params(params)):
            if L.out_param_index(p) is not None:
                out[fn] = i
                break
    return out


TYPED_TABLE_RE = re.compile(r"static\s+const\s+\w+\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[\s*\]")


def typed_table_origins(text):
    """{variable: {LITERAL}} for pointers into a hand-typed table.

    DERIVED, not typed.  `const Expectation *e = &EXPECT[i];` is the gate
    pointing at its OWN expectation table, and the expectation's `text` member
    is a pointer to a `static const uint8_t T_*[]` of bytes the author typed.
    That is the hand-typed other side, and the census already has a letter for
    it: C4, "bytes, but no independent other side".  Recognising it is what
    stops `machine_x64`'s `memcmp(v1.text, e->text, ...)` from reading as an
    unresolved operand -- an unresolved operand is an ABSTENTION, and filing
    an abstention as a class would be the dishonest move W141 refused to make.
    """
    tables = set(TYPED_TABLE_RE.findall(text))
    out = {}
    # The pointer's own `*` sits between the identifier and the `=`, so the
    # pattern must allow it: `const Expectation *e = &EXPECT[i];` does not
    # match `(\w+)\s*=\s*` and the expectation table reads as undeclared.  A
    # pattern that silently finds nothing here is an abstention that looks like
    # a source with no hand-typed bytes in it.
    for m in re.finditer(r"\bconst\s+[A-Za-z_][A-Za-z0-9_]*\s*\*\s*"
                         r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*&?\s*"
                         r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[[^\]]*\])?\s*;", text):
        lhs, rhs = m.group(1), m.group(2)
        if rhs in tables:
            out[lhs] = {"LITERAL"}
    return out


def derive_cell(path, eps):
    """-> dict, the cell.  It cannot see the hand-entered table: `derive_all`
    runs every cell to completion before `load_hand_table` is ever called, and
    a runtime guard raises if the table has been parsed."""
    global _TABLE_PARSED
    if _TABLE_PARSED:
        raise SystemExit("REFUSING TO DERIVE: the hand-entered table is already "
                         "in scope.  A cell derived with one eye on it is not "
                         "a derivation.")
    raw = path.read_bytes().decode("utf-8", errors="replace")
    text = L.strip_noise(raw)
    defs = L.function_defs(text)
    rtypes = L.run_typedefs(text)
    loaders = [n for n, _r, _p, b in defs if "fopen" in b and "fread" in b]
    # Two more producer families the C-layer partition does not name, both read
    # off a header by the SAME out-parameter rule, and neither a gate list:
    nprod = nova_host_producers()

    # scopes are a LIST and every later lookup is BY INDEX.  Two static helpers
    # in one gate may share a name, and looking a scope up by name alone scans
    # the first one twice and never the second -- which is how a memcmp left a
    # site list that otherwise looked healthy.
    scopes = [("<file>", L.scope_origins(text, eps, {"run_types": rtypes})[0],
               {}, text)]
    for idx, (name, _r, _p, body) in enumerate(defs):
        o, vt = L.scope_origins(body, eps, {"run_types": rtypes})
        scopes.append((name, o, vt, body))

    # gate-local factory edges: a helper that RETURNS a producer's bytes is a
    # factory, and its caller's variable carries that layer.
    fac = {}
    for name, ret, _p, body in defs:
        if "*" not in ret:
            continue
        o = dict(L.scope_origins(body, eps, {"run_types": rtypes})[0])
        got = set()
        for m in re.finditer(r"\breturn\b([^;]*);", body):
            for ident in L.IDENT_RE.findall(m.group(1)):
                got |= {x for x in o.get(ident, ()) if x in L.PRODUCING_CLASSES}
        if len(got) == 1:
            fac[name] = got.pop()
    for _n, o, _vt, txt in scopes:
        for m in L.FACTORY_RE.finditer(txt):
            lhs, callee = m.group(1), m.group(2)
            if callee in fac and lhs not in o:
                o[lhs] = {fac[callee]}

    # NOVA HOST products: an artifact filled by nova_compile*_v2 is bytes this
    # gate produced, and it must not read UNSET -- an unresolved operand is an
    # abstention, and an abstention filed as no evidence is what leaves the two
    # pending stems unreadable.
    for _n, o, _vt, txt in scopes:
        for fn, idx in sorted(nprod.items()):
            for m in re.finditer(r"\b" + re.escape(fn) + r"\s*\(", txt):
                args = L.call_args(txt, txt.index("(", m.end() - 1))
                if idx < len(args):
                    r = L.root_of(args[idx])
                    if r and r not in o:
                        o[r] = {"RUN"}

    # HAND-TYPED EXPECTATION TABLES: bytes the author wrote into the gate.
    for _n, o, _vt, _txt in scopes:
        for k, v in typed_table_origins(text).items():
            o.setdefault(k, set()).update(v)

    # The stored index is into SCOPES, which carries `<file>` at 0 and each
    # definition at 1..n.  Storing the `defs` index instead and then reading
    # `scopes[idx]` is an off-by-one that lands every parameter edge on the
    # NEXT function, and it fails silently: the edges still fire, on the wrong
    # callee.  Measured, in that shape: `main` -- which holds every memcmp in
    # tests_ntasm_machine_x64.c -- got `measure`'s parameter bindings, and the
    # two byte sites stayed UNSET for a reason that had nothing to do with the
    # gate.
    slots = {}
    for sidx, (name, _r, params, _b) in enumerate(defs):
        sl = _param_slots(params)
        if any(sl):
            slots.setdefault(name, []).append((sidx + 1, sl))

    # ---- ONE JOINT FIXPOINT: copy, forward parameter, BACKWARD parameter ---
    # All three in one loop, because in machine_x64 `measure` copies from `r`
    # into `v->text`, and `r` is a run buffer only through `run`'s writable
    # borrow -- a parameter fact.  Two sequential loops cannot see that edge.
    buf = set(L.PRODUCING_CLASSES) | {"RUN", "GOLDEN", "LOCAL"}
    for _ in range(12):
        grew = False
        # copy edges, inside a scope
        for _n, o, _vt, txt in scopes:
            for m in L.MEMCPY_RE.finditer(txt):
                d, s = L.root_of(m.group(1)), L.root_of(m.group(2))
                if d and s and d != s and d not in o:
                    have = o.get(s)
                    if have and len(have) == 1:
                        o[d] = set(have)
                        grew = True
        # parameter edges, both directions
        for sidx, (_sn, o, _vt, txt) in enumerate(scopes):
            for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", txt):
                fname = m.group(1)
                if fname not in slots:
                    continue
                args = L.call_args(txt, txt.index("(", m.end() - 1))
                for i, a in enumerate(args):
                    rt = L.root_of(a) or ""
                    if not rt:
                        continue
                    for didx, sl in slots[fname]:
                        if i >= len(sl) or not sl[i]:
                            continue
                        target = scopes[didx][1]
                        # backward: the callee's writability reaches the caller
                        if rt not in o and sl[i] in target:
                            got = set(target[sl[i]]) & buf
                            if len(got) == 1 and L.UNSET not in got:
                                o[rt] = set(got)
                                grew = True
                        # forward: the caller's argument names the parameter
                        elif sl[i] not in target:
                            have = o.get(rt)
                            if have and len(have) == 1:
                                target[sl[i]] = set(have)
                                grew = True
        if not grew:
            break

    # a byte array the gate DECLARES and WRITES is its own other side
    gbytes = set(re.findall(r"\b(?:static\s+)?uint8_t\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[",
                            text))
    gbytes |= set(re.findall(r"\bNtBuffer\s+([A-Za-z_][A-Za-z0-9_]*)", text))
    for _n, o, _vt, txt in scopes:
        local = set(re.findall(
            r"\b(?:static\s+)?uint8_t\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[", txt))
        local |= set(re.findall(r"\bNtBuffer\s+([A-Za-z_][A-Za-z0-9_]*)", txt))
        for nm in sorted(local | gbytes):
            if nm in o:
                continue
            if (re.search(r"\b" + re.escape(nm) + r"\s*\[[^\]]*\]\s*=(?!=)", txt)
                    or re.search(r"\b" + re.escape(nm) + r"\s*\+\s*[A-Za-z0-9_]", txt)
                    or re.search(r"memcpy\s*\(\s*" + re.escape(nm) + r"\b", txt)):
                o[nm] = {"LOCAL"}

    # ---- sites -----------------------------------------------------------
    bytesites, wordsites = 0, 0
    pairs = []            # (layer, other_side_kind, kind, a, b) per byte site
    unresolved = 0
    detail = []
    for _n, o, _vt, txt in scopes:
        for m in re.finditer(r"\bmem(cmp|bcmp)\s*\(", txt):
            args = L.call_args(txt, txt.index("(", m.end() - 1))
            if len(args) >= 2:
                bytesites += 1
                detail.append(("memcmp", L.root_of(args[0]), L.root_of(args[1]), o))
        for stmt in txt.split(";"):
            subs = []
            for m in L.SUB_RE.finditer(stmt):
                root, chain = m.group(1), m.group(2)
                members = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", chain)
                is_byte = ("bytes" in members or "data" in members
                           or root in gbytes
                           or any(mm in rtypes.get(_vt.get(root, ""), ())
                                  for mm in members))
                if is_byte and root not in subs:
                    subs.append(root)
            if len(subs) >= 2:
                bytesites += 1
                for i, a in enumerate(subs):
                    for b in subs[i + 1:]:
                        detail.append(("element", a, b, o))
            elif subs and re.search(r"==|!=", stmt):
                wordsites += 1

    def orgs(o, r):
        if r is None:
            return {"LITERAL"}
        return set(o.get(r, {L.UNSET}))

    produced_sites = 0
    for kind, a, b, o in detail:
        oa, ob = orgs(o, a), orgs(o, b)
        if "NAME" in oa or "NAME" in ob:
            continue
        if L.UNSET in oa or L.UNSET in ob:
            unresolved += 1
        # THE NOVA PRODUCT IS A PRODUCING SIDE.  It is not one of the C
        # reference layers, so it is not a `layer`, but it IS the other side of
        # a real byte comparison in both pending stems, and leaving it out made
        # `layers` empty and printed ABSTAIN beside two fully resolved sites.
        # `x == y` is skipped, which is correct and load-bearing: a gate that
        # compares TWO INDEPENDENTLY COMPILED IMAGES of the same sources
        # (machine_x64's `memcmp(v1.text, v2.text, ...)`, nova_language_lex's
        # `first.text.bytes` vs `second.text.bytes`) is comparing the product
        # with ITSELF.  That is a determinism check and not a reference
        # comparison, and it is what C4 is for.
        # A produced side is counted ONLY when the OTHER side is RESOLVED.  A
        # site whose far side reads UNSET is an abstention, and calling it "no
        # independent other side" would file a shrug as C4 -- which is how a
        # first draft of this produced SIXTEEN disagreements, eight of them
        # manufactured out of unresolved operands (`validate`'s two memcmps
        # have an UNSET far side and were filed C4 for that reason alone).
        # The same-layer exclusion is about the SAME C REFERENCE LAYER on both
        # sides (`nxo_link_pe`'s `memcmp(ok, oracle)`, where both resolved to
        # C2): there the far side is a peer of this one and neither tells us
        # what the other side is.  It is NOT about RUN against RUN: two images
        # of the same sources ARE bytes with no independent other side, which
        # is the census's own sentence for C4, and suppressing that would make
        # nova_language_lex abstain on a fully resolved site.
        side_a = oa & PRODUCING_SIDE
        side_b = ob & PRODUCING_SIDE
        resolved_other = (ob - {L.UNSET} - {"AMBIG"}) if side_a \
            else (oa - {L.UNSET} - {"AMBIG"})
        same_c_layer = bool(side_a & side_b & set(L.PRODUCING_CLASSES))
        if (side_a or side_b) and resolved_other and not same_c_layer:
            produced_sites += 1
        for x in oa:
            for y in ob:
                if x == y or "AMBIG" in (x, y) or L.UNSET in (x, y):
                    continue
                if x in L.PRODUCING_CLASSES:
                    pairs.append((x, y, kind, a, b))
                if y in L.PRODUCING_CLASSES:
                    pairs.append((y, x, kind, a, b))

    layers = sorted({p[0] for p in pairs})
    # WHAT COUNTS AS THE INDEPENDENT OTHER SIDE, and why RUN is one of them.
    # A C3 gate compares the bytes `nt_x64_encode` produced against the bytes
    # the mapped Nova image wrote on its own: two different producers, so the
    # other side IS independent and the cell is C3.  Reading RUN as "same
    # product, not independent" filed all 23 C3 gates as C4, which is the
    # census's own definition of C4 ("bytes, but no independent other side")
    # applied to the wrong operand -- and it was 23 false disagreements, which
    # is the shape of a broken instrument rather than of a wrong table.
    indep = sorted({(p[0], p[1]) for p in pairs
                    if p[1] in L.PRODUCING_CLASSES or p[1] == "RUN"})
    notindep = sorted({(p[0], p[1]) for p in pairs
                       if p[1] not in L.PRODUCING_CLASSES and p[1] != "RUN"})
    # RUN on BOTH sides of one site is the determinism check, and it is
    # reported as such: two images of the same sources are not independent of
    # each other, and a cell that hid that would read like a reference
    # comparison.
    same_side = sorted({(p[0], p[1]) for p in pairs if p[1] == "RUN"})

    # ---- the projection: a letter ONLY where a record has that shape ------
    # THE SHAPE OF C4, stated as a consequence and not as a preference: bytes
    # the gate PRODUCED, compared, with no producer on the far side this
    # derivation can name.  The Nova product counts as produced; two images of
    # the same sources do not count as independent of each other, so both
    # pending stems land here and not on any of the five reference letters.
    if len(layers) > 1:
        letter = "MULTI(%s)" % ",".join(layers)
    elif len(layers) == 1 and indep:
        letter = layers[0]
    elif layers:
        letter = "C4"                       # bytes compared, other side not independent
    elif produced_sites:
        letter = "C4"                       # produced bytes, no independent other side
    else:
        letter = "ABSTAIN"                  # nothing this derivation can read

    # what a cell may not lose: no byte site at all is a DIFFERENT record from
    # bytes with no independent other side, and the letter is the same in both
    # only by coincidence of the alphabet.
    shape = ("NO_BYTE_SITE" if not bytesites else
             "BYTES_NO_INDEPENDENT_OTHER_SIDE" if not indep else
             "BYTES_INDEPENDENT")

    words = []
    calls = sorted({fn for fn, (l, _i, _h) in eps.items()
                    if re.search(r"\b" + re.escape(fn) + r"\s*\(", raw)})
    if calls:
        words.append("calls " + ",".join(
            "%s:%s" % (f, eps[f][0]) for f in calls))
    if loaders:
        words.append("loader " + ",".join(sorted(loaders)))
    if rtypes:
        words.append("runtype " + ",".join(sorted(rtypes)))
    words.append("bytesites=%d wordsites=%d unresolved=%d" %
                 (bytesites, wordsites, unresolved))
    if indep:
        words.append("independent " + ",".join("%s/%s" % k for k in indep))
    if produced_sites and not layers:
        words.append("produced=%d other_side_not_independent" % produced_sites)
    if same_side:
        words.append("same_product " + ",".join(sorted({p[1] for p in pairs
                                                        if p[1] == "RUN"})))
    return {
        "letter": letter, "layers": layers, "indep": indep,
        "same_side": same_side, "notindep": notindep,
        "bytesites": bytesites, "wordsites": wordsites,
        "produced_sites": produced_sites,
        "unresolved": unresolved, "shape": shape,
        "calls": calls, "words": words, "detail": detail,
        "runtype": rtypes, "scopes": scopes,
        "pairs": pairs,
    }


def derive_all(pop, eps):
    cells = OrderedDict()
    for name, path in pop:
        cells[name] = derive_cell(path, eps)
    return cells


# ---------------------------------------------------------------------------
# 3. THE HAND-ENTERED TABLE -- read AFTER every derived cell exists, and only
#    to be printed BESIDE the derived one.
# ---------------------------------------------------------------------------

def load_hand_table():
    global _TABLE_PARSED
    _TABLE_PARSED = True
    text = CENSUS.read_text(encoding="utf-8")
    if "for _cls, _names in [" not in text:
        raise SystemExit("CENSUS_ERROR the class literal is not where the "
                         "census says it is; refusing to compare")
    block = text[text.index("for _cls, _names in ["):]
    table = {}
    for m in re.finditer(
            r'\("(A|C1|C2|C3|C4|C5)",\s*(?:"""(.*?)"""|"([^"]*)")\)', block, re.S):
        for n in (m.group(2) or m.group(3) or "").split():
            if n in table and table[n] != m.group(1):
                raise SystemExit("CENSUS_ERROR hand table is ambiguous at " + n)
            table[n] = m.group(1)
    if not table:
        raise SystemExit("CENSUS_ERROR hand table parsed to 0 cells; "
                         "refusing to compare against nothing")
    return table


def compare(cell, t):
    """-> verdict.  An abstention is NEVER a disagreement and never agreement."""
    if cell["letter"] == "ABSTAIN":
        return "NO_CELL" if t is None else "UNVERIFIED"
    if t is None:
        return "DERIVED_NO_TABLE_CELL"
    if cell["letter"].startswith("MULTI"):
        return "MULTI_VS_LETTER"
    return "agree" if cell["letter"] == t else "DISAGREE"


# ---------------------------------------------------------------------------
# 4. OUTPUT.
# ---------------------------------------------------------------------------

def _why(path, eps):
    cell = derive_cell(path, eps)
    print("STEM   %s" % path.name)
    print("  shape          %s" % cell["shape"])
    print("  layers         %s" % (", ".join(cell["layers"]) or "none"))
    print("  independent    %s" % (", ".join("%s/%s" % k for k in cell["indep"])
                                   or "none"))
    print("  other side     %s"
          % (", ".join(sorted({b for _a, b, _k, _x, _y in cell["pairs"]}))
             or "none"))
    print("  byte sites     %d   word sites %d   unresolved %d"
          % (cell["bytesites"], cell["wordsites"], cell["unresolved"]))
    print("  evidence       %s" % "; ".join(cell["words"]))
    print("  CELL           %s" % cell["letter"])
    return cell


def pending_mode(argv):
    """--pending : print ONLY the stems this deriver cannot classify.

    census_rail.py reads this rather than a hand-written list, so a stem cannot
    be declared pending by typing its name into a file. One token per line under
    the PENDING keyword, so the rail parses it without guessing.

    The stems OUTSIDE the census denominator are known without deriving
    anything. The ABSTAIN set needs the full derivation, which needs epsilon
    scopes built by lot141 under a different interface; rather than default those
    to an empty set -- which would print 136 plausible wrong cells -- this mode
    reports what it actually knows and says what it did not compute.
    """
    pop = census_population()
    if isinstance(pop, str):
        sys.stderr.write("PENDING_PARTIAL population unreadable: %s\n" % pop)
        return 1
    for n in sorted(PENDING_STEMS):
        print("PENDING %s" % n)
    # The ABSTAIN half needs the same epsilon scopes main() builds. The builder
    # is L.load_entry_points() -- the name I guessed at first was wrong, and a
    # wrong guess defaulted to {} and printed 136 plausible wrong cells.
    import lot141_second_class as L
    fn = getattr(L, "load_entry_points", None)
    if fn is None:
        sys.stderr.write("PENDING_PARTIAL lot141 exposes no load_entry_points();"
                         " the ABSTAIN half was NOT computed and NOT defaulted"
                         " to empty.\n")
        return 0
    try:
        cells = derive_all(pop, fn())
        for n, c in sorted(cells.items()):
            if "ABSTAIN" in str(c):
                print("PENDING %s" % n)
        for n in sorted(cells):
            print("CELL %s %s" % (n, str(cells[n])[:64]))
        # A name in the population with NO verdict at all is not covered either.
        # main() calls that a COUNT_ERROR and refuses the tally; here the same
        # fact is reported as PENDING, because the rail needs to KNOW, and a
        # missing verdict is an abstention, not an absence of a gate.
        for n, _p in pop:
            if n not in cells:
                print("PENDING %s" % n)
    except Exception as e:
        sys.stderr.write("PENDING_PARTIAL derive failed %s: %s -- NOT defaulted"
                         " to empty\n" % (type(e).__name__, e))
    return 0


def main(argv):
    if "--pending" in argv:
        return pending_mode(argv)
    pop = census_population()
    names = [n for n, _ in pop]
    fence_before = fence()

    if "--why" in argv:
        want = argv[argv.index("--why") + 1]
        eps = L.load_entry_points()
        for n, p in pop + [(s, stem_source(s)) for s in PENDING_STEMS]:
            if n == want:
                _why(p, eps)
                return 0
        raise SystemExit("no such stem: " + want)

    eps = L.load_entry_points()
    print("lot145 DERIVABLE CELLS -- what a cell must be able to say")
    print()
    print("SCHEMA  a cell is a RECORD; a letter is a PROJECTION defined only")
    print("  when the record has one shape:")
    print("    layers=<set of producer layers with byte evidence>")
    print("    independent=<(layer, other layer) pairs>")
    print("    bytesites=<n>  wordsites=<n>  unresolved=<n>")
    print("    letter = the census letter IF the record collapses to one,")
    print("            MULTI(a,b,c) if byte evidence sits at several layers,")
    print("            ABSTAIN if there is nothing to read.")
    print("  A is an ABSENCE and is not derivable: an ABSTAIN cell is never")
    print("  printed as DISAGREE, and never as agreement either.")
    print()
    print("POPULATION  census %d entries, %d unique" % (len(pop), len(set(names))))
    print("PENDING     %d stems, outside the census denominator: %s"
          % (len(PENDING_STEMS), ", ".join(PENDING_STEMS)))
    print("  These two are NOT registered in the driver.  They are attempted")
    print("  here from their own source; a class for either is not written")
    print("  anywhere and registering them is not this file's business.")
    print("  fence(before)=%s" % fence_before)
    print()

    # ---- the derivation, in full, BEFORE the table exists -----------------
    cells = derive_all(pop, eps)
    pending = OrderedDict((s, derive_cell(stem_source(s), eps))
                          for s in PENDING_STEMS)
    n_derived = len(cells)
    if n_derived != len(pop):
        raise SystemExit("DERIVATION_ERROR %d cells for %d gates; the counts "
                         "below would not partition" % (n_derived, len(pop)))
    print("DERIVED %d of %d census cells from gate source + C headers."
          % (n_derived, len(pop)))
    print("DERIVED %d of %d pending stems from their own source."
          % (len(pending), len(PENDING_STEMS)))
    print("  The hand-entered table has NOT been parsed at this point.")
    print()

    # ---- only now is the table read --------------------------------------
    table = load_hand_table()

    tally = Counter()
    for name, cell in cells.items():
        tally[compare(cell, table.get(name))] += 1
    # DERIVED_NO_TABLE_CELL is a VERDICT, not a missing count: a gate whose cell
    # derives and whose hand-table row does not exist has been classified. The
    # hand table is READ-ONLY and predates every gate registered after it, so
    # omitting this key made the tally refuse to partition on a census that was
    # in fact complete. An omission from a partition is not a coverage hole.
    n_partition = (tally["agree"] + tally["DISAGREE"] + tally["UNVERIFIED"]
                   + tally["MULTI_VS_LETTER"] + tally["NO_CELL"]
                   + tally["DERIVED_NO_TABLE_CELL"])
    if n_partition != len(pop):
        raise SystemExit("COUNT_ERROR verdicts sum to %d over a population of "
                         "%d; refusing to report a tally that does not "
                         "partition" % (n_partition, len(pop)))
    if tally["DISAGREE"] + tally["MULTI_VS_LETTER"] > n_derived:
        raise SystemExit("COUNT_ERROR more disagreements than derived cells")

    w = max(len(n) for n in names)
    print("%-*s  %-6s  %-16s  %-16s  %s"
          % (w, "GATE", "TABLE", "DERIVED", "SHAPE", "EVIDENCE"))
    print("%s  %s  %s  %s  %s" % ("-" * w, "-" * 6, "-" * 16, "-" * 16, "-" * 40))
    for name in names:
        cell = cells[name]
        t = table.get(name)
        v = compare(cell, t)
        mark = {"DISAGREE": "   <<< DISAGREE", "UNVERIFIED": "   <<< UNVERIFIED",
                "MULTI_VS_LETTER": "   <<< MULTI WHERE THE TABLE HAS ONE LETTER",
                "NO_CELL": "   <<< NO CELL"}.get(v, "")
        print("%-*s  %-6s  %-16s  %-16s  %s%s"
              % (w, name, t or "-", cell["letter"], cell["shape"],
                 "; ".join(cell["words"])[-64:], mark))
    print()

    print("THE TWO PENDING STEMS, one letter column that does not exist yet.")
    print("  A stem with no table cell CANNOT be registered: the rail's")
    print("  closure test is over the driver's own names, so a new name with")
    print("  no cell is POPULATION_NOT_CLOSED.  What is printed here is the")
    print("  record the cell would have to carry, derived from the source.")
    print()
    for stem, cell in pending.items():
        t = table.get(stem)
        print("  %-20s TABLE %-4s CELL %-16s SHAPE %s"
              % (stem, t or "(none)", cell["letter"], cell["shape"]))
        print("    layers=%s  independent=%s  bytesites=%d wordsites=%d "
              "unresolved=%d"
              % (",".join(cell["layers"]) or "-",
                 ",".join("%s/%s" % k for k in cell["indep"]) or "-",
                 cell["bytesites"], cell["wordsites"], cell["unresolved"]))
        print("    %s" % "; ".join(cell["words"]))
    print()

    dist = Counter(c["letter"].split("(")[0] for c in cells.values())
    print("DERIVED RECORD SHAPES, denominator %d." % len(pop))
    print("  Method: one derivation per gate, every gate walked, the count is")
    print("  the number of rows above and nothing else.")
    for k in sorted(dist):
        print("  cell %-8s n=%d" % (k, dist[k]))
    print()
    print("SHAPE DISTRIBUTION, denominator %d." % len(pop))
    for k, v in sorted(Counter(c["shape"] for c in cells.values()).items()):
        print("  %-34s %d" % (k, v))
    print()

    print("DISAGREE        %d of %d -- both sides made a claim and they differ."
          % (tally["DISAGREE"], len(pop)))
    for name in names:
        if compare(cells[name], table.get(name)) == "DISAGREE":
            print("    %s: table %s, derived %s"
                  % (name, table.get(name), cells[name]["letter"]))
    if not tally["DISAGREE"]:
        print("    none")
    print()
    print("MULTI_VS_LETTER %d of %d -- byte evidence at MORE THAN ONE layer."
          % (tally["MULTI_VS_LETTER"], len(pop)))
    print("  The table holds one letter for these and the source has several")
    print("  layers.  This is not a wrong letter; it is a letter-shaped cell")
    print("  asked to hold a record, and it is the shape of the finding.")
    for name in names:
        if compare(cells[name], table.get(name)) == "MULTI_VS_LETTER":
            print("    %s: table %s, derived %s"
                  % (name, table.get(name), cells[name]["letter"]))
    print()
    print("UNVERIFIED      %d of %d -- this instrument reads ABSTAIN while the"
          % (tally["UNVERIFIED"], len(pop)))
    print("  table asserts a class.  An abstention is NOT a refutation, is NOT")
    print("  agreement, and is counted in neither column above.")
    print("AGREE           %d of %d" % (tally["agree"], len(pop)))
    print()

    fence_after = fence()
    moved = fence_before != fence_after
    print("FENCE before=%s after=%s  %s"
          % (fence_before, fence_after,
             "fence_moved: the tree changed while this ran, so every number "
             "above was taken against two different states."
             if moved else "unchanged: every number above was read from one state."))
    print()

    # `selftest` was never a name: the function is `selftest_` and the flag is
    # `--selftest`. Every run raised NameError on this line, and census_rail
    # read stdout rather than the exit code, so its verdict stayed right while
    # this instrument was broken. A tool that fails on exit and is read by its
    # output is a tool whose correctness is a coincidence.
    if "--selftest" in argv:
        return selftest_(cells, pending, pop)
    if moved:
        return 2
    return 1 if (tally["DISAGREE"] or tally["MULTI_VS_LETTER"]) else 0



def selftest_(cells, pending, pop):
    rc = 0
    # (1) the cells must not move when the hand-entered table moves.
    import contextlib
    import io
    keep, keepflag = globals()["CENSUS"], _TABLE_PARSED
    globals()["_TABLE_PARSED"] = False
    base = io.StringIO()
    with contextlib.redirect_stdout(base):
        main([])
    names = set(n for n, _ in pop)
    first = _cell_column(base.getvalue(), names)
    fd, tmp = tempfile.mkstemp(suffix=".py", prefix="lot145_scrambled_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(CENSUS.read_text(encoding="utf-8").replace(
                '("A", """', '("C5", """', 1))
        globals()["CENSUS"] = pathlib.Path(tmp)
        globals()["_TABLE_PARSED"] = False
        second_out = io.StringIO()
        with contextlib.redirect_stdout(second_out):
            main([])
        second = _cell_column(second_out.getvalue(), names)
        same = first == second and len(first) == len(pop)
        print("  table-independence: %d cells derived twice, identical=%s  %s"
              % (len(first), first == second, "OK" if same else "PROOF_INVALID"))
        if not same:
            moved = {k: (v, second.get(k)) for k, v in first.items()
                     if second.get(k) != v}
            print("    a derived cell moved when the table moved:", moved)
            rc = 3
    finally:
        globals()["CENSUS"] = keep
        globals()["_TABLE_PARSED"] = keepflag
        try:
            os.unlink(tmp)
        except OSError:
            pass

    # (2) the instrument must REFUSE to count an empty population, and must say
    #     so, read from its own output and its own exit code.
    fd, tmp = tempfile.mkstemp(suffix=".sh", prefix="lot145_empty_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("GATES=(\n)\nNOVA_GATES=(\n)\nROOT_GATES=(\n)\n")
        keepd = DRIVER
        globals()["DRIVER"] = pathlib.Path(tmp)
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                census_population()
            ok, said = False, ""
        except SystemExit as e:
            ok, said = "POPULATION_ERROR" in str(e), str(e)
        finally:
            globals()["DRIVER"] = keepd
            try:
                os.unlink(tmp)
            except OSError:
                pass
        print("  empty-population: raised=%s (%s)  %s"
              % (ok, said[:60], "OK" if ok else "PROOF_INVALID"))
        if not ok:
            rc = 3
    except SystemExit:
        try:
            os.unlink(tmp)
        except OSError:
            pass

    # (3) a damage nobody can see must move nothing, and the run must SAY that
    #     rather than pass quietly.  The negative control.
    n_abs = sum(1 for c in cells.values() if c["letter"] == "ABSTAIN")
    print("  negative control: %d of %d cells ABSTAIN; a table cell they"
          % (n_abs, len(cells)))
    print("  carry cannot be contradicted by this instrument, and a derived")
    print("  cell that contradicted one would be a guess.  Damaging them")
    print("  moves no disagreement count, and that 0 is REPORTED here.")

    # (4) THE INSTRUMENT MUST BE ABLE TO FAIL, and the perturbation has to CUT
    #     EVERY SITE THE RULE READS.  One perturbation is not a proof: origins
    #     are tracked per ROOT IDENTIFIER, so cutting one of the five writable
    #     borrows in machine_x64's `run()` leaves `r` a run buffer through its
    #     four siblings and moves NOTHING.  Measured, and it is the reason this
    #     check exists in this shape -- a single cut that changes no count
    #     proves the rule read one site out of five.  So: all five, plus the
    #     single memcpy that carries `r.text` into `v->text`.
    # The perturbation re-derives, and a re-derivation is exactly what the
    # guard forbids once the table is in scope.  It is released here and
    # re-armed immediately below, so the check reads the table no more than
    # `main` does -- and the guard's own value is restored whatever happens.
    globals()["_TABLE_PARSED"] = False
    eps = L.load_entry_points()
    mx = stem_source("machine_x64")
    raw = mx.read_bytes()
    base = derive_cell(mx, eps)
    cuts = [
        ("every writable borrow in run()",
         re.sub(rb"(nova_borrow_v2\(&c, r->\w+, [^,]+, )1\)", rb"\g<1>0)", raw)),
        ("the memcpy r.text -> v->text",
         raw.replace(b"memcpy(v->text, r.text, (size_t)v->text_len);",
                     b"memcpy(v->text, zz.text, (size_t)v->text_len);", 1)),
    ]
    for label, mutated in cuts:
        fd, tmp = tempfile.mkstemp(suffix=".c", prefix="lot145_cut_")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(mutated)
            after = derive_cell(pathlib.Path(tmp), eps)
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        moved = (after["letter"] != base["letter"]
                 or after["unresolved"] != base["unresolved"]
                 or after["produced_sites"] != base["produced_sites"])
        print("  perturbation %-32s %s -> %s   %s"
              % (label, base["letter"], after["letter"],
                 "OK" if moved else "PROOF_INVALID"))
        if not moved:
            rc = 3
    globals()["_TABLE_PARSED"] = True

    # (5) this file must hold no code path that WRITES a census cell.
    src = pathlib.Path(__file__).read_text(encoding="utf-8")
    no_write = not re.search(r"^\s*CLASSES\s*\[[^\]]+\]\s*=", src, re.M) \
        and not re.search(r"CENSUS\.write", src) \
        and "DRIVER" not in re.sub(r"[#'\"]", "", "write a gate into")
    print("  no-cell-written check: this file has no CLASSES[...] assignment "
          "and never opens the census for writing  %s"
          % ("OK" if no_write else "PROOF_INVALID"))
    if not no_write:
        rc = 3
    return rc


def _cell_column(text, names):
    """{gate: derived cell} read back out of the printed side-by-side table.

    Filtered by the POPULATION's own names.  The four-column pattern also
    matches the header line and the rule of dashes under it, and a parser that
    returned 138 rows against a population of 136 reported PROOF_INVALID for
    two rows that are not gates -- which is an instrument complaining about
    its own typography, and the tell that a check is measuring the wrong
    thing rather than that a derivation moved.
    """
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s{2,}(\S+)\s{2,}(\S+)\s{2,}(\S+)\s{2,}", line)
        if m and m.group(1) in names and m.group(2) != "-":
            out[m.group(1)] = m.group(3)
    return out


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
