#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""lot141_second_class.py -- A SECOND, INDEPENDENTLY COMPUTED CLASSIFICATION.

WHAT THIS IS
============
The census at out/c-bootstrap/nova/W26Exposure/derive_population.py prints a
class for every cold-proof gate out of a HAND-ENTERED LITERAL, then digests
that literal.  A digest answers "did the claim change?".  It cannot answer
"is the claim right?", and the census file says so about itself: one cell is
known false, and "1 error in 124 is a FLOOR, not a rate".

This file computes the classification a SECOND time, from the only thing a
classifier may legitimately read -- the gate's OWN SOURCE, and the C headers
that declare the producers it calls -- and prints the two classifications
BESIDE each other with the disagreements visible.

THE ORDERING IS THE ARGUMENT
===========================
`classify_gate()` cannot read the hand-entered table, and that is not a
promise, it is the control flow: main() runs every classification to
completion and stores the results in `derived` BEFORE `load_hand_table()` is
ever called.  The table is parsed after the last derived cell exists, and
`classify_gate` does not take it as an argument, does not close over it, and
does not touch the module global that holds it.  A second opinion that reads
the first opinion is not a second opinion; this one is not given the means.

WHERE A CLASS COMES FROM
========================
Nothing here is a list of gate names.  Every class is the consequence of a
relation between two operands at a comparison site in the gate's own text.

  ORIGIN          derived from
  --------------  ------------------------------------------------------------
  C1 / C2 / C3    a call to an entry point DECLARED in a C header whose
                  signature gives it a non-const aggregate out-parameter.  The
                  header that declares the entry point is the layer, and it is
                  read out of the header rather than chosen.  See OUT_PARAM.
  C5              a call to an entry point declared in nova/pe_oracle.h or
                  nova/pe_layout_oracle.h, by the same rule.
  RUN             a buffer lent to the mapped Nova image by
                  nova_borrow_v2(..., buffer, n, 1) -- the fourth argument is
                  the writer flag, so this is read off the call, not assumed.
                  Also every value of a typedef'd struct that declares a
                  `uint8_t out[..]` member: that is the Run carrier these
                  harnesses use, read out of the declaration.
  GOLDEN          the result of a loader DEFINED IN THIS GATE, identified as a
                  function whose own body opens a file (fopen) and reads it
                  (fread).  Not a list of loader names.
  BYTES           a variable declared `uint8_t x[..]` here, or a `.bytes` /
                  `.data` member access: the gate is comparing octets, not
                  words.  This is what keeps a status-word comparison out of
                  the byte classes.

A COMPARISON SITE is a memcmp/bcmp, or an elementwise comparison of two
subscripted operands (`a[k] != b[j]`).  The second form is why byte gates
that contain no memcmp at all are visible here.

A variable may carry SEVERAL origins.  When a site pairs two variables and
more than one layer assignment is possible, that site yields nothing: the
instrument abstains rather than picking.  Where a whole gate's sites point at
two different classes, it emits `no_evidence`, not a coin toss.

THE CLASS, and the abstention
=============================
  C1 (frontend.h, codegen.h)          vs an independent side  ->  C1
  C2 (object.h, pe.h, ntasm.h,
      pe_layout.h, conformance.h, cli.h) vs an independent side ->  C2
  C3 (x64.h)                          vs an independent side  ->  C3
  C5 (the oracle headers)             vs an independent side  ->  C5
  a BYTE comparison, other side not independent              ->  C4
  anything else, or conflicting evidence                     ->  no_evidence

`no_evidence` is a VALUE, printed in the class column: never a blank, never a
copy of the hand-entered cell.  `A` is an ABSENCE over a comparison
vocabulary nobody has enumerated, so it is not derivable and this instrument
does not pretend to derive it; every `A` cell in the table reads `no_evidence`
here.  Those are reported as UNVERIFIED, separately from DISAGREE: a
disagreement says the two sides differ, an abstention says only that this side
has nothing to say, and collapsing the two would be the dishonest move.

WHAT THIS DOES NOT DO
====================
It does not repair the table, decide what any gate really is, close the
census, or register anything.  It prints a number.

Run:
    python legacy/tools/coldproof/lot141_second_class.py
    python legacy/tools/coldproof/lot141_second_class.py --selftest
"""

import hashlib
import os
import pathlib
import re
import sys
from collections import Counter, OrderedDict

ROOT = pathlib.Path(__file__).resolve().parents[2]
DRIVER = ROOT / "tools" / "coldproof" / "ngbuild.sh"
C = ROOT / "bootstrap" / "quarantine" / "c"
NOVA = C / "nova"
CENSUS = ROOT / "out" / "c-bootstrap" / "nova" / "W26Exposure" / "derive_population.py"

# A header is a layer by its own name.  Nothing below lists a gate.
LAYER_OF_HEADER = {
    "frontend.h": "C1",
    "codegen.h": "C1",
    "object.h": "C2",
    "pe.h": "C2",
    "ntasm.h": "C2",
    "pe_layout.h": "C2",
    "conformance.h": "C2",
    "cli.h": "C2",
    "x64.h": "C3",
    "pe_oracle.h": "C5",
    "pe_layout_oracle.h": "C5",
}

UNSET = "UNSET"
_TABLE_PARSED = False
PRODUCING_CLASSES = ("C1", "C2", "C3", "C5")
ANY_ORIGIN = ("C1", "C2", "C3", "C5", "RUN", "GOLDEN", "LITERAL", "LOCAL")


# ---------------------------------------------------------------------------
# 0. POPULATION.  Transcribed from the driver's own arrays, not imported from
#    the census, so a divergence between the two is a visible disagreement
#    rather than a silent behaviour change.  The rule is the census's: NAME=(
#    at column 0, then the shortest run of characters to the FIRST ')' in the
#    file, then split on whitespace.
# ---------------------------------------------------------------------------

def population():
    text = DRIVER.read_text(encoding="utf-8")
    pop = []
    for name, pathf in (
        ("GATES", lambda n: NOVA / ("tests_ntasm_%s.c" % n)),
        ("NOVA_GATES", lambda n: NOVA / (n + ".c")),
        ("ROOT_GATES", lambda n: C / n),
    ):
        m = re.search(r"^" + name + r"=\((.*?)\)", text, re.S | re.M)
        if not m:
            raise SystemExit("array not found in driver: " + name)
        for tok in m.group(1).split():
            pop.append((tok, pathf(tok)))
    return pop


# ---------------------------------------------------------------------------
# 1. THE C ENTRY POINTS, READ OUT OF THE HEADERS.
# ---------------------------------------------------------------------------

DECL_RE = re.compile(
    r"^[ \t]*(?!return\b)(?:static\s+|extern\s+|inline\s+)*"
    r"[A-Za-z_][A-Za-z0-9_]*(?:\s*\*)*\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\(([^;{}]*)\)\s*;",
    re.M,
)

AGGREGATE_RE = re.compile(r"^(?:const\s+)?([A-Z][A-Za-z0-9_]*)\s*$")

KEYWORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "do", "else", "case",
    "typedef", "struct", "union", "enum", "static", "inline", "extern",
    "CHECK", "RUN", "main", "printf", "fprintf", "memcpy", "memset",
    "malloc", "calloc", "realloc", "free", "strcpy", "strcmp", "strlen",
    "fopen", "fclose", "fread", "fwrite", "fseek", "ftell", "exit", "abort",
}


def split_params(s):
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return [p.strip() for p in out if p.strip()]


def call_args(text, open_paren):
    """Argument strings of the call whose '(' is at open_paren."""
    depth, j = 1, open_paren + 1
    while j < len(text) and depth:
        if text[j] == "(":
            depth += 1
        elif text[j] == ")":
            depth -= 1
        j += 1
    return split_params(text[open_paren + 1:j - 1])


def out_param_index(param):
    """Index of the non-const aggregate pointer parameter, or None.

    DERIVED, not typed.  An out-parameter is a pointer whose pointed-to type
    is (a) not const-qualified -- a const pointer is an input by the type
    system, (b) not void, and (c) an aggregate, i.e. a capitalised struct
    family name.  A function is a PRODUCER when it returns a status code
    rather than void and has such a parameter.  That is what separates
    nt_frontend_compile, which fills a caller-owned NtFProgram, from
    nt_frontend_free, which returns void, and from nt_frontend_type_name,
    which has no pointer parameter at all.  The destructors and the lookups
    fall out of the signature; none of them is on a list.
    """
    p = " ".join(param.split())
    if "*" not in p:
        return None
    head = p.split("*")[0].strip()
    if "const" in head.split():
        return None
    tail = p.split("*", 1)[1]
    if "(" in tail or "[" in tail:          # pointer-to-function, array decay
        return None
    base = head.split()[-1] if head else ""
    if not AGGREGATE_RE.match(base):
        return None
    return base


def load_entry_points():
    """{entry point: (class, out_param_index, declaring header)}."""
    eps = {}
    headers = sorted(C.glob("*.h")) + sorted(NOVA.glob("*oracle.h"))
    for h in headers:
        layer = LAYER_OF_HEADER.get(h.name)
        if layer is None:
            continue
        txt = h.read_text(encoding="utf-8", errors="replace")
        for m in DECL_RE.finditer(txt):
            fn, params = m.group(1), m.group(2)
            if not (fn.startswith("nt_") or fn.startswith("nova_oracle_")):
                continue
            line_start = txt.rfind("\n", 0, m.start()) + 1
            ret = txt[line_start:m.start(1)].strip()
            ret = re.sub(r"\b(static|extern|inline)\b", " ", ret).strip()
            ret = ret.rstrip("*").strip()
            if not ret or ret == "void":
                continue                        # a destructor, not a producer
            idx = None
            for i, p in enumerate(split_params(params)):
                if out_param_index(p) is not None:
                    idx = i
                    break
            if idx is None:
                continue                        # a lookup, not a producer
            eps.setdefault(fn, (layer, idx, h.name))
    return eps


# ---------------------------------------------------------------------------
# 2. GATE TEXT.  Comments and string literals are removed before anything is
#    read, so a path in a string can never be mistaken for a comparison and a
#    sentence in a comment can never taint a variable.
# ---------------------------------------------------------------------------

def strip_noise(src):
    src = re.sub(r"/\*.*?\*/", " ", src, flags=re.S)
    src = re.sub(r"//[^\n]*", " ", src)
    src = re.sub(r'"(\\.|[^"\\])*"', ' "S" ', src)
    src = re.sub(r"'(\\.|[^'\\])*'", " 'C' ", src)
    return src


IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# A subscripted expression: base identifier, then a member chain, then `[...]`.
SUB_RE = re.compile(
    r"([A-Za-z_][A-Za-z0-9_]*)"
    r"((?:\s*(?:\.|->)\s*[A-Za-z_][A-Za-z0-9_]*)*)"
    r"\s*\[[^\[\]]*\]")


def root_of(expr):
    """The base identifier of a C expression, ignoring & * [ ] . and ->."""
    e = re.sub(r"^[&*(\s]+", "", expr)
    e = re.sub(r"\[[^\]]*\](\s*\[[^\]]*\])*", "", e)   # a[i][j]
    e = re.sub(r"(\.|->)[A-Za-z_][A-Za-z0-9_]*", "", e)  # x.bytes  x->out
    m = IDENT_RE.search(e)
    return m.group(0) if m else None


FUNCDEF_RE = re.compile(
    r"(?:^|[};)\n])[ \t]*"
    r"(?P<pre>(?:[A-Za-z_][A-Za-z0-9_]*[ \t]+)*[* \t]*)"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
    r"[ \t]*\((?P<params>[^;{}]*)\)[ \t]*\{")


def function_defs(text):
    """[(name, return type, parameter list, body)] for functions DEFINED here.

    Every definition is taken with its own brace-matched body, because an
    identifier's origin is a property of the SCOPE it is written in.  The
    first version of this file kept one file-wide identifier table, and
    `image` in stub_table is an NtCodeImage filled by nt_codegen_x64 in one
    function and a NovaOraclePeImage filled by nova_oracle_make_pe in
    another; the file-wide table made it AMBIG and the gate fell out of the
    byte classes for a reason that had nothing to do with the gate.
    """
    out = []
    for m in FUNCDEF_RE.finditer(text):
        name = m.group("name")
        if name in KEYWORDS:
            continue
        i = text.index("{", m.end() - 1)
        depth, j = 0, i
        while j < len(text):
            if text[j] == "{":
                depth += 1
            elif text[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((name, m.group("pre").strip(),
                     m.group("params"), text[i:j]))
    return out


def run_typedefs(text):
    """Typedef'd structs carrying a run's output: `uint8_t out[..]`.

    DERIVED, not typed.  A harness that wants a run's bytes declares a struct
    to carry them; the member and the element width are read out of the
    declaration.  A gate with no such typedef gets no RUN origin, and if that
    was its only byte it reads `no_evidence`.  That is the honest answer, and
    it is why a large minority of the population abstains.
    """
    types = {}
    for m in re.finditer(r"typedef\s+struct\s*\{(.*?)\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
                         text, re.S):
        members = set(re.findall(r"uint8_t\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[", m.group(1)))
        if members:
            types[m.group(2)] = members
    return types

COPY_RE = re.compile(
    r"^[\s&*]*([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s*(?:\.|->)\s*[A-Za-z_][A-Za-z0-9_]*|\s*\[[^\]]*\])*[\s]*$")

ASSIGN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]{1,400});")
MEMCPY_RE = re.compile(r"\bmemcpy\s*\(\s*([^,]+?)\s*,\s*([^,]+?)\s*,")
FREAD_RE = re.compile(r"\bfread\s*\(\s*([^,]+?)\s*,")
FACTORY_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")


def scope_origins(scope, eps, ev):
    """Origins inside one scope (a function body, or the file's top level).

    Returns (origins, vartype).  `scope` is a block of text.
    """
    origins, vartype = {}, {}

    def add(name, origin):
        if not name:
            return
        s = origins.setdefault(name, set())
        if origin in s:
            return
        if s:
            s.add("AMBIG")          # two layers claim these bytes
        else:
            s.add(origin)

    # 1. calls that write through a declared out-parameter
    for fn, (layer, idx, _hdr) in sorted(eps.items()):
        for m in re.finditer(r"\b" + re.escape(fn) + r"\s*\(", scope):
            if m.start() and (scope[m.start() - 1].isalnum()
                              or scope[m.start() - 1] == "_"):
                continue
            args = call_args(scope, scope.index("(", m.end() - 1))
            if idx >= len(args):
                continue
            add(root_of(args[idx]), layer)

    # 2. buffers lent to the mapped Nova image -- the 4th argument IS the
    #    writer flag, so this is read off the call rather than assumed
    for m in re.finditer(r"\bnova_borrow_v2\s*\(", scope):
        args = call_args(scope, scope.index("(", m.end() - 1))
        if len(args) >= 4 and args[3].strip().rstrip(")") in ("1", "true", "writable"):
            r = root_of(args[1])
            if r:
                origins.setdefault(r, set()).add("RUN")

    # 3. bytes read off disk into a buffer
    for m in FREAD_RE.finditer(scope):
        r = root_of(m.group(1))
        if r:
            origins.setdefault(r, set()).add("GOLDEN")

    # 4. identifiers: `const char *` is a name, not bytes
    for m in re.finditer(r"\bconst\s+char\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)", scope):
        origins.setdefault(m.group(1), set()).add("NAME")

    # 5. Run carriers, by the typedef that declares them
    for m in ASSIGN_RE.finditer(scope):
        lhs = m.group(1)
        # The window ENDS where the identifier begins, so the pattern has to
        # match a trailing type token, not `TYPE name =` -- the name is not in
        # the window.  Matching `TYPE name =` here finds nothing, which is
        # why every Run carrier in the population went unbound until this was
        # read back off a failing gate rather than off the source.
        head = scope[max(0, m.start() - 80):m.start()]
        ty = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\**\s*$", head)
        if ty and ty.group(1) in ev["run_types"]:
            origins.setdefault(lhs, set()).add("RUN")
            vartype[lhs] = ty.group(1)

    # 6. propagate, COPY ONLY, to a fixpoint
    for _ in range(8):
        grew = False
        for m in ASSIGN_RE.finditer(scope):
            lhs, rhs = m.group(1), " ".join(m.group(2).split())
            if lhs in origins:
                continue
            cm = MEMCPY_RE.match(rhs)
            src = root_of(cm.group(2)) if cm else None
            if not src:
                c = COPY_RE.match(rhs)
                if c:
                    src = c.group(1)
            if not src or src == lhs:
                continue
            have = origins.get(src)
            if have and len(have) == 1:
                origins[lhs] = set(have)
                grew = True
        for m in MEMCPY_RE.finditer(scope):
            dst, src = root_of(m.group(1)), root_of(m.group(2))
            if not dst or dst == src or dst in origins:
                continue
            have = origins.get(src)
            if have and len(have) == 1:
                origins[dst] = set(have)
                grew = True
        if not grew:
            break
    return origins, vartype

def why(path, eps):
    """The evidence for one gate, in full: every site, both operands, both
    origins.  `--why <gate>` prints this and exits.  It is how a disagreement
    above is told apart from a defect in this instrument, and it is the only
    way to find out which one a given row is."""
    ev = collect_evidence(path, eps)
    print("GATE  %s" % path.name)
    print("  calls      %s" % (", ".join("%s=%s" % kv for kv in
                                          sorted(ev["producers"].items())) or "none"))
    print("  run types  %s" % (", ".join(sorted(ev["run_types"])) or "none"))
    print("  loaders    %s" % (", ".join(sorted(ev["loosen"])) or "none"))
    print("  scopes")
    for sname, o, _vt, _txt in ev["scopes"]:
        interesting = {k: v for k, v in o.items()
                       if v & {"C1", "C2", "C3", "C5", "RUN", "GOLDEN", "LOCAL"}}
        if interesting:
            print("    %-24s %s" % (sname, "; ".join(
                "%s=%s" % (k, ",".join(sorted(v))) for k, v in
                sorted(interesting.items()))))
    print("  sites  n=%d" % len(ev["sites"]))
    for kind, a, b, is_byte, o in ev["sites"]:
        oa = ",".join(sorted(o.get(a, {UNSET}))) if a else "LITERAL"
        ob = ",".join(sorted(o.get(b, {UNSET}))) if b else "LITERAL"
        print("      %-8s %-16s %-14s vs %-16s %-14s"
              % (kind, a, oa, b, ob))
    return classify_gate(path, eps)



def _scope_text(defs, blanked, sname, which=0):
    """The text of one scope.  `which` matters: two static helpers in one gate
    may share a name, and looking a scope up by name alone silently scans the
    first one twice and never the second.  That is how the memcmp at
    stub_table:1984 -- the one the census sentence cites -- went missing from
    a site list that otherwise looked healthy."""
    if sname == "<file>":
        return blanked
    hits = [b for n, _r, _p, b in defs if n == sname]
    return hits[which] if which < len(hits) else ""


def collect_evidence(path, eps):
    text = strip_noise(path.read_bytes().decode("utf-8", errors="replace"))
    defs = function_defs(text)
    ev = {
        "origins": {},                 # flattened, for reporting only
        "bytes": set(),
        "sites": [],                   # (kind, a, b, is_byte, scope origins)
        "run_types": run_typedefs(text),
        "loosen": [n for n, _r, _p, b in defs if "fopen" in b and "fread" in b],
    }
    blanked = text
    for _n, _r, _p, body in defs:
        blanked = blanked.replace(body, " " * len(body))

    # -- a gate-local helper that RETURNS a producer's bytes is a factory ----
    # c_stub_body() in stub_table returns a pointer into an NtCodeImage filled
    # by nt_codegen_x64; the caller of c_stub_body() holds C1 bytes and has no
    # way to know it.  The factory edge is local to the gate and is derived:
    # the function must return a POINTER, and every producer-layer origin it
    # returns must be the same single layer.
    fac = {}
    for name, ret, _p, body in defs:
        if "*" not in ret:
            continue
        o, _vt = scope_origins(body, eps, ev)
        got = set()
        for m in re.finditer(r"\breturn\b([^;]*);", body):
            for ident in IDENT_RE.findall(m.group(1)):
                got |= {x for x in o.get(ident, ()) if x in PRODUCING_CLASSES}
        if len(got) == 1:
            fac[name] = got.pop()
    ev["producers"] = OrderedDict(
        (fn, layer) for fn, (layer, _i, _h) in sorted(eps.items())
        if re.search(r"\b" + re.escape(fn) + r"\s*\(", text))

    scopes = [("<file>",) + scope_origins(blanked, eps, ev) + (blanked,)]
    for name, _ret, _params, body in defs:
        o, vt = scope_origins(body, eps, ev)
        for m in FACTORY_RE.finditer(body):
            lhs, callee = m.group(1), m.group(2)
            if callee in ev["loosen"] and lhs not in o:
                o[lhs] = {"GOLDEN"}
            elif callee in fac and lhs not in o:
                o[lhs] = {fac[callee]}
        scopes.append((name, o, vt, body))
    for _n, o, _vt, _txt in scopes:
        for m in FACTORY_RE.finditer(_txt):
            lhs, callee = m.group(1), m.group(2)
            if callee in fac and lhs not in o:
                o[lhs] = {fac[callee]}
    # -- parameter flow, inside this gate only ------------------------------
    # A helper's `uint8_t *pe` parameter is the Nova product because the
    # helper LENDS it to the host image, and the caller's local `pe` is that
    # same buffer because the caller passed it in.  The edge runs both ways:
    # argument -> parameter (the ordinary direction) and parameter -> argument
    # (the direction that carries a callee's writability back to the caller's
    # malloc'd buffer).  Without the second direction the memcmp at
    # stub_table:1984 -- Nova .text against nt_codegen_x64, the comparison the
    # census sentence cites -- has an unresolved left operand.
    # POINTER parameters only.  A by-value parameter cannot carry a buffer,
    # and letting it try taints sizes: without this guard `size_t n` in a
    # helper bound `n=C1` in every caller, which is a number being a
    # reference.  An unnamed parameter yields no name at all.
    TYPEISH = {"void", "char", "short", "int", "long", "float", "double",
               "unsigned", "signed", "const", "struct", "union", "size_t",
               "ssize_t", "ptrdiff_t", "uintptr_t", "intptr_t"}
    param_names = {}
    for name, _ret, params, _body in defs:
        # ONE SLOT PER PARAMETER, in order.  Dropping the non-pointer ones
        # from the list instead of leaving a hole shifts every later index and
        # binds each argument to the wrong parameter -- which is what happened,
        # and it silently unbound every buffer in the gate.
        names = []
        for pp in split_params(params):
            names.append(None)
            if "*" not in pp:
                continue
            mm = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", pp.replace("*", " * "))
            if mm and mm.group(1) not in KEYWORDS \
                    and mm.group(1) not in TYPEISH and not mm.group(1).endswith("_t"):
                names[-1] = mm.group(1)
        if any(names):
            param_names.setdefault(name, names)
    by_name = {}
    for sname, o, vt, txt in scopes:
        by_name.setdefault(sname, []).append((o, vt, txt))

    BUFFERISH = set(PRODUCING_CLASSES) | {"RUN", "GOLDEN", "LOCAL"}

    def callee_param_origin(fname, index):
        for o, _vt, _txt in by_name.get(fname, []):
            names = param_names.get(fname) or []
            if index < len(names) and names[index] and names[index] in o:
                got = set(o[names[index]]) & BUFFERISH
                if len(got) == 1 and UNSET not in got:
                    return got
        return None

    for _ in range(6):
        grew = False
        # forward: a caller's argument tells the callee's parameter
        for sname, o, _vt, txt in scopes:
            for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", txt):
                fname = m.group(1)
                if fname not in param_names:
                    continue
                args = call_args(txt, txt.index("(", m.end() - 1))
                for i, a in enumerate(args):
                    for po, _v, _t in by_name.get(fname, []):
                        names = param_names[fname]
                        if i >= len(names) or not names[i] or names[i] in po:
                            continue
                        have = o.get(root_of(a) or "", set()) & BUFFERISH
                        if len(have) == 1 and UNSET not in have:
                            po[names[i]] = set(have)
                            grew = True
        # backward: a callee's writability reaches the caller's buffer
        for sname, o, _vt, txt in scopes:
            for m in re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", txt):
                fname = m.group(1)
                if fname not in param_names:
                    continue
                args = call_args(txt, txt.index("(", m.end() - 1))
                for i, a in enumerate(args):
                    root = root_of(a) or ""
                    if not root or root in o:
                        continue
                    got = callee_param_origin(fname, i)
                    if got:
                        o[root] = set(got)
                        grew = True
        if not grew:
            break
    ev["scopes"] = scopes

    # -- a byte array the gate DECLARES and WRITES is its own other side ---
    global_bytes = set(re.findall(r"\b(?:static\s+)?uint8_t\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[",
                                  blanked))
    ev["bytes"] |= set(re.findall(r"\bNtBuffer\s+([A-Za-z_][A-Za-z0-9_]*)", text))
    ev["bytes"] |= set(re.findall(r"(\.|->)\s*(bytes|data)\b", text))
    for sname, o, _vt, scope in scopes:
        local = set(re.findall(
            r"\b(?:static\s+)?uint8_t\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[", scope))
        local |= set(re.findall(r"\bNtBuffer\s+([A-Za-z_][A-Za-z0-9_]*)", scope))
        ev["bytes"] |= local
        for name in sorted(local | global_bytes):
            if name in o:
                continue
            written = (re.search(r"\b" + re.escape(name) + r"\s*\[[^\]]*\]\s*=(?!=)", scope)
                       or re.search(r"\b" + re.escape(name) + r"\s*\+\s*[A-Za-z0-9_]", scope)
                       or re.search(r"memcpy\s*\(\s*" + re.escape(name) + r"\b", scope))
            if written:
                o[name] = {"LOCAL"}

    # -- comparison sites, per scope ---------------------------------------
    for sname, o, vt, scope in scopes:
        for m in re.finditer(r"\bmem(cmp|bcmp)\s*\(", scope):
            args = call_args(scope, scope.index("(", m.end() - 1))
            if len(args) >= 2:
                ev["sites"].append(("memcmp", root_of(args[0]), root_of(args[1]),
                                    True, o))
        for stmt in scope.split(";"):
            subs = []
            for m in SUB_RE.finditer(stmt):
                root, chain = m.group(1), m.group(2)
                members = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", chain)
                is_byte = ("bytes" in members or "data" in members
                           or root in ev["bytes"]
                           or any(mm in ev["run_types"].get(vt.get(root, ""), ())
                                  for mm in members))
                if is_byte and root not in subs:
                    subs.append(root)
            for i, a in enumerate(subs):
                for b in subs[i + 1:]:
                    ev["sites"].append(("element", a, b, True, o))
    for _n, o, _vt, _txt in scopes:
        for k, v in o.items():
            ev["origins"].setdefault(k, set()).update(v)
    return ev


# ---------------------------------------------------------------------------
# 4. THE CLASS, from the evidence alone.  It is handed a PATH.
# ---------------------------------------------------------------------------

def classify_gate(path, eps):
    """-> (class, [evidence words]).  It cannot see a table: it is not passed
    one, and by the time it runs the table has not been parsed.

    The second half of that is not a promise, it is a runtime guard: if the
    hand-entered table has been parsed even once, this raises rather than
    returning a class derived with one eye on it."""
    if _TABLE_PARSED:
        raise SystemExit("REFUSING TO CLASSIFY: the hand-entered table is "
                         "already in scope.  A second opinion that has read "
                         "the first one is not a second opinion.")
    ev = collect_evidence(path, eps)
    words = []
    if ev["producers"]:
        words.append("calls " + ",".join("%s:%s" % (f, l)
                                         for f, l in sorted(ev["producers"].items())))
    if ev["loosen"]:
        words.append("loader " + ",".join(sorted(ev["loosen"])))
    if ev["run_types"]:
        words.append("runtype " + ",".join(sorted(ev["run_types"])))

    def origins(o, r):
        if r is None:
            return {"LITERAL"}
        return o.get(r, {UNSET})

    found, sides = set(), set()
    byte_sites = other_sites = unresolved = produced_sites = 0
    for kind, a, b, is_byte, o in ev["sites"]:
        if kind != "memcmp" and not is_byte:
            other_sites += 1
            continue
        byte_sites += 1
        oa, ob = origins(o, a), origins(o, b)
        if "NAME" in oa or "NAME" in ob:
            continue          # a substring test against an identifier
        # "produced" means a side the gate generated: a C-layer producer's
        # output, or bytes the Nova product wrote.  A memcmp between two
        # strings the gate loaded off disk is not byte evidence about the
        # product at all, and filing it C4 would be counting the gate's
        # fixture plumbing as its evidence.
        if (oa & set(PRODUCING_CLASSES) or ob & set(PRODUCING_CLASSES)
                or "RUN" in oa or "RUN" in ob):
            produced_sites += 1
        if UNSET in oa or UNSET in ob:
            unresolved += 1
        for x in oa:
            for y in ob:
                if x == y or "AMBIG" in (x, y) or UNSET in (x, y):
                    continue
                if x in PRODUCING_CLASSES and y in ANY_ORIGIN:
                    found.add(x)
                    sides.add(y)
                elif y in PRODUCING_CLASSES and x in ANY_ORIGIN:
                    found.add(y)
                    sides.add(x)

    words.append("bytesites=%d produced=%d unresolved=%d"
                 % (byte_sites, produced_sites, unresolved))
    if len(found) == 1:
        cls = found.pop()
        if sides == {"LITERAL"}:
            words.append("other side is a hand-typed literal")
        return cls, words
    if len(found) > 1:
        # Byte evidence at MORE THAN ONE layer.  This is a value, not an
        # abstention: the gate demonstrably confronts a producer with an
        # independent other side, which is exactly what class A denies.  The
        # single letter is undecidable, and the instrument says so instead of
        # printing no_evidence, which would read beside an A cell as agreement.
        return "CONFLICT", words + ["byte evidence at " + ",".join(sorted(found))]
    if unresolved:
        # A byte comparison whose other side this instrument cannot resolve.
        # Filing that C4 would be guessing, and C4 is a claim, not a shrug.
        return "no_evidence", words + ["byte site with an unresolved side"]
    if produced_sites:
        return "C4", words + ["produces and compares bytes, other side is not independent"]
    if byte_sites:
        return "no_evidence", words + ["byte comparisons, but no side the gate produced"]
    return "no_evidence", words + ["no byte site"]


# ---------------------------------------------------------------------------
# 5. THE HAND-ENTERED TABLE -- read AFTER every cell is derived, and only to
#    be printed beside the derived one.
# ---------------------------------------------------------------------------

def load_hand_table():
    global _TABLE_PARSED
    _TABLE_PARSED = True
    text = CENSUS.read_text(encoding="utf-8")
    block = text[text.index("for _cls, _names in ["):]
    table = {}
    for m in re.finditer(
            r'\("(A|C1|C2|C3|C4|C5)",\s*(?:"""(.*?)"""|"([^"]*)")\)', block, re.S):
        for n in (m.group(2) or m.group(3) or "").split():
            if n in table and table[n] != m.group(1):
                raise SystemExit("hand table is ambiguous at " + n)
            table[n] = m.group(1)
    return table


# ---------------------------------------------------------------------------
# 6. OUTPUT.
# ---------------------------------------------------------------------------

def population_lines():
    text = DRIVER.read_text(encoding="utf-8")
    out = []
    for name in ("GATES", "NOVA_GATES", "ROOT_GATES"):
        m = re.search(r"^" + name + r"=\((.*?)\)", text, re.S | re.M)
        if m:
            toks = m.group(1).split()
            out.append("  %-11s %3d entries, %3d unique"
                       % (name, len(toks), len(set(toks))))
    return out


def main(argv):
    selftest = "--selftest" in argv
    pop = population()
    names = [n for n, _ in pop]
    if not pop:
        print("POPULATION 0 entries.")
        print("REFUSING TO PRINT A VERDICT ON AN EMPTY POPULATION.")
        print("  0 gates is not a result.  An instrument that renders 0 because")
        print("  it has not looked is the defect this project keeps paying for.")
        return 2
    missing = [n for n, p in pop if not p.is_file()]
    if missing:
        print("POPULATION is not closed; %d source(s) absent: %s"
              % (len(missing), ", ".join(missing[:8])))
        return 2
    if "--why" in argv:
        want = argv[argv.index("--why") + 1]
        eps_why = load_entry_points()
        for n, p in pop:
            if n == want:
                cls, words = why(p, eps_why)
                print("  DERIVED %s   (%s)" % (cls, "; ".join(words)))
                return 0
        raise SystemExit("no such gate: " + want)

    eps = load_entry_points()
    print("lot141 second classification -- INDEPENDENT of the census table")
    print()
    print("POPULATION  %d entries, %d unique" % (len(pop), len(set(names))))
    for l in population_lines():
        print(l)
    print("  driver sha256=%s"
          % hashlib.sha256(DRIVER.read_bytes()).hexdigest()[:16])
    print()
    print("ENTRY POINTS read from the C headers: %d producers, in %d layers"
          % (len(eps), len(set(l for l, _, _ in eps.values()))))
    for layer in sorted(set(l for l, _, _ in eps.values())):
        fns = sorted(f for f, (l, _, _) in eps.items() if l == layer)
        print("  %-3s n=%-3d %s" % (layer, len(fns), " ".join(fns)))
    print()

    # ---- the derivation, in full, before the table exists ----------------
    derived = OrderedDict((n, classify_gate(p, eps)) for n, p in pop)
    print("DERIVED %d of %d cells from gate source + C headers."
          % (len(derived), len(pop)))
    print("  The hand-entered table has NOT been parsed at this point; the")
    print("  derivation above is what it will be compared against.")
    print()

    # ---- only now is the table read ---------------------------------------
    table = load_hand_table()

    disagree, unver, agree = [], [], []
    rows = []
    for n in names:
        d, words = derived[n]
        t = table.get(n, "-")
        if d == "no_evidence":
            verdict = "NO_CELL" if t == "-" else "UNVERIFIED"
            if t != "-":
                unver.append(n)
        elif d == t:
            verdict = "agree"
            agree.append(n)
        else:
            verdict = "DISAGREE"
            disagree.append((n, t, d))
        rows.append((n, t, d, verdict, "; ".join(words)))

    w = max(len(r[0]) for r in rows)
    print("%-*s  %-6s  %-11s  %s" % (w, "GATE", "TABLE", "DERIVED", "EVIDENCE"))
    print("%s  %s  %s  %s" % ("-" * w, "-" * 6, "-" * 11, "-" * 58))
    for n, t, d, verdict, words in rows:
        if verdict == "DISAGREE":
            mark = "   <<< DISAGREE"
        elif verdict == "UNVERIFIED":
            mark = "   <<< UNVERIFIED"
        elif verdict == "NO_CELL":
            mark = "   <<< NO CELL IN THE TABLE"
        else:
            mark = ""
        print("%-*s  %-6s  %-11s  %s%s" % (w, n, t, d, words[:88], mark))
    print()

    # -- what evidence EXISTS per gate, before any class is assigned ---------
    shape = Counter()
    for _n, (_cls, words) in derived.items():
        w = " ".join(words)
        prod = int(re.search(r"produced=(\d+)", w).group(1))
        byt = int(re.search(r"bytesites=(\d+)", w).group(1))
        if prod:
            shape["byte-level evidence (a produced side is compared)"] += 1
        elif byt:
            shape["byte comparisons, none on a produced side"] += 1
        else:
            shape["no byte site at all (word/status assertions)"] += 1
    print("WHAT EVIDENCE EXISTS PER GATE, denominator %d.  Counted from the"
          % len(pop))
    print("  derivation's own per-gate site tallies, one row per gate:")
    for k in sorted(shape):
        print("  %-46s %d" % (k, shape[k]))
    print("  The middle row is gates whose memcmps are fixture plumbing -- two")
    print("  strings the gate loaded, neither of them anything it produced.")
    print("  The bottom row is where `A` lives, and it is an absence: a gate")
    print("  with no byte site may be asserting verdicts correctly for reasons")
    print("  this instrument cannot see.")
    print()

    dist = Counter(v[0] for v in derived.values())
    print("EVIDENCE DISTRIBUTION, denominator %d gates." % len(pop))
    print("  Method: one derivation per gate, every gate walked, the count is")
    print("  the number of rows above and nothing else.")
    for k in sorted(dist):
        print("  derived %-12s n=%d" % (k, dist[k]))
    print()

    print("DISAGREE   %d of %d -- both sides made a claim and they differ."
          % (len(disagree), len(pop)))
    for n, t, d in disagree:
        print("    %s: table %s, derived %s" % (n, t, d))
    if not disagree:
        print("    none")
    print()
    print("AGREE      %d of %d" % (len(agree), len(pop)))
    print("UNVERIFIED %d of %d -- this instrument emits no_evidence while the"
          % (len(unver), len(pop)))
    print("  table asserts a class.  An abstention is NOT a refutation and is")
    print("  not counted as a disagreement above.")
    for n in unver:
        print("    %s: table %s, derived no_evidence" % (n, table[n]))
    print()

    # -- the disagreement count, decomposed, because an undifferentiated
    #    number is a number nobody can act on ---------------------------
    kinds = Counter()
    for n, t, d in disagree:
        if t == "A":
            kinds["A denies an independent other side; bytes say otherwise"] += 1
        elif {t, d} == {"C1", "C2"} or d == "CONFLICT" or t == "CONFLICT":
            kinds["C1/C2 boundary or multi-layer evidence"] += 1
        else:
            kinds["other letter against other letter"] += 1
    print("DISAGREE, decomposed, denominator %d of %d:" % (len(disagree), len(pop)))
    for k, v in kinds.most_common():
        print("  %-52s %d" % (k, v))
    print("  A single number here would be one number for three different")
    print("  arguments.  Only the first kind is a claim that a table cell is")
    print("  wrong about its own bytes; the second is a difference of")
    print("  DEFINITION about which layer counts as the other side.")
    print()

    if selftest:
        return selftest_(derived, disagree)
    if disagree:
        # A disagreement exits non-zero, for the reason the census file gives:
        # printing one and exiting 0 makes it a line nobody reads.
        return 1
    print("REFUSING TO REPORT 0 DISAGREEMENTS AS `ALL GOOD`.")
    print("  0 disagreements is only a result if every gate was classified by")
    print("  something other than abstention, and %d of %d were not."
          % (len(unver), len(pop)))
    print("  An instrument that renders 0 because it has not looked is the")
    print("  defect this project keeps paying for.  Exit 2, not 0.")
    return 2


# ---------------------------------------------------------------------------
# 7. THE SELF-TEST.  It damages a COPY of the hand-entered table and requires
#    the instrument to report MORE disagreements, and to say by how many.  A
#    perturbation that changes nothing is PROOF_INVALID and exits 3.
# ---------------------------------------------------------------------------

DAMAGE = {"A": "C5", "C1": "A", "C2": "A", "C3": "A", "C4": "C1", "C5": "A"}


def damage_table(table, derived, k):
    """Choose k cells whose damage this instrument would SEE.  A cell it
    abstains on cannot be damaged into a disagreement, and saying so is the
    point of the test rather than a way around it."""
    victims = []
    for n in sorted(table):
        d = derived[n][0] if n in derived else "no_evidence"
        if d == "no_evidence":
            continue                    # an abstention cannot be contradicted
        if d != table.get(n):
            continue                    # already disagreeing: damage is a no-op
        if DAMAGE.get(table[n]) == d:
            continue                    # this damage is invisible by construction
        victims.append(n)
    return victims[:k]


def selftest_(derived, disagree):
    base_table = load_hand_table()
    base = len(disagree)
    print("SELFTEST -- a damaged COPY of the hand-entered table, in memory.")
    print("  The file on disk is never written; this process opens it read-only.")
    for k in (1, 3, 7, 15):
        victims = damage_table(base_table, derived, k)
        dmg = dict(base_table)
        for v in victims:
            dmg[v] = DAMAGE[dmg[v]]
        n_dis = n_unv = 0
        for name, (d, _w) in derived.items():
            t = dmg.get(name, "-")
            if d == "no_evidence":
                n_unv += 1 if t != "-" else 0
            elif d != t:
                n_dis += 1
        delta = n_dis - base
        expected = sum(1 for v in victims if derived[v][0] != "no_evidence")
        ok = (delta == expected and n_dis > base)
        print("  damaged %2d cell(s) %-42s disagreements %d -> %d (+%d), "
              "predicted +%d   %s"
              % (len(victims),
                 "(" + ",".join(victims[:3]) + (",..." if len(victims) > 3 else "")
                 + ")", base, n_dis, delta, expected,
                 "OK" if ok else "PROOF_INVALID"))
        if not ok:
            return 3
    # and the negative control: a damage nobody can see must move nothing,
    # and the run must say so rather than pass quietly.
    invisible = [n for n in sorted(base_table)
                 if derived.get(n, ("no_evidence",))[0] == "no_evidence"
                 and base_table.get(n, "-") != "-"][:5]
    if invisible:
        print("  negative control: %d abstained cell(s) (%s...) carry a table"
              % (len(invisible), ", ".join(invisible[:3])))
        print("  class that this instrument cannot contradict.  Damaging them")
        print("  moves the disagreement count by 0, and that 0 is REPORTED,")
        print("  not hidden and not counted as agreement.")
    rc = 0
    rc = table_independence_check() or rc
    rc = empty_population_check() or rc
    print("  PROOF VALID: the instrument's ability to fail is demonstrated.")
    return rc


def _derived_column(text):
    """{gate: derived class} parsed back out of the side-by-side table."""
    out = {}
    for line in text.splitlines():
        m = re.match(r"^(\S+)\s{2,}(A|C1|C2|C3|C4|C5|-)\s{2,}"
                     r"(\S+)\s{2,}", line)
        if m:
            out[m.group(1)] = m.group(3)
    return out


def table_independence_check():
    """Derive twice, once against the real census file and once against a
    SCRAMBLED copy of it, and require the derived column to be identical.

    This is the mechanical form of "the second classification does not read
    the first".  If any derived cell moved when the table moved, the
    instrument was reading it.  The scrambled copy is written outside the
    repository and deleted; the real census file is opened read-only.
    """
    import contextlib
    import io
    import tempfile
    global CENSUS, _TABLE_PARSED
    keep_c, keep_flag = CENSUS, _TABLE_PARSED
    # A nested run re-derives from scratch, so the guard has to be released
    # first; it is re-armed by load_hand_table inside that run exactly as it
    # would be in a fresh process.
    _TABLE_PARSED = False
    base = io.StringIO()
    with contextlib.redirect_stdout(base):
        main([])
    first = _derived_column(base.getvalue())
    fd, tmp = tempfile.mkstemp(suffix=".py", prefix="lot141_scrambled_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(open(CENSUS, encoding="utf-8").read().replace(
                '("A", """', '("C5", """', 1))
        CENSUS, _TABLE_PARSED = pathlib.Path(tmp), False
        second_out = io.StringIO()
        with contextlib.redirect_stdout(second_out):
            main([])
        second = _derived_column(second_out.getvalue())
        same = (first == second and len(first) == len(pop_check_count()))
        print("  table-independence check: %d cells derived twice, identical=%s"
              % (len(first), first == second))
        if not same:
            print("    PROOF_INVALID: a derived cell moved when the table moved.")
            print("    first  :", {k: v for k, v in first.items()
                                     if second.get(k) != v})
            print("    second :", {k: v for k, v in second.items()
                                     if first.get(k) != v})
            return 3
        return 0
    finally:
        CENSUS, _TABLE_PARSED = keep_c, keep_flag
        try:
            os.unlink(tmp)
        except OSError:
            pass


def pop_check_count():
    return population()


def empty_population_check():
    """The instrument must REFUSE to print a verdict on an empty population.

    Proven by pointing it at a driver whose three arrays are empty and
    reading the exit code, not by asserting that the code contains the word
    REFUSING.  The temporary driver is written outside the repository and
    removed; nothing in the tree is touched.
    """
    import contextlib
    import io
    import tempfile
    global DRIVER
    keep = DRIVER
    fd, tmp = tempfile.mkstemp(suffix=".sh", prefix="lot141_empty_")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("GATES=(\n)\nNOVA_GATES=(\n)\nROOT_GATES=(\n)\n")
        DRIVER = pathlib.Path(tmp)
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = main([])
        said = buf.getvalue()
        ok = (rc == 2 and "REFUSING" in said and "POPULATION 0" in said)
        print("  empty-population check: exit=%d, output says REFUSING=%s  %s"
              % (rc, "REFUSING" in said, "OK" if ok else "PROOF_INVALID"))
        if not ok:
            return 3
        return 0
    finally:
        DRIVER = keep
        try:
            os.unlink(tmp)
        except OSError:
            pass


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
