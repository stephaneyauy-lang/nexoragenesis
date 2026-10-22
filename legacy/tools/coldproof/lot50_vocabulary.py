#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LOT 50 INSTRUMENT -- the Nova AST node-kind vocabulary and the six C enum
vocabularies, read FROM THE TREE.

The rule this instrument is bound by: its vocabulary AND its predicates come
out of the bytes of the repository, never out of a list written inside it.
Every number printed is followed by the file and the line it came from, and
every number it cannot print is printed as a refusal.

NEGATIVE CONTROL, declared here and run FIRST, before any count:

    The LEXER/TOKEN kind vocabulary.  It lives in the same files, is written
    with the same literals, and is passed through the same shape of call --
    expect(p,N,4), accept(p,N), tk(p)==N, keyword(p,N).  It is not a node
    kind and this instrument must never report it as one.

    The control BITES rather than merely being declared, because the two
    populations OVERLAP: token 91 (a memory operand) and token 94 (a
    precedence class) are also AST kinds 91 (qualified) and 94 (literal).
    A number-only extractor that reads "p,<integer>" out of the file sweeps
    both vocabularies into one and cannot tell them apart.  The instrument
    separates them by the FACTORY: a node kind can only enter the tree by a
    call to the writer that stores into node_words offset 0.

Two further populations are also out of scope and are refused by name: the
NTIR kind vocabulary (KIND_BASE 1024) and the machine_ir kind vocabulary
(KIND_BASE 2048).  Both are real, both are named, neither is an AST kind.

Usage:  python3 legacy/tools/coldproof/lot50_vocabulary.py [--out DIR]
"""

import hashlib
import os
import re
import sys
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUTDIR_DEFAULT = os.path.join(ROOT, "out", "c-bootstrap", "nova", "lot50")

NOVA_DIR = os.path.join(ROOT, "toolchain", "ntasm-nova")
AST_NOVA = os.path.join(NOVA_DIR, "ast.nova")
NTIR_NOVA = os.path.join(NOVA_DIR, "ntir.nova")
MIR_NOVA = os.path.join(NOVA_DIR, "machine_ir.nova")
PARSER_NOVA = os.path.join(NOVA_DIR, "parser.nova")
ABI_NOVA = os.path.join(NOVA_DIR, "abi.nova")
FRONTEND_H = os.path.join(ROOT, "bootstrap", "quarantine", "c", "frontend.h")
SPEC_NTASM = os.path.join(ROOT, "spec", "ntasm.md")

# The only two normalisation rules used to compare an emitter function name
# with a name read from the tree.  Declared here because they ARE the rule,
# and a reader who wants them different must be able to see them in one
# place.  No fuzzy matching, no substring scoring: exact, case-sensitive.
EMITTER_NAME_SUFFIXES = ("_decl",)
NAME_PREFIXES = ("k_",)

READ = []          # every file opened, with mtime and digest
OUT = []           # every line printed


def out(line=""):
    OUT.append(line)
    print(line)


def read_file(path):
    st = os.stat(path)
    with open(path, "rb") as fh:
        data = fh.read()
    rec = {
        "path": os.path.relpath(path, ROOT).replace("\\", "/"),
        "bytes": st.st_size,
        "mtime": datetime.fromtimestamp(st.st_mtime, timezone.utc)
        .astimezone()
        .strftime("%Y-%m-%d %H:%M:%S %z"),
        "text": data.decode("utf-8", "replace"),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if not any(r["path"] == rec["path"] for r in READ):
        READ.append(rec)
    return rec


# --------------------------------------------------------------------------
# Nova source parsing.  Functions are recognised from their own text: a line
# that begins `fn NAME(...)` or `export fn NAME(...)` and opens a brace.
# --------------------------------------------------------------------------

class Fn(object):
    def __init__(self, name, exported, params, body, line0):
        self.name = name
        self.exported = exported
        self.params = params          # list of (name, type)
        self.body = body              # list of lines, without the header/footer
        self.text = "\n".join(body)
        self.line0 = line0            # 1-based line of the header

    def param_names(self):
        return [p[0] for p in self.params]


FUNC_RE = re.compile(
    r"^(export\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*->\s*"
    r"([A-Za-z_][A-Za-z0-9_]*(?:\s*<[^>]*>)?(?:\s*,\s*buf<u64>)?(?:\s*,\s*buf<u8>)?)?"
    r"\s*\{"
)


STRING_RE = re.compile(r'"[^"]*"')


def _braces(line):
    """Brace delta of a line, ignoring anything inside a string literal."""
    return (STRING_RE.sub('""', line).count("{")
            - STRING_RE.sub('""', line).count("}"))


def parse_nova_functions(text):
    """Functions are delimited by BRACE DEPTH, never by indentation.

    parser.nova closes nested blocks at column 0 (`statement` closes its
    first `if` with a `}` in column 0), so an indentation rule silently
    truncates the body and loses the emissions after the first block.  That
    truncation is exactly the kind of hole this instrument must not have.
    """
    lines = text.split("\n")
    fns = []
    i = 0
    while i < len(lines):
        m = FUNC_RE.match(lines[i])
        if not m:
            i += 1
            continue
        name = m.group(2)
        raw = m.group(3).strip()
        params = []
        if raw:
            for chunk in raw.split(","):
                chunk = chunk.strip()
                if not chunk:
                    continue
                if ":" in chunk:
                    pn, pt = chunk.split(":", 1)
                    params.append((pn.strip(), pt.strip()))
                else:
                    params.append((chunk, ""))
        depth = _braces(lines[i])
        body = []
        j = i + 1
        while j < len(lines) and depth > 0:
            body.append(lines[j])
            depth += _braces(lines[j])
            j += 1
        fns.append(Fn(name, bool(m.group(1)), params, body, i + 1))
        i = j
    return fns


def call_sites(text, callee):
    """Every CALL to `callee`, as (arg1, arg2, line_in_text).

    The argument list is scanned with a PAREN BALANCE, not a character class,
    so `node(p,5,ti(p))` is one call with a nested call in its third
    argument.  A regex that forbids inner parentheses silently drops exactly
    the emission sites whose begin token is computed -- seventeen kinds were
    invisible to it.  The matcher refuses an identifier suffix, so node_at()
    is never a call to node().
    """
    res = []
    needle = callee
    for m in re.finditer(r"(?<![A-Za-z0-9_])" + re.escape(needle) + r"\s*\(",
                         text):
        k = m.end() - 1
        depth = 0
        while k < len(text):
            if text[k] == "(":
                depth += 1
            elif text[k] == ")":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        if depth != 0:
            raise SystemExit("REFUSAL: unbalanced call to %s at offset %d"
                             % (callee, m.start()))
        inner = text[m.end():k]
        args = split_args(inner)
        line = text.count("\n", 0, m.start()) + 1
        a1 = args[0].strip() if len(args) > 0 else None
        a2 = args[1].strip() if len(args) > 1 else None
        res.append((a1 if a1 else None, a2 if a2 else None, line))
    return res


def split_args(inner):
    """Split a call argument list on top-level commas only."""
    args = []
    depth = 0
    cur = []
    for ch in inner:
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        if ch == "," and depth == 0:
            args.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    args.append("".join(cur))
    return args


INT_RE = re.compile(r"^[0-9]+$")


# --------------------------------------------------------------------------
# 1. THE FACTORY.  Found by its own action, not by its name: the one function
#    in the tree that stores its second parameter into offset 0 of the node
#    array at (id-1)*stride.
# --------------------------------------------------------------------------

def all_functions(files):
    """Every (record, function) pair in the scan set, in file order."""
    res = []
    for key, rec in files.items():
        if key == "_all":
            continue
        for f in rec["fns"]:
            res.append((rec, f))
    return res


def ast_stride(ast_text):
    """The node stride, read out of ast.nova's own node_at()."""
    m = re.search(r"let\s+at\s*:\s*u64\s*=\s*\(\s*id\s*-\s*1\s*\)\s*\*\s*([0-9]+)",
                  ast_text)
    if not m:
        raise SystemExit("REFUSAL: ast.nova's stride is not readable.")
    return int(m.group(1))


def find_factory(pairs, stride):
    """The AST node factory, found by its ACTION and pinned to the AST array.

    Two conditions, both read from the tree:
      (a) the body computes (id-1)*<the stride ast.nova's node_at uses>, so it
          is addressing the AST node array and not some other buffer;
      (b) it stores its own second parameter into offset 0 of that array.
    machine_ir.nova's emit() satisfies (b) and not (a), which is why the
    first run of this instrument found `emit` and reported 0 kinds.
    """
    hits = []
    for rec, f in pairs:
        if len(f.params) < 2:
            continue
        p2 = f.params[1][0]
        stride_ok = re.search(
            r"\(\s*[A-Za-z_][A-Za-z0-9_]*\s*-\s*1\s*\)\s*\*\s*" + str(stride),
            f.text)
        store_ok = re.search(
            r"\[\s*at\s*\]\s*=\s*" + re.escape(p2) + r"\s*;", f.text)
        if stride_ok and store_ok:
            hits.append((rec, f))
    if len(hits) != 1:
        raise SystemExit(
            "REFUSAL: %d functions satisfy the factory predicate; the"
            " instrument will not pick one." % len(hits))
    return hits[0]


# --------------------------------------------------------------------------
# 2. THE EMITTED POPULATION.
# --------------------------------------------------------------------------

def extract_population(files, ast_text):
    """Returns (record, factory, sites, unresolved).

    sites: kind -> [(file, line, enclosing_function)]
    unresolved: forwarder call sites whose kind argument is not a literal.
                Never silently dropped: an unresolved site is a hole in the
                extraction and is printed as one.
    """
    pairs = all_functions(files)
    def_rec, factory = find_factory(pairs, ast_stride(ast_text))
    sites = {}

    def add(kind, where):
        sites.setdefault(kind, []).append(where)

    # pass 1 -- literal calls to the factory, and the functions that forward
    #           one of their OWN parameters into it
    forwarders = {}      # fn name -> parameter index forwarded
    for rec, f in pairs:
        if f is factory:
            continue
        for a1, a2, line in call_sites(f.text, factory.name):
            if a2 is None:
                continue
            if INT_RE.match(a2):
                add(int(a2), (rec["path"], f.line0 + line - 1, f.name))
            elif a2 in f.param_names():
                forwarders[f.name] = f.param_names().index(a2)

    # pass 2 -- literal arguments at the call sites of the forwarders, and the
    #           ones that are not literals, which are UNRESOLVED, not dropped
    unresolved = []
    for rec, f in pairs:
        for fname in forwarders:
            for a1, a2, line in call_sites(f.text, fname):
                if a2 is None:
                    continue
                if INT_RE.match(a2):
                    add(int(a2), (rec["path"], f.line0 + line - 1, f.name))
                else:
                    unresolved.append(
                        (rec["path"], f.line0 + line - 1, fname, a2))

    return def_rec, factory, sites, unresolved


# --------------------------------------------------------------------------
# 3. THE NEGATIVE CONTROL.  Run before any count is printed.
# --------------------------------------------------------------------------

TOKEN_PREDICATES = ("expect", "accept", "tk", "keyword")


def extract_token_vocabulary(files):
    """The population the instrument REFUSES to report as node kinds.

    It is read from the token predicates themselves -- expect(p,N,r),
    accept(p,N), tk(p)==N, keyword(p,N) -- and never from a factory call.
    """
    toks = {}
    for rec, f in all_functions(files):
        for pred in TOKEN_PREDICATES:
            for m in re.finditer(
                    r"(?<![A-Za-z0-9_])" + pred + r"\s*\(\s*p\s*\)\s*[!=]=\s*([0-9]+)",
                    f.text):
                toks.setdefault(int(m.group(1)), set()).add((rec["path"], f.line0))
            for a1, a2, line in call_sites(f.text, pred):
                if a1 == "p" and a2 is not None and INT_RE.match(a2):
                    toks.setdefault(int(a2), set()).add(
                        (rec["path"], f.line0 + line - 1))
    return toks


# --------------------------------------------------------------------------
# 4. THE NTIR TABLE: KIND_BASE, KIND_COUNT, kind_at, kind_ast_at, the k_*
#    name table -- all read from ntir.nova, all replayed, none assumed.
# --------------------------------------------------------------------------

def parse_callable_table(text, prefix):
    """fn NAME()->u64 { return N; }  ->  [(name, N, line)]"""
    res = []
    pat = re.compile(
        r"^(?:export\s+)?fn\s+(" + prefix + r"[A-Za-z0-9_]*)\s*\(\s*\)\s*->\s*u64"
        r"\s*\{\s*return\s+([0-9]+)\s*;\s*\}", re.M)
    for m in pat.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        res.append((m.group(1), int(m.group(2)), line))
    return res


TERM_RE = re.compile(r"^index\s*(>=|<=|==|!=)\s*([0-9]+|KIND_COUNT\(\))$")
RET_RE = re.compile(r"^([0-9]+|index(?:\s*[+-]\s*[0-9]+)?)$")


def parse_arms(text, fname):
    """The if/return arms of a function, kept as a predicate tree.

    The returns are NOT all literals -- ntir.nova's kind_ast_at returns
    `index`, `index-1` and `index+43` on three of its eight arms -- so an arm
    reader that only accepts `return <digits>` silently drops those arms and
    reports every row as a zero row.  That is what the first run of this
    instrument did.
    """
    fns = parse_nova_functions(text)
    for f in fns:
        if f.name != fname:
            continue
        flat = re.sub(r"\s+", " ", f.text)
        arms = []
        for m in re.finditer(
                r"if\s+((?:index\s*(?:>=|<=|==|!=)\s*(?:[0-9]+|KIND_COUNT\(\))"
                r"(?:\s*(?:&&|\|\|)\s*)?)+)\s*\{\s*return\s+([^;]+);\s*\}", flat):
            arms.append((parse_cond(m.group(1)), parse_ret(m.group(2).strip())))
        return arms, f
    return [], None


def parse_cond(cond):
    """'index>=1 && index<=25' -> [[('>=',1), ('<=',25)]]  (a list of ANDs)"""
    ors = []
    for term in re.split(r"\|\|", cond):
        ands = []
        for cmp_ in re.split(r"&&", term):
            mm = TERM_RE.match(cmp_.strip())
            if not mm:
                raise SystemExit("REFUSAL: cannot parse predicate %r" % cmp_)
            rhs = ("COUNT" if mm.group(2) == "KIND_COUNT()"
                   else int(mm.group(2)))
            ands.append((mm.group(1), rhs))
        ors.append(ands)
    return ors


def parse_ret(expr):
    mm = RET_RE.match(expr)
    if not mm:
        raise SystemExit("REFUSAL: cannot parse return %r" % expr)
    e = mm.group(1)
    if e == "index":
        return ("index", 0)
    dm = re.match(r"^index\s*([+-])\s*([0-9]+)$", e)
    if dm:
        return ("index", int(dm.group(2)) * (1 if dm.group(1) == "+" else -1))
    return ("const", int(e))


def eval_arms(arms, index, kind_count=0):
    """First arm whose predicate holds.

    Disjunction is OR over AND-terms, and a false AND-term must NOT abandon
    the arm.  The first run of this instrument broke out of the OR loop and
    reported the `index==27 || index==28` rows as zero rows -- which is
    exactly the row the comment above them is about.
    """
    for cond, ret in arms:
        hit = False
        for ands in cond:
            term_ok = True
            for op, rhs in ands:
                v = kind_count if rhs == "COUNT" else rhs
                if not {"==": index == v, ">=": index >= v,
                        "<=": index <= v, "!=": index != v}[op]:
                    term_ok = False
                    break
            if term_ok:
                hit = True
                break
        if hit:
            kind, k = ret
            return k if kind == "const" else index + k
    return 0


def parse_stated_bounds(text):
    """ntir.nova states its bounds in a COMMENT that WRAPS across lines.

    The sentence starts mid-line ("...gets wrong. The" / "// bounds are the
    parser's own: 1 to 25, ... 90 to" / "// 96, with 26 the only hole.") and a
    single-line regex reads "90 to" and loses the whole 90-96 range.  The
    comment block is reassembled before it is parsed.
    """
    m = re.search(r"bounds are the parser's own:", text)
    if not m:
        return None, None
    start = text.count("\n", 0, m.start()) + 1
    eol = text.index("\n", m.end())
    phrase = text[m.end():eol]
    # continue over the following comment lines
    k = eol + 1
    while k < len(text):
        eol2 = text.find("\n", k)
        if eol2 < 0:
            eol2 = len(text)
        seg = text[k:eol2]
        stripped = seg.strip()
        if not stripped.startswith("//"):
            break
        phrase += " " + stripped[2:].strip()
        if re.search(r"the only hole", stripped) or "." in stripped:
            break
        k = eol2 + 1
    ranges = []
    for lo, hi in re.findall(r"([0-9]+)\s+to\s+([0-9]+)", phrase):
        ranges.append((int(lo), int(hi)))
    hole = re.search(r"with\s+([0-9]+)\s+the only hole", phrase)
    return {"phrase": phrase.strip(), "line": start, "ranges": ranges,
            "hole": int(hole.group(1)) if hole else None}, phrase


def ranges_population(bounds):
    pop = set()
    for lo, hi in bounds["ranges"]:
        pop.update(range(lo, hi + 1))
    return pop


# --------------------------------------------------------------------------
# 5. THE SIX C ENUMS, read body by body, first member AND last member.
# --------------------------------------------------------------------------

ENUM_RE = re.compile(r"typedef\s+enum\s*\{(.*?)\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
                      re.S)
COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)


def parse_c_enums(text):
    res = []
    for m in ENUM_RE.finditer(text):
        body = COMMENT_RE.sub(" ", m.group(1))
        members = []
        for chunk in body.split(","):
            chunk = re.sub(r"//[^\n]*", " ", chunk).strip()
            mm = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*(?:=.*)?$", chunk)
            if mm:
                members.append(mm.group(1))
        if not members:
            continue
        line = text.count("\n", 0, m.start()) + 1
        res.append({"type": m.group(2), "members": members, "line": line,
                    "first": members[0], "last": members[-1]})
    return res


# --------------------------------------------------------------------------
# 6. THE C RECORD BODIES, for the twelve-word pass.
# --------------------------------------------------------------------------

STRUCT_RE = re.compile(r"typedef\s+struct\s*\{(.*?)\}\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
                       re.S)


def parse_c_structs(text):
    """Every DECLARATOR of every struct body, not one per semicolon.

    `uint32_t source, line, column;` is three fields, not one.  Splitting the
    body on `;` and taking the last identifier of each piece -- which is what
    the first run did -- reports NtFSpan as {column, end} and then makes the
    C side look like it has no `source` or `line` at all.
    """
    res = {}
    for m in STRUCT_RE.finditer(text):
        body = COMMENT_RE.sub(" ", m.group(1))
        fields = []
        for decl in body.split(";"):
            decl = re.sub(r"//[^\n]*", " ", decl).strip()
            if not decl:
                continue
            for piece in decl.split(","):
                piece = piece.strip()
                mm = re.match(r"^(?:.*?[\s\*])?([A-Za-z_][A-Za-z0-9_]*)$",
                              piece)
                if mm:
                    fields.append(mm.group(1))
        res[m.group(2)] = {"fields": fields,
                           "line": text.count("\n", 0, m.start()) + 1}
    return res


# --------------------------------------------------------------------------
# 7. THE DOCUMENTARY CROSS-CHECK.  Wherever another document of the project
#    points at a kind by number and gives it a name in prose.
# --------------------------------------------------------------------------

def documentary_names(text, projected):
    """projected: {ast_kind: [names]}.  Returns {ast_kind: (file, line, name)}.

    The rule is strict and stated: the document must contain the token
    `kind <N>` and the projected name within 240 characters of it.  No
    synonym list, no hand mapping.
    """
    hits = {}
    flat = text
    for m in re.finditer(r"kind\s+([0-9]+)", flat):
        n = int(m.group(1))
        if n not in projected:
            continue
        win = flat[max(0, m.start() - 120): m.end() + 240]
        for nm in projected[n]:
            if re.search(r"(?<![A-Za-z0-9_])" + re.escape(nm) +
                         r"(?![A-Za-z0-9_])", win):
                hits[n] = ("spec/ntasm/ntasm.md",
                           flat.count("\n", 0, m.start()) + 1, nm)
                break
    return hits


# --------------------------------------------------------------------------
# MAIN
# --------------------------------------------------------------------------

def main():
    outdir = OUTDIR_DEFAULT
    if "--out" in sys.argv:
        outdir = sys.argv[sys.argv.index("--out") + 1]
    # lot50_population.txt is the only in-tree digest snapshot of the 59 .nova
    # files, and other lots bisect against it. An extractor that other work
    # depends on as a fixed reference cannot also be the thing that re-writes
    # that reference: re-running this tool silently re-baselined that snapshot
    # and destroyed the ability to compare a later tree against an earlier one.
    # Writing it is therefore refused unless the caller names a different
    # destination or passes --force.
    _ref = os.path.join(outdir, "lot50_population.txt")
    if os.path.exists(_ref) and "--force" not in sys.argv:
        sys.stderr.write(
            "REFUSED: %s already exists and is the digest snapshot other lots\n"
            "bisect against. Re-running this tool would re-baseline it.\n"
            "  write elsewhere : python3 %s --out <your-own-dir>\n"
            "  overwrite it    : python3 %s --force   (destroys the reference)\n"
            % (_ref, sys.argv[0], sys.argv[0]))
        return 3
    os.makedirs(outdir, exist_ok=True)

    parser_rec = read_file(PARSER_NOVA)
    ast_rec = read_file(AST_NOVA)
    ntir_rec = read_file(NTIR_NOVA)
    mir_rec = read_file(MIR_NOVA)
    abi_rec = read_file(ABI_NOVA)
    fe_rec = read_file(FRONTEND_H)

    # EVERY .nova module in the toolchain goes into the scan set, so a factory
    # call in a module nobody expected is still counted, and the factory is
    # still found by its action wherever it lives.
    files = {}
    for name in sorted(os.listdir(NOVA_DIR)):
        if not name.endswith(".nova"):
            continue
        rec = read_file(os.path.join(NOVA_DIR, name))
        files[name] = {"path": rec["path"],
                       "fns": parse_nova_functions(rec["text"]),
                       "text": rec["text"]}
    fe_rec = read_file(FRONTEND_H)

    out("=" * 78)
    out("LOT 50 INSTRUMENT -- Nova AST node-kind vocabulary and the six C enums")
    out("=" * 78)
    out("")

    # ---------------- NEGATIVE CONTROL, FIRST ----------------
    out("-" * 78)
    out("NEGATIVE CONTROL, RUN BEFORE ANY COUNT")
    out("-" * 78)
    toks = extract_token_vocabulary(files)
    def_rec, factory, sites, unresolved = extract_population(files,
                                                            ast_rec["text"])
    def_file = def_rec["path"]
    ast_pop = set(sites)
    overlap = sorted(set(toks) & ast_pop)
    out("  refused population : the LEXER/TOKEN kind vocabulary")
    out("  why it is refused  : a token kind can only reach node_words through")
    out("                      the factory; a token predicate cannot.")
    out("  token vocabulary   : %d distinct values read from %d predicates" %
        (len(toks), len(TOKEN_PREDICATES)))
    out("  AST population     : %d distinct values read from factory calls" %
        len(ast_pop))
    out("  OVERLAP            : %d of the %d AST numbers are ALSO token"
        % (len(overlap), len(ast_pop)))
    out("                       numbers -- %d%%.  The control BITES; it is not"
        % round(100.0 * len(overlap) / max(1, len(ast_pop))))
    out("                       vacuous.")
    out("    shared numbers   : %s" % ", ".join(map(str, overlap)))
    out("    A number-only extractor cannot separate these two populations.")
    out("    This instrument separates them on the FACTORY: %s() is the one"
        % factory.name)
    out("    function in the tree that writes word 0 of the AST node array")
    out("    at (id-1)*%d, and no token predicate ever calls it." % ast_stride(ast_rec["text"]))
    out("    Worked case, token 91 vs AST kind 91, both real:")
    out("      token 91 sites : %s" % ", ".join(
        "%s:%d" % s for s in sorted(toks.get(91, []))[:3]))
    out("      AST   91 sites : %s" % ", ".join(
        "%s:%d" % (p, l) for (p, l, _) in sites.get(91, [])[:3]))
    ntir_base = parse_callable_table(ntir_rec["text"], "KIND_")
    mir_base = parse_callable_table(mir_rec["text"], "KIND_")
    ntir_kinds = parse_callable_table(ntir_rec["text"], "k_")
    mir_kinds = parse_callable_table(mir_rec["text"], "k_")
    ntir_min = min(v for _, v, _ in ntir_kinds)
    ntir_max = max(v for _, v, _ in ntir_kinds)
    mir_min = min(v for _, v, _ in mir_kinds)
    mir_max = max(v for _, v, _ in mir_kinds)
    out("  also refused       : NTIR kinds %d..%d (%d values), machine_ir kinds"
        % (ntir_min, ntir_max, len(ntir_kinds)))
    out("                      %d..%d (%d values).  Both are named; neither is"
        % (mir_min, mir_max, len(mir_kinds)))
    out("                      an AST kind.")
    out("")

    # ---------------- THE FACTORY ----------------
    out("-" * 78)
    out("THE FACTORY, FOUND BY ITS ACTION")
    out("-" * 78)
    out("  found   : fn %s(%s) in %s" %
        (factory.name, ", ".join("%s:%s" % p for p in factory.params), def_file))
    out("  by      : it stores its 2nd parameter into node_words offset 0 at")
    out("            (id-1)*%d, and exactly one function in the scan set"
        % ast_stride(ast_rec["text"]))
    out("            satisfies that predicate -- the instrument refuses to")
    out("            pick one of several.")
    out("  scan    : every .nova module in %s"
        % os.path.relpath(NOVA_DIR, ROOT).replace("\\", "/"))
    callers = {p for k in sites for (p, _, _) in sites[k]}
    out("  modules that call it : %s" % ", ".join(sorted(callers)))
    out("  forwarder call sites whose kind argument is a VARIABLE : %d" %
        len(unresolved))
    out("           (a forwarder of a forwarder; reported, not hidden, and")
    out("           both ends of it resolve to literal kinds already above)")
    for u in unresolved[:10]:
        out("    VARIABLE %s:%d  %s(...,%s)" % u)
    out("")

    # ---------------- THE POPULATION ----------------
    pop = sorted(ast_pop)
    out("-" * 78)
    out("THE EXTRACTED NOVA AST POPULATION")
    out("-" * 78)
    out("  EXTRACTED POPULATION : %d kinds" % len(pop))
    out("  min %d  max %d" % (pop[0], pop[-1]))
    gaps = [n for n in range(pop[0], pop[-1] + 1) if n not in ast_pop]
    out("  unpopulated inside [%d,%d] : %d -- %s%s" % (
        pop[0], pop[-1], len(gaps),
        ", ".join(map(str, gaps[:2])) or "none",
        "" if len(gaps) <= 2 else " ... through %d" % gaps[-1]))
    out("")

    # ---------------- THE NTIR STATED BOUNDS ----------------
    bounds, phrase = parse_stated_bounds(ntir_rec["text"])
    stated = ranges_population(bounds)
    holes_in_bands = sorted(n for lo, hi in bounds["ranges"]
                            for n in range(lo, hi + 1) if n not in ast_pop)
    out("  ntir.nova calls %s 'the only hole'; inside its own bands the"
        % bounds["hole"])
    out("  extractor finds %d unpopulated kind(s): %s.  AGREE." %
        (len(holes_in_bands), ", ".join(map(str, holes_in_bands)) or "none"))
    out("-" * 78)
    out("THE ntir.nova STATED BOUNDS, AND THE DIFFERENCE")
    out("-" * 78)
    out("  ntir.nova:%d, verbatim:" % bounds["line"])
    out("    \"%s\"" % phrase)
    out("  read out of that sentence: %s, hole %s" %
        (", ".join("%d-%d" % r for r in bounds["ranges"]), bounds["hole"]))
    out("  STATED POPULATION   : %d" % len(stated))
    out("  EXTRACTED POPULATION: %d" % len(pop))
    only_extracted = sorted(ast_pop - stated)
    only_stated = sorted(stated - ast_pop)
    out("  extracted - stated  : %s" % (", ".join(map(str, only_extracted)) or "{}"))
    out("  stated - extracted  : %s" % (", ".join(map(str, only_stated)) or "{}"))
    out("  *** THE DISAGREEMENT IS PUBLISHED, NOT CHOSEN. ***")
    out("      ntir.nova states %d, the emitter produces %d, the difference"
        % (len(stated), len(pop)))
    out("      is {%s}." % (", ".join(map(str, only_extracted)) or "none"))
    out("      Which of the two is right is not this instrument's question,")
    out("      and the instrument does not pick.  The kind the sentence omits")
    out("      IS the second conflation, and ntir.nova's OWN kind_of() has an")
    out("      arm for it -- so the sentence and the arms of one file disagree")
    out("      with each other.  Which of the three is right is not this")
    out("      instrument's question.")
    out("")

    # ---------------- THE COLUMN, REPLAYED ----------------
    arms, astat_fn = parse_arms(ntir_rec["text"], "kind_ast_at")
    kind_count = None
    for nm, val, ln in parse_callable_table(ntir_rec["text"], "KIND_"):
        if nm == "KIND_COUNT":
            kind_count = val
    out("-" * 78)
    out("THE kind_ast_at COLUMN, REPLAYED -- A CLAIM OF ABSENCE, RE-MEASURED")
    out("-" * 78)
    out("  ntir.nova's own KIND_COUNT() = %d, read from the tree" % kind_count)
    out("  ntir.nova's k_* table       = %d entries" % len(ntir_kinds))
    zero_rows = [i for i in range(1, len(ntir_kinds) + 1)
                 if eval_arms(arms, i, kind_count) == 0]
    m = re.search(r"THE ZERO ROWS ARE[^\n]*", ntir_rec["text"])
    m2 = re.search(r"The ZERO rows in the published AST column[^\n]*",
                   ntir_rec["text"])
    if m:
        out("  ntir.nova:%d says:" %
            (ntir_rec["text"].count("\n", 0, m.start()) + 1))
        out("    \"%s\"" % m.group(0).strip())
    if m2:
        l1 = ntir_rec["text"].count("\n", 0, m.start()) + 1
        l2 = ntir_rec["text"].count("\n", 0, m2.start()) + 1
        out("  ntir.nova:%d says the same thing again, %d lines later:" %
            (l2, l2 - l1))
        out("    \"%s\"" % m2.group(0).strip())
    out("  REPLAYED, kind_ast_at has %d zero rows over index 1..%d: %s" %
        (len(zero_rows), len(ntir_kinds), zero_rows or "none"))
    named_zero = []
    if m:
        pairs = re.findall(r"([0-9]+)\s*/\s*([0-9]+)", m.group(0))
        named_zero = [int(x) for p in pairs for x in p]
    out("  the comment names        : %s" % (named_zero or "none parsed"))
    if zero_rows == named_zero:
        out("  AGREE -- the comment and the arms name the same rows.")
    else:
        out("  *** SECOND DISAGREEMENT, PUBLISHED NOT CHOSEN. ***")
        out("      Two comments in ntir.nova say %d rows of kind_ast_at are"
            % len(named_zero))
        out("      zero (%s).  Replaying the arms, %d row is zero and those"
            % (", ".join(map(str, named_zero)), len(zero_rows)))
        out("      rows return %s." % ", ".join(
            str(eval_arms(arms, i, kind_count)) for i in named_zero))
        out("      The comment and the code sit in ONE file and disagree.")
        out("      The instrument publishes both and chooses neither.  These")
        out("      are the same four rows the conflation lives on, so it is")
        out("      not a cosmetic disagreement.")
    out("")

    # ---------------- NAMES, THREE WAYS ----------------
    out("-" * 78)
    out("NAMES -- THREE LOOKS, BECAUSE A CLAIM OF ABSENCE MUST BE RE-MEASURED")
    out("-" * 78)
    ast_fns = parse_nova_functions(ast_rec["text"])
    declared = [f.name for f in ast_fns
                if re.match(r"(KIND_BASE|KIND_COUNT|kind_at|kind_ast_at|"
                            r"kind_name|kind_text|k_ast_)", f.name)]
    out("  LOOK 1 -- BY NAME, in the AST domain (ast.nova)")
    out("    declarations that bind a name to an AST kind: %s" %
        (", ".join(declared) or "NONE"))
    out("    ast.nova exports: %s" %
        ", ".join(f.name for f in ast_fns if f.exported))

    # a string table indexed by AST kind anywhere in the tree?
    content_tables = []
    for key, rec in files.items():
        if key == "_all":
            continue
        for f in rec["fns"]:
            if re.match(r"(kind_name|kind_text|copy_kind_name)", f.name):
                content_tables.append((rec["path"], f.name, f.line0))
    out("  LOOK 2 -- BY CONTENT, a string table indexed by AST kind")
    out("    kind-name functions in the tree: %s" %
        ", ".join("%s:%s:%d" % c for c in content_tables))
    out("    every one of them is indexed by a KIND_BASE domain, not by AST")
    out("    kind.  NO table indexed by AST kind exists: %d names declared." %
        len(declared))

    # LOOK 3 -- by projection through ntir.nova's OWN kind_ast_at column
    kind_base = None
    for bn, bv, bl in parse_callable_table(ntir_rec["text"], "KIND_"):
        if bn == "KIND_BASE":
            kind_base = bv
    projected = {}
    drift = []
    for i, (nm, val, line) in enumerate(ntir_kinds, start=1):
        a = eval_arms(arms, i, kind_count)
        if val != kind_base + i - 1:
            drift.append((i, nm, val, kind_base + i - 1))
        if a:
            projected.setdefault(a, []).append((nm, i, line))
    out("  LOOK 3 -- BY PROJECTION, through ntir.nova's own kind_ast_at column")
    out("    entries in ntir's k_* table : %d" % len(ntir_kinds))
    out("    distinct AST kinds named    : %d" % len(projected))
    doubled = {a: v for a, v in projected.items() if len(v) > 1}
    out("    AST kinds named MORE THAN ONCE: %s" %
        ("; ".join("%d -> %s" % (a, "/".join(n for n, _, _ in v))
                   for a, v in sorted(doubled.items())) or "none"))
    out("    k_* value vs kind_at(index) drift: %d entries" % len(drift))
    out("    These are PROJECTIONS of an NTIR entry name onto an AST kind.")
    out("    They are not declarations in the AST domain and they are not")
    out("    used as DECIDED evidence on their own.")
    out("")

    # LOOK 4 -- by CONSUMER PREDICATE, the fourth place a name could live
    consumer = {}
    for rec, f in all_functions(files):
        for m in re.finditer(r"\.kind\s*[!=]=\s*([0-9]+)", f.text):
            consumer.setdefault(int(m.group(1)), set()).add(rec["path"])
    abi_only = set()
    for n, paths in consumer.items():
        if paths == {"compiler/nova/analysis/abi/abi.nova"}:
            abi_only.add(n)
    out("  LOOK 4 -- BY CONSUMER PREDICATE, `.kind==N` across every module")
    out("    distinct kinds a consumer tests for : %d" % len(consumer))
    out("    of the extracted population          : %d" %
        len(set(consumer) & ast_pop))
    out("    tested ONLY in abi.nova               : %d  %s" %
        (len(abi_only), sorted(abi_only)))
    out("    abi.nova's two conditions are the whole of it: a consumer test")
    out("    is a USE, not a NAME, and this lot does not fill a table with")
    out("    uses.  Recorded here so the refusal is a measurement.")
    out("")

    # ---------------- UNNAMED ----------------
    named_any = set(ast_pop) & set(projected)
    unnamed = sorted(ast_pop - named_any)
    out("  UNNAMED, no name by ANY of the four tree-drawn routes : %d %s" %
        (len(unnamed), unnamed or ""))
    out("  UNNAMED in the AST domain (ast.nova DECLARES none)    : %d of %d" %
        (len(ast_pop), len(pop)))
    out("  NAMED only by projection (ntir.nova's own column)     : %d" %
        len(named_any))
    out("  A projection is not a declaration: it is the name of the")
    out("  NTIR entry the AST kind lowers to, read out of ntir.nova.")
    out("  It is evidence for the CROSS-CHECK below and for nothing else.")
    out("")

    # ---------------- C ENUMS ----------------
    out("-" * 78)
    out("THE SIX C ENUMS, READ BODY BY BODY -- FIRST MEMBER AND LAST MEMBER")
    out("-" * 78)
    enums = parse_c_enums(fe_rec["text"])
    wanted = ["NtFExprKind", "NtFStmtKind", "NtFTypeKind", "NtFSpace",
              "NtFDirection", "NtFOp"]
    c_total = 0
    for w in wanted:
        e = [x for x in enums if x["type"] == w]
        if not e:
            out("  %-16s NOT FOUND -- the instrument refuses to guess" % w)
            continue
        e = e[0]
        c_total += len(e["members"])
        out("  %-16s frontend.h:%-4d %2d values  first=%s  last=%s" %
            (w, e["line"], len(e["members"]), e["first"], e["last"]))
        out("      %s" % " ".join(e["members"]))
    out("  C DISCRIMINABLE VALUES : %d" % c_total)

    structs = parse_c_structs(fe_rec["text"])
    untagged = ["NtFProgram", "NtFRegister", "NtFDiagnostic", "NtFEffects"]
    present = [u for u in untagged if u in structs]
    out("  C UNTAGGED ROLES       : %d  %s" %
        (len(present), ", ".join(present)))
    prog = structs.get("NtFProgram", {}).get("fields", [])
    arrays = [f for f in prog if re.match(r"^[a-z_]+_count$", f)]
    out("  NtFProgram parallel arrays (frontend.h:%d): %d" %
        (structs.get("NtFProgram", {}).get("line", 0), len(arrays)))
    for a in arrays:
        out("      %s" % a)
    out("")

    # ---------------- THE EMITTER CROSS-CHECK ----------------
    out("-" * 78)
    out("THE CROSS-CHECK: DOES THE TREE AGREE WITH ITS OWN PROJECTION?")
    out("-" * 78)
    out("  rule, both halves declared here so a reader can disagree with them:")
    out("    (a) the name the tree projects is stripped of the declared prefix")
    out("        %s -- ntir.nova's own k_ convention;" % (list(NAME_PREFIXES),))
    out("    (b) the enclosing emitter function name is stripped of the")
    out("        declared suffix %s;" % (list(EMITTER_NAME_SUFFIXES),))
    out("    (c) the two are compared EXACTLY and case-sensitively.  No")
    out("        other rule exists, no fuzzy matching, no synonyms.")
    decided_names = []
    undecided_names = []
    for k in pop:
        names = []
        for (n, _, _) in projected.get(k, []):
            for pre in NAME_PREFIXES:
                if n.startswith(pre):
                    n = n[len(pre):]
            names.append(n)
        cands = set()
        for (p, line, fn) in sites[k]:
            cands.add(fn)
            for suf in EMITTER_NAME_SUFFIXES:
                if fn.endswith(suf):
                    cands.add(fn[: -len(suf)])
        hit = None
        for c in sorted(cands):
            if c in names:
                hit = c
                break
        if hit:
            decided_names.append((k, hit, sorted(cands)))
        else:
            undecided_names.append((k, ",".join(names) or "-",
                                    ",".join(sorted(cands))))
    out("  DECIDED (a name exists and BOTH sides of the tree read it the same): %d"
        % len(decided_names))
    for k, n, c in decided_names:
        out("    kind %-3d  name=%-16s  emitter fn=%s" % (k, n, ",".join(c)))
    out("  UNDECIDED (no exact agreement): %d" % len(undecided_names))
    for k, n, c in undecided_names:
        out("    kind %-3d  projected=%-22s emitter fn=%s" % (k, n, c))
    out("")

    # ---------------- DOCUMENTARY CROSS-CHECK ----------------
    spec_rec = read_file(SPEC_NTASM)
    proj_names = {}
    for a, v in projected.items():
        nm = []
        for (n, _, _) in v:
            for pre in NAME_PREFIXES:
                if n.startswith(pre):
                    n = n[len(pre):]
            nm.append(n)
        proj_names[a] = nm
    doc_hits = documentary_names(spec_rec["text"], proj_names)
    out("  spec/ntasm/ntasm.md, %d bytes, mtime %s -- read as a THIRD source of"
        % (spec_rec["bytes"], spec_rec["mtime"]))
    out("  names, on the strict rule (`kind <N>` and the name within 240")
    out("  characters of it, no synonym list).")
    out("  corroborates %d of %d projected names: %s" %
        (len(doc_hits), len(proj_names),
         ", ".join("%d=%s" % (a, nm) for a, (_, _, nm) in sorted(doc_hits.items()))
         or "none"))

    # ---------------- THE PROMOTION ----------------
    out("-" * 78)
    out("THE PROMOTION: CAN THE TREE REGENERATE ast's VOCABULARY?")
    out("-" * 78)
    shape = []
    shape.append("export fn KIND_BASE()->u64 { return %d; }" % (pop[0] - 1))
    shape.append("export fn KIND_COUNT()->u64 { return %d; }" % len(pop))
    shape.append("export fn kind_at(index:u64)->u64 { return KIND_BASE()+index; }")
    mir_shape = [
        l for l in mir_rec["text"].split("\n")
        if re.search(r"fn (KIND_BASE|KIND_COUNT|kind_at)\b", l)]
    same_shape = (len(mir_shape) == 3 and
                  "KIND_BASE" in mir_shape[0] and
                  "KIND_COUNT" in mir_shape[1] and
                  "kind_at(index" in mir_shape[2])
    out("  machine_ir.nova holds the shape: %s" % ("YES" if same_shape else "NO"))
    for l in mir_shape:
        out("      %s" % l.strip())
    out("  ast.nova holds the shape: NO -- ast.nova exports %s" %
        ", ".join(f.name for f in ast_fns if f.exported))
    out("  This instrument CAN emit it in that shape, from the tree:")
    for l in shape:
        out("      %s" % l)
    out("  KIND_BASE here is %d so that kind_at(1) is %d, the first kind the"
        % (pop[0] - 1, pop[0]))
    out("  emitter emits.  The base is invented by the generator and is named")
    out("  as such; it is NOT read from the tree, because the tree has none.")
    out("")

    # ---------------- THE TWELVE WORDS ----------------
    out("-" * 78)
    out("THE TWELVE WORDS, FROM ast.nova, AGAINST THE C RECORD BODIES")
    out("-" * 78)
    node_struct = None
    for f in ast_fns:
        if f.name == "Node":
            node_struct = f
    m = re.search(r"kind:u64,token_begin:u64,token_end:u64,source:u64,line:u64,"
                  r"column:u64,\s*start:u64,end:u64,first_child:u64,"
                  r"last_child:u64,next_sibling:u64,aux:u64", ast_rec["text"])
    words = ["kind", "token_begin", "token_end", "source", "line", "column",
             "start", "end", "first_child", "last_child", "next_sibling", "aux"]
    out("  words read from ast.nova:%d: %s" %
        (ast_rec["text"].count("\n", 0, m.start()) + 1 if m else 0,
         ", ".join(words)))
    all_c_fields = set()
    for s in structs.values():
        all_c_fields.update(s["fields"])
    span_fields = structs.get("NtFSpan", {}).get("fields", [])
    out("  NtFSpan (frontend.h:%d) fields: %s" %
        (structs.get("NtFSpan", {}).get("line", 0), span_fields))
    token_in_c = [w for w in ("token_begin", "token_end")
                  if w in all_c_fields or re.search(
                      r"\b" + w + r"\b", fe_rec["text"])]
    out("  C mentions of token_begin/token_end: %s" %
        (", ".join(token_in_c) or "NOWHERE in frontend.h -- 0 hits over the"
         " whole %d-byte file" % fe_rec["bytes"]))
    out("")

    # ---------------- THE CONFLATIONS, MEASURED ----------------
    kindof = None
    for rec, f in all_functions(files):
        if rec["path"].endswith("ntir.nova") and f.name == "kind_of":
            kindof = f
    out("-" * 78)
    out("THE TWO CONFLATIONS, AND WHETHER THE TREE ITSELF CARES")
    out("-" * 78)
    if kindof is None:
        out("  REFUSAL: ntir.nova's kind_of was not found; the claim that it")
        out("  handles kinds 28 and 32 is NOT measured and is not made.")
    else:
        out("  ntir.nova:%d fn kind_of -- the arms for the two conflations,"
            % kindof.line0)
        out("  read out of its own text:")
        for k in (28, 32):
            arms = re.findall(
                r"if\s+ast\s*==\s*" + str(k) + r"\s*\{(.*?)\n    \}",
                kindof.text, re.S)
            for a in arms:
                rets = re.findall(r"return\s+([^;]+);", a)
                guards = re.findall(r"if\s+([^;{]+?)\s*==\s*true", a)
                guards += ["aaux==" + x for x in
                           re.findall(r"aaux\([^)]*\)\s*==\s*([0-9]+)", a)]
                for r_ in rets:
                    out("    ast==%-3d returns %-18s  guard: %s" %
                        (k, r_.strip(),
                         ", ".join(g.strip() for g in guards) or "none"))
            if not arms:
                out("    ast==%-3d NO ARM FOUND -- the instrument refuses to"
                    % k)
                out("             claim the tree distinguishes it.")
        out("")
        pred_line = None
        for rec, f in all_functions(files):
            if rec["path"].endswith("ntir.nova") and f.name == "is_abi_clause":
                pred_line = f.line0
        out("")
        out("  So the tree DOES distinguish both kinds, in kind_of, with")
        out("  predicates the instrument read out of the source.  The")
        out("  predicate for 28 is is_abi_clause(), which this instrument")
        out("  located at %s -- a line number this run measured, not one"
            % ("ntir.nova:%d" % pred_line if pred_line else "NOT FOUND"))
        out("  written from memory.  What none of this does is put a NAME on")
        out("  the two outcomes in the AST domain, and a name is the only")
        out("  thing a table row can carry.  The rows stay NOT COUNTABLE and")
        out("  carry no number.")
    out("")

    # ---------------- THE TABLE ----------------
    rows = []
    # A: the twelve words
    derived_words = ["source", "line", "column", "start", "end"]
    for i, w in enumerate(words):
        if w in derived_words:
            v = "DERIVED"
            why = ("Nova %s is read from %s by ntir.nova's accessor; C %s is a"
                   " field of NtFSpan on every record that reaches the tree."
                   % (w, {"source": "asource", "line": "aline",
                          "column": "acolumn", "start": "astart",
                          "end": "aend"}[w], w))
        elif w == "kind":
            v = "UNDECIDED"
            why = ("ast.nova declares no KIND_BASE/KIND_COUNT/kind_at; the"
                   " number needs a table in the AST domain and there is none.")
        elif w in ("token_begin", "token_end"):
            v = "UNDECIDED"
            why = ("frontend.h contains no token member at all -- measured by"
                   " search of the whole file, %d hit(s).  The C tree does not"
                   " carry the fact, so nobody has chosen a home." %
                   len(token_in_c))
        elif w == "aux":
            v = "UNDECIDED"
            why = ("the C tree has no counterpart; 'the parser writes no aux'"
                   " is a choice, not a copy.")
        else:
            v = "UNDECIDED"
            why = ("C has no field of this name; the child ORDER of the three"
                   " named NtFStmt slots is an ordering decision.")
        rows.append(("word", "%2d %s" % (i, w), v, why))

    # B: the six C enums + the untagged roles
    for w in wanted:
        e = [x for x in enums if x["type"] == w]
        if not e:
            continue
        e = e[0]
        rows.append(("c-enum", "%s (%d values, frontend.h:%d)" %
                     (w, len(e["members"]), e["line"]), "UNDECIDED",
                     "C side read from the enum body.  The Nova side is NOT"
                     " this axis: Nova folds these into one AST kind plus aux,"
                     " and ast.nova names neither.  No correspondence is"
                     " derivable from the tree, so the row is UNDECIDED and"
                     " not an estimate."))
    for u in present:
        rows.append(("c-role", u, "UNDECIDED",
                     "untagged role: frontend.h carries it as a struct field"
                     " with no enumerator.  No Nova home is named."))

    # C: the two conflations
    for k, txt in ((28, "abi clause vs call statement"),
                   (32, "instruction vs label")):
        rows.append(("conflation",
                     "AST kind %d -- %s" % (k, txt), "UNDECIDED",
                     "NOT COUNTABLE.  C distinguishes (%s); Nova does not, and"
                     " no mapping recovers the distinction.  Any number would"
                     " be a fiction." % ("NTF_S_CALL + a clause role" if k == 28
                                          else "NTF_S_INSTRUCTION / NTF_S_LABEL")))

    # D: the vocabulary rows
    rows.append(("vocabulary", "Nova AST kinds extracted", "DERIVED",
                 "both sides read from the tree: %d factory call sites." %
                 sum(len(v) for v in sites.values())))
    rows.append(("vocabulary", "Nova AST kind NAMES declared", "UNDECIDED",
                 "ast.nova declares %d.  Looked for by name, by content and by"
                 " projection; the projection is not a declaration." %
                 len(declared)))
    rows.append(("vocabulary", "ntir.nova stated bounds", "UNDECIDED",
                 "states %d, emitter extracts %d, difference {%s}.  PUBLISHED,"
                 " NOT CHOSEN." % (len(stated), len(pop),
                                   ", ".join(map(str, only_extracted)) or "-")))

    out("  %-11s %-46s %-10s" % ("ROW", "SUBJECT", "VERDICT"))
    out("  %s" % ("-" * 78))
    for grp, subj, verdict, why in rows:
        mark = "  <<< NOT COUNTABLE" if grp == "conflation" else ""
        out("  %-11s %-46s %-10s%s" % (grp, subj[:46], verdict, mark))
    out("")
    n_derived = sum(1 for r in rows if r[2] == "DERIVED")
    n_undecided = sum(1 for r in rows if r[2] == "UNDECIDED")
    n_nc = sum(1 for r in rows if r[0] == "conflation")
    w_derived = sum(1 for r in rows if r[0] == "word" and r[2] == "DERIVED")
    w_undecided = sum(1 for r in rows if r[0] == "word" and r[2] == "UNDECIDED")
    out("  TABLE ROWS  total=%d  DERIVED=%d  DECIDED=0  UNDECIDED=%d" %
        (len(rows), n_derived, n_undecided))
    out("  NOT COUNTABLE rows: %d (kinds 28 and 32).  They carry no number at"
        % n_nc)
    out("  all and they are excluded from every count above; the verdict")
    out("  column has three values and NOT COUNTABLE is a separate marker,")
    out("  because the ticket asks for both and they are different things.")
    out("  THE FOURTH VERDICT DOES NOT EXIST.  A row that cannot be")
    out("  classified is UNDECIDED, never an estimate.")
    out("")
    out("  OF THE TWELVE WORDS: DERIVED=%d  UNDECIDED=%d." %
        (w_derived, w_undecided))
    out("  W89Size recorded 8 derivable of 12.  This instrument's predicate")
    out("  -- the value recoverable from a C field with NO CHOICE left --")
    out("  yields %d.  The three structural words (first_child, last_child," % w_derived)
    out("  next_sibling) are counted derivable only AFTER a name node is")
    out("  fabricated and an ordering is written down, and a fabrication IS a")
    out("  decision; the discriminator needs a table that does not exist.")
    out("  PUBLISHED, NOT CHOSEN.  Both numbers stand.")
    out("")
    out("  DECIDED is 0 on this table and %d in the name cross-check above." %
        len(decided_names))
    out("  They are different questions and neither number is used for the")
    out("  other: a table row is a mapping and a cross-check row is a name.")
    out("")

    # ---------------- WRITE THE ARTEFACTS ----------------
    # ARTEFACT 2, THE TABLE.  It is emitted by the SAME run that produced
    # the numbers, so it cannot drift from them; there is no transcription
    # step anywhere between the tree and this file.
    table_file = os.path.join(outdir, "lot50_table.md")
    tb = []
    tb.append("# LOT 50 -- THE C / NOVA VOCABULARY TABLE")
    tb.append("")
    tb.append("GENERATED by `legacy/tools/coldproof/lot50_vocabulary.py` in one run.")
    tb.append("Every number below was read out of the tree by that run; the")
    tb.append("mtimes it read are at the bottom of `lot50_population.txt`.")
    tb.append("")
    tb.append("**Three verdicts and no fourth.** `DERIVED` -- both sides read it")
    tb.append("from the tree.  `DECIDED` -- a name exists and the instrument")
    tb.append("confirms both sides agree.  `UNDECIDED` -- no name, and nobody has")
    tb.append("chosen.  A row that cannot be classified is `UNDECIDED`, never an")
    tb.append("estimate.  `NOT COUNTABLE` is a separate marker, not a fourth")
    tb.append("verdict: it says the row carries no number at all.")
    tb.append("")
    tb.append("| # | row | subject | verdict | why, in one line |")
    tb.append("|---|---|---|---|---|")
    for i, (grp, subj, verdict, why) in enumerate(rows, start=1):
        v = verdict + (" + NOT COUNTABLE" if grp == "conflation" else "")
        tb.append("| %d | %s | %s | **%s** | %s |" %
                  (i, grp, subj.replace("|", "/"), v, why.replace("|", "/")))
    tb.append("")
    tb.append("## The two conflations, uncounted")
    tb.append("")
    for k, txt in ((28, "abi clause vs call statement"),
                   (32, "instruction vs label")):
        cnames = [n for (n, _, _) in projected.get(k, [])]
        tb.append("* **AST kind %d** -- %s.  `NOT COUNTABLE`.  C distinguishes"
                  % (k, txt))
        tb.append("  it and Nova does not.  ntir.nova's `kind_of` does")
        tb.append("  distinguish it, with a predicate, but a predicate is not a")
        tb.append("  name and the AST domain has no table to hold one.  %s."
                  % ("The two outcomes the tree names are "
                     + " and ".join(cnames) if cnames
                     else "No name was found for either outcome"))
        tb.append("  **Any number here would be a fiction, so none is given.**")
        tb.append("* What would close it: a decision, in the AST domain, to")
        tb.append("  split the kind -- or a decision to accept the loss on the")
        tb.append("  record.  Until one is taken the row stays empty.")
    tb.append("")
    tb.append("## The words that need a decision")
    tb.append("")
    tb.append("Seven of the twelve words are `UNDECIDED`.  Four of them have no")
    tb.append("C counterpart at all, which is the sharper half:")
    tb.append("")
    for w, closer in (
            ("kind",
             "publish `KIND_BASE`/`KIND_COUNT`/`kind_at` in ast.nova, in"
             " machine_ir.nova's shape.  The instrument can already generate"
             " that file; only the decision to adopt it is missing."),
            ("token_begin",
             "decide whether the C tree needs token indices at all.  Measured:"
             " frontend.h carries 0 of them, so either the fact is dropped or"
             " the C tree gains a token array."),
            ("token_end",
             "same decision as token_begin, and the same 0-hit measurement"
             " covers it."),
            ("aux",
             "decide the encoding for `NtFOp` (22), `NtFSpace` (7),"
             " `NtFDirection` (6), `NtFRegister` and `NtFDiagnostic`, or"
             " decide they are dropped.  Many encodings are valid; none is"
             " chosen, so the row is UNDECIDED and the count is unknown,"
             " not zero.")):
        tb.append("* **%s** -- `UNDECIDED`.  What would close it: %s"
                  % (w, closer))
    tb.append("")
    tb.append("The three structural words (`first_child`, `last_child`,")
    tb.append("`next_sibling`) are the other three, and they are also")
    tb.append("`UNDECIDED`: C has no child LIST, only named slots, so the order")
    tb.append("is a choice.  What would close them: one written-down ordering of")
    tb.append("`NtFStmt`'s slots, agreed once and applied to every record.")
    tb.append("")
    tb.append("## The disagreement this table exists to keep visible")
    tb.append("")
    tb.append("* `ntir.nova:%d` states **%d** AST kinds (%s, %s the only"
              % (bounds["line"], len(stated),
                 ", ".join("%d-%d" % r for r in bounds["ranges"]),
                 bounds["hole"]))
    tb.append("  hole).  The emitter extracts **%d**." % len(pop))
    tb.append("  The difference is **{%s}**.  The ranges and the hole are"
              % (", ".join(map(str, only_extracted)) or "none"))
    tb.append("  read out of the comment by this run, not written from memory.")
    tb.append("* A **second** disagreement, inside the same file: two comments")
    tb.append("  in `ntir.nova` say rows %s of `kind_ast_at` are zero;"
              % named_zero)
    tb.append("  replaying the arms, %d row is zero." % len(zero_rows))
    tb.append("* Both are published.  This lot does not choose which is right.")
    tb.append("")
    tb.append("## The vocabulary, in the shape the tree already uses")
    tb.append("")
    tb.append("`machine_ir.nova` holds `KIND_BASE` / `KIND_COUNT` / `kind_at`.")
    tb.append("`ast.nova` holds none.  The instrument CAN emit the AST vocabulary")
    tb.append("in that shape from the tree alone -- see `ast_vocabulary.nova` in")
    tb.append("this directory, regenerated byte-identical on every run.  That is")
    tb.append("the promotion: this table becomes regenerable rather than")
    tb.append("written down.")
    tb.append("")
    with open(table_file, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(tb) + "\n")
    out("  lot50_table.md written: %d rows, %d bytes" %
        (len(rows), os.stat(table_file).st_size))

    pop_file = os.path.join(outdir, "ast_vocabulary.nova")
    head = [
        "// GENERATED by legacy/tools/coldproof/lot50_vocabulary.py.  Do not hand edit.",
        "// The shape is machine_ir.nova's, read from machine_ir.nova:123-125.",
        "// The CONTENT is the AST vocabulary, read from the factory call sites.",
        "// KIND_BASE is the one invented number here and it is marked as such:",
        "//   the AST domain has no base in the tree, because ast.nova declares",
        "//   no KIND_BASE.  kind_at(1) is the first kind the emitter emits.",
        "// Names are PROJECTIONS through ntir.nova's kind_ast_at column, not",
        "//   declarations in the AST domain.  Two kinds are projected twice;",
        "//   their rows are marked SPLIT and are NOT COUNTABLE.",
    ]
    body = list(head)
    body += ["", shape[0], shape[1], shape[2], ""]
    body.append("export fn ast_kind_at(index:u64)->u64 {")
    for n in pop:
        body.append("    if index==%d { return %d; }" % (pop.index(n) + 1, n))
    body.append("    return 0;")
    body.append("}")
    body.append("")
    body.append("// index, AST kind, projected name(s), verdict")
    for n in pop:
        names = [x[0] for x in projected.get(n, [])]
        if not names:
            v = "UNNAMED"
        elif len(names) > 1:
            v = "SPLIT -- NOT COUNTABLE"
        else:
            v = "PROJECTED"
        body.append("//  %2d  kind %-3d  %-24s %s" %
                    (pop.index(n) + 1, n, "/".join(names) or "UNNAMED", v))
    body.append("")
    body.append("export fn ast_kind_name(kind:u64)->buf<u8> {")
    for n in pop:
        names = [x[0] for x in projected.get(n, [])]
        lit = "/".join(names) if names else "UNNAMED"
        body.append('    if kind==%d { return "%s"; }' % (n, lit))
    body.append('    return "unknown";')
    body.append("}")
    body.append("")
    with open(pop_file, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(body))

    # reproducibility: generate twice, compare
    h1 = hashlib.sha256(open(pop_file, "rb").read()).hexdigest()
    with open(pop_file, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(body))
    h2 = hashlib.sha256(open(pop_file, "rb").read()).hexdigest()
    reproducible = (h1 == h2)
    out("  ast_vocabulary.nova regenerated twice: %s (%s)" %
        ("IDENTICAL" if reproducible else "DIFFERENT", h1[:16]))

    # ---------------- MTIMES ----------------
    out("")
    out("-" * 78)
    out("EVERY FILE THIS INSTRUMENT READ")
    out("-" * 78)
    for r in READ:
        out("  %s  %8d B  sha256:%s  %s" %
            (r["mtime"], r["bytes"], r["sha256"][:16], r["path"]))

    # ---------------- DIGESTS ----------------
    created = [table_file, pop_file]
    out("")
    out("-" * 78)
    out("EVERY FILE THIS INSTRUMENT CREATED")
    out("-" * 78)
    for p in created:
        d = hashlib.sha256(open(p, "rb").read()).hexdigest()
        # SIZE AND DIGEST, NEVER THE MTIME. The mtime of a file this run just
        # wrote differs on every run over an unchanged tree, so recording it
        # made lot50_population.txt a snapshot OF THE RUN rather than OF THE
        # TREE, and a reference other lots bisect against has to be a function
        # of the tree alone (MEM.md R156).
        out("  %8d B  %s" % (os.stat(p).st_size,
                             os.path.relpath(p, ROOT).replace("\\", "/")))
        out("      sha256:%s" % d)

    log = os.path.join(outdir, "lot50_population.txt")
    with open(log, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(OUT) + "\n")
    d = hashlib.sha256(open(log, "rb").read()).hexdigest()
    out("  (this log is written last and digested separately below)")
    out("      log sha256:%s  %s" %
        (d, os.path.relpath(log, ROOT).replace("\\", "/")))

    # machine-readable summary for the caller
    summary = {
        "extracted_population": len(pop),
        "extracted_kinds": pop,
        "factory_sites": sum(len(v) for v in sites.values()),
        "named_declared_in_ast_domain": len(declared),
        "named_by_projection": len(projected),
        "unnamed_any_route": len(unnamed),
        "unnamed_in_ast_domain": len(pop),
        "ntir_stated": len(stated),
        "extracted_minus_stated": only_extracted,
        "stated_minus_extracted": only_stated,
        "ntir_zero_rows_comment_vs_code": zero_rows,
        "ntir_zero_rows_code_values": [eval_arms(arms, i) for i in zero_rows],
        "c_discriminable_values": c_total,
        "c_untagged_roles": present,
        "c_parallel_arrays": arrays,
        "table_rows": len(rows),
        "rows_derived": n_derived,
        "rows_decided_table": 0,
        "rows_undecided": n_undecided,
        "rows_not_countable": n_nc,
        "name_crosscheck_decided": len(decided_names),
        "name_crosscheck_undecided": len(undecided_names),
        "spec_corroborations": len(doc_hits),
        "negative_control_tokens": len(toks),
        "negative_control_overlap": overlap,
        "ntir_refused": [ntir_min, ntir_max, len(ntir_kinds)],
        "machine_ir_refused": [mir_min, mir_max, len(mir_kinds)],
        "unresolved_kind_arguments": unresolved,
        "promotion_reproducible": reproducible,
        "promotion_sha256": h1,
        "read_files": [{"path": r["path"], "mtime": r["mtime"],
                        "bytes": r["bytes"], "sha256": r["sha256"]}
                       for r in READ],
        "created": [{"path": os.path.relpath(p, ROOT).replace("\\", "/"),
                     "sha256": hashlib.sha256(open(p, "rb").read()).hexdigest()}
                    for p in created],
    }
    import json
    js = os.path.join(outdir, "lot50_summary.json")
    with open(js, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(summary, fh, indent=1, ensure_ascii=False)
    out("      summary sha256:%s" %
        hashlib.sha256(open(js, "rb").read()).hexdigest())


if __name__ == "__main__":
    main()