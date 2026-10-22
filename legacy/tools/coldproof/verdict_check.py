#!/usr/bin/env python3
"""verdict_check.py -- the falsifier of the delivery verdicts.

THE GAP THIS EXISTS TO CLOSE, and it is measured, not asserted. The document
`docs/status/ntasm-completion.md` is the one that decides whether B2.1 is delivered,
and it now carries exactly ONE verdict per requirement in a four-word closed
vocabulary. The repository's own coherence check reads NONE of those words:
`grep -cE 'livré|partiel|bloqué|non commencé' compiler/c/nova/
tests_ntasm_registry.c` returns 0, and check_doc_structure reads geometry,
section anchors, links and citations. A verdict nobody can falsify is a
comment, and this is the document that decides the delivery.

WHERE EACH RULE COMES FROM. Every rule below is quoted from the document's own
text, with the line it is read from. Nothing here is taste, and a rule that
could only be justified by taste was NOT implemented -- the two that were
refused are named under WHAT IT DOES NOT ENFORCE.

  R1 VOCABULARY            :45-46  "Une exigence porte EXACTEMENT UN mot parmi
                                    `livré`, `partiel`, `bloqué`, `non commencé`,
                                    en deuxième colonne". The cell is read as the
                                    second cell of the row, so a verdict written
                                    anywhere else is not a verdict.
  R2 ONE-WORD-PER-ROW      :45-46  the same "EXACTEMENT UN mot": a row carrying a
                                    second word of the vocabulary carries two
                                    verdicts, which is what the "Historique des
                                    lignes" section now exists to hold.
  R3 BACKED                 :61-62  "Chaque verdict est adossé à une commande ou à
                                    un artefact nommable ; un verdict qui ne peut
                                    pas l'être est `bloqué`, jamais `partiel`."
                                    :185-186 repeats it as the ONE rule of the
                                    document with a mechanical consequence:
                                    "Une entrée qui ne peut nommer ni une commande
                                    ni un artefact fait passer sa ligne à `bloqué`".
  R4 LIVRE-CONTRADICTED     :49-50  "livré -- chaque conjonction nommée par le
                                    critère est portée par un artefact qui existe
                                    sur l'arbre aujourd'hui, et il ne reste
                                    AUCUNE RÉSERVE NOMMÉE." An entry that names a
                                    reserve contradicts the word it is filed under.
  R5 NON-COMMENCE-          :58     "non commencé -- aucun artefact de l'exigence
    CONTRADICTED                    n'existe." So a `non commencé` entry that
                                    names an artefact WHICH EXISTS ON THIS TREE is
                                    a contradiction, and this rule resolves paths
                                    ON DISK. It is the one rule the throwaway
                                    instrument written for W53 could not have had:
                                    that one read strings, this one opens files.
  R6 BLOQUE-NO-MISSING      :55-57  "bloqué -- ... La ligne dit ce qui manque, et
                                    non ce qui a été essayé."
  R7 ENTRY                  :184    "Une entrée par ligne du tableau, dans le
                                    même ordre, et c'est ici que vit la preuve qui
                                    rend le mot falsifiable." Hence: every row has
                                    exactly one entry, its heading carries the same
                                    word, and no word is claimed by two entries.
  R8 ROW-SET                :164    "Si un ID manque, B2.1 reste non livré." A
                                    population that cannot be closed is refused,
                                    never reported as a pass (same exit code as
                                    eol_rail.py's REFUSED).

WHAT IT MEASURES. The verdict CELL of each of the fifteen rows, against the
verdict WORD in the heading of that row's own evidence entry, against what that
entry NAMES, and -- for R5 -- against what exists on this tree. It reads the
document and it opens files; it never writes a byte of either.

FOUR STATES. Named here because a reader who cannot tell a RED from a QUEUE has
been handed the same sentence either way. Exactly ONE sets the exit code.
  CONSISTENT       every row's word agrees with its entry and its evidence.
                   Not the interesting state; it is the state a perturbation
                   leaves, which is what makes it a control and not a proof.
  FINDING          a row that contradicts the document's own rule. THE ONLY
                   RED STATE. Every finding is NAMED by its rule and its row.
  QUEUE            a row the document's rule can neither confirm nor refute --
                   printed with its reason, never red. See WHAT IT DOES NOT
                   ENFORCE for the two that land here, and for the reason.
  REFUSED          the row population could not be closed, or the document or
                   its section is absent. Exit 2. An instrument that cannot
                   read must not print a number that looks like a measurement.

WHAT IT DOES NOT ENFORCE, and why. Both refusals are named, because an
instrument that hides the stratum it refuses to walk is one stratum smaller than
its author believes.
  R9 PARTIEL-UNNAMED-       :51-52  "partiel -- au moins une conjonction est
     ARTEFACT   NOT RED           portée par un artefact qui existe aujourd'hui."
                                     The predicate this needs is WHICH artefact of
                                     WHICH conjunct is "porté", and the document
                                     does not write it down anywhere: the split
                                     is a judgement about the criterion's clauses,
                                     not a string. MEASURED, this stratum is not
                                     empty: the `A5` entry names `macro_expand`
                                     and three cap names and NO file path, so an
                                     honest reading of :51-52 cannot be turned into
                                     a red without a hand-written list of what
                                     counts as an artefact. It is printed, per row.
  R10 DATED-SCOPE           :62-65  "Toute portée de mesure est écrite DANS
     NOT CHECKED                  l'entrée, avec sa date." A date that has aged
                                   out is a claim about a PAST tree; proving it
                                   is not the job of a reader of this file, and
                                   guessing would be the invented rule this header
                                   refuses to invent.

SCOPE, PRINTED EVERY RUN, because a check that does not say what it did not
read is not a check.
  READ        docs/status/ntasm-completion.md: the two verdict tables, and the section
              "Ce qui a été vérifié, et ce qui manque" -- that section ONLY. The
              "Historique des lignes" section below it holds the FORMER cell
              texts verbatim, and they are quoted evidence, not current
              verdicts; an instrument that walked them would report every
              retraction as a contradiction, which is precisely what :289-292
              records happening once already.
  OPENED      every path an entry names, relative to the repo root, for R5. The
              count is printed: an artefact-resolution stratum that is never
              counted is a stratum nobody can audit.
  NOT READ    the whole document text for verdicts. A verdict word outside a
              verdict cell is prose, and prose is not a verdict.

EXIT CODES. 0 pass. 1 a FINDING. 2 REFUSED.

Run: verdict_check.py [--selftest] [--doc PATH] [--root PATH]
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOC_REL = "docs/status/ntasm-completion.md"

# THE VOCABULARY, closed and quoted from the document :45-46, accents included.
# Nothing else may appear in a verdict cell; a cell holding a word outside this
# tuple is not a verdict cell at all, and that is R1.
VOCAB = ("livré", "partiel", "bloqué", "non commencé")
VOCAB_PAT = re.compile(r"\b(livré|partiel|bloqué|non commenc\w*)\b")

# THE POPULATION, declared rather than inferred. Ten requirement IDs (:78-89) and
# the five "Résultats à prouver" rows (:176-180). A row is matched by its FIRST
# cell against these names; nothing else in the document can become a row.
IDS = ["A%d" % i for i in range(1, 11)]
RESULTS = ("Assembleur S0 complet", "Auto-hébergement", "NTASM typé",
           "Améliorations vérifiées", "Retrait du producteur étranger")

# THE SECTION BOUNDARIES. Read from the document's own headings, not from line
# numbers, because a line number is a dated fact about a file that changes. The
# two verdict tables are NOT under one heading: the acceptance matrix is under
# "Acceptation obligatoire de B2.1" (:78) and the results table under
# "Résultats à prouver" (:174), so the row span is the UNION of the two, from
# the first to the evidence section. Reading only the results table -- which is
# what the first version of this instrument did, and it reported rows=5 -- is a
# POPULATION of the wrong size that still looks like a population.
SEC_ACCEPT = "## Acceptation obligatoire de B2.1"
SEC_VERDICT_RULES = "## Résultats à prouver"
SEC_ENTRIES = "## Ce qui a été vérifié, et ce qui manque"
SEC_HISTORY = "## Historique des lignes"

# A results row's entry heading is `**<name> — <word>.**` -- the word is bounded
# by the closing bold marker, not by the end of the line. Parsing it as "the
# rest of the line" made every entry heading disagree with its row, which is the
# "uniform distribution" shape AGENTS.md:165-182 warns about: an instrument
# reddens on a parsing artefact and the red looks like a finding about the doc.
RESULT_HEAD = re.compile(r"^\*\*\s*(?P<k>[^*—]+?)\s+—\s+(?P<w>[^*]+?)\.?\*\*")

# THE RESERVE VOCABULARY of R4, quoted from the four words the document itself
# uses to name what is not closed: "Ce qui manque" (:194, :206, :210, :214, :230,
# :234, :236, :238, :242), "Réserve" (:198), "réserve" (:198, :240), "NON
# résolue" (:198), "non résolue", "désaccord" (:202, :218 -- a disagreement the
# entry records between the cell and the tree, which a "livré" also cannot carry),
# and "n'est pas" (:198, :226). Every one of these was read off a CURRENT entry of
# this document; none of them was invented.
RESERVE_PAT = re.compile(
    r"Ce qui manque|r[ée]serve|NON r[ée]solue|non r[ée]solue|"
    r"d[ée]saccord|n'est pas|n'est pas ferm"
)

# WHAT COUNTS AS A COMMAND OR AN ARTEFACT for R3, declared rather than inferred,
# because a predicate nobody wrote down is a rumour carrying a category's name.
#   ARTEFACT_PATH  a backticked token, line suffix and ellipsis stripped, that
#                  resolves on THIS tree. This is the strong form.
#   DIGEST         a hex run of >= 6 characters, with or without a trailing
#                  ellipsis: the document names EFI artefacts by sha256 prefix
#                  (:222 "82826f45...", :236), which is a NAMED artefact whose
#                  bytes are not in the repository. Counted, resolved=false.
#   COMMAND        a backticked bare word with no slash, no dot-extension and no
#                  colon: a gate name or a tool (`grep`, `stub_table`,
#                  `macro_expand`, `layout_audit`) is a command one can run.
# A citation `path:line` resolves to ARTEFACT_PATH with the suffix stripped, so a
# citation to a file that no longer exists is NOT a named artefact -- which is the
# point: the document's rule asks for an artefact that exists.
BACKTICK = re.compile(r"`([^`\n]+)`")
DIGEST = re.compile(r"^[0-9a-f]{6,}\.?…?$")
CITE = re.compile(r"^(?P<p>[^:]+):(?P<l>\d+)(-\d+)?$")


class Refused(Exception):
    pass


def cells(line):
    """Markdown cells of a table row. An ESCAPED PIPE is not a delimiter, for the
    reason the registry's own doc_cells gives: a naive split on `|` reads a row
    carrying an inline `|` as more rows than the table has, and reports every
    cell state empty -- an instrument that sees nothing prints nothing red."""
    out, cur, i = [], [], 0
    while i < len(line):
        if line[i] == "|" and not (i > 0 and line[i - 1] == "\\"):
            out.append("".join(cur))
            cur = []
        else:
            cur.append(line[i])
        i += 1
    out.append("".join(cur))
    if out and not out[0].strip():
        out = out[1:]
    if out and not out[-1].strip():
        out = out[:-1]
    return out


def section(lines, start_pred, end_pred=None):
    """The half-open span of lines between two headings, found BY THE HEADING."""
    a = None
    for n, l in enumerate(lines):
        if a is None:
            if start_pred(l):
                a = n
        elif end_pred(l):
            return a, n
    return a, len(lines) if a is not None else None


def is_h2(l):
    return l.startswith("## ") and not l.startswith("### ")


def has_h2(s):
    return lambda l: l.strip() == s


def is_hist(l):
    return l.startswith("## ") and "Historique des lignes" in l


def clean_path(tok):
    """A backticked token reduced to the path it names, or None."""
    t = tok.strip().strip(".,;:()[]")
    t = t.replace("…", "")
    if not t:
        return None
    m = CITE.match(t)
    if m:
        t = m.group("p")
    if "/" not in t and "." not in t:
        return None
    return t.strip()


def naming(entry, root):
    """What one evidence entry NAMES. Returns (has_command, has_artefact,
    resolved, unresolved, digests).

    `resolved` are named paths that EXIST on this tree; `unresolved` are named
    paths that do not, and they are printed rather than dropped: a name that no
    longer resolves is a fact about this tree, and an instrument that keeps it
    silent is the "0 desaccords / 124 silences" shape AGENTS.md:165-182 warns
    looks like a perfect measurement."""
    has_cmd = has_art = False
    resolved, unresolved, digests = [], [], []
    for tok in BACKTICK.findall(entry):
        p = clean_path(tok)
        if p is not None:
            has_art = True
            if os.path.exists(os.path.join(root, p.replace("/", os.sep))):
                resolved.append(p)
            else:
                unresolved.append(p)
            continue
        t = tok.strip()
        if DIGEST.match(t):
            digests.append(t)
            has_art = True
            continue
        if (t and "/" not in t and "." not in t and ":" not in t
                and not VOCAB_PAT.fullmatch(t) and not t.startswith("-")):
            has_cmd = True
    return has_cmd, has_art, resolved, unresolved, digests


def read_rows(lines, lo, hi):
    """id/name -> (verdict_cell, line_no) over the two verdict tables."""
    rows, order = {}, []
    for n in range(lo, hi):
        line = lines[n]
        if not line.startswith("|"):
            continue
        c = cells(line)
        if len(c) < 3:
            continue
        key = c[0].strip()
        if key in ("ID", "Résultat") or key not in IDS and key not in RESULTS:
            continue
        if key in rows:
            continue
        rows[key] = (c[1].strip(), n + 1)
        order.append(key)
    return rows, order


def read_entries(lines, lo, hi):
    """The evidence entries of the CURRENT section, keyed by row id.

    A requirement's entry is a `### <ID> — <word>` heading followed by its
    paragraphs. A results row's entry is the bold `**<name> — <word>.**`
    paragraph :234-242 uses, and its OWN paragraph is part of the entry -- the
    word and the first sentences of the evidence sit on that line, so an entry
    body that starts at the NEXT line drops the evidence and keeps the heading.

    The terminator is the next entry start or the next heading -- never a LINE
    COUNT, because a line count is a dated fact about a file that changes."""
    ents, order, starts = {}, [], []
    for n in range(lo, hi):
        l = lines[n]
        if l.startswith("### "):
            body = l[4:].strip()
            for k in IDS:
                if body.startswith(k + " —"):
                    starts.append((n, k, body[len(k) + 2:].strip()))
                    break
        else:
            m = RESULT_HEAD.match(l)
            if m and m.group("k").strip() in RESULTS:
                starts.append((n, m.group("k").strip(), m.group("w").strip()))
    for i, (n, k, word) in enumerate(starts):
        end = starts[i + 1][0] if i + 1 < len(starts) else hi
        chunk = []
        for m in range(n, end):
            t = lines[m]
            if m > n and (t.startswith("#") or RESULT_HEAD.match(t)):
                break
            chunk.append(t)
        body = "\n".join(chunk).strip()
        ents[k] = {"word": word, "body": body, "line": n + 1}
        order.append(k)
    return ents, order


def check(path, doc, root, verbose=True):
    lines = doc.split("\n")
    findings = []
    queue = []

    # The row span is the UNION of the two tables' sections, for the reason the
    # SEC_ACCEPT comment gives: they are not under one heading.
    a, b = section(lines, has_h2(SEC_ACCEPT), has_h2(SEC_ENTRIES))
    if a is None:
        raise Refused("section_absent=%r" % SEC_ACCEPT)
    if b is None:
        raise Refused("section_absent=%r" % SEC_ENTRIES)
    ea, eb = section(lines, has_h2(SEC_ENTRIES), is_hist)
    if ea is None:
        raise Refused("section_absent=%r" % SEC_ENTRIES)


    rows, order = read_rows(lines, a, b)
    ents, eorder = read_entries(lines, ea, eb)
    # ---- R8: close the population, or refuse. A missing ID means B2.1 is not
    # delivered (:164), and a check that cannot see its own population has no
    # right to print "findings=0".
    for k in IDS:
        if k not in rows:
            findings.append("R8 NO-ROW %s has no row in the acceptance table; the "
                            "document's rule :164 makes a missing ID a delivery "
                            "blocker, and an absent row cannot be falsified"
                            % k)
    for k in RESULTS:
        if k not in rows:
            findings.append("R8 NO-ROW %r has no row in the results table" % k)
    if rows and len([k for k in order if k in IDS]) != len(IDS):
        findings.append("R8 ROW-COUNT acceptance table carries %d rows, not %d"
                        % (len([k for k in order if k in IDS]), len(IDS)))
    if rows and len([k for k in order if k in RESULTS]) != len(RESULTS):
        findings.append("R8 ROW-COUNT results table carries %d rows, not %d"
                        % (len([k for k in order if k in RESULTS]), len(RESULTS)))

    opened_resolved, opened_absent = 0, 0

    for k in order:
        verdict, line_no = rows[k]
        # ---- R1: the cell is a verdict at all.
        if verdict not in VOCAB:
            findings.append("R1 NOT-IN-VOCABULARY %s:%d verdict cell is %r; the "
                            "vocabulary is closed at :45-46 -- %s"
                            % (doc_name(path), line_no, verdict, " / ".join(VOCAB)))
            continue
        # ---- R2: exactly one word per row.
        extra = sorted(set(w for w in VOCAB_PAT.findall(lines[line_no - 1])
                           if w != verdict))
        if extra:
            findings.append("R2 TWO-VERDICTS %s:%d the %s row reads %r and also "
                            "carries %s; :45-46 gives a row EXACTEMENT UN mot"
                            % (doc_name(path), line_no, k, verdict, ", ".join(extra)))
        # ---- R7: the entry exists, says the same word, and is claimed once.
        if k not in ents:
            findings.append("R7 NO-ENTRY %s is filed as %r and has no evidence "
                            "entry in the current section; :184 requires one entry "
                            "per row, and the entry is where the word becomes "
                            "falsifiable" % (k, verdict))
            continue
        ent = ents[k]
        if ent["word"] != verdict:
            findings.append("R7 ENTRY-DISAGREES %s row says %r but its entry "
                            "heading (line %d) says %r"
                            % (k, verdict, ent["line"], ent["word"]))
            continue
        body = ent["body"]
        cmd, art, resolved, unresolved, digests = naming(body, root)
        opened_resolved += len(resolved)
        opened_absent += len(unresolved)

        # ---- R3: BACKED. The document's one mechanical rule.
        if not cmd and not art and verdict != "bloqué":
            findings.append("R3 BACKED-CONTRADICTED %s:%d reads %r and its entry "
                            "names NEITHER a command NOR an artefact; the rule at "
                            ":185-186 is that such an entry forces its row to "
                            "`bloqué`, never `partiel`"
                            % (k, line_no, verdict))
        # ---- R4: `livré` leaves no named reserve (:49-50).
        if verdict == "livré":
            # EVERY reserve the entry names is printed, not the first one found.
            # The first version reported the leftmost match, which on A8 is
            # "n'est pas" from « le critère n'est pas la quatrième obligation » --
            # a true statement of the wrong strength, printed in place of the
            # entry's own « Ce qui manque, nommé ». A finding that quotes the
            # weakest token its evidence contains reads as a false alarm.
            hits = []
            for m in RESERVE_PAT.finditer(body):
                if m.group(0) not in hits:
                    hits.append(m.group(0))
            if hits:
                findings.append("R4 LIVRE-CONTRADICTED %s says 'livré' and its own "
                                "entry says %s; :49-50 is that `livré` leaves NO "
                                "réserve nommée"
                                % (k, ", ".join(repr(h) for h in hits[:6])))
        # ---- R5: `non commencé` and an artefact that EXISTS (:58). The one rule
        # that opens the tree rather than the text.
        if verdict == "non commencé" and resolved:
            findings.append("R5 NON-COMMENCE-CONTRADICTED %s says 'non commencé' "
                            "and its entry names %s, which EXISTS on this tree; "
                            ":58 defines `non commencé` as no artefact of the "
                            "requirement existing" % (k, ", ".join(resolved[:3])))
        # ---- R6: `bloqué` must say what is missing, not what was tried (:55-57).
        if verdict == "bloqué" and "Ce qui manque" not in body:
            findings.append("R6 BLOQUE-NO-MISSING %s is 'bloqué' and its entry does "
                            "not say what is missing; :55-57 requires the line to "
                            "say what is missing and NOT what was tried" % k)

        # ---- the two QUEUE strata, printed with their reason (:51-52, :62-65).
        if verdict == "partiel" and not resolved and unresolved:
            queue.append("R9 QUEUE %s is 'partiel' and its entry names NO artefact "
                         "that resolves on this tree (%s name the same paths); "
                         ":51-52 asks whether a conjunct is porté by an artefact "
                         "that exists, and the document does not write down WHICH "
                         "artefact of WHICH conjunct, so this is not made red"
                         % (k, ", ".join(sorted(set(unresolved))[:3])))
        if unresolved:
            queue.append("NAMED-UNRESOLVED %s names %s, which does not exist on "
                         "this tree -- reported, not red: a name that stopped "
                         "resolving is a fact, and an instrument that keeps it "
                         "silent looks like a clean sweep"
                         % (k, ", ".join(sorted(set(unresolved))[:4])))
        if digests:
            queue.append("NAMED-DIGEST %s names %d digest artefact(s) (%s): named, "
                         "counted, never opened -- the bytes are not in the tree"
                         % (k, len(digests), ", ".join(sorted(set(digests))[:2])))

    # ---- R7 once more, for the entries that claim a row that has none.
    for k in eorder:
        if k not in rows:
            findings.append("R7 ENTRY-ORPHAN %s has an evidence entry at line %d "
                            "but no verdict row, so the entry is evidence for a "
                            "verdict that does not exist" % (k, ents[k]["line"]))

    if verbose:
        print("matrix %s" % doc_name(path))
        for k in order:
            if k in rows:
                v, n = rows[k]
                w = ents[k]["word"] if k in ents else "NO-ENTRY"
                print("  %-30s row=%-12s entry=%-12s row_line=%d entry_line=%d"
                      % (k, v, w, n, ents[k]["line"] if k in ents else -1))
        print("  SCOPE read=the_two_verdict_tables_between=%r_and=%r plus=%r "
              "ONLY section_absent=0 history_section_read=no (it holds the former "
              "cells, and :289-292 records what reading it as current verdicts "
              "would do) verdict_words_read_only_from_a_verdict_cell_or_an_entry_"
              "heading"
              % (SEC_ACCEPT, SEC_ENTRIES, SEC_ENTRIES))
        print("  SCOPE opened_for_R3_and_R5 named_paths_resolved=%d "
              "named_paths_absent=%d note=resolved_against_the_repo_root_"
              "digest_artefacts_are_named_counted_and_never_opened "
              "command_named_by_a_bare_backticked_word" % (opened_resolved,
                                                            opened_absent))
    for q in queue:
        print("  QUEUE %s" % q)
    if not queue:
        print("  QUEUE n=0 (every entry names a command or an artefact; the two "
              "refused strata R9 and R10 had nothing to refuse on)")
    for f in findings:
        print("  FINDING %s" % f)
    if not findings:
        print("  FINDING n=0 (every row's verdict agrees with its evidence entry, "
              "and every entry names something a reader could run or open)")
    print("VERDICT_CHECK rows=%d findings=%d %s"
          % (len(rows), len(findings), "OK" if not findings else "RED"))
    return 1 if findings else 0


def doc_name(path):
    try:
        return os.path.relpath(path, ROOT).replace(os.sep, "/")
    except ValueError:
        return path


# --------------------------------------------------------------------------
# The selftest. One synthetic document per rule, each built to be GREEN on the
# rules it is not breaking, so a red can only come from the rule named in it. A
# selftest whose fixtures are all-red proves nothing about which rule bites.
# --------------------------------------------------------------------------
FIX = """# Recette

## Acceptation obligatoire de B2.1

| ID | Verdict | Livrable |
|---|---|---|
| A1 | {a1} | y |
| A2 | {a2} | y |
| A3 | {a3} | y |
| A4 | {a4} | y |
| A5 | {a5} | y |
| A6 | {a6} | y |
| A7 | {a7} | y |
| A8 | {a8} | y |
| A9 | {a9} | y |
| A10 | {a10} | y |

## Résultats à prouver

| Résultat | Verdict | Autorité |
|---|---|---|
| Assembleur S0 complet | {v0} | x |
| Auto-hébergement | {v1} | x |
| NTASM typé | {v2} | x |
| Améliorations vérifiées | {v3} | x |
| Retrait du producteur étranger | {v4} | x |

## Ce qui a été vérifié, et ce qui manque

### A1 — {a1}

`legacy/tools/coldproof/verdict_check.py` est cité, sha `25d8e4b8\u2026`. **Ce qui manque :** rien ici.

### A2 — {a2}

`legacy/tools/coldproof/verdict_check.py` est cité. **Ce qui manque :** rien.

### A3 — {a3}

`legacy/tools/coldproof/verdict_check.py` est cité. **Ce qui manque :** rien.

### A4 — {a4}

`legacy/tools/coldproof/verdict_check.py` est cité. **Ce qui manque :** rien.

### A5 — {a5}

`legacy/tools/coldproof/verdict_check.py` est cité. **Ce qui manque :** rien.

### A6 — {a6}

`legacy/tools/coldproof/verdict_check.py` est cité. **Ce qui manque :** rien.

### A7 — {a7}

`legacy/tools/coldproof/verdict_check.py` est cité. **Ce qui manque :** rien.

### A8 — {a8}

`legacy/tools/coldproof/verdict_check.py` est cité. **Ce qui manque :** rien.

### A9 — {a9}

`legacy/tools/coldproof/verdict_check.py` est cité. **Ce qui manque :** rien.

### A10 — {a10}

`legacy/tools/coldproof/verdict_check.py` est cité. **Ce qui manque :** rien.

### Résultats à prouver — une entrée par ligne

**Assembleur S0 complet — {v0}.** `stub_table` est cité. **Ce qui manque :** rien.

**Auto-hébergement — {v1}.** `stub_table` est cité. **Ce qui manque :** rien.

**NTASM typé — {v2}.** `stub_table` est cité. **Ce qui manque :** rien.

**Améliorations vérifiées — {v3}.** `stub_table` est cité. **Ce qui manque :** rien.

**Retrait du producteur étranger — {v4}.** `stub_table` est cité. **Ce qui manque :** rien.

## Historique des lignes — non courant, conservé intégralement

### A1 — texte de la cellule « Preuve exigée », au 30 septembre 2026

Ancienne cellule portant le mot `livré` et la réserve `encode_lea` fermée. Ce mot
est CITÉ et non courant : le lire ici comme un verdict serait une fausse alerte.
"""

GREEN = {"v0": "partiel", "v1": "partiel", "v2": "partiel", "v3": "partiel",
         "v4": "partiel"}
for _i in range(1, 11):
    GREEN["a%d" % _i] = "partiel"

# The entry bodies, spelled once, so a case that rewrites one of them rewrites
# the SAME text the case above wrote. A replace() on a string that no longer
# exists silently does nothing, and a negative control that did not apply is the
# failure AGENTS.md:250-261 names: the needle survived its own perturbation.
E_A1 = "### A1 — {a1}\n\n`legacy/tools/coldproof/verdict_check.py` est cité, sha `25d8e4b8\u2026`. **Ce qui manque :** rien ici."
E_A2 = "### A2 — {a2}\n\n`legacy/tools/coldproof/verdict_check.py` est cité. **Ce qui manque :** rien."


def fix(**over):
    d = dict(GREEN)
    d.update(over)
    return FIX.format(**d)



def selftest():
    import tempfile
    bad = 0
    cases = [
        # (name, document, expect_rc, expected rule token)
        ("baseline-green", fix(), 0, None),
        ("R1-not-in-vocabulary", fix(a1="quasi parti el"), 1, "R1"),
        # The row line must CARRY a second word, not merely be read as one: R2
        # reads the row's own line, and `| A1 | livré | y |` carries exactly
        # one -- which is the control that makes the red mean something.
        ("R2-two-words-in-one-row",
         fix(a1="livré").replace("| A1 | livré | y |",
                                "| A1 | livré | partiel puis non commencé |"),
         1, "R2"),
        ("R2-control-one-word-in-the-row", fix(a1="livré"), 1, "R4"),
        ("R4-livre-with-a-reserve", fix(a1="partiel", a2="livré"), 1, "R4"),
        ("R5-non-commence-with-a-live-artefact",
         fix(a1="non commencé"), 1, "R5"),
        ("R6-bloque-without-what-is-missing",
         fix(a1="partiel", a2="bloqué",
             ) .replace("### A2 — bloqué\n\n`legacy/tools/coldproof/verdict_check.py` "
                        "est cité. **Ce qui manque :** rien.",
                        "### A2 — bloqué\n\n`legacy/tools/coldproof/verdict_check.py` "
                        "est cité. Trois campagnes ont été tentées."), 1, "R6"),
        ("R7-entry-disagrees",
         fix(a1="partiel").replace("### A1 — partiel", "### A1 — bloqué"), 1, "R7"),
        ("R7-no-entry",
         fix(a1="partiel").replace("### A1 — partiel\n\n", ""), 1, "R7"),
        ("R3-backed-with-nothing-named",
         fix(a1="partiel", a2="partiel",
             ).replace("### A2 — partiel\n\n`legacy/tools/coldproof/verdict_check.py` "
                       "est cité. **Ce qui manque :** rien.",
                       "### A2 — partiel\n\nLa ligne dit ce qui manque."), 1, "R3"),
        ("R3-backed-bloque-is-allowed",
         fix(a1="bloqué",
             ).replace("### A1 — bloqué\n\n`legacy/tools/coldproof/verdict_check.py` "
                       "est cité. **Ce qui manque :** rien.",
                       "### A1 — bloqué\n\nRien n'est mesurable aujourd'hui, et "
                       "voici pourquoi."), 0, None),
        ("R8-row-removed",
         fix().replace("| A5 | partiel | y |\n", ""), 1, "R8"),
    ]
    with tempfile.TemporaryDirectory(prefix="verdict_check.") as td:
        p = os.path.join(td, "doc.md")
        for name, text, want_rc, want_tok in cases:
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(text)
            import io
            import contextlib
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = check(p, text, ROOT, verbose=False)
            out = buf.getvalue()
            tok_ok = (want_tok is None) or (want_tok in out)
            if rc != want_rc or not tok_ok:
                bad += 1
                print("SELFTEST_FAIL %s rc=%d want_rc=%d token=%s want_token=%s"
                      % (name, rc, want_rc, want_tok, tok_ok))
    # A refusal is not a pass: a document without the sections must exit 2.
    import io
    import contextlib
    with tempfile.TemporaryDirectory(prefix="verdict_check.") as td:
        p = os.path.join(td, "empty.md")
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write("# rien\n")
        buf = io.StringIO()
        rc = -1
        with contextlib.redirect_stdout(buf):
            try:
                check(p, "# rien\n", ROOT, verbose=False)
            except Refused as e:
                rc = 2
        if rc != 2:
            bad += 1
            print("SELFTEST_FAIL refuse rc=%d want_rc=2" % rc)
    print("VERDICT_CHECK_SELFTEST cases=%d failed=%d" % (len(cases) + 1, bad))
    return 1 if bad else 0


def main(argv):
    if "--selftest" in argv:
        return selftest()
    doc = os.path.join(ROOT, DOC_REL)
    root = ROOT
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--doc" and i + 1 < len(argv):
            doc = os.path.abspath(argv[i + 1]); i += 1
        elif a.startswith("--doc="):
            doc = os.path.abspath(a.split("=", 1)[1])
        elif a == "--root" and i + 1 < len(argv):
            root = os.path.abspath(argv[i + 1]); i += 1
        elif a.startswith("--root="):
            root = os.path.abspath(a.split("=", 1)[1])
        i += 1
    if not os.path.isfile(doc):
        print("VERDICT_REFUSED reason=document_absent doc=%s -- a verdict nobody "
              "could read is not a verdict nobody falsified" % doc)
        return 2
    try:
        with open(doc, encoding="utf-8") as f:
            return check(doc, f.read(), root)
    except Refused as e:
        print("VERDICT_REFUSED reason=%s" % e)
        return 2


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except Refused as e:
        print("VERDICT_REFUSED reason=%s" % e)
        sys.exit(2)
