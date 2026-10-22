#!/usr/bin/env python3
"""words.py — a vocabulary check built from the project's own text.

The character guard does not catch GLUED WORDS, and glued words are the family
that got through twice tonight: « porteContraigne », « de_course », « GPs »,
« isservelu », « SEUILIL », « wanted ». Each was grammatically wrong and nearly
visually correct.

There is no French lexicon here, and inventing one would be worse than the fault.
But the project ships tens of thousands of lines of its own French, and that text
IS the vocabulary: a token that appears nowhere in the project's prose, is not an
identifier, and is not in the code, did not come from this project's vocabulary.

MEM.md is DELIBERATELY EXCLUDED from that vocabulary. It is the ledger where
faults get quoted verbatim, so a word found only there is usually a fault that was
recorded rather than one that was committed. Including it made the check blind to
its own subject: "porteContraigne", "isservelu" and "attendance" were all in the
vocabulary, because this session wrote them into the ledger before writing them
anywhere else. A policeman that takes its vocabulary from the suspect is not a
policeman.
"""
import collections
import importlib.util
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

PROSE = [
    "docs/status/ntasm-completion.md",
    "docs/ntasm.md",
    "docs/guides/ntasm-cli.md",
    "docs/guides/ntasm-build.md",
    "spec/ntasm/ntasm-s0.md",
    "spec/formats/nxo-v0.md",
    "spec/formats/seed-pe32.md",
    "AGENTS.md",
    "TRUST.md",
    "README.md",
]

CODE_DIRS = ("compiler/c", "compiler/nova", "legacy/tools/coldproof")
CODE_SUFFIX = (".c", ".h", ".nova", ".py", ".sh", ".md")

WORD = re.compile(r"[A-Za-zÀ-ÿŒœ]{4,}")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\s*[\(\[,;=.]|\b[A-Z]{2,}_[A-Z0-9_]+\b")


def root():
    return ROOT


def vocabulary():
    vocab = collections.Counter()
    files = 0
    r = root()
    for rel in PROSE:
        p = r / rel
        if not p.exists():
            continue
        files += 1
        text = p.read_text(encoding="utf-8", errors="replace")
        for w in WORD.findall(text):
            vocab[w.lower()] += 1
    for d in CODE_DIRS:
        base = r / d
        if not base.exists():
            continue
        for p in base.rglob("*"):
            if p.is_file() and p.suffix in CODE_SUFFIX:
                files += 1
                text = p.read_text(encoding="utf-8", errors="replace")
                for w in WORD.findall(text):
                    vocab[w.lower()] += 1
    return vocab, files


def check(vocab, path):
    try:
        text = pathlib.Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return None, "cannot read: %s" % exc
    unknown = collections.Counter()
    for i, line in enumerate(text.splitlines(), 1):
        if IDENT.search(line):
            continue
        for w in WORD.findall(line):
            if w.lower() not in vocab:
                unknown[(i, w)] += 1
    return unknown, None


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    vocab, nfiles = vocabulary()
    if not vocab:
        sys.stderr.write("  vocabulary empty — no corpus read\n")
        return 2
    sys.stderr.write("  VOCABULARY %d tokens, from %d files, MEM.md excluded\n"
                     % (len(vocab), nfiles))
    bad = 0
    for path in argv[1:]:
        unknown, err = check(vocab, path)
        if err:
            sys.stderr.write("  %s: %s\n" % (path, err))
            return 2
        if not unknown:
            print("  CLEAN  %s" % path)
            continue
        bad = 1
        print("  %d UNKNOWN TOKEN(S)  %s" % (len(unknown), path))
        for (i, w), c in sorted(unknown.items())[:15]:
            print("    L%-5d %-24s x%d" % (i, w, c))
    return bad


if __name__ == "__main__":
    sys.exit(main(sys.argv))
