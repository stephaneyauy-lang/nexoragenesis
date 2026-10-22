#!/usr/bin/env python3
"""ink_guard.py — check text before it is sent or written.

The guard that protected MEM.md all session covers one file. The corruptions
that actually cost time left through the OTHER channel: messages sent to lots.
This closes that gap.

A guard is only worth running if it passes clean text. A first version also
flagged standalone Latin words and produced 1308 findings on MEM.md alone,
because quoted source, identifiers and gate output legitimately carry them.
**A tool nobody runs detects nothing.** So only four signals survive, each
chosen because it has no false-positive form in this corpus:

  CJK ideographs and kana      five slipped out of my prose this session
  Cyrillic                     one did, in a quotation
  invisible characters          NBSP, zero-width, soft hyphen — invisible
                                in review, and invisible to a reader too
  DROPPED: a fourth signal that tried to catch a French word fused to an
  English one. It was unsalvageable — `on` is both an English and a French
  word, so « on ne », « et on » and « qu'on ne » produced 56 false findings on
  MEM.md alone. **A guard with false positives is not run, and a guard that is
  not run detects nothing.** It is named here so the next person does not
  rebuild it.

Exit 0 clean. Exit 1 with a per-line report. Exit 2 usage error.
"""
import re
import sys

INVISIBLE = {
    "\u00a0": "NBSP", "\u200b": "ZWSP", "\u200c": "ZWNJ",
    "\u200d": "ZWJ", "\ufeff": "BOM", "\u00ad": "SOFT HYPHEN",
}
# Written as ESCAPES on purpose. A literal table made this guard flag its own
# source the first time it was pointed at itself — and that is the only way
# this particular false positive is ever going to be discovered.

# Written as escapes on purpose: a literal table made this guard flag its own
# source the first time it was pointed at itself, which is the only way that
# particular false positive is ever going to be discovered.


def scan(text):
    problems = []
    for n, line in enumerate(text.splitlines(), 1):
        for ch in line:
            o = ord(ch)
            if 0x2E80 <= o <= 0x9FFF or 0x3040 <= o <= 0x30FF:
                problems.append((n, "CJK", hex(o), line.strip()[:70]))
            elif 0x0400 <= o <= 0x04FF:
                problems.append((n, "CYRILLIC", hex(o), line.strip()[:70]))
            elif ch in INVISIBLE:
                problems.append((n, INVISIBLE[ch], hex(o), line.strip()[:70]))
    return problems


def main(argv):
    if len(argv) < 2:
        sys.stderr.write(__doc__)
        return 2
    bad = 0
    for path in argv[1:]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError as exc:
            sys.stderr.write("  cannot read %s: %s\n" % (path, exc))
            return 2
        found = scan(text)
        if not found:
            print("  CLEAN  %s" % path)
            continue
        bad = 1
        print("  %d PROBLEM(S)  %s" % (len(found), path))
        for n, kind, detail, ctx in found:
            print("    L%-5d %-11s %-12s %s" % (n, kind, detail, ctx))
    return bad


if __name__ == "__main__":
    sys.exit(main(sys.argv))
