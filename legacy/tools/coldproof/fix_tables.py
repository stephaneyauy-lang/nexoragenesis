#!/usr/bin/env python3
"""
Repair markdown table geometry in the two B2.1 documents.

Two defects, both found by the DOC-TABLE-* checks in tests_ntasm_registry.c:

  1. a row split across physical lines -- a continuation line that does not begin
     with '|' leaves the table, so the row above renders truncated;
  2. a row carrying more cells than its header, so every GFM renderer DROPS the
     last cell. This is the serious one: the appended "État au ..." text landed in
     a fourth cell that no reader ever saw.

Both are repaired by merging, never by deleting. A cell's text is preserved; only
the '|' separators that created the extra cells are removed.

The header's cell count is the oracle. Nothing here decides what a cell MEANS --
it only makes the row's structure match the header it sits under.
"""
import sys, re, hashlib

def cells(line):
    """Split a table row into cells, honouring backslash-pipe escapes and code spans."""
    s = line.strip()
    if not s.startswith('|'):
        return None
    # Strip BOTH edge pipes before splitting. Keeping the leading one and
    # dropping only the trailing produced a phantom empty FIRST cell, so
    # '|---|---|---|' parsed as four cells and no separator was ever recognised
    # -- which is why two versions of this script were a no-op.
    if s.endswith('|'):
        s = s[:-1]
    if s.startswith('|'):
        s = s[1:]
    out, cur, esc, in_code = [], [], False, False
    for ch in s:
        if esc:
            cur.append(ch); esc = False; continue
        if ch == '\\':
            cur.append(ch); esc = True; continue
        if ch == '`':
            in_code = not in_code
            cur.append(ch); continue
        if ch == '|' and not in_code:
            out.append(''.join(cur).strip()); cur = []; continue
        cur.append(ch)
    out.append(''.join(cur).strip())
    return out

def is_sep(cells_):
    return bool(cells_) and all(re.fullmatch(r':?-{2,}:?', c or '') for c in cells_)

def is_continuation(line):
    """A paragraph line that continues the row above. A list item is NOT a
    continuation -- and '**bold**' is not a list item either, which a bare
    startswith('*') test gets wrong. That mistake is why the first version of
    this script was a no-op."""
    s = line.lstrip()
    if not s or s.startswith(('#', '>', '|')):
        return False
    if re.match(r'^([-*+])\s', s):
        return False
    if re.match(r'^([-*+]){2,}\s*$', s):
        return False
    return True

def main(path):
    raw = open(path, 'rb').read()
    before = hashlib.sha256(raw).hexdigest()
    text = raw.decode('utf-8')
    lines = text.split('\n')

    out, i, fixed_split, fixed_wide, fixed_blank = [], 0, 0, 0, 0
    while i < len(lines):
        ln = lines[i]
        c = cells(ln)
        if c is None or not c or not is_sep(c) or i == 0:
            out.append(ln); i += 1; continue

        header = cells(lines[i - 1])
        ncol = len(header)
        out.append(ln)          # the separator
        i += 1
        # consume the body
        # A body line that is not a row is a CONTINUATION, not the end of the
        # table. Breaking here is what made the first version a no-op: a split
        # row's continuation is by definition not a row.
        while i < len(lines):
            c = cells(lines[i])
            if c and is_sep(c):
                break
            if c is None or not c:
                # A blank line inside a table body ends it for GFM and for this
                # tool. If a row follows, the blank is the defect: drop it.
                if not lines[i].strip():
                    j = i + 1
                    while j < len(lines) and not lines[j].strip():
                        j += 1
                    if j < len(lines) and cells(lines[j]) and not is_sep(cells(lines[j])):
                        fixed_blank += 1
                        i = j
                        continue
                    break
                if not is_continuation(lines[i]):
                    break
                out[-1] = out[-1].rstrip().rstrip('|').rstrip() + ' ' + lines[i].strip()
                fixed_split += 1
                i += 1
                continue
            # a row: normalise its cell count to the header's
            if len(c) > ncol:
                # merge the surplus into the LAST column, which is where an
                # appended status cell belongs; never drop its text
                merged = ' '.join(c[ncol - 1:]).replace('||', '|')
                c = c[:ncol - 1] + [merged]
                fixed_wide += 1
            out.append('| ' + ' | '.join(c) + ' |')
            i += 1


    data = '\n'.join(out).encode('utf-8')
    if data == raw:
        print(f'{path}: no change  sha256 {before[:16]}')
        return
    open(path, 'wb').write(data)
    print(f'{path}: joined {fixed_split} continuation line(s), '
          f'merged {fixed_wide} over-wide row(s), dropped {fixed_blank} blank line(s)')
    print(f'  sha256 {before[:16]} -> {hashlib.sha256(data).hexdigest()[:16]}')

for p in sys.argv[1:]:
    main(p)
