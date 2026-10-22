#!/usr/bin/env python3
"""The structural repairs that are mechanical, with the geometry check as oracle.

Three defects, three different repairs -- which is why they are not one rule:

  1. two header-less two-column runs in the spec are definition lists the author
     wrote as rows. A renderer needs a header, so give them one that names the
     columns truthfully rather than deleting the rows.
  2. a sentence that DENIES a section exists contains the token the resolver
     reads as a live cross-reference. The claim is preserved verbatim; only the
     token changes, because a claim is not a cross-reference.
  3. a prose line ending in an unescaped pipe is a cell that lost its row. The
     delimiter is the defect, so the delimiter goes.
"""
import re

# --- 1. the two header-less runs in spec/ntasm/ntasm.md ------------------------------
p = 'spec/ntasm/ntasm.md'
s = open(p, encoding='utf-8').read()
hdr = '| effet | instructions |\n|---|---|\n'
for lead in ('| `changes_flags` |', '| `writes_first` |'):
    i = s.find('\n' + lead)
    if i > 0 and '| effet | instructions |' not in s[max(0, i - 60):i]:
        s = s[:i + 1] + hdr + s[i + 1:]
        print('header added above ' + lead[:22])

# --- 2. the denying sentence ----------------------------------------------------
DENY_OLD = '**Il n' + chr(39) + 'y a pas de §17.2.**'
DENY_NEW = '**Il n' + chr(39) + 'y a pas de sous-section 17.2.**'
if DENY_OLD in s:
    s = s.replace(DENY_OLD, DENY_NEW)
    print('denial sentence: the claim is unchanged, the reference token is not a reference')
open(p, 'w', encoding='utf-8').write(s)

# --- 3. a stray cell delimiter on a prose line ---------------------------------
p2 = 'docs/status/ntasm-completion.md'
t = open(p2, encoding='utf-8').read()
out, changed = [], 0
for ln in t.split('\n'):
    st = ln.strip()
    is_row = st.startswith('|')
    is_head = st.startswith('#')
    is_item = re.match(r'^([-*+])\s', st)
    if not is_row and not is_head and not is_item and st.endswith('|') and len(st) > 1:
        out.append(ln.rstrip()[:-1].rstrip())
        changed += 1
    else:
        out.append(ln)
if changed:
    open(p2, 'w', encoding='utf-8').write('\n'.join(out))
print('stray trailing pipe removed from %d prose line(s)' % changed)
