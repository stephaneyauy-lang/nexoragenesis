# The three pin discrepancies of the reorganized repository

`VALIDATION.md` asks for it: **"Valider explicitement les trois entrées avant
de mettre à jour leurs empreintes."** This document validates them. **The pins
are not updated here**: they are the owner's decision, and the brief says to
preserve the three discrepancies rather than blindly update them.

Everything below is re-derived by a read-only tool:

```bash
python tools/validation/a8_pin_discrepancies.py
```

It reads the pin table of `scripts/ntbuild.sh`, the bytes on disk, the
history of this repository and, when it is available, the campaign's
pre-reorganization copy of the same sources. It writes nothing, and it exits 1
while a discrepancy remains.

## What the snapshot says today

```
$ bash scripts/ntbuild.sh pins --verify
NTBUILD_PINS_VERIFY ok=32 bad=3 rows=34
```

The three entries are:

| # | entry | what the snapshot says |
|---|---|---|
| 1 | `compiler/c/nova/frontend/nova.c` | the declared hash is older than the content |
| 2 | `compiler/c/nova/frontend/nova.h` | the declared hash is older than the content |
| 3 | `compiler/c/ntasm/analysis/seed_reachability.h` | a required header with no declared hash |

**Entry 3 carries a stale path in the validation document.** The file is
required (a granted source includes it) and it is in the tree, but at
`compiler/c/nova/analysis/seed_reachability.h`, not under
`compiler/c/ntasm/analysis/`. The tool finds it by following the includes of
the granted sources, so it does not depend on the path being written down
anywhere.

## Entry 1 — `compiler/c/nova/frontend/nova.c`

| | sha256 | bytes |
|---|---|---|
| the pin declares | `62ec6ffebb45a1b5…` | |
| on disk | `afb351098c806b61…` | 133 449 |
| the campaign's pre-reorganization copy | `2aa799d006eea6db…` | 133 522 |

- The pin **matches no revision of this file in the history of this
  repository**: the six revisions the history holds are `9a9c243b…`,
  `b0e9d5d2…`, `64c4c8a5…` and `b6c60d8c…`. The pin is therefore **older
  than this repository's history of the file** — it was taken in the campaign,
  whose tree carried its own edits after the last revision here.
- Against the campaign's copy, the file differs by **30 lines, and none of
  them is code**: three `#include` paths and the comment references to the old
  tree (`toolchain/ntasm-nova` → `compiler/nova`, `bootstrap/quarantine/c/`
  → `compiler/c/`).

**Verdict: the pin is stale, and the current content is the campaign's file
with its paths adapted. Nothing else changed.** The tool prints
`paths-and-comments-only`.

## Entry 2 — `compiler/c/nova/frontend/nova.h`

| | sha256 | bytes |
|---|---|---|
| the pin declares | `84db76383bbf7ad5…` | |
| on disk | `5825782a73eecda2…` | 2 045 |
| the campaign's pre-reorganization copy | `ac58b1b1575c404a…` | 2 024 |

- The pin **matches a real revision of this repository**:
  `87472cd778d320726d8222f639007b17887d73d9`, the file as it was before the
  reorganization (2026-09-13, 1 018 bytes). The pin is the pre-reorg
  revision, exactly.
- Against the campaign's copy, the file differs by **2 lines, and none of them
  is code**: one `#include` path.

**Verdict: the pin designates a real, older revision; the current content is
that file with its include adapted. Nothing else changed.** The tool prints
`paths-and-comments-only` and names the revision.

## Entry 3 — `compiler/c/nova/analysis/seed_reachability.h`

- The file is **in the tree** (16 637 bytes,
  `d49f9b32ef097c97…`) and it is **required**: the granted sources include it
  (`#include "../analysis/seed_reachability.h"`).
- It has **no row in the pin table**: the table goes from the
  `compiler/c/ntasm/analysis/conformance.*` rows straight past it.
- The campaign's copy is `bootstrap/quarantine/c/nova/seed_reachability.h`
  (16 594 bytes), so the reorganization moved it like the rest.

**Verdict: this is a missing pin row, not a wrong digest.** The tool finds it
by following the includes of the granted sources, and reports it under
`unpinned`.

## What follows, and what does not

- The three discrepancies are **explained**, not repaired: two pins are older
  than the files they name, and one required header is not pinned at all.
- **The pins stay as they are.** Updating them is the owner's decision, and
  the brief is explicit: preserve them rather than update them blindly. The
  tool exits 1 while they stand, so the state stays visible.
- The tool is the check a future update would run: after an update it must
  print `"ok": true` and exit 0. Until then, the snapshot's own statement is
  the honest one: 32 ok, 3 bad.
- This does not touch the A8 house build, which grants **no C at all**. It
  concerns the principal build, `scripts/ntbuild.sh`, and the official build
  acceptance that the three discrepancies still block
  (`PUBLICATION.json`: `official_build_accepted: false`).
