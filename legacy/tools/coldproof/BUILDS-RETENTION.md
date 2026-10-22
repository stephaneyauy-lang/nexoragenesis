# Retention policy — `out/c-bootstrap/builds/`

**Status:** in force since 30 September 2026. **Owner:** `W56PruneBuilds`.

N = 5

**Mechanism:** `legacy/tools/coldproof/prune_builds.sh`. **This document is the contract;
the script is the implementation.** They are cross-checked against each other by
`prune_builds.sh --check-policy`, which exits 3 if the `N` above and the `KEEP=`
in the script disagree.

---

## 1. What this directory is, and what it is not

Every `legacy/tools/coldproof/ngbuild.sh` run creates
`out/c-bootstrap/builds/ngbuild-<HHMMSS>-<pid>/` (`ngbuild.sh:198`). Before this
policy existed, **no code path ever removed an old one.**

Measured on 30 September 2026, before the first prune:

| | |
|---|---|
| entries | **397** |
| size | **33 405 MB** |
| per-run size | 42 MB – 834 MB (measured on 8 consecutive runs) |

This is not housekeeping. Two whole-tree censuses **timed out at 250 s and
280 s** because `out/` holds ~132 411 of the tree's ~136 820 files. A scan that
cannot finish is a scan that cannot report, and the lot that needed those
census numbers got nothing.

**This directory is per-run build output. It is regenerable by re-running the
suite, and nothing indexes it.** That is the whole basis for pruning it, and it
is the project's own rule rather than a preference — `MEM.md` states it
directly:

> *« Un artefact dans un répertoire que rien n'indexe vaut autant qu'un artefact
> supprimé — `out/c-bootstrap/nova/evidence/` est indexé et survit aux vagues ;
> `out/c-bootstrap/layout-probe/` ne l'est pas et personne n'y trouvera dans six
> semaines. »*

**The consequence is absolute and is not a matter of degree: this pruner never
touches `out/c-bootstrap/nova/`.** Not `nova/evidence/`, not `nova/` at all.
That directory is indexed evidence and it survives. The tool refuses to even
accept a path outside `out/c-bootstrap/builds/` as its target.

---

## 2. `N = 5`

**Five most-recent run directories are kept. Every other recognised run
directory is pruned.**

The number and the reason:

- **Five is enough to compare against.** The value of a previous run directory
  is answering *"was this gate green yesterday?"* — a one-step regression check.
  One is the minimum that answers it; five covers the case where the last four
  runs were themselves partial or mid-refactor, which is the normal state of
  this tree.
- **Five is cheap.** Measured: 42–834 MB per run, ~150 MB typical. Five runs is
  **~0.7 GB against a measured 33.4 GB** — a ~97% reduction that still leaves
  the comparison window intact.
- **It is a bound, not a target.** The acceptance for this lot is that growth
  stops being unbounded. Five is the smallest number that leaves a usable
  comparison window and it is the largest number that keeps a full census of the
  tree inside a timeout.

**Adjusting `N`:** edit `KEEP=` in `prune_builds.sh` **and** the `N =` line above,
then run `prune_builds.sh --check-policy`. The tool refuses to prune under a
policy the document and the code disagree about — a retention policy that lives
only in code is a policy a reader has to run something to learn.

---

## 3. What may be deleted: only what has been **positively classified**

An entry is a prune candidate only if **all** of the following hold. Any failure
is a **refusal**, and refusals are printed with their reason.

| # | Requirement | Refusal reason printed |
|---|---|---|
| 1 | It is a direct child of `out/c-bootstrap/builds/` | (the target itself is refused if it is absent, unresolvable, or resolves outside the repo) |
| 2 | It is not a symlink | `symlink` |
| 3 | It is a directory, not a file | `not_a_directory` |
| 4 | Its realpath resolves back inside `builds/` | `resolves_outside_builds` |
| 5 | Its name matches `^ngbuild-[0-9]{6}-[0-9]+$` — **the driver's own grammar**, `ngbuild.sh:198` | `unrecognised_name` |
| 6 | Its PID is **not** a live process | (kept as LIVE, not a refusal) |
| 7 | Its mtime is **older** than `LIVE_MIN_AGE_S` (default 1800 s) | (kept as LIVE, not a refusal) |

Requirement 5 is what protects the entries that are **cited**. Four files under
`out/c-bootstrap/builds/w26reg2/` are named as expected values by a live test —
`tests/c/nova/tests_ntasm_registry.c:6593-6596`. That directory
does not match the run-name grammar, so it is refused, and it stays. A pruner
that deleted "everything old-looking" would have deleted a test's expectations.

---

## 4. Live detection: two independent signals, ANDed

Nine agents share this tree and several are writing into `builds/` at any moment.
Deleting a directory a sibling is mid-build in corrupts its result, and **that is
worse than carrying the bytes** — the resulting failure looks like a gate going
red for no reason. So a directory is treated as live if **either** signal fires,
and pruned only when **both** agree it is dead.

### (a) PID, read out of the directory name

The run directory is *named* `ngbuild-<HHMMSS>-<pid>` by `ngbuild.sh:198`, so the
PID is **in the name**. Checked with `ps -p` and `tasklist //FI "PID eq N"`.

### (b) Age — newest mtime younger than `LIVE_MIN_AGE_S` (default 1800 s)

**This signal exists because (a) is not sufficient on this host, and pretending
otherwise would be the exact defect this project keeps measuring.** The runs
observed writing into `builds/` are WSL-hosted, launched as
`C:\windows\system32\bash.exe legacy/tools/coldproof/ngbuild.sh`. The `$$` baked into
the directory name is therefore a **Linux** PID, and it is **not in the PID
namespace this script can see** — `ps -p` on the Windows side is a *false
negative* for precisely the runs that matter. Signal (b) covers them.

1800 s is chosen against the measured full-suite duration of **~508 s**
(`ngbuild.sh:1493`): it is 3.5× a complete run, so a live run cannot be mistaken
for a corpse.

### Direction of each error

| signal | can it fail… | cost of that failure |
|---|---|---|
| PID | **false positive** — PIDs recycle | a few extra GB kept. Harmless. |
| PID | **false negative** — WSL PID invisible | covered by (b). |
| age | **false positive** — a quiet run still being written | bytes kept. Harmless. |

Every error direction costs **bytes kept**, never a sibling's run. That asymmetry
is the design.

---

## 5. Dry run is the default; `--apply` is not optional

```
legacy/tools/coldproof/prune_builds.sh                 # DRY RUN: full report, deletes nothing
legacy/tools/coldproof/prune_builds.sh --check-policy  # also assert N agrees with this document
legacy/tools/coldproof/prune_builds.sh --apply         # actually prune
```

An unattended `rm -rf` of 33 GB reached through a driver that nine agents run is
not a default worth having. **The default is a report.**

**Delete verification is mandatory.** After `rm -rf`, the directory is checked
for absence and a failure is reported as `PRUNE_FAILED ... still_present_after_rm`.
This is not defensive padding: `coldsuite.sh:9` records that *"`rm -rf` on this
filesystem has been observed NOT to take effect."* A delete that reports success
while the directory is still there is a silent no-op that would leave growth
unbounded while printing green.

---

## 6. Wiring: **standalone, deliberately not wired into `ngbuild.sh`**

The obvious place for this is one line in `ngbuild.sh` after
`echo "GATES_DONE fail=$fail"` and before `exit $fail` — that placement is correct
on the merits, because a prune must not be able to change `fail`.

**It is not wired, and that is a decision, not an omission.** `W49Terminator`
owns `ngbuild.sh` in this session and declined the wiring, for reasons that stand
on their own: a shared driver that nine agents run should have one owner per
change, and attaching unattended deletion to a file on a day when a
shared-name operation has already proven hard to bound is the wrong trade. **The
consequence, stated plainly: with no wiring, growth is bounded only when the
pruner is run.** `prune_builds.sh --apply` is currently a manual step. That is
recorded here rather than left for a reader to discover.

**Cost of reversing:** the wiring is one line in `legacy/tools/coldproof/ngbuild.sh`
between `GATES_DONE` and `exit`, and it comes back if and only if the owner of
that file asks for it. The liveness predicate is already PID-based with a
negative control (`tests_ntasm_builds_prune.sh`), so the objection that motivated
the refusal has already been answered on the merits.

---

## 7. Proof that the prune was safe

Measured on the first run, and re-measurable:

1. **`out/c-bootstrap/nova/evidence/` file count identical before and after.**
   Both numbers printed.
2. **A full `bash legacy/tools/coldproof/ngbuild.sh` after the prune ends
   `GATES_DONE fail=0`, exit 0.**
3. **The refusal is demonstrated, not asserted**: `tests_ntasm_builds_prune.sh`
   builds a fixture tree containing an unrecognised directory, a symlink, a
   plain file and a cited path, and requires the pruner to refuse each one with
   its own reason — and to leave the cited one on disk.
4. **The live-run negative control**: the same test starts a real `sleep` whose
   PID is written into a run directory's name, and requires the pruner to
   **keep** it. A liveness predicate that has never been shown refusing to
   delete a live directory is an assumption, not a guard.
