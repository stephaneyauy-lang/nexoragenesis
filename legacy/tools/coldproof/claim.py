#!/usr/bin/env python3
"""claim.py — file-ownership claims for concurrent lots, and an end-of-run report.

WHAT THIS IS. Three verbs over one state directory:

  claim   --lot L FILE...   take a claim; REFUSE if a live lot already holds a FILE
  release --lot L           drop the claim and print what was held, what moved
  report  [--since T]       audit the WHOLE surface; needs nothing from anybody

EXIT  0 clean   1 a finding the caller must see   2 state unusable / surface empty
     3 usage error

Exit 2 exists because the failure mode of a tool that is trusted is silence, and
silence here means « nobody is editing anything ». It is a separate code from 1
so a caller can tell « I found a conflict » from « I could not look ».

------------------------------------------------------------------ WHY THIS IS
NOT AN OBLIGATION

This project has been hurt all night by obligations nobody remembers.
`KNOWN_NOVA_MODULES` was an obligation and it was forgotten three times, and
`MODULE-SET` is its replacement: the module set is now DERIVED from the tree by
a C gate instead of being declared and remembered. That replacement is the
design this tool copies, and the copy is deliberate.

The question « does a claim count as an obligation? » has a precise answer here,
and it is not « no ». It is: **the DECLARATION is optional; the DETECTION is
not.** They are separate paths and only one of them depends on the lot.

  DETECTION comes from the tree. `claim` snapshots the whole surface — every
  file under the edit roots, with size and mtime — whether or not the lot named
  a single file. `release` and `report` diff that snapshot against the tree
  now. A lot that declares nothing, or that declares three files and edits a
  fourth, or that never runs this tool at all, is still caught by `report`,
  which is a global scan needing no cooperation from anybody. THE MOVE IS
  DETECTED FROM GROUND TRUTH. The declaration only changes the LABEL attached
  to the move — claimed-by-lot-110 versus NO-LOT-HELD-IT — and never whether
  the move is seen.

  That is the difference from KNOWN_NOVA_MODULES, and it is the whole design:
  there, forgetting the list made the WORK invalid and the damage was done
  before anyone noticed. Here, forgetting the list costs exactly one line, at
  the END of the run, naming the file, with a non-zero exit — and the work
  itself is not invalidated by it.

`MODULE-UNNAMED` and `IMPORT-UNPROVED` are the vocabulary this borrows, and
`MODULE-UNNAMED` is the exact shape of the thing being caught: a file that
exists, that is being read, and that no lot said it was writing.

------------------------------------------------------------------ ADVISORY

The CLAIM is advisory. The REPORT is enforced. That split is not a compromise,
it is the only placement that works:

  * Enforcing the claim would mean the gate harness or `scripts/ntbuild.sh`
    refusing to start a run whose files are held. Those files are shared, are
    being edited by sibling lots tonight, and are not mine to touch. More
    importantly: enforcing a SELF-DECLARATION enforces honesty, not safety. A
    lot that lies about its files passes any enforcement whatsoever. The thing
    that cannot lie is the tree.

  * The report's non-zero exit IS enforcement, and it is enforced against
    ground truth rather than against a promise. `MOVED-UNCLAIMED <path>` is
    not a warning a caller may print and continue past; it is exit 1 with a
    named file.

So a claim that can be ignored is fine here, because ignoring it does not
change what the mechanism SEES. It only changes who gets the blame.

------------------------------------------------------------------ ARM 4

The failure that actually happened is not « two lots declared the same file ».
It is « a lot edited a file it never declared, and the resulting reds were read
as real » — twenty-nine of thirty-nine on the census, and lot 83's
743/458-vs-3393/13. A claim system covering only declared files would have
missed it exactly, so arm 4 is covered by the full-surface snapshot, and
`claim` with no files at all is legal precisely so that a lot can be running
and detectable before it has decided what it will touch.

------------------------------------------------------------------ THE CLOCK

Claims EXPIRE, on a wall clock, LEASE_HOURS after the claim (or after the last
re-claim, which refreshes the lease and is how a long lot renews without a
fourth verb). An expired claim is RETAINED ON DISK and loses only its
precedence. It is never deleted, because a claim that vanishes is a claim that
can be covered up.

Expiry must fail toward noise, and that is the property worth stating: an
expired holder is reported as `CLAIM-EXPIRED`, and the moves that were its
files revert to `MOVED-UNCLAIMED` — the LOUD label. A stale claim can never
make a conflict disappear, can never restore a lie, and cannot block anyone.
Its total cost is that yesterday's edit is attributed to nobody tonight. The
six-hour lease is chosen so that it cannot expire inside a night's lot and
cannot survive to mislabel the next one.

------------------------------------------------------------------ ARM 5

If the state directory is unreadable, is not JSON, is JSON of an unknown
schema, is missing a required field, has a wrong type, or has a field of the
wrong type, every verb exits 2 and prints `CLAIM-STATE-UNUSABLE`. None of them
prints « no conflicts ». A conflict detector that stays silent is worse than
none, because it is trusted.

Arm 5's sibling, and just as load-bearing: if the resolved SURFACE is empty,
`claim` and `report` also exit 2 with `SURFACE-EMPTY`. An instrument pointed at
a root where nothing matches is green because it exercised nothing, and that is
the mirror of a green that exercised nothing.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from typing import Any

SCHEMA = "ng-coldproof-claim/1"

# 6 h. Long enough that a lot cannot expire inside its own run; short enough
# that a forgotten claim cannot label the next session's edits.
LEASE_HOURS = 6.0

# The roots a lot can actually write in, established by reading the tree and
# not by guessing: 61 modules and 106 gate entries under the toolchain, the
# C translation units and headers the twins read at run time, the build
# driver, the gate harnesses and rails under legacy/tools/coldproof, the specs the
# gates cite, and the registers at the top of the tree. Wider than
# machine_ir.nova by four orders of magnitude, which is the point.
SURFACE_DIRS = (
    "compiler/nova",
    "compiler/c",
    "scripts",
    "legacy/tools/coldproof",
    "spec",
)
SURFACE_FILES = (
    "MEM.md",
    "AGENTS.md",
    "TRUST.md",
    "README.md",
)

# Never walked: build outputs and caches. Their mtimes move for reasons that
# have nothing to do with the text a lot wrote, and including them is how a
# report turns into noise nobody reads.
SKIP_DIRS = frozenset({".git", "__pycache__", "node_modules", ".venv"})

# Windows note, measured not assumed: on NTFS the filesystem is
# case-PRESERVING and case-INSENSITIVE, so `Lot-110.json` and `lot-110.json`
# are ONE file. Two lots differing only in case would silently share a record,
# and the loser would overwrite the winner's holder. The lot-id check below
# refuses that rather than allowing it to happen quietly.
LOT_ID_CHARS = set(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
)

EXIT_CLEAN, EXIT_FINDING, EXIT_UNUSABLE, EXIT_USAGE = 0, 1, 2, 3


class Unusable(Exception):
    """The mechanism could not look. Never renders as « no conflicts »."""


class Finding(Exception):
    """A real conflict, reported by the caller with its holder's name."""

    def __init__(self, text: str) -> None:
        super().__init__(text)
        self.text = text


# --------------------------------------------------------------------- surface


def _iso(t: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(t))


def _walk(root: str, rel_dir: str, out: dict[str, tuple[int, int, str]]) -> None:
    base = os.path.join(root, rel_dir)
    if not os.path.isdir(base):
        return
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if rel in out:
                continue
            try:
                st = os.stat(full)
            except OSError:
                continue
            if not os.path.isfile(full):
                continue
            out[rel] = (st.st_size, st.st_mtime_ns, "")


def surface_roots(root: str) -> list[str]:
    found = [d for d in SURFACE_DIRS if os.path.isdir(os.path.join(root, d))]
    missing = [d for d in SURFACE_DIRS if d not in found]
    if missing:
        # Printed, not hidden: a root that was renamed silently shrinks the
        # surface, and a smaller surface reports fewer moves.
        print(f"SURFACE-ROOTS-ABSENT count={len(missing)} {','.join(missing)}")
    return found


def scan_surface(root: str) -> tuple[dict[str, tuple[int, int, str]], list[str]]:
    """(stamp table, resolved roots). Stamp is (size, mtime_ns, sha256[:16])."""
    roots = surface_roots(root)
    table: dict[str, tuple[int, int, str]] = {}
    for rel in SURFACE_DIRS:
        _walk(root, rel, table)
    for rel in SURFACE_FILES:
        full = os.path.join(root, rel)
        if os.path.isfile(full):
            st = os.stat(full)
            table[rel] = (st.st_size, st.st_mtime_ns, "")
    for rel, (size, mtime_ns, _) in list(table.items()):
        digest = _digest(os.path.join(root, rel), size)
        table[rel] = (size, mtime_ns, digest)
    return table, roots


def _digest(path: str, size: int) -> str:
    """sha256 prefix, or '' for a file too large to be worth reading.

    Not optional ornament. mtime alone misses a write that lands inside the
    filesystem's timestamp granularity onto a same-size file, and on the night
    this tool was written the whole loss was a five-minute-old mtime; the hash
    is what makes a same-second overwrite visible.
    """
    if size > (8 << 20):
        return ""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 16), b""):
                h.update(chunk)
        return h.hexdigest()[:16]
    except OSError:
        return ""


# ---------------------------------------------------------------------- state


def state_dir(root: str, override: str | None) -> str:
    d = os.path.abspath(override) if override else os.path.join(
        root, "out", "coldproof", "claims"
    )
    return d


def _claim_file(state: str, lot: str) -> str:
    return os.path.join(state, lot + ".json")


def _check_lot_id(lot: str) -> None:
    if not lot or len(lot) > 64:
        raise Unusable(f"CLAIM-STATE-UNUSABLE lot={lot!r} bad lot id (empty or >64)")
    bad = sorted(set(lot) - LOT_ID_CHARS)
    if bad:
        raise Unusable(
            f"CLAIM-STATE-UNUSABLE lot={lot!r} bad characters "
            f"{''.join(bad)!r}; allowed are letters digits . _ -"
        )


def _require(rec: Any, key: str, types: tuple, where: str) -> Any:
    if not isinstance(rec, dict):
        raise Unusable(f"CLAIM-STATE-UNUSABLE file={where} not a JSON object")
    if key not in rec:
        raise Unusable(f"CLAIM-STATE-UNUSABLE file={where} missing field {key!r}")
    val = rec[key]
    if not isinstance(val, types) or isinstance(val, bool) and bool not in types:
        raise Unusable(
            f"CLAIM-STATE-UNUSABLE file={where} field {key!r} is "
            f"{type(val).__name__}, expected {'|'.join(t.__name__ for t in types)}"
        )
    return val


def read_claim(path: str) -> dict[str, Any]:
    """Load one claim or REFUSE. There is no third outcome."""
    where = os.path.basename(path)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise Unusable(f"CLAIM-STATE-UNUSABLE file={where} unreadable: {exc.strerror}")
    try:
        rec = json.loads(text)
    except json.JSONDecodeError as exc:
        raise Unusable(
            f"CLAIM-STATE-UNUSABLE file={where} not JSON: line {exc.lineno} "
            f"col {exc.colno}: {exc.msg}"
        )
    schema = _require(rec, "schema", (str,), where)
    if schema != SCHEMA:
        raise Unusable(
            f"CLAIM-STATE-UNUSABLE file={where} unknown schema {schema!r}, "
            f"this tool speaks {SCHEMA!r}"
        )
    lot = _require(rec, "lot", (str,), where)
    _check_lot_id(lot)
    state = _require(rec, "state", (str,), where)
    if state not in ("live", "released"):
        raise Unusable(f"CLAIM-STATE-UNUSABLE file={where} state={state!r} is neither live nor released")
    claimed_at = _require(rec, "claimed_at", (float, int), where)
    lease_until = _require(rec, "lease_until", (float, int), where)
    files = _require(rec, "files", (list,), where)
    for f in files:
        if not isinstance(f, str):
            raise Unusable(
                f"CLAIM-STATE-UNUSABLE file={where} files[] holds "
                f"{type(f).__name__}, expected str"
            )
    snap = _require(rec, "snapshot", (dict,), where)
    for k, v in snap.items():
        if not isinstance(v, list) or len(v) != 3:
            raise Unusable(
                f"CLAIM-STATE-UNUSABLE file={where} snapshot[{k!r}] is not a "
                f"3-element stamp, so the run's before-image is not derivable"
            )
    released_at = rec.get("released_at")
    if released_at is not None and not isinstance(released_at, (float, int)):
        raise Unusable(f"CLAIM-STATE-UNUSABLE file={where} released_at is not a number")
    rec["_path"] = path
    return rec


def load_state(state: str) -> list[dict[str, Any]]:
    """Every claim record, or refuse. Never returns a partial list."""
    if not os.path.isdir(state):
        return []
    out = []
    for name in sorted(os.listdir(state)):
        if not name.endswith(".json"):
            continue
        out.append(read_claim(os.path.join(state, name)))
    # The case-collision check. Enumerated rather than assumed: on Windows the
    # two names below are the same file, so os.listdir returns one of them and
    # this loop would never see the clash it is here to catch.
    lowered: dict[str, str] = {}
    for name in sorted(os.listdir(state)):
        if not name.endswith(".json"):
            continue
        key = name.lower()
        if key in lowered and lowered[key] != name:
            raise Unusable(
                f"CLAIM-STATE-UNUSABLE case-collision on a case-insensitive "
                f"filesystem: {lowered[key]!r} and {name!r} are one file"
            )
        lowered[key] = name
    return out


def write_claim(state: str, rec: dict[str, Any]) -> None:
    os.makedirs(state, exist_ok=True)
    path = rec.pop("_path", None) or _claim_file(state, rec["lot"])
    tmp = path + ".tmp"
    body = dict(rec)
    body["schema"] = SCHEMA
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(body, fh, indent=1, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)
    rec["_path"] = path


# ------------------------------------------------------------------ conflicts


def live_holders(records: list[dict[str, Any]], now: float) -> list[dict[str, Any]]:
    return [r for r in records if r["state"] == "live" and r["lease_until"] > now]


def check_conflicts(records, now, files, lot, surface_roots_found) -> None:
    """Raise Finding naming the holder and when it claimed. Never a bare error."""
    for r in live_holders(records, now):
        if r["lot"] == lot:
            continue
        for f in files:
            if f in r["files"]:
                raise Finding(
                    f"CLAIM-REFUSED path={f} lot={lot} "
                    f"holder={r['lot']} holder_claimed_at={r['claimed_at']:.0f} "
                    f"holder_claimed_iso={_iso(r['claimed_at'])} "
                    f"holder_lease_until={r['lease_until']:.0f} "
                    f"holder_lease_iso={_iso(r['lease_until'])} "
                    f"held_for_s={now - r['claimed_at']:.0f}"
                )


def outside_surface(root: str, path: str) -> str | None:
    full = os.path.abspath(os.path.join(root, path))
    rel = os.path.relpath(full, root).replace(os.sep, "/")
    if rel.startswith(".."):
        return f"path={path!r} is outside the tree root"
    for d in SURFACE_DIRS:
        if rel == d or rel.startswith(d + "/"):
            return None
    for f in SURFACE_FILES:
        if rel == f:
            return None
    return (
        f"path={rel} is inside the tree but OUTSIDE the declared surface; a "
        f"claim there would be a claim this tool could never watch move"
    )


# ------------------------------------------------------------------- movement


def diff_movement(
    before: dict[str, tuple[int, int, str]],
    after: dict[str, tuple[int, int, str]],
) -> tuple[list[str], list[str], list[str]]:
    """(moved, created, deleted). Deleted counts as moved: a lot that removed
    an input moved the measurement just as surely as one that rewrote it."""
    moved, created, deleted = [], [], []
    for path, stamp in after.items():
        old = before.get(path)
        if old is None:
            created.append(path)
        elif old != stamp:
            moved.append(path)
    for path in before:
        if path not in after:
            deleted.append(path)
    return sorted(moved), sorted(created), sorted(deleted)


def label_for(path: str, lot: str, records, now) -> str:
    """Who holds it, derived from the records — never guessed from the caller."""
    holders = [r for r in records if path in r["files"] and r["state"] == "live"
               and r["lease_until"] > now]
    if any(r["lot"] == lot for r in holders):
        return f"held-by={lot}"
    if holders:
        return "held-by=" + ",".join(sorted(r["lot"] for r in holders))
    return "held-by=NONE"


def print_movement(records, now, lot, before, after, verb) -> int:
    moved, created, deleted = diff_movement(before, after)
    total = len(moved) + len(created) + len(deleted)
    print(
        f"{verb} lot={lot} surface_files={len(after)} "
        f"moved={len(moved)} created={len(created)} deleted={len(deleted)}"
    )
    # The count line is printed BEFORE the verdict because a verdict with no
    # count above it cannot be told from a verdict produced by an instrument
    # that matched nothing at all.
    if total == 0:
        print(f"{verb}-NOTHING-MOVED lot={lot} surface_files={len(after)} moved=0 "
              f"created=0 deleted=0")
    unclaimed = []
    for path in moved + created + deleted:
        tag = label_for(path, lot, records, now)
        if tag == "held-by=NONE":
            unclaimed.append(path)
            print(f"MOVED-UNCLAIMED lot={lot} path={path} {tag}")
        else:
            print(f"MOVED lot={lot} path={path} {tag}")
    if unclaimed:
        print(
            f"MOVED-UNCLAIMED-SUMMARY lot={lot} count={len(unclaimed)} "
            f"total_moved={total} "
            f"paths={','.join(unclaimed)}"
        )
        return EXIT_FINDING
    return EXIT_CLEAN


# ----------------------------------------------------------------------- verbs


def cmd_claim(args, root, state, now) -> int:
    records = load_state(state)
    files = [f.replace(os.sep, "/").lstrip("./") for f in args.paths]
    seen, dupes = set(), set()
    for f in files:
        norm = os.path.normpath(f).replace(os.sep, "/")
        if norm in seen:
            dupes.add(norm)
        seen.add(norm)
    files = sorted(seen)
    if dupes:
        print(f"CLAIM-DUPLICATE lot={args.lot} paths={','.join(sorted(dupes))}")
        return EXIT_USAGE
    # The REASON is kept, not the path. An earlier version of this line
    # collected the path and threw away what outside_surface() had to say
    # about it, so the refusal still fired but printed `path=…` and nothing
    # else — a refusal in terms the caller cannot act on, which is the one
    # kind of refusal this project treats as a defect.
    outside = [(f, outside_surface(root, f)) for f in files]
    outside = [(f, why) for f, why in outside if why]
    if outside:
        for f, why in outside:
            print(f"CLAIM-REFUSED lot={args.lot} {why}")
        return EXIT_FINDING
    missing = [f for f in files if not os.path.isfile(os.path.join(root, f))]
    if missing:
        # A claim on a path that does not exist proves nothing and can never
        # be checked against a movement. Refused, and named — because a typo
        # that printed nothing would be a claim that never held anything.
        for f in missing:
            print(
                f"CLAIM-REFUSED lot={args.lot} path={f} does not exist; "
                f"re-claim after creating it (re-claim also refreshes the lease)"
            )
        return EXIT_FINDING
    # Scanned ONCE. Two scans would take two different instants, so the
    # emptiness check would be reading a different tree than the one recorded
    # as this run's before-image.
    table, roots = scan_surface(root)
    if not table:
        print(
            "SURFACE-EMPTY lot=%s files=0 roots=0; this tool would watch nothing "
            "and report every run clean" % args.lot
        )
        return EXIT_UNUSABLE
    check_conflicts(records, now, files, args.lot, roots)
    lease_until = now + args.lease_seconds
    rec = {
        "lot": args.lot,
        "state": "live",
        "claimed_at": now,
        "lease_until": lease_until,
        "files": files,
        "snapshot": {k: list(v) for k, v in sorted(table.items())},
        "surface_roots": roots,
        "surface_files": len(table),
    }
    write_claim(state, rec)
    print(
        f"CLAIMED lot={args.lot} files={len(files)} surface_files={len(table)} "
        f"claimed_at={now:.0f} claimed_iso={_iso(now)} "
        f"lease_until={lease_until:.0f} lease_iso={_iso(lease_until)} "
        f"lease_hours={args.lease_seconds / 3600.0:.1f}"
    )
    for f in files:
        print(f"CLAIMED-FILE lot={args.lot} path={f}")
    return EXIT_CLEAN


def cmd_release(args, root, state, now) -> int:
    records = load_state(state)
    _check_lot_id(args.lot)
    path = _claim_file(state, args.lot)
    if not os.path.isfile(path):
        print(f"NO-CLAIM lot={args.lot} state={state} has no claim to release")
        return EXIT_FINDING
    rec = read_claim(path)
    if rec["lot"] != args.lot:
        print(f"CLAIM-STATE-UNUSABLE file={os.path.basename(path)} "
              f"holds lot={rec['lot']!r} but was addressed as {args.lot!r}")
        return EXIT_UNUSABLE
    if rec["state"] != "live":
        print(f"ALREADY-RELEASED lot={args.lot} released_at={rec['released_at']:.0f}")
        return EXIT_USAGE
    before = {k: tuple(v) for k, v in rec["snapshot"].items()}
    after, roots = scan_surface(root)
    if not after:
        print("SURFACE-EMPTY lot=%s files=0 roots=0" % args.lot)
        return EXIT_UNUSABLE
    rc = print_movement(records, now, args.lot, before, after, "RELEASE")
    rec["state"] = "released"
    rec["released_at"] = now
    rec["release_verdict"] = "CLEAN" if rc == EXIT_CLEAN else "MOVED-UNCLAIMED"
    write_claim(state, rec)
    print(
        f"RELEASED lot={args.lot} held_files={len(rec['files'])} "
        f"held_for_s={now - rec['claimed_at']:.0f} verdict={rec['release_verdict']} "
        f"expired={now > rec['lease_until']}"
    )
    if now > rec["lease_until"]:
        print(
            f"CLAIM-EXPIRED lot={args.lot} claimed_at={rec['claimed_at']:.0f} "
            f"lease_until={rec['lease_until']:.0f} overdue_s={now - rec['lease_until']:.0f} "
            f"retained=yes; an expired claim keeps its record and loses only its "
            f"precedence, so it cannot hide a later conflict"
        )
    return rc


def cmd_report(args, root, state, now) -> int:
    records = load_state(state)
    # An ABSENT state directory is NOT a defect and must not refuse. It is the
    # normal state of a project where nobody has ever claimed anything, and
    # refusing there blinded the report to the one case the whole design rests
    # on: a lot that ignores the mechanism completely. That lot leaves no
    # state behind, so a report that needs state cannot see it — the report was
    # blind to the ignoring lot, and exit 2 said « I could not look », which is
    # exactly the silence this tool exists to remove.
    #
    # So: no state directory means ZERO records, and the scan runs anyway and
    # names every moved file `held-by=NONE`. Corruption is a claim file that
    # exists and cannot be read; that still refuses, in load_state above.
    #
    # A wrong --root cannot masquerade as this: a wrong root has no surface,
    # and the emptiness check below refuses that separately.
    if not os.path.isdir(state):
        print(
            f"REPORT-NO-CLAIM-STATE state={state} claims=0; nothing has ever "
            f"claimed here, so every move below is unattributed by "
            f"construction — this is NOT a clean bill of health"
        )
    after, roots = scan_surface(root)
    if not after:
        print("SURFACE-EMPTY files=0 roots=0; a scan of nothing is a green of nothing")
        return EXIT_UNUSABLE
    since, source = args.since, "argument"
    if since is None:
        # With no claims to take a floor from, the window is the last 24 h and
        # the source is PRINTED, so the denominator is never guessed at.
        stamps = [r["claimed_at"] for r in records] or [now - 86400.0]
        since, source = min(stamps), ("claims" if records else "default-24h")
    print(
        f"REPORT since={since:.0f} since_iso={_iso(since)} since_source={source} "
        f"now={now:.0f} now_iso={_iso(now)} surface_files={len(after)} "
        f"claims_total={len(records)}"
    )
    moved = [p for p, st in after.items() if st[1] / 1e9 > since]
    moved.sort()
    print(f"REPORT-MOVED count={len(moved)}")
    unclaimed, expired = [], []
    for r in records:
        if r["state"] == "live" and r["lease_until"] <= now:
            expired.append(r)
    for path in moved:
        holders = [r for r in records if path in r["files"]]
        live_h = [r for r in holders if r["state"] == "live" and r["lease_until"] > now]
        dead_h = [r for r in holders if r not in live_h]
        if live_h:
            print(
                f"REPORT-MOVED path={path} "
                f"held-by={','.join(sorted(r['lot'] for r in live_h))}"
            )
        else:
            unclaimed.append(path)
            print(f"REPORT-MOVED path={path} held-by=NONE")
        for r in dead_h:
            print(
                f"REPORT-EXPIRED-HOLDER path={path} lot={r['lot']} "
                f"claimed_at={r['claimed_at']:.0f} state={r['state']}"
            )
    for r in sorted(expired, key=lambda x: x["lot"]):
        print(
            f"CLAIM-EXPIRED lot={r['lot']} claimed_at={r['claimed_at']:.0f} "
            f"claimed_iso={_iso(r['claimed_at'])} lease_until={r['lease_until']:.0f} "
            f"lease_iso={_iso(r['lease_until'])} overdue_s={now - r['lease_until']:.0f} "
            f"files={len(r['files'])} retained=yes"
        )
    live = live_holders(records, now)
    print(f"REPORT-LIVE-CLAIMS count={len(live)}")
    for r in sorted(live, key=lambda x: x["lot"]):
        print(
            f"REPORT-CLAIM lot={r['lot']} files={len(r['files'])} "
            f"claimed_iso={_iso(r['claimed_at'])} lease_iso={_iso(r['lease_until'])}"
        )
    if unclaimed:
        print(
            f"REPORT-UNCLAIMED count={len(unclaimed)} total_moved={len(moved)} "
            f"paths={','.join(unclaimed)}"
        )
        return EXIT_FINDING
    print(f"REPORT-CLEAN moved={len(moved)} unclaimed=0 expired={len(expired)}")
    return EXIT_CLEAN


# ------------------------------------------------------------------------ main


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="claim.py",
        description="File-ownership claims for concurrent lots, and the "
                    "end-of-run report that a claim cannot be used to fake.",
    )
    p.add_argument("verb", choices=("claim", "release", "report"))
    p.add_argument("paths", nargs="*", help="paths to claim, relative to --root")
    p.add_argument("--lot", default=os.environ.get("NG_LOT", ""))
    p.add_argument("--root", default=os.environ.get("NG_ROOT", "."))
    p.add_argument("--state", default=os.environ.get("NG_CLAIM_STATE"))
    p.add_argument(
        "--lease-seconds", type=float, default=LEASE_HOURS * 3600.0,
        help="lease length; re-claiming refreshes it",
    )
    p.add_argument(
        "--now", type=float, default=None,
        help="override the wall clock, in epoch seconds. Exists so a claim "
             "taken six hours ago can be inspected without waiting six hours; "
             "it reads and reports, it never fabricates a movement.",
    )
    p.add_argument("--since", type=float, default=None, help="report: epoch seconds")
    args = p.parse_args(argv)
    now = time.time() if args.now is None else args.now

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"USAGE root={root} is not a directory")
        return EXIT_USAGE
    state = state_dir(root, args.state)

    try:
        if args.verb == "claim":
            if not args.lot:
                print("USAGE claim requires --lot (or NG_LOT)")
                return EXIT_USAGE
            _check_lot_id(args.lot)
            return cmd_claim(args, root, state, now)
        if args.verb == "release":
            if not args.lot:
                print("USAGE release requires --lot (or NG_LOT)")
                return EXIT_USAGE
            return cmd_release(args, root, state, now)
        return cmd_report(args, root, state, now)
    except Unusable as exc:
        print(str(exc))
        return EXIT_UNUSABLE
    except Finding as exc:
        print(exc.text)
        return EXIT_FINDING


if __name__ == "__main__":
    sys.exit(main())
