#!/usr/bin/env python3
"""Explain the pin discrepancies of the reorganized repository.

READ ONLY. It reads the pin table of scripts/ntbuild.sh, the bytes on disk,
the history of this repository and, when it is available, the campaign's
pre-reorganization copy of the same sources. It writes nothing.

For every pin row whose digest does not match the bytes on disk, and for every
granted header that has no pin row at all, it reports:

  - the declared pin and the digest on disk;
  - whether the pin designates a REAL revision of that file in the history of
    this repository, and which one;
  - how the file differs from the campaign's pre-reorganization copy, and
    whether the difference is only the paths (the reorganization) or also
    code.

The three discrepancies the snapshot carries are explained here, and the pins
are NOT updated: updating them is a decision of the owner of the repository.

Usage:
    python tools/validation/a8_pin_discrepancies.py [--archive-root DIR]
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PIN_ROW = re.compile(r'^\s*"(?P<path>[^"]+)\|(?P<sha256>[0-9a-f]{64})",?\s*$')
INCLUDE = re.compile(r'^\s*#\s*include\s+"(?P<path>[^"\n]+)"', re.M)


def git(*args):
    proc = subprocess.run(["git", "-C", str(ROOT)] + list(args),
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    return proc.stdout


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pin_rows():
    """The pin table of scripts/ntbuild.sh: [(path, sha256)]."""
    text = (ROOT / "scripts" / "ntbuild.sh").read_text(encoding="utf-8",
                                                       errors="replace")
    rows = []
    for line in text.splitlines():
        found = PIN_ROW.match(line)
        if found:
            rows.append((found.group("path"), found.group("sha256")))
    return rows


def source_map():
    """The old -> new table the reorganization published."""
    path = ROOT / "docs" / "architecture" / "source-map.csv"
    if not path.is_file():
        return {}
    out = {}
    for line in path.read_text(encoding="utf-8",
                               errors="replace").splitlines()[1:]:
        old, _, new = line.partition(",")
        if old and new:
            out[old.strip()] = new.strip()
    return out


def history_revisions(old_path):
    """The revisions of a file in the history of this repository."""
    out = subprocess.run(["git", "-C", str(ROOT), "log", "--all",
                          "--format=%H", "--", old_path],
                         stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL).stdout.decode()
    return [line for line in out.split() if line]


def revision_digest(revision, path):
    blob = git("show", "%s:%s" % (revision, path))
    if not blob:
        return None
    return hashlib.sha256(blob).hexdigest(), len(blob)


def find_revision(pin, old_paths):
    """The revision whose bytes carry the pin, if this repository has one."""
    for old_path in old_paths:
        for revision in history_revisions(old_path):
            found = revision_digest(revision, old_path)
            if found and found[0] == pin:
                return dict(revision=revision, path=old_path, bytes=found[1],
                            found=True)
    return dict(found=False)


def changed_lines(old_text, new_text):
    import difflib
    out = [line for line in difflib.unified_diff(
        old_text.splitlines(), new_text.splitlines(), lineterm="", n=0)
        if line[:1] in "+-" and not line.startswith(("---", "+++"))]
    return out


def classify_delta(old_text, new_text):
    """'paths-only' when every changed line is a path or a comment."""
    changed = changed_lines(old_text, new_text)
    code = []
    for line in changed:
        body = line[1:].strip()
        if body.startswith("//") or body.startswith("*") or body.startswith("/*"):
            continue
        if '"' in body or "/" in body:
            continue
        code.append(line)
    return len(changed), len(code), code[:5]


def granted_headers(rows):
    """The headers the granted C sources include."""
    out = []
    for path, _ in rows:
        source = ROOT / path
        if not source.is_file() or source.suffix not in (".c", ".h"):
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        for found in INCLUDE.finditer(text):
            target = (source.parent / found.group("path")).resolve()
            try:
                target.relative_to(ROOT.resolve())
            except ValueError:
                continue
            out.append((path, str(target.relative_to(ROOT.resolve()))
                        .replace("\\", "/")))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--archive-root",
                    default="C:/NexoraGenesis",
                    help="the campaign tree, read only, for the "
                         "pre-reorganization copies")
    args = ap.parse_args(argv)
    rows = pin_rows()
    mapping = source_map()
    archive = Path(args.archive_root)

    stale = []
    for path, pin in rows:
        on_disk = ROOT / path
        if not on_disk.is_file():
            continue
        got = digest(on_disk)
        if got == pin:
            continue
        old_paths = [old for old, new in mapping.items() if new == path]
        entry = dict(path=path, pinned=pin, on_disk=got,
                     bytes=on_disk.stat().st_size,
                     history=find_revision(pin, old_paths))
        campaign = None
        for old in old_paths:
            candidate = archive / old
            if candidate.is_file():
                campaign = candidate
                break
        if campaign is not None:
            changed, code, sample = classify_delta(
                campaign.read_text(encoding="utf-8", errors="replace"),
                on_disk.read_text(encoding="utf-8", errors="replace"))
            entry["campaign_copy"] = str(campaign)
            entry["campaign_sha256"] = digest(campaign)
            entry["changed_lines"] = changed
            entry["code_lines"] = code
            entry["code_sample"] = sample
            entry["verdict"] = ("paths-and-comments-only" if code == 0
                                else "code-changed")
        else:
            entry["verdict"] = "campaign copy not available"
        stale.append(entry)

    pinned = {path for path, _ in rows}
    unpinned = []
    for source, header in granted_headers(rows):
        if header not in pinned and header not in [e["path"] for e in unpinned]:
            unpinned.append(dict(header=header, included_by=source,
                                 on_disk=digest(ROOT / header),
                                 bytes=(ROOT / header).stat().st_size))

    result = dict(pins=len(rows), stale=stale, unpinned=unpinned,
                  ok=not stale and not unpinned)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
