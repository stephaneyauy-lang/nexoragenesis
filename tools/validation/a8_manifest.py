#!/usr/bin/env python3
"""Generate the house manifest of THIS repository from the house stage's manifest.

The house builder (scripts/ntbuild_house.py) READS the manifest at
bootstrap/nova-native/manifest.json (MANIFEST_REL) and refuses with class
manifest-missing when it is absent: it never writes one and it never invents
one. This generator is what fills that file for the reorganized tree.

WHAT COMES FROM WHERE, and why nothing is copied blindly:

  * the LISTS come from the house stage's manifest
    (C:\\NexoraGenesis\\out\\a8-selfhost-20261015\\house-stage-20261021-01\\
    bootstrap\\nova-native\\manifest.json): the ORDER of the compiler closure,
    the ORDER of the producer closure, which entry is the root of each
    closure, the runtime and host pins, the bundle digest fields, the
    bootstrap history and the two values that come from outside this build.
  * every PATH is mapped through docs/architecture/source-map.csv, the
    repository's published old -> new table. A path with no row in that
    table is a REFUSAL: the generator never guesses where a file went.
  * every sha256 is recomputed from the bytes on disk. The stage's digests
    are never copied: 26 of the 57 sources differ from the stage because the
    reorganization rewrote the paths inside their comments, and the manifest
    must pin what is on disk NOW.
  * the bundle digests are recomputed with the EXACT algorithm of
    scripts/ntbuild_house.py: its pack_nvsrc001() and its sha256() are
    imported from that file, not re-implemented here.
  * the seed (nova_compiler) and expected_producer_sha256 are KEPT AS THEY
    ARE. They are PUBLISHED ARTEFACTS: they come from outside this build
    (the campaign archive), they are not bytes of this repository, and the
    builder checks them against the bytes it is given at run time.

This generator is READ-ONLY for the repository: it writes the manifest only
when an explicit --out path is given. With no --out it prints the JSON to
stdout and touches nothing.

Exit codes: 0 the manifest was produced; 78 a refusal (a path with no
mapping, a mapped file that is not on disk, a list whose shape moved).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

EXIT_OK = 0
EXIT_REFUSED = 78

TAG = "A8MANIFEST-POLICY/1"

# The repository, relative to this file (tools/validation/a8_manifest.py).
REPO_REL = "../.."
SOURCE_MAP_REL = "docs/architecture/source-map.csv"
BUILDER_REL = "scripts/ntbuild_house.py"
MANIFEST_REL = "bootstrap/nova-native/manifest.json"

# The house stage whose manifest holds the LISTS. It is the campaign's
# read-only archive; this generator only READS it.
STAGE_MANIFEST = (
    "/mnt/c/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01"
    "/bootstrap/nova-native/manifest.json"
)

# The two closures and the pins that describe them, as the stage wrote them.
CLOSURE_KEYS = ("compiler_sources", "producer_sources")
BUNDLE_KEYS = {
    "compiler_sources": "compiler_bundle_sha256",
    "producer_sources": "producer_bundle_sha256",
}
# The values that are NOT bytes of this repository: they are published
# artefacts, checked at run time by the builder, and they are carried over
# unchanged.
EXTERNAL_KEYS = ("nova_compiler", "expected_producer_sha256")

EXTERNAL_NOTE = (
    " The pinned seed PE (nova_compiler) and expected_producer_sha256 are "
    "PUBLISHED ARTEFACTS that come from outside this build: they are not "
    "bytes of this repository, they are carried over from the house stage "
    "unchanged, and the builder checks them against the bytes it is given at "
    "run time."
)


class Refusal(Exception):
    """A refusal: the table, the disk or the stage says no. Exit 78."""

    def __init__(self, cls, reason, input_path=""):
        super().__init__(reason)
        self.cls = cls
        self.reason = reason
        self.input_path = input_path


def refuse(cls, reason, input_path=""):
    raise Refusal(cls, reason, input_path)


# ---------------------------------------------------------------------------
# the house builder's own algorithm, imported, never re-invented
# ---------------------------------------------------------------------------


def load_builder(repo):
    """Import scripts/ntbuild_house.py so the bundle digest is ITS algorithm."""
    path = (repo / BUILDER_REL).resolve()
    if not path.is_file():
        refuse("builder-missing", "the house builder is missing: %s" % BUILDER_REL, BUILDER_REL)
    spec = importlib.util.spec_from_file_location("ntbuild_house_a8_manifest", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    for name in ("pack_nvsrc001", "sha256"):
        if not hasattr(module, name):
            refuse("builder-incomplete", "the house builder has no %s()" % name, BUILDER_REL)
    return module


# ---------------------------------------------------------------------------
# the published old -> new table
# ---------------------------------------------------------------------------


def load_source_map(repo):
    """Read docs/architecture/source-map.csv into an old -> new dictionary."""
    path = repo / SOURCE_MAP_REL
    if not path.is_file():
        refuse("source-map-missing", "the published path table is missing: %s" % SOURCE_MAP_REL,
               SOURCE_MAP_REL)
    mapping = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        header = next(reader, None)
        if header != ["ancien_chemin", "nouveau_chemin"]:
            refuse("source-map-bad-header",
                   "the path table header must be ancien_chemin,nouveau_chemin, got %r" % (header,),
                   SOURCE_MAP_REL)
        for row in reader:
            if not row:
                continue
            if len(row) != 2:
                refuse("source-map-bad-row", "the path table has a row that is not two columns: %r" % (row,),
                       SOURCE_MAP_REL)
            old, new = row
            if old in mapping and mapping[old] != new:
                refuse("source-map-ambiguous",
                       "the path table maps %r to two paths: %r and %r" % (old, mapping[old], new),
                       SOURCE_MAP_REL)
            mapping[old] = new
    return mapping


def map_path(old, mapping, what):
    """Map one stage path to its path in THIS repository, or refuse."""
    new = mapping.get(old)
    if new is None:
        refuse(
            "path-unmapped",
            "%s: %r has no row in %s, so its new path is unknown; the "
            "generator never guesses where a file went" % (what, old, SOURCE_MAP_REL),
            old,
        )
    return new


# ---------------------------------------------------------------------------
# the stage manifest
# ---------------------------------------------------------------------------


def load_stage_manifest(path):
    if not path.is_file():
        refuse("stage-manifest-missing",
               "the house stage's manifest is not there: %s" % path, str(path))
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        refuse("stage-manifest-unreadable", "%s is not readable JSON: %s" % (path, exc), str(path))
    if not isinstance(data, dict):
        refuse("stage-manifest-unreadable", "%s is not a JSON object" % path, str(path))
    required = tuple(CLOSURE_KEYS) + tuple(BUNDLE_KEYS.values()) + tuple(EXTERNAL_KEYS) \
        + ("schema", "bootstrap_history")
    for key in required:
        if key not in data:
            refuse("stage-manifest-incomplete", "the stage manifest has no %r" % key, str(path))
    return data


def digest_file(path, what):
    if not path.exists():
        refuse("source-missing", "%s does not exist: %s" % (what, path), str(path))
    if not path.is_file():
        refuse("source-missing", "%s is not a regular file: %s" % (what, path), str(path))
    return path.read_bytes()


def rebuild_closure(repo, stage, key, mapping, builder):
    """Rebuild one pinned Nova closure: new paths, digests from the disk."""
    entries = stage[key]
    if not isinstance(entries, list) or not entries:
        refuse("stage-manifest-incomplete", "the stage manifest's %s is not a non-empty list" % key)
    out = []
    items = []
    changed = 0
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            refuse("stage-manifest-incomplete", "the stage manifest's %s holds a bad entry" % key)
        old = entry["path"]
        new = map_path(old, mapping, "%s entry" % key)
        target = (repo / new).resolve()
        if not target.is_relative_to(repo.resolve()):
            refuse("path-escape", "%s: %r maps outside the repository" % (key, old), old)
        data = digest_file(target, "%s source" % key)
        got = builder.sha256(data)
        if got != entry.get("sha256"):
            changed += 1
        out.append({"path": new, "sha256": got})
        # The builder packs (name, bytes) pairs; the packet keeps the ORDER
        # and the BYTES of the list, which is what the bundle digest covers.
        items.append((new, data))
    return out, items, changed


def rebuild_ntasm_pin(repo, stage, key, mapping):
    """Rebuild one NTASM-S0 pin: the source path and its digest from disk."""
    spec = stage[key]
    if not isinstance(spec, dict):
        refuse("stage-manifest-incomplete", "the stage manifest's %s is not an object" % key)
    old = spec.get("source")
    if not isinstance(old, str):
        refuse("stage-manifest-incomplete", "the stage manifest's %s has no source path" % key)
    new = map_path(old, mapping, "%s source" % key)
    data = digest_file((repo / new).resolve(), "%s source" % key)
    got = hashlib.sha256(data).hexdigest()
    return {
        "source": new,
        "source_sha256": got,
        # The image digest is NOT a file of this repository: it is the image
        # the transport must rebuild from the source above. It is carried
        # over from the stage, unchanged.
        "image_sha256": spec.get("image_sha256"),
    }


# ---------------------------------------------------------------------------
# the manifest
# ---------------------------------------------------------------------------


def build_manifest(repo, stage, mapping, builder):
    """Build the manifest of THIS repository from the stage's manifest."""
    manifest = {"schema": stage["schema"]}
    report = {}

    # The seed: a published artefact, kept as the stage wrote it.
    manifest["nova_compiler"] = dict(stage["nova_compiler"])

    changed_total = 0
    for key in CLOSURE_KEYS:
        entries, items, changed = rebuild_closure(repo, stage, key, mapping, builder)
        manifest[key] = entries
        changed_total += changed
        packet = builder.pack_nvsrc001(items, 0)
        manifest[BUNDLE_KEYS[key]] = builder.sha256(packet)
        report[key] = {
            "sources": len(entries),
            "digests_differing_from_stage": changed,
            "bundle_sha256": manifest[BUNDLE_KEYS[key]],
            "stage_bundle_sha256": stage[BUNDLE_KEYS[key]],
            "packet_bytes": len(packet),
        }

    # The expected producer: a published artefact, kept as the stage wrote it.
    manifest["expected_producer_sha256"] = stage["expected_producer_sha256"]

    # The descriptive history: the stage's text, plus the one sentence that
    # says where the two external values come from. It is descriptive, never
    # a proof, and the builder never reads it.
    history = stage["bootstrap_history"]
    manifest["bootstrap_history"] = history + EXTERNAL_NOTE

    for key in ("runtime", "host"):
        manifest[key] = rebuild_ntasm_pin(repo, stage, key, mapping)

    report["digests_differing_from_stage"] = changed_total
    report["external"] = {
        "nova_compiler": manifest["nova_compiler"],
        "expected_producer_sha256": manifest["expected_producer_sha256"],
        "note": "carried over from the house stage unchanged; these come from "
                "outside this build",
    }
    return manifest, report


# ---------------------------------------------------------------------------
# the command line
# ---------------------------------------------------------------------------


def build_parser():
    parser = argparse.ArgumentParser(
        prog="a8_manifest.py",
        description="Generate the house manifest of this repository (read-only).",
    )
    parser.add_argument("--repo", default=str(Path(__file__).resolve().parents[2]),
                        help="the repository root (default: the repository this file lives in)")
    parser.add_argument("--stage-manifest", default=STAGE_MANIFEST,
                        help="the house stage's manifest, read for the LISTS (default: the campaign archive)")
    parser.add_argument("--out", default=None,
                        help="write the manifest to this path; without it the JSON goes to stdout only")
    return parser


def report_refusal(exc):
    print("A8MANIFEST_REFUSED class=%s" % exc.cls, file=sys.stderr)
    print("  input:   %s" % (exc.input_path or "-"), file=sys.stderr)
    print("  reason:  %s" % exc.reason, file=sys.stderr)
    print("A8MANIFEST_DONE status=refused policy=%s" % TAG)


def main(argv=None):
    args = build_parser().parse_args(argv)
    repo = Path(args.repo).resolve()
    try:
        builder = load_builder(repo)
        mapping = load_source_map(repo)
        stage = load_stage_manifest(Path(args.stage_manifest))
        manifest, report = build_manifest(repo, stage, mapping, builder)
    except Refusal as exc:
        report_refusal(exc)
        return EXIT_REFUSED

    payload = json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(payload, encoding="utf-8")
        print("A8MANIFEST_WRITTEN path=%s bytes=%d" % (out, len(payload)), file=sys.stderr)
    else:
        sys.stdout.write(payload)

    # The report goes to stderr, so the stdout stays the manifest itself.
    for key in CLOSURE_KEYS:
        info = report[key]
        print("  closure %-18s sources=%d digests_changed=%d bundle=%s (stage %s)"
              % (key, info["sources"], info["digests_differing_from_stage"],
                 info["bundle_sha256"], info["stage_bundle_sha256"]), file=sys.stderr)
    print("  external %-17s %s" % ("seed", report["external"]["nova_compiler"]["sha256"]), file=sys.stderr)
    print("  external %-17s %s" % ("expected_producer", report["external"]["expected_producer_sha256"]),
          file=sys.stderr)
    print("  %s" % report["external"]["note"], file=sys.stderr)
    print("A8MANIFEST_DONE status=ok policy=%s" % TAG, file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
