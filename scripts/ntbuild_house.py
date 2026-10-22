#!/usr/bin/env python3
"""House build A8: the pinned Nova bootstrap, rebuilt through the house transport.

This builder owns three things and refuses to trade any of them away:

  * the MANIFEST is an input, never an authorization. It pins bytes; it grants
    nothing, and no boolean inside it opens anything.
  * the pinned SEED is a TRUST ROOT. This build checks its digest and its PE64
    shape; it does NOT claim that the build proves where the seed came from.
  * the RESULT is never copied. The bytes reported are the bytes the transport
    extracted out of the emulated machine, and the expected digest comes from
    outside this build (the parent), never from the build's own output.

The transport (scripts/nova_native_transport.py, owned by another worker) is the
only way out of this process: no shell, no installer, no NASM, no C compiler,
no native_pe_run loader. Standard library only.

Commands: build (default), policy, check PATH..., pins, selftest, selfhost.
Exit codes: 0 delivered, 1 build failed, 78 refused (policy).

REPOSITORY PATHS. This is the A8 CANDIDATE house build, brought over from the
archived house stage (house-stage-20261021-01) into the reorganised tree. The
paths it reads are the ones docs/architecture/source-map.csv publishes:

  toolchain/ntasm-nova/    -> compiler/nova/     (the .nova sources, NESTED
                                                 by responsibility)
  toolchain/nova-runtime/  -> compiler/runtime/  (the two flat .ntasm files)
  bootstrap/quarantine/nasm -> legacy/nasm/       (the quarantined NASM tree)
  bootstrap/quarantine/c    -> compiler/c/        (the C bootstrap dependency)

TWO ARTEFACTS THE TREE DOES NOT HOLD, and that this builder therefore cannot
find: the manifest (bootstrap/nova-native/manifest.json) and the pinned seed
(bootstrap/nova-native/nova-compiler.EFI) are PUBLISHED artefacts, not files
of this repository. Their references are kept exactly as the stage wrote them;
a run that needs them is refused, not faked.

THE SEED IS EXTERNAL, THE WAY THE TRANSPORT'S IMAGES ARE. --seed-dir names the
directory that holds the pinned seed, and that directory may be OUTSIDE this
repository: the transport already takes its firmware and its images as
arguments, and the seed is the same kind of thing. The default stays the
repository path bootstrap/nova-native. Naming another directory changes
nothing about the seed itself: its digest is still checked against the
manifest, its path must still resolve inside that directory, and a missing
seed is still refused (class seed-missing), never faked from another file.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import signal
import struct
import subprocess
import sys
import time
import unittest
from pathlib import Path

EXIT_OK = 0
EXIT_BUILD_FAILED = 1
EXIT_REFUSED = 78

POLICY_TAG = "NTHOUSE-POLICY/1"

# The manifest is FIXED: it is read, never written by this builder, and the
# parent fills it later from real evidence. There is no fallback manifest.
MANIFEST_SCHEMA = "NEXORA_NOVA_BOOTSTRAP_V1"
# The manifest and the pinned seed are PUBLISHED artefacts: they are not files
# of this repository, and source-map.csv maps nothing for them. The references
# are kept as the house stage wrote them, so a run that needs them is refused
# with the name of the artefact, never faked from another file.
MANIFEST_REL = "bootstrap/nova-native/manifest.json"
SEED_DIR_REL = "bootstrap/nova-native"
# The pinned seed is a PUBLISHED artefact: it is NOT a file of this repository
# and must not be committed. It may live outside the tree, and --seed-dir
# (NG_SEED_DIR in the shell front) says where. The default stays the
# repository path above; whichever directory is named, it is a TRUST ANCHOR:
# the manifest's nova_compiler.path must resolve inside it.
SEED_DIR_ENV = "NG_SEED_DIR"
# toolchain/ntasm-nova/ -> compiler/nova/ (source-map.csv). The tree is NESTED
# in this repository: the .nova files are classified by responsibility under
# compiler/nova/{analysis,backend,drivers,formats,frontend,inspectors,ir,
# macros}/. The NTASM tree is still flat: compiler/runtime/ holds exactly
# runtime-v2-s0.ntasm and uefi-host-s0.ntasm.
#
# WHY THE FLAT RULE IS GONE. "A house source is one flat .nova file directly
# under the tree" described the LAYOUT of the stage, not the A8 contract: the
# stage's toolchain/ntasm-nova/ held one flat directory of sources, and the
# rule named that directory. What the contract states is the pinned closure,
# byte for byte: the manifest names the sources, their order and their
# digests. A rule that refuses a source for its DEPTH refuses a source the
# manifest pins, which is the opposite of what the contract asks. The rule
# that replaces it is the one the contract states: a house source is a .nova
# file UNDER compiler/nova, at any depth, whose digest matches the manifest
# pin. The count, the order, the uniqueness, the .nova suffix and the
# path-escape checks stay exactly as they were: a .nova file under the tree
# that the manifest does not name is still not a house source.
NOVA_TREE_REL = "compiler/nova"
NTASM_TREE_REL = "compiler/runtime"
OUT_REL = "out/ntasm-house"
TRANSPORT_REL = "scripts/nova_native_transport.py"
TEST_REL = "scripts/tests/test_ntbuild_house.py"

# The two pinned Nova closures, in the order the manifest gives them. The root
# source is FIRST in each list, so the NVSRC001 root_index is 0 for both.
COMPILER_SOURCE_COUNT = 56
PRODUCER_SOURCE_COUNT = 52
# The root source of each closure, under the new layout. The stage's roots
# were toolchain/ntasm-nova/{nova_native_driver_many,ntasm_native_driver}.nova;
# the reorganization moved them into the drivers/ directory of the tree.
COMPILER_ROOT_REL = "compiler/nova/drivers/nova_native_driver_many.nova"
PRODUCER_ROOT_REL = "compiler/nova/drivers/ntasm_native_driver.nova"

# NVSRC001 limits, identical to ../runtime-native/pack_sources.py.
MAX_SOURCES = 64
MAX_BLOB = 4 * 1024 * 1024
NVSRC_MAGIC = b"NVSRC001"

# The transport deadline, in seconds. The DEFAULT is the bounded full-build
# budget: a full build on TCG runs 45 batches and was still producing batch 19
# of 45 when a 3600 s deadline expired (no runtime error, RAM healthy), so the
# normal no-argument build needs a budget that can actually finish. The bound
# stays FINITE and the minimum stays 10: this is a deadline, not "no limit".
# The transport carries the same ceiling, so a build at the bound is never
# refused by the transport it calls.
TIMEOUT_DEFAULT = 10800
TIMEOUT_MIN = 10
TIMEOUT_MAX = 10800

# The parent's CPU gate. The BUILDER owns it; the transport never takes it.
LOCK_PATH = "/tmp/nexora-a7-cpu-safe-gates.lock"
LOCK_WAIT_S = 300

# How long the transport's process group is given to die on SIGTERM before
# SIGKILL. Bounded, because a group that survives the builder is the fault
# this whole path exists to prevent.
GROUP_STOP_GRACE_S = 5.0

ASSEMBLY_EXTS = {".asm", ".ASM", ".nasm", ".NASM", ".s", ".S", ".sx"}
C_EXTS = {".c", ".h"}
HEX64 = re.compile(r"[0-9a-fA-F]{64}\Z")

MANIFEST_KEYS = (
    "schema",
    "nova_compiler",
    "compiler_sources",
    "producer_sources",
    "compiler_bundle_sha256",
    "producer_bundle_sha256",
    "expected_producer_sha256",
    "runtime",
    "host",
)
# bootstrap_history is descriptive: it is never read, never a proof.
# Any other key is ignored and reported, so nothing can be smuggled in and
# nothing can be authorized by a flag nobody wrote a rule for.
IGNORED_MANIFEST_KEYS = ("bootstrap_history",)


# ---------------------------------------------------------------------------
# refusals
# ---------------------------------------------------------------------------


class Refusal(Exception):
    """A policy refusal: the tree or the manifest says no. Exit 78."""

    def __init__(self, cls, reason, input_path=""):
        super().__init__(reason)
        self.cls = cls
        self.reason = reason
        self.input_path = input_path


class BuildFailure(Exception):
    """The build ran and did not deliver. Exit 1."""

    def __init__(self, reason, input_path=""):
        super().__init__(reason)
        self.reason = reason
        self.input_path = input_path


class BuildTerminated(BaseException):
    """SIGTERM reached the builder.

    It is a BaseException on purpose: it must not be swallowed by an
    ``except Exception`` anywhere on the way out. The run has to be CLEANED
    UP (the transport's process group included), not abandoned silently.
    """


def _install_signal_handlers():
    """Turn SIGTERM into an exception, so the cleanup in the finally runs.

    Python's default SIGTERM handling kills the process on the spot. The
    transport's process group would then survive it, and its QEMU with it.
    Raising instead lets the transport's own cleanup take the group down
    first, and the builder exits afterwards with a message instead of dying
    without a word.
    """

    def handler(signum, _frame):
        raise BuildTerminated("the builder received signal %d" % signum)

    sigterm = getattr(signal, "SIGTERM", None)
    if sigterm is None:
        return
    try:
        signal.signal(sigterm, handler)
    except (ValueError, OSError, RuntimeError):
        # Not the main thread, or the signal cannot be set here. The builder
        # then dies the default way, which is the platform's business.
        pass


def refuse(cls, reason, input_path=""):
    raise Refusal(cls, reason, input_path)


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def digest_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def is_within(child, root):
    try:
        child.relative_to(root)
        return True
    except ValueError:
        return False


def split_relative(rel, what):
    """Split a declared relative path, refusing absolute paths and traversal."""
    if not isinstance(rel, str) or not rel.strip():
        refuse("manifest-bad-path", "%s is not a path" % what)
    if rel.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", rel) or "\\" in rel:
        refuse("manifest-bad-path", "%s must be a relative path with '/' separators: %r" % (what, rel))
    parts = rel.split("/")
    if any(part in ("", ".", "..") for part in parts):
        refuse("manifest-bad-path", "%s must not contain an empty, '.' or '..' component: %r" % (what, rel))
    return parts


def resolve_under(base, rel, root, what):
    """Resolve a declared path under a permitted root; escapes are refused.

    `base` is the directory the declared path is relative to: the repository
    root for the repo-relative paths, the manifest's own directory for the
    seed. The resolution follows symlinks, so a link pointing outside the
    permitted root is refused even though the declared path looked harmless.
    """
    parts = split_relative(rel, what)
    resolved = base.joinpath(*parts).resolve()
    if not is_within(resolved, root.resolve()):
        refuse("path-escape", "%s resolves outside %s: %r" % (what, root, rel), rel)
    return resolved


def read_regular(path, what, cls="source-missing"):
    if not path.exists():
        refuse(cls, "%s does not exist: %s" % (what, path))
    if not path.is_file():
        refuse(cls, "%s is not a regular file: %s" % (what, path))
    return path.read_bytes()


def default_seed_dir(repo):
    """The seed directory of the repository: bootstrap/nova-native."""
    return (Path(repo) / SEED_DIR_REL).resolve()


def resolve_seed_dir(repo, seed_dir=None):
    """The seed directory of a COMMAND LINE: option, then environment, then
    the repository path.

    This is the one place that reads the environment: the explicit
    --seed-dir first, then NG_SEED_DIR (the shell front forwards it as
    --seed-dir), then the repository path bootstrap/nova-native. The result
    is resolved, so a symlinked directory is followed and the containment
    check that follows compares resolved paths. The library below never
    reads the environment: it is given a directory, or the default.
    """
    if seed_dir:
        return Path(seed_dir).resolve()
    env = os.environ.get(SEED_DIR_ENV, "").strip()
    if env:
        return Path(env).resolve()
    return default_seed_dir(repo)


def need_hex64(value, what):
    if not isinstance(value, str) or not HEX64.match(value):
        refuse("manifest-bad-digest", "%s must be 64 hex characters" % what)
    return value.lower()


# ---------------------------------------------------------------------------
# NVSRC001, byte for byte the protocol of ../runtime-native/pack_sources.py
# ---------------------------------------------------------------------------


def pack_nvsrc001(items, root_index=0):
    """Pack (name, bytes) pairs into one NVSRC001 packet.

    Layout, exactly as pack_sources.py writes it:
      header  <8sQQQ>  b'NVSRC001', source_count, root_index, blob_bytes
      spans   <QQ>     per source, (offset, size), in list order
      blob              the source bytes, concatenated in list order
    The packet is what the manifest pins (compiler_bundle_sha256 and
    producer_bundle_sha256), so the order of the list is part of the pin.
    """
    count = len(items)
    if not 1 <= count <= MAX_SOURCES:
        refuse("source-count", "NVSRC001 takes 1..%d sources, got %d" % (MAX_SOURCES, count))
    if not 0 <= root_index < count:
        refuse("source-root-index", "root_index %d is outside 0..%d" % (root_index, count - 1))
    spans = []
    offset = 0
    for _, data in items:
        if not data:
            refuse("source-empty", "an empty source is refused by the protocol")
        if offset + len(data) > MAX_BLOB:
            refuse("source-blob-too-large", "the source blob exceeds %d bytes" % MAX_BLOB)
        spans.append((offset, len(data)))
        offset += len(data)
    blob = b"".join(data for _, data in items)
    packet = struct.pack("<8sQQQ", NVSRC_MAGIC, count, root_index, len(blob))
    packet += b"".join(struct.pack("<QQ", start, size) for start, size in spans) + blob
    return packet


# ---------------------------------------------------------------------------
# PE64
# ---------------------------------------------------------------------------


def pe_info(data):
    """Read the PE64 header fields this build checks. Refuses anything else."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        refuse("not-pe64", "the image does not start with MZ")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        refuse("not-pe64", "the image has no PE signature")
    machine, sections = struct.unpack_from("<HH", data, e_lfanew + 4)
    if machine != 0x8664:
        refuse("not-pe64", "PE machine is 0x%04x, expected x64 (0x8664)" % machine)
    opt = e_lfanew + 24
    if opt + 70 > len(data):
        refuse("not-pe64", "the PE optional header is truncated")
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        refuse("not-pe64", "PE optional header magic is 0x%03x, expected PE32+ (0x20b)" % magic)
    entry = struct.unpack_from("<I", data, opt + 16)[0]
    image_size = struct.unpack_from("<I", data, opt + 56)[0]
    subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    if not 0 < entry < image_size:
        refuse("not-pe64", "the PE entry point is outside the image")
    return {
        "machine": "x64",
        "sections": sections,
        "subsystem": subsystem,
        "entry_rva": entry,
        "image_size": image_size,
        "bytes": len(data),
    }


# ---------------------------------------------------------------------------
# manifest
# ---------------------------------------------------------------------------


def load_manifest(repo):
    """Read and shape-check the FIXED manifest. No fallback, no default file."""
    path = repo / MANIFEST_REL
    if not path.is_file():
        refuse(
            "manifest-missing",
            "no manifest at %s; the house build has no fallback and will not "
            "invent one" % MANIFEST_REL,
            MANIFEST_REL,
        )
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        refuse("manifest-unreadable", "%s is not readable JSON: %s" % (MANIFEST_REL, exc), MANIFEST_REL)
    if not isinstance(data, dict):
        refuse("manifest-unreadable", "%s is not a JSON object" % MANIFEST_REL, MANIFEST_REL)
    if data.get("schema") != MANIFEST_SCHEMA:
        refuse(
            "manifest-schema",
            "manifest schema must be %s, got %r" % (MANIFEST_SCHEMA, data.get("schema")),
            MANIFEST_REL,
        )
    missing = [key for key in MANIFEST_KEYS if key not in data]
    if missing:
        refuse("manifest-incomplete", "manifest is missing: %s" % ", ".join(missing), MANIFEST_REL)
    check_manifest_shape(data)
    return data, sha256(raw)


def check_manifest_shape(data):
    """Check the SHAPE of the manifest: types, digest formats, nothing else.

    This says nothing about the truth of a digest, only that the manifest has
    the shape the policy reads. The truth is checked against the disk.
    """
    seed = data["nova_compiler"]
    if not isinstance(seed, dict):
        refuse("manifest-incomplete", "nova_compiler is not an object")
    if not isinstance(seed.get("path"), str):
        refuse("manifest-bad-path", "nova_compiler.path is not a path")
    need_hex64(seed.get("sha256"), "nova_compiler sha256")
    for label in ("compiler_sources", "producer_sources"):
        entries = data[label]
        if not isinstance(entries, list):
            refuse("manifest-incomplete", "%s is not a list" % label)
        for entry in entries:
            if not isinstance(entry, dict):
                refuse("manifest-incomplete", "%s holds an entry that is not an object" % label)
            if not isinstance(entry.get("path"), str):
                refuse("manifest-bad-path", "%s holds an entry without a path" % label)
            need_hex64(entry.get("sha256"), "%s source sha256" % label)
    for key in ("compiler_bundle_sha256", "producer_bundle_sha256", "expected_producer_sha256"):
        need_hex64(data.get(key), key)
    for label in ("runtime", "host"):
        spec = data[label]
        if not isinstance(spec, dict):
            refuse("manifest-incomplete", "%s is not an object" % label)
        if not isinstance(spec.get("source"), str):
            refuse("manifest-bad-path", "%s.source is not a path" % label)
        need_hex64(spec.get("source_sha256"), "%s source_sha256" % label)
        need_hex64(spec.get("image_sha256"), "%s image_sha256" % label)


def validate_sources(repo, entries, expected_count, label):
    """Validate one pinned Nova source list and return its frozen bytes.

    A house source is a .nova file UNDER the Nova tree, at any depth: the tree
    of this repository is NESTED by responsibility, and the depth of a source
    is the organisation's business, not the contract's. What the contract
    pins is the LIST, its ORDER and the BYTES of every entry, and those are
    checked here exactly as they were: the count, the .nova suffix, the
    uniqueness of the file, the path escape, and the digest. A .nova file
    under the tree that the manifest does not name is not a house source,
    because only the manifest's own list is read here.
    """
    if not isinstance(entries, list):
        refuse("manifest-incomplete", "%s is not a list" % label)
    if not 1 <= len(entries) <= MAX_SOURCES:
        refuse("source-count", "%s must hold 1..%d sources, got %d" % (label, MAX_SOURCES, len(entries)))
    if len(entries) != expected_count:
        refuse(
            "source-count-mismatch",
            "%s holds %d sources, the house closure is %d" % (label, len(entries), expected_count),
        )
    tree = (repo / NOVA_TREE_REL)
    if not tree.is_dir():
        refuse("nova-tree-missing", "the house source tree is missing: %s" % NOVA_TREE_REL)
    root = tree.resolve()
    items = []
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict):
            refuse("manifest-incomplete", "%s holds an entry that is not an object" % label)
        rel = entry.get("path")
        want = need_hex64(entry.get("sha256"), "%s source sha256" % label)
        parts = split_relative(rel, "%s source path" % label)
        prefix = NOVA_TREE_REL.split("/")
        if parts[:len(prefix)] != prefix or len(parts) <= len(prefix):
            refuse(
                "source-not-in-tree",
                "%s source must be a file under %s: %r" % (label, NOVA_TREE_REL, rel),
                rel,
            )
        if not parts[-1].endswith(".nova"):
            refuse("source-not-nova", "%s source is not a .nova file: %r" % (label, rel), rel)
        resolved = resolve_under(repo, rel, root, "%s source" % label)
        if resolved in seen:
            refuse("source-duplicate", "%s names the same file twice: %r" % (label, rel), rel)
        seen.add(resolved)
        data = read_regular(resolved, "%s source" % label)
        got = sha256(data)
        if got != want:
            refuse(
                "source-digest-mismatch",
                "%s source %s: pinned %s, on disk %s" % (label, rel, want, got),
                rel,
            )
        items.append((rel, data))
    return items


def validate_ntasm_source(repo, spec, label):
    """Validate one pinned NTASM-S0 runtime/host source and its image pin.

    The NTASM tree is NOT reorganised: compiler/runtime/ holds exactly the
    two flat .ntasm files, so this rule is unchanged. Only its class name
    follows the tree it names, like the Nova one.
    """
    if not isinstance(spec, dict):
        refuse("manifest-incomplete", "%s is not an object" % label)
    rel = spec.get("source")
    want_source = need_hex64(spec.get("source_sha256"), "%s source_sha256" % label)
    want_image = need_hex64(spec.get("image_sha256"), "%s image_sha256" % label)
    parts = split_relative(rel, "%s source" % label)
    prefix = NTASM_TREE_REL.split("/")
    if len(parts) != len(prefix) + 1 or parts[:len(prefix)] != prefix:
        refuse(
            "source-not-in-runtime-tree",
            "%s source must be one file directly under %s: %r" % (label, NTASM_TREE_REL, rel),
            rel,
        )
    if not parts[-1].endswith(".ntasm"):
        refuse("source-not-ntasm", "%s source is not a .ntasm file: %r" % (label, rel), rel)
    root = (repo / NTASM_TREE_REL).resolve()
    resolved = resolve_under(repo, rel, root, "%s source" % label)
    data = read_regular(resolved, "%s source" % label)
    got = sha256(data)
    if got != want_source:
        refuse("source-digest-mismatch", "%s source %s: pinned %s, on disk %s" % (label, rel, want_source, got), rel)
    return {"rel": rel, "path": resolved, "source_sha256": want_source, "image_sha256": want_image}


def validate_seed(repo, manifest, seed_dir=None):
    """Validate the pinned seed. It stays a TRUST ROOT: pinned, not proven.

    `nova_compiler.path` is relative to the SEED DIRECTORY, not to the
    repository root: it is joined to that directory and must resolve inside
    it. The seed directory is the repository's bootstrap/nova-native unless
    --seed-dir (NG_SEED_DIR) names another one, which is how a checkout that
    does not ship the seed borrows it from outside the tree. The directory
    changes WHERE the bytes are read from; it changes nothing about the
    bytes: the digest is still the one the manifest pins, and a missing seed
    is still refused.
    """
    spec = manifest.get("nova_compiler")
    if not isinstance(spec, dict):
        refuse("manifest-incomplete", "nova_compiler is not an object")
    rel = spec.get("path")
    want = need_hex64(spec.get("sha256"), "nova_compiler sha256")
    root = Path(seed_dir).resolve() if seed_dir else default_seed_dir(repo)
    if not root.is_dir():
        refuse("seed-missing", "the seed directory does not exist: %s" % root, rel)
    resolved = resolve_under(root, rel, root, "nova_compiler path")
    data = read_regular(resolved, "nova_compiler", "seed-missing")
    got = sha256(data)
    if got != want:
        refuse("seed-digest-mismatch", "nova_compiler %s: pinned %s, on disk %s" % (rel, want, got), rel)
    return {"rel": rel, "path": resolved, "sha256": got, "pe": pe_info(data), "dir": str(root)}


# ---------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------


def _signal_group(pgid, sig):
    """Signal ONE group: the one this builder created.

    Nothing else is ever signalled: no pkill, no pid read from anywhere, no
    WSL shutdown. A group that is already gone is not an error.
    """
    try:
        os.killpg(pgid, sig)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return False


def _group_exists(pgid):
    """Is the group still there? A probe (signal 0), not a signal."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def _stop_process_group(proc, grace=GROUP_STOP_GRACE_S):
    """Take down the WHOLE group of a process this builder started.

    THE PROBE COMES FIRST: when the group has no member left, nothing is
    signalled at all. That is what keeps a stale id from being hit, and the
    probe costs nothing (signal 0 delivers nothing).

    Then SIGTERM, a bounded wait, and SIGKILL for whatever survived.

    On the timeout and interruption paths the leader is NOT reaped here: an
    unreaped pid stays reserved, so the kernel keeps that id and it cannot
    name another group while we signal it. On a normal return with a
    non-zero code the leader HAS already been reaped by communicate(), which
    is one more reason the probe comes first.

    Returns True when the group was signalled, False when there was nothing
    left of it.
    """
    pgid = proc.pid
    if not _group_exists(pgid):
        return False
    _signal_group(pgid, signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        if not _group_exists(pgid):
            break
        time.sleep(0.05)
    _signal_group(pgid, signal.SIGKILL)
    return True


def _reap_leader(proc):
    """Collect the leader. Called only when communicate() did not finish.

    On those paths the leader was still unreaped, so its pid was reserved
    while the group was being signalled.
    """
    try:
        return proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        return None
    except OSError:
        return None


def _drain(proc, timeout=5):
    """Collect what the dead group left in the pipes, so it stays readable."""
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except (subprocess.TimeoutExpired, OSError, ValueError):
        return b"", b""
    return stdout or b"", stderr or b""


class Transport:
    """Closed call surface of scripts/nova_native_transport.py.

    shell=True is never used and no external command is built by string
    concatenation: argv is a list, always. The transport owns QEMU, mtools and
    the RAM gate; this builder only asks it to assemble and to run a core.

    The transport is started in its OWN process group, and this class takes
    that whole group down on every path except a clean success: a timeout, an
    interruption, an error, and a normal return whose code is not zero. A
    transport that dies on its own leaves its QEMU running: the orphan keeps
    the parent's CPU and RAM budget busy, and the NEXT run refuses because
    another QEMU is already running. No pkill, no pid from outside this
    builder, no WSL stop: one group, the one this builder created.
    """

    def __init__(self, script, repo, work_root, timeout, runner=None, python=None,
                 grace=GROUP_STOP_GRACE_S):
        self.script = Path(script)
        self.repo = Path(repo)
        self.work_root = Path(work_root)
        self.timeout = timeout
        self.python = python or sys.executable
        self.grace = grace
        self.runner = runner or self._default_runner
        self.commands = []

    def _default_runner(self, argv, timeout):
        """Run the transport in its own group, and leave nothing behind.

        start_new_session=True makes the child a session and group leader: its
        pgid is its pid, and nothing else can be inside that group. No other
        id is ever signalled.

        THE GROUP IS STOPPED ON EVERY PATH BUT A CLEAN SUCCESS: a timeout, an
        interruption, an error, and ALSO a normal return with a non-zero code
        or no code at all, because a transport that dies on its own may leave
        its QEMU running. The signals go out ONCE per run: the branches below
        and the return path are exclusive.

        WHAT IS TRUE OF THE ID, WITHOUT EXAGGERATING: on the timeout and
        interruption paths the leader is still unreaped when the group is
        signalled, so the kernel keeps that id and it cannot name another
        group. On a NORMAL return, communicate() has already reaped the
        leader, so the id is free again and could in principle be recycled;
        that is why the group is probed first and NOTHING is signalled when it
        is empty.

        stdout, stderr and the return code stay usable.
        """
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            start_new_session=True,
        )
        reaped = False
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            reaped = True
        except subprocess.TimeoutExpired as exc:
            _stop_process_group(proc, self.grace)
            stdout, stderr = _drain(proc)
            raise subprocess.TimeoutExpired(argv, timeout, output=stdout, stderr=stderr) from exc
        except BaseException:
            # KeyboardInterrupt, a SIGTERM turned into an exception, any error:
            # the group must not outlive this call.
            _stop_process_group(proc, self.grace)
            raise
        finally:
            if not reaped:
                # communicate() did not finish: the leader is still our child
                # and is collected here, AFTER the group was taken down.
                _reap_leader(proc)
        rc = proc.returncode
        if rc is None or rc != 0:
            # The transport left on its own with a failure, so its own cleanup
            # may not have run: its QEMU can still be alive. The group goes
            # down here too, with the same single round of signals.
            _stop_process_group(proc, self.grace)
        return subprocess.CompletedProcess(argv, rc, stdout, stderr)

    def _call(self, name, arguments):
        argv = [
            self.python,
            str(self.script),
            "--repo", str(self.repo),
            "--work-root", str(self.work_root),
            "--name", name,
            "--timeout", str(self.timeout),
        ] + [str(item) for item in arguments]
        self.commands.append({"name": name, "argv": argv})
        try:
            proc = self.runner(argv, self.timeout + 120)
        except subprocess.TimeoutExpired as exc:
            # The group is already down; what the transport printed before it
            # died stays readable here.
            stream = getattr(exc, "stderr", None) or getattr(exc, "output", None) or b""
            tail = stream.decode("utf-8", "replace")[-600:].strip()
            raise BuildFailure(
                "the transport timed out on %s after %ss%s"
                % (name, self.timeout + 120, (": " + tail) if tail else "")
            ) from exc
        except OSError as exc:
            raise BuildFailure("the transport could not be started on %s: %s" % (name, exc)) from exc
        stdout = getattr(proc, "stdout", b"") or b""
        stderr = getattr(proc, "stderr", b"") or b""
        rc = getattr(proc, "returncode", None)
        if not isinstance(rc, int) or isinstance(rc, bool):
            # A runner that reports no return code has NOT succeeded. Reading a
            # missing returncode as 0 is how a run that never happened turns
            # into a green build.
            raise BuildFailure(
                "the transport runner returned no usable returncode for %s "
                "(stdout=%r stderr=%r)" % (name, stdout[-200:], stderr[-200:]),
            )
        if rc != 0:
            stream = stderr or stdout or b""
            tail = stream.decode("utf-8", "replace")[-600:].strip()
            if rc == 2:
                # The transport refuses on a contract or an environment fact
                # (RAM, another QEMU, missing firmware). That is a refusal,
                # and it is not the same claim as a run that failed.
                raise Refusal(
                    "transport-refused",
                    "the transport refused %s: %s" % (name, tail or "no message given"),
                )
            raise BuildFailure("the transport failed on %s (rc=%d)%s" % (name, rc, (": " + tail) if tail else ""))
        return proc

    def assemble(self, name, source):
        """Assemble one NTASM-S0 source; returns the produced.EFI path."""
        self._call(name, ["assemble", str(source)])
        produced = self.work_root / name / "produced.EFI"
        if not produced.is_file():
            raise BuildFailure("the transport %s produced no produced.EFI" % name)
        return produced

    def run_core(self, name, host, runtime, core, payload):
        """Run one Nova core under the host/runtime pair; returns the extraction."""
        self._call(
            name,
            [
                "run", str(host), str(runtime), str(core),
                "--payload", "NOVA.IN=" + str(payload),
                "--extract-file", "OUTPUT.EFI",
            ],
        )
        extracted = self.work_root / name / "extracted-OUTPUT.EFI"
        if not extracted.is_file():
            raise BuildFailure("the transport %s extracted no OUTPUT.EFI" % name)
        return extracted


# ---------------------------------------------------------------------------
# the CPU safety gate
# ---------------------------------------------------------------------------


class CpuSafetyLock:
    """The parent's CPU gate: /tmp/nexora-a7-cpu-safe-gates.lock, fcntl.

    The builder owns this lock; the transport never takes it. The wait is
    bounded, and a lock that cannot be taken is a refusal, not a race.
    """

    def __init__(self, path=LOCK_PATH, wait_s=LOCK_WAIT_S):
        self.path = path
        self.wait_s = wait_s
        self.fd = None
        self._fcntl = None

    def __enter__(self):
        try:
            import fcntl
        except ImportError as exc:  # pragma: no cover - the build runs on Linux/WSL
            raise Refusal(
                "lock-unavailable",
                "fcntl is required to hold the CPU safety gate; the house build "
                "runs on the Linux/WSL host",
            ) from exc
        self._fcntl = fcntl
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o644)
        deadline = time.monotonic() + self.wait_s
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(self.fd)
                    self.fd = None
                    raise Refusal(
                        "lock-timeout",
                        "the CPU safety gate %s was still taken after %ds" % (self.path, self.wait_s),
                    )
                time.sleep(1.0)

    def __exit__(self, exc_type, exc, tb):
        if self.fd is not None:
            try:
                self._fcntl.flock(self.fd, self._fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self.fd = None
        return False


# ---------------------------------------------------------------------------
# the build
# ---------------------------------------------------------------------------


def new_run_dir(repo):
    """Create a FRESH dated+nonce directory under out/ntasm-house."""
    base = repo / OUT_REL
    base.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    for _ in range(8):
        candidate = base / ("%s-%s" % (stamp, os.urandom(4).hex()))
        try:
            candidate.mkdir()
        except FileExistsError:
            continue
        return candidate
    raise BuildFailure("no fresh run directory could be created under %s" % OUT_REL)


class HouseBuild:
    """The house build itself. Every method is unit-testable with a mock."""

    def __init__(self, repo, timeout, transport=None, run_dir=None, lock=None, seed_dir=None):
        self.repo = Path(repo).resolve()
        self.timeout = timeout
        self.transport = transport
        self.run_dir = Path(run_dir) if run_dir else None
        self.lock = lock
        # Where the PUBLISHED seed is read from. The default is the
        # repository's bootstrap/nova-native; --seed-dir names a directory
        # outside the tree. The seed is still checked against the manifest.
        self.seed_dir = Path(seed_dir).resolve() if seed_dir else default_seed_dir(self.repo)

    # -- validation ---------------------------------------------------------

    def validate(self):
        """Check every pin, freeze the bytes, and pack both NVSRC001 bundles."""
        manifest, manifest_sha = load_manifest(self.repo)
        ignored = sorted(
            key for key in manifest
            if key not in MANIFEST_KEYS and key not in IGNORED_MANIFEST_KEYS
        )
        seed = validate_seed(self.repo, manifest, self.seed_dir)
        compiler_items = validate_sources(
            self.repo, manifest["compiler_sources"], COMPILER_SOURCE_COUNT, "compiler_sources"
        )
        producer_items = validate_sources(
            self.repo, manifest["producer_sources"], PRODUCER_SOURCE_COUNT, "producer_sources"
        )
        compiler_packet = pack_nvsrc001(compiler_items, 0)
        producer_packet = pack_nvsrc001(producer_items, 0)
        want_compiler = need_hex64(manifest["compiler_bundle_sha256"], "compiler_bundle_sha256")
        want_producer = need_hex64(manifest["producer_bundle_sha256"], "producer_bundle_sha256")
        compiler_bundle = sha256(compiler_packet)
        producer_bundle = sha256(producer_packet)
        if compiler_bundle != want_compiler:
            refuse(
                "bundle-mismatch",
                "compiler bundle: pinned %s, packed %s (the list or its order moved)"
                % (want_compiler, compiler_bundle),
            )
        if producer_bundle != want_producer:
            refuse(
                "bundle-mismatch",
                "producer bundle: pinned %s, packed %s (the list or its order moved)"
                % (want_producer, producer_bundle),
            )
        expected_producer = need_hex64(manifest["expected_producer_sha256"], "expected_producer_sha256")
        runtime = validate_ntasm_source(self.repo, manifest["runtime"], "runtime")
        host = validate_ntasm_source(self.repo, manifest["host"], "host")
        return {
            "manifest": manifest,
            "manifest_sha256": manifest_sha,
            "ignored_manifest_keys": ignored,
            "seed": seed,
            "compiler_items": compiler_items,
            "producer_items": producer_items,
            "compiler_packet": compiler_packet,
            "producer_packet": producer_packet,
            "compiler_bundle": compiler_bundle,
            "producer_bundle": producer_bundle,
            "expected_producer_sha256": expected_producer,
            "runtime": runtime,
            "host": host,
        }

    # -- helpers ------------------------------------------------------------

    def _transport(self, run_dir):
        if self.transport is not None:
            return self.transport
        script = self.repo / TRANSPORT_REL
        if not script.is_file():
            raise BuildFailure(
                "the house transport is missing: %s (it is owned by another worker)" % TRANSPORT_REL
            )
        return Transport(script, self.repo, run_dir, self.timeout)

    def _check_image(self, path, want, label):
        got = digest_file(path)
        if got != want:
            refuse(
                "image-digest-mismatch",
                "%s image: pinned %s, rebuilt %s" % (label, want, got),
            )
        return got

    def _pe_or_fail(self, data, what):
        try:
            return pe_info(data)
        except Refusal as exc:
            raise BuildFailure("%s is not a PE64 image: %s" % (what, exc.reason)) from exc

    def _recheck(self, state):
        """Re-read the sources and the seed: a concurrent edit is a refusal."""
        for rel, data in list(state["compiler_items"]) + list(state["producer_items"]):
            now = read_regular(self.repo / rel, "source")
            if sha256(now) != sha256(data):
                refuse("source-changed-during-build", "the source moved while the build ran: %s" % rel, rel)
        for label in ("runtime", "host"):
            rel = state[label]["rel"]
            now = read_regular(self.repo / rel, "%s source" % label)
            if sha256(now) != state[label]["source_sha256"]:
                refuse("source-changed-during-build", "the %s source moved while the build ran: %s" % (label, rel), rel)
        seed_now = read_regular(state["seed"]["path"], "nova_compiler", "seed-missing")
        if sha256(seed_now) != state["seed"]["sha256"]:
            refuse("seed-changed-during-build", "the seed moved while the build ran: %s" % state["seed"]["rel"])
        return {"sources_unchanged": True, "seed_unchanged": True}

    def _write_json(self, path, payload):
        with path.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")

    def _record(self, state, run_dir, transport, output, postcheck):
        return {
            "schema": "NTHOUSE_BUILD_V1",
            "status": "ok",
            "policy": POLICY_TAG,
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "repo": str(self.repo),
            "run_dir": str(run_dir),
            "manifest": {
                "path": MANIFEST_REL,
                "sha256": state["manifest_sha256"],
                "schema": MANIFEST_SCHEMA,
                "ignored_keys": state["ignored_manifest_keys"],
                "note": "the manifest pins bytes, it authorizes nothing; bootstrap_history is never a proof",
            },
            "seed": {
                "path": state["seed"]["rel"],
                "directory": state["seed"]["dir"],
                "resolved_path": str(state["seed"]["path"]),
                "sha256": state["seed"]["sha256"],
                "pe": state["seed"]["pe"],
                "role": "pinned trust root; this build checks its digest and its PE64 shape, it does not prove its provenance",
            },
            "sources": {
                "compiler": [
                    {"path": rel, "sha256": sha256(data), "bytes": len(data)}
                    for rel, data in state["compiler_items"]
                ],
                "producer": [
                    {"path": rel, "sha256": sha256(data), "bytes": len(data)}
                    for rel, data in state["producer_items"]
                ],
            },
            "bundles": {
                "compiler": {
                    "protocol": "NVSRC001",
                    "sha256": state["compiler_bundle"],
                    "bytes": len(state["compiler_packet"]),
                    "source_count": len(state["compiler_items"]),
                    "root_index": 0,
                },
                "producer": {
                    "protocol": "NVSRC001",
                    "sha256": state["producer_bundle"],
                    "bytes": len(state["producer_packet"]),
                    "source_count": len(state["producer_items"]),
                    "root_index": 0,
                },
            },
            "images": {
                "runtime": {
                    "source": state["runtime"]["rel"],
                    "source_sha256": state["runtime"]["source_sha256"],
                    "image_sha256": state["runtime"]["image_sha256"],
                },
                "host": {
                    "source": state["host"]["rel"],
                    "source_sha256": state["host"]["source_sha256"],
                    "image_sha256": state["host"]["image_sha256"],
                },
            },
            "transport": {
                "script": TRANSPORT_REL,
                "sha256": digest_file(self.repo / TRANSPORT_REL) if (self.repo / TRANSPORT_REL).is_file() else None,
                "timeout": self.timeout,
                "commands": transport.commands,
            },
            "output": output,
            "postcheck": postcheck,
            "notes": [
                "the produced bytes are the ones the transport extracted; no reference PE was copied as the result",
                "expected_producer_sha256 comes from outside this build and was never repinned from the output",
                "build does NOT claim a self-host run: the selfhost command rebuilds, this one does not",
            ],
        }

    # -- commands -----------------------------------------------------------

    def build(self):
        """Reconstruct the producer with the pinned seed and the house transport."""
        state = self.validate()
        run_dir = self.run_dir or new_run_dir(self.repo)
        self.run_dir = run_dir
        pack_dir = run_dir / "pack"
        try:
            pack_dir.mkdir(exist_ok=False)
        except OSError as exc:
            raise BuildFailure("the run directory %s is not usable: %s" % (run_dir, exc)) from exc
        producer_in = pack_dir / "producer.NOVA.IN"
        producer_in.write_bytes(state["producer_packet"])
        transport = self._transport(run_dir)
        lock = self.lock if self.lock is not None else CpuSafetyLock()
        with lock:
            runtime_image = transport.assemble("runtime", state["runtime"]["path"])
            host_image = transport.assemble("host", state["host"]["path"])
            self._check_image(runtime_image, state["runtime"]["image_sha256"], "runtime")
            self._check_image(host_image, state["host"]["image_sha256"], "host")
            extracted = transport.run_core(
                "producer", host_image, runtime_image, state["seed"]["path"], producer_in
            )
            data = extracted.read_bytes()
            info = self._pe_or_fail(data, "the extracted OUTPUT.EFI")
            produced = sha256(data)
            if produced != state["expected_producer_sha256"]:
                raise BuildFailure(
                    "the extracted OUTPUT.EFI is %s, the expected producer is %s"
                    % (produced, state["expected_producer_sha256"]),
                    str(extracted),
                )
            postcheck = self._recheck(state)
        output = {
            "path": str(extracted),
            "bytes": len(data),
            "sha256": produced,
            "expected_sha256": state["expected_producer_sha256"],
            "matches_expected": True,
            "pe": info,
        }
        record = self._record(state, run_dir, transport, output, postcheck)
        self._write_json(run_dir / "build.json", record)
        print("NTHOUSE_BUILD_DONE status=ok run_dir=%s" % run_dir)
        print("NTHOUSE_OUTPUT sha256=%s bytes=%d path=%s" % (produced, len(data), extracted))
        return EXIT_OK

    def selfhost(self):
        """Seed -> N1 -> N2 on the same package; the bytes must be identical."""
        state = self.validate()
        run_dir = self.run_dir or new_run_dir(self.repo)
        self.run_dir = run_dir
        pack_dir = run_dir / "pack"
        try:
            pack_dir.mkdir(exist_ok=False)
        except OSError as exc:
            raise BuildFailure("the run directory %s is not usable: %s" % (run_dir, exc)) from exc
        first_in = pack_dir / "n1" / "NOVA.IN"
        second_in = pack_dir / "n2" / "NOVA.IN"
        first_in.parent.mkdir(exist_ok=False)
        second_in.parent.mkdir(exist_ok=False)
        first_in.write_bytes(state["compiler_packet"])
        second_in.write_bytes(state["compiler_packet"])
        transport = self._transport(run_dir)
        lock = self.lock if self.lock is not None else CpuSafetyLock()
        with lock:
            runtime_image = transport.assemble("runtime", state["runtime"]["path"])
            host_image = transport.assemble("host", state["host"]["path"])
            self._check_image(runtime_image, state["runtime"]["image_sha256"], "runtime")
            self._check_image(host_image, state["host"]["image_sha256"], "host")
            n1_path = transport.run_core(
                "selfhost-n1", host_image, runtime_image, state["seed"]["path"], first_in
            )
            n1 = n1_path.read_bytes()
            self._pe_or_fail(n1, "the first generation")
            n2_path = transport.run_core("selfhost-n2", host_image, runtime_image, n1_path, second_in)
            n2 = n2_path.read_bytes()
            self._pe_or_fail(n2, "the second generation")
            postcheck = self._recheck(state)
        if n1 != n2:
            raise BuildFailure(
                "the two generations differ: %s vs %s" % (sha256(n1), sha256(n2)),
                str(n2_path),
            )
        output = {
            "n1": {"path": str(n1_path), "sha256": sha256(n1), "bytes": len(n1)},
            "n2": {"path": str(n2_path), "sha256": sha256(n2), "bytes": len(n2)},
            "identical": True,
            "pinned_seed_sha256": state["seed"]["sha256"],
            "n1_equals_pinned_seed": sha256(n1) == state["seed"]["sha256"],
            "note": "this command really rebuilt twice; an existing report is not an execution",
        }
        record = self._record(state, run_dir, transport, output, postcheck)
        record["schema"] = "NTHOUSE_SELFHOST_V1"
        self._write_json(run_dir / "selfhost.json", record)
        print("NTHOUSE_SELFHOST_DONE status=ok run_dir=%s" % run_dir)
        print("NTHOUSE_SELFHOST sha256=%s identical=yes" % sha256(n1))
        return EXIT_OK


# ---------------------------------------------------------------------------
# policy, check, pins, selftest
# ---------------------------------------------------------------------------


def cmd_policy(repo):
    print(POLICY_TAG)
    print("exit codes: %d delivered, %d build failed, %d refused (policy)" % (EXIT_OK, EXIT_BUILD_FAILED, EXIT_REFUSED))
    print("manifest: %s (schema %s), read-only, filled by the parent from real evidence" % (MANIFEST_REL, MANIFEST_SCHEMA))
    print("  the manifest pins bytes; it authorizes nothing. A 'selfhost' flag inside it")
    print("  opens nothing: the selfhost command always rebuilds both generations.")
    print("granted house sources: the .nova files under %s, nested by responsibility" % NOVA_TREE_REL)
    print("  a house source is a .nova file under %s at any depth" % NOVA_TREE_REL)
    print("  the manifest pins the LIST, its ORDER and the BYTES of every source")
    print("  a .nova file under the tree that the manifest does not name is not a house source")
    print("  compiler_sources: %d entries, root %s first" % (COMPILER_SOURCE_COUNT, COMPILER_ROOT_REL))
    print("  producer_sources: %d entries, root %s first" % (PRODUCER_SOURCE_COUNT, PRODUCER_ROOT_REL))
    print("granted runtime sources: the .ntasm files directly under %s" % NTASM_TREE_REL)
    print("trusted root: the pinned seed PE (%s/nova-compiler.EFI)" % SEED_DIR_REL)
    print("  the seed is pinned and checked; the build does NOT prove its provenance.")
    print("  the seed is a PUBLISHED artefact: --seed-dir (env %s) names the directory" % SEED_DIR_ENV)
    print("  that holds it, and that directory may be outside this repository.")
    print("  default: the repository path %s; the digest is checked against the" % SEED_DIR_REL)
    print("  manifest either way, and a missing seed is refused (seed-missing), never faked.")
    print("protocol: NVSRC001, %d..%d sources, blob <= %d bytes, root first (root_index=0)" % (1, MAX_SOURCES, MAX_BLOB))
    print("  the bundle digest pins the LIST and its ORDER; a moved list is a refusal.")
    print("transport: %s, closed argv, shell=True never used" % TRANSPORT_REL)
    print("  QEMU 512M/4 vCPU, no network; the RAM gate (9GiB start / 8GiB stop) is measured by the transport")
    print("  the 4 vCPUs do NOT parallelize the build: the emulated compiler stays SEQUENTIAL, one job at a time")
    print("  no 4x speedup is claimed; the build is not parallelized")
    print("  a transport success requires the marker, the firmware return, HMP, QEMU rc0 and no forced stop")
    print("outputs: one FRESH directory under %s/<utc>-<nonce>; nothing is removed or overwritten" % OUT_REL)
    print("lock: %s, exclusive fcntl, bounded wait %ds; the builder owns it, the transport never takes it" % (LOCK_PATH, LOCK_WAIT_S))
    print("refused classes:")
    for cls in (
        "manifest-missing", "manifest-unreadable", "manifest-schema", "manifest-incomplete",
        "manifest-bad-digest", "manifest-bad-path",
        "source-count", "source-count-mismatch", "source-duplicate", "source-empty",
        "source-not-in-tree", "source-not-in-runtime-tree", "source-not-nova", "source-not-ntasm",
        "path-escape", "source-missing", "source-digest-mismatch",
        "bundle-mismatch", "seed-missing", "seed-digest-mismatch", "not-pe64",
        "image-digest-mismatch", "source-changed-during-build", "seed-changed-during-build",
        "lock-unavailable", "lock-timeout", "timeout-out-of-range", "transport-refused",
    ):
        print("  %s" % cls)
    print("never admitted as a source: .c .h .asm .nasm .s, anything under legacy/nasm/ or")
    print("  compiler/c/, anything under out/, the C loader native_pe_run, NASM and every assembler")
    print("C: this build grants NO C at all. The temporary ADR0012 exception belongs to")
    print("  scripts/ntbuild.sh (the C bootstrap producer); the house build never calls it,")
    print("  and the C history of the very first bootstrap stays declared, not called.")
    return EXIT_OK


def classify_source(repo, raw):
    """Classify one candidate path against the house policy.

    A house source is a .nova file UNDER the Nova tree, at any depth: the
    tree of this repository is nested by responsibility, and the depth of a
    source is not what the contract pins. Everything else stays refused:
    the C sources, the assemblers, the quarantined trees and the outputs.
    """
    repo = Path(repo).resolve()
    path = Path(raw)
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    else:
        path = path.resolve()
    suffix = path.suffix
    try:
        rel = path.relative_to(repo)
    except ValueError:
        rel = None
    if rel is not None and rel.parts and rel.parts[0] == "out":
        return False, "out-artifact", "out/ holds build outputs, never a source"
    if rel is not None and rel.parts[:2] in (("legacy", "nasm"), ("compiler", "c")):
        return False, "quarantine-source", "legacy/nasm/ and compiler/c/ are quarantined and never a house source"
    if suffix in C_EXTS:
        return False, "c-source", "the house build compiles Nova, never C"
    if suffix in ASSEMBLY_EXTS:
        return False, "assembly-input", "no assembler is a house source"
    tree = (repo / NOVA_TREE_REL).resolve()
    if not is_within(path, tree):
        return False, "outside-nova-tree", "a house source is a .nova file under %s" % NOVA_TREE_REL
    if suffix != ".nova":
        return False, "source-not-nova", "a house source is a .nova file"
    return True, "allowed", ".nova file under %s, nested by responsibility" % NOVA_TREE_REL


def cmd_check(repo, paths):
    refused = 0
    for raw in paths:
        allowed, cls, why = classify_source(repo, raw)
        if allowed:
            print("NTHOUSE_ALLOWED class=allowed input=%s" % raw)
            print("  reason:  %s" % why)
        else:
            refused += 1
            print("NTHOUSE_REFUSED class=%s" % cls, file=sys.stderr)
            print("  input:   %s" % raw, file=sys.stderr)
            print("  reason:  %s" % why, file=sys.stderr)
    print("NTHOUSE_CHECK inputs=%d refused=%d policy=%s" % (len(paths), refused, POLICY_TAG))
    return EXIT_REFUSED if refused else EXIT_OK


def cmd_pins(repo, seed_dir=None):
    """Print the expected hashes of the house build, and verify them on disk.

    Only the pins that name a file on disk can be verified here. The image
    pins, the bundle pins and the expected producer are values the transport
    and the parent produce; they are printed, never checked against a file.
    The seed is verified against the seed DIRECTORY, the same one the build
    reads it from, so an external seed is verified where it really is.
    """
    seed_dir = Path(seed_dir).resolve() if seed_dir else default_seed_dir(repo)
    try:
        manifest, manifest_sha = load_manifest(repo)
    except Refusal as exc:
        print("NTHOUSE_REFUSED class=%s" % exc.cls, file=sys.stderr)
        print("  input:   %s" % (exc.input_path or MANIFEST_REL), file=sys.stderr)
        print("  reason:  %s" % exc.reason, file=sys.stderr)
        return EXIT_REFUSED
    rows = []
    for label, entries in (("compiler_sources", manifest["compiler_sources"]),
                            ("producer_sources", manifest["producer_sources"])):
        for entry in entries:
            rows.append((entry.get("path"), entry.get("sha256"), "source", repo))
    for label in ("runtime", "host"):
        spec = manifest[label]
        rows.append((spec.get("source"), spec.get("source_sha256"), label + " source", repo))
    rows.append((manifest["nova_compiler"].get("path"), manifest["nova_compiler"].get("sha256"),
                 "seed", seed_dir))
    print("  seed dir %s" % seed_dir)
    ok = 0
    bad = 0
    for path, want, kind, base in rows:
        target = Path(base) / path
        got = digest_file(target) if target.is_file() else None
        if got is not None and isinstance(want, str) and got == want.lower():
            ok += 1
            print("  ok      %-14s %s  %s" % (kind, want.lower(), path))
        else:
            bad += 1
            print("  DIFFERS %-14s pinned=%s actual=%s  %s" % (kind, want, got, path))
    for label, key, note in (
        ("compiler_bundle", "compiler_bundle_sha256", "NVSRC001 packet digest, order included"),
        ("producer_bundle", "producer_bundle_sha256", "NVSRC001 packet digest, order included"),
    ):
        print("  pin     %-14s %s  %s" % (label, manifest[key], note))
    for label in ("runtime", "host"):
        print("  pin     %-14s %s  %s" % (label + " image", manifest[label]["image_sha256"],
                                         "the image the transport must rebuild"))
    print("  pin     %-14s %s  %s" % ("expected_producer", manifest["expected_producer_sha256"],
                                     "independent digest, from the parent"))
    print("  pin     %-14s %s  %s" % ("manifest", manifest_sha, MANIFEST_REL))
    print("NTHOUSE_PINS_VERIFY ok=%d bad=%d" % (ok, bad))
    return EXIT_REFUSED if bad else EXIT_OK


def cmd_selftest(repo):
    """Run this builder's OWN unit tests. No firmware, no transport, no QEMU."""
    tests = repo / TEST_REL
    if not tests.is_file():
        raise BuildFailure("the house unit tests are missing: %s" % TEST_REL)
    spec = importlib.util.spec_from_file_location("test_ntbuild_house", tests)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=2).run(suite)
    print("NTHOUSE_SELFTEST tests=%d failures=%d errors=%d" % (
        result.testsRun, len(result.failures), len(result.errors)))
    return EXIT_OK if result.wasSuccessful() else EXIT_BUILD_FAILED


# ---------------------------------------------------------------------------
# entry point
# ---------------------------------------------------------------------------


COMMANDS = ("build", "policy", "check", "pins", "selftest", "selfhost")
VALUE_OPTIONS = ("--repo", "--timeout", "--seed-dir")


class HouseParser(argparse.ArgumentParser):
    """A malformed invocation is a refusal (78), not argparse's exit 2."""

    def error(self, message):
        self.print_usage(sys.stderr)
        print("NTHOUSE_REFUSED class=usage", file=sys.stderr)
        print("  reason:  %s" % message, file=sys.stderr)
        raise SystemExit(EXIT_REFUSED)


def normalize_argv(argv):
    """`build` is the default command, so a bare path is a build, not an error."""
    out = list(argv)
    index = 0
    while index < len(out):
        token = out[index]
        if token in VALUE_OPTIONS:
            index += 2
            continue
        if token.startswith("--") and "=" in token:
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        if token not in COMMANDS:
            out.insert(index, "build")
        return out
    return out


def build_parser():
    parser = HouseParser(prog="ntbuild_house.py", description="The house build A8.")
    parser.add_argument("--repo", default=None, help="repository root (default: the parent of scripts/)")
    parser.add_argument("--timeout", type=int, default=None, help="transport timeout in seconds (10..10800)")
    parser.add_argument("--seed-dir", default=None,
                        help="directory that holds the PUBLISHED seed PE "
                             "(default: <repo>/%s; env %s)" % (SEED_DIR_REL, SEED_DIR_ENV))
    sub = parser.add_subparsers(dest="command")

    def add(name, help_text):
        item = sub.add_parser(name, help=help_text)
        item.add_argument("--repo", default=argparse.SUPPRESS)
        item.add_argument("--timeout", type=int, default=argparse.SUPPRESS)
        item.add_argument("--seed-dir", default=argparse.SUPPRESS)
        return item

    add("build", "reconstruct the producer through the house transport (default)")
    add("policy", "print the house policy")
    add("pins", "print and verify the expected hashes")
    add("selftest", "run this builder's own unit tests")
    add("selfhost", "seed -> N1 -> N2 on the same package, bytes must match")
    checker = add("check", "classify candidate house sources")
    checker.add_argument("paths", nargs="+")
    return parser


def report_refusal(exc):
    """A refusal is a refusal, not a crash: exit 78, block on stderr."""
    print("NTHOUSE_REFUSED class=%s" % exc.cls, file=sys.stderr)
    if exc.input_path:
        print("  input:   %s" % exc.input_path, file=sys.stderr)
    print("  reason:  %s" % exc.reason, file=sys.stderr)
    print("NTHOUSE_DONE status=refused policy=%s" % POLICY_TAG)


def report_failure(exc):
    print("NTHOUSE_FAILED", file=sys.stderr)
    if exc.input_path:
        print("  input:   %s" % exc.input_path, file=sys.stderr)
    print("  reason:  %s" % exc.reason, file=sys.stderr)
    print("NTHOUSE_DONE status=failed policy=%s" % POLICY_TAG)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    args = build_parser().parse_args(normalize_argv(argv))
    repo = Path(args.repo).resolve() if args.repo else Path(__file__).resolve().parent.parent
    timeout = TIMEOUT_DEFAULT if args.timeout is None else args.timeout
    # Where the PUBLISHED seed is read from: --seed-dir, else NG_SEED_DIR,
    # else the repository path bootstrap/nova-native.
    seed_dir = resolve_seed_dir(repo, args.seed_dir)
    try:
        if not TIMEOUT_MIN <= timeout <= TIMEOUT_MAX:
            refuse("timeout-out-of-range", "--timeout must be %d..%d seconds, got %d" % (
                TIMEOUT_MIN, TIMEOUT_MAX, timeout))
        if args.command == "policy":
            return cmd_policy(repo)
        if args.command == "check":
            return cmd_check(repo, args.paths)
        if args.command == "pins":
            return cmd_pins(repo, seed_dir)
        if args.command == "selftest":
            return cmd_selftest(repo)
        # build and selfhost are the two commands that start the transport:
        # only there does SIGTERM have to become an exception, so that the
        # transport's process group is cleaned up instead of being orphaned.
        _install_signal_handlers()
        builder = HouseBuild(repo, timeout, seed_dir=seed_dir)
        if args.command == "selfhost":
            return builder.selfhost()
        return builder.build()
    except BuildTerminated as exc:
        print("NTHOUSE_TERMINATED", file=sys.stderr)
        print("  reason:  %s" % exc, file=sys.stderr)
        print("NTHOUSE_DONE status=terminated policy=%s" % POLICY_TAG)
        return EXIT_BUILD_FAILED
    except KeyboardInterrupt:
        print("NTHOUSE_INTERRUPTED", file=sys.stderr)
        print("  reason:  the run was interrupted; the transport group was stopped",
              file=sys.stderr)
        print("NTHOUSE_DONE status=interrupted policy=%s" % POLICY_TAG)
        return EXIT_BUILD_FAILED
    except Refusal as exc:
        report_refusal(exc)
        return EXIT_REFUSED
    except BuildFailure as exc:
        report_failure(exc)
        return EXIT_BUILD_FAILED


if __name__ == "__main__":
    sys.exit(main())
