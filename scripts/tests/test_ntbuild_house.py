#!/usr/bin/env python3
"""UNIT TESTS of the house build. They are not, and never will be, A8 proof.

Every case here runs in a TemporaryDirectory with a MOCKED transport: no QEMU,
no real sub-process, no firmware, no real repository file is read or written.
A green run of this file proves that the HOUSE RULES hold on synthetic trees.
It proves nothing about the real A8 delivery, which only the parent's real
transport runs can produce.

The fake manifest NEVER leaves its TemporaryDirectory.

THE SYNTHETIC TREE FOLLOWS THE BUILDER. The fake repository takes its three
trees from the builder's own constants (NOVA_TREE_REL, NTASM_TREE_REL,
SEED_DIR_REL) instead of repeating them as literals: the real source tree was
reorganized, and a fake tree that did not follow the builder would be testing
a tree the builder does not know.
"""

import importlib.util
import json
import os
import shutil
import signal
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
BUILDER_PATH = SCRIPTS / "ntbuild_house.py"


def load_builder():
    spec = importlib.util.spec_from_file_location("ntbuild_house", BUILDER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hb = load_builder()


def allowed_new_path(path, run_dir, out_root):
    """May a path the build CREATED be here?

    - a FILE must be inside the run dir, by real containment;
    - a DIRECTORY may be inside the run dir, or be one of the ancestors the
      builder had to create, strictly under repo/out;
    - nothing else is allowed.

    Containment is `in path.parents`, never a string prefix: a sibling whose
    name starts like the run dir is NOT inside it.
    """
    resolved = Path(path).resolve()
    run = Path(run_dir).resolve()
    out = Path(out_root).resolve()
    inside_run = resolved == run or run in resolved.parents
    if Path(path).is_dir():
        if inside_run:
            return True
        # a necessary ancestor, strictly under out/
        return resolved in run.parents and out in resolved.parents
    return inside_run


# ---------------------------------------------------------------------------
# synthetic artefacts
# ---------------------------------------------------------------------------


def fake_pe64(size=1024):
    """A synthetic PE64 HEADER, good enough for the validator, bootable by no one.

    This is a unit-test fixture for pe_info(), not an image.
    """
    import struct

    data = bytearray(b"\0" * size)
    data[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", data, 0x3C, e_lfanew)
    data[e_lfanew:e_lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HHI", data, e_lfanew + 4, 0x8664, 4, 0)
    opt = e_lfanew + 24
    struct.pack_into("<H", data, opt, 0x20B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<I", data, opt + 56, 0x2000)
    struct.pack_into("<H", data, opt + 68, 10)
    return bytes(data)


class NoLock:
    """The tests never take the parent's real CPU gate."""

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeTransport:
    """A MOCK of scripts/nova_native_transport.py. No process is ever started."""

    def __init__(self, work_root, produced=None, extracted=None, mutate=None, fail_on=()):
        self.work_root = Path(work_root)
        self.produced = dict(produced or {})
        self.extracted = dict(extracted or {})
        self.mutate = mutate
        self.fail_on = set(fail_on)
        self.commands = []

    def _dir(self, name):
        target = self.work_root / name
        target.mkdir(parents=True, exist_ok=True)
        return target

    def assemble(self, name, source):
        self.commands.append(("assemble", name))
        if name in self.fail_on:
            raise hb.BuildFailure("mock transport failure on %s" % name)
        out = self._dir(name) / "produced.EFI"
        out.write_bytes(self.produced.get(name, b""))
        return out

    def run_core(self, name, host, runtime, core, payload):
        self.commands.append(("run", name))
        if name in self.fail_on:
            raise hb.BuildFailure("mock transport failure on %s" % name)
        if not Path(payload).is_file():
            raise hb.BuildFailure("mock transport found no payload")
        out = self._dir(name) / "extracted-OUTPUT.EFI"
        out.write_bytes(self.extracted.get(name, b""))
        if self.mutate is not None:
            self.mutate()
        return out


class FakeRepo:
    """A synthetic repository in a TemporaryDirectory."""

    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix="nthouse-unit-"))
        # The three trees are the builder's own: toolchain/ntasm-nova became
        # compiler/nova and toolchain/nova-runtime became compiler/runtime in
        # the reorganized repository, and the builder is what names them.
        self.nova = self.root / hb.NOVA_TREE_REL
        self.runtime_tree = self.root / hb.NTASM_TREE_REL
        self.seed_dir = self.root / hb.SEED_DIR_REL
        self.nova.mkdir(parents=True)
        self.runtime_tree.mkdir(parents=True)
        self.seed_dir.mkdir(parents=True)
        self.compiler = []
        self.producer = []
        self.compiler.append(self._write_nova("nova_native_driver_many.nova", 0))
        self.producer.append(self._write_nova("ntasm_native_driver.nova", 0))
        for index in range(1, hb.COMPILER_SOURCE_COUNT):
            self.compiler.append(self._write_nova("c%02d.nova" % index, index))
        for index in range(1, hb.PRODUCER_SOURCE_COUNT):
            self.producer.append(self._write_nova("p%02d.nova" % index, index))
        self.runtime_source = self.runtime_tree / "runtime-v2-s0.ntasm"
        self.runtime_source.write_bytes(b"; runtime\nmodule runtime\n")
        self.host_source = self.runtime_tree / "uefi-host-s0.ntasm"
        self.host_source.write_bytes(b"; host\nmodule host\n")
        self.seed = self.seed_dir / "nova-compiler.EFI"
        self.seed.write_bytes(fake_pe64())
        self.runtime_image = fake_pe64(2048)
        self.host_image = fake_pe64(3072)
        self.producer_image = fake_pe64(4096)

    def _write_nova(self, name, index):
        path = self.nova / name
        path.write_bytes(b"// unit fixture %d\n" % index)
        return path

    def manifest(self, **overrides):
        def rows(paths):
            out = []
            for path in paths:
                out.append({
                    "path": "%s/%s" % (hb.NOVA_TREE_REL, path.name),
                    "sha256": hb.digest_file(path),
                })
            return out

        compiler_rows = rows(self.compiler)
        producer_rows = rows(self.producer)
        compiler_bundle = hb.sha256(hb.pack_nvsrc001(
            [(r["path"], (self.nova / Path(r["path"]).name).read_bytes()) for r in compiler_rows]))
        producer_bundle = hb.sha256(hb.pack_nvsrc001(
            [(r["path"], (self.nova / Path(r["path"]).name).read_bytes()) for r in producer_rows]))
        data = {
            "schema": hb.MANIFEST_SCHEMA,
            "nova_compiler": {"path": "nova-compiler.EFI", "sha256": hb.digest_file(self.seed)},
            "compiler_sources": compiler_rows,
            "producer_sources": producer_rows,
            "compiler_bundle_sha256": compiler_bundle,
            "producer_bundle_sha256": producer_bundle,
            "expected_producer_sha256": hb.sha256(self.producer_image),
            "runtime": {
                "source": "%s/%s" % (hb.NTASM_TREE_REL, self.runtime_source.name),
                "source_sha256": hb.digest_file(self.runtime_source),
                "image_sha256": hb.sha256(self.runtime_image),
            },
            "host": {
                "source": "%s/%s" % (hb.NTASM_TREE_REL, self.host_source.name),
                "source_sha256": hb.digest_file(self.host_source),
                "image_sha256": hb.sha256(self.host_image),
            },
        }
        data.update(overrides)
        self.write_manifest(data)
        return data

    def write_manifest(self, data):
        path = self.seed_dir / "manifest.json"
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path

    def cleanup(self):
        shutil.rmtree(self.root, ignore_errors=True)


# ---------------------------------------------------------------------------
# NVSRC001 protocol
# ---------------------------------------------------------------------------


class ProtocolTest(unittest.TestCase):
    """The packet layout is a golden byte string, not a re-computation."""

    GOLDEN = (
        "4e56535243303031"      # NVSRC001
        "0200000000000000"      # source_count = 2
        "0000000000000000"      # root_index = 0
        "0500000000000000"      # blob bytes = 5
        "0000000000000000"      # span 0: offset 0
        "0300000000000000"      # span 0: size 3
        "0300000000000000"      # span 1: offset 3
        "0200000000000000"      # span 1: size 2
        "4141414242"            # blob: AAA + BB
    )

    def test_packet_bytes_are_exact(self):
        packet = hb.pack_nvsrc001([("a.nova", b"AAA"), ("b.nova", b"BB")])
        self.assertEqual(packet.hex(), self.GOLDEN)

    def test_the_count_is_written(self):
        # magic [0:8], count [8:16], root_index [16:24], blob bytes [24:32].
        packet = hb.pack_nvsrc001([("a.nova", b"AAA"), ("b.nova", b"BB")])
        self.assertEqual(packet[8:16].hex(), "0200000000000000")

    def test_root_index_is_written(self):
        packet = hb.pack_nvsrc001([("a.nova", b"AAA"), ("b.nova", b"BB")], root_index=1)
        self.assertEqual(packet[16:24].hex(), "0100000000000000")

    def test_empty_list_is_refused(self):
        with self.assertRaises(hb.Refusal) as ctx:
            hb.pack_nvsrc001([])
        self.assertEqual(ctx.exception.cls, "source-count")

    def test_more_than_64_sources_is_refused(self):
        items = [("s%d.nova" % i, b"x") for i in range(65)]
        with self.assertRaises(hb.Refusal) as ctx:
            hb.pack_nvsrc001(items)
        self.assertEqual(ctx.exception.cls, "source-count")

    def test_blob_over_four_mib_is_refused(self):
        items = [("a.nova", b"x" * (hb.MAX_BLOB + 1))]
        with self.assertRaises(hb.Refusal) as ctx:
            hb.pack_nvsrc001(items)
        self.assertEqual(ctx.exception.cls, "source-blob-too-large")

    def test_empty_source_is_refused(self):
        with self.assertRaises(hb.Refusal) as ctx:
            hb.pack_nvsrc001([("a.nova", b"")])
        self.assertEqual(ctx.exception.cls, "source-empty")

    def test_root_index_out_of_range_is_refused(self):
        with self.assertRaises(hb.Refusal) as ctx:
            hb.pack_nvsrc001([("a.nova", b"x")], root_index=1)
        self.assertEqual(ctx.exception.cls, "source-root-index")


# ---------------------------------------------------------------------------
# manifest and pins
# ---------------------------------------------------------------------------


class ManifestTest(unittest.TestCase):
    def setUp(self):
        self.repo = FakeRepo()

    def tearDown(self):
        self.repo.cleanup()

    def test_missing_manifest_is_refused(self):
        with self.assertRaises(hb.Refusal) as ctx:
            hb.load_manifest(self.repo.root)
        self.assertEqual(ctx.exception.cls, "manifest-missing")

    def test_schema_must_match(self):
        self.repo.manifest(schema="SOMETHING_ELSE")
        with self.assertRaises(hb.Refusal) as ctx:
            hb.load_manifest(self.repo.root)
        self.assertEqual(ctx.exception.cls, "manifest-schema")

    def test_incomplete_manifest_is_refused(self):
        data = self.repo.manifest()
        del data["expected_producer_sha256"]
        self.repo.write_manifest(data)
        with self.assertRaises(hb.Refusal) as ctx:
            hb.load_manifest(self.repo.root)
        self.assertEqual(ctx.exception.cls, "manifest-incomplete")

    def test_bad_digest_is_refused(self):
        data = self.repo.manifest()
        data["expected_producer_sha256"] = "not-hex"
        self.repo.write_manifest(data)
        with self.assertRaises(hb.Refusal) as ctx:
            hb.load_manifest(self.repo.root)
        self.assertEqual(ctx.exception.cls, "manifest-bad-digest")

    def test_missing_source_file_is_refused(self):
        data = self.repo.manifest()
        (self.repo.nova / "c01.nova").unlink()
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        with self.assertRaises(hb.Refusal) as ctx:
            builder.validate()
        self.assertEqual(ctx.exception.cls, "source-missing")

    def test_modified_source_is_refused(self):
        data = self.repo.manifest()
        (self.repo.nova / "c01.nova").write_bytes(b"// changed\n")
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        with self.assertRaises(hb.Refusal) as ctx:
            builder.validate()
        self.assertEqual(ctx.exception.cls, "source-digest-mismatch")

    def test_wrong_source_count_is_refused(self):
        data = self.repo.manifest()
        data["producer_sources"] = data["producer_sources"][:-1]
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        with self.assertRaises(hb.Refusal) as ctx:
            builder.validate()
        self.assertEqual(ctx.exception.cls, "source-count-mismatch")

    def test_traversal_in_a_source_path_is_refused(self):
        data = self.repo.manifest()
        data["producer_sources"][1]["path"] = "../%s/p01.nova" % hb.NOVA_TREE_REL
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        with self.assertRaises(hb.Refusal) as ctx:
            builder.validate()
        self.assertIn(ctx.exception.cls, ("manifest-bad-path", "source-not-in-toolchain"))

    def test_the_seed_path_is_relative_to_the_manifest_directory(self):
        # nova_compiler.path is relative to bootstrap/nova-native/, NOT to the
        # repository root: "nova-compiler.EFI" names the seed next to the
        # manifest, not a file at the top of the tree.
        data = self.repo.manifest()
        self.assertEqual(data["nova_compiler"]["path"], "nova-compiler.EFI")
        builder = hb.HouseBuild(self.repo.root, 120)
        state = builder.validate()
        self.assertEqual(state["seed"]["path"],
                         (self.repo.seed_dir / "nova-compiler.EFI").resolve())

    def test_a_seed_symlink_outside_the_manifest_directory_is_refused(self):
        outside = self.repo.root / "outside.EFI"
        outside.write_bytes(fake_pe64())
        link = self.repo.seed_dir / "link.EFI"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError) as exc:
            self.skipTest("symlinks are unavailable here: %s" % exc)
        data = self.repo.manifest()
        data["nova_compiler"] = {"path": "link.EFI", "sha256": hb.digest_file(outside)}
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        with self.assertRaises(hb.Refusal) as ctx:
            builder.validate()
        self.assertEqual(ctx.exception.cls, "path-escape")

    def test_traversal_in_the_seed_path_is_refused(self):
        data = self.repo.manifest()
        data["nova_compiler"]["path"] = "../../%s/c01.nova" % hb.NOVA_TREE_REL
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        with self.assertRaises(hb.Refusal) as ctx:
            builder.validate()
        self.assertIn(ctx.exception.cls, ("manifest-bad-path", "path-escape"))

    def test_symlink_outside_the_tree_is_refused(self):
        outside = self.repo.root / "outside.nova"
        outside.write_bytes(b"// outside\n")
        link = self.repo.nova / "link.nova"
        try:
            os.symlink(outside, link)
        except (OSError, NotImplementedError) as exc:
            self.skipTest("symlinks are unavailable here: %s" % exc)
        data = self.repo.manifest()
        data["producer_sources"][1]["path"] = "%s/link.nova" % hb.NOVA_TREE_REL
        data["producer_sources"][1]["sha256"] = hb.digest_file(outside)
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        with self.assertRaises(hb.Refusal) as ctx:
            builder.validate()
        self.assertEqual(ctx.exception.cls, "path-escape")

    def test_c_quarantine_and_out_sources_are_refused(self):
        for bad in ("compiler/c/nova/frontend/nova.c", "out/whatever.nova",
                    "compiler/nova/thing.c", "compiler/nova/thing.asm"):
            data = self.repo.manifest()
            data["producer_sources"][1]["path"] = bad
            self.repo.write_manifest(data)
            builder = hb.HouseBuild(self.repo.root, 120)
            with self.assertRaises(hb.Refusal) as ctx:
                builder.validate()
            self.assertIn(ctx.exception.cls, (
                "source-not-in-tree", "source-not-in-toolchain", "source-not-nova",
                "manifest-bad-path"), bad)

    def test_a_nested_source_under_the_tree_is_admitted(self):
        # The tree of this repository is NESTED by responsibility: a house
        # source is a .nova file UNDER the tree, at any depth. The depth is
        # not what the contract pins: the manifest pins the list, its order
        # and the bytes.
        nested = "%s/nested/deeper/probe.nova" % hb.NOVA_TREE_REL
        target = self.repo.nova / "nested" / "deeper" / "probe.nova"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(b"// nested unit fixture\n")
        data = self.repo.manifest()
        data["producer_sources"][1] = {"path": nested,
                                       "sha256": hb.digest_file(target)}
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        try:
            builder.validate()
        except hb.Refusal as exc:
            # The source itself was admitted: the only refusal left is the
            # bundle digest, which pins the LIST and its order.
            self.assertNotIn(exc.cls, (
                "source-not-in-tree", "source-not-nova", "source-missing"))
            self.assertEqual(exc.cls, "bundle-mismatch")

    def test_a_source_outside_the_tree_is_refused(self):
        data = self.repo.manifest()
        data["producer_sources"][1]["path"] = "somewhere/else/p01.nova"
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        with self.assertRaises(hb.Refusal) as ctx:
            builder.validate()
        self.assertEqual(ctx.exception.cls, "source-not-in-tree")

    def test_bundle_digest_mismatch_is_refused(self):
        data = self.repo.manifest()
        data["producer_bundle_sha256"] = "0" * 64
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        with self.assertRaises(hb.Refusal) as ctx:
            builder.validate()
        self.assertEqual(ctx.exception.cls, "bundle-mismatch")

    def test_bundle_digest_pins_the_order(self):
        data = self.repo.manifest()
        data["producer_sources"][1], data["producer_sources"][2] = (
            data["producer_sources"][2], data["producer_sources"][1])
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        with self.assertRaises(hb.Refusal) as ctx:
            builder.validate()
        self.assertEqual(ctx.exception.cls, "bundle-mismatch")

    def test_a_selfhost_flag_authorizes_nothing(self):
        data = self.repo.manifest()
        data["selfhost"] = True
        data["producer_bundle_sha256"] = "1" * 64
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        with self.assertRaises(hb.Refusal) as ctx:
            builder.validate()
        self.assertEqual(ctx.exception.cls, "bundle-mismatch")

    def test_unknown_manifest_keys_are_ignored_but_reported(self):
        data = self.repo.manifest()
        data["selfhost"] = True
        data["bootstrap_history"] = {"note": "descriptive only"}
        self.repo.write_manifest(data)
        builder = hb.HouseBuild(self.repo.root, 120)
        state = builder.validate()
        self.assertEqual(state["ignored_manifest_keys"], ["selfhost"])


# ---------------------------------------------------------------------------
# the build, with a mocked transport
# ---------------------------------------------------------------------------


class BuildTest(unittest.TestCase):
    def setUp(self):
        self.repo = FakeRepo()
        self.repo.manifest()
        # The run directory lives inside the fake repository, so the test can
        # check that the build wrote NOTHING outside it.
        self.run_dir = self.repo.root / "out" / "ntasm-house" / "unit-run"
        self.run_dir.mkdir(parents=True)
        self.transport = FakeTransport(
            self.run_dir,
            produced={"runtime": self.repo.runtime_image, "host": self.repo.host_image},
            extracted={"producer": self.repo.producer_image},
        )

    def tearDown(self):
        self.repo.cleanup()
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def builder(self, transport=None):
        return hb.HouseBuild(self.repo.root, 120, transport=transport or self.transport,
                             run_dir=self.run_dir, lock=NoLock())

    def test_build_delivers_and_writes_build_json(self):
        code = self.builder().build()
        self.assertEqual(code, 0)
        record = json.loads((self.run_dir / "build.json").read_text(encoding="utf-8"))
        self.assertEqual(record["status"], "ok")
        self.assertEqual(record["output"]["sha256"], record["output"]["expected_sha256"])
        self.assertTrue(record["output"]["matches_expected"])
        self.assertEqual(record["bundles"]["producer"]["source_count"], hb.PRODUCER_SOURCE_COUNT)
        self.assertEqual(record["bundles"]["compiler"]["root_index"], 0)
        self.assertTrue((self.run_dir / "producer" / "extracted-OUTPUT.EFI").is_file())

    def test_the_transport_is_called_in_the_documented_order(self):
        self.builder().build()
        self.assertEqual(
            self.transport.commands,
            [("assemble", "runtime"), ("assemble", "host"), ("run", "producer")],
        )

    def test_build_does_not_claim_a_selfhost_run(self):
        self.builder().build()
        record = json.loads((self.run_dir / "build.json").read_text(encoding="utf-8"))
        self.assertNotIn("selfhost", record)
        self.assertEqual(record["schema"], "NTHOUSE_BUILD_V1")

    def test_build_writes_only_inside_its_run_dir(self):
        # Only the paths the build CREATED are judged, and they are judged by
        # real containment, not by a prefix: a sibling whose name starts like
        # the run dir is not inside it.
        out_root = self.repo.root / "out"
        before = {p for p in out_root.rglob("*")} if out_root.exists() else set()
        self.builder().build()
        after = {p for p in out_root.rglob("*")} if out_root.exists() else set()
        new = after - before
        self.assertTrue(new)
        for path in sorted(new):
            self.assertTrue(
                allowed_new_path(path, self.run_dir, out_root),
                "the build wrote outside its run dir: %s" % path,
            )

    def test_the_containment_check_refuses_a_sibling(self):
        # A prefix check would accept this one: the name starts like the run
        # dir. Containment must not.
        out_root = self.repo.root / "out"
        sibling = self.run_dir.with_name(self.run_dir.name + "-evil")
        sibling.mkdir(parents=True)
        stowaway = sibling / "stowaway.txt"
        stowaway.write_bytes(b"x")
        self.assertFalse(allowed_new_path(stowaway, self.run_dir, out_root))
        self.assertFalse(allowed_new_path(sibling, self.run_dir, out_root))
        inside = self.run_dir / "pack"
        inside.mkdir()
        self.assertTrue(allowed_new_path(inside, self.run_dir, out_root))

    def test_wrong_producer_digest_is_a_build_failure(self):
        transport = FakeTransport(
            self.run_dir,
            produced={"runtime": self.repo.runtime_image, "host": self.repo.host_image},
            extracted={"producer": fake_pe64(4096) + b"different"},
        )
        with self.assertRaises(hb.BuildFailure):
            self.builder(transport).build()
        self.assertFalse((self.run_dir / "build.json").exists())

    def test_a_non_pe64_output_is_a_build_failure(self):
        transport = FakeTransport(
            self.run_dir,
            produced={"runtime": self.repo.runtime_image, "host": self.repo.host_image},
            extracted={"producer": b"not a pe at all"},
        )
        with self.assertRaises(hb.BuildFailure):
            self.builder(transport).build()

    def test_a_transport_failure_is_a_build_failure(self):
        transport = FakeTransport(self.run_dir, fail_on=("runtime",))
        with self.assertRaises(hb.BuildFailure):
            self.builder(transport).build()

    def test_an_image_that_does_not_match_its_pin_is_refused(self):
        transport = FakeTransport(
            self.run_dir,
            produced={"runtime": fake_pe64(2048) + b"x", "host": self.repo.host_image},
            extracted={"producer": self.repo.producer_image},
        )
        with self.assertRaises(hb.Refusal) as ctx:
            self.builder(transport).build()
        self.assertEqual(ctx.exception.cls, "image-digest-mismatch")

    def test_a_source_that_moves_during_the_build_is_refused(self):
        def mutate():
            (self.repo.nova / "c01.nova").write_bytes(b"// moved\n")

        transport = FakeTransport(
            self.run_dir,
            produced={"runtime": self.repo.runtime_image, "host": self.repo.host_image},
            extracted={"producer": self.repo.producer_image},
            mutate=mutate,
        )
        with self.assertRaises(hb.Refusal) as ctx:
            self.builder(transport).build()
        self.assertEqual(ctx.exception.cls, "source-changed-during-build")

    def test_a_seed_that_moves_during_the_build_is_refused(self):
        def mutate():
            self.repo.seed.write_bytes(fake_pe64(1024) + b"moved")

        transport = FakeTransport(
            self.run_dir,
            produced={"runtime": self.repo.runtime_image, "host": self.repo.host_image},
            extracted={"producer": self.repo.producer_image},
            mutate=mutate,
        )
        with self.assertRaises(hb.Refusal) as ctx:
            self.builder(transport).build()
        self.assertEqual(ctx.exception.cls, "seed-changed-during-build")

    def test_run_directories_are_fresh(self):
        first = hb.new_run_dir(self.repo.root)
        second = hb.new_run_dir(self.repo.root)
        self.assertNotEqual(first, second)
        self.assertTrue(first.is_dir())
        self.assertTrue(second.is_dir())


# ---------------------------------------------------------------------------
# selfhost, with a mocked transport
# ---------------------------------------------------------------------------


class SelfhostTest(unittest.TestCase):
    def setUp(self):
        self.repo = FakeRepo()
        self.repo.manifest()
        self.run_dir = Path(tempfile.mkdtemp(prefix="nthouse-self-"))
        self.n1 = fake_pe64(4096)
        self.n2 = fake_pe64(4096)

    def tearDown(self):
        self.repo.cleanup()
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def builder(self, transport):
        return hb.HouseBuild(self.repo.root, 120, transport=transport, run_dir=self.run_dir, lock=NoLock())

    def test_two_identical_generations_are_a_fixed_point(self):
        transport = FakeTransport(
            self.run_dir,
            produced={"runtime": self.repo.runtime_image, "host": self.repo.host_image},
            extracted={"selfhost-n1": self.n1, "selfhost-n2": self.n2},
        )
        code = self.builder(transport).selfhost()
        self.assertEqual(code, 0)
        record = json.loads((self.run_dir / "selfhost.json").read_text(encoding="utf-8"))
        self.assertEqual(record["status"], "ok")
        self.assertTrue(record["output"]["identical"])

    def test_different_generations_are_refused(self):
        transport = FakeTransport(
            self.run_dir,
            produced={"runtime": self.repo.runtime_image, "host": self.repo.host_image},
            extracted={"selfhost-n1": self.n1, "selfhost-n2": self.n2 + b"x"},
        )
        with self.assertRaises(hb.BuildFailure):
            self.builder(transport).selfhost()
        self.assertFalse((self.run_dir / "selfhost.json").exists())

    def test_each_step_runs_in_its_own_directory(self):
        transport = FakeTransport(
            self.run_dir,
            produced={"runtime": self.repo.runtime_image, "host": self.repo.host_image},
            extracted={"selfhost-n1": self.n1, "selfhost-n2": self.n2},
        )
        self.builder(transport).selfhost()
        self.assertEqual(
            transport.commands,
            [("assemble", "runtime"), ("assemble", "host"),
             ("run", "selfhost-n1"), ("run", "selfhost-n2")],
        )
        self.assertTrue((self.run_dir / "selfhost-n1" / "extracted-OUTPUT.EFI").is_file())
        self.assertTrue((self.run_dir / "selfhost-n2" / "extracted-OUTPUT.EFI").is_file())
        self.assertTrue((self.run_dir / "pack" / "n1" / "NOVA.IN").is_file())
        self.assertTrue((self.run_dir / "pack" / "n2" / "NOVA.IN").is_file())
        self.assertEqual(
            (self.run_dir / "pack" / "n1" / "NOVA.IN").read_bytes(),
            (self.run_dir / "pack" / "n2" / "NOVA.IN").read_bytes())

    def test_selfhost_does_not_call_the_c_loader(self):
        transport = FakeTransport(
            self.run_dir,
            produced={"runtime": self.repo.runtime_image, "host": self.repo.host_image},
            extracted={"selfhost-n1": self.n1, "selfhost-n2": self.n2},
        )
        self.builder(transport).selfhost()
        for command in transport.commands:
            self.assertNotIn("native_pe_run", " ".join(str(part) for part in command))


# ---------------------------------------------------------------------------
# the check command
# ---------------------------------------------------------------------------


class CheckTest(unittest.TestCase):
    def setUp(self):
        self.repo = FakeRepo()

    def tearDown(self):
        self.repo.cleanup()

    def test_a_flat_nova_source_is_allowed(self):
        allowed, cls, _ = hb.classify_source(self.repo.root, str(self.repo.nova / "c01.nova"))
        self.assertTrue(allowed)
        self.assertEqual(cls, "allowed")

    def test_c_h_asm_quarantine_and_out_are_refused(self):
        cases = {
            "compiler/c/nova/frontend/nova.c": "quarantine-source",
            "compiler/nova/thing.h": "c-source",
            "compiler/nova/thing.asm": "assembly-input",
            "compiler/nova/thing.nasm": "assembly-input",
            "legacy/nasm/x.asm": "quarantine-source",
            "out/ntasm-house/thing.nova": "out-artifact",
            "compiler/runtime/runtime-v2-s0.ntasm": "outside-nova-tree",
        }
        for path, expected in cases.items():
            allowed, cls, _ = hb.classify_source(self.repo.root, str(self.repo.root / path))
            self.assertFalse(allowed, path)
            self.assertEqual(cls, expected, path)


# ---------------------------------------------------------------------------
# the transport call surface
# ---------------------------------------------------------------------------


class FakeProc:
    def __init__(self, returncode, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class TransportCallTest(unittest.TestCase):
    """The argv of the transport is a CONTRACT. It is pinned here, not described."""

    def _transport(self, runner):
        return hb.Transport(Path("nova_native_transport.py"), Path("/repo"), Path("/work"),
                            120, runner=runner)

    def test_the_argv_is_exactly_the_documented_one(self):
        seen = {}

        def runner(argv, timeout):
            seen["argv"] = argv
            return FakeProc(0)

        transport = self._transport(runner)
        transport._call("producer", ["run", "/h", "/r", "/c",
                                     "--payload", "NOVA.IN=/p",
                                     "--extract-file", "OUTPUT.EFI"])
        argv = seen["argv"]
        self.assertEqual(argv[0], sys.executable)
        self.assertEqual(argv[1:], [
            "nova_native_transport.py", "--repo", str(Path("/repo")),
            "--work-root", str(Path("/work")),
            "--name", "producer", "--timeout", "120",
            "run", "/h", "/r", "/c",
            "--payload", "NOVA.IN=/p", "--extract-file", "OUTPUT.EFI",
        ])

    def test_a_transport_refusal_stays_a_refusal(self):
        def runner(argv, timeout):
            return FakeProc(2, stderr=b"NOVA_TRANSPORT_REFUSED missing firmware")

        with self.assertRaises(hb.Refusal) as ctx:
            self._transport(runner)._call("runtime", ["assemble", "x.ntasm"])
        self.assertEqual(ctx.exception.cls, "transport-refused")

    def test_a_transport_failure_is_a_build_failure(self):
        def runner(argv, timeout):
            return FakeProc(1, stderr=b"NOVA_TRANSPORT_FAILED boot failed")

        with self.assertRaises(hb.BuildFailure):
            self._transport(runner)._call("runtime", ["assemble", "x.ntasm"])


# ---------------------------------------------------------------------------
# the process group: Popen and os.killpg are entirely MOCKED
# ---------------------------------------------------------------------------


class FakePopen:
    """A MOCK of subprocess.Popen. No process is ever created by a test."""

    def __init__(self, pid=424242, communicate=None, returncode=0):
        self.pid = pid
        self.returncode = returncode
        self._communicate = communicate
        self.communicated = []
        self.waited = []

    def communicate(self, timeout=None):
        self.communicated.append(timeout)
        if self._communicate is None:
            return b"", b""
        result = self._communicate(self, timeout)
        if isinstance(result, BaseException):
            raise result
        return result

    def wait(self, timeout=None):
        self.waited.append(timeout)
        return self.returncode


class ProcessGroupTest(unittest.TestCase):
    """The group cleanup, with Popen and os.killpg replaced by recorders.

    No real process is started and NO REAL SIGNAL IS EVER SENT: os.killpg is
    patched for the whole call, so a fake pid can never reach the kernel.
    """

    ARGV = ["python3", "nova_native_transport.py", "--name", "producer"]

    def _transport(self, grace=0.01):
        return hb.Transport(Path("nova_native_transport.py"), Path("/repo"), Path("/work"),
                            120, grace=grace)

    @staticmethod
    def _signals(killpg):
        """(pgid, signal) pairs, in order. The probe (signal 0) is one of them."""
        return [(call.args[0], call.args[1]) for call in killpg.call_args_list]

    @staticmethod
    def _count(signals, sig):
        return len([pair for pair in signals if pair[1] == sig])

    def _assert_one_round_of_signals(self, signals, pgid):
        """One SIGTERM, one SIGKILL, and never another pgid."""
        self.assertEqual(self._count(signals, signal.SIGTERM), 1)
        self.assertEqual(self._count(signals, signal.SIGKILL), 1)
        for signalled_pgid, _sig in signals:
            self.assertEqual(signalled_pgid, pgid)

    def test_a_successful_run_signals_nothing(self):
        popen = FakePopen(communicate=lambda proc, timeout: (b"out", b"err"))
        with mock.patch.object(hb.subprocess, "Popen", return_value=popen) as popen_mock, \
                mock.patch.object(hb.os, "killpg") as killpg:
            result = self._transport()._default_runner(list(self.ARGV), 30)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"out")
        self.assertEqual(result.stderr, b"err")
        killpg.assert_not_called()
        self.assertEqual(popen.waited, [])
        kwargs = popen_mock.call_args.kwargs
        self.assertFalse(kwargs["shell"])
        self.assertTrue(kwargs["start_new_session"])

    def test_a_normal_return_with_a_failure_still_takes_the_group_down(self):
        # The transport left on its own with an error and its QEMU is still
        # running: communicate() returned NORMALLY, so nothing would clean
        # the group up unless that path cleans it too. The failure itself is
        # NOT swallowed: the return code travels back untouched.
        popen = FakePopen(communicate=lambda proc, timeout: (b"partial", b"boom"), returncode=1)
        with mock.patch.object(hb.subprocess, "Popen", return_value=popen), \
                mock.patch.object(hb.os, "killpg") as killpg:
            result = self._transport()._default_runner(list(self.ARGV), 30)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, b"partial")
        self.assertEqual(result.stderr, b"boom")
        self._assert_one_round_of_signals(self._signals(killpg), popen.pid)

    def test_a_normal_return_without_a_code_still_takes_the_group_down(self):
        popen = FakePopen(communicate=lambda proc, timeout: (b"", b""), returncode=None)
        with mock.patch.object(hb.subprocess, "Popen", return_value=popen), \
                mock.patch.object(hb.os, "killpg") as killpg:
            result = self._transport()._default_runner(list(self.ARGV), 30)
        self.assertIsNone(result.returncode)
        self._assert_one_round_of_signals(self._signals(killpg), popen.pid)

    def test_a_normal_return_with_a_failure_is_not_a_success(self):
        # The group is cleaned up AND the failure is reported: a clean-up is
        # not a way to turn a failed transport into a green build.
        popen = FakePopen(communicate=lambda proc, timeout: (b"", b"boom"), returncode=1)
        transport = self._transport()
        with mock.patch.object(hb.subprocess, "Popen", return_value=popen), \
                mock.patch.object(hb.os, "killpg"):
            with self.assertRaises(hb.BuildFailure):
                transport._call("producer", ["run"])

    def test_a_timeout_takes_the_whole_group_down(self):
        def communicate(proc, timeout):
            raise hb.subprocess.TimeoutExpired(self.ARGV, timeout)

        popen = FakePopen(communicate=communicate)
        with mock.patch.object(hb.subprocess, "Popen", return_value=popen), \
                mock.patch.object(hb.os, "killpg") as killpg:
            with self.assertRaises(hb.subprocess.TimeoutExpired):
                self._transport()._default_runner(list(self.ARGV), 30)
        self._assert_one_round_of_signals(self._signals(killpg), popen.pid)
        self.assertTrue(popen.waited)

    def test_an_interruption_takes_the_whole_group_down(self):
        def communicate(proc, timeout):
            raise KeyboardInterrupt()

        popen = FakePopen(communicate=communicate)
        with mock.patch.object(hb.subprocess, "Popen", return_value=popen), \
                mock.patch.object(hb.os, "killpg") as killpg:
            with self.assertRaises(KeyboardInterrupt):
                self._transport()._default_runner(list(self.ARGV), 30)
        self._assert_one_round_of_signals(self._signals(killpg), popen.pid)
        self.assertTrue(popen.waited)

    def test_a_sigterm_during_the_run_cleans_the_group_up(self):
        def communicate(proc, timeout):
            raise hb.BuildTerminated("the builder received signal 15")

        popen = FakePopen(communicate=communicate)
        with mock.patch.object(hb.subprocess, "Popen", return_value=popen), \
                mock.patch.object(hb.os, "killpg") as killpg:
            with self.assertRaises(hb.BuildTerminated):
                self._transport()._default_runner(list(self.ARGV), 30)
        self._assert_one_round_of_signals(self._signals(killpg), popen.pid)
        self.assertTrue(popen.waited)

    def test_a_leader_that_already_exited_still_takes_the_group_down(self):
        # The transport died but its QEMU kept the pipes open: communicate()
        # times out although the leader is already gone. The group must still
        # be taken down and the leader reaped.
        def communicate(proc, timeout):
            raise hb.subprocess.TimeoutExpired(self.ARGV, timeout)

        popen = FakePopen(pid=987654, communicate=communicate, returncode=1)
        with mock.patch.object(hb.subprocess, "Popen", return_value=popen), \
                mock.patch.object(hb.os, "killpg") as killpg:
            with self.assertRaises(hb.subprocess.TimeoutExpired):
                self._transport()._default_runner(list(self.ARGV), 30)
        signals = self._signals(killpg)
        self.assertIn((987654, signal.SIGTERM), signals)
        self.assertIn((987654, signal.SIGKILL), signals)
        for pgid, _sig in signals:
            self.assertEqual(pgid, 987654)
        self.assertTrue(popen.waited)

    def test_no_foreign_pid_is_ever_signalled(self):
        def communicate(proc, timeout):
            raise hb.subprocess.TimeoutExpired(self.ARGV, timeout)

        popen = FakePopen(pid=555, communicate=communicate)
        with mock.patch.object(hb.subprocess, "Popen", return_value=popen), \
                mock.patch.object(hb.os, "killpg") as killpg:
            with self.assertRaises(hb.subprocess.TimeoutExpired):
                self._transport()._default_runner(list(self.ARGV), 30)
        for pgid, _sig in self._signals(killpg):
            self.assertEqual(pgid, popen.pid)

    def test_an_empty_group_is_not_signalled_at_all(self):
        # The group has no member left: the probe says so and NOTHING is
        # sent, so a stale id can never be hit.
        popen = FakePopen(communicate=lambda proc, timeout: (b"", b"boom"), returncode=1)
        with mock.patch.object(hb.subprocess, "Popen", return_value=popen), \
                mock.patch.object(hb.os, "killpg") as killpg:
            killpg.side_effect = ProcessLookupError("no such process group")
            self._transport()._default_runner(list(self.ARGV), 30)
        signals = self._signals(killpg)
        self.assertEqual(self._count(signals, signal.SIGTERM), 0)
        self.assertEqual(self._count(signals, signal.SIGKILL), 0)

    def test_a_runner_without_a_returncode_is_not_a_success(self):
        class NoReturncode:
            stdout = b"partial output"
            stderr = b""

        transport = self._transport()
        transport.runner = lambda argv, timeout: NoReturncode()
        with self.assertRaises(hb.BuildFailure) as ctx:
            transport._call("producer", ["run"])
        self.assertIn("returncode", str(ctx.exception))

    def test_a_runner_returning_none_is_not_a_success(self):
        class NoneReturncode:
            returncode = None
            stdout = b""
            stderr = b""

        transport = self._transport()
        transport.runner = lambda argv, timeout: NoneReturncode()
        with self.assertRaises(hb.BuildFailure):
            transport._call("producer", ["run"])

    def test_sigterm_becomes_an_exception_and_not_a_silent_death(self):
        previous = signal.getsignal(signal.SIGTERM)
        try:
            hb._install_signal_handlers()
            handler = signal.getsignal(signal.SIGTERM)
            self.assertTrue(callable(handler))
            with self.assertRaises(hb.BuildTerminated):
                handler(signal.SIGTERM, None)
        finally:
            signal.signal(signal.SIGTERM, previous)

    def test_the_termination_is_not_an_ordinary_exception(self):
        # It must not be swallowed by an `except Exception` on the way out.
        self.assertTrue(issubclass(hb.BuildTerminated, BaseException))
        self.assertFalse(issubclass(hb.BuildTerminated, Exception))


# ---------------------------------------------------------------------------
# the CLI surface
# ---------------------------------------------------------------------------


class CliTest(unittest.TestCase):
    def test_build_is_the_default_command(self):
        self.assertEqual(hb.normalize_argv([]), [])
        self.assertEqual(hb.normalize_argv(["--repo", "/x"]), ["--repo", "/x"])
        self.assertEqual(hb.normalize_argv(["--repo", "/x", "build"]), ["--repo", "/x", "build"])
        self.assertEqual(hb.normalize_argv(["some.nova"]), ["build", "some.nova"])
        self.assertEqual(hb.normalize_argv(["check", "a.nova"]), ["check", "a.nova"])

    def test_policy_runs_without_a_manifest(self):
        repo = Path(tempfile.mkdtemp(prefix="nthouse-policy-"))
        try:
            self.assertEqual(hb.cmd_policy(repo), 0)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_pins_without_a_manifest_is_a_refusal(self):
        repo = Path(tempfile.mkdtemp(prefix="nthouse-pins-"))
        try:
            self.assertEqual(hb.cmd_pins(repo), hb.EXIT_REFUSED)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_the_timeout_bounds_are_refused(self):
        repo = Path(tempfile.mkdtemp(prefix="nthouse-timeout-"))
        try:
            self.assertEqual(hb.main(["--repo", str(repo), "--timeout", "5", "policy"]), hb.EXIT_REFUSED)
            self.assertEqual(hb.main(["--repo", str(repo), "--timeout", "9", "policy"]), hb.EXIT_REFUSED)
            self.assertEqual(hb.main(["--repo", str(repo), "--timeout", "10801", "policy"]), hb.EXIT_REFUSED)
            self.assertEqual(hb.main(["--repo", str(repo), "--timeout", "10", "policy"]), 0)
            self.assertEqual(hb.main(["--repo", str(repo), "--timeout", "10800", "policy"]), 0)
        finally:
            shutil.rmtree(repo, ignore_errors=True)

    def test_the_default_timeout_is_the_bounded_full_build_budget(self):
        self.assertEqual(hb.TIMEOUT_MIN, 10)
        self.assertEqual(hb.TIMEOUT_MAX, 10800)
        self.assertEqual(hb.TIMEOUT_DEFAULT, 10800)


if __name__ == "__main__":
    unittest.main()
