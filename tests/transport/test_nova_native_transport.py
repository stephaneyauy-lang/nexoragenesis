"""Pure checks for the A8 transport.

The 54 serial-text cases of the transport prototype are here, adapted to the
new import and keeping their assertions: the functions they exercise now LIVE
in nova_native_transport, which is autonomous and reads no prototype at run
time.

The cases added below cover the new layer: the autonomy of the script, the
extraction path and names, the timeout and RAM bounds, the foreign QEMU check
and the fail-closed decisions.

The HMP liveness cases mock the QEMU process and the monitor: a scripted
socket, a driven clock and a fake process. No QEMU is started, no real
monitor is contacted and no test ever waits. Their evidence directories are
left in the system temporary directory on purpose: a removal can fail on
Windows, and a cleanup failure must never be read as a test failure.

No QEMU is launched, no firmware is read and no subprocess is started here.
"""
import argparse
import contextlib
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "validation"))

import nova_native_transport as nt
import a8_run_evidence as ev
from nova_native_transport import (exclusive_failure, firmware_return, nova_runtime_failure,
                                   native_driver_failure, driver_output_matches,
                                   root_inventory_names)

MARKER = "NG_NV2_NATIVE_TEST_OK"

# The archived A8 evidence, read only. The tests that need it are skipped
# when it is not on this machine.
ARCHIVE_ROOT = Path(os.environ.get(
    "A8_ARCHIVE_ROOT", "C:/NexoraGenesis/out/a8-selfhost-20261015"))
TRIAL05_PRODUCER = ARCHIVE_ROOT / (
    "house-stage-20261021-01/out/ntasm-house/20261021T170311Z-82584f32/producer")
TRIAL03_PRODUCER = ARCHIVE_ROOT / (
    "house-stage-20261021-01/out/ntasm-house/20261021T143738Z-1c413f15/producer")


def start(boot="Boot0001", name="UEFI Non-Block Boot Device"):
    return 'BdsDxe: starting ' + boot + ' "' + name + '" from fixture\r\n'


def returned(boot="Boot0001", name="UEFI Non-Block Boot Device"):
    return 'BdsDxe: failed to start ' + boot + ' "' + name + '" from fixture: Aborted\r\n'


class FirmwareReturnTests(unittest.TestCase):
    def evidence(self, before, after):
        serial = before + MARKER + "\r\n" + after
        return firmware_return(serial, len(before) + len(MARKER))

    def test_non_block_device_return_is_accepted(self):
        self.assertEqual(self.evidence(start(), returned()), returned().rstrip("\r\n"))

    def test_different_valid_name_and_boot_are_accepted(self):
        self.assertEqual(self.evidence(start("Boot00AF", "Nouveau volume"),
                                      returned("Boot00AF", "Nouveau volume")),
                         returned("Boot00AF", "Nouveau volume").rstrip("\r\n"))

    def test_matching_boot_with_wrong_name_is_rejected(self):
        self.assertIsNone(self.evidence(start(), returned(name="UEFI Misc Device")))

    def test_matching_name_with_wrong_boot_is_rejected(self):
        self.assertIsNone(self.evidence(start(), returned(boot="Boot0002")))

    def test_return_before_marker_is_rejected(self):
        self.assertIsNone(self.evidence(start() + returned(), ""))

    def test_fresh_return_after_an_old_return_is_accepted(self):
        self.assertTrue(self.evidence(start() + returned(), returned()))

    def test_latest_started_image_is_the_one_that_must_return(self):
        before = start() + start("Boot0002", "Other")
        self.assertIsNone(self.evidence(before, returned()))
        self.assertTrue(self.evidence(before, returned("Boot0002", "Other")))

    def test_start_after_marker_does_not_count(self):
        self.assertIsNone(self.evidence("", start() + returned()))

    def test_uiapp_after_marker_preserves_existing_protocol(self):
        uiapp = 'BdsDxe: loading Boot0000 "UiApp" from fixture\r\n'
        self.assertEqual(self.evidence(start(), uiapp), uiapp.rstrip("\r\n"))

    def test_uiapp_before_marker_cannot_prove_a_return(self):
        uiapp = 'BdsDxe: loading Boot0000 "UiApp" from fixture\r\n'
        self.assertIsNone(self.evidence(uiapp + start(), ""))

    def test_no_started_image_cannot_be_proved_by_uiapp_alone(self):
        self.assertIsNone(self.evidence("", 'BdsDxe: loading Boot0000 "UiApp"\r\n'))

    def test_invalid_marker_bounds_are_rejected(self):
        self.assertIsNone(firmware_return(start() + returned(), 0))
        self.assertIsNone(firmware_return(start() + returned(), 999999))


def bad_report(status=2, assertion=45, error=8):
    return "NG_NV2_NATIVE_BAD\r\n" + "".join(
        format(x, "016x") + "\r\n" for x in (status, assertion, error))


class ExclusiveFailureTests(unittest.TestCase):
    def test_status2_assertion45_error8_are_required(self):
        result = exclusive_failure(start() + bad_report() + returned())
        self.assertEqual(result["host_status"], 2)
        self.assertEqual(result["failed_assertion"], 45)
        self.assertEqual(result["context_error"], 8)
        self.assertTrue(result["context_error_captured_before_cleanup"])

    def test_bad55_is_not_the_exclusive_create_control(self):
        self.assertIsNone(exclusive_failure(
            start() + bad_report(assertion=55) + returned()))

    def test_wrong_status_with_bad45_is_rejected(self):
        self.assertIsNone(exclusive_failure(
            start() + bad_report(status=3) + returned()))

    def test_historical_bad45_zero_did_not_capture_context_error(self):
        self.assertIsNone(exclusive_failure(
            start() + bad_report(error=0) + returned()))

    def test_wrong_runtime_error_with_bad45_is_rejected(self):
        self.assertIsNone(exclusive_failure(
            start() + bad_report(error=7) + returned()))

    def test_bare_bad_marker_is_insufficient(self):
        self.assertIsNone(exclusive_failure(
            start() + "NG_NV2_NATIVE_BAD\r\n" + returned()))

    def test_old_marker_before_current_image_start_is_rejected(self):
        self.assertIsNone(exclusive_failure(
            bad_report() + start() + returned()))

    def test_old_return_before_report_is_rejected(self):
        self.assertIsNone(exclusive_failure(
            start() + returned() + bad_report()))

    def test_old_report_cannot_supply_values_for_fresh_marker(self):
        old_values = "".join(format(x, "016x") + "\r\n" for x in (2, 45, 8))
        self.assertIsNone(exclusive_failure(
            start() + old_values + "NG_NV2_NATIVE_BAD\r\n" + returned()))

    def test_two_markers_from_old_and_new_attempts_are_rejected(self):
        old = start() + bad_report() + returned()
        fresh = start("Boot0002", "New") + bad_report() + returned("Boot0002", "New")
        self.assertIsNone(exclusive_failure(old + fresh))

    def test_bad45_with_return_of_different_image_is_rejected(self):
        self.assertIsNone(exclusive_failure(
            start() + bad_report() + returned(name="Other")))

    def test_uiapp_return_is_allowed_for_the_precise_report(self):
        result = exclusive_failure(start() + bad_report() +
                                   'BdsDxe: loading Boot0000 "UiApp"\r\n')
        self.assertIsNotNone(result)


class NovaRuntimeFailureTests(unittest.TestCase):
    def test_readonly_requires_status3_return0_error9(self):
        report = nova_runtime_failure(
            start() + bad_report(3, 0, 9) + returned(), 9)
        self.assertEqual(report["host_status"], 3)
        self.assertEqual(report["returned_value"], 0)
        self.assertEqual(report["context_error"], 9)

    def test_stale_handle_requires_error7(self):
        report = nova_runtime_failure(
            start() + bad_report(3, 0, 7) + returned(), 7)
        self.assertEqual(report["context_error"], 7)

    def test_selftest_status_cannot_replace_nova_status(self):
        self.assertIsNone(nova_runtime_failure(
            start() + bad_report(2, 0, 9) + returned(), 9))

    def test_nonzero_return_cannot_replace_propagated_runtime_error(self):
        self.assertIsNone(nova_runtime_failure(
            start() + bad_report(3, 99, 9) + returned(), 9))

    def test_different_runtime_error_is_rejected(self):
        self.assertIsNone(nova_runtime_failure(
            start() + bad_report(3, 0, 9) + returned(), 7))

    def test_duplicate_historical_marker_is_rejected(self):
        trace = start() + bad_report(3, 0, 9) + returned()
        self.assertIsNone(nova_runtime_failure(trace + trace, 9))

    def test_marker_before_image_start_is_rejected(self):
        self.assertIsNone(nova_runtime_failure(
            bad_report(3, 0, 9) + start() + returned(), 9))

    def test_unplanned_runtime_error_is_rejected(self):
        self.assertIsNone(nova_runtime_failure(
            start() + bad_report(3, 0, 8) + returned(), 8))

    def test_no_firmware_return_is_rejected(self):
        self.assertIsNone(nova_runtime_failure(
            start() + bad_report(3, 0, 9), 9))


def driver_notice(code):
    return "NG_NOVA_NATIVE_DRIVER_REFUSED\r\n" + str(code) + "\r\n"


class NativeDriverRefusalTests(unittest.TestCase):
    def test_all_four_normal_codes_are_exact(self):
        for code in (970, 803, 1101, 1103):
            with self.subTest(code=code):
                trace = start() + driver_notice(code) + bad_report(3, code, 0) + returned()
                report = native_driver_failure(trace, code)
                self.assertEqual(report["returned_value"], code)
                self.assertEqual(report["context_error"], 0)
                self.assertEqual(report["driver_diagnostic_code"], code)

    def test_driver_io_is_return0_error8(self):
        report = native_driver_failure(start() + bad_report(3, 0, 8) + returned(),
                                       expected_io=True)
        self.assertEqual(report["returned_value"], 0)
        self.assertEqual(report["context_error"], 8)

    def test_other_normal_code_cannot_replace_the_expected_one(self):
        self.assertIsNone(native_driver_failure(
            start() + driver_notice(803) + bad_report(3, 970, 0) + returned(), 970))

    def test_normal_refusal_does_not_hide_runtime_error(self):
        self.assertIsNone(native_driver_failure(
            start() + driver_notice(970) + bad_report(3, 970, 8) + returned(), 970))

    def test_normal_refusal_requires_host_status3(self):
        self.assertIsNone(native_driver_failure(
            start() + driver_notice(970) + bad_report(2, 970, 0) + returned(), 970))

    def test_normal_refusal_requires_own_driver_notice(self):
        self.assertIsNone(native_driver_failure(
            start() + bad_report(3, 970, 0) + returned(), 970))

    def test_notice_code_must_match_host_value(self):
        self.assertIsNone(native_driver_failure(
            start() + driver_notice(803) + bad_report(3, 970, 0) + returned(), 970))

    def test_notice_before_current_start_is_stale(self):
        self.assertIsNone(native_driver_failure(
            driver_notice(970) + start() + bad_report(3, 970, 0) + returned(), 970))

    def test_duplicate_old_marker_is_rejected(self):
        trace = start() + driver_notice(970) + bad_report(3, 970, 0) + returned()
        self.assertIsNone(native_driver_failure(trace + trace, 970))

    def test_return_before_current_bad_is_stale(self):
        self.assertIsNone(native_driver_failure(
            start() + returned() + driver_notice(970) + bad_report(3, 970, 0), 970))

    def test_io_does_not_accept_readonly_error(self):
        self.assertIsNone(native_driver_failure(
            start() + bad_report(3, 0, 9) + returned(), expected_io=True))

    def test_io_does_not_accept_a_normal_driver_code(self):
        self.assertIsNone(native_driver_failure(
            start() + bad_report(3, 1101, 8) + returned(), expected_io=True))

    def test_io_does_not_accept_selftest_status(self):
        self.assertIsNone(native_driver_failure(
            start() + bad_report(2, 0, 8) + returned(), expected_io=True))

    def test_io_does_not_hide_a_prior_normal_refusal(self):
        self.assertIsNone(native_driver_failure(
            start() + driver_notice(970) + bad_report(3, 0, 8) + returned(),
            expected_io=True))

    def test_unknown_or_absent_expectation_is_rejected(self):
        trace = start() + driver_notice(812) + bad_report(3, 812, 0) + returned()
        self.assertIsNone(native_driver_failure(trace, 812))
        self.assertIsNone(native_driver_failure(trace))

    def test_io_and_normal_expectations_cannot_be_mixed(self):
        self.assertIsNone(native_driver_failure(
            start() + bad_report(3, 0, 8) + returned(), 970, expected_io=True))

    def test_duplicate_driver_notice_is_rejected(self):
        self.assertIsNone(native_driver_failure(
            start() + driver_notice(970) + driver_notice(970) +
            bad_report(3, 970, 0) + returned(), 970))


class DriverOutputContractTests(unittest.TestCase):
    def test_bare_root_inventory_accepts_long_names_and_aliases(self):
        names = root_inventory_names("::/EFI/\n::/INPUT.NOVA\n::/NVRUNTIME.EFI\nOUTPUT~1.EFI\n")
        self.assertEqual(names, {"EFI", "INPUT.NOVA", "NVRUNTIME.EFI", "OUTPUT~1.EFI"})

    def test_unrecognized_inventory_is_not_proven_absence(self):
        for text in ('Volume label is TEST\n', '::/EFI/BOOT/\n'):
            with self.subTest(text=text):
                with self.assertRaises(RuntimeError):
                    root_inventory_names(text)

    def test_absent_output_must_remain_absent(self):
        self.assertTrue(driver_output_matches(None, None))
        self.assertFalse(driver_output_matches(None, b""))
        self.assertFalse(driver_output_matches(None, b"PE"))

    def test_existing_output_must_be_preserved_exactly(self):
        self.assertTrue(driver_output_matches(b"UNCHANGED", b"UNCHANGED"))
        self.assertFalse(driver_output_matches(b"UNCHANGED", b"CHANGED"))
        self.assertFalse(driver_output_matches(b"UNCHANGED", None))
        self.assertTrue(driver_output_matches(b"", b""))
        self.assertFalse(driver_output_matches(b"", None))


class AutonomyTests(unittest.TestCase):
    """The script must stand on its own: no prototype is read at run time."""

    def test_the_transport_works_with_a_repository_without_any_prototype(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = nt.resolve_repo(tmp)
            self.assertEqual(repo, Path(tmp).resolve())
            self.assertFalse((repo / "runtime-native").exists())
            self.assertEqual(nt.resolve_work_root(repo, None),
                             (repo / "out").resolve())
            self.assertEqual(nt.resolve_work_root(repo, "out/run"),
                             (repo / "out" / "run").resolve())
            with self.assertRaises(nt.Refusal):
                nt.resolve_work_root(repo, "elsewhere")

    def test_every_function_the_run_needs_lives_in_this_module(self):
        for name in ("firmware_return", "failure_report", "exclusive_failure",
                     "nova_runtime_failure", "native_driver_failure",
                     "root_inventory_names", "driver_output_matches", "digest",
                     "run", "mcopy", "create_esp", "hmp_quit", "boot", "pe_check"):
            with self.subTest(name=name):
                self.assertTrue(callable(getattr(nt, name)))

    def test_the_transport_loads_no_prototype(self):
        source = Path(nt.__file__).read_text()
        for forbidden in ("importlib", "spec_from_file_location", "load_transport",
                          "transport_candidates", "runtime-native", "run_native"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, source)

    def test_the_transport_offers_no_prototype_option(self):
        parser = nt.build_parser()
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                parser.parse_args(["--transport", "anywhere.py", "--name", "n",
                                   "assemble", "source.ntasm"])

    def test_the_pins_are_the_contract_pins(self):
        self.assertEqual(nt.PINS, {
            "compiler-host.NTASM1.EFI":
                "82826f458aff21d4f5167b296b56813899ea422caedb9d8fda2d8120a9b4882d",
            "compiler-core.NTASM1.EFI":
                "a02425be642b839586593b6b5468bc13f4f85d29a503987aa972e4750d1d428f"})
        self.assertEqual(nt.DRIVER_REFUSAL_CODES, (970, 803, 1101, 1103))


class S0ProducerDependencyTests(unittest.TestCase):
    """The pinned S0 producers, against the reorganized repository.

    The house build keeps them under bootstrap/; the reorganization archived
    that directory under legacy/. The transport must find them where the
    repository publishes them, and must refuse - never skip - when they are
    absent.
    """

    REPO = Path(nt.__file__).resolve().parents[1]

    def test_the_documented_directory_is_searched_first(self):
        self.assertEqual(nt.S0_PRODUCER_DIRS[0], "legacy/ntasm-s0/fixed-point")
        self.assertIn("bootstrap/ntasm-s0/fixed-point", nt.S0_PRODUCER_DIRS)

    def test_the_pins_are_the_digests_the_repository_publishes(self):
        readme = self.REPO / "legacy/ntasm-s0/fixed-point/README.md"
        if not readme.is_file():
            self.skipTest("the fixed-point documentation is not in this tree")
        text = readme.read_text(encoding="utf-8", errors="replace")
        for name, pin in nt.PINS.items():
            with self.subTest(producer=name):
                self.assertIn(name, text)
                self.assertIn(pin, text)

    def test_the_documented_directory_is_accepted_when_it_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "legacy/ntasm-s0/fixed-point").mkdir(parents=True)
            found = nt.s0_producer_dir(repo)
            self.assertEqual(found, (repo / "legacy/ntasm-s0/fixed-point").resolve())

    def test_the_house_layout_is_still_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "bootstrap/ntasm-s0/fixed-point").mkdir(parents=True)
            found = nt.s0_producer_dir(repo)
            self.assertEqual(found, (repo / "bootstrap/ntasm-s0/fixed-point").resolve())

    def test_a_missing_producer_directory_is_a_refusal_not_a_skip(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            with self.assertRaises(nt.Refusal) as caught:
                nt.s0_producer_dir(repo)
            message = str(caught.exception)
            self.assertIn("missing S0 producer directory", message)
            # The paths are absolute, and Windows spells them with
            # backslashes: compare them the same way.
            message = message.replace("\\", "/")
            for relative in nt.S0_PRODUCER_DIRS:
                self.assertIn(relative, message)

    def test_the_transport_names_no_other_producer_path(self):
        source = Path(nt.__file__).read_text()
        # Only path-shaped strings are looked at, so a mention in a comment or
        # in the docstring is not mistaken for a dependency.
        named = set(re.findall(r"[\"']([\w./-]*fixed-point[\w./-]*)[\"']", source))
        self.assertTrue(named)
        for path in named:
            with self.subTest(path=path):
                self.assertIn(path, nt.S0_PRODUCER_DIRS)


class WorkspaceTests(unittest.TestCase):
    def test_repo_defaults_to_the_parent_of_the_scripts_folder(self):
        self.assertEqual(nt.DEFAULT_REPO, Path(nt.__file__).resolve().parent.parent)

    def test_work_root_defaults_to_repo_out(self):
        repo = nt.resolve_repo(None)
        self.assertEqual(nt.resolve_work_root(repo, None), (repo / "out").resolve())

    def test_work_root_under_repo_out_is_accepted(self):
        repo = nt.resolve_repo(None)
        where = nt.resolve_work_root(repo, "out/a8-selfhost")
        self.assertEqual(where, (repo / "out" / "a8-selfhost").resolve())

    def test_work_root_outside_repo_out_is_refused(self):
        repo = nt.resolve_repo(None)
        with self.assertRaises(nt.Refusal):
            nt.resolve_work_root(repo, "scripts")
        with self.assertRaises(nt.Refusal):
            nt.resolve_work_root(repo, str(repo.parent))

    def test_unsafe_names_are_refused(self):
        for bad in ("", ".", "..", "a/b", "a\\b", "-lead", "a b", "x" * 72):
            with self.subTest(name=bad):
                with self.assertRaises(nt.Refusal):
                    nt.check_name(bad)

    def test_safe_names_are_accepted(self):
        for good in ("a", "A1", "x-y_z", "x" * 71):
            with self.subTest(name=good):
                self.assertEqual(nt.check_name(good), good)

    def test_existing_evidence_is_never_reused(self):
        with self.assertRaises(nt.Refusal):
            nt.refuse_reuse(Path(__file__).resolve().parent)
        absent = Path(__file__).resolve().parent / "absent-evidence-12345"
        self.assertEqual(nt.refuse_reuse(absent), absent)


class TimeoutBoundsTests(unittest.TestCase):
    def test_the_bounds_are_ten_to_ten_thousand_eight_hundred(self):
        self.assertEqual(nt.TIMEOUT_MIN, 10)
        self.assertEqual(nt.TIMEOUT_MAX, 10800)

    def test_the_bounds_are_inclusive(self):
        self.assertEqual(nt.check_timeout(10), 10)
        self.assertEqual(nt.check_timeout(10800), 10800)

    def test_out_of_bounds_timeouts_are_refused(self):
        for bad in (9, 10801, 0, -1):
            with self.subTest(timeout=bad):
                with self.assertRaises(nt.Refusal):
                    nt.check_timeout(bad)

    def test_the_standalone_default_stays_two_hundred_and_forty(self):
        args = nt.build_parser().parse_args(
            ["--name", "probe", "assemble", "SOURCE"])
        self.assertEqual(args.timeout, 240)
        self.assertEqual(nt.check_timeout(240), 240)


class ExtractionNameTests(unittest.TestCase):
    def test_the_local_name_is_extracted_prefixed(self):
        self.assertEqual(nt.extract_file_name("OUTPUT.EFI"), "extracted-OUTPUT.EFI")
        self.assertEqual(nt.extract_file_name("NOVA.OUT"), "extracted-NOVA.OUT")

    def test_unsafe_extraction_targets_are_refused(self):
        for bad in ("", "sub/dir.EFI", "A B.EFI", "x" * 32, "back\\slash.EFI"):
            with self.subTest(name=bad):
                with self.assertRaises(nt.Refusal):
                    nt.extract_file_name(bad)

    def test_the_dot_names_are_refused_as_payload_and_as_extraction(self):
        for bad in (".", ".."):
            with self.subTest(name=bad):
                with self.assertRaises(nt.Refusal):
                    nt.extract_file_name(bad)
                with self.assertRaises(nt.Refusal):
                    nt.check_esp_names([(Path("a"), bad)], [])
                with self.assertRaises(nt.Refusal):
                    nt.check_esp_names([(Path("a"), "INPUT.NOVA")], [bad])

    def test_an_extraction_target_cannot_be_an_input(self):
        payloads = [(Path("host"), "EFI/BOOT/BOOTX64.EFI"),
                    (Path("runtime"), "NVRUNTIME.EFI"),
                    (Path("core"), "NOVACORE.EFI")]
        nt.check_esp_names(payloads, ["OUTPUT.EFI"])
        for bad in ("NVRUNTIME.EFI", "NOVACORE.EFI", "NOVACORE.efi"):
            with self.subTest(name=bad):
                with self.assertRaises(nt.Refusal):
                    nt.check_esp_names(payloads, [bad])

    def test_an_extraction_target_cannot_be_named_twice(self):
        payloads = [(Path("host"), "EFI/BOOT/BOOTX64.EFI")]
        with self.assertRaises(nt.Refusal):
            nt.check_esp_names(payloads, ["OUTPUT.EFI", "output.efi"])

    def test_two_payloads_with_one_name_collide(self):
        payloads = [(Path("a"), "SAME.EFI"), (Path("b"), "same.efi")]
        with self.assertRaises(nt.Refusal):
            nt.check_esp_names(payloads, [])

    def test_an_extraction_is_not_an_attestation(self):
        record = nt.extraction_record("OUTPUT.EFI", Path("extracted-OUTPUT.EFI"), b"PE")
        self.assertFalse(record["attestation"])
        self.assertEqual(record["bytes"], 2)
        self.assertEqual(record["sha256"], hashlib.sha256(b"PE").hexdigest())
        self.assertIn("NOT an attestation", record["statement"])


class RamGuardTests(unittest.TestCase):
    def test_the_thresholds_are_nine_and_eight_gibibytes(self):
        self.assertEqual(nt.RAM_START_MIN, 9 * 1024 ** 3)
        self.assertEqual(nt.RAM_STOP_MAX, 8 * 1024 ** 3)
        self.assertEqual(nt.RAM_POLL_SECONDS, 5.0)

    def test_the_start_decision_needs_nine_gibibytes(self):
        self.assertEqual(nt.ram_decision(nt.RAM_START_MIN, "start"), "allow")
        self.assertEqual(nt.ram_decision(nt.RAM_START_MIN - 1, "start"), "refuse")

    def test_the_running_decision_stops_under_eight_gibibytes(self):
        self.assertEqual(nt.ram_decision(nt.RAM_STOP_MAX, "running"), "continue")
        self.assertEqual(nt.ram_decision(nt.RAM_STOP_MAX - 1, "running"), "trip")

    def test_the_window_between_the_two_thresholds_refuses_the_start(self):
        self.assertEqual(nt.ram_decision(nt.RAM_STOP_MAX, "start"), "refuse")
        self.assertEqual(nt.ram_decision(nt.RAM_STOP_MAX, "running"), "continue")

    def test_a_measurement_that_fails_is_a_refusal(self):
        with mock.patch.object(nt, "measure_free_memory",
                               side_effect=nt.Refusal("cannot measure RAM")):
            with self.assertRaises(nt.Refusal):
                nt.require_ram_start()

    def test_a_start_below_the_threshold_is_refused(self):
        with mock.patch.object(nt, "measure_free_memory",
                               return_value=nt.RAM_START_MIN - 1):
            with self.assertRaises(nt.Refusal):
                nt.require_ram_start()

    def test_a_start_at_the_threshold_is_accepted(self):
        with mock.patch.object(nt, "measure_free_memory",
                               return_value=nt.RAM_START_MIN):
            self.assertEqual(nt.require_ram_start(), nt.RAM_START_MIN)

    def test_the_guard_alone_decides_the_boot_verdict(self):
        self.assertTrue(nt.ram_pass({}))
        self.assertFalse(nt.ram_pass({"tripped": True}))
        self.assertFalse(nt.ram_pass({"measurement_failed": True}))

    def test_the_guard_rides_in_the_boot_loop(self):
        source = inspect.getsource(nt.boot)
        self.assertIn("measure_free_memory()", source)
        self.assertIn("RAM_POLL_SECONDS", source)
        self.assertIn("ram_decision(free, \"running\")", source)
        self.assertIn("ram_pass(ram)", source)


class RamMeasurementTests(unittest.TestCase):
    """The measurement of the free RAM, when the host is busy.

    A QEMU guest takes every core it is given, and the measurement of the
    Windows host then takes longer than its timeout. A slow measurement is
    not a failed one: the call is retried, and only the failure of every
    attempt refuses the run.
    """

    def windows(self, side_effect):
        return mock.patch.multiple(
            nt, _powershell_path=mock.Mock(return_value=Path("/fake/powershell.exe")),
            **{"subprocess.run": mock.Mock(side_effect=side_effect),
               "time.sleep": mock.Mock()})

    def test_a_slow_measurement_is_retried_and_can_succeed(self):
        calls = []

        def fake_run(args, **kwargs):
            calls.append(args)
            if len(calls) < 3:
                raise subprocess.TimeoutExpired(cmd="powershell", timeout=60)
            return mock.Mock(returncode=0, stdout=b"1048576\r\n")

        with mock.patch.object(nt, "_powershell_path",
                               return_value=Path("/fake/powershell.exe")), \
             mock.patch.object(nt.subprocess, "run", side_effect=fake_run), \
             mock.patch.object(nt.time, "sleep"):
            free = nt._measure_windows()
        self.assertEqual(free, 1048576 * 1024)
        self.assertEqual(len(calls), 3)

    def test_a_measurement_that_always_fails_is_still_a_refusal(self):
        with mock.patch.object(nt, "_powershell_path",
                               return_value=Path("/fake/powershell.exe")), \
             mock.patch.object(nt.subprocess, "run",
                               side_effect=subprocess.TimeoutExpired(
                                   cmd="powershell", timeout=60)), \
             mock.patch.object(nt.time, "sleep"):
            with self.assertRaises(nt.Refusal) as caught:
                nt._measure_windows()
        self.assertIn("after 3 attempts", str(caught.exception))

    def test_an_unreadable_answer_is_still_a_refusal(self):
        with mock.patch.object(nt, "_powershell_path",
                               return_value=Path("/fake/powershell.exe")), \
             mock.patch.object(nt.subprocess, "run",
                               return_value=mock.Mock(returncode=0,
                                                     stdout=b"not a number")), \
             mock.patch.object(nt.time, "sleep"):
            with self.assertRaises(nt.Refusal):
                nt._measure_windows()

    def test_the_attempts_and_the_timeout_are_bounded(self):
        self.assertEqual(nt.RAM_MEASURE_ATTEMPTS, 3)
        self.assertLessEqual(nt.RAM_MEASURE_TIMEOUT, 120)
        self.assertGreater(nt.RAM_MEASURE_TIMEOUT, 60)


class ForeignQemuTests(unittest.TestCase):
    def test_the_linux_check_refuses_when_proc_is_absent(self):
        with self.assertRaises(nt.Refusal):
            nt.other_qemu_pids(Path("/definitely-absent-12345"))

    def test_the_windows_check_refuses_without_powershell(self):
        with mock.patch.object(nt, "_powershell_path", return_value=None):
            with self.assertRaises(nt.Refusal):
                nt.other_windows_qemu_pids()

    def test_under_wsl_both_sides_are_listed(self):
        with mock.patch.object(nt, "_under_wsl", return_value=True), \
                mock.patch.object(nt, "other_qemu_pids", return_value=[11]), \
                mock.patch.object(nt, "other_windows_qemu_pids", return_value=[22]):
            self.assertEqual(nt.foreign_qemu_pids(), [11, 22])

    def test_outside_wsl_only_the_linux_side_is_listed(self):
        with mock.patch.object(nt, "_under_wsl", return_value=False), \
                mock.patch.object(nt, "other_qemu_pids", return_value=[11]), \
                mock.patch.object(nt, "other_windows_qemu_pids",
                                  side_effect=AssertionError("must not be called")):
            self.assertEqual(nt.foreign_qemu_pids(), [11])

    def test_no_foreign_process_is_ever_stopped(self):
        for function in (nt.other_qemu_pids, nt.other_windows_qemu_pids,
                         nt.foreign_qemu_pids):
            source = inspect.getsource(function)
            for forbidden in ("kill", "terminate", "send_signal", "SIGTERM",
                              "Stop-Process"):
                with self.subTest(function=function.__name__, token=forbidden):
                    self.assertNotIn(forbidden, source)


class BootShapeTests(unittest.TestCase):
    def test_qemu_is_always_512m_four_cpu_headless_without_network(self):
        # The guest memory is ONE named value: the argv and the contract
        # record must carry exactly "512M", never a literal of their own.
        self.assertEqual(nt.QEMU_MEMORY, "512M")
        self.assertEqual(nt.QEMU_CPUS, 4)
        source = inspect.getsource(nt.boot)
        for token in ('"-m", QEMU_MEMORY', '"-smp", str(QEMU_CPUS)', '"-nic", "none"',
                      '"-display", "none"', '"-monitor"'):
            with self.subTest(token=token):
                self.assertIn(token, source)
        self.assertIn("qemu_memory=QEMU_MEMORY",
                      inspect.getsource(nt.record_workspace))

    def test_the_cleanup_quits_through_hmp_and_touches_only_its_own_pid(self):
        source = inspect.getsource(nt.boot)
        self.assertIn("hmp_quit(port, where)", source)
        self.assertIn("p.terminate()", source)
        self.assertIn("p.kill()", source)
        for forbidden in ("pkill", "os.kill", "killpg", "taskkill"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, source)

    def test_the_transport_takes_no_lock(self):
        source = Path(nt.__file__).read_text()
        self.assertNotIn("import fcntl", source)
        self.assertNotIn("fcntl.flock", source)
        self.assertNotIn("flock(", source)
        self.assertNotIn("LOCK_EX", source)


class RecordTests(unittest.TestCase):
    def test_the_complete_record_never_claims_a8(self):
        record = nt.complete_record(True, "run")
        self.assertTrue(record["pass_"])
        self.assertFalse(record["a8_selfhost_proven"])
        self.assertNotIn("a8=yes", json.dumps(record))

    def test_a_failed_run_is_not_complete(self):
        record = nt.complete_record(False, "run")
        self.assertFalse(record["pass_"])
        self.assertFalse(record["a8_selfhost_proven"])

    def test_the_ram_facts_are_computed(self):
        record = nt.ram_record({"start_free": 10, "last_free": 9, "polled": 3})
        self.assertEqual(record["start_min"], nt.RAM_START_MIN)
        self.assertEqual(record["stop_max"], nt.RAM_STOP_MAX)
        self.assertEqual(record["poll_seconds"], 5.0)
        self.assertEqual(record["polled"], 3)
        self.assertFalse(record["tripped"])
        self.assertFalse(record["measurement_failed"])


# --------------------------------------------------------------------------
# The HMP liveness poll: mocked, no QEMU, no real monitor, no wait
# --------------------------------------------------------------------------

class FakeClock:
    """A monotonic clock the test drives, so no test ever waits."""

    def __init__(self, start=1000.0, step=0.1):
        self.now = start
        self.step = step

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += max(seconds, self.step)


class FakeProcess:
    """A QEMU process that stays alive until somebody waits for it."""

    def __init__(self, returncode=0):
        self.pid = 4242
        self.returncode = None
        self.final = returncode
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.returncode = self.final
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9


class FakeSocket:
    """A scripted HMP socket: a banner, then one answer per command."""

    def __init__(self, answers=None, banner=b"QEMU 8.2.0 monitor\r\n(qemu) ",
                 write_error=None):
        self.answers = answers or {}
        self.banner = banner
        self.write_error = write_error or ()
        self.pending = [banner]
        self.sent = []
        self.timeout = None
        self.closed = False

    def settimeout(self, value):
        self.timeout = value

    def sendall(self, data):
        self.sent.append(data)
        command = data.decode("ascii", "replace").strip()
        if command in self.write_error:
            raise OSError("the monitor refused the command")
        self.pending = list(self.answers.get(command, []))

    def recv(self, size):
        if not self.pending:
            raise socket.timeout("no more data")
        return self.pending.pop(0)

    def close(self):
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


class FakeMonitor:
    """The monitor of the mocked QEMU: one new socket per connection.

    `answers` is either one answer set for every connection, or a list of
    answer sets used in the order of the connections (the last one repeated).
    `refuse` refuses the first N connections. `write_error` refuses to write
    the named commands: the monitor is there, but it never answers.
    """

    def __init__(self, answers=None, refuse=0, write_error=None):
        self.answers = answers if answers is not None else {}
        self.refuse = refuse
        self.write_error = write_error
        self.calls = 0
        self.sockets = []

    def connect(self, address, timeout=None):
        self.calls += 1
        if self.calls <= self.refuse:
            raise ConnectionRefusedError("connection refused")
        sock = FakeSocket(self.answers_for(self.calls), write_error=self.write_error)
        self.sockets.append(sock)
        return sock

    def answers_for(self, index):
        if isinstance(self.answers, list):
            return self.answers[min(index - 1, len(self.answers) - 1)]
        return self.answers

    def commands(self):
        """Every command the transport sent to the monitor."""
        sent = []
        for sock in self.sockets:
            sent += [data.decode("ascii", "replace").strip()
                     for data in sock.sent]
        return sent


class MockedBoot:
    """One boot of the transport with no QEMU, no real monitor and no wait.

    `serial_at` delays the appearance of the serial log, so the success
    markers can arrive BETWEEN two scheduled polls.
    """

    def __init__(self, serial, answers=None, refuse=0, timeout=10,
                 serial_at=None, write_error=None):
        self.serial = serial
        self.monitor = FakeMonitor(answers, refuse, write_error)
        self.clock = FakeClock()
        self.process = FakeProcess()
        self.polls = []
        self.timeout = timeout
        self.serial_at = None if serial_at is None else self.clock.now + serial_at
        self.written = False
        self.where = None
        self.start = self.clock.now
        self.end = self.start

    def sleep(self, seconds):
        self.clock.now += max(seconds, self.clock.step)
        if (self.serial_at is not None and not self.written
                and self.clock.now >= self.serial_at):
            self.written = True
            (self.where / "serial.log").write_text(self.serial, encoding="utf-8")

    def run(self):
        self.where = Path(tempfile.mkdtemp(prefix="a8-hmp-"))
        if self.serial_at is None:
            (self.where / "serial.log").write_text(self.serial, encoding="utf-8")
        args = argparse.Namespace(qemu="qemu-system-x86_64", code="code.fd",
                                  vars="vars.fd", timeout=self.timeout)
        real_liveness = nt.hmp_liveness

        def spy(port, command=nt.HMP_COMMAND):
            self.polls.append(self.clock.now)
            return real_liveness(port, command=command)

        error = None
        with mock.patch.object(nt, "measure_free_memory",
                               return_value=nt.RAM_START_MIN + 1024 ** 3), \
             mock.patch.object(nt.subprocess, "Popen",
                               return_value=self.process), \
             mock.patch.object(nt.socket, "create_connection",
                               side_effect=self.monitor.connect), \
             mock.patch.object(nt.time, "monotonic", self.clock.monotonic), \
             mock.patch.object(nt.time, "sleep", self.sleep), \
             mock.patch.object(nt, "hmp_liveness", spy):
            try:
                nt.boot(self.where, self.where / "esp.img", MARKER, args)
            except Exception as exc:
                error = exc
            self.end = self.clock.now
        result = json.loads((self.where / "boot-result.json").read_text())
        return result, error, self.where


def success_serial():
    """The serial log of a boot that proved itself: marker and return."""
    return start() + MARKER + "\r\n" + returned()


class HmpStatusTests(unittest.TestCase):
    def test_running_is_parsed(self):
        self.assertEqual(nt.parse_vm_status("VM status: running\r\n"),
                         ("running", None))

    def test_paused_shutdown_is_parsed(self):
        self.assertEqual(nt.parse_vm_status("VM status: paused (shutdown)\r\n"),
                         ("paused", "shutdown"))

    def test_paused_internal_error_is_parsed(self):
        self.assertEqual(nt.parse_vm_status("VM status: paused (internal error)"),
                         ("paused", "internal error"))

    def test_the_escapes_the_echo_and_the_prompt_are_ignored(self):
        transcript = ("\x1b[0mQEMU 8.2.0 monitor - type 'help' for more "
                      "information\r\n(qemu) \x1b[1minfo status\x1b[0m\r\n"
                      "VM status: running\r\n(qemu) ")
        self.assertEqual(nt.parse_vm_status(transcript), ("running", None))

    def test_a_transcript_without_a_status_is_not_parsed(self):
        self.assertIsNone(nt.parse_vm_status("QEMU 8.2.0 monitor\r\n(qemu) "))
        self.assertIsNone(nt.parse_vm_status(""))
        self.assertIsNone(nt.parse_vm_status("VM status:\r\n"))

    def test_a_partial_line_is_not_a_status(self):
        self.assertIsNone(nt.parse_vm_status("VM sta"))

    def test_running_and_prelaunch_are_not_fatal(self):
        self.assertFalse(nt.hmp_state_is_fatal("running", None))
        self.assertFalse(nt.hmp_state_is_fatal("paused", "prelaunch"))

    def test_shutdown_and_internal_error_are_fatal(self):
        self.assertTrue(nt.hmp_state_is_fatal("paused", "shutdown"))
        self.assertTrue(nt.hmp_state_is_fatal("paused", "internal error"))
        self.assertTrue(nt.hmp_state_is_fatal("paused", None))

    def test_a_plain_paused_status_is_a_paused_state(self):
        # QEMU prints a reason, but a bare `paused` is a paused guest and
        # never a verified one.
        self.assertEqual(nt.parse_vm_status("VM status: paused"),
                         ("paused", None))
        self.assertTrue(nt.hmp_state_is_fatal(*nt.parse_vm_status(
            "VM status: paused")))
        self.assertEqual(nt.hmp_state_text("paused", None), "paused")

    def test_the_live_monitor_transcripts_are_parsed(self):
        # The fixtures are the REAL transcripts of a live QEMU 8.2.2 monitor,
        # captured by the bounded live check. They carry the banner, the
        # prompt and the echoed command with its ANSI redisplay escapes.
        fixtures = Path(__file__).resolve().parent / "fixtures"
        running = fixtures / "hmp-live-running.txt"
        shutdown = fixtures / "hmp-live-paused-shutdown.txt"
        if not (running.is_file() and shutdown.is_file()):
            self.skipTest("the live transcripts are not in this tree")
        self.assertEqual(nt.parse_vm_status(running.read_text(encoding="utf-8")),
                         ("running", None))
        self.assertEqual(
            nt.parse_vm_status(shutdown.read_text(encoding="utf-8")),
            ("paused", "shutdown"))
        self.assertTrue(nt.hmp_state_is_fatal(
            *nt.parse_vm_status(shutdown.read_text(encoding="utf-8"))))
        # The live transcript is the one the archive recorded too.
        self.assertIn("QEMU 8.2.2 monitor", running.read_text(encoding="utf-8"))

    def test_a_truncated_status_is_never_a_verified_state(self):
        for text in ("VM status: runn", "VM status: paused (shut",
                     "VM status: running (x)", "VM status:"):
            with self.subTest(text=text):
                self.assertIsNone(nt.parse_vm_status(text))

    def test_the_state_text_is_the_one_qemu_prints(self):
        self.assertEqual(nt.hmp_state_text("paused", "shutdown"),
                         "paused (shutdown)")
        self.assertEqual(nt.hmp_state_text("running", None), "running")

    def test_a_fatal_state_vetoes_the_proof(self):
        self.assertFalse(nt.liveness_pass({"fatal": True, "confirmed": True}))
        self.assertFalse(nt.liveness_pass({"fatal": False, "confirmed": False}))
        self.assertTrue(nt.liveness_pass({"fatal": False, "confirmed": True}))

    def test_an_unconfirmed_success_is_not_a_proof(self):
        # No fatal state, but no DUE observation either: the markers of the
        # serial log alone are not a proof.
        self.assertFalse(nt.liveness_pass({"fatal": False, "confirmed": False}))
        self.assertFalse(nt.liveness_pass({}))

    def test_the_poll_is_read_only_and_never_frequent(self):
        self.assertEqual(nt.HMP_COMMAND, "info status")
        self.assertEqual(nt.HMP_POLL_SECONDS, 5.0)
        self.assertGreater(nt.HMP_QUERY_TIMEOUT, 0)
        self.assertLessEqual(nt.HMP_QUERY_TIMEOUT, nt.HMP_POLL_SECONDS)
        self.assertEqual(nt.HMP_VERIFIED_STATE, "running")
        self.assertEqual(nt.HMP_UNKNOWN_STATE, "unknown")


class HmpQueryTests(unittest.TestCase):
    def query(self, monitor, **kwargs):
        with mock.patch.object(nt.socket, "create_connection",
                               side_effect=monitor.connect):
            return nt.hmp_query(4711, **kwargs), monitor

    def test_the_query_sends_only_the_status_command(self):
        (transcript, error), monitor = self.query(
            FakeMonitor({"info status": [b"VM status: running\r\n"]}))
        self.assertIsNone(error)
        self.assertEqual(monitor.commands(), ["info status"])
        self.assertEqual(nt.parse_vm_status(transcript), ("running", None))

    def test_an_unavailable_monitor_is_reported_and_not_raised(self):
        (transcript, error), _ = self.query(FakeMonitor(refuse=1))
        self.assertEqual(transcript, "")
        self.assertIn("unavailable", error)

    def test_a_malformed_answer_is_kept_as_a_transcript(self):
        (transcript, error), _ = self.query(
            FakeMonitor({"info status": [b"what?\r\n"]}))
        self.assertIsNone(error)
        self.assertIn("what?", transcript)
        self.assertIsNone(nt.parse_vm_status(transcript))

    def test_a_partial_answer_is_accumulated(self):
        (transcript, error), _ = self.query(
            FakeMonitor({"info status": [b"VM sta", b"tus: running\r\n"]}))
        self.assertIsNone(error)
        self.assertEqual(nt.parse_vm_status(transcript), ("running", None))

    def test_a_disconnected_monitor_does_not_block(self):
        (transcript, error), _ = self.query(
            FakeMonitor({"info status": [b""]}))
        self.assertIsNone(error)
        self.assertIsNone(nt.parse_vm_status(transcript))

    def test_a_silent_monitor_does_not_block(self):
        (transcript, error), _ = self.query(FakeMonitor())
        self.assertIsNone(error)
        self.assertIsNone(nt.parse_vm_status(transcript))

    def test_the_liveness_observation_says_how_the_exchange_went(self):
        with mock.patch.object(nt.socket, "create_connection",
                               side_effect=FakeMonitor(
                                   {"info status": [b"VM status: running\r\n"]}
                               ).connect):
            observation = nt.hmp_liveness(4711)
        self.assertEqual(observation["outcome"], "ok")
        self.assertEqual(observation["state"], "running")
        self.assertFalse(observation["fatal"])

        with mock.patch.object(nt.socket, "create_connection",
                               side_effect=FakeMonitor(
                                   {"info status": [b"noise\r\n"]}).connect):
            observation = nt.hmp_liveness(4711)
        self.assertEqual(observation["outcome"], "malformed")
        self.assertFalse(observation["fatal"])

        with mock.patch.object(nt.socket, "create_connection",
                               side_effect=FakeMonitor(refuse=1).connect):
            observation = nt.hmp_liveness(4711)
        self.assertEqual(observation["outcome"], "unavailable")
        self.assertFalse(observation["fatal"])

    def test_an_unreadable_exchange_is_unknown_and_never_running(self):
        # The monitor answered, but not with a status: the state is UNKNOWN,
        # and it must never be counted as a verified running guest.
        for answers, expected in (({"info status": [b"noise\r\n"]}, "malformed"),
                                  ({"info status": [b"VM status: runn"]},
                                   "malformed")):
            with self.subTest(outcome=expected):
                with mock.patch.object(nt.socket, "create_connection",
                                       side_effect=FakeMonitor(answers).connect):
                    observation = nt.hmp_liveness(4711)
                self.assertEqual(observation["outcome"], expected)
                self.assertEqual(observation["state"], nt.HMP_UNKNOWN_STATE)
                self.assertNotEqual(observation["state"], nt.HMP_VERIFIED_STATE)
                self.assertFalse(observation["fatal"])


class BootLivenessTests(unittest.TestCase):
    """The boot loop of the transport, with a mocked QEMU and a mocked
    monitor: no QEMU is started, and no test ever waits."""

    def test_a_guest_that_is_gone_fails_the_proof_even_with_a_success_marker(self):
        boot = MockedBoot(
            success_serial(),
            {"info status": [b"VM status: paused (shutdown)\r\n(qemu) "]})
        result, error, where = boot.run()
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("paused (shutdown)", str(error))
        self.assertFalse(result["pass"])
        # The serial log held a COMPLETE proof...
        self.assertTrue(result["marker_exact_once"])
        self.assertTrue(result["firmware_return"])
        self.assertEqual(result["shutdown"], "hmp")
        self.assertEqual(result["exit_code"], 0)
        # ... and the proof still failed, because the guest was gone.
        self.assertTrue(result["liveness"]["fatal"])
        self.assertEqual(result["liveness"]["state"], "paused")
        self.assertEqual(result["liveness"]["reason"], "shutdown")
        self.assertIn("paused (shutdown)", result["failure_reason"])
        # The diagnostic HMP output is kept.
        kept = (where / "hmp-liveness.log").read_text(encoding="utf-8")
        self.assertIn("VM status: paused (shutdown)", kept)

    def test_a_guest_in_an_internal_error_fails_the_proof(self):
        boot = MockedBoot(
            success_serial(),
            {"info status": [b"VM status: paused (internal error)\r\n(qemu) "]})
        result, error, where = boot.run()
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("paused (internal error)", str(error))
        self.assertFalse(result["pass"])
        self.assertTrue(result["liveness"]["fatal"])
        self.assertEqual(result["liveness"]["reason"], "internal error")

    def test_a_normal_success_passes(self):
        boot = MockedBoot(
            success_serial(),
            {"info status": [b"VM status: running\r\n(qemu) "]})
        result, error, where = boot.run()
        self.assertIsNone(error)
        self.assertTrue(result["pass"])
        self.assertEqual(result["liveness"]["state"], "running")
        self.assertTrue(result["liveness"]["confirmed"])
        self.assertFalse(result["liveness"]["fatal"])
        self.assertEqual(result["liveness"]["unavailable"], 0)
        self.assertEqual(result["liveness"]["malformed"], 0)

    def test_a_running_guest_without_a_marker_fails_on_the_timeout(self):
        boot = MockedBoot(start(), {"info status": [b"VM status: running\r\n"]},
                          timeout=30)
        result, error, where = boot.run()
        self.assertIsInstance(error, RuntimeError)
        self.assertFalse(result["pass"])
        # The guest was alive: the failure is the missing proof, not the VM.
        self.assertFalse(result["liveness"]["fatal"])
        self.assertEqual(result["liveness"]["state"], "running")
        self.assertGreaterEqual(result["liveness"]["polled"], 2)

    def test_an_unavailable_monitor_is_recorded_and_does_not_fail_a_good_run(self):
        # The FIRST poll finds no monitor; the next due poll does, and it
        # confirms the success.
        boot = MockedBoot(
            success_serial(),
            {"info status": [b"VM status: running\r\n(qemu) "]},
            refuse=1)
        result, error, where = boot.run()
        self.assertIsNone(error)
        self.assertTrue(result["pass"])
        self.assertEqual(result["liveness"]["unavailable"], 1)
        self.assertTrue(result["liveness"]["confirmed"])
        self.assertFalse(result["liveness"]["fatal"])

    def test_a_malformed_monitor_is_recorded_and_never_confirms(self):
        # The monitor never answers with a status: the state stays UNKNOWN,
        # the success is never confirmed, and the run fails on the deadline.
        boot = MockedBoot(
            success_serial(),
            {"info status": [b"garbage from the monitor\r\n"]},
            timeout=10)
        result, error, where = boot.run()
        self.assertIsInstance(error, RuntimeError)
        self.assertFalse(result["pass"])
        self.assertGreaterEqual(result["liveness"]["malformed"], 2)
        self.assertEqual(result["liveness"]["state"], nt.HMP_UNKNOWN_STATE)
        self.assertNotEqual(result["liveness"]["state"], nt.HMP_VERIFIED_STATE)
        self.assertFalse(result["liveness"]["confirmed"])
        # The serial log held a complete proof, and the deadline was kept.
        self.assertTrue(result["marker_exact_once"])
        self.assertTrue(result["firmware_return"])
        self.assertGreaterEqual(boot.end - boot.start, boot.timeout - 1e-6)
        self.assertIn("never confirmed", result["failure_reason"])

    def test_a_success_between_polls_is_not_accepted_on_a_stale_observation(self):
        # The markers arrive at t=2, BETWEEN the polls of t=0 and t=5. The
        # observation of t=0 is stale: it cannot accept the success.
        boot = MockedBoot(
            success_serial(),
            [{"info status": [b"VM status: running\r\n(qemu) "]},
             {"info status": [b"VM status: running\r\n(qemu) "]}],
            timeout=30, serial_at=2.0)
        result, error, where = boot.run()
        self.assertIsNone(error)
        self.assertTrue(result["pass"])
        self.assertTrue(result["liveness"]["confirmed"])
        # Two polls were needed: the stale one did not accept the markers.
        self.assertEqual(len(boot.polls), 2)
        self.assertGreaterEqual(boot.polls[1] - boot.polls[0], 5.0)

    def test_a_shutdown_between_polls_fails_the_proof(self):
        # The markers arrive at t=2, between the polls. The next DUE poll
        # finds the guest gone: the proof fails, complete markers or not.
        boot = MockedBoot(
            success_serial(),
            [{"info status": [b"VM status: running\r\n(qemu) "]},
             {"info status": [b"VM status: paused (shutdown)\r\n(qemu) "]},
             {"info status": [b"VM status: paused (shutdown)\r\n(qemu) "]}],
            timeout=30, serial_at=2.0)
        result, error, where = boot.run()
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("paused (shutdown)", str(error))
        self.assertFalse(result["pass"])
        self.assertTrue(result["liveness"]["fatal"])
        self.assertFalse(result["liveness"]["confirmed"])
        self.assertEqual(result["liveness"]["state"], "paused")
        self.assertEqual(result["liveness"]["reason"], "shutdown")
        # The markers were complete: the veto alone failed the run.
        self.assertTrue(result["marker_exact_once"])
        self.assertTrue(result["firmware_return"])

    def test_a_success_with_an_unavailable_monitor_is_never_accepted(self):
        # The monitor never answers. The markers are complete, but the guest
        # state was never verified: the proof is not a proof.
        boot = MockedBoot(
            success_serial(),
            {"info status": [b"VM status: running\r\n(qemu) "]},
            timeout=10, write_error=("info status",))
        result, error, where = boot.run()
        self.assertIsInstance(error, RuntimeError)
        self.assertFalse(result["pass"])
        self.assertFalse(result["liveness"]["confirmed"])
        self.assertFalse(result["liveness"]["fatal"])
        self.assertEqual(result["liveness"]["state"], nt.HMP_UNKNOWN_STATE)
        self.assertNotEqual(result["liveness"]["state"], nt.HMP_VERIFIED_STATE)
        self.assertGreaterEqual(result["liveness"]["unavailable"], 2)
        # Every other fact of the run is good: the liveness is the only
        # reason it failed, and the cleanup was the normal one.
        self.assertTrue(result["marker_exact_once"])
        self.assertTrue(result["firmware_return"])
        self.assertEqual(result["shutdown"], "hmp")
        self.assertEqual(result["exit_code"], 0)
        self.assertFalse(result["forced"])
        self.assertIn("never confirmed", result["failure_reason"])
        # The deadline was kept, and the diagnostics are preserved.
        self.assertGreaterEqual(boot.end - boot.start, boot.timeout - 1e-6)
        self.assertTrue((where / "hmp-liveness.log").exists())

    def test_a_plain_paused_status_fails_the_proof(self):
        boot = MockedBoot(
            success_serial(),
            {"info status": [b"VM status: paused\r\n(qemu) "]})
        result, error, where = boot.run()
        self.assertIsInstance(error, RuntimeError)
        self.assertIn("paused", str(error))
        self.assertFalse(result["pass"])
        self.assertTrue(result["liveness"]["fatal"])
        self.assertEqual(result["liveness"]["state"], "paused")
        self.assertEqual(result["liveness"]["reason"], "")

    def test_a_truncated_status_is_unknown_and_the_next_poll_recovers(self):
        # The first answer is cut in the middle: it is UNKNOWN, never a
        # verified running guest. The next due poll answers properly.
        boot = MockedBoot(
            success_serial(),
            [{"info status": [b"VM status: runn"]},
             {"info status": [b"VM status: running\r\n(qemu) "]}],
            timeout=30, serial_at=2.0)
        result, error, where = boot.run()
        self.assertIsNone(error)
        self.assertTrue(result["pass"])
        self.assertTrue(result["liveness"]["confirmed"])
        self.assertEqual(result["liveness"]["malformed"], 1)
        self.assertEqual(result["liveness"]["state"], "running")

    def test_a_later_malformed_answer_does_not_keep_the_running_state(self):
        # The first poll says running, the next one is unreadable: the state
        # must become UNKNOWN, not stay the stale `running`.
        boot = MockedBoot(start(),
                          [{"info status": [b"VM status: running\r\n(qemu) "]},
                           {"info status": [b"garbage\r\n"]},
                           {"info status": [b"garbage\r\n"]}],
                          timeout=30)
        result, error, where = boot.run()
        self.assertIsInstance(error, RuntimeError)
        self.assertFalse(result["pass"])
        self.assertEqual(result["liveness"]["state"], nt.HMP_UNKNOWN_STATE)
        self.assertNotEqual(result["liveness"]["state"], nt.HMP_VERIFIED_STATE)
        self.assertGreaterEqual(result["liveness"]["malformed"], 1)
        self.assertFalse(result["liveness"]["fatal"])

    def test_the_poll_is_never_more_often_than_every_five_seconds(self):
        boot = MockedBoot(start(), {"info status": [b"VM status: running\r\n"]},
                          timeout=30)
        result, error, where = boot.run()
        gaps = [b - a for a, b in zip(boot.polls, boot.polls[1:])]
        self.assertGreaterEqual(len(gaps), 1)
        for gap in gaps:
            # The bound is the five seconds of the requirement itself, not the
            # constant of the module: a relaxed constant must fail here.
            self.assertGreaterEqual(gap, 5.0 - 1e-6)

    def test_the_poll_never_sends_anything_but_the_status_command(self):
        boot = MockedBoot(
            success_serial(),
            {"info status": [b"VM status: running\r\n(qemu) "]})
        result, error, where = boot.run()
        self.assertEqual(boot.monitor.commands(), ["info status", "quit"])

    def test_the_transport_never_resumes_a_paused_guest(self):
        source = Path(nt.__file__).read_text()
        for forbidden in ('b"cont"', "b'cont'", '"cont\\n"', "system_reset",
                          '"cont ', "cont\\r"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, source)
        self.assertEqual(nt.HMP_COMMAND, "info status")


class ArchivedRunEvidenceTests(unittest.TestCase):
    """The read-only reader of an archived A8 run.

    It turns a run directory into the facts the raw evidence holds, so a
    diagnosis is a measurement and not a story.
    """

    def batches(self, count, last_phase=None):
        lines = []
        for index in range(count):
            lines.append("NG_NOVA_BATCH_LOWER_BEGIN %d" % index)
            lines.append("NG_NOVA_BATCH_LOWER_END %d" % index)
            lines.append("NG_NOVA_BATCH_OBJECT_BEGIN %d" % index)
            lines.append("NG_NOVA_BATCH_OBJECT_END %d" % index)
        if last_phase == "LOWER":
            lines.append("NG_NOVA_BATCH_LOWER_BEGIN %d" % count)
        elif last_phase == "OBJECT":
            lines.append("NG_NOVA_BATCH_LOWER_BEGIN %d" % count)
            lines.append("NG_NOVA_BATCH_LOWER_END %d" % count)
            lines.append("NG_NOVA_BATCH_OBJECT_BEGIN %d" % count)
        return "\r\n".join(lines) + "\r\n"

    def test_the_completed_batches_are_counted(self):
        facts = ev.parse_serial(self.batches(16))
        self.assertEqual(facts["batches_completed"], 16)
        self.assertEqual(facts["last_completed_batch"], 15)
        self.assertIsNone(facts["stopped_in"])

    def test_a_stop_in_the_lower_phase_is_read(self):
        facts = ev.parse_serial(self.batches(16, "LOWER"))
        self.assertEqual(facts["batches_completed"], 16)
        self.assertEqual(facts["stopped_in"], "LOWER")
        self.assertEqual(facts["last_line"], "NG_NOVA_BATCH_LOWER_BEGIN 16")

    def test_a_stop_in_the_object_phase_is_read(self):
        facts = ev.parse_serial(self.batches(19, "OBJECT"))
        self.assertEqual(facts["batches_completed"], 19)
        self.assertEqual(facts["stopped_in"], "OBJECT")
        self.assertEqual(facts["last_line"], "NG_NOVA_BATCH_OBJECT_BEGIN 19")

    def test_the_terminal_marker_is_read(self):
        facts = ev.parse_serial(self.batches(2) + "NG_NV2_NATIVE_RUN_OK\r\n")
        self.assertEqual(facts["terminal_marker"], "NG_NV2_NATIVE_RUN_OK")
        self.assertEqual(facts["batches_completed"], 2)

    def test_an_empty_serial_reads_nothing(self):
        facts = ev.parse_serial("")
        self.assertEqual(facts["batches_completed"], 0)
        self.assertIsNone(facts["stopped_in"])
        self.assertIsNone(facts["terminal_marker"])
        self.assertEqual(facts["last_line"], "")

    def test_a_synthetic_run_directory_is_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            where = Path(tmp) / "20261021T170311Z-82584f32" / "producer"
            where.mkdir(parents=True)
            (where / "serial.log").write_text(self.batches(16, "LOWER"),
                                              encoding="utf-8")
            (where / "boot-result.json").write_text(json.dumps(dict(
                marker="NG_NV2_NATIVE_RUN_OK", marker_exact_once=False,
                firmware_return=False, exit_code=0, shutdown="hmp",
                forced=False, **{"pass": False})), encoding="utf-8")
            (where / "transport-result.json").write_text(json.dumps(dict(
                timeout=10800, failure="", runner_sha256="0" * 64,
                a8_selfhost_proven=False,
                ram=dict(polled=2135, tripped=False, poll_seconds=5.0))),
                encoding="utf-8")
            (where / "inputs.json").write_text(json.dumps([
                dict(esp="NOVACORE.EFI", bytes=10, sha256="ab" * 32)]),
                encoding="utf-8")
            facts = ev.read_run(where)
            self.assertTrue(facts["readable"])
            self.assertEqual(facts["serial"]["batches_completed"], 16)
            self.assertEqual(facts["serial"]["stopped_in"], "LOWER")
            self.assertFalse(facts["boot"]["pass_"])
            self.assertEqual(facts["transport"]["ram_polled"], 2135)
            self.assertEqual(facts["transport"]["ram_tripped"], False)
            self.assertEqual(facts["inputs"][0]["esp"], "NOVACORE.EFI")
            self.assertEqual(facts["wait"]["waited_seconds"], 2135 * 5.0)
            self.assertIn("guest_stopped_after_seconds", facts["wait"])

    def test_a_missing_directory_is_reported_not_raised(self):
        facts = ev.read_run(Path("/definitely-absent-12345"))
        self.assertFalse(facts["readable"])
        self.assertIn("error", facts)

    def test_the_reader_never_writes(self):
        source = Path(ev.__file__).read_text()
        for forbidden in ("open(", ".write_text", ".write_bytes", "shutil",
                          "os.remove", "unlink"):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, source)

    @unittest.skipUnless(TRIAL05_PRODUCER.is_dir(),
                         "the archived A8 evidence is not on this machine")
    def test_the_archived_trial05_run_says_what_the_diagnosis_says(self):
        facts = ev.read_run(TRIAL05_PRODUCER)
        self.assertTrue(facts["readable"])
        # The guest completed sixteen batches and stopped in the LOWER phase
        # of the seventeenth, with no terminal marker and no firmware return.
        self.assertEqual(facts["serial"]["batches_completed"], 16)
        self.assertEqual(facts["serial"]["stopped_in"], "LOWER")
        self.assertEqual(facts["serial"]["last_line"],
                         "NG_NOVA_BATCH_LOWER_BEGIN 16")
        self.assertIsNone(facts["serial"]["terminal_marker"])
        self.assertFalse(facts["boot"]["pass_"])
        self.assertFalse(facts["boot"]["firmware_return"])
        self.assertEqual(facts["boot"]["exit_code"], 0)
        self.assertEqual(facts["boot"]["shutdown"], "hmp")
        self.assertFalse(facts["boot"]["forced"])
        # The RAM guard never tripped, and the transport waited its whole
        # budget: the guest was gone long before the transport gave up.
        self.assertFalse(facts["transport"]["ram_tripped"])
        self.assertEqual(facts["transport"]["timeout"], 10800)
        self.assertGreater(facts["wait"]["dead_wait_seconds"], 3600)
        self.assertLess(facts["wait"]["guest_stopped_after_seconds"], 3600)

    @unittest.skipUnless(TRIAL03_PRODUCER.is_dir(),
                         "the archived A8 evidence is not on this machine")
    def test_the_earlier_run_was_still_working_when_its_deadline_hit(self):
        # The same reader on the run that reached nineteen batches: there,
        # the guest was still writing when the deadline arrived.
        facts = ev.read_run(TRIAL03_PRODUCER)
        self.assertEqual(facts["serial"]["batches_completed"], 19)
        self.assertEqual(facts["serial"]["stopped_in"], "OBJECT")
        self.assertLess(facts["wait"]["dead_wait_seconds"], 600)

    @unittest.skipUnless(TRIAL05_PRODUCER.is_dir(),
                         "the archived A8 evidence is not on this machine")
    def test_the_archived_run_used_the_watchdog_fixed_host(self):
        # The host of the failing run is the very image the watchdog proof
        # certified: the firmware watchdog was already neutralised there.
        facts = ev.read_run(TRIAL05_PRODUCER)
        digests = {item["esp"]: item["sha256"] for item in facts["inputs"]}
        self.assertEqual(digests["EFI/BOOT/BOOTX64.EFI"],
                         "9b3509ec28ca705fdaec2c95e2221d28d2f8793cb7fcc308986899c94b57dad2")
        proof = ARCHIVE_ROOT / "watchdog-20261021" / "result.json"
        if proof.is_file():
            self.assertEqual(json.loads(proof.read_text())["normal_host_sha256"],
                             digests["EFI/BOOT/BOOTX64.EFI"])


class PinDiscrepancyTests(unittest.TestCase):
    """The three pin discrepancies of the reorganized repository.

    They are preserved, not repaired: the brief says to preserve them rather
    than blindly update their digests. What is validated is WHY they stand.
    """

    def report(self):
        import a8_pin_discrepancies as pd
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = pd.main([])
        return code, json.loads(buffer.getvalue())

    def test_every_stale_pin_and_the_unpinned_header_are_named(self):
        code, report = self.report()
        # The discrepancies stand, so the tool says so and exits 1.
        self.assertEqual(code, 1)
        self.assertFalse(report["ok"])
        self.assertEqual(len(report["stale"]), 2)
        self.assertEqual(len(report["unpinned"]), 1)
        stale = {entry["path"]: entry for entry in report["stale"]}
        self.assertIn("compiler/c/nova/frontend/nova.c", stale)
        self.assertIn("compiler/c/nova/frontend/nova.h", stale)
        # The required header the snapshot names with a stale path.
        self.assertEqual(report["unpinned"][0]["header"],
                         "compiler/c/nova/analysis/seed_reachability.h")
        for entry in stale.values():
            self.assertNotEqual(entry["pinned"], entry["on_disk"])

    def test_the_pin_of_nova_h_designates_a_real_revision(self):
        _, report = self.report()
        entry = {e["path"]: e for e in report["stale"]}["compiler/c/nova/frontend/nova.h"]
        self.assertTrue(entry["history"]["found"])
        self.assertTrue(entry["history"]["revision"])

    def test_the_content_delta_is_paths_only(self):
        _, report = self.report()
        for entry in report["stale"]:
            if entry["verdict"] == "campaign copy not available":
                self.skipTest("the campaign tree is not on this machine")
            self.assertEqual(entry["verdict"], "paths-and-comments-only")
            self.assertEqual(entry["code_lines"], 0)
            self.assertGreater(entry["changed_lines"], 0)

    def test_the_tool_never_writes(self):
        import a8_pin_discrepancies as pd
        source = Path(pd.__file__).read_text()
        for forbidden in ("open(", "write_text", "write_bytes", "shutil",
                          "os.remove", "unlink", "subprocess.run([\"git\", \"-C\", str(ROOT), \"push\""):
            with self.subTest(token=forbidden):
                self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
