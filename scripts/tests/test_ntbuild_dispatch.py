#!/usr/bin/env python3
"""DISPATCH tests for scripts/ntbuild_house.sh, the house-build entrypoint.

These tests never build anything: no C, no QEMU, no transport, no manifest, no
real repository file is read or written, and the real interpreter is never
executed. The entrypoint is driven as a subprocess with a FAKE interpreter on
PATH, and the argv the fake received is read back from a log.

What is proved here, and what is not:
  * the entrypoint forwards the command and its flags in argv, spaces and
    shell metacharacters intact, and passes the repository as --repo;
  * NG_REPO is honoured by being PASSED, never interpolated into a command
    line, and the repository is otherwise resolved from the script own path;
  * a legacy command (corpus, census, clean) is REFUSED, and the refusal
    names the explicit `ntbuild_house.sh bootstrap ...` invocation that does it:
    there is no silent fallback to the legacy script;
  * an unknown command is refused and never forwarded - the house builder
    reads an unknown word as a PATH to build, so forwarding one would start a
    build;
  * `bootstrap` runs the preserved legacy script and nothing else;
  * a missing interpreter is a loud, non-zero failure, and it never becomes a
    run of the legacy script either.

This is NOT a proof of the house build: the house builder itself is mocked
here, so nothing here says anything about Nova sources, pins or QEMU.
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = HERE.parent
REPO = SCRIPTS.parent
# The house stage called the dispatcher scripts/ntbuild.sh and preserved the
# C bootstrap producer beside it as scripts/ntbuild_bootstrap.sh. In this
# repository the C bootstrap producer KEEPS the name scripts/ntbuild.sh, and
# the house-build entrypoint is scripts/ntbuild_house.sh.
ENTRY = SCRIPTS / "ntbuild_house.sh"
LEGACY = SCRIPTS / "ntbuild.sh"
HOUSE = SCRIPTS / "ntbuild_house.py"

REFUSE_EXIT = 78


def find_bash():
    """The bash that drives the entrypoint. None means these tests cannot run."""
    found = shutil.which("bash")
    if found:
        return found
    for candidate in (
        "/bin/bash",
        "/usr/bin/bash",
        "/usr/local/bin/bash",
        "/bin/sh",  # last resort: the entrypoint is POSIX-clean enough
    ):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


BASH = find_bash()

# The fake interpreter: it records the argv it was given, one element per
# line, and succeeds. It never runs a build.
FAKE_PYTHON = (
    "#!/bin/sh\n"
    "# A fake interpreter: it records the argv it was given, one element per\n"
    "# line, and succeeds. It never runs a build.\n"
    'if [ -z "${FAKE_ARGV_LOG:-}" ]; then\n'
    '  printf "FAKE_PYTHON: no log file named\\n" >&2\n'
    "  exit 9\n"
    "fi\n"
    ': >"$FAKE_ARGV_LOG"\n'
    'for arg in "$@"; do\n'
    "  printf '%s\\n' \"$arg\" >>\"$FAKE_ARGV_LOG\"\n"
    "done\n"
    'printf "FAKE_PYTHON argv=%s\\n" "$#"\n'
    "exit 0\n"
)


def same_path(left, right):
    """Compare two paths by their physical form, so a symlink is not a failure."""
    return os.path.realpath(str(left)) == os.path.realpath(str(right))


@unittest.skipUnless(
    BASH,
    "bash is required to drive the dispatch tests; without it this file proves nothing",
)
class DispatchTest(unittest.TestCase):
    """The entrypoint as a process: what it runs, what it refuses, what it forwards."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ntbuild-dispatch-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.empty_bin = self.root / "empty-bin"
        self.empty_bin.mkdir()
        self.fake = self.bin / "python3"
        self.fake.write_text(FAKE_PYTHON, encoding="utf-8")
        os.chmod(self.fake, 0o755)
        self.log = self.root / "argv.log"

    # -- helpers ------------------------------------------------------------

    def run_entry(self, args, env=None, cwd=None):
        environment = dict(os.environ)
        for name in ("NG_REPO", "NG_PYTHON", "NG_BUILD_SCRIPT"):
            environment.pop(name, None)
        environment["PATH"] = str(self.bin) + os.pathsep + environment.get("PATH", "")
        environment["FAKE_ARGV_LOG"] = str(self.log)
        if env:
            environment.update(env)
        return subprocess.run(
            [BASH, str(ENTRY)] + list(args),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=environment,
            cwd=str(cwd or REPO),
            timeout=120,
        )

    def recorded_argv(self):
        """The argv the fake interpreter received, or None when it never ran."""
        if not self.log.exists():
            return None
        text = self.log.read_text(encoding="utf-8")
        if not text:
            return []
        return text.split("\n")[:-1]

    def assert_builder_ran(self):
        argv = self.recorded_argv()
        self.assertIsNotNone(argv, "the house builder was never called")
        return argv

    # -- the house route ----------------------------------------------------

    def test_default_command_is_the_house_build(self):
        proc = self.run_entry([])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        argv = self.assert_builder_ran()
        self.assertTrue(same_path(argv[0], HOUSE), argv)
        self.assertIn("--repo", argv)
        self.assertTrue(same_path(argv[argv.index("--repo") + 1], REPO), argv)
        self.assertEqual(argv[-1], "build")

    def test_the_repository_is_resolved_from_the_scripts_own_path(self):
        elsewhere = self.root / "elsewhere"
        elsewhere.mkdir()
        proc = self.run_entry(["check", "x.nova"], cwd=elsewhere)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        argv = self.assert_builder_ran()
        self.assertTrue(same_path(argv[argv.index("--repo") + 1], REPO), argv)

    def test_command_and_flags_are_forwarded_in_argv(self):
        proc = self.run_entry(["check", "a path with spaces", "second one"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        argv = self.assert_builder_ran()
        self.assertIn("check", argv)
        self.assertIn("a path with spaces", argv)
        self.assertIn("second one", argv)
        # two arguments, not one argument with the two joined by a space
        self.assertNotIn("a path with spaces second one", argv)

    def test_house_options_after_the_command_are_forwarded(self):
        proc = self.run_entry(["build", "--timeout", "600"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        argv = self.assert_builder_ran()
        self.assertIn("--timeout", argv)
        self.assertEqual(argv[argv.index("--timeout") + 1], "600")

    def test_shell_metacharacters_are_not_interpreted(self):
        tricky = "a b;echo PWNED $(id) `id` * | & > <"
        proc = self.run_entry(["check", tricky])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        argv = self.assert_builder_ran()
        # one element, byte for byte: the house builder receives exactly
        # [builder, --repo, repo, check, tricky]
        self.assertEqual(len(argv), 5, argv)
        self.assertEqual(argv[-1], tricky)
        self.assertNotIn("PWNED", proc.stdout)

    def test_ng_repo_is_honoured_by_being_passed(self):
        shadow = self.root / "shadow repo with spaces"
        shadow.mkdir()
        proc = self.run_entry(["check", "x.nova"], env={"NG_REPO": str(shadow)})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        argv = self.assert_builder_ran()
        self.assertIn("--repo", argv)
        self.assertEqual(argv[argv.index("--repo") + 1], str(shadow))

    def test_ng_repo_that_is_not_a_directory_is_refused(self):
        proc = self.run_entry(["check", "x.nova"], env={"NG_REPO": str(self.root / "nope")})
        self.assertEqual(proc.returncode, REFUSE_EXIT, proc.stderr)
        self.assertIn("NG_REPO", proc.stderr)
        self.assertIsNone(self.recorded_argv(), "the builder ran with a bad NG_REPO")

    # -- no silent fallback -------------------------------------------------

    def test_legacy_commands_are_refused_and_name_the_bootstrap_invocation(self):
        for command in ("corpus", "census", "clean"):
            with self.subTest(command=command):
                if self.log.exists():
                    self.log.unlink()
                proc = self.run_entry([command])
                self.assertEqual(proc.returncode, REFUSE_EXIT, proc.stderr)
                self.assertIn("NTBUILD_REFUSED", proc.stderr)
                self.assertIn(command, proc.stderr)
                self.assertIn("ntbuild_house.sh bootstrap " + command, proc.stderr)
                # nothing ran: not the house builder, not the legacy script
                self.assertIsNone(self.recorded_argv(), "the house builder ran for a legacy command")
                self.assertEqual(proc.stdout, "", "the legacy script ran for a legacy command")

    def test_unknown_command_is_refused_and_never_forwarded(self):
        proc = self.run_entry(["frobnicate"])
        self.assertEqual(proc.returncode, REFUSE_EXIT, proc.stderr)
        self.assertIn("NTBUILD_REFUSED", proc.stderr)
        self.assertIn("frobnicate", proc.stderr)
        self.assertIsNone(self.recorded_argv(), "an unknown command reached the house builder")
        self.assertEqual(proc.stdout, "")

    def test_option_before_the_command_is_refused(self):
        proc = self.run_entry(["--repo", str(self.root)])
        self.assertEqual(proc.returncode, REFUSE_EXIT, proc.stderr)
        self.assertIn("NTBUILD_REFUSED", proc.stderr)
        self.assertIsNone(self.recorded_argv(), "an option before the command was forwarded")

    # -- the legacy route ----------------------------------------------------

    def test_bootstrap_runs_the_preserved_legacy_script(self):
        proc = self.run_entry(["bootstrap", "policy"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("NTBUILD-POLICY/1", proc.stdout)
        self.assertIsNone(self.recorded_argv(), "the house builder ran on the bootstrap route")

    def test_bootstrap_forwards_its_arguments_to_the_legacy_script(self):
        proc = self.run_entry(["bootstrap", "no-such-command"])
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("unknown command", proc.stderr)
        self.assertIsNone(self.recorded_argv(), "the house builder ran on the bootstrap route")

    def test_the_legacy_script_is_preserved_next_to_the_entrypoint(self):
        self.assertTrue(LEGACY.is_file(), "the preserved legacy script is missing")
        text = LEGACY.read_text(encoding="utf-8")
        self.assertIn("NTBUILD-POLICY/1", text)
        self.assertIn("RECORDED_EXAMPLES", text)
        self.assertIn("PINNED_INPUTS", text)

    # -- the interpreter -----------------------------------------------------

    def test_missing_interpreter_is_a_loud_failure_and_never_a_legacy_run(self):
        for command in (["policy"], ["check", "x.nova"]):
            with self.subTest(command=command):
                if self.log.exists():
                    self.log.unlink()
                proc = self.run_entry(command, env={"PATH": str(self.empty_bin)})
                self.assertNotEqual(proc.returncode, 0, "a missing interpreter was not a failure")
                self.assertEqual(proc.returncode, REFUSE_EXIT, proc.stderr)
                self.assertIn("python", proc.stderr)
                self.assertEqual(proc.stdout, "", "something ran without an interpreter")
                self.assertIsNone(self.recorded_argv())

    def test_help_is_the_entrypoints_own(self):
        proc = self.run_entry(["--help"])
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("ntbuild_house.sh", proc.stdout)
        self.assertIn("bootstrap", proc.stdout)
        self.assertIsNone(self.recorded_argv(), "--help reached the house builder")


if __name__ == "__main__":
    unittest.main()
