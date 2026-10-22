#!/usr/bin/env python3
"""nova_native_transport.py - the A8 transport.

It translates nothing: it copies bytes into an ESP, boots the S0 producer or
a Nova program under QEMU, reads the serial line, and extracts what the guest
wrote. The functions below (firmware return, negative causes, ESP building,
the boot and its HMP cleanup, the PE check) are the PROVEN ones, PROMOTED
here from the transport prototype. The prototype is left intact and is NOT
read at run time: this script is autonomous and needs nothing but the
canonical scripts, the pinned bootstrap and the house sources.

  --repo / --work-root   the evidence lands in <repo>/out/<work-root>/<name>
  --timeout 10..10800    the bound of the prototype, widened for big sources;
                         standalone default 240, house builder 10800
  a RAM guard             start >= 9 GiB free, stop < 8 GiB free, measured
                         before the boot and every 5s inside the boot loop; a
                         measurement that fails is a refusal
  an HMP liveness poll    a READ ONLY `info status` on the monitor, at most
                         every 5s while the boot waits for the proof: a guest
                         that is gone (`paused (shutdown)`, `paused (internal
                         error)`) fails the run at once, with the HMP
                         transcript kept and a clear reason, instead of
                         waiting for the timeout. The poll never resumes a
                         guest it did not pause. EXPERIMENTAL transport work
                         toward A8: it is NOT an A8 completion, and it is NOT
                         part of the normal build yet.
  a 512 MiB guest        QEMU runs the guest with 512M of RAM and 4 vCPUs; the
                         values are the named QEMU_MEMORY and QEMU_CPUS of this
                         script
  an other-QEMU check    a QEMU already running is reported and NEVER stopped
  --extract-file         a RAW extraction of one guest file, never an
                         attestation

The serialization of the runs belongs to the BUILDER, which holds the lock
around them. This file takes NO lock: taking the same one here would
deadlock against the builder that already holds it.

Exit codes: 0 the run passed, 1 the run happened and failed, 2 the run was
REFUSED (contract or environment) and nothing is claimed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import time

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_REPO = SCRIPT_DIR.parent

# The two pinned S0 producers: byte for byte the pins of the prototype.
PINS = {
    "compiler-host.NTASM1.EFI": "82826f458aff21d4f5167b296b56813899ea422caedb9d8fda2d8120a9b4882d",
    "compiler-core.NTASM1.EFI": "a02425be642b839586593b6b5468bc13f4f85d29a503987aa972e4750d1d428f",
}
DRIVER_REFUSAL_CODES = (970, 803, 1101, 1103)

TERMINAL_PATTERN = (
    r"(?m)^(NG_NV2_NATIVE_(?:TEST_OK|RUN_OK|BAD)|NG_NTASM_NATIVE_SCAN_OK|"
    r"NGS0 E[0-9]{3}[^\r\n]*)\r?$"
)
BOOT_START_PATTERN = r'(?m)^BdsDxe: starting (Boot[0-9A-Fa-f]{4}) "([^"\r\n]*)"[^\r\n]*\r?$'

TIMEOUT_MIN = 10
# The ceiling follows the builder's: a full build on TCG needs more than an
# hour (45 batches), so a transport that refused the budget its builder asks
# for would refuse the normal build. The STANDALONE default stays 240 (see
# build_parser): a short probe must still die quickly, and only the house
# builder widens the deadline.
TIMEOUT_MAX = 10800
RAM_START_MIN = 9 * 1024 ** 3
RAM_STOP_MAX = 8 * 1024 ** 3
RAM_POLL_SECONDS = 5.0

# The guest memory of the emulated machine. It is a CONTRACT value: the argv
# and the contract record always carry THIS one, never a literal of their
# own. 512M: the 256M guest failed the UEFI AllocatePool (nv_pool_bad).
QEMU_MEMORY = "512M"

# The number of vCPUs of the emulated machine. It is a CONTRACT value too: the
# argv and the contract/result records always carry THIS one, never a literal
# of their own. 4 vCPUs: the user authorized a 4-CPU guest.
# IMPORTANT: this does NOT parallelize anything. The emulated compiler and
# the producer remain strictly SEQUENTIAL (one job at a time, in the guest).
# Additional vCPUs are exposed as requested; no speedup is claimed.
QEMU_CPUS = 4

NAME_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,70}")
ESP_NAME_RE = re.compile(r"[A-Za-z0-9_.-]{1,31}")
POWERSHELL_REL = "Windows/System32/WindowsPowerShell/v1.0/powershell.exe"


class Refusal(Exception):
    """The contract or the environment forbids this run: nothing is claimed."""


class Failure(Exception):
    """The run happened and did not pass."""


# --------------------------------------------------------------------------
# The proven serial-text readers, promoted from the prototype
# --------------------------------------------------------------------------

def firmware_return(serial, marker_end):
    """Return fresh firmware evidence for the image started before the marker."""
    if not 0 < marker_end <= len(serial):
        return None
    starts = list(re.finditer(BOOT_START_PATTERN, serial[:marker_end]))
    if not starts:
        return None
    started = starts[-1]
    boot_id, image_name = started.group(1, 2)
    # Search only after the marker; an earlier return cannot prove this run.
    tail = serial[marker_end:]
    returned = re.search(
        r'(?m)^BdsDxe: failed to start ' + re.escape(boot_id) +
        r' "' + re.escape(image_name) + r'"[^\r\n]*\r?$', tail)
    if returned:
        return returned.group(0).rstrip("\r")
    # Preserve the existing UiApp return protocol, also strictly after marker.
    uiapp = re.search(r'(?m)^BdsDxe: loading Boot0000 "UiApp"[^\r\n]*\r?$', tail)
    return uiapp.group(0).rstrip("\r") if uiapp else None


def failure_report(serial, wanted_status, wanted_value, wanted_error):
    """Read one exact fresh host failure, with the saved pre-cleanup error."""
    terminals = list(re.finditer(TERMINAL_PATTERN, serial))
    if len(terminals) != 1 or terminals[0].group(1) != "NG_NV2_NATIVE_BAD":
        return None
    terminal = terminals[0]
    report = re.match(
        r"\r?\n([0-9a-f]{16})\r?\n([0-9a-f]{16})\r?\n([0-9a-f]{16})\r?\n",
        serial[terminal.end():])
    if not report:
        return None
    status, value, context_error = (int(x, 16) for x in report.groups())
    if (status, value, context_error) != (wanted_status, wanted_value, wanted_error):
        return None
    evidence = firmware_return(serial, terminal.end() + report.end())
    if not evidence:
        return None
    return dict(host_status=status, returned_value=value,
                context_error=context_error,
                context_error_captured_before_cleanup=True,
                firmware_evidence=evidence,
                terminal_start=terminal.start())


def exclusive_failure(serial):
    report = failure_report(serial, 2, 45, 8)
    if report:
        report["failed_assertion"] = report.pop("returned_value")
        report["cause"] = "exclusive-create assertion45"
    return report


def nova_runtime_failure(serial, wanted_error):
    if wanted_error not in (7, 9):
        return None
    report = failure_report(serial, 3, 0, wanted_error)
    if report:
        report["cause"] = "Nova ABI2 runtime rejection"
    return report


def native_driver_failure(serial, expected_code=None, expected_io=False):
    """Driver refusals need their exact tuple and this invocation's notice."""
    if expected_io:
        if expected_code is not None:
            return None
        report = failure_report(serial, 3, 0, 8)
        if report:
            prefix = serial[:report["terminal_start"]]
            starts = list(re.finditer(BOOT_START_PATTERN, prefix))
            if not starts or re.search(
                    r"(?m)^NG_NOVA_NATIVE_DRIVER_(?:OK|REFUSED)\r?$",
                    prefix[starts[-1].end():]):
                return None
            report["cause"] = "Nova native driver I/O error8"
        return report
    if expected_code not in DRIVER_REFUSAL_CODES:
        return None
    report = failure_report(serial, 3, expected_code, 0)
    if not report:
        return None
    prefix = serial[:report["terminal_start"]]
    starts = list(re.finditer(BOOT_START_PATTERN, prefix))
    notices = list(re.finditer(
        r"(?m)^NG_NOVA_NATIVE_DRIVER_REFUSED\r?\n([0-9]{1,20})\r?$", prefix))
    if not starts or len(notices) != 1 or notices[0].start() < starts[-1].end():
        return None
    if int(notices[0].group(1)) != expected_code:
        return None
    report["cause"] = "Nova native driver input refusal"
    report["driver_diagnostic_code"] = expected_code
    return report


def root_inventory_names(text):
    names = set()
    for line in text.splitlines():
        name = line.strip()
        if not name:
            continue
        if name.startswith("::/"):
            name = name[3:]
        name = name.rstrip("/")
        if not re.fullmatch(r"[A-Za-z0-9_.~-]+", name):
            raise RuntimeError("unrecognized root inventory row")
        names.add(name.upper())
    return names


def driver_output_matches(before, after):
    """None is proven absence; empty bytes mean a real empty file."""
    return before == after


# --------------------------------------------------------------------------
# The RAM guard
# --------------------------------------------------------------------------

def ram_decision(free_bytes, phase):
    """The one decision of the guard.

    phase "start": free RAM must be at least 9 GiB.
    phase "running": the run stops when free RAM falls under 8 GiB.
    """
    if phase == "start":
        return "allow" if free_bytes >= RAM_START_MIN else "refuse"
    if phase == "running":
        return "continue" if free_bytes >= RAM_STOP_MAX else "trip"
    raise ValueError("unknown phase: " + repr(phase))


def ram_pass(ram):
    """The guard alone decides the boot verdict."""
    return not ram.get("tripped") and not ram.get("measurement_failed")


def _under_wsl():
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text().lower()
    except OSError:
        return False
    return "microsoft" in release or "wsl" in release


def _powershell_path():
    """The known Windows PowerShell path, over every mounted drive."""
    candidates = [Path("/mnt/c/" + POWERSHELL_REL)]
    candidates += [Path("/mnt/%s/%s" % (letter, POWERSHELL_REL))
                   for letter in "cdefghijklmnopqrstuvwxyz"]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return None


def _measure_windows():
    """Free physical memory of the Windows host, in bytes."""
    exe = _powershell_path()
    if exe is None:
        raise Refusal("cannot measure RAM: no powershell.exe under "
                      "/mnt/*/Windows/System32/WindowsPowerShell/v1.0")
    script = ("$os = Get-CimInstance Win32_OperatingSystem; "
              "Write-Output $os.FreePhysicalMemory")
    try:
        proc = subprocess.run([str(exe), "-NoProfile", "-NonInteractive",
                               "-Command", script],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal("cannot measure RAM: powershell failed (%s)" % exc)
    text = proc.stdout.decode("utf-8", "replace").strip()
    try:
        kib = int(text)
    except ValueError:
        raise Refusal("cannot measure RAM: powershell returned " +
                      repr(text[:120]))
    return kib * 1024


def _measure_proc():
    """Free physical memory of this kernel, in bytes."""
    try:
        text = Path("/proc/meminfo").read_text()
    except OSError as exc:
        raise Refusal("cannot measure RAM: /proc/meminfo unreadable (%s)" % exc)
    fields = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        parts = rest.split()
        if parts and parts[0].isdigit():
            fields[key] = int(parts[0]) * 1024
    for key in ("MemAvailable", "MemFree"):
        if key in fields:
            return fields[key]
    raise Refusal("cannot measure RAM: no MemAvailable/MemFree in /proc/meminfo")


def measure_free_memory():
    """Free physical memory in bytes, or a refusal when it cannot be measured.

    Under WSL the guest sees the Linux memory, not the Windows memory QEMU
    actually uses, so the Windows host is measured through PowerShell CIM.
    """
    if _under_wsl():
        return _measure_windows()
    return _measure_proc()


def require_ram_start(free_bytes=None):
    """Measure (or take) the free RAM and refuse below the start threshold."""
    if free_bytes is None:
        free_bytes = measure_free_memory()
    if ram_decision(free_bytes, "start") != "allow":
        raise Refusal("free RAM %d bytes is under the start threshold %d bytes"
                      % (free_bytes, RAM_START_MIN))
    return free_bytes


# --------------------------------------------------------------------------
# The other QEMU instances: reported, never stopped
# --------------------------------------------------------------------------

def other_qemu_pids(proc_root=Path("/proc")):
    """The Linux qemu processes already running. READ ONLY: never signalled."""
    if not proc_root.is_dir():
        raise Refusal("cannot verify the other QEMU instances: " +
                      str(proc_root) + " is absent")
    pids = []
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text(errors="replace").strip()
        except OSError:
            continue
        try:
            argv = (entry / "cmdline").read_bytes().split(b"\0")[0]
        except OSError:
            argv = b""
        program = os.path.basename(argv.decode("utf-8", "replace"))
        if comm.startswith("qemu-system") or program.startswith("qemu-system"):
            pids.append(int(entry.name))
    return sorted(pids)


def other_windows_qemu_pids():
    """The Windows-side qemu processes, under WSL. READ ONLY: nothing stopped."""
    exe = _powershell_path()
    if exe is None:
        raise Refusal("cannot verify the other QEMU instances: no "
                      "powershell.exe under "
                      "/mnt/*/Windows/System32/WindowsPowerShell/v1.0")
    script = ("Get-CimInstance Win32_Process | "
              "Where-Object { $_.Name -like 'qemu-system*' } | "
              "ForEach-Object { $_.ProcessId }")
    try:
        proc = subprocess.run([str(exe), "-NoProfile", "-NonInteractive",
                               "-Command", script],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal("cannot verify the other QEMU instances: powershell "
                      "failed (%s)" % exc)
    if proc.returncode:
        raise Refusal("cannot verify the other QEMU instances: powershell "
                      "returned rc=" + str(proc.returncode))
    pids = []
    for line in proc.stdout.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.isdigit():
            pids.append(int(line))
    return sorted(pids)


def foreign_qemu_pids():
    """Every qemu already running: the Linux ones, and the Windows ones too."""
    pids = list(other_qemu_pids())
    if _under_wsl():
        pids += other_windows_qemu_pids()
    return sorted(set(pids))


# --------------------------------------------------------------------------
# The proven ESP, boot and PE work, promoted from the prototype
# --------------------------------------------------------------------------

def digest(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def run(args, where, label):
    with (where / (label + ".command.json")).open("x") as f:
        json.dump([str(x) for x in args], f)
    p = subprocess.run([str(x) for x in args], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, check=False, timeout=60)
    (where / (label + ".log")).write_bytes(p.stdout)
    if p.returncode:
        raise RuntimeError(label + " failed, rc=" + str(p.returncode))
    return p.stdout


def mcopy(image, source, dest, where, label):
    return run(["mcopy", "-i", image, source, dest], where, label)


def create_esp(where, payloads, args):
    image = where / "esp.img"
    with image.open("xb") as f:
        f.truncate(32 * 1024 * 1024)
    run(["mkfs.vfat", "-F", "16", "-n", "NVRUNTIME", image], where, "mkfs")
    run(["mmd", "-i", image, "::/EFI"], where, "mkdir-efi")
    run(["mmd", "-i", image, "::/EFI/BOOT"], where, "mkdir-boot")
    manifest = []
    for i, (native, name) in enumerate(payloads):
        native = Path(native).resolve(strict=True)
        mcopy(image, native, "::/" + name, where, "copy-" + str(i))
        check = where / ("readback-" + str(i) + ".bin")
        mcopy(image, "::/" + name, check, where, "readback-" + str(i))
        if check.read_bytes() != native.read_bytes():
            raise RuntimeError("ESP payload readback differs: " + name)
        manifest.append(dict(path=str(native), esp=name, bytes=native.stat().st_size,
                             sha256=digest(native)))
    shutil.copyfile(args.vars, where / "vars.fd")
    (where / "inputs.json").write_text(json.dumps(manifest, indent=2))
    run(["mdir", "-i", image, "::/"], where, "inventory")
    return image


def hmp_quit(port, where):
    transcript = b""
    with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
        s.settimeout(1)
        try:
            transcript += s.recv(65536)
        except socket.timeout:
            pass
        s.sendall(b"quit\n")
        for _ in range(10):
            try:
                piece = s.recv(65536)
                if not piece:
                    break
                transcript += piece
            except socket.timeout:
                continue
    (where / "hmp.log").write_bytes(transcript)


# --------------------------------------------------------------------------
# The HMP liveness poll: READ ONLY, bounded, and never a resume
# --------------------------------------------------------------------------

# The one and only command the poll sends. It READS the state of the VM and
# changes nothing: the transport never resumes a guest it did not pause, and
# never resets it either.
HMP_COMMAND = "info status"

# The cadence of the poll. The bound is the RAM guard's: no more often than
# every five seconds, so the monitor is never hammered and never delays the
# guest.
HMP_POLL_SECONDS = 5.0

# The bounded exchange: a connect, a read timeout, a total query bound and a
# read count. The whole query is finished in HMP_QUERY_TIMEOUT seconds at the
# worst, so the boot loop can never block on the monitor.
HMP_CONNECT_TIMEOUT = 2.0
HMP_READ_TIMEOUT = 1.0
HMP_QUERY_TIMEOUT = 5.0
HMP_MAX_READS = 32

# The benign states. `prelaunch` is the transient state of a QEMU whose guest
# has not started yet: it is NOT a failure, and it is never resumed either.
HMP_BENIGN_REASONS = ("prelaunch",)

# The ANSI escape sequences of the HMP prompt and of the echoes.
ANSI_RE = re.compile(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|[@-Z\\-_])")

# The one line that carries the state. The echo of the command and the prompt
# are ignored: only a `VM status:` line counts.
VM_STATUS_RE = re.compile(r"VM status:[ \t]*(.+?)[ \t\r]*$", re.MULTILINE)


def strip_ansi(text):
    """Remove the ANSI escape sequences of the HMP prompt and of the echoes."""
    return ANSI_RE.sub("", text)


def parse_vm_status(text):
    """The VM status of an HMP transcript, as (state, reason).

    The state is `running` or `paused`, and the reason is what QEMU puts in
    parentheses (`shutdown`, `internal error`, `prelaunch`...). None when the
    transcript carries no parsable status at all.
    """
    if not text:
        return None
    match = VM_STATUS_RE.search(strip_ansi(text))
    if not match:
        return None
    value = match.group(1).strip().lower()
    if value == "running":
        return ("running", None)
    if value.startswith("paused") and value.endswith(")") and "(" in value:
        reason = value[value.index("(") + 1:-1].strip()
        return ("paused", reason or None)
    return None


def hmp_state_text(state, reason):
    """The state of the VM, as QEMU prints it."""
    if state == "paused" and reason:
        return "paused (" + reason + ")"
    return state or "unknown"


def hmp_state_is_fatal(state, reason):
    """True when the guest is in a state it cannot come back from.

    `running` is fine and `prelaunch` is the transient state of a QEMU whose
    guest has not started yet. Every other state - `paused (shutdown)`,
    `paused (internal error)` and the rest - means the guest is gone, and the
    transport must fail the run instead of waiting for its timeout.
    """
    if state == "running":
        return False
    if state == "paused" and reason in HMP_BENIGN_REASONS:
        return False
    return True


def hmp_query(port, command=HMP_COMMAND, connect_timeout=HMP_CONNECT_TIMEOUT,
              read_timeout=HMP_READ_TIMEOUT, query_timeout=HMP_QUERY_TIMEOUT,
              max_reads=HMP_MAX_READS):
    """One bounded, read-only HMP query.

    Returns (transcript, error). The transcript is what the monitor said, its
    ANSI escapes and its echo included, so it can be kept as a diagnostic. The
    error is None when the exchange completed, and a short reason otherwise.

    The function never blocks longer than the connect bound plus the query
    bound, and it never sends anything but `command`.
    """
    try:
        sock = socket.create_connection(("127.0.0.1", port),
                                        timeout=connect_timeout)
    except OSError as exc:
        return "", "the monitor is unavailable: " + str(exc)
    transcript = ""
    try:
        sock.settimeout(read_timeout)
        deadline = time.monotonic() + query_timeout
        # The banner and the first prompt. One bounded read: the monitor may
        # still be starting, and the answer is what matters.
        try:
            transcript += sock.recv(65536).decode("utf-8", "replace")
        except socket.timeout:
            pass
        except OSError as exc:
            return transcript, "the monitor read failed: " + str(exc)
        # The command, and only this command.
        try:
            sock.sendall(command.encode("ascii") + b"\n")
        except OSError as exc:
            return transcript, "the monitor write failed: " + str(exc)
        # The answer, in as many pieces as it comes: a partial read is a
        # partial answer, and a disconnection ends the exchange.
        for _ in range(max_reads):
            if time.monotonic() >= deadline:
                break
            try:
                piece = sock.recv(65536)
            except socket.timeout:
                break
            except OSError as exc:
                return transcript, "the monitor read failed: " + str(exc)
            if not piece:
                break
            transcript += piece.decode("utf-8", "replace")
            if parse_vm_status(transcript):
                break
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return transcript, None


def hmp_liveness(port, command=HMP_COMMAND):
    """One liveness observation of the guest. READ ONLY, and it never raises.

    The observation says how the exchange went (`ok`, `malformed` or
    `unavailable`), what state the VM was in, the transcript to keep as a
    diagnostic, and whether that state is fatal.
    """
    transcript, error = hmp_query(port, command=command)
    observation = dict(outcome="", state="", reason="", error=error or "",
                       transcript=transcript, fatal=False)
    parsed = parse_vm_status(transcript)
    if parsed is not None:
        state, reason = parsed
        observation["outcome"] = "ok"
        observation["state"] = state
        observation["reason"] = reason or ""
        observation["fatal"] = hmp_state_is_fatal(state, reason)
    elif error:
        observation["outcome"] = "unavailable"
    else:
        observation["outcome"] = "malformed"
    return observation


def liveness_pass(liveness):
    """A guest that is gone fails the run, whatever the serial log says.

    This is the veto: the success markers of the serial log cannot make the
    proof true when the VM is not running any more.
    """
    return not liveness.get("fatal")


def append_liveness_log(where, index, transcript):
    """Keep the HMP transcript of one poll, as a diagnostic."""
    with (where / "hmp-liveness.log").open("a", encoding="utf-8",
                                           errors="replace") as f:
        f.write("--- poll %d ---\n%s\n" % (index, transcript))


def boot(where, image, marker, args, expect_bad=False, marker_checks=None,
         expected_runtime_error=None, expected_driver_code=None,
         expected_driver_io=False):
    """One boot. The marker, the firmware return, the HMP quit and the unique
    owned PID are the prototype's own controls; the RAM guard rides in the
    same loop and decides the verdict on its own.

    The HMP liveness poll rides in the same loop too: while the transport
    waits for the proof, it asks the monitor for the state of the VM, at most
    every five seconds. A guest that is gone - `paused (shutdown)`, `paused
    (internal error)` - fails the run at once, with the HMP transcript kept
    and a clear reason, instead of waiting for the timeout. The poll is READ
    ONLY: it never resumes the guest.
    """
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    serial_path = where / "serial.log"
    command = [
        args.qemu, "-machine", "q35,accel=tcg", "-cpu", "max", "-m", QEMU_MEMORY,
        "-smp", str(QEMU_CPUS),
        "-drive", "if=pflash,format=raw,unit=0,readonly=on,file=" + str(Path(args.code).resolve()),
        "-drive", "if=pflash,format=raw,unit=1,file=" + str(where / "vars.fd"),
        "-drive", "if=virtio,format=raw,file=" + str(image),
        "-boot", "order=c,menu=off", "-nic", "none", "-display", "none",
        "-monitor", "tcp:127.0.0.1:" + str(port) + ",server=on,wait=off",
        "-serial", "file:" + str(serial_path), "-d", "guest_errors",
        "-D", str(where / "qemu.log"), "-no-reboot", "-no-shutdown"]
    # Before the boot: a measurement that fails, or a machine under the start
    # threshold, refuses the run and no QEMU is started at all.
    ram = dict(start_free=require_ram_start(), last_free=None, polled=0,
               tripped=False, measurement_failed=False, reason="")
    liveness = dict(polled=0, unavailable=0, malformed=0, fatal=False,
                    state="", reason="", detail="", transcript="")
    (where / "qemu.command.json").write_text(json.dumps(command, indent=2))
    ready = False
    firmware_evidence = ""
    forced = False
    p = None
    shutdown = "not-started"
    serial = ""
    with (where / "qemu.stdout").open("xb") as out, (where / "qemu.stderr").open("xb") as err:
        try:
            p = subprocess.Popen(command, stdout=out, stderr=err)
            (where / "qemu.pid").write_text(str(p.pid))
            deadline = time.monotonic() + args.timeout
            next_ram = time.monotonic()
            next_hmp = time.monotonic()
            while time.monotonic() < deadline and p.poll() is None:
                now = time.monotonic()
                if now >= next_ram:
                    next_ram = now + RAM_POLL_SECONDS
                    ram["polled"] += 1
                    try:
                        free = measure_free_memory()
                    except Refusal as exc:
                        ram["measurement_failed"] = True
                        ram["reason"] = "RAM measurement failed: " + str(exc)
                        break
                    ram["last_free"] = free
                    if ram_decision(free, "running") == "trip":
                        ram["tripped"] = True
                        ram["reason"] = ("free RAM %d bytes fell under the stop "
                                         "threshold %d bytes" % (free, RAM_STOP_MAX))
                        break
                # The serial evidence of this instant. It is read BEFORE the
                # liveness poll, so a guest that dies in the very instant it
                # proved itself still fails the run its own serial log would
                # have proved.
                success = False
                if serial_path.exists():
                    serial = serial_path.read_text(errors="replace")
                    terminal = re.search(TERMINAL_PATTERN, serial)
                    if terminal:
                        firmware_evidence = firmware_return(serial, terminal.end()) or ""
                        if firmware_evidence:
                            ready = True
                            success = True
                # The liveness poll, when it is due. It is bounded, read only,
                # and it never resumes a guest it did not pause.
                if now >= next_hmp:
                    next_hmp = now + HMP_POLL_SECONDS
                    liveness["polled"] += 1
                    observation = hmp_liveness(port)
                    if observation["transcript"]:
                        liveness["transcript"] = observation["transcript"]
                        append_liveness_log(where, liveness["polled"],
                                             observation["transcript"])
                    if observation["outcome"] == "ok":
                        liveness["state"] = observation["state"]
                        liveness["reason"] = observation["reason"]
                    elif observation["outcome"] == "malformed":
                        liveness["malformed"] += 1
                    else:
                        liveness["unavailable"] += 1
                    if observation["fatal"]:
                        liveness["fatal"] = True
                        liveness["detail"] = (
                            "the monitor reported VM status: " +
                            hmp_state_text(observation["state"],
                                           observation["reason"]))
                        break
                if success:
                    break
                time.sleep(.1)
        finally:
            if p is not None and p.poll() is None:
                try:
                    hmp_quit(port, where)
                    shutdown = "hmp"
                    p.wait(timeout=10)
                except Exception as exc:
                    (where / "shutdown-error.txt").write_text(str(exc))
                    shutdown = "terminate-own-pid"
                    forced = True
                    p.terminate()
                    try:
                        p.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        p.kill()
                        p.wait(timeout=5)
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    lines = [line.strip("\r") for line in serial.splitlines()]
    exact = lines.count(marker) == 1
    bad_found = "NG_NV2_NATIVE_BAD" in lines or any(x.startswith("NGS0 E") for x in lines)
    checks_ok = True
    if marker_checks is not None:
        checks_ok = bool(re.search(re.escape(marker) + r"\r?\n" +
                                   format(marker_checks, "016x") + r"\r?\n", serial))
    negative_cause = (native_driver_failure(serial, expected_driver_code, expected_driver_io)
                      if expected_driver_code is not None or expected_driver_io else
                      nova_runtime_failure(serial, expected_runtime_error)
                      if expected_runtime_error is not None else
                      exclusive_failure(serial) if expect_bad else None)
    negative_cause_ok = not expect_bad or negative_cause is not None
    result = dict(marker=marker, marker_exact_once=exact, firmware_return=ready,
                  firmware_evidence=firmware_evidence,
                  exit_code=p.returncode if p else None, shutdown=shutdown,
                  forced=forced, bad_marker=bad_found, checks_ok=checks_ok,
                  negative_cause_ok=negative_cause_ok, negative_cause=negative_cause,
                  ram=ram, liveness=liveness)
    result["pass"] = bool(exact and ready and not forced and shutdown == "hmp"
                          and p.returncode == 0 and checks_ok and negative_cause_ok
                          and (expect_bad or not bad_found) and ram_pass(ram)
                          and liveness_pass(liveness))
    if liveness["fatal"]:
        result["failure_reason"] = (
            liveness["detail"] + "; the guest VM is gone and the serial log "
            "cannot make the proof true")
    else:
        result["failure_reason"] = "the boot did not satisfy the proof"
    (where / "boot-result.json").write_text(json.dumps(result, indent=2))
    if ram["measurement_failed"]:
        raise Refusal(ram["reason"])
    if not result["pass"]:
        raise RuntimeError("boot failed: " + result["failure_reason"] +
                           "; inspect " + str(where / "boot-result.json"))
    return ram


def pe_check(path):
    b = path.read_bytes()
    if len(b) < 1024 or b[:2] != b"MZ":
        raise RuntimeError("not a PE")
    pe = struct.unpack_from("<I", b, 60)[0]
    if pe > len(b) - 264 or b[pe:pe+4] != b"PE\0\0":
        raise RuntimeError("bad PE signature")
    machine, sections, stamp = struct.unpack_from("<HHI", b, pe+4)
    if (machine, sections, stamp) != (0x8664, 4, 0):
        raise RuntimeError("not canonical S0 PE")
    opt = pe+24
    magic = struct.unpack_from("<H", b, opt)[0]
    subsystem = struct.unpack_from("<H", b, opt+68)[0]
    entry = struct.unpack_from("<I", b, opt+16)[0]
    image_size = struct.unpack_from("<I", b, opt+56)[0]
    if magic != 0x20b or subsystem != 10 or not 0 < entry < image_size:
        raise RuntimeError("bad S0 PE optional header")
    if len(b) > 65536:
        raise RuntimeError("S0 output exceeds64KiB")


# --------------------------------------------------------------------------
# Paths and names
# --------------------------------------------------------------------------

def resolve_repo(repo_arg):
    """The repository root: the parent of the scripts folder by default."""
    root = Path(repo_arg).resolve() if repo_arg else DEFAULT_REPO
    if not root.is_dir():
        raise Refusal("repository root is not a directory: " + str(root))
    return root


def resolve_work_root(repo, work_root_arg):
    """The work root, which must resolve under <repo>/out.

    A relative work root is taken against the repository root, so the caller
    never has to know where it stands.
    """
    out = (repo / "out").resolve()
    if work_root_arg is None:
        return out
    raw = Path(work_root_arg)
    where = raw.resolve() if raw.is_absolute() else (repo / raw).resolve()
    if where != out and out not in where.parents:
        raise Refusal("work-root must resolve under " + str(out) +
                      ", not " + str(where))
    return where


def check_name(name):
    """One fresh evidence name, and never one that was used before."""
    if not isinstance(name, str) or not NAME_RE.fullmatch(name):
        raise Refusal("invalid fresh evidence name: " + repr(name))
    return name


def refuse_reuse(where):
    """Evidence is never reused: an existing directory is refused."""
    if where.exists():
        raise Refusal("refusing to reuse existing evidence: " + str(where))
    return where


def check_timeout(seconds):
    if isinstance(seconds, bool) or not isinstance(seconds, int):
        raise Refusal("timeout must be an integer number of seconds")
    if not TIMEOUT_MIN <= seconds <= TIMEOUT_MAX:
        raise Refusal("timeout must be %d..%ds, got %d" %
                      (TIMEOUT_MIN, TIMEOUT_MAX, seconds))
    return seconds


def safe_root_name(name):
    """One safe root filename: no path separator, and not a dot name."""
    if not isinstance(name, str) or not ESP_NAME_RE.fullmatch(name):
        return False
    if name in (".", ".."):
        return False
    return name.strip(".") != ""


def extract_file_name(esp_name):
    """The local name of a raw extraction: extracted-<ESP name>."""
    if not safe_root_name(esp_name):
        raise Refusal("extraction target must have one safe root filename: " +
                      repr(esp_name))
    return "extracted-" + esp_name


def check_esp_names(payloads, extracts=()):
    """Unsafe names and collisions are refused before anything is written."""
    taken = set()
    for _, name in payloads:
        if "/" in name:
            continue
        if not safe_root_name(name):
            raise Refusal("ESP name must have one safe root filename: " +
                          repr(name))
        key = name.upper()
        if key in taken:
            raise Refusal("ESP name collision: " + name)
        taken.add(key)
    seen = set()
    for name in extracts:
        if not safe_root_name(name):
            raise Refusal("extraction target must have one safe root filename: " +
                          repr(name))
        key = name.upper()
        if key in taken:
            raise Refusal("extraction target collides with an ESP name: " + name)
        if key in seen:
            raise Refusal("extraction target named twice: " + name)
        seen.add(key)


def plan(args):
    """The ESP root names and the extraction targets of a `run`."""
    if args.mode != "run":
        return [], []
    payloads = [(args.host, "EFI/BOOT/BOOTX64.EFI"),
                (args.runtime, "NVRUNTIME.EFI"),
                (args.core, "NOVACORE.EFI")]
    for item in args.payload:
        name, _, local = item.partition("=")
        if not name or not local:
            raise Refusal("payload must be ESP_NAME=local_path: " + repr(item))
        payloads.append((Path(local), name))
    check_esp_names(payloads, args.extract_file)
    return payloads, list(args.extract_file)


# --------------------------------------------------------------------------
# The records
# --------------------------------------------------------------------------

def extraction_record(name, path, data):
    """One raw extraction. It is NOT an attestation of anything."""
    return dict(esp_name=name, path=str(path), bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                attestation=False,
                statement="raw extraction of a guest file; it is NOT an attestation")


def ram_record(ram):
    """The RAM facts, computed."""
    ram = ram or {}
    return dict(start_min=RAM_START_MIN, stop_max=RAM_STOP_MAX,
                poll_seconds=RAM_POLL_SECONDS,
                start_free=ram.get("start_free"), last_free=ram.get("last_free"),
                polled=ram.get("polled", 0),
                tripped=bool(ram.get("tripped")),
                measurement_failed=bool(ram.get("measurement_failed")),
                reason=ram.get("reason", ""))


def complete_record(ok, mode, ram=None):
    """The COMPLETE.json of this transport: computed, and never an A8 claim."""
    return dict(pass_=bool(ok), mode=mode,
                transport_invokes_foreign_compiler=False,
                core_producer_attested_by_transport=False if mode == "run" else None,
                a8_selfhost_proven=False,
                ram=ram_record(ram))


def write_complete(where, mode, ram):
    (where / "COMPLETE.json").write_text(
        json.dumps(complete_record(True, mode, ram), indent=2))


def read_ram(where):
    """The RAM facts the boot recorded, computed in boot-result.json."""
    try:
        result = json.loads((where / "boot-result.json").read_text())
    except (OSError, ValueError):
        return {}
    return result.get("ram") or {}


def write_transport_result(where, args, repo, work_root, ram, failure):
    """What this run did, computed. Written whether the run passed or not."""
    record = dict(pass_=failure is None, mode=args.mode, name=args.name,
                  where=str(where), repo=str(repo), work_root=str(work_root),
                  timeout=args.timeout,
                  failure="" if failure is None else str(failure),
                  runner_path=str(Path(__file__).resolve()),
                  runner_sha256=digest(Path(__file__).resolve()),
                  qemu=args.qemu, qemu_memory=QEMU_MEMORY, qemu_smp=QEMU_CPUS,
                  code=str(args.code), vars=str(args.vars),
                  pins=PINS, ram=ram_record(ram), a8_selfhost_proven=False)
    (where / "transport-result.json").write_text(json.dumps(record, indent=2))


def record_workspace(where, args, repo, work_root):
    (where / "runner-sha256.txt").write_text(digest(Path(__file__).resolve()))
    (where / "transport-contract.json").write_text(json.dumps(dict(
        runner_path=str(Path(__file__).resolve()),
        runner_sha256=digest(Path(__file__).resolve()),
        repo=str(repo), work_root=str(work_root), name=args.name,
        timeout=args.timeout, timeout_bounds=[TIMEOUT_MIN, TIMEOUT_MAX],
        pins=PINS, qemu=args.qemu, code=str(args.code), vars=str(args.vars),
        qemu_memory=QEMU_MEMORY, qemu_smp=QEMU_CPUS, qemu_network="none", qemu_display="none",
        ram_start_min=RAM_START_MIN, ram_stop_max=RAM_STOP_MAX,
        ram_poll_seconds=RAM_POLL_SECONDS,
        hmp_poll_seconds=HMP_POLL_SECONDS, hmp_command=HMP_COMMAND,
        hmp_read_only=True, hmp_max_query_seconds=HMP_QUERY_TIMEOUT,
        hmp_resumes_guest=False,
        serialization="the builder holds the lock; this transport takes none",
    ), indent=2))


# --------------------------------------------------------------------------
# The modes
# --------------------------------------------------------------------------

def run_assemble(args, repo, where):
    """Assemble one source with the S0 producer, on QEMU. Nothing is translated."""
    s0 = repo / "bootstrap/ntasm-s0/fixed-point"
    material = args.source.read_bytes()
    if args.test_entry:
        if material.count(b"entry h_start\n") != 1:
            raise Refusal("test entry replacement must be unique")
        material = material.replace(b"entry h_start\n", b"entry h_test_entry\n", 1)
    if not 0 < len(material) < 65536 or not material.endswith(b"\n"):
        raise Refusal("source outside S0 limits")
    source = where / "source.ntasm"
    source.write_bytes(material)
    payloads = [(s0 / "compiler-host.NTASM1.EFI", "EFI/BOOT/BOOTX64.EFI"),
                (s0 / "compiler-core.NTASM1.EFI", "NTCORE.EFI"),
                (source, "NTASM1.NTASM")]
    image = create_esp(where, payloads, args)
    ram = boot(where, image, "NG_NTASM_NATIVE_SCAN_OK", args)
    output = where / "produced.EFI"
    mcopy(image, "::/NTASM1.EFI", output, where, "extract-produced")
    pe_check(output)
    (where / "artifact.json").write_text(json.dumps(dict(
        source=str(args.source.resolve()), source_sha256=digest(source),
        output=str(output), bytes=output.stat().st_size,
        sha256=digest(output), producer=PINS,
        scope="S0-native-assembly-only"), indent=2))
    return ram


def run_selftest(args, where):
    """The runtime selftest of the prototype, unchanged."""
    payloads = [(args.host, "EFI/BOOT/BOOTX64.EFI"),
                (args.runtime, "NVRUNTIME.EFI")]
    if args.red_existing:
        existing = where / "existing.bin"
        existing.write_bytes(b"UNCHANGED")
        payloads.append((existing, "NVROUND.BIN"))
    image = create_esp(where, payloads, args)
    marker = "NG_NV2_NATIVE_BAD" if args.red_existing else "NG_NV2_NATIVE_TEST_OK"
    ram = boot(where, image, marker, args, expect_bad=args.red_existing,
               marker_checks=None if args.red_existing else 77)
    output = where / "NVROUND.BIN"
    mcopy(image, "::/NVROUND.BIN", output, where, "extract-roundtrip")
    expected = b"UNCHANGED" if args.red_existing else b"0123456789abcdef"
    if output.read_bytes() != expected:
        raise Failure("roundtrip/exclusive-create file bytes differ")
    if not args.red_existing:
        log = (where / "serial.log").read_bytes()
        if log.count(b"NG_NV2_DIAG_OK\r\n") != 1:
            raise Failure("runtime diag bytes missing/duplicated")
    (where / "output-check.json").write_text(json.dumps(dict(
        pass_=True, sha256=digest(output),
        expected_hex=expected.hex()), indent=2))
    return ram


def extract_files(where, image, extracts):
    """RAW extraction of the requested guest files. Never an attestation."""
    records = []
    for name in extracts:
        local = where / extract_file_name(name)
        mcopy(image, "::/" + name, local, where, "extract-" + name)
        records.append(extraction_record(name, local, local.read_bytes()))
    (where / "extraction.json").write_text(json.dumps(dict(
        attestation=False,
        statement="raw extraction of guest files; it is NOT an attestation of "
                  "anything, and it proves nothing about the producer",
        files=records), indent=2))
    return records


def run_production(args, where, payloads, extracts):
    """Run a real Nova program on the native runtime."""
    image = create_esp(where, payloads, args)
    driver_control = (args.expect_driver_code is not None or
                      args.expect_driver_io)
    original_driver_output = None
    if driver_control:
        for index, (_, name) in enumerate(payloads):
            if name.upper() == "OUTPUT.EFI":
                original_driver_output = (
                    where / ("readback-" + str(index) + ".bin")).read_bytes()
                break
    expected_error = args.expect_error or None
    expected_bad = bool(expected_error) or driver_control
    ram = boot(where, image,
               "NG_NV2_NATIVE_BAD" if expected_bad else "NG_NV2_NATIVE_RUN_OK",
               args, expect_bad=expected_bad,
               expected_runtime_error=expected_error,
               expected_driver_code=args.expect_driver_code,
               expected_driver_io=args.expect_driver_io)
    file_results = []
    for index, item in enumerate(args.expect_file):
        name, separator, expected_hex = item.partition("=")
        if not separator or not name:
            raise Refusal("expected output must be NAME=hex_bytes: " + repr(item))
        try:
            expected_bytes = bytes.fromhex(expected_hex)
        except ValueError:
            raise Refusal("expected output must be NAME=hex_bytes: " + repr(item))
        output = where / ("program-output-" + str(index) + ".bin")
        mcopy(image, "::/" + name, output, where,
              "extract-output-" + str(index))
        if output.read_bytes() != expected_bytes:
            raise Failure("Nova output bytes differ: " + name)
        file_results.append(dict(name=name, bytes=len(expected_bytes),
                                 sha256=digest(output)))
    if args.expect_diag:
        wanted = args.expect_diag.encode("ascii") + b"\r\n"
        if (where / "serial.log").read_bytes().count(wanted) != 1:
            raise Failure("Nova diagnostic missing/duplicated")
    driver_output = None
    if driver_control:
        inventory = run(["mdir", "-b", "-i", image, "::/"], where,
                        "driver-post-root-inventory").decode(
                            "utf-8", errors="strict")
        present = "OUTPUT.EFI" in root_inventory_names(inventory)
        actual_output = None
        if present:
            extracted = where / "driver-output.EFI"
            mcopy(image, "::/OUTPUT.EFI", extracted, where,
                  "driver-extract-output")
            actual_output = extracted.read_bytes()
        if not driver_output_matches(original_driver_output, actual_output):
            raise Failure("driver refusal created or modified OUTPUT.EFI")
        driver_output = dict(
            existed_before=original_driver_output is not None,
            exists_after=present,
            bytes_after=len(actual_output) if actual_output is not None else None,
            sha256_after=hashlib.sha256(actual_output).hexdigest()
            if actual_output is not None else None,
            preserved=True)
    (where / "program-check.json").write_text(json.dumps(dict(
        expected_return=args.expect_driver_code or 0,
        expected_runtime_error=8 if args.expect_driver_io else args.expect_error,
        driver_output=driver_output, files=file_results,
        diagnostic=args.expect_diag,
        purpose="runtime_interchangeability_not_selfhost"), indent=2))
    extract_files(where, image, extracts)
    return ram


# --------------------------------------------------------------------------
# The command line
# --------------------------------------------------------------------------

def build_parser():
    ap = argparse.ArgumentParser(
        description="A8 transport: ESP, QEMU boot, extraction. Nothing is translated.")
    ap.add_argument("--repo", default=None,
                    help="repository root (default: the parent of scripts/)")
    ap.add_argument("--work-root", default=None,
                    help="where the evidence is written; must resolve under "
                         "<repo>/out (default: <repo>/out)")
    ap.add_argument("--name", required=True, help="one fresh evidence name")
    ap.add_argument("--qemu", default="qemu-system-x86_64")
    ap.add_argument("--code", default="/usr/share/OVMF/OVMF_CODE_4M.fd")
    ap.add_argument("--vars", default="/usr/share/OVMF/OVMF_VARS_4M.fd")
    # The STANDALONE default stays 240: a short probe keeps dying quickly.
    # The house builder passes its own --timeout explicitly (10800).
    ap.add_argument("--timeout", type=int, default=240,
                    help="seconds, %d..%d" % (TIMEOUT_MIN, TIMEOUT_MAX))
    sub = ap.add_subparsers(dest="mode", required=True)
    assembly = sub.add_parser("assemble")
    assembly.add_argument("source", type=Path)
    assembly.add_argument("--test-entry", action="store_true")
    execute = sub.add_parser("selftest")
    execute.add_argument("host", type=Path)
    execute.add_argument("runtime", type=Path)
    execute.add_argument("--red-existing", action="store_true")
    production = sub.add_parser("run")
    production.add_argument("host", type=Path)
    production.add_argument("runtime", type=Path)
    production.add_argument("core", type=Path)
    production.add_argument("--payload", action="append", default=[],
                            help="ESP_NAME=local_path")
    production.add_argument("--expect-error", type=int, choices=(0, 7, 9),
                            default=0)
    driver = production.add_mutually_exclusive_group()
    driver.add_argument("--expect-driver-code", type=int,
                         choices=DRIVER_REFUSAL_CODES)
    driver.add_argument("--expect-driver-io", action="store_true")
    production.add_argument("--expect-file", action="append", default=[],
                            help="ESP_NAME=hex_bytes")
    production.add_argument("--expect-diag", default="",
                            help="exact ASCII diagnostic line")
    production.add_argument("--extract-file", action="append", default=[],
                            help="ESP_NAME extracted RAW to "
                                 "WHERE/extracted-ESP_NAME; not an attestation")
    return ap


def preflight(args, repo):
    """Everything that can refuse the run, before a single file is written."""
    for firmware in (args.code, args.vars):
        if not Path(firmware).is_file():
            raise Refusal("missing firmware: " + str(firmware))
    if args.mode == "assemble":
        if not args.source.is_file():
            raise Refusal("missing source: " + str(args.source))
        s0 = repo / "bootstrap/ntasm-s0/fixed-point"
        for name, pin in PINS.items():
            producer = s0 / name
            if not producer.is_file():
                raise Refusal("missing S0 producer: " + str(producer))
            if digest(producer) != pin:
                raise Refusal("S0 producer pin mismatch: " + name)
    else:
        wanted = [args.host, args.runtime]
        if args.mode == "run":
            wanted.append(args.core)
            if (args.expect_driver_code is not None or
                    args.expect_driver_io) and args.expect_error:
                raise Refusal("driver and legacy runtime expectations cannot "
                              "be combined")
        for path in wanted:
            if not Path(path).is_file():
                raise Refusal("missing input image: " + str(path))
        for item in args.payload if args.mode == "run" else []:
            _, _, local = item.partition("=")
            if local and not Path(local).is_file():
                raise Refusal("missing payload file: " + local)
    running = foreign_qemu_pids()
    if running:
        raise Refusal("another QEMU is already running (pids " +
                      ", ".join(str(pid) for pid in running) +
                      "); this transport reports it and never stops it")


def main(argv=None):
    args = build_parser().parse_args(argv)
    repo = resolve_repo(args.repo)
    work_root = resolve_work_root(repo, args.work_root)
    check_name(args.name)
    check_timeout(args.timeout)
    where = work_root / args.name
    refuse_reuse(where)
    payloads, extracts = plan(args)
    preflight(args, repo)

    work_root.mkdir(parents=True, exist_ok=True)
    refuse_reuse(where)
    try:
        where.mkdir()
    except FileExistsError:
        raise Refusal("refusing to reuse existing evidence: " + str(where))
    record_workspace(where, args, repo, work_root)

    ram = {}
    failure = None
    try:
        if args.mode == "assemble":
            ram = run_assemble(args, repo, where)
        elif args.mode == "selftest":
            ram = run_selftest(args, where)
        else:
            ram = run_production(args, where, payloads, extracts)
    except (Refusal, Failure) as exc:
        failure = exc
    except RuntimeError as exc:
        failure = Failure(str(exc))
    finally:
        ram = read_ram(where) or ram
        write_transport_result(where, args, repo, work_root, ram, failure)
    if failure is not None:
        raise failure
    write_complete(where, args.mode, ram)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Refusal as exc:
        print("NOVA_TRANSPORT_REFUSED " + str(exc), file=sys.stderr)
        sys.exit(2)
    except Failure as exc:
        print("NOVA_TRANSPORT_FAILED " + str(exc), file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print("NOVA_TRANSPORT_ERROR " + str(exc), file=sys.stderr)
        sys.exit(1)
