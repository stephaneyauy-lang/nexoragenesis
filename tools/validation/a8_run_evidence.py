#!/usr/bin/env python3
"""Read one archived A8 run and report what its raw evidence holds.

READ ONLY. This reader opens the files of a run directory and prints JSON.
It writes nothing, it starts no process, and it never touches the archive it
reads.

The house build leaves one directory per step of a run. For the step that
boots a guest, the directory holds the serial log of the guest, the boot
result, the transport result and the digests of the images that were booted.
This reader turns them into the facts a reader needs before believing a
narrative:

  - how many batches the guest completed, and the phase of the batch it
    stopped in;
  - whether the terminal marker and the firmware return were there;
  - when the guest stopped writing to its serial log;
  - how long the transport kept waiting after that;
  - the digests of the images, so two runs can be compared.

Usage:
    python tools/validation/a8_run_evidence.py <run-directory> [<run-directory> ...]

Exit code 0 when every requested directory was read, 1 otherwise.
"""
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# The markers the Nova batch driver writes on the serial line.
LOWER_BEGIN = re.compile(r"^NG_NOVA_BATCH_LOWER_BEGIN (\d+)$")
LOWER_END = re.compile(r"^NG_NOVA_BATCH_LOWER_END (\d+)$")
OBJECT_BEGIN = re.compile(r"^NG_NOVA_BATCH_OBJECT_BEGIN (\d+)$")
OBJECT_END = re.compile(r"^NG_NOVA_BATCH_OBJECT_END (\d+)$")

# The terminal markers the transport looks for.
TERMINAL_MARKERS = ("NG_NV2_NATIVE_RUN_OK", "NG_NV2_NATIVE_TEST_OK",
                    "NG_NV2_NATIVE_BAD", "NG_NTASM_NATIVE_SCAN_OK")

# The name of a house run directory: 20261021T170311Z-82584f32
RUN_NAME = re.compile(r"^(\d{8})T(\d{6})Z-")


def parse_serial(text):
    """What the serial log of a guest says.

    The batches it completed, the phase of the batch it stopped in, the
    terminal marker it printed, and its last line.
    """
    marks = {}
    last = ""
    for raw in text.replace("\r", "").split("\n"):
        line = raw.strip()
        if not line:
            continue
        last = line
        for name, pattern in (("lower_begin", LOWER_BEGIN),
                              ("lower_end", LOWER_END),
                              ("object_begin", OBJECT_BEGIN),
                              ("object_end", OBJECT_END)):
            found = pattern.match(line)
            if found:
                marks.setdefault(int(found.group(1)), set()).add(name)
                break
    completed = sorted(index for index, seen in marks.items()
                        if "object_end" in seen)
    stopped_in = None
    for index in sorted(marks):
        seen = marks[index]
        if "object_end" in seen:
            continue
        if "object_begin" in seen:
            stopped_in = "OBJECT"
        elif "lower_begin" in seen and "lower_end" not in seen:
            stopped_in = "LOWER"
        break
    marker = None
    for line in text.replace("\r", "").split("\n"):
        for candidate in TERMINAL_MARKERS:
            if line.strip() == candidate:
                marker = candidate
    return dict(batches_completed=len(completed),
                last_completed_batch=(completed[-1] if completed else None),
                stopped_in=stopped_in,
                terminal_marker=marker,
                last_line=last)


def run_start(directory):
    """The start of a run, or None.

    The precise anchor is the moment QEMU was actually started, which the
    command file records; the name of the run directory is the fallback.
    """
    command = Path(directory) / "qemu.command.json"
    if command.is_file():
        return datetime.fromtimestamp(command.stat().st_mtime, timezone.utc)
    found = RUN_NAME.match(directory.parent.name)
    if not found:
        return None
    try:
        stamp = datetime.strptime(found.group(1) + found.group(2),
                                  "%Y%m%d%H%M%S")
    except ValueError:
        return None
    return stamp.replace(tzinfo=timezone.utc)


def _read_json(path):
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def read_run(directory):
    """The measured facts of one archived run directory.

    None for a fact that the directory does not hold: this reader never
    invents a value, and it never repairs an incomplete archive.
    """
    directory = Path(directory)
    serial_path = directory / "serial.log"
    boot = _read_json(directory / "boot-result.json")
    transport = _read_json(directory / "transport-result.json")
    inputs = _read_json(directory / "inputs.json")
    facts = dict(directory=str(directory), readable=False)
    if not directory.is_dir():
        facts["error"] = "not a directory"
        return facts
    facts["readable"] = True
    if serial_path.is_file():
        facts["serial"] = parse_serial(serial_path.read_text(
            encoding="utf-8", errors="replace"))
        facts["serial_last_write"] = _iso(serial_path.stat().st_mtime)
    if boot:
        facts["boot"] = dict(
            marker=boot.get("marker"),
            marker_exact_once=boot.get("marker_exact_once"),
            firmware_return=boot.get("firmware_return"),
            exit_code=boot.get("exit_code"),
            shutdown=boot.get("shutdown"),
            forced=boot.get("forced"),
            pass_=boot.get("pass"))
        liveness = boot.get("liveness")
        if liveness:
            facts["boot"]["liveness"] = liveness
    if transport:
        facts["transport"] = dict(
            timeout=transport.get("timeout"),
            failure=transport.get("failure"),
            runner_sha256=transport.get("runner_sha256"),
            a8_selfhost_proven=transport.get("a8_selfhost_proven"))
        ram = transport.get("ram") or {}
        facts["transport"]["ram_polled"] = ram.get("polled")
        facts["transport"]["ram_tripped"] = ram.get("tripped")
        facts["transport"]["ram_poll_seconds"] = ram.get("poll_seconds")
    if inputs:
        facts["inputs"] = [dict(esp=item.get("esp"), bytes=item.get("bytes"),
                                sha256=item.get("sha256"))
                           for item in inputs]
    facts["wait"] = _wait_facts(directory, facts)
    return facts


def _iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat()


def _wait_facts(directory, facts):
    """When the guest stopped writing, and how long the transport waited.

    The transport polls the free memory every five seconds, so the number of
    polls bounds the time it spent waiting. The last write of the serial log
    is when the guest stopped talking. The difference is the dead time: the
    transport waiting for a guest that was already gone.
    """
    out = dict(guest_last_write=facts.get("serial_last_write"))
    start = run_start(directory)
    out["run_start"] = start.isoformat() if start else None
    transport = facts.get("transport") or {}
    polled = transport.get("ram_polled")
    seconds = transport.get("ram_poll_seconds")
    if isinstance(polled, int) and isinstance(seconds, (int, float)):
        out["waited_seconds"] = polled * seconds
    if start and facts.get("serial_last_write"):
        stopped = datetime.fromisoformat(facts["serial_last_write"])
        out["guest_stopped_after_seconds"] = (stopped - start).total_seconds()
        if "waited_seconds" in out:
            out["dead_wait_seconds"] = (out["waited_seconds"] -
                                        out["guest_stopped_after_seconds"])
    return out


def report(directories):
    """The report of one or more run directories."""
    runs = [read_run(directory) for directory in directories]
    ok = all(run.get("readable") for run in runs)
    return dict(ok=ok, runs=runs)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print("usage: a8_run_evidence.py <run-directory> [<run-directory> ...]",
              file=sys.stderr)
        return 2
    result = report(argv)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
