# Experimental A8 native transport

The native transport in `scripts/nova_native_transport.py` is a candidate for the A8 house build. It is **not connected to the normal build**, and it does not establish that A8 is complete.

The observed failure was a live QEMU process whose guest had entered `paused (shutdown)`. Waiting for process exit alone concealed that condition until the overall timeout. The transport now polls the local HMP monitor with a bounded, read-only `info status` request, at most once every five seconds. Observed fatal guest states veto success and leave an HMP transcript alongside the boot result.

The existing RAM thresholds, timeout limits, firmware-return proof, negative controls and own-process cleanup remain in place. The transport never resumes or resets an unexpectedly paused guest.

The success markers alone are not a proof. They are accepted only by a **due** liveness observation, taken at or after them, that reports a running guest; a stale observation from before the markers, a malformed answer and an unavailable monitor never accept them. The transport waits for the next scheduled observation instead of accepting the markers, and the wait is bounded by the same deadline. A guest state that could not be read is recorded as `unknown`, never as `running`.

## Verification

```bash
python -m unittest discover -s tests/transport -p test_nova_native_transport.py
```

140 mocked tests pass: the 97 imported transport tests and 43 liveness and dependency cases. They cover a guest that is alive but `paused (shutdown)`, a plain `paused`, a success that arrives between two polls, a shutdown between two polls, a malformed answer, an unavailable monitor, a truncated answer and a normal success. No live QEMU boot was performed for this change. Run `python scripts/nova_native_transport.py --help` for explicit firmware, seed and evidence-path arguments; binary seeds and firmware are not supplied by this pull request.

The transport looks for the two pinned S0 producers in `legacy/ntasm-s0/fixed-point` first, then in `bootstrap/ntasm-s0/fixed-point`, and refuses when neither directory holds them. The pins it checks are the digests the repository publishes in `legacy/ntasm-s0/fixed-point/README.md`. The producer binaries themselves are not in this snapshot, so the `assemble` mode cannot run here.

## Live verification (2026-10-22)

The one bounded live QEMU run the review asked for was performed in WSL
(QEMU 8.2.2, the same build as the archived runs, with the OVMF 4M firmware
and `mtools`). It is scripted in `tests/transport/a8_live_check.sh` and it
boots the two hosts of the watchdog proof, so both outcomes are covered:

| case | guest | result | liveness | elapsed |
|---|---|---|---|---|
| `live-green` | the certified host | **pass**; `OUTPUT.EFI` byte-identical to the published `ea1dc3f9…` | 4 polls, `running`, confirmed | ~20 s of a 120 s budget |
| `live-red` | the watchdog host | **fail**, `the monitor reported VM status: paused (shutdown)` | 3 polls, `paused (shutdown)`, fatal | ~15 s of a 120 s budget |

The red case is the measured failure signature itself: the guest powers off
and the transport says so at once, with the HMP transcript kept, instead of
waiting for the budget. In the trial-05 terms that is about 15 s instead of
the 8601 s of dead waiting the archive records.

The real transcripts of the live monitor are kept as fixtures
(`tests/transport/fixtures/hmp-live-*.txt`) and the test suite parses them,
so the parser is locked to the format QEMU really sends: the banner, the
`(qemu)` prompt and the echoed command with its ANSI redisplay escapes.

## Remaining work

- The guest shutdown of trial 05 is still unexplained. What the archived
  evidence does establish, and what it refutes, is in
  [a8-trial05-shutdown.md](a8-trial05-shutdown.md): the firmware watchdog is
  refuted for that run, the guest stopped mid-batch at t+2074 s, and the
  transport then waited 8601 s for a guest that was already gone. The cause
  is not established; detecting it is not fixing its cause.
- Reconcile native-build dependencies with the reorganized source tree, then prove the complete A8 contract before integrating the normal build.
