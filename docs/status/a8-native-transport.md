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

## Remaining work

- Verify monitor exchange and cleanup with one bounded live QEMU run.
- Diagnose the original guest shutdown; detecting it is not fixing its cause.
- Reconcile native-build dependencies with the reorganized source tree, then prove the complete A8 contract before integrating the normal build.
