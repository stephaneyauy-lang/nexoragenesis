# Experimental A8 native transport

The native transport in `scripts/nova_native_transport.py` is a candidate for the A8 house build. It is **not connected to the normal build**, and it does not establish that A8 is complete.

The observed failure was a live QEMU process whose guest had entered `paused (shutdown)`. Waiting for process exit alone concealed that condition until the overall timeout. The transport now polls the local HMP monitor with a bounded, read-only `info status` request, at most once every five seconds. Observed fatal guest states veto success and leave an HMP transcript alongside the boot result.

The existing RAM thresholds, timeout limits, firmware-return proof, negative controls and own-process cleanup remain in place. The transport never resumes or resets an unexpectedly paused guest.

## Verification

```bash
python -m unittest discover -s tests/transport -p test_nova_native_transport.py
```

124 mocked tests pass: the 97 imported transport tests and 27 liveness cases. No live QEMU boot was performed for this change. Run `python scripts/nova_native_transport.py --help` for explicit firmware, seed and evidence-path arguments; binary seeds and firmware are not supplied by this pull request.

## Remaining work

- Verify monitor exchange and cleanup with one bounded live QEMU run.
- Review behavior when success appears between polls or the monitor remains unavailable.
- Diagnose the original guest shutdown; detecting it is not fixing its cause.
- Reconcile native-build dependencies with the reorganized source tree, then prove the complete A8 contract before integrating the normal build.
