# A8 house build — the live-test plan

**This document is a plan.** It states what the house build must be run
through, in what order, and what each step proves and what it does not prove.
Every command below was checked for existence, for its flags and for its
current behaviour; §7 lists the checks with their real output.

**Two of the steps have already been run, and their results are in this
document as measurements, not as predictions:**

- the two **assembles** (step D) — both images rebuilt **byte-identically** to
  the manifest's pins;
- the **producer step** (step E) — it **FAILED, reproducibly, at batch 16**,
  exactly like trial 05, and it was detected in **21.6 s** instead of the
  archive's 8 738 s of dead waiting.

So the plan's real content is not "what might happen": it is "what is now
known, what is still missing, and what the next heavy run must decide". The
next heavy run is **not** the producer step — that one has answered — it is
the **bisection** (step E2), and the **self-host route** (step F) cannot
produce a fixed point until the producer step can complete.

**The honest headline:** the house build's *first* full run on this
repository **did not deliver**, and it failed for the same reason trial 05
failed. Nothing in this plan changes that; the plan says what would.

---

## 0. What the house build is, in one paragraph

`scripts/ntbuild_house.py` (fronted by `scripts/ntbuild_house.sh`)
reconstructs the Nova producer from **pinned Nova sources**, through **one**
transport (`scripts/nova_native_transport.py`), which boots QEMU with the OVMF
firmware and extracts the bytes the emulated machine wrote. The builder never
calls a C compiler, never calls NASM, never calls the C loader
(`native_pe_run`), and grants no C at all (`bash scripts/ntbuild_house.sh
policy`, verified: *"this build grants NO C at all"*). It has two heavy
commands:

- `build` — assemble the runtime image and the host image from their pinned
  `.ntasm` sources, then run the pinned seed PE on the pinned producer package
  and compare the extracted `OUTPUT.EFI` with an **external** digest;
- `selfhost` — seed → N1 → N2, two real generations, and N1 must equal N2
  byte for byte.

Both write exactly one fresh directory under `out/ntasm-house/<utc>-<nonce>/`
and nothing else. On failure, **no `build.json` is written**: there is no
"ok" record to misread.

---

## 1. Prerequisites of the house build in this repository, and their state today

| # | Prerequisite | Where it comes from | State on 2026-10-22 | How it was checked |
|---|---|---|---|---|
| P1 | Python 3 with `fcntl` | the host | **present** (3.12.3) | `python3 --version`; `python3 -c "import fcntl"` |
| P2 | `scripts/ntbuild_house.py`, `scripts/ntbuild_house.sh` | this tree | **present** | `--help` on both |
| P3 | `scripts/nova_native_transport.py` | this tree | **present** | `python3 scripts/nova_native_transport.py --help` |
| P4 | The manifest `bootstrap/nova-native/manifest.json` | generated for this tree by `tools/validation/a8_manifest.py` | **present**, 18 322 bytes, sha256 `f59aa371f502a94b10ae61a7bf0483be343c13abb558f89c062a7dc4563a6bac` | `python3 scripts/ntbuild_house.py pins` |
| P5 | The **seed PE** `nova-compiler.EFI` (9 943 552 bytes, sha256 `6ab3b02d…`) | **published, not in this tree**; the campaign archive, read only | **not in the tree by design**; reachable at `/mnt/c/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01/bootstrap/nova-native/nova-compiler.EFI` (digest verified) | `sha256sum` of the archive copy; `pins --seed-dir <that dir>` → `ok=111 bad=0` |
| P6 | OVMF firmware + vars | the host's OVMF package | **present**: `/usr/share/OVMF/OVMF_CODE_4M.fd` (3 653 632 B), `OVMF_VARS_4M.fd` (540 672 B) | `ls -l`; the transport's preflight refuses a missing firmware |
| P7 | The two pinned **S0 producers** (`compiler-host.NTASM1.EFI`, `compiler-core.NTASM1.EFI`) | this tree, `legacy/ntasm-s0/fixed-point/` | **present**, digests `82826f45…` / `a02425be…` = the transport's `PINS` | `sha256sum legacy/ntasm-s0/fixed-point/*.EFI` vs `scripts/nova_native_transport.py:62-65` |
| P8 | The pinned Nova closure (56 compiler + 52 producer sources) | this tree, `compiler/nova/**.nova` | **present**; 75 `.nova` files on disk, the 108 manifest entries resolve, every digest matches | `pins` → `ok=110 bad=1` (the one bad is the seed only) |
| P9 | The pinned runtime and host `.ntasm` sources | this tree, `compiler/runtime/` | **present**, digests `0c768e48…` / `a2b8b4dc…` = the manifest's | same `pins` run |
| P10 | QEMU 8.2.2, `mtools` | the host | **present** (`qemu-system-x86_64` 8.2.2 Debian; `mtools`; `powershell.exe` reachable) | `qemu-system-x86_64 --version`; `which` |
| P11 | 4 vCPU, free RAM ≥ 9 GiB on the **Windows** host | the host | **present**: 4 CPUs; the transport's own measurement (`measure_free_memory()`, which under WSL measures the Windows host through `powershell.exe`) returned **10.4–12.4 GiB** free across three calls — always above the 9 GiB start threshold, but the margin is not large | `nproc`; `measure_free_memory()` called directly |
| P12 | Disk for `out/` | the host | **present**: 121 GB free on `/mnt/c` | `df -h /mnt/c` |
| P13 | The two **NVSRC001 bundle digests** of this tree | recomputed from the bytes on disk | **consistent**: compiler bundle `3dbdea63…` (1 965 761 B), producer bundle `a5f4f2ee…` (1 665 633 B) — recomputed independently with the builder's own `pack_nvsrc001()`, equal to the manifest's fields | `pack_nvsrc001()` re-run here; `pins` |
| P14 | The external expected producer digest `190cb8b1…` | published, carried over unchanged | **present in the manifest**; it is the digest of the archive's `runtime-native/ntasm-native-from-p2-02/OUTPUT.EFI` (12 544 512 B) — **which was produced by the C loader, not by this transport** (§2, step F) | `sha256sum` of that archive file; `NATIVE_PE_RUN` in its `run.log` |
| P15 | **Nothing else** is a prerequisite | — | the build refuses rather than degrades: `manifest-missing`, `seed-missing`, `source-not-in-tree`, `bundle-mismatch`, `image-digest-mismatch`, `lock-unavailable`, `timeout-out-of-range`, `transport-refused` | `bash scripts/ntbuild_house.sh policy` |

### 1.1 What is still missing, and what that means

1. **The seed bytes are not in this tree.** That is deliberate (the reviewer's
   own words: *"binary seeds and firmware are not supplied by this pull
   request"*), and it is not a defect. The consequence is concrete: **every
   heavy command must be given the seed directory explicitly**, or it refuses
   with `class=seed-missing` (exit 78) before touching QEMU. Verified:
   `bash scripts/ntbuild_house.sh build --seed-dir /tmp` →
   `NTHOUSE_REFUSED class=seed-missing / reason: nova_compiler does not exist: /tmp/nova-compiler.EFI`.

2. **The producer step cannot complete** — not because of a missing input,
   but because the guest powers itself off at batch 16 (§2, step E). The
   cause is still unknown; §5.

3. **The legacy C bootstrap's own pins are stale** — three discrepancies
   (`compiler/c/nova/frontend/nova.c`, `compiler/c/nova/frontend/nova.h`, and
   `compiler/c/nova/analysis/seed_reachability.h` has no pin row).
   `bash scripts/ntbuild.sh pins --verify` reports `ok=32 bad=3`. Since
   `cmd_build()` runs `check_granted_input_digests()` *before* it compiles
   anything, the legacy build refuses rather than rebuild on different bytes.
   **[INFERENCE from the code and the measured pin output; the legacy build was
   deliberately not run here, because running it would compile.]** The pins are
   the owner's decision (`docs/status/a8-pin-discrepancies.md` deliberately
   does not update them).

4. **One QEMU at a time.** The transport refuses to start while another QEMU
   is running, and that refusal is not theoretical: the first attempt at the
   heavy run on this tree (`out/ntasm-house/20261022T133305Z-4c56b01a`,
   15:33:05) left only `pack/producer.NOVA.IN` and no step directory — the
   first transport call was refused while agent a5's reproducer still held the
   slot (its QEMU lived 14:58:34 → 15:35:10). The second attempt, at 15:35:49,
   ran. **Steps E2 and F must be scheduled when the slot is free.**

---

## 2. The steps, cheapest first

Each step states the **exact command**, the **evidence** it must leave, its
**expected duration**, its **RAM and timeout budget**, and **how it is
stopped** (own process only). Steps marked **DONE** carry their measured
result.

### Step A — inventory and policy (read-only, no QEMU)

```bash
python3 scripts/ntbuild_house.py policy
python3 scripts/ntbuild_house.py pins --seed-dir /mnt/c/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01/bootstrap/nova-native
bash scripts/ntbuild_house.sh check compiler/nova/frontend/ast.nova
bash scripts/ntbuild_house.sh check compiler/c/nova/frontend/nova.c
bash scripts/ntbuild.sh policy
bash scripts/ntbuild.sh pins --verify
bash scripts/ntbuild.sh census
python3 tools/validation/a8_manifest.py
python3 tools/validation/a8_run_evidence.py /mnt/c/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01/out/ntasm-house/20261021T170311Z-82584f32/producer
python3 tools/validation/a8_pin_discrepancies.py --archive-root /mnt/c/NexoraGenesis
```

- **Expected evidence**: `NTHOUSE-POLICY/1`; `NTHOUSE_PINS_VERIFY ok=111 bad=0`;
  `NTHOUSE_ALLOWED` for the nested `.nova` and `NTHOUSE_REFUSED
  class=quarantine-source` for the C file; `NTBUILD_CORPUS_CENSUS … bad=0`;
  the manifest JSON with the two bundle digests; the archive reader's JSON
  (`batches_completed: 16`, `stopped_in: LOWER`, `ram_tripped: false`);
  `a8_pin_discrepancies.py` printing the three known discrepancies, with
  `verdict: paths-and-comments-only` for both stale pins, and exiting 1.
- **Duration**: seconds.
- **RAM / timeout**: none; no process is started.
- **Stop**: nothing to stop. The two tools under `tools/validation/` write
  nothing unless given an explicit `--out`.
- **Proves**: the tree and the manifest agree byte for byte, the published
  seed is the pinned seed, the policy refuses what it must refuse, and the
  legacy pins' discrepancies are exactly the three that are documented — and
  that their content delta is **paths and comments only, zero code lines**.
- **Proves NOT**: that anything can be built. No QEMU ran.

### Step B — the unit tests (no QEMU)

```bash
python3 scripts/ntbuild_house.py selftest
python3 -m unittest discover -s scripts/tests -p "test_ntbuild_dispatch.py"
python3 -m unittest discover -s scripts/tests -p "test_ntbuild_*.py"
python3 -m unittest discover -s tests/transport -p test_nova_native_transport.py
A8_ARCHIVE_ROOT=/mnt/c/NexoraGenesis/out/a8-selfhost-20261015 \
  python3 -m unittest discover -s tests/transport -p test_nova_native_transport.py
```

- **Expected evidence**: `NTHOUSE_SELFTEST tests=67 failures=0 errors=0`;
  `Ran 15 tests … OK`; `Ran 82 tests … OK`; and the transport suite
  **160 tests, `OK (skipped=4)`** without the archive root, **`OK (skipped=1)`**
  with it.
- **The skips are named**: without the archive root, three
  archived-evidence tests skip (*"the archived A8 evidence is not on this
  machine"*) plus `test_the_content_delta_is_paths_only` (*"the campaign tree
  is not on this machine"*); with the archive root set, only the last one
  remains skipped.
- **One environmental trap, named precisely.** This worktree's `.git` is a
  **file** containing `gitdir: C:/Users/…/ntasm-publication/.git/worktrees/
  a8-maintenance` — a Windows path that WSL's `git` cannot resolve, so
  `git -C ROOT log` returns nothing and exactly one test,
  `test_the_pin_of_nova_h_designates_a_real_revision`, fails on that alone.
  The test itself is correct: it asserts that the `nova.h` pin designates a
  real revision, and the tool finds it — revision
  `87472cd778d320726d8222f639007b17887d73d9`, path
  `bootstrap/quarantine/c/nova.h`, 1018 bytes. **To run the suite green under
  WSL, export the real worktree gitdir:**
  ```bash
  export GIT_DIR=/mnt/c/Users/steph/Documents/Codex/2026-10-22/ntasm-publication/.git/worktrees/a8-maintenance
  ```
  With that exported, the suite is `160 tests, OK (skipped=4)`, and with the
  archive root `OK (skipped=1)`. **A reviewer must not read the unexported
  failure as a code defect, and must not "fix" the pin from the test.**
- **Duration**: about 1–8 s per suite (measured: 1.2 s, 0.2 s, 1.4 s, 2.1 s,
  7.7 s with `GIT_DIR`).
- **RAM / timeout**: none.
- **Stop**: nothing to stop; the house suite mocks `subprocess.Popen` and
  `os.killpg` entirely, so no real process and no real signal is ever created.
- **Proves**: the house rules hold on synthetic trees, the entrypoint forwards
  and refuses without a silent fallback, and the transport's liveness contract
  (dead guest detected, stale observation rejected, unavailable monitor
  refused) holds as unit logic.
- **Proves NOT**: anything about the real tree, real QEMU, or the real
  delivery. The house test file says so itself: *"They are not, and never will
  be, A8 proof."*

### Step C — the transport's bounded live check (QEMU, ~35 s) — **DONE**

Performed on 2026-10-22; listed so the reviewer sees the shape of the cheapest
live evidence and can re-run it.

```bash
bash tests/transport/a8_live_check.sh
```

- **Expected evidence** (measured, `out/a8-live/`): `live-green` → `pass: true`,
  `marker_exact_once: true`, `firmware_return: true`, `exit_code: 0`,
  `shutdown: hmp`, `forced: false`, liveness `{polled: 4, state: running,
  confirmed: true}`, ~20 s of a 120 s budget; `live-red` → `pass: false`,
  `failure_reason: "the monitor reported VM status: paused (shutdown); the guest
  VM is gone and the serial log cannot make the proof true"`, liveness
  `{polled: 3, state: paused, fatal: true}`, ~15 s of a 120 s budget.
- **Duration**: ~35 s for both cases (budget `A8_LIVE_BUDGET`, default 120 s
  per case).
- **RAM / timeout**: guest 512 MiB / 4 vCPU / no network; the RAM gate refuses
  below 9 GiB free at start and stops the run below 8 GiB; the green case
  measured `start_free: 11 118 198 784` (10.36 GiB).
- **Stop**: the transport stops its own QEMU through the HMP monitor
  (`shutdown: "hmp"`), then `p.wait(timeout=10)`; on failure of that it
  `terminate()`s and finally `kill()`s **its own PID only**.
- **Proves**: the transport boots a guest on this host, extracts bytes, and
  detects a dead guest in ~15 s instead of waiting out the budget.
- **Proves NOT**: that the house build works; the live check uses archive
  images and says nothing about this tree's sources.

### Step D — the two assembles alone (QEMU, seconds each) — **DONE, PASS**

The cheap way to validate the assembly half of the house build without paying
for the 45-batch producer run: the exact calls the builder makes
(`Transport.assemble`, `scripts/ntbuild_house.py:792`).

```bash
python3 scripts/nova_native_transport.py --repo . --work-root out/a8-live \
  --name runtime --timeout 10800 \
  --code /usr/share/OVMF/OVMF_CODE_4M.fd --vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  assemble compiler/runtime/runtime-v2-s0.ntasm

python3 scripts/nova_native_transport.py --repo . --work-root out/a8-live \
  --name host --timeout 10800 \
  --code /usr/share/OVMF/OVMF_CODE_4M.fd --vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  assemble compiler/runtime/uefi-host-s0.ntasm
```

- **Measured result** (inside the heavy run of 2026-10-22,
  `out/ntasm-house/20261022T133548Z-db54d2d1/`):
  - `runtime/produced.EFI` → **`413b78160f34609a0d23f3cedb0308118483eb6204cc60e2f6795dc593e2c4b8`**
    — the manifest's `runtime.image_sha256`;
  - `host/produced.EFI` → **`9b3509ec28ca705fdaec2c95e2221d28d2f8793cb7fcc308986899c94b57dad2`**
    — the manifest's `host.image_sha256`;
  - both steps `pass: true`, `marker_exact_once: true`, `firmware_return: true`,
    `exit_code: 0`, `shutdown: "hmp"`, `forced: false`, liveness
    `{polled: 2, state: running, confirmed: true}`.
  **The two images rebuild byte-identically to their pins from this tree's
  sources.** The builder's own gate (`_check_image`, `class=image-digest-mismatch`
  on a difference) did not fire.
- **Duration**: **5.5 s** (runtime, 15:35:50 → 15:35:55) and **5.5 s** (host,
  15:35:56 → 15:36:02). The archive's stage agrees (19:03:12 → 19:03:16,
  19:03:17 → 19:03:21).
- **RAM / timeout**: 512 MiB guest, 4 vCPU, no network; `--timeout 10800` is
  the ceiling; the RAM gate as in step C.
- **Prerequisites of this step, checked**: the transport's `assemble` mode reads
  the pinned S0 producers from `legacy/ntasm-s0/fixed-point/` first
  (`S0_PRODUCER_DIRS`) and refuses on a digest mismatch — both files are
  present with the transport's own pinned digests; and it refuses a source
  that is not `0 < len < 65536` bytes ending in a newline — the two `.ntasm`
  sources are 21 576 and 25 252 bytes and both end in `0a`.
- **Stop**: the transport stops its own QEMU via HMP. If interrupted from
  outside: **Ctrl-C (SIGINT)** on the transport — the boot's `finally` sends
  the HMP `quit` and waits 10 s, then `terminate()`s and `kill()`s its own
  PID. No `pkill`, no PID from outside, no WSL shutdown.
- **Proves**: the S0 assembly path works on this host, the images are
  byte-reproducible, and the transport's success contract holds on a real boot.
- **Proves NOT**: anything about the producer, the seed, or self-hosting.

### Step E — the producer step of the house build (QEMU, 1.5–3 h) — **DONE, FAILED**

**This is the step that stopped in trial 05, and it stopped again on this
tree.** The result is a measurement, not a prediction.

- **Measured result** (`out/ntasm-house/20261022T133548Z-db54d2d1/`):

  | fact | value |
  |---|---|
  | the producer package used | **this tree's own**, sha256 `a5f4f2ee454253eb…`, 1 665 633 B (`producer/inputs.json`) |
  | the runtime image used | `413b7816…` (the word-wise zeroing build) |
  | the host image used | `9b3509ec…` |
  | the core (seed) used | `6ab3b02d…` |
  | batches completed | **16** (`NG_NOVA_BATCH_OBJECT_END 15`, then `NG_NOVA_BATCH_LOWER_BEGIN 16`) |
  | stopped in | the **LOWER** phase of batch 16 — the same batch and the same phase as trial 05 |
  | guest state at the stop | **`paused (shutdown)`**, measured by the monitor, `fatal: true`, 421 polls |
  | detection latency | **21.6 s** after the last serial write (16:11:01 → 16:11:22) |
  | dead wait | **0** — the run ended at once, against the archive's 8 738 s |
  | RAM guard | never tripped; free memory **rose** 12.18 → 13.44 GB, 421 polls at 5 s |
  | outcome | `pass: false`; `failure_reason: "the monitor reported VM status: paused (shutdown); the guest VM is gone and the serial log cannot make the proof true"` |
  | `build.json` | **absent** — the builder writes it only on success, so there is no "ok" record to misread |

  The same failure, the same batch and the same phase, with **this tree's own
  regenerated producer package** — so the stop is not an artefact of the
  archive's package bytes, and the comment-only differences of the
  reorganisation did not move it.
- **Expected duration of a re-run**: the guest reaches batch 16 at
  **≈131 s/batch** (measured here: 2 097.6 s for 16 batches), i.e. **≈35 min**
  to the stop, plus a few seconds of detection. A run that *survives* batch 16
  needs ≈45 batches ≈ **1.6 h**, which the 10 800 s budget covers.
- **RAM / timeout budget**: `--timeout 10800` (3 h) is the default and the
  ceiling of both the builder and the transport (`10..10800`). The RAM gate:
  refuse below **9 GiB** free at start, stop the run below **8 GiB** free,
  polled every 5 s, measured on the **Windows** host (`powershell.exe`) while
  running under WSL. Measured while this document was written: **10.4–12.4
  GiB** free — between 1.4 and 3.4 GiB above the start threshold. The WSL VM
  itself holds only ≈5 GiB total (`free -g`), see §5.4. Guest: 512 MiB, 4 vCPU,
  no network. The 4 vCPUs do **not** parallelise the build: the emulated
  compiler stays sequential, one job at a time.
- **Stop**: the primary stop is the deadline — on expiry the transport leaves
  the boot loop, sends the HMP `quit`, and the run ends `pass: false`. To stop
  it earlier: **SIGTERM to the builder PID** (`kill -TERM <builder pid>`); the
  builder turns SIGTERM into `BuildTerminated`, and its `finally` stops the
  transport's **own process group** (probe with signal 0, then SIGTERM, 5 s
  grace, then SIGKILL) and reaps the leader. The transport and the QEMU it
  started are inside that one group, because the builder starts the transport
  with `start_new_session=True`. **Never** `pkill`, never a PID read from
  outside the builder, never an WSL shutdown. On the builder's side a stop
  exits 1 with `NTHOUSE_TERMINATED`; a transport refusal (rc 2) exits 78 with
  `class=transport-refused`.
- **Proves**: that the producer step, on this tree, with this tree's package,
  **fails reproducibly at batch 16** and that the failure is now *detected in
  seconds* instead of costing two and a half hours of dead waiting. It
  proves the **failure** is deterministic and input-determined.
- **Proves NOT**: the fixed point, and nothing about the producer's output
  (the guest never got there).

### Step E2 — the bisection: the byte-wise runtime image (QEMU, up to 3 h) — **THE NEXT HEAVY RUN**

This is the run that decides whether the producer step can ever complete, and
it is agent a5's design, written up in `docs/status/a8-trial05-bisection.md`.
It is listed here because it is the next heavy step, it uses the transport
directly, and it shares this plan's budget and stop rules.

```bash
REPO=/mnt/c/Users/steph/Documents/Codex/2026-10-22/a8-maintenance
S=/mnt/c/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01
RUN=$S/out/ntasm-house/20261021T170311Z-82584f32
BYTE=$S/out/ntasm-house/20261021T135309Z-893a6637
python3 $REPO/scripts/nova_native_transport.py \
  --repo $REPO --work-root out/a8-bisect --name bisect-B \
  --timeout 10800 --code /usr/share/OVMF/OVMF_CODE_4M.fd \
  --vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  run $RUN/host/produced.EFI \
      $BYTE/runtime/produced.EFI \
      $S/bootstrap/nova-native/nova-compiler.EFI \
  --payload NOVA.IN=$RUN/pack/producer.NOVA.IN
```

- **The one variable**: the runtime image. `17fd29cd45667004…` (the byte-wise
  build of the same source line) instead of `413b7816…` (the word-wise one).
  Host, core and payload are the archive's, unchanged. The three digests to
  read before starting are printed in the bisection document.
- **Expected duration**: if the guest dies at batch 16 again, the run ends in
  **seconds** after the stop (the liveness poll), i.e. ≈35 min. If it
  *survives*, the archived byte-wise run needed 3 527 s to reach batch 19 and
  was still writing; a full 45-batch build needs ≈1.6 h. The 10 800 s budget
  is there so the survival case is not truncated.
- **RAM / timeout budget**: as step E, `--timeout 10800`, RAM gate 9/8 GiB on
  the Windows host.
- **Stop**: the transport's own deadline; to interrupt, **Ctrl-C (SIGINT)** on
  the transport (its boot `finally` sends the HMP `quit` and waits 10 s, then
  `terminate()`s and `kill()`s its own PID). Never a foreign PID.
- **Proves, per outcome**: past batch 16 → the **word-wise zeroing image is
  the cause**; stopping at batch 16 again → the cause lies in what both
  images share (host, core, payload, or the guest's own memory behaviour);
  stopping at a different batch → the stop is tied to the workload, not to the
  runtime image. The table is in the bisection document.
- **Proves NOT**: the fixed point, and not A8.

### Step F — the full self-host route (QEMU, 2.5–4 h) — **BLOCKED, NOT YET RUN**

```bash
bash scripts/ntbuild_house.sh selfhost \
  --seed-dir /mnt/c/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01/bootstrap/nova-native
```

- **Status: never run, and it cannot succeed while step E fails.** The
  self-host route runs the *same* guest, the *same* runtime image and the
  *same* transport as the producer step; only the payload differs (the
  56-source compiler closure instead of the 52-source producer closure). The
  word-wise runtime image is what stops the guest at batch 16, and the
  self-host route boots that image. **Running F before the cause is settled
  would spend hours to reproduce a stop.** The order is: E2 first, then F.
- **Expected evidence**: `out/ntasm-house/<utc>-<nonce>/selfhost.json` with
  `schema: NTHOUSE_SELFHOST_V1`, `output.n1.sha256 == output.n2.sha256`,
  `output.identical: true`, and `output.n1_equals_pinned_seed_sha256`
  recorded as an **observation, not a criterion**; plus `selfhost-n1/` and
  `selfhost-n2/`, each with its own `boot-result.json`, `serial.log` and
  `hmp-liveness.log`. Both generations must satisfy the transport's success
  contract (marker once, firmware return, HMP quit, rc 0, not forced, RAM
  healthy, liveness confirmed).
- **Expected duration**: **≈2.5–4 h**. Two generations of the 56-source
  compiler closure (32 batches each, at the measured ≈130 s/batch ≈ 1.2 h per
  generation) plus two assembles (~11 s). Each transport call gets its own
  `--timeout`, so the *worst case* is 4 × (10 800 + 120) s of wall clock.
- **RAM / timeout budget**: as step E, per transport call. The builder holds
  `/tmp/nexora-a7-cpu-safe-gates.lock` (exclusive `fcntl`, 300 s bounded
  wait) for the heavy steps, so a concurrent house run waits up to 300 s and
  then refuses (`lock-unavailable` / `lock-timeout`) rather than racing.
- **Stop**: exactly as step E — SIGTERM to the builder, which takes down its
  own process group and nothing else.
- **Proves**: the fixed point of the producer over the house chain — the
  producer rebuilds itself, byte for byte, with no C substitution. This is
  the shape of the A8(4) obligation.
- **Proves NOT**: that the C bootstrap is gone, that A8 is closed, or that A9
  is anything. See §4 and §6.

**One fact that must not be confused with the above.** The archive holds two
pairs of runs that look like a fixed point — `selfcompile-batches-p1-11` and
`selfcompile-batches-p2-04`, byte-identical (`6ab3b02d…`,
`NOVA_FIXED_POINT_P1_P2 identical=yes`), and `ntasm-native-from-p1-01` and
`ntasm-native-from-p2-02` (both `190cb8b1…`). **Those runs were executed by the
C loader `native_pe_run`**, not by this transport: their logs carry
`NATIVE_PE_RUN status=ok … source_not_compiled_by_C=yes`, and they contain no
`boot-result.json` and no QEMU evidence at all. **No producer compile has
ever completed through the house transport.** The transport route has reached
batch 16–19 and stopped, and that is the whole of its record. The expected
producer digest `190cb8b1…` is a **C-loader-era** digest; the transport has
never been shown to produce it.

---

## 3. The decision points

| Step | Result | What it proves | What it does **not** prove | Unlocks |
|---|---|---|---|---|
| A | `pins ok=111 bad=0` | the inputs of the build are exactly the pinned bytes | that the build can run | E |
| B | all suites green | the house rules and the transport's liveness logic hold | anything real | E |
| C | green passes, red fails fast | the transport boots here and sees a dead guest | anything about this tree | E |
| D | **both images equal their pins** (measured) | the S0 assembly path is byte-reproducible here | anything about the producer | E |
| E | **fails reproducibly at batch 16** (measured) | the producer step's failure is deterministic and input-determined, and is now detected in seconds | the fixed point; self-hosting; A8 | E2 |
| E2 | past batch 16 / stops again / stops elsewhere | **which input causes the stop** — the word-wise image, the shared inputs, or the workload | the fixed point | the fix, then F |
| F | `n1 == n2`, `identical: true` | the **fixed point** of the producer over the house chain — the A8(4) shape | that A8 is closed; that A9 is started | the integration decision |

**The decision that says "the A8 contract is proven"** is step F, and only in
combination with the other three A8 obligations, which this plan does not
measure:

- (1) C reproducibility — `TENU` (C gates, `GATES_DONE fail=0`);
- (2) C/Nova convergence — `TENU` on the delivered fixtures
  (`x64_lower_nxo_pe 2627/0/204`);
- (3) S0 fixed point — `CLOS` (the S0 recipe runs and is byte-identical);
- (4) v0 self-hosting — **OPEN**, and it is the only open one.

Step F is the evidence for (4). It does not, by itself, close A8: closing A8
requires the four obligations to hold together and the final review to accept
them (`docs/status/ntasm-completion.md`, *"A8 — DÉFINIE EN QUATRE OBLIGATIONS"*),
and the house build remains a **candidate** route until the lead integrates it.

**And today the chain stops before F.** E is red, E2 has not been run, and F is
blocked behind it. The honest status of this tree is therefore: *the house
build runs, the pins hold, the images are byte-reproducible, and the producer
step reproduces trial 05's failure in 35 minutes.*

---

## 4. What must still be true after the contract is proven

1. **The principal build of this snapshot is still the C bootstrap.**
   `scripts/ntbuild.sh` is the normal build; `scripts/ntbuild_house.sh` is the
   candidate route, and it says so itself: *"IT IS NOT THE NORMAL BUILD OF THIS
   REPOSITORY. The principal build of this snapshot is still scripts/ntbuild.sh,
   the legacy C bootstrap producer. The house build becomes the normal build
   only once the A8 contract is proven."* A green step F does not change that
   by itself; integration is the lead's decision.
2. **The seed remains a trust root, not a proven origin.** The build checks the
   seed's digest and its PE64 shape and re-reads it at the end; it never proves
   where the seed came from, and `build.json` says so (`seed.role: "pinned
   trust root; this build checks its digest and its PE64 shape, it does not
   prove its provenance"`).
3. **A8 stays open until the contract is proven and the final review accepts
   it.** The campaign's own finaliser is explicit: even after a *successful*
   integration it wrote `"A8_formally_closed": false` with the reason *"code
   integrated after real proof; completion contract and final review remain"*.
4. **A9 does not start on A8's green.** A9 is the tool deliverable (delivery
   manifest, installation, the usable binary) and is explicitly deferred until
   after A8 (`docs/status/ntasm-a9-acceptance.md`: *"A9 sera finalise apres
   A8 sur le producteur auto-heberge"*).
5. **The legacy C pins** (§1.1 item 3) remain the owner's decision, whatever
   the house build's outcome.
6. **The trial-05 shutdown cause** remains open unless step E2 or a further
   bisection settles it; a green step F does not explain why the guest of the
   17:03 run powered off.

---

## 5. The risks that are already known, with their evidence

### 5.1 The guest shutdown cause is unknown — and it is now reproducible

`docs/status/a8-trial05-shutdown.md` states it: the cause of the trial-05 stop
is **not established**. What the archive establishes: the guest stopped at
t+2074 s in the LOWER phase of batch 16, wrote no terminal marker, recorded no
firmware return, and the transport then waited **8 601 s** for a guest that
was already gone. What it refutes: the firmware watchdog (the failing run's
host was the certified watchdog-disabled one, `9b3509ec…`), the RAM guard
(never tripped; free memory *rose* 16.8 → 19.5 GB), and any CPU-level fault
(the `guest_errors` log is byte-identical to the healthy runs'). The candidates
the archive cannot exclude: a guest-side fault handled as a shutdown, a guest
allocation failure at 512 MiB, and a defect of the new word-wise zeroing path
reached only by a particular batch size.

**What the two reproductions add** (the archive's reproduction
`out/a8-repro/repro-trial05/`, 14:58:34 → 15:35:10, and this tree's heavy run
`out/ntasm-house/20261022T133548Z-db54d2d1/producer/`, 15:36:03 → 16:11:22):
both stop at **batch 16, LOWER phase**, with **`paused (shutdown)` measured by
the monitor** — 23.69 s and 21.6 s of detection latency respectively. The
second one used **this tree's own producer package** (`a5f4f2ee…`). So the
stop is **deterministic and input-determined**, it is **not** an artefact of
the archive's package bytes, and it is **not** a timing accident of one host.
Detecting it is not fixing it: **the cause is still unknown.**

### 5.2 The word-wise pool zeroing is a correlation, not a cause

Between the 14:37 run (which kept going) and the 17:03 run (which stopped),
the runtime source changed `486ce6f1…` → `0c768e48…`: one hunk, `nv_pool_zero`
became word-wise (`store64` while ≥ 8 bytes remain, then a 0–7 byte tail).
The optimisation's own proof records `"fullbuild_gain": "not measured"` — it
was integrated on a microbenchmark (77 runtime checks, 128 allocations of
32 MiB) and a mutant, never on a full build. And the 16:22 run used **the same
runtime** (`413b7816…`) for fifteen batches before it was stopped by hand.
So: coincidence in time, and step E2 is what tests it directly. The archive
holds the byte-wise image `17fd29cd…` (runs of 13:53, 14:14 and 14:37), which
is exactly what run B needs.

### 5.3 The liveness poll turns a dead guest into seconds

Measured, not hoped for, twice on this tree:

| run | last serial write → run ended | archive's dead wait |
|---|---|---|
| `out/a8-repro/repro-trial05/` | **23.69 s** | 8 738.19 s |
| `out/ntasm-house/20261022T133548Z-db54d2d1/producer/` | **21.6 s** | — |

The poll is read-only (`info status` on the HMP monitor), at most once every
5 s, it never resumes or resets a paused guest, and it is fail-closed: a
stale, malformed or unavailable observation never accepts the success markers,
and an unreadable state is recorded as `unknown`, never as `running`.

### 5.4 The RAM measurement is retried, and WSL's own budget is smaller than the gate

The transport measures free memory on the **Windows** host while running under
WSL (`powershell.exe` → `Win32_OperatingSystem.FreePhysicalMemory`), because
*"Under WSL the guest sees the Linux memory, not the Windows memory QEMU
actually uses"*. That call is retried: up to **3 attempts**, **120 s** each,
**2 s** apart, and only after all three fail is the measurement a refusal
(*"cannot measure RAM: powershell failed after 3 attempts"*). A busy Windows
host can therefore make a start slow, and a persistently slow CIM call refuses
the run rather than starting it unchecked. Two consequences for the plan:
budget the start generously, and note that the WSL VM itself holds only ≈5 GiB
total (`free -g`: total 5, available 3) while the gate watches the Windows
host's 10–12 GiB — **the 8 GiB stop threshold cannot fire on WSL memory
pressure**, it can only fire on host pressure. A WSL OOM would arrive as a
guest that stops writing, not as a tripped guard. That asymmetry is another
reason the trial-05 stop cannot be dismissed as "RAM": in both reproductions
the guard never tripped and free memory *rose* (12.18 → 13.44 GB).

### 5.5 The expected-producer digest was carried over from the stage, and it is a C-loader-era digest

The manifest's `expected_producer_sha256` (`190cb8b1…`) is the digest of the
archive's producer output, produced from the **stage's** producer package
(`1e57647d…`, 1 665 352 B) **by the C loader**. **This tree's producer package
is different**: `a5f4f2ee…`, 1 665 633 B, because **25 of the 52 producer
sources differ** — and the difference is **comments only** (path references
inside the `.nova` comments; every file keeps the same line count, and a
line-by-line comparison with all full-line comments stripped shows **no**
difference in any of the 108 pinned sources). The produced binary does not
embed the source bytes (neither the bundle digest nor any source path appears
in the archive's produced PE).

So when the transport eventually completes the producer step, the comparison
against `190cb8b1…` is an **expectation, not a fact**, and the most likely
place where it surprises. **If the build fails with "the extracted OUTPUT.EFI
is X, the expected producer is 190cb8b1…"**, the correct reading is *the
external expectation is stale for this tree*, **not** "the transport is
broken" — and the correct response is to establish the new digest **from
outside the build** (never by re-pinning it from the build's own output; the
builder's own note says *"expected_producer_sha256 comes from outside this
build and was never repinned from the output"*). The same applies to the
compiler bundle (`3dbdea63…` here vs `f7879463…` at the stage): in
`selfhost`, N1 and N2 are both produced from this tree's package, so
N1 == N2 is unaffected by the carry-over — but N1 == the pinned seed is an
observation, and if the seed's own bytes no longer reproduce from this tree's
compiler closure, that observation flips to `false` and **that is a finding
about the tree, not a failed test**.

### 5.6 The builder's own refusal surfaces are cheap; use them

Every one of these is a refusal with exit 78 and a named class, before any
QEMU: `manifest-missing`, `manifest-unreadable`, `manifest-schema`,
`manifest-incomplete`, `source-count`, `source-count-mismatch`,
`source-duplicate`, `source-not-in-tree`, `source-not-nova`,
`source-not-ntasm`, `path-escape`, `source-missing`, `source-digest-mismatch`,
`bundle-mismatch`, `seed-missing`, `seed-digest-mismatch`, `not-pe64`,
`image-digest-mismatch`, `source-changed-during-build`,
`seed-changed-during-build`, `lock-unavailable`, `lock-timeout`,
`timeout-out-of-range`, `transport-refused`. A refusal is **not** a failed
run, and the builder keeps that distinction: transport rc 2 → exit 78
(`transport-refused`), transport rc ≠ 0 → exit 1 (build failed). Step A exists
to consume every refusal that can be consumed without a guest.

### 5.7 One QEMU at a time, and one house build at a time

The transport refuses to start while another QEMU is running (it reports the
PIDs and never stops them) — and that refusal already fired once on this
tree (§1.1 item 4). The builder holds
`/tmp/nexora-a7-cpu-safe-gates.lock` (exclusive `fcntl`, 300 s bounded wait)
for the heavy steps. Steps E2 and F must be serialised, and the slot checked
before they start.

### 5.8 One more risk that is not about the transport: the tree's own pin history

The `nova.c` and `nova.h` pins of the legacy C build are stale, and the
discrepancy tool now shows **why**: the content delta between the campaign's
copy and this tree is **paths and comments only, zero code lines**
(`verdict: paths-and-comments-only`, `code_lines: 0`) — the same conclusion
the NVSRC001 comparison of the two producer packages reached. The pins
themselves are **not** updated here: that is the owner's decision, and
`docs/status/a8-pin-discrepancies.md` says so explicitly. A reviewer should
not read the three discrepancies as a broken tree, and no agent should
"fix" them by updating the pin table.

---

## 6. What must NOT be claimed, at each step

**One successful lot is not A8.** A "lot" here is one green execution of one
step. A8 is a contract of four obligations, of which the house build speaks to
one; the other three are the C gates and the S0 fixed point, and the closure
of A8 is the final review's act, not a run's outcome. The campaign itself
recorded, after a *successful* integration: `"A8_formally_closed": false`.

Per step, the sentence that must not be written:

| Step | Never write | Write instead |
|---|---|---|
| A | "the house build is ready" | "the pinned inputs on disk match the manifest and the published seed" |
| B | "the tests pass, so A8 works" | "the house rules and the transport's liveness logic hold on synthetic trees and mocked QEMU" |
| C | "the transport works" | "the transport boots a guest on this host and detects a dead guest in ~15 s" |
| D | "the runtime and the host are built" | "both images rebuild byte-identically to their pins" |
| E | "the producer is self-hosted" / "A8 is proven" | "the producer step **fails reproducibly at batch 16**; the failure is now detected in 21.6 s instead of 8 738 s of dead waiting" |
| E2 | "the word-wise zeroing is the cause" (before the run) | "run B changes exactly one image; its outcome decides whether the cause is the runtime image or what both images share" |
| F | "A8 is closed" / "A8 is done" | "the producer reproduces itself byte for byte over the house chain" — the closure is the reviewer's, and the C bootstrap is still the principal build of this snapshot |

**And A8 is not A9.** A9 is the usable tool — delivery manifest, installation,
the final binary — and it is explicitly *after* A8
(`docs/status/ntasm-a9-acceptance.md`). A green step F starts nothing in A9.

Three more sentences that must not appear anywhere in this campaign's reports:

- *"the guest stopped because of X"* — unless the bisection has produced X
  (§5.1, §5.2). The current state is: **it stopped, deterministically, and the
  cause is not established.**
- *"the build is reproducible"* — before the artifact exists. The archive's own
  `REPLAY.md` limit paragraph says the S0 producers are *"the result, not an
  independent input"*, and the same discipline applies here.
- *"the producer is fixed point"* / *"the self-host is proven"* — the archive's
  fixed-point runs were made by the **C loader**, not by this transport
  (§2, step F). No producer compile has ever completed through the transport.

---

## 7. The commands this plan uses, and how each was checked

Every command below exists in this repository, with the flags used. The checks
were read-only (`--help`, `--version`, `grep`, `sha256sum`, `ls`) or ran only
the pure unit suites and the read-only tools; **no build was run and no QEMU
was started by the writing of this document** (the heavy run of §2 step E was
run by the lead, and its evidence is read here).

| Command | Checked by | Result |
|---|---|---|
| `python3 scripts/ntbuild_house.py --help` | run | lists `build, policy, pins, selftest, selfhost, check`; `--repo`, `--timeout`, `--seed-dir` |
| `bash scripts/ntbuild_house.sh --help` | run | usage text; `NG_REPO`, `NG_PYTHON`, `NG_SEED_DIR` |
| `python3 scripts/nova_native_transport.py --help` | run | `--repo --work-root --name --qemu --code --vars --timeout`; modes `assemble, selftest, run` |
| `python3 scripts/ntbuild_house.py policy` | run | `NTHOUSE-POLICY/1`, exit 78 refusal classes, seed rule, NVSRC001 bounds, RAM gate 9/8 GiB, lock path and 300 s wait |
| `bash scripts/ntbuild_house.sh pins` | run | `NTHOUSE_PINS_VERIFY ok=110 bad=1` — the one bad is the seed (`DIFFERS seed`) |
| `… pins --seed-dir /mnt/c/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01/bootstrap/nova-native` | run | `NTHOUSE_PINS_VERIFY ok=111 bad=0`, exit 0 |
| `bash scripts/ntbuild_house.sh check compiler/nova/frontend/ast.nova` | run | `NTHOUSE_ALLOWED class=allowed` (nested `.nova` under `compiler/nova`) |
| `bash scripts/ntbuild_house.sh check compiler/c/nova/frontend/nova.c` | run | `NTHOUSE_REFUSED class=quarantine-source` |
| `bash scripts/ntbuild_house.sh build --seed-dir /tmp` | run | `NTHOUSE_REFUSED class=seed-missing` (exit 78) — the flag is accepted and the seed rule fires |
| `bash scripts/ntbuild_house.sh selfhost --seed-dir /tmp` | run | same refusal; `selfhost` accepts the flag |
| `python3 scripts/ntbuild_house.py build --timeout 5 --seed-dir /tmp` | run | `NTHOUSE_REFUSED class=timeout-out-of-range` — the 10..10800 bound is enforced |
| `python3 scripts/ntbuild_house.py selftest` | run | `Ran 67 tests … OK` → `NTHOUSE_SELFTEST tests=67 failures=0 errors=0` |
| `python3 -m unittest discover -s scripts/tests -p "test_ntbuild_dispatch.py"` | run | `Ran 15 tests … OK` |
| `python3 -m unittest discover -s scripts/tests -p "test_ntbuild_*.py"` | run | `Ran 82 tests … OK` |
| `python3 -m unittest discover -s tests/transport -p test_nova_native_transport.py` | run, with `GIT_DIR` exported | `Ran 160 tests … OK (skipped=4)` |
| the same with `A8_ARCHIVE_ROOT=/mnt/c/NexoraGenesis/out/a8-selfhost-20261015` | run, with `GIT_DIR` exported | `Ran 160 tests … OK (skipped=1)` |
| the same **without** `GIT_DIR` | run | `FAILED (failures=1, skipped=4)` / `(failures=1, skipped=1)` — the one failure is `test_the_pin_of_nova_h_designates_a_real_revision`, because this worktree's `.git` names a Windows path WSL's `git` cannot resolve; with `GIT_DIR` exported the tool finds revision `87472cd778d320726d8222f639007b17887d73d9` (`bootstrap/quarantine/c/nova.h`, 1018 B) and the test passes |
| `bash scripts/ntbuild.sh policy` | run | `NTBUILD-POLICY/1`, 17 granted units, 78 refusal exit |
| `bash scripts/ntbuild.sh pins --verify` | run | `NTBUILD_PINS_VERIFY ok=32 bad=3 rows=34` (the three known discrepancies) |
| `bash scripts/ntbuild.sh census` | run | `NTBUILD_CORPUS_CENSUS pinned=9 excluded=3 files=12 bad=0` |
| `bash scripts/ntbuild.sh corpus` | run | the 8 pinned corpus rows |
| `python3 tools/validation/a8_manifest.py` | run | prints the manifest JSON; stderr gives the two bundle digests and the external seed/expected digest; exit 0 |
| `python3 tools/validation/a8_run_evidence.py <producer dir>` | run | JSON: `batches_completed: 16`, `stopped_in: "LOWER"`, `ram_tripped: false`, `ram_polled: 2135` |
| `python3 tools/validation/a8_pin_discrepancies.py --archive-root /mnt/c/NexoraGenesis` | run | the three discrepancies, both stale pins `verdict: paths-and-comments-only` with `code_lines: 0`, exit 1 |
| `bash tests/transport/a8_live_check.sh` | **not re-run** (it starts QEMU) | already performed 2026-10-22; evidence in `out/a8-live/{live-green,live-red}` and tabulated in `docs/status/a8-native-transport.md` |
| `bash scripts/ntbuild_house.sh build --seed-dir <archive>/bootstrap/nova-native` | **flags checked; the run itself was executed by the lead** | `out/ntasm-house/20261022T133548Z-db54d2d1/` — runtime and host byte-identical to their pins, producer step failed at batch 16 with `paused (shutdown)`, no `build.json` |
| `bash scripts/ntbuild_house.sh selfhost --seed-dir <archive>/bootstrap/nova-native` | **flags checked, not run** | the heavy command of step F — never run, blocked behind E2 |
| the bisection run B of step E2 | **read, not run** | `docs/status/a8-trial05-bisection.md` §"Run B" |

Supporting facts used above, and where they were measured:

| Fact | Measured by |
|---|---|
| QEMU 8.2.2 (Debian), 4 CPUs, `mtools`, `powershell.exe` | `qemu-system-x86_64 --version`, `nproc`, `which` |
| firmware present: `OVMF_CODE_4M.fd` 3 653 632 B, `OVMF_VARS_4M.fd` 540 672 B | `ls -l /usr/share/OVMF/` |
| free RAM on the Windows host 10.4–12.4 GiB across three calls; WSL itself ≈5 GiB total | the transport's `measure_free_memory()`; `free -g` |
| archive digests: seed `6ab3b02d…`, host `9b3509ec…`, runtime (word-wise) `413b7816…`, runtime (byte-wise) `17fd29cd…`, expected producer `190cb8b1…`, stage producer package `1e57647d…` | `sha256sum` of the archive files; `inputs.json` of the failing runs |
| this tree's packages: compiler `3dbdea63…` (1 965 761 B), producer `a5f4f2ee…` (1 665 633 B) | the builder's own `pack_nvsrc001()`, re-run here; equal to the manifest |
| 25 of 52 producer sources and 26 of 56 compiler sources differ from the stage, **comments only** | byte comparison against the stage's manifest, plus a line-by-line diff with full-line comments stripped: zero differences in code across all 108 pinned sources |
| the tree's heavy run: 16 batches in 2 097.6 s (131 s/batch), stop detected 21.6 s later, RAM 12.18 → 13.44 GB, no `build.json` | `out/ntasm-house/20261022T133548Z-db54d2d1/producer/{serial.log,boot-result.json,transport-result.json}` and the file mtimes |
| the reproduction: 16 batches, stop detected 23.69 s after the last write | `out/a8-repro/repro-trial05/` and `docs/status/a8-trial05-bisection.md` |
| the archive's fixed-point pairs (`p1-11`/`p2-04` = `6ab3b02d…`, `from-p1-01`/`from-p2-02` = `190cb8b1…`) were produced by the **C loader**, not by the transport | `NATIVE_PE_RUN status=ok … source_not_compiled_by_C=yes` in their `run.log`; no `boot-result.json` in either directory |
| the legacy C pins: 3 discrepancies, content delta paths-and-comments-only | `bash scripts/ntbuild.sh pins --verify`; `tools/validation/a8_pin_discrepancies.py` |

---

## 8. The one-paragraph version

Cheap first: the inventory, the policy and the pins (read-only), then the unit
suites (mocked QEMU, with `GIT_DIR` exported under WSL), then the transport's
bounded live check (already green and red, ~35 s). Then the two **assembles
alone** — already done and **green**: both images rebuild byte-identically to
the manifest's pins in ~5.5 s each. Then the **producer step**, already done
and **red**: it stops at batch 16, LOWER phase, `paused (shutdown)` measured
by the monitor, detected in 21.6 s instead of 8 738 s of dead waiting, with
this tree's own regenerated producer package — so the failure is
deterministic, and the cause is still unknown. The next heavy run is the
**bisection** (one variable: the byte-wise runtime image `17fd29cd…` instead
of the word-wise `413b7816…`, 10 800 s budget, stopped through its own HMP
quit), and only after it can the **self-host route** be worth 3 hours, because
it boots the same runtime image in the same guest. The plan's own verdict:
**the contract is proven by the self-host step and by nothing else**; one
green lot is not A8; A8 is not A9; and today the chain is red at the producer
step, one bisection away from its next decision.
