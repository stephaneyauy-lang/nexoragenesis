# A8 trial 05: the bisection that would settle the cause

**The cause of the trial-05 guest stop is NOT established.** This document
states what is now measured, what the single remaining variable is, and the
two runs that would settle it. Nothing here is a claim about A8 being
complete, and nothing here is a claim that the word-wise zeroing is the
cause: the reproduction says the opposite of what the correlation suggested.

Every number below is measured from a file on disk, and the basis is named so
a reviewer can recompute it. The archive
(`C:\NexoraGenesis\out\a8-selfhost-20261015` and its tree `C:\NexoraGenesis`)
is READ ONLY; the reproduction evidence is in this repository under
`out/a8-repro/repro-trial05/`.

## 1. What the reproduction shows: the stop REPRODUCED

The reproduction ran the **exact four images of the failing archived run**,
with the transport of this branch (the one that polls the monitor). It
stopped at the **same batch and the same phase** as the archive, and the
monitor recorded **why** the guest went away — something the archive could
not record, because the transport of that day had no liveness poll.

The four inputs, from the reproduction's own `inputs.json`, are byte
identical to the archived run's `inputs.json`:

| ESP name | bytes | sha256 | role |
|---|---|---|---|
| `EFI/BOOT/BOOTX64.EFI` | 11776 | `9b3509ec28ca705fdaec2c95e2221d28d2f8793cb7fcc308986899c94b57dad2` | host (watchdog-disabled, certified) |
| `NVRUNTIME.EFI` | 8704 | `413b78160f34609a0d23f3cedb0308118483eb6204cc60e2f6795dc593e2c4b8` | runtime (word-wise zeroing) |
| `NOVACORE.EFI` | 9943552 | `6ab3b02dac3d5c833d1a19e3ef54fcd6fb804779a907f6dbf7e1bc4b9aba7891` | P2 Nova compiler seed |
| `NOVA.IN` | 1665352 | `1e57647d50429995207aac1700edaa4037f07c1cf08b9ba576847500e1cb49cc` | the 1.6 MB source bundle |

The reproduction's serial log ends with the same last line as the archived
one, `NG_NOVA_BATCH_LOWER_BEGIN 16` — sixteen batches (0..15) done, the
LOWER phase of the seventeenth opened and never closed:

```
$ tail -5 out/a8-repro/repro-trial05/serial.log
NG_NOVA_BATCH_LOWER_BEGIN 15
NG_NOVA_BATCH_LOWER_END 15
NG_NOVA_BATCH_OBJECT_BEGIN 15
NG_NOVA_BATCH_OBJECT_END 15
NG_NOVA_BATCH_LOWER_BEGIN 16
```

**The new fact: the guest powered off, and the transport saw it.** The
reproduction's `boot-result.json` carries the liveness block the archived
run had no equivalent of:

```json
"liveness": {
  "polled": 435, "unavailable": 0, "malformed": 0,
  "fatal": true, "state": "paused", "reason": "shutdown",
  "detail": "the monitor reported VM status: paused (shutdown)",
  "confirmed": false
},
"exit_code": 0, "shutdown": "hmp", "forced": false,
"failure_reason": "the monitor reported VM status: paused (shutdown); the guest VM is gone and the serial log cannot make the proof true"
```

The last poll of `hmp-liveness.log` (poll 435 of 435) reads
`VM status: paused (shutdown)`; the 434 before it read
`VM status: running`. The guest was alive and running up to a moment before,
then went to `paused (shutdown)` on its own. **The guest did not hang and
did not fault: it powered itself off, in the middle of the LOWER phase of
batch 16, at the same place the archive recorded the silence.**

That state is worth stating precisely, because it is the whole new
information: `paused (shutdown)` is what QEMU reports when the **guest
requests a shutdown** (UEFI `ExitBootServices` + shutdown, or an ACPI/PM
power-off), **not** a hang, **not** a triple fault, and **not** the
firmware watchdog. The archived run's own `qemu.log` (the `guest_errors`
log) is byte identical to the reproduction's:

```
$ diff out/a8-repro/repro-trial05/qemu.log <archive>/producer/qemu.log && echo IDENTICAL
IDENTICAL
```

Six `Invalid read at addr 0xFED40000` lines, the OVMF platform-watchdog
MMIO accesses, and nothing else. No CPU-level fault, in the archive or in
the reproduction.

### The timings, and where the dead wait went

The dead-wait figures in circulation differ because they are measured from
different anchors. Here are the anchors, so a reviewer can recompute:

| measurement | archive (`20261021T170311Z-82584f32/producer/`) | reproduction (`out/a8-repro/repro-trial05/`) |
|---|---|---|
| anchor (QEMU launched) | `qemu.command.json` mtime 19:03:23.295 | `qemu.pid` mtime 2026-10-22T12:58:34.758Z |
| last serial write | `serial.log` mtime 19:37:45.281 | `serial.log` mtime 2026-10-22T13:34:46.522Z |
| transport gave up | `boot-result.json` mtime 22:03:23.466 | `boot-result.json` mtime 2026-10-22T13:35:10.213Z |
| guest stopped writing at | t+2061.99 s | t+2171.76 s |
| transport gave up at | t+10800.17 s (exactly the timeout cap) | t+2195.45 s |
| **dead wait** | **8738.19 s** (2 h 25 min 38 s) | **23.69 s** |

So the archived run consumed **exactly** its 10800 s timeout: the guest was
gone from t+2062 s and the transport, which had no monitor poll, sat and
waited for another 8738 s. The reproduction, with the 5 s monitor poll of
this branch, saw the dead guest **23.69 s** after the last write (the
cadence is 5 s; the extra time is the guest's own power-off latency). That
is the one thing the liveness poll buys: **the same failure is now
reported in seconds instead of two and a half hours**, and the VM state at
the moment of the stop is written down.

### What this changes about the hypothesis

The archive could not tell a hang from a power-off. The reproduction says
it was a **power-off, at the same batch, with the same inputs**. So:

1. **The stop is deterministic and input-determined.** The same four images
   stop at the same batch. It is not a timing accident of one host.
2. **The word-wise zeroing is NOT refuted by this** — but it is no longer
   the only candidate. A guest that powers itself off is a guest that
   *reached a conclusion*: something in the guest decided to stop. That is
   a different failure class from "the zeroing corrupted the heap".
3. The archived evidence already contains a run that reached **batch 19**
   and was still writing when its own deadline arrived
   (`20261021T143738Z-1c413f15/producer`, 3527 s of writing, dead wait
   only 38 s). That run used the **byte-wise** runtime image `17fd29cd`.
   So the byte-wise image has demonstrably gone further than the word-wise
   one. This is the correlation the bisection now tests directly.

## 2. The one variable that is still open

The failing run and the run that kept going differ in the runtime image and
in nothing else that matters:

| run | host image | runtime image | core image | payload | outcome |
|---|---|---|---|---|---|
| `20261021T143738Z-1c413f15` (kept going) | `9b3509ec` | **`17fd29cd` (byte-wise)** | `6ab3b02d` | `1e57647d` | batch 19, still writing at its deadline |
| `20261021T170311Z-82584f32` (stopped) | `9b3509ec` | **`413b7816` (word-wise)** | `6ab3b02d` | `1e57647d` | batch 16, guest powered off |

Three of the four inputs are equal, one differs. That is exactly the shape
a single-variable bisection needs.

The runtime difference is one hunk in `runtime-v2-s0.ntasm`: the pool
zeroing became word-wise (`store64` while >= 8 bytes left, then a 0..7 byte
tail), source `486ce6f1` -> `0c768e48`.

The **byte-wise source is in the archive** and does not need a rebuild:

- source: `C:\NexoraGenesis\out\a8-selfhost-20261015\house-stage-20261021-01\out\ntasm-house\20261021T143738Z-1c413f15\runtime\source.ntasm`
- sha256: `486ce6f12abb6ac1561fea3ade0898857a260e1a08da91034c65480b6cc78de1`
- (identical copy in the runs `20261021T135309Z-893a6637` and
  `20261021T141450Z-8cec8cec`; the word-wise one is
  `20261021T170311Z-82584f32/runtime/source.ntasm`, sha256 `0c768e48...`)

The **byte-wise runtime image** is in the archive too, built by the same
pinned S0 producers (`compiler-host.NTASM1.EFI`
`82826f458aff21d4f5167b296b56813899ea422caedb9d8fda2d8120a9b4882d`,
`compiler-core.NTASM1.EFI`
`a02425be642b839586593b6b5468bc13f4f85d29a503987aa972e4750d1d428f`):

- `C:\NexoraGenesis\out\a8-selfhost-20261015\house-stage-20261021-01\out\ntasm-house\20261021T135309Z-893a6637\runtime\produced.EFI`
- sha256 `17fd29cd456670041e7b372f30f3bea3b0a17fa3814dec1ba3d722bbf6ebc104`
  (8704 bytes; byte identical to the `20261021T143738Z-1c413f15` copy)

**Run B therefore needs no build and no source edit**: it is the same run
with one image swapped. That is the whole point of keeping the archive's
runtime images.

### The payload is NOT a variable

The payload of the running build differs from the archived one by 281
bytes, and that difference is **only comments**: the channel host unpacked
both payloads in the NVSRC001 layout and diffed them source by source —
52 sources, same order, same root index, **0 changed lines of code**, 144
changed comment lines, every one of them the path reference
`toolchain/ntasm-nova` -> `compiler/nova`. (The running build's payload is
`a5f4f2ee454253eb44e1832fc509194b3d6922985a2aad6f0ef71cacba703624`,
1665633 bytes; the archived one is `1e57647d...`, 1665352 bytes.) Comments
are not code, so the payload cannot explain a difference in behaviour. It
must be recorded as "differs only in comments" so a reviewer does not
mistake 281 bytes for a second variable.

## 3. The runs

Both runs use the transport of this branch, on the same machine, one QEMU at
a time (the transport refuses to start when another QEMU is already
running — `foreign_qemu_pids()`), with the same memory and the same vCPU
count as the failing run (`-m 512M -smp 4`, the transport's `QEMU_MEMORY`
and `QEMU_CPUS` constants).

The RAM guard is the transport's own: it refuses to start below 9 GiB free
and stops the run below 8 GiB free, measured every 5 s. Both runs below
measured 11.4-11.7 GiB free at the start and never tripped it. The
archival run recorded 16.8 GiB at the start and **19.5 GiB** at the end —
free memory *rose*; the guest was not starved.

### Run A — the baseline (DONE)

The baseline is the reproduction that is already on disk: the four archived
images, the current transport. It has been run and it has stopped.

```bash
REPO=/mnt/c/Users/steph/Documents/Codex/2026-10-22/a8-maintenance
S=/mnt/c/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01
RUN=$S/out/ntasm-house/20261021T170311Z-82584f32
python3 $REPO/scripts/nova_native_transport.py \
  --repo $REPO --work-root out/a8-repro --name repro-trial05 \
  --timeout 3000 --code /usr/share/OVMF/OVMF_CODE_4M.fd \
  --vars /usr/share/OVMF/OVMF_VARS_4M.fd \
  run $RUN/host/produced.EFI \
      $RUN/runtime/produced.EFI \
      $S/bootstrap/nova-native/nova-compiler.EFI \
  --payload NOVA.IN=$RUN/pack/producer.NOVA.IN
```

**Outcome: FAILS.** Batch 16, LOWER phase, guest goes to
`paused (shutdown)`, detected 23.69 s after the last serial write. The
evidence is `out/a8-repro/repro-trial05/{serial.log, hmp-liveness.log,
boot-result.json, qemu.log, inputs.json}`.

**What A proves:** the word-wise runtime image `413b7816`, with these three
other images, is **sufficient** to reproduce the stop, on this machine, at
this batch. The failure is deterministic and input-determined.

**What A does not prove:** that the zeroing is what causes it. A shows the
conjunction "these four images" reproduces; it does not isolate which one.

### Run B — the byte-wise runtime, the one variable changed

Identical to run A in every argument but the runtime image, which is the
byte-wise build of the very same source line the archive carries.

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

Before starting it, check the four digests on the command line (the archive
is read only, but a reviewer should read the bytes, not trust the path):

```bash
sha256sum $RUN/host/produced.EFI \
          $BYTE/runtime/produced.EFI \
          $S/bootstrap/nova-native/nova-compiler.EFI \
          $RUN/pack/producer.NOVA.IN
# 9b3509ec28ca705fdaec2c95e2221d28d2f8793cb7fcc308986899c94b57dad2
# 17fd29cd456670041e7b372f30f3bea3b0a17fa3814dec1ba3d722bbf6ebc104
# 6ab3b02dac3d5c833d1a19e3ef54fcd6fb804779a907f6dbf7e1bc4b9aba7891
# 1e57647d50429995207aac1700edaa4037f07c1cf08b9ba576847500e1cb49cc
```

The timeout is **10800 s**, not 3000 s: the point of run B is to see
whether the guest goes *past* batch 16, and the archived byte-wise run
needed 3527 s to reach batch 19 and was still writing. A 3000 s budget
would truncate the very evidence that decides the question. On the liveness
poll, if the guest powers off, the run ends in seconds regardless of the
budget; the budget only bounds the *survival* case.

**Outcomes of B, and what each means:**

| B outcome | what it establishes |
|---|---|
| guest goes **past batch 16** (and keeps going to the end of the build, or well past it) | the **word-wise zeroing image is the cause** of the trial-05 stop, with the host, the core and the payload excluded. The hunk is then the first thing to fix, and its own proof (`zero-speed-20261021-05/integration.json`: `"fullbuild_gain": "not measured"`) is what let it in. |
| guest stops at **batch 16** again, same phase, same `paused (shutdown)` | the word-wise image is **not** the cause: the same stop happens with the byte-wise runtime. The cause lies in something both images share — the host image, the core image, the payload, or the guest's own memory behaviour — and the bisection must move **inside** the guest, not between these images. |
| guest stops at a **different** batch or phase | the stop is not tied to batch 16; the runtime image changes *when* it stops but not *whether*. The cause is a property of the workload that both images share, and the batch index is where the shared defect bites. |

B is worth running whatever it shows. The second row is as decisive as the
first: it moves the investigation from the runtime image to the guest.

### Run C — named by what A and B demand

Run C is **not** fixed in advance: what it is depends on the outcome of B,
and this is the point of the section rather than a gap in it.

**If B goes past batch 16** (the word-wise image is the cause): the cause
is established and run C is no longer a bisection step. It becomes the
**confirmation** run: rebuild the runtime from the byte-wise source with
the current toolchain, into a fresh image, and run the same producer step
with it. That distinguishes "the archived byte-wise image happens to be
good" from "the byte-wise *source* is good", which is the difference
between a lucky artefact and a fix. The rebuild is a house-build task
(`scripts/ntbuild_house.sh`), not a reader task, and it is deliberately
**not** spelled out here as a command: the image that run B uses is already
in the archive, and the reviewer must read the archive, not this document.

**If B stops at batch 16 too** (the runtime image is not the cause): the
next variable is **inside the guest**, and the next step is a guest-side
observation, not another image swap. The archive holds no guest state at
the moment of the stop, and no guest-side error marker was printed (the
14:14 run of the day did print `NG_NV2_NATIVE_BAD`; the failing run printed
nothing). So run C is: **one producer run whose guest writes a marker at
the moment it decides to stop** — the guest must be made to report why it
is powering off, because the only surviving trace of the decision is the
power-off itself. That is an instrumented runtime image, so it is a build
task, and the exact instrumentation is a design for the guest team, not a
file this document may name.

**If B stops at a different batch**: the same as the second row, with the
added constraint that the batch index is a property of the shared defect
and can be used as a second, independent observation.

In every case, run C is a *guest-side* or *rebuild* step, never another
swap between the two runtime images.

## 4. The decision table for A and B

| | **B: byte-wise `17fd29cd`** | |
|---|---|---|
| | goes past batch 16 | stops at batch 16 (or elsewhere) |
| **A: word-wise `413b7816` (DONE: stops at batch 16, `paused (shutdown)`)** | **the word-wise zeroing image is the cause.** The hunk is the defect; its integration proof never measured a full build. Fix the zeroing, re-measure `fullbuild_gain` on the full build, and the trial-05 stop is explained. | **the runtime image is not the cause.** The cause is in what both images share: the host, the core, the payload, or the guest's own memory behaviour. The bisection moves inside the guest (run C). The word-wise hunk is exonerated as the cause and stays a performance change. |

The archived history already fills two cells of this table, which is why
the table is credible rather than hypothetical:

- byte-wise + a **512 MiB** guest + **1 vCPU**: batch 19, still writing at
  the deadline (`20261021T143738Z-1c413f15`) — the "kept going" cell.
- word-wise + **512 MiB** + **1 vCPU**: batch 15, **user-stopped**
  (`20261021T162208Z-017721bb`) — inconclusive by construction, which is
  why it is not evidence of survival. Its `qemu.stderr` reads
  `terminating on signal 15 from pid 411 (python3)`: the user stopped it,
  it did not stop itself.
- word-wise + **512 MiB** + **4 vCPU**: batch 16, guest powered off
  (`20261021T170311Z-82584f32`), and the reproduction of it, again at
  batch 16. A third run of the same inputs (the house build of this tree,
  `out/ntasm-house/20261022T133548Z-db54d2d1/producer`, same runtime image
  `413b7816`, same host `9b3509ec`, same core `6ab3b02d`, payload
  differing only in comments) was killed by its owner at batch 15 with the
  guest still `running` on the last poll, so it is a third observation of
  the same inputs and not a fourth outcome.

Note the vCPU count changes between those archived rows (1 vs 4). It is
**not** a variable of run B: the transport's `QEMU_CPUS` is 4 in both A and
B, so run B changes exactly one thing. The archived rows are listed with
their real configuration so a reviewer does not read a second variable into
them.

## 5. Cost of each run

| run | wall clock | budget | RAM |
|---|---|---|---|
| A (done) | 2195 s total: 2172 s to the last write, 23.7 s to the detection | 3000 s requested; the stop ended it early | 11.4 GiB free at start, 11.5 GiB at the end; guard 9/8 GiB never tripped |
| B | **up to 10800 s** (3 h) if the guest survives; **~2200 s** if it powers off at batch 16, because the liveness poll ends the run in seconds | 10800 s requested | same guard; a surviving guest will keep the RAM measurement running every 5 s |
| C | build/instrumentation time plus one run; not costed here, because C is not a reader task | — | — |

The archived failing run took **2062 s** to reach the stop (from its
`qemu.command.json` anchor) and then **8738.19 s of dead waiting** before
the transport gave up at its 10800.17 s cap (the run's 2135 RAM polls at
5 s span the whole run, which is where the figure "10675 s" in circulation
comes from; it counts from the boot, not from the last write). That is the
cost the liveness poll removes: the transport of this branch reports the
same failure in **23.69 s** and records the VM state that the archive never
captured.

One run at a time: the transport refuses to start while another QEMU is
running, and the house builder holds a CPU gate
(`/tmp/nexora-a7-cpu-safe-gates.lock`) around its own runs.

## 6. The verdict

**The cause is not established.** What is established now:

1. **The failure reproduces.** The same four archived images stop at the
   same batch (16, LOWER phase) on this machine, with the transport of this
   branch.
2. **The guest powered itself off.** The monitor recorded
   `VM status: paused (shutdown)`, not a hang and not a fault. The
   archived `guest_errors` log and the reproduction's are byte identical,
   so no CPU-level fault occurred in either.
3. **The stop is deterministic and input-determined** — the same inputs
   give the same batch.
4. **The word-wise zeroing is a correlation, and now a testable one.** It
   is the only one of the four inputs that differs between the run that
   reached batch 19 and the run that stopped at 16, and the byte-wise
   image is in the archive, so the test costs one 3-hour run and no build.

**What is still missing:** the outcome of run B, and whatever run C it
demands. Until B has run, the statement "the word-wise zeroing stopped the
trial-05 guest" is a hypothesis with a plausible mechanism and a
contradicting archived counter-example (the byte-wise run reached batch
19), not a cause.

**A second, independent thing is missing, and it is the more interesting
one:** the archive never held the guest's own state at the moment of the
stop, and the guest printed no error marker. The reproduction now gives
the VM state, but not the guest's reason for powering off. A guest that
powers off has *decided* to; nothing in the current evidence says what it
decided, and the answer is not in the four images a reviewer can swap. If
run B exonerates the runtime image, the investigation has to move inside
the guest, and that is a harder and more valuable question than the hunk.

## 7. Reproducing the facts in this document

The reproduction evidence (read only):

```bash
cd /mnt/c/Users/steph/Documents/Codex/2026-10-22/a8-maintenance
cat out/a8-repro/repro-trial05/boot-result.json
tail -5 out/a8-repro/repro-trial05/serial.log
tail -8 out/a8-repro/repro-trial05/hmp-liveness.log
diff out/a8-repro/repro-trial05/qemu.log \
  /mnt/c/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01/out/ntasm-house/20261021T170311Z-82584f32/producer/qemu.log
```

The archived facts (read only, digests and the byte-wise source):

```bash
S=/mnt/c/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01
sha256sum $S/out/ntasm-house/20261021T170311Z-82584f32/host/produced.EFI \
          $S/out/ntasm-house/20261021T135309Z-893a6637/runtime/produced.EFI \
          $S/out/ntasm-house/20261021T143738Z-1c413f15/runtime/source.ntasm \
          $S/bootstrap/nova-native/nova-compiler.EFI \
          $S/out/ntasm-house/20261021T170311Z-82584f32/pack/producer.NOVA.IN
```

The companion document `docs/status/a8-trial05-shutdown.md` reads the
archive's evidence and states what the archive alone establishes; this
document adds the reproduction and the bisection.
