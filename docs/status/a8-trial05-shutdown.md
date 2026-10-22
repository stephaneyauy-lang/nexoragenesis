# A8 trial 05: what the archived evidence says about the guest shutdown

**The cause of the guest shutdown is not established by the archive.** This
document states what the raw evidence does establish, what it refutes, and
what it leaves open. Nothing here is a claim about A8 being complete.

Everything below is read from the archived evidence, read only, and it is
re-derived by a tool in this repository:

```bash
python tools/validation/a8_run_evidence.py <run-directory> [<run-directory> ...]
```

The reader is `tools/validation/a8_run_evidence.py`. It opens the files of a
run directory, prints JSON, writes nothing and starts no process.

## Which run this is

`CURRENT-A8.json` (the state file of the campaign, dated 2026-10-21T17:05:24Z)
names the trial: `house-integration-20261021-05/result.json or failure.json`,
and `out/house-build-05.log` of the house stage points at the step that
failed:

```
NTHOUSE_FAILED
  reason:  the transport failed on producer (rc=1): NOVA_TRANSPORT_FAILED boot failed;
           inspect .../out/ntasm-house/20261021T170311Z-82584f32/producer/boot-result.json
```

So the trial-05 failure is the **producer** step of the house run
`20261021T170311Z-82584f32`, under
`house-stage-20261021-01/out/ntasm-house/20261021T170311Z-82584f32/producer/`.
The same run directory is where the serial log quoted by the brief lives.

The images of that run, from its own `inputs.json`:

| ESP name | bytes | sha256 |
|---|---|---|
| `EFI/BOOT/BOOTX64.EFI` | 11776 | `9b3509ec28ca705fdaec2c95e2221d28d2f8793cb7fcc308986899c94b57dad2` |
| `NVRUNTIME.EFI` | 8704 | `413b78160f34609a0d23f3cedb0308118483eb6204cc60e2f6795dc593e2c4b8` |
| `NOVACORE.EFI` | 9943552 | `6ab3b02dac3d5c833d1a19e3ef54fcd6fb804779a907f6dbf7e1bc4b9aba7891` |
| `NOVA.IN` | 1665352 | `1e57647d50429995207aac1700edaa4037f07c1cf08b9ba576847500e1cb49cc` |

`NOVACORE.EFI` is the P2 Nova compiler of the campaign
(`CURRENT-A8.json` `nova_fixed_point.p2`), and `NOVA.IN` is the 1.6 MB source
bundle it was compiling.

## What the guest did, and when it stopped

The serial log of the run ends with:

```
NG_NOVA_BATCH_OBJECT_END 15
NG_NOVA_BATCH_LOWER_BEGIN 16
```

Sixteen batches (0 to 15) completed, each with its LOWER and OBJECT phase.
The last line is the opening of the LOWER phase of batch 16, with no
`LOWER_END 16` behind it. The terminal marker `NG_NV2_NATIVE_RUN_OK` never
appeared (`marker_exact_once: false`), and no firmware return was recorded
(`firmware_return: false`).

The transport facts of the same run (`boot-result.json`,
`transport-result.json`): the RAM guard never tripped and the free memory
**rose** during the run (16.8 GB to 19.5 GB), the cleanup was clean
(`exit_code: 0`, `shutdown: "hmp"`, `forced: false`), and the run ended with
`"pass": false`.

**When the guest stopped:** the last write of its serial log is at
**2074 s** after the start of the run (the run directory name carries the
start stamp `20261021T170311Z`; the mtime of `serial.log` is its last
write, and reading a file does not change its mtime). The transport then
waited for its whole budget: 2135 RAM polls at 5 s, that is **10675 s**. So
**about 8601 s, two hours and twenty-three minutes, were spent waiting for a
guest that was already gone.** That is the measured "the parent waited until
timeout and the UI showed waiting".

The guest was not slowing down before it stopped: sixteen batches in 2074 s
is 130 s per batch, against 98 s per batch in the run before it and 186 s
per batch in the run of 14:37. It stopped hard, in the middle of a batch.

## The five producer runs of that day

The same reader over the five producer runs of the stage, all of them
compiling the same `NOVA.IN` and the same P2 compiler:

| run | batches | stopped in | guest stopped at | transport waited | dead wait | host | runtime |
|---|---|---|---|---|---|---|---|
| 13:53:09Z | 1 | OBJECT | 245 s | 980 s | 735 s | `db85a53a` | `17fd29cd` |
| 14:14:50Z | 13 | LOWER | 983 s | 960 s | -23 s | `9b3509ec` | `17fd29cd` |
| 14:37:38Z | 19 | OBJECT | 3527 s | 3565 s | 38 s | `9b3509ec` | `17fd29cd` |
| 16:22:08Z | 15 | LOWER | 1470 s | no record | - | `9b3509ec` | `413b7816` |
| 17:03:11Z | 16 | LOWER | 2074 s | 10675 s | **8601 s** | `9b3509ec` | `413b7816` |

Read with care, the five runs are not five instances of the same thing. The
run of 14:37 was **still working** when its own deadline arrived (38 s of
dead wait, the guest was writing until the deadline). The run of 16:22 was
stopped by the user, and it has no `transport-result.json`, so its waiting
time is unknown, not zero. The run of 14:14 shows a **third** symptom: its
serial ends with the firmware loading `Boot0002 "EFI Internal Shell"`, so
the guest had *returned to the firmware* without a terminal marker and the
firmware moved on to the next boot option. That leaves two runs where the
guest stopped by itself: the run of 13:53 and the run of 17:03.

## What the evidence refutes

**The firmware watchdog is not the cause of the trial-05 stop.** The host of
the failing run is byte-identical to the image the watchdog proof certified
(`watchdog-20261021/result.json`: `normal_host_sha256` is
`9b3509ec28ca705fdaec2c95e2221d28d2f8793cb7fcc308986899c94b57dad2`), and
that host source (`toolchain/nova-runtime/uefi-host-s0.ntasm`, sha256
`a2b8b4dc…`) carries the fix that disables the UEFI platform watchdog before
any long step:

```
; Disable the firmware watchdog before any long step: UEFI 2.10 sec 7.5.1
; SetWatchdogTimer(Timeout=0) stops it.
load64 rax, [r13 + 256]
...
mov rcx, 0
mov rdx, 0
call rax
```

The only `VM status: paused (shutdown)` transcript in the archive
(`watchdog-20261021/red-paused-shutdown.txt`) belongs to the **deliberate RED**
case, which was built on the *unfixed* host (`db85a53a`, the host of the
13:53 run). The state was therefore already neutralised when trial 05 ran.

**The RAM guard is not the cause.** It never tripped, and the free memory of
the host rose during the run.

**A CPU level fault is not recorded.** The `qemu.log` of the failing run
(the `guest_errors` log) is byte-identical to the one of the healthy runs:
the same six `Invalid read at addr 0xFED40000` lines, which are the OVMF
platform-watchdog MMIO accesses. There is no triple fault and no exception
in it. The guest powered off in an orderly way, which is also what the house
build saw: the stage carries `close_paused_vm.py`, whose own comment reads
*"Sent HMP quit to our paused shutdown VM only"*.

## The one change that coincides with the stop

Between the run of 14:37, which kept going, and the run of 17:03, which
stopped, the **runtime** changed. The diff of the two runtime sources is one
hunk: the pool zeroing became word-wise.

```
 nv_pool_zero:
+cmp rsi, 8
+jae nv_pool_zero_word
+cmp rsi, 0
+je nv_pool_count
+nv_pool_zero_tail:
 store8 [rdi], rdx
 add rdi, 1
 sub rsi, 1
-jne nv_pool_zero
+jne nv_pool_zero_tail
+jmp nv_pool_count
+nv_pool_zero_word:
+store64 [rdi], rdx
+add rdi, 8
+sub rsi, 8
+jmp nv_pool_zero
```

Runtime source `486ce6f1` (run of 14:37) to `0c768e48` (run of 17:03). This
is the "word zeroing" optimisation of the campaign, and its own proof
(`zero-speed-20261021-05/integration.json`) says plainly what was measured
and what was not:

```json
{"microbenchmark_seconds": [27.072330077, 22.455829697],
 "fullbuild_gain": "not measured",
 "after": "0C768E4823279E4F…", "before": "486CE6F12ABB6AC1…",
 "file": "toolchain/nova-runtime/runtime-v2-s0.ntasm"}
```

The optimisation was integrated on a microbenchmark (77 runtime checks, zero
lengths 0 to 65, 128 allocations of 32 MiB) and on a mutant that the probe
caught, and the full build was never measured. The run of 17:03 is the first
full build that used it, and it is the run that stopped.

**This is a coincidence in time, not a demonstrated cause.** The run of
16:22 used the same runtime (413b7816) and completed fifteen batches before
the user stopped it, so the new zeroing path was exercised for a long time
without a stop; and the stops of the other runs fall in both phases. The
archive cannot say which batch the guest was on when it powered off beyond
the index 16, and it holds no guest-side state for that moment.

## What is still unknown, and what would settle it

The archive does not hold the guest's own state when it powered off: the
transport of that day recorded no VM state at all, and the guest printed no
error marker. The candidates the evidence does not exclude are a guest-side
fault handled by the runtime as a shutdown, a guest allocation failure at
512 MiB, and a defect of the new zeroing path that only a particular batch
size reaches.

Three measurements would settle it, and none of them is possible without
the heavy checks:

1. **One failing house trial with the liveness poll of this branch.** The
   transport now records the VM state, the HMP transcript, the last serial
   line and the wait it spent, in `boot-result.json` and `hmp-liveness.log`.
   The reader above turns them into facts.
2. **A bisection of the runtime change.** Reverting the word-wise zeroing
   and running the same producer step would either reproduce the stop or
   exclude it. That is a house-build task, not a reader task.
3. **The guest's own memory behaviour.** The guest has 512 MiB and the
   project records elsewhere a Nova allocation refused under 1 GiB. Nothing
   in the archive measures the guest's heap across the batches.

## Reproducing the facts in this document

```bash
python tools/validation/a8_run_evidence.py \
  "C:/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01/out/ntasm-house/20261021T170311Z-82584f32/producer" \
  "C:/NexoraGenesis/out/a8-selfhost-20261015/house-stage-20261021-01/out/ntasm-house/20261021T143738Z-1c413f15/producer"
```

The same facts are asserted by the test suite
(`tests/transport/test_nova_native_transport.py`, class
`ArchivedRunEvidenceTests`), which is skipped when the archive is not on the
machine.
