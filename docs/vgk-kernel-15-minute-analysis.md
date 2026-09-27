# Fifteen-minute VGK kernel capture — 2026-09-27

The corrected kernel model remained stable across a full fifteen-minute capture,
including almost twelve minutes after the three-minute timer expired. The next
bounded upgrade should make `SystemProcessInformation` use the existing live
process, handle-table, and thread models. Its current process records still
contain fabricated handle counts and thread records on a path VGK repeatedly uses.
This is a consistency defect established by source review, not a demonstrated
cause of a VGK failure. User-mode service startup is outside this analysis.

## Capture provenance

Local evidence directory: `build-conformance/kernel-20260927-122450-517/`.
The manifest records a **900.0825443-second** WHP run starting at
2026-09-27 12:24:50.728 +03:00. The supervisor deliberately stopped it at the
900-second limit; exit -1 is that forced stop, not a natural guest exit.
No emulator process remained afterward.

The executable and runtime DLLs were copied from the completed 210-second
capture `kernel-20260927-121310-132`; no rebuild or production edit was made.
The arguments remained `vgk.sys process_notify_user.exe`. The companion provides
one process creation/exit exercise; this is not a continuous process-churn test.

The frozen executable is generic commit `4008b0c` plus the local-only author
DEBUGCTL compatibility stub, lab commit `6c919b4`. Its SHA-256 is
`990DEC649896CE06C0061F1C14A71CA8CB27D4972B528D64F05736461D5C39FD`.
The stub changes the emulated image, not the driver file on disk. The generic
checkout remained at `6f3e208` during the run.

The driver SHA-256 is
`3CB2F36CF9F3B66BF63561D24649422D852229F2C788A7AAA783752DCE4AB39F`.
The driver, kernel, CI image, companion image, and frozen executable hashes all
matched before and after execution. The manifest also records runtime DLL hashes,
kernel version 10.0.26100.9444, and CI version 10.0.19041.6456.
The stdout SHA-256 is
`3A342E403667FE037F144AE394A2F798443314D2C7584F6D57BB7F769FCEFD58`.

## Completion and reference behavior

| Observation | Completed capture |
| --- | ---: |
| DriverEntry | STATUS_SUCCESS at 12:25:00.893 |
| Attach / detach events | 1,054 / 1,054, zero unmatched parsed events |
| Process-rundown release records | 1,050, all report zero references left |
| Unmatched rundown-release diagnostics | 0 |
| Process-notification BEGIN / END deliveries | 4 / 4 |
| Handled / unhandled exceptions | 608 / 0 |
| API/callback faults / executed unimplemented-function diagnostics | 0 / 0 |
| stderr | Empty |

The release hook is shared by `PsReleaseProcessExitSynchronization` and
`ObDereferenceProcessHandleTable`. The private acquisition hook is not logged,
so release records do not prove an exact acquisition/release census. The separate
conformance fixtures cover pairing. Here, repeated releases remained valid and
the earlier unmatched-release diagnostic did not recur.

The only three error-level records are the existing optional hook-symbol misses
for KeRaiseIrql, KfLowerIrql, and KeRaiseIrqlToSynchLevel. There are 601 repeated
access violations at `vgk.sys+0x377530`, matching 601 KdChangeOption calls; they
are handled. This remains a debugger-sensitive path, not evidence of complete
hardware fidelity or a reason by itself to prioritize software LBR/BTF modeling.

## Timer expiration and periodic workers

Timer `0xFFFFF80001B8E850` expired at **12:27:52.632**. Its first observed true
read was at **12:27:52.806** (stdout line 28564); 484 true reads followed in total.
There were 115 false reads before that transition. The phase split below uses
the first true read and excludes driver initialization from the cadence samples.

| Worker | Post-init observations used | Median interval before / after first true read |
| --- | --- | --- |
| TID 184: timing/shared state | 1,729 shared-lock acquisitions | 514 / 514 ms |
| TID 192: debugger/timer probe | 568 single-object wait records | 1,518 / 1,518 ms |
| TID 188: process audit | 29 single-object wait records | 30,192 / 30,186 ms |

TID 184 also logged 3,458 performance-counter reads and 1,729 corresponding
shared-lock releases after initialization. No exact KeDelayExecutionThread call
record is emitted in this capture, so its cadence is measured from lock records.
The post-init interval ranges are 501–623 ms for that worker, 1,505–1,864 ms for
TID 192 waits, and 30,143–30,358 ms for TID 188 waits. Logged call intervals are
not measurements of the underlying wait duration.

TID 188 performed **30 sweeps totaling 1,230 process lookups** across the full
capture: one sweep before DriverEntry returned and 29 afterward. Independent
grouping by gaps exceeding ten seconds verified that every sweep contains 41
lookups, 35 attachments, 35 detaches, and 35 rundown releases. The 24 sweeps after the first true timer
read account for 984 lookups, 840 attaches, 840 detaches, and 840 releases.
TID 188 also runs the debugger probe once per sweep; it is not confined to TID 192.

The timer now genuinely expires. Its expiration produced no visible change in
these API-level cadence patterns. That does not establish that internal VGK
state or untraced instruction paths stayed unchanged.

## Allocation and host-resource behavior

The logged pool calls contain 3,011 allocations and 1,188 frees. Reconstructing
their address/size lifetimes gives **1,823 outstanding allocations totaling
24,801,152 bytes**, both at DriverEntry return and at capture end. All allocations
still outstanding at the end originated before DriverEntry returned. There are
no unmatched frees, overlapping live allocation addresses, or size mismatches
in this reconstruction.

The supervisor sampled host resources every 15 seconds, yielding 60 samples.
From the first post-startup sample to the last, working set increased by only
53,248 bytes and private bytes decreased by 143,360 bytes. Final sampled private
bytes were 486,952,960; host handles settled at 289. There is no sustained growth
signal in these sampled host metrics or the logged outstanding pool footprint.

These are separate measurements. Pool reconstruction covers only the logged
ExAllocatePool/ExFreePool paths. Host handles are not guest handles. Retained
backing pages, every guest allocation source, and a live guest handle census are
not available from this trace; the forced stop also prevents a shutdown-leak test.

## Warning interpretation and the next upgrade

The 492 failed physical translations are consistent with recursive page-table
slot discovery: addresses are `n * 0x8040201000` for n=1 through 492, then n=493
(`0x1ED`) succeeds at `0xF6FB7DBED000`, translating to root `0x100000000`.
The startup trace and `x86_win_emulator::install_self_map` identify the same slot
and root. They are not evidence of 492 missing legitimate mappings.

CI, firmware, storage, and the physical-memory resource key retain the bounded
behavior seen in the short capture. CI has two trusted SHA-256 verdicts and six
digest/algorithm mismatches with offline revocation unchecked. BootCurrent and
Boot0000 succeed. The modeled disk dispatches requests; the eight opens for
unmodeled PhysicalDrive1–4 remain absent. Those observations do not indicate a
new runtime regression.

The actionable inconsistency is in
[`nt_sysinfo_ops.cpp`](../src/kernel/win/modules/nt_sysinfo_ops.cpp), where the
SystemProcessInformation builder sets `handle_count = 32`,
`number_of_threads = 1`, and a fabricated thread ID of `pid + 4`. The capture
contains **32 successful process snapshots**, each reporting 41 processes.
Thus, real handle-table and thread lifecycle state coexist with synthetic
enumeration records on an exercised interface. The trace does not establish
which individual record fields VGK consumes.

Recommended next pass: **coherent process/thread system-information snapshots**.

1. Derive process handle counts and owned thread records from the same models
   already used for handle operations and lifecycle transitions.
2. Preserve thread ownership across attachment, and publish consistent identities
   for explicitly modeled seeded processes/threads instead of inventing IDs in
   the query handler.
3. Make required buffer sizes, entry offsets, and names follow the actual snapshot;
   preserve safe buffer-probing and concurrent lifecycle behavior.
4. Verify open/duplicate/close count changes, thread creation/exit, process exit,
   attachment ownership, and query-size retry behavior with focused fixtures.
   Add bounded diagnostic counts if needed to make subsequent target captures
   measure the same invariants.

This scope closes a concrete contradiction in existing kernel state. No new
architectural implementation was made during this analysis pass.

## Retained analysis artifacts

The capture directory contains `manifest.json`, `stdout.log`, `stderr.log`,
`host-telemetry.jsonl`, `physical-memory-summary.json`, `resource-analysis.json`,
`worker-analysis.json`, and `phase-comparison.json`. Independent verification
checked the completed manifest, hash stability, pool accounting, and failure
counts. The worker parser was also checked against the preceding completed
210-second capture. Analysis helpers and raw captures remain local under the
ignored `build-conformance/` directory.
