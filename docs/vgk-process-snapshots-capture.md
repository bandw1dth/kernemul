# VGK capture after coherent process/thread snapshots

The full 900.050603-second capture completed with successful driver initialization,
32 successful process-information snapshots, balanced process attachments, and
no unhandled exception. The supervisor stopped the process at the configured
limit; exit -1 records that forced stop, not a spontaneous guest failure.
The improved snapshot interface did not produce a visible runtime regression.

## Provenance and scope

The kernel-only WHP capture started on 2026-09-27 at 13:35:17.561 +03:00,
requesting 900 seconds. Local evidence is in
`build-conformance/kernel-20260927-133517-527/`. The sole guest argument is
`vgk.sys`; no user-mode executable or service is launched.

The generic snapshot implementation is local commit `83d8d39`. Lab commit
`b49520d98c30c48a7d69e31dcbd70f341702fc08` adds only the existing author-provided
in-memory DEBUGCTL compatibility stub. It is retained on the local-only branch
`codex/local-process-snapshots-vgk-lab`. Nothing was pushed.

The frozen lab executable SHA-256 is
`110AE21BCD92ECFA5D5CC0F670AD831F4E3674D3CC21C32DF1C0AE6C7625BF9F`.
The generic branch and its previously verified executable
`A51DD8FDE7D8D887F39D490C673BBE571FD51ECAD5DC6A4A138ADA4F2B16AC76`
were restored after the capture launched from its frozen directory.

The target driver SHA-256 is
`3CB2F36CF9F3B66BF63561D24649422D852229F2C788A7AAA783752DCE4AB39F`.
The guest kernel is 10.0.26100.9444, SHA-256
`75665496A75FC020A0573523F3F77D7C719479ACEB5806A98D82FF2D1B5314A1`;
the CI image is 10.0.19041.6456, SHA-256
`22B2642903F1C93CE63E948E5540A4FAA1A65B7D69761F41DE5C817545A249F0`.
The compatibility stub modifies only emulated memory.

`verification.json` confirms all four manifest hashes still match after execution,
stderr is empty, the generic executable is restored, and no emulator process
remains. The frozen stdout has 66,603 lines and SHA-256
`C3539F62324B2F97B5321AF3EBEFE2A1D6B05F4F26679AEA399FAD11F9397D53`.

## Observed initialization and snapshot behavior

DriverEntry returned STATUS_SUCCESS at 13:35:27.735, about 10.174 seconds after
the supervisor started. Two initial successful class-5 queries report 41
processes, four modeled threads, two handles, and 11,872 bytes. The first audit
worker query reports five threads, three handles, and 11,952 bytes. The remaining
29 queries report 41 processes, five threads, and four handles. Thus all 32
successful queries use the modeled thread and handle counts. The baseline's
fixed one-thread-per-process layout occupied 14,784 bytes per snapshot.

Those are aggregate modeled counts, not a claim that the seeded environment
represents every thread of a real Windows installation. Seeded processes without
modeled threads now report zero. The capture logs aggregate counts; the focused
conformance fixtures verify individual identities and ownership across attachment.

The three-minute timer expires at 13:38:19.386; its first observed true read is
at 13:38:20.647. There are 115 false reads followed by 481 true reads. Continued
execution after that read is part of this capture; API traces do not expose every
internal VGK state transition.

## Periodic workers and reference behavior

| Worker role | New TID | Observations after DriverEntry | Median interval before / after first true timer read |
| --- | ---: | ---: | --- |
| Timing/shared state | 180 | 1,730 shared-lock acquisitions | 514 / 514 ms |
| Debugger/timer probe | 188 | 566 single-object waits | 1,519.5 / 1,518 ms |
| Process audit | 184 | 30 single-object waits | 30,204 / 30,219 ms |

The overall observed intervals span 501–594 ms, 1,504–1,906 ms, and
30,141–30,577 ms respectively. These measure logged call spacing, not exact
kernel wait durations. The timing worker also records 3,460 performance-counter
reads, twice its shared-lock acquisition count.

Grouping audit lookups into sweeps separated by more than ten seconds gives
30 sweeps, each with exactly 41 process lookups, 35 attachments, 35 detaches,
and 35 rundown releases. Totals are 1,230 lookups and 1,050 attach/detach/release
events apiece. Every release reports zero references left; no unmatched attach
or detach appears. The release hook is shared by process-exit synchronization
and handle-table dereference APIs, so these records are not a complete census
of all reference types. No live process-notification BEGIN/END events occurred.

## Exceptions and subsystem fidelity

All 603 dispatched exceptions have handled records. Of these, 598 are the known
null access violation at `vgk.sys+0x377530`, matching 598 `KdChangeOption` calls.
The other five are one DbgPrompt breakpoint and four handled startup access
violations. No unhandled exception or API/callback execution fault was found.
The only error-level records are the three existing optional IRQL hook-symbol
misses. There are no new normalized warning categories. The baseline additionally
contains 13 user-mode warnings from its companion workload. Independent final
inspection paired every dispatch with a handled record in order and confirmed
that all five exception sites also occur in the baseline.

Independent startup inspection confirms unchanged bounded subsystem behavior:

- CI: two trusted SHA-256 verdicts and six alternate-algorithm digest mismatches;
  offline revocation remains unchecked.
- Firmware: BootCurrent/Boot0000 and absent-entry results retain the baseline
  status, length, and attribute behavior.
- Storage: the modeled device handles the same requests, including the size
  negotiation and successful 8/94-byte responses; unmodeled disks remain absent.
- Physical-memory registry: the resource-map key opens and its 102-byte value
  matches the existing physical-memory model.
- Information class 76 is still unsupported and queried during VGK's kernel
  initialization (line 9566). It is a remaining fidelity gap, not a new regression.

The 492 failed physical translations still belong to recursive page-table slot
discovery, as explained in the baseline report. This capture does not establish
that they represent missing legitimate memory mappings.

## Allocation and host-resource observations

The logged pool trace contains 3,014 allocations and 1,191 frees. At capture end,
1,823 allocations totaling 24,801,152 bytes remain, exactly matching the baseline
capture's final logged footprint. Every surviving allocation originated before
DriverEntry returned. There are no unmatched frees, overlapping live allocation
addresses, or size mismatches in the logged reconstruction.

At the DriverEntry-return instant, an additional 11,952-byte allocation was still
live: the audit snapshot was in flight. The subsequent free and repeated return
to the smaller footprint distinguish that transient buffer from retained growth.

There are 28 host samples at approximately 30-second intervals, beginning after
startup. Private bytes decrease from 480,477,184 to 480,423,936; working set changes
from 392,413,184 to 392,486,912. Host handles settle at 290, whereas the guest
snapshot's handle total is four. These are separate measurements. Neither sampled
host memory nor the reconstructed logged pool footprint shows sustained growth;
this does not prove that every guest allocation or resource source is leak-free.

## Evidence

The capture directory contains `manifest.json`, `verification.json`, `stdout.log`,
`stderr.log`, `host-telemetry.jsonl`, `worker-analysis.json`,
`resource-analysis.json`, and `snapshot-analysis.json`. The latter records exact
snapshot groups, exception sites, cadence samples, and all 30 audit sweeps.
Reusable local analyzers are `build-conformance/analyze-vgk-workers.py`,
`analyze-vgk-resources.py`, and `analyze-snapshot-capture.py`.

## Comparison limits

The [previous fifteen-minute capture](vgk-kernel-15-minute-analysis.md) included
`process_notify_user.exe` to exercise a process creation/exit. This capture does
not. Consequently, no live process-notification delivery is expected here, TIDs
differ, and absolute host-memory or attach-count differences cannot all be
attributed to the snapshot upgrade. Worker roles and steady-state rates are the
appropriate comparison.

The capture tests execution against the improved snapshot interface. It does
not test `vgc.exe`, continuous process churn, all registered event callbacks,
complete hardware debugger semantics, or ARM64/WOW64 behavior. Forced termination
at the time limit does not test orderly unload or shutdown resource cleanup.
