# IRQL-aware thread scheduling

The CI target capture `kernel-20260926-155121-110` stopped after a thread was
switched out while holding an executive spinlock. Its successor inherited the
CPU's DISPATCH_LEVEL and correctly failed a PASSIVE_LEVEL callback guard.

## Required invariants

- Ordinary preemption is allowed below DISPATCH_LEVEL. A stopped quantum at
  DISPATCH_LEVEL or above resumes the same thread without requeueing it.
- Scheduler shutdown and fatal failure take precedence over deferred preemption.
- Each Windows thread starts at PASSIVE_LEVEL and preserves its own IRQL across
  legal switches. Restoring it updates both the per-CPU kernel state and hardware
  state; a new thread must not inherit its creator's raised IRQL.
- On x64, direct guest CR8 writes participate in the same scheduling policy as
  hooked IRQL APIs. The executing CPU observes them at a scheduling/API boundary.
- A queued DPC is deferred while the CPU is at DISPATCH_LEVEL or above. It runs at
  DISPATCH_LEVEL when eligible and restores the interrupted context's IRQL.
- A zero-timeout dispatcher poll at DISPATCH_LEVEL completes synchronously.
  A blocking wait or delay at that level is rejected before parking the thread.

This pass does not implement interrupt-priority arbitration, real multiprocessor
spinlock ownership, or the full Windows priority scheduler. A host cancellation
request may interrupt emulation; the decision to switch guest threads belongs to
the executing CPU, not the host clock thread.

## Verification

`thread::can_switch` is evaluated with the executing CPU's live state, before
the scheduler saves, requeues, or borrows the current context for DPC work.
Windows thread save/restore carries a separate IRQL field initialized to PASSIVE.
The x64 IRQL query reads CR8 and updates the KPCR mirror; ARM64 retains its KPCR
query. IRQL is deliberately not added to the generic register snapshot, which
would also affect construction and borrowed guest-call contexts.

The host clock retries a pending DPC work request after updating timers, even
when no ordinary thread is runnable. The clock checks queue/running atomics;
the executing CPU still decides IRQL eligibility. This prevents a stop request
deferred at high IRQL from being lost when the guest later lowers CR8 directly.

Blocking guards are placed before wait publication, sleep deadlines, self-suspend,
keyed-event posting, and fast-mutex contention changes. Dispatcher polls use a
local wait object under the dispatcher lock and never publish a parked wait.
An illegal raised-IRQL operation stops both the scheduler and the executing CPU
before reporting the error. Throwing alone is insufficient: the ordinary export
redirect boundary logs host exceptions and otherwise permits guest continuation.
Above-DISPATCH polling uses the same fatal path; DISPATCH polling remains legal.
These failures enforce emulator execution contracts; they do not reproduce a
particular Windows bugcheck code or dump.

Guest fixtures should keep a competitor runnable across several 50 ms host
quanta, exercise both hooked spinlock raises and direct CR8 writes, and prove
that the competitor runs only after IRQL falls. APC_LEVEL tests must demonstrate
actual competitor progress and correct IRQL on both threads. DPC and zero-timeout
poll tests cover the scheduling boundary; negative fixtures cover forbidden
blocking and termination of a failed elevated context.

All guest drivers are inert inputs to `kernemul.exe`; they are never installed
or executed as host drivers. The target capture uses the existing local-only
in-memory DEBUGCTL compatibility patch and preserves the driver file on disk.

```powershell
pwsh -NoProfile -File tests/scripts/build-drivers.ps1 -Driver 'irql_*'
pwsh -NoProfile -File tests/scripts/run-conformance.ps1 -Driver irql_conformance
pwsh -NoProfile -File tests/scripts/run-irql-negative.ps1
```

The positive fixture requires one vCPU and spans 200 ms per exclusion phase,
crossing several default 50 ms host quanta. The frozen pre-fix executable
`build-conformance/ci-verification-generic-20260926/kernemul.exe` produces 12
failures in `irql_conformance-20260926-214834-912.stdout.log`. Its high-IRQL
wait/delay/yield operations incorrectly return. The fatal-fault control already
stops promptly in that baseline and must continue to do so after the change.

## Validation on 2026-09-26

Implementation commit: `b85cf25`. Validated generic x64/WHP executable SHA-256:
`79EC91369EBBB811169AD8E8CE1E66C18491C3962F1D2BD0D98B07E4006A608E`.
The executable and runtime DLLs are frozen under
`build-conformance/irql-scheduling-validated-20260926`.

Independent verification completed **15 fixture runs: 265 positive assertions
and nine negative cases, all passing**. These include 49 new IRQL assertions,
five new rejection/fatal-stop cases, and existing timer, callback, process-attach,
CI, and callback/DPC failure regressions. Every runner exited zero; expected
negative guest executions exited one. None timed out; stderr was empty.

Evidence is in `build-conformance/irql_conformance-20260926-220047-106.json`, the
five `irql_failure_*-20260926-220040-*` through `220042-*` manifests, and regression
manifests from `timer_conformance-20260926-220100-474.json` through
`ci_verification-20260926-220121-484.json`. The attach harness used both companion
guest processes. Review found no further material issue after the final guard fix.

Runtime coverage is x64/WHP with one vCPU. ARM64 and multiprocessor behavior were
not execution-tested in this pass.

### Hyper-V target capture

`build-conformance/kernel-20260926-220301-430` ran `vgk.sys` with the
`process_notify_user.exe` companion for **210.039 seconds**. The harness stopped
it at the configured limit (`stoppedAtLimit=true`, forced-stop exit code `-1`);
this is a bounded capture, not a graceful driver unload.

The local-only lab commit is `f16edfe`, based on generic commit `b85cf25`. Lab
executable SHA-256: `2718335DF78AB3FF29CB3B7DE8D5FC4AECA3002ABE106A5EF929B1F0EDB1486C`.
The target's unchanged on-disk SHA-256 is
`3CB2F36CF9F3B66BF63561D24649422D852229F2C788A7AAA783752DCE4AB39F`.
The generic checkout and validated executable were restored during the frozen run.

- Driver initialization returned `STATUS_SUCCESS` at 22:03:08.088.
- Four process create/exit callback deliveries and four attach/detach pairs completed.
  The companion exited with its expected `0x1234` status; `vgc.exe` was not launched.
- The three-minute timer first returned true at 22:06:04.350, with **19 true reads**.
- **147 handled exceptions, zero unhandled faults, zero faulted API executions,
  zero callback IRQL failures, and zero unimplemented API executions** were recorded.
- Both system-image SHA-256 signatures still verified; six nonmatching digest
  algorithm probes correctly failed. No CI backend-unavailable result occurred.

Stderr was empty. Three startup error-level messages report optional hook symbols
absent from the mapped kernel (`KeRaiseIrql`, `KfLowerIrql`, and
`KeRaiseIrqlToSynchLevel`); they are not guest API execution failures. VGK still
emits the existing `E00000EF` diagnostic for `fltmgr.sys`. This scheduling pass
does not resolve remaining CI policy fields or firmware/storage fidelity.

The capture manifest, stdout/stderr, frozen executable, and `analysis-counts.json`
remain in that ignored local directory. Only the generic branch is published.

## Contract sources

- [Spinlock acquisition raises IRQL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquirespinlock)
- [Preemption and interruptibility](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/always-preemptible-and-always-interruptible)
- [Processor switches at APC_LEVEL or below](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-kegetcurrentprocessornumber)
- [Thread-local APC suppression](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/disabling-apcs)
- [Wait and zero-timeout IRQL requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kewaitforsingleobject)
- [DPC dispatch after lowering IRQL](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/registering-and-queuing-a-dpcforisr-routine)
