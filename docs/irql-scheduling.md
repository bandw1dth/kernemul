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

## Contract sources

- [Spinlock acquisition raises IRQL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquirespinlock)
- [Preemption and interruptibility](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/always-preemptible-and-always-interruptible)
- [Processor switches at APC_LEVEL or below](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-kegetcurrentprocessornumber)
- [Thread-local APC suppression](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/disabling-apcs)
- [Wait and zero-timeout IRQL requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kewaitforsingleobject)
- [DPC dispatch after lowering IRQL](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/registering-and-queuing-a-dpcforisr-routine)
