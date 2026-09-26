# Thread ownership queries

`PsGetThreadProcess` returns the specified modeled thread's owning process from
`ETHREAD.Tcb.Process`. It does not use the executing thread or the attachment
pointer in `ApcState.Process`. The model initializes ownership when constructing
the thread; attachment changes only APC state. A compile-time assertion checks
that the modeled `EPROCESS.Pcb` begins at offset zero. The query adds no reference.

This is an implementation of the emulator's ownership model, not a claim that
all Windows builds have identical internal layouts or that attachment switches
address spaces here. The existing attachment implementation explicitly models
only APC-state changes. The exact undocumented API contract has not been
independently established from a Windows disassembly.

The guest-only `thread_owner_conformance` fixture queries a child before it runs,
queries current and child ownership while attached to a distinct seeded process,
checks ownership after detachment, and checks the running child. It balances its
lookup references and handles. The existing `thread_notify_conformance` fixture
covers notification delivery and removal. Run both through
`tests/scripts/run-conformance.ps1` after building the emulator and fixtures.

The attachment distinction is documented for the related
[PsGetCurrentProcess](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetcurrentprocess)
and [PsGetCurrentProcessId](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetcurrentprocessid)
APIs. Those documents do not establish the internal layout used by this redirect.
